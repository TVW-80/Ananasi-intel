// FANGS pipeline: feed records -> provenance store -> link-analysis graph -> scored/mapped/narrated dispatch events -> bus.
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RecordStore } from './provenance.js';
import { FangsGraph } from './graph.js';
import { analyze, layout, placeIncremental } from './analytics.js';
import { AttackCatalog, mapEvent } from './attack.js';
import { VulnIntel, severity } from './scoring.js';
import { DispatchQueue } from './dispatch.js';
import { deterministicNarrative, llmNarrate, configuredProviders } from './narrate.js';
import { adapterMap, FEEDS, ANNOTATORS, c2intel } from './adapters/index.js';
import { C2_FILES } from './adapters/c2intel.js';
import { enrichIP } from './adapters/enrichers.js';
import { famKey } from './util.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SNAP_DIR = path.join(HERE, '..', 'data', 'snapshots', 'c2intel-2026-11-15');

export class Fangs extends EventEmitter {
  constructor({ env = process.env, now = () => Date.now(), llmFetch = fetch, enrichProviders, stixFile } = {}) {
    super();
    this.env = env; this.now = now; this.llmFetch = llmFetch; this.enrichProviders = enrichProviders;
    this.adapters = adapterMap();
    this.store = new RecordStore();
    this.fg = new FangsGraph({ store: this.store, adapters: this.adapters });
    this.catalog = AttackCatalog.load(stixFile);
    this.vuln = new VulnIntel().loadFixture();
    this.queue = new DispatchQueue();
    this.analysis = { communities: {}, betweenness: {}, degree: {}, modularity: 0, count: 0 };
    this.maxBetween = 0;
    this.feedStatus = new Map();
    for (const a of [...FEEDS, ...ANNOTATORS]) this.feedStatus.set(a.name, { name: a.name, label: a.label, state: a.keyed && !env[a.keyed] ? 'needs-key' : 'idle', key_env: a.keyed, records: 0, last_ok: null, last_error: null, note: null });
    this.seq = 0; this.ring = []; this.ringMax = 2000;
    this._analysisTimer = null; this._newSinceLayout = 0; this._enrichQueue = new Set(); this._enrichBusy = 0; this._llmBusy = 0; this._llmPending = new Set(); this._llmLast = 0; this._llmTimer = null;
    this.stats = { events_in: 0, llm_ok: 0, llm_fallback: 0, enriched: 0, enrich_fail: 0 };
  }

  // ---- bus (ring buffer for SSE Last-Event-ID replay) ----
  publish(type, data) {
    const msg = { id: ++this.seq, type, data, t: this.now() };
    this.ring.push(msg); if (this.ring.length > this.ringMax) this.ring.shift();
    this.emit('msg', msg);
    return msg;
  }
  since(id) { return this.ring.filter((m) => m.id > id); }

  setFeed(name, patch) {
    const s = this.feedStatus.get(name) || { name, label: name };
    Object.assign(s, patch); this.feedStatus.set(name, s);
    this.publish('feed', s);
  }

  // ---- ingestion ----
  // `recs` are parsed records for ONE adapter family. Returns timing info for latency measurement.
  ingestRecords(recs, { t0 = this.now() } = {}) {
    const newNodeIds = [], newEdges = [], evs = [];
    for (const r of recs) {
      const d = this.fg.ingest(r);
      for (const n of d.nodes) if (n.isNew) newNodeIds.push(n.id);
      newEdges.push(...d.edges);
      evs.push(...d.events);
    }
    for (const id of newNodeIds) placeIncremental(this.fg.graph, id, 3);
    this._newSinceLayout += newNodeIds.length;
    const snapshotNodes = newNodeIds.map((id) => this.nodeView(id));
    const snapshotEdges = [...new Set(newEdges.map((e) => e.key))].map((k) => this.edgeView(k));
    const produced = [];
    for (const ev of evs) produced.push(this.handleEvent(ev, t0));
    if (snapshotNodes.length || snapshotEdges.length) this.publish('graph-delta', { nodes: snapshotNodes, edges: snapshotEdges, t0 });
    for (const e of produced) if (e) this.publish('event', { event: this.eventView(e.event), created: e.created, t0 });
    this.scheduleAnalysis();
    for (const id of newNodeIds) { const a = this.fg.graph.getNodeAttributes(id); if (a.type === 'ip' && !a.prov.every((p) => String(this.store.get(p)?.origin || '').startsWith('fixture:'))) this._enrichQueue.add(id.slice(3)); }
    this.pumpEnrichment();
    return { newNodes: newNodeIds.length, newEdges: snapshotEdges.length, events: produced.filter(Boolean).length, t0, t1: this.now() };
  }

  handleEvent(ev, t0) {
    // Fronting domains are legitimate sites being abused; they are graphed but never dispatched as threats.
    if (ev.fronting && !ev.ip) return null;
    this.stats.events_in++;
    const up = this.queue.upsert(ev);
    const e = up.event;
    e.synthetic = e.sources.some((x) => String(this.store.get(x.recordId)?.origin || '').startsWith('fixture:'));
    if (up.newSource || up.created) this.rescore(e);
    // auto-triage: high/critical events move to "triaged" once scored+mapped+narrated (analyst still acknowledges)
    if (e.state === 'new' && e.score && (e.score.band === 'critical' || e.score.band === 'high')) this.queue.transition(e.id, 'triaged', 'auto');
    if (up.created || up.newSource) this.maybeLlm(e);
    return up;
  }

  nodeContext(nodeId) {
    const g = this.fg.graph;
    if (!nodeId || !g.hasNode(nodeId)) return {};
    const ctx = {};
    let asnId = null;
    g.forEachNeighbor(nodeId, (nb, a) => { if (a.type === 'asn') asnId = nb; });
    if (asnId) { const a = g.getNodeAttributes(asnId); ctx.asn = a.label + (a.attrs?.name ? ` ${a.attrs.name}` : ''); ctx.cc = a.attrs?.cc || null; ctx.asnPeers = Math.max(0, g.degree(asnId) - 1); }
    const cid = this.analysis.communities[nodeId];
    if (cid !== undefined) {
      const members = Object.entries(this.analysis.communities).filter(([, c]) => c === cid).map(([n]) => n);
      ctx.communitySize = members.length;
      const fams = {};
      for (const m of members) if (m.startsWith('family:')) fams[m.slice(7)] = (fams[m.slice(7)] || 0) + 1;
      ctx.communityFamily = Object.entries(fams).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
      ctx.community = cid;
    }
    ctx.betweenness = this.analysis.betweenness[nodeId] || 0;
    ctx.degree = g.hasNode(nodeId) ? g.degree(nodeId) : 0;
    return ctx;
  }

  rescore(e) {
    const { kev, epss } = this.vuln.lookup(e.cve);
    const ctx = this.nodeContext(e.node);
    const ageHours = Math.max(0, (this.now() - Date.parse(e.first_seen)) / 3600_000);
    const sources = new Set(e.sources.map((s) => s.source)).size;
    const centrality = this.maxBetween > 0 ? Math.min(1, (ctx.betweenness || 0) / this.maxBetween) : 0;
    e.score = { ...severity({ kev, epss, sources, family: e.family, ageHours, centrality }), basis: e.cve.length ? this.vuln.basis : 'no-cve' };
    const keepLlm = e.attack.filter((t) => t.basis === 'llm');
    e.attack = mapEvent(e, this.catalog);
    for (const t of keepLlm) if (!e.attack.some((x) => x.id === t.id)) e.attack.push(t);
    e.graph = { community: ctx.community ?? null, degree: ctx.degree, betweenness: +(ctx.betweenness || 0).toFixed(5), asn: ctx.asn || null, cc: ctx.cc || null };
    if (e.narrative?.basis !== 'llm') e.narrative = deterministicNarrative(e, ctx);   // an LLM rewrite survives re-scoring
  }

  // Fire-and-forget LLM upgrade. Never blocks the board, never throws. Events wait in a score-prioritised queue
  // (highest severity narrated first), paced to FANGS_LLM_RPM (default 20/min: free tiers are rate limited) with
  // bounded concurrency. Events that never get a slot keep the deterministic narrative.
  maybeLlm(e) {
    if (!configuredProviders(this.env).length) return;
    this._llmPending.add(e.id);
    const cap = 300;
    while (this._llmPending.size > cap) {
      let worst = null; for (const id of this._llmPending) { const s = this.queue.get(id)?.score?.score ?? 0; if (!worst || s < worst.s) worst = { id, s }; }
      this._llmPending.delete(worst.id); this.stats.llm_fallback++;
    }
    this.pumpLlm();
  }
  pumpLlm() {
    const gap = 60000 / Math.max(1, Number(this.env.FANGS_LLM_RPM) || 20);
    while (this._llmBusy < 3 && this._llmPending.size) {
      const wait = this._llmLast + gap - this.now();
      if (wait > 0) { if (!this._llmTimer) { this._llmTimer = setTimeout(() => { this._llmTimer = null; this.pumpLlm(); }, wait); this._llmTimer.unref?.(); } return; }
      let best = null; for (const id of this._llmPending) { const s = this.queue.get(id)?.score?.score ?? 0; if (!best || s > best.s) best = { id, s }; }
      this._llmPending.delete(best.id);
      const e = this.queue.get(best.id); if (!e) continue;
      this._llmLast = this.now(); this._llmBusy++;
      const ctx = this.nodeContext(e.node);
      llmNarrate(e, ctx, { env: this.env, fetchFn: this.llmFetch, catalog: this.catalog })
        .then((r) => {
          if (!r) { this.stats.llm_fallback++; return; }
          this.stats.llm_ok++;
          e.narrative = { ...r.narrative, fallback_text: deterministicNarrative(e, ctx).text };
          const have = new Set(e.attack.map((t) => t.id));
          for (const id of r.techniques) if (!have.has(id)) e.attack.push({ ...this.catalog.describe(id), basis: 'llm', why: `Suggested by ${r.provider}; validated against bundled ATT&CK STIX.` });
          this.publish('event-update', { event: this.eventView(e) });
        })
        .catch(() => { this.stats.llm_fallback++; })
        .finally(() => { this._llmBusy--; this.pumpLlm(); });
    }
  }

  // ---- analytics (debounced) ----
  scheduleAnalysis(delay = 150) {
    if (this._analysisTimer) return;
    this._analysisTimer = setTimeout(() => { this._analysisTimer = null; this.runAnalysis({ relayout: this._newSinceLayout >= 15 }); }, delay);
    this._analysisTimer.unref?.();
  }
  runAnalysis({ relayout = false } = {}) {
    const g = this.fg.graph;
    this.analysis = analyze(g);
    this.maxBetween = Math.max(0, ...Object.values(this.analysis.betweenness));
    if (relayout) { layout(g, this.analysis.communities); this._newSinceLayout = 0; }
    const patch = {};
    g.forEachNode((n, a) => { patch[n] = { community: this.analysis.communities[n], degree: this.analysis.degree[n], betweenness: +(this.analysis.betweenness[n] || 0).toFixed(5), ...(relayout ? { x: a.x, y: a.y } : {}) }; });
    for (const e of this.queue.events.values()) this.rescore(e);
    this.publish('analytics', { modularity: this.analysis.modularity, communities: this.analysis.count, nodes: patch, ms: this.analysis.ms });
    return this.analysis;
  }

  // ---- enrichment (live only; failures degrade to "no ASN", never to a guess) ----
  async pumpEnrichment() {
    if (this.env.FANGS_NO_ENRICH === '1') return;
    while (this._enrichBusy < 4 && this._enrichQueue.size) {
      const ip = this._enrichQueue.values().next().value; this._enrichQueue.delete(ip);
      this._enrichBusy++;
      enrichIP(ip, { providers: this.enrichProviders }).then(({ provider, input }) => {
        if (!provider) { this.stats.enrich_fail++; return; }
        this.stats.enriched++;
        const recs = this.adapters.get(provider).parse([input]);
        this.ingestRecords(recs);
      }).catch(() => { this.stats.enrich_fail++; }).finally(() => { this._enrichBusy--; this.pumpEnrichment(); });
    }
  }

  // ---- bundled real snapshot (honest fallback + offline start) ----
  loadSnapshot() {
    const inputs = C2_FILES.map((f) => ({ file: f, text: fs.readFileSync(path.join(SNAP_DIR, f), 'utf8'), url: `snapshot:c2intel-2026-11-15/${f}`, retrieved_at: '2026-11-15T21:18:00Z' }));
    const recs = c2intel.parse(inputs);
    const r = this.ingestRecords(recs);
    this.setFeed('c2intel', { state: 'snapshot', records: recs.length, note: 'Bundled real snapshot from 2026-11-15; live fetch not yet succeeded.' });
    return r;
  }

  async pollOnce(adapter) {
    const st = this.feedStatus.get(adapter.name);
    if (adapter.keyed && !this.env[adapter.keyed]) { this.setFeed(adapter.name, { state: 'needs-key', note: `Set ${adapter.keyed} to enable.` }); return null; }
    try {
      const inputs = await adapter.fetchAll({ env: this.env });
      const recs = adapter.parse(inputs.map((i) => ({ ...i, retrieved_at: new Date(this.now()).toISOString() })));
      const t0 = this.now();
      const r = this.ingestRecords(recs, { t0 });
      this.setFeed(adapter.name, { state: 'ok', records: (st?.records || 0) + recs.length, last_ok: new Date(this.now()).toISOString(), last_error: null, note: null });
      return r;
    } catch (e) {
      const prev = this.feedStatus.get(adapter.name);
      this.setFeed(adapter.name, { state: prev?.state === 'snapshot' ? 'snapshot' : 'degraded', last_error: String(e.message || e), note: prev?.state === 'snapshot' ? 'Live fetch failed; showing bundled snapshot.' : 'Feed unreachable; no data from this source.' });
      return null;
    }
  }
  start({ poll = true } = {}) {
    this.loadSnapshot();
    this.runAnalysis({ relayout: true });
    if (!poll) return;
    this._timers = FEEDS.map((a) => {
      this.pollOnce(a);
      const t = setInterval(() => this.pollOnce(a), a.intervalMs || 3600_000); t.unref?.(); return t;
    });
    this.vuln.refresh().then(() => this.publish('meta', { vuln_basis: this.vuln.basis })).catch(() => this.setFeed('kev', { label: 'CISA KEV / FIRST EPSS', state: 'degraded', last_error: 'unreachable', note: 'Using bundled SAMPLE KEV/EPSS values (synthetic).' }));
  }
  stop() { for (const t of this._timers || []) clearInterval(t); if (this._analysisTimer) clearTimeout(this._analysisTimer); }

  // ---- views ----
  nodeView(id) {
    const a = this.fg.graph.getNodeAttributes(id);
    return { id, type: a.type, label: a.label, attrs: a.attrs, prov: a.prov, sources: a.sources, x: a.x, y: a.y,
      community: this.analysis.communities[id] ?? null, degree: this.fg.graph.degree(id), betweenness: +(this.analysis.betweenness[id] || 0).toFixed(5) };
  }
  edgeView(key) {
    const g = this.fg.graph; const a = g.getEdgeAttributes(key);
    return { id: key, source: g.source(key), target: g.target(key), rels: a.rels };
  }
  eventView(e) { return e; }
  graphView() {
    const g = this.fg.graph;
    const nodes = [], edges = [];
    g.forEachNode((id) => nodes.push(this.nodeView(id)));
    g.forEachEdge((k) => edges.push(this.edgeView(k)));
    return { nodes, edges, stats: { nodes: nodes.length, edges: edges.length, rels: this.fg.relCount(), communities: this.analysis.count, modularity: +this.analysis.modularity.toFixed(4), records: this.store.size } };
  }
  recordView(id) { const r = this.store.get(id); return r ? { id: r.id, source: r.source, origin: r.origin, fetched_at: r.fetched_at, sha256: r.sha256, raw: r.raw, synthetic: String(r.origin || '').startsWith('fixture:') } : null; }
  llmStatus() { const p = configuredProviders(this.env); return { configured: p.map((x) => ({ name: x.name, model: x.model })), ...this.stats }; }
}
export { famKey };
