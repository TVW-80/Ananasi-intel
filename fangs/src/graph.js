// Provenance-enforcing link-analysis graph. Nodes/edges can ONLY be created by ingesting a stored record
// through an adapter's extract(); there is no public API for adding an element without a record id.
import Graph from 'graphology';

export class FangsGraph {
  constructor({ store, adapters }) {
    this.store = store;
    this.adapters = adapters;            // Map<source, adapter>
    this.graph = new Graph({ type: 'undirected', multi: false, allowSelfLoops: false });
    this.ingested = new Set();
    this.rejected = [];                  // {id, reason}
  }

  static edgeKey(a, b) { return a < b ? `${a}~${b}` : `${b}~${a}`; }

  // Returns a delta describing what changed (new/updated nodes, new rels) + extracted events.
  ingest(rec) {
    const delta = { recordId: rec?.id, nodes: [], edges: [], events: [], skipped: null };
    let stored;
    try { stored = this.store.put(rec); } catch (e) { this.rejected.push({ id: rec?.id, reason: e.message }); delta.skipped = e.message; return delta; }
    if (this.ingested.has(stored.id)) { delta.skipped = 'duplicate'; return delta; }
    const ad = this.adapters.get(stored.source);
    if (!ad) { this.rejected.push({ id: stored.id, reason: 'no adapter' }); delta.skipped = 'no adapter'; return delta; }
    let ex;
    try { ex = ad.extract(stored); } catch (e) { this.rejected.push({ id: stored.id, reason: `extract: ${e.message}` }); delta.skipped = 'extract error'; return delta; }
    this.ingested.add(stored.id);
    if (!ex.nodes.length && !ex.edges.length) { delta.skipped = 'no usable indicators'; this.rejected.push({ id: stored.id, reason: 'no usable indicators' }); return delta; }
    const g = this.graph;
    for (const n of ex.nodes) {
      if (!g.hasNode(n.id)) {
        g.addNode(n.id, { type: n.type, label: n.label, attrs: { ...n.attrs }, prov: [stored.id], sources: [stored.source], first_seen: stored.fetched_at, last_seen: stored.fetched_at });
        delta.nodes.push({ id: n.id, isNew: true });
      } else {
        const a = g.getNodeAttributes(n.id);
        for (const [k, v] of Object.entries(n.attrs || {})) if (v !== null && v !== undefined) a.attrs[k] = v;
        if (!a.prov.includes(stored.id)) { a.prov.push(stored.id); delta.nodes.push({ id: n.id, isNew: false }); }
        if (!a.sources.includes(stored.source)) a.sources.push(stored.source);
        a.last_seen = stored.fetched_at;
      }
    }
    for (const e of ex.edges) {
      const k = FangsGraph.edgeKey(e.src, e.dst);
      if (!g.hasEdge(k)) g.addEdgeWithKey(k, e.src, e.dst, { rels: [] });
      const ea = g.getEdgeAttributes(k);
      let rel = ea.rels.find((r) => r.type === e.type && r.src === e.src && r.dst === e.dst);
      if (!rel) { rel = { type: e.type, src: e.src, dst: e.dst, prov: [] }; ea.rels.push(rel); delta.edges.push({ key: k, type: e.type, src: e.src, dst: e.dst, isNew: true }); }
      if (!rel.prov.includes(stored.id)) rel.prov.push(stored.id);
    }
    delta.events = ex.events.map((ev) => ({ ...ev, source: stored.source, recordId: stored.id, observed_at: stored.fetched_at }));
    return delta;
  }

  ingestMany(recs) {
    const agg = { nodes: 0, edges: 0, events: [], skipped: {} };
    for (const r of recs) {
      const d = this.ingest(r);
      agg.nodes += d.nodes.filter((n) => n.isNew).length;
      agg.edges += d.edges.length;
      agg.events.push(...d.events);
      if (d.skipped) agg.skipped[d.skipped] = (agg.skipped[d.skipped] || 0) + 1;
    }
    return agg;
  }

  get order() { return this.graph.order; }
  get size() { return this.graph.size; }

  relCount() { let n = 0; this.graph.forEachEdge((_, a) => { n += a.rels.length; }); return n; }
  allRelKeys() { const s = new Set(); this.graph.forEachEdge((_, a) => a.rels.forEach((r) => s.add(`${r.type}|${r.src}|${r.dst}`))); return s; }
}
