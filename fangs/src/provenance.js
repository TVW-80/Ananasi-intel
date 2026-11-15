// Record store + provenance verification.
// Every graph node and edge must cite >=1 record id; every cited record must exist in the store and must
// actually yield that node/edge when its adapter's pure `extract()` is re-run on the stored raw payload.
import { sha256 } from './util.js';

export class RecordStore {
  constructor() { this.records = new Map(); }
  // rec: {id, source, origin, fetched_at, raw}
  put(rec) {
    if (!rec || !rec.id || !rec.source || rec.raw === undefined) throw new Error('record needs id, source, raw');
    if (this.records.has(rec.id)) return this.records.get(rec.id);
    const stored = { id: rec.id, source: rec.source, origin: rec.origin || null, fetched_at: rec.fetched_at || new Date().toISOString(),
      sha256: sha256(JSON.stringify(rec.raw)), raw: rec.raw };
    this.records.set(rec.id, stored);
    return stored;
  }
  get(id) { return this.records.get(id); }
  has(id) { return this.records.has(id); }
  get size() { return this.records.size; }
  // Integrity: stored raw must still hash to the recorded digest.
  verifyIntegrity() {
    let bad = 0;
    for (const r of this.records.values()) if (sha256(JSON.stringify(r.raw)) !== r.sha256) bad++;
    return bad;
  }
}

// adapters: Map<source, adapter>. Returns counts; `fabricated` must be 0 for the provenance PASS criterion.
export function verifyProvenance(fg, store, adapters) {
  const out = { nodes: 0, edges: 0, rels: 0, node_unsourced: 0, rel_unsourced: 0, missing_record: 0, fabricated_nodes: 0, fabricated_rels: 0, integrity_failures: store.verifyIntegrity(), problems: [] };
  const derivedCache = new Map();
  const derive = (recId) => {
    if (derivedCache.has(recId)) return derivedCache.get(recId);
    const rec = store.get(recId);
    const ad = rec && adapters.get(rec.source);
    const d = rec && ad ? ad.extract(rec) : null;
    const ent = d && { nodes: new Set((d.nodes || []).map((n) => n.id)), rels: new Set((d.edges || []).map((e) => `${e.type}|${e.src}|${e.dst}`)) };
    derivedCache.set(recId, ent);
    return ent;
  };
  fg.graph.forEachNode((id, a) => {
    out.nodes++;
    if (!a.prov || a.prov.length === 0) { out.node_unsourced++; out.problems.push(`node ${id}: no provenance`); return; }
    for (const p of a.prov) {
      if (!store.has(p)) { out.missing_record++; out.problems.push(`node ${id}: record ${p} missing`); continue; }
      const d = derive(p);
      if (!d || !d.nodes.has(id)) { out.fabricated_nodes++; out.problems.push(`node ${id}: not derivable from ${p}`); }
    }
  });
  fg.graph.forEachEdge((key, a) => {
    out.edges++;
    for (const rel of a.rels) {
      out.rels++;
      if (!rel.prov || rel.prov.length === 0) { out.rel_unsourced++; out.problems.push(`rel ${rel.type}|${rel.src}|${rel.dst}: no provenance`); continue; }
      for (const p of rel.prov) {
        if (!store.has(p)) { out.missing_record++; out.problems.push(`rel ${rel.type}|${rel.src}|${rel.dst}: record ${p} missing`); continue; }
        const d = derive(p);
        if (!d || !d.rels.has(`${rel.type}|${rel.src}|${rel.dst}`)) { out.fabricated_rels++; out.problems.push(`rel ${rel.type}|${rel.src}|${rel.dst}: not derivable from ${p}`); }
      }
    }
  });
  out.ok = out.node_unsourced + out.rel_unsourced + out.missing_record + out.fabricated_nodes + out.fabricated_rels + out.integrity_failures === 0;
  out.sourced_pct = out.nodes + out.rels === 0 ? 100 : +(100 * (1 - (out.node_unsourced + out.rel_unsourced + out.fabricated_nodes + out.fabricated_rels + out.missing_record) / (out.nodes + out.rels)) ).toFixed(2);
  return out;
}
