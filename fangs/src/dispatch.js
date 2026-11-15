// CAD-style dispatch queue. Strict lifecycle: new -> triaged -> acknowledged. Every transition is audited.
import { sha1short } from './util.js';

export const STATES = ['new', 'triaged', 'acknowledged'];
const NEXT = { new: 'triaged', triaged: 'acknowledged' };

export class DispatchQueue {
  constructor({ max = 5000, now = () => new Date().toISOString() } = {}) {
    this.events = new Map();
    this.max = max;
    this.now = now;
  }
  static idFor(ev) { return `ev_${sha1short(`${ev.node}|${ev.family || ''}`)}`; }

  // Merge by (node, family): a second source reporting the same indicator corroborates rather than duplicates.
  upsert(ev) {
    const id = DispatchQueue.idFor(ev);
    const at = this.now();
    let cur = this.events.get(id);
    if (!cur) {
      cur = { id, kind: ev.kind, family: ev.family || null, indicator: ev.indicator, node: ev.node, ip: ev.ip || null, host: ev.host || null,
        tags: [...(ev.tags || [])], cve: [...(ev.cve || [])], victims: [...(ev.victims || [])], country: ev.country || null,
        sources: [], first_seen: at, last_seen: at, state: 'new', history: [{ state: 'new', at, actor: 'system' }],
        score: null, attack: [], narrative: null, graph: null };
      this.events.set(id, cur);
      if (this.events.size > this.max) this.evict();
      this._addSource(cur, ev);
      return { event: cur, created: true, newSource: true };
    }
    const newSource = this._addSource(cur, ev);
    for (const t of ev.tags || []) if (!cur.tags.includes(t)) cur.tags.push(t);
    for (const c of ev.cve || []) if (!cur.cve.includes(c)) cur.cve.push(c);
    cur.last_seen = at;
    return { event: cur, created: false, newSource };
  }
  _addSource(cur, ev) {
    if (cur.sources.some((s) => s.recordId === ev.recordId)) return false;
    cur.sources.push({ source: ev.source, recordId: ev.recordId });
    return true;
  }
  evict() {
    // drop oldest acknowledged first, then oldest overall
    const arr = [...this.events.values()].sort((a, b) => (a.state === 'acknowledged' ? 0 : 1) - (b.state === 'acknowledged' ? 0 : 1) || a.last_seen.localeCompare(b.last_seen));
    while (this.events.size > this.max) this.events.delete(arr.shift().id);
  }
  get(id) { return this.events.get(id); }

  transition(id, to, actor = 'analyst') {
    const ev = this.events.get(id);
    if (!ev) return { ok: false, code: 404, error: 'unknown event' };
    if (NEXT[ev.state] !== to) return { ok: false, code: 409, error: `illegal transition ${ev.state} -> ${to}` };
    ev.state = to;
    ev.history.push({ state: to, at: this.now(), actor });
    return { ok: true, event: ev };
  }

  ranked(filter = {}) {
    let arr = [...this.events.values()];
    if (filter.state) arr = arr.filter((e) => e.state === filter.state);
    return arr.sort((a, b) => (b.score?.score ?? 0) - (a.score?.score ?? 0) || b.last_seen.localeCompare(a.last_seen));
  }
  counts() { const c = { new: 0, triaged: 0, acknowledged: 0 }; for (const e of this.events.values()) c[e.state]++; return c; }
}

// ---- Ranking quality (used by the labelled-replay benchmark) ----
export function dcg(rels, k) { let s = 0; for (let i = 0; i < Math.min(k, rels.length); i++) s += (2 ** rels[i] - 1) / Math.log2(i + 2); return s; }
export function ndcg(rankedRels, k) {
  const ideal = [...rankedRels].sort((a, b) => b - a);
  const d = dcg(ideal, k);
  return d === 0 ? 0 : dcg(rankedRels, k) / d;
}
