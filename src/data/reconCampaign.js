/**
 * Ananzi FANGS — RECON campaign detection (pure).
 *
 * Splits the event stream into a recent half and a prior half and compares the
 * per-technique (and per-origin) counts, so a building campaign — a technique
 * or an origin trending sharply upward — is visible as it forms, rather than
 * only as a static total.
 */

const toMs = (t) => (typeof t === 'number' ? t : Date.parse(t));

function tally(events, pick) {
  const m = new Map();
  for (const e of events) {
    const key = pick(e);
    if (!key) continue;
    m.set(key, (m.get(key) || 0) + 1);
  }
  return m;
}

/**
 * Trend each key across a recent vs. prior window.
 * @param {(e)=>string} pick - key extractor (technique id, origin, …)
 * @returns {Array<{key,recent,prior,delta,direction,label?}>}
 */
export function trendBy(events = [], pick, { now = Date.now(), windowMs = 24 * 3_600_000 } = {}) {
  const recentCut = now - windowMs;
  const priorCut = now - 2 * windowMs;
  const recent = [];
  const prior = [];
  for (const e of events || []) {
    const t = Number.isFinite(e?.timeMs) ? e.timeMs : toMs(e?.time);
    if (!Number.isFinite(t)) continue;
    if (t >= recentCut) recent.push(e);
    else if (t >= priorCut) prior.push(e);
  }
  const r = tally(recent, pick);
  const p = tally(prior, pick);
  const keys = new Set([...r.keys(), ...p.keys()]);
  const rows = [];
  for (const key of keys) {
    const rc = r.get(key) || 0;
    const pc = p.get(key) || 0;
    const delta = rc - pc;
    const direction = delta > 0 ? 'rising' : delta < 0 ? 'falling' : 'steady';
    rows.push({ key, recent: rc, prior: pc, delta, direction });
  }
  rows.sort((a, b) => b.delta - a.delta || b.recent - a.recent);
  return rows;
}

/** Technique trends, labelled for display. */
export function techniqueTrends(events = [], opts = {}) {
  const rows = trendBy(events, (e) => e?.technique?.id, opts);
  const byId = new Map();
  for (const e of events || []) if (e?.technique?.id && !byId.has(e.technique.id)) byId.set(e.technique.id, e.technique);
  return rows.map((row) => ({ ...row, technique: byId.get(row.key) || { id: row.key, name: row.key } }));
}

/** Origin (adversary) trends. */
export function originTrends(events = [], opts = {}) {
  return trendBy(events, (e) => (e?.adversary && e.adversary !== 'Unknown' ? e.adversary : ''), opts);
}

/** The sharpest rising signals (campaigns forming). */
export function topRising(rows = [], { limit = 5 } = {}) {
  return rows.filter((r) => r.direction === 'rising' && r.delta > 0).slice(0, limit);
}
