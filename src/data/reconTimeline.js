/**
 * Ananzi FANGS — RECON timeline model (pure).
 *
 * Bins the correlated event stream into time buckets for the scrubber/replay,
 * and answers "what had happened as of time T" so the UI can rewind the board.
 * Times are when each signal was reported, never a claim of when it happened —
 * the RECON surface carries that disclaimer.
 */

const toMs = (t) => (typeof t === 'number' ? t : Date.parse(t));

/**
 * Bucket events across a span into `bins` equal slots.
 * @param {Array<{timeMs?:number,time?:any,kind?:string}>} events
 * @returns {{start:number,end:number,bins:Array<{t0,t1,count,byKind}>,max:number,span:number}}
 */
export function buildTimeline(events = [], { now = Date.now(), bins = 48, spanMs = 72 * 3_600_000 } = {}) {
  const end = now;
  const start = now - spanMs;
  const width = spanMs / bins;
  const slots = Array.from({ length: bins }, (_, i) => ({
    t0: Math.round(start + i * width),
    t1: Math.round(start + (i + 1) * width),
    count: 0,
    byKind: {},
  }));
  for (const e of events || []) {
    const t = Number.isFinite(e?.timeMs) ? e.timeMs : toMs(e?.time);
    if (!Number.isFinite(t) || t < start || t > end) continue;
    let idx = Math.floor((t - start) / width);
    if (idx >= bins) idx = bins - 1;
    if (idx < 0) idx = 0;
    const slot = slots[idx];
    slot.count += 1;
    const k = e.kind || 'activity';
    slot.byKind[k] = (slot.byKind[k] || 0) + 1;
  }
  const max = slots.reduce((m, s) => Math.max(m, s.count), 0);
  return { start, end, bins: slots, max, span: spanMs };
}

/** Events reported at or before `tMs` (the replay "as of" set). */
export function visibleAsOf(events = [], tMs) {
  const cut = Number.isFinite(tMs) ? tMs : Infinity;
  return (events || []).filter((e) => {
    const t = Number.isFinite(e?.timeMs) ? e.timeMs : toMs(e?.time);
    return Number.isFinite(t) && t <= cut;
  });
}

/** A short human label for a timestamp on the axis (UTC, compact). */
export function axisLabel(ms) {
  const d = new Date(ms);
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()} ${String(d.getUTCHours()).padStart(2, '0')}:00Z`;
}
