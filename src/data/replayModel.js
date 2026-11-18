/**
 * Ananzi FANGS — RECON replay model (pure).
 *
 * Given the normalized event stream and a playhead time, returns the
 * country-level pulses to draw on the globe: one per country with a signal
 * reported at or before the playhead, sized by how many and coloured by the
 * dominant kind, with the most-recent report time (for a freshness fade).
 * Country-level only — it never implies a precise location.
 */
import { visibleAsOf } from './reconTimeline.js';
import { centroidOf } from './countryCentroids.js';

// Dominant-kind → pulse colour (matches the map's warm attack palette).
const KIND_COLOR = {
  ransomware: '#ff2b2b', breach: '#ff2b2b', ddos: '#ff5a5a', exploit: '#ff6b4a',
  c2: '#ff8a1f', botnet: '#ff8a1f', malware: '#c061dd', hijack: '#f4cf5e',
  phishing: '#e0457b', bruteforce: '#ff8a1f', scanning: '#d4af37', exposure: '#d4af37',
};

/**
 * @param {Array} events normalized RECON events (carry .adversary, .timeMs, .kind)
 * @param {{playheadMs:number}} opts
 * @returns {{playheadMs, pulses:Array<{country,lat,lon,count,kind,color,lastMs}>, offMap:number}}
 */
export function buildReplay(events = [], { playheadMs = Date.now() } = {}) {
  const asOf = visibleAsOf(events, playheadMs);
  const byCountry = new Map();
  let offMap = 0; // signals with no placeable country (news/vulns/outages)
  for (const e of asOf) {
    const cc = e.adversary && e.adversary !== 'Unknown' ? e.adversary : '';
    const c = cc && centroidOf(cc);
    if (!c) { offMap += 1; continue; }
    let g = byCountry.get(cc);
    if (!g) { g = { country: cc, lat: c.lat, lon: c.lon, count: 0, kinds: {}, lastMs: 0 }; byCountry.set(cc, g); }
    g.count += 1;
    g.kinds[e.kind] = (g.kinds[e.kind] || 0) + 1;
    if (e.timeMs > g.lastMs) g.lastMs = e.timeMs;
  }
  const pulses = [...byCountry.values()].map((g) => {
    const kind = Object.entries(g.kinds).sort((a, b) => b[1] - a[1])[0]?.[0] || 'scanning';
    return { country: g.country, lat: g.lat, lon: g.lon, count: g.count, kind, color: KIND_COLOR[kind] || '#d4af37', lastMs: g.lastMs };
  }).sort((a, b) => b.count - a.count);
  return { playheadMs, pulses, offMap };
}
