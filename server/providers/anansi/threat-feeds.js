// Anansi: threat-intel feed normalizers (pure, no I/O).
//
// Every feed becomes the same shape so one map layer implementation can draw
// them all:
//
//   { points: [{ id, lat, lon, title, detail, count, severity (0..1),
//                country, place, time, items: [{ text, time }] }],
//     total }
//
// Most threat feeds give an IP's COUNTRY, not a location, so those records are
// grouped per country and placed at the country's center (approximate by
// design). Shodan results carry real coordinates and stay individual.
import { readFileSync } from 'node:fs';

const CENTROIDS = JSON.parse(
  readFileSync(new URL('./geo/centroids.json', import.meta.url), 'utf8'),
);
const STATE_BY_NAME = new Map(
  Object.entries(CENTROIDS.usStates).map(([code, [, , name]]) => [name.toLowerCase(), code]),
);

const MAX_ITEMS = 8;
const str = (v) => (v === null || v === undefined ? '' : String(v).trim());
const iso2 = (v) => {
  const code = str(v).toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : null;
};
const toTime = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = typeof v === 'number' ? (v < 1e12 ? v * 1000 : v) : Date.parse(String(v).replace(' ', 'T'));
  return Number.isFinite(n) ? new Date(n).toISOString() : null;
};

export function countryCentroid(code) {
  const c = CENTROIDS.countries[iso2(code)];
  return c ? { lat: c[0], lon: c[1], name: c[2] } : null;
}

export function usStateCentroid(nameOrCode) {
  const key = str(nameOrCode);
  const code = CENTROIDS.usStates[key.toUpperCase()] ? key.toUpperCase() : STATE_BY_NAME.get(key.toLowerCase());
  const c = code && CENTROIDS.usStates[code];
  return c ? { lat: c[0], lon: c[1], name: c[2], code } : null;
}

/** Relative severity 0..1 on a log scale, so one huge country doesn't flatten the rest. */
function logScale(value, max) {
  if (!(value > 0) || !(max > 0)) return 0;
  return Math.min(1, Math.log10(value + 1) / Math.log10(max + 1));
}

/**
 * Group per-country records into one point per country.
 * @param {Array<{country: string, text: string, time?: string, weight?: number}>} records
 */
export function groupByCountry(kind, records, { title }) {
  const groups = new Map();
  let skipped = 0;
  for (const r of records) {
    const code = iso2(r.country);
    const center = code && countryCentroid(code);
    if (!center) {
      skipped += 1;
      continue;
    }
    let g = groups.get(code);
    if (!g) groups.set(code, (g = { code, center, count: 0, weight: 0, items: [], latest: null }));
    g.count += 1;
    g.weight += Number.isFinite(r.weight) ? r.weight : 1;
    if (r.time && (!g.latest || r.time > g.latest)) g.latest = r.time;
    g.items.push({ text: r.text, time: r.time || null });
  }
  const maxWeight = Math.max(0, ...[...groups.values()].map((g) => g.weight));
  const points = [...groups.values()]
    .map((g) => ({
      id: `${kind}:${g.code}`,
      lat: g.center.lat,
      lon: g.center.lon,
      country: g.code,
      place: g.center.name,
      title: title(g),
      detail: `${g.center.name} · ${g.count}`,
      count: g.count,
      severity: logScale(g.weight, maxWeight),
      time: g.latest,
      approximate: true,
      items: g.items
        .sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')))
        .slice(0, MAX_ITEMS),
    }))
    .sort((a, b) => b.count - a.count);
  return { points, total: records.length, skipped };
}

// ── abuse.ch Feodo Tracker: botnet command-and-control servers ───────────────
export function normalizeFeodo(payload) {
  const rows = Array.isArray(payload) ? payload : [];
  const records = rows
    .filter((r) => r && r.ip_address)
    .map((r) => ({
      country: r.country,
      time: toTime(r.last_online || r.first_seen),
      weight: str(r.status).toLowerCase() === 'online' ? 3 : 1,
      text: `${str(r.malware) || 'Botnet'} C2 ${r.ip_address}${r.port ? `:${r.port}` : ''}${r.as_name ? ` · ${str(r.as_name)}` : ''}${str(r.status) ? ` · ${str(r.status)}` : ''}`,
    }));
  return groupByCountry('feodo', records, {
    title: (g) => `${g.count} C2`,
  });
}

// ── AbuseIPDB blacklist: most-reported attacking IPs ─────────────────────────
export function normalizeAbuseIpdb(payload) {
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  const records = rows
    .filter((r) => r && r.ipAddress)
    .map((r) => ({
      country: r.countryCode,
      time: toTime(r.lastReportedAt),
      weight: Number(r.abuseConfidenceScore) / 100 || 1,
      text: `${r.ipAddress} · confidence ${Number(r.abuseConfidenceScore) || 0}%`,
    }));
  return groupByCountry('abuseipdb', records, { title: (g) => `${g.count} reported` });
}

// ── ransomware.live: recent leak-site victims ────────────────────────────────
export function normalizeRansomware(payload) {
  const rows = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : [];
  const records = rows
    .filter((r) => r && typeof r === 'object')
    .map((r) => {
      const victim = str(r.victim || r.post_title || r.name) || 'Unnamed victim';
      const group = str(r.group || r.group_name);
      const sector = str(r.activity || r.sector);
      return {
        country: r.country || r.countrycode || r.country_code,
        time: toTime(r.attackdate || r.discovered || r.published || r.date || r.discovered_at),
        text: `${victim}${group ? ` — ${group}` : ''}${sector ? ` · ${sector}` : ''}`,
      };
    });
  return groupByCountry('ransomware', records, { title: (g) => `${g.count} victims` });
}

// ── IODA (Georgia Tech): Internet outage scores per country / US state ──────
export function normalizeIoda(payload, { level = 'country' } = {}) {
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  const scored = rows
    .map((r) => {
      const entity = r?.entity || {};
      const score = Number(r?.scores?.overall);
      if (!(score > 0)) return null;
      const center = level === 'us-state' ? usStateCentroid(entity.name) : countryCentroid(entity.code);
      if (!center) return null;
      return { entity, score, center, events: Number(r.event_cnt) || 0 };
    })
    .filter(Boolean);
  const max = Math.max(0, ...scored.map((s) => s.score));
  const points = scored
    .map(({ entity, score, center, events }) => ({
      id: `ioda:${level}:${level === 'us-state' ? center.code : str(entity.code).toUpperCase()}`,
      lat: center.lat,
      lon: center.lon,
      country: level === 'us-state' ? 'US' : str(entity.code).toUpperCase(),
      place: center.name,
      title: `Outage ${Math.round(score).toLocaleString('en-US')}`,
      detail: `${center.name} · ${events} detection${events === 1 ? '' : 's'} (24h)`,
      count: events,
      severity: logScale(score, max),
      time: null,
      approximate: true,
      items: [{ text: `IODA outage score ${Math.round(score).toLocaleString('en-US')} over the last 24h`, time: null }],
    }))
    .sort((a, b) => b.severity - a.severity);
  return { points, total: rows.length, skipped: rows.length - points.length };
}

// ── Cloudflare Radar: outage annotations (needs a free API token) ───────────
export function normalizeCloudflareOutages(payload) {
  const annotations = payload?.result?.annotations || [];
  const records = [];
  for (const a of annotations) {
    const cause = str(a?.outage?.outageCause || a?.eventType).replace(/_/g, ' ');
    const text = [str(a?.description) || 'Outage', cause].filter(Boolean).join(' · ');
    const locations = Array.isArray(a?.locations) ? a.locations : [];
    for (const loc of locations) records.push({ country: loc, time: toTime(a?.startDate), text });
  }
  return groupByCountry('cloudflare', records, { title: (g) => `${g.count} outage${g.count === 1 ? '' : 's'}` });
}

// ── Shodan: exposed industrial control systems near you (exact positions) ───
export function normalizeShodan(payload) {
  const matches = Array.isArray(payload?.matches) ? payload.matches : [];
  const points = [];
  for (const m of matches) {
    const lat = Number(m?.location?.latitude);
    const lon = Number(m?.location?.longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    const product = str(m.product) || str(m._shodan?.module) || 'Service';
    const port = m.port ? `:${m.port}` : '';
    points.push({
      id: `shodan:${str(m.ip_str)}${port}`,
      lat,
      lon,
      country: iso2(m.location?.country_code),
      place: [str(m.location?.city), str(m.location?.region_code)].filter(Boolean).join(', '),
      title: `${product}${port}`,
      detail: [str(m.org), str(m.ip_str)].filter(Boolean).join(' · '),
      count: 1,
      severity: 0.7,
      time: toTime(m.timestamp),
      approximate: false,
      items: [{ text: `${str(m.ip_str)}${port} · ${product}${m.org ? ` · ${str(m.org)}` : ''}`, time: toTime(m.timestamp) }],
    });
  }
  return { points, total: Number(payload?.total) || matches.length, skipped: matches.length - points.length };
}

// ── Shodan host/count facets: how many, never which ──────────────────────────
// The count endpoint costs no query credits and returns no hosts, so these
// points carry totals only — no IPs, no screenshots, no streams.

/** Hampton Roads cities for the 757 focus (Shodan's city facet → a map position). */
export const HR_CITIES = Object.freeze({
  norfolk: [36.8508, -76.2859],
  'virginia beach': [36.8529, -75.978],
  chesapeake: [36.7682, -76.2875],
  portsmouth: [36.8354, -76.2983],
  suffolk: [36.7282, -76.5836],
  hampton: [37.0299, -76.3452],
  'newport news': [37.0871, -76.473],
  williamsburg: [37.2707, -76.7075],
  yorktown: [37.2388, -76.5097],
  poquoson: [37.1224, -76.3458],
  smithfield: [36.9824, -76.6311],
  gloucester: [37.4093, -76.5258],
  'gloucester point': [37.2532, -76.4971],
  'james city': [37.3132, -76.7739],
  toano: [37.3757, -76.8008],
  'cape charles': [37.2685, -76.017],
  'elizabeth city': [36.2946, -76.2511],
  moyock: [36.5235, -76.1752],
  currituck: [36.4498, -76.0157],
});

const SHODAN_EXPLAIN = Object.freeze({
  ics: {
    plain: 'Industrial control systems — the computers that run factories, water plants, pipelines and ports — answering openly on the internet. They were never meant to be reachable from outside.',
    tech: 'Shodan host/count, ICS-tagged services (Modbus, S7, DNP3, BACnet, EtherNet/IP…).',
  },
  cameras: {
    plain: 'Security cameras and webcams anyone on the internet can reach, often still using factory passwords. Hijacked cameras are what built botnets like Mirai.',
    tech: 'Shodan host/count on exposed camera services (webcam screenshot label). Counts only — no addresses or images are collected.',
  },
});

/**
 * @param {object} payload host/count response { total, facets: { country|city: [{value, count}] } }
 * @param {{kind: 'ics'|'cameras', facet: 'country'|'city'}} opts
 */
export function normalizeShodanFacets(payload, { kind, facet }) {
  const rows = Array.isArray(payload?.facets?.[facet]) ? payload.facets[facet] : [];
  const explain = SHODAN_EXPLAIN[kind];
  const label = kind === 'ics' ? 'industrial systems' : 'cameras';
  const groups = new Map();
  for (const r of rows) {
    const count = Number(r?.count) || 0;
    if (!count) continue;
    let key;
    let place;
    let lat;
    let lon;
    if (facet === 'country') {
      const c = countryCentroid(r.value);
      if (!c) continue;
      key = iso2(r.value);
      place = c.name;
      [lat, lon] = [c.lat, c.lon];
    } else {
      const name = str(r.value);
      const hit = HR_CITIES[name.toLowerCase()];
      key = hit ? name.toLowerCase().replace(/\s+/g, '-') : 'other';
      place = hit ? name : 'Elsewhere in the 757 area';
      [lat, lon] = hit || HR_CITIES.norfolk;
    }
    const g = groups.get(key) || { key, place, lat, lon, count: 0 };
    g.count += count;
    groups.set(key, g);
  }
  const max = Math.max(0, ...[...groups.values()].map((g) => g.count));
  const points = [...groups.values()]
    .sort((a, b) => b.count - a.count)
    .map((g) => ({
      id: `shodan-${kind}:${facet === 'country' ? g.key : `757-${g.key}`}`,
      lat: g.lat,
      lon: g.lon,
      country: facet === 'country' ? g.key : 'US',
      place: g.place,
      title: `${g.count.toLocaleString('en-US')} ${label}`,
      detail: g.place,
      count: g.count,
      severity: logScale(g.count, max),
      time: null,
      approximate: true,
      items: [
        { text: `${g.count.toLocaleString('en-US')} exposed ${label} in ${g.place}`, plain: explain.plain, tech: explain.tech },
      ],
    }));
  return { points, total: Number(payload?.total) || points.reduce((s, p) => s + p.count, 0), skipped: 0 };
}
