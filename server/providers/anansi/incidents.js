// Anansi: incident feed normalizers (pure, no I/O).
//
// Two keyless sources feed the "Incidents" layers, in the same point shape the
// threat-intel layers use ({ points: [...], total }):
//
//   NWS alerts   api.weather.gov active alerts (US-wide, or the 757 point)
//   News events  GDELT GEO 2.0 geolocated news clusters (US-wide, or 757 box)
//
// Nothing here invents a location: NWS alerts without a point are placed at
// their state's center (approximate), and news clusters keep GDELT's own
// coordinates. Both are labeled with their source in the popover.
import { usStateCentroid } from './threat-feeds.js';

/** Norfolk, VA: the center of the 757 focus. */
export const NORFOLK = Object.freeze({ lat: 36.85, lon: -76.29 });
/** Hampton Roads bounding box used to keep only 757 news clusters. */
export const HAMPTON_ROADS_BBOX = Object.freeze({
  south: 36.4,
  north: 37.5,
  west: -77.2,
  east: -75.8,
});

const MAX_ITEMS = 8;
const str = (v) => (v === null || v === undefined ? '' : String(v).trim());
const toTime = (v) => {
  const n = Date.parse(str(v));
  return Number.isFinite(n) ? new Date(n).toISOString() : null;
};

export const NWS_SEVERITY = Object.freeze({
  extreme: 1,
  severe: 0.8,
  moderate: 0.55,
  minor: 0.3,
});
const nwsSeverity = (v) => NWS_SEVERITY[str(v).toLowerCase()] ?? 0.2;

/** State codes an alert touches, from its UGC zone/county codes (e.g. VAZ095, NCC073). */
export function alertStates(properties) {
  const codes = new Set();
  for (const ugc of properties?.geocode?.UGC || []) {
    const code = str(ugc).slice(0, 2).toUpperCase();
    if (usStateCentroid(code)) codes.add(code);
  }
  return [...codes];
}

function alertItem(p) {
  const head = str(p.headline) || str(p.event) || 'Weather alert';
  return {
    text: head,
    time: toTime(p.sent || p.effective),
    plain:
      [str(p.severity), str(p.urgency)]
        .filter((s) => s && s !== 'Unknown')
        .join(' · ') || undefined,
    tech: str(p.areaDesc).slice(0, 160) || undefined,
  };
}

/**
 * NWS active alerts (GeoJSON). World/US focus: one point per state with the
 * worst severity and the top alerts. 757 focus: the feed was requested for
 * Norfolk's point, so every alert applies there and becomes one point.
 */
export function normalizeNwsAlerts(payload, focus = 'world') {
  const features = (Array.isArray(payload?.features) ? payload.features : [])
    .map((f) => f?.properties)
    .filter(
      (p) =>
        p &&
        str(p.status || 'Actual') === 'Actual' &&
        str(p.messageType || 'Alert') !== 'Cancel',
    );
  if (!features.length) return { points: [], total: 0 };

  if (focus === '757') {
    const sorted = [...features].sort(
      (a, b) => nwsSeverity(b.severity) - nwsSeverity(a.severity),
    );
    const latest =
      sorted
        .map((p) => toTime(p.sent || p.effective))
        .filter(Boolean)
        .sort()
        .at(-1) || null;
    return {
      total: features.length,
      points: [
        {
          id: 'incidents-alerts:757',
          lat: NORFOLK.lat,
          lon: NORFOLK.lon,
          title: `${features.length} active NWS alert${features.length === 1 ? '' : 's'} · Hampton Roads`,
          detail: str(sorted[0].event),
          count: features.length,
          severity: nwsSeverity(sorted[0].severity),
          country: 'US',
          place: 'Hampton Roads, VA',
          time: latest,
          approximate: false,
          items: sorted.slice(0, MAX_ITEMS).map(alertItem),
        },
      ],
    };
  }

  const byState = new Map();
  let placed = 0;
  for (const p of features) {
    const states = alertStates(p);
    if (!states.length) continue;
    placed += 1;
    for (const code of states) {
      let g = byState.get(code);
      if (!g)
        byState.set(
          code,
          (g = { code, alerts: [], severity: 0, latest: null }),
        );
      g.alerts.push(p);
      g.severity = Math.max(g.severity, nwsSeverity(p.severity));
      const t = toTime(p.sent || p.effective);
      if (t && (!g.latest || t > g.latest)) g.latest = t;
    }
  }
  const points = [...byState.values()].map((g) => {
    const center = usStateCentroid(g.code);
    const sorted = [...g.alerts].sort(
      (a, b) => nwsSeverity(b.severity) - nwsSeverity(a.severity),
    );
    return {
      id: `incidents-alerts:${g.code}`,
      lat: center.lat,
      lon: center.lon,
      title: `${g.alerts.length} active NWS alert${g.alerts.length === 1 ? '' : 's'} · ${center.name}`,
      detail: str(sorted[0].event),
      count: g.alerts.length,
      severity: g.severity,
      country: 'US',
      place: center.name,
      time: g.latest,
      approximate: true, // state-level position by design
      items: sorted.slice(0, MAX_ITEMS).map(alertItem),
    };
  });
  return { points, total: placed };
}

/** Pull article links out of a GDELT GEO `html` blob. Tolerant: falls back to the place name. */
export function parseGdeltLinks(html) {
  const out = [];
  for (const m of str(html).matchAll(
    /<a\s[^>]*href=["']([^"']+)["'][^>]*>([^<]{3,})<\/a>/gi,
  )) {
    let url;
    try {
      url = new URL(m[1]);
    } catch {
      continue;
    }
    if (!['http:', 'https:'].includes(url.protocol)) continue;
    out.push({
      text: m[2].replace(/\s+/g, ' ').trim().slice(0, 180),
      url: url.href,
    });
    if (out.length >= MAX_ITEMS) break;
  }
  return out;
}

const inBox = (lat, lon, b) =>
  lat >= b.south && lat <= b.north && lon >= b.west && lon <= b.east;

/**
 * GDELT GEO 2.0 point data (GeoJSON): one point per geolocated news cluster.
 * 757 focus keeps only clusters inside Hampton Roads.
 */
export function normalizeGdeltEvents(payload, focus = 'world') {
  const features = Array.isArray(payload?.features) ? payload.features : [];
  const rows = [];
  for (const f of features) {
    const [lon, lat] = f?.geometry?.coordinates || [];
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    if (focus === '757' && !inBox(lat, lon, HAMPTON_ROADS_BBOX)) continue;
    const props = f.properties || {};
    const count = Math.max(1, Number(props.count) || 1);
    rows.push({
      lat,
      lon,
      count,
      name: str(props.name) || 'Unnamed place',
      links: parseGdeltLinks(props.html),
    });
  }
  const maxCount = Math.max(1, ...rows.map((r) => r.count));
  const points = rows
    .sort((a, b) => b.count - a.count)
    .slice(0, 200)
    .map((r, i) => ({
      id: `incidents-news:${r.lat.toFixed(2)},${r.lon.toFixed(2)}:${i}`,
      lat: r.lat,
      lon: r.lon,
      title: r.links[0]?.text || `News activity · ${r.name}`,
      detail: `${r.count} article${r.count === 1 ? '' : 's'}`,
      count: r.count,
      severity: Math.min(1, Math.log10(r.count + 1) / Math.log10(maxCount + 1)),
      country: 'US',
      place: r.name,
      time: null, // GEO point data is a rolling window, not per-article times
      approximate: false,
      items: (r.links.length
        ? r.links
        : [
            {
              text: `${r.count} recent article${r.count === 1 ? '' : 's'} mention this place`,
            },
          ]
      ).map((l) => ({ text: l.text })),
    }));
  return { points, total: rows.length };
}

const EVENT_TERMS =
  'shooting OR explosion OR "structure fire" OR "plane crash" OR evacuation OR tornado OR flooding OR "power outage" OR "state of emergency" OR derailment';
const HAMPTON_ROADS_TERMS =
  '(Norfolk OR "Virginia Beach" OR Chesapeake OR "Newport News" OR Hampton OR Portsmouth OR Suffolk OR Williamsburg)';

/** NWS alerts URL: US-wide, or only the alerts covering Norfolk's point. */
export function nwsAlertsUrl(focus) {
  const params = new URLSearchParams({
    status: 'actual',
    message_type: 'alert',
  });
  if (focus === '757') params.set('point', `${NORFOLK.lat},${NORFOLK.lon}`);
  return `https://api.weather.gov/alerts/active?${params}`;
}

/** GDELT GEO URL: US incident-type news, or Hampton Roads place names over 48h. */
export function gdeltGeoUrl(focus) {
  const query =
    focus === '757'
      ? `${HAMPTON_ROADS_TERMS} sourcecountry:US`
      : `(${EVENT_TERMS}) sourcecountry:US`;
  const params = new URLSearchParams({
    query,
    format: 'GeoJSON',
    timespan: focus === '757' ? '48h' : '24h',
  });
  return `https://api.gdeltproject.org/api/v2/geo/geo?${params}`;
}
