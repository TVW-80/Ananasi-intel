/**
 * Hampton Roads Maritime feed for the Anansi 757 panel.
 *
 * Reads the base platform's own live AIS endpoint (`/api/vessels`, served by
 * server/providers/vessels/ais-live.js — the AISStream key stays server-side)
 * and turns raw vessel rows into a short, ranked list of panel items:
 *
 *   - which port zone each vessel is in (terminals, Naval Station Norfolk,
 *     the bridge-tunnel crossings, Thimble Shoal Channel, anchorages, ...)
 *   - what kind of vessel it is (AIS ship-type family)
 *   - whether it is underway, and how notable it is for the panel
 *
 * Items use the same normalized shape as the n8n traffic / weather / news
 * pipelines: {lat, lng, label, type, metadata}, plus top-level `source`,
 * `severity` and `timestamp` for the right-rail feed.
 *
 * Pure functions are exported for testing; createHamptonRoadsMaritimeFeed()
 * is the poller the panel uses. No dependencies.
 */

export const SOURCE = 'AISStream';

/** AISStream subscription box covering Hampton Roads, the lower bay and the capes. */
export const HAMPTON_ROADS_BBOX = [[[36.75, -76.75], [37.45, -75.65]]];

/**
 * Port zones, checked in order (first match wins), so small, specific zones
 * come before the broad water areas around them. Boxes are approximate.
 * [south, west, north, east]
 */
export const ZONES = [
  { id: 'ns-norfolk', name: 'Naval Station Norfolk', box: [36.935, -76.345, 36.975, -76.305] },
  { id: 'nit', name: 'Norfolk International Terminals', box: [36.905, -76.34, 36.935, -76.315] },
  { id: 'vig', name: 'Virginia International Gateway', box: [36.865, -76.38, 36.895, -76.35] },
  { id: 'hrbt', name: 'Hampton Roads Bridge-Tunnel', box: [36.965, -76.315, 37.005, -76.285] },
  { id: 'cbbt', name: 'Chesapeake Bay Bridge-Tunnel', box: [36.94, -76.14, 37.08, -76.05] },
  { id: 'newport-news', name: 'Newport News waterfront', box: [36.955, -76.455, 37.01, -76.41] },
  { id: 'elizabeth', name: 'Elizabeth River', box: [36.78, -76.34, 36.865, -76.26] },
  { id: 'thimble-shoal', name: 'Thimble Shoal Channel', box: [36.95, -76.285, 37.0, -76.14] },
  { id: 'harbor', name: 'Hampton Roads harbor', box: [36.895, -76.41, 37.02, -76.26] },
  { id: 'james', name: 'James River', box: [36.95, -76.75, 37.25, -76.455] },
  { id: 'cape-henry', name: 'Cape Henry approaches', box: [36.75, -76.05, 37.1, -75.65] },
  { id: 'lower-bay', name: 'Lower Chesapeake Bay', box: [37.0, -76.45, 37.45, -75.9] },
];

/** Zones where a moving ship is worth calling out (tunnels and the main channel). */
const CHOKEPOINTS = new Set(['hrbt', 'cbbt', 'thimble-shoal']);
/** Zones that count as "in port" for the summary. */
const PORT_ZONES = new Set(['ns-norfolk', 'nit', 'vig', 'newport-news', 'elizabeth']);

const UNDERWAY_KNOTS = 1;

/** AIS ship-type code (string or number) -> family. */
export function shipFamily(code) {
  const n = Number(code);
  if (!Number.isInteger(n) || n <= 0) return 'Unknown';
  if (n >= 70 && n <= 79) return 'Cargo';
  if (n >= 80 && n <= 89) return 'Tanker';
  if (n >= 60 && n <= 69) return 'Passenger';
  if (n >= 40 && n <= 49) return 'High-speed craft';
  return (
    {
      30: 'Fishing', 31: 'Towing', 32: 'Towing', 33: 'Dredging', 34: 'Diving ops',
      35: 'Military', 36: 'Sailing', 37: 'Pleasure craft', 50: 'Pilot',
      51: 'Search & rescue', 52: 'Tug', 53: 'Port tender', 55: 'Law enforcement',
      58: 'Medical transport',
    }[n] || (n >= 90 && n <= 99 ? 'Other' : 'Unknown')
  );
}

const NOTABLE_FAMILIES = new Set(['Military', 'Search & rescue', 'Law enforcement', 'Medical transport']);
const COMMERCIAL_FAMILIES = new Set(['Cargo', 'Tanker', 'Passenger']);

/** Which zone a point is in, or null when outside every zone. */
export function zoneFor(lat, lng) {
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  for (const zone of ZONES) {
    const [s, w, n, e] = zone.box;
    if (lat >= s && lat <= n && lng >= w && lng <= e) return zone;
  }
  return null;
}

/**
 * Severity for the panel:
 *   high   — search & rescue, law enforcement, medical, or military transmitting
 *   medium — tanker or deep-draft cargo/passenger moving through a tunnel crossing
 *            or Thimble Shoal Channel
 *   low    — other commercial traffic underway
 *   info   — everything else (moored, anchored, small craft)
 */
export function severityFor(family, zoneId, underway) {
  if (NOTABLE_FAMILIES.has(family)) return 'high';
  if (underway && COMMERCIAL_FAMILIES.has(family) && CHOKEPOINTS.has(zoneId)) return 'medium';
  if (underway && COMMERCIAL_FAMILIES.has(family)) return 'low';
  return 'info';
}

const SEVERITY_RANK = { high: 0, medium: 1, low: 2, info: 3 };

/** One /api/vessels row -> normalized panel item (or null when outside Hampton Roads). */
export function toItem(row) {
  const lat = Number(row?.lat);
  const lng = Number(row?.lon ?? row?.lng);
  const zone = zoneFor(lat, lng);
  if (!zone) return null;
  const family = shipFamily(row.type);
  const speed = Number.isFinite(row.speed) ? row.speed : null;
  const underway = speed !== null && speed >= UNDERWAY_KNOTS;
  const severity = severityFor(family, zone.id, underway);
  const name = String(row.name || `MMSI ${row.mmsi}`).trim();
  const motion = underway ? `underway ${speed.toFixed(1)} kn` : 'stationary';
  return {
    lat,
    lng,
    label: `${name} — ${family}, ${motion} · ${zone.name}`,
    type: 'maritime',
    source: SOURCE,
    severity,
    timestamp: row.last_position_UTC || null,
    metadata: {
      source: SOURCE,
      severity,
      timestamp: row.last_position_UTC || null,
      mmsi: row.mmsi || null,
      imo: row.imo || null,
      name,
      shipType: family,
      shipTypeCode: row.type || null,
      zone: zone.id,
      zoneName: zone.name,
      underway,
      speedKn: speed,
      course: row.course ?? null,
      heading: row.heading ?? null,
      destination: row.destination || null,
    },
  };
}

/**
 * Rows -> {items, summary}. `items` is the ranked, capped list for the panel:
 * notable vessels first, then commercial traffic underway (newest first).
 * Moored and small-craft rows are counted in the summary but not listed.
 */
export function buildMaritimePicture(rows, { maxItems = 25 } = {}) {
  const all = (Array.isArray(rows) ? rows : []).map(toItem).filter(Boolean);

  const byFamily = {};
  const byZone = {};
  let underway = 0;
  let inPort = 0;
  for (const item of all) {
    const m = item.metadata;
    byFamily[m.shipType] = (byFamily[m.shipType] || 0) + 1;
    byZone[m.zoneName] = (byZone[m.zoneName] || 0) + 1;
    if (m.underway) underway += 1;
    if (PORT_ZONES.has(m.zone) && COMMERCIAL_FAMILIES.has(m.shipType)) inPort += 1;
  }

  const items = all
    .filter((i) => i.severity !== 'info')
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        String(b.timestamp || '').localeCompare(String(a.timestamp || '')),
    )
    .slice(0, maxItems);

  const commercial = ['Cargo', 'Tanker', 'Passenger'].map((f) => `${byFamily[f] || 0} ${f.toLowerCase()}`).join(', ');
  return {
    items,
    summary: {
      total: all.length,
      underway,
      commercialInPort: inPort,
      byFamily,
      byZone,
      headline: `${all.length} vessels in Hampton Roads waters · ${underway} underway · ${commercial}`,
    },
  };
}

/**
 * Poller for the 757 panel. Degrades gracefully: a failed poll keeps the last
 * good picture, marks it stale, and retries with backoff instead of turning
 * the panel off (the lesson from the original 757 layer).
 *
 * @param {object} opts
 * @param {(picture: object) => void} opts.onUpdate  Called with {items, summary, status, updatedAt, error}
 * @param {string} [opts.url]          Same-origin AIS endpoint
 * @param {number} [opts.intervalMs]   Normal poll interval
 * @param {number} [opts.maxItems]     Panel item cap
 * @param {typeof fetch} [opts.fetchImpl]
 */
export function createHamptonRoadsMaritimeFeed({
  onUpdate,
  url = '/api/vessels?maxRows=20000',
  intervalMs = 30_000,
  maxItems = 25,
  fetchImpl = globalThis.fetch?.bind(globalThis),
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let timer = null;
  let failures = 0;
  let stopped = true;
  let last = { items: [], summary: null, status: 'starting', updatedAt: null, error: null };

  const emit = (patch) => {
    last = { ...last, ...patch };
    try {
      onUpdate?.(last);
    } catch (err) {
      console.warn('[Anansi maritime] onUpdate failed', err);
    }
  };

  async function refresh() {
    try {
      const res = await fetchImpl(url, { cache: 'no-store' });
      if (res.status === 503) {
        failures = 0;
        emit({ status: 'key-required', error: 'Set AISSTREAM_API_KEY in .env to enable live vessels.' });
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const picture = buildMaritimePicture(body.rows, { maxItems });
      failures = 0;
      // The server reports 'live' or a recovering state; surface it as-is.
      emit({ ...picture, status: body.status === 'live' ? 'live' : body.status || 'live', updatedAt: new Date().toISOString(), error: body.error || null });
    } catch (err) {
      failures += 1;
      emit({ status: last.updatedAt ? 'stale' : 'error', error: String(err?.message || err) });
    }
  }

  function schedule() {
    if (stopped) return;
    const delay = failures ? Math.min(intervalMs * 2 ** failures, 5 * 60_000) : intervalMs;
    timer = setTimer(async () => {
      await refresh();
      schedule();
    }, delay);
  }

  return {
    async start() {
      if (!stopped) return;
      stopped = false;
      await refresh();
      schedule();
    },
    stop() {
      stopped = true;
      if (timer) clearTimer(timer);
      timer = null;
    },
    refresh,
    get current() {
      return last;
    },
  };
}
