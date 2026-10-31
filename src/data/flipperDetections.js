/**
 * @module flipperDetections
 *
 * Turns SquachWatch / Spider Sense detections from a Flipper-tethered ESP32
 * into map-ready GeoJSON for Anansi.
 *
 * Two input shapes are accepted, because the sensor has no clock or GPS of its
 * own and the two field setups differ:
 *
 *  - **Live serial** — the Spider Sense sensor streams `SQW,*` text lines over
 *    the Flipper's GPIO UART (see SquachWatch docs/FLIPPER.md). The dev-server
 *    middleware (vite.config.js `flipperSerialProxy`) reads COM3, stamps each
 *    line with its arrival time, and appends a capture CSV.
 *  - **Capture / SD CSV** — that capture file, or a SquachWatch SD log
 *    (`ts,type,rssi,mac,channel,vendor,ssid`), imported after the fact.
 *
 * Location comes from outside the sensor: either a position the browser posts
 * while listening live, or a GPX track logged on a phone and timestamp-matched
 * to the detections here. Everything in this module is pure data — no Cesium,
 * no DOM — so it runs identically in the middleware and in unit tests.
 */

/** Canonical surveillance-device types, with map styling per type. */
export const DETECTION_TYPES = Object.freeze({
  FLOCK: { label: 'Flock camera', color: '#ff2d2d', icon: '◉' },
  ALPR: { label: 'Plate reader', color: '#ff5a1f', icon: '◉' },
  AXON: { label: 'Axon / LE', color: '#ffd21f', icon: '▮' },
  CAMERA: { label: 'Camera', color: '#ff2d2d', icon: '◉' },
  RING: { label: 'Ring', color: '#ff7ad0', icon: '◉' },
  DEAUTH: { label: 'Deauth flood', color: '#b026ff', icon: '✖' },
  EVILTWIN: { label: 'Evil twin AP', color: '#b026ff', icon: '⚑' },
  'EVIL TWIN': { label: 'Evil twin AP', color: '#b026ff', icon: '⚑' },
  HACKER: { label: 'Pentest gear', color: '#00e0ff', icon: '☠' },
  META: { label: 'Camera glasses', color: '#ff7ad0', icon: '◉' },
  SKIMMER: { label: 'BT skimmer', color: '#ff5a1f', icon: '▮' },
  AIRTAG: { label: 'Tracker', color: '#7affc0', icon: '◆' },
  TILE: { label: 'Tile tracker', color: '#7affc0', icon: '◆' },
  SAMSUNG_TAG: { label: 'SmartTag', color: '#7affc0', icon: '◆' },
  GOOGLE_TAG: { label: 'Find My Device', color: '#7affc0', icon: '◆' },
  DRONE: { label: 'Drone', color: '#00e0ff', icon: '✈' },
  RAVEN: { label: 'Gunshot sensor', color: '#ffd21f', icon: '▮' },
  IBEACON: { label: 'Beacon', color: '#8a8a8a', icon: '○' },
  UNKNOWN: { label: 'Unknown', color: '#8a8a8a', icon: '○' },
});

const DEFAULT_STYLE = DETECTION_TYPES.UNKNOWN;
const CONF_LABEL = { H: 'High', M: 'Medium', L: 'Low' };

/** Styling + friendly label for a detection type (case-insensitive). */
export function typeStyle(type) {
  if (!type) return DEFAULT_STYLE;
  return DETECTION_TYPES[String(type).toUpperCase()] || DEFAULT_STYLE;
}

/** Parse one epoch/ISO timestamp into epoch-ms, or null if unusable. */
export function toEpochMs(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Heuristic: seconds vs milliseconds (anything before year ~2001 in ms
    // is implausible for a field log, so treat small numbers as seconds).
    return value < 1e11 ? Math.round(value * 1000) : Math.round(value);
  }
  const s = String(value).trim();
  if (/^\d+$/.test(s)) return toEpochMs(Number(s));
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

/**
 * Parse one `SQW,DET,...` line into a detection, or null for any other line
 * (STAT/HELLO/OK/ERR/blank). The live line carries no timestamp — the caller
 * stamps `tMs` with arrival time.
 *
 * Shape: SQW,DET,<NEW|AGAIN|SEEN>,<type>,<conf>,<mac>,<rssi>,<ch>,<hits>,<vendor>,<name>
 */
export function parseSqwLine(line) {
  if (typeof line !== 'string') return null;
  const f = line.trim().split(',');
  if (f[0] !== 'SQW' || f[1] !== 'DET' || f.length < 11) return null;
  const rssi = Number(f[6]);
  const channel = Number(f[7]);
  const hits = Number(f[8]);
  return {
    what: f[2] || 'NEW',
    type: (f[3] || 'UNKNOWN').toUpperCase(),
    conf: (f[4] || 'L').toUpperCase().charAt(0),
    mac: (f[5] || '').toUpperCase(),
    rssi: Number.isFinite(rssi) ? rssi : null,
    channel: Number.isFinite(channel) ? channel : null,
    hits: Number.isFinite(hits) ? hits : 1,
    vendor: f[9] || '',
    // name may itself have been cleaned of commas by the sensor; re-join any
    // stragglers defensively so a stray comma never truncates it.
    name: f.slice(10).join(',') || '',
    tMs: null,
  };
}

/** Parse a `SQW,STAT,...` status line, or null. */
export function parseSqwStat(line) {
  if (typeof line !== 'string') return null;
  const f = line.trim().split(',');
  if (f[0] !== 'SQW' || f[1] !== 'STAT' || f.length < 9) return null;
  return {
    uptimeSec: Number(f[2]) || 0,
    framesPerSec: Number(f[3]) || 0,
    channel: Number(f[4]) || 0,
    hopping: f[5] === '1',
    running: f[6] === '1',
    total: Number(f[7]) || 0,
    dropped: Number(f[8]) || 0,
  };
}

/**
 * Parse a detections CSV. Tolerant of two header layouts:
 *   - capture:  ts,what,type,conf,mac,rssi,channel,hits,vendor,name
 *   - SD log:   ts,type,rssi,mac,channel,vendor,ssid
 * Column order is taken from the header row (case-insensitive); a file with no
 * recognizable header is rejected (returns []).
 */
export function parseDetectionsCsv(text) {
  if (typeof text !== 'string' || !text.trim()) return [];
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== '');
  if (!lines.length) return [];
  const header = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const known = ['ts', 'type', 'mac', 'rssi', 'channel', 'vendor', 'what', 'conf', 'hits', 'name', 'ssid'];
  if (!header.some((h) => known.includes(h))) return []; // not a header we know
  const idx = (names) => {
    for (const n of names) {
      const i = header.indexOf(n);
      if (i !== -1) return i;
    }
    return -1;
  };
  const col = {
    ts: idx(['ts', 'time', 'timestamp', 'when']),
    what: idx(['what', 'state']),
    type: idx(['type']),
    conf: idx(['conf', 'confidence']),
    mac: idx(['mac', 'bssid']),
    rssi: idx(['rssi']),
    channel: idx(['channel', 'ch']),
    hits: idx(['hits']),
    vendor: idx(['vendor']),
    name: idx(['name', 'ssid']),
  };
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const f = lines[i].split(',');
    const get = (c) => (c >= 0 && c < f.length ? f[c].trim() : '');
    const type = (get(col.type) || 'UNKNOWN').toUpperCase();
    if (!type) continue;
    const rssi = Number(get(col.rssi));
    const channel = Number(get(col.channel));
    const hits = Number(get(col.hits));
    out.push({
      what: get(col.what) || 'NEW',
      type,
      conf: (get(col.conf) || 'L').toUpperCase().charAt(0) || 'L',
      mac: get(col.mac).toUpperCase(),
      rssi: Number.isFinite(rssi) ? rssi : null,
      channel: Number.isFinite(channel) ? channel : null,
      hits: Number.isFinite(hits) ? hits : 1,
      vendor: get(col.vendor),
      name: get(col.name),
      tMs: toEpochMs(get(col.ts)),
    });
  }
  return out;
}

/**
 * Parse a GPX track into time-stamped points, sorted ascending by time.
 * Regex-based (no XML dependency); tolerant of attribute order and namespaces.
 * Returns [{tMs, lat, lon}].
 */
export function parseGpx(text) {
  if (typeof text !== 'string' || !text) return [];
  const pts = [];
  const re = /<trkpt\b([^>]*)>([\s\S]*?)<\/trkpt>|<trkpt\b([^>]*)\/>/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const attrs = m[1] || m[3] || '';
    const inner = m[2] || '';
    const lat = Number((attrs.match(/\blat\s*=\s*"([^"]+)"/i) || [])[1]);
    const lon = Number((attrs.match(/\blon\s*=\s*"([^"]+)"/i) || [])[1]);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    const timeStr = (inner.match(/<time>([^<]+)<\/time>/i) || [])[1];
    const tMs = toEpochMs(timeStr);
    if (tMs == null) continue;
    pts.push({ tMs, lat, lon });
  }
  pts.sort((a, b) => a.tMs - b.tMs);
  return pts;
}

/**
 * Assign a lat/lon to a time from a sorted GPX track by nearest-in-time match,
 * within `maxGapMs` (default 60 s). Returns {lat, lon} or null.
 */
export function locateAt(tMs, track, maxGapMs = 60000) {
  if (tMs == null || !Array.isArray(track) || track.length === 0) return null;
  // binary search for the insertion point
  let lo = 0;
  let hi = track.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (track[mid].tMs < tMs) lo = mid + 1;
    else hi = mid;
  }
  let best = track[lo];
  const prev = track[lo - 1];
  if (prev && Math.abs(prev.tMs - tMs) < Math.abs(best.tMs - tMs)) best = prev;
  if (Math.abs(best.tMs - tMs) > maxGapMs) return null;
  return { lat: best.lat, lon: best.lon };
}

/** One detection → a GeoJSON Point Feature at [lon, lat]. */
export function detectionToFeature(det, lonLat, index = 0) {
  const style = typeStyle(det.type);
  const whenIso = det.tMs != null ? new Date(det.tMs).toISOString() : null;
  const title = `${style.label}${det.vendor ? ` · ${det.vendor}` : ''}`;
  return {
    type: 'Feature',
    id: `${det.mac || 'det'}:${det.type}:${index}`,
    geometry: { type: 'Point', coordinates: [lonLat.lon, lonLat.lat] },
    properties: {
      name: title,
      detType: det.type,
      typeLabel: style.label,
      color: style.color,
      icon: style.icon,
      vendor: det.vendor || null,
      mac: det.mac || null,
      rssi: det.rssi,
      channel: det.channel,
      confidence: CONF_LABEL[det.conf] || 'Low',
      ssid: det.name || null,
      hits: det.hits,
      when: whenIso,
    },
  };
}

/**
 * Join detections to a GPX track and produce GeoJSON Features. Detections that
 * can't be located (no timestamp, or no track point within maxGapMs) are left
 * out and counted. If `fallback` {lat,lon} is given, unlocatable detections are
 * placed there instead of dropped (used for the live "stamp with current
 * browser position" path, where every detection shares one recent fix).
 *
 * @returns {{features:object[], located:number, dropped:number}}
 */
export function detectionsToFeatures(detections, { track = [], maxGapMs = 60000, fallback = null } = {}) {
  const features = [];
  let located = 0;
  let dropped = 0;
  detections.forEach((det, i) => {
    let pos = locateAt(det.tMs, track, maxGapMs);
    if (!pos && fallback && Number.isFinite(fallback.lat) && Number.isFinite(fallback.lon)) {
      pos = { lat: fallback.lat, lon: fallback.lon };
    }
    if (!pos) {
      dropped++;
      return;
    }
    located++;
    features.push(detectionToFeature(det, pos, i));
  });
  return { features, located, dropped };
}

/** Features → GeoJSON JSON-Lines text (one Feature per line), the form the
 *  local-GeoJSON layer loads. */
export function featuresToGeoJsonl(features) {
  return features.map((f) => JSON.stringify(f)).join('\n');
}

/** Convenience: CSV text + GPX text → GeoJSONL text. */
export function csvAndGpxToGeoJsonl(csvText, gpxText, opts = {}) {
  const detections = parseDetectionsCsv(csvText);
  const track = parseGpx(gpxText || '');
  const { features } = detectionsToFeatures(detections, { track, ...opts });
  return featuresToGeoJsonl(features);
}
