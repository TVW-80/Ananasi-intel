// Ananzi: extra worldwide public traffic-camera networks for the CCTV layer.
//
// One SSRF-safe, config-driven loader covers the two shapes official open-data
// camera feeds almost always use — a GeoJSON FeatureCollection, or a flat JSON
// array/table of camera records — so adding a country is one entry in
// WORLD_NETWORKS below plus its own env kill switch in catalog.js.
//
// These are cameras their operators publish for the public (road, traffic and
// city-view cameras from transport agencies), the same category as the packs
// already in catalog.js — never the misconfigured private cameras the attack
// map only ever counts.
//
// Safety posture matches the hand-written packs: image URLs must be https with
// no embedded credentials and a host on the network's own allow-list, the URL
// is rebuilt from its parsed parts so query tricks can't redirect it,
// coordinates are bounds-checked to the country, and ids are slugged.
import { CCTV_SOURCE_FETCH_TIMEOUT_MS } from './constants.js';
import {
  cameraDisplayCode,
  fallbackHeadingFromId,
  prioritizeSources,
} from './normalize.js';
import { readResponseJsonCapped } from '../common/http.js';

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_SOURCES = 160;
const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Read a dotted path ("a.b.0.c") out of a nested object; undefined if absent. */
export function dget(obj, path) {
  if (!path) return undefined;
  let cur = obj;
  for (const key of String(path).split('.')) {
    if (cur == null) return undefined;
    cur = cur[key];
  }
  return cur;
}

const num = (v) => {
  const n = typeof v === 'number' ? v : Number(String(v ?? '').trim());
  return Number.isFinite(n) ? n : NaN;
};

/** host === allowed, or a subdomain of it. */
function hostAllowed(hostname, hosts) {
  const h = String(hostname || '').toLowerCase();
  return hosts.some((a) => {
    const base = String(a).toLowerCase();
    return h === base || h.endsWith(`.${base}`);
  });
}

/**
 * Validate and rebuild a candidate image URL. Returns the safe href, or ''.
 * https only, no userinfo, host on the allow-list; rebuilt from origin +
 * pathname + search so nothing in the original can smuggle a different target.
 */
export function safeImageUrl(raw, hosts) {
  let url;
  try {
    url = new URL(String(raw ?? ''));
  } catch {
    return '';
  }
  if (url.protocol !== 'https:' || url.username || url.password) return '';
  if (!hostAllowed(url.hostname, hosts)) return '';
  return `${url.origin}${url.pathname}${url.search}`;
}

/** Fill {id} / {field} placeholders from the raw record (id already validated). */
function fillTemplate(template, id, item) {
  return String(template).replace(/\{([A-Za-z0-9_.]+)\}/g, (_, key) => {
    if (key === 'id') return id;
    const v = dget(item, key);
    return v == null ? '' : String(v);
  });
}

/** Rows out of whichever shape the feed uses. */
export function extractRows(payload, net) {
  if (net.arrayPath) {
    const at = dget(payload, net.arrayPath);
    return Array.isArray(at) ? at : [];
  }
  if (net.shape === 'geojson') {
    return Array.isArray(payload?.features) ? payload.features : [];
  }
  if (Array.isArray(payload)) return payload;
  // A bare object keyed by id (some agencies do this).
  if (payload && typeof payload === 'object') return Object.values(payload);
  return [];
}

/** One feed record → a normalized CCTV source, or null when it can't be trusted. */
export function worldCameraToSource(row, net) {
  if (!row || typeof row !== 'object') return null;
  const props = net.shape === 'geojson' ? row.properties || {} : row;

  let lat;
  let lon;
  if (net.shape === 'geojson') {
    const c = row.geometry?.coordinates;
    if (!Array.isArray(c) || c.length < 2) return null;
    lon = num(c[0]);
    lat = num(c[1]);
  } else {
    lat = num(dget(props, net.latField));
    lon = num(dget(props, net.lonField));
  }
  const b = net.bounds;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (b && (lat < b.latMin || lat > b.latMax || lon < b.lonMin || lon > b.lonMax)) return null;

  const rawId = String(dget(props, net.idField) ?? '').trim();
  if (!ID_RE.test(rawId)) return null;
  const slug = rawId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  if (!slug) return null;
  const cameraId = `${net.id}-${slug}`;

  const candidate = net.imageTemplate
    ? fillTemplate(net.imageTemplate, rawId, props)
    : dget(props, net.imageField);
  const imageUrl = safeImageUrl(candidate, net.imageHosts);
  if (!imageUrl) return null;

  const name =
    (net.nameFields || [])
      .map((f) => dget(props, f))
      .filter((v) => v != null && String(v).trim() !== '')
      .join(net.nameJoin || ' · ')
      .trim()
      .slice(0, 160) || `${net.provider} ${rawId}`;

  return {
    id: cameraId,
    name,
    city: net.label,
    cityId: net.cityId,
    provider: net.provider,
    lat,
    lon,
    // No calibrated pose in these feeds; the app's low-confidence prior, like
    // the Lithuania / Norway packs.
    headingDeg: fallbackHeadingFromId(cameraId),
    headingConfidence: 'low',
    pitchDeg: -18,
    fovDeg: 44,
    rangeM: 145,
    mountHeightM: 8,
    feedType: 'image',
    url: imageUrl,
    snapshotUrl: imageUrl,
    sourceKind: net.sourceKind || `${net.id}-open`,
    credit: net.license,
    code: cameraDisplayCode(name.toUpperCase()),
  };
}

/** Fetch + normalize one network. Independent failure → []. */
export function makeWorldLoader(net) {
  return async function loadWorldPack() {
    try {
      const endpoint = process.env[`CCTV_${net.id.toUpperCase()}_URL`] || net.url;
      const resp = await fetch(endpoint, {
        headers: { Accept: 'application/geo+json,application/json;q=0.9,*/*;q=0.5' },
        redirect: 'manual',
        signal: AbortSignal.timeout(CCTV_SOURCE_FETCH_TIMEOUT_MS),
      });
      if (resp.status >= 300 && resp.status < 400) {
        try {
          await resp.body?.cancel();
        } catch {
          /* no-op */
        }
        console.warn(`[CCTV] ${net.id} redirected; redirects are not followed`);
        return [];
      }
      if (!resp.ok) {
        console.warn(`[CCTV] ${net.id} camera download failed:`, resp.status);
        try {
          await resp.body?.cancel();
        } catch {
          /* no-op */
        }
        return [];
      }
      const payload = await readResponseJsonCapped(resp, net.maxBytes || DEFAULT_MAX_BYTES);
      const rows = extractRows(payload, net);
      const cameras = [];
      const seen = new Set();
      for (const row of rows) {
        const cam = worldCameraToSource(row, net);
        if (!cam || seen.has(cam.id)) continue;
        seen.add(cam.id);
        cameras.push(cam);
      }
      const maxRaw = Number(process.env[`CCTV_${net.id.toUpperCase()}_MAX_SOURCES`] || net.maxSources || DEFAULT_MAX_SOURCES);
      const maxCount = Number.isFinite(maxRaw) ? Math.max(8, Math.min(1000, Math.floor(maxRaw))) : DEFAULT_MAX_SOURCES;
      const prioritized = prioritizeSources(cameras, maxCount, net.anchors || []);
      console.log(`[CCTV] Loaded ${net.id} camera sources: ${cameras.length} (using nearest ${prioritized.length})`);
      return prioritized;
    } catch (error) {
      console.warn(`[CCTV] ${net.id} camera download error:`, error?.message || error);
      return [];
    }
  };
}

/**
 * Worldwide official traffic-camera networks.
 *
 * `defaultOn` packs carry an open-government or Creative-Commons licence that
 * plainly allows reuse; everything else is `optIn` (loads only when its env
 * flag is set to 1) until its terms are confirmed — the same stance catalog.js
 * already takes for Lithuania, NYC and Florida. Endpoint shapes are the public
 * documented ones; a feed whose live shape differs simply yields no cameras
 * (fails independently) rather than breaking the layer.
 */
export const WORLD_NETWORKS = Object.freeze([
  {
    id: 'nzta',
    label: 'New Zealand',
    cityId: 'new-zealand',
    provider: 'NZTA Waka Kotahi',
    defaultOn: true,
    shape: 'array',
    arrayPath: 'response.cameras.camera',
    url: 'https://trafficnz.info/service/traffic/rest/4/cameras/all',
    idField: 'id',
    nameFields: ['name', 'description'],
    latField: 'lat',
    lonField: 'long',
    imageField: 'imageUrl',
    imageHosts: ['trafficnz.info'],
    bounds: { latMin: -48.5, latMax: -33.5, lonMin: 166, lonMax: 179.5 },
    license: 'NZTA Waka Kotahi open traffic-camera data (CC BY 4.0)',
    anchors: [
      { lat: -36.8485, lon: 174.7633 }, // Auckland
      { lat: -41.2866, lon: 174.7756 }, // Wellington
      { lat: -43.532, lon: 172.6306 }, // Christchurch
      { lat: -37.787, lon: 175.2793 }, // Hamilton
      { lat: -45.8788, lon: 170.5028 }, // Dunedin
    ],
  },
  {
    id: 'scotland',
    label: 'Scotland',
    cityId: 'scotland',
    provider: 'Traffic Scotland',
    optIn: true, // open-data terms for the camera images not yet confirmed
    shape: 'geojson',
    url: 'https://trafficscotland.org/rss/feeds/cameras.aspx',
    idField: 'id',
    nameFields: ['name', 'road'],
    imageField: 'image',
    imageHosts: ['trafficscotland.org'],
    bounds: { latMin: 54.5, latMax: 61, lonMin: -8.7, lonMax: -0.5 },
    license: 'Traffic Scotland road cameras',
    anchors: [
      { lat: 55.9533, lon: -3.1883 }, // Edinburgh
      { lat: 55.8642, lon: -4.2518 }, // Glasgow
      { lat: 57.1497, lon: -2.0943 }, // Aberdeen
      { lat: 56.462, lon: -2.9707 }, // Dundee
    ],
  },
  {
    id: 'ireland',
    label: 'Ireland / Éire',
    cityId: 'ireland',
    provider: 'Transport Infrastructure Ireland',
    optIn: true,
    shape: 'geojson',
    url: 'https://www.tiitraffic.ie/api/cameras',
    idField: 'id',
    nameFields: ['name', 'route'],
    imageField: 'imageUrl',
    imageHosts: ['tiitraffic.ie'],
    bounds: { latMin: 51.3, latMax: 55.5, lonMin: -10.7, lonMax: -5.3 },
    license: 'Transport Infrastructure Ireland traffic cameras',
    anchors: [
      { lat: 53.3498, lon: -6.2603 }, // Dublin
      { lat: 51.8985, lon: -8.4756 }, // Cork
      { lat: 53.2707, lon: -9.0568 }, // Galway
      { lat: 52.6638, lon: -8.6267 }, // Limerick
    ],
  },
  {
    id: 'utah',
    label: 'Utah (UDOT)',
    cityId: 'utah',
    provider: 'Utah DOT',
    optIn: true, // UDOT Traffic terms limit reuse; opt in once confirmed
    shape: 'array',
    url: 'https://www.udottraffic.utah.gov/api/v2/get/cameras',
    idField: 'Id',
    nameFields: ['Location', 'Roadway'],
    latField: 'Latitude',
    lonField: 'Longitude',
    imageField: 'Views.0.Url',
    imageHosts: ['udottraffic.utah.gov'],
    bounds: { latMin: 37, latMax: 42, lonMin: -114.1, lonMax: -109 },
    license: 'Utah DOT (UDOT Traffic)',
    anchors: [
      { lat: 40.7608, lon: -111.891 }, // Salt Lake City
      { lat: 40.2338, lon: -111.6585 }, // Provo
      { lat: 37.0965, lon: -113.5684 }, // St. George
      { lat: 41.223, lon: -111.9738 }, // Ogden
    ],
  },
  {
    id: 'iowa',
    label: 'Iowa (Iowa DOT)',
    cityId: 'iowa',
    provider: 'Iowa DOT',
    optIn: true,
    shape: 'geojson',
    url: 'https://data.iowadot.gov/datasets/iowadot::cameras.geojson',
    idField: 'CAMERAID',
    nameFields: ['NAME', 'ROUTE'],
    imageField: 'IMAGEURL',
    imageHosts: ['iowadot.gov', 'iowadot.us'],
    bounds: { latMin: 40.3, latMax: 43.6, lonMin: -96.7, lonMax: -90.1 },
    license: 'Iowa DOT open data',
    anchors: [
      { lat: 41.5868, lon: -93.625 }, // Des Moines
      { lat: 41.6611, lon: -91.5302 }, // Iowa City
      { lat: 42.4963, lon: -92.3426 }, // Waterloo
      { lat: 41.5236, lon: -90.5776 }, // Davenport
    ],
  },
]);

/** LIVE_PACKS entries for every world network (registered in catalog.js). */
export function worldPacks() {
  return WORLD_NETWORKS.map((net) => {
    const flag = `CCTV_${net.id.toUpperCase()}_ENABLED`;
    return {
      name: net.id,
      enabled: () =>
        net.optIn
          ? String(process.env[flag] || '').trim() === '1'
          : String(process.env[flag] || '1').trim() !== '0',
      load: makeWorldLoader(net),
    };
  });
}

// ── TravelIQ 511 platform (keyed; BYOK) ──────────────────────────────────────
// Many US state 511 systems run on the same TravelIQ platform, which exposes
// GET /api/v2/get/cameras?key=<KEY>&format=json — a flat array of cameras, each
// with Id, Location, Roadway, Direction, Latitude, Longitude and a Views[] list
// whose Url is the live snapshot on the agency's own host. The key is free but
// personal (you register for it), and the terms typically limit reuse to your
// own use, so these packs are BYOK: a pack makes no request until you put its
// key in .env (CCTV_<ID>_KEY), and CCTV_<ID>_ENABLED=0 forces it off anyway.
const VIEW_STATUS_OK = new Set(['', 'enabled', 'active', 'online', 'ok']);

/** One TravelIQ camera record → a normalized source, or null. */
export function travelIqCameraToSource(cam, net) {
  if (!cam || typeof cam !== 'object') return null;
  const lat = num(cam.Latitude);
  const lon = num(cam.Longitude);
  const b = net.bounds;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (b && (lat < b.latMin || lat > b.latMax || lon < b.lonMin || lon > b.lonMax)) return null;

  const rawId = String(cam.Id ?? cam.SourceId ?? '').trim();
  if (!ID_RE.test(rawId)) return null;
  const cameraId = `${net.id}-${rawId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')}`;

  const views = Array.isArray(cam.Views) ? cam.Views : [];
  let imageUrl = '';
  for (const v of views) {
    const status = String(v?.Status ?? '').trim().toLowerCase();
    if (!VIEW_STATUS_OK.has(status)) continue;
    const safe = safeImageUrl(v?.Url, net.imageHosts);
    if (safe) {
      imageUrl = safe;
      break;
    }
  }
  if (!imageUrl) return null;

  const dir = String(cam.Direction ?? '').trim();
  const name =
    [String(cam.Location ?? '').trim(), String(cam.Roadway ?? '').trim(), dir && dir !== 'Unknown' && dir !== 'None' ? dir : '']
      .filter(Boolean)
      .join(' · ')
      .slice(0, 160) || `${net.provider} ${rawId}`;

  return {
    id: cameraId,
    name,
    city: net.label,
    cityId: net.cityId,
    provider: net.provider,
    lat,
    lon,
    headingDeg: fallbackHeadingFromId(cameraId),
    headingConfidence: 'low',
    pitchDeg: -18,
    fovDeg: 44,
    rangeM: 145,
    mountHeightM: 8,
    feedType: 'image',
    url: imageUrl,
    snapshotUrl: imageUrl,
    sourceKind: 'traveliq-511',
    credit: net.license,
    code: cameraDisplayCode(name.toUpperCase()),
  };
}

export function makeTravelIqLoader(net) {
  return async function loadTravelIqPack() {
    const key = String(process.env[`CCTV_${net.id.toUpperCase()}_KEY`] || '').trim();
    if (!key) return []; // BYOK: nothing to fetch without the operator's own key
    try {
      const base = process.env[`CCTV_${net.id.toUpperCase()}_URL`] || net.url;
      const endpoint = `${base}?${new URLSearchParams({ key, format: 'json' })}`;
      const resp = await fetch(endpoint, {
        headers: { Accept: 'application/json' },
        redirect: 'manual',
        signal: AbortSignal.timeout(CCTV_SOURCE_FETCH_TIMEOUT_MS),
      });
      if (!resp.ok || (resp.status >= 300 && resp.status < 400)) {
        try {
          await resp.body?.cancel();
        } catch {
          /* no-op */
        }
        console.warn(`[CCTV] ${net.id} camera download failed:`, resp.status);
        return [];
      }
      const payload = await readResponseJsonCapped(resp, net.maxBytes || DEFAULT_MAX_BYTES);
      const rows = Array.isArray(payload) ? payload : Array.isArray(payload?.Cameras) ? payload.Cameras : [];
      const cameras = [];
      const seen = new Set();
      for (const cam of rows) {
        const source = travelIqCameraToSource(cam, net);
        if (!source || seen.has(source.id)) continue;
        seen.add(source.id);
        cameras.push(source);
      }
      const maxRaw = Number(process.env[`CCTV_${net.id.toUpperCase()}_MAX_SOURCES`] || net.maxSources || DEFAULT_MAX_SOURCES);
      const maxCount = Number.isFinite(maxRaw) ? Math.max(8, Math.min(2000, Math.floor(maxRaw))) : DEFAULT_MAX_SOURCES;
      const prioritized = prioritizeSources(cameras, maxCount, net.anchors || []);
      console.log(`[CCTV] Loaded ${net.id} camera sources: ${cameras.length} (using nearest ${prioritized.length})`);
      return prioritized;
    } catch (error) {
      console.warn(`[CCTV] ${net.id} camera download error:`, error?.message || error);
      return [];
    }
  };
}

export const TRAVELIQ_NETWORKS = Object.freeze([
  {
    id: 'virginia',
    label: 'Virginia (VDOT 511)',
    cityId: 'virginia',
    provider: 'Virginia DOT · 511Virginia',
    url: 'https://www.nvroads.com/api/v2/get/cameras',
    imageHosts: ['nvroads.com', '511virginia.org'],
    bounds: { latMin: 36.5, latMax: 39.5, lonMin: -83.7, lonMax: -75.2 },
    license: 'Virginia DOT 511 (VDOT) — used under your own 511Virginia developer key',
    maxSources: 400,
    anchors: [
      { lat: 36.8508, lon: -76.2859 }, // Norfolk / Hampton Roads
      { lat: 37.5407, lon: -77.436 }, // Richmond
      { lat: 38.8816, lon: -77.0910 }, // Northern Virginia / Arlington
      { lat: 37.2707, lon: -76.7075 }, // Williamsburg
      { lat: 37.2296, lon: -80.4139 }, // Blacksburg / Roanoke area
    ],
  },
  {
    id: 'arizona',
    label: 'Arizona (AZ511)',
    cityId: 'arizona',
    provider: 'Arizona DOT · AZ511',
    url: 'https://az511.com/api/v2/get/cameras',
    imageHosts: ['az511.com'],
    bounds: { latMin: 31.2, latMax: 37.1, lonMin: -114.9, lonMax: -108.9 },
    license: 'Arizona DOT (AZ511) — used under your own AZ511 developer key',
    maxSources: 400,
    anchors: [
      { lat: 33.4484, lon: -112.074 }, // Phoenix
      { lat: 32.2226, lon: -110.9747 }, // Tucson
      { lat: 35.1983, lon: -111.6513 }, // Flagstaff
      { lat: 32.6927, lon: -114.6277 }, // Yuma
    ],
  },
  {
    id: 'ncarolina',
    label: 'North Carolina (DriveNC)',
    cityId: 'north-carolina',
    provider: 'NCDOT · DriveNC',
    url: 'https://drivenc.gov/api/v2/get/cameras',
    imageHosts: ['drivenc.gov', 'ncdot.gov', 'traveliq.co'],
    bounds: { latMin: 33.7, latMax: 36.7, lonMin: -84.4, lonMax: -75.3 },
    license: 'NCDOT (DriveNC) — used under your own DriveNC developer key',
    maxSources: 400,
    anchors: [
      { lat: 35.7796, lon: -78.6382 }, // Raleigh
      { lat: 35.2271, lon: -80.8431 }, // Charlotte
      { lat: 36.0726, lon: -79.792 }, // Greensboro
      { lat: 35.5951, lon: -82.5515 }, // Asheville
      { lat: 34.2257, lon: -77.9447 }, // Wilmington
    ],
  },
]);

/** LIVE_PACKS entries for the TravelIQ states. Enabled when a key is present. */
export function travelIqPacks() {
  return TRAVELIQ_NETWORKS.map((net) => {
    const flag = `CCTV_${net.id.toUpperCase()}_ENABLED`;
    const keyEnv = `CCTV_${net.id.toUpperCase()}_KEY`;
    return {
      name: net.id,
      enabled: () =>
        String(process.env[keyEnv] || '').trim() !== '' &&
        String(process.env[flag] || '1').trim() !== '0',
      load: makeTravelIqLoader(net),
    };
  });
}
