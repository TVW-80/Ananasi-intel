// Anansi: threat-intel feeds for the Cyber map layers.
//
//   GET /api/threat/<feed>?focus=world|757
//        feed = feodo | abuseipdb | ransomware | ioda | ioda-us | cloudflare | shodan-ics | shodan-cameras | sundown
//   `focus` only changes the Shodan feeds (focusAware): WORLD asks Shodan's
//   credit-free count API per country, 757 searches around Norfolk. Every
//   other feed is filtered by focus in the browser.
//
// Each response is { feed, status, updatedAt, error, keyEnv, points, total }:
//   status 'ok'           fresh data
//   status 'stale'        upstream failed; last good points are served
//   status 'key-required' the feed needs a key that isn't in .env (no request made)
//   status 'error'        upstream failed and there is nothing cached yet
//
// Keys stay on the server. Responses are cached per feed (TTL below) and
// refreshes are single-flight, so many layers / tabs cost one upstream call.
import {
  normalizeAbuseIpdb,
  normalizeCloudflareOutages,
  normalizeFeodo,
  normalizeIoda,
  normalizeRansomware,
  normalizeShodan,
  normalizeShodanFacets,
} from './threat-feeds.js';
import { loadSundownFeed } from './sundown.js';

const USER_AGENT = 'Anansi/1.0 (personal threat-intel dashboard)';
const TIMEOUT_MS = 30_000;
const MAX_BYTES = 25 * 1024 * 1024;
const MIN = 60_000;

const env = (name, e) => String(e[name] || '').trim();

/** Feed table. `request(e, now)` returns {url, headers} or null when its key is missing. */
export const FEEDS = Object.freeze({
  // Local research file (no network) — see server/providers/anansi/sundown.js.
  sundown: {
    ttl: 60_000,
    keyEnv: null,
    local: loadSundownFeed,
  },
  feodo: {
    ttl: 30 * MIN,
    keyEnv: null, // abuse.ch downloads are keyless; ABUSECH_AUTH_KEY is sent if you set one
    request: (e) => ({
      url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
      headers: env('ABUSECH_AUTH_KEY', e) ? { 'Auth-Key': env('ABUSECH_AUTH_KEY', e) } : {},
    }),
    normalize: normalizeFeodo,
  },
  abuseipdb: {
    ttl: 6 * 60 * MIN, // free plan: 5 blacklist calls/day
    keyEnv: 'ABUSEIPDB_API_KEY',
    request: (e) =>
      env('ABUSEIPDB_API_KEY', e) && {
        url: 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000',
        headers: { Key: env('ABUSEIPDB_API_KEY', e), Accept: 'application/json' },
      },
    normalize: normalizeAbuseIpdb,
  },
  ransomware: {
    ttl: 60 * MIN,
    keyEnv: null,
    request: () => ({ url: 'https://api.ransomware.live/v2/recentvictims', headers: {} }),
    normalize: normalizeRansomware,
  },
  ioda: {
    ttl: 15 * MIN,
    keyEnv: null,
    request: (_e, now) => ({ url: iodaSummaryUrl(now, { entityType: 'country' }), headers: {} }),
    normalize: (p) => normalizeIoda(p, { level: 'country' }),
  },
  'ioda-us': {
    ttl: 15 * MIN,
    keyEnv: null,
    request: (_e, now) => ({ url: iodaSummaryUrl(now, { entityType: 'region', relatedTo: 'country/US' }), headers: {} }),
    normalize: (p) => normalizeIoda(p, { level: 'us-state' }),
  },
  cloudflare: {
    ttl: 30 * MIN,
    keyEnv: 'CLOUDFLARE_API_TOKEN',
    request: (e) =>
      env('CLOUDFLARE_API_TOKEN', e) && {
        url: 'https://api.cloudflare.com/client/v4/radar/annotations/outages?dateRange=7d&limit=100&format=json',
        headers: { Authorization: `Bearer ${env('CLOUDFLARE_API_TOKEN', e)}` },
      },
    normalize: normalizeCloudflareOutages,
  },
  'shodan-ics': {
    ttl: 12 * 60 * MIN, // a 757 refresh spends a Shodan query credit; WORLD uses the free count API
    keyEnv: 'SHODAN_API_KEY',
    focusAware: true,
    request: (e, _now, focus) => {
      const key = env('SHODAN_API_KEY', e);
      if (!key) return null;
      // Default is the free count API in every focus — no query credits, no
      // paid membership. Only SHODAN_EXPOSURE_SEARCH=1 opts into the paid
      // host/search that pins exact systems near Norfolk.
      const exactPoints = focus === '757' && env('SHODAN_EXPOSURE_SEARCH', e) === '1';
      if (exactPoints) {
        const query = env('SHODAN_ICS_QUERY', e) || 'tag:ics geo:"36.85,-76.29,120"';
        return { url: `https://api.shodan.io/shodan/host/search?${new URLSearchParams({ key, query, minify: 'true' })}`, headers: {}, redact: true };
      }
      if (focus === '757') {
        const query = `${env('SHODAN_ICS_WORLD_QUERY', e) || 'tag:ics'} geo:"36.85,-76.29,120"`;
        return { url: `https://api.shodan.io/shodan/host/count?${new URLSearchParams({ key, query, facets: 'city:40' })}`, headers: {}, redact: true, countFacet: 'city' };
      }
      const query = env('SHODAN_ICS_WORLD_QUERY', e) || 'tag:ics';
      return { url: `https://api.shodan.io/shodan/host/count?${new URLSearchParams({ key, query, facets: 'country:100' })}`, headers: {}, redact: true, countFacet: 'country' };
    },
    // Branch on the payload shape, so this never depends on env: host/search
    // returns `matches`, host/count returns `facets`.
    normalize: (p, focus) =>
      Array.isArray(p?.matches)
        ? normalizeShodan(p)
        : normalizeShodanFacets(p, { kind: 'ics', facet: focus === '757' ? 'city' : 'country' }),
  },
  'shodan-cameras': {
    ttl: 12 * 60 * MIN, // count API: no query credits
    keyEnv: 'SHODAN_API_KEY',
    focusAware: true,
    request: (e, _now, focus) => {
      const key = env('SHODAN_API_KEY', e);
      if (!key) return null;
      const base = env('SHODAN_CAMERA_QUERY', e) || 'screenshot.label:webcam';
      const query = focus === '757' ? `${base} geo:"36.85,-76.29,120"` : base;
      const facets = focus === '757' ? 'city:40' : 'country:100';
      return { url: `https://api.shodan.io/shodan/host/count?${new URLSearchParams({ key, query, facets })}`, headers: {}, redact: true };
    },
    normalize: (p, focus) => normalizeShodanFacets(p, { kind: 'cameras', facet: focus === '757' ? 'city' : 'country' }),
  },
});

export function iodaSummaryUrl(now, { entityType, relatedTo }) {
  const until = Math.floor(now / 1000);
  const params = new URLSearchParams({ from: String(until - 86_400), until: String(until), entityType, limit: '100' });
  if (relatedTo) params.set('relatedTo', relatedTo);
  return `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary?${params}`;
}

export function createThreatIntelMiddleware({
  fetchImpl = (...a) => fetch(...a),
  envSource = process.env,
  clock = Date.now,
  feeds = FEEDS,
} = {}) {
  const cache = new Map(); // feed -> { at, body }
  const inflight = new Map();

  async function load(name, feed, focus) {
    const now = clock();
    if (feed.local) {
      const { points = [], total = 0, error = null, empty = false } = feed.local();
      return { feed: name, status: empty ? 'no-data' : 'ok', keyEnv: null, updatedAt: new Date(now).toISOString(), error, points, total };
    }
    const req = feed.request(envSource, now, focus);
    if (!req) {
      return { feed: name, status: 'key-required', keyEnv: feed.keyEnv, updatedAt: null, error: `Needs ${feed.keyEnv} — paste it in POWER UP (bottom-right chip)`, points: [], total: 0 };
    }
    const label = req.redact ? `${name} upstream` : req.url;
    let res;
    try {
      res = await fetchImpl(req.url, {
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json', ...req.headers },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      throw new Error(`${name}: ${err?.cause?.code || err?.name || 'fetch failed'}`);
    }
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}${res.status === 401 || res.status === 403 ? ' (check the key)' : ''}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error(`${name}: response too large`);
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`${name}: non-JSON response from ${req.redact ? label : new URL(req.url).host}`);
    }
    const { points, total } = feed.normalize(payload, focus);
    return { feed: name, status: 'ok', keyEnv: feed.keyEnv, updatedAt: new Date(now).toISOString(), error: null, points, total };
  }

  async function get(name, focusParam = 'world') {
    const feed = feeds[name];
    const focus = feed.focusAware && focusParam === '757' ? '757' : 'world';
    const cacheKey = feed.focusAware ? `${name}:${focus}` : name;
    const cached = cache.get(cacheKey);
    if (cached && clock() - cached.at < feed.ttl) return cached.body;
    if (!inflight.has(cacheKey)) {
      inflight.set(
        cacheKey,
        load(name, feed, focus)
          .then((body) => {
            if (feed.focusAware) body.focused = true;
            // key-required is never cached: a key pasted in POWER UP lands in
            // process.env live and must take effect on the very next poll.
            if (['ok', 'no-data'].includes(body.status)) cache.set(cacheKey, { at: clock(), body });
            return body;
          })
          .catch((err) => {
            const message = err?.message || String(err);
            console.warn(`[threat-intel] ${message}${cached ? ' — serving last good data' : ''}`);
            if (cached) return { ...cached.body, status: 'stale', error: message };
            return { feed: name, status: 'error', keyEnv: feed.keyEnv, updatedAt: null, error: message, points: [], total: 0 };
          })
          .finally(() => inflight.delete(cacheKey)),
      );
    }
    return inflight.get(cacheKey);
  }

  async function threatIntelMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    const [rawPath, query = ''] = String(req.url || '/').split('?');
    const name = rawPath.replace(/^\/+|\/+$/g, '');
    const focus = new URLSearchParams(query).get('focus') === '757' ? '757' : 'world';
    if (!Object.hasOwn(feeds, name)) return send(404, { error: 'unknown feed', feeds: Object.keys(feeds) });
    try {
      return send(200, await get(name, focus));
    } catch (err) {
      return send(500, { error: `threat-intel error: ${err?.message || err}` });
    }
  }
  /** Other Anansi providers (the attack map) read feeds through the same cache. */
  threatIntelMiddleware.get = (name, focus) => (Object.hasOwn(feeds, name) ? get(name, focus) : Promise.resolve(null));
  return threatIntelMiddleware;
}

let _shared = null;
/** One process-wide instance, so the Cyber layers and the attack map share upstream calls and quotas. */
export function sharedThreatIntel() {
  _shared ??= createThreatIntelMiddleware();
  return _shared;
}

export function threatIntelProxy() {
  const middleware = sharedThreatIntel();
  return {
    name: 'anansi-threat-intel',
    configureServer(server) {
      server.middlewares.use('/api/threat', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/threat', middleware);
    },
  };
}
