// Anansi: threat-intel feeds for the Cyber map layers.
//
//   GET /api/threat/<feed>   feed = feodo | abuseipdb | ransomware | ioda | ioda-us | cloudflare | shodan-ics | sundown
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
    ttl: 12 * 60 * MIN, // each refresh spends a Shodan query credit
    keyEnv: 'SHODAN_API_KEY',
    request: (e) => {
      const key = env('SHODAN_API_KEY', e);
      if (!key) return null;
      // Default: ICS/SCADA-tagged services within ~120 km of Norfolk.
      const query = env('SHODAN_ICS_QUERY', e) || 'tag:ics geo:"36.85,-76.29,120"';
      return { url: `https://api.shodan.io/shodan/host/search?${new URLSearchParams({ key, query, minify: 'true' })}`, headers: {}, redact: true };
    },
    normalize: normalizeShodan,
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

  async function load(name, feed) {
    const now = clock();
    if (feed.local) {
      const { points = [], total = 0, error = null, empty = false } = feed.local();
      return { feed: name, status: empty ? 'no-data' : 'ok', keyEnv: null, updatedAt: new Date(now).toISOString(), error, points, total };
    }
    const req = feed.request(envSource, now);
    if (!req) {
      return { feed: name, status: 'key-required', keyEnv: feed.keyEnv, updatedAt: null, error: `Set ${feed.keyEnv} in .env`, points: [], total: 0 };
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
    const { points, total } = feed.normalize(payload);
    return { feed: name, status: 'ok', keyEnv: feed.keyEnv, updatedAt: new Date(now).toISOString(), error: null, points, total };
  }

  async function get(name) {
    const feed = feeds[name];
    const cached = cache.get(name);
    if (cached && clock() - cached.at < feed.ttl) return cached.body;
    if (!inflight.has(name)) {
      inflight.set(
        name,
        load(name, feed)
          .then((body) => {
            if (['ok', 'key-required', 'no-data'].includes(body.status)) cache.set(name, { at: clock(), body });
            return body;
          })
          .catch((err) => {
            const message = err?.message || String(err);
            console.warn(`[threat-intel] ${message}${cached ? ' — serving last good data' : ''}`);
            if (cached) return { ...cached.body, status: 'stale', error: message };
            return { feed: name, status: 'error', keyEnv: feed.keyEnv, updatedAt: null, error: message, points: [], total: 0 };
          })
          .finally(() => inflight.delete(name)),
      );
    }
    return inflight.get(name);
  }

  return async function threatIntelMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    const name = String(req.url || '/').split('?')[0].replace(/^\/+|\/+$/g, '');
    if (!Object.hasOwn(feeds, name)) return send(404, { error: 'unknown feed', feeds: Object.keys(feeds) });
    try {
      return send(200, await get(name));
    } catch (err) {
      return send(500, { error: `threat-intel error: ${err?.message || err}` });
    }
  };
}

export function threatIntelProxy() {
  const middleware = createThreatIntelMiddleware();
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
