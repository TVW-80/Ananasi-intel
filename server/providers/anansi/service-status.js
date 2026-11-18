// Anansi: SERVICE STATUS aggregator. The honest, keyless stand-in for
// Downdetector — it fans out to major providers' statuspage.io v2 "summary"
// endpoints, normalises each into operational / degraded / down with any active
// incidents, and serves one cached snapshot. Modelled on cyber-news.js: every
// provider degrades on its own, last-good records are kept, and it's keyless so
// it just works on the owner's machine.
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  STATUSPAGE_PROVIDERS,
  summaryUrl,
  parseSummary,
  assembleServiceStatus,
} from '../../../src/data/serviceStatus.js';

const USER_AGENT = 'Ananzi/0.3 (+service-status; personal research)';
const MAX_BYTES = 2_000_000;
const TTL_MS = 3 * 60_000; // status changes fast; refresh at most every 3 min
const DEGRADED_TTL_MS = 60_000; // retry a degraded fetch sooner

export function createServiceStatusMiddleware({
  fetchImpl = (...args) => fetch(...args),
  clock = () => Date.now(),
  cachePath = path.join(process.cwd(), '.gev-cache', 'service-status.json'),
  ttlMs = TTL_MS,
  degradedTtlMs = DEGRADED_TTL_MS,
  providers = STATUSPAGE_PROVIDERS,
} = {}) {
  let state = null;
  let inflight = null;

  const fetchJson = async (url) => {
    let res;
    try {
      res = await fetchImpl(url, {
        redirect: 'follow',
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json, */*' },
      });
    } catch (err) {
      const cause = err?.cause?.code || err?.cause?.message;
      throw new Error(`${err?.message || 'fetch failed'}${cause ? ` [${cause}]` : ''}`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('response too large');
    return JSON.parse(text);
  };

  const SOURCES = providers.map((provider) => ({
    ...provider,
    fetch: async () => parseSummary(await fetchJson(summaryUrl(provider.host)), provider),
  }));

  async function readDisk() {
    if (!cachePath) return null;
    try {
      const parsed = JSON.parse(await fsp.readFile(cachePath, 'utf8'));
      if (Number.isFinite(parsed?.at) && parsed?.snapshot && parsed?.perSource) return parsed;
    } catch { /* no disk cache yet */ }
    return null;
  }

  async function writeDisk(next) {
    if (!cachePath) return;
    try {
      await fsp.mkdir(path.dirname(cachePath), { recursive: true });
      await fsp.writeFile(cachePath, JSON.stringify(next), 'utf8');
    } catch (err) {
      console.warn('[service-status] cache write failed:', err?.message || err);
    }
  }

  const isFresh = (entry) => {
    const degraded = entry.snapshot.sources.some((s) => !s.ok);
    return clock() - entry.at < (degraded ? degradedTtlMs : ttlMs);
  };

  async function refresh(previous) {
    const now = clock();
    const results = await Promise.allSettled(SOURCES.map((s) => s.fetch()));
    const perSource = { ...(previous?.perSource || {}) };
    const sources = [];
    results.forEach((result, index) => {
      const { id, label } = SOURCES[index];
      if (result.status === 'fulfilled') {
        perSource[id] = { at: now, record: result.value };
        sources.push({ id, label, ok: true, at: now });
      } else {
        const reason = result.reason?.message || String(result.reason);
        console.warn(`[service-status] ${id} failed (${reason})${perSource[id] ? ' — keeping last-good' : ''}`);
        sources.push({ id, label, ok: false, stale: Boolean(perSource[id]), at: perSource[id]?.at || null, error: reason });
      }
    });
    if (!sources.some((s) => s.ok)) throw new Error('every status source failed');
    const records = SOURCES.map((s) => perSource[s.id]?.record).filter(Boolean);
    const snapshot = { ...assembleServiceStatus({ records, now }), sources };
    return { at: now, snapshot, perSource };
  }

  return async function serviceStatusMiddleware(req, res) {
    const send = (status, body, cacheStatus) => {
      if (res.headersSent) return;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'x-service-status-cache': cacheStatus,
      });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') {
      send(405, { error: 'method not allowed' }, 'NONE');
      return;
    }
    try {
      if (!state) state = await readDisk();
      if (state && isFresh(state)) {
        send(200, state.snapshot, 'HIT');
        return;
      }
      if (!inflight) {
        const previous = state;
        inflight = refresh(previous)
          .then(async (fresh) => {
            state = fresh;
            await writeDisk(fresh);
            return fresh;
          })
          .catch((err) => {
            console.warn(`[service-status] refresh failed (${err?.message || err}) — serving cache if any`);
            return null;
          })
          .finally(() => { inflight = null; });
      }
      const fresh = await inflight;
      if (fresh) send(200, fresh.snapshot, 'MISS');
      else if (state) send(200, state.snapshot, 'STALE-ERROR');
      else send(502, { error: 'status sources unavailable and no cache yet' }, 'NONE');
    } catch (err) {
      send(500, { error: `service-status proxy error: ${err?.message || err}` }, 'ERROR');
    }
  };
}

export function serviceStatusProxy() {
  const middleware = createServiceStatusMiddleware();
  return {
    name: 'service-status-proxy',
    configureServer(server) {
      server.middlewares.use('/api/service-status', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/service-status', middleware);
    },
  };
}
