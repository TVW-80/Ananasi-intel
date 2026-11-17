// Anansi: CYBER NEWS aggregator. One keyless endpoint fans out to several
// reputable cyber-security news feeds (breaches, outages, ransomware, exploits,
// official advisories), normalises them into one plain-English, source-linked
// wire, and serves a single cached snapshot. Modelled on ai-sec-intel.js: every
// source degrades on its own, last-good items are kept, and the whole thing is
// keyless so it just works on the owner's machine.
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  CYBER_NEWS_SOURCES,
  assembleCyberNews,
  normalizeItems,
  parseFeed,
} from '../../../src/data/cyberNews.js';

const USER_AGENT = 'Ananzi/0.3 (+cyber-news; personal research)';
const MAX_BYTES = 4_000_000;
const TTL_MS = 10 * 60_000; // refresh at most every 10 min
const DEGRADED_TTL_MS = 2 * 60_000; // retry a degraded wire sooner

export function createCyberNewsMiddleware({
  fetchImpl = (...args) => fetch(...args),
  clock = () => Date.now(),
  cachePath = path.join(process.cwd(), '.gev-cache', 'cyber-news.json'),
  ttlMs = TTL_MS,
  degradedTtlMs = DEGRADED_TTL_MS,
} = {}) {
  let state = null;
  let inflight = null;

  const fetchBody = async (url) => {
    let res;
    try {
      res = await fetchImpl(url, {
        redirect: 'follow',
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*' },
      });
    } catch (err) {
      const cause = err?.cause?.code || err?.cause?.message;
      throw new Error(`${err?.message || 'fetch failed'}${cause ? ` [${cause}]` : ''}`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('response too large');
    return text;
  };

  const SOURCES = CYBER_NEWS_SOURCES.map(({ id, label, url }) => ({
    id,
    label,
    fetch: async (now) => normalizeItems(label, id, parseFeed(await fetchBody(url)), { now }),
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
      console.warn('[cyber-news] cache write failed:', err?.message || err);
    }
  }

  const isFresh = (entry) => {
    const degraded = entry.snapshot.sources.some((source) => !source.ok);
    return clock() - entry.at < (degraded ? degradedTtlMs : ttlMs);
  };

  async function refresh(previous) {
    const now = clock();
    const results = await Promise.allSettled(SOURCES.map((source) => source.fetch(now)));
    const perSource = { ...(previous?.perSource || {}) };
    const sources = [];
    results.forEach((result, index) => {
      const { id, label } = SOURCES[index];
      if (result.status === 'fulfilled') {
        perSource[id] = { at: now, items: result.value };
        sources.push({ id, label, ok: true, count: result.value.length, at: now });
      } else {
        const reason = result.reason?.message || String(result.reason);
        console.warn(`[cyber-news] ${id} failed (${reason})${perSource[id] ? ' — keeping last-good items' : ''}`);
        sources.push({
          id, label, ok: false, stale: Boolean(perSource[id]),
          count: perSource[id]?.items?.length || 0, at: perSource[id]?.at || null, error: reason,
        });
      }
    });
    if (!sources.some((source) => source.ok)) throw new Error('every cyber-news source failed');
    const items = SOURCES.flatMap((source) => perSource[source.id]?.items || []);
    const snapshot = assembleCyberNews({ items, sources, now });
    return { at: now, snapshot, perSource };
  }

  return async function cyberNewsMiddleware(req, res) {
    const send = (status, body, cacheStatus) => {
      if (res.headersSent) return;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'x-cyber-news-cache': cacheStatus,
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
            console.warn(`[cyber-news] refresh failed (${err?.message || err}) — serving cache if any`);
            return null;
          })
          .finally(() => { inflight = null; });
      }
      const fresh = await inflight;
      if (fresh) send(200, fresh.snapshot, 'MISS');
      else if (state) send(200, state.snapshot, 'STALE-ERROR');
      else send(502, { error: 'cyber-news sources unavailable and no cache yet' }, 'NONE');
    } catch (err) {
      send(500, { error: `cyber-news proxy error: ${err?.message || err}` }, 'ERROR');
    }
  };
}

export function cyberNewsProxy() {
  const middleware = createCyberNewsMiddleware();
  return {
    name: 'cyber-news-proxy',
    configureServer(server) {
      server.middlewares.use('/api/cyber-news', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/cyber-news', middleware);
    },
  };
}
