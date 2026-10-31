// Anansi: AI Security Intelligence aggregator (moved from the 0.1.x vite.config.js
// when Anansi was ported onto God's Eye View 0.3.0's server/providers layout).
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  GHSA_PACKAGES,
  RETAIN_DAYS as AI_SEC_RETAIN_DAYS,
  assembleSnapshot as assembleAiSecSnapshot,
  normalizeFederalRegister,
  normalizeGhsa,
  normalizeKev,
  normalizeModelFeed,
  normalizeResearchFeed,
  parseFeed,
} from '../../../src/data/aiSecIntel.js';

/**
 * AI Security Intelligence aggregator. One keyless endpoint fans out to
 * CISA KEV, GitHub Security Advisories, the Federal Register, and a handful
 * of lab/research feeds, normalizes them (src/data/aiSecIntel.js), and serves
 * a single cached snapshot.
 *
 * Reliability model: every source keeps its own last-good normalized items on
 * disk, so one upstream outage degrades that source to "stale" instead of
 * blanking the panel; the whole snapshot is also served stale if a refresh
 * throws. Refreshes are single-flight, so N tabs cost one upstream sweep.
 * Optional `GITHUB_TOKEN` lifts the 60 req/h anonymous GitHub limit; it never
 * leaves the server.
 */
export function createAiSecIntelMiddleware({
  fetchImpl = (...args) => fetch(...args),
  now: clock = Date.now,
  cachePath = path.join(process.cwd(), '.gev-cache', 'ai-sec-intel.json'),
  ttlMs = 3 * 3600_000,
  /** After a partial outage, retry sooner than the full TTL. */
  degradedTtlMs = 15 * 60_000,
} = {}) {
  const FETCH_TIMEOUT_MS = 25_000;
  const MAX_BYTES = 8 * 1024 * 1024;
  const USER_AGENT = 'Anansi/1.0 (AI security intelligence panel)';
  /** @type {{ at: number, snapshot: object, history: object, perSource: object } | null} */
  let state = null;
  let inflight = null;

  const fetchBody = async (url, { json = false, headers = {} } = {}) => {
    let res;
    try {
      res = await fetchImpl(url, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { 'User-Agent': USER_AGENT, Accept: json ? 'application/json' : 'application/xml, text/xml, */*', ...headers },
      });
    } catch (err) {
      // undici reports every network failure as a bare "fetch failed"; the
      // actionable part (cert trust vs. connect timeout vs. DNS) is on `cause`.
      const cause = err?.cause?.code || err?.cause?.message || err?.name;
      throw new Error(`${err?.message || 'fetch failed'}${cause ? ` [${cause}]` : ''}`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('response too large');
    return json ? JSON.parse(text) : text;
  };

  const feedSource = (id, label, bucket, url, normalize) => ({
    id, label, bucket,
    fetch: async (now) => normalize(label, parseFeed(await fetchBody(url)), { now }),
  });

  const SOURCES = [
    {
      id: 'cisa-kev', label: 'CISA KEV', bucket: 'vulns',
      fetch: async (now) => normalizeKev(await fetchBody(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        { json: true },
      ), { now }),
    },
    {
      id: 'ghsa', label: 'GitHub Advisories', bucket: 'vulns',
      fetch: async (now) => {
        const url = new URL('https://api.github.com/advisories');
        url.searchParams.set('type', 'reviewed');
        url.searchParams.set('affects', GHSA_PACKAGES.join(','));
        url.searchParams.set('published', `>=${new Date(now - AI_SEC_RETAIN_DAYS * 86_400_000).toISOString().slice(0, 10)}`);
        url.searchParams.set('sort', 'published');
        url.searchParams.set('direction', 'desc');
        url.searchParams.set('per_page', '100');
        const token = String(process.env.GITHUB_TOKEN || '').trim();
        return normalizeGhsa(await fetchBody(url.toString(), {
          json: true,
          headers: { 'X-GitHub-Api-Version': '2022-11-28', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        }), { now });
      },
    },
    {
      id: 'federal-register', label: 'Federal Register', bucket: 'policy',
      fetch: async () => {
        const url = new URL('https://www.federalregister.gov/api/v1/documents.json');
        url.searchParams.append('conditions[presidential_document_type][]', 'executive_order');
        url.searchParams.set('conditions[term]', 'artificial intelligence');
        url.searchParams.set('order', 'newest');
        url.searchParams.set('per_page', '30'); // headroom: the AI-relevance filter discards full-text-only hits
        for (const field of ['title', 'executive_order_number', 'signing_date', 'publication_date', 'html_url', 'abstract', 'document_number']) {
          url.searchParams.append('fields[]', field);
        }
        return normalizeFederalRegister(await fetchBody(url.toString(), { json: true }));
      },
    },
    feedSource('openai', 'OpenAI', 'models', 'https://openai.com/news/rss.xml', normalizeModelFeed),
    feedSource('google-ai', 'Google AI', 'models', 'https://blog.google/technology/ai/rss/', normalizeModelFeed),
    feedSource('deepmind', 'Google DeepMind', 'models', 'https://deepmind.google/blog/rss.xml', normalizeModelFeed),
    feedSource('huggingface', 'Hugging Face', 'models', 'https://huggingface.co/blog/feed.xml', normalizeModelFeed),
    feedSource(
      'arxiv', 'arXiv cs.CR', 'research',
      'https://export.arxiv.org/api/query?search_query=cat:cs.CR+AND+(all:LLM+OR+all:%22prompt+injection%22+OR+all:jailbreak+OR+all:%22AI+agent%22)&sortBy=submittedDate&sortOrder=descending&max_results=15',
      normalizeResearchFeed,
    ),
    feedSource('owasp-genai', 'OWASP GenAI', 'research', 'https://genai.owasp.org/feed/', normalizeResearchFeed),
    feedSource('mitre-atlas', 'MITRE ATLAS', 'research', 'https://github.com/mitre-atlas/atlas-data/releases.atom', normalizeResearchFeed),
  ];

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
      console.warn('[ai-sec-intel] cache write failed:', err?.message || err);
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
        console.warn(`[ai-sec-intel] ${id} failed (${reason})${perSource[id] ? ' — keeping last-good items' : ''}`);
        sources.push({
          id, label, ok: false, stale: Boolean(perSource[id]),
          count: perSource[id]?.items?.length || 0, at: perSource[id]?.at || null, error: reason,
        });
      }
    });
    if (!sources.some((source) => source.ok)) throw new Error('every upstream source failed');
    const bucketItems = (bucket) => SOURCES
      .filter((source) => source.bucket === bucket)
      .flatMap((source) => perSource[source.id]?.items || []);
    const { snapshot, history } = assembleAiSecSnapshot({
      vulns: bucketItems('vulns'),
      models: bucketItems('models'),
      research: bucketItems('research'),
      policy: bucketItems('policy'),
      sources,
      history: previous?.history || null,
      now,
    });
    return { at: now, snapshot, history, perSource };
  }

  return async function aiSecIntelMiddleware(req, res) {
    const send = (status, body, cacheStatus) => {
      if (res.headersSent) return;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'x-ai-sec-cache': cacheStatus,
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
            console.warn(`[ai-sec-intel] refresh failed (${err?.message || err}) — serving cache if any`);
            return null;
          })
          .finally(() => { inflight = null; });
      }
      const fresh = await inflight;
      if (fresh) send(200, fresh.snapshot, 'MISS');
      else if (state) send(200, state.snapshot, 'STALE-ERROR');
      else send(502, { error: 'AI security intel sources unavailable and no cache yet' }, 'NONE');
    } catch (err) {
      send(500, { error: `ai-sec-intel proxy error: ${err?.message || err}` }, 'ERROR');
    }
  };
}

export function aiSecIntelProxy() {
  const middleware = createAiSecIntelMiddleware();
  return {
    name: 'ai-sec-intel-proxy',
    configureServer(server) {
      server.middlewares.use('/api/ai-sec-intel', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/ai-sec-intel', middleware);
    },
  };
}
