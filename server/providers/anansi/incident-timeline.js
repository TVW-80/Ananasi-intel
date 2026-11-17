// Anansi: incident timeline reconstruction from public reporting.
//
// For a place picked on the News Events layer, ask GDELT DOC 2.0 for the
// articles that mention it, oldest first, and boil them down to a de-duplicated
// timeline of "first seen" times. This is reconstruction FROM REPORTING, not
// from evidence: the times are when GDELT first saw an article, not when
// anything happened, and nothing here is verified. The popover says so.
const USER_AGENT = 'Anansi/1.0 (personal threat-intel dashboard)';
const TIMEOUT_MS = 20_000;
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_ENTRIES = 40;
const TTL_MS = 10 * 60_000;

const str = (v) => (v === null || v === undefined ? '' : String(v).trim());

/** Keep a place name to plain characters so it can sit safely inside a quoted GDELT query. */
export function cleanPlace(value) {
  const place = str(value)
    .replace(/[^\p{L}\p{N} ,.'-]/gu, ' ')
    .replace(/\s+/g, ' ')
    .replace(/,\s*(United States|USA|US)$/i, '') // GDELT names end in the country; articles rarely do
    .trim()
    .slice(0, 80);
  return place.length >= 3 ? place : null;
}

export function timelineUrl(place, timespan = '72h') {
  const params = new URLSearchParams({
    query: `"${place}" sourcecountry:US`,
    mode: 'ArtList',
    format: 'json',
    maxrecords: '100',
    sort: 'DateAsc',
    timespan,
  });
  return `https://api.gdeltproject.org/api/v2/doc/doc?${params}`;
}

/** GDELT `seendate` looks like 20261114T153000Z. */
export function parseSeenDate(value) {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(str(value));
  if (!m) return null;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

const titleKey = (title) =>
  title
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
    .slice(0, 80);

/**
 * Oldest-first, de-duplicated timeline entries.
 * @returns {{ entries: Array<{time: string, title: string, domain: string, url: string}>, total: number, firstSeen: string|null, lastSeen: string|null, sources: number }}
 */
export function normalizeTimeline(payload) {
  const rows = Array.isArray(payload?.articles) ? payload.articles : [];
  const seen = new Set();
  const entries = [];
  for (const a of rows) {
    const title = str(a?.title).replace(/\s+/g, ' ').slice(0, 180);
    const time = parseSeenDate(a?.seendate);
    let url;
    try {
      url = new URL(str(a?.url));
    } catch {
      continue;
    }
    if (!title || !time || !['http:', 'https:'].includes(url.protocol))
      continue;
    const key = titleKey(title);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    entries.push({
      time,
      title,
      domain: str(a.domain) || url.hostname.replace(/^www\./, ''),
      url: url.href,
    });
  }
  entries.sort((x, y) => x.time.localeCompare(y.time));
  const picked = entries.slice(0, MAX_ENTRIES);
  return {
    entries: picked,
    total: entries.length,
    firstSeen: picked[0]?.time ?? null,
    lastSeen: picked.at(-1)?.time ?? null,
    sources: new Set(picked.map((e) => e.domain)).size,
  };
}

export function createIncidentTimelineMiddleware({
  fetchImpl = (...a) => fetch(...a),
  clock = Date.now,
} = {}) {
  const cache = new Map();

  async function load(place) {
    let res;
    try {
      res = await fetchImpl(timelineUrl(place), {
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      throw new Error(
        `timeline: ${err?.cause?.code || err?.name || 'fetch failed'}`,
      );
    }
    if (!res.ok) throw new Error(`timeline: HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES)
      throw new Error('timeline: response too large');
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(
        'timeline: GDELT returned no JSON (it does this when a query matches nothing)',
      );
    }
    return {
      place,
      status: 'ok',
      updatedAt: new Date(clock()).toISOString(),
      ...normalizeTimeline(payload),
    };
  }

  return async function incidentTimelineMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    const query = new URLSearchParams(
      String(req.url || '').split('?')[1] || '',
    );
    const place = cleanPlace(query.get('place'));
    if (!place)
      return send(400, {
        error: 'place is required (3-80 letters, numbers, spaces, commas)',
      });
    const hit = cache.get(place);
    if (hit && clock() - hit.at < TTL_MS) return send(200, hit.body);
    try {
      const body = await load(place);
      cache.set(place, { at: clock(), body });
      if (cache.size > 100) cache.delete(cache.keys().next().value);
      return send(200, body);
    } catch (err) {
      console.warn(`[incident-timeline] ${err?.message || err}`);
      return send(200, {
        place,
        status: 'error',
        error: err?.message || String(err),
        entries: [],
        total: 0,
        firstSeen: null,
        lastSeen: null,
        sources: 0,
      });
    }
  };
}

export function incidentTimelineProxy() {
  const middleware = createIncidentTimelineMiddleware();
  return {
    name: 'anansi-incident-timeline',
    configureServer(server) {
      server.middlewares.use('/api/incident-timeline', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/incident-timeline', middleware);
    },
  };
}
