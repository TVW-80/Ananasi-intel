import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanPlace,
  timelineUrl,
  parseSeenDate,
  normalizeTimeline,
  createIncidentTimelineMiddleware,
} from './incident-timeline.js';

const art = (
  title,
  seendate,
  url = `https://example.com/${encodeURIComponent(title)}`,
  domain = 'example.com',
) => ({ title, seendate, url, domain });

test('place names are cleaned for a quoted GDELT query', () => {
  assert.equal(cleanPlace('Norfolk, Virginia'), 'Norfolk, Virginia');
  assert.equal(
    cleanPlace('Norfolk" OR sourcecountry:RU "x'),
    'Norfolk OR sourcecountry RU x',
  );
  assert.equal(
    cleanPlace('Norfolk, Virginia, United States'),
    'Norfolk, Virginia',
  );
  assert.equal(cleanPlace('ab'), null);
  assert.equal(cleanPlace(null), null);
  assert.equal(cleanPlace('x'.repeat(200)).length, 80);
});

test('timeline URL asks GDELT for oldest-first US articles about the place', () => {
  const u = new URL(timelineUrl('Norfolk, Virginia'));
  assert.equal(
    u.searchParams.get('query'),
    '"Norfolk, Virginia" sourcecountry:US',
  );
  assert.equal(u.searchParams.get('sort'), 'DateAsc');
  assert.equal(u.searchParams.get('mode'), 'ArtList');
});

test('seendate parses to ISO and rejects junk', () => {
  assert.equal(parseSeenDate('20261114T153000Z'), '2026-11-14T15:30:00.000Z');
  assert.equal(parseSeenDate('2026-11-14'), null);
  assert.equal(parseSeenDate(undefined), null);
});

test('timeline sorts oldest first, de-duplicates titles, drops bad rows', () => {
  const t = normalizeTimeline({
    articles: [
      art('Crash closes Hampton Blvd', '20261114T160000Z', undefined, 'b.com'),
      art('Crash closes Hampton Blvd!', '20261114T161000Z', undefined, 'c.com'), // same title once punctuation is ignored
      art(
        'Police respond to crash on Hampton Blvd',
        '20261114T150000Z',
        undefined,
        'a.com',
      ),
      art('No time', 'garbage'),
      art('Bad url', '20261114T170000Z', 'javascript:alert(1)'),
      art('', '20261114T170000Z'),
    ],
  });
  assert.deepEqual(
    t.entries.map((e) => e.title),
    ['Police respond to crash on Hampton Blvd', 'Crash closes Hampton Blvd'],
  );
  assert.equal(t.total, 2);
  assert.equal(t.firstSeen, '2026-11-14T15:00:00.000Z');
  assert.equal(t.lastSeen, '2026-11-14T16:00:00.000Z');
  assert.equal(t.sources, 2);
  assert.deepEqual(normalizeTimeline({}), {
    entries: [],
    total: 0,
    firstSeen: null,
    lastSeen: null,
    sources: 0,
  });
});

function run(mw, url) {
  return new Promise((resolve) => {
    const res = {
      headersSent: false,
      writeHead(status) {
        this.status = status;
      },
      end(body) {
        this.headersSent = true;
        resolve({ status: this.status, body: JSON.parse(body) });
      },
    };
    mw({ method: 'GET', url }, res);
  });
}

test('middleware validates place, caches, and reports upstream trouble as data', async () => {
  let calls = 0;
  let now = 0;
  const mw = createIncidentTimelineMiddleware({
    clock: () => now,
    fetchImpl: async () => {
      calls += 1;
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            articles: [art('Fire on Granby Street', '20261114T150000Z')],
          }),
      };
    },
  });
  assert.equal((await run(mw, '/')).status, 400);
  const first = await run(mw, '/?place=Norfolk%2C%20Virginia');
  assert.equal(first.status, 200);
  assert.equal(first.body.entries.length, 1);
  await run(mw, '/?place=Norfolk%2C%20Virginia');
  assert.equal(calls, 1, 'second call served from cache');
  now += 11 * 60_000;
  await run(mw, '/?place=Norfolk%2C%20Virginia');
  assert.equal(calls, 2, 'cache expires');

  const failing = createIncidentTimelineMiddleware({
    fetchImpl: async () => ({ ok: false, status: 429, text: async () => '' }),
  });
  const bad = await run(failing, '/?place=Norfolk');
  assert.equal(bad.status, 200);
  assert.equal(bad.body.status, 'error');
  assert.match(bad.body.error, /HTTP 429/);

  const nonJson = createIncidentTimelineMiddleware({
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => 'Your query did not match',
    }),
  });
  assert.equal((await run(nonJson, '/?place=Norfolk')).body.status, 'error');
});
