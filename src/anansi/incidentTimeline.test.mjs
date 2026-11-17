import test from 'node:test';
import assert from 'node:assert/strict';
import {
  groupByHour,
  summarizeTimeline,
  timelineRequestUrl,
  TIMELINE_DISCLAIMER,
} from './incidentTimeline.js';

test('request URL encodes the place', () => {
  assert.equal(
    timelineRequestUrl(' Norfolk, Virginia '),
    '/api/incident-timeline?place=Norfolk%2C%20Virginia',
  );
});

test('entries group into UTC hour buckets in order', () => {
  const g = groupByHour([
    { time: '2026-11-14T15:05:00.000Z', title: 'a' },
    { time: '2026-11-14T15:55:00.000Z', title: 'b' },
    { time: '2026-11-14T16:01:00.000Z', title: 'c' },
    { time: 'bad', title: 'd' },
  ]);
  assert.deepEqual(
    g.map((b) => [b.hour, b.entries.length]),
    [
      ['2026-11-14T15:00Z', 2],
      ['2026-11-14T16:00Z', 1],
    ],
  );
});

test('summary handles errors, empty results and normal timelines', () => {
  assert.equal(
    summarizeTimeline({ status: 'error', error: 'timeline: HTTP 429' }),
    'timeline: HTTP 429',
  );
  assert.match(
    summarizeTimeline({ status: 'ok', entries: [] }),
    /No matching reports/,
  );
  assert.equal(
    summarizeTimeline({
      status: 'ok',
      entries: [{}, {}],
      sources: 2,
      firstSeen: '2026-11-14T15:00:00Z',
      lastSeen: '2026-11-14T18:00:00Z',
    }),
    '2 reports from 2 sources over ~3h',
  );
  assert.match(TIMELINE_DISCLAIMER, /Unverified/);
});
