import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LAST_LOGIN_KEY,
  parseTime,
  readLastLogin,
  writeLastLogin,
  selectNewSince,
  timeAgo,
  summarize,
} from './loginReport.js';

function memoryStorage(seed = {}) {
  const map = new Map(Object.entries(seed));
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, String(v)),
    _map: map,
  };
}

const T = (iso) => Date.parse(iso);

test('readLastLogin / writeLastLogin round-trip through storage', () => {
  const s = memoryStorage();
  assert.equal(readLastLogin(s), null); // first visit
  writeLastLogin(s, T('2026-11-08T12:00:00Z'));
  assert.equal(readLastLogin(s), T('2026-11-08T12:00:00Z'));
  assert.ok(s._map.get(LAST_LOGIN_KEY).includes('2026-11-08'));
});

test('storage failures never throw (private window / blocked storage)', () => {
  const hostile = {
    getItem() { throw new Error('blocked'); },
    setItem() { throw new Error('blocked'); },
  };
  assert.equal(readLastLogin(hostile), null);
  assert.doesNotThrow(() => writeLastLogin(hostile, Date.now()));
});

test('parseTime reads ISO strings and epoch numbers, rejects junk', () => {
  assert.equal(parseTime('2026-11-09T00:00:00Z'), T('2026-11-09T00:00:00Z'));
  assert.equal(parseTime(1700000000000), 1700000000000);
  assert.equal(parseTime('not a date'), null);
  assert.equal(parseTime(null), null);
});

test('selectNewSince keeps only items after the cutoff, most important first', () => {
  const entries = [
    { kind: 'attack', tag: 'DSHIELD', time: '2026-11-07T10:00:00Z', priority: 10 },
    { kind: 'vuln', tag: 'EXPLOITED NOW', time: '2026-11-08T09:00:00Z', priority: 1300 },
    { kind: 'vuln', tag: 'VULNERABILITY', time: '2026-11-08T08:00:00Z', priority: 200 },
    { kind: 'models', tag: 'AI MODELS', time: '2026-11-06T00:00:00Z', priority: 50 },
    { kind: 'policy', tag: 'AI POLICY', time: null, priority: 0 }, // no time -> dropped
  ];
  const since = T('2026-11-07T12:00:00Z');
  const out = selectNewSince(entries, since);
  // 10:00 on the 7th is before the cutoff; the undated item is dropped.
  assert.deepEqual(out.map((e) => e.tag), ['EXPLOITED NOW', 'VULNERABILITY']);
});

test('selectNewSince on a first visit (no cutoff) keeps all dated items, newest first', () => {
  const entries = [
    { kind: 'attack', time: '2026-11-01T00:00:00Z', priority: 10 },
    { kind: 'attack', time: '2026-11-05T00:00:00Z', priority: 10 },
  ];
  const out = selectNewSince(entries, null);
  assert.equal(out.length, 2);
  assert.equal(out[0].time, '2026-11-05T00:00:00Z'); // newest first when priority ties
});

test('timeAgo speaks in plain, rounded units', () => {
  const now = T('2026-11-09T12:00:00Z');
  assert.equal(timeAgo(T('2026-11-09T11:59:30Z'), now), 'just now');
  assert.equal(timeAgo(T('2026-11-09T11:30:00Z'), now), '30 min ago');
  assert.equal(timeAgo(T('2026-11-09T09:00:00Z'), now), '3 hours ago');
  assert.equal(timeAgo(T('2026-11-06T12:00:00Z'), now), '3 days ago');
});

test('summarize writes a high-school-plain headline and counts by category', () => {
  const since = T('2026-11-08T00:00:00Z');
  const entries = [
    { kind: 'vuln', tag: 'EXPLOITED NOW' },
    { kind: 'vuln', tag: 'VULNERABILITY' },
    { kind: 'attack', tag: 'DSHIELD' },
    { kind: 'models', tag: 'AI MODELS' },
    { kind: 'research', tag: 'RESEARCH' },
  ];
  const s = summarize(entries, since, T('2026-11-09T12:00:00Z'));
  assert.equal(s.count, 5);
  assert.match(s.headline, /5 things worth knowing/);
  // One urgent hole, one other, one attack, two news items.
  assert.match(s.bullets[0], /already being used by hackers right now/);
  assert.ok(s.bullets.some((b) => /other new security weakness/.test(b)));
  assert.ok(s.bullets.some((b) => /attack warning showed up/.test(b)));
  assert.ok(s.bullets.some((b) => /2 AI-security news updates/.test(b)));
});

test('summarize reports an all-quiet period gently with no bullets', () => {
  const s = summarize([], T('2026-11-08T00:00:00Z'), Date.now());
  assert.equal(s.count, 0);
  assert.match(s.headline, /All quiet since you were last here/);
  assert.deepEqual(s.bullets, []);
});
