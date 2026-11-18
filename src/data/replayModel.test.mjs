import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReplay } from './replayModel.js';
import { centroidOf } from './countryCentroids.js';

const NOW = Date.parse('2026-11-18T18:00:00Z');
const h = (n) => NOW - n * 3_600_000;

test('centroidOf resolves known codes and rejects junk', () => {
  assert.deepEqual(centroidOf('ru'), { lat: 61.5, lon: 105.3 });
  assert.equal(centroidOf('ZZ'), null);
  assert.equal(centroidOf(''), null);
});

test('buildReplay aggregates as-of events into country pulses, newest-aware', () => {
  const events = [
    { adversary: 'RU', timeMs: h(5), kind: 'ddos' },
    { adversary: 'RU', timeMs: h(2), kind: 'ransomware' },
    { adversary: 'CN', timeMs: h(4), kind: 'exploit' },
    { adversary: 'Unknown', timeMs: h(3), kind: 'phishing' }, // no country → off-map
    { adversary: 'RU', timeMs: h(1), kind: 'ddos' }, // after the playhead below
  ];
  const r = buildReplay(events, { playheadMs: h(2) });
  const ru = r.pulses.find((p) => p.country === 'RU');
  assert.equal(ru.count, 2); // the h(1) event is after the playhead, excluded
  assert.equal(ru.lastMs, h(2));
  assert.ok(Number.isFinite(ru.lat) && Number.isFinite(ru.lon));
  assert.equal(r.offMap, 1); // the Unknown phishing signal
  assert.ok(r.pulses[0].count >= r.pulses[r.pulses.length - 1].count); // ranked
});

test('buildReplay with an early playhead shows nothing yet', () => {
  const events = [{ adversary: 'RU', timeMs: h(2), kind: 'ddos' }];
  assert.deepEqual(buildReplay(events, { playheadMs: h(10) }).pulses, []);
});
