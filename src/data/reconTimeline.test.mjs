import test from 'node:test';
import assert from 'node:assert/strict';
import { buildTimeline, visibleAsOf, axisLabel } from './reconTimeline.js';

const NOW = Date.parse('2026-11-18T12:00:00Z');
const h = (n) => NOW - n * 3_600_000;

test('buildTimeline bins events into the span and reports the peak', () => {
  const events = [
    { timeMs: h(1), kind: 'ddos' }, { timeMs: h(1), kind: 'ddos' },
    { timeMs: h(10), kind: 'phishing' },
    { timeMs: h(200), kind: 'scanning' }, // outside 72h span → dropped
  ];
  const tl = buildTimeline(events, { now: NOW, bins: 72, spanMs: 72 * 3_600_000 });
  assert.equal(tl.bins.length, 72);
  const total = tl.bins.reduce((s, b) => s + b.count, 0);
  assert.equal(total, 3); // the 200h-old one is outside the span
  assert.equal(tl.max, 2); // two ddos share a bin
  assert.ok(tl.bins.some((b) => b.byKind.ddos === 2));
});

test('visibleAsOf returns only events reported at or before the playhead', () => {
  const events = [{ timeMs: h(5) }, { timeMs: h(3) }, { timeMs: h(1) }];
  assert.equal(visibleAsOf(events, h(3)).length, 2);
  assert.equal(visibleAsOf(events, h(10)).length, 0);
  assert.equal(visibleAsOf(events).length, 3); // no cutoff = all
});

test('axisLabel renders a compact UTC stamp', () => {
  assert.match(axisLabel(Date.parse('2026-11-18T09:00:00Z')), /11\/18 09:00Z/);
});
