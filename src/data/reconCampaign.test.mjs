import test from 'node:test';
import assert from 'node:assert/strict';
import { trendBy, techniqueTrends, originTrends, topRising } from './reconCampaign.js';

const NOW = Date.parse('2026-11-18T18:00:00Z');
const h = (n) => NOW - n * 3_600_000;
const W = 24 * 3_600_000;

// 5 phishing signals in the recent 24h, 1 in the prior 24h → a rising campaign.
const events = [
  ...Array.from({ length: 5 }, () => ({ timeMs: h(2), technique: { id: 'T1566', name: 'Phishing' }, adversary: 'CN' })),
  { timeMs: h(30), technique: { id: 'T1566', name: 'Phishing' }, adversary: 'CN' },
  { timeMs: h(1), technique: { id: 'T1498', name: 'Network DoS' }, adversary: 'RU' },
  { timeMs: h(28), technique: { id: 'T1498', name: 'Network DoS' }, adversary: 'RU' },
  { timeMs: h(27), technique: { id: 'T1498', name: 'Network DoS' }, adversary: 'RU' },
];

test('trendBy compares a recent vs prior window and flags direction', () => {
  const rows = trendBy(events, (e) => e.technique.id, { now: NOW, windowMs: W });
  const phish = rows.find((r) => r.key === 'T1566');
  assert.deepEqual([phish.recent, phish.prior, phish.direction], [5, 1, 'rising']);
  const dos = rows.find((r) => r.key === 'T1498');
  assert.equal(dos.direction, 'falling'); // 1 recent vs 2 prior
});

test('techniqueTrends attaches technique metadata; topRising surfaces campaigns', () => {
  const trends = techniqueTrends(events, { now: NOW, windowMs: W });
  const rising = topRising(trends);
  assert.equal(rising[0].technique.id, 'T1566');
  assert.equal(rising[0].technique.name, 'Phishing');
  assert.ok(rising.every((r) => r.delta > 0));
});

test('originTrends ignores Unknown and ranks by rise', () => {
  const rows = originTrends([...events, { timeMs: h(1), adversary: 'Unknown', technique: { id: 'T1595' } }], { now: NOW, windowMs: W });
  assert.ok(!rows.some((r) => r.key === 'Unknown'));
  assert.ok(rows.some((r) => r.key === 'CN'));
});
