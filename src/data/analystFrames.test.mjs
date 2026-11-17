import test from 'node:test';
import assert from 'node:assert/strict';
import { KILL_CHAIN, killChainPhase, pyramidLevel, confidenceOf } from './analystFrames.js';

test('killChainPhase places activity on the 7-phase Lockheed chain', () => {
  assert.equal(KILL_CHAIN.length, 7);
  assert.deepEqual(killChainPhase('scanning'), { index: 1, name: 'Reconnaissance' });
  assert.deepEqual(killChainPhase('phishing'), { index: 3, name: 'Delivery' });
  assert.deepEqual(killChainPhase('exploit'), { index: 4, name: 'Exploitation' });
  assert.deepEqual(killChainPhase('c2'), { index: 6, name: 'Command & Control' });
  assert.deepEqual(killChainPhase('ransomware'), { index: 7, name: 'Actions on Objectives' });
});

test('pyramidLevel grades how painful the indicator is to change', () => {
  assert.equal(pyramidLevel('scanning').level, 'IP Addresses');
  assert.equal(pyramidLevel('scanning').rank, 2);
  assert.equal(pyramidLevel('malware').level, 'Tools');
  const ttp = pyramidLevel('exploit');
  assert.equal(ttp.level, 'TTPs');
  assert.equal(ttp.rank, 6);
  assert.match(ttp.pain, /re-learn/i);
});

test('confidenceOf scores Timeliness · Relevance · Accuracy and an overall level', () => {
  const now = Date.parse('2026-11-17T18:00:00Z');
  const strong = confidenceOf(
    { source: 'abuse.ch Feodo Tracker', time: '2026-11-17T12:00:00Z', title: 'C2 hitting Virginia hospital', place: 'Russia' },
    { now },
  );
  assert.equal(strong.timeliness, 'high'); // 6h old
  assert.equal(strong.relevance, 'high'); // Virginia / hospital
  assert.equal(strong.accuracy, 'high'); // abuse.ch
  assert.equal(strong.level, 'High');

  const weak = confidenceOf({ source: '', time: null, title: '', place: '' }, { now });
  assert.equal(weak.timeliness, 'low');
  assert.equal(weak.accuracy, 'low');
  assert.equal(weak.level, 'Low');

  const mid = confidenceOf(
    { source: 'Some community feed', time: '2026-11-14T00:00:00Z', title: 'Scanning', place: 'Brazil' },
    { now },
  );
  assert.equal(mid.accuracy, 'medium');
  assert.equal(mid.relevance, 'medium');
  assert.ok(['Medium', 'Low'].includes(mid.level));
});
