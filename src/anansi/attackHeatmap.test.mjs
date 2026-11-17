import test from 'node:test';
import assert from 'node:assert/strict';
import { tallyTechniques, buildHeat } from './attackHeatmap.js';

test('tallyTechniques counts ATT&CK techniques across event hints', () => {
  const tally = tallyTechniques([
    { text: 'Massive DDoS flood knocks sites offline' }, // T1498
    { text: 'Another DDoS wave' }, // T1498
    { text: 'LockBit ransomware encrypts files' }, // T1486
    { layerId: 'cyber-botnet-c2', text: '' }, // T1071
  ]);
  assert.equal(tally.get('T1498').count, 2);
  assert.equal(tally.get('T1486').count, 1);
  assert.equal(tally.get('T1071').count, 1);
});

test('buildHeat ranks hottest-first and reports the peak for scaling', () => {
  const tally = tallyTechniques([
    { text: 'ddos' }, { text: 'ddos' }, { text: 'ddos' }, // T1498 x3
    { text: 'ransomware' }, // T1486 x1
    { text: 'phishing page' }, // T1566 x1
  ]);
  const { rows, max } = buildHeat(tally);
  assert.equal(max, 3);
  assert.equal(rows[0].technique.id, 'T1498');
  assert.equal(rows[0].count, 3);
  assert.ok(rows.length >= 3);
});

test('buildHeat caps the list and empty input yields nothing', () => {
  assert.deepEqual(buildHeat(tallyTechniques([])), { rows: [], max: 0 });
  const many = Array.from({ length: 20 }, (_, i) => ({ text: `cve-2026-${i} exploit` }));
  const { rows } = buildHeat(tallyTechniques(many), { limit: 8 });
  assert.ok(rows.length <= 8);
});
