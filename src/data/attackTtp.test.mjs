import test from 'node:test';
import assert from 'node:assert/strict';
import { TECHNIQUES, techniqueUrl, classifyKind, ttpFor } from './attackTtp.js';

test('techniqueUrl points at attack.mitre.org, handling sub-techniques', () => {
  assert.equal(techniqueUrl('T1498'), 'https://attack.mitre.org/techniques/T1498/');
  assert.equal(techniqueUrl('T1071.001'), 'https://attack.mitre.org/techniques/T1071/001/');
});

test('every technique has an id, name and a tactic', () => {
  for (const t of Object.values(TECHNIQUES)) {
    assert.match(t.id, /^T\d{4}$/);
    assert.ok(t.name && t.tacticId && t.tacticName, `incomplete ${JSON.stringify(t)}`);
  }
});

test('classifyKind falls back to the layer default, and hints win when present', () => {
  assert.equal(classifyKind('cyber-ransomware', ''), 'ransomware');
  assert.equal(classifyKind('cyber-reported-attackers', ''), 'scanning');
  assert.equal(classifyKind('cyber-botnet-c2', ''), 'c2');
  assert.equal(classifyKind('exposed-cameras', ''), 'exposure');
  // a hint overrides the layer default
  assert.equal(classifyKind('cyber-attack-map', 'Massive DDoS flood knocks sites offline'), 'ddos');
  assert.equal(classifyKind('cyber-attack-map', 'Phishing page impersonates bank'), 'phishing');
  // unknown layer, no hint → scanning
  assert.equal(classifyKind('something-else', ''), 'scanning');
});

test('ttpFor returns a technique, a plain capability and a live URL', () => {
  const ddos = ttpFor('cyber-internet-outages', 'service outage from DDoS');
  assert.equal(ddos.technique.id, 'T1498');
  assert.equal(ddos.technique.tacticName, 'Impact');
  assert.match(ddos.capability, /Denial-of-service/i);
  assert.equal(ddos.url, 'https://attack.mitre.org/techniques/T1498/');

  const ransom = ttpFor('cyber-ransomware', 'LockBit encrypted the files');
  assert.equal(ransom.technique.id, 'T1486');
  const c2 = ttpFor('cyber-botnet-c2', '');
  assert.equal(c2.technique.tacticName, 'Command and Control');
});
