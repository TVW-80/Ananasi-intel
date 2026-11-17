import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDiamond, HOME_VICTIM } from './diamond.js';

const layer = (id) => ({ id, name: 'X', icon: '☣', color: '#f4cf5e', source: 'test' });

test('buildDiamond fills all four vertices with the event + ATT&CK capability', () => {
  const d = buildDiamond(layer('cyber-botnet-c2'), {
    title: 'Botnet C2 servers',
    place: 'Russia',
    items: [{ text: 'Emotet', tech: 'Host 185.220.101.5 · AS12345' }],
  });
  assert.equal(d.adversary, 'Russia');
  assert.equal(d.victim, HOME_VICTIM);
  assert.match(d.capability, /Command-and-control/i);
  assert.equal(d.technique.id, 'T1071');
  assert.equal(d.techniqueUrl, 'https://attack.mitre.org/techniques/T1071/');
  // infrastructure is read from the event text (IP + ASN present).
  assert.match(d.infrastructure, /185\.220\.101\.5/);
  assert.match(d.infrastructure, /AS12345/i);
});

test('infrastructure falls back to the place when no IP/ASN is known', () => {
  const d = buildDiamond(layer('cyber-reported-attackers'), { title: 'Reported attackers', place: 'China', items: [] });
  assert.equal(d.infrastructure, 'China netblocks');
  assert.equal(d.technique.id, 'T1595'); // scanning
});

test('a title hint steers the capability even on the aggregate attack layer', () => {
  const d = buildDiamond(layer('cyber-attack-map'), { title: 'Ransomware wave hits hospitals', place: 'Unknown', items: [] });
  assert.equal(d.technique.id, 'T1486');
  assert.match(d.capability, /Ransomware/i);
});

test('buildDiamond never throws on a bare or empty point', () => {
  assert.doesNotThrow(() => buildDiamond(layer('cyber-attack-map'), {}));
  const d = buildDiamond(layer('cyber-attack-map'), {});
  assert.equal(d.adversary, 'Unattributed');
  assert.equal(d.victim, HOME_VICTIM);
  assert.ok(d.technique.id);
});
