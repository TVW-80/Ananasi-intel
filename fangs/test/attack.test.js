import test from 'node:test';
import assert from 'node:assert/strict';
import { AttackCatalog, mapEvent, RULE_TECHNIQUE_IDS } from '../src/attack.js';
import { makeFangs, loadSynthetic, loadSnapshotInto, readJson } from './helpers/env.js';

const cat = AttackCatalog.load();

test('bundled STIX is a real ATT&CK Enterprise bundle (>=800 techniques, tactics present, version recorded)', () => {
  const b = readJson('data/attack-enterprise-trimmed.json');
  assert.equal(b.type, 'bundle'); assert.equal(b.spec_version, '2.1');
  assert.ok(cat.techniques.size >= 800, `techniques ${cat.techniques.size}`);
  assert.ok(cat.tactics.size >= 14);
  assert.match(String(cat.meta.attack_version), /^\d+(\.\d+)?$/);
  for (const t of cat.techniques.values()) assert.match(t.id, /^T\d{4}(\.\d{3})?$/);
  console.log(`  ATT&CK v${cat.meta.attack_version}: ${cat.techniques.size} techniques, ${cat.tactics.size} tactics`);
});

test('PASS ATT&CK validation: every technique in the deterministic rule table exists, is not revoked/deprecated', () => {
  assert.ok(RULE_TECHNIQUE_IDS.length >= 10);
  const { valid, invalid } = cat.validate(RULE_TECHNIQUE_IDS);
  assert.deepEqual(invalid, [], `rule table references invalid techniques: ${invalid}`);
  assert.equal(valid.length, RULE_TECHNIQUE_IDS.length);
});

test('PASS ATT&CK validation: every mapping emitted on real + synthetic events validates against the bundle, with tactics from STIX', () => {
  const f = makeFangs(); loadSnapshotInto(f); loadSynthetic(f, 2);
  let n = 0, events = 0;
  for (const e of f.queue.events.values()) {
    events++; assert.ok(e.attack.length > 0, `event ${e.indicator} (${e.kind}) has no mapping`);
    for (const t of e.attack) { n++; assert.ok(cat.isValid(t.id), `${t.id} invalid`); assert.ok(t.tactics.length > 0, `${t.id} has no tactic from STIX`); assert.equal(t.name, cat.techniques.get(t.id).name); }
  }
  console.log(`  validated ${n} technique mappings across ${events} events: 0 invalid`);
});

test('validator rejects bogus, malformed, revoked and deprecated IDs', () => {
  assert.equal(cat.isValid('T9999'), false); assert.equal(cat.isValid('T1071.999'), false); assert.equal(cat.isValid('banana'), false);
  const bad = [...cat.techniques.values()].filter((t) => t.revoked || t.deprecated);
  console.log(`  (bundle contains ${bad.length} revoked/deprecated techniques)`);
  for (const t of bad.slice(0, 20)) assert.equal(cat.isValid(t.id), false, `${t.id} should be rejected`);
  assert.deepEqual(cat.validate(['t1071.001', 'T0000', 'T1071.001']).valid, ['T1071.001'], 'case-insensitive, deduped');
});

test('rule mapper is behaviour-driven: phish != scan != c2', () => {
  const ids = (e) => mapEvent(e, cat).map((t) => t.id);
  assert.ok(ids({ kind: 'phish', tags: [] }).includes('T1566.002'));
  assert.ok(ids({ kind: 'scan', tags: [] }).includes('T1595.002'));
  assert.ok(!ids({ kind: 'scan', tags: [] }).includes('T1071.001'));
  assert.ok(ids({ kind: 'c2', ip: '192.0.2.1', tags: [] }).includes('T1583.003'));
  assert.deepEqual(ids({ kind: 'unknown' }), [], 'unknown behaviour gets no guess');
});
