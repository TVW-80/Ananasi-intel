import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFangs, loadSnapshotInto, loadSynthetic } from './helpers/env.js';
import { verifyProvenance } from '../src/provenance.js';
import { FangsGraph } from '../src/graph.js';

test('PASS provenance: real C2Intel snapshot is 100% sourced, 0 fabricated', () => {
  const f = makeFangs(); loadSnapshotInto(f);
  const v = verifyProvenance(f.fg, f.store, f.adapters);
  console.log(`  real snapshot: ${v.nodes} nodes, ${v.edges} edges, ${v.rels} rels, sourced ${v.sourced_pct}%, fabricated nodes=${v.fabricated_nodes} rels=${v.fabricated_rels}`);
  assert.ok(v.nodes > 200 && v.rels > 300, 'snapshot should produce a real graph');
  assert.equal(v.ok, true, v.problems.slice(0, 3).join('; '));
  assert.equal(v.sourced_pct, 100); assert.equal(v.fabricated_rels + v.fabricated_nodes, 0);
});

test('PASS provenance: synthetic multi-feed replay (10 seeds) is 100% sourced, 0 fabricated', () => {
  let nodes = 0, rels = 0;
  for (let seed = 1; seed <= 10; seed++) {
    const f = makeFangs(); loadSynthetic(f, seed);
    const v = verifyProvenance(f.fg, f.store, f.adapters);
    nodes += v.nodes; rels += v.rels;
    assert.equal(v.ok, true, `seed ${seed}: ${v.problems.slice(0, 3).join('; ')}`);
  }
  console.log(`  synthetic x10 seeds: ${nodes} nodes, ${rels} rels verified`);
});

test('verifier has teeth: fabricated edge, stripped provenance, missing record, tampered raw are all caught', () => {
  const mk = () => { const f = makeFangs(); loadSynthetic(f, 3); return f; };
  // 1. fabricated rel citing a real record that does not derive it
  let f = mk(); const [a, b] = [...f.fg.graph.nodes()].filter((n) => n.startsWith('ip:'));
  const anyRec = [...f.store.records.keys()][0];
  f.fg.graph.addEdgeWithKey('fake', a, b, { rels: [{ type: 'hosts', src: a, dst: b, prov: [anyRec] }] });
  let v = verifyProvenance(f.fg, f.store, f.adapters);
  assert.ok(v.fabricated_rels >= 1 && !v.ok, 'fabricated edge must be detected');
  // 2. rel with no provenance
  f = mk(); f.fg.graph.addEdgeWithKey('nop', a, b, { rels: [{ type: 'hosts', src: a, dst: b, prov: [] }] });
  v = verifyProvenance(f.fg, f.store, f.adapters); assert.ok(v.rel_unsourced >= 1 && !v.ok);
  // 3. node citing a record that is not in the store
  f = mk(); f.fg.graph.addNode('ip:9.9.9.9', { type: 'ip', label: '9.9.9.9', attrs: {}, prov: ['ghost:1'], sources: [] });
  v = verifyProvenance(f.fg, f.store, f.adapters); assert.ok(v.missing_record >= 1 && !v.ok);
  // 4. raw payload tampered after storage
  f = mk(); const rec = f.store.get(anyRec); rec.raw = { ...rec.raw, tampered: true };
  v = verifyProvenance(f.fg, f.store, f.adapters); assert.ok(v.integrity_failures >= 1 && !v.ok);
});

test('graph has no public API for adding elements without a record', () => {
  const proto = Object.getOwnPropertyNames(FangsGraph.prototype);
  assert.deepEqual(proto.filter((n) => /^(add|merge|set)/i.test(n)), [], 'FangsGraph must only grow via ingest()');
  const f = makeFangs();
  assert.equal(f.fg.ingest({ id: 'x', source: 'c2intel' }).skipped != null, true, 'record without raw is rejected');
  assert.equal(f.fg.order, 0);
});
