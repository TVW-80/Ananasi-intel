import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, layoutGraph, HOME_VICTIM } from './reconGraph.js';

const events = [
  { adversary: 'RU', technique: { id: 'T1486', name: 'Data Encrypted for Impact' }, malware: 'LockBit', ip: '198.51.100.7', cve: 'CVE-2026-1' },
  { adversary: 'RU', technique: { id: 'T1071', name: 'Application Layer Protocol' }, ip: '198.51.100.7' },
  { adversary: 'Unknown', technique: { id: 'T1566', name: 'Phishing' } },
];

test('buildGraph creates typed nodes, a victim hub, and dedupes edges', () => {
  const g = buildGraph(events);
  const types = new Set(g.nodes.map((n) => n.type));
  assert.ok(types.has('victim') && types.has('adversary') && types.has('technique') && types.has('malware') && types.has('infra') && types.has('cve'));
  assert.ok(g.nodes.some((n) => n.type === 'victim' && n.label === HOME_VICTIM));
  // The shared IP appears once, with weight from both events.
  const ip = g.nodes.find((n) => n.label === '198.51.100.7');
  assert.equal(ip.weight, 2);
  // No duplicate edges.
  const keys = g.edges.map((e) => [e.from, e.to].sort().join('__'));
  assert.equal(keys.length, new Set(keys).size);
});

test('layoutGraph places the victim at centre and others on type rings', () => {
  const laid = layoutGraph(buildGraph(events), { width: 300, height: 240 });
  const victim = laid.nodes.find((n) => n.type === 'victim');
  assert.deepEqual([victim.x, victim.y], [150, 120]);
  assert.ok(laid.nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y)));
  // Edges resolve to endpoint coordinates.
  assert.ok(laid.edges.every((e) => e.a && e.b));
});

test('buildGraph caps node count', () => {
  const many = Array.from({ length: 200 }, (_, i) => ({ adversary: `C${i}`, technique: { id: 'T1595', name: 'Active Scanning' }, ip: `10.0.0.${i}` }));
  const g = buildGraph(many, { maxNodes: 30 });
  assert.ok(g.nodes.length <= 31); // + victim
});
