import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DispatchQueue, ndcg } from '../src/dispatch.js';
import { severity } from '../src/scoring.js';
import { evaluateRanking } from '../src/eval.js';
import { makeFangs, loadSynthetic, ROOT } from './helpers/env.js';

test('CAD lifecycle is strictly new -> triaged -> acknowledged and audited', () => {
  const q = new DispatchQueue({ now: () => '2026-01-01T00:00:00Z' });
  const { event } = q.upsert({ kind: 'c2', family: 'sliver', indicator: '192.0.2.1', node: 'ip:192.0.2.1', source: 'c2intel', recordId: 'r1' });
  assert.equal(event.state, 'new');
  assert.equal(q.transition(event.id, 'acknowledged').code, 409, 'cannot skip triage');
  assert.equal(q.transition(event.id, 'new').code, 409);
  assert.equal(q.transition(event.id, 'triaged', 'analyst-a').ok, true);
  assert.equal(q.transition(event.id, 'triaged').code, 409, 'cannot repeat');
  assert.equal(q.transition(event.id, 'acknowledged').ok, true);
  assert.equal(q.transition(event.id, 'triaged').code, 409, 'cannot go backwards');
  assert.equal(q.transition('nope', 'triaged').code, 404);
  assert.deepEqual(event.history.map((h) => h.state), ['new', 'triaged', 'acknowledged']);
  assert.equal(event.history[1].actor, 'analyst-a');
});

test('same indicator from two sources merges (corroboration) instead of duplicating', () => {
  const f = makeFangs(); loadSynthetic(f, 1);
  const corro = [...f.queue.events.values()].filter((e) => new Set(e.sources.map((s) => s.source)).size > 1);
  assert.ok(corro.length > 0, 'expected at least one multi-source event');
  for (const e of corro) assert.ok(e.score.components.corroboration > 0);
  const nodes = [...f.queue.events.values()].map((e) => `${e.node}|${e.family}`);
  assert.equal(new Set(nodes).size, nodes.length, 'no duplicate (node,family) events');
});

test('severity: KEV and EPSS raise the score; bands need vulnerability evidence to reach critical', () => {
  const base = { sources: 1, family: 'cobaltstrike', ageHours: 1, centrality: 0.3 };
  const s0 = severity({ ...base, kev: 0, epss: 0 }), s1 = severity({ ...base, kev: 0, epss: 0.9 }), s2 = severity({ ...base, kev: 1, epss: 0.9 });
  assert.ok(s0.score < s1.score && s1.score < s2.score);
  assert.notEqual(s0.band, 'critical', 'a CVE-less event must not reach critical on family weight alone');
  assert.equal(s2.band, 'critical');
  assert.ok(severity({ ...base, ageHours: 500 }).score < severity({ ...base, ageHours: 1 }).score, 'stale events rank lower');
});

test('KEV-linked event outranks a non-KEV event end-to-end through the pipeline', () => {
  const f = makeFangs();
  const mk = (n, cve) => ({ id: `urlhaus:${n}`, source: 'urlhaus', origin: 'fixture:test', fetched_at: new Date().toISOString(), raw: { url: `http://192.0.2.${n}/x.sh`, tags: ['mirai', ...(cve ? [cve] : [])], url_status: 'online' } });
  f.ingestRecords([mk(10, null), mk(11, 'CVE-2021-44228')]);
  const ranked = f.queue.ranked();
  assert.equal(ranked[0].indicator, 'http://192.0.2.11/x.sh');
  assert.equal(ranked[0].score.components.kev, 1);
  assert.equal(ranked[0].score.basis, 'fixture', 'score must disclose that KEV/EPSS came from the sample fixture');
  assert.ok(ranked[0].attack.some((t) => t.id === 'T1190'), 'CVE-linked URL maps to exploit-public-facing-app');
});

test('PASS labelled-replay dispatch ranking beats severity-blind baselines (nDCG, 10 seeds)', () => {
  const seeds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  const rows = seeds.map((s) => evaluateRanking(s));
  const res = { synthetic_labels: true, seeds, k: {} };
  for (const k of [10, 25, 50]) {
    const sev = rows.map((r) => r.ks[k].severity), fifo = rows.map((r) => r.ks[k].fifo), rnd = rows.map((r) => r.ks[k].random);
    const m = (a) => a.reduce((x, y) => x + y, 0) / a.length;
    const wins = rows.filter((r) => r.ks[k].severity > r.ks[k].fifo && r.ks[k].severity > r.ks[k].random).length;
    res.k[k] = { severity_mean: m(sev), severity_min: Math.min(...sev), fifo_mean: m(fifo), random_mean: m(rnd), seeds_won: `${wins}/${seeds.length}` };
    console.log(`  nDCG@${k}: severity ${m(sev).toFixed(3)} (min ${Math.min(...sev).toFixed(3)})  FIFO ${m(fifo).toFixed(3)}  random ${m(rnd).toFixed(3)}  wins ${wins}/${seeds.length}`);
    assert.equal(wins, seeds.length, `severity ranking must beat both baselines on every seed @${k}`);
    assert.ok(m(sev) > m(fifo) + 0.3, `margin over FIFO @${k}`);
  }
  fs.writeFileSync(path.join(ROOT, 'results', 'ndcg.json'), JSON.stringify(res, null, 1));
});

test('nDCG sanity: perfect ranking = 1, reversed ranking < 1, all-zero grades = 0', () => {
  assert.equal(ndcg([3, 2, 1, 0], 4), 1);
  assert.ok(ndcg([0, 1, 2, 3], 4) < 0.6);
  assert.equal(ndcg([0, 0, 0], 3), 0);
});

test('null control: scores shuffled across events collapse toward the blind baseline (the benchmark can fail)', async () => {
  const { generateLabelledStream } = await import('../src/fixtures.js');
  const { rng } = await import('../src/util.js');
  let tot = 0, base = 0;
  for (let seed = 1; seed <= 10; seed++) {
    const s = generateLabelledStream({ seed }); const R = rng(seed);
    const sev = s.map((e) => severity(e.features).score);
    for (let i = sev.length - 1; i > 0; i--) { const j = Math.floor(R() * (i + 1)); [sev[i], sev[j]] = [sev[j], sev[i]]; }
    const order = s.map((e, i) => ({ g: e.grade, v: sev[i] })).sort((a, b) => b.v - a.v);
    tot += ndcg(order.map((o) => o.g), 25); base += ndcg(s.map((e) => e.grade), 25);
  }
  console.log(`  shuffled-score nDCG@25 ${(tot / 10).toFixed(3)} vs FIFO ${(base / 10).toFixed(3)}`);
  assert.ok(tot / 10 < 0.4);
});
