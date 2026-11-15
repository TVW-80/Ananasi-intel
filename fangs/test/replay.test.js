import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { evaluateReplay } from '../src/eval.js';
import { ROOT } from './helpers/env.js';

const SEEDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];   // held-out: dev/tuning used seeds 100-104 only
const f3 = (x) => x.toFixed(3);
const mean = (a) => a.reduce((s, x) => s + x, 0) / a.length;

test('PASS known-campaign replay: edge precision/recall + C2-set reconstruction (10 held-out seeds)', () => {
  const rows = SEEDS.map((s) => evaluateReplay(s));
  const agg = (fn) => ({ mean: mean(rows.map(fn)), min: Math.min(...rows.map(fn)), max: Math.max(...rows.map(fn)) });
  const out = {
    seeds: SEEDS,
    ingest_precision: agg((r) => r.ingest.p), ingest_recall: agg((r) => r.ingest.r),
    world_edge_precision: agg((r) => r.worldEdges.p), world_edge_recall: agg((r) => r.worldEdges.r),
    c2set_precision: agg((r) => r.campaignMicro.p), c2set_recall: agg((r) => r.campaignMicro.r), c2set_f1: agg((r) => r.campaignMicro.f1),
    hidden_host_recovery: agg((r) => r.hiddenRecovery), pairwise_precision: agg((r) => r.pairwise.p), pairwise_recall: agg((r) => r.pairwise.r), ari: agg((r) => r.ari),
    communities: agg((r) => r.communities), modularity: agg((r) => r.modularity),
  };
  for (const [k, v] of Object.entries(out)) if (v.mean !== undefined) console.log(`  ${k.padEnd(22)} mean ${f3(v.mean)}  min ${f3(v.min)}  max ${f3(v.max)}`);
  fs.mkdirSync(path.join(ROOT, 'results'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'results', 'replay.json'), JSON.stringify({ generated: 'by test/replay.test.js', synthetic: true, ...out, perSeed: rows.map(({ perCampaign, ...r }) => r) }, null, 1));

  // Ingest fidelity: parsers + junk rejection + dedupe must reproduce exactly what the records say.
  for (const r of rows) { assert.equal(r.ingest.p, 1, `seed ${r.seed}: ingest precision`); assert.equal(r.ingest.r, 1, `seed ${r.seed}: ingest recall`); assert.equal(r.worldEdges.p, 1, `seed ${r.seed}: no edge outside the simulated world`); }
  // Campaign reconstruction thresholds were set from dev seeds (observed 0.93-0.99) with margin.
  assert.ok(out.c2set_f1.mean >= 0.93, `C2-set F1 mean ${out.c2set_f1.mean}`);
  assert.ok(out.c2set_f1.min >= 0.85, `C2-set F1 min ${out.c2set_f1.min}`);
  assert.ok(out.hidden_host_recovery.mean >= 0.85, `hidden-host recovery ${out.hidden_host_recovery.mean}`);
  assert.ok(out.pairwise_precision.mean >= 0.9 && out.pairwise_recall.mean >= 0.9);
});

test('replay is deterministic: same seed -> identical numbers', () => {
  const a = evaluateReplay(5), b = evaluateReplay(5);
  assert.equal(JSON.stringify([a.ingest, a.campaignMicro, a.ari, a.communities]), JSON.stringify([b.ingest, b.campaignMicro, b.ari, b.communities]));
});

test('real snapshot: resolves-to edges match the raw CSV lines exactly (no ground-truth labels exist, so this is a fidelity check, not a recall claim)', async () => {
  const { makeFangs, loadSnapshotInto } = await import('./helpers/env.js');
  const f = makeFangs(); loadSnapshotInto(f);
  const csv = fs.readFileSync(path.join(ROOT, 'data/snapshots/c2intel-2026-11-15/domainC2swithURLwithIP-30day.csv'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  const expected = new Set();
  for (const l of csv) { const p = l.split(','); const dom = p[0].toLowerCase(), ip = p[p.length - 1]; if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) expected.add(`resolves-to|host:${dom}|ip:${ip}`); }
  const have = f.fg.allRelKeys(); let missing = 0; for (const k of expected) if (!have.has(k)) missing++;
  console.log(`  real resolves-to: expected ${expected.size}, missing ${missing}`);
  assert.ok(expected.size > 50); assert.equal(missing, 0);
});
