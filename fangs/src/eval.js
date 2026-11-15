// Evaluation harness shared by tests and scripts/bench.js. All numbers it returns are measured, never asserted.
import { Fangs } from './pipeline.js';
import { buildReplayRecords } from './replay.js';
import { generateLabelledStream } from './fixtures.js';
import { severity } from './scoring.js';
import { ndcg } from './dispatch.js';
import { rng } from './util.js';

const prf = (tp, fp, fn) => { const p = tp + fp ? tp / (tp + fp) : 1, r = tp + fn ? tp / (tp + fn) : 1; return { p, r, f1: p + r ? (2 * p * r) / (p + r) : 0 }; };

function ari(labelsA, labelsB) {
  // Adjusted Rand Index over equal-length label arrays
  const n = labelsA.length; if (n < 2) return 1;
  const cont = new Map(); const ra = new Map(), rb = new Map();
  for (let i = 0; i < n; i++) { const k = `${labelsA[i]}|${labelsB[i]}`; cont.set(k, (cont.get(k) || 0) + 1); ra.set(labelsA[i], (ra.get(labelsA[i]) || 0) + 1); rb.set(labelsB[i], (rb.get(labelsB[i]) || 0) + 1); }
  const c2 = (x) => (x * (x - 1)) / 2;
  let sumC = 0, sumA = 0, sumB = 0; for (const v of cont.values()) sumC += c2(v); for (const v of ra.values()) sumA += c2(v); for (const v of rb.values()) sumB += c2(v);
  const exp = (sumA * sumB) / c2(n), max = (sumA + sumB) / 2;
  return max === exp ? 1 : (sumC - exp) / (max - exp);
}

export function evaluateReplay(seed, opts = {}) {
  const f = new Fangs({ env: { FANGS_NO_ENRICH: '1' } });
  const { recs, camp } = buildReplayRecords(f, { seed, ...opts });
  f.ingestRecords(recs);
  const a = f.runAnalysis();
  const T = camp.truth;
  const sys = f.fg.allRelKeys();
  const obs = new Set(T.observable), world = new Set(T.world);
  let tpO = 0, tpW = 0;
  for (const k of sys) { if (obs.has(k)) tpO++; if (world.has(k)) tpW++; }
  const ingest = prf(tpO, sys.size - tpO, obs.size - tpO);          // fidelity to what the records say
  const worldEdges = prf(tpW, sys.size - tpW, world.size - tpW);   // vs full simulated truth (recall capped by unobserved edges)

  // Campaign reconstruction: label each community by the plurality family node inside it (uses only graph evidence).
  const comm = a.communities;
  const famInComm = new Map();
  for (const [n, c] of Object.entries(comm)) if (n.startsWith('family:')) { (famInComm.get(c) || famInComm.set(c, []).get(c)).push(n.slice(7)); }
  const labelOf = (c) => { const fs = famInComm.get(c); if (!fs) return null; const cnt = {}; for (const x of fs) cnt[x] = (cnt[x] || 0) + 1; return Object.entries(cnt).sort((x, y) => y[1] - x[1])[0][0]; };
  const truthIps = Object.keys(T.hostCampaign).filter((id) => f.fg.graph.hasNode(id));
  const pred = {}; for (const id of truthIps) pred[id] = labelOf(comm[id]);
  const perCamp = {};
  let tpS = 0, fpS = 0, fnS = 0;
  for (const c of T.campaigns) {
    const truthSet = new Set(c.hosts.filter((id) => f.fg.graph.hasNode(id)));
    const predSet = new Set(truthIps.filter((id) => pred[id] === c.family));
    let tp = 0; for (const id of predSet) if (truthSet.has(id)) tp++;
    perCamp[c.family] = { ...prf(tp, predSet.size - tp, truthSet.size - tp), truth: truthSet.size, predicted: predSet.size };
    tpS += tp; fpS += predSet.size - tp; fnS += truthSet.size - tp;
  }
  const micro = prf(tpS, fpS, fnS);
  const hiddenIds = T.hidden.filter((id) => f.fg.graph.hasNode(id));
  const hiddenRecovered = hiddenIds.filter((id) => pred[id] === T.hostCampaign[id]).length;
  // pairwise (edge-level) precision/recall of the implied "same campaign" relation
  let ptp = 0, pfp = 0, pfn = 0;
  for (let i = 0; i < truthIps.length; i++) for (let j = i + 1; j < truthIps.length; j++) {
    const sameT = T.hostCampaign[truthIps[i]] === T.hostCampaign[truthIps[j]], sameP = comm[truthIps[i]] === comm[truthIps[j]];
    if (sameT && sameP) ptp++; else if (!sameT && sameP) pfp++; else if (sameT && !sameP) pfn++;
  }
  return {
    seed, nodes: f.fg.order, rels: sys.size, communities: a.count, modularity: a.modularity,
    ingest, worldEdges, campaignMicro: micro, perCampaign: perCamp,
    hiddenHosts: hiddenIds.length, hiddenRecovered, hiddenRecovery: hiddenIds.length ? hiddenRecovered / hiddenIds.length : 1,
    pairwise: prf(ptp, pfp, pfn), ari: ari(truthIps.map((id) => comm[id]), truthIps.map((id) => T.hostCampaign[id])),
    rejected: f.fg.rejected.length,
  };
}

export function evaluateRanking(seed, { n = 300, ks = [10, 25, 50], shuffles = 50 } = {}) {
  const stream = generateLabelledStream({ seed, n });
  const scored = stream.map((e) => ({ ...e, sev: severity(e.features).score }));
  const byScore = [...scored].sort((x, y) => y.sev - x.sev || x.idx - y.idx);
  const fifo = [...scored].sort((x, y) => x.idx - y.idx);            // arrival order = severity-blind baseline
  const R = rng(seed * 7919);
  const out = { seed, n, ks: {} };
  for (const k of ks) {
    const sc = ndcg(byScore.map((e) => e.grade), k);
    const ff = ndcg(fifo.map((e) => e.grade), k);
    let rnd = 0;
    for (let s = 0; s < shuffles; s++) { const arr = [...scored]; for (let i = arr.length - 1; i > 0; i--) { const j = Math.floor(R() * (i + 1)); [arr[i], arr[j]] = [arr[j], arr[i]]; } rnd += ndcg(arr.map((e) => e.grade), k); }
    // permutation sanity: scores shuffled across events should collapse to ~baseline
    out.ks[k] = { severity: sc, fifo: ff, random: rnd / shuffles };
  }
  return out;
}
