import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { analyze, layout } from '../src/analytics.js';
import { plantedGraph } from './helpers/synth-graph.js';
import { makeFangs, withServer, loadSnapshotInto, ROOT } from './helpers/env.js';
import { launch, CHROME } from './helpers/chrome.js';
import { createServer } from '../server.js';

const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]; };
const RESULTS = path.join(ROOT, 'results', 'perf.json');
const save = (patch) => { let cur = {}; try { cur = JSON.parse(fs.readFileSync(RESULTS, 'utf8')); } catch { /* first write */ } fs.mkdirSync(path.dirname(RESULTS), { recursive: true }); fs.writeFileSync(RESULTS, JSON.stringify({ ...cur, ...patch }, null, 1)); };
const urlhausRec = (i, cve = 'CVE-2021-44228') => ({ id: `urlhaus:perf-${i}-${Date.now()}`, source: 'urlhaus', origin: 'fixture:perf', fetched_at: new Date().toISOString(), raw: { url: `http://198.51.100.${(i % 250) + 1}/p${i}-${Math.random().toString(36).slice(2, 7)}.sh`, tags: ['mirai', cve], url_status: 'online' } });

test('PASS perf: 1k-node layout < 300 ms (median of 9 after warm-up; also reports p95/max and analytics cost)', () => {
  const runs = [], an = [];
  for (let i = 0; i < 11; i++) {
    const g = plantedGraph(1000);
    const t = performance.now(); const a = analyze(g); const ta = performance.now() - t;
    const r = layout(g, a.communities);
    if (i >= 2) { runs.push(r.ms); an.push(ta); }
  }
  const out = { nodes: 1000, edges: plantedGraph(1000).size, layout_ms: { median: pct(runs, 50), p95: pct(runs, 95), max: Math.max(...runs), runs: runs.map((x) => +x.toFixed(1)) }, analytics_ms: { median: pct(an, 50), max: Math.max(...an) } };
  console.log(`  1k-node layout: median ${out.layout_ms.median.toFixed(1)} ms, p95 ${out.layout_ms.p95.toFixed(1)}, max ${out.layout_ms.max.toFixed(1)}   (Louvain+betweenness: median ${out.analytics_ms.median.toFixed(1)} ms)`);
  save({ layout_1k: out });
  assert.ok(out.layout_ms.median < 300, `median ${out.layout_ms.median}`);
  assert.ok(out.layout_ms.max < 300, `max ${out.layout_ms.max} (every run, not just the median)`);
});

test('PASS perf: event -> board < 5 s over a real HTTP SSE connection (60 events, on a loaded 305-node real graph)', async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const res = await fetch(`${base}/api/stream`); const reader = res.body.getReader(); const dec = new TextDecoder();
    const waiters = new Map(); let buf = '';
    (async () => { for (;;) { const { value, done } = await reader.read(); if (done) return; buf += dec.decode(value); let i; while ((i = buf.indexOf('\n\n')) >= 0) { const frame = buf.slice(0, i); buf = buf.slice(i + 2); if (!frame.includes('event: event\n')) continue; const m = /data: (.*)/.exec(frame); const d = JSON.parse(m[1]); const w = waiters.get(d.event.indicator); if (w) { w(performance.now()); waiters.delete(d.event.indicator); } } } })();
    await new Promise((r) => setTimeout(r, 100));
    const lat = [];
    for (let i = 0; i < 60; i++) {
      const rec = urlhausRec(i); const ind = rec.raw.url;
      const arrived = new Promise((r) => waiters.set(ind, r));
      const t0 = performance.now(); f.ingestRecords([rec], { t0: Date.now() });
      lat.push((await arrived) - t0);
      await new Promise((r) => setTimeout(r, 20));
    }
    await reader.cancel();
    const out = { events: lat.length, ms: { p50: pct(lat, 50), p95: pct(lat, 95), max: Math.max(...lat) } };
    console.log(`  event->SSE client: p50 ${out.ms.p50.toFixed(1)} ms, p95 ${out.ms.p95.toFixed(1)} ms, max ${out.ms.max.toFixed(1)} ms`);
    save({ event_to_sse_client: out });
    assert.ok(out.ms.max < 5000);
  });
});

test('PASS perf: event -> board < 5 s measured in real headless Chrome (ingest -> DOM shows the event), 20 events', { skip: !CHROME && 'no chrome installed' }, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  const server = createServer(f); await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const b = await launch();
  try {
    await b.goto(`${base}/`); await b.waitFor('window.__fangs && window.__fangs.ready === true', 20000);
    const lat = [];
    for (let i = 0; i < 20; i++) {
      const rec = urlhausRec(1000 + i); const ind = rec.raw.url; const short = ind.length > 26 ? `${ind.slice(0, 25)}…` : ind;
      const t0 = performance.now(); f.ingestRecords([rec], { t0: Date.now() });
      await b.waitFor(`document.getElementById('cols').innerText.includes(${JSON.stringify(short)})`, 5000);
      lat.push(performance.now() - t0); await new Promise((r) => setTimeout(r, 30));
    }
    const nodesInGraph = await b.eval('window.__fangs.state.cy.nodes().length');
    const out = { events: lat.length, ms: { p50: pct(lat, 50), p95: pct(lat, 95), max: Math.max(...lat) }, polling_granularity_ms: '~50 (includes CDP round-trip; upper bound)' };
    console.log(`  event->DOM (Chrome): p50 ${out.ms.p50.toFixed(0)} ms, p95 ${out.ms.p95.toFixed(0)} ms, max ${out.ms.max.toFixed(0)} ms; graph now ${nodesInGraph} nodes`);
    save({ event_to_dom_chrome: out });
    assert.ok(out.ms.max < 5000); assert.ok(nodesInGraph >= f.fg.order - 5, 'graph deltas reached the canvas');
  } finally { await b.close(); server.closeClients(); await new Promise((r) => server.close(r)); }
});
