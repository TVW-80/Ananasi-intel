import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, readJson, makeFangs, loadSnapshotInto, withServer } from './helpers/env.js';
import { launch, CHROME } from './helpers/chrome.js';

const en = readJson('public/locales/en.json'), es = readJson('public/locales/es.json');
const html = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8'), js = fs.readFileSync(path.join(ROOT, 'public/app.js'), 'utf8');
const ph = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

test('I18N locales have identical key sets, non-empty values, and matching {placeholders}', () => {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(es).sort());
  for (const k of Object.keys(en)) { assert.ok(en[k].trim() && es[k].trim(), `empty ${k}`); assert.deepEqual(ph(en[k]), ph(es[k]), `placeholder mismatch in ${k}`); }
});

test('I18N Spanish is actually translated (>= 75% of strings differ from English; identical ones are proper nouns/acronyms)', () => {
  const same = Object.keys(en).filter((k) => en[k] === es[k]); const pct = 1 - same.length / Object.keys(en).length;
  console.log(`  ${Object.keys(en).length} keys; ${(pct * 100).toFixed(0)}% differ; identical: ${same.join(', ')}`);
  assert.ok(pct >= 0.75);
  for (const k of same) assert.ok(/^(type\.(ip|asn)|comp\.(kev|epss)|foot\.back|detail\.attack|app\.tagline)$/.test(k) || en[k].length <= 14, `untranslated: ${k}=${en[k]}`);
});

test('I18N every key referenced by index.html (data-i18n*, aria, placeholder) exists', () => {
  const keys = [...html.matchAll(/data-i18n(?:-placeholder|-aria)?="([^"]+)"/g)].map((m) => m[1]); assert.ok(keys.length >= 25);
  for (const k of keys) { assert.ok(k in en, `HTML key ${k} missing from en`); assert.ok(k in es, `HTML key ${k} missing from es`); }
});

test('I18N every key referenced by app.js exists (static t() calls + enumerated dynamic families)', () => {
  const stat = [...js.matchAll(/\b(?:t|h4)\('([a-z0-9.\-]+)'/g)].map((m) => m[1]);
  // keys that appear as quoted literals elsewhere in app.js (e.g. action tuples) also count as referenced
  const literals = Object.keys(en).filter((k) => js.includes(`'${k}'`));
  const fam = { type: ['ip', 'host', 'family', 'asn', 'campaign', 'victim'], band: ['critical', 'high', 'medium', 'low'], feed: ['ok', 'snapshot', 'degraded', 'needs-key', 'idle', 'error'], basis: ['deterministic', 'llm', 'rule'],
    comp: ['kev', 'epss', 'corroboration', 'family', 'freshness', 'centrality'], 'score.basis': ['no-cve', 'fixture', 'live', 'live-kev'], state: ['new', 'triaged', 'acknowledged'] };
  const dyn = Object.entries(fam).flatMap(([p, vs]) => vs.map((v) => `${p}.${v}`));
  for (const m of js.matchAll(/\bt\(`([a-z.]+)\./g)) assert.ok(Object.keys(fam).includes(m[1]), `dynamic key family ${m[1]}.* not enumerated in this test`);
  for (const k of [...stat, ...dyn]) { assert.ok(k in en, `${k} missing en`); assert.ok(k in es, `${k} missing es`); }
  const sev = fs.readFileSync(path.join(ROOT, 'src/scoring.js'), 'utf8'); for (const b of ['critical', 'high', 'medium', 'low']) assert.ok(sev.includes(`'${b}'`));
  const used = new Set([...stat, ...literals, ...dyn, ...[...html.matchAll(/data-i18n(?:-placeholder|-aria)?="([^"]+)"/g)].map((m) => m[1])]);
  const orphans = Object.keys(en).filter((k) => !used.has(k)); assert.deepEqual(orphans, [], `unused locale keys: ${orphans}`);
});

test('I18N basis values produced by the server are all covered', async () => {
  const f = makeFangs(); loadSnapshotInto(f); const seen = new Set();
  for (const e of f.queue.events.values()) { seen.add(`score.basis.${e.score.basis}`); seen.add(`basis.${e.narrative.basis}`); e.attack.forEach((t) => seen.add(`basis.${t.basis}`)); seen.add(`band.${e.score.band}`); }
  for (const k of seen) assert.ok(k in en && k in es, `${k} not localised`);
});

test('I18N in the browser: switching to Spanish translates every visible label, sets <html lang>, localises dynamic strings, persists, leaves no raw keys', { skip: !CHROME && 'no chrome' }, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor('window.__fangs && window.__fangs.ready === true', 20000);
      assert.equal(await b.eval(`document.getElementById('gtitle').textContent`), en['graph.title']);
      await b.eval(`const s=document.getElementById('lang'); s.value='es'; s.dispatchEvent(new Event('change'))`);
      await b.waitFor(`document.getElementById('gtitle').textContent === ${JSON.stringify(es['graph.title'])}`, 5000);
      assert.equal(await b.eval('document.documentElement.lang'), 'es');
      assert.equal(await b.eval(`document.getElementById('search').placeholder`), es['graph.search']);
      assert.equal(await b.eval(`document.querySelector('.col[data-state="new"] h3 span').textContent`), es['state.new']);
      await b.eval(`document.querySelector('.ev').click()`); await b.waitFor(`document.querySelector('#detailBody h4')`, 5000);
      const body = await b.eval(`document.getElementById('detailBody').innerText`);
      assert.ok(body.includes(es['detail.narrative'].toUpperCase()) || body.toUpperCase().includes(es['detail.narrative'].toUpperCase()), 'detail headings localised');
      const text = await b.eval(`document.body.innerText`);
      assert.ok(!/\b(detail|graph|queue|state|band|feed|comp|stats|ui|foot|type)\.[a-z-]+\b/.test(text), `raw i18n key visible: ${text.match(/\b(detail|graph|queue|state|band|feed|comp|stats|ui|foot|type)\.[a-z-]+\b/)?.[0]}`);
      await b.goto(`${base}/`); await b.waitFor('window.__fangs && window.__fangs.ready === true', 20000);
      assert.equal(await b.eval('document.documentElement.lang'), 'es', 'language choice persists');
      assert.equal(await b.eval(`document.getElementById('lang').value`), 'es');
    } finally { await b.close(); }
  });
});
