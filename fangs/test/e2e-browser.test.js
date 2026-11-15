import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFangs, loadSnapshotInto, loadSynthetic, withServer } from './helpers/env.js';
import { launch, CHROME } from './helpers/chrome.js';

const opts = { skip: !CHROME && 'no chrome installed' };
const BOOT = 'window.__fangs && window.__fangs.ready === true && window.__fangs.streaming === true';

test('E2E board loads real + synthetic data with no page errors; canvas graph matches the API; keyboard-reachable queue', opts, async () => {
  const f = makeFangs(); loadSnapshotInto(f); loadSynthetic(f, 1); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch(); const errs = []; b.on((m) => { if (m.method === 'Runtime.exceptionThrown') errs.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text); if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') errs.push(JSON.stringify(m.params.args.map((a) => a.value || a.description))); });
    try {
      await b.goto(`${base}/`); await b.waitFor(BOOT, 20000);
      const api = await (await fetch(`${base}/api/graph`)).json();
      assert.equal(await b.eval('window.__fangs.state.cy.nodes().length'), api.stats.nodes); assert.equal(await b.eval('window.__fangs.state.cy.edges().length'), api.stats.edges);
      assert.equal(await b.eval(`document.getElementById('banner').hidden`), false, 'synthetic banner shown when synthetic data is present');
      assert.ok((await b.eval(`document.getElementById('banner').textContent`)).includes('SYNTHETIC'));
      assert.ok(await b.eval(`document.querySelectorAll('button.ev').length`) > 10); assert.ok(await b.eval(`[...document.querySelectorAll('.feed')].some(e => e.textContent.includes('snapshot'))`), 'feed health shows the snapshot state');
      assert.ok(await b.eval(`document.querySelector('.ev').dataset.band`));
      assert.deepEqual(errs, []);
    } finally { await b.close(); }
  });
});

test('E2E detail pane shows narrative, severity breakdown, ATT&CK chips and expandable source records; CAD buttons walk the lifecycle', opts, async () => {
  const f = makeFangs(); loadSnapshotInto(f); loadSynthetic(f, 1); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor(BOOT, 20000);
      await b.eval(`document.querySelector('#list-triaged .ev, #list-new .ev').click()`); await b.waitFor(`document.querySelector('#detailBody .narr')`, 5000);
      assert.ok((await b.eval(`document.querySelector('#detailBody .narr').textContent`)).length > 80);
      assert.ok(await b.eval(`document.querySelectorAll('#detailBody .bars .bar-o').length`) === 6); assert.ok(await b.eval(`document.querySelectorAll('#detailBody a.ttp').length`) >= 1);
      assert.ok(await b.eval(`[...document.querySelectorAll('#detailBody a.ttp')].every(a => a.href.startsWith('https://attack.mitre.org/') && a.rel.includes('noopener'))`));
      await b.waitFor(`document.querySelectorAll('#detailBody details.rec').length >= 1`, 5000);
      assert.ok(await b.eval(`document.querySelector('#detailBody details.rec pre').textContent.includes('sha256:')`));
      // lifecycle via UI: pick a NEW event
      const newId = await b.eval(`document.querySelector('#list-new .ev')?.dataset.id`);
      if (newId) {
        await b.eval(`document.querySelector('#list-new .ev').click()`); await b.waitFor(`document.querySelector('#detailBody .actions button')`, 5000);
        await b.eval(`document.querySelector('#detailBody .actions button').click()`); await b.waitFor(`document.querySelector('#list-triaged .ev[data-id="${newId}"]')`, 5000);
        await b.eval(`document.querySelector('#detailBody .actions button').click()`); await b.waitFor(`document.querySelector('#list-acknowledged .ev[data-id="${newId}"]')`, 5000);
        assert.equal(await b.eval(`document.querySelector('#detailBody .actions button')`), null, 'no further action after acknowledged');
        assert.equal(f.queue.get(newId).state, 'acknowledged', 'server state matches the UI');
      }
    } finally { await b.close(); }
  });
});

test('E2E provenance inspector: clicking a node and an edge shows the source records behind them', opts, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor(BOOT, 20000);
      await b.eval(`window.__fangs.state.cy.nodes('[type = "ip"]')[0].emit('tap'); true`); await b.waitFor(`document.querySelectorAll('#detailBody details.rec').length >= 1`, 5000);
      assert.ok((await b.eval(`document.querySelector('#detailBody details.rec summary').textContent`)).includes('c2intel'));
      assert.ok((await b.eval(`document.querySelector('#detailBody details.rec pre').textContent`)).includes('snapshot:c2intel-2026-11-15'));
      await b.eval(`window.__fangs.state.cy.edges()[0].emit('tap'); true`); await b.waitFor(`document.querySelector('#detailBody h4')?.textContent.toLowerCase().includes('relationships')`, 5000);
      await b.waitFor(`document.querySelectorAll('#detailBody details.rec').length >= 1`, 5000);   // records load asynchronously after the heading
    } finally { await b.close(); }
  });
});

test('E2E XSS: hostile feed text (brand with <img onerror>) renders as inert text, never as markup', opts, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor(BOOT, 20000);
      const payload = '<img src=x onerror=window.__pwned=1>';
      f.ingestRecords(f.adapters.get('openphish').parse([{ text: JSON.stringify({ url: 'https://login.xss-test.example/a', brand: payload }) + '\n', url: 'fixture:xss' }]));
      const sel = `window.__fangs.state.cy.nodes('[type = "victim"]').filter(n => n.data('label').includes('onerror'))`;
      await b.waitFor(`${sel}.nonempty()`, 5000);
      await b.eval(`${sel}[0].emit('tap'); true`); await b.waitFor(`document.getElementById('detailBody').innerText.includes('onerror')`, 5000);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(await b.eval('window.__pwned'), undefined, 'script executed from feed data!'); assert.equal(await b.eval(`document.querySelectorAll('#detailBody img, #cols img').length`), 0);
      assert.ok((await b.eval(`document.getElementById('detailBody').innerText`)).includes(payload), 'payload visible as literal text');
    } finally { await b.close(); }
  });
});

test('E2E reconnect: a client that drops and reconnects with Last-Event-ID gets the events it missed', opts, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base, server) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor(BOOT, 20000);
      const before = await b.eval('window.__fangs.state.events.size');
      server.closeClients();                                        // server drops every SSE connection
      f.ingestRecords(f.adapters.get('urlhaus').parse([{ text: JSON.stringify({ urls: [{ id: 'r1', url: 'http://198.51.100.99/missed.sh', tags: ['mirai', 'CVE-2021-44228'] }] }), url: 'fixture:reconnect' }]));
      await b.waitFor(`window.__fangs.state.events.size === ${before + 1}`, 10000);   // EventSource auto-reconnects with Last-Event-ID
    } finally { await b.close(); }
  });
});
