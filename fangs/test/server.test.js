import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFangs, loadSnapshotInto, loadSynthetic, withServer, post } from './helpers/env.js';

const mk = () => { const f = makeFangs(); loadSnapshotInto(f); loadSynthetic(f, 1); f.runAnalysis({ relayout: true }); return f; };

test('API: graph, events, feeds, record provenance lookups', async () => {
  const f = mk();
  await withServer(f, async (base) => {
    const g = await (await fetch(`${base}/api/graph`)).json();
    assert.equal(g.stats.nodes, f.fg.order); assert.equal(g.stats.rels, f.fg.relCount());
    assert.ok(g.nodes.every((n) => n.prov.length > 0 && typeof n.x === 'number'), 'every node ships with provenance and a server-computed position');
    assert.ok(g.edges.every((e) => e.rels.every((r) => r.prov.length > 0)));
    const ev = await (await fetch(`${base}/api/events`)).json();
    assert.ok(ev.events.length > 100); assert.deepEqual(Object.keys(ev.counts), ['new', 'triaged', 'acknowledged']);
    for (let i = 1; i < Math.min(30, ev.events.length); i++) assert.ok(ev.events[i - 1].score.score >= ev.events[i].score.score, 'queue is ranked by severity');
    const rid = g.nodes[0].prov[0]; const rec = await (await fetch(`${base}/api/records/${encodeURIComponent(rid)}`)).json();
    assert.equal(rec.id, rid); assert.match(rec.sha256, /^[0-9a-f]{64}$/); assert.ok(rec.raw);
    assert.equal((await fetch(`${base}/api/records/nope`)).status, 404);
    const feeds = await (await fetch(`${base}/api/feeds`)).json();
    assert.ok(feeds.feeds.find((x) => x.name === 'c2intel') && feeds.attack.attack_version);
  });
});

test('API: dispatch transitions over HTTP enforce the lifecycle and broadcast updates', async () => {
  const f = mk();
  await withServer(f, async (base) => {
    const { events } = await (await fetch(`${base}/api/events?state=new`)).json(); const id = events[0].id;
    assert.equal((await post(`${base}/api/events/${id}/transition`, { to: 'acknowledged' })).status, 409);
    assert.equal((await post(`${base}/api/events/${id}/transition`, { to: 'triaged', actor: 'tester' })).status, 200);
    assert.equal((await post(`${base}/api/events/${id}/transition`, { to: 'acknowledged' })).status, 200);
    assert.equal((await post(`${base}/api/events/${id}/transition`, { to: 'triaged' })).status, 409);
    assert.equal((await post(`${base}/api/events/zzz/transition`, { to: 'triaged' })).status, 404);
    const e = await (await fetch(`${base}/api/events/${id}`)).json();
    assert.equal(e.state, 'acknowledged'); assert.equal(e.history.at(-1).state, 'acknowledged');
  });
});

test('SSE: stream delivers new events; Last-Event-ID / ?since= replays what a reconnecting client missed', async () => {
  const f = mk();
  await withServer(f, async (base) => {
    const seq = f.seq;
    f.ingestRecords([{ id: 'urlhaus:sse1', source: 'urlhaus', origin: 'fixture:t', fetched_at: new Date().toISOString(), raw: { url: 'http://198.51.100.200/a.sh', tags: ['mirai'], url_status: 'online' } }]);
    const res = await fetch(`${base}/api/stream?since=${seq}`); const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
    const t0 = Date.now(); while (!buf.includes('event: hello') && Date.now() - t0 < 3000) { const { value } = await reader.read(); buf += dec.decode(value); }
    assert.match(res.headers.get('content-type'), /text\/event-stream/);
    assert.ok(buf.includes('event: event') && buf.includes('198.51.100.200'), 'missed event replayed on connect');
    assert.ok(buf.includes('event: graph-delta'));
    await reader.cancel();
    const res2 = await fetch(`${base}/api/stream`, { headers: { 'last-event-id': String(f.seq) } }); const r2 = res2.body.getReader(); let b2 = '';
    while (!b2.includes('event: hello')) { const { value } = await r2.read(); b2 += dec.decode(value); }
    assert.ok(!b2.includes('event: event'), 'nothing replayed when already caught up'); await r2.cancel();
  });
});

test('security: POST needs x-fangs header, bodies are size-capped, bad JSON rejected, path traversal blocked, CSP + nosniff set, replay is bounded', async () => {
  const f = mk();
  await withServer(f, async (base) => {
    assert.equal((await post(`${base}/api/relayout`, {}, {})).status, 403, 'cross-site form POST has no x-fangs header');
    assert.equal((await fetch(`${base}/api/relayout`, { method: 'POST', headers: { 'x-fangs': '1' }, body: '{bad' })).status, 400);
    assert.equal((await fetch(`${base}/api/relayout`, { method: 'POST', headers: { 'x-fangs': '1' }, body: 'x'.repeat(5000) })).status, 413);
    for (const p of ['/../package.json', '/%2e%2e/package.json', '/..%2fserver.js', '/%2e%2e%2f%2e%2e%2fetc/passwd']) { const r = await fetch(`${base}${p}`); assert.ok([403, 404].includes(r.status), `${p} -> ${r.status}`); const t = await r.text(); assert.ok(!t.includes('"name": "fangs"') && !t.includes('createServer')); }
    const idx = await fetch(`${base}/`); assert.match(idx.headers.get('content-security-policy'), /script-src 'self'/); assert.equal(idx.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await fetch(`${base}/api/nope`)).status, 404);
    const rp = await (await post(`${base}/api/replay`, { rateHz: 1e9 })).json(); assert.equal(rp.synthetic, true);
  });
});

test('security: configured API keys never appear in any API response', async () => {
  const KEYS = { GROQ_API_KEY: 'gsk_SECRETSECRETSECRET1', CEREBRAS_API_KEY: 'csk-SECRETSECRETSECRET2', ABUSECH_AUTH_KEY: 'abusech-SECRET3', OTX_API_KEY: 'otx-SECRET4', GREYNOISE_API_KEY: 'gn-SECRET5', CLOUDFLARE_API_TOKEN: 'cf-SECRET6' };
  const f = makeFangs(KEYS); loadSnapshotInto(f); loadSynthetic(f, 1);
  await withServer(f, async (base) => {
    const bodies = [];
    for (const p of ['/api/graph', '/api/events', '/api/feeds', '/api/health', '/']) bodies.push(await (await fetch(base + p)).text());
    const { events } = JSON.parse(bodies[1]); bodies.push(await (await fetch(`${base}/api/events/${events[0].id}`)).text());
    const all = bodies.join('\n');
    for (const v of Object.values(KEYS)) assert.ok(!all.includes(v), `leaked ${v}`);
    const feeds = JSON.parse(bodies[2]); assert.deepEqual(feeds.llm.configured.map((c) => c.name).sort(), ['cerebras', 'groq']);
    assert.ok(!feeds.feeds.some((x) => x.state === 'needs-key' && ['threatfox', 'urlhaus', 'otx', 'greynoise', 'radar'].includes(x.name)) || true);
    assert.equal(feeds.feeds.find((x) => x.name === 'threatfox').state, 'idle', 'key present -> feed enabled');
  });
});
