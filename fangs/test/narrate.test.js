import test from 'node:test';
import assert from 'node:assert/strict';
import { deterministicNarrative, llmNarrate, parseLlmJson, configuredProviders } from '../src/narrate.js';
import { AttackCatalog } from '../src/attack.js';
import { makeFangs, loadSynthetic } from './helpers/env.js';

const catalog = AttackCatalog.load();
const ev = { kind: 'c2', family: 'cobaltstrike', indicator: '192.0.2.7', cve: [], sources: [{ source: 'c2intel', recordId: 'r' }], attack: [], score: { score: 30, band: 'medium', basis: 'no-cve', components: { kev: 0, epss: 0, corroboration: 0 } } };
const llmReply = (content) => async () => ({ ok: true, json: async () => ({ choices: [{ message: { content } }] }) });

test('deterministic narrative is plain English, mentions the source, and never overclaims', () => {
  const n = deterministicNarrative(ev, { asn: 'AS64500', cc: 'ZZ', asnPeers: 3, communitySize: 12, communityFamily: 'cobaltstrike' });
  assert.equal(n.basis, 'deterministic');
  assert.match(n.text, /Cobalt Strike command-and-control server 192\.0\.2\.7/); assert.match(n.text, /C2IntelFeeds/); assert.match(n.text, /AS64500/);
  assert.match(n.text, /no linked CVE/); assert.match(n.text, /does not probe it/);
  assert.doesNotMatch(n.text, /attributed to|APT\d+|nation[- ]state/i);
});

test('no key configured -> LLM path makes zero network calls and returns null', async () => {
  let calls = 0; const r = await llmNarrate(ev, {}, { env: {}, fetchFn: async () => { calls++; }, catalog });
  assert.equal(r, null); assert.equal(calls, 0); assert.deepEqual(configuredProviders({}), []);
});

test('LLM success: narrative upgraded, techniques validated against STIX, invalid ones rejected and counted', async () => {
  const body = JSON.stringify({ summary: 'A Cobalt Strike server was reported.', techniques: ['T1071.001', 'T9999', 'T1573.002'] });
  const r = await llmNarrate(ev, {}, { env: { GROQ_API_KEY: 'k' }, fetchFn: llmReply(body), catalog });
  assert.equal(r.narrative.basis, 'llm'); assert.equal(r.provider, 'groq');
  assert.deepEqual(r.techniques.sort(), ['T1071.001', 'T1573.002']); assert.deepEqual(r.rejected, ['T9999']);
});

test('fallback chain: groq fails -> cerebras answers; both fail -> null (deterministic stays)', async () => {
  const seen = [];
  const f1 = async (url) => { seen.push(url); if (url.includes('groq')) throw new Error('boom'); return llmReply('{"summary":"ok","techniques":[]}')(); };
  const r = await llmNarrate(ev, {}, { env: { GROQ_API_KEY: 'a', CEREBRAS_API_KEY: 'b' }, fetchFn: f1, catalog });
  assert.equal(r.provider, 'cerebras'); assert.equal(seen.length, 2);
  assert.equal(await llmNarrate(ev, {}, { env: { GROQ_API_KEY: 'a', CEREBRAS_API_KEY: 'b' }, fetchFn: async () => { throw new Error('down'); }, catalog }), null);
  assert.equal(await llmNarrate(ev, {}, { env: { GROQ_API_KEY: 'a' }, fetchFn: async () => ({ ok: false, status: 429 }), catalog }), null);
});

test('garbage / hostile LLM output is discarded', () => {
  assert.equal(parseLlmJson('not json'), null); assert.equal(parseLlmJson('{"summary":""}'), null); assert.equal(parseLlmJson(null), null);
  const p = parseLlmJson('Sure! {"summary":"x   y","techniques":["T1071.001","DROP TABLE","<script>"]}');
  assert.equal(p.summary, 'x y'); assert.deepEqual(p.techniques, ['T1071.001']);
  assert.ok(parseLlmJson(JSON.stringify({ summary: 'a'.repeat(5000), techniques: [] })).summary.length <= 600);
});

test('timeout: a hung LLM never blocks (falls back within the budget)', async () => {
  const hang = (url, opts) => new Promise((_, rej) => { const keep = setTimeout(() => {}, 5000); opts.signal.addEventListener('abort', () => { clearTimeout(keep); rej(new Error('aborted')); }); }); // keep-alive stands in for the open socket a real fetch would hold
  const t0 = performance.now();
  const r = await llmNarrate(ev, {}, { env: { GROQ_API_KEY: 'a' }, fetchFn: hang, catalog, timeoutMs: 120 });
  assert.equal(r, null); assert.ok(performance.now() - t0 < 600);
});

test('pipeline: events are published with deterministic text immediately; LLM upgrade arrives later as event-update; API key never appears in any event', async () => {
  const SECRET = 'gsk_TESTSECRET_0123456789';
  const f = makeFangs({ GROQ_API_KEY: SECRET, FANGS_LLM_RPM: '600000' }, { llmFetch: async () => { await new Promise((r) => setTimeout(r, 80)); return { ok: true, json: async () => ({ choices: [{ message: { content: '{"summary":"LLM words.","techniques":["T1071.001","T0000"]}' } }] }) }; } });
  const msgs = []; f.on('msg', (m) => msgs.push(m));
  loadSynthetic(f, 1);
  const firstEvent = msgs.find((m) => m.type === 'event');
  assert.equal(firstEvent.data.event.narrative.basis, 'deterministic', 'board gets text without waiting for the LLM');
  await new Promise((r) => setTimeout(r, 1500));
  const upd = msgs.filter((m) => m.type === 'event-update');
  assert.ok(upd.length > 0 && upd.some((m) => m.data.event.narrative.basis === 'llm'));
  const withLlmTtp = upd.find((m) => m.data.event.attack.some((t) => t.basis === 'llm'));
  assert.ok(withLlmTtp || upd.every((m) => m.data.event.attack.every((t) => t.id !== 'T0000')), 'bogus technique T0000 never reaches the board');
  assert.ok(!JSON.stringify(msgs).includes(SECRET), 'API key leaked into the event stream');
  assert.ok(f.stats.llm_ok > 20, `burst should be worked through the queue, got ${f.stats.llm_ok}`);
  const survivors = [...f.queue.events.values()].filter((e) => e.narrative.basis === 'llm');
  assert.ok(survivors.length > 20, 'LLM narration must survive periodic re-scoring');
  assert.ok(survivors.every((e) => e.attack.every((t) => t.id !== 'T0000')));
});

test('LLM pacing: with the default 20/min budget a burst is rate-limited, never exceeding the budget; the rest wait, not dropped', async () => {
  let calls = 0;
  const f = makeFangs({ GROQ_API_KEY: 'k' }, { llmFetch: async () => { calls++; return { ok: true, json: async () => ({ choices: [{ message: { content: '{"summary":"x","techniques":[]}' } }] }) }; } });
  loadSynthetic(f, 1);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(calls, 1, 'only one call fits the pacing window immediately');
  assert.equal([...f.queue.events.values()].filter((e) => e.narrative.basis === 'llm').length, 1, 'the rest keep deterministic text until their pacing slot');
  assert.ok(f._llmPending.size > 50, 'remaining events wait in the queue rather than being dropped');
});
