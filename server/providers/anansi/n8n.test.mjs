import test from 'node:test';
import assert from 'node:assert/strict';
import { createN8nMiddleware, n8nWebhookBase } from './n8n.js';

function call(middleware, { method = 'GET', url }) {
  return new Promise((resolve) => {
    const res = {
      headersSent: false,
      writeHead(status, headers) { this.status = status; this.headers = headers; this.headersSent = true; },
      end(body) { resolve({ status: this.status, headers: this.headers, body: JSON.parse(body) }); },
    };
    middleware({ method, url }, res);
  });
}
const ok = (body) => async () => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });

test('forwards a webhook name to the configured n8n base', async () => {
  let seen;
  const mw = createN8nMiddleware({ env: { N8N_WEBHOOK_BASE: 'http://n8n.local:5678/webhook/' }, fetchImpl: async (u, o) => { seen = { u, o }; return ok([{ label: 'x' }])(); } });
  const r = await call(mw, { url: '/757-traffic' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, [{ label: 'x' }]);
  assert.equal(seen.u, 'http://n8n.local:5678/webhook/757-traffic');
  assert.equal(r.headers['Cache-Control'], 'no-store');
});

test('defaults to localhost:5678 and rejects bad bases', () => {
  assert.equal(n8nWebhookBase({}), 'http://localhost:5678/webhook');
  assert.equal(n8nWebhookBase({ N8N_WEBHOOK_BASE: 'file:///etc' }), 'http://localhost:5678/webhook');
});

test('refuses anything that is not a plain webhook name or GET', async () => {
  const mw = createN8nMiddleware({ fetchImpl: () => assert.fail('must not fetch') });
  for (const url of ['/../admin', '/a/b', '/%2e%2e', '/', '/x?y=1&z'.replace('?y=1&z', '/..')]) {
    assert.equal((await call(mw, { url })).status, 400, url);
  }
  assert.equal((await call(mw, { method: 'POST', url: '/757-traffic' })).status, 405);
});

test('reports n8n being down or misbehaving as clear errors', async () => {
  const down = createN8nMiddleware({ fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { code: 'ECONNREFUSED' }; throw e; } });
  const r = await call(down, { url: '/757-weather' });
  assert.equal(r.status, 502);
  assert.match(r.body.error, /ECONNREFUSED/);
  const html = createN8nMiddleware({ fetchImpl: async () => ({ ok: true, status: 200, text: async () => '<html>' }) });
  assert.match((await call(html, { url: '/757-news' })).body.error, /non-JSON/);
  const missing = createN8nMiddleware({ fetchImpl: async () => ({ ok: false, status: 404, text: async () => '{}' }) });
  assert.equal((await call(missing, { url: '/nope' })).status, 404);
});
