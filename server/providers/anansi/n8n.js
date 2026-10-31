// Anansi: same-origin bridge to the local n8n webhooks.
//
// God's Eye View 0.3.0 ships a Content Security Policy whose connect-src only
// allows the page's own origin and https:, so the browser can no longer call
// http://localhost:5678/webhook/... directly (the 0.1.x 757 panel did). This
// provider forwards GET /api/n8n/<webhook-path> to the n8n webhook base and
// returns the JSON, keeping n8n off the browser's network entirely.
//
//   N8N_WEBHOOK_BASE   default http://localhost:5678/webhook
//
// Only simple webhook names are forwarded (letters, digits, - and _), only GET,
// with a timeout and a response size cap — it is not a general-purpose proxy.

const DEFAULT_BASE = 'http://localhost:5678/webhook';
const NAME_RE = /^[A-Za-z0-9_-]{1,80}$/;
const TIMEOUT_MS = 20_000;
const MAX_BYTES = 5 * 1024 * 1024;

export function n8nWebhookBase(env = process.env) {
  const raw = String(env.N8N_WEBHOOK_BASE || DEFAULT_BASE).trim().replace(/\/+$/, '');
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('protocol');
    return url.href.replace(/\/+$/, '');
  } catch {
    return DEFAULT_BASE;
  }
}

export function createN8nMiddleware({ fetchImpl = (...a) => fetch(...a), env = process.env } = {}) {
  return async function n8nMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    // Validate the raw path (no URL normalization), so "/../x" or "%2e%2e"
    // are refused rather than tidied into a valid-looking name.
    const rawPath = String(req.url || '/').split('?')[0];
    const match = /^\/([^/]+)\/?$/.exec(rawPath);
    const name = match ? match[1] : '';
    if (!NAME_RE.test(name)) return send(400, { error: 'unknown webhook' });
    const target = `${n8nWebhookBase(env)}/${name}`;
    let upstream;
    try {
      upstream = await fetchImpl(target, {
        headers: { Accept: 'application/json', 'User-Agent': 'Anansi/1.0' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      const cause = err?.cause?.code || err?.name || 'fetch failed';
      return send(502, { error: `n8n unreachable (${cause}) — is n8n running and the workflow active?` });
    }
    const text = await upstream.text();
    if (text.length > MAX_BYTES) return send(502, { error: 'n8n response too large' });
    if (!upstream.ok) return send(upstream.status === 404 ? 404 : 502, { error: `n8n returned HTTP ${upstream.status}` });
    try {
      JSON.parse(text);
    } catch {
      return send(502, { error: 'n8n returned non-JSON' });
    }
    return send(200, text);
  };
}

export function n8nProxy() {
  const middleware = createN8nMiddleware();
  return {
    name: 'anansi-n8n-proxy',
    configureServer(server) {
      server.middlewares.use('/api/n8n', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/n8n', middleware);
    },
  };
}
