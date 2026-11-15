// FANGS HTTP server: static UI, JSON API, and SSE dispatch stream. Zero web-framework deps.
// Binds to loopback by default. Keys are read from the environment and never serialised into any response.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Fangs } from './src/pipeline.js';
import { startReplay } from './src/replay.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(HERE, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const json = (res, code, obj) => { const b = JSON.stringify(obj); res.writeHead(code, { 'content-type': MIME['.json'], 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(b); };

function serveFile(res, file, cache = 'no-cache') {
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': cache, 'content-security-policy': CSP, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
    res.end(buf);
  });
}

export function createServer(fangs, { allowReplay = true } = {}) {
  const clients = new Set();
  fangs.on('msg', (m) => { for (const c of clients) c.write(`id: ${m.id}\nevent: ${m.type}\ndata: ${JSON.stringify(m.data)}\n\n`); });
  const hb = setInterval(() => { for (const c of clients) c.write(': hb\n\n'); }, 15000); hb.unref();
  let replay = null;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = decodeURIComponent(url.pathname);
    try {
      if (req.method === 'GET') {
        if (p === '/api/stream') {
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no', 'x-content-type-options': 'nosniff' });
          res.write('retry: 2000\n\n');
          const last = Number(req.headers['last-event-id'] || url.searchParams.get('since') || 0);
          if (last > 0) for (const m of fangs.since(last)) res.write(`id: ${m.id}\nevent: ${m.type}\ndata: ${JSON.stringify(m.data)}\n\n`);
          res.write(`event: hello\ndata: ${JSON.stringify({ seq: fangs.seq })}\n\n`);
          clients.add(res); req.on('close', () => clients.delete(res));
          return;
        }
        if (p === '/api/graph') return json(res, 200, fangs.graphView());
        if (p === '/api/events') return json(res, 200, { counts: fangs.queue.counts(), events: fangs.queue.ranked({ state: url.searchParams.get('state') || undefined }).slice(0, 500) });
        if (p.startsWith('/api/events/')) { const e = fangs.queue.get(p.slice(12)); return e ? json(res, 200, e) : json(res, 404, { error: 'unknown event' }); }
        if (p.startsWith('/api/records/')) { const r = fangs.recordView(p.slice(13)); return r ? json(res, 200, r) : json(res, 404, { error: 'unknown record' }); }
        if (p === '/api/feeds') return json(res, 200, { feeds: [...fangs.feedStatus.values()], vuln: { basis: fangs.vuln.basis }, llm: fangs.llmStatus(), attack: fangs.catalog.meta, replay: replay ? replay.status() : null });
        if (p === '/api/health') return json(res, 200, { ok: true, nodes: fangs.fg.order, edges: fangs.fg.size, records: fangs.store.size, seq: fangs.seq });
        if (p === '/vendor/cytoscape.js') return serveFile(res, path.join(HERE, 'node_modules', 'cytoscape', 'dist', 'cytoscape.min.js'), 'public, max-age=3600');
        const rel = p === '/' ? 'index.html' : p.slice(1);
        const file = path.resolve(PUBLIC, rel);
        if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end('forbidden'); }
        return serveFile(res, file);
      }
      if (req.method === 'POST') {
        if (req.headers['x-fangs'] !== '1') return json(res, 403, { error: 'missing x-fangs header' });
        let body = ''; let size = 0;
        for await (const ch of req) { size += ch.length; if (size > 4096) return json(res, 413, { error: 'too large' }); body += ch; }
        let j = {}; try { j = body ? JSON.parse(body) : {}; } catch { return json(res, 400, { error: 'bad json' }); }
        const m = /^\/api\/events\/([^/]+)\/transition$/.exec(p);
        if (m) { const r = fangs.queue.transition(m[1], j.to, String(j.actor || 'analyst').slice(0, 40)); if (!r.ok) return json(res, r.code, { error: r.error }); fangs.publish('event-update', { event: r.event }); return json(res, 200, r.event); }
        if (p === '/api/relayout') { fangs.runAnalysis({ relayout: true }); return json(res, 200, { ok: true }); }
        if (p === '/api/replay' && allowReplay) {
          if (replay) replay.stop();
          replay = startReplay(fangs, { rateHz: Math.min(50, Math.max(0.2, Number(j.rateHz) || 2)) });
          return json(res, 200, replay.status());
        }
        return json(res, 404, { error: 'not found' });
      }
      res.writeHead(405); res.end();
    } catch (e) { json(res, 500, { error: 'internal error' }); }
  });
  server.on('close', () => { clearInterval(hb); for (const c of clients) c.end(); });
  server.closeClients = () => { for (const c of clients) c.end(); clients.clear(); };
  return server;
}

// CLI entry
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8757);
  const host = process.env.HOST || '127.0.0.1';
  const fangs = new Fangs();
  fangs.start({ poll: process.env.FANGS_OFFLINE !== '1' });
  createServer(fangs).listen(port, host, () => console.log(`FANGS board: http://${host}:${port}/  (LLM: ${fangs.llmStatus().configured.map((c) => c.name).join(', ') || 'deterministic only'})`));
}
