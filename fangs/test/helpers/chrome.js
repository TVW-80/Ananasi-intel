// Minimal CDP driver for headless Chrome (no puppeteer dependency). Used by browser E2E tests and screenshots.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CHROME = ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].find((p) => fs.existsSync(p)) || null;

export async function launch({ width = 1500, height = 950 } = {}) {
  if (!CHROME) throw new Error('no chrome');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fangs-chrome-'));
  const proc = spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', '--hide-scrollbars', `--window-size=${width},${height}`, '--remote-debugging-port=0', `--user-data-dir=${dir}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = ''; const to = setTimeout(() => reject(new Error('chrome start timeout')), 15000);
    proc.stderr.on('data', (d) => { buf += d; const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf); if (m) { clearTimeout(to); resolve(m[1]); } });
    proc.on('exit', () => reject(new Error('chrome exited')));
  });
  const port = new URL(wsUrl).port;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const page = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0; const pending = new Map(); const listeners = [];
  ws.onmessage = (m) => { const j = JSON.parse(m.data); if (j.id && pending.has(j.id)) { const { res, rej } = pending.get(j.id); pending.delete(j.id); j.error ? rej(new Error(j.error.message)) : res(j.result); } else listeners.forEach((l) => l(j)); };
  const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Page.enable'); await send('Runtime.enable');
  const api = {
    send, on: (fn) => listeners.push(fn),
    async goto(url) { await send('Page.navigate', { url }); await new Promise((r) => setTimeout(r, 300)); },
    async eval(expr) { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval error'); return r.result.value; },
    async waitFor(expr, timeoutMs = 10000) { const t0 = Date.now(); while (Date.now() - t0 < timeoutMs) { try { if (await api.eval(expr)) return true; } catch { /* page not ready */ } await new Promise((r) => setTimeout(r, 50)); } throw new Error(`waitFor timeout: ${expr}`); },
    async screenshot(file) { const r = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(file, Buffer.from(r.data, 'base64')); },
    async close() { try { ws.close(); } catch { /* */ } const done = new Promise((r) => proc.once('exit', r)); proc.kill('SIGKILL'); await done; try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* temp dir cleanup is best-effort */ } },
  };
  return api;
}
