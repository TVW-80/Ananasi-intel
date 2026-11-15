import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Fangs } from '../../src/pipeline.js';
import { createServer } from '../../server.js';
import { buildReplayRecords } from '../../src/replay.js';

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function makeFangs(env = {}, opts = {}) {
  return new Fangs({ env: { FANGS_NO_ENRICH: '1', ...env }, ...opts });
}
export function loadSnapshotInto(f) { return f.loadSnapshot(); }
export function loadSynthetic(f, seed = 1) { const { recs, camp } = buildReplayRecords(f, { seed }); f.ingestRecords(recs); return camp; }

export async function withServer(fangs, fn, opts) {
  const server = createServer(fangs, opts);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { return await fn(base, server); }
  finally { server.closeClients(); await new Promise((r) => server.close(r)); }
}
export const post = (url, body = {}, headers = { 'x-fangs': '1' }) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
export const readJson = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
export const walk = (dir, filter = () => true, out = []) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'scratch', '.git'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    e.isDirectory() ? walk(p, filter, out) : filter(p) && out.push(p);
  }
  return out;
};
