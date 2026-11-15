import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { makeFangs, loadSnapshotInto, loadSynthetic, walk, ROOT } from './helpers/env.js';
import { adapterMap, ENRICHERS } from '../src/adapters/index.js';

const SRC = walk(path.join(ROOT, 'src'), (p) => p.endsWith('.js')).concat([path.join(ROOT, 'server.js')]);
const PUBLIC = walk(path.join(ROOT, 'public'), (p) => /\.(js|html|css)$/.test(p));
const read = (p) => fs.readFileSync(p, 'utf8');
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

// Hosts FANGS may ever contact. Indicator hosts (from feeds) are never on this list.
const ALLOWED_HOSTS = new Set(['raw.githubusercontent.com', 'feodotracker.abuse.ch', 'threatfox-api.abuse.ch', 'urlhaus-api.abuse.ch', 'openphish.com', 'isc.sans.edu', 'api.cloudflare.com', 'api.greynoise.io', 'otx.alienvault.com',
  'www.cisa.gov', 'api.first.org', 'stat.ripe.net', 'api.groq.com', 'api.cerebras.ai', 'origin.asn.cymru.com', 'asn.cymru.com', 'github.com']);

test('BOUNDARY defensive-only: no raw sockets, subprocesses, scanners or exploit tooling in server code', () => {
  const banned = [/\bnode:net['"]\s*;?[\s\S]{0,0}/, /child_process/, /\bnet\.(connect|createConnection|Socket)\b/, /\bdgram\b/, /\btls\.connect\b/, /\bhttp\.request\b/, /\bhttps\.request\b/, /\beval\s*\(/, /new Function\(/, /\bpuppeteer\b/, /\bnmap\b/i, /\bmasscan\b/i, /\bexploit(ation)?[-_ ]?(kit|payload|module)\b/i];
  for (const f of SRC) {
    const code = stripComments(read(f));
    for (const re of banned) {
      if (re.source.startsWith('\\bnode:net')) { // net is allowed ONLY for isIP() validation
        const uses = [...code.matchAll(/\bnet\.(\w+)/g)].map((m) => m[1]).filter((m) => m !== 'isIP'); assert.deepEqual(uses, [], `${path.basename(f)} uses net.${uses}`); continue;
      }
      assert.ok(!re.test(code), `${path.relative(ROOT, f)} matches banned pattern ${re}`);
    }
  }
});

test('BOUNDARY: every URL literal in the server code points at an allowlisted host', () => {
  const found = new Set();
  for (const f of SRC) for (const m of stripComments(read(f)).matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) if (!['x', 'localhost'].includes(m[1])) found.add(m[1].toLowerCase());
  const bad = [...found].filter((h) => !ALLOWED_HOSTS.has(h));
  assert.deepEqual(bad, [], `unexpected hosts: ${bad}`); console.log(`  ${found.size} outbound hosts in code, all allowlisted`);
});

test('BOUNDARY: running the whole pipeline on real + synthetic indicators never contacts an indicator host (network spy)', async () => {
  const contacted = []; const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, ...rest) => { contacted.push(String(url)); if (String(url).startsWith('http://127.0.0.1')) return realFetch(url, ...rest); throw new Error('blocked by test'); };
  try {
    const f = makeFangs({ FANGS_NO_ENRICH: '0' }, { enrichProviders: [['cymru', async () => null]] }); loadSnapshotInto(f); loadSynthetic(f, 1); f.runAnalysis({ relayout: true }); await new Promise((r) => setTimeout(r, 200));
    const indicatorHosts = new Set(); f.fg.graph.forEachNode((id, a) => { if (a.type === 'ip' || a.type === 'host') indicatorHosts.add(a.label); });
    for (const u of contacted) { const h = new URL(u).hostname; assert.ok(!indicatorHosts.has(h), `contacted indicator ${h}`); assert.ok(ALLOWED_HOSTS.has(h), `contacted non-allowlisted ${h}`); }
    console.log(`  pipeline made ${contacted.length} outbound HTTP calls (indicator hosts contacted: 0)`);
  } finally { globalThis.fetch = realFetch; }
});

test('BOUNDARY enrichment: the only network lookups are Team Cymru DNS and RIPEstat, keyed by the IP being enriched, never connecting to it', async () => {
  const queried = []; const { cymruLookup } = await import('../src/adapters/enrichers.js');
  await cymruLookup('203.0.113.9', { resolveTxt: async (n) => { queried.push(n); return [['64500 | 203.0.113.0/24 | ZZ | arin | 2020-01-01']]; } });
  assert.ok(queried.every((n) => /\.asn\.cymru\.com$/.test(n)), queried.join(','));
  assert.equal(ENRICHERS.length, 2); assert.ok(adapterMap().has('cymru'));
});

test('BOUNDARY secrets: no API keys committed; .env and key files are gitignored; code reads keys only from the environment', () => {
  const PATTERNS = [/gsk_[A-Za-z0-9]{20,}/, /csk-[A-Za-z0-9]{20,}/, /\b[0-9a-f]{32,64}\b(?=['"]\s*[,}\]]?\s*$)/m, /(api[_-]?key|token|secret|auth[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];
  const files = walk(ROOT, (p) => /\.(js|json|html|css|md|sh|env|txt|yml|yaml)$/.test(p) && !p.includes('package-lock') && !p.includes('/data/snapshots/') && !p.includes('attack-enterprise') && !p.includes('/results/'));
  for (const f of files) { const t = read(f); const inTests = f.includes(`${path.sep}test${path.sep}`); for (const re of PATTERNS.filter((_, i) => !inTests || [0, 1, 4].includes(i))) { const m = re.exec(t); assert.ok(!m, `${path.relative(ROOT, f)} looks like it contains a secret: ${m && m[0].slice(0, 12)}…`); } }
  const gi = read(path.join(ROOT, '.gitignore')); for (const e of ['.env', '*.key', 'node_modules/']) assert.ok(gi.includes(e), `.gitignore missing ${e}`);
  assert.ok(!fs.existsSync(path.join(ROOT, '.env')));
  for (const f of SRC) for (const m of stripComments(read(f)).matchAll(/process\.env\.([A-Z_]+)/g)) assert.match(m[1], /^(PORT|HOST|FANGS_[A-Z_]+|[A-Z_]*(KEY|TOKEN)|GROQ_MODEL|CEREBRAS_MODEL)$/, `unexpected env var ${m[1]}`);
  try { const tracked = execFileSync('git', ['-C', ROOT, 'ls-files', '--', '.'], { encoding: 'utf8' }); assert.ok(!/(^|\/)\.env(\.|$)/m.test(tracked) && !/\.key$/m.test(tracked) && !/node_modules\//.test(tracked)); } catch { /* not in a git checkout */ }
});

test('BOUNDARY exposure: server binds loopback by default; client never uses innerHTML/eval and sets no inline handlers (feed text cannot inject markup)', () => {
  const srv = read(path.join(ROOT, 'server.js')); assert.match(srv, /process\.env\.HOST \|\| '127\.0\.0\.1'/);
  for (const f of PUBLIC.filter((p) => p.endsWith('.js'))) { const c = stripComments(read(f)); assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(c), `${path.basename(f)} uses an HTML-injection sink`); }
  const html = read(path.join(ROOT, 'public/index.html')); assert.ok(!/\son[a-z]+\s*=/i.test(html), 'inline event handler in HTML'); assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), 'inline script in HTML');
  assert.ok(!/style\s*=/.test(html), 'inline style attribute in HTML (CSP style-src self)'); assert.ok(!/https?:\/\//.test(html.replace(/<meta[^>]*>/g, '')), 'page loads nothing from third-party origins');
});

test('BOUNDARY data labelling: synthetic fixtures are marked synthetic everywhere and use only reserved ranges', () => {
  const j = JSON.parse(read(path.join(ROOT, 'data/fixtures/campaign-replay.seed1.json'))); assert.equal(j.synthetic, true); assert.match(j.note, /SYNTHETIC/);
  const k = JSON.parse(read(path.join(ROOT, 'data/fixtures/kev-epss.sample.json'))); assert.equal(k.synthetic, true); assert.match(k.note, /NOT authoritative/);
  const f = makeFangs(); loadSynthetic(f, 1);
  f.fg.graph.forEachNode((_, a) => { if (a.type === 'ip') assert.match(a.label, /^(192\.0\.2|198\.51\.100|203\.0\.113)\./); });
  assert.ok([...f.queue.events.values()].every((e) => e.synthetic === true), 'every synthetic event is flagged for the UI');
  loadSnapshotInto(makeFangs());
});
