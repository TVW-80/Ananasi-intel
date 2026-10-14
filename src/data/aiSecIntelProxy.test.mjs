import assert from 'node:assert/strict';
import test from 'node:test';
import { createAiSecIntelMiddleware } from '../../vite.config.js';

const T0 = Date.parse('2026-10-05T12:00:00Z');
const HOUR = 3_600_000;

const KEV = {
  vulnerabilities: [{
    cveID: 'CVE-2026-1111',
    vendorProject: 'Langflow',
    product: 'Langflow',
    vulnerabilityName: 'Langflow Missing Authentication Vulnerability',
    dateAdded: '2026-10-01',
    shortDescription: 'Missing authentication allows code execution.',
    requiredAction: 'Apply mitigations per vendor instructions.',
    dueDate: '2026-10-22',
    knownRansomwareCampaignUse: 'Unknown',
  }],
};
const GHSA = [{
  ghsa_id: 'GHSA-aaaa-bbbb-cccc',
  cve_id: 'CVE-2026-1111',
  html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  summary: 'Langflow auth bypass',
  description: '## Summary\n\nBypass.',
  severity: 'critical',
  cvss: { score: 9.8 },
  published_at: '2026-09-30T00:00:00Z',
  vulnerabilities: [{
    package: { name: 'langflow' }, vulnerable_version_range: '< 1.4.0', first_patched_version: '1.4.0',
  }],
}];
const FR = {
  results: [{
    title: 'Advancing AI Security',
    executive_order_number: '14999',
    signing_date: '2026-09-20',
    html_url: 'https://www.federalregister.gov/d/2026-1',
  }],
};
const RSS = `<rss><channel><item><title>Introducing GPT-9</title><link>https://openai.com/index/gpt-9/</link>
<pubDate>Tue, 29 Sep 2026 10:00:00 GMT</pubDate></item></channel></rss>`;
const ATOM = `<feed><entry><title>Jailbreaking agents</title><link rel="alternate" href="https://arxiv.org/abs/1"/>
<published>2026-10-04T00:00:00Z</published></entry></feed>`;

/** Route a URL to a fixture, or throw a TLS-style error for hosts in `failing`. */
function createFetch({ failing = new Set(), calls = [] } = {}) {
  return async (url) => {
    const href = String(url);
    calls.push(href);
    const host = new URL(href).hostname;
    if (failing.has(host)) {
      throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' } });
    }
    if (host === 'www.cisa.gov') return new Response(JSON.stringify(KEV));
    if (host === 'api.github.com') return new Response(JSON.stringify(GHSA));
    if (host === 'www.federalregister.gov') return new Response(JSON.stringify(FR));
    if (host === 'export.arxiv.org' || host === 'github.com') return new Response(ATOM);
    return new Response(RSS);
  };
}

function invoke(middleware, method = 'GET') {
  return new Promise((resolve, reject) => {
    const result = { status: 0, headers: {}, body: '' };
    const res = {
      headersSent: false,
      writeHead(status, headers = {}) { result.status = status; result.headers = headers; this.headersSent = true; },
      end(body = '') { result.body = String(body); resolve(result); },
    };
    Promise.resolve(middleware({ url: '/', method }, res)).catch(reject);
  });
}

function setup(options = {}) {
  const clock = { now: T0 };
  const calls = [];
  const failing = options.failing || new Set();
  const middleware = createAiSecIntelMiddleware({
    fetchImpl: createFetch({ failing, calls }),
    now: () => clock.now,
    cachePath: null,
  });
  return { clock, calls, failing, middleware };
}

const json = (result) => JSON.parse(result.body);
// Silence the proxy's expected warnings so test output stays readable.
const quiet = (fn) => async (...args) => {
  const original = console.warn;
  console.warn = () => {};
  try { return await fn(...args); } finally { console.warn = original; }
};

test('first request sweeps every source, merges KEV + GHSA on CVE, then serves from cache', quiet(async () => {
  const { middleware, calls } = setup();
  const first = await invoke(middleware);
  assert.equal(first.status, 200);
  assert.equal(first.headers['x-ai-sec-cache'], 'MISS');
  const snapshot = json(first);
  assert.equal(snapshot.sources.length, 10);
  assert.ok(snapshot.sources.every((source) => source.ok));
  assert.equal(snapshot.vulns.length, 1);
  assert.equal(snapshot.vulns[0].exploited, 'kev');
  assert.equal(snapshot.vulns[0].fixed, 'langflow 1.4.0');
  assert.equal(snapshot.policy[0].number, 'EO 14999');
  assert.ok(snapshot.models.some((item) => item.source === 'OpenAI'));
  assert.ok(snapshot.research.some((item) => item.source === 'arXiv cs.CR'));

  const upstreamCalls = calls.length;
  const second = await invoke(middleware);
  assert.equal(second.headers['x-ai-sec-cache'], 'HIT');
  assert.equal(calls.length, upstreamCalls, 'a fresh cache must not touch upstream');
}));

test('concurrent requests share one upstream sweep (single-flight)', quiet(async () => {
  const { middleware, calls } = setup();
  const [a, b, c] = await Promise.all([invoke(middleware), invoke(middleware), invoke(middleware)]);
  assert.deepEqual([a.status, b.status, c.status], [200, 200, 200]);
  assert.equal(calls.length, 10, 'ten sources fetched exactly once for three clients');
}));

test('a failing source keeps its last-good items, reports stale + the TLS cause, and retries sooner', quiet(async () => {
  const { middleware, clock, failing, calls } = setup();
  await invoke(middleware);

  clock.now = T0 + 4 * HOUR; // past the 3h TTL
  failing.add('api.github.com');
  const degraded = json(await invoke(middleware));
  const ghsa = degraded.sources.find((source) => source.id === 'ghsa');
  assert.equal(ghsa.ok, false);
  assert.equal(ghsa.stale, true);
  assert.match(ghsa.error, /UNABLE_TO_VERIFY_LEAF_SIGNATURE/);
  assert.equal(degraded.vulns[0].fixed, 'langflow 1.4.0', 'last-good GHSA data must survive the outage');

  const callsAfterDegraded = calls.length;
  clock.now += 5 * 60_000; // inside the 15 min degraded retry window
  assert.equal((await invoke(middleware)).headers['x-ai-sec-cache'], 'HIT');
  assert.equal(calls.length, callsAfterDegraded);

  clock.now += 11 * 60_000; // past it → retry, and GitHub has recovered
  failing.delete('api.github.com');
  const recovered = await invoke(middleware);
  assert.equal(recovered.headers['x-ai-sec-cache'], 'MISS');
  assert.ok(json(recovered).sources.every((source) => source.ok));
}));

test('total outage: 502 with no cache, stale snapshot (never an empty one) with a cache', quiet(async () => {
  const cold = setup({ failing: new Set(['www.cisa.gov', 'api.github.com', 'www.federalregister.gov', 'openai.com', 'blog.google', 'deepmind.google', 'huggingface.co', 'export.arxiv.org', 'genai.owasp.org', 'github.com']) });
  const none = await invoke(cold.middleware);
  assert.equal(none.status, 502);
  assert.equal(none.headers['x-ai-sec-cache'], 'NONE');

  const { middleware, clock, failing } = setup();
  await invoke(middleware);
  clock.now = T0 + 4 * HOUR;
  for (const host of ['www.cisa.gov', 'api.github.com', 'www.federalregister.gov', 'openai.com', 'blog.google', 'deepmind.google', 'huggingface.co', 'export.arxiv.org', 'genai.owasp.org', 'github.com']) failing.add(host);
  const stale = await invoke(middleware);
  assert.equal(stale.status, 200);
  assert.equal(stale.headers['x-ai-sec-cache'], 'STALE-ERROR');
  assert.equal(json(stale).vulns.length, 1);
}));

test('only GET is accepted', async () => {
  const { middleware, calls } = setup();
  const result = await invoke(middleware, 'POST');
  assert.equal(result.status, 405);
  assert.equal(calls.length, 0);
});
