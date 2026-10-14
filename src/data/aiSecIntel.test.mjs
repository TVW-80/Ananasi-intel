import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyFirstSeen,
  assembleSnapshot,
  cleanText,
  isAiRelatedKev,
  isModelRelease,
  markdownToPlain,
  mergeVulns,
  normalizeFederalRegister,
  normalizeGhsa,
  normalizeKev,
  normalizeModelFeed,
  normalizeResearchFeed,
  parseFeed,
  safeUrl,
  withinWindow,
} from './aiSecIntel.js';

const NOW = Date.parse('2026-10-05T12:00:00Z');

const KEV = {
  vulnerabilities: [
    {
      cveID: 'CVE-2026-1111',
      vendorProject: 'Langflow',
      product: 'Langflow',
      vulnerabilityName: 'Langflow Missing Authentication Vulnerability',
      dateAdded: '2026-10-01',
      shortDescription: 'Langflow contains a missing authentication flaw allowing code execution.',
      requiredAction: 'Apply mitigations per vendor instructions.',
      dueDate: '2026-10-22',
      knownRansomwareCampaignUse: 'Known',
      notes: 'https://github.com/langflow-ai/langflow/security/advisories/GHSA-x; https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
    },
    {
      cveID: 'CVE-2026-2222',
      vendorProject: 'Microsoft',
      product: 'Windows',
      vulnerabilityName: 'Windows Kernel Privilege Escalation',
      dateAdded: '2026-10-02',
      shortDescription: 'Kernel flaw.',
      requiredAction: 'Patch.',
      knownRansomwareCampaignUse: 'Unknown',
    },
    {
      cveID: 'CVE-2019-0001',
      vendorProject: 'Anyscale',
      product: 'Ray',
      vulnerabilityName: 'Ray Dashboard RCE',
      dateAdded: '2024-01-01',
      shortDescription: 'old',
      requiredAction: 'x',
    },
  ],
};

test('KEV filter keeps AI/ML software and rejects unrelated products', () => {
  assert.equal(isAiRelatedKev(KEV.vulnerabilities[0]), true);
  assert.equal(isAiRelatedKev(KEV.vulnerabilities[1]), false);
  assert.equal(isAiRelatedKev({ vendorProject: 'Anyscale', product: 'Ray' }), true);
  // "ray" only counts as a product name, never as a word in prose.
  assert.equal(isAiRelatedKev({
    vendorProject: 'Acme', product: 'Imaging', vulnerabilityName: 'X', shortDescription: 'x ray viewer overflow',
  }), false);
  assert.equal(isAiRelatedKev({
    vendorProject: 'Acme', product: 'Agent', vulnerabilityName: 'X', shortDescription: 'Prompt flaw in an AI agent runtime',
  }), true);
});

test('normalizeKev windows by retention, flags ransomware, and keeps only http(s) evidence', () => {
  const items = normalizeKev(KEV, { now: NOW });
  assert.equal(items.length, 1);
  const [item] = items;
  assert.equal(item.cve, 'CVE-2026-1111');
  assert.equal(item.exploited, 'kev');
  assert.equal(item.ransomware, true);
  assert.equal(item.severity, 'critical');
  assert.equal(item.dueDate, '2026-10-22');
  assert.ok(item.evidence.some((l) => l.label === 'CISA KEV'));
  assert.ok(item.evidence.every((l) => /^https?:/.test(l.url)));
});

const GHSA = [
  {
    ghsa_id: 'GHSA-aaaa-bbbb-cccc',
    cve_id: 'CVE-2026-1111',
    html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
    summary: 'Langflow auth bypass',
    description: '## Summary\n\nLangflow <b>bypass</b> &amp; RCE',
    severity: 'critical',
    cvss: { score: 9.8 },
    published_at: '2026-09-30T00:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [{
      package: { ecosystem: 'pip', name: 'langflow' },
      vulnerable_version_range: '< 1.4.0',
      first_patched_version: '1.4.0',
    }],
  },
  {
    ghsa_id: 'GHSA-dddd-eeee-ffff',
    cve_id: 'CVE-2026-3333',
    html_url: 'https://github.com/advisories/GHSA-dddd-eeee-ffff',
    summary: 'vLLM DoS',
    description: 'desc',
    severity: 'moderate',
    cvss: { score: 0 },
    published_at: '2026-10-03T00:00:00Z',
    vulnerabilities: [{ package: { name: 'vllm' }, vulnerable_version_range: '< 0.9', first_patched_version: null }],
  },
  { ghsa_id: 'GHSA-gone', published_at: '2026-10-03T00:00:00Z', withdrawn_at: '2026-10-04T00:00:00Z' },
];

test('normalizeGhsa extracts affected/fixed, cleans text, drops withdrawn, never invents exploitation', () => {
  const items = normalizeGhsa(GHSA, { now: NOW });
  assert.equal(items.length, 2);
  const [langflow, vllm] = items;
  assert.equal(langflow.affected, 'langflow < 1.4.0');
  assert.equal(langflow.fixed, 'langflow 1.4.0');
  assert.equal(langflow.cvss, 9.8);
  assert.equal(langflow.summary, 'Langflow bypass & RCE');
  assert.equal(
    markdownToPlain('## Impact\n\n> quoted `media_io_kwargs` and **bold** [docs](https://x.test)'),
    'quoted media_io_kwargs and bold docs',
  );
  assert.equal(langflow.exploited, 'unconfirmed');
  assert.equal(vllm.severity, 'unknown');
  assert.equal(vllm.cvss, null);
  assert.match(vllm.action, /No patched version/);
});

test('mergeVulns joins KEV and GHSA on CVE, KEV wins exploitation, max severity, dedupes evidence', () => {
  const merged = mergeVulns(normalizeKev(KEV, { now: NOW }), normalizeGhsa(GHSA, { now: NOW }));
  assert.equal(merged.length, 2);
  const [first, second] = merged;
  assert.equal(first.cve, 'CVE-2026-1111');
  assert.equal(first.exploited, 'kev');
  assert.equal(first.severity, 'critical');
  assert.equal(first.cvss, 9.8);
  assert.equal(first.fixed, 'langflow 1.4.0');
  assert.match(first.action, /Patched release: langflow 1\.4\.0/);
  const urls = first.evidence.map((l) => l.url);
  assert.equal(new Set(urls).size, urls.length);
  assert.equal(second.cve, 'CVE-2026-3333');
});

test('normalizeFederalRegister maps executive orders newest-first and rejects unlinkable docs', () => {
  const items = normalizeFederalRegister({
    results: [
      { title: 'Promoting Artificial Intelligence Innovation', executive_order_number: '14001', signing_date: '2025-01-02', html_url: 'https://www.federalregister.gov/d/a' },
      { title: 'Securing the Grid', executive_order_number: '14999', signing_date: '2026-09-20', html_url: 'https://www.federalregister.gov/d/b', abstract: 'AI <i>policy</i>' },
      { title: 'No link — Artificial Intelligence', executive_order_number: '1', signing_date: '2026-09-21', html_url: 'javascript:alert(1)' },
      { title: "Accelerating Access to Veterans' Benefits", executive_order_number: '14426', signing_date: '2026-09-08', html_url: 'https://www.federalregister.gov/d/c' },
    ],
  });
  // Newest first; the veterans order only mentions AI in full text, so it is dropped.
  assert.deepEqual(items.map((i) => i.number), ['EO 14999', 'EO 14001']);
  assert.equal(items[0].summary, 'AI policy');
});

const RSS = `<?xml version="1.0"?><rss><channel>
<item><title><![CDATA[Introducing GPT-9 &amp; the new API]]></title><link>https://openai.com/index/gpt-9/</link>
<pubDate>Tue, 29 Sep 2026 10:00:00 GMT</pubDate><description><![CDATA[<p>Our <b>best</b> model.</p>]]></description></item>
<item><title>Company picnic photos</title><link>https://openai.com/index/picnic/</link><pubDate>Tue, 29 Sep 2026 10:00:00 GMT</pubDate></item>
<item><title>Ancient release notes</title><link>https://openai.com/index/old/</link><pubDate>Tue, 29 Sep 2024 10:00:00 GMT</pubDate></item>
</channel></rss>`;

const ATOM = `<feed xmlns="http://www.w3.org/2005/Atom"><entry>
<id>x</id><title>Jailbreaking agents</title>
<link rel="related" type="application/pdf" href="https://arxiv.org/pdf/1"/>
<link rel="alternate" type="text/html" href="https://arxiv.org/abs/1"/>
<published>2026-10-04T00:00:00Z</published><summary>A study.</summary></entry></feed>`;

test('parseFeed handles RSS (CDATA, entities) and Atom (rel=alternate link)', () => {
  const rss = parseFeed(RSS);
  assert.equal(rss.length, 3);
  assert.equal(rss[0].title, 'Introducing GPT-9 & the new API');
  assert.equal(rss[0].summary, 'Our best model.');
  const atom = parseFeed(ATOM);
  assert.equal(atom.length, 1);
  assert.equal(atom[0].link, 'https://arxiv.org/abs/1');
});

test('normalizeModelFeed keeps release-like titles inside retention; research keeps all recent', () => {
  const models = normalizeModelFeed('OpenAI', parseFeed(RSS), { now: NOW });
  assert.deepEqual(models.map((m) => m.url), ['https://openai.com/index/gpt-9/']);
  assert.equal(models[0].source, 'OpenAI');
  const research = normalizeResearchFeed('arXiv', parseFeed(ATOM), { now: NOW });
  assert.equal(research.length, 1);
});

test('isModelRelease needs a model family, or a generic model/API word with a release verb', () => {
  for (const title of [
    'Introducing GPT-6.1 Sol',
    'A model guide for the GPT-6 family',
    'Gemini 4 Argon: our next era of frontier intelligence',
    'Claude gets a new tool-use API',
    "We're releasing a new open-weights model",
    'Deprecating the legacy completions endpoint',
    'The latest AI news we announced in September 2026',
  ]) assert.equal(isModelRelease(title), true, title);
  for (const title of [
    'Introducing dots',
    'Introducing SynthID Bio',
    'Basis completes a tax workbook 2x faster with GPT-6 Astra',
    'Training a model on your laptop',
    'Watch the winning trailer from the Future Vision XPRIZE',
    'Google Beam expands with new regions',
  ]) assert.equal(isModelRelease(title), false, title);
});

test('applyFirstSeen: first run uses item dates; later runs flag only unseen ids as new', () => {
  const items = [
    { id: 'a', dateMs: NOW - 10 * 86_400_000 },
    { id: 'b', dateMs: NOW - 3_600_000 },
  ];
  const first = applyFirstSeen(items, null, NOW, true);
  assert.deepEqual(first.items.map((i) => i.isNew), [false, true]);
  const later = applyFirstSeen([...items, { id: 'c', dateMs: NOW }], first.history, NOW + 3 * 86_400_000, false);
  assert.deepEqual(later.items.map((i) => i.isNew), [false, false, true]);
  assert.deepEqual(Object.keys(later.history).sort(), ['a', 'b', 'c']);
});

test('assembleSnapshot merges sources, caps policy, and prunes history to live ids', () => {
  const { snapshot, history } = assembleSnapshot({
    vulns: [...normalizeKev(KEV, { now: NOW }), ...normalizeGhsa(GHSA, { now: NOW })],
    models: normalizeModelFeed('OpenAI', parseFeed(RSS), { now: NOW }),
    research: normalizeResearchFeed('arXiv', parseFeed(ATOM), { now: NOW }),
    policy: [],
    sources: [{ id: 'cisa-kev', ok: true, count: 1 }],
    history: { stale: 1 },
    now: NOW,
  });
  assert.equal(snapshot.vulns.length, 2);
  assert.equal(snapshot.windowDays, 30);
  assert.equal(snapshot.models.length, 1);
  assert.ok(!('stale' in history));
  assert.ok('CVE-2026-1111' in history);
});

test('withinWindow, cleanText, and safeUrl guard the display edge', () => {
  const items = [{ dateMs: NOW - 5 * 86_400_000 }, { dateMs: NOW - 45 * 86_400_000 }];
  assert.equal(withinWindow(items, 30, NOW).length, 1);
  assert.equal(withinWindow(items, 90, NOW).length, 2);
  assert.equal(cleanText('a&#39;b &lt;i&gt; &#x41;'.padEnd(10)), "a'b <i> A");
  assert.equal(cleanText('x'.repeat(50), 10).length, 10);
  assert.equal(safeUrl('javascript:alert(1)'), null);
  assert.equal(safeUrl('data:text/html,x'), null);
  assert.equal(safeUrl('https://example.com/a'), 'https://example.com/a');
});
