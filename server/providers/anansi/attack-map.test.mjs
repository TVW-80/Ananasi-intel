import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSources,
  createAttackMapService,
  normalizeIp,
  normalizeIpInfo,
  normalizeTopIps,
  normalizeTopPorts,
  parseRssItems,
} from './attack-map.js';

// Synthetic fixtures shaped like the public APIs — documentation-range IPs only.
const TOP_IPS = [
  { rank: 1, source: '198.051.100.007', reports: 1440, targets: 300 },
  { rank: 2, source: '203.000.113.009', reports: 720, targets: 90 },
  { rank: 3, source: 'not-an-ip', reports: 5, targets: 1 },
];
const IP_INFO = {
  '198.51.100.7': { ip: { number: '198.51.100.7', ascountry: 'cn', asname: 'SAMPLE-AS' } },
  '203.0.113.9': { ip: { number: '203.0.113.9', ascountry: 'NL', asname: 'EXAMPLE-NET' } },
};
const TOP_PORTS = { limit: 3, date: '2026-10-31', 0: { rank: 1, targetport: 23, records: 900, targets: 50, sources: 40 }, 1: { rank: 2, targetport: 22, records: 1200, targets: 70, sources: 60 }, 2: { rank: 3, targetport: 0, records: 1 } };
const RSS = `<?xml version="1.0"?><rss><channel><title>FortiGuard</title>
  <item><title><![CDATA[Sample Outbreak &amp; Exploit]]></title><link>https://www.fortiguard.com/outbreak-alert/sample</link><pubDate>Sat, 31 Oct 2026 12:00:00 GMT</pubDate></item>
  <item><title>Older signal</title><link>javascript:alert(1)</link><pubDate>Fri, 30 Oct 2026 12:00:00 GMT</pubDate></item>
</channel></rss>`;

test('DShield padded IPs normalize; junk is dropped', () => {
  assert.equal(normalizeIp('045.148.010.240'), '45.148.10.240');
  assert.equal(normalizeIp('256.1.1.1'), '');
  assert.equal(normalizeIp('1.2.3'), '');
  assert.deepEqual(normalizeTopIps(TOP_IPS).map((r) => r.ip), ['198.51.100.7', '203.0.113.9']);
  assert.deepEqual(normalizeIpInfo(IP_INFO['198.51.100.7']), { country: 'CN', asname: 'SAMPLE-AS', as: '' });
});

test('top ports accept the object form, name services, sort by records', () => {
  const ports = normalizeTopPorts(TOP_PORTS);
  assert.deepEqual(ports.map((p) => [p.port, p.service]), [[22, 'SSH'], [23, 'Telnet']]);
});

test('RSS items decode CDATA and entities and keep only https links', () => {
  const items = parseRssItems(RSS, 'Outbreak Alert');
  assert.equal(items.length, 2);
  assert.equal(items[0].title, 'Sample Outbreak & Exploit');
  assert.equal(items[0].link, 'https://www.fortiguard.com/outbreak-alert/sample');
  assert.equal(items[1].link, '');
  assert.equal(items[0].source, 'Outbreak Alert');
});

test('sources merge DShield IPs and AbuseIPDB countries into weighted rows', () => {
  const rows = buildSources(
    [
      { ip: '198.51.100.7', reports: 1440, targets: 300, country: 'CN', asname: 'SAMPLE-AS' },
      { ip: '203.0.113.9', reports: 720, targets: 90, country: 'NL' },
      { ip: '192.0.2.1', reports: 10, targets: 1, country: '' },
    ],
    [{ id: 'abuseipdb:RU', count: 50 }, { id: 'abuseipdb:CN', count: 5 }],
  );
  assert.deepEqual(rows.map((r) => r.country).sort(), ['CN', 'NL', 'RU']);
  const cn = rows.find((r) => r.country === 'CN');
  assert.equal(cn.weight, 1);
  assert.equal(cn.abuse, 5);
  assert.equal(cn.ips[0].asname, 'SAMPLE-AS');
  assert.ok(rows.every((r) => Number.isFinite(r.lat) && Number.isFinite(r.lon) && r.weight > 0));
});

function fakeFetch(calls) {
  return async (url) => {
    calls.push(url);
    const body = (() => {
      if (url.includes('/topips/')) return JSON.stringify(TOP_IPS);
      if (url.includes('/topports/')) return JSON.stringify(TOP_PORTS);
      const m = url.match(/\/api\/ip\/([\d.]+)\?json/);
      if (m) return JSON.stringify(IP_INFO[m[1]] || {});
      if (url.endsWith('.xml')) return RSS;
      return null;
    })();
    return body === null ? { ok: false, status: 404, text: async () => '' } : { ok: true, status: 200, text: async () => body };
  };
}

test('the service builds arcs, ports, a rate and a ticker, and caches IP lookups', async () => {
  const calls = [];
  let t = 0;
  const service = createAttackMapService({
    fetchImpl: fakeFetch(calls),
    envSource: {},
    clock: () => t,
    sleep: async () => {},
    threatIntel: () => ({ get: async () => ({ status: 'key-required', points: [] }) }),
  });
  const body = await service.get();
  assert.equal(body.status, 'ok');
  assert.deepEqual(body.sources.map((s) => s.country), ['CN', 'NL']);
  assert.equal(body.ports[0].service, 'SSH');
  assert.equal(body.rate.perMinute, 1.5); // (1440 + 720) / 1440
  assert.equal(body.alerts[0].title, 'Sample Outbreak & Exploit');
  assert.equal(body.target.name, 'Hampton Roads');
  const lookups = () => calls.filter((u) => u.includes('/api/ip/')).length;
  assert.equal(lookups(), 2);

  await service.get(); // fresh snapshot: no upstream calls
  t += 31 * 60_000; // snapshot expired, IP cache still warm
  const before = calls.length;
  await service.get();
  assert.equal(lookups(), 2, 'IP countries are cached for a day');
  assert.ok(calls.length > before, 'top IPs are refreshed');
});

test('an upstream outage keeps the last good map and says it is stale', async () => {
  let down = false;
  let t = 0;
  const inner = fakeFetch([]);
  const service = createAttackMapService({
    fetchImpl: async (url) => (down ? { ok: false, status: 503, text: async () => '' } : inner(url)),
    envSource: {},
    clock: () => t,
    sleep: async () => {},
    threatIntel: () => null,
  });
  assert.equal((await service.get()).status, 'ok');
  down = true;
  t += 31 * 60_000;
  const stale = await service.get();
  assert.equal(stale.status, 'stale');
  assert.equal(stale.sources.length, 2);
  assert.ok(stale.errors.some((e) => /HTTP 503/.test(e)));
});

test('with every source configured, the picture merges arcs, tags, malware and two-voice alerts', async () => {
  const seen = [];
  const json = (o, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(o) });
  const text = (t) => ({ ok: true, status: 200, text: async () => t });
  const fetchImpl = async (url, init = {}) => {
    seen.push({ url, init });
    if (url.includes('/topips/')) return json(TOP_IPS);
    if (url.includes('/topports/')) return json(TOP_PORTS);
    const m = url.match(/\/api\/ip\/([\d.]+)\?json/);
    if (m) return json(IP_INFO[m[1]] || { ip: { ascountry: 'DE', asname: 'SAMPLE-DE' } });
    if (url.endsWith('.xml')) return text(RSS);
    if (url.includes('/radar/attacks/layer7/top/attacks')) return json({ result: { top_0: [{ originCountryAlpha2: 'US', originCountryName: 'United States', targetCountryAlpha2: 'BE', targetCountryName: 'Belgium', value: '3.6' }, { originCountryAlpha2: 'US', targetCountryAlpha2: 'US', value: '3.7' }] } });
    if (url.includes('/radar/attacks/layer7/top/industry')) return json({ result: { top_0: [{ name: 'Gambling', value: '12.5' }] } });
    if (url.includes('/radar/')) return json({ result: { top_0: [] } });
    if (url.includes('lists.blocklist.de/lists/ssh.txt')) return text('198.51.100.7\n192.0.2.10\n');
    if (url.includes('lists.blocklist.de/lists/strongips.txt')) return text('198.51.100.7\n');
    if (url.includes('lists.blocklist.de')) return text('');
    if (url.includes('threatfox')) return json({ data: [{ ioc: '192.0.2.50:443', threat_type: 'botnet_cc', malware_printable: 'AsyncRAT' }] });
    if (url.includes('urlhaus')) return json({ urls: [{ url: 'http://192.0.2.60/x', url_status: 'online', tags: ['mirai'] }] });
    if (url.includes('otx.alienvault')) return json({ results: [{ id: 'p1', name: 'SAMPLE pulse', adversary: 'Sample Group', modified: '2026-11-01T10:00:00' }] });
    if (url.includes('greynoise')) return json({ noise: true, riot: false, classification: 'malicious' });
    if (url.includes('shadowserver')) return text('{"vendor":"Sample","product":"Router","class":"router","vulnerability":"CVE-2000-0003","iot":"yes","1d":"40"}\n');
    if (url.includes('drop_v4.json')) return text('{"cidr":"203.0.113.0/24","sblid":"SBL000009"}\n');
    if (url.includes('torbulkexitlist')) return text('203.0.113.9\n');
    if (url.includes('known_exploited')) return json({ vulnerabilities: [{ cveID: 'CVE-2000-0002', dateAdded: '2026-11-01', vendorProject: 'Sample', product: 'Router', vulnerabilityName: 'Sample RCE' }] });
    return { ok: false, status: 404, text: async () => '' };
  };
  const service = createAttackMapService({
    fetchImpl,
    envSource: { CLOUDFLARE_API_TOKEN: 'cf', ABUSECH_AUTH_KEY: 'ac', OTX_API_KEY: 'otx', GREYNOISE_API_KEY: 'gn', SHADOWSERVER_API_KEY: 'k', SHADOWSERVER_API_SECRET: 's' },
    clock: () => Date.UTC(2026, 10, 2, 12),
    sleep: async () => {},
    threatIntel: () => null,
    resolve4: async () => [],
  });
  const body = await service.get();

  // Cloudflare: one drawable pair; the domestic pair is kept but flagged.
  assert.deepEqual(body.pairs.map((p) => [p.from.code, p.to.code, p.domestic]), [['US', 'BE', false], ['US', 'US', true]]);
  assert.match(body.pairs[0].plain, /Belgium/);
  assert.equal(body.ddos.industries[0].name, 'Gambling');

  // Tags on the Chinese DShield IP: SSH (blocklist.de), repeat offender, GreyNoise.
  const cn = body.sources.find((s) => s.country === 'CN');
  assert.equal(cn.dominantService, 'ssh');
  const lines = cn.ips[0].lines.map((l) => l.text).join(' | ');
  assert.match(lines, /SSH break-in attempts/);
  assert.match(lines, /Repeat offender/);
  assert.match(lines, /GreyNoise: Mass attacker/);
  assert.ok(cn.ips[0].lines.every((l, i) => i === 0 || (l.plain && l.tech)), 'every tag line has both voices');

  // The Dutch IP is a Tor exit inside a DROP netblock.
  const nl = body.sources.find((s) => s.country === 'NL');
  assert.deepEqual([nl.flags.tor, nl.flags.drop], [1, 1]);

  // Malware C2 markers, attack-type legend, exploited list.
  assert.equal(body.malware[0].families[0].name, 'AsyncRAT');
  assert.deepEqual(body.attackTypes.map((a) => [a.service, a.count]), [['ssh', 2]]);
  assert.match(body.exploited[0].plain, /decoy servers/);

  // Alerts from every lane, each with both voices.
  const lanes = new Set(body.alerts.map((a) => a.source.split(' ')[0]));
  for (const lane of ['FortiGuard', 'OTX', 'CISA', 'Shadowserver', 'ThreatFox', 'URLhaus']) assert.ok(lanes.has(lane), lane);
  assert.ok(body.alerts.every((a) => a.title && a.plain && a.technical));

  // Keys go only where they belong; Shadowserver is HMAC-signed.
  const ss = seen.find((r) => r.url.includes('shadowserver'));
  assert.match(ss.init.headers.HMAC2, /^[0-9a-f]{64}$/);
  assert.equal(JSON.parse(ss.init.body).apikey, 'k');
  assert.equal(seen.find((r) => r.url.includes('threatfox')).init.headers['Auth-Key'], 'ac');
  assert.ok(seen.filter((r) => !r.url.includes('cloudflare')).every((r) => !String(r.init.headers?.Authorization || '').includes('cf')));
  const original = ['dshield', 'radar', 'blocklist', 'threatfox', 'urlhaus', 'otx', 'shadowserver', 'drop', 'tor', 'kev', 'fortiguard', 'greynoise'];
  const notOk = body.feeds.filter((f) => f.status !== 'ok' && original.includes(f.id));
  assert.deepEqual(notOk, []);
});

test('missing keys switch single ingredients off, never the map', async () => {
  const service = createAttackMapService({
    resolve4: async () => [],
    fetchImpl: fakeFetch([]),
    envSource: {},
    clock: () => 0,
    sleep: async () => {},
    threatIntel: () => null,
  });
  const body = await service.get();
  assert.equal(body.status, 'ok');
  const status = Object.fromEntries(body.feeds.map((f) => [f.id, f.status]));
  for (const id of ['radar', 'threatfox', 'urlhaus', 'otx', 'shadowserver']) assert.equal(status[id], 'key-required', id);
  assert.equal(status.greynoise, 'ok', 'GreyNoise works without a key');
});

test('every Attack Map key can be entered in POWER UP', async () => {
  const { KEY_SETUP_KEYS } = await import('../../../src/keySetupCore.mjs');
  const vars = new Set(KEY_SETUP_KEYS.filter((k) => !k.hidden).flatMap((k) => k.envVars));
  for (const v of ['CLOUDFLARE_API_TOKEN', 'ABUSECH_AUTH_KEY', 'OTX_API_KEY', 'GREYNOISE_API_KEY', 'SHADOWSERVER_API_KEY', 'SHADOWSERVER_API_SECRET', 'ABUSEIPDB_API_KEY']) {
    assert.ok(vars.has(v), `${v} missing from POWER UP`);
  }
});

test('GreyNoise is asked without a key when none is set, within a smaller daily cap', async () => {
  const calls = [];
  const base = fakeFetch([]);
  const service = createAttackMapService({
    fetchImpl: async (url, init = {}) => {
      if (url.includes('greynoise')) {
        calls.push(init.headers || {});
        return { ok: true, status: 200, text: async () => JSON.stringify({ noise: true, riot: false, classification: 'malicious' }) };
      }
      return base(url);
    },
    envSource: {},
    clock: () => 0,
    sleep: async () => {},
    threatIntel: () => null,
  });
  await service.get();
  assert.ok(calls.length > 0);
  assert.ok(calls.every((h) => !('key' in h)), 'no key header is sent');
});

test('world-wide extras: BGP hijacks, phishing, C2 toolkits, SSLBL, breaches, PoCs, ICS, EPSS and ATT&CK', async () => {
  const json = (o) => ({ ok: true, status: 200, text: async () => JSON.stringify(o) });
  const text = (t) => ({ ok: true, status: 200, text: async () => t });
  const geo = { '192.0.2.70': 'RU', '192.0.2.71': 'CN', '192.0.2.72': 'NL', '192.0.2.80': 'US' };
  const seen = [];
  const fetchImpl = async (url, init = {}) => {
    seen.push({ url, init });
    const m = url.match(/\/api\/ip\/([\d.]+)\?json/);
    if (m) return json({ ip: { ascountry: geo[m[1]] || 'DE' } });
    if (url.includes('/topips/')) return json([]);
    if (url.includes('/bgp/hijacks/')) return json({ result: { events: [{ id: 1, hijacker_asn: 64500, hijacker_country: 'RU', victim_asns: [64501], victim_countries: ['US'], confidence_score: 9, prefixes: ['198.51.100.0/24'], min_hijack_ts: '2026-11-02T08:00:00', on_going_count: 1 }], asn_info: [{ asn: 64500, org_name: 'Sample Transit', country_code: 'RU' }, { asn: 64501, org_name: 'Sample Bank', country_code: 'US' }] } });
    if (url.includes('/bgp/leaks/')) return json({ result: { events: [{ id: 2, leak_asn: 64502, countries: ['BR'], prefix_count: 120, origin_count: 40, detected_ts: '2026-11-02T07:00:00', finished: false }], asn_info: [] } });
    if (url.includes('/radar/')) return json({ result: { top_0: [] } });
    if (url.includes('mb-api.abuse.ch')) return json({ data: [{ signature: 'AgentTesla', file_type: 'exe', file_name: 'Invoice_2026.pdf.exe' }, { signature: 'AgentTesla', file_type: 'exe', file_name: 'x.exe' }] });
    if (url.includes('sslbl')) return text('# SSLBL\n2026-11-01 10:00:00,192.0.2.72,443\n');
    if (url.includes('haveibeenpwned')) return json([{ Name: 'SampleCo', Title: 'Sample Co', Domain: 'sample.example', BreachDate: '2026-10-01', AddedDate: '2026-11-01T00:00:00Z', PwnCount: 120000, DataClasses: ['Email addresses', 'Passwords'], IsVerified: true }]);
    if (url.includes('api.github.com/search')) return json({ items: [{ name: 'CVE-2026-1234-poc', full_name: 'someone/CVE-2026-1234-poc', created_at: '2026-11-02T01:00:00Z', stargazers_count: 12 }] });
    if (url.includes('ics-advisories')) return text('<rss><item><title>ICSA-26-306-01 Sample PLC</title><link>https://www.cisa.gov/x</link><pubDate>Mon, 02 Nov 2026 10:00:00 GMT</pubDate></item></rss>');
    if (url.includes('openphish')) return text('https://paypal-login.example/verify\nhttps://other.example/a\n');
    if (url.includes('C2IntelFeeds')) return text('#ip,ioc\n192.0.2.70,Possible Cobaltstrike C2 IP\n192.0.2.71,Possible Sliver C2 IP\n');
    if (url.includes('malpedia')) return json({ 'win.agent_tesla': { common_name: 'Agent Tesla', alt_names: [], description: 'Sample description of a keylogger. Second sentence. Third.' } });
    if (url.includes('api.first.org')) return json({ data: [{ cve: 'CVE-2026-1234', epss: '0.97', percentile: '0.999' }] });
    if (url.includes('otx.alienvault')) return json({ results: [{ id: 'p', name: 'SAMPLE pulse', attack_ids: [{ id: 'T1566.001' }, 'T1486'] }] });
    return { ok: false, status: 404, text: async () => '' };
  };
  const service = createAttackMapService({
    fetchImpl,
    envSource: { CLOUDFLARE_API_TOKEN: 'cf', ABUSECH_AUTH_KEY: 'ac', OTX_API_KEY: 'o' },
    clock: () => Date.UTC(2026, 10, 2, 12),
    sleep: async () => {},
    threatIntel: () => null,
    resolve4: async (host) => (host.startsWith('paypal') ? ['192.0.2.80'] : []),
  });
  const body = await service.get();

  assert.equal(body.hijacks[0].from.code, 'RU');
  assert.equal(body.hijacks[0].to.code, 'US');
  assert.match(body.hijacks[0].title, /Sample Transit/);
  assert.equal(body.leaks[0].country, 'BR');
  assert.deepEqual(body.phishing.map((p) => [p.country, p.brands[0]?.name]), [['US', 'PayPal']]);
  assert.match(body.phishing[0].hosts[0], /paypal-login\[\.\]example/, 'phishing hosts are defanged');
  const families = body.malware.flatMap((m) => m.families.map((f) => f.name));
  for (const f of ['Cobalt Strike', 'Sliver', 'SSLBL-listed botnet server']) assert.ok(families.includes(f), f);

  const by = (src) => body.alerts.find((a) => a.source === src);
  assert.match(by('Breach').plain, /120,000/);
  assert.match(by('PoC watch').title, /CVE-2026-1234/);
  assert.match(by('PoC watch').details[0].plain, /97%/, 'EPSS odds in plain words');
  assert.match(by('CISA ICS').plain, /industrial/);
  assert.match(by('BGP hijack').plain, /post office/);
  assert.match(by('MalwareBazaar').plain, /Invoice_2026\.pdf\.exe/);
  assert.match(by('OpenPhish').title, /PayPal/);
  assert.match(by('C2IntelFeeds').title, /Cobalt Strike|Sliver/);
  const otx = by('OTX');
  assert.deepEqual(otx.details.map((d) => d.label), ['T1566.001 · Spearphishing attachment', 'T1486 · Data encrypted for impact']);
  assert.match(otx.details[1].plain, /Ransomware/);
  assert.ok(body.alerts.every((a) => a.plain && a.technical && (a.details || []).every((d) => d.plain && d.technical)));

  const mb = seen.find((r) => r.url.includes('mb-api'));
  assert.equal(mb.init.body, 'query=get_recent&selector=time');
  assert.equal(mb.init.headers['Auth-Key'], 'ac');
});
