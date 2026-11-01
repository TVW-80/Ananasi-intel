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
