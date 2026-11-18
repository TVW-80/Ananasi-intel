import test from 'node:test';
import assert from 'node:assert/strict';
import {
  findRange,
  ipToInt,
  normalizeKev,
  normalizeOtx,
  normalizeRadarPairs,
  normalizeRadarTop,
  normalizeThreatFox,
  normalizeUrlhaus,
  parseDrop,
  parseIpList,
} from './attack-sources.js';
import { familyExplained, kevExplained, pulseExplained, SERVICES, SERVICE_ORDER } from './attack-glossary.js';

// Synthetic fixtures shaped like each API — documentation-range IPs only.
test('IP lists skip comments and junk', () => {
  assert.deepEqual(parseIpList('# header\n198.51.100.7\n\n203.0.113.9 ; note\nnot-an-ip\n2001:db8::1\n'), ['198.51.100.7', '203.0.113.9']);
  assert.equal(ipToInt('255.255.255.255'), 4294967295);
});

test('Spamhaus DROP parses NDJSON and legacy text, and finds containing ranges', () => {
  const json = '{"cidr":"198.51.100.0/24","sblid":"SBL000001","rir":"arin"}\n{"type":"metadata","timestamp":1}\n';
  const txt = '; Spamhaus DROP\n203.0.113.0/25 ; SBL000002\n';
  const ranges = [...parseDrop(json), ...parseDrop(txt)].sort((a, b) => a.start - b.start);
  assert.equal(findRange('198.51.100.200', ranges).sbl, 'SBL000001');
  assert.equal(findRange('203.0.113.127', ranges).sbl, 'SBL000002');
  assert.equal(findRange('203.0.113.128', ranges), null);
});

test('Cloudflare Radar pairs and top lists normalize', () => {
  const pairs = normalizeRadarPairs({ result: { top_0: [
    { originCountryAlpha2: 'us', originCountryName: 'United States', targetCountryAlpha2: 'BE', targetCountryName: 'Belgium', value: '3.6' },
    { originCountryAlpha2: '', targetCountryAlpha2: 'DE', value: '1' },
  ] } }, 'L7');
  assert.deepEqual(pairs.map((p) => [p.from.code, p.to.code, p.value, p.layer]), [['US', 'BE', 3.6, 'L7']]);
  assert.deepEqual(normalizeRadarTop({ result: { top_0: [{ name: 'Gambling', value: '12.5' }] } }), [{ name: 'Gambling', code: '', value: 12.5 }]);
});

test('ThreatFox IOCs expose ip and port for ip:port indicators', () => {
  const iocs = normalizeThreatFox({ query_status: 'ok', data: [
    { ioc: '198.51.100.7:443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'AsyncRAT', confidence_level: 100, tags: ['RAT'] },
    { ioc: 'evil.example', ioc_type: 'domain', threat_type: 'payload_delivery', malware_printable: 'Emotet' },
  ] });
  assert.deepEqual([iocs[0].ip, iocs[0].port, iocs[0].malware], ['198.51.100.7', 443, 'AsyncRAT']);
  assert.equal(iocs[1].ip, '');
});

test('URLhaus summary counts online links and tags', () => {
  const u = normalizeUrlhaus({ urls: [
    { url: 'http://198.51.100.7/x', url_status: 'online', tags: ['mirai', 'elf'] },
    { url: 'http://203.0.113.9/y', url_status: 'offline', tags: ['mirai'] },
  ] });
  assert.deepEqual([u.total, u.online, u.topTags[0]], [2, 1, { tag: 'mirai', count: 2 }]);
});

test('OTX pulses and KEV entries become two-voice alerts', () => {
  const [p] = normalizeOtx({ results: [{ id: 'abc', name: 'SAMPLE campaign', adversary: 'Sample Group', malware_families: [{ display_name: 'Lumma' }], industries: ['Healthcare'] }] });
  const a = pulseExplained(p);
  assert.match(a.plain, /Sample Group/);
  assert.match(a.plain, /Healthcare/);
  const [k] = normalizeKev({ vulnerabilities: [
    { cveID: 'CVE-2000-0001', dateAdded: '2026-10-01', vendorProject: 'Old', product: 'Thing' },
    { cveID: 'CVE-2000-0002', dateAdded: '2026-11-01', vendorProject: 'Sample', product: 'Router', vulnerabilityName: 'Sample RCE', knownRansomwareCampaignUse: 'Known', dueDate: '2026-11-22' },
  ] });
  const e = kevExplained(k);
  assert.match(e.plain, /ransomware/);
  assert.match(e.plain, /2026-11-22/);
  assert.match(e.technical, /CVE-2000-0002/);
});

test('every attack type and common malware family has both voices', () => {
  for (const s of SERVICE_ORDER) assert.ok(SERVICES[s].plain && SERVICES[s].technical && SERVICES[s].color, s);
  const known = familyExplained('AsyncRAT', 'botnet_cc');
  assert.match(known.plain, /remote control/);
  assert.match(known.technical, /C2/);
  assert.ok(familyExplained('Brand New Family').plain);
});

import { EXPOSURE_QUERIES, normalizeInternetDb, normalizeShodanCount, prettyCpe } from './attack-sources.js';

test('InternetDB payloads normalize to ports, vulns, products — junk dropped', () => {
  const idb = normalizeInternetDb({
    ip: '198.51.100.7',
    ports: [22, 3389, 70000, -1, 'x'],
    vulns: ['CVE-2021-1234', 'cve-2019-0708', 'not-a-cve'],
    cpes: ['cpe:2.3:a:apache:http_server:2.4.49:*:*', 'cpe:2.3:o:microsoft:windows:*'],
    tags: ['rdp'],
    hostnames: ['host.example'],
  });
  assert.deepEqual(idb.ports, [22, 3389]);
  assert.deepEqual(idb.vulns, ['CVE-2021-1234', 'CVE-2019-0708']);
  assert.equal(prettyCpe(idb.cpes[0]), 'apache http server');
  assert.equal(normalizeInternetDb(null), null);
});

test('Shodan count facets normalize to a total and top countries', () => {
  const c = normalizeShodanCount({ total: 1234, facets: { country: [{ value: 'US', count: 900 }, { value: 'zz', count: 0 }, { value: 'CN', count: 334 }] } });
  assert.equal(c.total, 1234);
  assert.deepEqual(c.top.map((t) => t.country), ['US', 'CN']);
  assert.ok(EXPOSURE_QUERIES.every((q) => q.id && q.query && q.plain && q.technical));
});

import { parseFeodoIps, buildAttackerIps } from './attack-sources.js';

test('Feodo ipblocklist JSON → C2 source IPs with country and malware; junk dropped', () => {
  const rows = parseFeodoIps([
    { ip_address: '198.51.100.7', port: 443, country: 'ru', malware: 'Emotet', last_online: '2026-11-17' },
    { ip_address: 'not-an-ip', country: 'US' },
    { ip_address: '203.0.113.9', port: 8080, country: 'cn', malware: 'QakBot' },
  ]);
  assert.deepEqual(rows.map((r) => [r.ip, r.country, r.malware, r.port]), [
    ['198.51.100.7', 'RU', 'Emotet', 443],
    ['203.0.113.9', 'CN', 'QakBot', 8080],
  ]);
  assert.deepEqual(parseFeodoIps(null), []);
});

test('buildAttackerIps merges + dedupes feeds, ranks by corroboration, caps', () => {
  const merged = buildAttackerIps({
    cins: '198.51.100.7\n203.0.113.9\n# comment\n',
    et: '198.51.100.7\n192.0.2.4',
    blocklistAll: '198.51.100.7',
    feodo: [{ ip: '203.0.113.9', country: 'CN', malware: 'QakBot', port: 8080 }],
  });
  // 198.51.100.7 is on three lists → ranked first.
  assert.equal(merged[0].ip, '198.51.100.7');
  assert.deepEqual(merged[0].sources, ['CINS Army', 'Emerging Threats', 'blocklist.de']);
  // Feodo metadata flows onto the deduped 203.0.113.9 entry.
  const q = merged.find((m) => m.ip === '203.0.113.9');
  assert.equal(q.malware, 'QakBot');
  assert.equal(q.country, 'CN');
  assert.ok(q.sources.includes('CINS Army') && q.sources.includes('Feodo C2'));
  // Cap is honored.
  assert.ok(buildAttackerIps({ cins: Array.from({ length: 50 }, (_, i) => `10.0.0.${i}`).join('\n') }, { limit: 10 }).length <= 10);
  assert.deepEqual(buildAttackerIps({}), []);
});

import { normalizeVirusTotalIp } from './attack-sources.js';

test('VirusTotal v3 IP report → compact reputation; bad payloads → null', () => {
  const vt = normalizeVirusTotalIp({
    data: { attributes: {
      last_analysis_stats: { malicious: 12, suspicious: 3, harmless: 40, undetected: 30, timeout: 1 },
      reputation: -40, as_owner: 'EVIL-AS', country: 'ru',
    } },
  });
  assert.equal(vt.malicious, 12);
  assert.equal(vt.suspicious, 3);
  assert.equal(vt.total, 86); // 12+3+40+30+1
  assert.equal(vt.asOwner, 'EVIL-AS');
  assert.equal(vt.country, 'RU');
  assert.equal(vt.reputation, -40);
  assert.equal(normalizeVirusTotalIp({}), null);
  assert.equal(normalizeVirusTotalIp(null), null);
});
