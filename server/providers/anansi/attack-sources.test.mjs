import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  findRange,
  ipToInt,
  normalizeGreyNoise,
  normalizeKev,
  normalizeOtx,
  normalizeRadarPairs,
  normalizeRadarTop,
  normalizeThreatFox,
  normalizeUrlhaus,
  parseDrop,
  parseIpList,
  parseJsonLines,
  shadowserverRequest,
} from './attack-sources.js';
import { familyExplained, greyNoiseExplained, kevExplained, pulseExplained, SERVICES, SERVICE_ORDER } from './attack-glossary.js';

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

test('GreyNoise answers both "seen" and "not seen", and explains them', () => {
  const seen = normalizeGreyNoise({ noise: true, riot: false, classification: 'malicious' }, 200);
  assert.match(greyNoiseExplained(seen).plain, /everyone/);
  const unseen = normalizeGreyNoise({ noise: false, riot: false, message: 'IP not observed' }, 404);
  assert.match(greyNoiseExplained(unseen).label, /targeted/);
  assert.equal(normalizeGreyNoise({ message: 'rate limited' }, 429), null);
});

test('Shadowserver requests are signed like call-api.py (HMAC-SHA256 of the body)', () => {
  const { body, headers } = shadowserverRequest({ limit: 5 }, 'KEY', 'SECRET');
  assert.deepEqual(JSON.parse(body), { limit: 5, apikey: 'KEY' });
  assert.equal(headers.HMAC2, createHmac('sha256', 'SECRET').update(body).digest('hex'));
  assert.equal(parseJsonLines('{"a":1}\n{"a":2}\nnot json').length, 2);
});

test('every attack type and common malware family has both voices', () => {
  for (const s of SERVICE_ORDER) assert.ok(SERVICES[s].plain && SERVICES[s].technical && SERVICES[s].color, s);
  const known = familyExplained('AsyncRAT', 'botnet_cc');
  assert.match(known.plain, /remote control/);
  assert.match(known.technical, /C2/);
  assert.ok(familyExplained('Brand New Family').plain);
});
