import test from 'node:test';
import assert from 'node:assert/strict';
import { c2intel, feodo, threatfox, urlhaus, openphish, dshield, radar, greynoise, otx, cymru, ripestat } from '../src/adapters/index.js';
import { cymruLookup, ripestatLookup, enrichIP } from '../src/adapters/enrichers.js';
import { isPublicIP, normDomain, famKey, findCVEs } from '../src/util.js';
import { makeFangs } from './helpers/env.js';

const ex = (ad, raw, id = 'x:1') => ad.extract({ id, source: ad.name, raw });
const keys = (r) => r.edges.map((e) => `${e.type}|${e.src}|${e.dst}`).sort();

test('util: only public, well-formed indicators become nodes', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '192.168.0.1', '172.16.5.5', '169.254.1.1', '100.64.0.1', '224.0.0.1', '0.0.0.0', '::1', 'fd00::1', 'nope', '']) assert.equal(isPublicIP(ip), false, ip);
  for (const ip of ['8.8.8.8', '1.117.74.144', '2606:4700::1111']) assert.equal(isPublicIP(ip), true, ip);
  assert.equal(normDomain('EXAMPLE.com.'), 'example.com'); assert.equal(normDomain('1.2.3.4'), null); assert.equal(normDomain('a b.com'), null); assert.equal(normDomain('nodot'), null);
  assert.equal(famKey('win.cobalt_strike'), 'cobaltstrike'); assert.equal(famKey('Cobalt Strike'), 'cobaltstrike');
  assert.deepEqual(findCVEs(['cve-2021-44228', 'x'], 'see CVE-2023-4966.'), ['CVE-2021-44228', 'CVE-2023-4966']);
});

test('c2intel: IP list, domain+IP, fronting domains, uri paths with commas, junk', () => {
  const recs = c2intel.parse([
    { file: 'IPC2s-30day.csv', text: '#ip,ioc\n1.117.74.144,Possible Cobaltstrike C2 IP\n10.0.0.1,Possible Cobaltstrike C2 IP\ngarbage\n' },
    { file: 'domainC2swithURLwithIP-30day.csv', text: '#domain,ioc,uri_path,ip\nc2.evil.test,Possible Cobalt Strike C2 Fronted Domain,/a,b/c.js,203.0.113.9\n360.net,Possible Cobalt Strike C2 Fronting Domain,/sugrec,154.37.218.73\n' },
  ]);
  assert.equal(recs.length, 4);
  const a = c2intel.extract(recs[0]); assert.deepEqual(keys(a), ['hosts|family:cobaltstrike|ip:1.117.74.144']);
  assert.deepEqual(keys(c2intel.extract(recs[1])), [], 'private IP rejected, no edges');
  const d = c2intel.extract(recs[2]); assert.deepEqual(keys(d), ['hosts|family:cobaltstrike|host:c2.evil.test', 'resolves-to|host:c2.evil.test|ip:203.0.113.9']);
  assert.equal(recs[2].raw.uri_path, '/a,b/c.js'); assert.equal(d.nodes.find((n) => n.id === 'host:c2.evil.test').attrs.role, 'fronted');
  const f = c2intel.extract(recs[3]); assert.equal(f.nodes.find((n) => n.id === 'host:360.net').attrs.role, 'fronting');
  assert.equal(f.events[0].node, 'ip:154.37.218.73', 'a fronting domain is a legit site; the dispatch event targets the IP');
  assert.equal(recs[0].origin.endsWith('#L2'), true, 'origin cites the exact line');
});

test('feodo: ASN comes straight from the record (no enrichment guess)', () => {
  const [r] = feodo.parse([{ text: JSON.stringify([{ ip_address: '203.0.113.5', port: 443, status: 'online', hostname: 'bad.test', as_number: 64500, as_name: 'EXAMPLE-AS', country: 'NL', malware: 'QakBot', first_seen: '2026-01-01' }, { ip_address: '10.0.0.1', malware: 'x' }, { nope: 1 }]) }]);
  const o = ex(feodo, r.raw);
  assert.deepEqual(keys(o), ['hosts|family:qakbot|ip:203.0.113.5', 'resolves-to|host:bad.test|ip:203.0.113.5', 'same-asn|ip:203.0.113.5|asn:AS64500']);
  assert.equal(o.events[0].kind, 'botnet');
  assert.equal(feodo.parse([{ text: 'not json' }]).length, 0);
});

test('threatfox: API form and export form both parse; tags -> CVE and campaign; url/domain/ip:port IOC types', () => {
  const api = JSON.stringify({ query_status: 'ok', data: [{ id: '11', ioc: '203.0.113.7:8443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware: 'win.cobalt_strike', malware_printable: 'Cobalt Strike', confidence_level: 90, first_seen: '2026-01-01 00:00:00', tags: ['campaign:op-x', 'cve-2021-44228'] }, { id: '12', ioc: 'c2.bad.test', ioc_type: 'domain', threat_type: 'botnet_cc', malware_printable: 'Sliver', tags: null }] });
  const exp = JSON.stringify({ 13: [{ ioc_value: 'http://203.0.113.8/p.exe', ioc_type: 'url', threat_type: 'payload_delivery', fk_malware: 'win.asyncrat', malware_printable: 'AsyncRAT', tags: 'rat,cve-2023-4966' }] });
  const recs = threatfox.parse([{ text: api }, { text: exp }]); assert.equal(recs.length, 3);
  const a = ex(threatfox, recs[0].raw); assert.deepEqual(keys(a), ['hosts|campaign:op-x|ip:203.0.113.7', 'hosts|family:cobaltstrike|ip:203.0.113.7']);
  assert.deepEqual(a.events[0].cve, ['CVE-2021-44228']); assert.equal(a.events[0].kind, 'c2');
  assert.deepEqual(keys(ex(threatfox, recs[1].raw)), ['hosts|family:sliver|host:c2.bad.test']);
  const u = ex(threatfox, recs[2].raw); assert.equal(u.events[0].kind, 'malware-url'); assert.deepEqual(u.events[0].cve, ['CVE-2023-4966']);
});

test('urlhaus: host extraction, family from tags (file-type tags ignored), CVE from tags/url', () => {
  const recs = urlhaus.parse([{ text: JSON.stringify({ urls: [{ id: 5, url: 'http://203.0.113.20/bin/x.sh', url_status: 'online', threat: 'malware_download', tags: ['elf', 'mirai', 'cve-2022-0001'], date_added: '2026-01-01' }, { id: 6, url: 'https://drop.bad.test/a.exe', tags: ['exe', 'AsyncRAT'] }, { id: 7, url: 'not a url' }] }) }]);
  assert.equal(recs.length, 3);
  const a = ex(urlhaus, recs[0].raw); assert.deepEqual(keys(a), ['hosts|family:mirai|ip:203.0.113.20']); assert.deepEqual(a.events[0].cve, ['CVE-2022-0001']);
  assert.deepEqual(keys(ex(urlhaus, recs[1].raw)), ['hosts|family:asyncrat|host:drop.bad.test']);
  assert.equal(ex(urlhaus, recs[2].raw).events.length, 0, 'unparseable URL yields nothing');
});

test('openphish: free text feed and brand-bearing JSON lines; victims via attacks edge', () => {
  const recs = openphish.parse([{ text: 'https://login.bad.test/a\nhttp://203.0.113.30/x\n{"url":"https://pay.bad.test/","brand":"ExampleBank"}\n\nnot-a-url\n' }]);
  assert.equal(recs.length, 3);
  assert.deepEqual(keys(ex(openphish, recs[0].raw)), []);
  assert.deepEqual(keys(ex(openphish, recs[2].raw)), ['attacks|host:pay.bad.test|victim:examplebank']);
  assert.equal(ex(openphish, recs[1].raw).events[0].ip, '203.0.113.30');
});

test('dshield: top-sources shapes; private sources dropped', () => {
  const recs = dshield.parse([{ text: JSON.stringify([{ rank: 1, source: '203.0.113.40', reports: 99, targets: 7, lastseen: '2026-01-02' }, { source: '192.168.1.1' }]) }, { text: JSON.stringify({ sources: [{ ip: '203.0.113.41' }] }) }]);
  assert.equal(recs.length, 3);
  assert.equal(ex(dshield, recs[0].raw).events[0].kind, 'scan'); assert.equal(ex(dshield, recs[1].raw).events.length, 0);
  assert.equal(ex(dshield, recs[2].raw).nodes[0].id, 'ip:203.0.113.41');
});

test('radar (aggregate) creates country context nodes only, never host edges', () => {
  const recs = radar.parse([{ text: JSON.stringify({ result: { top_0: [{ originCountryAlpha2: 'US', originCountryName: 'United States', value: '12.5', rank: 1 }] } }) }]);
  const o = ex(radar, recs[0].raw); assert.equal(o.nodes.length, 1); assert.equal(o.edges.length, 0);
});

test('greynoise annotates; otx yields campaign + victim edges with provenance-friendly records', () => {
  const g = greynoise.parse([{ text: JSON.stringify({ ip: '203.0.113.50', noise: true, riot: false, classification: 'malicious', name: 'x' }), url: 'u' }]);
  assert.equal(ex(greynoise, g[0].raw).nodes[0].attrs.greynoise, 'malicious');
  const o = otx.parse([{ text: JSON.stringify({ indicator: '203.0.113.51', pulse_info: { pulses: [{ id: 'p1', name: 'Operation Example', targeted_countries: ['Germany'] }] } }), url: 'u' }]);
  assert.deepEqual(keys(ex(otx, o[0].raw)), ['attacks|campaign:operation-example|victim:germany', 'hosts|campaign:operation-example|ip:203.0.113.51']);
  assert.equal(otx.parse([{ text: JSON.stringify({ indicator: '203.0.113.52', pulse_info: { pulses: [] } }) }]).length, 0, 'no pulses -> no record');
});

test('Team Cymru parsing via injected DNS; RIPEstat via injected HTTP; fallback chain; failure => no ASN (never a guess)', async () => {
  const txt = { '5.113.0.203.origin.asn.cymru.com': [['64500 | 203.0.113.0/24 | ZZ | arin | 2020-01-01']], 'AS64500.asn.cymru.com': [['64500 | ZZ | arin | 2020-01-01 | EXAMPLE-NET, ZZ']] };
  const c = await cymruLookup('203.0.113.5', { resolveTxt: async (n) => { if (!txt[n]) throw new Error('NXDOMAIN'); return txt[n]; } });
  assert.deepEqual(c, { ip: '203.0.113.5', asn: '64500', prefix: '203.0.113.0/24', cc: 'ZZ', registry: 'arin', as_name: 'EXAMPLE-NET, ZZ' });
  const r = await ripestatLookup('203.0.113.5', { get: async () => JSON.stringify({ data: { resource: '203.0.113.0/24', asns: [{ asn: 64500, holder: 'EXAMPLE' }] } }) });
  assert.equal(r.asn, '64500'); assert.equal(r.as_name, 'EXAMPLE');
  const ok = await enrichIP('203.0.113.5', { providers: [['cymru', async () => { throw new Error('dns blocked'); }], ['ripestat', async (ip) => ({ ip, asn: '64501', as_name: 'B', cc: null })]] });
  assert.equal(ok.provider, 'ripestat'); assert.match(ok.errors[0], /dns blocked/);
  const none = await enrichIP('203.0.113.5', { providers: [['cymru', async () => { throw new Error('x'); }], ['ripestat', async () => null]] });
  assert.equal(none.provider, null); assert.equal(none.input, null);
  const rec = cymru.parse([ok.input && { ...ok.input, raw: { ip: '203.0.113.5', asn: '64500', as_name: 'E', cc: 'ZZ' } }])[0];
  assert.deepEqual(keys(cymru.extract(rec)), ['same-asn|ip:203.0.113.5|asn:AS64500']);
  void ripestat;
});

test('enrichment in the pipeline adds ip->asn edges WITH provenance and never invents one on failure', async () => {
  const f = makeFangs({ FANGS_NO_ENRICH: '0' }, { enrichProviders: [['cymru', async (ip) => (ip === '203.0.113.60' ? { ip, asn: '64510', as_name: 'T', cc: 'ZZ' } : null)]] });
  const recs = c2intel.parse([{ file: 'IPC2s-30day.csv', text: '#ip,ioc\n203.0.113.60,Possible Sliver C2 IP\n203.0.113.61,Possible Sliver C2 IP\n' }]);
  f.ingestRecords(recs); await new Promise((r) => setTimeout(r, 100));
  assert.ok(f.fg.graph.hasNode('asn:AS64510')); assert.ok(f.fg.graph.hasNode('ip:203.0.113.61'));
  assert.equal(f.fg.graph.neighbors('ip:203.0.113.61').some((n) => n.startsWith('asn:')), false, 'unenriched IP has no ASN edge');
  assert.equal(f.stats.enriched, 1); assert.equal(f.stats.enrich_fail, 1);
  const { verifyProvenance } = await import('../src/provenance.js'); assert.equal(verifyProvenance(f.fg, f.store, f.adapters).ok, true);
});

test('honest degradation: keyed feeds report needs-key; a failing live feed degrades without crashing and keeps the snapshot', async () => {
  const f = makeFangs(); f.loadSnapshot();
  assert.equal(f.feedStatus.get('threatfox').state, 'needs-key'); assert.equal(f.feedStatus.get('greynoise').state, 'needs-key');
  const failing = { ...c2intel, fetchAll: async () => { throw new Error('HTTP 403'); } };
  const before = f.fg.order; await f.pollOnce(failing);
  assert.equal(f.feedStatus.get('c2intel').state, 'snapshot'); assert.match(f.feedStatus.get('c2intel').last_error, /403/); assert.equal(f.fg.order, before);
  await f.pollOnce(threatfox); assert.equal(f.feedStatus.get('threatfox').state, 'needs-key');
  const failing2 = { ...feodo, fetchAll: async () => { throw new Error('ECONNRESET'); } }; await f.pollOnce(failing2);
  assert.equal(f.feedStatus.get('feodo').state, 'degraded');
  const good = { ...feodo, fetchAll: async () => [{ text: JSON.stringify([{ ip_address: '203.0.113.70', port: 80, malware: 'Emotet', as_number: 64511, as_name: 'X', country: 'ZZ' }]), url: 'https://example.invalid/f.json' }] };
  await f.pollOnce(good); assert.equal(f.feedStatus.get('feodo').state, 'ok'); assert.ok(f.fg.graph.hasNode('ip:203.0.113.70'));
});
