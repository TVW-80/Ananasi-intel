import test from 'node:test';
import assert from 'node:assert/strict';
import { toEvent, correlateIncidents, collectReconEvents, RECON_DISCLAIMER } from './incidentCorrelation.js';

const NOW = Date.parse('2026-11-18T18:00:00Z');
const h = (n) => new Date(NOW - n * 3_600_000).toISOString();

test('toEvent derives kind, technique, kill-chain phase and confidence', () => {
  const e = toEvent(
    { title: 'LockBit ransomware encrypts hospital files', source: 'abuse.ch Feodo', time: h(2), country: 'ru' },
    { now: NOW },
  );
  assert.equal(e.kind, 'ransomware');
  assert.equal(e.technique.id, 'T1486');
  assert.equal(e.killChain.name, 'Actions on Objectives');
  assert.equal(e.adversary, 'RU');
  assert.equal(e.confidence, 'High'); // fresh + abuse.ch + hospital
  assert.equal(e.pyramid.level, 'TTPs');
});

test('toEvent guesses an adversary country from text when none is given, and pulls a CVE', () => {
  const e = toEvent({ title: 'Chinese group exploits CVE-2026-1234 in VPN', source: 'The Record', time: h(1) }, { now: NOW });
  assert.equal(e.adversary, 'CN');
  assert.equal(e.cve, 'CVE-2026-1234');
  assert.equal(e.kind, 'exploit');
});

test('correlateIncidents clusters by adversary + tactic within the time window', () => {
  const incidents = correlateIncidents(
    [
      { title: 'DDoS flood from Russia hits bank', source: 'Cloudflare', time: h(6), country: 'RU' },
      { title: 'Another DDoS wave from Russian IPs', source: 'DShield', time: h(5), country: 'RU' },
      { title: 'Data encrypted for impact — ransomware from Russia', source: 'BleepingComputer', time: h(4), country: 'RU' },
      { title: 'Phishing surge, origin unknown', source: 'OpenPhish', time: h(3) },
    ],
    { now: NOW },
  );
  // Two RU DDoS signals (Impact tactic) collapse into one incident; the RU
  // ransomware is also Impact → joins them. Phishing (Initial Access) is separate.
  const ru = incidents.find((i) => i.adversary === 'RU');
  assert.ok(ru.eventCount >= 3, 'the RU Impact signals merge');
  assert.ok(ru.sources.length >= 3, 'multiple corroborating sources');
  assert.ok(incidents.some((i) => i.adversary === 'Unknown' && /Phishing/.test(i.title)));
});

test('an incident reconstructs the kill chain and lifts confidence with corroboration', () => {
  const incidents = correlateIncidents(
    [
      { title: 'Scanning of Virginia hospital from Iran', source: 'DShield', time: h(10), country: 'IR' },
      { title: 'Phishing email delivery, Iranian actor', source: 'OpenPhish', time: h(9), country: 'IR' },
      { title: 'Exploit of public-facing app, Iran', source: 'CISA', time: h(8), country: 'IR' },
      { title: 'C2 beacon to Iranian server', source: 'abuse.ch', time: h(7), country: 'IR' },
      { title: 'Ransomware detonation, Iran', source: 'The Record', time: h(6), country: 'IR' },
    ],
    { now: NOW, windowMs: 48 * 3_600_000 },
  );
  const ir = incidents.find((i) => i.adversary === 'IR');
  // Several tactics, but the engine groups by tactic — still, the top incident
  // should carry multiple kill-chain phases and brutal pyramid level + high conf.
  assert.ok(ir);
  assert.equal(ir.confidence, 'High');
  assert.ok(ir.killChainCoverage >= 1 && ir.furthestPhase);
  assert.ok(ir.title.includes('IR'));
});

test('ranking puts the strongest incident first and caps the list', () => {
  const many = Array.from({ length: 40 }, (_, i) => ({
    title: `scan ${i}`, source: `src${i % 2}`, time: h(1 + (i % 5)), country: i % 2 ? 'BR' : 'CN',
  }));
  const incidents = correlateIncidents(many, { now: NOW, limit: 5 });
  assert.ok(incidents.length <= 5);
  for (let i = 1; i < incidents.length; i++) assert.ok(incidents[i - 1].score >= incidents[i].score);
  assert.ok(typeof RECON_DISCLAIMER === 'string' && RECON_DISCLAIMER.length > 20);
});

test('collectReconEvents flattens the FANGS snapshots into the signal stream', () => {
  const events = collectReconEvents({
    attack: { alerts: [{ title: 'KEV alert', plain: 'bad', technical: 'CVE', source: 'CISA KEV', time: h(1) }], sources: [{ name: 'Moscow, RU', country: 'RU', dominantService: 'ssh', ips: [{ ip: '198.51.100.7' }] }] },
    cyber: { items: [{ title: 'Ransomware hits hospital', plain: 'bad', source: 'The Record', date: h(2), url: 'https://x' }] },
    ai: { vulns: [{ title: 'FortiOS bypass', id: 'CVE-2026-9', date: '2026-11-17', ransomware: true }] },
    service: { at: NOW, providers: [{ label: 'GitHub', bucket: 'down', plain: 'down' }, { label: 'Fastly', bucket: 'ok' }] },
  });
  assert.equal(events.length, 5); // 1 alert + 1 source + 1 news + 1 vuln + 1 down provider (ok skipped)
  assert.ok(events.some((e) => e.country === 'RU' && e.ip === '198.51.100.7'));
  assert.ok(events.some((e) => e.cve === 'CVE-2026-9'));
  assert.ok(!events.some((e) => /Fastly/.test(e.title))); // operational provider excluded
});

test('toEvent is idempotent so callers can normalize once', () => {
  const once = toEvent({ title: 'ransomware from RU', source: 'abuse.ch', time: h(1), country: 'RU' }, { now: NOW });
  const twice = toEvent(once, { now: NOW });
  assert.equal(twice, once); // same object, time/country preserved
  assert.equal(twice.adversary, 'RU');
  assert.equal(twice.timeMs, once.timeMs);
});

test('empty / junk input yields no incidents and never throws', () => {
  assert.deepEqual(correlateIncidents([], { now: NOW }), []);
  assert.deepEqual(correlateIncidents(null, { now: NOW }), []);
  assert.doesNotThrow(() => correlateIncidents([null, {}, { title: '' }], { now: NOW }));
});
