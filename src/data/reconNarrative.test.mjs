import test from 'node:test';
import assert from 'node:assert/strict';
import { correlateIncidents } from './incidentCorrelation.js';
import { narrate, caseFile, killChainPercent } from './reconNarrative.js';

const NOW = Date.parse('2026-11-18T18:00:00Z');
const h = (n) => new Date(NOW - n * 3_600_000).toISOString();

const incidents = correlateIncidents(
  [
    { title: 'DDoS flood from Russia hits a bank', source: 'Cloudflare', time: h(5), country: 'RU' },
    { title: 'Data encrypted for impact, ransomware from Russia', source: 'BleepingComputer', time: h(4), country: 'RU', malware: 'LockBit' },
    { title: 'Another Russian DDoS wave', source: 'DShield', time: h(3), country: 'RU' },
  ],
  { now: NOW },
);

test('narrate summarizes the incident set in plain English', () => {
  const text = narrate(incidents, { now: NOW });
  assert.match(text, /correlated incident/);
  assert.match(text, /RU/);
  assert.match(text, /Highest-priority/);
  assert.equal(narrate([], { now: NOW }).startsWith('No correlated incidents'), true);
});

test('caseFile exports a Markdown reconstruction with kill chain, ATT&CK and timeline', () => {
  const md = caseFile(incidents[0]);
  assert.match(md, /^# Incident —/m);
  assert.match(md, /## Cyber Kill Chain/);
  assert.match(md, /\[x\] 7\. Actions on Objectives|\[ \] 7\. Actions on Objectives/);
  assert.match(md, /## MITRE ATT&CK/);
  assert.match(md, /## Timeline \(as reported\)/);
  assert.match(md, /Correlated from public signals/); // the disclaimer
  assert.equal(caseFile(null), '');
});

test('killChainPercent reports coverage out of seven', () => {
  assert.equal(killChainPercent({ killChainCoverage: 7 }), 100);
  assert.equal(killChainPercent({ killChainCoverage: 0 }), 0);
});
