import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreVuln, rankVulns, bandCounts } from './vulnPriority.js';

const NOW = Date.parse('2026-11-17T12:00:00Z');

test('active exploitation (KEV) always outranks a merely-severe vuln', () => {
  const kevHigh = scoreVuln(
    { exploited: 'kev', severity: 'high', dueDate: '2026-12-20' },
    { now: NOW },
  );
  const criticalNotExploited = scoreVuln(
    { exploited: 'unconfirmed', severity: 'critical', cvss: 9.8 },
    { now: NOW },
  );
  assert.equal(kevHigh.band, 'P1');
  assert.ok(kevHigh.factors.includes('Actively exploited (CISA KEV)'));
  assert.equal(criticalNotExploited.band, 'P2'); // severe, but not being exploited
  assert.ok(kevHigh.score > criticalNotExploited.score);
});

test('ransomware use and an overdue CISA deadline add traceable points', () => {
  const r = scoreVuln(
    { exploited: 'kev', ransomware: true, severity: 'critical', dueDate: '2026-11-10' },
    { now: NOW },
  );
  assert.equal(r.band, 'P1');
  assert.ok(r.factors.includes('Used in ransomware campaigns'));
  assert.ok(r.factors.some((f) => /overdue/i.test(f)));
  // base(critical 90) + kev 120 + ransomware 60 + overdue 40
  assert.equal(r.score, 310);
});

test('a low-severity, unexploited item lands in P3 with a plain action', () => {
  const low = scoreVuln({ exploited: 'unconfirmed', severity: 'low' }, { now: NOW });
  assert.equal(low.band, 'P3');
  assert.equal(low.bandLabel, 'Track');
  assert.match(low.action, /patch/i);
});

test('rankVulns sorts hottest-first, caps, and bandCounts tallies', () => {
  const ranked = rankVulns(
    [
      { id: 'A', exploited: 'unconfirmed', severity: 'medium' },
      { id: 'B', exploited: 'kev', ransomware: true, severity: 'critical', date: '2026-11-16' },
      { id: 'C', exploited: 'kev', severity: 'high', date: '2026-11-15' },
      null,
    ],
    { now: NOW, limit: 2 },
  );
  assert.equal(ranked.length, 2);
  assert.equal(ranked[0].id, 'B'); // ransomware KEV is hottest
  assert.equal(ranked[1].id, 'C');
  const counts = bandCounts(ranked);
  assert.equal(counts.P1, 2);
  assert.equal(counts.P2 + counts.P3, 0);
});

test('CVSS drives the base score when present; missing fields never throw', () => {
  const withCvss = scoreVuln({ cvss: 7.5, exploited: 'unconfirmed' }, { now: NOW });
  assert.ok(withCvss.factors.includes('CVSS 7.5'));
  assert.equal(withCvss.score, 75);
  assert.doesNotThrow(() => scoreVuln({}, { now: NOW }));
  assert.doesNotThrow(() => scoreVuln(undefined, { now: NOW }));
});
