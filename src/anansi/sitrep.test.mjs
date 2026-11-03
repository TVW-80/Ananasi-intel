import test from 'node:test';
import assert from 'node:assert/strict';
import { attackAlertEntries, buildSitrep, plainAiSecEntries, tidy } from './sitrep.js';

test('tidy trims to a word boundary with an ellipsis', () => {
  assert.equal(tidy('  hello   world  '), 'hello world');
  assert.equal(tidy('one two three four five', 12), 'one two…');
});

test('a vulnerability becomes a plain-English, do-this card; KEV ranks first', () => {
  const [e] = plainAiSecEntries({ vulns: [
    { id: 'CVE-2026-1', title: 'Auth bypass', vendor: 'Acme', product: 'VPN', severity: 'critical', exploited: 'kev', dueDate: '2026-11-20', cvss: 9.8, action: 'Update to 7.2', ransomware: true, evidence: [{ url: 'https://x' }], date: '2026-11-02' },
  ] });
  assert.equal(e.tag, 'EXPLOITED NOW');
  assert.match(e.plain, /security hole was found in Acme VPN/);
  assert.match(e.plain, /Hackers are already using it/);
  assert.match(e.plain, /Ransomware gangs/);
  assert.match(e.todo, /Update to 7.2/);
  assert.match(e.detail, /CVE-2026-1/);
  assert.equal(e.link, 'https://x');
  assert.ok(e.priority >= 1000);
});

test('news items (models/research/policy) summarize in plain words', () => {
  const entries = plainAiSecEntries({ models: [{ title: 'New model', summary: 'It is faster.', source: 'OpenAI', url: 'https://m', date: '2026-11-01' }], policy: [{ title: 'New rule', number: 'EO 1', date: '2026-10-01' }] });
  const model = entries.find((e) => e.tag === 'AI MODELS');
  assert.equal(model.plain, 'It is faster.');
  assert.equal(model.link, 'https://m');
  assert.ok(entries.some((e) => e.tag === 'AI POLICY'));
});

test('attack alerts merge in, most important first, capped', () => {
  const body = { alerts: [{ source: 'CISA KEV', title: 'bug', plain: 'A bug is being used.', technical: 'CVE-x', link: 'https://k', time: '2026-11-02T00:00:00Z' }] };
  assert.equal(attackAlertEntries(body)[0].kind, 'attack');
  const merged = buildSitrep(body, { vulns: [{ id: 'CVE-9', title: 'x', exploited: 'kev', severity: 'critical' }] });
  assert.ok(merged.length >= 2);
  assert.equal(merged[0].tag, 'EXPLOITED NOW', 'KEV vuln outranks a plain alert');
  assert.ok(merged.length <= 40);
});
