import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CYBER_NEWS_SOURCES,
  RETAIN_DAYS,
  categorize,
  normalizeItems,
  assembleCyberNews,
  parseFeed,
} from './cyberNews.js';

const NOW = Date.parse('2026-11-17T18:00:00Z');
const ago = (days) => new Date(NOW - days * 86_400_000).toUTCString();

/** Build an RSS document the shared parser understands. */
function rss(items) {
  const body = items
    .map(
      (it) =>
        `<item><title>${it.title}</title><link>${it.link}</link>` +
        `<description>${it.desc || ''}</description><pubDate>${it.date}</pubDate></item>`,
    )
    .join('');
  return `<?xml version="1.0"?><rss><channel>${body}</channel></rss>`;
}

test('every bundled source has an id, label and an https feed URL', () => {
  assert.ok(CYBER_NEWS_SOURCES.length >= 5);
  for (const s of CYBER_NEWS_SOURCES) {
    assert.ok(s.id && s.label && /^https:\/\//.test(s.url), `bad source ${JSON.stringify(s)}`);
  }
});

test('categorize sorts headlines into the right plain-English bucket', () => {
  assert.equal(categorize('Massive DDoS attack knocks major websites offline').tag, 'OUTAGE');
  assert.equal(categorize('LockBit ransomware hits hospital, files encrypted').tag, 'RANSOMWARE');
  assert.equal(categorize('Retailer data breach exposes 2 million records').tag, 'BREACH');
  assert.equal(categorize('Chinese state-sponsored hackers breach telecom').tag, 'NATION-STATE');
  assert.equal(categorize('Zero-day in VPN actively exploited, CVE-2026-1234').tag, 'EXPLOIT');
  assert.equal(categorize('CISA warns of flaw', '', 'cisa-advisories').tag, 'ADVISORY');
  assert.equal(categorize('Company announces new security hire').tag, 'NEWS');
});

test('categorize carries a plain, non-expert one-liner for real categories', () => {
  assert.match(categorize('websites taken offline by DDoS').plain, /knocked websites or online services offline/i);
  assert.equal(categorize('a generic industry update').plain, ''); // NEWS has no lead
});

test('normalizeItems drops undated and anything older than the retention window', () => {
  const parsed = parseFeed(rss([
    { title: 'Fresh breach exposes data', link: 'https://x/1', desc: 'records stolen', date: ago(1) },
    { title: 'Old ransomware story', link: 'https://x/2', desc: 'ransom', date: ago(RETAIN_DAYS + 3) },
  ]));
  const out = normalizeItems('Test', 'thehackernews', parsed, { now: NOW });
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'Fresh breach exposes data');
  assert.equal(out[0].tag, 'BREACH');
  assert.equal(out[0].source, 'Test');
  assert.ok(out[0].priority > 0 && typeof out[0].url === 'string');
});

test('normalizeItems flags recent items as new and boosts close-to-home headlines', () => {
  const parsed = parseFeed(rss([
    { title: 'Cyber attack disrupts Virginia hospital network', link: 'https://x/3', desc: 'outage', date: ago(0.1) },
    { title: 'Minor outage at an overseas firm', link: 'https://x/4', desc: 'service disruption', date: ago(0.1) },
  ]));
  const [home, away] = normalizeItems('Test', 'bleepingcomputer', parsed, { now: NOW });
  assert.equal(home.isNew, true);
  assert.ok(home.priority > away.priority, 'the Virginia headline outranks the generic one');
});

test('assembleCyberNews dedups by headline and ranks most-important-newest first', () => {
  const items = [
    { title: 'Big ransomware attack', url: 'https://a', dateMs: NOW - 3_600_000, priority: 76, tag: 'RANSOMWARE' },
    { title: 'Big ransomware attack!', url: 'https://b', dateMs: NOW - 7_200_000, priority: 76, tag: 'RANSOMWARE' }, // dup headline
    { title: 'Routine security newsletter', url: 'https://c', dateMs: NOW - 60_000, priority: 28, tag: 'NEWS' },
    { title: 'Websites knocked offline', url: 'https://d', dateMs: NOW - 1_800_000, priority: 78, tag: 'OUTAGE' },
  ];
  const { items: ranked } = assembleCyberNews({ items, now: NOW });
  // The two "Big ransomware attack" headlines collapse to one (the newer).
  assert.equal(ranked.filter((i) => /ransomware/i.test(i.title)).length, 1);
  assert.equal(ranked.find((i) => /ransomware/i.test(i.title)).url, 'https://a');
  // Highest priority leads; the low-priority newsletter sinks to the bottom.
  assert.equal(ranked[0].tag, 'OUTAGE');
  assert.equal(ranked.at(-1).tag, 'NEWS');
});

test('assembleCyberNews caps the wire length', () => {
  const items = Array.from({ length: 120 }, (_, i) => ({
    title: `headline ${i}`, url: `https://x/${i}`, dateMs: NOW - i * 1000, priority: 30, tag: 'NEWS',
  }));
  const { items: ranked } = assembleCyberNews({ items, now: NOW, limit: 60 });
  assert.equal(ranked.length, 60);
});
