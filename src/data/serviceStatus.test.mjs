import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSummary, bucketOf, plainStatus, assembleServiceStatus, summaryUrl } from './serviceStatus.js';

const OK = {
  page: { id: 'p1', name: 'Cloudflare', url: 'https://www.cloudflarestatus.com', updated_at: '2026-11-17T20:00:00Z' },
  status: { indicator: 'none', description: 'All Systems Operational' },
  components: [{ name: 'CDN', status: 'operational' }, { name: 'Group', status: 'operational', group: true }],
  incidents: [],
};
const DOWN = {
  page: { id: 'p2', name: 'GitHub', url: 'https://www.githubstatus.com', updated_at: '2026-11-17T20:01:00Z' },
  status: { indicator: 'major', description: 'Major Service Outage' },
  components: [
    { name: 'Actions', status: 'major_outage' },
    { name: 'Pages', status: 'partial_outage' },
    { name: 'API', status: 'operational' },
  ],
  incidents: [
    { name: 'Elevated errors on Actions', impact: 'major', status: 'investigating', shortlink: 'https://stspg.io/x', updated_at: '2026-11-17T19:55:00Z' },
    { name: 'Old one', impact: 'minor', status: 'resolved', shortlink: 'https://stspg.io/y' },
  ],
};

test('summaryUrl targets the statuspage v2 summary endpoint', () => {
  assert.equal(summaryUrl('status.zoom.us'), 'https://status.zoom.us/api/v2/summary.json');
});

test('parseSummary reads operational pages with no issues', () => {
  const rec = parseSummary(OK, { id: 'cloudflare', label: 'Cloudflare', host: 'www.cloudflarestatus.com' });
  assert.equal(rec.indicator, 'none');
  assert.equal(rec.rank, 0);
  assert.deepEqual(rec.down, []); // group rows are skipped, operational ignored
  assert.deepEqual(rec.incidents, []);
  assert.equal(bucketOf(rec), 'ok');
  assert.match(plainStatus(rec), /all systems operational/i);
});

test('parseSummary captures down components + active incidents, drops resolved ones', () => {
  const rec = parseSummary(DOWN, { id: 'github', label: 'GitHub', host: 'www.githubstatus.com' });
  assert.equal(rec.indicator, 'major');
  assert.equal(rec.rank, 2);
  assert.deepEqual(rec.down.map((d) => [d.name, d.word]), [['Actions', 'major outage'], ['Pages', 'partial outage']]);
  assert.equal(rec.incidents.length, 1); // resolved one dropped
  assert.equal(rec.incidents[0].url, 'https://stspg.io/x');
  assert.equal(bucketOf(rec), 'down');
  assert.match(plainStatus(rec), /Elevated errors on Actions/);
});

test('a minor indicator or a lone bad component counts as degraded', () => {
  const rec = parseSummary(
    { page: { name: 'Zoom' }, status: { indicator: 'minor', description: 'Degraded' }, components: [{ name: 'Mtg', status: 'degraded_performance' }], incidents: [] },
    { id: 'zoom', label: 'Zoom' },
  );
  assert.equal(bucketOf(rec), 'degraded');
});

test('assembleServiceStatus ranks worst-first and tallies the buckets', () => {
  const okRec = parseSummary(OK, { id: 'cloudflare', label: 'Cloudflare' });
  const downRec = parseSummary(DOWN, { id: 'github', label: 'GitHub' });
  const board = assembleServiceStatus({ records: [okRec, downRec], now: 1000 });
  assert.equal(board.at, 1000);
  assert.equal(board.providers[0].label, 'GitHub'); // down ranks above ok
  assert.deepEqual(board.summary, { down: 1, degraded: 0, ok: 1, total: 2 });
  assert.equal(board.providers[0].bucket, 'down');
  assert.ok(board.providers[0].plain);
});
