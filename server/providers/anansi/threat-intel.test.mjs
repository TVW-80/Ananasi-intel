import test from 'node:test';
import assert from 'node:assert/strict';
import {
  countryCentroid,
  usStateCentroid,
  normalizeFeodo,
  normalizeAbuseIpdb,
  normalizeRansomware,
  normalizeIoda,
  normalizeCloudflareOutages,
  normalizeShodan,
} from './threat-feeds.js';
import { createThreatIntelMiddleware, FEEDS, iodaSummaryUrl } from './threat-intel.js';

test('centroids resolve countries and US states by code or name', () => {
  assert.equal(countryCentroid('us').name, 'United States');
  assert.equal(countryCentroid('ZZ'), null);
  assert.equal(usStateCentroid('Virginia').code, 'VA');
  assert.equal(usStateCentroid('va').code, 'VA');
  assert.equal(usStateCentroid('Atlantis'), null);
});

test('Feodo C2 servers group per country, online weighted higher', () => {
  const { points, total } = normalizeFeodo([
    { ip_address: '1.2.3.4', port: 443, status: 'online', as_name: 'EXAMPLE-AS', country: 'US', last_online: '2026-10-30', malware: 'QakBot' },
    { ip_address: '5.6.7.8', port: 8080, status: 'offline', country: 'US', last_online: '2026-10-01', malware: 'Emotet' },
    { ip_address: '9.9.9.9', status: 'offline', country: 'DE', malware: 'Dridex' },
    { ip_address: '7.7.7.7', country: '??' },
  ]);
  assert.equal(total, 4);
  assert.deepEqual(points.map((p) => p.id), ['feodo:US', 'feodo:DE']);
  assert.equal(points[0].title, '2 C2');
  assert.equal(points[0].severity, 1);
  assert.match(points[0].items[0].text, /^QakBot C2 1\.2\.3\.4:443 · EXAMPLE-AS · online$/);
  assert.equal(points[0].approximate, true);
});

test('AbuseIPDB, ransomware.live and Cloudflare normalize to country points', () => {
  const abuse = normalizeAbuseIpdb({ data: [{ ipAddress: '1.1.1.1', countryCode: 'CN', abuseConfidenceScore: 100, lastReportedAt: '2026-10-31T01:00:00+00:00' }] });
  assert.equal(abuse.points[0].id, 'abuseipdb:CN');
  assert.match(abuse.points[0].items[0].text, /confidence 100%/);

  const rw = normalizeRansomware([
    { victim: 'Example Hospital', group: 'akira', country: 'US', activity: 'Healthcare', attackdate: '2026-10-29 12:00:00' },
    { post_title: 'Old Shape Co', group_name: 'lockbit3', country: 'US', discovered: '2026-10-30' },
  ]);
  assert.equal(rw.points[0].title, '2 victims');
  assert.equal(rw.points[0].items[0].text, 'Old Shape Co — lockbit3');

  const cf = normalizeCloudflareOutages({ result: { annotations: [{ description: 'Power outage', locations: ['VE', 'CO'], outage: { outageCause: 'POWER_OUTAGE' }, startDate: '2026-10-30T00:00:00Z' }] } });
  assert.deepEqual(cf.points.map((p) => p.country).sort(), ['CO', 'VE']);
  assert.match(cf.points[0].items[0].text, /Power outage · POWER OUTAGE/);
});

test('IODA scores map to countries or US states; zero scores are dropped', () => {
  const countries = normalizeIoda({ data: [
    { entity: { code: 'IR', name: 'Iran' }, scores: { overall: 1e6 }, event_cnt: 4 },
    { entity: { code: 'US', name: 'United States' }, scores: { overall: 10 }, event_cnt: 1 },
    { entity: { code: 'FR', name: 'France' }, scores: { overall: 0 }, event_cnt: 0 },
  ] });
  assert.deepEqual(countries.points.map((p) => p.id), ['ioda:country:IR', 'ioda:country:US']);
  assert.equal(countries.points[0].severity, 1);
  const states = normalizeIoda({ data: [{ entity: { code: '4417', name: 'Virginia', type: 'region' }, scores: { overall: 250 }, event_cnt: 2 }] }, { level: 'us-state' });
  assert.equal(states.points[0].id, 'ioda:us-state:VA');
  assert.equal(states.points[0].place, 'Virginia');
});

test('Shodan matches keep exact coordinates', () => {
  const { points } = normalizeShodan({ total: 2, matches: [
    { ip_str: '203.0.113.5', port: 502, product: 'Modbus', org: 'Example Utility', location: { latitude: 36.9, longitude: -76.2, city: 'Norfolk', region_code: 'VA', country_code: 'US' } },
    { ip_str: '203.0.113.6', port: 102, location: {} },
  ] });
  assert.equal(points.length, 1);
  assert.deepEqual([points[0].lat, points[0].lon, points[0].approximate], [36.9, -76.2, false]);
  assert.equal(points[0].title, 'Modbus:502');
  assert.equal(points[0].place, 'Norfolk, VA');
});

test('IODA URLs cover the last 24 hours, US states scoped to the country', () => {
  const url = new URL(iodaSummaryUrl(Date.parse('2026-10-31T00:00:00Z'), { entityType: 'region', relatedTo: 'country/US' }));
  assert.equal(url.searchParams.get('until') - url.searchParams.get('from'), 86400);
  assert.equal(url.searchParams.get('relatedTo'), 'country/US');
});

// ── middleware ──────────────────────────────────────────────────────────────
function call(mw, url) {
  return new Promise((resolve) => {
    const res = { headersSent: false, writeHead(s) { this.status = s; this.headersSent = true; }, end(b) { resolve({ status: this.status, body: JSON.parse(b) }); } };
    mw({ method: 'GET', url }, res);
  });
}
const json = (body, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });

test('keyed feeds report key-required without calling upstream', async () => {
  const mw = createThreatIntelMiddleware({ envSource: {}, fetchImpl: () => assert.fail('no request without a key') });
  for (const feed of ['abuseipdb', 'cloudflare', 'shodan-ics']) {
    const r = await call(mw, `/${feed}`);
    assert.equal(r.body.status, 'key-required', feed);
    assert.equal(r.body.keyEnv, FEEDS[feed].keyEnv);
  }
  assert.equal((await call(mw, '/nope')).status, 404);
});

test('caches, serves stale on failure, and never leaks the Shodan key', async () => {
  let t = 0;
  let mode = 'ok';
  const seen = [];
  const mw = createThreatIntelMiddleware({
    clock: () => t,
    envSource: { SHODAN_API_KEY: 'SECRET123' },
    fetchImpl: async (url, opts) => {
      seen.push({ url, opts });
      if (mode === 'down') throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNRESET' } });
      return json({ total: 1, matches: [{ ip_str: '203.0.113.5', port: 502, location: { latitude: 36.9, longitude: -76.2 } }] });
    },
  });
  const first = await call(mw, '/shodan-ics');
  assert.equal(first.body.status, 'ok');
  assert.equal(first.body.points.length, 1);
  assert.match(seen[0].opts.headers['User-Agent'], /^Anansi/);
  await call(mw, '/shodan-ics');
  assert.equal(seen.length, 1, 'second call within TTL is cached');

  t += FEEDS['shodan-ics'].ttl + 1;
  mode = 'down';
  const stale = await call(mw, '/shodan-ics');
  assert.equal(stale.body.status, 'stale');
  assert.equal(stale.body.points.length, 1, 'last good points kept');
  assert.doesNotMatch(JSON.stringify(stale.body), /SECRET123/);
});

test('a first failure reports error with no points', async () => {
  const mw = createThreatIntelMiddleware({ fetchImpl: async () => json({}, 503) });
  const r = await call(mw, '/feodo');
  assert.equal(r.body.status, 'error');
  assert.match(r.body.error, /HTTP 503/);
});

test('a key pasted in POWER UP is used on the very next poll', async () => {
  const envSource = {};
  let calls = 0;
  const mw = createThreatIntelMiddleware({
    envSource,
    fetchImpl: async () => {
      calls += 1;
      return json({ data: [] });
    },
  });
  assert.equal((await call(mw, '/abuseipdb')).body.status, 'key-required');
  envSource.ABUSEIPDB_API_KEY = 'pasted-key'; // what /api/setup does to process.env
  assert.equal((await call(mw, '/abuseipdb')).body.status, 'ok');
  assert.equal(calls, 1);
});

test('every keyed feed and optional feed key has a POWER UP entry', async () => {
  const { KEY_SETUP_KEYS } = await import('../../../src/keySetupCore.mjs');
  const panelVars = new Set(KEY_SETUP_KEYS.filter((k) => !k.hidden).flatMap((k) => k.envVars));
  for (const [name, feed] of Object.entries(FEEDS)) {
    if (feed.keyEnv) assert.ok(panelVars.has(feed.keyEnv), `${name}: ${feed.keyEnv} missing from POWER UP`);
  }
  for (const optional of ['ABUSECH_AUTH_KEY', 'GITHUB_TOKEN']) assert.ok(panelVars.has(optional), optional);
});
