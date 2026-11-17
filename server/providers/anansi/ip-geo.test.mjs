import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeIpApiBatch, normalizeMmdb, createIpGeo } from './ip-geo.js';

test('normalizeIpApiBatch keeps only successful rows with finite coords', () => {
  const m = normalizeIpApiBatch([
    { status: 'success', query: '198.51.100.7', countryCode: 'ru', city: 'Moscow', lat: 55.75, lon: 37.62 },
    { status: 'fail', query: '203.0.113.9' },
    { status: 'success', query: '192.0.2.4', countryCode: 'US', city: '', lat: 'nan', lon: 1 },
  ]);
  assert.equal(m.size, 1);
  assert.deepEqual(m.get('198.51.100.7'), { lat: 55.75, lon: 37.62, city: 'Moscow', country: 'RU' });
});

test('normalizeMmdb reads a GeoLite2 City record, or null without coords', () => {
  assert.deepEqual(
    normalizeMmdb({ location: { latitude: 1.5, longitude: -2.5 }, city: { names: { en: 'Testville' } }, country: { iso_code: 'de' } }),
    { lat: 1.5, lon: -2.5, city: 'Testville', country: 'DE' },
  );
  assert.equal(normalizeMmdb({ city: { names: { en: 'No coords' } } }), null);
});

test('resolve uses ip-api batch, caches results, and never re-queries fresh IPs', async () => {
  let calls = 0;
  const getJson = async (_url, opts) => {
    calls += 1;
    const ips = JSON.parse(opts.body);
    return ips.map((q) => ({ status: 'success', query: q, countryCode: 'NL', city: 'Amsterdam', lat: 52.37, lon: 4.9 }));
  };
  const geo = createIpGeo({ getJson, env: {}, cache: new Map(), clock: () => 1000 });
  const first = await geo.resolve(['198.51.100.7', '203.0.113.9']);
  assert.equal(first.size, 2);
  assert.equal(calls, 1);
  // Second call for the same IPs is served from cache — no new fetch.
  const second = await geo.resolve(['198.51.100.7', '203.0.113.9']);
  assert.equal(second.get('203.0.113.9').city, 'Amsterdam');
  assert.equal(calls, 1);
});

test('resolve prefers a local GeoLite2 DB when configured, skipping the network', async () => {
  let netCalls = 0;
  const getJson = async () => { netCalls += 1; return []; };
  const openMmdb = async () => ({
    get: (ip) => (ip === '198.51.100.7'
      ? { location: { latitude: 10, longitude: 20 }, city: { names: { en: 'Localcity' } }, country: { iso_code: 'US' } }
      : null),
  });
  const geo = createIpGeo({ getJson, env: { GEOLITE2_CITY_DB: '/tmp/x.mmdb' }, openMmdb, cache: new Map() });
  const out = await geo.resolve(['198.51.100.7', '192.0.2.4']);
  assert.equal(netCalls, 0); // local DB used, no ip-api call
  assert.deepEqual(out.get('198.51.100.7'), { lat: 10, lon: 20, city: 'Localcity', country: 'US' });
  assert.equal(out.has('192.0.2.4'), false); // not found locally, cached as a miss
});

test('resolve degrades honestly: a failing fetch records an error and returns what it has', async () => {
  const getJson = async () => { throw new Error('rate limited'); };
  const errors = [];
  const geo = createIpGeo({ getJson, env: {}, cache: new Map() });
  const out = await geo.resolve(['198.51.100.7'], errors);
  assert.equal(out.size, 0);
  assert.ok(errors.some((e) => /ip-geo/.test(e)));
});
