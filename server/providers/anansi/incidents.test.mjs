import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeNwsAlerts,
  normalizeGdeltEvents,
  parseGdeltLinks,
  alertStates,
  nwsAlertsUrl,
  gdeltGeoUrl,
  NORFOLK,
} from './incidents.js';
import { createThreatIntelMiddleware, FEEDS } from './threat-intel.js';

const alert = (over = {}) => ({
  properties: {
    status: 'Actual',
    messageType: 'Alert',
    event: 'Coastal Flood Warning',
    headline: 'Coastal Flood Warning issued October 30 by NWS Wakefield VA',
    severity: 'Moderate',
    urgency: 'Expected',
    areaDesc: 'Norfolk/Portsmouth; Virginia Beach',
    sent: '2026-10-30T12:00:00-04:00',
    geocode: { UGC: ['VAZ095', 'VAZ096'] },
    ...over,
  },
});

test('alertStates reads state codes from UGC and ignores marine zones', () => {
  assert.deepEqual(
    alertStates({
      geocode: { UGC: ['VAZ095', 'NCC073', 'ANZ650', 'VAZ096'] },
    }).sort(),
    ['NC', 'VA'],
  );
  assert.deepEqual(alertStates({}), []);
});

test('NWS alerts group per state, worst severity first, and skip cancels/tests', () => {
  const { points, total } = normalizeNwsAlerts({
    features: [
      alert(),
      alert({
        event: 'Tornado Warning',
        headline: 'Tornado Warning',
        severity: 'Extreme',
        geocode: { UGC: ['VAC710'] },
      }),
      alert({ messageType: 'Cancel' }),
      alert({ status: 'Test' }),
      alert({ geocode: { UGC: ['ANZ650'] } }),
    ],
  });
  assert.equal(total, 2);
  assert.equal(points.length, 1);
  const va = points[0];
  assert.equal(va.id, 'incidents-alerts:VA');
  assert.equal(va.count, 2);
  assert.equal(va.severity, 1);
  assert.equal(va.detail, 'Tornado Warning');
  assert.equal(va.approximate, true);
  assert.equal(va.items[0].text, 'Tornado Warning');
});

test('NWS 757 focus makes one exact point at Norfolk', () => {
  const { points, total } = normalizeNwsAlerts(
    {
      features: [
        alert(),
        alert({
          severity: 'Severe',
          event: 'High Wind Warning',
          headline: 'High Wind Warning',
        }),
      ],
    },
    '757',
  );
  assert.equal(total, 2);
  assert.equal(points.length, 1);
  assert.equal(points[0].lat, NORFOLK.lat);
  assert.equal(points[0].approximate, false);
  assert.equal(points[0].detail, 'High Wind Warning');
  assert.match(points[0].title, /^2 active NWS alerts/);
});

test('NWS handles empty and malformed payloads', () => {
  assert.deepEqual(normalizeNwsAlerts({}), { points: [], total: 0 });
  assert.deepEqual(normalizeNwsAlerts(null, '757'), { points: [], total: 0 });
});

const gdelt = (lon, lat, count, name, html = '') => ({
  type: 'Feature',
  geometry: { type: 'Point', coordinates: [lon, lat] },
  properties: { name, count, html },
});

test('GDELT links parse tolerantly and reject non-http URLs', () => {
  const links = parseGdeltLinks(
    '<a href="https://example.com/a" target="_blank">Fire closes I-64 lanes</a><a href="javascript:alert(1)">bad</a><a href="not a url">worse</a>',
  );
  assert.deepEqual(links, [
    { text: 'Fire closes I-64 lanes', url: 'https://example.com/a' },
  ]);
  assert.deepEqual(parseGdeltLinks(''), []);
});

test('GDELT world focus keeps US clusters; 757 focus keeps only Hampton Roads', () => {
  const payload = {
    features: [
      gdelt(
        -76.29,
        36.85,
        12,
        'Norfolk, Virginia',
        '<a href="https://example.com/n">Crash on Hampton Blvd</a>',
      ),
      gdelt(-97.4, 42.0, 30, 'Norfolk, Nebraska'),
      gdelt(-76.0, 36.8, 3, 'Virginia Beach, Virginia'),
      { geometry: null, properties: {} },
    ],
  };
  const world = normalizeGdeltEvents(payload, 'world');
  assert.equal(world.total, 3);
  assert.equal(world.points[0].place, 'Norfolk, Nebraska'); // sorted by count
  const local = normalizeGdeltEvents(payload, '757');
  assert.deepEqual(
    local.points.map((p) => p.place),
    ['Norfolk, Virginia', 'Virginia Beach, Virginia'],
  );
  assert.equal(local.points[0].title, 'Crash on Hampton Blvd');
  assert.equal(local.points[0].severity, 1);
});

test('request URLs: US-wide vs 757', () => {
  assert.doesNotMatch(nwsAlertsUrl('world'), /point=/);
  assert.match(nwsAlertsUrl('757'), /point=36\.85%2C-76\.29/);
  assert.match(gdeltGeoUrl('world'), /sourcecountry%3AUS/);
  assert.match(gdeltGeoUrl('757'), /Norfolk/);
  assert.match(gdeltGeoUrl('757'), /timespan=48h/);
});

test('incident feeds are keyless, focus-aware, and served through the middleware', async () => {
  for (const name of ['incidents-alerts', 'incidents-news']) {
    assert.equal(FEEDS[name].keyEnv, null);
    assert.equal(FEEDS[name].focusAware, true);
  }
  const seen = [];
  const mw = createThreatIntelMiddleware({
    envSource: {},
    clock: () => 1_000,
    fetchImpl: async (url, init) => {
      seen.push({ url: String(url), accept: init.headers.Accept });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ features: [alert()] }),
      };
    },
  });
  const body = await mw.get('incidents-alerts', '757');
  assert.equal(body.status, 'ok');
  assert.equal(body.focused, true);
  assert.equal(body.points[0].id, 'incidents-alerts:757');
  assert.match(seen[0].url, /api\.weather\.gov\/alerts\/active\?.*point=/);
  assert.equal(seen[0].accept, 'application/geo+json');
});
