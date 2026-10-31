// Run: node --test src/data/hamptonRoadsMaritime.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  shipFamily, zoneFor, severityFor, toItem, buildMaritimePicture, createHamptonRoadsMaritimeFeed,
} from './hamptonRoadsMaritime.js';

// Rows shaped like GEV's /api/vessels output (server/providers/vessels/ais-store.js).
const row = (o) => ({ mmsi: '366999001', name: 'TEST', type: '70', speed: 0, course: 90, heading: 90,
  last_position_UTC: '2026-10-30T22:00:00Z', ...o });

const ROWS = [
  row({ mmsi: '1', name: 'MAERSK KENSINGTON', type: '71', lat: 36.92, lon: -76.33, speed: 0.1 }), // NIT, moored
  row({ mmsi: '2', name: 'STENA IMPERO', type: '80', lat: 36.975, lon: -76.20, speed: 11.2 }),    // tanker in Thimble Shoal
  row({ mmsi: '3', name: 'CG RESPONDER', type: '51', lat: 36.95, lon: -76.32, speed: 18 }),        // SAR at NS Norfolk
  row({ mmsi: '4', name: 'EVER GIVEN', type: '70', lat: 36.99, lon: -76.30, speed: 8 }),           // cargo through HRBT
  row({ mmsi: '5', name: 'WEEKENDER', type: '37', lat: 36.85, lon: -76.30, speed: 6 }),            // pleasure, Elizabeth River
  row({ mmsi: '6', name: 'MSC ALLEGRA', type: '75', lat: 36.88, lon: -76.36, speed: 0 }),          // VIG, moored
  row({ mmsi: '7', name: 'CARNIVAL SUNRISE', type: '60', lat: 36.80, lon: -75.90, speed: 15 }),    // passenger off Cape Henry
  row({ mmsi: '8', name: 'FAR AWAY', type: '70', lat: 40.7, lon: -74.0, speed: 10 }),              // New York — outside
  row({ mmsi: '9', name: '', type: '', lat: 37.2, lon: -76.2, speed: null }),                      // no name/type, lower bay
];

test('ship families follow AIS type codes', () => {
  assert.equal(shipFamily('70'), 'Cargo');
  assert.equal(shipFamily(79), 'Cargo');
  assert.equal(shipFamily('84'), 'Tanker');
  assert.equal(shipFamily('51'), 'Search & rescue');
  assert.equal(shipFamily('35'), 'Military');
  assert.equal(shipFamily(''), 'Unknown');
  assert.equal(shipFamily('abc'), 'Unknown');
});

test('zones resolve specific places before broad water', () => {
  assert.equal(zoneFor(36.92, -76.33).id, 'nit');
  assert.equal(zoneFor(36.95, -76.32).id, 'ns-norfolk');
  assert.equal(zoneFor(36.99, -76.30).id, 'hrbt');
  assert.equal(zoneFor(37.03, -76.08).id, 'cbbt');
  assert.equal(zoneFor(36.975, -76.20).id, 'thimble-shoal');
  assert.equal(zoneFor(36.97, -76.43).id, 'newport-news');
  assert.equal(zoneFor(40.7, -74.0), null);
  assert.equal(zoneFor(NaN, -76.3), null);
});

test('severity ranks responders, then big ships at chokepoints', () => {
  assert.equal(severityFor('Search & rescue', 'harbor', false), 'high');
  assert.equal(severityFor('Tanker', 'cbbt', true), 'medium');
  assert.equal(severityFor('Tanker', 'cbbt', false), 'info');
  assert.equal(severityFor('Cargo', 'cape-henry', true), 'low');
  assert.equal(severityFor('Pleasure craft', 'hrbt', true), 'info');
});

test('items use the normalized panel schema', () => {
  const item = toItem(ROWS[1]);
  assert.deepEqual(Object.keys(item).slice(0, 7), ['lat', 'lng', 'label', 'type', 'source', 'severity', 'timestamp']);
  assert.equal(item.type, 'maritime');
  assert.equal(item.source, 'AISStream');
  assert.equal(item.metadata.zoneName, 'Thimble Shoal Channel');
  assert.match(item.label, /STENA IMPERO — Tanker, underway 11\.2 kn · Thimble Shoal Channel/);
  assert.equal(toItem(ROWS[7]), null);
  assert.equal(toItem(ROWS[8]).metadata.name, 'MMSI 9');
});

test('picture ranks, filters and summarizes', () => {
  const { items, summary } = buildMaritimePicture(ROWS);
  assert.deepEqual(items.map((i) => i.metadata.mmsi), ['3', '2', '4', '7']);
  assert.equal(summary.total, 8);
  assert.equal(summary.underway, 5);
  assert.equal(summary.commercialInPort, 2); // the two moored container ships
  assert.equal(summary.byFamily.Cargo, 3);
  assert.match(summary.headline, /^8 vessels in Hampton Roads waters · 5 underway · 3 cargo, 1 tanker, 1 passenger$/);
  assert.equal(buildMaritimePicture(ROWS, { maxItems: 2 }).items.length, 2);
  assert.deepEqual(buildMaritimePicture(undefined).items, []);
});

function fakeTimers() {
  const pending = [];
  return { pending, setTimer: (fn, ms) => (pending.push({ fn, ms }), pending.length), clearTimer: () => {} };
}
const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

test('poller keeps the last good picture when a poll fails', async () => {
  const updates = [];
  const responses = [json(200, { rows: ROWS, status: 'live' }), new Error('network down'), json(200, { rows: ROWS.slice(0, 2), status: 'live' })];
  const timers = fakeTimers();
  const feed = createHamptonRoadsMaritimeFeed({
    onUpdate: (p) => updates.push(structuredClone(p)),
    fetchImpl: async () => { const r = responses.shift(); if (r instanceof Error) throw r; return r; },
    intervalMs: 1000, ...timers,
  });
  await feed.start();
  assert.equal(updates.at(-1).status, 'live');
  assert.equal(updates.at(-1).items.length, 4);

  await feed.refresh(); // fails
  assert.equal(updates.at(-1).status, 'stale');
  assert.equal(updates.at(-1).items.length, 4, 'last good items are kept');
  assert.match(updates.at(-1).error, /network down/);

  await feed.refresh(); // recovers
  assert.equal(updates.at(-1).status, 'live');
  assert.equal(updates.at(-1).error, null);
  assert.equal(timers.pending[0].ms, 1000);
  feed.stop();
});

test('poller backs off after failures and reports a missing key', async () => {
  const timers = fakeTimers();
  const updates = [];
  const feed = createHamptonRoadsMaritimeFeed({
    onUpdate: (p) => updates.push(p.status),
    fetchImpl: async () => { throw new Error('down'); },
    intervalMs: 1000, ...timers,
  });
  await feed.start();
  assert.deepEqual(updates, ['error']);
  assert.equal(timers.pending[0].ms, 2000, 'first retry backs off');
  feed.stop();

  const keyless = [];
  const f2 = createHamptonRoadsMaritimeFeed({ onUpdate: (p) => keyless.push(p.status), fetchImpl: async () => json(503, {}), ...fakeTimers() });
  await f2.start();
  assert.deepEqual(keyless, ['key-required']);
  f2.stop();
});
