// Run: node --test integrations/vdot-511/vdotWorkZones.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { normalizeWzdx } from './vdotWorkZones.js';
import { CODE_NODE_JS, workflow } from './build-n8n.mjs';

const NOW = '2026-10-30T15:00:00Z';

// WZDx v4 WorkZoneRoadEvent features, shaped like the spec's examples.
const feature = (id, roads, dir, impact, coords, extra = {}) => ({
  id,
  type: 'Feature',
  properties: {
    core_details: { event_type: 'work-zone', data_source_id: 'vdot', road_names: roads, direction: dir,
      description: `${roads[0]} work`, update_date: '2026-10-30T12:00:00Z' },
    start_date: '2026-10-29T00:00:00Z',
    end_date: '2026-11-15T00:00:00Z',
    location_method: 'channel-device-method',
    is_start_date_verified: true,
    is_end_date_verified: false,
    is_start_position_verified: false,
    is_end_position_verified: false,
    vehicle_impact: impact,
    ...extra,
  },
  geometry: { type: 'LineString', coordinates: coords },
});

const FEED = {
  feed_info: { update_date: '2026-10-30T14:55:00Z', publisher: 'VDOT', version: '4.2', data_sources: [] },
  type: 'FeatureCollection',
  features: [
    feature('hrbt-lane', ['I-64'], 'eastbound', 'some-lanes-closed', [[-76.31, 36.985], [-76.30, 36.99]]),
    feature('i264-full', ['I-264'], 'westbound', 'all-lanes-closed', [[-76.10, 36.84], [-76.12, 36.84]],
      { beginning_cross_street: 'Lynnhaven Pkwy', ending_cross_street: 'Rosemont Rd' }),
    feature('shift', ['VA-168'], 'southbound', 'all-lanes-open-shift-left', [[-76.24, 36.70], [-76.24, 36.69]]),
    feature('mmmbt-shift', ['I-664'], 'northbound', 'all-lanes-open-shift-right', [[-76.40, 36.93], [-76.40, 36.94]], { reduced_speed_limit_kph: 72.4 }),
    feature('richmond', ['I-95'], 'northbound', 'all-lanes-closed', [[-77.43, 37.54], [-77.43, 37.55]]),       // outside region
    feature('future', ['I-64'], 'westbound', 'all-lanes-closed', [[-76.6, 37.2], [-76.61, 37.21]], { start_date: '2026-11-20T00:00:00Z', end_date: '2026-11-21T00:00:00Z' }),
    feature('ended', ['US-17'], 'northbound', 'some-lanes-closed', [[-76.47, 36.98]], { end_date: '2026-10-01T00:00:00Z' }),
    { id: 'detour', type: 'Feature', properties: { core_details: { event_type: 'detour', road_names: ['US-60'] } }, geometry: { type: 'LineString', coordinates: [[-76.5, 37.0]] } },
  ],
};

test('keeps active Hampton Roads work zones and ranks crossings first', () => {
  const { items, summary } = normalizeWzdx(FEED, { now: NOW });
  assert.deepEqual(items.map((i) => i.metadata.id), ['hrbt-lane', 'i264-full', 'mmmbt-shift', 'shift']);
  assert.equal(summary.active, 4);
  assert.equal(summary.closures, 1);
  assert.equal(summary.skippedOutside, 1);
  assert.equal(summary.skippedInactive, 2);
  assert.deepEqual(summary.crossingsAffected, ['Hampton Roads Bridge-Tunnel (I-64)', 'Monitor-Merrimac Bridge-Tunnel (I-664)']);
  assert.equal(summary.feedUpdated, '2026-10-30T14:55:00Z');
});

test('severity: closures and crossing restrictions are high', () => {
  const by = Object.fromEntries(normalizeWzdx(FEED, { now: NOW }).items.map((i) => [i.metadata.id, i]));
  assert.equal(by['hrbt-lane'].severity, 'high');   // lane closure at a tunnel
  assert.equal(by['i264-full'].severity, 'high');   // full closure anywhere
  assert.equal(by['mmmbt-shift'].severity, 'medium'); // shift at a crossing
  assert.equal(by['shift'].severity, 'low');
});

test('items follow the panel schema with readable labels', () => {
  const [hrbt, i264] = normalizeWzdx(FEED, { now: NOW }).items;
  assert.equal(hrbt.type, 'roadwork');
  assert.equal(hrbt.source, 'VDOT 511 (SmarterRoads WZDx)');
  assert.equal(hrbt.label, 'I-64 EB — lane closure · Hampton Roads Bridge-Tunnel (I-64)');
  assert.equal(i264.label, 'I-264 WB — all lanes closed · Lynnhaven Pkwy to Rosemont Rd');
  assert.ok(hrbt.lat > 36.9 && hrbt.lng < -76.2, 'GeoJSON [lng, lat] order is handled');
  const mmmbt = normalizeWzdx(FEED, { now: NOW }).items[2];
  assert.equal(mmmbt.metadata.reducedSpeedMph, 45);
});

test('tolerates empty or malformed feeds', () => {
  assert.equal(normalizeWzdx(null).items.length, 0);
  assert.equal(normalizeWzdx({ features: [{}, { properties: {} }, { properties: { core_details: {} }, geometry: { type: 'Point', coordinates: ['x', 1] } }] }).items.length, 0);
});

test('the official WZDx example feeds parse (relocated into Hampton Roads)', () => {
  const dir = process.env.WZDX_EXAMPLES;
  if (!dir) return; // optional: point at a clone of usdot-jpo-ode/wzdx/examples/WorkZoneFeed
  for (const name of ['scenario1_simple_linestring_example', 'scenario6_multi_lane_closure_linestring_example', 'scenario1_simple_multipoint_example']) {
    const feed = JSON.parse(readFileSync(`${dir}/${name}.geojson`, 'utf8'));
    const [x0, y0] = feed.features[0].geometry.coordinates[0];
    for (const f of feed.features) {
      const shift = (c) => [c[0] - x0 + -76.30, c[1] - y0 + 36.985]; // move the feed from Iowa onto the HRBT
      f.geometry.coordinates = f.geometry.coordinates.map(shift);
      f.properties.start_date = '2026-10-01T00:00:00Z';
      f.properties.end_date = '2026-12-01T00:00:00Z';
    }
    const out = normalizeWzdx(feed, { now: NOW });
    assert.ok(out.items.length >= 1, name);
    assert.equal(out.items[0].metadata.crossing, 'hrbt', name);
  }
});

test('generated n8n Code node runs the same normalizer', async () => {
  const run = async (input) => {
    const ctx = { $input: { first: () => ({ json: input }) } };
    return vm.runInNewContext(`(async () => { ${CODE_NODE_JS} })()`, ctx);
  };
  const ok = await run(FEED);
  // Default "now" is the real clock; just check shape and the error flag.
  assert.equal(ok[0].json.error, null);
  assert.ok(Array.isArray(ok[0].json.items));
  const failed = await run({ error: { message: '401 - invalid token' } });
  assert.equal(failed[0].json.items.length, 0);
  assert.match(failed[0].json.error, /invalid token/);
  // Workflow wiring
  assert.deepEqual(workflow.nodes.map((n) => n.name), ['Webhook', 'VDOT WZDx feed', 'Normalize to panel items', 'Respond']);
  assert.equal(workflow.nodes[1].onError, 'continueRegularOutput');
  assert.equal(workflow.nodes[2].alwaysOutputData, true);
});
