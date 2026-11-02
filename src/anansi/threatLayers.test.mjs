import test from 'node:test';
import assert from 'node:assert/strict';
import { THREAT_LAYERS, fetchFeeds, slotPosition } from './threatLayers.js';

test('layer ids are unique and every layer names its feeds and source', () => {
  const ids = THREAT_LAYERS.map((l) => l.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const l of THREAT_LAYERS) assert.ok(l.feeds.length && l.source && l.color && l.updateInterval > 0, l.id);
});

test('country-level points get distinct offsets per layer; exact points stay put', () => {
  const a = slotPosition(37, -95, 0, true);
  const b = slotPosition(37, -95, 2, true);
  assert.notDeepEqual(a, b);
  assert.ok(Math.abs(a.lat - 37) < 2 && Math.abs(b.lat - 37) < 2);
  assert.deepEqual(slotPosition(36.9, -76.2, 3, false), { lat: 36.9, lon: -76.2 });
  const wrapped = slotPosition(10, 179.5, 0, true);
  assert.ok(wrapped.lon <= 180 && wrapped.lon >= -180);
});

test('fetchFeeds merges feeds, dedupes points, and surfaces a missing key only when nothing loaded', async () => {
  const bodies = {
    ioda: { status: 'ok', points: [{ id: 'x' }, { id: 'y' }] },
    'ioda-us': { status: 'ok', points: [{ id: 'y' }, { id: 'z' }] },
    abuseipdb: { status: 'key-required', error: 'Set ABUSEIPDB_API_KEY in .env', points: [] },
  };
  const fetchImpl = async (url) => ({ ok: true, json: async () => bodies[url.split('/').pop().split('?')[0]] });
  const merged = await fetchFeeds(['ioda', 'ioda-us'], { fetchImpl });
  assert.deepEqual(merged.points.map((p) => p.id), ['x', 'y', 'z']);
  assert.equal(merged.error, null);
  const keyed = await fetchFeeds(['abuseipdb'], { fetchImpl });
  assert.equal(keyed.keyRequired, true);
  assert.match(keyed.error, /ABUSEIPDB_API_KEY/);
});

test('keyed Cyber layers name a real POWER UP entry and report it on the row', async () => {
  const { KEY_SETUP_KEYS } = await import('../keySetupCore.mjs');
  const keyed = THREAT_LAYERS.filter((l) => l.keyId);
  assert.deepEqual(keyed.map((l) => l.id).sort(), ['cyber-ics-exposure', 'cyber-outage-reports', 'cyber-reported-attackers', 'exposed-cameras']);
  for (const l of keyed) assert.ok(KEY_SETUP_KEYS.some((k) => k.id === l.keyId && !k.hidden), l.keyId);
});

test('757 focus keeps US entries and points inside Hampton Roads; WORLD keeps everything', async () => {
  const bodies = {
    feodo: { status: 'ok', points: [{ id: 'feodo:US', approximate: true }, { id: 'feodo:DE', approximate: true }] },
    'ioda-us': { status: 'ok', points: [{ id: 'ioda:us-state:VA', approximate: true }] },
    'shodan-ics': { status: 'ok', focused: true, points: [{ id: 'shodan:DE', approximate: true }] },
  };
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    return { ok: true, json: async () => bodies[url.split('/').pop().split('?')[0]] };
  };
  const world = await fetchFeeds(['feodo', 'ioda-us'], { fetchImpl });
  assert.equal(world.points.length, 3);
  const local = await fetchFeeds(['feodo', 'ioda-us'], { fetchImpl, focus: '757' });
  assert.deepEqual(local.points.map((p) => p.id), ['feodo:US', 'ioda:us-state:VA']);
  assert.ok(urls.at(-1).endsWith('?focus=757'));
  const focused = await fetchFeeds(['shodan-ics'], { fetchImpl, focus: '757' });
  assert.equal(focused.points.length, 1, 'server-focused feeds are not filtered twice');
});
