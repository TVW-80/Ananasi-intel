// Run: node --test integrations/osm-buildings/osmBuildings.test.mjs
// Optional real-CesiumJS style check: CESIUM_DIR=/path/with/node_modules node --test ...
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  OSM_BUILDINGS_ASSET_ID, addOsmBuildings, addOsmBuildingsIfNeeded, removeOsmBuildings, anansiBuildingStyle,
} from './osmBuildings.js';

function fakeCesium() {
  const calls = {};
  return {
    calls,
    IonResource: { fromAssetId: async (id, opts) => ((calls.ion = { id, opts }), { url: `ion://${id}` }) },
    Cesium3DTileset: { fromUrl: async (res, opts) => ((calls.tileset = { res, opts }), { kind: 'tileset' }) },
    Cesium3DTileStyle: class { constructor(spec) { this.spec = spec; } },
  };
}
function fakeViewer() {
  const list = [];
  return { list, scene: { primitives: { add: (p) => list.push(p), contains: (p) => list.includes(p), remove: (p) => list.splice(list.indexOf(p), 1) } } };
}

test('adds the ion OSM Buildings asset with a per-resource token', async () => {
  const C = fakeCesium();
  const viewer = fakeViewer();
  const tileset = await addOsmBuildings(viewer, C, { ionToken: ' abc ' });
  assert.equal(C.calls.ion.id, OSM_BUILDINGS_ASSET_ID);
  assert.deepEqual(C.calls.ion.opts, { accessToken: 'abc' });
  assert.equal(viewer.list[0], tileset);
  assert.ok(tileset.style.spec.color.conditions.length === 4, 'Anansi style applied');
  removeOsmBuildings(viewer, tileset);
  assert.equal(viewer.list.length, 0);
});

test('requires a token, and can keep Cesium default styling', async () => {
  await assert.rejects(addOsmBuildings(fakeViewer(), fakeCesium(), {}), /ion token/);
  const t = await addOsmBuildings(fakeViewer(), fakeCesium(), { ionToken: 'x', anansiStyle: false });
  assert.equal(t.style, undefined);
});

test('only adds buildings when Google 3D is not on screen', async () => {
  for (const route of ['google-direct', 'google-token', 'google-ion']) {
    assert.equal(await addOsmBuildingsIfNeeded(fakeViewer(), fakeCesium(), { route, ionToken: 'x' }), null, route);
  }
  assert.equal(await addOsmBuildingsIfNeeded(fakeViewer(), fakeCesium(), { route: 'osm' }), null, 'no token → skip quietly');
  const v = fakeViewer();
  assert.ok(await addOsmBuildingsIfNeeded(v, fakeCesium(), { route: 'osm', ionToken: 'x' }));
  assert.equal(v.list.length, 1);
});

test('style compiles and colors by height in real CesiumJS', { skip: !process.env.CESIUM_DIR && 'set CESIUM_DIR to run' }, () => {
  const Cesium = createRequire(`${process.env.CESIUM_DIR}/`)('cesium');
  const style = anansiBuildingStyle(Cesium);
  const feat = (h) => ({ getPropertyInherited: (n) => (n === 'cesium#estimatedHeight' ? h : undefined), getProperty: () => h });
  const hex = (h) => style.color.evaluateColor(feat(h), new Cesium.Color()).toCssHexString().slice(0, 7);
  assert.equal(hex(5), '#1c1c1c');
  assert.equal(hex(30), '#5a4a1c');
  assert.equal(hex(80), '#d4af37');
  assert.equal(hex(150), '#f4cf5e');
  assert.equal(hex(undefined), '#1c1c1c', 'missing height does not throw');
});
