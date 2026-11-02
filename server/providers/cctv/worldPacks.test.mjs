import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WORLD_NETWORKS,
  dget,
  extractRows,
  safeImageUrl,
  worldCameraToSource,
  worldPacks,
} from './worldPacks.js';

const nz = WORLD_NETWORKS.find((n) => n.id === 'nzta');

test('dget walks dotted paths including array indices', () => {
  assert.equal(dget({ a: { b: [{ c: 7 }] } }, 'a.b.0.c'), 7);
  assert.equal(dget({ a: 1 }, 'a.b.c'), undefined);
  assert.equal(dget(null, 'a'), undefined);
});

test('safeImageUrl requires https, no credentials, and an allow-listed host', () => {
  assert.equal(safeImageUrl('https://trafficnz.info/camera/1.jpg?x=1', ['trafficnz.info']), 'https://trafficnz.info/camera/1.jpg?x=1');
  assert.equal(safeImageUrl('https://cams.trafficnz.info/1.jpg', ['trafficnz.info']), 'https://cams.trafficnz.info/1.jpg', 'subdomain ok');
  assert.equal(safeImageUrl('http://trafficnz.info/1.jpg', ['trafficnz.info']), '', 'http refused');
  assert.equal(safeImageUrl('https://user:pw@trafficnz.info/1.jpg', ['trafficnz.info']), '', 'credentials refused');
  assert.equal(safeImageUrl('https://evil.example/1.jpg', ['trafficnz.info']), '', 'off-list host refused');
  assert.equal(safeImageUrl('https://trafficnz.info.evil.com/1.jpg', ['trafficnz.info']), '', 'suffix spoof refused');
  assert.equal(safeImageUrl('not a url', ['trafficnz.info']), '');
});

test('extractRows reads array, arrayPath and geojson shapes', () => {
  assert.deepEqual(extractRows({ response: { cameras: { camera: [1, 2] } } }, nz), [1, 2]);
  assert.deepEqual(extractRows({ features: [{ a: 1 }] }, { shape: 'geojson' }), [{ a: 1 }]);
  assert.deepEqual(extractRows([{ a: 1 }], { shape: 'array' }), [{ a: 1 }]);
});

test('an array-shape record becomes a safe source; bad ones are dropped', () => {
  const good = worldCameraToSource(
    { id: 'AKL07', name: 'SH1 Newmarket', description: 'Northbound', lat: -36.87, long: 174.77, imageUrl: 'https://trafficnz.info/camera/akl07.jpg' },
    nz,
  );
  assert.equal(good.id, 'nzta-akl07');
  assert.equal(good.city, 'New Zealand');
  assert.equal(good.feedType, 'image');
  assert.equal(good.url, 'https://trafficnz.info/camera/akl07.jpg');
  assert.match(good.name, /SH1 Newmarket/);
  // Out of country bounds.
  assert.equal(worldCameraToSource({ id: 'X', lat: 51.5, long: -0.1, imageUrl: 'https://trafficnz.info/x.jpg' }, nz), null);
  // Off-list image host.
  assert.equal(worldCameraToSource({ id: 'X', lat: -36.8, long: 174.7, imageUrl: 'https://evil.example/x.jpg' }, nz), null);
  // Missing id.
  assert.equal(worldCameraToSource({ lat: -36.8, long: 174.7, imageUrl: 'https://trafficnz.info/x.jpg' }, nz), null);
});

test('a geojson record uses its geometry and an id template', () => {
  const net = {
    id: 'demo',
    label: 'Demo',
    cityId: 'demo',
    provider: 'Demo Agency',
    shape: 'geojson',
    idField: 'cam',
    nameFields: ['name'],
    imageTemplate: 'https://cams.demo.gov/{id}/snap.jpg',
    imageHosts: ['demo.gov'],
    bounds: { latMin: 0, latMax: 60, lonMin: -10, lonMax: 10 },
    license: 'Demo open data',
  };
  const cam = worldCameraToSource({ geometry: { coordinates: [2.3, 48.8] }, properties: { cam: 'A-12', name: 'Rue X' } }, net);
  assert.equal(cam.id, 'demo-a-12');
  assert.equal(cam.url, 'https://cams.demo.gov/A-12/snap.jpg', 'template keeps the raw id, host validated');
});

test('every network is well-formed and packs gate by env correctly', () => {
  for (const n of WORLD_NETWORKS) {
    assert.ok(n.id && n.label && n.cityId && n.provider && n.license, n.id);
    assert.ok(Array.isArray(n.imageHosts) && n.imageHosts.length, n.id);
    assert.ok(n.url.startsWith('https://'), n.id);
    assert.ok(n.defaultOn || n.optIn, `${n.id} must declare defaultOn or optIn`);
  }
  const packs = worldPacks();
  const nzPack = packs.find((p) => p.name === 'nzta');
  const irePack = packs.find((p) => p.name === 'ireland');
  const prev = { ...process.env };
  try {
    delete process.env.CCTV_NZTA_ENABLED;
    delete process.env.CCTV_IRELAND_ENABLED;
    assert.equal(nzPack.enabled(), true, 'open-licence pack on by default');
    assert.equal(irePack.enabled(), false, 'opt-in pack off by default');
    process.env.CCTV_NZTA_ENABLED = '0';
    assert.equal(nzPack.enabled(), false, 'kill switch disables an on pack');
    process.env.CCTV_IRELAND_ENABLED = '1';
    assert.equal(irePack.enabled(), true, 'opt-in flag enables');
  } finally {
    for (const k of ['CCTV_NZTA_ENABLED', 'CCTV_IRELAND_ENABLED']) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
});

import { TRAVELIQ_NETWORKS, travelIqCameraToSource, travelIqPacks } from './worldPacks.js';

const va = TRAVELIQ_NETWORKS.find((n) => n.id === 'virginia');

test('a TravelIQ camera becomes a source from its first allowed, enabled view', () => {
  const cam = {
    Id: 1234,
    Location: 'I-64 at Mallory St',
    Roadway: 'I-64',
    Direction: 'Eastbound',
    Latitude: 36.99,
    Longitude: -76.33,
    Views: [
      { Id: 1, Status: 'Disabled', Url: 'https://www.nvroads.com/map/Cctv/1' },
      { Id: 2, Status: 'Enabled', Url: 'https://www.nvroads.com/map/Cctv/1234' },
    ],
  };
  const s = travelIqCameraToSource(cam, va);
  assert.equal(s.id, 'virginia-1234');
  assert.equal(s.city, 'Virginia (VDOT 511)');
  assert.equal(s.url, 'https://www.nvroads.com/map/Cctv/1234');
  assert.match(s.name, /I-64 at Mallory St · I-64 · Eastbound/);
  // Off-list image host is refused even if the camera is in-bounds.
  assert.equal(travelIqCameraToSource({ ...cam, Views: [{ Status: 'Enabled', Url: 'https://evil.example/x.jpg' }] }, va), null);
  // Out-of-state is dropped.
  assert.equal(travelIqCameraToSource({ ...cam, Latitude: 33.4, Longitude: -112 }, va), null);
  // No usable view.
  assert.equal(travelIqCameraToSource({ ...cam, Views: [] }, va), null);
});

test('TravelIQ packs are BYOK: off with no key, on when the key is set, kill switch wins', () => {
  const vaPack = travelIqPacks().find((p) => p.name === 'virginia');
  const prev = { ...process.env };
  try {
    delete process.env.CCTV_VIRGINIA_KEY;
    delete process.env.CCTV_VIRGINIA_ENABLED;
    assert.equal(vaPack.enabled(), false, 'no key → no request');
    process.env.CCTV_VIRGINIA_KEY = 'demo-key';
    assert.equal(vaPack.enabled(), true, 'key present → enabled');
    process.env.CCTV_VIRGINIA_ENABLED = '0';
    assert.equal(vaPack.enabled(), false, 'kill switch overrides a present key');
  } finally {
    for (const k of ['CCTV_VIRGINIA_KEY', 'CCTV_VIRGINIA_ENABLED']) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
  for (const n of TRAVELIQ_NETWORKS) {
    assert.ok(n.url.startsWith('https://') && n.url.endsWith('/api/v2/get/cameras'), n.id);
    assert.ok(n.imageHosts.length && n.bounds && n.license, n.id);
  }
});
