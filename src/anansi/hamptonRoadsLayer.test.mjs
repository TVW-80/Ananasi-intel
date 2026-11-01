import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHamptonRoadsPoints, itemPosition } from './hamptonRoadsLayer.js';

test('positions are read from the shapes n8n and AIS produce', () => {
  assert.deepEqual(itemPosition({ lat: 36.9, lng: -76.2 }), { lat: 36.9, lon: -76.2 });
  assert.deepEqual(itemPosition({ metadata: { latitude: '37.1', longitude: '-76.5' } }), { lat: 37.1, lon: -76.5 });
  assert.deepEqual(itemPosition({ geometry: { type: 'LineString', coordinates: [[-76.3, 36.8], [-76.4, 36.9]] } }), { lat: 36.8, lon: -76.3 });
  assert.equal(itemPosition({ lat: '', lng: '' }), null);
  assert.equal(itemPosition({ lat: 0, lng: 0 }), null);
});

test('located items become points; unlocated news and weather are grouped on anchors', () => {
  const points = buildHamptonRoadsPoints({
    traffic: [{ label: 'Crash I-64 W', lat: 36.95, lng: -76.3, metadata: { from: 'Exit 276', to: 'Exit 272', severity: 4 } }],
    roadwork: [],
    weather: [{ label: 'Small Craft Advisory' }],
    ships: [{ label: 'SAMPLE VESSEL', lat: 36.95, lng: -76.33, metadata: { zone: 'Norfolk Harbor' } }],
    news: [{ label: 'Story one', metadata: { source: 'WJCC' } }, { label: 'Story two' }],
  });
  const byKind = Object.groupBy(points, (p) => p.kind);
  assert.equal(byKind.traffic[0].severity, 1);
  assert.match(byKind.traffic[0].items[0].text, /Exit 276 → Exit 272/);
  assert.equal(byKind.ships.length, 1);
  assert.equal(byKind.news[0].count, 2);
  assert.equal(byKind.news[0].lat, 37.2707);
  assert.equal(byKind.weather[0].title, '1 weather item');
  assert.equal(new Set(points.map((p) => p.id)).size, points.length);
});

test('an empty or missing state draws nothing', () => {
  assert.deepEqual(buildHamptonRoadsPoints({}), []);
  assert.deepEqual(buildHamptonRoadsPoints(null), []);
});
