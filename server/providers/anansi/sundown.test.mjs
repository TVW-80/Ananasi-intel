import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildSundownPoints, evidenceLevel, parseDelimited, readSundownFolder, EVIDENCE } from './sundown.js';

// Synthetic test rows — not real research data.
const CSV = [
  'Town,State,Latitude,Longitude,Status,Notes',
  '"Testville, East",ZZ,40.1,-88.2,surely,"Sample note with ""quotes"""',
  'Sampleton,ZZ,41.0,-87.5,Probable,',
  'Exampleburg,ZZ,,,possible,no coordinates',
  'Nowhere,ZZ,abc,def,unlikely,',
].join('\r\n');

test('evidence levels map common wordings', () => {
  assert.equal(evidenceLevel('Surely'), 'surely');
  assert.equal(evidenceLevel('probably'), 'probable');
  assert.equal(evidenceLevel('Possible'), 'possible');
  assert.equal(evidenceLevel('unlikely'), 'unlikely');
  assert.equal(evidenceLevel("don't know"), 'unrated');
  assert.equal(evidenceLevel(''), 'unrated');
  assert.ok(EVIDENCE.surely.severity > EVIDENCE.possible.severity);
});

test('CSV parsing handles quotes, escaped quotes, CRLF and tabs', () => {
  const rows = parseDelimited(CSV);
  assert.equal(rows.length, 4);
  assert.equal(rows[0].Town, 'Testville, East');
  assert.equal(rows[0].Notes, 'Sample note with "quotes"');
  const tsv = parseDelimited('name\tlat\tlon\nA\t1\t2\n');
  assert.deepEqual(tsv, [{ name: 'A', lat: '1', lon: '2' }]);
});

test('rows with coordinates become colored points ranked by evidence', () => {
  const { points, total, placed, unplaced } = buildSundownPoints([{ name: 'towns.csv', text: CSV }]);
  assert.equal(total, 4);
  assert.equal(placed, 2);
  assert.equal(unplaced, 2);
  assert.deepEqual(points.map((p) => p.title), ['Testville, East', 'Sampleton']);
  assert.equal(points[0].color, EVIDENCE.surely.color);
  assert.equal(points[0].approximate, false);
  assert.ok(points[0].items.some((i) => /not the town today/.test(i.text)));
  assert.ok(points[0].items.some((i) => i.text === 'Sample note with "quotes"'));
});

test('GEOID-only rows are placed through a Census gazetteer file', () => {
  const data = 'GEOID,NAME,STUSPS,certainty\n9900001,Gazville,ZZ,possible\n9900002,Lostville,ZZ,surely\n';
  const gaz = 'USPS\tGEOID\tANSICODE\tNAME\tINTPTLAT\tINTPTLONG\nZZ\t9900001\t000\tGazville city\t38.5\t-90.25\n';
  const { points, unplaced } = buildSundownPoints([
    { name: 'study.csv', text: data },
    { name: '2020_Gaz_place_national.txt', text: gaz },
  ]);
  assert.equal(points.length, 1);
  assert.deepEqual([points[0].lat, points[0].lon, points[0].level], [38.5, -90.25, 'possible']);
  assert.equal(unplaced, 1);
});

test('GeoJSON points are read with their properties', () => {
  const gj = JSON.stringify({ type: 'FeatureCollection', features: [
    { type: 'Feature', geometry: { type: 'Point', coordinates: [-80, 35] }, properties: { name: 'Geoville', state: 'ZZ', status: 'surely', source: 'Test source' } },
    { type: 'Feature', geometry: { type: 'Polygon', coordinates: [] }, properties: {} },
  ] });
  const { points } = buildSundownPoints([{ name: 'towns.geojson', text: gj }]);
  assert.equal(points.length, 1);
  assert.equal(points[0].place, 'Geoville, ZZ');
  assert.ok(points[0].items.some((i) => i.text === 'Source: Test source'));
});

test('folder reader skips README and reports a missing folder', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sundown-'));
  writeFileSync(path.join(dir, 'README.md'), '# notes');
  writeFileSync(path.join(dir, 'towns.csv'), CSV);
  const folder = readSundownFolder(dir);
  assert.deepEqual(folder.files.map((f) => f.name), ['towns.csv']);
  assert.equal(readSundownFolder(path.join(dir, 'nope')).signature, 'missing');
});
