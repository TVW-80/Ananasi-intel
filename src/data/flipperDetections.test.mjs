// src/data/flipperDetections.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSqwLine,
  parseSqwStat,
  parseDetectionsCsv,
  parseGpx,
  locateAt,
  detectionsToFeatures,
  featuresToGeoJsonl,
  csvAndGpxToGeoJsonl,
  typeStyle,
  toEpochMs,
} from './flipperDetections.js';

test('parseSqwLine parses a DET line', () => {
  const d = parseSqwLine('SQW,DET,NEW,FLOCK,H,AA:BB:CC:DD:EE:FF,-61,6,3,FlockSafety,');
  assert.equal(d.what, 'NEW');
  assert.equal(d.type, 'FLOCK');
  assert.equal(d.conf, 'H');
  assert.equal(d.mac, 'AA:BB:CC:DD:EE:FF');
  assert.equal(d.rssi, -61);
  assert.equal(d.channel, 6);
  assert.equal(d.hits, 3);
  assert.equal(d.vendor, 'FlockSafety');
  assert.equal(d.tMs, null);
});

test('parseSqwLine keeps an SSID name and ignores non-DET lines', () => {
  const d = parseSqwLine('SQW,DET,NEW,HACKER,H,11:22:33:44:55:66,-40,1,2,Pineapple,Pineapple_test');
  assert.equal(d.name, 'Pineapple_test');
  assert.equal(parseSqwLine('SQW,STAT,12,400,6,1,1,3,0'), null);
  assert.equal(parseSqwLine(''), null);
  assert.equal(parseSqwLine('garbage'), null);
});

test('parseSqwStat parses a STAT line', () => {
  const s = parseSqwStat('SQW,STAT,12,420,6,1,1,3,0');
  assert.deepEqual(s, {
    uptimeSec: 12, framesPerSec: 420, channel: 6,
    hopping: true, running: true, total: 3, dropped: 0,
  });
  assert.equal(parseSqwStat('SQW,DET,NEW,FLOCK,H,x,-1,1,1,v,'), null);
});

test('parseDetectionsCsv reads the capture header layout', () => {
  const csv = [
    'ts,what,type,conf,mac,rssi,channel,hits,vendor,name',
    '2026-10-13T12:00:00.000Z,NEW,FLOCK,H,AA:BB:CC:DD:EE:FF,-61,6,3,FlockSafety,',
    '2026-10-13T12:00:05.000Z,NEW,HACKER,H,11:22:33:44:55:66,-40,1,2,Pineapple,Pineapple_test',
  ].join('\n');
  const rows = parseDetectionsCsv(csv);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].type, 'FLOCK');
  assert.equal(rows[0].tMs, Date.parse('2026-10-13T12:00:00.000Z'));
  assert.equal(rows[1].name, 'Pineapple_test');
});

test('parseDetectionsCsv reads the SquachWatch SD layout (ssid→name)', () => {
  const csv = [
    'ts,type,rssi,mac,channel,vendor,ssid',
    '1760356800,CAMERA,-70,DE:AD:BE:EF:00:01,11,Wyze,',
  ].join('\n');
  const rows = parseDetectionsCsv(csv);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].type, 'CAMERA');
  assert.equal(rows[0].vendor, 'Wyze');
  assert.equal(rows[0].tMs, 1760356800 * 1000); // seconds → ms
});

test('parseDetectionsCsv rejects a file with no known header', () => {
  assert.deepEqual(parseDetectionsCsv('foo,bar\n1,2'), []);
  assert.deepEqual(parseDetectionsCsv(''), []);
});

test('toEpochMs handles seconds, millis, and ISO', () => {
  assert.equal(toEpochMs(1760356800), 1760356800000);
  assert.equal(toEpochMs(1760356800000), 1760356800000);
  assert.equal(toEpochMs('2026-10-13T12:00:00.000Z'), Date.parse('2026-10-13T12:00:00.000Z'));
  assert.equal(toEpochMs(''), null);
  assert.equal(toEpochMs('not a date'), null);
});

test('parseGpx extracts sorted timestamped points', () => {
  const gpx = `<?xml version="1.0"?><gpx><trk><trkseg>
    <trkpt lat="36.85" lon="-76.28"><time>2026-10-13T12:00:04Z</time></trkpt>
    <trkpt lat="36.80" lon="-76.20"><time>2026-10-13T12:00:00Z</time></trkpt>
  </trkseg></trk></gpx>`;
  const pts = parseGpx(gpx);
  assert.equal(pts.length, 2);
  assert.ok(pts[0].tMs < pts[1].tMs, 'sorted ascending');
  assert.equal(pts[0].lat, 36.80);
  assert.equal(pts[1].lon, -76.28);
});

test('locateAt nearest-matches within the gap and drops beyond it', () => {
  const track = [
    { tMs: 1000, lat: 1, lon: 1 },
    { tMs: 5000, lat: 2, lon: 2 },
    { tMs: 9000, lat: 3, lon: 3 },
  ];
  assert.deepEqual(locateAt(5200, track), { lat: 2, lon: 2 });
  assert.deepEqual(locateAt(900, track), { lat: 1, lon: 1 });
  assert.equal(locateAt(100000, track, 1000), null); // beyond gap
  assert.equal(locateAt(null, track), null);
  assert.equal(locateAt(1000, []), null);
});

test('detectionsToFeatures joins to a track and counts drops', () => {
  const dets = [
    { type: 'FLOCK', vendor: 'FlockSafety', mac: 'AA', rssi: -61, channel: 6, conf: 'H', hits: 1, name: '', tMs: 1400 },
    { type: 'CAMERA', vendor: 'Wyze', mac: 'BB', rssi: -70, channel: 11, conf: 'H', hits: 1, name: '', tMs: 999999 },
  ];
  const track = [{ tMs: 1000, lat: 36.8, lon: -76.2 }, { tMs: 3000, lat: 36.9, lon: -76.3 }];
  const { features, located, dropped } = detectionsToFeatures(dets, { track, maxGapMs: 2000 });
  assert.equal(located, 1);
  assert.equal(dropped, 1);
  assert.equal(features.length, 1);
  assert.equal(features[0].geometry.type, 'Point');
  assert.equal(features[0].properties.detType, 'FLOCK');
  assert.equal(features[0].properties.color, typeStyle('FLOCK').color);
  // nearest track point to t=1400 is t=1000 → [lon, lat]
  assert.deepEqual(features[0].geometry.coordinates, [-76.2, 36.8]);
});

test('detectionsToFeatures fallback places otherwise-unlocatable detections', () => {
  const dets = [{ type: 'HACKER', vendor: '', mac: 'CC', rssi: -40, channel: 1, conf: 'H', hits: 1, name: 'Pineapple_test', tMs: null }];
  const { features, located } = detectionsToFeatures(dets, { track: [], fallback: { lat: 36.85, lon: -76.28 } });
  assert.equal(located, 1);
  assert.deepEqual(features[0].geometry.coordinates, [-76.28, 36.85]);
});

test('featuresToGeoJsonl emits one valid Feature per line', () => {
  const dets = parseDetectionsCsv([
    'ts,type,rssi,mac,channel,vendor,ssid',
    '2000,FLOCK,-61,AA,6,FlockSafety,',
  ].join('\n'));
  const { features } = detectionsToFeatures(dets, { fallback: { lat: 1, lon: 2 } });
  const jsonl = featuresToGeoJsonl(features);
  const lines = jsonl.split('\n');
  assert.equal(lines.length, 1);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.type, 'Feature');
  assert.equal(parsed.properties.detType, 'FLOCK');
});

test('csvAndGpxToGeoJsonl end-to-end', () => {
  const csv = [
    'ts,type,rssi,mac,channel,vendor,ssid',
    '2026-10-13T12:00:01Z,FLOCK,-61,AA:BB:CC:DD:EE:FF,6,FlockSafety,',
  ].join('\n');
  const gpx = `<gpx><trkpt lat="36.85" lon="-76.28"><time>2026-10-13T12:00:00Z</time></trkpt></gpx>`;
  const jsonl = csvAndGpxToGeoJsonl(csv, gpx, { maxGapMs: 5000 });
  const feat = JSON.parse(jsonl);
  assert.equal(feat.geometry.coordinates[0], -76.28);
  assert.equal(feat.geometry.coordinates[1], 36.85);
  assert.equal(feat.properties.detType, 'FLOCK');
});
