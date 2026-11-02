import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTACK_MAP_LAYER, arcColor, arcPoints, counterStart, sourceColor, twoVoice } from './attackMap.js';
import { glyphBadgeImage } from './markerIcons.js';

test('arcs start and end on the ground at the endpoints and bow upward between', () => {
  const src = { lat: 39.9, lon: 116.4 }; // Beijing
  const dst = { lat: 36.85, lon: -76.29 }; // Norfolk
  const pts = arcPoints(src, dst, 32);
  assert.equal(pts.length, 33);
  assert.ok(Math.abs(pts[0].lat - src.lat) < 1e-6 && Math.abs(pts[0].lon - src.lon) < 1e-6);
  assert.ok(Math.abs(pts[32].lat - dst.lat) < 1e-6 && Math.abs(pts[32].lon - dst.lon) < 1e-6);
  assert.ok(pts[0].height < 1e-6 && pts[32].height < 1);
  assert.ok(pts[16].height > 1_000_000 && pts[16].height <= 1_600_000);
  // The great circle Beijing→Norfolk goes over the Arctic, not across the Pacific at 40°N.
  assert.ok(Math.max(...pts.map((p) => p.lat)) > 60);
});

test('short arcs still lift off the ground; identical points do not blow up', () => {
  assert.ok(arcPoints({ lat: 37, lon: -77 }, { lat: 36.85, lon: -76.29 })[32].height >= 120_000 * 0.99);
  assert.ok(arcPoints({ lat: 1, lon: 1 }, { lat: 1, lon: 1 }).every((p) => Number.isFinite(p.lat)));
});

test('color runs gold to red; the counter starts at today’s estimated total', () => {
  assert.equal(arcColor(0), 'rgb(244, 207, 94)');
  assert.equal(arcColor(1), 'rgb(255, 43, 43)');
  assert.equal(counterStart(10, Date.UTC(2026, 10, 1, 1, 30)), 900);
  assert.equal(ATTACK_MAP_LAYER.id, 'cyber-attack-map');
});

test('arcs take the colour of their dominant attack type, else their strength', () => {
  const types = [{ service: 'ssh', color: '#ff2b2b' }];
  assert.equal(sourceColor({ dominantService: 'ssh', weight: 0 }, types), '#ff2b2b');
  assert.equal(sourceColor({ dominantService: 'ftp', weight: 1 }, types), arcColor(1));
  assert.equal(twoVoice('Simple words.', 'Jargon.'), 'Simple words.\nTECH: Jargon.');
});

test('each category gets a distinct glyph badge image, colour baked in', () => {
  const src = glyphBadgeImage('⌖', '#ff2b2b');
  const malware = glyphBadgeImage('☣', '#c04dd8');
  const phish = glyphBadgeImage('✉', '#8fd46b');
  for (const uri of [src, malware, phish]) assert.match(uri, /^data:image\/svg\+xml,/);
  assert.notEqual(src, malware);
  assert.notEqual(malware, phish);
  // The colour is in the SVG, and the same glyph+colour is memoized to one URI.
  assert.ok(decodeURIComponent(malware).includes('%23c04dd8') || decodeURIComponent(malware).includes('#c04dd8'));
  assert.equal(glyphBadgeImage('☣', '#c04dd8'), malware);
});
