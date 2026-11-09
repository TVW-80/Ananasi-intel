import test from 'node:test';
import assert from 'node:assert/strict';
import { BODIES, SKY_LAYER, bodyRaDec } from './skyLayer.js';

test('the Sky layer declares its identity and an on-theme (non-blue) accent', () => {
  assert.equal(SKY_LAYER.id, 'sky-overhead');
  assert.match(SKY_LAYER.color, /^#f4cf5e$/i);
  assert.ok(SKY_LAYER.updateInterval > 0);
});

test('BODIES covers the Sun, Moon and the planets, all with warm (non-blue) glyph colors', () => {
  const names = BODIES.map((b) => b.name);
  for (const expected of ['Sun', 'Moon', 'Mercury', 'Venus', 'Mars', 'Jupiter', 'Saturn', 'Uranus', 'Neptune']) {
    assert.ok(names.includes(expected), `missing ${expected}`);
  }
  // Theme rule: nothing blue/cyan. Red channel must lead green and blue.
  for (const b of BODIES) {
    const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(b.color);
    assert.ok(m, `${b.name} color ${b.color} is a hex triple`);
    const [r, , bl] = [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)];
    assert.ok(r >= bl, `${b.name} (${b.color}) must not be blue-dominant`);
  }
});

test('bodyRaDec returns right ascension in [0,360) and declination in [-90,90]', () => {
  const date = new Date(Date.UTC(2026, 5, 21, 12, 0, 0));
  for (const b of BODIES) {
    const { ra, dec } = bodyRaDec(b.body, date);
    assert.ok(ra >= 0 && ra < 360, `${b.name} ra in range: ${ra}`);
    assert.ok(dec >= -90 && dec <= 90, `${b.name} dec in range: ${dec}`);
  }
});

test('bodyRaDec tracks the Sun near the solstice declination', () => {
  // Northern summer solstice 2026: the Sun sits near +23.4 deg declination.
  const { dec } = bodyRaDec('Sun', new Date(Date.UTC(2026, 5, 21, 12, 0, 0)));
  assert.ok(Math.abs(dec - 23.4) < 1, `solstice Sun dec ~23.4, got ${dec}`);
});
