import test from 'node:test';
import assert from 'node:assert/strict';
import {
  gmstDeg,
  subPoint,
  splitByAntimeridian,
  starSizePx,
  starAlpha,
} from './skyMath.js';

test('gmstDeg returns an angle in [0,360) and matches a known epoch', () => {
  // J2000.0 (2000-01-01 12:00 UTC): GMST ~= 280.46 deg.
  const g = gmstDeg(new Date(Date.UTC(2000, 0, 1, 12, 0, 0)));
  assert.ok(g >= 0 && g < 360, `in range: ${g}`);
  assert.ok(Math.abs(g - 280.46) < 0.1, `near 280.46, got ${g}`);
});

test('gmstDeg advances ~15.041 deg per hour (sidereal rate)', () => {
  const base = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  const later = new Date(base.getTime() + 3_600_000);
  let d = gmstDeg(later) - gmstDeg(base);
  if (d < 0) d += 360;
  assert.ok(Math.abs(d - 15.0411) < 0.01, `~15.041/hr, got ${d}`);
});

test('subPoint maps declination to latitude and wraps longitude to [-180,180]', () => {
  assert.deepEqual(subPoint(10, 45, 10), { lat: 45, lon: 0 });
  // ra 350, gmst 10 -> 340 -> wraps to -20
  assert.deepEqual(subPoint(350, -12, 10), { lat: -12, lon: -20 });
  // ra 10, gmst 350 -> -340 -> wraps to 20
  assert.deepEqual(subPoint(10, 0, 350), { lat: 0, lon: 20 });
});

test('splitByAntimeridian breaks a path where longitude jumps > 180', () => {
  const path = [
    { lat: 0, lon: 170 },
    { lat: 1, lon: 179 },
    { lat: 2, lon: -179 }, // jump of 358 -> split here
    { lat: 3, lon: -170 },
  ];
  const parts = splitByAntimeridian(path);
  assert.equal(parts.length, 2);
  assert.equal(parts[0].length, 2);
  assert.equal(parts[1].length, 2);
});

test('splitByAntimeridian leaves a continuous path whole and drops lone points', () => {
  const whole = splitByAntimeridian([
    { lat: 0, lon: 10 },
    { lat: 0, lon: 20 },
    { lat: 0, lon: 30 },
  ]);
  assert.equal(whole.length, 1);
  assert.equal(whole[0].length, 3);
  // A run of a single point is not a drawable polyline.
  assert.deepEqual(splitByAntimeridian([{ lat: 0, lon: 0 }]), []);
});

test('starSizePx is larger for brighter (smaller magnitude) stars and is clamped', () => {
  assert.ok(starSizePx(-1.5) > starSizePx(1) && starSizePx(1) > starSizePx(5));
  assert.ok(starSizePx(-10) <= 6.5, 'upper clamp');
  assert.ok(starSizePx(99) >= 1.4, 'lower clamp');
});

test('starAlpha fades faint stars and stays within [0.35,1]', () => {
  assert.ok(starAlpha(0) > starAlpha(5));
  for (const m of [-2, 0, 3, 6, 20]) {
    const a = starAlpha(m);
    assert.ok(a >= 0.35 && a <= 1, `alpha in range for mag ${m}: ${a}`);
  }
});
