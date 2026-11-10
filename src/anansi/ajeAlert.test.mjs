import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AJE,
  WILLIAMSBURG,
  compass,
  compassWords,
  starAltAz,
  scanWindows,
  isVisible,
  describeStatus,
} from './ajeAlert.js';

// Always-dark and always-day Sun stubs, so the star geometry is tested without
// pulling in astronomy-engine's Sun model.
const DARK = () => -30;
const DAY = () => 10;

test('AJE carries the deed values in both hours and degrees', () => {
  assert.ok(Math.abs(AJE.raDeg - 319.3155) < 0.01);
  assert.ok(Math.abs(AJE.decDeg - -4.9581) < 0.01);
  assert.equal(AJE.magnitude, 10.217);
});

test('compass and compassWords map azimuth to a direction', () => {
  assert.equal(compass(0), 'N');
  assert.equal(compass(90), 'E');
  assert.equal(compass(180), 'S');
  assert.equal(compass(270), 'W');
  assert.equal(compass(206), 'SSW');
  assert.equal(compassWords(206), 'south-southwest');
});

test('starAltAz transits due south at the textbook culmination altitude', () => {
  // A star culminates at 90 − |lat − dec|, due south when dec < lat.
  const expected = 90 - Math.abs(WILLIAMSBURG.lat - AJE.decDeg); // ≈ 47.77°
  // Sweep a full day and take the highest point — that is the transit.
  let best = { altitude: -90, azimuth: 0 };
  const start = Date.UTC(2026, 10, 10, 0, 0, 0);
  for (let m = 0; m < 24 * 60; m += 2) {
    const h = starAltAz(new Date(start + m * 60000));
    if (h.altitude > best.altitude) best = h;
  }
  assert.ok(Math.abs(best.altitude - expected) < 0.2, `peak ${best.altitude} ≈ ${expected}`);
  assert.ok(Math.abs(best.azimuth - 180) < 2, `peak azimuth ${best.azimuth} ≈ due south`);
});

test('starAltAz stays in range across a day', () => {
  const start = Date.UTC(2026, 10, 10, 0, 0, 0);
  for (let m = 0; m < 24 * 60; m += 30) {
    const { altitude, azimuth } = starAltAz(new Date(start + m * 60000));
    assert.ok(altitude >= -90 && altitude <= 90);
    assert.ok(azimuth >= 0 && azimuth < 360.0001);
  }
});

test('scanWindows finds a nightly window whose peak is the transit altitude', () => {
  const from = Date.UTC(2026, 10, 10, 0, 0, 0);
  const windows = scanWindows(from, { sunAltAt: DARK, count: 3, horizonHours: 48 });
  assert.ok(windows.length >= 1, 'at least one window in 48h of darkness');
  for (const w of windows) assert.ok(w.endMs >= w.startMs);
  // The first window may be a partial arc already in progress; a full night's
  // window peaks at the transit altitude (≈47.77°) due south.
  const peak = windows.reduce((a, b) => (b.bestAlt > a.bestAlt ? b : a));
  assert.ok(Math.abs(peak.bestAlt - 47.77) < 0.5, `best alt ${peak.bestAlt} ≈ transit`);
  assert.equal(compass(peak.bestAz), 'S');
});

test('scanWindows returns nothing while the Sun is always up (daytime)', () => {
  const from = Date.UTC(2026, 10, 10, 0, 0, 0);
  assert.deepEqual(scanWindows(from, { sunAltAt: DAY, horizonHours: 48 }), []);
});

test('isVisible needs both a star above the horizon and a dark sky', () => {
  // 2026-11-10 00:21 UTC: Aje is ~44° up from Williamsburg (verified).
  const up = new Date('2026-11-10T00:21:00Z');
  const down = new Date('2026-11-10T12:21:00Z'); // ~12h later, below the horizon
  assert.equal(isVisible(up, { sunAltAt: DARK }), true);
  assert.equal(isVisible(up, { sunAltAt: DAY }), false); // up but bright
  assert.equal(isVisible(down, { sunAltAt: DARK }), false); // dark but below horizon
});

test('describeStatus speaks plainly when Aje is up now', () => {
  const now = new Date('2026-11-10T00:21:00Z').getTime();
  const s = describeStatus(now, { sunAltAt: DARK });
  assert.equal(s.visible, true);
  assert.equal(s.state, 'up');
  assert.match(s.headline, /Aje is up right now/);
  assert.match(s.headline, /above the horizon/);
});

test('describeStatus points to the next window when Aje is not up now', () => {
  const now = new Date('2026-11-10T12:21:00Z').getTime(); // below horizon
  const s = describeStatus(now, { sunAltAt: DARK });
  assert.equal(s.visible, false);
  assert.match(s.headline, /Aje is next in view/);
  assert.match(s.detail, /climbs highest/);
});
