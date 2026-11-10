/**
 * Ananzi "AJE WATCH": a special, personal alert for one named star.
 *
 * Aje is a star named on a Star Name Deed (designation 6500814, in Aquarius,
 * named 17 March 2022). This module works out when Aje's patch of sky is above
 * the horizon in darkness as seen from Williamsburg, Virginia, and shows a
 * standing card that says — in plain words — whether it's up right now or when
 * the next good viewing window is.
 *
 * The star's altitude/azimuth are computed here with a plain spherical-astronomy
 * formula (validated against astronomy-engine to ~0.5°, the horizon-refraction
 * difference), so the core is pure and unit-tested in ajeAlert.test.mjs.
 * astronomy-engine is used only for the Sun, to tell day from night.
 *
 * Honest note carried in the card: at magnitude 10.2 Aje is far too faint for
 * the naked eye or binoculars. The alert tells you when to aim a telescope at
 * its spot — or simply when to look that way and know it is there.
 */
import * as Astronomy from 'astronomy-engine';
import { gmstDeg } from './skyMath.js';

/** The named star, from the deed. */
export const AJE = Object.freeze({
  name: 'Aje',
  designation: '6500814 — Aquarius',
  named: '17 March 2022',
  raHours: 21 + 17 / 60 + 15.72 / 3600,
  raDeg: (21 + 17 / 60 + 15.72 / 3600) * 15, // 319.3155°
  decDeg: -(4 + 57 / 60 + 29.16 / 3600), // -4.9581°
  magnitude: 10.217,
  raText: '21h 17m 15.72s',
  decText: '-4° 57′ 29.16″',
});

/** The observer: home base. */
export const WILLIAMSBURG = Object.freeze({
  name: 'Williamsburg, VA',
  lat: 37.2707,
  lon: -76.7074,
  elevM: 12,
});

// A star this low is lost in trees and haze; the sky this bright isn't dark yet.
export const MIN_ALT_DEG = 10;
export const DARK_SUN_DEG = -12; // nautical twilight — "dark enough to look"

const D2R = Math.PI / 180;
const R2D = 180 / Math.PI;
const COMPASS_16 = [
  'N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
  'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW',
];

/** 16-point compass label for an azimuth in degrees (0 = due north). */
export function compass(azDeg) {
  return COMPASS_16[Math.round((((azDeg % 360) + 360) % 360) / 22.5) % 16];
}

/** Spoken direction, e.g. "south-southwest". */
export function compassWords(azDeg) {
  const map = {
    N: 'north', NNE: 'north-northeast', NE: 'northeast', ENE: 'east-northeast',
    E: 'east', ESE: 'east-southeast', SE: 'southeast', SSE: 'south-southeast',
    S: 'south', SSW: 'south-southwest', SW: 'southwest', WSW: 'west-southwest',
    W: 'west', WNW: 'west-northwest', NW: 'northwest', NNW: 'north-northwest',
  };
  return map[compass(azDeg)];
}

/**
 * The star's altitude (degrees above the horizon) and azimuth (degrees from
 * north, clockwise) for a date, from a fixed site. Airless geometric altitude.
 */
export function starAltAz(date, site = WILLIAMSBURG, star = AJE) {
  const lst = (gmstDeg(date) + site.lon) % 360;
  let h = (((lst - star.raDeg) % 360) + 360) % 360;
  if (h > 180) h -= 360; // hour angle, −180..180
  const hr = h * D2R;
  const phi = site.lat * D2R;
  const dec = star.decDeg * D2R;
  const sinAlt =
    Math.sin(dec) * Math.sin(phi) +
    Math.cos(dec) * Math.cos(phi) * Math.cos(hr);
  const alt = Math.asin(Math.max(-1, Math.min(1, sinAlt)));
  let cosA =
    (Math.sin(dec) - sinAlt * Math.sin(phi)) /
    (Math.cos(alt) * Math.cos(phi));
  cosA = Math.max(-1, Math.min(1, cosA));
  let az = Math.acos(cosA) * R2D;
  if (Math.sin(hr) > 0) az = 360 - az;
  return { altitude: alt * R2D, azimuth: az };
}

/** The Sun's altitude in degrees (uses astronomy-engine). */
export function sunAltitude(date, site = WILLIAMSBURG, Astro = Astronomy) {
  const observer = new Astro.Observer(site.lat, site.lon, site.elevM);
  const eq = Astro.Equator(Astro.Body.Sun, date, observer, true, true);
  return Astro.Horizon(date, observer, eq.ra, eq.dec, 'normal').altitude;
}

/**
 * Scan forward from `fromMs` and return the visibility windows (star above
 * MIN_ALT_DEG while the Sun is below DARK_SUN_DEG). If the star is already
 * visible at `fromMs`, the first window starts at `fromMs`. `sunAltAt` is
 * injectable so the scan is testable without astronomy-engine.
 * @returns {{startMs:number,endMs:number,bestMs:number,bestAlt:number,bestAz:number}[]}
 */
export function scanWindows(
  fromMs,
  {
    count = 3,
    stepMinutes = 10,
    horizonHours = 24 * 7,
    site = WILLIAMSBURG,
    star = AJE,
    minAlt = MIN_ALT_DEG,
    darkSun = DARK_SUN_DEG,
    sunAltAt = (ms) => sunAltitude(new Date(ms), site),
  } = {},
) {
  const stepMs = stepMinutes * 60_000;
  const endScan = fromMs + horizonHours * 3_600_000;
  const windows = [];
  let cur = null;
  for (let ms = fromMs; ms <= endScan && windows.length < count; ms += stepMs) {
    const { altitude, azimuth } = starAltAz(new Date(ms), site, star);
    const visible = altitude >= minAlt && sunAltAt(ms) <= darkSun;
    if (visible) {
      if (!cur) cur = { startMs: ms, endMs: ms, bestMs: ms, bestAlt: altitude, bestAz: azimuth };
      cur.endMs = ms;
      if (altitude > cur.bestAlt) {
        cur.bestAlt = altitude;
        cur.bestAz = azimuth;
        cur.bestMs = ms;
      }
    } else if (cur) {
      windows.push(cur);
      cur = null;
    }
  }
  if (cur && windows.length < count) windows.push(cur);
  return windows;
}

/** True when Aje is above the horizon and the sky is dark, at `date`. */
export function isVisible(date, opts = {}) {
  const site = opts.site || WILLIAMSBURG;
  const { altitude } = starAltAz(date, site, opts.star || AJE);
  const sun = (opts.sunAltAt || ((ms) => sunAltitude(new Date(ms), site)))(
    date.getTime(),
  );
  return (
    altitude >= (opts.minAlt ?? MIN_ALT_DEG) &&
    sun <= (opts.darkSun ?? DARK_SUN_DEG)
  );
}

/* ── Plain-English status ──────────────────────────────────────────────────── */

function fmtDay(ms, now) {
  const d = new Date(ms);
  const today = new Date(now);
  const sameDay = d.toDateString() === today.toDateString();
  const tomorrow = new Date(now + 86_400_000).toDateString() === d.toDateString();
  if (sameDay) return 'tonight';
  if (tomorrow) return 'tomorrow night';
  try {
    return `on ${d.toLocaleDateString(undefined, { weekday: 'long' })}`;
  } catch {
    return 'soon';
  }
}

function fmtTime(ms) {
  try {
    return new Date(ms).toLocaleTimeString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    });
  } catch {
    return new Date(ms).toISOString();
  }
}

/**
 * A plain, high-school-level status for the card.
 * @returns {{visible:boolean, state:'up'|'later'|'none', headline:string, detail:string, altitude?:number, azimuth?:number}}
 */
export function describeStatus(nowMs, opts = {}) {
  const site = opts.site || WILLIAMSBURG;
  const star = opts.star || AJE;
  const now = new Date(nowMs);
  const { altitude, azimuth } = starAltAz(now, site, star);
  const visibleNow = isVisible(now, opts);
  const windows = scanWindows(nowMs, { ...opts, site, star, count: 2 });

  if (visibleNow) {
    const end = windows[0]?.endMs;
    const dirn = compassWords(azimuth);
    return {
      visible: true,
      state: 'up',
      altitude,
      azimuth,
      headline: `Aje is up right now — look ${dirn}, about ${Math.round(altitude)}° above the horizon.`,
      detail: end
        ? `Its spot stays in the dark until about ${fmtTime(end)}.`
        : 'Its spot is in the dark sky now.',
    };
  }

  const w = windows.find((win) => win.startMs > nowMs) || windows[0];
  if (!w) {
    return {
      visible: false,
      state: 'none',
      headline: `Aje doesn't climb into the dark sky over Williamsburg in the next week.`,
      detail: `It will come back around as the seasons turn.`,
    };
  }
  const dirn = compassWords(w.bestAz);
  return {
    visible: false,
    state: 'later',
    headline: `Aje is next in view ${fmtDay(w.startMs, nowMs)} from about ${fmtTime(w.startMs)}.`,
    detail: `It climbs highest around ${fmtTime(w.bestMs)} — roughly ${Math.round(w.bestAlt)}° up in the ${dirn}.`,
  };
}

/** The honest faintness note, shown once in the card. */
export const FAINTNESS_NOTE =
  'At magnitude 10.2, Aje is far too faint for the eye or binoculars — this tells you when its patch of sky is up in the dark, where to aim a telescope, or simply where to look and know it’s there.';

/* ── DOM card ────────────────────────────────────────────────────────────── */

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/**
 * The standing "Aje watch" card. `now` and `sunAltAt` are injectable for tests.
 */
export function createAjeAlert(
  doc = document,
  { now = () => Date.now(), sunAltAt, site = WILLIAMSBURG, star = AJE } = {},
) {
  const panel = el(doc, 'section', 'aje-alert');
  panel.setAttribute('role', 'status');
  panel.setAttribute('aria-label', 'Aje star visibility alert');

  const head = el(doc, 'div', 'aje-alert-head');
  head.append(
    el(doc, 'span', 'aje-alert-star', '★'),
    el(doc, 'span', 'aje-alert-kicker', 'AJE WATCH · YOUR STAR'),
  );
  const close = el(doc, 'button', 'aje-alert-close', '✕');
  close.type = 'button';
  close.title = 'Hide the Aje watch';
  head.append(close);
  panel.append(head);

  const headline = el(doc, 'p', 'aje-alert-headline');
  const detail = el(doc, 'p', 'aje-alert-detail');
  const coords = el(
    doc,
    'p',
    'aje-alert-coords',
    `${star.designation} · ${star.raText} · ${star.decText} · named ${star.named}`,
  );
  const note = el(doc, 'p', 'aje-alert-note', FAINTNESS_NOTE);
  panel.append(headline, detail, coords, note);

  close.addEventListener('click', () => {
    panel.hidden = true;
  });

  function refresh() {
    const s = describeStatus(now(), { site, star, sunAltAt });
    panel.classList.toggle('is-up', s.visible);
    headline.textContent = s.headline;
    detail.textContent = s.detail;
    return s;
  }

  return {
    element: panel,
    refresh,
    isUp: () => panel.classList.contains('is-up'),
    destroy() {
      panel.remove();
    },
  };
}

const REFRESH_MS = 5 * 60_000;

/** Boot helper: build the card, mount it, refresh now and every 5 minutes. */
export function initAjeAlert({ now, sunAltAt, doc = document } = {}) {
  const alert = createAjeAlert(doc, { now, sunAltAt });
  doc.body.append(alert.element);
  alert.refresh();
  const timer = setInterval(() => alert.refresh(), REFRESH_MS);
  const base = alert.destroy;
  alert.destroy = () => {
    clearInterval(timer);
    base.call(alert);
  };
  return alert;
}
