/**
 * Ananzi Sky: the pure astronomy helpers that turn a star or planet's
 * coordinates into the point on Earth it is directly over right now (its
 * "sub-point"). No Cesium, no network — unit-tested in skyMath.test.mjs.
 *
 * A body at right ascension α and declination δ stands at the zenith of the
 * ground point whose latitude is δ and whose longitude is α minus the
 * Greenwich sidereal time. As the Earth turns, that point sweeps westward
 * ~15°/hour, which is what makes the layer move in real time.
 */

/** Greenwich Mean Sidereal Time in degrees [0,360) for a Date. */
export function gmstDeg(date) {
  const jd = date.getTime() / 86_400_000 + 2_440_587.5;
  const t = jd - 2_451_545.0;
  const g = (280.46061837 + 360.98564736629 * t) % 360;
  return ((g % 360) + 360) % 360;
}

const wrapLon = (lon) => ((((lon + 180) % 360) + 360) % 360) - 180;

/**
 * The ground point a body is over now.
 * @param {number} raDeg  Right ascension, degrees [0,360).
 * @param {number} decDeg  Declination, degrees [-90,90].
 * @param {number} gmst    Greenwich sidereal time, degrees (from gmstDeg).
 * @returns {{lat:number, lon:number}}
 */
export function subPoint(raDeg, decDeg, gmst) {
  return { lat: decDeg, lon: wrapLon(raDeg - gmst) };
}

/**
 * Split a path of {lat,lon} points wherever it would jump across the
 * antimeridian, so a constellation line never draws a false streak straight
 * across the globe. Returns an array of sub-paths, each safe to draw as one
 * polyline.
 * @param {{lat:number, lon:number}[]} points
 * @returns {{lat:number, lon:number}[][]}
 */
export function splitByAntimeridian(points) {
  const out = [];
  let run = [];
  for (let i = 0; i < points.length; i++) {
    if (i > 0 && Math.abs(points[i].lon - points[i - 1].lon) > 180) {
      if (run.length > 1) out.push(run);
      run = [];
    }
    run.push(points[i]);
  }
  if (run.length > 1) out.push(run);
  return out;
}

/** A visual size in pixels for a star of apparent magnitude `mag`. */
export function starSizePx(mag) {
  // Brightest (~ -1.5) big, faintest (~5) a speck.
  return Math.max(1.4, Math.min(6.5, 5.6 - 0.8 * mag));
}

/** Opacity for a star of magnitude `mag`. */
export function starAlpha(mag) {
  return Math.max(0.35, Math.min(1, 1.1 - 0.13 * mag));
}
