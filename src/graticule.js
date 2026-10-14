import * as Cesium from 'cesium';
import { governorRequestRender } from './renderGovernor.js';

/**
 * Lat/long graticule — the glowing wireframe grid draped over the real globe
 * for "console mode" (see `body.console-mode` in style.css and
 * `setGraticuleEnabled` in ui.js's console-mode toggle).
 *
 * Real WGS84 polyline entities, not a screen-space effect: Cesium depth-tests
 * them against the terrain/imagery like any other surface feature, so the
 * far side of the globe occludes correctly at any camera angle for free.
 * Pure decoration otherwise — no picking, no effect on camera/globe state.
 * Only visible at zoom levels wide enough to see more than one grid cell
 * (roughly country/continent scale and wider); at street level the nearest
 * grid lines are simply off-screen, same as any real-world lat/long grid.
 */

const LAT_STEP_DEG = 10;
const LON_STEP_DEG = 10;
const SEGMENTS_PER_LINE = 90;
const MAX_LAT_DEG = 80;

let _viewer = null;
let _entities = null;
let _enabled = false;

/** Reads the live theme accent so the grid never drifts from the CSS palette. */
function graticuleColor() {
  const style = getComputedStyle(document.documentElement);
  const hex = style.getPropertyValue('--text-primary').trim() || '#d4af37';
  let color;
  try {
    color = Cesium.Color.fromCssColorString(hex);
  } catch {
    color = Cesium.Color.GOLD;
  }
  return (color || Cesium.Color.GOLD).withAlpha(0.4);
}

function buildEntities(viewer) {
  const color = graticuleColor();
  const equatorColor = color.withAlpha(Math.min(1, color.alpha + 0.25));
  const entities = [];

  for (let lat = -MAX_LAT_DEG; lat <= MAX_LAT_DEG; lat += LAT_STEP_DEG) {
    const positions = [];
    for (let i = 0; i <= SEGMENTS_PER_LINE; i += 1) {
      const lon = -180 + (360 * i) / SEGMENTS_PER_LINE;
      positions.push(Cesium.Cartesian3.fromDegrees(lon, lat));
    }
    const isEquator = lat === 0;
    entities.push(viewer.entities.add({
      polyline: {
        positions,
        width: isEquator ? 2 : 1,
        material: new Cesium.PolylineGlowMaterialProperty({
          glowPower: 0.12,
          color: isEquator ? equatorColor : color,
        }),
        arcType: Cesium.ArcType.RHUMB,
      },
    }));
  }

  for (let lon = -180; lon < 180; lon += LON_STEP_DEG) {
    const positions = [];
    for (let i = 0; i <= SEGMENTS_PER_LINE; i += 1) {
      const lat = -90 + (180 * i) / SEGMENTS_PER_LINE;
      positions.push(Cesium.Cartesian3.fromDegrees(lon, lat));
    }
    const isPrimeMeridian = lon === 0;
    entities.push(viewer.entities.add({
      polyline: {
        positions,
        width: isPrimeMeridian ? 2 : 1,
        material: new Cesium.PolylineGlowMaterialProperty({
          glowPower: 0.12,
          color: isPrimeMeridian ? equatorColor : color,
        }),
        arcType: Cesium.ArcType.RHUMB,
      },
    }));
  }

  return entities;
}

/**
 * Register the viewer this module draws into. Idempotent; drawing itself
 * stays deferred until {@link setGraticuleEnabled} turns it on.
 * @param {Cesium.Viewer} viewer
 * @returns {void}
 */
export function installGraticule(viewer) {
  if (_viewer || !viewer) return;
  _viewer = viewer;
  // ui.js's console-mode restore (from localStorage) can run its
  // setGraticuleEnabled(true) call before this install runs, since that
  // restore doesn't wait on main.js's viewer setup — in that case _enabled
  // is already true but there was no _viewer yet to build entities into.
  // Pick that up now instead of silently staying empty until the next
  // manual toggle.
  if (_enabled && !_entities) _entities = buildEntities(_viewer);
}

/**
 * @param {boolean} enabled - Wired to `body.console-mode`; off by default so
 *   the default globe is unaffected until console mode is turned on.
 * @returns {void}
 */
export function setGraticuleEnabled(enabled) {
  _enabled = Boolean(enabled);
  if (!_viewer) return;
  if (_enabled && !_entities) {
    _entities = buildEntities(_viewer);
  } else if (!_enabled && _entities) {
    for (const entity of _entities) _viewer.entities.remove(entity);
    _entities = null;
  }
  governorRequestRender('graticule-toggle');
}

/** @returns {boolean} */
export function isGraticuleEnabled() {
  return _enabled;
}

/** Tear the graticule down (entities only). Reinstall with installGraticule. */
export function destroyGraticule() {
  if (_entities && _viewer) {
    for (const entity of _entities) _viewer.entities.remove(entity);
  }
  _entities = null;
  _enabled = false;
  _viewer = null;
}
