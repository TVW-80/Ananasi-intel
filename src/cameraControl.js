/**
 * @module cameraControl
 *
 * A self-contained VIEW CONTROL panel for manual camera/view control, wired
 * straight to the Cesium camera. Deliberately independent of the right rail's
 * adaptive-layout system: it owns its own fixed panel and show/hide toggle.
 *
 * Every orientation change orbits around the point under the screen centre
 * (lookAt + release), which:
 *   - rotates/tilts around what you're actually looking at, not the camera's
 *     own axis, and
 *   - zeroes roll as a side effect — so "LEVEL" and any button instantly fix
 *     a tilted/"flipped the wrong way" horizon.
 *
 * All operations are synchronous setView-style (no flight), so they respond
 * immediately and work even in the keyless/degraded tile environment.
 */

import * as Cesium from 'cesium';

const HEADING_STEP_DEG = 15;
const PITCH_STEP_DEG = 10;
const ZOOM_IN_FACTOR = 0.6;
const ZOOM_OUT_FACTOR = 1 / ZOOM_IN_FACTOR;
const MIN_PITCH_DEG = -89; // not -90: straight-down makes heading undefined (gimbal flip)
const MAX_PITCH_DEG = -2;
const MIN_RANGE_M = 60;
const READOUT_MS = 200;

const norm360 = (deg) => ((deg % 360) + 360) % 360;
const clampPitch = (deg) => Math.max(MIN_PITCH_DEG, Math.min(MAX_PITCH_DEG, deg));

/**
 * The point the camera is looking at (centre of screen), as a world Cartesian.
 *
 * Primary method is the camera's own view DIRECTION intersected with the
 * WGS84 ellipsoid — it needs no canvas dimensions, so it works even before
 * layout and when the pane is hidden (pickEllipsoid/pickPosition both rely on
 * a screen coordinate and return null when clientWidth is 0). When the canvas
 * is laid out, a depth pick at the true centre is preferred so the orbit
 * centre sits on 3D-tile surfaces (buildings), not the bare ellipsoid. Falls
 * back to the ground point directly beneath the camera.
 */
function viewCenterPoint(viewer) {
  const scene = viewer.scene;
  const cam = viewer.camera;
  const w = scene.canvas.clientWidth;
  const h = scene.canvas.clientHeight;
  // Depth pick at the real centre (best surface accuracy) — only when laid out.
  if (w > 0 && h > 0) {
    try {
      const p = scene.pickPosition(new Cesium.Cartesian2(w / 2, h / 2));
      if (Cesium.defined(p)) return p;
    } catch { /* no depth texture */ }
  }
  // View-direction ray ∩ ellipsoid — robust, layout-independent.
  try {
    const ray = new Cesium.Ray(cam.positionWC, cam.directionWC);
    const interval = Cesium.IntersectionTests.rayEllipsoid(ray, Cesium.Ellipsoid.WGS84);
    if (interval) return Cesium.Ray.getPoint(ray, interval.start);
  } catch { /* fall through */ }
  // Looking at space: use the ground point straight below the camera.
  const cc = cam.positionCartographic;
  if (cc) return Cesium.Cartesian3.fromRadians(cc.longitude, cc.latitude, 0);
  return null;
}

/**
 * Orbit the camera around the screen-centre point to a new heading/pitch/range.
 * Any argument left undefined keeps the camera's current value.
 */
function applyOrientation(viewer, { headingDeg, pitchDeg, rangeFactor = 1 } = {}) {
  const center = viewCenterPoint(viewer);
  if (!center) return false;
  const cam = viewer.camera;
  const heading = Cesium.Math.toRadians(
    headingDeg != null ? headingDeg : Cesium.Math.toDegrees(cam.heading),
  );
  const pitch = Cesium.Math.toRadians(
    clampPitch(pitchDeg != null ? pitchDeg : Cesium.Math.toDegrees(cam.pitch)),
  );
  const range = Math.max(MIN_RANGE_M, Cesium.Cartesian3.distance(cam.positionWC, center) * rangeFactor);
  cam.lookAt(center, new Cesium.HeadingPitchRange(heading, pitch, range));
  cam.lookAtTransform(Cesium.Matrix4.IDENTITY); // release the reference frame, keep the pose
  viewer.scene.requestRender();
  return true;
}

function fmtAlt(m) {
  if (!Number.isFinite(m)) return '--';
  return m >= 1000 ? `${(m / 1000).toFixed(1)} km` : `${Math.round(m)} m`;
}

/**
 * Build and wire the VIEW CONTROL panel. The markup lives in index.html
 * (#view-control-panel / #view-control-toggle); this attaches the camera
 * behaviour. Returns a disposer.
 * @param {Cesium.Viewer} viewer
 */
export function createCameraControlPanel(viewer) {
  const panel = document.getElementById('view-control-panel');
  const toggle = document.getElementById('view-control-toggle');
  if (!panel || !toggle || !viewer) return () => {};

  const $ = (id) => document.getElementById(id);
  const out = { hdg: $('vc-hdg'), pitch: $('vc-pitch'), alt: $('vc-alt') };
  let readoutTimer = null;

  const cam = () => viewer.camera;
  const headingDeg = () => Cesium.Math.toDegrees(cam().heading);
  const pitchDeg = () => Cesium.Math.toDegrees(cam().pitch);

  const refreshReadout = () => {
    if (out.hdg) out.hdg.textContent = `${Math.round(norm360(headingDeg()))}°`;
    if (out.pitch) out.pitch.textContent = `${Math.round(pitchDeg())}°`;
    if (out.alt) out.alt.textContent = fmtAlt(cam().positionCartographic?.height);
  };

  // Each control computes from the live camera, applies, then repaints.
  const act = (fn) => () => { fn(); refreshReadout(); };
  const handlers = {
    'vc-rot-left': act(() => applyOrientation(viewer, { headingDeg: headingDeg() - HEADING_STEP_DEG })),
    'vc-rot-right': act(() => applyOrientation(viewer, { headingDeg: headingDeg() + HEADING_STEP_DEG })),
    'vc-north': act(() => applyOrientation(viewer, { headingDeg: 0 })),
    'vc-tilt-up': act(() => applyOrientation(viewer, { pitchDeg: pitchDeg() + PITCH_STEP_DEG })),
    'vc-tilt-down': act(() => applyOrientation(viewer, { pitchDeg: pitchDeg() - PITCH_STEP_DEG })),
    'vc-level': act(() => applyOrientation(viewer, {})), // reapply current pose → roll 0
    'vc-top': act(() => applyOrientation(viewer, { pitchDeg: -89 })),
    'vc-oblique': act(() => applyOrientation(viewer, { pitchDeg: -45 })),
    'vc-horizon': act(() => applyOrientation(viewer, { pitchDeg: -8 })),
    'vc-zoom-in': act(() => applyOrientation(viewer, { rangeFactor: ZOOM_IN_FACTOR })),
    'vc-zoom-out': act(() => applyOrientation(viewer, { rangeFactor: ZOOM_OUT_FACTOR })),
    'vc-reset': act(() => applyOrientation(viewer, { headingDeg: 0, pitchDeg: -45 })),
  };
  const bound = [];
  for (const [id, fn] of Object.entries(handlers)) {
    const el = $(id);
    if (el) { el.addEventListener('click', fn); bound.push([el, fn]); }
  }

  const setOpen = (open) => {
    panel.hidden = !open;
    toggle.classList.toggle('active', open);
    toggle.setAttribute('aria-expanded', String(open));
    if (open) {
      refreshReadout();
      if (!readoutTimer) readoutTimer = window.setInterval(refreshReadout, READOUT_MS);
    } else if (readoutTimer) {
      window.clearInterval(readoutTimer);
      readoutTimer = null;
    }
  };

  const onToggle = () => setOpen(panel.hidden);
  const onClose = () => setOpen(false);
  toggle.addEventListener('click', onToggle);
  const closeBtn = $('view-ctrl-close');
  if (closeBtn) closeBtn.addEventListener('click', onClose);

  setOpen(false); // start hidden; toggle reveals it

  return () => {
    if (readoutTimer) window.clearInterval(readoutTimer);
    toggle.removeEventListener('click', onToggle);
    if (closeBtn) closeBtn.removeEventListener('click', onClose);
    for (const [el, fn] of bound) el.removeEventListener('click', fn);
  };
}

export default createCameraControlPanel;
