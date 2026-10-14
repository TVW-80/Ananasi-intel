import { getKeyholeGeometry } from './celestialRing.js';

/**
 * HUD frame — the decorative porthole ring and circuit-trace lines for
 * "console mode" (see `body.console-mode` in style.css).
 *
 * Deliberately a SEPARATE module from scopeMask.js rather than an addition
 * to it: scopeMask.js's altitude-adaptive terminus ramp is tuned and
 * documented in detail, and this file's concerns (a static ring stroke,
 * plus lines to on-screen panels) are unrelated enough that bolting them on
 * would only make both harder to reason about. The two share exactly one
 * thing on purpose: `getKeyholeGeometry()`, so the ring drawn here always
 * lands on the same circle scopeMask.js already fades its vignette against.
 *
 * Pure decoration: this canvas is `pointer-events:none` and never resizes
 * `#cesiumContainer` or touches camera/picking code. It only reads element
 * positions to draw lines toward them.
 */

/** DOM targets the circuit traces reach toward. Queried fresh each redraw —
 * panels collapse/expand and reflow, so cached rects would go stale. */
const TRACE_TARGET_SELECTORS = [
  '#title-bar',
  '#style-indicator',
  '#left-panel-stack',
  '#right-context-rail',
  '#command-dock',
  '.hud-top-left',
  '.hud-top-right',
  '.hud-bottom-left',
  '.hud-bottom-right',
];

let _canvas = null;
let _container = null;
let _resizeObserver = null;
let _traceObserver = null;
let _dprQuery = null;
let _dprListener = null;
let _enabled = false;

/** Rotating radar-sweep state. Only ticks while console mode is enabled —
 * this is the one part of hudFrame.js that redraws on its own clock rather
 * than in response to a resize/mutation, so it's throttled to ~30fps and
 * fully torn down (not just paused) the moment console mode goes off, to
 * avoid leaving a perpetual rAF loop running for a hidden decoration. */
let _sweepAngle = 0;
let _sweepAnimationFrame = null;
let _sweepLastDrawMs = 0;
const SWEEP_FRAME_INTERVAL_MS = 1000 / 30;
const SWEEP_RADIANS_PER_MS = (Math.PI * 2) / 9000; // one full turn per ~9s

function sweepTick(timestampMs) {
  if (!_enabled) {
    _sweepAnimationFrame = null;
    return;
  }
  const elapsed = _sweepLastDrawMs ? timestampMs - _sweepLastDrawMs : 0;
  if (elapsed >= SWEEP_FRAME_INTERVAL_MS) {
    _sweepAngle = (_sweepAngle + elapsed * SWEEP_RADIANS_PER_MS) % (Math.PI * 2);
    _sweepLastDrawMs = timestampMs;
    draw();
  }
  _sweepAnimationFrame = requestAnimationFrame(sweepTick);
}

function startSweep() {
  if (_sweepAnimationFrame !== null || typeof requestAnimationFrame !== 'function') return;
  _sweepLastDrawMs = 0;
  _sweepAnimationFrame = requestAnimationFrame(sweepTick);
}

function stopSweep() {
  if (_sweepAnimationFrame !== null && typeof cancelAnimationFrame === 'function') {
    cancelAnimationFrame(_sweepAnimationFrame);
  }
  _sweepAnimationFrame = null;
}

/** Reads the live theme tokens so the ring/traces never drift from the CSS palette. */
function themeColors() {
  const style = getComputedStyle(document.documentElement);
  return {
    ring: style.getPropertyValue('--text-primary').trim() || '#d4af37',
    glow: style.getPropertyValue('--accent-glow').trim() || 'rgba(200, 30, 30, 0.4)',
    trace: style.getPropertyValue('--accent').trim() || '#c81e1e',
  };
}

function devicePixelRatioClamped() {
  return Math.min(2, Number(typeof window !== 'undefined' ? window.devicePixelRatio : 1) || 1);
}

/** Nearest point on an element's bounding box to an external (x, y) point. */
function nearestRectPoint(rect, x, y) {
  return {
    x: Math.max(rect.left, Math.min(rect.right, x)),
    y: Math.max(rect.top, Math.min(rect.bottom, y)),
  };
}

/**
 * Draw one elbowed circuit-trace line from a point on the ring toward a
 * target element's nearest edge, with small glow dots at both ends.
 */
/** Small filled diamond — the HUD "node" marker used at trace joints/ends. */
function drawNode(ctx, x, y, size, color, alpha) {
  ctx.save();
  ctx.fillStyle = color;
  ctx.globalAlpha = alpha;
  ctx.beginPath();
  ctx.moveTo(x, y - size);
  ctx.lineTo(x + size, y);
  ctx.lineTo(x, y + size);
  ctx.lineTo(x - size, y);
  ctx.closePath();
  ctx.fill();
  ctx.restore();
}

/** A small crosshair reticle dead-center of the porthole — the classic
 * cockpit-HUD "aim point," independent of the ring/ticks/sweep. */
function drawCenterReticle(ctx, keyhole, colors) {
  const { centerX: cx, centerY: cy } = keyhole;
  ctx.save();
  ctx.strokeStyle = colors.ring;
  ctx.lineWidth = 1;
  ctx.globalAlpha = 0.5;
  ctx.shadowColor = colors.glow;
  ctx.shadowBlur = 4;
  ctx.beginPath();
  ctx.arc(cx, cy, 10, 0, Math.PI * 2);
  ctx.stroke();
  for (const [dx, dy] of [[16, 0], [-16, 0], [0, 16], [0, -16]]) {
    ctx.beginPath();
    ctx.moveTo(cx + dx * 0.4, cy + dy * 0.4);
    ctx.lineTo(cx + dx, cy + dy);
    ctx.stroke();
  }
  ctx.restore();
}

/** Rotating radar-sweep line with a fading trail, drawn inside the ring
 * over the live globe — purely decorative and driven by sweepTick()'s own
 * throttled rAF loop, not by any real scan/detection state. */
function drawRadarSweep(ctx, keyhole, colors) {
  const inner = 24;
  const outer = keyhole.radius - 22;
  if (!(outer > inner)) return;
  const trailSpan = Math.PI / 3.5;
  const steps = 22;
  ctx.save();
  ctx.lineWidth = 1.25;
  for (let i = steps; i >= 0; i -= 1) {
    const t = i / steps;
    const angle = _sweepAngle - t * trailSpan;
    ctx.strokeStyle = t === 0 ? colors.ring : colors.trace;
    ctx.globalAlpha = t === 0 ? 0.85 : (1 - t) * 0.3;
    if (t === 0) {
      ctx.shadowColor = colors.glow;
      ctx.shadowBlur = 8;
    } else {
      ctx.shadowBlur = 0;
    }
    ctx.beginPath();
    ctx.moveTo(keyhole.centerX + inner * Math.cos(angle), keyhole.centerY + inner * Math.sin(angle));
    ctx.lineTo(keyhole.centerX + outer * Math.cos(angle), keyhole.centerY + outer * Math.sin(angle));
    ctx.stroke();
  }
  ctx.restore();
}

/** Viewfinder-style corner brackets pinned to the four screen corners — a
 * cockpit-HUD framing motif independent of the ring and of any panel's
 * position, so it reads correctly no matter how the console-mode panels
 * are currently arranged. */
function drawCornerBrackets(ctx, width, height, colors) {
  const margin = 18;
  const armLen = 40;
  const corners = [
    { x: margin, y: margin, dx: 1, dy: 1 },
    { x: width - margin, y: margin, dx: -1, dy: 1 },
    { x: margin, y: height - margin, dx: 1, dy: -1 },
    { x: width - margin, y: height - margin, dx: -1, dy: -1 },
  ];
  ctx.save();
  ctx.strokeStyle = colors.ring;
  ctx.lineWidth = 2;
  ctx.globalAlpha = 0.5;
  ctx.shadowColor = colors.glow;
  ctx.shadowBlur = 8;
  for (const corner of corners) {
    ctx.beginPath();
    ctx.moveTo(corner.x + corner.dx * armLen, corner.y);
    ctx.lineTo(corner.x, corner.y);
    ctx.lineTo(corner.x, corner.y + corner.dy * armLen);
    ctx.stroke();
  }
  ctx.restore();
}

/**
 * @param {CanvasRenderingContext2D} ctx
 * @param {number} ringX - Canvas-local (not viewport) coordinates.
 * @param {number} ringY
 * @param {{left:number,right:number,top:number,bottom:number}} rect - Target
 *   bounds already converted to canvas-local space (see the draw() loop) —
 *   ringX/ringY and rect must share one coordinate space, or the trace
 *   points at nothing.
 * @param {{ring:string,glow:string,trace:string}} colors
 */
function drawTrace(ctx, ringX, ringY, rect, colors) {
  const end = nearestRectPoint(rect, ringX, ringY);
  // Right-angle elbow partway along, so it reads as a routed trace rather
  // than a straight wire — bend toward whichever axis has more distance left.
  const dx = end.x - ringX;
  const dy = end.y - ringY;
  const elbow = Math.abs(dx) > Math.abs(dy)
    ? { x: ringX + dx * 0.6, y: ringY }
    : { x: ringX, y: ringY + dy * 0.6 };

  ctx.save();
  ctx.strokeStyle = colors.trace;
  ctx.lineWidth = 2;
  ctx.globalAlpha = 0.75;
  ctx.shadowColor = colors.glow;
  ctx.shadowBlur = 6;
  ctx.beginPath();
  ctx.moveTo(ringX, ringY);
  ctx.lineTo(elbow.x, elbow.y);
  ctx.lineTo(end.x, end.y);
  ctx.stroke();

  // A thinner "ribbon" line offset a few px alongside the main trace, for a
  // routed-PCB-bus look rather than a single bare wire.
  ctx.lineWidth = 1;
  ctx.globalAlpha = 0.35;
  ctx.shadowBlur = 0;
  const offset = 3;
  ctx.beginPath();
  ctx.moveTo(ringX, ringY + offset);
  ctx.lineTo(elbow.x, elbow.y + (Math.abs(dx) > Math.abs(dy) ? offset : 0));
  ctx.lineTo(end.x, end.y + (Math.abs(dx) > Math.abs(dy) ? 0 : offset));
  ctx.stroke();
  ctx.restore();

  drawNode(ctx, ringX, ringY, 3, colors.ring, 0.9);
  drawNode(ctx, elbow.x, elbow.y, 2, colors.trace, 0.7);
  drawNode(ctx, end.x, end.y, 3, colors.ring, 0.9);
}

function draw() {
  if (!_canvas || !_container) return;
  if (!_enabled) {
    const ctx = _canvas.getContext('2d');
    if (ctx) {
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, _canvas.width, _canvas.height);
    }
    return;
  }
  const width = _container.clientWidth;
  const height = _container.clientHeight;
  if (!(width > 0) || !(height > 0)) return;
  const dpr = devicePixelRatioClamped();
  _canvas.width = Math.round(width * dpr);
  _canvas.height = Math.round(height * dpr);
  const ctx = _canvas.getContext('2d');
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const keyhole = getKeyholeGeometry(width, height);
  if (!(keyhole.radius > 0)) return;
  const colors = themeColors();

  // Thick physical bezel — a beveled metal band (radial gradient standing in
  // for a lit cross-section) rather than a thin outlined circle, closer to
  // the reference's lens-housing porthole. Mostly sits INSIDE keyhole.radius
  // (the scopeMask.js vignette boundary) so its outer sliver blends into the
  // already-darkening edge instead of fighting it.
  const bezelOuter = keyhole.radius + 8;
  const bezelInner = keyhole.radius - 30;
  if (bezelInner > 0) {
    const bevel = ctx.createRadialGradient(
      keyhole.centerX, keyhole.centerY, bezelInner,
      keyhole.centerX, keyhole.centerY, bezelOuter,
    );
    bevel.addColorStop(0, 'rgba(0, 0, 0, 0.92)');
    bevel.addColorStop(0.16, colors.trace);
    bevel.addColorStop(0.42, colors.ring);
    bevel.addColorStop(0.58, colors.trace);
    bevel.addColorStop(0.78, colors.ring);
    bevel.addColorStop(1, 'rgba(0, 0, 0, 0.92)');
    ctx.save();
    ctx.shadowColor = colors.glow;
    ctx.shadowBlur = 26;
    ctx.beginPath();
    ctx.arc(keyhole.centerX, keyhole.centerY, bezelOuter, 0, Math.PI * 2);
    ctx.arc(keyhole.centerX, keyhole.centerY, bezelInner, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fillStyle = bevel;
    ctx.fill('evenodd');
    ctx.restore();
  }
  const bezelHighlightR = keyhole.radius - 10;
  const bezelGrooveR = keyhole.radius - 18;

  // Rivet/bolt plates riding the bright highlight band — small solid
  // squares at 12 evenly spaced points, rotated to face outward, for a
  // welded-plate mechanical look rather than a smooth ring.
  ctx.save();
  for (let deg = 15; deg < 360; deg += 30) {
    const rad = (deg * Math.PI) / 180;
    const px = keyhole.centerX + bezelHighlightR * Math.cos(rad);
    const py = keyhole.centerY + bezelHighlightR * Math.sin(rad);
    ctx.save();
    ctx.translate(px, py);
    ctx.rotate(rad);
    ctx.fillStyle = 'rgba(0, 0, 0, 0.75)';
    ctx.globalAlpha = 0.85;
    ctx.fillRect(-3, -3, 6, 6);
    ctx.restore();
  }
  ctx.restore();

  // Small bright accent wedges at the eight compass points — the little
  // triangular tabs the reference marks each panel joint with, planted
  // directly on the bezel rather than on the (unrotated-safe) panels.
  ctx.save();
  for (let deg = 0; deg < 360; deg += 45) {
    const rad = (deg * Math.PI) / 180;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);
    const tipX = keyhole.centerX + (bezelOuter + 10) * cos;
    const tipY = keyhole.centerY + (bezelOuter + 10) * sin;
    const baseR = bezelOuter - 4;
    const perpX = -sin * 5;
    const perpY = cos * 5;
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(keyhole.centerX + baseR * cos + perpX, keyhole.centerY + baseR * sin + perpY);
    ctx.lineTo(keyhole.centerX + baseR * cos - perpX, keyhole.centerY + baseR * sin - perpY);
    ctx.closePath();
    ctx.fillStyle = colors.ring;
    ctx.globalAlpha = 0.95;
    ctx.shadowColor = colors.glow;
    ctx.shadowBlur = 8;
    ctx.fill();
  }
  ctx.restore();

  // Outer segmented scanner ring — dashed arcs a bit outside the bezel,
  // the classic sci-fi HUD "reticle" detail.
  ctx.save();
  ctx.strokeStyle = colors.trace;
  ctx.lineWidth = 1.5;
  ctx.globalAlpha = 0.6;
  ctx.shadowColor = colors.glow;
  ctx.shadowBlur = 6;
  ctx.setLineDash([keyhole.radius * 0.09, keyhole.radius * 0.05]);
  ctx.beginPath();
  ctx.arc(keyhole.centerX, keyhole.centerY, bezelOuter + 16, 0, Math.PI * 2);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.restore();

  // A recessed groove hairline part-way through the band, plus tick marks
  // around the circumference — long/bright every 90 deg, medium every 30
  // deg, short every 10 deg — with a diamond node at each of the 8 compass
  // points, echoing the reference HUD's reticle detailing.
  ctx.save();
  ctx.strokeStyle = 'rgba(0, 0, 0, 0.6)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(keyhole.centerX, keyhole.centerY, bezelGrooveR, 0, Math.PI * 2);
  ctx.stroke();
  for (let deg = 0; deg < 360; deg += 10) {
    const rad = (deg * Math.PI) / 180;
    const isCardinal = deg % 90 === 0;
    const isOrdinal = deg % 45 === 0;
    const tickLen = isCardinal ? 26 : isOrdinal ? 18 : 10;
    const inner = bezelInner - 6;
    const outer = inner - tickLen;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);
    ctx.strokeStyle = isCardinal ? colors.ring : colors.trace;
    ctx.lineWidth = isCardinal ? 2 : 1;
    ctx.globalAlpha = isCardinal ? 0.9 : isOrdinal ? 0.6 : 0.35;
    ctx.beginPath();
    ctx.moveTo(keyhole.centerX + inner * cos, keyhole.centerY + inner * sin);
    ctx.lineTo(keyhole.centerX + outer * cos, keyhole.centerY + outer * sin);
    ctx.stroke();
    if (isCardinal) {
      drawNode(
        ctx,
        keyhole.centerX + (bezelOuter + 16) * cos,
        keyhole.centerY + (bezelOuter + 16) * sin,
        4,
        colors.ring,
        0.85,
      );
    }
  }
  ctx.restore();

  drawRadarSweep(ctx, keyhole, colors);
  drawCenterReticle(ctx, keyhole, colors);
  drawCornerBrackets(ctx, width, height, colors);

  // One trace per visible target, anchored to the ring point closest to it.
  // Targets (title bar, panel stacks, HUD corners) live in VIEWPORT space,
  // but this canvas — and therefore keyhole.centerX/Y and everything drawn
  // above — is CANVAS-LOCAL, i.e. relative to #cesiumContainer's own
  // top-left. Those two spaces only coincided by accident while the
  // container was full-viewport; console mode now shrinks it to a centered
  // box (style.css), so every target rect needs to be re-based onto the
  // canvas's own origin before any of the angle/nearest-point math below
  // runs, or traces point at the wrong place entirely.
  const containerRect = _container.getBoundingClientRect();
  for (const selector of TRACE_TARGET_SELECTORS) {
    const target = document.querySelector(selector);
    if (!target || target.hidden) continue;
    const viewportRect = target.getBoundingClientRect();
    if (viewportRect.width <= 0 || viewportRect.height <= 0) continue;
    const rect = {
      left: viewportRect.left - containerRect.left,
      right: viewportRect.right - containerRect.left,
      top: viewportRect.top - containerRect.top,
      bottom: viewportRect.bottom - containerRect.top,
      width: viewportRect.width,
      height: viewportRect.height,
    };
    const angle = Math.atan2(
      rect.top + rect.height / 2 - keyhole.centerY,
      rect.left + rect.width / 2 - keyhole.centerX,
    );
    const ringX = keyhole.centerX + keyhole.radius * Math.cos(angle);
    const ringY = keyhole.centerY + keyhole.radius * Math.sin(angle);
    drawTrace(ctx, ringX, ringY, rect, colors);
  }
}

function watchDevicePixelRatio() {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
  teardownDevicePixelRatioWatch();
  const dpr = window.devicePixelRatio || 1;
  let query;
  try {
    query = window.matchMedia(`(resolution: ${dpr}dppx)`);
  } catch {
    return;
  }
  _dprQuery = query;
  _dprListener = () => {
    watchDevicePixelRatio();
    draw();
  };
  if (typeof query.addEventListener === 'function') query.addEventListener('change', _dprListener, { once: true });
  else if (typeof query.addListener === 'function') query.addListener(_dprListener);
}

function teardownDevicePixelRatioWatch() {
  if (_dprQuery && _dprListener) {
    if (typeof _dprQuery.removeEventListener === 'function') _dprQuery.removeEventListener('change', _dprListener);
    else if (typeof _dprQuery.removeListener === 'function') _dprQuery.removeListener(_dprListener);
  }
  _dprQuery = null;
  _dprListener = null;
}

/**
 * Install the HUD frame canvas into the viewer container. Idempotent.
 * Starts disabled — {@link setHudFrameEnabled} (wired to console mode)
 * turns it on.
 * @param {Cesium.Viewer} viewer
 * @returns {void}
 */
export function installHudFrame(viewer) {
  if (_canvas || !viewer?.container) return;
  _container = viewer.container;
  _canvas = document.createElement('canvas');
  _canvas.id = 'hud-frame';
  _canvas.setAttribute('aria-hidden', 'true');
  _container.appendChild(_canvas);

  _resizeObserver = new ResizeObserver(() => draw());
  _resizeObserver.observe(_container);
  watchDevicePixelRatio();

  // Panels resize (collapse/expand) and reflow independent of the
  // container's own size, so traces need their own watch on each target.
  _traceObserver = new ResizeObserver(() => draw());
  const mutationObserver = new MutationObserver(() => draw());
  for (const selector of TRACE_TARGET_SELECTORS) {
    const target = document.querySelector(selector);
    if (!target) continue;
    _traceObserver.observe(target);
    mutationObserver.observe(target, { attributes: true, attributeFilter: ['class', 'hidden'] });
  }
  // Reuse the resize observer's disconnect for the mutation observer too —
  // stash it on the same handle so destroy() has one thing to tear down.
  _traceObserver._mutationObserver = mutationObserver;

  draw();
}

/**
 * @param {boolean} enabled - Wired to `body.console-mode`; off by default so
 *   the default layout is unaffected until console mode is turned on.
 * @returns {void}
 */
export function setHudFrameEnabled(enabled) {
  _enabled = Boolean(enabled);
  if (_enabled) startSweep();
  else stopSweep();
  draw();
}

/** @returns {boolean} */
export function isHudFrameEnabled() {
  return _enabled;
}

/** Tear the frame down (canvas + observers). Reinstall with installHudFrame. */
export function destroyHudFrame() {
  stopSweep();
  _resizeObserver?.disconnect();
  _resizeObserver = null;
  _traceObserver?._mutationObserver?.disconnect();
  _traceObserver?.disconnect();
  _traceObserver = null;
  teardownDevicePixelRatioWatch();
  _canvas?.remove();
  _canvas = null;
  _container = null;
  _enabled = false;
}
