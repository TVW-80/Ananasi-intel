/**
 * Ananzi focus: WORLD (default) or 757.
 *
 * WORLD shows everything everywhere. 757 is a filter you switch on: the
 * Attack Map draws its arcs into Hampton Roads and keeps DDoS pairs that hit
 * the US, the country-level Cyber layers keep only US entries, and the
 * Shodan layers (Exposed ICS, Exposed Cameras) search around Hampton Roads
 * instead of the whole world. Remembered in this browser.
 */
export const FOCUS_WORLD = 'world';
export const FOCUS_757 = '757';
const STORAGE_KEY = 'ananzi.focus';
const listeners = new Set();

let current = FOCUS_WORLD;
try {
  if (globalThis.localStorage?.getItem(STORAGE_KEY) === FOCUS_757) current = FOCUS_757;
} catch {
  // storage unavailable: start on WORLD
}

export function getFocus() {
  return current;
}

export function setFocus(next) {
  const value = next === FOCUS_757 ? FOCUS_757 : FOCUS_WORLD;
  if (value === current) return;
  current = value;
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, value);
  } catch {
    // still applies for this session
  }
  for (const fn of [...listeners]) {
    try {
      fn(value);
    } catch (err) {
      console.warn('[Ananzi focus] listener failed', err);
    }
  }
}

export function toggleFocus() {
  setFocus(current === FOCUS_757 ? FOCUS_WORLD : FOCUS_757);
}

/** @returns {() => void} unsubscribe */
export function onFocusChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * Country-level points in 757 focus: keep only the United States (and US
 * states). Points with exact coordinates are kept if they are within the
 * Hampton Roads box.
 */
export function inFocus(point, focus = current) {
  if (focus !== FOCUS_757) return true;
  const id = String(point?.id || '');
  if (point?.approximate === false && Number.isFinite(point.lat) && Number.isFinite(point.lon)) {
    return point.lat > 35.9 && point.lat < 38.0 && point.lon > -77.9 && point.lon < -75.3;
  }
  return /:US$/.test(id) || /:us-state:/.test(id);
}

/** A small toggle button bound to the focus (used in the corner row and the Attack Map HUD). */
export function createFocusToggle(doc = document, className = 'ananzi-focus-btn') {
  const btn = doc.createElement('button');
  btn.type = 'button';
  btn.className = className;
  const render = (f) => {
    btn.textContent = f === FOCUS_757 ? '⚓ 757' : '🌐 WORLD';
    btn.title = f === FOCUS_757
      ? 'Showing Hampton Roads / 757 focus — click for the whole world'
      : 'Showing the whole world — click to focus on Hampton Roads / 757';
    btn.setAttribute('aria-pressed', String(f === FOCUS_757));
    btn.dataset.focus = f;
  };
  render(current);
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleFocus();
  });
  btn.addEventListener('pointerdown', (e) => e.stopPropagation());
  btn.addEventListener('dblclick', (e) => e.stopPropagation());
  const off = onFocusChange(render);
  btn.dispose = off;
  return btn;
}
