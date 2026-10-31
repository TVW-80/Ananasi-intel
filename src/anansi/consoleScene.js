/**
 * Anansi console mode, viewer side: the porthole HUD frame and lat/long
 * graticule follow the `console-mode` class on <body>, which the CONSOLE
 * toggle in the DISPLAY panel sets (src/anansi/panels.js). Keeping this
 * link one-way (UI sets a class, the scene watches it) keeps the UI shell
 * free of Cesium/render imports.
 */
import { setHudFrameEnabled } from '../hudFrame.js';
import { setGraticuleEnabled } from '../graticule.js';

/** @returns {() => void} stop watching */
export function installConsoleScene(doc = globalThis.document) {
  const body = doc?.body;
  if (!body) return () => {};
  let active = null;
  const sync = () => {
    const next = body.classList.contains('console-mode');
    if (next === active) return;
    active = next;
    setHudFrameEnabled(next);
    setGraticuleEnabled(next);
  };
  sync();
  if (typeof MutationObserver === 'undefined') return () => {};
  const observer = new MutationObserver(sync);
  observer.observe(body, { attributes: true, attributeFilter: ['class'] });
  return () => observer.disconnect();
}
