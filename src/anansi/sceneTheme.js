/**
 * Anansi scene palette: where no imagery tile has loaded yet (or none exists),
 * Cesium paints the globe's base color — bright blue by default. Use the
 * Anansi near-black instead so loading/missing tiles read as dark, not blue.
 */
import * as Cesium from 'cesium';

export const ANANSI_GLOBE_BASE = '#0b0a08';

export function applyAnansiSceneTheme(viewer) {
  const globe = viewer?.scene?.globe;
  if (!globe) return;
  globe.baseColor = Cesium.Color.fromCssColorString(ANANSI_GLOBE_BASE);
}
