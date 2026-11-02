/**
 * Ananzi map marker icons: a small SVG "badge" (disc + ringed glyph) rendered
 * as a Cesium billboard image, so every layer gets a distinct shape and colour
 * instead of an interchangeable dot. The glyphs are the same symbols shown next
 * to each layer's name in the Data Layers panel.
 *
 * Billboards (images) are allowed on the globe; Cesium text labels are not
 * (src/noCesiumLabels.test.mjs), so the glyph is baked into the SVG here.
 *
 * Personal research tooling: English-only by design.
 */
const CACHE = new Map();

const escapeXml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);

/**
 * One badge as an SVG `data:` URI: a soft colour disc, a ring, and the glyph
 * in the layer colour with a dark outline so it reads over bright terrain.
 * Pure and memoized, so repeated markers reuse one image.
 *
 * @param {string} glyph  A single symbol, e.g. '☣' or '⚙'.
 * @param {string} color  CSS colour for the glyph, ring and disc tint.
 * @param {{ring?: boolean}} [opts]
 * @returns {string} data:image/svg+xml URI
 */
export function glyphBadgeImage(glyph, color, { ring = true } = {}) {
  const key = `${glyph}|${color}|${ring ? 1 : 0}`;
  const hit = CACHE.get(key);
  if (hit) return hit;
  const g = escapeXml(glyph);
  const c = escapeXml(color);
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">` +
    (ring
      ? `<circle cx="24" cy="24" r="15" fill="${c}" fill-opacity="0.16" stroke="${c}" stroke-width="2" stroke-opacity="0.85"/>`
      : '') +
    `<text x="24" y="25" font-size="24" text-anchor="middle" dominant-baseline="central" ` +
    `font-family="'Apple Color Emoji','Segoe UI Symbol','Noto Sans Symbols2',sans-serif" ` +
    `fill="${c}" stroke="#0b0a08" stroke-width="3" paint-order="stroke" stroke-linejoin="round">${g}</text>` +
    `</svg>`;
  const uri = `data:image/svg+xml,${encodeURIComponent(svg)}`;
  CACHE.set(key, uri);
  return uri;
}

/**
 * Cesium billboard options for a glyph badge. Depth-tested (the globe hides
 * the ones on its far side) and shrinks a little with distance.
 *
 * @param {object} Cesium  The Cesium namespace (passed in to keep this module Cesium-free for tests).
 * @param {string} glyph
 * @param {string} color
 * @param {{scale?: number, ring?: boolean}} [opts]
 */
export function glyphBillboard(Cesium, glyph, color, { scale = 1, ring = true } = {}) {
  const px = Math.round(30 * scale);
  return {
    image: glyphBadgeImage(glyph, color, { ring }),
    width: px,
    height: px,
    verticalOrigin: Cesium.VerticalOrigin.CENTER,
    horizontalOrigin: Cesium.HorizontalOrigin.CENTER,
    scaleByDistance: new Cesium.NearFarScalar(1.5e6, 1.0, 4.0e7, 0.7),
    // No disableDepthTestDistance: keep it depth-tested so the globe occludes
    // far-side markers, matching the lifted-point behaviour it replaces.
  };
}
