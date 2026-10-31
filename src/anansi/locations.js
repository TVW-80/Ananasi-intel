/**
 * Anansi: which preset cities get a quick-jump pill in the command dock.
 *
 * Every God's Eye View preset stays in CITY_POIS, so CCTV seeds, voice
 * "fly to <city>" and search-by-name still resolve them. Only the pill row
 * is limited to the Hampton Roads / Historic Triangle area of operations.
 */
export const ANANSI_VISIBLE_CITY_IDS = Object.freeze(['hamptonroads', 'williamsburg']);

/** @param {Record<string, object>} cities  CITY_POIS */
export function anansiVisibleCities(cities, ids = ANANSI_VISIBLE_CITY_IDS) {
  const visible = Object.fromEntries(ids.filter((id) => cities[id]).map((id) => [id, cities[id]]));
  // Never leave the dock empty if the presets are missing for some reason.
  return Object.keys(visible).length ? visible : cities;
}
