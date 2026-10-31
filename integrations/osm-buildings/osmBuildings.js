/**
 * Cesium OSM Buildings for Anansi: free 3D buildings from Cesium ion
 * (asset 96188), styled in the red / black / gold theme.
 *
 * Use it when the globe is NOT showing Google Photorealistic 3D Tiles (those
 * already include buildings, so drawing both would double up). The base
 * platform reports which route it landed on: 'google-direct', 'google-token',
 * 'google-ion' or 'osm' (see src/maps/google3d.js). Call this on 'osm'.
 *
 * Like the base platform, the ion token is passed to this one resource
 * instead of being set as Cesium's global default.
 */

export const OSM_BUILDINGS_ASSET_ID = 96188;

/**
 * Anansi building style: near-black blocks, warming to gold with height so
 * towers read at a glance; Naval Station / port areas aren't special-cased.
 * `cesium#estimatedHeight` is the height field OSM Buildings provides.
 */
export function anansiBuildingStyle(Cesium) {
  return new Cesium.Cesium3DTileStyle({
    // Some footprints carry no height; treat them as low-rise instead of
    // letting the comparison throw and blank the tileset.
    defines: {
      h: "isNaN(Number(${feature['cesium#estimatedHeight']})) ? 0 : Number(${feature['cesium#estimatedHeight']})",
    },
    color: {
      conditions: [
        ['${h} >= 120', "color('#f4cf5e', 0.95)"],
        ['${h} >= 60', "color('#d4af37', 0.9)"],
        ['${h} >= 25', "color('#5a4a1c', 0.9)"],
        ['true', "color('#1c1c1c', 0.88)"],
      ],
    },
  });
}

/**
 * Adds OSM Buildings to the scene and returns the tileset (call
 * removeOsmBuildings(viewer, tileset) to take it off again).
 *
 * @param {object} viewer   Cesium.Viewer
 * @param {object} Cesium   The Cesium namespace (import * as Cesium from 'cesium')
 * @param {object} opts
 * @param {string} opts.ionToken  Cesium ion token (CESIUM_ION_TOKEN)
 * @param {boolean} [opts.anansiStyle=true]  Apply the theme; false keeps Cesium's default white
 */
export async function addOsmBuildings(viewer, Cesium, { ionToken, anansiStyle = true } = {}) {
  const token = String(ionToken || '').trim();
  if (!token) throw new Error('OSM Buildings needs a Cesium ion token (CESIUM_ION_TOKEN).');
  const resource = await Cesium.IonResource.fromAssetId(OSM_BUILDINGS_ASSET_ID, { accessToken: token });
  const tileset = await Cesium.Cesium3DTileset.fromUrl(resource, {
    // Buildings are context, not the subject: trade a little detail for frame rate.
    maximumScreenSpaceError: 24,
  });
  if (anansiStyle) tileset.style = anansiBuildingStyle(Cesium);
  viewer.scene.primitives.add(tileset);
  return tileset;
}

export function removeOsmBuildings(viewer, tileset) {
  if (tileset && viewer?.scene?.primitives?.contains(tileset)) viewer.scene.primitives.remove(tileset);
}

/**
 * Convenience: add buildings only when the map fell back to the 'osm' route,
 * i.e. no Google 3D tiles are on screen.
 */
export async function addOsmBuildingsIfNeeded(viewer, Cesium, { route, ionToken, anansiStyle } = {}) {
  if (route && route !== 'osm') return null;
  if (!String(ionToken || '').trim()) return null;
  return addOsmBuildings(viewer, Cesium, { ionToken, anansiStyle });
}
