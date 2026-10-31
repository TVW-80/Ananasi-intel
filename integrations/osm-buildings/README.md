# 3D buildings without Google billing

The Google Photorealistic 3D Tiles layer was blocked because Google wants a payment method on file, even for free-tier use. There are two ways around that. Try them in this order.

## Option 1: Google 3D through Cesium ion (try this first)

The current God's Eye View can load the **same Google Photorealistic 3D tiles through Cesium ion**, which only needs a free ion token. No Google billing is involved. See `selectMapStartupRoute()` in `src/maps/google3d.js`: when `CESIUM_ION_TOKEN` is set, startup takes the `google-ion` route.

1. Create a free account at [ion.cesium.com](https://ion.cesium.com). The Community plan covers eligible personal and non-commercial use, with quotas.
2. Create an access token with **assets:read** scope, and restrict it to your dev URL, since this key is sent to the browser.
3. Add it to `.env`, then restart the dev server:
   ```env
   CESIUM_ION_TOKEN=your-ion-token
   ```

If your Anansi copy predates the ion route (there's no `createGoogleIonTileset` in `src/maps/google3d.js`), use Option 2. You could also update your copy from the newer God's Eye View.

## Option 2: Cesium OSM Buildings (fallback)

[`osmBuildings.js`](osmBuildings.js) adds Cesium's free **OSM Buildings** (ion asset 96188): about 350 million building footprints worldwide, extruded to 3D. They're styled in the Anansi palette: near-black low-rise, warming to bronze and gold with height, so downtown Norfolk's towers stand out.

```js
import * as Cesium from 'cesium';
import { addOsmBuildingsIfNeeded } from './osmBuildings.js';

// `route` is what loadPhotorealisticTileset() reports: 'google-direct' | 'google-token' | 'google-ion' | 'osm'
const buildings = await addOsmBuildingsIfNeeded(viewer, Cesium, {
  route,
  ionToken: import.meta.env.CESIUM_ION_TOKEN, // or however your build exposes it
});
```

- It only adds buildings when the globe landed on the `osm` route. Google 3D already includes buildings, so drawing both would double them up.
- The token is passed to this one resource, not set as Cesium's global default, which matches how the base platform handles credentials.
- `removeOsmBuildings(viewer, buildings)` takes them off again, for example behind a Data Layers toggle.

## Tests

```bash
node --test integrations/osm-buildings/osmBuildings.test.mjs
```

The tests check the asset and token handling, the Google-route guard, and add/remove. With `CESIUM_DIR` pointing at a folder that has `cesium` installed, they also compile the style in real **CesiumJS 1.124**, the version God's Eye View uses, and confirm its colors. That check caught a real bug: buildings with no height recorded would have made the style throw.
