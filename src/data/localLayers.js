import { createLocalGeoJsonLayer } from './localGeojson.js';
import { createFirmsHeatmapLayer } from './firmsHeatmap.js';
import { createFlipperDetectionsLayer } from './flipperDetectionsLayer.js';
import submarineCablesLayer from './telegeographySubmarineCables.js';

// Use Vite's ?url import to properly resolve these assets in dev and build
import datacentersUrl from './local_data/datacenters/datacenters.geojsonl?url';
import damsUrl from './local_data/dams/dams.geojsonl?url';

/**
 * Registry of local GeoJSON datasets.
 * These are lazily loaded natively into Cesium when enabled.
 */
const datacenters = createLocalGeoJsonLayer({
  id: 'local-datacenters',
  url: datacentersUrl,
  name: 'Datacenters',
  color: '#00ffff', // Cyan
  icon: '▣',
  source: 'Local',
  labels: true,
  labelMax: 700,
  labelGridPx: 138,
});

const dams = createLocalGeoJsonLayer({
  id: 'local-dams',
  url: damsUrl,
  name: 'Dams',
  color: '#0088ff', // Blue
  icon: '▰',
  source: 'USACE',
  labels: true,
  labelMax: 900,
  labelGridPx: 132,
});

// Live NASA FIRMS fires (VIIRS ×3 NRT via the /api/firms proxy). The id keeps
// the historical `local-` prefix for persistence + voice-tool-enum compat,
// but the data is NOT bundled anymore — it needs FIRMS_MAP_KEY server-side.
const fires = createFirmsHeatmapLayer({
  id: 'local-firms',
  name: 'FIRMS Active Fires',
  icon: '▲',
  source: 'NASA FIRMS · LIVE',
});

// Surveillance devices detected in the field by a Flipper-tethered Spider
// Sense sensor, served as GeoJSONL by the dev-server middleware
// (vite.config.js flipperSerialProxy). A dedicated live layer: it re-fetches
// on an interval so new detections appear without toggling, and while enabled
// it posts the browser's position so live detections are placed accurately.
// See src/data/flipperDetectionsLayer.js, flipperSerialProxy.js, flipperDetections.js.
const flipperDetections = createFlipperDetectionsLayer();

export default [
  datacenters,
  dams,
  submarineCablesLayer,
  fires,
  flipperDetections,
];
