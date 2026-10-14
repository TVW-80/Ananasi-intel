/**
 * @module flipperDetectionsLayer
 *
 * Live map layer for Flipper / Spider Sense surveillance-device detections.
 *
 * Unlike the generic local-GeoJSON layer (which loads once per enable), this
 * one re-fetches `/api/flipper/detections.geojsonl` on `updateInterval` so new
 * detections appear without toggling the layer (feature B). While enabled it
 * also watches the browser's geolocation and POSTs it to /api/flipper/where,
 * so live detections are stamped with your real position instead of the
 * server's FLIPPER_HOME_* default (feature C).
 *
 * Contract mirrors earthquakes.js: init / enable / disable / update /
 * destroy / getStats, with the manager owning the periodic update tick.
 */

import * as Cesium from 'cesium';

const GEOJSONL_URL = '/api/flipper/detections.geojsonl';
const WHERE_URL = '/api/flipper/where';
const WHERE_POST_MIN_MS = 5000; // don't spam the endpoint

/** Parse JSON-Lines text into an array of GeoJSON Features. */
function parseJsonl(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try {
      const f = JSON.parse(s);
      if (f && f.geometry && Array.isArray(f.geometry.coordinates)) out.push(f);
    } catch {
      /* skip a partial/garbled line */
    }
  }
  return out;
}

/**
 * Starts watching the browser position and POSTing it to the sensor proxy, so
 * live detections land at the operator's real location. Returns a stop fn.
 * Safe where geolocation is unavailable or permission is denied — it simply
 * never posts, and the server keeps using its configured home position.
 */
function startGeolocationPump() {
  if (typeof navigator === 'undefined' || !navigator.geolocation) {
    return () => {};
  }
  let lastPost = 0;
  let stopped = false;
  const post = (lat, lon) => {
    const now = Date.now();
    if (now - lastPost < WHERE_POST_MIN_MS) return;
    lastPost = now;
    fetch(WHERE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lat, lon }),
      keepalive: true,
    }).catch(() => { /* best-effort */ });
  };
  let watchId = null;
  try {
    watchId = navigator.geolocation.watchPosition(
      (pos) => {
        if (stopped) return;
        const { latitude, longitude } = pos.coords || {};
        if (Number.isFinite(latitude) && Number.isFinite(longitude)) post(latitude, longitude);
      },
      (err) => { console.warn('[Data:Flipper] geolocation unavailable:', err?.message || err); },
      { enableHighAccuracy: true, maximumAge: 10000, timeout: 20000 },
    );
  } catch (e) {
    console.warn('[Data:Flipper] geolocation watch failed:', e);
  }
  return () => {
    stopped = true;
    if (watchId != null) { try { navigator.geolocation.clearWatch(watchId); } catch { /* noop */ } }
  };
}

export function createFlipperDetectionsLayer() {
  let _dataSource = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  let _enabled = false;
  let _stopGeo = null;

  return {
    id: 'flipper-detections',
    name: 'Flipper Detections',
    icon: '☠',
    source: 'Flipper · Spider Sense · LIVE',
    // Re-fetch every 3 s so new detections appear without toggling. The
    // endpoint is local and tiny (the sensor sees at most a few per second).
    updateInterval: 3000,

    init(viewer) {
      _dataSource = new Cesium.CustomDataSource('flipper-detections');
      _dataSource.show = false;
      viewer.dataSources.add(_dataSource);
      _count = 0;
      _lastUpdate = null;
      _lastError = null;
      _enabled = false;
      console.log('[Data:Flipper] Initialized');
    },

    enable(viewer) {
      _enabled = true;
      if (_dataSource) _dataSource.show = true;
      // Feature C: stamp live detections with the operator's real position.
      if (!_stopGeo) _stopGeo = startGeolocationPump();
    },

    disable(viewer) {
      _enabled = false;
      if (_dataSource) _dataSource.show = false;
      if (_stopGeo) { _stopGeo(); _stopGeo = null; }
    },

    // Feature B: the manager ticks this every updateInterval, so new
    // detections render on their own.
    async update(viewer) {
      try {
        const response = await fetch(GEOJSONL_URL, { cache: 'no-store' });
        if (!response.ok) {
          _lastError = `Flipper HTTP ${response.status}`;
          return false;
        }
        const features = parseJsonl(await response.text());

        _dataSource.entities.removeAll();
        let count = 0;
        for (const f of features) {
          const [lon, lat] = f.geometry.coordinates;
          if (!Number.isFinite(lon) || !Number.isFinite(lat)) continue;
          const p = f.properties || {};
          const color = Cesium.Color.fromCssColorString(p.color || '#00e0ff');
          const rssiTxt = Number.isFinite(p.rssi) ? ` ${p.rssi}dBm` : '';
          count++;
          _dataSource.entities.add({
            id: `flipper:${f.id ?? count}`,
            position: Cesium.Cartesian3.fromDegrees(lon, lat),
            point: {
              pixelSize: 11,
              color,
              outlineColor: Cesium.Color.BLACK,
              outlineWidth: 2,
              heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
              disableDepthTestDistance: Number.POSITIVE_INFINITY,
            },
            label: {
              text: `${p.typeLabel || p.detType || 'Detection'}${rssiTxt}`,
              font: '600 12px monospace',
              fillColor: color,
              outlineColor: Cesium.Color.BLACK,
              outlineWidth: 3,
              style: Cesium.LabelStyle.FILL_AND_OUTLINE,
              verticalOrigin: Cesium.VerticalOrigin.BOTTOM,
              pixelOffset: new Cesium.Cartesian2(0, -14),
              heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
              disableDepthTestDistance: Number.POSITIVE_INFINITY,
              translucencyByDistance: new Cesium.NearFarScalar(2.0e4, 1.0, 3.0e5, 0.0),
            },
            properties: {
              detType: p.detType ?? null,
              vendor: p.vendor ?? null,
              mac: p.mac ?? null,
              rssi: p.rssi ?? null,
              channel: p.channel ?? null,
              confidence: p.confidence ?? null,
              ssid: p.ssid ?? null,
              when: p.when ?? null,
            },
          });
        }
        _count = count;
        _lastUpdate = Date.now();
        _lastError = null;
        return true;
      } catch (e) {
        _lastError = 'Flipper feed unreachable';
        return false;
      }
    },

    destroy(viewer) {
      _enabled = false;
      if (_stopGeo) { _stopGeo(); _stopGeo = null; }
      if (_dataSource) {
        viewer.dataSources.remove(_dataSource, true);
        _dataSource = null;
      }
      _count = 0;
      _lastUpdate = null;
      _lastError = null;
    },

    getStats() {
      return { count: _count, lastUpdate: _lastUpdate, error: _lastError };
    },
  };
}

const flipperDetectionsLayer = createFlipperDetectionsLayer();
export default flipperDetectionsLayer;
