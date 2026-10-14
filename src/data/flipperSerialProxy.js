/**
 * @module flipperSerialProxy
 *
 * Dev-server middleware that links a Flipper-tethered Spider Sense sensor to
 * Anansi. It mirrors the other proxies' shape (a vite plugin whose
 * `configureServer` mounts `/api/flipper`), and follows the AIS-live pattern:
 * accumulate upstream data in memory, let the browser poll an HTTP endpoint.
 *
 * Data path (live):
 *   ESP32 (Spider Sense firmware) --UART--> Flipper --USB-UART bridge--> COM
 *   port --> this middleware parses `SQW,*` lines --> in-memory ring buffer +
 *   a capture CSV --> served as GeoJSONL at /api/flipper/detections.geojsonl.
 *
 * Location: the sensor has neither clock nor GPS, so each live detection is
 * stamped on arrival with the most recent position the browser POSTed to
 * /api/flipper/where (falling back to FLIPPER_HOME_LAT/LON, default the app's
 * Hampton Roads center). For precise per-detection coordinates, drop a capture
 * CSV + a phone GPX into local_data/flipper/ and they are timestamp-matched.
 *
 * `serialport` is an OPTIONAL dependency, imported lazily: if it is not
 * installed (or no board is attached) the live feed simply reports
 * disconnected and the file-import path still works. Nothing here can break the
 * globe's build or the other layers.
 *
 * Endpoints:
 *   GET  /api/flipper                      → { feed, status, count, detections }
 *   GET  /api/flipper/detections.geojsonl  → GeoJSON JSON-Lines (the layer URL)
 *   POST /api/flipper/where {lat,lon}      → set the live stamp position
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseSqwLine,
  parseSqwStat,
  parseDetectionsCsv,
  parseGpx,
  detectionsToFeatures,
  featuresToGeoJsonl,
} from './flipperDetections.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'local_data', 'flipper');

const PORT_NAME = process.env.FLIPPER_PORT || 'COM3';
const BAUD = parseInt(process.env.FLIPPER_BAUD || '115200', 10);
const ENABLED = process.env.FLIPPER_SERIAL !== '0'; // set FLIPPER_SERIAL=0 to disable the live read
const HOME = {
  lat: Number.parseFloat(process.env.FLIPPER_HOME_LAT || '36.8508'),
  lon: Number.parseFloat(process.env.FLIPPER_HOME_LON || '-76.2859'),
};
const RING_CAP = 1000;
const RECONNECT_MS = 5000;

// ---- in-memory state -------------------------------------------------------
const ring = []; // recent detections (each carries its stamped {lat,lon})
let status = null; // latest SQW,STAT
let where = { ...HOME, fromBrowser: false };
const feed = {
  port: PORT_NAME,
  baud: BAUD,
  connected: false,
  error: ENABLED ? null : 'disabled (FLIPPER_SERIAL=0)',
  lastLineAt: 0,
  lines: 0,
  detections: 0,
};

let _port = null;
let _reconnectTimer = null;
let _captureStream = null;
let _captureDay = '';

function pushDetection(det) {
  det.lat = where.lat;
  det.lon = where.lon;
  ring.push(det);
  if (ring.length > RING_CAP) ring.shift();
  feed.detections++;
  appendCapture(det);
}

function appendCapture(det) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const day = new Date(det.tMs).toISOString().slice(0, 10);
    if (day !== _captureDay || !_captureStream) {
      if (_captureStream) _captureStream.end();
      const file = path.join(DATA_DIR, `capture-${day}.csv`);
      const fresh = !fs.existsSync(file);
      _captureStream = fs.createWriteStream(file, { flags: 'a' });
      _captureDay = day;
      if (fresh) _captureStream.write('ts,what,type,conf,mac,rssi,channel,hits,vendor,name\n');
    }
    const iso = new Date(det.tMs).toISOString();
    const clean = (s) => String(s ?? '').replace(/[,\r\n]/g, '_');
    _captureStream.write(
      [iso, det.what, det.type, det.conf, det.mac, det.rssi, det.channel, det.hits,
        clean(det.vendor), clean(det.name)].join(',') + '\n',
    );
  } catch {
    /* capture is best-effort; never let it break the feed */
  }
}

function handleLine(line) {
  feed.lastLineAt = Date.now();
  feed.lines++;
  const stat = parseSqwStat(line);
  if (stat) { status = stat; return; }
  const det = parseSqwLine(line);
  if (det && det.what !== 'SEEN') { // SEEN is a quiet refresh; only map NEW/AGAIN
    det.tMs = Date.now();
    pushDetection(det);
  }
}

// ---- serial connection (lazy, optional) ------------------------------------
async function connect() {
  if (!ENABLED) return;
  let SerialPort;
  try {
    ({ SerialPort } = await import('serialport'));
  } catch {
    feed.error = 'serialport not installed — run `npm i serialport` for the live feed';
    return; // file-import path still works
  }
  let ReadlineParser;
  try {
    ({ ReadlineParser } = await import('@serialport/parser-readline'));
  } catch {
    feed.error = '@serialport/parser-readline not installed';
    return;
  }
  try {
    _port = new SerialPort({ path: PORT_NAME, baudRate: BAUD, autoOpen: false });
    _port.open((err) => {
      if (err) {
        feed.connected = false;
        feed.error = `${PORT_NAME}: ${err.message}`;
        scheduleReconnect();
        return;
      }
      feed.connected = true;
      feed.error = null;
      const parser = _port.pipe(new ReadlineParser({ delimiter: '\n' }));
      parser.on('data', (line) => { try { handleLine(String(line)); } catch { /* ignore one bad line */ } });
    });
    _port.on('error', (err) => { feed.error = `${PORT_NAME}: ${err.message}`; });
    _port.on('close', () => { feed.connected = false; scheduleReconnect(); });
  } catch (err) {
    feed.error = `${PORT_NAME}: ${err?.message || err}`;
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (!ENABLED || _reconnectTimer) return;
  _reconnectTimer = setTimeout(() => {
    _reconnectTimer = null;
    try { _port?.removeAllListeners(); } catch { /* noop */ }
    _port = null;
    connect();
  }, RECONNECT_MS);
}

function dispose() {
  if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
  try { _port?.close?.(); } catch { /* noop */ }
  _port = null;
  try { _captureStream?.end?.(); } catch { /* noop */ }
  _captureStream = null;
}

// ---- file-import fallback --------------------------------------------------
// Any capture-*.csv (+ an optional track.gpx) dropped in local_data/flipper/
// is timestamp-matched and merged into the served GeoJSONL. This is the
// precise, GPS-accurate path and needs no live link.
function importedFeatures() {
  const out = [];
  let gpx = '';
  try {
    const gpxFile = fs.readdirSync(DATA_DIR).find((f) => f.toLowerCase().endsWith('.gpx'));
    if (gpxFile) gpx = fs.readFileSync(path.join(DATA_DIR, gpxFile), 'utf8');
  } catch { /* no dir yet */ }
  const track = parseGpx(gpx);
  let files = [];
  try { files = fs.readdirSync(DATA_DIR).filter((f) => f.toLowerCase().endsWith('.csv')); } catch { /* none */ }
  for (const f of files) {
    try {
      const dets = parseDetectionsCsv(fs.readFileSync(path.join(DATA_DIR, f), 'utf8'));
      const { features } = detectionsToFeatures(dets, { track, fallback: track.length ? null : HOME });
      out.push(...features);
    } catch { /* skip a bad file */ }
  }
  return out;
}

function liveFeatures() {
  // Each ring detection was stamped with its position at arrival; place it
  // there (detectionsToFeatures uses `fallback` when the detection has no GPX
  // match, which is always the case for the live path).
  const placed = [];
  ring.forEach((d, i) => {
    if (!Number.isFinite(d.lat) || !Number.isFinite(d.lon)) return;
    const { features } = detectionsToFeatures([d], { track: [], fallback: { lat: d.lat, lon: d.lon } });
    if (features[0]) { features[0].id = `${features[0].id}:${i}`; placed.push(features[0]); }
  });
  return placed;
}

function geojsonl() {
  const feats = [...liveFeatures(), ...importedFeatures()];
  return featuresToGeoJsonl(feats);
}

// ---- the vite plugin -------------------------------------------------------
export function flipperSerialProxy() {
  return {
    name: 'flipper-serial-proxy',
    configureServer(server) {
      connect();
      server.middlewares.use('/api/flipper', (req, res) => {
        try {
          const url = new URL(req.url || '', 'http://localhost');
          if (req.method === 'POST' && url.pathname === '/where') {
            let body = '';
            req.on('data', (c) => { body += c; if (body.length > 1e4) req.destroy(); });
            req.on('end', () => {
              try {
                const { lat, lon } = JSON.parse(body || '{}');
                if (Number.isFinite(lat) && Number.isFinite(lon)) {
                  where = { lat, lon, fromBrowser: true };
                }
                res.setHeader('Content-Type', 'application/json; charset=utf-8');
                res.end(JSON.stringify({ ok: true, where }));
              } catch {
                res.statusCode = 400;
                res.end(JSON.stringify({ ok: false, error: 'bad JSON' }));
              }
            });
            return;
          }
          if (url.pathname === '/detections.geojsonl') {
            res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.end(geojsonl());
            return;
          }
          // default: status snapshot
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.setHeader('Cache-Control', 'no-store');
          res.end(JSON.stringify({
            feed,
            status,
            where,
            count: ring.length,
            detections: ring.slice(-50),
          }));
        } catch (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: err?.message || 'flipper proxy error' }));
        }
      });
      server.httpServer?.on('close', dispose);
    },
  };
}

export default flipperSerialProxy;
