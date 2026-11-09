// Ananzi: Sky data provider.
//
//   GET /api/sky   → { stars, lines, constellations }
//
// Serves the bundled star catalogue, constellation stick-figures and
// constellation label points (src/data/local_data/sky/anansi/, converted from
// the MIT-licensed d3-celestial dataset by ofrohn). All static and offline —
// read once, held in memory, served with a long cache. No network, no key.
//
// Coordinates are J2000: star/line/label positions are [raDeg(0..360), decDeg].
// The client turns them into live ground points (skyMath.js) and adds the
// planets, Sun and Moon from astronomy-engine.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'src', 'data', 'local_data', 'sky', 'anansi');

let _payload = null;
let _error = null;
export function loadSky(dir = DIR) {
  if (_payload || _error) return { payload: _payload, error: _error };
  try {
    const read = (name) => JSON.parse(readFileSync(path.join(dir, name), 'utf8'));
    const stars = read('stars.json');
    const lines = read('constellation-lines.json');
    const cons = read('constellations.json');
    _payload = {
      epoch: stars.epoch || 'J2000',
      // Compact star rows: [hip, raDeg, decDeg, mag, name?].
      stars: Array.isArray(stars.stars) ? stars.stars : [],
      lines: Array.isArray(lines.lines) ? lines.lines : [],
      constellations: Array.isArray(cons.constellations) ? cons.constellations : [],
    };
  } catch (err) {
    _error = err?.message || String(err);
  }
  return { payload: _payload, error: _error };
}

export function createSkyMiddleware({ load = loadSky } = {}) {
  return function skyMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        // Static bundle; let the browser keep it for the session.
        'Cache-Control': 'public, max-age=86400',
      });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    const { payload, error } = load();
    if (!payload) return send(500, { error: `sky data unavailable: ${error}` });
    return send(200, payload);
  };
}

export function skyProxy() {
  const middleware = createSkyMiddleware();
  return {
    name: 'anansi-sky',
    configureServer(server) {
      server.middlewares.use('/api/sky', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/sky', middleware);
    },
  };
}
