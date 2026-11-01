// Anansi: Sundown Towns (historical) — loads a research dataset YOU supply.
//
// No records are bundled with Anansi. Drop files into
//   src/data/local_data/sundown/        (or set SUNDOWN_DATA_DIR)
// and the "Sundown Towns (historical)" layer reads them:
//
//   *.geojson / *.json   GeoJSON FeatureCollection of points
//   *.csv / *.tsv / *.txt with latitude/longitude columns, OR with a Census
//                        GEOID column plus a Census Gazetteer places file
//                        (e.g. 2020_Gaz_place_national.txt) in the same folder
//
// Columns are matched by common names (see COLUMN_ALIASES). The evidence
// rating (Loewen / Tougaloo style: surely, probable, possible, unlikely,
// don't know) drives icon color and size. Everything here describes what the
// source records historically — it is not a statement about any town today.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'src', 'data', 'local_data', 'sundown');

export const COLUMN_ALIASES = Object.freeze({
  lat: ['latitude', 'lat', 'intptlat', 'y', 'place_lat', 'centroid_lat'],
  lon: ['longitude', 'lon', 'lng', 'long', 'intptlong', 'intptlon', 'x', 'place_lon', 'centroid_lon'],
  name: ['name', 'town', 'place', 'place_name', 'city', 'municipality', 'namelsad', 'town_name'],
  state: ['state', 'stusps', 'state_abbr', 'st', 'state_name', 'statename'],
  status: ['status', 'confidence', 'certainty', 'sundown_status', 'loewen_status', 'category', 'classification', 'rating', 'evidence'],
  notes: ['notes', 'note', 'description', 'summary', 'comments'],
  source: ['source', 'sources', 'citation', 'reference'],
  geoid: ['geoid', 'geoid20', 'geoid10', 'placefp_full', 'place_geoid', 'fips'],
});

/** Evidence levels, strongest first: color, relative size, plain label. */
export const EVIDENCE = Object.freeze({
  surely: { rank: 4, severity: 1.0, color: '#c81e1e', label: 'Surely (strong evidence)' },
  probable: { rank: 3, severity: 0.72, color: '#e0702a', label: 'Probable' },
  possible: { rank: 2, severity: 0.48, color: '#d4af37', label: 'Possible' },
  unlikely: { rank: 1, severity: 0.25, color: '#8a8a7a', label: 'Unlikely' },
  unrated: { rank: 0, severity: 0.3, color: '#a8842a', label: 'Not rated / unknown' },
});

export function evidenceLevel(value) {
  const v = String(value ?? '').trim().toLowerCase();
  if (!v) return 'unrated';
  if (/^(surely|sure|certain|confirmed|definite)/.test(v)) return 'surely';
  if (/^(probabl|likely)/.test(v)) return 'probable';
  if (/^possib/.test(v)) return 'possible';
  if (/^(unlikely|not likely|improbable|no\b|not a sundown)/.test(v)) return 'unlikely';
  return 'unrated';
}

// ── parsing ──────────────────────────────────────────────────────────────────
/** RFC-4180-ish CSV/TSV parser (quoted fields, escaped quotes, CRLF). */
export function parseDelimited(text) {
  const src = String(text).replace(/^﻿/, '');
  const firstLine = src.split(/\r?\n/, 1)[0] || '';
  const delim = (firstLine.match(/\t/g) || []).length > (firstLine.match(/,/g) || []).length ? '\t' : (firstLine.includes('|') && !firstLine.includes(',') ? '|' : ',');
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"' && src[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"' && field === '') quoted = true;
    else if (c === delim) { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((f) => f.trim() !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((f) => f.trim() !== '')) rows.push(row);
  if (!rows.length) return [];
  const header = rows[0].map((h) => h.trim());
  return rows.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, (r[i] ?? '').trim()])));
}

function pick(record, kind) {
  const keys = Object.keys(record);
  for (const alias of COLUMN_ALIASES[kind]) {
    const key = keys.find((k) => k.trim().toLowerCase() === alias);
    if (key !== undefined && String(record[key]).trim() !== '') return String(record[key]).trim();
  }
  return '';
}

const num = (v) => {
  const t = String(v ?? '').trim();
  if (t === '') return null; // an empty cell is "no coordinate", never 0
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
};

function isGazetteer(rows) {
  const keys = Object.keys(rows[0] || {}).map((k) => k.toLowerCase());
  return keys.includes('geoid') && keys.includes('intptlat') && keys.some((k) => k.startsWith('intptlong')) && !keys.some((k) => COLUMN_ALIASES.status.includes(k));
}

/** Records from one parsed file (array of objects) -> towns (lat/lon may be missing). */
function recordsToTowns(records, file) {
  return records.map((r) => ({
    name: pick(r, 'name'),
    state: pick(r, 'state'),
    lat: num(pick(r, 'lat')),
    lon: num(pick(r, 'lon')),
    geoid: pick(r, 'geoid').replace(/\D/g, ''),
    level: evidenceLevel(pick(r, 'status')),
    statusText: pick(r, 'status'),
    notes: pick(r, 'notes'),
    source: pick(r, 'source'),
    file,
  }));
}

function geojsonToTowns(json, file) {
  const features = Array.isArray(json?.features) ? json.features : [];
  return features
    .filter((f) => f?.geometry?.type === 'Point' && Array.isArray(f.geometry.coordinates))
    .map((f) => {
      const [lon, lat] = f.geometry.coordinates;
      const t = recordsToTowns([f.properties || {}], file)[0];
      return { ...t, lat: num(lat), lon: num(lon) };
    });
}

/**
 * Turn the folder's files into map points.
 * @param {{name: string, text: string}[]} files
 */
export function buildSundownPoints(files) {
  const gazetteer = new Map();
  const towns = [];
  const notes = [];
  for (const { name, text } of files) {
    const lower = name.toLowerCase();
    try {
      if (lower.endsWith('.geojson') || lower.endsWith('.json')) {
        towns.push(...geojsonToTowns(JSON.parse(text), name));
        continue;
      }
      const rows = parseDelimited(text);
      if (isGazetteer(rows)) {
        for (const r of rows) {
          const keys = Object.keys(r);
          const g = r[keys.find((k) => k.toLowerCase() === 'geoid')].replace(/\D/g, '');
          const lat = num(r[keys.find((k) => k.toLowerCase() === 'intptlat')]);
          const lon = num(r[keys.find((k) => k.toLowerCase().startsWith('intptlong'))]);
          if (g && lat !== null && lon !== null) gazetteer.set(g, { lat, lon });
        }
        notes.push(`${name}: Census gazetteer (${gazetteer.size} places)`);
        continue;
      }
      towns.push(...recordsToTowns(rows, name));
    } catch (err) {
      notes.push(`${name}: could not read (${err.message})`);
    }
  }
  let placed = 0;
  let unplaced = 0;
  const points = [];
  for (const t of towns) {
    let { lat, lon } = t;
    if ((lat === null || lon === null) && t.geoid && gazetteer.has(t.geoid)) ({ lat, lon } = gazetteer.get(t.geoid));
    if (lat === null || lon === null || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
      unplaced += 1;
      continue;
    }
    placed += 1;
    const ev = EVIDENCE[t.level];
    const where = [t.name || 'Unnamed place', t.state].filter(Boolean).join(', ');
    points.push({
      id: `sundown:${t.geoid || `${t.name}|${t.state}|${lat.toFixed(4)},${lon.toFixed(4)}`}`,
      lat,
      lon,
      title: t.name || 'Unnamed place',
      place: where,
      detail: ev.label,
      count: 1,
      severity: ev.severity,
      color: ev.color,
      level: t.level,
      time: null,
      approximate: false,
      items: [
        { text: `Evidence: ${t.statusText || ev.label}` },
        ...(t.notes ? [{ text: t.notes }] : []),
        ...(t.source ? [{ text: `Source: ${t.source}` }] : []),
        { text: 'Historical record — describes past practices, not the town today.' },
      ],
    });
  }
  points.sort((a, b) => EVIDENCE[b.level].rank - EVIDENCE[a.level].rank);
  return { points, total: towns.length, placed, unplaced, notes };
}

/** Read every supported file in the folder (sync; the folder is small and local). */
export function readSundownFolder(dir = process.env.SUNDOWN_DATA_DIR || DEFAULT_DIR) {
  let names = [];
  try {
    names = readdirSync(dir).filter((n) => /\.(csv|tsv|txt|geojson|json)$/i.test(n) && !/^readme/i.test(n));
  } catch {
    return { dir, files: [], signature: 'missing' };
  }
  const files = names.map((name) => {
    const full = path.join(dir, name);
    return { name, text: readFileSync(full, 'utf8'), mtime: statSync(full).mtimeMs };
  });
  return { dir, files, signature: files.map((f) => `${f.name}@${f.mtime}`).join('|') || 'empty' };
}

/** Feed entry for threat-intel's FEEDS table (local, no network). */
let _memo = { signature: null, body: null };
export function loadSundownFeed() {
  const folder = readSundownFolder();
  if (_memo.signature === folder.signature) return _memo.body;
  if (!folder.files.length) {
    _memo = { signature: folder.signature, body: { points: [], total: 0, empty: true, error: `No data yet — add a sundown-towns CSV or GeoJSON to ${path.relative(process.cwd(), folder.dir) || folder.dir} (see README there)` } };
    return _memo.body;
  }
  const built = buildSundownPoints(folder.files);
  const error = built.points.length ? null : `Read ${built.total} rows but none had coordinates — add latitude/longitude columns or a Census gazetteer file to join on GEOID`;
  _memo = { signature: folder.signature, body: { ...built, error } };
  return _memo.body;
}
