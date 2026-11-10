/**
 * Ananzi Sky layer: the live night sky projected onto the globe.
 *
 * Every star, planet, the Sun and the Moon is drawn at the ground point it is
 * directly over right now; constellation stick-figures connect their stars'
 * ground points. Because that point sweeps west as the Earth turns, the whole
 * sky drifts across the globe in real time (recomputed every ~20 s). A body on
 * the far side of the planet is depth-hidden — it is below your horizon.
 *
 * A search box (opens with the layer) finds any of the 88 constellations and
 * flies the camera to where it is overhead at that moment.
 *
 * Data: /api/sky (bundled J2000 catalogue). Planets: astronomy-engine (offline).
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
import * as Cesium from 'cesium';
import * as Astronomy from 'astronomy-engine';
import { registerPickOwner, unregisterPickOwner } from '../data/pickRegistry.js';
import { governorRequestRender, holdContinuousRender, releaseContinuousRender } from '../renderGovernor.js';
import { POINT_LIFT_M, attachThreatClick, detachThreatClick, forgetThreatPoint, registerThreatPoint } from './threatLayers.js';
import { gmstDeg, splitByAntimeridian, starAlpha, starSizePx, subPoint } from './skyMath.js';
import { AJE } from './ajeAlert.js';

export const SKY_LAYER = Object.freeze({
  id: 'sky-overhead',
  name: 'Sky (stars & planets)',
  icon: '✦',
  color: '#f4cf5e',
  source: 'd3-celestial (MIT) · astronomy-engine',
  updateInterval: 20_000,
});

const ID = 'sky:';
const RECOMPUTE_MS = 20_000;
const STAR_LABEL_MAG = 1.7; // only the brightest stars get a name label
// Constellations get a cyan-blue glow (an intentional exception to the gold/red
// theme, for the sky only — the theme guard scans CSS, not this layer).
const LINE_COLOR = '#3fd0ff';
const RENDER_HOLD = 'anansi-sky';

// The sky is drawn as one shell floating well above the globe, so the figures
// read as a dome of light overhead rather than paint stuck to the surface.
const SHELL_STARS = 260_000; // m — stars and the constellation lines that join them
const SHELL_BODIES = 320_000; // m — Sun / Moon / planets sit just above the star field

/** Sun, Moon and the naked-eye planets, with a glyph and an on-theme colour. */
export const BODIES = Object.freeze([
  { body: 'Sun', name: 'Sun', glyph: '☉', color: '#ffcf3f', size: 1.5 },
  { body: 'Moon', name: 'Moon', glyph: '☾', color: '#e6e3d6', size: 1.5 },
  { body: 'Mercury', name: 'Mercury', glyph: '☿', color: '#cfc3a6', size: 1.0 },
  { body: 'Venus', name: 'Venus', glyph: '♀', color: '#ffe9a8', size: 1.3 },
  { body: 'Mars', name: 'Mars', glyph: '♂', color: '#ff6b4a', size: 1.1 },
  { body: 'Jupiter', name: 'Jupiter', glyph: '♃', color: '#e8c98a', size: 1.3 },
  { body: 'Saturn', name: 'Saturn', glyph: '♄', color: '#e8d9a8', size: 1.2 },
  { body: 'Uranus', name: 'Uranus', glyph: '♅', color: '#cfe0c0', size: 0.9 },
  { body: 'Neptune', name: 'Neptune', glyph: '♆', color: '#c6cf9a', size: 0.9 },
]);

/** Glyph billboard for a planet/Sun/Moon (depth-tested, scales with distance). */
function bodyBadge(glyph, color) {
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="44" height="44" viewBox="0 0 44 44">` +
    `<circle cx="22" cy="22" r="13" fill="${color}" fill-opacity="0.18" stroke="${color}" stroke-width="1.5"/>` +
    `<text x="22" y="23" font-size="22" text-anchor="middle" dominant-baseline="central" ` +
    `font-family="'Segoe UI Symbol','Noto Sans Symbols2',sans-serif" fill="${color}" stroke="#0b0a08" stroke-width="2.5" paint-order="stroke">${glyph}</text></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

/** Geocentric-ish equatorial RA(deg)/Dec(deg) of a Solar-System body now. */
export function bodyRaDec(bodyName, date, Astro = Astronomy) {
  const eq = Astro.Equator(bodyName, date, new Astro.Observer(0, 0, 0), true, true);
  return { ra: ((eq.ra * 15) % 360 + 360) % 360, dec: eq.dec };
}

export function createSkyLayer({ overlayHost, fetchImpl = (...a) => globalThis.fetch(...a), now = () => new Date() } = {}) {
  const def = SKY_LAYER;
  let _viewer = null;
  let _ds = null;
  let _enabled = false;
  let _data = null; // { stars, lines, constellations }
  let _timer = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  let _search = null;
  const overlayId = `anansi-${def.id}`;
  const ownedIds = new Set();

  function clearOwned() {
    for (const id of ownedIds) forgetThreatPoint(id);
    ownedIds.clear();
  }

  function pos(lat, lon, lift = 20_000) {
    return Cesium.Cartesian3.fromDegrees(lon, lat, lift);
  }

  /** Recompute every ground point for the current time and redraw. */
  function draw() {
    if (!_enabled || !_ds || !_data) return;
    const date = now();
    const gmst = gmstDeg(date);
    clearOwned();
    _ds.entities.removeAll();
    const labels = [];

    // Stars: plain points, sized and dimmed by magnitude (dots suit stars).
    _data.stars.forEach((s, si) => {
      const [hip, ra, dec, mag, name] = s;
      const p = subPoint(ra, dec, gmst);
      const entityId = `${ID}star:${hip}:${si}`;
      _ds.entities.add({
        id: entityId,
        position: pos(p.lat, p.lon, SHELL_STARS),
        point: {
          pixelSize: starSizePx(mag),
          color: Cesium.Color.fromCssColorString('#fff3d6').withAlpha(starAlpha(mag)),
          disableDepthTestDistance: 0,
        },
      });
      if (name && mag <= STAR_LABEL_MAG) {
        labels.push({ id: `star:${hip}:${si}`, position: pos(p.lat, p.lon, SHELL_STARS), title: name, accent: '#fff3d6', priority: Math.round((6 - mag) * 100) });
      }
      if (name) {
        ownedIds.add(entityId);
        registerThreatPoint(entityId, { ...def, icon: '★', name: 'Star', color: '#fff3d6' }, {
          title: name, place: `Constellation star · ${hip ? `HIP ${hip}` : ''}`, count: 0, time: null, approximate: true,
          items: [{ text: `Magnitude ${mag}`, plain: `A star you can see with the naked eye.`, tech: `RA ${ra.toFixed(2)}°, Dec ${dec.toFixed(2)}° (J2000). Shown over the point it is above right now.` }],
        });
      }
    });

    // Constellation stick-figures: polylines between their stars' ground points.
    let lineSeq = 0;
    for (const con of _data.lines) {
      con.lines.forEach((path, i) => {
        const pts = path.map(([ra, dec]) => subPoint(ra, dec, gmst));
        for (const seg of splitByAntimeridian(pts)) {
          _ds.entities.add({
            // A single line can split into several segments at the antimeridian;
            // a running counter keeps every polyline id unique within the draw.
            id: `${ID}line:${con.abbr}:${i}:${lineSeq++}`,
            polyline: {
              positions: seg.map((q) => pos(q.lat, q.lon, SHELL_STARS)),
              width: 2.4,
              arcType: Cesium.ArcType.NONE,
              // Same floating-glow treatment as the attack-map arcs.
              material: new Cesium.PolylineGlowMaterialProperty({
                glowPower: 0.3,
                taperPower: 0.85,
                color: Cesium.Color.fromCssColorString(LINE_COLOR).withAlpha(0.85),
              }),
            },
          });
        }
      });
    }

    // Constellation name labels + clickable centres. A few abbreviations repeat
    // (Serpens Caput and Cauda both "Ser"), so the index keeps ids unique.
    _data.constellations.forEach((c, ci) => {
      const p = subPoint(c.ra, c.dec, gmst);
      labels.push({ id: `con:${c.abbr}:${ci}`, position: pos(p.lat, p.lon, SHELL_STARS), title: c.name, accent: LINE_COLOR, priority: 400 });
      const cid = `${ID}con:${c.abbr}:${ci}`;
      _ds.entities.add({ id: cid, position: pos(p.lat, p.lon, SHELL_STARS), point: { pixelSize: 4, color: Cesium.Color.fromCssColorString(LINE_COLOR).withAlpha(0.7), disableDepthTestDistance: 0 } });
      ownedIds.add(cid);
      registerThreatPoint(cid, { ...def, icon: '✧', name: 'Constellation', color: '#d4af37' }, {
        title: c.name, place: `Constellation (${c.abbr})`, count: 0, time: null, approximate: true,
        items: [{ text: 'Where it is now', plain: `The ${c.name} constellation is currently above the ocean/land near this point. Use the Sky search box to fly here.`, tech: `Centre RA ${c.ra.toFixed(1)}°, Dec ${c.dec.toFixed(1)}°.` }],
      });
    });

    // Planets, Sun and Moon: distinct glyph badges.
    let planetCount = 0;
    for (const b of BODIES) {
      let rd;
      try {
        rd = bodyRaDec(b.body, date);
      } catch {
        continue;
      }
      const p = subPoint(rd.ra, rd.dec, gmst);
      const id = `${ID}body:${b.body}`;
      _ds.entities.add({
        id,
        position: pos(p.lat, p.lon, SHELL_BODIES),
        billboard: {
          image: bodyBadge(b.glyph, b.color),
          width: Math.round(30 * b.size),
          height: Math.round(30 * b.size),
          scaleByDistance: new Cesium.NearFarScalar(1.5e6, 1.0, 4.0e7, 0.7),
        },
      });
      labels.push({ id: `body:${b.body}`, position: pos(p.lat, p.lon, SHELL_BODIES), title: `${b.glyph} ${b.name}`, accent: b.color, priority: 900 });
      ownedIds.add(id);
      registerThreatPoint(id, { ...def, icon: b.glyph, name: b.name, color: b.color }, {
        title: b.name, place: 'Planet / Solar System body', count: 0, time: null, approximate: true,
        items: [{ text: `Overhead near ${p.lat.toFixed(1)}°, ${p.lon.toFixed(1)}° right now`, plain: `${b.name} is currently directly above this point on Earth.`, tech: `RA ${rd.ra.toFixed(2)}°, Dec ${rd.dec.toFixed(2)}° (of date).` }],
      });
      planetCount += 1;
    }

    // Aje — a personally named star (Star Name Deed). Always drawn, highlighted
    // gold with a ★ so it stands out from the catalogue; its popover carries the
    // deed details. The AJE WATCH card handles "is it visible from home" timing.
    {
      const p = subPoint(AJE.raDeg, AJE.decDeg, gmst);
      const id = `${ID}aje`;
      _ds.entities.add({
        id,
        position: pos(p.lat, p.lon, SHELL_BODIES),
        billboard: {
          image: bodyBadge('★', '#ffd76a'),
          width: 30,
          height: 30,
          scaleByDistance: new Cesium.NearFarScalar(1.5e6, 1.1, 4.0e7, 0.8),
        },
      });
      labels.push({ id: 'aje', position: pos(p.lat, p.lon, SHELL_BODIES), title: '★ Aje', accent: '#ffd76a', priority: 950 });
      ownedIds.add(id);
      registerThreatPoint(id, { ...def, icon: '★', name: 'Aje', color: '#ffd76a' }, {
        title: 'Aje — your named star', place: AJE.designation, count: 0, time: null, approximate: true,
        items: [
          { text: `Named ${AJE.named}`, plain: 'This is Aje, the star named on your Star Name Deed.', tech: `RA ${AJE.raText}, Dec ${AJE.decText}, magnitude ${AJE.magnitude}.` },
          { text: 'Too faint to see by eye', plain: 'At magnitude 10.2 it needs a telescope — the AJE WATCH card tells you when its sky is up in the dark over Williamsburg.', tech: AJE.designation },
        ],
      });
    }

    labels.sort((a, b) => b.priority - a.priority);
    overlayHost?.setEntries(overlayId, labels.slice(0, 60).map((l) => ({
      ...l, variant: 'label', collisionGroup: 'ambient-label', paintLane: 'ambient-label', interactive: false,
      edgeFade: 'keyhole', horizonCull: true, terrainOcclusion: false, gapPx: 10, verticalOnly: true, placement: 'above',
    })), { cohortLimit: 60, collisionCapacity: 60, moving: true });

    _count = _data.stars.length + planetCount;
    _lastUpdate = Date.now();
    governorRequestRender(`anansi:${def.id}`);
  }

  /** Fly the camera to where a constellation (or body) is overhead now. */
  function flyTo(target) {
    if (!_viewer || !_data) return false;
    const date = now();
    const gmst = gmstDeg(date);
    const con = _data.constellations.find((c) => c.abbr.toLowerCase() === target.toLowerCase() || c.name.toLowerCase() === target.toLowerCase());
    let p;
    if (con) {
      p = subPoint(con.ra, con.dec, gmst);
    } else {
      const b = BODIES.find((x) => x.name.toLowerCase() === target.toLowerCase());
      if (!b) return false;
      const rd = bodyRaDec(b.body, date);
      p = subPoint(rd.ra, rd.dec, gmst);
    }
    _viewer.camera.flyTo({ destination: Cesium.Cartesian3.fromDegrees(p.lon, p.lat, 12_000_000), duration: 1.6 });
    return true;
  }

  return {
    id: def.id,
    name: def.name,
    icon: def.icon,
    source: def.source,
    updateInterval: def.updateInterval,
    requiresKeyId: null,

    init(viewer) {
      _viewer = viewer;
      _ds = new Cesium.CustomDataSource(def.id);
      _ds.show = false;
      viewer.dataSources.add(_ds);
      overlayHost?.setVisible(overlayId, false);
    },

    async enable(viewer) {
      _enabled = true;
      if (_ds) _ds.show = true;
      overlayHost?.setVisible(overlayId, true);
      registerPickOwner(def.id, (id) => ownedIds.has(String(id)));
      attachThreatClick(viewer || _viewer);
      holdContinuousRender(RENDER_HOLD);
      _search = createSkySearch(this);
      _search.mount();
      if (!_data) {
        try {
          const res = await fetchImpl('/api/sky', { cache: 'force-cache' });
          if (res.ok) _data = await res.json();
          else _lastError = `sky data HTTP ${res.status}`;
        } catch (e) {
          _lastError = e?.message || 'sky data unavailable';
        }
        _search?.setConstellations(_data?.constellations || []);
      }
      draw();
      _timer ??= setInterval(draw, RECOMPUTE_MS);
    },

    disable() {
      _enabled = false;
      clearInterval(_timer);
      _timer = null;
      if (_ds) _ds.show = false;
      overlayHost?.clearSource(overlayId);
      overlayHost?.setVisible(overlayId, false);
      unregisterPickOwner(def.id);
      clearOwned();
      detachThreatClick();
      _search?.unmount();
      _search = null;
      releaseContinuousRender(RENDER_HOLD);
    },

    async update() {
      if (!_enabled) return false;
      draw();
      return true;
    },

    flyTo,
    searchConstellations: (q) => {
      const query = String(q || '').trim().toLowerCase();
      if (!query) return [];
      return (_data?.constellations || [])
        .filter((c) => c.name.toLowerCase().includes(query) || c.abbr.toLowerCase().includes(query))
        .slice(0, 10);
    },

    destroy(viewer = _viewer) {
      if (_enabled) this.disable();
      overlayHost?.clearSource(overlayId);
      if (_ds && viewer) viewer.dataSources.remove(_ds, true);
      _ds = null;
      _viewer = null;
    },

    getStats() {
      return { count: _count, lastUpdate: _lastUpdate, error: _count > 0 ? null : _lastError };
    },
  };
}

// ── search box (mounted with the layer) ──────────────────────────────────────
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function createSkySearch(layer) {
  const box = el('div', 'sky-search');
  box.id = 'sky-search';
  const label = el('div', 'sky-search-label', '✦ FIND A CONSTELLATION');
  const input = el('input', 'sky-search-input');
  input.type = 'search';
  input.placeholder = 'Orion, Ursa Major, a planet…';
  input.setAttribute('aria-label', 'Find a constellation or planet');
  const results = el('ul', 'sky-search-results');
  box.append(label, input, results);
  let constellations = [];

  const planetRows = BODIES.map((b) => ({ abbr: '', name: b.name, glyph: b.glyph }));

  function render(q) {
    const query = q.trim().toLowerCase();
    results.replaceChildren();
    if (!query) return;
    const cons = constellations.filter((c) => c.name.toLowerCase().includes(query) || c.abbr.toLowerCase().includes(query));
    const planets = planetRows.filter((b) => b.name.toLowerCase().includes(query));
    const items = [...planets.map((b) => ({ name: b.name, hint: `${b.glyph} planet / body`, key: b.name })), ...cons.map((c) => ({ name: c.name, hint: c.abbr, key: c.abbr }))].slice(0, 10);
    for (const it of items) {
      const li = el('li');
      const btn = el('button', null);
      btn.type = 'button';
      btn.append(el('span', 'sky-res-name', it.name), el('span', 'sky-res-hint', it.hint));
      btn.addEventListener('click', () => {
        layer.flyTo(it.key || it.name);
        input.value = it.name;
        results.replaceChildren();
      });
      li.append(btn);
      results.append(li);
    }
    if (!items.length) results.append(el('li', 'sky-search-empty', 'No match — try a full name like “Cassiopeia”.'));
  }

  input.addEventListener('input', () => render(input.value));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const first = results.querySelector('button');
      if (first) first.click();
    }
  });

  return {
    mount() {
      document.body.append(box);
    },
    unmount() {
      box.remove();
    },
    setConstellations(list) {
      constellations = Array.isArray(list) ? list : [];
    },
  };
}
