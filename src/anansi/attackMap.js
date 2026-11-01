/**
 * Anansi Attack Map: attack sources as glowing arcs into Hampton Roads, with
 * "missiles" riding each arc, a live counter, the most-targeted ports and a
 * FortiGuard alert ticker. Data: /api/attackmap (server/providers/anansi/attack-map.js).
 *
 * The counter is an estimate: it runs at DShield's daily average report rate
 * for the top sources and says so on screen.
 *
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
import * as Cesium from 'cesium';
import { registerPickOwner, unregisterPickOwner } from '../data/pickRegistry.js';
import { governorRequestRender, holdContinuousRender, releaseContinuousRender } from '../renderGovernor.js';
import { POINT_LIFT_M, attachThreatClick, detachThreatClick, forgetThreatPoint, registerThreatPoint } from './threatLayers.js';

export const ATTACK_MAP_LAYER = Object.freeze({
  id: 'cyber-attack-map',
  name: 'Attack Map',
  icon: '⌁',
  color: '#ff2b2b',
  source: 'SANS ISC / DShield · AbuseIPDB · FortiGuard RSS',
  updateInterval: 10 * 60_000,
});

const EARTH_RADIUS_M = 6_371_000;
const ARC_SEGMENTS = 64;
const RENDER_HOLD = 'anansi-attack-map';
const ID_PREFIX = 'attackmap:';
const LABEL_LIMIT = 8;

const toRad = (d) => (d * Math.PI) / 180;
const toDeg = (r) => (r * 180) / Math.PI;

/**
 * Great-circle arc from src to dst, lifted into a parabola-like bow.
 * @returns {{lat: number, lon: number, height: number}[]}
 */
export function arcPoints(src, dst, segments = ARC_SEGMENTS) {
  const unit = ({ lat, lon }) => {
    const la = toRad(lat);
    const lo = toRad(lon);
    return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)];
  };
  const a = unit(src);
  const b = unit(dst);
  const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const omega = Math.acos(dot);
  const distance = omega * EARTH_RADIUS_M;
  const peak = Math.min(1_600_000, Math.max(120_000, distance * 0.16));
  const out = [];
  for (let i = 0; i <= segments; i++) {
    const t = i / segments;
    let p;
    if (omega < 1e-9) p = a;
    else {
      const s = Math.sin(omega);
      const wa = Math.sin((1 - t) * omega) / s;
      const wb = Math.sin(t * omega) / s;
      p = [wa * a[0] + wb * b[0], wa * a[1] + wb * b[1], wa * a[2] + wb * b[2]];
    }
    const lat = toDeg(Math.atan2(p[2], Math.hypot(p[0], p[1])));
    const lon = toDeg(Math.atan2(p[1], p[0]));
    out.push({ lat, lon, height: Math.sin(Math.PI * t) * peak });
  }
  return out;
}

/** Gold (weak) → red (strong). */
export function arcColor(weight) {
  const w = Math.max(0, Math.min(1, Number(weight) || 0));
  const lerp = (x, y) => Math.round(x + (y - x) * w);
  return `rgb(${lerp(244, 255)}, ${lerp(207, 43)}, ${lerp(94, 43)})`;
}

/** Counter start: today's estimated total so far at the given rate. */
export function counterStart(perMinute, now = Date.now()) {
  const d = new Date(now);
  const minutes = d.getUTCHours() * 60 + d.getUTCMinutes() + d.getUTCSeconds() / 60;
  return Math.max(0, Math.round(perMinute * minutes));
}

const fmt = (n) => Math.round(n).toLocaleString('en-US');

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ── HUD (counter, sources, ports, FortiGuard ticker) ─────────────────────────
// Docked top-center as a slim strip by default; drag the header to move it, "–" folds it to
// the counter. Position and fold state are remembered in this browser.
const HUD_STORAGE_KEY = 'anansi.attackMapHud';

function readHudPrefs() {
  try {
    return JSON.parse(localStorage.getItem(HUD_STORAGE_KEY) || '{}') || {};
  } catch {
    return {};
  }
}

function writeHudPrefs(patch) {
  try {
    localStorage.setItem(HUD_STORAGE_KEY, JSON.stringify({ ...readHudPrefs(), ...patch }));
  } catch {
    // storage unavailable: the panel still works, it just won't remember
  }
}

/** Keep a dragged position on screen (the window may have shrunk since). */
export function clampHudPosition({ x, y }, { width, height }, viewport) {
  const pad = 8;
  return {
    x: Math.round(Math.min(Math.max(pad, x), Math.max(pad, viewport.width - width - pad))),
    y: Math.round(Math.min(Math.max(pad, y), Math.max(pad, viewport.height - height - pad))),
  };
}

function placeHud(hud) {
  const prefs = readHudPrefs();
  hud.classList.toggle('folded', Boolean(prefs.folded));
  const fold = hud.querySelector('.attack-map-fold');
  if (fold) fold.textContent = prefs.folded ? '+' : '–';
  if (!Number.isFinite(prefs.x) || !Number.isFinite(prefs.y)) {
    hud.style.left = hud.style.top = hud.style.transform = '';
    return;
  }
  const rect = hud.getBoundingClientRect();
  const at = clampHudPosition(prefs, rect, { width: window.innerWidth, height: window.innerHeight });
  hud.style.left = `${at.x}px`;
  hud.style.top = `${at.y}px`;
  hud.style.right = hud.style.bottom = 'auto';
  hud.style.transform = 'none';
}

function wireHudChrome(hud, head, fold) {
  fold.addEventListener('click', (event) => {
    event.stopPropagation();
    const folded = !hud.classList.contains('folded');
    hud.classList.toggle('folded', folded);
    fold.textContent = folded ? '+' : '–';
    fold.title = folded ? 'Expand' : 'Minimize';
    writeHudPrefs({ folded });
  });
  let drag = null;
  head.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || event.target === fold) return;
    const rect = hud.getBoundingClientRect();
    drag = { dx: event.clientX - rect.left, dy: event.clientY - rect.top, rect };
    head.setPointerCapture?.(event.pointerId);
    hud.classList.add('dragging');
  });
  head.addEventListener('pointermove', (event) => {
    if (!drag) return;
    const at = clampHudPosition(
      { x: event.clientX - drag.dx, y: event.clientY - drag.dy },
      drag.rect,
      { width: window.innerWidth, height: window.innerHeight },
    );
    hud.style.left = `${at.x}px`;
    hud.style.top = `${at.y}px`;
    hud.style.right = hud.style.bottom = 'auto';
  hud.style.transform = 'none';
  });
  const end = () => {
    if (!drag) return;
    drag = null;
    hud.classList.remove('dragging');
    writeHudPrefs({ x: parseFloat(hud.style.left), y: parseFloat(hud.style.top) });
  };
  head.addEventListener('pointerup', end);
  head.addEventListener('pointercancel', end);
  head.addEventListener('dblclick', () => {
    // Double-click the header to send it back to its dock.
    writeHudPrefs({ x: null, y: null });
    hud.style.left = hud.style.top = hud.style.right = hud.style.bottom = hud.style.transform = '';
  });
}

function createHud() {
  const hud = el('aside', 'attack-map-hud');
  hud.id = 'attack-map-hud';
  hud.setAttribute('aria-label', 'Attack map');
  const head = el('div', 'attack-map-hud-head');
  const fold = el('button', 'attack-map-fold', '–');
  fold.type = 'button';
  fold.title = 'Minimize';
  fold.setAttribute('aria-label', 'Minimize attack map panel');
  head.append(el('span', 'attack-map-live', '● LIVE'), el('span', 'attack-map-title', 'ATTACK MAP'), fold);
  head.title = 'Drag to move';
  const counter = el('div', 'attack-map-counter', '—');
  const basis = el('div', 'attack-map-basis', 'waiting for DShield…');
  const sourcesTitle = el('div', 'attack-map-sub', 'TOP SOURCES');
  const sources = el('ol', 'attack-map-list');
  const portsTitle = el('div', 'attack-map-sub', 'MOST TARGETED PORTS');
  const ports = el('ol', 'attack-map-list');
  const status = el('div', 'attack-map-status');
  const main = el('div', 'attack-map-main');
  const counterCol = el('div', 'attack-map-col attack-map-col-counter');
  counterCol.append(counter, basis, status);
  const sourcesCol = el('div', 'attack-map-col attack-map-detail');
  sourcesCol.append(sourcesTitle, sources);
  const portsCol = el('div', 'attack-map-col attack-map-detail');
  portsCol.append(portsTitle, ports);
  main.append(counterCol, sourcesCol, portsCol);

  const ticker = el('div', 'attack-map-ticker');
  ticker.setAttribute('aria-label', 'FortiGuard alerts');
  const tag = el('span', 'attack-map-ticker-tag', 'FORTIGUARD');
  const track = el('div', 'attack-map-ticker-track');
  const lane = el('div', 'attack-map-ticker-lane');
  track.append(lane);
  ticker.append(tag, track);
  hud.append(head, main, ticker);
  wireHudChrome(hud, head, fold);

  let rate = 0;
  let value = 0;
  let timer = null;

  return {
    mount() {
      document.body.append(hud);
      placeHud(hud);
      timer ??= setInterval(() => {
        if (!rate) return;
        // Poisson-ish jitter around the average so it feels live without lying about the mean.
        value += (rate / 240) * (0.4 + Math.random() * 1.2);
        counter.textContent = fmt(value);
      }, 250);
    },
    unmount() {
      clearInterval(timer);
      timer = null;
      hud.remove();
    },
    update(body) {
      rate = Number(body?.rate?.perMinute) || 0;
      value = Math.max(value, counterStart(rate));
      counter.textContent = rate ? fmt(value) : '—';
      basis.title = body?.rate?.basis || '';
      basis.textContent = rate
        ? `≈${fmt(rate)}/min · estimate since 00:00 UTC`
        : 'no DShield data yet';
      sources.replaceChildren(
        ...(body.sources || []).slice(0, 4).map((s) => {
          const li = el('li');
          li.append(el('span', null, s.name), el('b', null, s.reports ? fmt(s.reports) : `${fmt(s.abuse)} rep.`));
          li.style.setProperty('--bar', arcColor(s.weight));
          return li;
        }),
      );
      ports.replaceChildren(
        ...(body.ports || []).slice(0, 4).map((p) => {
          const li = el('li');
          li.append(el('span', null, `${p.port}${p.service ? ` · ${p.service}` : ''}`), el('b', null, fmt(p.records)));
          return li;
        }),
      );
      const when = body.updatedAt ? new Date(body.updatedAt).toLocaleTimeString() : '';
      status.textContent = body.status === 'stale' ? `STALE · showing last good data · ${body.errors?.[0] || ''}` : when ? `updated ${when}` : '';
      status.dataset.state = body.status || '';

      const items = body.alerts || [];
      const nodes = items.length
        ? items.map((a) => {
            const node = a.link ? el('a', 'attack-map-ticker-item') : el('span', 'attack-map-ticker-item');
            if (a.link) {
              node.href = a.link;
              node.target = '_blank';
              node.rel = 'noopener noreferrer';
            }
            node.append(el('em', null, `${a.source.toUpperCase()} ▸ `), document.createTextNode(a.title));
            return node;
          })
        : [el('span', 'attack-map-ticker-item', 'No FortiGuard bulletins reachable right now — DShield and AbuseIPDB arcs still update.')];
      // Two copies make the CSS marquee seamless.
      lane.replaceChildren(...nodes, ...nodes.map((n) => n.cloneNode(true)));
      lane.style.setProperty('--ticker-seconds', `${Math.max(40, items.length * 9)}s`);
    },
  };
}

// ── layer ────────────────────────────────────────────────────────────────────
export function createAttackMapLayer({ overlayHost, fetchImpl = (...a) => globalThis.fetch(...a) } = {}) {
  const def = ATTACK_MAP_LAYER;
  let _viewer = null;
  let _ds = null;
  let _enabled = false;
  let _request = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  let _hud = null;
  const overlayId = `anansi-${def.id}`;
  const ownedIds = new Set();

  function clearOwned() {
    for (const id of ownedIds) forgetThreatPoint(id);
    ownedIds.clear();
  }

  function addTarget(target) {
    const position = Cesium.Cartesian3.fromDegrees(target.lon, target.lat, POINT_LIFT_M.local);
    _ds.entities.add({
      id: `${ID_PREFIX}target`,
      position,
      point: {
        pixelSize: new Cesium.CallbackProperty(() => 12 + 8 * Math.abs(Math.sin(performance.now() / 420)), false),
        color: Cesium.Color.fromCssColorString('#ff2b2b').withAlpha(0.35),
        outlineColor: Cesium.Color.fromCssColorString('#ff2b2b'),
        outlineWidth: 2,
      },
    });
  }

  function addArc(source, target, index) {
    const pts = arcPoints(source, target);
    const last = pts.length - 1;
    // Ends meet the (lifted) markers so the depth-tested arc doesn't dive into terrain.
    const positions = pts.map((p, i) =>
      Cesium.Cartesian3.fromDegrees(p.lon, p.lat, p.height + POINT_LIFT_M.world + ((POINT_LIFT_M.local - POINT_LIFT_M.world) * i) / last),
    );
    const css = arcColor(source.weight);
    const color = Cesium.Color.fromCssColorString(css);
    const w = source.weight || 0;
    _ds.entities.add({
      id: `${ID_PREFIX}arc:${source.country}`,
      polyline: {
        positions,
        width: 2 + w * 5,
        arcType: Cesium.ArcType.NONE,
        material: new Cesium.PolylineGlowMaterialProperty({ glowPower: 0.22, taperPower: 0.9, color: color.withAlpha(0.35 + w * 0.45) }),
      },
    });
    // Missiles: 1–3 heads per arc, faster for heavier sources.
    const heads = w > 0.75 ? 3 : w > 0.4 ? 2 : 1;
    const period = 5200 - w * 2400;
    for (let h = 0; h < heads; h++) {
      const offset = (index * 0.137 + h / heads) % 1;
      const scratch = new Cesium.Cartesian3();
      _ds.entities.add({
        id: `${ID_PREFIX}head:${source.country}:${h}`,
        position: Cesium.CallbackPositionProperty
          ? new Cesium.CallbackPositionProperty((time, result) => headAt(positions, period, offset, result || scratch), false)
          : new Cesium.CallbackProperty((time, result) => headAt(positions, period, offset, result || scratch), false),
        point: {
          pixelSize: 4 + w * 4,
          color: Cesium.Color.WHITE.withAlpha(0.95),
          outlineColor: color,
          outlineWidth: 3,
          },
      });
    }
    // Source marker (clickable).
    const markerId = `${ID_PREFIX}src:${source.country}`;
    _ds.entities.add({
      id: markerId,
      position: Cesium.Cartesian3.fromDegrees(source.lon, source.lat, POINT_LIFT_M.world),
      point: {
        pixelSize: 7 + w * 11,
        color: color.withAlpha(0.85),
        outlineColor: Cesium.Color.BLACK.withAlpha(0.9),
        outlineWidth: 2,
      },
    });
    ownedIds.add(markerId);
    registerThreatPoint(markerId, def, {
      title: source.name,
      place: `→ ${target.name}`,
      count: source.ips.length,
      time: null,
      approximate: true,
      items: [
        ...(source.reports ? [{ text: `DShield: ${fmt(source.reports)} reports from its top IPs, ${fmt(source.targets)} targets` }] : []),
        ...(source.abuse ? [{ text: `AbuseIPDB: ${fmt(source.abuse)} reported attacker IPs` }] : []),
        ...source.ips.map((ip) => ({ text: `${ip.ip}${ip.asname ? ` · ${ip.asname}` : ''} · ${fmt(ip.reports)} reports` })),
        { text: 'Arc ends at your vantage point; sensors are worldwide.' },
      ],
    });
    return { id: source.country, position: positions[0], title: `${def.icon} ${source.name}`, accent: css, priority: Math.round(w * 1000) };
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

    enable(viewer) {
      _enabled = true;
      if (_ds) _ds.show = true;
      overlayHost?.setVisible(overlayId, true);
      registerPickOwner(def.id, (id) => ownedIds.has(String(id)) || String(id).startsWith(ID_PREFIX));
      attachThreatClick(viewer || _viewer);
      _hud ??= createHud();
      _hud.mount();
      holdContinuousRender(RENDER_HOLD);
    },

    disable() {
      _request?.abort();
      _request = null;
      _enabled = false;
      if (_ds) _ds.show = false;
      overlayHost?.clearSource(overlayId);
      overlayHost?.setVisible(overlayId, false);
      unregisterPickOwner(def.id);
      clearOwned();
      detachThreatClick();
      _hud?.unmount();
      releaseContinuousRender(RENDER_HOLD);
    },

    async update() {
      if (!_enabled || !_ds) return false;
      _request?.abort();
      const request = new AbortController();
      _request = request;
      try {
        const res = await fetchImpl('/api/attackmap', { signal: request.signal, cache: 'no-store' });
        if (!res.ok) throw new Error(`attack map: HTTP ${res.status}`);
        const body = await res.json();
        if (request.signal.aborted || !_enabled) return false;
        clearOwned();
        _ds.entities.removeAll();
        const target = body.target || { lat: 36.8508, lon: -76.2859, name: 'Hampton Roads' };
        addTarget(target);
        const labels = (body.sources || []).map((s, i) => addArc(s, target, i));
        overlayHost?.setEntries(
          overlayId,
          labels
            .sort((a, b) => b.priority - a.priority)
            .slice(0, LABEL_LIMIT)
            .map((l) => ({
              ...l,
              variant: 'label',
              collisionGroup: 'ambient-label',
              paintLane: 'ambient-label',
              interactive: false,
              edgeFade: 'keyhole',
              horizonCull: true,
              terrainOcclusion: false,
              gapPx: 12,
              verticalOnly: true,
              placement: 'above',
            })),
          { cohortLimit: LABEL_LIMIT, collisionCapacity: LABEL_LIMIT, moving: false },
        );
        _hud?.update(body);
        _count = (body.sources || []).length;
        _lastUpdate = Date.now();
        _lastError = body.status === 'ok' ? null : body.errors?.[0] || null;
        governorRequestRender(`anansi:${def.id}`);
        return true;
      } catch (e) {
        if (request.signal.aborted || !_enabled) return false;
        _lastError = e?.message || 'Attack map unavailable';
        return false;
      } finally {
        if (_request === request) _request = null;
      }
    },

    destroy(viewer = _viewer) {
      if (_enabled) this.disable();
      overlayHost?.clearSource(overlayId);
      if (_ds && viewer) viewer.dataSources.remove(_ds, true);
      _ds = null;
      _viewer = null;
    },

    getStats() {
      return { count: _count, lastUpdate: _lastUpdate, error: _lastError };
    },
  };
}

/** Position of a missile head `offset` of the way through its loop. */
function headAt(positions, period, offset, result) {
  const n = positions.length - 1;
  const phase = ((performance.now() / period) + offset) % 1;
  const f = phase * n;
  const i = Math.min(n - 1, Math.floor(f));
  return Cesium.Cartesian3.lerp(positions[i], positions[i + 1], f - i, result);
}
