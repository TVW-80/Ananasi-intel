/**
 * Anansi Cyber layers: threat-intel feeds as icons on the globe.
 *
 * Each layer polls /api/threat/<feed> (server/providers/anansi/threat-intel.js),
 * draws one point per record (country-level feeds are grouped at the country's
 * center; Shodan results sit at their real coordinates), labels the biggest
 * ones through the world-overlay host, and shows a detail popover on click.
 *
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
import * as Cesium from 'cesium';
import { registerPickOwner, unregisterPickOwner, resolvePickId } from '../data/pickRegistry.js';
import { governorRequestRender } from '../renderGovernor.js';
import { getFocus, inFocus, onFocusChange } from './focus.js';
import { glyphBillboard } from './markerIcons.js';

/**
 * Layer definitions: id, feeds it merges, look, and attribution. `keyId` names
 * the POWER UP registry entry (src/keySetupCore.mjs) a layer needs, so its row
 * says which key to paste when the feed reports key-required.
 */
export const THREAT_LAYERS = Object.freeze([
  { id: 'cyber-botnet-c2', name: 'Botnet C2 Servers', icon: '☣', feeds: ['feodo'], color: '#ff2b2b', source: 'abuse.ch Feodo Tracker', updateInterval: 15 * 60_000 },
  { id: 'cyber-reported-attackers', name: 'Reported Attackers', icon: '⚑', feeds: ['abuseipdb'], keyId: 'abuseipdb', color: '#ff8a1f', source: 'AbuseIPDB', updateInterval: 60 * 60_000 },
  { id: 'cyber-ransomware', name: 'Ransomware Victims', icon: '☠', feeds: ['ransomware'], color: '#e0457b', source: 'ransomware.live', updateInterval: 30 * 60_000 },
  { id: 'cyber-internet-outages', name: 'Internet Outages', icon: '⚡', feeds: ['ioda', 'ioda-us'], color: '#f4cf5e', source: 'IODA · Georgia Tech', updateInterval: 10 * 60_000 },
  { id: 'cyber-outage-reports', name: 'Outage Reports', icon: '⚠', feeds: ['cloudflare'], keyId: 'cloudflare-radar', color: '#e8d9a8', source: 'Cloudflare Radar', updateInterval: 30 * 60_000 },
  // Shodan layers follow the WORLD / 757 focus server-side (world = per-country counts, 757 = around Norfolk).
  { id: 'cyber-ics-exposure', name: 'Exposed ICS', icon: '⚙', feeds: ['shodan-ics'], keyId: 'shodan', color: '#d4af37', source: 'Shodan', updateInterval: 60 * 60_000 },
  // Lives in the Cameras group: how many internet-exposed cameras, never which ones (no IPs, no images).
  { id: 'exposed-cameras', name: 'Exposed Cameras', icon: '◉', feeds: ['shodan-cameras'], keyId: 'shodan', color: '#e8a33c', source: 'Shodan (counts only)', updateInterval: 60 * 60_000 },
  // History: a dataset you supply (src/data/local_data/sundown). Icons are colored by evidence level.
  { id: 'history-sundown-towns', name: 'Sundown Towns (historical)', icon: '◐', feeds: ['sundown'], color: '#c81e1e', source: 'Your sundown-towns research file (local)', updateInterval: 5 * 60_000, focusFilter: false },
]);

const LABEL_LIMIT = 40;
// Country-level points from different layers share a country's center; give
// each layer its own small offset around it so icons don't stack.
const SLOT_RADIUS_DEG = 1.6;

/** Offset an approximate (country-center) point by the layer's slot. */
export function slotPosition(lat, lon, slot, approximate) {
  if (!approximate) return { lat, lon };
  const angle = (slot * 60 * Math.PI) / 180;
  const dLat = SLOT_RADIUS_DEG * Math.sin(angle);
  const dLon = (SLOT_RADIUS_DEG * Math.cos(angle)) / Math.max(0.2, Math.cos((lat * Math.PI) / 180));
  return { lat: Math.max(-85, Math.min(85, lat + dLat)), lon: ((lon + dLon + 540) % 360) - 180 };
}
const ID_PREFIX = 'threat:';

/**
 * Icons are depth-tested so the globe hides the ones on its far side. They sit
 * a little above the ground so terrain doesn't swallow them: country-level
 * points clear the highest plateaus, exact local points stay close.
 */
export const POINT_LIFT_M = Object.freeze({ world: 9000, local: 400 });
export const liftFor = (approximate) => (approximate ? POINT_LIFT_M.world : POINT_LIFT_M.local);

// ── shared click popover ─────────────────────────────────────────────────────
const _pointsById = new Map(); // entity id -> { layer, point }
let _popover = null;
let _clickHandler = null;
let _clickUsers = 0;

function popoverEl() {
  if (_popover) return _popover;
  _popover = document.createElement('div');
  _popover.id = 'threat-popover';
  _popover.hidden = true;
  _popover.setAttribute('role', 'dialog');
  _popover.setAttribute('aria-label', 'Threat details');
  document.body.appendChild(_popover);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hidePopover();
  });
  return _popover;
}

export function hidePopover() {
  if (_popover) _popover.hidden = true;
}

function text(tag, cls, value) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  el.textContent = value;
  return el;
}

function showPopover({ layer, point }, screen) {
  const el = popoverEl();
  const head = text('div', 'threat-popover-head', `${layer.icon} ${layer.name}`);
  head.style.setProperty('--threat-color', layer.color);
  const close = text('button', 'threat-popover-close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', 'Close');
  close.addEventListener('click', hidePopover);
  head.appendChild(close);
  const title = text('div', 'threat-popover-title', point.title);
  const meta = text(
    'div',
    'threat-popover-meta',
    [point.place, point.approximate ? 'country-level position' : null, point.time ? new Date(point.time).toLocaleString() : null]
      .filter(Boolean)
      .join(' · '),
  );
  const list = document.createElement('ul');
  list.className = 'threat-popover-items';
  for (const item of point.items || []) {
    const li = text('li', null, item.text);
    // Two voices: what it means in plain words, then the analyst's jargon.
    if (item.plain) li.appendChild(text('div', 'threat-popover-plain', item.plain));
    if (item.tech) li.appendChild(text('div', 'threat-popover-tech', item.tech));
    list.appendChild(li);
  }
  const more = point.count && point.count > (point.items || []).length ? text('div', 'threat-popover-more', `+${point.count - point.items.length} more`) : null;
  const src = text('div', 'threat-popover-source', `Source: ${layer.source}`);
  el.replaceChildren(head, title, meta, list, ...(more ? [more] : []), src);
  el.hidden = false;
  const pad = 12;
  const w = el.offsetWidth || 320;
  const h = el.offsetHeight || 200;
  el.style.left = `${Math.min(Math.max(pad, screen.x + 14), window.innerWidth - w - pad)}px`;
  el.style.top = `${Math.min(Math.max(pad, screen.y + 14), window.innerHeight - h - pad)}px`;
}

function attachClick(viewer) {
  _clickUsers += 1;
  if (_clickHandler) return;
  _clickHandler = new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
  _clickHandler.setInputAction((event) => {
    const picked = viewer.scene.pick(event.position);
    const id = picked ? resolvePickId(picked) : null;
    const hit = id && _pointsById.get(String(id));
    if (hit) showPopover(hit, event.position);
    else hidePopover();
  }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
}

function detachClick() {
  _clickUsers = Math.max(0, _clickUsers - 1);
  if (_clickUsers === 0 && _clickHandler) {
    _clickHandler.destroy();
    _clickHandler = null;
    hidePopover();
  }
}

/** Shared with the Attack Map layer, so every Cyber icon opens the same popover. */
export const attachThreatClick = attachClick;
export const detachThreatClick = detachClick;
export function registerThreatPoint(entityId, layer, point) {
  _pointsById.set(String(entityId), { layer, point });
}
export function forgetThreatPoint(entityId) {
  _pointsById.delete(String(entityId));
}

// ── layer factory ────────────────────────────────────────────────────────────
export async function fetchFeeds(feeds, { fetchImpl = globalThis.fetch, signal, focus = 'world', filter = true } = {}) {
  const bodies = await Promise.all(
    feeds.map(async (feed) => {
      const res = await fetchImpl(`/api/threat/${feed}?focus=${encodeURIComponent(focus)}`, { signal, cache: 'no-store' });
      if (!res.ok) throw new Error(`${feed}: HTTP ${res.status}`);
      return res.json();
    }),
  );
  const points = new Map();
  for (const body of bodies) {
    for (const p of body.points || []) {
      // Server-side focused feeds (Shodan) already answer for the focus; the rest are filtered here.
      if (filter && !body.focused && !inFocus(p, focus)) continue;
      if (!points.has(p.id)) points.set(p.id, p);
    }
  }
  const usable = bodies.filter((b) => b.status === 'ok' || b.status === 'stale');
  const keyMissing = bodies.find((b) => b.status === 'key-required');
  const failed = bodies.find((b) => b.status === 'error' || b.status === 'stale' || (b.status === 'no-data' && b.error) || (b.error && !(b.points || []).length));
  return {
    points: [...points.values()],
    error: !usable.length && keyMissing ? keyMissing.error : failed?.error || null,
    keyRequired: !usable.length && Boolean(keyMissing),
  };
}

export function createThreatLayer(def, { overlayHost, fetchImpl } = {}) {
  let _viewer = null;
  let _dataSource = null;
  let _enabled = false;
  let _request = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  let _keyRequired = false;
  let _offFocus = null;
  const overlayId = `anansi-${def.id}`;
  const ownedIds = new Set();
  const slot = Math.max(0, THREAT_LAYERS.findIndex((l) => l.id === def.id));

  function clearOwned() {
    for (const id of ownedIds) _pointsById.delete(id);
    ownedIds.clear();
  }

  return {
    id: def.id,
    name: def.name,
    icon: def.icon,
    source: def.source,
    updateInterval: def.updateInterval,
    requiresKeyId: def.keyId || null,

    init(viewer) {
      _viewer = viewer;
      _dataSource = new Cesium.CustomDataSource(def.id);
      _dataSource.show = false;
      viewer.dataSources.add(_dataSource);
      overlayHost?.setVisible(overlayId, false);
    },

    enable(viewer) {
      _enabled = true;
      if (_dataSource) _dataSource.show = true;
      overlayHost?.setVisible(overlayId, true);
      registerPickOwner(def.id, (pickedId) => ownedIds.has(String(pickedId)));
      attachClick(viewer || _viewer);
      // WORLD / 757 switch: redraw right away instead of waiting for the next poll.
      if (def.focusFilter !== false) _offFocus = onFocusChange(() => this.update());
    },

    disable() {
      _request?.abort();
      _request = null;
      _enabled = false;
      _offFocus?.();
      _offFocus = null;
      if (_dataSource) _dataSource.show = false;
      overlayHost?.clearSource(overlayId);
      overlayHost?.setVisible(overlayId, false);
      unregisterPickOwner(def.id);
      clearOwned();
      detachClick();
    },

    async update() {
      if (!_enabled || !_dataSource) return false;
      _request?.abort();
      const request = new AbortController();
      _request = request;
      try {
        const { points, error, keyRequired } = await fetchFeeds(def.feeds, {
          fetchImpl,
          signal: request.signal,
          focus: getFocus(),
          filter: def.focusFilter !== false,
        });
        if (request.signal.aborted || !_enabled) return false;
        clearOwned();
        _dataSource.entities.removeAll();
        const labels = [];
        for (const p of points) {
          const entityId = `${ID_PREFIX}${p.id}`;
          const at = slotPosition(p.lat, p.lon, slot, p.approximate);
          const position = Cesium.Cartesian3.fromDegrees(at.lon, at.lat, liftFor(p.approximate));
          // Each layer's own glyph (the symbol beside its name in Data Layers),
          // as a depth-tested billboard badge — so layers look different, not
          // like identical dots.
          _dataSource.entities.add(
            new Cesium.Entity({
              id: entityId,
              position,
              billboard: glyphBillboard(Cesium, def.icon, p.color || def.color, { scale: 0.85 + (p.severity || 0) * 0.7 }),
            }),
          );
          ownedIds.add(entityId);
          _pointsById.set(entityId, { layer: def, point: p });
          labels.push({
            id: p.id,
            position,
            variant: 'label',
            title: `${def.icon} ${p.title}`,
            accent: p.color || def.color,
            priority: Math.round((p.severity || 0) * 1000) + Math.min(999, p.count || 0),
            collisionGroup: 'ambient-label',
            paintLane: 'ambient-label',
            interactive: false,
            edgeFade: 'keyhole',
            horizonCull: true,
            terrainOcclusion: false,
            gapPx: 12,
            verticalOnly: true,
            placement: 'above',
          });
        }
        labels.sort((a, b) => b.priority - a.priority);
        overlayHost?.setEntries(overlayId, labels.slice(0, LABEL_LIMIT), { cohortLimit: LABEL_LIMIT, collisionCapacity: LABEL_LIMIT, moving: false });
        _count = points.length;
        _lastUpdate = Date.now();
        _lastError = error;
        _keyRequired = Boolean(keyRequired && def.keyId);
        governorRequestRender(`anansi:${def.id}`);
        return true;
      } catch (e) {
        if (request.signal.aborted || !_enabled) return false;
        _lastError = e?.message || 'Threat feed unavailable';
        return false;
      } finally {
        if (_request === request) _request = null;
      }
    },

    destroy(viewer = _viewer) {
      if (_enabled) this.disable();
      overlayHost?.clearSource(overlayId);
      if (_dataSource && viewer) viewer.dataSources.remove(_dataSource, true);
      _dataSource = null;
      _viewer = null;
    },

    getStats() {
      // Honest chip state without crying wolf: a missing key is always
      // surfaced; while the layer is still showing records, a failed or stale
      // refresh reads STALE (data on screen is just older), not DEGRADED; only
      // a layer with nothing to show reports the hard error.
      if (_keyRequired) return { count: _count, lastUpdate: _lastUpdate, error: 'KEY REQUIRED', keyRequired: true };
      if (_count > 0) return { count: _count, lastUpdate: _lastUpdate, stale: Boolean(_lastError), note: _lastError || null };
      return { count: _count, lastUpdate: _lastUpdate, error: _lastError };
    },
  };
}

/** All Cyber layers, wired to the application overlay host. */
export function createThreatLayers(options = {}) {
  return THREAT_LAYERS.map((def) => createThreatLayer(def, options));
}
