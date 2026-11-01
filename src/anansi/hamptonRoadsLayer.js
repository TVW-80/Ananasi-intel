/**
 * Hampton Roads 757 as a data layer.
 *
 * Turning the layer on starts the 757 feed (traffic, VDOT roadwork, weather,
 * ships, WJCC news via n8n — src/data/hamptonRoads757.js), plots every item
 * that has a location as an icon on the map, and shows the 757 list panel.
 * Turning it off stops the polling and hides the panel.
 *
 * Items without coordinates are grouped onto one marker per kind (news at
 * Williamsburg, weather at Norfolk) so they are still one click away.
 *
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
import * as Cesium from 'cesium';
import hamptonRoads757Feed from '../data/hamptonRoads757.js';
import { registerPickOwner, unregisterPickOwner } from '../data/pickRegistry.js';
import { governorRequestRender } from '../renderGovernor.js';
import { POINT_LIFT_M, attachThreatClick, detachThreatClick, forgetThreatPoint, registerThreatPoint } from './threatLayers.js';

export const HAMPTON_ROADS_LAYER = Object.freeze({
  id: 'local-hampton-roads-757',
  name: 'Hampton Roads 757',
  icon: '◆',
  color: '#d4af37',
  source: 'Your n8n flows (TomTom, NWS, WJCC, VDOT 511) · AISStream',
  updateInterval: 45_000,
});

export const KINDS = Object.freeze({
  traffic: { label: 'Traffic', glyph: '🚦', color: '#ff8a1f' },
  roadwork: { label: 'Roadwork', glyph: '🚧', color: '#f4cf5e' },
  weather: { label: 'Weather', glyph: '⛈', color: '#e8d9a8' },
  ships: { label: 'Ships', glyph: '🚢', color: '#d4af37' },
  news: { label: 'News', glyph: '📰', color: '#e0457b' },
});

/** Where grouped items without coordinates are pinned. */
const ANCHORS = Object.freeze({
  news: { lat: 37.2707, lon: -76.7075, place: 'Williamsburg / James City County' },
  weather: { lat: 36.8508, lon: -76.2859, place: 'Hampton Roads' },
});

const PANEL_ID = 'hampton-roads-panel';
const PANEL_OFF_CLASS = 'layer-off';
const ID_PREFIX = 'hr757:';
const LABEL_LIMIT = 12;

const num = (v) => {
  if (v === null || v === undefined || String(v).trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

/** Pull a lat/lon out of the shapes n8n flows and the AIS picture produce. */
export function itemPosition(item) {
  const m = item?.metadata || {};
  const coords = item?.geometry?.coordinates || m.geometry?.coordinates;
  const candidates = [
    [item?.lat, item?.lng ?? item?.lon],
    [item?.latitude, item?.longitude],
    [m.lat, m.lng ?? m.lon],
    [m.latitude, m.longitude],
    Array.isArray(coords) && typeof coords[0] === 'number' ? [coords[1], coords[0]] : [null, null],
    // LineString / multi-point: first vertex.
    Array.isArray(coords?.[0]) && typeof coords[0][0] === 'number' ? [coords[0][1], coords[0][0]] : [null, null],
  ];
  for (const [la, lo] of candidates) {
    const lat = num(la);
    const lon = num(lo);
    if (lat !== null && lon !== null && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && !(lat === 0 && lon === 0)) return { lat, lon };
  }
  return null;
}

function itemTitle(item) {
  return String(item?.label || item?.title || item?.metadata?.title || item?.name || 'Untitled').trim();
}

function itemDetail(kind, item) {
  const m = item?.metadata || {};
  if (kind === 'traffic') {
    const road = [m.from, m.to].filter(Boolean).join(' → ');
    return [road, m.delay ? `delay ${Math.round(m.delay / 60)} min` : null, m.severity ? `severity ${m.severity}` : null].filter(Boolean).join(' · ');
  }
  if (kind === 'roadwork') return [m.crossingName || m.road, item.severity || m.severity].filter(Boolean).join(' · ');
  if (kind === 'ships') return [m.zone || m.portZone, m.type || item.type, m.speed != null ? `${m.speed} kn` : null].filter(Boolean).join(' · ');
  if (kind === 'news') return [m.source, m.pubDate ? new Date(m.pubDate).toLocaleString() : null].filter(Boolean).join(' · ');
  return String(m.description || m.summary || item.type || '').slice(0, 200);
}

/**
 * Feed state → map points (one per located item, plus grouped anchors).
 * Pure, so it is unit-tested without Cesium.
 */
export function buildHamptonRoadsPoints(state) {
  const points = [];
  const grouped = {};
  for (const kind of Object.keys(KINDS)) {
    const items = Array.isArray(state?.[kind]) ? state[kind] : [];
    items.forEach((item, index) => {
      const at = itemPosition(item);
      const title = itemTitle(item);
      const detail = itemDetail(kind, item);
      if (!at) {
        if (ANCHORS[kind]) (grouped[kind] ??= []).push({ title, detail, link: item?.metadata?.link });
        return;
      }
      const severity = Math.max(0, Math.min(1, (Number(item?.metadata?.severity ?? item?.severity) || 1) / 4));
      points.push({
        id: `${kind}:${index}:${at.lat.toFixed(4)},${at.lon.toFixed(4)}`,
        kind,
        lat: at.lat,
        lon: at.lon,
        title,
        place: `${KINDS[kind].glyph} ${KINDS[kind].label}`,
        severity,
        count: 1,
        items: [...(detail ? [{ text: detail }] : []), ...(item?.metadata?.link ? [{ text: item.metadata.link }] : [])],
      });
    });
  }
  for (const [kind, list] of Object.entries(grouped)) {
    const a = ANCHORS[kind];
    points.push({
      id: `${kind}:group`,
      kind,
      lat: a.lat,
      lon: a.lon,
      title: `${list.length} ${KINDS[kind].label.toLowerCase()} item${list.length === 1 ? '' : 's'}`,
      place: `${KINDS[kind].glyph} ${a.place}`,
      severity: 0.6,
      count: list.length,
      items: list.slice(0, 12).map((x) => ({ text: x.detail ? `${x.title} — ${x.detail}` : x.title })),
    });
  }
  return points;
}

function setPanelVisible(visible) {
  const panel = typeof document !== 'undefined' ? document.getElementById(PANEL_ID) : null;
  panel?.classList.toggle(PANEL_OFF_CLASS, !visible);
}

export function createHamptonRoadsLayer({ overlayHost, feed = hamptonRoads757Feed } = {}) {
  const def = HAMPTON_ROADS_LAYER;
  let _viewer = null;
  let _ds = null;
  let _enabled = false;
  let _unsubscribe = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  const overlayId = `anansi-${def.id}`;
  const ownedIds = new Set();

  function clearOwned() {
    for (const id of ownedIds) forgetThreatPoint(id);
    ownedIds.clear();
  }

  function draw(state) {
    if (!_enabled || !_ds) return;
    clearOwned();
    _ds.entities.removeAll();
    const points = buildHamptonRoadsPoints(state);
    const labels = [];
    for (const p of points) {
      const entityId = `${ID_PREFIX}${p.id}`;
      const kind = KINDS[p.kind];
      const position = Cesium.Cartesian3.fromDegrees(p.lon, p.lat, POINT_LIFT_M.local);
      _ds.entities.add({
        id: entityId,
        position,
        point: {
          pixelSize: 8 + Math.round(p.severity * 8),
          color: Cesium.Color.fromCssColorString(kind.color).withAlpha(0.9),
          outlineColor: Cesium.Color.BLACK.withAlpha(0.9),
          outlineWidth: 2,
        },
      });
      ownedIds.add(entityId);
      registerThreatPoint(entityId, { ...def, icon: kind.glyph, name: `757 · ${kind.label}`, color: kind.color }, p);
      labels.push({
        id: p.id,
        position,
        variant: 'label',
        title: `${kind.glyph} ${p.title.length > 38 ? `${p.title.slice(0, 37)}…` : p.title}`,
        accent: kind.color,
        priority: Math.round(p.severity * 1000) + (p.kind === 'traffic' || p.kind === 'roadwork' ? 200 : 0),
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
    _lastUpdate = state?.lastUpdate || null;
    _lastError = state?.error || null;
    governorRequestRender(`anansi:${def.id}`);
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
      setPanelVisible(false);
    },

    enable(viewer) {
      _enabled = true;
      if (_ds) _ds.show = true;
      overlayHost?.setVisible(overlayId, true);
      registerPickOwner(def.id, (id) => ownedIds.has(String(id)));
      attachThreatClick(viewer || _viewer);
      setPanelVisible(true);
      _unsubscribe = feed.subscribe(draw);
      feed.start();
    },

    disable() {
      _enabled = false;
      _unsubscribe?.();
      _unsubscribe = null;
      feed.stop();
      if (_ds) _ds.show = false;
      overlayHost?.clearSource(overlayId);
      overlayHost?.setVisible(overlayId, false);
      unregisterPickOwner(def.id);
      clearOwned();
      detachThreatClick();
      setPanelVisible(false);
    },

    /** The feed polls on its own timer; the manager's tick just redraws. */
    async update() {
      if (!_enabled) return false;
      draw(feed.getState());
      return true;
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
