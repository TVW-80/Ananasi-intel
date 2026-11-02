/**
 * Ananzi Attack Map. Data: /api/attackmap (server/providers/anansi/attack-map.js).
 *
 *   WORLD (default): pulsing hotspots per attacking country, coloured by the
 *                    attack type they send most (blocklist.de)
 *   757 focus:       the same sources as glowing arcs into Hampton Roads, and
 *                    only the US slice of everything below (focus.js)
 *   amber dotted arcs / rings      internet route hijacks / leaks (Cloudflare BGP)
 *   green dots                     phishing sites (OpenPhish)
 *   pink dashed arcs               Cloudflare Radar DDoS origin → target pairs
 *   purple dots                    malware command servers (ThreatFox)
 *   HUD                            estimated counter, attack types, a rotating
 *                                  view (sources / ports / DDoS industries /
 *                                  DDoS targets / exploited now), alert ticker,
 *                                  and BRIEF: every alert in plain English AND
 *                                  technical terms, a legend, and source status
 *
 * Every arc and dot is clickable; popup lines carry the same two voices.
 * The counter is an estimate at DShield's daily average rate and says so.
 *
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
import * as Cesium from 'cesium';
import { registerPickOwner, unregisterPickOwner } from '../data/pickRegistry.js';
import { governorRequestRender, holdContinuousRender, releaseContinuousRender } from '../renderGovernor.js';
import { POINT_LIFT_M, attachThreatClick, detachThreatClick, forgetThreatPoint, registerThreatPoint } from './threatLayers.js';
import { FOCUS_757, createFocusToggle, getFocus, onFocusChange } from './focus.js';
import { COLORS, renderLegend } from './legend.js';

export const ATTACK_MAP_LAYER = Object.freeze({
  id: 'cyber-attack-map',
  name: 'Attack Map',
  icon: '⌁',
  color: '#ff2b2b',
  source: 'DShield · AbuseIPDB · blocklist.de · Cloudflare Radar · abuse.ch · OTX · GreyNoise · Shadowserver · Spamhaus · Tor · CISA KEV · FortiGuard',
  updateInterval: 10 * 60_000,
});

const EARTH_RADIUS_M = 6_371_000;
const ARC_SEGMENTS = 64;
const RENDER_HOLD = 'anansi-attack-map';
const ID_PREFIX = 'attackmap:';
const LABEL_LIMIT = 8;
const DDOS_COLOR = '#e0457b';
const MALWARE_COLOR = '#c04dd8';

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

/** Pure: which colour an arc gets. Attack type wins; otherwise strength. */
export function sourceColor(source, attackTypes = []) {
  const t = source?.dominantService && attackTypes.find((a) => a.service === source.dominantService);
  return t?.color || arcColor(source?.weight);
}

/** Two-voice tooltip text: plain first, then the jargon. */
export function twoVoice(plain, technical) {
  return [plain, technical ? `TECH: ${technical}` : ''].filter(Boolean).join('\n');
}

const ROTATING_VIEWS = Object.freeze([
  { id: 'sources', title: 'TOP SOURCES' },
  { id: 'ports', title: 'TARGETED PORTS' },
  { id: 'industries', title: 'DDOS · HIT INDUSTRIES' },
  { id: 'targets', title: 'DDOS · TARGET COUNTRIES' },
  { id: 'exploited', title: 'EXPLOITED NOW' },
  { id: 'exposure', title: 'EXPOSED WORLDWIDE' },
]);

function createHud() {
  const hud = el('aside', 'attack-map-hud');
  hud.id = 'attack-map-hud';
  hud.setAttribute('aria-label', 'Attack map');
  const head = el('div', 'attack-map-hud-head');
  const brief = el('button', 'attack-map-brief-btn', 'BRIEF');
  brief.type = 'button';
  brief.title = 'Open the briefing: every alert in plain English and technical terms, a map legend and source status';
  brief.setAttribute('aria-expanded', 'false');
  const fold = el('button', 'attack-map-fold', '–');
  fold.type = 'button';
  fold.title = 'Minimize';
  fold.setAttribute('aria-label', 'Minimize attack map panel');
  const focusBtn = createFocusToggle(document);
  head.append(el('span', 'attack-map-live', '● LIVE'), el('span', 'attack-map-title', 'ATTACK MAP'), focusBtn, brief, fold);
  head.title = 'Drag to move · double-click to re-dock';
  const counter = el('div', 'attack-map-counter', '—');
  const basis = el('div', 'attack-map-basis', 'waiting for DShield…');
  const status = el('div', 'attack-map-status');
  const typesTitle = el('div', 'attack-map-sub', 'ATTACK TYPES · 48H');
  const types = el('ol', 'attack-map-list');
  const rotTitle = el('button', 'attack-map-sub attack-map-rotate', 'TOP SOURCES');
  rotTitle.type = 'button';
  rotTitle.title = 'Click for the next view';
  const rot = el('ol', 'attack-map-list');
  const main = el('div', 'attack-map-main');
  const counterCol = el('div', 'attack-map-col attack-map-col-counter');
  counterCol.append(counter, basis, status);
  const typesCol = el('div', 'attack-map-col attack-map-detail');
  typesCol.append(typesTitle, types);
  const rotCol = el('div', 'attack-map-col attack-map-detail');
  rotCol.append(rotTitle, rot);
  main.append(counterCol, typesCol, rotCol);

  const ticker = el('div', 'attack-map-ticker');
  ticker.setAttribute('aria-label', 'Threat alerts');
  const tag = el('span', 'attack-map-ticker-tag', 'INTEL');
  const track = el('div', 'attack-map-ticker-track');
  const lane = el('div', 'attack-map-ticker-lane');
  track.append(lane);
  ticker.append(tag, track);

  const panel = el('div', 'attack-map-brief');
  panel.hidden = true;
  hud.append(head, main, ticker, panel);
  wireHudChrome(hud, head, fold);
  for (const type of ['pointerdown', 'dblclick']) brief.addEventListener(type, (e) => e.stopPropagation());
  brief.addEventListener('click', (event) => {
    event.stopPropagation();
    panel.hidden = !panel.hidden;
    brief.setAttribute('aria-expanded', String(!panel.hidden));
    brief.classList.toggle('active', !panel.hidden);
  });

  let rate = 0;
  let value = 0;
  let timer = null;
  let rotateTimer = null;
  let view = 0;
  let last = {};

  const li = (label, valueText, { color, tip } = {}) => {
    const item = el('li');
    item.append(el('span', null, label), el('b', null, valueText));
    if (color) item.style.setProperty('--bar', color);
    if (tip) item.title = tip;
    return item;
  };

  function renderRotating() {
    // Skip views with no data.
    for (let i = 0; i < ROTATING_VIEWS.length; i++) {
      const v = ROTATING_VIEWS[(view + i) % ROTATING_VIEWS.length];
      const rows = rotatingRows(v.id);
      if (rows.length) {
        view = (view + i) % ROTATING_VIEWS.length;
        rotTitle.textContent = `${v.title} ▸`;
        rot.replaceChildren(...rows.slice(0, 4));
        return;
      }
    }
    rotTitle.textContent = 'TOP SOURCES';
    rot.replaceChildren();
  }

  function rotatingRows(id) {
    const b = last;
    if (id === 'sources') {
      return (b.sources || []).map((s) =>
        li(s.name, s.reports ? fmt(s.reports) : s.abuse ? `${fmt(s.abuse)} rep.` : `${s.blocklist} seen`, {
          color: sourceColor(s, b.attackTypes),
          tip: `${s.name}: ${s.reports ? `${fmt(s.reports)} DShield reports` : ''}${s.abuse ? ` · ${fmt(s.abuse)} AbuseIPDB` : ''}${s.blocklist ? ` · ${s.blocklist} blocklist.de samples` : ''}`,
        }),
      );
    }
    if (id === 'ports') return (b.ports || []).map((p) => li(`${p.port}${p.service ? ` · ${p.service}` : ''}`, fmt(p.records), { tip: twoVoice(p.plain, p.technical) }));
    if (id === 'industries') return (b.ddos?.industries || []).map((i) => li(i.name, `${i.value.toFixed(1)}%`, { color: '#e0457b', tip: twoVoice(i.plain, i.technical) }));
    if (id === 'targets') return (b.ddos?.targets || []).map((t) => li(t.name, `${t.value.toFixed(1)}%`, { color: '#e0457b', tip: twoVoice(`${t.name} was on the receiving end of ${t.value.toFixed(1)}% of blocked web attacks.`, `Cloudflare Radar L7 top target locations (zone billing country), 24h.`) }));
    if (id === 'exploited') return (b.exploited || []).map((x) => li(x.vulnerability || x.title, '', { color: '#ff8a1f', tip: twoVoice(x.plain, x.technical) }));
    if (id === 'exposure') return (b.exposure || []).map((e) => li(e.label, fmt(e.total), { color: '#d4af37', tip: twoVoice(e.plain, e.technical) }));
    return [];
  }
  rotTitle.addEventListener('click', () => {
    view = (view + 1) % ROTATING_VIEWS.length;
    renderRotating();
  });

  function renderBrief(b) {
    const section = (title, nodes) => {
      const sec = el('section', 'attack-map-brief-section');
      sec.append(el('h4', null, title), ...nodes);
      return sec;
    };
    const explain = (heading, plain, technical, { color, link, source, details = [] } = {}) => {
      const card = el('article', 'attack-map-brief-card');
      if (color) card.style.setProperty('--bar', color);
      const h = el('div', 'attack-map-brief-title');
      if (source) h.append(el('em', null, `${source} ▸ `));
      if (link) {
        const a = el('a', null, heading);
        a.href = link;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        h.append(a);
      } else h.append(document.createTextNode(heading));
      card.append(h);
      if (plain) card.append(el('p', 'attack-map-plain', plain));
      if (technical) card.append(el('p', 'attack-map-tech', technical));
      // Extra two-voice lines: EPSS odds, MITRE ATT&CK techniques.
      for (const d of details) {
        const sub = el('div', 'attack-map-brief-detail');
        const label = d.link ? el('a', null, d.label) : el('span', null, d.label);
        if (d.link) {
          label.href = d.link;
          label.target = '_blank';
          label.rel = 'noopener noreferrer';
        }
        sub.append(label);
        if (d.plain) sub.append(el('p', 'attack-map-plain', d.plain));
        if (d.technical) sub.append(el('p', 'attack-map-tech', d.technical));
        card.append(sub);
      }
      return card;
    };
    const typeCards = (b.attackTypes || []).map((t) => explain(`${t.label} — ${fmt(t.count)} attackers (48h)`, t.plain, t.technical, { color: t.color }));
    const legend = [renderLegend(document, { only: ['focus', 'attack-map'] }), ...typeCards];
    const alerts = (b.alerts || []).map((a) => explain(a.title, a.plain, a.technical, { link: a.link, source: a.source, details: a.details || [] }));
    const feeds = (b.feeds || []).map((f) => {
      const row = el('div', `attack-map-feed attack-map-feed-${f.status}`);
      const note = f.status === 'key-required'
        ? `needs ${f.keyEnv} — add it in POWER UP`
        : f.status === 'ok'
          ? 'live'
          : f.status === 'stale'
            ? `showing last good data${f.error ? ` · ${f.error}` : ''}`
            : f.status === 'off'
              ? `off${f.keyEnv ? ` (${f.keyEnv})` : ''}`
              : f.error || f.status;
      row.append(el('span', null, f.label), el('b', null, note));
      return row;
    });
    const exposure = (b.exposure || []).map((e) => {
      const card = explain(`${e.label} — ${fmt(e.total)} exposed worldwide`, e.plain, e.technical, { color: '#d4af37' });
      if (e.top?.length) card.append(el('p', 'attack-map-tech', `TOP: ${e.top.map((t) => `${t.country} ${fmt(t.count)}`).join(' · ')}`));
      return card;
    });
    const sections = [
      section('ALERTS — PLAIN ENGLISH + TECHNICAL', alerts.length ? alerts : [el('p', 'attack-map-plain', 'No alerts yet — add keys in POWER UP or wait for the next refresh.')]),
    ];
    if (exposure.length) sections.push(section('EXPOSED TO THE INTERNET (Shodan counts, free)', exposure));
    sections.push(
      section('WHAT YOU’RE LOOKING AT (full key: LEGEND, bottom-right)', legend),
      section('SOURCES', feeds),
    );
    panel.replaceChildren(...sections);
  }

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
      rotateTimer ??= setInterval(() => {
        view = (view + 1) % ROTATING_VIEWS.length;
        renderRotating();
      }, 8000);
    },
    unmount() {
      focusBtn.dispose?.();
      clearInterval(timer);
      clearInterval(rotateTimer);
      timer = rotateTimer = null;
      hud.remove();
    },
    update(body) {
      last = body || {};
      rate = Number(body?.rate?.perMinute) || 0;
      value = Math.max(value, counterStart(rate));
      counter.textContent = rate ? fmt(value) : '—';
      basis.title = body?.rate?.basis || '';
      basis.textContent = rate ? `≈${fmt(rate)}/min · estimate since 00:00 UTC` : 'no DShield data yet';
      const typeRows = (body.attackTypes || []).slice(0, 4).map((t) => li(t.label, fmt(t.count), { color: t.color, tip: twoVoice(t.plain, t.technical) }));
      typesTitle.textContent = typeRows.length ? 'ATTACK TYPES · 48H' : 'ATTACK TYPES';
      types.replaceChildren(...(typeRows.length ? typeRows : [li('blocklist.de not reachable yet', '')]));
      renderRotating();
      const when = body.updatedAt ? new Date(body.updatedAt).toLocaleTimeString() : '';
      const live = (body.feeds || []).filter((f) => f.status === 'ok').length;
      status.textContent = body.status === 'stale'
        ? `STALE · showing last good data · ${body.errors?.[0] || ''}`
        : `${live}/${(body.feeds || []).length} sources live${when ? ` · ${when}` : ''}`;
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
            node.title = twoVoice(a.plain, a.technical);
            node.append(el('em', null, `${a.source.toUpperCase()} ▸ `), document.createTextNode(a.title));
            return node;
          })
        : [el('span', 'attack-map-ticker-item', 'No alerts reachable right now — arcs still update. Open BRIEF to see which sources are live.')];
      // Two copies make the CSS marquee seamless.
      lane.replaceChildren(...nodes, ...nodes.map((n) => n.cloneNode(true)));
      lane.style.setProperty('--ticker-seconds', `${Math.max(50, items.length * 10)}s`);
      renderBrief(body);
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
  let _offFocus = null;
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

  /** Lifted arc positions so the depth-tested line meets its (lifted) end markers. */
  function liftedArc(from, to, fromLift, toLift) {
    const pts = arcPoints(from, to);
    const last = pts.length - 1;
    return pts.map((p, i) => Cesium.Cartesian3.fromDegrees(p.lon, p.lat, p.height + fromLift + ((toLift - fromLift) * i) / last));
  }

  function addHeads(key, positions, color, w, index) {
    // Missiles: 1–3 heads per arc, faster for heavier sources.
    const heads = w > 0.75 ? 3 : w > 0.4 ? 2 : 1;
    const period = 5200 - w * 2400;
    for (let h = 0; h < heads; h++) {
      const offset = (index * 0.137 + h / heads) % 1;
      const scratch = new Cesium.Cartesian3();
      _ds.entities.add({
        id: `${ID_PREFIX}head:${key}:${h}`,
        position: new Cesium.CallbackPositionProperty((time, result) => headAt(positions, period, offset, result || scratch), false),
        point: { pixelSize: 4 + w * 4, color: Cesium.Color.WHITE.withAlpha(0.95), outlineColor: color, outlineWidth: 3 },
      });
    }
  }

  /** Register an entity for the shared Cyber popover (works for arcs and dots alike). */
  function clickable(entityId, point) {
    ownedIds.add(entityId);
    registerThreatPoint(entityId, def, point);
  }

  function addArc(source, target, index, attackTypes) {
    const positions = liftedArc(source, target, POINT_LIFT_M.world, POINT_LIFT_M.local);
    const css = sourceColor(source, attackTypes);
    const color = Cesium.Color.fromCssColorString(css);
    const w = source.weight || 0;
    const arcId = `${ID_PREFIX}arc:${source.country}`;
    _ds.entities.add({
      id: arcId,
      polyline: {
        positions,
        width: 2 + w * 5,
        arcType: Cesium.ArcType.NONE,
        material: new Cesium.PolylineGlowMaterialProperty({ glowPower: 0.22, taperPower: 0.9, color: color.withAlpha(0.35 + w * 0.45) }),
      },
    });
    addHeads(source.country, positions, color, w, index);
    const markerId = `${ID_PREFIX}src:${source.country}`;
    _ds.entities.add({
      id: markerId,
      position: Cesium.Cartesian3.fromDegrees(source.lon, source.lat, POINT_LIFT_M.world),
      point: { pixelSize: 7 + w * 11, color: color.withAlpha(0.85), outlineColor: Cesium.Color.BLACK.withAlpha(0.9), outlineWidth: 2 },
    });
    const point = sourcePopup(source, attackTypes, target);
    clickable(markerId, point);
    clickable(arcId, point);
    return { id: source.country, position: positions[0], title: `${def.icon} ${source.name}`, accent: css, priority: Math.round(w * 1000) };
  }

  /** Popup for an attack-source country (shared by WORLD hotspots and 757 arcs). */
  function sourcePopup(source, attackTypes, target) {
    const dominant = attackTypes.find((t) => t.service === source.dominantService);
    const flagLines = [];
    if (source.flags?.tor) flagLines.push({ text: `${source.flags.tor} via Tor`, plain: 'Some of these came through Tor, an anonymity network — the real attacker could be anywhere.', tech: 'Source IPs match the Tor Project bulk exit list.' });
    if (source.flags?.drop) flagLines.push({ text: `${source.flags.drop} from criminal netblocks`, plain: 'Some addresses belong to blocks of the internet run by criminals or stolen from their owners.', tech: 'Source IPs fall inside Spamhaus DROP netblocks.' });
    return {
      title: source.name,
      place: target ? `→ ${target.name}` : 'attack source (WORLD view)',
      count: 0,
      time: null,
      approximate: true,
      items: [
        ...(dominant ? [{ text: `Mostly: ${dominant.label}`, plain: dominant.plain, tech: dominant.technical }] : []),
        ...(source.reports ? [{ text: `DShield: ${fmt(source.reports)} reports from its top IPs, ${fmt(source.targets)} targets`, plain: 'How often SANS’s worldwide decoy sensors saw these addresses attacking.', tech: 'Sum of DShield topips “reports” (blocked packets) and unique targets.' }] : []),
        ...(source.abuse ? [{ text: `AbuseIPDB: ${fmt(source.abuse)} reported attacker IPs`, plain: 'Addresses other server owners reported for attacks.', tech: 'AbuseIPDB blacklist, confidence 100, grouped by country.' }] : []),
        ...flagLines,
        ...source.ips.flatMap((ip) => ip.lines || [{ text: ip.ip }]),
        ...(target ? [{ text: 'The arc ends at your vantage point; the sensors are worldwide.' }] : []),
      ],
    };
  }

  /** WORLD focus: a pulsing hotspot per attacking country (no vantage arcs). */
  function addHotspot(source, attackTypes) {
    const css = sourceColor(source, attackTypes);
    const color = Cesium.Color.fromCssColorString(css);
    const w = source.weight || 0;
    const id = `${ID_PREFIX}src:${source.country}`;
    const phase = (source.country.charCodeAt(0) * 37) % 1000;
    _ds.entities.add({
      id,
      position: Cesium.Cartesian3.fromDegrees(source.lon, source.lat, POINT_LIFT_M.world),
      point: {
        pixelSize: new Cesium.CallbackProperty(() => 8 + w * 16 + 3 * Math.abs(Math.sin((performance.now() + phase) / 520)), false),
        color: color.withAlpha(0.8),
        outlineColor: color.withAlpha(0.35),
        outlineWidth: 6,
      },
    });
    clickable(id, sourcePopup(source, attackTypes, null));
    return { id: source.country, position: Cesium.Cartesian3.fromDegrees(source.lon, source.lat, POINT_LIFT_M.world), title: `${def.icon} ${source.name}`, accent: css, priority: Math.round(w * 1000) };
  }

  /** BGP hijack: amber dotted arc hijacker → victim (same-country hijacks become a ring). */
  function addHijack(h, index) {
    const color = Cesium.Color.fromCssColorString(COLORS.hijack);
    const id = `${ID_PREFIX}bgp:${h.id}`;
    const point = { title: h.title, place: `${h.from.name} → ${h.to.name}`, count: 0, time: h.time, approximate: true, items: [{ text: `${h.ongoing ? 'Ongoing' : 'Ended'} · confidence ${h.confidence}/10`, plain: h.plain, tech: h.technical }] };
    if (h.domestic) {
      _ds.entities.add({ id, position: Cesium.Cartesian3.fromDegrees(h.from.lon + 1.6, h.from.lat, POINT_LIFT_M.world), point: { pixelSize: 12, color: color.withAlpha(0.05), outlineColor: color, outlineWidth: 2 } });
      clickable(id, point);
      return;
    }
    const positions = liftedArc(h.from, h.to, POINT_LIFT_M.world, POINT_LIFT_M.world);
    _ds.entities.add({
      id,
      polyline: { positions, width: 2.5, arcType: Cesium.ArcType.NONE, material: new Cesium.PolylineDashMaterialProperty({ color: color.withAlpha(0.9), dashLength: 6, dashPattern: 0b1100110011001100 }) },
    });
    addHeads(`bgp:${h.id}`, positions, color, 0.3, index + 13);
    clickable(id, point);
  }

  /** BGP route leak: amber ring at the leaking network's country. */
  function addLeak(l) {
    const id = `${ID_PREFIX}leak:${l.id}`;
    const color = Cesium.Color.fromCssColorString(COLORS.hijack);
    _ds.entities.add({ id, position: Cesium.Cartesian3.fromDegrees(l.lon - 1.6, l.lat, POINT_LIFT_M.world), point: { pixelSize: 13, color: color.withAlpha(0.05), outlineColor: color, outlineWidth: 2.5 } });
    clickable(id, { title: l.title, place: l.name, count: 0, time: l.time, approximate: true, items: [{ text: 'Internet route leak', plain: l.plain, tech: l.technical }] });
  }

  /** Phishing pages hosted in a country: green dot, brands in the popup. */
  function addPhish(p) {
    const id = `${ID_PREFIX}phish:${p.country}`;
    _ds.entities.add({
      id,
      position: Cesium.Cartesian3.fromDegrees(p.lon + 1.6, Math.min(85, p.lat + 1.2), POINT_LIFT_M.world),
      point: { pixelSize: 8 + Math.min(10, p.count * 2), color: Cesium.Color.fromCssColorString(COLORS.phishing).withAlpha(0.9), outlineColor: Cesium.Color.BLACK.withAlpha(0.9), outlineWidth: 2 },
    });
    clickable(id, {
      title: `${p.count} phishing site${p.count === 1 ? '' : 's'}`,
      place: p.name,
      count: 0,
      time: null,
      approximate: true,
      items: [
        { text: 'What this is', plain: p.plain, tech: p.technical },
        ...p.brands.map((b) => ({ text: `Pretends to be ${b.name} × ${b.count}` })),
        ...p.hosts.map((h) => ({ text: h })),
      ],
    });
  }

  /** Cloudflare DDoS pair: dashed pink arc country → country. */
  function addPair(pair, index, maxValue) {
    if (pair.domestic) return;
    const positions = liftedArc(pair.from, pair.to, POINT_LIFT_M.world, POINT_LIFT_M.world);
    const w = Math.max(0.15, Math.min(1, pair.value / Math.max(0.01, maxValue)));
    const color = Cesium.Color.fromCssColorString(DDOS_COLOR);
    const id = `${ID_PREFIX}ddos:${pair.layer}:${pair.from.code}-${pair.to.code}`;
    _ds.entities.add({
      id,
      polyline: {
        positions,
        width: 1.5 + w * 3,
        arcType: Cesium.ArcType.NONE,
        material: new Cesium.PolylineDashMaterialProperty({ color: color.withAlpha(0.45 + w * 0.4), dashLength: 18 }),
      },
    });
    addHeads(`ddos:${pair.layer}:${pair.from.code}-${pair.to.code}`, positions, color, w * 0.6, index + 7);
    clickable(id, {
      title: `${pair.from.name} → ${pair.to.name}`,
      place: pair.label,
      count: 0,
      time: null,
      approximate: true,
      items: [{ text: `${pair.value.toFixed(2)}% of blocked ${pair.layer === 'L3' ? 'network' : 'web'} attack traffic`, plain: pair.plain, tech: pair.technical }],
    });
  }

  /** ThreatFox C2 servers grouped per country: purple dot, malware families in the popup. */
  function addMalware(m) {
    const id = `${ID_PREFIX}c2:${m.country}`;
    _ds.entities.add({
      id,
      // Nudged south of the country centre so it doesn't sit on the source marker.
      position: Cesium.Cartesian3.fromDegrees(m.lon, Math.max(-85, m.lat - 1.4), POINT_LIFT_M.world),
      point: {
        pixelSize: 8 + Math.min(10, m.count * 2),
        color: Cesium.Color.fromCssColorString(MALWARE_COLOR).withAlpha(0.9),
        outlineColor: Cesium.Color.BLACK.withAlpha(0.9),
        outlineWidth: 2,
      },
    });
    clickable(id, {
      title: `${m.count} malware control server${m.count === 1 ? '' : 's'}`,
      place: m.name,
      count: 0,
      time: null,
      approximate: true,
      items: [
        { text: 'What this is', plain: 'Computers that send orders to machines infected with malware. Shutting these down cuts the criminals off.', tech: 'ThreatFox botnet_cc indicators (ip:port), last 24h, AS country.' },
        ...m.families.map((f) => ({ text: `${f.name} × ${f.count}`, plain: f.plain, tech: f.technical })),
        ...m.examples.map((e) => ({ text: `${e.ioc}${e.confidence ? ` · confidence ${e.confidence}%` : ''}` })),
      ],
    });
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
      _hud = createHud();
      _hud.mount();
      holdContinuousRender(RENDER_HOLD);
      _offFocus = onFocusChange(() => this.update());
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
      _hud = null;
      _offFocus?.();
      _offFocus = null;
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
        const focus = getFocus();
        const view = focusView(body, focus);
        const target = body.target || { lat: 36.8508, lon: -76.2859, name: 'Hampton Roads' };
        const attackTypes = body.attackTypes || [];
        let labels;
        if (focus === FOCUS_757) {
          addTarget(target);
          labels = view.sources.map((src, i) => addArc(src, target, i, attackTypes));
        } else {
          labels = view.sources.map((src) => addHotspot(src, attackTypes));
        }
        const maxPair = Math.max(0, ...view.pairs.filter((p) => !p.domestic).map((p) => p.value));
        view.pairs.forEach((p, i) => addPair(p, i, maxPair));
        view.hijacks.forEach((h, i) => addHijack(h, i));
        view.leaks.forEach(addLeak);
        view.malware.forEach(addMalware);
        view.phishing.forEach(addPhish);
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
        _count = view.sources.length + view.pairs.filter((p) => !p.domestic).length + view.malware.length + view.phishing.length + view.hijacks.length;
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

/**
 * What to draw for a focus. WORLD: everything. 757: the US slice — DDoS and
 * hijacks that touch the US, US malware/phishing/leaks; sources still arc in.
 */
export function focusView(body, focus) {
  const all = {
    sources: body.sources || [],
    pairs: body.pairs || [],
    hijacks: body.hijacks || [],
    leaks: body.leaks || [],
    malware: body.malware || [],
    phishing: body.phishing || [],
  };
  if (focus !== FOCUS_757) return all;
  const us = (code) => code === 'US';
  return {
    sources: all.sources,
    pairs: all.pairs.filter((p) => us(p.from.code) || us(p.to.code)),
    hijacks: all.hijacks.filter((h) => us(h.from.code) || us(h.to.code)),
    leaks: all.leaks.filter((l) => us(l.country)),
    malware: all.malware.filter((m) => us(m.country)),
    phishing: all.phishing.filter((p) => us(p.country)),
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
