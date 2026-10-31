/**
 * Anansi side panels and console mode, ported from the 0.1.x src/ui.js
 * StyleManager onto God's Eye View 0.3.0. The methods below are carried over
 * unchanged; only their host moved from StyleManager to this small class.
 *
 *  - HAMPTON ROADS 757: local n8n traffic / weather / news feed
 *  - AI SECURITY INTEL: /api/ai-sec-intel snapshot (server/providers/anansi)
 *  - CONSOLE mode: porthole HUD frame + graticule + angular panel skin
 */
import hamptonRoads757Feed from '../data/hamptonRoads757.js';
import aiSecIntelFeed from '../data/aiSecIntelFeed.js';
import { withinWindow as aiSecWithinWindow } from '../data/aiSecIntel.js';

/**
 * Elements console mode gives a small decorative `transform: rotate()` tilt
 * (see `body.console-mode` in style.css) purely for the "radiating panel"
 * look. Several of these are also load-bearing inputs to the adaptive-layout
 * collision math above (obstacle rects, or the stack's own children whose
 * `getBoundingClientRect()` height feeds natural/allocated-height math), and
 * `getBoundingClientRect()` reports a rotated element's larger axis-aligned
 * bounding box rather than its visual footprint — feeding that inflated box
 * into the layout math starves whichever panel the math thinks needs to make
 * room. `withUnrotatedConsolePanels()` below neutralizes these specific
 * elements' rotation for the duration of one synchronous measurement pass so
 * every rect read during layout reflects the true, unrotated footprint.
 */
const CONSOLE_MODE_ROTATED_SELECTOR = [
  '#title-bar',
  '#style-indicator',
  '#intel-hud .hud-top-left',
  '#intel-hud .hud-top-right',
  '#intel-hud .hud-bottom-left',
  '#intel-hud .hud-bottom-right',
  '#left-panel-stack > #data-panel',
  '#left-panel-stack > #cctv-panel',
  '#left-panel-stack > #scene-panel',
  '#right-context-rail > #cctv-panel',
  '#right-context-rail > #global-context-panel',
].join(', ');
/**
 * Runs `fn` with every console-mode decorative rotation temporarily zeroed
 * out, then restores each element's own inline transform afterward — so any
 * `getBoundingClientRect()` call `fn` makes (directly, or transitively via
 * `_measureLeftPanelNaturalHeight`) sees the unrotated layout footprint. A
 * no-op outside console mode. Synchronous and restores before returning, so
 * nothing paints the intermediate unrotated state.
 * @param {() => T} fn
 * @returns {T}
 * @template T
 */
export function withUnrotatedConsolePanels(fn) {
  if (!document.body.classList.contains('console-mode')) return fn();
  const elements = document.querySelectorAll(CONSOLE_MODE_ROTATED_SELECTOR);
  const saved = [];
  for (const el of elements) {
    saved.push([el, el.style.transform]);
    el.style.transform = 'none';
  }
  try {
    return fn();
  } finally {
    for (const [el, prevTransform] of saved) {
      if (prevTransform) el.style.transform = prevTransform;
      else el.style.removeProperty('transform');
    }
  }
}

/**
 * Coarse "Xs/Xm/Xh ago" formatting for panel status lines.
 * @param {number} timestamp - Epoch ms.
 * @returns {string}
 */
function formatRelativeTime(timestamp) {
  if (!Number.isFinite(timestamp)) return 'never';
  const diff = Math.floor((Date.now() - timestamp) / 1000);
  if (diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export class AnansiPanels {
  constructor(doc = document) {
    this._hamptonRoadsFeedEl = doc.getElementById('hampton-roads-feed');
    this._hamptonRoadsMetaEl = doc.getElementById('hampton-roads-meta');
    this._hamptonRoadsUnsubscribe = null;
    this._aiSecPanelEl = doc.getElementById('ai-sec-panel');
    this._aiSecListEl = doc.getElementById('ai-sec-list');
    this._aiSecMetaEl = doc.getElementById('ai-sec-meta');
    this._aiSecSourcesEl = doc.getElementById('ai-sec-sources');
    this._aiSecTab = 'vulns';
    this._aiSecWindowDays = 30;
    this._aiSecUnsubscribe = null;
    this._consoleModeBtn = doc.getElementById('console-mode-toggle');
  }

  init() {
    this._initHamptonRoadsPanel();
    this._initAiSecPanel();
    this._initConsoleModeToggle();
    return this;
  }

  destroy() {
    this._hamptonRoadsUnsubscribe?.();
    this._aiSecUnsubscribe?.();
  }

  /**
   * Wires the Hampton Roads 757 side panel to its polling feed. Plain
   * subscribe/render — no data-layer lifecycle, no map entities. The feed
   * runs continuously once started; only the panel's collapsed/expanded
   * state (handled generically by `_initPanelChrome`) controls whether the
   * rendered list is visible.
   * @returns {void}
   */
  _initHamptonRoadsPanel() {
    if (!this._hamptonRoadsFeedEl) return;
    this._hamptonRoadsUnsubscribe = hamptonRoads757Feed.subscribe((state) => {
      this._renderHamptonRoadsFeed(state);
    });
    hamptonRoads757Feed.start();
  }

  /**
   * Formats one Hampton Roads feed item's metadata line. Shape varies by
   * kind (traffic carries severity/from/to, news carries source/pubDate).
   * @param {'traffic'|'weather'|'news'} kind
   * @param {Object} item
   * @returns {string}
   */
  _hamptonRoadsItemMeta(kind, item) {
    const meta = item?.metadata || {};
    if (kind === 'traffic') {
      const road = [meta.from, meta.to].filter(Boolean).join(' → ');
      const sev = Number.isFinite(meta.severity) ? `SEV ${meta.severity}` : null;
      return [road, sev].filter(Boolean).join(' · ') || 'TomTom';
    }
    if (kind === 'roadwork') {
      return [meta.crossingName || meta.road, String(item.severity || meta.severity || '').toUpperCase()].filter(Boolean).join(' · ') || 'VDOT 511';
    }
    if (kind === 'ships') {
      const speed = Number.isFinite(meta.speedKn) && meta.underway ? `${meta.speedKn.toFixed(1)} kn` : null;
      return [meta.shipType, meta.zoneName, speed].filter(Boolean).join(' · ') || 'AISStream';
    }
    if (kind === 'news') {
      const ago = meta.pubDate ? formatRelativeTime(new Date(meta.pubDate).getTime()) : null;
      return [meta.source, ago].filter(Boolean).join(' · ');
    }
    // weather — shape is whatever the n8n workflow emits; show what's there.
    return [meta.source, meta.event].filter(Boolean).join(' · ');
  }

  /**
   * Builds one feed-item card. News labels link out; everything else is
   * plain text. Deliberately minimal — this panel is a read-only feed.
   * @param {'traffic'|'weather'|'news'} kind
   * @param {Object} item
   * @returns {HTMLElement}
   */
  _buildHamptonRoadsItemEl(kind, item) {
    const row = document.createElement('div');
    row.className = 'hampton-roads-item';
    row.setAttribute('role', 'listitem');

    const kindEl = document.createElement('span');
    kindEl.className = 'hampton-roads-item-kind';
    const KIND_LABELS = { traffic: '🚦 traffic', weather: '⛈️ weather', news: '📰 news', roadwork: '🚧 roadwork', ships: '🚢 ships' };
    kindEl.textContent = KIND_LABELS[kind] ?? KIND_LABELS.news;

    const labelEl = document.createElement('span');
    labelEl.className = 'hampton-roads-item-label';
    const label = String(item?.label || '(no label)');
    if (kind === 'news' && item?.metadata?.link) {
      const link = document.createElement('a');
      link.href = item.metadata.link;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = label;
      labelEl.appendChild(link);
    } else {
      labelEl.textContent = label;
    }

    const metaEl = document.createElement('span');
    metaEl.className = 'hampton-roads-item-meta';
    metaEl.textContent = this._hamptonRoadsItemMeta(kind, item);

    row.append(kindEl, labelEl, metaEl);
    return row;
  }

  /**
   * Renders the full feed list from the polling service's current state.
   * Caps each category so a 150+-incident TomTom response doesn't turn the
   * panel into an unusable scroll well — traffic sorts by severity (worst
   * first), news by publish date (newest first).
   * @param {Object} state - `hamptonRoads757Feed` state (see data/hamptonRoads757.js).
   * @returns {void}
   */
  _renderHamptonRoadsFeed(state) {
    const CAP = { traffic: 15, weather: 10, news: 10, roadwork: 10, ships: 10 };
    const list = this._hamptonRoadsFeedEl;
    if (list) {
      list.innerHTML = '';
      const traffic = [...(state.traffic || [])]
        .sort((a, b) => (b?.metadata?.severity || 0) - (a?.metadata?.severity || 0))
        .slice(0, CAP.traffic);
      const weather = (state.weather || []).slice(0, CAP.weather);
      const news = [...(state.news || [])]
        .sort((a, b) => new Date(b?.metadata?.pubDate || 0) - new Date(a?.metadata?.pubDate || 0))
        .slice(0, CAP.news);

      // Roadwork and ships arrive pre-ranked by severity (VDOT WZDx / AIS port zones).
      const roadwork = (state.roadwork || []).slice(0, CAP.roadwork);
      const ships = (state.ships || []).slice(0, CAP.ships);
      const sections = [['traffic', traffic], ['roadwork', roadwork], ['weather', weather], ['ships', ships], ['news', news]];
      let rendered = 0;
      for (const [kind, items] of sections) {
        for (const item of items) {
          list.appendChild(this._buildHamptonRoadsItemEl(kind, item));
          rendered++;
        }
      }
      if (rendered === 0) {
        const empty = document.createElement('div');
        empty.className = 'hampton-roads-empty';
        empty.textContent = state.error
          ? `No data yet — ${state.error}`
          : (state.loading ? 'Loading…' : 'No current incidents, alerts, or headlines.');
        list.appendChild(empty);
      }
    }

    if (this._hamptonRoadsMetaEl) {
      const extra = [
        (state.roadwork || []).length ? `${state.roadwork.length} roadwork` : null,
        (state.ships || []).length ? `${state.ships.length} ships` : null,
      ].filter(Boolean).map((part) => ` · ${part}`).join('');
      const counts = `${(state.traffic || []).length} traffic · ${(state.weather || []).length} weather · ${(state.news || []).length} news${extra}`;
      const status = state.loading
        ? 'syncing…'
        : state.error
          ? `error — ${state.error}`
          : (state.lastUpdate ? formatRelativeTime(state.lastUpdate) : 'never');
      this._hamptonRoadsMetaEl.textContent = `n8n (local) · ${counts} · ${status}`;
      this._hamptonRoadsMetaEl.classList.toggle('hampton-roads-error', Boolean(state.error) && !state.loading);
    }
  }

  /**
   * Wires the AI Security Intelligence panel to its polling feed. Like the
   * Hampton Roads panel this is a plain subscribe/render read-only feed — no
   * data-layer lifecycle, no map entities. Tabs switch which bucket of the
   * snapshot (vulns / models / research / policy) is listed.
   * @returns {void}
   */
  _initAiSecPanel() {
    if (!this._aiSecListEl || !this._aiSecPanelEl) return;
    const tabs = [...this._aiSecPanelEl.querySelectorAll('[data-ai-sec-tab]')];
    const select = (tab, { focus = false } = {}) => {
      this._aiSecTab = tab.dataset.aiSecTab;
      this._syncAiSecTabs();
      this._renderAiSecPanel(aiSecIntelFeed.getState());
      if (focus) tab.focus();
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => select(tab));
      tab.addEventListener('keydown', (event) => {
        let next = null;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        if (next === null) return;
        event.preventDefault();
        select(tabs[next], { focus: true });
      });
    });
    this._syncAiSecTabs();
    this._aiSecUnsubscribe = aiSecIntelFeed.subscribe((state) => this._renderAiSecPanel(state));
    aiSecIntelFeed.start();
  }

  /** Mirrors `_aiSecTab` onto the tab buttons (active class, aria-selected, roving tabindex). */
  _syncAiSecTabs() {
    this._aiSecPanelEl?.querySelectorAll('[data-ai-sec-tab]').forEach((tab) => {
      const active = tab.dataset.aiSecTab === this._aiSecTab;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
    });
  }

  /**
   * Appends an http(s)-only anchor. The proxy already validates every URL;
   * this is the second, DOM-side gate so a bad value can never become a
   * `javascript:` link.
   * @param {HTMLElement} parent
   * @param {string} label
   * @param {string|null|undefined} url
   * @returns {HTMLElement} The anchor, or a plain span when the URL is unsafe.
   */
  _appendAiSecLink(parent, label, url) {
    const safe = typeof url === 'string' && /^https?:\/\//i.test(url);
    const el = document.createElement(safe ? 'a' : 'span');
    el.textContent = label;
    if (safe) {
      el.href = url;
      el.target = '_blank';
      el.rel = 'noopener noreferrer';
    }
    parent.appendChild(el);
    return el;
  }

  /** @returns {HTMLElement} A small label chip (`KEV`, `HIGH`, `NEW`, ...). */
  _buildAiSecBadge(text, className) {
    const badge = document.createElement('span');
    badge.className = `ai-sec-badge ${className}`;
    badge.textContent = text;
    return badge;
  }

  /** @returns {HTMLElement} One label/value line inside an expanded advisory. */
  _buildAiSecField(label, value) {
    const row = document.createElement('div');
    row.className = 'ai-sec-field';
    const key = document.createElement('span');
    key.className = 'ai-sec-field-key';
    key.textContent = label;
    const val = document.createElement('span');
    val.className = 'ai-sec-field-value';
    val.textContent = value;
    row.append(key, val);
    return row;
  }

  /**
   * One vulnerability card. Collapsed it shows exploitation status, severity,
   * title and product; expanded it adds affected → fixed versions, the
   * recommended action, KEV due date and evidence links.
   * @param {Object} vuln - `vulns[]` item from /api/ai-sec-intel.
   * @returns {HTMLElement}
   */
  _buildAiSecVulnEl(vuln) {
    const kev = vuln.exploited === 'kev';
    const details = document.createElement('details');
    details.className = 'ai-sec-item ai-sec-vuln';
    details.dataset.severity = vuln.severity || 'unknown';
    details.dataset.kev = String(kev);
    details.setAttribute('role', 'listitem');

    const summary = document.createElement('summary');
    const badges = document.createElement('span');
    badges.className = 'ai-sec-badges';
    if (kev) badges.appendChild(this._buildAiSecBadge('KEV', 'ai-sec-badge-kev'));
    badges.appendChild(this._buildAiSecBadge(String(vuln.severity || 'unknown').toUpperCase(), `ai-sec-badge-${vuln.severity || 'unknown'}`));
    if (vuln.isNew) badges.appendChild(this._buildAiSecBadge('NEW', 'ai-sec-badge-new'));
    const title = document.createElement('span');
    title.className = 'ai-sec-item-title';
    title.textContent = vuln.title || vuln.id;
    const meta = document.createElement('span');
    meta.className = 'ai-sec-item-meta';
    meta.textContent = [
      vuln.id,
      [vuln.vendor, vuln.product].filter(Boolean).join(' ') || null,
      Number.isFinite(vuln.cvss) ? `CVSS ${vuln.cvss.toFixed(1)}` : null,
      vuln.date,
    ].filter(Boolean).join(' · ');
    summary.append(badges, title, meta);
    details.appendChild(summary);

    const body = document.createElement('div');
    body.className = 'ai-sec-item-body';
    if (vuln.summary) {
      const text = document.createElement('p');
      text.textContent = vuln.summary;
      body.appendChild(text);
    }
    if (vuln.affected) body.appendChild(this._buildAiSecField('AFFECTED', vuln.affected));
    if (vuln.fixed) body.appendChild(this._buildAiSecField('FIXED', vuln.fixed));
    if (vuln.action) body.appendChild(this._buildAiSecField('DO NOW', vuln.action));
    if (kev && vuln.dueDate) body.appendChild(this._buildAiSecField('KEV DUE', vuln.dueDate));
    if (vuln.ransomware) body.appendChild(this._buildAiSecField('RISK', 'Known ransomware campaign use'));
    if (Array.isArray(vuln.evidence) && vuln.evidence.length) {
      const links = document.createElement('div');
      links.className = 'ai-sec-links';
      for (const link of vuln.evidence.slice(0, 5)) this._appendAiSecLink(links, link.label || 'source', link.url);
      body.appendChild(links);
    }
    details.appendChild(body);
    return details;
  }

  /**
   * One headline card for the models / research / policy tabs.
   * @param {Object} item
   * @param {string} kindLabel
   * @returns {HTMLElement}
   */
  _buildAiSecNewsEl(item, kindLabel) {
    const row = document.createElement('div');
    row.className = 'ai-sec-item ai-sec-news';
    row.setAttribute('role', 'listitem');

    const kind = document.createElement('span');
    kind.className = 'ai-sec-item-kind';
    kind.textContent = kindLabel;
    if (item.isNew) kind.appendChild(this._buildAiSecBadge('NEW', 'ai-sec-badge-new'));

    const title = document.createElement('span');
    title.className = 'ai-sec-item-title';
    this._appendAiSecLink(title, item.title || '(untitled)', item.url);

    const meta = document.createElement('span');
    meta.className = 'ai-sec-item-meta';
    meta.textContent = item.date || '';

    row.append(kind, title, meta);
    if (item.summary) {
      const text = document.createElement('p');
      text.className = 'ai-sec-item-summary';
      text.textContent = item.summary;
      row.appendChild(text);
    }
    return row;
  }

  /**
   * Renders the active tab, the header summary line, and per-source health.
   * The snapshot holds `retainDays` of history but the panel shows the
   * `windowDays` window (30 d) — except policy, where executive orders are too
   * sparse to window.
   * @param {Object} state - `aiSecIntelFeed` state (see data/aiSecIntelFeed.js).
   * @returns {void}
   */
  _renderAiSecPanel(state) {
    const list = this._aiSecListEl;
    if (!list) return;
    const snap = state.snapshot;
    const windowDays = snap?.windowDays || this._aiSecWindowDays;
    const now = Date.now();
    const windowed = (key) => aiSecWithinWindow(snap?.[key] || [], windowDays, now);
    // A confirmed-exploited (CISA KEV) vulnerability stays on the board for the
    // snapshot's whole retention window — it is exactly the item a 30-day
    // cutoff would wrongly retire while it is still being exploited.
    const windowCutoffMs = now - windowDays * 86_400_000;
    const buckets = {
      vulns: (snap?.vulns || []).filter((v) => v.exploited === 'kev' || v.dateMs >= windowCutoffMs),
      models: windowed('models'),
      research: windowed('research'),
      policy: snap?.policy || [],
    };

    this._aiSecPanelEl?.querySelectorAll('[data-ai-sec-tab]').forEach((tab) => {
      const count = buckets[tab.dataset.aiSecTab]?.length || 0;
      tab.dataset.count = count ? String(count) : '';
    });

    const rows = [];
    const items = buckets[this._aiSecTab] || [];
    for (const item of items.slice(0, 30)) {
      if (this._aiSecTab === 'vulns') rows.push(this._buildAiSecVulnEl(item));
      else if (this._aiSecTab === 'models') rows.push(this._buildAiSecNewsEl(item, item.source || 'MODEL'));
      else if (this._aiSecTab === 'research') rows.push(this._buildAiSecNewsEl(item, item.source || 'RESEARCH'));
      else rows.push(this._buildAiSecNewsEl(item, item.number || 'POLICY'));
    }
    if (!rows.length) {
      const empty = document.createElement('div');
      empty.className = 'ai-sec-empty';
      empty.textContent = !snap
        ? (state.error ? `No data yet — ${state.error}` : 'Loading…')
        : `Nothing in the last ${windowDays} days from the connected sources.`;
      rows.push(empty);
    }
    list.replaceChildren(...rows);

    if (this._aiSecMetaEl) {
      const sources = snap?.sources || [];
      const live = sources.filter((s) => s.ok).length;
      const kev = buckets.vulns.filter((v) => v.exploited === 'kev').length;
      const critical = buckets.vulns.filter((v) => v.severity === 'critical').length;
      const status = state.loading
        ? 'syncing…'
        : state.error
          ? `error — ${state.error}`
          : (state.lastUpdate ? formatRelativeTime(state.lastUpdate) : 'never');
      this._aiSecMetaEl.textContent = snap
        ? `${kev} KEV · ${critical} critical · ${windowDays}d · ${live}/${sources.length} sources · ${status}`
        : status;
      this._aiSecMetaEl.classList.toggle('ai-sec-error', Boolean(state.error) && !state.loading);
    }

    if (this._aiSecSourcesEl) {
      const chips = (snap?.sources || []).map((source) => {
        const chip = document.createElement('span');
        const health = source.ok ? 'ok' : (source.stale ? 'stale' : 'down');
        chip.className = `ai-sec-source ai-sec-source-${health}`;
        chip.textContent = source.label;
        chip.title = source.ok
          ? `${source.label}: ${source.count} items`
          : `${source.label}: ${source.error || 'unavailable'}${source.stale ? ' (showing last-good items)' : ''}`;
        return chip;
      });
      this._aiSecSourcesEl.replaceChildren(...chips);
    }
  }

  /**
   * Console mode: the radial "porthole" HUD skin (angular panels + the
   * hud-frame ring/circuit-trace canvas from src/hudFrame.js). Deliberately
   * a plain, self-contained toggle — no share-link wiring, no direct calls
   * into Cockpit (flight) mode's own state machine — since it's a purely
   * decorative skin, not a data-affecting mode. Persisted the same simple
   * way panel-collapse state is (a single localStorage flag).
   *
   * One exception to "purely decorative": Hampton Roads gets physically
   * moved out of #right-context-rail to a direct child of <body> while
   * console mode is active, rather than just visually offset in place like
   * its siblings. _syncRightPanelAdaptiveLayout() (the collision-avoidance
   * engine that sizes/collapses the rail's panels) only ever measures
   * `#right-context-rail`'s *current* DOM children — so moving the node out
   * is what keeps that algorithm's height/collapse math for the *other*
   * rail panels correct, instead of feeding it a panel that's no longer
   * actually in the rail's visual flow. A body-class MutationObserver (not
   * a direct call into CockpitMode) re-attaches it the moment cockpit mode
   * engages, so it's never left stranded body-level while cockpit mode's
   * own CSS expects the rail back to normal.
   * @returns {void}
   */
  _initConsoleModeToggle() {
    if (!this._consoleModeBtn) return;
    const STORAGE_KEY = 'gev.consoleMode';
    const hamptonRoadsPanel = document.getElementById('hampton-roads-panel');
    const rightRail = document.getElementById('right-context-rail');
    const narrowQuery = window.matchMedia('(max-width: 900px)');
    const syncHamptonRoadsDetachment = () => {
      if (!hamptonRoadsPanel || !rightRail) return;
      const shouldDetach = document.body.classList.contains('console-mode')
        && !document.body.classList.contains('cockpit-mode')
        && !narrowQuery.matches;
      if (shouldDetach === hamptonRoadsPanel.classList.contains('rail-detached')) return;
      if (shouldDetach) document.body.appendChild(hamptonRoadsPanel);
      else rightRail.appendChild(hamptonRoadsPanel);
      hamptonRoadsPanel.classList.toggle('rail-detached', shouldDetach);
    };
    const apply = (active) => {
      document.body.classList.toggle('console-mode', active);
      // HUD frame + graticule follow this class: src/anansi/consoleScene.js
      this._consoleModeBtn.classList.toggle('active', active);
      this._consoleModeBtn.setAttribute('aria-pressed', String(active));
      syncHamptonRoadsDetachment();
    };
    let restored = false;
    try {
      restored = localStorage.getItem(STORAGE_KEY) === '1';
    } catch {
      // storage unavailable — default to off
    }
    apply(restored);
    this._consoleModeBtn.addEventListener('click', () => {
      const next = !document.body.classList.contains('console-mode');
      apply(next);
      try {
        localStorage.setItem(STORAGE_KEY, next ? '1' : '0');
      } catch {
        // storage unavailable — mode still applies for this session
      }
    });
    narrowQuery.addEventListener('change', syncHamptonRoadsDetachment);
    if (typeof MutationObserver !== 'undefined') {
      new MutationObserver(syncHamptonRoadsDetachment)
        .observe(document.body, { attributes: true, attributeFilter: ['class'] });
    }
  }
}

/** Build and start the Anansi panels once the 0.3.0 shell has mounted its templates. */
export function initAnansiPanels(doc = document) {
  return new AnansiPanels(doc).init();
}
