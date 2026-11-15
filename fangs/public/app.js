// FANGS board client. Graph = cytoscape (preset layout computed server-side); queue/detail = plain DOM.
// No innerHTML with data: every dynamic string goes through textContent so feed content can never inject markup.
/* global cytoscape */
const $ = (id) => document.getElementById(id);
const state = { lang: 'en', dict: {}, events: new Map(), cy: null, selected: null, colorBy: 'type', sizeBy: 'degree', lat: [], feeds: new Map(), nodes: new Map() };
window.__fangs = { latencies: state.lat, state };

// ---------- i18n ----------
async function loadLang(lang) {
  const res = await fetch(`/locales/${lang}.json`); state.dict = await res.json(); state.lang = lang; document.documentElement.lang = lang;
  try { localStorage.setItem('fangs.lang', lang); } catch { /* storage may be unavailable */ }
  applyI18n();
}
const t = (key, vars) => { let s = state.dict[key] ?? key; if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v); return s; };
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
  document.querySelectorAll('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.i18nAria)); });
  renderLegend(); renderFeeds(); renderQueue(); if (state.selected) showSelection(state.selected);
  updateBanner();
}

// ---------- theme ----------
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
function setTheme(th) {
  document.documentElement.dataset.theme = th; $('theme').setAttribute('aria-pressed', String(th === 'light'));
  try { localStorage.setItem('fangs.theme', th); } catch { /* ignore */ }
  if (state.cy) styleGraph();
}

// ---------- graph ----------
const TYPES = ['ip', 'host', 'family', 'asn', 'campaign', 'victim'];
const SHAPE = { ip: 'ellipse', host: 'round-rectangle', family: 'star', asn: 'diamond', campaign: 'hexagon', victim: 'triangle' };
const commColor = (c) => css(`--c${Math.abs(c) % 10}`);   // theme-aware categorical palette (CSS custom properties)

function elementFromNode(n) { return { group: 'nodes', data: { id: n.id, type: n.type, label: n.label, community: n.community ?? -1, degree: n.degree || 0, betweenness: n.betweenness || 0, attrs: n.attrs, prov: n.prov }, position: { x: n.x ?? 0, y: n.y ?? 0 } }; }
function elementFromEdge(e) { return { group: 'edges', data: { id: e.id, source: e.source, target: e.target, rels: e.rels, kinds: [...new Set(e.rels.map((r) => r.type))].join('+') } }; }

function styleGraph() {
  const sizeKey = state.sizeBy;
  const maxB = Math.max(1e-6, ...state.cy.nodes().map((n) => n.data('betweenness')));
  state.cy.style([
    { selector: 'node', style: { label: 'data(label)', 'font-size': 11, color: css('--text'), 'text-outline-color': css('--bg'), 'text-outline-width': 2, 'text-opacity': 0.0, 'min-zoomed-font-size': 8,
      width: (n) => (sizeKey === 'degree' ? 6 + Math.min(18, Math.sqrt(n.data('degree')) * 3) : 6 + 22 * Math.sqrt(n.data('betweenness') / maxB)), height: (n) => (sizeKey === 'degree' ? 6 + Math.min(18, Math.sqrt(n.data('degree')) * 3) : 6 + 22 * Math.sqrt(n.data('betweenness') / maxB)),
      'background-color': (n) => (state.colorBy === 'community' ? commColor(n.data('community')) : css(`--n-${n.data('type')}`)), shape: (n) => SHAPE[n.data('type')] || 'ellipse', 'border-width': 1, 'border-color': css('--bg'), opacity: 0.92 } },
    { selector: 'node[type = "family"], node[type = "campaign"], node[degree >= 8]', style: { 'text-opacity': 1 } },
    { selector: 'node:selected, node.hot', style: { 'border-width': 3, 'border-color': css('--edge-hot'), 'text-opacity': 1, 'z-index': 99 } },
    { selector: 'edge', style: { width: 1, 'line-color': css('--edge'), 'curve-style': 'haystack', 'haystack-radius': 0, opacity: 0.8 } },
    { selector: 'edge[kinds *= "resolves-to"]', style: { 'line-style': 'dashed' } },
    { selector: 'edge[kinds *= "attacks"]', style: { 'line-style': 'dotted', width: 1.5 } },
    { selector: 'edge:selected, edge.hot', style: { 'line-color': css('--edge-hot'), width: 2.5, opacity: 1 } },
    { selector: '.dim', style: { opacity: 0.12 } },
  ]);
}

function initGraph(g) {
  state.cy = cytoscape({ container: $('graph'), elements: [...g.nodes.map(elementFromNode), ...g.edges.map(elementFromEdge)], layout: { name: 'preset' }, wheelSensitivity: 0.3, minZoom: 0.05, maxZoom: 6, textureOnViewport: true });
  g.nodes.forEach((n) => state.nodes.set(n.id, n));
  styleGraph(); state.cy.fit(undefined, 30);
  state.cy.on('dragpan zoom', () => { state.userMoved = true; });
  state.cy.on('tap', 'node', (e) => select({ kind: 'node', id: e.target.id() }));
  state.cy.on('tap', 'edge', (e) => select({ kind: 'edge', id: e.target.id() }));
  state.cy.on('mouseover', 'node', (e) => { e.target.style('text-opacity', 1); });
  state.cy.on('mouseout', 'node', (e) => { if (!(['family', 'campaign'].includes(e.target.data('type')) || e.target.data('degree') >= 8)) e.target.removeStyle('text-opacity'); });
  updateStats(g.stats);
}

function applyGraphDelta(d) {
  if (!state.cy) return;
  state.cy.batch(() => {
    for (const n of d.nodes) { const ex = state.cy.getElementById(n.id); if (ex.empty()) state.cy.add(elementFromNode(n)); else ex.data({ prov: n.prov, attrs: n.attrs, degree: n.degree, betweenness: n.betweenness }); state.nodes.set(n.id, n); }
    for (const e of d.edges) { const ex = state.cy.getElementById(e.id); if (ex.empty()) { if (state.cy.getElementById(e.source).nonempty() && state.cy.getElementById(e.target).nonempty()) state.cy.add(elementFromEdge(e)); } else ex.data({ rels: e.rels, kinds: [...new Set(e.rels.map((r) => r.type))].join('+') }); }
  });
}
function applyAnalytics(a) {
  if (!state.cy) return;
  state.cy.batch(() => { for (const [id, v] of Object.entries(a.nodes)) { const n = state.cy.getElementById(id); if (n.nonempty()) { n.data({ community: v.community ?? -1, degree: v.degree, betweenness: v.betweenness }); if (typeof v.x === 'number') n.position({ x: v.x, y: v.y }); } } });
  styleGraph();
  if (Object.values(a.nodes).some((v) => typeof v.x === 'number') && !state.selected && !state.userMoved) state.cy.fit(undefined, 30);
  $('st-comm').textContent = a.communities; $('st-q').textContent = a.modularity.toFixed(3);
  $('st-nodes').textContent = state.cy.nodes().length; $('st-edges').textContent = state.cy.edges().length;
}
function updateStats(s) { $('st-nodes').textContent = s.nodes; $('st-edges').textContent = s.edges; $('st-comm').textContent = s.communities; $('st-q').textContent = s.modularity; }

function renderLegend() {
  const ul = $('legend'); ul.replaceChildren();
  for (const ty of TYPES) { const li = document.createElement('li'); const i = document.createElement('i'); i.style.background = css(`--n-${ty}`); li.append(i, t(`type.${ty}`)); ul.append(li); }
}

// ---------- queue ----------
const fmtScore = (e) => (e.score ? e.score.score.toFixed(1) : '–');
function renderQueue() {
  for (const st of ['new', 'triaged', 'acknowledged']) {
    const list = $(`list-${st}`); list.replaceChildren();
    const evs = [...state.events.values()].filter((e) => e.state === st).sort((a, b) => (b.score?.score ?? 0) - (a.score?.score ?? 0)).slice(0, 60);
    $(`cnt-${st}`).textContent = [...state.events.values()].filter((e) => e.state === st).length;
    if (!evs.length) { const li = document.createElement('li'); li.className = 'dim'; li.textContent = t('queue.empty'); list.append(li); continue; }
    for (const e of evs) {
      const li = document.createElement('li'); const b = document.createElement('button'); b.type = 'button'; b.className = 'ev'; b.dataset.band = e.score?.band || 'low'; b.dataset.id = e.id;
      if (state.selected?.kind === 'event' && state.selected.id === e.id) b.setAttribute('aria-current', 'true');
      const top = document.createElement('span'); top.className = 't'; const l = document.createElement('span'); l.textContent = e.indicator.length > 26 ? `${e.indicator.slice(0, 25)}…` : e.indicator; const sc = document.createElement('span'); sc.className = 'score'; sc.textContent = fmtScore(e); top.append(l, sc);
      const sub = document.createElement('span'); sub.className = 's'; sub.textContent = `${e.synthetic ? `${t('badge.synthetic')} · ` : ''}${e.family || e.kind} · ${t(`band.${e.score?.band || 'low'}`)}`;
      b.append(top, sub); b.addEventListener('click', () => select({ kind: 'event', id: e.id })); li.append(b); list.append(li);
    }
  }
}
function upsertEvent(ev) { state.events.set(ev.id, ev); }

// ---------- detail ----------
function el(tag, props = {}, ...kids) { const n = document.createElement(tag); Object.assign(n, props); n.append(...kids.filter((k) => k !== null && k !== undefined)); return n; }
function h4(key) { return el('h4', { textContent: t(key) }); }

async function recordBlock(id) {
  const r = await (await fetch(`/api/records/${encodeURIComponent(id)}`)).json();
  const d = el('details', { className: 'rec' });
  const sum = el('summary', {}, el('b', { textContent: r.source }), ' ', el('span', { className: 'dim', textContent: r.id }));
  if (r.synthetic) sum.append(' ', el('span', { className: 'badge synthetic', textContent: t('badge.synthetic') }));
  d.append(sum, el('pre', { textContent: `origin: ${r.origin}\nfetched: ${r.fetched_at}\nsha256: ${r.sha256}\n\n${JSON.stringify(r.raw, null, 2)}` }));
  return d;
}

async function showSelection(sel) {
  const body = $('detailBody'); body.replaceChildren();
  state.selected = sel;
  if (sel.kind === 'event') {
    const e = state.events.get(sel.id); if (!e) return;
    body.append(el('div', {}, el('b', { textContent: e.indicator }), ' ', el('span', { className: 'badge', textContent: e.family || e.kind }), el('span', { className: 'badge', textContent: t(`band.${e.score?.band || 'low'}`) })));
    body.append(h4('detail.narrative'), el('div', { className: 'narr', textContent: e.narrative?.text || '' }), el('span', { className: 'badge', textContent: t(`basis.${e.narrative?.basis || 'deterministic'}`) }));
    if (e.score) {
      body.append(h4('detail.severity'), el('div', { textContent: `${e.score.score.toFixed(1)} / 100 · ${t(`score.basis.${e.score.basis}`)}` }));
      const grid = el('div', { className: 'bars' });
      for (const [k, v] of Object.entries(e.score.components)) { const o = el('div', { className: 'bar-o' }, el('span')); o.firstChild.style.width = `${Math.round(v * 100)}%`; grid.append(el('span', { textContent: t(`comp.${k}`) }), o, el('span', { textContent: v.toFixed(2) })); }
      body.append(grid);
    }
    if (e.attack?.length) { body.append(h4('detail.attack')); for (const a of e.attack) body.append(el('a', { className: 'ttp', href: a.url, target: '_blank', rel: 'noopener noreferrer', title: a.why || '', textContent: `${a.id} ${a.name} · ${t(`basis.${a.basis}`)}` })); }
    if (e.graph) body.append(h4('detail.graph'), el('div', { textContent: `${t('detail.cluster')} ${e.graph.community ?? '–'} · ${t('detail.degree')} ${e.graph.degree} · ${t('detail.between')} ${e.graph.betweenness}${e.graph.asn ? ` · ${e.graph.asn}` : ''}` }));
    body.append(h4('detail.actions'));
    const act = el('div', { className: 'actions' });
    const next = { new: ['triaged', 'action.triage'], triaged: ['acknowledged', 'action.ack'] }[e.state];
    if (next) { const b = el('button', { type: 'button', textContent: t(next[1]) }); b.addEventListener('click', () => transition(e.id, next[0])); act.append(b); }
    body.append(act, h4('detail.history'), el('div', { className: 'dim', textContent: e.history.map((h) => `${h.state} (${h.actor}) ${h.at.slice(11, 19)}`).join(' → ') }));
    body.append(h4('detail.sources'));
    for (const s of e.sources) body.append(await recordBlock(s.recordId));
    const n = state.cy?.getElementById(e.node); if (n?.nonempty()) focusNode(n);
  } else if (sel.kind === 'node') {
    const n = state.cy.getElementById(sel.id); if (n.empty()) return;
    body.append(el('div', {}, el('b', { textContent: n.data('label') }), ' ', el('span', { className: 'badge', textContent: t(`type.${n.data('type')}`) })));
    body.append(el('div', { className: 'dim', textContent: `${t('detail.cluster')} ${n.data('community')} · ${t('detail.degree')} ${n.data('degree')} · ${t('detail.between')} ${n.data('betweenness')}` }));
    const attrs = Object.entries(n.data('attrs') || {}).filter(([, v]) => v !== null && v !== undefined);
    if (attrs.length) body.append(el('pre', { textContent: attrs.map(([k, v]) => `${k}: ${v}`).join('\n') }));
    body.append(h4('detail.prov'));
    for (const id of n.data('prov')) body.append(await recordBlock(id));
    focusNode(n);
  } else if (sel.kind === 'edge') {
    const ed = state.cy.getElementById(sel.id); if (ed.empty()) return;
    body.append(el('div', {}, el('b', { textContent: `${ed.source().data('label')} ↔ ${ed.target().data('label')}` })), h4('detail.rels'));
    for (const r of ed.data('rels')) { body.append(el('div', { textContent: `${r.type}: ${r.src} → ${r.dst}` })); for (const id of r.prov) body.append(await recordBlock(id)); }
  }
  renderQueue();
}
const select = (sel) => showSelection(sel);
function focusNode(n) {
  state.cy.elements().removeClass('hot dim'); const nb = n.closedNeighborhood();
  state.cy.elements().not(nb).addClass('dim'); nb.addClass('hot'); state.cy.animate({ center: { eles: n }, duration: 250 });
}

async function transition(id, to) {
  const res = await fetch(`/api/events/${id}/transition`, { method: 'POST', headers: { 'x-fangs': '1', 'content-type': 'application/json' }, body: JSON.stringify({ to, actor: 'analyst' }) });
  if (res.ok) { upsertEvent(await res.json()); renderQueue(); showSelection({ kind: 'event', id }); }
}

// ---------- feeds / banner ----------
function renderFeeds() {
  const box = $('feeds'); box.replaceChildren();
  for (const f of state.feeds.values()) { const s = el('span', { className: 'feed', title: f.note || f.last_error || '' }, el('i'), `${f.label} · ${t(`feed.${f.state}`)}`); s.dataset.state = f.state; box.append(s); }
}
function updateBanner() {
  const b = $('banner'); const synth = [...state.events.values()].some((e) => e.synthetic) || state.replayActive;
  const degraded = [...state.feeds.values()].some((f) => f.state === 'degraded' || f.state === 'snapshot');
  b.hidden = !(synth || degraded); b.textContent = synth ? t('banner.synthetic') : t('banner.snapshot');
}

// ---------- stream ----------
function connect(since = 0) {
  const es = new EventSource(`/api/stream?since=${since}`);
  es.addEventListener('hello', () => { window.__fangs.streaming = true; });
  es.addEventListener('event', (m) => {
    const d = JSON.parse(m.data); upsertEvent(d.event);
    if (d.t0) { const lat = Date.now() - d.t0; state.lat.push(lat); $('st-lat-wrap').hidden = false; $('st-lat').textContent = lat; performance.mark?.('fangs-event'); }
    renderQueue();
    if (d.created) $('live').textContent = t('live.new', { band: t(`band.${d.event.score?.band || 'low'}`), label: d.event.indicator });
    updateBanner();
  });
  es.addEventListener('event-update', (m) => { const d = JSON.parse(m.data); upsertEvent(d.event); renderQueue(); if (state.selected?.id === d.event.id) showSelection(state.selected); });
  es.addEventListener('graph-delta', (m) => applyGraphDelta(JSON.parse(m.data)));
  es.addEventListener('analytics', (m) => applyAnalytics(JSON.parse(m.data)));
  es.addEventListener('feed', (m) => { const f = JSON.parse(m.data); state.feeds.set(f.name, f); renderFeeds(); updateBanner(); });
}

// ---------- boot ----------
async function boot() {
  let lang = 'en', theme = 'dark';
  try { lang = localStorage.getItem('fangs.lang') || (navigator.language || 'en').slice(0, 2); theme = localStorage.getItem('fangs.theme') || 'dark'; } catch { /* defaults */ }
  if (!['en', 'es'].includes(lang)) lang = 'en';
  $('lang').value = lang; setTheme(theme); await loadLang(lang);
  // Remember the stream position BEFORE loading state, then replay from it: nothing published in the gap is lost.
  const seq0 = (await fetch('/api/health').then((r) => r.json())).seq;
  const [g, evs, feeds] = await Promise.all([fetch('/api/graph').then((r) => r.json()), fetch('/api/events').then((r) => r.json()), fetch('/api/feeds').then((r) => r.json())]);
  for (const e of evs.events) upsertEvent(e);
  for (const f of feeds.feeds) state.feeds.set(f.name, f);
  state.replayActive = !!feeds.replay?.running;
  initGraph(g); renderQueue(); renderFeeds(); updateBanner(); connect(seq0);
  $('lang').addEventListener('change', (e) => loadLang(e.target.value));
  $('theme').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('colorBy').addEventListener('change', (e) => { state.colorBy = e.target.value; styleGraph(); });
  $('sizeBy').addEventListener('change', (e) => { state.sizeBy = e.target.value; styleGraph(); });
  $('search').addEventListener('input', (e) => { const q = e.target.value.trim().toLowerCase(); state.cy.elements().removeClass('hot dim'); if (!q) return; const m = state.cy.nodes().filter((n) => n.data('label').toLowerCase().includes(q)); if (m.nonempty()) { state.cy.elements().not(m.closedNeighborhood()).addClass('dim'); m.addClass('hot'); } });
  $('relayout').addEventListener('click', () => fetch('/api/relayout', { method: 'POST', headers: { 'x-fangs': '1' } }));
  $('replay').addEventListener('click', async () => { state.replayActive = true; updateBanner(); await fetch('/api/replay', { method: 'POST', headers: { 'x-fangs': '1', 'content-type': 'application/json' }, body: JSON.stringify({ rateHz: 8 }) }); });
  window.__fangs.ready = true;
}
boot();
