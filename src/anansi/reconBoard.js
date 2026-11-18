/**
 * Ananzi FANGS — RECON board (event reconstruction).
 *
 * Ties the pure recon models into one collapsible FANGS surface:
 *   • a plain-English narrative of the correlated incidents,
 *   • a timeline strip you can scrub to replay the board "as of" a time,
 *   • incident cards with a reconstructed Cyber Kill Chain + confidence,
 *   • rising-campaign trends,
 *   • a link-analysis graph of shared infrastructure.
 *
 * Honest by construction: everything carries the correlation disclaimer, and
 * the timeline is "as reported", never "as happened". Rendering only; all logic
 * is in src/data/incidentCorrelation|reconTimeline|reconGraph|reconNarrative|
 * reconCampaign.js.
 */
import { correlateIncidents, collectReconEvents, toEvent, RECON_DISCLAIMER } from '../data/incidentCorrelation.js';
import { buildTimeline, visibleAsOf, axisLabel } from '../data/reconTimeline.js';
import { buildGraph, layoutGraph } from '../data/reconGraph.js';
import { narrate, caseFile } from '../data/reconNarrative.js';
import { techniqueTrends, topRising } from '../data/reconCampaign.js';
import { techniqueUrl } from '../data/attackTtp.js';

const SVG = 'http://www.w3.org/2000/svg';
const CONF_COLOR = { High: '#ff2b2b', Medium: '#ff8a1f', Low: '#d4af37' };

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function svg(doc, tag, attrs = {}) {
  const n = doc.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  return n;
}

export function createReconBoard(doc = document, { now = () => Date.now(), onReplay = null } = {}) {
  const wrap = el(doc, 'section', 'recon collapsed');
  wrap.setAttribute('aria-label', 'Event reconstruction');
  const head = el(doc, 'div', 'recon-head');
  const headL = el(doc, 'div', 'recon-headL');
  const toggle = el(doc, 'button', 'recon-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'recon-title', '◆ RECON · event reconstruction');
  const tally = el(doc, 'span', 'recon-tally', '');
  headL.append(toggle, title);
  head.append(headL, tally);

  const body = el(doc, 'div', 'recon-body');
  const narrative = el(doc, 'p', 'recon-narrative', '');
  const disclaimer = el(doc, 'p', 'recon-disclaimer', RECON_DISCLAIMER);
  // Timeline + scrubber.
  const tlWrap = el(doc, 'div', 'recon-timeline');
  const tlSvgBox = el(doc, 'div', 'recon-tl-bars');
  const scrub = el(doc, 'input', 'recon-scrub');
  scrub.type = 'range';
  scrub.min = '0';
  scrub.max = '100';
  scrub.value = '100';
  const asOf = el(doc, 'div', 'recon-asof', 'Live');
  tlWrap.append(tlSvgBox, scrub, asOf);
  const campaign = el(doc, 'div', 'recon-campaign');
  const list = el(doc, 'div', 'recon-list');
  const graphBox = el(doc, 'div', 'recon-graph');
  const empty = el(doc, 'div', 'recon-empty', 'No correlated incidents yet.');
  body.append(narrative, disclaimer, tlWrap, campaign, graphBox, list, empty);
  wrap.append(head, body);

  // Collapse (remembered; collapsed by default — it is a heavy surface).
  const STORE_KEY = 'ananzi.fangs.recon.collapsed';
  let collapsed = true;
  try { const v = globalThis.localStorage?.getItem(STORE_KEY); if (v != null) collapsed = v === '1'; } catch { /* private mode */ }
  function applyCollapsed() {
    wrap.classList.toggle('collapsed', collapsed);
    toggle.setAttribute('aria-expanded', String(!collapsed));
    toggle.title = collapsed ? 'Expand reconstruction' : 'Collapse reconstruction';
  }
  const setCollapsed = (n) => { collapsed = n; try { globalThis.localStorage?.setItem(STORE_KEY, n ? '1' : '0'); } catch { /* ignore */ } applyCollapsed(); if (!n) renderDerived(); };
  toggle.addEventListener('click', () => setCollapsed(!collapsed));
  title.style.cursor = 'pointer';
  title.addEventListener('click', () => setCollapsed(!collapsed));
  applyCollapsed();

  let allEvents = [];
  let span = { start: 0, end: 0 };

  function killChainBar(inc) {
    const bar = el(doc, 'span', 'recon-kc');
    const seen = new Set((inc.killChain || []).map((p) => p.index));
    for (let i = 1; i <= 7; i++) {
      const seg = el(doc, 'span', `recon-kc-seg${seen.has(i) ? ' on' : ''}`);
      seg.title = `${i}. ${['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command & Control', 'Actions on Objectives'][i - 1]}`;
      bar.append(seg);
    }
    return bar;
  }

  function incidentCard(inc) {
    const card = el(doc, 'article', 'recon-card');
    card.style.setProperty('--conf', CONF_COLOR[inc.confidence] || '#d4af37');
    const top = el(doc, 'div', 'recon-card-top');
    const pill = el(doc, 'span', 'recon-conf', inc.confidence);
    top.append(pill, el(doc, 'span', 'recon-card-title', inc.title));
    card.append(top);
    const meta = el(doc, 'div', 'recon-card-meta');
    meta.append(killChainBar(inc), el(doc, 'span', 'recon-kc-cov', `${inc.killChainCoverage}/7`));
    card.append(meta);
    if ((inc.techniques || []).length) {
      const tl = el(doc, 'div', 'recon-techs');
      for (const t of inc.techniques.slice(0, 6)) {
        const a = el(doc, 'a', 'recon-tech', t.id);
        a.href = techniqueUrl(t.id);
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.title = `${t.name} · ${t.tacticName}`;
        tl.append(a);
      }
      card.append(tl);
    }
    const foot = el(doc, 'div', 'recon-card-foot');
    foot.append(el(doc, 'span', 'recon-card-sub', `${(inc.sources || []).length} source${(inc.sources || []).length === 1 ? '' : 's'} · ${(inc.infrastructure || []).length} infra`));
    const copy = el(doc, 'button', 'recon-copy', 'copy case file');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      const md = caseFile(inc);
      try { await globalThis.navigator?.clipboard?.writeText(md); copy.textContent = 'copied ✓'; }
      catch { copy.textContent = 'copy failed'; }
      setTimeout(() => { copy.textContent = 'copy case file'; }, 1800);
    });
    foot.append(copy);
    card.append(foot);
    return card;
  }

  function renderTimeline() {
    const tl = buildTimeline(allEvents, { now: now() });
    span = { start: tl.start, end: tl.end };
    const w = 100;
    const h = 28;
    const s = svg(doc, 'svg', { viewBox: `0 0 ${w} ${h}`, preserveAspectRatio: 'none', class: 'recon-tl-svg' });
    const bw = w / tl.bins.length;
    tl.bins.forEach((b, i) => {
      const bh = tl.max ? (b.count / tl.max) * (h - 2) : 0;
      if (bh <= 0) return;
      s.append(svg(doc, 'rect', { x: (i * bw).toFixed(2), y: (h - bh).toFixed(2), width: Math.max(0.4, bw - 0.3).toFixed(2), height: bh.toFixed(2), fill: '#f4cf5e', opacity: 0.8 }));
    });
    tlSvgBox.replaceChildren(s);
  }

  function renderCampaign(events) {
    const rising = topRising(techniqueTrends(events, { now: now() }), { limit: 4 });
    if (!rising.length) { campaign.replaceChildren(); campaign.hidden = true; return; }
    campaign.hidden = false;
    campaign.replaceChildren(el(doc, 'span', 'recon-campaign-h', 'RISING'));
    for (const r of rising) {
      const a = el(doc, 'a', 'recon-campaign-item', `▲ ${r.technique.id} ${r.technique.name} +${r.delta}`);
      a.href = techniqueUrl(r.technique.id);
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      campaign.append(a);
    }
  }

  function renderGraph(events) {
    const g = layoutGraph(buildGraph(events), { width: 300, height: 180 });
    if (g.nodes.length <= 1) { graphBox.replaceChildren(); graphBox.hidden = true; return; }
    graphBox.hidden = false;
    const s = svg(doc, 'svg', { viewBox: '0 0 300 180', class: 'recon-graph-svg' });
    for (const e of g.edges) s.append(svg(doc, 'line', { x1: e.a.x, y1: e.a.y, x2: e.b.x, y2: e.b.y, stroke: 'rgba(212,175,55,0.3)', 'stroke-width': 0.6 }));
    for (const n of g.nodes) {
      const r = n.type === 'victim' ? 4 : 2 + Math.min(3, n.weight);
      const c = svg(doc, 'circle', { cx: n.x, cy: n.y, r, fill: n.color });
      const t = svg(doc, 'title');
      t.textContent = `${n.type}: ${n.label}`;
      c.append(t);
      s.append(c);
    }
    graphBox.replaceChildren(s);
  }

  // Recompute everything from the (possibly rewound) event set.
  function renderDerived() {
    if (collapsed) return;
    const live = scrub.value >= 100;
    const playMs = live ? now() : Math.round(span.start + ((Number(scrub.value) / 100) * (span.end - span.start)));
    const events = live ? allEvents : visibleAsOf(allEvents, playMs);
    asOf.textContent = live ? 'Live' : `as of ${axisLabel(playMs)}`;
    asOf.classList.toggle('rewound', !live);
    const incidents = correlateIncidents(events, { now: now() });
    // Drive the globe: replay country-level signal pulses as-of the playhead.
    try { onReplay?.({ live, playheadMs: playMs, events: allEvents }); } catch { /* map not ready */ }
    tally.textContent = incidents.length ? `${incidents.length} incident${incidents.length === 1 ? '' : 's'}` : '';
    narrative.textContent = narrate(incidents, { now: now() });
    renderCampaign(events);
    renderGraph(events);
    empty.hidden = incidents.length > 0;
    list.replaceChildren(...incidents.map(incidentCard));
  }

  scrub.addEventListener('input', renderDerived);

  function update(snapshots) {
    // Normalize once; every model (timeline, graph, campaign, correlation)
    // then works on the same canonical events (toEvent is idempotent).
    allEvents = collectReconEvents(snapshots || {}).map((e) => toEvent(e, { now: now() }));
    renderTimeline();
    renderDerived();
  }

  return { element: wrap, update };
}
