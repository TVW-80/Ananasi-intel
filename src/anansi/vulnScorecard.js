/**
 * Ananzi FANGS — vulnerability prioritization scorecard.
 *
 * A compact "PATCH PRIORITY" board for the one-pane SITREP: the live vuln
 * feed, re-sorted into a CySA+ action queue (P1 patch now / P2 this cycle /
 * P3 track) with the reasons spelled out. Sits under the ATT&CK heat map,
 * above the rolling cards.
 *
 * Rendering only; the ranking lives in src/data/vulnPriority.js.
 */
import { rankVulns, bandCounts } from '../data/vulnPriority.js';

/** Band → accent colour (P1 hottest). */
const BAND_COLOR = { P1: '#ff2b2b', P2: '#ff8a1f', P3: '#d4af37' };

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** A live scorecard widget: { element, update(vulns) }. */
export function createVulnScorecard(doc = document, { now = () => Date.now() } = {}) {
  const wrap = el(doc, 'section', 'vuln-score');
  wrap.setAttribute('aria-label', 'Vulnerability patch priority');
  const head = el(doc, 'div', 'vuln-score-head');
  const headL = el(doc, 'div', 'vuln-score-headL');
  const toggle = el(doc, 'button', 'vuln-score-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'vuln-score-title', '◆ PATCH PRIORITY · live');
  const tally = el(doc, 'span', 'vuln-score-tally', '');
  headL.append(toggle, title);
  head.append(headL, tally);
  const list = el(doc, 'div', 'vuln-score-list');
  const empty = el(doc, 'div', 'vuln-score-empty', 'No open vulnerabilities to triage.');
  wrap.append(head, list, empty);

  // Collapse toggle — remembered per viewer (best-effort; never throws).
  const STORE_KEY = 'ananzi.fangs.patchPriority.collapsed';
  let collapsed = false;
  try { collapsed = globalThis.localStorage?.getItem(STORE_KEY) === '1'; } catch { /* private mode */ }
  function applyCollapsed() {
    wrap.classList.toggle('collapsed', collapsed);
    toggle.setAttribute('aria-expanded', String(!collapsed));
    const label = collapsed ? 'Expand patch priority' : 'Collapse patch priority';
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  }
  function setCollapsed(next) {
    collapsed = next;
    try { globalThis.localStorage?.setItem(STORE_KEY, next ? '1' : '0'); } catch { /* private mode */ }
    applyCollapsed();
  }
  toggle.addEventListener('click', () => setCollapsed(!collapsed));
  title.style.cursor = 'pointer';
  title.addEventListener('click', () => setCollapsed(!collapsed));
  applyCollapsed();

  function update(vulns) {
    const ranked = rankVulns(vulns, { now: now(), limit: 6 });
    empty.hidden = ranked.length > 0;
    if (!ranked.length) {
      tally.textContent = '';
      list.replaceChildren();
      return;
    }
    const counts = bandCounts(ranked);
    tally.textContent = `P1 ${counts.P1} · P2 ${counts.P2} · P3 ${counts.P3}`;
    list.replaceChildren(
      ...ranked.map((v) => {
        const accent = BAND_COLOR[v.band] || '#d4af37';
        const link = v.link || v.evidence?.[0]?.url || '';
        const row = el(doc, link ? 'a' : 'div', 'vuln-score-row');
        row.style.setProperty('--band', accent);
        if (link) {
          row.href = link;
          row.target = '_blank';
          row.rel = 'noopener noreferrer';
        }
        const badge = el(doc, 'span', 'vuln-score-band', v.band);
        badge.title = v.bandLabel;
        const main = el(doc, 'div', 'vuln-score-main');
        main.append(
          el(doc, 'span', 'vuln-score-name', v.title || v.id || 'Unnamed vulnerability'),
          el(doc, 'span', 'vuln-score-why', v.factors.join(' · ')),
        );
        row.append(badge, main);
        return row;
      }),
    );
  }

  return { element: wrap, update };
}
