/**
 * Ananzi FANGS — MITRE ATT&CK heat map.
 *
 * Tallies the ATT&CK techniques across everything FANGS is showing right now
 * (attack-map alerts + the cyber-news wire + exploited vulns) and ranks them by
 * how "hot" they are — the heat-map view CySA+ calls out for threat
 * visualization. Sits at the top of the one-pane SITREP dashboard.
 *
 * tally/build are pure (unit-tested in attackHeatmap.test.mjs); the renderer is
 * a tiny live widget fed a list of event hints.
 */
import { ttpFor, techniqueUrl } from '../data/attackTtp.js';

/** Count ATT&CK techniques across event hints. @returns {Map<string, {technique,count}>} */
export function tallyTechniques(events = []) {
  const tally = new Map();
  for (const ev of events) {
    if (!ev) continue;
    const { technique } = ttpFor(ev.layerId, ev.text || '');
    const prior = tally.get(technique.id);
    if (prior) prior.count += 1;
    else tally.set(technique.id, { technique, count: 1 });
  }
  return tally;
}

/** Ranked, hottest-first rows with the peak count for scaling. */
export function buildHeat(tally, { limit = 8 } = {}) {
  const rows = [...tally.values()].sort(
    (a, b) => b.count - a.count || a.technique.id.localeCompare(b.technique.id),
  );
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0);
  return { rows: rows.slice(0, limit), max };
}

/** Tactic → heat-bar colour (warm only; Impact/Exfil run hotter). */
const TACTIC_COLOR = {
  Reconnaissance: '#d4af37',
  'Resource Development': '#e8c98a',
  'Initial Access': '#ff8a1f',
  'Credential Access': '#ff8a1f',
  'Command and Control': '#ff6b4a',
  Exfiltration: '#ff5a5a',
  Impact: '#ff2b2b',
};

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** A live ATT&CK heat widget: { element, update(events) }. */
export function createAttackHeatmap(doc = document) {
  const wrap = el(doc, 'section', 'attack-heat');
  wrap.setAttribute('aria-label', 'MITRE ATT&CK heat map');
  const head = el(doc, 'div', 'attack-heat-head', '◆ ATT&CK HEAT · live');
  const list = el(doc, 'div', 'attack-heat-list');
  const empty = el(doc, 'div', 'attack-heat-empty', 'No mapped activity yet.');
  wrap.append(head, list, empty);

  function update(events) {
    const { rows, max } = buildHeat(tallyTechniques(events));
    empty.hidden = rows.length > 0;
    if (!rows.length) { list.replaceChildren(); return; }
    list.replaceChildren(...rows.map(({ technique, count }) => {
      const row = el(doc, 'a', 'attack-heat-row');
      row.href = techniqueUrl(technique.id);
      row.target = '_blank';
      row.rel = 'noopener noreferrer';
      row.title = `${technique.tacticName} · ${count} event${count === 1 ? '' : 's'}`;
      const bar = el(doc, 'span', 'attack-heat-bar');
      bar.style.width = `${Math.max(8, Math.round((count / max) * 100))}%`;
      bar.style.background = TACTIC_COLOR[technique.tacticName] || '#d4af37';
      row.append(
        el(doc, 'span', 'attack-heat-id', technique.id),
        el(doc, 'span', 'attack-heat-name', technique.name),
        bar,
        el(doc, 'span', 'attack-heat-count', String(count)),
      );
      return row;
    }));
  }

  return { element: wrap, update };
}
