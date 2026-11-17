/**
 * Ananzi FANGS — Diamond Model of Intrusion Analysis.
 *
 * The Diamond Model (Caltagirone, Pendergast & Betz, 2013) frames every
 * intrusion event as four linked features: an ADVERSARY uses a CAPABILITY over
 * some INFRASTRUCTURE against a VICTIM. FANGS turns each clicked threat point
 * into that diamond — the apparent origin, the MITRE ATT&CK capability, the
 * attacking infrastructure, and you (Hampton Roads) as the victim — so an event
 * reads like an analyst's worksheet, not just a dot on a globe.
 *
 * buildDiamond is pure (unit-tested in diamond.test.mjs); renderDiamond draws
 * the classic four-vertex figure with the connecting edges.
 */
import { ttpFor } from '../data/attackTtp.js';

export const HOME_VICTIM = 'Hampton Roads, VA';

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const ASN_RE = /\bAS\s?\d{2,6}\b/i;

/** Best infrastructure string we can read from a threat point (IP / ASN / place). */
function pickInfrastructure(point) {
  const blob = [point.place, ...(point.items || []).flatMap((i) => [i.text, i.tech, i.plain])]
    .filter(Boolean)
    .join(' ');
  const ip = blob.match(IP_RE)?.[0];
  const asn = blob.match(ASN_RE)?.[0];
  if (ip && asn) return `${ip} · ${asn}`;
  if (ip) return ip;
  if (asn) return asn.toUpperCase().replace(/\s+/, '');
  return point.place ? `${point.place} netblocks` : 'Unknown infrastructure';
}

/**
 * Build the Diamond for a clicked threat point.
 * @returns {{adversary, capability, technique, techniqueUrl, infrastructure, victim}}
 */
export function buildDiamond(layer, point, { home = HOME_VICTIM } = {}) {
  const p = point || {};
  const hints = `${p.title || ''} ${p.place || ''} ${(p.items || []).map((i) => `${i.text || ''} ${i.tech || ''}`).join(' ')}`;
  const ttp = ttpFor(layer?.id, hints);
  return {
    adversary: p.place || 'Unattributed',
    capability: ttp.capability,
    technique: ttp.technique,
    techniqueUrl: ttp.url,
    infrastructure: pickInfrastructure(p),
    victim: home,
  };
}

/* ── render ──────────────────────────────────────────────────────────────── */

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function node(doc, cls, role, value) {
  const n = el(doc, 'div', `diamond-node ${cls}`);
  n.append(el(doc, 'span', 'diamond-role', role), el(doc, 'span', 'diamond-val', value));
  return n;
}

/** The four-vertex Diamond figure for a built diamond, as a DOM element. */
export function renderDiamond(doc, diamond) {
  const wrap = el(doc, 'div', 'diamond');
  wrap.setAttribute('role', 'group');
  wrap.setAttribute('aria-label', 'Diamond Model of this event');
  wrap.append(el(doc, 'div', 'diamond-kicker', `◆ DIAMOND MODEL · ${diamond.technique.tacticName}`));

  const grid = el(doc, 'div', 'diamond-grid');
  // Edges drawn behind the four nodes (perimeter + both diagonals).
  const svgNs = 'http://www.w3.org/2000/svg';
  const svg = doc.createElementNS(svgNs, 'svg');
  svg.setAttribute('class', 'diamond-edges');
  svg.setAttribute('viewBox', '0 0 100 100');
  svg.setAttribute('preserveAspectRatio', 'none');
  // Adversary top(50,6) · Capability left(14,50) · Infrastructure right(86,50) · Victim bottom(50,94)
  for (const [x1, y1, x2, y2] of [
    [50, 6, 14, 50], [50, 6, 86, 50], [50, 94, 14, 50], [50, 94, 86, 50], // perimeter
    [50, 6, 50, 94], [14, 50, 86, 50], // diagonals (socio-political / technology axes)
  ]) {
    const line = doc.createElementNS(svgNs, 'line');
    line.setAttribute('x1', x1); line.setAttribute('y1', y1);
    line.setAttribute('x2', x2); line.setAttribute('y2', y2);
    svg.appendChild(line);
  }
  grid.appendChild(svg);

  grid.append(
    node(doc, 'n-adversary', 'ADVERSARY', diamond.adversary),
    node(doc, 'n-capability', 'CAPABILITY', diamond.capability),
    node(doc, 'n-infrastructure', 'INFRASTRUCTURE', diamond.infrastructure),
    node(doc, 'n-victim', 'VICTIM', diamond.victim),
  );
  wrap.appendChild(grid);

  // ATT&CK technique line under the diamond, linking to attack.mitre.org.
  const ttp = el(doc, 'div', 'diamond-ttp');
  ttp.append(el(doc, 'span', 'diamond-ttp-tag', 'ATT&CK'));
  const link = el(doc, 'a', 'diamond-ttp-link', `${diamond.technique.id} · ${diamond.technique.name}`);
  link.href = diamond.techniqueUrl;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  ttp.append(link);
  wrap.appendChild(ttp);
  return wrap;
}
