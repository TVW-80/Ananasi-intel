/**
 * Ananzi FANGS — RECON link-analysis graph model (pure).
 *
 * Turns the correlated events into a node-link graph (adversary ↔ technique ↔
 * infrastructure ↔ malware ↔ CVE ↔ victim) so an analyst can pivot and see
 * shared infrastructure across incidents — the aggregate of the per-event
 * Diamond Model. Layout is deterministic (type rings), so it is unit-testable
 * and renders the same every time.
 */

const str = (v) => (v == null ? '' : String(v).trim());
export const HOME_VICTIM = 'Hampton Roads';

// Ring order (inner → outer) and colour per node type.
export const NODE_TYPES = ['victim', 'adversary', 'technique', 'malware', 'cve', 'infra'];
const TYPE_COLOR = {
  victim: '#8fd46b', adversary: '#ff2b2b', technique: '#f4cf5e',
  malware: '#c061dd', cve: '#ff8a1f', infra: '#3fd0ff',
};

/**
 * Build the graph from correlated events (or an incident's events).
 * @returns {{nodes:Array<{id,type,label,weight,color}>, edges:Array<{from,to}>}}
 */
export function buildGraph(events = [], { home = HOME_VICTIM, maxNodes = 60 } = {}) {
  const nodes = new Map();
  const edgeSet = new Set();
  const edges = [];
  const add = (type, label) => {
    const id = `${type}:${label}`;
    if (!nodes.has(id)) nodes.set(id, { id, type, label, weight: 0, color: TYPE_COLOR[type] || '#d4af37' });
    nodes.get(id).weight += 1;
    return id;
  };
  const link = (a, b) => {
    if (!a || !b || a === b) return;
    const key = a < b ? `${a}__${b}` : `${b}__${a}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);
    edges.push({ from: a, to: b });
  };

  const victim = add('victim', home);
  for (const e of events || []) {
    if (!e) continue;
    const adv = e.adversary && e.adversary !== 'Unknown' ? add('adversary', e.adversary) : null;
    const tech = e.technique?.id ? add('technique', e.technique.id) : null;
    const mal = str(e.malware) ? add('malware', str(e.malware)) : null;
    const cve = str(e.cve) ? add('cve', str(e.cve)) : null;
    const infraLabel = str(e.ip) || str(e.asn);
    const infra = infraLabel ? add('infra', infraLabel) : null;
    // Wire the event's entities together and to the victim.
    link(adv, tech);
    link(adv, infra);
    link(tech, victim);
    link(infra, tech);
    link(mal, infra || tech);
    link(cve, tech);
    if (!adv && tech) link(tech, victim);
  }

  // Cap: keep the victim + highest-weight nodes.
  let list = [...nodes.values()].sort((a, b) => b.weight - a.weight);
  if (list.length > maxNodes) {
    const keep = new Set(list.slice(0, maxNodes).map((n) => n.id));
    keep.add(victim);
    list = list.filter((n) => keep.has(n.id));
    const keptIds = new Set(list.map((n) => n.id));
    return { nodes: list, edges: edges.filter((e) => keptIds.has(e.from) && keptIds.has(e.to)) };
  }
  return { nodes: list, edges };
}

/**
 * Deterministic layout: each node type sits on a ring, spaced evenly.
 * @returns {{nodes:Array<{...,x,y}>, edges}}
 */
export function layoutGraph(graph, { width = 320, height = 260 } = {}) {
  const cx = width / 2;
  const cy = height / 2;
  const rings = NODE_TYPES.map((t, i) => (i === 0 ? 0 : (Math.min(width, height) / 2 - 16) * (i / (NODE_TYPES.length - 1))));
  const byType = new Map();
  for (const n of graph.nodes) {
    if (!byType.has(n.type)) byType.set(n.type, []);
    byType.get(n.type).push(n);
  }
  const placed = graph.nodes.map((n) => {
    const peers = byType.get(n.type);
    const ti = NODE_TYPES.indexOf(n.type);
    const ringR = ti >= 0 ? rings[ti] : rings[rings.length - 1];
    const k = peers.indexOf(n);
    if (ringR === 0) return { ...n, x: cx, y: cy };
    const angle = (2 * Math.PI * k) / peers.length - Math.PI / 2;
    return { ...n, x: Math.round(cx + ringR * Math.cos(angle)), y: Math.round(cy + ringR * Math.sin(angle)) };
  });
  const pos = new Map(placed.map((n) => [n.id, n]));
  return { nodes: placed, edges: graph.edges.map((e) => ({ ...e, a: pos.get(e.from), b: pos.get(e.to) })).filter((e) => e.a && e.b) };
}
