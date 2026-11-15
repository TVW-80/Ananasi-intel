// Server-side graph analytics with graphology: Louvain communities, degree + betweenness centrality, layout.
import louvain from 'graphology-communities-louvain';
import betweenness from 'graphology-metrics/centrality/betweenness.js';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { rng } from './util.js';

const BASE_W = { hosts: 1, 'resolves-to': 1, attacks: 0.6, 'same-asn': 0.5 };

// Edge weight for community detection. Mega-hubs (a hosting ASN with hundreds of members, a fronting
// domain used by unrelated crews) would otherwise glue unrelated campaigns together, so we damp them.
export function makeWeightFn(graph) {
  return (_k, attrs, s, t) => {
    let w = 0;
    for (const r of attrs.rels) {
      let rw = BASE_W[r.type] ?? 0.5;
      if (r.type === 'same-asn') {
        const asn = graph.getNodeAttribute(s, 'type') === 'asn' ? s : t;
        rw = rw / Math.log2(2 + Math.max(0, graph.degree(asn) - 1));
      }
      const hostEnd = [s, t].find((n) => graph.getNodeAttribute(n, 'type') === 'host');
      if (hostEnd && graph.getNodeAttribute(hostEnd, 'attrs')?.role === 'fronting') rw *= 0.1;
      w = Math.max(w, rw);
    }
    return Math.max(w, 1e-3);
  };
}

export function analyze(graph, { seed = 7 } = {}) {
  const t0 = performance.now();
  const out = { communities: {}, modularity: 0, count: 0, degree: {}, betweenness: {}, ms: {} };
  if (graph.order === 0) return out;
  const gw = makeWeightFn(graph);
  let t = performance.now();
  const det = louvain.detailed(graph, { getEdgeWeight: gw, rng: rng(seed), resolution: 1 });
  out.communities = det.communities; out.modularity = det.modularity; out.count = det.count;
  out.ms.louvain = performance.now() - t;
  t = performance.now();
  graph.forEachNode((n) => { out.degree[n] = graph.degree(n); });
  out.ms.degree = performance.now() - t;
  t = performance.now();
  out.betweenness = betweenness(graph, { normalized: true });
  out.ms.betweenness = performance.now() - t;
  out.ms.total = performance.now() - t0;
  return out;
}

// Community-seeded initial placement (communities start as separate wedges), then ForceAtlas2.
// Positions are written to node attributes x/y. Deterministic for a given seed.
export function layout(graph, communities = {}, { iterations = 80, seed = 11, scale = 100 } = {}) {
  // (positions are written to node attributes x/y)
  const t0 = performance.now();
  if (graph.order === 0) return { ms: 0 };
  const r = rng(seed);
  const cids = [...new Set(Object.values(communities))];
  const K = Math.max(1, cids.length);
  graph.forEachNode((n, a) => {
    if (typeof a.x === 'number' && typeof a.y === 'number' && a.pinned) return;
    const c = cids.indexOf(communities[n]);
    const ang = ((c < 0 ? r() * K : c) / K) * Math.PI * 2;
    const rad = scale * (0.5 + r());
    graph.mergeNodeAttributes(n, { x: Math.cos(ang) * rad + (r() - 0.5) * scale * 0.4, y: Math.sin(ang) * rad + (r() - 0.5) * scale * 0.4 });
  });
  const settings = { ...forceAtlas2.inferSettings(graph), barnesHutOptimize: graph.order > 200, barnesHutTheta: 0.8, slowDown: 2, gravity: 1, scalingRatio: 4 };
  forceAtlas2.assign(graph, { iterations, settings, getEdgeWeight: null });
  // Normalise spread: target RMS radius grows with sqrt(N) so node glyphs (fixed pixel size) don't overlap.
  let cx = 0, cy = 0, n = 0;
  graph.forEachNode((_, a) => { cx += a.x; cy += a.y; n++; });
  cx /= n; cy /= n;
  let ms2 = 0; graph.forEachNode((_, a) => { ms2 += (a.x - cx) ** 2 + (a.y - cy) ** 2; });
  const rms = Math.sqrt(ms2 / n) || 1, k = (24 * Math.sqrt(n)) / rms;
  graph.updateEachNodeAttributes((_, a) => ({ ...a, x: (a.x - cx) * k, y: (a.y - cy) * k }), { attributes: ['x', 'y'] });
  return { ms: performance.now() - t0 };
}

// Place a brand-new node near the centroid of its already-placed neighbours (cheap incremental update).
export function placeIncremental(graph, nodeId, seed = 1) {
  const r = rng((seed + [...nodeId].reduce((a, c) => a + c.charCodeAt(0), 0)) >>> 0);
  let sx = 0, sy = 0, n = 0;
  graph.forEachNeighbor(nodeId, (nb, a) => { if (typeof a.x === 'number') { sx += a.x; sy += a.y; n++; } });
  const cx = n ? sx / n : (r() - 0.5) * 200, cy = n ? sy / n : (r() - 0.5) * 200;
  graph.mergeNodeAttributes(nodeId, { x: cx + (r() - 0.5) * 24, y: cy + (r() - 0.5) * 24 });
}
