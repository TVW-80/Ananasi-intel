import Graph from 'graphology';
import { rng } from '../../src/util.js';
// Planted-partition graph with FANGS-shaped attributes, for layout/analytics timing at a stated size.
export function plantedGraph(n = 1000, { groups = 20, avgDeg = 3, pIn = 0.9, seed = 5 } = {}) {
  const R = rng(seed); const g = new Graph({ type: 'undirected', multi: false, allowSelfLoops: false });
  for (let i = 0; i < n; i++) g.addNode(`n${i}`, { type: 'ip', label: `n${i}`, attrs: {}, prov: ['x'], sources: ['x'], grp: i % groups });
  const m = Math.round((n * avgDeg) / 2);
  let added = 0, guard = 0;
  while (added < m && guard++ < m * 20) {
    const a = Math.floor(R() * n); let b;
    if (R() < pIn) { const off = Math.floor(R() * (n / groups)); b = (a % groups) + off * groups; if (b >= n) continue; } else b = Math.floor(R() * n);
    if (a === b || g.hasEdge(`n${a}`, `n${b}`)) continue;
    g.addEdge(`n${a}`, `n${b}`, { rels: [{ type: 'hosts', src: `n${a}`, dst: `n${b}`, prov: ['x'] }] }); added++;
  }
  return g;
}
