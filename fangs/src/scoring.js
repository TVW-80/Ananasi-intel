// Severity scoring: CISA KEV + FIRST EPSS + corroboration + family weight + freshness + graph centrality.
// KEV/EPSS come from the live feeds when reachable, otherwise from data/fixtures/kev-epss.sample.json,
// which is a SYNTHETIC SAMPLE (illustrative values). Every score records its `basis` so the UI can say so.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { clamp } from './util.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';

export const WEIGHTS = { kev: 0.30, epss: 0.20, corroboration: 0.15, family: 0.15, freshness: 0.10, centrality: 0.10 };

// Rough operational weight of a family class. Editable knowledge, not data from a feed.
const FAMILY_WEIGHT = { cobaltstrike: 0.9, sliver: 0.8, havoc: 0.8, bruteratel: 0.9, mythic: 0.7, metasploit: 0.6, qakbot: 0.9, emotet: 0.9, icedid: 0.85,
  bumblebee: 0.8, pikabot: 0.8, dridex: 0.85, trickbot: 0.85, asyncrat: 0.5, remcos: 0.5, mirai: 0.5, lumma: 0.6, redline: 0.6 };
export const familyWeight = (k) => (k ? FAMILY_WEIGHT[k] ?? 0.4 : 0.25);

export class VulnIntel {
  constructor() { this.kev = new Set(); this.epss = new Map(); this.basis = 'none'; this.loadedAt = null; }
  loadFixture(file = path.join(HERE, '..', 'data', 'fixtures', 'kev-epss.sample.json')) {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    this.kev = new Set(j.kev); this.epss = new Map(Object.entries(j.epss)); this.basis = 'fixture'; this.loadedAt = new Date().toISOString();
    return this;
  }
  async refresh({ fetchFn = fetch } = {}) {
    const kevRes = await fetchFn(KEV_URL, { signal: AbortSignal.timeout(10000) });
    if (!kevRes.ok) throw new Error(`KEV HTTP ${kevRes.status}`);
    const kj = await kevRes.json();
    const kev = new Set((kj.vulnerabilities || []).map((v) => v.cveID));
    if (!kev.size) throw new Error('KEV empty');
    this.kev = kev; this.basis = 'live-kev'; this.loadedAt = new Date().toISOString();
    return this;
  }
  async epssFor(cves, { fetchFn = fetch } = {}) {
    const need = cves.filter((c) => !this.epss.has(c));
    if (!need.length) return;
    try {
      const r = await fetchFn(`${EPSS_URL}?cve=${need.join(',')}`, { signal: AbortSignal.timeout(6000) });
      if (!r.ok) return;
      const j = await r.json();
      for (const d of j.data || []) this.epss.set(d.cve, Number(d.epss));
      if (this.basis !== 'fixture') this.basis = 'live';
    } catch { /* keep whatever we have; basis stays honest */ }
  }
  lookup(cves = []) {
    let kev = 0, epss = 0;
    for (const c of cves) { if (this.kev.has(c)) kev = 1; epss = Math.max(epss, this.epss.get(c) || 0); }
    return { kev, epss };
  }
}

// features: {kev, epss, sources (count), family, ageHours, centrality (0..1 normalised)}
export function severity(f) {
  const comp = {
    kev: f.kev ? 1 : 0,
    epss: clamp(f.epss || 0, 0, 1),
    corroboration: clamp(((f.sources || 1) - 1) / 2, 0, 1),
    family: familyWeight(f.family),
    freshness: Math.exp(-Math.max(0, f.ageHours || 0) / 72),
    centrality: clamp(f.centrality || 0, 0, 1),
  };
  let s = 0;
  for (const k of Object.keys(WEIGHTS)) s += WEIGHTS[k] * comp[k];
  const score = Math.round(clamp(s, 0, 1) * 1000) / 10;
  const band = score >= 55 ? 'critical' : score >= 40 ? 'high' : score >= 25 ? 'medium' : 'low';
  return { score, band, components: comp };
}
