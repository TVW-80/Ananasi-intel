// Keyed / optional sources. Each is skipped (reported as "needs key") unless its env var is set.
// None of these can be exercised live from the build sandbox (egress blocked); response shapes follow vendor
// docs and are covered by fixture tests only. Treat live behaviour as UNVERIFIED until run with a real key.
import { ipNode, victimNode, campaignNode, edge, result } from './base.js';
import { nowIso, sha1short } from '../util.js';

// Cloudflare Radar: aggregate (not record-level) attack origin->target location shares. Token: CLOUDFLARE_API_TOKEN.
export const radar = {
  name: 'radar', label: 'Cloudflare Radar', keyed: 'CLOUDFLARE_API_TOKEN', intervalMs: 3600_000,
  async fetchAll({ env = process.env } = {}) {
    const url = 'https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?limit=10&dateRange=1d&format=json';
    const res = await fetch(url, { headers: { authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` }, signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return [{ text: await res.text(), url }];
  },
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      let j; try { j = JSON.parse(text); } catch { continue; }
      const rows = j?.result?.top_0 || j?.result?.top || [];
      for (const r of rows) {
        const cc = r.originCountryAlpha2 || r.clientCountryAlpha2 || r.countryCode;
        if (!cc) continue;
        recs.push({ id: `radar:${cc}:${sha1short(JSON.stringify(r))}`, source: 'radar', origin: url || 'radar', fetched_at: retrieved_at || nowIso(), raw: { cc, name: r.originCountryName || r.countryName || cc, value: r.value ?? null, rank: r.rank ?? null } });
      }
    }
    return recs;
  },
  // Aggregate record => a country-level context node only (no host-level edges are invented from it).
  extract(rec) {
    const v = victimNode(rec.raw.name, 'country');
    return result({ nodes: [v], edges: [], events: [] });
  },
};

// GreyNoise Community API: per-IP classification. Key: GREYNOISE_API_KEY. Annotates existing ip nodes.
export const greynoise = {
  name: 'greynoise', label: 'GreyNoise', keyed: 'GREYNOISE_API_KEY', intervalMs: 0,
  async lookup(ip, { env = process.env } = {}) {
    const res = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { headers: { key: env.GREYNOISE_API_KEY }, signal: AbortSignal.timeout(8000) });
    if (res.status === 404) return { text: JSON.stringify({ ip, noise: false, riot: false, classification: 'unknown', message: 'IP not observed' }), url: `https://api.greynoise.io/v3/community/${ip}` };
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { text: await res.text(), url: `https://api.greynoise.io/v3/community/${ip}` };
  },
  parse(inputs) {
    return inputs.flatMap(({ text, url, retrieved_at }) => {
      let j; try { j = JSON.parse(text); } catch { return []; }
      return j?.ip ? [{ id: `greynoise:${j.ip}`, source: 'greynoise', origin: url, fetched_at: retrieved_at || nowIso(), raw: { ip: j.ip, noise: !!j.noise, riot: !!j.riot, classification: j.classification || 'unknown', name: j.name || null } }] : [];
    });
  },
  extract(rec) {
    const r = rec.raw;
    return result({ nodes: [ipNode(r.ip, { greynoise: r.classification, noise: r.noise, riot: r.riot })], edges: [], events: [] });
  },
};

// AlienVault OTX: per-IP pulses -> campaign nodes + targeted-country victims. Key: OTX_API_KEY.
export const otx = {
  name: 'otx', label: 'AlienVault OTX', keyed: 'OTX_API_KEY', intervalMs: 0,
  async lookup(ip, { env = process.env } = {}) {
    const url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`;
    const res = await fetch(url, { headers: { 'X-OTX-API-KEY': env.OTX_API_KEY }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { text: await res.text(), url };
  },
  parse(inputs) {
    return inputs.flatMap(({ text, url, retrieved_at }) => {
      let j; try { j = JSON.parse(text); } catch { return []; }
      const ip = j?.indicator;
      const pulses = j?.pulse_info?.pulses || [];
      if (!ip || !pulses.length) return [];
      return [{ id: `otx:${ip}`, source: 'otx', origin: url, fetched_at: retrieved_at || nowIso(),
        raw: { ip, pulses: pulses.slice(0, 5).map((p) => ({ id: p.id, name: p.name, adversary: p.adversary || null, targeted_countries: p.targeted_countries || [] })) } }];
    });
  },
  extract(rec) {
    const ipn = ipNode(rec.raw.ip);
    const nodes = [ipn], edges = [];
    for (const p of rec.raw.pulses) {
      const c = campaignNode(p.name);
      nodes.push(c);
      edges.push(edge('hosts', c, ipn));
      for (const cc of p.targeted_countries) { const v = victimNode(cc, 'country'); nodes.push(v); edges.push(edge('attacks', c, v)); }
    }
    return result({ nodes, edges, events: [] });
  },
};
