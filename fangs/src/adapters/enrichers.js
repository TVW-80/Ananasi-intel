// ASN/geo enrichment: Team Cymru (DNS TXT) primary, RIPEstat (HTTP) fallback.
// Enrichment results are stored as records (source "cymru"/"ripestat") so each ip->asn edge has provenance.
// Both are blocked from the build sandbox; unit-tested via injected resolvers. If neither answers, the IP simply
// has no ASN edge: we never guess one.
import dns from 'node:dns/promises';
import net from 'node:net';
import { ipNode, asnNode, edge, result, httpGet } from './base.js';
import { nowIso } from '../util.js';

const rev4 = (ip) => ip.split('.').reverse().join('.');

export async function cymruLookup(ip, { resolveTxt = (n) => dns.resolveTxt(n), timeoutMs = 3000 } = {}) {
  if (net.isIP(ip) !== 4) return null; // IPv6 origin zone omitted for brevity; falls through to RIPEstat
  const withTimeout = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('dns timeout')), timeoutMs))]);
  const o = await withTimeout(resolveTxt(`${rev4(ip)}.origin.asn.cymru.com`));
  // "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"   (multi-origin: "13335 15169 | ...")
  const first = (o?.[0] || []).join('');
  const parts = first.split('|').map((s) => s.trim());
  const asn = (parts[0] || '').split(/\s+/)[0];
  if (!/^\d+$/.test(asn)) return null;
  let name = null;
  try {
    const n = await withTimeout(resolveTxt(`AS${asn}.asn.cymru.com`));
    name = ((n?.[0] || []).join('').split('|')[4] || '').trim() || null;
  } catch { /* name is optional */ }
  return { ip, asn, prefix: parts[1] || null, cc: parts[2] || null, registry: parts[3] || null, as_name: name };
}

export async function ripestatLookup(ip, { get = httpGet } = {}) {
  const url = `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`;
  const j = JSON.parse(await get(url));
  const a = j?.data?.asns?.[0];
  if (!a) return null;
  return { ip, asn: String(a.asn), prefix: j.data.resource || null, cc: null, registry: null, as_name: a.holder || null };
}

const enrichAdapter = (name, label) => ({
  name, label, keyed: null, intervalMs: 0,
  parse: (inputs) => inputs.map(({ raw, retrieved_at, url }) => ({ id: `${name}:${raw.ip}`, source: name, origin: url || name, fetched_at: retrieved_at || nowIso(), raw })),
  extract(rec) {
    const { ip, asn, as_name, cc } = rec.raw;
    const ipn = ipNode(ip), a = asnNode(asn, as_name, cc);
    return result({ nodes: [ipn, a], edges: [edge('same-asn', ipn, a)], events: [] });
  },
});
export const cymru = enrichAdapter('cymru', 'Team Cymru IP-to-ASN');
export const ripestat = enrichAdapter('ripestat', 'RIPEstat');

// Resolve with fallback chain; returns {record-input, provider} or null. Providers injectable for tests.
export async function enrichIP(ip, { providers } = {}) {
  const chain = providers || [['cymru', cymruLookup], ['ripestat', ripestatLookup]];
  const errors = [];
  for (const [name, fn] of chain) {
    try {
      const raw = await fn(ip);
      if (raw) return { provider: name, input: { raw, retrieved_at: nowIso(), url: name === 'ripestat' ? `https://stat.ripe.net/data/prefix-overview/data.json?resource=${ip}` : `dns:${rev4(ip)}.origin.asn.cymru.com` }, errors };
    } catch (e) { errors.push(`${name}: ${e.message}`); }
  }
  return { provider: null, input: null, errors };
}
