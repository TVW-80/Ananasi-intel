// Shared constructors for node/edge/event objects emitted by adapters' pure extract().
import { isPublicIP, normDomain, famKey, famLabel } from '../util.js';

export const ipNode = (ip, attrs = {}) => (isPublicIP(ip) ? { id: `ip:${ip.toLowerCase()}`, type: 'ip', label: ip, attrs } : null);
export const hostNode = (d, attrs = {}) => { const n = normDomain(d); return n ? { id: `host:${n}`, type: 'host', label: n, attrs } : null; };
export const famNode = (name) => { const k = famKey(name); return k ? { id: `family:${k}`, type: 'family', label: famLabel(k), attrs: {} } : null; };
export const campaignNode = (name) => { const n = String(name || '').trim(); return n ? { id: `campaign:${n.toLowerCase().replace(/\s+/g, '-')}`, type: 'campaign', label: n, attrs: {} } : null; };
export const victimNode = (name, kind = 'victim') => { const n = String(name || '').trim(); return n ? { id: `victim:${n.toLowerCase().replace(/\s+/g, '-')}`, type: 'victim', label: n, attrs: { kind } } : null; };
export const asnNode = (asn, name, cc) => {
  const n = String(asn || '').replace(/^AS/i, '').trim();
  return /^\d{1,10}$/.test(n) ? { id: `asn:AS${n}`, type: 'asn', label: `AS${n}`, attrs: { name: name || null, cc: cc || null } } : null;
};
export const edge = (type, a, b) => (a && b && a.id !== b.id ? { type, src: a.id, dst: b.id } : null);

// Drops nulls; returns the standard extract() result.
export function result({ nodes = [], edges = [], events = [] }) {
  const seen = new Set();
  const ns = nodes.filter((n) => n && !seen.has(n.id) && seen.add(n.id));
  const ids = new Set(ns.map((n) => n.id));
  // An edge is only legal when both endpoints are nodes extracted from the same record.
  const es = edges.filter((e) => e && ids.has(e.src) && ids.has(e.dst));
  return { nodes: ns, edges: es, events };
}

export const parseCsvLine = (line) => {
  // C2IntelFeeds rows are simple (no quoted commas in the columns we use except the last, which is re-joined).
  return line.split(',');
};

export async function httpGet(url, { headers = {}, timeoutMs = 8000, signal } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'FANGS/0.1 (+defensive research; Ananzi)', ...headers }, signal: signal || ctl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally { clearTimeout(t); }
}
