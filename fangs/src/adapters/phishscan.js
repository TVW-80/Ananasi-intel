// OpenPhish (free text feed) and SANS ISC DShield (top attacking sources). Both keyless.
// Sandbox egress to both is policy-blocked, so tests use format fixtures (synthetic, labelled).
import { ipNode, hostNode, victimNode, famNode, asnNode, edge, result, httpGet } from './base.js';
import { hostFromUrl, sha1short, nowIso } from '../util.js';
import net from 'node:net';

export const openphish = {
  name: 'openphish', label: 'OpenPhish', keyed: null, intervalMs: 1800_000,
  async fetchAll() { const url = 'https://openphish.com/feed.txt'; return [{ text: await httpGet(url), url }]; },
  // Free feed = one URL per line. Also accepts JSON-lines {url, brand?, sector?} (premium-style) when supplied.
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      for (const line of text.split('\n')) {
        const l = line.trim();
        if (!l) continue;
        let raw;
        if (l.startsWith('{')) { try { raw = JSON.parse(l); } catch { continue; } } else raw = { url: l };
        if (!raw.url || !hostFromUrl(raw.url)) continue;
        recs.push({ id: `openphish:${sha1short(raw.url)}`, source: 'openphish', origin: url || 'openphish', fetched_at: retrieved_at || nowIso(), raw });
      }
    }
    return recs;
  },
  extract(rec) {
    const { url, brand } = rec.raw;
    const h = hostFromUrl(url);
    if (!h) return result({});
    const ipn = net.isIP(h) ? ipNode(h) : null;
    const hn = ipn ? null : hostNode(h, { role: 'phishing' });
    const target = ipn || hn;
    const victim = brand ? victimNode(brand, 'brand') : null;
    const edges = [edge('attacks', target, victim)];
    const events = target ? [{ key: `openphish|${target.id}|${sha1short(url)}`, kind: 'phish', family: null, indicator: url, node: target.id, ip: ipn?.label || null, host: hn?.label || null, tags: brand ? [`brand:${brand}`] : [], cve: [], victims: brand ? [brand] : [], ts: null }] : [];
    return result({ nodes: [ipn, hn, victim], edges, events });
  },
};

export const dshield = {
  name: 'dshield', label: 'SANS ISC DShield', keyed: null, intervalMs: 3600_000,
  async fetchAll() { const url = 'https://isc.sans.edu/api/topips/records/100?json'; return [{ text: await httpGet(url), url }]; },
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      let j; try { j = JSON.parse(text); } catch { continue; }
      const arr = Array.isArray(j) ? j : Array.isArray(j?.sources) ? j.sources : [];
      for (const o of arr) {
        const ip = o.source || o.ip || o.ipv4;
        if (!ip) continue;
        recs.push({ id: `dshield:${ip}:${o.lastseen || o.date || ''}`, source: 'dshield', origin: url || 'dshield', fetched_at: retrieved_at || nowIso(), raw: { ...o, source: ip } });
      }
    }
    return recs;
  },
  extract(rec) {
    const o = rec.raw;
    const ipn = ipNode(String(o.source), { reports: o.reports ?? null, targets: o.targets ?? null });
    const asn = o.asn || o.as ? asnNode(o.asn ?? o.as, o.asname || o.as_name, o.country) : null;
    const edges = [edge('same-asn', ipn, asn)];
    const events = ipn ? [{ key: `dshield|${ipn.id}|${o.lastseen || ''}`, kind: 'scan', family: null, indicator: String(o.source), node: ipn.id, ip: String(o.source), host: null, tags: ['dshield-top-source'], cve: [], victims: [], reports: o.reports ?? null, targets: o.targets ?? null, ts: o.lastseen || null }] : [];
    return result({ nodes: [ipn, asn], edges, events });
  },
};
