// abuse.ch feeds: Feodo Tracker, ThreatFox, URLhaus.
// NOTE: sandbox egress to abuse.ch is policy-blocked, so these adapters are tested against fixtures written
// from the documented formats (data/fixtures/*, labelled synthetic), not against live responses.
// ThreatFox and URLhaus APIs need a free abuse.ch Auth-Key (ABUSECH_AUTH_KEY); Feodo's blocklist JSON does not.
import { ipNode, hostNode, famNode, campaignNode, asnNode, edge, result, httpGet } from './base.js';
import { famKey, findCVEs, hostFromUrl, sha1short, nowIso } from '../util.js';
import net from 'node:net';

const asTags = (t) => (Array.isArray(t) ? t : typeof t === 'string' ? t.split(',') : []).map((x) => String(x).trim()).filter(Boolean);
const splitHostPort = (v) => { const m = /^(.*?)(?::(\d{1,5}))?$/.exec(String(v)); return m ? { host: m[1], port: m[2] || null } : { host: String(v), port: null }; };

// Tags like "cve-2021-44228" are CVEs; tags like "campaign:foo" (convention used by some reporters) are campaigns.
function campaignsFromTags(tags) {
  return tags.filter((t) => /^campaign[:=]/i.test(t)).map((t) => t.replace(/^campaign[:=]/i, '').trim()).filter(Boolean);
}

export const feodo = {
  name: 'feodo', label: 'abuse.ch Feodo Tracker', keyed: null, intervalMs: 1800_000,
  async fetchAll() { const url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'; return [{ text: await httpGet(url), url }]; },
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      let arr; try { arr = JSON.parse(text); } catch { continue; }
      if (!Array.isArray(arr)) continue;
      for (const o of arr) {
        if (!o || !o.ip_address) continue;
        recs.push({ id: `feodo:${o.ip_address}:${o.port ?? ''}`, source: 'feodo', origin: url || 'feodo', fetched_at: retrieved_at || nowIso(), raw: o });
      }
    }
    return recs;
  },
  extract(rec) {
    const o = rec.raw;
    const fam = famNode(o.malware);
    const ipn = ipNode(String(o.ip_address), { port: o.port ?? null, status: o.status || null });
    const hn = o.hostname ? hostNode(o.hostname, { role: 'c2' }) : null;
    const asn = o.as_number ? asnNode(o.as_number, o.as_name, o.country) : null;
    const edges = [edge('hosts', fam, ipn), edge('same-asn', ipn, asn)];
    if (hn) edges.push(edge('resolves-to', hn, ipn));
    const events = ipn && fam ? [{ key: `feodo|${famKey(o.malware)}|${ipn.id}`, kind: 'botnet', family: famKey(o.malware), indicator: `${o.ip_address}${o.port ? ':' + o.port : ''}`, node: ipn.id, ip: String(o.ip_address), host: hn?.label || null, tags: [o.status].filter(Boolean), cve: [], victims: [], country: o.country || null, ts: o.first_seen || o.last_online || null }] : [];
    return result({ nodes: [fam, ipn, hn, asn], edges, events });
  },
};

export const threatfox = {
  name: 'threatfox', label: 'abuse.ch ThreatFox', keyed: 'ABUSECH_AUTH_KEY', intervalMs: 900_000,
  async fetchAll({ env = process.env } = {}) {
    const url = 'https://threatfox-api.abuse.ch/api/v1/';
    const res = await fetch(url, { method: 'POST', headers: { 'Auth-Key': env.ABUSECH_AUTH_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ query: 'get_iocs', days: 1 }), signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return [{ text: await res.text(), url }];
  },
  // Supports the API form {query_status, data:[...]} and the export form {"<id>":[{...}]}.
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      let j; try { j = JSON.parse(text); } catch { continue; }
      const list = [];
      if (Array.isArray(j?.data)) for (const o of j.data) list.push({ id: o.id, o: { ioc_value: o.ioc, ioc_type: o.ioc_type, threat_type: o.threat_type, malware: o.malware, malware_printable: o.malware_printable, malware_alias: o.malware_alias, confidence_level: o.confidence_level, first_seen: o.first_seen, tags: o.tags, reference: o.reference } });
      else if (j && typeof j === 'object') for (const [id, arr] of Object.entries(j)) if (Array.isArray(arr)) for (const o of arr) list.push({ id, o: { ioc_value: o.ioc_value, ioc_type: o.ioc_type, threat_type: o.threat_type, malware: o.fk_malware, malware_printable: o.malware_printable, malware_alias: o.malware_alias, confidence_level: o.confidence_level, first_seen: o.first_seen_utc, tags: o.tags, reference: o.reference } });
      for (const { id, o } of list) {
        if (!o.ioc_value || id === undefined) continue;
        recs.push({ id: `threatfox:${id}`, source: 'threatfox', origin: url || 'threatfox', fetched_at: retrieved_at || nowIso(), raw: o });
      }
    }
    return recs;
  },
  extract(rec) {
    const o = rec.raw;
    const tags = asTags(o.tags);
    const fam = famNode(o.malware_printable || o.malware);
    const camps = campaignsFromTags(tags).map(campaignNode);
    const nodes = [fam, ...camps];
    const edges = [];
    let target = null, ipn = null, hn = null;
    if (o.ioc_type === 'ip:port' || net.isIP(splitHostPort(o.ioc_value).host)) { const { host, port } = splitHostPort(o.ioc_value); ipn = ipNode(host, { port }); target = ipn; }
    else if (o.ioc_type === 'domain') { hn = hostNode(o.ioc_value, { role: 'c2' }); target = hn; }
    else if (o.ioc_type === 'url') { const h = hostFromUrl(o.ioc_value); if (h) { if (net.isIP(h)) { ipn = ipNode(h); target = ipn; } else { hn = hostNode(h, { role: 'c2' }); target = hn; } } }
    nodes.push(ipn, hn);
    if (target) { edges.push(edge('hosts', fam, target)); for (const c of camps) edges.push(edge('hosts', c, target)); }
    const isC2 = /botnet_cc/i.test(o.threat_type || '');
    const events = target && fam ? [{ key: `threatfox|${famKey(o.malware_printable || o.malware)}|${target.id}`, kind: isC2 ? 'c2' : 'malware-url', family: famKey(o.malware_printable || o.malware), indicator: String(o.ioc_value), node: target.id, ip: ipn?.label || null, host: hn?.label || null, tags, cve: findCVEs(tags), victims: [], confidence: o.confidence_level ?? null, ts: o.first_seen || null }] : [];
    return result({ nodes, edges, events });
  },
};

export const urlhaus = {
  name: 'urlhaus', label: 'abuse.ch URLhaus', keyed: 'ABUSECH_AUTH_KEY', intervalMs: 900_000,
  async fetchAll({ env = process.env } = {}) {
    const url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/';
    const res = await fetch(url, { headers: { 'Auth-Key': env.ABUSECH_AUTH_KEY }, signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return [{ text: await res.text(), url }];
  },
  // API form {query_status, urls:[...]} and the json_recent export {"<id>":[{...}]}.
  parse(inputs) {
    const recs = [];
    for (const { text, url, retrieved_at } of inputs) {
      let j; try { j = JSON.parse(text); } catch { continue; }
      const list = [];
      if (Array.isArray(j?.urls)) for (const o of j.urls) list.push({ id: o.id, o: { url: o.url, url_status: o.url_status, threat: o.threat, tags: o.tags, date: o.date_added } });
      else if (j && typeof j === 'object') for (const [id, arr] of Object.entries(j)) if (Array.isArray(arr)) for (const o of arr) list.push({ id, o: { url: o.url, url_status: o.url_status, threat: o.threat, tags: o.tags, date: o.dateadded } });
      for (const { id, o } of list) {
        if (!o.url) continue;
        recs.push({ id: `urlhaus:${id ?? sha1short(o.url)}`, source: 'urlhaus', origin: url || 'urlhaus', fetched_at: retrieved_at || nowIso(), raw: o });
      }
    }
    return recs;
  },
  extract(rec) {
    const o = rec.raw;
    const tags = asTags(o.tags);
    const h = hostFromUrl(o.url);
    let ipn = null, hn = null;
    if (h) { if (net.isIP(h)) ipn = ipNode(h); else hn = hostNode(h, { role: 'payload' }); }
    const target = ipn || hn;
    // Family: first tag that is a known-looking malware family (not a file type / CVE / campaign marker).
    const famTag = tags.find((t) => !/^(exe|dll|elf|zip|doc|xls|js|ps1|sh|bat|apk|campaign[:=].*|cve-.*|32-bit|64-bit|opendir|geo|.*\.\w{2,3})$/i.test(t));
    const fam = famNode(famTag);
    const camps = campaignsFromTags(tags).map(campaignNode);
    const edges = [];
    if (target) { edges.push(edge('hosts', fam, target)); for (const c of camps) edges.push(edge('hosts', c, target)); }
    const events = target ? [{ key: `urlhaus|${famKey(famTag) || 'unknown'}|${target.id}|${sha1short(o.url)}`, kind: 'malware-url', family: famKey(famTag), indicator: o.url, node: target.id, ip: ipn?.label || null, host: hn?.label || null, tags, cve: findCVEs(tags, o.url), victims: [], status: o.url_status || null, ts: o.date || null }] : [];
    return result({ nodes: [fam, ...camps, ipn, hn], edges, events });
  },
};
