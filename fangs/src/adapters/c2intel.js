// C2IntelFeeds (drb-ra) — CSV feeds of C2 IPs and domains. Real, record-level, no key.
// Reachable through raw.githubusercontent.com. Formats (verified against the bundled snapshot):
//   IPC2s*.csv                    #ip,ioc
//   domainC2s*.csv                #domain,ioc
//   domainC2swithURL.csv          #domain,ioc,uri_path
//   domainC2swithURLwithIP*.csv   #domain,ioc,uri_path,ip
import { ipNode, hostNode, famNode, edge, result, httpGet } from './base.js';
import { famKey, nowIso } from '../util.js';

const BASE = 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds';
export const C2_FILES = ['IPC2s-30day.csv', 'domainC2swithURLwithIP-30day.csv'];

function familyFromIoc(ioc) {
  const m = /possible\s+(.+?)\s+c2/i.exec(ioc || '');
  return m ? famKey(m[1]) : null;
}

export const c2intel = {
  name: 'c2intel', label: 'C2IntelFeeds', keyed: null, intervalMs: 3600_000,
  async fetchAll({ files = C2_FILES } = {}) {
    const out = [];
    for (const f of files) out.push({ file: f, text: await httpGet(`${BASE}/${f}`), url: `${BASE}/${f}` });
    return out;
  },
  // input: [{file, text, url?, retrieved_at?}]
  parse(inputs) {
    const recs = [];
    for (const { file, text, url, retrieved_at } of inputs) {
      const cols = (text.split('\n', 1)[0] || '').replace(/^#/, '').split(',').map((s) => s.trim());
      const lines = text.split('\n');
      lines.forEach((line, i) => {
        if (!line || line.startsWith('#')) return;
        const p = line.replace(/\r$/, '').split(',');
        if (p.length < 2) return;
        // columns beyond the header: join the tail (uri paths may contain commas)
        const raw = {};
        if (cols[0] === 'ip') { raw.ip = p[0].trim(); raw.ioc = p.slice(1).join(',').trim(); }
        else if (cols[0] === 'domain') {
          raw.domain = p[0].trim();
          if (cols.includes('ip')) { raw.ip = p[p.length - 1].trim(); raw.uri_path = p.slice(2, -1).join(',').trim(); raw.ioc = p[1].trim(); }
          else { raw.ioc = p[1].trim(); if (cols.includes('uri_path')) raw.uri_path = p.slice(2).join(',').trim(); }
        } else return;
        recs.push({ id: `c2intel:${file}:${i + 1}`, source: 'c2intel', origin: `${url || file}#L${i + 1}`, fetched_at: retrieved_at || nowIso(), raw });
      });
    }
    return recs;
  },
  extract(rec) {
    const { ip, domain, ioc, uri_path } = rec.raw;
    const fam = famNode(familyFromIoc(ioc));
    const fronting = /fronting domain/i.test(ioc || '');
    const ipn = ip ? ipNode(ip) : null;
    const hn = domain ? hostNode(domain, { role: fronting ? 'fronting' : /fronted/i.test(ioc) ? 'fronted' : 'c2', uri_path: uri_path || undefined }) : null;
    const nodes = [fam, ipn, hn];
    const edges = [];
    if (hn) {
      edges.push(edge('hosts', fam, hn));
      if (ipn) edges.push(edge('resolves-to', hn, ipn));
    } else if (ipn) edges.push(edge('hosts', fam, ipn));
    const target = fronting ? ipn : (hn || ipn); // a fronting domain is a legitimate site being abused; the C2 is the IP
    const events = target && fam ? [{ key: `c2intel|${famKey(familyFromIoc(ioc))}|${target.id}`, kind: 'c2', family: famKey(familyFromIoc(ioc)), indicator: target.label, node: target.id, ip: ip || null, host: hn?.label || null, tags: [ioc], cve: [], victims: [], fronting }] : [];
    return result({ nodes, edges, events });
  },
};
