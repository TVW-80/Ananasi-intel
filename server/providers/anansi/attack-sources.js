// Ananzi attack-map sources: endpoints, parsers and normalizers.
//
// Everything here is pure (no network, no clock) so it is unit-tested with
// fixtures; attack-map.js does the fetching, caching and merging.
//
//   Cloudflare Radar   DDoS / web-attack origin→target country pairs, hit industries
//   blocklist.de       IPs that attacked its members' servers in 48h, per service
//   abuse.ch           ThreatFox IOCs (malware family) + URLhaus malware URLs
//   AlienVault OTX     community threat "pulses" (campaign reports)
//   GreyNoise          mass scanner vs. targeted, per IP
//   Shadowserver       honeypot-observed exploited vulnerabilities
//   Spamhaus DROP      criminal / hijacked netblocks
//   Tor Project        current Tor exit relays
//   CISA KEV           vulnerabilities exploited in the wild
import { createHmac } from 'node:crypto';

export const URLS = Object.freeze({
  radar: 'https://api.cloudflare.com/client/v4/radar/attacks',
  blocklist: (service) => `https://lists.blocklist.de/lists/${service}.txt`,
  threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/',
  otx: 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&page=1',
  greynoise: (ip) => `https://api.greynoise.io/v3/community/${ip}`,
  shadowserver: 'https://transform.shadowserver.org/api2/honeypot/exploited-vulnerabilities',
  dropJson: 'https://www.spamhaus.org/drop/drop_v4.json',
  dropTxt: 'https://www.spamhaus.org/drop/drop.txt',
  tor: 'https://check.torproject.org/torbulkexitlist',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  bgpHijacks: 'https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events?dateRange=7d&per_page=15&sortBy=TIME&sortOrder=DESC&minConfidence=7&format=json',
  bgpLeaks: 'https://api.cloudflare.com/client/v4/radar/bgp/leaks/events?dateRange=7d&per_page=10&sortBy=TIME&sortOrder=DESC&format=json',
  malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
  sslbl: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
  hibp: 'https://haveibeenpwned.com/api/v3/breaches',
  epss: (cves) => `https://api.first.org/data/v1/epss?cve=${cves.map(encodeURIComponent).join(',')}`,
  poc: (year) => `https://api.github.com/search/repositories?q=${encodeURIComponent(`CVE-${year} in:name`)}&sort=updated&order=desc&per_page=30`,
  icsAdvisories: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
  openphish: 'https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt',
  c2intel: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv',
  malpedia: 'https://malpedia.caad.fkie.fraunhofer.de/api/get/families',
  // Shodan InternetDB: keyless, free, no query credits — per-IP open ports,
  // detected software (CPEs), hostnames, tags and known vulnerabilities (CVEs).
  internetdb: (ip) => `https://internetdb.shodan.io/${ip}`,
  // Shodan free count API (facets): how many hosts expose a service, never
  // which hosts. No query credits.
  shodanCount: (key, query, facets) =>
    `https://api.shodan.io/shodan/host/count?${new URLSearchParams({ key, query, facets })}`,
});

/** The exposure scoreboard's services — each a free Shodan count query. */
export const EXPOSURE_QUERIES = Object.freeze([
  { id: 'rdp', label: 'Remote Desktop (RDP)', query: 'port:3389', plain: 'Windows Remote Desktop open to the internet — a top way ransomware crews break in.', technical: 'Shodan host/count port:3389.' },
  { id: 'telnet', label: 'Telnet', query: 'port:23', plain: 'Old, unencrypted remote logins — the doorway IoT botnets like Mirai walk through.', technical: 'Shodan host/count port:23.' },
  { id: 'smb', label: 'Windows file sharing (SMB)', query: 'port:445', plain: 'Windows file sharing exposed — how WannaCry spread.', technical: 'Shodan host/count port:445.' },
  { id: 'databases', label: 'Open databases', query: 'product:MongoDB,Elastic,Redis', plain: 'Databases (MongoDB, Elasticsearch, Redis) reachable from the internet, often with no password.', technical: 'Shodan host/count product:MongoDB,Elastic,Redis.' },
  { id: 'ics', label: 'Industrial control systems', query: 'tag:ics', plain: 'Factory, utility and port control systems answering openly online.', technical: 'Shodan host/count tag:ics.' },
  { id: 'cameras', label: 'Cameras', query: 'screenshot.label:webcam', plain: 'Internet-exposed cameras, often on default passwords.', technical: 'Shodan host/count screenshot.label:webcam.' },
]);

const str = (v) => (v === null || v === undefined ? '' : String(v).trim());
const num = (v) => {
  const n = Number(str(v).replace(/,/g, ''));
  return Number.isFinite(n) ? n : 0;
};

// ── IPv4 helpers ─────────────────────────────────────────────────────────────
export function ipToInt(ip) {
  const p = str(ip).split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
}

/** Plain IP-per-line lists (blocklist.de, Tor bulk exit list). */
export function parseIpList(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const ip = line.trim().split(/[\s;#]/)[0];
    if (ipToInt(ip) !== null) out.push(ip);
  }
  return out;
}

/** Spamhaus DROP: NDJSON (drop_v4.json) or the legacy "cidr ; SBL" text. Sorted ranges. */
export function parseDrop(text) {
  const ranges = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(';')) continue;
    let cidr = '';
    let sbl = '';
    if (line.startsWith('{')) {
      try {
        const o = JSON.parse(line);
        cidr = str(o.cidr);
        sbl = str(o.sblid);
      } catch {
        continue;
      }
    } else {
      [cidr, sbl] = line.split(';').map((s) => s.trim());
    }
    const [base, bits] = cidr.split('/');
    const start = ipToInt(base);
    const b = Number(bits);
    if (start === null || !Number.isInteger(b) || b < 0 || b > 32) continue;
    const size = 2 ** (32 - b);
    const s = Math.floor(start / size) * size;
    ranges.push({ start: s, end: s + size - 1, cidr, sbl });
  }
  return ranges.sort((a, b) => a.start - b.start);
}

/** Binary search a sorted range list. */
export function findRange(ip, ranges) {
  const n = ipToInt(ip);
  if (n === null) return null;
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid];
    if (n < r.start) hi = mid - 1;
    else if (n > r.end) lo = mid + 1;
    else return r;
  }
  return null;
}

// ── Cloudflare Radar ─────────────────────────────────────────────────────────
export function radarUrl(path, params = {}) {
  const q = new URLSearchParams({ dateRange: '1d', format: 'json', ...params });
  return `${URLS.radar}/${path}?${q}`;
}

/** top/attacks → origin→target pairs. */
export function normalizeRadarPairs(payload, layer) {
  const rows = payload?.result?.top_0 || [];
  return rows
    .map((r) => ({
      layer,
      from: { code: str(r.originCountryAlpha2).toUpperCase(), name: str(r.originCountryName) },
      to: { code: str(r.targetCountryAlpha2).toUpperCase(), name: str(r.targetCountryName) },
      value: num(r.value),
    }))
    .filter((r) => r.from.code && r.to.code && r.value > 0);
}

/** top/industry, top/vertical, top/locations/* → [{name, code?, value}] */
export function normalizeRadarTop(payload) {
  const rows = payload?.result?.top_0 || [];
  return rows
    .map((r) => ({
      name: str(r.name || r.targetCountryName || r.originCountryName || r.clientCountryName),
      code: str(r.targetCountryAlpha2 || r.originCountryAlpha2 || r.clientCountryAlpha2).toUpperCase(),
      value: num(r.value),
    }))
    .filter((r) => r.name && r.value > 0);
}

// ── abuse.ch ─────────────────────────────────────────────────────────────────
/** ThreatFox get_iocs → IOCs; ip:port IOCs carry `ip` for geolocation. */
export function normalizeThreatFox(payload) {
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  return rows
    .filter((r) => r && r.ioc)
    .map((r) => {
      const ioc = str(r.ioc);
      const m = ioc.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$/);
      return {
        ioc,
        ip: m && ipToInt(m[1]) !== null ? m[1] : '',
        port: m?.[2] ? Number(m[2]) : null,
        iocType: str(r.ioc_type),
        threatType: str(r.threat_type),
        malware: str(r.malware_printable || r.malware),
        confidence: num(r.confidence_level),
        firstSeen: str(r.first_seen),
        tags: Array.isArray(r.tags) ? r.tags.map(str).filter(Boolean) : [],
      };
    });
}

/** URLhaus recent URLs → per-threat counts and the freshest examples. */
export function normalizeUrlhaus(payload) {
  const rows = Array.isArray(payload?.urls) ? payload.urls : [];
  const urls = rows
    .filter((r) => r && r.url)
    .map((r) => ({
      url: str(r.url),
      host: str(r.host),
      status: str(r.url_status),
      threat: str(r.threat),
      tags: Array.isArray(r.tags) ? r.tags.map(str).filter(Boolean) : [],
      dateAdded: str(r.date_added),
      reference: str(r.urlhaus_reference),
    }));
  const tagCounts = new Map();
  for (const u of urls) for (const t of u.tags) tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
  return {
    total: urls.length,
    online: urls.filter((u) => u.status === 'online').length,
    topTags: [...tagCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([tag, count]) => ({ tag, count })),
    latest: urls.slice(0, 10),
  };
}

// ── AlienVault OTX ───────────────────────────────────────────────────────────
export function normalizeOtx(payload) {
  const rows = Array.isArray(payload?.results) ? payload.results : [];
  return rows
    .filter((p) => p && p.name)
    .map((p) => ({
      id: str(p.id),
      name: str(p.name),
      description: str(p.description),
      author_name: str(p.author_name),
      adversary: str(p.adversary),
      malware_families: Array.isArray(p.malware_families) ? p.malware_families : [],
      industries: Array.isArray(p.industries) ? p.industries.map(str) : [],
      targeted_countries: Array.isArray(p.targeted_countries) ? p.targeted_countries.map(str) : [],
      attack_ids: Array.isArray(p.attack_ids) ? p.attack_ids : [],
      tags: Array.isArray(p.tags) ? p.tags.map(str) : [],
      time: str(p.modified || p.created),
    }));
}

// ── GreyNoise Community ──────────────────────────────────────────────────────
/** 200 and 404 both answer the question ("not observed" is an answer). */
export function normalizeGreyNoise(payload, httpStatus = 200) {
  if (!payload || (httpStatus !== 200 && httpStatus !== 404)) return null;
  return {
    noise: Boolean(payload.noise),
    riot: Boolean(payload.riot),
    classification: str(payload.classification) || (httpStatus === 404 ? 'not-observed' : 'unknown'),
    name: str(payload.name),
    link: /^https:\/\//.test(str(payload.link)) ? str(payload.link) : '',
    lastSeen: str(payload.last_seen),
  };
}

// ── Shadowserver ─────────────────────────────────────────────────────────────
/** Body + HMAC2 header, exactly as Shadowserver's own call-api.py signs requests. */
export function shadowserverRequest(params, key, secret) {
  const body = JSON.stringify({ ...params, apikey: key });
  const hmac = createHmac('sha256', Buffer.from(secret, 'utf8')).update(Buffer.from(body, 'utf8')).digest('hex');
  return { body, headers: { HMAC2: hmac, 'Content-Type': 'application/json' } };
}

export function parseJsonLines(text) {
  const t = String(text || '').trim();
  if (!t) return [];
  if (t.startsWith('[')) {
    try {
      return JSON.parse(t);
    } catch {
      return [];
    }
  }
  return t
    .split(/\r?\n/)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter((x) => x && typeof x === 'object');
}

// ── CISA KEV ─────────────────────────────────────────────────────────────────
export function normalizeKev(payload, limit = 8) {
  const rows = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];
  return [...rows]
    .filter((v) => v && v.cveID)
    .sort((a, b) => str(b.dateAdded).localeCompare(str(a.dateAdded)))
    .slice(0, limit);
}

// ── Cloudflare Radar BGP ─────────────────────────────────────────────────────
function asnOrgs(payload) {
  const m = new Map();
  for (const a of payload?.result?.asn_info || []) m.set(Number(a.asn), { org: str(a.org_name), country: str(a.country_code).toUpperCase() });
  return m;
}
export function normalizeBgpHijacks(payload) {
  const orgs = asnOrgs(payload);
  return (payload?.result?.events || [])
    .map((e) => {
      const victims = (e.victim_countries || []).map((c) => str(c).toUpperCase()).filter(Boolean);
      const victimAsn = Number((e.victim_asns || [])[0]);
      return {
        id: str(e.id),
        hijackerAsn: Number(e.hijacker_asn) || null,
        hijackerOrg: orgs.get(Number(e.hijacker_asn))?.org || '',
        hijackerCountry: str(e.hijacker_country).toUpperCase() || orgs.get(Number(e.hijacker_asn))?.country || '',
        victimAsn: victimAsn || null,
        victimOrg: orgs.get(victimAsn)?.org || '',
        victimCountries: victims.length ? victims : [orgs.get(victimAsn)?.country].filter(Boolean),
        confidence: num(e.confidence_score),
        prefixes: (e.prefixes || []).map(str).slice(0, 5),
        start: str(e.min_hijack_ts),
        end: str(e.max_hijack_ts),
        ongoing: num(e.on_going_count) > 0,
      };
    })
    .filter((e) => e.hijackerCountry && e.victimCountries.length);
}
export function normalizeBgpLeaks(payload) {
  const orgs = asnOrgs(payload);
  return (payload?.result?.events || [])
    .map((e) => ({
      id: str(e.id),
      leakAsn: Number(e.leak_asn) || null,
      leakOrg: orgs.get(Number(e.leak_asn))?.org || '',
      countries: (e.countries || []).map((c) => str(c).toUpperCase()).filter(Boolean),
      prefixes: num(e.prefix_count),
      origins: num(e.origin_count),
      detected: str(e.detected_ts || e.min_ts),
      finished: Boolean(e.finished),
    }))
    .filter((e) => e.countries.length);
}

// ── abuse.ch MalwareBazaar + SSLBL ───────────────────────────────────────────
export function normalizeMalwareBazaar(payload) {
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  const count = (key) => {
    const m = new Map();
    for (const r of rows) {
      const v = str(r[key]);
      if (v) m.set(v, (m.get(v) || 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, n]) => ({ name, count: n }));
  };
  // Double extensions and document-ish names are the classic disguises.
  const disguises = rows
    .map((r) => str(r.file_name))
    .filter((n) => /\.(pdf|docx?|xlsx?|jpg|png|txt|zip|rar|iso|img)\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$/i.test(n) || /(invoice|order|payment|receipt|shipping|quotation|statement|scan)/i.test(n))
    .slice(0, 5);
  return { total: rows.length, topSignatures: count('signature'), topTypes: count('file_type'), disguises };
}
/** sslipblacklist.csv: "# comments" then "Firstseen,DstIP,DstPort". */
export function parseSslbl(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const ip = line.split(',')[1]?.trim();
    if (ip && ipToInt(ip) !== null) out.push(ip);
  }
  return [...new Set(out)];
}

// ── Have I Been Pwned (breach catalogue, no key) ─────────────────────────────
export function normalizeHibp(payload, limit = 6) {
  const rows = Array.isArray(payload) ? payload : [];
  return rows
    .filter((b) => b && b.Name && !b.IsSpamList && !b.IsFabricated)
    .sort((a, b) => str(b.AddedDate).localeCompare(str(a.AddedDate)))
    .slice(0, limit)
    .map((b) => ({
      name: str(b.Name),
      title: str(b.Title),
      domain: str(b.Domain),
      breachDate: str(b.BreachDate),
      addedDate: str(b.AddedDate),
      pwnCount: num(b.PwnCount),
      dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses.map(str) : [],
      isVerified: Boolean(b.IsVerified),
    }));
}

// ── EPSS ─────────────────────────────────────────────────────────────────────
export function normalizeEpss(payload) {
  const m = new Map();
  for (const r of payload?.data || []) {
    const epss = Number(r.epss);
    const percentile = Number(r.percentile);
    if (r.cve && Number.isFinite(epss)) m.set(str(r.cve).toUpperCase(), { epss, percentile: Number.isFinite(percentile) ? percentile : 0 });
  }
  return m;
}

// ── PoC-in-GitHub style: newest repos named after a CVE ──────────────────────
export function normalizePocSearch(payload, limit = 8) {
  const seen = new Set();
  const out = [];
  for (const r of payload?.items || []) {
    const cve = (str(r.name).match(/CVE-\d{4}-\d{4,7}/i) || str(r.description).match(/CVE-\d{4}-\d{4,7}/i) || [])[0];
    if (!cve) continue;
    const id = cve.toUpperCase();
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ cve: id, repo: str(r.full_name), created: str(r.created_at), stars: num(r.stargazers_count) });
    if (out.length >= limit) break;
  }
  return out;
}

// ── OpenPhish community feed ─────────────────────────────────────────────────
const BRANDS = [
  ['microsoft', /microsoft|office ?365|outlook|onedrive|sharepoint|hotmail|live\.com/i],
  ['PayPal', /paypal/i],
  ['Apple', /apple|icloud/i],
  ['Amazon', /amazon/i],
  ['Netflix', /netflix/i],
  ['Facebook / Meta', /facebook|meta|instagram/i],
  ['Google', /google|gmail/i],
  ['a bank', /bank|chase|wellsfargo|wells-fargo|citi|hsbc|santander|barclays|boa|bankofamerica/i],
  ['a delivery company', /usps|dhl|fedex|ups|royalmail|parcel|delivery|tracking/i],
  ['a crypto wallet', /metamask|coinbase|binance|wallet|ledger|trust-?wallet/i],
  ['a telecom', /att|verizon|t-?mobile|orange|vodafone/i],
];
export function brandFor(url) {
  for (const [name, re] of BRANDS) if (re.test(url)) return name === 'microsoft' ? 'Microsoft' : name;
  return '';
}
export function parseOpenPhish(text) {
  const urls = String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => /^https?:\/\//i.test(l));
  const byHost = new Map();
  for (const u of urls) {
    let host = '';
    try {
      host = new URL(u).hostname.toLowerCase();
    } catch {
      continue;
    }
    const h = byHost.get(host) || { host, urls: 0, brand: '' };
    h.urls += 1;
    h.brand ||= brandFor(u);
    byHost.set(host, h);
  }
  return { total: urls.length, hosts: [...byHost.values()] };
}
/** Show phishing hosts without making them clickable: example[.]com */
export const defang = (host) => String(host || '').replace(/\./g, '[.]');

// ── C2IntelFeeds ─────────────────────────────────────────────────────────────
export function parseC2Intel(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const [ip, ioc = ''] = line.split(',');
    if (ipToInt(ip?.trim()) === null) continue;
    const tool = (ioc.match(/Possible\s+(.+?)\s+C2/i)?.[1] || ioc || 'C2 framework').trim();
    out.push({ ip: ip.trim(), malware: tool.replace(/^cobaltstrike$/i, 'Cobalt Strike'), threatType: 'botnet_cc' });
  }
  return out;
}

// ── Malpedia family descriptions (technical voice for unknown families) ─────
const normName = (n) => str(n).toLowerCase().replace(/[^a-z0-9]/g, '');
export function normalizeMalpedia(payload) {
  const m = new Map();
  for (const [id, f] of Object.entries(payload || {})) {
    const desc = str(f?.description).replace(/\s+/g, ' ');
    if (!desc) continue;
    const short = desc.split(/(?<=\.)\s/).slice(0, 2).join(' ').slice(0, 320);
    for (const n of [f.common_name, ...(f.alt_names || []), id.split('.').pop()]) {
      const k = normName(n);
      if (k && !m.has(k)) m.set(k, { id, description: short });
    }
  }
  return m;
}
export function malpediaLookup(map, name) {
  return map?.get(normName(name)) || null;
}

// ── Shodan InternetDB (keyless per-IP enrichment) ────────────────────────────
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
export function normalizeInternetDb(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const arr = (v) => (Array.isArray(v) ? v : []);
  const ports = arr(payload.ports).map((p) => Number(p)).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535).slice(0, 24);
  const vulns = arr(payload.vulns).map((v) => String(v).toUpperCase()).filter((v) => CVE_RE.test(v)).slice(0, 24);
  const cpes = arr(payload.cpes).map((c) => String(c).trim()).filter(Boolean).slice(0, 12);
  const tags = arr(payload.tags).map((t) => String(t).trim()).filter(Boolean).slice(0, 12);
  const hostnames = arr(payload.hostnames).map((h) => String(h).trim()).filter(Boolean).slice(0, 6);
  return { ports, vulns, cpes, tags, hostnames };
}

/** Human product names out of noisy CPE strings: cpe:2.3:a:apache:http_server:... → "apache http server". */
export function prettyCpe(cpe) {
  const parts = String(cpe).split(':');
  const vendor = parts[3];
  const product = parts[4];
  if (!product || product === '*') return '';
  return [vendor, product].filter((x) => x && x !== '*').join(' ').replace(/_/g, ' ');
}

// ── Shodan free count facets (exposure scoreboard) ───────────────────────────
export function normalizeShodanCount(payload) {
  const total = Number(payload?.total);
  const facets = payload?.facets?.country;
  const top = Array.isArray(facets)
    ? facets
        .map((f) => ({ country: String(f?.value || '').toUpperCase(), count: Number(f?.count) || 0 }))
        .filter((f) => /^[A-Z]{2}$/.test(f.country) && f.count > 0)
        .slice(0, 8)
    : [];
  return { total: Number.isFinite(total) ? total : top.reduce((s, f) => s + f.count, 0), top };
}
