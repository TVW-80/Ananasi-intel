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
});

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
