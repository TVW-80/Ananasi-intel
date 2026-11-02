// Ananzi: Attack Map — who is attacking, how, and with what.
//
//   GET /api/attackmap
//
// Arcs into Hampton Roads (the viewer's vantage point, not a claim these
// sources hit Hampton Roads specifically):
//   SANS ISC / DShield     top attacking IPs from its worldwide honeypot sensors
//   AbuseIPDB              reported attackers per country (shared threat-intel cache)
//   blocklist.de           IPs that attacked members' servers in 48h, per service —
//                          arcs are coloured by the dominant attack type
// Country-to-country arcs:
//   Cloudflare Radar       DDoS / web-attack origin→target pairs (L7 + L3), hit industries
// Markers and tags:
//   abuse.ch ThreatFox     malware command servers, labelled by family
//   Spamhaus DROP, Tor     "criminal netblock" / "via Tor" flags on source IPs
//   GreyNoise Community    mass scanner vs. possibly targeted, per top IP
// Alerts (ticker + BRIEF), each in plain English AND technical terms:
//   FortiGuard RSS, AlienVault OTX pulses, CISA KEV, Shadowserver honeypot
//   exploited vulnerabilities, URLhaus and ThreatFox summaries.
//
// Every source is cached on its own schedule and fails on its own: a missing
// key or an outage removes one ingredient, never the map. Keys come from
// POWER UP (.env) and never leave the server.
import { countryCentroid } from './threat-feeds.js';
import { sharedThreatIntel } from './threat-intel.js';
import {
  URLS,
  findRange,
  normalizeGreyNoise,
  normalizeKev,
  normalizeOtx,
  normalizeRadarPairs,
  normalizeRadarTop,
  normalizeThreatFox,
  normalizeUrlhaus,
  parseDrop,
  parseIpList,
  parseJsonLines,
  radarUrl,
  shadowserverRequest,
  normalizeBgpHijacks,
  normalizeBgpLeaks,
  normalizeMalwareBazaar,
  parseSslbl,
  normalizeHibp,
  normalizeEpss,
  normalizePocSearch,
  parseOpenPhish,
  parseC2Intel,
  normalizeMalpedia,
  malpediaLookup,
  defang,
} from './attack-sources.js';
import { resolve4 as dnsResolve4 } from 'node:dns/promises';
import {
  DDOS,
  FLAGS,
  FORTIGUARD_KINDS,
  SERVICES as SERVICE_INFO,
  SERVICE_ORDER,
  exploitedExplained,
  familyExplained,
  greyNoiseExplained,
  kevExplained,
  portExplained,
  pulseExplained,
  techniqueExplained,
  epssExplained,
  BGP,
  PHISHING,
  C2_TOOLS,
  SSLBL,
  breachExplained,
  pocExplained,
  icsAdvisoryExplained,
  malwareBazaarExplained,
} from './attack-glossary.js';

const MIN = 60_000;
const TTL = 10 * MIN; // whole-picture snapshot; each source has its own TTL below
const IP_TTL = 24 * 60 * MIN;
const TIMEOUT_MS = 20_000;
const TOP_IPS = 40; // DShield asks for restraint; 40 lookups a day per new IP at most
const LOOKUP_GAP_MS = 250;
const USER_AGENT = 'Ananzi/1.0 (personal threat-intel research dashboard)';
const MAX_NEW_LOOKUPS = 100; // country lookups per refresh across all sources (cached a day per IP)
const PHISH_SAMPLE = 20;
const C2INTEL_SAMPLE = 15;
const SSLBL_SAMPLE = 10;
const EPSS_TTL = 24 * 60 * MIN;
const BLOCKLIST_SAMPLE = 8; // IPs per blocklist.de service placed on the map
const GREYNOISE_TTL = 7 * 24 * 60 * MIN;
const GREYNOISE_PER_REFRESH = 5;

/** Per-source refresh intervals. */
const SOURCE_TTL = Object.freeze({
  radar: 30 * MIN,
  blocklist: 60 * MIN,
  threatfox: 30 * MIN,
  urlhaus: 30 * MIN,
  otx: 30 * MIN,
  shadowserver: 6 * 60 * MIN,
  drop: 24 * 60 * MIN,
  tor: 6 * 60 * MIN,
  kev: 6 * 60 * MIN,
  fortiguard: 60 * MIN,
  bgp: 30 * MIN,
  malwarebazaar: 60 * MIN,
  sslbl: 6 * 60 * MIN,
  hibp: 6 * 60 * MIN,
  poc: 60 * MIN,
  ics: 6 * 60 * MIN,
  openphish: 6 * 60 * MIN, // the community feed updates every 12 hours
  c2intel: 6 * 60 * MIN,
  malpedia: 7 * 24 * 60 * MIN,
});
const RETRY_MS = 5 * MIN;
const KEY_REQUIRED = Symbol('key-required');

export const TARGET = Object.freeze({ lat: 36.8508, lon: -76.2859, name: 'Hampton Roads' });

export const DEFAULT_FORTIGUARD_FEEDS = Object.freeze([
  { label: 'Outbreak Alert', url: 'https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml' },
  { label: 'Threat Signal', url: 'https://filestore.fortinet.com/fortiguard/rss/threatsignal.xml' },
  { label: 'PSIRT', url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml' },
]);

/** Well-known services for the "most targeted ports" readout. */
const SERVICES = Object.freeze({
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
  135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  502: 'Modbus', 1433: 'MSSQL', 1723: 'PPTP', 1883: 'MQTT', 2222: 'SSH-alt', 2323: 'Telnet-alt',
  3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5432: 'Postgres', 5555: 'ADB', 5900: 'VNC', 6379: 'Redis',
  7547: 'TR-069', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-alt', 9200: 'Elastic', 11211: 'Memcached',
  20000: 'DNP3', 27017: 'MongoDB', 37215: 'Huawei-HG', 52869: 'UPnP',
});

const str = (v) => (v === null || v === undefined ? '' : String(v).trim());
const num = (v) => {
  const n = Number(str(v).replace(/,/g, ''));
  return Number.isFinite(n) ? n : 0;
};

/** DShield pads octets ("045.148.010.240"); return a normal dotted quad or ''. */
export function normalizeIp(value) {
  const parts = str(value).split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return '';
  return parts.map((p) => String(Number(p))).join('.');
}

/** Accept a JSON array or DShield's {"0": {...}, "1": {...}, date, limit} object form. */
function rowsOf(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') return Object.values(payload).filter((v) => v && typeof v === 'object' && !Array.isArray(v));
  return [];
}

/** /api/topips/records/N?json → [{ip, reports, targets}] */
export function normalizeTopIps(payload) {
  return rowsOf(payload)
    .map((r) => ({ ip: normalizeIp(r.source ?? r.ip), reports: num(r.reports ?? r.count), targets: num(r.targets ?? r.attacks) }))
    .filter((r) => r.ip)
    .sort((a, b) => b.reports - a.reports);
}

/** /api/ip/<ip>?json → {country, asname} */
export function normalizeIpInfo(payload) {
  const r = payload?.ip && typeof payload.ip === 'object' ? payload.ip : payload || {};
  return { country: str(r.ascountry || r.country).toUpperCase().slice(0, 2), asname: str(r.asname), as: str(r.as) };
}

/** /api/topports/records/N?json → [{port, service, records, targets, sources}] */
export function normalizeTopPorts(payload) {
  return rowsOf(payload)
    .map((r) => {
      const port = num(r.targetport ?? r.port);
      return { port, service: SERVICES[port] || '', records: num(r.records), targets: num(r.targets), sources: num(r.sources) };
    })
    .filter((r) => r.port > 0)
    .sort((a, b) => b.records - a.records)
    .slice(0, 10);
}

function decodeXml(s) {
  return str(s)
    .replace(/^<!\[CDATA\[([\s\S]*?)\]\]>$/, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Minimal RSS 2.0 / Atom item reader for the ticker. */
export function parseRssItems(xml, label) {
  const out = [];
  const items = String(xml || '').match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  for (const item of items) {
    const tag = (name) => item.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)</${name}>`, 'i'))?.[1] ?? '';
    const title = decodeXml(tag('title'));
    if (!title) continue;
    const href = item.match(/<link\b[^>]*href="([^"]+)"/i)?.[1];
    const link = decodeXml(href || tag('link'));
    const date = Date.parse(decodeXml(tag('pubDate') || tag('updated') || tag('published')));
    out.push({
      source: label,
      title,
      link: /^https:\/\//.test(link) ? link : '',
      time: Number.isFinite(date) ? new Date(date).toISOString() : null,
    });
  }
  return out;
}

/**
 * One row per source country (arcs into the vantage point): DShield top IPs,
 * AbuseIPDB country counts and geolocated blocklist.de samples, with each
 * IP's tags (attack services, Tor, DROP, GreyNoise, malware).
 */
export function buildSources(dshieldIps, abusePoints = [], blocklistIps = []) {
  const byCountry = new Map();
  const row = (code) => {
    if (!byCountry.has(code)) {
      const c = countryCentroid(code);
      if (!c) return null;
      byCountry.set(code, {
        country: code, name: c.name, lat: c.lat, lon: c.lon,
        reports: 0, targets: 0, abuse: 0, blocklist: 0,
        services: {}, flags: { tor: 0, drop: 0, strong: 0 }, ips: [],
      });
    }
    return byCountry.get(code);
  };
  const addIp = (r, ip) => {
    for (const s of ip.services || []) r.services[s] = (r.services[s] || 0) + 1;
    if (ip.tor) r.flags.tor += 1;
    if (ip.drop) r.flags.drop += 1;
    if (ip.strong) r.flags.strong += 1;
    if (r.ips.length < 8 && !r.ips.some((x) => x.ip === ip.ip)) r.ips.push(ip);
  };
  for (const ip of dshieldIps) {
    const r = ip.country && row(ip.country);
    if (!r) continue;
    r.reports += ip.reports || 0;
    r.targets += ip.targets || 0;
    addIp(r, ip);
  }
  for (const ip of blocklistIps) {
    const r = ip.country && row(ip.country);
    if (!r) continue;
    r.blocklist += 1;
    addIp(r, ip);
  }
  for (const p of abusePoints) {
    const code = str(p.id).split(':')[1];
    const r = code && row(code);
    if (r) r.abuse += num(p.count);
  }
  const rows = [...byCountry.values()];
  const max = (k) => Math.max(1, ...rows.map((r) => r[k]));
  const maxR = max('reports');
  const maxA = max('abuse');
  const maxB = max('blocklist');
  for (const r of rows) {
    // 0..1 weight: the strongest of the three signals, each on a log scale.
    const w = Math.max(
      Math.log1p(r.reports) / Math.log1p(maxR),
      Math.log1p(r.abuse) / Math.log1p(maxA),
      0.85 * (Math.log1p(r.blocklist) / Math.log1p(maxB)),
    );
    r.weight = Math.round(w * 1000) / 1000;
    const top = Object.entries(r.services).sort((a, b) => b[1] - a[1])[0];
    r.dominantService = top ? top[0] : null;
  }
  return rows.sort((a, b) => b.weight - a.weight).slice(0, 36);
}

/** Popup lines for one IP: what we know, in both voices. */
export function describeIp(ip) {
  const lines = [];
  const head = `${ip.ip}${ip.asname ? ` · ${ip.asname}` : ''}${ip.reports ? ` · ${ip.reports.toLocaleString('en-US')} DShield reports` : ''}`;
  lines.push({ text: head });
  for (const s of ip.services || []) {
    const info = SERVICE_INFO[s];
    if (info) lines.push({ text: `↳ ${info.label}`, plain: info.plain, tech: `${info.technical} (blocklist.de, last 48h)` });
  }
  if (ip.malware) {
    const f = familyExplained(ip.malware, ip.threatType);
    lines.push({ text: `↳ Malware: ${ip.malware}`, plain: f.plain, tech: `${f.technical} (ThreatFox)` });
  }
  for (const flag of ['tor', 'drop', 'strong']) {
    if (ip[flag]) {
      const f = FLAGS[flag];
      lines.push({ text: `↳ ${f.label}${flag === 'drop' && ip.dropRef ? ` (${ip.dropRef})` : ''}`, plain: f.plain, tech: f.technical });
    }
  }
  if (ip.sslbl) lines.push({ text: `↳ ${SSLBL.label}`, plain: SSLBL.plain, tech: SSLBL.technical });
  const g = greyNoiseExplained(ip.greynoise);
  if (g) lines.push({ text: `↳ GreyNoise: ${g.label}`, plain: g.plain, tech: g.technical });
  return lines;
}

/** Cloudflare pairs → arcs between countries (same-country pairs are listed, not drawn). */
export function buildPairs(pairs) {
  return pairs
    .map((p) => {
      const a = countryCentroid(p.from.code);
      const b = countryCentroid(p.to.code);
      if (!a || !b) return null;
      const info = DDOS[p.layer] || DDOS.L7;
      return {
        layer: p.layer,
        value: p.value,
        from: { code: p.from.code, name: p.from.name || a.name, lat: a.lat, lon: a.lon },
        to: { code: p.to.code, name: p.to.name || b.name, lat: b.lat, lon: b.lon },
        domestic: p.from.code === p.to.code,
        label: info.label,
        plain: `${info.plain} ${p.value.toFixed(1)}% of what Cloudflare blocked went from ${p.from.name || a.name} to ${p.to.name || b.name}.`,
        technical: `${info.technical} Pair ${p.from.code}→${p.to.code}: ${p.value.toFixed(2)}% (last 24h).`,
      };
    })
    .filter(Boolean);
}

/** ThreatFox IOCs with a country → malware infrastructure markers per country. */
/** Family explanation, with Malpedia's description as the technical voice for families we don't know. */
export function explainFamily(name, threatType, malpedia) {
  const f = familyExplained(name, threatType);
  const m = malpediaLookup(malpedia, name);
  if (m && !f.technical.includes('·') && f.technical.startsWith(String(name || ''))) {
    return { ...f, technical: `${m.description} (Malpedia ${m.id})` };
  }
  return f;
}

export function buildMalwarePoints(iocs, malpedia = null) {
  const byCountry = new Map();
  for (const i of iocs) {
    if (!i.country) continue;
    const c = countryCentroid(i.country);
    if (!c) continue;
    if (!byCountry.has(i.country)) byCountry.set(i.country, { country: i.country, name: c.name, lat: c.lat, lon: c.lon, count: 0, families: new Map(), examples: [] });
    const r = byCountry.get(i.country);
    r.count += 1;
    const key = i.malware || 'Unknown';
    r.families.set(key, { count: (r.families.get(key)?.count || 0) + 1, threatType: i.threatType });
    if (r.examples.length < 4) r.examples.push(i);
  }
  return [...byCountry.values()]
    .map((r) => ({
      ...r,
      families: [...r.families.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .map(([name, v]) => ({ name, count: v.count, threatType: v.threatType, ...explainFamily(name, v.threatType, malpedia) })),
    }))
    .sort((a, b) => b.count - a.count);
}

/** Phishing hosts (resolved + geolocated) → one green marker per hosting country. */
export function buildPhishPoints(hosts) {
  const byCountry = new Map();
  for (const h of hosts) {
    const c = h.country && countryCentroid(h.country);
    if (!c) continue;
    const r = byCountry.get(h.country) || { country: h.country, name: c.name, lat: c.lat, lon: c.lon, count: 0, brands: new Map(), hosts: [] };
    r.count += 1;
    if (h.brand) r.brands.set(h.brand, (r.brands.get(h.brand) || 0) + 1);
    if (r.hosts.length < 5) r.hosts.push(`${defang(h.host)}${h.brand ? ` — pretends to be ${h.brand}` : ''}`);
    byCountry.set(h.country, r);
  }
  return [...byCountry.values()]
    .map((r) => ({ ...r, brands: [...r.brands.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })), ...PHISHING }))
    .sort((a, b) => b.count - a.count);
}

/** BGP hijacks → arcs from the hijacker's country to the victim's. */
export function buildHijacks(events) {
  return events
    .map((e) => {
      const a = countryCentroid(e.hijackerCountry);
      const b = countryCentroid(e.victimCountries[0]);
      if (!a || !b) return null;
      const who = e.hijackerOrg ? `${e.hijackerOrg} (AS${e.hijackerAsn})` : `AS${e.hijackerAsn}`;
      const victim = e.victimOrg ? `${e.victimOrg}${e.victimAsn ? ` (AS${e.victimAsn})` : ''}` : e.victimAsn ? `AS${e.victimAsn}` : 'another network';
      return {
        id: e.id,
        from: { code: e.hijackerCountry, name: a.name, lat: a.lat, lon: a.lon },
        to: { code: e.victimCountries[0], name: b.name, lat: b.lat, lon: b.lon },
        domestic: e.hijackerCountry === e.victimCountries[0],
        confidence: e.confidence,
        ongoing: e.ongoing,
        title: `${who} claimed ${victim}’s addresses`,
        plain: BGP.hijack.plain,
        technical: `${BGP.hijack.technical} Hijacker ${who} (${e.hijackerCountry}) → victim ${victim} (${e.victimCountries.join(', ')}); prefixes ${e.prefixes.join(', ') || 'n/a'}; confidence ${e.confidence}/10; ${e.ongoing ? 'ongoing' : `ended ${e.end || '?'}`}.`,
        time: e.start || null,
      };
    })
    .filter(Boolean);
}

export function buildLeaks(events) {
  return events
    .map((e) => {
      const c = countryCentroid(e.countries[0]);
      if (!c) return null;
      const who = e.leakOrg ? `${e.leakOrg} (AS${e.leakAsn})` : `AS${e.leakAsn}`;
      return {
        id: e.id,
        country: e.countries[0],
        name: c.name,
        lat: c.lat,
        lon: c.lon,
        title: `${who} leaked ${e.prefixes} internet routes`,
        plain: BGP.leak.plain,
        technical: `${BGP.leak.technical} Leaker ${who}; countries ${e.countries.join(', ')}; ${e.prefixes} prefixes from ${e.origins} origins; ${e.finished ? 'finished' : 'ongoing'}; detected ${e.detected || '?'}.`,
        time: e.detected || null,
      };
    })
    .filter(Boolean);
}

function spacedSample(list, n) {
  if (list.length <= n) return [...list];
  const out = [];
  for (let i = 0; i < n; i++) out.push(list[Math.floor((i * list.length) / n)]);
  return out;
}

export function createAttackMapService({
  fetchImpl = (...a) => fetch(...a),
  envSource = process.env,
  clock = Date.now,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  threatIntel = () => sharedThreatIntel(),
  resolve4 = (host) => dnsResolve4(host),
} = {}) {
  const ipCache = new Map(); // ip -> { at, info }
  const hostCache = new Map(); // phishing host -> { at, ip }
  const epssCache = new Map(); // CVE -> { at, value }
  const gnCache = new Map(); // ip -> { at, info }
  const gnBudget = { day: '', used: 0 };
  const sources = new Map(); // id -> { at, ok, status, value, error }
  let snapshot = null; // { at, body }
  let inflight = null;
  const env = (name) => str(envSource[name]);

  async function request(url, { method = 'GET', headers = {}, body } = {}) {
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        body,
        headers: { 'User-Agent': USER_AGENT, Accept: '*/*', ...headers },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      throw new Error(`${new URL(url).host}: ${err?.cause?.code || err?.name || 'fetch failed'}`);
    }
    return res;
  }
  async function getText(url, options) {
    const res = await request(url, options);
    if (!res.ok) throw new Error(`${new URL(url).host}: HTTP ${res.status}${res.status === 401 || res.status === 403 ? ' (check the key / access)' : ''}`);
    return res.text();
  }
  const getJson = async (url, options) => JSON.parse(await getText(url, options));

  /** Per-source cache: fresh value, last good on failure, key-required without calling out. */
  async function cached(id, ttl, fn) {
    const c = sources.get(id);
    if (c && clock() - c.at < (c.ok ? ttl : RETRY_MS) && c.status !== 'key-required') return c;
    let entry;
    try {
      const value = await fn();
      entry = value === KEY_REQUIRED
        ? { at: clock(), ok: false, status: 'key-required', value: null, error: null }
        : { at: clock(), ok: true, status: 'ok', value, error: null };
    } catch (err) {
      const message = err?.message || String(err);
      entry = { at: clock(), ok: false, status: c?.value ? 'stale' : 'error', value: c?.value ?? null, error: message };
    }
    sources.set(id, entry);
    return entry;
  }

  async function lookupCountries(ips, budget, errors) {
    for (const ip of ips) {
      const hit = ipCache.get(ip.ip);
      if (hit && clock() - hit.at < IP_TTL) {
        Object.assign(ip, hit.info);
        continue;
      }
      if (budget.left <= 0 || budget.failed) continue;
      budget.left -= 1;
      try {
        const info = normalizeIpInfo(await getJson(`https://isc.sans.edu/api/ip/${ip.ip}?json`));
        ipCache.set(ip.ip, { at: clock(), info });
        Object.assign(ip, info);
      } catch (err) {
        errors.push(`DShield IP lookup: ${err.message}`);
        budget.failed = true; // don't hammer a struggling API; the rest resolve next refresh
      }
      await sleep(LOOKUP_GAP_MS);
    }
  }

  async function greyNoise(ips, errors) {
    // The Community API also answers without a key (a smaller daily allowance),
    // so a key is optional: GreyNoise only issues them to work-email accounts.
    const key = env('GREYNOISE_API_KEY');
    const today = new Date(clock()).toISOString().slice(0, 10);
    if (gnBudget.day !== today) Object.assign(gnBudget, { day: today, used: 0 });
    const dailyCap = Number(env('GREYNOISE_DAILY_LIMIT')) || (key ? 40 : 25);
    let asked = 0;
    for (const ip of ips) {
      const hit = gnCache.get(ip.ip);
      if (hit && clock() - hit.at < GREYNOISE_TTL) {
        ip.greynoise = hit.info;
        continue;
      }
      if (asked >= GREYNOISE_PER_REFRESH || gnBudget.used >= dailyCap) continue;
      asked += 1;
      gnBudget.used += 1;
      try {
        const res = await request(URLS.greynoise(ip.ip), { headers: key ? { key, Accept: 'application/json' } : { Accept: 'application/json' } });
        if (res.status === 429) {
          errors.push('GreyNoise: daily limit reached');
          gnBudget.used = dailyCap;
          break;
        }
        const info = normalizeGreyNoise(JSON.parse((await res.text()) || '{}'), res.status);
        if (info) {
          gnCache.set(ip.ip, { at: clock(), info });
          ip.greynoise = info;
        } else if (res.status === 401 || res.status === 403) {
          errors.push(`GreyNoise: HTTP ${res.status} (check the key)`);
          break;
        }
      } catch (err) {
        errors.push(`GreyNoise: ${err.message}`);
        break;
      }
    }
    return 'ok';
  }

  async function dshield(errors) {
    let ips = [];
    try {
      ips = normalizeTopIps(await getJson(`https://isc.sans.edu/api/topips/records/${TOP_IPS}?json`)).slice(0, TOP_IPS);
    } catch (err) {
      errors.push(`DShield top IPs: ${err.message}`);
      return { ips: [], ports: [], ok: false };
    }
    let ports = [];
    try {
      ports = normalizeTopPorts(await getJson('https://isc.sans.edu/api/topports/records/10?json'));
    } catch (err) {
      errors.push(`DShield top ports: ${err.message}`);
    }
    return { ips, ports, ok: true };
  }

  function fortiguardFeeds() {
    const custom = env('FORTIGUARD_RSS');
    return custom
      ? custom.split(',').map((url) => ({ label: 'FortiGuard', url: url.trim() })).filter((f) => /^https:\/\//.test(f.url))
      : DEFAULT_FORTIGUARD_FEEDS;
  }

  const fetchers = {
    radar: () => {
      const token = env('CLOUDFLARE_API_TOKEN');
      if (!token) return KEY_REQUIRED;
      const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
      const get = (path, params) => getJson(radarUrl(path, params), { headers });
      return Promise.allSettled([
        get('layer7/top/attacks', { limit: '20' }),
        get('layer3/top/attacks', { limit: '15' }),
        get('layer7/top/industry', { limit: '8' }),
        get('layer7/top/locations/target', { limit: '8' }),
      ]).then(([l7, l3, industry, targets]) => {
        if ([l7, l3, industry, targets].every((r) => r.status === 'rejected')) throw l7.reason;
        return {
          pairs: [
            ...(l7.status === 'fulfilled' ? normalizeRadarPairs(l7.value, 'L7') : []),
            ...(l3.status === 'fulfilled' ? normalizeRadarPairs(l3.value, 'L3') : []),
          ],
          industries: industry.status === 'fulfilled' ? normalizeRadarTop(industry.value) : [],
          targets: targets.status === 'fulfilled' ? normalizeRadarTop(targets.value) : [],
        };
      });
    },
    blocklist: async () => {
      const lists = {};
      const results = await Promise.allSettled(
        [...SERVICE_ORDER, 'strongips'].map(async (s) => [s, parseIpList(await getText(URLS.blocklist(s)))]),
      );
      for (const r of results) if (r.status === 'fulfilled') lists[r.value[0]] = r.value[1];
      if (!Object.keys(lists).length) throw results[0].reason;
      return lists;
    },
    threatfox: async () => {
      const key = env('ABUSECH_AUTH_KEY');
      if (!key) return KEY_REQUIRED;
      return normalizeThreatFox(
        await getJson(URLS.threatfox, {
          method: 'POST',
          headers: { 'Auth-Key': key, 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ query: 'get_iocs', days: 1 }),
        }),
      );
    },
    urlhaus: async () => {
      const key = env('ABUSECH_AUTH_KEY');
      if (!key) return KEY_REQUIRED;
      return normalizeUrlhaus(await getJson(URLS.urlhaus, { headers: { 'Auth-Key': key, Accept: 'application/json' } }));
    },
    otx: async () => {
      const key = env('OTX_API_KEY');
      if (!key) return KEY_REQUIRED;
      return normalizeOtx(await getJson(URLS.otx, { headers: { 'X-OTX-API-KEY': key, Accept: 'application/json' } }));
    },
    shadowserver: async () => {
      const key = env('SHADOWSERVER_API_KEY');
      const secret = env('SHADOWSERVER_API_SECRET');
      if (!key || !secret) return KEY_REQUIRED;
      const req = shadowserverRequest({ limit: 12 }, key, secret);
      return parseJsonLines(await getText(URLS.shadowserver, { method: 'POST', headers: req.headers, body: req.body }));
    },
    drop: async () => {
      try {
        return parseDrop(await getText(URLS.dropJson));
      } catch {
        return parseDrop(await getText(URLS.dropTxt));
      }
    },
    tor: async () => new Set(parseIpList(await getText(URLS.tor))),
    kev: async () => normalizeKev(await getJson(URLS.kev)),
    fortiguard: async () => {
      const items = [];
      const errs = [];
      await Promise.all(
        fortiguardFeeds().map(async (f) => {
          try {
            items.push(...parseRssItems(await getText(f.url), f.label).slice(0, 12));
          } catch (err) {
            errs.push(`${f.label}: ${err.message}`);
          }
        }),
      );
      if (!items.length && errs.length) throw new Error(errs.join('; '));
      return items;
    },
    bgp: async () => {
      const token = env('CLOUDFLARE_API_TOKEN');
      if (!token) return KEY_REQUIRED;
      const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
      const [h, l] = await Promise.allSettled([getJson(URLS.bgpHijacks, { headers }), getJson(URLS.bgpLeaks, { headers })]);
      if (h.status === 'rejected' && l.status === 'rejected') throw h.reason;
      return {
        hijacks: h.status === 'fulfilled' ? normalizeBgpHijacks(h.value) : [],
        leaks: l.status === 'fulfilled' ? normalizeBgpLeaks(l.value) : [],
      };
    },
    malwarebazaar: async () => {
      const key = env('ABUSECH_AUTH_KEY');
      if (!key) return KEY_REQUIRED;
      return normalizeMalwareBazaar(
        await getJson(URLS.malwarebazaar, {
          method: 'POST',
          headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
          body: new URLSearchParams({ query: 'get_recent', selector: 'time' }).toString(),
        }),
      );
    },
    sslbl: async () => {
      const key = env('ABUSECH_AUTH_KEY');
      return parseSslbl(await getText(URLS.sslbl, { headers: key ? { 'Auth-Key': key } : {} }));
    },
    hibp: async () => normalizeHibp(await getJson(URLS.hibp, { headers: { Accept: 'application/json' } })),
    poc: async () => {
      const token = env('GITHUB_TOKEN');
      const year = new Date(clock()).getUTCFullYear();
      const headers = { Accept: 'application/vnd.github+json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
      return normalizePocSearch(await getJson(URLS.poc(year), { headers }));
    },
    ics: async () => parseRssItems(await getText(URLS.icsAdvisories), 'ICS').slice(0, 8),
    openphish: async () => parseOpenPhish(await getText(URLS.openphish)),
    c2intel: async () => parseC2Intel(await getText(URLS.c2intel)),
    malpedia: async () => normalizeMalpedia(await getJson(URLS.malpedia)),
  };

  async function resolveHosts(hosts, errors) {
    let asked = 0;
    for (const h of hosts) {
      const hit = hostCache.get(h.host);
      if (hit && clock() - hit.at < IP_TTL) {
        h.ip = hit.ip;
        continue;
      }
      if (asked >= PHISH_SAMPLE) continue;
      asked += 1;
      try {
        const ips = await Promise.race([resolve4(h.host), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000).unref?.())]);
        h.ip = Array.isArray(ips) ? ips[0] || '' : '';
      } catch {
        h.ip = '';
      }
      hostCache.set(h.host, { at: clock(), ip: h.ip });
    }
    return hosts.filter((h) => h.ip);
  }

  async function epssFor(cves, errors) {
    const want = [...new Set(cves.filter((c) => /^CVE-\d{4}-\d+$/.test(c)))].slice(0, 40);
    const missing = want.filter((c) => !(epssCache.get(c) && clock() - epssCache.get(c).at < EPSS_TTL));
    if (missing.length) {
      try {
        const m = normalizeEpss(await getJson(URLS.epss(missing)));
        for (const c of missing) epssCache.set(c, { at: clock(), value: m.get(c) || null });
      } catch (err) {
        errors.push(`EPSS: ${err.message}`);
      }
    }
    return new Map(want.map((c) => [c, epssCache.get(c)?.value || null]));
  }

  async function build() {
    const errors = [];
    const ids = Object.keys(fetchers);
    const [dsh, abuse, ...entries] = await Promise.all([
      dshield(errors),
      Promise.resolve(threatIntel()?.get?.('abuseipdb')).catch(() => null),
      ...ids.map((id) => cached(id, SOURCE_TTL[id], fetchers[id])),
    ]);
    const src = Object.fromEntries(ids.map((id, i) => [id, entries[i]]));
    const val = (id) => src[id]?.value;
    for (const [id, e] of Object.entries(src)) if (e.error) errors.push(`${id}: ${e.error}`);

    // Membership sets for tagging.
    const lists = val('blocklist') || {};
    const sets = Object.fromEntries(Object.entries(lists).map(([k, v]) => [k, new Set(v)]));
    const tor = val('tor') || new Set();
    const drop = val('drop') || [];
    const iocs = val('threatfox') || [];
    const iocByIp = new Map(iocs.filter((i) => i.ip).map((i) => [i.ip, i]));
    const sslblList = val('sslbl') || [];
    const sslblSet = new Set(sslblList);
    const malpedia = val('malpedia');
    const tag = (ip) => {
      ip.services = SERVICE_ORDER.filter((s) => sets[s]?.has(ip.ip));
      ip.tor = tor.has(ip.ip);
      const d = drop.length ? findRange(ip.ip, drop) : null;
      ip.drop = Boolean(d);
      if (d) ip.dropRef = d.sbl;
      ip.strong = Boolean(sets.strongips?.has(ip.ip));
      const ioc = iocByIp.get(ip.ip);
      if (ioc) Object.assign(ip, { malware: ioc.malware, threatType: ioc.threatType });
      ip.sslbl = sslblSet.has(ip.ip);
      return ip;
    };

    // Country lookups, shared budget: DShield top IPs first, then samples.
    const budget = { left: MAX_NEW_LOOKUPS, failed: false };
    await lookupCountries(dsh.ips, budget, errors);
    const blocklistIps = SERVICE_ORDER.flatMap((s) =>
      spacedSample(lists[s] || [], BLOCKLIST_SAMPLE).map((ip) => ({ ip, services: [s] })),
    );
    await lookupCountries(blocklistIps, budget, errors);
    const c2 = [
      ...iocs.filter((i) => i.ip && i.threatType === 'botnet_cc').slice(0, 24),
      ...spacedSample(val('c2intel') || [], C2INTEL_SAMPLE).map((x) => ({ ...x, ioc: x.ip, source: 'C2IntelFeeds' })),
      ...spacedSample(sslblList, SSLBL_SAMPLE).map((ip) => ({ ip, ioc: ip, malware: 'SSLBL-listed botnet server', threatType: 'botnet_cc', source: 'SSLBL' })),
    ];
    await lookupCountries(c2, budget, errors);
    const phish = val('openphish') || { total: 0, hosts: [] };
    const phishHosts = await resolveHosts(spacedSample(phish.hosts, PHISH_SAMPLE).map((h) => ({ ...h })), errors);
    await lookupCountries(phishHosts, budget, errors);

    dsh.ips.forEach(tag);
    blocklistIps.forEach((ip) => {
      const own = ip.services;
      tag(ip);
      if (!ip.services.length) ip.services = own;
    });
    const gnStatus = await greyNoise(dsh.ips.slice(0, 10), errors);

    const abusePoints = abuse && (abuse.status === 'ok' || abuse.status === 'stale') ? abuse.points || [] : [];
    const rows = buildSources(dsh.ips, abusePoints, blocklistIps);
    for (const r of rows) r.ips = r.ips.map((ip) => ({ ip: ip.ip, lines: describeIp(ip) }));

    const radar = val('radar') || { pairs: [], industries: [], targets: [] };
    const pairs = buildPairs(radar.pairs);
    const malware = buildMalwarePoints(c2, malpedia);
    const phishing = buildPhishPoints(phishHosts);
    const bgp = val('bgp') || { hijacks: [], leaks: [] };
    const hijacks = buildHijacks(bgp.hijacks);
    const leaks = buildLeaks(bgp.leaks);
    const attackTypes = SERVICE_ORDER.filter((s) => lists[s]?.length).map((s) => ({
      service: s,
      count: lists[s].length,
      ...SERVICE_INFO[s],
    }));
    const exploited = (val('shadowserver') || []).slice(0, 8).map((r) => ({ ...exploitedExplained(r), vulnerability: r.vulnerability }));
    const pocs = val('poc') || [];
    const kev = val('kev') || [];
    const epss = await epssFor([...kev.map((v) => v.cveID), ...exploited.map((e) => e.vulnerability), ...pocs.map((p) => p.cve)], errors);
    const dailyReports = dsh.ips.reduce((sum, ip) => sum + ip.reports, 0);

    const body = {
      status: rows.length || pairs.length || malware.length ? 'ok' : 'error',
      updatedAt: new Date(clock()).toISOString(),
      target: TARGET,
      sources: rows,
      pairs,
      malware,
      phishing,
      hijacks,
      leaks,
      attackTypes,
      ddos: {
        industries: radar.industries.map((i) => ({
          ...i,
          plain: `${i.name} websites took ${i.value.toFixed(1)}% of the web attacks Cloudflare blocked.`,
          technical: `Cloudflare Radar L7 top industry: ${i.value.toFixed(2)}% of mitigated requests (24h).`,
        })),
        targets: radar.targets,
      },
      exploited,
      ports: dsh.ports.map((p) => ({ ...p, ...portExplained(p.port, p.service) })),
      rate: {
        perMinute: Math.round((dailyReports / 1440) * 10) / 10,
        basis: `DShield reports from the top ${dsh.ips.length} sources, averaged over a day`,
      },
      alerts: buildAlerts({
        fortiguard: val('fortiguard') || [],
        otx: val('otx') || [],
        kev,
        exploited,
        urlhaus: val('urlhaus'),
        iocs,
        epss,
        hijacks,
        leaks,
        malwarebazaar: val('malwarebazaar'),
        breaches: val('hibp') || [],
        pocs,
        ics: val('ics') || [],
        phish,
        c2intel: val('c2intel') || [],
        malpedia,
      }),
      abuseipdb: abuse?.status || 'off',
      feeds: [
        { id: 'dshield', label: 'SANS ISC / DShield', status: dsh.ok ? 'ok' : 'error' },
        { id: 'abuseipdb', label: 'AbuseIPDB', status: abuse?.status || 'off', keyEnv: 'ABUSEIPDB_API_KEY' },
        ...ids.map((id) => ({ id, label: FEED_LABELS[id], status: src[id].status, error: src[id].error, keyEnv: FEED_KEYS[id] || null })),
        { id: 'epss', label: 'FIRST EPSS', status: errors.some((e) => e.startsWith('EPSS')) ? 'error' : 'ok' },
        { id: 'greynoise', label: env('GREYNOISE_API_KEY') ? 'GreyNoise' : 'GreyNoise (no key, smaller daily allowance)', status: gnStatus, keyEnv: 'GREYNOISE_API_KEY' },
      ],
      errors,
    };
    return body;
  }

  return {
    async get() {
      if (snapshot && clock() - snapshot.at < TTL) return snapshot.body;
      inflight ??= build()
        .then((body) => {
          const lastGood = snapshot?.body?.sources?.length ? snapshot.body : null;
          if (!body.sources.length && !body.pairs.length && !body.malware.length && lastGood) {
            // Keep the last good arcs (and any fresh ticker items); retry in 5 minutes.
            const stale = { ...lastGood, status: 'stale', alerts: body.alerts.length ? body.alerts : lastGood.alerts, feeds: body.feeds, errors: body.errors };
            snapshot = { at: clock() - TTL + RETRY_MS, body: lastGood };
            return stale;
          }
          snapshot = { at: body.status === 'ok' ? clock() : clock() - TTL + RETRY_MS, body };
          return body;
        })
        .finally(() => {
          inflight = null;
        });
      return inflight;
    },
  };
}

const FEED_LABELS = Object.freeze({
  radar: 'Cloudflare Radar',
  blocklist: 'blocklist.de',
  threatfox: 'abuse.ch ThreatFox',
  urlhaus: 'abuse.ch URLhaus',
  otx: 'AlienVault OTX',
  shadowserver: 'Shadowserver',
  drop: 'Spamhaus DROP',
  tor: 'Tor exit list',
  kev: 'CISA KEV',
  fortiguard: 'FortiGuard',
  bgp: 'Cloudflare Radar BGP (route hijacks & leaks)',
  malwarebazaar: 'abuse.ch MalwareBazaar',
  sslbl: 'abuse.ch SSLBL',
  hibp: 'Have I Been Pwned (breaches)',
  poc: 'GitHub PoC watch',
  ics: 'CISA ICS advisories',
  openphish: 'OpenPhish',
  c2intel: 'C2IntelFeeds',
  malpedia: 'Malpedia',
});
const FEED_KEYS = Object.freeze({
  radar: 'CLOUDFLARE_API_TOKEN',
  threatfox: 'ABUSECH_AUTH_KEY',
  urlhaus: 'ABUSECH_AUTH_KEY',
  otx: 'OTX_API_KEY',
  shadowserver: 'SHADOWSERVER_API_KEY',
  bgp: 'CLOUDFLARE_API_TOKEN',
  malwarebazaar: 'ABUSECH_AUTH_KEY',
});

/** EPSS line for a CVE, as an alert detail. */
function epssDetail(epss, cve) {
  const e = epssExplained(epss?.get?.(cve));
  return e ? [{ label: `EPSS · ${cve}`, plain: e.plain, technical: e.technical, link: `https://www.first.org/epss/` }] : [];
}

/**
 * Every alert: { source, title, plain, technical, link, time, details? }.
 * `details` are extra two-voice lines (EPSS odds, ATT&CK techniques).
 * Newest first, sources interleaved so no one feed floods the ticker.
 */
export function buildAlerts({
  fortiguard = [], otx = [], kev = [], exploited = [], urlhaus = null, iocs = [], epss = new Map(),
  hijacks = [], leaks = [], malwarebazaar = null, breaches = [], pocs = [], ics = [], phish = null, c2intel = [], malpedia = null,
} = {}) {
  const lanes = [];
  lanes.push(
    fortiguard.map((a) => {
      const kind = FORTIGUARD_KINDS[a.source] || FORTIGUARD_KINDS['Threat Signal'];
      return { source: `FortiGuard ${a.source}`, title: a.title, plain: kind.plain, technical: `${kind.technical} “${a.title}”`, link: a.link, time: a.time };
    }),
  );
  lanes.push(
    otx.slice(0, 12).map((p) => {
      const techniques = (p.attack_ids || []).map(techniqueExplained).filter(Boolean).slice(0, 5);
      return {
        source: 'OTX',
        ...pulseExplained(p),
        link: p.id ? `https://otx.alienvault.com/pulse/${p.id}` : '',
        time: p.time || null,
        details: techniques.map((t) => ({ label: `${t.id} · ${t.name}`, plain: t.plain, technical: t.technical, link: t.link })),
      };
    }),
  );
  lanes.push(
    kev.map((v) => ({
      source: 'CISA KEV',
      ...kevExplained(v),
      link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cveID)}`,
      time: v.dateAdded ? `${v.dateAdded}T00:00:00Z` : null,
      details: epssDetail(epss, v.cveID),
    })),
  );
  lanes.push(exploited.map((e) => ({ source: 'Shadowserver', title: e.title, plain: e.plain, technical: e.technical, link: '', time: null, details: epssDetail(epss, e.vulnerability) })));
  lanes.push(
    pocs.slice(0, 6).map((p) => ({
      source: 'PoC watch',
      ...pocExplained(p),
      link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(p.cve)}`,
      time: p.created || null,
      details: epssDetail(epss, p.cve),
    })),
  );
  lanes.push(ics.slice(0, 6).map((a) => ({ source: 'CISA ICS', ...icsAdvisoryExplained(a), link: a.link, time: a.time })));
  lanes.push(hijacks.slice(0, 5).map((h) => ({ source: 'BGP hijack', title: h.title, plain: h.plain, technical: h.technical, link: 'https://radar.cloudflare.com/routing', time: h.time })));
  lanes.push(leaks.slice(0, 3).map((l) => ({ source: 'BGP leak', title: l.title, plain: l.plain, technical: l.technical, link: 'https://radar.cloudflare.com/routing', time: l.time })));
  lanes.push(breaches.map((b) => ({ source: 'Breach', ...breachExplained(b), link: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(b.name)}`, time: b.addedDate || null })));
  const extra = [];
  if (iocs.length) {
    const counts = new Map();
    for (const i of iocs) if (i.malware) counts.set(i.malware, (counts.get(i.malware) || 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
    if (top.length) {
      const f = explainFamily(top[0][0], undefined, malpedia);
      extra.push({
        source: 'ThreatFox',
        title: `Most-reported malware today: ${top.map(([n, c]) => `${n} (${c})`).join(', ')}`,
        plain: `${top[0][0]}: ${f.plain}`,
        technical: `ThreatFox IOCs (24h): ${iocs.length} indicators; top families ${top.map(([n, c]) => `${n}=${c}`).join(', ')}. ${f.technical}`,
        link: 'https://threatfox.abuse.ch/browse/',
        time: null,
      });
    }
  }
  if (urlhaus?.total) {
    extra.push({
      source: 'URLhaus',
      title: `${urlhaus.online} malware download links are live right now`,
      plain: `Researchers reported ${urlhaus.total} web links handing out malware in the last few days; ${urlhaus.online} still work. Opening one infects the computer.`,
      technical: `URLhaus recent URLs: ${urlhaus.total} (online ${urlhaus.online}); top tags ${urlhaus.topTags.map((t) => `${t.tag}=${t.count}`).join(', ') || 'n/a'}.`,
      link: 'https://urlhaus.abuse.ch/browse/',
      time: null,
    });
  }
  if (malwarebazaar?.total) extra.push({ source: 'MalwareBazaar', ...malwareBazaarExplained(malwarebazaar), link: 'https://bazaar.abuse.ch/browse/', time: null });
  if (phish?.total) {
    const brands = new Map();
    for (const h of phish.hosts) if (h.brand) brands.set(h.brand, (brands.get(h.brand) || 0) + h.urls);
    const top = [...brands.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
    extra.push({
      source: 'OpenPhish',
      title: `${phish.total.toLocaleString('en-US')} phishing pages active${top.length ? ` — most faked: ${top[0][0]}` : ''}`,
      plain: `${PHISHING.plain}${top.length ? ` The most-copied brands right now: ${top.map(([n]) => n).join(', ')}.` : ''}`,
      technical: `${PHISHING.technical} ${phish.total} URLs on ${phish.hosts.length} hosts${top.length ? `; brand keywords ${top.map(([n, c]) => `${n}=${c}`).join(', ')}` : ''}.`,
      link: 'https://openphish.com/',
      time: null,
    });
  }
  if (c2intel.length) {
    const tools = new Map();
    for (const c of c2intel) tools.set(c.malware, (tools.get(c.malware) || 0) + 1);
    const top = [...tools.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
    extra.push({
      source: 'C2IntelFeeds',
      title: `${c2intel.length.toLocaleString('en-US')} hacking-toolkit servers seen this month — mostly ${top[0][0]}`,
      plain: C2_TOOLS.plain,
      technical: `${C2_TOOLS.technical} ${top.map(([n, c]) => `${n}=${c}`).join(', ')}.`,
      link: 'https://github.com/drb-ra/C2IntelFeeds',
      time: null,
    });
  }
  lanes.push(extra);
  const sorted = lanes.map((l) => [...l].sort((a, b) => String(b.time || '').localeCompare(String(a.time || ''))));
  const out = [];
  for (let i = 0; out.length < 60 && sorted.some((l) => i < l.length); i++) for (const l of sorted) if (l[i] && out.length < 60) out.push(l[i]);
  return out;
}

export function createAttackMapMiddleware(options) {
  const service = createAttackMapService(options);
  return async function attackMapMiddleware(req, res) {
    const send = (status, body) => {
      if (res.headersSent) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return send(405, { error: 'method not allowed' });
    try {
      return send(200, await service.get());
    } catch (err) {
      return send(500, { error: `attack-map error: ${err?.message || err}` });
    }
  };
}

export function attackMapProxy() {
  const middleware = createAttackMapMiddleware();
  return {
    name: 'anansi-attack-map',
    configureServer(server) {
      server.middlewares.use('/api/attackmap', middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/api/attackmap', middleware);
    },
  };
}
