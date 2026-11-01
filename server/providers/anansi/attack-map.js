// Anansi: Attack Map — who is attacking, drawn as arcs into Hampton Roads.
//
//   GET /api/attackmap
//
// Sources (all public; none of them is FortiGuard's map, which has no API):
//   SANS Internet Storm Center / DShield   top attacking IPs seen by its
//                                          volunteer honeypot sensors, each
//                                          looked up for its country (cached
//                                          per IP for a day), plus the most
//                                          targeted ports
//   AbuseIPDB (when its key is set)        reported attackers per country,
//                                          read through the shared threat-
//                                          intel cache so quotas are shared
//   FortiGuard RSS                         outbreak alerts / threat signals /
//                                          PSIRT advisories for the ticker
//
// The arcs show where attack traffic comes FROM. DShield sensors are spread
// worldwide, so the arc end point (Hampton Roads) is the viewer's vantage,
// not a claim that these sources hit Hampton Roads specifically.
//
// Response: { status, updatedAt, target, sources[], ports[], rate, alerts[], errors[] }
import { countryCentroid } from './threat-feeds.js';
import { sharedThreatIntel } from './threat-intel.js';

const MIN = 60_000;
const TTL = 30 * MIN;
const ALERT_TTL = 60 * MIN;
const IP_TTL = 24 * 60 * MIN;
const TIMEOUT_MS = 20_000;
const TOP_IPS = 40; // DShield asks for restraint; 40 lookups a day per new IP at most
const LOOKUP_GAP_MS = 250;
const USER_AGENT = 'Anansi/1.0 (personal threat-intel research dashboard)';

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
 * Group DShield IPs (with looked-up countries) and AbuseIPDB country points
 * into one row per source country.
 */
export function buildSources(dshieldIps, abusePoints = []) {
  const byCountry = new Map();
  const row = (code) => {
    if (!byCountry.has(code)) {
      const c = countryCentroid(code);
      if (!c) return null;
      byCountry.set(code, { country: code, name: c.name, lat: c.lat, lon: c.lon, reports: 0, targets: 0, abuse: 0, ips: [] });
    }
    return byCountry.get(code);
  };
  for (const ip of dshieldIps) {
    const r = ip.country && row(ip.country);
    if (!r) continue;
    r.reports += ip.reports;
    r.targets += ip.targets;
    if (r.ips.length < 6) r.ips.push({ ip: ip.ip, reports: ip.reports, asname: ip.asname || '' });
  }
  for (const p of abusePoints) {
    const code = str(p.id).split(':')[1];
    const r = code && row(code);
    if (r) r.abuse += num(p.count);
  }
  const rows = [...byCountry.values()];
  const maxR = Math.max(1, ...rows.map((r) => r.reports));
  const maxA = Math.max(1, ...rows.map((r) => r.abuse));
  for (const r of rows) {
    // 0..1 weight mixing both sources on a log scale so one country can't flatten the rest.
    const w = Math.max(Math.log1p(r.reports) / Math.log1p(maxR), Math.log1p(r.abuse) / Math.log1p(maxA));
    r.weight = Math.round(w * 1000) / 1000;
  }
  return rows.sort((a, b) => b.weight - a.weight).slice(0, 30);
}

export function createAttackMapService({
  fetchImpl = (...a) => fetch(...a),
  envSource = process.env,
  clock = Date.now,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  threatIntel = () => sharedThreatIntel(),
} = {}) {
  const ipCache = new Map(); // ip -> { at, info }
  let snapshot = null; // { at, body }
  let alerts = { at: -Infinity, items: [], errors: [] };
  let inflight = null;

  async function getText(url) {
    let res;
    try {
      res = await fetchImpl(url, { headers: { 'User-Agent': USER_AGENT, Accept: '*/*' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (err) {
      throw new Error(`${new URL(url).host}: ${err?.cause?.code || err?.name || 'fetch failed'}`);
    }
    if (!res.ok) throw new Error(`${new URL(url).host}: HTTP ${res.status}`);
    return res.text();
  }
  const getJson = async (url) => JSON.parse(await getText(url));

  async function dshield(errors) {
    let ips = [];
    try {
      ips = normalizeTopIps(await getJson(`https://isc.sans.edu/api/topips/records/${TOP_IPS}?json`)).slice(0, TOP_IPS);
    } catch (err) {
      errors.push(`DShield top IPs: ${err.message}`);
      return { ips: [], ports: [] };
    }
    for (const ip of ips) {
      const hit = ipCache.get(ip.ip);
      if (hit && clock() - hit.at < IP_TTL) {
        Object.assign(ip, hit.info);
        continue;
      }
      try {
        const info = normalizeIpInfo(await getJson(`https://isc.sans.edu/api/ip/${ip.ip}?json`));
        ipCache.set(ip.ip, { at: clock(), info });
        Object.assign(ip, info);
      } catch (err) {
        errors.push(`DShield IP lookup: ${err.message}`);
        break; // don't hammer a struggling API; the rest resolve next refresh
      }
      await sleep(LOOKUP_GAP_MS);
    }
    let ports = [];
    try {
      ports = normalizeTopPorts(await getJson('https://isc.sans.edu/api/topports/records/10?json'));
    } catch (err) {
      errors.push(`DShield top ports: ${err.message}`);
    }
    return { ips, ports };
  }

  async function fortiguard() {
    if (clock() - alerts.at < ALERT_TTL) return alerts;
    const custom = str(envSource.FORTIGUARD_RSS);
    const feeds = custom
      ? custom.split(',').map((url) => ({ label: 'FortiGuard', url: url.trim() })).filter((f) => /^https:\/\//.test(f.url))
      : DEFAULT_FORTIGUARD_FEEDS;
    const items = [];
    const errors = [];
    await Promise.all(
      feeds.map(async (f) => {
        try {
          items.push(...parseRssItems(await getText(f.url), f.label).slice(0, 15));
        } catch (err) {
          errors.push(`FortiGuard ${f.label}: ${err.message}`);
        }
      }),
    );
    items.sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')));
    alerts = { at: items.length ? clock() : clock() - ALERT_TTL + 5 * MIN, items: items.slice(0, 25), errors };
    return alerts;
  }

  async function build() {
    const errors = [];
    const [{ ips, ports }, abuse, feed] = await Promise.all([
      dshield(errors),
      Promise.resolve(threatIntel()?.get?.('abuseipdb')).catch(() => null),
      fortiguard(),
    ]);
    errors.push(...feed.errors);
    const abusePoints = abuse && (abuse.status === 'ok' || abuse.status === 'stale') ? abuse.points || [] : [];
    const sources = buildSources(ips, abusePoints);
    const dailyReports = ips.reduce((sum, ip) => sum + ip.reports, 0);
    const body = {
      status: sources.length ? 'ok' : feed.items.length ? 'partial' : 'error',
      updatedAt: new Date(clock()).toISOString(),
      target: TARGET,
      sources,
      ports,
      rate: {
        perMinute: Math.round((dailyReports / 1440) * 10) / 10,
        basis: `DShield reports from the top ${ips.length} sources, averaged over a day`,
      },
      alerts: feed.items,
      abuseipdb: abuse?.status || 'off',
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
          if (!body.sources.length && lastGood) {
            // Keep the last good arcs (and any fresh ticker items); retry in 5 minutes.
            const stale = { ...lastGood, status: 'stale', alerts: body.alerts.length ? body.alerts : lastGood.alerts, errors: body.errors };
            snapshot = { at: clock() - TTL + 5 * MIN, body: lastGood };
            return stale;
          }
          snapshot = { at: body.sources.length ? clock() : clock() - TTL + 5 * MIN, body };
          return body;
        })
        .finally(() => {
          inflight = null;
        });
      return inflight;
    },
  };
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
