/**
 * Ananzi FANGS — per-IP city geolocation.
 *
 * Turns a flat list of attacker IPs into { lat, lon, city, country } so the
 * attack map can scatter sources across real cities worldwide instead of
 * collapsing everyone onto a country centroid.
 *
 * Two strategies, in order of preference:
 *   1. A local MaxMind GeoLite2-City database (no network, no rate limit) when
 *      the GEOLITE2_CITY_DB env var points at a .mmdb file and the optional
 *      `maxmind` package is installed. This is the right production path.
 *   2. ip-api.com's keyless batch endpoint (up to 100 IPs/call, ~15 calls/min,
 *      non-commercial use) as a zero-config fallback.
 *
 * Honest degradation throughout: results are cached, lookups are capped per
 * refresh, and any failure leaves the cache intact and returns whatever is
 * already known — it never throws into the map build.
 */

const GEO_TTL_MS = 30 * 24 * 60 * 60 * 1000; // a city rarely moves
const IPAPI_BATCH = 100;
const IPAPI_MAX_NEW_PER_REFRESH = 300; // polite to the keyless endpoint
const IPAPI_URL = 'http://ip-api.com/batch?fields=status,countryCode,city,lat,lon,query';

const str = (v) => (v == null ? '' : String(v).trim());

/** ip-api.com /batch response → Map(ip → {lat, lon, city, country}). Pure. */
export function normalizeIpApiBatch(payload) {
  const rows = Array.isArray(payload) ? payload : [];
  const out = new Map();
  for (const r of rows) {
    if (!r || r.status !== 'success') continue;
    const ip = str(r.query);
    const lat = Number(r.lat);
    const lon = Number(r.lon);
    if (!ip || !Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    out.set(ip, { lat, lon, city: str(r.city), country: str(r.countryCode).toUpperCase().slice(0, 2) });
  }
  return out;
}

/** MaxMind GeoLite2-City record → {lat, lon, city, country} or null. Pure. */
export function normalizeMmdb(rec) {
  const lat = Number(rec?.location?.latitude);
  const lon = Number(rec?.location?.longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  return {
    lat,
    lon,
    city: str(rec?.city?.names?.en),
    country: str(rec?.country?.iso_code || rec?.registered_country?.iso_code).toUpperCase().slice(0, 2),
  };
}

/**
 * Build a geolocation resolver.
 * @param {object} deps
 * @param {(url, options?) => Promise<any>} deps.getJson - JSON fetch (shares the map's fetchImpl).
 * @param {Record<string,string>} [deps.env] - environment (for GEOLITE2_CITY_DB).
 * @param {() => number} [deps.clock]
 * @param {Map} [deps.cache] - injectable ip → {at, geo|null} cache.
 * @param {() => Promise<object|null>} [deps.openMmdb] - test seam for the local DB reader.
 */
export function createIpGeo({ getJson, env = {}, clock = Date.now, cache = new Map(), openMmdb } = {}) {
  let mmdbReader; // lazily opened, reused
  let mmdbTried = false;

  async function reader() {
    if (mmdbTried) return mmdbReader;
    mmdbTried = true;
    const dbPath = str(env.GEOLITE2_CITY_DB);
    if (!dbPath) return (mmdbReader = null);
    try {
      if (openMmdb) mmdbReader = await openMmdb(dbPath);
      else {
        const maxmind = await import('maxmind'); // optional dependency
        mmdbReader = await (maxmind.open || maxmind.default?.open)(dbPath);
      }
    } catch {
      mmdbReader = null; // not installed / unreadable → fall back to ip-api
    }
    return mmdbReader;
  }

  const fresh = (ip) => {
    const hit = cache.get(ip);
    return hit && clock() - hit.at < GEO_TTL_MS ? hit : null;
  };

  async function resolve(ips, errors = []) {
    const want = [...new Set((ips || []).filter(Boolean))];
    const result = new Map();
    const need = [];
    for (const ip of want) {
      const hit = fresh(ip);
      if (hit) {
        if (hit.geo) result.set(ip, hit.geo);
      } else need.push(ip);
    }
    if (!need.length) return result;

    // Strategy 1: local GeoLite2 (all of them, no network cost).
    const rdr = await reader();
    if (rdr) {
      for (const ip of need) {
        let geo = null;
        try { geo = normalizeMmdb(rdr.get(ip)); } catch { geo = null; }
        cache.set(ip, { at: clock(), geo });
        if (geo) result.set(ip, geo);
      }
      return result;
    }

    // Strategy 2: ip-api.com keyless batch, capped per refresh.
    const batchable = need.slice(0, IPAPI_MAX_NEW_PER_REFRESH);
    for (let i = 0; i < batchable.length; i += IPAPI_BATCH) {
      const chunk = batchable.slice(i, i + IPAPI_BATCH);
      try {
        const geo = normalizeIpApiBatch(
          await getJson(IPAPI_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(chunk),
          }),
        );
        for (const ip of chunk) {
          const g = geo.get(ip) || null;
          cache.set(ip, { at: clock(), geo: g });
          if (g) result.set(ip, g);
        }
      } catch (err) {
        errors.push(`ip-geo: ${err?.message || err}`);
        break; // rate-limited or offline — keep what we have, try again next refresh
      }
    }
    return result;
  }

  return { resolve };
}
