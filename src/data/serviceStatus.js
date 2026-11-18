/**
 * Ananzi FANGS — service / outage status (the honest "is it down right now").
 *
 * Downdetector has no free API and can't be scraped, so this uses the open
 * equivalent: the statuspage.io v2 "summary" endpoint that most big providers
 * publish for free and keyless (`/api/v2/summary.json`). Each tells us, from
 * the horse's mouth, whether a provider is operational, degraded or down, plus
 * any active incidents — authoritative status rather than crowd complaints.
 *
 * Pure parsing + assembly (unit-tested in serviceStatus.test.mjs); the IO shell
 * lives in server/providers/anansi/service-status.js and the board widget in
 * src/anansi/serviceStatus.js.
 */

/** Reputable providers that publish a statuspage.io v2 summary (all keyless). */
export const STATUSPAGE_PROVIDERS = Object.freeze([
  { id: 'cloudflare', label: 'Cloudflare', host: 'www.cloudflarestatus.com' },
  { id: 'github', label: 'GitHub', host: 'www.githubstatus.com' },
  { id: 'fastly', label: 'Fastly', host: 'www.fastlystatus.com' },
  { id: 'discord', label: 'Discord', host: 'discordstatus.com' },
  { id: 'reddit', label: 'Reddit', host: 'www.redditstatus.com' },
  { id: 'zoom', label: 'Zoom', host: 'status.zoom.us' },
  { id: 'twilio', label: 'Twilio', host: 'status.twilio.com' },
  { id: 'digitalocean', label: 'DigitalOcean', host: 'status.digitalocean.com' },
  { id: 'dropbox', label: 'Dropbox', host: 'status.dropbox.com' },
  { id: 'coinbase', label: 'Coinbase', host: 'status.coinbase.com' },
  { id: 'datadog', label: 'Datadog', host: 'status.datadoghq.com' },
  { id: 'sendgrid', label: 'SendGrid', host: 'status.sendgrid.com' },
]);

export const summaryUrl = (host) => `https://${host}/api/v2/summary.json`;

const str = (v) => (v == null ? '' : String(v).trim());

// statuspage.io indicator → our severity bucket (0 ok … 3 critical).
const INDICATOR_RANK = { none: 0, minor: 1, major: 2, critical: 3 };
const COMPONENT_DOWN = new Set(['degraded_performance', 'partial_outage', 'major_outage']);
const COMPONENT_WORD = {
  degraded_performance: 'degraded',
  partial_outage: 'partial outage',
  major_outage: 'major outage',
};

/** One provider's /api/v2/summary.json → a normalized status record. Pure. */
export function parseSummary(payload, provider = {}) {
  const page = payload?.page || {};
  const status = payload?.status || {};
  const indicator = INDICATOR_RANK[str(status.indicator)] != null ? str(status.indicator) : 'none';

  const down = [];
  for (const c of Array.isArray(payload?.components) ? payload.components : []) {
    if (c?.group) continue; // skip the parent group rows
    if (COMPONENT_DOWN.has(str(c?.status))) {
      down.push({ name: str(c.name), status: str(c.status), word: COMPONENT_WORD[str(c.status)] || 'issue' });
    }
  }

  const incidents = [];
  for (const i of Array.isArray(payload?.incidents) ? payload.incidents : []) {
    const st = str(i?.status);
    if (st === 'resolved' || st === 'completed' || st === 'postmortem') continue;
    incidents.push({
      name: str(i.name),
      impact: str(i.impact) || 'none',
      status: st,
      url: /^https?:\/\//.test(str(i.shortlink)) ? str(i.shortlink) : '',
      updatedAt: str(i.updated_at) || null,
    });
  }

  return {
    id: provider.id || str(page.id),
    label: provider.label || str(page.name) || provider.id || 'Service',
    indicator,
    rank: INDICATOR_RANK[indicator] ?? 0,
    description: str(status.description) || 'Status unknown',
    url: /^https?:\/\//.test(str(page.url)) ? str(page.url) : `https://${provider.host || ''}`,
    updatedAt: str(page.updated_at) || null,
    down,
    incidents,
  };
}

/** Bucket a record: 'down' (critical/major), 'degraded' (minor/any issue) or 'ok'. */
export function bucketOf(rec) {
  if (rec.rank >= 2) return 'down';
  if (rec.rank === 1 || rec.down.length || rec.incidents.length) return 'degraded';
  return 'ok';
}

/** A plain-English one-liner for a provider's current state. */
export function plainStatus(rec) {
  const bucket = bucketOf(rec);
  if (bucket === 'ok') return `${rec.label}: all systems operational.`;
  if (rec.incidents.length) {
    const top = rec.incidents[0];
    return `${rec.label}: ${top.name || rec.description}.`;
  }
  if (rec.down.length) {
    const first = rec.down[0];
    const more = rec.down.length > 1 ? ` (+${rec.down.length - 1} more)` : '';
    return `${rec.label}: ${first.word} on ${first.name}${more}.`;
  }
  return `${rec.label}: ${rec.description}.`;
}

/**
 * Fold the parsed records into one ranked board.
 * @returns {{at, providers: object[], summary: {down, degraded, ok, total}}}
 */
export function assembleServiceStatus({ records = [], now = Date.now() } = {}) {
  const providers = records
    .filter(Boolean)
    .map((rec) => ({ ...rec, bucket: bucketOf(rec), plain: plainStatus(rec) }))
    .sort(
      (a, b) =>
        b.rank - a.rank ||
        b.incidents.length - a.incidents.length ||
        b.down.length - a.down.length ||
        a.label.localeCompare(b.label),
    );
  const summary = { down: 0, degraded: 0, ok: 0, total: providers.length };
  for (const p of providers) summary[p.bucket] += 1;
  return { at: now, providers, summary };
}
