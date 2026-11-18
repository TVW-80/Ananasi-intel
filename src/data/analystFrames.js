/**
 * Ananzi FANGS — analyst frames for a single event: the CySA+ lenses an analyst
 * (and anyone studying for it) applies on top of ATT&CK and the Diamond Model.
 *
 *  - Cyber Kill Chain (Lockheed Martin): which of the 7 phases the activity is at.
 *  - Pyramid of Pain (David Bianco): how painful the indicator is for the
 *    adversary to change — hashes are trivial, TTPs are brutal.
 *  - Intelligence confidence (Timeliness · Relevance · Accuracy): how much to
 *    trust the event, the way CySA+ scores threat intel.
 *
 * All pure; the activity "kind" comes from attackTtp.classifyKind. Unit-tested
 * in analystFrames.test.mjs.
 */

/** Lockheed Martin Cyber Kill Chain, phases 1→7. */
export const KILL_CHAIN = Object.freeze([
  'Reconnaissance',
  'Weaponization',
  'Delivery',
  'Exploitation',
  'Installation',
  'Command & Control',
  'Actions on Objectives',
]);

const KIND_TO_PHASE = Object.freeze({
  scanning: 1, exposure: 1,
  phishing: 3, malware: 3,
  bruteforce: 4, exploit: 4,
  botnet: 5,
  c2: 6, hijack: 6,
  ddos: 7, ransomware: 7, breach: 7,
});

/** Where this activity sits on the Kill Chain. @returns {{index:number,name:string}} */
export function killChainPhase(kind) {
  const index = KIND_TO_PHASE[kind] || 1;
  return { index, name: KILL_CHAIN[index - 1] };
}

/** Pyramid of Pain levels, 1 (trivial to change) → 6 (brutal). */
export const PYRAMID = Object.freeze([
  { rank: 1, level: 'Hash Values', pain: 'Trivial — a one-byte change gives a new hash.' },
  { rank: 2, level: 'IP Addresses', pain: 'Easy — the adversary rotates IPs in seconds.' },
  { rank: 3, level: 'Domain Names', pain: 'Simple — a new domain is cheap to register.' },
  { rank: 4, level: 'Network / Host Artifacts', pain: 'Annoying — they must change tooling to avoid these.' },
  { rank: 5, level: 'Tools', pain: 'Challenging — they must find or build new tools.' },
  { rank: 6, level: 'TTPs', pain: 'Tough — this forces them to re-learn how they operate.' },
]);

const KIND_TO_PYRAMID = Object.freeze({
  scanning: 2, ddos: 2, bruteforce: 2,
  phishing: 3, c2: 3,
  botnet: 4, exposure: 4,
  malware: 5,
  exploit: 6, hijack: 6, ransomware: 6, breach: 6,
});

/** Pyramid-of-Pain level for this activity. @returns {{rank,level,pain}} */
export function pyramidLevel(kind) {
  return PYRAMID[(KIND_TO_PYRAMID[kind] || 2) - 1];
}

/* ── intelligence confidence (Timeliness · Relevance · Accuracy) ──────────── */

// Sources FANGS trusts most (abuse.ch, CISA, government, big infra providers).
const HIGH_SOURCE = /abuse\.ch|threatfox|urlhaus|feodo|sslbl|cisa|kev|dshield|sans|cloudflare|openphish|shodan|greynoise|abuseipdb|otx|alienvault/i;
// Close-to-home / critical-infrastructure relevance.
const RELEVANCE_RE = /\b(united\s+states|u\.?s\.?|america|federal|critical\s+infrastructure|hospital|power\s+grid|water|911|virginia|hampton\s+roads|norfolk|newport\s+news)\b/i;

const SCORE = { high: 2, medium: 1, low: 0 };
const LABEL = (s) => (s >= 1.5 ? 'High' : s >= 0.75 ? 'Medium' : 'Low');

/**
 * Score an event's intelligence confidence the CySA+ way.
 * @returns {{level:'High'|'Medium'|'Low', timeliness, relevance, accuracy}}
 */
export function confidenceOf({ source = '', time = null, title = '', place = '' } = {}, { now = Date.now() } = {}) {
  const ageMs = time ? now - Date.parse(time) : NaN;
  const timeliness = !Number.isFinite(ageMs)
    ? 'low'
    : ageMs < 24 * 3_600_000 ? 'high' : ageMs < 7 * 86_400_000 ? 'medium' : 'low';
  const text = `${title} ${place}`;
  const relevance = RELEVANCE_RE.test(text) ? 'high' : place ? 'medium' : 'low';
  const accuracy = HIGH_SOURCE.test(source) ? 'high' : source ? 'medium' : 'low';
  const avg = (SCORE[timeliness] + SCORE[relevance] + SCORE[accuracy]) / 3;
  return { level: LABEL(avg), timeliness, relevance, accuracy };
}
