/**
 * Ananzi FANGS — incident correlation (event reconstruction).
 *
 * Takes the live signal stream FANGS already produces (attack-map alerts,
 * cyber-news, service outages, exploited vulns) and clusters the signals into
 * *incidents*: groups that share an adversary, an ATT&CK tactic and a time
 * window. Each incident is reconstructed into the frameworks FANGS already
 * computes per event — a Cyber Kill Chain (which phases were observed), the
 * techniques seen, the Pyramid-of-Pain high-water mark, the infrastructure,
 * and an aggregate intelligence-confidence.
 *
 * Honest by construction: this is correlation by co-occurrence, not confirmed
 * attribution. Every surface that shows an incident shows RECON_DISCLAIMER.
 *
 * Pure + unit-tested (incidentCorrelation.test.mjs). The timeline, graph,
 * narrative and campaign views all build on the incidents this returns.
 */
import { ttpFor } from './attackTtp.js';
import { killChainPhase, pyramidLevel, confidenceOf, KILL_CHAIN } from './analystFrames.js';

export const RECON_DISCLAIMER =
  'Correlated from public signals by shared actor, technique and time. A hypothesis, not confirmed attribution — co-occurrence is not causation.';

const str = (v) => (v == null ? '' : String(v).trim());
const toMs = (t) => (typeof t === 'number' ? t : Date.parse(t));
const CONF_SCORE = { High: 2, Medium: 1, Low: 0 };
const CONF_LABEL = (s) => (s >= 1.5 ? 'High' : s >= 0.75 ? 'Medium' : 'Low');

const KIND_LABEL = {
  ransomware: 'Ransomware', ddos: 'Denial-of-service', phishing: 'Phishing',
  c2: 'C2 activity', malware: 'Malware', exploit: 'Exploitation', breach: 'Data breach',
  hijack: 'Route hijack', botnet: 'Botnet', bruteforce: 'Brute-forcing',
  scanning: 'Scanning', exposure: 'Exposure',
};

// Country names an adversary is commonly reported under → ISO-2 (used only when
// a signal carries no country of its own; deliberately small and explicit).
const COUNTRY_WORDS = Object.freeze([
  [/\brussian?\b|\bmoscow\b/i, 'RU'], [/\bchinese?\b|\bbeijing\b/i, 'CN'],
  [/\biran(ian)?\b|\btehran\b/i, 'IR'], [/\bnorth\s*korea|\bdprk\b|lazarus/i, 'KP'],
  [/\bukrain/i, 'UA'], [/\bbrazil/i, 'BR'], [/\bindia\b/i, 'IN'],
  [/\bvietnam/i, 'VN'], [/\bnigeria/i, 'NG'], [/\bpakistan/i, 'PK'],
]);
function guessCountry(text) {
  for (const [re, cc] of COUNTRY_WORDS) if (re.test(text)) return cc;
  return '';
}

/**
 * Normalize a loose feed signal into the canonical event the engine clusters.
 * Accepts {title, text|plain|summary, source, time, country, ip, asn, malware,
 * cve, layerId, url|link, id}. Everything is derived; nothing is invented.
 */
export function toEvent(raw = {}, { now = Date.now() } = {}) {
  // Idempotent: an already-normalized event passes straight through, so callers
  // can normalize once and still hand the result to correlateIncidents.
  if (raw && raw.technique && raw.killChain && Number.isFinite(raw.timeMs)) return raw;
  const title = str(raw.title);
  const text = `${title} ${str(raw.text || raw.plain || raw.summary)}`.trim();
  const timeMs = Number.isFinite(toMs(raw.time)) ? toMs(raw.time) : now;
  const country = str(raw.country).toUpperCase().slice(0, 2) || guessCountry(text);
  const ttp = ttpFor(raw.layerId, text);
  const kc = killChainPhase(ttp.kind);
  const pyr = pyramidLevel(ttp.kind);
  const conf = confidenceOf(
    { source: str(raw.source), time: new Date(timeMs).toISOString(), title, place: country },
    { now },
  );
  return {
    id: str(raw.id) || `${ttp.kind}:${timeMs}:${title.slice(0, 24)}`,
    title,
    text,
    source: str(raw.source) || 'unknown',
    timeMs,
    kind: ttp.kind,
    technique: ttp.technique,
    killChain: kc,
    pyramid: pyr,
    confidence: conf.level,
    adversary: country || 'Unknown',
    ip: str(raw.ip),
    asn: raw.asn ? `AS${String(raw.asn).replace(/^AS/i, '')}` : '',
    malware: str(raw.malware),
    cve: str(raw.cve) || (text.match(/CVE-\d{4}-\d{4,7}/i)?.[0] || '').toUpperCase(),
    url: str(raw.url || raw.link),
  };
}

/**
 * Flatten the live FANGS snapshots into the raw signal stream the engine
 * clusters. Pure field-mapping; nothing is invented.
 * @param {{attack?,cyber?,ai?,service?}} snapshots
 */
export function collectReconEvents({ attack = null, cyber = null, ai = null, service = null } = {}) {
  const events = [];
  for (const a of attack?.alerts || []) {
    events.push({ title: a.title, text: `${a.plain || ''} ${a.technical || ''}`, source: a.source, time: a.time, url: a.link });
  }
  for (const s of attack?.sources || []) {
    events.push({
      title: `${s.name} — attack source`,
      text: `${s.dominantService || ''} attacks`,
      source: 'DShield',
      time: null,
      country: s.country,
      ip: s.ips?.[0]?.ip || '',
      layerId: 'cyber-attack-map',
    });
  }
  for (const it of cyber?.items || []) {
    events.push({ title: it.title, text: `${it.plain || ''} ${it.summary || ''}`, source: it.source, time: it.date, url: it.url });
  }
  for (const v of ai?.vulns || []) {
    events.push({ title: v.title, text: v.title, source: 'CISA KEV', time: v.date, cve: v.id, layerId: 'vuln', malware: v.ransomware ? 'ransomware' : '' });
  }
  const svcTime = service?.at ? new Date(service.at).toISOString() : null;
  for (const p of service?.providers || []) {
    if (p.bucket === 'ok') continue;
    events.push({ title: `${p.label} — ${p.bucket}`, text: p.plain || p.description || '', source: p.label, time: svcTime });
  }
  return events;
}

function startIncident(ev) {
  const inc = {
    adversary: ev.adversary,
    startMs: ev.timeMs,
    endMs: ev.timeMs,
    events: [],
    _tech: new Map(),
    _phases: new Set(),
    _sources: new Set(),
    _infra: new Set(),
    _cves: new Set(),
    _malware: new Set(),
    _kinds: new Map(),
    _confSum: 0,
    _pyramidMax: 0,
    _pyramidLevel: '',
    _pyramidPain: '',
  };
  addToIncident(inc, ev);
  return inc;
}

function addToIncident(inc, ev) {
  inc.events.push(ev);
  inc.startMs = Math.min(inc.startMs, ev.timeMs);
  inc.endMs = Math.max(inc.endMs, ev.timeMs);
  inc._tech.set(ev.technique.id, ev.technique);
  inc._phases.add(ev.killChain.index);
  inc._sources.add(ev.source);
  if (ev.ip) inc._infra.add(ev.ip);
  if (ev.asn) inc._infra.add(ev.asn);
  if (ev.cve) inc._cves.add(ev.cve);
  if (ev.malware) inc._malware.add(ev.malware);
  inc._kinds.set(ev.kind, (inc._kinds.get(ev.kind) || 0) + 1);
  inc._confSum += CONF_SCORE[ev.confidence] ?? 0;
  if (ev.pyramid.rank > inc._pyramidMax) {
    inc._pyramidMax = ev.pyramid.rank;
    inc._pyramidLevel = ev.pyramid.level;
    inc._pyramidPain = ev.pyramid.pain;
  }
}

function finalize(inc) {
  const n = inc.events.length;
  const avg = n ? inc._confSum / n : 0;
  const distinct = inc._sources.size;
  // Corroboration lifts confidence: more independent sources, more signals.
  const boost = (distinct >= 3 ? 0.4 : distinct >= 2 ? 0.2 : 0) + (n >= 5 ? 0.3 : n >= 3 ? 0.15 : 0);
  const score = Math.min(2, avg + boost);
  const killChain = [...inc._phases].sort((a, b) => a - b).map((i) => ({ index: i, name: KILL_CHAIN[i - 1] }));
  const furthestPhase = killChain[killChain.length - 1] || null;
  const dominantKind = [...inc._kinds.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || 'activity';
  const out = {
    adversary: inc.adversary,
    startMs: inc.startMs,
    endMs: inc.endMs,
    eventCount: n,
    confidence: CONF_LABEL(score),
    score: Math.round(score * 100) / 100,
    killChain,
    killChainCoverage: killChain.length, // of 7
    furthestPhase,
    techniques: [...inc._tech.values()],
    pyramidTop: inc._pyramidLevel ? { level: inc._pyramidLevel, pain: inc._pyramidPain, rank: inc._pyramidMax } : null,
    sources: [...inc._sources],
    infrastructure: [...inc._infra],
    cves: [...inc._cves],
    malware: [...inc._malware],
    dominantKind,
    events: inc.events,
  };
  out.title = incidentTitle(out);
  out.id = `inc:${out.adversary}:${out.furthestPhase?.index || 0}:${out.startMs}`;
  return out;
}

function incidentTitle(inc) {
  const kind = KIND_LABEL[inc.dominantKind] || inc.dominantKind;
  const who = inc.adversary && inc.adversary !== 'Unknown' ? ` from ${inc.adversary}` : '';
  const reach = inc.furthestPhase ? ` · reached ${inc.furthestPhase.name}` : '';
  return `${kind}${who} — ${inc.eventCount} signal${inc.eventCount === 1 ? '' : 's'}${reach}`;
}

/**
 * Cluster raw signals into ranked incidents.
 * Events sharing an adversary + ATT&CK tactic that fall within `windowMs` of the
 * running cluster are merged; a longer gap starts a new incident.
 * @returns {Array<object>} incidents, strongest first
 */
export function correlateIncidents(rawEvents = [], { now = Date.now(), windowMs = 24 * 3_600_000, limit = 12 } = {}) {
  const events = (rawEvents || [])
    .filter(Boolean)
    .map((e) => toEvent(e, { now }))
    .sort((a, b) => a.timeMs - b.timeMs);

  const open = new Map(); // signature -> incident being accumulated
  const all = [];
  for (const ev of events) {
    const sig = `${ev.adversary}|${ev.technique.tacticId || ev.kind}`;
    const cur = open.get(sig);
    if (cur && ev.timeMs - cur.endMs <= windowMs) {
      addToIncident(cur, ev);
    } else {
      const inc = startIncident(ev);
      open.set(sig, inc);
      all.push(inc);
    }
  }

  const incidents = all.map(finalize);
  incidents.sort(
    (a, b) =>
      b.score - a.score ||
      b.killChainCoverage - a.killChainCoverage ||
      b.endMs - a.endMs ||
      b.eventCount - a.eventCount,
  );
  return incidents.slice(0, limit);
}
