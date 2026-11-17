/**
 * Ananzi FANGS — vulnerability prioritization (CySA+ style).
 *
 * The AI-security feed hands us a flat list of vulnerabilities (CISA KEV +
 * GHSA advisories). A long list is not a plan, so this ranks them the way a
 * CySA+ analyst triages a patch queue: what is being exploited RIGHT NOW
 * outranks what is merely severe. The score is transparent — every point is
 * traceable to a named factor shown on the card — so the reasoning is
 * auditable, not a black box.
 *
 * Inputs are only the honest fields the feed actually carries
 * (exploited='kev', ransomware, cvss, severity, dueDate). We do NOT invent an
 * EPSS number the sources never gave us; active-exploitation status (KEV) is
 * the real-world signal EPSS is a proxy for, and we have it directly.
 *
 * Pure + unit-tested (vulnPriority.test.mjs); the renderer lives in
 * src/anansi/vulnScorecard.js.
 */

/** Severity → base points when no numeric CVSS is published. */
const SEVERITY_BASE = { critical: 90, high: 70, medium: 40, low: 15 };

/** Point weights for each prioritization factor (order = display order). */
const WEIGHT = {
  kev: 120, // actively exploited in the wild — the dominant signal
  ransomware: 60, // tied to ransomware campaigns
  overdue: 40, // CISA remediation deadline already passed
  dueSoon: 20, // deadline within a week
};

const DAY_MS = 86_400_000;

function baseScore(v) {
  if (Number.isFinite(v?.cvss) && v.cvss > 0) return Math.round(v.cvss * 10);
  return SEVERITY_BASE[String(v?.severity || '').toLowerCase()] ?? 30;
}

function dueUrgency(v, nowMs) {
  const due = v?.dueDate ? Date.parse(v.dueDate) : NaN;
  if (!Number.isFinite(due)) return { points: 0, overdue: false, dueSoon: false };
  const daysLeft = Math.ceil((due - nowMs) / DAY_MS);
  if (daysLeft <= 0) return { points: WEIGHT.overdue, overdue: true, dueSoon: false, daysLeft };
  if (daysLeft <= 7) return { points: WEIGHT.dueSoon, overdue: false, dueSoon: true, daysLeft };
  return { points: 0, overdue: false, dueSoon: false, daysLeft };
}

/**
 * Score one vulnerability. Higher = patch sooner.
 * @returns {{score, band, bandLabel, factors: string[], action: string}}
 */
export function scoreVuln(v, { now = Date.now() } = {}) {
  const nowMs = typeof now === 'number' ? now : Date.parse(now);
  const kev = v?.exploited === 'kev';
  const factors = [];
  let score = baseScore(v);

  if (kev) {
    score += WEIGHT.kev;
    factors.push('Actively exploited (CISA KEV)');
  }
  if (v?.ransomware) {
    score += WEIGHT.ransomware;
    factors.push('Used in ransomware campaigns');
  }
  const due = dueUrgency(v, nowMs);
  score += due.points;
  if (due.overdue) factors.push(`Fix overdue${v.dueDate ? ` (was due ${v.dueDate})` : ''}`);
  else if (due.dueSoon) factors.push(`Fix due within a week${v.dueDate ? ` (${v.dueDate})` : ''}`);

  if (Number.isFinite(v?.cvss) && v.cvss > 0) factors.push(`CVSS ${v.cvss.toFixed(1)}`);
  else if (v?.severity) factors.push(`Severity: ${v.severity}`);

  // Bands: P1 patch now, P2 this cycle, P3 track. KEV always lands P1.
  const band = score >= 150 ? 'P1' : score >= 80 ? 'P2' : 'P3';
  const bandLabel = band === 'P1' ? 'Patch now' : band === 'P2' ? 'This cycle' : 'Track';

  const action =
    v?.action ||
    (v?.fixed ? `Update to ${v.fixed}.` : kev ? 'Patch immediately or isolate the system.' : 'Patch when a fix ships.');

  return { score, band, bandLabel, factors, action };
}

/**
 * Rank a vuln list hottest-first and attach the scorecard fields.
 * Ties break by newest first, then by id for stability.
 * @returns {Array<object & {score, band, bandLabel, factors, action}>}
 */
export function rankVulns(vulns = [], { now = Date.now(), limit = 8 } = {}) {
  const scored = (vulns || [])
    .filter(Boolean)
    .map((v) => ({ ...v, ...scoreVuln(v, { now }) }));
  scored.sort(
    (a, b) =>
      b.score - a.score ||
      String(b.date || '').localeCompare(String(a.date || '')) ||
      String(a.id || '').localeCompare(String(b.id || '')),
  );
  return scored.slice(0, limit);
}

/** Count how many land in each band (for the header tally). */
export function bandCounts(ranked = []) {
  const counts = { P1: 0, P2: 0, P3: 0 };
  for (const r of ranked) if (counts[r.band] != null) counts[r.band] += 1;
  return counts;
}
