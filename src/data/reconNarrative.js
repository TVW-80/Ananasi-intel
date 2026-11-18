/**
 * Ananzi FANGS — RECON narrative + case-file export (pure).
 *
 * narrate(): a plain-English "what the last window looks like" brief built
 * deterministically from the correlated incidents (no model required; a free-LLM
 * pass can refine it later without changing this contract).
 * caseFile(): a Markdown case file for one incident — timeline, ATT&CK, kill
 * chain, infrastructure — the exportable reconstruction.
 */
import { RECON_DISCLAIMER } from './incidentCorrelation.js';
import { KILL_CHAIN } from './analystFrames.js';

const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);
const whenUTC = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + 'Z';

/** A compact human summary of the whole incident set. */
export function narrate(incidents = [], { now = Date.now() } = {}) {
  const list = (incidents || []).filter(Boolean);
  if (!list.length) return 'No correlated incidents in the current window. Signals are rolling in individually.';
  const signals = list.reduce((s, i) => s + (i.eventCount || 0), 0);
  const actors = [...new Set(list.map((i) => i.adversary).filter((a) => a && a !== 'Unknown'))];
  const high = list.filter((i) => i.confidence === 'High');
  const lead = list[0];
  const parts = [];
  parts.push(
    `${list.length} correlated incident${list.length === 1 ? '' : 's'} from ${signals} signal${signals === 1 ? '' : 's'}` +
      (actors.length ? `, implicating ${actors.slice(0, 4).join(', ')}${actors.length > 4 ? ` +${actors.length - 4}` : ''}` : '') +
      '.',
  );
  if (lead) {
    const reach = lead.furthestPhase ? ` reaching ${lead.furthestPhase.name} on the kill chain` : '';
    parts.push(
      `Highest-priority: ${lead.title} (${lead.confidence} confidence)${reach}` +
        (lead.sources?.length ? `, corroborated by ${lead.sources.length} source${lead.sources.length === 1 ? '' : 's'}` : '') +
        '.',
    );
  }
  if (high.length) parts.push(`${high.length} incident${high.length === 1 ? '' : 's'} rated High confidence.`);
  return parts.join(' ');
}

/** A Markdown case file for one incident — the exportable reconstruction. */
export function caseFile(incident) {
  if (!incident) return '';
  const i = incident;
  const lines = [];
  lines.push(`# Incident — ${i.title}`, '');
  lines.push(`- **Confidence:** ${i.confidence} (${i.score})`);
  lines.push(`- **Window:** ${whenUTC(i.startMs)} → ${whenUTC(i.endMs)}`);
  lines.push(`- **Adversary (hypothesis):** ${i.adversary}`);
  lines.push(`- **Signals:** ${i.eventCount} from ${(i.sources || []).length} source(s)`);
  if (i.pyramidTop) lines.push(`- **Pyramid of Pain high-water mark:** ${i.pyramidTop.level} — ${i.pyramidTop.pain}`);
  lines.push('');

  lines.push('## Cyber Kill Chain', '');
  const seen = new Set((i.killChain || []).map((p) => p.index));
  for (let idx = 1; idx <= KILL_CHAIN.length; idx++) {
    lines.push(`- [${seen.has(idx) ? 'x' : ' '}] ${idx}. ${KILL_CHAIN[idx - 1]}`);
  }
  lines.push('', `Kill-chain coverage: ${i.killChainCoverage}/7.`, '');

  if ((i.techniques || []).length) {
    lines.push('## MITRE ATT&CK', '');
    for (const t of i.techniques) lines.push(`- ${t.id} ${t.name} (${t.tacticName}) — https://attack.mitre.org/techniques/${t.id}/`);
    lines.push('');
  }
  if ((i.infrastructure || []).length) lines.push('## Infrastructure', '', ...i.infrastructure.map((x) => `- ${x}`), '');
  if ((i.cves || []).length) lines.push('## CVEs', '', ...i.cves.map((c) => `- ${c}`), '');
  if ((i.malware || []).length) lines.push('## Malware / families', '', ...i.malware.map((m) => `- ${m}`), '');

  lines.push('## Timeline (as reported)', '');
  for (const e of [...(i.events || [])].sort((a, b) => a.timeMs - b.timeMs)) {
    lines.push(`- ${whenUTC(e.timeMs)} · [${e.source}] ${e.title}`);
  }
  lines.push('', `> ${RECON_DISCLAIMER}`, '');
  return lines.join('\n');
}

/** Coverage percent helper (exported for the UI meter). */
export const killChainPercent = (incident) => pct(incident?.killChainCoverage || 0, 7);
