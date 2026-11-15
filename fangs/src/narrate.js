// Plain-English event narration. The deterministic generator ALWAYS runs first and is always the fallback;
// an optional fast free LLM (Groq or Cerebras, OpenAI-compatible) may upgrade the wording and suggest ATT&CK IDs.
// API keys are read from the server environment only and never leave this module. LLM techniques are kept
// only if they validate against the bundled STIX.
import { famLabel } from './util.js';

const KIND_TEXT = {
  c2: 'command-and-control server',
  botnet: 'botnet command-and-control server',
  'malware-url': 'malware-distribution URL',
  phish: 'phishing page',
  scan: 'internet scanner',
};
const SRC_LABEL = { c2intel: 'C2IntelFeeds', feodo: 'Feodo Tracker', threatfox: 'ThreatFox', urlhaus: 'URLhaus', openphish: 'OpenPhish', dshield: 'DShield', radar: 'Cloudflare Radar', greynoise: 'GreyNoise', otx: 'AlienVault OTX' };
export const srcLabel = (s) => SRC_LABEL[s] || s;

export function deterministicNarrative(ev, ctx = {}) {
  const fam = ev.family ? famLabel(ev.family) : null;
  const what = KIND_TEXT[ev.kind] || 'suspicious indicator';
  const srcs = [...new Set(ev.sources.map((s) => srcLabel(s.source)))];
  const parts = [];
  parts.push(`${fam ? `${fam} ` : ''}${what} ${ev.indicator.length > 70 ? ev.indicator.slice(0, 67) + '…' : ev.indicator} was reported by ${srcs.length === 1 ? srcs[0] : `${srcs.length} sources (${srcs.join(', ')})`}.`);
  if (ctx.asn) parts.push(`It is announced from ${ctx.asn}${ctx.cc ? ` (${ctx.cc})` : ''}${ctx.asnPeers > 0 ? `, alongside ${ctx.asnPeers} other tracked ${ctx.asnPeers === 1 ? 'host' : 'hosts'}` : ''}.`);
  if (ctx.communitySize > 1) parts.push(`It falls in a cluster of ${ctx.communitySize} linked entities${ctx.communityFamily ? `, mostly tied to ${famLabel(ctx.communityFamily)}` : ''}.`);
  const s = ev.score;
  if (s) {
    const why = [];
    if (s.components.kev) why.push('a linked CVE is on the CISA KEV list');
    else if (ev.cve.length) why.push(`it references ${ev.cve.join(', ')} (not in the KEV list we hold)`);
    if (s.components.epss > 0) why.push(`EPSS ${(s.components.epss * 100).toFixed(0)}%`);
    if (s.components.corroboration > 0) why.push(`confirmed by more than one source`);
    if (!ev.cve.length) why.push('no linked CVE, so vulnerability evidence adds nothing');
    parts.push(`Severity ${s.score} (${s.band}): ${why.join('; ')}.${s.basis === 'fixture' ? ' KEV/EPSS values are sample data in this run.' : ''}`);
  }
  if (ev.attack.length) parts.push(`Likely ATT&CK behaviour: ${ev.attack.slice(0, 3).map((t) => `${t.name} (${t.id})`).join(', ')}.`);
  parts.push('Defensive action: block or monitor the indicator and review logs for contact with it; this board does not probe it.');
  return { text: parts.join(' '), basis: 'deterministic' };
}

// ---- LLM upgrade (optional) ----
const PROVIDERS = [
  { name: 'groq', keyEnv: 'GROQ_API_KEY', modelEnv: 'GROQ_MODEL', defaultModel: 'llama-3.1-8b-instant', url: 'https://api.groq.com/openai/v1/chat/completions' },
  { name: 'cerebras', keyEnv: 'CEREBRAS_API_KEY', modelEnv: 'CEREBRAS_MODEL', defaultModel: 'llama3.1-8b', url: 'https://api.cerebras.ai/v1/chat/completions' },
];

export function configuredProviders(env = process.env) {
  return PROVIDERS.filter((p) => env[p.keyEnv]).map((p) => ({ ...p, model: env[p.modelEnv] || p.defaultModel, key: env[p.keyEnv] }));
}

function buildPrompt(ev, ctx) {
  const facts = { kind: ev.kind, family: ev.family, indicator: ev.indicator, sources: ev.sources.map((s) => srcLabel(s.source)), cves: ev.cve, severity: ev.score && { score: ev.score.score, band: ev.score.band },
    asn: ctx.asn || null, country: ctx.cc || null, cluster_size: ctx.communitySize || null };
  return [
    { role: 'system', content: 'You are a SOC dispatcher assistant for defensive awareness. Use ONLY the facts provided; never invent CVEs, victims or attribution. No offensive instructions. Reply with JSON only: {"summary": "<=55 words plain English", "techniques": ["T####" or "T####.###" ids of MITRE ATT&CK Enterprise techniques the behaviour suggests, max 4]}.' },
    { role: 'user', content: JSON.stringify(facts) },
  ];
}

export function parseLlmJson(text) {
  if (typeof text !== 'string') return null;
  const m = /\{[\s\S]*\}/.exec(text);
  if (!m) return null;
  try {
    const j = JSON.parse(m[0]);
    const summary = typeof j.summary === 'string' ? j.summary.trim().replace(/\s+/g, ' ').slice(0, 600) : '';
    const techniques = Array.isArray(j.techniques) ? j.techniques.filter((t) => typeof t === 'string' && /^T\d{4}(\.\d{3})?$/i.test(t.trim())).map((t) => t.trim().toUpperCase()) : [];
    return summary ? { summary, techniques } : null;
  } catch { return null; }
}

// Returns {narrative, techniques[], provider, model, rejected[]} or null when no provider answers (caller keeps deterministic).
export async function llmNarrate(ev, ctx, { env = process.env, fetchFn = fetch, timeoutMs = 2500, catalog } = {}) {
  for (const p of configuredProviders(env)) {
    try {
      const res = await fetchFn(p.url, {
        method: 'POST', headers: { authorization: `Bearer ${p.key}`, 'content-type': 'application/json' },
        body: JSON.stringify({ model: p.model, messages: buildPrompt(ev, ctx), temperature: 0.2, max_tokens: 220, response_format: { type: 'json_object' } }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) continue;
      const j = await res.json();
      const parsed = parseLlmJson(j?.choices?.[0]?.message?.content);
      if (!parsed) continue;
      const v = catalog ? catalog.validate(parsed.techniques) : { valid: [], invalid: parsed.techniques };
      return { narrative: { text: parsed.summary, basis: 'llm', provider: p.name, model: p.model }, techniques: v.valid, rejected: v.invalid, provider: p.name };
    } catch { /* try next provider, then fall back */ }
  }
  return null;
}
