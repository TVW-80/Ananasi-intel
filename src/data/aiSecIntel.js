// src/data/aiSecIntel.js
//
// Pure normalization for the AI Security Intelligence panel: turns raw
// upstream payloads (CISA KEV, GitHub Security Advisories, Federal Register,
// RSS/Atom feeds) into one compact, source-linked snapshot. No I/O lives here —
// the dev-server proxy in vite.config.js fetches, this module shapes — so every
// rule below is unit-testable (aiSecIntel.test.mjs).
//
// Scope is deliberately an intelligence/education view: it reports what
// maintainers and public catalogs say. It never scans, validates exploits, or
// claims a PoC exists unless a source says so.

export const WINDOW_DAYS = 30;
/** Items older than this are dropped from the snapshot entirely. */
export const RETAIN_DAYS = 90;
export const NEW_WINDOW_MS = 86_400_000;
const DAY_MS = 86_400_000;

/** Packages queried against GitHub Security Advisories (`affects=`). */
export const GHSA_PACKAGES = Object.freeze([
  'torch', 'tensorflow', 'keras', 'transformers', 'huggingface-hub', 'onnx',
  'onnxruntime', 'langchain', 'langchain-core', 'langchain-community', 'langgraph',
  'langflow', 'llama-index', 'llama-cpp-python', 'vllm', 'mlflow', 'ray',
  'gradio', 'litellm', 'chromadb', 'open-webui', 'comfyui', 'flowise', 'n8n',
  'ollama', 'mcp', '@modelcontextprotocol/sdk', 'openai', 'anthropic',
]);

/** Matched against vendor/product/name AND description. */
const STRONG_AI_RE = new RegExp(
  '\\b(?:pytorch|tensorflow|keras|scikit-learn|langchain|langgraph|langflow|'
  + 'llama[\\s._-]?index|llama\\.cpp|llama-cpp|ollama|vllm|mlflow|kubeflow|comfyui|'
  + 'open[\\s-]?webui|gradio|hugging\\s?face|onnx(?:runtime)?|triton inference|'
  + 'nvidia nemo|openai|anthropic|chatgpt|copilot|flowise|litellm|autogpt|'
  + 'model context protocol|artificial intelligence|machine learning|'
  + 'large language models?|generative ai|ai agents?|ai assistant|ai/ml|llms?|'
  + 'inference server|model serving)\\b',
  'i',
);
/** Ambiguous short names — only trusted against vendor/product, not prose. */
const PRODUCT_ONLY_AI_RE = /\b(?:ray|transformers|n8n|dify|mcp|chroma(?:db)?|langserve|bentoml|triton)\b/i;
const BARE_AI_RE = /\bAI\b/;

const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, unknown: 0 });

const ENTITIES = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' });

/** Decode entities, strip tags, collapse whitespace, truncate. */
export function cleanText(value, max = 280) {
  let text = String(value ?? '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, body) => {
      if (body[0] === '#') {
        const code = body[1] === 'x' || body[1] === 'X'
          ? Number.parseInt(body.slice(2), 16)
          : Number.parseInt(body.slice(1), 10);
        return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : '';
      }
      return ENTITIES[body.toLowerCase()] ?? match;
    })
    .replace(/\s+/g, ' ')
    .trim();
  if (text.length > max) text = `${text.slice(0, max - 1).trimEnd()}…`;
  return text;
}

/** GitHub advisory bodies are Markdown — flatten to plain prose before display. */
export function markdownToPlain(value, max = 320) {
  const flattened = String(value ?? '')
    .replace(/^\s*#{1,6}\s*(?:summary|description|overview|impact|details)\s*$/im, '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/^\s{0,3}#{1,6}\s*/gm, '')
    .replace(/^\s{0,3}>+\s?/gm, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[*`]+/g, '');
  return cleanText(flattened, max);
}

/** Only http(s) URLs may reach the DOM as links. */
export function safeUrl(value) {
  try {
    const url = new URL(String(value ?? '').trim());
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

function toMs(value) {
  const ms = Date.parse(String(value ?? ''));
  return Number.isFinite(ms) ? ms : null;
}

function isoDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Whether a CISA KEV entry concerns AI/ML software. */
export function isAiRelatedKev(entry) {
  const vendor = String(entry?.vendorProject ?? '');
  const product = String(entry?.product ?? '');
  const name = String(entry?.vulnerabilityName ?? '');
  const description = String(entry?.shortDescription ?? '');
  if (PRODUCT_ONLY_AI_RE.test(`${vendor} ${product}`)) return true;
  if (BARE_AI_RE.test(`${product} ${name}`)) return true;
  return STRONG_AI_RE.test(`${vendor} ${product} ${name} ${description}`);
}

/** CISA KEV → normalized vulnerability items (AI-related only). */
export function normalizeKev(json, { now = Date.now() } = {}) {
  const entries = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  const cutoff = now - RETAIN_DAYS * DAY_MS;
  const items = [];
  for (const entry of entries) {
    if (!entry?.cveID || !isAiRelatedKev(entry)) continue;
    const dateMs = toMs(entry.dateAdded);
    if (dateMs === null || dateMs < cutoff) continue;
    const ransomware = String(entry.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known';
    const evidence = [
      { label: 'CISA KEV', url: safeUrl(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(entry.cveID)}`) },
      { label: 'NVD', url: safeUrl(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(entry.cveID)}`) },
      ...String(entry.notes ?? '').split(';')
        .map((part) => safeUrl(part))
        .filter(Boolean)
        .slice(0, 3)
        .map((url) => ({ label: new URL(url).hostname.replace(/^www\./, ''), url })),
    ].filter((link) => link.url);
    items.push({
      id: entry.cveID,
      cve: entry.cveID,
      title: cleanText(entry.vulnerabilityName || entry.cveID, 140),
      vendor: cleanText(entry.vendorProject, 60),
      product: cleanText(entry.product, 60),
      severity: ransomware ? 'critical' : 'high',
      cvss: null,
      exploited: 'kev',
      ransomware,
      affected: null,
      fixed: null,
      summary: cleanText(entry.shortDescription, 320),
      action: cleanText(entry.requiredAction, 240),
      dueDate: entry.dueDate || null,
      dateMs,
      date: isoDay(dateMs),
      origin: 'cisa-kev',
      evidence,
    });
  }
  return items;
}

function ghsaSeverity(value) {
  const key = String(value ?? '').toLowerCase();
  return key in SEVERITY_RANK ? key : 'unknown';
}

/** GitHub Security Advisories (REST list) → normalized vulnerability items. */
export function normalizeGhsa(list, { now = Date.now() } = {}) {
  if (!Array.isArray(list)) return [];
  const cutoff = now - RETAIN_DAYS * DAY_MS;
  const items = [];
  for (const adv of list) {
    if (!adv?.ghsa_id || adv.withdrawn_at) continue;
    const dateMs = toMs(adv.published_at);
    if (dateMs === null || dateMs < cutoff) continue;
    const vulns = Array.isArray(adv.vulnerabilities) ? adv.vulnerabilities : [];
    const packages = [...new Set(vulns.map((v) => v?.package?.name).filter(Boolean))];
    const affected = vulns
      .map((v) => (v?.package?.name && v?.vulnerable_version_range
        ? `${v.package.name} ${v.vulnerable_version_range}` : null))
      .filter(Boolean).slice(0, 4).join('; ') || null;
    const fixedList = vulns
      .map((v) => (v?.package?.name && v?.first_patched_version
        ? `${v.package.name} ${v.first_patched_version}` : null))
      .filter(Boolean).slice(0, 4);
    const fixed = fixedList.length ? fixedList.join('; ') : null;
    const cvss = Number.isFinite(adv?.cvss?.score) && adv.cvss.score > 0 ? adv.cvss.score : null;
    const htmlUrl = safeUrl(adv.html_url);
    items.push({
      id: adv.cve_id || adv.ghsa_id,
      cve: adv.cve_id || null,
      ghsa: adv.ghsa_id,
      title: cleanText(adv.summary || adv.ghsa_id, 140),
      vendor: '',
      product: cleanText(packages.join(', '), 80),
      severity: ghsaSeverity(adv.severity),
      cvss,
      exploited: 'unconfirmed',
      ransomware: false,
      affected,
      fixed,
      summary: markdownToPlain(adv.description, 320),
      action: fixed
        ? `Upgrade to a patched release: ${fixed}.`
        : 'No patched version is listed yet — apply maintainer mitigations and monitor the advisory.',
      dueDate: null,
      dateMs,
      date: isoDay(dateMs),
      origin: 'ghsa',
      evidence: [
        htmlUrl ? { label: adv.ghsa_id, url: htmlUrl } : null,
        adv.cve_id ? { label: 'NVD', url: safeUrl(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(adv.cve_id)}`) } : null,
      ].filter((link) => link?.url),
    });
  }
  return items;
}

/** Merge KEV + GHSA entries sharing a CVE; KEV wins exploitation status. */
export function mergeVulns(...lists) {
  const byKey = new Map();
  for (const item of lists.flat()) {
    const key = item.cve || item.id;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...item, evidence: [...item.evidence] });
      continue;
    }
    const kev = existing.exploited === 'kev' ? existing : item.exploited === 'kev' ? item : null;
    const other = kev === existing ? item : existing;
    const merged = {
      ...(kev || existing),
      affected: existing.affected || item.affected,
      fixed: existing.fixed || item.fixed,
      cvss: existing.cvss ?? item.cvss,
      product: existing.product || item.product,
      ghsa: existing.ghsa || item.ghsa,
      severity: SEVERITY_RANK[existing.severity] >= SEVERITY_RANK[item.severity]
        ? existing.severity : item.severity,
      evidence: [],
    };
    if (kev && other.fixed) merged.action = `${kev.action} Patched release: ${other.fixed}.`;
    const seen = new Set();
    for (const link of [...existing.evidence, ...item.evidence]) {
      if (seen.has(link.url)) continue;
      seen.add(link.url);
      merged.evidence.push(link);
    }
    byKey.set(key, merged);
  }
  return [...byKey.values()].sort((a, b) => (
    (b.exploited === 'kev') - (a.exploited === 'kev')
    || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    || b.dateMs - a.dateMs
  ));
}

/**
 * The Federal Register `term` search is full-text, so it also returns orders
 * that merely mention AI in passing (veterans' benefits, power-grid
 * emergencies…). Keep only orders whose own title/abstract is about AI.
 */
const AI_POLICY_RE = new RegExp(
  '\\b(?:artificial intelligence|a\\.i\\.|ai|(?:super|general)\\s?intelligence|'
  + 'genesis mission|machine learning|frontier (?:ai|models?)|large language|data cent(?:er|re)s?|'
  + 'semiconductors?|compute)\\b',
  'i',
);

/** Federal Register executive-order search → AI policy items (newest first). */
export function normalizeFederalRegister(json) {
  const results = Array.isArray(json?.results) ? json.results : [];
  return results.map((doc) => {
    const dateMs = toMs(doc?.signing_date) ?? toMs(doc?.publication_date);
    const url = safeUrl(doc?.html_url);
    if (dateMs === null || !url) return null;
    if (!AI_POLICY_RE.test(`${doc?.title ?? ''} ${doc?.abstract ?? ''}`)) return null;
    const number = doc.executive_order_number ? String(doc.executive_order_number) : null;
    return {
      id: `eo-${number || doc.document_number || url}`,
      title: cleanText(doc.title, 180),
      number: number ? `EO ${number}` : null,
      summary: cleanText(doc.abstract, 320),
      dateMs,
      date: isoDay(dateMs),
      url,
      origin: 'federal-register',
    };
  }).filter(Boolean).sort((a, b) => b.dateMs - a.dateMs);
}

function tagText(body, name) {
  const escaped = name.replace(/[:.]/g, '\\$&');
  const match = body.match(new RegExp(`<${escaped}\\b[^>]*>([\\s\\S]*?)</${escaped}>`, 'i'));
  if (!match) return '';
  const inner = match[1].trim();
  const cdata = inner.match(/^<!\[CDATA\[([\s\S]*?)\]\]>$/);
  return cdata ? cdata[1] : inner;
}

/** Minimal RSS 2.0 / Atom parser — enough for headline feeds, no DOM needed. */
export function parseFeed(xml) {
  const text = String(xml ?? '');
  const items = [];
  for (const [, , body] of text.matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    let link = '';
    const hrefLinks = [...body.matchAll(/<link\b([^>]*?)\/?>/gi)]
      .map(([, attrs]) => ({
        href: attrs.match(/\bhref=["']([^"']+)["']/i)?.[1],
        rel: attrs.match(/\brel=["']([^"']+)["']/i)?.[1],
      }))
      .filter((l) => l.href);
    if (hrefLinks.length) {
      link = (hrefLinks.find((l) => !l.rel || l.rel === 'alternate') || hrefLinks[0]).href;
    } else {
      link = cleanText(tagText(body, 'link'), 500);
    }
    const dateRaw = tagText(body, 'pubDate') || tagText(body, 'published')
      || tagText(body, 'updated') || tagText(body, 'dc:date');
    items.push({
      title: cleanText(tagText(body, 'title'), 180),
      link: safeUrl(link.replaceAll('&amp;', '&')),
      dateMs: toMs(dateRaw),
      summary: cleanText(
        tagText(body, 'description') || tagText(body, 'summary') || tagText(body, 'content:encoded'),
        280,
      ),
    });
  }
  return items.filter((item) => item.title && item.link && item.dateMs !== null);
}

/** A named model family is enough on its own to mark a post as model news. */
const MODEL_FAMILY_RE = new RegExp(
  '\\b(?:gpt-?\\d[\\w.-]*|o[1-9](?:-\\w+)?|gemini|gemma|claude|llama|mistral|mixtral|'
  + 'qwen|deepseek|grok|sora|veo|imagen|codex|phi-?\\d|(?:latest )?ai (?:news|updates))\\b',
  'i',
);
/** Generic words ("model", "API") only count when paired with a release verb. */
const MODEL_GENERIC_RE = /\b(?:models?|api|open[- ]weights?)\b/i;
const MODEL_RELEASE_VERB_RE = /\b(?:introducing|launch(?:es|ed|ing)?|releas(?:e|es|ed|ing)|now available|new|deprecat\w*|retir\w*)\b/i;

/** "<Customer> does X faster with GPT-…" case studies name a model without releasing one. */
const CUSTOMER_STORY_RE = /\b(?:with|using|on|powered by)\s+(?:openai|chatgpt|gpt-?\d[\w.-]*|claude|gemini|codex)\b/i;

/** Whether a headline reads as a frontier-model or model-API change. */
export function isModelRelease(title) {
  const text = String(title ?? '');
  if (CUSTOMER_STORY_RE.test(text) && !MODEL_RELEASE_VERB_RE.test(text)) return false;
  return MODEL_FAMILY_RE.test(text)
    || (MODEL_GENERIC_RE.test(text) && MODEL_RELEASE_VERB_RE.test(text))
    || /\bdeprecat\w*\b/i.test(text);
}

/** Feed items → frontier-model / API change items. */
export function normalizeModelFeed(label, items, { now = Date.now() } = {}) {
  const cutoff = now - RETAIN_DAYS * DAY_MS;
  return items
    .filter((item) => item.dateMs >= cutoff && item.dateMs <= now + DAY_MS
      && isModelRelease(item.title))
    .map((item) => ({
      id: item.link,
      title: item.title,
      source: label,
      summary: item.summary,
      dateMs: item.dateMs,
      date: isoDay(item.dateMs),
      url: item.link,
    }));
}

/** Feed items → AI-security research/incident/tooling items. */
export function normalizeResearchFeed(label, items, { now = Date.now(), limit = 10 } = {}) {
  const cutoff = now - RETAIN_DAYS * DAY_MS;
  return items
    .filter((item) => item.dateMs >= cutoff && item.dateMs <= now + DAY_MS)
    .sort((a, b) => b.dateMs - a.dateMs)
    .slice(0, limit)
    .map((item) => ({
      id: item.link,
      title: item.title,
      source: label,
      summary: item.summary,
      dateMs: item.dateMs,
      date: isoDay(item.dateMs),
      url: item.link,
    }));
}

/**
 * Stamp each item with `firstSeenMs` / `isNew`. On a first run (no history)
 * an item's own date stands in for "first seen" so nothing falsely reads NEW.
 */
export function applyFirstSeen(items, history, now, firstRun) {
  const nextHistory = {};
  const stamped = items.map((item) => {
    const firstSeenMs = history?.[item.id] ?? (firstRun ? item.dateMs : now);
    nextHistory[item.id] = firstSeenMs;
    return { ...item, firstSeenMs, isNew: now - firstSeenMs < NEW_WINDOW_MS };
  });
  return { items: stamped, history: nextHistory };
}

/**
 * Assemble the final snapshot. `sources` is the per-upstream health report so
 * the panel can show which feeds are live without hiding partial outages.
 */
export function assembleSnapshot({
  vulns = [], research = [], models = [], policy = [], sources = [], history = null, now = Date.now(),
}) {
  const firstRun = !history || Object.keys(history).length === 0;
  const byDateDesc = (a, b) => b.dateMs - a.dateMs;
  const stampedVulns = applyFirstSeen(mergeVulns(vulns), history, now, firstRun);
  const stampedResearch = applyFirstSeen([...research].sort(byDateDesc), history, now, firstRun);
  const stampedModels = applyFirstSeen([...models].sort(byDateDesc), history, now, firstRun);
  const stampedPolicy = applyFirstSeen(policy.slice(0, 10), history, now, firstRun);
  return {
    snapshot: {
      generatedAt: now,
      windowDays: WINDOW_DAYS,
      retainDays: RETAIN_DAYS,
      vulns: stampedVulns.items,
      research: stampedResearch.items,
      models: stampedModels.items.slice(0, 20),
      policy: stampedPolicy.items,
      sources,
    },
    history: {
      ...stampedVulns.history,
      ...stampedResearch.history,
      ...stampedModels.history,
      ...stampedPolicy.history,
    },
  };
}

/** Items inside the display window (policy is sparse, so never windowed). */
export function withinWindow(items, days, now = Date.now()) {
  const cutoff = now - days * DAY_MS;
  return items.filter((item) => item.dateMs >= cutoff);
}
