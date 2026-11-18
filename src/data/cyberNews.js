/**
 * Ananzi CYBER NEWS: reputable cyber-security news feeds (breaches, outages,
 * ransomware, exploits, official advisories) turned into one compact,
 * plain-English, source-linked wire — the kind of headline a level-1/2 help
 * desk reader can grasp at a glance.
 *
 * Pure: no I/O. The server shell (server/providers/anansi/cyber-news.js) does
 * the fetching; this module parses (reusing the shared RSS/Atom parser),
 * categorises, writes a plain lead, dedups, ranks and ages. Unit-tested in
 * cyberNews.test.mjs.
 */
import { parseFeed } from './aiSecIntel.js';

export { parseFeed };

/** Reputable, keyless RSS/Atom sources for cyber-attack news. */
export const CYBER_NEWS_SOURCES = Object.freeze([
  { id: 'thehackernews', label: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { id: 'bleepingcomputer', label: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
  { id: 'krebs', label: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
  { id: 'therecord', label: 'The Record', url: 'https://therecord.media/feed' },
  { id: 'securityweek', label: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
  { id: 'cisa-advisories', label: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
  { id: 'darkreading', label: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' },
  { id: 'cyberscoop', label: 'CyberScoop', url: 'https://cyberscoop.com/feed/' },
  { id: 'cybersecuritydive', label: 'Cybersecurity Dive', url: 'https://www.cybersecuritydive.com/feeds/news/' },
  { id: 'cybersecurity-insiders', label: 'Cybersecurity Insiders', url: 'https://www.cybersecurity-insiders.com/feed/' },
  { id: 'industrialcyber', label: 'Industrial Cyber (ICS/OT)', url: 'https://industrialcyber.co/feed/' },
  { id: 'reddit-cybersecurity', label: 'r/cybersecurity', url: 'https://www.reddit.com/r/cybersecurity/.rss' },
  { id: 'reddit-blueteamsec', label: 'r/blueteamsec', url: 'https://www.reddit.com/r/blueteamsec/.rss' },
  { id: 'reddit-crowdstrike', label: 'r/crowdstrike', url: 'https://www.reddit.com/r/crowdstrike/.rss' },
  // Mainstream outlets — general feeds filtered to cyber items only (filter:true).
  { id: 'newsweek', label: 'Newsweek', url: 'https://www.newsweek.com/rss', filter: true },
  { id: 'bbc-tech', label: 'BBC Technology', url: 'https://feeds.bbci.co.uk/news/technology/rss.xml', filter: true },
  { id: 'cnbc-tech', label: 'CNBC Technology', url: 'https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=19854910', filter: true },
]);

export const RETAIN_DAYS = 10; // news is time-sensitive; drop anything older
export const FRESH_HOURS = 12; // "NEW" window for emphasis
export const MAX_ITEMS = 60;

/**
 * Category tests, in priority order (first match wins). Each carries a short
 * uppercase tag, a plain-English one-liner for a non-expert, and a base weight.
 */
const CATEGORY_RULES = [
  {
    tag: 'OUTAGE', weight: 78,
    plain: 'An attack knocked websites or online services offline.',
    re: /\b(ddos|denial[- ]of[- ]service|knocked\s+offline|taken?\s+(?:down|offline)|took\s+down|outage|disrupt(?:ed|ion)|went\s+down|unavailable|service\s+(?:disruption|outage))\b/i,
  },
  {
    tag: 'RANSOMWARE', weight: 76,
    plain: 'Criminals locked an organization’s files and demanded payment.',
    re: /\b(ransomware|ransom|extort(?:ion|ed)?|lockbit|alphv|blackcat|cl0p|clop|akira|rhysida|double\s+extortion|encrypt(?:ed|s)?\s+(?:files|systems|data))\b/i,
  },
  {
    // Checked before BREACH: attribution to a government is the sharper fact.
    tag: 'NATION-STATE', weight: 74,
    plain: 'Government-backed hackers were involved.',
    re: /\b(nation[- ]state|state[- ]sponsored|apt\s?\d+|espionage|spy(?:ing|ware)?|chinese|russian|iranian|north\s+korean|lazarus|salt\s+typhoon|volt\s+typhoon|cozy\s+bear|fancy\s+bear|sandworm)\b/i,
  },
  {
    tag: 'BREACH', weight: 72,
    plain: 'Private data was stolen, leaked or left exposed.',
    re: /\b(breach(?:es|ed)?|hacked?|stole(?:n)?|leak(?:ed|s|ing)?|expos(?:e|es|ed|ing)\s+(?:\d|data|records?|database|customer|user|million)|exfiltrat\w*|compromis\w*|credential\s+(?:theft|stuffing)|records?\s+(?:exposed|stolen|leaked))\b/i,
  },
  {
    tag: 'EXPLOIT', weight: 64,
    plain: 'Attackers are abusing a software weakness — patch if it affects you.',
    re: /\b(zero[- ]day|0[- ]day|actively\s+exploit(?:ed|ing)|exploit(?:ed|ing|s)?|cve-\d{4}-\d+|vulnerabilit(?:y|ies)|flaw|rce|remote\s+code\s+execution|patch(?:ed|es)?\s+now|under\s+attack)\b/i,
  },
  {
    tag: 'ADVISORY', weight: 58,
    plain: 'An official security warning was issued.',
    re: /\b(advisory|advisories|alert|guidance|cisa|us-cert|warns?|warning|urges?|mandate)\b/i,
  },
];

const FALLBACK = { tag: 'NEWS', weight: 28, plain: '' };

/** Extra weight for headlines close to home or to critical services. */
const BOOST_RE = /\b(united\s+states|u\.?s\.?|america|federal|critical\s+infrastructure|hospital|power\s+grid|water|911|virginia|hampton\s+roads|norfolk)\b/i;

// Cyber-relevance gate for general-interest feeds (Newsweek, BBC, CNBC …): only
// items whose headline/summary clearly concern cyber-security pass through, so
// a mainstream outlet never floods the wire with sports or markets.
export const CYBER_RE =
  /\b(cyber(?:\s?security|\s?attack|\s?crime|\s?espionage|\s?threat)?|hack(?:er|ers|ing|ed)?|breach|ransomware|malware|phish|ddos|exploit|vulnerabilit|CVE-\d|zero[-\s]day|data\s+(?:leak|breach)|threat\s+actor|nation[-\s]state|\bAPT\b|botnet|CISA|infosec|back\s?door|spyware|credential|extortion|leak\s+site|patch\s+tuesday|security\s+(?:flaw|researcher|firm|team|vulnerabilit)|infostealer|wiper|supply[-\s]chain\s+attack)\b/i;

/** Classify a headline into { tag, plain, weight }. */
export function categorize(title, summary = '', sourceId = '') {
  const text = `${title} ${summary}`;
  if (sourceId === 'cisa-advisories') {
    return { tag: 'ADVISORY', plain: 'An official CISA security warning was issued.', weight: 60 };
  }
  for (const rule of CATEGORY_RULES) {
    if (rule.re.test(text)) return { tag: rule.tag, plain: rule.plain, weight: rule.weight };
  }
  return { ...FALLBACK };
}

const clip = (s, n) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  if (t.length <= n) return t;
  const cut = t.slice(0, n);
  const sp = cut.lastIndexOf(' ');
  return `${(sp > n * 0.6 ? cut.slice(0, sp) : cut).trimEnd()}…`;
};

/**
 * Normalise one source's parsed items into wire items, dropping anything older
 * than RETAIN_DAYS or undated.
 * @returns {Array<{title,summary,plain,source,sourceId,url,date,dateMs,tag,priority,isNew}>}
 */
export function normalizeItems(label, sourceId, parsed, { now = Date.now(), cyberOnly = false } = {}) {
  const cutoff = now - RETAIN_DAYS * 86_400_000;
  const out = [];
  for (const item of parsed || []) {
    if (!item || !Number.isFinite(item.dateMs) || item.dateMs < cutoff) continue;
    // parseFeed exposes the item URL as `link`.
    const url = item.url || item.link;
    if (!item.title || !url) continue;
    // General-interest feeds: keep only clearly cyber-security items.
    if (cyberOnly && !CYBER_RE.test(`${item.title} ${item.summary || ''}`)) continue;
    const title = clip(item.title, 160);
    const summary = clip(item.summary, 240);
    const cat = categorize(title, summary, sourceId);
    const boost = BOOST_RE.test(`${title} ${summary}`) ? 8 : 0;
    out.push({
      title,
      summary,
      plain: cat.plain,
      source: label,
      sourceId,
      url,
      date: new Date(item.dateMs).toISOString(),
      dateMs: item.dateMs,
      tag: cat.tag,
      priority: cat.weight + boost,
      isNew: now - item.dateMs < FRESH_HOURS * 3_600_000,
    });
  }
  return out;
}

const dedupeKey = (item) => {
  const byTitle = String(item.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 64);
  return byTitle || String(item.url || '').toLowerCase();
};

/**
 * Merge every source's items into one ranked, de-duplicated wire.
 * Most important first (priority, then newest). A duplicate headline keeps the
 * higher-priority / newer copy.
 * @returns {{at:number, items:Array, sources:Array}}
 */
export function assembleCyberNews({ items = [], sources = [], now = Date.now(), limit = MAX_ITEMS } = {}) {
  const best = new Map();
  for (const item of items) {
    const key = dedupeKey(item);
    const prior = best.get(key);
    if (
      !prior ||
      item.priority > prior.priority ||
      (item.priority === prior.priority && item.dateMs > prior.dateMs)
    ) {
      best.set(key, item);
    }
  }
  const ranked = [...best.values()].sort(
    (a, b) => b.priority - a.priority || b.dateMs - a.dateMs,
  );
  return { at: now, items: ranked.slice(0, limit), sources };
}
