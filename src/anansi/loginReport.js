/**
 * Ananzi WELCOME-BACK REPORT: a one-time, plain-English digest shown when you
 * open the app, covering the major things that happened since your last visit.
 *
 * It reuses the SITREP plain-English engine (attack-map alerts + the AI
 * Security Intelligence feed), keeps only the items newer than your last login,
 * and writes them in words a high-school student can follow. The globe opens
 * clean (every layer off), so this card is how you catch up at a glance before
 * turning anything on.
 *
 * The pure helpers (readLastLogin, selectNewSince, summarize, timeAgo…) carry
 * no DOM and are unit-tested in loginReport.test.mjs.
 */
import { buildSitrep } from './sitrep.js';

export const LAST_LOGIN_KEY = 'anansi:last-login';
const ATTACK_ENDPOINT = '/api/attackmap';
const AI_SEC_ENDPOINT = '/api/ai-sec-intel';
const MAX_ITEMS = 24;

/** Milliseconds for a time string/number, or null when it can't be read. */
export function parseTime(t) {
  if (t == null) return null;
  const n = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(n) ? n : null;
}

/** The last-login timestamp (ms) we stored, or null on the very first visit. */
export function readLastLogin(storage) {
  try {
    return parseTime(storage?.getItem?.(LAST_LOGIN_KEY));
  } catch {
    return null;
  }
}

/** Remember that the visitor has now seen everything up to `date`. */
export function writeLastLogin(storage, date = Date.now()) {
  try {
    storage?.setItem?.(LAST_LOGIN_KEY, new Date(date).toISOString());
  } catch {
    /* best effort — a private window just gets the report every time */
  }
}

/**
 * Keep the SITREP entries that are newer than the last login, most important
 * first. With no last login (first visit) everything qualifies, newest first.
 */
export function selectNewSince(entries, sinceMs, { cap = MAX_ITEMS } = {}) {
  const items = (entries || []).filter((e) => {
    const t = parseTime(e.time);
    if (t == null) return false;
    return sinceMs == null || t > sinceMs;
  });
  items.sort(
    (a, b) =>
      (b.priority || 0) - (a.priority || 0) ||
      (parseTime(b.time) || 0) - (parseTime(a.time) || 0),
  );
  return items.slice(0, cap);
}

/** A short, friendly "x minutes/hours/days ago" for an item's timestamp. */
export function timeAgo(ms, now = Date.now()) {
  const t = parseTime(ms);
  if (t == null) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 90) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? '' : 's'} ago`;
  const d = Math.round(h / 24);
  return `${d} day${d === 1 ? '' : 's'} ago`;
}

/** A readable local date+time for the last-login line, e.g. "Fri, Nov 7, 3:12 PM". */
export function friendlyWhen(ms) {
  const t = parseTime(ms);
  if (t == null) return '';
  try {
    return new Date(t).toLocaleString(undefined, {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  } catch {
    return new Date(t).toISOString();
  }
}

const NEWS_KINDS = new Set(['models', 'research', 'policy']);

/**
 * A plain-English headline + a few bullet counts describing the new items.
 * @returns {{count:number, headline:string, bullets:string[]}}
 */
export function summarize(entries, sinceMs, now = Date.now()) {
  const n = entries.length;
  const when = sinceMs ? friendlyWhen(sinceMs) : null;
  const since = when ? ` (last here ${when})` : '';
  if (n === 0) {
    return {
      count: 0,
      headline: `All quiet since you were last here${since}. Nothing major to report.`,
      bullets: [],
    };
  }
  const vulns = entries.filter((e) => e.kind === 'vuln');
  const urgent = vulns.filter((e) => e.tag === 'EXPLOITED NOW').length;
  const otherVulns = vulns.length - urgent;
  const attacks = entries.filter((e) => e.kind === 'attack').length;
  const news = entries.filter((e) => NEWS_KINDS.has(e.kind)).length;
  const bullets = [];
  if (urgent)
    bullets.push(
      `${urgent} security hole${urgent === 1 ? ' is' : 's are'} already being used by hackers right now — fix ${urgent === 1 ? 'it' : 'these'} first.`,
    );
  if (otherVulns > 0)
    bullets.push(
      `${otherVulns} other new security weakness${otherVulns === 1 ? '' : 'es'} worth patching.`,
    );
  if (attacks)
    bullets.push(
      `${attacks} new attack warning${attacks === 1 ? '' : 's'} showed up on the world map.`,
    );
  if (news)
    bullets.push(
      `${news} AI-security news update${news === 1 ? '' : 's'} came in from the feeds.`,
    );
  return {
    count: n,
    headline: `Here's what you missed${since}: ${n} thing${n === 1 ? '' : 's'} worth knowing.`,
    bullets,
  };
}

/* ── DOM ──────────────────────────────────────────────────────────────────── */

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function card(doc, e, now) {
  const c = el(doc, 'article', 'login-report-card');
  const top = el(doc, 'div', 'login-report-card-top');
  top.append(el(doc, 'span', `login-report-tag kind-${e.kind}`, e.tag || 'UPDATE'));
  const ago = timeAgo(e.time, now);
  if (ago) top.append(el(doc, 'span', 'login-report-ago', ago));
  c.append(top);
  if (e.title) c.append(el(doc, 'h4', 'login-report-card-title', e.title));
  if (e.plain) c.append(el(doc, 'p', 'login-report-card-plain', e.plain));
  if (e.todo) {
    const todo = el(doc, 'p', 'login-report-todo');
    todo.append(el(doc, 'strong', null, 'Do this: '), doc.createTextNode(e.todo));
    c.append(todo);
  }
  if (e.link) {
    const a = el(doc, 'a', 'login-report-link', 'Read more →');
    a.href = e.link;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    c.append(a);
  }
  return c;
}

/**
 * Build the welcome-back panel. `fetchImpl`, `now` and `storage` are injectable
 * for tests; nothing here enables a layer or touches the globe.
 */
export function createLoginReport(
  doc = document,
  {
    fetchImpl = (...a) => globalThis.fetch(...a),
    now = () => Date.now(),
    storage = globalThis.localStorage,
  } = {},
) {
  const panel = el(doc, 'section', 'login-report');
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'What happened since your last visit');
  panel.hidden = true;

  const head = el(doc, 'div', 'login-report-head');
  head.append(el(doc, 'span', 'login-report-kicker', '✦ WELCOME BACK · SINCE YOU LEFT'));
  const close = el(doc, 'button', 'login-report-close', 'Got it ✕');
  close.type = 'button';
  head.append(close);
  panel.append(head);

  const headline = el(doc, 'p', 'login-report-headline');
  const sum = el(doc, 'ul', 'login-report-sum');
  const list = el(doc, 'div', 'login-report-list');
  const foot = el(
    doc,
    'p',
    'login-report-foot',
    'Every layer is off right now — open the layers panel and switch on what you want to watch.',
  );
  panel.append(headline, sum, list, foot);

  let shown = false;
  function open() {
    shown = true;
    panel.hidden = false;
  }
  function closePanel() {
    shown = false;
    panel.hidden = true;
  }
  close.addEventListener('click', closePanel);

  function renderDigest(entries, sinceMs) {
    const nowMs = now();
    const s = summarize(entries, sinceMs, nowMs);
    headline.textContent = s.headline;
    sum.replaceChildren(...s.bullets.map((b) => el(doc, 'li', null, b)));
    sum.hidden = s.bullets.length === 0;
    list.replaceChildren(...entries.map((e) => card(doc, e, nowMs)));
    list.hidden = entries.length === 0;
  }

  async function fetchJson(url) {
    try {
      const res = await fetchImpl(url, { cache: 'no-store' });
      return res?.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  /**
   * Fetch the feeds, compute the digest, show it (returning visitors only), and
   * stamp the new last-login time. Resolves to a small summary for callers/tests.
   */
  async function init() {
    const lastLogin = readLastLogin(storage);
    const [attack, ai] = await Promise.all([
      fetchJson(ATTACK_ENDPOINT),
      fetchJson(AI_SEC_ENDPOINT),
    ]);
    const entries = selectNewSince(buildSitrep(attack, ai, 200), lastLogin);
    renderDigest(entries, lastLogin);
    // Stamp AFTER computing, so this visit's cutoff is "now".
    writeLastLogin(storage, now());
    // First-ever visit has no baseline to compare against — let the normal
    // welcome card greet them instead of a "since last time" report.
    const firstVisit = lastLogin == null;
    if (!firstVisit) open();
    return { shown: !firstVisit, count: entries.length, firstVisit };
  }

  return {
    element: panel,
    init,
    open,
    close: closePanel,
    isOpen: () => shown,
    destroy() {
      closePanel();
      panel.remove();
    },
  };
}

/**
 * Boot helper: build the panel, mount it, kick off the async digest, and return
 * a handle with destroy(). Safe to call once at app open.
 */
export function initLoginReport({ now, storage, fetchImpl, doc = document } = {}) {
  const report = createLoginReport(doc, { now, storage, fetchImpl });
  doc.body.append(report.element);
  void report.init();
  return report;
}
