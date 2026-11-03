/**
 * Ananzi SITREP: a pop-up dashboard fused into the attack map that slowly
 * rolls one plain-English card at a time — the attack-map alerts plus the AI
 * Security Intelligence feed (/api/ai-sec-intel), merged and written so a
 * level-1/2 help-desk tech can read them at a glance.
 *
 * Every card leads with plain words; the technical detail is a quieter second
 * line. The column auto-scrolls and pauses when you hover.
 *
 * Personal research tooling: English-only by design.
 */
const AI_SEC_ENDPOINT = '/api/ai-sec-intel';
const AI_SEC_POLL_MS = 15 * 60_000;

/** Trim a sentence to a readable length without cutting a word in half. */
export function tidy(text, max = 180) {
  const s = String(text || '').replace(/\s+/g, ' ').trim();
  if (s.length <= max) return s;
  return `${s.slice(0, s.lastIndexOf(' ', max) > 0 ? s.lastIndexOf(' ', max) : max)}…`;
}

const sevWord = (s) =>
  ({ critical: 'very serious', high: 'serious', medium: 'moderate', low: 'minor' })[String(s || '').toLowerCase()] || '';

/**
 * Turn the AI-security snapshot into plain-English SITREP entries.
 * Pure, so it is unit-tested without the DOM.
 * @returns {Array<{kind, tag, title, plain, todo?, detail?, link?, time?}>}
 */
export function plainAiSecEntries(snapshot) {
  const snap = snapshot || {};
  const out = [];
  for (const v of (snap.vulns || []).slice(0, 20)) {
    const product = [v.vendor, v.product].filter(Boolean).join(' ') || 'some software';
    const kev = v.exploited === 'kev';
    const sev = sevWord(v.severity);
    const plain =
      `A security hole was found in ${product}.` +
      (kev ? ' Hackers are already using it in real attacks.' : sev ? ` It is rated ${sev}.` : '') +
      (v.ransomware ? ' Ransomware gangs are known to use it.' : '');
    out.push({
      kind: 'vuln',
      tag: kev ? 'EXPLOITED NOW' : 'VULNERABILITY',
      title: tidy(v.title || v.id, 90),
      plain,
      todo: tidy(v.action || (v.fixed ? `Update ${product} to ${v.fixed}.` : 'Patch it when a fix is available.'), 140),
      detail: [v.id, Number.isFinite(v.cvss) ? `CVSS ${v.cvss.toFixed(1)}` : null, kev && v.dueDate ? `US agencies must fix by ${v.dueDate}` : null].filter(Boolean).join(' · '),
      link: v.evidence?.[0]?.url || '',
      time: v.date || null,
      severity: v.severity || null,
      priority: (kev ? 1000 : 0) + (v.severity === 'critical' ? 300 : v.severity === 'high' ? 200 : 0),
    });
  }
  const news = (kind, tag) =>
    (snap[kind] || []).slice(0, 10).map((item) => ({
      kind,
      tag,
      title: tidy(item.title || '(untitled)', 100),
      plain: tidy(item.summary || 'New item from the AI-security sources.', 200),
      detail: [item.source || item.number || null, item.date || null].filter(Boolean).join(' · '),
      link: item.url || '',
      time: item.date || null,
      priority: item.isNew ? 50 : 0,
    }));
  out.push(...news('models', 'AI MODELS'), ...news('research', 'RESEARCH'), ...news('policy', 'AI POLICY'));
  return out;
}

/** Attack-map alerts → the same SITREP entry shape. */
export function attackAlertEntries(body) {
  return (body?.alerts || []).slice(0, 30).map((a) => ({
    kind: 'attack',
    tag: String(a.source || 'ALERT').toUpperCase(),
    title: tidy(a.title, 110),
    plain: tidy(a.plain, 220),
    detail: tidy(a.technical, 160),
    link: a.link || '',
    time: a.time || null,
    priority: 10,
  }));
}

/** Merge, newest/most-important first, and cap. */
export function buildSitrep(body, aiSnapshot, limit = 40) {
  const entries = [...attackAlertEntries(body), ...plainAiSecEntries(aiSnapshot)];
  entries.sort((a, b) => (b.priority || 0) - (a.priority || 0) || String(b.time || '').localeCompare(String(a.time || '')));
  return entries.slice(0, limit);
}

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

const TAG_COLOR = {
  'EXPLOITED NOW': '#ff2b2b',
  VULNERABILITY: '#ff8a1f',
  'AI MODELS': '#8fd46b',
  RESEARCH: '#d4af37',
  'AI POLICY': '#e0457b',
  attack: '#f4cf5e',
};

function card(doc, e) {
  const c = el(doc, 'article', 'sitrep-card');
  c.style.setProperty('--tag', TAG_COLOR[e.tag] || TAG_COLOR.attack);
  const head = el(doc, 'div', 'sitrep-card-head');
  head.append(el(doc, 'span', 'sitrep-tag', e.tag), el(doc, 'span', 'sitrep-title', e.title));
  c.append(head);
  if (e.plain) c.append(el(doc, 'p', 'sitrep-plain', e.plain));
  if (e.todo) {
    const todo = el(doc, 'p', 'sitrep-todo');
    todo.append(el(doc, 'b', null, 'Do: '), doc.createTextNode(e.todo));
    c.append(todo);
  }
  const foot = el(doc, 'div', 'sitrep-foot');
  if (e.detail) foot.append(el(doc, 'span', 'sitrep-detail', e.detail));
  if (e.link) {
    const a = el(doc, 'a', 'sitrep-src', 'read more ↗');
    a.href = e.link;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    foot.append(a);
  }
  if (foot.childNodes.length) c.append(foot);
  return c;
}

/**
 * The rolling dashboard. `fetchImpl` is injectable for tests; the DOM pieces
 * are created lazily on first mount.
 */
export function createSitrep(doc = document, { fetchImpl = (...a) => globalThis.fetch(...a) } = {}) {
  const panel = el(doc, 'aside', 'sitrep');
  panel.id = 'attack-sitrep';
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Plain-English situation report');
  const head = el(doc, 'div', 'sitrep-head');
  const title = el(doc, 'span', null, 'SITREP · what’s happening, in plain English');
  const close = el(doc, 'button', 'sitrep-close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', 'Close SITREP');
  head.append(title, close);
  const roll = el(doc, 'div', 'sitrep-roll');
  const track = el(doc, 'div', 'sitrep-track');
  roll.append(track);
  const empty = el(doc, 'p', 'sitrep-empty', 'Waiting for the first intel to roll in…');
  panel.append(head, roll, empty);

  let attackBody = null;
  let aiSnapshot = null;
  let aiTimer = null;
  let open = false;

  function render() {
    const entries = buildSitrep(attackBody, aiSnapshot);
    empty.hidden = entries.length > 0;
    if (!entries.length) {
      track.replaceChildren();
      return;
    }
    const cards = entries.map((e) => card(doc, e));
    // Two copies make the vertical marquee seamless.
    track.replaceChildren(...cards, ...cards.map((c) => c.cloneNode(true)));
    // Slow, readable crawl: ~7s per card, paused on hover (CSS).
    track.style.setProperty('--sitrep-seconds', `${Math.max(40, entries.length * 7)}s`);
  }

  async function pollAiSec() {
    try {
      const res = await fetchImpl(AI_SEC_ENDPOINT, { cache: 'no-store' });
      if (res.ok) {
        aiSnapshot = await res.json();
        if (open) render();
      }
    } catch {
      // leave the last snapshot; the attack alerts still roll
    }
  }

  close.addEventListener('click', () => api.setOpen(false));

  const api = {
    element: panel,
    setAttack(body) {
      attackBody = body;
      if (open) render();
    },
    setOpen(next) {
      open = next;
      panel.hidden = !next;
      if (next) {
        render();
        if (!aiSnapshot) pollAiSec();
        aiTimer ??= setInterval(pollAiSec, AI_SEC_POLL_MS);
      }
    },
    isOpen: () => open,
    dispose() {
      clearInterval(aiTimer);
      aiTimer = null;
      panel.remove();
    },
  };
  return api;
}
