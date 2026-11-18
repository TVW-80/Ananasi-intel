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
import { createAttackHeatmap } from './attackHeatmap.js';
import { createVulnScorecard } from './vulnScorecard.js';
import { createServiceBoard } from './serviceStatus.js';
import { createPwnedCheck } from './pwnedCheck.js';
import { createReconBoard } from './reconBoard.js';

const AI_SEC_ENDPOINT = '/api/ai-sec-intel';
const CYBER_NEWS_ENDPOINT = '/api/cyber-news';
const SERVICE_STATUS_ENDPOINT = '/api/service-status';
const AI_SEC_POLL_MS = 15 * 60_000;
const SERVICE_STATUS_POLL_MS = 2 * 60_000; // outages move fast

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

/**
 * Cyber-attack NEWS wire (/api/cyber-news) → the same SITREP entry shape.
 * The headline leads; the plain line says, in a sentence a non-expert gets,
 * what kind of thing happened.
 */
export function plainCyberNewsEntries(snapshot) {
  return (snapshot?.items || []).slice(0, 20).map((item) => ({
    kind: 'cyber-news',
    tag: item.tag || 'NEWS',
    title: tidy(item.title || '(untitled)', 120),
    plain: tidy(item.plain || item.summary || 'New cyber-security headline.', 200),
    detail: [item.source, item.plain && item.summary ? tidy(item.summary, 120) : null].filter(Boolean).join(' · '),
    link: item.url || '',
    time: item.date || null,
    priority: (item.priority || 30) + (item.isNew ? 10 : 0),
  }));
}

/** Merge, newest/most-important first, and cap. */
export function buildSitrep(body, aiSnapshot, cyberSnapshot = null, limit = 40) {
  const entries = [
    ...attackAlertEntries(body),
    ...plainAiSecEntries(aiSnapshot),
    ...plainCyberNewsEntries(cyberSnapshot),
  ];
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
  // Cyber-news wire categories (/api/cyber-news).
  BREACH: '#e0457b',
  RANSOMWARE: '#ff2b2b',
  OUTAGE: '#ff8a1f',
  'NATION-STATE': '#c061dd',
  EXPLOIT: '#ff6b4a',
  ADVISORY: '#f4cf5e',
  NEWS: '#e8d9a8',
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
export function createSitrep(doc = document, { fetchImpl = (...a) => globalThis.fetch(...a), onReplay = null } = {}) {
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
  const heat = createAttackHeatmap(doc); // live ATT&CK heat map at the top
  const vulnScore = createVulnScorecard(doc); // CySA+ patch-priority queue
  const serviceBoard = createServiceBoard(doc); // "is it down right now" board
  const pwnedCheck = createPwnedCheck(doc); // keyless k-anonymity password check
  const recon = createReconBoard(doc, { onReplay }); // event reconstruction (correlate/replay)
  const roll = el(doc, 'div', 'sitrep-roll');
  const track = el(doc, 'div', 'sitrep-track');
  roll.append(track);
  const empty = el(doc, 'p', 'sitrep-empty', 'Waiting for the first intel to roll in…');
  panel.append(head, heat.element, vulnScore.element, serviceBoard.element, recon.element, pwnedCheck.element, roll, empty);

  let attackBody = null;
  let aiSnapshot = null;
  let cyberSnapshot = null;
  let svcSnapshot = null;
  let aiTimer = null;
  let svcTimer = null;
  let open = false;

  function render() {
    const entries = buildSitrep(attackBody, aiSnapshot, cyberSnapshot);
    // Feed the ATT&CK heat map from the attack + cyber-news + exploited-vuln
    // entries (the ones that map to a technique).
    heat.update(
      entries
        .filter((e) => ['attack', 'cyber-news', 'vuln'].includes(e.kind))
        .map((e) => ({
          layerId: e.kind === 'attack' ? 'cyber-attack-map' : undefined,
          text: `${e.title || ''} ${e.plain || ''} ${e.tag || ''}`,
        })),
    );
    // Re-triage the live vuln feed into a CySA+ patch-priority queue.
    vulnScore.update(aiSnapshot?.vulns || []);
    // Providers' own status: what's degraded or down right now.
    serviceBoard.update(svcSnapshot);
    // Reconstruct incidents from every live signal (correlate + replay).
    recon.update({ attack: attackBody, cyber: cyberSnapshot, ai: aiSnapshot, service: svcSnapshot });
    empty.hidden = entries.length > 0;
    if (!entries.length) {
      track.replaceChildren();
      return;
    }
    // A single, naturally-flowing list the user can scroll freely.
    track.replaceChildren(...entries.map((e) => card(doc, e)));
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

  async function pollCyberNews() {
    try {
      const res = await fetchImpl(CYBER_NEWS_ENDPOINT, { cache: 'no-store' });
      if (res.ok) {
        cyberSnapshot = await res.json();
        if (open) render();
      }
    } catch {
      // leave the last wire; the rest of the board still rolls
    }
  }

  async function pollServiceStatus() {
    try {
      const res = await fetchImpl(SERVICE_STATUS_ENDPOINT, { cache: 'no-store' });
      if (res.ok) {
        svcSnapshot = await res.json();
        if (open) render();
      }
    } catch {
      // leave the last status; the rest of the board still works
    }
  }

  close.addEventListener('click', () => api.setOpen(false));

  // Gentle auto-advance of the rolling column — a medium, steady pace that
  // gently ping-pongs. The reader stays in control: it pauses while the
  // pointer is over the roll and yields for a moment whenever they scroll,
  // wheel, touch or key through it, then quietly resumes.
  const AUTO_STEP_MS = 40;
  const AUTO_PX = 0.7; // ~17px/s
  const YIELD_MS = 2500;
  let hovering = false;
  let yieldUntil = 0;
  let autoTimer = null;
  let dir = 1;
  roll.addEventListener('pointerenter', () => { hovering = true; });
  roll.addEventListener('pointerleave', () => { hovering = false; });
  const nudge = () => { yieldUntil = Date.now() + YIELD_MS; };
  roll.addEventListener('wheel', nudge, { passive: true });
  roll.addEventListener('pointerdown', nudge);
  roll.addEventListener('touchstart', nudge, { passive: true });
  roll.addEventListener('keydown', nudge);
  function autoTick() {
    if (!open || hovering || Date.now() < yieldUntil) return;
    const maxTop = roll.scrollHeight - roll.clientHeight;
    if (maxTop <= 1) return; // nothing to scroll
    roll.scrollTop += AUTO_PX * dir;
    if (roll.scrollTop >= maxTop - 0.5) { dir = -1; yieldUntil = Date.now() + 1500; }
    else if (roll.scrollTop <= 0.5) { dir = 1; yieldUntil = Date.now() + 1500; }
  }
  function startAuto() {
    if (autoTimer == null && typeof setInterval === 'function') autoTimer = setInterval(autoTick, AUTO_STEP_MS);
  }
  function stopAuto() {
    clearInterval(autoTimer);
    autoTimer = null;
  }

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
        startAuto();
        if (!aiSnapshot) pollAiSec();
        if (!cyberSnapshot) pollCyberNews();
        if (!svcSnapshot) pollServiceStatus();
        aiTimer ??= setInterval(() => { pollAiSec(); pollCyberNews(); }, AI_SEC_POLL_MS);
        svcTimer ??= setInterval(() => pollServiceStatus(), SERVICE_STATUS_POLL_MS);
      } else {
        stopAuto();
      }
    },
    isOpen: () => open,
    dispose() {
      clearInterval(aiTimer);
      clearInterval(svcTimer);
      aiTimer = null;
      svcTimer = null;
      stopAuto();
      panel.remove();
    },
  };
  return api;
}
