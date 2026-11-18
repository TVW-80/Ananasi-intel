/**
 * Ananzi FANGS — service / outage status board.
 *
 * The honest "is it down right now" panel in the one-pane SITREP: major
 * providers' own statuspage.io status (operational / degraded / down) with any
 * active incidents, worst first. Collapsible like the Patch Priority board.
 *
 * Rendering only; the data lives in src/data/serviceStatus.js (and /api/
 * service-status).
 */

/** Bucket → accent colour. */
const BUCKET_COLOR = { down: '#ff2b2b', degraded: '#ff8a1f', ok: '#8fd46b' };
const BUCKET_DOT = { down: '●', degraded: '▲', ok: '●' };

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** A live service-status board: { element, update(snapshot) }. */
export function createServiceBoard(doc = document) {
  const wrap = el(doc, 'section', 'svc-status');
  wrap.setAttribute('aria-label', 'Service and outage status');
  const head = el(doc, 'div', 'svc-status-head');
  const headL = el(doc, 'div', 'svc-status-headL');
  const toggle = el(doc, 'button', 'svc-status-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'svc-status-title', '◆ SERVICE STATUS · live');
  const tally = el(doc, 'span', 'svc-status-tally', '');
  headL.append(toggle, title);
  head.append(headL, tally);
  const list = el(doc, 'div', 'svc-status-list');
  const empty = el(doc, 'div', 'svc-status-empty', 'Checking service status…');
  wrap.append(head, list, empty);

  const STORE_KEY = 'ananzi.fangs.serviceStatus.collapsed';
  let collapsed = false;
  try { collapsed = globalThis.localStorage?.getItem(STORE_KEY) === '1'; } catch { /* private mode */ }
  function applyCollapsed() {
    wrap.classList.toggle('collapsed', collapsed);
    toggle.setAttribute('aria-expanded', String(!collapsed));
    const label = collapsed ? 'Expand service status' : 'Collapse service status';
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  }
  function setCollapsed(next) {
    collapsed = next;
    try { globalThis.localStorage?.setItem(STORE_KEY, next ? '1' : '0'); } catch { /* private mode */ }
    applyCollapsed();
  }
  toggle.addEventListener('click', () => setCollapsed(!collapsed));
  title.style.cursor = 'pointer';
  title.addEventListener('click', () => setCollapsed(!collapsed));
  applyCollapsed();

  function row(p) {
    const accent = BUCKET_COLOR[p.bucket] || '#d4af37';
    const incident = p.incidents?.[0];
    const link = incident?.url || p.url || '';
    const node = el(doc, link ? 'a' : 'div', 'svc-status-row');
    node.style.setProperty('--sev', accent);
    if (link) {
      node.href = link;
      node.target = '_blank';
      node.rel = 'noopener noreferrer';
    }
    const dot = el(doc, 'span', 'svc-status-dot', BUCKET_DOT[p.bucket] || '●');
    dot.style.color = accent;
    const main = el(doc, 'div', 'svc-status-main');
    main.append(
      el(doc, 'span', 'svc-status-name', p.label),
      el(doc, 'span', 'svc-status-desc', p.plain || p.description || ''),
    );
    node.append(dot, main);
    return node;
  }

  function update(snapshot) {
    const providers = snapshot?.providers || [];
    if (!providers.length) {
      empty.hidden = false;
      empty.textContent = 'Service status unavailable right now.';
      tally.textContent = '';
      list.replaceChildren();
      return;
    }
    const s = snapshot.summary || { down: 0, degraded: 0, ok: providers.length };
    tally.textContent = `↓ ${s.down} · ⚠ ${s.degraded} · ✓ ${s.ok}`;
    // Show everything with a problem; if all clear, show the all-good note.
    const problems = providers.filter((p) => p.bucket !== 'ok');
    if (!problems.length) {
      empty.hidden = false;
      empty.textContent = `All ${s.total} monitored services operational.`;
      list.replaceChildren();
      return;
    }
    empty.hidden = true;
    list.replaceChildren(...problems.map(row));
  }

  return { element: wrap, update };
}
