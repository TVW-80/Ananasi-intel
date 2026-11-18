/**
 * Ananzi FANGS — Pwned Passwords checker widget.
 *
 * A small tool in the one-pane SITREP: type a password, see how many times it
 * has turned up in known breaches (Have I Been Pwned), with the password never
 * leaving the device (k-anonymity — see src/data/pwnedPasswords.js). Keyless.
 * Collapsed by default since it is a tool, not a live feed.
 */
import { checkPassword } from '../data/pwnedPasswords.js';

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

export function createPwnedCheck(doc = document, { check = checkPassword } = {}) {
  const wrap = el(doc, 'section', 'pwned-check collapsed');
  wrap.setAttribute('aria-label', 'Password breach check');
  const head = el(doc, 'div', 'pwned-head');
  const headL = el(doc, 'div', 'pwned-headL');
  const toggle = el(doc, 'button', 'pwned-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'pwned-title', '◆ PASSWORD CHECK');
  headL.append(toggle, title);
  head.append(headL);

  const body = el(doc, 'div', 'pwned-body');
  const form = el(doc, 'form', 'pwned-form');
  const input = el(doc, 'input', 'pwned-input');
  input.type = 'password';
  input.placeholder = 'Test a password…';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.setAttribute('aria-label', 'Password to check (never sent)');
  const btn = el(doc, 'button', 'pwned-btn', 'Check');
  btn.type = 'submit';
  form.append(input, btn);
  const result = el(doc, 'p', 'pwned-result');
  result.hidden = true;
  const note = el(doc, 'p', 'pwned-note', 'Only a partial hash is sent — your password never leaves this device.');
  body.append(form, result, note);
  wrap.append(head, body);

  let collapsed = true;
  function applyCollapsed() {
    wrap.classList.toggle('collapsed', collapsed);
    toggle.setAttribute('aria-expanded', String(!collapsed));
    const label = collapsed ? 'Expand password check' : 'Collapse password check';
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  }
  const setCollapsed = (next) => { collapsed = next; applyCollapsed(); };
  toggle.addEventListener('click', () => setCollapsed(!collapsed));
  title.style.cursor = 'pointer';
  title.addEventListener('click', () => setCollapsed(!collapsed));
  applyCollapsed();

  function show(cls, text) {
    result.hidden = false;
    result.className = `pwned-result ${cls}`;
    result.textContent = text;
  }

  async function run() {
    const value = input.value;
    if (!value) { show('pwned-neutral', 'Enter a password to check.'); return; }
    if (!globalThis.crypto?.subtle) {
      show('pwned-bad', 'Secure hashing is unavailable here (needs HTTPS).');
      return;
    }
    btn.disabled = true;
    show('pwned-neutral', 'Checking…');
    try {
      const { count } = await check(value);
      if (count > 0) {
        show('pwned-bad', `⚠ Found in ${count.toLocaleString('en-US')} known breaches — do not use this password.`);
      } else {
        show('pwned-good', '✓ Not found in any known breach.');
      }
    } catch {
      show('pwned-bad', 'Could not reach the breach service. Try again.');
    } finally {
      btn.disabled = false;
      input.value = ''; // don't keep the password sitting in the field
    }
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });

  return { element: wrap };
}
