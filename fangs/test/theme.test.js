import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, makeFangs, loadSnapshotInto, withServer } from './helpers/env.js';
import { launch, CHROME } from './helpers/chrome.js';

const css = fs.readFileSync(path.join(ROOT, 'public/styles.css'), 'utf8');
const block = (re) => { const m = re.exec(css); assert.ok(m, `missing block ${re}`); return m[1]; };
const vars = (b) => Object.fromEntries([...b.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
const FONT_VARS = vars(block(/:root\s*\{([^}]*)\}/));
const dark = vars(block(/:root,\s*\[data-theme="dark"\]\s*\{([^}]*)\}/)), light = vars(block(/\[data-theme="light"\]\s*\{([^}]*)\}/));

const hex = (h) => { const n = h.replace('#', ''); const f = n.length === 3 ? n.split('').map((c) => c + c).join('') : n; return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16) / 255); };
const lum = (h) => { const [r, g, b] = hex(h).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

test('THEME both themes define the identical set of custom properties', () => {
  assert.deepEqual(Object.keys(dark).sort(), Object.keys(light).sort());
  assert.ok(Object.keys(dark).length >= 25);
});

test('THEME every var(--x) used in CSS/JS is defined in both themes (except font stacks defined once)', () => {
  const used = new Set([...css.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((m) => m[1]));
  const js = fs.readFileSync(path.join(ROOT, 'public/app.js'), 'utf8');
  for (const m of js.matchAll(/css\('(--[a-z0-9-]+)'\)/g)) used.add(m[1]);
  for (const m of js.matchAll(/css\(`(--n-)\$\{[^}]+\}`\)/g)) for (const t of ['ip', 'host', 'family', 'asn', 'campaign', 'victim']) used.add(`${m[1]}${t}`);
  for (const v of used) { if (v in FONT_VARS) continue; assert.ok(v in dark, `${v} missing in dark`); assert.ok(v in light, `${v} missing in light`); }
  for (const k of ['--c0', '--c1', '--c2', '--c3', '--c4', '--c5', '--c6', '--c7', '--c8', '--c9']) { assert.ok(k in dark && k in light, `cluster colour ${k}`); }
});

test('THEME no hard-coded colours outside the two variable blocks (CSS)', () => {
  const stripped = css.replace(/:root,\s*\[data-theme="dark"\]\s*\{[^}]*\}/, '').replace(/\[data-theme="light"\]\s*\{[^}]*\}/, '');
  const hits = stripped.match(/#[0-9a-fA-F]{3,8}\b|rgba?\(/g) || [];
  assert.deepEqual(hits, [], `hard-coded colours: ${hits}`);
});

test('THEME WCAG contrast: body/secondary text >= 4.5:1 on every surface, graph glyph colours >= 3:1 against the graph background, both themes', () => {
  const rows = [];
  for (const [name, t] of [['dark', dark], ['light', light]]) {
    for (const fg of ['--text', '--text-dim', '--accent', '--red', '--ok', '--warn', '--bad', '--sev-critical', '--sev-high', '--sev-medium', '--sev-low']) for (const bg of ['--bg', '--panel', '--panel-2']) {
      const c = contrast(t[fg], t[bg]); rows.push([name, fg, bg, c]);
      const need = fg.startsWith('--sev') ? 3 : 4.5;   // severity colours are border stripes (non-text) -> 3:1
      assert.ok(c >= need, `${name}: ${fg} on ${bg} = ${c.toFixed(2)} < ${need}`);
    }
    for (const n of ['ip', 'host', 'family', 'asn', 'campaign', 'victim']) { const c = contrast(t[`--n-${n}`], t['--bg']); rows.push([name, `--n-${n}`, '--bg', c]); assert.ok(c >= 3, `${name}: node colour ${n} on graph bg = ${c.toFixed(2)}`); }
    assert.ok(contrast(t['--edge-hot'], t['--bg']) >= 3 && contrast(t['--focus'], t['--bg']) >= 3, `${name}: focus/edge highlight`);
  }
  const min = rows.reduce((a, r) => (r[3] < a[3] ? r : a));
  console.log(`  ${rows.length} contrast pairs checked; lowest: ${min[0]} ${min[1]} on ${min[2]} = ${min[3].toFixed(2)}:1`);
  for (const [name, t] of [['dark', dark], ['light', light]]) {
    for (let i = 0; i < 10; i++) { const c = contrast(t[`--c${i}`], t['--bg']); assert.ok(c >= 3, `${name}: cluster colour --c${i} = ${c.toFixed(2)}:1 on graph background`); }
    assert.ok(contrast(t['--on-accent'], t['--accent']) >= 4.5, `${name}: skip-link text on accent`);
  }
});

test('THEME honours reduced motion and keeps a visible focus ring', () => { assert.match(css, /prefers-reduced-motion: reduce/); assert.match(css, /:focus-visible\s*\{[^}]*outline/); });

test('THEME in the browser: toggle flips data-theme, aria-pressed, and re-styles the graph canvas', { skip: !CHROME && 'no chrome' }, async () => {
  const f = makeFangs(); loadSnapshotInto(f); f.runAnalysis({ relayout: true });
  await withServer(f, async (base) => {
    const b = await launch();
    try {
      await b.goto(`${base}/`); await b.waitFor('window.__fangs && window.__fangs.ready === true', 20000);
      assert.equal(await b.eval('document.documentElement.dataset.theme'), 'dark', 'Ananzi default is dark');
      const colorOf = () => b.eval(`window.__fangs.state.cy.nodes('[type = "ip"]')[0].style('background-color')`);
      const d = await colorOf();
      await b.eval(`document.getElementById('theme').click()`);
      assert.equal(await b.eval('document.documentElement.dataset.theme'), 'light'); assert.equal(await b.eval(`document.getElementById('theme').getAttribute('aria-pressed')`), 'true');
      const l = await colorOf(); assert.notEqual(d, l, 'graph glyph colour must follow the theme');
      assert.equal(await b.eval(`getComputedStyle(document.body).backgroundColor`), 'rgb(246, 243, 238)');
      await b.eval(`document.getElementById('theme').click()`); assert.equal(await colorOf(), d);
      await b.eval(`localStorage.setItem('fangs.theme','light')`); await b.goto(`${base}/`); await b.waitFor('window.__fangs && window.__fangs.ready === true', 20000);
      assert.equal(await b.eval('document.documentElement.dataset.theme'), 'light', 'choice persists');
    } finally { await b.close(); }
  });
});
