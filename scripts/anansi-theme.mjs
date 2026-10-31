#!/usr/bin/env node
// Anansi theme: recolor God's Eye View's cyan accent to Anansi red.
//
// Upstream hard-codes its accent (#00d4ff / rgba(0, 212, 255, a)) in ~110
// places across src/ui/styles. Anansi's 0.1.x fork swapped every one of them
// for #c81e1e / rgba(200, 30, 30, a) by hand; this script does the same swap
// reproducibly, so after merging a newer God's Eye View you can re-run it:
//
//   node scripts/anansi-theme.mjs          # rewrite in place
//   node scripts/anansi-theme.mjs --check  # exit 1 if any cyan is left
//
// Token-level colors (--accent, --text-primary, ...) and Anansi-only
// components live in src/ui/styles/anansi.css, imported last by style.css.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const STYLE_DIR = path.join(root, 'src', 'ui', 'styles');
const FILES = [
  path.join(root, 'style.css'),
  ...readdirSync(STYLE_DIR)
    .filter((f) => f.endsWith('.css') && f !== 'anansi.css')
    .map((f) => path.join(STYLE_DIR, f)),
];

const CYAN_RGB = /rgba?\(\s*0\s*,\s*212\s*,\s*255\s*(,\s*[\d.]+\s*)?\)/gi;
const CYAN_HEX = /#00d4ff\b/gi;
const CYAN_SPACE = /rgba?\(\s*0\s+212\s+255\s*(\/\s*[\d.]+%?\s*)?\)/gi;
// Upstream's secondary sky-cyan (dock, first-run, voice card, key setup).
// Its teal "live" shades (65,220,231 and 34,230,230) stay, as in Anansi 0.1.x.
const SKY_RGB = /rgba?\(\s*54\s*,\s*220\s*,\s*255\s*(,\s*[\d.]+\s*)?\)/gi;

export function recolor(css) {
  return css
    .replace(CYAN_RGB, (_m, alpha) => (alpha ? `rgba(200, 30, 30${alpha.replace(/\s+/g, ' ').replace(/^,\s*/, ', ')})` : 'rgb(200, 30, 30)'))
    .replace(SKY_RGB, (_m, alpha) => (alpha ? `rgba(200, 30, 30${alpha.replace(/\s+/g, ' ').replace(/^,\s*/, ', ')})` : 'rgb(200, 30, 30)'))
    .replace(CYAN_HEX, '#c81e1e')
    .replace(CYAN_SPACE, (_m, alpha) => (alpha ? `rgb(200 30 30 ${alpha.trim()})` : 'rgb(200 30 30)'));
}

function main() {
  const check = process.argv.includes('--check');
  let remaining = 0;
  let changedFiles = 0;
  for (const file of FILES) {
    const before = readFileSync(file, 'utf8');
    const after = recolor(before);
    const hits = [CYAN_RGB, SKY_RGB, CYAN_HEX, CYAN_SPACE].reduce((n, re) => n + (before.match(re) || []).length, 0);
    if (check) {
      remaining += hits;
      if (hits) console.log(`${path.relative(root, file)}: ${hits} cyan value(s)`);
    } else if (after !== before) {
      writeFileSync(file, after);
      changedFiles += 1;
      console.log(`recolored ${hits} value(s) in ${path.relative(root, file)}`);
    }
  }
  if (check) {
    console.log(remaining ? `${remaining} cyan value(s) left — run without --check` : 'Anansi theme: no cyan left');
    process.exit(remaining ? 1 : 0);
  }
  console.log(`done: ${changedFiles} file(s) recolored`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
