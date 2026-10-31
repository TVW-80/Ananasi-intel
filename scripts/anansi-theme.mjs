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
    // cyber.css is the optional, deliberately cyan "Cyber" HUD layout and
    // bhote-koshi.css a scripted scene; both keep their own palettes.
    .filter((f) => f.endsWith('.css') && !['anansi.css', 'cyber.css', 'bhote-koshi.css'].includes(f))
    .map((f) => path.join(STYLE_DIR, f)),
];

const CYAN_RGB = /rgba?\(\s*0\s*,\s*212\s*,\s*255\s*(,\s*[\d.]+\s*)?\)/gi;
const CYAN_HEX = /#00d4ff\b/gi;
const CYAN_SPACE = /rgba?\(\s*0\s+212\s+255\s*(\/\s*[\d.]+%?\s*)?\)/gi;
// Upstream's secondary sky-cyan (dock, first-run, voice card, key setup).
// Its teal "live" shades (65,220,231 and 34,230,230) stay, as in Anansi 0.1.x.
const SKY_RGB = /rgba?\(\s*54\s*,\s*220\s*,\s*255\s*(,\s*[\d.]+\s*)?\)/gi;

// Any remaining blue/cyan/teal (hue 165–255°, saturated, not dark) is mapped
// by what it paints: text-like properties go Anansi gold, everything else
// (backgrounds, borders, shadows, gradients) goes Anansi red. Alpha is kept.
const TEXT_PROPS = /^(color|fill|stroke|caret-color|-webkit-text-fill-color|text-decoration-color|accent-color)$/;
const ANY_COLOR = /rgba?\(\s*(\d{1,3})\s*(,|\s)\s*(\d{1,3})\s*[,\s]\s*(\d{1,3})\s*(?:([,/])\s*([\d.]+%?)\s*)?\)|#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b/g;
const RED = [200, 30, 30];
const GOLD = [212, 175, 55];

/** 'bright' | 'dark' | null — dark navy/teal glass is neutralized, not recolored. */
export function blueKind(r, g, b) {
  const max = Math.max(r, g, b) / 255;
  const min = Math.min(r, g, b) / 255;
  const d = max - min;
  if (max === 0 || d / max < 0.3) return null;
  let h;
  if (max === r / 255) h = ((g - b) / 255 / d) % 6;
  else if (max === g / 255) h = (b - r) / 255 / d + 2;
  else h = (r - g) / 255 / d + 4;
  h = (h * 60 + 360) % 360;
  if (h < 165 || h > 255) return null;
  return max < 0.35 ? 'dark' : 'bright';
}

export function isBlue(r, g, b) {
  const max = Math.max(r, g, b) / 255;
  const min = Math.min(r, g, b) / 255;
  const d = max - min;
  if (max < 0.35 || max === 0 || d / max < 0.3) return false;
  let h;
  if (max === r / 255) h = ((g - b) / 255 / d) % 6;
  else if (max === g / 255) h = (b - r) / 255 / d + 2;
  else h = (r - g) / 255 / d + 4;
  h = (h * 60 + 360) % 360;
  return h >= 165 && h <= 255;
}

const ONE_COLOR = new RegExp(ANY_COLOR.source); // non-global: no lastIndex state

function swapColor(literal, target) {
  const m = ONE_COLOR.exec(literal);
  if (!m) return literal;
  let r, g, b;
  if (m[7]) {
    const hex = m[7].length === 3 ? [...m[7]].map((c) => c + c).join('') : m[7];
    [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
  } else [r, g, b] = [+m[1], +m[3], +m[4]];
  const kind = blueKind(r, g, b);
  if (!kind) return literal;
  // Dark navy/teal panel glass -> Anansi's warm near-black at the same brightness.
  const v = Math.max(r, g, b);
  const [R, G, B] = kind === 'dark' ? [v, Math.round(v * 0.9), Math.round(v * 0.8)] : target;
  if (m[7]) return `#${[R, G, B].map((v) => v.toString(16).padStart(2, '0')).join('')}`;
  const spaceSyntax = m[2] !== ',';
  if (m[6] === undefined) return spaceSyntax ? `rgb(${R} ${G} ${B})` : `rgb(${R}, ${G}, ${B})`;
  return spaceSyntax ? `rgb(${R} ${G} ${B} / ${m[6]})` : `rgba(${R}, ${G}, ${B}, ${m[6]})`;
}

export function recolorBlues(css) {
  return css.replace(/([\w-]+)(\s*:\s*)([^;{}]+)/g, (decl, prop, sep, value) => {
    ANY_COLOR.lastIndex = 0;
    if (!ANY_COLOR.test(value)) return decl;
    ANY_COLOR.lastIndex = 0;
    const target = TEXT_PROPS.test(prop.trim().toLowerCase()) ? GOLD : RED;
    return prop + sep + value.replace(ANY_COLOR, (lit) => swapColor(lit, target));
  });
}

export function recolor(css) {
  return recolorBlues(css
    .replace(CYAN_RGB, (_m, alpha) => (alpha ? `rgba(200, 30, 30${alpha.replace(/\s+/g, ' ').replace(/^,\s*/, ', ')})` : 'rgb(200, 30, 30)'))
    .replace(SKY_RGB, (_m, alpha) => (alpha ? `rgba(200, 30, 30${alpha.replace(/\s+/g, ' ').replace(/^,\s*/, ', ')})` : 'rgb(200, 30, 30)'))
    .replace(CYAN_HEX, '#c81e1e')
    .replace(CYAN_SPACE, (_m, alpha) => (alpha ? `rgb(200 30 30 ${alpha.trim()})` : 'rgb(200 30 30)')));
}

function countBlues(css) {
  let n = 0;
  for (const m of css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(ANY_COLOR)) {
    const lit = m[0];
    if (swapColor(lit, RED) !== lit) n += 1;
  }
  return n;
}

function main() {
  const check = process.argv.includes('--check');
  let remaining = 0;
  let changedFiles = 0;
  for (const file of FILES) {
    const before = readFileSync(file, 'utf8');
    const after = recolor(before);
    const hits = countBlues(before);
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
    console.log(remaining ? `${remaining} blue/cyan value(s) left — run without --check` : 'Anansi theme: no blue/cyan left');
    process.exit(remaining ? 1 : 0);
  }
  console.log(`done: ${changedFiles} file(s) recolored`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
