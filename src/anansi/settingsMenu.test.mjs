import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MENU_OPEN_CLASS, initSettingsMenu } from './settingsMenu.js';

function fakeDoc() {
  const classes = new Set();
  const attrs = {};
  let handler = null;
  const button = {
    setAttribute: (k, v) => (attrs[k] = v),
    addEventListener: (_e, fn) => (handler = fn),
    removeEventListener: () => (handler = null),
  };
  const body = { classList: { toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)), contains: (c) => classes.has(c) } };
  return { doc: { body, getElementById: (id) => (id === 'ananzi-settings' ? button : null) }, classes, attrs, click: () => handler() };
}

test('the settings button starts closed and toggles the menu class', () => {
  const store = new Map();
  globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) };
  const { doc, classes, attrs, click } = fakeDoc();
  initSettingsMenu(doc);
  assert.equal(classes.has(MENU_OPEN_CLASS), false);
  assert.equal(attrs['aria-expanded'], 'false');
  click();
  assert.equal(classes.has(MENU_OPEN_CLASS), true);
  assert.equal(attrs['aria-expanded'], 'true');
  assert.equal(store.get('ananzi.settingsOpen'), '1');
  delete globalThis.localStorage;
});

test('closed menu hides every panel except the bottom dock', () => {
  const css = readFileSync(new URL('../ui/styles/anansi.css', import.meta.url), 'utf8');
  const block = css.slice(css.indexOf('body:not(.ananzi-menu-open) :is('));
  const list = block.slice(0, block.indexOf(') {'));
  for (const id of ['#data-panel', '#scene-panel', '#right-context-rail', '#pp-toggles', '#top-center-actions', '#view-control-toggle']) {
    assert.ok(list.includes(id), `${id} should be in the settings menu`);
  }
  for (const id of ['#command-dock', '#control-panel', '#location-bar']) assert.ok(!list.includes(id), `${id} must stay on screen`);
});
