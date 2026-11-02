/**
 * Ananzi SETTINGS: the gold spider button in the bottom-right corner.
 *
 * Closed (the default), the screen is just the globe, the HUD readouts, the
 * bottom dock (Location · AI agent · Visual Presets) and the small POWER UP
 * spider. Open, every panel and control comes back: Data Layers, Scenes, the
 * VIEW tab, Display, CCTV, Street Level, Context, Hampton Roads 757, AI
 * Security, the globe action buttons and the language picker. Layers stay on while the menu is closed.
 *
 * The body class `ananzi-menu-open` drives everything (src/ui/styles/anansi.css);
 * the open/closed choice is remembered in this browser.
 */
import { createFocusToggle } from './focus.js';

export const MENU_OPEN_CLASS = 'ananzi-menu-open';
const STORAGE_KEY = 'ananzi.settingsOpen';

export function initSettingsMenu(doc = document) {
  const button = doc.getElementById('ananzi-settings');
  if (!button) return () => {};
  const body = doc.body;

  const apply = (open) => {
    body.classList.toggle(MENU_OPEN_CLASS, open);
    // The label stays "Settings" (translated by the template); aria-expanded says open/closed.
    button.setAttribute('aria-expanded', String(open));
  };

  let restored = false;
  try {
    restored = localStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    // storage unavailable: start closed
  }
  apply(restored);

  const onClick = () => {
    const open = !body.classList.contains(MENU_OPEN_CLASS);
    apply(open);
    try {
      localStorage.setItem(STORAGE_KEY, open ? '1' : '0');
    } catch {
      // still works for this session
    }
  };
  button.addEventListener('click', onClick);
  return () => button.removeEventListener('click', onClick);
}

/** WORLD / 757 focus chip in the bottom-right corner row (always visible). */
export function initFocusChip(doc = document) {
  const row = doc.getElementById('corner-actions');
  if (!row || doc.getElementById('ananzi-focus')) return () => {};
  const chip = createFocusToggle(doc, 'ananzi-focus-btn ananzi-focus-chip');
  chip.id = 'ananzi-focus';
  row.prepend(chip);
  return () => {
    chip.dispose?.();
    chip.remove();
  };
}
