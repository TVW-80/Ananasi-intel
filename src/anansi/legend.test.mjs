import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTACK_TYPE_COLORS, LEGEND_757, LEGEND_LAYERS, legendGroups, swatchSvg } from './legend.js';
import { THREAT_LAYERS } from './threatLayers.js';
import { KINDS } from './hamptonRoadsLayer.js';
import { SERVICES } from '../../server/providers/anansi/attack-glossary.js';

test('legend icons and colours match the layers that draw them', () => {
  for (const l of LEGEND_LAYERS) {
    const real = THREAT_LAYERS.find((t) => t.id === l.id);
    assert.ok(real, l.id);
    assert.deepEqual([l.name, l.icon, l.color], [real.name, real.icon, real.color], l.id);
  }
  for (const id of THREAT_LAYERS.filter((t) => t.id !== 'history-sundown-towns').map((t) => t.id)) {
    assert.ok(LEGEND_LAYERS.some((l) => l.id === id), `${id} missing from the legend`);
  }
  for (const [k, v] of Object.entries(KINDS)) assert.deepEqual(LEGEND_757[k], v, k);
  for (const [k, [label, color]] of Object.entries(ATTACK_TYPE_COLORS)) {
    assert.deepEqual([label, color], [SERVICES[k].label, SERVICES[k].color], k);
  }
});

test('every legend row explains itself in both voices and draws a swatch', () => {
  for (const g of legendGroups()) {
    assert.ok(g.rows.length, g.id);
    for (const r of g.rows) {
      assert.ok(r.label && r.plain, `${g.id}: ${r.label}`);
      if (!['glyph', 'chip'].includes(r.shape)) assert.match(swatchSvg(r), /<svg/);
    }
  }
});
