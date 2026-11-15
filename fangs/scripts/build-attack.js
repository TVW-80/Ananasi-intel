// Trim the full MITRE ATT&CK Enterprise STIX 2.1 bundle to the objects FANGS validates against.
// Usage: node scripts/build-attack.js <full-enterprise-attack.json> <out.json>
// Output remains a valid STIX 2.1 bundle: attack-pattern + x-mitre-tactic objects only, minimal properties.
import fs from 'node:fs';
const [,, inp, out] = process.argv;
if (!inp || !out) { console.error('usage: build-attack.js <in> <out>'); process.exit(2); }
const full = JSON.parse(fs.readFileSync(inp, 'utf8'));
const ext = (o) => (o.external_references || []).find((r) => r.source_name === 'mitre-attack');
const keep = [];
let collection = null;
for (const o of full.objects) {
  if (o.type === 'x-mitre-collection') collection = o;
  if (o.type === 'x-mitre-tactic') {
    const e = ext(o);
    keep.push({ type: o.type, spec_version: o.spec_version, id: o.id, name: o.name, x_mitre_shortname: o.x_mitre_shortname,
      external_references: e ? [{ source_name: 'mitre-attack', external_id: e.external_id, url: e.url }] : [] });
  } else if (o.type === 'attack-pattern') {
    const e = ext(o);
    if (!e) continue;
    keep.push({ type: o.type, spec_version: o.spec_version, id: o.id, name: o.name,
      kill_chain_phases: o.kill_chain_phases || [], x_mitre_is_subtechnique: !!o.x_mitre_is_subtechnique,
      x_mitre_deprecated: !!o.x_mitre_deprecated, revoked: !!o.revoked,
      external_references: [{ source_name: 'mitre-attack', external_id: e.external_id, url: e.url }] });
  }
}
const bundle = { type: 'bundle', id: full.id, spec_version: '2.1',
  x_fangs_source: { origin: 'https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)',
    attack_version: collection?.x_mitre_version || null, collection_modified: collection?.modified || null,
    trimmed_by: 'scripts/build-attack.js', note: 'Trimmed: attack-pattern and x-mitre-tactic only.' },
  objects: keep };
fs.writeFileSync(out, JSON.stringify(bundle));
const tech = keep.filter((o) => o.type === 'attack-pattern');
console.log(`kept ${keep.length} objects (${tech.length} techniques, ${keep.length - tech.length} tactics); ATT&CK v${bundle.x_fangs_source.attack_version}`);
