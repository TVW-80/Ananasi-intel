// MITRE ATT&CK: load the bundled STIX 2.1 bundle (trimmed from enterprise-attack), validate technique IDs against it,
// and map FANGS event behaviour -> techniques with a deterministic rule set. LLM suggestions are accepted only if
// they validate against the same bundle.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_STIX = path.join(HERE, '..', 'data', 'attack-enterprise-trimmed.json');

export class AttackCatalog {
  constructor(bundle) {
    this.meta = bundle.x_fangs_source || {};
    this.tactics = new Map();      // shortname -> {name, id}
    this.techniques = new Map();   // Txxxx(.yyy) -> {id, name, tactics[], revoked, deprecated, url}
    for (const o of bundle.objects) {
      const ext = (o.external_references || []).find((r) => r.source_name === 'mitre-attack');
      if (o.type === 'x-mitre-tactic' && ext) this.tactics.set(o.x_mitre_shortname, { id: ext.external_id, name: o.name });
      if (o.type === 'attack-pattern' && ext) {
        this.techniques.set(ext.external_id, {
          id: ext.external_id, name: o.name, sub: !!o.x_mitre_is_subtechnique, revoked: !!o.revoked, deprecated: !!o.x_mitre_deprecated,
          tactics: (o.kill_chain_phases || []).filter((k) => k.kill_chain_name === 'mitre-attack').map((k) => k.phase_name), url: ext.url,
        });
      }
    }
  }
  static load(file = DEFAULT_STIX) { return new AttackCatalog(JSON.parse(fs.readFileSync(file, 'utf8'))); }
  // "Valid" = present in the bundle and neither revoked nor deprecated.
  isValid(id) { const t = this.techniques.get(String(id).toUpperCase()); return !!t && !t.revoked && !t.deprecated; }
  describe(id) {
    const t = this.techniques.get(String(id).toUpperCase());
    if (!t) return null;
    return { id: t.id, name: t.name, tactics: t.tactics.map((s) => this.tactics.get(s)?.name || s), url: t.url };
  }
  validate(ids) {
    const valid = [], invalid = [];
    for (const id of ids) (this.isValid(id) ? valid : invalid).push(String(id).toUpperCase());
    return { valid: [...new Set(valid)], invalid: [...new Set(invalid)] };
  }
}

// Deterministic rule table: [predicate, [technique ids], rationale]. Rationale text is shown to the analyst.
const RULES = [
  [(e) => e.kind === 'c2' || e.kind === 'botnet', ['T1071.001', 'T1583.001'], 'Command-and-control over web protocols using adversary-acquired domains/infrastructure.'],
  [(e) => (e.kind === 'c2' || e.kind === 'botnet') && !!e.ip && !e.host, ['T1583.003'], 'Indicator is a bare IP, consistent with leased VPS infrastructure.'],
  [(e) => e.kind === 'c2' && /fronted|fronting/i.test((e.tags || []).join(' ')), ['T1090.004'], 'Feed flags domain fronting, which hides C2 behind a legitimate CDN-hosted domain.'],
  [(e) => e.family === 'cobaltstrike', ['T1573.002', 'T1105'], 'Cobalt Strike beacons use encrypted channels and stage/transfer tooling.'],
  [(e) => e.kind === 'phish', ['T1566.002', 'T1204.001'], 'Phishing URL delivered to users, requiring a click on a malicious link.'],
  [(e) => e.kind === 'malware-url', ['T1105', 'T1204.002'], 'Hosted payload retrieved onto a victim host (ingress tool transfer / user-executed file).'],
  [(e) => e.kind === 'malware-url' && (e.cve || []).length > 0, ['T1190'], 'Associated CVE suggests exploitation of a public-facing application.'],
  [(e) => e.kind === 'scan', ['T1595.002', 'T1595.001'], 'Mass internet scanning observed by DShield sensors.'],
];

export function mapEvent(event, catalog) {
  const seen = new Map();
  for (const [pred, ids, why] of RULES) {
    let hit = false;
    try { hit = pred(event); } catch { hit = false; }
    if (!hit) continue;
    for (const id of ids) if (!seen.has(id)) seen.set(id, why);
  }
  const out = [];
  for (const [id, why] of seen) {
    if (!catalog.isValid(id)) continue; // never emit a technique the bundled STIX doesn't back
    out.push({ ...catalog.describe(id), basis: 'rule', why });
  }
  return out;
}
export const RULE_TECHNIQUE_IDS = [...new Set(RULES.flatMap(([, ids]) => ids))];
