/**
 * Ananzi FANGS — MITRE ATT&CK mapping.
 *
 * A small, offline, keyless lookup that classifies the kinds of activity the
 * FANGS feeds surface into MITRE ATT&CK techniques (https://attack.mitre.org/),
 * so an analyst sees the tactic/technique behind an event and can open the
 * official page. Curated to the ~dozen techniques these feeds actually show —
 * not the whole matrix — and easy to extend. Pure; unit-tested in
 * attackTtp.test.mjs.
 *
 * ATT&CK® is a registered trademark of The MITRE Corporation; this is a
 * read-only reference with attribution, no endorsement implied.
 */

/** The techniques FANGS references, with their enterprise tactic. */
export const TECHNIQUES = Object.freeze({
  T1595: { id: 'T1595', name: 'Active Scanning', tacticId: 'TA0043', tacticName: 'Reconnaissance' },
  T1498: { id: 'T1498', name: 'Network Denial of Service', tacticId: 'TA0040', tacticName: 'Impact' },
  T1566: { id: 'T1566', name: 'Phishing', tacticId: 'TA0001', tacticName: 'Initial Access' },
  T1071: { id: 'T1071', name: 'Application Layer Protocol', tacticId: 'TA0011', tacticName: 'Command and Control' },
  T1105: { id: 'T1105', name: 'Ingress Tool Transfer', tacticId: 'TA0011', tacticName: 'Command and Control' },
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tacticId: 'TA0001', tacticName: 'Initial Access' },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tacticId: 'TA0040', tacticName: 'Impact' },
  T1557: { id: 'T1557', name: 'Adversary-in-the-Middle', tacticId: 'TA0006', tacticName: 'Credential Access' },
  T1133: { id: 'T1133', name: 'External Remote Services', tacticId: 'TA0001', tacticName: 'Initial Access' },
  T1110: { id: 'T1110', name: 'Brute Force', tacticId: 'TA0006', tacticName: 'Credential Access' },
  T1041: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tacticId: 'TA0010', tacticName: 'Exfiltration' },
  T1584: { id: 'T1584', name: 'Compromise Infrastructure', tacticId: 'TA0042', tacticName: 'Resource Development' },
});

/** The official attack.mitre.org page for a technique id (handles sub-techniques Txxxx.yyy). */
export function techniqueUrl(id) {
  const [base, sub] = String(id || '').split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

/**
 * The normalised "kind" of activity → its technique id and a plain capability
 * label (what the adversary is doing, in words).
 */
const KIND = Object.freeze({
  scanning: { tech: 'T1595', capability: 'Scanning / probing for targets' },
  bruteforce: { tech: 'T1110', capability: 'Password brute-forcing' },
  ddos: { tech: 'T1498', capability: 'Denial-of-service flood' },
  phishing: { tech: 'T1566', capability: 'Phishing lure' },
  c2: { tech: 'T1071', capability: 'Command-and-control channel' },
  malware: { tech: 'T1105', capability: 'Malware delivery' },
  botnet: { tech: 'T1584', capability: 'Botnet infrastructure' },
  exploit: { tech: 'T1190', capability: 'Exploiting a public-facing service' },
  ransomware: { tech: 'T1486', capability: 'Ransomware encryption' },
  hijack: { tech: 'T1557', capability: 'Traffic interception (route hijack)' },
  exposure: { tech: 'T1133', capability: 'Exposed remote service' },
  breach: { tech: 'T1041', capability: 'Data exfiltration' },
});

/** FANGS layer id → default kind. */
const LAYER_KIND = Object.freeze({
  'cyber-botnet-c2': 'c2',
  'cyber-reported-attackers': 'scanning',
  'cyber-ransomware': 'ransomware',
  'cyber-internet-outages': 'ddos',
  'cyber-outage-reports': 'ddos',
  'cyber-ics-exposure': 'exposure',
  'exposed-cameras': 'exposure',
  'cyber-attack-map': 'scanning',
});

/** Keyword hints (from an event's title / attack type) → kind, most-specific first. */
const HINTS = [
  [/ransomware|encrypt|lockbit|alphv|clop|akira/i, 'ransomware'],
  [/ddos|denial[- ]of[- ]service|flood|knocked\s+offline|outage/i, 'ddos'],
  [/phish|credential\s+harvest|fake\s+login/i, 'phishing'],
  [/hijack|route\s+leak|bgp|man[- ]in[- ]the[- ]middle|adversary[- ]in[- ]the[- ]middle/i, 'hijack'],
  [/botnet|c2|command[- ]and[- ]control|cobalt\s+strike|sliver/i, 'c2'],
  [/malware|trojan|loader|dropper|stealer/i, 'malware'],
  [/exploit|zero[- ]day|cve-\d|rce|vulnerab/i, 'exploit'],
  [/brute|password\s+spray|login\s+attempt/i, 'bruteforce'],
  [/breach|exfiltrat|data\s+theft|stolen\s+data|leak/i, 'breach'],
  [/exposed|open\s+port|unauthenticated|internet[- ]facing/i, 'exposure'],
  [/scan|probe|recon/i, 'scanning'],
];

/** Work out the activity kind from a layer id and free-text hints. */
export function classifyKind(layerId, hints = '') {
  const text = String(hints || '');
  for (const [re, kind] of HINTS) if (re.test(text)) return kind;
  return LAYER_KIND[layerId] || 'scanning';
}

/**
 * The ATT&CK mapping for an event.
 * @returns {{kind, capability, technique:{id,name,tacticId,tacticName}, url}}
 */
export function ttpFor(layerId, hints = '') {
  const kind = classifyKind(layerId, hints);
  const entry = KIND[kind] || KIND.scanning;
  const technique = TECHNIQUES[entry.tech];
  return {
    kind,
    capability: entry.capability,
    technique,
    url: techniqueUrl(technique.id),
  };
}
