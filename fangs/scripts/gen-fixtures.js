// Writes the bundled SYNTHETIC fixtures. Deterministic: same seed => byte-identical output.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateCampaigns } from '../src/fixtures.js';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'fixtures');
fs.mkdirSync(OUT, { recursive: true });
const c = generateCampaigns({ seed: 1 });
fs.writeFileSync(path.join(OUT, 'campaign-replay.seed1.json'), JSON.stringify({ synthetic: true, note: 'SYNTHETIC. Documentation IP ranges / ASNs, .example domains. Not real threat data.', ...c }, null, 1));

// KEV/EPSS SAMPLE: illustrative values only, used when the live CISA/FIRST endpoints are unreachable.
const sample = {
  synthetic: true,
  note: 'SAMPLE values for offline operation and tests. NOT authoritative CISA KEV / FIRST EPSS data. Live fetch replaces this when reachable.',
  kev: ['CVE-2021-44228', 'CVE-2023-4966', 'CVE-2024-3400', 'CVE-2023-34362'],
  epss: { 'CVE-2021-44228': 0.97, 'CVE-2023-4966': 0.94, 'CVE-2024-3400': 0.96, 'CVE-2023-34362': 0.95, 'CVE-2022-0001': 0.02, 'CVE-2020-1234': 0.11 },
};
fs.writeFileSync(path.join(OUT, 'kev-epss.sample.json'), JSON.stringify(sample, null, 1));
console.log('fixtures written to', OUT);
