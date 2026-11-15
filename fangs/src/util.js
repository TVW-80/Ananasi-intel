// Small shared helpers: IP/domain validation, hashing, seeded RNG, family normalisation.
import net from 'node:net';
import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const sha1short = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 12);

// Deterministic PRNG (mulberry32) so fixtures, layouts and Louvain are reproducible.
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Only publicly routable IPv4/IPv6 become nodes. Private/reserved space in a feed is a data-quality
// problem (or a sinkhole), never infrastructure we should graph.
export function isPublicIP(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && ip.startsWith('192.0.0.')) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (v === 6) {
    const l = ip.toLowerCase();
    return !(l === '::' || l === '::1' || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') || l.startsWith('fc') || l.startsWith('fd'));
  }
  return false;
}

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
export function normDomain(d) {
  if (typeof d !== 'string') return null;
  const x = d.trim().toLowerCase().replace(/\.$/, '');
  if (!x || net.isIP(x) || !DOMAIN_RE.test(x)) return null;
  return x;
}

export function hostFromUrl(u) {
  try {
    const h = new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return h || null;
  } catch { return null; }
}

// "Possible Cobaltstrike C2 IP" / "win.cobalt_strike" / "Cobalt Strike" -> "cobaltstrike"
export function famKey(s) {
  if (!s) return null;
  const x = String(s).toLowerCase().replace(/^(win|elf|osx|apk|jar|js|php|ps1)\./, '').replace(/[^a-z0-9]/g, '');
  return x || null;
}
const FAMILY_LABELS = { cobaltstrike: 'Cobalt Strike', sliver: 'Sliver', havoc: 'Havoc', qakbot: 'QakBot', emotet: 'Emotet', mirai: 'Mirai',
  dridex: 'Dridex', icedid: 'IcedID', asyncrat: 'AsyncRAT', remcos: 'Remcos', bruteratel: 'Brute Ratel', mythic: 'Mythic', metasploit: 'Metasploit',
  trickbot: 'TrickBot', bumblebee: 'Bumblebee', pikabot: 'PikaBot', lumma: 'Lumma Stealer', redline: 'RedLine' };
export const famLabel = (k) => FAMILY_LABELS[k] || k;

export const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
export const findCVEs = (...parts) => [...new Set(parts.flat().filter(Boolean).join(' ').match(CVE_RE)?.map((c) => c.toUpperCase()) || [])];

export const nowIso = () => new Date().toISOString();
export const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
