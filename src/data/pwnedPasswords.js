/**
 * Ananzi FANGS — Have I Been Pwned "Pwned Passwords" check (k-anonymity).
 *
 * Privacy by design: the password is SHA-1'd in the browser, and only the
 * FIRST FIVE hex characters of that hash are ever sent to HIBP. The service
 * returns every hash suffix that shares those five characters, and we match
 * the rest locally. The password — and its full hash — never leave the device.
 * Keyless; no account, no API key.
 *
 * Pure helpers (splitHash/parseRange) are unit-tested; the hashing uses Web
 * Crypto in the browser and an injectable digest for tests.
 */

const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/** Split a 40-char SHA-1 hex into the 5-char range prefix and the suffix. */
export function splitHash(sha1Hex) {
  const h = String(sha1Hex || '').trim().toUpperCase();
  return { prefix: h.slice(0, 5), suffix: h.slice(5) };
}

/**
 * Find a suffix's breach count in a range response ("SUFFIX:COUNT" per line).
 * Case-insensitive; padding rows (count 0) and junk lines are ignored.
 */
export function parseRange(text, suffix) {
  const want = String(suffix || '').trim().toUpperCase();
  if (!want) return 0;
  for (const line of String(text || '').split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    if (line.slice(0, idx).trim().toUpperCase() === want) return Number(line.slice(idx + 1).trim()) || 0;
  }
  return 0;
}

/** Default digest: SHA-1 hex via Web Crypto (browser). */
async function webCryptoSha1(text) {
  const bytes = new TextEncoder().encode(text);
  const buf = await globalThis.crypto.subtle.digest('SHA-1', bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Check one password against HIBP without revealing it.
 * @returns {Promise<{count:number, pwned:boolean, prefix:string}>}
 */
export async function checkPassword(password, { fetchImpl = (...a) => globalThis.fetch(...a), digest = webCryptoSha1 } = {}) {
  if (!password) return { count: 0, pwned: false, prefix: '' };
  const { prefix, suffix } = splitHash(await digest(password));
  // Add-Padding makes every response a uniform size, so the five-char prefix
  // reveals nothing about how many real matches there are.
  const res = await fetchImpl(`${RANGE_URL}${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const count = parseRange(await res.text(), suffix);
  return { count, pwned: count > 0, prefix };
}
