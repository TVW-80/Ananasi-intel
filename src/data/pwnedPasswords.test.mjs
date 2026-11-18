import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { splitHash, parseRange, checkPassword } from './pwnedPasswords.js';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PW_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';

test('splitHash separates the 5-char range prefix from the suffix', () => {
  assert.deepEqual(splitHash(PW_HASH), { prefix: '5BAA6', suffix: '1E4C9B93F3F0682250B6CF8331B7EE68FD8' });
  assert.deepEqual(splitHash('abc'), { prefix: 'ABC', suffix: '' });
});

test('parseRange finds a suffix count case-insensitively, ignores padding/junk', () => {
  const body = [
    '0018A45C4D1DEF81644B54AB7F969B88D65:1', // padding-style noise
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824', // "password"
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0',
  ].join('\r\n');
  assert.equal(parseRange(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8'), 9545824);
  assert.equal(parseRange(body, 'deadbeef'), 0);
  assert.equal(parseRange('', 'x'), 0);
});

test('checkPassword sends ONLY the 5-char prefix and matches locally', async () => {
  const digest = async (text) => createHash('sha1').update(text).digest('hex');
  let requestedUrl = '';
  const fetchImpl = async (url) => {
    requestedUrl = url;
    return { ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\nAAAA...:0' };
  };
  const out = await checkPassword('password', { fetchImpl, digest });
  assert.equal(out.count, 42);
  assert.equal(out.pwned, true);
  // Privacy guarantee: the request carries the 5-char prefix only — never the
  // password, the full hash, or the matching suffix.
  assert.equal(requestedUrl, 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.ok(!requestedUrl.includes(PW_HASH));
  assert.ok(!requestedUrl.includes('1E4C9B93F3F0682250B6CF8331B7EE68FD8')); // the suffix
});

test('checkPassword reports a clean password and short-circuits empty input', async () => {
  const digest = async (text) => createHash('sha1').update(text).digest('hex');
  const fetchImpl = async () => ({ ok: true, text: async () => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3' });
  const clean = await checkPassword('a-very-unique-passphrase-xyz', { fetchImpl, digest });
  assert.deepEqual([clean.count, clean.pwned], [0, false]);
  assert.deepEqual(await checkPassword('', { fetchImpl, digest }), { count: 0, pwned: false, prefix: '' });
});
