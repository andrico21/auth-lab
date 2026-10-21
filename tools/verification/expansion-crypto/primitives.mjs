import { createCipheriv, timingSafeEqual } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha1, md5 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';

export { sha256, sha1, md5, hmac, pbkdf2 };
export const utf8 = (s) => Buffer.from(s, 'utf8');
export const hex = (v) => Buffer.from(v).toString('hex');
export function bytes(s) {
  if (typeof s !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(s)) throw new Error('Non-canonical hex fixture');
  return Buffer.from(s, 'hex');
}
export const cat = (...v) => Buffer.concat(v.map((x) => Buffer.from(x)));
export const be = (v) => BigInt(`0x${hex(v) || '0'}`);
export const le = (v) => be(Buffer.from(v).reverse());
export const mod = (x, n) => ((x % n) + n) % n;
export function integer(x, size, little = false) {
  const s = x.toString(16).padStart(size * 2, '0');
  if (x < 0n || s.length !== size * 2) throw new Error('Integer encoding overflow');
  const out = bytes(s);
  return little ? out.reverse() : out;
}
export const u32 = (n) => integer(BigInt(n), 4);
export const framed = (...v) => cat(...v.flatMap((x) => [integer(BigInt(x.length), 8, true), x]));
export const kdf = (ikm, info, size) => hkdf(sha256, ikm, new Uint8Array(), utf8(info), size);
export function equal(a, b) { return a.length === b.length && timingSafeEqual(a, b); }
export function requireEqual(a, b, label) {
  if (!equal(a, b)) throw new Error(`${label}: computed value differs from independent expectation`);
}
export function requireTrue(v, label) { if (!v) throw new Error(label); }
export const xor = (a, b) => {
  if (a.length !== b.length) throw new Error('XOR length mismatch');
  return Buffer.from(a.map((v, i) => v ^ b[i]));
};
export function aesBlock(key, data) {
  if (![16, 32].includes(key.length) || data.length !== 16) throw new Error('AES fixture size');
  const cipher = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  cipher.setAutoPadding(false);
  return cat(cipher.update(data), cipher.final());
}

// RFC 3961 section 5.1: concatenate 13-bit right-rotations to the LCM,
// then sum output-sized chunks using end-around carry (one's complement).
export function nfold(input, size) {
  const a = input.length * 8, b = size * 8;
  const gcd = (x, y) => y === 0 ? x : gcd(y, x % y);
  const lcm = a * b / gcd(a, b);
  const maskA = (1n << BigInt(a)) - 1n, maskB = (1n << BigInt(b)) - 1n;
  let value = be(input), joined = 0n;
  for (let i = 0; i < lcm / a; i++) {
    joined = (joined << BigInt(a)) | value;
    const shift = 13 % a;
    value = ((value >> BigInt(shift)) | (value << BigInt(a - shift))) & maskA;
  }
  let sum = 0n;
  for (let i = 0; i < lcm / b; i++) { sum += joined & maskB; joined >>= BigInt(b); }
  while (sum > maskB) sum = (sum & maskB) + (sum >> BigInt(b));
  return integer(sum, size);
}
export function dk(key, constant) {
  let block = constant.length === 16 ? constant : nfold(constant, 16);
  const out = [];
  for (let n = 0; n < key.length; n += 16) { block = aesBlock(key, block); out.push(block); }
  return cat(...out).subarray(0, key.length);
}
// AES-SHA1 simplified-profile PRF truncates SHA1 to the AES cipher block
// size, not the byte-granularity message padding unit (MIT prf_dk.c).
export const aesPrf = (key, input) => aesBlock(dk(key, utf8('prf')), sha1(input).subarray(0, 16));
export function prfPlus(key, pepper, size) {
  const out = [];
  for (let counter = 1; out.length * 16 < size; counter++) {
    if (counter > 255) throw new Error('PRF+ counter overflow');
    out.push(aesPrf(key, cat(Uint8Array.of(counter), pepper)));
  }
  return cat(...out).subarray(0, size);
}
export const cf2 = (key1, key2, pepper1, pepper2) => xor(prfPlus(key1, utf8(pepper1), key1.length), prfPlus(key2, utf8(pepper2), key1.length));

export function der(tag, ...parts) {
  const body = cat(...parts);
  let length = integer(BigInt(body.length), Math.max(1, Math.ceil(body.length.toString(16).length / 2)));
  if (body.length >= 128) length = cat(Uint8Array.of(0x80 | length.length), length);
  return cat(Uint8Array.of(tag), length, body);
}
export const seq = (...parts) => der(0x30, ...parts);
export const ctx = (tag, value) => der(0xa0 + tag, value);
export function derInt(n) {
  let v = integer(BigInt(n), Math.max(1, Math.ceil(n.toString(16).length / 2)));
  if (v[0] & 0x80) v = cat(Uint8Array.of(0), v);
  return der(2, v);
}
