import { ed25519 } from '@noble/curves/ed25519.js';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { bytes, integer, be, le, mod, utf8, cat, xor, u32, sha256, sha1, hmac, pbkdf2, dk, prfPlus, cf2, seq, ctx, der, derInt, equal, requireTrue } from './primitives.mjs';

const E = ed25519.Point;
const M = E.fromHex('d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf', false);
const N = E.fromHex('d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab', false);
const q = (1n << 252n) + 27742317777372353535851937790883648493n;
const scalar = (input) => mod(le(input), q);
const encode = (p) => p.toBytes();
function point(input) {
  const p = E.fromBytes(input, false);
  p.assertValidity();
  requireTrue(!p.equals(E.ZERO) && p.isTorsionFree(), 'Reject identity or non-subgroup Edwards point');
  return p;
}
const initialKey = (password, salt, iterations) => dk(pbkdf2(sha1, utf8(password), utf8(salt), { c: iterations, dkLen: 16 }), utf8('kerberos'));
const support = () => ctx(0, seq(ctx(0, seq(derInt(1)))));
const factor = () => seq(ctx(0, derInt(1)));
const challenge = (T) => ctx(1, seq(ctx(0, derInt(1)), ctx(1, der(4, T)), ctx(2, seq(factor()))));
function requestBody() {
  const str = (s) => der(0x1b, utf8(s));
  const principal = (type, names) => seq(ctx(0, derInt(type)), ctx(1, seq(...names.map(str))));
  return seq(ctx(0, der(3, bytes('0000000000'))), ctx(1, principal(1, ['raeburn'])), ctx(2, str('ATHENA.MIT.EDU')), ctx(3, principal(2, ['krbtgt', 'ATHENA.MIT.EDU'])), ctx(5, der(0x18, utf8('19700101000000Z'))), ctx(7, derInt(0)), ctx(8, seq(derInt(17))));
}
function derive(key, w, K, transcript, body, n) {
  const intermediate = sha256(cat(utf8('SPAKEkey'), u32(1), u32(17), w, K, transcript, body, u32(n), Uint8Array.of(1))).subarray(0, key.length);
  return cf2(key, intermediate, 'SPAKE', 'keyderiv');
}
function exchange(f, clientPassword = f.password, changedBody = false) {
  const key = initialKey(f.password, f.salt, f.iterations), clientKey = initialKey(clientPassword, f.salt, f.iterations);
  const pepper = cat(utf8('SPAKEsecret'), u32(1));
  const w = prfPlus(key, pepper, 32), clientW = prfPlus(clientKey, pepper, 32);
  const xRaw = le(bytes(f.x)), yRaw = le(bytes(f.y));
  requireTrue(xRaw % 8n === 0n && yRaw % 8n === 0n && xRaw < 8n * q && yRaw < 8n * q, 'Ephemerals are cofactor multiples within group order');
  const x = mod(xRaw, q), y = mod(yRaw, q);
  const X = E.BASE.multiply(x), Y = E.BASE.multiply(y);
  const T = X.add(M.multiply(scalar(w))), S = Y.add(N.multiply(scalar(clientW)));
  const K = point(encode(S)).subtract(N.multiply(scalar(w))).multiply(x);
  const clientK = point(encode(T)).subtract(M.multiply(scalar(clientW))).multiply(y);
  const encodedSupport = support(), encodedChallenge = challenge(encode(T));
  const afterChallenge = sha256(cat(new Uint8Array(32), encodedSupport, encodedChallenge));
  const transcript = sha256(cat(afterChallenge, encode(S)));
  const body = requestBody(), clientBody = Buffer.from(body);
  if (changedBody) clientBody[clientBody.length - 1] ^= 1;
  const keys = Array.from({ length: 4 }, (_, n) => derive(key, w, encode(K), transcript, body, n));
  const clientKeys = Array.from({ length: 4 }, (_, n) => derive(clientKey, clientW, encode(clientK), transcript, clientBody, n));
  return { key, w, X, Y, T, S, K, clientK, encodedSupport, encodedChallenge, afterChallenge, transcript, body, keys, clientKeys };
}
// Only the deterministic 23-byte synthetic SF-NONE input is supported here.
// The fixed confounder is public QA material, never a production encryption API.
function protectedFactor(key) {
  const clear = cat(bytes('000102030405060708090a0b0c0d0e0f'), factor());
  const cipher = createCipheriv('aes-128-cbc', dk(key, cat(u32(65), Uint8Array.of(0xaa))), new Uint8Array(16));
  cipher.setAutoPadding(false);
  const padded = cat(clear, new Uint8Array(32 - clear.length));
  const cbc = cat(cipher.update(padded), cipher.final());
  const ciphertext = cat(cbc.subarray(16), cbc.subarray(0, clear.length - 16));
  const mac = hmac(sha1, dk(key, cat(u32(65), Uint8Array.of(0x55))), clear).subarray(0, 12);
  return cat(ciphertext, mac);
}
function unwrapFactor(key, protectedValue) {
  const cipher = protectedValue.subarray(0, -12), tag = protectedValue.subarray(-12);
  requireTrue(cipher.length === 23, 'Synthetic protected factor ciphertext length');
  const ke = dk(key, cat(u32(65), Uint8Array.of(0xaa)));
  const decryptBlock = (b) => { const d = createDecipheriv('aes-128-ecb', ke, null); d.setAutoPadding(false); return cat(d.update(b), d.final()); };
  const d2 = decryptBlock(cipher.subarray(0, 16)), c1 = cat(cipher.subarray(16), d2.subarray(7));
  const clear = cat(decryptBlock(c1), xor(d2.subarray(0, 7), c1.subarray(0, 7)));
  const expected = hmac(sha1, dk(key, cat(u32(65), Uint8Array.of(0x55))), clear).subarray(0, 12);
  if (!equal(tag, expected)) throw new Error('SF-NONE integrity rejected');
  requireTrue(equal(clear.subarray(16), factor()), 'Decoded SF-NONE DER');
  return clear;
}
export function registerKerberos(add, fixtures) {
  const f = fixtures.rfc9588, source = 'RFC 9588 sections 4-7,12.2.2.1 and Appendix C aes128-cts-hmac-sha1-96 edwards25519; RFC 3961/3962; RFC 6113 section 5.1';
  add(f.id, source, (check) => {
    const c = E.CURVE();
    requireTrue(c.p === (1n << 255n) - 19n && c.n === q && c.h === 8n && mod(c.a + 1n, c.p) === 0n, 'Edwards field, scalar order, cofactor, a');
    requireTrue(mod(c.d * 121666n + 121665n, c.p) === 0n, 'Edwards d=-121665/121666');
    check('Edwards base encoding', encode(E.BASE), bytes('5866666666666666666666666666666666666666666666666666666666666666'));
    requireTrue(point(encode(M)).equals(M) && point(encode(N)).equals(N), 'Mask subgroup validation');
    const v = exchange(f);
    check('password PBKDF2+DK', v.key, bytes(f.key));
    check('w full PRF+ output', v.w, bytes(f['w (PRF+ output)']));
    check('w reduced scalar little-endian', integer(scalar(v.w), 32, true), bytes(f['w (reduced multiplier)']));
    for (const name of ['X', 'Y', 'T', 'S', 'K']) check(name, encode(v[name]), bytes(f[name]));
    check('client shared K', encode(v.clientK), bytes(f.K));
    check('DER support', v.encodedSupport, bytes(f.SPAKESupport));
    check('DER challenge', v.encodedChallenge, bytes(f.SPAKEChallenge));
    check('hash after challenge', v.afterChallenge, bytes(f['Transcript hash after challenge']));
    check('hash after pubkey', v.transcript, bytes(f['Final transcript hash after pubkey']));
    check('DER request body', v.body, bytes(f['KDC-REQ-BODY']));
    for (let n = 0; n < 4; n++) { check(`KDC K'[${n}]`, v.keys[n], bytes(f[`K'[${n}]`])); check(`client K'[${n}]`, v.clientKeys[n], bytes(f[`K'[${n}]`])); }
  });
  add(`${f.id}-synthetic-protected-factor`, source, (check) => {
    const v = exchange(f), ciphertext = protectedFactor(v.clientKeys[1]);
    check('AES-CTS and HMAC-SHA1-96 SF-NONE', ciphertext, bytes(fixtures.synthetic.kerberos.protectedFactor));
    unwrapFactor(v.keys[1], ciphertext);
  });
  add(`${f.id}-password-mismatch`, source, (check) => {
    const v = exchange(f, `${f.password}!`);
    const expected = fixtures.synthetic.kerberos.passwordMismatch;
    check('independent wrong-password KDC K', encode(v.K), bytes(expected.KDC.K));
    check('independent wrong-password client K', encode(v.clientK), bytes(expected.client.K));
    for (let n = 0; n < 4; n++) {
      check(`independent KDC mismatched K'[${n}]`, v.keys[n], bytes(expected.KDC.keys[n]));
      check(`independent client mismatched K'[${n}]`, v.clientKeys[n], bytes(expected.client.keys[n]));
    }
    requireTrue(!equal(encode(v.K), encode(v.clientK)), 'Wrong initial reply key must disagree on group secret');
    const protectedValue = protectedFactor(v.clientKeys[1]);
    check('independent wrong-password protected factor', protectedValue, bytes(expected.client.protectedFactor));
    let rejected = false;
    try { unwrapFactor(v.keys[1], protectedValue); } catch { rejected = true; }
    requireTrue(rejected, 'KDC must reject factor integrity under wrong password');
  });
  add(`${f.id}-transcript-mismatch`, source, (check) => {
    const v = exchange(f, f.password, true);
    const expected = fixtures.synthetic.kerberos.transcriptMismatch;
    for (let n = 0; n < 4; n++) {
      check(`independent KDC request-bound K'[${n}]`, v.keys[n], bytes(expected.KDC.keys[n]));
      check(`independent client request-bound K'[${n}]`, v.clientKeys[n], bytes(expected.client.keys[n]));
    }
    check('independent mismatched-body protected factor', protectedFactor(v.clientKeys[1]), bytes(expected.client.protectedFactor));
    requireTrue(equal(encode(v.K), encode(v.clientK)), 'Request-body mismatch leaves group secret unchanged');
    requireTrue(!equal(v.keys[0], v.clientKeys[0]) && !equal(v.keys[1], v.clientKeys[1]), 'Request body must bind reply and factor keys');
    let rejected = false;
    try { unwrapFactor(v.keys[1], protectedFactor(v.clientKeys[1])); } catch { rejected = true; }
    requireTrue(rejected, 'Mismatched request-body binding rejects factor');
  });
  add(`${f.id}-transcript-reset`, source, () => {
    const v = exchange(f), stale = sha256(cat(v.transcript, v.encodedSupport, v.encodedChallenge));
    requireTrue(!equal(stale, v.afterChallenge), 'Retry must restart transcript from zero');
    const bad = derive(v.key, v.w, encode(v.K), sha256(cat(stale, encode(v.S))), v.body, 0);
    requireTrue(!equal(bad, v.keys[0]), 'Stale transcript changes strengthened reply key');
  });
  add(`${f.id}-invalid-point`, source, () => {
    for (const input of [new Uint8Array(31), new Uint8Array(32).fill(255), bytes('0100000000000000000000000000000000000000000000000000000000000000'), new Uint8Array(32)]) {
      let rejected = false;
      try { point(input); } catch { rejected = true; }
      requireTrue(rejected, 'Malformed, noncanonical, identity or low-order Edwards point must reject');
    }
  });
  add(`${f.id}-directional-key-use`, source, () => {
    const v = exchange(f);
    let rejected = false;
    try { unwrapFactor(v.keys[2], protectedFactor(v.keys[1])); } catch { rejected = true; }
    requireTrue(rejected, 'Reflected factor using opposite direction key must reject');
  });
}
