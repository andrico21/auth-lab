import { p256 } from '@noble/curves/nist.js';
import { bytes, hex, be, integer, utf8, cat, framed, sha256, hmac, kdf, equal, requireTrue } from './primitives.mjs';

const P = p256.Point;
const M = P.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = P.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');
const scalar = (s) => be(bytes(s));
const encode = (p) => p.toBytes(false);
const scalarBytes = (n) => integer(n, 32);
function point(encoded) {
  const p = P.fromBytes(encoded);
  p.assertValidity();
  requireTrue(!p.equals(P.ZERO) && p.isTorsionFree(), 'Reject identity or non-subgroup point');
  return p;
}
function params(check) {
  const c = P.CURVE();
  check('field prime', integer(c.p, 32), bytes('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'));
  check('group order', integer(c.n, 32), bytes('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'));
  requireTrue(c.h === 1n, 'P-256 cofactor');
  check('curve a', integer(c.a, 32), bytes('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'));
  check('curve b', integer(c.b, 32), bytes('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'));
  check('base point', encode(P.BASE), bytes('046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'));
  requireTrue(point(M.toBytes()).equals(M) && point(N.toBytes()).equals(N), 'Valid mask points');
}
function balanced(f, wA = scalar(f.w), wB = scalar(f.w), identityB = f.B) {
  const x = scalar(f.x), y = scalar(f.y);
  const pA = P.BASE.multiply(x).add(M.multiply(wA));
  const pB = P.BASE.multiply(y).add(N.multiply(wB));
  const KA = point(encode(pB)).subtract(N.multiply(wA)).multiply(x);
  const KB = point(encode(pA)).subtract(M.multiply(wB)).multiply(y);
  const t = (K, w, binding) => framed(utf8(f.A), utf8(binding), encode(pA), encode(pB), encode(K), scalarBytes(w));
  const schedule = (TT) => {
    const hash = sha256(TT), Ke = hash.subarray(0, 16), Ka = hash.subarray(16);
    const kc = kdf(Ka, 'ConfirmationKeys', 32), KcA = kc.subarray(0, 16), KcB = kc.subarray(16);
    return { TT, hash, Ke, Ka, KcA, KcB, cA: hmac(sha256, KcA, TT), cB: hmac(sha256, KcB, TT) };
  };
  return { pA, pB, KA, KB, A: schedule(t(KA, wA, identityB)), B: schedule(t(KB, wB, f.B)) };
}
function augmented(f, wP = scalar(f.w0), wV = scalar(f.w0), w1 = scalar(f.w1), context = f.context) {
  const x = scalar(f.x), y = scalar(f.y);
  // Verifier receives only the independently provisioned record, never w1.
  const L = point(bytes(f.L));
  const shareP = P.BASE.multiply(x).add(M.multiply(wP));
  const shareV = P.BASE.multiply(y).add(N.multiply(wV));
  const unmaskedV = point(encode(shareV)).subtract(N.multiply(wP));
  const ZP = unmaskedV.multiply(x), VP = unmaskedV.multiply(w1);
  const ZV = point(encode(shareP)).subtract(M.multiply(wV)).multiply(y), VV = L.multiply(y);
  const schedule = (Z, V, w, binding) => {
    const TT = framed(utf8(binding), utf8(f.idProver), utf8(f.idVerifier), encode(M), encode(N), encode(shareP), encode(shareV), encode(Z), encode(V), scalarBytes(w));
    const K_main = sha256(TT), kc = kdf(K_main, 'ConfirmationKeys', 64);
    const K_confirmP = kc.subarray(0, 32), K_confirmV = kc.subarray(32);
    return { TT, K_main, K_confirmP, K_confirmV, K_shared: kdf(K_main, 'SharedKey', 32), confirmP: hmac(sha256, K_confirmP, encode(shareV)), confirmV: hmac(sha256, K_confirmV, encode(shareP)) };
  };
  return { L: P.BASE.multiply(w1), shareP, shareV, ZP, ZV, VP, VV, P: schedule(ZP, VP, wP, context), V: schedule(ZV, VV, wV, f.context) };
}
function rejectsInvalid() {
  for (const input of [new Uint8Array(65), cat(Uint8Array.of(4), new Uint8Array(64)), Uint8Array.of(0), cat(Uint8Array.of(2), new Uint8Array(32).fill(255))]) {
    let rejected = false;
    try { point(input); } catch { rejected = true; }
    requireTrue(rejected, `Invalid P-256 point accepted (${hex(input).slice(0, 12)})`);
  }
}
export function registerPake(add, fixtures) {
  const b = fixtures.rfc9382, a = fixtures.rfc9383;
  const bs = 'RFC 9382 sections 3.2-4,6; Appendix B first vector';
  const as = 'RFC 9383 sections 3.2-4; Appendix C first vector';
  add(b.id, bs, (check) => {
    params(check);
    const v = balanced(b);
    for (const name of ['pA', 'pB']) check(name, encode(v[name]), bytes(b[name]));
    check('K from A', encode(v.KA), bytes(b.K)); check('K from B', encode(v.KB), bytes(b.K));
    for (const role of ['A', 'B']) {
      for (const name of ['TT', 'Ke', 'Ka', 'KcA', 'KcB']) check(`${role} ${name}`, v[role][name], bytes(b[name]));
      check(`${role} Hash(TT)`, v[role].hash, bytes(b['HASH(TT)']));
      check(`${role} cA`, v[role].cA, bytes(b['A conf'])); check(`${role} cB`, v[role].cB, bytes(b['B conf']));
    }
  });
  add(`${b.id}-password-mismatch`, bs, (check) => {
    const v = balanced(b, scalar(b.w) + 1n);
    const expected = fixtures.synthetic.rfc9382.passwordMismatch;
    for (const role of ['A', 'B']) {
      check(`${role} independent mismatched K`, encode(v[`K${role}`]), bytes(expected[role].K));
      for (const tag of ['cA', 'cB']) check(`${role} independent ${tag}`, v[role][tag], bytes(expected[role][tag]));
    }
    requireTrue(!equal(encode(v.KA), encode(v.KB)), 'Different password masks must disagree on K');
    requireTrue(!equal(v.A.cA, v.B.cA) && !equal(v.A.cB, v.B.cB), 'Both directional confirmations reject');
  });
  add(`${b.id}-transcript-mismatch`, bs, (check) => {
    const good = balanced(b), altered = balanced(b, scalar(b.w), scalar(b.w), 'client-altered');
    const expected = fixtures.synthetic.rfc9382.transcriptMismatch;
    for (const role of ['A', 'B']) for (const name of ['TT', 'Ke', 'Ka', 'KcA', 'KcB', 'cA', 'cB']) check(`${role} independent exchange ${name}`, altered[role][name], bytes(expected[role][name]));
    for (const name of ['TT', 'Ke', 'Ka', 'KcA', 'KcB']) check(`unchanged B official ${name}`, altered.B[name], bytes(b[name]));
    check('unchanged B official cA', altered.B.cA, bytes(b['A conf']));
    check('unchanged B official cB', altered.B.cB, bytes(b['B conf']));
    requireTrue(equal(encode(good.KA), encode(altered.KA)), 'Identity change must not change group DH result');
    requireTrue(!equal(altered.A.TT, altered.B.TT) && !equal(altered.A.Ke, altered.B.Ke), 'Only A changes binding and output');
    requireTrue(!equal(altered.A.cA, altered.B.cA), 'A first sent cA fails unchanged B expectation');
  });
  add(`${b.id}-invalid-point`, bs, rejectsInvalid);
  add(a.id, as, (check) => {
    params(check);
    const v = augmented(a);
    for (const name of ['L', 'shareP', 'shareV']) check(name, encode(v[name]), bytes(a[name]));
    for (const name of ['ZP', 'ZV']) check(name, encode(v[name]), bytes(a.Z));
    for (const name of ['VP', 'VV']) check(name, encode(v[name]), bytes(a.V));
    for (const role of ['P', 'V']) {
      for (const name of ['TT', 'K_main', 'K_confirmP', 'K_confirmV', 'K_shared']) check(`${role} ${name}`, v[role][name], bytes(a[name]));
      check(`${role} confirmP`, v[role].confirmP, bytes(a['HMAC(K_confirmP, shareV)']));
      check(`${role} confirmV`, v[role].confirmV, bytes(a['HMAC(K_confirmV, shareP)']));
    }
  });
  add(`${a.id}-password-mismatch`, as, (check) => {
    const v = augmented(a, scalar(a.w0) + 1n, scalar(a.w0), scalar(a.w1) + 1n);
    const expected = fixtures.synthetic.rfc9383.passwordMismatch;
    for (const role of ['P', 'V']) {
      check(`${role} independent mismatched Z`, encode(v[`Z${role}`]), bytes(expected[role].Z));
      check(`${role} independent mismatched V`, encode(v[`V${role}`]), bytes(expected[role].V));
      for (const tag of ['confirmP', 'confirmV', 'K_shared']) check(`${role} independent ${tag}`, v[role][tag], bytes(expected[role][tag]));
    }
    requireTrue(!equal(encode(v.ZP), encode(v.ZV)) && !equal(encode(v.VP), encode(v.VV)), 'Password-derived scalars disagree with record');
    requireTrue(!equal(v.P.confirmV, v.V.confirmV) && !equal(v.P.confirmP, v.V.confirmP), 'Both confirmations reject mismatched record');
  });
  add(`${a.id}-transcript-mismatch`, as, (check) => {
    const good = augmented(a), altered = augmented(a, scalar(a.w0), scalar(a.w0), scalar(a.w1), `${a.context} altered`);
    const expected = fixtures.synthetic.rfc9383.transcriptMismatch;
    for (const role of ['P', 'V']) for (const name of ['TT', 'K_main', 'K_confirmP', 'K_confirmV', 'confirmP', 'confirmV', 'K_shared']) check(`${role} independent exchange ${name}`, altered[role][name], bytes(expected[role][name]));
    for (const name of ['TT', 'K_main', 'K_confirmP', 'K_confirmV', 'K_shared']) check(`unchanged V official ${name}`, altered.V[name], bytes(a[name]));
    check('unchanged V official confirmV', altered.V.confirmV, bytes(a['HMAC(K_confirmV, shareP)']));
    check('unchanged V official confirmP', altered.V.confirmP, bytes(a['HMAC(K_confirmP, shareV)']));
    requireTrue(equal(encode(good.ZP), encode(altered.ZP)) && equal(encode(good.VP), encode(altered.VP)), 'Context leaves group results unchanged');
    requireTrue(!equal(altered.V.confirmV, altered.P.confirmV), 'Unchanged verifier first confirmV fails changed prover expectation');
    requireTrue(!equal(altered.P.K_shared, altered.V.K_shared), 'Context binds application output');
  });
  add(`${a.id}-invalid-point`, as, rejectsInvalid);
  add(`${a.id}-confirmation-direction`, as, () => {
    const v = augmented(a);
    requireTrue(!equal(v.P.confirmP, v.V.confirmV), 'Reflected proof must not authenticate opposite role');
    requireTrue(!equal(hmac(sha256, v.P.K_confirmV, encode(v.shareV)), v.V.confirmV), 'MAC must cover received opposite share');
  });
}
