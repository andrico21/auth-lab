import { X509Certificate } from 'node:crypto';
import { md4 } from 'hash-wasm';
import CryptoJS from 'crypto-js';
import { bytes, hex, utf8, cat, integer, sha256, md5, hmac, equal, requireTrue } from './primitives.mjs';

const utf16 = (s) => Buffer.from(s, 'utf16le');
const rc4 = (key, data) => bytes(CryptoJS.RC4.encrypt(CryptoJS.enc.Hex.parse(hex(data)), CryptoJS.enc.Hex.parse(hex(key))).ciphertext.toString(CryptoJS.enc.Hex));
const av = (id, value) => cat(integer(BigInt(id), 2, true), integer(BigInt(value.length), 2, true), value);
async function ntlm(f, { password = f.password, domain = f.domain, challenge = bytes(f.serverChallenge) } = {}) {
  const ntHash = bytes(await md4(utf16(password)));
  const responseKeyNT = hmac(md5, ntHash, utf16(f.user.toUpperCase() + domain));
  const targetInfo = cat(av(2, utf16(f.domain)), av(1, utf16(f.serverName)), new Uint8Array(4));
  const temp = cat(bytes('0101000000000000'), bytes(f.timestamp), bytes(f.clientChallenge), new Uint8Array(4), targetInfo, new Uint8Array(4));
  const ntProofStr = hmac(md5, responseKeyNT, cat(challenge, temp));
  const ntChallengeResponse = cat(ntProofStr, temp);
  const lmChallengeResponse = cat(hmac(md5, responseKeyNT, cat(challenge, bytes(f.clientChallenge))), bytes(f.clientChallenge));
  const sessionBaseKey = hmac(md5, responseKeyNT, ntProofStr);
  // In the selected NTLMv2 KEY_EXCH profile KeyExchangeKey=SessionBaseKey.
  const keyExchangeKey = sessionBaseKey, exportedSessionKey = bytes(f.randomSessionKey);
  return { ntHash, responseKeyNT, temp, ntProofStr, ntChallengeResponse, lmChallengeResponse, sessionBaseKey, keyExchangeKey, exportedSessionKey, encryptedRandomSessionKey: rc4(keyExchangeKey, exportedSessionKey) };
}
function tlv(data, start = 0) {
  const tag = data[start];
  let offset = start + 1, length = data[offset++];
  if (length & 0x80) {
    const n = length & 0x7f;
    requireTrue(n > 0 && n <= 3 && offset + n <= data.length && data[offset] !== 0, 'Canonical DER length');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + data[offset++];
    requireTrue(length >= 128, 'DER long length must be necessary');
  }
  requireTrue(offset + length <= data.length, 'DER truncated');
  return { tag, content: data.subarray(offset, offset + length), end: offset + length };
}
function subjectFromSpki(spki) {
  const outer = tlv(spki);
  requireTrue(outer.tag === 0x30 && outer.end === spki.length, 'SPKI is exactly one DER sequence');
  const algorithm = tlv(outer.content), bitString = tlv(outer.content, algorithm.end);
  requireTrue(algorithm.tag === 0x30 && bitString.tag === 3 && bitString.end === outer.content.length && bitString.content[0] === 0, 'SPKI subjectPublicKey BIT STRING with zero unused bits');
  return bitString.content.subarray(1);
}
function binding(direction, nonce, subject, terminate = true) {
  requireTrue(nonce.length === 32, 'CredSSP v6 requires a 32-byte nonce');
  requireTrue(direction === 'Client-To-Server' || direction === 'Server-To-Client', 'Explicit CredSSP direction');
  return sha256(cat(utf8(`CredSSP ${direction} Binding Hash${terminate ? '\0' : ''}`), nonce, subject));
}
export function registerWindows(add, fixtures) {
  const f = fixtures.ntlmv2;
  const ns = 'MS-NLMP 37.0 (2026-03-30), sections 3.3.2,4.2.1,4.2.4.1-4.2.4.2; MD4 input from 4.2.2.1.2';
  add(f.id, ns, async (check) => {
    const v = await ntlm(f);
    for (const name of ['ntHash', 'responseKeyNT', 'temp', 'ntProofStr', 'lmChallengeResponse', 'sessionBaseKey', 'encryptedRandomSessionKey']) check(name, v[name], bytes(f[name]));
    check('full NTChallengeResponse proof plus complete blob', v.ntChallengeResponse, cat(bytes(f.ntProofStr), bytes(f.temp)));
    check('KeyExchangeKey', v.keyExchangeKey, bytes(f.sessionBaseKey));
    check('ExportedSessionKey selected random key', v.exportedSessionKey, bytes(f.randomSessionKey));
    check('server recovers ExportedSessionKey', rc4(v.keyExchangeKey, v.encryptedRandomSessionKey), bytes(f.randomSessionKey));
  });
  add(`${f.id}-password-mismatch`, ns, async () => {
    const wrong = await ntlm(f, { password: `${f.password}!` });
    requireTrue(!equal(wrong.ntProofStr, bytes(f.ntProofStr)), 'Validator rejects wrong-password response');
    requireTrue(!equal(wrong.sessionBaseKey, bytes(f.sessionBaseKey)), 'No shared session key under wrong password');
  });
  add(`${f.id}-challenge-mismatch`, ns, async () => {
    const challenge = bytes(f.serverChallenge); challenge[0] ^= 1;
    const changed = await ntlm(f, { challenge });
    requireTrue(!equal(changed.ntProofStr, bytes(f.ntProofStr)), 'Old response rejects against changed server challenge');
  });
  add(`${f.id}-account-authority-mismatch`, ns, async () => {
    const changed = await ntlm(f, { domain: 'DOMAIN' });
    requireTrue(!equal(changed.responseKeyNT, bytes(f.responseKeyNT)) && !equal(changed.ntProofStr, bytes(f.ntProofStr)), 'Only username is uppercased; authority is bound exactly');
  });
  add(`${f.id}-blob-tamper`, ns, async () => {
    const v = await ntlm(f), tampered = Buffer.from(v.temp); tampered[16] ^= 1;
    const expected = hmac(md5, v.responseKeyNT, cat(bytes(f.serverChallenge), tampered));
    requireTrue(!equal(expected, v.ntProofStr), 'Client challenge/target-info blob is authenticated');
  });
  const c = fixtures.synthetic.credssp;
  const cs = 'MS-CSSP 21.0 (2024-04-23), section 3.1.5 steps 3-5, version 6; RFC 7517 Appendix B public certificate example';
  add(c.id, cs, (check) => {
    const certificate = new X509Certificate(bytes(c.certificate));
    const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
    const subject = subjectFromSpki(spki);
    check('certificate actual SPKI', spki, bytes(c.spki));
    check('BIT STRING SubjectPublicKey bytes without wrapper/unused-bit octet', subject, bytes(c.subjectPublicKey));
    check('RSA PKCS1 public key agrees', certificate.publicKey.export({ type: 'pkcs1', format: 'der' }), subject);
    check('client-to-server v6 SHA256', binding('Client-To-Server', bytes(c.nonce), subject), bytes(c.clientToServer));
    check('server-to-client v6 SHA256', binding('Server-To-Client', bytes(c.nonce), subject), bytes(c.serverToClient));
  });
  const negative = [
    ['missing-nul', 'missingNul', () => binding('Client-To-Server', bytes(c.nonce), bytes(c.subjectPublicKey), false)],
    ['nonce-mismatch', 'wrongNonce', () => { const n = bytes(c.nonce); n[0] ^= 1; return binding('Client-To-Server', n, bytes(c.subjectPublicKey)); }],
    ['spki-substitution', 'spkiSubstitution', () => binding('Client-To-Server', bytes(c.nonce), bytes(c.spki))],
    ['certificate-substitution', 'certificateSubstitution', () => binding('Client-To-Server', bytes(c.nonce), bytes(c.certificate))],
    ['thumbprint-substitution', 'thumbprintSubstitution', () => binding('Client-To-Server', bytes(c.nonce), sha256(bytes(c.certificate)))],
  ];
  for (const [id, expected, compute] of negative) add(`${c.id}-${id}`, cs, (check) => {
    const result = compute();
    check('independent altered binding digest', result, bytes(c[expected]));
    requireTrue(!equal(result, bytes(c.clientToServer)), 'Malformed binding must reject');
  });
  add(`${c.id}-direction-reflection`, cs, () => {
    const reflected = binding('Client-To-Server', bytes(c.nonce), bytes(c.subjectPublicKey));
    requireTrue(!equal(reflected, bytes(c.serverToClient)), 'Client proof cannot authenticate server direction');
  });
  add(`${c.id}-wrong-public-key`, cs, () => {
    const changed = bytes(c.subjectPublicKey); changed[changed.length - 1] ^= 2;
    requireTrue(!equal(binding('Client-To-Server', bytes(c.nonce), changed), bytes(c.clientToServer)), 'Different TLS public key must reject');
  });
  add(`${c.id}-nonce-length`, cs, () => {
    for (const size of [0, 31, 33]) {
      let rejected = false;
      try { binding('Client-To-Server', new Uint8Array(size), bytes(c.subjectPublicKey)); } catch { rejected = true; }
      requireTrue(rejected, 'Invalid nonce length must reject before digest computation');
    }
  });
}
