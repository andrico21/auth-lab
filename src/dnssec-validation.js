import { DNSSEC_MATERIAL, dnssecProfile } from './dnssec-fixtures.js';

// Reference-bound verification is an offline teaching boundary, not browser crypto.
// Only independently verified immutable byte tuples can supply signature evidence.
const DNSSEC_VALIDATION_TYPES = Object.freeze({ A: 1, NS: 2, MD: 3, MF: 4, CNAME: 5, SOA: 6, MB: 7, MG: 8, MR: 9, NULL: 10, WKS: 11, PTR: 12, HINFO: 13, MINFO: 14, MX: 15, TXT: 16, RP: 17, AFSDB: 18, RT: 21, SIG: 24, PX: 26, AAAA: 28, NXT: 30, SRV: 33, NAPTR: 35, KX: 36, DNAME: 39, DS: 43, SSHFP: 44, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, NSEC3PARAM: 51, TLSA: 52, CDS: 59, CDNSKEY: 60, CSYNC: 62, ZONEMD: 63, SVCB: 64, HTTPS: 65, DSYNC: 66, NXNAME: 128, CAA: 257 });
const DNSSEC_VALIDATION_SERIAL_MODULUS = 4294967296;
const DNSSEC_VALIDATION_HALF_RANGE = 2147483648;
const DNSSEC_VALIDATION_EVIDENCE_MODE = 'symbolic-reference-bound';

function dnssecValidationFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) dnssecValidationFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function dnssecValidationFail(reason) {
  throw new RangeError(reason);
}

function dnssecValidationInteger(value, bits) {
  if (!Number.isInteger(value) || value < 0 || value >= 2 ** bits) dnssecValidationFail('invalid-unsigned-integer');
  return value;
}

function dnssecValidationUintHex(value, bits) {
  return dnssecValidationInteger(value, bits).toString(16).padStart(bits / 4, '0');
}

function dnssecValidationHex(value) {
  if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]*$/i.test(value)) dnssecValidationFail('invalid-hex-octets');
  return value.toLowerCase();
}

function dnssecValidationOctets(hex) {
  const value = dnssecValidationHex(hex);
  const bytes = [];
  for (let index = 0; index < value.length; index += 2) bytes.push(parseInt(value.slice(index, index + 2), 16));
  return bytes;
}

function dnssecValidationByteHex(bytes) {
  return bytes.map(byte => dnssecValidationUintHex(byte, 8)).join('');
}

function dnssecValidationNameLabels(name, lowercase = true) {
  if (typeof name !== 'string' || !name.length) dnssecValidationFail('invalid-name');
  if (name === '.') return [];
  const labels = [];
  let label = [];
  let ended = false;
  for (let index = 0; index < name.length; index++) {
    let octet = name.charCodeAt(index);
    let decimalEscape = false;
    if (octet === 46) {
      if (!label.length) dnssecValidationFail('empty-name-label');
      labels.push(label);
      label = [];
      ended = index === name.length - 1;
      continue;
    }
    if (octet === 92) {
      if (++index >= name.length) dnssecValidationFail('invalid-name-escape');
      const decimal = name.slice(index, index + 3);
      if (/^\d{3}$/.test(decimal)) {
        octet = Number(decimal);
        decimalEscape = true;
        index += 2;
      } else octet = name.charCodeAt(index);
    }
    if (octet > 255 || (octet > 127 && !decimalEscape)) dnssecValidationFail('non-ascii-name-needs-octet-escape');
    if (lowercase && octet >= 65 && octet <= 90) octet += 32;
    label.push(octet);
    if (label.length > 63) dnssecValidationFail('name-label-too-long');
  }
  if (label.length) labels.push(label);
  else if (!ended) dnssecValidationFail('empty-name-label');
  if (labels.reduce((length, item) => length + item.length + 1, 1) > 255) dnssecValidationFail('name-too-long');
  return labels;
}

function dnssecValidationLabelsWire(labels) {
  return labels.map(label => dnssecValidationUintHex(label.length, 8) + dnssecValidationByteHex(label)).join('') + '00';
}

export function dnssecCanonicalName(name) {
  return dnssecValidationLabelsWire(dnssecValidationNameLabels(name));
}

function dnssecValidationSameName(left, right) {
  return dnssecCanonicalName(left) === dnssecCanonicalName(right);
}

function dnssecValidationBelow(name, zone) {
  const labels = dnssecValidationNameLabels(name);
  const suffix = dnssecValidationNameLabels(zone);
  return labels.length >= suffix.length && suffix.every((label, index) => dnssecValidationByteHex(label) === dnssecValidationByteHex(labels[labels.length - suffix.length + index]));
}

function dnssecValidationType(value) {
  if (Number.isInteger(value)) return dnssecValidationInteger(value, 16);
  const name = String(value).toUpperCase();
  if (Object.hasOwn(DNSSEC_VALIDATION_TYPES, name)) return DNSSEC_VALIDATION_TYPES[name];
  if (/^TYPE\d+$/.test(name)) return dnssecValidationInteger(Number(name.slice(4)), 16);
  dnssecValidationFail('unsupported-record-type');
}

function dnssecValidationRrsetType(rrset) {
  const type = dnssecValidationType(rrset.type ?? rrset.typeCode);
  if (rrset.typeCode !== undefined && rrset.typeCode !== type) dnssecValidationFail('inconsistent-record-type');
  return type;
}

function dnssecValidationTokens(text) {
  if (typeof text !== 'string') dnssecValidationFail('unsupported-rdata-representation');
  const tokens = text.match(/"(?:\\[\s\S]|[^"\\])*"|(?:\\[\s\S]|[^\s])+/g) || [];
  if (!tokens.length) dnssecValidationFail('empty-rdata');
  return tokens;
}

function dnssecValidationCharacterString(token) {
  const text = token.startsWith('"') && token.endsWith('"') ? token.slice(1, -1) : token;
  const bytes = [];
  for (let index = 0; index < text.length; index++) {
    let octet = text.charCodeAt(index);
    if (octet === 92) {
      if (++index >= text.length) dnssecValidationFail('invalid-character-string-escape');
      const decimal = text.slice(index, index + 3);
      if (/^\d{3}$/.test(decimal)) { octet = Number(decimal); index += 2; }
      else octet = text.charCodeAt(index);
    }
    bytes.push(dnssecValidationInteger(octet, 8));
  }
  if (bytes.length > 255) dnssecValidationFail('character-string-too-long');
  return dnssecValidationUintHex(bytes.length, 8) + dnssecValidationByteHex(bytes);
}

function dnssecValidationBase64(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const value = String(text).replace(/\s/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) dnssecValidationFail('invalid-base64');
  let accumulator = 0;
  let bits = 0;
  const bytes = [];
  for (const character of value.replace(/=+$/, '')) {
    accumulator = (accumulator << 6) | alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  if (bits && (accumulator & ((1 << bits) - 1))) dnssecValidationFail('noncanonical-base64-padding');
  return dnssecValidationByteHex(bytes);
}

function dnssecValidationBase32hex(text) {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  let accumulator = 0;
  let bits = 0;
  const bytes = [];
  if (!/^[0-9a-v]+$/i.test(text)) dnssecValidationFail('invalid-base32hex');
  for (const character of text.toUpperCase()) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  if (bits && (accumulator & ((1 << bits) - 1))) dnssecValidationFail('noncanonical-base32hex-padding');
  return dnssecValidationByteHex(bytes);
}

function dnssecValidationBitmap(tokens) {
  const windows = new Map();
  for (const token of tokens) {
    const type = dnssecValidationType(token);
    const window = type >>> 8;
    const low = type & 255;
    if (!windows.has(window)) windows.set(window, []);
    const bytes = windows.get(window);
    while (bytes.length <= (low >>> 3)) bytes.push(0);
    bytes[low >>> 3] |= 128 >>> (low & 7);
  }
  return [...windows.keys()].sort((left, right) => left - right).map(window => dnssecValidationUintHex(window, 8) + dnssecValidationUintHex(windows.get(window).length, 8) + dnssecValidationByteHex(windows.get(window))).join('');
}

function dnssecValidationIpv6(text) {
  let value = text;
  if (value.includes('.')) {
    const split = value.lastIndexOf(':');
    const bytes = dnssecValidationOctets(dnssecValidationRdata(1, value.slice(split + 1)));
    value = value.slice(0, split + 1) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
  }
  const halves = value.split('::');
  if (halves.length > 2) dnssecValidationFail('invalid-ipv6');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) dnssecValidationFail('invalid-ipv6');
  const words = halves.length === 2 ? [...left, ...Array(missing).fill('0'), ...right] : left;
  return words.map(word => {
    if (!/^[0-9a-f]{1,4}$/i.test(word)) dnssecValidationFail('invalid-ipv6');
    return word.toLowerCase().padStart(4, '0');
  }).join('');
}

function dnssecValidationPresentationTime(token) {
  if (!/^\d+$/.test(token)) dnssecValidationFail('invalid-rrsig-time');
  if (token.length !== 14) return dnssecValidationInteger(Number(token), 32);
  const parts = [token.slice(0, 4), token.slice(4, 6), token.slice(6, 8), token.slice(8, 10), token.slice(10, 12), token.slice(12, 14)].map(Number);
  const milliseconds = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]);
  const date = new Date(milliseconds);
  const actual = [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()];
  if (parts.some((value, index) => value !== actual[index])) dnssecValidationFail('invalid-rrsig-time');
  return dnssecValidationInteger(milliseconds / 1000, 32);
}

function dnssecValidationRdata(type, text) {
  const tokens = dnssecValidationTokens(text);
  const uint = (index, bits = 16) => dnssecValidationUintHex(Number(tokens[index]), bits);
  const name = index => dnssecCanonicalName(tokens[index]);
  const count = expected => { if (tokens.length !== expected) dnssecValidationFail('invalid-rdata-field-count'); };
  if (tokens[0] === '\\#') {
    if (Object.values(DNSSEC_VALIDATION_TYPES).includes(type)) dnssecValidationFail('known-type-needs-typed-rdata');
    const hex = dnssecValidationHex(tokens.slice(2).join(''));
    if (Number(tokens[1]) !== hex.length / 2) dnssecValidationFail('invalid-rdata-length');
    return hex;
  }
  if (type === 1) {
    count(1);
    const parts = tokens[0].split('.');
    if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) dnssecValidationFail('invalid-ipv4');
    return dnssecValidationByteHex(parts.map(Number));
  }
  if (type === 28) { count(1); return dnssecValidationIpv6(tokens[0]); }
  if ([2, 3, 4, 5, 7, 8, 9, 12, 39].includes(type)) { count(1); return name(0); }
  if ([14, 17].includes(type)) { count(2); return name(0) + name(1); }
  if ([15, 18, 21, 36].includes(type)) { count(2); return uint(0) + name(1); }
  if (type === 26) { count(3); return uint(0) + name(1) + name(2); }
  if (type === 6) { count(7); return name(0) + name(1) + tokens.slice(2).map(token => dnssecValidationUintHex(Number(token), 32)).join(''); }
  if (type === 33) { count(4); return uint(0) + uint(1) + uint(2) + name(3); }
  if (type === 35) { count(6); return uint(0) + uint(1) + tokens.slice(2, 5).map(dnssecValidationCharacterString).join('') + name(5); }
  if (type === 16 || type === 13) {
    if (type === 13) count(2);
    return tokens.map(dnssecValidationCharacterString).join('');
  }
  if (type === 48 || type === 60) {
    if (tokens.length < 4) dnssecValidationFail('invalid-rdata-field-count');
    return uint(0) + uint(1, 8) + uint(2, 8) + dnssecValidationBase64(tokens.slice(3).join(''));
  }
  if (type === 43 || type === 59) {
    if (tokens.length < 4) dnssecValidationFail('invalid-rdata-field-count');
    return uint(0) + uint(1, 8) + uint(2, 8) + dnssecValidationHex(tokens.slice(3).join(''));
  }
  if (type === 46) {
    if (tokens.length < 9) dnssecValidationFail('invalid-rdata-field-count');
    // RFC6840 section 5.1: RRSIG names are downcased; NSEC next names are not.
    return dnssecValidationUintHex(dnssecValidationType(tokens[0]), 16) + uint(1, 8) + uint(2, 8) + uint(3, 32) + dnssecValidationUintHex(dnssecValidationPresentationTime(tokens[4]), 32) + dnssecValidationUintHex(dnssecValidationPresentationTime(tokens[5]), 32) + uint(6) + name(7) + dnssecValidationBase64(tokens.slice(8).join(''));
  }
  if (type === 47 || type === 30) {
    // RFC6840: the NSEC Next Domain Name is NOT downcased for signing.
    if (type === 30) dnssecValidationFail('unsupported-rdata-type');
    return dnssecValidationLabelsWire(dnssecValidationNameLabels(tokens[0], false)) + dnssecValidationBitmap(tokens.slice(1));
  }
  if (type === 50 || type === 51) {
    if (tokens.length < (type === 50 ? 5 : 4)) dnssecValidationFail('invalid-rdata-field-count');
    const salt = tokens[3] === '-' ? '' : dnssecValidationHex(tokens[3]);
    let hex = uint(0, 8) + uint(1, 8) + uint(2) + dnssecValidationUintHex(salt.length / 2, 8) + salt;
    if (type === 50) {
      const next = dnssecValidationBase32hex(tokens[4]);
      hex += dnssecValidationUintHex(next.length / 2, 8) + next + dnssecValidationBitmap(tokens.slice(5));
    } else count(4);
    return hex;
  }
  if (type === 44 || type === 52) {
    if (tokens.length < (type === 44 ? 3 : 4)) dnssecValidationFail('invalid-rdata-field-count');
    const fields = type === 44 ? 2 : 3;
    return tokens.slice(0, fields).map(token => dnssecValidationUintHex(Number(token), 8)).join('') + dnssecValidationHex(tokens.slice(fields).join(''));
  }
  if (type === 62) {
    if (tokens.length < 2) dnssecValidationFail('invalid-rdata-field-count');
    return uint(0, 32) + uint(1) + dnssecValidationBitmap(tokens.slice(2));
  }
  if (type === 63) {
    if (tokens.length < 4) dnssecValidationFail('invalid-rdata-field-count');
    return uint(0, 32) + uint(1, 8) + uint(2, 8) + dnssecValidationHex(tokens.slice(3).join(''));
  }
  if (type === 66) {
    count(4);
    return dnssecValidationUintHex(dnssecValidationType(tokens[0]), 16) + uint(1, 8) + uint(2) + name(3);
  }
  dnssecValidationFail('unsupported-rdata-type');
}

function dnssecValidationRdatas(rrset) {
  if (!Array.isArray(rrset.records) || !rrset.records.length) dnssecValidationFail('missing-rdata-records');
  const type = dnssecValidationRrsetType(rrset);
  // Never consume canonicalRdataHex: it is inspectable reference metadata only.
  return [...new Set(rrset.records.map(record => dnssecValidationRdata(type, record)))].sort();
}

function dnssecValidationSignaturePrefix(signature) {
  return dnssecValidationUintHex(dnssecValidationType(signature.typeCovered), 16) + dnssecValidationUintHex(signature.algorithm, 8) + dnssecValidationUintHex(signature.labels, 8) + dnssecValidationUintHex(signature.originalTtl, 32) + dnssecValidationUintHex(signature.expiration, 32) + dnssecValidationUintHex(signature.inception, 32) + dnssecValidationUintHex(signature.keyTag, 16) + dnssecCanonicalName(signature.signer);
}
function dnssecValidationRrsetWire(rrset, owner, originalTtl) {
  const type = dnssecValidationRrsetType(rrset);
  const rrclass = rrset.class === undefined || String(rrset.class).toUpperCase() === 'IN' ? 1 : Number(String(rrset.class).replace(/^CLASS/i, ''));
  const header = owner + dnssecValidationUintHex(type, 16) + dnssecValidationUintHex(rrclass, 16) + dnssecValidationUintHex(originalTtl, 32);
  return dnssecValidationRdatas(rrset).map(rdata => header + dnssecValidationUintHex(rdata.length / 2, 16) + rdata).join('');
}

// Complete RFC4034 canonical RRs, ordered by canonical RDATA, without an RRSIG prefix.
// The ordinary owner is preserved here; wildcard expansion belongs to RRSIG Labels.
export function dnssecCanonicalRrsetWire(rrset, { originalTtl = rrset?.ttl } = {}) {
  return dnssecValidationRrsetWire(rrset, dnssecCanonicalName(rrset.owner), originalTtl);
}


export function dnssecCanonicalInput(rrset, signature) {
  const type = dnssecValidationRrsetType(rrset);
  if (type !== dnssecValidationType(signature.typeCovered)) dnssecValidationFail('wrong-type-covered');
  let labels = dnssecValidationNameLabels(rrset.owner);
  const count = dnssecValidationInteger(signature.labels, 8);
  if (count > labels.length || (labels[0]?.length === 1 && labels[0][0] === 42 && count !== labels.length - 1)) dnssecValidationFail('invalid-rrsig-labels');
  if (count < labels.length) labels = [[42], ...labels.slice(labels.length - count)];
  return dnssecValidationSignaturePrefix(signature) + dnssecValidationRrsetWire(rrset, dnssecValidationLabelsWire(labels), signature.originalTtl);
}

export function dnssecKeyTag(dnskeyRdataHex) {
  const bytes = dnssecValidationOctets(dnskeyRdataHex);
  if (bytes.length < 4) dnssecValidationFail('invalid-dnskey-rdata');
  if (bytes[3] === 1) {
    if (bytes.length < 7) dnssecValidationFail('invalid-rsamd5-key');
    return (bytes[bytes.length - 3] << 8) + bytes[bytes.length - 2];
  }
  let accumulator = 0;
  for (let index = 0; index < bytes.length; index++) accumulator += index & 1 ? bytes[index] : bytes[index] * 256;
  accumulator += Math.floor(accumulator / 65536) & 65535;
  return accumulator & 65535;
}

function dnssecValidationSerial(value) {
  if (!Number.isSafeInteger(value) || value < 0) dnssecValidationFail('invalid-serial-time');
  return value % DNSSEC_VALIDATION_SERIAL_MODULUS;
}

export function dnssecSignatureTime(now, inception, expiration) {
  try {
    const current = dnssecValidationSerial(now);
    dnssecValidationInteger(inception, 32);
    dnssecValidationInteger(expiration, 32);
    const span = (expiration - inception + DNSSEC_VALIDATION_SERIAL_MODULUS) % DNSSEC_VALIDATION_SERIAL_MODULUS;
    const afterInception = (current - inception + DNSSEC_VALIDATION_SERIAL_MODULUS) % DNSSEC_VALIDATION_SERIAL_MODULUS;
    const untilExpiration = (expiration - current + DNSSEC_VALIDATION_SERIAL_MODULUS) % DNSSEC_VALIDATION_SERIAL_MODULUS;
    if (span >= DNSSEC_VALIDATION_HALF_RANGE || afterInception === DNSSEC_VALIDATION_HALF_RANGE || untilExpiration === DNSSEC_VALIDATION_HALF_RANGE) return Object.freeze({ valid: false, reason: 'undefined-serial-order' });
    if (afterInception < DNSSEC_VALIDATION_HALF_RANGE && untilExpiration < DNSSEC_VALIDATION_HALF_RANGE) return Object.freeze({ valid: true, reason: 'valid' });
    return Object.freeze({ valid: false, reason: afterInception >= DNSSEC_VALIDATION_HALF_RANGE ? 'not-yet-valid' : 'expired' });
  } catch (error) { return Object.freeze({ valid: false, reason: error.message }); }
}

function dnssecValidationKeyWire(key) {
  if (!key || typeof key !== 'object') dnssecValidationFail('missing-dnskey');
  const publicHex = key.publicKeyHex === undefined ? dnssecValidationBase64(key.publicKeyBase64) : dnssecValidationHex(key.publicKeyHex);
  if (!publicHex.length) dnssecValidationFail('missing-public-key');
  if (key.publicKeyBase64 !== undefined && dnssecValidationBase64(key.publicKeyBase64) !== publicHex) dnssecValidationFail('inconsistent-public-key');
  const wire = dnssecValidationUintHex(key.flags, 16) + dnssecValidationUintHex(key.protocol, 8) + dnssecValidationUintHex(key.algorithm, 8) + publicHex;
  if (key.dnskeyRdataHex !== undefined && dnssecValidationHex(key.dnskeyRdataHex) !== wire) dnssecValidationFail('inconsistent-dnskey-rdata');
  if (key.keyTag !== undefined && key.keyTag !== dnssecKeyTag(wire)) dnssecValidationFail('inconsistent-key-tag');
  return wire;
}

function dnssecValidationPolicy(policy) {
  const selected = typeof policy === 'string' || policy === undefined ? dnssecProfile(policy) : policy;
  if (!selected || !Array.isArray(selected.validationAlgorithms) || !Array.isArray(selected.dsDigestTypes)) dnssecValidationFail('invalid-validation-policy');
  return selected;
}

function dnssecValidationAlgorithms(policy) {
  return policy.validationAlgorithms;
}

function dnssecValidationDigests(policy) {
  return policy.dsDigestTypes;
}

function dnssecValidationAllowed(values, value) {
  if (!Array.isArray(values)) dnssecValidationFail('invalid-validation-policy');
  return values.includes(value);
}

function dnssecValidationEvidenceRefs(kind, id) {
  return { kind, id, provenance: DNSSEC_MATERIAL.provenance?.objects?.[kind]?.[id] ?? [] };
}

// checked reports a reference-tuple comparison, not acceptance, transport success,
// chain authentication, or browser cryptographic execution. Mathematics and use
// eligibility remain separate even for expired and not-yet-valid signatures.
export function dnssecCheckSignature({ rrset, signatures = [], keys = [], now, policy, expectedSigner } = {}) {
  const candidates = [];
  let selected = null;
  const finish = reason => {
    const mathematicalResult = candidates.some(candidate => candidate.mathematicalResult === true) ? true : candidates.some(candidate => candidate.mathematicalResult === false) ? false : null;
    return dnssecValidationFreeze({
      checked: candidates.some(candidate => candidate.checked),
      checkedMeaning: 'reference-tuple-comparison-attempted',
      mathematicalResult,
      valid: !!selected,
      usable: !!selected,
      reason: selected ? 'valid-signature-path' : reason ?? candidates[0]?.reason ?? 'no-valid-signature-path',
      selectedSignatureId: selected?.signatureId ?? null,
      selectedKeyId: selected?.keyId ?? null,
      evidenceMode: DNSSEC_VALIDATION_EVIDENCE_MODE,
      evidenceRefs: selected?.evidenceRefs ?? [],
      selectedEvidence: selected,
      candidates
    });
  };
  try {
    const selectedPolicy = dnssecValidationPolicy(policy);
    if (!rrset) dnssecValidationFail('missing-rrset');
    if (!Array.isArray(signatures) || !Array.isArray(keys)) dnssecValidationFail('invalid-signature-candidates');
    if (!signatures.length) dnssecValidationFail('missing-signature');
    const type = dnssecValidationRrsetType(rrset);
    for (const signature of signatures) {
      const base = {
        signatureId: signature?.id ?? null,
        keyId: null,
        checked: false,
        mathematicalResult: null,
        valid: false,
        usable: false,
        reason: null,
        eligibility: { algorithm: null, key: null, signer: null, type: null, labels: null, time: null },
        time: null,
        evidenceMode: DNSSEC_VALIDATION_EVIDENCE_MODE,
        evidenceRefs: []
      };
      let input;
      let signatureHex;
      try {
        if (!signature || typeof signature !== 'object') dnssecValidationFail('missing-signature-descriptor');
        base.eligibility.algorithm = dnssecValidationAllowed(dnssecValidationAlgorithms(selectedPolicy), signature.algorithm);
        base.eligibility.type = dnssecValidationType(signature.typeCovered) === type;
        base.eligibility.signer = (expectedSigner === undefined || dnssecValidationSameName(signature.signer, expectedSigner)) && dnssecValidationBelow(rrset.owner, signature.signer) && (type !== 48 || dnssecValidationSameName(signature.signer, rrset.owner)) && (type !== 43 || !dnssecValidationSameName(signature.signer, rrset.owner));
        base.time = dnssecSignatureTime(now, signature.inception, signature.expiration);
        base.eligibility.time = base.time.valid;
        base.originalTtl = signature.originalTtl;
        base.inception = signature.inception;
        base.expiration = signature.expiration;
        if (!base.eligibility.algorithm) base.reason = 'unsupported-signature-algorithm';
        else if (!base.eligibility.type) base.reason = 'wrong-type-covered';
        else if (!base.eligibility.signer) base.reason = 'wrong-signer';
        if (!base.eligibility.type) dnssecValidationFail(base.reason);
        try {
          input = dnssecCanonicalInput(rrset, signature);
          base.eligibility.labels = true;
        } catch (error) {
          if (error.message === 'invalid-rrsig-labels') base.eligibility.labels = false;
          throw error;
        }
        signatureHex = dnssecValidationHex(signature.signatureHex);
        if (!signatureHex.length) dnssecValidationFail('missing-signature-octets');
        if (signature.rrsigRdataHex !== undefined && dnssecValidationHex(signature.rrsigRdataHex) !== dnssecValidationSignaturePrefix(signature) + signatureHex) dnssecValidationFail('inconsistent-rrsig-rdata');
        base.canonicalInputHex = input;
        base.signatureHex = signatureHex;
        if (!base.reason && !base.time.valid) base.reason = base.time.reason === 'expired' || base.time.reason === 'not-yet-valid' ? `signature-${base.time.reason}` : base.time.reason;
      } catch (error) {
        candidates.push({ ...base, reason: base.reason ?? error.message });
        continue;
      }
      let matched = false;
      for (const key of keys) {
        const candidate = { ...base, keyId: key?.id ?? null, eligibility: { ...base.eligibility } };
        try {
          if (!key || typeof key !== 'object') dnssecValidationFail('missing-dnskey');
          if (key.algorithm !== signature.algorithm || !dnssecValidationSameName(key.owner, signature.signer)) continue;
          const wire = dnssecValidationKeyWire(key);
          if (dnssecKeyTag(wire) !== signature.keyTag) continue;
          matched = true;
          candidate.dnskeyRdataHex = wire;
          candidate.eligibility.key = key.protocol === 3 && !!(key.flags & 256);
          const keyReason = key.protocol !== 3 ? 'dnskey-protocol-not-3' : !(key.flags & 256) ? 'dnskey-zone-flag-clear' : null;
          if (candidate.eligibility.algorithm) {
            candidate.checked = true;
            // Key tags select candidates, never identities. Compare the entire
            // actual algorithm/public-key tuple, not a key ID or a unique tag.
            // Flags/protocol affect DNSSEC eligibility, not the signature math.
            const reference = Object.values(DNSSEC_MATERIAL.signatures).find(item => {
              if (item.signingInputHex !== input || item.signatureHex !== signatureHex) return false;
              const publicKey = DNSSEC_MATERIAL.keys[item.keyId];
              return publicKey && publicKey.algorithm === key.algorithm && dnssecValidationKeyWire(publicKey).slice(8) === wire.slice(8);
            });
            candidate.mathematicalResult = !!reference;
            if (reference) candidate.evidenceRefs = [dnssecValidationEvidenceRefs('signatures', reference.id), dnssecValidationEvidenceRefs('keys', reference.keyId)];
          }
          candidate.usable = candidate.mathematicalResult === true && Object.values(candidate.eligibility).every(value => value === true);
          candidate.valid = candidate.usable;
          candidate.reason = candidate.reason ?? keyReason ?? (candidate.mathematicalResult ? 'verified-reference-tuple' : 'signature-reference-tuple-mismatch');
          candidates.push(candidate);
          if (candidate.usable && !selected) selected = candidate;
        } catch (error) {
          candidate.eligibility.key = false;
          candidates.push({ ...candidate, reason: candidate.reason ?? error.message });
        }
      }
      if (!matched) candidates.push({ ...base, eligibility: { ...base.eligibility, key: false }, reason: base.reason ?? 'no-matching-dnskey' });
    }
    return finish();
  } catch (error) { return finish(error.message); }
}

function dnssecValidationDsWire(ds) {
  return dnssecValidationUintHex(ds.keyTag, 16) + dnssecValidationUintHex(ds.algorithm, 8) + dnssecValidationUintHex(ds.digestType, 8) + dnssecValidationHex(ds.digestHex);
}

export function dnssecDsMatchesKey(ds, key, policy) {
  try {
    const selectedPolicy = dnssecValidationPolicy(policy);
    if (!ds || !key) dnssecValidationFail('missing-ds-or-dnskey');
    if (!dnssecValidationAllowed(dnssecValidationAlgorithms(selectedPolicy), ds.algorithm)) dnssecValidationFail('unsupported-ds-key-algorithm');
    if (!dnssecValidationAllowed(dnssecValidationDigests(selectedPolicy), ds.digestType)) dnssecValidationFail('unsupported-ds-digest');
    if (!dnssecValidationSameName(ds.owner, key.owner)) dnssecValidationFail('ds-owner-mismatch');
    const wire = dnssecValidationKeyWire(key);
    if (key.algorithm !== ds.algorithm) dnssecValidationFail('ds-algorithm-mismatch');
    if (dnssecKeyTag(wire) !== ds.keyTag) dnssecValidationFail('ds-key-tag-mismatch');
    if (key.protocol !== 3) dnssecValidationFail('dnskey-protocol-not-3');
    if (!(key.flags & 256)) dnssecValidationFail('dnskey-zone-flag-clear');
    const input = dnssecCanonicalName(key.owner) + wire;
    const digest = dnssecValidationHex(ds.digestHex);
    const dsWire = dnssecValidationDsWire(ds);
    if (ds.dsRdataHex !== undefined && dnssecValidationHex(ds.dsRdataHex) !== dsWire) dnssecValidationFail('inconsistent-ds-rdata');
    if (ds.digestInputHex !== undefined && dnssecValidationHex(ds.digestInputHex) !== input) dnssecValidationFail('ds-digest-input-mismatch');
    const reference = Object.values(DNSSEC_MATERIAL.ds).find(item => item.digestType === ds.digestType && item.digestInputHex === input && item.digestHex === digest && item.dsRdataHex === dsWire);
    if (!reference) dnssecValidationFail('ds-reference-tuple-mismatch');
    return dnssecValidationFreeze({ valid: true, matched: true, reason: 'ds-verified-reference-tuple', keyId: key.id ?? null, dsId: ds.id ?? null, digestInputHex: input, digestHex: digest, dnskeyRdataHex: wire, evidenceMode: DNSSEC_VALIDATION_EVIDENCE_MODE, evidenceRefs: [dnssecValidationEvidenceRefs('ds', reference.id)] });
  } catch (error) { return dnssecValidationFreeze({ valid: false, matched: false, reason: error.message, keyId: key?.id ?? null, dsId: ds?.id ?? null, evidenceMode: DNSSEC_VALIDATION_EVIDENCE_MODE, evidenceRefs: [] }); }
}

export function dnssecTtlWindow({ receivedTtl, rrsigTtl, originalTtl, signatureExpiration, now, receivedAt = now } = {}) {
  try {
    for (const value of [receivedTtl, rrsigTtl, originalTtl]) dnssecValidationInteger(value, 32);
    dnssecValidationSerial(now);
    dnssecValidationSerial(receivedAt);
    dnssecValidationInteger(signatureExpiration, 32);
    if (now < receivedAt) dnssecValidationFail('represented-time-before-receipt');
    const elapsedSeconds = now - receivedAt;
    const distance = (signatureExpiration - dnssecValidationSerial(now) + DNSSEC_VALIDATION_SERIAL_MODULUS) % DNSSEC_VALIDATION_SERIAL_MODULUS;
    if (distance === DNSSEC_VALIDATION_HALF_RANGE) dnssecValidationFail('undefined-serial-order');
    const limits = { receivedTtl: receivedTtl - elapsedSeconds, rrsigTtl: rrsigTtl - elapsedSeconds, originalTtl: originalTtl - elapsedSeconds, signatureValidity: distance < DNSSEC_VALIDATION_HALF_RANGE ? distance : 0 };
    const remainingSeconds = Math.max(0, Math.min(...Object.values(limits)));
    return dnssecValidationFreeze({ valid: remainingSeconds > 0, reason: remainingSeconds > 0 ? 'ttl-window-live' : 'ttl-window-expired', remainingSeconds, expiresAt: now + remainingSeconds, elapsedSeconds, limits });
  } catch (error) { return dnssecValidationFreeze({ valid: false, reason: error.message, remainingSeconds: 0, expiresAt: null, limits: null }); }
}

function dnssecValidationMembers(rrset, keys) {
  const wires = dnssecValidationRdatas(rrset);
  return keys.filter(key => {
    try { return dnssecValidationSameName(key.owner, rrset.owner) && wires.includes(dnssecValidationKeyWire(key)); }
    catch { return false; }
  });
}

function dnssecValidationDsRecords(rrset) {
  if (dnssecValidationRrsetType(rrset) !== 43) dnssecValidationFail('required-ds-rrset');
  return rrset.records.map(record => {
    const tokens = dnssecValidationTokens(record);
    return { owner: rrset.owner, keyTag: Number(tokens[0]), algorithm: Number(tokens[1]), digestType: Number(tokens[2]), digestHex: dnssecValidationHex(tokens.slice(3).join('')) };
  });
}

export function dnssecValidateChain({ anchor, links = [], answer, now, policy } = {}) {
  const checks = [];
  const selectedEvidence = [];
  let signatureChecked = false;
  let chainEstablished = false;
  const finish = (securityStatus, reasonCode) => dnssecValidationFreeze({ securityStatus, reasonCode, signatureChecked, chainEstablished, evidenceMode: DNSSEC_VALIDATION_EVIDENCE_MODE, checks, selectedEvidence });
  const recordSignature = (stage, zone, result) => {
    checks.push({ stage, zone, valid: result.valid, reason: result.reason, result });
    signatureChecked ||= result.checked;
    if (result.valid) selectedEvidence.push({ stage, zone, ...result.selectedEvidence });
    return result.valid;
  };
  try {
    if (!anchor) return finish('indeterminate', 'no-applicable-trust-anchor');
    const selectedPolicy = dnssecValidationPolicy(policy);
    if (!Array.isArray(links) || !links.length) return finish('bogus', 'missing-trust-point-dnskey');
    let parent = null;
    for (let index = 0; index < links.length; index++) {
      const link = links[index];
      if (!link || typeof link !== 'object') return finish('bogus', 'missing-delegation-link');
      const zone = link.zone;
      dnssecCanonicalName(zone);
      let authenticatingKeys = [];
      const keyAuthenticationEvidence = [];
      let members;
      if (index === 0) {
        if (!link.dnskeyRrset || dnssecValidationRrsetType(link.dnskeyRrset) !== 48 || !dnssecValidationSameName(link.dnskeyRrset.owner, zone)) return finish('bogus', 'missing-or-wrong-zone-dnskey-rrset');
        members = dnssecValidationMembers(link.dnskeyRrset, link.keys ?? []);
        if (!members.length) return finish('bogus', 'no-supplied-dnskey-members');
        const anchors = Array.isArray(anchor) ? anchor : Array.isArray(anchor.keys) ? anchor.keys : anchor.key ? [anchor.key] : anchor.algorithm !== undefined && anchor.digestType === undefined ? [anchor] : [];
        const anchorDs = Array.isArray(anchor.ds) ? anchor.ds : anchor.ds ? [anchor.ds] : anchor.digestType !== undefined ? [anchor] : [];
        const anchorZone = anchor.zone ?? anchors[0]?.owner ?? anchorDs[0]?.owner;
        if (!anchorZone || !dnssecValidationSameName(anchorZone, zone)) return finish('indeterminate', 'no-applicable-trust-anchor');
        authenticatingKeys = members.filter(key => anchors.some(trusted => dnssecValidationSameName(trusted.owner, key.owner) && dnssecValidationKeyWire(trusted) === dnssecValidationKeyWire(key)));
        for (const key of authenticatingKeys) keyAuthenticationEvidence.push({ stage: 'anchor', zone, keyId: key.id ?? null, dnskeyRdataHex: dnssecValidationKeyWire(key), reason: 'configured-anchor-matches-public-key' });
        for (const ds of anchorDs) for (const key of members) {
          const result = dnssecDsMatchesKey(ds, key, selectedPolicy);
          checks.push({ stage: 'anchor-digest', zone, valid: result.valid, reason: result.reason, result });
          if (result.valid) { authenticatingKeys.push(key); keyAuthenticationEvidence.push({ stage: 'anchor-digest', zone, ...result }); }
        }
        checks.push({ stage: 'anchor', zone, valid: authenticatingKeys.length > 0, reason: authenticatingKeys.length ? 'configured-anchor-matches-public-key' : 'anchor-key-mismatch' });
        if (!authenticatingKeys.length) return finish('bogus', 'anchor-key-mismatch');
      } else {
        if (!dnssecValidationBelow(zone, parent.zone) || dnssecValidationSameName(zone, parent.zone)) return finish('bogus', 'unordered-delegation-path');
        if (link.noDsProof && !link.dsRrset) {
          const proof = link.noDsProof;
          const rrset = proof.rrset;
          if ((proof.zone !== undefined && !dnssecValidationSameName(proof.zone, parent.zone)) || (proof.delegation !== undefined && !dnssecValidationSameName(proof.delegation, zone))) return finish('bogus', 'wrong-no-ds-proof-context');
          if (!rrset || dnssecValidationRrsetType(rrset) !== 47 || !dnssecValidationSameName(rrset.owner, zone) || rrset.records.length !== 1) return finish('bogus', 'unsupported-or-missing-no-ds-proof');
          const bitmap = dnssecValidationTokens(rrset.records[0]).slice(1).map(dnssecValidationType);
          if (!bitmap.includes(2) || bitmap.includes(43) || bitmap.includes(6)) return finish('bogus', 'invalid-no-ds-delegation-bitmap');
          const result = dnssecCheckSignature({ rrset, signatures: proof.signatures, keys: parent.keys, now, policy: selectedPolicy, expectedSigner: parent.zone });
          if (!recordSignature('parent-no-ds-proof', zone, result)) return finish('bogus', 'invalid-parent-no-ds-proof');
          return finish('insecure', 'authenticated-no-ds-delegation');
        }
        if (!link.dsRrset || !dnssecValidationSameName(link.dsRrset.owner, zone)) return finish('bogus', 'missing-parent-ds');
        const dsSignature = dnssecCheckSignature({ rrset: link.dsRrset, signatures: link.dsSignatures, keys: parent.keys, now, policy: selectedPolicy, expectedSigner: parent.zone });
        if (!recordSignature('parent-ds-signature', zone, dsSignature)) return finish('bogus', 'invalid-parent-ds-signature');
        const actualDs = dnssecValidationDsRecords(link.dsRrset);
        const suppliedDs = link.ds === undefined ? actualDs : Array.isArray(link.ds) ? link.ds : [link.ds];
        const wires = dnssecValidationRdatas(link.dsRrset);
        if (suppliedDs.some(ds => !dnssecValidationSameName(ds.owner, zone) || !wires.includes(dnssecValidationDsWire(ds)))) return finish('bogus', 'ds-not-in-authenticated-rrset');
        // Support is evaluated over the actual authenticated set, not a caller-selected subset.
        const supported = actualDs.filter(ds => dnssecValidationAllowed(dnssecValidationAlgorithms(selectedPolicy), ds.algorithm) && dnssecValidationAllowed(dnssecValidationDigests(selectedPolicy), ds.digestType));
        checks.push({ stage: 'ds-policy', zone, valid: supported.length > 0, reason: supported.length ? 'supported-ds-path-present' : 'no-supported-ds-path' });
        if (!supported.length) return finish('insecure', 'no-supported-ds-path');
        if (!link.dnskeyRrset || dnssecValidationRrsetType(link.dnskeyRrset) !== 48 || !dnssecValidationSameName(link.dnskeyRrset.owner, zone)) return finish('bogus', 'missing-or-wrong-zone-dnskey-rrset');
        members = dnssecValidationMembers(link.dnskeyRrset, link.keys ?? []);
        if (!members.length) return finish('bogus', 'no-supplied-dnskey-members');
        for (const ds of supported) for (const key of members) {
          const result = dnssecDsMatchesKey(ds, key, selectedPolicy);
          checks.push({ stage: 'ds-digest', zone, valid: result.valid, reason: result.reason, result });
          if (result.valid) { authenticatingKeys.push(key); keyAuthenticationEvidence.push({ stage: 'ds-digest', zone, ...result }); }
        }
        if (!authenticatingKeys.length) return finish('bogus', 'no-matching-supported-ds-key');
      }
      const dnskeySignature = dnssecCheckSignature({ rrset: link.dnskeyRrset, signatures: link.dnskeySignatures, keys: authenticatingKeys, now, policy: selectedPolicy, expectedSigner: zone });
      if (dnskeySignature.valid) {
        const selectedAuthentication = keyAuthenticationEvidence.find(item => item.dnskeyRdataHex === dnskeySignature.selectedEvidence.dnskeyRdataHex);
        if (selectedAuthentication) selectedEvidence.push(selectedAuthentication);
      }
      if (!recordSignature('dnskey-rrset-signature', zone, dnskeySignature)) return finish('bogus', 'invalid-dnskey-rrset-signature');
      // Only members of this authenticated DNSKEY RRset may verify the next stage.
      parent = { zone, keys: members };
    }
    chainEstablished = true;
    if (!answer?.rrset) return finish('bogus', 'missing-answer-rrset');
    if (!dnssecValidationBelow(answer.rrset.owner, parent.zone)) return finish('bogus', 'answer-outside-selected-zone');
    const answerSignature = dnssecCheckSignature({ rrset: answer.rrset, signatures: answer.signatures, keys: parent.keys, now, policy: selectedPolicy, expectedSigner: parent.zone });
    if (!recordSignature('answer-signature', parent.zone, answerSignature)) return finish('bogus', answerSignature.reason);
    return finish('secure', 'authenticated-answer-path');
  } catch (error) { return finish('bogus', error.message); }
}
