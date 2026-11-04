
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[2]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Public DNS19 evidence only. dnspython produces signatures, TSIG and digest bytes."""
import copy
import hashlib
import importlib.metadata
import io
import json
import pathlib
import platform
import struct
import subprocess
import sys
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rrset
import dns.tsig
import dns.update
import dns.zone
import dns.zonetypes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = ROOT
HERE = pathlib.Path(__file__).resolve().parent
NUM = output_root()
OUT = NUM / 'post-freeze-completion/dns19'
BASE = 1792713600
ZONE = 'lab.example.'
FREEZE = 'b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
ORDER = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
OUT.mkdir(parents=True, exist_ok=True)


def identity(path):
    raw = path.read_bytes()
    return {'path': reference_path(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def public(value):
    """Frozen public projection; never carry frozen private or expectation fields."""
    if isinstance(value, dict):
        return {k: public(v) for k, v in value.items() if not k.startswith('expected') and k != 'generation'}
    if isinstance(value, list):
        return [public(v) for v in value]
    return value


frozen_path = NUM / 'dnssec-numeric-fixtures.json'
base = json.loads(frozen_path.read_bytes())
zonemd_path = NUM / 'zonemd-auth-fixtures.json'
frozen_zonemd = json.loads(zonemd_path.read_bytes())
data = {'schemaVersion': 1, 'postFreeze': True, 'freezeAuthoritySha256': FREEZE,
        'baseClock': BASE, 'id': 'dns19-public-reference-vectors',
        'kind': 'dns19-independent-public-transport-reference-vectors',
        'keys': {}, 'dnssecKeys': {}, 'rrsets': {}, 'signatures': {}, 'messages': {}, 'streams': {},
        'updates': {}, 'macReferenceTuples': [], 'zonemdReferenceTuples': []}
for keyid in ['child-ksk-g1', 'child-zsk-g1', 'root-ksk-g1', 'root-zsk-g1', 'example-ksk-g1', 'example-zsk-g1']:
    data['dnssecKeys'][keyid] = public(base['keys'][keyid])
private = {}
for keyid in ['child-zsk-g1']:
    seed = hashlib.sha256(('auth-lab-dnssec-D0:' + keyid).encode()).digest()
    scalar = int.from_bytes(seed, 'big') % (ORDER - 1) + 1
    private[keyid] = ec.derive_private_key(scalar, ec.SECP256R1())
    rebuilt = dns.dnssec.make_dnskey(private[keyid].public_key(), 13, flags=256)
    assert rebuilt.to_wire().hex() == data['dnssecKeys'][keyid]['dnskeyRdataHex']


def retain(rrid, sigid=None):
    data['rrsets'][rrid] = public(base['rrsets'][rrid])
    if sigid is not None:
        data['signatures'][sigid] = public(base['signatures'][sigid])


for rrid in ['child-ns', 'child-soa', 'child-mx', 'child-txt', 'www-a', 'wildcard-a']:
    retain(rrid, rrid + '-signature')
for prefix in ['root', 'example', 'child']:
    retain(prefix + '-dnskey-g1', prefix + '-dnskey-g1-by-ksk')
retain('root-example-ds', 'root-example-ds-signature')
retain('example-child-ds', 'example-child-ds-signature')


def rrset(rrid, owner, typ, records, ttl=3600, sign=True):
    rr = dns.rrset.from_text(owner, ttl, 'IN', typ, *records)
    data['rrsets'][rrid] = {'id': rrid, 'owner': owner, 'class': 'IN', 'type': typ,
                             'typeCode': int(rr.rdtype), 'ttl': ttl, 'records': records,
                             'canonicalRdataHex': sorted(r.to_digestable().hex() for r in rr)}
    if sign:
        keyid = 'child-zsk-g1'
        dk = dns.rdata.from_text('IN', 'DNSKEY', data['dnssecKeys'][keyid]['text'])
        sig = dns.dnssec.sign(rr, private[keyid], dns.name.from_text(ZONE), dk,
                              inception=BASE - 600, expiration=BASE + 3600, deterministic=True)
        signing_input = dns.dnssec._make_rrsig_signature_data(rr, sig)
        sigid = rrid + '-signature'
        data['signatures'][sigid] = {'id': sigid, 'rrsetId': rrid, 'keyId': keyid,
            'typeCovered': int(sig.type_covered), 'algorithm': sig.algorithm, 'labels': sig.labels,
            'originalTtl': sig.original_ttl, 'inception': sig.inception, 'expiration': sig.expiration,
            'keyTag': sig.key_tag, 'signer': sig.signer.to_text(), 'rrsigText': sig.to_text(),
            'rrsigRdataHex': sig.to_wire().hex(), 'signatureHex': sig.signature.hex(),
            'signingInputHex': signing_input.hex(), 'signingInputSha256': hashlib.sha256(signing_input).hexdigest()}
    return rrid


for serial in [2026102200, 2026102302]:
    rrset('child-soa-' + str(serial), ZONE, 'SOA',
          [f'ns1.lab.example. hostmaster.lab.example. {serial} 3600 600 86400 300'])
rrset('www-a-initial-update', 'www.lab.example.', 'A', ['192.0.2.82'])
for rrid, owner, nxt, types in [
    ('transfer-apex-nsec', ZONE, '*.lab.example.', 'NS SOA MX TXT DNSKEY RRSIG NSEC'),
    ('transfer-wildcard-nsec', '*.lab.example.', 'unsigned.lab.example.', 'A RRSIG NSEC'),
    ('transfer-delegation-nsec', 'unsigned.lab.example.', 'www.lab.example.', 'NS RRSIG NSEC'),
    ('transfer-www-nsec', 'www.lab.example.', ZONE, 'A RRSIG NSEC')]:
    rrset(rrid, owner, 'NSEC', [nxt + ' ' + types], ttl=300)
rrset('transfer-unsigned-ns', 'unsigned.lab.example.', 'NS', ['ns.unsigned.lab.example.'], sign=False)
rrset('transfer-unsigned-glue', 'ns.unsigned.lab.example.', 'A', ['192.0.2.200'], sign=False)
COMMON = ['child-dnskey-g1', 'child-ns', 'child-mx', 'child-txt', 'wildcard-a',
          'transfer-apex-nsec', 'transfer-wildcard-nsec', 'transfer-delegation-nsec',
          'transfer-www-nsec', 'transfer-unsigned-ns', 'transfer-unsigned-glue']


def sig_for(rrid):
    return 'child-dnskey-g1-by-ksk' if rrid == 'child-dnskey-g1' else rrid + '-signature'


def zone_ids(soa='child-soa', a='www-a'):
    return [soa] + COMMON + [a]


def zone_lines(ids):
    lines = []
    for rrid in ids:
        rr = data['rrsets'][rrid]
        lines += [f"{rr['owner']} {rr['ttl']} IN {rr['type']} {r}" for r in rr['records']]
        sigid = sig_for(rrid)
        if sigid in data['signatures']:
            lines.append(f"{rr['owner']} {rr['ttl']} IN RRSIG {data['signatures'][sigid]['rrsigText']}")
    return lines


oldids = zone_ids()
newids = zone_ids('child-soa-2026102302')
initialids = zone_ids(a='www-a-initial-update')
olderids = zone_ids('child-soa-2026102200')
newtext = '\n'.join(zone_lines(newids)) + '\n'

# TSIG synthetic keys are regenerated privately. Only fingerprints and custody leave this process.
secrets = {}
libkeys = {}
for keyid, name, custodians in [
    ('zone-transfer', 'zone-transfer-key.', ['dnsPrimary', 'dnsSecondary']),
    ('update', 'update-key.', ['dnsOperator', 'dnsPrimary'])]:
    secret = hashlib.sha256(('auth-lab-dns19-postfreeze-tsig:' + name).encode()).digest()
    secrets[keyid] = secret
    libkeys[keyid] = dns.tsig.Key(name, secret, algorithm='hmac-sha256.')
    data['keys'][keyid] = {'id': keyid, 'keyName': name, 'algorithm': 'hmac-sha256.',
        'fingerprint': hashlib.sha256(secret).hexdigest(), 'custodians': custodians,
        'secretRef': 'synthetic-private-regeneration:' + keyid,
        'scope': 'Transaction MAC only; not ACL, DNSSEC trust or confidentiality.'}


class CaptureContext:
    def __init__(self, inner, chunks):
        self.inner = inner
        self.chunks = chunks
    def update(self, chunk):
        self.chunks.append(chunk)
        return self.inner.update(chunk)
    def sign(self):
        return self.inner.sign()


# Observe actual library HMAC input, including its seeded prior-message context.
original_get_context = dns.tsig.get_context
captured_contexts = []
def capture_get_context(key):
    chunks = []
    captured_contexts.append(chunks)
    return CaptureContext(original_get_context(key), chunks)
dns.tsig.get_context = capture_get_context


def append_tsig(unsigned, key, tsig):
    stream = io.BytesIO()
    dns.rrset.from_rdata(key.name, 0, tsig).to_wire(stream)
    count = struct.unpack('!H', unsigned[10:12])[0]
    return unsigned[:10] + struct.pack('!H', count + 1) + unsigned[12:] + stream.getvalue()


def signed_message(identity, message, keyid, request_mac=b'', prior_mac=b'', ctx=None, multi=False):
    message.tsig = None
    unsigned = message.to_wire(want_shuffle=False)
    key = libkeys[keyid]
    message.use_tsig(key, fudge=300)
    template = message.tsig[0]
    if ctx is None:
        before = len(captured_contexts)
        tsig, newctx = dns.tsig.sign(unsigned, key, template, time=BASE, request_mac=request_mac, multi=multi)
        chunks = captured_contexts[before]
    else:
        tsig, newctx = dns.tsig.sign(unsigned, key, template, time=BASE, request_mac=request_mac, ctx=ctx, multi=multi)
        chunks = ctx.chunks
    wire = append_tsig(unsigned, key, tsig)
    tuple_id = identity + '-hmac-reference'
    data['macReferenceTuples'].append({'id': tuple_id, 'keyFingerprint': data['keys'][keyid]['fingerprint'],
        'keyName': key.name.to_text(), 'algorithm': key.algorithm.to_text(), 'unsignedWireHex': unsigned.hex(),
        'timeSigned': BASE, 'fudgeSeconds': 300, 'requestMacHex': request_mac.hex(), 'priorMacHex': prior_mac.hex(),
        'macInputHex': b''.join(chunks).hex(), 'macHex': tsig.mac.hex()})
    data['messages'][identity] = {'id': identity, 'keyId': keyid, 'messageId': message.id,
        'unsignedWireHex': unsigned.hex(), 'wireHex': wire.hex(), 'tcpFramedWireHex': (struct.pack('!H', len(wire)) + wire).hex(),
        'tsigStart': len(unsigned), 'tsigRdataHex': tsig.to_wire().hex(), 'timeSigned': BASE, 'fudgeSeconds': 300,
        'timeSigned48Hex': BASE.to_bytes(6, 'big').hex(), 'error': 0, 'otherHex': '', 'originalId': tsig.original_id,
        'requestMacHex': request_mac.hex(), 'priorMacHex': prior_mac.hex(), 'macHex': tsig.mac.hex(),
        'macReferenceTupleId': tuple_id, 'rcode': message.rcode(),
        'macMode': 'tcp-prior-mac-timers' if prior_mac else ('response-request-mac-full-variables' if request_mac else 'request-full-variables')}
    return tsig.mac, newctx


def rr_from_line(line):
    owner, ttl, cls, typ, text = line.split(None, 4)
    return dns.rrset.from_text(owner, int(ttl), cls, typ, text)


def transfer(streamid, kind, baseids, requested_serial, qid, incremental=False):
    q = dns.message.make_query(ZONE, 'AXFR' if kind == 'axfr' else 'IXFR')
    q.id = qid
    q.flags = 0
    if kind != 'axfr':
        rr = data['rrsets']['child-soa' if requested_serial == 2026102301 else 'child-soa-2026102200']
        q.authority.append(dns.rrset.from_text(rr['owner'], rr['ttl'], 'IN', 'SOA', *rr['records']))
    requestid = streamid + '-request'
    request_mac, _ = signed_message(requestid, q, 'zone-transfer')
    soa = zone_lines(['child-soa-2026102302'])[0]
    if incremental:
        oldsoa = zone_lines(['child-soa'])[0]
        oldsig = zone_lines(['child-soa'])[1]
        newsig = zone_lines(['child-soa-2026102302'])[1]
        deletes = [oldsoa, oldsig]
        adds = [soa, newsig]
        if baseids == initialids:
            deletes += zone_lines(['www-a-initial-update'])
            adds += zone_lines(['www-a'])
        lines = [soa] + deletes + adds + [soa]
        chunks = [lines[:3], lines[3:]]
    else:
        lines = [soa] + [line for line in zone_lines(newids) if line != soa] + [soa]
        chunks = [lines[:10], lines[10:20], lines[20:]]
    responseids = []
    ctx = None
    prior = b''
    for index, chunk in enumerate(chunks):
        response = dns.message.make_response(q)
        response.flags = dns.flags.QR | dns.flags.AA
        response.answer = [rr_from_line(line) for line in chunk]
        mid = streamid + '-response-' + str(index + 1)
        mac, ctx = signed_message(mid, response, 'zone-transfer', request_mac if index == 0 else b'', prior, ctx, True)
        data['messages'][mid].update({'streamId': streamid, 'sequence': index, 'answerRecords': chunk})
        responseids.append(mid)
        prior = mac
    data['streams'][streamid] = {'id': streamid, 'kind': 'ixfr' if incremental else kind,
        'requestMessageId': requestid, 'responseMessageIds': responseids, 'requestedSerial': requested_serial,
        'baseZoneText': '\n'.join(zone_lines(baseids)) + '\n', 'resultZoneText': newtext,
        'zoneRrsetIds': newids, 'zoneSignatureIds': [sig_for(r) for r in newids if sig_for(r) in data['signatures']]}


transfer('axfr', 'axfr', oldids, None, 0x1901)
transfer('ixfr', 'ixfr', oldids, 2026102301, 0x1902, True)
transfer('fallback', 'fallback', olderids, 2026102200, 0x1903)
transfer('updateAxfr', 'axfr', initialids, None, 0x1904)
transfer('updateIxfr', 'ixfr', initialids, 2026102301, 0x1905, True)

# Explicit selected management policy is separate from every mathematical MAC tuple.
data['managementPolicy'] = {'id': 'selected-www-a-only-update-policy', 'subjectKeyName': 'update-key.',
    'rule': 'Only replace www.lab.example. IN A; apex NS edits are outside this selected grant.',
    'allowedOwner': 'www.lab.example.', 'allowedType': 'A', 'deniedOwner': ZONE, 'deniedType': 'NS',
    'source': 'RFC2136 section 2.2 REFUSED; RFC3007 authorization remains distinct from TSIG verification.'}
for updateid, owner, typ, records, qid, rcode in [
    ('wwwAllowed', 'www', 'A', ['192.0.2.80', '192.0.2.81'], 0x1911, 0),
    ('apexNsDenied', '@', 'NS', ['ns.attacker.example.'], 0x1912, 5)]:
    update = dns.update.Update(ZONE)
    update.id = qid
    update.replace(owner, 3600, typ, *records)
    requestid = updateid + '-request'
    request_mac, _ = signed_message(requestid, update, 'update')
    response = dns.message.make_response(update)
    response.set_rcode(rcode)
    responseid = updateid + '-response'
    signed_message(responseid, response, 'update', request_mac)
    data['updates'][updateid] = {'id': updateid, 'requestMessageId': requestid, 'responseMessageId': responseid,
        'transferStreamId': 'updateAxfr', 'policyRef': data['managementPolicy']['id']}

# Alter one transmitted A RDATA octet, retain its original transmitted MAC, and also
# publish a POSITIVE tuple for the actual recomputed HMAC over the changed input.
original = data['messages']['wwwAllowed-request']
unsigned = bytes.fromhex(original['unsignedWireHex'])
needle = bytes([192, 0, 2, 80])
assert unsigned.count(needle) == 1
changed_offset = unsigned.index(needle) + 3
mutated = unsigned[:changed_offset] + bytes([83]) + unsigned[changed_offset + 1:]
changed_wire = bytearray.fromhex(original['wireHex'])
changed_wire[changed_offset] = 83
key = libkeys['update']
template = dns.rdata.from_wire(255, 250, bytes.fromhex(original['tsigRdataHex']), 0, len(bytes.fromhex(original['tsigRdataHex'])))
before = len(captured_contexts)
recomputed, _ = dns.tsig.sign(mutated, key, template, time=BASE)
recomputed_tuple = {'id': 'mutatedRetainedMac-recomputed-hmac-reference', 'keyFingerprint': data['keys']['update']['fingerprint'],
    'keyName': key.name.to_text(), 'algorithm': key.algorithm.to_text(), 'unsignedWireHex': mutated.hex(),
    'timeSigned': BASE, 'fudgeSeconds': 300, 'requestMacHex': '', 'priorMacHex': '',
    'macInputHex': b''.join(captured_contexts[before]).hex(), 'macHex': recomputed.mac.hex()}
data['macReferenceTuples'].append(recomputed_tuple)
mutid = 'mutatedRetainedMac-request'
data['messages'][mutid] = {**original, 'id': mutid, 'unsignedWireHex': mutated.hex(), 'wireHex': bytes(changed_wire).hex(),
    'tcpFramedWireHex': (struct.pack('!H', len(changed_wire)) + changed_wire).hex(),
    'macReferenceTupleId': recomputed_tuple['id'], 'retainedMacFromMessageId': 'wwwAllowed-request',
    'changedOffset': changed_offset, 'recomputedMacHex': recomputed.mac.hex()}
error = dns.message.make_response(dns.update.Update(ZONE))
error.id = original['messageId']
error.set_rcode(dns.rcode.NOTAUTH)
error_unsigned = error.to_wire(want_shuffle=False)
error_tsig = template.replace(time_signed=BASE, mac=b'', error=dns.rcode.BADSIG)
error_wire = append_tsig(error_unsigned, key, error_tsig)
errorid = 'mutatedRetainedMac-response'
data['messages'][errorid] = {'id': errorid, 'messageId': error.id, 'keyId': 'update',
    'unsignedWireHex': error_unsigned.hex(), 'wireHex': error_wire.hex(),
    'tcpFramedWireHex': (struct.pack('!H', len(error_wire)) + error_wire).hex(),
    'tsigStart': len(error_unsigned), 'tsigRdataHex': error_tsig.to_wire().hex(), 'timeSigned': BASE,
    'timeSigned48Hex': BASE.to_bytes(6, 'big').hex(), 'fudgeSeconds': 300, 'error': 16, 'otherHex': '',
    'originalId': error_tsig.original_id, 'macHex': '', 'requestMacHex': '', 'priorMacHex': '',
    'rcode': 9, 'macMode': 'unsigned-badsig-error'}
data['updates']['mutatedRetainedMac'] = {'id': 'mutatedRetainedMac', 'requestMessageId': mutid,
    'responseMessageId': errorid, 'transferStreamId': 'updateAxfr', 'policyRef': data['managementPolicy']['id']}
dns.tsig.get_context = original_get_context

# dnspython canonical iteration is independent of the verifier's reference_bytes collation.
def library_zone_input(text):
    zone = dns.zone.from_text(text, origin=ZONE, relativize=False)
    output = bytearray()
    for name in sorted(zone.nodes):
        node = zone.nodes[name]
        bytype = {}
        for rdataset in node.rdatasets:
            if name == zone.origin and (rdataset.rdtype == 63 or (rdataset.rdtype == 46 and rdataset.covers == 63)):
                continue
            bytype.setdefault(int(rdataset.rdtype), []).append(rdataset)
        for typ, rdatasets in sorted(bytype.items()):
            records = sorted({r.to_digestable() for rdataset in rdatasets for r in rdataset})
            for raw in records:
                output.extend(name.to_digestable() + struct.pack('!HHIH', typ, 1, rdatasets[0].ttl, len(raw)) + raw)
    return bytes(output), zone


original_text = frozen_zonemd['zonemd']['zoneText']
assert original_text.count('192.0.2.200') == 1
for identity_, text in [('zonemd-original', original_text), ('zonemd-unsigned-glue-mutated', original_text.replace('192.0.2.200', '192.0.2.201'))]:
    raw, zone = library_zone_input(text)
    digest = zone.compute_digest(dns.zonetypes.DigestHashAlgorithm.SHA384)
    assert hashlib.sha384(raw).digest() == digest.digest
    data['zonemdReferenceTuples'].append({'id': identity_, 'canonicalZoneWireHex': raw.hex(),
        'digestHex': digest.digest.hex(), 'scheme': 1, 'hashAlgorithm': 1, 'zoneText': text,
        'frozenZoneRef': reference_path(zonemd_path), 'zoneTextSha256': hashlib.sha256(text.encode()).hexdigest()})
assert data['zonemdReferenceTuples'][0]['digestHex'] == frozen_zonemd['zonemd']['digestHex']

source_specs = [('rfc8945', ['4.3', '5.2.2', '5.3', '5.3.1', '5.3.2']),
                ('rfc5936', ['2.1', '2.2', '3.3']), ('rfc1995', ['3', '4']),
                ('rfc2136', ['2.2', '2.5']), ('rfc8976', ['3.3.1', '3.3.1.1', '3.3.1.2', '4'])]
data['provenance'] = {'producer': identity(HERE / 'produce.py'),
    'inputs': [identity(frozen_path), identity(zonemd_path), identity(ROOT / 'docs/dnssec-expansion/contract-freeze.json'),
               identity(NUM / 'runtime-and-licenses.json'), identity(ROOT / reference_path(CURRENT_TOOLS / 'reference_bytes.py'))],
    'sources': [{**identity(ROOT / 'docs/dnssec-expansion/sources/publication' / (rfc + '.txt')),
                 'sections': sections, 'primaryUrl': 'https://www.rfc-editor.org/rfc/' + rfc + '.html',
                 'captureRef': 'docs/dnssec-expansion/sources/publication/capture-metadata.json'} for rfc, sections in source_specs],
    'runtime': {'python': platform.python_version(),
                'packages': {name: importlib.metadata.version(name) for name in ['dnspython', 'cryptography', 'cffi', 'pycparser']},
                'opensslCli': subprocess.run(['openssl', 'version'], capture_output=True, text=True, check=True).stdout.strip(),
                'pythonExecutable': reference_path(pathlib.Path(sys.executable))},
    'command': [_current_sys.executable, '-B', str(_CurrentPath(__file__).resolve())],
    'zoneVariance': 'Transfer zones deliberately omit frozen checksum-only ZONEMD/RRSIG(ZONEMD), replace contradictory two-node frozen NSEC span with four signed NSEC nodes and apex without ZONEMD bit. Unsigned delegation NS and glue retained exactly. No new key or fictitious apex NS address introduced. Other frozen signed RRsets unchanged.',
    'updateDirection': 'Initial update-only holdings www-a-initial-update .82; UPDATE replaces with frozen www-a .80/.81, newly signed SOA2302. Regular transfers change only SOA/RRSIG(SOA).',
    'secretCustody': 'Deterministic synthetic signer and HMAC secrets regenerated only in local process; no private bytes emitted.',
    'limits': ['Offline fixed-clock numeric reference, not live DNS/transfer/update server interoperability.',
               'MAC authentication does not decide ACL or DNSSEC trust; selected management policy is separately declared.',
               'New tuples contain actual positive HMAC/digest values, never application acceptance expectations.',
               'Frozen ZONEMD checksum variant kept exact, including its original NSEC span; not reused as coherent transfer NSEC chain.',
               'Existing offline environment reused; interpreter and system OpenSSL are not bundled by this addendum.']}
raw = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()
path = OUT / 'dns19-fixtures.json'
if path.exists() and path.read_bytes() != raw:
    raise RuntimeError('Preserve prior producer output before regenerating changed evidence')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({**identity(path), 'messages': len(data['messages']), 'streams': len(data['streams']),
                  'macReferenceTuples': len(data['macReferenceTuples']), 'zonemdReferenceTuples': len(data['zonemdReferenceTuples']),
                  'rrsets': len(data['rrsets']), 'signatures': len(data['signatures'])}, sort_keys=True))
