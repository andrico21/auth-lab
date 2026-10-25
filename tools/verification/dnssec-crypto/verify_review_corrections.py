#!/usr/bin/env python3
"""Verification-only byte reconstruction and OpenSSL checks; no producer/DNS/app imports."""
import hashlib
import json
import pathlib
import struct
import tempfile
import reference_bytes as v

path = v.OUT / 'review-corrections/denial-authority-fixtures.json'
raw = path.read_bytes()
f = json.loads(raw)
v.check('review-corrections:fixture-sha256', hashlib.sha256(raw).hexdigest(), '3cd9d0a42ed1117f9a8bac5869d4b75d98e1ae5d2367513b040d31714c6f3253')
for ref in f['provenance']['sources']:
    data = (v.ROOT / ref['path']).read_bytes()
    v.check(ref['path'] + ':sha256', hashlib.sha256(data).hexdigest(), ref['sha256'])
    v.check(ref['path'] + ':bytes', len(data), ref['bytes'])
for identity, key in f['keys'].items():
    v.check(identity + ':rdata', v.rdata('DNSKEY', key['text']).hex(), key['dnskeyRdataHex'])
    v.check(identity + ':tag', v.key_tag(bytes.fromhex(key['dnskeyRdataHex'])), key['keyTag'])
for identity, rr in f['rrsets'].items():
    v.check(identity + ':rdata', sorted(v.rdata(rr['type'], text).hex() for text in rr['records']), rr['canonicalRdataHex'])
rows = []
with tempfile.TemporaryDirectory(prefix='dnssec-review-corrections-') as directory:
    for identity, sig in f['signatures'].items():
        rr = f['rrsets'][sig['rrsetId']]
        key = f['keys'][sig['keyId']]
        data = v.canonical(rr, sig)
        v.check(identity + ':input', data.hex(), sig['signingInputHex'])
        v.check(identity + ':input-hash', hashlib.sha256(data).hexdigest(), sig['signingInputSha256'])
        wire = struct.pack('!HBBIIIH', sig['typeCovered'], sig['algorithm'], sig['labels'], sig['originalTtl'], sig['expiration'], sig['inception'], sig['keyTag']) + v.name_wire(sig['signer']) + bytes.fromhex(sig['signatureHex'])
        v.check(identity + ':rrsig-rdata', wire.hex(), sig['rrsigRdataHex'])
        v.check(identity + ':rrsig-hash', hashlib.sha256(wire).hexdigest(), sig['rrsigRdataSha256'])
        v.check(identity + ':crypto', v.valid(key, bytes.fromhex(sig['signatureHex']), data), True)
        rows.append(v.openssl_check(identity, key, bytes.fromhex(sig['signatureHex']), data, pathlib.Path(directory)))
for identity, item in f['nsec3'].items():
    actual = v.nsec3(item['owner'], item['iterations'], bytes.fromhex(item['saltHex']))
    v.check(identity + ':wire', v.name_wire(item['owner']).hex(), item['ownerWireHex'])
    v.check(identity + ':hash', actual['hashHex'], item['finalHashHex'])
    v.check(identity + ':initial', actual['initialHashHex'], item['initialHashHex'])
    v.check(identity + ':base32hex', actual['hashBase32hex'], item['hashBase32hex'])
for label in ['ancestor-delegation-nsec3', 'dname-nsec3']:
    profile = f['profiles'][label]
    chain = profile['chain']
    for index, item in enumerate(chain):
        actual = v.nsec3(item['originalOwner'], 0, b'')['hashBase32hex']
        v.check(label + ':owner-' + str(index), actual, item['ownerHash'])
        v.check(label + ':link-' + str(index), item['nextHash'], chain[(index + 1) % len(chain)]['ownerHash'])
        rr = f['rrsets'][item['rrsetId']]
        v.check(label + ':encoded-owner-' + str(index), rr['owner'], actual + '.' + profile['zone'])
        v.check(label + ':encoded-next-' + str(index), rr['records'][0].split()[4], item['nextHash'])
print(json.dumps({'schemaVersion': 1, 'kind': 'dnssec-independent-review-correction-denial-verification',
    'fixture': {'path': str(path.relative_to(v.ROOT)), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
    'independentCanonicalReconstruction': True, 'producerOrDnsLibraryImported': False,
    'productionEvaluatorExecuted': False, 'predicates': len(v.RESULTS), 'results': v.RESULTS, 'openssl': rows}, indent=2, sort_keys=True))
