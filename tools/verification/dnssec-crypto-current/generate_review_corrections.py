
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Additive public R04 tuples from pinned reference libraries, never application state."""
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = ROOT
BASE = output_root()
OUT = BASE / 'review-corrections'
assert importlib.metadata.version('dnspython') == '2.8.0'
assert importlib.metadata.version('cryptography') == '50.0.0'
original_path = BASE / 'dnssec-numeric-fixtures.json'
original = json.loads(original_path.read_bytes())
sha = lambda data: hashlib.sha256(data).hexdigest()
refs = [original_path, BASE / 'runtime-and-licenses.json', BASE / 'sources/rfc6840.txt', BASE / 'sources/rfc5155.txt', pathlib.Path(__file__)]
f = {'schemaVersion': 1, 'kind': 'dnssec-independent-review-correction-denial-fixtures',
     'baseClock': 1792713600, 'keys': {}, 'rrsets': {}, 'signatures': {}, 'nsec3': {}, 'profiles': {},
     'provenance': {'independentOfProduction': True, 'applicationSourceRead': False,
                    'productionEvaluatorExecuted': False, 'osSandboxEnforcementClaimed': False,
                    'producer': reference_path(pathlib.Path(__file__)),
                    'libraries': {'dnspython': '2.8.0', 'cryptography': '50.0.0'},
                    'python': platform.python_version(),
                    'sources': [{'path': reference_path(p), 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in refs],
                    'sections': ['RFC6840 section4.1', 'RFC5155 sections5,8.3'],
                    'scope': 'Actual signed bounded denial-rule controls, not full live zone or server conformance. Existing deterministic fixture keys are reference producers only; no private bytes are emitted.'}}
for keyid in ['example-zsk-g1', 'child-zsk-g1']:
    k = original['keys'][keyid]
    f['keys'][keyid] = {name: value for name, value in k.items() if name != 'generation'}

def record(identity, owner, typ, records, keyid):
    rr = dns.rrset.from_text(owner, 300, 'IN', typ, *records)
    k = original['keys'][keyid]
    private = ec.derive_private_key(int(k['generation']['fixtureOnlyPrivateHex'], 16), ec.SECP256R1())
    key = dns.rdata.from_text('IN', 'DNSKEY', k['text'])
    sig = dns.dnssec.sign(rr, private, dns.name.from_text(k['owner']), key,
                          inception=1792713000, expiration=1792717200, deterministic=True)
    data = dns.dnssec._make_rrsig_signature_data(rr, sig)
    f['rrsets'][identity] = {'id': identity, 'owner': owner, 'class': 'IN', 'type': typ,
                             'typeCode': int(rr.rdtype), 'ttl': 300, 'records': records,
                             'canonicalRdataHex': sorted(r.to_digestable().hex() for r in rr)}
    sid = identity + '-signature'
    f['signatures'][sid] = {'id': sid, 'rrsetId': identity, 'keyId': keyid,
        'typeCovered': int(sig.type_covered), 'algorithm': int(sig.algorithm), 'labels': sig.labels,
        'originalTtl': sig.original_ttl, 'inception': sig.inception, 'expiration': sig.expiration,
        'keyTag': sig.key_tag, 'signer': sig.signer.to_text(), 'rrsigText': sig.to_text(),
        'rrsigRdataHex': sig.to_wire().hex(), 'rrsigRdataSha256': sha(sig.to_wire()),
        'signatureHex': sig.signature.hex(), 'signingInputHex': data.hex(), 'signingInputSha256': sha(data),
        'verificationAt': f['baseClock'], 'expectedCryptographicValid': True}

names = ['example.', 'lab.example.', 'no.lab.example.', '*.lab.example.', 'cee.lab.example.',
         'branch.lab.example.', 'no.branch.lab.example.', '*.branch.lab.example.']
for index, name in enumerate(names):
    wire = dns.name.from_text(name).to_digestable()
    digest = hashlib.sha1(wire).hexdigest()
    identity = 'review-correction-name-' + str(index)
    f['nsec3'][identity] = {'id': identity, 'owner': name, 'ownerWireHex': wire.hex(),
        'hashAlgorithm': 1, 'iterations': 0, 'saltHex': '', 'initialHashHex': digest,
        'finalHashHex': digest, 'hashBase32hex': dns.dnssec.nsec3_hash(name, '', 0, 1), 'totalHashApplications': 1}
for label, zone, entries, keyid in [
    ('ancestor-delegation', 'example.', [('example.', 'NS SOA DNSKEY RRSIG'), ('lab.example.', 'NS RRSIG')], 'example-zsk-g1'),
    ('dname', 'lab.example.', [('lab.example.', 'NS SOA DNSKEY RRSIG'), ('branch.lab.example.', 'DNAME RRSIG')], 'child-zsk-g1')]:
    ordered = sorted((dns.dnssec.nsec3_hash(name, '', 0, 1), name, bitmap) for name, bitmap in entries)
    chain = []
    for index, (hashed, name, bitmap) in enumerate(ordered):
        nxt = ordered[(index + 1) % len(ordered)][0]
        identity = 'review-correction-nsec3-' + label + '-' + str(index)
        record(identity, hashed + '.' + zone, 'NSEC3', ['1 0 0 - ' + nxt + ' ' + bitmap], keyid)
        chain.append({'rrsetId': identity, 'originalOwner': name, 'ownerHash': hashed, 'nextHash': nxt, 'flags': 0})
    f['profiles'][label + '-nsec3'] = {'zone': zone, 'signerKeyId': keyid, 'hashAlgorithm': 1, 'iterations': 0, 'saltHex': '', 'chain': chain}
for suffix, owner, nxt, bitmap in [
    ('apex', 'lab.example.', 'branch.lab.example.', 'NS SOA DNSKEY RRSIG NSEC'),
    ('branch', 'branch.lab.example.', 'z.lab.example.', 'DNAME RRSIG NSEC'),
    ('z', 'z.lab.example.', 'lab.example.', 'A RRSIG NSEC')]:
    record('review-correction-nsec-dname-' + suffix, owner, 'NSEC', [nxt + ' ' + bitmap], 'child-zsk-g1')
f['profiles']['dname-nsec'] = {'zone': 'lab.example.', 'signerKeyId': 'child-zsk-g1',
    'rrsetIds': ['review-correction-nsec-dname-' + suffix for suffix in ['apex', 'branch', 'z']]}
OUT.mkdir(exist_ok=True)
text = (json.dumps(f, indent=2, sort_keys=True) + '\n').encode()
with (OUT / 'denial-authority-fixtures.json').open('xb') as handle:
    handle.write(text)
print(json.dumps({'path': reference_path((OUT / 'denial-authority-fixtures.json')), 'bytes': len(text), 'sha256': sha(text), 'rrsets': len(f['rrsets']), 'signatures': len(f['signatures']), 'nsec3': len(f['nsec3'])}))
