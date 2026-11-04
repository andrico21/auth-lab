
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Verify only newly signed long paths, plus selected dependencies at their new clocks."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'long-profile-fixtures.json').read_bytes()
f=json.loads(raw)
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
profiles=json.loads((v.OUT/'profile-fixtures.json').read_text())
rrsets={**base['rrsets'],**profiles['rrsets'],**f['rrsets']}
sigs={**base['signatures'],**profiles['signatures'],**f['signatures']}
keys=base['keys']
v.check('long-profiles-pinned-sha256',hashlib.sha256(raw).hexdigest(),generated_hash('long-profile-fixtures.json'))
v.check('long-profiles-baseline-binding',f['baselineSha256'],hashlib.sha256((v.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
rows=[]
def library_at(identity,offset):
    sig=sigs[identity]; rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
    now=f['baseClock']+offset
    dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
    v.check(identity+':clock-'+str(offset),v.time_state(now,sig['inception'],sig['expiration']),'valid')
    rows.append({'signatureId':identity,'offset':offset,'now':now,'libraryValid':True})
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.OUT) as directory:
    for identity,sig in f['signatures'].items():
        rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':independent-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        for offset in f['observedOffsets']:
            library_at(identity,offset)
# Existing coherent CSK/Ed25519 DNSKEY/parentDS dependencies consumed at new95100 clock.
for keyid in ['child-csk-g1','child-csk-g2','child-ed25519-g1']:
    for identity in [keyid+'-dnskey-signature','parent-ds-for-'+keyid+'-signature']:
        library_at(identity,95100)
# Match all new authenticated parentDS records to their actual child key bytes.
for rrid,keyids in [('parent-ds-dual-algorithm',['child-ksk-g1','child-ed25519-g1']),('parent-ds-provider-overlap',['child-ksk-g1','provider-b-ksk-g1']),('parent-ds-provider-b-only',['provider-b-ksk-g1'])]:
    actual=sorted(v.rdata('DS',r).hex() for r in rrsets[rrid]['records'])
    expected=[]
    for keyid in keyids:
        key=keys[keyid]
        digest=hashlib.sha256(v.name_wire(key['owner'])+v.rdata('DNSKEY',key['text'])).hexdigest()
        expected.append(v.rdata('DS',str(key['keyTag'])+' '+str(key['algorithm'])+' 2 '+digest).hex())
    v.check(rrid+':actual-key-bound-digests',actual,sorted(expected))
v.check('dual-dnskey-algorithm-set',sorted(set(int(r.split()[2]) for r in rrsets['child-dual-algorithm-dnskey']['records'])),[13,15])
report={'schemaVersion':1,'kind':'dnssec-independent-long-clock-profile-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'observations':rows,
 'scope':'New actual long-clock leaf/DNSKEY/parentDS/upper-chain signatures plus existing CSK/Ed15 profile dependencies at95100. No timeless signature assumptions or live server execution.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'long-profile-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable long-profile verification differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
