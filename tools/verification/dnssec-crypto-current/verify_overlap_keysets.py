
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Independently verify exact intermediate membership and all consumed clock-path evidence."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'overlap-keysets-fixtures.json').read_bytes(); f=json.loads(raw)
v.check('overlap-fixture-pinned-sha256',hashlib.sha256(raw).hexdigest(),generated_hash('overlap-keysets-fixtures.json'))
keys={}; rrsets={}; sigs={}
for name,expected in f['sourceFixtureSha256'].items():
    data=(v.OUT/name).read_bytes(); v.check(name+':source-binding',hashlib.sha256(data).hexdigest(),expected)
    source=json.loads(data); keys.update(source.get('keys',{})); rrsets.update(source.get('rrsets',{})); sigs.update(source.get('signatures',{}))
rrsets.update(f['rrsets']); sigs.update(f['signatures'])
observations=[]
for rrid,keyids in f['exactMemberships'].items():
    v.check(rrid+':exact-membership',sorted(rrsets[rrid]['records']),sorted(keys[keyid]['text'] for keyid in keyids))
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.OUT) as directory:
    for identity,sig in f['signatures'].items():
        data=v.canonical(rrsets[sig['rrsetId']],sig); key=keys[sig['keyId']]
        v.check(identity+':independent-canonical',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        observations.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
clocked=[]
for path_id,path in f['paths'].items():
    for offset in path['observedOffsets']:
        now=f['baseClock']+offset; trusted={path['anchorKeyId']}; steps=[]
        for index,step in enumerate(path['steps']):
            sig=sigs[step['signatureId']]; rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
            identity=path_id+':'+str(offset)+':'+str(index)
            v.check(identity+':authenticated-signer',sig['keyId'] in trusted,True)
            v.check(identity+':signed-current-window',v.time_state(now,sig['inception'],sig['expiration']),'valid')
            data=v.canonical(rr,sig)
            v.check(identity+':independent-input',data.hex(),sig['signingInputHex'])
            v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
            dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
            if step['role']=='dnskey':
                records={v.rdata('DNSKEY',record) for record in rr['records']}
                trusted.update(k for k,candidate in keys.items() if candidate['owner']==rr['owner'] and v.rdata('DNSKEY',candidate['text']) in records)
            elif step['role']=='ds':
                records={v.rdata('DS',record) for record in rr['records']}
                for keyid in step['matchedChildKeyIds']:
                    candidate=keys[keyid]
                    digest=hashlib.sha256(v.name_wire(candidate['owner'])+v.rdata('DNSKEY',candidate['text'])).hexdigest()
                    expected=v.rdata('DS',str(candidate['keyTag'])+' '+str(candidate['algorithm'])+' 2 '+digest)
                    v.check(identity+':ds-owner',rr['owner'],candidate['owner'])
                    v.check(identity+':computed-key-digest-matches',expected in records,True)
                    trusted.add(keyid)
            elif step['role']=='answer':
                v.check(identity+':exact-answer',rr['records'],['192.0.2.80','192.0.2.81'])
            else:
                raise ValueError('Unknown path role')
            steps.append({'role':step['role'],'signatureId':sig['id'],'rrsetId':rr['id'],'keyId':sig['keyId'],'inception':sig['inception'],'expiration':sig['expiration'],'libraryValidAt':now})
        clocked.append({'pathId':path_id,'offset':offset,'now':now,'exactChildKeyIds':path['exactChildKeyIds'],'pathValid':True,'steps':steps})
report={'schemaVersion':1,'kind':'dnssec-independent-authored-overlap-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'newSignatureObservations':observations,'clockedCompletePathObservations':clocked,'scope':'Only exact already-authored ZSK/KSK/CSK/Model1 provider keysets. Every consumed chain/leaf signature is actually checked at its protocol clock. Long-window fixtures do not establish publication/cache/hold-down policy or operational lifetime advice.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); path=v.OUT/'overlap-keysets-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable overlap verification differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'clockedCompletePaths':len(clocked),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
