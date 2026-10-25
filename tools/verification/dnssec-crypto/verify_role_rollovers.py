#!/usr/bin/env python3
"""Actually check exact single-role final DNSKEY sets and their entire future-clock paths."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'role-rollover-fixtures.json').read_bytes(); f=json.loads(raw)
v.check('role-rollover-pinned-sha256',hashlib.sha256(raw).hexdigest(),'59ce4eac57f5cf9a55d9a07354aecfc7b8e9d79d979c613c6b8d66cd9e6e5589')
keys={}; rrsets={}; sigs={}
for name,expected in f['sourceFixtureSha256'].items():
    data=(v.OUT/name).read_bytes(); v.check(name+':source-binding',hashlib.sha256(data).hexdigest(),expected)
    source=json.loads(data); keys.update(source.get('keys',{})); rrsets.update(source.get('rrsets',{})); sigs.update(source.get('signatures',{}))
rrsets.update(f['rrsets']); sigs.update(f['signatures'])
observations=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    for identity,sig in f['signatures'].items():
        data=v.canonical(rrsets[sig['rrsetId']],sig); key=keys[sig['keyId']]
        v.check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        observations.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
clocked=[]
for path_id,path in f['paths'].items():
    final=sigs[path['steps'][-2]['signatureId']]
    rr=rrsets[final['rrsetId']]
    v.check(path_id+':exact-final-keyset',sorted(rr['records']),sorted(keys[keyid]['text'] for keyid in path['exactFinalKeyIds']))
    for offset in path['observedOffsets']:
        now=f['baseClock']+offset; trusted={path['anchorKeyId']}; steps=[]
        for index,step in enumerate(path['steps']):
            sig=sigs[step['signatureId']]; rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
            identity=path_id+':'+str(offset)+':'+str(index)
            v.check(identity+':signer-authenticated',sig['keyId'] in trusted,True)
            v.check(identity+':time',v.time_state(now,sig['inception'],sig['expiration']),'valid')
            data=v.canonical(rr,sig)
            v.check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
            v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
            dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
            if step['role']=='dnskey':
                records={v.rdata('DNSKEY',r) for r in rr['records']}
                trusted.update(k for k,value in keys.items() if value['owner']==rr['owner'] and v.rdata('DNSKEY',value['text']) in records)
            elif step['role']=='ds':
                records={v.rdata('DS',r) for r in rr['records']}
                for keyid in step['matchedChildKeyIds']:
                    candidate=keys[keyid]
                    digest=hashlib.sha256(v.name_wire(candidate['owner'])+v.rdata('DNSKEY',candidate['text'])).hexdigest()
                    expected=v.rdata('DS',str(candidate['keyTag'])+' '+str(candidate['algorithm'])+' 2 '+digest)
                    v.check(identity+':ds-child-owner',rr['owner'],candidate['owner'])
                    v.check(identity+':actual-ds-key-match',expected in records,True)
                    trusted.add(keyid)
            elif step['role']=='answer':
                v.check(identity+':answer-owner',rr['owner'],'www.lab.example.')
                v.check(identity+':answer-records',rr['records'],['192.0.2.80','192.0.2.81'])
            else:
                raise ValueError('Unknown path role')
            steps.append({'role':step['role'],'signatureId':sig['id'],'rrsetId':rr['id'],'keyId':sig['keyId'],'inception':sig['inception'],'expiration':sig['expiration'],'libraryValidAt':now})
        clocked.append({'pathId':path_id,'now':now,'offset':offset,'exactFinalKeyIds':path['exactFinalKeyIds'],'pathValid':True,'steps':steps})
report={'schemaVersion':1,'kind':'dnssec-independent-single-role-rollover-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'newSignatureObservations':observations,'clockedCompletePathObservations':clocked,'scope':'Exact single-role DNSKEY final states and all consumed root/DS/DNSKEY/leaf evidence at95100/day35/day90; no both-g2 substitution. Long120day intervals remain synthetic choices.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); out=v.OUT/'role-rollover-verification.json'
if out.exists() and out.read_bytes()!=result:
    raise RuntimeError('Immutable single-role verification differs')
if not out.exists():
    out.write_bytes(result)
files=['docs/dnssec-expansion/numeric/role-rollover-fixtures.json','docs/dnssec-expansion/numeric/role-rollover-verification.json','tools/verification/dnssec-crypto/generate_role_rollovers.py','tools/verification/dnssec-crypto/verify_role_rollovers.py']
identities={'schemaVersion':1,'kind':'dnssec-numeric-single-role-additive-identities','previousExpandedCatalogSha256':'a4f2fdf2792052b5061f1b805c79d4d92860917ebab25675ac63675cf510be9b','previousExpandedSealUnchanged':True,'addedCounts':{'rrsets':2,'signatures':2,'paths':2,'clockedCompletePathObservations':6,'assertions':len(v.RESULTS)},'files':[{'path':name,'bytes':(v.ROOT/name).stat().st_size,'sha256':hashlib.sha256((v.ROOT/name).read_bytes()).hexdigest()} for name in files],'commandEvidence':['runs/run-035.json','runs/run-036.json'],'scope':'Supplement, not rewrite, the preserved expanded D0 seal. Parent combines this identity list into overall source/review packaging.'}
identity_raw=(json.dumps(identities,indent=2,sort_keys=True)+'\n').encode(); path=v.OUT/'role-rollover-identities.json'
if path.exists() and path.read_bytes()!=identity_raw:
    raise RuntimeError('Immutable role identities differ')
if not path.exists():
    path.write_bytes(identity_raw)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'clockedCompletePaths':len(clocked),'reportSha256':hashlib.sha256(result).hexdigest(),'identityCatalogSha256':hashlib.sha256(identity_raw).hexdigest()},indent=2))
