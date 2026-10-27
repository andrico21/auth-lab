
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[1]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Verify additive audit bytes with an independent canonicalizer and two crypto surfaces."""
import hashlib
import json
import pathlib
import struct
import sys
import tempfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import reference_bytes as v
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
ROOT=v.ROOT; OUT=v.OUT/'post-freeze-contract-errata'
FREEZE_HASH='b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
PUB_HASH=generated_hash('post-freeze-contract-errata/publication-fixtures.json')
RES_HASH=generated_hash('post-freeze-contract-errata/resolution-fixtures-owner-wire-corrected.json')
RES_FILENAME='resolution-fixtures-owner-wire-corrected.json'
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
pub=json.loads((OUT/'publication-fixtures.json').read_text()); res=json.loads((OUT/RES_FILENAME).read_text())
provenance=json.loads((OUT/'generation-provenance.json').read_text())
keys={**base['keys'],**pub['keys']}; rrsets={**base['rrsets'],**pub['rrsets'],**res['rrsets']}; sigs={**base['signatures'],**pub['signatures'],**res['signatures']}
T=1792713600; I=1792713000; X=1792717200; LONG=1803081600
frozen_observations=[]
for entry in provenance['frozenOwnedArtifactsBefore']:
    actual=hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()
    if actual!=entry['sha256']:
        raise RuntimeError('Frozen owned artifact differs before verifier: '+entry['path'])
    frozen_observations.append({'path':entry['path'],'sha256':actual,'unchanged':True})
if hashlib.sha256((ROOT/'docs/dnssec-expansion/contract-freeze.json').read_bytes()).hexdigest()!=FREEZE_HASH:
    raise RuntimeError('Frozen manifest changed')

def lib_validate(sig,rr,key,now):
    dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)

def verify_objects(dataset,expected_hash,scratch):
    filename='publication-fixtures.json' if dataset is pub else RES_FILENAME
    v.check(filename+':pinned-hash',hashlib.sha256((OUT/filename).read_bytes()).hexdigest(),expected_hash)
    observations=[]
    for identity,key in dataset.get('keys',{}).items():
        v.check(identity+':key-wire',v.rdata('DNSKEY',key['text']).hex(),key['dnskeyRdataHex'])
        v.check(identity+':keytag',v.key_tag(v.rdata('DNSKEY',key['text'])),key['keyTag'])
        v.check(identity+':fixture-private-only',key['generation']['privateIsNetworkRecord'],False)
        v.check(identity+':attributed-operator',bool(key.get('privateHolderLabel')),True)
    for identity,rr in dataset['rrsets'].items():
        v.check(identity+':canonical-rdata',sorted(v.rdata(rr['type'],r).hex() for r in rr['records']),rr['canonicalRdataHex'])
    for identity,sig in dataset['signatures'].items():
        rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]; data=v.canonical(rr,sig)
        v.check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':input-sha256',hashlib.sha256(data).hexdigest(),sig['signingInputSha256'])
        v.check(identity+':rrsig-rdata-sha256',hashlib.sha256(bytes.fromhex(sig['rrsigRdataHex'])).hexdigest(),sig['rrsigRdataSha256'])
        prefix=18+len(v.name_wire(sig['signer']))
        v.check(identity+':canonical-rrset',data[prefix:].hex(),sig['canonicalRrsetHex'])
        v.check(identity+':cryptographic-valid',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        cli=v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,scratch)
        now=max(T,sig['inception']); lib_validate(sig,rr,key,now)
        additional_times=[]
        if sig['expiration']==LONG:
            future=T+90*86400; lib_validate(sig,rr,key,future)
            v.check(identity+':day90-window',v.time_state(future,sig['inception'],sig['expiration']),'valid')
            additional_times.append(future)
        observations.append({'id':identity,'rrsetId':rr['id'],'keyId':key['id'],'keyTag':sig['keyTag'],'signer':sig['signer'],'typeCovered':sig['typeCovered'],'algorithm':sig['algorithm'],'labels':sig['labels'],'originalTtl':sig['originalTtl'],'inception':sig['inception'],'expiration':sig['expiration'],'rrsigRdataHex':sig['rrsigRdataHex'],'rrsigRdataSha256':sig['rrsigRdataSha256'],'signingInputSha256':sig['signingInputSha256'],'canonicalRrsetHex':sig['canonicalRrsetHex'],'cryptographicValid':True,'libraryValidAt':now,'additionalLibraryValidAt':additional_times,'openssl':cli})
    return observations

pub_start=len(v.RESULTS)
with tempfile.TemporaryDirectory(prefix='openssl-',dir=OUT) as directory:
    pub_observations=verify_objects(pub,PUB_HASH,pathlib.Path(directory))
# Required exact membership and metadata tuples, independently declared from audit requirements.
requirements=[
 ('child-dnskey-collision',['child-ksk-g1','collision-a','collision-b'],'child-dnskey-collision-by-ksk','child-ksk-g1',22775,I,X),
 ('child-dnskey-a-b-g0',['child-ksk-g1','child-ksk-g2','child-zsk-g1'],'child-dnskey-a-b-g0-by-ksk','child-ksk-g1',22775,I,X),
 ('revoked-dnskey-a-b-z0',['child-ksk-g1-revoked','child-ksk-g2','child-zsk-g1'],'revoked-dnskey-a-b-z0-self-signature','child-ksk-g1-revoked',22903,1792972200,1796169600),
 ('provider-dnskey-shared-k0-z0-zb',['child-ksk-g1','child-zsk-g1','provider-b-zsk-g1'],'provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long','child-ksk-g1',22775,I,LONG),
 ('provider-dnskey-shared-k0-z0-zb',['child-ksk-g1','child-zsk-g1','provider-b-zsk-g1'],'provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-1h','child-ksk-g1',22775,I,X),
 ('provider-dnskey-model2-b-kb-z0-zb',['provider-b-ksk-g1','child-zsk-g1','provider-b-zsk-g1'],'provider-dnskey-model2-b-kb-z0-zb-by-provider-b-ksk-g1-long','provider-b-ksk-g1',10155,I,LONG)]
for rrid,members,sigid,keyid,tag,inception,expiration in requirements:
    rr=rrsets[rrid]; sig=sigs[sigid]
    v.check(sigid+':exact-requested-membership',sorted(rr['records']),sorted(keys[k]['text'] for k in members))
    actual={k:sig[k] for k in ['rrsetId','keyId','keyTag','signer','typeCovered','originalTtl','inception','expiration']}
    v.check(sigid+':exact-requested-tuple',actual,{'rrsetId':rrid,'keyId':keyid,'keyTag':tag,'signer':'lab.example.','typeCovered':48,'originalTtl':3600,'inception':inception,'expiration':expiration})
for identity,algorithm,digest_type in [('parent-ds-unsupported-alg17',17,2),('parent-ds-archival-alg5',5,2),('parent-ds-obsolete-alg5',5,2),('parent-ds-obsolete-alg12-digest3',12,3)]:
    p=pub['opaqueDsPayloadProvenance'][identity]; rr=rrsets[identity]; sig=sigs[identity+'-signature']
    expected=hashlib.sha256(p['label'].encode('ascii')).hexdigest()
    v.check(identity+':opaque-label-digest',p['payloadHex'],expected)
    v.check(identity+':opaque-record',rr['records'],['22775 '+str(algorithm)+' '+str(digest_type)+' '+expected])
    v.check(identity+':not-key-derived',p['notDnskeyDerivedDigest'],True)
    v.check(identity+':selected-policy-only',p['selectedPolicyOnly'],algorithm in [5,12])
    v.check(identity+':parent-signature-tuple',[sig[k] for k in ['keyId','keyTag','signer','typeCovered','inception','expiration','originalTtl']],['example-zsk-g1',30008,'example.',43,I,X,3600])
for identity,d in pub['ds'].items():
    key=keys[d['keyId']]; data=v.name_wire(key['owner'])+v.rdata('DNSKEY',key['text'])
    v.check(identity+':independent-real-ds',hashlib.sha256(data).hexdigest(),d['digestHex'])
    v.check(identity+':real-ds-input',data.hex(),d['digestInputHex'])
# Independent trust progression: every DS key promotion follows an authenticated parent RRset.
chain_observations=[]
for suffix,chain in pub['signalingChains'].items():
    trusted={chain['anchorKeyId']}; observed=[]
    v.check(suffix+':out-of-child-domain',dns.name.from_text(chain['nameserver']).is_subdomain(dns.name.from_text('lab.example.')),False)
    for index,step in enumerate(chain['chain']+chain['claimSteps']):
        sig=sigs[step['signatureId']]; rr=rrsets[step['rrsetId']]; key=keys[sig['keyId']]
        prefix=suffix+':'+str(index)
        v.check(prefix+':signer-authenticated',sig['keyId'] in trusted,True)
        v.check(prefix+':no-child-initial-trust',sig['keyId'].startswith('child-'),False)
        v.check(prefix+':canonical',v.canonical(rr,sig).hex(),sig['signingInputHex'])
        v.check(prefix+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),v.canonical(rr,sig)),True)
        lib_validate(sig,rr,key,T)
        if step['role']=='dnskey':
            records={v.rdata('DNSKEY',r) for r in rr['records']}
            trusted.update(k for k,candidate in keys.items() if candidate['owner']==rr['owner'] and v.rdata('DNSKEY',candidate['text']) in records)
        elif step['role']=='ds':
            records={v.rdata('DS',r) for r in rr['records']}
            for keyid in step['matchedChildKeyIds']:
                candidate=keys[keyid]; digest=hashlib.sha256(v.name_wire(candidate['owner'])+v.rdata('DNSKEY',candidate['text'])).hexdigest()
                ds=v.rdata('DS',str(candidate['keyTag'])+' '+str(candidate['algorithm'])+' 2 '+digest)
                v.check(prefix+':ds-owner',rr['owner'],candidate['owner'])
                v.check(prefix+':ds-key-match',ds in records,True); trusted.add(keyid)
        elif step['role']=='signaling-claim':
            apex=rrsets[step['copiedApexRrsetId']]
            v.check(prefix+':identical-copied-type',rr['type'],apex['type'])
            v.check(prefix+':identical-copied-payload',rr['canonicalRdataHex'],apex['canonicalRdataHex'])
            v.check(prefix+':exact-signaling-owner',rr['owner'],chain['signalingName'])
            v.check(prefix+':signaling-zone-signer',sig['signer'],chain['signalingZone'])
        else:
            raise ValueError('Unknown RFC9615 reference step')
        observed.append({'role':step['role'],'rrsetId':rr['id'],'signatureId':sig['id'],'signer':sig['signer'],'keyId':sig['keyId'],'keyTag':sig['keyTag'],'inception':sig['inception'],'expiration':sig['expiration'],'originalTtl':sig['originalTtl'],'verifiedAt':T})
    v.check(suffix+':child-key-never-used-as-chain-anchor','child-ksk-g1' in trusted,False)
    chain_observations.append({'branch':suffix,'signalingName':chain['signalingName'],'signalingZone':chain['signalingZone'],'valid':True,'childApexSignatureUsedAsInitialTrust':False,'steps':observed})
# CDS copies retain digest over the CHILD owner, not the signaling owner.
child=keys['child-ksk-g1']; child_digest=hashlib.sha256(v.name_wire('lab.example.')+v.rdata('DNSKEY',child['text'])).hexdigest()
v.check('copied-cds-child-owner-digest',rrsets['postfreeze-child-cds-claim']['records'][0].split()[-1].lower(),child_digest)
v.check('copied-cdnskey-child-key',rrsets['postfreeze-child-cdnskey-claim']['canonicalRdataHex'],[child['dnskeyRdataHex']])
# Authenticate the explicit no-DS prerequisite in its separate unsigned-child profile.
frozen_resolution=json.loads((v.OUT/'resolution-profile-fixtures.json').read_text())
bootstrap_nsec=frozen_resolution['rrsets']['denial-parent-unsigned-lab']
bootstrap_sig=frozen_resolution['signatures']['denial-parent-unsigned-lab-signature']
bootstrap_trusted={'root-ksk-g1'}; bootstrap_parent_observations=[]
for sig in [sigs['root-dnskey-g1-by-ksk'],sigs['root-example-ds-signature'],sigs['example-dnskey-g1-by-ksk'],bootstrap_sig]:
    rr=bootstrap_nsec if sig['id']==bootstrap_sig['id'] else rrsets[sig['rrsetId']]
    key=keys[sig['keyId']]
    v.check(sig['id']+':bootstrap-parent-authenticated-signer',sig['keyId'] in bootstrap_trusted,True)
    v.check(sig['id']+':bootstrap-parent-crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),v.canonical(rr,sig)),True)
    lib_validate(sig,rr,key,T)
    if rr['type']=='DNSKEY':
        records={v.rdata('DNSKEY',r) for r in rr['records']}
        bootstrap_trusted.update(k for k,candidate in keys.items() if candidate['owner']==rr['owner'] and v.rdata('DNSKEY',candidate['text']) in records)
    elif rr['type']=='DS':
        candidate=keys['example-ksk-g1']; digest=hashlib.sha256(v.name_wire(candidate['owner'])+v.rdata('DNSKEY',candidate['text'])).hexdigest()
        v.check('bootstrap-parent-ds-key-match',rr['records'][0].split()[-1].lower(),digest)
        bootstrap_trusted.add('example-ksk-g1')
    bootstrap_parent_observations.append({'signatureId':sig['id'],'rrsetId':rr['id'],'signer':sig['signer'],'keyId':sig['keyId'],'verifiedAt':T})
v.check('bootstrap-nsec-delegation-owner',bootstrap_nsec['owner'],'lab.example.')
v.check('bootstrap-nsec-ns-present-ds-soa-absent',bytes.fromhex(bootstrap_nsec['canonicalRdataHex'][0]),v.name_wire('next.example.')+v.bitmap(['NS','RRSIG','NSEC']))
for target in rrsets['postfreeze-parent-delegation-outside-ns']['records']:
    v.check('bootstrap-nameserver-out-of-child:'+target,dns.name.from_text(target).is_subdomain(dns.name.from_text('lab.example.')),False)
pub_results=list(v.RESULTS[pub_start:])
pub_report={'schemaVersion':1,'kind':'dnssec-publication-post-freeze-audit-verification','fixturePath':reference_path(output_root() / 'post-freeze-contract-errata/publication-fixtures.json'),'fixtureSha256':PUB_HASH,'result':'pass','checks':len(pub_results),'results':pub_results,'signatureObservations':pub_observations,'signalingChainObservations':chain_observations,'opaqueDsPayloadProvenance':pub['opaqueDsPayloadProvenance'],'freezeAuthoritySha256':FREEZE_HASH,'frozenNumericAndVerificationFilesUnchanged':True,'frozenArtifacts':frozen_observations,'scope':'Actual numeric signatures and two independently secure synthetic out-of-domain chains. No child-apex signature used for initial trust. Opaque alg5/12/17 DS extras are not full DNSKEY-derived legacy/unsupported paths. No network/RFC9615 live interoperability or application acceptance claim.'}
pub_report['bootstrapParentNoDsObservations']=bootstrap_parent_observations
pub_report['bootstrapParentNoDsScope']='Authenticated no-DS delegation prerequisite in the explicitly separate unsigned-child variant; no child-apex initial trust or public-baseline mutation.'
res_start=len(v.RESULTS)
failed_candidate_raw=(OUT/'resolution-fixtures.json').read_bytes()
v.check('retained-failed-candidate-hash',hashlib.sha256(failed_candidate_raw).hexdigest(),generated_hash('post-freeze-contract-errata/resolution-fixtures.json'))
failed_candidate=json.loads(failed_candidate_raw)
v.check('owner-literal-correction-preserves-every-rrset',res['rrsets'],failed_candidate['rrsets'])
v.check('owner-literal-correction-preserves-every-signature',res['signatures'],failed_candidate['signatures'])
v.check('owner-literal-correction-preserves-target-variant',res['unsignedTargetBinding'],failed_candidate['unsignedTargetBinding'])
with tempfile.TemporaryDirectory(prefix='openssl-',dir=OUT) as directory:
    res_observations=verify_objects(res,RES_HASH,pathlib.Path(directory))
zz=rrsets['zz-a']; zzsig=sigs['zz-a-signature']; zzkey=keys['child-zsk-g1']; binding=res['zzBinding']
v.check('zz-exact-key-wire',zzkey['dnskeyRdataHex'],binding['keyDnskeyRdataHex'])
v.check('zz-owner-wire',v.name_wire(zz['owner']).hex(),'027a7a036c6162076578616d706c6500')
v.check('zz-owner-preserved',zz['owner'],'zz.lab.example.')
v.check('zz-records-preserved',zz['records'],['192.0.2.80','192.0.2.81'])
v.check('zz-canonical-rdata',zz['canonicalRdataHex'],['c0000250','c0000251'])
v.check('zz-exact-key-metadata',[zzkey[k] for k in ['owner','flags','protocol','algorithm','keyTag']],['lab.example.',256,3,13,55402])
v.check('zz-exact-rrsig-metadata',[zzsig[k] for k in ['keyId','signer','keyTag','typeCovered','algorithm','labels','originalTtl','inception','expiration']],['child-zsk-g1','lab.example.',55402,1,13,3,3600,I,X])
v.check('zz-received-ttls',[zz['receivedRrsetTtl'],zzsig['receivedRrsigTtl']],[300,300])
v.check('zz-received-ttl-does-not-mutate-input',v.canonical({**zz,'ttl':300},zzsig).hex(),zzsig['signingInputHex'])
other=rrsets['other-www-a-unsigned-no-ds']; nsec=rrsets['other-parent-no-ds-nsec']; nsig=sigs['other-parent-no-ds-nsec-signature']
v.check('unsigned-other-address',other['records'],['192.0.2.80'])
v.check('unsigned-other-no-rrsig',any(sig['rrsetId']==other['id'] for sig in res['signatures'].values()),False)
v.check('unsigned-other-received-ttl',other['receivedRrsetTtl'],300)
v.check('nsec-next-final',nsec['records'][0].split()[0],'zzz.example.')
v.check('nsec-owner-wire',v.name_wire(nsec['owner']).hex(),'056f74686572076578616d706c6500')
v.check('nsec-next-wire',v.name_wire('zzz.example.').hex(),'037a7a7a076578616d706c6500')
v.check('nsec-exact-rdata',bytes.fromhex(nsec['canonicalRdataHex'][0]),v.name_wire('zzz.example.')+v.bitmap(['NS','RRSIG','NSEC']))
v.check('nsec-parent-exact-signature',[nsig[k] for k in ['keyId','keyTag','signer','algorithm','originalTtl','inception','expiration']],['example-zsk-g1',30008,'example.',13,300,I,X])
v.check('nsec-received-ttls',[nsec['receivedRrsetTtl'],nsig['receivedRrsigTtl']],[300,300])
# Authenticate the parent NSEC through the existing synthetic root/example path.
trusted={'root-ksk-g1'}; parent_path=[]
for identity in ['root-dnskey-g1-by-ksk','root-example-ds-signature','example-dnskey-g1-by-ksk','other-parent-no-ds-nsec-signature']:
    sig=sigs[identity]; rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
    v.check(identity+':parent-chain-trusted-signer',sig['keyId'] in trusted,True)
    v.check(identity+':parent-chain-crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),v.canonical(rr,sig)),True); lib_validate(sig,rr,key,T)
    if rr['type']=='DNSKEY':
        records={v.rdata('DNSKEY',r) for r in rr['records']}
        trusted.update(k for k,candidate in keys.items() if candidate['owner']==rr['owner'] and v.rdata('DNSKEY',candidate['text']) in records)
    elif rr['type']=='DS':
        candidate=keys['example-ksk-g1']; digest=hashlib.sha256(v.name_wire(candidate['owner'])+v.rdata('DNSKEY',candidate['text'])).hexdigest()
        v.check('parent-chain-ds-key-match',rr['records'][0].split()[-1].lower(),digest); trusted.add('example-ksk-g1')
    parent_path.append({'signatureId':identity,'rrsetId':rr['id'],'signer':sig['signer'],'keyId':sig['keyId'],'validAt':T})
res_results=list(v.RESULTS[res_start:])
res_report={'schemaVersion':1,'kind':'dnssec-resolution-post-freeze-audit-verification','fixturePath':reference_path(OUT/RES_FILENAME),'fixtureBytes':(OUT/RES_FILENAME).stat().st_size,'fixtureSha256':RES_HASH,'result':'pass','checks':len(res_results),'results':res_results,'signatureObservations':res_observations,
 'zzPublicFields':{'rrset':zz,'signature':zzsig,'key':{field:zzkey[field] for field in ['id','owner','flags','protocol','algorithm','keyTag','publicKeyHex','dnskeyRdataHex']},'canonicalOwnerWireHex':v.name_wire(zz['owner']).hex(),'canonicalSigningInputHex':v.canonical(zz,zzsig).hex(),'verificationAgainstExactRequestedKey':True},
 'unsignedTargetFields':{'rrset':other,'parentNsec':nsec,'signature':nsig,'canonicalNsecRdataHex':nsec['canonicalRdataHex'][0],'parentPath':parent_path,'nsecNextFinal':'zzz.example.','nsPresent':True,'dsAbsent':True,'soaAbsent':True,'sourceSections':['RFC4035 3.1.4','RFC4035 5.2','RFC6840 4.4'],'scope':'Authenticated parent DS absence/delegation proof only, not authentication of the unsigned target A.'},
 'freezeAuthoritySha256':FREEZE_HASH,'frozenNumericAndVerificationFilesUnchanged':True,'frozenManifestUnchanged':True,'frozenArtifacts':frozen_observations,'newUnsignedTargetVariantNotFrozenMutation':True,'scope':'New exact zz question/bytes and separate unsigned-target variant; no frozen object or manifest changed, no production source/evaluator/build/test/formatter consulted.'}
res_report['ownerWireCorrection']=res['ownerWireCorrection']
res_report['unsignedTargetFields']['nsecOwnerWireHex']=v.name_wire(nsec['owner']).hex()
res_report['unsignedTargetFields']['nsecOwnerWireBytes']=len(v.name_wire(nsec['owner']))
res_report['unsignedTargetFields']['nsecNextWireHex']=v.name_wire('zzz.example.').hex()
res_report['unsignedTargetFields']['nsecNextWireBytes']=len(v.name_wire('zzz.example.'))
res_report['unsignedTargetFields']['nsecRdataBytes']=len(bytes.fromhex(nsec['canonicalRdataHex'][0]))
outputs=[]
for filename,report in [('publication-verification.json',pub_report),('resolution-verification.json',res_report)]:
    raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); path=OUT/filename
    if path.exists() and path.read_bytes()!=raw:
        raise RuntimeError('Existing additive report differs: '+filename)
    if not path.exists():
        path.write_bytes(raw)
    outputs.append({'path':reference_path(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'checks':report['checks']})
for entry in frozen_observations:
    if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:
        raise RuntimeError('Frozen owned file changed during verifier: '+entry['path'])
if hashlib.sha256((ROOT/'docs/dnssec-expansion/contract-freeze.json').read_bytes()).hexdigest()!=FREEZE_HASH:
    raise RuntimeError('Frozen manifest changed during verifier')
print(json.dumps({'outputs':outputs,'frozenOwnedArtifactsChecked':len(frozen_observations),'frozenArtifactsAndManifestUnchanged':True,'newSignatureOpenSslObservations':len(pub_observations)+len(res_observations)},indent=2))
