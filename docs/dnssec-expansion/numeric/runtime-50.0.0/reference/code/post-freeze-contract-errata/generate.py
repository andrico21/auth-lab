
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[1]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Post-freeze audit inputs only. Never overwrite a frozen file or import production code."""
import copy
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import generate as g
import dns.name
ROOT=g.ROOT
OUT=g.OUT/'post-freeze-contract-errata'
OUT.mkdir(parents=True,exist_ok=True)
FREEZE=ROOT/'docs/dnssec-expansion/contract-freeze.json'
FREEZE_HASH='b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
if hashlib.sha256(FREEZE.read_bytes()).hexdigest()!=FREEZE_HASH:
    raise RuntimeError('Freeze authority differs; do not substitute another baseline')
authority=json.loads(FREEZE.read_text())
owned_prefixes=['docs/dnssec-expansion/numeric/','tools/verification/dnssec-crypto/']
frozen_owned=[]
for entry in authority['inputs']:
    if any(entry['path'].startswith(prefix) for prefix in owned_prefixes):
        path=ROOT/entry['path']; actual=hashlib.sha256(path.read_bytes()).hexdigest()
        if actual!=entry['sha256']:
            raise RuntimeError('Frozen owned file already differs: '+entry['path'])
        frozen_owned.append({'path':entry['path'],'sha256':actual,'bytes':path.stat().st_size})
base=copy.deepcopy(g.FIXTURES)
T=g.CLOCK; I=1792713000; X=1792717200; LONG=1803081600
assert T==1792713600

def make(identity,keyids,signers,window=(I,X)):
    g.rrset(identity,'lab.example.','DNSKEY',[g.DNSKEY[keyid].to_text() for keyid in keyids],3600)
    for sigid,keyid in signers:
        g.sign(sigid,identity,keyid,*window)

make('child-dnskey-collision',['child-ksk-g1','collision-a','collision-b'],[('child-dnskey-collision-by-ksk','child-ksk-g1')])
make('child-dnskey-a-b-g0',['child-ksk-g1','child-ksk-g2','child-zsk-g1'],[('child-dnskey-a-b-g0-by-ksk','child-ksk-g1')])
make('revoked-dnskey-a-b-z0',['child-ksk-g1-revoked','child-ksk-g2','child-zsk-g1'],[('revoked-dnskey-a-b-z0-self-signature','child-ksk-g1-revoked')],(1792972200,1796169600))
make('provider-dnskey-shared-k0-z0-zb',['child-ksk-g1','child-zsk-g1','provider-b-zsk-g1'],[('provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long','child-ksk-g1')],(I,LONG))
g.sign('provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-1h','provider-dnskey-shared-k0-z0-zb','child-ksk-g1',I,X)
make('provider-dnskey-model2-b-kb-z0-zb',['provider-b-ksk-g1','child-zsk-g1','provider-b-zsk-g1'],[('provider-dnskey-model2-b-kb-z0-zb-by-provider-b-ksk-g1-long','provider-b-ksk-g1')],(I,LONG))
opaque={}
for identity,algorithm,digest_type in [('parent-ds-unsupported-alg17',17,2),('parent-ds-archival-alg5',5,2),('parent-ds-obsolete-alg5',5,2),('parent-ds-obsolete-alg12-digest3',12,3)]:
    label='DNSSEC post-freeze opaque DS envelope:'+identity
    payload=hashlib.sha256(label.encode('ascii')).hexdigest()
    assert payload!='00'*32
    g.rrset(identity,'lab.example.','DS',['22775 '+str(algorithm)+' '+str(digest_type)+' '+payload],3600)
    g.sign(identity+'-signature',identity,'example-zsk-g1',I,X)
    opaque[identity]={'label':label,'producer':'Python hashlib.sha256(ASCII label)','payloadHex':payload,'opaqueSyntheticPayload':True,'dnskeyDerivedDigest':False,'notDnskeyDerivedDigest':True,'selectedPolicyOnly':algorithm in [5,12],'matchingLegacyDnskeyOrSignatureProvided':False,
      'scope':'Actual parent signature over a deliberately opaque unsupported/archival DS envelope. Not proof of an alg5/12/17 DNSKEY path or legacy signature acceptance.'}
# Exact singleton child claim copied to both independently secure signaling names.
g.rrset('postfreeze-child-cds-claim','lab.example.','CDS',[base['ds']['child-ksk-g1-sha256']['text']])
g.rrset('postfreeze-child-cdnskey-claim','lab.example.','CDNSKEY',[g.DNSKEY['child-ksk-g1'].to_text()])
for typ in ['cds','cdnskey']:
    g.sign('postfreeze-child-'+typ+'-claim-signature','postfreeze-child-'+typ+'-claim','child-ksk-g1',I,X)
g.rrset('postfreeze-parent-delegation-outside-ns','lab.example.','NS',['ns1.provider.example.net.','ns2.provider.example.org.'])
chains={}
for suffix,ns in [('net','ns1'),('org','ns2')]:
    zones=[(suffix+'.','signal-'+suffix),('example.'+suffix+'.','signal-example-'+suffix),('provider.example.'+suffix+'.','signal-provider-'+suffix)]
    path=[{'role':'dnskey','signatureId':'root-dnskey-g1-by-ksk','rrsetId':'root-dnskey-g1','referencedFrozen':True}]
    parent_prefix='root'; parent_owner='.'
    for owner,prefix in zones:
        for role,flags in [('ksk',257),('zsk',256)]:
            keyid=prefix+'-'+role+'-g1'; g.key(keyid,owner,flags)
            g.FIXTURES['keys'][keyid]['privateHolderLabel']='fixture-only operator '+owner+' signer '+role
            g.FIXTURES['keys'][keyid]['generation']['privateCustodian']='synthetic-signaling-operator-'+suffix
            g.FIXTURES['keys'][keyid]['generation']['privateIsNetworkRecord']=False
        ksk=prefix+'-ksk-g1'; zsk=prefix+'-zsk-g1'
        g.ds(ksk+'-sha256',ksk)
        dsid=prefix+'-parent-ds'; g.rrset(dsid,owner,'DS',[g.FIXTURES['ds'][ksk+'-sha256']['text']])
        g.sign(dsid+'-signature',dsid,parent_prefix+'-zsk-g1',I,X)
        rrid=prefix+'-dnskey'; g.rrset(rrid,owner,'DNSKEY',[g.DNSKEY[ksk].to_text(),g.DNSKEY[zsk].to_text()])
        g.sign(rrid+'-signature',rrid,ksk,I,X)
        path += [{'role':'ds','signatureId':dsid+'-signature','rrsetId':dsid,'matchedChildKeyIds':[ksk],'parentZone':parent_owner},{'role':'dnskey','signatureId':rrid+'-signature','rrsetId':rrid}]
        parent_prefix=prefix; parent_owner=owner
    claim_name='_dsboot.lab.example._signal.'+ns+'.provider.example.'+suffix+'.'
    signal_steps=[]
    for typ in ['CDS','CDNSKEY']:
        identity='signal-'+suffix+'-'+typ.lower()+'-child-claim'
        records=[base['ds']['child-ksk-g1-sha256']['text']] if typ=='CDS' else [g.DNSKEY['child-ksk-g1'].to_text()]
        g.rrset(identity,claim_name,typ,records)
        g.sign(identity+'-signature',identity,parent_prefix+'-zsk-g1',I,X)
        signal_steps.append({'role':'signaling-claim','signatureId':identity+'-signature','rrsetId':identity,'copiedApexRrsetId':'postfreeze-child-'+typ.lower()+'-claim'})
    chains[suffix]={'anchorKeyId':'root-ksk-g1','nameserver':ns+'.provider.example.'+suffix+'.','signalingName':claim_name,'signalingZone':zones[-1][0],'chain':path,'claimSteps':signal_steps,
      'initialTrustUsesChildApexSignature':False,'fixtureOnly':True,'source':'RFC9615 sections3.1,3.2,4.1,4.2','verificationAt':T}
# Resolution audit: enforce the exact requested key identity and signed bytes.
expected_z='0100030ddc6ca279402fe21dae3f0b7afb4a3da02f1f9b7f234ea40ab73a3026f5f100038d27270465e542d1073befde0449935a112ef159f45d2177ba339e2d87d1ed07'
if base['keys']['child-zsk-g1']['dnskeyRdataHex']!=expected_z or base['keys']['child-zsk-g1']['keyTag']!=55402:
    raise RuntimeError('Requested exact zz key identity differs; no substitution allowed')
g.rrset('zz-a','zz.lab.example.','A',['192.0.2.80','192.0.2.81'],3600)
g.sign('zz-a-signature','zz-a','child-zsk-g1',I,X)
g.FIXTURES['rrsets']['zz-a']['receivedRrsetTtl']=300; g.FIXTURES['signatures']['zz-a-signature']['receivedRrsigTtl']=300
g.rrset('other-www-a-unsigned-no-ds','www.other.example.','A',['192.0.2.80'],3600)
g.FIXTURES['rrsets']['other-www-a-unsigned-no-ds'].update(receivedRrsetTtl=300,signatureRefs=[],unsignedVariant=True)
g.rrset('other-parent-no-ds-nsec','other.example.','NSEC',['zzz.example. NS RRSIG NSEC'],300)
g.sign('other-parent-no-ds-nsec-signature','other-parent-no-ds-nsec','example-zsk-g1',I,X)
g.FIXTURES['rrsets']['other-parent-no-ds-nsec']['receivedRrsetTtl']=300; g.FIXTURES['signatures']['other-parent-no-ds-nsec-signature']['receivedRrsigTtl']=300
g.rrset('other-parent-no-ds-ns','other.example.','NS',['ns1.other.example.'],300)
# Hash the actual produced RRSIG bytes and expose the canonical covered RRset portion.
new_signatures={k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']}
for signature in new_signatures.values():
    signature['rrsigRdataSha256']=hashlib.sha256(bytes.fromhex(signature['rrsigRdataHex'])).hexdigest()
    prefix_size=18+len(dns.name.from_text(signature['signer']).to_digestable())
    signature['canonicalRrsetHex']=bytes.fromhex(signature['signingInputHex'])[prefix_size:].hex()
new_rrsets={k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']}
resolution_ids=['zz-a','other-www-a-unsigned-no-ds','other-parent-no-ds-nsec','other-parent-no-ds-ns']
resolution_sig_ids=['zz-a-signature','other-parent-no-ds-nsec-signature']
common={'schemaVersion':1,'independentOfProduction':True,'postFreeze':True,'freezeAuthoritySha256':FREEZE_HASH,'baseClock':T,'baselineFixtureSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest()}
pub={**common,'kind':'dnssec-publication-post-freeze-audit-fixtures','keys':{k:v for k,v in g.FIXTURES['keys'].items() if k not in base['keys']},'rrsets':{k:v for k,v in new_rrsets.items() if k not in resolution_ids},'signatures':{k:v for k,v in new_signatures.items() if k not in resolution_sig_ids},'ds':{k:v for k,v in g.FIXTURES['ds'].items() if k not in base['ds']},'opaqueDsPayloadProvenance':opaque,'signalingChains':chains,
 'bootstrapSetup':{'child':'lab.example.','parentSideNsRrsetId':'postfreeze-parent-delegation-outside-ns','selectedParentNoDsRrsetId':'denial-parent-unsigned-lab','selectedParentNoDsSignatureId':'denial-parent-unsigned-lab-signature','selectedParentNoDsSource':'resolution-profile-fixtures.json','childClaimKeyId':'child-ksk-g1','childApexSignaturesAreInitialTrust':False,'copiedRrsetsAreIdenticalByType':True,'networkQueriesExecuted':False},
 'scope':'Actual numeric bytes under synthetic independent out-of-domain chains, not live RFC9615 interoperability or publication authorization. Deliberately opaque DS envelopes do not prove legacy/unsupported DNSKEY path validity.'}
resolution={**common,'kind':'dnssec-resolution-post-freeze-audit-fixtures','rrsets':{k:new_rrsets[k] for k in resolution_ids},'signatures':{k:new_signatures[k] for k in resolution_sig_ids},
 'zzBinding':{'query':'zz.lab.example.','rrsetId':'zz-a','signatureId':'zz-a-signature','keyId':'child-zsk-g1','keyTag':55402,'keyDnskeyRdataHex':expected_z,'canonicalOwnerWireHex':'037a7a036c6162076578616d706c6500','canonicalRdataHex':['c0000250','c0000251'],'signedOriginalTtl':3600,'receivedRrsetTtl':300,'receivedRrsigTtl':300,'purpose':'DNS10 out-of-proof-range; preserve exact zz question'},
 'unsignedTargetBinding':{'query':'www.other.example.','unsignedRrsetId':'other-www-a-unsigned-no-ds','nsecRrsetId':'other-parent-no-ds-nsec','nsecSignatureId':'other-parent-no-ds-nsec-signature','nsecOwner':'other.example.','nsecNext':'zzz.example.','nsecBitmap':['NS','RRSIG','NSEC'],'nsPresent':True,'dsPresent':False,'soaPresent':False,'keyId':'example-zsk-g1','signer':'example.','keyTag':30008,'signedOriginalTtl':300,'receivedRrsetTtl':300,'receivedRrsigTtl':300,'source':'RFC4035 sections3.1.4 and5.2; RFC6840 section4.4','newUnsignedTargetVariant':True,'existingSignedOtherWwwObjectMutated':False},
 'scope':'Two explicit resolution audit variants. Unsigned other target does not inherit authentication from parent noDS proof, and existing signed target/profile objects remain unchanged.'}
pub['rootTrustMaterial']={'frozenSource':reference_path(output_root() / 'dnssec-numeric-fixtures.json'),'sourceSha256':common['baselineFixtureSha256'],
 'anchorKey':{field:base['keys']['root-ksk-g1'][field] for field in ['id','owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex','keyTag']},
 'dnskeyRrset':base['rrsets']['root-dnskey-g1'],'dnskeySignature':base['signatures']['root-dnskey-g1-by-ksk']}
outputs=[]
for filename,value in [('publication-fixtures.json',pub),('resolution-fixtures.json',resolution)]:
    raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode(); path=OUT/filename
    if path.exists() and path.read_bytes()!=raw:
        raise RuntimeError('Existing additive fixture differs: '+filename)
    if not path.exists():
        path.write_bytes(raw)
    outputs.append({'path':reference_path(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'keys':len(value.get('keys',{})),'rrsets':len(value['rrsets']),'signatures':len(value['signatures'])})
# These source captures were already frozen; reuse them rather than refetching or rewriting.
source_paths=['docs/dnssec-expansion/sources/publication/rfc9615.raw','docs/dnssec-expansion/sources/publication/rfc9615.txt','docs/dnssec-expansion/sources/publication/capture-metadata.json','docs/dnssec-expansion/numeric/sources/rfc4035.txt','docs/dnssec-expansion/numeric/sources/rfc6840.txt']
provenance={'schemaVersion':1,'kind':'dnssec-post-freeze-generation-provenance','freezeAuthoritySha256':FREEZE_HASH,'outputs':outputs,'python':platform.python_version(),'dependencies':{name:importlib.metadata.version(name) for name in ['dnspython','cryptography','cffi','pycparser']},'producer':reference_path(CURRENT_TOOLS / 'post-freeze-contract-errata/generate.py'),'command':[_current_sys.executable,'-B',str(pathlib.Path(__file__).resolve())],'referenceSigningProducer':'Maintained current verification-only generate.py + dnspython2.8.0/cryptography50 deterministic sign; no production imports','sourceReferences':[{'path':name,'sha256':hashlib.sha256((ROOT/name).read_bytes()).hexdigest()} for name in source_paths],'frozenOwnedArtifactsBefore':frozen_owned,'frozenOwnedArtifactsAfterGenerationUnchanged':True,'dependencyEnvironment':'Inherited exact current replay interpreter; strict runtime profile checked before generation','newKeyScope':'12 deterministic fixture-only net/org/example/provider KSK/ZSK keys; attributed synthetic out-of-domain operators, no production secrets. Existing root and child keys reused byte-for-byte.'}
for entry in frozen_owned:
    if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:
        raise RuntimeError('Frozen owned file changed during producer: '+entry['path'])
raw=(json.dumps(provenance,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'generation-provenance.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Existing generation provenance differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'outputs':outputs,'provenanceSha256':hashlib.sha256(raw).hexdigest(),'frozenOwnedArtifactsChecked':len(frozen_owned),'freezeUnchanged':hashlib.sha256(FREEZE.read_bytes()).hexdigest()==FREEZE_HASH},indent=2))
