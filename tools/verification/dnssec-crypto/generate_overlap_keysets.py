#!/usr/bin/env python3
"""Only the exact already-authored intermediate membership sets requested by the oracle."""
import hashlib
import json
import generate as g
DAY=86400
sets=[
 ('child-dnskey-zsk-overlap3',['child-ksk-g1','child-zsk-g1','child-zsk-g2'],['child-ksk-g1']),
 ('child-dnskey-ksk-overlap3',['child-ksk-g1','child-ksk-g2','child-zsk-g1'],['child-ksk-g1','child-ksk-g2']),
 ('child-dnskey-provider-model1-overlap4',['child-ksk-g1','child-zsk-g1','child-zsk-g2','provider-b-zsk-g1'],['child-ksk-g1']),
 ('child-dnskey-provider-model1-final3',['child-ksk-g1','child-zsk-g2','provider-b-zsk-g1'],['child-ksk-g1']),
 ('child-dnskey-csk-overlap2',['child-csk-g1','child-csk-g2'],['child-csk-g1','child-csk-g2'])]
rrsets={}; signatures={}; memberships={}
for rrid,keyids,signers in sets:
    g.rrset(rrid,'lab.example.','DNSKEY',[g.DNSKEY[keyid].to_text() for keyid in keyids]); rrsets[rrid]=g.FIXTURES['rrsets'][rrid]
    memberships[rrid]=keyids
    for keyid in signers:
        identity=rrid+'-by-'+keyid+'-long'
        g.sign(identity,rrid,keyid,g.CLOCK-600,g.CLOCK+120*DAY); signatures[identity]=g.FIXTURES['signatures'][identity]
upper=[{'role':'dnskey','signatureId':'root-dnskey-path-long'},{'role':'ds','signatureId':'root-example-ds-path-long','matchedChildKeyIds':['example-ksk-g1']},{'role':'dnskey','signatureId':'example-dnskey-path-long'}]
paths={}
for identity,rrid,signer,ds_signature,leaf_signature in [
 ('zsk-overlap','child-dnskey-zsk-overlap3','child-ksk-g1','example-child-ds-path-long','www-a-complete-path-g2'),
 ('ksk-overlap-old','child-dnskey-ksk-overlap3','child-ksk-g1','example-child-ds-path-long','www-a-complete-path-g1'),
 ('ksk-overlap-new','child-dnskey-ksk-overlap3','child-ksk-g2','example-child-ds-g2-long','www-a-complete-path-g1'),
 ('provider-model1-overlap','child-dnskey-provider-model1-overlap4','child-ksk-g1','example-child-ds-path-long','www-a-complete-path-provider-b'),
 ('provider-model1-final','child-dnskey-provider-model1-final3','child-ksk-g1','example-child-ds-path-long','www-a-complete-path-provider-b'),
 ('csk-overlap-old','child-dnskey-csk-overlap2','child-csk-g1','parent-ds-for-child-csk-g1-signature','www-a-complete-path-csk-g1'),
 ('csk-overlap-new','child-dnskey-csk-overlap2','child-csk-g2','parent-ds-for-child-csk-g2-signature','www-a-complete-path-csk-g2')]:
    paths[identity]={'id':identity,'anchorKeyId':'root-ksk-g1','exactChildKeyIds':memberships[rrid],'observedOffsets':[0,95100,35*DAY,90*DAY],
      'steps':upper+[{'role':'ds','signatureId':ds_signature,'matchedChildKeyIds':[signer]},{'role':'dnskey','signatureId':rrid+'-by-'+signer+'-long'},{'role':'answer','signatureId':leaf_signature}]}
files=['dnssec-numeric-fixtures.json','lifecycle-fixtures.json','profile-fixtures.json','long-profile-fixtures.json','complete-path-fixtures.json']
f={'schemaVersion':1,'kind':'dnssec-independent-authored-overlap-keysets','baseClock':g.CLOCK,'sourceFixtureSha256':{name:hashlib.sha256((g.OUT/name).read_bytes()).hexdigest() for name in files},'rrsets':rrsets,'signatures':signatures,'exactMemberships':memberships,'paths':paths,
 'scope':'Exact authored ZSK/KSK/CSK and coordinated Model1 provider keysets, not four-key baseline aliases. Different DS stages remain explicit profile paths. No new keys, algorithms, lessons or optional profiles.120day signatures are synthetic fixed-byte lifecycle choices, not normal operational advice.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=g.OUT/'overlap-keysets-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable overlap fixtures differ')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':len(rrsets),'signatures':len(signatures),'paths':len(paths)},indent=2))
