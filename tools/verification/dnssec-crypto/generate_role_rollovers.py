#!/usr/bin/env python3
"""Exact separate ZSK-only and KSK-only final keysets, without changing prior seals."""
import hashlib
import json
import generate as g
DAY=86400
roles=[('zsk-only-final',['child-ksk-g1','child-zsk-g2'],'child-ksk-g1','example-child-ds-path-long','www-a-complete-path-g2'),('ksk-only-final',['child-ksk-g2','child-zsk-g1'],'child-ksk-g2','example-child-ds-g2-long','www-a-complete-path-g1')]
rrsets={}; signatures={}; paths={}
for identity,keyids,signer,ds_signature,answer_signature in roles:
    rrid='child-dnskey-'+identity
    sigid=rrid+'-long-signature'
    g.rrset(rrid,'lab.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in keyids])
    g.sign(sigid,rrid,signer,g.CLOCK-600,g.CLOCK+120*DAY)
    rrsets[rrid]=g.FIXTURES['rrsets'][rrid]; signatures[sigid]=g.FIXTURES['signatures'][sigid]
    paths[identity]={'id':identity,'anchorKeyId':'root-ksk-g1','exactFinalKeyIds':keyids,
      'observedOffsets':[95100,35*DAY,90*DAY],
      'steps':[{'role':'dnskey','signatureId':'root-dnskey-path-long'}, {'role':'ds','signatureId':'root-example-ds-path-long','matchedChildKeyIds':['example-ksk-g1']}, {'role':'dnskey','signatureId':'example-dnskey-path-long'}, {'role':'ds','signatureId':ds_signature,'matchedChildKeyIds':[signer]}, {'role':'dnskey','signatureId':sigid}, {'role':'answer','signatureId':answer_signature}]}
files=['dnssec-numeric-fixtures.json','lifecycle-fixtures.json','long-profile-fixtures.json','complete-path-fixtures.json']
f={'schemaVersion':1,'kind':'dnssec-independent-single-role-rollover-fixtures','baseClock':g.CLOCK,'sourceFixtureSha256':{name:hashlib.sha256((g.OUT/name).read_bytes()).hexdigest() for name in files},'rrsets':rrsets,'signatures':signatures,'paths':paths,
 'scope':'Separate final states: ZSK-only rollover preserves KSKg1 and changes only ZSK; KSK-only rollover preserves ZSKg1 and changes only KSK. Actual base-600..day120 signatures are synthetic reference choices, not operational advice. Prior both-g2 fixture is not substituted for either role-specific final keyset.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=g.OUT/'role-rollover-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable role rollover fixtures differ')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':2,'signatures':2,'paths':2},indent=2))
