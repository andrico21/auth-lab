
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Supplement the sealed datasets with strict leaf IDs and literal full clock-path bindings."""
import copy
import hashlib
import json
import generate as g
base=copy.deepcopy(g.FIXTURES)
DAY=86400
for suffix,keyid in [('g1','child-zsk-g1'),('g2','child-zsk-g2'),('csk-g1','child-csk-g1'),('csk-g2','child-csk-g2'),('ed25519','child-ed25519-g1'),('provider-b','provider-b-zsk-g1')]:
    g.sign('www-a-complete-path-'+suffix,'www-a',keyid,g.CLOCK-600,g.CLOCK+120*DAY)
g.rrset('child-dnskey-g2-final','lab.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in ['child-ksk-g2','child-zsk-g2']])
g.sign('child-dnskey-g2-final-long','child-dnskey-g2-final','child-ksk-g2',g.CLOCK-600,g.CLOCK+120*DAY)
files=['dnssec-numeric-fixtures.json','lifecycle-fixtures.json','profile-fixtures.json','long-profile-fixtures.json']
sources={name:json.loads((g.OUT/name).read_text()) for name in files}
new_rr={k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']}
new_sig={k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']}
source_for={}
signatures={}
for name,data in sources.items():
    for identity,signature in data['signatures'].items():
        source_for[identity]=name
        signatures[identity]=signature
for identity,signature in new_sig.items():
    source_for[identity]='complete-path-fixtures.json'; signatures[identity]=signature

def step(role,signature_id,keys=None):
    s=signatures[signature_id]
    result={'role':role,'signatureId':signature_id,'signatureSource':source_for[signature_id],
      'rrsetId':s['rrsetId'],'signerKeyId':s['keyId'],'inception':s['inception'],'expiration':s['expiration'],'signedOriginalTtl':s['originalTtl']}
    if keys is not None:
        result['matchedChildKeyIds']=keys
    return result
upper=[step('dnskey','root-dnskey-path-long'),step('ds','root-example-ds-path-long',['example-ksk-g1']),step('dnskey','example-dnskey-path-long')]
paths={}
def path(identity,ds_sig,dnskey_sig,answer_sig,keyids):
    paths[identity]={'id':identity,'anchorKeyId':'root-ksk-g1','anchorScope':'Explicit synthetic root DNSKEY provisioned locally, not public Internet root.',
     'observations':[{'offset':n,'now':g.CLOCK+n} for n in [0,95100,175200,35*DAY,90*DAY]],
     'steps':upper+[step('ds',ds_sig,keyids),step('dnskey',dnskey_sig),step('answer',answer_sig)],
     'expectedReferencePathValid':True,'expectedAddressRecords':['192.0.2.80','192.0.2.81']}
path('complete-g1-ttl3600','example-child-ds-path-long','child-dnskey-g1-path-long','www-a-complete-path-g1',['child-ksk-g1'])
path('complete-g2-final-ttl3600','example-child-ds-g2-long','child-dnskey-g2-final-long','www-a-complete-path-g2',['child-ksk-g2'])
path('complete-g1-ttl7200','example-child-ds-rollover-long','child-dnskey-g1-path-long','www-a-rollover-old-long',['child-ksk-g1'])
path('complete-g2-final-ttl7200','example-child-ds-g2-long','child-dnskey-g2-final-long','www-a-rollover-new-long',['child-ksk-g2'])
for suffix in ['csk-g1','csk-g2','ed25519-g1']:
    keyid='child-'+suffix
    leafsuffix='ed25519' if suffix=='ed25519-g1' else suffix
    path('complete-'+suffix+'-ttl3600','parent-ds-for-'+keyid+'-signature',keyid+'-dnskey-signature','www-a-complete-path-'+leafsuffix,[keyid])
    path('complete-'+suffix+'-ttl7200','parent-ds-for-'+keyid+'-signature',keyid+'-dnskey-signature','www-a-long-'+leafsuffix,[keyid])
path('complete-provider-b-ttl3600','parent-ds-provider-b-only-long-signature','provider-shared-dnskey-by-provider-long','www-a-complete-path-provider-b',['provider-b-ksk-g1'])
path('complete-provider-b-ttl7200','parent-ds-provider-b-only-long-signature','provider-shared-dnskey-by-provider-long','www-a-long-provider-b',['provider-b-ksk-g1'])
path('complete-dual-algorithm-ed25519','parent-ds-dual-algorithm-long-signature','child-dual-algorithm-dnskey-alg15','www-a-complete-path-ed25519',['child-ksk-g1','child-ed25519-g1'])
for suffix,keyid,dnskey_sig,answer_sig in [
 ('old-local','child-ksk-g1','child-dnskey-g1-path-long','www-a-complete-path-g1'),
 ('successor-local','child-ksk-g2','child-dnskey-g2-final-long','www-a-complete-path-g2')]:
    paths['complete-'+suffix]={'id':'complete-'+suffix,'anchorKeyId':keyid,'anchorScope':'Explicit independent local lab.example. trust point. Successor eligibility/hold-down is worksheet policy, not inferred from a crypto pass.',
      'observations':[{'offset':n,'now':g.CLOCK+n} for n in [35*DAY,90*DAY]],
      'steps':[step('dnskey',dnskey_sig),step('answer',answer_sig)],'expectedReferencePathValid':True,'expectedAddressRecords':['192.0.2.80','192.0.2.81']}
f={'schemaVersion':1,'kind':'dnssec-independent-complete-lifecycle-path-fixtures','baseClock':g.CLOCK,
 'sourceFixtureSha256':{name:hashlib.sha256((g.OUT/name).read_bytes()).hexdigest() for name in files},'rrsets':new_rr,'signatures':new_sig,'paths':paths,
 'scope':'Explicit synthetic lifecycle path choices. Every consumed DNSKEY/DS/leaf signature has actual fixed long-window bytes; no RRSIG metadata mutation.120day signature windows are NOT recommended normal lifetimes. Short base/refresh signatures remain unchanged for expiry/outage lessons. Reference path crypto validity does not establish cache eligibility or RFC5011 state transitions.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'complete-path-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable complete-path dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':len(new_rr),'signatures':len(new_sig),'literalPaths':len(paths)},indent=2))
