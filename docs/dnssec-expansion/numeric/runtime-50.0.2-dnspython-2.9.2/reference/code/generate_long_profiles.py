
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Real long-window complete paths for lifecycle CSK/algorithm/provider transitions."""
import copy
import hashlib
import json
import generate as g
base=copy.deepcopy(g.FIXTURES)
DAY=86400
for identity,rrid,keyid in [
 ('root-dnskey-path-long','root-dnskey-g1','root-ksk-g1'),
 ('root-example-ds-path-long','root-example-ds','root-zsk-g1'),
 ('example-dnskey-path-long','example-dnskey-g1','example-ksk-g1'),
 ('example-child-ds-path-long','example-child-ds','example-zsk-g1'),
 ('child-dnskey-g1-path-long','child-dnskey-g1','child-ksk-g1'),
 ('provider-shared-dnskey-by-original-long','provider-shared-dnskey','child-ksk-g1'),
 ('provider-shared-dnskey-by-provider-long','provider-shared-dnskey','provider-b-ksk-g1')]:
    g.sign(identity,rrid,keyid,g.CLOCK-600,g.CLOCK+120*DAY)
g.rrset('www-a-long-profile-ttl7200','www.lab.example.','A',['192.0.2.80','192.0.2.81'],7200)
for suffix,keyid in [('csk-g1','child-csk-g1'),('csk-g2','child-csk-g2'),('ed25519','child-ed25519-g1'),('provider-b','provider-b-zsk-g1')]:
    g.sign('www-a-long-'+suffix,'www-a-long-profile-ttl7200',keyid,g.CLOCK-600,g.CLOCK+120*DAY)
g.rrset('child-dual-algorithm-dnskey','lab.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in ['child-ksk-g1','child-zsk-g1','child-ed25519-g1']])
for suffix,keyid in [('alg13','child-ksk-g1'),('alg15','child-ed25519-g1')]:
    g.sign('child-dual-algorithm-dnskey-'+suffix,'child-dual-algorithm-dnskey',keyid,g.CLOCK-600,g.CLOCK+120*DAY)
for identity,keyids in [('parent-ds-dual-algorithm',['child-ksk-g1','child-ed25519-g1']),('parent-ds-provider-overlap',['child-ksk-g1','provider-b-ksk-g1']),('parent-ds-provider-b-only',['provider-b-ksk-g1'])]:
    g.rrset(identity,'lab.example.','DS',[g.FIXTURES['ds'][k+'-sha256']['text'] for k in keyids],86400)
    g.sign(identity+'-long-signature',identity,'example-zsk-g1',g.CLOCK-600,g.CLOCK+120*DAY)
f={'schemaVersion':1,'kind':'dnssec-independent-long-clock-profile-fixtures','baseClock':g.CLOCK,'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'observedOffsets':[0,95100,175200,45*DAY],
 'upperPathSignatureIds':['root-dnskey-path-long','root-example-ds-path-long','example-dnskey-path-long'],
 'profiles':{'csk-final':{'signatureIds':['www-a-long-csk-g1','www-a-long-csk-g2'],'dnskeySource':'profile-fixtures.json','offset':95100},
 'dual-algorithm':{'dnskeyRrsetId':'child-dual-algorithm-dnskey','dsRrsetId':'parent-ds-dual-algorithm','answerSignatureId':'www-a-long-ed25519','offset':95100},
 'provider-migration':{'dnskeyRrsetId':'provider-shared-dnskey','dsOverlapId':'parent-ds-provider-overlap','dsFinalId':'parent-ds-provider-b-only','answerSignatureId':'www-a-long-provider-b','offset':175200}},
 'scope':'Actual signatures cover all named upper-path and leaf evidence at lifecycle clocks. The120day lifetime is a synthetic fixed-byte choice, not operational advice; cache/hold-down policy remains independent.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'long-profile-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable long-profile dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':len(f['rrsets']),'signatures':len(f['signatures'])},indent=2))
