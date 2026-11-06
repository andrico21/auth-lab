
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Additional independently signed alternate-profile and anchor omission inputs."""
import copy
import hashlib
import json
import generate as g
base=copy.deepcopy(g.FIXTURES)
DAY=86400
for identity,ids,signer in [
 ('child-csk-g1-dnskey',['child-csk-g1'],'child-csk-g1'),
 ('child-csk-g2-dnskey',['child-csk-g2'],'child-csk-g2'),
 ('child-ed25519-g1-dnskey',['child-ed25519-g1'],'child-ed25519-g1'),
 ('child-anchor-omission',['child-ksk-g1','child-zsk-g1'],'child-ksk-g1')]:
    g.rrset(identity,'lab.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in ids],3600)
    g.sign(identity+'-signature',identity,signer,g.CLOCK-600,g.CLOCK+120*DAY)
for keyid in ['child-csk-g1','child-csk-g2','child-ed25519-g1']:
    identity='parent-ds-for-'+keyid
    g.rrset(identity,'lab.example.','DS',[g.FIXTURES['ds'][keyid+'-sha256']['text']],86400)
    g.sign(identity+'-signature',identity,'example-zsk-g1',g.CLOCK-600,g.CLOCK+120*DAY)
g.rrset('parent-ds-overlap-g1-g2','lab.example.','DS',[g.FIXTURES['ds'][k+'-sha256']['text'] for k in ['child-ksk-g1','child-ksk-g2']],86400)
g.sign('parent-ds-overlap-g1-g2-signature','parent-ds-overlap-g1-g2','example-zsk-g1',g.CLOCK-600,g.CLOCK+120*DAY)
supp={'schemaVersion':1,'kind':'dnssec-independent-numeric-profile-supplement','baseClock':g.CLOCK,
 'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},
 'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'profiles':{
  'combined-key-g1':{'dnskeyRrsetId':'child-csk-g1-dnskey','dsRrsetId':'parent-ds-for-child-csk-g1','answerSignatureId':'www-a-csk'},
  'combined-key-g2':{'dnskeyRrsetId':'child-csk-g2-dnskey','dsRrsetId':'parent-ds-for-child-csk-g2'},
  'ed25519-alternate':{'dnskeyRrsetId':'child-ed25519-g1-dnskey','dsRrsetId':'parent-ds-for-child-ed25519-g1','answerSignatureId':'www-a-ed25519'},
  'anchor-interrupted-add':{'initialRrsetId':'child-anchor-observation','omissionRrsetId':'child-anchor-omission','omissionAtDay':10,'readdedAtDay':20,'eligibleObservationDay':50}},
 'scope':'Explicit alternate RRset profiles. Child public keys may be combined differently only with the corresponding signed DNSKEY/DS fixture, not by mutating covered bytes.'}
raw=(json.dumps(supp,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'profile-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable profile dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':len(supp['rrsets']),'signatures':len(supp['signatures'])},indent=2))
