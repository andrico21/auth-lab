
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Check all alternate-profile signatures without importing the fixture producer."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import verify as v
raw=(v.OUT/'profile-fixtures.json').read_bytes()
p=json.loads(raw)
v.check('profiles-pinned-sha256',hashlib.sha256(raw).hexdigest(),generated_hash('profile-fixtures.json'))
v.check('profiles-baseline-binding',p['baselineSha256'],hashlib.sha256((v.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
start=len(v.RESULTS)
rows=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.OUT) as directory:
    for identity,sig in p['signatures'].items():
        rr=p['rrsets'][sig['rrsetId']]
        key=v.fixture['keys'][sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':independent-canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        librr=dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records'])
        libsig=dns.rdata.from_text('IN','RRSIG',sig['rrsigText'])
        libkeys={dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])}
        now=p['baseClock']+(10*86400 if 'omission' in identity else 0)
        dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=now)
        rows.append({'id':identity+':dnspython','now':now,'result':'pass'})
v.check('omission-is-exact-baseline-keys',p['rrsets']['child-anchor-omission']['records'],v.fixture['rrsets']['child-dnskey-g1']['records'])
report={'schemaVersion':1,'kind':'dnssec-independent-profile-verification','baselineSha256':p['baselineSha256'],'profilesSha256':hashlib.sha256(raw).hexdigest(),
 'result':'pass','independentAdditionalChecks':len(v.RESULTS)-start,'checks':v.RESULTS[start:],'observations':rows,
 'scope':'Concrete canonical/cryptographic profile bindings; no production evaluator or live server execution.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'profile-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Retain immutable previous profile result')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','additionalChecks':len(v.RESULTS)-start,'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
