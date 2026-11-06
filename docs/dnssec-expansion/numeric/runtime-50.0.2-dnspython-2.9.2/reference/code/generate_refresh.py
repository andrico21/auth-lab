
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Actual old/refreshed same-key signatures for the worksheet's fixed DNS12 offsets."""
import hashlib
import json
import generate as g
identity='www-a-refresh-ttl7200'
g.rrset(identity,'www.lab.example.','A',['192.0.2.80','192.0.2.81'],7200)
g.sign('www-a-refresh-old-expiry10000',identity,'child-zsk-g1',g.CLOCK-600,g.CLOCK+10000)
g.sign('www-a-refresh-same-key-new',identity,'child-zsk-g1',g.CLOCK+5400,g.CLOCK+14*86400)
f={'schemaVersion':1,'kind':'dnssec-independent-refresh-time-fixtures','baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),'baseClock':g.CLOCK,
 'rrsets':{identity:g.FIXTURES['rrsets'][identity]},'signatures':{i:g.FIXTURES['signatures'][i] for i in ['www-a-refresh-old-expiry10000','www-a-refresh-same-key-new']},
 'observations':[{'offset':7000,'old':'valid','refreshed':'valid'},{'offset':10000,'old':'valid','refreshed':'valid'},{'offset':10001,'old':'expired','refreshed':'valid'}],
 'scope':'Both signatures use child-zsk-g1 and signed OriginalTTL7200. Outage means refreshed signature was not delivered, not that its fixed cryptographic bytes are invalid.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'refresh-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable refresh fixtures differ')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},indent=2))
