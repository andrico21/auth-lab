#!/usr/bin/env python3
"""Check only new precise refresh signatures and captured validity boundaries."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'refresh-fixtures.json').read_bytes()
f=json.loads(raw)
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
v.check('refresh-pinned-sha256',hashlib.sha256(raw).hexdigest(),'f4b56e67c5cf51d72f498ea1e287f470515a6c9d380008a1be5e1a580ed2e6d2')
rows=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    for identity,sig in f['signatures'].items():
        rr=f['rrsets'][sig['rrsetId']]
        key=base['keys'][sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        for point in f['observations']:
            expected=point['old' if identity=='www-a-refresh-old-expiry10000' else 'refreshed']
            now=f['baseClock']+point['offset']
            v.check(identity+':independent-time-'+str(point['offset']),v.time_state(now,sig['inception'],sig['expiration']),expected)
            try:
                dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
                observation={'valid':True}
            except Exception as error:
                observation={'valid':False,'exceptionClass':type(error).__name__,'message':str(error)}
            v.check(identity+':library-time-'+str(point['offset']),observation['valid'],expected=='valid')
            rows.append({'signatureId':identity,'offset':point['offset'],'observation':observation})
report={'schemaVersion':1,'kind':'dnssec-independent-refresh-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'observations':rows}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'refresh-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable refresh verification differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
