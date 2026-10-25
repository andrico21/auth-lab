#!/usr/bin/env python3
"""Verify actual parent SOA/NSEC bytes and their separate negative TTL binding."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'parent-negative-fixtures.json').read_bytes(); f=json.loads(raw)
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
r=json.loads((v.OUT/'resolution-profile-fixtures.json').read_text())
v.check('parent-negative-pinned-sha256',hashlib.sha256(raw).hexdigest(),'0d0c433ab595dec3991ad83d26ed1ff71fa3656205e7fcc7388f8db6d43646f3')
v.check('parent-negative-resolution-binding',hashlib.sha256((v.OUT/'resolution-profile-fixtures.json').read_bytes()).hexdigest(),f['resolutionProfileSha256'])
rr=f['rrsets']['example-soa-negative-cache']; sig=f['signatures']['example-soa-negative-cache-signature']; key=base['keys'][sig['keyId']]
data=v.canonical(rr,sig)
v.check('parent-soa-independent-input',data.hex(),sig['signingInputHex'])
v.check('parent-soa-crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    observation=v.openssl_check(sig['id'],key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory))
for s,record in [(sig,rr),(r['signatures']['denial-parent-unsigned-lab-signature'],r['rrsets']['denial-parent-unsigned-lab'])]:
    dns.dnssec.validate_rrsig(dns.rrset.from_text(record['owner'],record['ttl'],'IN',record['type'],*record['records']),dns.rdata.from_text('IN','RRSIG',s['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=f['baseClock'])
minimum=int(rr['records'][0].split()[-1]); binding=f['binding']
v.check('parent-soa-minimum',minimum,300)
v.check('parent-negative-original-ttl-signed',sig['originalTtl'],3600)
v.check('parent-negative-received-soa-input',v.canonical({**rr,'ttl':binding['receivedSoaTtl']},sig).hex(),sig['signingInputHex'])
v.check('parent-negative-ttl-cap',min(binding['receivedSoaTtl'],minimum),300)
report={'schemaVersion':1,'kind':'dnssec-independent-parent-negative-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'opensslObservation':observation,'libraryObservations':[{'rrsetId':rr['id'],'validAt':f['baseClock']},{'rrsetId':'denial-parent-unsigned-lab','validAt':f['baseClock']}],'scope':'Actual parent SOA and parent noDS NSEC validation in a separate unsigned-delegation profile, not a claim that public baseline child DS is absent.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); path=v.OUT/'parent-negative-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable parent negative verification differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
