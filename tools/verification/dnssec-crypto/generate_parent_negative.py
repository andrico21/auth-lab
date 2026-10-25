#!/usr/bin/env python3
"""Signed parent SOA for the explicit parent no-DS negative-cache variant."""
import hashlib
import json
import generate as g
g.rrset('example-soa-negative-cache','example.','SOA',['ns1.example. hostmaster.example. 2026102301 3600 600 86400 300'],3600)
g.sign('example-soa-negative-cache-signature','example-soa-negative-cache','example-zsk-g1')
f={'schemaVersion':1,'kind':'dnssec-independent-parent-negative-fixtures','baseClock':g.CLOCK,
 'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'resolutionProfileSha256':hashlib.sha256((g.OUT/'resolution-profile-fixtures.json').read_bytes()).hexdigest(),
 'rrsets':{'example-soa-negative-cache':g.FIXTURES['rrsets']['example-soa-negative-cache']},
 'signatures':{'example-soa-negative-cache-signature':g.FIXTURES['signatures']['example-soa-negative-cache-signature']},
 'binding':{'parentZone':'example.','delegation':'lab.example.','soaRrsetId':'example-soa-negative-cache','nsecRrsetId':'denial-parent-unsigned-lab','soaOriginalTtl':3600,'receivedSoaTtl':300,'soaMinimum':300,'negativeCacheTtlCap':300,'scope':'Parent DS NODATA in explicitly unsigned-delegation zone variant, not public baseline signed delegation. Signature validity and negative TTL remain distinct.'}}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=g.OUT/'parent-negative-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable parent negative fixtures differ')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},indent=2))
