
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""A distinct zone variant with real authenticated ZONEMD expected-digest bytes."""
import copy
import hashlib
import json
import dns.rdata
import dns.zone
import dns.zonetypes
import generate as g
base=copy.deepcopy(g.FIXTURES)
g.rrset('child-nsec-with-zonemd','lab.example.','NSEC',['WWW.lab.example. NS SOA MX TXT RRSIG NSEC DNSKEY ZONEMD'])
g.sign('child-nsec-with-zonemd-signature','child-nsec-with-zonemd','child-zsk-g1')
selected=['child-dnskey-g1','child-ns','child-soa','child-mx','child-txt','child-nsec-with-zonemd','www-a','www-nsec','wildcard-a']
lines=[]
for identity in selected:
    rr=g.FIXTURES['rrsets'][identity]
    lines += [f"{rr['owner']} {rr['ttl']} IN {rr['type']} {text}" for text in rr['records']]
    sigid='child-dnskey-g1-by-ksk' if identity=='child-dnskey-g1' else identity+'-signature'
    sig=g.FIXTURES['signatures'][sigid]
    lines.append(f"{rr['owner']} {rr['ttl']} IN RRSIG {sig['rrsigText']}")
lines+=['unsigned.lab.example. 3600 IN NS ns.unsigned.lab.example.','ns.unsigned.lab.example. 3600 IN A 192.0.2.200']
zone_text='\n'.join(lines)+'\n'
zone=dns.zone.from_text(zone_text,origin='lab.example.',relativize=False)
digest=zone.compute_digest(dns.zonetypes.DigestHashAlgorithm.SHA384)
zone.verify_digest(digest)
g.rrset('child-zonemd-auth','lab.example.','ZONEMD',[digest.to_text()])
g.sign('child-zonemd-auth-signature','child-zonemd-auth','child-zsk-g1')
zone_text+=f"lab.example. 3600 IN ZONEMD {digest.to_text()}\nlab.example. 3600 IN RRSIG {g.FIXTURES['signatures']['child-zonemd-auth-signature']['rrsigText']}\n"
zone=dns.zone.from_text(zone_text,origin='lab.example.',relativize=False)
zone.verify_digest()
supp={'schemaVersion':1,'kind':'dnssec-independent-authenticated-zonemd-fixtures','baseClock':g.CLOCK,
 'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},
 'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'zonemd':{'id':'child-zone-authenticated-simple-sha384','owner':'lab.example.','serial':2026102301,'scheme':1,'hashAlgorithm':1,
 'zoneText':zone_text,'zonemdText':digest.to_text(),'digestHex':digest.digest.hex(),'soaRrsetId':'child-soa','soaSignatureId':'child-soa-signature',
 'expectedDigestRrsetId':'child-zonemd-auth','expectedDigestSignatureId':'child-zonemd-auth-signature',
 'tampering':{'replace':'192.0.2.200','with':'192.0.2.201','signedRrsetsPreserved':True,'expectedWholeZoneDigestMatch':False,'expectedZoneAccepted':False}},
 'trustPath':{'anchorKeyId':'root-ksk-g1','scope':'Explicit synthetic locally provisioned root DNSKEY anchor; no live root identity.',
 'orderedSignatureIds':['root-dnskey-g1-by-ksk','root-example-ds-signature','example-dnskey-g1-by-ksk','example-child-ds-signature','child-dnskey-g1-by-ksk','child-soa-signature','child-zonemd-auth-signature'],
 'delegationDsIds':['example-ksk-g1-sha256','child-ksk-g1-sha256']},
 'scope':'Signed expected-digest path plus whole-zone SIMPLE SHA384. Variant adds ZONEMD bit to apex NSEC before digest. Digest/RRSIG(ZONEMD) excluded to prevent cycle. No server interoperability.'}
raw=(json.dumps(supp,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'zonemd-auth-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable authenticated ZONEMD dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'digestHex':digest.digest.hex()},indent=2))
