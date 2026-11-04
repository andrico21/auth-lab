
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Concrete trust-path and signed expected-digest reference checks, no production imports."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import dns.zone
import verify_lifecycle as lv
v=lv.v
raw=(v.OUT/'zonemd-auth-fixtures.json').read_bytes()
a=json.loads(raw)
v.check('zonemd-auth-pinned-sha256',hashlib.sha256(raw).hexdigest(),generated_hash('zonemd-auth-fixtures.json'))
v.check('zonemd-auth-baseline-binding',a['baselineSha256'],hashlib.sha256((v.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
rrsets={**v.fixture['rrsets'],**a['rrsets']}
sigs={**v.fixture['signatures'],**a['signatures']}
keys=v.fixture['keys']
start=len(v.RESULTS)
rows=[]
# Literal, independently selected synthetic trust-chain sequence. Public keys readable before trust.
trusted={'root-ksk-g1'}
def verify_signature(identity):
    sig=sigs[identity]
    rr=rrsets[sig['rrsetId']]
    key=keys[sig['keyId']]
    v.check(identity+':signing-key-authenticated',sig['keyId'] in trusted,True)
    v.check(identity+':independent-canonical',v.canonical(rr,sig).hex(),sig['signingInputHex'])
    v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),v.canonical(rr,sig)),True)
    librr=dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records'])
    libsig=dns.rdata.from_text('IN','RRSIG',sig['rrsigText'])
    libkeys={dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])}
    dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=a['baseClock'])
    rows.append({'signatureId':identity,'keyId':sig['keyId'],'authenticatedAt':a['baseClock'],'result':'pass'})

def promote_dnskey(prefix):
    verify_signature(prefix+'-dnskey-g1-by-ksk')
    texts=rrsets[prefix+'-dnskey-g1']['records']
    for suffix in ['ksk-g1','zsk-g1']:
        identity=prefix+'-'+suffix
        v.check(identity+':in-authenticated-dnskey-rrset',keys[identity]['text'] in texts,True)
        trusted.add(identity)

def delegated_key(keyid,dsid,signature_id):
    verify_signature(signature_id)
    sig=sigs[signature_id]
    actual_ds=v.fixture['ds'][dsid]
    v.check(dsid+':record-in-parent-authenticated-ds',actual_ds['text'] in rrsets[sig['rrsetId']]['records'],True)
    key=keys[keyid]
    digest=hashlib.sha256(v.name_wire(key['owner'])+v.rdata('DNSKEY',key['text'])).hexdigest()
    v.check(dsid+':child-key-matches-authenticated-ds',digest,actual_ds['digestHex'])
    trusted.add(keyid)

promote_dnskey('root')
delegated_key('example-ksk-g1','example-ksk-g1-sha256','root-example-ds-signature')
promote_dnskey('example')
delegated_key('child-ksk-g1','child-ksk-g1-sha256','example-child-ds-signature')
promote_dnskey('child')
for identity in ['child-soa-signature','child-zonemd-auth-signature','child-nsec-with-zonemd-signature','child-ns-signature','child-mx-signature','child-txt-signature','www-a-signature','www-nsec-signature','wildcard-a-signature']:
    verify_signature(identity)
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.OUT) as directory:
    for identity,sig in a['signatures'].items():
        rows.append(v.openssl_check(identity,keys[sig['keyId']],bytes.fromhex(sig['signatureHex']),v.canonical(rrsets[sig['rrsetId']],sig),pathlib.Path(directory)))
z=a['zonemd']
v.check('zonemd-soa-serial-match',int(rrsets[z['soaRrsetId']]['records'][0].split()[2]),z['serial'])
v.check('zonemd-signed-rdata-serial-match',int(rrsets[z['expectedDigestRrsetId']]['records'][0].split()[0]),z['serial'])
v.check('zonemd-digest-independent',hashlib.sha384(lv.zone_input(z['zoneText'],z['owner'])).hexdigest(),z['digestHex'])
zone=dns.zone.from_text(z['zoneText'],origin=z['owner'],relativize=False)
zone.verify_digest()
rows.append({'id':'authenticated-expected-digest-and-whole-zone-match','result':'pass','acceptedForUse':True})
mutation=z['zoneText'].replace(z['tampering']['replace'],z['tampering']['with'])
v.check('tampered-unsigned-glue-whole-zone-digest-mismatch',hashlib.sha384(lv.zone_input(mutation,z['owner'])).hexdigest()==z['digestHex'],False)
mutated_zone=dns.zone.from_text(mutation,origin=z['owner'],relativize=False)
try:
    mutated_zone.verify_digest()
    result={'exceptionClass':None}
except Exception as error:
    result={'exceptionClass':type(error).__name__,'message':str(error)}
v.check('tampered-zone-reference-rejection',result['exceptionClass'],'DigestVerificationFailure')
rows.append({'id':'tampered-zone-rejected','observation':result,'individuallyValidSignedRrsetsPreserved':True,'zoneAccepted':False})
# Exact mutation is to unsigned glue only. Recheck preserved signatures, not a fabricated global bogus RRset.
for identity in ['child-soa-signature','child-zonemd-auth-signature','www-a-signature']:
    verify_signature(identity)
report={'schemaVersion':1,'kind':'dnssec-independent-authenticated-zonemd-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),
 'result':'pass','additionalChecks':len(v.RESULTS)-start,'checks':v.RESULTS[start:],'observations':rows,
 'authenticationScope':{'anchor':'Explicit local synthetic root-ksk-g1','path':['.','example.','lab.example.'],'clock':a['baseClock'],
 'expectedDigestAuthenticated':True,'soaAuthenticated':True,'originalZoneDigestMatches':True,'mutatedWholeZoneAccepted':False,
 'individualRrsetSignatureFailuresInvented':False},'limits':['Concrete fixture path only, not production validator','No live DNS, transfer server or interoperability execution','Checksum-only lifecycle and RFC8976 fixtures retain their separate narrower scope']}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'zonemd-auth-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Retain immutable previous authenticated ZONEMD verification')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','additionalChecks':len(v.RESULTS)-start,'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
