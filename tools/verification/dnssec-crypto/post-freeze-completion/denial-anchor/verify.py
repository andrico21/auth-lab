#!/usr/bin/env python3
"""Check new positive hash bytes and B signature independently, without app/hold-down decisions."""
import base64
import hashlib
import json
import pathlib
import sys
import tempfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
import reference_bytes as v
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
OUT=v.OUT/'post-freeze-completion/denial-anchor'
raw=(OUT/'fixtures.json').read_bytes(); f=json.loads(raw)
v.check('denial-anchor-fixed-dataset',hashlib.sha256(raw).hexdigest(),'6d1a09887942d7568583804e7df47870faea9c10a96ee050a8f0b72b59cb8b40')
vector=f['nsec3']['nsec3-other-lab-zero-empty']
# The literal canonical wire is independently specified, not taken from the worksheet hash.
wire=bytes.fromhex('056f74686572036c6162076578616d706c6500')
v.check('other-name-independent-wire',v.name_wire('other.lab.example.'),wire)
digest=hashlib.sha1(wire).digest(); text=base64.b32hexencode(digest).decode('ascii').rstrip('=')
v.check('other-name-initial-sha1',digest.hex(),vector['initialHashHex'])
v.check('other-name-zero-iterations-final',digest.hex(),vector['finalHashHex'])
v.check('other-name-independent-base32hex',text,vector['hashBase32hex'])
v.check('other-name-library-nsec3',dns.dnssec.nsec3_hash('other.lab.example.','',0,1),text)
v.check('other-name-one-hash-application',vector['totalHashApplications'],1)
source_ref=f['rrsetReferences']['revoked-dnskey-a-b-z0']; source_raw=(v.ROOT/source_ref['path']).read_bytes()
v.check('unchanged-revoked-source-binding',hashlib.sha256(source_raw).hexdigest(),source_ref['sha256'])
source=json.loads(source_raw); rr=source['rrsets']['revoked-dnskey-a-b-z0']
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
v.check('exact-complete-revoked-keyset',sorted(rr['records']),sorted(base['keys'][key]['text'] for key in ['child-ksk-g1-revoked','child-ksk-g2','child-zsk-g1']))
sig=f['signatures']['revoked-dnskey-a-b-z0-by-b-refresh']; key=base['keys']['child-ksk-g2']; data=v.canonical(rr,sig)
v.check('b-exact-requested-signature-tuple',[sig[k] for k in ['keyId','keyTag','signer','originalTtl','inception','expiration']],['child-ksk-g2',46400,'lab.example.',3600,1792972200,1796169600])
v.check('b-independent-canonical-input',data.hex(),sig['signingInputHex'])
v.check('b-independent-signing-hash',hashlib.sha256(data).hexdigest(),sig['signingInputSha256'])
v.check('b-independent-signature-rdata-hash',hashlib.sha256(bytes.fromhex(sig['rrsigRdataHex'])).hexdigest(),sig['rrsigRdataSha256'])
v.check('b-independent-crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
with tempfile.TemporaryDirectory(prefix='openssl-',dir=pathlib.Path(__file__).resolve().parent) as directory:
    cli=v.openssl_check(sig['id'],key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory))
clock_checks=[]
for hour in range(25):
    now=f['baseClock']+3*86400+hour*3600
    v.check('b-current-window-hour'+str(hour),v.time_state(now,sig['inception'],sig['expiration']),'valid')
    dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text('lab.example.'):dns.rrset.from_text('lab.example.',3600,'IN','DNSKEY',key['text'])},now=now)
    clock_checks.append({'protocolClock':now,'hourSinceDay3':hour,'signatureId':sig['id'],'libraryVerified':True})
a=source['signatures']['revoked-dnskey-a-b-z0-self-signature']; akey=base['keys']['child-ksk-g1-revoked']
v.check('separate-a-revocation-selfsig-crypto',v.valid(akey,bytes.fromhex(a['signatureHex']),v.canonical(rr,a)),True)
report={'schemaVersion':1,'kind':'dnssec-public-denial-anchor-completion-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'nsec3IndependentCalculation':{'owner':'other.lab.example.','canonicalOwnerWireHex':wire.hex(),'initialAndFinalSha1Hex':digest.hex(),'base32hex':text,'worksheetClaim':f['worksheetHashClaim']['claim'],'claimMatchesActualDerivedHash':text==f['worksheetHashClaim']['claim']},'bSignatureObservation':{'signatureId':sig['id'],'keyId':sig['keyId'],'keyTag':sig['keyTag'],'inception':sig['inception'],'expiration':sig['expiration'],'openssl':cli,'clockedLocalChecks':clock_checks},'separateARevocationSignatureId':a['id'],'scope':'Local actual mathematical/library checks at25 protocol clocks, not network observations, hourly receipt/correlation evidence, RFC5011 eligibility or application acceptance. No production imports; no new secrets in public data/report.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Existing denial/anchor report differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'path':str(path.relative_to(v.ROOT)),'bytes':len(result),'sha256':hashlib.sha256(result).hexdigest(),'checks':len(v.RESULTS),'localSignatureClockChecks':len(clock_checks),'actualOtherHash':text},indent=2))
