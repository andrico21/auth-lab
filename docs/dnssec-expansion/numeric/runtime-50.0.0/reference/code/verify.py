
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Independent limited-fixture canonical reconstruction. Does not import dns or generate.
Supported types are explicit; unknown types fail. Not a production DNS validator.
"""
import base64
import hashlib
import ipaddress
import json
import pathlib
import shlex
import struct
import subprocess
import tempfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

ROOT = ROOT
HERE=pathlib.Path(__file__).resolve().parent
OUT=output_root()
TYPES={'A':1,'NS':2,'CNAME':5,'SOA':6,'MX':15,'TXT':16,'AAAA':28,'DNAME':39,'DS':43,'RRSIG':46,'NSEC':47,'DNSKEY':48,'NSEC3':50,'NSEC3PARAM':51,'CDS':59,'CDNSKEY':60,'CSYNC':62,'ZONEMD':63,'DSYNC':66,'NXNAME':128}
RESULTS=[]

from reference_bytes import (
    RESULTS, check, name_wire, bitmap, rdata, canonical, public_key,
    signature_der, valid, openssl_check, key_tag, nsec3, serial_order,
    time_state, wire_name, read_mx_message,
)

fixture_bytes=(OUT/'dnssec-numeric-fixtures.json').read_bytes()
fixture=json.loads(fixture_bytes)
check('dataset-pinned-sha256',hashlib.sha256(fixture_bytes).hexdigest(),generated_hash('dnssec-numeric-fixtures.json'))
for identity,key in fixture['keys'].items():
    raw=rdata('DNSKEY',key['text'])
    check(identity+':dnskey-wire',raw.hex(),key['dnskeyRdataHex'])
    check(identity+':keytag',key_tag(raw),key['keyTag'])
    check(identity+':public-pem',public_key(key).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode(),key['publicKeyPem'])
for identity,d in fixture['ds'].items():
    key=fixture['keys'][d['keyId']]
    data=name_wire(key['owner'])+rdata('DNSKEY',key['text'])
    check(identity+':input',data.hex(),d['digestInputHex'])
    digest=hashlib.sha256(data).hexdigest() if d['digestType']==2 else hashlib.sha1(data).hexdigest()
    check(identity+':digest',digest,d['digestHex'])
    check(identity+':rdata',rdata('DS',d['text']).hex(),d['dsRdataHex'])
openssl_results=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=OUT) as directory:
    scratch=pathlib.Path(directory)
    for identity,sig in fixture['signatures'].items():
        rr=fixture['rrsets'][sig['rrsetId']]
        key=fixture['keys'][sig['keyId']]
        data=canonical(rr,sig)
        check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
        check(identity+':cryptographic-valid',valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        openssl_results.append(openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,scratch))
        RESULTS.append({'id':identity+':openssl-cli','result':'pass'})
for identity,rr in fixture['rrsets'].items():
    check(identity+':canonical-rdata',sorted(rdata(rr['type'],r).hex() for r in rr['records']),rr['canonicalRdataHex'])
for vector in fixture['vectors']['mutations']:
    sig=fixture['signatures'][vector['signatureId']]
    key=fixture['keys'][sig['keyId']]
    check(vector['id'],valid(key,bytes.fromhex(sig['signatureHex']),canonical(vector,sig)),False)
v=fixture['vectors']['canonical-equivalence']
sig=fixture['signatures'][v['signatureId']]
check('canonical-presentation-equivalence',canonical(v['variant'],sig).hex(),sig['signingInputHex'])
for variant in ['compressed','uncompressed']:
    v=fixture['vectors']['mx-'+variant]
    rr=read_mx_message(bytes.fromhex(v['wireHex']))
    sig=fixture['signatures'][v['expectedSameSigningInputAs']]
    check('mx-'+variant+':same-canonical-input',canonical(rr,sig).hex(),sig['signingInputHex'])
sig=fixture['signatures']['wildcard-a-signature']
rr={**fixture['rrsets']['wildcard-a'],'owner':'shop.lab.example.'}
check('wildcard-expanded-input',canonical(rr,sig).hex(),sig['signingInputHex'])
collision=fixture['vectors']['keytag-collision']
sig=fixture['signatures']['www-a-collision']
for identity,expected in zip(collision['candidateIds'],collision['expectedCandidateResults']):
    check('collision-candidate:'+identity,valid(fixture['keys'][identity],bytes.fromhex(sig['signatureHex']),bytes.fromhex(sig['signingInputHex'])),expected)
check('revocation-preserves-public-bytes',fixture['keys']['child-ksk-g1']['publicKeyHex'],fixture['keys']['child-ksk-g1-revoked']['publicKeyHex'])
check('revocation-tag-delta',fixture['keys']['child-ksk-g1-revoked']['keyTag']-fixture['keys']['child-ksk-g1']['keyTag'],128)
nsec3_results={}
for identity,v in fixture['nsec3'].items():
    result=nsec3(v['owner'],v['iterations'],bytes.fromhex(v['saltHex']))
    check(identity+':nsec3',result['hashBase32hex'],v['hashBase32hex'])
    nsec3_results[identity]=result
for v in fixture['vectors']['signature-time']:
    check('serial:'+v['id'],time_state(v['now'],v['inception'],v['expiration']),v['expected'])
published=json.loads((HISTORICAL_TOOLS/'published-vectors.json').read_text())
for identity in ['rfc6605-p256','rfc8080-ed25519-erratum-1','rfc4509-sha256']:
    v=published[identity]
    raw=rdata('DNSKEY',v['dnskey'])
    check(identity+':published-tag',key_tag(raw),v['keyTag'])
    digest=hashlib.sha256(name_wire(v['owner'])+raw).hexdigest()
    check(identity+':published-ds',digest,v['ds'].split()[-1].lower())
    if 'rrsig' in v:
        fields=v['rrsig'].split()
        def timestamp(s):
            import datetime
            return int(datetime.datetime.strptime(s,'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc).timestamp()) if len(s)==14 else int(s)
        sig={'typeCovered':TYPES[fields[0]],'algorithm':int(fields[1]),'labels':int(fields[2]),'originalTtl':int(fields[3]),'expiration':timestamp(fields[4]),'inception':timestamp(fields[5]),'keyTag':int(fields[6]),'signer':fields[7]}
        key={'algorithm':int(v['dnskey'].split()[2]),'publicKeyHex':base64.b64decode(v['dnskey'].split()[3]).hex()}
        check(identity+':published-signature',valid(key,base64.b64decode(fields[8]),canonical(v['rrset'],sig)),True)
v=published['rfc5155-appendix-a']
for name,expected in v['hashes'].items():
    check('rfc5155:'+name,nsec3(name,v['iterations'],bytes.fromhex(v['saltHex']))['hashBase32hex'],expected)
report={'schemaVersion':1,'kind':'dnssec-independent-numeric-verification','fixtureSha256':hashlib.sha256(fixture_bytes).hexdigest(),
 'result':'pass','checks':len(RESULTS),'results':RESULTS,'openssl':{'version':subprocess.check_output(['openssl','version'],text=True).strip(),'observations':openssl_results},
 'nsec3Calculations':nsec3_results,'limits':['Limited fixture-type canonicalizer, not production DNSSEC validator','Serial vectors checked separately from dnspython plain-time API','No live DNS or server interoperability claimed']}
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'independent-verification.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Preserve previous independent result; changed output requires new artifact identity')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'result':'pass','checks':len(RESULTS),'reportSha256':hashlib.sha256(raw).hexdigest(),'path':reference_path(path)},indent=2))
