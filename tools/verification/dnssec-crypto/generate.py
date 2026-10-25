#!/usr/bin/env python3
"""Verification-only DNS fixture producer. dnspython owns signing canonicalization.
The independent verifier MUST NOT import this file or dns.*.
"""
import base64
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import struct
import sys
import dns.dnssec
import dns.message
import dns.name
import dns.rdata
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = ROOT / 'docs/dnssec-expansion/numeric'
CLOCK = 1792713600
INCEPTION = CLOCK - 600
EXPIRATION = CLOCK + 3600
ORDER = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
FIXTURES = {'schemaVersion': 1, 'kind': 'dnssec-independent-numeric-fixtures', 'independentOfProduction': True,
 'researchCutoff': '2026-10-23', 'baseClock': CLOCK,
 'referenceTool': {'name': 'dnspython', 'version': '2.8.0', 'crypto': 'cryptography==46.0.3',
 'python': platform.python_version(), 'signingInputProducer': 'dns.dnssec._make_rrsig_signature_data',
 'independentVerifier': 'verify.py (no dns imports; separate canonical reconstruction and OpenSSL CLI)'},
 'keys': {}, 'rrsets': {}, 'signatures': {}, 'ds': {}, 'nsec3': {}, 'vectors': {},
 'generationProvenance': {'command': 'tools/verification/dnssec-crypto/.venv/bin/python tools/verification/dnssec-crypto/generate.py',
 'privateMaterial': 'Public deterministic fixture-only bytes; signer-only illustration, NEVER real secrets or network DNSKEY fields.',
 'scope': 'Offline synthetic cryptographic bytes, not live DNS/server interoperability or full denial validation.',
 'canonicalOracle': 'Published primary bytes transcribed in published-vectors.json, independent verify.py canonical reconstruction, frozen expectations.json hashes.'}}
PRIVATE = {}
DNSKEY = {}
RRSETS = {}
RRSIGS = {}

def key(identity, owner, flags=257, algorithm=13, scalar=None):
    seed = hashlib.sha256(('auth-lab-dnssec-D0:' + identity).encode()).digest()
    if algorithm == 13:
        scalar = scalar or (int.from_bytes(seed, 'big') % (ORDER - 1) + 1)
        private = ec.derive_private_key(scalar, ec.SECP256R1())
        secret = scalar.to_bytes(32, 'big')
    else:
        secret = seed
        private = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
    public = private.public_key()
    dnskey = dns.dnssec.make_dnskey(public, algorithm, flags=flags)
    PRIVATE[identity] = private
    DNSKEY[identity] = dnskey
    FIXTURES['keys'][identity] = {'id': identity, 'owner': owner, 'flags': flags, 'protocol': 3, 'algorithm': algorithm,
      'publicKeyHex': dnskey.key.hex(), 'publicKeyBase64': base64.b64encode(dnskey.key).decode(),
      'dnskeyRdataHex': dnskey.to_wire().hex(), 'keyTag': dns.dnssec.key_id(dnskey), 'text': dnskey.to_text(),
      'publicKeyPem': public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
      'generation': {'method': 'SHA256(label) reduced modulo P256 order minus1 plus1' if algorithm == 13 else 'SHA256(label) Ed25519 seed',
      'label': 'auth-lab-dnssec-D0:' + identity, 'scalarOverride': scalar if identity.startswith('collision-') else None,
      'fixtureOnlyPrivateHex': secret.hex(), 'privateCustodian': 'dnsSigner', 'privateIsNetworkRecord': False},
      'lineage': identity}
    return dnskey

def rrset(identity, owner, rrtype, records, ttl=3600):
    rr = dns.rrset.from_text(owner, ttl, 'IN', rrtype, *records)
    RRSETS[identity] = rr
    FIXTURES['rrsets'][identity] = {'id': identity, 'owner': owner, 'class': 'IN', 'type': rrtype,
      'typeCode': int(rr.rdtype), 'ttl': ttl, 'records': records,
      'canonicalRdataHex': sorted(r.to_digestable().hex() for r in rr)}
    return rr

def sign(identity, rrid, keyid, inception=INCEPTION, expiration=EXPIRATION):
    rr = RRSETS[rrid]
    signer = dns.name.from_text(FIXTURES['keys'][keyid]['owner'])
    sig = dns.dnssec.sign(rr, PRIVATE[keyid], signer, DNSKEY[keyid], inception=inception, expiration=expiration, deterministic=True)
    data = dns.dnssec._make_rrsig_signature_data(rr, sig)
    RRSIGS[identity] = sig
    FIXTURES['signatures'][identity] = {'id': identity, 'rrsetId': rrid, 'keyId': keyid,
      'typeCovered': int(sig.type_covered), 'algorithm': sig.algorithm, 'labels': sig.labels, 'originalTtl': sig.original_ttl,
      'inception': sig.inception, 'expiration': sig.expiration, 'keyTag': sig.key_tag, 'signer': sig.signer.to_text(),
      'rrsigText': sig.to_text(), 'rrsigRdataHex': sig.to_wire().hex(), 'signatureHex': sig.signature.hex(),
      'signingInputHex': data.hex(), 'signingInputSha256': hashlib.sha256(data).hexdigest(),
      'verificationAt': CLOCK, 'expectedCryptographicValid': True}
    return sig

def ds(identity, keyid, digest_type=2):
    k = FIXTURES['keys'][keyid]
    d = dns.dnssec.make_ds(k['owner'], DNSKEY[keyid], digest_type, policy=dns.dnssec.allow_all_policy)
    raw = dns.name.from_text(k['owner']).to_digestable() + DNSKEY[keyid].to_wire()
    FIXTURES['ds'][identity] = {'id': identity, 'keyId': keyid, 'owner': k['owner'], 'keyTag': d.key_tag,
      'algorithm': d.algorithm, 'digestType': d.digest_type, 'digestHex': d.digest.hex(), 'digestInputHex': raw.hex(),
      'dsRdataHex': d.to_wire().hex(), 'text': d.to_text(), 'policy': 'baseline' if digest_type == 2 else 'verification-only historical digest, not signing policy'}
    return d

for identity, owner, flags in [
 ('root-ksk-g1', '.',257), ('root-zsk-g1','.',256), ('example-ksk-g1','example.',257), ('example-zsk-g1','example.',256),
 ('child-ksk-g1','lab.example.',257), ('child-zsk-g1','lab.example.',256), ('child-ksk-g2','lab.example.',257), ('child-zsk-g2','lab.example.',256),
 ('child-csk-g1','lab.example.',257), ('child-csk-g2','lab.example.',257), ('provider-b-ksk-g1','lab.example.',257), ('provider-b-zsk-g1','lab.example.',256)]:
    key(identity, owner, flags)
key('child-ed25519-g1', 'lab.example.', algorithm=15)
revoked = DNSKEY['child-ksk-g1'].replace(flags=385)
DNSKEY['child-ksk-g1-revoked'] = revoked
PRIVATE['child-ksk-g1-revoked'] = PRIVATE['child-ksk-g1']
FIXTURES['keys']['child-ksk-g1-revoked'] = {**FIXTURES['keys']['child-ksk-g1'], 'id': 'child-ksk-g1-revoked', 'flags': 385,
 'dnskeyRdataHex': revoked.to_wire().hex(), 'keyTag': dns.dnssec.key_id(revoked), 'text': revoked.to_text(), 'lineage': 'child-ksk-g1',
 'revokedBit': 128, 'generation': {'samePrivateMaterialAs': 'child-ksk-g1', 'privateCustodian': 'dnsSigner', 'privateIsNetworkRecord': False}}
# Birthday search over real P256 public keys, not invalid point-byte edits.
seen = {}
for scalar in range(1, 100000):
    public = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
    candidate = dns.dnssec.make_dnskey(public, 13, flags=256)
    tag = dns.dnssec.key_id(candidate)
    if tag in seen:
        key('collision-a', 'lab.example.',256,scalar=seen[tag])
        key('collision-b', 'lab.example.',256,scalar=scalar)
        FIXTURES['vectors']['keytag-collision'] = {'candidateIds':['collision-a','collision-b'], 'keyTag':tag,
          'candidateOrder':['collision-a','collision-b'], 'matchingSigner':'collision-b', 'expectedCandidateResults':[False,True],
          'source':'RFC4034 Appendix B; RFC4035 5.3.1', 'searchScalars':[seen[tag],scalar]}
        break
    seen[tag] = scalar
else:
    raise RuntimeError('No collision in declared search bound')
for zone, prefix in [('.', 'root'), ('example.','example'), ('lab.example.','child')]:
    rrset(prefix+'-dnskey-g1', zone, 'DNSKEY', [DNSKEY[prefix+'-ksk-g1'].to_text(), DNSKEY[prefix+'-zsk-g1'].to_text()])
    sign(prefix+'-dnskey-g1-by-ksk',prefix+'-dnskey-g1',prefix+'-ksk-g1')
for keyid in list(DNSKEY):
    if not keyid.startswith('collision-'):
        ds(keyid+'-sha256',keyid)
ds('child-ksk-g1-sha1-historical','child-ksk-g1',1)
for rrid, child, signer in [('root-example-ds','example-ksk-g1','root-zsk-g1'),('example-child-ds','child-ksk-g1','example-zsk-g1')]:
    d = FIXTURES['ds'][child+'-sha256']
    rrset(rrid,d['owner'],'DS',[d['text']])
    sign(rrid+'-signature',rrid,signer)
rrset('child-dnskey-rollover','lab.example.','DNSKEY',[DNSKEY[k].to_text() for k in ['child-ksk-g1','child-zsk-g1','child-ksk-g2','child-zsk-g2']])
for k in ['child-ksk-g1','child-ksk-g2']:
    sign('child-dnskey-rollover-by-'+k,'child-dnskey-rollover',k)
rrset('provider-shared-dnskey','lab.example.','DNSKEY',[DNSKEY[k].to_text() for k in ['child-ksk-g1','child-zsk-g1','provider-b-ksk-g1','provider-b-zsk-g1']])
for k in ['child-ksk-g1','provider-b-ksk-g1']:
    sign('provider-shared-dnskey-by-'+k,'provider-shared-dnskey',k)
for identity, owner, typ, records in [
 ('www-a','www.lab.example.','A',['192.0.2.80','192.0.2.81']),
 ('child-mx','lab.example.','MX',['20 MAIL2.lab.example.','10 Mail1.LAB.example.']),
 ('child-txt','lab.example.','TXT',['"OpaqueCase"']),
 ('child-ns','lab.example.','NS',['NS1.lab.example.','ns2.lab.example.']),
 ('child-soa','lab.example.','SOA',['ns1.lab.example. hostmaster.lab.example. 2026102301 3600 600 86400 300']),
 ('child-nsec','lab.example.','NSEC',['WWW.lab.example. NS SOA MX TXT RRSIG NSEC DNSKEY']),
 ('www-nsec','www.lab.example.','NSEC',['lab.example. A RRSIG NSEC']),
 ('wildcard-a','*.lab.example.','A',['192.0.2.90'])]:
    rrset(identity,owner,typ,records)
    sign(identity+'-signature',identity,'child-zsk-g1')
for identity,keyid in [('www-a-ed25519','child-ed25519-g1'),('www-a-collision','collision-b'),('www-a-provider-b','provider-b-zsk-g1'),('www-a-csk','child-csk-g1')]:
    sign(identity,'www-a',keyid)
rrset('revoked-dnskey','lab.example.','DNSKEY',[revoked.to_text(),DNSKEY['child-ksk-g2'].to_text()])
sign('revoked-dnskey-self-signature','revoked-dnskey','child-ksk-g1-revoked')
# Capture actual wire occurrence differences. Compression is in the permitted MX RDATA.
for variant,compress in [('compressed',True),('uncompressed',False)]:
    message = dns.message.make_response(dns.message.make_query('lab.example.','MX'))
    message.id=0
    if compress:
        # Pin the initially captured10-before20 occurrence; dnspython defaults to RR shuffling.
        source=RRSETS['child-mx']
        message.answer.append(dns.rrset.from_rdata_list(source.name,source.ttl,sorted(source,key=lambda r:r.to_digestable())))
        raw=message.to_wire(want_shuffle=False)
    else:
        raw=struct.pack('!HHHHHH',0,0x8100,0,2,0,0)+b''.join(RRSETS['child-mx'].name.to_wire()+struct.pack('!HHIH',15,1,3600,len(r.to_wire()))+r.to_wire() for r in RRSETS['child-mx'])
    FIXTURES['vectors']['mx-'+variant]={'wireHex':raw.hex(),'rrsetId':'child-mx','expectedSameSigningInputAs':'child-mx-signature'}
FIXTURES['vectors']['canonical-equivalence']={'rrsetId':'child-mx','signatureId':'child-mx-signature',
 'variant':{'owner':'LAB.EXAMPLE.','ttl':42,'type':'MX','records':['10 mail1.lab.EXAMPLE.','20 mail2.LAB.example.']},
 'expectedValid':True,'originalTtl':3600,'notes':'Order, name-field case and received TTL differ; opaque TXT and NSEC next-name are not folded.'}
FIXTURES['vectors']['mutations']=[
 {'id':'changed-a','rrsetId':'www-a','signatureId':'www-a-signature','owner':'www.lab.example.','type':'A','records':['192.0.2.82','192.0.2.81'],'expectedValid':False},
 {'id':'opaque-txt-case','rrsetId':'child-txt','signatureId':'child-txt-signature','owner':'lab.example.','type':'TXT','records':['"opaquecase"'],'expectedValid':False},
 {'id':'changed-owner','rrsetId':'www-a','signatureId':'www-a-signature','owner':'other.lab.example.','type':'A','records':['192.0.2.80','192.0.2.81'],'expectedValid':False},
 {'id':'nsec-next-name-case','rrsetId':'child-nsec','signatureId':'child-nsec-signature','owner':'lab.example.','type':'NSEC','records':['www.lab.example. NS SOA MX TXT RRSIG NSEC DNSKEY'],'expectedValid':False,'source':'RFC6840 5.1'}]
FIXTURES['vectors']['wildcard']={'signatureId':'wildcard-a-signature','sourceOwner':'*.lab.example.','expandedOwner':'shop.lab.example.','labels':2,'expectedCryptographicValid':True,'proofScope':'Signature check alone does not prove wildcard applicability; next-closer denial required separately.'}
# Literal RFC1982 comparisons, NOT generated by a prospective production evaluator.
FIXTURES['vectors']['signature-time']=[
 {'id':'before-inception','inception':INCEPTION,'expiration':EXPIRATION,'now':INCEPTION-1,'expected':'not-yet-valid'},
 {'id':'at-inception','inception':INCEPTION,'expiration':EXPIRATION,'now':INCEPTION,'expected':'valid'},
 {'id':'at-expiration','inception':INCEPTION,'expiration':EXPIRATION,'now':EXPIRATION,'expected':'valid'},
 {'id':'after-expiration','inception':INCEPTION,'expiration':EXPIRATION,'now':EXPIRATION+1,'expected':'expired'},
 {'id':'wrap-before-inception','inception':4294967280,'expiration':32,'now':4294967279,'expected':'not-yet-valid'},
 {'id':'wrap-at-inception','inception':4294967280,'expiration':32,'now':4294967280,'expected':'valid'},
 {'id':'wrap-before-zero','inception':4294967280,'expiration':32,'now':4294967295,'expected':'valid'},
 {'id':'wrap-zero','inception':4294967280,'expiration':32,'now':0,'expected':'valid'},
 {'id':'wrap-at-expiration','inception':4294967280,'expiration':32,'now':32,'expected':'valid'},
 {'id':'wrap-after-expiration','inception':4294967280,'expiration':32,'now':33,'expected':'expired'},
 {'id':'half-range-undefined','inception':0,'expiration':2147483648,'now':0,'expected':'undefined-serial-order'}]
sign('www-a-wrap','www-a','child-zsk-g1',4294967280,32)
for name in ['lab.example.','no.lab.example.','*.lab.example.','www.lab.example.','unsigned.lab.example.']:
    for iterations,salt in [(0,''),(1,''),(0,'aabbccdd'),(12,'aabbccdd')]:
        identity=name+':i'+str(iterations)+':salt'+(salt or 'empty')
        FIXTURES['nsec3'][identity]={'id':identity,'owner':name,'hashAlgorithm':1,'iterations':iterations,'saltHex':salt,
          'hashBase32hex':dns.dnssec.nsec3_hash(name,salt,iterations,1),'totalHashApplications':iterations+1,
          'profile':'modern default' if not iterations and not salt else 'comparison-only nondefault parameters'}
# Add signed NSEC3 chain for this explicit nameset; not the conventional NSEC baseline zone.
hashed=sorted((dns.dnssec.nsec3_hash(n,'',0,1),n) for n in ['lab.example.','www.lab.example.','*.lab.example.'])
for index,(h,name) in enumerate(hashed):
    next_hash=hashed[(index+1)%len(hashed)][0]
    bitmap='A RRSIG' if name!='lab.example.' else 'NS SOA MX TXT DNSKEY RRSIG'
    identity='nsec3-proof-'+str(index)
    rrset(identity,h+'.lab.example.','NSEC3',['1 0 0 - '+next_hash+' '+bitmap],300)
    sign(identity+'-signature',identity,'child-zsk-g1')
FIXTURES['vectors']['nsec3-proof-parameters']={'zone':'lab.example.','hashAlgorithm':1,'flags':0,'iterations':0,'saltHex':'','optOut':False,
 'rrsetIds':['nsec3-proof-0','nsec3-proof-1','nsec3-proof-2'],'separateZoneVariant':True}
for package,version in [('dnspython','2.8.0'),('cryptography','46.0.3'),('cffi','2.1.1'),('pycparser','3.12')]:
    assert importlib.metadata.version(package)==version
raw=(json.dumps(FIXTURES,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'dnssec-numeric-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable fixture differs; preserve it and use an explicitly new dataset ID instead of replacing expected bytes')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
 'counts':{name:len(FIXTURES[name]) for name in ['keys','rrsets','signatures','ds','nsec3','vectors']},
 'keyTags':{k:v['keyTag'] for k,v in FIXTURES['keys'].items()}},indent=2))
