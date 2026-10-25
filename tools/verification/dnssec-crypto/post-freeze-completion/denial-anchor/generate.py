#!/usr/bin/env python3
"""Positive NSEC3 reference bytes and an exact independent B refresh signature; public data only."""
import copy
import hashlib
import json
import pathlib
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
import generate as g
import dns.dnssec
import dns.name
OUT=g.OUT/'post-freeze-completion/denial-anchor'; OUT.mkdir(parents=True,exist_ok=True)
FREEZE_HASH='b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
if hashlib.sha256((g.ROOT/'docs/dnssec-expansion/contract-freeze.json').read_bytes()).hexdigest()!=FREEZE_HASH:
    raise RuntimeError('Freeze authority changed')
source_path=g.OUT/'post-freeze-contract-errata/publication-fixtures.json'; source=json.loads(source_path.read_text())
rrid='revoked-dnskey-a-b-z0'; original=source['rrsets'][rrid]
g.rrset(rrid,original['owner'],original['type'],original['records'],original['ttl'])
if g.FIXTURES['rrsets'][rrid]!=original:
    raise RuntimeError('Requested B refresh must bind exactly the unchanged complete source RRset')
sigid='revoked-dnskey-a-b-z0-by-b-refresh'
g.sign(sigid,rrid,'child-ksk-g2',1792972200,1796169600)
signature=g.FIXTURES['signatures'][sigid]
signature['rrsigRdataSha256']=hashlib.sha256(bytes.fromhex(signature['rrsigRdataHex'])).hexdigest()
name='other.lab.example.'; wire=dns.name.from_text(name).to_digestable()
if wire.hex()!='056f74686572036c6162076578616d706c6500':
    raise RuntimeError('Exact requested other owner wire differs')
hash_text=dns.dnssec.nsec3_hash(name,'',0,1)
initial=hashlib.sha1(wire).hexdigest()
vector={'id':'nsec3-other-lab-zero-empty','owner':name,'ownerWireHex':wire.hex(),'hashAlgorithm':1,'iterations':0,'saltHex':'','initialHashHex':initial,'finalHashHex':initial,'hashBase32hex':hash_text,'totalHashApplications':1}
key=g.FIXTURES['keys']['child-ksk-g2']
f={'schemaVersion':1,'kind':'dnssec-public-denial-anchor-completion-fixtures','postFreeze':True,'freezeAuthoritySha256':FREEZE_HASH,'baseClock':g.CLOCK,
 'nsec3':{vector['id']:vector},'nsec3ReferenceTuples':[vector],
 'signatures':{sigid:signature},'rrsetReferences':{rrid:{'path':str(source_path.relative_to(g.ROOT)),'sha256':hashlib.sha256(source_path.read_bytes()).hexdigest(),'id':rrid}},
 'keyReferences':{'child-ksk-g2':{field:key[field] for field in ['id','owner','flags','protocol','algorithm','keyTag','publicKeyHex','dnskeyRdataHex','publicKeyPem']}},
 'anchorRefresh':{'rrsetId':rrid,'bOrdinaryRefreshSignatureId':sigid,'aRevocationSelfSignatureId':'revoked-dnskey-a-b-z0-self-signature','aSelfSignatureSource':str(source_path.relative_to(g.ROOT)),'signatureRoles':'Separate actual A-revocation self-signature and already-Valid B ordinary refresh. No upper path or leaf query inferred.'},
 'worksheetHashClaim':{'claim':'K6RHCQQNQ2FD50JM9ONFV4B6SSC5M6NH','role':'Unauthoritative claim retained for comparison; actual vector generated independently from canonical owner bytes.'},
 'provenance':{'producer':'Pinned dnspython2.8.0 NSEC3 plus cryptography46.0.3 deterministic signing; Python3.14.4','referenceEnvironment':'docs/dnssec-expansion/numeric/runtime-and-licenses.json','sourceSections':['RFC5155 section5','RFC5011 sections2.1,2.2,2.3,2.4'],
 'sourceHashes':{name:hashlib.sha256((g.ROOT/name).read_bytes()).hexdigest() for name in ['docs/dnssec-expansion/numeric/sources/rfc5155.txt','docs/dnssec-expansion/numeric/sources/rfc5011.txt']},'newDependencySetupExecuted':False},
 'scope':'Public numerical reference tuples only; no private key bytes or expected application/hold-down acceptance. B refresh signature is an actual fixed tuple, not manufactured hourly observations.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Existing denial/anchor completion fixture differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'nsec3':vector,'signatureId':sigid,'signature':{field:signature[field] for field in ['rrsetId','keyId','keyTag','signer','originalTtl','inception','expiration','signingInputSha256','rrsigRdataSha256']}},indent=2))
