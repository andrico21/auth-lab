
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Actual signed conventional/hashed denial variants and authenticated key-prerequisite inputs."""
import copy
import hashlib
import json
import dns.dnssec
import generate as g
base=copy.deepcopy(g.FIXTURES)
for identity,owner,typ,records,keyid in [
 ('denial-apex-to-a','lab.example.','NSEC',['a.lab.example. NS SOA RRSIG NSEC DNSKEY'],'child-zsk-g1'),
 ('denial-a-to-www','a.lab.example.','NSEC',['www.lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('denial-www-to-apex','www.lab.example.','NSEC',['lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('denial-apex-to-wildcard','lab.example.','NSEC',['*.lab.example. NS SOA RRSIG NSEC DNSKEY'],'child-zsk-g1'),
 ('denial-wildcard-to-a','*.lab.example.','NSEC',['a.lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('denial-a-to-x-branch','a.lab.example.','NSEC',['x.branch.lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('denial-x-branch-to-www','x.branch.lab.example.','NSEC',['www.lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('denial-a-address','a.lab.example.','A',['192.0.2.1'],'child-zsk-g1'),
 ('denial-x-branch-address','x.branch.lab.example.','A',['192.0.2.22'],'child-zsk-g1'),
 ('denial-z-address','z.lab.example.','A',['192.0.2.250'],'child-zsk-g1'),
 ('denial-parent-unsigned-lab','lab.example.','NSEC',['next.example. NS RRSIG NSEC'],'example-zsk-g1'),
 ('denial-nsec3-zero-param','lab.example.','NSEC3PARAM',['1 0 0 -'],'child-zsk-g1')]:
    g.rrset(identity,owner,typ,records,300)
    g.sign(identity+'-signature',identity,keyid)
# Deliberately unsigned parent-side delegation NS and glue; neither is secured by proximity.
g.rrset('denial-unsigned-delegation-ns','unsigned.lab.example.','NS',['ns.unsigned.lab.example.'],300)
g.rrset('denial-unsigned-delegation-glue','ns.unsigned.lab.example.','A',['192.0.2.200'],300)
names=['lab.example.','a.lab.example.','www.lab.example.','z.lab.example.']
hashed=sorted((dns.dnssec.nsec3_hash(name,'',0,1),name) for name in names)
unsigned_hash=dns.dnssec.nsec3_hash('unsigned.lab.example.','',0,1)
chains={}
for variant in ['no-wildcard','optout']:
    chain=[]
    for index,(ownerhash,name) in enumerate(hashed):
        nexthash=hashed[(index+1)%len(hashed)][0]
        covers_unsigned=(ownerhash<unsigned_hash<nexthash) if ownerhash<nexthash else (unsigned_hash>ownerhash or unsigned_hash<nexthash)
        flags=1 if variant=='optout' and covers_unsigned else 0
        bitmap='NS SOA DNSKEY RRSIG NSEC3PARAM' if name=='lab.example.' else 'A RRSIG'
        identity='denial-nsec3-'+variant+'-'+str(index)
        g.rrset(identity,ownerhash+'.lab.example.','NSEC3',['1 '+str(flags)+' 0 - '+nexthash+' '+bitmap],300)
        g.sign(identity+'-signature',identity,'child-zsk-g1')
        chain.append({'rrsetId':identity,'originalOwner':name,'ownerHash':ownerhash,'nextHash':nexthash,'flags':flags,'coversUnsignedHash':covers_unsigned})
    chains[variant]=chain
comparison_chains={}
for label,iterations,salt in [('iteration1',1,''),('salt-aa',0,'aa')]:
    ordered=sorted((dns.dnssec.nsec3_hash(name,salt,iterations,1),name) for name in names)
    param_id='denial-nsec3-'+label+'-param'
    g.rrset(param_id,'lab.example.','NSEC3PARAM',['1 0 '+str(iterations)+' '+(salt or '-')],300)
    g.sign(param_id+'-signature',param_id,'child-zsk-g1')
    chain=[]
    for index,(ownerhash,name) in enumerate(ordered):
        nexthash=ordered[(index+1)%len(ordered)][0]
        identity='denial-nsec3-'+label+'-'+str(index)
        bitmap='NS SOA DNSKEY RRSIG NSEC3PARAM' if name=='lab.example.' else 'A RRSIG'
        g.rrset(identity,ownerhash+'.lab.example.','NSEC3',['1 0 '+str(iterations)+' '+(salt or '-')+' '+nexthash+' '+bitmap],300)
        g.sign(identity+'-signature',identity,'child-zsk-g1')
        chain.append({'rrsetId':identity,'originalOwner':name,'ownerHash':ownerhash,'nextHash':nexthash,'flags':0})
    comparison_chains[label]={'hashAlgorithm':1,'iterations':iterations,'saltHex':salt,'chain':chain,'nsec3paramRrsetId':param_id}
for identity,algorithm,digest_type in [('parent-ds-unsupported-alg250',250,2),('parent-ds-unsupported-digest250',13,250)]:
    # Opaque synthetic unsupported fields, not a claim that an unknown digest was computed.
    g.rrset(identity,'lab.example.','DS',[str(base['keys']['child-ksk-g1']['keyTag'])+' '+str(algorithm)+' '+str(digest_type)+' '+'00'*32])
    g.sign(identity+'-signature',identity,'example-zsk-g1')
# DNSKEY candidate metadata variants are authenticated by a genuinely new KSK signature.
# Their leaf RRSIGs bind the recalculated candidate tag and unchanged underlying Z private key.
for identity,protocol,flags in [('child-zsk-protocol2',2,256),('child-zsk-zoneflag-clear',3,1)]:
    candidate=g.DNSKEY['child-zsk-g1'].replace(protocol=protocol,flags=flags)
    g.DNSKEY[identity]=candidate
    g.PRIVATE[identity]=g.PRIVATE['child-zsk-g1']
    g.FIXTURES['keys'][identity]={**base['keys']['child-zsk-g1'],'id':identity,'protocol':protocol,'flags':flags,
      'dnskeyRdataHex':candidate.to_wire().hex(),'keyTag':dns.dnssec.key_id(candidate),'text':candidate.to_text(),
      'lineage':'child-zsk-g1','purpose':'Deliberately ineligible DNSSEC candidate, not a conformant signing-profile key.',
      'generation':{'samePrivateMaterialAs':'child-zsk-g1','privateCustodian':'dnsSigner','privateIsNetworkRecord':False}}
    g.rrset(identity+'-dnskey','lab.example.','DNSKEY',[g.DNSKEY['child-ksk-g1'].to_text(),candidate.to_text()])
    g.sign(identity+'-dnskey-signature',identity+'-dnskey','child-ksk-g1')
    g.sign(identity+'-leaf-signature','www-a',identity)
g.rrset('child-dnskey-zsk-missing','lab.example.','DNSKEY',[g.DNSKEY['child-ksk-g1'].to_text()])
g.sign('child-dnskey-zsk-missing-signature','child-dnskey-zsk-missing','child-ksk-g1')
f={'schemaVersion':1,'kind':'dnssec-independent-resolution-profile-fixtures','baseClock':g.CLOCK,
 'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'keys':{k:v for k,v in g.FIXTURES['keys'].items() if k not in base['keys']},
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},
 'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'profiles':{
 'conventional-no-wildcard':{'existingNames':['lab.example.','a.lab.example.','www.lab.example.'],'absentNames':['*.lab.example.','no.lab.example.','foo.lab.example.'],'nsecRrsetIds':['denial-apex-to-a','denial-a-to-www','denial-www-to-apex'],'apexTypes':['NS','SOA','DNSKEY','RRSIG','NSEC'],'commonSignedRrsets':['child-ns','child-soa','child-dnskey-g1','denial-a-address','www-a']},
 'conventional-wildcard':{'existingNames':['lab.example.','*.lab.example.','a.lab.example.','www.lab.example.'],'nsecRrsetIds':['denial-apex-to-wildcard','denial-wildcard-to-a','denial-a-to-www','denial-www-to-apex'],'wildcardRrsetId':'wildcard-a','wildcardSignatureId':'wildcard-a-signature'},
 'conventional-ent':{'existingDataNames':['lab.example.','a.lab.example.','x.branch.lab.example.','www.lab.example.'],'emptyNonTerminal':'branch.lab.example.','nsecRrsetIds':['denial-apex-to-a','denial-a-to-x-branch','denial-x-branch-to-www','denial-www-to-apex'],'descendantRrsetId':'denial-x-branch-address'},
 'parent-unsigned-delegation':{'nsecRrsetId':'denial-parent-unsigned-lab','signerKeyId':'example-zsk-g1','parentZone':'example.','childZone':'lab.example.','dsAbsentInThisVariant':True,'wrongZoneReuseMustNotProveChildDenial':True},
 'nsec3-no-wildcard':{'zone':'lab.example.','originalNames':names,'wildcardAbsent':True,'hashAlgorithm':1,'iterations':0,'saltHex':'','chain':chains['no-wildcard'],'nsec3paramRrsetId':'denial-nsec3-zero-param'},
 'nsec3-optout-unsigned-delegation':{'zone':'lab.example.','originalSignedNames':names,'omittedDelegation':'unsigned.lab.example.','omittedHash':unsigned_hash,'chain':chains['optout'],'unsignedNsRrsetId':'denial-unsigned-delegation-ns','unsignedGlueRrsetId':'denial-unsigned-delegation-glue'},
 'nsec3-parameter-comparisons':comparison_chains,
 'unsupported-parent-ds':{'rrsetIds':['parent-ds-unsupported-alg250','parent-ds-unsupported-digest250'],'signerKeyId':'example-zsk-g1','opaqueDigestHex':'00'*32,'unknownDigestHasComputedMeaning':False},
 'protocol2-candidate':{'dnskeyRrsetId':'child-zsk-protocol2-dnskey','dnskeySignatureId':'child-zsk-protocol2-dnskey-signature','candidateKeyId':'child-zsk-protocol2','leafSignatureId':'child-zsk-protocol2-leaf-signature','expectedLeafCryptographicValid':True,'expectedDnssecCandidateEligible':False,'failurePrerequisite':'protocol-not3'},
 'zoneflag-clear-candidate':{'dnskeyRrsetId':'child-zsk-zoneflag-clear-dnskey','dnskeySignatureId':'child-zsk-zoneflag-clear-dnskey-signature','candidateKeyId':'child-zsk-zoneflag-clear','leafSignatureId':'child-zsk-zoneflag-clear-leaf-signature','expectedLeafCryptographicValid':True,'expectedDnssecCandidateEligible':False,'failurePrerequisite':'zone-flag-clear'},
 'missing-candidate':{'dnskeyRrsetId':'child-dnskey-zsk-missing','dnskeySignatureId':'child-dnskey-zsk-missing-signature','absentKeyId':'child-zsk-g1','leafSignatureId':'www-a-signature'}},
 'queriedNameHashes':{name:dns.dnssec.nsec3_hash(name,'',0,1) for name in ['lab.example.','*.lab.example.','no.lab.example.','foo.lab.example.','unsigned.lab.example.']},
 'scope':'Separate explicit zone variants, not mutations of a shared published zone. Conventional no-wildcard apex omits MX/TXT because that variant has none. Denial RRset byte validity is distinct from complete validator proof/policy decisions. NSEC3PARAM is authority coordination, not replacement for actual proof parameters. Candidate leaf signatures are numerically valid but candidate DNSKEY protocol/flags deliberately fail DNSSEC eligibility.'}
raw=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'resolution-profile-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable resolution profiles differ')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'counts':{k:len(f[k]) for k in ['keys','rrsets','signatures']},'keyTags':{k:v['keyTag'] for k,v in f['keys'].items()}},indent=2))
