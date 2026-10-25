#!/usr/bin/env python3
"""Independent bytes and actual library observations for new resolution variants only."""
import hashlib
import inspect
import json
import pathlib
import struct
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'resolution-profile-fixtures.json').read_bytes()
f=json.loads(raw)
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
keys={**base['keys'],**f['keys']}; rrsets={**base['rrsets'],**f['rrsets']}; sigs={**base['signatures'],**f['signatures']}
v.check('resolution-profiles-pinned-sha256',hashlib.sha256(raw).hexdigest(),'4001c10f0f19a52d69d7d07198874ea4d96a448e75ac4f35d0bb7f97f282973d')
v.check('resolution-baseline-binding',f['baselineSha256'],hashlib.sha256((v.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
# Local support for newly supplied NSEC3PARAM; the sealed primitive module is unchanged.
def rdata(typ,text):
    if typ!='NSEC3PARAM':
        return v.rdata(typ,text)
    p=text.split(); salt=b'' if p[3]=='-' else bytes.fromhex(p[3])
    return struct.pack('!BBHB',int(p[0]),int(p[1]),int(p[2]),len(salt))+salt

def canonical(rr,sig):
    if rr['type']!='NSEC3PARAM':
        return v.canonical(rr,sig)
    prefix=struct.pack('!HBBIIIH',sig['typeCovered'],sig['algorithm'],sig['labels'],sig['originalTtl'],sig['expiration'],sig['inception'],sig['keyTag'])+v.name_wire(sig['signer'])
    return prefix+b''.join(v.name_wire(rr['owner'])+struct.pack('!HHIH',51,1,sig['originalTtl'],len(data))+data for data in sorted(rdata('NSEC3PARAM',r) for r in rr['records']))

def library_check(sig,rr,dnskeys):
    try:
        dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text('lab.example.'):dnskeys} if sig['signer']=='lab.example.' else {dns.name.from_text(sig['signer']):dnskeys},now=f['baseClock'])
        return {'valid':True}
    except Exception as error:
        return {'valid':False,'exceptionClass':type(error).__name__,'message':str(error)}
rows=[]
for identity,key in f['keys'].items():
    v.check(identity+':rdata',rdata('DNSKEY',key['text']).hex(),key['dnskeyRdataHex'])
    v.check(identity+':tag',v.key_tag(rdata('DNSKEY',key['text'])),key['keyTag'])
    v.check(identity+':same-public-lineage',key['publicKeyHex'],base['keys']['child-zsk-g1']['publicKeyHex'])
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    for identity,sig in f['signatures'].items():
        rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]; data=canonical(rr,sig)
        v.check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        candidate_set=dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])
        observed=library_check(sig,rr,candidate_set)
        expected=not identity.endswith('-leaf-signature')
        v.check(identity+':library-dnssec-eligibility',observed['valid'],expected)
        rows.append({'id':identity+':library','observation':observed,'expectedEligible':expected})
for identity,rr in f['rrsets'].items():
    v.check(identity+':canonical-rdata',sorted(rdata(rr['type'],text).hex() for text in rr['records']),rr['canonicalRdataHex'])
# Ensure the mutated/missing candidate sets first authenticate under the existing valid KSK.
for profile_id in ['protocol2-candidate','zoneflag-clear-candidate','missing-candidate']:
    p=f['profiles'][profile_id]
    dnskey_rr=rrsets[p['dnskeyRrsetId']]
    ksk=keys['child-ksk-g1']
    observed=library_check(sigs[p['dnskeySignatureId']],dnskey_rr,dns.rrset.from_text('lab.example.',3600,'IN','DNSKEY',ksk['text']))
    v.check(profile_id+':dnskey-set-authenticated-before-candidate-check',observed['valid'],True)
    leaf=sigs[p['leafSignatureId']]
    candidate_set=dns.rrset.from_text('lab.example.',3600,'IN','DNSKEY',*dnskey_rr['records'])
    candidates=dns.dnssec._find_candidate_keys({dns.name.from_text('lab.example.'):candidate_set},dns.rdata.from_text('IN','RRSIG',leaf['rrsigText']))
    v.check(profile_id+':no-eligible-candidate',len(candidates),0)
    observed=library_check(leaf,rrsets[leaf['rrsetId']],candidate_set)
    v.check(profile_id+':leaf-not-accepted-by-library',observed['valid'],False)
    rows.append({'id':profile_id,'authenticatedDnskeySignatureId':p['dnskeySignatureId'],'leafSignatureId':p['leafSignatureId'],'eligibleCandidateCount':len(candidates),'observation':observed,'stage':'Candidate protocol/ZoneFlag/presence prerequisite, not corrupted DNSKEY-set RRSIG.'})
# Independent canonical-name and hash interval mathematics; no application verdict generator.
def order(name):
    return tuple(reversed(name.lower().rstrip('.').encode().split(b'.')))
def covers(owner,next_name,query):
    a,b,q=order(owner),order(next_name),order(query)
    return a<q<b if a<b else (q>a or q<b)
for identity,query in [('denial-a-to-www','no.lab.example.'),('denial-a-to-www','foo.lab.example.'),('denial-apex-to-a','*.lab.example.'),('denial-a-to-x-branch','branch.lab.example.')]:
    rr=rrsets[identity]
    v.check(identity+':covers-'+query,covers(rr['owner'],rr['records'][0].split()[0],query),True)
parent=rrsets['denial-parent-unsigned-lab']
v.check('parent-nsec-not-child-signer',sigs['denial-parent-unsigned-lab-signature']['signer'],'example.')
v.check('parent-nsec-no-soa-or-ds',rdata('NSEC',parent['records'][0]),v.name_wire('next.example.')+v.bitmap(['NS','RRSIG','NSEC']))
chain_sets=[('nsec3-no-wildcard',f['profiles']['nsec3-no-wildcard'],f['profiles']['nsec3-no-wildcard']['chain']),('nsec3-optout',{'iterations':0,'saltHex':''},f['profiles']['nsec3-optout-unsigned-delegation']['chain'])]
chain_sets += [(label,profile,profile['chain']) for label,profile in f['profiles']['nsec3-parameter-comparisons'].items()]
for label,params,chain in chain_sets:
    for index,item in enumerate(chain):
        hashed=v.nsec3(item['originalOwner'],params['iterations'],bytes.fromhex(params['saltHex']))['hashBase32hex']
        v.check(label+':hash-'+item['originalOwner'],hashed,item['ownerHash'])
        v.check(label+':next-link-'+str(index),item['nextHash'],chain[(index+1)%len(chain)]['ownerHash'])
    if label=='nsec3-no-wildcard':
        for query in ['no.lab.example.','*.lab.example.']:
            target=v.nsec3(query,0,b'')['hashBase32hex']
            matched=[i for i in chain if i['ownerHash']==target]
            covering=[i for i in chain if ((i['ownerHash']<target<i['nextHash']) if i['ownerHash']<i['nextHash'] else (target>i['ownerHash'] or target<i['nextHash']))]
            v.check(label+':not-matching-'+query,len(matched),0)
            v.check(label+':single-covering-'+query,len(covering),1)
            rows.append({'id':label+':interval','query':query,'hash':target,'coveringRrsetId':covering[0]['rrsetId'],'matching':False})
opt=f['profiles']['nsec3-optout-unsigned-delegation']
target=v.nsec3(opt['omittedDelegation'],0,b'')['hashBase32hex']
v.check('optout-unsigned-hash',target,opt['omittedHash'])
flagged=[i for i in opt['chain'] if i['flags']==1]
v.check('optout-single-flagged-covering-interval',len(flagged),1)
v.check('optout-flagged-owner-covers-unsigned',flagged[0]['coversUnsignedHash'],True)
for label,p in f['profiles']['nsec3-parameter-comparisons'].items():
    for item in p['chain']:
        modern=v.nsec3(item['originalOwner'],0,b'')['hashBase32hex']
        v.check(label+':distinct-modern-input-'+item['originalOwner'],item['ownerHash']!=modern,True)
# Unknown DS algorithm/digest values remain actual signed opaque records, not generated hash claims.
v.check('unsupported-algorithm-id',int(rrsets['parent-ds-unsupported-alg250']['records'][0].split()[1]),250)
v.check('unsupported-digest-id',int(rrsets['parent-ds-unsupported-digest250']['records'][0].split()[2]),250)
source=inspect.getsource(dns.dnssec._find_candidate_keys)
report={'schemaVersion':1,'kind':'dnssec-independent-resolution-profile-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,'observations':rows,
 'candidateFilterSource':source,'candidateFilterSourceSha256':hashlib.sha256(source.encode()).hexdigest(),
 'limits':['Denial RRset signatures and explicit interval/hash mathematics verified; application security-status/policy remains worksheet-owned','Protocol2 and ZoneFlagclear leaf cryptographic signatures pass, DNSSEC candidate eligibility fails as intended','Unsigned delegation NS/glue have no signatures','Unknown DS digest250 is opaque fixed data, not a fabricated computed digest','Separate conventional/NSEC3/private variants must not be merged into one contradictory zone','No production evaluator or live interoperability execution']}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'resolution-profile-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable resolution verification differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
