#!/usr/bin/env python3
"""Validate every consumed DNSKEY/DS/answer byte on each literal future-clock path."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'complete-path-fixtures.json').read_bytes()
f=json.loads(raw)
v.check('complete-path-pinned-sha256',hashlib.sha256(raw).hexdigest(),'a94a106399372c65a7e1e3f2e6a8b44738e13c8ee7c72c5ce96cdf7ba0e02f7f')
keys={}; rrsets={}; signatures={}
for name,expected_hash in f['sourceFixtureSha256'].items():
    data=(v.OUT/name).read_bytes()
    v.check(name+':unchanged-reference',hashlib.sha256(data).hexdigest(),expected_hash)
    source=json.loads(data)
    keys.update(source.get('keys',{})); rrsets.update(source.get('rrsets',{})); signatures.update(source.get('signatures',{}))
rrsets.update(f['rrsets']); signatures.update(f['signatures'])
rows=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    for identity,sig in f['signatures'].items():
        rr=rrsets[sig['rrsetId']]; key=keys[sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':independent-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':crypto',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
path_observations=[]
for path_id,path in f['paths'].items():
    for point in path['observations']:
        now=point['now']
        trusted={path['anchorKeyId']}
        observed=[]
        for position,step in enumerate(path['steps']):
            sig=signatures[step['signatureId']]; rr=rrsets[step['rrsetId']]; key=keys[sig['keyId']]
            check_id=path_id+':'+str(point['offset'])+':'+str(position)
            v.check(check_id+':bound-rrset',sig['rrsetId'],step['rrsetId'])
            v.check(check_id+':authenticated-signer',sig['keyId'] in trusted,True)
            v.check(check_id+':current-signed-window',v.time_state(now,sig['inception'],sig['expiration']),'valid')
            data=v.canonical(rr,sig)
            v.check(check_id+':independent-canonical',data.hex(),sig['signingInputHex'])
            v.check(check_id+':cryptographic',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
            dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',sig['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
            if step['role']=='dnskey':
                v.check(check_id+':dnskey-type',rr['type'],'DNSKEY')
                records={v.rdata('DNSKEY',record) for record in rr['records']}
                for identity,candidate in keys.items():
                    if candidate['owner']==rr['owner'] and v.rdata('DNSKEY',candidate['text']) in records:
                        trusted.add(identity)
            elif step['role']=='ds':
                v.check(check_id+':ds-type',rr['type'],'DS')
                records={v.rdata('DS',record) for record in rr['records']}
                for identity in step['matchedChildKeyIds']:
                    child=keys[identity]
                    digest=hashlib.sha256(v.name_wire(child['owner'])+v.rdata('DNSKEY',child['text'])).hexdigest()
                    expected=v.rdata('DS',str(child['keyTag'])+' '+str(child['algorithm'])+' 2 '+digest)
                    v.check(check_id+':ds-owner-'+identity,rr['owner'],child['owner'])
                    v.check(check_id+':ds-matches-key-'+identity,expected in records,True)
                    trusted.add(identity)
            elif step['role']=='answer':
                v.check(check_id+':answer-type',rr['type'],'A')
                v.check(check_id+':answer-records',rr['records'],path['expectedAddressRecords'])
            else:
                raise ValueError('Unknown literal reference-path role')
            observed.append({'role':step['role'],'rrsetId':rr['id'],'signatureId':sig['id'],'keyId':sig['keyId'],'inception':sig['inception'],'expiration':sig['expiration'],'signedOriginalTtl':sig['originalTtl'],'cryptographicValid':True,'libraryValidAt':now})
        path_observations.append({'pathId':path_id,'anchorKeyId':path['anchorKeyId'],'offset':point['offset'],'now':now,'pathValid':True,'steps':observed})
# Preserve the narrow expiry profile, rather than silently stretching its signed metadata.
short=signatures['www-a-signature']; rr=rrsets[short['rrsetId']]; key=keys[short['keyId']]
for day in [35,90]:
    now=f['baseClock']+day*86400
    try:
        dns.dnssec.validate_rrsig(dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records']),dns.rdata.from_text('IN','RRSIG',short['rrsigText']),{dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])},now=now)
        result={'exceptionClass':None}
    except Exception as error:
        result={'exceptionClass':type(error).__name__,'message':str(error)}
    v.check('short-base-still-expired-day'+str(day),result,{'exceptionClass':'ValidationFailure','message':'expired'})
    rows.append({'id':'short-base-expiry-preserved','day':day,'observation':result})
report={'schemaVersion':1,'kind':'dnssec-independent-complete-lifecycle-path-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass','checks':len(v.RESULTS),'results':v.RESULTS,
 'newSignatureObservations':rows,'completePathObservations':path_observations,'completePathCount':len(f['paths']),'clockedPathObservations':len(path_observations),
 'scope':'Every consumed chain and leaf RRset was actually checked at the literal current clock with independent canonical/crypto verification and pinned DNS library. Root vs local anchor setups explicit. No cache reuse or RFC5011 eligibility conclusion is inferred from signature validity. Long lifetimes are synthetic choices, not recommendations.'}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'complete-path-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Immutable complete-path report differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'completePaths':len(f['paths']),'clockedPathObservations':len(path_observations),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
