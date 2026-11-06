
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[2]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Independent bytes + cryptography + OpenSSL, cross-checked with pinned DNS library."""
import hashlib,json,pathlib,sys,tempfile,subprocess,struct
ROOT = ROOT; TOOLS=CURRENT_TOOLS; sys.path.insert(0,str(TOOLS)); import reference_bytes as ref
import dns.dnssec,dns.rrset,dns.rdata,dns.name
N=output_root(); OUT=N/'post-freeze-completion/parent-signing'; raw=(OUT/'parent-signing-fixtures.json').read_bytes(); D=json.loads(raw); B=json.loads((N/'dnssec-numeric-fixtures.json').read_text()); P=json.loads((N/'post-freeze-contract-errata/publication-fixtures.json').read_text()); keys={**B['keys'],**P['keys'],**D['keys']}; rrsets={**B['rrsets'],**P['rrsets'],**D['rrsets']}; signatures={**B['signatures'],**P['signatures'],**D['signatures']}; observations=[]
assert hashlib.sha256(raw).hexdigest() == generated_hash('post-freeze-completion/parent-signing/parent-signing-fixtures.json')
def verify(sid,scratch):
 s=signatures[sid]; r=rrsets[s['rrsetId']]; k=keys[s['keyId']]; canonical=ref.canonical(r,s); assert canonical.hex()==s['signingInputHex']; assert hashlib.sha256(canonical).hexdigest()==s['signingInputSha256']; assert sorted(ref.rdata(r['type'],x).hex() for x in r['records'])==r['canonicalRdataHex']; assert ref.key_tag(bytes.fromhex(k['dnskeyRdataHex']))==s['keyTag']; assert ref.valid(k,bytes.fromhex(s['signatureHex']),canonical); op=ref.openssl_check(sid,k,bytes.fromhex(s['signatureHex']),canonical,scratch)
 rr=dns.rrset.from_text(r['owner'],r['ttl'],'IN',r['type'],*r['records']); sig=dns.rdata.from_text(1,46,s['rrsigText']); assert sig.to_wire().hex()==s['rrsigRdataHex']; assert dns.dnssec._make_rrsig_signature_data(rr,sig)==canonical
 dk=dns.rrset.from_text(k['owner'],3600,'IN','DNSKEY',k['text']); sr=dns.rrset.from_rdata(r['owner'],r['ttl'],sig); dns.dnssec.validate(rr,sr,{dns.name.from_text(k['owner']):dk},now=D['baseClock'],policy=dns.dnssec.allow_all_policy)
 observations.append({'id':sid,'signingInputSha256':hashlib.sha256(canonical).hexdigest(),'rrsetMembers':len(r['records']),'rrsetTtl':r['ttl'],'originalTtl':s['originalTtl'],'keyId':s['keyId'],'openssl':op,'independentBytes':'equal','cryptography':'verified','dnspython':'verified'})
with tempfile.TemporaryDirectory(prefix='dnssec-parent-public-',dir=OUT) as tmp:
 scratch=pathlib.Path(tmp)
 for sid in D['signatures']: verify(sid,scratch)
 for suffix,path in D['providerAncestorPaths'].items():
  trusted={'root-ksk-g1'}
  for step in path['steps']:
   s=signatures[step['signatureId']]; assert s['keyId'] in trusted; verify(s['id'],scratch); rr=rrsets[step['rrsetId']]
   if step['role']=='dnskey':
    for kid,k in keys.items():
     if k['owner']==rr['owner'] and k['dnskeyRdataHex'] in rr['canonicalRdataHex']: trusted.add(kid)
   else:
    for kid in step['matchedChildKeyIds']:
     k=keys[kid]; digest=hashlib.sha256(ref.name_wire(k['owner'])+bytes.fromhex(k['dnskeyRdataHex'])).digest(); ds=struct.pack('!HBB',k['keyTag'],k['algorithm'],2)+digest; assert ds.hex() in rr['canonicalRdataHex']; trusted.add(kid)
  terminal=signatures[path['terminalSignatureId']]; assert terminal['keyId'] in trusted
  proof=rrsets[path['terminalProofId']]; fields=proof['records'][0].split(); assert 'NS' in fields and 'SOA' not in fields and 'DS' not in fields; assert proof['owner']=='provider.example.'+suffix+'.'; assert fields[0]=='zzz.example.'+suffix+'.'
 for refobj in D['references'].values():
  source=json.loads((ROOT/refobj['path']).read_text()); sid=refobj['signaturePointer'].split('/')[-1]; verify(sid,scratch)
for kid,k in D['keys'].items():
 src=k['publicRdataSource']; original=json.loads((ROOT/src['path']).read_text())['keys'][kid]; assert k['dnskeyRdataHex']==original['dnskeyRdataHex']
for d in D['ds'].values():
 k=keys[d['keyId']]; inp=ref.name_wire(k['owner'])+bytes.fromhex(k['dnskeyRdataHex']); assert inp.hex()==d['digestInputHex']; assert hashlib.sha384(inp).hexdigest()==d['digestHex']
expected={
 'child-cds-newk-only':[B['ds']['child-ksk-g2-sha256']['text']],
 'child-cdnskey-newk-only':[keys['child-ksk-g2']['text']],
 'child-cds-mixed-ds4':[B['ds']['child-ksk-g1-sha256']['text'],B['ds']['child-ksk-g2-sha256']['text'],D['ds']['child-ksk-g1-sha384']['text']],
 'child-cds-malformed-delete-plus-newk':['0 0 0 00',B['ds']['child-ksk-g2-sha256']['text']],
 'child-cdnskey-malformed-delete':['1 3 0 AA=='],
 'child-cds-delete-by-newk':['0 0 0 00'],'child-cdnskey-delete-by-newk':['0 3 0 AA=='],
 'parent-ds-historical-sha1':[B['ds']['child-ksk-g1-sha1-historical']['text']],
 'parent-ds-modern-obsolete':[B['ds']['child-ksk-g1-sha256']['text'],P['rrsets']['parent-ds-obsolete-alg5']['records'][0],P['rrsets']['parent-ds-obsolete-alg12-digest3']['records'][0]],
 'provider-b-cds-intent':[B['ds']['provider-b-ksk-g1-sha256']['text']], 'provider-b-cdnskey-intent':[keys['provider-b-ksk-g1']['text']]}
for rid,records in expected.items(): assert set(rrsets[rid]['records'])==set(records)
for d in D['signalDigestReferenceTuples']:
 k=keys[d['keyId']]; inp=ref.name_wire(k['owner'])+bytes.fromhex(k['dnskeyRdataHex']); digest=hashlib.sha256(inp).digest(); assert inp.hex()==d['digestInputHex']; assert digest.hex()==d['digestHex']; assert (struct.pack('!HBB',k['keyTag'],k['algorithm'],2)+digest).hex()==d['dsRdataHex']
for sid,s in D['signatures'].items():
 assert (s['inception'],s['expiration'])==(1792713000,1792717200)
 rid=s['rrsetId']; expected_key=('provider-b-ksk-g1' if rid.startswith('provider-b-') else 'signal-example-'+rid.split('-')[1]+'-zsk-g1' if rid.startswith('provider-') else 'example-zsk-g1' if rid.startswith(('parent-','remote-')) else 'child-ksk-g2' if rid in ['child-cds-delete-by-newk','child-cdnskey-delete-by-newk'] else 'child-ksk-g1'); assert s['keyId']==expected_key
original_proof=json.loads((N/'resolution-profile-fixtures.json').read_text())['rrsets']['denial-parent-unsigned-lab']
assert rrsets['remote-old-nods-ttl3600']['owner']==original_proof['owner'] and rrsets['remote-old-nods-ttl3600']['records']==original_proof['records']
for variant,record in [('scheme0','CDS 0 53 notify.example.'),('scheme99','CDS 99 53 notify.example.'),('port0','CDS 1 0 notify.example.'),('missing-target','CDS 1 53 missing.example.')]: assert rrsets['parent-dsync-'+variant]['records']==[record]
f=D['remoteReceiptFacts']; soa=rrsets[f['soaId']]; proof=rrsets[f['proofId']]; minimum=int(soa['records'][0].split()[-1]); assert min(soa['ttl'],minimum,proof['ttl'],signatures[f['proofId']+'-signature']['originalTtl'],f['signatureExpiration']-f['receiptClock'])==3600; assert f['expiryClock']==f['receiptClock']+3600; assert f['remainingAtInspection']==f['expiryClock']-f['inspectionClock']==2999
report={'schemaVersion':1,'postFreeze':True,'freezeAuthoritySha256':D['freezeAuthoritySha256'],'baseClock':D['baseClock'],'dataset':{'path':reference_path((OUT/'parent-signing-fixtures.json')),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},'signatureObservations':observations,'ancestorPathCount':2,'exactMembershipIds':list(expected),'digestFacts':D['ds'],'remoteReceiptFacts':f,'opensslVersion':subprocess.run(['openssl','version'],capture_output=True,text=True,check=True).stdout.strip(),'sourceReferences':D['provenance']['sources'],'codeReferences':[{'path':reference_path(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in [pathlib.Path(__file__),pathlib.Path(__file__).with_name('produce.py'),TOOLS/'reference_bytes.py']],'limits':D['limits']}
report['signalDigestReferenceTuples']=D['signalDigestReferenceTuples']
report_raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode(); (OUT/'parent-signing-verification.json').write_bytes(report_raw); print(json.dumps({'reportSha256':hashlib.sha256(report_raw).hexdigest(),'bytes':len(report_raw),'signatureObservations':len(observations),'ancestorPaths':2},sort_keys=True))
