
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[2]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Independent verification-only public parent/signing completion producer."""
import hashlib,json,pathlib,sys,platform,importlib.metadata
import dns.dnssec,dns.name,dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
ROOT = ROOT
N=output_root(); OUT=N/'post-freeze-completion/parent-signing'; OUT.mkdir(parents=True,exist_ok=True)
B=json.loads((N/'dnssec-numeric-fixtures.json').read_text()); P=json.loads((N/'post-freeze-contract-errata/publication-fixtures.json').read_text()); R=json.loads((N/'resolution-profile-fixtures.json').read_text())
T=1792713600; I=T-600; X=T+3600
D={'schemaVersion':1,'postFreeze':True,'independentOfProduction':True,'freezeAuthoritySha256':'b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19','baseClock':T,'keys':{},'rrsets':{},'signatures':{},'ds':{},'references':{},'providerAncestorPaths':{}}
KEYS={**B['keys'],**P['keys']}; PRIVATE={}; DK={}
ORDER=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
for kid in ['child-ksk-g1','child-ksk-g2','child-zsk-g1','example-zsk-g1','provider-b-ksk-g1','signal-example-net-zsk-g1','signal-example-org-zsk-g1']:
 k=KEYS[kid]; seed=hashlib.sha256(('auth-lab-dnssec-D0:'+kid).encode()).digest(); private=ec.derive_private_key(int.from_bytes(seed,'big')%(ORDER-1)+1,ec.SECP256R1()); dk=dns.dnssec.make_dnskey(private.public_key(),13,flags=k['flags']); assert dk.to_wire().hex()==k['dnskeyRdataHex']; PRIVATE[kid]=private; DK[kid]=dk
 D['keys'][kid]={f:k[f] for f in ['id','owner','flags','protocol','algorithm','publicKeyHex','publicKeyBase64','dnskeyRdataHex','keyTag','text','publicKeyPem']}; D['keys'][kid]['custody']=k.get('privateHolderLabel','dnsProviderB' if kid.startswith('provider-b') else 'dnsSigner'); D['keys'][kid]['publicRdataSource']={'path':reference_path((N/('post-freeze-contract-errata/publication-fixtures.json' if kid in P['keys'] else 'dnssec-numeric-fixtures.json'))),'pointer':'/keys/'+kid}
def add(rid,owner,typ,records,kid,ttl=3600):
 rr=dns.rrset.from_text(owner,ttl,'IN',typ,*records); D['rrsets'][rid]={'id':rid,'owner':owner,'type':typ,'typeCode':int(rr.rdtype),'class':'IN','ttl':ttl,'records':records,'canonicalRdataHex':sorted(r.to_digestable().hex() for r in rr)}
 sig=dns.dnssec.sign(rr,PRIVATE[kid],dns.name.from_text(KEYS[kid]['owner']),DK[kid],inception=I,expiration=X,deterministic=True); data=dns.dnssec._make_rrsig_signature_data(rr,sig)
 sid=rid+'-signature'; D['signatures'][sid]={'id':sid,'rrsetId':rid,'keyId':kid,'typeCovered':int(sig.type_covered),'algorithm':sig.algorithm,'labels':sig.labels,'originalTtl':sig.original_ttl,'inception':I,'expiration':X,'keyTag':sig.key_tag,'signer':sig.signer.to_text(),'rrsigText':sig.to_text(),'rrsigRdataHex':sig.to_wire().hex(),'signatureHex':sig.signature.hex(),'signingInputHex':data.hex(),'signingInputSha256':hashlib.sha256(data).hexdigest()}
old=B['ds']['child-ksk-g1-sha256']['text']; new=B['ds']['child-ksk-g2-sha256']['text']
d4=dns.dnssec.make_ds('lab.example.',DK['child-ksk-g1'],4,policy=dns.dnssec.allow_all_policy)
D['ds']['child-ksk-g1-sha384']={'id':'child-ksk-g1-sha384','keyId':'child-ksk-g1','owner':'lab.example.','digestType':4,'algorithm':13,'keyTag':22775,'digestHex':d4.digest.hex(),'digestInputHex':(dns.name.from_text('lab.example.').to_digestable()+DK['child-ksk-g1'].to_wire()).hex(),'dsRdataHex':d4.to_wire().hex(),'text':d4.to_text(),'policy':'Explicit requested SHA384 tuple; not an obsolete digest'}
for rid,typ,records,kid in [('child-cds-newk-only','CDS',[new],'child-ksk-g1'),('child-cdnskey-newk-only','CDNSKEY',[KEYS['child-ksk-g2']['text']],'child-ksk-g1'),('child-cds-mixed-ds4','CDS',[old,new,d4.to_text()],'child-ksk-g1'),('child-cds-malformed-delete-plus-newk','CDS',['0 0 0 00',new],'child-ksk-g1'),('child-cdnskey-malformed-delete','CDNSKEY',['1 3 0 AA=='],'child-ksk-g1'),('child-cds-delete-by-newk','CDS',['0 0 0 00'],'child-ksk-g2'),('child-cdnskey-delete-by-newk','CDNSKEY',['0 3 0 AA=='],'child-ksk-g2'),('parent-ds-historical-sha1','DS',[B['ds']['child-ksk-g1-sha1-historical']['text']],'example-zsk-g1'),('parent-ds-modern-obsolete','DS',[old,P['rrsets']['parent-ds-obsolete-alg5']['records'][0],P['rrsets']['parent-ds-obsolete-alg12-digest3']['records'][0]],'example-zsk-g1'),('provider-b-cds-intent','CDS',[B['ds']['provider-b-ksk-g1-sha256']['text']],'provider-b-ksk-g1'),('provider-b-cdnskey-intent','CDNSKEY',[KEYS['provider-b-ksk-g1']['text']],'provider-b-ksk-g1')]: add(rid,'lab.example.',typ,records,kid)
for suffix in ['net','org']:
 rid='provider-'+suffix+'-nods'; add(rid,'provider.example.'+suffix+'.','NSEC',['zzz.example.'+suffix+'. NS RRSIG NSEC'],'signal-example-'+suffix+'-zsk-g1',300)
 D['providerAncestorPaths'][suffix]={'anchorKeyId':'root-ksk-g1','steps':P['signalingChains'][suffix]['chain'][:-2],'terminalProofId':rid,'terminalSignatureId':rid+'-signature','sourcePath':reference_path(output_root() / 'post-freeze-contract-errata/publication-fixtures.json'),'initialTrust':'root-ksk-g1 only'}
for variant,record in [('scheme0','CDS 0 53 notify.example.'),('scheme99','CDS 99 53 notify.example.'),('port0','CDS 1 0 notify.example.'),('missing-target','CDS 1 53 missing.example.')]: add('parent-dsync-'+variant,'lab._dsync.example.','DSYNC',[record],'example-zsk-g1')
proof=R['rrsets']['denial-parent-unsigned-lab']; add('remote-old-nods-ttl3600',proof['owner'],proof['type'],proof['records'],'example-zsk-g1',3600)
add('remote-old-nods-soa-min3600','example.','SOA',['ns1.example. hostmaster.example. 2026102301 3600 600 86400 3600'],'example-zsk-g1',3600)
D['remoteReceiptFacts']={'receiptClock':T,'inspectionClock':T+601,'receivedProofTtl':3600,'proofOriginalTtl':3600,'soaTtl':3600,'soaMinimum':3600,'signatureExpiration':X,'negativeTtlMinimum':3600,'expiryClock':T+3600,'remainingAtInspection':2999,'proofId':'remote-old-nods-ttl3600','soaId':'remote-old-nods-soa-min3600','separatePrimaryProof':{'path':reference_path(output_root() / 'resolution-profile-fixtures.json'),'pointer':'/rrsets/denial-parent-unsigned-lab'}}
for rid in ['postfreeze-child-cds-claim','postfreeze-child-cdnskey-claim']:
 D['references'][rid]={'path':reference_path(output_root() / 'post-freeze-contract-errata/publication-fixtures.json'),'rrsetPointer':'/rrsets/'+rid,'signaturePointer':'/signatures/'+rid+'-signature'}
D['references']['baseline-apex-nsec']={'path':reference_path(output_root() / 'dnssec-numeric-fixtures.json'),'rrsetPointer':'/rrsets/child-nsec','signaturePointer':'/signatures/child-nsec-signature','nextNamePreservesCase':'WWW.lab.example.'}
D['signalDigestReferenceTuples']=[{field:B['ds'][kid+'-sha256'][field] for field in ['id','keyId','owner','digestType','algorithm','keyTag','digestHex','digestInputHex','dsRdataHex','text']} for kid in ['child-ksk-g1','child-ksk-g2','provider-b-ksk-g1']]
D['limits']=['Mathematical signatures and reference facts only; no application acceptance or ACL outcomes.','Opaque algorithm5/12 DS extras are not DNSKEY-derived and establish no legacy algorithm cryptographic path.','Historical SHA1 DS uses frozen existing DS bytes only; no new SHA1 DS digest generation.','No endpoint lookup, network DNS queries or authorization execution.','Synthetic private material regenerated in memory only; public RDATA equality checked against attributed frozen/addendum sources.']
D['provenance']={'python':platform.python_version(),'dependencies':{x:importlib.metadata.version(x) for x in ['dnspython','cryptography','cffi','pycparser']},'environment':str(pathlib.Path(sys.executable).parent.parent),'command':[sys.executable,'-B',str(pathlib.Path(__file__).resolve())],'sources':[{'path':reference_path(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in [N/'dnssec-numeric-fixtures.json',N/'post-freeze-contract-errata/publication-fixtures.json',N/'resolution-profile-fixtures.json',N/'sources/rfc8078.txt',N/'sources/rfc9859.txt',N/'sources/rfc4035.txt',N/'sources/rfc6840.txt',ROOT/'docs/dnssec-expansion/sources/publication/rfc9615.txt']]}
raw=(json.dumps(D,indent=2,sort_keys=True)+'\n').encode(); (OUT/'parent-signing-fixtures.json').write_bytes(raw)
print(json.dumps({'datasetSha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rrsets':len(D['rrsets']),'signatures':len(D['signatures']),'keys':len(D['keys']),'ds':len(D['ds'])},sort_keys=True))
