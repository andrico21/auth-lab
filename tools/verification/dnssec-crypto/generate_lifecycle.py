#!/usr/bin/env python3
"""Supplement immutable baseline with genuinely signed long-lived inputs/TSIG/ZONEMD."""
import copy
import hashlib
import json
import pathlib
import struct
import dns.message
import dns.rdata
import dns.rrset
import dns.tsig
import dns.update
import dns.zone
import dns.zonetypes
import generate as g

OUT=g.OUT
base=copy.deepcopy(g.FIXTURES)
base_hash=hashlib.sha256((OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest()
DAY=86400
# Explicit fixture windows, not production algorithm decisions or mutating baseline metadata.
g.key('root-ksk-g2','.')
for prefix,owner,ids in [
 ('root-anchor-observation','.', ['root-ksk-g1','root-ksk-g2','root-zsk-g1']),
 ('child-anchor-observation','lab.example.',['child-ksk-g1','child-ksk-g2','child-zsk-g1'])]:
    g.rrset(prefix,owner,'DNSKEY',[g.DNSKEY[k].to_text() for k in ids],35*DAY)
    signer='root-ksk-g1' if owner=='.' else 'child-ksk-g1'
    g.sign(prefix+'-long-signature',prefix,signer,g.CLOCK-600,g.CLOCK+120*DAY)
for identity,rrid,keyid in [
 ('www-a-successor-long','www-a','child-zsk-g2'),
 ('child-dnskey-successor-long','child-dnskey-rollover','child-ksk-g2'),
 ('example-child-ds-refreshed-long','example-child-ds','example-zsk-g1'),
 ('provider-shared-dnskey-long','provider-shared-dnskey','provider-b-ksk-g1')]:
    g.sign(identity,rrid,keyid,g.CLOCK+2*DAY,g.CLOCK+120*DAY)
g.rrset('www-a-original-ttl60','www.lab.example.','A',['192.0.2.80','192.0.2.81'],60)
g.sign('www-a-original-ttl60-signature','www-a-original-ttl60','child-zsk-g1')
g.rrset('www-a-rollover-ttl7200','www.lab.example.','A',['192.0.2.80','192.0.2.81'],7200)
g.rrset('example-child-ds-rollover-ttl86400','lab.example.','DS',[g.FIXTURES['ds']['child-ksk-g1-sha256']['text']],86400)
g.rrset('example-child-ds-g2-ttl86400','lab.example.','DS',[g.FIXTURES['ds']['child-ksk-g2-sha256']['text']],86400)
for identity,rrid,keyid in [
 ('www-a-rollover-old-long','www-a-rollover-ttl7200','child-zsk-g1'),
 ('www-a-rollover-new-long','www-a-rollover-ttl7200','child-zsk-g2'),
 ('child-dnskey-rollover-old-long','child-dnskey-rollover','child-ksk-g1'),
 ('child-dnskey-rollover-new-long','child-dnskey-rollover','child-ksk-g2'),
 ('example-child-ds-rollover-long','example-child-ds-rollover-ttl86400','example-zsk-g1'),
 ('example-child-ds-g2-long','example-child-ds-g2-ttl86400','example-zsk-g1')]:
    g.sign(identity,rrid,keyid,g.CLOCK-600,g.CLOCK+120*DAY)
g.sign('revoked-dnskey-day3-self-signature','revoked-dnskey','child-ksk-g1-revoked',g.CLOCK+3*DAY-600,g.CLOCK+40*DAY)
g.rrset('child-dnskey-manual-day90','lab.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in ['child-ksk-g2','child-zsk-g2']])
g.sign('child-dnskey-manual-day90-current-signature','child-dnskey-manual-day90','child-ksk-g2',g.CLOCK+89*DAY,g.CLOCK+120*DAY)
# Genuine HMAC-SHA256 UPDATE, fixed ID/time. Shared fixture secret is not DNSSEC key material.
secret=hashlib.sha256(b'auth-lab-D0:operator-to-primary-tsig').digest()
key=dns.tsig.Key('operator-primary.lab.example.',secret,algorithm='hmac-sha256.')
update=dns.update.Update('lab.example.')
update.id=0x1234
update.replace('www',60,'A','192.0.2.82')
unsigned=update.to_wire()
update.use_tsig(key,fudge=300)
template=update.tsig[0]
signed,_=dns.tsig.sign(unsigned,key,template,time=g.CLOCK)
tsigr=dns.rrset.from_rdata(key.name,0,signed)
# TSIG is appended once and ARCOUNT changes, but MAC input uses original count0.
import io
stream=io.BytesIO()
tsigr.to_wire(stream)
rrbytes=stream.getvalue()
header=bytearray(unsigned[:12]); header[10:12]=struct.pack('!H',1)
wire=bytes(header)+unsigned[12:]+rrbytes
validated=dns.tsig.validate(wire,key,key.name,signed,g.CLOCK,b'',len(unsigned))
mac_input=unsigned+key.name.to_digestable()+struct.pack('!HI',255,0)+key.algorithm.to_digestable()+struct.pack('!HIHHH',0,g.CLOCK,300,0,0)
# Whole-zone digest variant has explicit source records, including unsigned delegation/glue.
selected=['child-dnskey-g1','child-ns','child-soa','child-mx','child-txt','child-nsec','www-a','www-nsec','wildcard-a']
lines=[]
for identity in selected:
    rr=base['rrsets'][identity]
    lines += [f"{rr['owner']} {rr['ttl']} IN {rr['type']} {text}" for text in rr['records']]
    sigid='child-dnskey-g1-by-ksk' if identity=='child-dnskey-g1' else identity+'-signature'
    sig=base['signatures'][sigid]
    lines.append(f"{rr['owner']} {rr['ttl']} IN RRSIG {sig['rrsigText']}")
lines+=['unsigned.lab.example. 3600 IN NS ns.unsigned.lab.example.','ns.unsigned.lab.example. 3600 IN A 192.0.2.200']
zone_text='\n'.join(lines)+'\n'
zone=dns.zone.from_text(zone_text,origin='lab.example.',relativize=False)
digest=zone.compute_digest(dns.zonetypes.DigestHashAlgorithm.SHA384)
zone.verify_digest(digest)
# Supplement records preserve exact baseline identity and never replace the old dataset.
supp={'schemaVersion':1,'kind':'dnssec-independent-numeric-lifecycle-supplement','baselineSha256':base_hash,'baseClock':g.CLOCK,
 'keys':{k:v for k,v in g.FIXTURES['keys'].items() if k not in base['keys']},
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},
 'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'timeWindows':{'holdDownObservationDays':[0,15,30,45,60],'anchorObservationSignatureIds':['root-anchor-observation-long-signature','child-anchor-observation-long-signature'],
 'successorObservationDay':45,'successorSignatureIds':['www-a-successor-long','child-dnskey-successor-long','example-child-ds-refreshed-long','provider-shared-dnskey-long'],
 'notes':'Long lifetime is an explicit deterministic numerical teaching fixture, not an operational recommendation. Repeated authenticated observations and hold-down policy remain independent requirements.'},
 'tsig':{'id':'operator-primary-update-hmac-sha256','algorithm':'hmac-sha256.','keyName':key.name.to_text(),'fixtureOnlySharedSecretHex':secret.hex(),
 'custodians':['dnsOperator','dnsPrimary'],'privateIsNetworkRecord':False,'timeSigned':g.CLOCK,'fudge':300,'messageId':4660,
 'unsignedUpdateWireHex':unsigned.hex(),'tsigRdataHex':signed.to_wire().hex(),'tsigStart':len(unsigned),'authenticatedUpdateWireHex':wire.hex(),
 'macInputHex':mac_input.hex(),'macHex':signed.mac.hex(),'dnspythonValidation':'passed actual dns.tsig.validate at fixed now',
 'scope':'Transaction authentication of UPDATE only; not DNSSEC RRset trust, ACL authorization, transport confidentiality or server interoperability.'},
 'zonemd':{'id':'child-zone-simple-sha384','owner':'lab.example.','serial':2026102301,'scheme':1,'hashAlgorithm':1,
 'zoneText':zone_text,'zonemdText':digest.to_text(),'digestHex':digest.digest.hex(),
 'dnssecAuthentication':'Digest record not signed in this variant; numeric checksum only, MUST NOT call authenticated origin without DNSSEC verification of ZONEMD RRset.',
 'scope':'Whole-zone SIMPLE SHA384 digest, includes unsigned delegation/glue. No zone-transfer server execution.'}}
raw=(json.dumps(supp,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'lifecycle-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable supplemental dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'signatures':len(supp['signatures']),
 'newKeyTags':{k:v['keyTag'] for k,v in supp['keys'].items()},'tsigMac':signed.mac.hex(),'zonemdDigest':digest.digest.hex()},indent=2))
