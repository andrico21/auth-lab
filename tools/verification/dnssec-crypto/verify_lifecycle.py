#!/usr/bin/env python3
"""Verify supplement with independent byte reconstruction, OpenSSL and pinned DNS library."""
import hashlib
import hmac
import json
import pathlib
import struct
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import dns.tsig
import dns.zone
import verify as v

OUT=v.OUT
raw=(OUT/'lifecycle-fixtures.json').read_bytes()
s=json.loads(raw)
v.check('lifecycle-pinned-sha256',hashlib.sha256(raw).hexdigest(),'cfb51583bfb32a133f725ce2cc160d69ca681e4ad1186ddfab26b68f7d6cc62c')
v.check('supplement-baseline-binding',s['baselineSha256'],hashlib.sha256((OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
keys={**v.fixture['keys'],**s['keys']}
rrsets={**v.fixture['rrsets'],**s['rrsets']}
initial=len(v.RESULTS)
rows=[]
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.HERE) as directory:
    for identity,sig in s['signatures'].items():
        rr=rrsets[sig['rrsetId']]
        key=keys[sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':independent-canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':cryptographic',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        librr=dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records'])
        libsig=dns.rdata.from_text('IN','RRSIG',sig['rrsigText'])
        libkeys={dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])}
        now=max(s['baseClock'],sig['inception'])
        dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=now)
        rows.append({'id':identity+':dnspython','now':now,'result':'pass'})
        if 'anchor-observation' in identity:
            for day in [0,15,30,35,50,60]:
                now=s['baseClock']+day*86400+(1 if day in [35,50] else 0)
                dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=now)
                v.check(identity+':day'+str(day),v.time_state(now,sig['inception'],sig['expiration']),'valid')
        if 'manual-day90' in identity:
            dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=s['baseClock']+90*86400)
            rows.append({'id':identity+':day90','result':'pass'})
short=s['signatures']['www-a-original-ttl60-signature']
v.check('short-original-ttl-signed',short['originalTtl'],60)
changed=dict(short,originalTtl=61)
v.check('changing-signed-original-ttl-invalidates',v.valid(keys[short['keyId']],bytes.fromhex(short['signatureHex']),v.canonical(rrsets[short['rrsetId']],changed)),False)
v.check('changing-received-ttl-retains-input',v.canonical(dict(rrsets[short['rrsetId']],ttl=12),short).hex(),short['signingInputHex'])
# TSIG reconstructed solely from literal request, key and metadata, not copied MAC input.
t=s['tsig']
unsigned=bytes.fromhex(t['unsignedUpdateWireHex'])
mac_input=unsigned+v.name_wire(t['keyName'])+struct.pack('!HI',255,0)+v.name_wire(t['algorithm'])+int(t['timeSigned']).to_bytes(6,'big')+struct.pack('!HHH',t['fudge'],0,0)
v.check('tsig-independent-input',mac_input.hex(),t['macInputHex'])
secret=bytes.fromhex(t['fixtureOnlySharedSecretHex'])
expected=hmac.new(secret,mac_input,hashlib.sha256).hexdigest()
v.check('tsig-independent-hmac-sha256',expected,t['macHex'])
v.check('tsig-wrong-key-hmac-mismatch',hmac.new(b'wrong-fixture-key',mac_input,hashlib.sha256).hexdigest()==t['macHex'],False)
key=dns.tsig.Key(t['keyName'],secret,algorithm=t['algorithm'])
wire=bytes.fromhex(t['authenticatedUpdateWireHex'])
tsig=dns.rdata.from_wire(255,250,bytes.fromhex(t['tsigRdataHex']),0,len(bytes.fromhex(t['tsigRdataHex'])))
for identity,message,now,expected_error in [('tsig-normal',wire,t['timeSigned'],None),('tsig-expired',wire,t['timeSigned']+301,'BadTime')]:
    try:
        dns.tsig.validate(message,key,key.name,tsig,now,b'',t['tsigStart'])
        actual=None
    except Exception as error:
        actual=type(error).__name__
    v.check(identity,actual,expected_error)
    rows.append({'id':identity,'expectedError':expected_error,'observedError':actual})
mutated=bytearray(wire)
# The final update address octet changes from82 to83, preserving all structure.
index=unsigned.index(bytes([192,0,2,82]))+3
mutated[index]=83
try:
    dns.tsig.validate(bytes(mutated),key,key.name,tsig,t['timeSigned'],b'',t['tsigStart'])
    error_class=None
except Exception as error:
    error_class=type(error).__name__
v.check('tsig-mutated-update',error_class,'BadSignature')
rows.append({'id':'tsig-mutated-update','observedError':error_class,'changedOffset':index})
# Independent ZONEMD collation from explicit text records; RFC8976 exclusions.
def zone_input(text,origin):
    records=[]
    for line in text.splitlines():
        if not line.strip():
            continue
        owner,ttl,cls,typ,rtext=line.split(None,4)
        if cls!='IN':
            raise ValueError('Expected IN fixture zone')
        if owner.lower()==origin.lower() and typ=='ZONEMD':
            continue
        if typ=='RRSIG':
            p=rtext.split()
            if owner.lower()==origin.lower() and p[0]=='ZONEMD':
                continue
            import datetime
            def stamp(t):
                return int(datetime.datetime.strptime(t,'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc).timestamp()) if len(t)==14 else int(t)
            data=struct.pack('!HBBIIIH',v.TYPES[p[0]],int(p[1]),int(p[2]),int(p[3]),stamp(p[4]),stamp(p[5]),int(p[6]))+v.name_wire(p[7])+__import__('base64').b64decode(''.join(p[8:]))
        else:
            data=v.rdata(typ,rtext)
        rr=v.name_wire(owner)+struct.pack('!HHIH',v.TYPES[typ],1,int(ttl),len(data))+data
        name_order=tuple(reversed(owner.lower().rstrip('.').encode().split(b'.')))
        records.append(((name_order,v.TYPES[typ],data),rr))
    return b''.join(rr for _,rr in sorted(set(records)))
z=s['zonemd']
data=zone_input(z['zoneText'],z['owner'])
v.check('zonemd-independent-simple-sha384',hashlib.sha384(data).hexdigest(),z['digestHex'])
modified=z['zoneText'].replace('192.0.2.200','192.0.2.201')
v.check('zonemd-unsigned-glue-mutation-detected',hashlib.sha384(zone_input(modified,z['owner'])).hexdigest()==z['digestHex'],False)
zone=dns.zone.from_text(z['zoneText'],origin=z['owner'],relativize=False)
zone.verify_digest(dns.rdata.from_text('IN','ZONEMD',z['zonemdText']))
rows.append({'id':'zonemd-dnspython-verify','result':'pass'})
# Independently published RFC8976 Appendix A.1 fixed bytes, not generated by producer.
published_zone='''example. 86400 IN SOA ns1.example. admin.example. 2018031900 1800 900 604800 86400
example. 86400 IN NS ns1.example.
example. 86400 IN NS ns2.example.
ns1.example. 3600 IN A 203.0.113.63
ns2.example. 3600 IN AAAA 2001:db8::63
'''
published_digest='c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c'
v.check('rfc8976-published-A1-sha384',hashlib.sha384(zone_input(published_zone,'example.')).hexdigest(),published_digest)
pz=dns.zone.from_text(published_zone,origin='example.',relativize=False)
pz.verify_digest(dns.rdata.from_text('IN','ZONEMD','2018031900 1 1 '+published_digest))
rows.append({'id':'rfc8976-published-A1-library','result':'pass','source':'sources/rfc8976.txt Appendix A.1','fixedDigestHex':published_digest})
report={'schemaVersion':1,'kind':'dnssec-independent-lifecycle-verification','baselineSha256':s['baselineSha256'],'supplementSha256':hashlib.sha256(raw).hexdigest(),
 'result':'pass','independentAdditionalChecks':len(v.RESULTS)-initial,'checks':v.RESULTS[initial:],'observations':rows,
 'zonemdCanonicalInputHex':data.hex(),'zonemdCanonicalInputSha256':hashlib.sha256(data).hexdigest(),
 'limits':['TSIG verifies transaction authentication, not authorization or DNSSEC RRset trust','ZONEMD is a verified whole-zone checksum here, not an authenticated origin claim','No server/live DNS interoperability','Long-window RRSIG fixture lifetime is not operational advice']}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'lifecycle-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Retain immutable prior verification output')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','additionalChecks':len(v.RESULTS)-initial,'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
