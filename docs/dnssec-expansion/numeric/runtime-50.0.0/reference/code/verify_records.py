
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Verify only new record profiles; no import executes prior verifier/generator gates."""
import hashlib
import json
import pathlib
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset
import reference_bytes as v
raw=(v.OUT/'record-profile-fixtures.json').read_bytes()
f=json.loads(raw)
base=json.loads((v.OUT/'dnssec-numeric-fixtures.json').read_text())
v.check('records-pinned-sha256',hashlib.sha256(raw).hexdigest(),generated_hash('record-profile-fixtures.json'))
v.check('records-baseline-binding',f['baselineSha256'],hashlib.sha256((v.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest())
keys={**base['keys'],**f['keys']}
rows=[]
for identity,key in f['keys'].items():
    v.check(identity+':wire',v.rdata('DNSKEY',key['text']).hex(),key['dnskeyRdataHex'])
    v.check(identity+':keytag',v.key_tag(v.rdata('DNSKEY',key['text'])),key['keyTag'])
with tempfile.TemporaryDirectory(prefix='openssl-',dir=v.OUT) as directory:
    for identity,sig in f['signatures'].items():
        rr=f['rrsets'][sig['rrsetId']]
        key=keys[sig['keyId']]
        data=v.canonical(rr,sig)
        v.check(identity+':canonical-input',data.hex(),sig['signingInputHex'])
        v.check(identity+':cryptographic',v.valid(key,bytes.fromhex(sig['signatureHex']),data),True)
        rows.append(v.openssl_check(identity,key,bytes.fromhex(sig['signatureHex']),data,pathlib.Path(directory)))
        librr=dns.rrset.from_text(rr['owner'],rr['ttl'],'IN',rr['type'],*rr['records'])
        libsig=dns.rdata.from_text('IN','RRSIG',sig['rrsigText'])
        libkeys={dns.name.from_text(key['owner']):dns.rrset.from_text(key['owner'],3600,'IN','DNSKEY',key['text'])}
        dns.dnssec.validate_rrsig(librr,libsig,libkeys,now=f['baseClock'])
        rows.append({'id':identity+':dnspython','now':f['baseClock'],'result':'pass'})
for identity,rr in f['rrsets'].items():
    v.check(identity+':rdata',sorted(v.rdata(rr['type'],text).hex() for text in rr['records']),rr['canonicalRdataHex'])
d=f['ds']['other-ksk-g1-sha256']
k=f['keys']['other-ksk-g1']
v.check('sibling-ds-independent-digest',hashlib.sha256(v.name_wire(k['owner'])+v.rdata('DNSKEY',k['text'])).hexdigest(),d['digestHex'])
v.check('sibling-ds-parent-authenticated-signature-key',f['signatures']['example-other-ds-signature']['keyId'],'example-zsk-g1')
v.check('sibling-dnskey-has-ksk',k['text'] in f['rrsets']['other-dnskey-g1']['records'],True)
v.check('sibling-dnskey-has-zsk',f['keys']['other-zsk-g1']['text'] in f['rrsets']['other-dnskey-g1']['records'],True)
targetsig=f['signatures']['other-www-a-signature']
v.check('cname-signer-cannot-authenticate-target',v.valid(keys['child-zsk-g1'],bytes.fromhex(targetsig['signatureHex']),bytes.fromhex(targetsig['signingInputHex'])),False)
p=f['profiles']['dname']
synth=f['rrsets'][p['synthesizedUnsignedCnameId']]
computed=p['query'][:-len(f['rrsets'][p['authenticatedDnameId']]['owner'])]+f['rrsets'][p['authenticatedDnameId']]['records'][0]
v.check('dname-literal-suffix-substitution',computed,synth['records'][0])
v.check('dname-synthesized-cname-remains-unsigned',any(s['rrsetId']==synth['id'] for s in f['signatures'].values()),False)
p=f['profiles']['private-view']
v.check('private-public-query-owner-equal',f['rrsets'][p['privateRrsetId']]['owner'],base['rrsets'][p['publicRrsetId']]['owner'])
v.check('private-answer-distinct',f['rrsets'][p['privateRrsetId']]['records']!=base['rrsets'][p['publicRrsetId']]['records'],True)
private_key=keys[p['localAnchorKeyId']]
private_digest=hashlib.sha256(v.name_wire(private_key['owner'])+v.rdata('DNSKEY',private_key['text'])).hexdigest()
v.check('public-ds-does-not-authenticate-private-key',private_digest==base['ds'][p['publicDsIdUnchanged']]['digestHex'],False)
v.check('cds-delete-singleton-wire',f['rrsets']['child-cds-delete-singleton']['canonicalRdataHex'],['0000000000'])
v.check('cdnskey-delete-singleton-wire',f['rrsets']['child-cdnskey-delete-singleton']['canonicalRdataHex'],['0000030000'])
for typ,identity in [('CDS','child-cds-intent'),('CDNSKEY','child-cdnskey-intent')]:
    expected=sorted(v.rdata('DS' if typ=='CDS' else 'DNSKEY',(base['ds'][key+'-sha256']['text'] if typ=='CDS' else base['keys'][key]['text'])).hex() for key in ['child-ksk-g1','child-ksk-g2'])
    v.check(identity+':eligible-old-new-material',f['rrsets'][identity]['canonicalRdataHex'],expected)
for identity,owner,expected_types in [('compact-no-nxname','no.lab.example.',['RRSIG','NSEC','NXNAME']),('compact-other-nxname','other.lab.example.',['RRSIG','NSEC','NXNAME']),('compact-www-nodata','www.lab.example.',['A','RRSIG','NSEC']),('compact-branch-ent','branch.lab.example.',['RRSIG','NSEC'])]:
    actual=bytes.fromhex(f['rrsets'][identity]['canonicalRdataHex'][0])
    next_name=b'\x01\x00'+v.name_wire(owner)
    v.check(identity+':minimal-next-name',actual[:len(next_name)],next_name)
    v.check(identity+':bitmap',actual[len(next_name):],v.bitmap(expected_types))
    v.check(identity+':exact-owner-labels',f['signatures'][identity+'-signature']['labels'],len(owner.rstrip('.').split('.')))
v.check('compact-other-signature-not-reused',f['signatures']['compact-no-nxname-signature']['signatureHex']!=f['signatures']['compact-other-nxname-signature']['signatureHex'],True)
v.check('dsync-actual-wire',f['rrsets']['parent-dsync-cds']['canonicalRdataHex'],['003b0114ef066e6f74696679076578616d706c6500'])
v.check('csync-only-a-ns-aaaa-not-ds',v.rdata('CSYNC',f['rrsets']['child-csync']['records'][0])[6:],v.bitmap(['A','NS','AAAA']))
# Record actual library presentation limits and the original uncorrected RFC literals.
for identity,action,expected in [
 ('nxname-mnemonic',lambda:dns.rdatatype.from_text('NXNAME'),'UnknownRdatatype'),
 ('rfc8078-original-cds-shorthand',lambda:dns.rdata.from_text('IN','CDS','0 0 0 0'),'SyntaxError'),
 ('rfc8078-original-cdnskey-shorthand',lambda:dns.rdata.from_text('IN','CDNSKEY','0 3 0 0'),'SyntaxError')]:
    try:
        action(); result={'exceptionClass':None}
    except Exception as error:
        result={'exceptionClass':type(error).__name__,'message':str(error)}
    v.check(identity,result['exceptionClass'],expected)
    rows.append({'id':identity,'expectedError':expected,'observation':result,'disposition':'TYPE128 wire-bit supported; RFC8078 verified erratum5049 corrected octet00 forms used, never fabricated parser success.'})
report={'schemaVersion':1,'kind':'dnssec-independent-record-profile-verification','fixtureSha256':hashlib.sha256(raw).hexdigest(),'result':'pass',
 'checks':len(v.RESULTS),'results':v.RESULTS,'observations':rows,
 'trustScope':{'siblingParentKey':'example-zsk-g1 authenticated by frozen baseline chain','siblingKsk':'other-ksk-g1 matches parent-signed DS','siblingZsk':'other-zsk-g1 is in sibling self-authenticated DNSKEY RRset','privateAnchor':'Explicit separate local child-csk-g1; publicDS cannot authenticate it','cdsAndCdnskey':'Existing child-ksk-g1 signing identity, sentinel is never a signing key'},
 'limits':['NXNAME mnemonic not registered in dnspython2.8.0; actual TYPE128 bitmap encoded and verified','DSYNC trigger and CSYNC address/NS synchronization do not authorize DS changes','Compact per-query profiles not broad denial spans','Unsigned DNAME synthesized CNAME has no independent signature','No application/runtime crypto or live server interoperability']}
result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=v.OUT/'record-profile-verification.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Retain immutable previous record-profile verification')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'result':'pass','checks':len(v.RESULTS),'observations':len(rows),'sha256':hashlib.sha256(result).hexdigest()},indent=2))
