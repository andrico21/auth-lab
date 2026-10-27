
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[0]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Observe pinned independent library outcomes, including known time limitations."""
import hashlib
import inspect
import json
import pathlib
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
ROOT = ROOT
HERE=pathlib.Path(__file__).resolve().parent
OUT=output_root()
f=json.loads((OUT/'dnssec-numeric-fixtures.json').read_text())
assert hashlib.sha256((OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest() == generated_hash('dnssec-numeric-fixtures.json')
published=json.loads((HISTORICAL_TOOLS/'published-vectors.json').read_text())
rows=[]

def rr(v):
    return dns.rrset.from_text(v['owner'],v['ttl'],'IN',v['type'],*v['records'])

def observe(identity,action,expect_success,context=None):
    try:
        action()
        result={'success':True}
    except Exception as error:
        result={'success':False,'exceptionClass':type(error).__name__,'message':str(error)}
    rows.append({'id':identity,'expectedLibrarySuccess':expect_success,'observation':result,'context':context})
    if result['success']!=expect_success:
        raise AssertionError(rows[-1])

for identity,s in f['signatures'].items():
    if identity=='www-a-wrap':
        continue
    k=f['keys'][s['keyId']]
    keys={dns.name.from_text(k['owner']):dns.rrset.from_text(k['owner'],3600,'IN','DNSKEY',k['text'])}
    sig=dns.rdata.from_text('IN','RRSIG',s['rrsigText'])
    observe(identity,lambda: dns.dnssec.validate_rrsig(rr(f['rrsets'][s['rrsetId']]),sig,keys,now=f['baseClock']),True)
for v in f['vectors']['mutations']:
    s=f['signatures'][v['signatureId']]
    k=f['keys'][s['keyId']]
    keys={dns.name.from_text(k['owner']):dns.rrset.from_text(k['owner'],3600,'IN','DNSKEY',k['text'])}
    sig=dns.rdata.from_text('IN','RRSIG',s['rrsigText'])
    observe(v['id'],lambda: dns.dnssec.validate_rrsig(rr({**v,'ttl':3600}),sig,keys,now=f['baseClock']),False)
for v in f['vectors']['signature-time']:
    if v['id']=='half-range-undefined':
        rows.append({'id':v['id'],'observation':{'performed':False},'context':'RFC1982 undefined half-range has no library validation claim; independent literal vector only.'})
        continue
    s=f['signatures']['www-a-wrap' if v['id'].startswith('wrap-') else 'www-a-signature']
    k=f['keys'][s['keyId']]
    keys={dns.name.from_text(k['owner']):dns.rrset.from_text(k['owner'],3600,'IN','DNSKEY',k['text'])}
    sig=dns.rdata.from_text('IN','RRSIG',s['rrsigText'])
    plain_time_success=v['inception']<=v['now']<=v['expiration']
    observe(v['id'],lambda: dns.dnssec.validate_rrsig(rr(f['rrsets'][s['rrsetId']]),sig,keys,now=v['now']),plain_time_success,
      {'rfcSerialExpected':v['expected'],'libraryUsesSerialArithmetic':False,'agreementWithRfcVector':plain_time_success==(v['expected']=='valid')})
for identity,v in published.items():
    if identity in ['schemaVersion','kind']:
        continue
    if identity=='rfc5155-appendix-a':
        for name,expected in v['hashes'].items():
            actual=dns.dnssec.nsec3_hash(name,v['saltHex'],v['iterations'],v['algorithm'])
            if actual!=expected:
                raise AssertionError({'name':name,'actual':actual,'expected':expected})
            rows.append({'id':identity+':'+name,'observation':{'success':True,'hashBase32hex':actual}})
        continue
    key=dns.rdata.from_text('IN','DNSKEY',v['dnskey'])
    actual=dns.dnssec.make_ds(v['owner'],key,2).to_text().lower()
    if actual!=v['ds'].lower():
        raise AssertionError({'id':identity,'actual':actual,'expected':v['ds']})
    rows.append({'id':identity+':ds','observation':{'success':True,'ds':actual,'keyTag':dns.dnssec.key_id(key)}})
    if 'rawInvalidRrsig' in v:
        observe(identity+':unmodified-rfc-parse',lambda: dns.rdata.from_text('IN','RRSIG',v['rawInvalidRrsig']),False,
          'Published RFC8080 example is malformed. Corrected independently published bytes are from verified technical erratum4935, not regenerated oracle bytes.')
        # Inserting only missing algorithm/labels is insufficient: old signature bytes remain invalid.
        corrected_header=v['rrsig'].rsplit(' ',1)[0]
        old_signature=v['rawInvalidRrsig'].rsplit(' ',1)[1]
        sig=dns.rdata.from_text('IN','RRSIG',corrected_header+' '+old_signature)
        keys={dns.name.from_text(v['owner']):dns.rrset.from_text(v['owner'],3600,'IN','DNSKEY',v['dnskey'])}
        observe(identity+':old-signature-with-corrected-header',lambda: dns.dnssec.validate_rrsig(rr(v['rrset']),sig,keys,now=v['now']),False)
    if 'rrsig' in v:
        sig=dns.rdata.from_text('IN','RRSIG',v['rrsig'])
        keys={dns.name.from_text(v['owner']):dns.rrset.from_text(v['owner'],3600,'IN','DNSKEY',v['dnskey'])}
        observe(identity+':published-signature',lambda: dns.dnssec.validate_rrsig(rr(v['rrset']),sig,keys,now=v['now']),True)
source=inspect.getsource(dns.dnssec._validate_rrsig)
report={'schemaVersion':1,'kind':'dnssec-version-pinned-library-observations','dnspython':'2.8.0','rows':rows,
 'timeApiSource':source,'timeApiSourceSha256':hashlib.sha256(source.encode()).hexdigest(),
 'sourceScope':'dns.dnssec._validate_rrsig from bundled dnspython2.8.0 source; plain comparisons observed. RFC serial vectors remain independent literals.',
 'summary':{'observations':len(rows),'recordedExpectedFailures':sum(r.get('observation',{}).get('success') is False for r in rows),
 'serialDisagreements':sum(r.get('context',{}).get('agreementWithRfcVector') is False for r in rows if isinstance(r.get('context'),dict))}}
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'library-observations.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable observations differ; retain prior result')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':reference_path(path),'sha256':hashlib.sha256(raw).hexdigest(),**report['summary']},indent=2))
