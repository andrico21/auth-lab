#!/usr/bin/env python3
"""Immutable actual signed record profiles for aliasing/publication/compact/private lessons."""
import copy
import hashlib
import json
import generate as g
base=copy.deepcopy(g.FIXTURES)
g.key('other-ksk-g1','other.example.')
g.key('other-zsk-g1','other.example.',256)
g.ds('other-ksk-g1-sha256','other-ksk-g1')
g.rrset('other-dnskey-g1','other.example.','DNSKEY',[g.DNSKEY[k].to_text() for k in ['other-ksk-g1','other-zsk-g1']])
g.sign('other-dnskey-g1-signature','other-dnskey-g1','other-ksk-g1')
g.rrset('example-other-ds','other.example.','DS',[g.FIXTURES['ds']['other-ksk-g1-sha256']['text']])
g.sign('example-other-ds-signature','example-other-ds','example-zsk-g1')
for identity,owner,typ,records,keyid in [
 ('www-aaaa','www.lab.example.','AAAA',['2001:db8::80'],'child-zsk-g1'),
 ('cross-zone-cname','alias.lab.example.','CNAME',['www.other.example.'],'child-zsk-g1'),
 ('other-www-a','www.other.example.','A',['192.0.2.80'],'other-zsk-g1'),
 ('child-dname','branch.lab.example.','DNAME',['other.example.'],'child-zsk-g1'),
 ('other-host-a','host.other.example.','A',['192.0.2.80'],'other-zsk-g1'),
 ('private-www-a','www.lab.example.','A',['198.51.100.80'],'child-csk-g1'),
 ('private-child-dnskey','lab.example.','DNSKEY',[g.DNSKEY['child-csk-g1'].to_text()],'child-csk-g1'),
 ('child-cds-intent','lab.example.','CDS',[g.FIXTURES['ds'][k+'-sha256']['text'] for k in ['child-ksk-g1','child-ksk-g2']],'child-ksk-g1'),
 ('child-cdnskey-intent','lab.example.','CDNSKEY',[g.DNSKEY[k].to_text() for k in ['child-ksk-g1','child-ksk-g2']],'child-ksk-g1'),
 ('child-cds-delete-singleton','lab.example.','CDS',['0 0 0 00'],'child-ksk-g1'),
 ('child-cdnskey-delete-singleton','lab.example.','CDNSKEY',['0 3 0 AA=='],'child-ksk-g1'),
 ('parent-dsync-cds','lab._dsync.example.','DSYNC',['CDS 1 5359 notify.example.'],'example-zsk-g1'),
 ('parent-dsync-notify-address','notify.example.','A',['192.0.2.54'],'example-zsk-g1'),
 ('child-csync','lab.example.','CSYNC',['2026102301 3 A NS AAAA'],'child-zsk-g1'),
 ('child-ns1-a','ns1.lab.example.','A',['192.0.2.53'],'child-zsk-g1'),
 ('child-ns1-aaaa','ns1.lab.example.','AAAA',['2001:db8::53'],'child-zsk-g1'),
 ('child-ns2-a','ns2.lab.example.','A',['192.0.2.54'],'child-zsk-g1'),
 ('child-ns2-aaaa','ns2.lab.example.','AAAA',['2001:db8::54'],'child-zsk-g1'),
 ('compact-no-nxname','no.lab.example.','NSEC',[r'\000.no.lab.example. RRSIG NSEC TYPE128'],'child-zsk-g1'),
 ('compact-other-nxname','other.lab.example.','NSEC',[r'\000.other.lab.example. RRSIG NSEC TYPE128'],'child-zsk-g1'),
 ('compact-www-nodata','www.lab.example.','NSEC',[r'\000.www.lab.example. A RRSIG NSEC'],'child-zsk-g1'),
 ('compact-branch-ent','branch.lab.example.','NSEC',[r'\000.branch.lab.example. RRSIG NSEC'],'child-zsk-g1'),
 ('compact-ent-descendant','leaf.branch.lab.example.','A',['192.0.2.22'],'child-zsk-g1')]:
    g.rrset(identity,owner,typ,records,300 if identity.startswith('compact-') else 3600)
    g.sign(identity+'-signature',identity,keyid)
# Synthesized DNAME CNAME is a real wire record, deliberately has no RRSIG.
g.rrset('dname-synthesized-unsigned-cname','host.branch.lab.example.','CNAME',['host.other.example.'])
supp={'schemaVersion':1,'kind':'dnssec-independent-numeric-record-profiles','baseClock':g.CLOCK,
 'baselineSha256':hashlib.sha256((g.OUT/'dnssec-numeric-fixtures.json').read_bytes()).hexdigest(),
 'keys':{k:v for k,v in g.FIXTURES['keys'].items() if k not in base['keys']},
 'rrsets':{k:v for k,v in g.FIXTURES['rrsets'].items() if k not in base['rrsets']},
 'signatures':{k:v for k,v in g.FIXTURES['signatures'].items() if k not in base['signatures']},
 'ds':{k:v for k,v in g.FIXTURES['ds'].items() if k not in base['ds']},
 'profiles':{
 'aaaa':{'rrsetId':'www-aaaa'},
 'cross-zone-cname':{'aliasRrsetId':'cross-zone-cname','targetRrsetId':'other-www-a','targetKeyIds':['other-ksk-g1','other-zsk-g1'],'targetDnskeyId':'other-dnskey-g1','parentDsId':'example-other-ds','parentSignerKeyId':'example-zsk-g1','independentTargetValidationRequired':True},
 'dname':{'authenticatedDnameId':'child-dname','query':'host.branch.lab.example.','synthesizedUnsignedCnameId':'dname-synthesized-unsigned-cname','targetRrsetId':'other-host-a','synthesizedCnameHasIndependentRrsig':False},
 'private-view':{'query':'www.lab.example.','publicRrsetId':'www-a','publicKeyId':'child-zsk-g1','privateRrsetId':'private-www-a','privateDnskeyId':'private-child-dnskey','localAnchorKeyId':'child-csk-g1','localAnchorIndependentlyProvisioned':True,'publicDsIdUnchanged':'child-ksk-g1-sha256','publicParentDsDoesNotAuthenticatePrivateKey':True},
 'child-intent':{'cdsRrsetId':'child-cds-intent','cdnskeyRrsetId':'child-cdnskey-intent','signerKeyId':'child-ksk-g1','existingParentDsId':'child-ksk-g1-sha256','eligibleKeyIds':['child-ksk-g1','child-ksk-g2'],'publicationIsSeparateAction':True},
 'delete':{'cdsRrsetId':'child-cds-delete-singleton','cdnskeyRrsetId':'child-cdnskey-delete-singleton','signerKeyId':'child-ksk-g1','source':'RFC8078 section4 corrected by verified technical erratum5049','payloadHex':'00','sentinelIsOrdinaryKeyOrDs':False},
 'dsync':{'rrsetId':'parent-dsync-cds','addressRrsetId':'parent-dsync-notify-address','parentSignerKeyId':'example-zsk-g1','triggerOnly':True,'authorizesDsChange':False},
 'csync':{'rrsetId':'child-csync','serial':2026102301,'flags':3,'types':['A','NS','AAAA'],'nsRrsetId':'child-ns','addressRrsetIds':['child-ns1-a','child-ns1-aaaa','child-ns2-a','child-ns2-aaaa'],'authorizesDsChange':False},
 'compact':{'source':'RFC9824 sections2,3.1,3.2','nxnameTypeCode':128,'nxnameIsStandaloneRecord':False,'libraryMnemonic':'TYPE128','rrsetIds':['compact-no-nxname','compact-other-nxname','compact-www-nodata','compact-branch-ent'],'noAndOtherHaveSeparateSignatures':True,'scope':'Per-query online-signed zone variants, not a broad cached NSEC span. ENT branch variant has leaf.branch descendant and is separate from the DNAME branch variant.'}},
 'scope':'Fixed inspectable record/canonical/signature bytes. Separate profile variants are not combined into a contradictory single zone. No runtime crypto or live DNS/server interoperability.'}
raw=(json.dumps(supp,indent=2,sort_keys=True)+'\n').encode()
path=g.OUT/'record-profile-fixtures.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Immutable record-profile dataset differs')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(g.ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'counts':{k:len(supp[k]) for k in ['keys','rrsets','signatures','ds']},'keyTags':{k:v['keyTag'] for k,v in supp['keys'].items()}},indent=2))
