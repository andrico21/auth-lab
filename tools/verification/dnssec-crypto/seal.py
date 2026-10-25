#!/usr/bin/env python3
"""Seal retained numeric inputs/outputs, excluding generated environments and caches."""
import hashlib
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[3]
TOOLS=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric'
PAIRS=[('dnssec-numeric-fixtures.json','independent-verification.json'),('lifecycle-fixtures.json','lifecycle-verification.json'),('profile-fixtures.json','profile-verification.json'),('zonemd-auth-fixtures.json','zonemd-auth-verification.json'),('record-profile-fixtures.json','record-profile-verification.json'),('refresh-fixtures.json','refresh-verification.json'),('long-profile-fixtures.json','long-profile-verification.json')]
rows=[]
merged={name:{} for name in ['keys','rrsets','signatures','ds','nsec3']}
for fixture_name,report_name in PAIRS:
    fixture_raw=(OUT/fixture_name).read_bytes(); fixture=json.loads(fixture_raw)
    report_raw=(OUT/report_name).read_bytes(); report=json.loads(report_raw)
    if report['result']!='pass':
        raise RuntimeError('Unsuccessful gate cannot be sealed as passed: '+report_name)
    bound_hash=report.get('fixtureSha256',report.get('supplementSha256',report.get('profilesSha256')))
    if bound_hash!=hashlib.sha256(fixture_raw).hexdigest():
        raise RuntimeError('Verification report is not bound to this fixture: '+report_name)
    counts={name:len(fixture.get(name,{})) for name in merged}
    for name in merged:
        for identity,value in fixture.get(name,{}).items():
            if identity in merged[name]:
                raise ValueError('Duplicate numeric ID '+identity)
            merged[name][identity]=value
    rows.append({'fixture':fixture_name,'schemaVersion':fixture['schemaVersion'],'kind':fixture['kind'],'bytes':len(fixture_raw),'sha256':hashlib.sha256(fixture_raw).hexdigest(),
      'counts':counts,'verificationReport':report_name,'verificationSha256':hashlib.sha256(report_raw).hexdigest(),
      'namedChecks':report.get('independentAdditionalChecks',report.get('additionalChecks',report.get('checks'))),
      'result':'pass'})
ledger=json.loads((OUT/'capture-ledger.json').read_text())
summary={'schemaVersion':1,'kind':'dnssec-numeric-D0-fixed-identity-catalog','independentOfProduction':True,'researchCutoff':'2026-10-23',
 'producerCommand':'python3 tools/verification/dnssec-crypto/seal.py','datasets':rows,'totals':{name:len(values) for name,values in merged.items()},
 'namedAssertionsAcrossReports':sum(r['namedChecks'] for r in rows),'keyTags':{identity:value['keyTag'] for identity,value in merged['keys'].items()},
 'signatureIds':sorted(merged['signatures']),'recordProfileIds':sorted(merged['rrsets']),
 'sourceCaptures':{'successful':sum(r['status']==200 for r in ledger),'failedRetained':sum(r['status']!=200 for r in ledger)},
 'separateObservations':'library-observations.json records58 observations,14 expected negative results and4 serial wrap disagreements; these are NOT turned into library passes.',
 'unperformedOrLimited':['Live DNS/server interoperability not performed','No standalone-app crypto or app startup execution','No app build/regression/lint/formatter mid-flight','dnspython wraparound time validation unsupported; separate RFC serial literals verified','NXNAME mnemonic absent; numeric TYPE128 bitmap actually verified','Offline re-verification depends on externally supplied recorded Python/uv/OpenSSL/OS; wheels bundled forLinuxx86_64CPython3.14 only','Source rebuild of cryptoRust dependency graph not performed'],
 'packagingExclusions':['tools/verification/dnssec-crypto/.venv/','tools/verification/dnssec-crypto/.offline-venv/','Any __pycache__/ below tools/verification/dnssec-crypto/'],
 'privateMaterialScope':'Deterministic synthetic public fixture material only, not real secrets or network private records; signer/TSIG custody explicitly labelled.'}
summary_raw=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'FIXTURE-IDENTITIES.json'
if path.exists() and path.read_bytes()!=summary_raw:
    raise RuntimeError('Existing seal differs; preserve prior seal identity')
if not path.exists():
    path.write_bytes(summary_raw)
files=[]
for directory in [OUT,TOOLS]:
    for item in directory.rglob('*'):
        relative=item.relative_to(ROOT)
        if any(part in ['.venv','.offline-venv','__pycache__'] for part in relative.parts):
            continue
        if item.name in ['CONTENTS.json','SHA256SUMS'] or item.is_dir():
            continue
        if item.is_symlink():
            raise RuntimeError('Unexpected retained symlink '+str(relative))
        data=item.read_bytes()
        files.append({'path':str(relative),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
files.sort(key=lambda r:r['path'])
contents={'schemaVersion':1,'kind':'dnssec-numeric-retained-payload-identities','producerCommand':summary['producerCommand'],'files':files,'fileCount':len(files),'payloadBytes':sum(r['bytes'] for r in files),'excludesSelfAndSha256Sums':True,'exclusions':summary['packagingExclusions']}
contents_raw=(json.dumps(contents,indent=2,sort_keys=True)+'\n').encode()
(OUT/'CONTENTS.json').write_bytes(contents_raw)
checksums=''.join(r['sha256']+'  '+r['path']+'\n' for r in files)
checksums+=hashlib.sha256(contents_raw).hexdigest()+'  docs/dnssec-expansion/numeric/CONTENTS.json\n'
(OUT/'SHA256SUMS').write_text(checksums)
print(json.dumps({'catalogSha256':hashlib.sha256(summary_raw).hexdigest(),'contentsSha256':hashlib.sha256(contents_raw).hexdigest(),'sha256SumsSha256':hashlib.sha256(checksums.encode()).hexdigest(),'retainedFiles':len(files),'payloadBytes':contents['payloadBytes'],'totals':summary['totals'],'namedChecks':summary['namedAssertionsAcrossReports']},indent=2))
