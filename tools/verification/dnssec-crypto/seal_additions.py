#!/usr/bin/env python3
"""Add a new D0 seal without overwriting any previously sealed artifact."""
import hashlib
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[3]
TOOLS=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric'
prior={'FIXTURE-IDENTITIES.json':'6e6aedbb12102f738e6530e8f17b4d87e8fd16512eba392dd3279e00ce082158','CONTENTS.json':'63765689cb500926387b573032eaac772008ffa4422a084f811290a1dc3e35e6','SHA256SUMS':'cbf138599545819946d5d92201232c7d97791e1be44e3dc6f2a32433ddd2644f'}
for name,expected in prior.items():
    if hashlib.sha256((OUT/name).read_bytes()).hexdigest()!=expected:
        raise RuntimeError('Earlier sealed artifact changed: '+name)
old=json.loads((OUT/'FIXTURE-IDENTITIES.json').read_text())
rows=list(old['datasets'])
for fixture_name,report_name in [('complete-path-fixtures.json','complete-path-verification.json'),('resolution-profile-fixtures.json','resolution-profile-verification.json'),('parent-negative-fixtures.json','parent-negative-verification.json')]:
    raw=(OUT/fixture_name).read_bytes(); f=json.loads(raw)
    report_raw=(OUT/report_name).read_bytes(); report=json.loads(report_raw)
    if report['result']!='pass' or report['fixtureSha256']!=hashlib.sha256(raw).hexdigest():
        raise RuntimeError('Added reference verification is not passed and correctly bound: '+fixture_name)
    rows.append({'fixture':fixture_name,'schemaVersion':f['schemaVersion'],'kind':f['kind'],'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'counts':{name:len(f.get(name,{})) for name in ['keys','rrsets','signatures','ds','nsec3']},'verificationReport':report_name,'verificationSha256':hashlib.sha256(report_raw).hexdigest(),'namedChecks':report['checks'],'result':'pass'})
merged={name:{} for name in ['keys','rrsets','signatures','ds','nsec3']}
for row in rows:
    raw=(OUT/row['fixture']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=row['sha256']:
        raise RuntimeError('Fixture identity changed: '+row['fixture'])
    f=json.loads(raw)
    for name in merged:
        for identity,value in f.get(name,{}).items():
            if identity in merged[name]:
                raise RuntimeError('Duplicate object identity '+identity)
            merged[name][identity]=value
summary={'schemaVersion':1,'kind':'dnssec-numeric-D0-expanded-fixed-identity-catalog','producerCommand':'python3 tools/verification/dnssec-crypto/seal_additions.py','independentOfProduction':True,'researchCutoff':'2026-10-23','previousSealPreserved':prior,'datasets':rows,'totals':{name:len(values) for name,values in merged.items()},'namedAssertionsAcrossReports':sum(r['namedChecks'] for r in rows),'keyTags':{identity:key['keyTag'] for identity,key in merged['keys'].items()},'signatureIds':sorted(merged['signatures']),'recordProfileIds':sorted(merged['rrsets']),
 'additionalScope':{'completeLiteralPaths':15,'completeClockedPathObservations':69,'longPathClocksIncludeDays':[35,90],'negativeCandidateDnskeyMetadataObjects':2,'longSignatureLifetimesAreOperationalAdvice':False,'anchorManagementImpliesLeafQueries':False},'preservedLimits':old['unperformedOrLimited'],'packagingExclusions':old['packagingExclusions']}
summary_raw=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode()
summary_path=OUT/'FIXTURE-IDENTITIES-expanded.json'
if summary_path.exists() and summary_path.read_bytes()!=summary_raw:
    raise RuntimeError('Existing expanded seal differs; retain it')
if not summary_path.exists():
    summary_path.write_bytes(summary_raw)
files=[]
for root in [OUT,TOOLS]:
    for item in root.rglob('*'):
        relative=item.relative_to(ROOT)
        if any(part in ['.venv','.offline-venv','__pycache__'] for part in relative.parts):
            continue
        if item.name in ['CONTENTS-expanded.json','SHA256SUMS-expanded'] or item.is_dir():
            continue
        if item.is_symlink():
            raise RuntimeError('Unexpected retained symlink '+str(relative))
        data=item.read_bytes(); files.append({'path':str(relative),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
files.sort(key=lambda r:r['path'])
contents={'schemaVersion':1,'kind':'dnssec-numeric-expanded-retained-payload-identities','producerCommand':summary['producerCommand'],'files':files,'fileCount':len(files),'payloadBytes':sum(r['bytes'] for r in files),'excludesSelfAndExpandedSha256Sums':True,'previousSealFilesIncludedAsPayload':True,'exclusions':summary['packagingExclusions']}
contents_raw=(json.dumps(contents,indent=2,sort_keys=True)+'\n').encode()
contents_path=OUT/'CONTENTS-expanded.json'
if contents_path.exists() and contents_path.read_bytes()!=contents_raw:
    raise RuntimeError('Existing expanded contents differ; retain them')
if not contents_path.exists():
    contents_path.write_bytes(contents_raw)
sums=''.join(row['sha256']+'  '+row['path']+'\n' for row in files)+hashlib.sha256(contents_raw).hexdigest()+'  docs/dnssec-expansion/numeric/CONTENTS-expanded.json\n'
sums_path=OUT/'SHA256SUMS-expanded'
if sums_path.exists() and sums_path.read_text()!=sums:
    raise RuntimeError('Existing expanded checksums differ; retain them')
if not sums_path.exists():
    sums_path.write_text(sums)
print(json.dumps({'catalogSha256':hashlib.sha256(summary_raw).hexdigest(),'contentsSha256':hashlib.sha256(contents_raw).hexdigest(),'sha256SumsSha256':hashlib.sha256(sums.encode()).hexdigest(),'retainedFiles':len(files),'payloadBytes':contents['payloadBytes'],'totals':summary['totals'],'namedChecks':summary['namedAssertionsAcrossReports']},indent=2))
