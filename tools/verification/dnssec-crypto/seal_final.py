#!/usr/bin/env python3
"""Final immutable catalog of every produced DNSSEC numeric dataset/report; prior seals stay intact."""
import hashlib
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[3]
TOOLS=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric'
PAIRS=[
 ('dnssec-numeric-fixtures.json','independent-verification.json'),
 ('lifecycle-fixtures.json','lifecycle-verification.json'),
 ('profile-fixtures.json','profile-verification.json'),
 ('zonemd-auth-fixtures.json','zonemd-auth-verification.json'),
 ('record-profile-fixtures.json','record-profile-verification.json'),
 ('refresh-fixtures.json','refresh-verification.json'),
 ('long-profile-fixtures.json','long-profile-verification.json'),
 ('complete-path-fixtures.json','complete-path-verification.json'),
 ('resolution-profile-fixtures.json','resolution-profile-verification.json'),
 ('parent-negative-fixtures.json','parent-negative-verification.json'),
 ('role-rollover-fixtures.json','role-rollover-verification.json'),
 ('overlap-keysets-fixtures.json','overlap-keysets-verification.json')]
PRIOR={
 'FIXTURE-IDENTITIES.json':'6e6aedbb12102f738e6530e8f17b4d87e8fd16512eba392dd3279e00ce082158',
 'CONTENTS.json':'63765689cb500926387b573032eaac772008ffa4422a084f811290a1dc3e35e6',
 'SHA256SUMS':'cbf138599545819946d5d92201232c7d97791e1be44e3dc6f2a32433ddd2644f',
 'FIXTURE-IDENTITIES-expanded.json':'a4f2fdf2792052b5061f1b805c79d4d92860917ebab25675ac63675cf510be9b',
 'CONTENTS-expanded.json':'bd6f7d8151d141d71576880ef2644164c99b22017aa73b0e087427234ef0e9cc',
 'SHA256SUMS-expanded':'d51d914d8f4c4c4775f497813551835bbc990480acd0f2aaaf44bd724de3f9bc'}
def identity(path):
    raw=path.read_bytes()
    return {'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in PRIOR.items():
    if identity(OUT/name)['sha256']!=expected:
        raise RuntimeError('Prior seal changed: '+name)
rows=[]; merged={name:{} for name in ['keys','rrsets','signatures','ds','nsec3']}
for fixture_name,report_name in PAIRS:
    fixture_path=OUT/fixture_name; report_path=OUT/report_name
    f=json.loads(fixture_path.read_text()); report=json.loads(report_path.read_text())
    fid=identity(fixture_path); rid=identity(report_path)
    bound=report.get('fixtureSha256',report.get('supplementSha256',report.get('profilesSha256')))
    if report['result']!='pass' or bound!=fid['sha256']:
        raise RuntimeError('Verification not passed or bound: '+fixture_name)
    ids={name:sorted(f.get(name,{})) for name in merged}
    for name in merged:
        for object_id,value in f.get(name,{}).items():
            if object_id in merged[name]:
                raise RuntimeError('Duplicate numeric object ID '+object_id)
            merged[name][object_id]=value
    rows.append({'fixture':fid,'report':rid,'schemaVersion':f['schemaVersion'],'kind':f['kind'],'objectIds':ids,
      'pathIds':sorted(f.get('paths',{})),'profileIds':sorted(f.get('profiles',{})),
      'assertions':report.get('independentAdditionalChecks',report.get('additionalChecks',report.get('checks'))),'result':'pass'})
other_reports=[identity(OUT/name) for name in ['library-observations.json','runtime-and-licenses.json','prerequisite-attempts.json','capture-ledger.json','role-rollover-identities.json']]
commands=[]
for path in sorted((OUT/'runs').glob('run-*.json')):
    run=json.loads(path.read_text()); commands.append({**identity(path),'argv':run['argv'],'exitCode':run['exitCode']})
summary={'schemaVersion':1,'kind':'dnssec-numeric-D0-final-immutable-catalog','independentOfProduction':True,'researchCutoff':'2026-10-23','baseClock':1792713600,
 'producerCommand':'python3 tools/verification/dnssec-crypto/seal_final.py','datasetCount':len(rows),'datasetsAndReports':rows,
 'otherReportsAndLedgers':other_reports,'publishedReferenceBytes':identity(TOOLS/'published-vectors.json'),
 'previousSealsPreserved':[{**identity(OUT/name),'expectedSha256':expected} for name,expected in PRIOR.items()],
 'totals':{name:len(values) for name,values in merged.items()},'namedAssertionsAcrossReports':sum(row['assertions'] for row in rows),
 'keyTags':{object_id:value['keyTag'] for object_id,value in merged['keys'].items()},
 'commandRuns':commands,'recordedCommandFailuresRetained':sum(row['exitCode']!=0 for row in commands),
 'scope':{'appBridge':'Read fixed independently produced bytes/IDs from these exact files; do not run numerical crypto at startup or mutate signed inputs.',
 'syntheticTree':['.','example.','lab.example.'],'siblingTarget':'other.example.','runtimeNumericCryptoIntroduced':False,'longSignatureIntervals':'Synthetic lifecycle choices base-600..day120, not normal operational lifetime advice.',
 'candidateMetadataVariants':'Two DNSKEY objects deliberately fail protocol/ZoneFlag eligibility while their authenticated DNSKEY-set and actual leaf cryptographic signatures are independently checkable.',
 'originalNsec3Vectors':'20 original vector objects; additional actual signed chain variants are counted as RRsets, not silently omitted or relabelled vector passes.',
 'lessonAcceptance':'Numeric references and exact consumed paths, not all159 application-case acceptance or RFC5011 policy acceptance.'},
 'preservedLimits':['No live DNS/server interoperability executed','No production src or application evaluator imported','No application build/regression/lint/formatter mid-flight','dnspython2.8.0 plain-time API disagrees with4 valid serial-wrap literals; independent RFC serial vectors separately verified','NXNAME mnemonic unsupported; actual TYPE128 bitmap bytes/signatures verified','TSIG transaction authentication differs from DNSSEC RRset validation; ZONEMD checksum-only and authenticated expected-digest variants remain distinct','Offline Python dependency installation/reverification executed for recordedLinuxx86_64CPython3.14 environment; interpreter/uv/systemOpenSSL/OS not bundled','No source rebuild of cryptographyRust dependency graph','Manual accessibility and historic gates not represented by numeric passes'],
 'packagingExclusions':['tools/verification/dnssec-crypto/.venv/','tools/verification/dnssec-crypto/.offline-venv/','Any __pycache__/ under tools/verification/dnssec-crypto/']}
raw=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'FINAL-FIXTURE-IDENTITIES.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Existing final catalog differs; retain prior identity')
if not path.exists():
    path.write_bytes(raw)
files=[]
for root in [OUT,TOOLS]:
    for item in root.rglob('*'):
        relative=item.relative_to(ROOT)
        if any(part in ['.venv','.offline-venv','__pycache__'] for part in relative.parts) or item.is_dir() or item.name in ['FINAL-CONTENTS.json','FINAL-SHA256SUMS']:
            continue
        if item.is_symlink():
            raise RuntimeError('Unexpected retained symlink '+str(relative))
        files.append(identity(item))
files.sort(key=lambda row:row['path'])
contents={'schemaVersion':1,'kind':'dnssec-numeric-final-retained-payload-identities','files':files,'fileCount':len(files),'payloadBytes':sum(row['bytes'] for row in files),'excludesSelfAndFinalSha256Sums':True,'includesEarlierSealsAsImmutablePayload':True,'exclusions':summary['packagingExclusions']}
contents_raw=(json.dumps(contents,indent=2,sort_keys=True)+'\n').encode(); contents_path=OUT/'FINAL-CONTENTS.json'
if contents_path.exists() and contents_path.read_bytes()!=contents_raw:
    raise RuntimeError('Existing final contents differ')
if not contents_path.exists():
    contents_path.write_bytes(contents_raw)
sums=''.join(row['sha256']+'  '+row['path']+'\n' for row in files)+hashlib.sha256(contents_raw).hexdigest()+'  docs/dnssec-expansion/numeric/FINAL-CONTENTS.json\n'
sums_path=OUT/'FINAL-SHA256SUMS'
if sums_path.exists() and sums_path.read_text()!=sums:
    raise RuntimeError('Existing final checksums differ')
if not sums_path.exists():
    sums_path.write_text(sums)
print(json.dumps({'finalCatalogPath':str(path.relative_to(ROOT)),'finalCatalogSha256':hashlib.sha256(raw).hexdigest(),'contentsSha256':hashlib.sha256(contents_raw).hexdigest(),'sha256SumsSha256':hashlib.sha256(sums.encode()).hexdigest(),'datasets':len(rows),'retainedFiles':len(files),'payloadBytes':contents['payloadBytes'],'totals':summary['totals'],'namedAssertions':summary['namedAssertionsAcrossReports']},indent=2))
