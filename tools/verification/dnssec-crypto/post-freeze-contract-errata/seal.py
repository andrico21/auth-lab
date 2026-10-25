#!/usr/bin/env python3
"""Seal only the additive audit package and prove all authority-listed frozen inputs unchanged."""
import hashlib
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[4]
TOOLS=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric/post-freeze-contract-errata'
FREEZE=ROOT/'docs/dnssec-expansion/contract-freeze.json'
FREEZE_HASH='b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
def identity(path):
    raw=path.read_bytes()
    return {'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
if identity(FREEZE)['sha256']!=FREEZE_HASH:
    raise RuntimeError('Freeze authority changed')
authority=json.loads(FREEZE.read_text()); preservation=[]
for entry in authority['inputs']:
    if entry['path'].startswith('src/'):
        raise RuntimeError('Unexpected production source in preservation list; do not consult evaluator')
    actual=identity(ROOT/entry['path'])
    if actual['sha256']!=entry['sha256']:
        raise RuntimeError('Frozen artifact differs; never overwrite it: '+entry['path'])
    preservation.append({**actual,'unchanged':True})
active=[]
for fixture_name,report_name in [('publication-fixtures.json','publication-verification.json'),('resolution-fixtures-owner-wire-corrected.json','resolution-verification.json')]:
    fid=identity(OUT/fixture_name); rid=identity(OUT/report_name)
    f=json.loads((OUT/fixture_name).read_text()); r=json.loads((OUT/report_name).read_text())
    if r['result']!='pass' or r['fixtureSha256']!=fid['sha256']:
        raise RuntimeError('Active fixture/report not passed and bound: '+fixture_name)
    signature_metadata={key:{field:value[field] for field in ['rrsetId','keyId','keyTag','signer','typeCovered','algorithm','labels','inception','expiration','originalTtl','rrsigRdataHex','rrsigRdataSha256','signingInputSha256']} for key,value in f['signatures'].items()}
    active.append({'fixture':fid,'report':rid,'kind':f['kind'],'objectIds':{kind:sorted(f.get(kind,{})) for kind in ['keys','rrsets','signatures','ds']},'signatureMetadata':signature_metadata,'exactRrsetRecords':{key:{field:value[field] for field in ['owner','type','ttl','records','canonicalRdataHex']} for key,value in f['rrsets'].items()},'checks':r['checks'],'result':'pass'})
runs=[]
for path in sorted((OUT/'runs').glob('run-*.json')):
    row=json.loads(path.read_text()); runs.append({**identity(path),'argv':row['argv'],'exitCode':row['exitCode']})
pub=json.loads((OUT/'publication-fixtures.json').read_text())
summary={'schemaVersion':1,'kind':'dnssec-independent-post-freeze-audit-addendum-catalog','postFreeze':True,'replacesFrozenCatalog':False,
 'freezeAuthority':identity(FREEZE),'frozenFinalCatalog':identity(ROOT/'docs/dnssec-expansion/numeric/FINAL-FIXTURE-IDENTITIES.json'),
 'activeDatasetsAndReports':active,'generationProvenance':identity(OUT/'generation-provenance.json'),
 'retainedFailedAttempt':{'fixture':identity(OUT/'resolution-fixtures.json'),'verifierSource':identity(OUT/'attempts/verify-owner-wire-03-first-attempt.py.txt'),'command':identity(OUT/'runs/run-002.json'),'acceptedAsPassed':False,'reason':'Auditor-specified03 owner-length literal for zz was incorrect and withdrawn. Corrected02 changes binding metadata only; every signed RRset/signature remains byte-identical.'},
 'producer':identity(TOOLS/'generate.py'),'correctionProducer':identity(TOOLS/'correct_owner_wire.py'),'verifier':identity(TOOLS/'verify.py'),'recorder':identity(TOOLS/'record.py'),'instructions':identity(TOOLS/'README.txt'),
 'referenceEnvironment':identity(ROOT/'docs/dnssec-expansion/numeric/runtime-and-licenses.json'),'pinnedRequirements':identity(ROOT/'tools/verification/dnssec-crypto/requirements.txt'),'independentCanonicalizer':identity(ROOT/'tools/verification/dnssec-crypto/reference_bytes.py'),
 'commandRuns':runs,'failuresRetained':sum(row['exitCode']!=0 for row in runs),'preservation':{'frozenInputCount':len(preservation),'allFrozenAuthorityInputsByteIdentical':True,'frozenManifestByteIdentical':True,'inputs':preservation},
 'newObjectCounts':{'keys':len(pub['keys']),'rrsets':sum(len(json.loads((ROOT/row['fixture']['path']).read_text())['rrsets']) for row in active),'signatures':sum(len(row['objectIds']['signatures']) for row in active),'derivedDs':len(pub['ds'])},
 'namedAssertions':sum(row['checks'] for row in active),'actualOpenSslSignatureObservations':30,
 'opaqueDsPayloadProvenance':pub['opaqueDsPayloadProvenance'],'signalingChainIds':sorted(pub['signalingChains']),
 'scope':{'newDependencySetupExecuted':False,'productionOrEvaluatorImports':False,'appBuildTestLintFormatterExecuted':False,'liveDnsOrServerInteroperabilityExecuted':False,'initialSignalingTrustUsesChildApexSignature':False,'longFutureDirectSignatureChecksAreFullFutureChainClaims':False,'opaqueLegacyEnvelopesAreVerifiedLegacyKeyPaths':False,'parentNoDsProofAuthenticatesUnsignedTargetAddress':False},
 'producerCommand':'python3 tools/verification/dnssec-crypto/post-freeze-contract-errata/seal.py'}
raw=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'POST-FREEZE-CATALOG.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Existing post-freeze catalog differs; retain it')
if not path.exists():
    path.write_bytes(raw)
files=[]
for root in [OUT,TOOLS]:
    for item in root.rglob('*'):
        if '__pycache__' in item.parts or item.is_dir() or item.name in ['CONTENTS.json','SHA256SUMS']:
            continue
        if item.is_symlink():
            raise RuntimeError('Unexpected additive retained symlink')
        files.append(identity(item))
files.sort(key=lambda row:row['path'])
contents={'schemaVersion':1,'kind':'dnssec-post-freeze-additive-payload-identities','postFreeze':True,'files':files,'fileCount':len(files),'payloadBytes':sum(row['bytes'] for row in files),'excludesSelfAndSha256Sums':True}
contents_raw=(json.dumps(contents,indent=2,sort_keys=True)+'\n').encode(); cp=OUT/'CONTENTS.json'
if cp.exists() and cp.read_bytes()!=contents_raw:
    raise RuntimeError('Existing additive contents differ')
if not cp.exists():
    cp.write_bytes(contents_raw)
sums=''.join(row['sha256']+'  '+row['path']+'\n' for row in files)+hashlib.sha256(contents_raw).hexdigest()+'  '+str(cp.relative_to(ROOT))+'\n'
sp=OUT/'SHA256SUMS'
if sp.exists() and sp.read_text()!=sums:
    raise RuntimeError('Existing additive checksums differ')
if not sp.exists():
    sp.write_text(sums)
print(json.dumps({'catalog':str(path.relative_to(ROOT)),'catalogBytes':len(raw),'catalogSha256':hashlib.sha256(raw).hexdigest(),'contentsSha256':hashlib.sha256(contents_raw).hexdigest(),'sha256SumsSha256':hashlib.sha256(sums.encode()).hexdigest(),'payloadFiles':len(files),'payloadBytes':contents['payloadBytes'],'frozenInputsChecked':len(preservation),'allFrozenInputsAndManifestUnchanged':True,'checks':summary['namedAssertions'],'verifierSha256':summary['verifier']['sha256']},indent=2))
