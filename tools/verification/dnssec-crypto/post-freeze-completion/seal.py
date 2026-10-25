#!/usr/bin/env python3
"""Seal only independently verified public completion components; preserve every earlier authority/addendum byte."""
import hashlib
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[4]
TOOLS=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric/post-freeze-completion'
FREEZE=ROOT/'docs/dnssec-expansion/contract-freeze.json'
FREEZE_HASH='b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19'
AUDIT=ROOT/'docs/dnssec-expansion/numeric/post-freeze-contract-errata'
AUDIT_HASH='2c8c7a134e56714d09be1371c8b8cd6f90cb8dc1737fe381f78d59f0e53fa7c5'
AUDIT_CONTENTS_HASH='4d7a78c38b8fcf7f0287d6ec1ecec60a06cac33aef762fbf25c65c90f330ac9a'
AUDIT_SUMS_HASH='3457cc9e8d8fc7fd7c08f9fed7179bd00ff989ca1b61b6778ef19fd2364e944c'

def identity(path):
    raw=path.read_bytes()
    return {'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def at(value,path):
    for field in path.split('.'):
        value=value[field]
    return value

def public_payload(value,path='$'):
    forbidden={'fixtureonlyprivatehex','privatekeyhex','privatekeypem','privatekeybytes','privatescalar','sharedsecret','sharedsecrethex','sharedsecretbase64','secrethex','secretbase64','keymaterialhex','tsigsecrethex'}
    expected_flags={'expectedvalid','expectedmacvalid','expectedaccepted','expectedacceptedforuse','expectedallowed','expectedapplicationresult'}
    if isinstance(value,dict):
        for key,item in value.items():
            normalized=''.join(character for character in key.lower() if character.isalnum())
            if normalized in forbidden and item is not None and not isinstance(item,bool):
                raise RuntimeError('Private material in public payload: '+path+'.'+key)
            if normalized in expected_flags:
                raise RuntimeError('Stored expected acceptance in public payload: '+path+'.'+key)
            public_payload(item,path+'.'+key)
    elif isinstance(value,list):
        for index,item in enumerate(value):
            public_payload(item,path+'['+str(index)+']')
    elif isinstance(value,str) and ('-----BEGIN PRIVATE KEY' in value or '-----BEGIN EC PRIVATE KEY' in value or '-----BEGIN RSA PRIVATE KEY' in value):
        raise RuntimeError('Private PEM in public payload: '+path)

def bridge_projection(dataset,namespaces):
    projection={}
    for target,spec in namespaces.items():
        if isinstance(spec,str):
            projection[target]=dataset[spec]
        else:
            source=dataset[spec['sourceField']]
            projection[target]={identity:{field:value[field] for field in spec['publicFields'] if field in value} for identity,value in source.items()}
    def no_derivation(value,path='$'):
        if isinstance(value,dict):
            for key,item in value.items():
                if key.lower() in ['generation','derivation','seed','secretref','privateseed','privatekeyseed']:
                    raise RuntimeError('Generator-only label in application projection: '+path+'.'+key)
                no_derivation(item,path+'.'+key)
        elif isinstance(value,list):
            for index,item in enumerate(value):
                no_derivation(item,path+'['+str(index)+']')
    public_payload(projection)
    no_derivation(projection)
    return hashlib.sha256((json.dumps(projection,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()

def openssl_signature_observations(value):
    if isinstance(value,dict):
        argv=value.get('argv',[])
        observed=int(isinstance(argv,list) and len(argv)>1 and argv[0]=='openssl' and '-verify' in argv and value.get('exitCode')==0)
        return observed+sum(openssl_signature_observations(item) for item in value.values())
    if isinstance(value,list):
        return sum(openssl_signature_observations(item) for item in value)
    return 0

def immutable_write(path,raw):
    if path.exists() and path.read_bytes()!=raw:
        raise RuntimeError('Existing immutable completion output differs: '+str(path.relative_to(ROOT)))
    if not path.exists():
        path.write_bytes(raw)

if identity(FREEZE)['sha256']!=FREEZE_HASH:
    raise RuntimeError('Original freeze authority changed')
authority=json.loads(FREEZE.read_text()); frozen=[]
for entry in authority['inputs']:
    if entry['path'].startswith('src/'):
        raise RuntimeError('Unexpected production path in preservation inputs; do not inspect evaluator')
    current=identity(ROOT/entry['path'])
    if current['sha256']!=entry['sha256']:
        raise RuntimeError('Frozen artifact differs: '+entry['path'])
    frozen.append({**current,'unchanged':True})
if identity(AUDIT/'POST-FREEZE-CATALOG.json')['sha256']!=AUDIT_HASH or identity(AUDIT/'CONTENTS.json')['sha256']!=AUDIT_CONTENTS_HASH or identity(AUDIT/'SHA256SUMS')['sha256']!=AUDIT_SUMS_HASH:
    raise RuntimeError('Prior independently sealed audit identity changed')
audit_contents=json.loads((AUDIT/'CONTENTS.json').read_text()); prior_audit=[]
for entry in audit_contents['files']:
    current=identity(ROOT/entry['path'])
    if current['sha256']!=entry['sha256']:
        raise RuntimeError('Prior audit payload differs: '+entry['path'])
    prior_audit.append({**current,'unchanged':True})
components=json.loads((OUT/'COMPONENTS.json').read_text()); active=[]; all_runs=[]
for component in components['components']:
    dataset_path=ROOT/component['dataset']; report_path=ROOT/component['report']
    did=identity(dataset_path); rid=identity(report_path)
    if did['sha256']!=component['datasetSha256'] or rid['sha256']!=component['reportSha256']:
        raise RuntimeError('Returned component hashes differ: '+component['id'])
    dataset=json.loads(dataset_path.read_text()); report=json.loads(report_path.read_text())
    if at(report,component['reportBinding'])!=did['sha256']:
        raise RuntimeError('Component report not bound to public dataset: '+component['id'])
    public_payload(dataset)
    # Reports contain actual mathematical observations, not application oracle inputs.
    report_for_private_check=json.dumps(report)
    if any(marker in report_for_private_check for marker in ['fixtureOnlyPrivateHex','-----BEGIN PRIVATE KEY','-----BEGIN EC PRIVATE KEY','-----BEGIN RSA PRIVATE KEY']):
        raise RuntimeError('Private material in public report: '+component['id'])
    evidence=component['successEvidence']
    if evidence['kind']=='result':
        if at(report,evidence['path'])!=evidence['value']:
            raise RuntimeError('Component numerical report not successful: '+component['id'])
        observations=report.get('signatureObservations',[])
    elif evidence['kind']=='signature-observations':
        observations=at(report,evidence['path'])
        if len(observations)!=evidence['count']:
            raise RuntimeError('Unexpected signature-observation count: '+component['id'])
        for observation in observations:
            for path,expected in evidence['fields'].items():
                if at(observation,path)!=expected:
                    raise RuntimeError('Component signature observation not verified: '+component['id']+':'+observation.get('id','unknown'))
        observed_ids={observation['id'] for observation in observations}
        if not set(dataset.get('signatures',{})).issubset(observed_ids):
            raise RuntimeError('New signature lacks reference observation: '+component['id'])
    else:
        raise RuntimeError('Unknown explicit numerical report evidence kind')
    for namespace in ['macReferenceTuples','zonemdReferenceTuples','nsec3ReferenceTuples','signalDigestReferenceTuples']:
        tuples=dataset.get(namespace,[])
        if isinstance(tuples,list):
            for item in tuples:
                if any(key.lower() in ['valid','expectedvalid','expected','accepted','allowed'] for key in item):
                    raise RuntimeError('Expected acceptance flag in positive reference tuple: '+component['id']+':'+namespace)
    runs=[]
    for path in sorted(dataset_path.parent.rglob('run-*.json')):
        row=json.loads(path.read_text())
        runs.append({**identity(path),'argv':row.get('argv',row.get('command')),'exitCode':row.get('exitCode',row.get('returncode'))})
    if not runs or not any(row['exitCode']==0 for row in runs):
        raise RuntimeError('Component lacks captured successful execution: '+component['id'])
    all_runs+=runs
    object_ids={name:sorted(dataset.get(name,{})) for name in ['keys','dnssecKeys','keyReferences','rrsets','rrsetReferences','signatures','ds','nsec3','messages','streams','updates'] if isinstance(dataset.get(name,{}),dict)}
    tuple_counts={name:len(dataset.get(name,[])) for name in ['macReferenceTuples','zonemdReferenceTuples','nsec3ReferenceTuples','signalDigestReferenceTuples']}
    code=[identity(ROOT/path) for path in component['codeFiles']]
    checks=report.get('checks')
    explicit_check_count=len(checks) if isinstance(checks,list) else checks
    projection_hash=bridge_projection(dataset,component['publicNamespaces'])
    active.append({'id':component['id'],'fixture':did,'report':rid,'postFreeze':True,'referenceVerification':'observed-success','reportBindingPath':component['reportBinding'],'reportSuccessEvidence':evidence,'explicitNamedChecks':explicit_check_count,'recordedOpenSslSignatureObservationCount':openssl_signature_observations(report),'reportObservationCount':len(report.get('observations',observations)),'objectIds':object_ids,'referenceTupleCounts':tuple_counts,'publicNamespaces':component['publicNamespaces'],'applicationProjectionSha256':projection_hash,'generatorDerivationLabelsExcludedFromApplicationProjection':True,'selectionNotes':component.get('selectionNotes',{}),'code':code,'commandRuns':runs,'scope':component['scope']})
summary={'schemaVersion':1,'kind':'dnssec-public-post-freeze-completion-catalog','postFreeze':True,'replacesFrozenOrAuditCatalog':False,'freezeAuthority':identity(FREEZE),'previousIndependentAuditCatalog':identity(AUDIT/'POST-FREEZE-CATALOG.json'),'activeDatasetsAndReports':active,
 'componentDescriptor':identity(OUT/'COMPONENTS.json'),'preservation':{'allAuthorityInputsByteIdentical':True,'authorityInputCount':len(frozen),'authorityInputs':frozen,'allPriorIndependentAuditPayloadByteIdentical':True,'priorAuditPayloadCount':len(prior_audit),'priorAuditPayload':prior_audit,'priorAuditContents':identity(AUDIT/'CONTENTS.json'),'priorAuditSha256Sums':identity(AUDIT/'SHA256SUMS')},
 'recordedCommandFailuresRetained':sum(row['exitCode']!=0 for row in all_runs),'publicPayloadSecretFieldCheck':'passed active data plus private-PEM/raw-private-field rejection; synthetic secrets remain generator inputs only','expectedApplicationAcceptanceFlagCheck':'none in positive reference tuples or forbidden expected application fields',
 'environment':identity(ROOT/'docs/dnssec-expansion/numeric/runtime-and-licenses.json'),'pinnedRequirements':identity(ROOT/'tools/verification/dnssec-crypto/requirements.txt'),'noNewDependencySetup':True,
 'scope':{'numericExecutionOnly':True,'productionOrEvaluatorImported':False,'applicationBuildRegressionLintFormatterRun':False,'liveDnsServerOrInteroperabilityClaim':False,'tsigAuthenticationGrantsAclPermission':False,'macAndZoneDigestReferenceTuplesAreActualPositiveCalculations':True,'localAnchorChecksImplyHourlyNetworkReceipts':False,'hmacOpaqueKeyNamespaceIsDnskeyNamespace':False},
 'selectedContractNotes':components.get('selectedContractNotes',{}),
 'producerCommand':'python3 tools/verification/dnssec-crypto/post-freeze-completion/seal.py'}
raw=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(); catalog_path=OUT/'POST-FREEZE-COMPLETION-CATALOG.json'; immutable_write(catalog_path,raw)
files=[]
for root in [OUT,TOOLS]:
    for path in root.rglob('*'):
        if '__pycache__' in path.parts or path.is_dir() or path.name in ['CONTENTS.json','SHA256SUMS']:
            continue
        if path.is_symlink():
            raise RuntimeError('Unexpected retained completion symlink')
        files.append(identity(path))
files.sort(key=lambda row:row['path'])
contents={'schemaVersion':1,'kind':'dnssec-post-freeze-completion-retained-payload','postFreeze':True,'files':files,'fileCount':len(files),'payloadBytes':sum(row['bytes'] for row in files),'excludesSelfAndSha256Sums':True}
contents_raw=(json.dumps(contents,indent=2,sort_keys=True)+'\n').encode(); contents_path=OUT/'CONTENTS.json'; immutable_write(contents_path,contents_raw)
sums=''.join(row['sha256']+'  '+row['path']+'\n' for row in files)+hashlib.sha256(contents_raw).hexdigest()+'  '+str(contents_path.relative_to(ROOT))+'\n'; immutable_write(OUT/'SHA256SUMS',sums.encode())
print(json.dumps({'catalog':str(catalog_path.relative_to(ROOT)),'catalogBytes':len(raw),'catalogSha256':hashlib.sha256(raw).hexdigest(),'contentsSha256':hashlib.sha256(contents_raw).hexdigest(),'sha256SumsSha256':hashlib.sha256(sums.encode()).hexdigest(),'activeComponents':len(active),'payloadFiles':len(files),'payloadBytes':contents['payloadBytes'],'authorityInputsPreserved':len(frozen),'priorAuditPayloadPreserved':len(prior_audit),'failedCommandsRetained':summary['recordedCommandFailuresRetained']},indent=2))
