#!/usr/bin/env bun
/** Independent worksheet oracles over the real source snapshot/held/field consumers.
 * Does not build, fetch, run historical collectors, or claim browser/platform acceptance.
 * See --help for the permanent input and evidence contract.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const runner=fileURLToPath(import.meta.url);
const root=path.resolve(path.dirname(runner),'../..');
if(process.argv.includes('--help')||process.argv.includes('-h')){
  console.log(`Usage: bun tools/verification/run-next-expansion-contracts.mjs [--output DIRECTORY]
Requires integrated final source and an already built dist/auth-flow-studio.html. Bun only.
Default output: docs/verification/next-expansion-contracts (or AUTH_LAB_NEXT_CONTRACT_EVIDENCE_DIR).
Writes contracts-status.json and raw cases/*.json, with exact input/output SHA256 identities.
Does not modify source, invoke the build, or duplicate the existing dynamic all-choice collectors.
Run held-objects-check.mjs and compiled-bundle-smoke.mjs separately on these same inputs.
Independent worksheet row contract:
  modelProfile: {name: string, version: string}
  canonicalCases: [{id: 'default'|namedVariantId, assertions: [
    {at:{stepId:'actual-source-id',milestone:'complete'},target:'state',path:'namespace.field',equals:typedValue},
    {at:{stepId:'actual-source-id',milestone:'complete'},target:'holding',actorId,artifactId,representation:'plain',present:false}
  ]}]
Cursor forms: at:{milestone:'initial'}, at:{end:true,milestone:'complete'}, or exact stepId and authored milestone (including 'before').
No prose parsing or runtime-derived expected outcomes. Missing predicates are explicit contract failures.
Every case needs a state oracle; receipt/acceptance/knowledge/preserved-state predicates must be authored by its source-family owner.
Required source references need hash-checked HTTP200 captures. Explicit source.replacementEvidence:{sourceRowIds:[capturedAlternateIds],claimScope:string,excludedClaims:[string],reason:string} may bound an unavailable original to named successful primary captures; failed original bytes remain unverified evidence. No implicit URL aliases.
JSON schemaVersion 1: reconciliation, worksheetContracts, sourceDocuments, sourceEvidence, sourceGates, rows[].cases[], findings, rawErrors, inputs, outputs, sourceUnchanged, limits, passed.
This source-level offline result is not a numeric crypto, native OS, live interoperability, browser, G01, publication or historical-performance pass.`);
  process.exit(0);
}
const args=process.argv.slice(2);
let output=process.env.AUTH_LAB_NEXT_CONTRACT_EVIDENCE_DIR||'docs/verification/next-expansion-contracts';
for(let i=0;i<args.length;i++){
  if(args[i]==='--output'&&args[i+1])output=args[++i];
  else throw new TypeError('Unknown or incomplete argument: '+args[i]);
}
output=path.resolve(root,output);
for(const directory of ['src','tests','tools','docs/next-expansion']){
  const absolute=path.join(root,directory);
  if(output===absolute||output.startsWith(absolute+path.sep))throw new TypeError('Evidence output must not overlap an input tree.');
}
fs.mkdirSync(output,{recursive:false});
fs.mkdirSync(path.join(output,'cases'));
const sha=value=>createHash('sha256').update(value).digest('hex');
const relative=filename=>path.relative(root,filename).split(path.sep).join('/');
const digest=filename=>{const bytes=fs.readFileSync(filename);return {path:relative(filename),bytes:bytes.length,sha256:sha(bytes)};};
const report={schemaVersion:1,kind:'next-expansion-independent-canonical-contracts',timestamp:new Date().toISOString(),project:root,nativeBrowser:false,
  runtime:{executable:process.execPath,version:process.version,bun:process.versions.bun||null,versions:{...process.versions}},
  argv:[...process.argv],regenerationCommand:[process.execPath,...process.argv.slice(1)],runner:digest(runner),
  inputs:[],outputs:[],reconciliation:{},worksheetContracts:[],sourceDocuments:[],sourceEvidence:[],rows:[],findings:[],rawErrors:[],sourceUnchanged:false,passed:false,
  limits:{evidenceClass:'Fresh source-level offline canonical/held/field-consumer execution only.',
    nativePlatform:'Not executed by this collector; documentation snapshots do not establish installed OS/build, cluster or live interoperability.',
    crypto:'Authored symbolic protection/signature verdicts are not numerical or production cryptographic verification.',
    manualG01:'Open manual screen-reader speech/comprehension gate; not established by canonical execution.',
    preservedScopedClosures:'24 scoped historical closures must remain preserved; this collector does not independently re-close them.',
    historicalPerformance:'Seven predecessor flags remain open; current canonical correctness is not a performance comparison.',
    siblingKeyOrigins:'Six disclosed historical sibling-key-origin omissions remain explicit, not waived or closed.',
    allChoiceCollectors:[{command:'bun tools/verification/held-objects-check.mjs',status:'separate dynamic full-choice/Core collector, not executed here'},
      {command:'bun tools/verification/compiled-bundle-smoke.mjs',status:'separate emitted-bundle all-choice collector, not executed here'}]}};
let active=null;
function failure(code,error,context={}){
  const raw=error instanceof Error?{name:error.name,message:error.message,stack:error.stack,...(error.actual!==undefined?{actual:error.actual}:{}),...(error.expected!==undefined?{expected:error.expected}:{})}:{message:String(error)};
  const finding={id:'finding-'+String(report.findings.length+1).padStart(6,'0'),severity:'error',code,...context,...(active?{planId:active.planId,variantId:active.variantId}:{}),message:raw.message};
  report.findings.push(finding);report.rawErrors.push({findingId:finding.id,...raw});
  if(active)active.findings.push(finding.id);
}
function check(code,fn,context={}){try{return fn();}catch(error){failure(code,error,context);return undefined;}}
function unique(values,label){assert.ok(Array.isArray(values),label+' must be an array');assert.equal(new Set(values).size,values.length,label+' contains duplicate identities');return values;}
function sameSet(actual,expected,label){unique(actual,label+' actual');unique(expected,label+' expected');assert.deepEqual([...actual].sort(),[...expected].sort(),label);}
function readJSON(filename){return JSON.parse(fs.readFileSync(path.join(root,filename),'utf8'));}
function safePath(filename){assert.equal(typeof filename,'string');const absolute=path.resolve(root,filename);assert.ok(absolute.startsWith(root+path.sep),'Input escapes project: '+filename);return absolute;}
function tree(directory){return fs.readdirSync(directory,{withFileTypes:true}).filter(entry=>!['node_modules','.git'].includes(entry.name)).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(entry=>{
  const filename=path.join(directory,entry.name);assert.ok(!entry.isSymbolicLink(),'Input symlink not permitted: '+relative(filename));
  return entry.isDirectory()?tree(filename):entry.isFile()?[filename]:[];
});}
function captureInputs(){
  const files=['src','assets','tests','tools/verification','docs/next-expansion'].flatMap(name=>tree(path.join(root,name)));
  for(const name of ['index.html','build.mjs','security-policy.mjs','package.json','dist/auth-flow-studio.html'])if(fs.existsSync(path.join(root,name)))files.push(path.join(root,name));
  return new Map([...new Set(files)].sort().map(filename=>[filename,digest(filename)]));
}
function writeEvidence(filename,value){const absolute=path.join(output,filename);fs.writeFileSync(absolute,JSON.stringify(value,null,2)+'\n');const identity=digest(absolute);report.outputs.push(identity);return identity;}
function atPath(value,field){
  assert.ok(typeof field==='string'&&field.length,'State predicate requires a path');
  for(const part of field.split('.')){assert.ok(part&&!['__proto__','prototype','constructor'].includes(part),'Unsafe predicate path');if(value===null||typeof value!=='object'||!Object.hasOwn(value,part))return {exists:false};value=value[part];}
  return {exists:true,value};
}
const families=['nfs','windows-workstation','unix-workstation','jwt','kubernetes','mcp'];
let before=new Map(),harness;
try{
  assert.ok(process.versions.bun,'This collector requires Bun, not a Node fallback.');
  before=captureInputs();
  report.canonicalSourceFiles=Object.fromEntries([...before.values()].filter(item=>/^(?:src|assets|tests)\//.test(item.path)||['index.html','build.mjs','package.json','security-policy.mjs'].includes(item.path)).map(item=>[item.path,item.sha256]));
  const manifest=readJSON('docs/next-expansion/scenario-manifest.json');
  report.manifest=digest(path.join(root,'docs/next-expansion/scenario-manifest.json'));
  const ledger=readJSON('docs/next-expansion/source-ledger.json');
  const plan=readJSON('docs/next-expansion/plan-ledger.json');
  const baseline=manifest.provenance.baselineInventory;
  for(const [label,identity] of [['plan input',manifest.provenance.input],['baseline inventory',baseline]])check('manifest-input-identity',()=>{
    const filename=safePath(identity.path),observed=digest(filename);assert.equal(observed.sha256,identity.sha256,label);before.set(filename,observed);
  });
  check('built-html-input',()=>{report.html=digest(path.join(root,'dist/auth-flow-studio.html'));});
  check('ledger-provenance',()=>{
    assert.deepEqual(plan.provenance.input,manifest.provenance.input,'Plan and scenario ledger input identities');
    assert.deepEqual(ledger.provenance.input,manifest.provenance.input,'Source and scenario ledger input identities');
  });
  const core=manifest.scenarios.filter(row=>row.deliveryScope==='core'&&!row.optional);
  const optional=manifest.scenarios.filter(row=>row.optional);
  report.reconciliation.expectedRows=core.length;
  report.reconciliation.expectedChoiceCount=manifest.counts.plannedCoreTotal;
  check('frozen-manifest-counts',()=>{
    assert.deepEqual(manifest.counts,{baselineChoices:214,coreNewChoices:81,optionalNewChoices:4,plannedCoreTotal:295});
    assert.equal(core.length,manifest.counts.coreNewChoices);assert.equal(optional.length,manifest.counts.optionalNewChoices);
    unique(manifest.scenarios.map(row=>row.id),'Manifest plan IDs');unique(manifest.scenarios.map(row=>row.runtimeId),'Manifest runtime IDs');
    sameSet(optional.map(row=>row.id),manifest.optionalDeferred.map(row=>row.planId),'Optional identities');
    for(const row of manifest.optionalDeferred){assert.equal(row.status,'optional/deferred');assert.equal(row.includedInCoreTotal,false);}
    sameSet(core.map(row=>row.runtimeId).filter(id=>baseline.choiceIds.includes(id)),[],'New versus baseline collision');
    assert.equal(baseline.choiceIds.length,manifest.counts.baselineChoices);
  });
  const kubernetesFixtures=await import(pathToFileURL(path.join(root,'src/kubernetes-fixtures.js')).href);
  check('exact-kubernetes-plan-inputs',()=>{
    const exact=plan.originalPlanMetadata.jwtKubernetesMetadataAndManifests.manifestBundles;
    assert.deepEqual(kubernetesFixtures.K8S_PLAN_BUNDLES,exact.bundles);
    assert.deepEqual(kubernetesFixtures.K8S_PLAN_CONFIGURATIONS,exact.configurations);
  });
  check('kubernetes-release-and-implementation-bytes',()=>{
    const sources=readJSON('docs/next-expansion/kubernetes-sources.json'),support=readJSON('docs/next-expansion/kubernetes-support-evidence.json'),additional=[];
    for(const name of sources.additionalEvidence){const evidence=readJSON('docs/next-expansion/'+name);additional.push(...(evidence.sources||[]),...(evidence.source?[evidence.source]:[]),...(evidence.path?[evidence]:[]));}
    for(const record of [...sources.releaseIdentities,...sources.implementation,...support.implementation,...additional]){
      assert.equal(record.httpStatus,200,record.url);
      const actual=digest(safePath(record.path));assert.equal(actual.bytes,record.bytes,record.path);assert.equal(actual.sha256,record.sha256,record.path);
    }
    const tag=readJSON('docs/next-expansion/sources/kubernetes/release-tag.json'),published=readJSON('docs/next-expansion/sources/kubernetes/release-published.json');
    assert.equal(tag.tag,'v1.37.1');assert.equal(tag.object.sha,kubernetesFixtures.K8S_SOURCE_PROFILE.commit);
    assert.equal(published.tag_name,tag.tag);assert.equal(published.draft,false);assert.equal(published.prerelease,false);
  });
  report.limits.releaseGates=manifest.releaseGates;
  report.reconciliation.optionalDeferred=manifest.optionalDeferred;
  const worksheets=new Map();
  for(const family of families){
    const filename='docs/next-expansion/'+family+'-worksheet.json';
    const worksheet=check('worksheet-load',()=>readJSON(filename),{family,worksheet:filename});
    const sources=check('family-sources-load',()=>readJSON('docs/next-expansion/'+family+'-sources.json'),{family});
    if(!worksheet||!sources)continue;
    const rows=worksheet.rows||worksheet.scenarios;
    report.worksheetContracts.push({family,identity:digest(path.join(root,filename)),metadata:Object.fromEntries(Object.entries(worksheet).filter(([key])=>!['rows','scenarios'].includes(key)))});
    report.sourceDocuments.push({family,identity:digest(path.join(root,'docs/next-expansion/'+family+'-sources.json')),metadata:Object.fromEntries(Object.entries(sources).filter(([key])=>key!=='sources'))});
    check('worksheet-manifest-identity',()=>{
      if(worksheet.sourceManifestSha256)assert.equal(worksheet.sourceManifestSha256,digest(path.join(root,'docs/next-expansion/scenario-manifest.json')).sha256);
      unique(rows.map(row=>row.planId||row.id),family+' worksheet rows');
      for(const row of rows){const id=row.planId||row.id;assert.ok(core.some(entry=>entry.id===id),'Unexpected worksheet row '+id);assert.ok(!worksheets.has(id),'Colliding worksheet row '+id);worksheets.set(id,{family,row,filename});}
    },{family});
    const seenSourceIds=new Set();
    for(const source of sources.sources||[]){
      const sourceRowId=source.sourceRowId||source.id;
      check('source-row-collision',()=>{assert.ok(!seenSourceIds.has(sourceRowId),'Duplicate source evidence '+sourceRowId);seenSourceIds.add(sourceRowId);},{family,sourceRowId});
      const capture=source.capture?.sha256?source.capture:source.snapshot?.sha256?source.snapshot:source;
      const filename=capture.capturedPath||capture.path||source.snapshotReference;
      const evidence={family,sourceRowId,status:source.sourceSnapshotStatus||source.snapshotStatus||source.status||'explicitly-unverified',httpStatus:capture.httpStatus??capture.status??source.httpStatus??null,metadata:source,identity:null,successfulCapture:false};
      report.sourceEvidence.push(evidence);
      if(capture.sha256&&filename)check('source-snapshot-identity',()=>{
        evidence.identity=digest(safePath(filename));assert.equal(evidence.identity.sha256,capture.sha256,sourceRowId+' captured bytes');
        if(capture.bytes!==undefined)assert.equal(evidence.identity.bytes,capture.bytes,sourceRowId+' captured size');
        assert.ok(capture.finalUrl||source.finalUrl,sourceRowId+' requires final URL provenance');
        before.set(safePath(filename),evidence.identity);
        evidence.successfulCapture=evidence.httpStatus===200;
        if(!evidence.successfulCapture)evidence.unverifiedReason='Captured attempt bytes are not a successful source document (HTTP '+evidence.httpStatus+').';
      },{family,sourceRowId});
      else evidence.unverifiedReason='No captured bytes/hash pair. Not counted as runtime or platform proof.';
    }
  }
  check('worksheet-coverage',()=>sameSet([...worksheets.keys()],core.map(row=>row.id),'Independent worksheet core coverage'));
  report.sourceGates=[];
  for(const expected of core){
    const entry=worksheets.get(expected.id);
    if(!entry)continue;
    for(const sourceRowId of expected.sourceRowIds){
      const gate={planId:expected.id,family:entry.family,sourceRowId,status:'unverified'};report.sourceGates.push(gate);
      check('required-source-prerequisite',()=>{
        const matches=report.sourceEvidence.filter(item=>item.family===entry.family&&item.sourceRowId===sourceRowId);
        assert.equal(matches.length,1,'Missing/colliding required source evidence '+sourceRowId);
        const source=matches[0];
        if(source.successfulCapture){gate.status='captured-successful-source';gate.identity=source.identity;return;}
        const replacement=source.metadata.replacementEvidence;
        assert.ok(replacement,'Required source '+sourceRowId+' has no successful capture or explicit claim-limited replacementEvidence');
        assert.ok(typeof replacement.claimScope==='string'&&replacement.claimScope.length,'Alternate requires explicit independent claim scope');
        assert.ok(typeof replacement.reason==='string'&&replacement.reason.length,'Alternate requires original failure disposition');
        assert.ok(Array.isArray(replacement.excludedClaims)&&replacement.excludedClaims.length,'Alternate requires explicit excluded platform/default claims');
        unique(replacement.sourceRowIds,'Alternate source identities');assert.ok(replacement.sourceRowIds.length,'Empty alternate source mapping');
        gate.replacementEvidence=replacement;gate.replacementIdentities=[];
        for(const id of replacement.sourceRowIds){
          assert.notEqual(id,sourceRowId,'Unavailable source cannot replace itself');
          const alternatives=report.sourceEvidence.filter(item=>item.family===entry.family&&item.sourceRowId===id);
          assert.equal(alternatives.length,1,'Alternate evidence missing/colliding '+id);
          assert.equal(alternatives[0].successfulCapture,true,'Alternate is not a captured successful source '+id);
          gate.replacementIdentities.push(alternatives[0].identity);
        }
        gate.status='mapped-alternate-claim-limited';
      },{planId:expected.id,family:entry.family,sourceRowId});
    }
  }
  const api=await import('./held-object-fixtures.mjs');harness=api.heldFixtureHarness;
  const catalog=await import(pathToFileURL(path.join(root,'src/lab-catalog.js')).href);
  const {ATTRIBUTES}=await import(pathToFileURL(path.join(root,'src/protocol-data.js')).href);
  const held=await import(pathToFileURL(path.join(root,'src/held-objects.js')).href);
  const {HeldObjectView}=await import(pathToFileURL(path.join(root,'src/held-object-view.js')).href);
  const state=await import(pathToFileURL(path.join(root,'src/held-object-state.js')).href);
  const protocol=await import(pathToFileURL(path.join(root,'src/protocol-state.js')).href);
  const usage=await import(pathToFileURL(path.join(root,'src/attribute-usage.js')).href);
  const {buildAttributeTrace}=await import(pathToFileURL(path.join(root,'src/attribute-trace.js')).href);
  const {FlowPlayer,pairKey,resolveActor}=await import(pathToFileURL(path.join(root,'src/player.js')).href);
  report.reconciliation.actualChoiceIds=[...api.HELD_OBJECT_CHOICES];
  check('catalog-id-reconciliation',()=>{
    unique(catalog.LAB_SCENARIOS.map(model=>model.id),'Registered lab model IDs');
    sameSet(api.HELD_OBJECT_CHOICES,[...baseline.choiceIds,...core.map(row=>row.runtimeId)],'Baseline plus frozen core choices');
    assert.equal(api.HELD_OBJECT_CHOICES.length,manifest.counts.plannedCoreTotal);
    for(const row of optional)assert.ok(!api.HELD_OBJECT_CHOICES.includes(row.runtimeId),'Deferred row unexpectedly registered '+row.id);
  });
  const seek=(compiled,queue,index,progress)=>{
    assert.ok(index>=0&&index<queue.length,'Playback row absent');
    const player=new FlowPlayer({requestFrame:()=>null,cancelFrame:()=>{}});
    const elapsed=player.totalDuration(queue.slice(0,index))+player.totalDuration([queue[index]])*progress;
    player.seek(queue,elapsed/player.totalDuration(queue),'verification');
    const snapshot=player.snapshot();
    return state.projectHeldObjects(compiled,state.heldCursorForPlayback(compiled,snapshot,snapshot.step));
  };
  for(const expected of core){
    const entry=worksheets.get(expected.id),base=catalog.LAB_MODELS[expected.runtimeId];
    const rowReport={planId:expected.id,runtimeId:expected.runtimeId,workspace:expected.workspace,family:expected.family,worksheet:entry?.filename||null,cases:[],findings:[]};report.rows.push(rowReport);
    const rowStart=report.findings.length;
    check('required-runtime-row',()=>assert.ok(base,'Missing actual registered model '+expected.runtimeId),{planId:expected.id});
    if(!entry||!base){rowReport.status='failed';continue;}
    const independent=entry.row;
    check('row-identity',()=>{
      assert.equal(independent.runtimeId,expected.runtimeId);assert.equal(base.id,expected.runtimeId);
      assert.equal(base.workspace,expected.workspace);assert.equal(base.family,expected.family);
      if(independent.family)assert.equal(independent.family,expected.family);
      sameSet(independent.sourceRowIds||independent.sourceRows,expected.sourceRowIds,'Worksheet source references '+expected.id);
      sameSet(ledger.scenarioSourceReferences[expected.id],expected.sourceRowIds,'Independent source ledger '+expected.id);
      assert.ok(independent.modelProfile&&typeof independent.modelProfile==='object','Missing contract '+entry.filename+' row '+expected.id+'.modelProfile {name,version}');
      for(const key of ['name','version']){assert.ok(Object.hasOwn(independent.modelProfile,key),'Missing modelProfile.'+key);assert.deepEqual(base.profile?.[key],independent.modelProfile[key],'Independent profile '+key);}
      for(const key of ['publicationStatus','supportStatus','implementation','assumptions','transports','completion','algorithms','cryptoDetail','sources'])assert.ok(base.profile&&Object.hasOwn(base.profile,key),'Missing runtime profile field '+key);
      const sourceEvidence=report.sourceEvidence.filter(source=>source.family===entry.family);
      for(const id of expected.sourceRowIds)assert.equal(sourceEvidence.filter(source=>source.sourceRowId===id).length,1,'Missing/colliding source evidence '+id);
    },{planId:expected.id});
    const declaredCaseIds=['default'];
    for(const key of ['namedCases','negativeCases','additionalCases','cases'])if(Array.isArray(independent[key])){
      const named=independent[key].filter(value=>value&&typeof value==='object'&&value.id).map(value=>value.id);
      check('worksheet-case-collision',()=>unique(named,expected.id+'.'+key),{planId:expected.id});
      for(const id of named)if(!declaredCaseIds.includes(id))declaredCaseIds.push(id);
    }
    const oracleCases=Array.isArray(independent.canonicalCases)?independent.canonicalCases:[];
    const actualCases=Array.isArray(base.variantChoices)?base.variantChoices.map(choice=>choice.id):[];
    check('case-contract-reconciliation',()=>{
      assert.ok(oracleCases.length,'Missing contract '+entry.filename+' row '+expected.id+'.canonicalCases');
      sameSet(oracleCases.map(item=>item.id),declaredCaseIds,expected.id+' source cases versus machine oracles');
      sameSet(actualCases,declaredCaseIds,expected.id+' actual variants versus independent cases');
      assert.equal(typeof base.withVariant,'function','Required actual immutable model variant constructor');
      assert.throws(()=>base.withVariant('__unknown_contract_case__'),RangeError);
    },{planId:expected.id});
    // Union retains unexpected variants and missing runtime variants as evidence, never silently skips a case.
    const caseIds=[...new Set([...declaredCaseIds,...actualCases,...oracleCases.map(item=>item.id)])];
    for(const variantId of caseIds){
      const result={planId:expected.id,variantId,findings:[],assertions:[],checks:[],rawEvidence:null};active=result;rowReport.cases.push(result);
      const raw={schemaVersion:1,planId:expected.id,runtimeId:expected.runtimeId,variantId,worksheet:entry.filename,oracle:oracleCases.find(item=>item.id===variantId)||null};
      let fixture,compiled,model;
      check('canonical-model',()=>{
        assert.ok(actualCases.includes(variantId),'Required variant missing '+variantId);
        fixture=api.makeHeldObjectFixture(expected.runtimeId,{lessonVariant:variantId});model=fixture.model;
        assert.ok(model,'Application did not resolve model');assert.equal(model.id,expected.runtimeId);assert.equal(model.variantId,variantId);
        assert.equal(fixture.app.lessonVariant,variantId);
        const expectedProfile=raw.oracle?.modelProfile||independent.modelProfile;
        assert.ok(expectedProfile&&typeof expectedProfile==='object','Missing independent case profile identity');
        for(const key of ['name','version']){
          assert.ok(Object.hasOwn(expectedProfile,key),'Missing independent case modelProfile.'+key);
          assert.deepEqual(model.profile?.[key],expectedProfile[key],'Independent case profile '+key);
        }
        raw.expectedProfile=expectedProfile;
        const source=fixture.app.scenarioSnapshot();
        model={...model,initialState:source.initialState||model.initialState,protocolValues:source.protocolValues||model.protocolValues};
        unique(fixture.steps.map(step=>step.id),'Actual canonical source IDs');assert.ok(fixture.steps.length,'No authored canonical steps');
        // held-object-fixtures imports the real app, which performs production
        // glossary registration. Never patch missing variant definitions here.
        const definitions=model.definitions(fixture.config);
        for(const step of fixture.steps)for(const op of step.attributeOperations||[]){
          assert.ok(Object.hasOwn(catalog.LAB_ATTRIBUTES,op.attributeId),'Variant field missing from registered family export '+op.attributeId);
          assert.ok(Object.hasOwn(ATTRIBUTES,op.attributeId),'Missing real application glossary definition '+op.attributeId);
        }
        raw.profile=model.profile;raw.supportNote=model.supportNote;raw.configuration=fixture.config;raw.contextId=fixture.contextId;
        raw.steps=fixture.steps;raw.initialState=protocol.reconstructProtocolState({...model,steps:()=>fixture.steps},-1);
        raw.definitions=definitions;
        raw.fixtureInputs=model.fixtureInputs||model.fixture||null;
        result.checks.push('actual-application-snapshot-and-real-glossary');
      });
      if(fixture&&model){
        const sourceModel={...model,steps:()=>fixture.steps};
        check('protocol-provenance',()=>{
          const validation=protocol.validateProtocolScenario(sourceModel);raw.protocolValidation=validation;
          assert.deepEqual(validation.errors,[],'Canonical protocol validation');
          assert.deepEqual(validation.warnings,[],'New authored occurrences require exact representation/value metadata');
          const instances=protocol.buildProtocolInstances(sourceModel,fixture.steps.length-1);raw.protocolInstances=instances;
          for(const step of fixture.steps)for(const operation of step.attributeOperations||[]){
            for(const key of ['instanceId','fieldPath','representation','sourceEventId','exactValueRef','creator','holders','inspectors'])assert.ok(Object.hasOwn(operation,key),'Missing occurrence provenance '+step.id+'.'+key);
            const record=instances.find(instance=>instance.instanceId===operation.instanceId);assert.ok(record,'Actual instance consumer lost occurrence');
            const occurrence=record.occurrences.find(item=>item.eventId===step.id&&item.operationIndex===(step.attributeOperations||[]).indexOf(operation));
            assert.ok(occurrence,'Exact occurrence absent');
            const exact=Object.hasOwn(operation,'value')?operation.value:(typeof model.protocolValues==='function'?model.protocolValues():model.protocolValues||{})[operation.exactValueRef];
            assert.deepEqual(occurrence.value,exact,'Exact value consumer provenance');
            if(['create','derive'].includes(operation.kind))assert.equal(operation.actorId,operation.creator,'Create/derive must be actual creator-local, even on another actor carrier');
          }
          result.checks.push('canonical-instance-field-value-representation-provenance');
        });
        check('held-builder-coverage',()=>{
          const view={app:fixture.app,memo:new WeakMap(),expanded:new Set()};
          compiled=HeldObjectView.prototype.compiled.call(view);assert.ok(compiled,'Actual application family builder missing');state.assertHeldObjectCoverage(compiled);
          assert.deepEqual(compiled.steps,fixture.steps,'Application held view must compile exact canonical source');
          fixture.contextId=compiled.contextId;raw.contextId=compiled.contextId;
          raw.plan=compiled.plan;raw.planManifest=held.describeHeldObjectPlan(compiled,{choiceId:fixture.choiceId,model,configuration:fixture.config});
          sameSet(Object.keys(compiled.plan.events),fixture.steps.map(step=>step.id),'Explicit inventory/source event reconciliation');
          result.checks.push('actual-registered-held-builder-and-complete-coverage');
        });
        check('real-field-consumers',()=>{
          const ids=[...new Set(fixture.steps.flatMap(step=>(step.attributeOperations||[]).map(operation=>operation.attributeId)))];raw.fieldConsumers=[];
          for(const id of ids){
            const usages=usage.getAttributeUsage(fixture.steps,id,fixture.config.authenticator),contexts=usage.getAttributeContext(fixture.steps,id,fixture.config.authenticator);
            const trace=buildAttributeTrace(usages,model.examples?.(fixture.config)||{},typeof model.protocolValues==='function'?model.protocolValues():model.protocolValues||{});
            const expectedOps=fixture.steps.flatMap((step,index)=>usage.getStepAttributeOperations(step,fixture.config.authenticator).filter(op=>op.attributeId===id&&op.kind!=='inspect').map(op=>({index,op})));
            const observedOps=usages.flatMap(item=>item.actions.map(op=>({index:item.index,op})));
            assert.deepEqual(observedOps,expectedOps,'Real usage consumer must retain all replayable operations '+id);
            for(const context of contexts)assert.ok(context.actions.every(action=>action.kind==='inspect'),'Genuine inspection remains non-replay context');
            assert.ok(!trace.some(row=>row.traceKind==='inspect'),'Genuine inspect must not become replay');
            for(const row of trace){
              assert.equal(row.sourceStepId,fixture.steps[row.sourceIndex]?.id,'Field trace source prefix');
              for(const payload of row.payload){
                const operation=row.traceActions.find(action=>action.attributeId===payload.attributeId);assert.ok(operation);
                const exact=Object.hasOwn(operation,'value')?operation.value:(typeof model.protocolValues==='function'?model.protocolValues():model.protocolValues||{})[operation.exactValueRef];
                assert.deepEqual(payload.value,exact,'Trace must preserve exact operation value, not glossary example');
                if(['create','derive'].includes(row.traceKind)){assert.equal(row.from,operation.creator);assert.equal(row.to,operation.creator);}
              }
            }
            raw.fieldConsumers.push({attributeId:id,usages,contexts,trace});
          }
          result.checks.push('real-field-usage-context-and-exact-value-trace-consumers');
        });
        if(compiled){
          check('message-and-creation-custody',()=>{
            // Initial fixtures seed pre-existing lineage and current copies. A
            // cached issued token does not require an issuer-retained copy.
            // New event-local creation still requires creator custody below.
            for(const step of fixture.steps){
              const index=fixture.steps.indexOf(step),event=compiled.plan.events[step.id];
              for(const operation of step.attributeOperations||[]){
                const artifact=compiled.plan.artifacts.find(item=>item.artifactId===operation.instanceId);
                if(!artifact)continue; // Explicit protocol-only event records are not invented held credentials.
                assert.equal(operation.creator,artifact.creator,'Protocol/held creator provenance mismatch');
                const representation=artifact.representations.find(item=>item.representationId===operation.representation);
                assert.ok(representation,'Protocol occurrence references missing held representation');
                const field=representation.fields.find(item=>item.attributeId===operation.attributeId);
                assert.ok(field,'Protocol occurrence references missing exact held field');
                const exact=Object.hasOwn(operation,'value')?operation.value:(typeof model.protocolValues==='function'?model.protocolValues():model.protocolValues||{})[operation.exactValueRef];
                assert.deepEqual(exact,field.value,'Protocol/held exact-value provenance mismatch');
              }
              for(const message of event.messages||[]){
                const delivered=state.projectHeldObjects(compiled,{eventIndex:index,progress:message.end});
                for(const object of message.objects){
                  const actions=step.attributeOperations||[];
                  for(const [kind,actorId] of [['send',message.from],['receive',message.to]])assert.ok(actions.some(operation=>operation.kind===kind&&operation.actorId===actorId&&operation.instanceId===object.artifactId&&operation.representation===object.representationId),'Message has no exact '+kind+' occurrence '+object.artifactId);
                  assert.ok(delivered.holdings.some(item=>item.actorId===message.to&&item.artifactId===object.artifactId&&item.representationId===object.representationId),'Message receipt has no exact receiver representation '+object.artifactId);
                  const sent=state.projectHeldObjects(compiled,{eventIndex:index,progress:message.start});
                  assert.ok(sent.holdings.some(item=>item.actorId===message.from&&item.artifactId===object.artifactId&&item.representationId===object.representationId),'Message sender lacks exact representation custody at transfer start '+object.artifactId);
                }
              }
            }
            result.checks.push('exact-message-receipt-and-creator-local-custody');
          });
          check('prefix-and-inspection-parity',()=>{
            let comparisons=0;raw.checkpoints=[];raw.exactObjectTraces=[];
            for(let index=0;index<fixture.steps.length;index++){
              const step=fixture.steps[index],event=compiled.plan.events[step.id];
              const complete=state.projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});
              assert.deepEqual(complete.state,protocol.reconstructProtocolState(sourceModel,index),'Held/source canonical prefix '+step.id);
              const milestones=[{id:'before',at:0},...event.milestones];
              for(const milestone of milestones){
                const cursor={eventIndex:index,milestone:milestone.id},snapshot=state.projectHeldObjects(compiled,cursor);
                raw.checkpoints.push({cursor,sha256:sha(JSON.stringify(snapshot)),state:snapshot.state,holdings:snapshot.holdings});
                for(const holding of snapshot.holdings){
                  const inspected=state.inspectHeldObject(snapshot,holding.holdingId);assert.ok(inspected);
                  const artifact=compiled.plan.artifacts.find(item=>item.artifactId===holding.artifactId);
                  const representation=artifact.representations.find(item=>item.representationId===holding.representationId);
                  for(const field of inspected.fields){
                    const original=representation.fields.find(item=>item.attributeId===field.attributeId);
                    const allowed=representation.readableBy.includes(holding.actorId)&&(!original.readableBy||original.readableBy.includes(holding.actorId));
                    assert.equal(field.readable,allowed);
                    if(allowed)assert.deepEqual(field.value,original.value);else{assert.equal(field.redacted,true);assert.equal(Object.hasOwn(field,'value'),false,'Protected/nonpermitted field leaks through inspect');}
                  }
                }
              }
              const progressPoints=[...new Set([.3,.9,...event.milestones.filter(item=>item.at>0&&item.at<1).map(item=>item.at)])];
              for(const progress of progressPoints){
                const expectedSnapshot=state.projectHeldObjects(compiled,{eventIndex:index,progress});
                assert.deepEqual(seek(compiled,fixture.steps,index,progress),expectedSnapshot,'Full replay equal actual source cursor');
                const key=pairKey(resolveActor(step.from,fixture.config.authenticator),resolveActor(step.to,fixture.config.authenticator));
                const filtered=fixture.steps.filter(candidate=>pairKey(resolveActor(candidate.from,fixture.config.authenticator),resolveActor(candidate.to,fixture.config.authenticator))===key);
                assert.deepEqual(seek(compiled,filtered,filtered.indexOf(step),progress),expectedSnapshot,'Filtered replay includes hidden canonical predecessors');comparisons+=2;
              }
              for(const milestone of event.milestones)for(const effect of milestone.effects)if(effect.op==='create'){
                const artifact=compiled.plan.artifacts.find(item=>item.artifactId===effect.artifactId);
                const snapshot=state.projectHeldObjects(compiled,{eventIndex:index,milestone:milestone.id});
                assert.ok(snapshot.holdings.some(holding=>holding.artifactId===artifact.artifactId&&holding.actorId===artifact.creator),'Declared create has no actual creator-local holding '+artifact.artifactId);
              }
            }
            for(const artifact of compiled.plan.artifacts){
              const trace=state.heldObjectTrace(compiled,artifact.artifactId);raw.exactObjectTraces.push({artifactId:artifact.artifactId,trace});
              for(const row of trace){
                const selected=state.heldCursorForPlayback(compiled,{status:'idle',step:row},row,{selected:true});
                assert.deepEqual(state.projectHeldObjects(compiled,selected),state.projectHeldObjects(compiled,row.heldCursorEnd),'Exact-object selected actual cursor');comparisons++;
                for(const progress of [.3,.9])assert.deepEqual(seek(compiled,[row],0,progress),state.projectHeldObjects(compiled,state.heldCursorForPlayback(compiled,{status:'playing',step:row,duration:1,stepElapsed:progress},row)),'Exact-object playback cursor');
              }
            }
            result.equalCursorComparisons=comparisons;result.checks.push('full-filtered-exact-source-prefix-and-inspection-parity');
          });
          const oracle=raw.oracle;
          check('independent-case-contract',()=>{
            assert.ok(oracle,'Missing independent canonical case '+expected.id+'/'+variantId);
            assert.ok(Array.isArray(oracle.assertions)&&oracle.assertions.some(item=>item.target==='state'),'Missing meaningful typed canonical state predicate '+expected.id+'/'+variantId);
            unique(oracle.assertions.map(item=>JSON.stringify(item)),expected.id+'/'+variantId+' duplicate predicates');
            if(oracle.firstDetector&&typeof oracle.firstDetector==='object'){
              assert.equal(typeof oracle.firstDetector.stepId,'string','First detector requires exact stepId');
              assert.ok(fixture.steps.some(step=>step.id===oracle.firstDetector.stepId),'Independent first-detector event missing '+oracle.firstDetector.stepId);
            }
            const acceptance=independent.acceptanceCases?.find(item=>item.variantId===variantId);
            if(acceptance){
              raw.acceptanceContract=acceptance;
              const eventId=id=>independent.eventIdPrefix?independent.eventIdPrefix+id:id;
              if(independent.eventIdPrefix)assert.equal(independent.eventIdPrefix,expected.runtimeId+':','Explicit event-prefix identity');
              for(const id of acceptance.requiredEvents||[])assert.ok(fixture.steps.some(step=>step.id===eventId(id)),'Independent required event missing '+eventId(id));
              for(const id of acceptance.forbiddenEvents||[])assert.ok(!fixture.steps.some(step=>step.id===eventId(id)),'Independent forbidden later event reached '+eventId(id));
              const final=protocol.reconstructProtocolState(sourceModel,fixture.steps.length-1);
              for(const [field,value] of Object.entries({...acceptance.expectedFinal,...acceptance.preserved})){
                const actual=atPath(final,field);assert.ok(actual.exists,'Independent acceptance path absent '+field);assert.deepEqual(actual.value,value,'Independent acceptance/preserved-state predicate '+field);
              }
            }
          });
          for(const [assertionIndex,predicate] of (oracle?.assertions||[]).entries()){
            const observation={assertionIndex,predicate,passed:false};result.assertions.push(observation);
            check('independent-oracle',()=>{
              const at=predicate.at;assert.ok(at&&typeof at==='object','Predicate requires explicit cursor');
              let index;
              if(at.milestone==='initial'){assert.equal(at.stepId,undefined);assert.ok(!at.end);index=-1;}
              else if(at.end===true){assert.equal(at.stepId,undefined);index=fixture.steps.length-1;}
              else{assert.equal(typeof at.stepId,'string');index=fixture.steps.findIndex(step=>step.id===at.stepId);assert.ok(index>=0,'Independent predicate names missing source event '+at.stepId);}
              const milestone=at.milestone||'complete';
              assert.ok(index===-1||milestone==='before'||compiled.plan.events[fixture.steps[index].id].milestones.some(item=>item.id===milestone),'Independent predicate names missing milestone '+milestone);
              const snapshot=state.projectHeldObjects(compiled,{eventIndex:index,milestone});observation.cursor=snapshot.cursor;observation.snapshotSha256=sha(JSON.stringify(snapshot));
              if(predicate.target==='state'){
                assert.ok(Object.hasOwn(predicate,'equals'),'Typed state predicate needs equals, not prose');
                const actual=atPath(snapshot.state,predicate.path);assert.ok(actual.exists,'Missing canonical state path '+predicate.path);observation.actual=actual.value;
                assert.deepEqual(actual.value,predicate.equals,'Independent state oracle '+predicate.path);
              }else if(predicate.target==='holding'){
                assert.equal(typeof predicate.present,'boolean');assert.ok(Object.hasOwn(compiled.plan.actors,predicate.actorId),'Unknown oracle actor '+predicate.actorId);
                assert.ok(typeof predicate.artifactId==='string'&&predicate.artifactId.length,'Holding oracle must name exact artifact identity');
                const artifact=compiled.plan.artifacts.find(item=>item.artifactId===predicate.artifactId);
                const representation=predicate.representation;assert.ok(typeof representation==='string'&&representation.length,'Holding oracle must name exact representation');
                // An independent denial oracle can name the success object that
                // must never be created. Do not manufacture it to test absence.
                observation.definitionPresent=!!artifact;
                if(predicate.present)assert.ok(artifact,'Required oracle artifact is not authored '+predicate.artifactId);
                if(artifact&&predicate.present)assert.ok(artifact.representations.some(item=>item.representationId===representation),'Required oracle representation is not authored '+representation);
                observation.actual=snapshot.holdings.filter(item=>item.actorId===predicate.actorId&&item.artifactId===predicate.artifactId&&item.representationId===representation);
                assert.equal(observation.actual.length>0,predicate.present,'Independent exact custody oracle');
              }else throw new TypeError('Unsupported independent predicate target '+predicate.target);
              observation.passed=true;
            },{assertionIndex});
          }
        }
      }
      result.status=result.findings.length?'failed':'passed';raw.result=result;
      result.rawEvidence=writeEvidence('cases/'+encodeURIComponent(expected.id)+'--'+encodeURIComponent(variantId)+'.json',raw);
      active=null;
    }
    rowReport.findings=report.findings.slice(rowStart).map(item=>item.id);rowReport.status=rowReport.findings.length?'failed':'passed';
  }
}catch(error){failure('collector-exception',error);}
finally{
  active=null;
  check('source-unchanged',()=>{
    const after=captureInputs();
    for(const [filename,identity]of before){const current=after.get(filename)||digest(filename);assert.equal(current.sha256,identity.sha256,'Input changed during collection '+identity.path);assert.equal(current.bytes,identity.bytes);}
    const inputTreeBefore=[...before.keys()].filter(filename=>['src','assets','tests','tools/verification','docs/next-expansion'].some(directory=>filename.startsWith(path.join(root,directory)+path.sep)));
    const inputTreeAfter=[...after.keys()].filter(filename=>['src','assets','tests','tools/verification','docs/next-expansion'].some(directory=>filename.startsWith(path.join(root,directory)+path.sep)));
    sameSet(inputTreeAfter,inputTreeBefore,'Source tree membership unchanged');report.sourceUnchanged=true;
  });
  report.inputs=[...before.values()];
  check('unexpected-output-evidence',()=>{
    const expected=new Set(report.outputs.map(item=>path.resolve(root,item.path)));
    for(const filename of tree(path.join(output,'cases')))assert.ok(expected.has(filename),'Unexpected/stale case evidence '+filename);
  });
  report.summary={requiredRows:report.reconciliation.expectedRows??null,observedRows:report.rows.length,observedCases:report.rows.reduce((sum,row)=>sum+row.cases.length,0),passedCases:report.rows.flatMap(row=>row.cases).filter(item=>item.status==='passed').length,failedCases:report.rows.flatMap(row=>row.cases).filter(item=>item.status!=='passed').length,sourceSnapshots:report.sourceEvidence.filter(item=>item.successfulCapture).length,explicitlyUnverifiedSources:report.sourceEvidence.filter(item=>!item.successfulCapture).map(item=>({family:item.family,sourceRowId:item.sourceRowId,status:item.status,httpStatus:item.httpStatus,reason:item.unverifiedReason})),findings:report.findings.length};
  report.passed=report.sourceUnchanged&&report.rows.length===report.reconciliation.expectedRows&&report.findings.length===0;
  report.status=report.passed?'passed':report.rows.length===report.reconciliation.expectedRows?'failed':'partial';
  report.exitCode=report.passed?0:1;
  if(harness){harness.clock.frames.clear();harness.clock.timers.clear();}
  fs.writeFileSync(path.join(output,'contracts-status.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({passed:report.passed,...report.summary,sourceUnchanged:report.sourceUnchanged,report:path.join(output,'contracts-status.json')},null,2));
  if(!report.passed)process.exitCode=1;
}
