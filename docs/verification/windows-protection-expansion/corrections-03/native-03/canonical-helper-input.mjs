import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {LAB_SCENARIOS,LAB_MODELS,LAB_ATTRIBUTES} from '../../src/lab-catalog.js';
import {buildWindowsRemoteAdministrationFixture} from '../../src/windows-remote-administration-lab.js';
import {buildWindowsProtectionFixture,buildWindowsProtectionSubfixture} from '../../src/windows-protection-lab.js';
import {createPamFoundationsCase} from '../../src/pam-foundations-lab.js';
import {buildHeldObjects} from '../../src/held-objects.js';
import {projectHeldObjects,heldObjectTrace,heldCursorForPlayback,inspectHeldObject,assertHeldObjectCoverage} from '../../src/held-object-state.js';
import {reconstructProtocolState} from '../../src/protocol-state.js';
import {ATTRIBUTES} from '../../src/protocol-data.js';
import {getAttributeUsage} from '../../src/attribute-usage.js';
import {buildAttributeTrace} from '../../src/attribute-trace.js';

const wpcRoot=fileURLToPath(new URL('../../',import.meta.url));
const wpcHash=value=>createHash('sha256').update(value).digest('hex');
const wpcJson=name=>JSON.parse(fs.readFileSync(path.join(wpcRoot,name),'utf8'));
const wpcIdentity=name=>{const bytes=fs.readFileSync(path.join(wpcRoot,name));return {path:name,bytes:bytes.length,sha256:wpcHash(bytes)};};
function wpcFiles(directory){
  return fs.readdirSync(path.join(wpcRoot,directory),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(entry=>{
    assert.equal(entry.isSymbolicLink(),false,'No symbolic review input: '+directory+'/'+entry.name);
    const name=directory+'/'+entry.name;
    assert.ok(entry.isDirectory()||entry.isFile(),'Regular review input: '+name);
    return entry.isDirectory()?wpcFiles(name):[name];
  });
}
function wpcReviewIdentity(){
  const names=['index.html','build.mjs','package.json','security-policy.mjs',...wpcFiles('src'),...wpcFiles('assets'),...wpcFiles('tests')].sort();
  return {sourceFiles:Object.fromEntries(names.map(name=>[name,wpcIdentity(name).sha256])),standaloneSha256:wpcIdentity('dist/auth-flow-studio.html').sha256,runner:wpcIdentity('tools/verification/windows-protection-canonical.mjs')};
}
const wpcModelId=caseId=>'lab-'+caseId.split('/')[0].toLowerCase();
const wpcVariant=caseId=>caseId.split('/')[1];
const wpcNewModel=model=>/^lab-(?:wra0[1-5]|wprot0[1-5]|pam01)$/.test(model.id);

// These are executable entry points, not another expected-answer implementation.
// Canonical/default comparison overlap is recorded once under its actual member ID.
function wpcSpecs(){
  const remote=wpcJson('docs/windows-protection-expansion/remote-cases.json');
  const protection=wpcJson('docs/windows-protection-expansion/protection-cases.json');
  const pam=wpcJson('docs/pam-foundations/expectations.json');
  return [
    ...remote.cases.flatMap(row=>row.subfixtures.map(member=>({caseId:row.id,memberId:member.id,canonical:member.id===row.defaultSubfixtureId,create:()=>buildWindowsRemoteAdministrationFixture(row.modelId,wpcVariant(row.id),member.id)}))),
    ...protection.cases.map(row=>({caseId:row.id,canonical:true,create:()=>buildWindowsProtectionFixture(row.modelId,wpcVariant(row.id))})),
    ...protection.subfixtures.map(row=>({caseId:row.caseId,memberId:row.id,canonical:false,create:()=>buildWindowsProtectionSubfixture(row.id)})),
    ...pam.cases.map(row=>({caseId:row.caseId,canonical:true,create:()=>createPamFoundationsCase(wpcVariant(row.caseId))})),
    ...pam.subfixtures.map(row=>({caseId:'PAM01/'+row.case,memberId:row.id,canonical:false,create:()=>createPamFoundationsCase(row.case,row.id)})),
  ];
}

function wpcHolding(holding,snapshot){
  const inspected=inspectHeldObject(snapshot,holding.holdingId);
  return {actorId:holding.actorId,artifactId:holding.artifactId,representationId:holding.representationId,store:holding.store,retention:holding.retention,fields:inspected?.fields||[]};
}
export function windowsProtectionFrame(snapshot){
  return {clock:snapshot.protocolClock,state:snapshot.state.workstation,holdings:snapshot.holdings.map(holding=>wpcHolding(holding,snapshot))};
}

function wpcCheckFixture(model,record){
  const steps=model.steps(),actors=model.actors(),union=new Set(model.catalogAttributeIds||model.ids),source=model.workstationInventory;
  assert.equal(model.id,wpcModelId(record.caseId),'registered model identity');
  assert.equal(model.variantId,wpcVariant(record.caseId),'registered named case identity');
  for(const id of model.ids){assert.ok(union.has(id),'variant field outside declared union: '+id);assert.ok(LAB_ATTRIBUTES[id],'undeclared variant field: '+id);}
  for(const step of steps)for(const operation of step.attributeOperations||[]){assert.ok(union.has(operation.attributeId),'operation outside field union: '+operation.attributeId);assert.ok(source.events[operation.sourceEventId],'operation lacks canonical source event: '+operation.sourceEventId);}
  const members=model.subfixtureChoices||[];
  if(members.length){assert.ok(members.some(member=>member.id===model.subfixtureId),'selected comparison member must match visible options');assert.ok(members.some(member=>member.id===model.defaultSubfixtureId),'default comparison member must be registered');}
  for(const id of Object.keys(actors)){assert.ok(model.compactPositions?.[id]||model.positions?.[id],'missing authored compact actor '+id);assert.ok(model.expandedPositions?.[id]||model.positions?.[id],'missing authored expanded actor '+id);}
  const compiled=buildHeldObjects({model,steps,actors,config:{},contextId:'windows-protection-verification:'+record.executionId,choiceId:model.id});
  assertHeldObjectCoverage(compiled);
  const initial=projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}),prefixes=[];
  assert.deepEqual(initial.state.workstation,reconstructProtocolState(model,-1).workstation,'initial source/held state');
  const artifactIds=new Set();
  for(const artifact of source.artifacts){assert.equal(artifactIds.has(artifact.artifactId),false,'duplicate object identity '+artifact.artifactId);artifactIds.add(artifact.artifactId);}
  const eventIds=new Set();
  for(const [index,step] of steps.entries()){
    assert.equal(eventIds.has(step.id),false,'duplicate source event '+step.id);eventIds.add(step.id);
    const frame=projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'}),expected=reconstructProtocolState(model,index);
    assert.deepEqual(frame.state.workstation,expected.workstation,'source/held prefix '+step.id);
    assert.equal(frame.protocolClock,expected.protocolClock,'source/held protocol clock '+step.id);
    for(const message of compiled.plan.events[step.id].messages||[]){
      const before=projectHeldObjects(compiled,{eventIndex:index,progress:message.start});
      for(const object of message.objects)assert.ok(before.holdings.some(holding=>holding.actorId===message.from&&holding.artifactId===object.artifactId&&holding.representationId===object.representationId),'sender must hold exact representation before transfer: '+step.id+'/'+object.artifactId);
    }
    prefixes.push({eventId:step.id,index,sha256:wpcHash(JSON.stringify(windowsProtectionFrame(frame)))});
  }
  const final=projectHeldObjects(compiled,{eventIndex:steps.length-1,milestone:'complete'});
  assert.equal(final.holdings.some(holding=>holding.retention==='temporary'),false,'attempt scratch survived final cleanup');
  // A view operation is not acquisition, including when the descriptor exists.
  for(const artifact of source.artifacts){
    const history=heldObjectTrace(compiled,artifact.artifactId);
    for(const row of history){
      const cursor=heldCursorForPlayback(compiled,{step:row,status:'paused',kind:'object',queue:[row],queuePosition:0},row,{selected:true});
      const frame=projectHeldObjects(compiled,cursor),eventIndex=cursor.eventIndex<0?-1:cursor.milestone==='complete'?cursor.eventIndex:cursor.eventIndex-1;
      assert.deepEqual(frame.state.workstation,reconstructProtocolState(model,eventIndex).workstation,'exact-object history must preserve hidden source prerequisites: '+artifact.artifactId+'/'+row.id);
    }
  }
  const field=steps.flatMap(step=>step.attributeOperations||[]).find(operation=>['verify','use','deny'].includes(operation.kind))?.attributeId;
  let filteredRows=0;
  if(field){
    const previous=ATTRIBUTES[field];ATTRIBUTES[field]=model.definitions()[field];
    try{
      const queue=buildAttributeTrace(getAttributeUsage(steps,field),model.examples());
      for(const row of queue){
        const cursor=heldCursorForPlayback(compiled,{step:row,status:'paused',kind:'attribute',queue,queuePosition:queue.indexOf(row)},row,{selected:true});
        const frame=projectHeldObjects(compiled,cursor),eventIndex=cursor.eventIndex<0?-1:cursor.milestone==='complete'?cursor.eventIndex:cursor.eventIndex-1;
        assert.deepEqual(frame.state.workstation,reconstructProtocolState(model,eventIndex).workstation,'filtered source prerequisite or rewind lost: '+field+'/'+row.id);filteredRows++;
      }
    }finally{if(previous===undefined)delete ATTRIBUTES[field];else ATTRIBUTES[field]=previous;}
  }
  return {steps:steps.length,objects:source.artifacts.length,prefixes,filteredField:field||null,filteredRows,initial:windowsProtectionFrame(initial),final:windowsProtectionFrame(final),terminalSha256:wpcHash(JSON.stringify(windowsProtectionFrame(final)))};
}

function wpcCheckCatalog(){
  const eventOwners=new Map(),newObjectOwners=new Map();let variants=0;
  for(const base of LAB_SCENARIOS){
    assert.equal(LAB_MODELS[base.id],base,'Catalog identity must resolve the registered model: '+base.id);
    const choices=base.variantChoices?.length?base.variantChoices:[{id:'default'}];
    for(const choice of choices){
      const model=choice.id==='default'||choice.id===base.defaultVariantId?base:base.withVariant(choice.id);variants++;
      for(const step of model.steps()){
        const owner=eventOwners.get(step.id);assert.ok(!owner||owner===base.id,'cross-model event collision '+step.id+': '+owner+' / '+base.id);eventOwners.set(step.id,base.id);
      }
      if(wpcNewModel(base))for(const artifact of model.workstationInventory.artifacts){const owner=newObjectOwners.get(artifact.artifactId);assert.ok(!owner||owner===base.id,'cross-model object collision '+artifact.artifactId);newObjectOwners.set(artifact.artifactId,base.id);}
    }
  }
  return {models:LAB_SCENARIOS.length,enumeratedVariants:variants,uniqueSourceEvents:eventOwners.size,newFamilyObjectIdentities:newObjectOwners.size};
}

export function verifyWindowsProtectionCanonical({onFixture=()=>{}}={}){
  const report={schemaVersion:2,kind:'windows-protection-source-held-prefix-check',recordedAt:new Date().toISOString(),passed:false,complete:false,sourceUnchanged:false,scope:'Source canonical/held/history/filtered prefix invariants. Model-specific independent outcome predicates are in the focused suites. Observed standalone identity is bound but this runner does not establish emitted-browser behavior or source/build correspondence. No native Windows/DC claim.',identities:wpcReviewIdentity(),inputs:['docs/windows-protection-expansion/remote-cases.json','docs/windows-protection-expansion/protection-cases.json','docs/pam-foundations/expectations.json'].map(wpcIdentity),catalog:null,canonicalCases:[],fixtures:[],aliases:[],failures:[]};
  const executed=new Map(),canonical=new Set();
  for(const spec of wpcSpecs()){
    let model,executionId;
    try{
      model=spec.create();executionId=[model.id,model.variantId,model.subfixtureId||'default'].join('/');
      if(spec.canonical)canonical.add(spec.caseId);
      if(executed.has(executionId)){report.aliases.push({caseId:spec.caseId,memberId:spec.memberId||null,executionId});continue;}
      const record={caseId:spec.caseId,modelId:model.id,variantId:model.variantId,subfixtureId:model.subfixtureId||null,memberId:spec.memberId||model.subfixtureId||null,executionId,passed:false};
      report.fixtures.push(record);executed.set(executionId,record);
      Object.assign(record,wpcCheckFixture(model,record));record.passed=true;onFixture(record);
    }catch(error){report.failures.push({caseId:spec.caseId,memberId:spec.memberId||null,executionId:executionId||null,error:error.stack||String(error)});onFixture({caseId:spec.caseId,executionId,passed:false});}
  }
  report.canonicalCases=[...canonical];
  try{assert.equal(canonical.size,110,'every named case has a canonical execution');assert.equal(report.fixtures.length,128,'every additional paired/account/control member executes');report.catalog=wpcCheckCatalog();}catch(error){report.failures.push({kind:'catalog',error:error.stack||String(error)});}
  report.afterIdentities=wpcReviewIdentity();
  report.sourceUnchanged=JSON.stringify(report.identities)===JSON.stringify(report.afterIdentities)&&report.inputs.every(input=>input.sha256===wpcIdentity(input.path).sha256);
  if(!report.sourceUnchanged)report.failures.push({kind:'input-mutation',error:'Source, runner, standalone or independent expectation input changed during verification.'});
  report.complete=true;report.passed=report.failures.length===0;return report;
}

if(import.meta.main){
  const out=process.argv[2];assert.ok(out,'Usage: bun tools/verification/windows-protection-canonical.mjs NEW_REPORT.json');assert.equal(fs.existsSync(out),false,'Evidence report already exists');
  const report=verifyWindowsProtectionCanonical({onFixture:record=>console.log(JSON.stringify({caseId:record.caseId,executionId:record.executionId,passed:record.passed}))});
  fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({passed:report.passed,canonicalCases:report.canonicalCases.length,uniqueExecutions:report.fixtures.length,failures:report.failures.length,catalog:report.catalog}));
  process.exitCode=report.passed?0:1;
}
