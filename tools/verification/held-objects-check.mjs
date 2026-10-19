#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {HELD_OBJECT_CHOICES,makeHeldObjectFixture,heldCoreConfigurations,HELD_OBJECT_SCOPE_EXCLUSIONS} from './held-object-fixtures.mjs';
import {buildHeldObjects,describeHeldObjectPlan} from '../../src/held-objects.js';
import {projectHeldObjects,assertHeldObjectCoverage,heldObjectTrace,heldCursorForPlayback} from '../../src/held-object-state.js';
import {CORE_HELD_OBJECT_INTERACTIONS,CORE_HELD_OBJECT_SCOPE} from '../../src/held-object-core.js';
import {reconstructProtocolState} from '../../src/protocol-state.js';
import {FlowPlayer,pairKey,resolveActor} from '../../src/player.js';

const heldCheckRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const heldCheckOutput=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(heldCheckRoot,'docs/verification/held-objects'));
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/held-objects-check.mjs\nChecks all picker choices and applicable normalized Core configurations. Uses actual source generation with no rendered DOM. Writes manifest and observed semantic evidence to AUTH_LAB_HELD_EVIDENCE_DIR or docs/verification/held-objects.');process.exit(0);}
fs.mkdirSync(heldCheckOutput,{recursive:true});
const heldCheckDigest=filename=>{const bytes=fs.readFileSync(path.join(heldCheckRoot,filename));return {path:filename,bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};};
const heldCheckReport={kind:'held-objects-source-semantic-acceptance',nativeBrowser:false,timestamp:new Date().toISOString(),runtime:process.versions.bun?'Bun '+process.versions.bun:process.version,choices:[],coreConfigurations:[],interactionCases:[],scopeExclusions:HELD_OBJECT_SCOPE_EXCLUSIONS,failures:[],passed:false};
const heldCheckManifest=[];
const heldCheckSourceFiles=['index.html','build.mjs','security-policy.mjs',...fs.readdirSync(path.join(heldCheckRoot,'src')).filter(name=>/\.(?:js|css)$/.test(name)).sort().map(name=>'src/'+name),...fs.readdirSync(path.join(heldCheckRoot,'tests')).filter(name=>/^held-object.*\.test\.mjs$/.test(name)).sort().map(name=>'tests/'+name),'tools/verification/held-objects-check.mjs','tools/verification/held-object-fixtures.mjs'];
heldCheckReport.inputs=heldCheckSourceFiles.map(heldCheckDigest);

function heldCheckAtQueue(compiled,queue,index,progress) {
  const player=new FlowPlayer({requestFrame:()=>null,cancelFrame:()=>{}});
  const target=(player.totalDuration(queue.slice(0,index))+player.totalDuration([queue[index]])*progress)/player.totalDuration(queue);
  player.seek(queue,target,'verification');
  const event=player.snapshot();
  return projectHeldObjects(compiled,heldCursorForPlayback(compiled,event,event.step));
}

function heldCheckFixture(fixture,{differential=false}={}) {
  const compiled=buildHeldObjects(fixture);
  assertHeldObjectCoverage(compiled);
  const initial=projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'});
  assert.equal(initial.coverageStatus,'complete',fixture.choiceId+' initial complete coverage');
  let equalCursorComparisons=0;
  if(differential){
    const sourceModel=fixture.model?{...fixture.model,steps:()=>fixture.steps}:null;
    for(let index=0;index<fixture.steps.length;index++){
      const step=fixture.steps[index];
      const completed=projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});
      if(fixture.model?.initialState)assert.deepEqual(completed.state,reconstructProtocolState(sourceModel,index),fixture.choiceId+' family-state binding after '+step.id);
      for(const progress of [.3,.9]){
        const expected=projectHeldObjects(compiled,{eventIndex:index,progress});
        const full=heldCheckAtQueue(compiled,fixture.steps,index,progress);
        assert.deepEqual(full,expected,fixture.choiceId+' full playback '+step.id+' at '+progress);
        const key=pairKey(resolveActor(step.from,fixture.config.authenticator),resolveActor(step.to,fixture.config.authenticator));
        const linked=fixture.steps.filter(candidate=>pairKey(resolveActor(candidate.from,fixture.config.authenticator),resolveActor(candidate.to,fixture.config.authenticator))===key);
        const filtered=heldCheckAtQueue(compiled,linked,linked.indexOf(step),progress);
        assert.deepEqual(filtered,expected,fixture.choiceId+' link replay hidden predecessor prefix '+step.id+' at '+progress);
        equalCursorComparisons+=2;
      }
    }
    const artifacts=compiled.plan.artifacts;
    for(const artifact of artifacts){
      for(const row of heldObjectTrace(compiled,artifact.artifactId)){
        const selectedCursor=heldCursorForPlayback(compiled,{status:'idle',step:row},row,{selected:true});
        assert.deepEqual(projectHeldObjects(compiled,selectedCursor),projectHeldObjects(compiled,row.heldCursorEnd),fixture.choiceId+' exact-object selected milestone '+artifact.artifactId);
        equalCursorComparisons++;
      }
    }
  }
  const final=projectHeldObjects(compiled,{eventIndex:fixture.steps.length-1,milestone:'complete'});
  return {compiled,evidence:{choiceId:fixture.choiceId,configuration:fixture.config,sourceEvents:fixture.steps.length,artifacts:compiled.plan.artifacts.length,logicalActors:Object.keys(compiled.plan.actors),initialHoldings:initial.holdings.length,finalHoldings:final.holdings.length,equalCursorComparisons,complete:true}};
}

try{
  assert.equal(new Set(HELD_OBJECT_CHOICES).size,HELD_OBJECT_CHOICES.length);
  for(const choiceId of HELD_OBJECT_CHOICES){
    const fixture=makeHeldObjectFixture(choiceId);
    const {compiled,evidence}=heldCheckFixture(fixture,{differential:true});
    heldCheckReport.choices.push(evidence);
    heldCheckManifest.push(describeHeldObjectPlan(compiled,{choiceId,model:fixture.model,configuration:fixture.config}));
  }
  const seen=new Set();
  for(const config of heldCoreConfigurations()){
    const fixture=makeHeldObjectFixture('core',config),signature=JSON.stringify(fixture.config);
    if(seen.has(signature))continue;
    seen.add(signature);
    const {evidence}=heldCheckFixture(fixture);
    heldCheckReport.coreConfigurations.push(evidence);
  }
  for(const interaction of CORE_HELD_OBJECT_INTERACTIONS){
    const fixture=makeHeldObjectFixture('core',interaction.config||{});
    const {evidence}=heldCheckFixture(fixture,{differential:true});
    heldCheckReport.interactionCases.push({id:interaction.id,...evidence});
  }
  heldCheckReport.passed=true;
}catch(error){heldCheckReport.failures.push({message:error.message,stack:error.stack});process.exitCode=1;}
finally{
  fs.writeFileSync(path.join(heldCheckOutput,'held-objects-source-status.json'),JSON.stringify(heldCheckReport,null,2)+'\n');
  fs.writeFileSync(path.join(heldCheckOutput,'held-objects-coverage-manifest.json'),JSON.stringify({kind:'authored-held-object-manifest',reviewDisposition:'Pending independent Astra implementation review',choices:heldCheckManifest,core:{normalizedConfigurationCount:heldCheckReport.coreConfigurations.length,configurations:heldCheckReport.coreConfigurations,interactions:CORE_HELD_OBJECT_INTERACTIONS,authoredScope:CORE_HELD_OBJECT_SCOPE,exclusions:HELD_OBJECT_SCOPE_EXCLUSIONS}},null,2)+'\n');
  console.log(JSON.stringify({passed:heldCheckReport.passed,choices:heldCheckReport.choices.length,coreConfigurations:heldCheckReport.coreConfigurations.length,interactionCases:heldCheckReport.interactionCases.length,equalCursorComparisons:heldCheckReport.choices.reduce((total,choice)=>total+choice.equalCursorComparisons,0)+heldCheckReport.interactionCases.reduce((total,choice)=>total+choice.equalCursorComparisons,0),failures:heldCheckReport.failures.map(failure=>failure.message),evidenceDirectory:heldCheckOutput},null,2));
}
