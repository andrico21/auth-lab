import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {installHarness} from '../auth-lab-main/tests/dom-harness.mjs';
import {ADLAB_SCENARIOS} from '../auth-lab-main/src/kerberos-ad-lab.js';
import {CRYPTOLAB_SCENARIOS} from '../auth-lab-main/src/kerberos-crypto-lab.js';
import {projectScenarioContext,scenarioContextRows} from '../auth-lab-main/src/scenario-context.js';
const harness=installHarness();
const {AuthFlowStudio}=await import('../auth-lab-main/src/app.js');
const hash=path=>createHash('sha256').update(readFileSync(new URL(path,import.meta.url))).digest('hex');
const files=['src/kerberos-context.js','src/kerberos-ad-lab.js','src/kerberos-crypto-lab.js','src/runtime-environment.js','src/scenario-context.js','src/app.js'];
const sourceHashes=()=>Object.fromEntries(files.map(path=>[path,hash('../auth-lab-main/'+path)]));
const report={scope:'Read-only independent source constructor + actual Apply handler probes. Deterministic DOM harness only; no emitted bundle, native browser, real cryptography, or interoperability acceptance.',sourceHashes:sourceHashes(),scriptHash:hash('./handler-and-projection.mjs'),cases:[],projectionCases:[]};
const modelData=model=>JSON.stringify({definitions:model.definitions(),steps:model.steps(),initialState:model.initialState,protocolValues:model.protocolValues,actors:model.actors()});
const input=(app,key)=>app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');
const enter=(app,key,value)=>{assert.ok(input(app,key),key+' is editable');input(app,key).value=value;};
const click=app=>app.querySelector('#environment-apply').click();
const state=app=>JSON.stringify({context:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision,model:modelData(app.labModel),player:app.player.snapshot(),handle:app.player.handle,lastTime:app.player.lastTime,index:app.index,selection:app.attributeSelection,traceIndex:app.traceIndex,queue:app.traceQueue,visited:[...app.visited],protocol:app.protocolSnapshot(),packet:[app.refs.packet.hidden,app.refs['packet-name'].textContent,app.refs['packet-value'].textContent]});
const reject=(app,before,key)=>{assert.equal(state(app),before);assert.equal(app.refs['environment-errors'].hidden,false);assert.equal(input(app,key).getAttribute('aria-invalid'),'true');assert.equal(input(app,key).getAttribute('aria-errormessage'),'environment-errors');assert.ok(app.refs['environment-errors'].textContent.length>0);};
const cases=[['lab-ad-first-sign-in','cifs/review.corp.test'],['lab-kc-kerberos-sso','HTTP/review.corp.test'],['lab-ad-pkinit-success','HTTP/review.corp.test'],['lab-ad-fast-tgs-success','HTTP/review.corp.test']];
try{
 for(const [id,name] of cases){
  const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();
  try{
   app.selectLabScenario(id);const base=app.baseLabModel,baseBefore=modelData(base),initial=modelData(app.labModel);
   enter(app,'kerberosRealm','CORP.EXAMPLE');enter(app,'servicePrincipal',name);click(app);
   assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);
   const plain=modelData(app.labModel);enter(app,'servicePrincipal',name+'@CORP.EXAMPLE');click(app);
   assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);assert.equal(modelData(app.labModel),plain);assert.equal(app.runtimeEnvironment.draft.servicePrincipal,name+'@CORP.EXAMPLE');
   const serviceActor=id.startsWith('lab-kc')?'adKeycloak':id.startsWith('lab-ad-pkinit')||id.includes('fast')?'cryptoService':'adService';
   for(const row of app.actorContextRows(serviceActor).filter(row=>row.key==='servicePrincipal'))assert.equal(row.value,name);
   app.player.play(app.steps,'demo');harness.clock.advance(700);if(id.includes('fast')||id.startsWith('lab-kc'))app.player.pause();
   app.visited.add('preserve');
   let before=state(app);enter(app,'servicePrincipal',name+'@OTHER.EXAMPLE');click(app);reject(app,before,'servicePrincipal');
   enter(app,'servicePrincipal',name+'@CORP.EXAMPLE');
   for(const length of [255,2048]){before=state(app);enter(app,'kerberosRealm','R'.repeat(length));click(app);reject(app,before,'kerberosRealm');}
   enter(app,'kerberosRealm','R'.repeat(254));enter(app,'servicePrincipal',name+'@'+'R'.repeat(254));click(app);
   assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.runtimeEnvironment.applied.kerberosRealm.length,254);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);
   assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);
   const realBase=app.baseLabModel;let fail=true,candidateSeen=false;
   Object.defineProperty(app,'baseLabModel',{configurable:true,get:()=>({...realBase,contextualize:(context,metadata)=>{candidateSeen=true;assert.equal(context.servicePrincipal,name+'/changed');assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);if(fail)throw Object.assign(new Error('Injected construction rejection'),{field:'servicePrincipal'});return realBase.contextualize(context,metadata);}})});
   app.player.play(app.steps,'demo');harness.clock.advance(500);before=state(app);
   enter(app,'servicePrincipal',name+'/changed@'+'R'.repeat(254));click(app);assert.ok(candidateSeen);reject(app,before,'servicePrincipal');
   fail=false;click(app);assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name+'/changed');
   delete app.baseLabModel;
   app.querySelector('#environment-reset').click();assert.equal(app.runtimeEnvironment.active,false);assert.equal(modelData(app.labModel),initial);assert.equal(modelData(base),baseBefore);
   report.cases.push({id,passed:true,acceptedPlainAndMatchingQualifier:true,rejectedLengths:[255,2048],acceptedRealmLength:254,conflictingQualifierRejected:true,constructorFailureBeforeCommit:true,correctedWithoutReset:true,resetAndBasePreserved:true});
  }finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
 }
 const all=[...ADLAB_SCENARIOS,...CRYPTOLAB_SCENARIOS];
 for(const id of ['lab-ad-first-sign-in','lab-kc-kerberos-sso','lab-ad-pkinit-success','lab-ad-fast-tgs-success']){
  const source=all.find(model=>model.id===id);assert.ok(source,id);
  for(const realm of ['A.EXAMPLE','CORP.EXAMPLE']){
   const name=(id==='lab-ad-first-sign-in'?'cifs':'HTTP')+'/review.corp.test';
   const model=source.contextualize({kerberosRealm:realm,servicePrincipal:name+'@'+realm}),before=modelData(model);
   const raw={servicePrincipal:name+'@'+realm};
   const projected=projectScenarioContext(model,model.steps(),raw);
   assert.deepEqual(projected.steps,model.steps());assert.deepEqual(projected.initialState,model.initialState||{});assert.deepEqual(projected.protocolValues,model.protocolValues||{});
   for(const actorId of Object.keys(model.actors()))for(const row of scenarioContextRows(model,actorId,raw).filter(row=>row.key==='servicePrincipal'))assert.equal(row.value,name);
   assert.equal(modelData(model),before);assert.equal(raw.servicePrincipal,name+'@'+realm);
   report.projectionCases.push({id,realm,passed:true,rawMatchingDraftNormalized:true,rowsAndRequestKeepSeparateName:true,sourceUnchanged:true});
  }
 }
 assert.deepEqual(sourceHashes(),report.sourceHashes,'All probed source files stayed unchanged throughout this probe');report.passed=true;
}catch(error){report.passed=false;report.error=error.stack;process.exitCode=1;}
report.caseCount=report.cases.length;report.projectionCaseCount=report.projectionCases.length;
writeFileSync(new URL('./handler-and-projection-status.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
