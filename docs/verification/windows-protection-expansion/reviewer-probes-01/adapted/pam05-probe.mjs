import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createPamFoundationsCase} from '../source/src/pam-foundations-lab.js';
import {LINUXLOGONLAB_SCENARIOS,createLinuxPasswordChangeCase} from '../source/src/linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS} from '../source/src/linux-elevation-lab.js';
import {LINUXLOGONLAB_SCENARIOS as OLD_LOGON} from '../../windows-protection-02/source/src/linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS as OLD_ELEV} from '../../windows-protection-02/source/src/linux-elevation-lab.js';
import {reconstructProtocolState} from '../source/src/protocol-state.js';
import {reconstructProtocolState as oldState} from '../../windows-protection-02/source/src/protocol-state.js';
import {pamEvaluate,pamApiBoundary} from '../source/src/pam-stack-evaluator.js';
import {buildUnixWorkstationHeldObjects} from '../source/src/held-object-unix-workstation.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../source/src/held-object-state.js';
import {installHarness,HarnessEvent} from '../source/tests/dom-harness.mjs';

const mode=process.argv[2]||'source',json=x=>x===undefined?undefined:JSON.parse(JSON.stringify(x));
let checks=0,positions=0,runtimePrefixes=0;const contracts=[],observations=[];
function eq(a,b,label){assert.deepEqual(json(a),json(b),label);checks++;}
function ok(v,label){assert.ok(v,label);checks++;}
function contract(id,label,actual,expected){contracts.push({id,label,actual,expected,passed:JSON.stringify(actual)===JSON.stringify(expected)});}
const current=[...LINUXLOGONLAB_SCENARIOS,...LINUXELEVLAB_SCENARIOS],old=[...OLD_LOGON,...OLD_ELEV];
const select=(id,variant='default')=>current.find(m=>m.id===id).withVariant(variant);
const core=state=>{const value=json(state.workstation);delete value.pamEvaluation;delete value.pamResults;return value;};
const end=m=>reconstructProtocolState(m,m.steps().length-1);
const existing=[],danglingSecretUses=[],invalidPublicCalls=[];
let prefixes=0;
for(const base of current.filter(m=>/^lab-(llog0[1-4]|lelev0[12])$/.test(m.id)))for(const choice of base.variantChoices){
 const m=base.withVariant(choice.id),previous=old.find(x=>x.id===m.id).withVariant(choice.id),steps=m.steps();
 eq(core(end(m)),core(oldState(previous,previous.steps().length-1)),m.id+'/'+choice.id+' final core unchanged');
 const plan=compileHeldObjects(buildUnixWorkstationHeldObjects({model:m,steps,actors:m.actors(),choiceId:m.id,contextId:'independent:'+m.id+':'+choice.id}),{model:m,steps});
 const secrets=new Set(m.workstationInventory.artifacts.filter(x=>x.type==='secret').map(x=>x.artifactId));
 let prior=projectHeldObjects(plan,{eventIndex:-1,milestone:'initial'});prefixes++;
 for(let i=0;i<steps.length;i++){
  const step=steps[i];
  for(const op of step.attributeOperations||[])if(['use','verify'].includes(op.kind)&&secrets.has(op.instanceId)){
   const available=prior.holdings.some(h=>h.artifactId===op.instanceId&&h.actorId===op.actorId)||step.attributeOperations.some(o=>o.instanceId===op.instanceId&&o.actorId===op.actorId&&o.kind==='create');
   if(!available)danglingSecretUses.push({scenario:m.id,variant:choice.id,index:i,step:step.id,secret:op.instanceId,actor:op.actorId});
  }
  prior=projectHeldObjects(plan,{eventIndex:i,milestone:'complete'});prefixes++;eq(prior.state,reconstructProtocolState(m,i),'Held/state canonical prefix');
  eq(prior.state.workstation.unrelatedSession,'other-user-session-retained','Unrelated session retained');
 }
 for(const artifact of m.workstationInventory.artifacts){
  if(artifact.type!=='local-api-input'||artifact.creator!=='pamChangeApp')continue;
  let value;try{value=JSON.parse(artifact.value);}catch{continue;}
  if(value.api==='pam_chauthtok'&&/PAM_PRELIM_CHECK|PAM_UPDATE_AUTHTOK/.test(String(value.flags)))invalidPublicCalls.push({scenario:m.id,variant:choice.id,id:artifact.artifactId,flags:value.flags});
 }
 // Exact artifact type is not needed for the actual application-created control contract.
 for(const artifact of m.workstationInventory.artifacts.filter(a=>a.creator==='pamChangeApp'&&a.artifactId.includes('pam-call-'))){
  let value;try{value=JSON.parse(artifact.value);}catch{continue;}
  if(value.api==='pam_chauthtok'&&/PAM_PRELIM_CHECK|PAM_UPDATE_AUTHTOK/.test(String(value.flags))&&!invalidPublicCalls.some(x=>x.variant===choice.id&&x.id===artifact.artifactId))invalidPublicCalls.push({scenario:m.id,variant:choice.id,id:artifact.artifactId,flags:value.flags});
 }
 existing.push({scenario:m.id,variant:choice.id,steps:steps.length});
}
eq(existing.length,55,'All six existing consumers / 55 controls');
contract('WP-R06-A','No raw password use after release across all 55 existing consumers',danglingSecretUses,[]);
contract('WP-R06-B','Public pam_chauthtok calls never carry internal phase bits',invalidPublicCalls,[]);

const flagMembers=[['change-success',['prelim','update'],'PAM_SUCCESS',2],['change-prelim-failure',['prelim'],'PAM_AUTHTOK_ERR',1],['change-update-failure',['prelim','update'],'PAM_AUTHTOK_ERR',1],['change-unsupported',[],null,1]];
for(const [member,phases,status,generation] of flagMembers){
 const m=createPamFoundationsCase('password-change-required',member);
 for(const phase of phases){
  const flags='PAM_CHANGE_EXPIRED_AUTHTOK | '+(phase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK');
  eq(m.pamEvaluations[phase].flags,flags,'Full caller/internal flags '+member+'/'+phase);
  for(const row of m.pamEvaluations[phase].trace)eq(row.flags,flags,'Every module record has complete flags');
 }
 eq(m.steps().filter(s=>s.pamEvaluation?.executed&&['prelim','update'].includes(s.pamEvaluation.apiPhase)).map(s=>s.pamEvaluation.apiPhase),phases,'Exact reached internal passes');
 for(const artifact of m.workstationInventory.artifacts.filter(a=>a.creator==='pamCaller'&&a.artifactId.includes('call-password-')))eq(JSON.parse(artifact.value).flags,'PAM_CHANGE_EXPIRED_AUTHTOK','Public foundation invocation has caller flags only');
 eq(end(m).workstation.authorityGeneration,generation,'No failed update advances authority');
 if(status)eq(end(m).workstation.pamResults.password,status,'Public password API outcome');
 else eq(m.steps().filter(s=>['password','prelim','update'].includes(s.pamEvaluation?.apiPhase)).length,0,'Unsupported caller dispatches nothing');
}
for(const phase of ['prelim','update']){
 const flags=phase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK';
 eq(pamEvaluate('afs-login',phase,{callerFlags:0,inputs:{['pam_unix.so:'+phase]:'PAM_SUCCESS'}}).flags,flags,'Zero-caller flag control');
 eq(pamApiBoundary('afs-login',phase,'control',{callerFlags:0}).flags,flags,'Zero-caller boundary');
}
eq(pamApiBoundary('afs-login','password','control').flags,0,'Public API does not globally inherit expired-only bit');


const extra=[];
for(const variant of ['default','wrong-password','expired-timestamp','different-terminal','rootpw','targetpw','runaspw','account-denied']){
 const m=select('lab-lelev01',variant),steps=m.steps(),plan=compileHeldObjects(buildUnixWorkstationHeldObjects({model:m,steps,actors:m.actors(),choiceId:m.id,contextId:'evidence:'+variant}),{model:m,steps});
 const index=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.aggregateReturn!==undefined),before=projectHeldObjects(plan,{eventIndex:index-1,milestone:'complete'}),aggregate=steps[index];
 const evidence=aggregate.attributeOperations.filter(o=>o.kind==='use').map(o=>m.workstationInventory.artifacts.find(a=>a.artifactId===o.instanceId)).filter(a=>a?.type==='pam-return');
 eq(evidence.length,1,'Sudo aggregate consumes one real module record');
 for(const artifact of evidence){ok(before.holdings.some(h=>h.artifactId===artifact.artifactId&&h.actorId==='lelevPAM'),'Module evidence held before aggregate');eq(JSON.parse(artifact.value).rawReturn,variant==='wrong-password'?'PAM_AUTH_ERR':'PAM_SUCCESS','Evidence is actual physical outcome');}
 extra.push({scenario:m.id,variant,moduleEvidence:evidence.map(a=>a.artifactId)});
}
for(const variant of ['command-denied','runas-denied','cached-policy-denied','noninteractive','nopasswd','root-caller','timestamp-reuse']){
 const m=select('lab-lelev01',variant);eq(m.workstationInventory.artifacts.filter(a=>a.type==='secret').length,0,'No prompt/reused control creates no fabricated password');eq(m.steps().filter(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed).length,0,'No prompt/reused control invents no password module');
}
{
 const m=createLinuxPasswordChangeCase({...select('lab-llog04').fixture,prelimOk:false}),steps=m.steps();
 const calls=steps.filter(s=>s.from==='pamChangeApp'&&s.to==='pamChange'&&s.pamEvaluation?.api==='pam_chauthtok'),returns=steps.filter(s=>s.from==='pamChange'&&s.to==='pamChangeApp'&&s.pamEvaluation?.api==='pam_chauthtok'&&s.pamEvaluation.aggregateReturn!==undefined),modules=steps.filter(s=>s.pamEvaluation?.executed&&['prelim','update'].includes(s.pamEvaluation.apiPhase));
 eq(calls.length,1,'Additive preliminary-failure fixture opens one public call');eq(returns.length,1,'Additive preliminary-failure fixture closes one public call');eq(returns[0].pamEvaluation.aggregateReturn,'PAM_AUTHTOK_ERR','Preliminary failure returns exact error');eq(modules.map(s=>s.pamEvaluation.apiPhase),['prelim'],'Preliminary failure stops before update');eq(m.workstationInventory.artifacts.filter(a=>a.artifactId==='lab-llog04:new-secret').length,0,'Preliminary failure never collects candidate');eq(end(m).workstation.authorityGeneration,1,'Preliminary failure cannot write backend');eq(end(m).workstation.session,false,'Preliminary failure cannot admit session');
 extra.push({scenario:'lab-llog04',fixture:'prelimOk:false',registered:false,steps:steps.length,call:calls[0].id,returned:returns[0].id,phases:modules.map(s=>s.pamEvaluation.apiPhase)});
}

const sandbox=mode==='emitted'?{structuredClone}:globalThis;
const harness=installHarness(sandbox);let Studio;
if(mode==='emitted'){
 const bytes=fs.readFileSync(new URL('../auth-flow-studio-windows-protection.html',import.meta.url));
 eq(createHash('sha256').update(bytes).digest('hex'),'9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694','Exact supplied candidate05');
 const scripts=[...bytes.toString().matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];eq(scripts.length,1,'One actual IIFE');
 new vm.Script(scripts[0][1]).runInContext(vm.createContext(sandbox));Studio=harness.registry.get('auth-flow-studio');
}else ({AuthFlowStudio:Studio}=await import('../source/src/app.js'));
const app=new Studio();harness.document.body.appendChild(app);app.connectedCallback();
const text=node=>node?.textContent.replace(/\s+/g,' ').trim();
function cell(label){const dl=app.querySelector('#pam-configuration-panel .pam-evaluation');return text([...dl.children].find(row=>text(row.querySelector('dt'))===label)?.querySelector('dd'));}
function position(index){app.selectStep(index,false);positions++;const snapshot=app.heldView.snapshot(),m=app.labModel.id==='lab-pam01'?createPamFoundationsCase(app.labModel.variantId,app.labModel.subfixtureId):select(app.labModel.id,app.labModel.variantId||'default');eq(snapshot.state,reconstructProtocolState(m,snapshot.cursor.eventIndex),'Rendered current prefix equals independently constructed source model prefix');return snapshot;}
function reset(){app.clearAttribute();app.reset();eq(app.heldView.snapshot().cursor,{eventIndex:-1,milestone:'initial'},'Reset rewinds');eq(app.heldView.selection,null,'Reset clears object selection');}
function history(artifactId,index){
 app.clearAttribute();position(index);
 const artifact=app.labModel.workstationInventory.artifacts.find(a=>a.artifactId===artifactId);ok(artifact,'History target exists');
 app.selectAttribute(artifact.attributeId,false);
 const field=app.traceQueue.map(s=>s.sourceStepId||s.id);
 for(let n=0;n<app.visibleSteps.length;n++)position(n);
 for(let n=app.visibleSteps.length-1;n>=0;n--)position(n);
 app.clearAttribute();position(index);app.heldView.trace(artifactId);
 const exact=app.traceQueue.map(s=>s.sourceStepId||s.id);
 for(let n=0;n<app.visibleSteps.length;n++)position(n);
 for(let n=app.visibleSteps.length-1;n>=0;n--)position(n);
 app.clearAttribute();return {field,exact};
}
try{
 for(const row of existing){
  app.selectLabScenario(row.scenario,{variant:row.variant});
  const model=select(row.scenario,row.variant),steps=model.steps();eq(app.steps,steps,'Actual runtime step declarations equal independent source');
  let before=app.heldView.snapshot();runtimePrefixes++;eq(before.state,reconstructProtocolState(model,-1),'Actual runtime initial prefix');
  const secrets=new Set(app.labModel.workstationInventory.artifacts.filter(a=>a.type==='secret').map(a=>a.artifactId));
  for(let i=0;i<steps.length;i++){
   for(const op of app.steps[i].attributeOperations.filter(o=>secrets.has(o.instanceId)&&['use','verify'].includes(o.kind))){
    const created=app.steps[i].attributeOperations.some(other=>other.instanceId===op.instanceId&&other.actorId===op.actorId&&other.kind==='create');
    ok(created||before.holdings.some(h=>h.artifactId===op.instanceId&&h.actorId===op.actorId),'Actual runtime secret consumption has custody');
   }
   before=position(i);runtimePrefixes++;
  }
  eq(core(before.state),core(oldState(old.find(m=>m.id===row.scenario).withVariant(row.variant),old.find(m=>m.id===row.scenario).withVariant(row.variant).steps().length-1)),'Actual runtime old operational final core preserved');
  reset();
 }
 for(const [member,phases] of flagMembers){
  app.selectLabScenario('lab-pam01',{variant:'password-change-required'});const control=app.querySelector('#lesson-subfixture');control.value=member;control.dispatchEvent(new HarnessEvent('change'));
  for(const phase of phases){
   const index=app.steps.findIndex(s=>s.pamEvaluation?.executed&&s.pamEvaluation.apiPhase===phase);position(index);
   const flags='PAM_CHANGE_EXPIRED_AUTHTOK | '+(phase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK');eq(cell('Internal module dispatch / flags'),'pam_chauthtok / '+flags,'Visible complete internal flags');
   const artifact=app.labModel.workstationInventory.artifacts.find(a=>a.type==='pam-return'&&JSON.parse(a.value).apiPhase===phase);
   const trace=history(artifact.artifactId,index);ok(trace.exact.includes(app.steps[index].id),'Exact record history includes real module completion');
  }
  reset();
 }
 for(const [id,variant,lines,allowed] of [['lab-lelev01','default',[3,4],true],['lab-lelev01','account-denied',[3,4],false],['lab-lelev02','default',[4,5],true],['lab-lelev02','access-denied',[4,5],false]]){
  app.selectLabScenario(id,{variant});const modules=app.steps.map((step,index)=>({step,index})).filter(x=>x.step.pamEvaluation?.apiPhase==='account'&&x.step.pamEvaluation.executed),returned=app.steps.findIndex(s=>s.pamEvaluation?.apiPhase==='account'&&s.pamEvaluation.aggregateReturn!==undefined);
  eq(modules.map(x=>x.step.pamEvaluation.line),lines,'Ordered account physical rows once');ok(returned>modules.at(-1).index,'Aggregate after every module');
  for(const {step,index} of modules){const s=position(index);eq(s.state.workstation.pamResults?.account,undefined,'No future aggregate');eq(s.state.workstation.admitted,false,'No admission before aggregate');eq(cell('API aggregate return'),'Pending: current API call has not completed','Visible pending aggregate');eq(cell('Accumulator after'),step.pamEvaluation.accumulatorAfter.impression+' / '+step.pamEvaluation.accumulatorAfter.status,'Visible ordered accumulator');}
  const s=position(returned);eq(s.state.workstation.admitted,allowed,'Actual account decision');eq(cell('API aggregate return'),allowed?'PAM_SUCCESS':'PAM_PERM_DENIED','Visible completed aggregate');
  const artifact=app.labModel.workstationInventory.artifacts.find(a=>a.type==='pam-return'&&JSON.parse(a.value).apiPhase==='account'&&JSON.parse(a.value).line===lines[1]);history(artifact.artifactId,modules.at(-1).index);reset();
 }
 for(const [variant,expected] of [['setuid-not-real-root',['pam_rootok.so','pam_unix.so']],['real-root-bypass',['pam_rootok.so']]]){
  app.selectLabScenario('lab-lelev02',{variant});const modules=app.steps.map((step,index)=>({step,index})).filter(x=>x.step.pamEvaluation?.apiPhase==='authenticate'&&x.step.pamEvaluation.executed),ret=app.steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.aggregateReturn!==undefined);
  eq(modules.map(x=>x.step.pamEvaluation.module),expected,'Rootok exact dispatch chain');
  eq(app.steps.filter(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.apiPending&&s.pamEvaluation.line===null&&!s.id.endsWith('-prepare')).length,1,'One authenticate begin, not second API');
  for(const {index} of modules){const snap=position(index);eq(snap.state.workstation.pamResults?.authenticate,undefined,'No rootok premature aggregate');}
  ok(ret>modules.at(-1).index,'Rootok returns after module');position(ret);eq(cell('API aggregate return'),variant==='real-root-bypass'?'PAM_SUCCESS':'PAM_AUTH_ERR','Rootok actual returned aggregate');reset();
 }
 for(const [id,secret,owner,variant] of [['lab-llog01','entered-secret','llogPAM','default'],...['default','wrong-password','expired-timestamp','different-terminal','rootpw','targetpw','runaspw','account-denied'].map(v=>['lab-lelev01','secret','lelevPAM',v])]){
  app.selectLabScenario(id,{variant});const artifactId=id+':'+secret,modules=app.steps.map((step,index)=>({step,index})).filter(x=>x.step.pamEvaluation?.apiPhase==='authenticate'&&x.step.pamEvaluation.executed),ret=app.steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.aggregateReturn!==undefined),snap=position(ret);
  eq(modules.length,1,'One actual password-auth module');
  const uses=app.steps.flatMap(s=>s.attributeOperations.filter(o=>o.instanceId===artifactId&&o.kind==='use'&&o.actorId===owner).map(()=>s.id));
  const trace=history(artifactId,modules[0].index),observation={scenario:id,variant,module:modules[0].step.id,aggregate:app.steps[ret].id,uses,field:trace.field,exact:trace.exact,heldAtAggregate:snap.holdings.filter(h=>h.artifactId===artifactId).map(h=>h.actorId)};observations.push(observation);
  contract('WP-R06-A',mode+' '+id+' raw password used only by physical module',uses,[modules[0].step.id]);
  contract('WP-R06-A',mode+' '+id+' exact history excludes aggregate',trace.exact.includes(app.steps[ret].id),false);
  contract('WP-R06-A',mode+' '+id+' field history excludes aggregate',trace.field.includes(app.steps[ret].id),false);
  if(id==='lab-llog01')eq(snap.holdings.filter(h=>h.artifactId===id+':verifier').map(h=>h.actorId),['llogPAM'],'Verifier remains owner-local');reset();
 }
 for(const variant of ['default','directory-online','directory-unreachable','new-policy-denied','update-failed','post-change-account-denied','consumer-no-change','account-expired','wrong-current-password']){
  app.selectLabScenario('lab-llog04',{variant});
  const calls=app.steps.map((step,index)=>({step,index})).filter(({step})=>step.from==='pamChangeApp'&&step.to==='pamChange'&&step.pamEvaluation?.api==='pam_chauthtok');
  const returned=app.steps.map((step,index)=>({step,index})).filter(({step})=>step.from==='pamChange'&&step.to==='pamChangeApp'&&step.pamEvaluation?.api==='pam_chauthtok'&&step.pamEvaluation.aggregateReturn!==undefined);
  const expectedCalls=['consumer-no-change','account-expired','wrong-current-password'].includes(variant)?0:1;
  contract('WP-R06-B',mode+' LLOG04/'+variant+' one public password-change invocation',calls.length,expectedCalls);
  contract('WP-R06-B',mode+' LLOG04/'+variant+' public calls contain caller flags only',calls.map(({step})=>step.pamEvaluation.flags),Array(expectedCalls).fill('PAM_CHANGE_EXPIRED_AUTHTOK'));
  contract('WP-R06-B',mode+' LLOG04/'+variant+' one public password-change return',returned.length,expectedCalls);
  const samples=[];
  if(expectedCalls){
   const status=['new-policy-denied','update-failed'].includes(variant)?'PAM_AUTHTOK_ERR':variant==='directory-unreachable'?'PAM_AUTHINFO_UNAVAIL':'PAM_SUCCESS';
   const changeArtifacts=app.labModel.workstationInventory.artifacts.filter(a=>a.type==='pam-aggregate'&&JSON.parse(a.value).api==='pam_chauthtok');
   eq(changeArtifacts.length,1,'One genuine public chauthtok result artifact');
   const result=changeArtifacts[0],value=JSON.parse(result.value);
   eq([value.apiPhase,value.flags,value.status],['password','PAM_CHANGE_EXPIRED_AUTHTOK',status],'Public result caller flags and exact status');
   const modules=app.steps.map((step,index)=>({step,index})).filter(({step})=>step.pamEvaluation?.executed&&['prelim','update'].includes(step.pamEvaluation.apiPhase));
   eq(modules.map(x=>x.step.pamEvaluation.apiPhase),['prelim','update'],'Internal preliminary then update exactly once');
   for(const {step,index} of modules){ok(calls[0].index<index&&index<returned[0].index,'Internal pass within one public call');eq(step.pamEvaluation.flags,'PAM_CHANGE_EXPIRED_AUTHTOK | '+(step.pamEvaluation.apiPhase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK'),'Complete internal phase bits');}
   for(let i=calls[0].index;i<returned[0].index;i++){
    const snap=position(i);eq(cell('API aggregate return'),'Pending: current API call has not completed','Rendered pending through every preparation/conversation/backend prefix');
    eq(snap.state.workstation.pamResults?.password,undefined,'No future public status');
    eq(snap.holdings.some(h=>h.actorId==='pamChangeApp'&&h.artifactId===result.artifactId),false,'Caller has no future public result');
   }
   position(modules[0].index);
   const disclosure=app.querySelector('[data-pam-disclosure="aggregates"]');
   const classification={scenario:'lab-llog04',variant,at:modules[0].step.id,summary:text(disclosure.querySelector('summary')),values:app.heldView.snapshot().state.workstation.pamResults};
   observations.push({classification});
   contract('WP-R06-B-classification',mode+' LLOG04/'+variant+' internal phase is not classified as completed public API result',Object.keys(JSON.parse(disclosure.querySelector('pre').textContent)).filter(k=>['prelim','update'].includes(k)),[]);
   const completed=position(returned[0].index);eq(cell('API aggregate return'),status,'Actual one public completion');eq(completed.state.workstation.pamResults.password,status,'Public state completed only at return');
   ok(completed.holdings.some(h=>h.actorId==='pamChangeApp'&&h.artifactId===result.artifactId),'Caller acquires actual public result');
   const final=position(app.steps.length-1);eq(final.state.workstation.authorityGeneration,status==='PAM_SUCCESS'?2:1,'Authority generation follows actual commit, not admission');
   if(variant==='post-change-account-denied'){eq(final.state.workstation.admitted,false,'Post-change policy can deny');eq(final.state.workstation.postChangeAccountChecked,true,'Post-change account check preserved');}
   const resultHistory=history(result.artifactId,returned[0].index);ok(resultHistory.exact.includes(returned[0].step.id),'Exact public result history includes actual return');ok(resultHistory.field.includes(returned[0].step.id),'Field public result history includes actual return');
   position(calls[0].index);eq(cell('API aggregate return'),'Pending: current API call has not completed','Rewind restores pending public call');
   position(returned[0].index);eq(cell('API aggregate return'),status,'Forward restores public result');
  }
  for(const {step,index} of [...calls,...returned]){const snap=position(index);samples.push({index,id:step.id,from:step.from,to:step.to,phase:step.pamEvaluation.apiPhase,flags:step.pamEvaluation.flags,aggregate:step.pamEvaluation.aggregateReturn??null,renderedPhase:cell('Internal module dispatch / flags'),renderedAggregate:cell('API aggregate return'),callerHoldsPhaseReturn:snap.holdings.filter(h=>h.actorId==='pamChangeApp'&&h.artifactId.includes('pam-return-password')).map(h=>h.artifactId)});}
  observations.push({scenario:'lab-llog04',variant,samples});reset();
 }
}finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}

const result={mode,checks,positions,runtimePrefixes,extra,existingExecutions:existing.length,existingPrefixes:prefixes,existing,contracts,contractFailures:contracts.filter(x=>!x.passed),danglingSecretUses,invalidPublicCalls,observations,scope:'Independent source/emitted DOM, source-prefix and held-history review. No native PAM/browser execution or timing collection.'};
fs.writeFileSync(new URL('./pam05-'+mode+'.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({mode,checks,positions,runtimePrefixes,existingExecutions:existing.length,existingPrefixes:prefixes,contractFailures:result.contractFailures.length,danglingSecretUses:danglingSecretUses.length,invalidPublicCalls:invalidPublicCalls.length},null,2));