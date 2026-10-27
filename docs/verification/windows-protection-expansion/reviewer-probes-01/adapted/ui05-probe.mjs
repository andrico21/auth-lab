import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {installHarness,HarnessEvent} from '../source/tests/dom-harness.mjs';
import {LINUXLOGONLAB_SCENARIOS} from '../source/src/linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS} from '../source/src/linux-elevation-lab.js';
import {createPamFoundationsCase} from '../source/src/pam-foundations-lab.js';
import {reconstructProtocolState} from '../source/src/protocol-state.js';
const mode=process.argv[2]||'source',sandbox=mode==='emitted'?{structuredClone}:globalThis;
const harness=installHarness(sandbox);let Component,checks=0,positions=0;
const observations=[],disclosureMislabels=[];
const copy=x=>x===undefined?undefined:JSON.parse(JSON.stringify(x));
const eq=(a,b,m)=>{assert.deepEqual(copy(a),copy(b),m);checks++;};
const ok=(v,m)=>{assert.ok(v,m);checks++;};
if(mode==='emitted'){
 const bytes=fs.readFileSync(new URL('../auth-flow-studio-windows-protection.html',import.meta.url));
 eq(createHash('sha256').update(bytes).digest('hex'),'9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694','Exact supplied candidate05');
 const scripts=[...bytes.toString().matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];eq(scripts.length,1,'One actual emitted script');
 new vm.Script(scripts[0][1]).runInContext(vm.createContext(sandbox));Component=harness.registry.get('auth-flow-studio');
}else ({AuthFlowStudio:Component}=await import('../source/src/app.js'));
const app=new Component();harness.document.body.appendChild(app);app.connectedCallback();
const text=n=>n?.textContent.replace(/\s+/g,' ').trim()||'';
const values=()=>Object.fromEntries([...app.querySelector('#pam-configuration-panel .pam-evaluation')?.children||[]].map(n=>[text(n.querySelector('dt')),text(n.querySelector('dd'))]));
const bases=[...LINUXLOGONLAB_SCENARIOS,...LINUXELEVLAB_SCENARIOS];
let independentModel;
function choose(id,variant='default'){
 app.selectLabScenario(id,{variant});independentModel=bases.find(m=>m.id===id).withVariant(variant);
}
function select(i){app.selectStep(i,false);positions++;const s=app.heldView.snapshot();eq(s.state,reconstructProtocolState(independentModel,s.cursor.eventIndex),'Actual rendered prefix equals independent source state');return s;}
function reset(){app.clearAttribute();app.reset();eq(app.heldView.snapshot().cursor,{eventIndex:-1,milestone:'initial'},'Reset initial');eq(app.heldView.selection,null,'Reset selection cleared');}
function histories(artifactId){
 const artifact=app.labModel.workstationInventory.artifacts.find(a=>a.artifactId===artifactId);ok(artifact,'Actual history artifact exists');
 app.clearAttribute();app.selectAttribute(artifact.attributeId,false);
 const field=app.traceQueue.map(s=>s.sourceStepId||s.id);
 for(let i=0;i<app.visibleSteps.length;i++)select(i);
 for(let i=app.visibleSteps.length-1;i>=0;i--)select(i);
 app.clearAttribute();app.heldView.trace(artifactId);const exact=app.traceQueue.map(s=>s.sourceStepId||s.id);
 for(let i=0;i<app.visibleSteps.length;i++)select(i);
 for(let i=app.visibleSteps.length-1;i>=0;i--)select(i);
 app.clearAttribute();return {field,exact};
}
try{
 for(const variant of ['default','wrong-password','expired-timestamp','different-terminal','rootpw','targetpw','runaspw','account-denied']){
  choose('lab-lelev01',variant);const steps=app.steps,secret='lab-lelev01:secret';
  const module=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed),aggregate=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.aggregateReturn!==undefined);
  const before=select(module-1);ok(before.holdings.some(h=>h.artifactId===secret&&h.actorId==='lelevPAM'),'Password held at real operation');
  const after=select(module);eq(after.holdings.filter(h=>h.artifactId===secret),[],'Password released at module');eq(values()['API aggregate return'],'Pending: current API call has not completed','Module return is not API aggregate');
  const completed=select(aggregate);eq(completed.holdings.filter(h=>h.artifactId===secret),[],'Aggregate never recreates secret');eq(values()['API aggregate return'],variant==='wrong-password'?'PAM_AUTH_ERR':'PAM_SUCCESS','Sudo aggregate outcome');
  const uses=steps.flatMap(s=>(s.attributeOperations||[]).filter(o=>o.instanceId===secret&&o.kind==='use'&&o.actorId==='lelevPAM').map(()=>s.id));eq(uses,[steps[module].id],'One physical raw password use');
  const trace=histories(secret);for(const kind of ['field','exact']){ok(trace[kind].includes(steps[module].id),'History retains true physical use');eq(trace[kind].includes(steps[aggregate].id),false,'History excludes invented aggregate secret use');}
  select(module-1);eq(select(aggregate),completed,'Backward/forward restores exact completed snapshot');
  observations.push({type:'sudo',variant,module:steps[module].id,aggregate:steps[aggregate].id,uses,...trace});reset();
 }
 choose('lab-llog01');{
  const steps=app.steps,secret='lab-llog01:entered-secret',module=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed),aggregate=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.aggregateReturn!==undefined);
  const end=select(aggregate);eq(end.holdings.filter(h=>h.artifactId==='lab-llog01:verifier').map(h=>h.actorId),['llogPAM'],'LLOG01 verifier provenance retained');const trace=histories(secret);eq(trace.exact.includes(steps[aggregate].id),false,'LLOG01 aggregate not a new password use');observations.push({type:'llog01',...trace});reset();
 }
 for(const [variant,status] of [['default','PAM_SUCCESS'],['new-policy-denied','PAM_AUTHTOK_ERR'],['update-failed','PAM_AUTHTOK_ERR'],['directory-unreachable','PAM_AUTHINFO_UNAVAIL'],['directory-online','PAM_SUCCESS'],['post-change-account-denied','PAM_SUCCESS']]){
  choose('lab-llog04',variant);const steps=app.steps,inventory=app.labModel.workstationInventory.artifacts;
  const calls=steps.map((s,i)=>({s,i})).filter(({s})=>s.from==='pamChangeApp'&&s.to==='pamChange'&&s.pamEvaluation?.api==='pam_chauthtok'),returns=steps.map((s,i)=>({s,i})).filter(({s})=>s.from==='pamChange'&&s.to==='pamChangeApp'&&s.pamEvaluation?.api==='pam_chauthtok'&&s.pamEvaluation.aggregateReturn!==undefined);
  eq(calls.length,1,'One actual public password API call');eq(returns.length,1,'One actual public password API return');const begin=calls[0].i,end=returns[0].i;
  eq(calls[0].s.pamEvaluation.flags,'PAM_CHANGE_EXPIRED_AUTHTOK','Public call has no internal flag');eq(returns[0].s.pamEvaluation.flags,'PAM_CHANGE_EXPIRED_AUTHTOK','Public return caller flags');
  const aggregate=inventory.find(a=>a.type==='pam-aggregate'&&JSON.parse(a.value).api==='pam_chauthtok');ok(aggregate,'One actual aggregate artifact');
  eq(inventory.filter(a=>a.type==='pam-aggregate'&&JSON.parse(a.value).api==='pam_chauthtok').length,1,'No internal phase public aggregates');
  const samples=[];
  for(let i=begin;i<end;i++){
   const snap=select(i),rendered=values();eq(rendered['API aggregate return'],'Pending: current API call has not completed','Every intermediate rendered prefix remains pending');eq(snap.state.workstation.pamResults?.password,undefined,'Public result not published early');eq(snap.holdings.some(h=>h.actorId==='pamChangeApp'&&h.artifactId===aggregate.artifactId),false,'No caller-held public result before delivery');
   const e=steps[i].pamEvaluation;
   if(e?.executed&&['prelim','update'].includes(e.apiPhase)){
    eq(rendered['Internal module dispatch / flags'],'pam_chauthtok / PAM_CHANGE_EXPIRED_AUTHTOK | '+(e.apiPhase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK'),'Internal hook complete flags');
    const line=app.querySelector('#pam-configuration-panel [aria-current="step"]');eq(Number(line.dataset.pamLine),e.line,'Current physical configuration line');eq(text(line.querySelector('code')),e.text,'Exact physical configuration statement');
   }
   const disclosure=app.querySelector('#pam-configuration-panel [data-pam-disclosure="aggregates"]');
   if(snap.state.workstation.pamResults?.prelim!==undefined){
    const label=text(disclosure?.querySelector('summary')),content=text(disclosure?.querySelector('pre'));
    if(label==='Completed API aggregate results'&&content.includes('prelim'))disclosureMislabels.push({scenario:'lab-llog04',variant,index:i,step:steps[i].id,label,content,currentAggregate:rendered['API aggregate return']});
   }
   samples.push({index:i,id:steps[i].id,rendered,results:copy(snap.state.workstation.pamResults)});
  }
  const returned=select(end);eq(values()['API aggregate return'],status,'Rendered single public completion');eq(returned.state.workstation.pamResults.password,status,'Canonical single public outcome');ok(returned.holdings.some(h=>h.actorId==='pamChangeApp'&&h.artifactId===aggregate.artifactId),'Actual caller receives public result');
  const trace=histories(aggregate.artifactId);for(const kind of ['field','exact'])ok(trace[kind].includes(steps[end].id),'Result history includes actual delivery');
  for(let i=end;i>=begin;i--){select(i);eq(values()['API aggregate return'],i===end?status:'Pending: current API call has not completed','Backward full-flow current public status');}
  eq(select(end),returned,'Password return exact deterministic rewind');observations.push({type:'password',variant,begin,end,publicAggregate:aggregate.artifactId,samples,...trace});reset();
 }
 for(const variant of ['consumer-no-change','account-expired','wrong-current-password']){choose('lab-llog04',variant);eq(app.steps.filter(s=>s.pamEvaluation?.api==='pam_chauthtok').length,0,'No invented unsupported/denied password call');reset();}
 // Reference PAM01 exhibits the same shared disclosure wording, without changing its closed flag contract.
 app.selectLabScenario('lab-pam01',{variant:'password-change-required'});const control=app.querySelector('#lesson-subfixture');control.value='change-success';control.dispatchEvent(new HarnessEvent('change'));independentModel=createPamFoundationsCase('password-change-required','change-success');
 const p=app.steps.findIndex(s=>(s.protocolEffects||[]).some(e=>e.path==='workstation.pamResults.prelim'));
 select(p);const disclosure=app.querySelector('#pam-configuration-panel [data-pam-disclosure="aggregates"]');observations.push({type:'reference-pam01-disclosure',index:p,step:app.steps[p].id,label:text(disclosure?.querySelector('summary')),content:text(disclosure?.querySelector('pre'))});
 const result={mode,checks,positions,observations,disclosureMislabels,scope:'Actual source and exact supplied IIFE in DOM harness; no native browser, OS/PAM, screen-reader or performance acceptance.'};
 fs.writeFileSync(new URL('./ui05-'+mode+'.json',import.meta.url),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({mode,checks,positions,disclosureMislabels:disclosureMislabels.length}));
}finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}