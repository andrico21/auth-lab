import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness} from './dom-harness.mjs';
import {LINUXLOGONLAB_SCENARIOS,createLinuxPasswordChangeCase} from '../src/linux-logon-lab.js';

const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const reached=[['default','PAM_SUCCESS'],['new-policy-denied','PAM_AUTHTOK_ERR'],['update-failed','PAM_AUTHTOK_ERR'],['directory-unreachable','PAM_AUTHINFO_UNAVAIL'],['directory-online','PAM_SUCCESS'],['post-change-account-denied','PAM_SUCCESS']];
const categories=[['public','aggregates','Completed API aggregate results'],['internal','password-dispatch','Internal password dispatch results'],['pending','pending-results','Pending / not-started results']];
const clone=value=>JSON.parse(JSON.stringify(value));

function withApp(run,{fixture}={}){
  const {document,window,clock}=harness,saved={location:window.location,history:window.history};
  window.location={hash:''};window.history={pushState(_state,_title,hash){window.location.hash=hash;},replaceState(_state,_title,hash){window.location.hash=hash;}};
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;app.connectedCallback();
  // Match the existing logical-focus fixtures; native Tab/CSS/AT behavior is separate.
  app.addEventListener('focusin',event=>{document.activeElement=event.target;});
  try{
    if(fixture)Object.defineProperty(app,'labModel',{configurable:true,value:fixture});
    return run(app);
  }finally{
    app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();window.location=saved.location;window.history=saved.history;
  }
}
function currentResultMap(app){
  return app.labModel.pamStatePaths.results.split('.').reduce((value,key)=>value?.[key],app.protocolSnapshot().state);
}
function assertCategories(app){
  const canonical=currentResultMap(app),expected={public:{},internal:{},pending:{}},actual={};
  for(const [phase,status] of Object.entries(canonical||{})){
    const group=status==='not evaluated'?'pending':phase==='prelim'||phase==='update'?'internal':'public';
    expected[group][phase]=status;
  }
  for(const [group,key,summary] of categories){
    const disclosure=app.querySelector('#pam-configuration-panel [data-pam-disclosure="'+key+'"]');
    if(!disclosure){
      assert.deepEqual(expected[group],{},'Missing non-empty '+group+' result disclosure');
      actual[group]={};continue;
    }
    assert.equal(disclosure.querySelector('summary').textContent,summary);
    actual[group]=JSON.parse(disclosure.querySelector('pre').textContent);
    assert.deepEqual(actual[group],expected[group],summary+' at '+app.currentStep?.id);
    if(group==='internal'){
      const explanation=disclosure.querySelector('p')?.textContent||'';
      assert.match(explanation,/prelim/);assert.match(explanation,/update/);assert.match(explanation,/pam_chauthtok/);
      assert.match(explanation,/passes.*inside|inside.*passes/i);assert.match(explanation,/not separate application calls/i);
    }
  }
  assert.equal(Object.hasOwn(actual.public,'prelim'),false);assert.equal(Object.hasOwn(actual.public,'update'),false);
  assert.equal(Object.values(actual.public).includes('not evaluated'),false);
  return actual;
}
function publicPasswordBounds(app){
  const call=app.steps.findIndex(step=>step.from==='pamChangeApp'&&step.to==='pamChange'&&step.pamEvaluation?.api==='pam_chauthtok');
  const returned=app.steps.findIndex(step=>step.from==='pamChange'&&step.to==='pamChangeApp'&&step.pamEvaluation?.api==='pam_chauthtok'&&step.pamEvaluation.aggregateReturn!==undefined);
  return {call,returned};
}
function currentAggregate(app){
  return [...(app.querySelector('#pam-configuration-panel .pam-evaluation')?.children||[])].find(row=>row.querySelector('dt')?.textContent==='API aggregate return')?.querySelector('dd')?.textContent;
}

for(const [variant,status] of reached)test('WP-R06-B separates actual public/internal disclosures through every LLOG04 prefix: '+variant,()=>withApp(app=>{
  app.selectLabScenario('lab-llog04',{variant});
  const {call,returned}=publicPasswordBounds(app);assert.ok(call>0&&returned>call);
  const observed=[];
  for(let index=0;index<app.steps.length;index++){
    app.selectStep(index,false);const groups=assertCategories(app);
    if(index<call){assert.equal(Object.hasOwn(groups.public,'password'),false);assert.deepEqual(groups.internal,{});}
    if(index>=call&&index<returned){assert.equal(Object.hasOwn(groups.public,'password'),false);assert.equal(currentAggregate(app),'Pending: current API call has not completed');}
    if(index===returned)assert.equal(groups.public.password,status);
    observed.push({groups:clone(groups),snapshot:clone(app.heldView.snapshot())});
  }
  for(const index of [returned,call-1,returned-1,call,app.steps.length-1,call-1,returned]){
    app.selectStep(index,false);assert.deepEqual(assertCategories(app),observed[index].groups);assert.deepEqual(app.heldView.snapshot(),observed[index].snapshot);
  }
}));

for(const variant of ['consumer-no-change','account-expired','wrong-current-password'])test('WP-R06-B denied/unsupported consumers do not invent password evidence: '+variant,()=>withApp(app=>{
  app.selectLabScenario('lab-llog04',{variant});
  assert.deepEqual(publicPasswordBounds(app),{call:-1,returned:-1});
  for(let index=0;index<app.steps.length;index++){
    app.selectStep(index,false);const groups=assertCategories(app);
    assert.equal(Object.hasOwn(groups.public,'password'),false);assert.deepEqual(groups.internal,{});
  }
}));

const pamReferences=[['change-success',{prelim:'PAM_SUCCESS',update:'PAM_SUCCESS'},'PAM_SUCCESS'],['change-prelim-failure',{prelim:'PAM_AUTHTOK_ERR'},'PAM_AUTHTOK_ERR'],['change-update-failure',{prelim:'PAM_SUCCESS',update:'PAM_AUTHTOK_ERR'},'PAM_AUTHTOK_ERR'],['change-unsupported',{},null]];
for(const [member,internal,status] of pamReferences)test('WP-R06-B PAM01 public/internal/not-started disclosures retain canonical timing: '+member,()=>withApp(app=>{
  app.selectLabScenario('lab-pam01',{variant:'password-change-required'});app.selectLessonSubfixture(member);
  const observed=[];
  for(let index=0;index<app.steps.length;index++){
    app.selectStep(index,false);observed.push(clone(assertCategories(app)));
  }
  const final=observed.at(-1);assert.deepEqual(final.internal,internal);
  if(status)assert.equal(final.public.password,status);
  else{assert.equal(Object.hasOwn(final.public,'password'),false);assert.equal(final.pending.password,'not evaluated');}
  const preliminary=app.steps.findIndex(step=>(step.protocolEffects||[]).some(effect=>effect.path==='workstation.pamResults.prelim'));
  if(preliminary>=0){
    app.selectStep(preliminary,false);const groups=assertCategories(app);
    assert.equal(groups.internal.prelim,internal.prelim);assert.equal(Object.hasOwn(groups.public,'password'),false);
    assert.equal(groups.pending.password,'not evaluated');
    assert.equal(groups.pending.setcred,'not evaluated');assert.equal(groups.pending.open,'not evaluated');
    assert.equal(groups.pending.close,'not evaluated');assert.equal(groups.pending['setcred-delete'],'not evaluated');assert.equal(groups.pending.end,'not evaluated');
    app.selectStep(app.steps.length-1,false);assert.deepEqual(assertCategories(app),final);
    app.selectStep(preliminary,false);assert.deepEqual(assertCategories(app),observed[preliminary]);
  }
}));

test('WP-R06-B additive preliminary failure is internally labelled and never collects or updates a candidate',()=>{
  const fixture=createLinuxPasswordChangeCase({...LINUXLOGONLAB_SCENARIOS.find(model=>model.id==='lab-llog04').fixture,prelimOk:false});
  withApp(app=>{
    app.selectLabScenario('lab-llog04');const {call,returned}=publicPasswordBounds(app);assert.ok(call>=0&&returned>call);
    for(let index=0;index<app.steps.length;index++){app.selectStep(index,false);assertCategories(app);}
    app.selectStep(returned,false);const groups=assertCategories(app);
    assert.deepEqual(groups.internal,{prelim:'PAM_AUTHTOK_ERR'});assert.equal(groups.public.password,'PAM_AUTHTOK_ERR');
    assert.equal(app.labModel.workstationInventory.artifacts.some(artifact=>artifact.artifactId==='lab-llog04:new-secret'),false);
    assert.equal(app.steps.some(step=>step.pamEvaluation?.apiPhase==='update'),false);
    assert.equal(app.protocolSnapshot().state.workstation.authorityGeneration,1);
    app.selectStep(call,false);assert.deepEqual(assertCategories(app).internal,{});
    app.selectStep(returned,false);assert.deepEqual(assertCategories(app),groups);
  },{fixture});
});

for(const [,key,summary] of categories)test('WP-R06-B disclosure focus and expanded state survive result arrival and rewind: '+key,()=>withApp(app=>{
  app.selectLabScenario('lab-pam01',{variant:'password-change-required'});app.selectLessonSubfixture('change-success');
  const preliminary=app.steps.findIndex(step=>(step.protocolEffects||[]).some(effect=>effect.path==='workstation.pamResults.prelim'));
  app.selectStep(preliminary,false);
  const selector='#pam-configuration-panel [data-pam-disclosure="'+key+'"]';
  let disclosure=app.querySelector(selector);assert.ok(disclosure);disclosure.setAttribute('open','');disclosure.querySelector('summary').focus();
  for(const index of [app.steps.length-1,preliminary-1,preliminary,app.steps.length-1]){
    app.selectStep(index,false);assertCategories(app);disclosure=app.querySelector(selector);
    assert.equal(disclosure.querySelector('summary').textContent,summary);assert.equal(disclosure.hasAttribute('open'),true);
    assert.equal(harness.document.activeElement,disclosure.querySelector('summary'));
  }
}));

test('WP-R06-B public credential teardown results remain public, not internal or pending',()=>withApp(app=>{
  app.selectLabScenario('lab-llog01');app.selectStep(app.steps.length-1,false);const groups=assertCategories(app);
  assert.equal(groups.public['setcred-delete'],'PAM_SUCCESS');assert.deepEqual(groups.internal,{});
  assert.equal(Object.hasOwn(groups.pending,'setcred-delete'),false);
}));
