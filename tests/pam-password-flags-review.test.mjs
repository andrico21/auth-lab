import test from 'node:test';
import assert from 'node:assert/strict';
import {createPamFoundationsCase} from '../src/pam-foundations-lab.js';
import {pamEvaluate,pamApiBoundary} from '../src/pam-stack-evaluator.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Literal corrections to the complete invocation flags, not replacement oracles.
const members=[
  {id:'change-success',phases:[['prelim','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_PRELIM_CHECK','PAM_SUCCESS'],['update','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_UPDATE_AUTHTOK','PAM_SUCCESS']],status:'PAM_SUCCESS',generation:2},
  {id:'change-prelim-failure',phases:[['prelim','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_PRELIM_CHECK','PAM_AUTHTOK_ERR']],status:'PAM_AUTHTOK_ERR',generation:1},
  {id:'change-update-failure',phases:[['prelim','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_PRELIM_CHECK','PAM_SUCCESS'],['update','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_UPDATE_AUTHTOK','PAM_AUTHTOK_ERR']],status:'PAM_AUTHTOK_ERR',generation:1},
];
for(const member of members)test('WP-R05 complete flags persist through '+member.id,()=>{
  const model=createPamFoundationsCase('password-change-required',member.id),steps=model.steps();
  for(const [phase,flags,status] of member.phases){
    const evaluation=model.pamEvaluations[phase];
    assert.equal(evaluation.flags,flags);assert.equal(evaluation.status,status);
    const rows=evaluation.trace;assert.ok(rows.length>0);
    for(const row of rows){
      assert.equal(row.flags,flags);assert.equal(row.api,'pam_chauthtok');
      if(row.executed)assert.equal(row.moduleHook,'pam_sm_chauthtok');
      const index=steps.findIndex(step=>step.pamEvaluation===row);assert.ok(index>=0);
      assert.deepEqual(reconstructProtocolState(model,index).workstation.pamEvaluation,row);
      const records=model.workstationInventory.artifacts.filter(artifact=>artifact.type==='pam-return').map(artifact=>JSON.parse(artifact.value));
      const record=records.find(record=>record.apiPhase===phase&&record.configurationId===row.configurationId&&record.line===row.line);
      assert.deepEqual(record,row);assert.equal(record.flags,flags);
    }
    const boundaries=steps.filter(step=>step.pamEvaluation.apiPhase===phase&&step.pamEvaluation.executed===null);
    assert.ok(boundaries.length>0);
    for(const boundary of boundaries)assert.equal(boundary.pamEvaluation.flags,flags);
  }
  const publicRows=steps.filter(step=>step.pamEvaluation.apiPhase==='password');assert.ok(publicRows.length>=2);
  for(const step of publicRows){assert.equal(step.pamEvaluation.flags,'PAM_CHANGE_EXPIRED_AUTHTOK');assert.equal(step.pamEvaluation.moduleHook,null);}
  const call=model.workstationInventory.artifacts.find(artifact=>artifact.artifactId==='lab-pam01:call-password-default-control');
  assert.ok(call);assert.equal(JSON.parse(call.value).flags,'PAM_CHANGE_EXPIRED_AUTHTOK');
  const aggregate=model.workstationInventory.artifacts.find(artifact=>artifact.artifactId==='lab-pam01:aggregate-password-default');
  const receipt=JSON.parse(aggregate.value);
  assert.equal(receipt.api,'pam_chauthtok');assert.equal(receipt.status,member.status);assert.equal(receipt.flags,'PAM_CHANGE_EXPIRED_AUTHTOK');
  const final=reconstructProtocolState(model,steps.length-1).workstation;
  assert.equal(final.pamResults.password,member.status);assert.equal(final.authorityGeneration,member.generation);
  assert.equal(final.authenticated,true);assert.equal(final.unrelatedSession,'other-user-session-retained');
});

test('WP-R05 failed preliminary and unsupported caller never dispatch update',()=>{
  const failed=createPamFoundationsCase('password-change-required','change-prelim-failure');
  assert.equal(failed.pamEvaluations.update,undefined);
  assert.equal(failed.steps().some(step=>step.pamEvaluation.apiPhase==='update'||step.id==='lab-pam01:password-candidate'),false);
  assert.equal(failed.workstationInventory.artifacts.some(artifact=>artifact.type==='pam-return'&&JSON.parse(artifact.value).apiPhase==='update'),false);
  const unsupported=createPamFoundationsCase('password-change-required','change-unsupported');
  assert.equal(unsupported.pamEvaluations.prelim,undefined);assert.equal(unsupported.pamEvaluations.update,undefined);
  assert.equal(unsupported.steps().some(step=>['password','prelim','update'].includes(step.pamEvaluation.apiPhase)),false);
  const final=reconstructProtocolState(unsupported,unsupported.steps().length-1).workstation;
  assert.equal(final.pamResults.password,'not evaluated');assert.equal(final.authorityGeneration,1);
  assert.equal(final.authenticated,true);assert.equal(final.admitted,false);
  const noChange=createPamFoundationsCase('local-login-success');
  assert.equal(noChange.steps().some(step=>['password','prelim','update'].includes(step.pamEvaluation.apiPhase)),false);
});

test('WP-R05 nonexpired caller0 supplies only internal phase bits and a phase-free public call',()=>{
  for(const [phase,flags] of [['prelim','PAM_PRELIM_CHECK'],['update','PAM_UPDATE_AUTHTOK']]){
    const result=pamEvaluate('afs-login',phase,{callerFlags:0,inputs:{['pam_unix.so:'+phase]:'PAM_SUCCESS'}});
    assert.equal(result.flags,flags);assert.equal(result.status,'PAM_SUCCESS');assert.ok(result.trace.length>0);
    for(const row of result.trace)assert.equal(row.flags,flags);
    assert.equal(pamApiBoundary('afs-login',phase,'nonexpired change',{callerFlags:0}).flags,flags);
  }
  const boundary=pamApiBoundary('afs-login','password','nonexpired caller',{callerFlags:0});
  assert.equal(boundary.flags,0);assert.equal(boundary.api,'pam_chauthtok');assert.equal(boundary.moduleHook,null);
  assert.equal(pamApiBoundary('afs-login','password','default caller').flags,0);
  const ordinary=pamEvaluate('afs-login','prelim',{inputs:{'pam_unix.so:prelim':'PAM_SUCCESS'}});
  assert.equal(ordinary.flags,'PAM_PRELIM_CHECK');
});

test('WP-R05 preserves callback PAM_CONV_ERR versus selected module PAM_AUTHTOK_ERR',()=>{
  const model=createPamFoundationsCase('conversation-failure'),steps=model.steps();
  const callback=steps.findIndex(step=>step.id==='lab-pam01:conversation-response');
  assert.equal(reconstructProtocolState(model,callback).workstation.conversationStatus,'PAM_CONV_ERR');
  const row=model.pamEvaluations.authenticate.trace.find(row=>row.module==='pam_unix.so');
  assert.equal(row.rawReturn,'PAM_AUTHTOK_ERR');assert.equal(model.pamEvaluations.authenticate.status,'PAM_AUTHTOK_ERR');
});

const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {document,window,clock}=harness;
for(const member of members)test('WP-R05 source inspector renders complete internal dispatch: '+member.id,()=>{
  const saved={location:window.location,history:window.history};
  window.location={hash:''};window.history={pushState(_state,_title,hash){window.location.hash=hash;},replaceState(_state,_title,hash){window.location.hash=hash;}};
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  try{
    app.selectLabScenario('lab-pam01',{variant:'password-change-required'});
    const control=app.querySelector('#lesson-subfixture');control.value=member.id;control.dispatchEvent(new HarnessEvent('change'));
    for(const [phase,flags,status] of member.phases){
      const index=app.steps.findIndex(step=>step.pamEvaluation?.apiPhase===phase&&step.pamEvaluation.executed===true);assert.ok(index>=0);
      app.selectStep(index,false);
      const panel=app.querySelector('#pam-configuration-panel');
      const dispatch=[...panel.querySelectorAll('.pam-evaluation div')].find(row=>row.querySelector('dt')?.textContent==='Internal module dispatch / flags');
      assert.ok(dispatch);assert.equal(dispatch.querySelector('dd').textContent,'pam_chauthtok / '+flags);
      assert.equal(app.protocolSnapshot().state.workstation.pamEvaluation.flags,flags);
      assert.equal(app.protocolSnapshot().state.workstation.pamEvaluation.rawReturn,status);
      assert.ok(panel.querySelector('[aria-current="step"] code').textContent.includes('password required pam_unix.so'));
    }
    app.selectStep(app.steps.findIndex(step=>step.id==='lab-pam01:call-password-default'),false);
    const panel=app.querySelector('#pam-configuration-panel');
    const publicCall=[...panel.querySelectorAll('.pam-evaluation div')].find(row=>row.querySelector('dt')?.textContent==='API call / flags');
    assert.equal(publicCall.querySelector('dd').textContent,'pam_chauthtok / PAM_CHANGE_EXPIRED_AUTHTOK');
    assert.equal(panel.textContent.includes('PAM_PRELIM_CHECK'),false);assert.equal(panel.textContent.includes('PAM_UPDATE_AUTHTOK'),false);
  }finally{
    app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();window.location=saved.location;window.history=saved.history;
  }
});
