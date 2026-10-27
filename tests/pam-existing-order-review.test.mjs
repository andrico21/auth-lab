import test from 'node:test';
import assert from 'node:assert/strict';
import {LINUXLOGONLAB_SCENARIOS} from '../src/linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS} from '../src/linux-elevation-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildUnixWorkstationHeldObjects} from '../src/held-object-unix-workstation.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';

const select=(id,variant='default')=>[...LINUXLOGONLAB_SCENARIOS,...LINUXELEVLAB_SCENARIOS].find(model=>model.id===id).withVariant(variant);
const state=(model,index)=>reconstructProtocolState(model,index).workstation;
const rows=(model,phase)=>model.steps().map((step,index)=>({step,index,row:step.pamEvaluation})).filter(({row})=>row?.apiPhase===phase);
const completed=(model,phase)=>rows(model,phase).find(({row})=>Object.hasOwn(row,'aggregateReturn'));
function held(model){const steps=model.steps(),raw=buildUnixWorkstationHeldObjects({model,steps,actors:model.actors(),choiceId:model.id,contextId:model.id+':ordered-pam'}),plan=compileHeldObjects(raw,{model,steps});return index=>projectHeldObjects(plan,{eventIndex:index,milestone:index<0?'initial':'complete'});}

for(const [id,variant,lines,allowed] of [
  ['lab-lelev01','default',[3,4],true],
  ['lab-lelev01','account-denied',[3,4],false],
  ['lab-lelev02','default',[4,5],true],
  ['lab-lelev02','access-denied',[4,5],false],
])test('WP-R06 account rows complete once in causal order: '+id+'/'+variant,()=>{
  const model=select(id,variant),flow=rows(model,'account'),modules=flow.filter(({row})=>row.executed===true),result=completed(model,'account');
  const expected=allowed?'PAM_SUCCESS':'PAM_PERM_DENIED';
  assert.deepEqual(modules.map(({row})=>row.line),lines);
  assert.deepEqual(modules.map(({row})=>row.module),['pam_unix.so','pam_access.so']);
  assert.deepEqual(modules.map(({row})=>row.rawReturn),['PAM_SUCCESS',expected]);
  assert.deepEqual(modules.map(({row})=>row.mappedAction),['ok',allowed?'ok':'bad']);
  assert.deepEqual(modules[0].row.accumulatorBefore,{impression:'undefined',status:'PAM_PERM_DENIED'});
  assert.deepEqual(modules[0].row.accumulatorAfter,{impression:'positive',status:'PAM_SUCCESS'});
  assert.deepEqual(modules[1].row.accumulatorBefore,modules[0].row.accumulatorAfter);
  assert.deepEqual(modules[1].row.accumulatorAfter,{impression:allowed?'positive':'negative',status:expected});
  assert.deepEqual(modules[0].row.nextRow,{configurationId:model.pamConfiguration.configurationId,line:lines[1]});
  const begin=flow.find(({row})=>row.apiPending&&row.line===null);
  assert.ok(begin.index<modules[0].index);assert.ok(modules[0].index<modules[1].index);assert.ok(modules[1].index<result.index);
  for(let index=begin.index;index<result.index;index++){
    const current=state(model,index);assert.equal(current.pamResults?.account,undefined);assert.equal(current.admitted,false);
  }
  assert.equal(state(model,result.index).pamResults.account,expected);assert.equal(state(model,result.index).admitted,allowed);
  for(const {index,row} of modules){assert.deepEqual(state(model,index).pamEvaluation,row);assert.equal(row.apiPending,true);}
  const records=model.workstationInventory.artifacts.filter(artifact=>artifact.type==='pam-return').map(artifact=>JSON.parse(artifact.value)).filter(row=>row.apiPhase==='account'&&row.executed);
  assert.deepEqual(records.map(row=>[row.line,row.rawReturn]),[[lines[0],'PAM_SUCCESS'],[lines[1],expected]]);
  const frame=held(model),before=frame(modules[1].index-1),after=frame(result.index);
  assert.deepEqual(frame(modules[1].index-1),before);assert.equal(after.state.workstation.pamResults.account,expected);
  assert.equal(state(model,model.steps().length-1).operation,allowed);assert.equal(state(model,model.steps().length-1).unrelatedSession,'other-user-session-retained');
});

test('WP-R06 non-root rootok continues the same API without an early aggregate',()=>{
  const model=select('lab-lelev02','setuid-not-real-root'),auth=rows(model,'authenticate'),modules=auth.filter(({row})=>row.executed===true),result=completed(model,'authenticate');
  assert.deepEqual(modules.map(({row})=>[row.module,row.rawReturn,row.mappedAction]),[['pam_rootok.so','PAM_AUTH_ERR','ignore'],['pam_unix.so','PAM_AUTH_ERR','bad']]);
  assert.deepEqual(modules[1].row.accumulatorBefore,modules[0].row.accumulatorAfter);
  assert.equal(auth.filter(({row})=>row.apiPending&&row.line===null).length,1);
  for(let index=modules[0].index;index<result.index;index++)assert.equal(state(model,index).pamResults?.authenticate,undefined);
  assert.equal(state(model,result.index).pamResults.authenticate,'PAM_AUTH_ERR');assert.equal(state(model,model.steps().length-1).operation,false);
});

test('WP-R06 real-UID0 sufficient rootok returns before caller consumption without a password hook',()=>{
  const model=select('lab-lelev02','real-root-bypass'),auth=rows(model,'authenticate'),modules=auth.filter(({row})=>row.executed===true),result=completed(model,'authenticate');
  assert.deepEqual(modules.map(({row})=>[row.module,row.rawReturn,row.mappedAction]),[['pam_rootok.so','PAM_SUCCESS','done']]);
  assert.equal(state(model,modules[0].index).pamResults?.authenticate,undefined);
  assert.equal(state(model,result.index).pamResults.authenticate,'PAM_SUCCESS');assert.equal(state(model,result.index).authenticated,false);
  const final=state(model,model.steps().length-1);assert.equal(final.authenticated,true);assert.equal(final.passwordCompared,false);assert.equal(final.operation,true);
  const results=model.workstationInventory.artifacts.filter(artifact=>artifact.type==='pam-aggregate').map(artifact=>JSON.parse(artifact.value)).filter(result=>result.apiPhase==='authenticate');
  assert.deepEqual(results.map(result=>result.status),['PAM_SUCCESS']);
});

test('WP-R06 target process custody waits for completed open-session aggregate',()=>{
  const model=select('lab-lelev02'),result=completed(model,'open'),frame=held(model),steps=model.steps(),launch=steps.findIndex(step=>step.attributeOperations.some(op=>op.kind==='create'&&op.instanceId==='lab-lelev02:shell'));
  assert.ok(result.index<launch);assert.equal(frame(result.index).holdings.some(h=>h.artifactId==='lab-lelev02:shell'),false);
  assert.equal(state(model,result.index).operation,false);assert.equal(state(model,launch).operation,true);
  assert.equal(frame(launch).holdings.some(h=>h.artifactId==='lab-lelev02:shell'&&h.actorId==='suShell'),true);
});

for(const variant of ['default','directory-online','directory-unreachable'])test('WP-R05 existing expired-token caller keeps complete internal flags: '+variant,()=>{
  const model=select('lab-llog04',variant);
  for(const [phase,flags] of [['prelim','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_PRELIM_CHECK'],['update','PAM_CHANGE_EXPIRED_AUTHTOK | PAM_UPDATE_AUTHTOK']]){
    const modules=rows(model,phase).filter(({row})=>row.executed===true);
    assert.deepEqual(modules.map(({row})=>row.flags),[flags]);
    const records=model.workstationInventory.artifacts.filter(artifact=>artifact.type==='pam-return').map(artifact=>JSON.parse(artifact.value)).filter(row=>row.apiPhase===phase&&row.executed);
    assert.deepEqual(records.map(row=>row.flags),[flags]);
  }
});

test('local authentication acceptance retains verifier provenance without a second check or caller disclosure',()=>{
  const model=select('lab-llog01'),auth=rows(model,'authenticate'),modules=auth.filter(({row})=>row.executed===true),result=completed(model,'authenticate'),frame=held(model);
  assert.equal(modules.length,1);
  assert.ok(modules[0].index<result.index);
  assert.equal(result.step.id,'lab-llog01:pam-auth');
  assert.equal(result.step.from,'llogPAM');assert.equal(result.step.to,'llogPAM');
  assert.equal(frame(modules[0].index).state.workstation.authenticated,false);
  assert.equal(frame(result.index).state.workstation.authenticated,true);
  const verifier='lab-llog01:verifier';
  const checks=Object.entries(model.workstationInventory.events).filter(([,event])=>event.milestones.some(m=>m.effects.some(effect=>effect.op==='observe'&&effect.kind==='verification'&&effect.artifactId===verifier)));
  assert.deepEqual(checks.map(([eventId])=>eventId),[modules[0].step.id]);
  const steps=model.steps(),compiled=compileHeldObjects(buildUnixWorkstationHeldObjects({model,steps,actors:model.actors(),choiceId:model.id,contextId:model.id+':single-secret-use'}),{model,steps});
  const secretHistory=heldObjectTrace(compiled,'lab-llog01:entered-secret');
  assert.ok(secretHistory.some(row=>row.sourceStepId===modules[0].step.id));
  assert.equal(secretHistory.some(row=>row.sourceStepId===result.step.id),false);
  for(let index=modules[0].index;index<model.steps().length;index++){
    assert.deepEqual(frame(index).holdings.filter(h=>h.artifactId===verifier).map(h=>h.actorId),['llogPAM']);
  }
});
