import test from 'node:test';
import assert from 'node:assert/strict';
import {buildWindowsLogonFixture} from '../src/windows-logon-lab.js';
import {buildWindowsElevationFixture} from '../src/windows-elevation-lab.js';
import {buildWindowsWorkstationHeldObjects} from '../src/held-object-windows-workstation.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

function fixture(id,variant='default'){
  const model=id.startsWith('lab-welev')?buildWindowsElevationFixture(id,variant):buildWindowsLogonFixture(id,variant),steps=model.steps();
  const plan=buildWindowsWorkstationHeldObjects({model,steps,actors:model.actors(),config:{},contextId:id+':'+variant,choiceId:id}),compiled=compileHeldObjects(plan,{model,steps});
  const index=stage=>{const n=steps.findIndex(step=>step.workstationStage===stage);assert.ok(n>=0,id+'/'+variant+'/'+stage);return n;};
  return {model,steps,plan,index,step:stage=>steps[index(stage)],frame:(stage,milestone='complete')=>projectHeldObjects(compiled,{eventIndex:index(stage),milestone}),state:stage=>reconstructProtocolState(model,index(stage)).workstation};
}
const holds=(frame,actor,artifact,representation='plain')=>frame.holdings.some(h=>h.actorId===actor&&h.artifactId===artifact&&h.representationId===representation);
const operations=(step,kind)=>step.attributeOperations.filter(op=>op.kind===kind).map(op=>[op.actorId,op.instanceId]);

for(const [variant,returnStage,resultKey] of [
  ['default','network-handoff','network-result'],
  ['wrong-password-launches','network-handoff','network-result'],
  ['share-denied','network-handoff','network-result'],
  ['dc-unreachable','network-result-1','failure-network'],
  ['connection-reuse','network-result-1','failure-network']
])test('WIN-P6-01 '+variant+' returns only Q-owned SMB operation holdings',()=>{
  const f=fixture('lab-welev05',variant),id='lab-welev05',request=f.step('network-request'),returned=f.step(returnStage),launched=f.state('context');
  assert.deepEqual([request.from,request.to],['wslChild','wslNetwork']);
  assert.deepEqual([returned.from,returned.to],['wslNetwork','wslChild']);
  assert.ok(f.index('context')<f.index('network-prepare'));assert.ok(f.index('network-prepare')<f.index('network-request'));assert.ok(f.index('network-request')<f.index(returnStage));
  assert.ok(holds(f.frame('network-request','before'),'wslChild',id+':network-request'));assert.ok(holds(f.frame('network-request','before'),'wslChild',id+':new-credentials-reference'));
  assert.equal(launched.launchSucceeded,true);assert.equal(launched.childRunning,true);assert.equal(launched.credentialVerified,false);assert.equal(launched.networkAuthenticated,false);
  assert.equal(launched.childToken.account,'WORKGROUPPC\\bob');assert.equal(launched.childToken.userSid,'S-1-5-21-110-220-330-1001');
  assert.deepEqual(launched.childToken.groups,launched.callerToken.groups);assert.deepEqual(launched.childToken.privileges,launched.callerToken.privileges);
  assert.equal(launched.childToken.integrity,'medium');assert.equal(launched.childToken.authenticationId,'LUID(NewCredentials-5)');assert.notEqual(launched.childToken.authenticationId,launched.callerToken.authenticationId);
  const requestObject=f.model.workstationInventory.artifacts.find(o=>o.artifactId===id+':network-request');
  assert.deepEqual(requestObject.value,{requestId:id+':network-request-1',operation:'SMB read quarterly report',server:'files.corp.example',credentialContextRef:id+':new-credentials-context'});
  assert.ok(holds(f.frame('local'),'wslChild',id+':new-credentials-reference'));
  assert.equal(holds(f.frame('local'),'wslChild',id+':deferred-credential'),false);
  assert.deepEqual(operations(request,'use'),[['wslChild',id+':new-credentials-reference']]);
  const before=f.frame(returnStage,'before'),after=f.frame(returnStage);
  assert.equal(holds(before,'wslChild',id+':'+resultKey),false);assert.ok(holds(after,'wslChild',id+':'+resultKey));
  const holding=after.holdings.find(h=>h.actorId==='wslChild'&&h.artifactId===id+':'+resultKey);
  const value=inspectHeldObject(after,holding.holdingId).fields[0].value;
  assert.equal(value.requestId,id+':network-request-1');assert.equal(value.operation,'SMB read quarterly report');assert.equal(value.credentialContextRef,id+':new-credentials-context');
  for(const step of f.steps){
    for(const message of f.plan.events[step.id].messages||[])assert.equal(message.to==='wslProcess'&&message.objects.some(o=>[id+':'+resultKey,id+':smb:file-data'].includes(o.artifactId)),false);
    const frame=f.frame(step.workstationStage);
    assert.equal(holds(frame,'wslProcess',id+':'+resultKey),false);assert.equal(holds(frame,'wslProcess',id+':smb:file-data'),false);
  }
  if(variant==='default'){
    assert.equal(holds(before,'wslChild',id+':smb:file-data'),false);assert.ok(holds(after,'wslChild',id+':smb:file-data'));
    assert.ok(f.index('smb:read-accept')<f.index(returnStage));
    const data=after.holdings.find(h=>h.actorId==='wslChild'&&h.artifactId===id+':smb:file-data');
    assert.equal(inspectHeldObject(after,data.holdingId).fields[0].value,'Quarterly report: synthetic teaching content.');
  }else{
    assert.equal(f.state(returnStage).childRunning,true);assert.equal(holds(after,'wslChild',id+':smb:file-data'),false);
    if(['dc-unreachable','connection-reuse'].includes(variant))assert.equal(f.state('network').detector,'wslNetwork');
    if(variant==='wrong-password-launches')assert.ok(f.index('context')<f.index('network'));
  }
});

test('WIN-P6-01 WLOG08 preserves its original requesting application actor',()=>{
  const f=fixture('lab-wlog08');assert.deepEqual([f.step('network-request').from,f.step('network-request').to],['wslProcess','wslNetwork']);
  assert.deepEqual([f.step('network-handoff').from,f.step('network-handoff').to],['wslNetwork','wslProcess']);
  assert.ok(holds(f.frame('network-handoff'),'wslProcess','lab-wlog08:network-result'));
  assert.ok(holds(f.frame('network-handoff'),'wslProcess','lab-wlog08:smb:file-data'));
});

for(const [id,variant,tgtKey,tgt] of [
  ['lab-wlog02','default','tgt-session-key','tgt'],
  ['lab-wlog02','host-key-mismatch','tgt-session-key','tgt'],
  ['lab-wlog02','denied-local-logon','tgt-session-key','tgt'],
  ['lab-wlog05','default','ad:user-tgt-session-key:1','ad:user-tgt:1'],
  ['lab-wlog06','default','ad:issued-ticket-session-key:1','ad:issued-ticket:1'],
  ['lab-welev03','domain-admin-credential','tgt-session-key','tgt']
])test('WIN-P6-02 '+id+'/'+variant+' authenticates and decrypts with the exact request subkey',()=>{
  const f=fixture(id,variant),subkey=id+':host-reply-subkey',request=id+':host-tgs-request',proof=id+':host-operation-proof';
  const sequence=['host-tgs-prepare','host-tgs-operation','host-tgs-operation-return','host-tgs-encode','host-tgs-request','host-tgs-verify','host-ticket','host-tgs-reply','host-reply-context-check','host-client-decode','host-tgs-accept'];
  for(let n=1;n<sequence.length;n++)assert.ok(f.index(sequence[n-1])<f.index(sequence[n]),sequence[n]);
  assert.deepEqual(operations(f.step('host-tgs-operation'),'use'),[['wslIso',id+':credential-context-reference'],['wslIso',id+':'+tgtKey]]);
  assert.deepEqual(operations(f.step('host-tgs-operation'),'create'),[['wslIso',subkey],['wslIso',proof]]);
  assert.equal(holds(f.frame('host-tgs-operation'),'wslLSA',subkey),false);
  assert.ok(holds(f.frame('host-tgs-operation-return'),'wslLSA',subkey));
  assert.equal(holds(f.frame('host-tgs-request'),'wslDC',subkey),false);
  assert.deepEqual(operations(f.step('host-tgs-verify'),'use'),[['wslDC',id+':kdc-krbtgt-key'],['wslDC',id+':'+tgtKey]]);
  assert.deepEqual(new Set(operations(f.step('host-tgs-verify'),'verify').map(op=>op[1])),new Set([id+':'+tgt,proof,request]));
  assert.deepEqual(operations(f.step('host-tgs-verify'),'decrypt'),[['wslDC',subkey]]);
  assert.ok(holds(f.frame('host-tgs-verify'),'wslDC',subkey));
  assert.deepEqual(operations(f.step('host-ticket'),'use'),[['wslDC',id+':kdc-machine-service-key'],['wslDC',subkey]]);
  const subkeyObject=f.model.workstationInventory.artifacts.find(o=>o.artifactId===subkey),reply=f.model.workstationInventory.artifacts.find(o=>o.artifactId===id+':host-client-reply');
  assert.deepEqual(subkeyObject.value,{key:'HANDLE(fresh AES128 TGS authenticator subkey)',requestId:id+':host-request-52001',nonce:52001,target:'host/workstation.corp.example',keyUsage:9});
  assert.equal(reply.value.replyKeyRef,subkey);assert.equal(reply.value.requestId,id+':host-request-52001');assert.equal(reply.value.keyUsage,9);
  const receipt=f.frame('host-tgs-reply');assert.ok(holds(receipt,'wslLSA',id+':host-client-reply','wire'));
  assert.equal(holds(receipt,'wslLSA',id+':host-client-reply'),false);assert.equal(holds(receipt,'wslLSA',id+':host-session-key'),false);
  assert.deepEqual(f.step('host-client-decode').attributeOperations.map(op=>[op.kind,op.actorId,op.instanceId]),[['use','wslLSA',subkey],['decrypt','wslLSA',id+':host-client-reply']]);
  assert.ok(holds(f.frame('host-client-decode'),'wslLSA',id+':host-client-reply'));
  assert.equal(holds(f.frame('host-client-decode'),'wslLSA',id+':host-session-key'),false);assert.ok(holds(f.frame('host-tgs-accept'),'wslLSA',id+':host-session-key'));
  assert.ok(holds(receipt,'wslIso',id+':'+tgtKey));assert.equal(holds(receipt,'wslLSA',id+':'+tgtKey),false);
  assert.equal(holds(receipt,'wslMachine',id+':kdc-machine-service-key'),false);assert.equal(holds(receipt,'wslDC',id+':machine-service-key'),false);
  for(const event of Object.values(f.plan.events))for(const message of event.messages||[])assert.equal(message.objects.some(o=>o.artifactId===id+':'+tgtKey),false);
});

for(const variant of ['missing-host-reply-context','wrong-host-reply-context'])test('WIN-P6-02 '+variant+' stops before plaintext, service-key installation and local ticket submission',()=>{
  const f=fixture('lab-wlog02',variant),id='lab-wlog02',rejected=f.frame('host-reply-context');
  assert.ok(f.index('host-tgs-reply')<f.index('host-reply-context'));
  for(const stage of ['host-client-decode','host-tgs-accept','local-ticket-submit'])assert.equal(f.steps.some(s=>s.workstationStage===stage),false);
  assert.equal(holds(rejected,'wslLSA',id+':host-client-reply'),false);assert.equal(holds(rejected,'wslLSA',id+':host-session-key'),false);
  assert.ok(holds(rejected,'wslLSA',id+':host-client-reply','wire'));assert.equal(f.state('host-reply-context').clientKnowsResult,false);
  assert.equal(f.state('host-reply-context').tgtAccepted,true);assert.equal(f.state('host-reply-context').hostTicketAccepted,false);assert.equal(f.state('host-reply-context').token,null);
  if(variant==='missing-host-reply-context')assert.equal(holds(rejected,'wslLSA',id+':host-reply-subkey'),false);
  else assert.deepEqual(operations(f.step('host-reply-context'),'use'),[['wslLSA',id+':wrong-host-reply-subkey']]);
});

for(const [variant,account] of [['default','WORKSTATION\\admin2'],['domain-admin-credential','CORP\\admin2']])test('WIN-P6-03 '+variant+' completes with credential-free correlated caller receipt',()=>{
  const f=fixture('lab-welev03',variant),id='lab-welev03';
  assert.ok(f.index('launch')<f.index('input-cleanup'));assert.ok(f.index('input-cleanup')<f.index('launch-result-prompt'));assert.ok(f.index('launch-result-prompt')<f.index('launch-result'));
  for(const stage of ['launch','input-cleanup','launch-result-prompt'])assert.equal(f.state(stage).clientKnowsResult,false);
  assert.equal(f.state('launch-result').clientKnowsResult,true);assert.equal(f.state('launch-result').alternateVerified,true);
  assert.ok(f.model.decisionBindings.some(b=>b.label==='Alternate administrator credential verified'&&b.path==='workstation.alternateVerified'));
  assert.equal(f.model.decisionBindings.some(b=>b.label==='Credential verified for this attempt'),false);
  assert.deepEqual([f.step('launch-result-prompt').from,f.step('launch-result-prompt').to],['wslBroker','wslUI']);
  assert.deepEqual([f.step('launch-result').from,f.step('launch-result').to],['wslUI','wslProcess']);
  assert.equal(holds(f.frame('launch-result','before'),'wslProcess',id+':launch-result'),false);assert.ok(holds(f.frame('launch-result'),'wslProcess',id+':launch-result'));
  const outcome=f.model.workstationInventory.artifacts.find(o=>o.artifactId===id+':launch-result');
  assert.deepEqual(outcome.value,{requestId:id+':request-1',success:true,processId:'PID('+id+'-Q)',childAccount:account,originalDesktopUnchanged:true});
  assert.deepEqual(f.state('launch-result').token,f.model.initialState.workstation.callerToken);assert.equal(f.state('launch-result').childRunning,true);
  assert.equal(f.frame('launch-result').holdings.some(h=>h.artifactId===id+':admin-input'),false);
});

test('WIN-P6-03 existing rejection returns remain separate from successful launch results',()=>{
  for(const variant of ['wrong-admin-password','valid-nonadmin','domain-unavailable','auto-deny-standard-users']){
    const f=fixture('lab-welev03',variant),last=f.steps.at(-1).workstationStage;
    assert.equal(f.steps.some(s=>s.workstationStage==='launch-result'),false);assert.equal(f.state(last).clientKnowsResult,true);
    assert.equal(f.state(last).childRunning,false);assert.deepEqual(f.state(last).token,f.model.initialState.workstation.callerToken);
  }
});
