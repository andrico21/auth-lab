import test from 'node:test';
import assert from 'node:assert/strict';
import {buildWindowsLogonFixture,WINDOWSLOGONLAB_SCENARIOS} from '../src/windows-logon-lab.js';
import {buildWindowsElevationFixture,WINDOWSELEVLAB_SCENARIOS} from '../src/windows-elevation-lab.js';
import {buildWindowsWorkstationHeldObjects} from '../src/held-object-windows-workstation.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

function wshtFixture(variant='default'){
  const model=buildWindowsLogonFixture('lab-wlog01',variant),steps=model.steps();
  const plan=buildWindowsWorkstationHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':'+variant,choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  return {model,steps,plan,compiled,frame:stage=>projectHeldObjects(compiled,{eventIndex:steps.findIndex(s=>s.workstationStage===stage),milestone:'complete'})};
}

test('Exact token is born at local policy grant, not password collection; seek reconstructs prefix',()=>{
  const f=wshtFixture(),id='lab-wlog01:primary-token';
  for(const stage of ['collect','submit','verify','verify-return'])assert.equal(f.frame(stage).holdings.some(h=>h.artifactId===id),false);
  const authorized=f.frame('authorize'),holding=authorized.holdings.find(h=>h.artifactId===id&&h.actorId==='wslLSA');assert.ok(holding);
  const inspected=inspectHeldObject(authorized,holding.holdingId);
  assert.equal(inspected.fields[0].value.userSid,'S-1-5-21-110-220-330-1001');
  assert.ok(f.frame('process').holdings.some(h=>h.artifactId===id&&h.actorId==='wslProcess'));
  assert.equal(f.frame('collect').holdings.some(h=>h.artifactId===id),false);
  const trace=heldObjectTrace(f.compiled,id);assert.ok(trace.some(r=>r.sourceStepId==='lab-wlog01:authorize'));
});

test('Temporary input is released without destroying SAM verifier or issued token',()=>{
  const f=wshtFixture(),frame=f.frame('input-cleanup');
  assert.equal(frame.holdings.some(h=>h.artifactId==='lab-wlog01:credential-input'),false);
  assert.ok(frame.holdings.some(h=>h.artifactId==='lab-wlog01:sam-verifier'&&h.actorId==='wslSAM'));
  assert.ok(frame.holdings.some(h=>h.artifactId==='lab-wlog01:primary-token'));
  for(const variant of ['bad-password','disabled-account','deny-interactive']){
    const denied=wshtFixture(variant),end=projectHeldObjects(denied.compiled,{eventIndex:denied.steps.length-1,milestone:'complete'});
    assert.equal(end.holdings.some(h=>h.artifactId==='lab-wlog01:credential-input'),false);
    assert.ok(end.holdings.some(h=>h.artifactId==='lab-wlog01:sam-verifier'));
    assert.equal(end.holdings.some(h=>h.artifactId==='lab-wlog01:primary-token'),false);
  }
});


function wshtCase(id,variant='default'){
  const model=id.startsWith('lab-welev')?buildWindowsElevationFixture(id,variant):buildWindowsLogonFixture(id,variant),steps=model.steps(),plan=buildWindowsWorkstationHeldObjects({model,steps,actors:model.actors(),config:{},contextId:id+':'+variant,choiceId:id});
  const compiled=compileHeldObjects(plan,{model,steps});return {model,steps,compiled,frame:stage=>{const index=steps.findIndex(s=>s.workstationStage===stage);assert.ok(index>=0,stage);return projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});}};
}
test('Protected TGT keys appear at the VBS acceptance boundary, never as ciphertext-receipt grants',()=>{
  for(const [id,receipt,accept,key] of [['lab-wlog02','as-reply','as-accept','tgt-session-key'],['lab-wlog05','ad:as-response','ad:accept-tgt','ad:user-tgt-session-key:1'],['lab-wlog06','ad:fast-response','ad:accept-ticket','ad:issued-ticket-session-key:1']]){
    const f=wshtCase(id),artifact=id+':'+key;assert.equal(f.frame(receipt).holdings.some(h=>h.artifactId===artifact&&h.actorId==='wslIso'),false);assert.ok(f.frame(accept).holdings.some(h=>h.artifactId===artifact&&h.actorId==='wslIso'&&h.representationId==='plain'));assert.equal(f.frame(accept).holdings.some(h=>h.artifactId===artifact&&h.actorId==='wslProcess'),false);
  }
});
test('Consent cancellation retains linked full token; netonly remote rejection retains the launched Q',()=>{
  const consent=wshtCase('lab-welev02','cancel'),last=projectHeldObjects(consent.compiled,{eventIndex:consent.steps.length-1,milestone:'complete'});assert.ok(last.holdings.some(h=>h.artifactId==='lab-welev02:full-token'&&h.actorId==='wslLSA'));assert.equal(last.holdings.some(h=>h.artifactId==='lab-welev02:child-token'),false);
  const net=wshtCase('lab-welev05','wrong-password-launches'),end=projectHeldObjects(net.compiled,{eventIndex:net.steps.length-1,milestone:'complete'});assert.ok(end.holdings.some(h=>h.artifactId==='lab-welev05:child-token'&&h.actorId==='wslChild'));assert.ok(end.holdings.some(h=>h.artifactId==='lab-welev05:caller-token'&&h.actorId==='wslProcess'));
});
test('SMB protected bytes are accepted by the OS client before readable file data reaches the application',()=>{
  const f=wshtCase('lab-wlog08'),id='lab-wlog08:smb:file-data';assert.equal(f.frame('smb:read-success').holdings.some(h=>h.artifactId===id&&h.actorId==='wslProcess'),false);assert.ok(f.frame('smb:read-accept').holdings.some(h=>h.artifactId===id&&h.actorId==='wslNetwork'&&h.representationId==='plain'));const app=f.frame('network-handoff'),holding=app.holdings.find(h=>h.artifactId===id&&h.actorId==='wslProcess');assert.ok(holding);assert.equal(inspectHeldObject(app,holding.holdingId).artifact.creator,'wslFile');assert.equal(inspectHeldObject(app,holding.holdingId).fields[0].value,'Quarterly report: synthetic teaching content.');
});

test('All 14 Windows rows and 88 named cases have explicit holding lifecycles and no orphaned scratch',()=>{
  const models=[...WINDOWSLOGONLAB_SCENARIOS,...WINDOWSELEVLAB_SCENARIOS];
  assert.equal(models.length,14);
  let cases=0;
  for(const base of models)for(const choice of base.variantChoices){
    const f=wshtCase(base.id,choice.id),plan=f.compiled.plan;
    const effects=[...plan.initial,...f.steps.flatMap(step=>plan.events[step.id].milestones.flatMap(m=>m.effects))];
    for(const effect of effects)if(effect.op==='acquire')assert.ok(['temporary','retained'].includes(effect.retention),base.id+':'+choice.id+':'+effect.holdingId);
    for(const step of f.steps)for(const message of plan.events[step.id].messages||[]){
      const before=projectHeldObjects(f.compiled,{eventIndex:f.steps.indexOf(step),progress:message.start});
      for(const object of message.objects)assert.ok(before.holdings.some(h=>h.actorId===message.from&&h.artifactId===object.artifactId&&h.representationId===object.representationId),base.id+'/'+choice.id+': sender must already hold '+object.artifactId+'/'+object.representationId);
    }
    const end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(end.holdings.some(h=>h.retention==='temporary'),false,base.id+':'+choice.id);
    // Authority configuration and the original caller are not attempt scratch.
    for(const initial of plan.initial.filter(e=>e.op==='acquire'&&['wslSAM','wslProcess'].includes(e.actorId)&&!e.artifactId.includes(':smb:')&&!e.artifactId.includes(':ad:'))){
      assert.ok(end.holdings.some(h=>h.holdingId===initial.holdingId),base.id+':'+choice.id+': preserved '+initial.holdingId);
    }
    cases++;
  }
  assert.equal(cases,88);
});

test('Accepted password TGT outlives AS buffers while its key stays only in protected client custody',()=>{
  const f=wshtCase('lab-wlog02'),receipt=f.frame('as-reply'),accepted=f.frame('as-accept');
  assert.equal(receipt.holdings.some(h=>h.artifactId==='lab-wlog02:tgt'&&h.store==='accepted TGT credential'),false);
  assert.ok(accepted.holdings.some(h=>h.artifactId==='lab-wlog02:tgt'&&h.actorId==='wslLSA'&&h.retention==='retained'));
  const end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
  assert.ok(end.holdings.some(h=>h.artifactId==='lab-wlog02:tgt-session-key'&&h.actorId==='wslIso'&&h.retention==='retained'));
  assert.equal(end.holdings.some(h=>['lab-wlog02:client-user-key','lab-wlog02:as-request','lab-wlog02:as-client-reply','lab-wlog02:host-session-key'].includes(h.artifactId)),false);
  assert.ok(end.holdings.some(h=>h.artifactId==='lab-wlog02:kdc-user-key'&&h.actorId==='wslDC'));
  assert.ok(end.holdings.some(h=>h.artifactId==='lab-wlog02:primary-token'&&h.actorId==='wslProcess'));
});

test('Netonly deferred credentials survive a denied network operation but end with Q, not with the input buffer',()=>{
  for(const variant of ['wrong-password-launches','dc-unreachable','share-denied','connection-reuse']){
    const f=wshtCase('lab-welev05',variant),end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    for(const key of ['deferred-credential','new-credentials-context','child-token','child-process'])assert.ok(end.holdings.some(h=>h.artifactId==='lab-welev05:'+key&&h.retention==='retained'),variant+': '+key);
    assert.equal(end.holdings.some(h=>h.artifactId==='lab-welev05:outbound-input'),false);
  }
  const f=wshtCase('lab-welev05'),end=f.frame('close');
  for(const key of ['deferred-credential','new-credentials-context','child-token','child-process'])assert.equal(end.holdings.some(h=>h.artifactId==='lab-welev05:'+key),false,key);
  assert.ok(end.holdings.some(h=>h.artifactId==='lab-welev05:caller-token'));
});

test('Unlock failure preserves the original session token and isolated-profile denial preserves its live context',()=>{
  const unlock=wshtCase('lab-wlog07','bad-credential'),locked=projectHeldObjects(unlock.compiled,{eventIndex:unlock.steps.length-1,milestone:'complete'});
  assert.ok(locked.holdings.some(h=>h.artifactId==='lab-wlog07:existing-token'&&h.actorId==='wslProcess'&&h.retention==='retained'));
  assert.equal(locked.holdings.some(h=>h.artifactId==='lab-wlog07:credential-input'),false);
  const isolated=wshtCase('lab-welev06','separate-profile-access'),end=projectHeldObjects(isolated.compiled,{eventIndex:isolated.steps.length-1,milestone:'complete'});
  for(const key of ['caller-token','managed-identity','isolated-token','child-token','child-process'])assert.ok(end.holdings.some(h=>h.artifactId==='lab-welev06:'+key&&h.retention==='retained'),key);
});

test('Composed SMB client inventory activates only when the explicit network context starts',()=>{
  for(const id of ['lab-wlog08','lab-welev05']){
    const f=wshtCase(id),record=f.model.workstationInventory.reuse.find(r=>r.kind==='smb');
    const eventIndex=f.steps.findIndex(step=>step.id===record.clientContextStartsAt);
    assert.ok(eventIndex>0);
    const before=projectHeldObjects(f.compiled,{eventIndex,milestone:'before'});
    assert.equal(before.holdings.some(h=>['wslNetwork','wslIso'].includes(h.actorId)&&h.artifactId.includes(':smb:')),false);
    const started=projectHeldObjects(f.compiled,{eventIndex,milestone:'complete'});
    assert.ok(started.holdings.some(h=>h.actorId==='wslNetwork'&&h.artifactId.includes(':smb:')));
    assert.ok(started.holdings.some(h=>h.artifactId===id+(id==='lab-welev05'?':caller-token':':primary-token')&&h.actorId==='wslProcess'));
  }
});

function wshtFieldTrace(f,field){
  const previous=ATTRIBUTES[field];
  ATTRIBUTES[field]=f.model.definitions()[field];
  try{return buildAttributeTrace(getAttributeUsage(f.steps,field),f.model.examples());}
  finally{if(previous)ATTRIBUTES[field]=previous;else delete ATTRIBUTES[field];}
}

test('Host-ticket issuance uses the KDC machine account key, not the workstation local handle',()=>{
  const cases=[['lab-wlog02','default'],['lab-wlog02','host-key-mismatch'],['lab-wlog02','denied-local-logon'],['lab-wlog05','default'],['lab-wlog06','default'],['lab-welev03','domain-admin-credential']];
  for(const [id,variant] of cases){
    const f=wshtCase(id,variant),authority=id+':kdc-machine-service-key',local=id+':machine-service-key',session=id+':host-session-key',ticket=id+':host-ticket';
    const initial=projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'}),issued=f.frame('host-ticket');
    for(const frame of [initial,issued,projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'})]){
      const kdc=frame.holdings.filter(h=>h.artifactId===authority),machine=frame.holdings.filter(h=>h.artifactId===local);
      assert.equal(kdc.length,1,id+'/'+variant);assert.equal(machine.length,1,id+'/'+variant);
      assert.equal(kdc[0].actorId,'wslDC');assert.equal(kdc[0].store,'AD account database');assert.equal(kdc[0].retention,'retained');
      assert.equal(machine[0].actorId,'wslMachine');assert.equal(machine[0].store,'machine credential context');assert.equal(machine[0].retention,'retained');
      assert.equal(inspectHeldObject(frame,kdc[0].holdingId).fields[0].value,'HANDLE(AD WORKSTATION$ authoritative host/workstation.corp.example service key)');
      assert.equal(inspectHeldObject(frame,machine[0].holdingId).fields[0].value,'HANDLE(WORKSTATION$ service identity key)');
    }
    assert.equal(initial.holdings.some(h=>h.artifactId===session),false,'The configured machine key is not the fresh host session key');
    assert.ok(issued.holdings.some(h=>h.artifactId===session&&h.actorId==='wslDC'));
    assert.equal(issued.holdings.some(h=>h.artifactId===session&&h.actorId!=='wslDC'),false);
    assert.equal(issued.holdings.some(h=>h.artifactId===ticket&&h.actorId==='wslMachine'),false);
    const submit=f.frame('local-ticket-submit');
    assert.ok(submit.holdings.some(h=>h.artifactId===ticket&&h.actorId==='wslMachine'&&h.representationId==='wire'));
    assert.equal(submit.holdings.some(h=>h.artifactId===ticket&&h.actorId==='wslMachine'&&h.representationId==='plain'),false);
    assert.equal(submit.holdings.some(h=>h.artifactId===session&&h.actorId==='wslMachine'),false);
    if(id.startsWith('lab-wlog')){
      assert.equal(issued.state.workstation.tgtAccepted,true);
      assert.equal(issued.state.workstation.hostTicketAccepted,false);
      assert.equal(issued.state.workstation.token,null);
      assert.equal(issued.state.workstation.sessionId,null);
      assert.equal(issued.state.workstation.desktopReady,false);
    }
    const prefix=id.replace(/-/g,'_'),kdcTrace=wshtFieldTrace(f,prefix+'_kdc_machine_service_key'),localTrace=wshtFieldTrace(f,prefix+'_machine_service_key');
    assert.equal(kdcTrace.length,1);
    assert.equal(kdcTrace[0].sourceStepId,id+':host-ticket');assert.equal(kdcTrace[0].traceKind,'use');
    assert.deepEqual([kdcTrace[0].from,kdcTrace[0].to],['wslDC','wslDC']);
    assert.equal(kdcTrace[0].payload[0].value,'HANDLE(AD WORKSTATION$ authoritative host/workstation.corp.example service key)');
    assert.equal(kdcTrace[0].traceActions[0].instanceId,authority);
    assert.equal(kdcTrace[0].traceActions[0].exactValueRef,authority+':plain');
    assert.equal(localTrace.length,1);
    assert.equal(localTrace[0].sourceStepId,id+(variant==='host-key-mismatch'?':local-ticket-check':':local-ticket-decode'));
    assert.equal(localTrace[0].traceKind,'use');assert.deepEqual([localTrace[0].from,localTrace[0].to],['wslMachine','wslMachine']);
    assert.equal(localTrace[0].payload[0].value,'HANDLE(WORKSTATION$ service identity key)');
    assert.equal(localTrace[0].traceActions[0].instanceId,local);
    for(const replay of [...kdcTrace,...localTrace]){
      const frame=projectHeldObjects(f.compiled,{eventIndex:replay.sourceIndex,milestone:'complete'});
      assert.ok(frame.holdings.some(h=>h.artifactId===replay.traceActions[0].instanceId&&h.actorId===replay.from&&h.representationId==='plain'));
      assert.equal(replay.traceActions.some(op=>op.kind==='send'||op.kind==='receive'),false);
    }
    for(const message of Object.values(f.compiled.plan.events).flatMap(event=>event.messages||[])){
      assert.equal(message.objects.some(o=>[authority,local,session].includes(o.artifactId)),false,'Key objects never cross IPC or network as message payloads');
    }
    if(variant!=='host-key-mismatch'){
      const decoded=f.frame('local-ticket-decode');
      assert.ok(decoded.holdings.some(h=>h.artifactId===ticket&&h.actorId==='wslMachine'&&h.representationId==='plain'));
      assert.ok(decoded.holdings.some(h=>h.artifactId===session&&h.actorId==='wslMachine'));
      assert.equal(decoded.state.workstation.hostTicketAccepted,false,'Local decryption precedes validation and admission');
      assert.equal(f.frame('local-ticket-check').state.workstation.hostTicketAccepted,true);
    }
    assert.deepEqual(projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'}),initial,'Backward seek cannot turn provisioned machine keys into a session credential');
  }
});

test('Host SPN and local-key failures preserve protected user credentials without granting a local session',()=>{
  for(const [variant,stage,detector] of [['unknown-host-spn','host-ticket','wslDC'],['host-key-mismatch','local-ticket-check','wslMachine'],['denied-local-logon','token','wslLSA']]){
    const f=wshtCase('lab-wlog02',variant),rejected=f.frame(stage),end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(rejected.state.workstation.detector,detector);assert.equal(rejected.state.workstation.clientKnowsResult,false);
    assert.equal(end.state.workstation.clientKnowsResult,true);assert.equal(end.state.workstation.tgtAccepted,true);
    assert.equal(end.state.workstation.token,null);assert.equal(end.state.workstation.sessionId,null);assert.equal(end.state.workstation.desktopReady,false);
    assert.equal(end.state.workstation.hostTicketAccepted,variant==='denied-local-logon');
    assert.ok(end.holdings.some(h=>h.artifactId==='lab-wlog02:tgt-session-key'&&h.actorId==='wslIso'&&h.retention==='retained'));
    assert.equal(end.holdings.some(h=>h.artifactId==='lab-wlog02:primary-token'),false);
    if(variant==='unknown-host-spn'){
      assert.equal(rejected.holdings.some(h=>['lab-wlog02:host-ticket','lab-wlog02:host-session-key'].includes(h.artifactId)),false);
      assert.deepEqual(wshtFieldTrace(f,'lab_wlog02_kdc_machine_service_key'),[],'No ticket encryption is performed for an unknown service target');
    }else if(variant==='host-key-mismatch'){
      assert.equal(rejected.holdings.some(h=>h.artifactId==='lab-wlog02:host-ticket'&&h.actorId==='wslMachine'&&h.representationId==='plain'),false);
      assert.equal(rejected.holdings.some(h=>h.artifactId==='lab-wlog02:host-session-key'&&h.actorId==='wslMachine'),false);
    }
  }
  for(const [id,keySuffix] of [['lab-wlog02','tgt-session-key'],['lab-wlog05','ad:user-tgt-session-key:1'],['lab-wlog06','ad:issued-ticket-session-key:1']]){
    const f=wshtCase(id),key=id+':'+keySuffix,issued=f.frame('host-ticket');
    assert.ok(issued.holdings.some(h=>h.artifactId===key&&h.actorId==='wslIso'));
    assert.equal(issued.holdings.some(h=>h.artifactId===key&&['wslMachine','wslLSA','wslProcess'].includes(h.actorId)),false);
    for(const message of Object.values(f.compiled.plan.events).flatMap(event=>event.messages||[])){
      assert.equal(message.objects.some(object=>object.artifactId===key),false,'Protected user-TGT key material never becomes a message payload');
    }
    for(const choice of f.model.variantChoices.filter(choice=>choice.id!=='default')){
      const denied=wshtCase(id,choice.id);
      if(denied.steps.some(step=>step.workstationStage==='host-tgs-prepare'))continue;
      const end=projectHeldObjects(denied.compiled,{eventIndex:denied.steps.length-1,milestone:'complete'});
      assert.equal(end.holdings.some(h=>h.artifactId===id+':kdc-machine-service-key'),false);
      assert.equal(end.state.workstation.token,null);assert.equal(end.state.workstation.desktopReady,false);
    }
  }
});

test('Endpoint-local reconstruction retains the shared key creator and exposes only the reconstructing endpoint copy',()=>{
  for(const [id,stage,key,actor,creator] of [
    ['lab-wlog05','ad:client-key','ad:dh-shared-secret:1','wslLSA','wslDC'],
    ['lab-wlog05','ad:client-key','ad:as-reply-key:1','wslLSA','wslDC'],
    ['lab-wlog06','ad:user-credential','ad:user-long-term-key:1','wslIso','wslDC'],
    ['lab-wlog06','ad:armor-kdc','ad:armor-key:1','wslDC','wslMachine'],
    ['lab-wlog08','smb:client-key-derivation','smb:signing-key','wslNetwork','wslFile'],
    ['lab-welev05','smb:client-key-derivation','smb:signing-key','wslNetwork','wslFile']
  ]){
    const f=wshtCase(id),artifactId=id+':'+key,frame=f.frame(stage),holding=frame.holdings.find(h=>h.actorId===actor&&h.artifactId===artifactId&&h.representationId==='plain');
    assert.ok(holding,id+': exact local key copy');
    const inspected=inspectHeldObject(frame,holding.holdingId);assert.equal(inspected.artifact.creator,creator);
    const operation=f.steps.find(step=>step.workstationStage===stage).attributeOperations.find(op=>op.actorId===actor&&op.instanceId===artifactId);
    assert.equal(operation.kind,'store');assert.equal(operation.creator,creator);assert.equal(operation.representation,'plain');
    assert.ok(inspected.fields.some(field=>field.attributeId===operation.attributeId&&field.value===operation.value));
    const index=f.steps.findIndex(step=>step.workstationStage===stage),before=projectHeldObjects(f.compiled,{eventIndex:index,milestone:'before'});
    assert.equal(before.holdings.some(h=>h.actorId===actor&&h.artifactId===artifactId&&h.representationId==='plain'),false);
    assert.equal((f.compiled.plan.events[f.steps[index].id].messages||[]).some(message=>message.objects.some(object=>object.artifactId===artifactId)),false,'Reconstruction does not transport key bytes');
  }
});
