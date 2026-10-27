import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {buildWindowsRemoteAdministrationFixture} from '../src/windows-remote-administration-lab.js';
import {buildWindowsProtectionFixture,buildWindowsProtectionSubfixture} from '../src/windows-protection-lab.js';
import {buildWindowsLogonFixture} from '../src/windows-logon-lab.js';
import {buildHeldObjects} from '../src/held-objects.js';
import {assertHeldObjectCoverage,projectHeldObjects,inspectHeldObject,heldObjectTrace,heldCursorForPlayback} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

// Correction assertions are literal review requirements, not new answers derived
// from production. The historical input manifests and oracles are untouched.
const manifest=name=>JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/'+name,import.meta.url)));
const remote=manifest('remote-cases.json'),protection=manifest('protection-cases.json');
const effects=(model,step)=>model.workstationInventory.events[step.id].milestones.flatMap(m=>m.effects);
const end=model=>reconstructProtocolState(model,model.steps().length-1).workstation;
const object=(model,key)=>{const found=model.workstationInventory.artifacts.find(o=>o.key===key||o.artifactId===model.id+':'+key);assert.ok(found,key);return found;};
function fixture(model){
 const steps=model.steps(),compiled=buildHeldObjects({model,steps,actors:model.actors(),config:{},contextId:'review-corrections:'+model.canonicalCaseId+':'+model.subfixtureId,choiceId:model.id});
 assertHeldObjectCoverage(compiled);
 const at=index=>projectHeldObjects(compiled,{eventIndex:index,milestone:index<0?'initial':'complete'});
 const index=stage=>{const found=steps.findIndex(s=>s.workstationStage===stage);assert.ok(found>=0,stage);return found;};
 return {model,steps,compiled,at,index};
}
function fieldTrace(f,field){
 const previous=ATTRIBUTES[field];ATTRIBUTES[field]=f.model.definitions()[field];
 try{return buildAttributeTrace(getAttributeUsage(f.steps,field),f.model.examples());}
 finally{if(previous===undefined)delete ATTRIBUTES[field];else ATTRIBUTES[field]=previous;}
}
function equalPrefix(f,row,kind,queue,expected){
 const cursor=heldCursorForPlayback(f.compiled,{step:row,status:'paused',kind,queue,queuePosition:queue.indexOf(row)},row,{selected:true});
 const actual=projectHeldObjects(f.compiled,cursor);
 assert.deepEqual(actual.holdings,expected.holdings,'all holdings at equal source prefix');
 assert.deepEqual(actual.observations,expected.observations,'all verification/knowledge observations at equal prefix');
 assert.deepEqual(actual.state,expected.state,'hidden prerequisites and decisions at equal prefix');
 assert.equal(actual.protocolClock,expected.protocolClock);
 return actual;
}
function histories(f,step,artifact,expected,{owner=null}={}){
 const exact=heldObjectTrace(f.compiled,artifact.artifactId),rows=exact.filter(row=>row.sourceStepId===step.id);
 assert.ok(rows.length,'exact history includes '+step.id+' / '+artifact.artifactId);
 for(const row of rows){if(owner){assert.equal(row.from,owner);assert.equal(row.to,owner);}equalPrefix(f,row,'object',exact,expected);}
 const fields=[...new Set((step.attributeOperations||[]).filter(op=>op.instanceId===artifact.artifactId).map(op=>op.attributeId))];
 assert.ok(fields.length);
 for(const field of fields){const queue=fieldTrace(f,field),selected=queue.filter(row=>row.sourceStepId===step.id);assert.ok(selected.length,'field history includes source event');for(const row of selected){if(owner){assert.equal(row.from,owner);assert.equal(row.to,owner);}equalPrefix(f,row,'attribute',queue,expected);}}
}

function uniqueProtectionModels(){
 const unique=new Map();
 for(const row of protection.cases){const model=buildWindowsProtectionFixture(row.modelId,row.variantId);unique.set(model.canonicalCaseId+'|'+model.subfixtureId,model);}
 for(const row of protection.subfixtures){const model=buildWindowsProtectionSubfixture(row.id);unique.set(model.canonicalCaseId+'|'+model.subfixtureId,model);}
 return [...unique.values()];
}

test('WP-R03 all 44 WRA and all 55 WPROT executions release exact temporary holdings only at the local owner',()=>{
 const wra=remote.cases.flatMap(row=>row.subfixtures.map(member=>buildWindowsRemoteAdministrationFixture(row.modelId,row.id.split('/')[1],member.id))),wprot=uniqueProtectionModels();
 assert.equal(wra.length,44);assert.equal(wprot.length,55);
 assert.deepEqual([...new Set(wra.map(m=>m.planId))],['WRA01','WRA02','WRA03','WRA04','WRA05']);
 assert.deepEqual([...new Set(wprot.map(m=>m.planId))],['WPROT01','WPROT02','WPROT03','WPROT04','WPROT05']);
 for(const model of [...wra,...wprot]){
  const f=fixture(model);let cleanupCount=0;
  const state=end(model);
  if(model.family==='windows-protection'){
   const answer=protection.subfixtures.find(row=>row.id===model.subfixtureId)||protection.cases.find(row=>row.id===model.canonicalCaseId);
   for(const [field,value] of Object.entries(answer.expected))assert.deepEqual(state[field],value,model.canonicalCaseId+' unchanged '+field);
  }else{
   const answer=remote.cases.find(row=>row.id===model.canonicalCaseId).subfixtures.find(member=>member.id===model.subfixtureId).expected;
   for(const field of ['credentialVerified','admissionAllowed','resourceAllowed','serverAuthenticated','clientSessionAccepted','clientKnowsResult'])assert.equal(state[field],answer[field],model.canonicalCaseId+' unchanged '+field);
   assert.equal(state.token?.mode??null,answer.tokenMode);assert.equal(state.failureStage,answer.firstDetector);assert.equal(state.returnedResult,answer.returnedResult);
   assert.equal(Boolean(state.priorSession),answer.priorSessionRetained);assert.equal(state.sourceDesktopPreserved,true);
  }
  for(const [index,step] of f.steps.entries()){
   const releases=effects(model,step).filter(effect=>effect.op==='release');
   if(step.from!==step.to||!releases.length)continue;
   cleanupCount++;assert.equal(step.layers.length,0);
   const before=f.at(index-1),after=f.at(index),releasedIds=new Set(releases.map(effect=>effect.holdingId));
   const gone=before.holdings.filter(h=>!after.holdings.some(next=>next.holdingId===h.holdingId));
   assert.equal(gone.length,releases.length,'every release names an existing exact holding, including aliases');
   for(const holding of gone){
    assert.equal(holding.actorId,step.from,model.canonicalCaseId+' / '+step.id+' foreign cleanup');
    assert.equal(holding.retention,'temporary');assert.ok(releasedIds.has(holding.holdingId));
   }
   for(const holding of before.holdings.filter(h=>!releasedIds.has(h.holdingId)))assert.ok(after.holdings.some(next=>next.holdingId===holding.holdingId),'unrelated ownership and retained state survive');
   for(const id of new Set(gone.map(h=>h.artifactId)))histories(f,step,model.workstationInventory.artifacts.find(o=>o.artifactId===id),after,{owner:step.from});
   assert.deepEqual(f.at(index-1),before,'rewind restores the complete exact pre-cleanup state');
   assert.deepEqual(f.at(index),after,'replay does not change the cleanup prefix');
   if(step.workstationStage.includes('attempt-cleanup'))assert.ok(reconstructProtocolState(model,index-1).workstation.clientKnowsResult,'terminal cleanup follows actual caller result');
  }
  assert.ok(cleanupCount||!f.at(f.steps.length-1).holdings.some(h=>h.retention==='temporary'));
  assert.equal(f.at(f.steps.length-1).holdings.some(h=>h.retention==='temporary'),false);
 }
});

test('WP-R03 cleanup retains accepted service authority and unrelated sessions on denial',()=>{
 for(const [id,variant,keys] of [
  ['lab-wra01','default-filtered',['desktop','account-verifier','session-context','target-token']],
  ['lab-wra01','reused-session',['desktop','reused-session-record']],
  ['lab-wprot01','constrained-continuation',['prior-signin-tgt','live-signin-session','s4u-session-key','constrained-service-ticket']],
  ['lab-wprot05','ticket-then-acl-denial',['preexisting-user-tgt','preexisting-user-tgt-key','host-ticket','host-session-key','host-service-context']],
  ['lab-wprot03','lifetime-expired',['old-ticket-lineage','existing-local-session']]
 ]){
  const model=id.startsWith('lab-wra')?buildWindowsRemoteAdministrationFixture(id,variant):buildWindowsProtectionFixture(id,variant),f=fixture(model),last=f.at(f.steps.length-1);
  for(const key of keys)assert.ok(last.holdings.some(h=>h.artifactId===model.id+':'+key&&h.retention==='retained'),variant+' retained '+key);
 }
 const denied=buildWindowsRemoteAdministrationFixture('lab-wra01','reused-session','later-proof-denial'),f=fixture(denied);
 assert.equal(end(denied).credentialVerified,false);assert.ok(f.at(f.steps.length-1).holdings.some(h=>h.artifactId===denied.id+':prior-session'));
 const legacy=buildWindowsLogonFixture('lab-wlog01');assert.ok(legacy.steps().some(s=>s.workstationStage==='input-cleanup'));assert.ok(legacy.steps().some(s=>s.workstationStage==='attempt-cleanup'));
});

for(const [variant,decode,verify,key,keyUse] of [
 ['constrained-continuation','s4u-ticket-decode','s4u-proof-check','s4u-service-tgt','kdc-krbtgt-key'],
 ['constrained-continuation','s4u-authenticator-decode','s4u-proof-check','s4u-authenticator','s4u-service-tgt-key'],
 ['allowed-service','host-tgt-decode','host-tgs-verify','preexisting-user-tgt','kdc-krbtgt-key'],
 ['allowed-service','compound-ticket-decode','compound-kdc-armor','computer-armor-ticket','kdc-krbtgt-key'],
 ['allowed-service','compound-proof-decode','compound-kdc-armor','computer-armor-proof','computer-armor-ticket-key'],
 ['allowed-service','compound-request-decode','compound-kdc-armor','compound-fast-request','compound-armor-key']
])test('WP-R04 '+key+' is redacted before the actual receiver decode, then readable with identical wire provenance',()=>{
 const model=buildWindowsProtectionFixture(variant==='allowed-service'?'lab-wprot05':'lab-wprot01',variant),f=fixture(model),artifact=object(model,key),decodeIndex=f.index(decode),verifyIndex=f.index(verify),before=f.at(decodeIndex-1),after=f.at(decodeIndex);
 assert.ok(decodeIndex<verifyIndex);
 const wire=before.holdings.find(h=>h.artifactId===artifact.artifactId&&h.actorId==='wslDC'&&h.representationId==='wire');assert.ok(wire);
 assert.equal(before.holdings.some(h=>h.artifactId===artifact.artifactId&&h.actorId==='wslDC'&&h.representationId==='plain'),false);
 assert.ok(inspectHeldObject(before,wire.holdingId).fields.every(field=>field.redacted&&field.readable===false));
 const decoded=after.holdings.find(h=>h.artifactId===artifact.artifactId&&h.actorId==='wslDC'&&h.representationId==='plain');assert.ok(decoded);
 assert.deepEqual(after.holdings.find(h=>h.holdingId===wire.holdingId),wire,'retain the exact received wire holding');
 const inspected=inspectHeldObject(after,decoded.holdingId);assert.equal(inspected.artifact.artifactId,artifact.artifactId);assert.equal(inspected.artifact.creator,artifact.creator);
 assert.ok(inspected.fields.some(field=>field.readable&&!field.redacted));
 assert.ok(f.steps[decodeIndex].attributeOperations.some(op=>op.kind==='use'&&op.instanceId===model.id+':'+keyUse&&op.actorId==='wslDC'),'existing receiver authority/key is explicitly used');
 assert.ok(before.holdings.some(h=>h.artifactId===model.id+':'+keyUse&&h.actorId==='wslDC'&&h.representationId==='plain'));
 const verification=f.steps[verifyIndex].attributeOperations.find(op=>op.instanceId===artifact.artifactId&&op.kind==='verify');assert.equal(verification.representation,'plain');assert.match(verification.fieldPath,/^decoded\./);
 histories(f,f.steps[decodeIndex],artifact,after);histories(f,f.steps[verifyIndex],artifact,f.at(verifyIndex));
 assert.deepEqual(f.at(decodeIndex-1),before,'rewind returns to redacted received bytes');
});

test('WP-R04 failed evidence installs no credential; policy and resource denial preserve prior accepted credentials',()=>{
 for(const variant of ['forged-device-label','required-armor-missing','device-denied-enforce']){
  const model=buildWindowsProtectionFixture('lab-wprot04',variant),f=fixture(model),last=f.at(f.steps.length-1);
  assert.equal(end(model).tgtAccepted,false);assert.equal(last.holdings.some(h=>h.artifactId.endsWith(':issued-ticket:1')&&h.actorId==='wslLSA'),false);
 }
 for(const variant of ['required-context-missing','target-rule-enforce']){
  const model=buildWindowsProtectionFixture('lab-wprot05',variant),f=fixture(model),last=f.at(f.steps.length-1);
  assert.equal(Boolean(end(model).hostTicketAccepted),false);assert.equal(last.holdings.some(h=>h.artifactId===model.id+':host-session-key'),false);
  assert.ok(last.holdings.some(h=>h.artifactId===model.id+':preexisting-user-tgt'&&h.actorId==='wslLSA'));
 }
 const model=buildWindowsProtectionFixture('lab-wprot05','ticket-then-acl-denial');assert.equal(end(model).hostTicketAccepted,true);assert.equal(end(model).resourceAllowed,false);
 const f=fixture(model);assert.ok(f.at(f.steps.length-1).holdings.some(h=>h.artifactId===model.id+':host-session-key'&&h.actorId==='wslLSA'));
});

for(const [variant,configured,duration,wouldDeny,enforced,result] of [
 ['device-denied-audit',120,480,true,false,'audit'],['allowed-device',120,120,false,true,'success'],['policy-lifetime',90,90,false,true,'success']
])test('WP-R01 '+variant+' separates configured lifetime from the literal effective limits',()=>{
 const model=buildWindowsProtectionFixture('lab-wprot04',variant),f=fixture(model),state=end(model),decision=object(model,'as-policy'),policy=object(model,'account-policy');
 assert.equal(policy.value.lifetimeMinutes,configured);assert.equal(policy.value.enforced,enforced);
 assert.equal(decision.value.configuredLifetimeMinutes,configured);assert.equal(decision.value.baselineLifetimeMinutes,480);assert.equal(decision.value.lifetimeMinutes,duration);assert.equal(decision.value.endMinutes,duration);assert.equal(decision.value.renewMinutes,duration);
 assert.equal(state.policyWouldDeny,wouldDeny);assert.equal(state.policyAllowed,true);assert.equal(state.tgtAccepted,true);assert.equal(state.resultCode,result);
 assert.equal(state.ticketIssuedMinutes,0);assert.equal(state.ticketDurationMinutes,duration);assert.equal(state.ticketEndMinutes,duration);assert.equal(state.ticketRenewMinutes,duration);
 assert.equal(object(model,'policy-as-result').value.configuredLifetimeMinutes,configured);assert.equal(object(model,'policy-as-result').value.lifetimeMinutes,duration);
 const index=f.index('as-policy'),after=f.at(index),holding=after.holdings.find(h=>h.artifactId===decision.artifactId&&h.actorId==='wslDC');
 assert.equal(inspectHeldObject(after,holding.holdingId).fields[0].value.lifetimeMinutes,duration);histories(f,f.steps[index],decision,after);assert.equal(f.at(index-1).state.workstation.policyAllowed,null);
 const issued=model.workstationInventory.artifacts.filter(o=>o.representations.some(rep=>rep.fields.some(field=>typeof field.value==='string'&&field.value.includes('endtime='+duration+'min; renew-till='+duration+'min'))));
 assert.ok(issued.length>=1,'issued ticket uses literal corrected deadlines');
 if(variant==='policy-lifetime')assert.deepEqual(object(model,'as-client-reply').value.lifetime,{issuedMinutes:0,startMinutes:0,durationMinutes:90,endMinutes:90,renewMinutes:90});
 else {
  const ticket=model.workstationInventory.artifacts.find(o=>o.artifactId===model.id+':ad:issued-ticket:1');assert.ok(ticket);
  const acceptIndex=f.index('as-accepted'),accepted=f.at(acceptIndex),acceptedTicket=accepted.holdings.find(h=>h.artifactId===ticket.artifactId&&h.actorId==='wslLSA');assert.ok(acceptedTicket);
  // The imported FAST ticket remains opaque. Lifetime corrections do not grant readability.
  assert.ok(inspectHeldObject(accepted,acceptedTicket.holdingId).fields.every(field=>field.redacted));
  assert.ok(ticket.representations.some(rep=>rep.fields.some(field=>String(field.value).includes('endtime='+duration+'min; renew-till='+duration+'min'))));
 }
});

test('WP-R02 fresh issue 241 plus duration 240 yields 481 without reviving the original expired lineage',()=>{
 const model=buildWindowsProtectionSubfixture('WPROT03/fresh-authentication/fresh-lineage'),f=fixture(model),fresh=object(model,'tgt'),old=object(model,'old-ticket-lineage'),reply=object(model,'as-client-reply'),state=end(model);
 const times={issuedMinutes:241,startMinutes:241,durationMinutes:240,endMinutes:481,renewMinutes:481};
 assert.deepEqual(reply.value.lifetime,times);assert.deepEqual(fresh.lifetime,times);assert.notEqual(fresh.artifactId,old.artifactId);
 assert.deepEqual(old.value,{lineage:'PU-original-0',issuedMinutes:0,endMinutes:240,renewTillMinutes:240,expired:true});
 assert.equal(state.ticketIssuedMinutes,241);assert.equal(state.ticketStartMinutes,241);assert.equal(state.ticketDurationMinutes,240);assert.equal(state.ticketEndMinutes,481);assert.equal(state.ticketRenewMinutes,481);assert.equal(state.newCredentialLineage,true);assert.equal(state.localSessionRetained,true);assert.equal(state.tgtAccepted,true);
 const decode=f.index('as-decode'),accept=f.index('as-accept'),accepted=f.at(accept),holding=accepted.holdings.find(h=>h.artifactId===reply.artifactId&&h.actorId==='wslLSA'&&h.representationId==='plain');
 assert.deepEqual(inspectHeldObject(accepted,holding.holdingId).fields[0].value.lifetime,times);assert.ok(reply.value.lifetime.endMinutes>model.fixtureInputs.nowMinutes);
 assert.equal(f.at(decode-1).holdings.some(h=>h.artifactId===reply.artifactId&&h.actorId==='wslLSA'&&h.representationId==='plain'),false);
 histories(f,f.steps[decode],reply,f.at(decode));histories(f,f.steps[accept],reply,accepted);histories(f,f.steps[accept],fresh,accepted);
 for(const index of [-1,decode-1,accept,f.steps.length-1,decode-1]){
  const frame=f.at(index),oldHolding=frame.holdings.find(h=>h.artifactId===old.artifactId&&h.actorId==='wslLSA');assert.ok(oldHolding);
  assert.equal(inspectHeldObject(frame,oldHolding.holdingId).fields[0].value.expired,true);assert.ok(frame.holdings.some(h=>h.artifactId===model.id+':existing-local-session'));
 }
 const zero=buildWindowsProtectionFixture('lab-wprot03','aes-kerberos');assert.deepEqual(object(zero,'as-client-reply').value.lifetime,{issuedMinutes:0,startMinutes:0,durationMinutes:240,endMinutes:240,renewMinutes:240});
 const renewal=buildWindowsProtectionSubfixture('WPROT03/lifetime-expired/renewal');assert.equal(end(renewal).resultCode,'renewal-denied');assert.equal(end(renewal).newCredentialLineage,false);assert.equal(end(renewal).localSessionRetained,true);assert.equal(renewal.steps().some(s=>s.workstationStage==='as-accept'),false);
});

for(const [id,variant,authority,verify] of [['lab-wra01','default-filtered','TARGET SAM','sam-verify'],['lab-wra03','domain-ntlm-explicit','CORP domain DC through target machine secure channel','dc-verify']])test('WP-R07 '+authority+' inspector names the NTLMv2 challenge inputs and keeps MIC outside the blob',()=>{
 const model=buildWindowsRemoteAdministrationFixture(id,variant),proof=object(model,'ntlm-proof'),f=fixture(model);
 const equation='HMAC-MD5(ResponseKeyNT, ServerChallenge || NTLMv2_CLIENT_CHALLENGE)';
 assert.ok(proof.value.includes(equation));assert.ok(proof.value.includes('8-byte ServerChallenge field'));assert.ok(proof.value.includes('MsvAvFlags MIC-presence bit'));assert.ok(proof.value.includes('AUTHENTICATE_MESSAGE.MIC is a separate transcript MIC, not client-challenge bytes'));assert.equal(proof.value.includes('target-AV,MIC'),false);
 const index=f.index(verify),after=f.at(index),holding=after.holdings.find(h=>h.artifactId===proof.artifactId&&h.actorId===f.steps[index].from&&h.representationId==='plain');assert.ok(holding);
 assert.equal(inspectHeldObject(after,holding.holdingId).fields[0].value,proof.value);histories(f,f.steps[index],proof,after);
 assert.equal(end(model).credentialVerified,true);assert.equal(end(model).clientSessionAccepted,true);assert.equal(end(model).verifierAuthority,authority);
 const authenticate=object(model,'ntlm-authenticate');assert.match(JSON.stringify(authenticate.value),/MIC/);
 assert.ok(model.steps().some(step=>step.attributeOperations.some(op=>op.kind==='verify'&&op.instanceId===authenticate.artifactId)),'actual message-MIC validation boundary remains');
});

test('review corrections reach the actual rendered inspector, exact-object replay and rewind',async()=>{
 const {installHarness}=await import('./dom-harness.mjs'),harness=installHarness();
 const {AuthFlowStudio}=await import('../src/app.js'),app=new AuthFlowStudio();
 harness.document.body.appendChild(app);app.connectedCallback();
 try{
  for(const [id,variant,decode,verify,key] of [
   ['lab-wprot01','constrained-continuation','s4u-authenticator-decode','s4u-proof-check','s4u-authenticator'],
   ['lab-wprot05','allowed-service','compound-request-decode','compound-kdc-armor','compound-fast-request'],
   ['lab-wprot05','allowed-service','host-tgt-decode','host-tgs-verify','preexisting-user-tgt']
  ]){
   app.selectLabScenario(id,{variant});
   const decodeIndex=app.steps.findIndex(step=>step.workstationStage===decode),verifyIndex=app.steps.findIndex(step=>step.workstationStage===verify),artifactId=id+':'+key;
   app.selectStep(decodeIndex-1,false);
   const before=app.heldView.snapshot(),wire=before.holdings.find(h=>h.actorId==='wslDC'&&h.artifactId===artifactId&&h.representationId==='wire');
   assert.ok(wire);app.heldView.select(wire);assert.match(app.querySelector('#held-inspector').textContent,/Not readable by this holder/);
   app.selectStep(verifyIndex,false);
   const verified=app.heldView.snapshot(),plain=verified.holdings.find(h=>h.actorId==='wslDC'&&h.artifactId===artifactId&&h.representationId==='plain');
   assert.ok(plain);app.heldView.select(plain);
   const text=app.querySelector('#held-inspector').textContent;assert.equal(text.includes('Not readable by this holder'),false);assert.ok(text.includes('verification')&&text.includes('accepted'));
   app.heldView.trace(artifactId);
   const rowIndex=app.traceQueue.findIndex(row=>row.sourceStepId===app.steps[verifyIndex]?.id||row.sourceStepId===id+':'+verify);
   assert.ok(rowIndex>=0);app.selectStep(rowIndex,false);assert.deepEqual(app.heldView.snapshot().holdings,verified.holdings);
   app.selectLabScenario(id,{variant});app.selectStep(decodeIndex-1,false);assert.deepEqual(app.heldView.snapshot().holdings,before.holdings);
  }
  app.selectLabScenario('lab-wprot04',{variant:'device-denied-audit'});
  app.selectStep(app.steps.findIndex(step=>step.workstationStage==='as-policy'),false);
  let frame=app.heldView.snapshot(),holding=frame.holdings.find(h=>h.artifactId==='lab-wprot04:as-policy'&&h.actorId==='wslDC');app.heldView.select(holding);
  let text=app.querySelector('#held-inspector').textContent;assert.match(text,/configuredLifetimeMinutes/);assert.match(text,/480/);
  app.selectLabScenario('lab-wprot03',{variant:'fresh-authentication'});
  app.selectStep(app.steps.findIndex(step=>step.workstationStage==='as-accept'),false);
  frame=app.heldView.snapshot();holding=frame.holdings.find(h=>h.artifactId==='lab-wprot03:as-client-reply'&&h.actorId==='wslLSA'&&h.representationId==='plain');app.heldView.select(holding);
  text=app.querySelector('#held-inspector').textContent;for(const literal of ['issuedMinutes','durationMinutes','241','240','481'])assert.ok(text.includes(literal),literal);
  for(const [id,variant,stage] of [['lab-wra01','default-filtered','sam-verify'],['lab-wra03','domain-ntlm-explicit','dc-verify']]){
   app.selectLabScenario(id,{variant});const index=app.steps.findIndex(step=>step.workstationStage===stage);app.selectStep(index,false);
   frame=app.heldView.snapshot();holding=frame.holdings.find(h=>h.artifactId===id+':ntlm-proof'&&h.actorId===app.steps[index].from&&h.representationId==='plain');app.heldView.select(holding);
   text=app.querySelector('#held-inspector').textContent;assert.ok(text.includes('HMAC-MD5(ResponseKeyNT, ServerChallenge || NTLMv2_CLIENT_CHALLENGE)'));assert.ok(text.includes('MsvAvFlags MIC-presence bit'));assert.ok(text.includes('AUTHENTICATE_MESSAGE.MIC is a separate transcript MIC'));
  }
 }finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
});

test('default protection field replay preserves the selected model and complete source prefix',async()=>{
 const {installHarness}=await import('./dom-harness.mjs'),harness=installHarness();
 const {AuthFlowStudio}=await import('../src/app.js'),app=new AuthFlowStudio();
 harness.document.body.appendChild(app);app.connectedCallback();
 try{
  for(const id of ['lab-wprot01','lab-wprot02','lab-wprot03','lab-wprot04','lab-wprot05']){
   app.selectLabScenario(id);
   const source=app.steps.find(step=>step.attributeOperations.length),index=app.steps.indexOf(source),field=source.attributeOperations[0].attributeId;
   app.selectStep(index,false);const before=app.heldView.snapshot();
   app.selectAttribute(field,false);
   const selected=app.traceQueue.findIndex(row=>row.sourceStepId===source.id);assert.ok(selected>=0);
   app.selectStep(selected,false);const traced=app.heldView.snapshot();
   assert.equal(app.labScenarioId,id);assert.equal(app.attributeSelection,field);
   assert.deepEqual(traced.state,before.state);assert.deepEqual(traced.holdings,before.holdings);assert.equal(traced.protocolClock,before.protocolClock);
   app.clearAttribute();app.selectStep(index,false);assert.deepEqual(app.heldView.snapshot().holdings,before.holdings);
  }
 }finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
});
