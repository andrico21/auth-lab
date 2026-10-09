import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness} from './dom-harness.mjs';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {buildProtocolInstances,reconstructProtocolState,validateProtocolScenario} from '../src/protocol-state.js';
import {projectScenarioContext,scenarioContextRows} from '../src/scenario-context.js';

// Independent R2/R3 conditions from auth-lab-code3-final-review(1).html.
// These invoke the actual Apply button and inspect transmitted fields, source
// prefixes and packet values. This is deterministic evidence, not G01 native
// browser acceptance or a live AD/Keycloak interoperability test.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const families=[['lab-ad-first-sign-in','cifs/review.corp.example'],['lab-kc-kerberos-sso','HTTP/review.corp.example']];
const data=model=>JSON.stringify({definitions:model.definitions(),initialState:model.initialState,steps:model.steps(),actors:model.actors(),protocolValues:model.protocolValues});
const authored=new Map(Object.entries(LAB_MODELS).map(([id,model])=>[id,data(model)]));
const field=(step,id)=>step.payload.find(item=>item.attributeId===id)?.value;
const reply=(name,realm)=>'EncryptedData(key=tgt-session:01, EncTGSRepPart for '+name+'; srealm='+realm+')';
const operations=model=>model.steps().flatMap((step,index)=>step.attributeOperations.map(operation=>({...operation,step,index})));

function mount(id){const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();app.selectLabScenario(id);return app;}
function dispose(app){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
function input(app,key){const node=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(node,'Editable environment field '+key);return node;}
function enter(app,key,value){input(app,key).value=value;}
function apply(app){assert.doesNotThrow(()=>app.querySelector('#environment-apply').click(),'The real Apply handler must report a recoverable inline error instead of throwing');}
function accepted(app){assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.refs['environment-errors'].textContent,'');assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);}
function reset(app,id){app.querySelector('#environment-reset').click();assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'');assert.equal(app.runtimeEnvironment.applied.servicePrincipal,'');assert.equal(app.runtimeEnvironment.draft.kerberosRealm,'');assert.equal(app.runtimeEnvironment.draft.servicePrincipal,'');assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);assert.equal(app.visibleIndex,0);assert.equal(data(app.labModel),authored.get(id),'Reset restores the complete authored fixture');assert.equal(data(LAB_MODELS[id]),authored.get(id),'Applying/resetting never changes the base fixture');}
function running(app,focused=false){
  app.selectStep(Math.floor(app.steps.length/2),false);
  if(focused)app.selectAttribute('adTGSReply',true);else app.player.play(app.steps,'demo');
  harness.clock.advance(600);app.visited.add('pre-existing-context-link');
  assert.equal(app.player.status,'playing');assert.ok(app.player.queue.length);assert.ok(app.visited.size);
}
function capture(app){
  return {applied:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision,active:app.runtimeEnvironment.active,
    model:app.labModel,modelData:data(app.labModel),memo:app.contextModelMemo,steps:app.steps,stepsData:JSON.stringify(app.steps),
    protocolState:JSON.stringify(app.protocolSnapshot().state),queue:app.player.queue,queueData:JSON.stringify(app.player.queue),player:JSON.stringify(app.player.snapshot()),
    index:app.index,traceIndex:app.traceIndex,visibleIndex:app.visibleIndex,selection:app.attributeSelection,trace:app.traceQueue,traceData:JSON.stringify(app.traceQueue),
    visited:app.visited,visitedData:[...app.visited],inspection:JSON.stringify(app.inspection),status:app.refs.status.textContent,environmentStatus:app.refs['environment-status'].textContent,
    packetName:app.refs['packet-name'].textContent,packetValue:app.refs['packet-value'].textContent,packetHidden:app.refs.packet.hidden};
}
function unchanged(app,before){
  assert.strictEqual(app.runtimeEnvironment.applied,before.applied,'A rejected draft cannot commit any environment context');assert.equal(app.runtimeEnvironment.revision,before.revision);assert.equal(app.runtimeEnvironment.active,before.active);
  assert.strictEqual(app.labModel,before.model,'A rejected draft retains the previously issued model');assert.equal(data(app.labModel),before.modelData);assert.strictEqual(app.contextModelMemo,before.memo);
  assert.strictEqual(app.steps,before.steps);assert.equal(JSON.stringify(app.steps),before.stepsData);assert.equal(JSON.stringify(app.protocolSnapshot().state),before.protocolState,'A rejected draft cannot rewrite protocol knowledge or cached credentials');
  assert.strictEqual(app.player.queue,before.queue,'A rejected draft does not replace the running queue');assert.equal(JSON.stringify(app.player.queue),before.queueData);assert.equal(JSON.stringify(app.player.snapshot()),before.player,'Playback status, position, packet and elapsed time stay unchanged');
  assert.equal(app.index,before.index);assert.equal(app.traceIndex,before.traceIndex);assert.equal(app.visibleIndex,before.visibleIndex);assert.equal(app.attributeSelection,before.selection);assert.strictEqual(app.traceQueue,before.trace);assert.equal(JSON.stringify(app.traceQueue),before.traceData);
  assert.strictEqual(app.visited,before.visited);assert.deepEqual([...app.visited],before.visitedData);assert.equal(JSON.stringify(app.inspection),before.inspection);assert.equal(app.refs.status.textContent,before.status);assert.equal(app.refs['environment-status'].textContent,before.environmentStatus);
  assert.equal(app.refs['packet-name'].textContent,before.packetName);assert.equal(app.refs['packet-value'].textContent,before.packetValue);assert.equal(app.refs.packet.hidden,before.packetHidden);
}
function rejected(app,key,before,pattern){
  const errors=app.refs['environment-errors'],node=input(app,key);
  assert.equal(errors.hidden,false,'The inline failure must be visible');assert.ok(errors.textContent.trim().length,'The failure must explain how to recover');if(pattern)assert.match(errors.textContent,pattern);
  assert.equal(node.getAttribute('aria-invalid'),'true','The failing field is marked invalid');assert.ok((node.getAttribute('aria-describedby')||'').split(/\s+/).includes(errors.id),'The field is explicitly associated with the visible inline explanation');
  assert.ok(app.contains(errors));unchanged(app,before);
}
function assertADIdentity(app,name,realm){
  if(app.attributeSelection)app.clearAttribute();
  const model=app.labModel,all=operations(model),last=reconstructProtocolState(model,model.steps().length-1);
  assert.equal(validateProtocolScenario(model).valid,true);
  const serviceRequests=all.filter(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname'&&operation.instanceId.startsWith('target:service:'));
  assert.ok(serviceRequests.length,'The service name must actually travel in the request body');for(const operation of serviceRequests)assert.equal(operation.value,name);
  assert.equal(last.proofs.tgsService.target,name);assert.equal(last.proofs.tgsService.realm,realm,'The proof interprets the same realm as the ticket and the client');
  for(const id of ['adTicketTarget','adTicketRealm','adTGSReply']){
    const fields=all.filter(operation=>operation.attributeId===id&&operation.instanceId!== 'ticket:host:01'&&operation.instanceId!=='reply:tgs:host:result');assert.ok(fields.length,id+' appears in real source events');
    for(const operation of fields){const expected=id==='adTicketTarget'?name:id==='adTicketRealm'?realm:reply(name,realm);assert.equal(operation.value,expected,id+' keeps the parsed name/realm across create, send, receive and verify');const instance=buildProtocolInstances(model,operation.index).find(instance=>instance.instanceId===operation.instanceId);assert.ok(instance.occurrences.some(occurrence=>occurrence.definitionId===id&&occurrence.value===expected),'The exact value ledger agrees with the source operation');}
  }
  assert.equal(last.issued.service.target,name);assert.equal(last.issued.service.crealm,realm);assert.equal(last.credentials.service.target,name);assert.equal(last.credentials.service.crealm,realm,'The accepted cache records the same parsed identity');
  assert.equal(model.definitions().adSPN.example,name);assert.equal(model.definitions().adTicketRealm.example,realm);
  const index=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));assert.ok(index>=0);app.selectStep(index,false);const full=app.protocolSnapshot(),expected=reply(name,realm);
  assert.equal(field(app.currentStep,'adTGSReply'),expected);assert.ok(app.refs.inspector.textContent.includes(expected));assert.equal(full.state.proofs.tgsService.target,name);assert.equal(full.state.proofs.tgsService.realm,realm);assert.equal(full.state.credentials.service,undefined,'A sent reply is not a cached credential before validation');
  app.selectAttribute('adTGSReply',false);const sendIndex=app.traceQueue.findIndex(step=>step.traceKind==='send'&&step.sourceStepId.endsWith('-service-tgs-reply'));assert.ok(sendIndex>=0);app.selectStep(sendIndex,false);const send=app.currentStep;
  assert.equal(field(send,'adTGSReply'),expected);assert.equal(send.sourceIndex,index);assert.deepEqual(app.protocolSnapshot().state,full.state,'Focused Send retains the real complete source prefix');assert.ok(app.querySelector('#protocol-instance-list').textContent.includes(expected));
  app.player.seek([send],.3,'attribute-step');assert.equal(app.player.snapshot().packet.value,expected);assert.equal(app.refs.packet.hidden,false);assert.ok(expected.startsWith(app.refs['packet-value'].textContent.replace(/…$/,'')),'The compact animation packet derives from the exact protected reply');
  assert.equal(data(LAB_MODELS[model.id]),authored.get(model.id),'Source fixtures are immutable across context construction');
}

for(const [id,name] of families){
  test('R2: '+id+' accepts the chosen 254-character realm boundary and Reset restores its base',()=>{
    const app=mount(id);try{const revision=app.runtimeEnvironment.revision;enter(app,'kerberosRealm','R'.repeat(254));enter(app,'servicePrincipal',name);apply(app);accepted(app);assert.equal(app.runtimeEnvironment.revision,revision+1);assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'R'.repeat(254));assertADIdentity(app,name,'R'.repeat(254));reset(app,id);}finally{dispose(app);}
  });
  for(const length of [255,2048])test('R2: '+id+' rejects a '+length+'-character realm atomically, then corrected Apply works without Reset',()=>{
    const app=mount(id);try{enter(app,'kerberosRealm','CORP.EXAMPLE');enter(app,'servicePrincipal',name);apply(app);accepted(app);running(app,length===2048);const before=capture(app);
      enter(app,'kerberosRealm','R'.repeat(length));enter(app,'servicePrincipal',name.replace('review','rejected'));apply(app);rejected(app,'kerberosRealm',before,/(254|characters|length|limit)/i);
      enter(app,'kerberosRealm','FIXED.EXAMPLE');enter(app,'servicePrincipal',name.replace('review','corrected'));apply(app);accepted(app);assert.equal(app.runtimeEnvironment.revision,before.revision+1,'Only the successful correction increments the revision');assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'FIXED.EXAMPLE');assert.equal(input(app,'kerberosRealm').getAttribute('aria-invalid'),'false');assert.equal(app.visited.size,0);assert.equal(app.visibleIndex,0);assertADIdentity(app,name.replace('review','corrected'),'FIXED.EXAMPLE');reset(app,id);
    }finally{dispose(app);}
  });
  test('R2: '+id+' unexpected fixture-constructor failure is an atomic recoverable Apply rejection',()=>{
    const app=mount(id),base=LAB_MODELS[id],constructor=base.contextualize;try{
      enter(app,'kerberosRealm','CORP.EXAMPLE');enter(app,'servicePrincipal',name);apply(app);accepted(app);running(app,true);const before=capture(app),failed=name.replace('review','injected');let injectedCalls=0;
      base.contextualize=(context,...args)=>{if(context.servicePrincipal===failed){injectedCalls++;throw new TypeError('Synthetic fixture rebuild failure');}return constructor(context,...args);};
      enter(app,'servicePrincipal',failed);apply(app);assert.equal(injectedCalls,1,'The actual candidate fixture constructor was exercised');rejected(app,'servicePrincipal',before,/failure|construct|rebuild|context/i);
      base.contextualize=constructor;enter(app,'servicePrincipal',name.replace('review','recovered'));apply(app);accepted(app);assert.equal(app.runtimeEnvironment.revision,before.revision+1);assertADIdentity(app,name.replace('review','recovered'),'CORP.EXAMPLE');reset(app,id);
    }finally{base.contextualize=constructor;dispose(app);}
  });
  test('R3: '+id+' unqualified service identity is consistent through requests, full/focused reply, animation and cache',()=>{
    const app=mount(id);try{enter(app,'kerberosRealm','CORP.EXAMPLE');enter(app,'servicePrincipal',name);apply(app);accepted(app);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);assertADIdentity(app,name,'CORP.EXAMPLE');reset(app,id);}finally{dispose(app);}
  });
  for(const realm of ['A.EXAMPLE','CORP.EXAMPLE'])test('R3: '+id+' matching @'+realm+' qualifier normalizes without moving the account realm',()=>{
    const app=mount(id);try{const old=data(app.labModel);if(realm!=='A.EXAMPLE')enter(app,'kerberosRealm',realm);enter(app,'servicePrincipal',name+'@'+realm);apply(app);accepted(app);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name,'Committed context contains the separate unqualified principal name');assert.equal(app.runtimeEnvironment.applied.kerberosRealm,realm==='A.EXAMPLE'?'':realm,'Matching qualification never silently changes the account-realm input');assertADIdentity(app,name,realm);reset(app,id);assert.equal(data(app.labModel),old);}finally{dispose(app);}
  });
  for(const realm of ['A.EXAMPLE','CORP.EXAMPLE'])test('R3: '+id+' conflicting @OTHER.EXAMPLE preserves the prior '+realm+' model and running trace',()=>{
    const app=mount(id);try{if(realm!=='A.EXAMPLE')enter(app,'kerberosRealm',realm);enter(app,'servicePrincipal',name);apply(app);accepted(app);running(app,true);const before=capture(app);
      enter(app,'servicePrincipal',name+'@OTHER.EXAMPLE');apply(app);rejected(app,'servicePrincipal',before,/cross.realm/i);assert.equal(app.runtimeEnvironment.applied.kerberosRealm,realm==='A.EXAMPLE'?'':realm,'A conflicting target cannot move the account realm or synthesize referrals');
      enter(app,'servicePrincipal',name+'@'+realm);apply(app);accepted(app);assert.equal(app.runtimeEnvironment.revision,before.revision+1);assertADIdentity(app,name,realm);reset(app,id);
    }finally{dispose(app);}
  });
}

for(const malformed of ['cifs/review.corp.example@A.EXAMPLE@OTHER.EXAMPLE','cifs/review\\@corp.example@A.EXAMPLE'])test('R3: Apply rejects unsupported or ambiguous principal notation '+malformed,()=>{
  const app=mount('lab-ad-first-sign-in');try{running(app);const before=capture(app);enter(app,'servicePrincipal',malformed);apply(app);rejected(app,'servicePrincipal',before,/principal|escape|qualifier|format|notation/i);enter(app,'servicePrincipal','cifs/review.corp.example@A.EXAMPLE');apply(app);accepted(app);assertADIdentity(app,'cifs/review.corp.example','A.EXAMPLE');reset(app,'lab-ad-first-sign-in');}finally{dispose(app);}
});

test('R2: an invalid inactive Kerberos draft cannot poison a successful SSH environment Apply',()=>{
  const id='lab-ad-first-sign-in',app=mount(id);try{
    const before=capture(app);enter(app,'kerberosRealm','R'.repeat(255));apply(app);rejected(app,'kerberosRealm',before,/(254|characters|length|limit)/i);
    app.selectLabScenario('lab-ssh-cert-success');assert.equal(app.runtimeEnvironment.draft.kerberosRealm.length,255,'The rejected draft remains available for correction');assert.equal(app.refs['environment-fields'].querySelector('[data-environment-field="kerberosRealm"]'),null,'The Kerberos field is inactive in the SSH certificate lesson');
    const revision=app.runtimeEnvironment.revision;enter(app,'caURL','https://ca.corp.example/ssh');apply(app);accepted(app);assert.equal(app.runtimeEnvironment.revision,revision+1);assert.equal(app.runtimeEnvironment.applied.caURL,'https://ca.corp.example/ssh');assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'','An inactive invalid draft is never committed by another workspace');
    assert.doesNotThrow(()=>app.selectLabScenario(id),'Returning to Kerberos must not consult a poisoned applied realm');assert.equal(data(app.labModel),authored.get(id));assert.equal(app.runtimeEnvironment.draft.kerberosRealm.length,255);enter(app,'kerberosRealm','CORP.EXAMPLE');apply(app);accepted(app);assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'CORP.EXAMPLE');reset(app,id);
  }finally{dispose(app);}
});

for(const id of ['lab-ad-pkinit-success','lab-ad-fast-tgs-success']){
  test('R3: '+id+' uses the same matching qualifier contract in the request and accepted service cache',()=>{
    const app=mount(id);try{
      const name='HTTP/review.corp.example',realm='CORP.EXAMPLE';enter(app,'kerberosRealm',realm);enter(app,'servicePrincipal',name+'@'+realm);apply(app);accepted(app);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,name);
      const model=app.labModel,defs=model.definitions(),spnId=Object.keys(defs).find(key=>defs[key].name==='sname (service request)'),realmId=Object.keys(defs).find(key=>defs[key].name==='realm (KDC-REQ-BODY)');assert.ok(spnId&&realmId);assert.equal(defs[spnId].example,name);assert.equal(defs[realmId].example,realm);
      if(id==='lab-ad-pkinit-success'){
        const sent=operations(model).filter(operation=>operation.attributeId===spnId&&operation.kind==='send');assert.ok(sent.length,'The PKINIT downstream request transmits a distinct service-name field');for(const operation of sent)assert.equal(operation.value,name);
      }else{
        const outer=operations(model).filter(operation=>operation.fieldPath==='KDC-REQ.req-body'&&operation.kind==='send');assert.ok(outer.length,'The selected FAST profile transmits its modeled outer request body');for(const operation of outer){assert.ok(operation.value.includes('sname='+name));assert.ok(operation.value.includes('realm='+realm));}
        const inner=operations(model).filter(operation=>operation.fieldPath==='KrbFastReq.req-body'&&operation.kind==='verify');assert.ok(inner.length,'The FAST KDC verifies the decoded authoritative inner target');for(const operation of inner){assert.ok(operation.value.includes('sname='+name));assert.ok(operation.value.includes('realm='+realm));}
      }
      const cache=reconstructProtocolState(model,model.steps().length-1).credentials.service;assert.ok(cache);assert.equal(cache.sname,name);assert.equal(cache.crealm,realm);assert.equal(validateProtocolScenario(model).valid,true);
      assert.ok(!data(model).includes(name+'@'+realm),'An accepted realm suffix never leaks into the generated principal-name fields');reset(app,id);
    }finally{dispose(app);}
  });
  test('R3: '+id+' rejects a conflicting target realm through Apply and remains correctable',()=>{
    const app=mount(id);try{const before=capture(app);enter(app,'servicePrincipal','HTTP/review.corp.example@OTHER.EXAMPLE');apply(app);rejected(app,'servicePrincipal',before,/cross.realm/i);enter(app,'servicePrincipal','HTTP/review.corp.example@A.EXAMPLE');apply(app);accepted(app);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,'HTTP/review.corp.example');reset(app,id);}finally{dispose(app);}
  });
}

for(const [id,name] of families)test('R3: direct '+id+' projection and participant rows normalize a raw matching-qualified context without mutating issued fixtures',()=>{
  const realm='CORP.EXAMPLE',raw={kerberosRealm:realm,servicePrincipal:name+'@'+realm},base=LAB_MODELS[id],model=base.contextualize(raw),before=data(model),snapshot=projectScenarioContext(model,model.steps(),raw),projected={...model,steps:()=>snapshot.steps,initialState:snapshot.initialState,protocolValues:snapshot.protocolValues};
  const request=operations(projected).filter(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname'&&operation.instanceId.startsWith('target:service:'));assert.ok(request.length);for(const operation of request)assert.equal(operation.value,name,'A raw qualifier cannot be reintroduced into a normalized request by the generic projector');
  const state=reconstructProtocolState(projected,projected.steps().length-1);assert.equal(state.proofs.tgsService.target,name);assert.equal(state.proofs.tgsService.realm,realm);assert.equal(state.credentials.service.target,name);assert.equal(state.credentials.service.crealm,realm);
  for(const operation of operations(projected).filter(operation=>operation.attributeId==='adTGSReply'))assert.equal(operation.value,reply(operation.instanceId==='reply:tgs:host:result'?'host/ws01.a.example':name,realm),'Projecting scalar context never edits a previously constructed protected reply');
  const binding=model.runtimeBindings.find(item=>item.field==='servicePrincipal'),rows=scenarioContextRows(model,binding.actorId,raw),row=rows.find(item=>item.key==='servicePrincipal');assert.ok(row);assert.equal(row.value,name,'Participant context rows show the same separated service principal name');
  assert.equal(validateProtocolScenario(projected).valid,true);assert.equal(data(model),before,'Generic projection does not mutate the issued fixture');assert.equal(data(base),authored.get(id),'Context construction leaves the authored fixture unchanged');
});
