import assert from 'node:assert/strict';
import {ADLAB_ATTRIBUTES,ADLAB_SCENARIOS} from './src/kerberos-ad-lab.js';
import {reconstructProtocolState,buildProtocolInstances,validateProtocolScenario} from './src/protocol-state.js';
import {buildAttributeTrace} from './src/attribute-trace.js';
import {projectScenarioContext} from './src/scenario-context.js';
const baseSnapshot=JSON.stringify(ADLAB_SCENARIOS.map(m=>({id:m.id,state:m.initialState,steps:m.steps(),defs:m.definitions(),actors:m.actors()})));
const definitionSnapshot=JSON.stringify(ADLAB_ATTRIBUTES);
let models=0,headers=0,traces=0,prefixes=0;
for(const base of ADLAB_SCENARIOS){
 const bridge=base.family==='keycloak-bridge';
 for(const context of [{servicePrincipal:bridge?'HTTP/other.corp.test':'cifs/other.corp.test'},{kerberosRealm:'CORP.TEST',servicePrincipal:bridge?'HTTP/login.corp.test':'cifs/share.corp.test'}]){
  const expectedRealm=context.kerberosRealm||'A.EXAMPLE',target=context.servicePrincipal;
  const rebuilt=base.contextualize(context), projected=projectScenarioContext(rebuilt,rebuilt.steps(),context);
  const model={...rebuilt,steps:()=>projected.steps,initialState:projected.initialState,protocolValues:projected.protocolValues};
  assert.deepEqual(validateProtocolScenario(model).errors,[],base.id);
  const operations=model.steps().flatMap(s=>s.attributeOperations);
  assert.equal(rebuilt.definitions().adSPN?.example||target,target);
  assert.notStrictEqual(rebuilt.initialState,base.initialState);
  assert.notStrictEqual(rebuilt.steps(),base.steps());
  assert.ok(Object.isFrozen(rebuilt.initialState)&&Object.isFrozen(rebuilt.steps())&&Object.isFrozen(rebuilt.definitions()));
  const requested=model.steps().find(s=>s.id.endsWith('-service-tgs-request'));
  if(requested) assert.ok(requested.attributeOperations.some(o=>o.kind==='send'&&o.attributeId==='adSPN'&&o.value===target));
  for(const o of operations){
   if(o.attributeId==='adTicketTarget'){ assert.equal(o.value,o.instanceId==='ticket:host:01'?'host/ws01.a.example':target,base.id+' target '+o.instanceId); headers++; }
   if(o.attributeId==='adTicketRealm') assert.equal(o.value,expectedRealm,base.id+' realm');
   if(o.attributeId==='adTgtTarget') assert.equal(o.value,'krbtgt/'+expectedRealm,base.id+' tgt');
   if(o.attributeId==='adTGSReply'){
    const expected=o.instanceId.includes(':host:')?'host/ws01.a.example':target;
    assert.ok(o.value.includes('EncTGSRepPart for '+expected+'; srealm='+expectedRealm+')'),base.id+' protected '+o.value);
   }
  }
  const final=reconstructProtocolState(model,model.steps().length-1);
  if(final.proofs?.tgsService){assert.equal(final.proofs.tgsService.target,target);assert.equal(final.proofs.tgsService.realm,expectedRealm);}
  if(final.credentials.service){assert.equal(final.credentials.service.target,target);assert.equal(final.credentials.service.crealm,expectedRealm);}
  if(final.issued?.service){assert.equal(final.issued.service.target,target);assert.equal(final.issued.service.crealm,expectedRealm);assert.equal(final.issued.service.encryptedFor,bridge?'adKeycloak':'adService');}
  if(final.credentials.host){assert.equal(final.credentials.host.target,'host/ws01.a.example');assert.equal(final.credentials.host.crealm,expectedRealm);assert.equal(final.proofs.tgsHost.target,'host/ws01.a.example');}
  const trace=buildAttributeTrace(model.steps().map((step,index)=>({step,index,actions:step.attributeOperations.filter(o=>o.attributeId==='adTGSReply')})).filter(u=>u.actions.length),rebuilt.examples());
  for(const t of trace.filter(t=>t.traceKind==='send')){
   const expected=t.sourceStepId.includes('-host-')?'host/ws01.a.example':target;
   assert.ok(t.payload[0].value.includes('EncTGSRepPart for '+expected+'; srealm='+expectedRealm+')'));
   const focusState=reconstructProtocolState(model,t.sourceIndex);
   const suffix=t.sourceStepId.includes('-host-')?'host':'service';
   assert.equal(focusState.issued[suffix].target,expected);
   assert.equal(focusState.proofs[suffix==='host'?'tgsHost':'tgsService'].target,expected);
   traces++;
  }
  for(let i=-1;i<model.steps().length;i++){buildProtocolInstances(model,i);reconstructProtocolState(model,i);prefixes++;}
  models++;
 }
 const reset=base.contextualize({});
 assert.deepEqual(reset.initialState,base.initialState,base.id+' reset state');
 assert.deepEqual(reset.steps(),base.steps(),base.id+' reset steps');
 assert.deepEqual(reset.definitions(),base.definitions(),base.id+' reset defs');
}
assert.equal(JSON.stringify(ADLAB_ATTRIBUTES),definitionSnapshot);
assert.equal(JSON.stringify(ADLAB_SCENARIOS.map(m=>({id:m.id,state:m.initialState,steps:m.steps(),defs:m.definitions(),actors:m.actors()}))),baseSnapshot);
console.log(JSON.stringify({passed:true,models,headers,focusedSendMoments:traces,prefixes,baseFixturesUnchanged:true,resetRestores:true,nativeBrowser:false}));
