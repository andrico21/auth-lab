import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness} from './dom-harness.mjs';
import {ADLAB_ATTRIBUTES,ADLAB_SCENARIOS} from '../src/kerberos-ad-lab.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {buildProtocolInstances,reconstructProtocolState,validateProtocolScenario} from '../src/protocol-state.js';

// Independent acceptance conditions from auth-lab-html2-recheck(1).html, R1.
// Actual request/proof/header/reply/cache values are compared across source and
// focused views. This is deterministic handler evidence, not native acceptance.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const base=id=>ADLAB_SCENARIOS.find(model=>model.id===id);
const data=model=>JSON.stringify({definitions:model.definitions(),initialState:model.initialState,steps:model.steps(),actors:model.actors(),protocolValues:model.protocolValues});
const originals=new Map(ADLAB_SCENARIOS.map(model=>[model.id,data(model)]));
const originalRegistry=JSON.stringify(ADLAB_ATTRIBUTES);
const final=model=>reconstructProtocolState(model,model.steps().length-1);
const replyValue=(target,realm='A.EXAMPLE')=>'EncryptedData(key=tgt-session:01, EncTGSRepPart for '+target+'; srealm='+realm+')';
const operations=model=>model.steps().flatMap((step,index)=>step.attributeOperations.map(operation=>({...operation,step,index})));
function focused(model,id){return buildAttributeTrace(model.steps().map((step,index)=>({step,index,actions:step.attributeOperations.filter(operation=>operation.attributeId===id)})).filter(usage=>usage.actions.length),model.examples(),model.protocolValues||{});}
function mount(){const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();return app;}
function dispose(app){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
function enter(app,path,value){const input=app.refs['environment-fields'].querySelector('[data-environment-field="'+path+'"]');assert.ok(input,'The operator can edit '+path);input.value=value;}
function assertTarget(model,target,realm='A.EXAMPLE'){
  const all=operations(model),state=final(model);
  for(const operation of all.filter(operation=>operation.attributeId==='adSPN'&&operation.carriedAs==='TGS-REQ.req-body.sname'))assert.equal(operation.value,operation.step.id.endsWith('-host-tgs-request')?'host/ws01.a.example':target,model.id+' transmitted request sname');
  if(state.proofs?.tgsService)assert.equal(state.proofs.tgsService.target,target,model.id+' TGS proof target');
  if(state.proofs?.tgsHost)assert.equal(state.proofs.tgsHost.target,'host/ws01.a.example','Workstation host proof remains an independent target');
  for(const operation of all.filter(operation=>operation.attributeId==='adTicketTarget'))assert.equal(operation.value,operation.instanceId==='ticket:host:01'?'host/ws01.a.example':target,model.id+' clear ticket sname');
  for(const operation of all.filter(operation=>operation.attributeId==='adTicketRealm'))assert.equal(operation.value,realm,model.id+' clear ticket realm');
  for(const operation of all.filter(operation=>operation.attributeId==='adTGSReply')){
    const expected=replyValue(operation.instanceId==='reply:tgs:host:result'?'host/ws01.a.example':target,realm);
    assert.equal(operation.value,expected,model.id+' protected reply schematic');
    const instance=buildProtocolInstances(model,operation.index).find(instance=>instance.instanceId===operation.instanceId);
    assert.ok(instance.occurrences.some(occurrence=>occurrence.definitionId==='adTGSReply'&&occurrence.fieldPath===operation.fieldPath&&occurrence.value===expected),'The ledger records the same constructed reply field');
  }
  for(const name of ['service','host','tgt'])for(const section of ['issued','credentials']){
    const credential=state[section]?.[name];if(!credential)continue;
    assert.equal(credential.target,name==='service'?target:name==='host'?'host/ws01.a.example':'krbtgt/'+realm,model.id+' '+section+'.'+name);
    assert.equal(credential.crealm,realm,model.id+' credential client realm');
  }
  for(const step of focused(model,'adTGSReply')){
    const expected=replyValue(step.sourceStepId.endsWith('-host-tgs-create')||step.sourceStepId.endsWith('-host-tgs-reply')||step.sourceStepId.endsWith('-host-cache')?'host/ws01.a.example':target,realm);
    assert.equal(step.payload.find(field=>field.attributeId==='adTGSReply').value,expected,model.id+' focused '+step.traceKind+' exact reply');
    const sourceIndex=model.steps().findIndex(source=>source.id===step.sourceStepId);
    assert.equal(step.sourceIndex,sourceIndex,'Focus retains the actual source event');
  }
}

for(const [id,target] of [['lab-ad-first-sign-in','cifs/other.corp.test'],['lab-kc-kerberos-sso','HTTP/other.corp.test']])for(const realm of ['A.EXAMPLE','CORP.EXAMPLE']){
  test('R1: '+id+' Apply keeps full TGS reply, focused Send and final state consistent in '+realm,()=>{
    const app=mount();try{
      app.selectLabScenario(id);const source=base(id),sourceBefore=data(source),oldModel=app.labModel;
      app.selectStep(app.steps.length-1,false);app.player.play(app.steps,'demo');app.visited.add('old-context-link');
      const oldRevision=app.runtimeEnvironment.revision;
      enter(app,'servicePrincipal',target);if(realm!=='A.EXAMPLE')enter(app,'kerberosRealm',realm);
      app.querySelector('#environment-apply').click();
      assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.runtimeEnvironment.revision,oldRevision+1);
      assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);assert.equal(app.index,0);assert.equal(app.attributeSelection,null);assert.equal(app.visited.size,0);
      const request=app.steps.find(step=>step.id.endsWith('-service-tgs-request')).attributeOperations.find(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname');
      assert.ok(request,'The service name is actually transmitted in KDC-REQ-BODY');assert.equal(request.value,target);
      const fullReplyIndex=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));assert.ok(fullReplyIndex>=0);
      app.selectStep(fullReplyIndex,false);const full=app.protocolSnapshot();
      const expected=replyValue(target,realm),reply=app.currentStep.payload.find(field=>field.attributeId==='adTGSReply');
      assert.equal(reply.value,expected,'Full TGS-REP names the operator-selected service');
      assert.ok(app.refs.inspector.textContent.includes(expected),'The full-step inspector presents the exact reply');
      assert.equal(full.state.proofs.tgsService.target,target);assert.equal(full.state.issued.service.target,target);
      assert.equal(full.state.credentials.service,undefined,'A sent reply is not a successfully checked cached credential yet');
      assert.equal(full.state.issued.service.crealm,realm);
      app.selectAttribute('adTGSReply',false);
      const sendIndex=app.traceQueue.findIndex(step=>step.sourceStepId.endsWith('-service-tgs-reply')&&step.traceKind==='send');assert.ok(sendIndex>=0,'The focused reply includes its Send moment');
      app.selectStep(sendIndex,false);const send=app.currentStep;
      assert.equal(send.payload.find(field=>field.attributeId==='adTGSReply').value,expected);
      assert.ok(app.querySelector('#protocol-instance-list').textContent.includes(expected),'Focused instance inspector presents the same protected reply');
      assert.deepEqual(app.protocolSnapshot().state,full.state,'Focused Send uses the complete same source prefix');
      app.player.seek([send],.3,'attribute-step');
      assert.equal(app.player.snapshot().packet.value,expected,'The animated packet carries the exact newly constructed reply');
      assert.ok(expected.startsWith(app.refs['packet-value'].textContent.replace(/…$/,'')),'The compact packet label comes from that actual transmitted value');
      assert.equal(app.refs.packet.hidden,false);
      app.clearAttribute();app.selectStep(app.steps.length-1,false);const last=app.protocolSnapshot();assertTarget(last.model,target,realm);
      if(id==='lab-ad-first-sign-in'){
        assert.equal(last.state.credentials.host.target,'host/ws01.a.example');assert.equal(last.state.proofs.tgsHost.target,'host/ws01.a.example');
        const hostReply=app.steps.find(step=>step.id.endsWith('-host-tgs-reply')).payload.find(field=>field.attributeId==='adTGSReply');assert.equal(hostReply.value,replyValue('host/ws01.a.example',realm));
      }
      assert.notEqual(app.labModel,oldModel,'Apply selects a fresh fixture instead of editing an already issued one');
      assert.equal(data(source),sourceBefore,'Original model definitions, objects and source events remain unchanged');
      app.selectAttribute('adTGSReply',true);harness.clock.advance(500);const appliedRevision=app.runtimeEnvironment.revision;
      enter(app,'servicePrincipal',target.replace('other','second'));app.querySelector('#environment-apply').click();
      assert.equal(app.runtimeEnvironment.revision,appliedRevision+1);assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);assert.equal(app.visibleIndex,0);assert.equal(app.attributeSelection,'adTGSReply');
      assert.ok(!JSON.stringify(app.traceQueue).includes('EncTGSRepPart for '+target+';'),'Reapplying clears the prior fixture from the focused queue');
      app.querySelector('#environment-reset').click();
      assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,'');assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'');
      assert.equal(app.player.status,'idle');assert.equal(app.visibleIndex,0);
      assert.equal(data(app.labModel),sourceBefore,'Reset reconstructs the original complete fixture');
      assert.equal(JSON.stringify(app.steps),JSON.stringify(source.steps()),'Reset restores all authored source steps');
      assert.equal(data(source),sourceBefore);assert.equal(JSON.stringify(ADLAB_ATTRIBUTES),originalRegistry);
    }finally{dispose(app);}
  });
}

for(const source of ADLAB_SCENARIOS)test('R1: constructor context preserves causal outcomes and exact field values for '+source.id,()=>{
  assert.equal(typeof source.contextualize,'function','Every AD/bridge preset uses a typed fixture constructor');
  const target=source.family==='keycloak-bridge'?'HTTP/other.corp.test':'cifs/other.corp.test';
  const rebuilt=source.contextualize({servicePrincipal:target,kerberosRealm:'CORP.EXAMPLE'},{revision:73});
  assert.notEqual(rebuilt,source);assert.notEqual(rebuilt.steps(),source.steps());assert.notEqual(rebuilt.definitions(),source.definitions());assert.notEqual(rebuilt.initialState,source.initialState);
  assert.deepEqual(rebuilt.steps().map(step=>step.id),source.steps().map(step=>step.id),'Changing displayed context adds no successful protocol events');
  assert.equal(validateProtocolScenario(rebuilt).valid,true,'The reconstructed source remains independently valid');
  assertTarget(rebuilt,target,'CORP.EXAMPLE');
  assert.deepEqual(final(rebuilt).sessions,final(source).sessions,'Context does not turn denial/expiry/MIC errors into acceptance');
  assert.deepEqual(final(rebuilt).failure,final(source).failure,'The selected failure owner and stage are preserved');
  assert.equal(data(source),originals.get(source.id),'Fresh object construction preserves the authored source fixture');
  assert.equal(JSON.stringify(ADLAB_ATTRIBUTES),originalRegistry,'The shared attribute registry stays unchanged');
});
