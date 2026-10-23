import test from 'node:test';
import assert from 'node:assert/strict';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {buildMCPScenarioFixture,MCPLAB_CASE_BUILDERS} from '../src/mcp-auth-lab.js';
import {buildMCPHeldObjects} from '../src/held-object-mcp.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';
import {reconstructProtocolState,buildProtocolInstances} from '../src/protocol-state.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
function fixture(model){const steps=model.steps(),plan=buildMCPHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+model.variantId}),compiled=compileHeldObjects(plan,{model,steps});const index=key=>{const eventIndex=steps.findIndex(s=>s.id===model.id+':'+key);assert.ok(eventIndex>=0,'Missing MCP checkpoint '+model.id+':'+key);return eventIndex;};return {model,steps,plan,compiled,index,at:key=>projectHeldObjects(compiled,{eventIndex:index(key),milestone:'complete'}),has:(frame,key,actor,representation)=>frame.holdings.some(h=>h.artifactId===model.id+':'+key&&h.actorId===actor&&(!representation||h.representationId===representation))};}
test('MCP wire receipt adds no plaintext token or request authority, including when an older copy is retained',()=>{
  const f=fixture(buildMCPScenarioFixture('lab-mcp01'));
  assert.equal(f.has(f.at('grant-token-response'),'grant-access-g1','mcpC','readable-untrusted'),false);
  assert.equal(f.has(f.at('grant-token-response-recover'),'grant-access-g1','mcpC','readable-untrusted'),true);
  assert.equal(f.has(f.at('list-request-wire'),'grant-access-g1','mcpR','readable-untrusted'),false);
  assert.equal(f.has(f.at('list-request-wire-recover'),'grant-access-g1','mcpR','readable-untrusted'),true);
  // The subsequent invocation cannot erase the copy already received for tools/list.
  const tokenHoldings=frame=>frame.holdings.filter(h=>h.artifactId===f.model.id+':grant-access-g1'&&h.actorId==='mcpR').map(h=>h.holdingId);
  const before=f.at('operation-construct'),wire=f.at('operation-request-wire'),recovered=f.at('operation-request-wire-recover');
  assert.ok(tokenHoldings(before).length>0);
  assert.deepEqual(tokenHoldings(wire),tokenHoldings(before));
  assert.equal(tokenHoldings(recovered).length,tokenHoldings(before).length+1);
  assert.equal(f.has(wire,'operation-request','mcpR','plain'),false);
  assert.equal(f.has(wire,'operation-request-wire-tls-record','mcpR','wire'),true);
  assert.equal(f.has(recovered,'operation-request','mcpR','plain'),true);
  assert.equal(f.has(recovered,'operation-request-wire-tls-record','mcpR','wire'),false);
  for(const key of ['operation-request-wire','operation-request-wire-recover']){
    assert.equal(f.has(f.at(key),'operation-token-context','mcpR'),false);
    assert.equal(reconstructProtocolState(f.model,f.index(key)).mcp.tokenAccepted,false);
  }
  assert.equal(f.has(f.at('operation-token'),'operation-token-context','mcpR'),true);
});
test('MCP verifier is created locally before token exchange and never acquired by browser/resource',()=>{
  const f=fixture(buildMCPScenarioFixture('lab-mcp01'));
  for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){
    const frame=projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
    assert.equal(f.has(frame,'grant-verifier','mcpB'),false);assert.equal(f.has(frame,'grant-verifier','mcpR'),false);
  }
  assert.equal(f.has(f.at('grant-prepare'),'grant-verifier','mcpC'),true);
  assert.equal(f.has(f.at('grant-token-request'),'grant-verifier','mcpA'),false);
  assert.equal(f.has(f.at('grant-token-request-recover'),'grant-verifier','mcpA'),true);
  const trace=heldObjectTrace(f.compiled,f.model.id+':grant-verifier');assert.ok(trace.some(row=>row.sourceStepId===f.model.id+':grant-prepare'));
});
test('MCP canonical prefix reconstructed at exact-object replay cursor retains full protocol state',()=>{
  const f=fixture(buildMCPScenarioFixture('lab-mcp01'));
  const trace=heldObjectTrace(f.compiled,f.model.id+':operation-result');
  for(const row of trace){const eventIndex=f.steps.findIndex(s=>s.id===row.sourceStepId);if(eventIndex<0)continue;const canonical=reconstructProtocolState(f.model,eventIndex);assert.equal(canonical.mcp.priorReadGrant.valid,true);if(row.sourceStepId.endsWith(':operation-result-wire'))assert.equal(canonical.mcp.resultLearned,false);}
  const result=f.plan.artifacts.find(a=>a.artifactId===f.model.id+':operation-result');assert.equal(result.creator,'mcpR');assert.equal(result.representations[0].fields[0].value,'SYM(permitted report bytes)');
});
test('Every MCP default and named case has unique source lineage and explicit held lifetimes at all prefixes',()=>{
  let caseCount=0;
  for(const cases of Object.values(MCPLAB_CASE_BUILDERS))for(const build of Object.values(cases)){
    const model=build(),steps=model.steps(),label=model.id+'/'+model.variantId;
    assert.equal(new Set(steps.map(step=>step.id)).size,steps.length,label);
    assert.deepEqual(Object.keys(model.mcpInventory.events),steps.map(step=>step.id),label);
    for(const step of steps)for(const operation of step.attributeOperations)assert.equal(operation.sourceEventId,step.id,label);
    const f=fixture(model);
    for(const step of steps){
      if(step.eventType==='local'&&step.from!=='mcpC')assert.equal(step.protocolEffects.some(effect=>effect.path==='mcp.clientKnowledge'),false,label+' remote decision cannot grant client knowledge');
      const event=model.mcpInventory.events[step.id];
      for(const message of event.messages)for(const object of message.objects)if(object.representationId==='wire'){
        const recovery=model.mcpInventory.events[step.id+'-recover'];
        assert.ok(recovery,label+' protected receipt needs a local recovery');
        const receipt=event.effects.find(effect=>effect.op==='acquire'&&effect.artifactId===object.artifactId);
        assert.equal(receipt.retention,'temporary',label);
        assert.equal(recovery.effects.some(effect=>effect.op==='release'&&effect.holdingId===receipt.holdingId),true,label);
        assert.equal(event.effects.some(effect=>effect.op==='acquire'&&effect.artifactId!==object.artifactId),false,label+' wire receipt cannot acquire inner plaintext');
      }
    }
    for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++)assert.equal(projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'}).coverageStatus,'complete',label);
    const end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(end.holdings.some(holding=>holding.retention==='temporary'),false,label);
    assert.equal(f.has(end,'prior-read-grant','mcpC','plain'),true,label);
    caseCount++;
  }
  assert.equal(caseCount,117);
});

test('Decoded token history preserves each issuer while exposing claims only at the receiving parser',()=>{
  const model=buildMCPScenarioFixture('lab-mcp09'),steps=model.steps();
  const downstreamParse=steps.findIndex(step=>step.id==='lab-mcp09:downstream-token-parse');
  const before=buildProtocolInstances(model,downstreamParse-1).find(instance=>instance.instanceId==='lab-mcp09:downstream-access-g1');
  assert.equal(before.creator,'mcpA');
  assert.equal(before.occurrences.some(item=>item.representation==='decoded-untrusted'),false);
  const instances=buildProtocolInstances(model,steps.length-1);
  const downstream=instances.find(instance=>instance.instanceId==='lab-mcp09:downstream-access-g1');
  const upstream=instances.find(instance=>instance.instanceId==='lab-mcp09:upstream-access-g1');
  assert.equal(downstream.creator,'mcpA');
  assert.equal(upstream.creator,'mcpS');
  assert.ok(downstream.occurrences.some(item=>item.representation==='decoded-untrusted'&&item.actorId==='mcpR'));
  assert.ok(upstream.occurrences.some(item=>item.representation==='decoded-untrusted'&&item.actorId==='mcpU'));
});

test('MCP TLS envelopes exist in exact sender custody before receipt and release both temporary wire copies',()=>{
  const f=fixture(buildMCPScenarioFixture('lab-mcp01')),packet='initial-post-tls-record';
  const before=projectHeldObjects(f.compiled,{eventIndex:f.index('initial-post-protect'),milestone:'before'});
  assert.equal(f.has(before,packet,'mcpC','wire'),false);
  assert.equal(f.has(f.at('initial-post-protect'),packet,'mcpC','wire'),true);
  assert.equal(f.has(f.at('initial-post-protect'),packet,'mcpR','wire'),false);
  const sendStart=projectHeldObjects(f.compiled,{eventIndex:f.index('initial-post'),progress:0});
  assert.equal(f.has(sendStart,packet,'mcpC','wire'),true);
  assert.equal(f.has(sendStart,packet,'mcpR','wire'),false);
  assert.equal(f.has(f.at('initial-post'),packet,'mcpC','wire'),false);
  assert.equal(f.has(f.at('initial-post'),packet,'mcpR','wire'),true);
  assert.equal(f.has(f.at('initial-post-recover'),packet,'mcpR','wire'),false);
  const instance=buildProtocolInstances(f.model,f.index('initial-post-recover')).find(item=>item.instanceId===f.model.id+':'+packet);
  assert.equal(instance.creator,'mcpC');
  assert.deepEqual(instance.occurrences.filter(item=>['create','derive'].includes(item.kind)).map(item=>[item.sourceEventId,item.actorId]),[[f.model.id+':initial-post-protect','mcpC']]);
  assert.equal(reconstructProtocolState(f.model,f.index('initial-post')).mcp.tokenAccepted,false);
});

test('MCP incremental scope selection inspects the existing AS token without recreating it at the client',()=>{
  for(const variant of ['default','repeated-challenge','consent-declined']){
    const f=fixture(buildMCPScenarioFixture('lab-mcp06',{variant})),token=f.model.id+':read-access-g1';
    const instance=buildProtocolInstances(f.model,f.steps.length-1).find(item=>item.instanceId===token);
    assert.equal(instance.creator,'mcpA',variant);
    assert.ok(instance.occurrences.some(item=>item.sourceEventId===f.model.id+':stepup-check'&&item.kind==='inspect'&&item.actorId==='mcpC'),variant);
    assert.equal(instance.occurrences.some(item=>['create','derive'].includes(item.kind)&&item.actorId!=='mcpA'),false,variant);
    assert.equal(f.has(f.at('stepup-check'),'read-access-g1','mcpC','readable-untrusted'),true,variant);
  }
});

test('MCP absent issuer-capability metadata stays explicitly absent in local field replay without changing issuer checks',()=>{
  for(const [variant,accepted,present] of [
    ['absent-advertisement-iss-match',true,true],
    ['absent-advertisement-iss-wrong',false,true],
    ['absent-advertisement-iss-absent',true,false],
  ]){
    const model=buildMCPScenarioFixture('lab-mcp04',{variant}),steps=model.steps(),attributeId='mcp_field_Advertised';
    const config=model.mcpInventory.artifacts.find(item=>item.artifactId===model.id+':validated-as-config');
    assert.equal(Object.hasOwn(JSON.parse(config.representations[0].fields[0].value),'authorization_response_iss_parameter_supported'),false);
    const validation=steps.find(step=>step.id===model.id+':grant-callback-validation'),operation=validation.attributeOperations.find(item=>item.attributeId===attributeId);
    assert.deepEqual(JSON.parse(operation.value),{present:false,value:null});
    const previous=ATTRIBUTES[attributeId];ATTRIBUTES[attributeId]=model.definitions()[attributeId];
    try{
      const trace=buildAttributeTrace(getAttributeUsage(steps,attributeId),model.examples());
      const moment=trace.find(step=>step.sourceStepId===validation.id);
      assert.equal(moment.payload.find(field=>field.attributeId===attributeId).value,operation.value);
      assert.equal(moment.from,'mcpC');assert.equal(moment.to,'mcpC');
    }finally{if(previous)ATTRIBUTES[attributeId]=previous;else delete ATTRIBUTES[attributeId];}
    const state=reconstructProtocolState(model,steps.indexOf(validation)).mcp;
    assert.equal(state.callbackAccepted,accepted,variant);
    assert.equal(validation.attributeOperations.find(item=>item.attributeId==='mcp_field_IssuerPresent').value,JSON.stringify(present),variant);
  }
});
