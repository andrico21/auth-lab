import test from 'node:test';
import assert from 'node:assert/strict';
import {buildDNSSECScenarioFixture} from '../src/dnssec-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildDNSSECHeldObjects} from '../src/held-object-dnssec.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';

const value=artifact=>artifact.representations[0].fields.find(field=>field.attributeId.endsWith('_record')).value;
const fixture=(id,variant)=>buildDNSSECScenarioFixture(id,{variant});
function packets(model){return model.dnssecInventory.artifacts.filter(a=>a.type==='dns-header').map(a=>({artifact:a,packet:value(a)})).filter(({packet})=>packet.flags?.QR&&packet.objects?.length);}
function stateAt(model,boundary){const steps=model.steps(),index=steps.findIndex(s=>s.dnssecBoundary===boundary);assert.ok(index>=0,boundary);return reconstructProtocolState(model,index).dnssec;}

test('independent validating stub keeps its unsent verdict and secure cache inside its own trust boundary',()=>{
  const model=fixture('lab-dnssec05','validating-stub'),inventory=model.dnssecInventory;
  const before=stateAt(model,'stub-owns-independent-anchor-and-validation');
  assert.equal(before.acceptedForUse,false);
  assert.equal(before.cached,false);
  const state=stateAt(model,'accepted-use-and-cache-boundary');
  const cache=state.cacheEntries.find(entry=>entry.kind==='answer');
  assert.equal(cache.namespace.cacheOwner,'dnsStub');
  assert.equal(cache.namespace.checkingOwner,'dnsStub');
  assert.equal(cache.namespace.trustStore,'stub-public-v1');
  assert.deepEqual(state.trustStores['resolver-fetch-only-v1'].anchors,[]);
  const finalState=reconstructProtocolState(model,model.steps().length-1).dnssec;
  assert.equal(finalState.validators.dnsValidator.signatureChecked,false);
  const relayHops=finalState.response.traceHops.filter(hop=>hop.from==='dnsResolver');
  assert.ok(relayHops.some(hop=>hop.id==='lab-dnssec05:authority'));
  for(const hop of relayHops)assert.equal(hop.checkingOwner,null,'A fetch-only resolver has no checking owner for its relayed authority replies');
  for(const hop of finalState.response.traceHops.filter(hop=>hop.from==='dnsStub'))assert.equal(hop.checkingOwner,'dnsStub');
  for(const boundary of ['record-selected-evidence','accepted-use-and-cache-boundary','selected-cache-and-timer-focus']){
    const step=model.steps().find(s=>s.dnssecBoundary===boundary);
    assert.equal(step.from,'dnsStub');
  }
  const evidence=inventory.artifacts.filter(a=>a.creator==='dnsStub'&&a.type==='dns-trust');
  assert.ok(evidence.length>0);
  for(const artifact of evidence){
    for(const event of Object.values(inventory.events))for(const effect of event.effects||[])
      if(effect.op==='acquire'&&effect.artifactId===artifact.artifactId)assert.notEqual(effect.actorId,'dnsResolver','Unsent stub evidence must not appear at resolver');
  }
  assert.equal(inventory.bindings.find(b=>b.path==='dnssec.resultCacheArtifact').actorId,'dnsStub');
  const steps=model.steps(),plan=buildDNSSECHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':validating-stub',choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});
  const acceptedIndex=steps.findIndex(s=>s.dnssecBoundary==='accepted-use-and-cache-boundary');
  const cacheId=state.resultCacheArtifact;
  for(const index of [acceptedIndex,steps.length-1,acceptedIndex-1,-1]){
    const frame=projectHeldObjects(compiled,{eventIndex:index,milestone:index<0?'initial':'complete'});
    assert.deepEqual(frame.state,reconstructProtocolState(model,index));
    assert.equal(frame.holdings.some(h=>h.artifactId===cacheId&&h.actorId==='dnsStub'),index>=acceptedIndex);
    assert.equal(frame.holdings.some(h=>h.artifactId===cacheId&&h.actorId==='dnsResolver'),false);
  }
  assert.ok(heldObjectTrace(compiled,cacheId).every(row=>!row.actorId||row.actorId!=='dnsResolver'));
});

test('local create/derivation custody respects physical owners while allowing declared folded validators',()=>{
  for(const [id,variant] of [['lab-dnssec05','validating-stub'],['lab-dnssec05','trusted-resolver-ad'],['lab-dnssec06','both-validate'],['lab-dnssec06','upstream-validates-local-relies']]){
    const model=fixture(id,variant),artifacts=new Map(model.dnssecInventory.artifacts.map(a=>[a.artifactId,a]));
    const physical=actor=>actor==='dnsValidator'?'dnsResolver':actor==='dnsUpstreamValidator'?'dnsUpstream':actor==='dnsApp'?'dnsStub':actor;
    for(const event of Object.values(model.dnssecInventory.events)){
      const created=new Set(event.effects.filter(e=>e.op==='create').map(e=>e.artifactId));
      for(const effect of event.effects)if(effect.op==='acquire'&&created.has(effect.artifactId)){
        const artifact=artifacts.get(effect.artifactId);
        assert.equal(physical(effect.actorId),physical(artifact.creator),`${variant}: local creation crosses physical custody: ${artifact.artifactId}`);
        for(const ref of artifact.derivedFrom||[]){const source=artifacts.get(ref);if(source?.creator==='dnsStub'&&source.type==='dns-trust')assert.equal(physical(effect.actorId),'dnsStub','Unsent stub derivation cannot become resolver evidence');}
      }
    }
  }
});

for(const [id,variant,expected] of [['lab-dnssec05','response-flags-and-cached-ad',240],['lab-dnssec05','ad-interest-without-do',300],['lab-dnssec20','cd-one-diagnostic-data',300],['lab-dnssec20','temporary-negative-trust-anchor',299]])test(`outgoing exact packet TTLs agree with carried ordinary records: ${variant}`,()=>{
  const model=fixture(id,variant),all=packets(model);
  const reply=all.find(({artifact})=>artifact.artifactId===`${id}:${variant==='temporary-negative-trust-anchor'?'nta-active-stub':'stub'}:r-message`);
  assert.ok(reply,'Expected actual downstream response occurrence');
  const {packet}=reply,rrset=packet.objects.find(o=>o.value.type==='A').value;
  assert.equal(rrset.ttl,expected);
  assert.equal(packet.receivedRrsetTtl,expected);
  const signature=packet.objects.find(o=>o.value.typeCovered===1);
  if(variant==='ad-interest-without-do'){
    assert.equal(signature,undefined);
    assert.equal(packet.receivedRrsigTtl,null);
  }else{
    assert.ok(signature);
    assert.equal(signature.value.ttl,expected,'Ordinary signature TTL must be aged independently of signed RDATA');
    assert.equal(packet.receivedRrsigTtl,expected);
    assert.equal(signature.value.originalTtl,3600);
    const original=model.dnssecInventory.artifacts.find(a=>a.type==='dns-rrsig'&&value(a).id===signature.value.id);
    assert.equal(signature.value.rrsigRdataHex,value(original).rrsigRdataHex);
    const held=model.dnssecInventory.artifacts.find(a=>a.artifactId===signature.artifactId);
    assert.equal(value(held).ttl,expected);
  }
  if(variant==='response-flags-and-cached-ad'){
    const initial=model.initialState.dnssec.cacheEntries.find(e=>e.kind==='answer'),final=reconstructProtocolState(model,model.steps().length-1).dnssec.selectedCache;
    assert.equal(final.receivedAt,initial.receivedAt);assert.equal(final.expiresAt,initial.expiresAt);
  }
});

test('undelivered retry descriptors contain only the concrete attempts reached in this prefix',()=>{
  for(const [id,variant] of [['lab-dnssec06','forwarder-loop-or-unreachable'],['lab-dnssec20','transport-timeout']]){
    const model=fixture(id,variant),steps=model.steps();
    for(const count of [1,2,3,2,1]){
      const ids=Array.from({length:count},(_,index)=>`${id}:${variant}:attempt-${index+1}:q`);
      const index=steps.findIndex(step=>step.id===ids.at(-1));assert.ok(index>=0);
      const state=reconstructProtocolState(model,index).dnssec,hop=state.response.traceHops.find(hop=>hop.id===id+':attempt-1');
      assert.ok(hop);assert.equal(hop.delivery.attempts,count,'No future attempts before their own source events');
      const attempts=hop.attempts||[{query:hop.query,response:hop.response}];
      assert.deepEqual(attempts.map(attempt=>attempt.query.id),ids);
      assert.ok(attempts.every(attempt=>attempt.query.delivered===false&&attempt.response===null));
    }
  }
});
