import test from 'node:test';
import assert from 'node:assert/strict';
import {buildDNSSECScenarioFixture} from '../src/dnssec-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

function stubAnswer(model){
  const artifacts=new Map(model.dnssecInventory.artifacts.map(artifact=>[artifact.artifactId,artifact]));
  for(const step of model.steps())for(const message of model.dnssecInventory.events[step.id]?.messages||[]){
    if(message.from!=='dnsResolver'||message.to!=='dnsStub')continue;
    const records=message.objects.map(object=>artifacts.get(object.artifactId));
    const rrset=records.find(artifact=>artifact.type==='dns-rrset');
    if(!rrset)continue;
    const signature=records.find(artifact=>artifact.type==='dns-rrsig');
    return {
      rrset:rrset.representations[0].fields.find(field=>field.attributeId==='dnssec_rrset_record').value,
      signature:signature.representations[0].fields.find(field=>field.attributeId==='dnssec_rrsig_record').value
    };
  }
  assert.fail('A positive DNS response must carry an actual RRset to the stub');
}

test('a warm answer retains its receipt deadline and returns only its remaining TTL',()=>{
  const model=buildDNSSECScenarioFixture('lab-dnssec01',{variant:'warm-answer-cache'});
  const initial=model.initialState.dnssec.cacheEntries[0],steps=model.steps();
  const final=reconstructProtocolState(model,steps.length-1),cached=final.dnssec.cacheEntries[0];
  const reply=stubAnswer(model);
  assert.equal(cached.receivedAt,initial.receivedAt,'A cache hit is not a fresh receipt');
  assert.equal(cached.expiresAt,initial.expiresAt,'Serving a cache hit does not restart its lifetime');
  assert.equal(reply.rrset.ttl,initial.expiresAt-final.protocolClock,'The stub cannot retain data beyond the existing cache deadline');
});

test('a newly returned signed RRset cannot outlive its authenticated signature',()=>{
  const model=buildDNSSECScenarioFixture('lab-dnssec02'),steps=model.steps();
  const final=reconstructProtocolState(model,steps.length-1),reply=stubAnswer(model);
  assert.ok(final.protocolClock>reply.signature.inception);
  assert.ok(reply.rrset.ttl<=reply.signature.expiration-final.protocolClock,'A publication delay consumes signature lifetime even when the received TTL is longer');
});
