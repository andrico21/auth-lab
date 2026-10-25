import test from 'node:test';
import assert from 'node:assert/strict';
import {buildDNSSECScenarioFixture} from '../src/dnssec-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {DNSSEC_BASE_CLOCK,dnssecMaterial} from '../src/dnssec-fixtures.js';
import {dnssecCheckDenial,dnssecDenialCacheEligible,dnssecDenialCacheKey} from '../src/dnssec-denial.js';
import {buildDNSSECHeldObjects} from '../src/held-object-dnssec.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject} from '../src/held-object-state.js';

function finalState(id,variant){
  const model=buildDNSSECScenarioFixture(id,{variant});
  return reconstructProtocolState(model,model.steps().length-1).dnssec;
}
function context(state,negativeKind=null){
  return {...state.query,...state.cacheNamespace,negativeKind};
}
function denial(id,{qname,qtype='AAAA',zone='lab.example.',key='child-zsk-g1',...options}){
  return dnssecCheckDenial({qname,qtype,zone,keys:[dnssecMaterial('keys',key)],now:DNSSEC_BASE_CLOCK,
    proofs:[{rrset:dnssecMaterial('rrsets',id),signatures:[dnssecMaterial('signatures',id+'-signature')]}],...options});
}

for(const [id,variant] of [['lab-dnssec07','nxdomain'],['lab-dnssec07','wildcard-excluded'],['lab-dnssec08','nsec3-nxdomain']]){
  test(`${id}/${variant}: the actual new NXDOMAIN cache answers another type without a new lifetime`,()=>{
    const state=finalState(id,variant),entry=state.cacheEntries[0],query=context(state,'NXDOMAIN');
    assert.equal(state.response.rcode,'NXDOMAIN');
    assert.equal(state.applicationResult.authenticated,true);
    assert.equal(entry.negativeKind,'nxdomain');
    const original=JSON.stringify(entry),later=entry.receivedAt+60;
    assert.ok(later<entry.expiresAt);
    for(const now of [entry.receivedAt,later])for(const qtype of ['A','AAAA','CNAME']){
      assert.equal(dnssecDenialCacheEligible(entry,{...query,qtype},now),true,`${qtype} at ${now}`);
    }
    assert.equal(dnssecDenialCacheEligible(entry,query,entry.expiresAt),false);
    assert.equal(dnssecDenialCacheEligible(entry,{...query,view:'private-v1'},later),false);
    assert.equal(dnssecDenialCacheEligible(entry,{...query,trustStore:'other-anchor'},later),false);
    assert.equal(dnssecDenialCacheEligible(entry,{...query,qclass:'CH'},later),false);
    assert.equal(JSON.stringify(entry),original,'Eligibility must not renew or mutate the inserted entry');
    assert.equal(entry.expiresAt-later,entry.expiresAt-entry.receivedAt-60);
  });
}

for(const [id,variant] of [['lab-dnssec07','existing-name-nodata'],['lab-dnssec08','nsec3-nodata'],['lab-dnssec21','genuine-nodata'],['lab-dnssec21','compact-nonexistent-name'],['lab-dnssec21','co-enabled']]){
  test(`${id}/${variant}: exact type-specific negative cache does not become broad NXDOMAIN`,()=>{
    const state=finalState(id,variant),entry=state.cacheEntries[0],query=context(state);
    assert.equal(dnssecDenialCacheEligible(entry,query,entry.receivedAt),true);
    assert.equal(dnssecDenialCacheEligible(entry,{...query,qtype:query.qtype==='AAAA'?'A':'AAAA'},entry.receivedAt),false);
    assert.equal(dnssecDenialCacheEligible(entry,{...query,negativeKind:'NXDOMAIN'},entry.receivedAt),false);
  });
}

test('unsigned denial and alias records never advertise a received RRSIG TTL',()=>{
  const record=artifact=>artifact.representations[0].fields.find(field=>field.attributeId.endsWith('_record')).value;
  for(const [id,variant] of [['lab-dnssec08','unsigned-optout-delegation'],['lab-dnssec09','cname-insecure-target']]){
    const model=buildDNSSECScenarioFixture(id,{variant}),artifacts=new Map(model.dnssecInventory.artifacts.map(artifact=>[artifact.artifactId,artifact])),unsignedTypes=new Set();
    for(const artifact of artifacts.values())if(artifact.type==='dns-header'){
      const packet=record(artifact);if(!packet.flags?.QR||!packet.recordTtls)continue;
      const signedIds=new Set(packet.objects.filter(object=>typeof object.value.signatureHex==='string').map(object=>object.value.rrsetId));
      for(const metadata of packet.recordTtls){
        const rrset=record(artifacts.get(metadata.rrsetRef));
        if(!signedIds.has(rrset.id)){
          unsignedTypes.add(rrset.type);
          assert.equal(metadata.receivedRrsigTtl,null,`${id}/${variant}: no signature was carried for ${rrset.owner} ${rrset.type}`);
          assert.equal(metadata.originalTtl,null);
        }
      }
    }
    assert.ok(unsignedTypes.has('NS'),'The actual unsigned delegation NS occurrence was checked');
  }
});

for(const [variant,targetSecurity] of [['cname-insecure-target','insecure'],['cname-secure-target','secure'],['cname-bogus-target','bogus'],['dname-synthesized-cname','secure']]){
  test(`lab-dnssec09/${variant}: actual namespace caches retain their own received TTL provenance`,()=>{
    const model=buildDNSSECScenarioFixture('lab-dnssec09',{variant}),state=reconstructProtocolState(model,model.steps().length-1).dnssec;
    const record=artifact=>artifact.representations[0].fields.find(field=>field.attributeId.endsWith('_record')).value;
    const artifacts=new Map(model.dnssecInventory.artifacts.map(artifact=>[artifact.artifactId,artifact]));
    const packets=[...artifacts.values()].filter(artifact=>artifact.type==='dns-header').map(record).filter(packet=>packet.flags?.QR&&packet.recordTtls);
    const receivedRefs=new Set(state.response.traceHops.flatMap(hop=>hop.receivedObjectRefs||[]));
    const target=state.namespaceCaches.find(entry=>entry.id.endsWith(':target-cache')),alias=state.namespaceCaches.find(entry=>entry.id.endsWith(':alias-cache'));
    assert.ok(target,'The independently retained target cache exists in actual reconstructed state');
    assert.ok(alias,'The authenticated alias cache remains independently retained');
    assert.equal(target.securityStatus,targetSecurity);
    assert.equal(alias.securityStatus,'secure');
    for(const entry of [target,alias]){
      const matches=packets.flatMap(packet=>packet.recordTtls.filter(metadata=>receivedRefs.has(metadata.rrsetRef)).map(metadata=>({packet,metadata,rrset:record(artifacts.get(metadata.rrsetRef))}))).filter(({rrset})=>rrset.owner===entry.key[2]&&rrset.type===entry.key[3]);
      assert.equal(matches.length,1,'Cache provenance must resolve to one actual received packet occurrence');
      const {packet,metadata,rrset}=matches[0],signatures=packet.objects.filter(object=>typeof object.value.signatureHex==='string'&&object.value.rrsetId===rrset.id).map(object=>object.value);
      assert.equal(entry.receivedRrsetTtl,metadata.receivedRrsetTtl);
      assert.equal(entry.receivedRrsetTtl,rrset.receivedRrsetTtl);
      assert.equal(entry.receivedRrsigTtl,metadata.receivedRrsigTtl);
      assert.equal(entry.originalTtl,metadata.originalTtl);
      if(entry===target&&targetSecurity==='insecure'){
        assert.equal(signatures.length,0,'The actual target A receipt has no RRSIG');
        assert.equal(entry.receivedRrsigTtl,null);
        assert.equal(entry.originalTtl,null);
      }else{
        assert.equal(signatures.length,1,'The signed alias or target keeps its own actual signature');
        assert.equal(entry.receivedRrsigTtl,rrset.receivedRrsigTtl);
        assert.equal(entry.originalTtl,signatures[0].originalTtl);
        assert.ok(Number.isFinite(entry.receivedRrsigTtl));
        assert.ok(Number.isFinite(entry.originalTtl));
      }
    }
  });
}

test('DNS-R10 secure alias cache keeps its authenticated lifetime independently of the bogus target',()=>{
  const model=buildDNSSECScenarioFixture('lab-dnssec09',{variant:'cname-bogus-target'}),steps=model.steps();
  const boundary=steps.findIndex(step=>step.dnssecBoundary==='accepted-use-and-cache-boundary');
  assert.ok(boundary>=0);
  const state=reconstructProtocolState(model,boundary).dnssec,T=1792713600;
  const alias=state.namespaceCaches.find(entry=>entry.id==='lab-dnssec09:alias-cache');
  const target=state.namespaceCaches.find(entry=>entry.id==='lab-dnssec09:target-cache');
  const expected={
    kind:'answer',securityStatus:'secure',receivedAt:T,validatedAt:T,
    expiresAt:T+300,remainingTtl:300,signatureDeadline:T+3600,
    authenticatedProofDeadline:T+3600,receivedRrsetTtl:300,receivedRrsigTtl:300,originalTtl:3600,
  };
  const observed=entry=>Object.fromEntries(Object.keys(expected).map(key=>[key,entry[key]]));
  assert.equal(state.clock.now,T);
  assert.equal(state.validators.dnsValidator.alias.securityStatus,'secure');
  assert.equal(state.validators.dnsValidator.target.securityStatus,'bogus');
  assert.deepEqual(observed(alias),expected,'Secure CNAME metadata belongs to its own authenticated tuple, not the failed target');
  assert.deepEqual(
    {kind:target.kind,securityStatus:target.securityStatus,receivedAt:target.receivedAt,validatedAt:target.validatedAt,expiresAt:target.expiresAt,remainingTtl:target.remainingTtl,authenticatedProofDeadline:target.authenticatedProofDeadline},
    {kind:'failure',securityStatus:'bogus',receivedAt:T,validatedAt:null,expiresAt:T+5,remainingTtl:5,authenticatedProofDeadline:null},
  );
  const evidence=model.dnssecInventory.artifacts.find(artifact=>artifact.artifactId===alias.evidenceRefs[0]);
  const checked=evidence.representations[0].fields.find(field=>field.attributeId.endsWith('_record')).value;
  assert.equal(checked.valid,true);
  assert.equal(checked.checkedAt,T);
  assert.equal(alias.validatedAt,checked.checkedAt,'Cache validation time is the existing successful alias check');
  const query={...context(state),qtype:'CNAME'},original=structuredClone(alias);
  assert.equal(dnssecDenialCacheEligible(alias,query,T+6),true,'The target failure expiry does not expire the secure alias');
  assert.equal(dnssecDenialCacheEligible(alias,query,T+299),true);
  assert.equal(dnssecDenialCacheEligible(alias,query,T+300),false);
  assert.deepEqual(alias,original,'Eligibility does not renew receipt, validation, expiry or creation-clock metadata');
  assert.equal(alias.remainingTtl,300,'Stored remaining TTL represents its original T clock, not the later eligibility query');
  const final=reconstructProtocolState(model,steps.length-1).dnssec;
  assert.equal(final.securityStatus,'bogus');
  assert.equal(final.acceptedForUse,false);
  assert.equal(final.response.rcode,'SERVFAIL');
  assert.deepEqual(final.applicationResult,{status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false});
  const compiled=compileHeldObjects(buildDNSSECHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':cname-bogus-target',choiceId:model.id}),{model,steps});
  for(const index of [boundary,steps.length-1,boundary-1,boundary]){
    const snapshot=projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});
    const holding=snapshot.holdings.find(item=>item.actorId==='dnsResolver'&&item.artifactId===alias.id);
    assert.equal(!!holding,index>=boundary,'Rewind restores actual cache custody rather than a future cache');
    if(index<boundary){
      assert.equal((snapshot.state.dnssec.namespaceCaches||[]).some(entry=>entry.id===alias.id),false);
      continue;
    }
    assert.equal(holding.store,'Result cache');
    const inspected=inspectHeldObject(snapshot,holding.holdingId),field=inspected.fields.find(item=>item.attributeId==='dnssec_cache_record');
    assert.equal(field.readable,true);
    assert.deepEqual(observed(field.value),expected,'Exact readable inspector exposes the independent literal alias lifetime');
    assert.deepEqual(field.value,snapshot.state.dnssec.namespaceCaches.find(entry=>entry.id===alias.id));
  }
});

test('transient failure keys remain type-specific and checking-context-specific',()=>{
  const state=finalState('lab-dnssec07','proof-from-wrong-zone'),entry=state.cacheEntries[0];
  const query={...context(state),failure:true};
  assert.equal(entry.kind,'failure');
  assert.deepEqual(entry.key,dnssecDenialCacheKey(query));
  assert.notDeepEqual(entry.key,dnssecDenialCacheKey({...query,qtype:'AAAA'}));
  assert.notDeepEqual(entry.key,dnssecDenialCacheKey({...query,checkingContext:'CD1'}));
});

for(const qtype of ['A','AAAA','CNAME']){
  test(`authenticated parent delegation cannot deny child-side ${qtype} at the cut`,()=>{
    const result=denial('denial-parent-unsigned-lab',{qname:'lab.example.',qtype,zone:'example.',key:'example-zsk-g1'});
    assert.equal(result.checked,true);
    assert.ok(result.checks.every(check=>check.signature.valid),'The unchanged parent signature is valid');
    assert.equal(result.valid,false,'Parent-side NS/no-SOA bitmap is not child answer authority');
  });
}

test('the same parent delegation can authenticate DS absence without denying child records',()=>{
  for(const purpose of ['negative','no-ds']){
    const result=denial('denial-parent-unsigned-lab',{qname:'lab.example.',qtype:'DS',zone:'example.',key:'example-zsk-g1',purpose});
    assert.equal(result.valid,true);
    assert.equal(result.kind,purpose==='no-ds'?'no-ds':'nodata');
  }
});

for(const qtype of ['A','AAAA','DS']){
  test(`the parent delegation cannot deny ${qtype} below its zone cut`,()=>{
    const result=denial('denial-parent-unsigned-lab',{qname:'no.lab.example.',qtype,zone:'example.',key:'example-zsk-g1'});
    assert.ok(result.checks.every(check=>check.signature.valid));
    assert.equal(result.valid,false);
  });
}

test('child authoritative NSEC and NSEC3 NODATA remain valid',()=>{
  for(const id of ['denial-www-to-apex','denial-nsec3-no-wildcard-3']){
    const result=denial(id,{qname:'www.lab.example.'});
    assert.equal(result.valid,true);
    assert.equal(result.kind,'nodata');
  }
  const apex=denial('denial-apex-to-a',{qname:'lab.example.'});
  assert.equal(apex.valid,true,'NS+SOA at the child apex is not an ancestor delegation');
});

test('the caller requiredZone guard still rejects a separately signed wrong zone',()=>{
  const result=denial('denial-parent-unsigned-lab',{qname:'no.lab.example.',zone:'example.',key:'example-zsk-g1',requiredZone:'lab.example.'});
  assert.equal(result.valid,false);
  assert.equal(result.reason,'proof-from-wrong-zone');
  assert.equal(finalState('lab-dnssec07','proof-from-wrong-zone').acceptedForUse,false);
});
