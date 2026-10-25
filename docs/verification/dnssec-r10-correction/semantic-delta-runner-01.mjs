import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const [root,beforeRoot,out]=process.argv.slice(2);
const load=async directory=>{
  const api=await import(pathToFileURL(path.join(directory,'src/dnssec-lab.js')).href);
  const state=await import(pathToFileURL(path.join(directory,'src/protocol-state.js')).href);
  return {...api,...state};
};
const current=await load(root),before=await load(beforeRoot),rows=[];
function differences(a,b,prefix=''){
  if(Object.is(a,b))return [];
  if(!a||!b||typeof a!=='object'||typeof b!=='object')return [prefix];
  return [...new Set([...Object.keys(a),...Object.keys(b)])].sort().flatMap(key=>differences(a[key],b[key],prefix?prefix+'.'+key:key));
}
const outcome=state=>Object.fromEntries(['securityStatus','acceptedForUse','signatureChecked','chainEstablished','returnedToStub','applicationResult','reasonCode','failureStage','firstDetector'].map(key=>[key,state[key]]));
const topology=model=>model.steps().map(({id,from,to,channel,phase,fields})=>({id,from,to,channel,phase,fields}));
const records=(model,types)=>model.dnssecInventory.artifacts.filter(item=>types.includes(item.type)).map(item=>({id:item.artifactId,type:item.type,representations:item.representations}));
for(const variant of ['cname-bogus-target','cname-secure-target','cname-insecure-target','dname-synthesized-cname']){
  const oldModel=before.buildDNSSECScenarioFixture('lab-dnssec09',{variant}),model=current.buildDNSSECScenarioFixture('lab-dnssec09',{variant});
  const oldState=before.reconstructProtocolState(oldModel,oldModel.steps().length-1).dnssec,state=current.reconstructProtocolState(model,model.steps().length-1).dnssec;
  assert.deepEqual(topology(model),topology(oldModel),'Source event structure preserved: '+variant);
  const packets=records(model,['dns-header']),signed=records(model,['dns-rrset','dns-rrsig','dns-dnskey','dns-ds']);
  assert.deepEqual(packets,records(oldModel,['dns-header']),'All actual wire packet records preserved: '+variant);
  assert.deepEqual(signed,records(oldModel,['dns-rrset','dns-rrsig','dns-dnskey','dns-ds']),'All signed/public tuple representations preserved: '+variant);
  assert.deepEqual(outcome(state),outcome(oldState),'Trust classification and application result preserved: '+variant);
  assert.deepEqual(state.cacheEntries,oldState.cacheEntries,'Aggregate result/failure cache preserved: '+variant);
  const caches=Object.fromEntries(state.namespaceCaches.map(entry=>[entry.id,entry])),oldCaches=Object.fromEntries(oldState.namespaceCaches.map(entry=>[entry.id,entry]));
  const delta=differences(oldCaches,caches),alias=caches['lab-dnssec09:alias-cache'],target=caches['lab-dnssec09:target-cache'];
  assert.deepEqual(target,oldCaches['lab-dnssec09:target-cache'],'Every target cache field preserved: '+variant);
  assert.deepEqual(delta,variant==='cname-bogus-target'?['lab-dnssec09:alias-cache.authenticatedProofDeadline','lab-dnssec09:alias-cache.remainingTtl','lab-dnssec09:alias-cache.validatedAt']:[],'Only the three independently specified alias values change: '+variant);
  if(variant==='cname-bogus-target'){
    assert.equal(alias.validatedAt,1792713600);assert.equal(alias.remainingTtl,300);assert.equal(alias.authenticatedProofDeadline,1792717200);
    assert.equal(target.validatedAt,null);assert.equal(target.remainingTtl,5);assert.equal(state.response.rcode,'SERVFAIL');assert.equal(state.applicationResult.status,'error');
  }
  if(variant==='cname-insecure-target'){assert.equal(target.receivedRrsigTtl,null);assert.equal(target.originalTtl,null);}
  rows.push({variant,sourceEvents:model.steps().length,wirePacketArtifacts:packets.length,signedPublicArtifacts:signed.length,sourceStructureUnchanged:true,allWireAndSignedValuesUnchanged:true,outcomeUnchanged:true,aggregateCacheUnchanged:true,entireTargetCacheUnchanged:true,namespaceChangedPaths:delta,alias,target});
}
const report={schemaVersion:1,kind:'DNS-R10-bounded-before-after-alias-semantic-preservation',passed:true,argv:process.argv,rows,scope:'Exact verified corrections02 canonical source versus R10 source. No expected worksheet/data regenerated, no added network/check event. Four neighbors, every target field, aggregate result and all carried/signed public records compared; only the three literal bogus-target alias fields differ. Not live DNS, native browser or timing evidence.'};
fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:true,cases:rows.length,changedCases:rows.filter(row=>row.namespaceChangedPaths.length).map(row=>row.variant),wireAndSignedPreserved:true,entireTargetCachePreserved:true}));
