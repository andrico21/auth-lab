import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only schema mapping. Parent supplied the API path; R01 supplies unchanged values.
// No application, tests, evaluator or production diagnostic imports.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-mixed-path-policy';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-cache-namespace-location');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,sha256,bytes){
  const data=fs.readFileSync(path.join(root,relative)),identity={path:relative,bytes:data.length,sha256:hash(data)};
  if(sha256)assert.equal(identity.sha256,sha256,'Exact immutable input: '+relative);
  if(bytes!==undefined)assert.equal(identity.bytes,bytes,'Exact immutable size: '+relative);
  return identity;
}
function load(relative,sha256,bytes){return {ref:ref(relative,sha256,bytes),value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'))};}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19',68646);
const previousSeal=load(prior+'/contract-addendum.json','b4d113783a82fa2c55e523985b218b697203eb9d663b92804787574d559519ff',9044);
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','9d2380b4e6a43a9a9082f1c516ff50534f3439b79c61e7925aec045ad9c99b19',5664817)],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','9d4cf7a82f0025c9653bb8edb3f9b4e244ed451933d02d38fe9b5a143e9795ae',1137172)],
  ['worksheet.json',load(prior+'/worksheet.json','97c42a3ae12a2939bcbd89a546ebbf7350ff8c3caf03e3e94b1317dbdf2a4f9f',6727718)]
]);
const proposal=load(base+'/contract-errata/cache-namespace-location-proposal.json','f2f70808fce36b26a4c21fe91c43874c5eefb3190fe5e5ce660caa05843d3960',11745);
const audit=load(base+'/contract-errata/cache-namespace-location-audit.json','45f3c4c405e746118ccbc0712aee40a246a6053a266adea5be26e38e94322e70',3806);
assert.deepEqual(proposal.value.originalFreeze,freeze.ref);
assert.deepEqual(proposal.value.previousAddendum,previousSeal.ref);
assert.deepEqual(proposal.value.targets,[...originals.values()].map(input=>input.ref));
assert.deepEqual(proposal.value.audit,audit.ref);
assert.equal(proposal.value.patchCount,1);assert.equal(proposal.value.patches.length,1);
assert.equal(proposal.value.productionExistedDuringCorrection,true);
assert.equal(proposal.value.claimsPreProductionAddendum,false);
assert.equal(proposal.value.schemaDesignDiscoveryIndependenceClaimed,false);
assert.equal(proposal.value.independence.applicationSourceRead,false);
assert.equal(proposal.value.independence.productionEvaluatorExecuted,false);
assert.equal(proposal.value.independence.osSandboxEnforcementClaimed,false);
assert.equal(proposal.value.priorLayersPreserved.length,28);
const pinned=[proposal.value.review,...proposal.value.priorLayersPreserved,...audit.value.consultedFiles];
for(const input of pinned)ref(input.path,input.sha256,input.bytes);
const preserved=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));assert.equal(preserved.length,354);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=documents.get('worksheet-resolution.json'),lesson=resolution.lessons[3],selected=lesson.cases[3],checkpoint=selected.checkpoints[5];
assert.equal(lesson.planId,'DNS05');assert.equal(selected.id,'validating-stub');assert.equal(checkpoint.name,'accepted-use-and-cache-boundary');
const patch=proposal.value.patches[0],before=checkpoint.expected.cacheEntries[0];
assert.equal(patch.order,1);assert.equal(patch.op,'replace');
assert.equal(patch.path,'/lessons/3/cases/3/checkpoints/5/expected/cacheEntries/0');
assert.equal(patch.mergedPointer,'/lessons/4/cases/3/checkpoints/5/expected/cacheEntries/0');
assert.deepEqual(before,patch.expectedBefore);assert.equal(hash(JSON.stringify(before)),patch.expectedBeforeCanonicalSha256);
assert.equal(hash(JSON.stringify(patch.value)),patch.valueCanonicalSha256);
assert.equal(before.checkingOwner,'dnsStub');assert.equal(before.trustStore,'stub-public-v1');
const after=structuredClone(patch.value);
assert.equal(Object.hasOwn(after,'checkingOwner'),false);assert.equal(Object.hasOwn(after,'trustStore'),false);
assert.equal(after.namespace.checkingOwner,before.checkingOwner);assert.equal(after.namespace.trustStore,before.trustStore);
if(Object.hasOwn(before,'namespace'))for(const [key,value] of Object.entries(before.namespace))assert.deepEqual(after.namespace[key],value,'Preserved existing namespace field: '+key);
const restored=structuredClone(after);
restored.checkingOwner=after.namespace.checkingOwner;restored.trustStore=after.namespace.trustStore;
if(Object.hasOwn(before,'namespace'))restored.namespace=structuredClone(before.namespace);else delete restored.namespace;
assert.deepEqual(restored,before,'Path relocation only: every semantic value unchanged');
checkpoint.expected.cacheEntries[0]=after;
const unchangedResolution=structuredClone(resolution);unchangedResolution.lessons[3].cases[3].checkpoints[5].expected.cacheEntries[0]=structuredClone(before);
assert.deepEqual(unchangedResolution,originals.get('worksheet-resolution.json').value,'Only selected schema location changes');
assert.deepEqual(documents.get('worksheet-publication.json'),originals.get('worksheet-publication.json').value,'Publication shard unchanged');
const merged=documents.get('worksheet.json');assert.equal(merged.lessons[4].planId,'DNS05');merged.lessons[4]=structuredClone(lesson);
const identities=document=>document.lessons.map(item=>({planId:item.planId,runtimeId:item.runtimeId,defaultCaseId:item.defaultCaseId,cases:item.cases.map(row=>({id:row.id,setup:row.setup,outcome:row.outcome}))}));
for(const [name,input] of originals)assert.deepEqual(identities(documents.get(name)),identities(input.value),'All setup/outcome/default identities unchanged: '+name);
assert.equal(merged.lessons.length,22);assert.equal(merged.lessons.reduce((count,item)=>count+item.cases.length,0),159);
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.cacheNamespaceLocationErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposal:proposal.ref,audit:audit.ref,inputs:[freeze.ref,previousSeal.ref,proposal.ref,audit.ref,...[...originals.values()].map(input=>input.ref)].map(input=>({...input,effectivePath:input.path})),effectiveAddendum:{effectivePath:path.relative(root,path.join(out,'contract-addendum.json'))},productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,schemaDesignDiscoveryIndependenceClaimed:false,schemaContractSource:proposal.value.schemaContractSource,originalAndPriorEffectiveInputsRewritten:false};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-eighth-cache-namespace-location-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposal:proposal.ref,audit:audit.ref,priorLayersPreserved:proposal.value.priorLayersPreserved,independence:proposal.value.independence,productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,schemaDesignDiscoveryIndependenceClaimed:false,schemaContractSource:proposal.value.schemaContractSource,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:1,originalD0InputsVerified:354,priorEffectiveLayersVerified:7},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Exact reproduced schema-location overlay: '+name);
for(const input of [...originals.values(),freeze,previousSeal,proposal,audit])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
for(const input of [...pinned,...preserved])ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,outputs:refs}));
