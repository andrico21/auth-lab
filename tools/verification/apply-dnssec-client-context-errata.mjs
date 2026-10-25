import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only input transform. No production or evaluator imports.
// Only the four independently audited client-context corrections are applied.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-receipts';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-client-context');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,expected,expectedBytes){
  const bytes=fs.readFileSync(path.join(root,relative)),identity={path:relative,bytes:bytes.length,sha256:hash(bytes)};
  if(expected)assert.equal(identity.sha256,expected,'Exact immutable input: '+relative);
  if(expectedBytes!==undefined)assert.equal(identity.bytes,expectedBytes,'Exact input size: '+relative);
  return identity;
}
function load(relative,expected,expectedBytes){
  const identity=ref(relative,expected,expectedBytes);
  return {value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8')),ref:identity};
}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19');
const manifest=load(base+'/scenario-manifest.json');
const previousSeal=load(prior+'/contract-addendum.json','40c2c97a737f5c1032c5b4393a3c4f3380eed40709def2e5cbffd7e5c7d12d75');
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','2a170c5b4bbe2328dbec4939e06434ad111d5c30160248e86a8605ed384e7564',5664020)],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','4152649110d465de7a562a83bc97814c3a84dbd042ce3c70ff1ac777e152ad09',1122685)],
  ['worksheet.json',load(prior+'/worksheet.json','d189ae3805268d378f4c2acd32f8a562ada4557b9ae67a1493734d47ecfbaedd',6698486)]
]);
const proposal=load(base+'/contract-errata/client-context-erratum.json','bba7ce2c482433c82e80a36e0fb9151ebe4f2fd0a7ed708ecdb65b65ea4e8a54',4189);
const audit=ref(proposal.value.audit.path,'e0e0fff4a27c836bc11502d6815a6920b6222ac719f870570f1bb55629220f67',22367);
assert.deepEqual(proposal.value.target,originals.get('worksheet-resolution.json').ref);
assert.deepEqual(proposal.value.mergedTarget,originals.get('worksheet.json').ref);
assert.deepEqual(proposal.value.previousAddendum,previousSeal.ref);
assert.equal(proposal.value.patchCount,4);assert.equal(proposal.value.patches.length,4);
const preserved=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));
assert.equal(preserved.length,354,'Entire original D0 input set');
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=documents.get('worksheet-resolution.json'),lesson=resolution.lessons[12],selected=lesson.cases[3];
assert.equal(lesson.planId,'DNS22');assert.equal(selected.id,'different-client-trust-stores');
const paths=[
  '/lessons/12/cases/3/checkpoints/2/expected/cacheEntries/0/kind',
  '/lessons/12/cases/3/checkpoints/2/expected/cacheEntries/1/kind',
  '/lessons/12/cases/3/ownership/anchors/dnsValidator/1',
  '/lessons/12/cases/3/ownership/anchors/dnsValidator/2'
];
assert.deepEqual(selected.ownership.anchors.dnsValidator,['root-ksk-g1, trusted out-of-band in resolver-public-v1']);
for(const [index,patch] of proposal.value.patches.entries()){
  assert.equal(patch.order,index+1);assert.equal(patch.path,paths[index]);
  const parts=patch.path.slice(1).split('/');let parent=resolution;
  for(const part of parts.slice(0,-1)){assert.ok(parent&&Object.hasOwn(parent,part),'Existing patch parent');parent=parent[part];}
  const key=parts.at(-1);
  if(index<2){
    assert.equal(patch.op,'replace');assert.equal(patch.expectedBefore,'positive');assert.equal(patch.value,'answer');
    assert.deepEqual(parent[key],patch.expectedBefore);assert.equal(hash(JSON.stringify(parent[key])),patch.expectedBeforeCanonicalSha256);
    parent[key]=patch.value;
  }else{
    assert.equal(patch.op,'add');assert.equal(patch.expectedBeforeAbsent,true);
    assert.ok(Array.isArray(parent));assert.equal(Number(key),parent.length,'Append only at the sealed anchor-array gap');
    parent.push(patch.value);
  }
  assert.equal(hash(JSON.stringify(patch.value)),patch.valueCanonicalSha256);
}
const merged=documents.get('worksheet.json'),byLesson=new Map(resolution.lessons.map(item=>[item.planId,item]));
merged.lessons=merged.lessons.map(item=>byLesson.get(item.planId)||item);
const dispositions=document=>document.lessons.map(item=>({planId:item.planId,runtimeId:item.runtimeId,defaultCaseId:item.defaultCaseId,cases:item.cases.map(row=>({id:row.id,setup:row.setup,outcome:row.outcome}))}));
for(const [name,input] of originals)assert.deepEqual(dispositions(documents.get(name)),dispositions(input.value),'Every setup, outcome, case and default stays fixed: '+name);
assert.equal(merged.lessons.length,22);assert.equal(merged.lessons.reduce((count,item)=>count+item.cases.length,0),159);
assert.deepEqual(documents.get('worksheet-publication.json'),originals.get('worksheet-publication.json').value,'Publication authority unchanged');
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.clientContextErrata={
  originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposal:proposal.ref,audit,
  inputs:[freeze.ref,previousSeal.ref,proposal.ref,audit,...[...originals.values()].map(input=>input.ref)].map(input=>({...input,effectivePath:input.path})),
  effectiveAddendum:{effectivePath:path.relative(root,path.join(out,'contract-addendum.json'))},
  productionExistedDuringCorrection:true,productionConsultedByIndependentAuthor:false,osSandboxEnforcementClaimed:false,
  originalAndPriorEffectiveInputsRewritten:false,topologyOwnershipAndAllOutcomesUnchanged:true
};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-client-context-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,manifest:manifest.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposal:proposal.ref,audit,independence:'Read-only input audit reports no production source/evaluator access. This transform imports neither. No OS sandbox claim.',productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:4,originalD0InputsVerified:preserved.length},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Reproduced client-context overlay: '+name);
for(const input of [...originals.values(),freeze,manifest,previousSeal,proposal])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
ref(audit.path,audit.sha256,audit.bytes);for(const input of preserved)ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,outputs:refs}));
