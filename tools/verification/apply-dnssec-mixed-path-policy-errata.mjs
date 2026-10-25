import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only additive authority clarification; no application/evaluator imports.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-review-corrections';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-mixed-path-policy');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,sha256,bytes){
  const data=fs.readFileSync(path.join(root,relative)),identity={path:relative,bytes:data.length,sha256:hash(data)};
  if(sha256)assert.equal(identity.sha256,sha256,'Exact immutable input: '+relative);
  if(bytes!==undefined)assert.equal(identity.bytes,bytes,'Exact immutable size: '+relative);
  return identity;
}
function load(relative,sha256,bytes){return {ref:ref(relative,sha256,bytes),value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'))};}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19',68646);
const previousSeal=load(prior+'/contract-addendum.json','107da17168b011654451c7d7156d65d72f2e90691f34d46fff4395980503b488',8810);
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','9d2380b4e6a43a9a9082f1c516ff50534f3439b79c61e7925aec045ad9c99b19',5664817)],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','2db1cb1e0a22e38f037fb76e5d565e2ffb1928db56c0fd92feb28458b31f2938',1136165)],
  ['worksheet.json',load(prior+'/worksheet.json','c0312c6841e141b50bde40d91baf6d376f6d2b33523c0d98c262c2a0d1a4e8a2',6723137)]
]);
const proposal=load(base+'/contract-errata/mixed-path-policy-proposal.json','c19a5516e76b352b746f461a11f46f0537a1b2ef2f71d6a240472f708594b5f2',11897);
const audit=load(base+'/contract-errata/mixed-path-policy-audit.json','3003a9950b1d90a551129f17329abeaa8fe6f6c813287139e5bb9af9d02a4f80',7193);
assert.deepEqual(proposal.value.originalFreeze,freeze.ref);
assert.deepEqual(proposal.value.previousAddendum,previousSeal.ref);
assert.deepEqual(proposal.value.targets,[...originals.values()].map(input=>input.ref));
assert.deepEqual(proposal.value.audit,audit.ref);
assert.equal(proposal.value.patchCount,3);assert.equal(proposal.value.patches.length,3);
assert.equal(proposal.value.independence.applicationSourceRead,false);
assert.equal(proposal.value.independence.productionEvaluatorExecuted,false);
assert.equal(proposal.value.independence.osSandboxEnforcementClaimed,false);
assert.equal(proposal.value.priorLayersPreserved.length,24);
const pinned=[...proposal.value.sources,...proposal.value.priorLayersPreserved,...audit.value.consultedFiles];
for(const input of pinned)ref(input.path,input.sha256,input.bytes);
const preserved=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));assert.equal(preserved.length,354);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const publication=documents.get('worksheet-publication.json'),lesson=publication.lessons[3],selected=lesson.cases[4];
assert.equal(lesson.planId,'DNS14');assert.equal(selected.id,'modern-and-obsolete-paths');
assert.equal(selected.checkpoints[0].name,'retain-valid-current-path');
const policy=selected.checkpoints[0].expected.algorithmPolicy;
const reasonOrder=['implementation-capability','operator-policy','digest-capability','digest-policy'];
assert.deepEqual(proposal.value.patches.map(patch=>patch.path),['unsupportedReason','rejectedPaths','unsupportedReasons'].map(field=>'/lessons/3/cases/4/checkpoints/0/expected/algorithmPolicy/'+field));
for(const [index,patch] of proposal.value.patches.entries()){
  assert.equal(patch.order,index+1);assert.ok(patch.sources.length>0&&patch.finding.length>0);
  const key=patch.path.split('/').at(-1);
  assert.equal(hash(JSON.stringify(patch.value)),patch.valueCanonicalSha256,'Exact after value: '+key);
  if(patch.op==='replace'){
    assert.ok(Object.hasOwn(policy,key));assert.deepEqual(policy[key],patch.expectedBefore);
    assert.equal(hash(JSON.stringify(policy[key])),patch.expectedBeforeCanonicalSha256,'Exact before hash: '+key);
  }else{
    assert.equal(patch.op,'add');assert.equal(patch.expectedBeforeAbsent,true);assert.equal(Object.hasOwn(policy,key),false);
  }
  policy[key]=structuredClone(patch.value);
}
assert.equal(policy.unsupportedReason,'multiple-path-constraints');
assert.deepEqual(policy.unsupportedReasons,reasonOrder);
assert.deepEqual(policy.rejectedPaths,[{algorithm:5,digestType:2,reasons:['operator-policy'],primaryReason:'operator-policy'},{algorithm:12,digestType:3,reasons:reasonOrder,primaryReason:'implementation-capability'}]);
assert.equal(policy.usedPathAlgorithm,13);assert.equal(policy.usedDsDigest,2);assert.equal(policy.obsoleteExtrasPoisonAnswer,false);
const merged=documents.get('worksheet.json');assert.equal(merged.lessons[13].planId,'DNS14');merged.lessons[13]=structuredClone(lesson);
const identities=document=>document.lessons.map(item=>({planId:item.planId,runtimeId:item.runtimeId,defaultCaseId:item.defaultCaseId,cases:item.cases.map(row=>({id:row.id,setup:row.setup,outcome:row.outcome}))}));
for(const [name,input] of originals)assert.deepEqual(identities(documents.get(name)),identities(input.value),'All setup/outcome/default identities unchanged: '+name);
assert.deepEqual(documents.get('worksheet-resolution.json'),originals.get('worksheet-resolution.json').value,'Resolution shard unchanged');
assert.equal(merged.lessons.length,22);assert.equal(merged.lessons.reduce((count,item)=>count+item.cases.length,0),159);
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.mixedPathPolicyErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposal:proposal.ref,audit:audit.ref,inputs:[freeze.ref,previousSeal.ref,proposal.ref,audit.ref,...[...originals.values()].map(input=>input.ref)].map(input=>({...input,effectivePath:input.path})),effectiveAddendum:{effectivePath:path.relative(root,path.join(out,'contract-addendum.json'))},productionExistedDuringCorrection:true,productionConsultedByIndependentAuthor:false,osSandboxEnforcementClaimed:false,originalAndPriorEffectiveInputsRewritten:false};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-seventh-mixed-path-policy-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposal:proposal.ref,audit:audit.ref,priorLayersPreserved:proposal.value.priorLayersPreserved,sources:proposal.value.sources,independence:proposal.value.independence,productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:3,originalD0InputsVerified:354,priorEffectiveLayersVerified:6},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Exact reproduced mixed-path-policy overlay: '+name);
for(const input of [...originals.values(),freeze,previousSeal,proposal,audit])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
for(const input of [...pinned,...preserved])ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,outputs:refs}));
