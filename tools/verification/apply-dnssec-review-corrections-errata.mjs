import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only authority transform. No application, tests or evaluator imports.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-cache-kind';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-review-corrections');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,sha256,bytes){
  const data=fs.readFileSync(path.join(root,relative)),identity={path:relative,bytes:data.length,sha256:hash(data)};
  if(sha256)assert.equal(identity.sha256,sha256,'Exact immutable input: '+relative);
  if(bytes!==undefined)assert.equal(identity.bytes,bytes,'Exact immutable size: '+relative);
  return identity;
}
function load(relative,sha256,bytes){return {ref:ref(relative,sha256,bytes),value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'))};}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19',68646);
const manifest=load(base+'/scenario-manifest.json','dc65e951a869d24e62b8d36e4ec8885da8e484d991a15d98367ea96c893b8574',28215);
const previousSeal=load(prior+'/contract-addendum.json','f500a7278bac53f72b9cf5c43927601c2b4d7aefd2f5e81fc2887d4f6ec5a4f3',2948);
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','4f3b6901297359a58f10cd87785afeb6d047e3a7906728cd171dee234a4bfc89',5664202)],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','4152649110d465de7a562a83bc97814c3a84dbd042ce3c70ff1ac777e152ad09',1122685)],
  ['worksheet.json',load(prior+'/worksheet.json','330fbc0db84e21e116d78da6ea316fb4694cd16d40c73f13a8c49f7a0100c055',6705865)]
]);
const proposal=load(base+'/contract-errata/review-corrections-proposal.json','dbc72e7bf7dcacfa10b6a412e9fcc7d1661302f4accd1ff2175c195776c741db',57786);
const audit=load(base+'/contract-errata/review-corrections-audit.json','48dc09275e9f8bcc221af83dec960d19552ace5c1520aa891ecbdb10e6c2a0fb',33720);
assert.deepEqual(proposal.value.originalFreeze,freeze.ref);
assert.deepEqual(proposal.value.previousAddendum,previousSeal.ref);
assert.deepEqual(proposal.value.targets,[...originals.values()].map(input=>input.ref));
assert.deepEqual(proposal.value.audit,audit.ref);
assert.equal(proposal.value.patchCount,30);assert.equal(proposal.value.patches.length,30);
assert.equal(proposal.value.independence.applicationSourceRead,false);
assert.equal(proposal.value.independence.productionEvaluatorExecuted,false);
assert.equal(proposal.value.independence.osSandboxEnforcementClaimed,false);
const pinned=[proposal.value.review,...proposal.value.sources,...proposal.value.priorLayersPreserved,...audit.value.consultedFiles];
for(const input of pinned)ref(input.path,input.sha256,input.bytes);
assert.equal(proposal.value.priorLayersPreserved.length,20,'All five prior worksheet/seal layers');
const preserved=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));assert.equal(preserved.length,354);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=documents.get('worksheet-resolution.json'),publication=documents.get('worksheet-publication.json');
function location(document,pointer){
  assert.ok(pointer.startsWith('/')&&!pointer.includes('~'),'Only exact literal worksheet pointers');
  const keys=pointer.slice(1).split('/');let parent=document;
  for(const key of keys.slice(0,-1)){
    assert.ok(Object.hasOwn(parent,key),'Existing parent at '+pointer);parent=parent[key];
  }
  return {parent,key:keys.at(-1)};
}
for(const [index,patch] of proposal.value.patches.entries()){
  assert.equal(patch.order,index+1);assert.ok(patch.shard==='resolution'||patch.shard==='publication');
  assert.ok(patch.sources.length>0&&patch.finding.length>0,'Per-patch independent provenance');
  const document=patch.shard==='resolution'?resolution:publication,{parent,key}=location(document,patch.path);
  assert.equal(hash(JSON.stringify(patch.value)),patch.valueCanonicalSha256,'Exact after value at '+patch.path);
  if(patch.op==='replace'){
    assert.ok(Object.hasOwn(parent,key),'Existing before value at '+patch.path);
    assert.deepEqual(parent[key],patch.expectedBefore,'Exact before value at '+patch.path);
    assert.equal(hash(JSON.stringify(parent[key])),patch.expectedBeforeCanonicalSha256,'Exact before hash at '+patch.path);
  }else{
    assert.equal(patch.op,'add');assert.equal(patch.expectedBeforeAbsent,true);assert.equal(Object.hasOwn(parent,key),false,'Absent before addition at '+patch.path);
  }
  parent[key]=structuredClone(patch.value);
}
const merged=documents.get('worksheet.json');
for(const document of [resolution,publication])for(const lesson of document.lessons){
  const index=merged.lessons.findIndex(item=>item.planId===lesson.planId);assert.ok(index>=0);merged.lessons[index]=structuredClone(lesson);
}
const identities=document=>document.lessons.map(lesson=>({planId:lesson.planId,runtimeId:lesson.runtimeId,defaultCaseId:lesson.defaultCaseId,cases:lesson.cases.map(row=>({id:row.id,outcome:row.outcome}))}));
for(const [name,input] of originals){
  const document=documents.get(name);assert.deepEqual(identities(document),identities(input.value),'All case/default/outcome identities unchanged: '+name);
  for(const [li,lesson] of document.lessons.entries())for(const [ci,row] of lesson.cases.entries()){
    const before=input.value.lessons[li].cases[ci];
    for(const field of ['rrsets','keys','keyBindings','numericBindings','evidenceBindingIndex'])assert.deepEqual(row.setup[field],before.setup[field],'Existing public numeric declarations unchanged: '+name+'/'+lesson.planId+'/'+row.id+'/'+field);
  }
}
assert.equal(merged.lessons.length,22);assert.equal(merged.lessons.reduce((count,lesson)=>count+lesson.cases.length,0),159);
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.reviewCorrectionsErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposal:proposal.ref,audit:audit.ref,inputs:[freeze.ref,previousSeal.ref,proposal.ref,audit.ref,...[...originals.values()].map(input=>input.ref)].map(input=>({...input,effectivePath:input.path})),effectiveAddendum:{effectivePath:path.relative(root,path.join(out,'contract-addendum.json'))},findings:['DNS-R01','DNS-R03','DNS-R05','DNS-R06'],productionExistedDuringCorrection:true,productionConsultedByIndependentAuthor:false,osSandboxEnforcementClaimed:false,originalAndPriorEffectiveInputsRewritten:false};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-sixth-review-corrections-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,manifest:manifest.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposal:proposal.ref,audit:audit.ref,priorLayersPreserved:proposal.value.priorLayersPreserved,sources:proposal.value.sources,independence:proposal.value.independence,productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:30,originalD0InputsVerified:354,priorEffectiveLayersVerified:5},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Exact reproduced review-corrections overlay: '+name);
for(const input of [...originals.values(),freeze,manifest,previousSeal,proposal,audit])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
for(const input of [...pinned,...preserved])ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,outputs:refs}));
