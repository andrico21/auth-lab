import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only data transform. The original D0 and first derived overlay stay immutable.
// Never import production models, evaluators or generated application material here.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-completion');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sort=value=>Array.isArray(value)?value.map(sort):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;
const canonical=value=>JSON.stringify(sort(value));
const json=value=>JSON.stringify(value,null,2)+'\n';
function load(relative,expected){
  const bytes=fs.readFileSync(path.join(root,relative));
  const ref={path:relative,bytes:bytes.length,sha256:hash(bytes)};
  if(expected)assert.equal(ref.sha256,expected,'Exact immutable input: '+relative);
  return {value:JSON.parse(bytes),ref};
}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19');
const manifest=load(base+'/scenario-manifest.json');
const previousSeal=load(prior+'/contract-addendum.json','a7b0013612ed44da1fda94360d99ab1a9c365f6fb17f95d6bf92a7c85367cb56');
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','cf2baaaa75c7d894ac61b492582e1b10ea06a2e7860d2fa1754404b2fafe3cb1')],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','b37c001fc0a866c39bb19da9e5c0e3696d49202d06d0be08fcd7b212ee831cac')],
  ['worksheet.json',load(prior+'/worksheet.json','cee8806fbec443618158d75f971a20662f389d30564e2065d3712e75cb6fd8a1')]
]);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=load(base+'/contract-errata/completion-resolution-erratum.json','422bca3acab66f5f7628e727001d48b9653313da05c3c8b249c9fb3c43008edf');
const publication=load(base+'/contract-errata/completion-publication-erratum.json','0109712f2dba9d2ffe714f7da6c29f9549ca04a7796a69ee511b867995f0e5b0');
for(const target of Object.values(resolution.value.targets)){
  const actual=load(target.path,target.sha256);
  if(target.bytes!==undefined)assert.equal(actual.ref.bytes,target.bytes,'Exact target byte count');
}
assert.equal(publication.value.target.effectiveSha256,originals.get('worksheet-publication.json').ref.sha256);
assert.equal(publication.value.target.originalFreezeSha256,freeze.ref.sha256);
for(const ref of Object.values(publication.value.evidenceHashes))if(ref?.path&&ref.sha256){
  assert.equal(hash(fs.readFileSync(path.join(root,ref.path))),ref.sha256,'Exact raw numerical/source evidence: '+ref.path);
}
function parentAt(document,pointer){
  assert.ok(pointer.startsWith('/')&&pointer!=='/','A patch addresses a concrete JSON member');
  const parts=pointer.slice(1).split('/').map(part=>part.replaceAll('~1','/').replaceAll('~0','~'));
  let parent=document;
  for(const part of parts.slice(0,-1)){
    assert.ok(parent&&typeof parent==='object'&&Object.hasOwn(parent,part),'Missing patch parent: '+pointer);
    parent=parent[part];
  }
  assert.ok(parent&&typeof parent==='object','Invalid patch parent: '+pointer);
  return {parent,key:parts.at(-1)};
}
let applied=0;
function apply(document,patch){
  assert.ok(['add','replace','remove'].includes(patch.op),'Unsupported patch operation');
  const {parent,key}=parentAt(document,patch.path);
  const absent=patch.expectedBeforeAbsent===true||patch.expectedBeforeState==='absent';
  if(absent)assert.equal(Object.hasOwn(parent,key),false,'Expected absent: '+patch.path);
  else{
    assert.ok(Object.hasOwn(parent,key),'Expected existing: '+patch.path);
    assert.deepEqual(parent[key],patch.expectedBefore,'Exact expected-before: '+patch.path);
    const expectedHash=patch.expectedBeforeCanonicalSha256||patch.expectedBeforeSha256;
    if(expectedHash)assert.equal(hash(canonical(parent[key])),expectedHash,'Expected-before canonical hash');
  }
  if(patch.op!=='remove'){
    assert.ok(Object.hasOwn(patch,'value'),'Patch value is required');
    const valueHash=patch.valueCanonicalSha256||patch.valueSha256;
    if(valueHash)assert.equal(hash(canonical(patch.value)),valueHash,'Final canonical hash');
  }
  if(Array.isArray(parent)){
    const index=key==='-'?parent.length:Number(key);
    assert.ok(Number.isInteger(index)&&index>=0&&index<=parent.length,'Invalid array index');
    if(patch.op==='add')parent.splice(index,0,structuredClone(patch.value));
    else if(patch.op==='remove')parent.splice(index,1);
    else parent[index]=structuredClone(patch.value);
  }else if(patch.op==='remove')delete parent[key];
  else parent[key]=structuredClone(patch.value);
  applied++;
}
for(const patch of resolution.value.patches){
  assert.ok(documents.has(patch.file),'Exact declared patch target');
  apply(documents.get(patch.file),patch);
}
// Resolution patches explicitly cover both the shard and merged document; verify that they agree.
const merged=documents.get('worksheet.json');
for(const lesson of documents.get('worksheet-resolution.json').lessons){
  assert.deepEqual(merged.lessons.find(item=>item.planId===lesson.planId),lesson,'Resolution merged/shard consistency');
}
for(const patch of publication.value.patches)apply(documents.get('worksheet-publication.json'),patch);
const byLesson=new Map(['worksheet-resolution.json','worksheet-publication.json'].flatMap(name=>documents.get(name).lessons).map(lesson=>[lesson.planId,lesson]));
merged.lessons=merged.lessons.map(lesson=>{assert.ok(byLesson.has(lesson.planId),'No missing lesson');return byLesson.get(lesson.planId);});
const identities=document=>document.lessons.map(lesson=>({planId:lesson.planId,runtimeId:lesson.runtimeId,defaultCaseId:lesson.defaultCaseId,cases:lesson.cases.map(item=>item.id)}));
for(const [name,input] of originals)assert.deepEqual(identities(documents.get(name)),identities(input.value),'No changed lesson/case/default identity: '+name);
assert.equal(merged.lessons.length,22);
assert.equal(merged.lessons.reduce((sum,lesson)=>sum+lesson.cases.length,0),159);
assert.equal(applied,resolution.value.patches.length+publication.value.patches.length);
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.completionErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposals:[resolution.ref,publication.ref],productionExistedDuringCorrection:true,productionConsultedByIndependentAuthors:false,originalAndPriorEffectiveInputsRewritten:false};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-completion-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,manifest:manifest.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposals:[resolution.ref,publication.ref],independence:'Authors report no production source/evaluator access or execution. This transform imports neither and reads only independently proposed exact data patches and immutable authority inputs.',productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:applied},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});
  for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Reproduced completion overlay: '+name);
for(const input of [...originals.values(),freeze,previousSeal,resolution,publication])load(input.ref.path,input.ref.sha256);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,originalFreeze:freeze.ref.sha256,outputs:refs}));
