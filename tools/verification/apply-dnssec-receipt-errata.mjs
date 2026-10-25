import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only input transform. No production, evaluator or public-fixture imports.
// D0, v1 and v2 stay byte-immutable; independent exact patches produce a new overlay.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-completion';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-receipts');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sort=value=>Array.isArray(value)?value.map(sort):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;
const canonical=value=>JSON.stringify(sort(value));
const json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,expected,expectedBytes){
  const bytes=fs.readFileSync(path.join(root,relative));
  const value={path:relative,bytes:bytes.length,sha256:hash(bytes)};
  if(expected)assert.equal(value.sha256,expected,'Exact immutable input: '+relative);
  if(expectedBytes!==undefined)assert.equal(value.bytes,expectedBytes,'Exact immutable input size: '+relative);
  return value;
}
function load(relative,expected,expectedBytes){
  const identity=ref(relative,expected,expectedBytes);
  return {value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8')),ref:identity};
}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19');
const manifest=load(base+'/scenario-manifest.json');
const previousSeal=load(prior+'/contract-addendum.json','06ec9dc1d179634f88cbcbadc70df57c4d6fe9164503c52c6052ec52153b72c6');
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','72424f5380942d2bba570fe0fceca8c5e234e4bd64372d4cd2ac751a77e30656')],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','34ca3c3b55829e3402299a125f408ef0a74609f1c223e23cc834d1c0393dd332')],
  ['worksheet.json',load(prior+'/worksheet.json','d1f319e715da522e5a64e564514e1b6791486cb276394ebb380ca6e42c895bbc')]
]);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=load(base+'/contract-errata/receipt-resolution-erratum.json','300253a62a155a99c0cddfdc1762d946bb89d86917e06775a566d6e32f247d19');
const wildcard=load(base+'/contract-errata/receipt-wildcard-erratum.json','472cd3e4dedc1415ae70173ccfb43467d82d4a1b0a71c72d5dcfea9a99479408');
const publication=load(base+'/contract-errata/receipt-publication-erratum.json','5bce74baeded4d4e03bccf7ef5526f839226433e0c172ae0167930c3ac8cb17c');
const proposals=[resolution,wildcard,publication];
const preservedInputs=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));
assert.equal(preservedInputs.length,354,'Entire original D0 input set');
for(const proposal of [resolution,wildcard]){
  const target=proposal.value.target,original=originals.get('worksheet-resolution.json').ref;
  assert.equal(target.path,original.path);assert.equal(target.sha256,original.sha256);assert.equal(target.bytes,original.bytes);
  assert.equal(target.lessons,13);assert.equal(target.cases,93);
}
assert.equal(publication.value.target.effectivePath,originals.get('worksheet-publication.json').ref.path);
assert.equal(publication.value.target.effectiveSha256,originals.get('worksheet-publication.json').ref.sha256);
assert.equal(publication.value.target.effectiveBytes,originals.get('worksheet-publication.json').ref.bytes);
assert.equal(publication.value.target.mergedSha256,originals.get('worksheet.json').ref.sha256);
assert.equal(publication.value.target.originalFreezeSha256,freeze.ref.sha256);
function parentAt(document,pointer){
  assert.ok(pointer.startsWith('/')&&pointer!=='/','Patch addresses a concrete JSON member');
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
  assert.ok(['add','replace','remove'].includes(patch.op),'Supported patch operation');
  const {parent,key}=parentAt(document,patch.path);
  const absent=patch.expectedBeforeAbsent===true||patch.expectedBeforeState==='absent';
  if(absent){
    // JSON Patch array additions address an insertion gap, not an existing member.
    // The target's sealed bytes and ordered prior patches bind the whole input array.
    if(!Array.isArray(parent)||patch.op!=='add')assert.equal(Object.hasOwn(parent,key),false,'Expected absent: '+patch.path);
  }else{
    assert.ok(Object.hasOwn(parent,key),'Expected existing: '+patch.path);
    assert.deepEqual(parent[key],patch.expectedBefore,'Exact expected-before: '+patch.path);
    const expectedHash=patch.expectedBeforeCanonicalSha256||patch.expectedBeforeSha256;
    if(expectedHash)assert.equal(hash(canonical(parent[key])),expectedHash,'Expected-before canonical hash: '+patch.path);
  }
  if(patch.op!=='remove'){
    assert.ok(Object.hasOwn(patch,'value'),'Patch value required');
    const valueHash=patch.valueCanonicalSha256||patch.valueSha256;
    if(valueHash)assert.equal(hash(canonical(patch.value)),valueHash,'Final canonical hash: '+patch.path);
  }
  if(Array.isArray(parent)){
    const index=key==='-'?parent.length:Number(key);
    assert.ok(Number.isInteger(index)&&index>=0&&index<=parent.length,'Valid array index');
    if(patch.op==='add')parent.splice(index,0,structuredClone(patch.value));
    else if(patch.op==='remove')parent.splice(index,1);
    else parent[index]=structuredClone(patch.value);
  }else if(patch.op==='remove')delete parent[key];
  else parent[key]=structuredClone(patch.value);
  applied++;
}
function applyProposal(proposal,target){
  if(proposal.value.patchCount!==undefined)assert.equal(proposal.value.patchCount,proposal.value.patches.length,'Declared proposal patch count');
  for(const [index,patch] of proposal.value.patches.entries()){
    assert.equal(patch.order,index+1,'Explicit ordered patch');
    if(patch.target)assert.equal(patch.target,originals.get(target).ref.path,'Exact declared patch target');
    apply(documents.get(target),patch);
  }
}
applyProposal(resolution,'worksheet-resolution.json');
applyProposal(wildcard,'worksheet-resolution.json');
applyProposal(publication,'worksheet-publication.json');
const merged=documents.get('worksheet.json');
const byLesson=new Map(['worksheet-resolution.json','worksheet-publication.json'].flatMap(name=>documents.get(name).lessons).map(lesson=>[lesson.planId,lesson]));
merged.lessons=merged.lessons.map(lesson=>{assert.ok(byLesson.has(lesson.planId),'No missing lesson');return byLesson.get(lesson.planId);});
for(const key of ['typedRoots','chainTargetSemantics']){
  assert.ok(Object.hasOwn(documents.get('worksheet-resolution.json'),key),'Independent typed root');
  assert.equal(Object.hasOwn(merged,key),false,'No silent replacement of merged typed root');
  merged[key]=structuredClone(documents.get('worksheet-resolution.json')[key]);
}
// Core dispositions remain fixed; receipt/header metadata changes only through exact patches.
const identities=document=>document.lessons.map(lesson=>({planId:lesson.planId,runtimeId:lesson.runtimeId,defaultCaseId:lesson.defaultCaseId,cases:lesson.cases.map(item=>({id:item.id,securityStatus:item.outcome.securityStatus,applicationResult:item.outcome.applicationResult,acceptedForUse:item.outcome.acceptedForUse,cached:item.outcome.cached}))}));
for(const [name,input] of originals)assert.deepEqual(identities(documents.get(name)),identities(input.value),'Preserve all case/default identities and core dispositions: '+name);
assert.equal(merged.lessons.length,22);
assert.equal(merged.lessons.reduce((sum,lesson)=>sum+lesson.cases.length,0),159);
assert.equal(applied,244,'159 resolution + 14 wildcard + 71 publication exact patches');
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.receiptErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposals:proposals.map(input=>input.ref),productionExistedDuringCorrection:true,productionConsultedByIndependentAuthors:false,originalAndPriorEffectiveInputsRewritten:false};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)]));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-receipt-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,manifest:manifest.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposals:proposals.map(input=>input.ref),independence:'Independent authors report no production source/evaluator access or execution. This data transform imports neither and reads exact proposed patches and immutable authority inputs only.',productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:applied,originalD0InputsVerified:preservedInputs.length},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});
  for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Reproduced receipt overlay: '+name);
for(const input of [...originals.values(),freeze,manifest,previousSeal,...proposals])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
for(const input of preservedInputs)ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,originalFreeze:freeze.ref.sha256,outputs:refs}));
