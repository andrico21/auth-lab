import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only data transform. Never import the application/evaluator or rewrite D0 inputs.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',out=path.resolve(root,args[1]||base+'/contract-errata/effective');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>JSON.stringify(sort(value));
function sort(value){
  if(Array.isArray(value))return value.map(sort);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])]));
  return value;
}
const json=value=>JSON.stringify(value,null,2)+'\n';
function load(relative){const bytes=fs.readFileSync(path.join(root,relative));return {value:JSON.parse(bytes),ref:{path:relative,bytes:bytes.length,sha256:sha(bytes)}};}
const freeze=load(base+'/contract-freeze.json');
assert.equal(freeze.ref.sha256,'b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19','Original D0 freeze remains unchanged');
const numeric=load(base+'/numeric/post-freeze-contract-errata/POST-FREEZE-CATALOG.json');
assert.equal(numeric.ref.sha256,'2c8c7a134e56714d09be1371c8b8cd6f90cb8dc1737fe381f78d59f0e53fa7c5','Independent post-freeze numeric catalog');
const manifest=load(base+'/scenario-manifest.json'),merged=load(base+'/worksheet.json');
const signature=worksheet=>worksheet.lessons.map(lesson=>({planId:lesson.planId,runtimeId:lesson.runtimeId,defaultCaseId:lesson.defaultCaseId,cases:lesson.cases.map(item=>item.id)}));
function parentAt(document,pointer){
  assert.ok(pointer.startsWith('/')&&pointer!=='/','Patch must address a concrete JSON member');
  const parts=pointer.slice(1).split('/').map(part=>part.replaceAll('~1','/').replaceAll('~0','~'));
  let parent=document;
  for(const part of parts.slice(0,-1)){assert.ok(parent&&typeof parent==='object'&&Object.hasOwn(parent,part),'Missing patch parent: '+pointer);parent=parent[part];}
  assert.ok(parent&&typeof parent==='object','Invalid patch parent: '+pointer);
  return {parent,key:parts.at(-1)};
}
const shards=[];
for(const name of ['resolution','publication']){
  const original=load(base+'/worksheet-'+name+'.json'),proposal=load(base+'/contract-errata/'+name+'-patches.json');
  assert.equal(original.ref.sha256,proposal.value.target.sha256,'Exact frozen '+name+' worksheet');
  assert.equal(original.ref.bytes,proposal.value.target.bytes);
  const corrected=structuredClone(original.value),findings=new Set();
  for(const patch of proposal.value.patches){
    assert.ok(['add','replace','remove'].includes(patch.op),'Unsupported patch operation');
    const {parent,key}=parentAt(corrected,patch.path),absent=patch.expectedBeforeAbsent===true||patch.expectedBeforeState==='absent';
    const present=Object.hasOwn(parent,key);
    if(absent)assert.equal(present,false,'Expected absent: '+patch.path);
    else{
      assert.equal(present,true,'Expected existing: '+patch.path);
      assert.deepEqual(parent[key],patch.expectedBefore,'Exact expected-before: '+patch.path);
      if(patch.expectedBeforeSha256)assert.equal(sha(canonical(parent[key])),patch.expectedBeforeSha256,'Expected-before canonical hash: '+patch.path);
    }
    if(patch.op!=='remove'){
      assert.ok(Object.hasOwn(patch,'value'),'Patch value is required');
      if(patch.valueSha256)assert.equal(sha(canonical(patch.value)),patch.valueSha256,'Final canonical hash: '+patch.path);
    }
    if(Array.isArray(parent)){
      const index=key==='-'?parent.length:Number(key);
      assert.ok(Number.isInteger(index)&&index>=0&&index<=parent.length,'Invalid array patch index');
      if(patch.op==='add')parent.splice(index,0,structuredClone(patch.value));
      else if(patch.op==='remove')parent.splice(index,1);
      else parent[index]=structuredClone(patch.value);
    }else if(patch.op==='remove')delete parent[key];
    else parent[key]=structuredClone(patch.value);
    findings.add(patch.finding);
  }
  assert.deepEqual(signature(corrected),signature(original.value),'Lesson, case and default identities remain unchanged');
  shards.push({name,original:original.ref,proposal:proposal.ref,worksheet:corrected,patchCount:proposal.value.patches.length,findings:[...findings]});
}
const byLesson=new Map(shards.flatMap(shard=>shard.worksheet.lessons).map(lesson=>[lesson.planId,lesson]));
const effective={...merged.value,lessons:merged.value.lessons.map(lesson=>{assert.ok(byLesson.has(lesson.planId),'Missing corrected lesson');return byLesson.get(lesson.planId);}),shards:shards.map(shard=>({original:shard.original,patches:shard.proposal,effectivePath:path.relative(root,path.join(out,'worksheet-'+shard.name+'.json'))})),contractErrata:{originalFreeze:freeze.ref,numericAddendum:numeric.ref,productionExistedDuringCorrection:true,productionConsultedByIndependentAuthors:false,originalInputsRewritten:false}};
assert.deepEqual(signature(effective),signature(merged.value),'Merged 22-lesson/159-case identities remain unchanged');
assert.equal(effective.lessons.length,22);assert.equal(effective.lessons.reduce((sum,lesson)=>sum+lesson.cases.length,0),159);
const outputs=new Map(shards.map(shard=>['worksheet-'+shard.name+'.json',json(shard.worksheet)]));outputs.set('worksheet.json',json(effective));
const refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:sha(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-contract-errata-addendum',originalFreeze:freeze.ref,numericAddendum:numeric.ref,manifest:manifest.ref,originalMergedWorksheet:merged.ref,independence:'The independent authors report that production existed but was not read, imported or executed. This transform reads only their patches and original authority documents.',productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:shards.reduce((sum,shard)=>sum+shard.patchCount,0)},shards:shards.map(({name,original,proposal,patchCount,findings})=>({name,original,proposal,patchCount,findings})),outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){
  fs.mkdirSync(out,{recursive:false});
  for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});
}else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Reproduced additive artifact: '+name);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,originalFreeze:freeze.ref.sha256,numericAddendum:numeric.ref.sha256,outputs:refs}));
