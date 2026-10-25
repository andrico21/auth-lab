import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Verification-only exact input correction; never imports application/evaluator code.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2),mode=args[0];
assert.ok(mode==='--emit'||mode==='--check','Use --emit [new-output-directory] or --check [output-directory]');
assert.ok(args.length<=2,'Unexpected arguments');
const base='docs/dnssec-expansion',prior=base+'/contract-errata/effective-client-context';
const out=path.resolve(root,args[1]||base+'/contract-errata/effective-cache-kind');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),json=value=>JSON.stringify(value,null,2)+'\n';
function ref(relative,sha256,bytes){
  const data=fs.readFileSync(path.join(root,relative)),identity={path:relative,bytes:data.length,sha256:hash(data)};
  if(sha256)assert.equal(identity.sha256,sha256,'Exact immutable input: '+relative);
  if(bytes!==undefined)assert.equal(identity.bytes,bytes,'Exact immutable size: '+relative);
  return identity;
}
function load(relative,sha256,bytes){return {ref:ref(relative,sha256,bytes),value:JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'))};}
const freeze=load(base+'/contract-freeze.json','b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19');
const manifest=load(base+'/scenario-manifest.json');
const previousSeal=load(prior+'/contract-addendum.json','3a0bad331b33f2fe45f01832a1029c8b5064a6aec638ddda5761b8d9c0e1a4bb',2857);
const originals=new Map([
  ['worksheet-resolution.json',load(prior+'/worksheet-resolution.json','03c39153f73dffa9c28fca61adde906eeb440af9198f48798df65c2e6f3b5796',5664204)],
  ['worksheet-publication.json',load(prior+'/worksheet-publication.json','4152649110d465de7a562a83bc97814c3a84dbd042ce3c70ff1ac777e152ad09',1122685)],
  ['worksheet.json',load(prior+'/worksheet.json','c7fc1efdd3b0e011499da4cf3bd19e2ae95b21885a1ac4975d6458646d0c77bc',6702212)]
]);
const proposal=load(base+'/contract-errata/cache-kind-erratum.json','f4d6052bf2278b62656638f58dcff78a2ac9bce71d0e8b8b3741bc196e4e264b',2798);
const audit=ref(proposal.value.audit.path,'05de219f4a6cbfcafefca670ada9f10386f5ba46c34a19a8daff72b4c7bfac93',1883);
assert.deepEqual(proposal.value.target,originals.get('worksheet-resolution.json').ref);
assert.deepEqual(proposal.value.mergedTarget,originals.get('worksheet.json').ref);
assert.deepEqual(proposal.value.previousAddendum,previousSeal.ref);
assert.equal(proposal.value.patchCount,1);assert.equal(proposal.value.patches.length,1);
const preserved=freeze.value.inputs.map(input=>ref(input.path,input.sha256,input.bytes));assert.equal(preserved.length,354);
const documents=new Map([...originals].map(([name,input])=>[name,structuredClone(input.value)]));
const resolution=documents.get('worksheet-resolution.json'),lesson=resolution.lessons[10],selected=lesson.cases[5],patch=proposal.value.patches[0];
assert.equal(lesson.planId,'DNS20');assert.equal(selected.id,'retry-after-expiry');
assert.equal(patch.order,1);assert.equal(patch.op,'replace');assert.equal(patch.path,'/lessons/10/cases/5/checkpoints/2/expected/cacheEntries/0/kind');
assert.equal(patch.expectedBefore,'positive');assert.equal(patch.value,'answer');
assert.equal(selected.checkpoints[2].name,'new-work-required-after-expiry');
const observed=selected.checkpoints[2].expected.cacheEntries[0],accepted=selected.checkpoints.find(point=>point.name==='accepted-use-and-cache-boundary').expected.cacheEntries[0];
assert.equal(observed.kind,patch.expectedBefore);assert.equal(accepted.kind,patch.value);
assert.equal(observed.generation,2);assert.equal(observed.receivedAt,1792713606);assert.equal(observed.expiresAt,1792713906);
assert.equal(accepted.receivedAt,observed.receivedAt);assert.equal(accepted.expiresAt,observed.expiresAt);
assert.equal(hash(JSON.stringify(observed.kind)),patch.expectedBeforeCanonicalSha256);assert.equal(hash(JSON.stringify(patch.value)),patch.valueCanonicalSha256);
observed.kind=patch.value;
const merged=documents.get('worksheet.json');merged.lessons=merged.lessons.map(item=>item.planId==='DNS20'?lesson:item);
const dispositions=document=>document.lessons.map(item=>({planId:item.planId,runtimeId:item.runtimeId,defaultCaseId:item.defaultCaseId,cases:item.cases.map(row=>({id:row.id,setup:row.setup,outcome:row.outcome}))}));
for(const [name,input] of originals)assert.deepEqual(dispositions(documents.get(name)),dispositions(input.value),'All setup/outcome/default identities unchanged: '+name);
assert.equal(merged.lessons.length,22);assert.equal(merged.lessons.reduce((count,item)=>count+item.cases.length,0),159);
assert.deepEqual(documents.get('worksheet-publication.json'),originals.get('worksheet-publication.json').value,'Publication input unchanged');
merged.shards=['resolution','publication'].map(name=>({previousEffective:originals.get('worksheet-'+name+'.json').ref,effectivePath:path.relative(root,path.join(out,'worksheet-'+name+'.json'))}));
merged.cacheKindErrata={originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,proposal:proposal.ref,audit,inputs:[freeze.ref,previousSeal.ref,proposal.ref,audit,...[...originals.values()].map(input=>input.ref)].map(input=>({...input,effectivePath:input.path})),effectiveAddendum:{effectivePath:path.relative(root,path.join(out,'contract-addendum.json'))},independentCasesScanned:159,productionExistedDuringCorrection:true,productionConsultedByIndependentAuthor:false,osSandboxEnforcementClaimed:false,originalAndPriorEffectiveInputsRewritten:false,allOutcomesAndGenerationReceiptDeadlineFactsUnchanged:true};
const outputs=new Map([...documents].map(([name,value])=>[name,json(value)])),refs=[...outputs].map(([name,text])=>({path:path.relative(root,path.join(out,name)),bytes:Buffer.byteLength(text),sha256:hash(text)}));
const seal={schemaVersion:1,kind:'dnssec-independent-cache-kind-contract-addendum',originalFreeze:freeze.ref,previousAddendum:previousSeal.ref,manifest:manifest.ref,previousWorksheets:[...originals.values()].map(input=>input.ref),proposal:proposal.ref,audit,independence:'Read-only all159-case input consistency audit reports no production/source/gate access. Transform imports neither application nor evaluator. No OS sandbox claim.',productionExistedDuringCorrection:true,claimsPreProductionAddendum:false,originalAndPriorEffectiveInputsRewritten:false,totals:{lessons:22,namedCases:159,patches:1,independentCasesScanned:159,originalD0InputsVerified:354},outputs:refs};
outputs.set('contract-addendum.json',json(seal));
if(mode==='--emit'){fs.mkdirSync(out,{recursive:false});for(const [name,text] of outputs)fs.writeFileSync(path.join(out,name),text,{flag:'wx'});}
else for(const [name,text] of outputs)assert.equal(fs.readFileSync(path.join(out,name),'utf8'),text,'Exact reproduced cache-kind overlay: '+name);
for(const input of [...originals.values(),freeze,manifest,previousSeal,proposal])ref(input.ref.path,input.ref.sha256,input.ref.bytes);
ref(audit.path,audit.sha256,audit.bytes);for(const input of preserved)ref(input.path,input.sha256,input.bytes);
console.log(JSON.stringify({result:mode==='--emit'?'emitted':'checked',output:path.relative(root,out),...seal.totals,outputs:refs}));
