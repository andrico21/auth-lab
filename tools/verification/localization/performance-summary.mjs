#!/usr/bin/env bun
// Offline aggregation only: never launches a browser or changes retained inputs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {classifyPerformanceSamples, CONTRACT_PATH} from './performance-fixtures.mjs';

const filename=fileURLToPath(import.meta.url), repo=path.resolve(path.dirname(filename),'../../..');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const options={};
for(const arg of process.argv.slice(2)){
  const match=/^--(extended|focused|resources|approval|out)=(.+)$/.exec(arg);
  assert.ok(match&&!Object.hasOwn(options,match[1]),'Unique --extended=DIR --focused=DIR --resources=DIR --approval=JSON --out=NEW required');
  options[match[1]]=path.resolve(match[2]);
}
for(const key of ['extended','focused','resources','approval','out'])assert.ok(options[key],'Missing --'+key);
assert.ok(!fs.existsSync(options.out),'Output must be new');
const inputs=[], handles=new Map();
async function identity(file){
  const digest=createHash('sha256');let bytes=0;
  for await(const chunk of fs.createReadStream(file)){digest.update(chunk);bytes+=chunk.length;}
  return {path:file,bytes,sha256:digest.digest('hex')};
}
async function load(file){inputs.push(await identity(file));return JSON.parse(fs.readFileSync(file,'utf8'));}
function rawRecord(dir,ref){
  assert.ok(ref&&Number.isSafeInteger(ref.offset)&&ref.offset>=0&&Number.isSafeInteger(ref.bytes)&&ref.bytes>0);
  const file=path.resolve(dir,ref.path);assert.equal(path.dirname(file),dir,'Raw record must be within its producer directory');
  if(!handles.has(file))handles.set(file,fs.openSync(file,'r'));
  const bytes=Buffer.alloc(ref.bytes);let read=0;
  while(read<bytes.length){const n=fs.readSync(handles.get(file),bytes,read,bytes.length-read,ref.offset+read);assert.ok(n,'Truncated raw record');read+=n;}
  assert.equal(hash(bytes),ref.sha256,'Raw byte range SHA256');assert.equal(bytes.at(-1),10,'JSONL newline');
  return JSON.parse(bytes.toString('utf8'));
}
const approval=await load(options.approval), producers=[];
for(const role of ['extended','focused','resources']){
  const dir=options[role],plan=await load(path.join(dir,'plan.json')),report=await load(path.join(dir,'report.json'));
  producers.push({role,dir,plan,report});
}
const base=producers[0].plan;
for(const {plan} of producers){
  for(const arm of ['baseline','candidate'])for(const key of ['canonicalSha256','sourceFileCount','sourceAlgorithm','standalone','sources'])assert.deepEqual(plan.identities[arm][key],base.identities[arm][key],arm+'/'+key);
  for(const key of ['fixtures','contract','helper'])assert.deepEqual(plan.identities[key],base.identities[key],key+' identity');
  for(const key of ['fixtures','contract','cells','fieldProbes'])assert.deepEqual(plan[key],base[key],key+' frozen data');
}
assert.equal(base.identities.candidate.canonicalSha256,approval.canonicalSha256);
assert.deepEqual(base.identities.candidate.standalone,approval.standalone);
assert.equal((await identity(path.join(path.dirname(filename),'performance-fixtures.mjs'))).sha256,base.identities.fixtures.sha256);
assert.equal((await identity(path.join(repo,CONTRACT_PATH))).sha256,base.identities.contract.sha256);
// These are the retained producer epochs, not a restamping with the current collector.
const collectorEpochs={extended:'05783e3368c6f605bdcf3a4fd50fb8092e43b878edcd18cb9dfca39834ec4bbc',focused:'19f8c9566780eefb410680ffea53ea8ad9ea06c10e0eab848ab916f444ca454f',resources:'5f0f0da600b75e9d21c366a495a9814b67b423b4615545ae6d4278c71c1e3fec'};
for(const p of producers)assert.equal(p.plan.identities.collector.sha256,collectorEpochs[p.role],'Known scheduling/resource-capture producer epoch');
const timingRows=[], comparisons=[], completeCells=[], producerCounts=[];
let checkedTiming=0;
for(const p of producers.slice(0,2)){
  const rows=p.report.samples, cells=[...p.plan.cells,...p.plan.fieldProbes],complete=[];
  for(const cell of cells){
    const measured=rows.filter(r=>r.cell===cell.id&&!r.warmup);
    if(measured.length!==14||measured.some(r=>r.status!=='complete'))continue;
    const a=measured.filter(r=>cell.locale==='en'?r.rootName==='baseline':r.locale==='en'),b=measured.filter(r=>r.rootName==='candidate'&&r.locale===cell.locale);
    assert.equal(a.length,7);assert.equal(b.length,7);
    for(const group of [a,b])assert.deepEqual(group.map(r=>r.sample).sort((a,b)=>a-b),[0,1,2,3,4,5,6]);
    assert.ok(!completeCells.includes(cell.id),'No duplicate complete cell');complete.push(cell.id);completeCells.push(cell.id);
    for(const name of new Set(b.flatMap(r=>r.actions.map(x=>x.name)))){
      const samples=(group,operation=name)=>group.flatMap(r=>r.actions.filter(x=>x.name===operation).map(x=>x.latencyMs));
      const native=samples(b),control=cell.locale!=='en'&&['first-search','repeat-search'].includes(name)?[]:samples(a,name==='startup-saved-locale'?'startup-en':name);
      assert.equal(native.length,7);const kind=name.startsWith('startup')?'startup':'interaction';
      const stats=classifyPerformanceSamples({baseline:control.length===7?control:native,candidate:native,kind});
      const result={cell:cell.id,name,classification:p.plan.fixtures.find(f=>f.id===cell.fixtureId).classification,comparison:control.length===7?(cell.locale==='en'?'frozen-en/candidate-en':'candidate-en/native'):'candidate-only-feature-no-baseline',...stats};
      if(control.length!==7){delete result.baseline;delete result.materialRegression;}
      comparisons.push({...result,producer:p.role,actualSamples:{control,candidate:native}});
    }
  }
  for(let order=0;order<rows.length;order++){
    const summary=rows[order],raw=rawRecord(p.dir,summary.rawRecord);checkedTiming++;
    const projection=r=>({...r,actions:r.actions.map(({before,after,...action})=>action)});
    const {rawRecord:ref,...withoutRef}=summary;assert.deepEqual(projection(raw),withoutRef,'Raw timing matches producer summary');
    const {actions,evidence,...metadata}=raw;
    timingRows.push({...metadata,actions:actions.map(({before,after,...action})=>action),producer:p.role,producerRowOrder:order,rawRecord:ref,representation:'timing-only projection; not original state bytes',aggregation:raw.warmup?'EXCLUDED-WARMUP':complete.includes(raw.cell)?'AGGREGATED':'UNAGGREGATED'});
  }
  producerCounts.push({producer:p.role,completeCells:complete.length,completeMeasuredRows:rows.filter(r=>!r.warmup&&r.status==='complete').length,warmups:rows.filter(r=>r.warmup).length,failedMeasuredRows:rows.filter(r=>!r.warmup&&r.status==='failed').length,unaggregatedCompleteRows:timingRows.filter(r=>r.producer===p.role&&r.aggregation==='UNAGGREGATED'&&r.status==='complete').length});
  if(p.role==='focused')assert.deepEqual(comparisons.filter(r=>r.producer==='focused').map(({producer,actualSamples,...r})=>r),p.report.comparisons,'Existing focused comparisons unchanged');
}
const resources=producers[2].report.resources;let checkedCheckpoints=0,trustedEvents=0;
for(const resource of resources)for(const checkpoint of resource.checkpoints){
  const raw=rawRecord(options.resources,checkpoint.rawRecord);assert.equal(raw.cell,resource.cell);assert.ok(raw.state&&typeof raw.state==='object','Full raw checkpoint state retained');
  const {state,browserEvents,cell,...diagnostics}=raw;const {rawRecord:ref,...summary}=checkpoint;
  assert.deepEqual(diagnostics,summary,'All checkpoint diagnostics match raw');assert.equal(browserEvents.length,raw.browserEventCount);
  assert.ok(browserEvents.every(e=>e.trusted===true),'Trusted events');trustedEvents+=browserEvents.length;checkedCheckpoints++;
}
for(const fd of handles.values())fs.closeSync(fd);
const localOnly=[];
for(const p of producers)for(const name of ['samples.jsonl','warmups.jsonl','resource-checkpoints.jsonl']){
  const file=path.join(p.dir,name);if(fs.existsSync(file))localOnly.push({...await identity(file),producer:p.role,distribution:'LOCAL ONLY - original full state/raw stream retained unchanged'});
}
const required=approval.requiredRepresentativeCells.map(cell=>({cell,complete:completeCells.includes(cell)}));
assert.equal(completeCells.length,104);assert.equal(required.length,18);assert.ok(required.every(r=>r.complete));
assert.equal(resources.length,2);assert.deepEqual(resources.map(r=>r.cell),approval.remainingResourceCells);assert.equal(checkedCheckpoints,170);assert.equal(trustedEvents,679);
assert.deepEqual(producerCounts.map(r=>r.completeCells),[100,4]);assert.equal(producerCounts[0].unaggregatedCompleteRows,13);
const timingFlags=comparisons.filter(r=>r.materialRegression||r.candidateOrdinaryTargetMiss||r.candidate.variation||r.baseline?.variation).map(r=>({...r,disposition:'open-unaccepted-unwaived'}));
const resourceFlags=producers[2].report.flags.map(r=>({...r,producer:'resources',disposition:'open-unaccepted-unwaived'}));
assert.equal(timingFlags.filter(r=>r.producer==='focused').length,36);assert.equal(resourceFlags.length,2);
const matrix=[...base.cells,...base.fieldProbes];assert.equal(matrix.length,240);
const report={schemaVersion:1,kind:'offline-focused-performance-summary',status:'complete-approved-selected-scope-with-open-observations',approval:false,waiver:false,noLeakClaim:false,
 qualification:'Owner authorized scope only. No blanket Native or human performance acceptance. Positive qualified heap is diagnostic, not proof of leak. No outlier removal, language averaging, threshold changes or waivers.',
 runner:{path:path.relative(repo,filename),runnerSha256:(await identity(filename)).sha256,argv:process.argv,environment:Object.fromEntries(['PATH','HOME','TMPDIR','BUN_TMPDIR','BUN_INSTALL_AUTO','BUN_BE_BUN','LANG','TZ'].map(k=>[k,process.env[k]]))},sourceInputDigests:inputs,
 identities:base.identities,producerScopes:producers.map(p=>({producer:p.role,originalStatus:p.report.status,collector:p.plan.identities.collector,selectedCellIds:p.plan.selectedCellIds||null,argv:p.report.argv,errors:p.report.errors,method:p.report.method,inheritedOpenConditions:p.report.inheritedOpenConditions,scope:p.role==='extended'?'Owner-cancelled exhaustive run; completed cells retained; final cancellation failure not product failure':'Completed selected scope only'})),
 collectorDifferences:'Original known collector epochs retained; focused scheduling/selection and streamed resource capture only. Fixture, contract, helper and runtime source identities are not replaced by current collector identities.',
 counts:{completeTimingCells:104,requiredTimingCells:18,requiredCovered:18,resourceCells:2,fullTimingCells:240,unperformedOwnerDeferredTimingCells:136,fullResourceCells:210,unperformedOwnerDeferredResourceCells:208,checkedTimingRawRecords:checkedTiming,checkedRawCheckpoints:checkedCheckpoints,trustedEvents,producerCounts,timingComparisons:comparisons.length,timingFlags:timingFlags.length,resourceFlags:resourceFlags.length,totalFlags:timingFlags.length+resourceFlags.length},
 completeCells,requiredCoverage:required,unperformedTimingCells:matrix.filter(c=>!completeCells.includes(c.id)).map(c=>({cell:c.id,status:'owner-deferred-unperformed-not-passed'})),unperformedResourceCells:matrix.filter(c=>c.locale!=='en'&&!resources.some(r=>r.cell===c.id)).map(c=>({cell:c.id,status:'owner-deferred-unperformed-not-passed'})),comparisons,flags:[...timingFlags,...resourceFlags],resources,localOnly,
 timingProjection:'samples.jsonl and warmups.jsonl preserve all recorded timing values and original row/action ordering, including unaggregated partial/failed rows. Original canonical state arrays and full raw bytes remain LOCAL ONLY and SHA-bound above.'};
assert.equal(report.unperformedResourceCells.length,208);
fs.mkdirSync(options.out);
const save=(name,value)=>fs.writeFileSync(path.join(options.out,name),JSON.stringify(value,null,2)+'\n');
for(const warmup of [false,true])fs.writeFileSync(path.join(options.out,warmup?'warmups.jsonl':'samples.jsonl'),timingRows.filter(r=>r.warmup===warmup).map(r=>JSON.stringify(r)+'\n').join(''));
save('report.json',report);
save('invocation.json',{...report.runner,exitCode:0,aggregationOnly:true,outputs:await Promise.all(['report.json','samples.jsonl','warmups.jsonl'].map(name=>identity(path.join(options.out,name))))});
console.log(JSON.stringify({status:report.status,out:options.out,...report.counts}));
