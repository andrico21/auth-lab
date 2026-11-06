import test from 'node:test';
import assert from 'node:assert/strict';
import {PngExporter, pngStepSelection, pngExportFilename} from '../src/png-export.js';
import {capturePngSnapshot} from '../src/png-renderer.js';

// Controller boundaries only; real HTML/SVG rasterization and downloads are
// exercised in the browser. No DOM adapter is presented as pixel evidence.
function fixture() {
  const row = {id:'trace-row', sourceIndex:8, sourceStepId:'source-8'};
  const queue = {rows:[row],position:0,initial:false,empty:false,cursor:{eventIndex:8,milestone:'message',progress:.37},playerSnapshot:{status:'paused',kind:'attribute',stepElapsed:370}};
  const app = {labScenarioId:'selected-case',baseLabModel:{id:'canonical-scenario'},lessonVariant:'alternate',lessonSubfixture:null,presentationMode:'compact',theme:'light',
    runtimeEnvironment:{revision:4,draft:{issuer:'https://private.example/unchanged-draft'}},localizer:{revision:2,locale:'en'},heldView:{contextId:'context-4',actorId:'actor-a',selection:null},
    attributeSelection:'client_id',objectTraceSelection:null,player:{queue:queue.rows},steps:Array.from({length:10},(_,index)=>({id:'source-'+index})),
    studyQueue:()=>queue,querySelector:()=>null};
  let complete;
  const downloads = [], exporter = new PngExporter(app,{capture:()=>Object.freeze({captured:true}),encode:()=>new Promise(resolve=>{complete=resolve;}),download:(blob,filename)=>downloads.push({blob,filename})});
  return {app,queue,downloads,exporter,finish:()=>complete(new Blob(['encoded by browser in the smoke'],{type:'image/png'}))};
}
function state({app,queue}) {
  return {draft:structuredClone(app.runtimeEnvironment.draft),queue:app.player.queue,position:queue.position,elapsed:queue.playerSnapshot.stepElapsed,cursor:structuredClone(queue.cursor),view:app.presentationMode,variant:app.lessonVariant,field:app.attributeSelection};
}

test('only a genuine selected paused or completed row is exportable',()=>{
  const f=fixture();
  assert.equal(f.exporter.unavailable(),null);
  f.queue.initial=true;assert.equal(pngStepSelection(f.app),null);assert.equal(f.exporter.unavailable(),'no-step');
  f.queue.initial=false;f.queue.rows[0].sourceIndex=-1;assert.equal(f.exporter.unavailable(),'no-step');
  f.queue.rows[0].sourceIndex=8;f.queue.playerSnapshot.status='playing';assert.equal(f.exporter.unavailable(),'pause');
  f.queue.playerSnapshot.status='idle';assert.equal(f.exporter.unavailable(),'pause');
  f.queue.playerSnapshot.status='complete';assert.equal(f.exporter.unavailable(),null);
  f.queue.rows=[];f.queue.empty=true;assert.equal(f.exporter.unavailable(),'no-step');
});

test('a pending export suppresses duplicates and preserves exact study state on success',async()=>{
  const f=fixture(),before=state(f),pending=f.exporter.save();
  assert.equal(await f.exporter.save(),false);assert.equal(f.downloads.length,0);
  f.finish();assert.equal(await pending,true);assert.equal(f.downloads.length,1);
  assert.equal(f.downloads[0].filename,'auth-flow-studio-canonical-scenario-step-9.png');
  assert.deepEqual(state(f),before);assert.equal(f.exporter.job,null);assert.equal(f.exporter.notice,'requested');
});

for(const [name,change] of [
  ['presentation',f=>{f.app.presentationMode='full';}],
  ['case',f=>{f.app.lessonVariant='different-case';}],
  ['paused progress',f=>{f.queue.playerSnapshot.stepElapsed=371;}],
  ['locale',f=>{f.app.localizer.revision++;}],
  ['queue identity',f=>{f.app.player.queue=[...f.queue.rows];}],
])test('a changed '+name+' cancels the frozen export rather than mixing or restoring state',async()=>{
  const f=fixture(),pending=f.exporter.save();change(f);const changed=state(f);
  f.finish();assert.equal(await pending,false);assert.equal(f.downloads.length,0);assert.equal(f.exporter.notice,'canceled');
  assert.deepEqual(state(f),changed);assert.equal(f.exporter.job,null);
});

for(const [code,expected] of [['encoding','failed'],['size','too-large']])test(code+' failure releases the pending job without changing the study',async()=>{
  const f=fixture(),before=state(f);f.exporter.encode=async()=>{throw Object.assign(new Error('deliberate failure'),{code});};
  assert.equal(await f.exporter.save(),false);assert.equal(f.exporter.notice,expected);assert.equal(f.exporter.job,null);assert.equal(f.downloads.length,0);
  assert.deepEqual(state(f),before);assert.equal(f.exporter.unavailable(),null);
});

test('oversized raster dimensions fail before DOM traversal or canvas allocation',()=>{
  for(const dimensions of [{width:4097,height:10},{width:2048,height:2048}])assert.throws(()=>capturePngSnapshot(dimensions),error=>error.code==='size');
});

test('filenames contain only a bounded canonical component and source step, never path syntax',()=>{
  const filename=pngExportFilename('../unsafe?/\\'+'a'.repeat(1000),8);
  assert.match(filename,/^auth-flow-studio-[a-z0-9_-]+-step-9\.png$/i);
  assert.ok(filename.length<100);assert.doesNotMatch(filename,/[\\/?:]/);
});
