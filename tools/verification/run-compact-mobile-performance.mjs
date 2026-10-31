#!/usr/bin/env bun
// Permanent serial collector. Compare timing never installs resource/profiler instrumentation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';
import {captureInputs, fileIdentity, sha256, launchBrowser, createStaticServer, createBrowserSession,
  settle, activate, studyState, assertClean, runtimeIdentity, LOAD_MODES,
  continuityProjection, armSwitchWitness, finishSwitchWitness} from './compact-mobile-browser.mjs';

const HELP = `Usage: bun tools/verification/run-compact-mobile-performance.mjs --mode=compare|profile|resource
  --baseline-root=PATH --candidate-root=PATH --baseline-source-sha256=HASH --candidate-source-sha256=HASH
  --baseline-html-sha256=HASH --candidate-html-sha256=HASH --fixtures=PATH --fixtures-sha256=HASH --out=NEW_DIRECTORY
Optional: --playwright-module=PATH --chromium-executable=PATH --library-path=PATH --retain-profiles=true
All arguments use =VALUE. Exactly seven measured serial samples and one separately retained warmup per arm/cell.
Fixtures must be frozen before collection. Compare has no CDP, event counters, profiling or resource instrumentation.
Resource/profile sessions never contribute latency. No installs, downloads, builds or concurrent collectors.
Exit 0: collection complete without current flags (not acceptance); 1: collection/input failure; 2: open current flags.
Outputs: compact-mobile-performance-status.json, report-schema.json, fixtures.json, inputs-before/after.json,
  samples.jsonl, warmups.jsonl, and optional bounded profiles. Failed attempts remain in their exclusive directory.`;
if (process.argv.includes('--help') || process.argv.includes('-h')) { console.log(HELP); process.exit(0); }
assert.ok(process.versions.bun,'Run with the provisioned Bun runtime; no Node toolchain is used');
const options = {}, allowed = new Set(['mode','baseline-root','candidate-root','baseline-source-sha256','candidate-source-sha256',
  'baseline-html-sha256','candidate-html-sha256','fixtures','fixtures-sha256','out','playwright-module','chromium-executable','library-path','retain-profiles']);
for (const arg of process.argv.slice(2)) {
  const m = /^--([^=]+)=(.+)$/.exec(arg); assert.ok(m && allowed.has(m[1]), 'Unknown argument: ' + arg + '\n' + HELP);
  assert.ok(!Object.hasOwn(options,m[1]), 'Duplicate argument'); options[m[1]] = m[2];
}
for (const name of ['mode','baseline-root','candidate-root','baseline-source-sha256','candidate-source-sha256','baseline-html-sha256','candidate-html-sha256','fixtures','fixtures-sha256','out']) assert.ok(options[name], 'Missing --' + name);
assert.ok(['compare','profile','resource'].includes(options.mode), 'Unknown mode');
for (const name of ['baseline-source-sha256','candidate-source-sha256','baseline-html-sha256','candidate-html-sha256','fixtures-sha256']) assert.match(options[name], /^[a-f0-9]{64}$/);
assert.ok(!options['retain-profiles'] || options['retain-profiles'] === 'true', 'Only explicit true retains profiles');
const roots = Object.fromEntries(['baseline','candidate'].map(name => [name, fs.realpathSync(options[name + '-root'])]));
const runner = fileURLToPath(import.meta.url), helper = path.join(path.dirname(runner),'compact-mobile-browser.mjs');
const fixturePath = fs.realpathSync(options.fixtures), out = path.resolve(options.out);
fs.mkdirSync(path.dirname(out), {recursive:true});
const realOut = path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
for (const root of Object.values(roots)) assert.ok(realOut !== root && !realOut.startsWith(root + path.sep), 'Evidence must be outside measured roots');
fs.mkdirSync(out); // Exclusive creation: never combine attempts or overwrite a previous failure.
const report = {schemaVersion:1,kind:'compact-mobile-performance',mode:options.mode,status:'collecting',startedAt:new Date().toISOString(),
  argv:[process.execPath,...process.argv.slice(1)],runtime:runtimeIdentity(),roots,identities:{},inputChecks:[],samples:[],warmups:[],comparisons:[],candidateActions:[],resources:[],profiles:[],files:[],errors:[],
  limits:[{id:'historical',status:'open',message:'All inherited startup/material/variation conditions and prior qualifications remain unaccepted and unwaived. Fresh candidate-07 runs do not clear frozen-baseline flags.'},
    {id:'devices',status:'unperformed',message:'Chromium desktop phone emulation is not an actual slower phone, iPhone/Safari or Android/Chrome task session.'},
    {id:'engines',status:'unperformed',message:'No WebKit or Firefox acceptance is supplied by this Chromium collector.'},
    {id:'human',status:'unperformed',message:'G01, VoiceOver/TalkBack speech and comprehension, mobile accessibility and overall release acceptance remain open.'},
    {id:'protocol',status:'unperformed',message:'No native Windows/DC or live protocol interoperability acceptance.'}],
  methods:{samples:7,warmups:1,order:'Alternating paired serial arms; fresh context per arm/cell/sample, one shared browser. No slow observations removed.',
    latency:'Host monotonic action-to-usable-result time including Playwright round trips and two animation frames. No CDP or execution wrappers in compare.',
    cache:'Empty context storage/cache, not cold OS caches. Equal strict request routing disables HTTP cache.',
    startup:'Actual source/emitted/file navigation, held player and picker, correct default lesson/cursor, visible working search/navigation/current content after layout. Index setup occurs after startup.',
    playingFilter:'Same trusted playing-filter action in both views. Compact intentionally pauses on search focus; Full preserves legacy playing behavior. Endpoints enforce that explicit presentation policy.',
    stateEvidence:'Full before/after states are asserted before packing, then retained losslessly as checksum-bound gzip JSON outside every timed interval. Readable summaries replace repeated source snapshots/queues with their exact hashes and source-row identities; no raw protocol field is dropped.',
    material:{relativeGreaterThan:0.25,startupAbsoluteGreaterThanMs:100,interactionAbsoluteGreaterThanMs:50},
    variation:'Range/median > 25% AND range > corresponding absolute threshold on either arm. Descriptive, not statistical significance.',
    newActions:{ordinaryMedianTargetMs:250,ordinaryMaximumTargetMs:500,large:'Predeclared large-history/payload fixtures reported separately; no invented baseline.'},
    resource:'Separate instrumented session; retained playing-switch warmup roundtrip, then 20 complete paused Compact-Full-Compact cycles from stable same-surface baseline; weak-reference counters, CDP DOM/heap, GC where supported. Not a blanket no-leak proof.',
    disposition:'Every flag retains data with disposition.status=open. Collection never infers a waiver or owner acceptance.'}};
const json = (name,value) => fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
const save = () => json('compact-mobile-performance-status.json',report);
const append = (name,value) => fs.appendFileSync(path.join(out,name),JSON.stringify(value)+'\n');
const errorText = error => String(error.stack || error);
const fail = (phase,error) => report.errors.push({phase,error:errorText(error)});
const disposition = () => ({status:'open',ownerAcceptance:false,message:'Requires explicit investigation/disposition; no inferred waiver.'});
const schema = {$schema:'https://json-schema.org/draft/2020-12/schema',title:'Compact mobile exact-input performance evidence',type:'object',
  required:['schemaVersion','kind','mode','status','identities','inputChecks','samples','warmups','comparisons','candidateActions','resources','profiles','errors','limits','methods'],
  not:{required:['passed']},properties:{schemaVersion:{const:1},kind:{const:'compact-mobile-performance'},mode:{enum:['compare','resource','profile']},
    status:{enum:['collecting','complete','failed']},exitCode:{enum:[0,1,2]},
    samples:{type:'array',items:{$ref:'#/$defs/sample'}},warmups:{type:'array',items:{$ref:'#/$defs/sample'}},comparisons:{type:'array'},candidateActions:{type:'array'},resources:{type:'array'},profiles:{type:'array'},
    measurementStatus:{enum:['incomplete','review-required','no-current-flags','diagnostic-only']}},
  allOf:[{if:{properties:{mode:{enum:['resource','profile']}}},then:{properties:{comparisons:{maxItems:0},candidateActions:{maxItems:0},samples:{items:{properties:{actions:{items:{not:{required:['latencyMs']}}}}}}}}}],
  $defs: {
    sample: {
      type: 'object',
      required: ['cell','arm','sample','warmup','status','actions'],
      properties: {
        status: {enum:['attempted','complete','failed']},
        actions: {
          type: 'array',
          items: {
            type: 'object',
            required: ['name','status','before'],
            properties: {
              status: {enum:['attempted','complete','failed']},
              latencyMs: {type:'number',minimum:0},
              before: {type:['object','null']},
              after: {type:'object'}
            }
          }
        }
      }
    }
  }
};
json('report-schema.json',schema); save();
let fixtures, launch, server, lock, lockFile;
const legacy = ['startup','idle-filter','selection','replay-start','playing-filter'];
const featureNames = ['switch-full','switch-compact','next','previous','disclosure-open','exact-history','large-payload'];
const fieldFeatures = new Set(['fields-open','field-definition-open']);
function named(list,id,what) { const matches = list.filter(item => item.id === id); assert.equal(matches.length,1,'Exactly one '+what+': '+id); return matches[0]; }
function validateManifest(m) {
  assert.equal(m.schemaVersion,1); assert.equal(m.kind,'compact-mobile-performance-fixtures'); assert.equal(m.frozen,true,'Freeze the manifest before collecting');
  for (const list of ['arms','fixtures','viewports','loadModes','indexStates','comparisons','candidateActions']) assert.ok(Array.isArray(m[list]) && m[list].length,'Nonempty '+list);
  for (const list of ['arms','fixtures','viewports','comparisons','candidateActions']) assert.equal(new Set(m[list].map(x=>x.id)).size,m[list].length,'Unique IDs in '+list);
  for (const arm of m.arms) { assert.ok(['baseline','candidate'].includes(arm.root)); assert.ok(['compact','full'].includes(arm.presentation)); assert.ok([null,'compact','full'].includes(arm.preference)); }
  for (const fixture of m.fixtures) { assert.ok(['ordinary','large-history','large-payload'].includes(fixture.classification)); assert.equal(typeof fixture.scenarioId,'string'); assert.equal(typeof fixture.startupScenarioId,'string','Freeze expected startup lesson'); }
  for (const v of m.viewports) { assert.ok(Number.isInteger(v.width)&&v.width>0&&Number.isInteger(v.height)&&v.height>0); assert.ok(v.dpr>0); assert.equal(typeof v.touch,'boolean'); assert.ok(['reduce','no-preference'].includes(v.reducedMotion)); }
  assert.deepEqual([...m.loadModes].sort(),[...LOAD_MODES].sort(),'Declare all three actual loading paths');
  assert.deepEqual([...m.indexStates].sort(),['closed','open']);
  for (const c of m.comparisons) {
    const a=named(m.arms,c.baselineArm,'arm'), b=named(m.arms,c.candidateArm,'arm');
    assert.deepEqual(c.actions,legacy,'Legacy endpoint sequence must remain unchanged');
    assert.ok((a.root==='baseline'&&a.presentation==='full'&&b.root==='candidate'&&b.presentation==='full') ||
      (a.root==='candidate'&&a.presentation==='full'&&b.root==='candidate'&&b.presentation==='compact'),'Only declared historical Full or same-candidate Full/Compact comparisons');
    for (const id of c.fixtureIds) named(m.fixtures,id,'fixture'); for (const id of c.viewportIds) named(m.viewports,id,'viewport');
  }
  assert.ok(m.comparisons.some(c=>named(m.arms,c.baselineArm,'arm').root==='baseline'),'Need accepted07Full versus newFull');
  assert.ok(m.comparisons.some(c=>named(m.arms,c.candidateArm,'arm').presentation==='compact'),'Need newCompact versus newFull');
  for (const name of featureNames) assert.ok(m.candidateActions.some(a=>a.name===name),'Missing candidate action '+name);
  for (const a of m.candidateActions) {
    assert.ok(featureNames.includes(a.name)||fieldFeatures.has(a.name));assert.equal(named(m.arms,a.arm,'arm').root,'candidate');
    assert.equal(typeof a.selector,'string');assert.equal(typeof a.resultSelector,'string');assert.ok(a.fixtureIds.length && a.viewportIds.length);
    for(const id of a.fixtureIds) {
      const fixture=named(m.fixtures,id,'fixture');
      if(a.name==='large-payload')assert.equal(fixture.classification,'large-payload','Large payload classification is frozen, not inferred from timing');
    }
    for(const id of a.viewportIds)named(m.viewports,id,'viewport');
  }
  assert.ok(m.resource && Array.isArray(m.resource.fullOnlySelectors) && m.resource.fullOnlySelectors.length);
  assert.ok(Array.isArray(m.resource.fullMethods)&&m.resource.fullMethods.length,'Predeclare Full-only rendering/geometry method counters');
  for (const category of ['graph','geometry','dock','packet','timeline']) assert.ok(m.resource.fullMethods.some(x=>x.category===category),'Missing Full work counter category '+category);
  for (const key of ['listeners','observers','timers','detachedNodes']) assert.ok(Number.isInteger(m.resource.resourceBounds[key])&&m.resource.resourceBounds[key]>=0,'Predeclare resource bound '+key);
  assert.equal(named(m.arms,m.resource.arm,'resource arm').presentation,'compact');
  for(const id of m.resource.fixtureIds)named(m.fixtures,id,'resource fixture');
  for(const id of m.resource.viewportIds)named(m.viewports,id,'resource viewport');
  assert.ok(m.resource.fixtureIds.length&&m.resource.viewportIds.length,'Nonempty resource matrix');
  assert.ok(Number.isInteger(m.resource.returnViewport?.width)&&m.resource.returnViewport.width>0&&Number.isInteger(m.resource.returnViewport?.height)&&m.resource.returnViewport.height>0,'Predeclare alternate Full return viewport');
  for(const id of m.resource.viewportIds){const v=named(m.viewports,id,'resource viewport');assert.ok(v.width!==m.resource.returnViewport.width||v.height!==m.resource.returnViewport.height,'Return viewport must exercise an actual size change');}
  for(const selector of ['switchFullSelector','switchCompactSelector','fullReturnSelector'])assert.equal(typeof m.resource[selector],'string','Predeclare resource '+selector);
  for(const method of m.resource.fullMethods){assert.equal(typeof method.name,'string');assert.ok(['app','heldView'].includes(method.owner||'app'));}
}
function bindings() {
  return {baseline:captureInputs(roots.baseline),candidate:captureInputs(roots.candidate),runner:fileIdentity(runner),helper:fileIdentity(helper),fixtures:fileIdentity(fixturePath),runtime:runtimeIdentity(),
    legacyProducer:fileIdentity(path.join(roots.candidate,'tools/verification/run-next-expansion-performance.mjs')),
    browser:launch ? {executable:fileIdentity(launch.identity.executable.path),module:fileIdentity(launch.identity.module.entry),package:fileIdentity(launch.identity.module.packageFile)} : null};
}
function checkInputs(label) {
  const current = bindings();
  const expected = report.identities;
  // Browser metadata is added once launch has resolved the explicit installed executable/module.
  for (const name of ['baseline','candidate','runner','helper','fixtures','runtime','legacyProducer']) assert.deepEqual(current[name],expected[name],'Input changed during '+label+': '+name);
  if (expected.browser) assert.deepEqual(current.browser,expected.browser,'Browser/module bytes changed');
  report.inputChecks.push({label,at:new Date().toISOString(),status:'unchanged'}); return current;
}
async function usable(page,arm,fixture,{startup=false}={}) {
  await page.waitForFunction(({scenario,presentation})=>{
    const a=document.querySelector('auth-flow-studio');
    return a?.heldView && a.player && a.steps?.length && a.scenarioPicker && a.labScenarioId===scenario && (a.presentationMode||'full')===presentation;
  },{scenario:startup?fixture.startupScenarioId:fixture.scenarioId,presentation:arm.presentation});
  await page.locator('#lab-scenario-search').waitFor({state:'visible'});
  await page.locator('#scenario-title').waitFor({state:'visible'});
  await page.locator(arm.presentation==='compact'?'[data-compact-command="play"]':'#play').waitFor({state:'visible'});
  await page.locator(arm.presentation==='compact'?'#compact-current-title':'#story').waitFor({state:'visible'});
  await page.waitForFunction(presentation=>{
    const a=document.querySelector('auth-flow-studio'), selector=presentation==='compact'?'#compact-current-title':'#story';
    const content=a.querySelector(selector); return !!content?.textContent.trim() && a.heldView.snapshot().cursor != null;
  },arm.presentation); await settle(page);
}
async function setupFixture(page,fixture) {
  // Explicit setup is outside every timed action. No app setter is used as a measured UI action.
  await page.evaluate(f=>{
    const a=document.querySelector('auth-flow-studio');
    if(a.labScenarioId!==f.scenarioId)a.selectLabScenario(f.scenarioId);
    if(f.variantId!==undefined)a.selectLessonVariant(f.variantId);
    if(f.subfixtureId!==undefined)a.selectLessonSubfixture(f.subfixtureId);
    if(f.queueBoundary!==undefined)a.inspectQueueBoundary(f.queueBoundary,f.queueEdge||'end');
  },fixture); await settle(page);
}
async function setIndex(page,indexState,row,touch) {
  const before=await studyState(page), want=indexState==='open';
  if(before.indexVisible!==want) {
    const selector=before.presentation==='compact'?'[data-compact-disclosure="fields"] > summary':want?'#index-open':'#attribute-index-toggle';
    await activate(page,selector,{touch});await settle(page);row.controls.push({purpose:'set index '+indexState,selector,before:retainState(before),after:retainState(await studyState(page))});
  }
  assert.equal((await studyState(page)).indexVisible,want,'Actual post-startup index state');
}
const playSelector=arm=>arm.presentation==='compact'?'[data-compact-command="play"]':'#play';
const rawStates=new Map();
function retainState(state){
  if(!state)return state;
  const bytes=Buffer.from(JSON.stringify(state)),hash=sha256(bytes);let rawState=rawStates.get(hash);
  if(!rawState){
    assert.ok(bytes.length<=64*1024*1024,'Raw study state exceeds64MiB');
    const name='raw/state-'+hash+'.json.gz';fs.mkdirSync(path.join(out,'raw'),{recursive:true});fs.writeFileSync(path.join(out,name),gzipSync(bytes),{flag:'wx'});
    rawState={path:name,...fileIdentity(path.join(out,name)),encoding:'gzip-json',decodedBytes:bytes.length,decodedSha256:hash};rawStates.set(hash,rawState);(report.stateFiles??=[]).push(rawState);
  }
  const rows=queue=>({sha256:sha256(JSON.stringify(queue)),rows:queue.map(r=>({id:r.id,sourceIndex:r.sourceIndex,heldCursorStart:r.heldCursorStart,heldCursorEnd:r.heldCursorEnd}))});
  const {session,player,trace,studyQueue,...rest}=state;
  // Preserve absent-value markers; only actual queue containers have rows to summarize.
  return {...rest,rawState,session:session?{...session,scenarioSnapshot:{sha256:sha256(JSON.stringify(session.scenarioSnapshot))}}:null,
    player:player?{...player,queue:rows(player.queue)}:null,trace:trace?{...trace,queue:rows(trace.queue)}:null,
    studyQueue:studyQueue&&Object.hasOwn(studyQueue,'rows')?{...studyQueue,rows:rows(studyQueue.rows)}:studyQueue};
}
async function timeAction(row,page,name,fn) {
  const record={name,status:'attempted',before:name==='startup'?null:await studyState(page)};
  record.ui=name==='startup'?{action:'navigate',target:row.target}:
    name==='idle-filter'||name==='playing-filter'?{action:'fill',selector:'#lab-scenario-search',value:name==='idle-filter'?'refresh':'basic'}:
    name==='selection'?{action:'activate',selector:'[data-scenario-option="lab-refresh-rotation"]'}:
    name==='replay-start'?{action:'activate',selector:playSelector({presentation:record.before.presentation})}:row.featureUI;
  record.inputMechanism=row.viewport.touch?'Playwright touch tap or native text input':'Playwright pointer click or native text input';
  record.trustedEventObservation=options.mode==='compare'?'Not instrumented; native Playwright UI input only':'Separate diagnostic trusted-event log';
  row.actions.push(record);save();
  try {const start=performance.now();await fn();const elapsed=performance.now()-start; if(options.mode==='compare')record.latencyMs=elapsed;
    record.after=await studyState(page);record.status='complete';return record;
  } catch(error) {record.status='failed';record.error=errorText(error);throw error;}
}
function sameFields(a,b,keys,label) {for(const k of keys)assert.deepEqual(a[k],b[k],label+' '+k);}
async function legacyActions(session,row,arm,fixture,indexState,viewport) {
  const {page,target}=session;
  await timeAction(row,page,'startup',async()=>{await page.goto(target,{waitUntil:'domcontentloaded'});await usable(page,arm,fixture,{startup:true});});
  row.defaultIndexVisible=(await studyState(page)).indexVisible;
  await setupFixture(page,fixture); await usable(page,arm,fixture); await setIndex(page,indexState,row,viewport.touch);
  const idle=await timeAction(row,page,'idle-filter',async()=>{await page.locator('#lab-scenario-search').fill('refresh');await page.locator('[data-scenario-option="lab-refresh-rotation"]').waitFor({state:'visible'});await settle(page);});
  sameFields(idle.before,idle.after,['scenario'],'Idle filter preserves');sameFields(idle.before.player,idle.after.player,['status','kind','elapsed'],'Idle filter preserves');
  await timeAction(row,page,'selection',async()=>{await activate(page,'[data-scenario-option="lab-refresh-rotation"]',{touch:viewport.touch});await page.waitForFunction(()=>document.querySelector('auth-flow-studio').labScenarioId==='lab-refresh-rotation');await settle(page);});
  assert.equal((await studyState(page)).scenario,'lab-refresh-rotation'); await setIndex(page,indexState,row,viewport.touch);
  const replay=await timeAction(row,page,'replay-start',async()=>{await activate(page,playSelector(arm),{touch:viewport.touch});await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});await settle(page);});
  assert.equal(replay.after.player.status,'playing');
  const playing=await timeAction(row,page,'playing-filter',async()=>{await page.locator('#lab-scenario-search').fill('basic');await page.locator('[data-scenario-option="basic-keycloak"]').waitFor({state:'visible'});await settle(page);});
  assert.equal(playing.after.player.status,arm.presentation==='compact'?'paused':'playing');sameFields(playing.before,playing.after,['scenario'],'Playing filter preserves');assert.equal(playing.before.player.kind,playing.after.player.kind);assert.ok(playing.after.player.elapsed>=playing.before.player.elapsed);
  for(const action of row.actions.filter(x=>x.name!=='startup'))assert.equal(action.after.indexVisible,indexState==='open','Index state preserved');
  if((await studyState(page)).player.status==='playing'){
    const beforeDismiss=await studyState(page);
    await page.locator('#lab-scenario-search').press('Escape');await settle(page);
    assert.equal(await page.locator('#lab-scenario-search').getAttribute('aria-expanded'),'false','Post-measurement picker dismissed');
    const beforePause=await studyState(page);
    row.controls.push({purpose:'post-measurement picker dismissal',action:'press',selector:'#lab-scenario-search',key:'Escape',before:retainState(beforeDismiss),after:retainState(beforePause)});
    await activate(page,playSelector(arm),{touch:viewport.touch});const afterPause=await studyState(page);
    assert.equal(afterPause.player.status,'paused');
    row.controls.push({purpose:'pause after measurements',action:'activate',selector:playSelector(arm),before:retainState(beforePause),after:retainState(afterPause)});
  }
}
async function featureAction(session,row,arm,fixture,action,viewport) {
  const {page,target}=session;
  row.featureUI={action:'activate',selector:action.selector,resultSelector:action.resultSelector};
  await page.goto(target,{waitUntil:'domcontentloaded'});await usable(page,arm,fixture,{startup:true});await setupFixture(page,fixture);await usable(page,arm,fixture);
  for(const step of action.setup||[]) {
    const control={purpose:'predeclared untimed action setup',...step,before:retainState(await studyState(page))};row.controls.push(control);
    if(step.action==='click')await activate(page,step.selector,{touch:viewport.touch});
    else {assert.equal(step.action,'fill');await page.locator(step.selector).fill(step.value);}
    await settle(page);control.after=retainState(await studyState(page));
  }
  const expectedArtifact=action.name==='exact-history'?await page.locator(action.selector).getAttribute('data-held-trace'):null;
  if(action.name==='exact-history')assert.ok(expectedArtifact,'Exact history action must target an actual exact artifact control');
  if(action.name==='disclosure-open'||action.name==='large-payload'||fieldFeatures.has(action.name))assert.equal(await page.locator(action.resultSelector).isVisible(),false,'Predeclared disclosure/payload/definition result starts closed');
  const diagnosticSwitch=options.mode!=='compare' && action.name.startsWith('switch-') && (await studyState(page)).player.status==='playing';
  if(diagnosticSwitch)await armSwitchWitness(page);
  const result=await timeAction(row,page,action.name,async()=>{
    await activate(page,action.selector,{touch:viewport.touch});await page.locator(action.resultSelector).waitFor({state:'visible'});
    if(action.resultText!==undefined)await page.waitForFunction(({selector,text})=>document.querySelector(selector)?.textContent.includes(text),{selector:action.resultSelector,text:action.resultText});
    if(action.name.startsWith('switch-'))await page.waitForFunction(mode=>document.querySelector('auth-flow-studio').presentationMode===mode,action.name.slice(7));
    if(action.name==='next'||action.name==='previous') {
      const before=row.actions.at(-1).before.studyQueue;
      const position=action.name==='previous'?before.position-1:before.initial?0:before.rowComplete[before.position]?before.position+1:Math.max(0,before.position);
      await page.waitForFunction(position=>{
        const a=document.querySelector('auth-flow-studio'),q=a.studyQueue(),title=a.querySelector('#compact-current-title');
        return q.position===position && !!title?.textContent.trim() && (!q.rows[position]?.title||title.textContent.includes(q.rows[position].title));
      },position);
    }
    if(action.name==='disclosure-open')await page.waitForFunction(selector=>document.querySelector(selector)?.closest('details')?.open,action.selector);
    if(action.name==='fields-open')await page.waitForFunction(()=>{
      const index=document.querySelector('#attribute-index'),rows=index?.querySelectorAll('[data-index-attribute]');
      return index?.closest('details')?.open&&rows.length>0&&rows.length<=40;
    });
    if(action.name==='field-definition-open')await page.waitForFunction(()=>{
      const region=document.querySelector('#compact-field-definition'),r=region?.getBoundingClientRect();
      return region&&!region.hidden&&document.activeElement===region&&!!region.querySelector('[data-compact-field-trace]')&&r.top>=-1&&r.top<innerHeight;
    });
    if(action.name==='exact-history')await page.waitForFunction(artifact=>{
      const a=document.querySelector('auth-flow-studio'),selection=a.objectTraceSelection;
      return !!selection && (selection===artifact || selection.artifactId===artifact) && a.hasTrace;
    },expectedArtifact);
    if(action.name==='large-payload')await page.waitForFunction(selector=>!!document.querySelector(selector)?.textContent.trim(),action.resultSelector);
    await settle(page);
  });
  if(action.name.startsWith('switch-')) {
    assert.equal(result.after.presentation,action.name.slice(7));assert.notEqual(result.after.player.status,'playing');
    if(result.before.player.status==='playing') {
      result.switchWitness=diagnosticSwitch ? await finishSwitchWitness(page) : {status:'delegated-to-separate-diagnostic',evidence:'Matched resource/profile evidence supplies the postpause witness; latency observations make no racing pre-click equality claim and are not a missing required continuity case.'};
    } else assert.deepEqual(continuityProjection(result.after),continuityProjection(result.before),'Exact paused switch continuity');
    const again=await studyState(page);assert.deepEqual(continuityProjection(again),continuityProjection(result.after),'No implicit resume or post-switch cursor drift');
  }
  if(action.name==='next'||action.name==='previous') {
    assert.notEqual(result.after.player.status,'playing');
    const before=result.before.studyQueue,after=result.after.studyQueue;
    assert.ok(before&&after&&!before.$undefined&&!after.$undefined,'Actual active queue projection required');
    const expected=action.name==='previous'?before.position-1:before.initial?0:before.rowComplete[before.position]?before.position+1:Math.max(0,before.position);
    assert.equal(after.position,expected,'Exact active queue navigation boundary');assert.deepEqual(after.rows,before.rows,'Navigation retains full active queue');
    if(expected>=0) {
      assert.equal(after.rowComplete[expected],true,'Exact completed active-row boundary, not a fractional seek');
      if(after.rows[expected].heldCursorEnd) {
        const requested=after.rows[expected].heldCursorEnd;
        assert.equal(after.cursor.eventIndex,requested.eventIndex,'Exact mapped source event');
        if(requested.milestone!==undefined)assert.equal(after.cursor.milestone,requested.milestone,'Exact authored milestone');
        result.boundary={requested,canonical:after.cursor,rowComplete:after.rowComplete[expected],sourceComplete:after.sourceComplete};
      }
    } else assert.equal(after.initial,true,'Previous to the explicit initial active-queue boundary');
  }
  if(action.name==='disclosure-open'||action.name==='fields-open') {
    assert.equal(await page.locator(action.selector).evaluate(node=>node.closest('details')?.open),true,'Actual disclosure opened');
    if(result.before.player.status==='playing')assert.equal(result.after.player.status,'paused');
  }
  if(fieldFeatures.has(action.name)&&result.before.player.status!=='playing')assert.deepEqual(continuityProjection(result.after),continuityProjection(result.before),'Field browsing preserves the paused canonical prefix, active queue and selection');
  if(action.name==='exact-history') {
    assert.ok(result.after.trace.object && !result.after.trace.object.$undefined,'Actual exact object selection');
    assert.ok(result.after.trace.object===expectedArtifact || result.after.trace.object.artifactId===expectedArtifact,'Exact requested artifact history');
    assert.ok(result.after.player.queue.length || result.after.studyQueue?.empty,'Exact history has real queue or explicit no-match');
  }
  if(action.expected) {
    for(const [key,value] of Object.entries(action.expected))assert.deepEqual(result.after[key],value,'Predeclared result '+key);
  }
  return result;
}
function instrumentResources({fullMethods,fullOnlySelectors}) {
  const counts={listeners:[],observers:[],timeouts:new Set(),intervals:new Set(),frames:new Set(),fullCalls:{},geometry:0,playerAssignments:0};
  const originals={add:EventTarget.prototype.addEventListener,remove:EventTarget.prototype.removeEventListener};
  const capture=o=>typeof o==='boolean'?o:!!o?.capture;
  EventTarget.prototype.addEventListener=function(type,callback,options){
    if(!callback)return originals.add.call(this,type,callback,options);
    const cap=capture(options),existing=counts.listeners.find(r=>r.active&&r.target.deref()===this&&r.callback.deref()===callback&&r.type===type&&r.capture===cap);
    if(existing)return originals.add.call(this,type,existing.wrapper.deref(),options);
    const record={target:new WeakRef(this),callback:new WeakRef(callback),type,capture:cap,active:!options?.signal?.aborted};
    function wrapped(event){if(options?.once)record.active=false;return typeof callback==='function'?callback.call(this,event):callback.handleEvent(event);}
    record.wrapper=new WeakRef(wrapped);counts.listeners.push(record);
    if(options?.signal)originals.add.call(options.signal,'abort',()=>{record.active=false;},{once:true});
    return originals.add.call(this,type,wrapped,options);
  };
  EventTarget.prototype.removeEventListener=function(type,callback,options){
    const record=counts.listeners.find(r=>r.active&&r.target.deref()===this&&r.callback.deref()===callback&&r.type===type&&r.capture===capture(options));
    if(record){record.active=false;return originals.remove.call(this,type,record.wrapper.deref(),options);}return originals.remove.call(this,type,callback,options);
  };
  for(const name of ['ResizeObserver','MutationObserver','IntersectionObserver']) {
    const Native=window[name];if(!Native)continue;
    window[name]=class extends Native {
      constructor(...args){super(...args);this.__compactResource={ref:new WeakRef(this),targets:new Set()};counts.observers.push(this.__compactResource);}
      observe(target,...args){this.__compactResource.targets.add(new WeakRef(target));return super.observe(target,...args);}
      unobserve(target){for(const ref of this.__compactResource.targets)if(ref.deref()===target)this.__compactResource.targets.delete(ref);return super.unobserve(target);}
      disconnect(){this.__compactResource.targets.clear();return super.disconnect();}
    };
  }
  const timeout=window.setTimeout.bind(window),clearTimeoutNative=window.clearTimeout.bind(window),interval=window.setInterval.bind(window),clearIntervalNative=window.clearInterval.bind(window),raf=window.requestAnimationFrame.bind(window),cancel=window.cancelAnimationFrame.bind(window);
  window.setTimeout=(callback,delay,...args)=>{const id=timeout(typeof callback==='function'?()=>{counts.timeouts.delete(id);callback(...args);}:callback,delay,...(typeof callback==='function'?[]:args));counts.timeouts.add(id);return id;};
  window.clearTimeout=id=>{counts.timeouts.delete(id);counts.intervals.delete(id);return clearTimeoutNative(id);};
  window.setInterval=(...args)=>{const id=interval(...args);counts.intervals.add(id);return id;};window.clearInterval=id=>{counts.intervals.delete(id);counts.timeouts.delete(id);return clearIntervalNative(id);};
  window.requestAnimationFrame=callback=>{const id=raf(time=>{counts.frames.delete(id);callback(time);});counts.frames.add(id);return id;};window.cancelAnimationFrame=id=>{counts.frames.delete(id);return cancel(id);};
  const rect=Element.prototype.getBoundingClientRect;
  Element.prototype.getBoundingClientRect=function(...args){if(fullOnlySelectors.some(selector=>this.matches(selector)||this.closest(selector)))counts.geometry++;return rect.apply(this,args);};
  const define=customElements.define.bind(customElements),ids=new WeakMap();let nextId=1;
  customElements.define=function(name,constructor,options){
    if(name==='auth-flow-studio') {
      const proto=constructor.prototype;
      const wrap=(target,owner)=>{
        for(const {name:method,owner:declaredOwner='app'} of fullMethods) {
          if(declaredOwner!==owner)continue;
          const original=target[method],key=owner+'.'+method;
          if(typeof original!=='function')throw new Error('Missing declared Full method '+key);
          counts.fullCalls[key]=0;target[method]=function(...args){counts.fullCalls[key]++;return original.apply(this,args);};
        }
      };
      wrap(proto,'app');
      const heldSlot=new WeakMap();Object.defineProperty(proto,'heldView',{configurable:true,get(){return heldSlot.get(this);},set(value){heldSlot.set(this,value);if(value)wrap(value,'heldView');}});
      const playerSlot=new WeakMap();Object.defineProperty(proto,'player',{configurable:true,get(){return playerSlot.get(this);},set(value){counts.playerAssignments++;playerSlot.set(this,value);if(value&&!ids.has(value))ids.set(value,nextId++);}});
    }
    return define(name,constructor,options);
  };
  window.__compactResources=()=>{
    const app=document.querySelector('auth-flow-studio'),p=app?.player;
    const live=counts.listeners.filter(r=>r.active&&r.target.deref()&&r.callback.deref());
    return {listeners:live.length,detachedListenerTargets:live.filter(r=>{const t=r.target.deref();return t instanceof Node&&!t.isConnected;}).length,
      observers:counts.observers.filter(r=>r.ref.deref()&&[...r.targets].some(t=>t.deref())).length,
      timers:counts.timeouts.size+counts.intervals.size,animationFrames:counts.frames.size,fullCalls:{...counts.fullCalls},geometry:counts.geometry,
      playerAssignments:counts.playerAssignments,playerId:p?ids.get(p):null,playerListeners:p?.listeners.size,
      playerSchedulers:Number(p?.handle!=null)+Number(p?.timer!=null),playerStatus:p?.status,viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio},
      fullDOM:fullOnlySelectors.map(selector=>({selector,count:document.querySelectorAll(selector).length})),nodes:document.querySelectorAll('*').length};
  };
}
async function resourceRun(session,row,arm,fixture,viewport) {
  const {page,target,context}=session,r=fixtures.resource;
  await page.addInitScript(instrumentResources,{fullMethods:r.fullMethods,fullOnlySelectors:r.fullOnlySelectors});
  const cdp=await context.newCDPSession(page);await cdp.send('Performance.enable');await cdp.send('DOM.enable');
  await page.goto(target,{waitUntil:'domcontentloaded'});await usable(page,arm,fixture,{startup:true});
  const cold=await page.evaluate(()=>window.__compactResources());row.cold=cold;
  assert.ok(cold.fullDOM.every(x=>x.count===0),'No Full DOM on Compact cold start');assert.equal(cold.geometry,0,'No Full geometry at Compact cold start');
  for(const [method,calls]of Object.entries(cold.fullCalls))assert.equal(calls,0,'No Full-only work on Compact cold start: '+method);
  assert.equal(cold.playerAssignments,1,'Exactly one shared player constructed');assert.ok(cold.playerSchedulers<=1,'At most one player scheduler');
  await setupFixture(page,fixture);row.checkpoints=[];
  async function checkpoint(cycle) {
    // Detached-node inspection pins its returned nodes in the DOM agent.
    // Release those inspector-only bindings before measuring the next live heap.
    await cdp.send('DOM.disable');await cdp.send('DOM.enable');
    const gc={supported:true,performed:0};
    try{await cdp.send('HeapProfiler.collectGarbage');gc.performed++;await cdp.send('HeapProfiler.collectGarbage');gc.performed++;}
    catch(error){gc.supported=false;gc.error=errorText(error);if(!/wasn't found|not found|not supported|method.*available/i.test(String(error)))throw error;}
    await settle(page);
    const data=await page.evaluate(()=>window.__compactResources());
    const memory={heap:await cdp.send('Runtime.getHeapUsage'),dom:await cdp.send('Memory.getDOMCounters')};
    try {
      const detached=await cdp.send('DOM.getDetachedDomNodes');
      const count=node=>1+['children','shadowRoots','pseudoElements'].reduce((sum,key)=>sum+(node[key]||[]).reduce((n,child)=>n+count(child),0),0)+(node.contentDocument?count(node.contentDocument):0);
      memory.detached={status:'collected',treeCount:detached.detachedNodes.length,
        nodeCount:detached.detachedNodes.reduce((sum,item)=>sum+count(item.treeNode),0),
        retainedNodeIds:detached.detachedNodes.flatMap(item=>item.retainedNodeIds)};
    } catch(error) {
      if(!/wasn't found|not found|not supported|method.*available/i.test(String(error)))throw error;
      memory.detached={status:'unperformed',error:errorText(error)};
    }
    const record={cycle,gc,data,memory,state:await studyState(page)};row.checkpoints.push(record);save();return record;
  }
  // Separately retain a diagnostic warmup roundtrip, including both playing-switch witnesses.
  // Growth starts only after this stable same-surface baseline, never at an empty shell.
  row.resourceWarmup={status:'attempted',before:await studyState(page)};
  await activate(page,'[data-compact-command="play"]',{touch:viewport.touch});await settle(page);
  row.playing=await page.evaluate(()=>window.__compactResources());assert.equal(row.playing.playerSchedulers,1,'Exactly one active player scheduler while playing');
  await armSwitchWitness(page);
  await activate(page,r.switchFullSelector,{touch:viewport.touch});await page.locator(r.fullReturnSelector).waitFor({state:'visible'});await settle(page);
  row.resourceWarmup.compactToFull=await finishSwitchWitness(page);
  await activate(page,r.fullPlaySelector||'#play',{touch:viewport.touch});await settle(page);
  assert.equal((await studyState(page)).player.status,'playing');
  await armSwitchWitness(page);
  await activate(page,r.switchCompactSelector,{touch:viewport.touch});await page.locator('.compact-study').waitFor({state:'visible'});await settle(page);
  row.resourceWarmup.fullToCompact=await finishSwitchWitness(page);
  row.resourceWarmup.after=await studyState(page);row.resourceWarmup.status='complete';
  const base=await checkpoint(0),playerId=cold.playerId;
  row.fullReturns=[];
  for(let cycle=1;cycle<=20;cycle++) {
    const expectedViewport=cycle%2?r.returnViewport:{width:viewport.width,height:viewport.height};
    const resizeBefore=await studyState(page);
    await page.setViewportSize(expectedViewport);await settle(page);
    assert.equal((await studyState(page)).presentation,'compact','Viewport change does not override explicit Compact presentation');
    assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(resizeBefore),'Resizing inactive Full cannot reset canonical study state');
    const compactBefore=await studyState(page);
    await activate(page,r.switchFullSelector,{touch:viewport.touch});await page.locator(r.fullReturnSelector).waitFor({state:'visible'});await settle(page);
    assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(compactBefore),'Paused Compact-to-Full continuity');
    const full=await page.evaluate(selector=>{const n=document.querySelector(selector),rect=n.getBoundingClientRect(),a=document.querySelector('auth-flow-studio');return {viewport:{width:innerWidth,height:innerHeight},rect:{x:rect.x,y:rect.y,width:rect.width,height:rect.height},geometry:a.heldGeometry};},r.fullReturnSelector);
    assert.equal(full.viewport.width,expectedViewport.width);assert.equal(full.viewport.height,expectedViewport.height);assert.ok(full.rect.width>0&&full.rect.height>0,'Full return actually laid out in current viewport');
    row.fullReturns.push({cycle,requestedViewport:expectedViewport,...full});
    const fullBefore=await studyState(page);
    await activate(page,r.switchCompactSelector,{touch:viewport.touch});await page.locator('.compact-study').waitFor({state:'visible'});await settle(page);
    assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(fullBefore),'Paused Full-to-Compact continuity');
    const state=await page.evaluate(()=>window.__compactResources());assert.equal(state.playerId,playerId,'Same shared player');assert.equal(state.playerAssignments,1);assert.equal(state.playerSchedulers,0,'No scheduling after paused switch');assert.ok(state.fullDOM.every(x=>x.count===0),'Outgoing Full DOM removed');
    if([1,5,10,15,20].includes(cycle))await checkpoint(cycle);
  }
  const final=row.checkpoints.at(-1),bounds=r.resourceBounds;
  row.growth={listeners:final.data.listeners-base.data.listeners,observers:final.data.observers-base.data.observers,
    timers:final.data.timers-base.data.timers,documentNodes:final.memory.dom.nodes-base.memory.dom.nodes,
    detachedNodes:final.memory.detached.status==='collected'&&base.memory.detached.status==='collected'?final.memory.detached.nodeCount-base.memory.detached.nodeCount:null,
    detachedListenerTargets:final.data.detachedListenerTargets-base.data.detachedListenerTargets,
    heapBytes:final.memory.heap.usedSize-base.memory.heap.usedSize,playerListeners:final.data.playerListeners-base.data.playerListeners};
  row.detachedNodeEvidence={status:final.memory.detached.status,method:'CDP DOM.getDetachedDomNodes plus weak detached listener targets after releasing prior DOM-agent bindings and supported GC',limitation:'Observed diagnostic trees are not a blanket no-leak proof'};
  row.memoryLimitations=['Instrumented heap includes weak-reference counter bookkeeping, not only application allocations.','GC and detached-tree support are reported independently; these samples do not prove absence of all leaks.'];
  row.bounds=Object.fromEntries(['listeners','observers','timers','detachedNodes'].map(key=>[key,{growth:row.growth[key],maximum:bounds[key],
    status:row.growth[key]===null?'unperformed':row.growth[key]<=bounds[key]?'within-declared-bound':'flagged'}]));
  if(Object.values(row.bounds).some(x=>x.status!=='within-declared-bound')||row.growth.detachedListenerTargets>0||row.growth.playerListeners>0)row.disposition=disposition();
  row.noLeakClaim=false;await cdp.detach();
}
async function profileRun(session,row,arm,fixture,action,viewport) {
  const cdp=await session.context.newCDPSession(session.page);await cdp.send('Profiler.enable');await cdp.send('Profiler.setSamplingInterval',{interval:1000});await cdp.send('Performance.enable');
  await cdp.send('Profiler.start');const before=await cdp.send('Performance.getMetrics');
  try {
    if(action)await featureAction(session,row,arm,fixture,action,viewport);
    else await legacyActions(session,row,arm,fixture,row.indexState,viewport);
  } finally {
    const {profile}=await cdp.send('Profiler.stop'),after=await cdp.send('Performance.getMetrics');
    const totals=new Map();for(let i=0;i<(profile.samples||[]).length;i++)totals.set(profile.samples[i],(totals.get(profile.samples[i])||0)+(profile.timeDeltas?.[i]||0));
    row.profile={status:'diagnostic-only',scope:'Whole disposable session: boot, explicit untimed fixture setup, UI actions and assertions. Sampled self attribution is not action latency.',counterBefore:before.metrics,counterAfter:after.metrics,
      sampledSelfFunctions:profile.nodes.map(n=>({name:n.callFrame.functionName,url:n.callFrame.url,line:n.callFrame.lineNumber,selfMs:(totals.get(n.id)||0)/1000})).sort((a,b)=>b.selfMs-a.selfMs).slice(0,30)};
    if(options['retain-profiles']==='true') {
      const bytes=Buffer.from(JSON.stringify(profile));assert.ok(bytes.length<=64*1024*1024,'Profile exceeds per-file cap');
      const used=report.files.reduce((sum,f)=>sum+f.bytes,0);assert.ok(used+bytes.length<=512*1024*1024,'Profile total exceeds cap');
      const name='profile-'+report.profiles.length+'.cpuprofile';fs.writeFileSync(path.join(out,name),bytes);row.profile.file={file:name,...fileIdentity(path.join(out,name))};report.files.push(row.profile.file);
    }
    await cdp.detach();
  }
}
async function collect({cell,arm,fixture,viewport,loadingMode,indexState,sample,warmup,order,action=null}) {
  checkInputs('before '+cell+'/'+arm.id+'/'+sample);
  const row={cell,arm:arm.id,fixture:fixture.id,classification:fixture.classification,viewport,loadingMode,indexState,sample,warmup,order,status:'attempted',actions:[],controls:[],startedAt:new Date().toISOString()};
  row.throttle={cpu:'not-requested',network:'not-requested',actualDevice:false,emulatedTouch:viewport.touch};
  const destination=options.mode==='resource'?report.resources:options.mode==='profile'?report.profiles:warmup?report.warmups:report.samples;
  destination.push(row);save();let session;
  try {
    session=await createBrowserSession({browser:launch.browser,server,rootName:arm.root,root:roots[arm.root],identity:report.identities[arm.root],
      loadingMode,viewport:{width:viewport.width,height:viewport.height},dpr:viewport.dpr,touch:viewport.touch,reducedMotion:viewport.reducedMotion,
      preference:arm.preference,diagnostic:options.mode!=='compare'});
    row.target=session.target;row.evidence=session.evidence;
    if(options.mode==='resource')await resourceRun(session,row,arm,fixture,viewport);
    else if(options.mode==='profile')await profileRun(session,row,arm,fixture,action,viewport);
    else if(action)await featureAction(session,row,arm,fixture,action,viewport);
    else await legacyActions(session,row,arm,fixture,indexState,viewport);
    assertClean(session.evidence);assert.deepEqual(server.errors,[],'Static server errors');row.status='complete';
  } catch(error){row.status='failed';row.error=errorText(error);fail('cell '+cell,error);}
  finally {
    if(session)try{await session.close();}catch(error){row.status='failed';fail('context cleanup',error);}
    for(const action of row.actions){action.before=retainState(action.before);if(action.after)action.after=retainState(action.after);}
    try{checkInputs('after '+cell+'/'+arm.id+'/'+sample);row.inputsUnchanged=true;}catch(error){row.inputsUnchanged=false;fail('input integrity',error);}
    row.finishedAt=new Date().toISOString();append(warmup?'warmups.jsonl':'samples.jsonl',row);save();
  }
  assert.ok(row.inputsUnchanged,'Input mutation stops collection');assert.equal(row.status,'complete','Failed cell retained; collection stops rather than collecting a favorable subset');
}
function stats(values) {
  assert.ok(values.length===7&&values.every(Number.isFinite),'Exactly seven finite retained samples');
  const sorted=[...values].sort((a,b)=>a-b),median=sorted[3],rangeMs=sorted[6]-sorted[0];
  return {values,min:sorted[0],median,max:sorted[6],rangeMs,rangeOverMedian:median?rangeMs/median:null};
}
function compareCells() {
  for(const cell of report.matrix.filter(x=>x.type==='comparison'))for(const name of legacy) {
    const distributions=Object.fromEntries(cell.arms.map(id=>[id,stats(report.samples.filter(r=>r.cell===cell.id&&r.arm===id).map(r=>r.actions.find(a=>a.name===name).latencyMs))]));
    const [baseline,candidate]=cell.arms.map(id=>distributions[id]),deltaMs=candidate.median-baseline.median,ratio=baseline.median?candidate.median/baseline.median:null,absolute=name==='startup'?100:50;
    const materialRegression=ratio!==null&&ratio>1.25&&deltaMs>absolute;
    const variation=Object.fromEntries(cell.arms.map(id=>[id,distributions[id].rangeOverMedian>0.25&&distributions[id].rangeMs>absolute]));
    report.comparisons.push({cell:cell.id,action:name,arms:cell.arms,baseline,candidate,deltaMs,ratio,materialRegression,variation,
      status:materialRegression||Object.values(variation).some(Boolean)?'flagged':'no-current-flag',disposition:materialRegression||Object.values(variation).some(Boolean)?disposition():{status:'not-required',ownerAcceptance:false}});
  }
  for(const cell of report.matrix.filter(x=>x.type==='feature')) {
    const action=named(fixtures.candidateActions,cell.action,'candidate action'),fixture=named(fixtures.fixtures,cell.fixture,'fixture');
    const distribution=stats(report.samples.filter(r=>r.cell===cell.id).map(r=>r.actions[0].latencyMs));
    const ordinary=fixture.classification==='ordinary',targetApplicable=ordinary&&(['switch-full','switch-compact','next','previous','disclosure-open'].includes(action.name)||fieldFeatures.has(action.name));
    const targetMiss=targetApplicable&&(distribution.median>250||distribution.max>500);
    const variable=distribution.rangeOverMedian>0.25&&distribution.rangeMs>50;
    report.candidateActions.push({cell:cell.id,action:action.name,classification:fixture.classification,distribution,historicalBaseline:null,
      planningTarget:targetApplicable?{medianMs:250,maximumMs:500}:null,targetMiss,variation:variable,status:targetMiss||variable?'flagged':'measured',
      disposition:targetMiss||variable?disposition():{status:'not-required',ownerAcceptance:false}});
  }
}
function matrix() {
  const cells=[];
  for(const comparison of fixtures.comparisons)for(const fixture of comparison.fixtureIds)for(const viewport of comparison.viewportIds)for(const loadingMode of fixtures.loadModes)for(const indexState of fixtures.indexStates)
    cells.push({id:[comparison.id,fixture,viewport,loadingMode,indexState].join('/'),type:'comparison',fixture,viewport,loadingMode,indexState,arms:[comparison.baselineArm,comparison.candidateArm]});
  for(const action of fixtures.candidateActions)for(const fixture of action.fixtureIds)for(const viewport of action.viewportIds)for(const loadingMode of fixtures.loadModes)
    cells.push({id:[action.id,fixture,viewport,loadingMode].join('/'),type:'feature',action:action.id,fixture,viewport,loadingMode,indexState:null,arms:[action.arm]});
  assert.equal(new Set(cells.map(x=>x.id)).size,cells.length,'Unique matrix cells');return cells;
}
try {
  assert.equal(fileIdentity(fixturePath).sha256,options['fixtures-sha256'],'Exact frozen fixture manifest');
  fixtures=JSON.parse(fs.readFileSync(fixturePath,'utf8'));validateManifest(fixtures);json('fixtures.json',fixtures);
  // OS-enforced exclusive create plus a held fd prevents two collectors with the same measured root pair.
  lockFile=path.join(path.dirname(roots.candidate),'.compact-mobile-performance-collector.lock');
  lock=fs.openSync(lockFile,'wx');fs.writeFileSync(lock,JSON.stringify({pid:process.pid,out,startedAt:report.startedAt})+'\n');
  report.identities=bindings();
  for(const name of ['baseline','candidate']) {assert.equal(report.identities[name].canonicalSha256,options[name+'-source-sha256'],'Pinned '+name+' source');assert.equal(report.identities[name].standalone.sha256,options[name+'-html-sha256'],'Pinned '+name+' HTML');}
  launch=await launchBrowser({modulePath:options['playwright-module'],executablePath:options['chromium-executable'],libraryPath:options['library-path']});
  report.browser=launch.identity;report.identities.browser=bindings().browser;json('inputs-before.json',report.identities);
  const byteSum=(identity,filter)=>Object.entries(identity.sources).filter(([name])=>filter(name)).reduce((sum,[,value])=>sum+value.bytes,0);
  report.byteGrowth={
    canonicalInputBytes:byteSum(report.identities.candidate,()=>true)-byteSum(report.identities.baseline,()=>true),
    runtimeSourceBytes:byteSum(report.identities.candidate,name=>!name.startsWith('tests/'))-byteSum(report.identities.baseline,name=>!name.startsWith('tests/')),
    testBytes:byteSum(report.identities.candidate,name=>name.startsWith('tests/'))-byteSum(report.identities.baseline,name=>name.startsWith('tests/')),
    standaloneBytes:report.identities.candidate.standalone.bytes-report.identities.baseline.standalone.bytes};
  server=await createStaticServer({roots,identities:report.identities});report.matrix=matrix();save();
  if(options.mode==='resource') {
    const r=fixtures.resource,arm=named(fixtures.arms,r.arm,'arm');
    for(const fixtureId of r.fixtureIds)for(const viewportId of r.viewportIds)for(const loadingMode of fixtures.loadModes)
      await collect({cell:['resource',fixtureId,viewportId,loadingMode].join('/'),arm,fixture:named(fixtures.fixtures,fixtureId,'fixture'),viewport:named(fixtures.viewports,viewportId,'viewport'),loadingMode,indexState:null,sample:0,warmup:false,order:0});
  } else {
    for(let ci=0;ci<report.matrix.length;ci++) {
      const cell=report.matrix[ci],fixture=named(fixtures.fixtures,cell.fixture,'fixture'),viewport=named(fixtures.viewports,cell.viewport,'viewport'),action=cell.action?named(fixtures.candidateActions,cell.action,'action'):null;
      const rounds=options.mode==='compare'?[-1,0,1,2,3,4,5,6]:[0];
      for(const sample of rounds) {
        const order=(sample+1+ci)%2?[...cell.arms].reverse():cell.arms;
        for(let oi=0;oi<order.length;oi++)await collect({cell:cell.id,arm:named(fixtures.arms,order[oi],'arm'),fixture,viewport,loadingMode:cell.loadingMode,indexState:cell.indexState,sample,warmup:sample===-1,order:oi,action});
      }
    }
  }
  if(options.mode==='compare')compareCells();report.status='complete';
} catch(error) {report.status='failed';fail('collection',error);}
finally {
  if(launch)try{await launch.close();}catch(error){fail('browser cleanup',error);report.status='failed';}
  if(server)try{await server.close();}catch(error){fail('server cleanup',error);report.status='failed';}
  try{const after=bindings();json('inputs-after.json',after);if(report.identities.baseline)checkInputs('final');}catch(error){fail('final identities',error);report.status='failed';}
  if(lock!==undefined){fs.closeSync(lock);fs.unlinkSync(lockFile);}
  const flagged=report.comparisons.some(x=>x.status==='flagged')||report.candidateActions.some(x=>x.status==='flagged')||report.resources.some(x=>x.disposition?.status==='open');
  report.measurementStatus=report.status!=='complete'?'incomplete':options.mode!=='compare'?'diagnostic-only':flagged?'review-required':'no-current-flags';
  report.exitCode=report.status!=='complete'||report.errors.length?1:flagged?2:0;report.finishedAt=new Date().toISOString();save();
  console.log(JSON.stringify({out,status:report.status,measurementStatus:report.measurementStatus,exitCode:report.exitCode}));process.exitCode=report.exitCode;
}
