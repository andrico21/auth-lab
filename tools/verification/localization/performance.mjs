#!/usr/bin/env bun
// Serial exact-input collector. Importing this module never starts collection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureInputs,fileIdentity,sha256,runtimeIdentity,launchBrowser,createStaticServer,createBrowserSession,activate,settle,studyState,continuityProjection,assertClean} from '../compact-mobile-browser.mjs';
import {PERFORMANCE_ROOT,CONTRACT_PATH,LOCALE_STORAGE_KEY,bindPerformanceFixtures,performanceCells,performanceReady,classifyPerformanceSamples,pairedSampleOrder,freezeNativeSearchFixture,freezeFieldSearchFixture} from './performance-fixtures.mjs';

const HELP=`Usage: bun tools/verification/localization/performance.mjs --mode=plan|smoke|compare|resource --out=NEW_DIRECTORY
  --candidate-source-sha256=HASH --candidate-html-sha256=HASH
  [--baseline-root=EXACT_RECONSTRUCTED_1_2_ROOT]
  [--cells=COMMA_SEPARATED_EXACT_CELL_IDS]
Relocation requires the unchanged frozen baseline source and HTML hashes, never an older control.
Plan validates and binds exact inputs without launching a browser. Compare/resource require --plan=PREVIOUS_PLAN_JSON
and --plan-sha256=HASH. No downloads/builds. Seven serial samples plus one excluded warmup; failures retained.
Output must be outside both roots. Compare uses no execution instrumentation or CDP. Resource never reports latency.
Smoke runs the same interaction callbacks across both arms/views, English/RTL, dense fixtures and field probes.
It freezes only its own references, records no timings, runs two diagnostic resource cycles, and is never matrix acceptance.
Run smoke successfully before freezing the final measurement plan. Resource does not repeat unused search preflight.
An explicit cell selection is frozen into its plan and reports selected-scope completion, never full-matrix acceptance.
Exit 1 = failed/incomplete, 2 = open observations, 0 = no current flags (never approval/waiver).`;
const filename=fileURLToPath(import.meta.url);
const writeJSON=(out,name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
const errorText=error=>String(error.stack||error);
function appendRecord(out,name,value){
  const filename=path.join(out,name),bytes=Buffer.from(JSON.stringify(value)+'\n'),offset=fs.existsSync(filename)?fs.statSync(filename).size:0;
  fs.appendFileSync(filename,bytes);
  return {path:name,offset,bytes:bytes.length,sha256:sha256(bytes)};
}
function argumentsFor(args){
  const options={};
  for(const arg of args){const m=/^--([^=]+)=(.+)$/.exec(arg);assert.ok(m&&['mode','out','candidate-source-sha256','candidate-html-sha256','plan','plan-sha256','baseline-root','cells'].includes(m[1]),'Unknown argument: '+arg);assert.ok(!Object.hasOwn(options,m[1]),'Duplicate argument');options[m[1]]=m[2];}
  for(const key of ['mode','out','candidate-source-sha256','candidate-html-sha256'])assert.ok(options[key],'Missing --'+key);
  assert.ok(['plan','smoke','compare','resource'].includes(options.mode));
  for(const key of ['candidate-source-sha256','candidate-html-sha256'])assert.match(options[key],/^[a-f0-9]{64}$/);
  if(options.mode==='compare'||options.mode==='resource'){assert.ok(options.plan);assert.match(options['plan-sha256']||'',/^[a-f0-9]{64}$/);}
  if(options.cells){assert.notEqual(options.mode,'smoke','Smoke has its own declared path coverage');const names=options.cells.split(',');assert.ok(names.every(Boolean)&&new Set(names).size===names.length,'Unique nonempty selected cell IDs');}
  return options;
}
function identities(roots){return {baseline:captureInputs(roots.baseline),candidate:captureInputs(roots.candidate),collector:fileIdentity(filename),fixtures:fileIdentity(path.join(path.dirname(filename),'performance-fixtures.mjs')),contract:fileIdentity(path.join(roots.candidate,CONTRACT_PATH)),helper:fileIdentity(path.join(path.dirname(filename),'../compact-mobile-browser.mjs')),runtime:runtimeIdentity()};}
function probes(contract,fixtures){
  const rows=[];
  for(const fixture of fixtures.filter(f=>!contract.matrix.primaryFixtureIds.includes(f.id)))for(const presentation of contract.matrix.presentations)for(const loadingMode of contract.matrix.loadModes)for(const locale of contract.matrix.locales)rows.push({id:[fixture.id,presentation,loadingMode,locale].join('/'),fixtureId:fixture.id,caseId:fixture.caseId,presentation,loadingMode,locale,viewportId:contract.matrix.viewportByPresentation[presentation],indexState:'closed',probe:true});
  return rows;
}
async function ready(page,cell,baseline=false,scenarioId='basic-keycloak'){
  await page.waitForFunction(performanceReady,{scenarioId,presentation:cell.presentation,locale:cell.locale,baseline});
  // Usability must include actual translated explanation/control resolution, never only a locale attribute.
  if(!baseline&&cell.locale!=='en')await page.waitForFunction(()=>{
    const a=document.querySelector('auth-flow-studio'),l=a.localizer;
    const content=a.querySelector(a.presentationMode==='compact'?'#compact-action-summary':'#story > div > p');
    let nativeExplanation=false;
    for(const [key,language]of l.resolvedLanguages)if(language===l.locale&&(Number.isInteger(key)||typeof key==='string'&&!key.startsWith('ui.'))){nativeExplanation=true;break;}
    return !!l.catalog&&l.fallbacks.size===0&&nativeExplanation&&!!content?.textContent.trim()&&!content.querySelector('[lang="en"]');
  });
  await settle(page);
}
async function setup(page,fixture){await page.evaluate(f=>{const a=document.querySelector('auth-flow-studio');a.player.pause();a.selectLabScenario(f.scenarioId,{variant:f.variantId});if(f.subfixtureId)a.selectLessonSubfixture(f.subfixtureId);if(f.queueBoundary!==undefined)a.inspectQueueBoundary(f.queueBoundary,f.queueEdge);a.player.pause();},fixture);await settle(page);}
async function localeInput(page,tag){
  // Native keyboard navigation commits a trusted select change, not dispatchEvent/selectOption.
  const select=page.locator('#language-select');await select.focus();await select.press('Alt+ArrowDown');await select.press('Home');
  const tags=['en','ru','uk','he','de','ar-AE','fr','pl'];for(let i=0;i<tags.indexOf(tag);i++)await select.press('ArrowDown');await select.press('Enter');
}
async function openFields(page,presentation,touch){await activate(page,presentation==='compact'?'[data-compact-disclosure="fields"] > summary':'#index-open',{touch});await page.locator('#attribute-search').waitFor({state:'visible'});await settle(page);}
async function closeFields(page,presentation,touch){await activate(page,presentation==='compact'?'[data-compact-disclosure="fields"] > summary':'#attribute-index-toggle',{touch});await page.locator('#attribute-search').waitFor({state:'hidden'});await settle(page);}
const fieldIDs=page=>page.locator('#attribute-index-list [data-index-attribute]').evaluateAll(nodes=>nodes.map(n=>n.dataset.indexAttribute));
async function prepareReferences(page,locale,presentation){
  // This disposable preflight invokes the actual picker/index renderers. No preflight observations are timings.
  let native=null;
  if(locale!=='en'){
    const scenario=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),p=a.scenarioPicker;return p.options.map(row=>({...a.localizer.searchEntry('scenario',row.id,row),id:row.id}));});
    const script=locale==='he'?/\p{Script=Hebrew}/u:locale==='ar-AE'?/\p{Script=Arabic}/u:['ru','uk'].includes(locale)?/\p{Script=Cyrillic}/u:/[^\x00-\x7f]/u;
    outer:for(const row of scenario){
      const text=[row.title,row.summary,row.category,...(row.searchTags||[])].filter(v=>typeof v==='string').join(' ');
      for(const token of text.match(/[\p{L}\p{M}]{3,}/gu)||[]){
        if(!script.test(token))continue;
        const ids=await page.evaluate(query=>{const p=document.querySelector('auth-flow-studio').scenarioPicker;p.query=query;p.render();return p.results.map(r=>r.id);},token);
        if(!ids.includes(row.id))continue;
        native=freezeNativeSearchFixture({locale,entries:[{id:row.id,title:token}],match:()=>ids});break outer;
      }
    }
    assert.ok(native,'No actual native production search match: '+locale);
  }
  await page.evaluate(()=>{const p=document.querySelector('auth-flow-studio').scenarioPicker;p.query='';p.render();});
  if(!await page.locator('#attribute-search').isVisible())await openFields(page,presentation,false);
  if(presentation==='compact')await activate(page,'#compact-field-scope-global');
  const fieldQueries=['client_id'];
  if(locale!=='en'){
    const prose=await page.locator('#attribute-index-list').textContent();const script=locale==='he'?/\p{Script=Hebrew}/u:locale==='ar-AE'?/\p{Script=Arabic}/u:['ru','uk'].includes(locale)?/\p{Script=Cyrillic}/u:/[^\x00-\x7f]/u;
    const token=(prose.match(/[\p{L}\p{M}]{3,}/gu)||[]).find(word=>script.test(word));assert.ok(token,'Native field explanation query unavailable: '+locale);fieldQueries.push(token);
  }
  const fields=[];for(const query of fieldQueries){await page.evaluate(query=>{const a=document.querySelector('auth-flow-studio');a.attributeQuery=query;a.renderAttributeIndex();},query);fields.push(freezeFieldSearchFixture({locale,query,expectedIds:await fieldIDs(page)}));}
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.attributeQuery='';a.renderAttributeIndex();});
  const expansion=presentation==='compact'?await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.compactView.fieldBrowser.limit=80;a.renderAttributeIndex();return [...a.querySelectorAll('#attribute-index-list [data-index-attribute]')].map(n=>n.dataset.indexAttribute);}):null;
  return {native,fields,expansion};
}
async function assertSearch(page,reference){await page.waitForFunction(ref=>{const a=document.querySelector('auth-flow-studio'),p=a.scenarioPicker;return p.query===ref.query&&JSON.stringify(p.results.map(r=>r.id))===JSON.stringify(ref.expectedIds)&&JSON.stringify([...a.querySelectorAll('[data-scenario-option]')].filter(n=>n.getClientRects().length).map(n=>n.dataset.scenarioOption))===JSON.stringify(ref.expectedIds);},reference);await settle(page);}
async function assertFields(page,reference){await page.waitForFunction(ref=>{const a=document.querySelector('auth-flow-studio');return a.querySelector('#attribute-search').value===ref.query&&JSON.stringify([...a.querySelectorAll('#attribute-index-list [data-index-attribute]')].map(n=>n.dataset.indexAttribute))===JSON.stringify(ref.expectedIds);},reference);await settle(page);}

function smokeSchedule(cells){
  const pick=(fixtureId,presentation,loadingMode,locale)=>{const cell=cells.find(c=>c.fixtureId===fixtureId&&c.presentation===presentation&&c.loadingMode===loadingMode&&c.locale===locale);assert.ok(cell,'Declared smoke cell '+[fixtureId,presentation,loadingMode,locale]);return cell;};
  const rows=[],resources=[];
  for(const presentation of ['full','compact']){
    const loader=presentation==='full'?'source-http':'standalone-file',english=pick('perf-basic-web',presentation,loader,'en'),native=pick('perf-basic-web',presentation,loader,'he');
    rows.push({cell:english,rootName:'baseline',selected:false},{cell:english,rootName:'candidate',selected:false},{cell:native,rootName:'candidate',selected:false},{cell:native,rootName:'candidate',selected:true});
    const fields=pick('perf-core-fields',presentation,'emitted-http','en'),nativeFields=pick('perf-core-fields',presentation,'emitted-http','he');
    rows.push({cell:fields,rootName:'baseline',selected:false},{cell:fields,rootName:'candidate',selected:false},{cell:nativeFields,rootName:'candidate',selected:true},{cell:pick('perf-mcp09-fields',presentation,'emitted-http','he'),rootName:'candidate',selected:true});
    resources.push(nativeFields);
  }
  rows.push({cell:pick('perf-nested-jwt-payload','compact','standalone-file','he'),rootName:'candidate',selected:true},{cell:pick('perf-long-dnssec-history','full','source-http','he'),rootName:'candidate',selected:true});
  return {rows,resources};
}

// Diagnostic-only wrappers. Weak references avoid making targets/callbacks permanent roots.
function installResources(){
  const listeners=[],timers=new Map(),observers=[],catalogs=[],indexes=[];const weak=value=>new WeakRef(value);
  const add=EventTarget.prototype.addEventListener,remove=EventTarget.prototype.removeEventListener;
  EventTarget.prototype.addEventListener=function(type,callback,options){if(callback&&!listeners.some(r=>r.active&&r.target.deref()===this&&r.callback.deref()===callback&&r.type===type&&r.capture===!!(typeof options==='boolean'?options:options?.capture)))listeners.push({target:weak(this),callback:weak(callback),type,capture:!!(typeof options==='boolean'?options:options?.capture),once:!!options?.once,signal:options?.signal?weak(options.signal):null,active:true});return add.call(this,type,callback,options);};
  EventTarget.prototype.removeEventListener=function(type,callback,options){for(const r of listeners)if(r.target.deref()===this&&r.callback.deref()===callback&&r.type===type&&r.capture===!!(typeof options==='boolean'?options:options?.capture))r.active=false;return remove.call(this,type,callback,options);};
  for(const [set,clear,repeat]of [['setTimeout','clearTimeout',false],['setInterval','clearInterval',true],['requestAnimationFrame','cancelAnimationFrame',false]]){const original=window[set],cancel=window[clear];window[set]=function(callback,...args){let id;id=original.call(this,typeof callback==='function'?function(...values){if(!repeat)timers.delete(set+id);return callback.apply(this,values);}:callback,...args);timers.set(set+id,{kind:set,id});return id;};window[clear]=function(id){for(const kind of set==='requestAnimationFrame'?['requestAnimationFrame']:['setTimeout','setInterval'])timers.delete(kind+id);return cancel.call(this,id);};}
  for(const name of ['MutationObserver','ResizeObserver','IntersectionObserver']){const Original=window[name];if(!Original)continue;window[name]=class extends Original{constructor(...args){super(...args);this.__record={ref:weak(this),targets:[],kind:name};observers.push(this.__record);}observe(target,...args){if(!this.__record.targets.some(r=>r.deref()===target))this.__record.targets.push(weak(target));return super.observe(target,...args);}unobserve(target){this.__record.targets=this.__record.targets.filter(r=>r.deref()!==target);return super.unobserve(target);}disconnect(){this.__record.targets=[];return super.disconnect();}};}
  window.__localizationResources=()=>{
    const a=document.querySelector('auth-flow-studio'),l=a.localizer;
    for(const [value,rows]of [[l.catalog,catalogs],[l.searchCache,indexes]])if(value&&!rows.some(r=>r.ref.deref()===value))rows.push({ref:weak(value),locale:l.locale,revision:l.revision});
    const live=listeners.filter(r=>r.active&&r.target.deref()&&r.callback.deref()&&!r.signal?.deref()?.aborted);
    const summarize=rows=>rows.filter(r=>r.ref.deref()).map(r=>({locale:r.locale,revision:r.revision,active:r.ref.deref()===(rows===catalogs?l.catalog:l.searchCache)}));
    return {locale:l.locale,revision:l.revision,catalogs:summarize(catalogs),indexes:summarize(indexes),
      resourceRepresentations:Object.entries(l.resources).map(([locale,value])=>({locale,type:typeof value,serializedBytes:typeof value==='string'?new TextEncoder().encode(value).length:null,inactiveParsed:locale!==l.locale&&value!==null&&typeof value==='object'})),
      catalogBytes:l.catalog?new TextEncoder().encode(JSON.stringify(l.catalog)).length:0,englishBindings:l.contracts?.size||0,activeSearchEntries:l.searchCache.size,
      listeners:live.map(r=>({type:r.type,target:r.target.deref()?.id||r.target.deref()?.constructor.name,once:r.once,owner:'target weak identity; shared library/app owner not inferred'})),
      listenerQualification:'once callbacks may overcount after firing; positive growth remains open',timers:[...timers.values()],
      observers:observers.filter(r=>r.ref.deref()&&r.targets.some(t=>t.deref())).map(r=>({kind:r.kind,targets:r.targets.filter(t=>t.deref()).length})),
      nodes:document.querySelectorAll('*').length,detachedListenerTargets:live.filter(r=>r.target.deref() instanceof Node&&!r.target.deref().isConnected).length,fallbacks:[...l.fallbacks]};
  };
}
export async function runCLI(args=process.argv.slice(2)){
  if(args.includes('--help')){console.log(HELP);return 0;}
  const options=argumentsFor(args),isSmoke=options.mode==='smoke';assert.ok(process.versions.bun,'Use provisioned Bun');
  const binding=await bindPerformanceFixtures({baselineRoot:options['baseline-root']});const {contract,fixtures}=binding,roots={baseline:binding.baselineRoot,candidate:PERFORMANCE_ROOT};
  fs.mkdirSync(path.dirname(path.resolve(options.out)),{recursive:true});const out=path.join(fs.realpathSync(path.dirname(path.resolve(options.out))),path.basename(options.out));
  for(const root of Object.values(roots))assert.ok(out!==root&&!out.startsWith(root+path.sep),'Output outside roots');fs.mkdirSync(out);
  const report={schemaVersion:1,kind:'localization-performance',mode:options.mode,argv:[process.execPath,...process.argv.slice(1)],status:'collecting',diagnosticOnly:isSmoke,approval:false,waiver:false,errors:[],flags:[],samples:[],resources:[],smokeRows:[],smokeResources:[],smokeObservations:[],inheritedOpenConditions:contract.inheritedOpenConditions,method:contract.sampling,persistence:{samples:'Complete raw rows and before/after states appended once to samples.jsonl or warmups.jsonl; report rows retain byte-offset/SHA256 references and every timing.',resources:'Complete raw checkpoints and canonical states appended once to resource-checkpoints.jsonl; report retains diagnostic data and byte-offset/SHA256 references.',progress:'Small progress.json updates outside timing windows; full report saved at row boundaries and completion/failure.'}};
  const save=()=>writeJSON(out,'report.json',report);save();let launch,server,lock;
  const progress=value=>writeJSON(out,'progress.json',{schemaVersion:1,mode:options.mode,recordedSampleRows:report.samples.length,recordedResourceCells:report.resources.length,smokeRows:report.smokeRows.length,smokeResourceCells:report.smokeResources.length,...value});
  try{
    const before=identities(roots);assert.equal(before.baseline.canonicalSha256,contract.inputs.baseline.sourceSha256);assert.equal(before.baseline.standalone.sha256,contract.inputs.baseline.standaloneSha256);assert.equal(before.candidate.canonicalSha256,options['candidate-source-sha256']);assert.equal(before.candidate.standalone.sha256,options['candidate-html-sha256']);
    assert.equal(before.runtime.sha256,contract.runtime.sha256);assert.equal(process.versions.bun,contract.runtime.version);
    const plan={schemaVersion:1,kind:isSmoke?'localization-performance-smoke-inputs':'localization-performance-exact-plan',frozen:!isSmoke,identities:before,fixtures,cells:performanceCells(contract),fieldProbes:probes(contract,fixtures),contract,selectedCellIds:options.cells?options.cells.split(','):null};
    assert.equal(plan.cells.length,144);assert.equal(plan.cells.filter(c=>c.locale==='en').length,18);assert.equal(plan.fieldProbes.length,96);
    if(plan.selectedCellIds){const ids=new Set([...plan.cells,...plan.fieldProbes].map(cell=>cell.id));assert.ok(plan.selectedCellIds.every(id=>ids.has(id)),'Selected IDs belong to the full declared matrix');report.selection={scope:'explicit-selected-scope-not-full-matrix',cellIds:plan.selectedCellIds,originalTimingUniverse:240,originalResourceUniverse:210};}
    writeJSON(out,'inputs-before.json',before);writeJSON(out,'plan.json',plan);
    if(options.mode==='plan'){report.status='predeclared-not-collected';report.cellCounts=contract.matrix.cellCounts;save();return 0;}
    if(!isSmoke){assert.equal(fileIdentity(options.plan).sha256,options['plan-sha256']);assert.deepEqual(JSON.parse(fs.readFileSync(options.plan,'utf8')),plan,'Exact predeclared plan/input mismatch');}
    const lockPath=path.join(path.dirname(out),'.localization-performance.lock');lock=fs.openSync(lockPath,'wx');fs.writeFileSync(lock,JSON.stringify({pid:process.pid,out}));report.lockPath=lockPath;
    launch=await launchBrowser({modulePath:path.join(roots.candidate,contract.runtime.playwrightModule),executablePath:contract.runtime.browserExecutable,libraryPath:contract.runtime.libraryPath});
    assert.equal(fileIdentity(launch.identity.executable.path).sha256,contract.runtime.browserSha256);report.browser=launch.identity;
    const beforeBrowserModule=fileIdentity(launch.identity.module.entry),beforeBrowserPackage=fileIdentity(launch.identity.module.packageFile);
    writeJSON(out,'browser-inputs.json',{identity:launch.identity,module:beforeBrowserModule,package:beforeBrowserPackage});
    server=await createStaticServer({roots,identities:{baseline:before.baseline,candidate:before.candidate}});
    const view=cell=>contract.matrix.viewports.find(v=>v.id===cell.viewportId);
    async function sessionFor(cell,rootName,saved=null,diagnostic=false){const v=view(cell);const session=await createBrowserSession({browser:launch.browser,server,rootName,root:roots[rootName],identity:before[rootName],loadingMode:cell.loadingMode,viewport:{width:v.width,height:v.height},dpr:v.dpr,touch:v.touch,reducedMotion:v.reducedMotion,preference:cell.presentation,diagnostic});if(saved)await session.context.addInitScript(({key,tag,target})=>{if(location.href===target)localStorage.setItem(key,tag);},{key:LOCALE_STORAGE_KEY,tag:saved,target:session.target});return session;}
    const allCells=[...plan.cells,...plan.fieldProbes],selectedIds=plan.selectedCellIds?new Set(plan.selectedCellIds):null,executionCells=selectedIds?allCells.filter(cell=>selectedIds.has(cell.id)):allCells,smoke=isSmoke?smokeSchedule(allCells):null,references={baseline:{},candidate:{}};
    const englishCell=cell=>{const found=allCells.find(c=>c.fixtureId===cell.fixtureId&&c.presentation===cell.presentation&&c.loadingMode===cell.loadingMode&&c.locale==='en');assert.ok(found,'Declared English control cell');return found;};
    const needed=new Map(),need=(rootName,cell)=>needed.set(rootName+'\0'+cell.id,{rootName,cell});
    if(isSmoke)for(const row of smoke.rows)need(row.rootName,row.selected?row.cell:englishCell(row.cell));
    else if(options.mode==='compare')for(const cell of executionCells){need('candidate',cell);need('candidate',englishCell(cell));if(cell.locale==='en')need('baseline',cell);}
    // Each arm freezes its own real results. Resource uses no search references.
    for(const {rootName,cell}of needed.values()){
      const session=await sessionFor(cell,rootName,cell.locale==='en'?null:cell.locale),baseline=rootName==='baseline',fixture=fixtures.find(f=>f.id===cell.fixtureId);
      try{await session.page.goto(session.target);await ready(session.page,cell,baseline);await setup(session.page,fixture);await ready(session.page,cell,baseline,fixture.scenarioId);references[rootName][cell.id]=await prepareReferences(session.page,cell.locale,cell.presentation);assertClean(session.evidence);}finally{await session.close();}
    }
    writeJSON(out,'search-fixtures.json',{frozen:true,diagnosticOnly:isSmoke,sha256:sha256(JSON.stringify(references)),references});assert.deepEqual(identities(roots),before,'Inputs changed during fixture freezing');
    if(isSmoke){report.smokeScope={interactionRows:smoke.rows.map(row=>({cell:row.cell.id,rootName:row.rootName,locale:row.selected?row.cell.locale:'en'})),resourceCells:smoke.resources.map(cell=>cell.id),resourceCycles:2,timingSamples:0,fullTimingCellsUnperformed:240,fullResourceCellsUnperformed:210};save();}
    async function measured(cell,rootName,sample,warmup,selected){
      const fixture=fixtures.find(f=>f.id===cell.fixtureId),locale=selected?cell.locale:'en',current={...cell,locale};const s=await sessionFor(current,rootName,locale==='en'?null:locale);const row={cell:cell.id,rootName,locale,sample,warmup,diagnosticOnly:isSmoke,actions:[],status:'attempted'};(isSmoke?report.smokeRows:report.samples).push(row);save();
      const baseline=rootName==='baseline',v=view(cell),refs=references[rootName][locale==='en'?englishCell(cell).id:cell.id];assert.ok(refs,'Own-arm frozen search references');
      async function action(name,fn,{continuity=true}={}){
        const record={name,status:'attempted',before:continuity?await studyState(s.page):null};row.actions.push(record);
        const location={cell:cell.id,rootName,locale,sample,warmup,action:name};
        progress({...location,status:record.status});
        try{const start=isSmoke?null:performance.now();await fn();if(!isSmoke)record.latencyMs=performance.now()-start;record.after=await studyState(s.page);if(continuity)assert.deepEqual(continuityProjection(record.after),continuityProjection(record.before),'Paused canonical continuity: '+name);record.status='complete';}
        catch(error){record.status='failed';record.error=errorText(error);throw error;}
        finally{progress({...location,status:record.status,latencyMs:record.latencyMs,error:record.error});}
      }
      try{
        await action(locale==='en'?'startup-en':'startup-saved-locale',async()=>{await s.page.goto(s.target,{waitUntil:'domcontentloaded'});await ready(s.page,current,baseline);},{continuity:false});
        await setup(s.page,fixture);await ready(s.page,current,baseline,fixture.scenarioId);
        if(!baseline&&locale!=='en'){
          await localeInput(s.page,'en');await ready(s.page,{...cell,locale:'en'},false,fixture.scenarioId);
          // The first activation must use a fresh en document, not saved startup's already-loaded catalog.
          await s.close();row.status='startup-complete';
          const first=await sessionFor({...cell,locale:'en'},'candidate');
          try{await first.page.goto(first.target);await ready(first.page,{...cell,locale:'en'});await setup(first.page,fixture);
            for(const [name,tag]of [['first-language-switch',locale],['repeat-language-switch-to-en','en'],['repeat-language-switch',locale]]){const beforeState=await studyState(first.page),r={name,status:'attempted',before:beforeState};row.actions.push(r);progress({cell:cell.id,rootName,locale,sample,warmup,action:name,status:r.status});const start=isSmoke?null:performance.now();await localeInput(first.page,tag);await ready(first.page,{...cell,locale:tag},false,fixture.scenarioId);if(!isSmoke)r.latencyMs=performance.now()-start;r.after=await studyState(first.page);assert.deepEqual(continuityProjection(r.after),continuityProjection(beforeState));r.status='complete';progress({cell:cell.id,rootName,locale,sample,warmup,action:name,status:r.status,latencyMs:r.latencyMs});}
            // Continue actions in the document that experienced first and repeated switches.
            Object.assign(s,{page:first.page,context:first.context,evidence:first.evidence,close:first.close});
          }catch(error){await first.close();throw error;}
        }
        const query=locale==='en'?{query:'refresh',expectedIds:null}:refs.native;
        // Clearing a focused search opens its results; dismiss them before unrelated field controls.
        if(query){for(const name of ['first-search','repeat-search']){await s.page.locator('#lab-scenario-search').fill('');await settle(s.page);await action(name,async()=>{await s.page.locator('#lab-scenario-search').fill(query.query);if(query.expectedIds)await assertSearch(s.page,query);else{await s.page.locator('[data-scenario-option="lab-refresh-rotation"]').waitFor({state:'visible'});await settle(s.page);}});}await s.page.locator('#lab-scenario-search').fill('');await settle(s.page);await s.page.locator('#lab-scenario-search').press('Escape');await settle(s.page);}
        if(await s.page.locator('#attribute-search').isVisible())await closeFields(s.page,cell.presentation,v.touch);
        for(const name of ['first-field-open','repeat-field-open']){await action(name,()=>openFields(s.page,cell.presentation,v.touch));await closeFields(s.page,cell.presentation,v.touch);}
        await openFields(s.page,cell.presentation,v.touch);if(cell.presentation==='compact')await activate(s.page,'#compact-field-scope-global',{touch:v.touch});
        for(const ref of refs.fields.filter(r=>!baseline||r.query==='client_id'))for(const prefix of ['first','repeat']){await s.page.locator('#attribute-search').fill('');await settle(s.page);await action(prefix+'-field-search/'+ref.query,async()=>{await s.page.locator('#attribute-search').fill(ref.query);await assertFields(s.page,ref);});}
        await s.page.locator('#attribute-search').fill('');await settle(s.page);
        if(cell.probe&&cell.presentation==='compact'){
          assert.equal(await s.page.locator('#attribute-index-list [data-index-attribute]').count(),40);
          await action('field-expand-40-to-80',async()=>{await activate(s.page,'#compact-field-more',{touch:v.touch});await s.page.waitForFunction(ids=>{const a=document.querySelector('auth-flow-studio'),rows=[...a.querySelectorAll('#attribute-index-list [data-index-attribute]')];return a.compactView.fieldBrowser.limit===80&&rows.length===80&&JSON.stringify(rows.map(n=>n.dataset.indexAttribute))===JSON.stringify(ids)&&document.activeElement===rows[40];},refs.expansion);await settle(s.page);});
        }
        await closeFields(s.page,cell.presentation,v.touch);
        for(const presentation of [cell.presentation==='full'?'compact':'full',cell.presentation])await action('switch-'+presentation,async()=>{await activate(s.page,'[data-presentation-choice="'+presentation+'"]',{touch:v.touch});await ready(s.page,{...current,presentation},baseline,fixture.scenarioId);});
        assertClean(s.evidence);row.evidence=s.evidence;row.status='complete';
      }catch(error){row.status='failed';row.error=errorText(error);throw error;}finally{
        await s.close();row.rawRecord=appendRecord(out,isSmoke?'smoke-rows.jsonl':warmup?'warmups.jsonl':'samples.jsonl',row);
        for(const record of row.actions){delete record.before;delete record.after;}
        save();
      }
    }
    if(isSmoke)for(const row of smoke.rows)await measured(row.cell,row.rootName,null,false,row.selected);
    if(options.mode==='compare'){
      for(const cell of executionCells)for(let sample=-1;sample<7;sample++){
        const rootsInOrder=pairedSampleOrder(Math.max(sample,0));for(const arm of rootsInOrder)await measured(cell,cell.locale==='en'?arm:'candidate',sample,sample===-1,cell.locale!=='en'&&arm==='candidate');
      }
      report.comparisons=[];
      for(const cell of executionCells){
        const rows=report.samples.filter(r=>r.cell===cell.id&&!r.warmup);const a=rows.filter(r=>cell.locale==='en'?r.rootName==='baseline':r.locale==='en'),b=rows.filter(r=>r.rootName==='candidate'&&r.locale===cell.locale);
        const names=new Set(b.flatMap(r=>r.actions.map(x=>x.name)));
        for(const name of names){
          const samples=(group,operation=name)=>group.flatMap(r=>r.actions.filter(x=>x.name===operation).map(x=>x.latencyMs));
          const native=samples(b),control=cell.locale!=='en'&&['first-search','repeat-search'].includes(name)?[]:samples(a,name==='startup-saved-locale'?'startup-en':name);
          assert.equal(native.length,7,'Seven feature samples');const kind=name.startsWith('startup')?'startup':'interaction';
          const stats=classifyPerformanceSamples({baseline:control.length===7?control:native,candidate:native,kind});
          const result={cell:cell.id,name,classification:fixtures.find(f=>f.id===cell.fixtureId).classification,comparison:control.length===7?(cell.locale==='en'?'frozen-en/candidate-en':'candidate-en/native'):'candidate-only-feature-no-baseline',...stats};
          if(control.length!==7){delete result.baseline;delete result.materialRegression;}
          report.comparisons.push(result);
          if(result.materialRegression||result.candidateOrdinaryTargetMiss||result.candidate.variation||result.baseline?.variation)report.flags.push({...result,disposition:'open-unaccepted-unwaived'});
        }
      }
    }
    if(options.mode==='resource'||isSmoke){
      const resourceCells=isSmoke?smoke.resources:executionCells.filter(c=>c.locale!=='en'),cycles=isSmoke?2:20;
      for(const cell of resourceCells){
        const s=await sessionFor({...cell,locale:'en'},'candidate',null,true),fixture=fixtures.find(f=>f.id===cell.fixtureId);const row={cell:cell.id,diagnosticOnly:isSmoke,checkpoints:[],noLeakClaim:false,qualification:'Diagnostic wrapper overhead included; no latency. Weak retained objects observed only at boundaries. WeakMap internal search records are not enumerable; old cache identity reachability is checked.'};(isSmoke?report.smokeResources:report.resources).push(row);save();
        try{await s.page.addInitScript(installResources);const cdp=await s.context.newCDPSession(s.page);await s.page.goto(s.target);await ready(s.page,{...cell,locale:'en'});await setup(s.page,fixture);
          async function checkpoint(cycle,boundary){
            const gc={supported:true,forced:false};try{await cdp.send('HeapProfiler.collectGarbage');gc.forced=true;}catch(error){gc.supported=false;gc.error=errorText(error);}await settle(s.page);
            const r={cycle,boundary,gc,data:await s.page.evaluate(()=>window.__localizationResources()),state:await studyState(s.page)};
            for(const [key,method]of [['heap','Runtime.getHeapUsage'],['dom','Memory.getDOMCounters'],['detached','DOM.getDetachedDomNodes']])try{r[key]={status:'collected',value:await cdp.send(method)};}catch(error){r[key]={status:'unperformed',error:errorText(error)};}
            r.browserEvents=s.evidence.trustedEvents;r.browserEventCount=r.browserEvents.length;
            r.rawRecord=appendRecord(out,'resource-checkpoints.jsonl',{cell:cell.id,...r});s.evidence.trustedEvents.length=0;delete r.browserEvents;delete r.state;row.checkpoints.push(r);
            progress({cell:cell.id,cycle,boundary,status:'checkpoint-recorded',rawRecord:r.rawRecord});return r;
          }
          async function cycle(index){for(const [type,value]of [['locale',cell.locale],['view',cell.presentation==='compact'?'full':'compact'],['locale','en'],['view',cell.presentation]]){const state=await studyState(s.page);if(type==='locale')await localeInput(s.page,value);else await activate(s.page,'[data-presentation-choice="'+value+'"]',{touch:view(cell).touch});const active=await s.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {locale:a.localizer.locale,presentation:a.presentationMode};});await ready(s.page,{...cell,...active},false,fixture.scenarioId);assert.deepEqual(continuityProjection(await studyState(s.page)),continuityProjection(state));await prepareProbe(active.presentation);await checkpoint(index,type+'-'+value);}}
          async function prepareProbe(presentation){
            if(!cell.probe)return;
            if(!await s.page.locator('#attribute-search').isVisible())await openFields(s.page,presentation,view(cell).touch);
            if(presentation==='compact')await activate(s.page,'#compact-field-scope-global',{touch:view(cell).touch});
            await s.page.locator('#attribute-search').fill('client_id');await settle(s.page);
          }
          await prepareProbe(cell.presentation);await cycle(-1);const base=await checkpoint(0,'stable-reference');for(let i=1;i<=cycles;i++)await cycle(i);const final=row.checkpoints.at(-1);
          row.growth={listeners:final.data.listeners.length-base.data.listeners.length,timers:final.data.timers.length-base.data.timers.length,observers:final.data.observers.length-base.data.observers.length,nodes:final.data.nodes-base.data.nodes,detachedListenerTargets:final.data.detachedListenerTargets-base.data.detachedListenerTargets};
          row.sameStateHeap=row.checkpoints.filter(r=>r.boundary==='stable-reference'||r.boundary==='view-'+cell.presentation).map(r=>({cycle:r.cycle,gc:r.gc,heap:r.heap}));
          row.qualifiedHeapGrowth=base.heap.status==='collected'&&final.heap.status==='collected'?{bytes:final.heap.value.usedSize-base.heap.value.usedSize,forced:base.gc.forced&&final.gc.forced,interpretation:'Positive same-state delta is an open diagnostic observation, not proof of leak; retained repeated readings include instrumentation overhead.'}:{status:'unperformed'};
          const inactive=row.checkpoints.filter(r=>r.cycle>0&&(r.data.catalogs.some(c=>!c.active)||r.data.indexes.some(c=>!c.active)||r.data.resourceRepresentations.some(c=>c.inactiveParsed)));row.inactiveReachability=inactive.map(r=>({cycle:r.cycle,boundary:r.boundary,catalogs:r.data.catalogs,indexes:r.data.indexes,resourceRepresentations:r.data.resourceRepresentations}));
          if(Object.values(row.growth).some(n=>n>0)||inactive.length||row.qualifiedHeapGrowth.bytes>0)(isSmoke?report.smokeObservations:report.flags).push({cell:cell.id,growth:row.growth,qualifiedHeapGrowth:row.qualifiedHeapGrowth,inactiveReachability:row.inactiveReachability,disposition:isSmoke?'smoke-diagnostic-only-not-measurement':'open-unaccepted-unwaived'});row.evidence=s.evidence;assertClean(s.evidence);await cdp.detach();
        }finally{await s.close();save();}
      }
    }
    assert.deepEqual(identities(roots),before,'Measured input bytes changed');
    assert.equal(fileIdentity(launch.identity.executable.path).sha256,contract.runtime.browserSha256);
    assert.deepEqual(fileIdentity(launch.identity.module.entry),beforeBrowserModule,'Playwright module changed');
    assert.deepEqual(fileIdentity(launch.identity.module.packageFile),beforeBrowserPackage,'Playwright package changed');
    assert.deepEqual(server.errors,[],'Static server errors');
    writeJSON(out,'inputs-after.json',identities(roots));report.status=isSmoke?'smoke-complete-not-measurement':options.cells?'complete-selected-scope':'complete';report.measurementStatus=isSmoke?'unperformed':report.flags.length?'review-required':options.mode==='resource'?'diagnostic-only':'no-current-flags';save();return report.flags.length?2:0;
  }catch(error){report.status='failed';report.errors.push(errorText(error));save();return 1;}finally{
    try{writeJSON(out,'inputs-final.json',identities(roots));}catch(error){report.errors.push('Final input capture: '+errorText(error));save();}
    await server?.close();await launch?.browser.close();if(lock!==undefined){fs.closeSync(lock);fs.unlinkSync(report.lockPath);}
  }
}
if(process.argv[1]&&path.resolve(process.argv[1])===filename)process.exitCode=await runCLI();
