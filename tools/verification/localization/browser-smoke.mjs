#!/usr/bin/env bun
// Serial, exact-input browser evidence. Importing this producer performs no collection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {gzipSync} from 'node:zlib';
import {DEFAULT_CHECKOUT,DEFAULT_BROWSER,DEFAULT_PLAYWRIGHT,DEFAULT_LIBRARIES,LOAD_MODES,captureInputs,fileIdentity,sha256,runtimeIdentity,launchBrowser,createStaticServer,createBrowserSession,activate,settle,studyState,continuityProjection,assertClean,armSwitchWitness,finishSwitchWitness} from '../compact-mobile-browser.mjs';
import {launchNativeZoom,nativeIsolation,X11_ROOT} from '../compact-native-zoom.mjs';
import {text200,layoutSnapshot} from './browser-layout.mjs';
import {PILOT_CELLS,PILOT_SCOPE,installPilotCapture,capturePilotFamilies} from './pilot-families.mjs';

export const LOCALES=['en','ru','uk','he','de','ar-AE','fr','pl'];
export function browserPlan(){
  const cells=[];
  for(const locale of LOCALES)for(const presentation of ['compact','full'])for(const loadingMode of LOAD_MODES)
    cells.push({id:['smoke',locale,presentation,loadingMode].join('-'),kind:'ordinary',locale,presentation,loadingMode,width:presentation==='compact'?390:1440});
  for(const locale of LOCALES)for(const fixture of ['compact320','compact390','full-desktop','long-text','text200','native400'])
    cells.push({id:['layout',locale,fixture].join('-'),kind:fixture==='native400'?'native':'layout',locale,presentation:fixture==='full-desktop'?'full':'compact',loadingMode:'emitted-http',fixture,width:fixture==='compact320'?320:fixture==='full-desktop'?1440:390});
  return {schemaVersion:1,kind:'localization-browser-plan',ordinaryPlannedCells:48,cells,expectations:{ordinary:['selected-language shell/lesson/accessible labels','actual catalog-derived Unicode and original English/identifier/case queries','trusted selector and picker keyboard/pointer actions','exact postpause projection/queue and object-reference invariance','field/object/connection scopes, drafts, help and disclosures','global10843 technical names/current counts; Compact40-to80','raw clipboard bytes and actual denied fallback','repeated English/RTL/LTR roundtrips'],layout:['Compact320/390 and Full1440 actual layout','long nested JWT text','qualified exact2x user-style simulation, not native scaling','native X11 Ctrl+plus DPR4/visualScale1 in measured private namespace'],copyBoundaryClassification:'CR/LF and empty are explicitly synthetic raw-copy API inputs, not authored protocol or future-value evidence'},external:['human G01 and native-language comprehension','language-capable assistive technology and screen-reader voices','WebKit','physical phones and device OS scaling'],scope:'Actual exercised browser boundaries only; no overall acceptance, release, native protocol or inherited performance waiver'};
}
const HELP=`Usage: bun tools/verification/localization/browser-smoke.mjs --out=NEW_DIRECTORY [--root=CHECKOUT] [--baseline-root=FROZEN_1_2]
  [--source-sha256=SHA256] [--html-sha256=SHA256] [--starting-sha256=SHA256]
  [--playwright-module=PATH] [--chromium-executable=PATH] [--library-path=PATH]
  [--native-zoom=true|false] [--x11-tools=PATH] [--cell=EXACT_PLAN_ID] [--plan-only=true|false]
  [--pilot-families=true|false]
  [--ime-only=true|false]
All options require =VALUE. Output must be new and outside candidate and frozen roots.
48 ordinary cells are explicit:8 locales x2 presentations x3 exact loaders. Additional layout cells
cover320/390,Full desktop,long nested JWT,text200 user-style simulation and isolated native X11 400%.
Native zoom uses an owned bwrap child with measured private tmpfs /tmp and separate network namespace.
Scenario setup is untimed programmatic; user actions use trusted pointer and keyboard input.
Failures, exact producer/input/runtime identities, all cell outcomes and failure screenshots are retained.
--cell is a focused diagnostic, never complete matrix acceptance. --plan-only creates an unperformed plan only.
--pilot-families=true appends pilot-families-{en,de,he}-full-source-http. Select one exact --cell.
English captures source-mode renderer requests. German/Hebrew require actual native language metadata
and zero fallback across representative Full/Compact render families; no linguistic/human acceptance.
Actual metadata discovers fixtures. Typed requests, surfaces, omissions and producer identities are retained.
Ordinary cells also exercise Chromium CDP IME commit/cancel and Enter/keyCode229 on real search inputs.
This is a browser IME-boundary diagnostic, not OS/human IME or physical-keyboard acceptance.
--ime-only=true requires one ordinary --cell and runs only IME plus loader/CSP diagnostics.
All other ordinary checks are explicitly unperformed; a focused result is never matrix acceptance.
No downloads, builds, synthetic trusted events, performance measurements or external/human acceptance.
Exit0 means attempted checks passed, not overall acceptance. Exit1 retains failed attempts.`;

export async function main(argv=process.argv.slice(2)){
  if(argv.includes('--help')){console.log(HELP);return;}
  const options={},allowed=new Set(['out','root','baseline-root','source-sha256','html-sha256','starting-sha256','playwright-module','chromium-executable','library-path','native-zoom','x11-tools','cell','plan-only','pilot-families','ime-only']);
  for(const arg of argv){const m=/^--([^=]+)=(.+)$/.exec(arg);assert.ok(m&&allowed.has(m[1]),'Unknown argument '+arg+'\n'+HELP);assert.ok(!Object.hasOwn(options,m[1]),'Duplicate option');options[m[1]]=m[2];}
  assert.ok(options.out,'Required --out\n'+HELP);
  for(const key of ['native-zoom','plan-only','pilot-families','ime-only']){options[key]??=key==='native-zoom'?'true':'false';assert.ok(['true','false'].includes(options[key]),key);}
  const root=fs.realpathSync(options.root||DEFAULT_CHECKOUT),startingPath=path.join(root,'docs/localization/starting-inputs.json');
  const starting=JSON.parse(fs.readFileSync(startingPath,'utf8')),baseline=fs.realpathSync(options['baseline-root']||starting.immutableSnapshot),out=path.resolve(options.out);
  // Validate canonical and standalone baseline bytes below; a byte-identical relocated review must not rewrite frozen metadata.
  fs.mkdirSync(path.dirname(out),{recursive:true});const destination=path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
  for(const source of [root,baseline])assert.ok(destination!==source&&!destination.startsWith(source+path.sep),'Output outside both roots');
  fs.mkdirSync(out);for(const sub of ['cells','screenshots','raw'])fs.mkdirSync(path.join(out,sub));
  const json=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
  const compressedJson=(name,value)=>{const bytes=Buffer.from(JSON.stringify(value));fs.writeFileSync(path.join(out,name),gzipSync(bytes),{flag:'wx'});return {path:name,...fileIdentity(path.join(out,name)),decodedSha256:sha256(bytes),decodedBytes:bytes.length};};
  const probeTraceName='actions.jsonl.gz';let probeRecordCount=0,probeDecodedBytes=0;
  const appendProbeRecord=value=>{const bytes=Buffer.from(JSON.stringify(value)+'\n');fs.appendFileSync(path.join(out,probeTraceName),gzipSync(bytes));probeRecordCount++;probeDecodedBytes+=bytes.length;};
  const plan=browserPlan(),nativeChild=process.env.LOCALIZATION_NATIVE_CHILD==='1';
  if(options['pilot-families']==='true'){plan.cells.push(...PILOT_CELLS.map(cell=>({...cell})));plan.pilot={scope:PILOT_SCOPE,locales:PILOT_CELLS.map(cell=>cell.locale),classification:'Actual-program renderer-family diagnostics; German/Hebrew engineering assertions are separate from human/native linguistic acceptance'};}
  if(options.cell)assert.ok(plan.cells.some(c=>c.id===options.cell),'Unknown exact cell');
  if(options['ime-only']==='true')assert.ok(options.cell&&plan.cells.some(c=>c.id===options.cell&&c.kind==='ordinary'),'--ime-only requires one exact ordinary --cell');
  json('execution-plan.json',{...plan,argv:[process.execPath,...process.argv.slice(1)],options});const planIdentity=fileIdentity(path.join(out,'execution-plan.json'));
  const report={schemaVersion:2,kind:'localization-real-browser',status:'collecting',root,baseline,argv:[process.execPath,...process.argv.slice(1)],runtime:runtimeIdentity(),startedAt:new Date().toISOString(),cells:[],errors:[],screenshots:[],inputChecks:[],engines:{},planIdentity,external:plan.external.map(capability=>({capability,status:'unperformed',reason:'No human, AT, WebKit or physical-device execution provided by this producer'})),scope:plan.scope,focused:options.cell||null,methods:{actions:'Trusted Playwright pointer/keyboard only; scenario selection and diagnostic instrumentation explicitly untimed programmatic',copy:'Actual production raw values and real clipboard permission denial; separately declared CR/LF/empty raw-copy API inputs are never canonical/protocol evidence. Manual-control normalization requires an actual byte-verified UTF-8 download.',text200:'Qualified user-style simulation, not native text scaling; snapshots before writes, restores detached nodes and transitions, no mutation observer recalibration',network:'Shared exact-byte server/request allowlist and CSP instrumentation; no external runtime allowed',retention:'Exclusive new output, lossless gzip cell JSON and multi-member gzip JSONL probe records, per-cell failure retention; at most12 representative screenshots plus all failures; unchanged64MiB per stored artifact/512MiB total stored'}};
  report.imeOnlyDiagnostic=options['ime-only']==='true';
  const save=()=>json('browser-status.json',report),errorText=e=>String(e.stack||e);
  let server,launch,native,active,before,lock;
  let modulePath=path.resolve(options['playwright-module']||DEFAULT_PLAYWRIGHT),executablePath=path.resolve(options['chromium-executable']||DEFAULT_BROWSER);const libraryPath=options['library-path']||DEFAULT_LIBRARIES;
  const producerNames=['localization/browser-smoke.mjs','localization/browser-layout.mjs','localization/pilot-families.mjs','compact-mobile-browser.mjs','compact-native-zoom.mjs'];
  const identities=()=>({candidate:captureInputs(root),baseline:captureInputs(baseline),starting:fileIdentity(startingPath),authority:fileIdentity(path.join(root,'docs/localization/inputs/localization-worker-plan.html.input.txt')),producers:Object.fromEntries(producerNames.map(name=>{const file=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..',name);return [name,{path:file,...fileIdentity(file)}];})),runtime:fileIdentity(process.execPath),playwright:fileIdentity(modulePath),chromium:fileIdentity(executablePath),libraryPath});
  function inputs(label){const now=identities();assert.deepEqual(now,before,'Inputs unchanged '+label);assert.deepEqual(fileIdentity(path.join(out,'execution-plan.json')),planIdentity);report.inputChecks.push({label,status:'unchanged'});}
  function bounds(){let total=0;const walk=dir=>{for(const e of fs.readdirSync(dir,{withFileTypes:true})){const f=path.join(dir,e.name);if(e.isDirectory())walk(f);else{const size=fs.statSync(f).size;assert.ok(size<=64*1024*1024,'Artifact64MiB limit');total+=size;}}};walk(out);assert.ok(total<=512*1024*1024,'Artifact512MiB limit');}
  function raw(row,label,value){row.rawSerial=(row.rawSerial||0)+1;return compressedJson('raw/'+row.id+'-'+label+'-'+row.rawSerial+'.json.gz',value);}
  async function screenshot(row,failure=false){const limit=nativeChild?8:options['native-zoom']==='true'?4:12;if(!active||!failure&&report.screenshots.filter(s=>!s.failure).length>=limit)return;const name='screenshots/'+row.id+(failure?'-failure':'')+'.png';try{if(row.kind==='native')await native.screenshot(active.page,path.join(out,name));else await active.page.screenshot({path:path.join(out,name),fullPage:false,timeout:15000});report.screenshots.push({path:name,cell:row.id,failure,...fileIdentity(path.join(out,name))});}catch(e){row.screenshotError=errorText(e);}}
  async function probe(row,name,fn){const p={name,status:'attempted'};row.probes.push(p);save();try{p.result=await fn();p.status=p.result?.status==='unperformed'?'unperformed':'passed';}catch(e){p.status='failed';p.error=errorText(e);try{p.failureState=raw(row,'failed-probe-state',{study:await studyState(active.page),locale:await localeState(active.page),switch:await active.page.evaluate(()=>window.__localeSwitchDiagnostic||null)});}catch(diagnosticError){p.diagnosticError=errorText(diagnosticError);}await screenshot({...row,id:row.id+'-'+row.probes.length},true);try{await active.page.reload({waitUntil:'domcontentloaded'});await active.page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.localizer&&document.querySelector('auth-flow-studio')?.scenarioPicker);await settle(active.page);await setup(row);await choose(row,row.locale);const presentation=await active.page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode);if(presentation!==row.presentation)await click(row,'[data-presentation-choice='+JSON.stringify(row.presentation)+']');p.recovery={status:'performed',method:'Fresh document, declared default setup, original cell locale and presentation; failed state never reused'};}catch(recoveryError){p.recovery={status:'failed',error:errorText(recoveryError)};throw recoveryError;}}finally{appendProbeRecord({cell:row.id,...p});}return p;}
  async function action(row,name,fn,method='trusted pointer/keyboard'){const value=await fn();await settle(active.page);if(row.fixture==='text200'){row.enlargement??=[];row.enlargement.push(await text200(active.page));}row.actions.push({name,status:'performed',method});const events=active.evidence.trustedEvents;if(events.length>=80){assert.ok(!active.evidence.truncated,'Never discard a capped shared log');assert.ok(events.every(e=>e.trusted),'All observed input trusted');row.trustedChunks??=[];row.trustedChunks.push(raw(row,'trusted-input',events));events.length=0;}return value;}
  const click=(row,selector)=>action(row,'activate '+selector,()=>activate(active.page,selector,{touch:row.presentation==='compact'&&row.kind!=='native'}));
  const key=(row,value)=>action(row,'keyboard '+value,()=>active.page.keyboard.press(value));
  async function type(row,selector,text){await click(row,selector);await key(row,'ControlOrMeta+A');if(text)await action(row,'insert actual query',()=>active.page.keyboard.insertText(text));else await key(row,'Backspace');}
  async function choose(row,tag){const page=active.page,select=page.locator('#language-select'),values=await select.locator('option').evaluateAll(ns=>ns.map(n=>n.value));assert.ok(values.includes(tag));await click(row,'#language-select');await key(row,'Home');for(let i=0;i<values.indexOf(tag);i++)await key(row,'ArrowDown');await key(row,'Enter');assert.equal(await select.inputValue(),tag);await page.waitForFunction(tag=>document.querySelector('auth-flow-studio').localizer.locale===tag,tag);}
  async function setup(row,id='basic-keycloak',variant='default',boundary=null){await active.page.evaluate(({id,variant,boundary})=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario(id,{variant});if(boundary!==null)a.inspectQueueBoundary(boundary,'end');},{id,variant,boundary});await settle(active.page);row.setups.push({id,variant,boundary,method:'explicit untimed programmatic fixture setup'});}
  async function disclosures(row,selector){const n=active.page.locator(selector);assert.equal(await n.count(),1);if(!await n.evaluate(n=>n.open))await click(row,selector+' > summary');}
  const referenceNames=['presenter','player','queue','model','scenarioPicker','workspacePicker','snapshot','steps'];
  async function refs(page,install=false){return page.evaluate(install=>{const a=document.querySelector('auth-flow-studio'),nodes=[a.presenter,a.player,a.player.queue,a.labModel,a.scenarioPicker,a.workspacePicker,a.scenarioSnapshot(),a.steps];if(install){window.__localeRefs=nodes;window.__localeHeldSnapshot=JSON.stringify(a.heldView.snapshot());return null;}return nodes.map((n,i)=>n===window.__localeRefs[i]);},install);}
  async function assertReferences(page,label){const same=await refs(page),failed=referenceNames.filter((name,i)=>!same[i]);assert.deepEqual(failed,[],label+': changed references '+failed.join(', '));return same;}
  async function localeState(page){return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {picker:[a.scenarioPicker,a.workspacePicker].map(p=>({query:p.query,draft:p.draft,suspended:p.suspended,opened:p.opened,selectedId:p.selectedId})),attributeQuery:a.attributeQuery,help:a.heldView.helpOpen,disclosures:[...a.querySelectorAll('details')].map(n=>[n.id||n.dataset.compactDisclosure||n.dataset.compactOwner||n.dataset.pamDisclosure||null,n.open]),focus:document.activeElement.id,locale:a.localizer.locale,direction:a.localizer.direction,appLang:a.lang,studioLang:a.querySelector('#studio')?.lang,documentLang:document.documentElement.lang,storage:localStorage.getItem('auth-flow-studio.locale.v1')};});}
  async function switchDepth(row,{playing=false,explicit=true}={}){
    const page=active.page;let witness,ui,state;
    try{
      // Object/field replay can already be running even when the caller did not request Play.
      playing=playing||(await studyState(page)).player.status==='playing';
      if(playing){
        // Play may legitimately replace the queue. The locale boundary starts after Play.
        await page.evaluate(()=>document.querySelector('auth-flow-studio').player.setSpeed(.01));
        if((await studyState(page)).player.status!=='playing')await click(row,'#play');
        await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});
      }
      await refs(page,true);state=await studyState(page);ui=await localeState(page);
      const target=ui.locale==='en'?(row.locale==='en'?'he':row.locale):'en';
      if(playing){
        await armSwitchWitness(page);
        await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');window.__localeSnapshotUnsubscribe=a.player.subscribe(e=>{if(e.type==='state'&&e.status==='paused'){window.__localeRefs=[a.presenter,a.player,a.player.queue,a.labModel,a.scenarioPicker,a.workspacePicker,a.scenarioSnapshot(),a.steps];window.__localeHeldSnapshot=JSON.stringify(a.heldView.snapshot());}});});
      }
      await page.evaluate(({target,explicit})=>{window.__localeSwitchDiagnostic={target,explicit,before:{locale:document.querySelector('auth-flow-studio').localizer.locale,status:document.querySelector('auth-flow-studio').player.status},trustedStart:performance.now()};},{target,explicit});
      if(explicit)await choose(row,target);else await page.evaluate(tag=>document.querySelector('auth-flow-studio').changeLocale(tag,{explicit:false}),target);
      await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),w=window.__compactSwitchWitness;Object.assign(window.__localeSwitchDiagnostic,{after:{locale:a.localizer.locale,status:a.player.status},pauseEvents:w?.events,paused:w?.paused||null});});
      if(playing)witness=await finishSwitchWitness(page);else assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(state),'Paused exact canonical/queue continuity');
      await assertReferences(page,'Actual postpause locale boundary');
      const exactProjection=await page.evaluate(()=>({before:window.__localeHeldSnapshot,after:JSON.stringify(document.querySelector('auth-flow-studio').heldView.snapshot())}));
      assert.equal(exactProjection.after,exactProjection.before,'All canonical projected exact values unchanged at actual postpause boundary');row.projectionWitnesses??=[];row.projectionWitnesses.push({beforeSha256:sha256(exactProjection.before),afterSha256:sha256(exactProjection.after),snapshot:raw(row,'exact-projection',JSON.parse(exactProjection.after))});
      const after=await localeState(page);assert.equal(after.help,ui.help);assert.deepEqual(after.disclosures,ui.disclosures);assert.equal(after.attributeQuery,ui.attributeQuery);assert.deepEqual(after.picker,ui.picker);assert.equal(after.focus,explicit?'language-select':ui.focus);
      // Native anchoring settles on the first paint when a localized field match disappears.
      await settle(page);
      const scroll=await page.evaluate(()=>({x:scrollX,y:scrollY}));await settle(page);await settle(page);const settledScroll=await page.evaluate(()=>({x:scrollX,y:scrollY}));assert.deepEqual(settledScroll,scroll,'No repeated automatic scrolling after completed locale action');
      (row.localeScrollWitnesses??=[]).push({boundary:'After first completed paint, then two unchanged two-frame settles',before:scroll,after:settledScroll});
      await choose(row,ui.locale);await assertReferences(page,'Locale return');return {before:ui,after,witness,referenceNames};
    }finally{await page.evaluate(()=>{window.__localeSnapshotUnsubscribe?.();delete window.__localeSnapshotUnsubscribe;window.__compactSwitchWitness?.unsubscribe();delete window.__compactSwitchWitness;});}
  }
  async function shell(row){const page=active.page;await choose(row,row.locale);const value=await localeState(page);assert.equal(value.appLang,row.locale);assert.equal(value.direction,['he','ar-AE'].includes(row.locale)?'rtl':'ltr');assert.equal(value.storage,row.locale);if(value.studioLang)assert.equal(value.studioLang,row.locale);const surface=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {documentOwner:a.hasAttribute('data-document-owner'),title:a.querySelector('#scenario-title')?.textContent,description:a.querySelector('#scenario-description')?.textContent,languageName:a.querySelector('#language-label')?.textContent,selectLabelledBy:a.querySelector('#language-select')?.getAttribute('aria-labelledby'),fallbackSpans:[...a.querySelectorAll('#scenario-title [lang=\"en\"],#scenario-description [lang=\"en\"]')].map(n=>n.textContent)};});assert.ok(surface.title&&surface.description&&surface.languageName);assert.equal(surface.selectLabelledBy,'language-label');if(surface.documentOwner)assert.equal(value.documentLang,row.locale);if(row.locale!=='en')assert.deepEqual(surface.fallbackSpans,[]);return {metadata:value,surface};}
  async function search(row){const page=active.page;const queries=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),p=a.scenarioPicker,l=a.localizer;return p.options.map(o=>({id:o.id,entry:l.searchEntry('scenario',o.id,o,{scenarioId:o.id,variantId:'default',subfixtureId:null}),english:o.title}));});
    const native=queries.flatMap(o=>[o.entry?.title,...(o.entry?.searchTags||[])].filter(t=>typeof t==='string'&&t!==o.english&&/\p{L}/u.test(t)).map(query=>({...o,query}))).find(o=>row.locale==='en'||/[^\u0000-\u007f]/u.test(o.query)||o.query!==o.english);
    assert.ok(row.locale==='en'||native,'Actual active-catalog native query required, never English substitute');const source=native||queries[0],query=native?source.query:source.english;
    const state=await studyState(page);await type(row,'#lab-scenario-search',query);const result=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),p=a.scenarioPicker;return {query:p.query,ids:p.results.map(o=>o.id),active:p.results[p.activeIndex]?.id,selected:p.selectedId};});
    assert.ok(result.ids.includes(source.id),'Catalog-derived query matches actual production picker');assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(state),'Searching never selects/evaluates');
    await key(row,'Escape');const visits=[],unmatched=query+' 不存在73921';for(const q of ['', '   ',source.english,source.id,source.id.toUpperCase(),unmatched,'zzzzzz-no-localized-match-73921']){await type(row,'#lab-scenario-search',q);visits.push(await page.evaluate(()=>{const p=document.querySelector('auth-flow-studio').scenarioPicker;return {query:p.query,ids:p.results.map(o=>o.id),active:p.activeIndex};}));if(q===unmatched||q.startsWith('zzzzzz')){assert.deepEqual(visits.at(-1).ids,[]);await key(row,'Enter');assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(state));}await key(row,'Escape');}return {source,query,result,visits,querySource:'Actual active catalog; production picker performs matcher/ranking'};}
  async function fields(row){const page=active.page;await setup(row,'core');if(row.presentation==='compact'){await disclosures(row,'[data-compact-disclosure="fields"]');await click(row,'[data-compact-field-scope="global"]');}else if(!await page.locator('#attribute-index').isVisible())await click(row,'#index-open');
    const read=()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {total:a.attributeIndexRows.total,global:a.attributeIndexRows.global,rows:[...a.querySelectorAll('#attribute-index-list [data-index-attribute]')].map(n=>{const id=n.dataset.indexAttribute,name=a.definition(id).name,count=a.attributeUsage(a.steps,id).length,label=n.getAttribute('aria-label')||'',described=n.getAttribute('aria-describedby')||'',contextNodes=described.split(/\s+/).filter(Boolean).map(id=>({id,text:document.getElementById(id)?.textContent||null})),visibleCount=n.querySelector('.attribute-index-count')?.textContent;const issues=[];if(n.querySelector('code')?.textContent!==name)issues.push('technical-name');if(visibleCount!==String(count))issues.push('current-source-count');if(!label.includes(name))issues.push('accessible-technical-name');if(!new RegExp('(?:^|[^0-9])'+count+'(?:[^0-9]|$)').test(label.replace(name,'')))issues.push('accessible-current-count');if(!contextNodes.length||contextNodes.some(c=>!c.text?.trim()))issues.push('missing-accessible-context');return {id,name:n.querySelector('code')?.textContent,expected:name,currentSourceSteps:count,visibleCount,label,described,controls:n.getAttribute('aria-controls'),shortcut:n.getAttribute('aria-keyshortcuts'),contextNodes,issues};})};});
    const initial=await read();row.fieldAccessibility=raw(row,'field-accessibility',initial);const failedRows=initial.rows.filter(n=>n.issues.length);row.failedFieldRows=failedRows;assert.equal(initial.total,10843,'Current global definition count, not translation count');assert.deepEqual(failedRows,[],'Exact technical names, independent current counts and nonempty accessible context; see retained per-row diagnostics');
    if(row.presentation==='compact'){assert.equal(initial.rows.length,40);await click(row,'[data-compact-field-more]');assert.equal((await read()).rows.length,80);}
    const localizedField=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return [...a.querySelectorAll('#attribute-index-list [data-index-attribute]')].map(n=>{const id=n.dataset.indexAttribute,d=a.definition(id),entry=a.localizer.searchEntry('field',id,d,a.localeContext());return {id,query:entry?.meaning||entry?.purpose||entry?.origin,english:d.meaning||d.purpose||d.origin};}).find(r=>r.query&&r.query!==r.english);});
    if(row.locale!=='en'){assert.ok(localizedField,'Actual active-catalog field query, never English substitute');await type(row,'#attribute-search',localizedField.query);assert.ok(await page.locator('[data-index-attribute='+JSON.stringify(localizedField.id)+']').count(),'Actual production field matcher returns localized field');await switchDepth(row,{explicit:false});await type(row,'#attribute-search','');}
    const used=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return a.steps.flatMap(step=>step.fields||[]).find(id=>a.attributeUsage(a.steps,id).length);});assert.ok(used,'Actual authored field has source usage');if(!await page.locator('[data-index-attribute='+JSON.stringify(used)+']').count())await type(row,'#attribute-search',used);
    const selector='[data-index-attribute='+JSON.stringify(used)+']';await click(row,selector);if(row.presentation==='compact'){assert.equal(await page.locator('#compact-field-definition').isVisible(),true);await switchDepth(row);await click(row,'[data-compact-field-trace='+JSON.stringify(used)+']');}else{await key(row,'F2');assert.equal(await page.locator('#attribute-popup').isVisible(),true);await switchDepth(row,{explicit:false,playing:(await studyState(page)).player.status==='playing'});await key(row,'Escape');}
    const current=await studyState(page);if(row.presentation==='compact'){assert.equal(current.trace.attribute,used);await switchDepth(row);await click(row,'[data-compact-action="return"]');}
    return {initial:raw(row,'field-accessibility',initial),expanded:row.presentation==='compact'?80:null,field:used,scopeState:current};}
  async function copyDownload(row,selector,value,suffix){
    const pending=active.page.waitForEvent('download');await click(row,selector);const download=await pending;
    const filename=path.join(out,'downloads',row.id+'-'+suffix+'.txt');fs.mkdirSync(path.dirname(filename),{recursive:true});await download.saveAs(filename);
    const actual=fs.readFileSync(filename);assert.deepEqual(actual,Buffer.from(value),'Downloaded UTF-8 preserves every raw byte');
    return {suggestedFilename:download.suggestedFilename(),file:fileIdentity(filename),method:'Actual production download link, trusted pointer action, completed browser download and saved-byte equality'};
  }
  async function denyClipboard(row){
    const page=active.page,cdp=await page.context().newCDPSession(page);let browserContextId;
    try{
      ({targetInfo:{browserContextId}}=await cdp.send('Target.getTargetInfo'));assert.ok(browserContextId,'Actual isolated page browser context');
      await cdp.send('Browser.setPermission',{permission:{name:'clipboard-write'},setting:'denied',browserContextId});
      const permission=await page.evaluate(async()=>(await navigator.permissions.query({name:'clipboard-write'})).state);assert.equal(permission,'denied','Real page clipboard-write permission is denied');
      row.setups.push({permission:'clipboard-write',state:permission,browserContextId,method:'explicit untimed actual CDP permission setup verified by navigator.permissions'});
      return {cdp,browserContextId,permission};
    }catch(error){try{if(browserContextId)await cdp.send('Browser.resetPermissions',{browserContextId});}finally{await cdp.detach();}throw error;}
  }
  async function copyBoundaries(row){const page=active.page;if(row.presentation!=='compact')return {status:'unperformed',reason:'Production Compact controls exercised in Compact cells'};
    await setup(row,'lab-jwt03','invalid-inner-signature',3);
    const fixtures=[{id:'crlf',value:'first\r\nsecond\rthird\n'},{id:'empty',value:''}];
    // These are declared raw-copy API boundary inputs, not authored protocol values or future holdings.
    await page.evaluate(fixtures=>{const a=document.querySelector('auth-flow-studio'),region=document.createElement('section');region.id='localization-copy-boundary-fixture';region.setAttribute('aria-label','Diagnostic raw-copy boundary fixtures, not protocol evidence');for(const f of fixtures){const pre=document.createElement('pre');pre.id='localization-copy-'+f.id;pre.dataset.copyRawJson=JSON.stringify(f.value);pre.dir='ltr';pre.translate=false;pre.textContent=f.value;region.append(pre);}a.compactView.root.append(region);a.compactView.addCopyControls();},fixtures);
    row.setups.push({fixture:'Declared CR/LF/empty raw-copy API boundary inputs, not protocol evidence',method:'explicit untimed programmatic fixture setup'});
    const evidence=[],{cdp,browserContextId,permission}=await denyClipboard(row);
    try{for(const f of fixtures){
      const token=await page.locator('#localization-copy-'+f.id).getAttribute('data-compact-value');await click(row,'[data-compact-copy='+JSON.stringify(token)+']');
      const field=page.locator('#localization-copy-boundary-fixture [data-exact-copy-fallback]');let method,download;
      if(f.value.includes('\r')){
        const selector='#localization-copy-boundary-fixture [data-exact-copy-download]';await page.locator(selector).waitFor({state:'visible'});assert.equal(await field.count(),0,'Never offer normalized text as the exact raw value');
        download=await copyDownload(row,selector,f.value,'boundary-'+f.id);method='Byte-exact UTF-8 export after real clipboard denial and textarea normalization';
      }else{
        await field.waitFor({state:'visible'});assert.equal(await field.inputValue(),f.value,'Manual fallback preserves the exact representable raw value');assert.equal(await field.evaluate(n=>n.selectionStart),0);assert.equal(await field.evaluate(n=>n.selectionEnd),f.value.length);method='Selected exact production textarea after real clipboard denial';
      }
      evidence.push({id:f.id,rawUtf8Base64:Buffer.from(f.value).toString('base64'),sha256:sha256(f.value),method,...(download?{download}:{})});
    }}
    finally{await cdp.send('Browser.resetPermissions',{browserContextId});await cdp.detach();await page.evaluate(()=>{document.querySelector('auth-flow-studio').releaseExactCopyDownload();document.getElementById('localization-copy-boundary-fixture')?.remove();});}
    return {classification:'Explicit synthetic raw-copy API boundary inputs only, never canonical/protocol evidence',permission,fixtures:evidence};}
  async function unreadable(row){
    const page=active.page;await setup(row);const finalBoundary=await page.evaluate(()=>document.querySelector('auth-flow-studio').steps.length-1);assert.ok(finalBoundary>=0);
    await setup(row,'basic-keycloak','default',finalBoundary);
    const boundary=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),snapshot=a.heldView.snapshot();return {cursor:snapshot.cursor,holdings:snapshot.holdings.map(holding=>{const artifact=snapshot.artifacts.find(item=>item.artifactId===holding.artifactId),representation=artifact.representations.find(item=>item.representationId===holding.representationId),unreadable=representation.fields.filter(field=>!representation.readableBy.includes(holding.actorId)||field.readableBy!==undefined&&!field.readableBy.includes(holding.actorId)).map(field=>({attributeId:field.attributeId,name:field.name||a.definition(field.attributeId).name,readable:false}));return {holding,representation:{id:representation.representationId,format:representation.format,readableBy:representation.readableBy},unreadable};})};});
    row.unreadableBoundary=boundary;const found=boundary.holdings.find(item=>item.unreadable.length);assert.ok(found,'Actual current authored unreadable representation, discovered by representation/field permissions; see unreadableBoundary');
    // Core HttpOnly browser-cookie holdings have restricted fields. JWT wire ciphertext,
    // by contrast, is deliberately readable as ciphertext and cannot prove field redaction.
    if(row.presentation==='compact'){await disclosures(row,'[data-compact-disclosure="holdings"]');await disclosures(row,'[data-compact-owner='+JSON.stringify(found.holding.actorId)+']');}
    else await click(row,'#held-objects [data-held-action='+JSON.stringify('picker:'+found.holding.actorId)+']');
    await click(row,'#held-objects [data-holding-id='+JSON.stringify(found.holding.holdingId)+']');const controls=await page.locator('#held-inspector [data-copy-disabled="unreadable"]').evaluateAll(ns=>ns.map(n=>({text:n.textContent,raw:n.hasAttribute('data-copy-raw-json'),copy:n.parentElement.querySelector('[data-compact-copy]')!==null})));assert.equal(controls.length,found.unreadable.length);assert.ok(controls.every(c=>!c.raw&&!c.copy),'Unreadable representation never exports/copies protected value');await switchDepth(row);return {source:found,cursor:boundary.cursor,controls};
  }
  async function draftDepth(row){const visits=[];for(const query of ['client_id','','   ']){await type(row,'#lab-scenario-search',query);const forward=await switchDepth(row,{explicit:false});visits.push({query,forward});await key(row,'Escape');}return visits;}
  async function imeBoundaries(row){
    const page=active.page;await setup(row);
    if(row.presentation==='compact')await disclosures(row,'[data-compact-disclosure="fields"]');
    else{
      if(!await page.locator('#attribute-index').isVisible())await click(row,'#index-open');
      await disclosures(row,'#ready-journeys');await disclosures(row,'#lab-catalog');
    }
    const discovered=await page.locator('auth-flow-studio input[type="search"]').evaluateAll(nodes=>nodes.map(node=>({id:node.id,visible:node.checkVisibility()})));
    const attempts=[];row.imeAttempts=attempts;
    const method='Chromium CDP browser IME boundary; not OS/human IME';
    const cdp=await page.context().newCDPSession(page),send=(name,args)=>action(row,'IME '+name,()=>cdp.send(name,args),method);
    const read=selector=>page.evaluate(selector=>{const a=document.querySelector('auth-flow-studio'),input=document.querySelector(selector),picker=[a.scenarioPicker,a.workspacePicker].find(p=>p.input===input);return {raw:input?.value,locale:a.localizer.locale,pending:a.pendingLocale?{tag:a.pendingLocale.tag,explicit:a.pendingLocale.explicit}:null,compositionCount:a.localeCompositions.size,pickerComposing:picker?.composing||false,query:picker?picker.query:input?.id==='attribute-search'?a.attributeQuery:input?.id==='lab-search'?a.catalogQuery:a.glossaryQuery,selected:[a.scenarioPicker.selectedId,a.workspacePicker.selectedId],events:window.__localeIME?.events||[],javascriptDispatches:window.__localeIME?.dispatches||[]};},selector);
    await page.evaluate(()=>{
      const types=['compositionstart','compositionupdate','compositionend','beforeinput','input','keydown'],state=window.__localeIME={events:[],dispatches:[],activeDispatches:new WeakSet(),originalDispatch:EventTarget.prototype.dispatchEvent};
      state.instrumentedDispatch=function(event){if(types.includes(event.type)){state.dispatches.push({type:event.type,target:this.id||null,searchInput:!!this.matches?.('auth-flow-studio input[type="search"]')});state.activeDispatches.add(event);}try{return state.originalDispatch.call(this,event);}finally{state.activeDispatches.delete(event);}};
      EventTarget.prototype.dispatchEvent=state.instrumentedDispatch;
      state.listener=event=>{if(!event.target.matches?.('auth-flow-studio input[type="search"]'))return;state.events.push({type:event.type,target:event.target.id,trusted:event.isTrusted,javascriptDispatch:state.activeDispatches.has(event),key:event.key,keyCode:event.keyCode,isComposing:event.isComposing,data:event.data,inputType:event.inputType,value:event.target.value});};
      for(const type of types)document.addEventListener(type,state.listener,true);
    });
    try{
      for(const input of discovered){
        if(!input.visible||!input.id){for(const ending of ['commit','cancel'])attempts.push({id:input.id,ending,status:'unperformed',reason:input.id?'Search input not visible on this actual presentation; no synthetic focus or hidden input interaction':'Actual search input lacks a stable authored ID'});continue;}
        const selector='#'+input.id;
        for(const ending of ['commit','cancel']){
          const record={id:input.id,ending,status:'attempted',method},evidence={};attempts.push(record);
          try{
            // The prior attempt's real Escape closes Compact's containing field disclosure.
            if(input.id==='attribute-search'&&row.presentation==='compact')await disclosures(row,'[data-compact-disclosure="fields"]');
            await type(row,selector,'client_id  ');await page.evaluate(()=>{window.__localeIME.events=[];window.__localeIME.dispatches=[];});
            evidence.before=await studyState(page);evidence.initial=await read(selector);await refs(page,true);
            const original=evidence.initial.locale,target=original==='en'?'he':'en',composition='日本語',expected='client_id  '+(ending==='commit'?composition:'');
            await send('Input.imeSetComposition',{text:composition,selectionStart:composition.length,selectionEnd:composition.length});
            evidence.composing=await read(selector);
            assert.ok(evidence.composing.compositionCount>0,'Actual browser compositionstart reached application');
            assert.equal(evidence.composing.raw,'client_id  '+composition,'Raw draft retains exact uncommitted composition');
            assert.ok(evidence.composing.events.some(e=>e.type==='compositionstart'&&e.trusted),'Browser-generated trusted compositionstart');
            await send('Input.dispatchKeyEvent',{type:'rawKeyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:229,nativeVirtualKeyCode:229});
            await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:229,nativeVirtualKeyCode:229});
            evidence.enter=await read(selector);
            assert.ok(evidence.enter.events.some(e=>e.type==='keydown'&&e.key==='Enter'&&e.keyCode===229&&e.trusted),'Actual trusted Enter229 observed');
            assert.deepEqual(evidence.enter.selected,evidence.initial.selected,'Enter229 cannot select either picker');
            assert.deepEqual(continuityProjection(await studyState(page)),continuityProjection(evidence.before),'IME/Enter229 cannot change canonical model or queue');
            evidence.localeRequest=await page.evaluate(tag=>document.querySelector('auth-flow-studio').changeLocale(tag,{explicit:false}),target);
            evidence.deferred=await read(selector);
            assert.equal(evidence.deferred.locale,original,'Display locale remains unchanged during actual composition');
            assert.equal(evidence.deferred.pending?.tag,target,'Distinct locale request is actually deferred');
            assert.equal(evidence.deferred.raw,'client_id  '+composition,'Deferred locale preserves raw composing draft');
            if(ending==='commit')await send('Input.insertText',{text:composition});
            else await send('Input.imeSetComposition',{text:'',selectionStart:0,selectionEnd:0});
            await page.waitForFunction(tag=>document.querySelector('auth-flow-studio').localizer.locale===tag,target);
            evidence.after=await read(selector);evidence.final=await studyState(page);
            assert.equal(evidence.after.compositionCount,0,'Actual composition end/cancel clears composition guard');
            const starts=evidence.after.events.filter(e=>e.type==='compositionstart'),ends=evidence.after.events.filter(e=>e.type==='compositionend');
            assert.equal(starts.length,1,'Exactly one actual browser compositionstart');
            assert.equal(ends.length,1,'Exactly one actual browser compositionend');
            assert.ok(evidence.after.events.indexOf(starts[0])<evidence.after.events.indexOf(ends[0]),'Actual compositionend follows actual compositionstart');
            assert.deepEqual(evidence.after.javascriptDispatches.filter(e=>e.searchInput),[],'No JavaScript-dispatched IME/input/keyboard events');
            assert.ok(evidence.after.events.every(e=>!e.javascriptDispatch&&(e.trusted||e.type==='compositionend')),'All observed input trusted except Chromium-native compositionend; raw trust bits retained');
            // Chromium's native DispatchScopedEvent path can emit compositionend with
            // isTrusted=false. Do not relabel it or mistake that engine flag for a JS event.
            evidence.compositionEndOrigin={observedIsTrusted:ends[0].trusted,javascriptDispatch:ends[0].javascriptDispatch,source:'https://issues.chromium.org/issues/40666368',classification:'Actual Chromium composition end, not fabricated/synthetic trusted input'};
            assert.equal(evidence.after.raw,expected,'Exact raw committed/cancelled draft survives deferred locale commit');
            assert.equal(evidence.after.query,expected,'Actual search draft state matches exact raw input');
            assert.deepEqual(evidence.after.selected,evidence.initial.selected,'IME end and locale commit never select a scenario');
            assert.deepEqual(continuityProjection(evidence.final),continuityProjection(evidence.before),'Exact canonical model/queue continuity through IME and deferred locale');
            await assertReferences(page,'IME deferred locale commit');
            await page.evaluate(tag=>document.querySelector('auth-flow-studio').changeLocale(tag,{explicit:false}),original);
            assert.equal(await page.locator(selector).isVisible(),true,'Locale roundtrip keeps the originally visible composing control visible before Escape cleanup');
            await type(row,selector,'');await key(row,'Escape');record.status='passed';
          }catch(error){record.status='failed';record.error=errorText(error);throw error;}
          finally{try{evidence.lastObserved=await read(selector);}catch(error){evidence.lastObservedError=errorText(error);}record.evidence=raw(row,'ime-'+input.id+'-'+ending,evidence);}
        }
      }
      assert.ok(attempts.some(a=>a.status==='passed'),'At least one actual search input exercised');
      return {method,discovered,attempts,unperformed:['OS/human IME installation and candidate-window interaction','Physical keyboard/platform IME acceptance']};
    }finally{
      for(const input of discovered)for(const ending of ['commit','cancel'])if(!attempts.some(a=>a.id===input.id&&a.ending===ending))attempts.push({id:input.id,ending,status:'unperformed',reason:'Collection stopped at an earlier retained failure; no later input interaction attempted'});
      row.imeScope={classification:method,compositionEndTrustPolicy:{source:'https://issues.chromium.org/issues/40666368',policy:'Preserve engine isTrusted bit; require actual ordered composition events and zero JS-dispatched search input events. Never mark a false bit true.'},discovered,unperformed:attempts.filter(a=>a.status==='unperformed'),externalUnperformed:['OS/human IME installation and candidate-window interaction','Physical keyboard/platform IME acceptance']};
      await page.evaluate(()=>{const state=window.__localeIME;if(!state)return;for(const type of ['compositionstart','compositionupdate','compositionend','beforeinput','input','keydown'])document.removeEventListener(type,state.listener,true);if(EventTarget.prototype.dispatchEvent!==state.instrumentedDispatch)throw new Error('IME dispatch observer changed during collection');EventTarget.prototype.dispatchEvent=state.originalDispatch;});
      await cdp.detach();
    }
  }
  async function selectedReplay(row){
    const page=active.page;await setup(row,'basic-keycloak','default',1);if(row.presentation==='compact')await click(row,'[data-presentation-choice="full"]');await page.evaluate(()=>document.querySelector('auth-flow-studio').player.setSpeed(.01));await click(row,'#follow');await click(row,'[data-replay]');await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});
    const language=await switchDepth(row,{playing:true});
    await click(row,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');
    let compact;await armSwitchWitness(page);try{await click(row,'[data-presentation-choice="compact"]');row.replaySwitchDiagnostic=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),w=window.__compactSwitchWitness;return {before:w.before,paused:w.paused,pauseEvents:w.events,after:window.__compactReadStudyState(),locale:a.localizer.locale};});compact=await finishSwitchWitness(page);}finally{await page.evaluate(()=>{window.__compactSwitchWitness?.unsubscribe();delete window.__compactSwitchWitness;});}
    await switchDepth(row);await click(row,'[data-presentation-choice="full"]');const state=await studyState(page);assert.equal(state.player.queue.length,1,'Selected-action replay remains a one-row queue');await click(row,'#follow');assert.notEqual((await studyState(page)).player.status,'playing','Follow is inspection only');if(row.presentation==='compact')await click(row,'[data-presentation-choice="compact"]');await choose(row,row.locale);return {language,compact,state};
  }
  async function protocolBoundaries(row){const page=active.page,results=[];for(const id of ['lab-dnssec15','lab-mcp09','lab-smb-multichannel-binding-success']){await setup(row,id,id==='lab-dnssec15'?'rfc5011-add':'default',1);const chapter=page.locator('[data-lesson-chapter]:visible:not(:disabled)').first();if(await chapter.count())await action(row,'trusted chapter '+id,()=>chapter.click());const crypto=page.locator('[data-learning-detail="crypto"]:visible').first();if(await crypto.count())await action(row,'trusted cryptographic detail '+id,()=>crypto.click());const summaries=page.locator('#lesson-decisions details:visible > summary,#lesson-chapters details:visible > summary');for(let i=0;i<Math.min(3,await summaries.count());i++)if(!await summaries.nth(i).evaluate(n=>n.parentElement.open))await action(row,'trusted comparison disclosure '+id,()=>summaries.nth(i).click());const before=await studyState(page);await switchDepth(row);const after=await studyState(page);assert.deepEqual(continuityProjection(after),continuityProjection(before));results.push({id,before,after,rendered:await page.locator('#lesson-decisions').textContent()});}return raw(row,'protocol-boundaries',results);}
  async function copies(row,deny=false){const page=active.page;if(row.presentation!=='compact')return {status:'unperformed',reason:'Compact production exact-value buttons are exercised in Compact cells; Full technical names checked separately'};
    if(row.kind==='ordinary')await setup(row,'lab-jwt03','invalid-inner-signature',3);
    // Configuration exposes actual applied values even after a failed probe reload clears inspector state.
    await disclosures(row,'[data-compact-disclosure="configuration"]');
    await disclosures(row,'[data-compact-disclosure="data"]');const values=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return [...a.querySelectorAll('[data-compact-copy]')].filter(n=>n.checkVisibility()).map(n=>({token:n.dataset.compactCopy,value:a.compactView.copyValues.get(n.dataset.compactCopy)}));});assert.ok(values.length,'Real permitted copy target');
    const target=values.find(v=>typeof v.value==='string'&&v.value.length>20)||values[0];assert.equal(typeof target.value,'string');assert.ok(!/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(target.value),'Raw copy contains no injected bidi controls');
    let denial;if(deny)denial=await denyClipboard(row);
    await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),original=a.copyExactValue;window.__localeCopyOriginal=original;window.__localeCopy=[];window.__localeCopySettled=false;a.copyExactValue=function(value,trigger){window.__localeCopy.push(value);return original.call(this,value,trigger).finally(()=>{window.__localeCopySettled=true;});};});
    try{await click(row,'[data-compact-copy='+JSON.stringify(target.token)+']');await page.waitForFunction(()=>window.__localeCopySettled);assert.equal(await page.evaluate(()=>window.__localeCopy.at(-1)),target.value);
      const fallback=page.locator('[data-exact-copy-fallback]:visible'),downloadLink=page.locator('[data-exact-copy-download]:visible');let method,download;
      if(await fallback.count()){assert.equal(await fallback.last().inputValue(),target.value);assert.equal(await fallback.last().getAttribute('dir'),'ltr');method='actual production manual fallback';}
      else if(await downloadLink.count()){download=await copyDownload(row,'[data-exact-copy-download]:visible',target.value,deny?'production-denied':'production');method='actual byte-exact production UTF-8 download fallback';}
      else{assert.equal(deny,false,'Denied clipboard must expose real exact fallback');await page.context().grantPermissions(['clipboard-read']);assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),target.value);method='actual clipboard readback';}
      const categories={CR:values.filter(v=>v.value?.includes('\r')),LF:values.filter(v=>v.value?.includes('\n')),empty:values.filter(v=>v.value==='')};return {method,...(download?{download}:{}),permissionDenied:deny,rawUtf8Base64:Buffer.from(target.value).toString('base64'),sha256:sha256(target.value),categories:Object.fromEntries(Object.entries(categories).map(([kind,rows])=>[kind,{status:rows.length?'observed-not-all-copied':'unperformed',actualValues:rows.map(v=>({token:v.token,utf8Base64:Buffer.from(v.value).toString('base64')})),reason:rows.length?null:'No actual authored value of this class on exercised surface'}])),unreadable:{status:'unperformed',reason:'No unreadable representation was selected on this fixture; no permission evidence invented'}};
    }finally{await page.evaluate(()=>{document.querySelector('auth-flow-studio').copyExactValue=window.__localeCopyOriginal;delete window.__localeCopyOriginal;delete window.__localeCopy;delete window.__localeCopySettled;});if(denial){await denial.cdp.send('Browser.resetPermissions',{browserContextId:denial.browserContextId});await denial.cdp.detach();}}}
  async function objectScope(row){
    const page=active.page;await setup(row,'lab-dnssec15','rfc5011-add',24);
    const available=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),v=a.heldView,s=v.snapshot();return {cursor:s.cursor,holdings:s.holdings.map(h=>({holdingId:h.holdingId,actorId:h.actorId,artifactId:h.artifactId,traceSteps:v.buildTrace(h.artifactId).length}))};});
    row.objectBoundary=available;const holding=available.holdings.find(h=>h.actorId==='dnsResolver'&&h.traceSteps)||available.holdings.find(h=>h.traceSteps);assert.ok(holding,'An actually current authored holding with trace at the declared DNS boundary; see objectBoundary');
    if(row.presentation==='compact'){await disclosures(row,'[data-compact-disclosure="holdings"]');await disclosures(row,'[data-compact-owner='+JSON.stringify(holding.actorId)+']');}
    else await click(row,'#held-objects [data-held-action='+JSON.stringify('picker:'+holding.actorId)+']');
    const selector='#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']';assert.ok(await page.locator(selector).count(),'Current authored holding has a rendered control');await click(row,selector);await click(row,'#held-inspector [data-held-trace]');assert.equal((await studyState(page)).studyQueue.kind,'object');await switchDepth(row);let help=page.locator('[data-held-help]').first();assert.ok(await help.count());await action(row,'trusted help open',()=>help.click());await switchDepth(row,{explicit:false});await click(row,'[data-held-help-close]');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.helpOpen),false);help=page.locator('[data-held-help]').first();await action(row,'trusted help reopen',()=>help.click());await key(row,'Escape');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.helpOpen),false);return {holding,boundary:available.cursor,state:await studyState(page)};
  }
  async function connectionScope(row){const page=active.page;await setup(row);if(row.presentation==='compact')await click(row,'[data-presentation-choice="full"]');const node=page.locator('.connection-hit[tabindex="0"]').first();assert.ok(await node.count(),'Actual connection scope control');await node.focus();assert.equal(await node.evaluate(n=>document.activeElement===n),true);await action(row,'trusted connection scope keyboard Enter',()=>page.keyboard.press('Enter'));await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');await click(row,'#play');if(row.presentation==='compact')await click(row,'[data-presentation-choice="compact"]');await switchDepth(row);return {state:await studyState(page),entry:'Actual focusable graph path, trusted keyboard Enter; no bounding-box or forced click'};}
  async function geometry(row){const value=await layoutSnapshot(active.page),evidence=raw(row,'geometry',value);assert.ok(value.document.scrollWidth<=value.document.width+1&&value.document.bodyScrollWidth<=value.document.width+1,'No page horizontal overflow');assert.ok(value.targets.length,'Actual controls');if(row.presentation==='compact')assert.deepEqual(value.smallTargets,[],'Compact44px controls');assert.deepEqual(value.unreadableValues,[],'Visible protected values readable without clipping');assert.deepEqual(value.duplicateIds,[]);assert.ok(value.focus.connected&&value.focus.fullyVisible&&value.focus.sampledAreaUsable&&value.focus.hit.every(p=>p.hit)&&value.focus.outerHit.every(p=>p.hit||p.ownedReservedAffordance),'Actual current focus and editable content are visible, connected and unobscured; only component-owned buttons wholly inside reserved padding are non-obstructions');return evidence;}
  async function collect(cell){const row={...cell,status:'attempted',probes:[],actions:[],setups:[],startedAt:new Date().toISOString()};report.cells.push(row);save();try{inputs('before '+row.id);active=await createBrowserSession({browser:cell.kind==='native'?native.browser:launch.browser,server,rootName:'candidate',root,identity:before.candidate,loadingMode:row.loadingMode,viewport:cell.kind==='native'?null:{width:cell.width,height:cell.presentation==='full'?1000:844},touch:cell.presentation==='compact'&&cell.kind!=='native',preference:cell.presentation,diagnostic:true});
      if(cell.kind==='pilot')await installPilotCapture(active.page);
      // The shared helper has a200-event cap. Retain this collector's full trusted log separately without weakening that cap.
      row.target=active.target;row.browserEvidence=active.evidence;await active.page.addInitScript(tag=>localStorage.setItem('auth-flow-studio.locale.v1',tag),row.locale);await active.page.goto(active.target,{waitUntil:'domcontentloaded'});await active.page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.presenter&&a.player&&a.scenarioPicker&&a.localizer;});await settle(active.page);await setup(row);
      if(options['ime-only']==='true'){row.diagnosticOnly={scope:'IME plus trusted input/CSP/exact loader',unperformed:['Selected-language shell','Catalog/draft search acceptance','Non-IME locale roundtrips','Fields/object/connection/copy/replay/protocol/layout/zero-fallback acceptance'],matrixAcceptance:false};await probe(row,'Chromium IME commit/cancel deferred locale and Enter229 boundaries',()=>imeBoundaries(row));}
      else if(cell.kind==='pilot')await probe(row,'source renderer-family requests and actual surface witnesses',()=>capturePilotFamilies({page:active.page,action,settle,raw,row}));
      else await probe(row,'selected language shell',()=>shell(row));
      if(cell.kind==='ordinary'&&options['ime-only']!=='true'){
        await probe(row,'native catalog search and nonselecting drafts',()=>search(row));
        await probe(row,'nonempty empty whitespace drafts and focused API switch',()=>draftDepth(row));
        await probe(row,'Chromium IME commit/cancel deferred locale and Enter229 boundaries',()=>imeBoundaries(row));
        await probe(row,'paused locale roundtrip',()=>switchDepth(row));
        await probe(row,'partial elapsed exact postpause locale switch',()=>switchDepth(row,{playing:true}));
        await probe(row,'field accessibility10843 and Compact40-to80/definition-first',()=>fields(row));
        await probe(row,'exact object scope and help retention',()=>objectScope(row));
        await probe(row,'connection scope retention',()=>connectionScope(row));
        await probe(row,'real raw copy',()=>copies(row));
        await probe(row,'actual clipboard denied fallback',()=>copies(row,true));
        await probe(row,'CR LF empty production copy boundary inputs',()=>copyBoundaries(row));
        await probe(row,'actual unreadable permission projection has no copy',()=>unreadable(row));
        await probe(row,'selected-action replay language and view roundtrips',()=>selectedReplay(row));
        await probe(row,'DNSSEC MCP chapters comparisons and SMB crypto',()=>protocolBoundaries(row));
        await probe(row,'repeated RTL LTR language switching',async()=>{const sequence=[row.locale,'en','he','ar-AE','he','en',row.locale],samples=[];await refs(active.page,true);const initial=await studyState(active.page);for(let repetition=0;repetition<3;repetition++)for(const tag of sequence){await choose(row,tag);const sample=await active.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {locale:a.localizer.locale,nodes:document.querySelectorAll('*').length,diagnostics:a.localizer.diagnostics(),scheduled:{frame:a.player.handle!=null,timer:a.player.timer!=null}};});assert.ok(sample.diagnostics.inactiveParsedCatalogs<=1,'Only English plus active parsed resource');assert.ok(sample.diagnostics.activeSourceMatchers<=sample.diagnostics.sourceMatcherLimit);assert.deepEqual(sample.scheduled,{frame:false,timer:false});samples.push(sample);}assert.ok((await refs(active.page)).every(Boolean));assert.deepEqual(continuityProjection(await studyState(active.page)),continuityProjection(initial));return {sequence,repetitions:3,samples,state:await studyState(active.page),retentionScope:'Same references, bounded catalog/matcher counters and no player scheduling. Not a heap/listener/observer leak proof or performance acceptance.'};});
      }else if(cell.kind!=='pilot'&&options['ime-only']!=='true'){
        if(['long-text','text200','native400'].includes(row.fixture))await setup(row,'lab-jwt03','invalid-inner-signature',3);
        if(row.fixture==='text200')row.enlargement=[await text200(active.page)];
        if(row.kind==='native')row.nativeZoom=await native.apply(active.page,row.id);
        await probe(row,'trusted disclosure/search after layout calibration',async()=>{await search(row);return geometry(row);});
        await probe(row,'trusted exact copy after enlargement',async()=>{if(row.presentation==='compact')await disclosures(row,'[data-compact-disclosure="configuration"]');const result=await copies(row);return {...result,fixture:'Actual applied Core/context values in the production configuration disclosure; not inherited inspector state, a future credential or an injected value'};});
      }
      if(cell.kind!=='pilot'&&options['ime-only']!=='true')await probe(row,'real layout',()=>geometry(row));
      if(cell.kind!=='pilot'&&options['ime-only']!=='true')await probe(row,'exercised diagnostics have zero fallback',async()=>{const d=await active.page.evaluate(()=>document.querySelector('auth-flow-studio').localizer.diagnostics());assert.deepEqual(d.fallbacks,[],'English fallback is not translation');return d;});
      await probe(row,'trusted inputs/CSP/offline exact loader',async()=>{assertClean(active.evidence);assert.ok(active.evidence.trustedEvents.some(e=>e.trusted)||row.trustedChunks?.length);assert.ok(active.evidence.trustedEvents.every(e=>e.trusted));assert.deepEqual(server.errors,[]);return {evidence:active.evidence,trustedChunks:row.trustedChunks||[]};});
      row.finalState=raw(row,'final-state',await studyState(active.page));if(row.locale==='he'||row.locale==='ar-AE'||row.fixture==='long-text')await screenshot(row);
    }catch(e){row.error=errorText(e);}finally{row.status=row.error||row.probes.some(p=>p.status==='failed')?'failed':'passed';if(row.status==='failed')await screenshot(row,true);if(active){await active.close().catch(e=>{row.cleanupError=errorText(e);row.status='failed';});active=null;}try{inputs('after '+row.id);}catch(e){row.inputError=errorText(e);row.status='failed';}row.finishedAt=new Date().toISOString();const evidence=compressedJson('cells/'+row.id+'.json.gz',row);report.cells[report.cells.indexOf(row)]={id:row.id,kind:row.kind,locale:row.locale,presentation:row.presentation,loadingMode:row.loadingMode,status:row.status,evidencePath:evidence.path,evidenceEncoding:'gzip-json',evidenceIdentity:{bytes:evidence.bytes,sha256:evidence.sha256},decodedEvidenceIdentity:{bytes:evidence.decodedBytes,sha256:evidence.decodedSha256},failedProbes:row.probes.filter(p=>p.status==='failed').map(p=>p.name)};save();bounds();}}
  function runNative(){const childOut=path.join(out,'native-child'),privateBin=fs.mkdtempSync(path.join(out,'.native-bin-')),names=fs.readdirSync('/usr/bin').sort(),compiler=path.join(options['x11-tools']||X11_ROOT,'xkbcomp');for(const name of names)fs.symlinkSync('/run/localization-host-bin/'+name,path.join(privateBin,name));if(names.includes('xkbcomp'))fs.unlinkSync(path.join(privateBin,'xkbcomp'));fs.symlinkSync(compiler,path.join(privateBin,'xkbcomp'));
    const parentNet=fs.readlinkSync('/proc/self/ns/net'),args=argv.map(a=>a.startsWith('--out=')?'--out='+childOut:a),binds=[];for(const value of [root,baseline,out,modulePath,executablePath,process.execPath])if(value.startsWith('/tmp/')){const top='/tmp/'+value.slice(5).split('/')[0];if(!binds.includes(top))binds.push(top);}
    const command=['--die-with-parent','--new-session','--unshare-user','--uid','0','--gid','0','--unshare-net','--bind','/','/','--tmpfs','/run','--ro-bind','/usr/bin','/run/localization-host-bin','--ro-bind',privateBin,'/usr/bin','--dev-bind','/dev','/dev','--proc','/proc','--tmpfs','/tmp',...binds.flatMap(p=>['--bind',p,p]),'--chdir',root,'--',process.execPath,fileURLToPath(import.meta.url),...args];
    let result;try{result=spawnSync('bwrap',command,{env:{...process.env,LOCALIZATION_NATIVE_CHILD:'1',COMPACT_NATIVE_PARENT_NETNS:parentNet},encoding:'utf8',maxBuffer:4*1024*1024,timeout:3600000});}finally{fs.rmSync(privateBin,{recursive:true});}
    for(const stream of ['stdout','stderr'])fs.writeFileSync(path.join(out,'native-launch.'+stream+'.txt'),result[stream]||'',{flag:'wx'});report.nativeChild={command:['bwrap',...command],status:result.status,signal:result.signal,error:result.error?errorText(result.error):null,parentNetworkNamespace:parentNet,compiler:fileIdentity(compiler),childReport:'native-child/browser-status.json'};assert.ifError(result.error);const child=JSON.parse(fs.readFileSync(path.join(childOut,'browser-status.json'),'utf8'));report.nativeChild.reportIdentity=fileIdentity(path.join(childOut,'browser-status.json'));report.nativeChild.planIdentity=fileIdentity(path.join(childOut,'execution-plan.json'));report.nativeChild.screenshots=child.screenshots;assert.equal(child.engines.native.isolation.verified,true);assert.notEqual(child.engines.native.isolation.networkNamespace,parentNet);for(const c of child.cells.filter(c=>c.kind==='native')){if(c.evidencePath)assert.deepEqual(fileIdentity(path.join(childOut,c.evidencePath)),c.evidenceIdentity,'Exact native child cell binding');report.cells.push({...c,evidenceBase:'native-child'});}assert.equal(result.status,0,'Native child actual failure retained');}
  try{save();modulePath=fs.realpathSync(modulePath);executablePath=fs.realpathSync(executablePath);before=identities();json('inputs-before.json',before);report.identities=before;assert.equal(before.baseline.canonicalSha256,starting.canonical.canonicalSha256);assert.deepEqual(before.baseline.standalone,starting.canonical.standalone);assert.equal(before.authority.sha256,starting.authority.sha256,'Exact supplied authority');assert.equal(before.authority.bytes,starting.authority.bytes);
    fs.mkdirSync(path.join(out,'producers'));report.producerPreimages={};for(const [name,identity]of Object.entries(before.producers)){const relative='producers/'+name;fs.mkdirSync(path.dirname(path.join(out,relative)),{recursive:true});fs.copyFileSync(identity.path,path.join(out,relative),fs.constants.COPYFILE_EXCL);const copied=fileIdentity(path.join(out,relative));assert.equal(copied.sha256,identity.sha256);report.producerPreimages[name]={path:relative,...copied};}
    for(const [key,actual]of [['source-sha256',before.candidate.canonicalSha256],['html-sha256',before.candidate.standalone.sha256],['starting-sha256',before.starting.sha256]])if(options[key])assert.equal(actual,options[key],key+' exact argv binding');
    if(options['plan-only']==='false'){
      const lockPath=path.join(path.dirname(out),'.localization-browser-collection.lock');if(!nativeChild){lock=fs.openSync(lockPath,'wx');fs.writeSync(lock,JSON.stringify({pid:process.pid,out}));report.lockPath=lockPath;}
      server=await createStaticServer({roots:{candidate:root},identities:{candidate:before.candidate}});
      if(nativeChild){assert.equal(nativeIsolation().verified,true);native=await launchNativeZoom({out,modulePath,executablePath,libraryPath,toolRoot:options['x11-tools']||X11_ROOT});report.engines.native=native.identity;}else{launch=await launchBrowser({modulePath,executablePath,libraryPath});report.engines.chromium=launch.identity;}
      for(const cell of plan.cells){if(options.cell&&cell.id!==options.cell)continue;if(nativeChild?cell.kind!=='native':cell.kind==='native')continue;await collect(cell);}
      if(!nativeChild&&options['native-zoom']==='true'&&(!options.cell||plan.cells.some(c=>c.kind==='native'&&c.id===options.cell)))await runNative();
    }
  }catch(e){report.errors.push(errorText(e));}finally{
    await active?.close().catch(e=>report.errors.push(errorText(e)));await native?.close().catch(e=>report.errors.push(errorText(e)));await launch?.close().catch(e=>report.errors.push(errorText(e)));await server?.close().catch(e=>report.errors.push(errorText(e)));
    for(const cell of plan.cells)if(!report.cells.some(c=>c.id===cell.id))report.cells.push({...cell,status:'unperformed',reason:options['plan-only']==='true'?'Explicit plan-only, no browser execution':options.cell&&cell.id!==options.cell?'Excluded focused diagnostic':nativeChild&&cell.kind!=='native'?'Ordinary cells owned by host parent':cell.kind==='native'&&options['native-zoom']==='false'?'Explicit native zoom omission':'Collection did not reach this cell; see retained errors'});
    if(before){try{inputs('final');json('inputs-after.json',identities());}catch(e){report.errors.push(errorText(e));}}
    report.probeTrace=probeRecordCount?{path:probeTraceName,encoding:'gzip-jsonl-multi-member',records:probeRecordCount,decodedBytes:probeDecodedBytes,...fileIdentity(path.join(out,probeTraceName))}:{status:'unperformed',reason:'No probe records collected'};
    if(lock!==undefined){fs.closeSync(lock);fs.unlinkSync(report.lockPath);}report.status=report.errors.length||report.cells.some(c=>c.status==='failed')?'failed':'collection-complete-not-acceptance';report.counts=Object.fromEntries(['passed','failed','unperformed'].map(status=>[status,report.cells.filter(c=>c.status===status).length]));report.finishedAt=new Date().toISOString();save();process.exitCode=report.status==='failed'?1:0;
  }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
