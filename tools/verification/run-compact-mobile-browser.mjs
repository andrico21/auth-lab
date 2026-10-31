#!/usr/bin/env bun
// Permanent bounded real-browser MC15/MC18 producer. Importing helpers never launches a browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {gzipSync} from 'node:zlib';
import {DEFAULT_CHECKOUT,DEFAULT_BROWSER,DEFAULT_PLAYWRIGHT,DEFAULT_LIBRARIES,PRESENTATION_KEY,
  captureInputs,fileIdentity,sha256,runtimeIdentity,launchBrowser,createStaticServer,createBrowserSession,
  settle,activate,studyState,continuityProjection,armSwitchWitness,finishSwitchWitness,assertClean} from './compact-mobile-browser.mjs';
import {COMPACT_CONTROL,compactRegistry,compactFixture,compactImport,compactStable} from './compact-view-fixtures.mjs';
import {launchNativeZoom,nativeIsolation,X11_ROOT} from './compact-native-zoom.mjs';

const HELP=`Usage: bun tools/verification/run-compact-mobile-browser.mjs --out=NEW_DIRECTORY
  [--root=CHECKOUT] [--control-root=FROZEN_CANDIDATE07] [--plan=PATH]
  [--source-sha256=HASH] [--html-sha256=HASH] [--plan-sha256=HASH]
  [--playwright-module=PATH] [--chromium-executable=PATH] [--firefox-executable=PATH] [--library-path=PATH]
  [--native-zoom=true|false] [--x11-tools=PATH]
  [--cell=EXACT_FROZEN_ID]  Focused diagnostic only; every other cell stays unperformed.
All options use =VALUE. Default checkout is derived from import.meta.url. Output must not exist and must be outside both roots.
Runs serially:33 primary Chromium semantic cells,84 emitted layout cells,13 preference/lifecycle cells,
3 user-style text200 fixtures,3 separately instrumented playing-switch witnesses,3 Firefox desktop representatives,
and3 real X11 browser400 zoom fixtures. Only native zoom runs in an owned bwrap child with private
tmpfs/tmp and network namespace, both verified before Xvfb; ordinary Chromium/Firefox stay on the host.
--native-zoom=false explicitly omits that capability;
No acknowledgment flag substitutes for measured isolation. No install/download/build or global X lock removal.
Native400 uses owned Xvfb and focused xdotool Ctrl+0 then eight Ctrl+plus events, asserting DPR4,scale1 and320..360CSSpx.
Text200 is accurately labelled user-style simulation, not native OS/browser text scaling. Touch emulation is not a phone.
WebKit,physical phones and human AT remain explicit unperformed cells. No overall accessibility/release acceptance.
Exit0: attempted browser cells passed with external gaps still open; exit1: failed collection/check/input identity.
Every attempt retains its frozen execution-plan.json, inputs-before/after.json, per-cell JSON, actions.jsonl,
trusted input/focus/cursor/geometry evidence and bounded representative screenshots plus every failed-cell screenshot.`;
if(process.argv.includes('--help')){console.log(HELP);process.exit(0);}
assert.ok(process.versions.bun,'Use the provisioned Bun runtime');
const options={},allowed=new Set(['out','root','control-root','plan','source-sha256','html-sha256','plan-sha256','playwright-module','chromium-executable','firefox-executable','library-path','native-zoom','x11-tools','cell']);
for(const arg of process.argv.slice(2)){const m=/^--([^=]+)=(.+)$/.exec(arg);assert.ok(m&&allowed.has(m[1]),'Unknown argument: '+arg+'\n'+HELP);assert.ok(!Object.hasOwn(options,m[1]),'Duplicate option');options[m[1]]=m[2];}
assert.ok(options.out,'Required --out\n'+HELP);
options['native-zoom']??='true';assert.ok(['true','false'].includes(options['native-zoom']));
const root=fs.realpathSync(options.root||DEFAULT_CHECKOUT),controlRoot=fs.realpathSync(options['control-root']||COMPACT_CONTROL);
const runner=fileURLToPath(import.meta.url),directory=path.dirname(runner),out=path.resolve(options.out);
const planFile=fs.realpathSync(options.plan||path.join(root,'docs/compact-view/phase-0/browser-device-at-plan.json'));
const nativeChild=process.env.COMPACT_NATIVE_REEXEC==='1';
fs.mkdirSync(path.dirname(out),{recursive:true});
const realOut=path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
for(const source of [root,controlRoot])assert.ok(realOut!==source&&!realOut.startsWith(source+path.sep),'Output outside source roots');
fs.mkdirSync(out);fs.mkdirSync(path.join(out,'cells'));fs.mkdirSync(path.join(out,'screenshots'));
const json=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
const errorText=error=>String(error.stack||error);
const report={schemaVersion:1,kind:'compact-mobile-real-browser',status:'collecting',startedAt:new Date().toISOString(),
  argv:[process.execPath,...process.argv.slice(1)],root,controlRoot,runtime:runtimeIdentity(),processIdentity:{pid:process.pid,uid:process.getuid(),gid:process.getgid(),userNamespace:fs.readlinkSync('/proc/self/ns/user'),networkNamespace:fs.readlinkSync('/proc/self/ns/net')},cells:[],inputChecks:[],engines:{},errors:[],screenshots:[],
  coverageScope:nativeChild?'owned-native-zoom-child-not-full-acceptance':options.cell?'focused-diagnostic-not-full-acceptance':'full-frozen-plan',selectedCell:options.cell||null,
  methods:{coverage:'Stable frozen cells are unique executions; multiple properties in one cell are not multiplied. Baseline DOM fixture factory supplies canonical expected data only, never browser/layout evidence.',
    browser:'Real provisioned Chromium/Firefox processes via Playwright, exact-byte loopback HTTP or actual standalone file, CSP and strict request allowlist, serial fresh contexts.',
    actions:'Exact fixture setup is explicitly programmatic and untimed. All user navigation/search/native-select/copy/disclosure/playback/View actions use actual trusted Playwright touch/pointer/keyboard input.',
    scopeEntry:'History entry must not start playback. An unstarted queue may be idle; the collector does not require an incidental paused enum. Nonempty field paths are selected from actual authored field usage, not the first global reference definition.',
    semantic:'Exact frozen candidate07 authored source and canonical held snapshot at observed source cursor; only context-qualified identity is rebuilt with the actual browser context, no protocol field omitted.',
    text200:'User-style simulation restores its own prior inline sizes including detached nodes, snapshots current computed fonts and doubles once at explicit post-action boundaries. No mutation callback recalibrates fonts during a trusted pointer/key sequence. Temporary transition suspension is restored before user actions; every sample checks exact2x computed sizes. Not native browser text-only zoom or mobile OS text scaling.',
    zoom400:'Separate native desktop X11 browser zoom only; CDP pageScale,CSS transforms and pinch are not browser zoom.',
    geometry:'All target/value geometry is checked and retained losslessly as checksum-bound gzip JSON; cell summaries reference that data. Focus probes use center plus8px inset points inside rounded borders. Editable text uses its content region, excluding separately measured clear/toggle adornments in input padding.',
    screenshots:'At most12 ordinary representative viewport captures; every failed cell additionally retained. Per-file64MiB,total512MiB bound. Logs capped by shared helper; a cap/truncation is failure.',
    acceptance:'No blanket WCAG/mobile accessibility, native protocol, human G01, publication, release or waiver claim.'}};
const save=()=>json('compact-mobile-browser-status.json',report);
let launch,firefox,native,server,active,baselineRegistry,baselineState,plan,before,lockFd,executionCells=[];
const oracle=new Map(), lockFile=path.join(path.dirname(out),'.compact-mobile-browser-collection.lock');
const manifestNames=['docs/compact-view/phase-0/catalog-and-cases.json','docs/compact-view/phase-0/deep-fixtures.json','docs/compact-view/phase-0/state-and-lifecycle-contract.json','docs/compact-view/phase-0/implementation-contract.json','docs/compact-view/inputs/worker-plan.html.input.txt','docs/next-expansion/scenario-manifest.json'];
const modulePath=fs.realpathSync(options['playwright-module']||process.env.PLAYWRIGHT_MODULE||DEFAULT_PLAYWRIGHT);
const chromiumPath=fs.realpathSync(options['chromium-executable']||process.env.CHROMIUM_EXECUTABLE||DEFAULT_BROWSER);
const firefoxPath=options['firefox-executable']||'/home/andrico/.cache/ms-playwright/firefox-1555/firefox/firefox';
const libraryPath=options['library-path']||process.env.LD_LIBRARY_PATH||DEFAULT_LIBRARIES;
function identities(){return {candidate:captureInputs(root),control:captureInputs(controlRoot),plan:fileIdentity(planFile),
  producers:Object.fromEntries(['run-compact-mobile-browser.mjs','compact-mobile-browser.mjs','compact-view-fixtures.mjs','compact-native-zoom.mjs'].map(name=>[name,fileIdentity(path.join(directory,name))])),
  controlFixtureHelper:fileIdentity(path.join(controlRoot,'tools/verification/held-object-fixtures.mjs')),
  manifests:Object.fromEntries(manifestNames.map(name=>[name,fileIdentity(path.join(root,name))])),
  toolchain:{runtime:fileIdentity(process.execPath),playwright:fileIdentity(modulePath),package:fileIdentity(path.join(path.dirname(modulePath),'package.json')),chromium:fileIdentity(chromiumPath),
    firefox:fs.existsSync(firefoxPath)?fileIdentity(firefoxPath):null,
    x11:options['native-zoom']==='true'?Object.fromEntries(['Xvfb','xdotool','scrot','xkbcomp'].map(name=>[name,fileIdentity(path.join(options['x11-tools']||X11_ROOT,name))])):null,
    nativeOverlay:process.env.COMPACT_NATIVE_OVERLAY?JSON.parse(process.env.COMPACT_NATIVE_OVERLAY):null}};}
function checkInputs(label){const current=identities();assert.deepEqual(current,before,'Exact inputs unchanged: '+label);if(report.executionPlan)assert.deepEqual(fileIdentity(path.join(out,'execution-plan.json')),report.executionPlan,'Frozen execution plan unchanged');report.inputChecks.push({label,status:'unchanged',at:new Date().toISOString()});}
function check(row,name,actual,expected=true){const a=compactStable(actual),b=compactStable(expected),ok=a===b;row.checks.push(ok?{name,status:'passed',actualSha256:sha256(a),expectedSha256:sha256(b)}:{name,status:'failed',actual,expected});return ok;}
function actionState(state){if(!state)return state;const {studyQueue,player,trace,session,...rest}=state;return {...rest,session:session?{...session,scenarioSnapshot:{sha256:sha256(compactStable(session.scenarioSnapshot))}}:null,player:player?{...player,queue:{sha256:sha256(compactStable(player.queue)),rows:player.queue?.map(r=>({id:r.id,sourceIndex:r.sourceIndex,heldCursorStart:r.heldCursorStart,heldCursorEnd:r.heldCursorEnd}))}}:null,
  trace:trace?{...trace,queue:{sha256:sha256(compactStable(trace.queue)),rows:trace.queue?.length}}:null,studyQueue:studyQueue?{kind:studyQueue.kind,label:studyQueue.label,position:studyQueue.position,initial:studyQueue.initial,atEnd:studyQueue.atEnd,cursor:studyQueue.cursor,scoped:studyQueue.scoped,rows:studyQueue.rows?.length}:null};}
async function step(row,page,name,fn){const action={cell:row.id,name,status:'attempted',before:actionState(await safeState(page))};row.actions.push(action);save();
  try{const result=await fn();await settle(page);if(row.text200)row.enlargement.push(await textEnlargement(page));action.after=actionState(await safeState(page));action.result=result;action.status='passed';return result;}
  catch(error){action.status='failed';action.error=errorText(error);throw error;}
  finally{fs.appendFileSync(path.join(out,'actions.jsonl'),JSON.stringify(action)+'\n');}}
const safeState=studyState;
async function click(row,page,selector,touch=row.touch){return step(row,page,'activate '+selector,()=>activate(page,selector,{touch}));}
async function key(row,page,value){return step(row,page,'keyboard '+value,()=>page.keyboard.press(value));}
async function type(row,page,value){return step(row,page,'type '+value,()=>page.keyboard.type(value));}
async function choose(row,page,selector,value){
  const control=page.locator(selector),choices=await control.locator('option').evaluateAll(nodes=>nodes.filter(node=>!node.disabled&&!node.parentElement.disabled).map(node=>({value:node.value,label:node.textContent})));
  const index=choices.findIndex(option=>option.value===value);assert.ok(index>=0,'Actual enabled native select option: '+selector+'='+value);
  await step(row,page,'focus actual native select '+selector,()=>control.focus());
  await key(row,page,'Home');
  for(let position=0;position<index;position++){await control.focus();await key(row,page,'ArrowDown');}
  await control.focus();await key(row,page,'Enter');
  check(row,'trusted keyboard native select value '+selector,await control.inputValue(),value);
  const events=active.evidence.trustedEvents.filter(event=>event.target===selector.slice(1)&&['input','change'].includes(event.type));
  check(row,'native select emits actual trusted input '+selector,events.length>0&&events.every(event=>event.trusted));
  row.nativeSelections||=[];row.nativeSelections.push({selector,value,choices,index,events});
}
async function openDetails(row,page,selector){if(!await page.locator(selector).evaluate(n=>n.open))await click(row,page,selector+' > summary');}
async function ready(page){await page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.presenter&&a.player&&a.steps?.length&&a.heldView?.compiled()?.plan&&a.scenarioPicker;});await settle(page);await page.locator('#scenario-title').waitFor({state:'visible'});}
async function setup(row,page,fixture){await page.evaluate(f=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario(f.choiceId,{variant:f.variant||'default'});if(f.member)a.selectLessonSubfixture(f.member);},fixture);await ready(page);
  row.setup={kind:'explicit untimed programmatic exact fixture selection only, not a user action',selector:fixture,state:retainState(row,await safeState(page),'setup')};
  assert.equal(row.setup.state.scenario,fixture.choiceId);if(fixture.member)assert.equal(row.setup.state.subfixture,fixture.member);
}
async function session(row,{browser=launch.browser,viewport={width:390,height:844},touch=true,preference='compact',loadingMode='emitted-http',reducedMotion='no-preference',seed=null}={}){
  row.touch=touch;row.viewport=viewport;row.loadingMode=loadingMode;
  const s=await createBrowserSession({browser,server,rootName:'candidate',root,identity:before.candidate,loadingMode,viewport,touch,preference,reducedMotion,diagnostic:true});
  active=s;row.target=s.target;row.browserEvidence=s.evidence;
  if(seed)await s.page.addInitScript(seed.fn,seed.arg);
  await s.page.goto(s.target,{waitUntil:'domcontentloaded'});await ready(s.page);return s;
}
async function screenshot(row,page,{failure=false,nativeCapture=false}={}){
  const ordinaryLimit=nativeChild?3:options['native-zoom']==='true'&&(!options.cell||options.cell.startsWith('zoom400-'))?9:12;
  if(!failure&&report.screenshots.filter(x=>!x.failure).length>=ordinaryLimit)return;
  const name='screenshots/'+row.id.replace(/[^a-z0-9_-]/gi,'_')+(failure?'-failure':'')+'.png';
  if(report.screenshots.some(x=>x.path===name))return;
  try{if(nativeCapture)await native.screenshot(page,path.join(out,name));else await page.screenshot({path:path.join(out,name),fullPage:false,timeout:15000});report.screenshots.push({path:name,cell:row.id,failure,...fileIdentity(path.join(out,name))});}
  catch(error){row.screenshotError=errorText(error);if(nativeCapture)throw error;}
}
async function collect(cell,fn){
  if(nativeChild&&cell.kind!=='native-zoom'){report.cells.push({...cell,status:'unperformed',reason:'Owned native zoom child only; ordinary browser cells belong to the host parent.'});return;}
  if(options.cell&&cell.id!==options.cell){report.cells.push({...cell,status:'unperformed',reason:'Excluded by explicit focused diagnostic --cell='+options.cell});return;}
  const row={...cell,status:'attempted',startedAt:new Date().toISOString(),checks:[],actions:[]};report.cells.push(row);save();
  try{checkInputs('before '+row.id);await fn(row);if(active){assertClean(active.evidence);if(row.actions.some(a=>a.name.startsWith('activate ')||a.name.startsWith('inspect ')||a.name.startsWith('select exact')))check(row,'actual trusted activation evidence',active.evidence.trustedEvents.some(e=>e.trusted&&e.type==='pointerdown'&&(!row.touch||e.pointerType==='touch')));check(row,'input evidence never synthetic',active.evidence.trustedEvents.filter(e=>e.kind==='input').every(e=>e.trusted));}assert.deepEqual(server.errors,[],'Exact-byte server clean');
    row.status=row.checks.some(x=>x.status==='failed')?'failed':'passed';}
  catch(error){row.status='failed';row.error=errorText(error);}
  finally{if(active){try{row.finalState=retainState(row,await safeState(active.page),'final');row.finalGeometry=retainGeometry(row,await geometry(active.page),'final');if(row.status==='failed')await screenshot(row,active.page,{failure:true,nativeCapture:row.kind==='native-zoom'});}catch(error){row.captureError=errorText(error);}await active.close().catch(error=>{row.cleanupError=errorText(error);row.status='failed';});active=null;}
    try{checkInputs('after '+row.id);}catch(error){row.status='failed';row.inputError=errorText(error);}
    row.finishedAt=new Date().toISOString();const evidencePath='cells/'+row.id+'.json';json(evidencePath,row);
    report.cells[report.cells.indexOf(row)]={...cell,status:row.status,evidencePath,evidenceIdentity:fileIdentity(path.join(out,evidencePath)),failedChecks:row.checks.filter(c=>c.status==='failed').map(c=>c.name),error:row.error,inputError:row.inputError,cleanupError:row.cleanupError};save();artifactBounds();}
  return row;
}
function artifactBounds(){let total=0;function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isDirectory())walk(file);else{const bytes=fs.statSync(file).size;assert.ok(bytes<=64*1024*1024,'Artifact exceeds64MiB: '+file);total+=bytes;}}}walk(out);assert.ok(total<=512*1024*1024,'Artifacts exceed512MiB');}
function retainRaw(row,value,label){
  const bytes=Buffer.from(JSON.stringify(value)),name='raw/'+row.id+'-'+label.replace(/[^a-z0-9]+/gi,'-')+'.json.gz';
  fs.mkdirSync(path.join(out,'raw'),{recursive:true});fs.writeFileSync(path.join(out,name),gzipSync(bytes),{flag:'wx'});
  return {path:name,...fileIdentity(path.join(out,name)),encoding:'gzip-json',decodedBytes:bytes.length,decodedSha256:sha256(bytes)};
}
function retainState(row,state,label){return {...actionState(state),rawState:retainRaw(row,state,'state-'+label)};}
function retainGeometry(row,g,label){
  const {targets,values,...summary}=g;
  return {...summary,targetCount:targets.length,valueCount:values.length,rawGeometry:retainRaw(row,g,'geometry-'+label)};
}
async function geometry(page){return page.evaluate(()=>{
  const box=n=>{const r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
  const visible=n=>!!n.getClientRects().length&&getComputedStyle(n).visibility!=='hidden';
  const names=n=>({tag:n.tagName,id:n.id,text:(n.getAttribute('aria-label')||n.textContent||'').trim().slice(0,160)});
  const root=document.querySelector('auth-flow-studio'),controls=[...root.querySelectorAll('button,input,select,textarea,summary,[tabindex="0"]')].filter(visible);
  const targets=controls.map(n=>({...names(n),box:box(n),disabled:!!n.disabled}));
  const values=[...root.querySelectorAll('.compact-study pre,.compact-study code')].filter(visible).map(n=>{
    const bounds=box(n),style=getComputedStyle(n);
    // Inline elements have no client box; Gecko can still report their content scroll width.
    return {...names(n),box:bounds,characters:n.textContent.length,scrollWidth:n.scrollWidth,clientWidth:n.clientWidth,scrollBoxWidth:n.clientWidth||bounds.width,display:style.display,whiteSpace:style.whiteSpace,overflowWrap:style.overflowWrap,sha256UnavailableInPage:true};
  });
  const regions=[...root.querySelectorAll('.instance-table-scroll,.table-scroll')].filter(visible).map(n=>({...names(n),role:n.getAttribute('role'),label:n.getAttribute('aria-label')||n.querySelector('caption')?.textContent,tabindex:n.getAttribute('tabindex'),overflow:n.scrollWidth>n.clientWidth+1}));
  const active=document.activeElement,r=box(active),style=getComputedStyle(active),editable=active.matches('input,textarea');
  const probe=editable?{left:r.left+parseFloat(style.paddingLeft),right:r.right-parseFloat(style.paddingRight),top:r.top,bottom:r.bottom}:r;
  const inset=Math.min(8,(probe.right-probe.left)/4,(probe.bottom-probe.top)/4),points=[[probe.left+inset,probe.top+inset],[probe.right-inset,probe.top+inset],[probe.left+inset,probe.bottom-inset],[probe.right-inset,probe.bottom-inset],[(probe.left+probe.right)/2,(probe.top+probe.bottom)/2]];
  const hit=points.map(([x,y])=>{const n=document.elementFromPoint(x,y);return {x,y,hit:!!n&&(active===n||active.contains(n)),cover:n?names(n):null};});
  return {viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,visualScale:visualViewport?.scale},document:{width:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,bodyScrollWidth:document.body.scrollWidth},
    targets,tooSmall:targets.filter(n=>n.box.width<43.9||n.box.height<43.9),values,unwrapped:values.filter(n=>n.scrollWidth>n.scrollBoxWidth+1),regions,
    focus:{...names(active),box:r,probeRegion:editable?'editable-content-excluding-padding-adornments':'rounded-control-interior',probeBox:probe,connected:active.isConnected,focusVisible:active.matches(':focus-visible'),outline:style.outline,hit,fullyVisible:r.top>=0&&r.left>=0&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1},
    bars:[...root.querySelectorAll('.compact-playback')].filter(visible).map(n=>({...names(n),position:getComputedStyle(n).position,box:box(n)})),
    duplicateIds:[...new Set([...document.querySelectorAll('[id]')].map(n=>n.id))].filter(id=>document.querySelectorAll('#'+CSS.escape(id)).length>1),
    fullDOM:root.querySelectorAll('#graph,#timeline,#packet,#connections,.held-dock').length,meta:document.querySelector('meta[name="viewport"]')?.content,
    liveRegions:[...root.querySelectorAll('[aria-live]')].map(n=>({...names(n),live:n.getAttribute('aria-live')}))};
});}
async function layoutChecks(row,page,label){const g=await geometry(page);row.geometries||=[];row.geometries.push({label,...retainGeometry(row,g,label)});
  check(row,label+' no page horizontal overflow',g.document.scrollWidth<=g.document.width+1&&g.document.bodyScrollWidth<=g.document.width+1);
  check(row,label+' exact values wrap without local value scrolling',g.unwrapped,[]);check(row,label+' non-inline target44px',g.tooSmall,[]);
  check(row,label+' unique IDs',g.duplicateIds,[]);check(row,label+' no mounted Full tree',g.fullDOM,0);
  check(row,label+' pinch not disabled',!/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?:\D|$)/i.test(g.meta||''));
  for(const region of g.regions.filter(x=>x.overflow))check(row,label+' labelled reachable two-dimensional region '+region.id,!!region.label&&region.tabindex==='0');
  return g;
}
async function focusChecks(row,page,label){const g=await geometry(page);row.focusEvidence||=[];row.focusEvidence.push({label,...g.focus,bars:g.bars});
  check(row,label+' focus connected',g.focus.connected);check(row,label+' focus fully visible',g.focus.fullyVisible);check(row,label+' focus not obscured inside rounded border and center',g.focus.hit.every(x=>x.hit));
  if(/keyboard|native summary/.test(label))check(row,label+' visible keyboard focus indicator',g.focus.focusVisible&&!/\snone\s/.test(g.focus.outline));
}
async function keyboardReach(row,page){await click(row,page,'[data-presentation-choice="compact"]',false);await key(row,page,'Tab');await focusChecks(row,page,'keyboard first shared control');
  const search=page.locator('#lab-scenario-search');await search.focus();await key(row,page,'ArrowDown');await key(row,page,'Escape');await focusChecks(row,page,'search editing focus');
  const summary=page.locator('[data-compact-disclosure="overview"] > summary');
  await click(row,page,'[data-compact-disclosure="overview"] > summary',false);await key(row,page,'Tab');await key(row,page,'Shift+Tab');
  check(row,'native summary reached by actual keyboard navigation',await summary.evaluate(node=>document.activeElement===node));
  const wasOpen=await summary.evaluate(node=>node.parentElement.open);
  await key(row,page,'Enter');check(row,'native summary Enter toggles disclosure',await summary.evaluate(node=>node.parentElement.open),!wasOpen);
  await key(row,page,'Enter');check(row,'native summary Enter restores disclosure',await summary.evaluate(node=>node.parentElement.open),wasOpen);await focusChecks(row,page,'native summary keyboard');
}
async function expectedFixture(fixture){const k=compactStable(fixture);if(!oracle.has(k)){const entry={...fixture,member:fixture.member||null,configuration:{},kind:'registered-case',id:'browser-oracle-'+sha256(k).slice(0,24)};oracle.set(k,await compactFixture(baselineRegistry,entry));}return oracle.get(k);}
async function canonical(row,page,fixture,label){const expected=await expectedFixture(fixture);
  const actual=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),q=a.studyQueue();return {snapshot:a.heldView.snapshot(),steps:a.scenarioSnapshot().steps,activeRow:q.rows[Math.max(0,q.position)],projection:a.compactView.projection&&{cursor:a.compactView.projection.cursor,state:a.compactView.projection.state,currentHoldings:a.compactView.projection.currentHoldings,authority:a.compactView.projection.authority,observations:a.compactView.projection.observations},title:a.querySelector('#compact-current-title')?.textContent,position:a.querySelector('#compact-position')?.textContent,result:a.querySelector('#compact-result')?.textContent};});
  const compiled=baselineState.compileHeldObjects({...expected.compiled.plan,contextId:actual.snapshot.contextId},{model:expected.model,steps:expected.source.steps});
  const wanted=baselineState.projectHeldObjects(compiled,actual.snapshot.cursor);
  check(row,label+' exact frozen authored steps',compactStable(actual.steps),compactStable(expected.source.steps));
  check(row,label+' exact frozen canonical snapshot',compactStable(actual.snapshot),compactStable(wanted));
  check(row,label+' rendered projection canonical cursor',actual.projection?.cursor,actual.snapshot.cursor);
  check(row,label+' rendered projection canonical state',compactStable(actual.projection?.state),compactStable(actual.snapshot.state));
  check(row,label+' rendered projection holdings',actual.projection?.currentHoldings,actual.snapshot.holdings);
  check(row,label+' visible authored row title',actual.title,actual.activeRow?.title||'No matching steps in this scope');
  if(actual.snapshot.cursor.eventIndex<0)check(row,label+' visible before-step1 qualification',actual.result?.includes('Before step 1'));
  row.canonicalEvidence||=[];row.canonicalEvidence.push({label,cursor:actual.snapshot.cursor,actualSha256:sha256(compactStable(actual.snapshot)),expectedSha256:sha256(compactStable(wanted)),snapshot:actual.snapshot,title:actual.title,position:actual.position,result:actual.result});
  return actual.snapshot;
}
const readerPanels=page=>page.evaluate(()=>Object.fromEntries(['protocol-state-panel','pam-configuration-panel','windows-remote-evidence','lifetime-strip','lesson-decisions'].map(id=>{const node=document.getElementById(id);return [id,node?{hidden:node.hidden,text:node.textContent}:null];})));
async function pausedRoundtrip(row,page,label){const before=await studyState(page),url=page.url(),history=await page.evaluate(()=>history.length);
  const panels=await readerPanels(page);
  await click(row,page,'[data-presentation-choice="full"]');const full=await studyState(page);check(row,label+' Full continuity',continuityProjection(full),continuityProjection(before));
  await click(row,page,'[data-presentation-choice="compact"]');const compact=await studyState(page);check(row,label+' Compact continuity',continuityProjection(compact),continuityProjection(before));
  check(row,label+' rendered canonical evidence survives presenter replacement',await readerPanels(page),panels);
  check(row,label+' URL unchanged',page.url(),url);check(row,label+' history unchanged',await page.evaluate(()=>window.history.length),history);
}
async function queueRow(row,page,index){await openDetails(row,page,'[data-compact-disclosure="overview"]');await click(row,page,'[data-compact-row="'+index+'"]');}
async function exactCopy(row,page,label,scope='.compact-study'){
  const target=await page.evaluate(scope=>{const a=document.querySelector(scope);return [...a.querySelectorAll('[data-compact-value]')].filter(n=>n.getClientRects().length&&n.parentElement.querySelector('[data-compact-copy]')).sort((a,b)=>b.textContent.length-a.textContent.length).map(n=>({token:n.dataset.compactValue,text:n.textContent}))[0]||null;},scope);
  assert.ok(target,'Meaningful permitted exact value exists for '+label);check(row,label+' full nonempty exact value',target.text.length>0);
  // Observe actual clipboard API argument without granting or emulating clipboard success.
  await page.evaluate(()=>{window.__compactCopyCalls=[];const a=document.querySelector('auth-flow-studio'),original=a.copyExactValue;a.copyExactValue=function(value,trigger){window.__compactCopyCalls.push(value);return original.call(this,value,trigger);};});
  await click(row,page,'[data-compact-copy="'+target.token+'"]');
  check(row,label+' exact copy call bytes',await page.evaluate(()=>window.__compactCopyCalls.at(-1)),target.text);
  const fallback=page.locator('[data-compact-value="'+target.token+'"]').locator('..').locator('[data-exact-copy-fallback]:visible');
  if(await fallback.count())check(row,label+' exact manual copy fallback',await fallback.last().inputValue(),target.text);
  else {if(row.kind!=='firefox-representative')await page.context().grantPermissions(['clipboard-read']);check(row,label+' actual clipboard bytes',await page.evaluate(()=>navigator.clipboard.readText()),target.text);}
  row.copies||=[];row.copies.push({label,characters:target.text.length,sha256:sha256(target.text),method:await fallback.count()?'actual manual fallback':'actual clipboard readback'});
}
async function fieldHistory(row,page,fixture){await openDetails(row,page,'[data-compact-disclosure="fields"]');
  const id=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return [...document.querySelectorAll('#attribute-index-list [data-index-attribute],#attribute-index-list [data-attribute]')].map(n=>n.dataset.indexAttribute||n.dataset.attribute).find(id=>a.attributeUsage(a.steps,id).length>0);});
  assert.ok(id,'Actual field with authored usage in this fixture');
  const definition=page.locator('#attribute-index-list [data-index-attribute="'+id+'"],#attribute-index-list [data-attribute="'+id+'"]');assert.equal(await definition.count(),1,'Unique actual field definition control');
  await step(row,page,'select exact field '+id,()=>row.touch?definition.tap():definition.click());
  await exactCopy(row,page,'field definition exact identifier','#compact-field-definition');
  await click(row,page,'[data-compact-field-trace="'+id+'"]');const state=await studyState(page);check(row,'field path starts without playback',state.player.status!=='playing');check(row,'field path exact selection',state.trace.attribute,id);assert.ok(state.studyQueue.rows.length,'Actual nonempty authored field path');
  await canonical(row,page,fixture,'field history initial');await pausedRoundtrip(row,page,'paused field history');
  if(state.studyQueue.rows.length){await queueRow(row,page,state.studyQueue.rows.length-1);await canonical(row,page,fixture,'field history end');}
  const cursor=(await studyState(page)).held.cursor;await click(row,page,'[data-compact-action="return"]');check(row,'field return same canonical cursor',(await studyState(page)).held.cursor,cursor);
}
async function objectHistory(row,page,fixture){
  await openDetails(row,page,'[data-compact-disclosure="holdings"]');
  const owner=await page.evaluate(()=>[...document.querySelectorAll('[data-compact-owner]')].find(n=>n.querySelector('[data-holding-id]'))?.dataset.compactOwner||null);
  assert.ok(owner,'Actual owner with current holding');const ownerSelector='[data-compact-owner="'+owner+'"]';await openDetails(row,page,ownerSelector);
  const holding=page.locator(ownerSelector+' [data-holding-id]').first();const holdingId=await holding.getAttribute('data-holding-id');
  await step(row,page,'inspect exact holding '+holdingId,()=>row.touch?holding.tap():holding.click());
  await exactCopy(row,page,'permission-scoped holding','#held-inspector');
  const trace=page.locator('#held-inspector [data-held-trace]').first();assert.equal(await trace.count(),1,'Actual exact-object trace control');const artifactId=await trace.getAttribute('data-held-trace');
  await step(row,page,'open exact-object history '+artifactId,()=>row.touch?trace.tap():trace.click());const state=await studyState(page);
  check(row,'exact history starts without playback',state.player.status!=='playing');check(row,'exact artifact identity',state.trace.object,artifactId);assert.ok(state.studyQueue.rows.length,'Actual exact history rows');
  await canonical(row,page,fixture,'exact history initial');await pausedRoundtrip(row,page,'paused exact history');
  await queueRow(row,page,state.studyQueue.rows.length-1);await canonical(row,page,fixture,'exact history end');await queueRow(row,page,0);await canonical(row,page,fixture,'exact history rewind');
  const cursor=(await studyState(page)).held.cursor;await click(row,page,'[data-compact-action="return"]');check(row,'exact return same source cursor',(await studyState(page)).held.cursor,cursor);
}
async function pamDetails(row,page,fixture){
  const steps=await page.evaluate(()=>document.querySelector('auth-flow-studio').steps.map((s,i)=>({i,pam:s.pamEvaluation})));
  const module=steps.find(s=>s.pam?.line);assert.ok(module,'PAM physical source line fixture');await queueRow(row,page,module.i);
  const source=await page.locator('[data-pam-line="'+module.pam.line+'"] code').textContent();
  const expected=await page.evaluate(({file,line})=>{const a=document.querySelector('auth-flow-studio');const f=a.labModel.pamConfiguration.files.find(f=>f.id===file||f.file===file)||a.labModel.pamConfiguration.files[0];return f.text.split('\n')[line-1];},{file:module.pam.configurationId||module.pam.file,line:module.pam.line});
  check(row,'PAM exact physical source text',source,expected);await canonical(row,page,fixture,'PAM module line');
  const prelim=steps.filter(s=>s.pam?.apiPhase==='prelim').at(-1);
  assert.ok(prelim,'PAM intermediate internal/public pending fixture');await queueRow(row,page,prelim.i);
  const pendingState=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().state.workstation.pamResults);
  check(row,'PAM internal preliminary success',pendingState.prelim,'PAM_SUCCESS');check(row,'PAM enclosing public call still not returned',pendingState.password,'not evaluated');
  for(const id of ['aggregates','password-dispatch','pending-results'])await openDetails(row,page,'[data-pam-disclosure="'+id+'"]');
  const groups=await page.locator('#pam-configuration-panel').innerText();check(row,'PAM public/internal/pending groups remain distinct',groups.includes('Completed API aggregate results')&&groups.includes('Internal password dispatch results')&&groups.includes('Pending / not-started results'));
  check(row,'PAM intermediate pending is not public success',/pending|not evaluated|not-started/i.test(await page.locator('[data-pam-disclosure="pending-results"]').innerText()));
  await canonical(row,page,fixture,'PAM internal pass public pending');
  // Select a real temporary secret before its authored release, then traverse its exact history through release and rewind.
  const release=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),p=a.heldView.compiled().plan,secrets=new Set(p.artifacts.filter(x=>x.type==='secret').map(x=>x.artifactId)),holdings=new Map();
    for(const fx of p.initial||[])if(fx.op==='acquire')holdings.set(fx.holdingId,fx.artifactId);
    for(let i=0;i<a.steps.length;i++)for(const m of p.events[a.steps[i].id].milestones)for(const fx of m.effects){if(fx.op==='acquire')holdings.set(fx.holdingId,fx.artifactId);if(fx.op==='release'&&secrets.has(holdings.get(fx.holdingId)))return {i,holdingId:fx.holdingId,artifactId:holdings.get(fx.holdingId)};}return null;});
  assert.ok(release&&release.i>0,'PAM authored secret release');await queueRow(row,page,release.i-1);
  const secret=await page.evaluate(id=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.holdingId===id),release.holdingId);assert.ok(secret,'Secret held immediately before release');
  await openDetails(row,page,'[data-compact-disclosure="holdings"]');await openDetails(row,page,'[data-compact-owner="'+secret.actorId+'"]');await click(row,page,'[data-holding-id="'+secret.holdingId+'"]');
  await click(row,page,'#held-inspector [data-held-trace]');const q=(await studyState(page)).studyQueue;const released=q.rows.findIndex(r=>/release/.test(r.traceKind||''));assert.ok(released>=0,'Actual release row in exact history');
  await queueRow(row,page,released);const gone=await canonical(row,page,fixture,'PAM exact release');check(row,'PAM released secret not current',gone.holdings.some(h=>h.holdingId===secret.holdingId),false);
  if(released>0)await queueRow(row,page,released-1);else await click(row,page,'[data-compact-action="previous"]');
  const rewound=await canonical(row,page,fixture,'PAM exact pre-release rewind');check(row,'PAM rewind restores earlier custody',rewound.holdings.some(h=>h.holdingId===secret.holdingId));await pausedRoundtrip(row,page,'PAM exact release rewind');
  await click(row,page,'[data-compact-action="return"]');
}
async function protocolSpecific(row,page,fixture){
  if(fixture.choiceId==='lab-pam01')return pamDetails(row,page,fixture);
  if(fixture.choiceId==='lab-wra01'){
    const state=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().state.workstation);
    row.windowsEvidence=state;const text=await page.locator('#windows-remote-evidence').innerText();
    check(row,'Windows filtering versus ACL distinct evidence',/filter|token/i.test(text)&&/ACL|authoriz|access/i.test(text));check(row,'Windows full token does not imply allow',/denied|deny|not authorized/i.test(text));
    const comparison=page.locator('[data-remote-comparison]');if(await comparison.count())await openDetails(row,page,'[data-remote-comparison]');
  }
  if(fixture.choiceId==='lab-dnssec09'){
    const state=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().state.dnssec),alias=state.namespaceCaches.find(x=>x.id==='lab-dnssec09:alias-cache'),target=state.namespaceCaches.find(x=>x.id==='lab-dnssec09:target-cache');
    assert.ok(alias&&target,'Exact DNS-R10 caches');check(row,'DNSSEC alias remains secure',alias.securityStatus,'secure');check(row,'DNSSEC failed target remains bogus',target.securityStatus,'bogus');check(row,'DNSSEC target has no validation time',target.validatedAt,null);
    check(row,'DNSSEC independent alias TTL300',alias.remainingTtl,300);check(row,'DNSSEC independent failed-target TTL5',target.remainingTtl,5);check(row,'DNSSEC failed target not accepted',state.acceptedForUse,false);row.dnssecEvidence={alias,target};
    await openDetails(row,page,'[data-compact-disclosure="holdings"]');await openDetails(row,page,'[data-compact-owner="dnsResolver"]');
    const id=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId==='dnsResolver'&&h.artifactId==='lab-dnssec09:alias-cache')?.holdingId);assert.ok(id);await click(row,page,'[data-holding-id="'+id+'"]');
    const shown=await page.locator('#held-inspector pre').first().textContent();check(row,'DNSSEC exact alias inspector equals canonical tuple',JSON.parse(shown),alias);await exactCopy(row,page,'DNSSEC alias exact tuple','#held-inspector');
  }
}
async function semantic(row,cell){const fixture=plan.semanticFixtures.find(f=>f.id===cell.fixtureId).selector;
  const {page}=await session(row,{loadingMode:cell.loadingMode});check(row,'no startup autofocus',await page.evaluate(()=>document.activeElement===document.body));check(row,'no startup autoplay',(await studyState(page)).player.status==='playing',false);
  await setup(row,page,fixture);const initial=await canonical(row,page,fixture,'initial');check(row,'canonical initial source index',initial.cursor.eventIndex,-1);await pausedRoundtrip(row,page,'initial');
  await click(row,page,'[data-compact-action="next"]');check(row,'Next from initial first row',(await studyState(page)).studyQueue.position,0);await canonical(row,page,fixture,'first row');await focusChecks(row,page,'Next activation focus');
  const count=(await studyState(page)).studyQueue.rows.length,mid=Math.floor((count-1)/2);await queueRow(row,page,mid);await canonical(row,page,fixture,'intermediate');await pausedRoundtrip(row,page,'intermediate');
  await queueRow(row,page,count-1);await canonical(row,page,fixture,'terminal');check(row,'terminal Next disabled',await page.locator('[data-compact-action="next"]').isDisabled());check(row,'terminal Replay explicit',await page.locator('#play').innerText(),'Replay');
  await protocolSpecific(row,page,fixture);
  // Re-enter journey terminal via actual row controls after any protocol-specific history.
  if((await studyState(page)).studyQueue.scoped)await click(row,page,'[data-compact-action="return"]');await queueRow(row,page,count-1);
  await fieldHistory(row,page,fixture);await queueRow(row,page,count-1);await objectHistory(row,page,fixture);
  await queueRow(row,page,0);await click(row,page,'[data-compact-action="previous"]');await canonical(row,page,fixture,'rewind to initial');check(row,'Previous reaches initial',(await studyState(page)).held.cursor.eventIndex,-1);
  if(cell.loadingMode==='emitted-http'&&['native-semantic-web','native-semantic-workstations','native-semantic-dnssec'].includes(cell.fixtureId))await screenshot(row,page);
}
async function textEnlargement(page){
  const result=await page.evaluate(()=>{
    if(!window.__compactFontSimulation){
      const simulation={records:[],refresh(){
        const scrollRoot=document.documentElement,focused=document.activeElement,viewport={left:scrollX,top:scrollY};
        const overflowAnchor=scrollRoot.style.getPropertyValue('overflow-anchor'),overflowAnchorPriority=scrollRoot.style.getPropertyPriority('overflow-anchor');
        const calibration={before:{...viewport,focus:{tag:focused.tagName,id:focused.id,box:focused.getBoundingClientRect().toJSON()}}};
        scrollRoot.style.setProperty('overflow-anchor','none','important');
        const nodes=[...document.querySelectorAll('auth-flow-studio,auth-flow-studio *')];
        const records=nodes.map(node=>({node:new WeakRef(node),transition:node.style.getPropertyValue('transition-property'),transitionPriority:node.style.getPropertyPriority('transition-property')}));
        try{
          // Native text scaling does not animate an author font-size property change.
          for(const node of nodes)node.style.setProperty('transition-property','none','important');
          // Detached presenters can be retained and remounted; restore their prior sizes too.
          for(const record of this.records){const node=record.node.deref();if(node&&node.style.getPropertyValue('font-size')===record.applied)record.inline?node.style.setProperty('font-size',record.inline,record.priority):node.style.removeProperty('font-size');}
          for(let index=0;index<nodes.length;index++){
            const node=nodes[index],record=records[index];
            record.inline=node.style.getPropertyValue('font-size');record.priority=node.style.getPropertyPriority('font-size');record.baseline=Number.parseFloat(getComputedStyle(node).fontSize);
          }
          for(let index=0;index<nodes.length;index++){const record=records[index];nodes[index].style.setProperty('font-size',(record.baseline*2)+'px','important');record.applied=nodes[index].style.getPropertyValue('font-size');}
          this.records=records;
          const sizes=new Map(),mismatches=[];
          for(let index=0;index<nodes.length;index++){
            const node=nodes[index],baseline=records[index].baseline,actual=Number.parseFloat(getComputedStyle(node).fontSize),expected=baseline*2,key=JSON.stringify([baseline,expected,actual]);
            sizes.set(key,(sizes.get(key)||0)+1);
            if(!Number.isFinite(baseline)||Math.abs(actual-expected)>.02)mismatches.push({tag:node.tagName,id:node.id,text:node.textContent.slice(0,80),rendered:node.checkVisibility(),inline:node.style.getPropertyValue('font-size'),baseline,expected,actual});
          }
          return {method:'post-action user-style simulation of200percent current computed text with important font-size; temporary font reset preserves the original viewport/focused node, transitions restored before user input, not browser/OS text scaling',nodes:nodes.length,calibration,sizes:[...sizes].map(([key,count])=>({sizes:JSON.parse(key),count})),mismatches};
        }finally{
          for(let index=0;index<nodes.length;index++){const record=records[index];record.transition?nodes[index].style.setProperty('transition-property',record.transition,record.transitionPriority):nodes[index].style.removeProperty('transition-property');}
          // A temporary smaller document can clamp scrollTop even when final fonts are unchanged.
          void scrollRoot.offsetHeight;
          window.scrollTo({left:viewport.left,top:viewport.top,behavior:'instant'});
          overflowAnchor?scrollRoot.style.setProperty('overflow-anchor',overflowAnchor,overflowAnchorPriority):scrollRoot.style.removeProperty('overflow-anchor');
          calibration.after={left:scrollX,top:scrollY,focus:{tag:document.activeElement.tagName,id:document.activeElement.id,box:document.activeElement.getBoundingClientRect().toJSON()}};
          calibration.focusUnchanged=document.activeElement===focused;
        }
      }};
      window.__compactFontSimulation=simulation;
    }
    return window.__compactFontSimulation.refresh();
  });
  assert.deepEqual(result.mismatches,[],'Every current rendered font-size is exactly200percent of its restored baseline');
  return result;
}
async function layout(row,fixture,{browser,viewport,touch=true,text200=false,nativeZoom=false}={}){
  const {page}=await session(row,{browser,viewport,touch});await setup(row,page,fixture);
  if(row.theme==='light')await click(row,page,'#theme-toggle');check(row,'actual requested theme',(await studyState(page)).session.theme,row.theme||'dark');
  await click(row,page,'[data-compact-action="next"]');await focusChecks(row,page,'manual Next activation focus');
  await click(row,page,'[data-compact-action="previous"]');await focusChecks(row,page,'manual Previous activation focus');
  const count=(await studyState(page)).studyQueue.rows.length;await queueRow(row,page,count-1);
  for(const id of ['data','state','holdings','fields','configuration','sources','overview']){const selector='[data-compact-disclosure="'+id+'"]';if(await page.locator(selector).isVisible())await openDetails(row,page,selector);}
  if(fixture.choiceId==='lab-pam01')for(const id of ['aggregates','password-dispatch','pending-results','configuration'])await openDetails(row,page,'[data-pam-disclosure="'+id+'"]');
  const owner=page.locator('[data-compact-owner]').first();if(await owner.count())await openDetails(row,page,'[data-compact-owner="'+await owner.getAttribute('data-compact-owner')+'"]');
  if(text200){row.text200=true;row.enlargement=[await textEnlargement(page)];await settle(page);}
  if(nativeZoom)row.zoom=await native.apply(page,row.id);
  await layoutChecks(row,page,'terminal expanded evidence');await exactCopy(row,page,'layout long permitted value');if(text200)row.enlargement.push(await textEnlargement(page));await layoutChecks(row,page,'after exact copy');await focusChecks(row,page,'exact copy focus');
  if(nativeZoom||text200||fixture.id==='layout-long-jwt'&&row.viewport.width===320&&row.theme==='dark')await screenshot(row,page,{nativeCapture:nativeZoom});
  await keyboardReach(row,page);await pausedRoundtrip(row,page,'layout switch');if(text200)row.enlargement.push(await textEnlargement(page));await layoutChecks(row,page,'returned Compact');
  // Soft-keyboard behavior on real phones remains external; this checks the editable-focus normal-flow policy only.
  await page.locator('#lab-scenario-search').focus();await type(row,page,'filtering');await focusChecks(row,page,'editable search focus');
  const g=await geometry(page);check(row,'editable focus playback not fixed over input',g.bars.every(b=>!['fixed','sticky'].includes(b.position)));
  await key(row,page,'Escape');
}
function preferenceSeed(value,blocked=false){return {fn:({key,value,blocked})=>{
  if(blocked){Object.defineProperty(window,'localStorage',{configurable:true,get(){throw new DOMException('Explicit acceptance fixture blocks storage','SecurityError');}});}
  else if(value!==null)localStorage.setItem(key,value);
},arg:{key:PRESENTATION_KEY,value,blocked}};}
async function preference(row,name){
  const width=name==='701px-auto-Full'||name==='stored-Compact-overrides-wide'?701:name==='700px-auto-Compact'?700:390;
  const stored=name==='stored-Full-overrides-narrow'?'full':name==='stored-Compact-overrides-wide'?'compact':name==='invalid-storage-enum-ignored'?'invalid':null;
  const blocked=name==='blocked-storage-page-memory-choice';const {page}=await session(row,{viewport:{width,height:844},preference:null,seed:preferenceSeed(stored,blocked)});
  const expected=stored==='full'?'full':stored==='compact'?'compact':width<=700?'compact':'full';check(row,'startup mode',(await safeState(page)).presentation,expected);
  if(['700px-auto-Compact','701px-auto-Full','stored-Full-overrides-narrow','stored-Compact-overrides-wide','invalid-storage-enum-ignored'].includes(name))return;
  if(name==='no-auto-persist'){check(row,'suggested mode not stored',await page.evaluate(key=>localStorage.getItem(key),PRESENTATION_KEY),null);return;}
  if(name==='no-autofocus'){check(row,'startup active element body',await page.evaluate(()=>document.activeElement===document.body));check(row,'startup no autoplay',(await safeState(page)).player.status==='playing',false);return;}
  if(blocked){await click(row,page,'[data-presentation-choice="full"]');check(row,'blocked storage Full working',(await safeState(page)).presentation,'full');await click(row,page,'[data-presentation-choice="compact"]');check(row,'blocked storage Compact page-memory choice',(await safeState(page)).presentation,'compact');return;}
  if(name==='orientation-does-not-switch'){await page.setViewportSize({width:844,height:390});await settle(page);check(row,'landscape remains Compact',(await studyState(page)).presentation,'compact');await page.setViewportSize({width:390,height:844});await settle(page);check(row,'portrait remains Compact',(await studyState(page)).presentation,'compact');await page.evaluate(key=>dispatchEvent(new StorageEvent('storage',{key,newValue:'full',storageArea:localStorage})),PRESENTATION_KEY);check(row,'other tab preference does not switch',(await studyState(page)).presentation,'compact');await layoutChecks(row,page,'orientation roundtrip');return;}
  if(name==='View-does-not-change-URL-or-history'){
    await pausedRoundtrip(row,page,'View URL/history');const before=await studyState(page),url=page.url();
    await openDetails(row,page,'[data-compact-disclosure="configuration"]');
    await click(row,page,'[data-compact-action="configuration"]');
    check(row,'configuration handoff opens Full',(await studyState(page)).presentation,'full');
    check(row,'configuration handoff opens editor',await page.locator('#advanced-configuration').evaluate(n=>n.open));
    check(row,'configuration handoff focus belongs to editor',await page.evaluate(()=>!!document.activeElement.closest('#advanced-configuration')));
    check(row,'configuration handoff preserves canonical session',continuityProjection(await studyState(page)),continuityProjection(before));
    await focusChecks(row,page,'configuration handoff focus');
    await click(row,page,'[data-presentation-choice="compact"]');await openDetails(row,page,'[data-compact-disclosure="overview"]');
    await click(row,page,'[data-compact-action="diagram"]');
    check(row,'diagram handoff opens Full',(await studyState(page)).presentation,'full');
    check(row,'diagram handoff focus is diagram title',await page.evaluate(()=>document.activeElement.id),'scenario-title');
    check(row,'diagram handoff preserves canonical session',continuityProjection(await studyState(page)),continuityProjection(before));
    await focusChecks(row,page,'diagram handoff focus');check(row,'handoffs do not change route',page.url(),url);
    return;
  }
  if(name==='search-draft-and-case-choice-retained')return searchChecks(row,page);
  if(name==='reduced-motion-survives-unmounted-Full'){
    await click(row,page,'[data-presentation-choice="full"]');await click(row,page,'[data-presentation-choice="compact"]');await page.emulateMedia({reducedMotion:'reduce'});await settle(page);
    check(row,'shared reduced-motion owner updates while Full unmounted',await page.evaluate(()=>document.querySelector('auth-flow-studio').player.reducedMotion),true);
    await click(row,page,'#play');check(row,'reduced-motion explicit Play works',(await studyState(page)).player.status,'playing');await click(row,page,'[data-presentation-choice="full"]');await click(row,page,'[data-presentation-choice="compact"]');check(row,'reduced-motion survives switching',await page.evaluate(()=>document.querySelector('auth-flow-studio').player.reducedMotion),true);return;
  }
  assert.equal(name,'speed-zero-explicit-Play-restores-positive-speed');await choose(row,page,'#compact-speed','0');check(row,'actual speed zero',(await studyState(page)).player.speed,0);await pausedRoundtrip(row,page,'zero speed');check(row,'switch alone preserves zero',(await studyState(page)).player.speed,0);await click(row,page,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');check(row,'explicit Play restores positive speed',(await studyState(page)).player.speed>0);await click(row,page,'#play');
}
async function searchChecks(row,page){
  // Diagnostic wrapper counts actual model-factory evaluations; it never supplies outcomes or changes input behavior.
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');window.__compactModelCalls=0;window.__compactRestoreModels=[];
    const memo=a.scenarioMemo,originalSet=memo.set;memo.set=function(...args){window.__compactModelCalls++;return originalSet.apply(this,args);};window.__compactRestoreModels.push(()=>{memo.set=originalSet;});
    for(const name of ['selectLabScenario','refreshConfiguration']){const original=a[name];a[name]=function(...args){window.__compactModelCalls++;return original.apply(this,args);};window.__compactRestoreModels.push(()=>{a[name]=original;});}
  });
  const initial=await studyState(page),search=page.locator('#lab-scenario-search');await search.focus();
  const queries=['filtering','lsa','sudo','FAST'];row.searchResults=[];
  for(const query of queries){await search.focus();await key(row,page,'ControlOrMeta+A');const calls=await page.evaluate(()=>window.__compactModelCalls);await type(row,page,query);await settle(page);check(row,'typing '+query+' does not construct/evaluate model',await page.evaluate(()=>window.__compactModelCalls),calls);check(row,'typing preserves selected lesson',(await studyState(page)).scenario,initial.scenario);const results=await page.locator('[data-scenario-option]:visible').evaluateAll(nodes=>nodes.map(n=>({id:n.dataset.scenarioOption,text:n.textContent})));check(row,'metadata search '+query+' has results',results.length>0);row.searchResults.push({query,results});await key(row,page,'ArrowDown');await key(row,page,'Escape');}
  await search.focus();await key(row,page,'ControlOrMeta+A');await type(row,page,'PAM');const draft=await search.inputValue();await pausedRoundtrip(row,page,'search draft');check(row,'search text retained',await search.inputValue(),draft);
  await search.focus();await key(row,page,'ControlOrMeta+A');await type(row,page,'password change');
  const ambiguous=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return (a.scenarioPicker.results||[]).find(r=>!r.variantId&&(r.matchingCases?.length>1||r.matchingVariantIds?.length>1))?.id||null;});
  assert.ok(ambiguous,'Real metadata ambiguity query must expose explicit case choice');await click(row,page,'[data-scenario-option="'+ambiguous+'"]');
  check(row,'ambiguity does not select scenario',(await studyState(page)).scenario,initial.scenario);const choice=await page.evaluate(()=>document.querySelector('auth-flow-studio').searchCaseChoice?.id);check(row,'explicit ambiguous lesson identity',choice,ambiguous);
  await click(row,page,'[data-presentation-choice="full"]');await click(row,page,'[data-presentation-choice="compact"]');check(row,'case-choice draft retained across switch',await page.evaluate(()=>document.querySelector('auth-flow-studio').searchCaseChoice?.id),ambiguous);
  await click(row,page,'[data-cancel-search-case]');check(row,'cancel preserves lesson',(await studyState(page)).scenario,initial.scenario);
  await search.focus();await key(row,page,'ControlOrMeta+A');await type(row,page,'lab-wra01');
  const targetIndex=await page.evaluate(()=>document.querySelector('auth-flow-studio').scenarioPicker.results.findIndex(r=>r.id==='lab-wra01'));assert.ok(targetIndex>=0,'Exact Windows lesson searchable');
  await key(row,page,'Home');for(let index=0;index<targetIndex;index++)await key(row,page,'ArrowDown');await key(row,page,'Enter');
  if(await page.locator('[data-search-case="full-token-acl-denied"]').isVisible())await click(row,page,'[data-search-case="full-token-acl-denied"]');
  else await choose(row,page,'#lesson-case','full-token-acl-denied');
  check(row,'keyboard search plus explicit case selects intended failure',(await studyState(page)).variant,'full-token-acl-denied');
  const fixture={choiceId:'lab-wra01',variant:'full-token-acl-denied'},expected=await expectedFixture(fixture);
  await queueRow(row,page,(await studyState(page)).studyQueue.rows.length-1);await canonical(row,page,fixture,'failure final cleanup');
  const deniedIndex=expected.source.steps.findIndex(step=>step.protocolEffects?.some(effect=>effect.path==='workstation.serverDecision'&&effect.value==='STATUS_ACCESS_DENIED'));
  const learnedIndex=expected.source.steps.findIndex(step=>step.protocolEffects?.some(effect=>effect.path==='workstation.returnedResult'&&effect.value==='STATUS_ACCESS_DENIED'));
  assert.ok(deniedIndex>=0&&learnedIndex>deniedIndex,'Authored server deny and later client result boundaries');
  row.denialEvidence=[];
  for(const [label,index] of [['server share authorization denial',deniedIndex],['client verified denial result',learnedIndex]]){
    await queueRow(row,page,index);const snapshot=await canonical(row,page,fixture,label),state=snapshot.state.workstation;
    const verdict=page.locator('#windows-remote-evidence [data-windows-verdict]'),visible=await verdict.isVisible(),text=await verdict.innerText();
    check(row,label+' exact authored source boundary',snapshot.cursor,{eventIndex:index,milestone:'complete'});
    check(row,label+' share remains unauthorized',state.shareAuthorized,false);check(row,label+' canonical denied status',state.serverDecision,'STATUS_ACCESS_DENIED');
    check(row,label+' full target token still does not grant share access',state.tokenComparison?.after.mode,'full');
    check(row,index===deniedIndex?'learner can read denial reason':label+' learner can read canonical denial meaning',visible&&!!state.verdictExplanation&&text===state.verdictExplanation);
    if(index===learnedIndex){check(row,'client has learned actual failure',state.clientKnowsFailure);check(row,'client result is SMB access denial',state.returnedResult,'STATUS_ACCESS_DENIED');}
    row.denialEvidence.push({label,sourceStepId:expected.source.steps[index].id,cursor:snapshot.cursor,visible,text,state});
  }
  await page.evaluate(()=>{for(const restore of window.__compactRestoreModels)restore();delete window.__compactRestoreModels;});
}
async function witness(row,mode){const {page}=await session(row,{loadingMode:mode});await setup(row,page,{choiceId:'basic-keycloak',variant:'default'});
  await click(row,page,'#play');await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});
  await armSwitchWitness(page);await click(row,page,'[data-presentation-choice="full"]');row.forwardWitness=await finishSwitchWitness(page);check(row,'postpause Full no scheduling',(await studyState(page)).scheduling,{frame:false,timer:false});
  await click(row,page,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');await armSwitchWitness(page);await click(row,page,'[data-presentation-choice="compact"]');row.reverseWitness=await finishSwitchWitness(page);
  check(row,'postpause Compact no scheduling',(await studyState(page)).scheduling,{frame:false,timer:false});const paused=await studyState(page);await settle(page);check(row,'no implicit resume/cursor drift',continuityProjection(await studyState(page)),continuityProjection(paused));
  await click(row,page,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');
  await openDetails(row,page,'[data-compact-disclosure="data"]');check(row,'opening evidence pauses actual playback',(await studyState(page)).player.status,'paused');
  await click(row,page,'[data-compact-disclosure="data"] > summary');check(row,'closing evidence does not resume',(await studyState(page)).player.status,'paused');
  await click(row,page,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');
  await click(row,page,'#lab-scenario-search');check(row,'opening search pauses actual playback',(await studyState(page)).player.status,'paused');await key(row,page,'Escape');check(row,'closing search never resumes',(await studyState(page)).player.status,'paused');
}
function runNativeChild(nativeCells){
  const childOut=path.join(out,'native-child'),binds=[];
  for(const value of [root,controlRoot,directory,childOut,path.dirname(planFile),modulePath,chromiumPath,firefoxPath,options['x11-tools']||X11_ROOT]){
    const resolved=path.resolve(value);
    if(resolved.startsWith('/tmp/')){const top='/tmp/'+resolved.slice(5).split('/')[0];if(!binds.includes(top))binds.push(top);}
  }
  const parentNetworkNamespace=fs.readlinkSync('/proc/self/ns/net'),privateBin=fs.mkdtempSync(path.join(out,'.compact-native-bin-'));
  const hostNames=fs.readdirSync('/usr/bin').sort(),compiler=path.join(options['x11-tools']||X11_ROOT,'xkbcomp');
  for(const name of hostNames)fs.symlinkSync('/run/compact-native-host-bin/'+name,path.join(privateBin,name));
  if(hostNames.includes('xkbcomp'))fs.unlinkSync(path.join(privateBin,'xkbcomp'));
  fs.symlinkSync(compiler,path.join(privateBin,'xkbcomp'));
  const overlay={method:'Private namespace /usr/bin proxy; cached xkbcomp only, no host filesystem installation',hostNames:hostNames.length,hostNamesSha256:sha256(JSON.stringify(hostNames)),compiler:{path:compiler,...fileIdentity(compiler)}};
  const childArgv=process.argv.slice(2).map(arg=>arg.startsWith('--out=')?'--out='+childOut:arg);
  const args=['--die-with-parent','--new-session','--unshare-user','--uid','0','--gid','0','--unshare-net','--bind','/','/','--tmpfs','/run','--ro-bind','/usr/bin','/run/compact-native-host-bin','--ro-bind',privateBin,'/usr/bin','--dev-bind','/dev','/dev','--proc','/proc','--tmpfs','/tmp',...binds.flatMap(p=>['--bind',p,p]),'--chdir',root,'--',process.execPath,runner,...childArgv];
  report.nativeChild={mechanism:'Only native zoom executes in an owned bwrap private user/mount/tmpfs/tmp/network child; ordinary engines remain in the host parent',outputBase:'native-child',command:['bwrap',...args],parentProcess:report.processIdentity,overlay};
  save();let attempt;
  try{attempt=spawnSync('bwrap',args,{env:{...process.env,COMPACT_NATIVE_REEXEC:'1',COMPACT_NATIVE_PARENT_NETNS:parentNetworkNamespace,COMPACT_NATIVE_OVERLAY:JSON.stringify(overlay)},encoding:'utf8',maxBuffer:4*1024*1024});}
  finally{fs.rmSync(privateBin,{recursive:true});}
  for(const stream of ['stdout','stderr'])fs.writeFileSync(path.join(out,'native-child-launch.'+stream+'.txt'),attempt[stream]||'',{flag:'wx'});
  Object.assign(report.nativeChild,{exitStatus:attempt.status,signal:attempt.signal,error:attempt.error?String(attempt.error):null,
    streams:Object.fromEntries(['stdout','stderr'].map(stream=>{const name='native-child-launch.'+stream+'.txt';return [stream,{path:name,...fileIdentity(path.join(out,name))}];}))});save();
  assert.ifError(attempt.error);
  const child=JSON.parse(fs.readFileSync(path.join(childOut,'compact-mobile-browser-status.json'),'utf8')),childPlan=JSON.parse(fs.readFileSync(path.join(childOut,'execution-plan.json'),'utf8'));
  const artifacts={};
  function inventory(relative=''){
    for(const entry of fs.readdirSync(path.join(childOut,relative),{withFileTypes:true})){
      const name=relative?relative+'/'+entry.name:entry.name,file=path.join(childOut,name);
      assert.ok(!entry.isSymbolicLink(),'Owned child artifacts are not symlinks');
      if(entry.isDirectory())inventory(name);else{assert.ok(entry.isFile());artifacts[name]=fileIdentity(file);}
    }
  }
  inventory();
  Object.assign(report.nativeChild,{argv:child.argv,runtime:child.runtime,processIdentity:child.processIdentity,identities:child.identities,inputChecks:child.inputChecks,
    isolation:child.engines.nativeChromium?.isolation||null,executionPlan:{path:'native-child/execution-plan.json',...artifacts['execution-plan.json']},status:child.status,counts:child.counts,errors:child.errors,
    report:{path:'native-child/compact-mobile-browser-status.json',...artifacts['compact-mobile-browser-status.json']},artifacts});
  assert.deepEqual(childPlan.cells,executionCells,'Child preserves the complete frozen156-cell manifest');
  assert.deepEqual(child.identities,{...before,toolchain:{...before.toolchain,nativeOverlay:overlay}},'Child executes exact parent source, HTML, plan, producers and tool inputs');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(childOut,'inputs-after.json'),'utf8')),child.identities,'Child exact inputs unchanged');
  assert.deepEqual(fileIdentity(path.join(childOut,'execution-plan.json')),child.executionPlan,'Child frozen execution plan unchanged');
  assert.equal(child.coverageScope,'owned-native-zoom-child-not-full-acceptance');
  assert.notEqual(child.processIdentity.networkNamespace,parentNetworkNamespace,'Native child cannot share the host network namespace');
  assert.equal(attempt.status,child.exitCode,'Exact child process exit is retained, not relabelled');
  report.engines.nativeChromium=child.engines.nativeChromium;
  for(const cell of nativeCells){
    const result=child.cells.find(row=>row.id===cell.id);assert.ok(result,'Exact native child result '+cell.id);
    if(!options.cell||options.cell===cell.id)assert.ok(['passed','failed'].includes(result.status),'Selected native child cell was attempted');
    if(result.evidencePath){assert.deepEqual(artifacts[result.evidencePath],result.evidenceIdentity,'Exact native child cell identity');fs.copyFileSync(path.join(childOut,result.evidencePath),path.join(out,result.evidencePath),fs.constants.COPYFILE_EXCL);}
    report.cells.push({...result,evidenceBase:'.',executionOwner:'native-child',childReport:report.nativeChild.report});
  }
  for(const name of Object.keys(artifacts).filter(name=>name.startsWith('raw/')||name.startsWith('screenshots/'))){
    fs.mkdirSync(path.dirname(path.join(out,name)),{recursive:true});fs.copyFileSync(path.join(childOut,name),path.join(out,name),fs.constants.COPYFILE_EXCL);
  }
  for(const screenshot of child.screenshots)report.screenshots.push({...screenshot,executionOwner:'native-child'});
  assert.ok(report.screenshots.filter(screenshot=>!screenshot.failure).length<=12,'Parent and native child together retain at most12 ordinary screenshots');
  if(artifacts['actions.jsonl'])fs.appendFileSync(path.join(out,'actions.jsonl'),fs.readFileSync(path.join(childOut,'actions.jsonl')));
  if(child.errors.length)report.errors.push({phase:'native zoom child',errors:child.errors,childReport:report.nativeChild.report});
  assert.equal(child.engines.nativeChromium?.isolation.verified,true,'Native child retains measured private tmpfs/tmp and network isolation');
  assert.equal(child.engines.nativeChromium.isolation.parentNetworkNamespace,parentNetworkNamespace);
  artifactBounds();save();
}
async function closeAll(){await active?.close().catch(error=>report.errors.push({phase:'session cleanup',error:errorText(error)}));active=null;await native?.close();await firefox?.close();await launch?.close();await server?.close();}
let interrupted=false;
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{interrupted=true;report.errors.push({phase:'interruption',error:signal});save();void closeAll();});
try{
  lockFd=fs.openSync(lockFile,'wx');fs.writeFileSync(lockFd,JSON.stringify({pid:process.pid,out,startedAt:report.startedAt}));
  plan=JSON.parse(fs.readFileSync(planFile,'utf8'));assert.equal(plan.frozenBeforeCollection,true);assert.equal(plan.cells.filter(c=>c.kind==='semantic-browser').length,33);assert.equal(plan.cells.filter(c=>c.kind==='layout-browser').length,84);assert.equal(new Set(plan.cells.map(c=>c.id)).size,117);
  before=identities();report.identities=before;json('inputs-before.json',before);
  assert.equal(before.control.canonicalSha256,'b743e4fc4cc8f9a804c55c1d8b2f8a0f845fab9caf94bb66d0d75c4a3396b825');assert.equal(before.control.standalone.sha256,'9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694');
  for(const [flag,actual] of [['source-sha256',before.candidate.canonicalSha256],['html-sha256',before.candidate.standalone.sha256],['plan-sha256',before.plan.sha256]])if(options[flag])assert.equal(actual,options[flag],'Pinned '+flag);
  for(const ref of [plan.catalog,plan.deep])assert.deepEqual(fileIdentity(path.join(root,ref.path)),{bytes:ref.bytes,sha256:ref.sha256},'Frozen plan reference '+ref.path);
  const frozenCells=[...plan.cells,...plan.preferenceAndLifecycleCases.map(name=>({id:'preference-'+name,kind:'preference-lifecycle',name})),
    ...plan.enlargementCases.flatMap(c=>c.fixtureIds.map(fixtureId=>({id:c.id+'-'+fixtureId,kind:c.id==='zoom400'?'native-zoom':'text-enlargement',fixtureId,theme:'dark'}))),
    ...['source-http','emitted-http','standalone-file'].map(loadingMode=>({id:'diagnostic-playing-switch-'+loadingMode,kind:'diagnostic-switch',loadingMode})),
    ...plan.engineRepresentatives.filter(e=>e.id==='firefox').flatMap(e=>e.fixtureIds.map(fixtureId=>({id:'firefox-'+fixtureId,kind:'firefox-representative',fixtureId,theme:'dark'}))),
    ...plan.engineRepresentatives.filter(e=>e.id==='webkit').map(e=>({...e,kind:'external-engine'})),...plan.externalCells.map(c=>({...c,kind:'external-device-human'}))];
  assert.equal(new Set(frozenCells.map(c=>c.id)).size,frozenCells.length,'Stable unique full execution plan IDs');
  assert.equal(frozenCells.length,156,'Complete frozen execution manifest');assert.equal(frozenCells.filter(cell=>!cell.kind.startsWith('external-')).length,142,'All142 available cells retained');
  if(options.cell)assert.ok(frozenCells.some(cell=>cell.id===options.cell),'Unknown frozen --cell ID');
  executionCells=frozenCells.map(cell=>({...cell,status:'unperformed'}));
  json('execution-plan.json',{schemaVersion:1,frozenAt:new Date().toISOString(),planIdentity:before.plan,identities:before,cells:executionCells,methods:report.methods,nativeZoomEnabled:options['native-zoom']==='true'});
  report.executionPlan=fileIdentity(path.join(out,'execution-plan.json'));save();
  const hostGlobals=new Map(['HTMLElement','customElements','document','window','matchMedia','requestAnimationFrame','cancelAnimationFrame','setTimeout','clearTimeout'].map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)]));
  try{baselineRegistry=await compactRegistry(controlRoot);baselineState=await compactImport(controlRoot,'src/held-object-state.js');}
  finally{for(const [key,descriptor] of hostGlobals){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}}
  if(!nativeChild){launch=await launchBrowser({modulePath,executablePath:chromiumPath,libraryPath});report.engines.chromium=launch.identity;}
  server=await createStaticServer({roots:{candidate:root},identities:{candidate:before.candidate}});
  for(const cell of plan.cells){if(interrupted)break;if(cell.kind==='semantic-browser')await collect(cell,row=>semantic(row,cell));else{
    const fixture=plan.layoutFixtures.find(f=>f.id===cell.fixtureId),viewport=plan.viewports.find(v=>v.id===cell.viewport);assert.ok(fixture&&viewport);
    await collect(cell,row=>layout(row,fixture,{viewport:{width:viewport.width,height:viewport.height},touch:viewport.width<=844}));
  }}
  for(const name of plan.preferenceAndLifecycleCases){if(interrupted)break;await collect({id:'preference-'+name,kind:'preference-lifecycle',name},row=>preference(row,name));}
  for(const mode of ['source-http','emitted-http','standalone-file']){if(interrupted)break;await collect({id:'diagnostic-playing-switch-'+mode,kind:'diagnostic-switch'},row=>witness(row,mode));}
  for(const fixtureId of plan.enlargementCases.find(c=>c.id==='text200').fixtureIds){if(interrupted)break;await collect({id:'text200-'+fixtureId,kind:'text-enlargement',theme:'dark'},row=>layout(row,plan.layoutFixtures.find(f=>f.id===fixtureId),{viewport:{width:390,height:844},text200:true}));}
  const nativeCells=frozenCells.filter(c=>c.kind==='native-zoom');
  const selectedNative=!options.cell||nativeCells.some(cell=>cell.id===options.cell);
  if(options['native-zoom']==='true'&&!interrupted&&selectedNative){
    try{
      if(nativeChild){
        assert.equal(nativeIsolation().verified,true,'Owned native child must verify OS isolation before browser launch');
        native=await launchNativeZoom({out,modulePath,executablePath:chromiumPath,libraryPath,toolRoot:options['x11-tools']||X11_ROOT});report.engines.nativeChromium=native.identity;
        for(const cell of nativeCells)await collect(cell,row=>layout(row,plan.layoutFixtures.find(f=>f.id===cell.fixtureId),{browser:native.browser,viewport:null,touch:false,nativeZoom:true}));
      }else runNativeChild(nativeCells);
    }catch(error){report.errors.push({phase:'native browser zoom launch/child',error:errorText(error)});for(const cell of nativeCells.filter(c=>!report.cells.some(r=>r.id===c.id)))report.cells.push({...cell,status:'failed',error:errorText(error)});}
  }else for(const cell of nativeCells)report.cells.push({...cell,status:'unperformed',reason:!selectedNative?'Excluded by explicit focused diagnostic --cell='+options.cell:'Explicit --native-zoom=false or interruption; no native400 capability pass and no CDP/CSS/pinch substitute.'});
  const firefoxCells=frozenCells.filter(c=>c.kind==='firefox-representative');
  if(!nativeChild&&fs.existsSync(firefoxPath)&&!interrupted&&(!options.cell||firefoxCells.some(cell=>cell.id===options.cell))){try{const {firefox:engine}=await import(pathToFileURL(modulePath).href);firefox=await engine.launch({executablePath:firefoxPath,headless:true,env:{...process.env,LD_LIBRARY_PATH:libraryPath}});report.engines.firefox={version:firefox.version(),path:firefoxPath,...fileIdentity(firefoxPath),owner:report.processIdentity,headless:true,libraryPath,sandboxEnvironment:Object.fromEntries(Object.entries(process.env).filter(([key])=>/MOZ_.*SANDBOX/.test(key)))};
    for(const cell of firefoxCells)await collect(cell,row=>layout(row,plan.layoutFixtures.find(f=>f.id===cell.fixtureId),{browser:firefox,viewport:{width:1440,height:1000},touch:false}));
  }catch(error){report.errors.push({phase:'Firefox launch/collection',error:errorText(error)});for(const cell of firefoxCells.filter(c=>!report.cells.some(r=>r.id===c.id)))report.cells.push({...cell,status:'failed',error:errorText(error)});}}
  else for(const cell of firefoxCells)report.cells.push({...cell,status:'unperformed',reason:nativeChild?'Owned native zoom child only; Firefox belongs to the host parent.':options.cell?'Excluded by explicit focused diagnostic --cell='+options.cell:'Provisioned Firefox executable unavailable or collection interrupted; no cross-engine pass.'});
  for(const cell of frozenCells.filter(c=>c.kind.startsWith('external-')))report.cells.push({...cell,status:'unperformed'});
  for(const cell of frozenCells)if(!report.cells.some(r=>r.id===cell.id))report.cells.push({...cell,status:'unperformed',reason:'Collection interrupted before this frozen cell'});
  checkInputs('final');report.status=report.errors.length||report.cells.some(c=>c.status==='failed')?'failed':'complete';
}catch(error){report.errors.push({phase:'collection',error:errorText(error)});report.status='failed';}
finally{
  for(const cell of executionCells)if(!report.cells.some(row=>row.id===cell.id))report.cells.push({...cell,reason:'Collection failed or interrupted before this frozen cell was attempted'});
  try{await closeAll();}catch(error){report.errors.push({phase:'cleanup',error:errorText(error)});report.status='failed';}
  try{const after=identities();json('inputs-after.json',after);if(before){assert.deepEqual(after,before,'Final exact identity');if(report.executionPlan)assert.deepEqual(fileIdentity(path.join(out,'execution-plan.json')),report.executionPlan,'Final frozen execution plan');}}catch(error){report.errors.push({phase:'final identity',error:errorText(error)});report.status='failed';}
  if(lockFd!==undefined){fs.closeSync(lockFd);fs.unlinkSync(lockFile);}
  report.finishedAt=new Date().toISOString();report.counts=Object.fromEntries(['attempted','passed','failed','unperformed'].map(status=>[status,status==='attempted'?report.cells.filter(c=>['attempted','passed','failed'].includes(c.status)).length:report.cells.filter(c=>c.status===status).length]));
  report.coverage=Object.fromEntries([...new Set(report.cells.map(c=>c.kind))].map(kind=>[kind,Object.fromEntries(['passed','failed','unperformed'].map(status=>[status,report.cells.filter(c=>c.kind===kind&&c.status===status).length]))]));
  report.openGates=['Physical iPhone/Safari and Android/Chrome, software-keyboard/chrome/safe areas, native mobile text scaling and pinch tasks remain unperformed.','VoiceOver/TalkBack spoken output and comprehension and existing human G01 remain open.','WebKit/Safari engine unavailable; no download attempted.','User-style text200 simulation is not native browser text-only/OS enlargement acceptance.','All inherited Full/protocol/performance/release qualifications remain scoped and unwaived.'];
  report.exitCode=report.status==='failed'?1:0;save();console.log(JSON.stringify({out,status:report.status,counts:report.counts,coverage:report.coverage,exitCode:report.exitCode}));process.exitCode=report.exitCode;
}
