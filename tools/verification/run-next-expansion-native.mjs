#!/usr/bin/env bun
// Serial, control-driven native acceptance. Never imports the application as its oracle.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';

const help=`Usage: bun tools/verification/run-next-expansion-native.mjs [project-directory] \\
  --phase=P0|final|review --output-new-dir=/absolute/new-directory --expectedHTMLhash=SHA256 \\
  [--source-root=/absolute/frozen-checkout] [--zoom-procedure=/absolute/procedure.json] [--review-fixtures=/absolute/fixtures.json] [--review-contrast-only=file:touch]
Requires provisioned PLAYWRIGHT_MODULE and CHROMIUM_EXECUTABLE; inherits LD_LIBRARY_PATH.
No build, install, downloads, application imports, credentials or non-loopback requests.
Serial source-http, built-http and file modes; desktop1480x1000 and native-touch390x844.
Output directory MUST NOT exist. All failures and actions are retained; exit1 on failure/blocker.
P0: grouped workspace/global picker, old choices/routes, editing, playback identity, focus,
compact geometry, internals/inventory and native touch. Final adds all manifest core defaults,
every independent worksheet canonicalCases variant/checkpoint, field/exact-object replay.
Review: explicit correction fixtures only, ordinary navigation/accessibility, selected
semantic cases/replays/surfaces and primary-control contrast. Requires --review-fixtures.
It is not the complete final matrix and does not claim browser-menu zoom acceptance.
--review-contrast-only=MODE:DEVICE limits review to primary controls in one source-http,
built-http or file context and desktop or touch device; it does not rerun semantic cases.
P0 and final require SEPARATE actual headed browser-menu200/400 zoom. Without a procedure,
the native matrix still runs but report is blocked, never an acceptance pass.
Zoom JSON schema1: {schemaVersion:1,mechanism:'x11-browser-menu',display:':N',
 isolatedDisplay:true,displayServer:{program:'/absolute/Xvfb',pid:DEDICATED_PID},
 screenCaptureProgram:'/absolute/scrot',
 steps:[{percent:200|400,menuCommandIndex:0,commands:[{program:'/absolute/xdotool',
 args:['...']}]}]}. Commands execute serially with DISPLAY, AUTH_LAB_ZOOM_WINDOW_TITLE
 and AUTH_LAB_ZOOM_TARGET. ${'${TITLE}'} in argv is replaced by the isolated window title.
 Use actual Alt+f browser menu, not CSS, CDP scale or viewport resize. The menu command
 is followed by a native whole-screen scrot capture before subsequent zoom clicks.
 Use xdotool search --sync --name TITLE ... chaining to target only that isolated window.
The title is 'Auth Lab Native Zoom <pid>'; no user browser/profile is read.
Worksheet schema: rows[] OR scenarios[] indexed by runtimeId; canonicalCases[] ids are
exact #lesson-case values, with assertions [{at:{end:true,milestone:'complete'} OR
{milestone:'initial'} OR {stepId:'exact source event',milestone:'complete'|AUTHORED_ID},
target:'state',path:'namespace.field',equals:TYPED} OR {target:'holding',actorId,
artifactId,representation:'explicit',present:BOOLEAN,at:...}]. modelProfile{name,version}
is independent; canonicalCase.modelProfile overrides its row for changed fixed profiles.
No missing predicates/source snapshots silently pass. Replay fixtures:
row.nativeReplay:[{kind:'local'|'protected-receipt'|'acceptance',caseId,at,fieldId,
holding:{actorId,artifactId,representation}}], >=local and receipt/acceptance per frozen
manifest workspace/family (not merely per owner worksheet).
Report: native-status.json schemaVersion1, identities before/after, cases/actions,
coverage, sources, browser logs/network/CSP, screenshots, zoom and exact blockers.
Manual G01, seven old performance flags, 24 scoped closures, 12SMB/icons and live/native
platform conformance remain separate; this collector does not relabel historical evidence.`;
if(process.argv.includes('--help')){console.log(help);process.exit(0);}
const args=process.argv.slice(2),positionals=args.filter(x=>!x.startsWith('--'));
assert.ok(positionals.length<=1,'At most one project directory');
const options=Object.fromEntries(args.filter(x=>x.startsWith('--')).map(x=>{const i=x.indexOf('=');assert.ok(i>2,'Options require --name=value');return [x.slice(2,i),x.slice(i+1)];}));
assert.ok(Object.keys(options).every(x=>['phase','source-root','output-new-dir','expectedHTMLhash','zoom-procedure','review-fixtures','review-contrast-only'].includes(x)),'Unknown option');
assert.ok(['P0','final','review'].includes(options.phase),'Explicit --phase=P0|final|review required');
assert.equal(Boolean(options['review-fixtures']),options.phase==='review','--review-fixtures is required only for the targeted review phase');
assert.match(options.expectedHTMLhash||'',/^[a-f0-9]{64}$/i,'Explicit --expectedHTMLhash=SHA256 required');
assert.ok(path.isAbsolute(options['output-new-dir']||''),'Absolute --output-new-dir required');
if(options['source-root'])assert.ok(path.isAbsolute(options['source-root']),'--source-root must be absolute');
const contrastOnly=options['review-contrast-only']?.split(':')||null;
if(contrastOnly){
  assert.equal(options.phase,'review','Contrast-only scope is a targeted review, never full acceptance');
  assert.equal(contrastOnly.length,2,'Contrast-only scope requires MODE:DEVICE');
  assert.ok(['source-http','built-http','file'].includes(contrastOnly[0]),'Named contrast loading mode');
  assert.ok(['desktop','touch'].includes(contrastOnly[1]),'Named contrast device');
}
const runner=fileURLToPath(import.meta.url),root=path.resolve(options['source-root']||positionals[0]||path.join(path.dirname(runner),'../..')),out=options['output-new-dir'];
fs.mkdirSync(out,{recursive:false});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const digest=file=>{const bytes=fs.readFileSync(file);return {sha256:sha(bytes),bytes:bytes.length};};
const readJSON=file=>JSON.parse(fs.readFileSync(path.join(root,file),'utf8'));
const rel=file=>path.relative(root,file).split(path.sep).join('/');
function files(dir){return fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):e.isFile()?[path.join(dir,e.name)]:[]);}
function identity(){
  const names=['index.html','build.mjs','package.json','security-policy.mjs',...files(path.join(root,'src')).map(rel),...files(path.join(root,'assets')).map(rel),...files(path.join(root,'tests')).map(rel),...files(path.join(root,'docs/next-expansion')).map(rel),...(fs.existsSync(path.join(root,'docs/research'))?files(path.join(root,'docs/research')).map(rel):[])].filter(n=>fs.existsSync(path.join(root,n)));
  const entries=Object.fromEntries(names.map(n=>[n,digest(path.join(root,n))]));
  const canonicalSourceFiles=Object.fromEntries(Object.entries(entries).filter(([name])=>/^(?:src|assets|tests)\//.test(name)||['index.html','build.mjs','package.json','security-policy.mjs'].includes(name)).map(([name,value])=>[name,value.sha256]));
  return {entries,canonicalSourceFiles,sha256:sha(JSON.stringify(entries)),html:digest(path.join(root,'dist/auth-flow-studio.html')),runner:digest(runner)};
}
const report={schemaVersion:1,kind:'next-expansion-serial-native',phase:options.phase,startedAt:new Date().toISOString(),passed:false,complete:false,argv:[process.execPath,...process.argv.slice(1)],cwd:process.cwd(),root,output:out,runtime:{bun:process.versions.bun||null,version:process.version,executable:process.execPath,platform:process.platform,arch:process.arch},environment:Object.fromEntries(['PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE','LD_LIBRARY_PATH','DISPLAY'].map(k=>[k,process.env[k]||null])),cases:[],actions:[],sessions:[],screenshots:[],sources:[],coverage:{},failures:[],blockers:[],zoom:{performed:false},notEstablished:['Manual G01: assistive-technology speech and user comprehension remain unperformed','Live platform/native OS/cluster/remote-service interoperability','Cross-engine conformance','Seven historical performance flags and current performance comparison require separate evidence','24 scoped historical closures and 12 SMB/icon preservation require the dedicated gates; old reports are not current correctness proof']};
report.acceptanceScope=contrastOnly?'one-context-primary-control-contrast-only':options.phase==='review'?'targeted-correction-fixtures-only':'established-full-'+options.phase+'-matrix-including-browser-menu-zoom';
if(options.phase==='review')report.notEstablished.push('The full unrelated protocol/native matrix and browser-menu zoom were not repeated in this targeted correction run.');
const save=()=>fs.writeFileSync(path.join(out,'native-status.json'),JSON.stringify(report,null,2)+'\n');
let browser,server,origin,activeRecord,targetedReview;
const action=(kind,details={})=>{const entry={sequence:report.actions.length+1,at:new Date().toISOString(),session:activeRecord?.id||null,kind,...details};report.actions.push(entry);return entry;};
async function check(label,fn,scope=null){const entry={label,scope,passed:false};report.cases.push(entry);try{entry.result=await fn();entry.passed=true;}catch(error){entry.error=String(error.stack||error);report.failures.push({label,scope,error:entry.error});}save();return entry;}
const settle=page=>page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
const observe=page=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),p=a.protocolSnapshot(),h=a.heldView.snapshot();return {id:a.labScenarioId,variant:a.labModel?.variantId||a.lessonVariant||'default',workspace:a.workspace,family:a.family,protocol:{sourceIndex:p.sourceIndex,state:p.state,cursor:p.cursor},held:h,status:a.player.status,kind:a.player.kind,queue:a.player.queue.map(s=>({id:s.id,sourceIndex:s.sourceIndex,sourceStepId:s.sourceStepId,heldContextId:s.heldContextId})),trace:a.traceQueue.map(s=>({id:s.id,sourceIndex:s.sourceIndex,sourceStepId:s.sourceStepId,heldContextId:s.heldContextId})),attribute:a.attributeSelection,object:a.objectTraceSelection,context:a.heldView.contextId};});
async function openDetails(page,id){const node=page.locator('#'+id);if(await node.isVisible()&&await node.getAttribute('open')===null){action('open-details',{id});await node.locator(':scope > summary').click();}}
async function activate(page,selector,touch=false){action(touch?'native-tap':'native-click',{selector});const node=page.locator(selector);if(touch)await node.tap();else await node.click();await settle(page);}
async function settleNativeScroll(page,selector){
  const result=await page.locator(selector).evaluate(element=>new Promise((resolve,reject)=>{
    const started=performance.now();let left=element.scrollLeft,top=element.scrollTop,quietFrames=0;
    function sample(){
      const nextLeft=element.scrollLeft,nextTop=element.scrollTop;
      quietFrames=Math.abs(nextLeft-left)<.01&&Math.abs(nextTop-top)<.01?quietFrames+1:0;
      left=nextLeft;top=nextTop;
      if(quietFrames>=6){resolve({left,top,quietFrames,elapsedMs:performance.now()-started});return;}
      if(performance.now()-started>30000){reject(new Error('Native scroll did not settle'));return;}
      requestAnimationFrame(sample);
    }
    requestAnimationFrame(sample);
  }));
  action('native-scroll-settled',{selector,...result});return result;
}
async function selectCase(page,variant){
  await openDetails(page,'lesson-reference');
  const control=page.locator('#lesson-case');
  assert.equal(await control.isVisible(),true,'Actual visible case selector');
  const ids=await control.locator('option').evaluateAll(es=>es.map(e=>e.value)),index=ids.indexOf(variant);
  assert.ok(index>=0,'Independent case exists in real selector '+variant);
  action('native-case-keyboard',{variant,index,keys:['Alt+ArrowDown','Home',...Array(index).fill('ArrowDown'),'Enter']});
  await control.focus();
  await page.keyboard.press('Alt+ArrowDown');
  await page.keyboard.press('Home');
  for(let i=0;i<index;i++)await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await settle(page);
  assert.equal(await control.inputValue(),variant,'Native selector committed exact case');
}
async function choose(page,id,variant='default',touch=false){
  action('picker-input',{selector:'#lab-scenario-search',value:id});
  await page.locator('#lab-scenario-search').fill(id);
  await activate(page,'[data-scenario-option='+JSON.stringify(id)+']',touch);
  assert.equal((await observe(page)).id,id);
  if(variant!=='default')await selectCase(page,variant);
  const state=await observe(page);
  assert.equal(state.variant,variant);
  assert.equal(state.attribute,null);
  assert.equal(state.object,null);
  assert.equal(state.trace.length,0);
  return state;
}
async function pause(page){if((await observe(page)).status==='playing')await activate(page,'#play');}
async function range(page,selector,value){
  assert.ok(Number.isInteger(value)&&value>=0&&value<=1000,'Range integer0..1000');
  const control=page.locator(selector),keys=[];
  await control.focus();
  keys.push('Home');
  await page.keyboard.press('Home');
  if(value===1000){keys.push('End');await page.keyboard.press('End');}
  else{
    let actual=Number(await control.inputValue());
    // Inspect the native large increment, then use arrows for exact final units.
    // This never assigns a DOM value or dispatches a synthetic input event.
    while(value-actual>=100){
      keys.push('PageUp');
      await page.keyboard.press('PageUp');
      const next=Number(await control.inputValue());
      assert.ok(next>actual,'Native large range increment progresses');
      actual=next;
    }
    while(actual!==value){
      const key=actual<value?'ArrowRight':'ArrowLeft';
      keys.push(key);
      await page.keyboard.press(key);
      actual=Number(await control.inputValue());
    }
  }
  action('native-range-keyboard',{selector,value,keys});
  await settle(page);
}
async function reset(page){
  const before=await observe(page);
  if(before.attribute||before.object)await activate(page,'[data-clear-trace]');
  await activate(page,'#reset');
  const state=await observe(page);
  assert.equal(state.held.cursor.eventIndex,-1,'Reset returns initial canonical cursor');
  assert.equal(state.object,null);
  return state;
}
async function checkpoint(page,at){
  assert.ok(at&&typeof at==='object','Explicit checkpoint required');
  if(at.milestone==='initial')return reset(page);
  if(at.end){assert.equal(at.milestone,'complete');await range(page,'#seek',1000);const state=await observe(page);assert.equal(state.held.cursor.milestone,'complete');return state;}
  assert.ok(typeof at.stepId==='string'&&typeof at.milestone==='string'&&at.milestone,'Exact event and authored milestone required');
  const info=await page.evaluate(at=>{const a=document.querySelector('auth-flow-studio'),index=a.steps.findIndex(s=>s.id===at.stepId);if(index<0)throw new Error('Missing authored event '+at.stepId);const clock=a.studyClock(),event=a.heldView.compiled().plan.events[at.stepId],milestones=event?.milestones||[];return {index,offset:clock.offsets[index],duration:clock.durations[index],total:clock.total,milestones};},at);
  if(at.milestone==='complete'){
    action('native-timeline-checkpoint',{stepId:at.stepId,index:info.index});await activate(page,'#timeline [data-step="'+info.index+'"]');
    await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete',null,{timeout:120000});
  }else{
    const index=info.milestones.findIndex(m=>m.id===at.milestone);
    assert.ok(index>=0,'Explicit authored milestone missing '+at.stepId+':'+at.milestone);
    const low=(info.offset+info.duration*info.milestones[index].at)/info.total*1000,high=(info.offset+info.duration*(info.milestones[index+1]?.at??1))/info.total*1000;
    const value=Math.ceil((low+high)/2);
    assert.ok(value>=low&&value<high,'Actual seek control cannot resolve milestone interval '+at.stepId);
    await range(page,'#seek',value);
  }
  const state=await observe(page);assert.equal(state.held.cursor.eventIndex,info.index,'Exact checkpoint event');assert.equal(state.held.cursor.milestone,at.milestone,'Exact checkpoint milestone');return state;
}
function predicate(frame,p){assert.ok(['state','holding'].includes(p.target),'Unknown independent predicate target');if(p.target==='state'){assert.ok(Object.hasOwn(p,'equals'),'Typed equals missing');assert.ok(typeof p.path==='string'&&p.path&&!p.path.split('.').some(k=>['__proto__','constructor','prototype'].includes(k)),'Safe state path');let actual=frame.protocol.state;for(const k of p.path.split('.')){assert.ok(actual!==null&&typeof actual==='object'&&Object.hasOwn(actual,k),'Missing state path '+p.path);actual=actual[k];}assert.deepEqual(actual,p.equals,p.path+' independent expected value');return {target:p.target,path:p.path,expected:p.equals,actual};}assert.equal(typeof p.present,'boolean');assert.ok(p.actorId&&p.artifactId,'Explicit holding identity');const actual=frame.held.holdings.filter(h=>h.actorId===p.actorId&&h.artifactId===p.artifactId&&(!p.representation||h.representationId===p.representation));assert.equal(actual.length>0,p.present,'Independent holding presence '+p.artifactId);return {target:p.target,actorId:p.actorId,artifactId:p.artifactId,representation:p.representation,expected:p.present,actual:actual.length>0};}
async function screenshot(page,name){assert.ok(report.screenshots.length<64,'Bounded representative screenshot limit');const file=name.replace(/[^A-Za-z0-9_.-]/g,'-')+'.png';await page.screenshot({path:path.join(out,file),fullPage:false});const item={file,...digest(path.join(out,file))};report.screenshots.push(item);return item;}
async function geometry(page,{beginner=false}={}){await settle(page);const result=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};},visible=e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&!e.closest('[hidden]')&&getComputedStyle(e).visibility!=='hidden';},graph=rect(a.refs.graph),cards=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(e=>({id:e.dataset.actor||e.dataset.heldDock,...rect(e)})),overlaps=[];for(let i=0;i<cards.length;i++)for(let j=i+1;j<cards.length;j++){const l=cards[i],r=cards[j];if(l.left<r.right-1&&l.right>r.left+1&&l.top<r.bottom-1&&l.bottom>r.top+1)overlaps.push([l.id,r.id]);}const clipSelectors='.actor-name,.actor-title,.packet-name,.held-object-name,#step-attributes code,#held-inspector code';const clipped=[...a.querySelectorAll(clipSelectors)].filter(visible).filter(e=>e.scrollWidth>e.clientWidth+1&&getComputedStyle(e).overflowX!=='auto'&&getComputedStyle(e).overflowX!=='scroll').map(e=>({text:e.textContent.slice(0,160),class:e.className}));const map=a.querySelector('.map-scroll'),external=a.querySelector('#held-objects');return {viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio},documentOverflow:document.documentElement.scrollWidth>innerWidth+1,graph,cards,overlaps,clipped,outside:cards.filter(c=>c.left<graph.left-1||c.right>graph.right+1||c.top<graph.top-1||c.bottom>graph.bottom+1),inventory:{geometry:a.refs.graph.dataset.heldGeometry,externalVisible:visible(external),scrollWidth:map.scrollWidth,clientWidth:map.clientWidth,overflowX:getComputedStyle(map).overflowX},targets:[...a.querySelectorAll('#held-objects button,#held-docks button,#play,#reset')].filter(visible).map(e=>({label:e.getAttribute('aria-label')||e.textContent.slice(0,50),...rect(e)})).filter(r=>r.width<43.9||r.height<43.9),beginner:Object.fromEntries(['learning-question','learning-start','learning-boundary','map-controls','scenario-title'].map(id=>{const e=a.querySelector('#'+id);return [id,{text:e.textContent.trim(),...rect(e)}];})),coverage:a.heldView.snapshot().coverageStatus};});assert.equal(result.documentOverflow,false,'No document horizontal overflow');for(const k of ['overlaps','clipped','outside','targets'])assert.deepEqual(result[k],[],'Geometry '+k);assert.equal(result.coverage,'complete','Explicit held ownership complete');assert.ok(result.cards.length,'Real rendered actors');if(result.inventory.scrollWidth>result.inventory.clientWidth+1)assert.ok(['auto','scroll'].includes(result.inventory.overflowX),'Intentional graph scroll');if(beginner){for(const id of ['learning-question','learning-start','learning-boundary']){const r=result.beginner[id];assert.ok(r.text&&r.top>=0&&r.bottom<=result.viewport.height,id+' visible first viewport');}assert.ok(result.beginner['scenario-title'].top<result.viewport.height,'Actual diagram begins in first viewport');}return result;}
async function beginnerSurface(page){
  const geometryResult=await geometry(page,{beginner:true});
  const controls=await page.evaluate(()=>{
    const rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom};};
    const a=document.querySelector('auth-flow-studio'),viewport=a.refs.graph.parentElement.getBoundingClientRect();
    const names=[...a.querySelectorAll('.actor-name')].map(e=>({name:e.textContent,...rect(e)})).filter(r=>r.left>=viewport.left&&r.right<=Math.min(viewport.right,innerWidth)&&r.top>=0&&r.bottom<=innerHeight);
    return {id:a.labScenarioId,play:rect(a.querySelector('#play')),names};
  });
  assert.ok(controls.play.top>=0&&controls.play.bottom<=geometryResult.viewport.height,'Play visible in first viewport');
  assert.ok(controls.names.length,'Beginning of useful flow includes a fully visible named actor, not merely the diagram heading');
  return {...geometryResult,entry:controls};
}
async function focusState(page){return page.evaluate(()=>{const e=document.activeElement,r=e?.getBoundingClientRect();return {id:e?.id,scenario:e?.dataset.labScenario,connected:e?.isConnected,visible:!!r?.width&&!!r?.height&&r.bottom>0&&r.top<innerHeight&&r.right>0&&r.left<innerWidth&&!e.closest('[hidden]'),bounds:r?{left:r.left,top:r.top,right:r.right,bottom:r.bottom}:null,focusVisible:e?.matches(':focus-visible')};});}
async function fieldIndexAccessibility(page){
  const cdp=await page.context().newCDPSession(page);
  try{
    await cdp.send('DOM.enable');
    const document=await cdp.send('DOM.getDocument',{depth:-1}),buttons=[];
    const walk=node=>{
      const attributes=node.attributes||[];
      for(let i=0;i<attributes.length;i+=2)if(attributes[i]==='data-index-attribute')buttons.push({id:attributes[i+1],backendId:node.backendNodeId});
      for(const child of node.children||[])walk(child);
    };
    walk(document.root);
    const tree=await cdp.send('Accessibility.getFullAXTree');
    const named=new Set(tree.nodes.filter(n=>!n.ignored&&n.role?.value==='button'&&n.name?.value).map(n=>n.backendDOMNodeId));
    const missing=buttons.filter(button=>!named.has(button.backendId));
    action('field-index-full-accessibility-tree',{domButtons:buttons.length,namedButtons:buttons.length-missing.length,missing:missing.map(button=>button.id)});
    assert.ok(buttons.length>1,'Actual global field controls');
    assert.deepEqual(missing,[],'Every offscreen field retains its accessible button name');
    const rows=page.locator('#attribute-index-list [data-index-attribute]'),last=await rows.last().getAttribute('data-index-attribute');
    await rows.nth(buttons.length-2).focus();
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(()=>document.activeElement.dataset.indexAttribute),last,'Native Tab reaches the final offscreen field');
    return {domButtons:buttons.length,namedButtons:buttons.length,finalKeyboardField:last,speechClaim:false};
  }finally{await cdp.detach();}
}
async function navigation(page,manifest){
  await choose(page,'basic-keycloak');
  const accessibility=await fieldIndexAccessibility(page);
  report.coverage.fieldIndexAccessibility??=[];
  report.coverage.fieldIndexAccessibility.push(accessibility);
  const results=[];await page.locator('#workspace-search').focus();await page.keyboard.press('Home');
  await page.keyboard.press('Escape');
  await page.locator('#lab-scenario-search').fill('');
  const globalIds=await page.locator('[data-scenario-option]').evaluateAll(es=>es.map(e=>e.dataset.scenarioOption));
  const expectedIds=[...manifest.provenance.baselineInventory.choiceIds,...(options.phase!=='P0'?manifest.scenarios.filter(s=>!s.optional&&s.deliveryScope==='core').map(s=>s.runtimeId):[])];
  assert.deepEqual([...globalIds].sort(),[...expectedIds].sort(),'Exact phase-aware global picker catalog, no duplicates or optional extras');
  report.coverage.observedChoiceIds=globalIds;
  await page.keyboard.press('Escape');
  await page.locator('#workspace-search').focus();
  await page.keyboard.press('Home');
  const workspaceOptions=await page.locator('[data-workspace-option]').evaluateAll(es=>es.map(e=>({id:e.dataset.workspaceOption,label:e.textContent})));
  assert.ok(workspaceOptions.some(o=>o.id==='workspace-web')&&workspaceOptions.some(o=>o.id.startsWith('family-')),'Actual grouped workspace/family options');
  assert.equal(new Set(workspaceOptions.map(o=>o.id)).size,workspaceOptions.length);
  for(const option of workspaceOptions){await page.locator('#workspace-search').fill('');await activate(page,'[data-workspace-option='+JSON.stringify(option.id)+']');const state=await observe(page);if(option.id.startsWith('workspace-'))assert.equal(state.workspace,option.id.slice(10));if(option.id.startsWith('family-'))assert.equal(option.id,'family-'+state.workspace+'-'+state.family);if(option.id==='files-smb-shortcut'){assert.equal(state.id,'lab-smb-nonjoined-kerberos');assert.match(await page.evaluate(()=>location.hash),/^#\/windows\/files\//);}results.push({option:option.id,id:state.id,workspace:state.workspace,family:state.family});}
  for(const id of manifest.provenance.baselineInventory.choiceIds){await choose(page,id);const route=await page.evaluate(()=>location.hash);assert.ok(route.startsWith('#/'),'Canonical route');results.push({oldChoice:id,route});}
  await choose(page,'basic-keycloak');await page.locator('#workspace-search').fill('Kerberos');await page.keyboard.press('End');await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('ArrowUp');await page.keyboard.press('Escape');assert.equal((await observe(page)).id,'basic-keycloak');
  for(const selector of ['#workspace-search','#lab-scenario-search']){
    const input=page.locator(selector);
    await input.focus();
    await page.keyboard.press('Escape');
    const closedValue=await input.inputValue(),closedScenario=(await observe(page)).id;
    action('picker-native-closed-caret',{selector,keys:['Home','ArrowRight','x'],expectedCaret:2});
    for(const key of ['Home','ArrowRight','x'])await page.keyboard.press(key);
    assert.equal(await input.inputValue(),closedValue.slice(0,1)+'x'+closedValue.slice(1),'Typing preserves native text insertion');
    assert.equal(await input.evaluate(n=>n.selectionStart),2,'Opening from input preserves the native caret');
    assert.equal((await observe(page)).id,closedScenario,'Text editing does not select a lesson');
    await page.keyboard.press('Escape');
    const editingKeys=['Control+ArrowLeft','Shift+Home','Control+End','Control+ArrowRight','Shift+End'];
    action('picker-native-edit-sequence',{selector,keys:[...editingKeys,'Escape'],composition:'CDP Input.imeSetComposition Kerberos + trusted Enter, then cancel',emptyQuery:'zzzz-no-matches-next-native'});
    await page.locator(selector).fill('Kerberos');
    const before=await page.locator(selector).getAttribute('aria-activedescendant');
    for(const key of editingKeys){await page.keyboard.press(key);assert.equal(await page.locator(selector).getAttribute('aria-activedescendant'),before,'Modified text editing does not navigate results');}
    await page.keyboard.press('Escape');
    const cdp=await page.context().newCDPSession(page);
    await page.locator(selector).fill('');
    const state=await observe(page);
    await cdp.send('Input.imeSetComposition',{text:'Kerberos',selectionStart:8,selectionEnd:8});
    assert.ok(await page.locator(selector==='#workspace-search'?'[data-workspace-option]':'[data-scenario-option]').count(),'Composition query has actual selectable results');
    await cdp.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
    await cdp.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
    assert.equal((await observe(page)).id,state.id,'Composition Enter cannot select matching result');
    await cdp.send('Input.imeSetComposition',{text:'',selectionStart:0,selectionEnd:0});
    await cdp.detach();
    await page.keyboard.press('Escape');
    await page.locator(selector).fill('zzzz-no-matches-next-native');assert.equal(await page.locator(selector==='#workspace-search'?'[data-workspace-option]':'[data-scenario-option]').count(),0);await page.keyboard.press('Enter');assert.equal((await observe(page)).id,state.id);await page.keyboard.press('Tab');assert.equal(await page.locator(selector).getAttribute('aria-expanded'),'false');
  }
  for(const [selector,query] of [['#workspace-search','ad-ds'],['#lab-scenario-search','lab-ad-first-sign-in']]){
    action('picker-native-keyboard-selection',{selector,query,keys:['Home','ArrowDown','ArrowUp','Enter']});
    await page.locator(selector).fill(query);
    for(const key of ['Home','ArrowDown','ArrowUp','Enter'])await page.keyboard.press(key);
    assert.equal((await observe(page)).id,'lab-ad-first-sign-in');
  }
  await choose(page,'lab-win-ntlmv2-domain');
  await choose(page,'lab-ssh-cert-success');
  action('native-history',{commands:['back','forward']});
  await page.goBack();
  await settle(page);
  assert.equal((await observe(page)).id,'lab-win-ntlmv2-domain');
  await page.goForward();
  await settle(page);
  assert.equal((await observe(page)).id,'lab-ssh-cert-success');
  await choose(page,'lab-win-ntlmv2-domain');await activate(page,'#play');await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='playing');
  for(const selector of ['#workspace-search','#lab-scenario-search']){
    const before=await observe(page);
    const references=await page.evaluateHandle(()=>{const a=document.querySelector('auth-flow-studio');return {source:a.scenarioSnapshot(),steps:a.steps,queue:a.player.queue};});
    const elapsedBefore=await page.evaluate(()=>document.querySelector('auth-flow-studio').player.snapshot().overallElapsed);
    action('filter-playing-preserve-identity',{selector,query:'Kerberos'});
    await page.locator(selector).fill('Kerberos');
    await settle(page);
    const after=await observe(page);
    const identities=await page.evaluate(ref=>{const a=document.querySelector('auth-flow-studio');return {source:a.scenarioSnapshot()===ref.source,steps:a.steps===ref.steps,queue:a.player.queue===ref.queue,elapsed:a.player.snapshot().overallElapsed};},references);
    await references.dispose();
    assert.equal(after.id,before.id);
    assert.equal(after.variant,before.variant);
    assert.equal(after.context,before.context);
    assert.equal(after.status,'playing');
    assert.deepEqual(after.queue,before.queue);
    assert.deepEqual(after.trace,before.trace);
    assert.equal(after.object,before.object);
    assert.equal(after.attribute,before.attribute);
    assert.ok(identities.source&&identities.steps&&identities.queue,'Filtering preserves actual source/steps/player queue references');
    assert.ok(identities.elapsed>=elapsedBefore,'Filtering does not rewind source playback');
    results.push({filterDuringPlayback:selector,before,after,identities,elapsedBefore});
    await page.keyboard.press('Escape');
  }
  await pause(page);
  await openDetails(page,'ready-journeys');const starters=page.locator('#workspace-presets [data-lab-scenario]');assert.ok(await starters.count(),'Actual workspace starters');const target=await starters.first().getAttribute('data-lab-scenario');await starters.first().focus();await page.keyboard.press('Enter');assert.equal((await observe(page)).id,target);let focus=await focusState(page);assert.ok(focus.connected&&focus.visible&&focus.focusVisible);assert.ok(focus.id==='play'||focus.scenario===target);results.push({starterFocus:focus});
  await choose(page,'lab-win-ntlmv2-domain');await openDetails(page,'lesson-reference');const related=page.locator('#related-journeys [data-compare-scenario]');assert.ok(await related.count(),'Actual related journey');const relatedId=await related.first().getAttribute('data-compare-scenario');await related.first().focus();await page.keyboard.press('Space');assert.equal((await observe(page)).id,relatedId);focus=await focusState(page);assert.ok(focus.connected&&focus.visible&&focus.focusVisible);assert.ok(focus.id==='play'||focus.scenario===relatedId);results.push({relatedFocus:focus});
  return results;
}
async function routes(page,target,manifest,full){const checks=[{route:'',id:'basic-keycloak'},{route:'#/web/basic-keycloak',id:'basic-keycloak'},{route:'#/windows/files/lab-smb-nonjoined-kerberos',id:'lab-smb-nonjoined-kerberos'},{route:'#/unsupported/../../lab-nope',id:'basic-keycloak'},{route:'#/files/nfs/lab-smb-nonjoined-kerberos',id:'basic-keycloak'},...(full?manifest.scenarios.filter(s=>!s.optional).map(s=>({route:'#/'+s.workspace+'/'+s.family+'/'+s.runtimeId,id:s.runtimeId})):[])];const results=[];for(const item of checks){action('navigate-route',{...item});await page.goto(target+item.route,{waitUntil:'load'});await page.waitForFunction(()=>!!document.querySelector('auth-flow-studio')?.heldView);assert.equal((await observe(page)).id,item.id);results.push({...item,actual:await page.evaluate(()=>location.hash)});}return results;}
function worksheetRows(value){const rows=[];function visit(x){if(!x||typeof x!=='object')return;if(!Array.isArray(x)&&(x.runtimeId||x.runtimeID)&&x.canonicalCases){rows.push(x);return;}for(const v of Object.values(x))if(v&&typeof v==='object')visit(v);}visit(value);return rows;}
const worksheetNames=['nfs','windows-workstation','unix-workstation','jwt','kubernetes','mcp'];
let contracts=new Map();
function sourceCheck(label,fn){
  const entry={label,scope:{kind:'source-gate'},passed:false};
  report.cases.push(entry);
  try{entry.result=fn();entry.passed=true;}
  catch(error){entry.error=String(error.stack||error);report.failures.push({label,scope:entry.scope,error:entry.error});}
  save();
  return entry;
}
function loadContracts(manifest){
  const core=manifest.scenarios.filter(s=>!s.optional&&s.deliveryScope==='core');
  assert.equal(core.length,manifest.counts.coreNewChoices,'Manifest full core count');
  const sourceRows=new Map(),verifiedSnapshots=new Set();
  for(const name of worksheetNames){
    const file='docs/next-expansion/'+name+'-sources.json',data=readJSON(file);
    // Family ledgers use the same explicit capture/snapshot shapes as the
    // canonical collector; shared RFC IDs remain scoped to their family.
    const candidates=(data.sources||[]).map(source=>{
      const capture=source.capture?.sha256?source.capture:source.snapshot?.sha256?source.snapshot:source;
      return {...source,sourceRowId:source.sourceRowId||source.id,
        path:capture.capturedPath||capture.path||source.snapshotReference,
        sha256:capture.sha256,bytes:capture.bytes,
        httpStatus:capture.httpStatus??(typeof capture.status==='number'?capture.status:source.httpStatus)??null,
        finalUrl:capture.finalUrl||source.finalUrl,
        retrievedAt:capture.retrievedAt||source.retrievedAt||null};
    });
    sourceCheck(name+' source ledger entries',()=>{assert.ok(candidates.length,'Source rows missing');return {count:candidates.length};});
    report.sources.push({family:name,ledger:file,identity:digest(path.join(root,file)),metadata:data});
    for(const row of candidates){
      const key=name+':'+row.sourceRowId;
      if(!sourceRows.has(key))sourceRows.set(key,[]);
      sourceRows.get(key).push(row);
      const snapshot=row.path||row.snapshotReference;
      if(snapshot&&row.sha256){
        const record=sourceCheck(row.sourceRowId+' source snapshot identity',()=>{
          const file=path.resolve(root,snapshot);
          assert.ok(file.startsWith(root+path.sep),'Source snapshot remains inside source root');
          const actual=digest(file);
          assert.equal(actual.sha256,row.sha256,'Captured source bytes match independently recorded hash');
          if(row.bytes!==undefined)assert.equal(actual.bytes,row.bytes,'Complete captured source byte length');
          return {sourceRowId:row.sourceRowId,path:snapshot,actual,httpStatus:row.httpStatus??row.status};
        });
        if(record.passed)verifiedSnapshots.add(row);
      }
      report.sources.push({family:name,...row});
    }
    const worksheet='docs/next-expansion/'+name+'-worksheet.json';
    for(const row of worksheetRows(readJSON(worksheet))){
      const id=row.runtimeId||row.runtimeID;
      assert.ok(!contracts.has(id),'Duplicate worksheet runtime ID '+id);
      contracts.set(id,{family:name,worksheet,row});
    }
  }
  sourceCheck('Kubernetes selected release and implementation snapshot identities',()=>{
    const sources=readJSON('docs/next-expansion/kubernetes-sources.json'),support=readJSON('docs/next-expansion/kubernetes-support-evidence.json'),additional=[];
    for(const name of sources.additionalEvidence){const evidence=readJSON('docs/next-expansion/'+name);additional.push(...(evidence.sources||[]),...(evidence.source?[evidence.source]:[]),...(evidence.path?[evidence]:[]));}
    const records=[...sources.releaseIdentities,...sources.implementation,...support.implementation,...additional],verified=[];
    for(const record of records){
      assert.equal(record.httpStatus,200,'Successful selected implementation capture '+record.path);
      const file=path.resolve(root,record.path);assert.ok(file.startsWith(root+path.sep),'Implementation snapshot remains inside source root');
      const actual=digest(file);assert.equal(actual.sha256,record.sha256,record.path);assert.equal(actual.bytes,record.bytes,record.path);
      verified.push({path:record.path,...actual,finalUrl:record.finalUrl,revision:record.revision||null});
    }
    const ref=readJSON('docs/next-expansion/sources/kubernetes/release-ref.json'),tag=readJSON('docs/next-expansion/sources/kubernetes/release-tag.json'),published=readJSON('docs/next-expansion/sources/kubernetes/release-published.json');
    assert.equal(sources.profile.selectedVersion,'v1.37.1');assert.equal(ref.object.sha,sources.profile.tagObject);
    assert.equal(tag.sha,sources.profile.tagObject);assert.equal(tag.tag,sources.profile.selectedVersion);assert.equal(tag.object.sha,sources.profile.commit);
    assert.equal(published.tag_name,tag.tag);assert.equal(published.draft,false);assert.equal(published.prerelease,false);
    return {profile:sources.profile,verified};
  });
  const uniqueSource=(family,id)=>{
    const rows=sourceRows.get(family+':'+id);
    assert.equal(rows?.length,1,'Required source row must resolve uniquely within '+family+': '+id);
    return rows[0];
  };
  const captured=row=>{
    assert.equal(row.httpStatus,200,'Genuine captured successful HTTP200 required '+row.sourceRowId);
    assert.ok(verifiedSnapshots.has(row),'Verified complete captured bytes required '+row.sourceRowId);
    assert.ok(row.finalUrl&&/^https?:/.test(row.finalUrl)&&row.retrievedAt,'Observed final URL and capture time required '+row.sourceRowId);
    // An exact retained snapshot does not invent a publication revision for
    // rolling documentation. Implementation pins are checked separately.
    return {sourceRowId:row.sourceRowId,sha256:row.sha256,finalUrl:row.finalUrl,retrievedAt:row.retrievedAt,publicationRevision:row.revision||null};
  };
  for(const item of core)for(const id of item.sourceRowIds)sourceCheck(item.id+' '+id+' required primary-source gate',()=>{
    const family=contracts.get(item.runtimeId)?.family,row=uniqueSource(family,id);
    if(row.httpStatus===200)return {status:'captured-200-verified',source:captured(row)};
    const replacement=row.replacementEvidence;
    assert.ok(replacement?.sourceRowIds?.length&&replacement.claimScope&&replacement.reason&&Array.isArray(replacement.excludedClaims)&&replacement.excludedClaims.length,'Unavailable original needs independent explicit replacementEvidence, never implicit alias '+id);
    const replacements=replacement.sourceRowIds.map(otherId=>{assert.notEqual(otherId,id,'Replacement cannot be itself');return captured(uniqueSource(family,otherId));});
    return {status:'mapped-alternate-claim-limited',original:{sourceRowId:id,httpStatus:row.httpStatus,sha256:row.sha256},replacements,claimScope:replacement.claimScope,excludedClaims:replacement.excludedClaims,reason:replacement.reason};
  });
  for(const item of core){
    const contract=contracts.get(item.runtimeId);
    assert.ok(contract,'Independent worksheet missing '+item.runtimeId);
    const row=contract.row;
    assert.ok(row.modelProfile?.name&&row.modelProfile?.version!==undefined,'Independent modelProfile missing '+item.runtimeId);
    assert.ok(row.canonicalCases?.length,'canonicalCases missing '+item.runtimeId);
    assert.ok(row.canonicalCases.some(c=>c.id==='default'),'Default predicates missing '+item.runtimeId);
    assert.equal(new Set(row.canonicalCases.map(c=>c.id)).size,row.canonicalCases.length,'Duplicate case IDs');
    for(const c of row.canonicalCases){
      assert.ok(c.assertions?.some(p=>p.target==='state'&&p.at?.milestone!=='initial'),'Meaningful noninitial state assertion required '+item.runtimeId+':'+c.id);
      for(const p of c.assertions)assert.ok(p.at,'Explicit predicate checkpoint');
    }
    contract.manifest=item;
  }
  report.coverage.expectedCoreIds=core.map(s=>s.runtimeId);
  report.coverage.expectedCases=core.flatMap(s=>contracts.get(s.runtimeId).row.canonicalCases.map(c=>({id:s.runtimeId,variant:c.id})));
  assert.ok(report.cases.filter(entry=>entry.scope?.kind==='source-gate').every(entry=>entry.passed),'Source prerequisites must resolve before native browser collection');
  return core;
}
function loadTargetedReview(){
  const filename=path.resolve(root,options['review-fixtures']);
  assert.equal(fs.realpathSync(filename),filename,'Review fixtures cannot follow a symlink');
  const input=JSON.parse(fs.readFileSync(filename,'utf8'));
  assert.equal(input.schemaVersion,1);
  assert.equal(input.kind,'next-expansion-targeted-native-fixtures');
  assert.ok(input.reviewSha256&&/^[a-f0-9]{64}$/.test(input.reviewSha256),'Exact independent review identity required');
  assert.ok(Array.isArray(input.cases)&&input.cases.length>0&&input.cases.length<=64,'Bounded explicit correction cases required');
  const entries=input.cases.map(item=>{
    const contract=contracts.get(item.id),fixture=contract?.row.canonicalCases.find(c=>c.id===item.variant);
    assert.ok(contract?.manifest&&fixture,'Unknown independent review case '+JSON.stringify(item));
    assert.ok(Array.isArray(item.findings)&&item.findings.length,'Case must identify its correction scope');
    return {item,contract,fixture};
  });
  const keys=entries.map(({item})=>item.id+':'+item.variant);
  assert.equal(new Set(keys).size,keys.length,'No duplicate review cases');
  assert.ok(Array.isArray(input.replays)&&input.replays.length>0&&input.replays.length<=24,'Bounded explicit replay fixtures required');
  const replays=input.replays.map(item=>{
    const contract=contracts.get(item.id);
    const fixtures=(contract?.row.nativeReplay||[]).filter(f=>f.kind===item.kind&&(f.caseId||'default')===item.variant);
    assert.equal(fixtures.length,1,'Replay reference must resolve exactly once: '+JSON.stringify(item));
    return {item,contract,fixture:fixtures[0]};
  });
  assert.ok(Array.isArray(input.surfaces)&&input.surfaces.length>0&&input.surfaces.length<=12,'Bounded explicit surface representatives required');
  for(const item of input.surfaces)assert.ok(entries.some(e=>e.item.id===item.id&&e.item.variant===item.variant),'Surface must be a declared review case');
  report.targetedReview={input:{path:filename,...digest(filename)},reviewSha256:input.reviewSha256,cases:input.cases,replays:input.replays,surfaces:input.surfaces,notEstablished:['No all-case or all-variant native matrix claim.','No browser-menu zoom, real AT speech or live platform acceptance claim.']};
  report.coverage.expectedCoreIds=[...new Set(entries.map(e=>e.item.id))];
  report.coverage.expectedCases=entries.map(({item})=>({id:item.id,variant:item.variant}));
  return {entries,replays,surfaces:input.surfaces,input:report.targetedReview.input};
}
function familyContracts(){
  const groups=new Map();
  for(const contract of contracts.values()){
    if(!contract.manifest)continue;
    const key=contract.manifest.workspace+'/'+contract.manifest.family;
    if(!groups.has(key))groups.set(key,{key,entries:[]});
    groups.get(key).entries.push(contract);
  }
  return [...groups.values()];
}
function entryRepresentatives(){
  return familyContracts().map(group=>({id:group.entries[0].manifest.runtimeId,variant:'default',beginner:true,selection:'Independent first core row for '+group.key}));
}
function denseRepresentatives(){
  return familyContracts().map(group=>{
    const ids=new Set(group.entries.map(c=>c.manifest.runtimeId));
    const observed=report.cases.filter(c=>c.result?.profile&&ids.has(c.result.id)).sort((a,b)=>(b.result.profile.stepCount-a.result.profile.stepCount)||(b.result.final.holdingCount-a.result.final.holdingCount));
    return observed.length?{id:observed[0].result.id,variant:observed[0].result.variant,selection:'Observed largest authored step count, then final holdings; geometry representative only, never a correctness oracle'}:{id:group.entries[0].manifest.runtimeId,variant:'default',selection:'Independent manifest family first row'};
  });
}
async function semanticCase(page,contract,fixture){
  const id=contract.manifest.runtimeId,mode=activeRecord.mode,caseKey=mode+':'+id+':'+fixture.id;
  const raw={schemaVersion:1,caseKey,mode,id,variant:fixture.id,expectedProfile:fixture.modelProfile||contract.row.modelProfile,frames:[],predicates:[],passed:false};
  const result={id,variant:fixture.id};
  try{
    await choose(page,id,fixture.id);
    const profile=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),m=a.labModel;return {id:m.id,variantId:m.variantId,name:m.profile.name,version:m.profile.version,variants:m.variantChoices.map(v=>v.id),stepCount:a.steps.length};});
    raw.profile=profile;result.profile=profile;
    assert.equal(profile.id,id,'Named variants retain the same frozen model ID');
    assert.equal(profile.variantId,fixture.id,'Actual model declares the exact variant, not only UI selection');
    assert.ok(raw.expectedProfile?.name&&raw.expectedProfile.version!==undefined,'Independent case/row profile identity required');
    assert.equal(profile.name,raw.expectedProfile.name);
    assert.equal(String(profile.version),String(raw.expectedProfile.version));
    assert.deepEqual([...profile.variants].sort(),contract.row.canonicalCases.map(c=>c.id).sort(),'Model/independent required variant IDs');
    let lastKey,frame,frameRef;
    for(const p of fixture.assertions){
      const key=JSON.stringify(p.at);
      if(key!==lastKey){frame=await checkpoint(page,p.at);frameRef='checkpoint-'+raw.frames.length;raw.frames.push({id:frameRef,at:p.at,frame});lastKey=key;}
      action('independent-predicate-observation',{caseKey,frameRef,predicateIndex:raw.predicates.length});
      raw.predicates.push({at:p.at,frameRef,cursor:frame.held.cursor,sourceIndex:frame.protocol.sourceIndex,...predicate(frame,p)});
    }
    const final=await checkpoint(page,{end:true,milestone:'complete'});raw.final=final;
    await range(page,'#seek',0);
    const back=await observe(page);raw.backseek=back;
    assert.equal(back.object,null);assert.equal(back.attribute,null);
    assert.ok(back.held.cursor.eventIndex<=final.held.cursor.eventIndex);
    await reset(page);
    result.final={holdingCount:final.held.holdings.length,cursor:final.held.cursor,sourceIndex:final.protocol.sourceIndex};
    result.predicateCount=raw.predicates.length;result.resetInitial=true;result.backseekNoTrace=true;raw.passed=true;
    return result;
  }catch(error){raw.error=String(error.stack||error);throw error;}
  finally{
    const files=report.caseFiles??=[],file='cases/case-'+String(files.length+1).padStart(6,'0')+'.json';
    fs.mkdirSync(path.join(out,'cases'),{recursive:true});
    fs.writeFileSync(path.join(out,file),JSON.stringify(raw,null,2)+'\n',{flag:'wx'});
    const ref={caseKey,file,...digest(path.join(out,file)),passed:raw.passed};
    files.push(ref);report.caseFiles=files;result.rawEvidence=ref;
  }
}
async function openHolding(page,ref,touch=false){const state=await observe(page),holding=state.held.holdings.find(h=>h.actorId===ref.actorId&&h.artifactId===ref.artifactId&&h.representationId===ref.representation);assert.ok(holding,'Independent exact holding present '+JSON.stringify(ref));const selector='#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']';if(!await page.locator(selector).isVisible())await activate(page,'#held-objects [data-held-actor='+JSON.stringify(ref.actorId)+']',touch);await activate(page,selector,touch);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection?.holdingId),holding.holdingId);assert.deepEqual((await observe(page)).held,state.held,'Inspect never changes possession');return holding;}
async function fullPrefix(page,frame){
  // Scenario selection intentionally keeps the field being followed. Exit
  // replay through its real control before comparing a full-journey prefix.
  await activate(page,'#attribute-focus [data-clear-trace]');
  const exited=await observe(page);
  assert.equal(exited.attribute,null);
  assert.equal(exited.object,null);
  assert.equal(exited.trace.length,0);
  await choose(page,frame.id,frame.variant);
  if(frame.held.cursor.eventIndex<0)await reset(page);
  else{
    const stepId=await page.evaluate(index=>document.querySelector('auth-flow-studio').steps[index].id,frame.held.cursor.eventIndex);
    await checkpoint(page,{stepId,milestone:frame.held.cursor.milestone});
  }
  const full=await observe(page);
  assert.deepEqual(full.protocol,frame.protocol,'Replay protocol equals full canonical source prefix');
  assert.deepEqual(full.held,frame.held,'Replay exact holdings equal full canonical source prefix');
  return {cursor:frame.held.cursor,sourceIndex:frame.protocol.sourceIndex,equal:true,replayExit:'actual Full journey control'};
}
async function traceCheckpoint(page,at){
  const trace=(await observe(page)).trace,index=trace.findLastIndex(row=>row.sourceStepId===at.stepId);
  assert.ok(index>=0,'Real projected trace contains independent checkpoint '+at.stepId);
  await activate(page,'#timeline [data-step="'+index+'"]');
  await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete',null,{timeout:120000});
  const frame=await observe(page);
  assert.equal(frame.held.cursor.milestone,at.milestone,'Projected row reaches actual independent milestone');
  return frame;
}
async function replay(page,contract,fixture){
  const id=contract.manifest.runtimeId,variant=fixture.caseId||'default';
  assert.ok(['local','protected-receipt','acceptance'].includes(fixture.kind));
  assert.ok(fixture.fieldId&&fixture.holding?.representation&&fixture.at,'Independent field/holding/checkpoint replay fixture');
  const initial=await choose(page,id,variant);
  await checkpoint(page,fixture.at);
  const holding=await openHolding(page,fixture.holding);
  await activate(page,'#held-inspector [data-held-trace]');
  await pause(page);
  const trace=(await observe(page)).trace;
  assert.ok(trace.length,'Exact object replay has real operations');
  const exact=await traceCheckpoint(page,fixture.at),exactPrefix=await fullPrefix(page,exact);
  await choose(page,id,variant);
  const control='#attribute-index [data-index-attribute='+JSON.stringify(fixture.fieldId)+']';
  await page.locator(control).focus();
  action('native-field-index-enter',{fieldId:fixture.fieldId});
  await page.keyboard.press('Enter');
  await pause(page);
  assert.equal((await observe(page)).attribute,fixture.fieldId);
  assert.ok((await observe(page)).trace.length,'Actual field-index projection');
  const field=await traceCheckpoint(page,fixture.at),fieldPrefix=await fullPrefix(page,field);
  await choose(page,id,variant);
  await checkpoint(page,fixture.at);
  await openHolding(page,fixture.holding);
  await range(page,'#seek',0);
  const backseek=await observe(page);
  assert.equal(backseek.protocol.sourceIndex,-1,'Backseek completes no future source event');
  for(const key of ['state','holdings','artifacts','authority','observations','protocolClock'])assert.deepEqual(backseek.held[key],initial.held[key],'Backseek restores initial '+key);
  const selected=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),selection=a.heldView.selection;
    return {artifactId:selection?.artifactId,holdingId:selection?.holdingId,inspected:selection?.inspected,status:a.querySelector('.held-detached-status')?.textContent||null};
  });
  assert.equal(selected.artifactId,fixture.holding.artifactId,'Backseek retains inspection of the exact selected object');
  const current=backseek.held.holdings.find(h=>h.holdingId===selected.holdingId);
  if(current){
    assert.deepEqual(selected.inspected.holding,current,'A provisioned object remains a current holding after backseek');
    assert.deepEqual(selected.inspected.observations,backseek.held.observations.filter(o=>o.artifactId===selected.artifactId&&o.actorId===current.actorId),'Inspector discards later checks for a currently held object');
  }
  action('backseek-inspector-state',{id,variant,artifactId:selected.artifactId,currentHolding:!!current,observedStatus:selected.status});
  await reset(page);
  assert.equal(await page.locator('#held-inspector').isVisible(),false,'Reset closes stale exact inspector');
  const alternate=contract.row.canonicalCases.find(c=>c.id!==variant);
  if(alternate){
    await checkpoint(page,fixture.at);
    await openHolding(page,fixture.holding);
    action('native-case-switch-with-open-inspector',{from:variant,to:alternate.id});
    await selectCase(page,alternate.id);
    const changed=await observe(page);
    assert.equal(changed.variant,alternate.id);
    assert.equal(changed.object,null);
    assert.equal(changed.trace.length,0);
    assert.equal(await page.locator('#held-inspector').isVisible(),false);
  }
  await choose(page,id,variant);
  await checkpoint(page,fixture.at);
  await openHolding(page,fixture.holding);
  await choose(page,'basic-keycloak');
  assert.equal((await observe(page)).object,null);
  assert.equal(await page.locator('#held-inspector').isVisible(),false,'Route change closes stale inspector');
  return {id,variant,kind:fixture.kind,holdingId:holding.holdingId,fieldId:fixture.fieldId,trace,exactPrefix,fieldPrefix,resetVariantRouteNoStale:true};
}
async function primaryContrast(page,touch,mode){
  const observations=[];
  const settleControl=async selector=>{
    await page.locator(selector).scrollIntoViewIfNeeded();
    await page.waitForFunction(selector=>{
      const element=document.querySelector(selector);
      return element&&element.getAnimations().every(animation=>!animation.pending&&animation.playState!=='running');
    },selector);
    await settle(page);
  };
  const capture=async(selector,theme,control,state)=>{
    await settleControl(selector);
    const value=await page.locator(selector).evaluate(element=>{
      const style=getComputedStyle(element),rgb=value=>{const parts=value.match(/[\d.]+/g)?.map(Number);if(!parts||parts.length<3)throw new Error('Expected resolved RGB color '+value);return parts.slice(0,3);};
      const brightness=style.filter==='none'?1:Number(/^brightness\(([\d.]+)\)$/.exec(style.filter)?.[1]);
      if(!Number.isFinite(brightness))throw new Error('Unsupported primary filter '+style.filter);
      const filtered=value=>rgb(value).map(channel=>Math.min(255,channel*brightness));
      const foreground=filtered(style.color),background=filtered(style.backgroundColor);
      const luminance=channels=>channels.map(channel=>{channel/=255;return channel<=.04045?channel/12.92:((channel+.055)/1.055)**2.4;}).reduce((sum,channel,index)=>sum+channel*[.2126,.7152,.0722][index],0);
      const a=luminance(foreground),b=luminance(background);
      return {label:element.textContent.trim(),enabled:!element.disabled,primary:element.classList.contains('primary'),foreground,background,filter:style.filter,opacity:style.opacity,contrast:(Math.max(a,b)+.05)/(Math.min(a,b)+.05),hover:element.matches(':hover'),focusVisible:element.matches(':focus-visible'),outline:{style:style.outlineStyle,width:style.outlineWidth,color:style.outlineColor},fontSize:style.fontSize};
    });
    const observation={theme,control,state,touch,selector,...value,colorMethod:'Browser-resolved colors with the explicit CSS brightness applied to both foreground and background.'};
    observations.push(observation);
    assert.equal(value.enabled,true,'Only enabled primary controls are contrast acceptance targets');
    assert.equal(value.primary,true,'Actual primary control');
    assert.equal(Number(value.opacity),1,'Enabled primary control is opaque');
    assert.ok(value.contrast>=4.5,'Normal primary text requires 4.5:1: '+JSON.stringify(observation));
    if(state==='keyboard-focus'){assert.equal(value.focusVisible,true);assert.notEqual(value.outline.style,'none');assert.ok(parseFloat(value.outline.width)>=2,'Preserved visible focus outline');}
    return observation;
  };
  const inspect=async(selector,theme,control)=>{
    await page.mouse.move(0,0);
    await page.locator('#theme-toggle').focus();
    await capture(selector,theme,control,'default');
    if(!touch){
      await page.locator(selector).hover();
      await capture(selector,theme,control,'hover');
      await page.mouse.move(0,0);
      await page.locator(selector).focus();
      await page.keyboard.press('Shift+Tab');
      await page.keyboard.press('Tab');
      await capture(selector,theme,control,'keyboard-focus');
    }
  };
  for(const theme of ['dark','light']){
    if(await page.locator('#studio').getAttribute('data-theme')!==theme)await activate(page,'#theme-toggle',touch);
    await choose(page,'basic-keycloak','default',touch);
    await page.locator('#speed').focus();await page.keyboard.press('Home');await page.keyboard.press('ArrowRight');
    await inspect('#play',theme,'Play');
    await activate(page,'#play',touch);
    assert.equal((await observe(page)).status,'playing');
    if(touch)await capture('#play',theme,'Pause','post-native-tap');
    await inspect('#play',theme,'Pause');
    await activate(page,'#play',touch);
    assert.equal((await observe(page)).status,'paused');
    if(touch)await capture('#play',theme,'Resume','post-native-tap');
    await inspect('#play',theme,'Resume');
    if(mode==='source-http')await screenshot(page,'primary-'+theme+'-'+(touch?'touch':'desktop'));
    await choose(page,'basic-keycloak','default',touch);
    await page.locator('#attribute-index [data-index-attribute="codeChallenge"]').focus();
    await page.keyboard.press('Enter');
    await pause(page);
    await inspect('#attribute-focus [data-trace-play]',theme,'Replay path');
    if(touch){await activate(page,'#attribute-focus [data-trace-play]',true);await capture('#attribute-focus [data-trace-play]',theme,'Replay path','post-native-tap');await pause(page);}
    await activate(page,'#attribute-focus [data-clear-trace]',touch);
    const exact=targetedReview.replays[0];
    await choose(page,exact.item.id,exact.item.variant,touch);
    const replaySpeedBefore=await page.locator('#speed').inputValue();
    await page.locator('#speed').focus();await page.keyboard.press('End');
    assert.equal(await page.locator('#speed').inputValue(),await page.locator('#speed').getAttribute('max'));
    action('native-contrast-checkpoint-speed',{before:replaySpeedBefore,after:await page.locator('#speed').inputValue(),keys:['End']});
    await checkpoint(page,exact.fixture.at);
    await openHolding(page,exact.fixture.holding,touch);
    await activate(page,'#held-inspector [data-held-trace]',touch);
    await pause(page);
    await inspect('#attribute-focus [data-trace-play]',theme,'Replay exact history');
    if(touch){await activate(page,'#attribute-focus [data-trace-play]',true);await capture('#attribute-focus [data-trace-play]',theme,'Replay exact history','post-native-tap');await pause(page);}
    await activate(page,'#attribute-focus [data-clear-trace]',touch);
    await choose(page,'basic-keycloak','default',touch);
  }
  return {mode,touch,minimumTextContrast:Math.min(...observations.filter(value=>value.contrast!==undefined).map(value=>value.contrast)),observations,physicalDeviceOrATSpeech:false};
}
async function animationSurface(page){
  const targets=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),clock=a.studyClock(),internal=id=>!!a.scenarioOwnedActors?.[id]?.parentId;
    return [...new Set([a.steps.find(s=>s.from!==s.to),a.steps.find(s=>s.from===s.to),a.steps.find(s=>s.from!==s.to&&(internal(s.from)||internal(s.to)))].filter(Boolean))].map(step=>{
      const index=clock.steps.findIndex(s=>s.id===step.id),duration=clock.durations[index],timing=a.player.getTiming?.(step,'demo'),message=timing?.messages?.[0];
      const start=message?(message.start-timing.start)/(timing.end-timing.start):0,end=message?(message.end-timing.start)/(timing.end-timing.start):1;
      const count=Math.max(1,step.payload.length),scale=message?Math.min(1,(end-start)*duration/(380+(count-1)*1290+1050)):1;
      return {id:step.id,value:Math.round((clock.offsets[index]+start*duration+(380+1050*.5)*scale)/clock.total*1000)};
    });
  });
  const records=[];
  for(const target of targets){
    await range(page,'#seek',target.value);
    const result=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),event=a.player.snapshot(),step=event.step,packet=a.refs.packet,rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};},graph=rect(a.refs.graph);
      const visible=e=>!e.closest('[hidden]')&&!!e.getBoundingClientRect().width;
      const boxes=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(e=>({id:e.dataset.actor||e.dataset.heldDock,...rect(e)}));
      const paths=[],collisions=[];
      for(const line of a.refs.connections.querySelectorAll('.connection-line')){
        const matrix=line.getScreenCTM();if(!matrix)continue;
        const length=line.getTotalLength();let samples=0;
        for(let n=0;n<=Math.ceil(length);n+=3){const p=line.getPointAtLength(Math.min(n,length)),point=new DOMPoint(p.x,p.y).matrixTransform(matrix);samples++;const hit=boxes.find(b=>point.x>b.left+1&&point.x<b.right-1&&point.y>b.top+1&&point.y<b.bottom-1);if(hit){collisions.push({pair:line.parentElement.dataset.pair,actor:hit.id});break;}}
        paths.push({pair:line.parentElement.dataset.pair,samples});
      }
      return {stepId:step?.sourceStepId||step?.id,packetVisible:!packet.hidden,packet:rect(packet),graph,phase:event.messagePhase,presentation:packet.dataset.presentation,clippedNames:[...a.querySelectorAll('#packet-name,#step-attributes code,#step-attributes-external code')].filter(visible).filter(e=>e.scrollWidth>e.clientWidth+1).map(e=>e.textContent),paths,collisions};
    });
    assert.equal(result.stepId,target.id,'Actual native seek reaches authored animation');
    assert.equal(result.packetVisible,true,'Real paused packet visible, not a CSS/synthetic snapshot');
    assert.deepEqual(result.clippedNames,[],'No active token/field-name clipping');
    assert.deepEqual(result.collisions,[],'Connection paths avoid rendered actors/docks');
    const contained=result.packet.left>=result.graph.left-1&&result.packet.right<=result.graph.right+1&&result.packet.top>=result.graph.top-1&&result.packet.bottom<=result.graph.bottom+1;
    if(!contained)action('native-packet-containment-failure',result);
    assert.ok(contained,'Active packet stays inside intentional graph surface');
    records.push(result);
  }
  return records;
}
async function surface(page,ids,touch,mode){
  const results=[];
  for(const [i,entry] of ids.entries()){
    const id=typeof entry==='string'?entry:entry.id,variant=typeof entry==='string'?'default':entry.variant;
    await choose(page,id,variant,touch);
    await page.evaluate(()=>scrollTo(0,0));
    const initial=i===0||entry.beginner===true?await beginnerSurface(page):await geometry(page);
    for(const expanded of [false,true]){
      const toggle=page.locator('#show-internals');
      if(await toggle.isVisible()&&await toggle.isChecked()!==expanded)await activate(page,'#show-internals',touch);
      await checkpoint(page,{end:true,milestone:'complete'});
      await page.locator('.map-scroll').scrollIntoViewIfNeeded();
      const scene=await geometry(page),animation=await animationSurface(page);
      results.push({id,expanded,geometry:scene,animation});
    }
    if((mode.startsWith('source-http')&&(typeof entry==='string'||entry.beginner===true))||(['built-http','file'].includes(mode)&&i<2))await screenshot(page,mode+'-'+(touch?'touch':'desktop')+'-'+i+'-flow');
    await checkpoint(page,{end:true,milestone:'complete'});
    const state=await observe(page),h=state.held.holdings.at(-1);
    assert.ok(h,'Representative real held object');
    await openHolding(page,{actorId:h.actorId,artifactId:h.artifactId,representation:h.representationId},touch);
    const expandable=page.locator('#held-inspector :is(.progressive-fields,.long-protocol-value):not([open]) > summary');
    while(await expandable.count())await expandable.first().click();
    await geometry(page);
    if(touch){
      await activate(page,'#held-inspector [data-held-trace]',true);
      await pause(page);
      assert.ok((await observe(page)).trace.length);
      await page.locator('.map-scroll').scrollIntoViewIfNeeded();
      const rect=await page.locator('.map-scroll').boundingBox();
      assert.ok(rect,'Actual scrollable graph');
      const before=await page.locator('.map-scroll').evaluate(e=>({left:e.scrollLeft,overflow:e.scrollWidth>e.clientWidth+1}));
      const x=Math.min(360,rect.x+rect.width-10),y=Math.max(10,Math.min(800,rect.y+rect.height/2));
      const cdp=await page.context().newCDPSession(page);
      await cdp.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x,y}]});
      for(let n=1;n<=6;n++)await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:x-n*25,y}]});
      await cdp.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
      await cdp.detach();
      await settle(page);
      await settleNativeScroll(page,'.map-scroll');
      const after=await page.locator('.map-scroll').evaluate(e=>({left:e.scrollLeft,overflow:e.scrollWidth>e.clientWidth+1}));
      action('trusted-native-touch-swipe',{x,y,before,after});
      if(before.overflow&&before.left===0)assert.ok(after.left>0,'Intentional horizontal graph scrolling works with native touch');
      results.push({id,nativeTouchScroll:{before,after}});
    }
    results.push({id,initial,inspectedHolding:h.holdingId});
  }
  return results;
}
async function mcpVisualSurfaces(page,touch,mode){
  const goals=[
    {name:'metadata-choice',id:'lab-mcp02',variant:'default',at:{stepId:'lab-mcp02:issuer-binding',milestone:'complete'},values:['https://login.lab.example/tenant-a']},
    {name:'rejected-issuer',id:'lab-mcp04',variant:'wrong-issuer',at:{stepId:'lab-mcp04:grant-callback-validation',milestone:'complete'},values:[]},
    {name:'scoped-upgrade',id:'lab-mcp06',variant:'default',at:{stepId:'lab-mcp06:stepup-grant-token-issue',milestone:'complete'},values:['files:read','files:write']},
    {name:'two-token-audiences',id:'lab-mcp09',variant:'default',at:{stepId:'lab-mcp09:upstream-token-receipt-recover',milestone:'complete'},holding:{actorId:'mcpR',artifactId:'lab-mcp09:two-grant-comparison',representation:'plain'},values:['https://mcp.lab.example/team/mcp','https://api.lab.example/files']},
    {name:'local-stdio-contrast',id:'lab-mcp13',variant:'default',at:{stepId:'lab-mcp13:stdio-call',milestone:'complete'},values:['Local process pipes']}
  ];
  for(const goal of goals)await check(mode+' MCP visual '+goal.name+' '+(touch?'touch':'desktop'),async()=>{
    await choose(page,goal.id,goal.variant,touch);
    let protectedReceipt=null;
    if(goal.name==='two-token-audiences'){
      protectedReceipt=await checkpoint(page,{stepId:'lab-mcp09:upstream-token-receipt',milestone:'complete'});
      assert.equal(protectedReceipt.held.holdings.some(h=>h.actorId==='mcpR'&&h.artifactId==='lab-mcp09:upstream-access-g1'),false,'Protected carrier receipt is not decoded token custody');
    }
    const frame=await checkpoint(page,goal.at),state=frame.protocol.state.mcp;
    if(goal.name==='metadata-choice'){
      assert.equal(state.selectedIssuer,'https://login.lab.example/tenant-a');
      assert.equal(state.resourceMetadataValid,true);
      assert.equal(state.operationExecuted,false);
    }
    if(goal.name==='rejected-issuer'){
      assert.equal(state.callbackAccepted,false);
      assert.equal(state.credentialRequests,0);
      assert.equal(state.operationExecuted,false);
    }
    if(goal.name==='scoped-upgrade'){
      assert.deepEqual(state.requestedScopes,['files:read','files:write']);
      assert.ok(frame.held.holdings.some(h=>h.actorId==='mcpA'&&h.artifactId==='lab-mcp06:stepup-grant-access-g1'),'New exact scoped token exists at its issuer');
    }
    if(goal.name==='two-token-audiences'){
      for(const artifactId of ['lab-mcp09:downstream-access-g1','lab-mcp09:upstream-access-g1'])assert.ok(frame.held.holdings.some(h=>h.actorId==='mcpR'&&h.artifactId===artifactId),'Proxy holds each separately issued credential only after local recovery');
    }
    if(goal.name==='local-stdio-contrast'){
      assert.equal(state.httpOAuthStarted,false);
      assert.equal(state.localIdentity,'synthetic-1001');
      assert.equal(state.credentialAvailable,true);
    }
    if(goal.holding)await openHolding(page,goal.holding,touch);
    const selector=goal.holding?'#held-inspector':'.inspector-panel',target=page.locator(selector);
    for(const detail of await target.locator('details').all()){
      if(await detail.getAttribute('open')===null){
        action('expand-real-event-value',{goal:goal.name,touch});
        const summary=detail.locator(':scope > summary');
        if(touch)await summary.tap();else await summary.click();
      }
    }
    await settle(page);
    const inspector=await page.locator('#inspector').evaluate(element=>{
      const bounds=element.getBoundingClientRect(),title=element.querySelector('.inspector-title').getBoundingClientRect();
      return {clientWidth:element.clientWidth,scrollWidth:element.scrollWidth,scrollLeft:element.scrollLeft,bounds:{left:bounds.left,right:bounds.right},title:{left:title.left,right:title.right}};
    });
    assert.ok(inspector.scrollWidth<=inspector.clientWidth+1,'Expanded metadata values fit the inspector instead of an implicit min-content grid');
    assert.ok(Math.abs(inspector.scrollLeft)<1,'Opening values does not pan the inspector heading');
    assert.ok(inspector.title.left>=inspector.bounds.left&&inspector.title.right<=inspector.bounds.right,'Inspector heading remains horizontally readable');
    const text=await target.innerText();
    for(const value of goal.values)assert.ok(text.includes(value),'Capture contains the requested protocol value '+value);
    let capture=null;
    if(mode==='built-http'){
      if(!goal.holding)await page.locator('#inspector .inspector-title').scrollIntoViewIfNeeded();
      await target.scrollIntoViewIfNeeded();
      await page.mouse.move(0,0);
      const file='mcp-'+goal.name+'-'+(touch?'mobile':'desktop')+'.png';
      await target.screenshot({path:path.join(out,file)});
      capture={file,...digest(path.join(out,file)),target:selector,viewport:await page.viewportSize(),elementOnly:true,goal:goal.name};
      report.screenshots.push(capture);
      assert.ok(report.screenshots.length<=64,'Bounded representative screenshot limit');
    }
    const after=await observe(page);
    assert.deepEqual(after.protocol,frame.protocol,'Inspection and expansion preserve the same canonical protocol prefix');
    assert.deepEqual(after.held,frame.held,'Inspection and expansion do not change custody');
    return {goal,protectedReceipt,frame,inspector,renderedText:text,capture,claim:'Actual responsive semantic-state capture, not an initial-viewport, replay, manual speech or live-platform claim'};
  },{kind:'mcp-visual',mode,touch,goal:goal.name});
}

function packageIdentity(entry){
  let dir=path.dirname(entry);
  while(dir!==path.dirname(dir)){
    const file=path.join(dir,'package.json');
    if(fs.existsSync(file)){
      const pkg=JSON.parse(fs.readFileSync(file));
      const tree=Object.fromEntries(files(dir).map(f=>[path.relative(dir,f),digest(f)]));
      return {entry,...digest(entry),packageFile:file,package:digest(file),name:pkg.name,version:pkg.version,treeSha256:sha(JSON.stringify(tree)),tree};
    }
    dir=path.dirname(dir);
  }
  throw new Error('Dependency package provenance missing '+entry);
}
async function staticServer(){
  const realRoot=fs.realpathSync(root);
  server=http.createServer((req,res)=>{
    try{
      if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return;}
      const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname),file=path.resolve(root,'.'+pathname+(pathname.endsWith('/')?'index.html':''));
      assert.ok(file.startsWith(root+path.sep)&&fs.realpathSync(file).startsWith(realRoot+path.sep),'Static path escapes root');
      assert.ok(fs.statSync(file).isFile(),'Static file required');
      const types={'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.ico':'image/x-icon','.png':'image/png','.json':'application/json'};
      res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});
      if(req.method==='HEAD')res.end();else fs.createReadStream(file).pipe(res);
    }catch(error){res.writeHead(404);res.end('Not found');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  origin='http://127.0.0.1:'+server.address().port;
  report.server={origin,bind:'127.0.0.1',ephemeral:true};
}
async function logPage(page,context,record,target,mode){
  page.setDefaultTimeout(30000);
  page.on('pageerror',error=>record.errors.push(String(error)));
  page.on('console',msg=>record.console.push({type:msg.type(),text:msg.text()}));
  page.on('response',r=>record.network.push({url:r.url(),status:r.status()}));
  page.on('requestfailed',r=>record.network.push({url:r.url(),failure:r.failure()}));
  await page.exposeBinding('__nextNativeEvidence',(_,value)=>{
    if(value.kind==='csp')record.csp.push(value);
    else if(record.trustedInputs.length<1000||value.kind.startsWith('composition')||value.composing)record.trustedInputs.push(value);
  });
  await page.addInitScript(()=>{
    document.addEventListener('securitypolicyviolation',e=>void window.__nextNativeEvidence({kind:'csp',directive:e.effectiveDirective,blocked:e.blockedURI}));
    for(const type of ['pointerdown','touchstart','compositionstart','compositionend','keydown'])document.addEventListener(type,e=>void window.__nextNativeEvidence({kind:type,trusted:e.isTrusted,pointerType:e.pointerType||null,key:e.key||null,composing:e.isComposing||false,target:e.target.id||e.target.tagName}),true);
  });
  await context.route('**/*',route=>{
    const url=route.request().url(),allowed=mode==='file'?url.split('#')[0]===target:url.startsWith(origin+'/');
    if(!allowed)record.requestsBlocked.push(url);
    return allowed?route.continue():route.abort('blockedbyclient');
  });
}
function assertLog(record){
  assert.deepEqual(record.errors,[]);
  assert.deepEqual(record.csp,[]);
  assert.deepEqual(record.requestsBlocked,[]);
  assert.deepEqual(record.console.filter(m=>m.type==='error'),[]);
  assert.deepEqual(record.network.filter(n=>n.status>=400||n.failure),[]);
}
async function session(mode,touch,fn){
  const target=mode==='file'?pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href:origin+'/'+(mode==='source-http'?'':'dist/auth-flow-studio.html');
  const record={id:mode+'-'+(touch?'touch':'desktop'),mode,touch,target,viewport:touch?{width:390,height:844}:{width:1480,height:1000},errors:[],console:[],csp:[],network:[],requestsBlocked:[],trustedInputs:[]};
  report.sessions.push(record);
  activeRecord=record;
  const context=await browser.newContext({viewport:record.viewport,hasTouch:touch,isMobile:touch,bypassCSP:false,reducedMotion:touch?'no-preference':'reduce',serviceWorkers:'block'});
  const page=await context.newPage();
  await logPage(page,context,record,target,mode);
  try{
    action('load-mode',{target});
    await page.goto(target,{waitUntil:'load'});
    await page.waitForFunction(()=>!!document.querySelector('auth-flow-studio')?.heldView);
    if(!touch){action('native-speed',{keys:['End']});await page.locator('#speed').focus();await page.keyboard.press('End');}
    await fn(page,target,record);
  }finally{
    await check(record.id+' console/CSP/network/native input',async()=>{
      assertLog(record);
      if(touch)assert.ok(record.trustedInputs.some(e=>e.kind==='pointerdown'&&e.trusted&&e.pointerType==='touch'),'Actual trusted native touch observed');
      else assert.ok(record.trustedInputs.some(e=>e.kind==='keydown'&&e.trusted&&e.composing),'Actual browser composing Enter path observed');
      return {requests:record.network.length,trustedTouch:touch};
    });
    await context.close();
    activeRecord=null;
    save();
  }
}
async function realZoom(playwright){
  if(!options['zoom-procedure']){
    report.blockers.push('UNPERFORMED_REQUIRED_BROWSER_MENU_ZOOM: no --zoom-procedure provided; actual headed/X11 browser-menu200/400 is separate from390 viewport simulation. No CSS/CDP zoom substitute was executed.');
    return;
  }
  assert.ok(path.isAbsolute(options['zoom-procedure']));
  const procedure=JSON.parse(fs.readFileSync(options['zoom-procedure'],'utf8'));
  assert.equal(procedure.schemaVersion,1);
  assert.equal(procedure.mechanism,'x11-browser-menu');
  assert.ok(procedure.display);
  report.zoomEnvironment={DISPLAY:procedure.display,LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH||null,IMLIB2_LOADER_PATH:process.env.IMLIB2_LOADER_PATH||null};
  assert.equal(procedure.isolatedDisplay,true,'Whole-screen capture requires explicitly dedicated isolated Xvfb, never a user desktop');
  const displayServer=procedure.displayServer;
  assert.ok(displayServer&&path.isAbsolute(displayServer.program||'')&&path.basename(displayServer.program)==='Xvfb'&&Number.isInteger(displayServer.pid)&&displayServer.pid>1,'Exact live dedicated Xvfb process required');
  const proc='/proc/'+displayServer.pid,displayExe=fs.readlinkSync(proc+'/exe'),displayArgv=fs.readFileSync(proc+'/cmdline','utf8').split(String.fromCharCode(0)).filter(Boolean);
  assert.equal(fs.realpathSync(displayExe),fs.realpathSync(displayServer.program),'Dedicated Xvfb executable identity');
  assert.equal(fs.statSync(proc).uid,os.userInfo().uid,'Dedicated Xvfb belongs to current user');
  assert.ok(displayArgv.includes(procedure.display),'Recorded Xvfb serves exactly the isolated display');
  const displayIdentity={...displayServer,exe:displayExe,argv:displayArgv,...digest(displayServer.program)};
  assert.deepEqual(procedure.steps.map(s=>s.percent),[200,400]);
  assert.ok(path.isAbsolute(procedure.screenCaptureProgram||'')&&path.basename(procedure.screenCaptureProgram)==='scrot','Provisioned scrot required to retain actual native browser menu, not page-only screenshot');
  const profile=fs.mkdtempSync(path.join(os.tmpdir(),'auth-lab-next-native-zoom-'));
  const title='Auth Lab Native Zoom '+process.pid;
  let context;
  try{
    context=await playwright.chromium.launchPersistentContext(profile,{executablePath:process.env.CHROMIUM_EXECUTABLE,headless:false,viewport:null,bypassCSP:false,env:{...process.env,DISPLAY:procedure.display},args:['--window-size=1480,1000','--disable-gpu','--disable-background-networking','--disable-component-update','--no-first-run','--no-default-browser-check']});
    const page=context.pages()[0]||await context.newPage(),target=origin+'/dist/auth-flow-studio.html';
    const record={id:'headed-real-browser-menu-zoom',errors:[],console:[],csp:[],network:[],requestsBlocked:[],trustedInputs:[]};
    report.sessions.push(record);
    activeRecord=record;
    await logPage(page,context,record,target,'built-http');
    await page.goto(target);
    await page.waitForFunction(()=>!!document.querySelector('auth-flow-studio')?.heldView);
    await page.evaluate(title=>{document.title=title;},title);
    const baseline=await page.evaluate(()=>({dpr:devicePixelRatio,width:innerWidth,outerWidth,scale:visualViewport.scale}));
    report.zoom={performed:false,mechanism:procedure.mechanism,procedure:{path:options['zoom-procedure'],...digest(options['zoom-procedure']),value:procedure},screenCapture:{path:procedure.screenCaptureProgram,...digest(procedure.screenCaptureProgram)},profileIsolated:true,title,baseline,steps:[]};
    report.zoom.displayServer=displayIdentity;
    for(const step of procedure.steps){
      assert.ok(Number.isInteger(step.menuCommandIndex)&&step.menuCommandIndex>=0&&step.menuCommandIndex<step.commands.length,'Actual menu-open command index required');
      const item={percent:step.percent,commands:[]};
      report.zoom.steps.push(item);
      for(const [index,command] of step.commands.entries()){
        assert.ok(path.isAbsolute(command.program)&&path.basename(command.program)==='xdotool','Only explicit provisioned native xdotool allowed');
        assert.ok(Array.isArray(command.args)&&command.args.every(s=>typeof s==='string'));
        assert.ok(!command.args.some(s=>/^(exec|spawn|kill|windowkill|windowclose)$/.test(s)),'No unrelated process execution/termination');
        const argv=command.args.map(s=>s.replaceAll('${TITLE}',title));
        const result=spawnSync(command.program,argv,{env:{...process.env,DISPLAY:procedure.display,AUTH_LAB_ZOOM_WINDOW_TITLE:title,AUTH_LAB_ZOOM_TARGET:target},encoding:'utf8',timeout:30000});
        item.commands.push({index,menuOpen:index===step.menuCommandIndex,program:command.program,identity:digest(command.program),argv,status:result.status,signal:result.signal,stdout:result.stdout,stderr:result.stderr,error:result.error?String(result.error):null});
        save();
        assert.equal(result.status,0,'Native X11 command must succeed');
        if(index===step.menuCommandIndex){
          assert.ok(argv.some(arg=>arg.toLowerCase()==='alt+f'),'Menu-open command must invoke actual Chrome Alt+f menu');
          const file='native-browser-menu-'+step.percent+'.png';
          const capture=spawnSync(procedure.screenCaptureProgram,[path.join(out,file)],{env:{...process.env,DISPLAY:procedure.display},encoding:'utf8',timeout:30000});
          item.menuCapture={program:procedure.screenCaptureProgram,argv:[path.join(out,file)],status:capture.status,signal:capture.signal,stdout:capture.stdout,stderr:capture.stderr,error:capture.error?String(capture.error):null};
          assert.equal(capture.status,0,'Native menu screen capture succeeds');
          item.menuScreenshot={file,...digest(path.join(out,file)),argv:[procedure.screenCaptureProgram,path.join(out,file)],stdout:capture.stdout,stderr:capture.stderr};
          report.screenshots.push(item.menuScreenshot);
        }
      }
      await settle(page);
      item.observed=await page.evaluate(()=>({dpr:devicePixelRatio,width:innerWidth,outerWidth,scale:visualViewport.scale}));
      assert.ok(Math.abs(item.observed.dpr/baseline.dpr-step.percent/100)<.02,'Actual browser page zoom DPR');
      assert.equal(item.observed.scale,1,'Not pinch/CSS zoom');
      item.geometry=await geometry(page);
      item.familyMatrix=[];
      for(const representative of (options.phase==='final'?denseRepresentatives():[{id:'lab-ad-forest-child-domains',variant:'default'}])){
        await choose(page,representative.id,representative.variant);
        for(const expanded of [false,true]){
          const toggle=page.locator('#show-internals');
          if(await toggle.isVisible()&&await toggle.isChecked()!==expanded)await activate(page,'#show-internals');
          await checkpoint(page,{end:true,milestone:'complete'});
          item.familyMatrix.push({...representative,expanded,geometry:await geometry(page)});
        }
        await page.locator('#play').focus();
        const focus=await focusState(page);
        assert.ok(focus.connected&&focus.visible&&focus.focusVisible,'Browser-menu zoom preserves reachable visible keyboard control');
      }
      await page.bringToFront();
      await page.locator('#play').scrollIntoViewIfNeeded();
      await settle(page);
      // In this provisioned runtime a Playwright page-only screenshot corrupts
      // the headed zoom surface. Retain the actual X11 surface instead; the
      // before/after diagnostic is separate from product geometry acceptance.
      const file='native-browser-surface-'+step.percent+'.png';
      const capture=spawnSync(procedure.screenCaptureProgram,[path.join(out,file)],{env:{...process.env,DISPLAY:procedure.display},encoding:'utf8',timeout:30000});
      item.surfaceCapture={program:procedure.screenCaptureProgram,argv:[path.join(out,file)],status:capture.status,signal:capture.signal,stdout:capture.stdout,stderr:capture.stderr,error:capture.error?String(capture.error):null};
      assert.equal(capture.status,0,'Actual native browser surface capture succeeds');
      item.surfaceScreenshot={file,...digest(path.join(out,file)),argv:[procedure.screenCaptureProgram,path.join(out,file)],stdout:capture.stdout,stderr:capture.stderr};
      report.screenshots.push(item.surfaceScreenshot);
    }
    assertLog(record);
    report.zoom.performed=true;
  }finally{
    await context?.close();
    fs.rmSync(profile,{recursive:true,force:true});
    activeRecord=null;
  }
}
const legacySurfaceIds=['basic-keycloak','lab-ad-forest-child-domains','lab-smb-nonjoined-kerberos','lab-ssh-cert-success','lab-win-credssp-v6-kerberos','lab-net-eap-tls13-wired','lab-pake-spake2plus-success'];
try{
  assert.ok(process.versions.bun,'Bun required');
  report.bunExecutable={path:process.execPath,...digest(process.execPath)};
  report.before=identity();
  assert.equal(report.before.html.sha256,options.expectedHTMLhash.toLowerCase(),'Built HTML current expected bytes');
  const manifest=readJSON('docs/next-expansion/scenario-manifest.json');assert.equal(manifest.kind,'next-expansion-independent-scenario-contract');const core=options.phase!=='P0'?loadContracts(manifest):[];
  if(options.phase==='review')targetedReview=loadTargetedReview();
  const require=createRequire(import.meta.url),entry=process.env.PLAYWRIGHT_MODULE||require.resolve('playwright-core');assert.ok(path.isAbsolute(entry),'PLAYWRIGHT_MODULE must resolve to absolute module entry');const playwright=await import(pathToFileURL(entry).href);report.dependency=packageIdentity(entry);assert.ok(process.env.CHROMIUM_EXECUTABLE&&path.isAbsolute(process.env.CHROMIUM_EXECUTABLE),'Provisioned CHROMIUM_EXECUTABLE required');report.browserExecutable={path:process.env.CHROMIUM_EXECUTABLE,...digest(process.env.CHROMIUM_EXECUTABLE)};report.nativeLibraries=process.env.LD_LIBRARY_PATH?process.env.LD_LIBRARY_PATH.split(':').filter(Boolean).map(dir=>({dir,files:fs.readdirSync(dir,{withFileTypes:true}).filter(e=>e.isFile()||e.isSymbolicLink()).map(e=>({name:e.name,...digest(path.join(dir,e.name))}))})):[];
  await staticServer();browser=await playwright.chromium.launch({executablePath:process.env.CHROMIUM_EXECUTABLE,headless:true,args:['--disable-background-networking','--disable-component-update','--no-first-run']});report.browserVersion=browser.version();save();
  if(contrastOnly)report.coverage={primaryContrastOnly:{mode:contrastOnly[0],device:contrastOnly[1]},semanticCasesNotRequested:true,unexecutedCorrectionFixtureCount:targetedReview.entries.length};
  for(const mode of (contrastOnly?[contrastOnly[0]]:['source-http','built-http','file'])){
    if(contrastOnly){
      const touch=contrastOnly[1]==='touch';
      await session(mode,touch,async page=>check(mode+' primary contrast-only '+contrastOnly[1]+' in both themes',()=>primaryContrast(page,touch,mode),{kind:'primary-contrast',mode,touch,findings:['P6-UX-01']}));
      continue;
    }
    await session(mode,false,async(page,target)=>{
      if(options.phase==='review'){
        await check(mode+' preserved ordinary navigation, editing and all-field accessibility',()=>navigation(page,manifest));
        for(const {item,contract,fixture} of targetedReview.entries)await check(mode+' correction '+item.id+' '+item.variant,async()=>{
          const result=await semanticCase(page,contract,fixture);
          if(item.startingText){
            assert.ok(Array.isArray(item.startingText)&&item.startingText.length);
            const element=page.locator('#learning-start');assert.equal(await element.isVisible(),true,'Disclosure belongs to the visible starting context, not closed advanced references');
            const text=await element.innerText();
            for(const needle of item.startingText)assert.ok(text.toLowerCase().includes(needle.toLowerCase()),'Required starting-context disclosure '+needle);
            result.startingDisclosure={text,required:item.startingText};
          }
          return result;
        },{kind:'semantic',mode,id:item.id,variant:item.variant,findings:item.findings});
        for(const {item,contract,fixture} of targetedReview.replays)await check(mode+' correction replay '+item.id+' '+item.kind,()=>replay(page,contract,fixture),{kind:'targeted-replay',mode,id:item.id,variant:item.variant,replayKind:item.kind});
        await check(mode+' primary default hover focus contrast in both themes',()=>primaryContrast(page,false,mode),{kind:'primary-contrast',mode,touch:false,findings:['P6-UX-01']});
        return;
      }
      await check(mode+' P0 grouped/global navigation and edit/identity/focus',()=>navigation(page,manifest));
      await check(mode+' old default/deep link/unsupported fallback',()=>routes(page,target,manifest,false));
      action('native-speed-after-route-reload',{keys:['End']});await page.locator('#speed').focus();await page.keyboard.press('End');assert.equal(await page.locator('#speed').inputValue(),await page.locator('#speed').getAttribute('max'));
      await check(mode+' desktop compact/internals/dense/inventory',()=>surface(page,legacySurfaceIds,false,mode));
      if(options.phase==='final'){
        for(const item of core){
          const contract=contracts.get(item.runtimeId);
          for(const fixture of contract.row.canonicalCases)await check(mode+' '+item.runtimeId+' case '+fixture.id,()=>semanticCase(page,contract,fixture),{kind:'semantic',mode,id:item.runtimeId,variant:fixture.id});
        }
        for(const group of familyContracts()){
          const fixtures=group.entries.flatMap(contract=>(contract.row.nativeReplay||[]).map(fixture=>({contract,fixture})));
          await check(mode+' '+group.key+' replay independent fixture gate',async()=>{
            assert.ok(fixtures.some(f=>f.fixture.kind==='local'),'Missing meaningful local field/holding replay fixture');
            assert.ok(fixtures.some(f=>['protected-receipt','acceptance'].includes(f.fixture.kind)),'Missing protected receipt/acceptance field/holding replay fixture');
            return {count:fixtures.length};
          });
          for(const {contract,fixture} of fixtures)await check(mode+' '+group.key+' replay '+contract.manifest.runtimeId+' '+fixture.kind,()=>replay(page,contract,fixture));
        }
        for(const item of core)await check(mode+' canonical new deep link '+item.runtimeId,async()=>{await choose(page,item.runtimeId);const route=await page.evaluate(()=>location.hash);assert.ok(route.startsWith('#/'+item.workspace+'/'));await page.goto(target+route);await page.waitForFunction(()=>!!document.querySelector('auth-flow-studio')?.heldView);assert.equal((await observe(page)).id,item.runtimeId);return {route};});
        const entries=entryRepresentatives(),dense=denseRepresentatives().filter(item=>!entries.some(entry=>entry.id===item.id&&entry.variant===item.variant));
        for(const entry of entries)await check(mode+' new family beginner '+entry.id,()=>surface(page,[entry],false,mode+'-entry-'+entry.id));
        for(const entry of dense)await check(mode+' new dense family '+entry.id+' '+entry.variant,()=>surface(page,[entry],false,mode+'-dense-'+entry.id+'-'+entry.variant));
        await mcpVisualSurfaces(page,false,mode);
      }
    });
    await session(mode,true,async page=>{
      if(options.phase==='review'){
        for(const item of targetedReview.surfaces)await check(mode+' correction native touch '+item.id+' '+item.variant,()=>surface(page,[item],true,mode+'-review-'+item.id+'-'+item.variant),{kind:'targeted-surface',mode,touch:true,id:item.id,variant:item.variant});
        await check(mode+' primary native touch and retained-hover contrast in both themes',()=>primaryContrast(page,true,mode),{kind:'primary-contrast',mode,touch:true,findings:['P6-UX-01']});
        return;
      }
      const entries=options.phase==='final'?entryRepresentatives():[];
      const representatives=options.phase==='final'?[...legacySurfaceIds,...entries,...denseRepresentatives().filter(item=>!entries.some(entry=>entry.id===item.id&&entry.variant===item.variant))]:legacySurfaceIds;
      if(options.phase==='final'){
        for(const entry of representatives){
          const id=typeof entry==='string'?entry:entry.id,variant=typeof entry==='string'?'default':entry.variant;
          await check(mode+' native touch '+id+' '+variant,()=>surface(page,[entry],true,mode+'-'+id+'-'+variant));
        }
        await mcpVisualSurfaces(page,true,mode);
      }else await check(mode+' native touch/internals/dense/inventory',()=>surface(page,representatives,true,mode));
    });
  }
  await browser.close();
  browser=null;
  if(options.phase==='review')report.zoom={performed:false,status:'outside-targeted-correction-scope',notEstablished:'Actual browser-menu200/400 zoom was not repeated; no full native acceptance is claimed.'};
  else await check('Required separate real browser-menu200/400 zoom',()=>realZoom(playwright));
  report.after=identity();assert.deepEqual(report.after,report.before,'Sources/worksheets/manifest/HTML/runner unchanged during collection');
  if(targetedReview)assert.deepEqual(digest(targetedReview.input.path),{sha256:targetedReview.input.sha256,bytes:targetedReview.input.bytes},'Explicit review fixtures unchanged during collection');
  report.coverage.executedCases=report.cases.filter(c=>c.scope?.kind==='semantic').map(c=>({...c.scope,passed:c.passed,error:c.error||null}));
  if((options.phase==='final'||options.phase==='review')&&!contrastOnly){
    const expected=['source-http','built-http','file'].flatMap(mode=>report.coverage.expectedCases.map(c=>mode+':'+c.id+':'+c.variant));
    const actual=report.coverage.executedCases.map(c=>c.mode+':'+c.id+':'+c.variant);
    assert.deepEqual(actual.sort(),expected.sort(),'Every independent default/named case attempted in all three modes');
    if(options.phase==='final'){
      report.coverage.denseRepresentatives=denseRepresentatives();
      report.coverage.beginnerEntries=entryRepresentatives();
      report.coverage.requiredMCPCaptures=report.cases.filter(c=>c.scope?.kind==='mcp-visual').map(c=>({...c.scope,passed:c.passed,capture:c.result?.capture||null,error:c.error||null}));
      assert.equal(report.coverage.requiredMCPCaptures.length,30,'Five required MCP semantic surfaces in desktop/touch and all three loading modes');
    }
  }
  report.complete=true;
}catch(error){report.failures.push({label:'collector/prerequisite',error:String(error.stack||error)});}
finally{
  try{await browser?.close();}catch(error){report.failures.push({label:'browser cleanup',error:String(error)});}
  if(server)await new Promise(resolve=>server.close(resolve));
  if(report.before&&!report.after){
    try{report.after=identity();if(JSON.stringify(report.after)!==JSON.stringify(report.before))report.failures.push({label:'input identity',error:'Inputs changed during failed collection'});}
    catch(error){report.failures.push({label:'final input identity',error:String(error)});}
  }
  report.finishedAt=new Date().toISOString();
  report.passed=report.complete&&report.failures.length===0&&report.blockers.length===0&&(options.phase==='review'||report.zoom.performed);
  report.status=report.passed?'passed':report.blockers.length?'blocked':report.complete?'failed':'partial';
  report.exitCode=report.passed?0:1;
  save();
  console.log(JSON.stringify({report:path.join(out,'native-status.json'),phase:report.phase,passed:report.passed,complete:report.complete,failures:report.failures.length,blockers:report.blockers},null,2));
  process.exitCode=report.exitCode;
}
