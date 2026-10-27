#!/usr/bin/env bun
// Real Chromium projections and trusted controls; no application/source rewriting.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {release as kernelRelease} from 'node:os';
import {seekNativeRange} from './dnssec-native-controls.mjs';

const help=`Usage: bun tools/verification/run-windows-protection-native.mjs
  --root CHECKOUT --out NEW_DIRECTORY --reference canonical-report.json
  --playwright /external/playwright-core/index.mjs --chrome /external/chrome
  --xvfb /external/Xvfb --xdotool /external/xdotool --scrot /external/scrot
  --private-tmp-ack yes [--scope all|smoke|devices|zoom|search|corrections|pam-lifetime] [--timeout-ms 14400000]
Run inside an OS-created private /tmp mount namespace (for example bwrap with
--bind / / --dev-bind /dev /dev --proc /proc --tmpfs /tmp). If checkout or output
is under /tmp, explicitly bind its parent back after --tmpfs /tmp. Inherit the
provisioned LD_LIBRARY_PATH. This runner starts its own -displayfd Xvfb, owns its
browser/profile/server, never cleans global X locks and never builds or installs.
All three loading modes run serially. Output must not exist. Browser zoom uses
real focused X11 Ctrl+plus shortcuts and requires measured DPR=2, scale=1.
Canonical prefix access uses a briefly paused real application method's lexical
exports via CDP Debugger, not injected evaluators or a changed standalone bundle.
Native here means Chromium input, NOT Windows/DC/live or human screen-reader QA.
Smoke selects every new model default plus previously failing optional-field/
composition cases in source HTTP, with the full search/control/device checks.
It never establishes the complete three-mode128-execution denominator.
Devices repeats only the narrow/reduced/genuine-zoom surfaces in all three modes;
it is an affected/broadened interaction collection, not a full canonical rerun.
Zoom repeats only the genuine200percent surfaces across the three modes.
Search repeats all 29 independent queries, running-search preservation, route/copy
and comparison activation, and browser errors in all three loading modes. It
does not rerun the unchanged canonical/PAM/device matrix after a picker-only edit.
Corrections selects the reviewed affected Windows/PAM controls plus focused
existing sudo/su/password integrations in three modes. It checks literal review
semantics, rendered values, full/field/exact histories and rewind, not a new full
1815-cell collection or performance/native-platform acceptance.
Pam-lifetime repeats only the existing PAM password custody/public-call corrections
and preserved account/rootok/PAM01 references in all three loading modes.
`;
if(process.argv.includes('--help')){console.log(help);process.exit(0);}
const options={};
for(let i=2;i<process.argv.length;i++){
  assert.ok(process.argv[i].startsWith('--'),'Named options only');
  const [key,inline]=process.argv[i].slice(2).split(/=(.*)/s),value=inline??process.argv[++i];
  assert.ok(['root','out','reference','playwright','chrome','xvfb','xdotool','scrot','private-tmp-ack','timeout-ms','scope'].includes(key),'Unknown option '+key);
  assert.ok(value&&!value.startsWith('--')&&!Object.hasOwn(options,key),'Missing/duplicate option '+key);options[key]=value;
}
for(const key of ['root','out','reference','playwright','chrome','xvfb','xdotool','scrot']){assert.ok(options[key],'Required --'+key);options[key]=path.resolve(options[key]);}
assert.equal(options['private-tmp-ack'],'yes','Explicit isolated private /tmp launch acknowledgment required');
options.scope??='all';assert.ok(['all','smoke','devices','zoom','search','corrections','pam-lifetime'].includes(options.scope),'Scope all, smoke, devices, zoom, search, corrections or pam-lifetime');
const deadline=Number(options['timeout-ms']??14400000);assert.ok(Number.isSafeInteger(deadline)&&deadline>=60000&&deadline<=86400000,'Finite timeout 60000..86400000ms');
const root=fs.realpathSync(options.root),out=options.out,runner=fileURLToPath(import.meta.url),started=performance.now();
fs.mkdirSync(out,{recursive:false});
const sha=value=>createHash('sha256').update(value).digest('hex');
const digest=file=>{assert.ok(fs.lstatSync(file).isFile(),'Regular immutable input '+file);const bytes=fs.readFileSync(file);return {sha256:sha(bytes),bytes:bytes.length};};
const json=file=>JSON.parse(fs.readFileSync(file,'utf8'));
const saveJSON=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
const log=(name,value)=>fs.appendFileSync(path.join(out,name),JSON.stringify({at:new Date().toISOString(),...value})+'\n');
const modes=options.scope==='smoke'?['source-http']:['source-http','emitted-http','offline-file'];
const surfaceOnly=['devices','zoom'].includes(options.scope);
const searchOnly=options.scope==='search';
const correctionsOnly=options.scope==='corrections';
const lifetimeOnly=options.scope==='pam-lifetime';
const report={schemaVersion:2,kind:'windows-protection-real-chromium',startedAt:new Date().toISOString(),argv:process.argv,options,root,out,passed:false,complete:false,sourceUnchanged:false,status:'running',matrix:[],sessions:[],screenshots:[],failures:[],subprocesses:[],runtime:{bun:process.versions.bun??null,node:process.version,platform:process.platform,arch:process.arch,executable:process.execPath,LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH??null},notEstablished:['Native Windows, domain controller, PAM host or live protocol conformance','Human screen-reader speech/comprehension or G01 acceptance','Performance acceptance, inherited-condition waiver, Astra review, release or publication approval']};
report.runtime.kernelRelease=kernelRelease();report.runtime.IMLIB2_LOADER_PATH=process.env.IMLIB2_LOADER_PATH??null;
report.runtime.pngLoader=process.env.IMLIB2_LOADER_PATH?{path:path.join(process.env.IMLIB2_LOADER_PATH,'png.so'),...digest(path.join(process.env.IMLIB2_LOADER_PATH,'png.so'))}:null;
const save=()=>saveJSON('native-status.json',report);
let browser,server,xvfb,origin,display,active,aborted=false;
function files(relative){return fs.readdirSync(path.join(root,relative),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>{assert.ok(!e.isSymbolicLink(),'No symbolic input '+relative+'/'+e.name);return e.isDirectory()?files(relative+'/'+e.name):[relative+'/'+e.name];});}
const inputNames=[
  'docs/windows-protection-expansion/search-fixtures.json',
  'docs/windows-protection-expansion/search-contract.json',
  'docs/windows-protection-expansion/routing-contract.json',
  'docs/pam-foundations/dispatch-expectations.json',
  'docs/pam-foundations/interface.json',
];
if(correctionsOnly||lifetimeOnly)inputNames.push('docs/windows-protection-expansion/corrections/expectations-01.json');
function identity(){
  const expected=json(options.reference),canonicalInputs=expected.inputs||[];
  for(const input of canonicalInputs)assert.ok(typeof input.path==='string'&&!path.isAbsolute(input.path)&&!input.path.split('/').includes('..'),'Safe canonical input path');
  return {
    sourceFiles:Object.fromEntries(['index.html','build.mjs','package.json','security-policy.mjs',...files('src'),...files('assets'),...files('tests')].sort().map(name=>[name,digest(path.join(root,name)).sha256])),
    standalone:digest(path.join(root,'dist/auth-flow-studio.html')),
    runner:digest(runner),reference:digest(options.reference),
    helpers:{
      seek:digest(fileURLToPath(new URL('./dnssec-native-controls.mjs',import.meta.url))),
      canonical:digest(path.join(root,'tools/verification/windows-protection-canonical.mjs')),
    },
    frozenInputs:Object.fromEntries([...new Set([...inputNames,...canonicalInputs.map(input=>input.path)])].map(name=>[name,digest(path.join(root,name))])),
    externalTools:Object.fromEntries(['playwright','chrome','xvfb','xdotool','scrot'].map(key=>[key,digest(options[key])])),
  };
}
let reference,search,routing,fixtures,pamDispatch,corrections;
const planned=(key,details={})=>{assert.ok(!report.matrix.some(r=>r.key===key),'Unique matrix key '+key);report.matrix.push({key,status:'unperformed',...details});};
async function cell(key,fn){if(aborted)return false;const row=report.matrix.find(r=>r.key===key);assert.ok(row&&row.status==='unperformed','Planned cell '+key);row.status='running';row.startedAt=new Date().toISOString();save();try{row.observed=await fn();row.status='passed';}catch(error){row.status='failed';row.error=String(error.stack||error);report.failures.push({key,error:row.error});}row.elapsedMs=Date.now()-Date.parse(row.startedAt);log('progress.jsonl',{key,status:row.status,elapsedMs:row.elapsedMs});save();return row.status==='passed';}
function command(program,args){const result=spawnSync(program,args,{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024,env:{...process.env,DISPLAY:display}}),index=report.subprocesses.length+1;fs.writeFileSync(path.join(out,`command-${index}.stdout`),result.stdout??'');fs.writeFileSync(path.join(out,`command-${index}.stderr`),result.stderr??'');report.subprocesses.push({program,args,status:result.status,signal:result.signal,error:result.error?String(result.error):null});assert.equal(result.status,0,'Owned native command '+program);return result.stdout.trim();}
const settle=page=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
const attr=(name,value)=>'['+name+'='+JSON.stringify(value)+']';
async function nativePointerClick(page,target,selector){
  await page.bringToFront();command(options.xdotool,['windowfocus','--sync',active.windowId]);
  const cdp=await page.context().newCDPSession(page);let metrics;
  try{metrics=await cdp.send('Page.getLayoutMetrics');}finally{await cdp.detach();}
  const expected=await target.evaluate(e=>{
    const b=e.getBoundingClientRect(),x=(Math.max(0,b.left)+Math.min(innerWidth,b.right))/2,y=(Math.max(0,b.top)+Math.min(innerHeight,b.bottom))/2,hit=document.elementFromPoint(x,y);
    window.__wpNativePointerEvidence=null;
    document.addEventListener('pointerdown',event=>{window.__wpNativePointerEvidence={trusted:event.isTrusted,x:event.clientX,y:event.clientY,matches:e===event.target||e.contains(event.target),target:event.target.id||event.target.tagName};},{capture:true,once:true});
    return {x,y,dpr:devicePixelRatio,inside:b.right>0&&b.bottom>0&&b.left<innerWidth&&b.top<innerHeight,hit:e===hit||e.contains(hit)};
  });
  assert.ok(expected.inside&&expected.hit,'Native pointer target is actually visible and unobstructed');
  const ratio=metrics.cssVisualViewport.zoom;assert.ok(Math.abs(ratio-2)<.025&&Math.abs(expected.dpr-2)<.025,'Owned native200percent scale');
  const geometry=Object.fromEntries(command(options.xdotool,['getwindowgeometry','--shell',active.windowId]).split('\n').map(line=>line.split('=')).filter(pair=>pair.length===2).map(([key,value])=>[key,Number(value)]));
  const native={x:Math.round(geometry.X+expected.x*ratio),y:Math.round(geometry.Y+geometry.HEIGHT-metrics.layoutViewport.clientHeight+expected.y*ratio)};
  assert.ok(Number.isFinite(native.x)&&Number.isFinite(native.y),'Native physical pointer coordinates');
  command(options.xdotool,['mousemove','--sync',String(native.x),String(native.y)]);command(options.xdotool,['click','1']);
  await page.waitForFunction(()=>window.__wpNativePointerEvidence!==null);
  const observed=await page.evaluate(()=>{const result=window.__wpNativePointerEvidence;delete window.__wpNativePointerEvidence;return result;});
  log('native-pointer.jsonl',{mode:active.mode,device:active.device,selector,expected,native,observed,geometry,metrics});
  assert.equal(observed.trusted,true,'Real X11 pointer event');assert.equal(observed.matches,true,'Native pointer reaches the intended participant control');
  assert.ok(Math.abs(observed.x-expected.x)<2&&Math.abs(observed.y-expected.y)<2,'Actual native client coordinates match the measured DOM target');
}
async function click(page,selector){
  const target=page.locator(selector).first();await target.scrollIntoViewIfNeeded();
  try{if(active.device==='zoom200')await nativePointerClick(page,target,selector);else if(active.touch)await target.tap();else await target.click();}
  catch(error){
    const details=await target.evaluate(e=>{const rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};},b=rect(e),x=Math.max(0,Math.min(innerWidth-1,b.left+b.width/2)),y=Math.max(0,Math.min(innerHeight-1,b.top+b.height/2)),ancestors=[];for(let n=e;n&&ancestors.length<8;n=n.parentElement)ancestors.push({tag:n.tagName,id:n.id,box:rect(n),zIndex:getComputedStyle(n).zIndex,overflow:getComputedStyle(n).overflow,position:getComputedStyle(n).position});return {target:rect(e),viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,scale:visualViewport.scale,scrollX,scrollY},center:{x,y},hit:document.elementsFromPoint(x,y).slice(0,10).map(n=>({tag:n.tagName,id:n.id,class:n.className,box:rect(n)})),ancestors};}).catch(caught=>({error:String(caught)}));
    let metrics;const cdp=await page.context().newCDPSession(page);try{metrics=await cdp.send('Page.getLayoutMetrics');}finally{await cdp.detach();}
    log('pointer-failures.jsonl',{mode:active.mode,device:active.device,selector,boundingBox:await target.boundingBox(),details,metrics,error:String(error.stack||error)});
    if(!report.pointerFailureScreenshot){const file='pointer-failure-first.png';try{await page.screenshot({path:path.join(out,file),fullPage:false});report.pointerFailureScreenshot={file,...digest(path.join(out,file))};}catch(caught){report.pointerFailureScreenshot={error:String(caught)};}}
    throw error;
  }
  log('input.jsonl',{mode:active.mode,device:active.device,mechanism:active.device==='zoom200'?'trusted-X11-pointer':active.touch?'trusted-touch-tap':'trusted-mouse-click',selector});await settle(page);
}
async function key(page,key){await page.keyboard.press(key);log('input.jsonl',{mode:active.mode,device:active.device,mechanism:'trusted-keyboard',key});}
async function fill(page,selector,value){await page.locator(selector).fill(value);log('input.jsonl',{mode:active.mode,device:active.device,mechanism:'Playwright-native-input-fill',selector,value});await settle(page);}
async function disclose(page,id){const e=page.locator('#'+id);if(await e.isVisible()&&await e.getAttribute('open')===null)await click(page,'#'+id+' > summary');}
async function select(page,selector,value){const e=page.locator(selector);assert.equal(await e.isVisible(),true,'Visible actual select '+selector);const values=await e.locator('option').evaluateAll(es=>es.map(e=>e.value)),index=values.indexOf(value);assert.ok(index>=0,'Actual allowed value '+value);await e.focus();await key(page,'Home');for(let i=0;i<index;i++)await key(page,'ArrowDown');await key(page,'Enter');await key(page,'Escape');await settle(page);assert.equal(await e.inputValue(),value,'Committed native select');}
async function state(page){return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),h=a.heldView.snapshot();return {id:a.labScenarioId,caseId:a.labModel?.caseId,variant:a.lessonVariant,subfixture:a.labModel?.subfixtureId??null,defaultSubfixture:a.labModel?.defaultSubfixtureId??null,cursor:h.cursor,context:a.heldView.contextId,status:a.player.status,attribute:a.attributeSelection??null,object:a.objectTraceSelection??null,inspection:a.heldView.selection??null,traceLength:a.traceQueue.length,focus:{id:document.activeElement?.id,searchCase:document.activeElement?.dataset?.searchCase,connected:document.activeElement?.isConnected},inspectorHidden:a.querySelector('#held-inspector').hidden};});}
function clean(s){assert.equal(s.cursor.eventIndex,-1,'Case/profile change resets playback');assert.equal(s.attribute,null,'No stale field');assert.equal(s.object,null,'No stale exact-object trace');assert.equal(s.inspection,null,'No stale inspected object');assert.equal(s.traceLength,0,'No stale trace queue');assert.equal(s.inspectorHidden,true,'Old object inspector hidden');}
async function choose(page,id,variant=null,member=null){await page.locator('#lab-scenario-search').focus();await fill(page,'#lab-scenario-search',id);await click(page,attr('data-scenario-option',id));assert.equal((await state(page)).id,id);if(variant&&(await state(page)).variant!==variant){await disclose(page,'lesson-reference');await select(page,'#lesson-case',variant);}if(member&&(await state(page)).subfixture!==member){await disclose(page,'lesson-reference');await select(page,'#lesson-subfixture',member);}const actual=await state(page);assert.equal(actual.id,id);if(variant)assert.equal(actual.variant,variant);if(member)assert.equal(actual.subfixture,member);clean(actual);return actual;}
async function activateFixture(page,fixture){
  await page.evaluate(({modelId,variantId,subfixtureId})=>{
    const app=document.querySelector('auth-flow-studio');
    app.selectLabScenario(modelId,{variant:variantId});
    if(subfixtureId&&app.labModel.subfixtureId!==subfixtureId)app.selectLessonSubfixture(subfixtureId);
  },fixture);
  await settle(page);
  const actual=await state(page);assert.equal(actual.id,fixture.modelId);assert.equal(actual.variant,fixture.variantId);
  if(fixture.subfixtureId)assert.equal(actual.subfixture,fixture.subfixtureId);clean(actual);
  log('observations.jsonl',{mode:active.mode,device:active.device,executionId:fixture.executionId,mechanism:'Actual application selection controller for repeated renderer checks; not trusted input. Canonical cells independently exercise native scenario/case/profile controls for every fixture.'});
}
async function seekZoomRange(page,value){
  assert.ok(Number.isInteger(value)&&value>=0&&value<=1000,'Actual zoom range0..1000');
  if(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status==='playing'))await click(page,'#play');
  const control=page.locator('#seek');await control.scrollIntoViewIfNeeded();await control.focus();
  command(options.xdotool,['windowfocus','--sync',active.windowId]);
  assert.equal(await control.evaluate(e=>document.activeElement===e&&document.hasFocus()),true,'Actual native range focus');
  const evidence={mode:active.mode,device:active.device,mechanism:'real-X11-keyboard-range',value,keys:[],pointerDragClaim:false};
  const press=async(key,count,expected=null)=>{
    assert.ok(Number.isInteger(count)&&count>0&&count<=1000,'Bounded native range key batch');
    const before=Number(await control.inputValue());
    command(options.xdotool,['key','--clearmodifiers','--delay','0',...Array(count).fill(key)]);
    await page.waitForFunction(({expected,before})=>{const value=Number(document.querySelector('#seek').value);return expected===null?value!==before:value===expected;},{expected,before});
    const after=Number(await control.inputValue());evidence.keys.push({key,count,before,after});return after;
  };
  try{
    let current=await press(value===1000?'End':'Home',1,value===1000?1000:0);
    if(value>0&&value<1000){
      const pageStep=await press('Page_Up',1);assert.ok(pageStep>0&&pageStep<=1000,'Measured actual native Page Up');
      evidence.measuredPageStep=pageStep;const pages=Math.round(value/pageStep);
      current=pages===0?await press('Home',1,0):pages===1?pageStep:await press('Page_Up',pages-1,Math.min(1000,pages*pageStep));
      const correction=value-current;assert.ok(Math.abs(correction)<=Math.ceil(pageStep/2)+1,'Nearest measured native page bounds correction');
      if(correction)current=await press(correction>0?'Right':'Left',Math.abs(correction),value);
    }
    assert.equal(current,value,'Exact range value from genuine native keys');evidence.final=current;evidence.passed=true;
  }finally{log('input.jsonl',evidence);}
  await settle(page);
}
async function seek(page,value){
  if(active.device==='zoom200'){await seekZoomRange(page,value);return;}
  await seekNativeRange(page,value,{
    click:selector=>click(page,selector),
    record:event=>log('input.jsonl',{mode:active.mode,device:active.device,...event}),
  });
  await settle(page);
}

// Access the real module bindings held inside the emitted IIFE. No code from the
// source is copied, recompiled, patched or substituted. Pause only the owned page.
async function captureLexical(page,method,expression){
  const cdp=await page.context().newCDPSession(page);
  await cdp.send('Debugger.enable');
  let breakpoint,timer,invocation;
  try{
    const target=await cdp.send('Runtime.evaluate',{expression:method});
    assert.ok(target.result.objectId,'Real application function object');
    ({breakpointId:breakpoint}=await cdp.send('Debugger.setBreakpointOnFunctionCall',{objectId:target.result.objectId}));
    const paused=new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(Error('Real function scope capture timeout')),10000);
      cdp.once('Debugger.paused',event=>{clearTimeout(timer);resolve(event);});
    });
    invocation=cdp.send('Runtime.evaluate',{expression:method+'()'});
    invocation.catch(()=>{});
    const event=await paused;
    const evaluated=await cdp.send('Debugger.evaluateOnCallFrame',{
      callFrameId:event.callFrames[0].callFrameId,expression,returnByValue:true,
    });
    assert.ok(!evaluated.exceptionDetails,'Real lexical exports accessible: '+JSON.stringify(evaluated.exceptionDetails));
    await cdp.send('Debugger.removeBreakpoint',{breakpointId:breakpoint});
    breakpoint=null;
    await cdp.send('Debugger.resume');
    const returned=await invocation;
    assert.ok(!returned.exceptionDetails,'Actual method resumed normally');
    log('observations.jsonl',{kind:'actual-lexical-export-access',mode:active.mode,method,
      mechanism:'Owned CDP function-call breakpoint; actual lexical bindings; immediate removal/resume; pure projection only, not user input'});
  }finally{
    clearTimeout(timer);
    if(breakpoint)await cdp.send('Debugger.removeBreakpoint',{breakpointId:breakpoint}).catch(()=>{});
    await cdp.send('Debugger.resume').catch(()=>{});
    await cdp.send('Debugger.disable').catch(()=>{});
    await cdp.detach();
  }
}
async function exportsFor(page){
  await captureLexical(page,'document.querySelector("auth-flow-studio").heldView.snapshot',
    'globalThis.__wpHeld={projectHeldObjects,inspectHeldObject}; true');
}
async function canonical(page,fixture){
  const encoded=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),c=a.heldView.compiled(),{projectHeldObjects:project,inspectHeldObject:inspect}=globalThis.__wpHeld;
    const frame=s=>({clock:s.protocolClock,state:s.state.workstation,holdings:s.holdings.map(h=>({actorId:h.actorId,artifactId:h.artifactId,representationId:h.representationId,store:h.store,retention:h.retention,fields:inspect(s,h.holdingId)?.fields||[]}))});
    return JSON.stringify({steps:a.steps.map(s=>s.id),initial:frame(project(c,{eventIndex:-1,milestone:'initial'})),prefixes:a.steps.map((step,index)=>({eventId:step.id,index,json:JSON.stringify(frame(project(c,{eventIndex:index,milestone:'complete'})))})),terminal:frame(project(c,{eventIndex:a.steps.length-1,milestone:'complete'})),context:c.contextId});
  });
  // Use the same serialized DTO as the frozen JSON reference and prefix hash.
  // Optional undefined members are not a different artifact field or state fact.
  const observed=JSON.parse(encoded),mismatches=[];
  assert.equal(observed.steps.length,fixture.prefixes.length,'Every completed prefix present');
  for(let i=0;i<observed.prefixes.length;i++){
    const actual=observed.prefixes[i],expected=fixture.prefixes[i];actual.sha256=sha(actual.json);delete actual.json;
    if(actual.index!==expected.index||actual.eventId!==expected.eventId||actual.sha256!==expected.sha256)mismatches.push({actual,expected});
  }
  log('canonical-prefixes.jsonl',{mode:active.mode,executionId:fixture.executionId,caseId:fixture.caseId,modelId:fixture.modelId,prefixes:observed.prefixes,initial:observed.initial,terminal:observed.terminal,mismatches});
  assert.deepEqual(mismatches,[],'Every actual compiled completed prefix matches frozen source reference');
  assert.deepEqual(observed.initial,fixture.initial,'Normalized initial state/holdings');assert.deepEqual(observed.terminal,fixture.final,'Normalized terminal state/holdings');
  assert.equal(sha(JSON.stringify(observed.terminal)),fixture.terminalSha256,'Terminal canonical hash');
  return {prefixes:observed.prefixes.length,terminalSha256:sha(JSON.stringify(observed.terminal)),context:observed.context};
}

async function geometry(page){
  await page.locator('.map-scroll').scrollIntoViewIfNeeded();await settle(page);
  const result=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio');
    const rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
    const visible=e=>!e.closest('[hidden]')&&e.getBoundingClientRect().width>0&&getComputedStyle(e).visibility!=='hidden';
    const inside=(r,b)=>r.left>=b.left-1&&r.right<=b.right+1&&r.top>=b.top-1&&r.bottom<=b.bottom+1;
    const graph=rect(a.refs.graph);
    const cards=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(e=>({id:e.dataset.actor||e.dataset.heldDock,kind:e.className,...rect(e)}));
    const overlaps=[],collisions=[],paths=[];
    for(let i=0;i<cards.length;i++)for(let j=i+1;j<cards.length;j++){
      const x=cards[i],y=cards[j];
      if(x.left<y.right-1&&x.right>y.left+1&&x.top<y.bottom-1&&x.bottom>y.top+1)overlaps.push([x.id,y.id]);
    }
    for(const line of a.refs.connections.querySelectorAll('.connection-line')){
      const length=line.getTotalLength(),matrix=line.getScreenCTM();
      if(!matrix)throw Error('Missing actual SVG transform');
      const point=t=>{const p=line.getPointAtLength(t);return new DOMPoint(p.x,p.y).matrixTransform(matrix);};
      const samples=Math.min(2000,Math.max(1,Math.ceil(length/3)));
      for(let i=1;i<samples;i++){
        const p=point(length*i/samples);
        const hit=cards.find(r=>p.x>r.left+1&&p.x<r.right-1&&p.y>r.top+1&&p.y<r.bottom-1);
        if(hit){collisions.push({pair:line.parentElement.dataset.pair,actor:hit.id});break;}
      }
      paths.push({pair:line.parentElement.dataset.pair,length,start:{x:point(0).x,y:point(0).y},end:{x:point(length).x,y:point(length).y},samples});
    }
    const map=a.querySelector('.map-scroll'),snapshot=a.heldView.snapshot();
    const groups=[...a.querySelectorAll('#trust-zones [data-zone-actor],#trust-zones [data-zone-host]')].filter(visible).map(e=>({id:e.dataset.zoneHost||e.dataset.zoneActor,physical:!!e.dataset.zoneHost,label:e.textContent,...rect(e)}));
    // Physical composites and logical parent groups are distinct from trust-zone
    // decoration. Record measured member envelopes, never guessed group nodes.
    const parents=Object.values(a.scenarioOwnedActors||{}).filter(actor=>actor.parentId);
    const logicalGroups=[...new Set(parents.map(actor=>actor.parentId))].map(id=>{
      const memberIds=[id,...parents.filter(actor=>actor.parentId===id).map(actor=>actor.id)];
      const members=cards.filter(card=>memberIds.includes(card.id));
      return {id,memberIds,visibleMembers:members.map(m=>m.id),bounds:members.length?{
        left:Math.min(...members.map(m=>m.left)),right:Math.max(...members.map(m=>m.right)),
        top:Math.min(...members.map(m=>m.top)),bottom:Math.max(...members.map(m=>m.bottom)),
      }:null};
    });
    const physicalHostErrors=[];
    if(/^lab-wprot0[1-5]$/.test(a.labScenarioId)){
      const actors=a.scenarioOwnedActors,root=id=>{let actor=actors[id];while(actor?.parentId&&actors[actor.parentId])actor=actors[actor.parentId];return actor;};
      const hostIds=new Set(Object.values(actors).filter(actor=>actor.parentId).map(actor=>root(actor.id).id));
      for(const card of cards){
        const host=root(card.id);if(!host)throw Error('Measured participant has no declared owner '+card.id);
        if(!hostIds.has(host.id)&&!['idp','service','host','ca','kdc'].includes(host.kind))continue;
        const matches=groups.filter(group=>group.physical&&group.id===host.id);
        if(matches.length!==1||!inside(card,matches[0]))physicalHostErrors.push({actor:card.id,host:host.id,reason:'Exactly one real host hull must contain its rendered participant and inventory'});
      }
      for(const group of groups.filter(group=>group.physical))for(const card of cards)if(root(card.id).id!==group.id&&card.left<group.right-1&&card.right>group.left+1&&card.top<group.bottom-1&&card.bottom>group.top+1)physicalHostErrors.push({actor:card.id,host:group.id,reason:'External participant intersects another physical host'});
    }
    const targets=[...a.querySelectorAll('#held-objects button,#held-docks button,#play,#reset')].filter(visible).map(e=>({label:e.getAttribute('aria-label')||e.textContent,...rect(e)}));
    const clipped=[...a.querySelectorAll('.actor-name,.actor-role,.packet-name,.held-object-name')].filter(visible).filter(e=>e.scrollWidth>e.clientWidth+2&&!['auto','scroll'].includes(getComputedStyle(e).overflowX)&&getComputedStyle(e).textOverflow!=='ellipsis').map(e=>({class:e.className,text:e.textContent}));
    return {model:a.labScenarioId,caseId:a.labModel?.caseId,member:a.labModel?.subfixtureId,expanded:a.showInternals,
      viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,scale:visualViewport.scale},
      documentOverflow:document.documentElement.scrollWidth>innerWidth+1,graph,cards,overlaps,collisions,paths,clipped,
      outside:cards.filter(r=>!inside(r,graph)),groups,logicalGroups,physicalHostErrors,
      groupsOutside:[...groups,...logicalGroups.filter(g=>g.bounds).map(g=>({id:g.id,...g.bounds}))].filter(r=>!inside(r,graph)),
      targetsTooSmall:targets.filter(r=>r.width<43.9||r.height<43.9),
      inventory:{mode:a.refs.graph.dataset.heldGeometry,visible:visible(a.querySelector('#held-objects')),
        holdings:snapshot.holdings.map(h=>({id:h.holdingId,actor:h.actorId,store:h.store})),
        coverage:snapshot.coverageStatus,owners:snapshot.coverage,scrollWidth:map.scrollWidth,clientWidth:map.clientWidth,overflowX:getComputedStyle(map).overflowX}};
  });
  log('geometry.jsonl',{mode:active.mode,device:active.device,...result});
  assert.equal(result.documentOverflow,false,'No document overflow');assert.ok(result.cards.length,'Actual actors rendered');
  assert.equal(result.inventory.coverage,'complete','Held coverage complete');
  for(const name of ['overlaps','collisions','clipped','outside','groupsOutside','physicalHostErrors','targetsTooSmall'])assert.deepEqual(result[name],[],'Actual geometry '+name);
  if(result.inventory.scrollWidth>result.inventory.clientWidth+1)assert.ok(['auto','scroll'].includes(result.inventory.overflowX),'Intentional graph scrolling');
  return {actors:result.cards.length,groups:result.groups.length,logicalGroups:result.logicalGroups.length,paths:result.paths.length,inventoryMode:result.inventory.mode};
}
async function expanded(page,value){const e=page.locator('#show-internals');if(!await e.isVisible()){assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').showInternals),false);return {applicable:false,reason:'Actual composition has no internal-component toggle'};}if(await e.isChecked()!==value)await click(page,'#show-internals');assert.equal(await e.isChecked(),value);return {applicable:true};}
async function animation(page){
  const targets=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),clock=a.studyClock();
    return [...new Set([a.steps.find(s=>s.from!==s.to),a.steps.find(s=>s.from===s.to)].filter(Boolean))].map(step=>{
      const i=clock.steps.findIndex(s=>s.id===step.id),duration=clock.durations[i];
      if(i<0)throw Error('Actual study clock omits animation representative');
      const timing=a.player.getTiming?.(step,'demo'),message=timing?.messages?.[0];
      const start=message?(message.start-timing.start)/(timing.end-timing.start):0;
      const end=message?(message.end-timing.start)/(timing.end-timing.start):1;
      const count=Math.max(1,step.payload.length);
      const scale=message?Math.min(1,(end-start)*duration/(380+(count-1)*1290+1050)):1;
      return {id:step.id,value:Math.round((clock.offsets[i]+start*duration+(380+1050*.5)*scale)/clock.total*1000)};
    });
  });
  assert.ok(targets.length,'Actual finite animation targets');
  const observations=[];
  for(const target of targets){
    await seek(page,target.value);
    const r=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),e=a.player.snapshot(),s=e.step,packet=a.refs.packet;
      const graph=a.refs.graph.getBoundingClientRect(),p=packet.getBoundingClientRect();
      const from=a.nodeId(s.from),to=a.nodeId(s.to);
      const line=a.refs.connections.querySelector('.connection-group.is-active .connection-line');
      const matrix=line?.getScreenCTM(),n=line?.getTotalLength();
      const point=t=>{const p=line.getPointAtLength(t);return new DOMPoint(p.x,p.y).matrixTransform(matrix);};
      const box=id=>{
        const r=[...a.refs.actors.querySelectorAll('[data-actor]')].find(e=>e.dataset.actor===id)?.getBoundingClientRect();
        return r?{left:r.left,right:r.right,top:r.top,bottom:r.bottom}:null;
      };
      const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
      const progress=(s.from===s.to||reduced)?0.5:e.progress;
      return {stepId:s.sourceStepId||s.id,from,to,packetVisible:!packet.hidden,progress:e.progress,
        messagePhase:e.messagePhase,routeProgress:Number(packet.dataset.routeProgress),presentation:packet.dataset.presentation,reduced,
        point:line&&matrix?{start:{x:point(0).x,y:point(0).y},end:{x:point(n).x,y:point(n).y},packet:{x:point(n*progress).x,y:point(n*progress).y}}:null,
        fromBox:box(from),toBox:box(to),
        contained:p.left>=graph.left-1&&p.right<=graph.right+1&&p.top>=graph.top-1&&p.bottom<=graph.bottom+1,
        clipped:[...a.querySelectorAll('#packet-name,#step-attributes code,#step-attributes-external code')].filter(e=>!e.closest('[hidden]')&&e.getBoundingClientRect().width&&e.scrollWidth>e.clientWidth+1).map(e=>e.textContent)};
    });
    log('animation.jsonl',{mode:active.mode,device:active.device,target,...r});
    assert.equal(r.stepId,target.id,'Native seek selects actual source event');
    assert.equal(r.packetVisible,true,'Actual paused animated packet');assert.equal(r.contained,true,'Packet graph bounds');
    assert.deepEqual(r.clipped,[],'Active field names unclipped');
    assert.ok(r.point&&r.fromBox&&r.toBox,'Actual connection and physical endpoints');assert.equal(r.routeProgress,r.progress);
    const near=(p,b)=>p.x>=b.left-12&&p.x<=b.right+12&&p.y>=b.top-12&&p.y<=b.bottom+12;
    assert.ok((near(r.point.start,r.fromBox)&&near(r.point.end,r.toBox))||(near(r.point.end,r.fromBox)&&near(r.point.start,r.toBox)),'Route endpoints touch actual source/target cards');
    observations.push(r);
  }
  return observations;
}

async function searchQuery(page,fixture){const before=await state(page);await page.locator('#lab-scenario-search').focus();await fill(page,'#lab-scenario-search',fixture.query);const rows=await page.locator('#lab-scenario-results [data-scenario-option]').evaluateAll(es=>es.map(e=>({id:e.dataset.scenarioOption,text:e.textContent}))),ids=rows.map(r=>r.id);assert.equal(new Set(ids).size,ids.length,'Unique result IDs');if(fixture.first)assert.equal(ids[0],fixture.first,'Independent first rank');for(const required of fixture.required){const rank=ids.indexOf(required.id)+1;assert.ok(rank>0&&rank<=required.maxRank,fixture.query+' independent max rank '+required.id);}
  const results=await page.evaluate(()=>document.querySelector('auth-flow-studio').scenarioPicker.results.map(r=>({id:r.id,variantId:r.variantId??null,matchingVariantIds:r.matchingVariantIds??[]})));assert.deepEqual(ids,results.map(r=>r.id),'Visible order equals actual ranked results');for(const required of fixture.required){const r=results.find(r=>r.id===required.id);if(required.variantId)assert.equal(r.variantId,required.variantId);if(required.matchingVariantIds)assert.deepEqual(r.matchingVariantIds,required.matchingVariantIds);}
  if(['lsa','LSA','lsass'].includes(fixture.query))
    assert.equal(rows.some(r=>/tls.?alert/i.test(r.text)),false,'LSA never matches an interior TLS-alert substring');
  if(fixture.query==='remote uac')
    assert.equal(rows.some(r=>/\b(?:OAuth|OIDC|JWT)\b/i.test(r.text)),false,'Remote UAC excludes unrelated OAuth validation');
  await key(page,'Home');for(let i=0;i<ids.length;i++){if(i)await key(page,'ArrowDown');assert.equal(await page.locator('#lab-scenario-search').getAttribute('aria-activedescendant'),'scenario-option-'+ids[i],'Every keyboard rank equals DOM rank');}await key(page,'Escape');const after=await state(page);for(const name of ['id','variant','subfixture','cursor','context'])assert.deepEqual(after[name],before[name],'Typing/highlighting does not replace case '+name);
  await disclose(page,'ready-journeys');await disclose(page,'lab-catalog');
  await fill(page,'#lab-search',fixture.query);
  const library=await page.locator('#lab-cards [data-lab-scenario]').evaluateAll(es=>es.map(e=>e.dataset.labScenario));
  assert.deepEqual(library,ids,'Library shares nonempty ranked order');
  await fill(page,'#lab-search','');
  for(const required of fixture.required.filter(r=>r.variantId||r.matchingVariantIds)){await page.locator('#lab-scenario-search').focus();await fill(page,'#lab-scenario-search',fixture.query);const old=await state(page);await click(page,attr('data-scenario-option',required.id));if(required.matchingVariantIds){const unchanged=await state(page);assert.equal(unchanged.id,old.id);assert.equal(unchanged.variant,old.variant);assert.equal(await page.locator('#search-case-choice').isVisible(),true);const choices=await page.locator('#search-case-choice [data-search-case]').evaluateAll(es=>es.map(e=>e.dataset.searchCase));assert.deepEqual(choices,required.matchingVariantIds);assert.equal((await state(page)).focus.searchCase,choices[0],'First explicit choice focus');await key(page,'Enter');assert.equal((await state(page)).variant,choices[0]);}else assert.equal((await state(page)).variant,required.variantId);assert.equal((await state(page)).id,required.id);assert.equal((await state(page)).focus.id,'play','Persistent Play focus after case selection');clean(await state(page));}
  log('search.jsonl',{mode:active.mode,query:fixture.query,rows,results,keyboardRanks:ids,library});return {query:fixture.query,count:ids.length};}

async function remoteEvidence(page){const r=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.protocolSnapshot().state.workstation,panel=a.querySelector('#windows-remote-evidence'),tables=[...panel.querySelectorAll('table')].map(table=>({caption:table.caption?.textContent,rows:[...table.querySelectorAll('tbody tr')].map(tr=>[...tr.querySelectorAll('th,td')].map(td=>td.textContent))}));return {state:s,text:panel.textContent,tables,hidden:panel.hidden,verdict:panel.querySelector('[data-windows-verdict]')?.textContent,qualification:panel.querySelector('[data-local-comparison-qualification]')?.textContent,actors:Object.fromEntries(Object.keys(a.labModel.actors()).map(id=>[id,a.actor(id).name]))};});log('remote-evidence.jsonl',{mode:active.mode,...r});const s=r.state;if(s.policyComparison||s.tokenComparison||s.verdictExplanation||s.localComparisonQualification)assert.equal(r.hidden,false);if(s.verdictExplanation)assert.equal(r.verdict,s.verdictExplanation);if(s.localComparisonQualification){assert.equal(r.qualification,s.localComparisonQualification);if(s.localComparisonKnown)assert.match(r.qualification,/local|bounded|comparison/i);}const p=s.policyComparison;if(p){const t=r.tables.find(t=>t.caption==='Remote policy snapshots');assert.ok(t);const row=label=>t.rows.find(r=>r[0]===label);assert.deepEqual(row(p.label)?.slice(1),[String(p.configured.restrictionsDisplay),p.applied?String(p.applied.restrictionsDisplay):'Not applied']);const expected=(v)=>v===null||v===undefined?'Not applied':typeof v==='object'?JSON.stringify(v,null,2):String(v);for(const field of ['EnableLUA','FilterAdministratorToken','administratorProtection']){const label=field==='administratorProtection'?'Administrator Protection':field;assert.deepEqual(row(label)?.slice(1),[expected(p.configured[field]),expected(p.applied?.[field])]);}assert.ok(row(p.registryValueName+' (raw; effective)'));assert.ok(r.text.includes(p.appliedStatus));}const c=s.tokenComparison;if(c){const table=r.tables.find(t=>t.caption==='Before / after target authorization context');assert.ok(table);const row=label=>table.rows.find(r=>r[0]===label);assert.deepEqual(row('Account SID')?.slice(1),[c.before.userSid,c.after.userSid]);for(const g of c.groups)assert.deepEqual(row('SID '+g.sid)?.slice(1),[g.beforeAttributes.join(', ')||'Not present',g.afterAttributes.join(', ')||'Not present']);for(const p of c.privileges)assert.deepEqual(row(p.name)?.slice(1),[p.before.state,p.after.state]);}return {policy:!!p,tokenComparison:!!c,verdict:!!r.verdict,localComparisonKnown:s.localComparisonKnown??null};}
async function pamEvidence(page){
  const r=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),m=a.labModel,s=a.protocolSnapshot(),step=a.currentStep;
    const sourceId=step?.sourceStepId||step?.id,i=a.steps.findIndex(row=>row.id===sourceId),declared=a.steps[i]?.pamEvaluation;
    const completed=i>=0&&s.cursor&&(s.cursor.eventIndex>i||s.cursor.eventIndex===i&&s.cursor.milestone==='complete');
    const read=p=>p?.split('.').reduce((o,k)=>o?.[k],s.state),canonical=read(m.pamStatePaths?.evaluation);
    const evaluation=completed&&canonical&&declared&&canonical.configurationId===declared.configurationId&&canonical.line===declared.line&&canonical.apiPhase===declared.apiPhase&&canonical.flags===declared.flags?canonical:declared;
    const p=a.querySelector('#pam-configuration-panel');
    return {modelId:m.id,variant:m.variantId,subfixture:m.subfixtureId,configuration:m.pamConfiguration,paths:m.pamStatePaths,declared,evaluation,canonical,completed,cursor:s.cursor,stepId:sourceId,
      hidden:p.hidden,text:p.textContent,
      current:[...p.querySelectorAll('[data-pam-line][aria-current="step"]')].map(e=>({line:Number(e.dataset.pamLine),text:e.querySelector('code').textContent})),
      rows:[...p.querySelectorAll('[data-pam-line]')].map(e=>({line:Number(e.dataset.pamLine),text:e.querySelector('code').textContent})),
      resources:[...p.querySelectorAll('[data-pam-resource-line]')].map(e=>({line:Number(e.dataset.pamResourceLine),text:e.querySelector('code').textContent})),
      values:Object.fromEntries([...p.querySelectorAll('.pam-evaluation > div')].map(e=>[e.querySelector('dt').textContent,e.querySelector('dd').textContent]))};
  });
  log('pam-evidence.jsonl',{mode:active.mode,device:active.device,...r});
  assert.ok(r.configuration,'Actual PAM configuration');assert.equal(r.hidden,false);
  for(const file of r.configuration.files){
    assert.equal(sha(file.text),file.sha256,'Actual configuration SHA');
    assert.ok(r.text.includes(file.text),'Complete actual configuration rendered');assert.ok(r.text.includes(file.sha256),'Configuration hash rendered');
  }
  const e=r.evaluation;
  if(e){
    const file=r.configuration.files.find(f=>f.id===e.configurationId||f.file===e.file)||r.configuration.files[0];
    if(e.line)assert.deepEqual(r.current,[{line:e.line,text:file.text.split('\n')[e.line-1]}],'Exact physical active line');
    else assert.deepEqual(r.current,[],'Caller/API boundary has no invented module line');
    for(const row of r.rows)assert.equal(row.text,file.text.split('\n')[row.line-1]);
    const apiNames={start:'pam_start',authenticate:'pam_authenticate',account:'pam_acct_mgmt',password:'pam_chauthtok',prelim:'pam_chauthtok',update:'pam_chauthtok',setcred:'pam_setcred',open:'pam_open_session',close:'pam_close_session',end:'pam_end','delete-credentials':'pam_setcred'};
    const hookNames={authenticate:'pam_sm_authenticate',account:'pam_sm_acct_mgmt',prelim:'pam_sm_chauthtok',update:'pam_sm_chauthtok',setcred:'pam_sm_setcred',open:'pam_sm_open_session',close:'pam_sm_close_session'};
    const apiDisplay=r.values['API call / flags']??r.values['Internal module dispatch / flags'];
    if(apiNames[e.apiPhase]){assert.equal(e.api,apiNames[e.apiPhase],'Declared C API identity');assert.ok(apiDisplay?.includes(apiNames[e.apiPhase]),'Actual C API visibly rendered');}
    if(e.flags!==null&&e.flags!==undefined)assert.ok(apiDisplay?.includes(String(e.flags)),'Actual flags, including numeric zero, visibly rendered');
    if(e.line&&e.hookCalled&&hookNames[e.apiPhase])assert.equal(e.moduleHook,hookNames[e.apiPhase],'Literal dispatched module hook');
    if(r.completed&&r.modelId==='lab-pam01'&&e.apiPhase==='authenticate'&&e.line){
      const ledger=pamDispatch.subfixtures?.[r.subfixture]||pamDispatch.cases[r.variant]||[],rows=ledger.filter(row=>row[0]===e.configurationId+':'+e.line);
      if(rows.length)assert.ok(rows.some(row=>row[1]===e.rawReturn&&row[2]===e.mappedAction&&row[3]===e.accumulatorAfter?.impression&&row[4]===e.accumulatorAfter?.status),'Independent frozen dispatch status/action/accumulator');
    }
    for(const [label,field]of [['Raw hook or loader return','rawReturn'],['Control status','controlStatus'],['Mapped control action','mappedAction'],['Skip / stop reason','skipStopReason'],...(Object.hasOwn(e,'aggregateReturn')?[['API aggregate return','aggregateReturn']]:[])]){
      const value=e[field];
      if(value!==null&&value!==undefined){if(r.completed)assert.equal(r.values[label],String(value),'Current PAM '+label);else assert.notEqual(r.values[label],String(value),'Future PAM result is not displayed: '+label);}
    }
    for(const [label,field,known]of [['Accumulator before','accumulatorBefore',true],['Accumulator after','accumulatorAfter',r.completed]]){
      const value=e[field];if(value){const text=r.values[label]||'',contains=text.includes(value.impression)&&text.includes(value.status);assert.equal(contains,known,'Current-prefix accumulator facts, independent of JSON serialization: '+label);}
    }
    if(e.nextRow){const text=r.values['Next row']||'',line=new RegExp('\\b'+e.nextRow.line+'\\b'),contains=line.test(text)&&(e.nextRow.configurationId===e.configurationId||text.includes(e.nextRow.configurationId));assert.equal(contains,r.completed,'Next physical row is not disclosed before completion');}
    if(e.moduleHook!==null&&e.moduleHook!==undefined)assert.equal(r.values['Module hook'],e.moduleHook);
    if(e.depth!==null&&e.depth!==undefined)assert.equal(r.values['Substack depth'],String(e.depth));
    if(r.completed)assert.equal(r.values['Hook called'],String(e.hookCalled));else assert.notEqual(r.values['Hook called'],String(e.hookCalled),'No future hook-call result');
  }
  if(r.declared?.resourceConfiguration){
    assert.deepEqual(r.resources,r.declared.resourceConfiguration.rows.map(row=>({line:row.line,text:row.text})));
    for(const resource of r.resources)assert.equal(r.rows.some(row=>row.text===resource.text),false,'Resource limits are not PAM control lines');
    if(r.completed)assert.ok(r.text.includes(r.declared.resourceConfiguration.applicationResult));
  }else assert.deepEqual(r.resources,[],'No stale limits configuration');
  return {stepId:r.stepId,cursor:r.cursor,completed:r.completed,line:e?.line??null,phase:e?.apiPhase??null,resourceLines:r.resources.length,raw:e?.rawReturn??null,aggregate:e?.aggregateReturn??null,moduleHook:e?.moduleHook??null};
}
async function pamTraversal(page){
  const targets=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),c=a.studyClock();
    return a.steps.map((s,i)=>s.pamEvaluation?{id:s.id,index:i,pending:Math.round((c.offsets[i]+c.durations[i]*.5)/c.total*1000),meaningful:s.pamEvaluation.rawReturn!==null&&s.pamEvaluation.rawReturn!==undefined||Object.hasOwn(s.pamEvaluation,'aggregateReturn')}:null).filter(Boolean);
  });
  const results=[],failures=[],representative=targets.find(row=>row.meaningful)||targets[0];
  assert.ok(representative,'Actual PAM module/API operation');
  // Trusted controls prove real selection and completion. Every remaining row
  // uses the real app/player controller for exhaustive rendering, not thousands
  // of redundant natural-animation waits. These are separately labelled.
  try{
    await seek(page,representative.pending);const pending=await pamEvidence(page);assert.equal(pending.stepId,representative.id);assert.equal(pending.completed,false);
    await click(page,'#timeline '+attr('data-step',String(representative.index)));
    await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete',null,{timeout:120000});
    const completed=await pamEvidence(page);assert.equal(completed.stepId,representative.id);assert.equal(completed.completed,true);
    log('pam-native-representatives.jsonl',{mode:active.mode,model:await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),mechanism:'trusted range and timeline controls; natural single-step completion',pending,completed});
  }catch(error){failures.push({target:representative,mechanism:'trusted-controls',error:String(error.stack||error)});}
  for(const target of targets)for(const completed of [false,true]){
    if(aborted)break;
    try{
      await page.evaluate(({index,completed})=>{const a=document.querySelector('auth-flow-studio');a.selectStep(index,false);if(!completed)a.player.seek([a.currentStep],.5,'step');},{index:target.index,completed});
      await settle(page);
      const observation=await pamEvidence(page);assert.equal(observation.stepId,target.id,'Controller reaches exact PAM source step');assert.equal(observation.completed,completed,'No future hook/control/API output');
      results.push({target,completed,status:'passed',mechanism:'actual application/player controller; programmatic renderer-prefix verification, not trusted input',observation});
    }catch(error){const failure={target,completed,status:'failed',error:String(error.stack||error)};results.push(failure);failures.push(failure);}
  }
  log('pam-traversal.jsonl',{mode:active.mode,model:await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),results});
  assert.equal(results.length,targets.length*2,'Every pending/completed PAM renderer prefix attempted');assert.deepEqual(failures,[],'All reachable PAM renderer prefixes and trusted representative controls');
  return {evaluations:targets.length,rendererMechanism:'actual controller API',trustedRepresentative:representative.id,observations:results};
}

async function staleContext(page,fixture){await choose(page,fixture.modelId,fixture.variantId,fixture.subfixtureId);await seek(page,1000);const h=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId));assert.ok(h,'Actual retained object');await click(page,'#held-objects '+attr('data-held-action','picker:'+h.actorId));let button=page.locator('#held-objects '+attr('data-holding-id',h.holdingId));if(!await button.isVisible()){const open=page.locator('#held-docks '+attr('data-held-actor',h.actorId));if(await open.count())await click(page,'#held-docks '+attr('data-held-actor',h.actorId));}await click(page,'#held-objects '+attr('data-holding-id',h.holdingId));assert.equal((await state(page)).inspection?.artifactId,h.artifactId);await click(page,'#held-inspector [data-held-trace]');assert.equal((await state(page)).object,h.artifactId);const before=await state(page),next=reference.fixtures.find(f=>f.modelId===fixture.modelId&&f.variantId!==fixture.variantId);assert.ok(next);await disclose(page,'lesson-reference');await select(page,'#lesson-case',next.variantId);const after=await state(page);clean(after);assert.notEqual(after.context,before.context);await click(page,'#index-open');const field=page.locator('#attribute-index [data-index-attribute]').first();assert.ok(await field.count());const fieldId=await field.getAttribute('data-index-attribute');await field.click();log('input.jsonl',{mechanism:'trusted-mouse-click',selector:'first actual field index button',fieldId});assert.equal((await state(page)).attribute,fieldId);await select(page,'#lesson-case',fixture.variantId);clean(await state(page));const member=reference.fixtures.find(f=>f.modelId===fixture.modelId&&f.variantId===fixture.variantId&&f.subfixtureId!==fixture.subfixtureId);if(member){await seek(page,1000);await select(page,'#lesson-subfixture',member.subfixtureId);clean(await state(page));}return {oldContext:before.context,newContext:after.context,artifact:h.artifactId,fieldId,subfixtureResetExercised:!!member};}

async function routes(page,mode){
  const chosen=reference.fixtures.find(f=>f.subfixtureId&&reference.fixtures.some(o=>o.modelId===f.modelId&&o.variantId===f.variantId&&o.subfixtureId!==f.subfixtureId));
  assert.ok(chosen,'Actual nondefault comparison fixture for link serialization');
  const second=reference.fixtures.find(f=>f.modelId!==chosen.modelId),base=active.url.split('#')[0];
  const routeFor=f=>{
    const defaults=routing.familyDefaults.find(row=>row.scenarioId===(f.modelId.startsWith('lab-wra')?'lab-wra01':f.modelId.startsWith('lab-wprot')?'lab-wprot01':'lab-llog01'));
    assert.ok(defaults,'Frozen routing family');
    return '#/'+defaults.workspace+'/'+defaults.routeSegment+'/'+f.modelId+'?case='+encodeURIComponent(f.variantId);
  };
  const route=await routeFor(chosen),other=await routeFor(second),results=[],failures=[];
  const attempt=async(name,fn)=>{
    try{results.push({name,status:'passed',observed:await fn()});}
    catch(error){const row={name,status:'failed',error:String(error.stack||error)};results.push(row);failures.push(row);}
  };
  await attempt('direct-load-back-forward',async()=>{
    await page.goto(base+route);await ready(page);await exportsFor(page);
    assert.equal((await state(page)).variant,chosen.variantId);clean(await state(page));
    await choose(page,second.modelId,second.variantId);
    await page.goBack();await settle(page);
    assert.equal((await state(page)).variant,chosen.variantId);assert.equal((await state(page)).id,chosen.modelId);clean(await state(page));
    await page.goForward();await settle(page);assert.equal((await state(page)).id,second.modelId);
    await page.reload();await ready(page);await exportsFor(page);assert.equal((await state(page)).id,second.modelId);
    return {route,other,reloaded:true};
  });
  await attempt('real-clipboard-and-permission-denied-manual-fallback',async()=>{
    await choose(page,chosen.modelId,chosen.variantId);await disclose(page,'lesson-reference');
    const members=await page.locator('#lesson-subfixture option').evaluateAll(es=>es.map(e=>e.value));
    assert.ok(members.length>1);await select(page,'#lesson-subfixture',members.at(-1));
    const cdp=await page.context().newCDPSession(page),info=await cdp.send('Target.getTargetInfo');
    const browserContextId=info.targetInfo.browserContextId,expected=base+route;
    const permission=async(name,setting)=>{
      for(const allowWithoutSanitization of name==='clipboard-write'?[true,false]:[true])
        await cdp.send('Browser.setPermission',{permission:{name,allowWithoutSanitization},setting,browserContextId,...(mode==='offline-file'?{}:{origin})});
    };
    let clipboardBranch;
    try{
      await permission('clipboard-write','granted');await permission('clipboard-read','granted');
      await click(page,'#copy-lesson-link');
      await page.waitForFunction(()=>{
        const toast=document.querySelector('#toast');
        return !toast.hidden&&/^(Named lesson\/case link copied\.|Clipboard unavailable\.)/.test(toast.textContent);
      });
      assert.equal(await page.locator('#lesson-link-value').inputValue(),expected,'Only named lesson/case serialized');
      if(await page.locator('#lesson-link-manual').isVisible()){
        clipboardBranch='actual-browser-unavailable-manual';assert.equal((await state(page)).focus.id,'lesson-link-value');
      }else{
        clipboardBranch='actual-browser-clipboard';
        assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),expected,'Actual clipboard exact URL');
      }
      await permission('clipboard-read','denied');await permission('clipboard-write','denied');await click(page,'#copy-lesson-link');
      await page.waitForFunction(()=>!document.querySelector('#lesson-link-manual').hidden);
      assert.equal(await page.locator('#lesson-link-value').inputValue(),expected);
      assert.equal(await page.locator('#lesson-link-value').getAttribute('readonly'),'');
      assert.equal((await state(page)).focus.id,'lesson-link-value','Readonly manual fallback focused');
      const selected=await page.locator('#lesson-link-value').evaluate(e=>({start:e.selectionStart,end:e.selectionEnd,length:e.value.length}));
      assert.deepEqual(selected,{start:0,end:expected.length,length:expected.length});
      await page.goto('about:blank');await page.goto(expected);await ready(page);
      const reopened=await state(page);assert.equal(reopened.variant,chosen.variantId);
      assert.equal(reopened.subfixture,reopened.defaultSubfixture,'Copied comparison opens default local inputs');
      return {expected,clipboardBranch,permissionDeniedFallback:true,comparisonProfileOmitted:true};
    }finally{await cdp.send('Browser.resetPermissions',{browserContextId}).catch(()=>{});await cdp.detach();}
  });
  const baseRoute=route.split('?')[0],bad=[
    '?case=not-a-real-case','?case='+chosen.variantId+'&case='+chosen.variantId,
    '?case=','?case=%ZZ','?case=%252F','?%63ase='+chosen.variantId+'&case='+chosen.variantId,'?case=%2F','?extra=value',
  ];
  for(const query of bad)await attempt('reject '+query,async()=>{
    await page.goto(base+baseRoute+query);await ready(page);
    const s=await state(page),defaultVariant=await page.evaluate(()=>document.querySelector('auth-flow-studio').baseLabModel.defaultVariantId||'default');
    assert.equal(s.id,chosen.modelId,'Rejected case retains valid base lesson');
    assert.equal(s.variant,defaultVariant,'Rejected query never evaluates as previous named case');clean(s);return s;
  });
  await attempt('unknown-base',async()=>{
    await page.goto(base+'#/unknown/invalid?case=x');await ready(page);
    assert.equal((await state(page)).id,'basic-keycloak','Unknown route safe base');return state(page);
  });
  // Reloads replace test-only bridges; recapture only the actual current module.
  await exportsFor(page);
  log('routes.jsonl',{mode,route,other,results});assert.deepEqual(failures,[],'Every reachable route/copy cell');
  return {results};
}

async function comparisons(page){
  const targets=[...new Set([...routing.comparison.rows.flatMap(r=>r.targets),...routing.comparison.requiredRelatedDestinations,routing.comparison.requiredRelatedCase.id])];
  const hosts=['lab-wra01','lab-wprot03','lab-wprot04','lab-wra03','lab-win-rdp-remote-credential-guard','lab-welev03','lab-welev04','lab-welev05','lab-wra04'];
  const results=[],failures=[];
  for(const target of targets){
    try{
      let found=false;
      for(const host of hosts){
        await choose(page,host);await disclose(page,'lesson-reference');await disclose(page,'windows-security-comparison');
        const buttons=page.locator('#windows-security-comparison '+attr('data-compare-scenario',target)+', #related-journeys '+attr('data-compare-scenario',target));
        let button;
        for(let i=0;i<await buttons.count();i++)if(await buttons.nth(i).isVisible()){button=buttons.nth(i);break;}
        if(!button)continue;
        await button.focus();await key(page,'Enter');await settle(page);
        const s=await state(page);assert.equal(s.id,target,'Static real comparison target');
        if(target===routing.comparison.requiredRelatedCase.id)assert.equal(s.variant,routing.comparison.requiredRelatedCase.variantId);
        const focusedDestination=await page.evaluate(target=>{const n=document.activeElement;return n?.isConnected&&n.getClientRects().length>0&&(n.id==='play'||n.dataset.labScenario===target&&n.closest('#workspace-presets')&&n.getAttribute('aria-pressed')==='true');},target);
        assert.equal(!!focusedDestination,true,'Comparison focus returns to its visible selected starter or persistent Play');clean(s);
        results.push({host,target,variant:s.variant,status:'passed'});found=true;break;
      }
      assert.ok(found,'Actual comparison/related control '+target);
    }catch(error){const row={target,status:'failed',error:String(error.stack||error)};results.push(row);failures.push(row);}
  }
  log('comparisons.jsonl',{mode:active.mode,results});assert.deepEqual(failures,[],'All reachable related/comparison targets');
  return results;
}

async function screenshot(page,label){assert.ok(report.screenshots.length<12,'Maximum twelve representative captures');const file=String(report.screenshots.length+1).padStart(2,'0')+'-'+label+'.png';if(active.device==='zoom200'){await page.bringToFront();command(options.xdotool,['windowfocus','--sync',active.windowId]);command(options.scrot,[path.join(out,file)]);}else await page.screenshot({path:path.join(out,file),fullPage:false});report.screenshots.push({file,mode:active.mode,device:active.device,mechanism:active.device==='zoom200'?'native-scrot':'real-Chromium-screenshot',...digest(path.join(out,file))});return file;}
async function zoom200(page){
  await page.bringToFront();const title='Windows Protection Native '+process.pid+' '+active.mode;
  await page.evaluate(title=>{document.title=title;},title);await settle(page);
  // Chromium appends its product name to the native window title.
  const ids=command(options.xdotool,['search','--sync','--onlyvisible','--name','^'+title]).split('\n');
  assert.equal(ids.length,1,'Only owned browser window');active.windowId=ids[0];
  const nativeTitle=command(options.xdotool,['getwindowname',ids[0]]);assert.ok(nativeTitle.startsWith(title));
  command(options.xdotool,['windowfocus','--sync',ids[0]]);command(options.xdotool,['key','--clearmodifiers','Escape']);command(options.xdotool,['key','--clearmodifiers','ctrl+0']);
  await page.waitForFunction(()=>Math.abs(devicePixelRatio-1)<.025&&visualViewport.scale===1);
  const observations=[];
  for(let i=0;i<5;i++){command(options.xdotool,['key','--clearmodifiers','ctrl+plus']);await settle(page);observations.push(await page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth,focused:document.hasFocus()})));}
  await page.waitForFunction(()=>Math.abs(devicePixelRatio-2)<.025&&visualViewport.scale===1);
  const final=await page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth,focused:document.hasFocus()}));
  assert.equal(final.focused,true);assert.equal(final.scale,1);assert.ok(Math.abs(final.dpr-2)<.025);
  log('zoom.jsonl',{mode:active.mode,mechanism:'actual xdotool Ctrl+0 then Ctrl+plus five times',windowId:ids[0],nativeTitle,observations,final});return final;
}
async function ready(page){await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView?.compiled()?.plan,{timeout:30000});await settle(page);}
async function attach(mode,device){const touch=device==='narrow390',context=await browser.newContext(device==='zoom200'?{viewport:null}:{viewport:{width:touch?390:1480,height:touch?844:1000},deviceScaleFactor:1,hasTouch:touch,isMobile:touch,reducedMotion:device==='reduced'?'reduce':'no-preference'}),page=await context.newPage(),url=mode==='source-http'?origin+'/':mode==='emitted-http'?origin+'/dist/auth-flow-studio.html':pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href;page.setDefaultTimeout(15000);page.setDefaultNavigationTimeout(30000);active={context,page,mode,device,touch,url,errors:[],consoleErrors:[],external:[]};const session=active;report.sessions.push({mode,device,url});await context.exposeBinding('wpInputEvent',(_source,event)=>log('trusted-events.jsonl',{mode,device,...event}));await context.addInitScript(()=>{for(const type of ['keydown','pointerdown','input','change','focusin'])document.addEventListener(type,e=>{void window.wpInputEvent({type,key:e.key??null,pointerType:e.pointerType??null,isTrusted:e.isTrusted,target:e.target?.id||e.target?.getAttribute?.('data-search-case')||e.target?.tagName,active:document.activeElement?.id,url:location.href}).catch(()=>{});},true);});page.on('pageerror',error=>{session.errors.push(String(error));log('browser-errors.jsonl',{mode,device,kind:'pageerror',error:String(error)});});page.on('console',msg=>{log('console.jsonl',{mode,device,type:msg.type(),text:msg.text(),location:msg.location()});if(msg.type()==='error')session.consoleErrors.push(msg.text());});await context.route('**/*',async route=>{const u=new URL(route.request().url());if(['http:','https:'].includes(u.protocol)&&u.origin!==origin){session.external.push(u.href);log('network.jsonl',{mode,device,url:u.href,action:'blocked-non-loopback'});await route.abort();}else await route.continue();});await page.goto(url);await ready(page);await exportsFor(page);return page;}
async function startX(){const stdout=fs.openSync(path.join(out,'xvfb.stdout'),'wx'),stderr=fs.openSync(path.join(out,'xvfb.stderr'),'wx');xvfb=spawn(options.xvfb,['-displayfd','3','-screen','0','1600x1200x24','-nolisten','tcp','-ac'],{stdio:['ignore',stdout,stderr,'pipe'],env:process.env});fs.closeSync(stdout);fs.closeSync(stderr);display=await new Promise((resolve,reject)=>{let text='';const timer=setTimeout(()=>reject(Error('Owned Xvfb timeout')),15000);xvfb.once('error',e=>{clearTimeout(timer);reject(e);});xvfb.once('exit',code=>{clearTimeout(timer);reject(Error('Owned Xvfb exited '+code));});xvfb.stdio[3].on('data',chunk=>{text+=chunk;if(/^\d+\n/.test(text)){clearTimeout(timer);resolve(':'+text.trim());}});});report.display={display,pid:xvfb.pid,privateTmpAcknowledged:true,noGlobalXCleanup:true};}
let cleaning;
function cleanup(){return cleaning||=(async()=>{await active?.context.close().catch(()=>{});await browser?.close().catch(()=>{});if(server)await new Promise(resolve=>server.close(resolve));if(xvfb&&xvfb.exitCode===null){xvfb.kill('SIGTERM');await new Promise(resolve=>{const timer=setTimeout(()=>{if(xvfb.exitCode===null)xvfb.kill('SIGKILL');resolve();},5000);timer.unref();xvfb.once('exit',()=>{clearTimeout(timer);resolve();});});}})();}
async function stop(reason){if(aborted)return;aborted=true;report.failures.push({kind:'interruption',reason});save();await cleanup();}
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{void stop(signal);});
const watchdog=setTimeout(()=>{void stop('Finite runner deadline exceeded '+deadline+'ms');},deadline);watchdog.unref();

const legacySurfaces=['basic-keycloak','lab-ssh-cert-success','lab-ad-first-sign-in'];
const deviceSurfaces=[...legacySurfaces,'lab-wra01','lab-wprot01','lab-pam01'];
const devices=['narrow390','reduced','zoom200'];
const existingPam=[
  {id:'lab-llog01'},{id:'lab-llog02'},{id:'lab-llog02',variant:'kdc-unavailable-cache-disabled',unavailable:true},
  {id:'lab-llog03'},{id:'lab-llog04'},{id:'lab-lelev01'},{id:'lab-lelev02'},
  {id:'lab-ssh-sssd-success'},{id:'lab-ssh-sssd-lookup',unavailable:true},{id:'lab-ssh-cert-success',publickey:true},
];
const pamKey=row=>row.id+'/'+(row.variant||'default');
const correctionPam=[
  {id:'lab-lelev01',variant:'default'},{id:'lab-lelev01',variant:'account-denied'},
  {id:'lab-lelev02',variant:'default'},{id:'lab-lelev02',variant:'access-denied'},
  {id:'lab-lelev02',variant:'setuid-not-real-root'},{id:'lab-lelev02',variant:'real-root-bypass'},
  {id:'lab-llog04',variant:'default'},{id:'lab-llog04',variant:'directory-unreachable'},
  {id:'lab-llog01',variant:'default'},
];
const lifetimePam=[
  ...['default','wrong-password','expired-timestamp','different-terminal','rootpw','targetpw','runaspw','account-denied','command-denied','runas-denied','cached-policy-denied','noninteractive','nopasswd','root-caller','timestamp-reuse'].map(variant=>({id:'lab-lelev01',variant})),
  ...['default','new-policy-denied','update-failed','directory-unreachable','directory-online','post-change-account-denied','consumer-no-change','account-expired','wrong-current-password'].map(variant=>({id:'lab-llog04',variant})),
  {id:'lab-llog01',variant:'default'},
  ...['default','access-denied','setuid-not-real-root','real-root-bypass'].map(variant=>({id:'lab-lelev02',variant})),
];
const selectedExistingPam=lifetimeOnly?lifetimePam:correctionsOnly?correctionPam:existingPam;
async function browserErrors(){
  assert.deepEqual(active.errors,[],'No uncaught pageerrors');
  assert.deepEqual(active.consoleErrors,[],'No browser console/CSP errors');
  return {pageerrors:active.errors,consoleErrors:active.consoleErrors,blockedExternal:active.external};
}
async function renderedTerminal(page,fixture){
  const encoded=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),s=a.heldView.snapshot(),inspect=globalThis.__wpHeld.inspectHeldObject;
    return JSON.stringify({clock:s.protocolClock,state:s.state.workstation,holdings:s.holdings.map(h=>({
      actorId:h.actorId,artifactId:h.artifactId,representationId:h.representationId,store:h.store,retention:h.retention,
      fields:inspect(s,h.holdingId)?.fields||[],
    }))});
  });
  const frame=JSON.parse(encoded);
  assert.deepEqual(frame,fixture.final,'Actual UI terminal normalized state and holdings');
  assert.equal(sha(JSON.stringify(frame)),fixture.terminalSha256);
  return fixture.terminalSha256;
}
async function correctionEvidence(page){
  const result=await page.evaluate(literal=>{
    const a=document.querySelector('auth-flow-studio'),m=a.labModel,steps=m.steps(),checks=[];
    const bounded=value=>typeof value==='string'&&value.length>4096?{kind:'successful-observation-summary',characters:value.length,completeCanonicalPrefixRecordsSuppliedSeparately:true}:value;
    const ok=(name,pass,actual,expected)=>{checks.push({name,passed:!!pass,...(pass?{actual:bounded(actual),expected:bounded(expected)}:{actual,expected})});if(!pass)throw Error(name+': '+JSON.stringify({actual,expected}));};
    const same=(name,actual,expected)=>ok(name,JSON.stringify(actual)===JSON.stringify(expected),actual,expected);
    const snapshot=()=>a.heldView.snapshot();
    const stable=s=>JSON.stringify({clock:s.protocolClock,state:s.state,holdings:s.holdings,observations:s.observations});
    const full=index=>{if(a.hasTrace)a.clearAttribute();if(index<0)a.reset();else a.selectStep(index,false);return snapshot();};
    const stage=name=>{const i=steps.findIndex(s=>s.workstationStage===name);ok('source stage '+name,i>=0,i,'present');return i;};
    const artifact=key=>m.workstationInventory.artifacts.find(o=>o.key===key||o.artifactId===m.id+':'+key);
    const values=()=>Object.fromEntries([...a.querySelectorAll('#pam-configuration-panel .pam-evaluation > div')].map(e=>[e.querySelector('dt').textContent,e.querySelector('dd').textContent]));
    function history(index,object){
      const expected=stable(full(index)),before=stable(full(index-1));full(index);
      a.heldView.trace(object.artifactId);
      let i=a.traceQueue.findIndex(row=>row.sourceStepId===steps[index].id);
      ok('exact-object history has source event',i>=0,i,'present');a.selectStep(i,false);same('exact-object equal prefix',stable(snapshot()),expected);
      a.clearAttribute();
      const field=steps[index].attributeOperations.find(op=>op.instanceId===object.artifactId)?.attributeId;
      ok('real declared field for history',!!field,field,'declared field');a.selectAttribute(field,false);
      i=a.traceQueue.findIndex(row=>row.sourceStepId===steps[index].id);ok('field history has source event',i>=0,i,'present');
      a.selectStep(i,false);same('field equal prefix',stable(snapshot()),expected);
      same('rewind exact source prefix',stable(full(index-1)),before);same('forward exact source prefix',stable(full(index)),expected);
    }
    if(/^lab-(wra|wprot)/.test(m.id)){
      let localReleases=0;
      for(const [index,step]of steps.entries()){
        const releases=m.workstationInventory.events[step.id].milestones.flatMap(e=>e.effects).filter(e=>e.op==='release');
        if(step.from!==step.to||!releases.length)continue;
        const before=full(index-1),after=full(index),gone=before.holdings.filter(h=>!after.holdings.some(next=>next.holdingId===h.holdingId));
        same('every released exact holding existed '+step.id,gone.length,releases.length);
        for(const h of gone){same('owner-local release '+step.id,h.actorId,step.from);same('temporary release '+step.id,h.retention,'temporary');}
        localReleases+=gone.length;
        if(gone.length)history(index,m.workstationInventory.artifacts.find(o=>o.artifactId===gone[0].artifactId));
      }
      same('no attempt scratch after completion',full(steps.length-1).holdings.filter(h=>h.retention==='temporary').length,0);
      checks.push({name:'owner-local release observations',passed:true,actual:localReleases});
    }
    if(m.id==='lab-wprot04'){
      const expected=literal['WP-R01'].cases.find(row=>row.variant===m.variantId);
      if(expected){
        const end=full(steps.length-1).state.workstation,policy=artifact('account-policy').value,decision=artifact('as-policy'),i=stage('as-policy');
        same('configured policy lifetime',policy.lifetimeMinutes,expected.configuredMinutes);same('effective enforcement',policy.enforced,expected.enforced);
        same('accepted authentication',end.tgtAccepted,true);same('audit would-deny',end.policyWouldDeny,expected.wouldDeny);
        for(const [field,value]of Object.entries({ticketIssuedMinutes:expected.issuedMinutes,ticketDurationMinutes:expected.durationMinutes,ticketEndMinutes:expected.endMinutes,ticketRenewMinutes:expected.renewMinutes}))same('literal '+field,end[field],value);
        const h=full(i).holdings.find(h=>h.artifactId===decision.artifactId&&h.actorId==='wslDC');a.heldView.select(h);
        const text=a.querySelector('#held-inspector').textContent;
        ok('rendered configured/effective lifetime',text.includes('configuredLifetimeMinutes')&&text.includes(String(expected.endMinutes)),text,'configured and effective fields');
        history(i,decision);
      }
    }
    if(m.id==='lab-wprot03'&&m.variantId==='fresh-authentication'){
      const reply=artifact('as-client-reply'),old=artifact('old-ticket-lineage'),i=stage('as-accept'),end=full(steps.length-1).state.workstation;
      same('fresh absolute clock',reply.value.lifetime,literal['WP-R02'].fresh);
      for(const [field,value]of Object.entries(literal['WP-R02'].old))same('old lineage '+field,old.value[field],value);
      same('local session retained',end.localSessionRetained,true);same('new credential accepted',end.tgtAccepted,true);
      const h=full(i).holdings.find(h=>h.artifactId===reply.artifactId&&h.actorId==='wslLSA'&&h.representationId==='plain');a.heldView.select(h);
      const text=a.querySelector('#held-inspector').textContent;for(const value of ['issuedMinutes','durationMinutes','241','240','481'])ok('fresh inspector '+value,text.includes(value),text,value);
      history(i,reply);same('old lineage still expired after rewind',old.value.expired,true);
    }
    for(const spec of literal['WP-R04'].objects.filter(row=>row.modelId===m.id&&row.variant===m.variantId)){
      const object=artifact(spec.key),decode=stage(spec.decode),verify=stage(spec.verify),before=full(decode-1);
      const wire=before.holdings.find(h=>h.actorId==='wslDC'&&h.artifactId===object.artifactId&&h.representationId==='wire');
      ok('actual received wire '+spec.key,!!wire,!!wire,true);
      same('no decoded holding before '+spec.key,before.holdings.some(h=>h.actorId==='wslDC'&&h.artifactId===object.artifactId&&h.representationId==='plain'),false);
      a.heldView.select(wire);ok('actual redacted inspector '+spec.key,a.querySelector('#held-inspector').textContent.includes('Not readable by this holder'),true,true);
      const decoded=full(decode),plain=decoded.holdings.find(h=>h.actorId==='wslDC'&&h.artifactId===object.artifactId&&h.representationId==='plain');
      ok('decoded exact received object '+spec.key,!!plain,!!plain,true);same('wire provenance retained '+spec.key,decoded.holdings.find(h=>h.holdingId===wire.holdingId),wire);
      ok('existing receiver key '+spec.key,before.holdings.some(h=>h.actorId==='wslDC'&&h.artifactId===m.id+':'+spec.keyUse&&h.representationId==='plain'),true,true);
      const verified=full(verify),held=verified.holdings.find(h=>h.holdingId===plain.holdingId);a.heldView.select(held);
      const text=a.querySelector('#held-inspector').textContent;ok('readable accepted verification '+spec.key,!text.includes('Not readable by this holder')&&text.includes('accepted'),text,'readable accepted verification');
      history(decode,object);history(verify,object);
    }
    if(m.id==='lab-pam01'&&m.variantId==='password-change-required'){
      const expected=literal['WP-R05'].members.find(row=>row.id===m.subfixtureId),modules=steps.map((s,index)=>({s,index,e:s.pamEvaluation})).filter(row=>row.e?.executed&&['prelim','update'].includes(row.e.apiPhase));
      same('reached internal phases',modules.map(row=>row.e.apiPhase),expected.phases);
      for(const {index,e}of modules){
        const flags=e.apiPhase==='prelim'?literal['WP-R05'].prelimFlags:literal['WP-R05'].updateFlags;full(index);
        same('complete stored dispatch flags',e.flags,flags);same('complete rendered dispatch flags',values()['Internal module dispatch / flags'],'pam_chauthtok / '+flags);
      }
      same('public password result',full(steps.length-1).state.workstation.pamResults.password,expected.status);
      const call=steps.findIndex(s=>s.id==='lab-pam01:call-password-default');
      if(call>=0){full(call);same('public call excludes phase bits',values()['API call / flags'],'pam_chauthtok / '+literal['WP-R05'].publicFlags);}
    }
    const account=literal['WP-R06'].cases.find(row=>row.modelId===m.id&&row.variant===m.variantId);
    if(account){
      const modules=steps.map((s,index)=>({s,index,e:s.pamEvaluation})).filter(row=>row.e?.apiPhase==='account'&&row.e.executed);
      same('physical account order once',modules.map(row=>row.e.line),account.lines);same('physical account module identity',modules.map(row=>row.e.module),literal['WP-R06'].modules);
      const returned=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='account'&&Object.hasOwn(s.pamEvaluation,'aggregateReturn'));
      for(const {index,e,s}of modules){
        const state=full(index).state.workstation;same('no future account aggregate',state.pamResults?.account??null,null);
        same('stored accumulator',state.pamEvaluation.accumulatorAfter,e.accumulatorAfter);
        same('rendered aggregate pending',values()['API aggregate return'],'Pending: current API call has not completed');
        same('rendered current physical row',Number(a.querySelector('#pam-configuration-panel [aria-current=\"step\"]').dataset.pamLine),e.line);
        const record=m.workstationInventory.artifacts.find(o=>s.attributeOperations.some(op=>op.kind==='create'&&op.instanceId===o.artifactId)&&o.type==='pam-return');history(index,record);
      }
      same('no accumulator reset',modules[1].e.accumulatorBefore,modules[0].e.accumulatorAfter);
      full(returned);same('completed account aggregate',values()['API aggregate return'],account.status);
    }
    if(m.id==='lab-llog01'){
      const modules=steps.map((s,index)=>({s,index})).filter(({s})=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed);
      same('one physical local authentication completion',modules.length,1);
      const returned=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&Object.hasOwn(s.pamEvaluation,'aggregateReturn')),secret=artifact('entered-secret'),verifier=artifact('verifier');
      ok('local aggregate follows module completion',returned>modules[0].index,returned,modules[0].index);
      same('aggregate remains owner-local',[steps[returned].from,steps[returned].to],['llogPAM','llogPAM']);
      same('password use only at physical module',steps.filter(s=>s.attributeOperations.some(op=>op.instanceId===secret.artifactId&&op.kind==='use'&&op.actorId==='llogPAM')).map(s=>s.id),[modules[0].s.id]);
      same('authentication pending until aggregate',full(modules[0].index).state.workstation.authenticated,false);
      same('rendered local API aggregate pending',values()['API aggregate return'],'Pending: current API call has not completed');
      const accepted=full(returned);
      same('completed local authentication',accepted.state.workstation.pamResults.authenticate,'PAM_SUCCESS');
      same('verifier never delivered to caller',accepted.holdings.filter(h=>h.artifactId===verifier.artifactId).map(h=>h.actorId),['llogPAM']);
      history(modules[0].index,secret);
      a.heldView.trace(secret.artifactId);same('exact password history excludes aggregate',a.traceQueue.some(s=>s.sourceStepId===steps[returned].id),false);
      full(modules[0].index);a.selectAttribute(secret.attributeId,false);same('field password history excludes aggregate',a.traceQueue.some(s=>s.sourceStepId===steps[returned].id),false);
      history(returned,verifier);
    }
    if(m.id==='lab-lelev02'&&['setuid-not-real-root','real-root-bypass'].includes(m.variantId)){
      const modules=steps.filter(s=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed).map(s=>s.pamEvaluation);
      same('rootok dispatch sequence',modules.map(e=>e.module),m.variantId==='real-root-bypass'?['pam_rootok.so']:['pam_rootok.so','pam_unix.so']);
      same('rootok action',modules[0].mappedAction,m.variantId==='real-root-bypass'?'done':'ignore');
    }
    if(m.id==='lab-llog04'){
      for(const [index,s]of steps.entries())if(s.pamEvaluation?.executed&&['prelim','update'].includes(s.pamEvaluation.apiPhase)){
        full(index);const flags=s.pamEvaluation.apiPhase==='prelim'?literal['WP-R05'].prelimFlags:literal['WP-R05'].updateFlags;
        same('existing expired-token stored flags',s.pamEvaluation.flags,flags);same('existing expired-token rendered flags',values()['Internal module dispatch / flags'],'pam_chauthtok / '+flags);
      }
    }
    if(m.id==='lab-wra01'&&m.variantId==='default-filtered'&&m.subfixtureId==='local'||m.id==='lab-wra03'&&m.variantId==='domain-ntlm-explicit'){
      const proof=artifact('ntlm-proof'),i=steps.findIndex(s=>s.workstationStage==='ntlm-derive');full(i);
      const h=snapshot().holdings.find(h=>h.artifactId===proof.artifactId&&h.actorId==='smbClient'&&h.representationId==='plain');a.heldView.select(h);
      const text=a.querySelector('#held-inspector').textContent;
      for(const value of [literal['WP-R07'].equation,literal['WP-R07'].avFlag,literal['WP-R07'].messageMicField])ok('NTLM inspector '+value,text.includes(value),text,value);
      same('MIC bytes not in client challenge',proof.value.includes('target-AV,MIC'),false);
    }
    return {modelId:m.id,variant:m.variantId,subfixture:m.subfixtureId??null,checks};
  },corrections.findings);
  log('correction-evidence.jsonl',{mode:active.mode,mechanism:'actual application selection/inspection/history controllers and rendered DOM in real Chromium; not claimed as trusted per-row input',...result});
  return result;
}

async function lifetimeEvidence(page){
  // Keep the previous correction assertions intact, including physical account
  // order, rootok and the PAM01 flags/status references.
  const preserved=await correctionEvidence(page);
  const result=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),m=a.labModel,steps=m.steps(),objects=m.workstationInventory.artifacts,checks=[],boundaries=[];
    const same=(name,actual,expected)=>{const passed=JSON.stringify(actual)===JSON.stringify(expected),bounded=v=>typeof v==='string'&&v.length>4096?{characters:v.length,completePrefixRecordsInCanonicalReference:true}:v;checks.push({name,passed,actual:passed?bounded(actual):actual,expected:passed?bounded(expected):expected});if(!passed)throw Error(name+': '+JSON.stringify({actual,expected}));};
    const ok=(name,actual)=>same(name,!!actual,true);
    const full=index=>{if(a.hasTrace)a.clearAttribute();if(index<0)a.reset();else a.selectStep(index,false);return a.heldView.snapshot();};
    const stable=s=>JSON.stringify({clock:s.protocolClock,state:s.state,holdings:s.holdings,observations:s.observations});
    const values=()=>Object.fromEntries([...a.querySelectorAll('#pam-configuration-panel .pam-evaluation > div')].map(e=>[e.querySelector('dt').textContent,e.querySelector('dd').textContent]));
    const object=key=>objects.find(o=>o.artifactId===m.id+':'+key||o.key===key);
    const histories=o=>{
      a.heldView.trace(o.artifactId);const exact=a.traceQueue.map(s=>s.sourceStepId);a.clearAttribute();
      a.selectAttribute(o.attributeId,false);const field=a.traceQueue.map(s=>s.sourceStepId);a.clearAttribute();
      return {exact,field};
    };
    const agreement=(index,o)=>{
      const expectedSnapshot=full(index),expected=stable(expectedSnapshot),before=stable(full(index-1)),traces=histories(o);
      for(const kind of ['exact','field']){
        full(index);if(kind==='exact')a.heldView.trace(o.artifactId);else a.selectAttribute(o.attributeId,false);
        const i=a.traceQueue.findIndex(s=>s.sourceStepId===steps[index].id);
        if(i>=0){
          a.selectStep(i,false);same(kind+' complete snapshot agrees '+steps[index].id,stable(a.heldView.snapshot()),expected);
        }else{
          // Histories deliberately omit unrelated API/control events. Compare
          // exact custody at those boundaries, not unrelated protocol state.
          const preceding=a.traceQueue.findLastIndex(s=>steps.findIndex(row=>row.id===s.sourceStepId)<=index);
          ok(kind+' preceding custody event '+steps[index].id,preceding>=0);a.selectStep(preceding,false);
          same(kind+' unchanged object custody agrees '+steps[index].id,a.heldView.snapshot().holdings.filter(h=>h.artifactId===o.artifactId),expectedSnapshot.holdings.filter(h=>h.artifactId===o.artifactId));
        }
      }
      same('rewind prefix '+steps[index].id,stable(full(index-1)),before);
      same('forward prefix '+steps[index].id,stable(full(index)),expected);
      return traces;
    };
    const inspect=(index,o)=>{
      const s=full(index),h=s.holdings.find(h=>h.artifactId===o.artifactId);
      ok('inspector current holding '+o.artifactId,!!h);a.heldView.select(h);
      const text=a.querySelector('#held-inspector').textContent;
      ok('real visible inspector '+o.artifactId,!a.querySelector('#held-inspector').hidden&&text.length>0);
      boundaries.push({index,stepId:steps[index].id,artifactId:o.artifactId,cursor:s.cursor,text,values:values()});
    };
    const classificationChecks=[],classificationObservations=[];
    const classifiedSame=(name,actual,expected)=>{
      const passed=JSON.stringify(actual)===JSON.stringify(expected);
      classificationChecks.push({name,passed,actual,expected});
      if(!passed)throw Error(name+': '+JSON.stringify({actual,expected}));
    };
    const classification=(label)=>{
      const snapshot=a.heldView.snapshot();
      const canonical=(m.pamStatePaths?.results||'').split('.').reduce((value,key)=>value?.[key],snapshot.state);
      if(!canonical)return;
      // Independent literal oracle: do not import or call the renderer partition.
      const expected={aggregates:{},'password-dispatch':{},'pending-results':{}};
      for(const [phase,status]of Object.entries(canonical)){
        const category=status==='not evaluated'?'pending-results':['prelim','update'].includes(phase)?'password-dispatch':'aggregates';
        expected[category][phase]=status;
      }
      const summaries={aggregates:'Completed API aggregate results','password-dispatch':'Internal password dispatch results','pending-results':'Pending / not-started results'};
      const observed={};
      for(const [category,summary]of Object.entries(summaries)){
        const disclosures=a.querySelectorAll('#pam-configuration-panel details[data-pam-disclosure="'+category+'"]');
        classifiedSame(label+' one '+category+' disclosure',disclosures.length,1);
        const disclosure=disclosures[0];
        classifiedSame(label+' literal '+category+' summary',disclosure.querySelector('summary').textContent,summary);
        const contents=JSON.parse(disclosure.querySelector('pre').textContent);
        classifiedSame(label+' canonical '+category+' contents',contents,expected[category]);
        observed[category]=contents;
      }
      classifiedSame(label+' public has no internal keys',Object.keys(observed.aggregates).some(key=>['prelim','update'].includes(key)),false);
      classifiedSame(label+' public has no placeholders',Object.values(observed.aggregates).includes('not evaluated'),false);
      classifiedSame(label+' internal only completed passes',Object.entries(observed['password-dispatch']).every(([key,status])=>['prelim','update'].includes(key)&&status!=='not evaluated'),true);
      classifiedSame(label+' pending only placeholders',Object.values(observed['pending-results']).every(status=>status==='not evaluated'),true);
      const explanation=a.querySelector('#pam-configuration-panel [data-pam-disclosure="password-dispatch"]').textContent;
      classifiedSame(label+' enclosing-call explanation',explanation.includes('pam_chauthtok')&&explanation.includes('prelim')&&explanation.includes('update')&&/passes.*inside|inside.*passes/i.test(explanation)&&/not separate application calls/i.test(explanation),true);
      classificationObservations.push({label,cursor:snapshot.cursor,canonical,observed});
    };
    if(['lab-llog04','lab-pam01'].includes(m.id)){
      // Every actual prefix, including intermediate conversation/backend and
      // sender-local preparation, is checked without adding matrix cells.
      for(let index=-1;index<steps.length;index++){
        full(index);classification('full '+index);
        const publicPasswordReturn=steps.findIndex(step=>step.pamEvaluation?.apiPhase==='password'&&Object.hasOwn(step.pamEvaluation,'aggregateReturn'));
        if(publicPasswordReturn<0||index<publicPasswordReturn){
          const publicResults=a.querySelector('#pam-configuration-panel [data-pam-disclosure="aggregates"] pre');
          if(publicResults)classifiedSame('no public password completion before return '+index,Object.hasOwn(JSON.parse(publicResults.textContent),'password'),false);
        }
      }
      for(let index=steps.length-1;index>=-1;index--){
        full(index);classification('rewind '+index);
      }
      const representative=steps.map((step,index)=>({step,index})).filter(({step})=>step.pamEvaluation&&['prelim','update','password'].includes(step.pamEvaluation.apiPhase));
      for(const {step,index}of representative){
        const artifact=objects.find(o=>step.attributeOperations.some(op=>op.instanceId===o.artifactId&&op.kind==='create'));
        if(!artifact)continue;
        for(const kind of ['exact','field']){
          full(index);
          if(kind==='exact')a.heldView.trace(artifact.artifactId);else a.selectAttribute(artifact.attributeId,false);
          const cursor=a.traceQueue.findIndex(row=>row.sourceStepId===step.id);
          classifiedSame(kind+' classification boundary exists '+step.id,cursor>=0,true);
          a.selectStep(cursor,false);classification(kind+' '+step.id);
          if(cursor>0){a.selectStep(cursor-1,false);classification(kind+' rewind '+step.id);a.selectStep(cursor,false);classification(kind+' forward '+step.id);}
        }
        full(index);
        for(const category of ['aggregates','password-dispatch','pending-results']){
          const disclosure=a.querySelector('#pam-configuration-panel [data-pam-disclosure="'+category+'"]');
          if(!disclosure)continue;
          disclosure.open=true;disclosure.querySelector('summary').focus();
          full(index-1);
          const restored=a.querySelector('#pam-configuration-panel [data-pam-disclosure="'+category+'"]');
          classifiedSame('rewind keeps '+category+' expanded '+step.id,restored?.open,true);
          classifiedSame('rewind keeps '+category+' focus '+step.id,document.activeElement===restored?.querySelector('summary'),true);
          classification('focused rewind '+category+' '+step.id);
          full(index);classification('focused forward '+category+' '+step.id);
        }
      }
    }
    const secrets=new Set(objects.filter(o=>o.type==='secret').map(o=>o.artifactId));
    for(let index=0;index<steps.length;index++){
      const before=full(index-1),step=steps[index];
      for(const op of step.attributeOperations.filter(op=>secrets.has(op.instanceId)&&['use','verify'].includes(op.kind))){
        ok('no post-release password use '+step.id+' '+op.instanceId,before.holdings.some(h=>h.artifactId===op.instanceId&&h.actorId===op.actorId)||step.attributeOperations.some(o=>o.kind==='create'&&o.instanceId===op.instanceId&&o.actorId===op.actorId));
      }
    }
    const captures=[];
    if(m.id==='lab-lelev01'){
      const fresh=['default','wrong-password','expired-timestamp','different-terminal','rootpw','targetpw','runaspw','account-denied'].includes(m.variantId);
      const modules=steps.map((s,index)=>({s,index})).filter(({s})=>s.pamEvaluation?.apiPhase==='authenticate'&&s.pamEvaluation.executed===true),secret=object('secret');
      if(fresh){
        same('one physical sudo password check',modules.length,1);
        const module=modules[0].index,aggregate=steps.findIndex(s=>s.pamEvaluation?.apiPhase==='authenticate'&&Object.hasOwn(s.pamEvaluation,'aggregateReturn'));
        ok('aggregate follows physical check',aggregate>module);
        same('only physical module consumes sudo password',steps.filter(s=>s.attributeOperations.some(o=>o.instanceId===secret.artifactId&&o.kind==='use'&&o.actorId==='lelevPAM')).map(s=>s.id),[steps[module].id]);
        same('live PAM custody immediately before module',full(module-1).holdings.some(h=>h.artifactId===secret.artifactId&&h.actorId==='lelevPAM'),true);
        inspect(module-1,secret);agreement(module-1,secret);
        for(const index of [module,aggregate])same('password absent after release '+steps[index].id,full(index).holdings.filter(h=>h.artifactId===secret.artifactId),[]);
        const traces=agreement(module,secret);
        for(const kind of ['exact','field']){
          same(kind+' password includes physical module',traces[kind].includes(steps[module].id),true);
          same(kind+' password excludes aggregate',traces[kind].includes(steps[aggregate].id),false);
        }
        agreement(aggregate,secret);
        const record=objects.find(o=>steps[aggregate].attributeOperations.some(op=>op.instanceId===o.artifactId&&op.kind==='create'));
        ok('aggregate evidence object exists',record);agreement(aggregate,record);inspect(aggregate,record);
        if(m.variantId==='default')captures.push({index:aggregate,artifactId:record.artifactId,label:'sudo-aggregate'});
        const end=full(steps.length-1).state.workstation;
        same('sudo authentication outcome',end.authenticated,m.variantId!=='wrong-password');
        same('sudo admission outcome',end.operation,!['wrong-password','account-denied'].includes(m.variantId));
      }else{
        same('no fabricated sudo password',objects.some(o=>o.type==='secret'),false);
        same('no fabricated sudo password module',modules.length,0);
      }
    }
    if(m.id==='lab-llog04'){
      const expected={default:['PAM_SUCCESS',true],'new-policy-denied':['PAM_AUTHTOK_ERR',false],'update-failed':['PAM_AUTHTOK_ERR',false],'directory-unreachable':['PAM_AUTHINFO_UNAVAIL',false],'directory-online':['PAM_SUCCESS',true],'post-change-account-denied':['PAM_SUCCESS',false]}[m.variantId];
      const calls=steps.map((s,index)=>({s,index})).filter(({s})=>s.from==='pamChangeApp'&&s.to==='pamChange'&&s.pamEvaluation?.api==='pam_chauthtok');
      const returns=steps.map((s,index)=>({s,index})).filter(({s})=>s.from==='pamChange'&&s.to==='pamChangeApp'&&s.pamEvaluation?.api==='pam_chauthtok'&&Object.hasOwn(s.pamEvaluation,'aggregateReturn'));
      same('public password call count',calls.length,expected?1:0);same('public password return count',returns.length,expected?1:0);
      if(expected){
        const call=calls[0],returned=returns[0],modules=steps.map((s,index)=>({s,index})).filter(({s})=>s.pamEvaluation?.executed===true&&['prelim','update'].includes(s.pamEvaluation.apiPhase));
        same('both internal phases within single call',modules.map(({s})=>s.pamEvaluation.apiPhase),['prelim','update']);
        ok('public call encloses internal modules',call.index<modules[0].index&&modules.at(-1).index<returned.index);
        for(const {s,index}of [call,returned]){
          same('public API phase '+s.id,s.pamEvaluation.apiPhase,'password');
          same('caller-only public flags '+s.id,s.pamEvaluation.flags,'PAM_CHANGE_EXPIRED_AUTHTOK');
          full(index);same('rendered caller flags '+s.id,values()['API call / flags'],'pam_chauthtok / PAM_CHANGE_EXPIRED_AUTHTOK');
        }
        for(const {s,index}of modules){
          const flags='PAM_CHANGE_EXPIRED_AUTHTOK | '+(s.pamEvaluation.apiPhase==='prelim'?'PAM_PRELIM_CHECK':'PAM_UPDATE_AUTHTOK');
          same('combined internal flags '+s.id,s.pamEvaluation.flags,flags);
          full(index);same('rendered combined flags '+s.id,values()['Internal module dispatch / flags'],'pam_chauthtok / '+flags);
        }
        const args=objects.filter(o=>o.creator==='pamChangeApp'&&o.type==='local-call-control').map(o=>({o,v:JSON.parse(o.value)})).filter(({v})=>v.api==='pam_chauthtok');
        const results=objects.filter(o=>o.type==='pam-aggregate').map(o=>({o,v:JSON.parse(o.value)})).filter(({v})=>v.api==='pam_chauthtok');
        same('one caller-created password argument',args.map(({v})=>v.flags),['PAM_CHANGE_EXPIRED_AUTHTOK']);
        same('one public result, no preliminary completion',results.map(({v})=>[v.apiPhase,v.flags,v.status]),[['password','PAM_CHANGE_EXPIRED_AUTHTOK',expected[0]]]);
        for(let index=call.index;index<returned.index;index++){
          const snap=full(index),w=snap.state.workstation;
          same('password pending '+steps[index].id,w.pamResults?.password??null,null);
          same('public invocation remains pending '+steps[index].id,w.pamEvaluation.apiPending,true);
          same('DOM aggregate remains pending '+steps[index].id,values()['API aggregate return'],'Pending: current API call has not completed');
          same('no preliminary public result delivered '+steps[index].id,snap.holdings.some(h=>h.actorId==='pamChangeApp'&&objects.some(o=>o.artifactId===h.artifactId&&o.type==='pam-aggregate'&&['prelim','update'].includes(JSON.parse(o.value).apiPhase))),false);
        }
        for(const {index,s}of [call,...modules,returned]){
          const record=index===call.index?args[0].o:index===returned.index?results[0].o:objects.find(o=>s.attributeOperations.some(op=>op.instanceId===o.artifactId&&op.kind==='create'));
          ok('boundary object '+s.id,record);agreement(index,record);inspect(index,record);
        }
        const aggregate=results[0].o;
        same('final result physically sent and received at public return',returned.s.attributeOperations.filter(op=>op.instanceId===aggregate.artifactId&&['send','receive'].includes(op.kind)).map(op=>[op.kind,op.actorId]),[['send','pamChange'],['receive','pamChangeApp']]);
        const completed=full(returned.index);
        same('caller holds the actual final public result',completed.holdings.some(h=>h.artifactId===aggregate.artifactId&&h.actorId==='pamChangeApp'),true);
        agreement(returned.index,aggregate);
        full(returned.index);same('completed public password result',values()['API aggregate return'],expected[0]);
        const end=full(steps.length-1);
        same('session admission outcome',end.state.workstation.session,expected[1]);
        same('generation G2 only on authority success',end.holdings.some(h=>h.artifactId==='lab-llog04:backend-generation-g2'&&h.actorId==='pamPasswordAuthority'),expected[0]==='PAM_SUCCESS');
        if(m.variantId==='post-change-account-denied'){
          same('post-change account performed',end.state.workstation.postChangeAccountChecked,true);
          same('post-change account denial retained',end.state.workstation.admitted,false);
        }
        if(m.variantId==='default'){
          const pendingRecord=objects.find(o=>o.type==='pam-return'&&modules[0].s.attributeOperations.some(op=>op.instanceId===o.artifactId&&op.kind==='create'));
          captures.push({index:modules[0].index,artifactId:pendingRecord.artifactId,label:'password-pending'},{index:returned.index,artifactId:aggregate.artifactId,label:'password-complete'});
        }
      }else same('no password API invented for unsupported/rejected consumer',steps.some(s=>s.pamEvaluation?.api==='pam_chauthtok'),false);
    }
    return {modelId:m.id,variant:m.variantId,subfixture:m.subfixtureId??null,checks,boundaries,captures,classificationChecks,classificationCheckCount:classificationChecks.length,classificationObservations};
  });
  log('pam-lifetime-evidence.jsonl',{mode:active.mode,mechanism:'real Chromium DOM and existing full/field/exact history controllers; per-boundary controller checks, not native OS claims',...result});
  if(active.mode==='source-http')for(const capture of result.captures){
    await page.evaluate(({index,artifactId})=>{
      const a=document.querySelector('auth-flow-studio');if(a.hasTrace)a.clearAttribute();a.selectStep(index,false);
      const h=a.heldView.snapshot().holdings.find(h=>h.artifactId===artifactId);assertHolding(h);
      function assertHolding(value){if(!value)throw Error('Screenshot current holding missing');}
      a.heldView.select(h);a.querySelector('#held-inspector').scrollIntoView({block:'center'});
    },capture);
    await settle(page);capture.screenshot=await screenshot(page,capture.label);
  }
  return {preserved,...result};
}

async function decisionEvidence(page){
  const observed=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),s=a.protocolSnapshot(),panel=a.querySelector('#lesson-decisions');
    const remote=a.labModel?.family==='windows-remote-administration';
    const bindings=(a.labModel?.decisionBindings||[]).filter(b=>!remote||!['workstation.tokenComparison','workstation.policyComparison','workstation.verdictExplanation','workstation.localComparisonQualification'].includes(b.path));
    const expected=bindings.map(binding=>{
      const value=binding.path.split('.').reduce((o,k)=>o&&Object.hasOwn(o,k)?o[k]:undefined,s.state);
      const display=binding.values&&Object.hasOwn(binding.values,String(value))?binding.values[String(value)]:
        value===undefined?'Not declared':value===null?'Not reached':value===true?'Yes':value===false?'No':typeof value==='object'?JSON.stringify(value):String(value);
      return {label:binding.label,path:binding.path,display:String(display)};
    });
    return {hidden:panel.hidden,cursor:s.cursor,expected,rows:[...panel.querySelectorAll(':scope > dl > div')].map(e=>({label:e.querySelector('dt').textContent,display:e.querySelector('dd').textContent}))};
  });
  log('decision-evidence.jsonl',{mode:active.mode,...observed});
  assert.equal(observed.hidden,observed.expected.length===0);
  assert.deepEqual(observed.rows,observed.expected.map(({label,display})=>({label,display})),'Every rendered decision comes from current canonical prefix');
  return observed;
}
async function runningSearch(page){
  await choose(page,'lab-wra01');await click(page,'#play');
  assert.equal((await state(page)).status,'playing');
  const before=await state(page);
  await page.locator('#lab-scenario-search').focus();await fill(page,'#lab-scenario-search','unrelated-no-result-73951');
  assert.equal(await page.locator('#lab-scenario-results [data-scenario-option]').count(),0);
  await key(page,'Enter');await key(page,'Escape');
  const after=await state(page);
  for(const field of ['id','variant','subfixture','context'])assert.deepEqual(after[field],before[field]);
  assert.equal(after.status,'playing','No-result Enter and typed query preserve real running demo');
  await click(page,'#play');assert.equal((await state(page)).status,'paused');
  await click(page,'#reset');clean(await state(page));
  return {before,after,reset:true};
}
async function shape(page,id,value,fixture=null){
  if(fixture)await activateFixture(page,fixture);else await choose(page,id);
  if(active.device==='zoom200'){
    if(Math.abs(await page.evaluate(()=>devicePixelRatio)-2)>.025)await zoom200(page);
    assert.equal(await page.evaluate(()=>visualViewport.scale),1);
  }
  const applicability=await expanded(page,value);await seek(page,1000);
  const terminalSha256=fixture?await renderedTerminal(page,fixture):null;
  const result={...applicability,terminalSha256,geometry:await geometry(page),animation:await animation(page)};
  return result;
}
try{
  report.before=identity();reference=json(options.reference);
  search=json(path.join(root,inputNames[0]));routing=json(path.join(root,inputNames[2]));
  pamDispatch=json(path.join(root,inputNames[3]));
  if(correctionsOnly||lifetimeOnly)corrections=json(path.join(root,inputNames.at(-1)));
  assert.equal(reference.schemaVersion,2);assert.equal(reference.kind,'windows-protection-source-held-prefix-check');
  for(const field of ['passed','complete','sourceUnchanged'])assert.equal(reference[field],true,'Accepted canonical reference '+field);
  assert.deepEqual(reference.failures,[],'No source reference failures');
  assert.deepEqual(reference.identities.sourceFiles,report.before.sourceFiles,'Exact actual source inventory and every hash');
  assert.equal(reference.identities.standaloneSha256,report.before.standalone.sha256,'Fresh emitted bytes');
  assert.equal(reference.identities.runner.sha256,report.before.helpers.canonical.sha256,'Actual source checker identity');
  for(const input of reference.inputs)assert.equal(report.before.frozenInputs[input.path].sha256,input.sha256,'Frozen independent input '+input.path);
  fixtures=reference.fixtures;assert.ok(Array.isArray(fixtures),'Canonical fixtures array');
  assert.equal(fixtures.length,128);assert.equal(reference.canonicalCases.length,110);
  assert.equal(new Set(fixtures.map(f=>f.modelId+'|'+f.variantId)).size,110);
  assert.equal(new Set(fixtures.map(f=>f.executionId)).size,128,'No dropped/duplicate canonical executions');
  assert.equal(search.fixtures.length,29);
  for(const f of fixtures){
    assert.equal(f.passed,true);assert.ok(f.modelId&&f.variantId&&f.executionId&&f.prefixes.length);
    assert.equal(f.prefixes.length,f.steps);
  }
  report.scope=options.scope;
  report.referenceDenominators={canonicalCases:110,uniqueExecutions:128,queries:29};
  if(options.scope==='smoke'){
    const seen=new Set(),regressions=new Set(['WPROT01/local-account','WPROT02/audit-plugin','WPROT03/constrained-denied','PAM01/requisite-immediate-failure','PAM01/sufficient-early-success','PAM01/bracket-default-denial','PAM01/include-termination']);
    fixtures=fixtures.filter(f=>{const first=!seen.has(f.modelId);seen.add(f.modelId);return first||regressions.has(f.caseId);});
    report.notEstablished.push('Complete three-loading-mode128-execution matrix: this is an explicitly bounded preflight.');
  }
  if(correctionsOnly){
    const cases=new Set(['WRA01/default-filtered','WRA01/reused-session','WRA03/domain-ntlm-explicit','WPROT01/constrained-continuation','WPROT03/aes-kerberos','WPROT03/fresh-authentication','WPROT03/lifetime-expired','WPROT04/allowed-device','WPROT04/device-denied-audit','WPROT04/policy-lifetime','WPROT04/device-denied-enforce','WPROT05/allowed-service','WPROT05/target-rule-enforce','WPROT05/ticket-then-acl-denial','WPROT05/required-context-missing','PAM01/password-change-required']);
    fixtures=fixtures.filter(f=>cases.has(f.caseId));assert.equal(new Set(fixtures.map(f=>f.caseId)).size,cases.size,'Every targeted correction case selected');
    report.notEstablished.push('Complete current1815-cell/browser/performance collection: this correction run is deliberately targeted. Earlier broad receipts remain bound to candidate02.');
  }
  if(lifetimeOnly){
    const members=new Set(['change-prelim-failure','change-unsupported','change-update-failure','change-success']);
    fixtures=fixtures.filter(f=>f.modelId==='lab-pam01'&&f.variantId==='password-change-required'&&members.has(f.subfixtureId));
    assert.equal(fixtures.length,4,'All four existing PAM01 password lifecycle references');
    report.notEstablished.push('Only PAM lifetime correction cells are rerun; closed Windows findings and prior broad browser/performance receipts are not rerun or promoted.');
    report.lifetimeDenominators={existingConsumerVariants:lifetimePam.length,sudoFreshPasswordVariants:8,sudoNoPromptControls:7,reachedPasswordChangeVariants:6,noPasswordChangeControls:3,localLoginControls:1,suAccountRootokControls:4,pam01References:4,loadingModes:3};
  }
  if(surfaceOnly){fixtures=[];report.notEstablished.push('Complete canonical/query/control matrix: this affected/broadened collection repeats only its declared three-mode device surfaces.');}
  if(searchOnly){fixtures=[];report.notEstablished.push('Complete canonical/PAM/device matrix: this affected picker collection repeats only 29 queries, playback preservation, route/copy and comparison activation in three modes. Prior complete case/device observations retain their original artifact identity.');}
  report.selectedFixtures=fixtures.map(f=>({caseId:f.caseId,executionId:f.executionId}));
  const captures=[
    [runner,'runner-input.mjs'],[options.reference,'canonical-reference-input.json'],
    [fileURLToPath(new URL('./dnssec-native-controls.mjs',import.meta.url)),'seek-helper-input.mjs'],
    [path.join(root,'tools/verification/windows-protection-canonical.mjs'),'canonical-helper-input.mjs'],
    ...Object.keys(report.before.frozenInputs).map((name,i)=>[path.join(root,name),'frozen-input-'+i+'.json']),
  ];
  for(const [file,name] of captures)fs.copyFileSync(file,path.join(out,name),fs.constants.COPYFILE_EXCL);
  report.frozenCaptures=captures.map(([file,name])=>({original:file,capture:name,...digest(path.join(out,name))}));
  for(const mode of modes){
    if(!surfaceOnly){
      planned(mode+'/setup');
      for(const f of fixtures)for(const stage of ['canonical','geometry-compact','geometry-expanded','evidence'])
        planned(mode+'/'+f.executionId+'/'+stage,{modelId:f.modelId,caseId:f.caseId,variantId:f.variantId,subfixtureId:f.subfixtureId??null});
      for(const s of correctionsOnly||lifetimeOnly?[]:search.fixtures)planned(mode+'/search/'+s.query);
      for(const name of correctionsOnly||lifetimeOnly?['browser-errors']:searchOnly?['running-search','routes','comparisons','browser-errors']:['running-search','routes','comparisons','stale-context','browser-errors'])planned(mode+'/'+name);
      for(const row of searchOnly?[]:selectedExistingPam)planned(mode+'/existing-pam/'+pamKey(row));
      for(const id of searchOnly||correctionsOnly||lifetimeOnly?[]:legacySurfaces)for(const shape of ['compact','expanded'])planned(mode+'/desktop/'+id+'/'+shape);
    }
    for(const device of searchOnly||correctionsOnly||lifetimeOnly?[]:options.scope==='zoom'?['zoom200']:devices){
      planned(mode+'/'+device+'/setup');planned(mode+'/'+device+'/browser-errors');
      for(const id of deviceSurfaces)for(const shape of ['compact','expanded'])planned(mode+'/'+device+'/'+id+'/'+shape);
    }
  }
  save();
  const mime=file=>({'.js':'application/javascript','.mjs':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.json':'application/json'})[path.extname(file)]||'text/html';
  server=http.createServer((req,res)=>{
    try{
      const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
      const file=fs.realpathSync(path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname)));
      assert.ok(file.startsWith(root+path.sep),'Confined HTTP input');assert.ok(fs.statSync(file).isFile());
      res.setHeader('Content-Type',mime(file));res.end(fs.readFileSync(file));
    }catch{res.statusCode=404;res.end('Not found');}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  origin='http://127.0.0.1:'+server.address().port;await startX();
  const {chromium}=await import(pathToFileURL(options.playwright).href);
  browser=await chromium.launch({executablePath:options.chrome,headless:false,env:{...process.env,DISPLAY:display},
    args:['--no-sandbox','--disable-dev-shm-usage','--ozone-platform=x11','--window-size=1480,1000','--no-first-run','--disable-background-networking','--disable-component-update','--force-device-scale-factor=1']});
  report.browser={version:browser.version(),playwrightPackage:json(path.join(path.dirname(options.playwright),'package.json')).version};
  for(const mode of modes){
    if(aborted)break;
    let page;
    const setup=surfaceOnly?false:await cell(mode+'/setup',async()=>{page=await attach(mode,'desktop');return {url:page.url()};});
    if(setup){
      for(const f of fixtures){
        if(aborted)break;
        await cell(mode+'/'+f.executionId+'/canonical',async()=>{
          await choose(page,f.modelId,f.variantId,f.subfixtureId);return canonical(page,f);
        });
        for(const value of [false,true])await cell(mode+'/'+f.executionId+'/geometry-'+(value?'expanded':'compact'),()=>shape(page,f.modelId,value,f));
        await cell(mode+'/'+f.executionId+'/evidence',async()=>{
          await activateFixture(page,f);
          if(lifetimeOnly)return lifetimeEvidence(page);
          if(correctionsOnly)return correctionEvidence(page);
          if(f.modelId==='lab-pam01'){
            await page.locator('#speed').focus();await key(page,'End');return pamTraversal(page);
          }
          const initial={decisions:await decisionEvidence(page),remote:f.modelId.startsWith('lab-wra')?await remoteEvidence(page):null};
          await seek(page,1000);
          const terminal={decisions:await decisionEvidence(page),remote:f.modelId.startsWith('lab-wra')?await remoteEvidence(page):null};
          let ordinaryShareComparison=null;
          if(f.modelId==='lab-wra01'&&f.variantId==='default-filtered'&&f.subfixtureId==='local'){
            const selector='#lesson-inputs '+attr('data-compare-scenario','lab-wra01')+attr('data-compare-variant','ordinary-share-allowed');
            assert.equal(await page.locator(selector).isVisible(),true,'Default filtering exposes actual ordinary-share comparison');
            await page.locator(selector).focus();await key(page,'Enter');await settle(page);
            const changed=await state(page);assert.equal(changed.id,'lab-wra01');assert.equal(changed.variant,'ordinary-share-allowed');clean(changed);
            const target=reference.fixtures.find(row=>row.modelId==='lab-wra01'&&row.variantId==='ordinary-share-allowed');
            assert.ok(target);await seek(page,1000);
            ordinaryShareComparison={selected:changed,terminalSha256:await renderedTerminal(page,target),evidence:await remoteEvidence(page)};
          }
          return {initial,terminal,ordinaryShareComparison};
        });
      }
      for(const s of correctionsOnly||lifetimeOnly?[]:search.fixtures)await cell(mode+'/search/'+s.query,()=>searchQuery(page,s));
      if(!correctionsOnly&&!lifetimeOnly){
        await cell(mode+'/running-search',()=>runningSearch(page));
        await cell(mode+'/routes',()=>routes(page,mode));
        await cell(mode+'/comparisons',()=>comparisons(page));
        if(!searchOnly)await cell(mode+'/stale-context',()=>staleContext(page,fixtures.find(f=>f.modelId==='lab-wra01')));
      }
      for(const row of searchOnly?[]:selectedExistingPam)await cell(mode+'/existing-pam/'+pamKey(row),async()=>{
        await choose(page,row.id,row.variant);await page.locator('#speed').focus();await key(page,'End');
        if(lifetimeOnly)return lifetimeEvidence(page);
        if(correctionsOnly)return correctionEvidence(page);
        const result=await pamTraversal(page),observations=result.observations.map(r=>r.observation).filter(Boolean);
        if(row.unavailable)assert.ok(observations.some(o=>[o.raw,o.aggregate].includes('PAM_AUTHINFO_UNAVAIL')),'Actual unavailable PAM result rendered');
        if(row.publickey)assert.equal(observations.some(o=>o.phase==='authenticate'),false,'Public-key SSH does not invent pam_authenticate');
        const explain=page.locator('#pam-configuration-panel '+attr('data-compare-scenario','lab-pam01'));
        assert.equal(await explain.count(),1,'One real in-panel PAM explanation link');
        assert.equal(await explain.isVisible(),true);
        const variant=await explain.getAttribute('data-compare-variant');
        await explain.focus();await key(page,'Enter');await settle(page);
        const destination=await state(page);assert.equal(destination.id,'lab-pam01');clean(destination);
        assert.equal(destination.variant,variant||'local-login-success','Explanation opens its explicit named case/default, not stale PAM context');
        return {...row,...result};
      });
      for(const id of searchOnly||correctionsOnly||lifetimeOnly?[]:legacySurfaces)for(const value of [false,true])await cell(mode+'/desktop/'+id+'/'+(value?'expanded':'compact'),async()=>{
        const result=await shape(page,id,value);
        if(mode==='source-http'&&!value)result.screenshot=await screenshot(page,mode+'-desktop-'+id);
        return result;
      });
      await cell(mode+'/browser-errors',browserErrors);
    }
    await active?.context.close().catch(()=>{});active=null;
    for(const device of searchOnly||correctionsOnly||lifetimeOnly?[]:options.scope==='zoom'?['zoom200']:devices){
      if(aborted)break;
      let devicePage;
      const ok=await cell(mode+'/'+device+'/setup',async()=>{
        devicePage=await attach(mode,device);
        if(device==='zoom200')return zoom200(devicePage);
        if(device==='reduced')assert.equal(await devicePage.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches),true);
        const width=await devicePage.evaluate(()=>innerWidth);
        if(device==='narrow390')assert.equal(width,390,'Actual narrow viewport');
        return {width,reduced:device==='reduced'};
      });
      if(ok){
        for(const id of deviceSurfaces)for(const value of [false,true])await cell(mode+'/'+device+'/'+id+'/'+(value?'expanded':'compact'),async()=>{
          const result=await shape(devicePage,id,value);
          if(id==='lab-wra01'&&!value&&device!=='reduced')result.screenshot=await screenshot(devicePage,mode+'-'+device+'-remote');
          if(id==='lab-pam01'&&!value&&device==='reduced')result.screenshot=await screenshot(devicePage,mode+'-reduced-PAM');
          return result;
        });
        await cell(mode+'/'+device+'/browser-errors',browserErrors);
      }
      await active?.context.close().catch(()=>{});active=null;
    }
  }
}catch(error){report.failures.push({kind:'fatal',error:String(error.stack||error)});}
finally{
  clearTimeout(watchdog);await cleanup();
  try{
    report.after=identity();assert.deepEqual(report.after,report.before,'Source, emitted HTML, runner, helpers, frozen inputs, reference and tools unchanged');
    report.sourceUnchanged=true;
  }catch(error){report.failures.push({kind:'identity',error:String(error.stack||error)});}
  report.cells={
    required:report.matrix.length,attempted:report.matrix.filter(r=>r.status!=='unperformed').length,
    passed:report.matrix.filter(r=>r.status==='passed').length,failed:report.matrix.filter(r=>r.status==='failed').length,
    unperformed:report.matrix.filter(r=>r.status==='unperformed'||r.status==='running').length,
  };
  report.unperformed=report.matrix.filter(r=>r.status==='unperformed'||r.status==='running').map(r=>({
    key:r.key,reason:aborted?'Interrupted or finite deadline reached':'Required prerequisite/setup did not complete; see failure records',
  }));
  report.complete=report.cells.required>0&&report.cells.unperformed===0;
  report.passed=report.complete&&report.sourceUnchanged&&report.cells.failed===0&&report.failures.length===0;
  report.status=report.passed?'passed':report.complete?'failed':'incomplete';
  report.finishedAt=new Date().toISOString();report.elapsedMs=performance.now()-started;save();
  process.exitCode=report.passed?0:1;
  console.log(JSON.stringify({out,status:report.status,cells:report.cells,sourceUnchanged:report.sourceUnchanged}));
}
