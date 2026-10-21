#!/usr/bin/env bun
// Diagnostic attribution for the real shared legacy journey, not a latency pass gate.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(here,'../..');
const usage=`Usage: bun tools/verification/profile-expansion-replay.mjs
Requires AUTH_LAB_EXPANSION_BASELINE_ROOT, PLAYWRIGHT_MODULE and CHROMIUM_EXECUTABLE.
Uses the already-built accepted and expanded standalone files, fresh serial contexts,
real Play and in-play search, Chrome CPU profiles and Performance counters.
AUTH_LAB_EXPANSION_EVIDENCE_DIR selects the parent of a unique output directory.
No install, build, live protocol or alteration of the acceptance latency flags.`;
if(process.argv.includes('--help')||process.argv.includes('-h')){console.log(usage);process.exit(0);}
assert.equal(process.argv.length,2,usage);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=file=>JSON.parse(fs.readFileSync(file,'utf8'));
const identity=directory=>{
  const names=['index.html','build.mjs','package.json',...fs.readdirSync(path.join(directory,'src')).filter(name=>/\.(js|css)$/.test(name)).sort().map(name=>'src/'+name)];
  const sources=Object.fromEntries(names.map(name=>[name,hash(fs.readFileSync(path.join(directory,name)))]));
  const bytes=fs.readFileSync(path.join(directory,'dist/auth-flow-studio.html'));
  return {sources,sourceSnapshotSha256:hash(JSON.stringify(sources)),standalone:{bytes:bytes.length,sha256:hash(bytes)}};
};
const parent=path.resolve(process.env.AUTH_LAB_EXPANSION_EVIDENCE_DIR||path.join(root,'docs/verification/expansion'));
fs.mkdirSync(parent,{recursive:true});
const out=fs.mkdtempSync(path.join(parent,new Date().toISOString().replace(/[:.]/g,'-')+'-replay-profile-'));
const report={kind:'expansion-native-replay-profile',timestamp:new Date().toISOString(),passed:false,nativeBrowser:true,runnerSha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),regenerationCommand:[process.execPath,...process.argv.slice(1)],runtime:{executable:process.execPath,version:process.version,bun:process.versions.bun||null,platform:process.platform,arch:process.arch},environment:Object.fromEntries(['AUTH_LAB_EXPANSION_BASELINE_ROOT','PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE','LD_LIBRARY_PATH'].map(name=>[name,process.env[name]||null])),method:'Fresh serial standalone-file contexts per checkout with the field index open and closed through its real control. Each phase records a 1 ms Chrome CPU sampling profile, marker-bounded native trace and aggregate Performance counters. Profiled wall time includes instrumentation and is not the acceptance latency benchmark. Native/layout work may appear as unsymbolized program time; CPU function samples do not attribute native layout to a JavaScript function.',notEstablished:['These diagnostics do not clear or suppress material latency flags in expansion-native-status.json','Continuous frame rate, cross-engine performance, manual G01 and live interoperability'],phases:[],files:[]};
const filename=path.join(out,'expansion-replay-profile-status.json');
const save=()=>fs.writeFileSync(filename,JSON.stringify(report,null,2)+'\n');
const settle=page=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
function sampledFunctions(profile){
  const weights=new Map(),hits=new Map();
  for(let i=0;i<(profile.samples||[]).length;i++){
    const id=profile.samples[i];weights.set(id,(weights.get(id)||0)+(profile.timeDeltas[i]||0));hits.set(id,(hits.get(id)||0)+1);
  }
  return profile.nodes.filter(node=>weights.has(node.id)).map(node=>({functionName:node.callFrame.functionName||'(anonymous)',url:node.callFrame.url,line:node.callFrame.lineNumber+1,column:node.callFrame.columnNumber+1,sampledSelfMs:weights.get(node.id)/1000,sampleCount:hits.get(node.id)})).sort((a,b)=>b.sampledSelfMs-a.sampledSelfMs).slice(0,30);
}
const counters=metrics=>Object.fromEntries(metrics.filter(metric=>['Nodes','LayoutDuration','RecalcStyleDuration','ScriptDuration','TaskDuration','JSHeapUsedSize','LayoutCount','RecalcStyleCount'].includes(metric.name)).map(metric=>[metric.name,metric.value]));
async function state(page){return page.evaluate(()=>{
  const a=document.querySelector('auth-flow-studio'),index=a.refs['attribute-index-list'];
  return {status:a.player.status,elapsed:a.player.elapsed,scenario:a.labScenarioId,mode:a.player.mode,liveNodes:document.querySelectorAll('*').length,fieldRows:index.querySelectorAll('[data-index-attribute]').length,fieldIndexVisible:!!index.getClientRects().length,scroll:{x:scrollX,y:scrollY},sourceStep:a.steps[a.index]?.id};
});}
function recordFile(file,bytes){
  fs.writeFileSync(path.join(out,file),bytes);const item={file,bytes:Buffer.byteLength(bytes),sha256:hash(bytes)};report.files.push(item);return item;
}
async function saveTrace(cdp,version,phase){
  const complete=new Promise(resolve=>cdp.once('Tracing.tracingComplete',resolve));await cdp.send('Tracing.end');
  const {stream}=await complete,chunks=[];
  try{for(;;){const part=await cdp.send('IO.read',{handle:stream});chunks.push(Buffer.from(part.data,part.base64Encoded?'base64':'utf8'));if(part.eof)break;}}finally{await cdp.send('IO.close',{handle:stream});}
  const bytes=Buffer.concat(chunks),file=recordFile(version+'-'+phase+'.trace.json',bytes),events=JSON.parse(bytes.toString('utf8')).traceEvents;
  const begin=events.find(event=>event.name==='TimeStamp'&&event.args?.data?.message===version+':'+phase+':begin');
  const end=events.find(event=>event.name==='TimeStamp'&&event.args?.data?.message===version+':'+phase+':end');
  assert.ok(begin&&end&&end.ts>=begin.ts,'Explicit native trace action markers');
  const totals=new Map();
  for(const event of events){
    if(event.ph!=='X'||event.pid!==begin.pid||event.tid!==begin.tid||!Number.isFinite(event.dur))continue;
    const duration=Math.max(0,Math.min(event.ts+event.dur,end.ts)-Math.max(event.ts,begin.ts));if(!duration)continue;
    const item=totals.get(event.name)||{name:event.name,inclusiveMs:0,count:0};item.inclusiveMs+=duration/1000;item.count++;totals.set(event.name,item);
  }
  return {file,actionWindowMs:(end.ts-begin.ts)/1000,pid:begin.pid,tid:begin.tid,events:[...totals.values()].sort((a,b)=>b.inclusiveMs-a.inclusiveMs).slice(0,35)};
}
async function profilePhase(cdp,page,version,phase,action){
  const beforeState=await state(page);
  await cdp.send('Tracing.start',{categories:'devtools.timeline,v8,blink,accessibility,blink.user_timing,disabled-by-default-devtools.timeline',transferMode:'ReturnAsStream'});
  await cdp.send('Profiler.start');
  const before=counters((await cdp.send('Performance.getMetrics')).metrics);
  await page.evaluate(label=>console.timeStamp(label),version+':'+phase+':begin');
  const start=performance.now();await action();const wallMsWithProfiling=performance.now()-start;
  await page.evaluate(label=>console.timeStamp(label),version+':'+phase+':end');
  const after=counters((await cdp.send('Performance.getMetrics')).metrics),{profile}=await cdp.send('Profiler.stop');
  const recorded=recordFile(version+'-'+phase+'.cpuprofile',JSON.stringify(profile)),nativeTrace=await saveTrace(cdp,version,phase);
  const counterChanges=Object.fromEntries(Object.entries(after).map(([name,value])=>[name,{before:before[name],after:value,delta:value-before[name]}]));
  const row={version,phase,wallMsWithProfiling,before:beforeState,after:await state(page),counterChanges,cpuProfile:recorded,nativeTrace,sampledFunctions:sampledFunctions(profile)};
  report.phases.push(row);save();return row;
}
report.traceMethod='Native trace X-event durations are clipped to explicit console TimeStamp markers around the action on the same renderer thread. Event durations are inclusive and overlap parents/children; do not sum rows. Performance counters exclude profiler/tracing startup and shutdown, but the action still runs under diagnostic instrumentation.';
report.visibilityControl='Repeat both checkouts after closing the field index through its real UI button. This is a presentation diagnostic on unmodified application bytes, not a replacement for default-open acceptance or its retained material flags.';
let browser;
try{
  assert.ok(process.versions.bun,'Run with Bun');
  for(const name of ['AUTH_LAB_EXPANSION_BASELINE_ROOT','PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE'])assert.ok(process.env[name],'Missing '+name);
  const baselineRoot=path.resolve(process.env.AUTH_LAB_EXPANSION_BASELINE_ROOT),manifest=json(path.join(root,'docs/expansion/plan-manifest.json'));
  report.identity=identity(root);report.baseline={expectedCommit:manifest.baselineCommit,root:baselineRoot,identity:identity(baselineRoot)};
  assert.equal(report.baseline.identity.standalone.sha256,manifest.baselineStandaloneSha256,'Accepted baseline standalone identity');
  const moduleFile=path.resolve(process.env.PLAYWRIGHT_MODULE),playwright=await import(pathToFileURL(moduleFile).href);
  let packageDir=path.dirname(moduleFile);
  while(!fs.existsSync(path.join(packageDir,'package.json'))&&path.dirname(packageDir)!==packageDir)packageDir=path.dirname(packageDir);
  const packageFile=path.join(packageDir,'package.json'),pkg=json(packageFile);
  report.dependency={entry:moduleFile,entrySha256:hash(fs.readFileSync(moduleFile)),packageFile,packageSha256:hash(fs.readFileSync(packageFile)),name:pkg.name,version:pkg.version};
  browser=await playwright.chromium.launch({executablePath:process.env.CHROMIUM_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  report.browser={version:browser.version(),executable:process.env.CHROMIUM_EXECUTABLE};save();
  for(const [version,directory,closeIndex]of [['baseline',baselineRoot,false],['expanded',root,false],['baseline-index-closed',baselineRoot,true],['expanded-index-closed',root,true]]){
    const context=await browser.newContext({viewport:{width:1920,height:1200},bypassCSP:false}),page=await context.newPage(),errors=[];page.setDefaultTimeout(30000);page.on('pageerror',error=>errors.push(String(error)));
    try{
      const target=pathToFileURL(path.join(directory,'dist/auth-flow-studio.html')).href;
      await context.route('**/*',route=>route.request().url()===target?route.continue():route.abort());
      await page.goto(target,{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);await settle(page);
      if(closeIndex){await page.locator('#attribute-index-toggle').click();await settle(page);}
      assert.equal((await state(page)).fieldIndexVisible,!closeIndex,'Idle field-index visibility control');
      const cdp=await context.newCDPSession(page);await cdp.send('Performance.enable');await cdp.send('Profiler.enable');await cdp.send('Profiler.setSamplingInterval',{interval:1000});
      const idle=await profilePhase(cdp,page,version,'idle-search',async()=>{
        await page.locator('#lab-scenario-search').fill('refresh');await page.locator('[data-scenario-option="lab-refresh-rotation"]').waitFor({state:'visible'});await settle(page);
      });
      assert.equal(idle.after.scenario,idle.before.scenario);assert.equal(idle.after.status,idle.before.status,'Idle search must not start or replace the journey');
      await page.locator('[data-scenario-option="lab-refresh-rotation"]').click();await settle(page);
      assert.equal((await state(page)).scenario,'lab-refresh-rotation');
      if(closeIndex&&(await state(page)).fieldIndexVisible){await page.locator('#attribute-index-toggle').click();await settle(page);}
      assert.equal((await state(page)).fieldIndexVisible,!closeIndex,'Playback field-index visibility control');
      const play=await profilePhase(cdp,page,version,'replay-start',async()=>{
        await page.locator('#play').click();await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});await settle(page);
      });
      assert.equal(play.after.status,'playing');
      const search=await profilePhase(cdp,page,version,'playing-search',async()=>{
        await page.locator('#lab-scenario-search').fill('basic');await page.locator('[data-scenario-option="basic-keycloak"]').waitFor({state:'visible'});await settle(page);
      });
      assert.equal(search.after.status,'playing');assert.equal(search.after.scenario,search.before.scenario);assert.equal(search.after.mode,search.before.mode);assert.ok(search.after.elapsed>=search.before.elapsed,'Search cannot reset playback');
      await page.locator('#play').click();assert.equal((await state(page)).status,'paused');assert.deepEqual(errors,[],version+' browser errors');
    }finally{await context.close();}
  }
  assert.deepEqual(identity(root),report.identity,'Expanded source remains unchanged');assert.deepEqual(identity(baselineRoot),report.baseline.identity,'Accepted source remains unchanged');report.identityUnchanged=true;report.passed=true;report.exitCode=0;
}catch(error){report.error=error.stack||String(error);report.exitCode=1;process.exitCode=1;
}finally{if(browser)await browser.close();report.finishedAt=new Date().toISOString();save();}
console.log(JSON.stringify({passed:report.passed,report:filename,error:report.error||null},null,2));
