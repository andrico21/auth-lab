#!/usr/bin/env bun
// Offline native UI collector. No app imports, builds, downloads, or latency instrumentation in compare mode.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';

const HELP=`Usage: bun tools/verification/run-next-expansion-performance.mjs [options]
Required options (all use =VALUE):
  --baseline-root=PATH --candidate-root=PATH
  --baseline-html-sha256=HASH --candidate-html-sha256=HASH
  --out=PATH              New, nonexistent evidence directory, outside both src/assets trees
  --mode=compare|profile  Uninstrumented latency OR separate CDP diagnostic collection
  --samples=N            3..30 fresh contexts per variant/loading mode/index state
Optional: --profile-action=all|startup|idle-filter|selection|replay-start|playing-filter
          (profile mode only; default all)
          --candidate-manifest-sha256=HASH (bind current phase evidence; omitted for historical characterization)
Requires provisioned PLAYWRIGHT_MODULE (Playwright-Core or Playwright entry file),
CHROMIUM_EXECUTABLE and inherited LD_LIBRARY_PATH. Never installs or downloads.
All three loading modes run serially at 1920x1200. Variant order alternates each
sample, reversing its starting order across loading modes and index states.
For baseline characterization, supply the same immutable root/hash on both sides;
the two labels then measure repeatability, not an optimization.
Startup ALWAYS measures normal default readiness, before any index control action.
Open/closed are post-startup interaction controls, never preclosed startup claims.
Each action settles for two requestAnimationFrame callbacks. Cold contexts mean
empty browser cache/storage, not cold OS caches; there is no discarded warmup.
Do not run other browser, build or regression jobs concurrently. Increase samples
when variation is unresolved; thresholds are descriptive project review rules.
Outputs: next-performance-status.json, report-schema.json and bounded raw CDP
artifacts in profile mode. The report retains every action/sample, identities,
logs/errors, medians, variation, material flags and explicit unresolved limits.
Exit 0: complete comparison without material or variation flags, or diagnostic
collection complete (NOT a latency pass). Exit 1: collection/identity/error issue.
Exit 2: complete comparison with material regression or unresolved variation.
Historical seven flags, manual G01 and live/platform acceptance never close here.`;
if(process.argv.includes('--help')||process.argv.includes('-h')){console.log(HELP);process.exit(0);}
const options={};
const allowed=new Set(['baseline-root','candidate-root','baseline-html-sha256','candidate-html-sha256','candidate-manifest-sha256','out','mode','samples','profile-action']);
for(const arg of process.argv.slice(2)){
  const match=/^--([^=]+)=(.+)$/.exec(arg);
  assert.ok(match&&allowed.has(match[1]),'Unknown or malformed option: '+arg+'\n'+HELP);
  assert.ok(!(match[1] in options),'Duplicate option: '+match[1]);options[match[1]]=match[2];
}
for(const key of ['baseline-root','candidate-root','baseline-html-sha256','candidate-html-sha256','out','mode','samples'])assert.ok(options[key],'Missing --'+key+'\n'+HELP);
assert.ok(['compare','profile'].includes(options.mode),'--mode must be compare or profile');
const sampleCount=Number(options.samples);
assert.ok(Number.isInteger(sampleCount)&&sampleCount>=3&&sampleCount<=30,'--samples must be 3..30');
for(const key of ['baseline-html-sha256','candidate-html-sha256'])assert.match(options[key],/^[a-f0-9]{64}$/,'Expected lowercase SHA256 for '+key);
if(options['candidate-manifest-sha256'])assert.match(options['candidate-manifest-sha256'],/^[a-f0-9]{64}$/,'Expected lowercase candidate manifest SHA256');
const actionNames=['startup','idle-filter','selection','replay-start','playing-filter'];
assert.ok(!options['profile-action']||options.mode==='profile','--profile-action requires profile mode');
assert.ok(!options['profile-action']||['all',...actionNames].includes(options['profile-action']),'Unknown profile action');
const rootNames=['baseline','candidate'],roots=Object.fromEntries(rootNames.map(name=>[name,fs.realpathSync(options[name+'-root'])]));
const out=path.resolve(options.out),runner=fileURLToPath(import.meta.url);
// mkdir without recursive on the leaf prevents overwriting or mixing evidence runs.
fs.mkdirSync(path.dirname(out),{recursive:true});
const realParent=fs.realpathSync(path.dirname(out)),realOut=path.join(realParent,path.basename(out));
const within=(root,file)=>file===root||file.startsWith(root+path.sep);
for(const root of Object.values(roots))for(const prefix of ['src','assets','dist'])assert.ok(!within(path.join(root,prefix),realOut),'Evidence must not mutate measured runtime trees');
assert.ok(!Object.values(roots).includes(realOut),'Evidence cannot replace a source root');
fs.mkdirSync(out);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fileIdentity=file=>{const bytes=fs.readFileSync(file);return {bytes:bytes.length,sha256:sha(bytes)};};
const modes=['source-http','standalone-http','standalone-file'];
const viewport={width:1920,height:1200};
const fixture={idleQuery:'refresh',selectedJourney:'lab-refresh-rotation',playingQuery:'basic',playingResult:'basic-keycloak'};
const SCHEMA={schemaVersion:1,kind:'next-expansion-performance',fields:{
  collection:'status=collecting|complete|failed; exitCode 0|1|2. No top-level pass field.',
  identities:'roots baseline/candidate: recursive src/assets plus index/build/package/security-policy input hashes and standalone bytes/hash; runner, runtime, OS, browser executable, Playwright/Core package+entry hashes',
  manifest:'Optional explicitly pinned current-candidate manifest; unchanged throughout collection. Historical characterization may omit it and cannot satisfy a current phase manifest binding.',
  currentMeasurementStatus:'passed|partial|failed for this comparison only; profile mode is unverified for latency. Never closes historical flags, manual G01 or platform limits.',
  samples:'variant, loadingMode, indexControl, sample, order, target, actions[], logs, errors, sourceUnchanged; actions retain before/after state, raw latencyMs ONLY in compare or diagnostic fields ONLY in profile',
  comparisons:'compare only: loadingMode, indexControl (default for startup), action, baseline/candidate {values,min,median,max,rangeMs,rangeOverMedian,mad}, deltaMs, ratio, materialRegression, variationUnresolved',
  profiles:'profile action diagnostic: wallMsWithProfiling, counters, CPU artifact, sampled self functions, marker-bounded trace inclusive attribution; never latency medians',
  files:'relative file, bytes, sha256 for retained CPU/trace artifacts',
  unresolved:'material regressions, variation, collection failures and explicitly unclosed historical/manual/platform limits',
  methods:'fixed UI fixture, cache/order/settling/startup semantics, attribution and thresholds',
  sourceChecks:'before/after hashes each context and final roots/runtime runner unchanged'
},units:{latency:'ms, includes Playwright action/readiness round trips',cpu:'sampled self ms',trace:'inclusive overlapping ms, clipped to same renderer thread markers',chromeCounters:'native CDP units (durations seconds, heap bytes)'},materialRule:{relativeIncreaseGreaterThan:0.25,startupAbsoluteIncreaseGreaterThanMs:100,interactionAbsoluteIncreaseGreaterThanMs:50},variationRule:'Unresolved when (max-min)/median > 0.25 AND range > corresponding absolute material threshold on either variant. Descriptive instability heuristic, not statistical significance. Add samples and inspect raw distribution.'};
Object.assign(SCHEMA,{
  $schema:'https://json-schema.org/draft/2020-12/schema',
  title:'Auth Flow Studio next expansion performance report',
  type:'object',
  required:['schemaVersion','kind','mode','status','nativeBrowser','argv','runner','runtime','environment','scope','methods','identities','samples','comparisons','files','errors','sourceChecks','unresolved'],
  not:{required:['passed']},
  properties:{
    schemaVersion:{const:1},kind:{const:'next-expansion-performance'},mode:{enum:['compare','profile']},
    status:{enum:['collecting','complete','failed']},nativeBrowser:{const:true},exitCode:{enum:[0,1,2]},
    argv:{type:'array',items:{type:'string'}},runner:{type:'object'},runtime:{type:'object'},environment:{type:'object'},scope:{type:'object'},methods:{type:'object'},identities:{type:'object'},
    samples:{type:'array',items:{$ref:'#/$defs/sample'}},
    comparisons:{type:'array',items:{$ref:'#/$defs/comparison'}},
    files:{type:'array',items:{$ref:'#/$defs/artifact'}},
    errors:{type:'array'},unresolved:{type:'array',items:{type:'object',required:['kind']}},
    sourceChecks:{type:'array',items:{type:'object',required:['label','variant','unchanged']}},
    latencyDisposition:{enum:['not-measured-in-diagnostic-mode','incomplete','review-required','no-current-material-or-variation-flags']}
  },
  allOf:[{if:{properties:{mode:{const:'profile'}}},then:{properties:{comparisons:{maxItems:0},samples:{items:{properties:{actions:{items:{not:{required:['latencyMs']}}}}}}}}}],
  $defs:{
    artifact:{type:'object',required:['file','bytes','sha256'],properties:{file:{type:'string'},bytes:{type:'integer',minimum:0},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}}},
    stats:{type:'object',required:['values','min','median','max','rangeMs','rangeOverMedian','mad'],properties:{values:{type:'array',minItems:3,items:{type:'number',minimum:0}},min:{type:'number'},median:{type:'number'},max:{type:'number'},rangeMs:{type:'number'},rangeOverMedian:{type:['number','null']},mad:{type:'number'}}},
    action:{type:'object',required:['name','ui','before'],properties:{name:{enum:actionNames},ui:{type:'object'},sequence:{type:'integer',minimum:1},before:{type:['object','null']},after:{type:'object'},latencyMs:{type:'number',minimum:0},wallMsWithProfiling:{type:'number',minimum:0},cpuProfile:{$ref:'#/$defs/artifact'},nativeTrace:{type:'object'},sampledFunctions:{type:'array'},error:{type:'string'},complete:{type:'boolean'}}},
    sample:{type:'object',required:['variant','loadingMode','indexControl','sample','order','target','actions','controls','uiSequence','logs','errors'],properties:{variant:{enum:rootNames},loadingMode:{enum:modes},indexControl:{enum:['open','closed']},sample:{type:'integer',minimum:0},order:{enum:[0,1]},target:{type:'string'},actions:{type:'array',maxItems:5,items:{$ref:'#/$defs/action'}},controls:{type:'array'},uiSequence:{type:'array'},logs:{type:'object'},errors:{type:'array'},actionCounts:{type:'object'},sourceUnchanged:{type:'boolean'},complete:{type:'boolean'}}},
    comparison:{type:'object',required:['loadingMode','indexControl','action','baseline','candidate','deltaMs','ratio','materialRegression','variationUnresolved'],properties:{loadingMode:{enum:modes},indexControl:{enum:['default','open','closed']},action:{enum:actionNames},baseline:{$ref:'#/$defs/stats'},candidate:{$ref:'#/$defs/stats'},deltaMs:{type:'number'},ratio:{type:['number','null']},materialRegression:{type:'boolean'},variationUnresolved:{type:'boolean'}}}
  }
});
fs.writeFileSync(path.join(out,'report-schema.json'),JSON.stringify(SCHEMA,null,2)+'\n');
const report={schemaVersion:1,kind:'next-expansion-performance',mode:options.mode,startedAt:new Date().toISOString(),status:'collecting',nativeBrowser:true,argv:[process.execPath,...process.argv.slice(1)],runner:{path:runner,...fileIdentity(runner)},runtime:{executable:process.execPath,...fileIdentity(process.execPath),version:process.version,bun:process.versions.bun||null,versions:process.versions,platform:process.platform,arch:process.arch,osRelease:os.release(),cpuModel:os.cpus()[0]?.model,logicalCpus:os.cpus().length},environment:Object.fromEntries(['PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE','LD_LIBRARY_PATH'].map(name=>[name,process.env[name]||null])),scope:{roots,modes,viewport,sampleCount,indexControls:['open','closed'],fixture,profileAction:options['profile-action']||'all'},methods:{
  startup:'goto start to DOMContentLoaded, real custom-element heldView/player/steps/picker readiness, visible Play and search controls, then two rAF. Always normal default; index state recorded before any control action. Repeated for both post-startup index controls, yielding 2*N default-startup samples per variant/mode.',
  actions:'Real fill/click, required visible matching result or selected journey/positive playback progress, then two rAF. Index state changed ONLY via #index-open or #attribute-index-toggle outside timed actions, reasserted after selection. Filtering cannot replace journey or reset/change playback mode/status.',
  caches:'Fresh isolated serial contexts; no warmup discarded; empty context HTTP cache/storage, no claim of cold OS filesystem or process/JIT caches. One shared serial browser. Routing is equal in both variants and disables browser HTTP cache.',
  ordering:'Alternate baseline/candidate starting order on sample parity plus loading-mode/index-control parity; no concurrent contexts or acceptance workers.',
  comparison:'No CDP session, tracing, init scripts or performance observers in compare mode. All observed latency values are retained; no instrumented profile duration enters comparisons.',
  profiling:'Separate run with CDP Performance counters, 1 ms CPU samples and streamed traces. Startup begin marker is injected at document creation, not navigation start; diagnostic startup excludes navigation before document creation. Other markers bound actual UI actions. Trace X events clipped to marker window on same renderer thread; inclusive rows overlap and must not be summed.',
  bounds:'At most 200 entries per console/request/CSP log; truncation is unresolved. At most 64 MiB per raw artifact and 512 MiB total, including partial traces; exceeding a cap fails collection rather than silently losing attribution. No heap snapshots or screenshots.',
  materialRule:SCHEMA.materialRule,variationRule:SCHEMA.variationRule
},identities:{},samples:[],comparisons:[],files:[],errors:[],sourceChecks:[],unresolved:[
  {kind:'historical',message:'Seven predecessor performance flags on 92ab17825e1a410940edc7b52a4a1a2f8f7e252c3dd340499a7ce420e3775775 remain open; this incremental comparison does not reproduce or clear them.'},
  {kind:'manual',message:'G01 real assistive-technology speech/comprehension is not performed or established by this collector.'},
  {kind:'platform',message:'Chromium UI evidence only, not cross-engine, native protocol/platform interoperability or live authentication acceptance.'},
  {kind:'scope',message:'Six disclosed sibling-key-origin omissions remain outside this performance collector; accepted WIN-11 and the 23 prior scoped closures are not rechecked here.'}
]};
const save=()=>fs.writeFileSync(path.join(out,'next-performance-status.json'),JSON.stringify(report,null,2)+'\n');
function sourceIdentity(root){
  const names=['index.html','build.mjs','package.json'];
  for(const directory of ['src','assets','dist'])assert.equal(fs.realpathSync(path.join(root,directory)),path.join(root,directory),'Runtime directory cannot follow a symlink: '+directory);
  if(fs.existsSync(path.join(root,'security-policy.mjs')))names.push('security-policy.mjs');
  function walk(relative){
    for(const entry of fs.readdirSync(path.join(root,relative),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
      const name=relative+'/'+entry.name;
      assert.ok(!entry.isSymbolicLink(),'Measured input cannot be a symlink: '+name);
      if(entry.isDirectory())walk(name);else {assert.ok(entry.isFile(),'Expected regular source file: '+name);names.push(name);}
    }
  }
  walk('src');walk('assets');walk('tests');
  const sources=Object.fromEntries(names.sort().map(name=>{assert.ok(!fs.lstatSync(path.join(root,name)).isSymbolicLink(),'No symlink input');return [name,fileIdentity(path.join(root,name))];}));
  const html=path.join(root,'dist/auth-flow-studio.html');assert.ok(!fs.lstatSync(html).isSymbolicLink(),'No standalone symlink');
  const canonicalSourceFiles=Object.fromEntries(Object.entries(sources).map(([name,value])=>[name,value.sha256]));
  return {sourceSnapshotSha256:sha(JSON.stringify(sources)),canonicalSourceFiles,sources,standalone:fileIdentity(html)};
}
function checkSources(label){
  for(const variant of rootNames){
    const current=sourceIdentity(roots[variant]),unchanged=JSON.stringify(current)===JSON.stringify(report.identities[variant]);
    report.sourceChecks.push({label,variant,at:new Date().toISOString(),unchanged,sourceSnapshotSha256:current.sourceSnapshotSha256,standaloneSha256:current.standalone.sha256});
    assert.ok(unchanged,variant+' source/HTML bytes changed during '+label);
  }
  assert.deepEqual(fileIdentity(runner),{bytes:report.runner.bytes,sha256:report.runner.sha256},'Runner bytes changed');
  if(report.manifest)assert.deepEqual(fileIdentity(report.manifest.path),{bytes:report.manifest.bytes,sha256:report.manifest.sha256},'Candidate manifest bytes changed');
}
function packageIdentity(entry){
  let directory=path.dirname(entry);
  while(!fs.existsSync(path.join(directory,'package.json'))&&path.dirname(directory)!==directory)directory=path.dirname(directory);
  const filename=path.join(directory,'package.json'),pkg=JSON.parse(fs.readFileSync(filename,'utf8'));
  return {entry,...fileIdentity(entry),packageFile:filename,packageIdentity:fileIdentity(filename),name:pkg.name,version:pkg.version};
}
async function serve(){
  // Only runtime input files, never .git, evidence, dependency trees or arbitrary paths.
  const server=http.createServer((request,response)=>{
    try{
      const url=new URL(request.url,'http://127.0.0.1'),parts=decodeURIComponent(url.pathname).split('/');
      const variant=parts[1],root=roots[variant];let relative=parts.slice(2).join('/');if(!relative)relative='index.html';
      if(!['GET','HEAD'].includes(request.method)){response.writeHead(405);response.end();return;}
      if(!root||(!Object.hasOwn(report.identities[variant].sources,relative)&&relative!=='dist/auth-flow-studio.html')){response.writeHead(404);response.end();return;}
      const file=path.join(root,relative),real=fs.realpathSync(file);
      if(!within(root,real)||real!==file||!fs.statSync(real).isFile()){response.writeHead(403);response.end();return;}
      response.writeHead(200,{'Content-Type':{'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
      if(request.method==='HEAD')response.end();else fs.createReadStream(real).on('error',()=>response.destroy()).pipe(response);
    }catch{response.writeHead(400);response.end();}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return server;
}
const settle=page=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
async function state(page){return page.evaluate(()=>{
  const a=document.querySelector('auth-flow-studio'),index=a.refs['attribute-index'];
  return {scenario:a.labScenarioId,status:a.player.status,elapsed:a.player.elapsed,kind:a.player.kind,sourceStep:a.steps[a.index]?.id,indexVisible:!index.hidden&&!!index.getClientRects().length,fieldRows:a.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]').length,liveNodes:document.querySelectorAll('*').length,query:a.querySelector('#lab-scenario-search').value,activeElement:document.activeElement?.id,scroll:{x:scrollX,y:scrollY}};
});}
function uiEvent(row,event){
  const recorded={sequence:row.uiSequence.length+1,at:new Date().toISOString(),...event};
  row.uiSequence.push(recorded);return recorded;
}
async function setIndex(page,open,row){
  const before=await state(page);
  if(before.indexVisible!==open){
    const selector=open?'#index-open':'#attribute-index-toggle',control=uiEvent(row,{action:'click',selector,purpose:'set index '+(open?'open':'closed')});
    row.controls.push(control);control.before=before;await page.locator(selector).click();await settle(page);control.after=await state(page);
  }
  assert.equal((await state(page)).indexVisible,open,'Actual index control state');
}
const threshold=action=>action==='startup'?100:50;
const metrics=values=>Object.fromEntries(values.filter(value=>['Nodes','LayoutDuration','RecalcStyleDuration','ScriptDuration','TaskDuration','JSHeapUsedSize','LayoutCount','RecalcStyleCount'].includes(value.name)).map(value=>[value.name,value.value]));
function sampledFunctions(profile){
  const weights=new Map(),hits=new Map(),timingValid=Array.isArray(profile.timeDeltas)&&profile.timeDeltas.length===profile.samples?.length&&profile.timeDeltas.every(delta=>Number.isFinite(delta)&&delta>=0);
  for(let i=0;i<(profile.samples||[]).length;i++){const id=profile.samples[i];if(timingValid)weights.set(id,(weights.get(id)||0)+profile.timeDeltas[i]);hits.set(id,(hits.get(id)||0)+1);}
  return profile.nodes.filter(node=>hits.has(node.id)).map(node=>({functionName:node.callFrame.functionName||'(anonymous)',url:node.callFrame.url,line:node.callFrame.lineNumber+1,column:node.callFrame.columnNumber+1,sampledSelfMs:timingValid?weights.get(node.id)/1000:null,timingValid,sampleCount:hits.get(node.id)})).sort((a,b)=>timingValid?b.sampledSelfMs-a.sampledSelfMs:b.sampleCount-a.sampleCount).slice(0,30);
}
const MAX_FILE=64*1024*1024,MAX_TOTAL=512*1024*1024;let artifactBytes=0;
function recordFile(filename,bytes){
  assert.ok(bytes.length<=MAX_FILE&&artifactBytes+bytes.length<=MAX_TOTAL,'Raw artifact byte cap exceeded');
  fs.writeFileSync(path.join(out,filename),bytes);artifactBytes+=bytes.length;
  const item={file:filename,bytes:bytes.length,sha256:sha(bytes)};report.files.push(item);return item;
}
async function stopTrace(cdp,token){
  const complete=new Promise(resolve=>cdp.once('Tracing.tracingComplete',resolve));await cdp.send('Tracing.end');
  const {stream}=await complete;let size=0;const chunks=[];
  try{
    for(;;){const part=await cdp.send('IO.read',{handle:stream,size:1024*1024}),bytes=Buffer.from(part.data,part.base64Encoded?'base64':'utf8');
      if(size+bytes.length>MAX_FILE||artifactBytes+size+bytes.length>MAX_TOTAL){if(size)recordFile(token+'.trace.partial',Buffer.concat(chunks));throw new Error('Trace cap exceeded; retained bounded partial artifact');}
      chunks.push(bytes);size+=bytes.length;if(part.eof)break;
    }
  }finally{await cdp.send('IO.close',{handle:stream});}
  const bytes=Buffer.concat(chunks),file=recordFile(token+'.trace.json',bytes),events=JSON.parse(bytes.toString('utf8')).traceEvents;
  const begin=events.find(event=>event.name==='TimeStamp'&&event.args?.data?.message===token+':begin');
  const end=events.find(event=>event.name==='TimeStamp'&&event.args?.data?.message===token+':end');
  assert.ok(begin&&end&&begin.pid===end.pid&&begin.tid===end.tid&&end.ts>=begin.ts,'Same-renderer-thread action trace markers');
  const totals=new Map();
  for(const event of events){
    if(event.ph!=='X'||event.pid!==begin.pid||event.tid!==begin.tid||!Number.isFinite(event.dur))continue;
    const duration=Math.max(0,Math.min(event.ts+event.dur,end.ts)-Math.max(event.ts,begin.ts));if(!duration)continue;
    const item=totals.get(event.name)||{name:event.name,inclusiveMs:0,count:0};item.inclusiveMs+=duration/1000;item.count++;totals.set(event.name,item);
  }
  return {file,actionWindowMs:(end.ts-begin.ts)/1000,pid:begin.pid,tid:begin.tid,events:[...totals.values()].sort((a,b)=>b.inclusiveMs-a.inclusiveMs).slice(0,35)};
}
async function action(row,page,cdp,name,run){
  const record={name,ui:name==='startup'?{action:'navigate',target:row.target}:name==='selection'?{action:'click',selector:'[data-scenario-option="'+fixture.selectedJourney+'"]'}:name==='replay-start'?{action:'click',selector:'#play'}:{action:'fill',selector:'#lab-scenario-search',value:name==='idle-filter'?fixture.idleQuery:fixture.playingQuery},before:name==='startup'?null:await state(page)};
  row.actions.push(record);
  record.sequence=uiEvent(row,{phase:name,...record.ui}).sequence;
  const profiled=cdp&&(report.scope.profileAction==='all'||report.scope.profileAction===name);
  const token=[row.variant,row.loadingMode,row.indexControl,row.sample,name].join('-');
  let initScript;
  try{
    if(profiled){
      await cdp.send('Tracing.start',{categories:'devtools.timeline,v8,blink,accessibility,blink.user_timing,disabled-by-default-devtools.timeline',transferMode:'ReturnAsStream'});
      await cdp.send('Profiler.start');record.countersBefore=metrics((await cdp.send('Performance.getMetrics')).metrics);
      if(name==='startup')initScript=await page.addInitScript(label=>console.timeStamp(label),token+':begin');
      else await page.evaluate(label=>console.timeStamp(label),token+':begin');
    }
    const start=performance.now();await run();const duration=performance.now()-start;
    if(options.mode==='compare')record.latencyMs=duration;
    if(profiled){
      record.wallMsWithProfiling=duration;await page.evaluate(label=>console.timeStamp(label),token+':end');
      const after=metrics((await cdp.send('Performance.getMetrics')).metrics),{profile}=await cdp.send('Profiler.stop');
      record.counterChanges=Object.fromEntries(Object.entries(after).map(([key,value])=>[key,{before:record.countersBefore[key],after:value,delta:value-record.countersBefore[key]}]));
      record.cpuProfile=recordFile(token+'.cpuprofile',Buffer.from(JSON.stringify(profile)));
      record.nativeTrace=await stopTrace(cdp,token);record.sampledFunctions=sampledFunctions(profile);
    }
    record.after=await state(page);record.complete=true;
  }catch(error){record.error=error.stack||String(error);throw error;}
  // The startup init script applies only to this single-navigation, disposable page.
  void initScript;save();return record;
}
function retain(list,item,row){if(list.length<200)list.push(item);else row.logsTruncated=true;}
async function collect(browser,origin,variant,loadingMode,indexControl,sample,order){
  checkSources('before '+[variant,loadingMode,indexControl,sample].join('/'));
  const target=loadingMode==='standalone-file'?pathToFileURL(path.join(roots[variant],'dist/auth-flow-studio.html')).href:origin+'/'+variant+'/'+(loadingMode==='source-http'?'':'dist/auth-flow-studio.html');
  const row={variant,loadingMode,indexControl,sample,order,target,startedAt:new Date().toISOString(),actions:[],controls:[],uiSequence:[],logs:{console:[],requestsFailed:[],externalRequests:[],httpErrors:[],csp:[]},errors:[]};report.samples.push(row);save();
  let context;
  try{
    context=await browser.newContext({viewport,bypassCSP:false,serviceWorkers:'block',reducedMotion:'no-preference'});
    const page=await context.newPage();page.setDefaultTimeout(60000);page.setDefaultNavigationTimeout(60000);
    page.on('console',message=>retain(row.logs.console,{type:message.type(),text:message.text().slice(0,4000)},row));
    page.on('pageerror',error=>retain(row.errors,String(error.stack||error).slice(0,8000),row));
    page.on('requestfailed',request=>retain(row.logs.requestsFailed,{url:request.url().slice(0,2000),failure:request.failure()},row));
    page.on('response',response=>{if(response.status()>=400)retain(row.logs.httpErrors,{url:response.url().slice(0,2000),status:response.status()},row);});
    // CSP failures also appear as native console errors; no init script is installed in compare mode.
    page.on('console',message=>{if(/content security policy|violates.*directive/i.test(message.text()))retain(row.logs.csp,message.text().slice(0,4000),row);});
    await context.route('**/*',route=>{
      const url=route.request().url();let permitted=url===target;
      if(loadingMode==='source-http')try{const parsed=new URL(url),relative=decodeURIComponent(parsed.pathname).slice(('/'+variant+'/').length)||'index.html';permitted=parsed.origin===origin&&parsed.pathname.startsWith('/'+variant+'/')&&Object.hasOwn(report.identities[variant].sources,relative);}catch{}
      if(permitted)return route.continue();retain(row.logs.externalRequests,url.slice(0,2000),row);return route.abort();
    });
    let cdp;
    if(options.mode==='profile'){cdp=await context.newCDPSession(page);await cdp.send('Performance.enable');await cdp.send('Profiler.enable');await cdp.send('Profiler.setSamplingInterval',{interval:1000});}
    const startup=await action(row,page,cdp,'startup',async()=>{
      await page.goto(target,{waitUntil:'domcontentloaded'});
      await page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.heldView&&a.player&&a.steps?.length&&a.scenarioPicker;});
      await page.locator('#play').waitFor({state:'visible'});await page.locator('#lab-scenario-search').waitFor({state:'visible'});await settle(page);
    });
    row.defaultIndexVisible=startup.after.indexVisible;
    await setIndex(page,indexControl==='open',row);
    const idle=await action(row,page,cdp,'idle-filter',async()=>{
      await page.locator('#lab-scenario-search').fill(fixture.idleQuery);
      await page.locator('[data-scenario-option="'+fixture.selectedJourney+'"]').waitFor({state:'visible'});await settle(page);
    });
    for(const key of ['scenario','status','kind','elapsed'])assert.equal(idle.after[key],idle.before[key],'Idle filter preserves '+key);
    await action(row,page,cdp,'selection',async()=>{
      await page.locator('[data-scenario-option="'+fixture.selectedJourney+'"]').click();
      await page.waitForFunction(id=>document.querySelector('auth-flow-studio').labScenarioId===id,fixture.selectedJourney);await settle(page);
    });
    assert.equal((await state(page)).scenario,fixture.selectedJourney);
    await setIndex(page,indexControl==='open',row);
    const replay=await action(row,page,cdp,'replay-start',async()=>{
      await page.locator('#play').click();await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});await settle(page);
    });
    assert.equal(replay.after.status,'playing');
    const playing=await action(row,page,cdp,'playing-filter',async()=>{
      await page.locator('#lab-scenario-search').fill(fixture.playingQuery);
      await page.locator('[data-scenario-option="'+fixture.playingResult+'"]').waitFor({state:'visible'});await settle(page);
    });
    assert.equal(playing.after.status,'playing');
    for(const key of ['scenario','kind'])assert.equal(playing.after[key],playing.before[key],'Playback filter preserves '+key);
    assert.ok(playing.after.elapsed>=playing.before.elapsed,'Playback filter cannot rewind');
    for(const result of row.actions.filter(result=>result.name!=='startup'))assert.equal(result.after.indexVisible,indexControl==='open','Action retains intended field index visibility');
    const pause=uiEvent(row,{action:'click',selector:'#play',purpose:'pause after measurements'});row.controls.push(pause);
    await page.locator('#play').click();assert.equal((await state(page)).status,'paused');pause.after=await state(page);
    assert.deepEqual(row.errors,[],'No page errors');assert.deepEqual(row.logs.csp,[],'No CSP violations');assert.deepEqual(row.logs.externalRequests,[],'No out-of-scope network requests');assert.deepEqual(row.logs.httpErrors,[],'No HTTP errors');assert.deepEqual(row.logs.requestsFailed,[],'No failed resource requests');
    assert.ok(!row.logs.console.some(message=>message.type==='error'),'No console errors');assert.ok(!row.logsTruncated,'Raw logs exceeded cap');
    row.complete=true;
  }catch(error){row.error=error.stack||String(error);report.errors.push({variant,loadingMode,indexControl,sample,error:row.error});}
  finally{
    if(context)await context.close().catch(error=>report.errors.push({phase:'context-close',error:String(error)}));
    try{checkSources('after '+[variant,loadingMode,indexControl,sample].join('/'));row.sourceUnchanged=true;}catch(error){row.sourceUnchanged=false;report.errors.push({phase:'source-integrity',error:error.stack||String(error)});}
    row.actionCounts={phases:row.actions.length,completedPhases:row.actions.filter(item=>item.complete).length,ui:row.uiSequence.length,byAction:Object.fromEntries(['navigate','fill','click'].map(name=>[name,row.uiSequence.filter(item=>item.action===name).length])),indexControls:row.controls.filter(item=>item.purpose?.startsWith('set index')).length};
    row.finishedAt=new Date().toISOString();save();
  }
  // A changed source or unbounded artifact is not a meaningful comparison input.
  assert.ok(row.sourceUnchanged,'Source mutation stops further collection');
  assert.ok(options.mode!=='profile'||row.complete,'Diagnostic failure stops further contexts to prevent tracing-state contamination');
  assert.ok(artifactBytes<MAX_TOTAL,'Artifact cap stops further collection');
}
function stats(values){
  assert.ok(values.length&&values.every(Number.isFinite),'Finite timing sample set');
  const sorted=[...values].sort((a,b)=>a-b),medianOf=array=>array.length%2?array[(array.length-1)/2]:(array[array.length/2-1]+array[array.length/2])/2;
  const median=medianOf(sorted),rangeMs=sorted.at(-1)-sorted[0];
  return {values,min:sorted[0],median,max:sorted.at(-1),rangeMs,rangeOverMedian:median?rangeMs/median:null,mad:medianOf(sorted.map(value=>Math.abs(value-median)).sort((a,b)=>a-b))};
}
function compare(){
  for(const loadingMode of modes)for(const name of actionNames)for(const indexControl of name==='startup'?['default']:['open','closed']){
    const distributions={};
    for(const variant of rootNames){
      const values=report.samples.filter(row=>row.complete&&row.variant===variant&&row.loadingMode===loadingMode&&(name==='startup'||row.indexControl===indexControl)).flatMap(row=>row.actions.filter(action=>action.name===name).map(action=>action.latencyMs));
      const expected=sampleCount*(name==='startup'?2:1);
      if(values.length!==expected){report.unresolved.push({kind:'incomplete-cell',variant,loadingMode,indexControl,action:name,expected,observed:values.length});continue;}
      distributions[variant]=stats(values);
    }
    if(!distributions.baseline||!distributions.candidate)continue;
    const {baseline,candidate}=distributions,deltaMs=candidate.median-baseline.median,ratio=baseline.median?candidate.median/baseline.median:null;
    const materialRegression=ratio!==null&&ratio>1.25&&deltaMs>threshold(name);
    const variationUnresolved=[baseline,candidate].some(distribution=>distribution.rangeOverMedian>0.25&&distribution.rangeMs>threshold(name));
    const row={loadingMode,indexControl,action:name,baseline,candidate,deltaMs,ratio,materialRegression,variationUnresolved};report.comparisons.push(row);
    if(materialRegression)report.unresolved.push({kind:'material-regression',loadingMode,indexControl,action:name,deltaMs,ratio});
    if(variationUnresolved)report.unresolved.push({kind:'variation',loadingMode,indexControl,action:name,message:'Add samples/inspect distribution; no statistical significance claimed.'});
  }
}
let browser,server;
save();
try{
  assert.ok(process.versions.bun,'Run with Bun');
  for(const name of ['PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE'])assert.ok(process.env[name],'Missing '+name);
  for(const variant of rootNames){report.identities[variant]=sourceIdentity(roots[variant]);assert.equal(report.identities[variant].standalone.sha256,options[variant+'-html-sha256'],variant+' expected standalone hash');}
  if(options['candidate-manifest-sha256']){
    const file=path.join(roots.candidate,'docs/next-expansion/scenario-manifest.json');
    assert.equal(fs.realpathSync(file),file,'Candidate manifest cannot follow a symlink');
    report.manifest={path:file,...fileIdentity(file)};
    assert.equal(report.manifest.sha256,options['candidate-manifest-sha256'],'Expected current candidate manifest');
  }
  report.sameInputCharacterization=roots.baseline===roots.candidate;
  const entry=fs.realpathSync(process.env.PLAYWRIGHT_MODULE),require=createRequire(import.meta.url);
  report.dependencies={playwright:packageIdentity(entry)};
  const core=report.dependencies.playwright.name==='playwright-core'?entry:require.resolve('playwright-core',{paths:[path.dirname(entry)]});
  report.dependencies.playwrightCore=packageIdentity(core);
  const playwright=await import(pathToFileURL(entry).href),chromium=playwright.chromium||playwright.default?.chromium;
  assert.ok(chromium,'PLAYWRIGHT_MODULE must export chromium');
  const executable=fs.realpathSync(process.env.CHROMIUM_EXECUTABLE);
  report.browser={engine:'chromium',executable,...fileIdentity(executable),launchArgs:['--no-sandbox','--disable-dev-shm-usage'],sandbox:'Disabled for provisioned local Chromium; synthetic loopback/file inputs only.'};
  server=await serve();const origin='http://127.0.0.1:'+server.address().port;report.server={origin,bind:'127.0.0.1',ephemeral:true,allowedFiles:'Runtime source manifest and exact standalone only'};
  browser=await chromium.launch({executablePath:executable,headless:true,args:report.browser.launchArgs});report.browser.version=browser.version();save();
  for(let modeIndex=0;modeIndex<modes.length;modeIndex++)for(let indexIndex=0;indexIndex<2;indexIndex++)for(let sample=0;sample<sampleCount;sample++){
    const variants=(sample+modeIndex+indexIndex)%2?[...rootNames].reverse():rootNames;
    for(let order=0;order<variants.length;order++)await collect(browser,origin,variants[order],modes[modeIndex],['open','closed'][indexIndex],sample,order);
  }
  if(options.mode==='compare')compare();
  report.collectionComplete=report.samples.length===modes.length*2*sampleCount*2&&report.samples.every(row=>row.complete&&row.sourceUnchanged);
  assert.ok(report.collectionComplete&&report.errors.length===0,'One or more samples failed; see raw samples and errors');
  const defaultStates=Object.fromEntries(rootNames.map(variant=>[variant,[...new Set(report.samples.filter(row=>row.variant===variant).map(row=>row.defaultIndexVisible))]]));
  report.defaultIndexStates=defaultStates;
  if(defaultStates.baseline.length!==1||defaultStates.candidate.length!==1||JSON.stringify(defaultStates.baseline)!==JSON.stringify(defaultStates.candidate))report.unresolved.push({kind:'default-startup-semantics',message:'Baseline/candidate default index differs or is unstable; startup is not an equivalent presentation. Hiding the default index is not an optimization acceptance.'});
  report.status='complete';
}catch(error){report.status='failed';report.errors.push({phase:'collection',error:error.stack||String(error)});}
finally{
  if(browser)await browser.close().catch(error=>report.errors.push({phase:'browser-close',error:String(error)}));
  if(server)await new Promise(resolve=>server.close(resolve));
  if(rootNames.every(variant=>report.identities[variant]))try{checkSources('final');report.identityUnchanged=true;}catch(error){report.identityUnchanged=false;report.errors.push({phase:'final-identity',error:error.stack||String(error)});}
  report.actionCounts={samples:report.samples.length,completedSamples:report.samples.filter(row=>row.complete).length,phases:report.samples.reduce((sum,row)=>sum+(row.actionCounts?.phases||0),0),ui:report.samples.reduce((sum,row)=>sum+(row.actionCounts?.ui||0),0)};
  if(report.errors.length)report.status='failed';
  report.latencyDisposition=options.mode==='profile'?'not-measured-in-diagnostic-mode':report.status!=='complete'?'incomplete':report.unresolved.some(item=>['material-regression','variation','default-startup-semantics'].includes(item.kind))?'review-required':'no-current-material-or-variation-flags';
  report.exitCode=report.status==='failed'?1:report.latencyDisposition==='review-required'?2:0;process.exitCode=report.exitCode;
  report.currentMeasurementStatus=report.status==='failed'?'failed':options.mode==='profile'?'unverified':report.exitCode===2?'partial':'passed';
  report.finishedAt=new Date().toISOString();save();
}
console.log(JSON.stringify({status:report.status,currentMeasurementStatus:report.currentMeasurementStatus,latencyDisposition:report.latencyDisposition,exitCode:report.exitCode,report:path.join(out,'next-performance-status.json'),samples:report.samples.length,materialFlags:report.comparisons.filter(row=>row.materialRegression).length,variationFlags:report.comparisons.filter(row=>row.variationUnresolved).length,errors:report.errors.length},null,2));
