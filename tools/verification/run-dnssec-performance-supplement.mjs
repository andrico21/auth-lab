#!/usr/bin/env bun
// Native UI evidence only. No app imports, dependency installation or acceptance inference.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
const HELP=`Usage: bun tools/verification/run-dnssec-performance-supplement.mjs --baseline-root=PATH --candidate-root=PATH --baseline-html-sha256=HASH --candidate-html-sha256=HASH --worksheet=FILE --out=NEW_DIR --samples=3
All options require =VALUE. Samples is exactly 3. Requires provisioned PLAYWRIGHT_MODULE, CHROMIUM_EXECUTABLE and inherited LD_LIBRARY_PATH. No installs/builds.
Runs source-http, standalone-http, standalone-file serially at 1920x1200; fresh contexts, alternating variants, no discarded warmups/outliers. Common legacy selection is preparation; seek is timed. Candidate-only DNS lesson/case selection and seek are timed separately. Each measured action ends after two RAF and observed UI readback. Timing includes automation round trips.
Only after all latency contexts close, separate CDP contexts measure GC-stabilized heap/DOM growth at 0/3/6/12 cycles. DNS warmup visits all five representatives before checkpoint zero. No latency CDP instrumentation. Diagnostic durations are never latency samples.
Outputs dnssec-performance-supplement-status.json and report-schema.json. Raw actions/checkpoints/logs, artifact bytes/hashes, identities before/after and descriptive medians/ranges/MAD retained. Exit 0 means collection complete ONLY; 1 means collection/identity/UI/prerequisite failure. No regression threshold or memory-leak pass, historical performance/manual G01/native/live gates remain open. Do not run concurrent browser/build/regression work.`;
if(process.argv.includes('--help')){console.log(HELP);process.exit(0);}
const keys=['baseline-root','candidate-root','baseline-html-sha256','candidate-html-sha256','worksheet','out','samples'],opt={};
for(const arg of process.argv.slice(2)){const m=/^--([^=]+)=(.+)$/.exec(arg);assert.ok(m&&keys.includes(m[1]),'Malformed option '+arg);assert.ok(!Object.hasOwn(opt,m[1]),'Duplicate option');opt[m[1]]=m[2];}
for(const k of keys)assert.ok(opt[k],'Missing --'+k+'\n'+HELP);
assert.equal(opt.samples,'3','Exactly three fresh samples are required');
for(const v of ['baseline','candidate'])assert.match(opt[v+'-html-sha256'],/^[a-f0-9]{64}$/);
const out=path.resolve(opt.out),within=(a,b)=>b===a||b.startsWith(a+path.sep);
fs.mkdirSync(path.dirname(out),{recursive:true});
const realOut=path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
// Prohibit output under either input root, including unknown/missing runtime subtrees.
for(const v of ['baseline','candidate'])assert.ok(!within(path.resolve(opt[v+'-root']),realOut),'Output must be outside input roots');
fs.mkdirSync(out);
const sha=b=>createHash('sha256').update(b).digest('hex');
function digest(file){assert.ok(!fs.lstatSync(file).isSymbolicLink(),'Symlink input: '+file);const b=fs.readFileSync(file);return {bytes:b.length,sha256:sha(b)};}
const runner=fileURLToPath(import.meta.url),variants=['baseline','candidate'],modes=['source-http','standalone-http','standalone-file'];
const report={schemaVersion:1,kind:'dnssec-performance-supplement',status:'collecting',startedAt:new Date().toISOString(),argv:process.argv,author:'Kirill / andrico21',environment:Object.fromEntries(['PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE','LD_LIBRARY_PATH'].map(k=>[k,process.env[k]??null])),runtime:{executable:process.execPath,versions:process.versions,platform:process.platform,arch:process.arch,osRelease:os.release()},methods:{viewport:{width:1920,height:1200},samples:3,modes,latency:'Serial fresh contexts, alternating variants by sample plus mode parity; no discarded samples. Actual UI select and native range keyboard End; two RAF then state readback included in wall milliseconds. No CDP sessions in latency contexts.',legacy:'lab-refresh-rotation; initial seek 0, measured seek 1000. Legacy select is untimed preparation.',dns:'Candidate-only five representatives; deterministic rotation by sample, separate selection and end seek measurements; actual default named case recorded.',memory:'Separate phase only after all latency work. Fresh context for each mode/variant/family; warm each fixture once, then checkpoint zero. Each cycle selects each family fixture, seeks End then Home. CDP HeapProfiler.collectGarbage twice before Runtime.getHeapUsage and Memory.getDOMCounters at 0/3/6/12 cycles. Not a memory-leak test.',limits:'Chromium only; empty context cache/storage, not cold OS/JIT. Wall timings include automation and observation overhead. GC stabilization means two forced collections, not guaranteed quiescence or leak attribution. Fixed bounded cycles cannot establish long-run behavior. No thresholds or acceptance decisions. Worksheet is identity-bound context, not an imported outcome oracle.'},identities:{before:null,after:null},artifactSizes:{},latency:[],diagnostics:[],summaries:[],errors:[],unresolved:['Seven predecessor performance flags and all existing current-build performance flags remain open; this supplement does not automatically resolve them.','Manual G01 speech/comprehension remains open.','Native/live/cross-engine conformance and prior scoped closures are not rechecked.']};
report.methods.initialCursor='Home on an already-zero, unstarted player may leave row null at cursor eventIndex -1 and elapsed0. This valid untouched initial state is not a missing replay row. A reached Home endpoint with a row must be source event0/before; End must have an actual row/nonnegative cursor. No additional warmup or control action is inserted.';
const save=()=>fs.writeFileSync(path.join(out,'dnssec-performance-supplement-status.json'),JSON.stringify(report,null,2)+'\n');
const reportSchema={
  $schema:'https://json-schema.org/draft/2020-12/schema',title:'DNSSEC performance supplement',type:'object',
  required:['schemaVersion','kind','status','methods','identities','artifactSizes','latency','diagnostics','summaries','errors','unresolved'],
  properties:{
    schemaVersion:{const:1},kind:{const:'dnssec-performance-supplement'},status:{enum:['collecting','complete','failed']},exitCode:{enum:[0,1]},
    latency:{
      type:'array',items:{
        type:'object',required:['variant','loadingMode','sample','order','actions','logs'],
        properties:{actions:{
          type:'array',items:{
            type:'object',required:['name','before'],
            properties:{latencyMs:{type:'number',minimum:0},after:{type:'object'},error:{type:'string'}}
          }
        }}
      }
    },
    diagnostics:{
      type:'array',items:{
        type:'object',required:['variant','loadingMode','family','checkpoints','cycles'],
        properties:{checkpoints:{type:'array',items:{type:'object',required:['cycles','heap','dom','ui']}}}
      }
    }
  },
  not:{required:['passed']}
};
fs.writeFileSync(path.join(out,'report-schema.json'),JSON.stringify(reportSchema,null,2)+'\n');
save();
let roots,server,browser,origin,representatives;
function snapshot(root){const files={};function walk(rel){const f=path.join(root,rel),s=fs.lstatSync(f);assert.ok(!s.isSymbolicLink(),'No symlink input '+f);if(s.isDirectory())for(const n of fs.readdirSync(f).sort())walk(path.join(rel,n));else {assert.ok(s.isFile());files[rel]=digest(f);}}for(const rel of ['index.html','build.mjs','package.json','src','assets','tests','dist/auth-flow-studio.html'])walk(rel);if(fs.existsSync(path.join(root,'security-policy.mjs')))walk('security-policy.mjs');if(root===roots.candidate)walk('docs/dnssec-expansion/scenario-manifest.json');return {files,sha256:sha(JSON.stringify(files))};}
function identities(){return {roots:Object.fromEntries(variants.map(v=>[v,snapshot(roots[v])])),runner:digest(runner),worksheet:digest(opt.worksheet),runtime:digest(process.execPath),playwright:digest(fs.realpathSync(process.env.PLAYWRIGHT_MODULE)),chromium:digest(fs.realpathSync(process.env.CHROMIUM_EXECUTABLE))};}
function check(label){const observed=identities();assert.deepEqual(observed,report.identities.before,'Input identity changed: '+label);return observed;}
const settle=p=>p.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
async function state(p){return p.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),f=a.heldView.snapshot(),s=a.player.snapshot();return {scenario:a.labScenarioId,caseId:a.labModel?.caseId??null,variant:a.lessonVariant,status:a.player.status,elapsed:a.player.elapsed,cursor:f.cursor,row:s.step?.id??null,index:a.index,progress:Number(document.querySelector('#seek').value),nodes:document.querySelectorAll('*').length};});}
async function range(p,end){
  const c=p.locator('#seek');await c.focus();await p.keyboard.press(end?'End':'Home');await settle(p);
  assert.equal(Number(await c.inputValue()),end?1000:0,'Native range target');
  const s=await state(p);assert.ok(s.cursor&&Number.isInteger(s.cursor.eventIndex),'Observed canonical cursor');
  if(s.row===null){assert.equal(end,false,'End requires an actual replay row');assert.equal(s.cursor.eventIndex,-1,'Unstarted Home is the untouched initial cursor');assert.equal(s.elapsed,0,'Unstarted Home has no elapsed playback');}
  else if(end)assert.ok(s.cursor.eventIndex>=0,'End reaches an actual source event');
  else {assert.equal(s.cursor.eventIndex,0,'Reached Home is the first source event');assert.equal(s.cursor.milestone,'before','Reached Home precedes its first source event');}
  return s;
}
async function select(p,fixture){await p.locator('#lab-scenario-search').fill(fixture.id);await p.locator('[data-scenario-option='+JSON.stringify(fixture.id)+']').click();await settle(p);if(fixture.variant&&fixture.variant!=='default'){if(await p.locator('#lesson-reference').getAttribute('open')===null)await p.locator('#lesson-reference > summary').click();const c=p.locator('#lesson-case'),values=await c.locator('option').evaluateAll(es=>es.map(e=>e.value)),i=values.indexOf(fixture.variant);assert.ok(i>=0,'Actual case option exists');await c.focus();await p.keyboard.press('Home');for(let j=0;j<i;j++)await p.keyboard.press('ArrowDown');await p.keyboard.press('Enter');await settle(p);assert.equal(await c.inputValue(),fixture.variant);}const s=await state(p);assert.equal(s.scenario,fixture.id);if(fixture.caseId)assert.equal(s.caseId,fixture.caseId,'Actual named case');assert.equal(s.progress,0,'Selection resets seek');return s;}
const legacy={id:'lab-refresh-rotation'};
async function timed(row,p,name,fixture,fn){const a={name,fixture,before:await state(p)};row.actions.push(a);save();const start=performance.now();try{a.after=await fn();a.latencyMs=performance.now()-start;a.complete=true;}catch(e){a.elapsedUntilFailureMs=performance.now()-start;a.error=String(e.stack||e);throw e;}finally{save();}}
async function active(row,fn){
  let context;
  try{
    check('before context');
    context=await browser.newContext({viewport:report.methods.viewport,bypassCSP:false,serviceWorkers:'block',reducedMotion:'no-preference'});
    const p=await context.newPage();
    p.setDefaultTimeout(60000);p.setDefaultNavigationTimeout(60000);
    row.logs=[];
    const log=x=>{
      if(row.logs.length>=200){row.logsTruncated=true;return;}
      row.logs.push(x);
    };
    p.on('console',m=>log({kind:'console',type:m.type(),text:m.text().slice(0,8000)}));
    p.on('pageerror',e=>log({kind:'pageerror',text:String(e.stack||e).slice(0,8000)}));
    p.on('requestfailed',r=>log({kind:'requestfailed',url:r.url(),failure:r.failure()}));
    p.on('response',r=>{if(r.status()>=400)log({kind:'http-error',url:r.url(),status:r.status()});});
    const target=row.loadingMode==='standalone-file'?pathToFileURL(path.join(roots[row.variant],'dist/auth-flow-studio.html')).href:origin+'/'+row.variant+'/'+(row.loadingMode==='source-http'?'index.html':'dist/auth-flow-studio.html');
    row.target=target;
    await context.route('**/*',route=>{
      const u=new URL(route.request().url()),rel=decodeURIComponent(u.pathname).slice(('/'+row.variant+'/').length);
      if(route.request().url()===target||(row.loadingMode==='source-http'&&u.origin===origin&&u.pathname.startsWith('/'+row.variant+'/')&&Object.hasOwn(report.identities.before.roots[row.variant].files,rel)))return route.continue();
      log({kind:'external-request',url:u.href});return route.abort();
    });
    await p.goto(target,{waitUntil:'domcontentloaded'});
    await p.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.heldView&&a.player&&a.steps?.length&&a.scenarioPicker;});
    await p.locator('#play').waitFor({state:'visible'});await settle(p);
    row.initial=await state(p);
    await fn(p,context);
    assert.ok(!row.logsTruncated,'Raw log cap exceeded');
    assert.ok(!row.logs.some(l=>l.kind!=='console'||l.type==='error'||/content security policy|violates.*directive/i.test(l.text)),'Native page/network/console errors');
    row.complete=true;
  }catch(e){
    row.error=String(e.stack||e);
    report.errors.push({variant:row.variant,loadingMode:row.loadingMode,phase:row.family?'diagnostic':'latency',sample:row.sample,error:row.error});
  }finally{
    if(context)try{await context.close();}catch(e){row.complete=false;report.errors.push({phase:'context-close',error:String(e)});}
    row.finishedAt=new Date().toISOString();
    try{check('after context');}finally{save();}
  }
}
function stats(values){const s=[...values].sort((a,b)=>a-b),median=a=>a.length%2?a[(a.length-1)/2]:(a[a.length/2-1]+a[a.length/2])/2,m=median(s);return {values,min:s[0],median:m,max:s.at(-1),range:s.at(-1)-s[0],rangeOverMedian:m?(s.at(-1)-s[0])/m:null,mad:median(s.map(v=>Math.abs(v-m)).sort((a,b)=>a-b))};}
try{
  assert.ok(process.versions.bun,'Bun required');for(const k of ['PLAYWRIGHT_MODULE','CHROMIUM_EXECUTABLE','LD_LIBRARY_PATH'])assert.ok(process.env[k],'Missing '+k);
  roots=Object.fromEntries(variants.map(v=>[v,fs.realpathSync(opt[v+'-root'])]));for(const root of Object.values(roots))assert.ok(!within(root,realOut),'Output inside input root');
  report.identities.before=identities();for(const v of variants){const h=report.identities.before.roots[v].files['dist/auth-flow-studio.html'];assert.equal(h.sha256,opt[v+'-html-sha256'],v+' HTML hash');report.artifactSizes[v]={standalone:h,sourceBytes:Object.entries(report.identities.before.roots[v].files).filter(([n])=>n==='index.html'||n.startsWith('src/')||n.startsWith('assets/')).reduce((n,[,d])=>n+d.bytes,0)};}
  const manifest=JSON.parse(fs.readFileSync(path.join(roots.candidate,'docs/dnssec-expansion/scenario-manifest.json'),'utf8'));JSON.parse(fs.readFileSync(opt.worksheet,'utf8'));
  representatives=[['DNS01','cold-secure'],['DNS08','unsigned-optout-delegation'],['DNS13','ksk-double-ds'],['DNS15','default'],['DNS19','default']].map(([planId,c])=>{const r=manifest.rows.find(r=>r.planId===planId);assert.ok(r&&r.caseIds.includes(c==='default'?r.defaultCaseId:c),'Required representative '+planId);const caseId=c==='default'?r.defaultCaseId:c;return {planId,id:r.runtimeId,caseId,variant:caseId===r.defaultCaseId?'default':caseId};});report.representatives=representatives;
  const entry=fs.realpathSync(process.env.PLAYWRIGHT_MODULE);let dir=path.dirname(entry);while(!fs.existsSync(path.join(dir,'package.json'))&&path.dirname(dir)!==dir)dir=path.dirname(dir);report.playwrightPackage={...JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8')),identity:digest(path.join(dir,'package.json'))};
  const module=await import(pathToFileURL(entry).href),chromium=module.chromium||module.default?.chromium;assert.ok(chromium,'Playwright chromium export required');
  server=http.createServer((req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1'),parts=decodeURIComponent(u.pathname).split('/'),v=parts[1],rel=parts.slice(2).join('/');if(!['GET','HEAD'].includes(req.method)||!variants.includes(v)||!Object.hasOwn(report.identities.before.roots[v].files,rel)||!(rel==='index.html'||rel==='dist/auth-flow-studio.html'||rel.startsWith('src/')||rel.startsWith('assets/'))){res.writeHead(404);res.end();return;}const f=path.join(roots[v],rel);assert.equal(fs.realpathSync(f),f);res.writeHead(200,{'Content-Type':{'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'}[path.extname(f)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});if(req.method==='HEAD')res.end();else fs.createReadStream(f).on('error',()=>res.destroy()).pipe(res);}catch{res.writeHead(400);res.end();}});await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({executablePath:fs.realpathSync(process.env.CHROMIUM_EXECUTABLE),headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});report.browser={version:browser.version(),launchArgs:['--no-sandbox','--disable-dev-shm-usage'],sandbox:'Disabled for provisioned synthetic loopback/file inputs only'};
  for(let mi=0;mi<modes.length;mi++)for(let sample=0;sample<3;sample++){const order=(mi+sample)%2?[...variants].reverse():variants;for(let oi=0;oi<order.length;oi++){const row={variant:order[oi],loadingMode:modes[mi],sample,order:oi,actions:[],logs:[]};report.latency.push(row);await active(row,async p=>{await select(p,legacy);await range(p,false);await timed(row,p,'legacy-seek',legacy,()=>range(p,true));if(row.variant==='candidate'){const rotated=representatives.map((_,i)=>representatives[(i+sample)%5]);row.representativeOrder=rotated;for(const f of rotated){await timed(row,p,'dns-selection',f,()=>select(p,f));await timed(row,p,'dns-seek',f,()=>range(p,true));}}});}}
  report.latencyFinishedAt=new Date().toISOString();save();
  // Diagnostic instrumentation is created only here, never in any latency context.
  for(const loadingMode of modes)for(const variant of variants)for(const family of variant==='candidate'?['legacy','dns-candidate-only']:['legacy']){const row={variant,loadingMode,family,cycles:[],checkpoints:[],logs:[]};report.diagnostics.push(row);await active(row,async(p,context)=>{const fixtures=family==='legacy'?[legacy]:representatives;for(const f of fixtures){await select(p,f);await range(p,true);await range(p,false);}const cdp=await context.newCDPSession(p);try{await cdp.send('Runtime.enable');await cdp.send('HeapProfiler.enable');for(let n=0;n<=12;n++){if(n){const cycle={number:n,states:[]};row.cycles.push(cycle);for(const f of fixtures){await select(p,f);cycle.states.push({fixture:f,end:await range(p,true),start:await range(p,false)});}}if([0,3,6,12].includes(n)){await cdp.send('HeapProfiler.collectGarbage');await cdp.send('HeapProfiler.collectGarbage');const heap=await cdp.send('Runtime.getHeapUsage'),dom=await cdp.send('Memory.getDOMCounters');assert.ok(Number.isFinite(heap.usedSize)&&Number.isFinite(dom.nodes),'CDP heap/DOM support required');row.checkpoints.push({cycles:n,at:new Date().toISOString(),forcedCollections:2,heap,dom,ui:await state(p)});save();}}const zero=row.checkpoints[0];row.growth=row.checkpoints.slice(1).map(c=>({cycles:c.cycles,usedHeapBytes:c.heap.usedSize-zero.heap.usedSize,nodes:c.dom.nodes-zero.dom.nodes,documents:c.dom.documents-zero.dom.documents,eventListeners:c.dom.jsEventListeners-zero.dom.jsEventListeners}));}finally{await cdp.detach();}});}
  for(const loadingMode of modes)for(const variant of variants){const rows=report.latency.filter(r=>r.loadingMode===loadingMode&&r.variant===variant);for(const name of ['legacy-seek',...(variant==='candidate'?['dns-selection','dns-seek']:[])])for(const fixture of name==='legacy-seek'?[legacy]:representatives){const actions=rows.flatMap(r=>r.actions).filter(a=>a.name===name&&a.fixture.id===fixture.id);const values=actions.filter(a=>a.complete).map(a=>a.latencyMs);report.summaries.push({loadingMode,variant,candidateOnly:name.startsWith('dns-'),name,fixture,expected:3,observed:values.length,statistics:values.length?stats(values):null});}}
  for(const loadingMode of modes){
    const rows=report.latency.filter(r=>r.loadingMode===loadingMode);
    const common=rows.flatMap(r=>r.actions.filter(a=>a.name==='legacy-seek'&&a.complete));
    assert.equal(common.length,6,'All common legacy seek samples required');
    const comparable=s=>({scenario:s.scenario,row:s.row,cursor:s.cursor,progress:s.progress});
    for(const action of common){
      assert.deepEqual(comparable(action.before),comparable(common[0].before),'Comparable legacy starting UI state');
      assert.deepEqual(comparable(action.after),comparable(common[0].after),'Comparable legacy resulting UI state');
      assert.notDeepEqual(action.after.cursor,action.before.cursor,'Seek must change actual cursor');
    }
  }
  assert.equal(report.latency.length,18);assert.equal(report.diagnostics.length,9);assert.ok(report.latency.every(r=>r.complete)&&report.diagnostics.every(r=>r.complete)&&report.summaries.every(r=>r.observed===3)&&!report.errors.length,'Collection incomplete; raw failures retained');report.status='complete';
}catch(e){report.status='failed';report.errors.push({phase:'collection',error:String(e.stack||e)});}
finally{if(browser)try{await browser.close();}catch(e){report.errors.push({phase:'browser-close',error:String(e)});}if(server)await new Promise(resolve=>server.close(resolve));if(report.identities.before)try{report.identities.after=identities();assert.deepEqual(report.identities.after,report.identities.before);report.identityUnchanged=true;}catch(e){report.identityUnchanged=false;report.errors.push({phase:'final-identity',error:String(e.stack||e)});}if(report.errors.length)report.status='failed';report.exitCode=report.status==='complete'?0:1;process.exitCode=report.exitCode;report.finishedAt=new Date().toISOString();save();}
console.log(JSON.stringify({status:report.status,exitCode:report.exitCode,report:path.join(out,'dnssec-performance-supplement-status.json'),latencyContexts:report.latency.length,diagnosticContexts:report.diagnostics.length,errors:report.errors.length}));
