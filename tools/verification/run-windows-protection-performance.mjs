#!/usr/bin/env bun
// Real Chromium UI latency collection. No app imports, builds, installs or acceptance inference.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const HELP=`Usage: bun tools/verification/run-windows-protection-performance.mjs
  --baseline-root=PATH --candidate-root=PATH --out=NEW_DIRECTORY --samples=3
  --baseline-html-sha256=HASH --candidate-html-sha256=HASH
Optional --playwright-module=FILE --chromium-executable=FILE (otherwise PLAYWRIGHT_MODULE / CHROMIUM_EXECUTABLE).
All options use =VALUE; samples is an integer 3..30. Provision dependencies externally; inherit LD_LIBRARY_PATH.
Run alone, never concurrently with browser/build/test/performance workloads. A cooperative lock prevents this runner overlapping itself, not arbitrary external jobs.
Serial fresh contexts at 1920x1200, all three loading modes and both post-startup index states. No startup latency (unchanged shared27 runner owns that), no warmup/sample discard. Each action includes automation, two rAF, and observed UI readback. Baseline/candidate alternate for two existing Linux/SSH PAM anchors; new Windows/PAM/search surfaces are candidate-only, NOT like-for-like speed regressions.
Outputs windows-protection-performance-status.json. Exit 0 complete without comparable flags; 2 complete with material/variation flags; 1 collection/identity error. No release, G01, Astra, native Windows or performance acceptance/waiver.`;
if(process.argv.includes('--help')){console.log(HELP);process.exit(0);}
const allowed=new Set(['baseline-root','candidate-root','out','samples','baseline-html-sha256','candidate-html-sha256','playwright-module','chromium-executable']),opt={};
for(const arg of process.argv.slice(2)){
  const m=/^--([^=]+)=(.+)$/.exec(arg);
  assert.ok(m&&allowed.has(m[1]),'Unknown/malformed option '+arg+'\n'+HELP);
  assert.ok(!Object.hasOwn(opt,m[1]),'Duplicate option '+m[1]);opt[m[1]]=m[2];
}
for(const key of ['baseline-root','candidate-root','out','samples','baseline-html-sha256','candidate-html-sha256'])assert.ok(opt[key],'Missing --'+key+'\n'+HELP);
const samples=Number(opt.samples);assert.ok(Number.isInteger(samples)&&samples>=3&&samples<=30,'--samples must be 3..30');
for(const side of ['baseline','candidate'])assert.match(opt[side+'-html-sha256'],/^[a-f0-9]{64}$/,'Expected lowercase HTML SHA256');
const sides=['baseline','candidate'],modes=['source-http','standalone-http','standalone-file'],profiles=['index-open','index-closed'];
const roots=Object.fromEntries(sides.map(side=>[side,fs.realpathSync(opt[side+'-root'])]));
const within=(root,file)=>file===root||file.startsWith(root+path.sep),out=path.resolve(opt.out);
fs.mkdirSync(path.dirname(out),{recursive:true});
const realOut=path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
for(const root of Object.values(roots))assert.ok(!within(root,realOut),'Evidence must be outside both immutable roots');
fs.mkdirSync(out); // Exclusive leaf creation: never overwrite or merge an old evidence directory.
const runner=fileURLToPath(import.meta.url),reportPath=path.join(out,'windows-protection-performance-status.json');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function digest(file){assert.ok(!fs.lstatSync(file).isSymbolicLink(),'Symlink input '+file);const bytes=fs.readFileSync(file);return {bytes:bytes.length,sha256:sha(bytes)};}
function tree(root,entries){
  const files={};
  function walk(rel){const file=path.join(root,rel),s=fs.lstatSync(file);assert.ok(!s.isSymbolicLink(),'Symlink input '+file);if(s.isDirectory())for(const n of fs.readdirSync(file).sort())walk(path.join(rel,n));else {assert.ok(s.isFile(),'Not a regular input '+file);files[rel]=digest(file);}}
  for(const rel of entries)walk(rel);
  return {files,sha256:sha(JSON.stringify(files))};
}
const inventory=[
  {id:'linux-pam-auth-row',comparison:'like-for-like',operation:'Select existing lab-llog01 pam-auth timeline row; read selected semantic row after two rAF. Does not time the new PAM panel in isolation.'},
  {id:'ssh-pam-account-row',comparison:'like-for-like',operation:'Select existing lab-ssh-sssd-success account-policy timeline row; same operation in both inputs, including their actual rendering work.'},
  {id:'remote-named-case',comparison:'candidate-only',operation:'Search/select lab-wra01 and choose explicit-zero named case.'},
  {id:'remote-local-domain',comparison:'candidate-only',operation:'Change default-filtered local comparison profile to domain.'},
  {id:'remote-filter-policy',comparison:'candidate-only',operation:'Open target-side token/filter comparison with actual configured/applied policy evidence at completed default-filtered prefix.'},
  {id:'protection-named-case',comparison:'candidate-only',operation:'Search/select lab-wprot01 and choose disabled-comparison.'},
  {id:'pam-named-case',comparison:'candidate-only',operation:'Search/select lab-pam01 and choose requisite-immediate-failure.'},
  {id:'pam-physical-row',comparison:'candidate-only',operation:'Select physical line 2 authentication evaluation in requisite-immediate-failure, read current physical/control row.'},
  {id:'pam-control-comparison',comparison:'candidate-only',operation:'Reveal changed required/requisite physical control-line comparison.'},
  {id:'pam-resource-row',comparison:'candidate-only',operation:'Select soft-hard-limits pam_limits open-session row and read separate resource limits.'},
  {id:'pam-aggregate',comparison:'candidate-only',operation:'Open API aggregate results after the soft-hard-limits open-session module completed.'},
  {id:'pam-configuration',comparison:'candidate-only',operation:'Open complete physical configuration/include tree and recorded file hashes.'},
  {id:'exact-object-history',comparison:'candidate-only',operation:'Open exact history of the actually selected target-policy artifact, not an attribute alias.'},
  {id:'search-latfp-rank',comparison:'candidate-only',operation:'Type LocalAccountTokenFilterPolicy; read complete ordered result IDs and require lab-wra01 first.'},
  {id:'search-runas-ppl-rank',comparison:'candidate-only',operation:'Type RunAsPPL; read complete ordered result IDs and require lab-wprot02 first.'},
  {id:'search-explicit-case-focus',comparison:'candidate-only',operation:'Choose ambiguous sufficient result, require first case-choice focus without lesson replacement.'},
  {id:'search-explicit-case-select',comparison:'candidate-only',operation:'Choose sufficient-after-failure explicitly; require actual case and persistent Play focus.'},
];
const report={schemaVersion:1,kind:'windows-protection-performance-supplement',status:'collecting',complete:false,nativeBrowser:true,startedAt:new Date().toISOString(),argv:process.argv,
  runtime:{executable:process.execPath,versions:process.versions,platform:process.platform,arch:process.arch,osRelease:os.release()},
  environment:{PLAYWRIGHT_MODULE:opt['playwright-module']||process.env.PLAYWRIGHT_MODULE||null,CHROMIUM_EXECUTABLE:opt['chromium-executable']||process.env.CHROMIUM_EXECUTABLE||null,LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH||null},
  inputs:{roots,expectedStandaloneSha256:Object.fromEntries(sides.map(side=>[side,opt[side+'-html-sha256']]))},identities:{},
  methods:{viewport:{width:1920,height:1200},samples,modes,profiles,inventory,contextPolicy:'Serial fresh storage/cache contexts for each side/mode/profile/sample. Empty browser cache is not cold OS cache. Comparable actions first, then candidate-only actions in fixed listed order. Preparation is retained, not a warmup sample. No selectively discarded samples or outliers.',
    timing:'Wall milliseconds includes actual Playwright input, exactly two requestAnimationFrame callbacks and bounded observed UI readback. Timeline selection latency measures initial selected-row rendering, not animation completion. Preparation may await natural completion; it is not a latency sample.',
    startup:'Not measured here; unchanged run-next-expansion-performance.mjs owns shared27 startup/general cells against the frozen actual parent.',
    ordering:'Side order alternates by sample + mode + profile parity. Each fresh side context uses identical comparable operations/preparation. Candidate-only operations follow both anchor operations and are never assigned baseline zero.',
    thresholds:{materialRelativeGreaterThan:.25,startupAbsoluteMsGreaterThan:100,interactionAbsoluteMsGreaterThan:50,baselineVariable:'baseline range/median > .25 AND range > 50ms; candidate instability is separately flagged by the same rule'},
    noConcurrency:'Operator must run alone. Cooperative lock prevents only this supplement overlapping itself; absence of arbitrary external workloads is not proven.',
    limits:'Real Chromium UI only, not Windows/DC/live or human screen-reader evidence. No acceptance or waiver. Candidate-only medians are descriptive and have no regression/acceptance threshold.'},
  rows:[],summaries:[],comparisons:[],availability:[],errors:[],unperformed:[],sourceUnchanged:null,
  excluded:[{kind:'startup-and-shared27',reason:'Owned by unchanged shared runner, unperformed by this supplement'},{kind:'cpu-profile',reason:'Optional diagnostic profile mode not implemented or performed; latency contexts have no CDP profiling'},{kind:'native-windows-live',reason:'No native Windows/DC/live collection'},{kind:'human-G01',reason:'Requires human screen-reader assessment'}]};
const save=()=>fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');
save();
let browser,server,origin,playwrightEntry,chrome,packageRoot,lockFd,interrupted=false;
const lockPath=path.join(os.tmpdir(),'auth-lab-windows-protection-performance.lock');
const errorText=e=>String(e.stack||e);
const schedule=[];
for(let mi=0;mi<modes.length;mi++)for(let pi=0;pi<profiles.length;pi++)for(let sample=0;sample<samples;sample++){
  const order=(mi+pi+sample)%2?[...sides].reverse():sides;
  for(let oi=0;oi<order.length;oi++)schedule.push({side:order[oi],loadingMode:modes[mi],profile:profiles[pi],sample,order:oi,globalOrder:schedule.length,sideOrder:[...order]});
}
report.schedule=schedule;
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{
  interrupted=true;report.errors.push({phase:'signal',signal});
  if(browser)void browser.close().catch(e=>report.errors.push({phase:'signal-browser-close',error:errorText(e)}));
});
function identity(){
  const sourceRoots=Object.fromEntries(sides.map(side=>{const root=roots[side],entries=['index.html','build.mjs','package.json','src','assets','tests','dist/auth-flow-studio.html'];for(const rel of ['security-policy.mjs','docs/windows-protection-expansion','docs/pam-foundations'])if(fs.existsSync(path.join(root,rel)))entries.push(rel);return [side,tree(root,entries)];}));
  return {roots:sourceRoots,runner:digest(runner),runtime:digest(fs.realpathSync(process.execPath)),browser:digest(chrome),playwright:tree(packageRoot,['package.json',path.relative(packageRoot,playwrightEntry),...(fs.existsSync(path.join(packageRoot,'lib'))?['lib']:[])])};
}
const settle=p=>p.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
const selector=(name,value)=>'['+name+'='+JSON.stringify(value)+']';
async function state(p){return p.evaluate(()=>{
  const a=document.querySelector('auth-flow-studio'),snapshot=a.heldView.snapshot(),text=sel=>document.querySelector(sel)?.textContent?.slice(0,18000)||null;
  return {scenario:a.labScenarioId,caseId:a.labModel?.caseId??null,variant:a.lessonVariant,subfixture:a.labModel?.subfixtureId??null,selectedSubfixture:document.querySelector('#lesson-subfixture')?.value??null,row:a.currentStep?.sourceStepId||a.currentStep?.id||null,title:a.currentStep?.title||null,status:a.player.status,cursor:snapshot.cursor,indexOpen:!document.querySelector('#attribute-index').hidden,focus:{id:document.activeElement?.id||null,searchCase:document.activeElement?.dataset?.searchCase||null},objectTrace:a.objectTraceSelection||null,pam:text('#pam-configuration-panel'),remote:text('#windows-remote-evidence'),currentPhysical:document.querySelector('[data-pam-line][aria-current="step"]')?.getAttribute('data-pam-line')||null,resourceLines:[...document.querySelectorAll('[data-pam-resource-line]')].map(e=>e.getAttribute('data-pam-resource-line')),openDetails:[...document.querySelectorAll('#pam-configuration-panel details[open], #windows-remote-evidence details[open]')].map(e=>e.dataset.pamDisclosure||'remote-comparison'),rankedResults:[...document.querySelectorAll('#lab-scenario-results [data-scenario-option]')].map(e=>e.dataset.scenarioOption),choiceCases:[...document.querySelectorAll('#search-case-choice:not([hidden]) [data-search-case]')].map(e=>e.dataset.searchCase)};
});}
async function select(p,id){await p.locator('#lab-scenario-search').fill(id);await p.locator(selector('data-scenario-option',id)).click();assert.equal((await state(p)).scenario,id,'Selected requested actual lesson');}
async function choose(p,id,value){const c=p.locator('#'+id);assert.ok((await c.locator('option').evaluateAll(es=>es.map(e=>e.value))).includes(value),'Required actual '+id+' option '+value);await c.selectOption(value);assert.equal(await c.inputValue(),value);}
async function lesson(p,id,caseId){await select(p,id);if(caseId){await choose(p,'lesson-case',caseId);await settle(p);}}
async function rowTarget(p,kind){return p.evaluate(kind=>{
  const a=document.querySelector('auth-flow-studio');
  const match=s=>kind==='linux'?/[-:]pam-auth$/.test(s.id):kind==='ssh'?/[-:]account-policy$/.test(s.id):kind==='physical'?s.pamEvaluation?.line===2&&s.pamEvaluation?.apiPhase==='authenticate':kind==='aggregate'?s.pamEvaluation?.apiPhase==='open'&&s.pamAggregate==='PAM_SUCCESS':!!s.pamEvaluation?.resourceConfiguration&&s.pamEvaluation?.apiPhase==='open';
  const s=a.steps.find(match);if(!s)return null;
  const i=a.visibleSteps.findIndex(row=>(row.sourceStepId||row.id)===s.id);
  return i<0?null:{id:s.id,index:i,title:s.title,evaluation:s.pamEvaluation||null};
},kind);}
async function clickRow(p,target){assert.ok(target,'Required semantic timeline operation unavailable; no alternate action');await p.locator(selector('data-step',String(target.index))).click();}
async function end(p){await p.locator('#seek').focus();await p.keyboard.press('End');await settle(p);assert.equal(Number(await p.locator('#seek').inputValue()),1000);}
async function open(p,sel){const d=p.locator(sel);assert.equal(await d.getAttribute('open'),null,'Disclosure starts closed');await d.locator(':scope > summary').click();assert.notEqual(await d.getAttribute('open'),null,'Disclosure opened by real input');}
async function prepare(row,p,name,fn){const entry={name,startedAt:new Date().toISOString()};row.preparation.push(entry);try{await fn();entry.after=await state(p);entry.complete=true;}catch(e){entry.error=errorText(e);throw e;}finally{save();}}
async function timed(row,p,id,action,verify=()=>{}){
  const cell=inventory.find(c=>c.id===id),entry={id,comparison:cell.comparison,sequence:row.actions.length+1,before:await state(p),complete:false};row.actions.push(entry);
  console.log('cell '+row.loadingMode+' '+row.profile+' sample='+row.sample+' order='+row.order+' '+row.side+' '+id);
  const start=performance.now();
  try{await action();await settle(p);entry.after=await state(p);verify(entry.after,entry.before);entry.latencyMs=performance.now()-start;entry.complete=true;}
  catch(e){entry.elapsedUntilFailureMs=performance.now()-start;entry.error=errorText(e);throw e;}
  finally{save();}
}
async function collect(row,p){
  for(const [id,scenario,kind] of [['linux-pam-auth-row','lab-llog01','linux'],['ssh-pam-account-row','lab-ssh-sssd-success','ssh']]){
    let target;
    await prepare(row,p,id,async()=>{await select(p,scenario);target=await rowTarget(p,kind);assert.ok(target,'Required comparable '+scenario+'/'+kind+' unavailable; no substitution');row.anchorTargets.push({id,...target});});
    await timed(row,p,id,()=>clickRow(p,target),s=>{assert.equal(s.scenario,scenario);assert.equal(s.row,target.id);});
  }
  if(row.side==='baseline')return;
  await prepare(row,p,'windows-start',()=>select(p,'lab-llog01'));
  await timed(row,p,'remote-named-case',async()=>{await select(p,'lab-wra01');await choose(p,'lesson-case','explicit-zero');},s=>{assert.equal(s.scenario,'lab-wra01');assert.equal(s.variant,'explicit-zero');});
  await prepare(row,p,'local-default-filtered',()=>lesson(p,'lab-wra01','default-filtered'));
  await timed(row,p,'remote-local-domain',()=>choose(p,'lesson-subfixture','domain'),s=>assert.equal(s.selectedSubfixture,'domain'));
  await prepare(row,p,'completed-remote-filter',async()=>{await lesson(p,'lab-wra01','default-filtered');await end(p);});
  await timed(row,p,'remote-filter-policy',()=>open(p,'[data-remote-comparison]'),s=>{assert.ok(s.openDetails.includes('remote-comparison'));assert.match(s.remote,/LocalAccountTokenFilterPolicy/);assert.match(s.remote,/deny.only/i);});
  await timed(row,p,'protection-named-case',async()=>{await select(p,'lab-wprot01');await choose(p,'lesson-case','disabled-comparison');},s=>{assert.equal(s.scenario,'lab-wprot01');assert.equal(s.variant,'disabled-comparison');});
  await timed(row,p,'pam-named-case',async()=>{await select(p,'lab-pam01');await choose(p,'lesson-case','requisite-immediate-failure');},s=>assert.equal(s.variant,'requisite-immediate-failure'));
  let physical;
  await prepare(row,p,'find-physical-control-row',async()=>{physical=await rowTarget(p,'physical');assert.ok(physical,'Physical line2 auth evaluation unavailable');});
  await timed(row,p,'pam-physical-row',()=>clickRow(p,physical),s=>{assert.equal(s.row,physical.id);assert.equal(s.currentPhysical,'2');assert.match(s.pam,/requisite/);});
  await prepare(row,p,'complete-control-row',async()=>{await p.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status!=='playing');await settle(p);});
  await timed(row,p,'pam-control-comparison',()=>open(p,'[data-pam-disclosure="comparison"]'),s=>{assert.ok(s.openDetails.includes('comparison'));assert.match(s.pam,/required/);assert.match(s.pam,/requisite/);});
  let resource;
  await prepare(row,p,'limits-case',async()=>{await lesson(p,'lab-pam01','soft-hard-limits');resource=await rowTarget(p,'resource');assert.ok(resource,'Actual pam_limits open row unavailable');});
  await timed(row,p,'pam-resource-row',()=>clickRow(p,resource),s=>{assert.equal(s.row,resource.id);assert.deepEqual(s.resourceLines,resource.evaluation.resourceConfiguration.rows.map(line=>String(line.line)));});
  await prepare(row,p,'complete-limits-and-open-api-return',async()=>{
    await p.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status!=='playing');await settle(p);
    const aggregate=await rowTarget(p,'aggregate');assert.ok(aggregate,'Actual successful open-session API return unavailable');
    await clickRow(p,aggregate);await p.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status!=='playing');await settle(p);
    const actual=await p.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.heldView.snapshot();return a.labModel.pamStatePaths.results.split('.').reduce((v,k)=>v?.[k],s.state);});
    assert.equal(actual.open,'PAM_SUCCESS','Inspect the completed canonical API aggregate, not a module return');
  });
  await timed(row,p,'pam-aggregate',()=>open(p,'[data-pam-disclosure="aggregates"]'),s=>{assert.ok(s.openDetails.includes('aggregates'));assert.match(s.pam,/PAM_SUCCESS/);});
  await timed(row,p,'pam-configuration',()=>open(p,'[data-pam-disclosure="configuration"]'),s=>assert.ok(s.openDetails.includes('configuration')));
  let artifact;
  await prepare(row,p,'exact-target-policy-object',async()=>{
    await lesson(p,'lab-wra01','default-filtered');
    const holding=await p.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return a.heldView.snapshot().holdings.find(h=>/target-policy/.test(h.artifactId))||null;});
    assert.ok(holding,'Actual seeded target-policy holding unavailable; no arbitrary object substitution');artifact=holding.artifactId;
    const button=p.locator('#held-objects '+selector('data-holding-id',holding.holdingId));
    if(!await button.isVisible())await p.locator('#held-objects '+selector('data-held-actor',holding.actorId)).click();
    await button.click();await settle(p);assert.equal(await p.locator('[data-held-trace]').getAttribute('data-held-trace'),artifact);
  });
  await timed(row,p,'exact-object-history',()=>p.locator(selector('data-held-trace',artifact)).click(),s=>assert.equal(s.objectTrace,artifact));
  for(const [id,query,first] of [['search-latfp-rank','LocalAccountTokenFilterPolicy','lab-wra01'],['search-runas-ppl-rank','RunAsPPL','lab-wprot02']]){
    await prepare(row,p,'clear-query-'+id,async()=>{await p.locator('#lab-scenario-search').fill('');await settle(p);});
    await timed(row,p,id,()=>p.locator('#lab-scenario-search').fill(query),(s,b)=>{assert.equal(s.rankedResults[0],first);assert.equal(new Set(s.rankedResults).size,s.rankedResults.length);assert.equal(s.scenario,b.scenario,'Typing does not replace lesson');});
  }
  await prepare(row,p,'ambiguous-sufficient-query',async()=>{await p.locator('#lab-scenario-search').fill('sufficient');await settle(p);const result=await p.evaluate(()=>document.querySelector('auth-flow-studio').scenarioPicker.results.find(r=>r.id==='lab-pam01'));assert.ok(result?.matchingVariantIds?.includes('sufficient-after-failure'),'Actual query is ambiguous and contains explicit target');});
  await timed(row,p,'search-explicit-case-focus',()=>p.locator('[data-scenario-option="lab-pam01"]').click(),(s,b)=>{assert.equal(s.scenario,b.scenario,'Ambiguous result preserves current lesson');assert.ok(s.choiceCases.length>1);assert.equal(s.focus.searchCase,s.choiceCases[0]);});
  await timed(row,p,'search-explicit-case-select',()=>p.locator('#search-case-choice [data-search-case="sufficient-after-failure"]').click(),s=>{assert.equal(s.scenario,'lab-pam01');assert.equal(s.variant,'sufficient-after-failure');assert.equal(s.focus.id,'play');assert.equal(s.choiceCases.length,0);});
}
function stats(values){const sorted=[...values].sort((a,b)=>a-b),median=a=>a.length%2?a[(a.length-1)/2]:(a[a.length/2-1]+a[a.length/2])/2,m=median(sorted),range=sorted.at(-1)-sorted[0];return {values,min:sorted[0],median:m,max:sorted.at(-1),rangeMs:range,rangeOverMedian:m?range/m:null,mad:median(sorted.map(n=>Math.abs(n-m)).sort((a,b)=>a-b))};}
async function context(row){
  let ctx,deadline;
  try{
    ctx=await browser.newContext({viewport:report.methods.viewport,serviceWorkers:'block',reducedMotion:'no-preference',bypassCSP:false});
    deadline=setTimeout(()=>{row.deadlineExceeded=true;void ctx.close().catch(e=>report.errors.push({phase:'deadline-close',error:errorText(e)}));},240000);
    const p=await ctx.newPage();p.setDefaultTimeout(45000);p.setDefaultNavigationTimeout(60000);
    const log=item=>{if(row.logs.length<100)row.logs.push(item);else row.logsTruncated=true;};
    p.on('console',m=>log({kind:'console',type:m.type(),text:m.text().slice(0,4000)}));
    p.on('pageerror',e=>log({kind:'pageerror',text:errorText(e).slice(0,4000)}));
    p.on('requestfailed',r=>log({kind:'requestfailed',url:r.url().slice(0,2000),failure:r.failure()}));
    p.on('response',r=>{if(r.status()>=400)log({kind:'http-error',url:r.url().slice(0,2000),status:r.status()});});
    row.target=row.loadingMode==='standalone-file'?pathToFileURL(path.join(roots[row.side],'dist/auth-flow-studio.html')).href:origin+'/'+row.side+'/'+(row.loadingMode==='source-http'?'index.html':'dist/auth-flow-studio.html');
    await ctx.route('**/*',route=>{const u=new URL(route.request().url()),prefix='/'+row.side+'/',rel=decodeURIComponent(u.pathname).slice(prefix.length);if(u.href===row.target||(row.loadingMode==='source-http'&&u.origin===origin&&u.pathname.startsWith(prefix)&&Object.hasOwn(report.identities.before.roots[row.side].files,rel)))return route.continue();log({kind:'unexpected-network',url:u.href.slice(0,2000)});return route.abort();});
    if(row.loadingMode==='standalone-file')await ctx.setOffline(true);
    await p.goto(row.target,{waitUntil:'domcontentloaded'});
    await p.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.heldView&&a.player&&a.steps?.length&&a.scenarioPicker;});
    await p.locator('#play').waitFor({state:'visible'});await settle(p);
    if(row.sample===0){report.availability.push({side:row.side,loadingMode:row.loadingMode,profile:row.profile,observed:await p.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {scenarios:Object.fromEntries(['lab-llog01','lab-ssh-sssd-success','lab-wra01','lab-wprot01','lab-pam01'].map(id=>[id,a.scenarioPicker.options.some(o=>o.id===id)])),pamPanelElement:!!document.querySelector('#pam-configuration-panel'),remotePanelElement:!!document.querySelector('#windows-remote-evidence'),caseChoiceElement:!!document.querySelector('#search-case-choice')};})});}
    const isOpen=await p.locator('#attribute-index').isVisible();
    if(isOpen!==(row.profile==='index-open'))await p.locator(isOpen?'#attribute-index-toggle':'#index-open').click();
    await settle(p);assert.equal((await state(p)).indexOpen,row.profile==='index-open');
    row.initial=await state(p);await collect(row,p);
    assert.ok(!row.logsTruncated,'Raw browser log cap exceeded');
    assert.ok(!row.logs.some(l=>l.kind!=='console'||l.type==='error'||/content security policy|violates.*directive/i.test(l.text)),'Browser console/page/network error; retained raw log');
    row.complete=true;
  }catch(e){row.error=errorText(e);report.errors.push({phase:'context',side:row.side,loadingMode:row.loadingMode,profile:row.profile,sample:row.sample,error:row.error});}
  finally{clearTimeout(deadline);if(ctx)try{await ctx.close();}catch(e){row.complete=false;report.errors.push({phase:'context-close',error:errorText(e)});}row.finishedAt=new Date().toISOString();save();}
}
const started=performance.now();
try{
  assert.ok(process.versions.bun,'Bun required');
  assert.ok(report.environment.PLAYWRIGHT_MODULE&&report.environment.CHROMIUM_EXECUTABLE,'Provision Playwright and Chromium externally');
  playwrightEntry=fs.realpathSync(report.environment.PLAYWRIGHT_MODULE);chrome=fs.realpathSync(report.environment.CHROMIUM_EXECUTABLE);
  packageRoot=path.dirname(playwrightEntry);while(!fs.existsSync(path.join(packageRoot,'package.json'))&&path.dirname(packageRoot)!==packageRoot)packageRoot=path.dirname(packageRoot);
  lockFd=fs.openSync(lockPath,'wx');fs.writeFileSync(lockFd,JSON.stringify({pid:process.pid,runner,out,startedAt:report.startedAt})+'\n');
  report.exclusivity={lockPath,pid:process.pid,acquired:true,externalWorkloadAbsence:'unverified; operator scheduling obligation'};
  report.identities.before=identity();
  for(const side of sides)assert.equal(report.identities.before.roots[side].files['dist/auth-flow-studio.html'].sha256,opt[side+'-html-sha256'],side+' explicit standalone SHA256');
  report.playwrightVersion=JSON.parse(fs.readFileSync(path.join(packageRoot,'package.json'),'utf8')).version;
  const imported=await import(pathToFileURL(playwrightEntry).href),chromium=imported.chromium||imported.default?.chromium;assert.ok(chromium,'Chromium export missing');
  server=http.createServer((req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1'),parts=decodeURIComponent(u.pathname).split('/'),side=parts[1],rel=parts.slice(2).join('/');if(!['GET','HEAD'].includes(req.method)||!sides.includes(side)||!Object.hasOwn(report.identities.before.roots[side].files,rel)||!(rel==='index.html'||rel==='dist/auth-flow-studio.html'||rel.startsWith('src/')||rel.startsWith('assets/'))){res.writeHead(404);res.end();return;}const file=path.join(roots[side],rel);assert.equal(fs.realpathSync(file),file);res.writeHead(200,{'Content-Type':{'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});if(req.method==='HEAD')res.end();else fs.createReadStream(file).on('error',()=>res.destroy()).pipe(res);}catch(e){report.errors.push({phase:'http-server',error:errorText(e)});res.writeHead(500);res.end();}});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});origin='http://127.0.0.1:'+server.address().port;
  report.browser={launchArgs:['--no-sandbox','--disable-dev-shm-usage'],sandbox:'Disabled for frozen synthetic loopback/file inputs only'};
  browser=await chromium.launch({executablePath:chrome,headless:true,args:report.browser.launchArgs,timeout:60000});report.browser.versionBefore=browser.version();save();
  for(const planned of schedule){
    assert.ok(!interrupted,'Interrupted collection; unperformed cells retained');
    const row={...planned,startedAt:new Date().toISOString(),complete:false,actions:[],preparation:[],anchorTargets:[],logs:[]};report.rows.push(row);await context(row);
  }
  report.browser.versionAfter=browser.version();assert.equal(report.browser.versionAfter,report.browser.versionBefore);
  for(const loadingMode of modes)for(const profile of profiles)for(const cell of inventory){
    const summaries={};
    for(const side of cell.comparison==='like-for-like'?sides:['candidate']){
      const actions=report.rows.filter(r=>r.side===side&&r.loadingMode===loadingMode&&r.profile===profile).flatMap(r=>r.actions.filter(a=>a.id===cell.id)),values=actions.filter(a=>a.complete).map(a=>a.latencyMs);
      const summary={id:cell.id,comparison:cell.comparison,loadingMode,profile,side,expected:samples,attempted:actions.length,completed:values.length,errors:actions.filter(a=>a.error).map(a=>a.error),statistics:values.length?stats(values):null};
      report.summaries.push(summary);summaries[side]=summary;
      console.log('summary '+loadingMode+' '+profile+' '+side+' '+cell.id+' collected='+values.length+'/'+samples+' '+cell.comparison);
      if(values.length!==samples)report.unperformed.push({id:cell.id,loadingMode,profile,side,missing:samples-values.length,reason:'Not successfully collected; never imputed or discarded'});
    }
    if(cell.comparison==='like-for-like'&&sides.every(side=>summaries[side].completed===samples)){
      const b=summaries.baseline.statistics,c=summaries.candidate.statistics,delta=c.median-b.median,relative=b.median?delta/b.median:null;
      assert.ok(relative!==null,'Zero comparable baseline median is invalid, never fabricated');
      report.comparisons.push({id:cell.id,loadingMode,profile,baseline:b,candidate:c,deltaMs:delta,relativeIncrease:relative,materialRegression:relative>.25&&delta>50,baselineVariable:b.rangeOverMedian>.25&&b.rangeMs>50,candidateVariable:c.rangeOverMedian>.25&&c.rangeMs>50});
    }
  }
  // Semantic source-row identity, not physical array position, binds the comparable action.
  for(const loadingMode of modes)for(const profile of profiles)for(const id of inventory.filter(c=>c.comparison==='like-for-like').map(c=>c.id)){
    const actions=report.rows.filter(r=>r.loadingMode===loadingMode&&r.profile===profile).flatMap(r=>r.actions.filter(a=>a.id===id&&a.complete));
    assert.equal(actions.length,2*samples,'Every comparable sample required');
    for(const a of actions){assert.equal(a.after.row,actions[0].after.row,'Same actual semantic source-row operation in both roots');assert.equal(a.after.scenario,actions[0].after.scenario);assert.equal(a.before.indexOpen,profile==='index-open');assert.equal(a.after.indexOpen,profile==='index-open');}
  }
  assert.equal(report.rows.length,12*samples);assert.ok(report.rows.every(row=>row.complete)&&!report.unperformed.length&&!report.errors.length,'Incomplete collection; all failures retained');
  report.complete=true;report.status='complete';
}catch(e){report.status='failed';report.errors.push({phase:'collection',error:errorText(e)});}
finally{
  if(browser)try{await browser.close();}catch(e){report.errors.push({phase:'browser-close',error:errorText(e)});}
  if(server)try{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}catch(e){report.errors.push({phase:'server-close',error:errorText(e)});}
  if(report.identities.before)try{report.identities.after=identity();assert.deepEqual(report.identities.after,report.identities.before,'Frozen source, standalone, runner, runtime, Playwright or Chromium changed');report.sourceUnchanged=true;}catch(e){report.sourceUnchanged=false;report.errors.push({phase:'final-identity',error:errorText(e)});}
  if(lockFd!==undefined)try{fs.closeSync(lockFd);fs.unlinkSync(lockPath);}catch(e){report.errors.push({phase:'lock-release',error:errorText(e)});}
  report.unperformed=[];
  for(const planned of schedule){
    const row=report.rows.find(r=>r.globalOrder===planned.globalOrder);
    for(const cell of inventory.filter(c=>c.comparison==='like-for-like'||planned.side==='candidate')){
      const action=row?.actions.find(a=>a.id===cell.id);
      if(!action?.complete)report.unperformed.push({...planned,id:cell.id,comparison:cell.comparison,attempted:!!action,reason:action?.error||row?.error||'Not reached; no timing imputed'});
    }
  }
  if(report.errors.length){report.status='failed';report.complete=false;}
  const flags=report.comparisons.filter(c=>c.materialRegression||c.baselineVariable||c.candidateVariable);
  report.exitCode=report.complete?(flags.length?2:0):1;
  report.latencyDisposition=report.complete?(flags.length?'comparable-review-required':'no-current-comparable-material-or-variation-flags'):'incomplete';
  report.candidateOnlyDisposition='descriptive-not-like-for-like; no acceptance/regression/waiver inferred';
  report.counts={contexts:{expected:12*samples,attempted:report.rows.length,completed:report.rows.filter(r=>r.complete).length},actions:{expected:114*samples,attempted:report.rows.reduce((n,r)=>n+r.actions.length,0),completed:report.rows.reduce((n,r)=>n+r.actions.filter(a=>a.complete).length,0)},finiteCells:102,comparableCells:12,candidateOnlyCells:90,flaggedComparableCells:flags.length,errors:report.errors.length,unperformed:report.unperformed.length};
  report.elapsedMs=performance.now()-started;report.finishedAt=new Date().toISOString();save();process.exitCode=report.exitCode;
}
console.log(JSON.stringify({report:reportPath,status:report.status,exitCode:report.exitCode,counts:report.counts,candidateOnlyDisposition:report.candidateOnlyDisposition}));
