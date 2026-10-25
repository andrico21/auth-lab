import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {seekNativeRange} from './dnssec-native-controls.mjs';

// Native input only. Browser evaluation reads state, identity, focus and geometry.
const help = `Usage: bun tools/verification/run-dnssec-correction-native.mjs
  --root CHECKOUT --out NEW_DIRECTORY --reference CORRECTED_REFERENCE.json
  --checkpoint-report CORRECTED_SOURCE_STATUS.json --worksheet WORKSHEET.json
  --playwright INDEX.mjs --chrome CHROME --xvfb XVFB --xdotool XDOTOOL --scrot SCROT
  [--suite smoke|all]
Both suites run the complete targeted correction matrix, not the old native matrix.
The output directory must not exist. No build, installation or performance collection.
Requires an isolated private /tmp for X11 (use the recorded bwrap runtime pattern).
External RFC navigation is observed and blocked, not replaced by fabricated content.
`;
if (process.argv.includes('--help')) { console.log(help); process.exit(0); }
const options = {suite: 'all'};
for (let i = 2; i < process.argv.length; i++) {
  const [key, inline] = process.argv[i].replace(/^--/, '').split(/=(.*)/s);
  assert.ok(['root','out','reference','checkpoint-report','worksheet','playwright','chrome','xvfb','xdotool','scrot','suite'].includes(key), 'Unknown option ' + key);
  const value = inline ?? process.argv[++i]; assert.ok(value && !value.startsWith('--'), 'Missing ' + key);
  assert.ok(!Object.hasOwn(options, key) || key === 'suite', 'Duplicate ' + key);
  options[key] = key === 'suite' ? value : path.resolve(value);
}
for (const key of ['root','out','reference','checkpoint-report','worksheet','playwright','chrome','xvfb','xdotool','scrot']) assert.ok(options[key], 'Required --' + key);
assert.ok(['smoke','all'].includes(options.suite));
const root = fs.realpathSync(options.root), out = options.out;
fs.mkdirSync(out, {recursive: false});
const runner = fileURLToPath(import.meta.url), controls = fileURLToPath(new URL('./dnssec-native-controls.mjs', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const digest = filename => { assert.ok(fs.lstatSync(filename).isFile(), 'Regular input ' + filename); const bytes = fs.readFileSync(filename); return {sha256: sha(bytes), bytes: bytes.length}; };
const write = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');
const append = (name, value) => fs.appendFileSync(path.join(out, name), JSON.stringify(value) + '\n');
const report = {schemaVersion: 1, kind: 'DNSSEC-correction-targeted-native', startedAt: new Date().toISOString(), argv: process.argv, options,
  status: 'running', passed: false, complete: false, cells: {required: 0, attempted: 0, passed: 0, failed: 0, unperformed: 0}, matrix: [], screenshots: [], failures: [], subprocesses: [], sessions: [],
  scope: 'Rendered canonical DNS correction controls in three loading modes; 390px trusted touch and genuine headed Chrome 200% zoom. Not the prior full native matrix, latency collector or independent semantic oracle.',
  notEstablished: ['Human screen-reader G01 acceptance', 'Six current performance conditions, seven historical flags, six P0 variable conditions or waivers', 'Native/live DNS or cryptographic conformance', 'Astra acceptance, release or publication approval', 'RFC remote content availability: genuine link navigation is opened but external requests are blocked']};
const save = () => write('native-status.json', report);
const reference = JSON.parse(fs.readFileSync(options.reference)), checkpoint = JSON.parse(fs.readFileSync(options['checkpoint-report']));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'docs/dnssec-expansion/scenario-manifest.json')));
const labelSelectionPath=path.join(root,'docs/verification/dnssec-review-corrections/chapter-label-selection-01.json');
const labelSelection=JSON.parse(fs.readFileSync(labelSelectionPath));
const labelInventoryPath=path.join(root,labelSelection.input.path);
const selectedWorstChapters=[['lab-dnssec16','dsync-notify-trigger'],['lab-dnssec02','equivalent-presentation'],['lab-dnssec05','response-flags-and-cached-ad']].map(([id,caseId])=>{
  const selected=labelSelection.top.find(row=>row.runtimeId===id&&row.caseId===caseId);assert.ok(selected,'Captured worst-label selection '+id+'/'+caseId);return selected;
});
let browser, server, xvfb, origin, display, active;
let sequence = 0;
const zoomStates = new WeakMap();
function files(directory) { return fs.readdirSync(path.join(root, directory), {withFileTypes: true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(entry => { assert.ok(!entry.isSymbolicLink()); const name=directory+'/'+entry.name; return entry.isDirectory()?files(name):[name]; }); }
function identity() { return {sourceFiles: Object.fromEntries(['index.html','build.mjs','package.json','security-policy.mjs',...files('src'),...files('assets'),...files('tests')].sort().map(name=>[name,digest(path.join(root,name)).sha256])), standalone: digest(path.join(root,'dist/auth-flow-studio.html')), worksheet: digest(options.worksheet), reference: digest(options.reference), checkpoint: digest(options['checkpoint-report']), runner: digest(runner), controls: digest(controls), chrome: digest(options.chrome), playwright: digest(options.playwright), chapterLabelSelection:digest(labelSelectionPath), chapterLabelInventory:digest(labelInventoryPath)}; }
function validateInputs() {
  assert.equal(reference.kind,'DNSSEC-canonical-source-prefix-reference'); assert.equal(reference.passed,true); assert.equal(reference.complete,true);
  assert.equal(checkpoint.kind,'DNSSEC-independent-contract-check'); assert.equal(checkpoint.mode,'source'); assert.equal(checkpoint.passed,true); assert.equal(checkpoint.sourceUnchanged,true); assert.deepEqual(checkpoint.failures,[]);
  assert.equal(reference.cases.length,159); assert.equal(checkpoint.cases.length,159);
  for (const [name,hash] of Object.entries(reference.identities.sourceFiles)) assert.equal(report.before.sourceFiles[name],hash,'Corrected source ' + name);
  assert.deepEqual(checkpoint.inputIdentity.review.sourceFiles,reference.identities.sourceFiles);
  for (const [actual, expected] of [[report.before.standalone.sha256,reference.identities.standaloneSha256],[report.before.worksheet.sha256,reference.identities.worksheetSha256],[checkpoint.htmlSha256,reference.identities.standaloneSha256],[checkpoint.worksheetSha256,reference.identities.worksheetSha256]]) assert.equal(actual,expected);
}
function command(program, argv) {
  const n=report.subprocesses.length+1, result=spawnSync(program,argv,{env:{...process.env,DISPLAY:display},encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
  fs.writeFileSync(path.join(out,`subprocess-${n}.stdout`),result.stdout||''); fs.writeFileSync(path.join(out,`subprocess-${n}.stderr`),result.stderr||'');
  report.subprocesses.push({program,argv,status:result.status,signal:result.signal,error:result.error?String(result.error):null}); assert.equal(result.status,0,'Native subprocess '+program); return result.stdout.trim();
}
const frames = page => page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
async function zoom(page, force=false) {
  const state=zoomStates.get(page); if(!state || (!force && state.url===page.url())) return;
  const observation={kind:'genuine-zoom',baseline:state.baseline,previousURL:state.url,url:page.url(),windowId:state.windowId,keys:'Escape; single Ctrl+plus preconditioning nudge; Ctrl+0 observed baseline; Ctrl+plus x5; Escape',passed:false};
  const measure=()=>page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth,url:location.href,focused:document.hasFocus(),active:document.activeElement?.id}));
  try{
    await page.bringToFront();
    command(options.xdotool,['windowfocus','--sync',state.windowId]);
    command(options.xdotool,['key','--clearmodifiers','Escape']);
    observation.before=await measure();observation.resetWindow=command(options.xdotool,['getwindowfocus']);assert.equal(observation.resetWindow,state.windowId,'Owned main X window receives reset shortcut');
    // A real non-idempotent zoom nudge makes the subsequent Ctrl+0 reset
    // observable after file hash navigation. Prior failed controls and the
    // measured workaround are retained in native-probe-01 through -04.
    command(options.xdotool,['key','--clearmodifiers','ctrl+plus']);
    await page.waitForFunction(before=>Math.abs(devicePixelRatio-before)>.025,observation.before.dpr);
    observation.preconditioningNudge=await measure();
    command(options.xdotool,['key','--clearmodifiers','ctrl+0']);
    await page.waitForFunction(base=>Math.abs(devicePixelRatio/base-1)<.025,state.baseline.dpr);
    observation.zero=await measure();
    command(options.xdotool,['windowfocus','--sync',state.windowId]);
    observation.zoomWindow=command(options.xdotool,['getwindowfocus']);assert.equal(observation.zoomWindow,state.windowId,'Owned main X window receives actual zoom shortcuts');
    observation.plusSteps=[];
    for(let i=0;i<5;i++){command(options.xdotool,['key','--clearmodifiers','ctrl+plus']);await frames(page);observation.plusSteps.push({press:i+1,...await measure()});}
    await page.waitForFunction(base=>Math.abs(devicePixelRatio/base-2)<.025,state.baseline.dpr);
    command(options.xdotool,['key','--clearmodifiers','Escape']);
    await frames(page);observation.actual=await measure();
    assert.equal(observation.actual.scale,1,'Not pinch/CSS/CDP zoom');
    state.url=page.url();observation.passed=true;
  }catch(error){observation.error=error.stack||String(error);observation.failureMetrics=await measure().catch(e=>({error:String(e)}));throw error;}
  finally{append('browser-events.jsonl',observation);}
}
async function settle(page) { await frames(page); await zoom(page); await frames(page); }
async function click(page,selector,touch=false) { await settle(page); const target=page.locator(selector).first(); if(touch)await target.tap();else await target.click(); append('browser-events.jsonl',{kind:'trusted-input',mechanism:touch?'touch-tap':'mouse-click',selector,url:page.url()}); await settle(page); }
async function seek(page,value) { await settle(page); await seekNativeRange(page,value,{click:selector=>click(page,selector,active.touch),record:e=>append('browser-events.jsonl',e)}); await settle(page); }
async function tabTo(page,selector,start='#reset') {
  await page.locator(start).focus();
  for(let i=0;i<240;i++) { await page.keyboard.press('Tab'); if(await page.locator(selector).first().evaluate(e=>e===document.activeElement)) { const found=await page.locator(selector).first().evaluate(e=>({focusVisible:e.matches(':focus-visible'),text:e.textContent})); assert.equal(found.focusVisible,true); append('browser-events.jsonl',{kind:'tab-reached',selector,tabs:i+1,...found}); return found; } }
  assert.fail('Native Tab did not reach '+selector);
}
async function workspace(page,name) { await page.locator('#workspace-search').fill(name); await click(page,'[data-workspace-option='+JSON.stringify('workspace-'+name.toLowerCase())+']',active.touch); }
const entryFor=(id,caseId)=>{const entry=reference.cases.find(e=>e.id===id&&(!caseId?e.variant==='default':e.caseId===caseId));assert.ok(entry,'Canonical case '+id+'/'+caseId);return entry;};
async function choose(page,id,caseId) {
  const entry=id.startsWith('lab-dnssec')?entryFor(id,caseId):{id,variant:'default'};
  await page.locator('#lab-scenario-search').fill(id); await click(page,'[data-scenario-option='+JSON.stringify(id)+']',active.touch);
  if(entry.variant!=='default') {
    if(await page.locator('#lesson-reference').getAttribute('open')===null)await click(page,'#lesson-reference > summary',active.touch);
    const control=page.locator('#lesson-case'),values=await control.locator('option').evaluateAll(es=>es.map(e=>e.value)); const index=values.indexOf(entry.variant);assert.ok(index>=0);
    await control.focus();await page.keyboard.press('Home');for(let i=0;i<index;i++)await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');await page.keyboard.press('Escape');assert.equal(await control.inputValue(),entry.variant,'Closing the native select popup preserves the chosen variant');await settle(page);
  }
  const actual=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {id:a.labScenarioId,caseId:a.labModel.caseId,variant:a.lessonVariant};});
  assert.equal(actual.id,id);assert.equal(actual.variant,entry.variant);if(entry.caseId)assert.equal(actual.caseId,entry.caseId);
  return entry;
}
async function observe(page,entry) {
  const actual=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),f=a.heldView.snapshot();return {cursor:f.cursor,state:a.protocolSnapshot().state,holdings:f.holdings.map(h=>({artifactId:h.artifactId,actorId:h.actorId,store:h.store,representationId:h.representationId,holdingId:h.holdingId})).sort((a,b)=>a.holdingId.localeCompare(b.holdingId))};});
  const prefix=entry.prefixes.find(p=>p.eventIndex===actual.cursor.eventIndex&&p.milestone===actual.cursor.milestone);assert.ok(prefix,'Canonical current cursor '+JSON.stringify(actual.cursor));
  assert.equal(sha(JSON.stringify(actual.state)),prefix.stateSha256,'Canonical source state');assert.equal(sha(JSON.stringify(actual.holdings)),prefix.holdingsSha256,'Canonical source custody');
  if(entry.id==='lab-dnssec05'&&entry.caseId==='validating-stub'){
    const privateEvidence=await page.evaluate(()=>document.querySelector('auth-flow-studio').labModel.dnssecInventory.artifacts.filter(a=>a.creator==='dnsStub'&&a.type==='dns-trust').map(a=>a.artifactId));
    assert.equal(actual.holdings.some(h=>privateEvidence.includes(h.artifactId)&&h.actorId==='dnsResolver'),false,'Unsent stub verdict never enters resolver custody, including rewind');
    const cacheId=actual.state.dnssec.resultCacheArtifact;
    if(cacheId)assert.equal(actual.holdings.some(h=>h.artifactId===cacheId&&h.actorId==='dnsResolver'),false,'Independent stub cache never enters resolver custody');
  }
  return actual;
}
async function comparison(page,entry) {
  const canonical=await observe(page,entry);
  const rendered=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.protocolSnapshot().state.dnssec,cell=(r,n)=>r.querySelector('[data-dnssec-hop-cell="'+n+'"]').textContent.replace(/\s+/g,' ').trim();return {hops:s.response.traceHops||[],actors:Object.fromEntries(Object.keys(a.labModel.actors()).map(id=>[id,a.actor(id).name])),rows:[...a.querySelectorAll('[data-dnssec-hop-id]')].map(r=>({id:r.dataset.dnssecHopId,...Object.fromEntries(['identity','query','response','delivery','owner'].map(n=>[n,cell(r,n)]))})),contexts:[...a.querySelectorAll('[data-dnssec-cache-context]')].map(r=>({id:r.dataset.dnssecCacheContext,hopId:r.hasAttribute('data-dnssec-hop-id'),...Object.fromEntries(['identity','query','response','delivery','owner'].map(n=>[n,cell(r,n)]))}))};});
  assert.deepEqual(rendered.rows.map(r=>r.id),rendered.hops.map(h=>h.id),'No future hops or invented cache packets');
  for(const [index,hop] of rendered.hops.entries()) {
    const row=rendered.rows[index];assert.ok(row.identity.includes(hop.id));assert.ok(row.identity.includes(hop.question.qtype));
    for(const side of ['query','response']) { const packet=hop[side];if(!packet){assert.match(row[side],/pending|not received/i);continue;}for(const flag of ['AD','CD'])assert.match(row[side],new RegExp(flag+'='+packet.flags[flag]+'(?:\\b|$)'));assert.ok(row[side].includes(packet.edns.present?'DO='+packet.edns.DO:'OPT absent')); }
    const attempts=hop.attempts||[{query:hop.query,response:hop.response}];
    assert.equal((row.query.match(/AD=/g)||[]).length,attempts.length,'Exactly the current canonical attempt count is rendered');
    for(const attempt of attempts){
      assert.ok(row.identity.includes(attempt.query.id),'Every actual query event ID is rendered');
      const flags='AD='+attempt.query.flags.AD+' / CD='+attempt.query.flags.CD+' / '+(attempt.query.edns.present?'DO='+attempt.query.edns.DO:'OPT absent');
      assert.ok(row.query.includes(flags),'Own query flag set is rendered for each actual attempt');
    }
    assert.ok(row.delivery.includes(hop.response?.rcode||'Pending'));assert.ok(row.owner.length);
    if(hop.checkingOwner)assert.ok(row.owner.includes(rendered.actors[hop.checkingOwner]),'Readable checking owner');
    if(hop.relianceOwner)assert.ok(row.owner.includes(rendered.actors[hop.relianceOwner]),'Readable reliance owner');
  }
  for(const context of rendered.contexts)assert.equal(context.hopId,false);
  return {cursor:canonical.cursor,canonicalStateSha256:sha(JSON.stringify(canonical.state)),holdingsSha256:sha(JSON.stringify(canonical.holdings)),...rendered};
}
async function targets(page) { return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),c=a.studyClock();return c.steps.map((s,i)=>({id:s.id,value:Math.max(1,Math.min(999,Math.round((c.offsets[i]+c.durations[i]*.5)/c.total*1000)))}));}); }
async function replay(page,entry,kind,compare=true) {
  const rows=await targets(page),result=[];assert.ok(rows.length);assert.equal(new Set(rows.map(r=>r.value)).size,rows.length,'No quantized row omissions');
  for(const direction of ['forward','backward'])for(const target of direction==='forward'?[{value:0},...rows,{value:1000}]:[{value:1000},...rows.slice().reverse(),{value:0}]){
    await seek(page,target.value);if(target.id)assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.snapshot().step?.id),target.id);
    const observation=compare?await comparison(page,entry):await observe(page,entry);result.push({direction,...target,...observation});
  }
  append('observations.jsonl',{kind:'replay',id:entry.id,caseId:entry.caseId,replay:kind,observations:result});return {kind,availableRows:rows.length,observations:result.length};
}
async function fieldReplay(page,entry) {
  await seek(page,1000);await click(page,'#index-open',active.touch);
  const name=await page.evaluate(()=>document.querySelector('auth-flow-studio').definition('dnssec_header_flags_CD').name);await page.locator('#attribute-search').fill(name);
  await click(page,'#attribute-index-toggle',active.touch);assert.equal(await page.locator('#attribute-index').isVisible(),false);
  await choose(page,'lab-dnssec05','unaware-stub');await choose(page,entry.id,entry.caseId);await seek(page,1000);
  await click(page,'#index-open',active.touch);
  assert.equal(await page.locator('#attribute-search').inputValue(),name,'Hidden index preserves current query');
  const target=page.locator('[data-index-attribute="dnssec_header_flags_CD"]');
  assert.equal(await target.getAttribute('aria-pressed'),'false','Reopened index has no stale prior selection');
  const reopened={query:await page.locator('#attribute-search').inputValue(),field:await target.innerText(),meta:await page.locator('#attribute-index-meta').innerText(),currentCase:entry.caseId};
  await click(page,'[data-index-attribute="dnssec_header_flags_CD"]',active.touch);
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').attributeSelection),'dnssec_header_flags_CD');
  await click(page,'#attribute-index-toggle',active.touch);await seek(page,1000);await click(page,'#index-open',active.touch);
  assert.equal(await target.getAttribute('aria-pressed'),'true','Reopened index reflects current selected replay');
  append('observations.jsonl',{kind:'hidden-index-reopen-current-contents',...reopened,selectedAfterReopen:true});
  const result=await replay(page,entry,'field-only-dnssec_header_flags_CD');await click(page,'[data-clear-trace]',active.touch);await click(page,'#reset',active.touch);assert.equal((await comparison(page,entry)).rows.length,0);return result;
}
async function screenshot(page,label) {
  const name=String(++sequence).padStart(3,'0')+'-'+label.replace(/[^a-zA-Z0-9_.-]/g,'-')+'.png',state=zoomStates.get(page);
  if(state){await page.bringToFront();command(options.xdotool,['windowfocus','--sync',state.windowId]);command(options.xdotool,['key','--clearmodifiers','Escape']);await frames(page);command(options.scrot,[path.join(out,name)]);}
  else await page.screenshot({path:path.join(out,name),fullPage:false});
  report.screenshots.push({file:name,mechanism:state?'scrot-native-X11-pixels':'Chromium-page-screenshot',...digest(path.join(out,name))});return name;
}
async function cell(key,page,run) {
  const row=report.matrix.find(r=>r.key===key);assert.ok(row&&row.status==='unperformed');row.status='running';report.cells.attempted++;
  try{row.observed=await run();row.status='passed';report.cells.passed++;}
  catch(error){row.status='failed';row.error=error.stack||String(error);report.cells.failed++;report.failures.push({key,error:row.error});try{row.screenshot=await screenshot(page,'failed-'+key);}catch{} }
  save();return row.status==='passed';
}
async function chapters(page,id,caseId) {
  await choose(page,id,caseId);
  const authored=await page.evaluate(()=>document.querySelector('auth-flow-studio').labModel.chapters.map(c=>({id:c.id,label:c.label,enabled:!!c.stepIds.length,stepId:c.stepIds[0]})));
  const observations=[];
  for(const chapter of authored){
    const selector='[data-lesson-chapter='+JSON.stringify(chapter.id)+']',button=page.locator(selector);await button.scrollIntoViewIfNeeded();await settle(page);
    const geometry=await button.evaluate(e=>{const box=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};},range=document.createRange();range.selectNodeContents(e);const style=getComputedStyle(e);return {text:e.textContent,button:box(e),panel:box(e.closest('.map-panel')),controls:box(e.closest('#lesson-chapters')),textRects:[...range.getClientRects()].filter(r=>r.width&&r.height).map(r=>({left:r.left,right:r.right,top:r.top,bottom:r.bottom})),viewport:{width:innerWidth,height:innerHeight},whiteSpace:style.whiteSpace,lineHeight:style.lineHeight};});
    assert.equal(geometry.text,chapter.label+(chapter.enabled?'':' - not reached in this case'),'Full unabridged chapter label');
    const inside=(r,b)=>r.left>=b.left-1&&r.right<=b.right+1&&r.top>=b.top-1&&r.bottom<=b.bottom+1;
    assert.ok(inside(geometry.button,{left:0,right:geometry.viewport.width,top:0,bottom:geometry.viewport.height}),'Button viewport bounds');assert.ok(inside(geometry.button,geometry.panel),'Button panel bounds');assert.ok(inside(geometry.button,geometry.controls),'Button controls bounds');
    assert.ok(geometry.textRects.length);for(const r of geometry.textRects){assert.ok(inside(r,geometry.button),'Text Range within button');assert.ok(inside(r,geometry.panel),'Text Range within panel');assert.ok(inside(r,{left:0,right:geometry.viewport.width,top:0,bottom:geometry.viewport.height}),'Text Range within viewport');}assert.ok(geometry.button.height>=44);
    if(chapter.enabled){await tabTo(page,selector);await page.keyboard.press('Enter');await settle(page);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').graphChapter.id),chapter.id);if(active.touch){await click(page,selector,true);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').graphChapter.id),chapter.id);}}
    observations.push({chapter,...geometry});
  }
  return {id,caseId,chapters:observations};
}
async function alignment(page) {
  await click(page,'#reset',active.touch);const before=await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status);
  const box=await page.locator('#play').boundingBox();assert.ok(box);await click(page,'#play',active.touch);const during=await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status);assert.equal(during,'playing');await click(page,'#play',active.touch);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'paused');
  return {before,during,after:'paused',button:box,mechanism:active.touch?'trusted-touch':'trusted-pointer',dpr:await page.evaluate(()=>devicePixelRatio)};
}
async function disclosures(page,entry) {
  await choose(page,entry.id,entry.caseId);await seek(page,1000);
  const summary='.dnssec-decision-details summary';await tabTo(page,summary);await page.keyboard.press('Enter');assert.ok(await page.locator('.dnssec-decision-details').getAttribute('open')!==null);
  await page.keyboard.press('Tab');const raw=await page.locator('.dnssec-decision-details').innerText();assert.match(raw,/dnsValidator|dnsStub|dnsUpstream/);
  await tabTo(page,'.dnssec-hop-comparison [tabindex="0"]');
  const region=await page.locator('.dnssec-hop-comparison [tabindex="0"]').evaluate(e=>({role:e.getAttribute('role'),label:e.getAttribute('aria-label'),focus:e===document.activeElement}));assert.equal(region.role,'region');assert.ok(region.label);assert.equal(region.focus,true);
  // Native Space starts playback from reset; focus is then reached by genuine Tab.
  await click(page,'#reset',active.touch);await click(page,'#play',active.touch);await tabTo(page,summary);
  const cursorBefore=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor);
  await page.waitForFunction(before=>JSON.stringify(document.querySelector('auth-flow-studio').heldView.snapshot().cursor)!==JSON.stringify(before),cursorBefore,{timeout:15000});
  assert.equal(await page.locator(summary).evaluate(e=>e===document.activeElement),true,'Disclosure focus survives playback redraw');
  await tabTo(page,'.dnssec-hop-comparison [tabindex="0"]',summary);const comparisonCursor=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor);
  await page.waitForFunction(before=>JSON.stringify(document.querySelector('auth-flow-studio').heldView.snapshot().cursor)!==JSON.stringify(before),comparisonCursor,{timeout:15000});
  assert.equal(await page.locator('.dnssec-hop-comparison [tabindex="0"]').evaluate(e=>e===document.activeElement),true,'Comparison focus survives playback redraw');await click(page,'#play',active.touch);
  return {raw,region,disclosureFocusPreserved:true,comparisonFocusPreserved:true};
}
async function sourceLink(page) {
  const entry=await choose(page,'lab-dnssec16');const panel=await page.locator('.dnssec-context-panel').innerText();assert.match(panel,/CSYNC/);assert.match(panel,/NS.*glue/is);assert.match(panel,/CDS.*CDNSKEY.*DS/is);assert.match(panel,/CSYNC.*(?:not|never).*DS/is);assert.match(panel,/parent.*(?:policy|decision|authentication)/is);
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').attributeSelection),null);
  const sourceLabel='CDNSKEY - public-key intent for DS source 6',target=()=>page.getByRole('link',{name:sourceLabel,exact:true});
  assert.equal(await target().count(),1,'Exact non-first field source is unambiguous');assert.equal(await target().getAttribute('href'),'https://www.rfc-editor.org/rfc/rfc7477.html');
  const sourceKey=await target().getAttribute('data-dnssec-source-key');assert.ok(sourceKey);
  const selector='.dnssec-context-panel a[data-dnssec-source-key='+JSON.stringify(sourceKey)+']';await tabTo(page,selector);
  const popupPromise=page.waitForEvent('popup');await page.keyboard.press('Enter');const popup=await popupPromise;
  await popup.waitForLoadState('domcontentloaded').catch(()=>{});const navigation=active.external.find(e=>e.url==='https://www.rfc-editor.org/rfc/rfc7477.html');assert.ok(navigation,'Genuine source-link navigation requested RFC7477');await popup.close();await page.bringToFront();
  assert.equal(await target().evaluate(e=>e===document.activeElement),true,'Exact initiating CDNSKEY source retains focus after popup close');
  await click(page,'#play',active.touch);await tabTo(page,selector);const cursor=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor);
  await page.waitForFunction(before=>JSON.stringify(document.querySelector('auth-flow-studio').heldView.snapshot().cursor)!==JSON.stringify(before),cursor,{timeout:15000});
  assert.equal(await target().evaluate(e=>e===document.activeElement),true,'Exact non-first CDNSKEY source focus survives redraw');await click(page,'#play',active.touch);
  await page.keyboard.press('Escape');await tabTo(page,selector);
  return {entry:entry.caseId,panel,sourceKey,sourceLabel,href:navigation.url,openedPopup:true,remoteContentFetched:false,focusRetained:true,screenshot:await screenshot(page,active.mode+'-'+active.kind+'-DNS16-CSYNC')};
}
async function behavior(page) {
  for(const caseId of ['unaware-stub','ad-interest-without-do','response-flags-and-cached-ad'])await cell(active.mode+'-flags-'+caseId,page,async()=>{const entry=await choose(page,'lab-dnssec05',caseId);await seek(page,1000);const result=await comparison(page,entry),stub=result.rows.find(r=>r.id==='lab-dnssec05:stub');assert.ok(stub);
    if(caseId==='unaware-stub'){assert.match(stub.query,/OPT absent/);assert.match(stub.response,/OPT absent/);}else if(caseId==='ad-interest-without-do'){assert.match(stub.query,/DO=0/);assert.match(stub.response,/DO=0/);}else{const state=(await observe(page,entry)).state.dnssec;assert.equal(state.received,false);assert.equal(state.returnedToStub,true);assert.equal(state.transport.authorityQueries,0);const text=await page.locator('#lesson-decisions').innerText();assert.match(text,/Fresh authority data received\s+No/);assert.match(text,/Authenticated cache reused\s+Yes/);assert.match(text,/Response delivered to stub\s+Yes/);const packet=await readPacket(page,'lab-dnssec05:stub:r-message');checkTtl(packet,240,true);result.packet=packet;result.decisions=text;}return result;});
  await cell(active.mode+'-both-validate-replay',page,async()=>{const entry=await choose(page,'lab-dnssec06','both-validate');const full=await replay(page,entry,'full'),field=await fieldReplay(page,entry);await seek(page,1000);const result=await comparison(page,entry);for(const [from,to,ad,cd]of[['dnsStub','dnsResolver',1,0],['dnsResolver','dnsUpstream',1,1],['dnsUpstream','dnsChild',0,1]]){const hop=result.hops.find(h=>h.from===from&&h.to===to&&h.question.qtype==='A');assert.ok(hop);assert.deepEqual([hop.query.flags.AD,hop.query.flags.CD,hop.query.edns.DO],[ad,cd,1]);if(to==='dnsChild')assert.equal(hop.response.flags.CD,0);}return {full,field,final:result,screenshot:await screenshot(page,active.mode+'-DNS06-comparison')};});
  await cell(active.mode+'-cached-error-fresh-retry',page,async()=>{
    const entry=await choose(page,'lab-dnssec06','cached-upstream-servfail-cd-zero-then-cd-one');await seek(page,1000);
    const result=await comparison(page,entry);assert.ok(result.contexts.length);const context=result.contexts[0];
    assert.match(context.query,/CD=0/);assert.match(context.query,/AD.*not recorded.*DO.*not recorded/i);assert.match(context.delivery,/SERVFAIL/);assert.match(context.response,/not recorded/i);
    const hop=result.hops.find(h=>h.priorContextId===context.id);assert.ok(hop);const fresh=result.rows.find(r=>r.id===hop.id);assert.match(fresh.query,/CD=1/);assert.match(fresh.delivery,/NOERROR/);
    const failedEntry=await choose(page,'lab-dnssec06','forwarder-loop-or-unreachable');await seek(page,1000);const failed=await comparison(page,failedEntry);
    const group=failed.hops.find(h=>h.attempts?.length===3);assert.ok(group,'Three canonical failed forwarding attempts');
    assert.equal(group.delivery.attempts,3);assert.ok(group.attempts.every(a=>a.response===null),'No invented failed-hop response');
    const row=failed.rows.find(r=>r.id===group.id);assert.ok(row);
    for(const attempt of group.attempts)assert.ok(row.identity.includes(attempt.query.id),'All three actual failed-query IDs');
    for(const flag of ['AD','CD','DO'])assert.equal((row.query.match(new RegExp(flag+'=','g'))||[]).length,3,'Three actual query flag sets');
    assert.doesNotMatch(row.response,/NOERROR|SERVFAIL/);assert.match(row.response,/pending|not received/i);
    const rewind=await replay(page,failedEntry,'failed-attempt-prefix-forward-and-backward');
    await click(page,'#reset',active.touch);assert.equal((await comparison(page,failedEntry)).rows.length,0,'Reset contains no future attempts');
    return {retainedContextAndFreshRetry:result,failedAttempts:failed,rewind};
  });
  await cell(active.mode+'-stub-exact-custody',page,async()=>{const entry=await choose(page,'lab-dnssec05','validating-stub');await seek(page,1000);const final=await observe(page,entry),state=final.state.dnssec,cache=state.cacheEntries.find(e=>e.kind==='answer');assert.equal(cache.namespace.cacheOwner,'dnsStub');assert.equal(cache.namespace.checkingOwner,'dnsStub');assert.equal(cache.namespace.trustStore,'stub-public-v1');const cacheId=state.resultCacheArtifact;assert.ok(final.holdings.some(h=>h.artifactId===cacheId&&h.actorId==='dnsStub'));assert.equal(final.holdings.some(h=>h.artifactId===cacheId&&h.actorId==='dnsResolver'),false);
    const holding=final.holdings.find(h=>h.artifactId===cacheId&&h.actorId==='dnsStub');await click(page,'#held-objects [data-held-action="picker:dnsStub"]',active.touch);await click(page,'#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']',active.touch);assert.ok((await page.locator('#held-inspector').innerText()).includes(cacheId));await click(page,'[data-held-trace='+JSON.stringify(cacheId)+']',active.touch);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').objectTraceSelection),cacheId);const exact=await replay(page,entry,'stub-cache-exact-history',false);await click(page,'[data-clear-trace]',active.touch);await click(page,'#reset',active.touch);const reset=await observe(page,entry);assert.equal(reset.cursor.eventIndex,-1);assert.equal(reset.holdings.some(h=>h.artifactId===cacheId),false);return {cache,cacheId,exact,resetCursor:reset.cursor};});
  await cell(active.mode+'-nta-ttl299',page,async()=>{const entry=await choose(page,'lab-dnssec20','temporary-negative-trust-anchor');await seek(page,1000);await observe(page,entry);const packet=await readPacket(page,'lab-dnssec20:nta-active-stub:r-message');checkTtl(packet,299,true);return packet;});
  await cell(active.mode+'-no-rrsig',page,async()=>{const entry=await choose(page,'lab-dnssec05','ad-interest-without-do');await seek(page,1000);await observe(page,entry);const packet=await readPacket(page,'lab-dnssec05:stub:r-message');checkTtl(packet,300,false);return packet;});
  await cell(active.mode+'-readable-insecure-verdict',page,async()=>{
    const entry=await choose(page,'lab-dnssec03','proved-no-ds');await seek(page,1000);await observe(page,entry);
    const text=await page.locator('#lesson-decisions').innerText();assert.match(text,/authenticated.*unsigned delegation.*insecure/is);assert.match(text,/secure-only.*refus/is);assert.match(text,/not.*forg/is);
    const rollover=await choose(page,'lab-dnssec12','old-key-removed-too-early'),rows=await targets(page),target=rows.find(r=>r.id.endsWith(':declare-cached-answer-revalidation-policy'));assert.ok(target,'Authored explicit selected revalidation event');
    await seek(page,target.value);await observe(page,rollover);
    const progressive=page.locator('.progressive-fields > summary');if(await progressive.count()&&await progressive.first().isVisible())await click(page,'.progressive-fields > summary',active.touch);
    const long=page.locator('.long-protocol-value > summary');for(let i=0;i<await long.count();i++)if(await long.nth(i).isVisible())await long.nth(i).click();
    const rendered=await page.locator('#inspector').innerText();assert.match(rendered,/deliberately recheck|deliberately revalidate/is);assert.match(rendered,/ordinary secure.cache reuse.*continue.*deadline/is);assert.match(rendered,/withdrawing.*DNSKEY.*does not revoke/is);
    return {text,C03:{caseId:rollover.caseId,event:target.id,rendered,screenshot:await screenshot(page,active.mode+'-DNS12-selected-revalidation')}};
  });
  await cell(active.mode+'-keyboard-focus-disclosures',page,()=>disclosures(page,entryFor('lab-dnssec06','both-validate')));
}
async function readPacket(page,id) { return page.evaluate(id=>{const a=document.querySelector('auth-flow-studio'),artifact=a.labModel.dnssecInventory.artifacts.find(o=>o.artifactId===id);if(!artifact)throw Error('Missing actual packet '+id);const held=a.heldView.snapshot().holdings.filter(h=>h.artifactId===id);return {artifactId:id,held,packet:artifact.representations[0].fields.find(f=>f.attributeId.endsWith('_record')).value};},id); }
function checkTtl(observation,ttl,signed) { const p=observation.packet,rr=p.objects.find(o=>o.value.type==='A');assert.ok(rr);assert.equal(rr.value.ttl,ttl);assert.equal(p.receivedRrsetTtl,ttl);const sig=p.objects.find(o=>o.value.typeCovered===1);if(signed){assert.ok(sig);assert.equal(sig.value.ttl,ttl);assert.equal(p.receivedRrsigTtl,ttl);assert.equal(sig.value.originalTtl,3600);}else{assert.equal(sig,undefined);assert.equal(p.receivedRrsigTtl,null);} }
const modes=['source-http','standalone-http','standalone-file'];
const behaviorKeys=['flags-unaware-stub','flags-ad-interest-without-do','flags-response-flags-and-cached-ad','both-validate-replay','cached-error-fresh-retry','stub-exact-custody','nta-ttl299','no-rrsig','readable-insecure-verdict','keyboard-focus-disclosures'];
for(const mode of modes){for(const key of behaviorKeys)report.matrix.push({key:mode+'-'+key,status:'unperformed'});for(const kind of ['touch390','zoom200'])for(const key of ['alignment','DNS-chapters','legacy-chapters','comparison','source-link'])report.matrix.push({key:mode+'-'+kind+'-'+key,status:'unperformed'});}
report.cells.required=report.matrix.length;
async function attach(mode,kind) {
  const touch=kind==='touch390',context=await browser.newContext(kind==='zoom200'?{viewport:null}:{viewport:{width:touch?390:1480,height:touch?844:1000},hasTouch:touch,isMobile:touch});
  const page=await context.newPage();active={context,page,mode,kind,touch,external:[],errors:[]};const session=active;report.sessions.push({mode,kind});
  await context.exposeBinding('dnsCorrectionKey',(_source,value)=>append('browser-events.jsonl',{kind:'trusted-keydown',mode,context:kind,...value}));
  await context.addInitScript(()=>document.addEventListener('keydown',e=>window.dnsCorrectionKey({key:e.key,code:e.code,ctrlKey:e.ctrlKey,shiftKey:e.shiftKey,altKey:e.altKey,metaKey:e.metaKey,isTrusted:e.isTrusted,active:document.activeElement?.id,url:location.href}),true));
  page.on('pageerror',error=>session.errors.push(String(error)));await context.route('**/*',async route=>{const u=new URL(route.request().url());if(['http:','https:'].includes(u.protocol)&&u.origin!==origin){session.external.push({url:u.href,resourceType:route.request().resourceType()});await route.abort();}else await route.continue();});
  const url=mode==='source-http'?origin+'/':mode==='standalone-http'?origin+'/dist/auth-flow-studio.html':pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href;await page.goto(url);await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView?.compiled());await frames(page);
  if(kind==='zoom200'){
    await page.bringToFront();const title='DNS Correction '+process.pid;await page.evaluate(t=>{document.title=t;},title);
    const ids=command(options.xdotool,['search','--sync','--onlyvisible','--name','^'+title]).split('\n');assert.equal(ids.length,1);
    command(options.xdotool,['windowfocus','--sync',ids[0]]);command(options.xdotool,['key','--clearmodifiers','Escape']);command(options.xdotool,['key','--clearmodifiers','ctrl+0']);await frames(page);
    const baseline=await page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth}));assert.equal(baseline.scale,1);
    append('browser-events.jsonl',{kind:'initial-native-reset',mode,windowId:ids[0],actual:baseline});
    zoomStates.set(page,{baseline,url:null,windowId:ids[0]});await zoom(page,true);
  }
  await workspace(page,'DNSSEC');return active;
}
async function startX() {
  const stdout=fs.openSync(path.join(out,'xvfb.stdout'),'wx'),stderr=fs.openSync(path.join(out,'xvfb.stderr'),'wx');xvfb=spawn(options.xvfb,['-displayfd','3','-screen','0','1600x1200x24','-nolisten','tcp','-ac'],{stdio:['ignore',stdout,stderr,'pipe'],env:process.env});fs.closeSync(stdout);fs.closeSync(stderr);
  display=await new Promise((resolve,reject)=>{let text='';const timer=setTimeout(()=>reject(Error('Private Xvfb allocation timeout')),15000);xvfb.once('error',e=>{clearTimeout(timer);reject(e);});xvfb.once('exit',code=>{clearTimeout(timer);reject(Error('Xvfb exited '+code));});xvfb.stdio[3].on('data',chunk=>{text+=chunk;if(/^\d+\n/.test(text)){clearTimeout(timer);resolve(':'+text.trim());}});});report.display={value:display,pid:xvfb.pid,xvfb:digest(options.xvfb)};
}
let cleanupPromise;
function cleanup() {
  return cleanupPromise ||= (async()=>{
    try{await active?.context.close();}catch{}
    try{await browser?.close();}catch{}
    if(server)await new Promise(resolve=>server.close(resolve));
    if(xvfb){
      xvfb.kill('SIGTERM');
      await new Promise(resolve=>{
        if(xvfb.exitCode!==null)resolve();
        else{xvfb.once('exit',resolve);setTimeout(()=>{if(xvfb.exitCode===null)xvfb.kill('SIGKILL');resolve();},5000).unref();}
      });
    }
  })();
}
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{
  report.failures.push({kind:'interrupted',signal});report.status='partial';save();void cleanup();
});
try {
  report.before=identity();validateInputs();for(const [source,name]of[[runner,'runner-input.mjs'],[controls,'controls-input.mjs'],[options.reference,'reference-input.json'],[options['checkpoint-report'],'checkpoint-input.json'],[options.worksheet,'worksheet-input.json']])fs.copyFileSync(source,path.join(out,name),fs.constants.COPYFILE_EXCL);save();
  assert.equal(report.before.chapterLabelInventory.sha256,labelSelection.input.sha256,'Captured inventory/selection binding');
  fs.copyFileSync(labelSelectionPath,path.join(out,'chapter-label-selection-input.json'),fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(labelInventoryPath,path.join(out,'chapter-label-inventory-input.json'),fs.constants.COPYFILE_EXCL);
  report.chapterLabelProvenance={selection:report.before.chapterLabelSelection,inventory:report.before.chapterLabelInventory,selectedWorstChapters,scope:'Earlier actual Source API inventory is selection provenance, not an independent oracle. Its captured source identities are preserved verbatim, not relabeled as the current frozen source. Native authored labels are compared anew at the current canonical build.'};
  const mime=file=>({'.js':'application/javascript','.mjs':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'})[path.extname(file)]||'text/html';
  server=http.createServer((req,res)=>{try{const name=decodeURIComponent(new URL(req.url,'http://localhost').pathname),file=path.resolve(root,'.'+(name==='/'?'/index.html':name));assert.ok(file.startsWith(root+path.sep));res.setHeader('Content-Type',mime(file));res.end(fs.readFileSync(file));}catch{res.statusCode=404;res.end('Not found');}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
  await startX();const {chromium}=await import(pathToFileURL(options.playwright).href);
  browser=await chromium.launch({executablePath:options.chrome,headless:false,env:{...process.env,DISPLAY:display},args:['--no-sandbox','--disable-dev-shm-usage','--ozone-platform=x11','--window-size=1480,1000','--no-first-run','--disable-background-networking','--disable-component-update']});report.browser=browser.version();
  for(const mode of modes){
    await attach(mode,'desktop');try{append('observations.jsonl',{kind:'desktop-trusted-pointer-alignment',mode,observed:await alignment(active.page)});await behavior(active.page);assert.deepEqual(active.errors,[]);}finally{await active.context.close();active=null;}
    for(const kind of ['touch390','zoom200']){
      await attach(mode,kind);const {page}=active;
      try{
        const aligned=await cell(mode+'-'+kind+'-alignment',page,()=>alignment(page));assert.ok(aligned,'Trusted pointer alignment is prerequisite to key acceptance; remaining context unperformed');
        await cell(mode+'-'+kind+'-DNS-chapters',page,async()=>{
          const results=[];for(const row of manifest.rows)results.push(await chapters(page,row.runtimeId));
          const worstVariants=[];
          for(const selected of selectedWorstChapters){
            const measured=await chapters(page,selected.runtimeId,selected.caseId),actual=measured.chapters.find(row=>row.chapter.id===selected.chapterId);
            assert.ok(actual,'Selected worst chapter is rendered');assert.equal(actual.text,selected.renderedLabel);assert.equal(actual.chapter.enabled,selected.enabled);
            worstVariants.push({...measured,selection:selected});
          }
          const longest=selectedWorstChapters[0];await choose(page,longest.runtimeId,longest.caseId);await tabTo(page,'[data-lesson-chapter='+JSON.stringify(longest.chapterId)+']');
          return {coverage:'Every chapter in all22 DNS defaults plus captured longest active and both longest disabled variants',results,worstVariants,longest,screenshot:await screenshot(page,mode+'-'+kind+'-longest-DNS')};
        });
        await cell(mode+'-'+kind+'-legacy-chapters',page,async()=>{await workspace(page,'MCP');const result=await chapters(page,'lab-mcp09');assert.ok(result.chapters.length>=2);await page.locator('#lesson-chapters').scrollIntoViewIfNeeded();const shot=await screenshot(page,mode+'-'+kind+'-MCP09-chapters');await workspace(page,'DNSSEC');return {...result,screenshot:shot};});
        await cell(mode+'-'+kind+'-comparison',page,async()=>{const entry=await choose(page,'lab-dnssec06','both-validate');await seek(page,1000);const result=await comparison(page,entry);await tabTo(page,'.dnssec-hop-comparison [tabindex="0"]');const region=await page.locator('.dnssec-hop-comparison [tabindex="0"]').evaluate(e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,width:innerWidth,overflow:getComputedStyle(e).overflowX};});assert.ok(region.left>=-1&&region.right<=region.width+1);await choose(page,'lab-dnssec06','both-validate');await tabTo(page,'[data-lesson-chapter="validation"]');const screenshotPath=await screenshot(page,mode+'-'+kind+'-DNS06-chapter-label');return {result,region,screenshot:screenshotPath};});
        await cell(mode+'-'+kind+'-source-link',page,()=>sourceLink(page));assert.deepEqual(active.errors,[]);
      }finally{await active.context.close();active=null;}
    }
  }
  report.complete=report.matrix.every(r=>r.status!=='unperformed'&&r.status!=='running');
}catch(error){report.failures.push({kind:'fatal',error:error.stack||String(error)});}
finally{
  await cleanup();
  try{report.after=identity();assert.deepEqual(report.after,report.before,'Unchanged source, HTML, worksheet, reference and native runner');report.identityUnchanged=true;}catch(error){report.failures.push({kind:'identity',error:error.stack||String(error)});}
  report.cells.unperformed=report.matrix.filter(r=>r.status==='unperformed'||r.status==='running').length;report.finishedAt=new Date().toISOString();report.passed=report.complete&&report.cells.failed===0&&report.cells.unperformed===0&&report.failures.length===0&&report.identityUnchanged;report.status=report.passed?'passed':report.cells.unperformed?'partial':'failed';save();process.exitCode=report.passed?0:1;console.log(JSON.stringify({status:report.status,cells:report.cells,screenshots:report.screenshots.length,out}));
}
