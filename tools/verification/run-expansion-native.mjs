#!/usr/bin/env bun
// Native acceptance only. No application imports, DOM adapter, downloads or live protocols.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
const help=`Usage: bun tools/verification/run-expansion-native.mjs [project-directory] [options]
Build first; this runner does not build or install anything.
Requires external Playwright (PLAYWRIGHT_MODULE or resolvable playwright) and Chromium
(CHROMIUM_EXECUTABLE or Playwright's installed executable). LD_LIBRARY_PATH is inherited.
Default: all manifest presets, all three modes, all three widths, deep checks and regressions.
Performance comparison additionally requires AUTH_LAB_EXPANSION_BASELINE_ROOT pointing
to the accepted 22242f2 checkout with its built dist; no benchmark runs during authoring.
  --jobs=1..4       Bounded concurrent mode workers (default 2)
  --mode=MODE       Diagnostic subset: source-http, standalone-http, standalone-file
  --id=ID          Diagnostic subset: one manifest preset (repeatable)
  --help           Show this help without loading browser dependencies
Evidence: AUTH_LAB_EXPANSION_EVIDENCE_DIR or docs/verification/expansion.
Every invocation gets a unique directory. Subsets are never reported as full acceptance.`;
if(process.argv.includes('--help')||process.argv.includes('-h')){console.log(help);process.exit(0);}
const args=process.argv.slice(2),positional=args.filter(arg=>!arg.startsWith('--'));
const root=path.resolve(positional[0]||path.join(here,'../..'));
const allModes=['source-http','standalone-http','standalone-file'],widths=[1920,1480,390];
const requestedIds=args.filter(arg=>arg.startsWith('--id=')).map(arg=>arg.slice(5));
const modes=args.some(arg=>arg.startsWith('--mode='))?args.filter(arg=>arg.startsWith('--mode=')).map(arg=>arg.slice(7)):allModes;
const jobs=Number(args.find(arg=>arg.startsWith('--jobs='))?.slice(7)||2);
assert.ok(Number.isInteger(jobs)&&jobs>=1&&jobs<=4,'--jobs must be 1..4');
assert.ok(modes.every(mode=>allModes.includes(mode)),'Unknown --mode');
assert.ok(args.every(arg=>!arg.startsWith('--')||/^--(?:jobs|mode|id)=/.test(arg)),'Unknown argument');
assert.ok(positional.length<=1,'Only one project directory is allowed');
const baselineRoot=process.env.AUTH_LAB_EXPANSION_BASELINE_ROOT?path.resolve(process.env.AUTH_LAB_EXPANSION_BASELINE_ROOT):null;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const runner=fileURLToPath(import.meta.url),manifestPath=path.join(root,'docs/expansion/plan-manifest.json');
const evidenceRoot=path.resolve(process.env.AUTH_LAB_EXPANSION_EVIDENCE_DIR||path.join(root,'docs/verification/expansion'));
fs.mkdirSync(evidenceRoot,{recursive:true});
const out=fs.mkdtempSync(path.join(evidenceRoot,new Date().toISOString().replace(/[:.]/g,'-')+'-native-'));
const report={kind:'expansion-native-acceptance',timestamp:new Date().toISOString(),nativeBrowser:true,passed:false,complete:false,runnerSha256:hash(fs.readFileSync(runner)),regenerationCommand:[process.execPath,...process.argv.slice(1)],environment:{PLAYWRIGHT_MODULE:process.env.PLAYWRIGHT_MODULE||null,CHROMIUM_EXECUTABLE:process.env.CHROMIUM_EXECUTABLE||null,LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH||null},runtime:{executable:process.execPath,version:process.version,bun:process.versions.bun||null,platform:process.platform,arch:process.arch},scope:{modes,widths,requestedIds,jobs},dependencies:{},modes:[],screenshots:[],failures:[],notEstablished:['Manual G01 remains open: real assistive-technology speech and user comprehension','Cross-engine acceptance','Live Windows, RADIUS, KDC or PAKE interoperability','Cryptographic vector correctness (separate offline QA)','Baseline HC01-HC09 acceptance (separate existing runners)']};
const save=()=>fs.writeFileSync(path.join(out,'expansion-native-status.json'),JSON.stringify(report,null,2)+'\n');
function identity(){
  const names=['index.html','build.mjs','package.json',...fs.readdirSync(path.join(root,'src')).filter(name=>/\.(js|css)$/.test(name)).sort().map(name=>'src/'+name)];
  const sources=Object.fromEntries(names.map(name=>[name,hash(fs.readFileSync(path.join(root,name)))]));
  const bytes=fs.readFileSync(path.join(root,'dist/auth-flow-studio.html'));
  return {sourceSnapshotSha256:hash(JSON.stringify(sources)),sources,manifestSha256:hash(fs.readFileSync(manifestPath)),worksheets:Object.fromEntries(['windows','network','kerberos-spake','pake'].map(name=>{const file='docs/expansion/'+name+'-scenarios.json';return [file,hash(fs.readFileSync(path.join(root,file)))];})),standalone:{sha256:hash(bytes),bytes:bytes.length}};
}
function packageIdentity(entry){
  let dir=path.dirname(entry);
  while(dir!==path.dirname(dir)){
    const file=path.join(dir,'package.json');
    if(fs.existsSync(file)){const pkg=JSON.parse(fs.readFileSync(file,'utf8'));return {entry,entrySha256:hash(fs.readFileSync(entry)),packageFile:file,packageSha256:hash(fs.readFileSync(file)),name:pkg.name,version:pkg.version};}
    dir=path.dirname(dir);
  }
  return {entry,entrySha256:hash(fs.readFileSync(entry)),version:null};
}
const representatives=['lab-win-ntlmv2-domain','lab-win-credssp-v6-kerberos','lab-win-credssp-v6-ntlm','lab-net-radius-password-accept','lab-net-eap-tls13-wired','lab-krb-spake-success','lab-pake-spake2-success','lab-pake-spake2plus-success'];
const worksheetContracts=new Map();
const settle=page=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
const canonical=page=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {protocol:a.protocolSnapshot(),held:a.heldView.snapshot()};});
async function choose(page,id){
  await page.locator('#lab-scenario-search').fill(id);
  const option=page.locator('[data-scenario-option='+JSON.stringify(id)+']');
  await option.waitFor({state:'visible'});await option.click();await settle(page);
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),id,'Actual picker selected '+id);
  // This predecessor profile-oriented collector deliberately opens reference details.
  const reference=page.locator('#lesson-reference');if(await reference.isVisible()&&await reference.getAttribute('open')===null)await reference.locator(':scope > summary').click();
}
async function checkpoint(page,suffix,progress=1){
  return page.evaluate(({suffix,progress})=>{
    const a=document.querySelector('auth-flow-studio');if(a.hasTrace)a.clearAttribute();
    const step=a.steps.find(step=>step.id.endsWith(':'+suffix)||step.id.endsWith('-'+suffix));
    if(!step)throw new Error('Missing required source event '+suffix);
    if(progress===1)a.selectStep(a.steps.indexOf(step),false);else a.player.seek([step],progress,'step');
    return {stepId:step.id,state:a.protocolSnapshot().state,held:a.heldView.snapshot(),status:a.player.status};
  },{suffix,progress});
}
async function inspect(page,holding){
  // Open the actual logical-owner inventory and actual exact-holding control.
  const owner=page.locator('#held-objects [data-held-actor='+JSON.stringify(holding.actorId)+']');
  const control=page.locator('#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']');
  if(!await control.isVisible())await owner.click();
  await control.click();
  await expandValues(page,'#held-inspector');
  return page.locator('#held-inspector').innerText();
}
async function exactReplay(page,holding){
  await inspect(page,holding);
  await page.locator('#held-inspector [data-held-trace]').click();
  await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {artifactId:a.objectTraceSelection,rows:a.traceQueue.map(row=>({id:row.id,sourceIndex:row.sourceIndex,from:row.from,to:row.to,kind:row.traceKind,payload:row.payload,heldCursorStart:row.heldCursorStart,heldCursorEnd:row.heldCursorEnd}))};});
}
async function expandValues(page,scope='#inspector'){
  const summaries=page.locator(scope+' :is(.progressive-fields,.long-protocol-value):not([open]) > summary');
  while(await summaries.count())await summaries.first().click();
}
async function assertFullPrefix(page,frame,label){
  await page.evaluate(index=>{
    const a=document.querySelector('auth-flow-studio');
    if(a.hasTrace)a.clearAttribute();
    if(index<0)a.reset();else a.selectStep(index,false);
  },frame.protocol.sourceIndex);
  const full=await canonical(page);
  assert.deepEqual(full.protocol.state,frame.protocol.state,label+' protocol state equals full source prefix');
  assert.deepEqual(full.held,frame.held,label+' exact holdings and cursor equal full source prefix');
  return {sourceIndex:frame.protocol.sourceIndex,cursor:frame.held.cursor,canonicalPrefixEqual:true};
}
async function scene(page){
  await settle(page);
  return page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),graph=a.refs.graph.getBoundingClientRect();
    const visible=e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&!e.closest('[hidden]')&&getComputedStyle(e).visibility!=='hidden';};
    const boxes=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(e=>{const r=e.getBoundingClientRect();return {id:e.dataset.actor||'dock:'+e.dataset.heldDock,left:r.left,right:r.right,top:r.top,bottom:r.bottom};});
    const overlaps=[],collisions=[];let pathSamples=0;
    for(let i=0;i<boxes.length;i++)for(let j=i+1;j<boxes.length;j++){const l=boxes[i],r=boxes[j];if(l.left<r.right-1&&l.right>r.left+1&&l.top<r.bottom-1&&l.bottom>r.top+1)overlaps.push([l.id,r.id]);}
    for(const line of a.refs.connections.querySelectorAll('.connection-line')){
      const matrix=line.getScreenCTM(),length=line.getTotalLength();if(!matrix)continue;
      for(let n=0;n<=Math.ceil(length);n++){const p=line.getPointAtLength(Math.min(n,length)),s=new DOMPoint(p.x,p.y).matrixTransform(matrix);pathSamples++;const hit=boxes.find(b=>s.x>b.left+1&&s.x<b.right-1&&s.y>b.top+1&&s.y<b.bottom-1);if(hit){collisions.push({pair:line.parentElement.dataset.pair,obstacle:hit.id});break;}}
    }
    const targets=[...a.querySelectorAll('#held-docks button,#held-objects button')].filter(visible).map(e=>{const r=e.getBoundingClientRect();return {id:e.dataset.heldAction||e.dataset.holdingId,width:r.width,height:r.height};});
    return {width:innerWidth,geometry:a.refs.graph.dataset.heldGeometry,boxes,pathSamples,overlaps,collisions,outside:boxes.filter(b=>b.left<graph.left-1||b.right>graph.right+1||b.top<graph.top-1||b.bottom>graph.bottom+1),smallTargets:targets.filter(t=>t.width<43.9||t.height<43.9),documentOverflow:document.documentElement.scrollWidth>innerWidth+1,coverage:a.heldView.snapshot().coverageStatus};
  });
}
function assertScene(result,label){
  for(const key of ['overlaps','collisions','outside','smallTargets'])assert.deepEqual(result[key],[],label+' '+key);
  assert.ok(result.boxes.length&&result.pathSamples,label+' real rendered cards and sampled routes');
  assert.equal(result.documentOverflow,false,label+' page overflow');assert.equal(result.coverage,'complete',label+' owner coverage');
}
async function animationSurface(page,captureName=null){
  const targets=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),internal=id=>!!a.scenarioOwnedActors?.[id]?.parentId;
    return [...new Set([a.steps.find(step=>step.from!==step.to),a.steps.find(step=>step.from===step.to),a.steps.find(step=>step.from!==step.to&&(internal(step.from)||internal(step.to)))].filter(Boolean).map(step=>step.id))];
  });
  const records=[];
  for(const stepId of targets){
    await page.evaluate(stepId=>{
      const a=document.querySelector('auth-flow-studio'),clock=a.studyClock(),index=clock.steps.findIndex(step=>step.id===stepId),step=clock.steps[index],duration=clock.durations[index],count=Math.max(1,step.payload.length);
      const timing=a.player.getTiming?.(step,'demo'),message=timing?.messages?.[0];
      const start=message?(message.start-timing.start)/(timing.end-timing.start):0,end=message?(message.end-timing.start)/(timing.end-timing.start):1;
      const scale=message?Math.min(1,(end-start)*duration/(380+(count-1)*1290+1050)):1;
      const fraction=(clock.offsets[index]+start*duration+(380+1050*.5)*scale)/clock.total;
      a.seekPlayback(fraction);
      for(const animation of a.refs.packet.getAnimations({subtree:true}))if(Number.isFinite(animation.effect.getComputedTiming().endTime))animation.finish();
    },stepId);
    await settle(page);
    const result=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),event=a.player.snapshot(),step=event.step,panel=a.refs['step-attributes'],packet=a.refs.packet,rect=node=>{const r=node.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
      const visible=node=>!node.closest('[hidden]')&&node.getBoundingClientRect().width>0;
      const obstacles=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(rect),label=rect(panel),external=panel.classList.contains('is-external');
      const overlaps=visible(panel)&&!external?obstacles.filter(box=>label.left<box.right-1&&label.right>box.left+1&&label.top<box.bottom-1&&label.bottom>box.top+1):[];
      const from=a.nodeId(step.from),to=a.nodeId(step.to),presentation=step.from===step.to?'local':from===to?'folded':'transfer',line=a.refs.connections.querySelector('.connection-group.is-active .connection-line');
      const source=a.refs.actors.querySelector('.is-source')?.dataset.actor,target=a.refs.actors.querySelector('.is-target')?.dataset.actor;
      return {stepId:step.id,presentation,actualPresentation:packet.dataset.presentation,from,to,source,target,packetVisible:!packet.hidden,packet:rect(packet),phase:event.messagePhase,labelVisible:visible(panel),external,label,labelOverlaps:overlaps,clippedNames:[...panel.querySelectorAll('code')].filter(node=>node.scrollWidth>node.clientWidth+1).map(node=>node.textContent),markerEnd:line?getComputedStyle(line).markerEnd:null,documentOverflow:document.documentElement.scrollWidth>innerWidth+1};
    });
    assert.equal(result.stepId,stepId,'Seek lands on the exact authored animation event');
    assert.equal(result.packetVisible,true,stepId+' actual visible paused field packet');
    assert.equal(result.actualPresentation,result.presentation,stepId+' logical transfer/local presentation');
    assert.equal(result.source,result.from,stepId+' rendered source owner');assert.equal(result.target,result.to,stepId+' rendered target owner');
    if(result.presentation==='local')assert.equal(result.markerEnd,'none',stepId+' local computation has no directional arrow');
    assert.deepEqual(result.labelOverlaps,[],stepId+' active label does not cover actors or docks');
    assert.deepEqual(result.clippedNames,[],stepId+' active field names are not clipped');
    assert.equal(result.documentOverflow,false,stepId+' active animation causes no document overflow');
    records.push(result);
    if(captureName)await screenshot(page,captureName+'-'+stepId.replace(/[^a-z0-9-]+/gi,'-'));
  }
  return records;
}
async function screenshot(page,name){
  await page.mouse.move(0,0);await page.keyboard.press('Escape');
  await page.locator('#graph').scrollIntoViewIfNeeded();await settle(page);
  const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false});
  const camera=await page.evaluate(()=>{const r=document.querySelector('#graph').getBoundingClientRect();return {viewport:{width:innerWidth,height:innerHeight},graph:{left:r.left,right:r.right,top:r.top,bottom:r.bottom},scroll:{x:scrollX,y:scrollY}};});
  report.screenshots.push({file,sha256:hash(fs.readFileSync(path.join(out,file))),camera});
}
function assertTerminal(state,id){
  const {family,row}=worksheetContracts.get(id);
  if(family==='windows'){
    for(const [key,value] of Object.entries(row.terminal))assert.deepEqual(state.windows[key],value,id+' independently authored terminal windows.'+key);
  }else if(family==='kerberos-spake'){
    const failure=['lab-krb-spake-wrong-password','lab-krb-spake-no-common-group','lab-krb-spake-downgrade-blocked'].includes(id);
    assert.equal(state.credentials.tgt,!failure,id+' TGT acceptance');
    assert.equal(state.credentials.serviceTicket,!failure,id+' service credential acceptance');
    assert.equal(state.session.established,!failure,id+' application session');
    if(!failure)assert.equal(state.credentials.mechanism,id==='lab-krb-spake-downgrade-allowed'?'encrypted-timestamp':'SPAKE',id+' actual successful mechanism');
    if(id==='lab-krb-spake-optimistic-renegotiate')assert.equal(state.negotiation.generation,1,id+' fresh negotiated generation');
  }else if(family==='pake'){
    for(const [actor,expected] of Object.entries(row.terminalPredicate).filter(([key,value])=>key.startsWith('pake-')&&value&&typeof value==='object')){
      for(const [key,value] of Object.entries(expected))assert.deepEqual(state.sessions.pake[actor][key],value,id+' '+actor+' '+key);
      assert.equal(state.sessions.pake[actor].temporaryDisposed,true,id+' endpoint-local temporary disposal');
    }
    assert.equal(state.outcome.pake.applicationAuthorization,row.terminalPredicate.applicationAuthorization,id+' no implicit application authorization');
  }
}
async function worksheetBoundaries(page,id){
  const {family,row}=worksheetContracts.get(id),checks=[];
  if(family==='network'){
    for(const [event,expected] of Object.entries(row.expectedMilestones)){
      const frame=await checkpoint(page,event),actual={};
      for(const [field,value] of Object.entries(expected)){
        actual[field]=field.split('.').reduce((node,key)=>node?.[key],frame.state);
        assert.deepEqual(actual[field],value==='absent'?undefined:value,id+' independently authored '+event+' '+field);
      }
      checks.push({event,actual});
    }
  }
  return checks;
}
async function journey(page,entry,mode){
  await choose(page,entry.id);
  const internalsEligible=await page.evaluate(()=>Object.values(document.querySelector('auth-flow-studio').scenarioOwnedActors||{}).some(actor=>actor.parentId));
  if(internalsEligible)await page.locator('#show-internals').uncheck();
  const record={id:entry.id,requiredTerminalBoundary:entry.requiredTerminalBoundary,passed:false,internalsEligible,geometry:[]};
  const initial=await canonical(page);
  const profile=await page.locator('#learning-profile').evaluate(panel=>{
    const a=document.querySelector('auth-flow-studio'),p=a.labModel.profile;
    return {visible:!!panel.getClientRects().length&&!panel.hidden,text:panel.innerText,name:p.name,support:p.supportStatus,completion:p.completion,prerequisites:a.labModel.prerequisites,initial:a.heldView.snapshot().cursor,irrelevantToolbars:[...a.querySelectorAll('.toolbar,.protocol-toolbar')].filter(e=>e.getClientRects().length&&!e.hidden).length};
  });
  assert.ok(profile.visible&&profile.prerequisites.length,entry.id+' profile before Play');
  for(const text of [profile.name,profile.support,profile.completion,...profile.prerequisites])assert.ok(profile.text.includes(text),entry.id+' rendered prerequisite/support/completion');
  assert.equal(profile.initial.eventIndex,-1);assert.equal(profile.irrelevantToolbars,0);record.profile=profile;
  for(const detail of ['fields','crypto','journey']){
    await page.locator('#learning-detail-'+detail).click();
    assert.equal(await page.locator('#learning-detail-'+detail).getAttribute('aria-pressed'),'true');
    assert.deepEqual(await canonical(page),initial,entry.id+' '+detail+' presentation preserves canonical state');
  }
  await page.locator('#play').click();await page.locator('#play').click();
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'paused',entry.id+' real Play/Pause');
  await page.locator('#reset').click();
  for(const width of widths){
    await page.setViewportSize({width,height:1200});await page.locator('#reset').click();
    const start=await scene(page);assertScene(start,mode+' '+entry.id+' initial '+width);
    await page.locator('#seek').focus();await page.keyboard.press('End');
    const terminal=await canonical(page);assert.equal(terminal.held.cursor.eventIndex,await page.evaluate(()=>document.querySelector('auth-flow-studio').steps.length-1));
    assertTerminal(terminal.protocol.state,entry.id);
    if(record.terminalState)assert.deepEqual(terminal.protocol.state,record.terminalState,entry.id+' same terminal state across responsive layouts');
    else record.terminalState=terminal.protocol.state;
    const end=await scene(page);assertScene(end,mode+' '+entry.id+' terminal '+width);
    record.geometry.push({expanded:false,initial:start,terminal:end});
    record.geometry.at(-1).animation=await animationSurface(page,mode==='source-http'&&width===1920&&representatives.includes(entry.id)?mode+'-active-'+entry.id:null);
    await page.locator('#seek').focus();await page.keyboard.press('End');
    if(internalsEligible){
      const collapsed=await canonical(page);
      await page.locator('#show-internals').check();
      assert.deepEqual(await canonical(page),collapsed,entry.id+' expanded internals preserve logical state and holdings');
      const expanded=await scene(page);assertScene(expanded,mode+' '+entry.id+' expanded '+width);
      record.geometry.push({expanded:true,terminal:expanded,animation:await animationSurface(page)});
      await page.locator('#seek').focus();await page.keyboard.press('End');
      if(mode==='source-http'&&width===1920&&['lab-win-ntlmv2-local','lab-net-radius-password-totp'].includes(entry.id))await screenshot(page,mode+'-'+entry.id+'-expanded');
      await page.locator('#show-internals').uncheck();
      assert.deepEqual(await canonical(page),collapsed,entry.id+' collapsing internals preserves logical state and holdings');
    }
    if(mode==='source-http'&&representatives.includes(entry.id)&&(width===1920||entry.id==='lab-net-eap-tls13-wired'))await screenshot(page,mode+'-'+entry.id+'-'+width);
  }
  await page.setViewportSize({width:1920,height:1200});await page.locator('#reset').click();
  assert.deepEqual(await canonical(page),initial,entry.id+' Reset restores exact initial state');
  await page.locator('#seek').focus();await page.keyboard.press('Home');await page.keyboard.press('ArrowRight');
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'paused');
  const edge=page.locator('#connections .connection-hit').first();await edge.focus();await page.keyboard.press('Enter');
  await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  const connection=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {kind:a.player.kind,queue:a.player.queue.map(s=>s.id)};});
  assert.equal(connection.kind,'connection',entry.id+' actual keyboard connection replay mode');
  assert.ok(connection.queue.length,entry.id+' actual keyboard connection replay queue');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.seek(a.player.queue,1,'connection');});
  record.connection=connection.queue;
  record.connectionPrefix=await assertFullPrefix(page,await canonical(page),entry.id+' connection replay');
  await page.locator('#reset').click();
  const fields=await page.locator('#attribute-index [data-index-attribute]').evaluateAll(nodes=>nodes.filter(n=>!n.hidden&&n.getClientRects().length).map(n=>n.dataset.indexAttribute));
  assert.ok(fields.length,entry.id+' current profile field index');
  const scope=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {ids:a.labModel.ids,zeroUseTopics:[...a.querySelectorAll('#attribute-topics [data-trace-topic]')].filter(n=>n.getClientRects().length&&a.attributeUsage(a.steps,n.dataset.traceTopic).length===0).map(n=>n.dataset.traceTopic)};});
  assert.ok(fields.every(id=>scope.ids.includes(id)),entry.id+' no irrelevant Web field rows');assert.deepEqual(scope.zeroUseTopics,[],entry.id+' no zero-use Web topics');
  if(entry.id==='lab-net-eap-tls13-wired'){
    const beforeSearch=await canonical(page);await page.locator('#attribute-search').fill('code_verifier');
    assert.ok((await page.locator('#attribute-index').innerText()).includes('code_verifier'),'Typed search reaches global protocol fields');
    await page.locator('#attribute-search').fill('');
    assert.deepEqual(await page.locator('#attribute-index [data-index-attribute]').evaluateAll(nodes=>nodes.filter(n=>!n.hidden&&n.getClientRects().length).map(n=>n.dataset.indexAttribute)),fields);
    assert.deepEqual(await canonical(page),beforeSearch,'Clearing global search restores exact profile and canonical state');
  }
  const traceField=await page.evaluate(ids=>{const a=document.querySelector('auth-flow-studio');return ids.find(id=>a.attributeUsage(a.steps,id).length>0);},fields);
  assert.ok(traceField,entry.id+' rendered replayable field');
  const field=page.locator('#attribute-index [data-index-attribute='+JSON.stringify(traceField)+']');await field.focus();await page.keyboard.press('Enter');
  await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  record.fieldTrace=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {attributeId:a.attributeSelection,rows:a.traceQueue.length};});
  assert.ok(record.fieldTrace.rows,entry.id+' real field trace');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.seek(a.player.queue,1,'attribute');});
  record.fieldTrace.prefix=await assertFullPrefix(page,await canonical(page),entry.id+' field replay');
  await choose(page,entry.id);
  const holding=(await canonical(page)).held.holdings[0];assert.ok(holding,entry.id+' initial exact holding');
  record.exactHistory=await exactReplay(page,holding);assert.equal(record.exactHistory.artifactId,holding.artifactId);assert.ok(record.exactHistory.rows.length);
  await page.locator('#seek').focus();await page.keyboard.press('End');
  record.exactHistory.prefix=await assertFullPrefix(page,await canonical(page),entry.id+' exact-object replay');
  await choose(page,entry.id);record.independentBoundaryChecks=await worksheetBoundaries(page,entry.id);record.passed=true;return record;
}
async function deep(page,id){
  await choose(page,id);const checks=[];
  const at=async(suffix,progress=1)=>{const frame=await checkpoint(page,suffix,progress);checks.push({suffix,progress,...frame});return frame;};
  if(id==='lab-win-ntlmv2-domain'){
    for(const suffix of ['authenticate','validation-request']){const f=await at(suffix);assert.equal(f.state.windows.mechanismComplete,false);assert.equal(f.state.windows.resourceAuthorized,false);}
    const verified=await at('dc-verify');assert.equal(verified.state.windows.dcValidated,true);assert.equal(verified.state.windows.mechanismComplete,false);
    const returned=await at('validation-result');assert.equal(returned.state.windows.resourceAuthorized,false);
    const context=await at('context');assert.equal(context.state.windows.mechanismComplete,true);assert.equal(context.state.windows.resourceAuthorized,false);
    assert.equal((await at('authorize')).state.windows.resourceAuthorized,true);
  }else if(id.startsWith('lab-win-credssp')){
    const before=await at('authinfo-receive',.5);assert.equal(before.state.windows.authInfoReceived,false);assert.equal(before.state.windows.credentialsReceived,false);
    const receipt=await at('authinfo-receive');assert.equal(receipt.state.windows.authInfoReceived,true);assert.equal(receipt.state.windows.credentialsReceived,false);
    const wire=receipt.held.holdings.find(h=>h.actorId==='winHost'&&h.artifactId.includes(':delegated-credentials')&&h.representationId==='wire');assert.ok(wire,'H owns same credential opaque inbox');
    const wireText=await inspect(page,wire);assert.ok(wireText.includes('TLS(Seal('));assert.ok(!wireText.includes('password=<synthetic Alice password>'));
    const recovered=await at('authinfo-unwrap');assert.equal(recovered.state.windows.credentialsReceived,true);assert.equal(recovered.state.windows.logonAuthorized,false);
    const plain=recovered.held.holdings.find(h=>h.actorId==='winHost'&&h.artifactId===wire.artifactId&&h.representationId==='plain');assert.ok(plain);
    assert.ok((await inspect(page,plain)).includes('password=<synthetic Alice password>'));
    const trace=await exactReplay(page,plain);assert.equal(trace.artifactId,wire.artifactId);
    const rowEvidence=[];
    for(let index=0;index<trace.rows.length;index++){
      await page.locator('#timeline [data-step='+JSON.stringify(String(index))+']').click();
      await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
      await expandValues(page);
      rowEvidence.push(await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.currentStep;return {from:s.from,to:s.to,kind:s.traceKind,payload:s.payload,text:a.refs.inspector.innerText};}));
    }
    assert.ok(rowEvidence.some(row=>row.from!==row.to&&JSON.stringify(row.payload).includes('TLS(Seal(')),'Exact credential opaque transfer row');
    assert.ok(rowEvidence.some(row=>row.from==='winHost'&&row.to==='winHost'&&row.text.includes('password=<synthetic Alice password>')),'Exact credential legitimate H decoded local row');
    checks.push({sameCredentialArtifactId:wire.artifactId,renderedRows:rowEvidence});
  }else if(id.startsWith('lab-net-')){
    const reply=await at('accept');assert.equal(reply.state.network.port,'unauthorized');assert.equal(reply.state.sessions?.access,undefined);
    const verified=await at('verify-reply');assert.equal(verified.state.network.port,'unauthorized');
    assert.equal((await at('enforce')).state.network.port,'authorized');
    const safety=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),bad=[],frames=[];
      for(let index=0;index<a.steps.length;index++){
        a.selectStep(index,false);const s=a.heldView.snapshot();
        const forbidden=s.holdings.filter(h=>h.actorId==='netNas'&&(/private|emsk|tls-secret|ephemeral/i.test(h.artifactId)||s.artifacts.find(a=>a.artifactId===h.artifactId)?.type==='private-key'));bad.push(...forbidden);frames.push({step:a.steps[index].id,port:s.state.network.port,nas:s.holdings.filter(h=>h.actorId==='netNas').map(h=>h.artifactId)});
      }
      return {bad,frames};
    });assert.deepEqual(safety.bad,[],'NAS never acquires private TLS keys, EMSK or endpoint TLS secrets');checks.push({safety});
  }else if(id==='lab-krb-spake-success'){
    const response=await at('response');assert.notEqual(response.state.kdc?.factorValidated,true);
    assert.equal((await at('kdc-validate')).state.kdc.factorValidated,true);
    const received=await at('as-receive');assert.equal(received.state.credentials.tgt,false);assert.notEqual(received.state.as.validated,true);
    const tgt=received.held.holdings.find(h=>h.actorId==='spake-client'&&/:tgt(?::|$)/.test(h.artifactId)&&h.representationId==='opaque');assert.ok(tgt,'Actual opaque TGT holding');
    const text=await inspect(page,tgt);const artifact=received.held.artifacts.find(a=>a.artifactId===tgt.artifactId),representation=artifact.representations.find(r=>r.representationId==='opaque');
    const values=representation.fields.map(field=>field.value).filter(value=>typeof value==='string'&&value.length);assert.ok(values.length);assert.ok(values.some(value=>text.includes(value)),'Opaque TGT bytes actually rendered');
    const trace=await exactReplay(page,tgt),wireIndex=trace.rows.findIndex(row=>row.from!==row.to&&JSON.stringify(row.payload).includes(values[0]));
    assert.ok(wireIndex>=0,'Opaque TGT appears in actual exact wire history');
    await page.locator('#timeline [data-step='+JSON.stringify(String(wireIndex))+']').click();
    await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());await expandValues(page);
    assert.ok((await page.locator('#inspector').innerText()).includes(values[0]),'Opaque TGT bytes visible in rendered exact history');
    const validated=await at('client-validate');assert.equal(validated.state.as.validated,true);assert.equal(validated.state.credentials.tgt,false);
    assert.equal((await at('cache')).state.credentials.tgt,true);
    assert.equal((await at('tgs-reply')).state.session.established,false);assert.equal((await at('session')).state.session.established,true);
    const safety=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),bad=[];
      for(let i=0;i<a.steps.length;i++){a.selectStep(i,false);for(const h of a.heldView.snapshot().holdings)if(h.actorId==='spake-client'&&/:(?:tgt|service-ticket|cookie)(?::|$)/.test(h.artifactId)&&h.representationId==='decoded')bad.push(h);}
      return bad;
    });assert.deepEqual(safety,[],'Client never owns decoded ticket or cookie body');
  }else{
    const plus=id.includes('spake2plus'),sender=plus?'pake-prover':'pake-b',receiver=plus?'pake-verifier':'pake-a',side=plus?'a':'b';
    const verification=await at('verify-confirm-'+(plus?'b':'a'));assert.equal(verification.state.sessions.pake[sender].peerConfirmed,true);assert.equal(verification.state.sessions.pake[sender].usable,false);
    const handoff=await at('handoff-confirm-'+side);assert.equal(handoff.state.sessions.pake[sender].usable,true);assert.equal(handoff.state.sessions.pake[receiver].receivedConfirmation,false);assert.equal(handoff.state.sessions.pake[receiver].usable,false);
    const flight=await at('send-confirm-'+side,.5);assert.equal(flight.state.sessions.pake[sender].usable,true);assert.equal(flight.state.sessions.pake[receiver].receivedConfirmation,false);
    const receipt=await at('send-confirm-'+side);assert.equal(receipt.state.sessions.pake[receiver].receivedConfirmation,true);assert.equal(receipt.state.sessions.pake[receiver].peerConfirmed,false);assert.equal(receipt.state.sessions.pake[receiver].usable,false);
    const confirmed=await at('verify-confirm-'+side);assert.equal(confirmed.state.sessions.pake[receiver].usable,true);assert.equal(confirmed.state.outcome.pake.applicationAuthorization,false);
    const safety=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),bad=[],keyOwners=[];
      for(let i=0;i<a.steps.length;i++){
        a.selectStep(i,false);const s=a.heldView.snapshot();
        for(const h of s.holdings.filter(h=>/:key-[ab]$/.test(h.artifactId))){const expected=h.artifactId.endsWith('key-a')?(a.labScenarioId.includes('spake2plus')?'pake-prover':'pake-a'):(a.labScenarioId.includes('spake2plus')?'pake-verifier':'pake-b');if(h.actorId!==expected||h.representationId!=='local')bad.push(h);keyOwners.push([h.artifactId,h.actorId]);}
      }
      const messages=Object.values(a.heldView.compiled().plan.events).flatMap(event=>event.messages||[]);for(const message of messages)for(const object of message.objects)if(/:key-[ab]$/.test(object.artifactId))bad.push(message);
      return {bad,keyOwners};
    });assert.ok(safety.keyOwners.length);assert.deepEqual(safety.bad,[],'Output keys local, independently owned and never transferred');checks.push({safety});
  }
  return {id,passed:true,checks};
}
async function regressions(page){
  await choose(page,'lab-win-ntlmv2-domain');const first=await canonical(page);
  await choose(page,'lab-net-radius-password-accept');const second=await canonical(page);
  await page.goBack();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').labScenarioId==='lab-win-ntlmv2-domain');
  assert.deepEqual(await canonical(page),first,'Native Back restores routed scenario initial state');
  await page.goForward();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').labScenarioId==='lab-net-radius-password-accept');
  assert.deepEqual(await canonical(page),second,'Native Forward restores routed scenario initial state');
  await choose(page,'lab-bff-api');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');const i=a.steps.findIndex(s=>s.id==='web-bff-token-request');if(i<0)throw new Error('N01 BFF token request missing');a.selectStep(i,false);});
  const label=await page.locator('#inspector .channel-badge').innerText();
  assert.match(label,/Server exchange/i,'N01 BFF server exchange label');assert.doesNotMatch(label,/Browser redirect/i);
  await choose(page,'lab-refresh-rotation');const initial=await canonical(page);
  const holding=initial.held.holdings.find(h=>h.artifactId==='R0'&&h.actorId==='app');assert.ok(holding);
  const trace=await exactReplay(page,holding);assert.equal(trace.rows[0].sourceIndex,-1);assert.equal(trace.rows[0].kind,'initial');
  const paused=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio');a.player.seek([a.traceQueue[0]],.5,'object');a.player.pause();
    return {status:a.player.status,protocol:a.protocolSnapshot(),held:a.heldView.snapshot(),text:a.refs.inspector.innerText};
  });assert.equal(paused.status,'paused');assert.deepEqual(paused.held,initial.held);assert.deepEqual(paused.protocol.state,initial.protocol.state);
  await page.waitForTimeout(80);assert.deepEqual((await canonical(page)).held,initial.held,'Zero-width initial replay stays initial while paused');
  return {nativeBackForward:true,bffLabel:label,zeroWidthInitialPaused:{artifactId:holding.artifactId,cursor:paused.held.cursor,canonicalPreserved:true}};
}
function performanceIdentity(directory){
  const names=['index.html','build.mjs','package.json',...fs.readdirSync(path.join(directory,'src')).filter(name=>/\.(js|css)$/.test(name)).sort().map(name=>'src/'+name)];
  const sources=Object.fromEntries(names.map(name=>{const bytes=fs.readFileSync(path.join(directory,name));return [name,{bytes:bytes.length,sha256:hash(bytes)}];}));
  const standalone=fs.readFileSync(path.join(directory,'dist/auth-flow-studio.html'));
  return {sourceSnapshotSha256:hash(JSON.stringify(sources)),sourceBytes:Object.values(sources).reduce((n,s)=>n+s.bytes,0),sources,standalone:{bytes:standalone.length,sha256:hash(standalone)}};
}
async function performanceComparison(origin,manifest){
  report.environment.AUTH_LAB_EXPANSION_BASELINE_ROOT=baselineRoot;
  if(!baselineRoot){report.performance={available:false,reason:'AUTH_LAB_EXPANSION_BASELINE_ROOT was not supplied; no before/after performance claim is established.'};if(!requestedIds.length&&modes.length===3)report.failures.push({phase:'performance',message:report.performance.reason});return;}
  const before=performanceIdentity(baselineRoot),after=performanceIdentity(root);
  assert.equal(before.standalone.sha256,manifest.baselineStandaloneSha256,'Performance baseline must be the accepted standalone artifact');
  const result={available:false,baseline:{root:baselineRoot,expectedCommit:manifest.baselineCommit,identity:before},expanded:{identity:after},samples:[],comparisons:[],method:'Three fresh isolated browser contexts per checkout and mode, serial without acceptance workers. Cold means empty browser HTTP/cache/storage, not cold OS filesystem caches. Startup ends at real held-view readiness plus two animation frames. Picker and selection use real Playwright input and clicks; timings include automation round trips. Quantiles from three observations are descriptive, not statistical significance.',causality:'Differences in source/standalone bytes and DOM counts are measured. Attribution to catalog size or rendering cost is an inference, not a CPU-profiled cause.'};
  report.performance=result;save();
  result.selectionDiagnosticsMethod='Chrome Performance domain counters are sampled immediately before and after real selection, outside its elapsed timing. Nodes includes detached nodes; liveNodesAfter is the current document count. Durations are Chrome seconds, not inferred function costs.';
  result.playbackMethod='Replay start measures a real Play click to positive elapsed progress plus two animation frames. A second real picker search must expose the Basic preset while playback remains playing, monotonic and on the same journey. These are interaction latencies, not frame-rate or screen-reader measurements.';
  for(const mode of modes)for(let sample=0;sample<3;sample++)for(const version of ['baseline','expanded']){
    const directory=version==='baseline'?baselineRoot:root,prefix=version==='baseline'?'/__baseline__/':'/';
    const target=mode==='standalone-file'?pathToFileURL(path.join(directory,'dist/auth-flow-studio.html')).href:origin+prefix+(mode==='source-http'?'':'dist/auth-flow-studio.html');
    const context=await browser.newContext({viewport:{width:1920,height:1200},bypassCSP:false}),page=await context.newPage();page.setDefaultTimeout(30000);
    try{
      await context.route('**/*',route=>{const url=route.request().url();return (url.startsWith(origin+'/')||url===target)?route.continue():route.abort();});
      const start=performance.now();await page.goto(target,{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);await settle(page);
      const startupMs=performance.now()-start;
      const dom=await page.evaluate(()=>({nodes:document.querySelectorAll('*').length,htmlBytes:new TextEncoder().encode(document.documentElement.outerHTML).length,transferBytes:performance.getEntriesByType('resource').reduce((n,r)=>n+(r.transferSize||0),0)}));
      const pickerStart=performance.now();await page.locator('#lab-scenario-search').fill('refresh');
      const option=page.locator('[data-scenario-option="lab-refresh-rotation"]');await option.waitFor({state:'visible'});await settle(page);const filterMs=performance.now()-pickerStart;
      const cdp=await context.newCDPSession(page);await cdp.send('Performance.enable');
      const metricsBefore=new Map((await cdp.send('Performance.getMetrics')).metrics.map(metric=>[metric.name,metric.value]));
      const selectionStart=performance.now();await option.click();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').labScenarioId==='lab-refresh-rotation');await settle(page);
      const selectionMs=performance.now()-selectionStart;
      const metricsAfter=(await cdp.send('Performance.getMetrics')).metrics;
      const selectionDiagnostics=Object.fromEntries(metricsAfter.filter(metric=>['Nodes','LayoutDuration','RecalcStyleDuration','ScriptDuration','TaskDuration','JSHeapUsedSize'].includes(metric.name)).map(metric=>[metric.name,{before:metricsBefore.get(metric.name),after:metric.value,delta:metric.value-metricsBefore.get(metric.name)}]));
      selectionDiagnostics.liveNodesAfter=await page.evaluate(()=>document.querySelectorAll('*').length);
      const replayStart=performance.now();await page.locator('#play').click();
      await page.waitForFunction(()=>{const p=document.querySelector('auth-flow-studio').player;return p.status==='playing'&&p.elapsed>0;});await settle(page);
      const replayStartMs=performance.now()-replayStart;
      const playbackBefore=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {status:a.player.status,elapsed:a.player.elapsed,scenario:a.labScenarioId,mode:a.player.mode};});
      const playingFilterStart=performance.now();await page.locator('#lab-scenario-search').fill('basic');
      await page.locator('[data-scenario-option="basic-keycloak"]').waitFor({state:'visible'});await settle(page);
      const playingFilterMs=performance.now()-playingFilterStart;
      const playbackAfter=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {status:a.player.status,elapsed:a.player.elapsed,scenario:a.labScenarioId,mode:a.player.mode};});
      assert.equal(playbackAfter.status,'playing','Picker search must remain usable during playback');
      assert.equal(playbackAfter.scenario,playbackBefore.scenario);assert.equal(playbackAfter.mode,playbackBefore.mode);
      assert.ok(playbackAfter.elapsed>=playbackBefore.elapsed,'Searching cannot reset replay progress');
      await page.locator('#play').click();assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'paused');
      result.samples.push({version,mode,sample,startupMs,filterMs,selectionMs,replayStartMs,playingFilterMs,dom,selectionDiagnostics,playbackSearch:{before:playbackBefore,after:playbackAfter,basicResultVisible:true}});save();
    }finally{await context.close();}
  }
  const stats=values=>{const sorted=[...values].sort((a,b)=>a-b);return {samples:values,min:sorted[0],median:sorted[Math.floor(sorted.length/2)],p95:sorted[Math.ceil(sorted.length*.95)-1],max:sorted.at(-1)};};
  for(const mode of modes)for(const metric of ['startupMs','filterMs','selectionMs','replayStartMs','playingFilterMs']){
    const baseline=stats(result.samples.filter(s=>s.mode===mode&&s.version==='baseline').map(s=>s[metric])),expanded=stats(result.samples.filter(s=>s.mode===mode&&s.version==='expanded').map(s=>s[metric]));
    const deltaMs=expanded.median-baseline.median,ratio=expanded.median/baseline.median;
    result.comparisons.push({mode,metric,baseline,expanded,deltaMs,ratio,materialRegression:ratio>1.25&&deltaMs>(metric==='startupMs'?100:50),review:'Material flag means both >25% and >100ms startup or >50ms interaction median increase. Inspect measurements and profile before attributing a cause; no threshold is silently suppressed.'});
  }
  assert.deepEqual(performanceIdentity(baselineRoot),before,'Performance baseline remains unchanged');assert.deepEqual(performanceIdentity(root),after,'Performance expansion remains unchanged');
  result.available=true;save();
}
async function observe(page,context,target,mode,origin,record){
  page.on('pageerror',error=>record.errors.push(String(error)));
  await page.exposeBinding('__expansionCsp',(_,value)=>record.csp.push(value));
  await page.addInitScript(()=>document.addEventListener('securitypolicyviolation',event=>void window.__expansionCsp({directive:event.effectiveDirective,blocked:event.blockedURI})));
  await context.route('**/*',route=>{const url=route.request().url(),allowed=mode==='standalone-file'?url===target:url.startsWith(origin+'/');if(!allowed)record.externalRequests.push(url);return allowed?route.continue():route.abort();});
}
async function touchAndZoom(mode,origin){
  const target=mode==='standalone-file'?pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href:origin+'/'+(mode==='source-http'?'':'dist/auth-flow-studio.html');
  const ids=['basic-keycloak','lab-win-rdp-remote-credential-guard','lab-ad-forest-child-domains','lab-krb-spake-optimistic-renegotiate','lab-ssh-cert-reissue','lab-net-radius-proxy-realm','lab-pake-spake2plus-record-boundary'];
  const record={mode,passed:false,touch:[],browserZoom:[],errors:[],csp:[],externalRequests:[]};
  report.surfaces.push(record);
  const touch=await browser.newContext({viewport:{width:390,height:844},hasTouch:true,isMobile:true,bypassCSP:false});
  try{
    const page=await touch.newPage();page.setDefaultTimeout(20000);await observe(page,touch,target,mode,origin,record);
    await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
    for(const id of ids){
      await page.locator('#lab-scenario-search').fill(id);await page.locator('[data-scenario-option='+JSON.stringify(id)+']').tap();await settle(page);
      const before=await canonical(page),holding=before.held.holdings[0];assert.ok(holding,id+' initial touch holding');
      await page.locator('#held-objects [data-held-actor='+JSON.stringify(holding.actorId)+']').tap();
      await page.locator('#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']').tap();
      assert.equal(await page.locator('#held-inspector').isVisible(),true,id+' actual tap opens inspector');
      assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection.holdingId),holding.holdingId,id+' exact tap identity');
      assert.deepEqual(await canonical(page),before,id+' touch inspection preserves canonical state');
      const geometry=await scene(page);assertScene(geometry,mode+' touch '+id);
      record.touch.push({id,nativeTouch:true,holdingId:holding.holdingId,geometry});
    }
  }finally{await touch.close();}
  const profile=fs.mkdtempSync(path.join(os.tmpdir(),'auth-lab-expansion-zoom-'));
  let desktop,settings;
  try{
    desktop=await browser.browserType().launchPersistentContext(profile,{headless:true,viewport:{width:1920,height:1200},bypassCSP:false,executablePath:report.dependencies.chromium.executable,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await desktop.newPage();page.setDefaultTimeout(20000);await observe(page,desktop,target,mode,origin,record);
    settings=await desktop.newPage();await settings.goto('chrome://settings/appearance');
    for(const zoom of [2,4]){
      await settings.evaluate(zoom=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(zoom,resolve)),zoom);
      await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
      const viewport=await page.evaluate(()=>({width:innerWidth,visualScale:visualViewport.scale}));
      assert.ok(Math.abs(viewport.width-1920/zoom)<=2,mode+' actual browser zoom changes CSS viewport');
      assert.equal(viewport.visualScale,1,mode+' browser zoom is not pinch or CSS zoom');
      for(const id of ids){
        await choose(page,id);await page.locator('#seek').focus();await page.keyboard.press('End');
        const geometry=await scene(page);assertScene(geometry,mode+' actual browser zoom '+zoom+' '+id);
        record.browserZoom.push({id,zoom,zoomIsBrowserUiZoom:true,...viewport,geometry});
      }
    }
    assert.deepEqual(record.errors,[],mode+' touch/zoom browser errors');
    assert.deepEqual(record.csp,[],mode+' touch/zoom CSP');
    assert.deepEqual(record.externalRequests,[],mode+' touch/zoom offline boundary');
    record.passed=true;return record;
  }finally{
    if(settings&&!settings.isClosed())await settings.evaluate(()=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(1,resolve))).catch(()=>{});
    await desktop?.close();
    fs.rmSync(profile,{recursive:true,force:true});
  }
}
let browser,server;
try{
  const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  assert.equal(manifest.scenarios.length,61);assert.equal(new Set(manifest.scenarios.map(s=>s.id)).size,61);
  assert.ok(requestedIds.every(id=>manifest.scenarios.some(s=>s.id===id)),'Unknown --id');
  for(const family of ['windows','network','kerberos-spake','pake']){
    const worksheet=JSON.parse(fs.readFileSync(path.join(root,'docs/expansion/'+family+'-scenarios.json'),'utf8'));
    for(const row of worksheet.scenarios){assert.equal(worksheetContracts.has(row.id),false,'Unique independent worksheet '+row.id);worksheetContracts.set(row.id,{family,row});}
  }
  assert.deepEqual([...worksheetContracts.keys()].sort(),manifest.scenarios.map(row=>row.id).sort(),'Every fixed preset has one independent worksheet');
  const entries=requestedIds.length?manifest.scenarios.filter(s=>requestedIds.includes(s.id)):manifest.scenarios;
  report.scope.ids=entries.map(s=>s.id);report.identity=identity();
  const require=createRequire(import.meta.url),entry=process.env.PLAYWRIGHT_MODULE?path.resolve(process.env.PLAYWRIGHT_MODULE):require.resolve('playwright');
  report.dependencies.playwright=packageIdentity(entry);
  const playwright=await import(pathToFileURL(entry).href),chromium=playwright.chromium||playwright.default?.chromium;
  const executable=process.env.CHROMIUM_EXECUTABLE||chromium.executablePath();
  report.dependencies.playwrightCore=packageIdentity(require.resolve('playwright-core',{paths:[path.dirname(entry)]}));
  report.dependencies.chromium={executable,sha256:hash(fs.readFileSync(executable))};
  browser=await chromium.launch({headless:true,executablePath:executable,args:['--no-sandbox','--disable-dev-shm-usage']});report.browser={engine:'chromium',version:browser.version()};
  server=http.createServer((request,response)=>{
    let file,directory=root;try{let name=decodeURIComponent(new URL(request.url,'http://localhost').pathname);if(name.startsWith('/__baseline__/')){if(!baselineRoot){response.writeHead(404);response.end();return;}directory=baselineRoot;name=name.slice('/__baseline__'.length);}file=path.resolve(directory,'.'+(name==='/'?'/index.html':name));}catch{response.writeHead(400);response.end();return;}
    if(!file.startsWith(directory+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){response.writeHead(404);response.end();return;}
    response.writeHead(200,{'Content-Type':{'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(response);
  });await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const origin='http://127.0.0.1:'+server.address().port;
  try{await performanceComparison(origin,manifest);}catch(error){report.failures.push({phase:'performance',message:error.message,stack:error.stack});}
  const pending=[...new Set(modes)];
  async function worker(){
    while(pending.length){
      const mode=pending.shift(),record={mode,passed:false,scenarios:[],deep:[],errors:[],csp:[],externalRequests:[]};report.modes.push(record);
      const context=await browser.newContext({viewport:{width:1920,height:1200},bypassCSP:false}),page=await context.newPage();page.setDefaultTimeout(20000);page.setDefaultNavigationTimeout(45000);
      const target=mode==='standalone-file'?pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href:origin+'/'+(mode==='source-http'?'':'dist/auth-flow-studio.html');
      await observe(page,context,target,mode,origin,record);
      try{
        await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
        for(const entry of entries){
          try{record.scenarios.push(await journey(page,entry,mode));}
          catch(error){report.failures.push({mode,id:entry.id,phase:'journey',message:error.message,stack:error.stack});await screenshot(page,mode+'-'+entry.id+'-failed').catch(()=>{});record.scenarios.push({id:entry.id,passed:false});await page.goto(target,{waitUntil:'networkidle'});}
          save();
        }
        for(const id of representatives.filter(id=>entries.some(e=>e.id===id))){try{record.deep.push(await deep(page,id));}catch(error){report.failures.push({mode,id,phase:'deep',message:error.message,stack:error.stack});record.deep.push({id,passed:false});await page.goto(target,{waitUntil:'networkidle'});}save();}
        try{record.regressions=await regressions(page);}catch(error){report.failures.push({mode,phase:'regressions',message:error.message,stack:error.stack});}
        assert.deepEqual(record.errors,[],mode+' browser errors');assert.deepEqual(record.csp,[],mode+' CSP violations');assert.deepEqual(record.externalRequests,[],mode+' offline boundary');
        record.passed=!report.failures.some(f=>f.mode===mode);
      }catch(error){report.failures.push({mode,phase:'mode',message:error.message,stack:error.stack});}
      finally{await context.close();save();}
    }
  }
  const workers=await Promise.allSettled(Array.from({length:Math.min(jobs,pending.length)},()=>worker()));
  for(const worker of workers)if(worker.status==='rejected')report.failures.push({phase:'worker',message:worker.reason?.message||String(worker.reason),stack:worker.reason?.stack});
  report.surfaces=[];
  for(const mode of [...new Set(modes)]){
    try{await touchAndZoom(mode,origin);}
    catch(error){report.failures.push({mode,phase:'native-touch-browser-zoom',message:error.message,stack:error.stack});}
    save();
  }
  assert.deepEqual(identity(),report.identity,'Sources, worksheets, manifest and standalone unchanged during acceptance');
  report.complete=entries.length===61&&allModes.every(mode=>report.modes.some(record=>record.mode===mode&&record.scenarios.length===61&&record.deep.length===8&&record.regressions)&&report.surfaces.some(record=>record.mode===mode&&record.touch?.length===7&&record.browserZoom?.length===14))&&report.performance?.available===true;
  report.passed=report.failures.length===0&&report.modes.every(mode=>mode.passed);
}catch(error){report.failures.push({phase:'setup-or-identity',message:error.message,stack:error.stack});}
finally{
  if(browser)await browser.close().catch(error=>report.failures.push({phase:'browser-close',message:error.message}));
  if(server)await new Promise(resolve=>server.close(resolve));
  if(report.failures.length)report.passed=false;
  save();console.log(JSON.stringify({passed:report.passed,complete:report.complete,report:path.join(out,'expansion-native-status.json'),failures:report.failures.map(({mode,id,phase,message})=>({mode,id,phase,message}))},null,2));
  if(!report.passed)process.exitCode=1;
}
