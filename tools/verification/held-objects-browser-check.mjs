#!/usr/bin/env bun
// Real Chromium acceptance. No DOM adapter, CSS zoom, protocol endpoints or
// production credentials. Playwright is optional QA tooling, not an app dependency.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
const heldNativeRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const heldNativeOutput=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(heldNativeRoot,'docs/verification/held-objects'));
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/held-objects-browser-check.mjs\nBuild first. Requires Playwright/PLAYWRIGHT_MODULE and installed Chromium/CHROMIUM_EXECUTABLE. No downloads or application dependencies. Checks source HTTP, standalone HTTP/file, exact focus, routes, rendered targets, touch, reduced motion and actual Chrome default browser zoom. Evidence: AUTH_LAB_HELD_EVIDENCE_DIR or docs/verification/held-objects.');process.exit(0);}
fs.mkdirSync(heldNativeOutput,{recursive:true});
const heldNativeHash=value=>createHash('sha256').update(value).digest('hex');
const heldNativeIdentity=()=>({standalone:{bytes:fs.statSync(path.join(heldNativeRoot,'dist/auth-flow-studio.html')).size,sha256:heldNativeHash(fs.readFileSync(path.join(heldNativeRoot,'dist/auth-flow-studio.html')))},sources:Object.fromEntries(['index.html','build.mjs',...fs.readdirSync(path.join(heldNativeRoot,'src')).filter(name=>/\.(js|css)$/.test(name)).sort().map(name=>'src/'+name)].map(name=>[name,heldNativeHash(fs.readFileSync(path.join(heldNativeRoot,name)))]))});
const heldNativeReport={kind:'held-objects-native-browser',timestamp:new Date().toISOString(),nativeBrowser:true,passed:false,runnerSha256:heldNativeHash(fs.readFileSync(fileURLToPath(import.meta.url))),regenerationCommand:[process.execPath,...process.argv.slice(1)],identity:heldNativeIdentity(),modes:[],screenshots:[],manualNotEstablished:['Screen-reader speech and announcement comprehension with a real assistive-technology user','Cross-engine and live KDC/IdP/SSH interoperability'],failures:[]};
let heldNativeBrowser,heldNativeServer,heldNativeContext,heldNativeProfile;
const heldNativeCheck=(condition,message)=>assert.ok(condition,message);
async function heldNativeObserve(page,mode,violations,errors,requests){
  page.on('pageerror',error=>errors.push(String(error)));
  page.on('request',request=>requests.push(request.url()));
  await page.exposeBinding('__heldNativeRecordCsp',({frame},record)=>violations.push({mode,documentUrl:frame.url(),...record}));
  await page.addInitScript(()=>document.addEventListener('securitypolicyviolation',event=>{
    void window.__heldNativeRecordCsp({documentUrl:location.href,directive:event.effectiveDirective,blocked:event.blockedURI,disposition:event.disposition});
  }));
}
async function heldNativeTouch(browser,mode,target,origin,record){
  const context=await browser.newContext({viewport:{width:390,height:844},hasTouch:true,isMobile:true,bypassCSP:false});
  const page=await context.newPage(),violations=[],errors=[],requests=[];
  record.touch={mode,target,viewport:{width:390,height:844},nativeTouch:true,passed:false,violations,errors};
  try{
    await heldNativeObserve(page,mode,violations,errors,requests);
    await context.route('**/*',route=>{const url=route.request().url();return (mode==='standalone-file'?url===target:url.startsWith(origin+'/'))?route.continue():route.abort();});
    await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
    await heldNativeChoose(page,'lab-refresh-rotation');
    await page.locator('#held-objects [data-held-actor="app"]').tap();
    const control=page.locator('#held-objects [data-holding-id]:visible').first(),id=await control.getAttribute('data-holding-id');
    await control.tap();
    assert.equal(await page.locator('#held-inspector').isVisible(),true,mode+' native tap opens inspector');
    assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection.holdingId),id,mode+' tap selects the actual exact holding');
    assert.deepEqual(errors,[],mode+' touch runtime errors');assert.deepEqual(violations,[],mode+' touch CSP');
    heldNativeCheck(requests.every(url=>mode==='standalone-file'?url===target:url.startsWith(origin+'/')),mode+' touch has no external requests');
    const file=mode+'-native-touch-exact-inspector.png';await page.screenshot({path:path.join(heldNativeOutput,file),fullPage:false});heldNativeReport.screenshots.push(file);
    Object.assign(record.touch,{passed:true,holdingId:id,exactObjectInspector:true,requests:requests.length,screenshot:file});
  }finally{await context.close();}
}
async function heldNativeChoose(page,id,expanded=false,final=false){const selected=await page.evaluate(({id,expanded,final})=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario(id);if(a.showInternals!==expanded){a.showInternals=expanded;a.renderAll();}if(final)a.selectStep(a.steps.length-1,false);return a.labScenarioId;},{id,expanded,final});assert.equal(selected,id,'Native acceptance fixture must select its exact registered scenario.');}
async function heldNativeScene(page,label,{routes=true}={}){
  const result=await page.evaluate(routes=>{
    const a=document.querySelector('auth-flow-studio'),graph=a.refs.graph.getBoundingClientRect();
    const visible=element=>{const r=element.getBoundingClientRect();return r.width>0&&r.height>0&&!element.closest('[hidden]')&&getComputedStyle(element).visibility!=='hidden';};
    const boxes=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(element=>{const r=element.getBoundingClientRect();return {id:element.dataset.actor||'dock:'+element.dataset.heldDock,left:r.left,right:r.right,top:r.top,bottom:r.bottom};});
    const overlaps=[];for(let i=0;i<boxes.length;i++)for(let j=i+1;j<boxes.length;j++){const x=boxes[i],y=boxes[j];if(x.left<y.right-1&&x.right>y.left+1&&x.top<y.bottom-1&&x.bottom>y.top+1)overlaps.push([x.id,y.id]);}
    const collisions=[];if(routes)for(const element of a.refs.connections.querySelectorAll('.connection-line')){const matrix=element.getScreenCTM(),length=element.getTotalLength();if(!matrix)continue;for(let n=0;n<=length;n+=2){const p=element.getPointAtLength(n),point=new DOMPoint(p.x,p.y).matrixTransform(matrix);const box=boxes.find(b=>point.x>b.left+1&&point.x<b.right-1&&point.y>b.top+1&&point.y<b.bottom-1);if(box){collisions.push({pair:element.parentElement.dataset.pair,obstacle:box.id});break;}}}
    const targets=[...a.querySelectorAll('#held-docks button,#held-objects button,#held-inspector button')].filter(visible).map(element=>{const r=element.getBoundingClientRect();return {name:element.textContent.trim().slice(0,80),width:r.width,height:r.height};});
    const outside=boxes.filter(box=>box.left<graph.left-1||box.right>graph.right+1||box.top<graph.top-1||box.bottom>graph.bottom+1);
    const snapshot=a.heldView.snapshot();
    return {choiceId:a.labScenarioId,expanded:a.showInternals,mode:a.refs.graph.dataset.heldGeometry,viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,visualScale:visualViewport.scale},graph:{width:graph.width,height:graph.height},overlaps,collisions,outside,smallTargets:targets.filter(target=>target.width<43.9||target.height<43.9),minimumTarget:targets.length?{width:Math.min(...targets.map(t=>t.width)),height:Math.min(...targets.map(t=>t.height))}:null,nestedActorButtons:a.querySelectorAll('.actor-card button').length,cursor:snapshot.cursor,protocolClock:snapshot.protocolClock,holdings:snapshot.holdings.map(h=>[h.actorId,h.artifactId,h.representationId,h.holdingId,h.store,h.retention]),state:snapshot.state,coverageStatus:snapshot.coverageStatus};
  },routes);
  assert.deepEqual(result.overlaps,[],label+' participant/dock overlap');assert.deepEqual(result.collisions,[],label+' routes clear actor and inventory bounds');assert.deepEqual(result.outside,[],label+' bounds fit map');assert.deepEqual(result.smallTargets,[],label+' inventory targets are 44 rendered CSS pixels');assert.equal(result.nestedActorButtons,0,label+' no nested actor buttons');assert.equal(result.coverageStatus,'complete',label+' complete logical-owner coverage');
  return result;
}
async function heldNativeScreenshot(page,name){const file=name+'.png',selector=page.viewportSize().width<960?'.map-scroll':'#graph';await page.locator(selector).evaluate(element=>element.scrollIntoView({block:'center',inline:'nearest'}));await page.locator(selector).screenshot({path:path.join(heldNativeOutput,file)});heldNativeReport.screenshots.push(file);}
async function heldNativeAnimationSurface(page,mode){
  const records=[];
  for(const [architecture,width]of [['web',1920],['native',1920],['web',1480],['web',390]]){
    await page.setViewportSize({width,height:1200});await heldNativeChoose(page,'basic-keycloak');
    if(architecture==='native')await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.refs.architecture.value='native';a.refs.architecture.dispatchEvent(new Event('change',{bubbles:true}));});
    const before=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),step=a.steps.find(step=>step.from==='user'&&step.to==='browser'&&step.id.endsWith('-p02'));if(!step)throw new Error('Credential-entry fixture is unavailable');a.player.seek([step],.5,'step');return {snapshot:JSON.stringify(a.protocolSnapshot()),names:a.stepAttributeItems(step).map(item=>item.name)};});
    await page.locator('[data-pair="browser--user"] .connection-hit').focus();
    const surface=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),active=document.activeElement,halo=active.closest('.connection-group')?.querySelector('.edge-focus'),actors=Object.fromEntries([...a.refs.actors.querySelectorAll('[data-actor]')].filter(element=>!element.hidden).map(element=>{const r=element.getBoundingClientRect();return [element.dataset.actor,{x:(r.left+r.right)/2,y:(r.top+r.bottom)/2}];}));
      const panel=a.refs['step-attributes'],box=panel.getBoundingClientRect();
      return {actors,focusedConnection:active.classList.contains('connection-hit'),outline:getComputedStyle(active).outlineStyle,routeHighlight:!!halo&&Number(getComputedStyle(halo).opacity)>0&&Number.parseFloat(getComputedStyle(halo).strokeWidth)>=6,stepNames:[...panel.querySelectorAll('code')].map(element=>element.textContent),stepNamesVisible:!panel.closest('[hidden]')&&box.width>0&&box.height>0,after:JSON.stringify(a.protocolSnapshot())};
    });
    assert.equal(surface.focusedConnection,true,mode+' connection receives keyboard focus');
    assert.equal(surface.outline,'none',mode+' route focus does not draw a bounding rectangle through cards');
    assert.equal(surface.routeHighlight,true,mode+' route itself retains a visible focus indicator');
    assert.equal(surface.after,before.snapshot,mode+' route focus preserves the complete canonical snapshot');
    assert.equal(surface.stepNamesVisible,true,mode+' the paused credential fields remain visible');
    assert.deepEqual(surface.stepNames,before.names,mode+' the complete credential field set remains visible');
    const scene=await heldNativeScene(page,mode+' basic '+architecture+' '+width+' animation surface');
    if(width===1920){
      assert.equal(scene.mode,'full');const p=surface.actors,aligned=(a,b)=>Math.abs(a-b)<1;
      assert.ok(aligned(p.user.x,p.browser.x)&&p.user.y<p.browser.y,mode+' person/browser column and vertical order');
      assert.ok(p.realmA.x>p.browser.x,mode+' issuer stays to the right of its clients');
      if(architecture==='web')assert.ok(aligned(p.realmA.x,p.app.x)&&p.realmA.y<p.app.y,mode+' web backend and issuer form the server column');
      else assert.ok(aligned(p.app.x,p.browser.x)&&p.browser.y<p.app.y,mode+' native application stays in the client column');
    }
    delete scene.state;delete scene.holdings;delete surface.after;
    records.push({architecture,width,...scene,...surface,canonicalSnapshotPreserved:true});
    await heldNativeScreenshot(page,mode+'-basic-keycloak-'+architecture+'-'+width+'-animation-surface');
  }
  return records;
}
async function heldNativeStepAttributes(page,mode){
  const records=[];
  for(const [width,id,expanded]of [[1920,'basic-keycloak',false],[1920,'basic-saml',false],[1920,'lab-refresh-rotation',false],[1920,'lab-ad-forest-child-domains',true],[1480,'lab-ad-fast-as-success',true],[1050,'lab-ssh-cert-reissue',true],[390,'lab-ssh-cert-success',false]]){
    await page.setViewportSize({width,height:1200});await heldNativeChoose(page,id,expanded);
    const expected=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),step=a.steps.find(step=>a.stepAttributeItems(step).length>=2);
      if(!step)throw new Error('The native fixture needs a multi-attribute step.');
      a.player.seek([step],.5,'step');
      return {stepId:step.id,names:a.stepAttributeItems(step).map(item=>item.name)};
    });
    await page.locator('#step-attributes').scrollIntoViewIfNeeded();
    const actual=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),panel=a.refs['step-attributes'],r=panel.getBoundingClientRect(),graph=a.refs.graph.getBoundingClientRect();
      const external=!!panel.closest('#step-attributes-external'),collisions=[];
      if(!external)for(const node of a.querySelectorAll('.actor-card,.held-dock')){
        const b=node.getBoundingClientRect();
        if(!node.closest('[hidden]')&&b.width&&b.height&&r.left<b.right-1&&r.right>b.left+1&&r.top<b.bottom-1&&r.bottom>b.top+1)collisions.push(node.dataset.actor||node.dataset.heldDock);
      }
      return {geometry:a.refs.graph.dataset.heldGeometry,external,visible:!panel.closest('[hidden]')&&r.width>0&&r.height>0,names:[...panel.querySelectorAll('code')].map(node=>node.textContent),collisions,bounded:external?r.left>=-1&&r.right<=innerWidth+1:r.left>=graph.left-1&&r.right<=graph.right+1&&r.top>=graph.top-1&&r.bottom<=graph.bottom+1};
    });
    assert.equal(actual.visible,true,mode+' checked step-attribute panel remains visible beside inventories');
    assert.deepEqual(actual.names,expected.names,mode+' the complete names-only set survives responsive placement');
    assert.deepEqual(actual.collisions,[],mode+' step attributes clear complete participant/inventory bounds');
    assert.equal(actual.bounded,true,mode+' step attributes fit their map or external region');
    records.push({width,id,stepId:expected.stepId,...actual});
    if(width===1920||width===1480||width===390){const file=mode+'-'+id+'-'+width+'-step-attributes.png';await page.screenshot({path:path.join(heldNativeOutput,file),fullPage:false});heldNativeReport.screenshots.push(file);}
    await page.locator('#show-step-attributes').uncheck();assert.equal(await page.locator('#step-attributes').isVisible(),false);
    await page.locator('#show-step-attributes').check();assert.equal(await page.locator('#step-attributes').isVisible(),true);
  }
  return records;
}
async function heldNativeExact(page,mode){
  await heldNativeChoose(page,'lab-refresh-rotation');
  const holding=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R0'));
  await page.locator('#held-objects [data-held-actor="app"]').click();
  const control=page.locator('[data-holding-id='+JSON.stringify(holding.holdingId)+']:visible').first();await control.focus();await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection.artifactId),'R0',mode+' keyboard selects exact R0');
  await page.locator('#held-inspector [data-held-help]').click();await page.keyboard.press('Escape');assert.equal(await page.evaluate(()=>document.activeElement.hasAttribute('data-held-help')),true,mode+' help Escape restores exact trigger');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),step=a.steps.find(s=>s.id.endsWith('-response'));a.player.seek([step],.5,'step');});
  const delayed=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.heldView.snapshot();return {selection:a.heldView.selection.artifactId,holdings:s.holdings.filter(h=>h.actorId==='app').map(h=>h.artifactId),cursor:s.cursor};});
  assert.equal(delayed.selection,'R0');heldNativeCheck(delayed.holdings.includes('R0')&&!delayed.holdings.includes('R1'),mode+' delayed response retains old holding only');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectStep(a.steps.findIndex(s=>s.id.endsWith('-replace')),false);});
  const released=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {selection:a.heldView.selection.artifactId,status:document.querySelector('#held-inspector .held-detached-status').textContent,ids:a.heldView.snapshot().holdings.filter(h=>h.actorId==='app').map(h=>h.artifactId),focusHolding:document.activeElement.dataset.holdingId};});
  assert.equal(released.selection,'R0');heldNativeCheck(released.status.startsWith('No longer held'),mode+' removed R0 is historical');heldNativeCheck(!released.ids.includes('R0')&&released.ids.includes('R1'),mode+' conforming replacement');heldNativeCheck(!released.focusHolding||!released.focusHolding.includes('R1'),mode+' focus never substitutes R1');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),h=a.heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R1');a.heldView.select(h);a.player.seek(a.steps,0,'demo');});
  heldNativeCheck((await page.locator('#held-inspector .held-detached-status').textContent()).startsWith('Not created'),mode+' rewind cannot grant future R1');
  await page.locator('#reset').click();assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor),{eventIndex:-1,milestone:'initial'});assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection),null);
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectStep(a.steps.findIndex(s=>s.id.endsWith('-replace')),false);});
  const r1=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R1'));
  const replacementControl=page.locator('[data-holding-id='+JSON.stringify(r1.holdingId)+']:visible').first();
  if(!await replacementControl.count())await page.locator('#held-objects [data-held-actor="app"]').click();
  await replacementControl.focus();await page.keyboard.press('Enter');
  const fullSnapshot=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot());
  const file=mode+'-exact-R1-inspector.png';await page.locator('#held-inspector').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(heldNativeOutput,file),fullPage:false});heldNativeReport.screenshots.push(file);
  await page.locator('#speed').evaluate(input=>{input.value='4';input.dispatchEvent(new Event('input',{bubbles:true}));});
  await page.locator('#held-inspector [data-held-trace]').click();
  await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete');
  const exactReplay=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {artifactId:a.objectTraceSelection,sourceRows:a.traceQueue.map(step=>step.sourceIndex),snapshot:a.heldView.snapshot()};});
  assert.equal(exactReplay.artifactId,'R1');assert.deepEqual(exactReplay.snapshot,fullSnapshot,mode+' exact R1 replay equals the same full canonical source cursor');
  await page.locator('#reset').click();
  return {keyboardExactSelection:true,delayedResponse:true,conformingRelease:true,detachedHistory:true,rewind:true,reset:true,exactReplay:{artifactId:exactReplay.artifactId,sourceRows:exactReplay.sourceRows,cursor:exactReplay.snapshot.cursor,fullSnapshotEquality:true}};
}
async function heldNativeFocusState(page){
  return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),e=document.activeElement;return {holdingId:e?.dataset.holdingId||null,actorId:e?.dataset.heldActor||e?.dataset.heldCollapse||null,region:e?.closest('#held-objects,#held-docks,#held-inspector')?.id||null,selected:a.heldView.selection?.holdingId||null,connected:!!e?.isConnected,visible:!!e&&e.getClientRects().length>0};});
}
async function heldNativeOwnersAndFocus(page,mode){
  const records=[];
  for(const geometry of ['full','compact']){
    let width;
    for(const candidate of geometry==='full'?[1920]:[1600,1480,1280,1050]){
      await page.setViewportSize({width:candidate,height:1200});await heldNativeChoose(page,'lab-refresh-rotation');
      if(await page.locator('#graph').getAttribute('data-held-geometry')===geometry){width=candidate;break;}
    }
    heldNativeCheck(width,mode+' refresh fixture must exercise '+geometry);
    for(let cycle=0;cycle<3;cycle++)for(const actor of ['app','realmA','app']){
      await page.locator('#held-objects .held-actor-picker [data-held-actor="'+actor+'"]').click();
      const inventory=await page.evaluate(actor=>{const a=document.querySelector('auth-flow-studio');return {expected:a.heldView.snapshot().holdings.filter(h=>h.actorId===actor).map(h=>h.holdingId).sort(),actual:[...a.querySelectorAll('#held-objects [data-held-owner="'+actor+'"] [data-holding-id]')].map(e=>e.dataset.holdingId).sort()};},actor);
      assert.ok(inventory.expected.length>0,mode+' owner fixture has holdings');
      assert.deepEqual(inventory.actual,inventory.expected,mode+' '+geometry+' repeated owner return shows complete inventory');
    }
    const focus=[];
    for(const region of geometry==='full'?['held-objects','held-docks']:['held-objects']){
      const control=page.locator('#'+region+' [data-held-owner="app"] [data-holding-id]:visible').first(),id=await control.getAttribute('data-holding-id');
      await control.focus();await page.keyboard.press('Enter');
      let actual=await heldNativeFocusState(page);
      assert.equal(actual.holdingId,id,mode+' selection preserves exact holding');assert.equal(actual.region,region,mode+' selection preserves origin');
      await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.heldView.lastKey='';a.heldView.render();});
      actual=await heldNativeFocusState(page);
      assert.equal(actual.holdingId,id,mode+' redraw preserves exact holding');assert.equal(actual.region,region,mode+' redraw preserves origin');
      const screenshot=mode+'-'+geometry+'-'+region+'-exact-focus.png';await page.locator(region==='held-docks'?'#graph':'#held-objects').screenshot({path:path.join(heldNativeOutput,screenshot)});heldNativeReport.screenshots.push(screenshot);
      focus.push({origin:region,holdingId:id,afterRedraw:actual,screenshot});
    }
    await heldNativeScreenshot(page,mode+'-'+geometry+'-owner-return-focus');records.push({geometry,width,ownerReturnCycles:3,completeInventory:true,focus});
  }
  await page.setViewportSize({width:1920,height:1200});await heldNativeChoose(page,'lab-refresh-rotation');
  await page.locator('#held-objects .held-actor-picker [data-held-actor="app"]').click();
  const dock=page.locator('#held-docks [data-held-owner="app"] [data-holding-id]:visible').first(),dockId=await dock.getAttribute('data-holding-id');
  await dock.focus();await page.keyboard.press('Enter');await page.setViewportSize({width:390,height:844});
  await page.waitForFunction(()=>document.querySelector('#graph').dataset.heldGeometry==='external');
  const resize=await heldNativeFocusState(page);assert.equal(resize.holdingId,dockId,mode+' resize retains equivalent exact holding');assert.equal(resize.region,'held-objects',mode+' removed dock falls back to complete list');
  await page.setViewportSize({width:1920,height:1200});await heldNativeChoose(page,'lab-refresh-rotation');
  await page.locator('#held-objects .held-actor-picker [data-held-actor="app"]').click();
  const r0=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R0').holdingId);
  await page.locator('#held-objects [data-holding-id='+JSON.stringify(r0)+']').focus();await page.keyboard.press('Enter');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectStep(a.steps.findIndex(s=>s.id.endsWith('-replace')),false);});
  const removal=await heldNativeFocusState(page);assert.equal(removal.selected,r0,mode+' removal retains historical selection');assert.equal(removal.holdingId,null,mode+' removal never substitutes another holding');assert.equal(removal.actorId,'app',mode+' removal returns to logical owner');assert.equal(removal.region,'held-objects',mode+' removal retains list origin');
  await page.locator('#held-objects .held-actor-picker [data-held-actor="app"]').click();
  const collapse=page.locator('#held-objects [data-held-collapse="app"]');
  assert.equal(await collapse.count(),1,mode+' explicit collapse exists');await collapse.focus();await page.keyboard.press('Enter');
  const collapsed=await heldNativeFocusState(page);assert.equal(await page.locator('#held-objects [data-held-owner="app"] [data-holding-id]').count(),0,mode+' explicit collapse closes list');assert.equal(collapsed.actorId,'app',mode+' collapse restores owner trigger');assert.equal(collapsed.region,'held-objects',mode+' collapse retains list origin');
  await heldNativeScreenshot(page,mode+'-focus-explicit-collapse');
  return {geometries:records,fallbacks:{resize,removal,collapse:collapsed}};
}
async function heldNativeRepresentations(page,mode){
  await page.setViewportSize({width:1920,height:1200});
  const fixture=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio');a.selectLabScenario('core');
    Object.assign(a,{mode:'password',architecture:'web',upstream:'single',applicationProtocol:'oidc',brokerProtocol:'oidc',providerProfileId:'generic',providerManaged:false,oidcFlow:'authorization-code',tokenProtection:'app-jwe'});a.refreshConfiguration();a.selectStep(a.steps.length-1,false);
    const artifact=a.heldView.compiled().plan.artifacts.find(o=>o.artifactId==='oidc-app-id-token'),wire=a.steps.find(s=>s.id==='single-web-password-l24');
    return {wireId:wire?.id,wireValue:wire?.payload.find(p=>p.attributeId==='idTokenA')?.value,decodedValue:artifact?.representations.find(r=>r.representationId==='view')?.fields.find(f=>f.attributeId==='idTokenA')?.value};
  });
  assert.equal(typeof fixture.wireValue,'string',mode+' authored compact JWE fixture');assert.equal(fixture.wireValue.split('.').length,5,mode+' five-part fixture value');assert.notEqual(fixture.decodedValue,fixture.wireValue);
  const records=[];
  for(const representationId of ['encrypted','view']){
    await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');if(a.hasTrace)a.clearAttribute();a.selectStep(a.steps.length-1,false);});
    await page.locator('#held-objects .held-actor-picker [data-held-actor="app"]').click();
    const holding=await page.evaluate(rep=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='oidc-app-id-token'&&h.representationId===rep),representationId);
    assert.ok(holding,mode+' final '+representationId+' holding');
    await page.locator('#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']').click();
    await page.locator('#held-inspector [data-held-trace]').click();await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
    const samples=[];
    for(const kind of ['wire','decoded']){
      const sample=await page.evaluate(({kind,fixture})=>{
        const a=document.querySelector('auth-flow-studio'),expected=kind==='wire'?fixture.wireValue:fixture.decodedValue;
        const row=a.traceQueue.find(r=>(kind==='wire'?r.sourceStepId===fixture.wireId:r.from==='app'&&r.to==='app')&&r.payload.some(f=>f.attributeId==='idTokenA'&&(kind==='wire'||f.value===expected)));
        if(!row)throw new Error('Missing '+kind+' exact representation occurrence');
        const index=row.payload.findIndex(f=>f.attributeId==='idTokenA');let found=kind==='decoded';
        if(kind==='decoded')a.player.seek([row],1,'object');
        else for(let n=0;n<=1000;n++){a.player.seek([row],n/1000,'object');const e=a.player.snapshot();if(e.packetIndex===index&&e.visible){found=true;break;}}
        if(!found)throw new Error('No visible '+kind+' packet sample');
        a.inspection={type:'step'};a.renderInspector();
        return {kind,rowId:row.id,sourceStepId:row.sourceStepId,expected,packetName:a.refs['packet-name'].textContent,packetValue:a.refs['packet-value'].textContent,activeMessage:a.querySelector('#held-active-message').textContent,packetVisible:!a.refs.packet.hidden,displayedFields:[...a.refs.inspector.querySelectorAll('.field-value')].map(e=>e.textContent),fieldsVisible:a.refs.inspector.getBoundingClientRect().height>0,holdings:a.heldView.snapshot().holdings};
      },{kind,fixture});
      assert.equal(sample.fieldsVisible,true,mode+' exact occurrence fields actually displayed');assert.ok(sample.displayedFields.includes(sample.expected),mode+' '+representationId+' selection displays full '+kind+' occurrence value');
      if(kind==='wire'){assert.equal(sample.packetVisible,true,mode+' encrypted wire packet actually displayed');assert.equal(sample.packetValue,sample.expected.slice(0,38)+(sample.expected.length>38?'…':''),mode+' compact JWE packet value');assert.ok(sample.activeMessage.includes(sample.expected),mode+' active message contains full compact JWE');}
      const file=mode+'-jwe-'+representationId+'-'+kind+'-display.png';await page.locator(kind==='wire'?'#graph':'#inspector').screenshot({path:path.join(heldNativeOutput,file)});heldNativeReport.screenshots.push(file);samples.push(sample);
    }
    records.push({selectedRepresentation:representationId,samples});
  }
  assert.deepEqual(records[0].samples.map(s=>s.holdings),records[1].samples.map(s=>s.holdings),mode+' representation selection never changes canonical holdings');
  return {fixture,records};
}
async function heldNativeBoundaries(page,mode){
  const records=[];
  for(const suffix of ['request','response'])for(const replay of ['full','connection','exact'])for(const speed of [.5,1,4]){
    await heldNativeChoose(page,'lab-refresh-rotation');
    const prepared=await page.evaluate(({suffix,replay,speed})=>{
      const a=document.querySelector('auth-flow-studio'),source=a.steps.find(s=>s.id==='lab-refresh-rotation-'+suffix),event=a.heldView.compiled().plan.events[source.id],message=event.messages[0];
      a.player.setSpeed(speed);let queue=a.steps,kind='demo';
      if(replay==='connection'){a.replayConnection([a.nodeId(source.from),a.nodeId(source.to)].sort().join('--'));a.player.pause();queue=a.player.queue.slice();kind='connection';}
      if(replay==='exact'){
        if(suffix==='response')a.selectStep(a.steps.length-1,false);const h=a.heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId===(suffix==='response'?'R1':'R0'));
        a.heldView.select(h);a.heldView.trace(h.artifactId);a.player.pause();queue=a.traceQueue.slice();kind='object';
      }
      const row=queue.find(r=>(r.sourceStepId||r.id)===source.id&&(!r.heldCursorEnd||r.heldCursorEnd.milestone==='received'||r.payload?.some(p=>source.payload.some(f=>f.attributeId===p.attributeId))));
      if(!row||!message)throw new Error('Missing authored '+replay+' '+suffix+' boundary');
      const timing=a.player.getTiming(row,kind),start=timing.start,end=timing.end,receipt=(message.end-start)/(end-start);
      if(!(receipt>0&&receipt<=1))throw new Error('Exact row does not contain receipt boundary');
      window.__heldBoundary={queue,kind,row,message,receipt,index:queue.indexOf(row)};
      const deliveryObjects=event.messages.filter(m=>m.from===message.from&&m.to===message.to&&m.end===message.end).flatMap(m=>m.objects);
      return {sourceId:source.id,rowId:row.id,payloadCount:row.payload.length,sourcePayloadCount:source.payload.length,receipt,message,deliveryObjects,kind};
    },{suffix,replay,speed});
    const samples=[];
    for(const [label,offset]of [['before',-.00001],['at',0],['after',.00001]]){
      const sample=await page.evaluate(({label,offset})=>{
        const a=document.querySelector('auth-flow-studio'),b=window.__heldBoundary,duration=a.player.totalDuration([b.row]),prior=a.player.totalDuration(b.queue.slice(0,b.index)),total=a.player.totalDuration(b.queue);
        const endpointClamped=b.kind==='connection'&&b.receipt===1&&label==='at';
        if(endpointClamped)a.player.seek([b.row],1,b.kind);
        else a.player.seek(b.queue,(prior+(b.receipt+offset)*duration)/total,b.kind);
        const p=a.player.snapshot(),s=a.heldView.snapshot(),packet=a.refs.packet;
        const result={label,endpointClamped,sampleScope:endpointClamped?'Isolated connection-row endpoint; receipt ends the replay interval':'Actual replay queue',cursor:s.cursor,holdings:s.holdings,inFlight:s.inFlight,state:s.state,displayedState:JSON.parse(a.querySelector('#protocol-state-value').textContent),summary:a.querySelector('#protocol-state-summary').textContent,phase:packet.dataset.messagePhase,messageId:packet.dataset.messageId,routeProgress:Number(packet.dataset.routeProgress),packetVisible:!packet.hidden,packetName:a.refs['packet-name'].textContent,packetCount:a.refs['packet-count'].textContent,playerPhase:p.messagePhase,playerProgress:p.progress,stepId:p.step?.id};
        if(b.kind==='connection'&&label==='after'){
          const source=a.steps[s.cursor.eventIndex],event=a.heldView.compiled().plan.events[source.id],at=s.cursor.milestone==='before'?0:event.milestones.find(m=>m.id===s.cursor.milestone).at;
          a.player.seek([source],at,'demo');const canonical=a.heldView.snapshot();result.canonicalAtCurrentCursor={holdings:canonical.holdings,state:canonical.state,inFlight:canonical.inFlight};
          a.player.seek(b.queue,(prior+(b.receipt+offset)*duration)/total,b.kind);
        }
        return result;
      },{label,offset});
      assert.deepEqual(sample.displayedState,sample.state,mode+' '+replay+' displayed protocol state agrees with holdings cursor');
      assert.ok(sample.summary.includes(sample.cursor.milestone),mode+' displayed current-state summary uses the same boundary');
      if(label==='before'){assert.equal(sample.phase,'in-flight',mode+' before receipt packet phase');assert.ok(sample.inFlight.length>0,mode+' before receipt canonical in-flight');}
      else if(replay==='connection'&&label==='after'){
        assert.ok(!sample.inFlight.some(m=>m.messageId===prepared.message.messageId),mode+' completed connection message is no longer in flight');
        if(sample.phase==='in-flight')assert.ok(sample.inFlight.some(m=>m.messageId===sample.messageId),mode+' next connection packet belongs to its own current canonical message');
        assert.deepEqual({holdings:sample.holdings,state:sample.state,inFlight:sample.inFlight},sample.canonicalAtCurrentCursor,mode+' after connection advances, current state equals full replay at its actual source cursor');
      }
      else{assert.notEqual(sample.phase,'in-flight',mode+' no unfinished packet after receipt');assert.equal(sample.inFlight.length,0,mode+' no canonical in-flight after receipt');if(sample.phase==='received'){assert.equal(sample.routeProgress,1,mode+' received packet is at destination');assert.equal(sample.packetVisible,false,mode+' received packet is not still visibly travelling');}}
      const objects=prepared.deliveryObjects;
      for(const object of objects){
        const acquired=sample.holdings.some(h=>h.actorId===prepared.message.to&&h.artifactId===object.artifactId&&h.representationId===object.representationId);
        if(label!=='before'&&!(replay==='connection'&&label==='after'))assert.equal(acquired,true,mode+' delivered object is held at receipt');
        else if(label==='before'&&suffix==='response')assert.equal(acquired,false,mode+' new response object is absent before receipt');
      }
      samples.push(sample);
      if(speed===1&&suffix==='response')await heldNativeScreenshot(page,mode+'-refresh-'+replay+'-'+label+'-receipt');
    }
    records.push({replay,speed,...prepared,samples});
    if(replay!=='full'){
      const full=records.find(r=>r.sourceId===prepared.sourceId&&r.replay==='full'&&r.speed===speed);
      const canonical=samples=>samples.filter(s=>replay!=='connection'||s.label!=='after').map(s=>({holdings:s.holdings,state:s.state,inFlight:s.inFlight}));
      assert.deepEqual(canonical(samples),canonical(full.samples),mode+' '+replay+' has the same canonical boundary state and holdings as full replay');
    }
  }
  heldNativeCheck(new Set(records.map(r=>r.sourcePayloadCount)).size>1,mode+' boundary acceptance includes different payload sizes');
  return records;
}
async function heldNativeFamilyComposition(page,mode){
  const records=[],fixtures=['lab-ad-first-sign-in','lab-ad-fast-as-success','lab-ad-forest-child-domains','lab-ssh-cert-success','lab-ssh-cert-reissue','lab-ssh-device-cadence','lab-ssh-sssd-success','lab-ssh-gss-success'];
  for(const id of fixtures)for(const expanded of [false,true]){
    await page.setViewportSize({width:1920,height:1200});await heldNativeChoose(page,id,expanded,true);
    const scene=await heldNativeScene(page,mode+' composition '+id+' '+expanded);
    const composition=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),graph=a.refs.graph.getBoundingClientRect(),visible=e=>!!e.getClientRects().length&&!e.closest('[hidden]'),box=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,x:(r.left+r.right)/2,y:(r.top+r.bottom)/2};};
      const actors=Object.fromEntries([...a.refs.actors.querySelectorAll('[data-actor]')].filter(visible).map(e=>[e.dataset.actor,box(e)]));
      const labels=[...a.querySelectorAll('#held-docks .held-dock > button[data-held-actor]')].filter(visible).map(e=>{
        const label=e.querySelector('strong')||e,r=box(label),b=box(e),range=document.createRange();range.selectNodeContents(label);
        const lines=[...range.getClientRects()].map(r=>({left:r.left,right:r.right,top:r.top,bottom:r.bottom}));
        return {actorId:e.dataset.heldActor,expected:a.actor(e.dataset.heldActor).name,text:label.textContent,button:b,label:r,lines,clipped:label.scrollWidth>label.clientWidth+1||label.scrollHeight>label.clientHeight+1||lines.some(l=>l.left<b.left-1||l.right>b.right+1||l.top<b.top-1||l.bottom>b.bottom+1)};
      });
      const frames=Object.fromEntries(Object.entries(actors).map(([id,r])=>{const dock=a.querySelector('[data-held-dock="'+id+'"]'),d=dock&&visible(dock)?box(dock):r;return [id,{left:Math.min(r.left,d.left),right:Math.max(r.right,d.right),top:Math.min(r.top,d.top),bottom:Math.max(r.bottom,d.bottom)}];}));
      const attachments=[];
      for(const group of a.refs.connections.querySelectorAll('[data-pair]')){
        const ids=group.dataset.pair.split('--'),line=group.querySelector('.connection-line'),matrix=line?.getScreenCTM();if(!matrix||!ids.every(id=>frames[id]))continue;
        const length=line.getTotalLength();
        for(const n of [0,length]){
          const point=line.getPointAtLength(n),p=new DOMPoint(point.x,point.y).matrixTransform(matrix);
          const distance=Math.min(...ids.map(id=>{const r=frames[id],dx=Math.max(r.left-p.x,0,p.x-r.right),dy=Math.max(r.top-p.y,0,p.y-r.bottom);if(dx||dy)return Math.hypot(dx,dy);return Math.min(p.x-r.left,r.right-p.x,p.y-r.top,r.bottom-p.y);}));
          attachments.push({pair:group.dataset.pair,endpoint:n===0?'start':'end',distance});
        }
      }
      const rows=[...new Set(Object.values(actors).map(r=>Math.round(r.y)))].sort((a,b)=>a-b),rowGaps=rows.slice(1).map((y,i)=>y-rows[i]);
      const bounds={left:Math.min(...Object.values(frames).map(r=>r.left)),right:Math.max(...Object.values(frames).map(r=>r.right)),top:Math.min(...Object.values(frames).map(r=>r.top)),bottom:Math.max(...Object.values(frames).map(r=>r.bottom))};
      return {actors,labels,attachments,rowGaps,graphTop:graph.top,graphHeight:graph.height,graphWidth:graph.width,occupied:{width:bounds.right-bounds.left,height:bounds.bottom-bounds.top},geometry:a.refs.graph.dataset.heldGeometry};
    });
    assert.deepEqual(composition.labels.filter(l=>l.clipped),[],mode+' '+id+' complete logical-owner names fit rendered controls');
    for(const label of composition.labels)assert.equal(label.text.trim(),label.expected,mode+' merged owner displays complete logical name');
    heldNativeCheck(composition.attachments.every(a=>a.distance<=20),mode+' '+id+' connector endpoints attach to participant frames');
    heldNativeCheck(composition.rowGaps.every(gap=>gap<=composition.graphWidth*.28),mode+' '+id+' composition has no redundant empty grid row');
    if(id==='lab-ad-first-sign-in'&&!expanded){
      const p=composition.actors;
      heldNativeCheck(p.adUser.x<p.adWorkstation.x&&p.adWorkstation.x<p.adKdc.x,mode+' AD retains user/workstation/KDC columns');
      heldNativeCheck(Math.abs(p.adUser.y-p.adWorkstation.y)<2&&Math.abs(p.adWorkstation.y-p.adKdc.y)<2,mode+' AD primary actors share top row');
      heldNativeCheck(Math.abs(p.adService.x-p.adWorkstation.x)<2&&p.adService.y>p.adWorkstation.y,mode+' file service stays below workstation');
    }
    if(id==='lab-ssh-cert-success'&&!expanded){
      const p=composition.actors;
      heldNativeCheck(p.user.y<p.sshCli.y&&Math.abs(p.user.x-p.sshCli.x)<2,mode+' SSH user remains above native CLI');
      heldNativeCheck(p.sshCli.x<p.browser.x&&p.browser.x<p.sshIdp.x,mode+' enrollment browser bridges CLI and issuer columns');
      heldNativeCheck(p.sshIdp.y<p.sshCa.y,mode+' SSH issuer remains above certificate authority');
    }
    if(id==='lab-ssh-gss-success'){
      const p=composition.actors;
      assert.equal(p.user,undefined,mode+' cache-only GSS has no inert user actor on map');
      const middle=composition.graphTop+composition.graphHeight/2;
      for(const actorId of ['sshCli','kdc','sshHost'])heldNativeCheck(Math.abs(p[actorId].y-middle)<2,mode+' GSS '+actorId+' is centered on rendered graph midline');
    }
    const file=mode+'-'+id+'-'+(expanded?'expanded':'collapsed')+'-composition.png';await page.locator('#graph').screenshot({path:path.join(heldNativeOutput,file)});heldNativeReport.screenshots.push(file);
    delete scene.state;delete scene.holdings;records.push({id,expanded,screenshot:file,scene,...composition});
  }
  return {scope:'Rendered Chromium composition and complete label bounds; not a human aesthetic review',records};
}
try{
  const require=createRequire(import.meta.url),module=process.env.PLAYWRIGHT_MODULE?await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href):require('playwright');
  heldNativeProfile=fs.mkdtempSync(path.join(os.tmpdir(),'auth-lab-held-native-'));
  heldNativeContext=await module.chromium.launchPersistentContext(heldNativeProfile,{headless:true,viewport:{width:1920,height:1200},bypassCSP:false,executablePath:process.env.CHROMIUM_EXECUTABLE||module.chromium.executablePath(),args:['--no-sandbox','--disable-dev-shm-usage']});
  heldNativeBrowser=heldNativeContext.browser();heldNativeReport.browser=heldNativeBrowser.version();
  heldNativeServer=http.createServer((request,response)=>{const pathname=decodeURIComponent(new URL(request.url,'http://localhost').pathname),file=path.resolve(heldNativeRoot,'.'+(pathname==='/'?'/index.html':pathname));if(!file.startsWith(heldNativeRoot+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){response.writeHead(404);response.end();return;}response.writeHead(200,{'Content-Type':{'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(response);});
  await new Promise(resolve=>heldNativeServer.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+heldNativeServer.address().port;
  const fingerprints=new Map();
  for(const mode of ['source-http','standalone-http','standalone-file']){
    const context=heldNativeContext,page=await context.newPage(),errors=[],requests=[],violations=[];
    await context.clearCookies();await page.setViewportSize({width:1920,height:1200});
    await heldNativeObserve(page,mode,violations,errors,requests);
    const target=mode==='standalone-file'?pathToFileURL(path.join(heldNativeRoot,'dist/auth-flow-studio.html')).href:origin+(mode==='source-http'?'/index.html':'/dist/auth-flow-studio.html');
    await context.route('**/*',route=>{const url=route.request().url();return (mode==='standalone-file'?url===target:url.startsWith(origin+'/'))?route.continue():route.abort();});
    const record={mode,target,scenarios:[],layouts:[],checks:[],runtimeErrors:errors,csp:{scope:'All application documents including every reload; accumulated host-side',violations}};heldNativeReport.modes.push(record);
    await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
    assert.equal(await page.locator('#show-held-objects').isChecked(),true);
    const choices=await page.evaluate(()=>[...document.querySelector('auth-flow-studio').refs['lab-scenario'].options].map(option=>option.value));
    assert.equal(choices.length,141,mode+' full 141-choice inventory gate');
    for(const id of choices){
      await heldNativeChoose(page,id);
      const initial=await heldNativeScene(page,mode+' '+id+' initial');
      assert.equal(initial.mode,'full',mode+' '+id+' collapsed desktop initial inventory remains full');
      await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectStep(a.steps.length-1,false);});
      const final=await heldNativeScene(page,mode+' '+id+' final');
      assert.equal(final.mode,'full',mode+' '+id+' collapsed desktop final inventory remains full');
      const fingerprint=heldNativeHash(JSON.stringify({initial:{holdings:initial.holdings,state:initial.state},final:{holdings:final.holdings,state:final.state}}));
      if(mode==='source-http')fingerprints.set(id,fingerprint);else assert.equal(fingerprint,fingerprints.get(id),mode+' source/emitted exact state for '+id);
      record.scenarios.push({id,initialHoldings:initial.holdings.length,finalHoldings:final.holdings.length,initialMode:initial.mode,mode:final.mode,fingerprint});
    }
    for(const width of [1920,1600,1480,1050,390,280]){await page.setViewportSize({width,height:1100});for(const id of ['lab-ad-forest-child-domains','lab-ssh-cert-reissue','lab-ad-fast-as-success'])for(const expanded of [false,true]){await heldNativeChoose(page,id,expanded,true);const scene=await heldNativeScene(page,mode+' '+id+' '+width+'px '+expanded);delete scene.state;delete scene.holdings;record.layouts.push(scene);}if(width===1920||width===1480||width===390)await heldNativeScreenshot(page,mode+'-'+width+'-inventory');}
    for(const geometry of ['full','compact','external'])heldNativeCheck(record.layouts.some(scene=>scene.mode===geometry),mode+' actually exercises '+geometry+' inventory geometry');
    record.animationSurface=await heldNativeAnimationSurface(page,mode);
    record.stepAttributes=await heldNativeStepAttributes(page,mode);
    record.familyComposition=await heldNativeFamilyComposition(page,mode);record.checks.push('Kerberos and SSH collapsed/expanded rendered composition, complete logical-owner labels and frame attachment');
    await page.setViewportSize({width:1920,height:1200});record.exact=await heldNativeExact(page,mode);
    record.code1={};
    record.code1.representations=await heldNativeRepresentations(page,mode);
    record.code1.boundaries=await heldNativeBoundaries(page,mode);
    record.code1.ownersAndFocus=await heldNativeOwnersAndFocus(page,mode);
    record.checks.push('HC01 rendered encrypted/decoded occurrence values from both selections','HC02 authored receipt boundaries across full/connection/exact replay, payload sizes and speeds','HC08 repeated owner return complete lists in full/compact','HC09 exact focus origin with separate resize/removal/collapse fallbacks');
    await heldNativeChoose(page,'lab-ad-forest-child-domains',true,true);const before=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {positions:a.positions,cursor:a.heldView.snapshot().cursor};});await page.locator('#show-held-objects').uncheck();assert.equal(await page.evaluate(()=>document.activeElement.id),'show-held-objects');await page.locator('#show-held-objects').check();assert.deepEqual(await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {positions:a.positions,cursor:a.heldView.snapshot().cursor};}),before,mode+' visibility does not reflow or seek');
    const settings=await context.newPage();await settings.goto('chrome://settings/appearance');
    record.browserZoom=[];for(const zoom of [2,4]){await settings.evaluate(zoom=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(zoom,resolve)),zoom);await page.reload({waitUntil:'networkidle'});await heldNativeChoose(page,'lab-ad-forest-child-domains',true,true);const scene=await heldNativeScene(page,mode+' actual browser zoom '+zoom,{routes:true});heldNativeCheck(Math.abs(scene.viewport.width-1920/zoom)<=2,mode+' actual zoom changes CSS layout viewport');heldNativeCheck(scene.viewport.visualScale===1,mode+' browser zoom is not pinch/CSS zoom');delete scene.state;delete scene.holdings;record.browserZoom.push({zoom,zoomIsBrowserUiZoom:true,...scene});}await settings.evaluate(()=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(1,resolve)));await settings.close();await page.reload({waitUntil:'networkidle'});
    await page.emulateMedia({reducedMotion:'reduce'});await heldNativeChoose(page,'lab-dpop');await page.locator('#play').click();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete');record.reducedMotion={status:'complete',cursor:await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor)};
    assert.deepEqual(errors,[],mode+' runtime errors');assert.deepEqual(violations,[],mode+' no application CSP violations across all documents');heldNativeCheck(requests.every(url=>mode==='standalone-file'?url===target:url.startsWith(origin+'/')),mode+' no external application requests');
    record.requests=requests.length;record.checks.push('all picker choices initial/final','source/emitted identity','authored web/native client-server columns','path-following keyboard focus without SVG bounding rectangles','dense full/compact/external layouts','complete visible step-attribute names and collision-aware fallback','44 CSS pixel targets','route/dock clearance','keyboard exact-object lifecycle','exact R1 replay/full-source equality','visibility reserve','actual browser zoom 200%/400%','reduced motion','CSP/no external requests');
    await page.close();await context.unroute('**/*');
    await heldNativeTouch(heldNativeBrowser,mode,target,origin,record);record.checks.push('native touch in '+mode);
  }
  heldNativeReport.identityAfter=heldNativeIdentity();assert.deepEqual(heldNativeReport.identityAfter,heldNativeReport.identity,'source and emitted bytes unchanged through native acceptance');heldNativeReport.passed=true;
}catch(error){heldNativeReport.failures.push({message:error.message,stack:error.stack});process.exitCode=1;}
finally{await heldNativeContext?.close();if(heldNativeServer)await new Promise(resolve=>heldNativeServer.close(resolve));if(heldNativeProfile)fs.rmSync(heldNativeProfile,{recursive:true,force:true});fs.writeFileSync(path.join(heldNativeOutput,'held-objects-native-status.json'),JSON.stringify(heldNativeReport,null,2)+'\n');console.log(JSON.stringify({passed:heldNativeReport.passed,browser:heldNativeReport.browser,modes:heldNativeReport.modes.map(mode=>({mode:mode.mode,scenarios:mode.scenarios.length,layouts:mode.layouts.length,checks:mode.checks})),failures:heldNativeReport.failures.map(failure=>failure.message),evidenceDirectory:heldNativeOutput},null,2));}
