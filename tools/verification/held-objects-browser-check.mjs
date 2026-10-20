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
try{
  const require=createRequire(import.meta.url),module=process.env.PLAYWRIGHT_MODULE?await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href):require('playwright');
  heldNativeProfile=fs.mkdtempSync(path.join(os.tmpdir(),'auth-lab-held-native-'));
  heldNativeContext=await module.chromium.launchPersistentContext(heldNativeProfile,{headless:true,viewport:{width:1920,height:1200},bypassCSP:false,executablePath:process.env.CHROMIUM_EXECUTABLE||module.chromium.executablePath(),args:['--no-sandbox','--disable-dev-shm-usage']});
  heldNativeBrowser=heldNativeContext.browser();heldNativeReport.browser=heldNativeBrowser.version();
  heldNativeServer=http.createServer((request,response)=>{const pathname=decodeURIComponent(new URL(request.url,'http://localhost').pathname),file=path.resolve(heldNativeRoot,'.'+(pathname==='/'?'/index.html':pathname));if(!file.startsWith(heldNativeRoot+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){response.writeHead(404);response.end();return;}response.writeHead(200,{'Content-Type':{'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(response);});
  await new Promise(resolve=>heldNativeServer.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+heldNativeServer.address().port;
  const fingerprints=new Map();
  for(const mode of ['source-http','standalone-http','standalone-file']){
    const context=heldNativeContext,page=await context.newPage(),errors=[],requests=[];
    await context.clearCookies();await page.setViewportSize({width:1920,height:1200});
    page.on('pageerror',error=>errors.push(String(error)));page.on('request',request=>requests.push(request.url()));
    await page.addInitScript(()=>{window.__heldNativeViolations=[];document.addEventListener('securitypolicyviolation',event=>window.__heldNativeViolations.push({directive:event.effectiveDirective,blocked:event.blockedURI,disposition:event.disposition}));});
    const target=mode==='standalone-file'?pathToFileURL(path.join(heldNativeRoot,'dist/auth-flow-studio.html')).href:origin+(mode==='source-http'?'/index.html':'/dist/auth-flow-studio.html');
    await context.route('**/*',route=>{const url=route.request().url();return (mode==='standalone-file'?url===target:url.startsWith(origin+'/'))?route.continue():route.abort();});
    await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);
    const record={mode,target,scenarios:[],layouts:[],checks:[]};heldNativeReport.modes.push(record);
    assert.equal(await page.locator('#show-held-objects').isChecked(),true);
    const choices=await page.evaluate(()=>[...document.querySelector('auth-flow-studio').refs['lab-scenario'].options].map(option=>option.value));
    for(const id of choices){await heldNativeChoose(page,id);const initial=await heldNativeScene(page,mode+' '+id+' initial');await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectStep(a.steps.length-1,false);});const final=await heldNativeScene(page,mode+' '+id+' final');const fingerprint=heldNativeHash(JSON.stringify({initial:{holdings:initial.holdings,state:initial.state},final:{holdings:final.holdings,state:final.state}}));if(mode==='source-http')fingerprints.set(id,fingerprint);else assert.equal(fingerprint,fingerprints.get(id),mode+' source/emitted exact state for '+id);record.scenarios.push({id,initialHoldings:initial.holdings.length,finalHoldings:final.holdings.length,mode:final.mode,fingerprint});}
    for(const width of [1920,1600,1480,1050,390,280]){await page.setViewportSize({width,height:1100});for(const id of ['lab-ad-forest-child-domains','lab-ssh-cert-reissue','lab-ad-fast-as-success'])for(const expanded of [false,true]){await heldNativeChoose(page,id,expanded,true);const scene=await heldNativeScene(page,mode+' '+id+' '+width+'px '+expanded);delete scene.state;delete scene.holdings;record.layouts.push(scene);}if(width===1920||width===1480||width===390)await heldNativeScreenshot(page,mode+'-'+width+'-inventory');}
    for(const geometry of ['full','compact','external'])heldNativeCheck(record.layouts.some(scene=>scene.mode===geometry),mode+' actually exercises '+geometry+' inventory geometry');
    record.animationSurface=await heldNativeAnimationSurface(page,mode);
    record.stepAttributes=await heldNativeStepAttributes(page,mode);
    await page.setViewportSize({width:1920,height:1200});record.exact=await heldNativeExact(page,mode);
    await heldNativeChoose(page,'lab-ad-forest-child-domains',true,true);const before=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {positions:a.positions,cursor:a.heldView.snapshot().cursor};});await page.locator('#show-held-objects').uncheck();assert.equal(await page.evaluate(()=>document.activeElement.id),'show-held-objects');await page.locator('#show-held-objects').check();assert.deepEqual(await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {positions:a.positions,cursor:a.heldView.snapshot().cursor};}),before,mode+' visibility does not reflow or seek');
    const settings=await context.newPage();await settings.goto('chrome://settings/appearance');
    record.browserZoom=[];for(const zoom of [2,4]){await settings.evaluate(zoom=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(zoom,resolve)),zoom);await page.reload({waitUntil:'networkidle'});await heldNativeChoose(page,'lab-ad-forest-child-domains',true,true);const scene=await heldNativeScene(page,mode+' actual browser zoom '+zoom,{routes:true});heldNativeCheck(Math.abs(scene.viewport.width-1920/zoom)<=2,mode+' actual zoom changes CSS layout viewport');heldNativeCheck(scene.viewport.visualScale===1,mode+' browser zoom is not pinch/CSS zoom');delete scene.state;delete scene.holdings;record.browserZoom.push({zoom,zoomIsBrowserUiZoom:true,...scene});}await settings.evaluate(()=>new Promise(resolve=>chrome.settingsPrivate.setDefaultZoom(1,resolve)));await settings.close();await page.reload({waitUntil:'networkidle'});
    await page.emulateMedia({reducedMotion:'reduce'});await heldNativeChoose(page,'lab-dpop');await page.locator('#play').click();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete');record.reducedMotion={status:'complete',cursor:await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().cursor)};
    assert.deepEqual(errors,[],mode+' runtime errors');assert.deepEqual(await page.evaluate(()=>window.__heldNativeViolations),[],mode+' no application CSP violations');heldNativeCheck(requests.every(url=>mode==='standalone-file'?url===target:url.startsWith(origin+'/')),mode+' no external application requests');
    record.requests=requests.length;record.checks.push('all picker choices initial/final','source/emitted identity','authored web/native client-server columns','path-following keyboard focus without SVG bounding rectangles','dense full/compact/external layouts','complete visible step-attribute names and collision-aware fallback','44 CSS pixel targets','route/dock clearance','keyboard exact-object lifecycle','exact R1 replay/full-source equality','visibility reserve','actual browser zoom 200%/400%','reduced motion','CSP/no external requests');
    await page.close();await context.unroute('**/*');
  }
  const touchContext=await heldNativeBrowser.newContext({viewport:{width:390,height:844},hasTouch:true,isMobile:true}),touch=await touchContext.newPage();await touch.goto(origin+'/dist/auth-flow-studio.html',{waitUntil:'networkidle'});await touch.locator('#held-objects [data-held-actor]').first().tap();const touchObject=touch.locator('#held-objects [data-holding-id]:visible').first();await touchObject.tap();heldNativeCheck(await touch.locator('#held-inspector').isVisible(),'touch opens exact-object inspector');heldNativeReport.touch={viewport:{width:390,height:844},nativeTouch:true,exactObjectInspector:true};await touchContext.close();
  heldNativeReport.identityAfter=heldNativeIdentity();assert.deepEqual(heldNativeReport.identityAfter,heldNativeReport.identity,'source and emitted bytes unchanged through native acceptance');heldNativeReport.passed=true;
}catch(error){heldNativeReport.failures.push({message:error.message,stack:error.stack});process.exitCode=1;}
finally{await heldNativeContext?.close();if(heldNativeServer)await new Promise(resolve=>heldNativeServer.close(resolve));if(heldNativeProfile)fs.rmSync(heldNativeProfile,{recursive:true,force:true});fs.writeFileSync(path.join(heldNativeOutput,'held-objects-native-status.json'),JSON.stringify(heldNativeReport,null,2)+'\n');console.log(JSON.stringify({passed:heldNativeReport.passed,browser:heldNativeReport.browser,modes:heldNativeReport.modes.map(mode=>({mode:mode.mode,scenarios:mode.scenarios.length,layouts:mode.layouts.length,checks:mode.checks})),failures:heldNativeReport.failures.map(failure=>failure.message),evidenceDirectory:heldNativeOutput},null,2));}
