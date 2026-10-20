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
async function heldNativeChoose(page,id,expanded=false,final=false){
  const selected=await page.evaluate(({id,expanded,final})=>{
    const a=document.querySelector('auth-flow-studio');a.selectLabScenario(id);
    if(a.showInternals!==expanded){a.showInternals=expanded;a.renderAll();}
    if(final)a.selectStep(a.steps.length-1,false);
    const message=a.querySelector('#held-active-message');
    return {id:a.labScenarioId,packetHidden:a.refs.packet.hidden,messageHidden:message.hidden,message:message.textContent,messagePhase:message.dataset.messagePhase||null};
  },{id,expanded,final});
  assert.equal(selected.id,id,'Native acceptance fixture must select its exact registered scenario.');
  assert.equal(selected.packetHidden,true,id+' inactive selection hides previous packet');
  assert.equal(selected.messageHidden,true,id+' inactive selection hides previous active message');
  assert.equal(selected.message,'',id+' inactive selection clears previous message content');
  assert.equal(selected.messagePhase,null,id+' inactive selection clears previous message phase');
}
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
async function heldNativeScreenshot(page,name,{selector=page.viewportSize().width<960?'.map-scroll':'#graph',requireFull=false}={}){
  const file=name+'.png',surface=page.locator(selector);
  await surface.evaluate(element=>element.scrollIntoView({block:'center',inline:'nearest'}));
  await page.evaluate(selector=>{
    const r=document.querySelector(selector).getBoundingClientRect(),toolbar=document.querySelector('#map-controls')?.getBoundingClientRect(),clearance=Math.max(0,toolbar?.bottom||0)+12;
    if(r.top<clearance)window.scrollBy(0,r.top-clearance);
  },selector);
  const camera=await page.evaluate(selector=>{
    const box=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};},surface=document.querySelector(selector),bounds=box(surface),toolbarElement=document.querySelector('#map-controls'),toolbar=toolbarElement?box(toolbarElement):null;
    const visibleBounds={left:Math.max(0,bounds.left),right:Math.min(innerWidth,bounds.right),top:Math.max(0,bounds.top),bottom:Math.min(innerHeight,bounds.bottom)};
    const displayed=[...surface.querySelectorAll('.actor-card,#held-docks button')].filter(e=>e.getClientRects().length&&!e.closest('[hidden]')).map(e=>{
      const r=box(e),x=(r.left+r.right)/2,y=(r.top+r.bottom)/2,displayed=x>=visibleBounds.left&&x<=visibleBounds.right&&y>=visibleBounds.top&&y<=visibleBounds.bottom,hit=displayed?document.elementFromPoint(x,y):null;
      return {kind:e.matches('.actor-card')?'actor':'inventory',actorId:e.dataset.actor||e.dataset.heldActor||null,action:e.dataset.heldAction||null,bounds:r,center:{x,y},displayed,centerExposed:!!hit&&(hit===e||e.contains(hit)),occluder:hit&&hit!==e&&!e.contains(hit)?{tag:hit.tagName,id:hit.id,classes:hit.getAttribute('class')}:null,toolbarOverlap:!!toolbar&&r.left<toolbar.right&&r.right>toolbar.left&&r.top<toolbar.bottom&&r.bottom>toolbar.top};
    });
    const actorTops=displayed.filter(e=>e.kind==='actor'),top=Math.min(...actorTops.map(e=>e.center.y));
    return {selector,viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio},scroll:{x:scrollX,y:scrollY},surfaceBounds:bounds,visibleBounds,toolbar,fullSurfaceVisible:bounds.left>=0&&bounds.top>=0&&bounds.right<=innerWidth&&bounds.bottom<=innerHeight,displayedTargets:displayed,topActorCenters:actorTops.filter(e=>Math.abs(e.center.y-top)<2).map(e=>({actorId:e.actorId,...e.center,displayed:e.displayed,centerExposed:e.centerExposed}))};
  },selector);
  camera.captureBounds={left:0,top:0,right:camera.viewport.width,bottom:camera.viewport.height};
  await page.screenshot({path:path.join(heldNativeOutput,file),fullPage:false});
  heldNativeReport.screenshots.push(file);(heldNativeReport.cameras??=[]).push({screenshot:file,...camera});
  heldNativeCheck(camera.visibleBounds.right>camera.visibleBounds.left&&camera.visibleBounds.bottom>camera.visibleBounds.top,name+' camera has a visible surface');
  heldNativeCheck(camera.displayedTargets.filter(t=>t.displayed).every(t=>!t.toolbarOverlap&&t.centerExposed),name+' displayed actor and inventory target centers are not occluded');
  if(requireFull){heldNativeCheck(camera.fullSurfaceVisible,name+' complete graph fits actual viewport');heldNativeCheck(camera.topActorCenters.length>0&&camera.topActorCenters.every(t=>t.displayed&&t.centerExposed),name+' complete top actor row is exposed');}
  return {file,camera};
}
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
// These are active full-journey seeks, not final-state composition screenshots.
async function heldNativeLocalProcessing(page,mode){
  const records=[],fixtures=[
    {id:'basic-keycloak',suffix:'-l02',actor:'app',kind:'pkce'},
    {id:'lab-ad-first-sign-in',suffix:'-select-key',actor:'adWorkstation',kind:'ad-key'},
    {id:'lab-ad-fast-as-success',suffix:'-computer-armor',actor:'cryptoComputer',kind:'fast-armor'},
    {id:'lab-ssh-cert-success',suffix:'-prepare',actor:'sshCli',kind:'ssh-cli'},
    {id:'lab-ssh-cert-success',suffix:'-sign',actor:'sshAgent',kind:'ssh-agent'},
    {id:'lab-ssh-cert-success',suffix:'-agent-request',actor:'sshCli',kind:'ssh-agent-ipc',exchange:true}
  ];
  for(const fixture of fixtures){
    await page.setViewportSize({width:1920,height:1200});await heldNativeChoose(page,fixture.id);
    const internalsEligible=await page.evaluate(()=>Object.values(document.querySelector('auth-flow-studio').scenarioOwnedActors||{}).some(actor=>actor.parentId));
    const canonical=new Map();
    for(const expanded of internalsEligible?[false,true]:[false])for(const width of [1920,1480,390]){
      await page.setViewportSize({width,height:1200});
      const prepared=await page.evaluate(({fixture,expanded})=>{
        const a=document.querySelector('auth-flow-studio');
        if(a.showInternals!==expanded){a.showInternals=expanded;a.renderAll();}
        const step=a.steps.find(s=>s.id.endsWith(fixture.suffix)&&s.from===fixture.actor);
        if(!step)throw new Error('Missing exact local-processing fixture '+fixture.id+fixture.suffix);
        const clock=a.studyClock(),index=clock.steps.findIndex(s=>s.id===step.id),duration=clock.durations[index],count=Math.max(1,step.payload.length);
        if(index<0)throw new Error('The local-processing fixture must be in the full journey');
        // Match the existing field cadence, including authored transport compression.
        const timing=a.player.getTiming?.(step,'demo'),message=timing?.messages?.[0];
        const start=message?(message.start-timing.start)/(timing.end-timing.start):0,end=message?(message.end-timing.start)/(timing.end-timing.start):1;
        const scale=message?Math.min(1,(end-start)*duration/(380+(count-1)*1290+1050)):1;
        const samples=Array.from({length:count},(_,packetIndex)=>[.2,.8].map(travel=>({packetIndex,travel,fraction:(clock.offsets[index]+start*duration+(380+packetIndex*1290+1050*travel)*scale)/clock.total}))).flat();
        const from=a.nodeId(step.from),to=a.nodeId(step.to);
        const markerDefinitions=[...a.refs.connections.querySelectorAll('marker')].map(marker=>{const view=marker.viewBox.baseVal;return {id:marker.id,units:marker.getAttribute('markerUnits'),width:marker.markerWidth.baseVal.value,height:marker.markerHeight.baseVal.value,refX:marker.refX.baseVal.value,viewBox:[view.x,view.y,view.width,view.height]};});
        return {stepId:step.id,title:step.title,from:step.from,to:step.to,drawnFrom:from,drawnTo:to,presentation:step.from===step.to?'local':from===to?'folded':'transfer',sourcePayloadCount:step.payload.length,payloadScope:step.payload.length?'Authored payload fields':'Existing Local action/title fallback; no invented payload fields',markerDefinitions,samples};
      },{fixture,expanded});
      assert.equal(prepared.from===prepared.to,!fixture.exchange,mode+' fixture uses original logical endpoints');
      if(fixture.exchange)assert.equal(prepared.presentation,expanded?'transfer':'folded',mode+' agent IPC is not local computation when folded');
      const samples=[];
      for(const target of prepared.samples){
        const observed=await page.evaluate(({fraction,stepId})=>{
          const a=document.querySelector('auth-flow-studio');a.seekPlayback(fraction);
          const event=a.player.snapshot(),step=event.step,packet=event.packet||{name:'Local action',value:step.title},format=value=>value===undefined?'':value!==null&&typeof value==='object'?JSON.stringify(value):String(value);
          if(step.id!==stepId)throw new Error('Seek did not land on the exact local-processing step');
          const group=a.refs.connections.querySelector('.connection-group.is-active'),line=group.querySelector('.connection-line');
          const canonicalBefore=JSON.stringify({protocol:a.protocolSnapshot(),held:a.heldView.snapshot()});
          group.querySelector('.connection-hit').focus({preventScroll:true});
          a.updateStep();a.renderPacket(event);
          const fields=[...a.refs['step-attributes'].querySelectorAll('[data-step-attribute]')].filter(field=>field.getClientRects().length),current=event.visible?(packet.attributeId||a.payloadAttributeId(packet,step)):null,style=getComputedStyle(line),orb=a.refs.packet.querySelector('.packet-orb'),orbStyle=getComputedStyle(orb);
          const point=line.getPointAtLength(line.getTotalLength()*.5),svg=a.refs.connections.viewBox.baseVal;
          const expectedValue=format(packet.value),badges=[...a.refs.actors.querySelectorAll('.actor-trace-action')].filter(e=>!e.hidden).map(e=>e.textContent);
          return {stepId:step.id,geometry:a.refs.graph.dataset.heldGeometry,presentation:group.dataset.presentation,packetPresentation:a.refs.packet.dataset.presentation,visible:event.visible,packetHidden:a.refs.packet.hidden,packetIndex:event.packetIndex,progress:event.progress,phase:event.messagePhase,name:a.refs['packet-name'].textContent,value:a.refs['packet-value'].textContent,count:a.refs['packet-count'].textContent,expectedName:packet.name,expectedValue:expectedValue.slice(0,38)+(expectedValue.length>38?'…':''),fullValue:expectedValue,expectedCount:(event.packetIndex+1)+'/'+Math.max(1,step.payload.length),fieldNames:fields.map(e=>e.textContent),expectedFieldNames:a.stepAttributeItems(step).map(item=>item.name),highlights:fields.filter(e=>e.classList.contains('is-current')).map(e=>e.dataset.stepAttribute),expectedHighlights:fields.filter(e=>!!current&&e.dataset.stepAttribute.split(' ').includes(current)).map(e=>e.dataset.stepAttribute),badges,markerEnd:line.getAttribute('marker-end'),animation:style.animationName,dasharray:style.strokeDasharray,filter:style.filter,orbShadow:orbStyle.boxShadow,orbAnimation:orbStyle.animationName,orbPlayState:orbStyle.animationPlayState,position:{left:a.refs.packet.style.left,top:a.refs.packet.style.top},midpoint:{left:point.x/svg.width*100,top:point.y/svg.height*100},status:event.status,kind:event.kind,playLabel:a.refs.play.textContent.trim(),seekEnabled:!a.refs.seek.disabled,seekValue:Number(a.refs.seek.value),expectedSeekValue:Math.round(fraction*1000),seekText:a.refs.seek.getAttribute('aria-valuetext'),canonicalBefore,canonicalAfter:JSON.stringify({protocol:a.protocolSnapshot(),held:a.heldView.snapshot()}),activeMessage:{visible:!a.querySelector('#held-active-message').hidden,text:a.querySelector('#held-active-message').textContent}};
        },{fraction:target.fraction,stepId:prepared.stepId});
        const label=mode+' '+fixture.kind+' '+expanded+' '+width+' field '+target.packetIndex+' @'+target.travel;
        assert.equal(observed.visible,true,label+' observes an actual visible field time');assert.equal(observed.packetHidden,false,label+' field marker is rendered');
        assert.equal(observed.packetIndex,target.packetIndex,label+' preserves legacy field cadence');assert.equal(observed.presentation,prepared.presentation,label+' logical route presentation');assert.equal(observed.packetPresentation,prepared.presentation,label+' packet presentation');
        assert.ok(Math.abs(observed.progress-target.travel)<.0001,label+' temporal field progress remains unchanged despite fixed local position');
        assert.equal(observed.name,observed.expectedName,label+' exact field label');assert.equal(observed.value,observed.expectedValue,label+' exact compact field value');assert.equal(observed.count,observed.expectedCount,label+' field count');
        assert.deepEqual(observed.fieldNames,observed.expectedFieldNames,label+' complete local field set');assert.deepEqual(observed.highlights,observed.expectedHighlights,label+' current field highlight follows the real packet');
        assert.equal(observed.status,'paused',label+' seeking remains paused');assert.equal(observed.kind,'demo',label+' normal full-journey playback');assert.equal(observed.playLabel,'Resume',label+' control remains resumable');assert.equal(observed.seekEnabled,true,label+' seek remains enabled');assert.equal(observed.seekValue,observed.expectedSeekValue,label+' seek control matches the selected time');assert.ok(observed.seekText.includes(prepared.title),label+' seek announces its exact source step');
        assert.equal(observed.canonicalAfter,observed.canonicalBefore,label+' presentation/focus redraw preserves the complete canonical snapshot');
        const key=target.packetIndex+':'+target.travel;
        if(canonical.has(key))assert.equal(observed.canonicalAfter,canonical.get(key),label+' width/internal folding preserves the exact canonical snapshot');else canonical.set(key,observed.canonicalAfter);
        if(!fixture.exchange){
          assert.equal(observed.markerEnd,null,label+' local route has no directional arrow');assert.equal(observed.animation,'none',label+' no travelling line animation');assert.equal(observed.dasharray,'none',label+' no directional dashes');assert.equal(observed.filter,'none',label+' no route glow');
          assert.equal(observed.orbShadow,'none',label+' local field pulse has no unbounded glow');assert.equal(observed.orbPlayState,'paused',label+' paused local pulse does not run');assert.ok(observed.badges.includes('Local processing'),label+' local processing is labelled in normal playback');
          assert.equal(observed.orbAnimation,'local-field-pulse',label+' local marker uses an opacity pulse, not travel');
          if(fixture.kind==='pkce')assert.ok(observed.highlights.length>0,label+' each visible PKCE field has its actual attribute highlight');
          assert.ok(Math.abs(parseFloat(observed.position.left)-observed.midpoint.left)<.001&&Math.abs(parseFloat(observed.position.top)-observed.midpoint.top)<.001,label+' field marker stays at the route midpoint');
          if(samples.length)assert.deepEqual(observed.position,samples[0].position,label+' local coordinates remain stable through meaningful time and field changes');
        }else{
          assert.ok(observed.markerEnd?.startsWith('url('),label+' actual IPC retains direction');assert.equal(observed.animation,'link-flow',label+' actual IPC retains travelling flow');
          if(!expanded)assert.ok(observed.badges.includes('Internal exchange'),label+' folded IPC is explicitly distinguished from local computation');
          if(samples.length&&samples.at(-1).packetIndex===observed.packetIndex)assert.notDeepEqual(observed.position,samples.at(-1).position,label+' actual IPC marker moves even on one drawn actor');
        }
        if(!fixture.exchange)assert.equal(observed.activeMessage.visible,true,label+' full local field value has a rendered readable panel');
        if(observed.activeMessage.visible)assert.ok(observed.activeMessage.text.includes(observed.fullValue),label+' visible message preserves the untruncated field value');
        const paint=await heldNativePaintedRoute(page,{local:!fixture.exchange});
        assert.deepEqual(paint.collisions,[],label+' painted route, focus halo, marker glyph and local field marker clear actor/dock/focus frames');
        for(const marker of paint.markers){assert.ok(marker.paintedSpanWorld<=10.1,label+' arrow paint fits the ten-unit route clearance');assert.ok(marker.tipOvershootCss<=.5,label+' arrow paint stops at its attachment port');}
        const canonicalHash=heldNativeHash(observed.canonicalAfter);delete observed.canonicalBefore;delete observed.canonicalAfter;
        samples.push({...target,...observed,canonicalHash,paint});
      }
      let pulse=null;
      if(!fixture.exchange){
        pulse=await page.evaluate(()=>{
          const a=document.querySelector('auth-flow-studio'),before=JSON.stringify({protocol:a.protocolSnapshot(),held:a.heldView.snapshot()}),orb=a.refs.packet.querySelector('.packet-orb');
          // Native click dispatch exercises the normal control without letting
          // a frame advance the authored clock between the two control states.
          a.refs.play.click();
          const playing={status:a.player.status,label:a.refs.play.textContent.trim(),packetStatus:a.refs.packet.dataset.playback,pulse:getComputedStyle(orb).animationPlayState,line:getComputedStyle(a.refs.connections.querySelector('.is-active .connection-line')).animationName};
          a.refs.play.click();
          return {playing,paused:{status:a.player.status,label:a.refs.play.textContent.trim(),packetStatus:a.refs.packet.dataset.playback,pulse:getComputedStyle(orb).animationPlayState},canonicalPreserved:before===JSON.stringify({protocol:a.protocolSnapshot(),held:a.heldView.snapshot()})};
        });
        assert.deepEqual(pulse.playing,{status:'playing',label:'Pause',packetStatus:'playing',pulse:'running',line:'none'},mode+' local play resumes only the bounded pulse');
        assert.deepEqual(pulse.paused,{status:'paused',label:'Resume',packetStatus:'paused',pulse:'paused'},mode+' local pause freezes the pulse');
        assert.equal(pulse.canonicalPreserved,true,mode+' local controls preserve canonical state without a clock tick');
      }
      // Capture the active PKCE request and every local family at a real visible
      // field, with the graph scrolled into the viewport and its route exposed.
      const name=mode+'-active-'+fixture.kind+'-'+(expanded?'expanded':'collapsed')+'-'+width;
      // Resizing can place a participant beneath the preceding UI click. Close
      // that incidental hover help without moving the focused SVG route.
      await page.mouse.move(0,0);
      await page.keyboard.press('Escape');
      await page.locator('#packet').evaluate(element=>element.scrollIntoView({block:'center',inline:'center'}));
      const capture=await heldNativeScreenshot(page,name,{selector:width<960?'.map-scroll':'#graph',requireFull:width===1920});
      assert.equal(await page.locator('#actor-popup').isHidden(),true,name+' active-scene camera is not covered by incidental participant help');
      const exposed=await page.evaluate(()=>{
        const a=document.querySelector('auth-flow-studio'),chip=a.refs.packet.querySelector('.packet-chip'),r=chip.getBoundingClientRect(),x=(r.left+r.right)/2,y=(r.top+r.bottom)/2;
        const toolbar=a.querySelector('#map-controls').getBoundingClientRect(),route=a.refs.connections.querySelector('.connection-group.is-active .connection-line').getBoundingClientRect(),inside=b=>b.left>=0&&b.right<=innerWidth&&b.top>=0&&b.bottom<=innerHeight,overlap=b=>b.left<toolbar.right&&b.right>toolbar.left&&b.top<toolbar.bottom&&b.bottom>toolbar.top;
        return {visible:!a.refs.packet.hidden,insideViewport:inside(r),toolbarOverlap:overlap(r),routeInsideViewport:inside(route),routeToolbarOverlap:overlap(route),routeBounds:{left:route.left,right:route.right,top:route.top,bottom:route.bottom},center:{x,y},stepId:a.player.snapshot().step.id};
      });
      assert.equal(exposed.stepId,prepared.stepId,name+' captures the exact active step');assert.equal(exposed.visible,true,name+' captures an active field, not a final state');assert.equal(exposed.insideViewport,true,name+' local glyph is inside the viewport');assert.equal(exposed.toolbarOverlap,false,name+' local glyph is unobscured by controls');
      if(!fixture.exchange){assert.equal(exposed.routeInsideViewport,true,name+' complete local U route is inside the viewport');assert.equal(exposed.routeToolbarOverlap,false,name+' complete local U route clears the controls');}
      records.push({id:fixture.id,kind:fixture.kind,expanded,width,...prepared,samples,pulse,screenshot:capture.file,camera:capture.camera,capturedField:exposed});
    }
  }
  for(const geometry of ['full','compact','external'])assert.ok(records.some(r=>r.samples.some(s=>s.geometry===geometry)),mode+' active local probes exercise '+geometry+' where eligible');
  return {scope:'Actual visible full-journey local/IPC fields, exact canonical snapshots and painted SVG/field extents; composition-only screenshots are not local-playback evidence',records};
}
async function heldNativePaintedRoute(page,{local}){
  return page.evaluate(local=>{
    const a=document.querySelector('auth-flow-studio'),group=a.refs.connections.querySelector('.connection-group.is-active'),line=group.querySelector('.connection-line'),matrix=line.getScreenCTM(),length=line.getTotalLength(),step=a.player.snapshot().step,endpoints=new Set([a.nodeId(step.from),a.nodeId(step.to)]);
    const visible=e=>!!e.getClientRects().length&&!e.closest('[hidden]')&&getComputedStyle(e).visibility!=='hidden',rect=e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom};},expand=(r,n)=>({left:r.left-n,right:r.right+n,top:r.top-n,bottom:r.bottom+n}),intersects=(a,b)=>a.left<b.right-.25&&a.right>b.left+.25&&a.top<b.bottom-.25&&a.bottom>b.top+.25;
    const scale=Math.max(Math.hypot(matrix.a,matrix.b),Math.hypot(matrix.c,matrix.d)),obstacles=[];
    for(const e of a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary,.trust-zone')){
      if(!visible(e))continue;
      const owner=e.dataset.actor||e.dataset.heldDock||e.dataset.heldActor||e.dataset.zoneActor||null,own=endpoints.has(owner),frame=e.classList.contains('trust-zone');
      // Endpoint ports may touch their own frame; other route paint may not.
      if(own&&!local)continue;
      const focus=e.matches('.actor-card.is-source,.actor-card.is-target,.actor-card:focus-visible'),bounds=expand(rect(e),focus?7:0);
      obstacles.push({owner,kind:frame?'trust-frame':focus?'actor-focus':e.className,bounds,own,frame});
    }
    const collisions=[],envelopes=[],markers=[];
    const collide=(paint,kind,at)=>{
      for(const obstacle of obstacles){
        if(obstacle.own&&at!==null&&(at<16*scale||length*scale-at<16*scale))continue;
        const r=obstacle.bounds,bands=obstacle.frame?[{...r,bottom:r.top+1},{...r,top:r.bottom-1},{...r,right:r.left+1},{...r,left:r.right-1}]:[r];
        if(bands.some(b=>intersects(paint,b)))collisions.push({paint:kind,obstacle:obstacle.owner||obstacle.kind,kind:obstacle.kind,at});
      }
    };
    for(const path of [line,group.querySelector('.edge-focus')]){
      const style=getComputedStyle(path);if(Number(style.opacity)===0||style.stroke==='none')continue;
      // The actual visible focus stroke is wider than its centerline. A CSS
      // drop-shadow is conservatively bounded at three blur radii.
      const shadowPixels=[...style.filter.matchAll(/(-?[\d.]+)px/g)].map(match=>Number(match[1])),shadowRadius=shadowPixels.length>=3?Math.hypot(shadowPixels.at(-3),shadowPixels.at(-2))+Math.abs(shadowPixels.at(-1))*3:0,radius=Number.parseFloat(style.strokeWidth)*scale/2+shadowRadius;
      envelopes.push({kind:path.classList.contains('edge-focus')?'focus-stroke':'route-stroke',stroke:style.stroke,width:Number.parseFloat(style.strokeWidth),radius,filter:style.filter});
      for(let n=0;n<=length;n+=.75){const p=path.getPointAtLength(n),s=new DOMPoint(p.x,p.y).matrixTransform(matrix);collide({left:s.x-radius,right:s.x+radius,top:s.y-radius,bottom:s.y+radius},envelopes.at(-1).kind,n*scale);}
    }
    const markerRef=line.getAttribute('marker-end');
    if(markerRef){
      const marker=a.querySelector(markerRef.slice(markerRef.indexOf('#'),markerRef.lastIndexOf(')'))),view=marker.viewBox.baseVal,tip=line.getPointAtLength(length),prior=line.getPointAtLength(Math.max(0,length-.1)),angle=Math.atan2(tip.y-prior.y,tip.x-prior.x),unitsScale=marker.getAttribute('markerUnits')==='userSpaceOnUse'?1:Number.parseFloat(getComputedStyle(line).strokeWidth),sx=marker.markerWidth.baseVal.value/view.width*unitsScale,sy=marker.markerHeight.baseVal.value/view.height*unitsScale,points=[];let forwardPaint=-Infinity;
      for(const glyph of marker.querySelectorAll('path,polygon,polyline,circle,rect')){
        const total=glyph.getTotalLength();
        for(let n=0;n<=total;n+=.2){const p=glyph.getPointAtLength(n),x=(p.x-marker.refX.baseVal.value)*sx,y=(p.y-marker.refY.baseVal.value)*sy;forwardPaint=Math.max(forwardPaint,x);points.push(new DOMPoint(tip.x+x*Math.cos(angle)-y*Math.sin(angle),tip.y+x*Math.sin(angle)+y*Math.cos(angle)).matrixTransform(matrix));}
      }
      const bounds={left:Math.min(...points.map(p=>p.x)),right:Math.max(...points.map(p=>p.x)),top:Math.min(...points.map(p=>p.y)),bottom:Math.max(...points.map(p=>p.y))};
      markers.push({units:marker.getAttribute('markerUnits'),width:marker.markerWidth.baseVal.value,height:marker.markerHeight.baseVal.value,refX:marker.refX.baseVal.value,viewBox:[view.x,view.y,view.width,view.height],paintedBounds:bounds,paintedSpanWorld:Math.max(bounds.right-bounds.left,bounds.bottom-bounds.top)/scale,tipOvershootCss:Math.max(0,forwardPaint*scale)});
      collide(bounds,'direction-marker',length*scale);
    }
    if(local){
      const chip=a.refs.packet.querySelector('.packet-chip'),orb=a.refs.packet.querySelector('.packet-orb');
      if(getComputedStyle(chip).boxShadow!=='none')throw new Error('A local field chip must not cast a glow beyond its bounded glyph');
      for(const [element,kind]of [[chip,'local-field-chip'],[orb,'local-field-orb']]){const bounds=rect(element);envelopes.push({kind,bounds,shadow:getComputedStyle(element).boxShadow});collide(bounds,kind,null);}
    }
    return {pair:group.dataset.pair,local,obstacles:obstacles.map(({owner,kind,bounds})=>({owner,kind,bounds})),envelopes,markers,collisions:[...new Map(collisions.map(c=>[c.paint+':'+c.obstacle+':'+c.kind,c])).values()]};
  },local);
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
  return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),e=document.activeElement;return {action:e?.dataset.heldAction||null,holdingId:e?.dataset.holdingId||null,actorId:e?.dataset.heldActor||e?.dataset.heldCollapse||null,region:e?.closest('#held-objects,#held-docks,#held-inspector')?.id||null,selected:a.heldView.selection?.holdingId||null,connected:!!e?.isConnected,visible:!!e&&e.getClientRects().length>0};});
}
async function heldNativeActionFocus(page,mode){
  const records=[],choices=await page.evaluate(()=>[...document.querySelector('auth-flow-studio').refs['lab-scenario'].options].map(o=>o.value));
  const redraw=async(action,region,label)=>{
    const before=await heldNativeFocusState(page);
    assert.equal(before.action,action,mode+' '+label+' starts on exact action');assert.equal(before.region,region,mode+' '+label+' starts in exact region');
    await page.evaluate(()=>{const v=document.querySelector('auth-flow-studio').heldView;v.lastKey='';v.render();});
    const after=await heldNativeFocusState(page);
    assert.equal(after.action,action,mode+' '+label+' redraw retains action');assert.equal(after.region,region,mode+' '+label+' redraw retains region');heldNativeCheck(after.connected&&after.visible,mode+' '+label+' redraw focus is live and visible');
    return {before,after};
  };
  for(const kind of ['dock-owner','dock-overflow','compact','picker']){
    let fixture;
    const ids=[...new Set(['lab-ad-first-sign-in','lab-refresh-rotation','lab-ssh-cert-success',...choices])];
    for(const width of kind==='compact'?[1600,1480,1280,1050]:[1920]){
      await page.setViewportSize({width,height:1200});
      for(const id of ids){
        await heldNativeChoose(page,id,false,true);
        const control=page.locator('[data-held-action^="'+kind+':"]:visible').first();
        if(await control.count()){fixture={id,width,action:await control.getAttribute('data-held-action'),actorId:await control.getAttribute('data-held-actor')};break;}
      }
      if(fixture)break;
    }
    heldNativeCheck(fixture,mode+' renders an actual '+kind+' trigger');
    const region=kind==='picker'?'held-objects':'held-docks',control=()=>page.locator('#'+region+' [data-held-action='+JSON.stringify(fixture.action)+']');
    await control().focus();const ordinary=await redraw(fixture.action,region,kind);
    const cycles=[];
    for(let cycle=0;cycle<3;cycle++){
      await control().click();
      if(kind==='picker'){
        cycles.push(await redraw(fixture.action,region,kind+' activated'));
      }else{
        // Opening an occupied owner may focus its complete-list holding. Escape returns to this exact dock action.
        const opened=await heldNativeFocusState(page);
        if(opened.region==='held-objects'){await page.keyboard.press('Escape');}
        else{await control().click();await page.keyboard.press('Escape');}
        cycles.push(await redraw(fixture.action,region,kind+' return'));
      }
    }
    let fallback=null;
    if(kind==='compact'){
      await control().focus();await page.setViewportSize({width:390,height:844});
      await page.waitForFunction(()=>document.querySelector('#graph').dataset.heldGeometry==='external');
      fallback=await heldNativeFocusState(page);assert.equal(fallback.action,'picker:'+fixture.actorId,mode+' removed compact action falls back to same logical owner picker');assert.equal(fallback.region,'held-objects',mode+' compact fallback uses complete list region');heldNativeCheck(fallback.connected&&fallback.visible,mode+' compact fallback is live and visible');
    }
    records.push({kind,...fixture,region,ordinary,cycles,fallback});
  }
  await page.setViewportSize({width:1920,height:1200});await heldNativeChoose(page,'lab-refresh-rotation',false,true);
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),h=a.heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R1');if(!h)throw new Error('Exit focus fixture needs exact R1');a.heldView.select(h);a.heldView.trace(h.artifactId);a.player.pause();});
  await page.locator('#held-inspector [data-held-action="exit"]').focus();
  records.push({kind:'exit',region:'held-inspector',ordinary:await redraw('exit','held-inspector','exit')});
  return {contract:'Stable data-held-action plus originating region across native redraws, three owner return cycles and removed compact-action fallback',records};
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
      const screenshot=mode+'-'+geometry+'-'+region+'-exact-focus.png';if(region==='held-docks')await heldNativeScreenshot(page,screenshot.slice(0,-4));else{await page.locator('#held-objects').screenshot({path:path.join(heldNativeOutput,screenshot)});heldNativeReport.screenshots.push(screenshot);}
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
    return {wireId:wire?.id,wireValue:wire?.payload.find(p=>p.attributeId==='idTokenA'||p.name==='id_token')?.value,decodedValue:artifact?.representations.find(r=>r.representationId==='view')?.fields.find(f=>f.attributeId==='idTokenA')?.value};
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
      if(kind==='wire'){assert.equal(sample.packetVisible,true,mode+' encrypted wire packet actually displayed');const prefix=sample.packetValue.replace(/…$/,'');assert.ok(prefix.length&&sample.expected.startsWith(prefix)&&!fixture.decodedValue.startsWith(prefix),mode+' wire packet displays ciphertext rather than the decoded value');assert.ok(sample.activeMessage.includes(sample.expected),mode+' active message contains full compact JWE');}
      const file=mode+'-jwe-'+representationId+'-'+kind+'-display.png';if(kind==='wire')await heldNativeScreenshot(page,file.slice(0,-4));else{await page.locator('#inspector').screenshot({path:path.join(heldNativeOutput,file)});heldNativeReport.screenshots.push(file);}samples.push(sample);
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
    const capture=await heldNativeScreenshot(page,mode+'-'+id+'-'+(expanded?'expanded':'collapsed')+'-composition',{selector:'#graph',requireFull:true});
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
      return {actors,labels,attachments,rowGaps,graphLeft:graph.left,graphTop:graph.top,graphHeight:graph.height,graphWidth:graph.width,occupied:{width:bounds.right-bounds.left,height:bounds.bottom-bounds.top},geometry:a.refs.graph.dataset.heldGeometry};
    });
    assert.equal(composition.geometry,'full',mode+' '+id+' '+(expanded?'expanded':'collapsed')+' fits full participant inventory geometry');
    if(id==='lab-ad-forest-child-domains'&&expanded)assert.equal(Object.keys(composition.actors).length,7,mode+' expanded forest retains seven physical actors without duplicate parent KDCs');
    if(id==='lab-ssh-cert-success'&&expanded){
      const collapsed=records.find(r=>r.id===id&&!r.expanded);
      heldNativeCheck(collapsed,mode+' SSH expanded comparison has collapsed reference');
      for(const [actorId,before]of Object.entries(collapsed.actors)){
        const after=composition.actors[actorId];heldNativeCheck(after,mode+' SSH expansion retains '+actorId);
        heldNativeCheck(Math.abs((before.x-collapsed.graphLeft)/collapsed.graphWidth-(after.x-composition.graphLeft)/composition.graphWidth)<.002&&Math.abs((before.y-collapsed.graphTop)/collapsed.graphHeight-(after.y-composition.graphTop)/composition.graphHeight)<.002,mode+' SSH expansion preserves shared '+actorId+' anchor rather than compressing vacant agent cell');
      }
    }
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
    delete scene.state;delete scene.holdings;records.push({id,expanded,screenshot:capture.file,camera:capture.camera,scene,...composition});
  }
  return {scope:'Final-state rendered Chromium composition and complete label bounds only; active local/IPC acceptance is recorded separately in localProcessing; not a human aesthetic review',records};
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
    record.code1={};
    record.code1.representations=await heldNativeRepresentations(page,mode);
    record.code1.boundaries=await heldNativeBoundaries(page,mode);
    record.code1.ownersAndFocus=await heldNativeOwnersAndFocus(page,mode);
    record.code1.actionFocus=await heldNativeActionFocus(page,mode);
    record.checks.push('HC01 rendered encrypted/decoded occurrence values from both selections','HC02 authored receipt boundaries across full/connection/exact replay, payload sizes and speeds','HC08 repeated owner return complete lists in full/compact','HC09 exact holding and non-holding action+region redraw focus, repeated merged/compact/overflow/picker return and separate resize/removal/collapse fallbacks');
    record.localProcessing=await heldNativeLocalProcessing(page,mode);record.checks.push('Actual PKCE, AD/FAST and SSH CLI/agent local fields across full/compact/external and internal folding; fixed local midpoint, no directional flow, exact field/control/canonical state, painted stroke/focus/glyph clearance, and folded SSH IPC motion/direction');
    // Start the catalog sweep from a fresh configuration, retaining host-side CSP evidence.
    await page.goto(target,{waitUntil:'networkidle'});await page.setViewportSize({width:1920,height:1200});
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
