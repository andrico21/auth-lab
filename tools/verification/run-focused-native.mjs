#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/run-focused-native.mjs [project-directory]\nBuild first. Requires Playwright/PLAYWRIGHT_MODULE and installed Chromium/CHROMIUM_EXECUTABLE. Serves its own ephemeral loopback HTTP origin and checks source HTTP, standalone HTTP/file focus, nested F2 help and milestone announcements. Evidence: AUTH_LAB_HELD_EVIDENCE_DIR or docs/verification/held-objects.');process.exit(0);}
const root=path.resolve(process.argv[2]||path.join(path.dirname(fileURLToPath(import.meta.url)),'../..')),out=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(root,'docs/verification/held-objects'));
fs.mkdirSync(out,{recursive:true});
const require=createRequire(import.meta.url),playwright=process.env.PLAYWRIGHT_MODULE?await import(pathToFileURL(path.resolve(process.env.PLAYWRIGHT_MODULE)).href):require('playwright');
const {chromium}=playwright;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const identity=()=>{const h=createHash('sha256');for(const name of ['index.html','build.mjs','package.json',...fs.readdirSync(path.join(root,'src')).filter(n=>/\.(js|css)$/.test(n)).sort().map(n=>'src/'+n)]){h.update(name+'\0');h.update(fs.readFileSync(path.join(root,name)));h.update('\0');}const html=fs.readFileSync(path.join(root,'dist/auth-flow-studio.html'));return {sourceSnapshotSha256:h.digest('hex'),standalone:{bytes:html.length,sha256:hash(html)}};};
const report={kind:'held-objects-focused-native-smoke',timestamp:new Date().toISOString(),nativeBrowser:true,passed:false,regenerationCommand:[process.execPath,...process.argv.slice(1)],identity:identity(),runnerSha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),modes:[],failures:[],notEstablished:['Real screen-reader speech and comprehension','Cross-engine and live-service interoperability']};
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage']});report.browser=browser.version();
const page=await browser.newPage({viewport:{width:1920,height:1200}});page.setDefaultTimeout(15000);
const settled=()=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
const bounded=async(label,fn)=>{let timer;try{return await Promise.race([fn(),new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error('Timed out: '+label)),30000))]);}finally{clearTimeout(timer);}};
let server;
try{
 server=http.createServer((request,response)=>{const pathname=decodeURIComponent(new URL(request.url,'http://localhost').pathname),file=path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){response.writeHead(404);response.end();return;}response.writeHead(200,{'Content-Type':{'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'}[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(response);});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 for(const mode of ['source-http','standalone-http','standalone-file']){
  const url=mode==='standalone-file'?pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href:origin+'/'+(mode==='source-http'?'':'dist/auth-flow-studio.html');
  await page.goto(url,{waitUntil:'networkidle'});await page.setViewportSize({width:1920,height:1200});await settled();
  const record={mode,responsiveFocus:[]};report.modes.push(record);
  record.stickyFocus=[];
  for(const width of [1920,1480,1050,390]){
   await page.setViewportSize({width,height:900});
   await bounded(mode+' sticky focus fixture',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-ad-cache-tgt');a.selectStep(a.steps.length-1,false);}));
   await settled();
   for(const kind of ['actor','inventory']){
    const found=await bounded(mode+' sticky '+kind+' focus',()=>page.evaluate(kind=>{
     const a=document.querySelector('auth-flow-studio');
     const candidates=[...a.querySelectorAll(kind==='actor'?'#actors [data-actor]':'#held-docks button')].filter(n=>n.getBoundingClientRect().width);
     candidates.sort((l,r)=>l.getBoundingClientRect().top-r.getBoundingClientRect().top||l.getBoundingClientRect().left-r.getBoundingClientRect().left);
     const target=candidates[0];if(!target)return false;
     window.__stickyFocus={target,snapshot:JSON.stringify(a.heldView.snapshot())};target.blur();
     window.scrollTo(0,scrollY+target.getBoundingClientRect().top-60);target.focus();return true;
    },kind));
    if(!found){assert.equal(kind,'inventory');assert.equal(await page.locator('#graph').getAttribute('data-held-geometry'),'external');continue;}
    // Participant help is a separate keyboard surface; dismiss it before hit-testing its anchor.
    if(kind==='actor')await page.keyboard.press('Escape');await settled();
    const result=await bounded(mode+' sticky '+kind+' visibility',()=>page.evaluate(kind=>{
     const a=document.querySelector('auth-flow-studio'),{target,snapshot}=window.__stickyFocus,controls=a.querySelector('#map-controls');
     const rect=target.getBoundingClientRect(),bar=controls.getBoundingClientRect(),hit=document.elementFromPoint(rect.x+rect.width/2,rect.y+rect.height/2);
     return {kind,geometry:a.refs.graph.dataset.heldGeometry,focused:document.activeElement===target,centerHitTarget:!!hit&&(hit===target||target.contains(hit)),unobscured:rect.top>=bar.bottom+4,toolbarHeight:bar.height,toolbarBottom:bar.bottom,targetTop:rect.top,canonicalSnapshotPreserved:snapshot===JSON.stringify(a.heldView.snapshot())};
    },kind));
    assert.ok(result.focused&&result.centerHitTarget&&result.unobscured&&result.canonicalSnapshotPreserved,JSON.stringify({mode,width,...result}));
    record.stickyFocus.push({width,...result});
    if(width===1920&&kind==='inventory'){const image=mode+'-sticky-toolbar-focus.png';await page.screenshot({path:path.join(out,image),fullPage:false});record.stickyFocusScreenshot=image;}
   }
  }
  await page.setViewportSize({width:1920,height:1200});await settled();
  const first=await bounded(mode+' choose R0',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-refresh-rotation');const h=a.heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R0');a.heldView.select(h);return {holdingId:h.holdingId,snapshot:a.heldView.snapshot()};}));
  await settled();await page.locator('[data-holding-id='+JSON.stringify(first.holdingId)+']:visible').first().focus();
  for(const width of [1480,1050,390,1920]){
   await page.setViewportSize({width,height:1200});await settled();
   const result=await bounded(mode+' resized focus',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {holdingId:document.activeElement?.dataset.holdingId,geometry:a.refs.graph.dataset.heldGeometry,snapshot:a.heldView.snapshot()};}));
   assert.equal(result.holdingId,first.holdingId);assert.deepEqual(result.snapshot,first.snapshot);
   record.responsiveFocus.push({width,geometry:result.geometry,exactHoldingPreserved:true,canonicalSnapshotPreserved:true});
  }
  const internal=await bounded(mode+' internal owner',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-ad-forest-child-domains');a.showInternals=true;a.renderAll();a.selectStep(a.steps.length-1,false);const snapshot=a.heldView.snapshot(),owner=Object.keys(a.scenarioOwnedActors).find(id=>a.scenarioOwnedActors[id].parentId&&snapshot.holdings.some(h=>h.actorId===id)),h=snapshot.holdings.find(h=>h.actorId===owner);a.heldView.select(h);return {owner,holdingId:h.holdingId,snapshot};}));
  await settled();await page.locator('[data-holding-id='+JSON.stringify(internal.holdingId)+']:visible').first().focus();
  const collapsed=await bounded(mode+' collapse owner',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),toggle=a.querySelector('#show-internals');toggle.checked=false;toggle.dispatchEvent(new Event('change',{bubbles:true}));return {focus:document.activeElement.id,snapshot:a.heldView.snapshot()};}));
  assert.equal(collapsed.focus,'show-internals');assert.deepEqual(collapsed.snapshot,internal.snapshot);record.collapse={logicalOwner:internal.owner,recovery:collapsed.focus,canonicalSnapshotPreserved:true};
  await page.setViewportSize({width:1600,height:1050});await bounded(mode+' SSH help fixture',()=>page.evaluate(()=>document.querySelector('auth-flow-studio').selectLabScenario('lab-ssh-cert-success')));await settled();
  await page.locator('#actors [data-actor="user"]').focus();await page.keyboard.press('F2');await page.locator('#actor-popup [data-attribute]').first().focus();await page.keyboard.press('F2');
  const popup=await bounded(mode+' focused help bounds',()=>page.locator('#attribute-popup').evaluate(n=>{const r=n.getBoundingClientRect();return {hidden:n.hidden,focused:n.contains(document.activeElement),left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight};}));
  assert.equal(popup.hidden,false);assert.equal(popup.focused,true);assert.ok(popup.left>=0&&popup.right<=popup.width&&popup.top>=0&&popup.bottom<=popup.height);record.nestedF2Help=popup;
  const image=mode+'-focused-nested-F2-help.png';await page.screenshot({path:path.join(out,image),fullPage:false});record.helpScreenshot=image;
  await page.keyboard.press('Escape');await page.keyboard.press('Escape');assert.equal(await page.evaluate(()=>document.activeElement.dataset.actor),'user');
  await page.setViewportSize({width:1920,height:1200});await bounded(mode+' cadence fixture',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-refresh-rotation');const step=a.steps.find(s=>s.id.endsWith('-response'));a.player.seek([step],.2,'step');a.player.setSpeed(4);window.__cadence={frames:0,updates:[],initial:a.querySelector('#held-announcement').textContent};window.__cadenceObserver=new MutationObserver(()=>window.__cadence.updates.push(a.querySelector('#held-announcement').textContent));window.__cadenceObserver.observe(a.querySelector('#held-announcement'),{childList:true,characterData:true,subtree:true});const frame=()=>{window.__cadence.frames++;if(a.player.status!=='complete')requestAnimationFrame(frame);};a.player.play([step],'step');requestAnimationFrame(frame);}));
  await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete');await settled();
  record.announcementCadence=await bounded(mode+' cadence evidence',()=>page.evaluate(()=>{window.__cadenceObserver.disconnect();return {...window.__cadence,cursor:document.querySelector('auth-flow-studio').heldView.snapshot().cursor};}));
  assert.equal(record.announcementCadence.updates.length,1);assert.ok(record.announcementCadence.frames>=2);
  console.log(JSON.stringify(record));
 }
 assert.deepEqual(identity(),report.identity);report.passed=true;
}catch(error){report.failures.push({message:error.message,stack:error.stack});process.exitCode=1;}
finally{await browser.close();if(server)await new Promise(resolve=>server.close(resolve));fs.writeFileSync(path.join(out,'held-objects-focused-native-status.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,modes:report.modes.length,failures:report.failures.map(f=>f.message),identity:report.identity},null,2));}
