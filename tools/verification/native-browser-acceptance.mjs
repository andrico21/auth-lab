#!/usr/bin/env node
/** Real-browser gate: never substitutes a DOM harness or downloads a browser.
 * node tools/verification/native-browser-acceptance.mjs [project-directory]
 * Optional PLAYWRIGHT_MODULE, CHROMIUM_EXECUTABLE, AUTH_LAB_QA_EVIDENCE_DIR.
 * Code1 correction evidence has separate names, preserving the original logs.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';

const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv.includes('--help')||process.argv.includes('-h')){
  console.log('Usage: node tools/verification/native-browser-acceptance.mjs [project-directory]\nDefaults to this repository. Requires installed Playwright and Chromium; no browser downloads.\nOptional PLAYWRIGHT_MODULE and CHROMIUM_EXECUTABLE absolute paths.\nEvidence: docs/verification/code1-correction-native-browser-status.json, or AUTH_LAB_QA_EVIDENCE_DIR.');
  process.exit(0);
}
const project=path.resolve(process.argv[2]||path.join(here,'../..'));
const evidenceDir=path.resolve(process.env.AUTH_LAB_QA_EVIDENCE_DIR||path.join(project,'docs/verification'));
fs.mkdirSync(evidenceDir,{recursive:true});
const digest=file=>{const bytes=fs.readFileSync(file);return {sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};};
const artifact={sourceEntry:digest(path.join(project,'index.html')),standalone:fs.existsSync(path.join(project,'dist/auth-flow-studio.html'))?digest(path.join(project,'dist/auth-flow-studio.html')):null};
const sourceSnapshot=()=>{const sourceFiles=fs.readdirSync(path.join(project,'src')).filter(name=>/\.(?:js|css)$/.test(name)).sort(),hash=createHash('sha256');for(const name of ['index.html','build.mjs','package.json',...sourceFiles.map(name=>'src/'+name)]){hash.update(name+'\0');hash.update(fs.readFileSync(path.join(project,name)));hash.update('\0');}return hash.digest('hex');};
artifact.sourceSnapshotSha256=sourceSnapshot();
const evidence={kind:'native-browser',review:'code1-correction/G01',verified:false,status:'blocked',timestamp:new Date().toISOString(),project,runnerSha256:digest(fileURLToPath(import.meta.url)).sha256,artifact,checks:[],scenarios:[],screenshots:[]};
const output=path.join(evidenceDir,'code1-correction-native-browser-status.json');
const save=()=>fs.writeFileSync(output,JSON.stringify(evidence,null,2)+'\n');
const check=(name,detail={})=>evidence.checks.push({name,...detail});
let browser,server;

// These families include the scenario-owned IDs missed by the original Basic-only
// F2 check. Forest children and AS/TGS nodes are tested in expanded form as well.
const studyCases=[
  {id:'lab-ssh-cert-success',family:'SSH certificate'},
  {id:'lab-ssh-device-cadence',family:'SSH Device'},
  {id:'lab-ssh-sssd-success',family:'SSH keyboard-interactive'},
  {id:'lab-ssh-gss-success',family:'SSH Kerberos GSS'},
  {id:'lab-ad-first-sign-in',family:'AD DS'},
  {id:'lab-kc-kerberos-fresh-totp',family:'Keycloak bridge / TOTP'},
  {id:'lab-kc-kerberos-fresh-webauthn',family:'Keycloak bridge / WebAuthn'},
  {id:'lab-ad-pkinit-success',family:'PKINIT'},
  {id:'lab-ad-fast-as-success',family:'FAST AS'},
  {id:'lab-ad-fast-tgs-success',family:'FAST TGS'},
  {id:'lab-ad-forest-child-domains',family:'Forest child domains'},
  {id:'lab-ad-forest-three-denied',family:'Third forest comparison'},
];

async function choose(page,id,expanded=false){
  await page.evaluate(({id,expanded})=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario(id);if(expanded){a.showInternals=true;a.renderAll();}}, {id,expanded});
}
async function overlayBounds(page,selector,label){
  const bounds=await page.locator(selector).evaluate(node=>{const r=node.getBoundingClientRect();return {hidden:node.hidden,left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight};});
  assert.equal(bounds.hidden,false,label+' opens');
  assert.ok(bounds.left>=-1&&bounds.right<=bounds.width+1&&bounds.top>=-1&&bounds.bottom<=bounds.height+1,label+' stays inside viewport: '+JSON.stringify(bounds));
  return bounds;
}
async function scene(page,label,{samplePaths=false}={}){
  const snapshot=await page.evaluate(samplePaths=>{
    const a=document.querySelector('auth-flow-studio');
    const cards=[...a.refs.actors.querySelectorAll('[data-actor]')].filter(c=>!c.hidden&&c.getBoundingClientRect().width>0);
    const rectangles=cards.map(c=>{const r=c.getBoundingClientRect();return {id:c.dataset.actor,left:r.left,right:r.right,top:r.top,bottom:r.bottom};});
    const collisions=[],overlaps=[],textClipping=[],intentionalAbbreviations=[];
    for(let i=0;i<rectangles.length;i++)for(let j=i+1;j<rectangles.length;j++){const x=rectangles[i],y=rectangles[j];if(x.left<y.right-1&&x.right>y.left+1&&x.top<y.bottom-1&&x.bottom>y.top+1)overlaps.push([x.id,y.id]);}
    if(samplePaths)for(const p of a.refs.connections.querySelectorAll('.connection-line')){
      const length=p.getTotalLength(),matrix=p.getScreenCTM();if(!matrix)continue;
      for(let n=0;n<=Math.ceil(length);n++){
        const v=p.getPointAtLength(Math.min(n,length)),s=new DOMPoint(v.x,v.y).matrixTransform(matrix);
        const card=rectangles.find(r=>s.x>r.left+1&&s.x<r.right-1&&s.y>r.top+1&&s.y<r.bottom-1);
        if(card){collisions.push({pair:p.parentElement.dataset.pair,actor:card.id});break;}
      }
    }
    // Context chips intentionally abbreviate addresses; the full context is below
    // the graph and must wrap. Scrollable <pre> and graph canvases are intentional.
    for(const node of document.querySelectorAll('.actor-name,.actor-role,.scenario-context-item code,.lifetime-card strong,.lifetime-card p')){
      if(node.getBoundingClientRect().width&&(node.scrollWidth>node.clientWidth+2||node.scrollHeight>node.clientHeight+2)){
        const css=getComputedStyle(node),item={class:node.className,text:node.textContent.slice(0,140)};
        if(css.textOverflow==='ellipsis'||Number(css.webkitLineClamp)>0)intentionalAbbreviations.push(item);else textClipping.push(item);
      }
    }
    return {id:a.labScenarioId,expanded:a.showInternals,steps:a.steps.length,actors:rectangles.map(r=>r.id),collisions,overlaps,textClipping,intentionalAbbreviations,documentOverflow:document.documentElement.scrollWidth>innerWidth+1};
  },samplePaths);
  assert.ok(snapshot.steps>0&&snapshot.actors.length>0,label+' has participants and events');
  assert.deepEqual(snapshot.collisions,[],label+' path/card collisions');
  assert.deepEqual(snapshot.overlaps,[],label+' overlapping participant cards');
  assert.deepEqual(snapshot.textClipping,[],label+' actual text clipping');
  assert.equal(snapshot.documentOverflow,false,label+' document overflow');
  return snapshot;
}
async function help(page,mode,{everyActor=true,fresh=false,screenshots=false}={}){
  const ids=await page.locator('#actors [data-actor]').evaluateAll(cards=>cards.filter(c=>!c.hidden&&c.getBoundingClientRect().width).map(c=>c.dataset.actor));
  const captureId=await page.evaluate(ids=>{const a=document.querySelector('auth-flow-studio');return ids.find(id=>a.scenarioOwnedActors?.[id]?.parentId)||ids[0];},ids);
  for(const id of everyActor?ids:ids.slice(0,1)){
    const card=page.locator('#actors [data-actor="'+id+'"]');
    await page.evaluate(fresh=>{const a=document.querySelector('auth-flow-studio');a.hidePopups();document.activeElement?.blur();if(fresh)a.refs['actor-popup'].innerHTML='';},fresh);
    await card.hover();await overlayBounds(page,'#actor-popup',mode+' '+id+' hover help');
    const title=await page.locator('#actor-popup .popup-title').textContent();
    const expected=await page.evaluate(id=>document.querySelector('auth-flow-studio').actor(id).name,id);assert.equal(title,expected);
    await page.evaluate(()=>{document.querySelector('auth-flow-studio').hidePopups();document.activeElement?.blur();});
    await card.focus();await overlayBounds(page,'#actor-popup',mode+' '+id+' focus help');
    await page.keyboard.press('F2');
    assert.equal(await page.evaluate(()=>document.querySelector('#actor-popup').contains(document.activeElement)),true,mode+' '+id+' F2 enters current participant help');
    if(screenshots&&id===captureId)await screen(page,mode+'-'+id+'-participant-help',{fullPage:false});
    const multipleHelpControls=await page.locator('#actor-popup button,#actor-popup a[href]').count()>1;
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(()=>document.activeElement?.isConnected&&document.activeElement?.getBoundingClientRect().width>0),true,mode+' Tab reaches visible content');
    if(multipleHelpControls)assert.equal(await page.evaluate(()=>document.querySelector('#actor-popup').contains(document.activeElement)),true,mode+' Tab explores controls inside participant help');
    const field=page.locator('#actor-popup [data-attribute]').first();
    if(await field.count()){
      const fieldId=await field.getAttribute('data-attribute');await field.focus();await page.keyboard.press('F2');
      await overlayBounds(page,'#attribute-popup',mode+' '+id+' nested field help');
      assert.equal(await page.evaluate(()=>document.querySelector('#attribute-popup').contains(document.activeElement)),true,mode+' nested F2 enters attribute help');
      if(screenshots&&id===captureId)await screen(page,mode+'-'+id+'-nested-attribute-help',{fullPage:false});
      await page.keyboard.press('Escape');
      assert.equal(await page.evaluate(()=>document.activeElement?.dataset.attribute),fieldId,mode+' nested Escape restores field');
      assert.equal(await page.locator('#actor-popup').evaluate(node=>node.hidden),false,mode+' nested Escape retains participant help');
    }else await page.locator('#actor-popup [data-close]').focus();
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(()=>document.activeElement?.dataset.actor),id,mode+' Escape restores exact participant');
  }
  check(mode+' hover/focus/F2/Tab/nested-help/Escape',{actors:everyActor?ids:ids.slice(0,1),fresh});
}
async function screen(page,name,{fullPage=true}={}){const safeName=name.replace(/[^A-Za-z0-9._-]+/g,'-').slice(0,180),file=path.join(evidenceDir,'code1-correction-'+safeName+'.png');await page.screenshot({path:file,fullPage});evidence.screenshots.push(file);}
async function protocolStudy(page,mode){
  await choose(page,'lab-ad-forest-child-domains',true);
  await page.evaluate(()=>document.querySelector('auth-flow-studio').selectStep(8,false));
  const before=await page.evaluate(()=>{const s=document.querySelector('auth-flow-studio').protocolSnapshot();return {state:s.state,sourceIndex:s.sourceIndex};});
  await page.locator('#attribute-search').fill('ticket');
  assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').protocolSnapshot().state),before.state,mode+' search preserves protocol state');
  const childId=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return Object.values(a.scenarioOwnedActors).find(actor=>actor.parentId&&a.positions[actor.id])?.id;});
  if(childId){
    await page.locator('#actors [data-actor="'+childId+'"]').focus();
    await page.evaluate(()=>{const toggle=document.querySelector('#show-internals');toggle.checked=false;toggle.dispatchEvent(new Event('change',{bubbles:true}));});
    assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').protocolSnapshot().state),before.state,mode+' collapsing preserves protocol state');
    assert.equal(await page.evaluate(()=>document.activeElement!==document.body&&document.activeElement?.isConnected&&document.activeElement?.getBoundingClientRect().width>0),true,mode+' collapse restores visible focus');
  }
  await page.locator('#attribute-search').fill('');
  const traceField=page.locator('#attribute-index [data-index-attribute="forestTgsRep"]');
  await traceField.focus();await page.keyboard.press('Enter');
  await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.pause();a.selectStep(Math.floor(a.traceQueue.length/2),false);});
  assert.equal(await page.evaluate(()=>document.activeElement?.dataset.indexAttribute),'forestTgsRep',mode+' keyboard field replay retains index focus');
  const focused=await page.evaluate(()=>{const s=document.querySelector('auth-flow-studio').protocolSnapshot();return {sourceIndex:s.sourceIndex,state:s.state};});
  await page.evaluate(index=>{const a=document.querySelector('auth-flow-studio');a.clearAttribute();a.selectStep(index,false);},focused.sourceIndex);
  assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').protocolSnapshot().state),focused.state,mode+' focused replay and full source prefix agree');
  assert.equal(await page.evaluate(()=>document.activeElement?.dataset.indexAttribute),'forestTgsRep',mode+' full source view restores focused index field');
  await page.evaluate(index=>{const a=document.querySelector('auth-flow-studio'),clock=a.studyClock();a.seekPlayback((clock.offsets[index]+1)/clock.total);},focused.sourceIndex);
  assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').protocolSnapshot().state),focused.state,mode+' seeking reconstructs same state');
  assert.equal(await page.evaluate(()=>document.activeElement?.dataset.indexAttribute),'forestTgsRep',mode+' seeking retains focused index field');
  const edge=page.locator('#connections .connection-hit').first();await edge.focus();await page.keyboard.press('Enter');
  await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  assert.equal(await page.evaluate(()=>document.activeElement?.matches('.connection-hit')),true,mode+' keyboard connection replay retains link focus');
  const connectionPrefix=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),s=a.protocolSnapshot();return {state:s.state,index:s.sourceIndex,queue:a.player.queue.map(step=>step.id)};});
  assert.ok(connectionPrefix.queue.length,mode+' connection selects ordered exchanges');
  await page.evaluate(index=>document.querySelector('auth-flow-studio').selectStep(index,false),connectionPrefix.index);
  assert.deepEqual(await page.evaluate(()=>document.querySelector('auth-flow-studio').protocolSnapshot().state),connectionPrefix.state,mode+' connection replay uses complete source prefix');
  await page.locator('#move-participants').check();
  const moveId=await page.locator('#actors [data-actor]').first().getAttribute('data-actor');
  const movementBefore=await page.evaluate(id=>{const a=document.querySelector('auth-flow-studio');return {position:a.positions[id],state:a.protocolSnapshot().state};},moveId);
  await page.locator('#actors [data-actor="'+moveId+'"]').focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowDown');
  const movementAfter=await page.evaluate(id=>{const a=document.querySelector('auth-flow-studio');return {position:a.positions[id],state:a.protocolSnapshot().state,focus:document.activeElement?.dataset.actor};},moveId);
  assert.notDeepEqual(movementAfter.position,movementBefore.position,mode+' keyboard movement moves a card');
  assert.deepEqual(movementAfter.state,movementBefore.state,mode+' movement preserves protocol state');assert.equal(movementAfter.focus,moveId);
  await page.locator('#move-participants').uncheck();await scene(page,mode+' moved forest',{samplePaths:true});
  check(mode+' filtering, collapse, focused replay, seek and keyboard movement preserve protocol semantics');
}
async function longContext(page,mode){
  for(const id of ['lab-ssh-cert-success','lab-ad-first-sign-in','lab-ad-pkinit-success','lab-ad-fast-as-success']){
    await choose(page,id);
    await page.locator('#environment-panel').evaluate(node=>node.open=true);
    await page.locator('#environment-fields details').evaluateAll(nodes=>nodes.forEach(node=>node.open=true));
    const fields=await page.locator('[data-environment-field]').evaluateAll(nodes=>nodes.map(node=>node.dataset.environmentField));
    const samples={caURL:'https://operator-memory-only.invalid/'+('ca-path-'.repeat(110)),aIssuerURL:'https://operator-memory-only.invalid/'+('issuer-path-'.repeat(90)),sshHost:('long-context-'.repeat(12))+'operator-memory-only.invalid',kerberosRealm:('LONGCONTEXT.'.repeat(28))+'OPERATOR-MEMORY-ONLY.INVALID',servicePrincipal:'HTTP/'+('long-context-'.repeat(12))+'operator-memory-only.invalid',appURL:'https://operator-memory-only.invalid/'+('application-path-'.repeat(70))};
    const applied=[];
    for(const [field,value]of Object.entries(samples))if(fields.includes(field)){await page.locator('[data-environment-field="'+field+'"]').fill(value);applied.push({field,value});}
    assert.ok(applied.length,mode+' '+id+' offers concrete runtime context');
    await page.locator('#environment-apply').click();
    assert.equal(await page.locator('#environment-errors').evaluate(node=>node.hidden),true,mode+' long context validates');
    assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').runtimeEnvironment.active),true);
    for(const {value}of applied)assert.equal(await page.locator('#scenario-environment').evaluate((node,value)=>node.textContent.includes(value),value),true,mode+' full address is readable below the diagram');
    await scene(page,mode+' '+id+' long context');
    assert.equal(await page.evaluate(()=>{if(location.href.includes('operator-memory-only'))return true;for(const name of ['localStorage','sessionStorage']){try{if(window[name].length>0)return true;}catch{/* Opaque file origin can prohibit storage access. */}}return false;}),false,mode+' runtime values never enter storage/history');
    await page.locator('#environment-panel').evaluate(node=>node.open=false);await screen(page,mode+'-'+id+'-long-context');
    await page.reload({waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.initialized);
    assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').runtimeEnvironment.active),false);
  }
  check(mode+' long context wraps, stays page-only, and resets on reload');
}

try{
  const require=createRequire(import.meta.url);let playwright;
  if(process.env.PLAYWRIGHT_MODULE)playwright=await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
  else{try{playwright=require('playwright');}catch(error){if(!process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES)throw new Error('Playwright is not installed. Install locally or set PLAYWRIGHT_MODULE to its absolute module path.',{cause:error});playwright=require(path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES,'playwright'));}}
  const executable=process.env.CHROMIUM_EXECUTABLE||playwright.chromium.executablePath();evidence.browserExecutable=executable;
  if(!fs.existsSync(executable))throw new Error('No Chromium executable is installed. Native-browser checks have not run.');
  browser=await playwright.chromium.launch({headless:true,executablePath:executable,args:['--no-sandbox']});evidence.browserVersion=browser.version();evidence.status='running';save();
  const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
  server=http.createServer((req,res)=>{const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname),file=path.resolve(project,'.'+(pathname==='/'?'/index.html':pathname));if(!file.startsWith(project+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){res.writeHead(404);res.end();return;}res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(res);});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
  for(const [mode,pathname]of [['source','/index.html'],['standalone','/dist/auth-flow-studio.html'],['standalone-file','/dist/auth-flow-studio.html']]){
    const target=mode==='standalone-file'?pathToFileURL(path.join(project,'dist/auth-flow-studio.html')).href:origin+pathname;
    const allowedRequest=url=>mode==='standalone-file'?url===target||url===new URL('favicon.ico',target).href:url.startsWith(origin+'/');
    const context=await browser.newContext({viewport:{width:1600,height:1050},bypassCSP:false});const page=await context.newPage(),errors=[],requests=[],interceptions=[],applicationViolations=[];
    page.on('pageerror',error=>errors.push(String(error)));page.on('request',request=>requests.push(request.url()));
    await page.exposeFunction('recordNativeQaCspViolation',record=>applicationViolations.push(record));
    await page.addInitScript(()=>{window.__qaNativeCspRecords=[];document.addEventListener('securitypolicyviolation',event=>{const record={directive:event.effectiveDirective,blocked:event.blockedURI,disposition:event.disposition,documentURI:event.documentURI};window.__qaNativeCspRecords.push(record);window.recordNativeQaCspViolation(record);});});
    await page.route('**/*',route=>{interceptions.push(route.request().url());return allowedRequest(route.request().url())?route.continue():route.abort();});
    await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.initialized);
    assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),'basic-keycloak');check(mode+' boots with ordinary Keycloak login');
    const scenarioIds=await page.evaluate(()=>[...document.querySelector('auth-flow-studio').refs['lab-scenario'].options].map(o=>o.value));assert.equal(new Set(scenarioIds).size,scenarioIds.length);
    for(const id of scenarioIds){await choose(page,id);const hasInternals=await page.evaluate(()=>Object.values(document.querySelector('auth-flow-studio').scenarioOwnedActors||{}).some(a=>a.parentId));for(const expanded of hasInternals?[false,true]:[false]){if(expanded)await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.showInternals=true;a.renderAll();});const snapshot=await scene(page,mode+' '+id,{samplePaths:true});assert.equal(snapshot.id,id);evidence.scenarios.push({mode,...snapshot});}}
    check(mode+' all catalog scenarios render without path/card overlap or actual text clipping',{count:scenarioIds.length});
    for(const workspace of ['web','ssh','kerberos']){await page.locator('[data-workspace="'+workspace+'"]').click();assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').workspace),workspace);await screen(page,mode+'-workspace-'+workspace);}
    await choose(page,'basic-keycloak');await help(page,mode+' Basic control',{everyActor:false,fresh:true});
    // Run every new visible participant against both an empty popup and legacy
    // help left in memory. This would reproduce F19 on the delivered code1.
    for(const {id,family}of studyCases){assert.ok(scenarioIds.includes(id),family+' fixture exists');await choose(page,id,true);await help(page,mode+' '+family,{fresh:true});await choose(page,'basic-keycloak');await help(page,mode+' legacy-before-'+family,{everyActor:false});await choose(page,id,true);await help(page,mode+' '+family+' after legacy');}
    await choose(page,'lab-ssh-cert-success');await page.locator('#play').click();await page.locator('#speed').evaluate(input=>{input.value='0';input.dispatchEvent(new Event('input',{bubbles:true}));});
    const paused=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {status:a.player.status,speed:a.player.speed,elapsed:a.player.elapsed,state:a.protocolSnapshot().state};});assert.equal(paused.status,'paused');assert.equal(paused.speed,0);await page.waitForTimeout(120);assert.deepEqual(await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {elapsed:a.player.elapsed,state:a.protocolSnapshot().state};}),{elapsed:paused.elapsed,state:paused.state});
    await page.locator('#seek').evaluate(input=>{input.value='550';input.dispatchEvent(new Event('input',{bubbles:true}));});const seek=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {status:a.player.status,progress:a.player.snapshot().overallProgress};});assert.equal(seek.status,'paused');assert.ok(Math.abs(seek.progress-.55)<.02);check(mode+' SSH speed zero freezes protocol state and scrub is paused',seek);
    await protocolStudy(page,mode);
    // Reduced CSS viewport sizes reproduce the reflow space of desktop browser
    // zoom without CSS zoom's different innerWidth semantics. This does not test
    // browser UI zoom, device pixel ratio or accessibility; those remain manual.
    const layoutCases=[{viewport:{width:1600,height:1050},zoomEquivalent:1},{viewport:{width:390,height:844},zoomEquivalent:1},{viewport:{width:800,height:525},zoomEquivalent:2},{viewport:{width:400,height:263},zoomEquivalent:4}];
    for(const {viewport,zoomEquivalent}of layoutCases){
      await page.setViewportSize(viewport);await page.emulateMedia({reducedMotion:'reduce'});
      for(const {id,family}of studyCases){await choose(page,id,true);const label=mode+' '+family+' '+viewport.width+'px desktop-zoom-equivalent '+zoomEquivalent;await scene(page,label);await help(page,label,{screenshots:true});await page.locator('#map-controls').scrollIntoViewIfNeeded();const sticky=await page.locator('#map-controls').evaluate(node=>({position:getComputedStyle(node).position,play:document.querySelector('#play').getBoundingClientRect().toJSON(),viewport:{width:innerWidth,height:innerHeight}}));assert.equal(sticky.position,'sticky',label+' controls stay beside map');assert.ok(sticky.play.top>=0&&sticky.play.bottom<=sticky.viewport.height&&sticky.play.left>=0&&sticky.play.right<=sticky.viewport.width,label+' Play is reachable in viewport');if(zoomEquivalent===1)await screen(page,mode+'-'+id+'-'+viewport.width);}
      check(mode+' dense new families at responsive / desktop zoom equivalent width / reduced motion',{viewport,desktopZoomEquivalent:zoomEquivalent,zoomIsBrowserUiZoom:false,reducedMotion:'reduce'});
    }
    await page.setViewportSize({width:390,height:844});await longContext(page,mode);
    assert.deepEqual(errors,[],mode+' native runtime errors');assert.deepEqual(applicationViolations,[],mode+' application CSP violations across all scenarios/reloads before deliberate probes');assert.deepEqual(await page.evaluate(()=>window.__qaNativeCspRecords),[],mode+' current page application CSP violations before deliberate probes');
    assert.ok(requests.every(allowedRequest),mode+' no external application requests');if(mode.startsWith('standalone'))assert.ok(requests.filter(url=>!url.endsWith('/favicon.ico')).every(url=>url===target),'standalone only loads its own document');
    check(mode+' application respects CSP and makes no external requests',{requestCount:requests.length});
    const fetchProbe=mode==='standalone-file'?'https://auth-lab-csp-probe.invalid/qa-prohibited-fetch':origin+'/qa-prohibited-fetch';
    const interceptionCountBeforeProbe=interceptions.length;
    const csp=await page.evaluate(async fetchProbe=>{window.__qaNativeCspRecords=[];let evalBlocked=false;try{Function('return 42')();}catch{evalBlocked=true;}const script=document.createElement('script');script.textContent='window.__qaInlineExecuted=true';document.head.append(script);let fetchRejected=false;try{await fetch(fetchProbe);}catch{fetchRejected=true;}return {evalBlocked,inlineBlocked:!window.__qaInlineExecuted,fetchRejected};},fetchProbe);
    await page.waitForFunction(()=>window.__qaNativeCspRecords.length>=3);const violations=await page.evaluate(()=>window.__qaNativeCspRecords);
    assert.equal(csp.evalBlocked,true);assert.equal(csp.inlineBlocked,true);assert.equal(csp.fetchRejected,true);
    assert.ok(violations.some(v=>/^script-src/.test(v.directive)&&v.blocked==='eval'&&v.disposition==='enforce'),mode+' eval attributed to script-src');
    assert.ok(violations.some(v=>/^script-src/.test(v.directive)&&v.blocked==='inline'&&v.disposition==='enforce'),mode+' arbitrary inline script attributed to script-src');
    assert.ok(violations.some(v=>v.directive==='connect-src'&&v.blocked.startsWith(new URL(fetchProbe).origin)&&v.disposition==='enforce'),mode+' fetch attributed to connect-src');
    assert.equal(interceptions.length,interceptionCountBeforeProbe,mode+' forbidden fetch never reaches request interception/network');
    check(mode+' actual CSP enforcement rejects eval/inline/fetch with attributable violation events',{...csp,violations});
    await context.close();save();
  }
  evidence.artifactAfterChecks={sourceEntry:digest(path.join(project,'index.html')),standalone:digest(path.join(project,'dist/auth-flow-studio.html')),sourceSnapshotSha256:sourceSnapshot()};
  assert.deepEqual(evidence.artifactAfterChecks,artifact,'source/standalone bytes remain unchanged throughout native checks');
  evidence.status='passed';evidence.verified=true;
}catch(error){evidence.reason=String(error.stack||error);if(evidence.status==='running')evidence.status='failed';process.exitCode=1;}
finally{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));save();console.log(JSON.stringify({status:evidence.status,verified:evidence.verified,output,artifact,reason:evidence.reason?.split('\n')[0]},null,2));}
