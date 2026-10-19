#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/review-file-smoke.mjs [standalone.html] [project-directory]\nBuild first. Defaults to this checkout and dist/auth-flow-studio.html; optionally pass the actual delivered HTML. Requires Playwright/PLAYWRIGHT_MODULE and installed Chromium/CHROMIUM_EXECUTABLE. Checks exact R1 replay, measured compact targets, file-mode CSP and no external application requests. Evidence: AUTH_LAB_HELD_EVIDENCE_DIR or docs/verification/held-objects.');process.exit(0);}
const root=path.resolve(process.argv[3]||path.join(path.dirname(fileURLToPath(import.meta.url)),'../..')),out=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(root,'docs/verification/held-objects')),file=path.resolve(process.argv[2]||path.join(root,'dist/auth-flow-studio.html'));
fs.mkdirSync(out,{recursive:true});
const require=createRequire(import.meta.url),playwright=process.env.PLAYWRIGHT_MODULE?await import(pathToFileURL(path.resolve(process.env.PLAYWRIGHT_MODULE)).href):require('playwright');
const {chromium}=playwright;
const sha256=createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(sha256,createHash('sha256').update(fs.readFileSync(root+'/dist/auth-flow-studio.html')).digest('hex'));
const report={kind:'delivered-held-objects-file-smoke',nativeBrowser:true,passed:false,timestamp:new Date().toISOString(),runnerSha256:createHash('sha256').update(fs.readFileSync(fileURLToPath(import.meta.url))).digest('hex'),regenerationCommand:[process.execPath,...process.argv.slice(1)],standalone:{bytes:fs.statSync(file).size,sha256},screenshots:[]};
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage']});report.browser=browser.version();
try{
 const page=await browser.newPage({viewport:{width:1920,height:1200}}),errors=[],requests=[];page.on('pageerror',e=>errors.push(String(e)));page.on('request',r=>requests.push(r.url()));
 await page.addInitScript(()=>{window.__violations=[];document.addEventListener('securitypolicyviolation',e=>window.__violations.push({directive:e.effectiveDirective,blocked:e.blockedURI}));});
 const url=pathToFileURL(file).href;await page.goto(url,{waitUntil:'networkidle'});
 const r1=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-refresh-rotation');a.selectStep(a.steps.findIndex(s=>s.id.endsWith('-replace')),false);return a.heldView.snapshot().holdings.find(h=>h.actorId==='app'&&h.artifactId==='R1').holdingId;});
 await page.locator('#held-docks [data-held-actor="app"]').click();await page.locator('#held-objects [data-holding-id='+JSON.stringify(r1)+']').click();
 await page.mouse.move(0,0);await page.locator('#actor-popup').waitFor({state:'hidden'});await page.locator('#attribute-popup').waitFor({state:'hidden'});await page.locator('#held-inspector').scrollIntoViewIfNeeded();
 assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.selection.artifactId),'R1');
 await page.screenshot({path:out+'/review-file-clean-R1-inspector.png',fullPage:false});report.screenshots.push('review-file-clean-R1-inspector.png');
 const full=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot());
 await page.locator('#speed').evaluate(n=>{n.value='4';n.dispatchEvent(new Event('input',{bubbles:true}));});await page.locator('#held-inspector [data-held-trace]').click();await page.waitForFunction(()=>document.querySelector('auth-flow-studio').player.status==='complete');
 const exact=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {artifactId:a.objectTraceSelection,rows:a.traceQueue.map(s=>s.sourceIndex),snapshot:a.heldView.snapshot()};});assert.deepEqual(exact.snapshot,full);report.exactReplay={artifactId:exact.artifactId,sourceRows:exact.rows,cursor:exact.snapshot.cursor,fullSnapshotEquality:true};
 await page.setViewportSize({width:1480,height:1100});
 await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.selectLabScenario('lab-ad-fast-as-success');a.showInternals=true;a.renderAll();const step=a.steps.find(s=>a.stepAttributeItems(s).length>=2);a.player.seek([step],.5,'step');});
 await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await page.mouse.move(0,0);
 report.compact=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),panel=a.refs['step-attributes'];return {geometry:a.refs.graph.dataset.heldGeometry,actors:[...a.querySelectorAll('.actor-card')].filter(n=>!n.closest('[hidden]')).map(n=>{const r=n.getBoundingClientRect();return {id:n.dataset.actor,width:r.width,height:r.height};}),targets:[...a.querySelectorAll('#held-docks button')].map(n=>{const r=n.getBoundingClientRect();return {width:r.width,height:r.height};}),stepAttributes:{visible:!panel.closest('[hidden]')&&panel.getBoundingClientRect().width>0,external:!!panel.closest('#step-attributes-external'),names:[...panel.querySelectorAll('code')].map(n=>n.textContent)}};});
 assert.equal(report.compact.geometry,'compact');for(const actor of report.compact.actors){assert.equal(actor.width,82);assert.equal(actor.height,132);}for(const target of report.compact.targets){assert.ok(target.width>=44&&target.height>=44);}assert.equal(report.compact.stepAttributes.visible,true);
 await page.locator('#graph').screenshot({path:out+'/review-file-compact-inventory.png'});report.screenshots.push('review-file-compact-inventory.png');
 if(report.compact.stepAttributes.external){await page.locator('#step-attributes-external').screenshot({path:out+'/review-file-compact-step-attributes.png'});report.screenshots.push('review-file-compact-step-attributes.png');}
 assert.deepEqual(errors,[]);assert.deepEqual(await page.evaluate(()=>window.__violations),[]);assert.ok(requests.every(r=>r===url));report.applicationRequests=requests;report.passed=true;
}catch(error){report.failures=[{message:error.message,stack:error.stack}];process.exitCode=1;}
finally{await browser.close();fs.writeFileSync(out+'/review-file-smoke-status.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));}
