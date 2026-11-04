#!/usr/bin/env bun
// Focused correction evidence only. No changes to the historical browser matrix.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {DEFAULT_BROWSER,DEFAULT_PLAYWRIGHT,DEFAULT_LIBRARIES,captureInputs,fileIdentity,runtimeIdentity,launchBrowser,createStaticServer,createBrowserSession,settle,studyState,continuityProjection,assertClean} from '../compact-mobile-browser.mjs';
import {launchNativeZoom,nativeIsolation,X11_ROOT} from '../compact-native-zoom.mjs';
import {performanceReady} from './performance-fixtures.mjs';
import {text200} from './browser-layout.mjs';

const producer=fileURLToPath(import.meta.url),checkout=path.resolve(path.dirname(producer),'../../..');
const help='correction-browser.mjs --out=NEW_EXTERNAL_DIR --locale=he|ar-AE|ru [--root=CHECKOUT] [--loading=source-http|emitted-http|standalone-file] [--mode=ordinary|text200|native400|recovery] [--source-sha256=HASH --html-sha256=HASH]; ru is recovery-only';
const json=(directory,name,value)=>fs.writeFileSync(path.join(directory,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
const selectors={list:'#attribute-index-list',fields:'#attribute-index-list [data-index-attribute]'};

async function accessibilityFields(session){
  const cdp=await session.context.newCDPSession(session.page);
  try{
    await cdp.send('Accessibility.enable');
    const {root}=await cdp.send('DOM.getDocument',{depth:0}),{nodeId}=await cdp.send('DOM.querySelector',{nodeId:root.nodeId,selector:selectors.list});
    const {node}=await cdp.send('DOM.describeNode',{nodeId}),{nodes}=await cdp.send('Accessibility.getFullAXTree');
    const byId=new Map(nodes.map(item=>[item.nodeId,item])),list=nodes.find(item=>item.backendDOMNodeId===node.backendNodeId);
    assert.ok(list,'Full index has an actual browser accessibility subtree');
    const buttons=[],visit=id=>{const item=byId.get(id);if(!item)return;if(item.role?.value==='button'&&!item.ignored)buttons.push({name:item.name?.value||'',backendDOMNodeId:item.backendDOMNodeId});for(const child of item.childIds||[])visit(child);};
    visit(list.nodeId);
    return {count:buttons.length,orderedNamesSha256:Bun.SHA256.hash(JSON.stringify(buttons.map(item=>item.name)),'hex'),first:buttons[0],last:buttons.at(-1),mechanism:'Actual Chromium Accessibility.getFullAXTree subtree, not DOM role counting or human AT acceptance'};
  }finally{await cdp.detach();}
}

async function run(options,out){
  const root=fs.realpathSync(options.root||checkout),before=captureInputs(root),native=options.mode==='native400';
  for(const [key,value]of [['source-sha256',before.canonicalSha256],['html-sha256',before.standalone.sha256]])if(options[key])assert.equal(options[key],value);
  const producerBefore=Object.fromEntries([['self',producer],['browserHelper',path.join(root,'tools/verification/compact-mobile-browser.mjs')],['zoomHelper',path.join(root,'tools/verification/compact-native-zoom.mjs')],['layoutHelper',path.join(root,'tools/verification/localization/browser-layout.mjs')]].map(([key,file])=>[key,{path:file,...fileIdentity(file)}]));
  const report={schemaVersion:1,kind:'localization-review01-focused-full-index-browser',status:'failed',qualification:'Actual Full browser/AX/focus/RTL/enlargement evidence only. Offscreen focus is an explicitly programmatic diagnostic setup followed by trusted F2/Escape. Not full matrix, human AT, language, physical-device or performance acceptance.',options,runtime:runtimeIdentity(),inputs:before,producers:producerBefore,errors:[]};
  let launch,server,session;
  try{
    launch=native?await launchNativeZoom({out,modulePath:DEFAULT_PLAYWRIGHT,executablePath:DEFAULT_BROWSER,libraryPath:DEFAULT_LIBRARIES}):await launchBrowser();report.browser=launch.identity;
    if(native)report.nativeIsolation=nativeIsolation();
    server=await createStaticServer({roots:{candidate:root},identities:{candidate:before}});
    session=await createBrowserSession({browser:launch.browser,server,rootName:'candidate',root,identity:before,loadingMode:options.loading,viewport:native?null:{width:1440,height:1000},preference:'full'});
    await session.context.addInitScript(({tag,target})=>{if(location.href===target)localStorage.setItem('auth-flow-studio.locale.v1',tag);},{tag:options.locale,target:session.target});
    await session.page.goto(session.target,{waitUntil:'domcontentloaded'});
    await session.page.waitForFunction(performanceReady,{scenarioId:'basic-keycloak',presentation:'full',locale:options.locale,baseline:false});await settle(session.page);
    await session.page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a.localizer.catalog?.locale===a.localizer.locale&&a.localizer.fallbacks.size===0;});
    if(options.mode==='ordinary'){
      const before=await studyState(session.page);
      await session.page.evaluate(async locale=>{const a=document.querySelector('auth-flow-studio');a.player.pause();await a.changeLocale('en',{explicit:false});await a.changeLocale(locale,{explicit:false});},options.locale);await settle(session.page);
      assert.deepEqual(continuityProjection(await studyState(session.page)),continuityProjection(before),'Diagnostic locale roundtrip preserves source state');
      report.localeRoundtripMechanism='Programmatic AuthFlowStudio.changeLocale diagnostic; not native selector, human input or trusted-event acceptance';
      report.sharedChrome=await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),source='↑ ↓ to navigate · Enter to choose';return {mechanism:'Actual Chromium CSS child/last-child selection after a product locale roundtrip, not the DOM harness adapter',locale:a.localizer.locale,menus:[['workspace-menu','ui.app.shell.text.0021'],['lab-scenario-menu','ui.app.shell.text.0028']].map(([id,key])=>{const node=a.querySelector('#'+id+' .scenario-picker-menu-heading > span:last-child');return {id,text:node.textContent,expected:a.uiText(key,source),protectedEnter:[...node.querySelectorAll('[dir="ltr"][translate="no"]')].some(child=>child.textContent==='Enter')};}),actorPopupName:a.refs['actor-popup'].getAttribute('aria-label'),expectedActorPopupName:a.uiText('ui.app.shell.attribute.0040','Participant attributes')};});
      for(const menu of report.sharedChrome.menus){assert.equal(menu.text,menu.expected,'Actual browser hidden menu hint uses the active locale');assert.equal(menu.protectedEnter,true);}
      assert.equal(report.sharedChrome.actorPopupName,report.sharedChrome.expectedActorPopupName);
    }
    await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.pause();a.openFieldIndex();});await settle(session.page);
    if(native)report.nativeZoom=await launch.apply(session.page,'full-'+options.locale);
    if(options.mode==='text200')report.textEnlargement=await text200(session.page);
    const state=await studyState(session.page);
    report.dom=await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),fields=[...a.querySelectorAll('#attribute-index-list [data-index-attribute]')];return {locale:a.localizer.locale,lang:a.lang,direction:a.dir,presentation:a.presentationMode,count:fields.length,first:fields[0]?.dataset.indexAttribute,last:fields.at(-1)?.dataset.indexAttribute,allTechnicalNamesProtected:fields.every(node=>{const code=node.querySelector('code');return code?.getAttribute('dir')==='ltr'&&code.getAttribute('translate')==='no';}),fallbacks:a.localizer.diagnostics().fallbacks};});
    assert.equal(report.dom.count,10843,'Full retains every original global technical field control');assert.equal(report.dom.presentation,'full');assert.equal(report.dom.direction,'rtl');assert.equal(report.dom.locale,options.locale);assert.equal(report.dom.allTechnicalNamesProtected,true);assert.deepEqual(report.dom.fallbacks,[]);
    report.accessibility=await accessibilityFields(session);assert.equal(report.accessibility.count,report.dom.count,'Offscreen layout deferral retains the complete actual AX field subtree');
    // Enter keyboard focus mode before the deliberately programmatic offscreen
    // focus diagnostic. Do not scroll/refocus to manufacture a visible result.
    await session.page.keyboard.press('Tab');
    const last=session.page.locator(selectors.fields).last();
    report.offscreenBefore=await last.evaluate(node=>({id:node.dataset.indexAttribute,top:node.getBoundingClientRect().top,height:node.getBoundingClientRect().height,viewport:innerHeight}));
    await last.evaluate(node=>node.focus());await settle(session.page);
    report.offscreenAfter=await last.evaluate(node=>{const rect=node.getBoundingClientRect();return {id:node.dataset.indexAttribute,focused:document.activeElement===node,top:rect.top,bottom:rect.bottom,left:rect.left,right:rect.right,viewport:{width:innerWidth,height:innerHeight},text:node.querySelector('code').textContent};});
    assert.equal(report.offscreenAfter.focused,true);assert.ok(report.offscreenAfter.bottom>0&&report.offscreenAfter.top<report.offscreenAfter.viewport.height,'Browser focus naturally exposes the deferred row');
    await session.page.keyboard.press('F2');await settle(session.page);
    report.popup=await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),popup=a.refs['attribute-popup'],ids=(popup.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean),labels=ids.map(id=>document.getElementById(id));return {visible:!popup.hidden&&popup.getClientRects().length>0,focusInside:popup.contains(document.activeElement),labelIds:ids,allLabelsResolve:labels.length>0&&labels.every(node=>!!node?.textContent.trim()),name:labels.map(node=>node?.textContent||'').join(' '),fieldTitle:popup.querySelector('#attribute-popup-field-title code')?.textContent,protectedTitle:!!popup.querySelector('h2 code[dir="ltr"][translate="no"]')};});
    assert.equal(report.popup.visible,true);assert.equal(report.popup.focusInside,true);assert.equal(report.popup.allLabelsResolve,true);assert.deepEqual(report.popup.labelIds,['attribute-popup-title','attribute-popup-field-title']);assert.equal(report.popup.protectedTitle,true);assert.equal(report.popup.fieldTitle,report.offscreenAfter.text);
    await session.page.keyboard.press('Escape');await settle(session.page);
    assert.equal(await last.evaluate(node=>document.activeElement===node),true,'Trusted Escape returns to the actual same technical field');
    assert.deepEqual(continuityProjection(await studyState(session.page)),continuityProjection(state),'AX/focus/enlargement do not change paused source state or queue');
    assertClean(session.evidence);report.evidence=session.evidence;
    const screenshot=path.join(out,'full-'+options.locale+'-'+options.mode+'.png');if(native)await launch.screenshot(session.page,screenshot);else await session.page.screenshot({path:screenshot,fullPage:false});report.screenshot={path:path.basename(screenshot),...fileIdentity(screenshot)};
    assert.deepEqual(captureInputs(root),before,'Exact source and emitted inputs unchanged');
    for(const [key,prior]of Object.entries(producerBefore)){const {path:file,...identity}=prior;assert.deepEqual(fileIdentity(file),identity,'Producer unchanged: '+key);}
    report.status='passed-focused-not-acceptance';
  }catch(error){report.errors.push(String(error.stack||error));if(session)try{const screenshot=path.join(out,'failure.png');await session.page.screenshot({path:screenshot,fullPage:false});report.failureScreenshot={path:'failure.png',...fileIdentity(screenshot)};}catch(screenshotError){report.screenshotError=String(screenshotError);}}
  finally{await session?.close();await server?.close();await launch?.close();json(out,'report.json',report);}
  return report;
}

async function recovery(options,out){
  const root=fs.realpathSync(options.root||checkout),identity=captureInputs(root),producerBefore=fileIdentity(producer);
  for(const [key,value]of [['source-sha256',identity.canonicalSha256],['html-sha256',identity.standalone.sha256]])if(options[key])assert.equal(options[key],value);
  const report={schemaVersion:1,kind:'localization-review01-actual-browser-gzip-recovery',status:'failed',qualification:'Actual missing-gzip startup and explicit-selection UI only. Full decode/rapid/retry matrix is separate; no Native language, human, AT, performance or release acceptance.',options,inputs:identity,producer:producerBefore,runtime:runtimeIdentity(),rows:[],errors:[]};
  let launch,server;
  try{
    launch=await launchBrowser();report.browser=launch.identity;server=await createStaticServer({roots:{candidate:root},identities:{candidate:identity}});
    for(const entry of ['saved-locale-startup','explicit-locale-selection']){
      const row={entry,status:'attempted'};report.rows.push(row);
      const session=await createBrowserSession({browser:launch.browser,server,rootName:'candidate',root,identity,loadingMode:options.loading,viewport:{width:1440,height:1000},preference:'full'});
      try{
        await session.context.addInitScript(({entry,locale,target})=>{if(location.href===target){globalThis.DecompressionStream=undefined;localStorage.setItem('auth-flow-studio.locale.v1',entry==='saved-locale-startup'?locale:'en');}},{entry,locale:options.locale,target:session.target});
        await session.page.goto(session.target,{waitUntil:'domcontentloaded'});
        await session.page.waitForFunction(performanceReady,{scenarioId:'basic-keycloak',presentation:'full',locale:'en',baseline:false});await settle(session.page);
        let before;
        if(entry==='explicit-locale-selection'){
          await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.inspectQueue(a.steps,{position:2,elapsed:a.player.durationFor(a.steps[2])*.37,kind:'demo'});a.player.pause();window.__correctionRecoveryQueue=a.player.queue;});
          before=await studyState(session.page);const select=session.page.locator('#language-select');await select.focus();await select.press('Alt+ArrowDown');await select.press('Home');
          for(let index=0;index<['en','ru','uk','he','de','ar-AE','fr','pl'].indexOf(options.locale);index++)await select.press('ArrowDown');await select.press('Enter');
        }
        await session.page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return !!a.localeFailure&&!a.localePreparation&&!a.hasAttribute('aria-busy')&&!a.refs.toast.hidden;});
        const after=await studyState(session.page);if(before)assert.deepEqual(continuityProjection(after),continuityProjection(before),'Failed language request preserves paused canonical state');
        row.surface=await session.page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),toast=a.refs.toast;return {initialized:a.initialized,locale:a.localizer.locale,failed:a.localeFailure.tag,selector:a.refs['language-select'].value,role:toast.getAttribute('role'),language:toast.getAttribute('lang'),direction:toast.getAttribute('dir'),visible:!toast.hidden&&toast.getClientRects().length>0,persistent:toast.hasAttribute('data-locale-failure'),busy:a.hasAttribute('aria-busy'),preparation:!!a.localePreparation,prepared:!!a.localizer.prepared,initialPreparation:!!a.localizer.initialPreparation,englishPreparation:!!a.localizer.englishPreparation,queueSame:!window.__correctionRecoveryQueue||a.player.queue===window.__correctionRecoveryQueue};});
        assert.equal(row.surface.initialized,true);assert.equal(row.surface.locale,'en');assert.equal(row.surface.failed,options.locale);assert.equal(row.surface.selector,'en');assert.equal(row.surface.role,'status');assert.equal(row.surface.language,'en');assert.equal(row.surface.direction,'ltr');assert.equal(row.surface.visible,true);assert.equal(row.surface.persistent,true);assert.equal(row.surface.queueSame,true);
        for(const field of ['busy','preparation','prepared','initialPreparation','englishPreparation'])assert.equal(row.surface[field],false,field+' cleared');
        assertClean(session.evidence);row.evidence=session.evidence;row.pausedStateAndQueueIdentityPreserved=!!before;
        const screenshot=path.join(out,entry+'.png');await session.page.screenshot({path:screenshot,fullPage:false});row.screenshot={path:path.basename(screenshot),...fileIdentity(screenshot)};row.status='passed';
      }catch(error){row.status='failed';row.error=String(error.stack||error);report.errors.push(entry+': '+row.error);}finally{await session.close();}
    }
    assert.deepEqual(captureInputs(root),identity);assert.deepEqual(fileIdentity(producer),producerBefore);
    if(report.rows.every(row=>row.status==='passed'))report.status='passed-focused-not-acceptance';
  }catch(error){report.errors.push(String(error.stack||error));}finally{await server?.close();await launch?.close();json(out,'report.json',report);}
  return report;
}

export async function main(argv=process.argv.slice(2)){
  if(argv.includes('--help')){console.log(help);return;}
  const options={mode:'ordinary',loading:'emitted-http'};
  for(const argument of argv){const match=/^--(out|locale|root|loading|mode|source-sha256|html-sha256)=(.+)$/.exec(argument);assert.ok(match,help);if(!['mode','loading'].includes(match[1]))assert.ok(!Object.hasOwn(options,match[1]),'Duplicate option');options[match[1]]=match[2];}
  assert.ok(options.out&&(options.mode==='recovery'?['ru','he','ar-AE']:['he','ar-AE']).includes(options.locale),help);assert.ok(['ordinary','text200','native400','recovery'].includes(options.mode));assert.ok(['source-http','emitted-http','standalone-file'].includes(options.loading));
  const root=fs.realpathSync(options.root||checkout),out=path.resolve(options.out);fs.mkdirSync(path.dirname(out),{recursive:true});const parent=fs.realpathSync(path.dirname(out));assert.ok(parent!==root&&!parent.startsWith(root+path.sep),'Output outside checkout');fs.mkdirSync(out);
  if(options.mode==='native400'&&process.env.LOCALIZATION_CORRECTION_NATIVE_CHILD!=='1'){
    const bin=fs.mkdtempSync(path.join(out,'.native-bin-')),names=fs.readdirSync('/usr/bin').sort();for(const name of names)fs.symlinkSync('/run/correction-host-bin/'+name,path.join(bin,name));if(names.includes('xkbcomp'))fs.unlinkSync(path.join(bin,'xkbcomp'));fs.symlinkSync(path.join(X11_ROOT,'xkbcomp'),path.join(bin,'xkbcomp'));
    const child=path.join(out,'native-child'),args=argv.map(value=>value.startsWith('--out=')?'--out='+child:value),network=fs.readlinkSync('/proc/self/ns/net');
    const command=['--die-with-parent','--new-session','--unshare-user','--uid','0','--gid','0','--unshare-net','--bind','/','/','--tmpfs','/run','--ro-bind','/usr/bin','/run/correction-host-bin','--ro-bind',bin,'/usr/bin','--dev-bind','/dev','/dev','--proc','/proc','--tmpfs','/tmp','--chdir',root,'--',process.execPath,producer,...args];
    let result;try{result=spawnSync('bwrap',command,{env:{...process.env,LOCALIZATION_CORRECTION_NATIVE_CHILD:'1',COMPACT_NATIVE_PARENT_NETNS:network},encoding:'utf8',maxBuffer:4*1024*1024,timeout:3600000});}finally{fs.rmSync(bin,{recursive:true});}
    json(out,'native-launch.json',{command:['bwrap',...command],status:result.status,signal:result.signal,error:result.error?String(result.error):null,parentNetworkNamespace:network,stdout:result.stdout,stderr:result.stderr,childReport:'native-child/report.json'});assert.ifError(result.error);process.exitCode=result.status===0?0:1;return;
  }
  const report=await(options.mode==='recovery'?recovery(options,out):run(options,out));console.log(JSON.stringify({status:report.status,dom:report.dom,accessibility:report.accessibility,rows:report.rows,errors:report.errors}));process.exitCode=report.status==='passed-focused-not-acceptance'?0:1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===producer)await main();
