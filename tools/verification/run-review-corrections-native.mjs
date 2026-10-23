#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
const runner=fileURLToPath(import.meta.url),root=path.resolve(process.argv[2]||path.join(path.dirname(runner),'../..'));
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/run-review-corrections-native.mjs [project-directory]\nBuild first. Uses installed PLAYWRIGHT_MODULE and CHROMIUM_EXECUTABLE, never downloads. Targeted NET-05/WIN-09/WIN-10/SMB-R01 recheck with preserved SMB/closed-finding coverage, NOT a full catalog/zoom/AT/interoperability gate. Output: AUTH_LAB_REVIEW_EVIDENCE_DIR or docs/verification/review-corrections-recheck/native.');process.exit(0);}
const out=path.resolve(process.env.AUTH_LAB_REVIEW_EVIDENCE_DIR||path.join(root,'docs/verification/review-corrections-recheck/native'));fs.mkdirSync(out,{recursive:true});
const hash=value=>createHash('sha256').update(value).digest('hex');
const digest=file=>hash(fs.readFileSync(file));
const identity=()=>({sources:Object.fromEntries(['index.html','build.mjs','package.json','security-policy.mjs',...fs.readdirSync(path.join(root,'src')).filter(n=>/\.(js|css)$/.test(n)).sort().map(n=>'src/'+n),...fs.readdirSync(path.join(root,'assets')).sort().map(n=>'assets/'+n)].map(n=>[n,digest(path.join(root,n))])),standalone:{bytes:fs.statSync(path.join(root,'dist/auth-flow-studio.html')).size,sha256:digest(path.join(root,'dist/auth-flow-studio.html'))}});
const report={kind:'review-corrections-recheck-targeted-native',timestamp:new Date().toISOString(),passed:false,nativeBrowser:true,scope:'Four-finding recheck: decoded RadSec field replay, intermediate-host result acceptance, Windows AES key lineage and five SMB ticket-key explanations, preserving the original closed fixes and twelve SMB models in three loading modes. No full catalog browser matrix or new performance comparison.',inputReview:{path:'docs/reviewer-handoff/auth-flow-studio-smb311-corrections-review.html',sha256:digest(path.join(root,'docs/reviewer-handoff/auth-flow-studio-smb311-corrections-review.html')),originalFindingsIndependentlyClosed:19,requestedFindings:['NET-05','WIN-09','WIN-10','SMB-R01']},runnerSha256:digest(runner),regenerationCommand:[process.execPath,...process.argv.slice(1)],runtime:{bun:process.versions.bun,version:process.version,platform:process.platform,arch:process.arch,os:os.release()},identity:identity(),modes:[],screenshots:[],failures:[],notEstablished:['Independent Astra acceptance of the four new corrections','Manual G01 and real assistive-technology comprehension','Cross-engine and live protocol interoperability','Fresh full-catalog native/zoom/touch/performance acceptance']};
const cases=[
 ['lab-smb-nonjoined-ntlm',{clientSessionAccepted:true,treeConnected:true,fileOpened:true,fileRead:true}],
 ['lab-smb-nonjoined-kerberos',{clientSessionAccepted:true,treeConnected:true,fileOpened:true,fileRead:true}],
 ['lab-smb-nonjoined-ntlm-blocked',{clientSessionAccepted:false,fileRead:false,clientKnowsFailure:true,failure:'incoming NTLM blocked'}],
 ['lab-smb-nonjoined-bad-credential',{clientSessionAccepted:false,fileRead:false,clientKnowsFailure:true,failure:'bad domain credential'}],
 ['lab-smb-nonjoined-dc-unavailable',{clientSessionAccepted:false,fileRead:false,clientKnowsFailure:true,failure:'DC validation unavailable'}],
 ['lab-smb-nonjoined-share-denied',{clientSessionAccepted:true,treeConnected:false,fileRead:false,failure:'share access denied'}],
 ['lab-smb-nonjoined-file-denied',{clientSessionAccepted:true,treeConnected:true,fileOpened:false,fileRead:false,failure:'file access denied'}],
 ['lab-smb-nonjoined-signature-rejected',{serverAuthenticated:true,clientSessionAccepted:false,clientDisconnected:true,fileRead:false}],
 ['lab-smb-nonjoined-encryption-rejected',{clientSessionWasAccepted:true,treeWasConnected:true,fileWasOpened:true,clientSessionAccepted:false,treeConnected:false,fileOpened:false,fileRead:false,clientDisconnected:true}],
 ['lab-smb-nonjoined-encryption-unavailable',{clientSessionAccepted:false,fileRead:false,clientKnowsFailure:true,serverKnowsFailure:false}],
 ['lab-smb-multichannel-binding-success',{clientSessionAccepted:true,channel2Usable:true,channel2FileRead:true,followupFileRead:true}],
 ['lab-smb-multichannel-binding-rejected',{clientSessionAccepted:true,treeConnected:true,fileOpened:true,channel1Usable:true,channel2Usable:false,bindingRejected:true,channel1ReadAfterBindingFailure:true,followupFileRead:true}],
];
const settle=page=>page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
async function choose(page,id){await page.locator('#lab-scenario-search').fill(id);const button=page.locator('[data-scenario-option='+JSON.stringify(id)+']');await button.click();await settle(page);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),id);for(const target of ['lesson-reference','ready-journeys']){const panel=page.locator('#'+target);if(await panel.isVisible()&&await panel.getAttribute('open')===null)await panel.locator(':scope > summary').click();}}
const canonical=page=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {state:a.protocolSnapshot().state,held:a.heldView.snapshot(),sourceIndex:a.protocolSnapshot().sourceIndex};});
async function scene(page){await settle(page);return page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),g=a.refs.graph.getBoundingClientRect(),visible=e=>e.getClientRects().length&&!e.closest('[hidden]');const boxes=[...a.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(e=>{const r=e.getBoundingClientRect();return {id:e.dataset.actor||'dock:'+e.dataset.heldDock,left:r.left,right:r.right,top:r.top,bottom:r.bottom};}),overlaps=[],collisions=[];let pathSamples=0;for(let i=0;i<boxes.length;i++)for(let j=i+1;j<boxes.length;j++){const l=boxes[i],r=boxes[j];if(l.left<r.right-1&&l.right>r.left+1&&l.top<r.bottom-1&&l.bottom>r.top+1)overlaps.push([l.id,r.id]);}for(const line of a.refs.connections.querySelectorAll('.connection-line')){const matrix=line.getScreenCTM(),length=line.getTotalLength();if(!matrix)continue;for(let n=0;n<=Math.ceil(length);n++){const p=line.getPointAtLength(Math.min(n,length)),s=new DOMPoint(p.x,p.y).matrixTransform(matrix);pathSamples++;const b=boxes.find(b=>s.x>b.left+1&&s.x<b.right-1&&s.y>b.top+1&&s.y<b.bottom-1);if(b){collisions.push({pair:line.parentElement.dataset.pair,obstacle:b.id});break;}}}const smallTargets=[...a.querySelectorAll('#held-docks button,#held-objects button')].filter(visible).map(e=>{const r=e.getBoundingClientRect();return {width:r.width,height:r.height};}).filter(r=>r.width<43.9||r.height<43.9);return {width:innerWidth,geometry:a.refs.graph.dataset.heldGeometry,boxes,pathSamples,overlaps,collisions,smallTargets,outside:boxes.filter(b=>b.left<g.left-1||b.right>g.right+1||b.top<g.top-1||b.bottom>g.bottom+1),documentOverflow:document.documentElement.scrollWidth>innerWidth+1,coverage:a.heldView.snapshot().coverageStatus};});}
function clearScene(value,label){for(const key of ['overlaps','collisions','smallTargets','outside'])assert.deepEqual(value[key],[],label+' '+key);assert.equal(value.documentOverflow,false,label+' page overflow');assert.equal(value.coverage,'complete',label+' ownership coverage');assert.ok(value.pathSamples&&value.boxes.length,label+' rendered routes/cards');}
async function capture(page,name){const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false});report.screenshots.push({file,sha256:digest(path.join(out,file))});return file;}
async function focusedDestination(page,label){const result=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),n=document.activeElement,r=n.getBoundingClientRect();return {connected:n.isConnected,visible:r.width>0&&r.height>0&&!n.closest('[hidden]'),id:n.id,scenario:n.dataset.labScenario,selected:n.getAttribute('aria-pressed'),focusVisible:n.matches(':focus-visible'),current:a.labScenarioId};});assert.equal(result.connected,true,label);assert.equal(result.visible,true,label);assert.equal(result.focusVisible,true,label+' keyboard focus styling');assert.ok(result.id==='play'||result.scenario===result.current&&result.selected==='true',label+' meaningful selected journey or Play');return result;}
async function navigation(page){const result=[];for(const key of ['Enter','Space']){await choose(page,'lab-win-ntlmv2-domain');const related=page.locator('#related-journeys [data-compare-scenario="lab-win-negotiate-kerberos"]');await related.focus();await page.keyboard.press(key);assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),'lab-win-negotiate-kerberos');result.push({kind:'related',key,...await focusedDestination(page,'related '+key)});await choose(page,'lab-win-ntlmv2-domain');const ready=page.locator('#workspace-presets [data-lab-scenario="lab-win-ntlmv2-domain"]');await ready.focus();await page.keyboard.press(key);result.push({kind:'current-ready',key,...await focusedDestination(page,'ready '+key)});}await choose(page,'lab-net-radius-udp-radsec');const disappearing=page.locator('#related-journeys [data-compare-scenario="lab-net-radius11"]');await disappearing.focus();await page.keyboard.press('Enter');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),'lab-net-radius11');result.push({kind:'comparison-disappears',...await focusedDestination(page,'disappeared comparison')});return result;}
async function cryptoProfiles(page){
 const results=[];
 for(const id of ['lab-win-ntlmv2-domain','lab-win-negotiate-kerberos','lab-win-credssp-v6-ntlm','lab-win-credssp-v6-kerberos','lab-net-radius-udp-radsec','lab-krb-spake-success','lab-pake-spake2-success','lab-smb-nonjoined-kerberos']){
  await choose(page,id);
  const before=await canonical(page);
  await page.locator('#learning-detail-crypto').click();
  const row=await page.locator('#learning-profile-crypto').evaluate(panel=>{
   const detail=document.querySelector('auth-flow-studio').labModel.profile.cryptoDetail;
   return {text:panel.innerText,visible:panel.getClientRects().length>0,detail};
  });
  assert.equal(row.visible,true,id);
  assert.ok(!row.text.includes('[object Object]')&&!row.text.includes('undefined'),id+' usable crypto detail');
  if(typeof row.detail==='object'){
   assert.ok(row.text.includes(row.detail.mechanism),id+' mechanism');
   for(const fixture of row.detail.fixtures)assert.ok(row.text.includes(fixture),id+' fixture');
   if(row.detail.binding)for(const key of ['clientMagic','serverMagic','nonceHex','nonceBytes','publicKeyEncoding','subjectPublicKeyFixture','fixture']){
    assert.ok(row.text.includes(JSON.stringify(row.detail.binding[key])),id+' binding '+key);
   }
  }else assert.ok(row.text.includes(row.detail),id+' visible string profile');
  assert.deepEqual(await canonical(page),before,id+' presentation-only detail');
  results.push({id,structured:typeof row.detail==='object',text:row.text});
 }
 return results;
}
async function replayField(page,id,field){await choose(page,id);const control=page.locator('#attribute-index [data-index-attribute='+JSON.stringify(field)+']');await control.focus();await page.keyboard.press('Enter');await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());const rows=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return a.traceQueue.map(s=>({sourceIndex:s.sourceIndex,sourceStepId:s.sourceStepId,kind:s.traceKind,title:s.title}));});assert.ok(rows.some(r=>['derive','create','store','verify','decrypt'].includes(r.kind)),id+' actual local lifecycle');assert.ok(rows.every(r=>r.title&&!r.title.includes('undefined')),id+' labeled operations');if(id.startsWith('lab-pake-'))assert.ok(rows.some(r=>r.kind==='evict'),id+' supported cleanup action');const traced=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.seek(a.traceQueue,1,'review');return {state:a.protocolSnapshot().state,held:a.heldView.snapshot(),sourceIndex:a.protocolSnapshot().sourceIndex};});await page.evaluate(index=>{const a=document.querySelector('auth-flow-studio');a.clearAttribute();a.selectStep(index,false);},traced.sourceIndex);assert.deepEqual(await canonical(page),traced,id+' field replay equals same canonical full prefix');return {id,field,rows,canonicalPrefixEqual:true};}
async function icons(page,mode){return page.evaluate(async embedded=>{const result=[];for(const link of document.querySelectorAll('link[rel="icon"],link[rel="apple-touch-icon"]')){const image=new Image();image.src=link.href;await image.decode();if(embedded&&!link.href.startsWith('data:image/'))throw new Error('Standalone icon requires an external asset');result.push({rel:link.rel,type:link.type,width:image.naturalWidth,height:image.naturalHeight,embedded:link.href.startsWith('data:')});}if(result.length!==3)throw new Error('Supplied favicon set missing');return result;},mode!=='source-http');}
async function sourceStep(page,id){await page.evaluate(id=>{const a=document.querySelector('auth-flow-studio');const index=a.steps.findIndex(s=>s.id===id);if(index<0)throw new Error('Missing source event '+id);a.selectStep(index,false);},id);await settle(page);}
async function openHolding(page,actorId,artifactId,representationId){
 const holding=await page.evaluate(({actorId,artifactId,representationId})=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h=>h.actorId===actorId&&h.artifactId===artifactId&&h.representationId===representationId),{actorId,artifactId,representationId});assert.ok(holding,'Expected '+actorId+' '+representationId+' holding');
 const control=page.locator('#held-objects [data-holding-id='+JSON.stringify(holding.holdingId)+']');if(!await control.isVisible())await page.locator('#held-objects [data-held-actor='+JSON.stringify(actorId)+']').click();await control.click();await page.mouse.move(0,0);
 const summaries=page.locator('#held-inspector :is(.progressive-fields,.long-protocol-value):not([open]) > summary');while(await summaries.count())await summaries.first().click();
 return page.locator('#held-inspector').innerText();
}
async function radsec(page){
 const id='lab-net-radius-udp-radsec',records=[];
 for(const [suffix,receiver,code] of [['identity-backend','netServer','Access-Request'],['accept','netNas','Access-Accept']]){
  const send=id+':radsec:'+suffix,artifact=send+'-packet:g1';await choose(page,id);await sourceStep(page,send);
  const wire=await openHolding(page,receiver,artifact,'outer-wire');assert.ok(wire.includes('SYM(outer RadSec TLS1.3'),'Opaque outer TLS value is visible');
  await page.locator('#held-inspector [data-held-trace]').click();await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  const trace=await page.evaluate(send=>{const a=document.querySelector('auth-flow-studio');return a.traceQueue.filter(s=>s.sourceStepId===send).map(s=>({sourceStepId:s.sourceStepId,representation:s.heldRepresentationId,payload:s.payload}));},send);
  assert.ok(trace.some(row=>row.payload.some(p=>String(p.value).includes('SYM(outer RadSec TLS1.3'))),'Exact wire replay remains outer-protected');
  assert.ok(trace.every(row=>row.payload.every(p=>!String(p.value).includes('Code='+code))),'Exact wire replay never becomes a decoded RADIUS packet');
  await choose(page,id);await sourceStep(page,send+'-decode');const decoded=await openHolding(page,receiver,artifact,'radius-decoded');assert.ok(decoded.includes(code),'Endpoint decoded RADIUS result is visible');if(suffix==='identity-backend')assert.ok(decoded.includes('switch.corp.example'),'NAS identity survives outer TLS decode');
  records.push({send,decode:send+'-decode',receiver,wireRepresentation:'outer-wire',decodedRepresentation:'radius-decoded',wireText:wire,decodedText:decoded,trace});
 }
 return records;
}
async function winrm(page){
 const records=[];
 for(const id of ['lab-win-winrm-second-hop-denied','lab-win-winrm-credssp-second-hop']){
  await choose(page,id);await sourceStep(page,id+':winrm-session-result');const received=await canonical(page);
  assert.equal(Boolean(received.state.windows.clientKnowsSession),false,id+' opaque shell receipt is not usable');
  assert.equal(received.held.holdings.some(h=>h.actorId==='winClient'&&h.artifactId===id+':session'&&h.representationId==='plain'),false,id+' no decoded shell before recovery');
  await sourceStep(page,id+':winrm-session-accept');const accepted=await canonical(page);assert.equal(accepted.state.windows.clientKnowsSession,true);
  const shell=await openHolding(page,'winClient',id+':session','plain');assert.ok(shell.includes('ShellId'),'Decoded shell handle is actually visible');
  await sourceStep(page,id+':winrm-command-result');const outputReceipt=await canonical(page);assert.equal(Boolean(outputReceipt.state.windows.clientKnowsFailure),false,id+' protected output receipt reveals no failure');assert.equal(outputReceipt.held.holdings.some(h=>h.actorId==='winClient'&&h.artifactId===id+':winrm-command-result'&&h.representationId==='plain'),false);
  await sourceStep(page,id+':winrm-command-accept');const outputAccepted=await canonical(page);assert.equal(outputAccepted.state.windows.sessionEstablished,true,id+' first-hop shell survives');assert.equal(outputAccepted.state.windows.clientKnowsResourceResult,true);assert.equal(Boolean(outputAccepted.state.windows.clientKnowsFailure),id.endsWith('denied'));
  const text=await openHolding(page,'winClient',id+':winrm-command-result','plain');if(id.endsWith('denied'))assert.ok(text.includes('credential unavailable'),'Client actually sees the second-hop failure');
  const carriers=await page.evaluate(()=>document.querySelector('auth-flow-studio').steps.filter(s=>s.httpCarrier).map(s=>({id:s.id,...s.httpCarrier}))),pending=new Set();
  for(const carrier of carriers){if(carrier.kind==='request'){assert.equal(pending.has(carrier.requestId),false);pending.add(carrier.requestId);}else{assert.ok(pending.delete(carrier.requestId),'HTTP response belongs to an outstanding request');}}assert.equal(pending.size,0,id+' complete HTTP carrier pairing');
  const geometry=await scene(page);clearScene(geometry,id+' protected result');records.push({id,received:received.state.windows,accepted:accepted.state.windows,outputReceipt:outputReceipt.state.windows,outputAccepted:outputAccepted.state.windows,shellText:shell,outputText:text,carriers,geometry});
 }
 return records;
}
async function radsecFieldReplay(page){
 const id='lab-net-radius-udp-radsec';
 await choose(page,id);
 const decoded=await page.evaluate(()=>{
  const a=document.querySelector('auth-flow-studio');
  return a.steps.filter(step=>step.id.startsWith(a.labScenarioId+':radsec:')&&step.id.endsWith('-decode')).map(step=>({id:step.id,from:step.from,to:step.to,payload:step.payload,operations:step.attributeOperations}));
 });
 assert.equal(decoded.length,8,'All eight actual RadSec decode events exist');
 assert.equal(decoded.reduce((count,step)=>count+step.payload.length,0),53,'All 53 recovered fields remain represented');
 for(const step of decoded)for(const field of step.payload){
  const operation=step.operations.find(op=>op.attributeId===field.attributeId&&op.kind==='decrypt');
  assert.ok(operation,step.id+' '+field.name+' has actual decode work');
  assert.equal(operation.actorId,step.to);assert.equal(step.from,step.to);
  assert.equal(operation.representation,'radius-decoded');assert.deepEqual(operation.value,field.value);
  assert.equal(operation.sourceEventId,step.id);assert.ok(operation.instanceId&&operation.exactValueRef,'Decoded value has exact provenance');
 }
 const replays=[];
 for(const [suffix,name] of [['identity-backend','NAS-Identifier'],['serverflight-backend','EAP-Message'],['accept','Response Authenticator']]){
  const step=decoded.find(step=>step.id===id+':radsec:'+suffix+'-decode');
  const field=step.payload.find(field=>field.name===name);assert.ok(field,'Decoded '+name+' exists');
  await choose(page,id);await page.locator('#learning-detail-fields').click();
  await sourceStep(page,step.id);
  await page.locator('#attribute-index [data-index-attribute='+JSON.stringify(field.attributeId)+']').focus();
  await page.keyboard.press('Enter');await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  const replay=page.locator('#attribute-focus [data-trace-play]');assert.ok(await replay.isEnabled(),name+' Replay path is enabled');
  const detail=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {text:a.refs.inspector.innerText,rows:a.traceQueue.map(row=>({sourceIndex:row.sourceIndex,sourceStepId:row.sourceStepId,kind:row.traceKind,from:row.from,to:row.to,payload:row.payload}))};});
  assert.ok(detail.rows.some(row=>row.sourceStepId===step.id&&row.kind==='decrypt'&&row.from===step.to&&row.to===step.to),name+' replays at actual receiver-local decode');
  assert.ok(!detail.text.includes('This is configured context; it is not transmitted'),name+' is not mislabeled as untransmitted configuration');
  await replay.click();assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'playing',name+' Replay path starts playback');
  const focused=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.player.pause();a.player.seek(a.traceQueue,1,'review');return {state:a.protocolSnapshot().state,held:a.heldView.snapshot(),sourceIndex:a.protocolSnapshot().sourceIndex};});
  await page.evaluate(index=>{const a=document.querySelector('auth-flow-studio');a.clearAttribute();a.selectStep(index,false);},focused.sourceIndex);
  assert.deepEqual(await canonical(page),focused,name+' replay has the exact canonical prefix');
  replays.push({sourceStepId:step.id,attributeId:field.attributeId,name,receiver:step.to,value:field.value,rows:detail.rows,inspectorText:detail.text,canonicalPrefixEqual:true});
 }
 return {decodedEvents:decoded.length,decodedOccurrences:53,events:decoded,replays};
}
async function smbTicketExplanations(page){
 const records=[];
 for(const id of ['lab-smb-nonjoined-kerberos','lab-smb-nonjoined-signature-rejected','lab-smb-nonjoined-encryption-rejected','lab-smb-multichannel-binding-success','lab-smb-multichannel-binding-rejected']){
  await choose(page,id);
  const keys=await page.evaluate(()=>{
   const a=document.querySelector('auth-flow-studio'),objects=a.labModel.smbInventory.artifacts;
   return Object.fromEntries(['ticket-key','initiator-subkey','session-key'].map(key=>[key,objects.find(object=>object.key===key)]));
  });
  for(const key of ['ticket-key','initiator-subkey','session-key'])assert.ok(keys[key],id+' '+key);
  assert.equal(new Set(Object.values(keys).map(key=>key.artifactId)).size,3,id+' keys remain distinct');
  assert.equal(keys['ticket-key'].creator,'smbDC');assert.equal(keys['initiator-subkey'].creator,'smbClient');assert.equal(keys['session-key'].creator,'smbServer');
  await page.locator('#attribute-index [data-index-attribute='+JSON.stringify(keys['ticket-key'].attributeId)+']').focus();
  await page.keyboard.press('Enter');await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());
  const explanation=await page.evaluate(()=>document.querySelector('auth-flow-studio').refs.inspector.innerText);
  for(const phrase of ['KDC-issued ticket session key','client AP-REQ initiator subkey','server AP-REP acceptor subkey','server-selected acceptor subkey is the exported SMB mechanism key'])assert.ok(explanation.includes(phrase),id+' truthful ticket-key explanation: '+phrase);
  assert.ok(!explanation.includes('client-selected GSS subkey used as the SMB session key'),id+' no stale exported-key claim');
  records.push({id,keys:Object.fromEntries(Object.entries(keys).map(([key,value])=>[key,{artifactId:value.artifactId,creator:value.creator,value:value.value}])),explanation});
 }
 return records;
}
async function windowsResourceResults(page){
 const records=[];
 for(const id of ['lab-win-winrm-credssp-second-hop','lab-win-winrm-credssp-http','lab-win-winrm-resource-denied','lab-win-rdp-normal','lab-win-rdp-restricted-admin','lab-win-rdp-remote-credential-guard']){
  await choose(page,id);await sourceStep(page,id+':resource-result');
  const received=await canonical(page);
  assert.equal(received.state.windows.resourceResultReceived,true);
  assert.equal(Boolean(received.state.windows.serverKnowsResourceResult),false,id+' H cannot know opaque resource output');
  assert.equal(Boolean(received.state.windows.serverKnowsFailure),false,id+' H has not accepted a denial');
  assert.equal(received.held.holdings.some(h=>h.actorId==='winHost'&&h.artifactId===id+':resource-result'&&h.representationId==='plain'),false);
  const wire=await openHolding(page,'winHost',id+':resource-result','wire');assert.ok(wire.includes('Protect('),id+' actual protected result is visible');
  await sourceStep(page,id+':resource-result-accept');const accepted=await canonical(page);
  assert.equal(accepted.state.windows.resourceResultAccepted,true);assert.equal(accepted.state.windows.serverKnowsResourceResult,true);
  assert.equal(accepted.state.windows.acceptedResourceResult,id+':resource-result');assert.equal(accepted.state.windows.sessionEstablished,true);
  const denied=id==='lab-win-winrm-resource-denied';assert.equal(accepted.state.windows.serverResourceResult,denied?'resource-denied':'success');
  assert.equal(Boolean(accepted.state.windows.serverKnowsFailure),denied);
  const plain=await openHolding(page,'winHost',id+':resource-result','plain');
  assert.ok(accepted.held.observations.some(o=>o.artifactId===id+':resource-result'&&o.actorId==='winHost'&&o.kind==='verification'),id+' H has actual verification history');
  const forwarded=id.startsWith('lab-win-winrm-');
  let provenance=null,output=null;
  if(forwarded){
   assert.ok(accepted.held.holdings.some(h=>h.actorId==='winHost'&&h.artifactId===id+':delegated-credentials'&&h.representationId==='plain'),id+' prior disclosure persists');
   await sourceStep(page,id+':winrm-command-result');
   provenance=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),objects=a.labModel.windowsInventory.artifacts;
    const result=objects.find(o=>o.artifactId===a.labScenarioId+':resource-result'),output=objects.find(o=>o.artifactId===a.labScenarioId+':winrm-command-result');
    const stages=['resource-result','resource-result-accept','winrm-command-result'].map(stage=>a.steps.findIndex(step=>step.id===a.labScenarioId+':'+stage));
    return {stages,sourceValue:result.value,outputValue:output.value,derivedFrom:output.derivedFrom,valueProvenance:output.valueProvenance,stepProvenance:a.steps[stages[2]].valueProvenance};
   });
   assert.ok(provenance.stages[0]<provenance.stages[1]&&provenance.stages[1]<provenance.stages[2]);
   assert.deepEqual(provenance.outputValue,provenance.sourceValue,id+' forwarded value is the accepted exact output');
   assert.deepEqual(provenance.derivedFrom,[id+':resource-result']);
   assert.deepEqual(provenance.valueProvenance,{artifactId:id+':resource-result',representationId:'plain',exactValueRef:id+':resource-result:plain',sourceEventId:id+':resource-result-accept'});
   assert.deepEqual(provenance.stepProvenance,provenance.valueProvenance);
   await sourceStep(page,id+':winrm-command-accept');output=await openHolding(page,'winClient',id+':winrm-command-result','plain');
   assert.ok(output.includes(provenance.sourceValue),id+' C sees the genuinely accepted downstream value');
  }
  records.push({id,received:received.state.windows,accepted:accepted.state.windows,wireText:wire,plainText:plain,forwarded,provenance,outputText:output});
 }
 return records;
}
async function windowsAesContexts(page){
 const records=[];
 for(const id of ['lab-win-negotiate-kerberos','lab-win-credssp-v6-kerberos','lab-win-credssp-binding-rejected','lab-win-credssp-logon-denied','lab-win-rdp-normal','lab-win-rdp-restricted-admin','lab-win-rdp-remote-credential-guard','lab-win-winrm-second-hop-denied','lab-win-winrm-credssp-second-hop','lab-win-winrm-credssp-http','lab-win-winrm-resource-denied']){
  await choose(page,id);await sourceStep(page,id+':ap-reply');
  const host=await canonical(page),key=id+':acceptor-subkey';
  assert.equal(host.state.windows.hostCompletedContextKey,key);
  assert.ok(host.held.holdings.some(h=>h.actorId==='winHost'&&h.artifactId===key&&h.representationId==='plain'));
  assert.equal(host.held.holdings.some(h=>h.actorId==='winClient'&&h.artifactId===key&&h.representationId==='plain'),false);
  const carrier=await page.evaluate(()=>{
   const a=document.querySelector('auth-flow-studio'),artifact=a.labScenarioId+':ap-reply';
   return a.steps.find(step=>step.from==='winHost'&&step.to==='winClient'&&step.attributeOperations.some(op=>op.instanceId===artifact&&op.kind==='receive'))?.id;
  });
  assert.ok(carrier,id+' actual AP-REP carrier');await sourceStep(page,carrier);const received=await canonical(page);
  assert.equal(received.held.holdings.some(h=>h.actorId==='winClient'&&h.artifactId===key&&h.representationId==='plain'),false,id+' AP-REP receipt grants no subkey');
  assert.notEqual(received.state.windows.clientCompletedContextKey,key);
  const wire=await openHolding(page,'winClient',id+':ap-reply','wire');
  await sourceStep(page,id+':mutual-verify');const accepted=await canonical(page);
  assert.equal(accepted.state.windows.clientCompletedContextKey,key);
  const keyText=await openHolding(page,'winClient',key,'plain');
  const layers=await page.evaluate(()=>document.querySelector('auth-flow-studio').steps.map(step=>({id:step.id,layers:step.layers})));
  const early=layers.find(step=>step.id===id+':last-token-binding'),reverse=layers.find(step=>step.id===id+':server-binding');
  if(early){
   assert.ok(early.layers.some(layer=>layer.keyRef===id+':mechanism-key'&&layer.acceptorSubkey===false),id+' early client binding uses available initiator key');
   assert.ok(reverse.layers.some(layer=>layer.keyRef===key&&layer.acceptorSubkey===true),id+' reverse binding uses completed context');
   const authinfo=layers.find(step=>step.id===id+':authinfo-receive');
   if(authinfo)assert.ok(authinfo.layers.some(layer=>layer.keyRef===key&&layer.acceptorSubkey===true),id+' authInfo follows completed context');
  }
  if(id==='lab-win-winrm-second-hop-denied'){
   for(const stage of ['winrm-shell-request','winrm-session-result','winrm-command-request','winrm-command-result'])assert.ok(layers.find(step=>step.id===id+':'+stage).layers.some(layer=>layer.keyRef===key),id+' '+stage+' uses accepted context');
  }else if(id.startsWith('lab-win-winrm-')){
   for(const stage of ['winrm-shell-request','winrm-command-request','winrm-command-result'])assert.ok(layers.find(step=>step.id===id+':'+stage).layers.some(layer=>layer.keyRef===id+':tls-inner-key'),id+' '+stage+' retains inner TLS body protection');
  }
  records.push({id,carrier,key,host:host.state.windows,received:received.state.windows,accepted:accepted.state.windows,wireText:wire,keyText,layers});
 }
 return records;
}
let browser,server;
try{
 const module=await import(pathToFileURL(path.resolve(process.env.PLAYWRIGHT_MODULE||path.join(root,'tools/verification/native-qa/node_modules/playwright-core/index.mjs'))).href);
 const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.ico':'image/x-icon','.png':'image/png'};
 server=http.createServer((req,res)=>{const name=decodeURIComponent(new URL(req.url,'http://localhost').pathname),file=path.resolve(root,'.'+(name==='/'?'/index.html':name));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile()){res.writeHead(404);res.end();return;}res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(res);});await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 browser=await module.chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage']});report.browser=browser.version();
 for(const mode of ['source-http','standalone-http','standalone-file']){
  const target=mode==='standalone-file'?pathToFileURL(path.join(root,'dist/auth-flow-studio.html')).href:origin+'/'+(mode==='source-http'?'':'dist/auth-flow-studio.html');
  const context=await browser.newContext({viewport:{width:1920,height:1200},bypassCSP:false}),page=await context.newPage();page.setDefaultTimeout(20000);
  const record={mode,passed:false,csp:[],errors:[],requests:[],smb:[]};report.modes.push(record);
  page.on('pageerror',e=>record.errors.push(String(e)));page.on('request',r=>record.requests.push(r.url()));await page.exposeBinding('__reviewCsp',(_,event)=>record.csp.push(event));await page.addInitScript(()=>document.addEventListener('securitypolicyviolation',e=>void window.__reviewCsp({directive:e.effectiveDirective,blocked:e.blockedURI})));
  try{
   await page.goto(target,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('auth-flow-studio')?.heldView);record.icons=await icons(page,mode);
   for(const [id,expected] of cases){await choose(page,id);assert.ok(await page.locator('#learning-profile').isVisible());const initial=await canonical(page);await page.locator('#play').click();await page.locator('#play').click();assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'paused');await page.locator('#reset').click();assert.deepEqual(await canonical(page),initial,id+' reset');const geometry=[];for(const width of id==='lab-smb-nonjoined-kerberos'||id==='lab-smb-multichannel-binding-success'?[1920,1480,390]:[1920]){await page.setViewportSize({width,height:1200});await page.locator('#reset').click();const start=await scene(page);clearScene(start,id+' initial '+width);await page.locator('#seek').focus();await page.keyboard.press('End');const end=await canonical(page),state=end.state.smb;assert.equal(state.clientJoined,false);assert.equal(state.localDesktopIdentity,'WORKGROUPPC\\bob');assert.equal(state.networkIdentity,'CORP\\alice');for(const [key,value] of Object.entries(expected))assert.deepEqual(state[key],value,id+' '+key);const terminal=await scene(page);clearScene(terminal,id+' terminal '+width);geometry.push({width,start,terminal});if(mode==='source-http'&&(id==='lab-smb-nonjoined-kerberos'||id==='lab-smb-multichannel-binding-success'))await capture(page,mode+'-'+id+'-'+width);}record.smb.push({id,expected,geometry,passed:true});}
   await page.setViewportSize({width:1480,height:1100});record.navigation=await navigation(page);record.cryptoProfiles=await cryptoProfiles(page);record.fieldReplays=[];
   record.smbTicketExplanations=await smbTicketExplanations(page);
   for(const field of ['kspInitialKeyKey','kspClientSharedK','kspClientReplyKeyKey','kspTgtSessionKey'])record.fieldReplays.push(await replayField(page,'lab-krb-spake-success',field));
   record.fieldReplays.push(await replayField(page,'lab-pake-spake2-success','pake_x'));
   record.radsec=await radsec(page);
   record.radsecFieldReplay=await radsecFieldReplay(page);
   record.winrm=await winrm(page);
   record.windowsResourceResults=await windowsResourceResults(page);
   record.windowsAesContexts=await windowsAesContexts(page);
   await choose(page,'lab-win-winrm-resource-denied');await sourceStep(page,'lab-win-winrm-resource-denied:winrm-command-accept');await openHolding(page,'winClient','lab-win-winrm-resource-denied:winrm-command-result','plain');
   await capture(page,mode+'-winrm-protected-command-result');assert.deepEqual(record.errors,[],mode+' runtime errors');assert.deepEqual(record.csp,[],mode+' CSP violations');assert.ok(record.requests.every(url=>mode==='standalone-file'?url===target:url.startsWith(origin+'/')),mode+' no external application requests');record.passed=true;
  }finally{await context.close();}
 }
 report.identityAfter=identity();assert.deepEqual(report.identityAfter,report.identity,'Source/artifact remain frozen');report.passed=report.modes.length===3&&report.modes.every(m=>m.passed);
}catch(error){report.failures.push({message:error.message,stack:error.stack});process.exitCode=1;}
finally{if(browser)await browser.close();if(server)await new Promise(r=>server.close(r));fs.writeFileSync(path.join(out,'review-corrections-recheck-native-status.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,scope:report.scope,modes:report.modes.map(m=>({mode:m.mode,passed:m.passed,smb:m.smb.length})),failures:report.failures,report:path.join(out,'review-corrections-recheck-native-status.json')},null,2));}
