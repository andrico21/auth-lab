#!/usr/bin/env node
/** Exercise Code3 R2/R3 through the unmodified emitted inline IIFE. Only the
 * deterministic DOM/clock harness is imported; application modules are not.
 * These checks establish handler/value behaviour, never native acceptance.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv.includes('--help')||process.argv.includes('-h')){
  console.log('Usage: node tools/verification/code3-environment-bundle-check.mjs [project-directory]\nBuild first. Executes the actual dist/auth-flow-studio.html inline IIFE.\nChecks Code3 R2/R3 via the real Apply/Reset handlers in AD and Keycloak bridge.\nEvidence: AUTH_LAB_QA_EVIDENCE_DIR, or docs/verification. Native browser: false.');
  process.exit(0);
}
const project=path.resolve(process.argv[2]||path.join(here,'../..'));
const evidenceDir=path.resolve(process.env.AUTH_LAB_QA_EVIDENCE_DIR||path.join(project,'docs/verification'));
fs.mkdirSync(evidenceDir,{recursive:true});
const artifactPath=path.join(project,'dist/auth-flow-studio.html');
const artifact=fs.readFileSync(artifactPath),html=artifact.toString('utf8');
const report={kind:'code3-environment-emitted-bundle-check',nativeBrowser:false,timestamp:new Date().toISOString(),project,
  artifact:{path:artifactPath,bytes:artifact.length,sha256:createHash('sha256').update(artifact).digest('hex')},
  contract:{realmLimit:254,realmLengths:[254,255,2048],singleRealmServiceNames:'Unqualified, or a qualifier exactly matching the candidate account realm.'},
  limits:['Unmodified emitted IIFE; deterministic DOM harness and animation clock.','No native browser, rendered layout, native keyboard accessibility or CSP enforcement acceptance.','No live AD/Keycloak interoperability or cryptographic certification.'],cases:[]};
const modelData=model=>JSON.stringify({definitions:model.definitions(),initialState:model.initialState,steps:model.steps(),actors:model.actors(),protocolValues:model.protocolValues});
const replyValue=(target,realm)=>'EncryptedData(key=tgt-session:01, EncTGSRepPart for '+target+'; srealm='+realm+')';
const field=(step,id)=>step.payload.find(item=>item.attributeId===id)?.value;
const scenarios=[['lab-ad-first-sign-in','cifs/review.corp.example'],['lab-kc-kerberos-sso','HTTP/review.corp.example']];
let harness;
function input(app,key){const node=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(node,'Editable '+key+' field exists');return node;}
function enter(app,key,value){input(app,key).value=value;}
function apply(app){app.querySelector('#environment-apply').click();}
function assertSuccess(app,previousRevision,expectedTarget){
  assert.equal(app.refs['environment-errors'].hidden,true,'Accepted Apply hides the inline error');
  assert.equal(app.refs['environment-errors'].textContent,'');
  assert.equal(app.runtimeEnvironment.revision,previousRevision+1,'A successful Apply commits exactly one new revision');
  assert.equal(app.runtimeEnvironment.applied.servicePrincipal,expectedTarget,'The committed service name is unqualified');
  assert.notEqual(input(app,'kerberosRealm').getAttribute('aria-invalid'),'true');
  assert.notEqual(input(app,'servicePrincipal').getAttribute('aria-invalid'),'true');
  assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);
  assert.equal(app.visibleIndex,0);assert.equal(app.index,0);assert.equal(app.visited.size,0);
}
function startExistingPlayback(app,focused){
  if(focused){
    app.selectAttribute('adTGSReply',false);
    const send=app.traceQueue.findIndex(step=>step.sourceStepId.endsWith('-service-tgs-reply')&&step.traceKind==='send');
    assert.ok(send>=0);app.selectStep(send,true);
  }else{
    const index=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));
    assert.ok(index>=0);app.selectStep(index,true);
  }
  harness.clock.advance(500);app.visited.add('retained-before-rejected-apply');
  assert.equal(app.player.status,'playing');assert.ok(app.player.queue.length>0);
}
function committedSnapshot(app){
  const protocol=app.protocolSnapshot();
  return {applied:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision,active:app.runtimeEnvironment.active,
    model:app.labModel,modelData:modelData(app.labModel),memo:app.contextModelMemo,steps:app.steps,traceQueue:app.traceQueue,
    queue:app.player.queue,visited:app.visited,values:JSON.stringify({
      applied:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision,active:app.runtimeEnvironment.active,
      index:app.index,traceIndex:app.traceIndex,visibleIndex:app.visibleIndex,attributeSelection:app.attributeSelection,
      visited:[...app.visited],inspection:app.inspection,player:app.player.snapshot(),handle:app.player.handle,lastTime:app.player.lastTime,
      queue:app.player.queue,traceQueue:app.traceQueue,steps:app.steps,
      sourceIndex:protocol.sourceIndex,state:protocol.state,instances:protocol.instances,
      packet:{hidden:app.refs.packet.hidden,name:app.refs['packet-name'].textContent,value:app.refs['packet-value'].textContent},
      environmentStatus:app.refs['environment-status'].textContent,status:app.refs.status.textContent})};
}
function assertRejected(app,before,key,expectedMessage){
  const errors=app.refs['environment-errors'],node=input(app,key);
  assert.equal(errors.hidden,false,'Rejected Apply exposes a recoverable inline error');
  assert.equal(errors.getAttribute('role'),'alert');assert.ok(errors.textContent.length>0);
  assert.match(errors.textContent,expectedMessage);
  assert.equal(node.getAttribute('aria-invalid'),'true','The rejected field is identified');
  assert.ok((node.getAttribute('aria-describedby')||'').split(/\s+/).includes('environment-errors'));
  assert.equal(node.getAttribute('aria-errormessage'),'environment-errors','The invalid field references its displayed error');
  assert.strictEqual(app.runtimeEnvironment.applied,before.applied,'Rejection keeps the exact committed context');
  assert.equal(app.runtimeEnvironment.revision,before.revision);assert.equal(app.runtimeEnvironment.active,before.active);
  assert.strictEqual(app.labModel,before.model,'Rejection keeps the exact applied fixture');
  assert.equal(modelData(app.labModel),before.modelData);assert.strictEqual(app.contextModelMemo,before.memo);
  assert.strictEqual(app.steps,before.steps);assert.strictEqual(app.traceQueue,before.traceQueue);
  assert.strictEqual(app.player.queue,before.queue);assert.strictEqual(app.visited,before.visited);
  assert.equal(committedSnapshot(app).values,before.values,'Playback, indices, attribute selection, visited links, packet and complete reconstructed state are unchanged');
  return errors.textContent;
}
function assertIdentity(app,id,target,realm){
  app.clearAttribute();
  const operations=app.steps.flatMap(step=>step.attributeOperations);
  const requests=operations.filter(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname');
  assert.ok(requests.some(operation=>operation.instanceId.startsWith('target:service:')),'An actual target-service request is transmitted');
  for(const request of requests)assert.equal(request.value,request.instanceId.startsWith('target:host:')?'host/ws01.a.example':target,'Each transmitted sname retains its own service identity');
  for(const operation of operations){
    if(operation.attributeId==='adSPN')assert.ok(!operation.value.includes('@'),'PrincipalName values omit the realm qualifier');
    if(operation.attributeId==='adRealm'||operation.attributeId==='adClientRealm'||operation.attributeId==='adTicketRealm')assert.equal(operation.value,realm,'Request, client and ticket realm fields agree');
    if(operation.attributeId==='adTicketTarget')assert.equal(operation.value,operation.instanceId==='ticket:host:01'?'host/ws01.a.example':target);
    if(operation.attributeId==='adTGSReply')assert.equal(operation.value,replyValue(operation.instanceId==='reply:tgs:host:result'?'host/ws01.a.example':target,realm));
  }
  assert.equal(app.definition('adSPN').example,target);assert.equal(app.definition('adTicketRealm').example,realm);
  const replyIndex=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));assert.ok(replyIndex>=0);
  app.selectStep(replyIndex,false);const full=app.protocolSnapshot(),expected=replyValue(target,realm);
  assert.equal(field(app.currentStep,'adTGSReply'),expected);assert.ok(app.refs.inspector.textContent.includes(expected));
  assert.equal(full.state.proofs.tgsService.target,target);assert.equal(full.state.proofs.tgsService.realm,realm);
  assert.equal(full.state.issued.service.target,target);assert.equal(full.state.issued.service.crealm,realm);
  assert.equal(full.state.credentials.service,undefined,'The sent reply precedes successful validation/cache insertion');
  app.selectAttribute('adTGSReply',false);
  const sendIndex=app.traceQueue.findIndex(step=>step.sourceStepId.endsWith('-service-tgs-reply')&&step.traceKind==='send');assert.ok(sendIndex>=0);
  app.selectStep(sendIndex,false);const send=app.currentStep;
  assert.equal(send.sourceIndex,replyIndex);assert.equal(field(send,'adTGSReply'),expected);
  assert.ok(app.querySelector('#protocol-instance-list').textContent.includes(expected));
  assert.deepEqual(app.protocolSnapshot().state,full.state,'Focused Send retains the complete same source-prefix state');
  app.player.seek([send],.3,'attribute-step');
  assert.equal(app.player.snapshot().packet.value,expected);assert.equal(app.refs.packet.hidden,false);
  const compact=app.refs['packet-value'].textContent;assert.ok(compact.length>0&&expected.startsWith(compact.replace(/…$/,'')));
  app.clearAttribute();app.selectStep(app.steps.length-1,false);const last=app.protocolSnapshot().state;
  for(const collection of ['issued','credentials']){
    assert.equal(last[collection].service.target,target);assert.equal(last[collection].service.crealm,realm);
  }
  assert.equal(last.proofs.tgsService.target,target);assert.equal(last.proofs.tgsService.realm,realm);
  if(id==='lab-ad-first-sign-in'){
    assert.equal(last.credentials.host.target,'host/ws01.a.example');assert.equal(last.credentials.host.crealm,realm);
    assert.equal(last.proofs.tgsHost.target,'host/ws01.a.example');assert.equal(last.proofs.tgsHost.realm,realm);
  }
  return {target,realm,transmittedRequestNames:requests.map(request=>request.value),proofTarget:last.proofs.tgsService.target,
    issuedTarget:last.issued.service.target,cachedTarget:last.credentials.service.target,fullReply:expected,
    focusedSend:{sourceIndex:send.sourceIndex,value:field(send,'adTGSReply'),packetValue:expected,compactPacketLabel:compact},
    ...(id==='lab-ad-first-sign-in'?{independentHostTarget:last.credentials.host.target}:{})};
}
try{
  const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
  assert.equal(scripts.length,1,'The artifact has one inline application script');
  const {installHarness}=await import(pathToFileURL(path.join(project,'tests/dom-harness.mjs')).href);
  harness=installHarness();new vm.Script(scripts[0],{filename:'auth-flow-studio.emitted.js'}).runInThisContext();
  const Klass=harness.registry.get('auth-flow-studio');assert.ok(Klass,'The emitted IIFE registers the real application');
  for(const [id,target] of scenarios)for(const condition of ['realm-254','realm-255','realm-2048','unqualified-service','matching-qualifier','conflicting-qualifier']){
    const result={id,condition};let app;
    try{
      app=new Klass();harness.document.body.appendChild(app);app.connectedCallback();app.selectLabScenario(id);
      const base=app.baseLabModel,baseBefore=modelData(base),initialBefore=modelData(app.labModel);
      const priorTarget=target.replace('review','before'),revision=app.runtimeEnvironment.revision;
      enter(app,'kerberosRealm','BASE.EXAMPLE');enter(app,'servicePrincipal',priorTarget);apply(app);
      assertSuccess(app,revision,priorTarget);
      const heldModel=app.labModel,heldBefore=modelData(heldModel);
      startExistingPlayback(app,condition==='realm-2048'||condition.includes('qualifier'));
      const before=committedSnapshot(app);let realm='CORP.EXAMPLE',submitted=target;
      if(condition.startsWith('realm-'))realm='R'.repeat(Number(condition.slice(6)));
      if(condition==='matching-qualifier')submitted=target+'@'+realm;
      if(condition==='conflicting-qualifier'){realm='';submitted=target+'@OTHER.EXAMPLE';}
      enter(app,'kerberosRealm',realm);enter(app,'servicePrincipal',submitted);apply(app);
      if(condition==='realm-255'||condition==='realm-2048'){
        result.rejection={draftRealmLength:realm.length,message:assertRejected(app,before,'kerberosRealm',/254/),committedRealm:app.runtimeEnvironment.applied.kerberosRealm,playbackUnchanged:true};
        realm='CORP.EXAMPLE';enter(app,'kerberosRealm',realm);apply(app);
        assertSuccess(app,before.revision,target);result.correctedApplyWithoutReset=true;
      }else if(condition==='conflicting-qualifier'){
        result.rejections=[{draftRealm:'',effectiveRealm:'A.EXAMPLE',message:assertRejected(app,before,'servicePrincipal',/cross-realm/i)}];
        assert.match(app.refs['environment-errors'].textContent,/A\.EXAMPLE/);
        realm='CORP.EXAMPLE';enter(app,'kerberosRealm',realm);apply(app);
        result.rejections.push({draftRealm:realm,effectiveRealm:realm,message:assertRejected(app,before,'servicePrincipal',/cross-realm/i)});
        assert.match(app.refs['environment-errors'].textContent,/CORP\.EXAMPLE/);
        submitted=target+'@'+realm;enter(app,'servicePrincipal',submitted);apply(app);
        assertSuccess(app,before.revision,target);result.correctedApplyWithoutReset=true;
      }else assertSuccess(app,before.revision,target);
      if(submitted.includes('@'))assert.equal(app.runtimeEnvironment.draft.servicePrincipal,submitted,'The draft retains the operator’s principal notation');
      assert.equal(app.runtimeEnvironment.applied.kerberosRealm,realm);
      assert.notStrictEqual(app.labModel,heldModel,'Accepted input reconstructs a fresh model');
      result.acceptedIdentity=assertIdentity(app,id,target,realm);
      assert.equal(modelData(heldModel),heldBefore,'The preceding applied fixture is never mutated');
      assert.equal(modelData(base),baseBefore,'The immutable source registry is unchanged');
      app.querySelector('#environment-reset').click();
      assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'');assert.equal(app.runtimeEnvironment.applied.servicePrincipal,'');
      assert.equal(app.runtimeEnvironment.draft.kerberosRealm,'');assert.equal(app.runtimeEnvironment.draft.servicePrincipal,'');
      assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);
      assert.equal(app.visibleIndex,0);assert.equal(modelData(app.labModel),initialBefore,'Reset restores the complete original example fixture');
      assert.equal(modelData(base),baseBefore);assert.equal(modelData(heldModel),heldBefore);
      result.baseAndPriorFixturesUnchanged=true;result.resetRestores=true;result.passed=true;
    }catch(error){result.passed=false;result.reason=String(error.stack||error);}
    finally{if(app){app.disconnectedCallback();harness.document.body.removeChild(app);}harness.clock.frames.clear();harness.clock.timers.clear();}
    report.cases.push(result);
  }
  report.passed=report.cases.length===12&&report.cases.every(result=>result.passed);
  if(!report.passed)process.exitCode=1;
}catch(error){report.passed=false;report.reason=String(error.stack||error);process.exitCode=1;}
finally{
  if(harness){harness.clock.frames.clear();harness.clock.timers.clear();}
  fs.writeFileSync(path.join(evidenceDir,'code3-environment-bundle-status.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({passed:report.passed,caseCount:report.cases.length,htmlSha256:report.artifact.sha256,nativeBrowser:false,
    reason:report.reason?.split('\n')[0],failures:report.cases.filter(result=>!result.passed).map(result=>({id:result.id,condition:result.condition,reason:result.reason.split('\n')[0]}))},null,2));
}
