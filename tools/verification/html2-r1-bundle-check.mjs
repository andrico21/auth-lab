#!/usr/bin/env node
/** Exercise the unmodified emitted IIFE for html2 review R1. The deterministic
 * DOM harness verifies handlers/values, never native layout or CSP enforcement.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv.includes('--help')||process.argv.includes('-h')){
  console.log('Usage: node tools/verification/html2-r1-bundle-check.mjs [project-directory]\nBuild first. Executes the actual dist/auth-flow-studio.html inline script.\nEvidence: AUTH_LAB_QA_EVIDENCE_DIR, or docs/verification. Native browser: false.');
  process.exit(0);
}
const project=path.resolve(process.argv[2]||path.join(here,'../..'));
const evidenceDir=path.resolve(process.env.AUTH_LAB_QA_EVIDENCE_DIR||path.join(project,'docs/verification'));
fs.mkdirSync(evidenceDir,{recursive:true});
const artifactPath=path.join(project,'dist/auth-flow-studio.html');
const artifact=fs.readFileSync(artifactPath),html=artifact.toString('utf8');
const report={kind:'html2-r1-emitted-bundle-context-check',nativeBrowser:false,timestamp:new Date().toISOString(),project,
  artifact:{path:artifactPath,bytes:artifact.length,sha256:createHash('sha256').update(artifact).digest('hex')},
  limits:['Unmodified emitted IIFE, deterministic DOM harness and animation clock.','No native browser, visual layout, accessibility or CSP enforcement acceptance.','No live AD/Keycloak interoperability or cryptographic certification.'],cases:[]};
const modelData=model=>JSON.stringify({definitions:model.definitions(),initialState:model.initialState,steps:model.steps(),actors:model.actors(),protocolValues:model.protocolValues});
const replyValue=(target,realm)=>'EncryptedData(key=tgt-session:01, EncTGSRepPart for '+target+'; srealm='+realm+')';
const field=(step,id)=>step.payload.find(item=>item.attributeId===id)?.value;
let harness;
try{
  const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
  assert.equal(scripts.length,1,'The built artifact has one inline application script');
  const {installHarness}=await import(pathToFileURL(path.join(project,'tests/dom-harness.mjs')).href);
  harness=installHarness();
  new vm.Script(scripts[0],{filename:'auth-flow-studio.emitted.js'}).runInThisContext();
  const Klass=harness.registry.get('auth-flow-studio');assert.ok(Klass,'The actual emitted app registers');
  for(const [id,target] of [['lab-ad-first-sign-in','cifs/other.corp.test'],['lab-kc-kerberos-sso','HTTP/other.corp.test']]){
    for(const realm of ['A.EXAMPLE','CORP.EXAMPLE']){
      const result={id,target,realm,mode:realm==='A.EXAMPLE'?'service-only':'realm-and-service'};let app;
      try{
        app=new Klass();harness.document.body.appendChild(app);app.connectedCallback();app.selectLabScenario(id);
        const original=app.labModel,before=modelData(original),revision=app.runtimeEnvironment.revision;
        app.selectStep(app.steps.length-1,false);app.player.play(app.steps,'demo');app.visited.add('prior-context-link');
        const enter=(key,value)=>{const input=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(input,'Editable '+key);input.value=value;};
        enter('servicePrincipal',target);if(realm!=='A.EXAMPLE')enter('kerberosRealm',realm);
        app.querySelector('#environment-apply').click();
        assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.runtimeEnvironment.revision,revision+1);
        assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);assert.equal(app.index,0);assert.equal(app.attributeSelection,null);assert.equal(app.visited.size,0);
        assert.notStrictEqual(app.labModel,original,'Apply reconstructs a fresh model');
        const replyIndex=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));assert.ok(replyIndex>=0);
        app.selectStep(replyIndex,false);const full=app.protocolSnapshot(),expected=replyValue(target,realm);
        assert.equal(field(app.currentStep,'adTGSReply'),expected);assert.ok(app.refs.inspector.textContent.includes(expected));
        assert.equal(full.state.proofs.tgsService.target,target);assert.equal(full.state.proofs.tgsService.realm,realm);
        assert.equal(full.state.issued.service.target,target);assert.equal(full.state.issued.service.crealm,realm);
        assert.equal(full.state.credentials.service,undefined,'Send precedes successful reply validation/cache insertion');
        result.fullReply={value:expected,proofTarget:full.state.proofs.tgsService.target,issuedTarget:full.state.issued.service.target,sourceIndex:full.sourceIndex};
        app.selectAttribute('adTGSReply',false);
        const sendIndex=app.traceQueue.findIndex(step=>step.sourceStepId.endsWith('-service-tgs-reply')&&step.traceKind==='send');assert.ok(sendIndex>=0);
        app.selectStep(sendIndex,false);const send=app.currentStep;
        assert.equal(field(send,'adTGSReply'),expected);assert.equal(send.sourceIndex,replyIndex);
        assert.ok(app.querySelector('#protocol-instance-list').textContent.includes(expected));
        assert.deepEqual(app.protocolSnapshot().state,full.state,'Focused Send retains all source-prefix effects');
        app.player.seek([send],.3,'attribute-step');
        assert.equal(app.player.snapshot().packet.value,expected);assert.equal(app.refs.packet.hidden,false);
        const packetLabel=app.refs['packet-value'].textContent;assert.ok(packetLabel.length>0&&expected.startsWith(packetLabel.replace(/…$/,'')));
        result.focusedSend={value:field(send,'adTGSReply'),sourceIndex:send.sourceIndex,packetValue:app.player.snapshot().packet.value,compactPacketLabel:packetLabel};
        app.clearAttribute();app.selectStep(app.steps.length-1,false);const last=app.protocolSnapshot();
        assert.equal(last.state.credentials.service.target,target);assert.equal(last.state.credentials.service.crealm,realm);
        const operations=app.steps.flatMap(step=>step.attributeOperations);
        const requests=operations.filter(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname');
        assert.ok(requests.some(operation=>operation.instanceId.startsWith('target:service:')),'At least one actual target-service request is transmitted');
        for(const request of requests)assert.equal(request.value,request.instanceId.startsWith('target:host:')?'host/ws01.a.example':target,'The transmitted request body names its own intended service');
        result.transmittedRequestTargets=requests.map(request=>({instanceId:request.instanceId,value:request.value}));
        for(const operation of operations){
          if(operation.attributeId==='adTicketTarget')assert.equal(operation.value,operation.instanceId==='ticket:host:01'?'host/ws01.a.example':target);
          if(operation.attributeId==='adTicketRealm')assert.equal(operation.value,realm);
          if(operation.attributeId==='adTGSReply')assert.equal(operation.value,replyValue(operation.instanceId==='reply:tgs:host:result'?'host/ws01.a.example':target,realm));
        }
        if(id==='lab-ad-first-sign-in'){
          assert.ok(requests.some(request=>request.instanceId.startsWith('target:host:')),'The independent workstation host request is actually transmitted');
          assert.equal(last.state.credentials.host.target,'host/ws01.a.example');assert.equal(last.state.proofs.tgsHost.target,'host/ws01.a.example');
          assert.equal(field(app.steps.find(step=>step.id.endsWith('-host-tgs-reply')),'adTGSReply'),replyValue('host/ws01.a.example',realm));
          result.independentHostTarget=last.state.credentials.host.target;
        }
        assert.equal(modelData(original),before,'Applied context cannot mutate the original fixture');
        result.finalCredentialTarget=last.state.credentials.service.target;
        app.selectAttribute('adTGSReply',true);harness.clock.advance(500);
        const appliedRevision=app.runtimeEnvironment.revision,nextTarget=target.replace('other','second');
        enter('servicePrincipal',nextTarget);app.querySelector('#environment-apply').click();
        assert.equal(app.runtimeEnvironment.revision,appliedRevision+1);assert.equal(app.player.status,'idle');assert.deepEqual(app.player.queue,[]);assert.equal(app.visibleIndex,0);assert.equal(app.attributeSelection,'adTGSReply');
        assert.ok(!JSON.stringify(app.traceQueue).includes('EncTGSRepPart for '+target+';'),'Reapply clears prior focused reply values');
        app.querySelector('#environment-reset').click();
        assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.applied.servicePrincipal,'');assert.equal(app.runtimeEnvironment.applied.kerberosRealm,'');
        assert.equal(app.player.status,'idle');assert.equal(app.visibleIndex,0);
        assert.equal(modelData(app.labModel),before,'Reset restores the complete base fixture');
        assert.equal(JSON.stringify(app.steps),JSON.stringify(original.steps()));assert.equal(modelData(original),before);
        result.baseFixtureUnchanged=true;result.resetRestores=true;result.passed=true;
      }catch(error){result.passed=false;result.reason=String(error.stack||error);}
      finally{if(app){app.disconnectedCallback();harness.document.body.removeChild(app);}harness.clock.frames.clear();harness.clock.timers.clear();}
      report.cases.push(result);
    }
  }
  report.passed=report.cases.length===4&&report.cases.every(result=>result.passed);
  if(!report.passed)process.exitCode=1;
}catch(error){report.passed=false;report.reason=String(error.stack||error);process.exitCode=1;}
finally{
  if(harness){harness.clock.frames.clear();harness.clock.timers.clear();}
  fs.writeFileSync(path.join(evidenceDir,'html2-r1-bundle-status.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({passed:report.passed,caseCount:report.cases.length,htmlSha256:report.artifact.sha256,nativeBrowser:false,reason:report.reason?.split('\n')[0],failures:report.cases.filter(result=>!result.passed).map(result=>({id:result.id,realm:result.realm,reason:result.reason.split('\n')[0]}))},null,2));
}
