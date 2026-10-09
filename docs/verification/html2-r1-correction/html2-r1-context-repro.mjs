import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const project=path.resolve(process.argv[2]),destination=path.resolve(process.argv[3]);
const load=name=>import(pathToFileURL(path.join(project,name)).href);
const {installHarness}=await load('tests/dom-harness.mjs');
const harness=installHarness();const {AuthFlowStudio}=await load('src/app.js');
const hash=name=>createHash('sha256').update(fs.readFileSync(path.join(project,name))).digest('hex');
const report={kind:'html2-r1-independent-context-repro',nativeBrowser:false,project,sourceSha256:hash('src/kerberos-ad-lab.js'),htmlSha256:hash('dist/auth-flow-studio.html'),scenarios:[],checks:[]};
function check(id,name,actual,expected){try{assert.deepEqual(actual,expected,name);report.checks.push({id,name,passed:true,actual,expected});}catch(error){report.checks.push({id,name,passed:false,actual,expected,assertion:error.message});}}
const targetFrom=value=>value.match(/EncTGSRepPart for ([^;)]+)/)?.[1];
for(const [id,target] of [['lab-ad-first-sign-in','cifs/other.corp.test'],['lab-kc-kerberos-sso','HTTP/other.corp.test']]){
 const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();app.selectLabScenario(id);
 app.refs['environment-fields'].querySelector('[data-environment-field="servicePrincipal"]').value=target;app.applyEnvironment();
 const request=app.steps.find(step=>step.id.endsWith('-service-tgs-request')).attributeOperations.find(operation=>operation.attributeId==='adSPN'&&operation.kind==='send'&&operation.carriedAs==='TGS-REQ.req-body.sname').value;
 const fullIndex=app.steps.findIndex(step=>step.id.endsWith('-service-tgs-reply'));app.selectStep(fullIndex,false);
 const header=app.currentStep.payload.find(field=>field.attributeId==='adTicketTarget').value;
 const fullReply=app.currentStep.payload.find(field=>field.attributeId==='adTGSReply').value;
 app.selectStep(app.steps.length-1,false);const state=app.protocolSnapshot().state;
 app.selectAttribute('adTGSReply',false);const sendIndex=app.traceQueue.findIndex(step=>step.sourceStepId.endsWith('-service-tgs-reply')&&step.traceKind==='send');assert.ok(sendIndex>=0);app.selectStep(sendIndex,false);
 const focusedReply=app.currentStep.payload.find(field=>field.attributeId==='adTGSReply').value;
 const record={id,input:{servicePrincipal:target,kerberosRealm:'unchanged A.EXAMPLE'},request,header,fullReply,proof:state.proofs.tgsService.target,cache:state.credentials.service.target,focusedSend:focusedReply,sessions:state.sessions};
 report.scenarios.push(record);
 check(id,'request sname',request,target);check(id,'clear ticket header',header,target);check(id,'proof target',record.proof,target);check(id,'protected reply target',targetFrom(fullReply),target);check(id,'cached target',record.cache,target);check(id,'focused Send target',targetFrom(focusedReply),target);
 if(id==='lab-ad-first-sign-in'){
  record.host={proof:state.proofs.tgsHost.target,cache:state.credentials.host.target,reply:app.steps.find(step=>step.id.endsWith('-host-tgs-reply')).payload.find(field=>field.attributeId==='adTGSReply').value};
  check(id,'independent host proof',record.host.proof,'host/ws01.a.example');check(id,'independent host cache',record.host.cache,'host/ws01.a.example');check(id,'independent host reply target',targetFrom(record.host.reply),'host/ws01.a.example');
 }
 app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();
}
report.summary={checks:report.checks.length,passed:report.checks.filter(check=>check.passed).length,failed:report.checks.filter(check=>!check.passed).length};
fs.writeFileSync(destination,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report.summary));
