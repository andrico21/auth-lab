import test from 'node:test';
import assert from 'node:assert/strict';
import {WINDOWSLAB_SCENARIOS,buildWindowsNegativeFixture} from '../src/windows-auth-lab.js';
import {buildWindowsHeldObjects} from '../src/held-object-windows.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

function winFixture(suffix){
  const model=typeof suffix==='string'?WINDOWSLAB_SCENARIOS.find(item=>item.id==='lab-win-'+suffix):suffix,steps=model.steps();
  const plan=buildWindowsHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':independent-test',choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const frame=(stage,milestone='complete')=>projectHeldObjects(compiled,{eventIndex:steps.findIndex(step=>step.winStage===stage),milestone});
  return {model,steps,plan,compiled,frame,id:key=>model.id+':'+key};
}
const winHolding=(frame,id,actor,representation)=>frame.holdings.find(item=>item.artifactId===id&&item.actorId===actor&&(!representation||item.representationId===representation));

test('Every Windows representative has explicit complete actor coverage at every canonical boundary',()=>{
  for(const model of WINDOWSLAB_SCENARIOS){
    const f=winFixture(model.id.slice('lab-win-'.length));
    for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){
      const frame=projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
      assert.equal(frame.coverageStatus,'complete');
      assert.equal(winHolding(frame,f.id('account-record'),'winHost'),undefined);
      assert.equal(winHolding(frame,f.id('password'),'winHost'),undefined);
      assert.equal(winHolding(frame,f.id('nt-hash'),'winHost'),undefined);
    }
  }
  assert.equal(buildWindowsHeldObjects({model:{id:'unowned'}}),null);
});

test('W01 response does not disclose NT hash and receipt-only negotiate remains historical',()=>{
  const f=winFixture('ntlmv2-domain');
  assert.equal(winHolding(f.frame('authenticate','before'),f.id('authenticate'),'winHost'),undefined);
  const response=winHolding(f.frame('authenticate'),f.id('authenticate'),'winHost');assert.ok(response);
  const inspected=inspectHeldObject(f.frame('authenticate'),response.holdingId);
  assert.ok(inspected.fields.every(field=>!String(field.value).includes('MD4(')));
  const negotiateHoldings=f.frame('negotiate').holdings.filter(item=>item.artifactId===f.id('negotiate')&&item.actorId==='winHost');
  assert.equal(negotiateHoldings.some(item=>item.store==='message inbox'),false);
  assert.ok(negotiateHoldings.some(item=>item.store==='mechanism transcript cache'));
  const trace=heldObjectTrace(f.compiled,f.id('negotiate'));
  assert.ok(trace.some(row=>row.sourceStepId===f.id('negotiate')&&row.from==='winClient'&&row.to==='winHost'),'Exact history retains the actual request after inbox consumption');
});

test('NTLM acceptor retains its transcript, unwraps a candidate key and verifies MIC without sending either field to the DC',()=>{
  for(const suffix of ['ntlmv2-domain','ntlmv2-local','ntlmv2-trust','negotiate-ntlm-allowed','credssp-v6-ntlm']){
    const f=winFixture(suffix);
    for(const key of ['ntlm-mic','encrypted-session-key','authenticate']){
      const artifact=f.model.windowsInventory.artifacts.find(item=>item.key===key);
      assert.deepEqual(artifact.readers,['winClient','winHost']);
      for(const frame of [f.frame('validation-result'),f.frame('ntlm-mic-verify')])assert.equal(winHolding(frame,f.id(key),'winDC'),undefined);
    }
    const keyTrace=heldObjectTrace(f.compiled,f.id('mechanism-key'));
    assert.ok(keyTrace.some(record=>record.sourceStepId===f.id('ntlm-key-process')));
    const micTrace=heldObjectTrace(f.compiled,f.id('ntlm-mic'));
    assert.ok(micTrace.some(record=>record.sourceStepId===f.id('ntlm-mic-verify')));
    assert.ok(winHolding(f.frame('ntlm-mic-verify'),f.id('negotiate'),'winHost'));
  }
});

for(const suffix of ['credssp-v6-kerberos','credssp-v6-ntlm'])test(suffix+' sealed receipt never grants readable delegated password before unwrap',()=>{
  const f=winFixture(suffix),id=f.id('delegated-credentials');
  for(const stage of ['last-token-binding','context','binding-verify-host','server-binding','binding-verify-client','authinfo-create','authinfo-receive'])assert.equal(winHolding(f.frame(stage),id,'winHost','plain'),undefined,stage);
  const received=f.frame('authinfo-receive'),wire=winHolding(received,f.id('authinfo'),'winHost','wire');assert.ok(wire);
  const opaque=inspectHeldObject(received,wire.holdingId);assert.equal(opaque.representation.readable,true);
  assert.ok(opaque.fields.some(field=>String(field.value).startsWith('TLS(Seal(')));
  assert.equal(opaque.fields.some(field=>String(field.value).includes('password=<synthetic Alice password>')),false);
  assert.ok(winHolding(f.frame('authinfo-create'),id,'winClient','plain'));
  const credentialWire=winHolding(received,id,'winHost','wire');assert.ok(credentialWire);
  const credentialInspection=inspectHeldObject(received,credentialWire.holdingId);
  assert.deepEqual(credentialInspection.fields.map(field=>field.value),opaque.fields.map(field=>field.value));
  assert.deepEqual(credentialInspection.fields.map(field=>field.attributeId),opaque.fields.map(field=>field.attributeId));
  const unwrapped=f.frame('authinfo-unwrap'),holding=winHolding(unwrapped,id,'winHost','plain');assert.ok(holding);
  const decoded=inspectHeldObject(unwrapped,holding.holdingId);assert.equal(decoded.representation.readable,true);
  assert.ok(decoded.fields.some(field=>String(field.value).includes('password=<synthetic Alice password>')));
  assert.equal(winHolding(unwrapped,f.id('authinfo'),'winHost','wire'),undefined);
  assert.equal(winHolding(unwrapped,id,'winHost','wire'),undefined);
  assert.equal(winHolding(f.frame('authinfo-receive','before'),id,'winHost'),undefined);
});

test('Kerberos client holds opaque ticket without ticket-decryption permission',()=>{
  const f=winFixture('credssp-v6-kerberos'),frame=f.frame('as-reply');
  const tgt=winHolding(frame,f.id('tgt'),'winClient');assert.ok(tgt);
  const tgtWire=inspectHeldObject(frame,tgt.holdingId);
  assert.equal(tgtWire.representation.readable,true);
  assert.ok(tgtWire.fields.every(field=>String(field.value).includes('ciphertext')));
  assert.equal(winHolding(frame,f.id('krbtgt-key'),'winClient'),undefined);
  const service=f.frame('tgs-reply'),ticket=winHolding(service,f.id('service-ticket'),'winClient');assert.ok(ticket);
  const serviceWire=inspectHeldObject(service,ticket.holdingId);
  assert.equal(serviceWire.representation.readable,true);
  assert.ok(serviceWire.fields.every(field=>String(field.value).includes('ciphertext')));
  for(const [key,issue,verify] of [['tgt-key','as-reply','as-verify'],['ticket-session-key','tgs-reply','ticket-verify']]){
    const issued=f.frame(issue);
    assert.equal(issued.artifacts.find(artifact=>artifact.artifactId===f.id(key)).creator,'winDC');
    assert.ok(winHolding(issued,f.id(key),'winDC'));
    assert.equal(winHolding(issued,f.id(key),'winClient'),undefined);
    assert.ok(winHolding(f.frame(verify),f.id(key),'winClient'));
  }
});

for(const suffix of ['credssp-v6-kerberos','credssp-v6-ntlm'])test(suffix+' exact delegated credential replay includes the real protected transfer and local recovery observation',()=>{
  const f=winFixture(suffix),trace=heldObjectTrace(f.compiled,f.id('delegated-credentials'));
  const carried=trace.find(row=>row.sourceStepId===f.model.id+':authinfo-receive');
  assert.ok(carried);assert.equal(carried.from,'winClient');assert.equal(carried.to,'winHost');
  assert.equal(carried.representationId,'wire');assert.ok(carried.messageId);
  assert.equal(carried.payload.some(field=>String(field.value).includes('password=<synthetic Alice password>')),false);
  const recovered=trace.find(row=>row.sourceStepId===f.model.id+':authinfo-unwrap');
  assert.ok(recovered.traceKind.includes('observe'));assert.equal(recovered.representationId,'plain');
  assert.ok(recovered.payload.some(field=>String(field.value).includes('password=<synthetic Alice password>')));
});

test('Exact proof and mechanism-key history records authored local verification and use, not inferred operations',()=>{
  const f=winFixture('credssp-v6-kerberos');
  for(const [key,stage] of [['ap-request','ap-verify'],['ap-reply','mutual-verify'],['client-binding','binding-verify-host'],['server-binding','binding-verify-client'],['acceptor-subkey','authinfo-create'],['acceptor-subkey','authinfo-unwrap']]){
    const row=heldObjectTrace(f.compiled,f.id(key)).find(item=>item.sourceStepId===f.model.id+':'+stage);
    assert.ok(row,key+'/'+stage);assert.ok(row.traceKind.includes('observe'));
    assert.ok(row.payload.every(field=>field.redacted!==true));
  }
  const ntlm=winFixture('ntlmv2-domain');
  assert.ok(heldObjectTrace(ntlm.compiled,ntlm.id('nt-proof')).some(row=>row.sourceStepId===ntlm.model.id+':dc-verify'&&row.traceKind.includes('observe')));
});

test('All named negative fixtures compile with complete inventory coverage and exact histories at every before/complete cursor',()=>{
  for(const model of WINDOWSLAB_SCENARIOS)for(const variant of model.negativeCases){
    const f=winFixture(buildWindowsNegativeFixture(model.id,variant));
    for(let index=0;index<f.steps.length;index++){
      const before=projectHeldObjects(f.compiled,{eventIndex:index,milestone:'before'}),after=projectHeldObjects(f.compiled,{eventIndex:index,milestone:'complete'});
      assert.equal(before.contextId,f.plan.contextId);assert.equal(after.contextId,f.plan.contextId);
      assert.equal(before.coverageStatus,'complete');
      assert.equal(after.coverageStatus,'complete');
    }
  }
});

test('Every actual message receipt has an explicit matching receiver acquisition, and scratch releases remain replayable',()=>{
  for(const model of WINDOWSLAB_SCENARIOS){
    const f=winFixture(model);
    for(const [sourceStepId,event] of Object.entries(f.plan.events))for(const message of event.messages||[]){
      const effects=event.milestones.flatMap(milestone=>milestone.effects);
      for(const object of message.objects){
        const receipt=effects.find(effect=>effect.op==='acquire'&&effect.actorId===message.to&&effect.artifactId===object.artifactId&&effect.representationId===object.representationId);
        assert.ok(receipt,sourceStepId+'/'+object.artifactId);
        const trace=heldObjectTrace(f.compiled,object.artifactId),row=trace.find(item=>item.sourceStepId===sourceStepId&&item.messageId===message.messageId);
        assert.ok(row,sourceStepId+'/trace');assert.equal(row.to,message.to);assert.equal(row.representationId,object.representationId);
        assert.ok(row.payload.every(field=>field.redacted!==true),sourceStepId+'/wire permission');
        const index=f.steps.findIndex(step=>step.id===sourceStepId);
        const before=projectHeldObjects(f.compiled,{eventIndex:index,milestone:'before'});
        assert.equal(before.holdings.some(holding=>holding.holdingId===receipt.holdingId),false,sourceStepId+'/no early receipt');
        assert.deepEqual(projectHeldObjects(f.compiled,{eventIndex:index,milestone:'before'}),before,'rewind restores pre-receipt holdings');
      }
    }
  }
});

test('Successful NTLM validation returns a distinct validator-owned SessionBaseKey without forwarding its account verifier',()=>{
  for(const suffix of ['ntlmv2-domain','ntlmv2-local','ntlmv2-trust','credssp-v6-ntlm']){
    const f=winFixture(suffix),key=f.id('validator-session-base-key'),authority=suffix==='ntlmv2-local'?'winLocalAuthority':'winDC';
    assert.equal(winHolding(f.frame('validation-result','before'),key,'winHost'),undefined);
    const returned=f.frame('validation-result');
    const keyDefinition=returned.artifacts.find(artifact=>artifact.artifactId===key);assert.equal(keyDefinition.creator,authority);
    assert.ok(winHolding(returned,key,'winHost',suffix==='ntlmv2-local'?'plain':'wire'));
    assert.equal(winHolding(returned,f.id('account-record'),'winHost'),undefined);
    const complete=f.frame('context');
    const decoded=winHolding(complete,key,'winHost','plain');assert.ok(decoded);
    assert.equal(inspectHeldObject(complete,decoded.holdingId).representation.readable,true);
    assert.notEqual(key,f.id('session-base-key'));assert.notEqual(key,f.id('mechanism-key'));
    assert.ok(heldObjectTrace(f.compiled,key).some(row=>row.sourceStepId===f.model.id+':validation-result'&&row.from===(suffix==='ntlmv2-trust'?'winResourceDC':authority)&&row.to==='winHost'));
  }
  const denied=winFixture('ntlmv2-response-rejected');
  assert.equal(denied.plan.artifacts.some(artifact=>artifact.artifactId===denied.id('validator-session-base-key')),false);
});

test('Local SAM and accepting application retain distinct stores and receipt histories',()=>{
  const f=winFixture('ntlmv2-local');
  const initial=projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'});
  assert.ok(winHolding(initial,f.id('account-record'),'winLocalAuthority'));
  assert.equal(winHolding(initial,f.id('account-record'),'winHost'),undefined);
  assert.equal(f.plan.artifacts.some(artifact=>artifact.artifactId===f.id('netlogon-channel')),false);
  const request=heldObjectTrace(f.compiled,f.id('validation-request')).find(row=>row.sourceStepId===f.model.id+':local-validation-request');
  assert.equal(request.from,'winHost');assert.equal(request.to,'winLocalAuthority');assert.equal(request.channel,'local-ipc');
});

test('A post-disclosure logon denial retains the real host password holding and its exact received history',()=>{
  const f=winFixture('credssp-logon-denied'),frame=f.frame('logon-deny');
  assert.equal(frame.state.windows.credentialsReceived,true);assert.equal(frame.state.windows.logonAuthorized,false);assert.equal(frame.state.windows.sessionEstablished,false);
  const holding=winHolding(frame,f.id('delegated-credentials'),'winHost','plain');assert.ok(holding);
  assert.ok(inspectHeldObject(frame,holding.holdingId).fields.some(field=>String(field.value).includes('password=<synthetic Alice password>')));
  const history=heldObjectTrace(f.compiled,f.id('delegated-credentials'));
  assert.ok(history.some(row=>row.sourceStepId===f.model.id+':authinfo-receive'&&row.representationId==='wire'));
  assert.ok(history.some(row=>row.sourceStepId===f.model.id+':logon-deny'&&row.traceKind.includes('observe')));
});

test('All three RDP modes have different credential inventories and the correct downstream principal',()=>{
  for(const [suffix,key,identity] of [['rdp-normal','delegated-credentials','CORP\\alice'],['rdp-restricted-admin','empty-password-credentials','CORP\\HOST$'],['rdp-remote-credential-guard','remote-guard-credentials','CORP\\alice']]){
    const f=winFixture(suffix),received=f.frame('authinfo-receive'),unwrapped=f.frame('authinfo-unwrap'),final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(winHolding(received,f.id(key),'winHost','plain'),undefined);assert.ok(winHolding(received,f.id(key),'winHost','wire'));
    const holding=winHolding(unwrapped,f.id(key),'winHost','plain');assert.ok(holding);
    const value=inspectHeldObject(unwrapped,holding.holdingId).fields.map(field=>String(field.value)).join(' ');
    if(suffix==='rdp-restricted-admin'){assert.match(value,/domainName=\"\",userName=\"\",password=\"\"/);assert.equal(winHolding(final,f.id('delegated-credentials'),'winHost'),undefined);}
    if(suffix==='rdp-remote-credential-guard'){assert.match(value,/credType=6/);assert.match(value,/credBuffer=<opaque/);assert.equal(winHolding(final,f.id('delegated-credentials'),'winHost'),undefined);}
    assert.equal(final.state.windows.downstreamIdentity,identity);assert.equal(final.state.windows.resourceAuthorized,true);
    const ticket=winHolding(final,f.id('downstream-ticket'),'winHost','wire');assert.ok(ticket);assert.equal(ticket.store,'service ticket cache');
    assert.equal(inspectHeldObject(final,ticket.holdingId).fields.some(field=>String(field.value).includes('client=')||String(field.value).includes('principal=')),false,'protected client identity is not invented in clear ticket header');
  }
});

test('Remote Guard forwards the same exact KDC reply ciphertext to C, then legitimately installs scoped service material at H',()=>{
  const f=winFixture('rdp-remote-credential-guard'),reply=f.id('downstream-tgs-reply'),key=f.id('downstream-session-key');
  const before=f.frame('redirect-unpack-request','before');assert.equal(winHolding(before,reply,'winClient'),undefined);
  const receipt=f.frame('redirect-unpack-request');assert.ok(winHolding(receipt,reply,'winClient','wire'));assert.equal(winHolding(receipt,reply,'winClient','plain'),undefined);
  const processed=f.frame('redirect-unpack-process');assert.ok(winHolding(processed,reply,'winClient','plain'));assert.ok(winHolding(processed,key,'winClient','plain'));
  assert.equal(winHolding(processed,key,'winHost'),undefined);
  const installed=f.frame('downstream-ticket-verify');assert.ok(winHolding(installed,key,'winHost','plain'));
  assert.equal(winHolding(installed,f.id('tgt-key'),'winHost'),undefined);assert.equal(winHolding(installed,f.id('downstream-tgt-key'),'winHost'),undefined);
  const trace=heldObjectTrace(f.compiled,reply);
  assert.ok(trace.some(row=>row.sourceStepId===f.model.id+':downstream-tgs-reply'&&row.from==='winDC'&&row.to==='winHost'&&row.representationId==='wire'));
  assert.ok(trace.some(row=>row.sourceStepId===f.model.id+':redirect-unpack-request'&&row.from==='winHost'&&row.to==='winClient'&&row.representationId==='wire'));
  assert.ok(trace.some(row=>row.sourceStepId===f.model.id+':redirect-unpack-process'&&row.traceKind.includes('observe')));
});

test('Remote Guard disconnect closes redirection/desktop without revoking already-issued service ticket or resource session',()=>{
  const f=winFixture(buildWindowsNegativeFixture('lab-win-rdp-remote-credential-guard','redirect-disconnect')),frame=f.frame('redirect-close');
  assert.equal(frame.state.windows.sessionEstablished,false);assert.equal(frame.state.windows.redirectedContext,false);
  assert.equal(frame.state.windows.downstreamResourceSessionEstablished,true);assert.equal(frame.state.windows.resourceAuthorized,true);
  assert.equal(winHolding(frame,f.id('remote-guard-credentials'),'winHost'),undefined);
  assert.equal(winHolding(frame,f.id('session'),'winHost'),undefined);
  assert.ok(winHolding(frame,f.id('downstream-ticket'),'winHost','wire'));
  assert.ok(winHolding(frame,f.id('downstream-context'),'winHost','plain'));
});

test('WinRM ACL denial preserves delegated credentials and first-hop session; HTTP has no outer HTTPS objects',()=>{
  const f=winFixture('winrm-resource-denied'),frame=f.frame('resource-acl-deny');
  assert.ok(winHolding(frame,f.id('delegated-credentials'),'winHost','plain'));
  assert.ok(winHolding(frame,f.id('session'),'winHost','plain'));
  assert.ok(winHolding(frame,f.id('context'),'winHost','plain'));
  assert.ok(winHolding(frame,f.id('downstream-context'),'winHost','plain'));
  assert.equal(frame.state.windows.downstreamIdentity,'CORP\\alice');
  assert.equal(frame.state.windows.resourceAuthorized,false);
  const http=winFixture('winrm-credssp-http'),httpFrame=projectHeldObjects(http.compiled,{eventIndex:http.steps.length-1,milestone:'complete'});
  assert.equal(http.plan.artifacts.some(artifact=>artifact.artifactId===http.id('outer-tls-key')||artifact.artifactId===http.id('outer-certificate-private-key')),false);
  assert.ok(winHolding(httpFrame,http.id('tls-inner-key'),'winHost'));
  const noDelegation=winFixture('winrm-second-hop-denied'),noFrame=noDelegation.frame('downstream-no-credential');
  assert.ok(winHolding(noFrame,noDelegation.id('session'),'winHost'));
  assert.equal(winHolding(noFrame,noDelegation.id('delegated-credentials'),'winHost'),undefined);
  assert.equal(winHolding(noFrame,noDelegation.id('host-machine-credential'),'winHost'),undefined);
});

test('WIN-06 KDC authoritative AES principal keys are provisioned, used and never transferred as client-derived or NTLM records',()=>{
  for(const suffix of ['negotiate-kerberos','credssp-v6-kerberos','rdp-normal','rdp-restricted-admin','winrm-credssp-second-hop']){
    const f=winFixture(suffix),before=projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'});
    const kdc=winHolding(before,f.id('kdc-account-key'),'winDC','plain');
    assert.ok(kdc,suffix);assert.equal(kdc.store,'Kerberos principal database');
    assert.ok(winHolding(before,f.id('client-account-key'),'winClient','plain'));
    assert.equal(f.plan.artifacts.some(artifact=>artifact.artifactId===f.id('account-record')),false);
    const asReply=f.steps.find(step=>step.winStage==='as-reply');
    assert.equal(asReply.layers[0].keyRef,f.id('kdc-account-key'));
    const trace=heldObjectTrace(f.compiled,f.id('kdc-account-key'));
    assert.ok(trace.some(row=>row.sourceStepId===f.id('as-preauth-verify')&&row.traceKind.split('/').includes('observe')));
    assert.ok(f.frame('as-preauth-verify').observations.some(observation=>observation.artifactId===f.id('kdc-account-key')&&observation.actorId==='winDC'&&observation.kind==='verification'));
    assert.ok(f.frame('as-reply').observations.some(observation=>observation.artifactId===f.id('kdc-account-key')&&observation.result==='used_for_EncASRepPart_encryption'));
    for(const stage of ['as-request','as-preauth-verify','as-reply','as-verify']){
      const frame=f.frame(stage);
      assert.equal(winHolding(frame,f.id('kdc-account-key'),'winClient'),undefined);
      assert.equal(winHolding(frame,f.id('kdc-account-key'),'winHost'),undefined);
      assert.equal(winHolding(frame,f.id('client-account-key'),'winDC'),undefined);
    }
    if(f.steps.some(step=>step.winStage==='downstream-as-request')){
      const frame=f.frame('downstream-as-preauth-verify');
      assert.ok(winHolding(frame,f.id('downstream-kdc-account-key'),'winDC','plain'));
      assert.equal(winHolding(frame,f.id('downstream-kdc-account-key'),'winHost'),undefined);
      assert.equal(winHolding(frame,f.id('downstream-kdc-account-key'),'winClient'),undefined);
      assert.ok(winHolding(frame,f.id('downstream-account-key'),'winHost','plain'));
      assert.equal(winHolding(frame,f.id('downstream-account-key'),'winDC'),undefined);
      assert.equal(f.steps.find(step=>step.winStage==='downstream-as-reply').layers[0].keyRef,f.id('downstream-kdc-account-key'));
      const keyTrace=heldObjectTrace(f.compiled,f.id('downstream-kdc-account-key'));
      assert.ok(keyTrace.some(row=>row.sourceStepId===f.id('downstream-as-preauth-verify')&&row.traceKind.split('/').includes('observe')));
      assert.ok(frame.observations.some(observation=>observation.artifactId===f.id('downstream-kdc-account-key')&&observation.actorId==='winDC'&&observation.kind==='verification'));
    }
  }
  const ntlm=winFixture('credssp-v6-ntlm'),initial=projectHeldObjects(ntlm.compiled,{eventIndex:-1,milestone:'initial'});
  assert.ok(winHolding(initial,ntlm.id('account-record'),'winDC'));
  assert.equal(ntlm.plan.artifacts.some(artifact=>artifact.artifactId===ntlm.id('kdc-account-key')),false);
});

test('WIN-02 final HTTP resource body and AP-REP share receipt but have separate validated client acquisition',()=>{
  const f=winFixture('negotiate-kerberos'),prepared=f.frame('ap-reply'),received=f.frame('result');
  assert.equal(winHolding(prepared,f.id('ap-reply'),'winClient'),undefined);
  assert.ok(winHolding(received,f.id('ap-reply'),'winClient','wire'));
  assert.ok(winHolding(received,f.id('http-result'),'winClient','wire'));
  assert.equal(winHolding(received,f.id('http-result'),'winClient','plain'),undefined);
  assert.equal(winHolding(f.frame('mutual-verify'),f.id('http-result'),'winClient','plain'),undefined);
  assert.ok(winHolding(f.frame('result-accept'),f.id('http-result'),'winClient','plain'));
  const event=f.plan.events[f.id('result')];
  assert.equal(event.messages.length,1);
  assert.deepEqual(event.messages[0].objects.map(object=>object.artifactId),[f.id('ap-reply'),f.id('http-result')]);
});

test('WIN-07 WinRM wire shell/output receipt grants no decoded handle or outcome until protected-response acceptance',()=>{
  for(const suffix of ['winrm-second-hop-denied','winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied']){
    const f=winFixture(suffix),shell=f.frame('winrm-session-result');
    assert.ok(winHolding(shell,f.id('session'),'winClient','wire'));
    assert.equal(winHolding(shell,f.id('session'),'winClient','plain'),undefined);
    assert.notEqual(shell.state.windows.clientKnowsSession,true);
    const accepted=f.frame('winrm-session-accept');
    assert.ok(winHolding(accepted,f.id('session'),'winClient','plain'));
    assert.equal(accepted.state.windows.clientKnowsSession,true);
    const output=f.frame('winrm-command-result');
    assert.ok(winHolding(output,f.id('winrm-command-result'),'winClient','wire'));
    assert.equal(winHolding(output,f.id('winrm-command-result'),'winClient','plain'),undefined);
    assert.notEqual(output.state.windows.clientKnowsResourceResult,true);
    const decoded=f.frame('winrm-command-accept');
    assert.ok(winHolding(decoded,f.id('winrm-command-result'),'winClient','plain'));
    assert.equal(decoded.state.windows.clientKnowsResourceResult,true);
    assert.ok(winHolding(decoded,f.id('session'),'winClient','plain'));
    const trace=heldObjectTrace(f.compiled,f.id('winrm-command-result'));
    assert.ok(trace.some(row=>row.sourceStepId===f.id('winrm-command-accept')&&row.traceKind.split('/').includes('observe')));
    assert.ok(decoded.observations.some(observation=>observation.artifactId===f.id('winrm-command-result')&&observation.actorId==='winClient'&&observation.kind==='verification'));
  }
});

test('WIN-09 shared file results acquire plaintext and outcome knowledge only at H protected-result acceptance',()=>{
  for(const suffix of ['winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied','rdp-normal','rdp-restricted-admin','rdp-remote-credential-guard']){
    const f=winFixture(suffix),received=f.frame('resource-result'),accepted=f.frame('resource-result-accept');
    assert.ok(winHolding(received,f.id('resource-result'),'winHost','wire'));
    assert.equal(winHolding(received,f.id('resource-result'),'winHost','plain'),undefined);
    assert.equal(received.observations.some(item=>item.artifactId===f.id('resource-result')&&item.actorId==='winHost'),false);
    assert.ok(winHolding(accepted,f.id('resource-result'),'winHost','plain'));
    assert.ok(accepted.observations.some(item=>item.artifactId===f.id('resource-result')&&item.actorId==='winHost'&&item.kind==='verification'));
    assert.ok(winHolding(accepted,f.id('session'),'winHost','plain'));
    if(suffix==='winrm-resource-denied')assert.ok(winHolding(accepted,f.id('delegated-credentials'),'winHost','plain'));
    const trace=heldObjectTrace(f.compiled,f.id('resource-result'));
    assert.ok(trace.some(item=>item.sourceStepId===f.id('resource-result')&&item.representationId==='wire'&&item.messageId));
    assert.ok(trace.some(item=>item.sourceStepId===f.id('resource-result-accept')&&item.representationId==='plain'&&item.traceKind.includes('observe')));
    if(suffix.startsWith('winrm-')){
      assert.deepEqual(f.plan.artifacts.find(item=>item.artifactId===f.id('winrm-command-result')).derivedFrom,[f.id('resource-result')]);
      const frame=f.frame('winrm-command-accept');
      const output=inspectHeldObject(frame,winHolding(frame,f.id('winrm-command-result'),'winClient','plain').holdingId);
      const source=inspectHeldObject(accepted,winHolding(accepted,f.id('resource-result'),'winHost','plain').holdingId);
      assert.deepEqual(output.fields.map(item=>item.value),source.fields.map(item=>item.value));
    }
  }
});

test('WIN-10 shared AES acceptor key exists first at H and never reaches C before validated AP-REP acquisition',()=>{
  for(const model of WINDOWSLAB_SCENARIOS.filter(item=>item.profile.selectedMechanism==='Kerberos'&&item.steps().some(step=>step.winStage==='ap-verify'))){
    const f=winFixture(model),receipt=f.steps.find(step=>['ap-reply','server-binding','result','http-kerberos-complete'].includes(step.winStage)&&f.plan.events[step.id].messages?.some(message=>message.objects.some(object=>object.artifactId===f.id('ap-reply'))));
    assert.ok(receipt,model.id);
    assert.equal(winHolding(f.frame('ap-verify'),f.id('acceptor-subkey'),'winHost'),undefined);
    assert.ok(winHolding(f.frame('ap-reply'),f.id('acceptor-subkey'),'winHost','plain'));
    assert.equal(winHolding(f.frame(receipt.winStage),f.id('acceptor-subkey'),'winClient'),undefined);
    assert.ok(winHolding(f.frame(receipt.winStage),f.id('ap-reply'),'winClient','wire'));
    assert.ok(winHolding(f.frame('mutual-verify'),f.id('acceptor-subkey'),'winClient','plain'));
    for(let index=0;index<f.steps.findIndex(step=>step.winStage==='mutual-verify');index++)assert.equal(winHolding(projectHeldObjects(f.compiled,{eventIndex:index,milestone:'complete'}),f.id('acceptor-subkey'),'winClient'),undefined);
    const key=f.plan.artifacts.find(item=>item.artifactId===f.id('acceptor-subkey'));
    assert.equal(key.creator,'winHost');assert.deepEqual(key.representations[0].readableBy,['winHost','winClient']);
    const trace=heldObjectTrace(f.compiled,f.id('acceptor-subkey'));
    assert.ok(trace.some(item=>item.sourceStepId===f.id('mutual-verify')&&item.traceKind.includes('observe')));
    assert.equal(trace.some(item=>item.from==='winHost'&&item.to==='winClient'&&item.representationId==='plain'&&item.messageId),false);
  }
});

test('WIN-11 raw CredSSP/RDP field replay starts at H creation without duplicate custody or key transmission',()=>{
  const cases=[
    ['credssp-v6-kerberos',['binding-direction','binding-nonce','binding-public-key']],
    ['credssp-binding-rejected',[]],
    ['credssp-logon-denied',[]],
    ['rdp-normal',['hybrid-without-early-result']],
    ['rdp-restricted-admin',['hybrid-without-early-result']],
    ['rdp-remote-credential-guard',['redirect-disconnect','hybrid-without-early-result']],
  ];
  for(const [suffix,variants] of cases){
    const model=WINDOWSLAB_SCENARIOS.find(item=>item.id==='lab-win-'+suffix);
    for(const candidate of [model,...variants.map(variant=>buildWindowsNegativeFixture(model.id,variant))]){
      const f=winFixture(candidate),key=candidate.windowsInventory.artifacts.find(item=>item.key==='acceptor-subkey');
      const replyIndex=f.steps.findIndex(step=>step.winStage==='ap-reply'),mutualIndex=f.steps.findIndex(step=>step.winStage==='mutual-verify');
      const previous=ATTRIBUTES[key.attributeId];
      ATTRIBUTES[key.attributeId]=candidate.definitions()[key.attributeId];
      try{
        const trace=buildAttributeTrace(getAttributeUsage(f.steps,key.attributeId),candidate.examples(),candidate.protocolValues||{});
        const origin=trace[0];
        assert.equal(origin?.traceKind,'create',candidate.id+' must expose the host origin before client validation');
        assert.deepEqual([origin.from,origin.to],['winHost','winHost']);
        assert.equal(origin.sourceStepId,f.id('ap-reply'));
        assert.equal(origin.sourceIndex,replyIndex);
        assert.deepEqual(origin.payload.map(field=>[field.attributeId,field.value]),[[key.attributeId,key.value]]);
        const operation=origin.traceActions[0];
        assert.equal(operation.instanceId,key.artifactId);
        assert.equal(operation.creator,'winHost');
        assert.deepEqual(operation.holders,['winHost']);
        assert.equal(operation.representation,'plain');
        assert.equal(operation.sourceEventId,f.id('ap-reply'));
        assert.equal(operation.exactValueRef,key.artifactId+':plain');
        assert.ok(trace.every(step=>step.from===step.to),'A local secret must never become a field-only wire replay');
        const client=trace.filter(step=>step.from==='winClient');
        assert.ok(client.some(step=>step.sourceIndex===mutualIndex));
        assert.ok(client.every(step=>step.sourceIndex>=mutualIndex&&step.payload.every(field=>field.value===key.value)));
        const effects=Object.values(f.plan.events).flatMap(event=>event.milestones.flatMap(milestone=>milestone.effects)).filter(effect=>effect.artifactId===key.artifactId);
        assert.equal(effects.filter(effect=>effect.op==='create').length,1);
        for(const actor of ['winHost','winClient'])assert.equal(effects.filter(effect=>effect.op==='acquire'&&effect.actorId===actor&&effect.representationId==='plain').length,1);
        const messages=Object.values(f.plan.events).flatMap(event=>event.messages||[]);
        assert.equal(messages.some(message=>message.objects.some(object=>object.artifactId===key.artifactId)),false);
      }finally{
        if(previous)ATTRIBUTES[key.attributeId]=previous;else delete ATTRIBUTES[key.attributeId];
      }
    }
  }
});
