import test from 'node:test';
import assert from 'node:assert/strict';
import {WINDOWSLAB_SCENARIOS,WINDOWSLAB_ATTRIBUTES,buildWindowsNegativeFixture} from '../src/windows-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const winModel=suffix=>WINDOWSLAB_SCENARIOS.find(model=>model.id==='lab-win-'+suffix);
const winIndex=(model,stage)=>model.steps().findIndex(step=>step.winStage===stage);
const winAt=(model,stage)=>reconstructProtocolState(model,winIndex(model,stage)).windows;



for(const suffix of ['credssp-v6-kerberos','credssp-v6-ntlm'])test(suffix+' pins v6 binding and never creates a logon/session at mechanism or credential receipt',()=>{
  const model=winModel(suffix),steps=model.steps();
  assert.equal(winAt(model,'last-token-binding').credentialsReceived,false);
  assert.equal(winAt(model,'context').bindingClientVerified,false);
  assert.equal(winAt(model,'binding-verify-host').bindingHostVerified,true);
  assert.equal(winAt(model,'server-binding').bindingClientVerified,false);
  assert.equal(winAt(model,'binding-verify-client').bindingClientVerified,true);
  assert.equal(winAt(model,'authinfo-create').authInfoReceived,false);
  assert.equal(winAt(model,'authinfo-receive').authInfoReceived,true);
  assert.equal(winAt(model,'authinfo-receive').credentialsReceived,false);
  assert.equal(winAt(model,'authinfo-unwrap').credentialsReceived,true);
  assert.equal(winAt(model,'authinfo-unwrap').logonAuthorized,false);
  assert.equal(winAt(model,'authinfo-unwrap').sessionEstablished,false);
  const binding=model.profile.cryptoDetail.binding;
  assert.equal(binding.clientMagic,'CredSSP Client-To-Server Binding Hash\0');
  assert.equal(binding.serverMagic,'CredSSP Server-To-Client Binding Hash\0');
  assert.notEqual(binding.clientMagic,binding.serverMagic);assert.equal(binding.nonceBytes,32);
  for(let index=-1;index<steps.length;index++){
    const state=reconstructProtocolState(model,index).windows;
    if(index<winIndex(model,'authinfo-unwrap'))assert.equal(state.credentialsReceived,false);
    if(index<winIndex(model,'binding-verify-client'))assert.equal(state.bindingClientVerified,false);
  }
  assert.deepEqual(reconstructProtocolState(model,-1).windows,model.initialState.windows);
});

test('W09 includes independent Kerberos acquisition and validation boundaries; W10 uses NTLM key terminology',()=>{
  const kerberos=winModel('credssp-v6-kerberos'),ntlm=winModel('credssp-v6-ntlm');
  assert.equal(winAt(kerberos,'as-reply').tgtUsable,undefined);
  assert.equal(winAt(kerberos,'as-verify').tgtUsable,true);
  assert.equal(winAt(kerberos,'tgs-reply').ticketUsable,undefined);
  assert.equal(winAt(kerberos,'ticket-verify').ticketUsable,true);
  assert.equal(winAt(kerberos,'ap-verify').hostMechanismAccepted,true);
  assert.equal(winAt(kerberos,'ap-reply').clientMechanismAccepted,false);
  assert.equal(winAt(kerberos,'mutual-verify').clientMechanismAccepted,true);
  assert.equal(ntlm.steps().some(step=>step.protocolLabel==='Kerberos AS-REQ'),false);
});

test('W01 has no CredSSP-only nonce/binding artifacts or field definitions',()=>{
  const model=winModel('ntlmv2-domain');
  assert.equal(model.windowsInventory.artifacts.some(artifact=>['client-binding','binding-nonce','server-binding','authinfo','delegated-credentials'].includes(artifact.key)),false);
});



const winTerminalExpectations=[
  ['ntlmv2-domain',{mechanismComplete:true,credentialsReceived:false,sessionEstablished:false,resourceAuthorized:true}],
  ['ntlmv2-local',{mechanismComplete:true,credentialsReceived:false,sessionEstablished:false,resourceAuthorized:true}],
  ['ntlmv2-trust',{mechanismComplete:true,credentialsReceived:false,sessionEstablished:false,resourceAuthorized:true}],
  ['ntlmv2-trust-denied',{mechanismComplete:false,credentialsReceived:false,resourceAuthorized:false,failure:'trust-route',serverKnowsFailure:true,clientKnowsFailure:true}],
  ['ntlmv2-response-rejected',{mechanismComplete:false,resourceAuthorized:false,failure:'bad-response',serverKnowsFailure:true,clientKnowsFailure:true}],
  ['negotiate-kerberos',{mechanismComplete:true,spnegoSelected:'Kerberos',resourceAuthorized:true,credentialsReceived:false}],
  ['negotiate-ntlm-allowed',{mechanismComplete:true,selectionReason:'configured-NTLM-only-profile',resourceAuthorized:true}],
  ['negotiate-ntlm-blocked',{mechanismComplete:false,failure:'ntlm-policy',transportReady:true,resourceAuthorized:false}],
  ['credssp-v6-kerberos',{mechanismComplete:true,bindingHostVerified:true,bindingClientVerified:true,credentialsReceived:true,logonAuthorized:false,sessionEstablished:false}],
  ['credssp-v6-ntlm',{mechanismComplete:true,bindingHostVerified:true,bindingClientVerified:true,credentialsReceived:true,sessionEstablished:false}],
  ['credssp-binding-rejected',{mechanismComplete:true,bindingHostVerified:true,bindingClientVerified:false,credentialsReceived:false,failure:'binding'}],
  ['credssp-delegation-denied',{mechanismComplete:false,transportReady:false,exportAllowed:false,credentialsReceived:false,failure:'delegation-policy'}],
  ['credssp-logon-denied',{mechanismComplete:true,credentialsReceived:true,logonAuthorized:false,sessionEstablished:false,failure:'logon-policy'}],
  ['rdp-normal',{credentialsReceived:true,logonAuthorized:true,sessionEstablished:true,downstreamIdentity:'CORP\\alice',downstreamAuthenticated:true,resourceAuthorized:true}],
  ['rdp-restricted-admin',{credentialsReceived:false,emptyCredentialsReceived:true,logonAuthorized:true,sessionEstablished:true,downstreamIdentity:'CORP\\HOST$',resourceAuthorized:true}],
  ['rdp-remote-credential-guard',{credentialsReceived:false,redirectedContext:true,sessionEstablished:true,downstreamIdentity:'CORP\\alice',downstreamAuthenticated:true,resourceAuthorized:true}],
  ['rdp-rcg-kerberos-unavailable',{mechanismComplete:false,credentialsReceived:false,sessionEstablished:false,failure:'kerberos-unavailable'}],
  ['rdp-required-mode-unsupported',{mechanismComplete:false,credentialsReceived:false,sessionEstablished:false,failure:'required-mode-unsupported'}],
  ['winrm-second-hop-denied',{mechanismComplete:true,credentialsReceived:false,sessionEstablished:true,resourceAuthorized:false,failure:'second-hop-user-credential-unavailable'}],
  ['winrm-credssp-second-hop',{outerTls:true,innerTls:true,credentialsReceived:true,sessionEstablished:true,downstreamIdentity:'CORP\\alice',resourceAuthorized:true}],
  ['winrm-delegation-denied',{transportReady:false,credentialsReceived:false,sessionEstablished:false,failure:'delegation-policy'}],
  ['winrm-credssp-http',{outerTls:false,innerTls:true,credentialsReceived:true,sessionEstablished:true,downstreamIdentity:'CORP\\alice',resourceAuthorized:true}],
  ['winrm-resource-denied',{credentialsReceived:true,sessionEstablished:true,downstreamIdentity:'CORP\\alice',downstreamAuthenticated:true,resourceAuthorized:false,failure:'resource-acl'}]
];

test('All23 fixed Windows presets meet independently authored terminal predicates',()=>{
  for(const [suffix,expected] of winTerminalExpectations){
    const model=winModel(suffix);assert.ok(model,suffix);
    const state=reconstructProtocolState(model,model.steps().length-1).windows;
    for(const [field,value] of Object.entries(expected))assert.deepEqual(state[field],value,suffix+'/'+field);
  }
});

test('Local account validation uses a separate SAM actor and local IPC without any DC/Kerberos query',()=>{
  const model=winModel('ntlmv2-local'),steps=model.steps(),actors=model.actors();
  assert.equal(actors.winDC,undefined);assert.ok(actors.winLocalAuthority);
  assert.equal(actors.winLocalAuthority.parentId,'winHost');
  const request=steps.find(step=>step.winStage==='local-validation-request');
  assert.equal(request.from,'winHost');assert.equal(request.to,'winLocalAuthority');assert.equal(request.channel,'local-ipc');
  const check=steps.find(step=>step.winStage==='local-verify');assert.equal(check.from,'winLocalAuthority');assert.equal(check.to,'winLocalAuthority');
  const result=steps.find(step=>step.winStage==='validation-result');assert.equal(result.from,'winLocalAuthority');assert.equal(result.to,'winHost');assert.equal(result.channel,'local-ipc');
  assert.equal(steps.some(step=>/Netlogon|Kerberos/.test(step.protocolLabel)),false);
  assert.equal(winAt(model,'local-verify').mechanismComplete,false);
  assert.equal(winAt(model,'validation-result').resourceAuthorized,false);
  assert.ok(model.windowsInventory.artifacts.some(artifact=>artifact.key==='account-record'&&artifact.creator==='winLocalAuthority'));
});

test('Direct trust has two independent secure channels and no validation at uncontacted account authority on route denial',()=>{
  const model=winModel('ntlmv2-trust'),steps=model.steps();
  for(const [stage,from,to] of [['validation-request','winHost','winResourceDC'],['trust-forward','winResourceDC','winDC'],['trust-return','winDC','winResourceDC'],['validation-result','winResourceDC','winHost']]){
    const step=steps.find(item=>item.winStage===stage);assert.equal(step.from,from);assert.equal(step.to,to);
  }
  assert.notEqual(steps.find(step=>step.winStage==='validation-request').layers[0].keyRef,steps.find(step=>step.winStage==='trust-forward').layers[0].keyRef);
  const denied=winModel('ntlmv2-trust-denied');
  assert.equal(denied.steps().some(step=>step.winStage==='dc-verify'||step.winStage==='trust-forward'),false);
  assert.equal(winAt(denied,'trust-deny').serverKnowsFailure,false);
  assert.equal(winAt(denied,'validation-result').serverKnowsFailure,true);
  assert.equal(winAt(denied,'validation-result').clientKnowsFailure,false);
  assert.equal(winAt(denied,'failure').clientKnowsFailure,true);
  const bad=winModel('ntlmv2-response-rejected');
  assert.equal(winAt(bad,'dc-verify').serverKnowsFailure,false);
  assert.equal(winAt(bad,'validation-result').serverKnowsFailure,true);
  assert.equal(winAt(bad,'validation-result').clientKnowsFailure,false);
});

test('RDP NLA, early authorization and desktop finalization are different boundaries',()=>{
  for(const suffix of ['rdp-normal','rdp-restricted-admin','rdp-remote-credential-guard']){
    const model=winModel(suffix);
    assert.equal(winAt(model,'context').sessionEstablished,false);
    assert.equal(winAt(model,'authinfo-unwrap').logonAuthorized,false);
    assert.equal(winAt(model,'logon').logonAuthorized,true);
    assert.equal(winAt(model,'logon').sessionEstablished,false);
    assert.equal(winAt(model,'early-authorization').earlyAuthorizationReceived,true);
    assert.equal(winAt(model,'early-authorization').sessionEstablished,false);
    assert.equal(winAt(model,'rdp-finalize').sessionEstablished,true);
    const hybrid=buildWindowsNegativeFixture(model.id,'hybrid-without-early-result');
    assert.equal(hybrid.steps().some(step=>step.winStage==='early-authorization'),false);
    assert.equal(reconstructProtocolState(hybrid,hybrid.steps().length-1).windows.sessionEstablished,true);
    assert.equal(hybrid.profile.rdpSecurity,'HYBRID');
  }
});

test('Required-mode support checks cover both exact modes without ordinary credential fallback',()=>{
  for(const [variant,mode,requestFlag] of [['required-mode-restricted-admin','restricted-admin','0x01'],['required-mode-remote-credential-guard','remote-credential-guard','0x02']]){
    const model=buildWindowsNegativeFixture('lab-win-rdp-required-mode-unsupported',variant),state=reconstructProtocolState(model,model.steps().length-1).windows;
    assert.equal(state.rdpRequestedMode,mode);assert.equal(state.rdpModeSupported,false);
    assert.equal(state.sessionEstablished,false);assert.equal(state.credentialsReceived,false);
    assert.equal(model.steps().some(step=>step.winStage==='inner-tls'||step.winStage==='authinfo-create'),false);
    assert.ok(model.steps().find(step=>step.winStage==='rdp-request').payload.some(field=>String(field.value).includes(requestFlag)));
  }
  const unavailable=winModel('rdp-rcg-kerberos-unavailable');
  assert.equal(unavailable.steps().some(step=>step.protocolLabel.includes('NTLM')||step.winStage==='authinfo-create'),false);
});

test('Remote Guard uses actual RDPEAR call pairs with H-to-KDC traffic and scoped host service tickets',()=>{
  const model=winModel('rdp-remote-credential-guard'),steps=model.steps();
  for(const stage of ['version','authdata','checksum','authenticator','unpack']){
    const request=steps.find(step=>step.winStage==='redirect-'+stage+'-request'),response=steps.find(step=>step.winStage==='redirect-'+stage+'-response');
    assert.equal(request.from,'winHost');assert.equal(request.to,'winClient');
    assert.equal(response.from,'winClient');assert.equal(response.to,'winHost');assert.ok(request.protocolLabel.includes('MS-RDPEAR'));
  }
  assert.ok(steps.find(step=>step.winStage==='redirect-version-request').payload.some(field=>String(field.value).includes('MaxSupportedVersion=0')));
  assert.ok(steps.find(step=>step.winStage==='redirect-unpack-request').payload.some(field=>String(field.value).includes('KeyUsage=8')));
  const tgs=steps.find(step=>step.winStage==='downstream-tgs-request');assert.equal(tgs.from,'winHost');assert.equal(tgs.to,'winDC');
  assert.equal(model.windowsInventory.artifacts.some(artifact=>['downstream-tgt','downstream-tgt-key','downstream-account-key','delegated-credentials'].includes(artifact.key)),false);
  assert.equal(winAt(model,'downstream-tgs-reply').downstreamAuthenticated,undefined);
  assert.equal(winAt(model,'downstream-verify-resource').downstreamIdentity,'CORP\\alice');
  assert.equal(winAt(model,'downstream-verify-resource').resourceAuthorized,false);
  assert.equal(winAt(model,'resource-acl').resourceAuthorized,true);
});

test('WinRM HTTP/HTTPS have identical inner CredSSP boundaries and distinct outer associations; failed second hop preserves shell',()=>{
  for(const suffix of ['winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied']){
    const model=winModel(suffix);
    assert.equal(winAt(model,'authinfo-receive').credentialsReceived,false);
    assert.equal(winAt(model,'authinfo-unwrap').credentialsReceived,true);
    assert.equal(winAt(model,'authinfo-unwrap').sessionEstablished,false);
    assert.equal(winAt(model,'winrm-session').sessionEstablished,true);
    assert.equal(winAt(model,'winrm-session').resourceAuthorized,false);
    assert.ok(model.steps().some(step=>step.layers.some(layer=>layer.protocol==='HTTP CredSSP authentication framing')));
    if(suffix==='winrm-credssp-http')assert.equal(model.windowsInventory.artifacts.some(artifact=>artifact.key==='outer-tls-key'),false);
    else assert.ok(model.windowsInventory.artifacts.some(artifact=>artifact.key==='outer-tls-key'));
  }
  const denied=winModel('winrm-resource-denied');
  assert.equal(winAt(denied,'resource-acl-deny').downstreamAuthenticated,true);
  assert.equal(winAt(denied,'resource-acl-deny').resourceAuthorized,false);
  assert.equal(winAt(denied,'resource-acl-deny').credentialsReceived,true);
  assert.equal(winAt(denied,'resource-acl-deny').sessionEstablished,true);
  const noDelegation=winModel('winrm-second-hop-denied');
  assert.equal(winAt(noDelegation,'downstream-no-credential').sessionEstablished,true);
  assert.equal(noDelegation.steps().some(step=>step.winStage==='downstream-as-request'),false);
});

test('Named negative profiles reject exact bad inputs and do not mutate registered definitions or invent success',()=>{
  const originalKeys=Object.keys(WINDOWSLAB_ATTRIBUTES),originalDefinitions=WINDOWSLAB_SCENARIOS.map(model=>JSON.stringify(model.definitions()));
  for(const model of WINDOWSLAB_SCENARIOS)for(const variant of model.negativeCases){
    const negative=buildWindowsNegativeFixture(model.id,variant),state=reconstructProtocolState(negative,negative.steps().length-1).windows;
    if(variant.startsWith('binding-')){assert.equal(state.failure,'binding');assert.equal(state.mechanismComplete,true);assert.equal(state.credentialsReceived,false);assert.equal(negative.steps().some(step=>step.winStage==='authinfo-create'),false);}
    else if(variant==='missing-last-token'||variant==='missing-pubKeyAuth'){assert.equal(state.failure,'malformed-TSRequest');assert.equal(state.mechanismComplete,false);assert.equal(state.credentialsReceived,false);const combined=negative.steps().find(step=>step.winStage==='last-token-binding');assert.ok(combined);assert.equal(combined.fields.some(field=>variant==='missing-pubKeyAuth'?field.endsWith('_client-binding'):field.endsWith('_ap-request')||field.endsWith('_authenticate')),false);}
    else if(['wrong-account-authority','expired-prerequisite','failed-prerequisite','missing-target-info','insufficient-key-strength'].includes(variant)){assert.equal(state.mechanismComplete,false);assert.equal(state.credentialsReceived,false);assert.equal(state.resourceAuthorized,false);}
    else if(variant==='bad-response'||variant==='ntlm-policy-server'||variant==='ntlm-policy-domain'){assert.equal(state.mechanismComplete,false);assert.equal(state.credentialsReceived,false);assert.equal(state.resourceAuthorized,false);if(variant==='ntlm-policy-domain')assert.ok(negative.steps().find(step=>step.winStage==='failure').payload.some(field=>String(field.value).includes('STATUS_NOT_SUPPORTED')));}
    else if(variant==='credential-protection-restriction'){assert.equal(state.failure,'delegation-policy');assert.equal(state.transportReady,false);assert.equal(state.credentialsReceived,false);}
    else if(variant==='redirect-disconnect'){assert.equal(state.sessionEstablished,false);assert.equal(state.redirectedContext,false);assert.equal(state.redirectChannelOpen,false);assert.equal(state.downstreamResourceSessionEstablished,true);assert.equal(state.resourceAuthorized,true);}
  }
  assert.deepEqual(Object.keys(WINDOWSLAB_ATTRIBUTES),originalKeys);
  assert.deepEqual(WINDOWSLAB_SCENARIOS.map(model=>JSON.stringify(model.definitions())),originalDefinitions);
  assert.throws(()=>buildWindowsNegativeFixture('lab-win-ntlmv2-domain','invented-fallback'),RangeError);
});


test('NTLM successful authority return does not bypass acceptor exported-key recovery and transcript MIC validation',()=>{
  for(const suffix of ['ntlmv2-domain','ntlmv2-local','ntlmv2-trust','negotiate-ntlm-allowed','credssp-v6-ntlm']){
    const model=winModel(suffix);
    assert.equal(winAt(model,'validation-result').mechanismComplete,false);
    assert.equal(winAt(model,'ntlm-key-process').mechanismComplete,false);
    assert.notEqual(winAt(model,'ntlm-key-process').ntlmMicVerified,true);
    assert.equal(winAt(model,'ntlm-mic-verify').ntlmMicVerified,true);
    assert.equal(winAt(model,'ntlm-mic-verify').mechanismComplete,false);
    assert.equal(winAt(model,'context').mechanismComplete,true);
    assert.ok(winIndex(model,'validation-result')<winIndex(model,'ntlm-key-process'));
    assert.ok(winIndex(model,'ntlm-key-process')<winIndex(model,'ntlm-mic-verify'));
    assert.ok(winIndex(model,'ntlm-mic-verify')<winIndex(model,'context'));
    assert.equal(model.profile.ntlmFieldRules.lmResponse,'Z(24)');
    assert.match(model.profile.ntlmFieldRules.channelBinding,/NULL/);
  }
  const blocked=winModel('negotiate-ntlm-blocked');
  assert.equal(blocked.steps().some(step=>step.winStage==='challenge'),false);
  assert.equal(blocked.steps().some(step=>step.winStage==='validation-request'),false);
  assert.ok(blocked.steps().find(step=>step.winStage==='policy-deny').payload.some(field=>String(field.value).includes('STATUS_NOT_SUPPORTED')));
});

test('Named reverse-binding negatives mutate exact hash inputs rather than a generic failure switch',()=>{
  const inputs=[['binding-direction','CredSSP Client-To-Server Binding Hash'],['binding-nonce','010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'],['binding-public-key','294-byte DER SubjectPublicKeyInfo']];
  for(const [variant,input] of inputs){
    const model=buildWindowsNegativeFixture('lab-win-credssp-v6-kerberos',variant);
    const proof=model.windowsInventory.artifacts.find(item=>item.key==='server-binding');
    assert.ok(proof.value.includes(input));assert.ok(proof.wireValue.includes(input));
    assert.equal(winAt(model,'binding-reject').credentialsReceived,false);
  }
});

test('Fresh-credential protection is an explicit exact-SPN DenyFreshCredentials policy, not an invented platform-wide ban',()=>{
  for(const suffix of ['credssp-v6-kerberos','winrm-credssp-second-hop','winrm-delegation-denied','winrm-credssp-http']){
    const model=buildWindowsNegativeFixture('lab-win-'+suffix,'credential-protection-restriction');
    const policy=model.windowsInventory.artifacts.find(item=>item.key==='policy');
    assert.ok(policy.value.includes('DenyFreshCredentials'));
    assert.ok(policy.value.includes(suffix.startsWith('winrm-')?'WSMAN/host.corp.example':'TERMSRV/host.corp.example'));
    assert.equal(winAt(model,'export-policy').transportReady,false);
    assert.equal(winAt(model,'export-policy').credentialsReceived,false);
  }
});

test('WinRM CredSSP body protection uses the inner TLS context; outer HTTP completion is not an inner TSRequest',()=>{
  for(const suffix of ['winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied']){
    const model=winModel(suffix);
    for(const stage of ['winrm-shell-request','winrm-session-result','winrm-command-result']){
      const layer=model.steps().find(step=>step.winStage===stage).layers.find(item=>item.protocol==='HTTP / WS-Management encrypted body');
      assert.equal(layer.keyRef,model.id+':tls-inner-key');
    }
    const complete=model.steps().find(step=>step.winStage==='http-credssp-complete');
    assert.equal(complete.layers.some(layer=>layer.keyRef===model.id+':tls-inner-key'),false);
  }
  assert.equal(Object.hasOwn(winModel('ntlmv2-domain').profile.cryptoDetail,'binding'),false);
});

test('WIN-01 raw CredSSP NTLM failure remains a v6 TSRequest error and changes client knowledge only at receipt',()=>{
  const model=buildWindowsNegativeFixture('lab-win-credssp-v6-ntlm','bad-response');
  const failure=model.steps().find(step=>step.winStage==='failure');
  assert.equal(model.profile.outerTransport,'CredSSP over TCP');
  assert.equal(winAt(model,'dc-verify').authorityKnowsFailure,true);
  assert.equal(winAt(model,'dc-verify').serverKnowsFailure,false);
  assert.equal(winAt(model,'validation-result').serverKnowsFailure,true);
  assert.equal(winAt(model,'validation-result').clientKnowsFailure,false);
  assert.match(failure.protocolLabel,/TSRequest v6/);
  assert.match(failure.payload[0].value,/errorCode=STATUS_LOGON_FAILURE \(0xC000006D\)/);
  assert.doesNotMatch(failure.payload[0].value,/HTTP|Negotiate/);
  assert.equal(failure.httpCarrier,undefined);
  const terminal=winAt(model,'failure');
  assert.equal(terminal.clientKnowsFailure,true);assert.equal(terminal.credsspStopped,true);
  assert.equal(terminal.mechanismComplete,false);assert.equal(terminal.authInfoReceived,false);
  assert.equal(model.steps().some(step=>step.winStage==='authinfo-create'),false);
});

test('WIN-02 every HTTP response consumes exactly one pending request, including grouped CredSSP inner records',()=>{
  const models=WINDOWSLAB_SCENARIOS.flatMap(model=>[model,...model.negativeCases.map(variant=>buildWindowsNegativeFixture(model.id,variant))]);
  for(const model of models){
    let outstanding=null;
    const responses=new Set();
    for(const step of model.steps()){
      const carrier=step.httpCarrier;if(!carrier)continue;
      if(carrier.kind==='request'){
        assert.equal(outstanding,null,model.id+'/'+step.winStage);
        outstanding=carrier.requestId;
      }else{
        assert.equal(carrier.requestId,outstanding,model.id+'/'+step.winStage);
        assert.ok(!responses.has(carrier.responseId));
        responses.add(carrier.responseId);outstanding=null;
      }
    }
    // A named local rejection can intentionally abandon its pending request.
    if(outstanding)assert.ok(model.profile.negativeVariant,model.id);
  }
  const kerberos=winModel('negotiate-kerberos');
  assert.equal(kerberos.steps().find(step=>step.winStage==='ap-reply').eventType,'local');
  const final=kerberos.steps().find(step=>step.winStage==='result');
  assert.equal(final.httpCarrier.status,200);
  assert.deepEqual(final.httpCarrier.innerRecords,['ap-reply','http-result']);
  assert.equal(winAt(kerberos,'result').clientMechanismAccepted,false);
  assert.equal(winAt(kerberos,'result').clientResult,undefined);
  assert.equal(winAt(kerberos,'mutual-verify').clientMechanismAccepted,true);
  assert.equal(winAt(kerberos,'mutual-verify').clientResult,undefined);
  assert.equal(winAt(kerberos,'result-accept').clientResult,'success');
  for(const suffix of ['winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied']){
    const model=winModel(suffix),response=model.steps().find(step=>step.winStage==='server-binding');
    assert.deepEqual(response.httpCarrier.innerRecords,['ap-reply','server-binding']);
    assert.equal(winAt(model,'server-binding').clientMechanismAccepted,false);
    assert.equal(winAt(model,'mutual-verify').bindingClientVerified,false);
    assert.equal(winAt(model,'binding-verify-client').bindingClientVerified,true);
  }
});

test('WIN-03 RESOURCE TargetInfo and CORP response-key/account authority coexist across direct-trust variants',()=>{
  for(const suffix of ['ntlmv2-trust','ntlmv2-trust-denied']){
    const model=winModel(suffix);
    for(const candidate of [model,...model.negativeCases.map(variant=>buildWindowsNegativeFixture(model.id,variant))]){
      assert.equal(candidate.profile.serverDomain,'RESOURCE');assert.equal(candidate.profile.accountDomain,'CORP');
      const challenge=candidate.windowsInventory.artifacts.find(artifact=>artifact.key==='server-challenge');
      if(!challenge)continue; // Explicit preflight rejection has no mechanism attempt.
      assert.match(challenge.value,/MsvAvNbDomainName=RESOURCE/);
      assert.match(candidate.windowsInventory.artifacts.find(artifact=>artifact.key==='authenticate').value,/DomainName=CORP/);
      assert.match(candidate.windowsInventory.artifacts.find(artifact=>artifact.key==='response-key').value,/UPPER\(alice\) \|\| CORP/);
    }
  }
});

test('WIN-04 NTLM-only selection cites local configuration, never a bare HTTP mechanism offer',()=>{
  for(const suffix of ['negotiate-ntlm-allowed','negotiate-ntlm-blocked']){
    const model=winModel(suffix),policy=model.windowsInventory.artifacts.find(artifact=>artifact.key==='policy');
    assert.match(policy.value,/Client endpoint mechanism allowlist=\[NTLM\]/);
    assert.equal(winAt(model,'offer').selectionReason,undefined);
    assert.equal(winAt(model,'select-ntlm').selectionReason,'configured-NTLM-only-profile');
    assert.equal(model.steps().find(step=>step.winStage==='offer').payload[0].value,'HTTP/1.1 401; WWW-Authenticate: Negotiate');
    assert.equal(model.steps().some(step=>step.winStage==='as-request'),false);
  }
});

test('WIN-05 and WIN-07 nondelegating WinRM executes a real protected operation and returns decoded failure without destroying shell',()=>{
  const model=winModel('winrm-second-hop-denied');
  const order=['http-kerberos-complete','mutual-verify','winrm-shell-request','winrm-shell-verify','logon','winrm-session','winrm-session-result','winrm-session-accept','winrm-command-request','winrm-command-verify','downstream-no-credential','winrm-command-result','winrm-command-accept'];
  for(let index=1;index<order.length;index++)assert.ok(winIndex(model,order[index-1])<winIndex(model,order[index]),order[index]);
  for(const stage of ['winrm-shell-request','winrm-command-request','winrm-command-result']){
    assert.equal(model.steps().find(step=>step.winStage===stage).layers.find(layer=>layer.protocol==='HTTP / WS-Management encrypted body').keyRef,model.id+':acceptor-subkey');
  }
  assert.notEqual(winAt(model,'winrm-session-result').clientKnowsSession,true);
  assert.equal(winAt(model,'winrm-session-accept').clientKnowsSession,true);
  assert.equal(winAt(model,'downstream-no-credential').clientKnowsFailure,false);
  assert.equal(winAt(model,'winrm-command-result').clientKnowsFailure,false);
  assert.notEqual(winAt(model,'winrm-command-result').clientKnowsResourceResult,true);
  const terminal=winAt(model,'winrm-command-accept');
  assert.equal(terminal.clientKnowsFailure,true);assert.equal(terminal.clientResult,'credential-unavailable');
  assert.equal(terminal.sessionEstablished,true);assert.equal(terminal.credentialsReceived,false);
  assert.equal(model.steps().some(step=>step.to==='winResource'),false);
});

test('WIN-08 guidance uses the selected authority and mechanism, not generic CORP/Netlogon defaults',()=>{
  const local=winModel('ntlmv2-local'),kerberos=winModel('negotiate-kerberos');
  assert.match(local.prerequisites[0],/^SERVER\\alice/);assert.doesNotMatch(local.prerequisites[0],/CORP/);
  assert.ok(local.profile.transports.some(value=>value.includes('Local LSA/SAM IPC')));
  assert.ok(kerberos.profile.transports.some(value=>value.includes('Kerberos AS/TGS')));
  assert.equal(kerberos.profile.transports.some(value=>value.includes('Netlogon')),false);
  assert.ok(kerberos.prerequisites.some(value=>value.includes('AES256 principal keys')));
});

for(const suffix of ['winrm-credssp-second-hop','winrm-credssp-http','winrm-resource-denied','rdp-normal','rdp-restricted-admin','rdp-remote-credential-guard'])test('WIN-09 '+suffix+' accepts the exact resource result before learning or forwarding it',()=>{
  const model=winModel(suffix),steps=model.steps(),result=model.windowsInventory.artifacts.find(item=>item.key==='resource-result');
  assert.ok(winIndex(model,'resource-result')<winIndex(model,'resource-result-accept'));
  const receipt=winAt(model,'resource-result'),accepted=winAt(model,'resource-result-accept');
  assert.equal(receipt.resourceResultReceived,true);
  assert.notEqual(receipt.serverKnowsResourceResult,true);
  assert.notEqual(receipt.resourceResultAccepted,true);
  assert.equal(receipt.serverKnowsFailure,false);
  assert.equal(accepted.resourceResultAccepted,true);
  assert.equal(accepted.serverKnowsResourceResult,true);
  assert.equal(accepted.acceptedResourceResult,result.artifactId);
  assert.equal(accepted.sessionEstablished,true);
  assert.equal(accepted.serverKnowsFailure,suffix==='winrm-resource-denied');
  if(suffix.startsWith('winrm-')){
    const output=model.windowsInventory.artifacts.find(item=>item.key==='winrm-command-result');
    assert.ok(winIndex(model,'resource-result-accept')<winIndex(model,'winrm-command-result'));
    assert.equal(output.value,result.value);
    assert.deepEqual(output.derivedFrom,[result.artifactId]);
    assert.deepEqual(output.valueProvenance,{artifactId:result.artifactId,representationId:'plain',exactValueRef:result.artifactId+':plain',sourceEventId:model.id+':resource-result-accept'});
    assert.deepEqual(steps.find(item=>item.winStage==='winrm-command-result').valueProvenance,output.valueProvenance);
    assert.equal(winAt(model,'winrm-command-accept').credentialsReceived,true);
  }
});

test('WIN-10 shared Windows AES profiles select a distinct completed context key without rewriting early CredSSP or TLS keys',()=>{
  for(const model of WINDOWSLAB_SCENARIOS.filter(item=>item.profile.selectedMechanism==='Kerberos'&&winIndex(item,'ap-verify')>=0)){
    const steps=model.steps(),key=model.windowsInventory.artifacts.find(item=>item.key==='acceptor-subkey');
    assert.ok(key,model.id);assert.equal(key.creator,'winHost');
    assert.equal(model.windowsInventory.artifacts.find(item=>item.key==='mechanism-key').creator,'winClient');
    assert.equal(winAt(model,'ap-verify').hostCompletedContextKey,undefined);
    assert.equal(winAt(model,'ap-reply').hostCompletedContextKey,key.artifactId);
    assert.equal(winAt(model,'mutual-verify').clientCompletedContextKey,key.artifactId);
    assert.ok(model.profile.sources.some(source=>source.standard==='MS-KILE'));
    assert.ok(model.profile.sources.some(source=>source.standard==='RFC 4121'));
    const early=steps.find(item=>item.winStage==='last-token-binding');
    if(early){
      const layer=early.layers.find(item=>item.keyRef===model.id+':mechanism-key');
      assert.ok(layer,model.id);assert.equal(layer.acceptorSubkey,false);
      const reverse=steps.find(item=>item.winStage==='server-binding').layers.find(item=>item.keyRef===key.artifactId);
      assert.ok(reverse);assert.equal(reverse.acceptorSubkey,true);
    }
    for(const step of steps){
      for(const layer of step.layers.filter(item=>item.protocol==='Kerberos AP-REP reciprocal proof'))assert.equal(layer.keyRef,model.id+':ticket-session-key');
      for(const layer of step.layers.filter(item=>item.protocol==='HTTP / WS-Management encrypted body'))assert.equal(layer.keyRef,model.id+(early?':tls-inner-key':':acceptor-subkey'));
    }
    for(const stage of ['server-binding','binding-verify-client','authinfo-create','authinfo-unwrap']){
      const step=steps.find(item=>item.winStage===stage);if(!step)continue;
      const uses=model.windowsInventory.events[step.id].milestones[0].effects.filter(item=>item.op==='observe'&&item.result.startsWith('used_for_'));
      assert.ok(uses.some(item=>item.artifactId===key.artifactId),model.id+' '+stage);
    }
  }
});

test('WIN-10 paths stopping before AP acceptance and all NTLM profiles have no acceptor key',()=>{
  for(const model of WINDOWSLAB_SCENARIOS){
    for(const candidate of [model,...model.negativeCases.map(variant=>buildWindowsNegativeFixture(model.id,variant))]){
      if(candidate.profile.selectedMechanism==='Kerberos'&&winIndex(candidate,'ap-verify')>=0)continue;
      assert.equal(candidate.windowsInventory.artifacts.some(item=>item.key==='acceptor-subkey'),false,candidate.id);
    }
    if(model.profile.selectedMechanism==='NTLM'&&winIndex(model,'context')>=0){
      assert.match(model.windowsInventory.artifacts.find(item=>item.key==='mechanism-key').value,/ExportedSessionKey/);
      for(const stage of ['last-token-binding','server-binding','authinfo-receive']){
        const step=model.steps().find(item=>item.winStage===stage);if(!step)continue;
        assert.ok(step.layers.some(layer=>layer.keyRef===model.id+':mechanism-key'));
        assert.equal(step.layers.some(layer=>layer.acceptorSubkey===true),false);
      }
      for(const step of model.steps())for(const layer of step.layers)assert.notEqual(layer.keyRef,model.id+':acceptor-subkey');
    }
  }
});
