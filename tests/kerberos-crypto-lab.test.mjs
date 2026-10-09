import test from 'node:test';
import assert from 'node:assert/strict';
import {CRYPTOLAB_ATTRIBUTES,CRYPTOLAB_SCENARIOS,CRYPTOLAB_SOURCES} from '../src/kerberos-crypto-lab.js';
import {buildProtocolInstances,reconstructProtocolState,validateProtocolScenario} from '../src/protocol-state.js';

const cryptoModel=id=>CRYPTOLAB_SCENARIOS.find(model=>model.id===id);
const cryptoStage=(model,key)=>model.steps().find(step=>step.labCryptoStage===key);
const cryptoIndex=(model,key)=>model.steps().findIndex(step=>step.labCryptoStage===key);
const cryptoId=(model,name)=>Object.entries(model.definitions()).find(([,def])=>def.name===name)?.[0];
const cryptoOps=(model,id)=>model.steps().flatMap(step=>step.attributeOperations.filter(op=>op.attributeId===id).map(op=>({...op,eventId:step.id,channel:step.channel})));
const cryptoEnd=model=>reconstructProtocolState(model,model.steps().length-1);

test('all crypto fixtures have independent definitions, exact occurrences and valid frozen state at every prefix',()=>{
  assert.equal(CRYPTOLAB_SCENARIOS.length,17);
  const allIds=new Set();
  for(const model of CRYPTOLAB_SCENARIOS){
    assert.equal(model.workspace,'kerberos');assert.equal(model.family,'ad-ds');assert.equal(model.status,'reference');
    assert.equal(model.initialState.protocolClock,1791381600);assert.equal(model.factorSelectable,false);
    assert.deepEqual(validateProtocolScenario(model),{valid:true,errors:[],warnings:[]},model.id);
    assert.deepEqual(new Set(Object.keys(model.definitions())),new Set(model.ids));
    assert.ok(model.supportNote);assert.ok(model.positions.cryptoKdc);
    const steps=model.steps();assert.equal(steps,model.steps());assert.ok(Object.isFrozen(steps));
    for(let index=-1;index<steps.length;index++){
      const state=reconstructProtocolState(model,index),instances=buildProtocolInstances(model,index);
      assert.ok(Object.isFrozen(state));assert.ok(Object.isFrozen(instances));assert.equal(state.protocolClock,1791381600);
      for(const instance of instances)for(const occurrence of instance.occurrences){
        assert.ok(occurrence.eventIndex<=index);assert.ok(occurrence.fieldPath);assert.ok(occurrence.representation);assert.ok(occurrence.exactValueRef);assert.notEqual(occurrence.value,undefined);
      }
    }
    for(const id of model.ids){allIds.add(id);const definition=model.definitions()[id];for(const property of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(definition[property],model.id+' '+id+' '+property);}
  }
  assert.deepEqual(allIds,new Set(Object.keys(CRYPTOLAB_ATTRIBUTES)));
  assert.ok(CRYPTOLAB_SOURCES.every(source=>/^https:\/\/(www\.rfc-editor\.org|learn\.microsoft\.com|support\.microsoft\.com)/.test(source.url)));
});

test('private signing/DH/challenge/reply/session keys never become KDC packets; armor support is explicitly local IPC',()=>{
  for(const model of CRYPTOLAB_SCENARIOS)for(const step of model.steps()){
    for(const operation of step.attributeOperations){
      if(['send','receive'].includes(operation.kind)&&step.channel!=='local-ipc')assert.notEqual(model.definitions()[operation.attributeId].sensitive,true,model.id+' '+step.id+' '+operation.attributeId);
    }
  }
});

test('PKINIT uses two separate nonce bindings and local fresh DH while keeping reply and ticket-session keys distinct',()=>{
  const model=cryptoModel('lab-ad-pkinit-success');
  const body=cryptoId(model,'nonce (KDC-REQ-BODY)'),pk=cryptoId(model,'pkAuthenticator.nonce'),dh=cryptoId(model,'nonce (KDCDHKeyInfo)'),reply=cryptoId(model,'nonce (EncASRepPart)');
  assert.equal(model.definitions()[body].example,'41001');assert.equal(model.definitions()[pk].example,'72002');
  assert.equal(model.definitions()[dh].example,model.definitions()[pk].example);assert.equal(model.definitions()[reply].example,model.definitions()[body].example);
  assert.notEqual(body,pk);assert.ok(cryptoStage(model,'kdc-reply-check').fields.includes(pk));assert.ok(cryptoStage(model,'accept-tgt').fields.includes(body));
  for(const absent of ['clientDHNonce','serverDHNonce','dhKeyExpiration'])assert.equal(Object.values(model.definitions()).some(def=>def.name===absent),false);
  const ids=['DH shared secret (local)','AS reply key (local)','key (EncASRepPart)'].map(name=>cryptoOps(model,cryptoId(model,name))[0].instanceId);
  assert.equal(new Set(ids).size,3);
  const before=reconstructProtocolState(model,cryptoIndex(model,'client-key'));assert.equal(before.credentials.userTgt,undefined);
  const accepted=reconstructProtocolState(model,cryptoIndex(model,'accept-tgt'));
  assert.notEqual(accepted.credentials.userTgt.instanceId,accepted.credentials.userTgt.sessionKeyInstanceId);
  assert.equal(cryptoEnd(model).sessions.service.authorized,true);
  assert.notEqual(cryptoEnd(model).credentials.service.instanceId,cryptoEnd(model).credentials.service.sessionKeyInstanceId);
});

test('PKINIT rejection is detected at the right actor without accepting a user credential',()=>{
  for(const [variant,reason,actor] of [['binding','strong-binding','cryptoAs'],['trust','client-certificate-trust','cryptoAs'],['kdc-trust','kdc-certificate-trust','cryptoClient']]){
    const model=cryptoModel('lab-ad-pkinit-'+variant),end=cryptoEnd(model);
    assert.equal(end.credentials.userTgt,undefined);assert.equal(end.sessions.service,undefined);assert.equal(end.knowledge.client.failure,reason);
    const rejected=cryptoStage(model,variant==='kdc-trust'?'client-reject':'kdc-reject');assert.equal(rejected.from,actor);
    if(variant!=='kdc-trust'){
      assert.equal(end.keys.asReplyKdc,undefined);
      assert.equal(reconstructProtocolState(model,cryptoIndex(model,'kdc-reject')).knowledge.client.failure,undefined);
    }else{
      assert.ok(end.keys.asReplyKdc);assert.equal(end.keys.asReplyClient,undefined);
    }
  }
});

test('actual holder chronology does not give the KDC a freshly created request before transmission',()=>{
  const model=cryptoModel('lab-ad-pkinit-success'),bodyId=cryptoId(model,'KDC-REQ-BODY');
  const instanceId=cryptoOps(model,bodyId)[0].instanceId;
  const initial=buildProtocolInstances(model,cryptoIndex(model,'authpack')).find(instance=>instance.instanceId===instanceId);
  assert.ok(initial.holders.includes('cryptoClient'));assert.equal(initial.holders.includes('cryptoAs'),false);
  const sent=buildProtocolInstances(model,cryptoIndex(model,'as-request')).find(instance=>instance.instanceId===instanceId);
  assert.ok(sent.holders.includes('cryptoAs'));
});

test('FAST user AS separates computer credential, user challenge and locally strengthened reply',()=>{
  const model=cryptoModel('lab-ad-fast-as-success'),end=cryptoEnd(model);
  assert.equal(end.credentials.computerTgt.owner,'cryptoComputer');assert.equal(end.credentials.userTgt.owner,'cryptoClient');
  assert.notEqual(end.credentials.computerTgt.instanceId,end.credentials.userTgt.instanceId);
  assert.notEqual(end.keys.armorClient.instanceId,end.keys.finalReplyClient.instanceId);
  assert.notEqual(end.keys.clientChallenge.instanceId,end.keys.finalReplyClient.instanceId);
  assert.equal(end.checks.userChallenge,true);assert.equal(end.checks.fastCredentialAccepted,true);
  const request=cryptoStage(model,'fast-request');
  assert.ok(request.payload.some(field=>field.name==='armor (KrbFastArmoredReq)'));
  for(const name of ['req-body (KrbFastReq)','PA-ENCRYPTED-CHALLENGE (138)','strengthen-key','key (EncASRepPart)'])assert.equal(cryptoOps(model,cryptoId(model,name)).some(op=>['send','receive'].includes(op.kind)),false,name);
  assert.equal(cryptoStage(model,'armor-local-api').eventType,'localIPC');
  const armorKey=cryptoId(model,'armor_key (local)');
  assert.equal(cryptoOps(model,armorKey).filter(op=>['send','receive'].includes(op.kind)).every(op=>op.channel==='local-ipc'),true);
  assert.equal(cryptoOps(model,cryptoId(model,'Client encrypted-challenge key (local)')).some(op=>op.actorId==='cryptoAs'&&op.kind==='derive'),true);
  assert.equal(cryptoOps(model,cryptoId(model,'KDC encrypted-challenge key (local)')).some(op=>op.actorId==='cryptoClient'&&op.kind==='derive'),true);
});

test('computer bootstrap is permitted under enforced FAST but never authenticates Alice',()=>{
  const model=cryptoModel('lab-ad-fast-as-bootstrap'),end=cryptoEnd(model);
  assert.equal(model.initialState.policy.kdcEnforceFAST,true);assert.equal(end.checks.bootstrapExceptionApplied,true);
  assert.equal(end.credentials.computerTgt.owner,'cryptoComputer');assert.equal(end.credentials.userTgt,undefined);
  assert.notEqual(end.credentials.computerTgt.instanceId,end.credentials.computerTgt.sessionKeyInstanceId);
  assert.equal(Object.values(model.definitions()).some(def=>def.name==='PA-FX-FAST (request)'),false);
  const ticket=cryptoId(model,'ticket (armor TGT)');assert.equal(cryptoOps(model,ticket)[0].sourceEventId,model.id+'-bootstrap-policy');
});

test('required FAST fails closed on prerequisites/armor while optional fallback is separately explicit',()=>{
  const missing=cryptoModel('lab-ad-fast-as-required-armor'),unsupported=cryptoModel('lab-ad-fast-as-unsupported-dc'),optional=cryptoModel('lab-ad-fast-as-optional-fallback');
  assert.equal(cryptoEnd(missing).knowledge.client.failure,'required-armor-absent');assert.equal(cryptoEnd(missing).credentials.userTgt,undefined);
  assert.ok(cryptoEnd(missing).credentials.computerTgt);
  assert.equal(unsupported.steps().every(step=>step.from===step.to),true);assert.equal(cryptoEnd(unsupported).knowledge.client.failure,'required-fast-no-suitable-dc');
  assert.equal(optional.initialState.policy.requireFAST,false);assert.equal(optional.initialState.policy.kdcEnforceFAST,false);
  assert.equal(cryptoEnd(optional).checks.fallbackUserAuthenticated,true);assert.equal(cryptoEnd(optional).checks.fastCredentialAccepted,undefined);
  assert.equal(Object.values(optional.definitions()).some(def=>def.name==='PA-FX-FAST (request)'),false);
});

test('bad FAST request checksum stops before KDC inner-body decode; challenge failures preserve existing credentials',()=>{
  const bad=cryptoModel('lab-ad-fast-as-checksum'),binding=cryptoStage(bad,'request-binding');
  assert.equal(binding.attributeOperations.some(op=>op.attributeId===cryptoId(bad,'enc-fast-req')&&op.actorId==='cryptoAs'&&op.kind==='use'),false);
  assert.equal(binding.fields.includes(cryptoId(bad,'req-body (KrbFastReq)')),false);
  for(const variant of ['checksum','challenge']){
    const model=cryptoModel('lab-ad-fast-as-'+variant),end=cryptoEnd(model);
    assert.ok(end.credentials.computerTgt);assert.equal(end.credentials.userTgt,undefined);assert.ok(end.knowledge.client.failure);
    assert.equal(Object.values(model.definitions()).some(def=>def.name==='strengthen-key'),false);
    assert.equal(Object.values(model.definitions()).some(def=>def.name==='finished'),false);
  }
});

test('FAST protected response failures never cache a returned credential or invent an early client result',()=>{
  for(const [variant,reason] of [['missing-response','missing-protected-response'],['response-nonce','protected-response-nonce'],['ticket-binding','finished-ticket-binding']]){
    const model=cryptoModel('lab-ad-fast-as-'+variant),end=cryptoEnd(model);
    assert.equal(reconstructProtocolState(model,cryptoIndex(model,'fast-response')).knowledge.client.failure,undefined);
    assert.equal(end.knowledge.client.failure,reason);assert.equal(end.credentials.userTgt,undefined);assert.ok(end.credentials.computerTgt);
  }
  const nonce=cryptoModel('lab-ad-fast-as-response-nonce'),id=cryptoId(nonce,'nonce (KrbFastResponse)');
  assert.deepEqual(new Set(cryptoOps(nonce,id).map(op=>op.value)),new Set(['51002']));
  const ticket=cryptoModel('lab-ad-fast-as-ticket-binding');assert.match(ticket.definitions()[cryptoId(ticket,'ticket-checksum')].example,/DIFFERENT Ticket/);
});

test('ordinary FAST TGS omits explicit armor, binds AP-REQ and retains the same subkey as original reply key',()=>{
  const model=cryptoModel('lab-ad-fast-tgs-success'),defs=model.definitions(),end=cryptoEnd(model);
  assert.equal(Object.values(defs).some(def=>def.name==='armor (KrbFastArmoredReq)'),false);
  assert.equal(Object.values(defs).some(def=>def.name==='PA-ENCRYPTED-CHALLENGE (138)'),false);
  assert.ok(cryptoStage(model,'tgs-request').payload.some(field=>field.name==='PA-TGS-REQ'));
  const checksum=defs[cryptoId(model,'req-checksum')].example;assert.match(checksum,/DER PA-TGS-REQ AP-REQ/);assert.doesNotMatch(checksum,/outer KDC-REQ-BODY/);
  const subkey=cryptoOps(model,cryptoId(model,'subkey (armor Authenticator)'))[0].instanceId;
  const original=cryptoOps(model,cryptoId(model,'padata-reply-key (local)'))[0].instanceId;
  assert.equal(subkey,original);assert.equal(end.keys.originalReplyClient.instanceId,subkey);
  assert.notEqual(end.keys.finalReplyClient.instanceId,subkey);assert.equal(end.checks.fastStrengthenPresent,true);
  assert.ok(end.credentials.userTgt);assert.ok(end.credentials.service);
});

test('required FAST TGS construction and reply failures preserve the initial user TGT',()=>{
  for(const [variant,reason] of [['missing-subkey','mandatory-tgs-subkey-absent'],['missing-strengthen','missing-tgs-strengthen-key']]){
    const model=cryptoModel('lab-ad-fast-tgs-'+variant),end=cryptoEnd(model);
    assert.equal(end.knowledge.client.failure,reason);assert.ok(end.credentials.userTgt);assert.equal(end.credentials.service,undefined);
    if(variant==='missing-subkey'){assert.equal(end.keys.armorKdc,undefined);assert.equal(end.keys.tgsSubkey,undefined);}
    else assert.equal(end.checks.fastStrengthenPresent,false);
  }
});

test('only scalar realm/SPN runtime fields are bound; internals preserve stable AS/TGS logical ownership',()=>{
  for(const model of CRYPTOLAB_SCENARIOS){
    assert.equal(new Set(model.runtimeBindings.map(binding=>binding.field)).size,model.runtimeBindings.length);
    for(const binding of model.runtimeBindings){assert.equal(model.definitions()[binding.attributeId].example,binding.example);assert.equal(binding.replacementMode,undefined);}
    const actors=model.actors();
    for(const step of model.steps())for(const actorId of [step.from,step.to]){
      assert.ok(actors[actorId]);if(['cryptoAs','cryptoTgs'].includes(actorId))assert.equal(actors[actorId].parentId,'cryptoKdc');
    }
  }
  const success=cryptoModel('lab-ad-pkinit-success');assert.equal(success.featured,true);
  assert.equal(cryptoStage(success,'as-request').to,'cryptoAs');assert.equal(cryptoStage(success,'tgs-request').to,'cryptoTgs');
});

test('typed realm context reconstructs every request, issued envelope and credential without mutating base fixtures',()=>{
  const originalRegistry=JSON.stringify(CRYPTOLAB_ATTRIBUTES);
  const originals=CRYPTOLAB_SCENARIOS.map(model=>JSON.stringify({definitions:model.definitions(),steps:model.steps(),actors:model.actors(),initialState:model.initialState}));
  for(const [index,base] of CRYPTOLAB_SCENARIOS.entries()){
    const model=base.contextualize({kerberosRealm:'CORP.EXAMPLE',servicePrincipal:'LDAP/directory.network.example'});
    assert.notEqual(model,base);assert.notEqual(model.definitions(),base.definitions());assert.notEqual(model.steps(),base.steps());
    const serialized=JSON.stringify({definitions:model.definitions(),steps:model.steps(),actors:model.actors(),initialState:model.initialState});
    assert.equal(serialized.includes('A.EXAMPLE'),false,base.id+' stale realm');assert.equal(serialized.includes('HTTP/intranet.a.example'),false,base.id+' stale SPN');
    assert.deepEqual(validateProtocolScenario(model),{valid:true,errors:[],warnings:[]});
    assert.ok(Object.isFrozen(model.definitions()));assert.ok(Object.isFrozen(model.steps()));assert.ok(Object.isFrozen(model.initialState));
    for(const [credentialName,credential] of Object.entries(cryptoEnd(model).credentials)){
      if(credential.crealm)assert.equal(credential.crealm,'CORP.EXAMPLE');
      if(credential.sname)assert.equal(credential.sname,credentialName==='service'?'LDAP/directory.network.example':'krbtgt/CORP.EXAMPLE');
    }
    assert.equal(JSON.stringify({definitions:base.definitions(),steps:base.steps(),actors:base.actors(),initialState:base.initialState}),originals[index]);
  }
  assert.equal(JSON.stringify(CRYPTOLAB_ATTRIBUTES),originalRegistry);
  const rebuilt=cryptoModel('lab-ad-pkinit-success').contextualize({kerberosRealm:'CORP.EXAMPLE'});
  assert.match(rebuilt.definitions()[cryptoId(rebuilt,'KDC-REQ-BODY')].example,/realm=CORP.EXAMPLE, sname=krbtgt\/CORP.EXAMPLE/);
  assert.match(rebuilt.definitions()[cryptoId(rebuilt,'PA-PK-AS-REQ.signedAuthPack')].example,/realm=CORP.EXAMPLE/);
  assert.equal(cryptoEnd(rebuilt).credentials.userTgt.sname,'krbtgt/CORP.EXAMPLE');
  assert.equal(cryptoEnd(rebuilt).sessions.service.principal,'alice@CORP.EXAMPLE');
  assert.equal(cryptoEnd(rebuilt).credentials.service.sname,'HTTP/intranet.a.example','realm and target hostname/SPN are independent inputs');
});

test('missing implicit FAST subkey is a local construction stop and distinguishes ordinary non-FAST optionality',()=>{
  const model=cryptoModel('lab-ad-fast-tgs-missing-subkey'),last=cryptoEnd(model),failure=cryptoStage(model,'missing-subkey-reject');
  assert.equal(failure.from,'cryptoClient');assert.equal(failure.to,'cryptoClient');
  assert.ok(model.steps().every(step=>step.from===step.to));
  assert.equal(model.steps().flatMap(step=>step.attributeOperations).some(operation=>['send','receive'].includes(operation.kind)),false);
  assert.equal(last.checks.implicitArmorConstructible,false);assert.equal(last.checks.ordinaryNonFastSubkeyOptional,true);
  assert.equal(last.knowledge.kdc.failure,undefined);assert.equal(last.knowledge.client.failure,'mandatory-tgs-subkey-absent');
  assert.deepEqual(last.credentials,model.initialState.credentials);
  assert.equal(last.keys.armorClient,undefined);assert.equal(last.keys.armorKdc,undefined);
  assert.match(failure.detail,/ordinary non-FAST TGS exchange Authenticator\.subkey is optional/);
});

test('protected FAST errors carry RFC 6113 METHOD-DATA and PA-FX-ERROR lineage before local knowledge',()=>{
  for(const variant of ['checksum','challenge']){
    const model=cryptoModel('lab-ad-fast-as-'+variant),wire=cryptoStage(model,'error-result'),decode=cryptoStage(model,'decode-error');
    const fast=cryptoId(model,'PA-FX-FAST (reply)'),enc=cryptoId(model,'enc-fast-rep'),inner=cryptoId(model,'KRB-ERROR (inside PA-FX-ERROR)'),outer=cryptoId(model,'KRB-ERROR (outer FAST error)'),pafx=cryptoId(model,'PA-FX-ERROR (137)');
    assert.equal(wire.attributeOperations.find(op=>op.attributeId===fast).fieldPath,'KRB-ERROR.e-data.METHOD-DATA.PA-FX-FAST');
    assert.equal(wire.attributeOperations.find(op=>op.attributeId===enc).fieldPath,'KRB-ERROR.e-data.METHOD-DATA.PA-FX-FAST.armored-data.enc-fast-rep');
    assert.ok(wire.attributeOperations.every(op=>!op.fieldPath.startsWith('KDC-REP.')));
    assert.equal(wire.attributeOperations.some(op=>op.attributeId===inner||op.attributeId===pafx),false,'inner plaintext is not a transmitted field');
    const decoded=model.definitions()[inner].example,transported=model.definitions()[outer].example;
    assert.equal(Object.hasOwn(decoded,'e-data'),false);
    const {'e-data':eData,...outerFields}=transported;assert.match(eData,/METHOD-DATA/);assert.deepEqual(outerFields,decoded);
    assert.equal(model.definitions()[pafx].example['padata-type'],137);assert.deepEqual(model.definitions()[pafx].example['padata-value'],decoded);
    const nonceOperation=decode.attributeOperations.find(op=>model.definitions()[op.attributeId].name==='nonce (KrbFastResponse)');
    const responseOperation=decode.attributeOperations.find(op=>model.definitions()[op.attributeId].name==='KrbFastResponse (error)');
    assert.equal(nonceOperation.instanceId,responseOperation.instanceId);assert.equal(nonceOperation.value,responseOperation.value.nonce);
    assert.ok(decode.attributeOperations.findIndex(op=>op.attributeId===enc&&op.kind==='use')<decode.attributeOperations.findIndex(op=>op.attributeId===inner&&op.kind==='verify'));
    const wireState=reconstructProtocolState(model,cryptoIndex(model,'error-result'));
    assert.equal(wireState.knowledge.client.failure,undefined);assert.equal(wireState.checks.protectedErrorDecoded,undefined);
    const wireInner=buildProtocolInstances(model,cryptoIndex(model,'error-result')).find(instance=>instance.instanceId===cryptoOps(model,inner)[0].instanceId);
    assert.equal(wireInner.holders.includes('cryptoClient'),false,'client has not decoded the inner object');
    const last=cryptoEnd(model);assert.equal(last.knowledge.client.failure,decoded['e-text']);assert.equal(last.checks.protectedErrorDecoded,true);assert.equal(last.checks.fastErrorNonce,true);
    assert.equal(last.credentials.userTgt,undefined);assert.equal(last.keys.finalReplyClient,undefined);
  }
});

test('the selected PA-ENCRYPTED-CHALLENGE AS factor requires strengthening before credential acceptance',()=>{
  const model=cryptoModel('lab-ad-fast-as-success'),id=cryptoId(model,'strengthen-key');
  assert.match(model.definitions()[id].purpose,/Required for the selected PA-ENCRYPTED-CHALLENGE AS factor before ticket issuance/);
  assert.match(cryptoStage(model,'protect-response').detail,/PA-ENCRYPTED-CHALLENGE AS factor requires reply-key strengthening before ticket issuance/);
  assert.match(cryptoStage(model,'decode-response').detail,/Require strengthen-key for the selected PA-ENCRYPTED-CHALLENGE factor/);
  assert.ok(cryptoStage(model,'decode-response').checks.includes('Required PA-ENCRYPTED-CHALLENGE AS strengthening'));
  assert.equal(reconstructProtocolState(model,cryptoIndex(model,'decode-response')).checks.fastStrengthenPresent,true);
  assert.equal(reconstructProtocolState(model,cryptoIndex(model,'decode-response')).credentials.userTgt,undefined);
  assert.equal(cryptoEnd(model).checks.fastStrengthenPresent,true);
  const keyIds=[cryptoEnd(model).keys.armorClient.instanceId,cryptoEnd(model).keys.originalReplyClient.instanceId,cryptoEnd(model).keys.finalReplyClient.instanceId,cryptoEnd(model).credentials.userTgt.sessionKeyInstanceId];
  assert.equal(new Set(keyIds).size,keyIds.length);
});
