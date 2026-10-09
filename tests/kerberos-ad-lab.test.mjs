import test from 'node:test';
import assert from 'node:assert/strict';
import {ADLAB_ATTRIBUTES,ADLAB_SOURCES,ADLAB_SCENARIOS} from '../src/kerberos-ad-lab.js';
import {buildProtocolInstances,reconstructProtocolState,validateProtocolScenario} from '../src/protocol-state.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
const scenario=id=>ADLAB_SCENARIOS.find(model=>model.id===id);
const index=(model,suffix)=>model.steps().findIndex(step=>step.id.endsWith('-'+suffix));
const frame=(model,suffix)=>model.steps()[index(model,suffix)];
const state=(model,suffix)=>reconstructProtocolState(model,index(model,suffix));
const final=model=>reconstructProtocolState(model,model.steps().length-1);
const allOps=model=>model.steps().flatMap(step=>step.attributeOperations);
const sends=(model,id)=>allOps(model).filter(op=>op.attributeId===id&&op.kind==='send');
const trace=(model,attr)=>buildAttributeTrace(model.steps().map((step,i)=>({step,index:i,actions:step.attributeOperations.filter(op=>op.attributeId===attr)})).filter(item=>item.actions.length),model.examples());

test('all required baseline and assurance presets are immutable, independently valid source histories',()=>{
  assert.equal(ADLAB_SCENARIOS.length,27);
  assert.equal(new Set(ADLAB_SCENARIOS.map(model=>model.id)).size,27);
  for(const model of ADLAB_SCENARIOS){
    const result=validateProtocolScenario(model);assert.deepEqual(result.errors,[],model.id);
    assert.equal(model.workspace,'kerberos');assert.ok(model.supportNote.includes('reference')||model.supportNote.includes('Reference'));
    assert.ok(Object.isFrozen(model.steps()));assert.ok(Object.isFrozen(model.definitions()));
    const actors=model.actors();
    for(const step of model.steps()){
      assert.ok(actors[step.from]&&actors[step.to],step.id);assert.ok(step.fields.length&&step.payload.length&&step.attributeOperations.length);
      assert.equal(new Set(step.fields).size,step.fields.length);
      for(const op of step.attributeOperations){assert.ok(actors[op.actorId]);assert.ok(model.definitions()[op.attributeId]);assert.ok(op.instanceId&&op.fieldPath&&op.representation&&op.exactValueRef);assert.ok(Object.hasOwn(op,'value'));}
    }
    for(let i=-1;i<model.steps().length;i++){assert.doesNotThrow(()=>buildProtocolInstances(model,i));assert.doesNotThrow(()=>reconstructProtocolState(model,i));}
    for(const def of Object.values(model.definitions()))for(const key of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(def[key]);
  }
  assert.ok(ADLAB_SOURCES.every(source=>source.label&&source.url.startsWith('https://')));
});

test('AS and TGS have distinct logical actor identities under the same AD DS parent',()=>{
  const model=scenario('lab-ad-first-sign-in'),actors=model.actors();
  assert.equal(actors.adAs.parentId,'adKdc');assert.equal(actors.adTgs.parentId,'adKdc');
  assert.equal(frame(model,'as-request').to,'adAs');assert.equal(frame(model,'as-reply').from,'adAs');
  assert.equal(frame(model,'service-tgs-request').to,'adTgs');assert.equal(frame(model,'service-tgs-reply').from,'adTgs');
  assert.equal(Object.hasOwn(actors,'adKeycloak'),false,'standalone AD does not depend on Keycloak');
});

test('Windows first logon obtains the workstation host credential/PAC before remote access',()=>{
  const model=scenario('lab-ad-first-sign-in');
  assert.ok(index(model,'cache-tgt')<index(model,'host-tgs-request'));
  assert.ok(index(model,'host-cache')<index(model,'local-logon'));
  assert.ok(index(model,'local-logon')<index(model,'service-tgs-request'));
  assert.equal(state(model,'local-logon').sessions.localLogon,true);
  assert.equal(state(model,'local-logon').credentials.host.target,'host/ws01.a.example');
  assert.equal(state(model,'local-logon').sessions.serviceAuthenticated,false);
  assert.equal(final(model).sessions.resourceAccess,true);
  assert.match(frame(model,'local-logon').checks.join(' '),/abstractly/);
  assert.deepEqual(sends(model,'adPassword').map(op=>op.actorId),['adUser']);
  assert.ok(sends(model,'adPassword').every(op=>!['adAs','adTgs'].includes(op.actorId)));
});

test('TGT, client reply, service ticket and every key remain distinct protected objects',()=>{
  const model=scenario('lab-ad-first-sign-in'),objects=buildProtocolInstances(model,model.steps().length-1);
  const tgt=objects.find(obj=>obj.instanceId==='ticket:tgt:01');
  assert.equal(tgt.creator,'adAs');assert.ok(tgt.holders.includes('adWorkstation'));
  assert.ok(tgt.occurrences.filter(op=>op.definitionId==='adTgt').every(op=>!op.inspectors.includes('adWorkstation')),'possession does not make TGT ciphertext inspectable');assert.ok(tgt.occurrences.some(op=>op.definitionId==='adTgtTarget'&&op.inspectors.includes('adWorkstation')),'clear outer target can be read without decrypting the ticket');
  const service=objects.find(obj=>obj.instanceId==='ticket:service:01');
  assert.equal(service.creator,'adTgs');assert.ok(service.holders.includes('adWorkstation'));assert.ok(service.inspectors.includes('adService'));assert.ok(service.occurrences.filter(op=>op.definitionId==='adServiceTicket').every(op=>!op.inspectors.includes('adWorkstation')));
  for(const id of ['adUserKey','adKrbtgtKey','adMachineKey','adServiceKey'])assert.equal(sends(model,id).length,0,id+' never goes on the wire');
  for(const id of ['adTgtKey','adHostKey','adServiceSessionKey'])assert.ok(sends(model,id).every(op=>/enc-part/.test(op.carriedAs)),id+' transmitted only inside encrypted reply');
  assert.notEqual(final(model).credentials.tgt.sessionKeyInstanceId,final(model).credentials.service.sessionKeyInstanceId);
});

test('cached presets omit only the exchanges their holdings can replace, and still make new AP proof',()=>{
  const cold=scenario('lab-ad-cache-none'),tgt=scenario('lab-ad-cache-tgt'),service=scenario('lab-ad-cache-service');
  assert.ok(index(cold,'as-request')>=0);assert.equal(index(tgt,'as-request'),-1);assert.ok(index(tgt,'service-tgs-request')>=0);
  assert.equal(index(service,'as-request'),-1);assert.equal(index(service,'service-tgs-request'),-1);
  for(const model of [tgt,service]){assert.equal(sends(model,'adPassword').length,0);assert.ok(frame(model,'ap-create').attributeOperations.some(op=>op.attributeId==='adAuthenticator'&&op.kind==='create'));assert.equal(final(model).sessions.resourceAccess,true);}
  assert.equal(reconstructProtocolState(service,-1).credentials.service.ticketInstanceId,final(service).credentials.service.ticketInstanceId);
});

test('unknown SPN is a KDC acquisition failure, with no target ticket/cache/AP request',()=>{
  const model=scenario('lab-ad-unknown-spn'),result=final(model);
  assert.equal(frame(model,'unknown-spn-check').from,'adTgs');assert.equal(result.failure.actorId,'adKdc');assert.equal(result.failure.logicalActorId,'adTgs');
  assert.equal(result.failure.stage,'ticket-acquisition');assert.equal(result.failure.eventId,frame(model,'unknown-spn-check').id);
  assert.equal(result.credentials.service,undefined);assert.equal(result.issued?.service,undefined);assert.equal(index(model,'ap-request'),-1);
  assert.equal(result.credentials.unrelated.target,'ldap/dc01.a.example');assert.ok(result.credentials.tgt);
  assert.equal(state(model,'unknown-spn-check').knowledge.adWorkstation.failure,undefined);
  assert.equal(state(model,'unknown-spn-error').knowledge.adWorkstation.failure,'unknown-spn');
});

test('R1 stale acceptor key succeeds at issuance/cache/AP delivery and fails only at the service',()=>{
  const model=scenario('lab-ad-stale-service-key');
  assert.ok(index(model,'service-tgs-reply')<index(model,'service-cache'));
  assert.ok(index(model,'service-cache')<index(model,'ap-request'));assert.ok(index(model,'ap-request')<index(model,'acceptor-reject'));
  const cached=state(model,'service-cache');assert.equal(cached.credentials.service.ticketInstanceId,'ticket:service:01');assert.equal(cached.failure,undefined);
  assert.equal(state(model,'ap-request').knowledge.adWorkstation.failure,undefined);
  const failed=state(model,'acceptor-reject');assert.equal(failed.failure.actorId,'adService');assert.equal(failed.failure.eventId,frame(model,'acceptor-reject').id);
  assert.equal(failed.knowledge.adWorkstation.failure,undefined,'client learns result only through modeled return');
  assert.equal(failed.credentials.service.ticketInstanceId,cached.credentials.service.ticketInstanceId);
  const result=final(model);assert.equal(result.knowledge.adWorkstation.failure,'stale');assert.equal(result.sessions.serviceAuthenticated,false);assert.equal(result.sessions.resourceAccess,false);
  assert.equal(index(model,'ap-reply'),-1);assert.equal(index(model,'resource'),-1);
  assert.equal(result.credentials.unrelated.target,'ldap/dc01.a.example');
  assert.match(frame(model,'acceptor-reject').payload.find(p=>p.attributeId==='adError').value,/selected RFC/,'do not invent a universal Windows key error');
});

test('source reconstruction through field replay includes hidden credential creation and knowledge events',()=>{
  const model=scenario('lab-ad-stale-service-key'),focused=trace(model,'adError');
  assert.ok(focused.length>0);
  for(const projected of focused){const full=reconstructProtocolState(model,projected.sourceIndex);const direct=reconstructProtocolState(model,index(model,projected.sourceStepId.slice(model.id.length+1)));assert.deepEqual(full,direct);assert.ok(full.credentials.service,'hidden ticket issuance/cache events still apply');}
  const failure=focused.find(item=>item.sourceStepId.endsWith('acceptor-reject'));
  assert.equal(reconstructProtocolState(model,failure.sourceIndex).failure.actorId,'adService');
  assert.equal(reconstructProtocolState(model,index(model,'service-cache')).knowledge.adWorkstation.failure,undefined,'rewind does not retain future error knowledge');
});

test('skew, expiry and replay are separate service-owned boundaries; only explicit events age protocol time',()=>{
  for(const [id,reason,code] of [['lab-ad-clock-skew','skew','SKEW'],['lab-ad-expired-ticket','expired','TKT_EXPIRED'],['lab-ad-authenticator-replay','replay','REPEAT']]){
    const model=scenario(id),result=final(model);assert.equal(result.failure.actorId,'adService');assert.equal(result.failure.reason,reason);assert.ok(result.credentials.service);assert.equal(result.sessions.serviceAuthenticated,false);assert.equal(index(model,'ap-reply'),-1);
    assert.match(frame(model,'acceptor-error').payload.find(p=>p.attributeId==='adError').value,new RegExp(code));
  }
  const expiry=scenario('lab-ad-expired-ticket');assert.equal(reconstructProtocolState(expiry,-1).protocolClock,1000);assert.equal(state(expiry,'time-advance').protocolClock,5301);assert.equal(final(scenario('lab-ad-cache-service')).protocolClock,1000);
  const replay=scenario('lab-ad-authenticator-replay');assert.deepEqual(reconstructProtocolState(replay,-1).replayCache,['authenticator:ap:already-accepted']);
  assert.equal(frame(replay,'ap-create').attributeOperations.find(op=>op.attributeId==='adAuthenticator').kind,'use','a replay does not create a new proof object');
});

test('resource denial follows successful mutual authentication and never pretends the ticket was rejected',()=>{
  const model=scenario('lab-ad-access-denied'),result=final(model);
  assert.equal(result.sessions.serviceAuthenticated,true);assert.equal(result.knowledge.adWorkstation.serviceProven,true);assert.equal(result.authorization.resource,'deny');assert.equal(result.sessions.resourceAccess,false);assert.equal(result.failure,undefined);
  assert.ok(index(model,'ap-reply-check')<index(model,'access-check'));assert.equal(index(model,'resource'),-1);
});

test('Keycloak bridge keeps one OIDC transaction and uses local GSS with explicit SPNEGO integrity',()=>{
  const model=scenario('lab-kc-kerberos-sso'),steps=model.steps();
  assert.equal(final(model).transactions.oidc.instanceId,'oidc:corporate:01');assert.equal(final(model).transactions.provider.oidcTransactionId,'oidc:corporate:01');
  assert.equal(final(model).sessions.spnegoComplete,true);assert.equal(final(model).sessions.applicationAuthenticated,true);
  assert.equal(sends(model,'adState').every(op=>op.value==='state:corporate:01'),true);
  assert.equal(frame(model,'sspi').channel,'local');assert.equal(frame(model,'spnego-local-check').to,'adWorkstation');assert.equal(frame(model,'spnego-integrity').from,'adWorkstation');
  assert.ok(index(model,'spnego-mic')<index(model,'spnego-complete'));assert.ok(index(model,'spnego-complete')<index(model,'code-create'));
  assert.match(frame(model,'http-accept').payload.find(p=>p.attributeId==='adChannelBinding').value,/absent/);
  assert.ok(steps.some(step=>step.fields.includes('adNegTokenInit'))&&steps.some(step=>step.fields.includes('adNegTokenResp'))&&steps.some(step=>step.fields.includes('adMechListMIC')));
  assert.equal(steps.some(step=>step.fields.includes('adOtp')),false);assert.equal(model.ids.includes('adAMR'),false);
});

test('Alternative Kerberos bypass comparison is clearly primary-only and stock-disabled',()=>{
  const model=scenario('lab-kc-kerberos-alternative-otp-skip');
  assert.ok(index(model,'alternative-short-circuit')>=0);assert.equal(final(model).assurance.factorSkipped,'Forms path not entered');assert.equal(final(model).assurance.factor,undefined);
  assert.equal(model.ids.includes('adOtp'),false);assert.equal(model.ids.includes('adAMR'),false);assert.equal(model.ids.includes('adACR'),false);
  assert.match(frame(model,'alternative-short-circuit').checks.join(' '),/starts disabled/);assert.match(model.title,/skip/);
});

test('fresh-factor enforcement covers fresh Kerberos, password fallback and both cookie assurance starts',()=>{
  for(const id of ['lab-kc-kerberos-fresh-totp','lab-kc-password-fresh-totp','lab-kc-low-assurance-cookie','lab-kc-cookie-fresh-factor','lab-kc-cookie-age-expired']){
    const model=scenario(id),result=final(model);assert.ok(index(model,'totp-check')<index(model,'code-create'));assert.equal(result.assurance.factor.freshFor,'oidc:corporate:01');assert.equal(result.assurance.factor.method,'TOTP');assert.equal(result.sessions.applicationAuthenticated,true);assert.equal(result.transactions.provider.pending,false);assert.equal(result.transactions.provider.result,'authorized');
    assert.equal(sends(model,'adFlowPolicy').length,0);assert.equal(sends(model,'adTotpSecret').length,0);assert.ok(result.otpReplayCache.includes(33));
    assert.match(model.definitions().adAMR.purpose,/not a universal automatic/);
  }
  assert.equal(final(scenario('lab-kc-password-fresh-totp')).assurance.primary.method,'password');
  assert.equal(index(scenario('lab-kc-password-fresh-totp'),'http-negotiate'),-1);
});

test('age-bound reuse is a separate selected policy and does not claim a fresh ceremony',()=>{
  const model=scenario('lab-kc-cookie-age-reuse'),result=final(model);
  assert.equal(index(model,'totp-check'),-1);assert.equal(result.assurance.reusedFactor,true);assert.equal(result.assurance.factor.freshFor,'oidc:earlier:01');assert.equal(result.sessions.applicationAuthenticated,true);
  const acr=frame(model,'token-response').payload.find(p=>p.attributeId==='adACR');assert.equal(acr.value,'urn:auth-lab:assurance:age-bounded-factor');
});

test('unenrolled, failed, cancelled, unsupported and silent-interaction failures issue no code or tokens',()=>{
  for(const id of ['lab-kc-factor-unenrolled','lab-kc-factor-failed','lab-kc-factor-cancelled','lab-kc-unsupported-assurance','lab-kc-prompt-none-factor-required','lab-kc-webauthn-uv-policy-fail']){
    const model=scenario(id),result=final(model);assert.equal(result.failure.actorId,'adKeycloak');assert.equal(result.sessions.applicationAuthenticated,false);assert.equal(result.transactions.oidc.result,'denied');
    assert.equal(index(model,'code-create'),-1);assert.equal(index(model,'token-response'),-1);
    assert.equal(model.ids.includes('adIdToken'),false);assert.equal(model.ids.includes('adACR'),false);
  }
  const silent=scenario('lab-kc-prompt-none-factor-required');assert.equal(sends(silent,'adOtp').length,0);assert.equal(index(silent,'http-negotiate'),-1);assert.equal(frame(silent,'error-redirect').payload.find(p=>p.attributeId==='adOidcError').value,'interaction_required');
  const cancelled=scenario('lab-kc-factor-cancelled');assert.equal(sends(cancelled,'adWaSignature').length,0);assert.equal(final(cancelled).assurance.factor.status,'cancelled');
});

test('the wrong entered OTP is a different immutable object from the correctly generated OTP',()=>{
  const model=scenario('lab-kc-factor-failed'),expected=frame(model,'totp-create').attributeOperations.find(op=>op.attributeId==='adOtp'),entered=frame(model,'totp-enter').attributeOperations.find(op=>op.attributeId==='adOtp');
  assert.notEqual(expected.instanceId,entered.instanceId);assert.notEqual(expected.value,entered.value);
  assert.equal(frame(model,'totp-check').attributeOperations.find(op=>op.attributeId==='adOtp').instanceId,entered.instanceId);
});

test('WebAuthn factor verifies UV and exact browser/signature context without exporting secret keys',()=>{
  const model=scenario('lab-kc-kerberos-fresh-webauthn'),result=final(model);
  assert.equal(result.assurance.factor.uv,true);assert.equal(result.assurance.factor.freshFor,'oidc:corporate:01');assert.equal(result.sessions.applicationAuthenticated,true);
  assert.equal(sends(model,'adPrivateKey').length,0);assert.equal(sends(model,'adPublicKey').length,0);assert.equal(sends(model,'adClientData').some(op=>op.actorId==='adBrowser'),true);
  assert.equal(frame(model,'wa-authenticator').fields.includes('adClientData'),false,'authenticator gets hash, not browser JSON');
  const fail=scenario('lab-kc-webauthn-uv-policy-fail');assert.equal(final(fail).assurance.factor.status,'uv-policy-failed');assert.equal(frame(fail,'wa-check').payload.find(p=>p.attributeId==='adUV').value,'false');
});

test('PKCE birth, transmission and verification have distinct owners and immutable commitment instances',()=>{
  const model=scenario('lab-kc-kerberos-fresh-totp');
  assert.equal(frame(model,'transaction').attributeOperations.find(op=>op.attributeId==='adVerifier'&&op.kind==='create').actorId,'adApp');
  assert.deepEqual(sends(model,'adVerifier').map(op=>op.actorId),['adApp']);
  assert.equal(frame(model,'open-browser').fields.includes('adVerifier'),false);assert.equal(frame(model,'authorize').fields.includes('adVerifier'),false);
  const first=frame(model,'transaction').attributeOperations.find(op=>op.attributeId==='adChallenge'&&op.kind==='derive'),recomputed=frame(model,'token-check').attributeOperations.find(op=>op.attributeId==='adChallenge'&&op.kind==='derive');
  assert.notEqual(first.instanceId,recomputed.instanceId);assert.equal(first.actorId,'adApp');assert.equal(recomputed.actorId,'adKeycloak');assert.equal(first.value,recomputed.value);
  assert.ok(index(model,'token-check')>index(model,'code-create'));assert.equal(final(model).transactions.code.consumed,true);
  assert.equal(frame(model,'token-response').payload.find(p=>p.attributeId==='adAudience').value,'corporate-web');assert.ok(frame(model,'app-validate').fields.includes('adClientId'));
});

test('runtime bindings keep issuer, application, client audience and Kerberos target ownership explicit',()=>{
  const model=scenario('lab-kc-kerberos-sso');
  assert.ok(model.runtimeBindings.some(binding=>binding.field==='aIssuerURL'&&binding.attributeId==='adIssuer'&&binding.actorId==='adKeycloak'));
  assert.ok(model.runtimeBindings.some(binding=>binding.field==='appURL'&&binding.actorId==='adApp'));
  assert.ok(model.runtimeBindings.some(binding=>binding.field==='clientID'&&binding.attributeId==='adAudience'));
  assert.ok(model.runtimeBindings.some(binding=>binding.field==='servicePrincipal'&&binding.actorId==='adKeycloak'));
  const invalid=ADLAB_SCENARIOS.flatMap(m=>m.runtimeBindings||[]).filter(binding=>binding.attributeId&&!ADLAB_ATTRIBUTES[binding.attributeId]);assert.deepEqual(invalid,[]);
});

test('credential, proof and transaction references resolve to the same immutable ledger object identities',()=>{
  for(const id of ['lab-ad-first-sign-in','lab-ad-stale-service-key','lab-kc-kerberos-fresh-totp']){
    const model=scenario(id),instances=buildProtocolInstances(model,model.steps().length-1),ids=new Set(instances.map(item=>item.instanceId)),result=final(model);
    for(const key of ['tgt','host','service'])if(result.credentials[key]){assert.ok(ids.has(result.credentials[key].ticketInstanceId),id+': '+key+' ticket');assert.ok(ids.has(result.credentials[key].sessionKeyInstanceId),id+': '+key+' session key');}
    if(result.proofs?.as)assert.ok(ids.has(result.proofs.as.instanceId));
    for(const proof of ['tgsHost','tgsService','ap','http'])if(result.proofs?.[proof])assert.ok(ids.has(result.proofs[proof].instanceId),id+': '+proof+' proof');
    if(result.transactions?.oidc){assert.ok(ids.has(result.transactions.oidc.verifier));assert.ok(ids.has(result.transactions.code.instanceId));}
  }
});


test('factor presentation distinguishes a TOTP app from the chosen WebAuthn security key',()=>{
  const totp=scenario('lab-kc-kerberos-fresh-totp').actors().adFactor;
  assert.equal(totp.name,'Authenticator app');assert.equal(totp.art,'totp');assert.match(totp.role,/TOTP/);
  for(const id of ['lab-kc-kerberos-fresh-webauthn','lab-kc-webauthn-uv-policy-fail','lab-kc-factor-cancelled']){
    const factor=scenario(id).actors().adFactor;assert.equal(factor.name,'Security key');assert.equal(factor.art,'yubikey');assert.match(factor.role,/WebAuthn/);
  }
});
