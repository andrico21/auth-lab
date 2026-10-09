import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { VARIANT_ATTRIBUTES } from '../src/architecture-variants.js';
import { FIDO_ATTRIBUTES, getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { CIBA_ATTRIBUTES, CIBA_SOURCES, CIBA_TOPIC_IDS, getCibaSteps, getCibaActorOverrides, getCibaAttributeOverrides, getCibaExampleOverrides } from '../src/ciba-data.js';

Object.assign(ATTRIBUTES,VARIANT_ATTRIBUTES,FIDO_ATTRIBUTES,CIBA_ATTRIBUTES);
const cibaTestModes=['passkey','password','one-time-code','password-totp','passkey-totp'];
const cibaTestStage=(steps,key)=>steps.find(s=>s.cibaStage===key);
const cibaTestWire=s=>s.attributeOperations.filter(o=>['send','receive'].includes(o.kind));
const cibaTestAbsent=new Set(['redirectApp','redirectBroker','authorizationEndpoint','stateApp','stateBroker','nonceApp','nonceBroker','codeVerifier','codeChallenge','codeChallengeMethod','codeA','codeB','clientIdBroker','clientSecret','idTokenB','accessTokenB','deviceCode','userCode','device_code','user_code']);

test('CIBA covers every configured factor method and authenticator using immutable cached authoritative models',()=>{
  const snapshot=JSON.stringify(FLOWS);
  for(const mode of cibaTestModes)for(const authenticator of ['hello','yubikey']){
    const config={mode,authenticator,architecture:'native',upstream:'external'},steps=getCibaSteps(config);
    assert.equal(steps,getCibaSteps({mode,authenticator}));assert.equal(new Set(steps.map(s=>s.id)).size,steps.length);
    for(const s of steps){
      assert.equal(s.architecture,'web');assert.equal(s.upstream,'single');assert.equal(s.oidcGrant,'ciba');assert.ok(Array.isArray(s.attributeOperations));
      for(const actor of [s.from,s.to])assert.ok(actor==='authenticator'||ACTORS[actor],s.id+': '+actor);
      for(const op of getStepAttributeOperations(s,authenticator)){assert.ok(ATTRIBUTES[op.attributeId],s.id+': '+op.attributeId);assert.ok(ACTORS[op.actorId],s.id+': '+op.actorId);assert.equal(cibaTestAbsent.has(op.attributeId),false,s.id+': '+op.attributeId);}
      for(const id of s.fields){assert.ok(ATTRIBUTES[id],s.id+': '+id);assert.equal(cibaTestAbsent.has(id),false,s.id+': '+id);}
      assert.doesNotMatch(JSON.stringify(s.payload),/"name":"(?:nonce|redirect_uri|code|device_code|user_code|code_verifier|code_challenge)"/);
    }
  }
  assert.equal(JSON.stringify(FLOWS),snapshot);assert.equal(getCibaSteps({mode:'passkey-enrollment'}),getCibaSteps({mode:'passkey'}));
});

test('CIBA begins through the authenticated backchannel and resolves a hint without treating it as authentication',()=>{
  const steps=getCibaSteps(),request=cibaTestStage(steps,'request'),prepare=cibaTestStage(steps,'prepare'),accept=cibaTestStage(steps,'accept');
  assert.equal(request.from,'app');assert.equal(request.to,'realmA');assert.equal(request.channel,'backchannel');
  assert.ok(request.payload.some(p=>p.name==='login_hint'));assert.ok(request.payload.some(p=>p.name==='scope'&&p.value.includes('openid')));
  assert.equal(request.payload.some(p=>p.name==='grant_type'),false);assert.equal(request.payload.some(p=>p.name==='auth_req_id'),false);
  assert.match(request.payload.find(p=>p.name==='Authorization').value,/^Basic /);
  assert.ok(prepare.attributeOperations.some(o=>o.attributeId==='authorizationHeaderApp'&&o.kind==='derive'&&o.actorId==='app'));
  assert.ok(accept.attributeOperations.some(o=>o.attributeId==='cibaAuthReqId'&&o.kind==='create'&&o.actorId==='realmA'));
  assert.ok(accept.attributeOperations.some(o=>o.attributeId==='cibaLoginHint'&&o.kind==='verify'));
  assert.match(accept.detail,/still unauthenticated/);assert.match(getCibaAttributeOverrides().cibaLoginHint.meaning,/identifier/i);
  assert.ok(getAttributeUsage(steps,'cibaAuthReqId').some(u=>u.step.cibaStage==='accept'));
});

test('CIBA controlled-service callback secrets remain backend-only and are distinct from client authentication',()=>{
  const steps=getCibaSteps(),delegate=cibaTestStage(steps,'delegate'),result=cibaTestStage(steps,'result');
  assert.equal(delegate.from,'realmA');assert.equal(delegate.to,'realmB');assert.equal(result.from,'realmB');assert.equal(result.to,'realmA');
  for(const s of steps)for(const op of s.attributeOperations.filter(o=>o.attributeId==='cibaChannelAuthorization'))assert.ok(['realmA','realmB'].includes(op.actorId),s.id);
  for(const s of steps)for(const op of cibaTestWire(s).filter(o=>['clientSecretApp','authorizationHeaderApp'].includes(o.attributeId)))assert.ok(['app','realmA'].includes(op.actorId),s.id);
  assert.equal(delegate.fields.includes('cibaAuthReqId'),false,'Keycloak delegation correlates its protected callback credential; do not invent an auth_req_id body field.');
  assert.ok(steps.indexOf(cibaTestStage(steps,'delegation-ack'))<steps.indexOf(cibaTestStage(steps,'handle')),'Keycloak acknowledges the controlled authentication delegation before returning auth_req_id.');
  assert.deepEqual(result.payload.filter(p=>!['HTTP','Authorization'].includes(p.name)).map(p=>p.name),['status']);
  assert.equal(result.payload.find(p=>p.name==='status').value,'SUCCEED');assert.match(result.detail,/not CIBA Push token delivery/);
  const actors=getCibaActorOverrides();assert.match(actors.realmB.role,/integration/);assert.match(actors.realmA.notes.join(' '),/not a second realm/);
  for(const id of ['browser','user','app'])assert.equal(actors[id].attributes.some(a=>a.id==='cibaChannelAuthorization'),false,id);
});

test('CIBA pending polls and safe interval/backoff policy precede the final approved result',()=>{
  const steps=getCibaSteps(),pending=cibaTestStage(steps,'pending'),backoff=cibaTestStage(steps,'backoff');
  assert.equal(pending.payload.find(p=>p.name==='error').value,'authorization_pending');
  assert.match(backoff.detail,/slow_down.*at least five seconds/);assert.match(backoff.detail,/Do not overlap/);assert.match(backoff.detail,/access_denied.*invalid_grant.*invalid_request/);
  for(const key of ['poll-pending','poll-approved']){const poll=cibaTestStage(steps,key);assert.equal(poll.payload.find(p=>p.name==='grant_type').value,'urn:openid:params:grant-type:ciba');assert.ok(poll.payload.some(p=>p.name==='auth_req_id'));assert.match(poll.payload.find(p=>p.name==='Authorization').value,/^Basic /);}
  assert.ok(steps.indexOf(pending)<steps.indexOf(cibaTestStage(steps,'approve')));
  assert.ok(steps.indexOf(cibaTestStage(steps,'approved'))<steps.indexOf(cibaTestStage(steps,'poll-approved')));
  assert.ok(steps.indexOf(cibaTestStage(steps,'poll-approved'))<steps.indexOf(cibaTestStage(steps,'l24')));
});

test('CIBA device-factor verification and an explicit subject-bound authorization decision precede tokens',()=>{
  for(const mode of cibaTestModes)for(const authenticator of ['hello','yubikey']){
    const steps=getCibaSteps({mode,authenticator}),approvalIndex=steps.indexOf(cibaTestStage(steps,'approve')),factors=steps.filter(s=>s.cibaStage==='factor');
    assert.ok(factors.length);assert.ok(factors.every(s=>steps.indexOf(s)<approvalIndex));
    const verifyFields=factors.flatMap(s=>s.attributeOperations.filter(o=>o.kind==='verify'&&o.actorId==='realmB').map(o=>o.attributeId));
    if(mode.includes('passkey')||mode==='passkey')assert.ok(verifyFields.includes('signature'));
    if(mode.includes('password'))assert.ok(verifyFields.includes('password'));
    if(mode.includes('totp')||mode==='one-time-code')assert.ok(verifyFields.includes('otpCode'));
    const checks=cibaTestStage(steps,'prepare-result').attributeOperations;
    const consumptionCue=cibaTestStage(steps,'consumption-cue'),deviceCue=cibaTestStage(steps,'compare');
    assert.ok(consumptionCue.attributeOperations.some(o=>o.attributeId==='cibaBindingMessage'&&o.kind==='send'&&o.actorId==='app'));
    assert.ok(deviceCue.attributeOperations.some(o=>o.attributeId==='cibaBindingMessage'&&o.kind==='send'&&o.actorId==='browser'));
    assert.ok(steps.indexOf(consumptionCue)<steps.indexOf(deviceCue));assert.ok(steps.indexOf(deviceCue)<approvalIndex);
    for(const id of ['cibaLoginHint','cibaBindingMessage','cibaApproval'])assert.ok(checks.some(o=>o.attributeId===id&&o.kind==='verify'&&o.actorId==='realmB'));
    assert.ok(steps.indexOf(cibaTestStage(steps,'decision'))<steps.indexOf(cibaTestStage(steps,'result')));
    assert.ok(steps.indexOf(cibaTestStage(steps,'result'))<steps.indexOf(cibaTestStage(steps,'l24')));
  }
});

test('CIBA illustrative WebAuthn and TOTP factors stay scoped to the controlled authentication service',()=>{
  for(const authenticator of ['hello','yubikey']){
    const steps=getCibaSteps({mode:'passkey-totp',authenticator}),factors=steps.filter(s=>s.cibaStage==='factor');
    for(const s of factors){assert.equal([s.from,s.to].includes('realmA'),false,s.id);assert.equal([s.from,s.to].includes('app'),false,s.id);assert.equal(s.relyingPartyActor,'realmB');assert.equal(s.attributeValues.rpId,'authenticate.example.test');assert.equal(s.attributeValues.origin,'https://authenticate.example.test');assert.doesNotMatch(JSON.stringify(s.payload),/idp2\.example\.test/);}
    for(const s of steps)for(const o of cibaTestWire(s).filter(o=>o.attributeId==='privateKey'))assert.fail('Credential private key sent: '+s.id);
    for(const s of steps)for(const o of cibaTestWire(s).filter(o=>['otpCode','otpSecret','password','passwordHash'].includes(o.attributeId)))assert.equal(['realmA','app'].includes(o.actorId),false,s.id);
    for(const s of steps)for(const o of s.attributeOperations.filter(o=>o.attributeId==='pinUvAuthToken'))assert.ok(['browser','yubikey'].includes(o.actorId),s.id);
    assert.equal(factors.some(s=>s.channel==='ctap2'),authenticator==='yubikey');
    assert.match(getCibaActorOverrides({mode:'passkey-totp',authenticator}).realmB.notes.join(' '),/example implementation, not a built-in/);
  }
});

test('CIBA tokens expose real Poll identity claims and remain compatible with ID-token JWE adaptation',()=>{
  const steps=getCibaSteps(),wire=cibaTestStage(steps,'l24'),validation=cibaTestStage(steps,'l25');
  assert.ok(wire.id.endsWith('-l24'));assert.ok(validation.id.endsWith('-l25'));assert.equal(wire.from,'realmA');assert.equal(wire.to,'app');
  assert.ok(wire.payload.some(p=>p.name==='id_token'));assert.equal(wire.payload.some(p=>p.name==='nonce'),false);assert.equal(wire.payload.some(p=>/auth_req_id/.test(p.name)),false);
  assert.deepEqual(wire.idTokenClaimIds,['issuerA','subjectA','audience','exp','iat','cibaAuthTime']);
  const claims=cibaTestWire(wire).filter(o=>wire.idTokenClaimIds.includes(o.attributeId));assert.equal(claims.length,12);assert.ok(claims.every(o=>o.carriedAs==='id_token claims'));
  const validated=validation.attributeOperations.filter(o=>o.kind==='verify').map(o=>o.attributeId);for(const id of wire.idTokenClaimIds)assert.ok(validated.includes(id));assert.equal(validated.includes('nonceApp'),false);
  assert.equal(getCibaExampleOverrides().audience,'ciba-client');assert.equal(getCibaAttributeOverrides().grantType.example,'urn:openid:params:grant-type:ciba');
});

test('CIBA index attributes have clear origins, purposes, standards and genuine animated lifecycle uses',()=>{
  const steps=getCibaSteps({mode:'passkey-totp',authenticator:'yubikey'});
  assert.deepEqual(CIBA_TOPIC_IDS,Object.keys(CIBA_ATTRIBUTES));assert.ok(CIBA_SOURCES.some(s=>s.url.includes('openid.net')));assert.ok(CIBA_SOURCES.some(s=>s.url.includes('keycloak.org')));
  for(const [id,def]of Object.entries(CIBA_ATTRIBUTES)){for(const key of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(def[key],id+': '+key);assert.ok(getAttributeUsage(steps,id,'yubikey').length,id+' needs an actual animated lifecycle use');}
  const overrides=getCibaActorOverrides({mode:'password'});assert.equal(overrides.app.attributes.some(a=>a.id==='codeVerifier'),false);assert.equal(overrides.browser.attributes.some(a=>a.id==='idTokenA'),false);
});

test('CIBA factor hover metadata describes the controlled service throughout every reused active definition',()=>{
  for(const mode of cibaTestModes)for(const authenticator of ['hello','yubikey']){
    const overrides=getCibaAttributeOverrides({mode,authenticator}),factorIds=[...new Set(getCibaSteps({mode,authenticator}).filter(s=>s.authenticationEntity).flatMap(s=>s.fields))];
    for(const id of factorIds){
      const definition=overrides[id];assert.ok(definition,id+' needs a complete controlled-service override, not the generic single-realm definition');
      for(const key of ['name','meaning','description','origin','generator','purpose','example','standard']){
        assert.ok(definition[key],id+': '+key);
        assert.doesNotMatch(definition[key],/\bRealm B\b|\bB(?:’s|'s)?\b|A(?:’s|'s) WebAuthn policy|Keycloak(?:’s|'s)? server-side sign-in|Keycloak (?:OTP|password|browser authentication|sessions)/,id+': '+key);
      }
      assert.equal(definition.description,definition.meaning,id);assert.equal(definition.generator,definition.origin,id);
      if(['rpId','origin','rpIdHash','userHandle','userVerification','session','otpCode','otpSecret','passwordHash'].includes(id))assert.match([definition.origin,definition.meaning,definition.purpose].join(' '),/authentication.service|trusted service|controlled service/,id);
    }
    for(const id of ['rpId','origin','userVerification','rpIdHash','userHandle','signature','privateKey','credentialPublicKey'])assert.match(overrides[id].standard,/WebAuthn/,id+' retains its W3C protocol reference');
    for(const id of ['otpCode','otpSecret','otpWindow','otpReplay'])assert.match(overrides[id].standard,/RFC 6238/,id+' retains its TOTP protocol reference');
    assert.match(overrides.session.name,/Device authentication session/);assert.match(overrides.session.example,/authentication-service device session/);
  }
});
