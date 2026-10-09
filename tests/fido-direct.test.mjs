import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { VARIANT_ATTRIBUTES, getJourneySteps } from '../src/architecture-variants.js';
import { FIDO_ATTRIBUTES } from '../src/attribute-usage.js';
import { FIDO_JOURNEYS, getFidoSteps, getFidoActorOverrides, getFidoAttributeOverrides, getFidoExampleOverrides, applyFidoTransport } from '../src/fido-direct.js';

const canonical=item=>String(item.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const value=(item,name)=>item.payload.find(p=>p.name===name)?.value;
const find=(steps,id)=>steps.find(item=>canonical(item)===id);
const forbidden=new Set(['codeVerifier','codeChallenge','codeChallengeMethod','clientSecret','clientSecretApp','clientIdApp','clientIdBroker','redirectApp','redirectBroker','stateApp','stateBroker','nonceApp','nonceBroker','codeA','codeB','grantType','idTokenA','idTokenB','accessTokenA','accessTokenB','issuerA','issuerB']);

test('direct FIDO2 exposes two web-only journeys involving the application, browser, person and selected authenticator',()=>{
  assert.equal(Object.keys(FIDO_JOURNEYS).length,2);
  for(const mode of Object.keys(FIDO_JOURNEYS))for(const device of ['hello','yubikey']) {
    const steps=getFidoSteps(mode,device);
    assert.ok(FIDO_JOURNEYS[mode].requiresWeb&&FIDO_JOURNEYS[mode].directFido);
    assert.equal(getFidoSteps(mode,device),steps);
    assert.equal(new Set(steps.map(item=>item.id)).size,steps.length);
    for(const item of steps) {
      for(const actor of [item.from,item.to])assert.ok(['app','browser','user','authenticator'].includes(actor),item.id+': '+actor);
      for(const field of item.fields){assert.ok(ATTRIBUTES[field]||VARIANT_ATTRIBUTES[field]||FIDO_ATTRIBUTES[field],item.id+': '+field);assert.equal(forbidden.has(field),false,item.id+': OIDC '+field);}
      assert.equal(item.directFido,true);assert.equal(item.relyingPartyActor,'app');assert.equal(item.architecture,'web');assert.equal(item.mode,mode);
      assert.ok(item.title&&item.summary&&item.detail&&item.payload.length,item.id);
    }
  }
  assert.equal(getFidoSteps('fido-login','hello').length,11);
  assert.equal(getFidoSteps('fido-login','yubikey').length,15);
  assert.equal(getFidoSteps('fido-enrollment','hello').length,8);
  assert.equal(getFidoSteps('fido-enrollment','yubikey').length,12);
});

test('direct login RP scope belongs to app.example.test and the backend verifies before issuing its session cookie',()=>{
  for(const device of ['hello','yubikey']){
    const steps=getFidoSteps('fido-login',device);
    assert.equal(find(steps,'l08').from,'app');assert.equal(find(steps,'l08').to,'browser');
    assert.equal(value(find(steps,'l08'),'rpId'),'app.example.test');
    assert.equal(value(find(steps,'l08'),'allowCredentials'),'[]');
    assert.equal(value(find(steps,'l14'),'Expected origin'),'https://app.example.test');
    const assertion=find(steps,'l13');assert.equal(assertion.from,'browser');assert.equal(assertion.to,'app');
    assert.equal(value(assertion,'HTTP'),'POST https://app.example.test/webauthn/assertion');
    assert.equal(find(steps,'l14').from,'app');assert.equal(find(steps,'l14').to,'app');
    assert.match(find(steps,'l14').detail,/credentialPublicKey/);
    assert.ok(find(steps,'l14').fields.includes('userHandle'));
    const cookie=steps.find(item=>item.directSessionCreated);
    assert.ok(steps.indexOf(cookie)>steps.indexOf(find(steps,'l14')));
    assert.equal(cookie.from,'app');assert.equal(cookie.to,'browser');
    assert.match(value(cookie,'Set-Cookie'),/Secure; HttpOnly; SameSite=Lax/);
    assert.equal(value(cookie,'id_token'),undefined);
  }
});

test('YubiKey CTAP2 PIN authorization precedes the authenticated command and touch, and never reaches the RP',()=>{
  for(const mode of ['fido-login','fido-enrollment']){
    const steps=getFidoSteps(mode,'yubikey');
    const prepare=steps.find(item=>item.ctapOperation==='prepare');
    const pin=steps.find(item=>item.ctapOperation==='local-pin');
    const token=steps.find(item=>item.ctapOperation==='pin-uv');
    const command=steps.find(item=>['get-assertion','make-credential'].includes(item.ctapOperation));
    const touch=steps.find(item=>item.ctapOperation==='user-presence');
    const operation=find(steps,mode==='fido-login'?'l11':'e06');
    assert.equal(prepare.channel,'internal');
    assert.equal(prepare.from,'browser');assert.equal(prepare.to,'browser');
    assert.ok(steps.indexOf(prepare)<steps.indexOf(pin));assert.ok(steps.indexOf(pin)<steps.indexOf(token));
    assert.ok(steps.indexOf(token)<steps.indexOf(command));assert.ok(steps.indexOf(command)<steps.indexOf(touch));assert.ok(steps.indexOf(touch)<steps.indexOf(operation));
    assert.equal(token.from,'authenticator');assert.equal(token.to,'browser');assert.equal(token.channel,'ctap2');
    assert.match(value(token,'pinUvAuthToken'),/Encrypted/);
    assert.equal(command.from,'browser');assert.equal(command.to,'authenticator');assert.equal(command.channel,'ctap2');
    assert.ok(command.fields.includes('pinUvAuthParam'));assert.ok(command.fields.includes('pinUvAuthProtocol'));
    assert.ok(!command.fields.includes('pinUvAuthToken'),'Send a tag, not the local token, in the credential command.');
    if(mode==='fido-enrollment'){
      assert.ok(command.fields.includes('ctapResidentKey'));
      assert.ok(command.fields.includes('residentKey'));
      assert.equal(value(command,'options.rk'),true,'Map required WebAuthn residentKey to the CTAP2 rk boolean.');
      assert.match(command.detail,/residentKey.*required.*options\.rk = true/);
    }
    assert.match(value(command,'pinUvAuthParam'),/authenticate\(pinUvAuthToken, clientDataHash\)/);
    assert.equal(command.payload.some(p=>p.name==='uv'&&p.value==='true'),false);
    for(const item of steps.filter(item=>item.to==='app'||item.from==='app'))for(const id of ['pinUvAuthToken','pinUvAuthParam','pinUvAuthProtocol'])assert.equal(item.fields.includes(id),false,item.id+' leaks '+id);
  }
  for(const mode of Object.keys(FIDO_JOURNEYS))for(const item of getFidoSteps(mode,'hello')) {
    assert.equal(item.channel==='ctap2',false,item.id);
    assert.equal(item.fields.some(id=>id.startsWith('pinUv')||id.startsWith('ctap')),false,item.id);
  }
});

test('direct registration starts from a verified app account and sends only public registration data',()=>{
  for(const device of ['hello','yubikey']){
    const steps=getFidoSteps('fido-enrollment',device);
    assert.match(find(steps,'e01').detail,/verified application account/);
    assert.equal(find(steps,'e03').from,'app');assert.equal(find(steps,'e03').to,'browser');
    assert.match(value(find(steps,'e03'),'rp'),/app\.example\.test/);
    assert.match(value(find(steps,'e03'),'user'),/opaque-app-user-bytes/);
    const create=find(steps,'e06');assert.equal(create.from,'authenticator');
    assert.match(create.detail,/creates a new credential private\/public-key pair/);
    const submit=find(steps,'e07');assert.equal(submit.from,'browser');assert.equal(submit.to,'app');
    assert.equal(value(submit,'HTTP'),'POST https://app.example.test/webauthn/registration');
    const store=find(steps,'e08');assert.equal(store.from,'app');assert.ok(store.fields.includes('credentialPublicKey'));
    assert.equal(steps.some(item=>item.to==='app'&&item.payload.some(p=>p.name==='privateKey')),false);
    assert.equal(steps.some(item=>item.payload.some(p=>/idp2\.example\.test|Keycloak Realm B/.test(p.value))),false);
  }
});

test('transport adapter leaves platform/reference data untouched and preserves external RP scope in brokered YubiKey requests',()=>{
  assert.equal(applyFidoTransport(FLOWS.login,'hello'),FLOWS.login);
  const base=getJourneySteps('passkey','web','external');const snapshot=JSON.stringify(base);
  const yubi=applyFidoTransport(base,'yubikey');
  assert.equal(applyFidoTransport(base,'yubikey'),yubi);assert.equal(JSON.stringify(base),snapshot);
  assert.equal(yubi.filter(item=>item.ctapOperation==='pin-uv').length,1);
  const command=yubi.find(item=>item.ctapOperation==='get-assertion');
  assert.equal(value(command,'rpId'),'login.partner.example.test');
  const prepare=yubi.find(item=>item.ctapOperation==='prepare');
  assert.equal(prepare.from,'browser');assert.equal(prepare.to,'browser');assert.equal(prepare.channel,'internal');
  assert.equal(prepare.fields.includes('pinUvAuthParam'),false);
  const enrolled=applyFidoTransport(getJourneySteps('enrollment','web','external'),'yubikey');
  assert.match(value(enrolled.find(item=>item.ctapOperation==='make-credential'),'rp'),/login\.partner\.example\.test/);
  assert.equal(value(enrolled.find(item=>item.ctapOperation==='make-credential'),'options.rk'),true);
});

test('direct participant and attribute definitions describe the application RP rather than a Keycloak broker',()=>{
  const actors=getFidoActorOverrides('fido-login','yubikey');
  assert.match(actors.app.role,/WebAuthn relying party/);
  assert.equal(actors.app.attributes.some(item=>forbidden.has(item.id)),false);
  assert.ok(actors.browser.attributes.some(item=>item.id==='pinUvAuthToken'));
  assert.equal(getFidoActorOverrides('fido-login','hello').browser.attributes.some(item=>item.id==='pinUvAuthToken'),false);
  const attributes=getFidoAttributeOverrides('fido-login');
  assert.equal(attributes.rpId.example,'app.example.test');assert.equal(attributes.origin.example,'https://app.example.test');
  assert.match(attributes.challengeLogin.origin,/application backend/);
  assert.match(attributes.credentialPublicKey.purpose,/application stores/);
  assert.match(getFidoAttributeOverrides('fido-enrollment').clientDataJSON.example,/webauthn\.create/);
  assert.equal(getFidoExampleOverrides().userHandle,'opaque-app-user-bytes');
});
