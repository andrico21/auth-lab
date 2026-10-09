import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, EXAMPLE, FLOWS } from '../src/protocol-data.js';
import { JOURNEYS, UPSTREAMS, VARIANT_ATTRIBUTES, getJourneySteps, getActorOverrides, getAttributeOverrides, getExampleOverrides } from '../src/architecture-variants.js';
import { applySingleRealm, getSingleRealmActorOverrides } from '../src/single-realm.js';
import { applyFidoTransport } from '../src/fido-direct.js';

const singleCanonical=item=>item.id.match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const singleFind=(steps,id)=>steps.find(item=>singleCanonical(item)===id);
const singleValue=(item,name)=>item.payload.find(p=>p.name===name)?.value;
const singleForbidden=new Set(['clientIdBroker','clientSecret','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','issuerB','subjectB','authorizationHeader']);
const singleDeleted=new Set(['l05','l06','l07','l15','l16','l17','l18','l19']);

test('single realm is an identity setup option for all seven journeys and both application architectures',()=>{
  assert.equal(UPSTREAMS.single.title,'Single Keycloak realm');
  assert.equal(Object.keys(JOURNEYS).length,7,'Do not add unrelated factor journeys for topology.');
  const original=JSON.stringify(FLOWS);
  for(const mode of Object.keys(JOURNEYS))for(const architecture of ['native','web']) {
    const steps=getJourneySteps(mode,architecture,'single');
    assert.ok(steps.length>=8);assert.equal(getJourneySteps(mode,architecture,'single'),steps);
    assert.equal(new Set(steps.map(item=>item.id)).size,steps.length);
    for(const item of steps) {
      assert.equal(item.topology,'single');assert.equal(item.upstreamKind,'single-realm');assert.equal(item.relyingPartyActor,'realmA');
      for(const actor of [item.from,item.to]){assert.notEqual(actor,'realmB');assert.ok(actor==='authenticator'||ACTORS[actor]);}
      assert.equal(singleDeleted.has(singleCanonical(item)),false,item.id);
      for(const field of item.fields){assert.ok(ATTRIBUTES[field]||VARIANT_ATTRIBUTES[field],item.id+': '+field);assert.equal(singleForbidden.has(field),false,item.id+': '+field);}
      for(const packet of item.payload)assert.doesNotMatch(String(packet.value),/idp2\.example\.test|realm-a-broker|st_broker_|n_broker_|c_broker_|user-in-B|opaque-user-B|\/broker\//,item.id);
    }
  }
  assert.equal(JSON.stringify(FLOWS),original,'Single realm must clone the reference journeys.');
});

test('Realm A completes its required factors before issuing its own application code for its existing account',()=>{
  for(const architecture of ['native','web'])for(const mode of ['passkey','password','one-time-code','password-totp','passkey-totp']) {
    const steps=getJourneySteps(mode,architecture,'single');
    const code=singleFind(steps,'l20');assert.equal(code.from,'realmA');assert.equal(code.to,'browser');
    assert.ok(code.fields.includes('subjectA')&&code.fields.includes('session')&&code.fields.includes('clientIdApp'));
    assert.match(code.detail,/existing local account user-in-A-204/);
    assert.match(code.detail,/single-use authorization code bound to the registered application client_id/);
    const required=mode==='passkey'?'l14':mode==='password'?'p03':'m05';
    const verified=singleFind(steps,required);assert.equal(verified.to,'realmA');assert.ok(steps.indexOf(verified)<steps.indexOf(code));
    if(mode==='passkey-totp')assert.match(singleFind(steps,'l14').detail,/pending.*TOTP|TOTP.*pending/);
    if(mode==='one-time-code'){
      assert.equal(steps.some(item=>item.fields.includes('password')),false);
      assert.match(singleFind(steps,'l04').detail,/one possession factor, not MFA/);
    }
    for(const item of steps.filter(item=>item.from!==item.to))assert.equal(item.payload.some(p=>p.name==='secret'||p.name==='privateKey'),false,item.id);
  }
});

test('application client_id selects registration, binds codes, identifies native/body or confidential/Basic redemption and matches aud',()=>{
  for(const architecture of ['native','web']){
    const steps=getJourneySteps('passkey',architecture,'single');const client=architecture==='web'?'web-app':'desktop-app';
    const request=singleFind(steps,'l04');assert.equal(singleValue(request,'client_id'),client);assert.match(request.detail,/select the registered application configuration/);
    assert.match(singleFind(steps,'l20').detail,new RegExp('client_id '+client));
    const exchange=singleFind(steps,'l23');assert.equal(exchange.from,'app');assert.equal(exchange.to,'realmA');assert.ok(exchange.fields.includes('clientIdApp'));
    if(architecture==='native'){
      assert.equal(singleValue(exchange,'client_id'),client);assert.equal(singleValue(exchange,'Authorization'),undefined);assert.match(exchange.detail,/public client_id by itself does not authenticate/);
    }else{
      assert.equal(singleValue(exchange,'client_id'),undefined,'Basic carries the web client ID; do not invent a redundant form member.');
      assert.match(singleValue(exchange,'Authorization'),/Basic.*web-app/);assert.match(exchange.detail,/client_id is encoded as the Basic username/);
    }
    const tokens=singleFind(steps,'l24');assert.equal(singleValue(tokens,'iss'),EXAMPLE.issuerA);assert.equal(singleValue(tokens,'aud'),client);assert.equal(singleValue(tokens,'nonce'),EXAMPLE.nonceApp);assert.equal(singleValue(tokens,'sub'),'user-in-A-204');
    assert.match(singleFind(steps,'l25').detail,new RegExp('aud claim must contain its own registered client_id '+client));
  }
});

test('native and HTTPS callbacks preserve the app code, state and PKCE while the browser never receives the verifier',()=>{
  for(const architecture of ['native','web']){
    const steps=getJourneySteps('password-totp',architecture,'single');const callback=singleFind(steps,'l21');
    const redirect=architecture==='web'?'https://app.example.test/oidc/callback':EXAMPLE.appCallback;
    assert.equal(callback.from,'browser');assert.equal(callback.to,'app');assert.equal(singleValue(callback,'HTTP'),'GET '+redirect);
    assert.equal(singleValue(callback,'code'),EXAMPLE.codeA);assert.equal(singleValue(callback,'state'),EXAMPLE.stateApp);
    const exchange=singleFind(steps,'l23');assert.equal(singleValue(exchange,'redirect_uri'),redirect);assert.equal(singleValue(exchange,'code_verifier'),EXAMPLE.verifier);
    for(const item of steps.filter(item=>item.to==='browser'||item.channel==='redirect'))assert.equal(singleValue(item,'code_verifier'),undefined,item.id);
  }
});

test('passkey and TOTP enrollment target verified A accounts and YubiKey CTAP inherits A RP scope',()=>{
  for(const architecture of ['native','web']){
    const passkey=getJourneySteps('enrollment',architecture,'single');
    assert.match(singleFind(passkey,'e01').detail,/verified Realm A account/);
    assert.equal(singleFind(passkey,'e03').from,'realmA');assert.match(singleValue(singleFind(passkey,'e03'),'rp'),/idp1\.example\.test.*Keycloak Realm A/);
    assert.match(singleValue(singleFind(passkey,'e03'),'user'),/opaque-user-A-bytes/);
    assert.equal(singleFind(passkey,'e07').to,'realmA');assert.equal(singleFind(passkey,'e08').from,'realmA');
    const totp=getJourneySteps('totp-enrollment',architecture,'single');
    assert.match(singleFind(totp,'t01').detail,/verified Realm A account|verify the account identity/);
    assert.equal(singleFind(totp,'t03').from,'realmA');assert.equal(singleFind(totp,'t07').to,'realmA');
    const uri=new URL(singleValue(singleFind(totp,'t03'),'Provisioning URI (de facto)'));assert.equal(uri.searchParams.get('issuer'),'Realm A');
    const login=applyFidoTransport(getJourneySteps('passkey',architecture,'single'),'yubikey');
    const assertion=login.find(item=>item.ctapOperation==='get-assertion');assert.equal(singleValue(assertion,'rpId'),'idp1.example.test');assert.equal(assertion.upstreamKind,'single-realm');assert.equal(assertion.relyingPartyActor,'realmA');
    const creation=applyFidoTransport(passkey,'yubikey').find(item=>item.ctapOperation==='make-credential');assert.match(singleValue(creation,'rp'),/idp1\.example\.test/);assert.equal(singleValue(creation,'options.rk'),true);
  }
});

test('single realm actor and attribute overrides contain A’s credentials and one registered application client',()=>{
  for(const architecture of ['native','web']){
    const actors=getActorOverrides(architecture,'single');const provider=actors.realmA;
    assert.match(provider.role,/OIDC provider.*authentication.*WebAuthn relying party/);
    assert.equal(provider.attributes.some(entry=>singleForbidden.has(entry.id)),false);
    assert.equal(provider.attributes.find(entry=>entry.id==='clientIdApp').kind,'static');
    assert.equal(provider.attributes.find(entry=>entry.id==='subjectA').kind,'static','Use the existing A account, rather than generating a new imported user.');
    if(architecture==='web')assert.match(actors.app.role,/Confidential server-side/);
    const definitions=getAttributeOverrides(architecture,'single');assert.equal(definitions.rpId.example,'idp1.example.test');assert.equal(definitions.origin.example,'https://idp1.example.test');assert.equal(definitions.userHandle.example,'opaque-user-A-bytes');
    assert.match(definitions.challengeLogin.origin,/Realm A/);assert.match(definitions.clientIdApp.origin,/client registration/);assert.match(definitions.clientIdApp.purpose,/registered client configuration/);
    assert.equal(getExampleOverrides(architecture,'single').issuerA,EXAMPLE.issuerA);assert.equal(getExampleOverrides(architecture,'single').tokenEndpoint,EXAMPLE.tokenA);
  }
  assert.equal(getSingleRealmActorOverrides(),getSingleRealmActorOverrides());
  assert.equal(applySingleRealm(FLOWS.login),applySingleRealm(FLOWS.login));
});
