import test from 'node:test';
import assert from 'node:assert/strict';
import {buildCoreHeldObjects,CORE_HELD_OBJECT_INTERACTIONS,CORE_HELD_OBJECT_SCOPE} from '../src/held-object-core.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,assertHeldObjectCoverage} from '../src/held-object-state.js';
import {makeHeldObjectFixture} from '../tools/verification/held-object-fixtures.mjs';

function fixture(config={},choice='core') {
  const args=makeHeldObjectFixture(choice,config);
  const plan=buildCoreHeldObjects(args);
  return {...args,plan,compiled:compileHeldObjects(plan,{model:args.model,steps:args.steps})};
}
function snapshot(f,id,position='complete') {
  const index=typeof id==='number'?id:f.steps.findIndex(s=>s.id===id||String(s.id).endsWith('-'+id));
  assert.ok(typeof id==='number'?index>=-1:index>=0,'Known source cursor '+id);
  return projectHeldObjects(f.compiled,{eventIndex:index,milestone:index<0?'initial':position});
}
const held=(s,id,owner)=>s.holdings.filter(h=>h.artifactId===id&&(!owner||h.actorId===owner));
const created=(s,id)=>s.artifacts.some(a=>a.artifactId===id);
const last=f=>snapshot(f,f.steps.length-1);
const declaration=(f,id)=>f.plan.artifacts.find(a=>a.artifactId===id);

test('Core only dispatch and concrete interaction/scope evidence',()=>{
  assert.equal(buildCoreHeldObjects({model:{id:'lab-spa-api'}}),null);
  assert.equal(new Set(CORE_HELD_OBJECT_INTERACTIONS.map(c=>c.familyId)).size,11);
  assert.ok(CORE_HELD_OBJECT_INTERACTIONS.every(c=>c.config&&c.rationale&&c.predicate));
  assert.ok(CORE_HELD_OBJECT_SCOPE.excluded.some(s=>s.includes('actor_token')));
  const f=fixture({mode:'password',upstream:'single'});
  assert.equal(f.plan.artifacts.some(a=>a.type==='refresh-token'),false);
  assert.ok(f.plan.limitations.some(text=>text.includes('not a selected issued credential')));
});

for(const interaction of CORE_HELD_OBJECT_INTERACTIONS) test('Core interaction '+interaction.id,()=>{
  const f=fixture(interaction.config);
  assertHeldObjectCoverage(f.compiled);
  const final=last(f);
  assert.equal(final.coverageStatus,'complete');
  assert.ok(final.holdings.every(h=>h.retention==='retained'));
  assert.deepEqual(projectHeldObjects(f.compiled,final.cursor),final);
  assert.ok(snapshot(f,-1).artifacts.every(a=>f.plan.initial.some(e=>e.op==='create'&&e.artifactId===a.artifactId)));
});

for(const architecture of ['native','web'])test(architecture+' PKCE owner, callback delivery and cookie permissions',()=>{
  const f=fixture({mode:'password',architecture,upstream:'single'});
  const initial=snapshot(f,-1);
  assert.equal(created(initial,'app-pkce-verifier'),false);
  const prepared=snapshot(f,'l02');
  assert.equal(held(prepared,'app-pkce-verifier','app').length,1);
  assert.equal(held(prepared,'app-pkce-verifier','browser').length,0);
  assert.deepEqual(declaration(f,'app-pkce-challenge').derivedFrom,['app-pkce-verifier']);
  assert.equal(held(snapshot(f,'l21','before'),'app-oidc-code','app').length,0);
  assert.equal(held(snapshot(f,'l21'),'app-oidc-code','app').length,1);
  assert.equal(held(snapshot(f,'l24','before'),'oidc-app-access-token','app').length,0);
  const final=last(f);
  assert.equal(held(final,'oidc-app-access-token','app').length,1);
  assert.equal(held(final,'oidc-app-access-token','browser').length,0);
  assert.equal(held(final,'app-pkce-verifier').length,0);
  const cookies=held(final,'application-cookie','browser');
  assert.equal(cookies.length,architecture==='web'?1:0);
  if(cookies.length) {
    const inspected=inspectHeldObject(final,cookies[0].holdingId);
    assert.ok(inspected);
    assert.equal(JSON.stringify(inspected).includes('sessionCookieApp (symbolic fixture value)'),false,'HttpOnly cookie value is not exposed to browser script inspection');
  }
});

test('broker OIDC generations and retained sender credentials never merge',()=>{
  const f=fixture({mode:'password-totp',architecture:'web',upstream:'keycloak'});
  const before=snapshot(f,'l05','before');
  assert.equal(created(before,'broker-oidc-state'),false);
  const pending=snapshot(f,'l05');
  assert.ok(created(pending,'app-oidc-state'));
  assert.ok(created(pending,'broker-oidc-state'));
  const final=last(f);
  assert.equal(held(final,'broker-oidc-registration','realmA').length,1);
  assert.equal(held(final,'oidc-broker-id-token','realmA').length,1);
  assert.equal(held(final,'oidc-app-id-token','app').length,1);
  assert.equal(held(final,'oidc-app-id-token','realmA').length,0,'Issuer output is not permanent token possession');
});

test('single realm creates no upstream generations regardless irrelevant broker dimensions',()=>{
  const f=fixture({mode:'password',upstream:'single',brokerProtocol:'saml',tokenProtection:'broker-jwe'});
  assert.equal(f.plan.artifacts.some(a=>/broker/.test(a.artifactId)),false);
});

for(const initiation of ['sp','idp'])test('encrypted SAML '+initiation+' separates transport and readable assertion',()=>{
  const f=fixture({mode:'password',architecture:'web',upstream:'single',applicationProtocol:'saml',initiation,binding:'post',encryptAssertions:true});
  assert.equal(!!declaration(f,'saml-app-request'),initiation==='sp');
  const response=f.steps.find(s=>s.samlHop==='app'&&s.samlStage==='response-post');
  const carried=snapshot(f,response.id);
  assert.equal(held(carried,'saml-app-response','browser').length,1);
  assert.equal(held(carried,'saml-app-assertion','browser').length,0);
  assert.equal(declaration(f,'saml-app-assertion').representations[0].readableBy.includes('browser'),false);
  const verify=f.steps.find(s=>s.samlHop==='app'&&s.samlStage==='response-verify');
  assert.equal(held(snapshot(f,verify.id,'before'),'saml-app-assertion','app').length,0);
  assert.equal(held(snapshot(f,verify.id),'saml-app-assertion','app').length,1);
  assert.equal(declaration(f,'saml-app-assertion').representations[0].fields.some(a=>a.attributeId==='samlInResponseToApp'),initiation==='sp');
});

test('JWE plaintext view waits for authenticated decrypt, with independent local keys',()=>{
  const f=fixture({mode:'password',upstream:'keycloak',architecture:'web',tokenProtection:'both-jwe'});
  for(const hop of ['app','broker']) {
    const recipient=hop==='app'?'app':'realmA';
    const wire=f.steps.find(s=>s.jweHop===hop&&s.jweStage==='wire');
    const decrypt=f.steps.find(s=>s.jweHop===hop&&s.jweStage==='decrypt');
    const afterWire=snapshot(f,wire.id);
    assert.equal(held(afterWire,'oidc-'+hop+'-id-token',recipient).filter(h=>h.representationId==='encrypted').length,1);
    assert.equal(held(afterWire,'oidc-'+hop+'-id-token',recipient).some(h=>h.representationId==='view'),false);
    assert.equal(held(snapshot(f,decrypt.id),'oidc-'+hop+'-id-token',recipient).some(h=>h.representationId==='view'),true);
    const key=declaration(f,'jwe-'+hop+'-private-key');
    assert.deepEqual(key.representations[0].readableBy,[recipient]);
    assert.equal(held(last(f),'jwe-'+hop+'-cek').length,0);
  }
});

for(const authenticator of ['hello','yubikey'])test(authenticator+' private key remains local; RP has public record only',()=>{
  const f=fixture({mode:'passkey-totp',upstream:'keycloak',authenticator});
  const initial=snapshot(f,-1);
  assert.equal(held(initial,'fido-private-key',authenticator).length,1);
  assert.equal(held(initial,'fido-rp-record','realmB').length,1);
  assert.deepEqual(declaration(f,'fido-private-key').representations[0].readableBy,[authenticator]);
  assert.equal(held(last(f),'fido-private-key').length,1);
  assert.equal(held(last(f),'totp-secret','totp').length,1);
  assert.equal(held(last(f),'totp-input').length,0);
  if(authenticator==='yubikey') {
    assert.ok(declaration(f,'ctap-result'));
    assert.deepEqual(declaration(f,'fido-proof').derivedFrom,['ctap-result','fido-client-context']);
    assert.equal(declaration(f,'ctap-result').representations[0].readableBy.includes('realmB'),false);
  }
});

test('enrollment starts verified but new key and TOTP seed do not preexist',()=>{
  const f=fixture({mode:'enrollment',upstream:'single',authenticator:'yubikey'});
  assert.ok(created(snapshot(f,-1),'verified-account-context'));
  assert.equal(created(snapshot(f,-1),'fido-private-key'),false);
  assert.equal(held(snapshot(f,'e08'),'fido-rp-record','realmA').length,1);
  const otp=fixture({mode:'totp-enrollment',upstream:'single'});
  assert.equal(created(snapshot(otp,-1),'totp-enrollment-secret'),false);
  assert.equal(held(snapshot(otp,'t03'),'totp-enrollment-secret','browser').length,1);
  assert.equal(held(snapshot(otp,'t04'),'totp-enrollment-secret','browser').length,0);
  assert.equal(held(last(otp),'totp-enrollment-secret','totp').length,1);
  assert.equal(held(last(otp),'totp-enrollment-secret','realmA').length,1);
  assert.equal(held(last(otp),'totp-provisioning-uri').length,0);
});

for(const providerProfileId of ['generic','entra','okta','cognito','aws-identity-center'])test(providerProfileId+' managed boundary never fabricates factor stores',()=>{
  const f=fixture({mode:'password',upstream:'external',providerManaged:true,providerProfileId,brokerProtocol:providerProfileId==='aws-identity-center'?'saml':'oidc'});
  assert.equal(f.plan.artifacts.some(a=>['password','password-verifier','symmetric-key','authentication-proof','public-key-record'].includes(a.type)),false);
  assert.equal(f.plan.artifacts.some(a=>/fido|totp/.test(a.artifactId)),false);
  if(providerProfileId==='entra')assert.match(declaration(f,'broker-oidc-registration').details,/client_secret_post/);
});

for(const architecture of ['native','web'])test('Device '+architecture+' private code never reaches approval browser',()=>{
  const f=fixture({mode:'password-totp',oidcFlow:'device',architecture,upstream:'single'});
  assert.equal(held(snapshot(f,'device-pending-response'),'oidc-app-access-token').length,0);
  assert.equal(held(snapshot(f,'device-slow-response'),'oidc-app-access-token').length,0);
  assert.equal(held(snapshot(f,'device-enter-user-code'),'device-user-code','browser').length,1);
  assert.equal(f.plan.artifacts.find(a=>a.artifactId==='device-private-code').representations[0].readableBy.includes('browser'),false);
  assert.equal(held(last(f),'oidc-app-access-token','app').length,1);
  assert.equal(held(last(f),'oidc-app-access-token','browser').length,0);
  const secret=declaration(f,'device-registration').representations[0].fields.some(a=>a.attributeId==='clientSecretApp');
  assert.equal(secret,architecture==='web');
});

test('CIBA handle and service callback credential are not tokens or device UI data',()=>{
  const f=fixture({mode:'password-totp',oidcFlow:'ciba',architecture:'web',upstream:'single'});
  const pending=snapshot(f,'ciba-pending');
  assert.equal(held(pending,'ciba-handle','app').length,1);
  assert.equal(created(pending,'oidc-app-id-token'),false);
  assert.equal(declaration(f,'ciba-channel-credential').representations[0].readableBy.includes('browser'),false);
  assert.equal(declaration(f,'ciba-handle').representations[0].readableBy.includes('browser'),false);
  assert.equal(held(last(f),'ciba-channel-credential').length,0);
  assert.equal(held(last(f),'oidc-app-id-token','app').length,1);
  assert.equal(held(last(f),'oidc-app-id-token','browser').length,0);
});

test('service/exchange normalization omits human credentials and keeps exact source lineage',()=>{
  for(const oidcFlow of ['client-credentials','token-exchange']) {
    const f=fixture({oidcFlow,mode:'passkey-totp',upstream:'external',architecture:'web'});
    assert.equal(f.plan.artifacts.some(a=>/fido|totp|password|cookie|nonce|pkce/.test(a.artifactId)),false);
    assert.equal(f.plan.artifacts.some(a=>a.type==='refresh-token'),false);
    if(oidcFlow==='token-exchange') {
      assert.equal(held(snapshot(f,-1),'exchange-source-token','app').length,1);
      assert.equal(created(snapshot(f,-1),'exchange-access-token'),false);
      assert.deepEqual(declaration(f,'exchange-access-token').derivedFrom,['exchange-source-token']);
      assert.equal(held(last(f),'exchange-source-token','app').length,1);
      assert.equal(held(last(f),'exchange-access-token','app').length,1);
      assert.equal(held(last(f),'exchange-access-token','realmA').length,0);
    }
  }
});

test('all Core-backed learning presets compile without changing contextual source',()=>{
  for(const choice of ['basic-keycloak','web-mfa','web-passkey','basic-saml','corporate-external','two-realms','desktop-sign-in','service-to-service','device-sign-in','backend-token-exchange']) {
    const f=fixture({},choice);
    assertHeldObjectCoverage(f.compiled);
    assert.equal(last(f).coverageStatus,'complete');
  }
});

test('immutable context rebuild and arbitrary seek never reuse stale qualified objects',()=>{
  const a=fixture({mode:'passkey',upstream:'single',architecture:'native'});
  const b=fixture({mode:'password',upstream:'single',architecture:'web'});
  assert.notEqual(a.contextId,b.contextId);
  assert.ok(last(a).holdings.every(h=>h.contextId===a.contextId));
  assert.ok(last(b).holdings.every(h=>h.contextId===b.contextId));
  assert.equal(b.plan.artifacts.some(a=>a.artifactId==='fido-private-key'),false);
  const sought=snapshot(a,'l24');
  snapshot(a,-1);last(a);
  assert.deepEqual(snapshot(a,'l24'),sought);
});
