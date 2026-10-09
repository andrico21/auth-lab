import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, EXAMPLE, FLOWS } from '../src/protocol-data.js';
import { JOURNEYS, ARCHITECTURES, UPSTREAMS, VARIANT_ATTRIBUTES, getJourneySteps, getActorOverrides, getExampleOverrides, getAttributeOverrides } from '../src/architecture-variants.js';

const variantCanonical = item => item.id.match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const variantFind = (steps, id) => steps.find(item => variantCanonical(item) === id);
const variantValue = (item, name) => item.payload.find(p => p.name === name)?.value;
const variantsOriginal = JSON.stringify(FLOWS);

test('seven learning journeys support independent native/web and Keycloak/external selections', () => {
  assert.equal(Object.keys(JOURNEYS).length, 7);
  for (const mode of Object.keys(JOURNEYS)) for (const architecture of Object.keys(ARCHITECTURES)) for (const upstream of Object.keys(UPSTREAMS)) {
    const steps = getJourneySteps(mode, architecture, upstream);
    assert.ok(steps.length >= 8, mode);
    assert.equal(new Set(steps.map(item => item.id)).size, steps.length);
    for (const item of steps) {
      for (const actor of [item.from, item.to]) assert.ok(actor === 'authenticator' || ACTORS[actor], item.id + ': ' + actor);
      for (const field of item.fields) assert.ok(ATTRIBUTES[field] || VARIANT_ATTRIBUTES[field], item.id + ': ' + field);
      assert.ok(item.title && item.summary && item.detail && item.payload.length, item.id);
    }
    // Rendering must not produce different objects on every frame.
    assert.equal(getJourneySteps(mode, architecture, upstream), steps);
  }
  for (const mode of ['passkey','passkey-totp','enrollment','totp-enrollment']) assert.equal(getJourneySteps(mode), FLOWS[JOURNEYS[mode].flow]);
  assert.ok(variantFind(getJourneySteps('password-totp'),'p02').fields.includes('loginUsername'));
  assert.equal(variantFind(getJourneySteps('password-totp'),'p02').fields.includes('userName'),false);
  assert.equal(JSON.stringify(FLOWS), variantsOriginal, 'Scenario transformation must not mutate the reference model.');
});

test('password-only requires a password but no passkey or TOTP, while OTP-only has account identification and one possession factor', () => {
  const password = getJourneySteps('password');
  assert.ok(password.some(item => item.from === 'browser' && item.to === 'realmB' && item.fields.includes('password')));
  assert.equal(password.some(item => item.fields.includes('otpCode') || item.fields.includes('signature') || item.to === 'authenticator'), false);
  assert.match(variantFind(password,'p03').detail, /password-only/);
  const otp = getJourneySteps('one-time-code');
  assert.equal(otp.some(item => item.fields.includes('password') || item.fields.includes('signature') || item.to === 'authenticator'), false);
  assert.equal(variantFind(otp,'u02').fields[0], 'loginUsername');
  assert.match(variantFind(otp,'u03').detail, /still incomplete|Sign-in is still incomplete/);
  assert.match(variantFind(otp,'l07').detail, /previously|already have an enrolled/);
  assert.match(variantFind(otp,'l07').detail, /one factor, not MFA/);
  assert.match(JOURNEYS['one-time-code'].caveat, /not the default.*not MFA/);
  const verify = otp.findIndex(item => variantCanonical(item) === 'm05');
  const issue = otp.findIndex(item => variantCanonical(item) === 'l15');
  assert.ok(verify > 0 && issue > verify);
  assert.equal(otp.filter(item => item.phase === 'otp').length,8);
  assert.equal(otp.some(item => item.phase === 'password' || item.phase === 'mfa'),false);
  assert.equal(variantValue(variantFind(otp,'m04'),'otp'),'287082');
  assert.equal(otp.some(item => item.to === 'app' && item.fields.includes('otpCode')),false);
});

test('network web app callback is HTTPS and code redemption combines backend-only authentication with PKCE', () => {
  for (const mode of Object.keys(JOURNEYS).filter(key => !JOURNEYS[key].enrollment)) {
    const steps = getJourneySteps(mode, 'web');
    const first = variantFind(steps,'l01');
    assert.equal(first.to,'browser');
    assert.equal(variantFind(steps,'w00').to,'app');
    const prepare = variantFind(steps,'l02');
    assert.equal(prepare.from,'app');assert.equal(prepare.to,'app');
    assert.equal(prepare.clientKind,'confidential-web');
    assert.match(prepare.detail,/server-side/);
    const open = variantFind(steps,'l03');
    assert.equal(open.channel,'redirect');
    assert.equal(variantValue(open,'redirect_uri'),ARCHITECTURES.web.callback);
    assert.equal(variantValue(open,'code_challenge'),EXAMPLE.challenge);
    assert.equal(variantValue(open,'code_verifier'),undefined);
    const callback = variantFind(steps,'l21');
    assert.equal(callback.from,'browser');assert.equal(callback.to,'app');assert.equal(callback.channel,'https');
    assert.equal(variantValue(callback,'HTTP'),'GET '+ARCHITECTURES.web.callback);
    const exchange = variantFind(steps,'l23');
    assert.equal(exchange.channel,'backchannel');
    assert.match(variantValue(exchange,'Authorization'),/^Basic /);
    assert.equal(variantValue(exchange,'code_verifier'),EXAMPLE.verifier);
    assert.equal(variantValue(exchange,'redirect_uri'),ARCHITECTURES.web.callback);
    assert.ok(exchange.fields.includes('clientSecretApp'));
    const token = variantFind(steps,'l24');
    assert.equal(token.to,'app');assert.equal(variantValue(token,'aud'),'web-app');
    const session = variantFind(steps,'l25');
    assert.equal(session.from,'app');assert.equal(session.to,'browser');
    assert.ok(session.fields.includes('sessionCookieApp'));
    assert.match(variantValue(session,'Set-Cookie'),/Secure; HttpOnly; SameSite=Lax/);
    assert.equal(variantValue(session,'id_token'),undefined);
    assert.equal(variantFind(steps,'w01').fields.length,0);
    for (const item of steps.filter(item => item.from !== item.to && item.channel !== 'backchannel')) {
      assert.equal(variantValue(item,'code_verifier'),undefined,item.id);
      assert.equal(variantValue(item,'client_secret'),undefined,item.id);
      assert.equal(item.payload.some(p => /127\.0\.0\.1:54321/.test(p.value)),false,item.id);
    }
  }
});

test('independent external OIDC provider changes issuer, endpoints, broker alias and passkey RP scope without forwarding app PKCE', () => {
  for (const architecture of ['native','web']) {
    const steps = getJourneySteps('passkey',architecture,'external');
    const request = variantFind(steps,'l06');
    assert.equal(variantValue(request,'Location'),'https://login.partner.example.test/oauth2/authorize');
    assert.equal(variantValue(request,'redirect_uri'),'https://idp1.example.test/realms/realm-a/broker/external-idp/endpoint');
    const proof = variantFind(steps,'l08');
    assert.equal(variantValue(proof,'rpId'),'login.partner.example.test');
    assert.equal(variantValue(variantFind(steps,'l14'),'Expected origin'),'https://login.partner.example.test');
    const upstreamToken = variantFind(steps,'l18');
    assert.equal(variantValue(upstreamToken,'iss'),'https://login.partner.example.test');
    assert.equal(variantValue(upstreamToken,'sub'),'external-user-913');
    assert.equal(variantValue(upstreamToken,'aud'),EXAMPLE.clientBroker);
    const upstreamExchange = variantFind(steps,'l17');
    assert.equal(variantValue(upstreamExchange,'code_verifier'),undefined);
    assert.ok(!upstreamExchange.fields.includes('codeVerifier'));
    assert.match(variantFind(steps,'l05').detail,/not forwarded|not forwarded as/);
    assert.ok(steps.every(item => item.upstream === 'external' && item.upstreamKind === 'external-oidc'));
  }
  const options = getJourneySteps('enrollment','native','external').find(item => variantCanonical(item)==='e03');
  assert.match(variantValue(options,'rp'),/login\.partner\.example\.test/);
  assert.doesNotMatch(variantValue(options,'rp'),/idp2|Realm B/);
});

test('actors and attribute definitions reflect backend placement and external provider prerequisites', () => {
  assert.deepEqual(getActorOverrides(),{});
  const actors = getActorOverrides('web','external');
  assert.match(actors.app.name,/Web application/);
  assert.ok(actors.app.attributes.some(item => item.id === 'clientSecretApp'));
  assert.ok(actors.browser.attributes.some(item => item.id === 'sessionCookieApp'));
  assert.match(actors.realmB.name,/External OIDC/);
  assert.match(UPSTREAMS.external.description,/supports.*configured/);
  const attributes = getAttributeOverrides('web','external');
  assert.equal(attributes.redirectApp.example,ARCHITECTURES.web.callback);
  assert.match(attributes.redirectApp.origin,/web server/);
  assert.match(attributes.codeVerifier.origin,/web backend/);
  assert.equal(attributes.issuerB.example,'https://login.partner.example.test');
  assert.equal(attributes.rpId.example,'login.partner.example.test');
  assert.equal(getExampleOverrides('web').clientIdApp,'web-app');
  for(const [id,item] of Object.entries(VARIANT_ATTRIBUTES)) for(const key of ['name','meaning','origin','purpose','example','standard','source']) assert.ok(item[key],id+' lacks '+key);
});
