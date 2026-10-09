import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { VARIANT_ATTRIBUTES, getJourneySteps } from '../src/architecture-variants.js';
import { FIDO_ATTRIBUTES, getStepAttributeOperations, getAttributeUsage } from '../src/attribute-usage.js';
import { JWE_ATTRIBUTES, applyJweProtection } from '../src/jwe-data.js';
import { DEVICE_ATTRIBUTES, DEVICE_SOURCES, DEVICE_TOPIC_IDS, getDeviceSteps, getDeviceActorOverrides, getDeviceAttributeOverrides, getDeviceExampleOverrides } from '../src/device-flow-data.js';

Object.assign(ATTRIBUTES, VARIANT_ATTRIBUTES, FIDO_ATTRIBUTES, DEVICE_ATTRIBUTES, JWE_ATTRIBUTES);
const deviceTestModes = ['passkey', 'password', 'one-time-code', 'password-totp', 'passkey-totp'];
const deviceTestStage = (steps, id) => steps.find(step => step.deviceStage === id);
const deviceTestWire = step => getStepAttributeOperations(step).filter(action => ['send', 'receive'].includes(action.kind));
const deviceTestAllWire = steps => steps.flatMap(step => deviceTestWire(step).map(action => ({ step, ...action })));
const deviceTestCanonical = step => step.id.match(/(?:^|-)([a-z]\d{2})$/)?.[1];

test('device models compose every configured factor with public/confidential clients and both authenticators without mutating references', () => {
  const original = JSON.stringify(FLOWS);
  for (const mode of deviceTestModes) for (const architecture of ['native', 'web']) for (const authenticator of ['hello', 'yubikey']) {
    const source = getJourneySteps(mode, architecture, 'single'), before = JSON.stringify(source);
    const config = { mode, architecture, authenticator, upstream: 'external' };
    const steps = getDeviceSteps(config);
    assert.equal(getDeviceSteps(config), steps, 'Returns the cached model');
    assert.equal(new Set(steps.map(step => step.id)).size, steps.length);
    for (const step of steps) {
      assert.equal(step.upstream, 'single');
      assert.equal(step.oidcGrant, 'device_code');
      assert.ok(step.attributeOperations, step.id + ' has an explicit authoritative ledger');
      for (const actor of [step.from, step.to]) assert.ok(actor === 'authenticator' || ACTORS[actor], actor);
      for (const action of getStepAttributeOperations(step, authenticator)) {
        assert.ok(ATTRIBUTES[action.attributeId], step.id + ': ' + action.attributeId);
        assert.ok(ACTORS[action.actorId], step.id + ': ' + action.actorId);
      }
      assert.equal(step.from === 'realmB' || step.to === 'realmB', false);
    }
    assert.equal(JSON.stringify(source), before, 'Does not rewrite source factor models');
    const verificationId = mode === 'password' ? 'p03' : mode === 'passkey' ? 'l14' : 'm05';
    const verification = steps.find(step => deviceTestCanonical(step) === verificationId);
    assert.ok(verification, mode);
    assert.ok(steps.indexOf(verification) < steps.indexOf(deviceTestStage(steps, 'approval-confirm')));
    assert.ok(steps.indexOf(deviceTestStage(steps, 'approval-confirm')) < steps.indexOf(deviceTestStage(steps, 'final-poll')));
    assert.ok(steps.indexOf(deviceTestStage(steps, 'redeem')) < steps.indexOf(deviceTestStage(steps, 'l24')));
    if (mode === 'password-totp' || mode === 'passkey-totp') assert.ok(steps.find(step => deviceTestCanonical(step) === 'm05'));
    if (authenticator === 'yubikey' && mode.includes('passkey')) assert.ok(steps.some(step => step.ctapOperation));
  }
  assert.equal(JSON.stringify(FLOWS), original);
});

test('private device_code is never displayed or sent to the verification browser; user_code stays off token polls', () => {
  const steps = getDeviceSteps({ mode: 'password-totp' });
  const deviceCodeWire = deviceTestAllWire(steps).filter(action => action.attributeId === 'deviceCode');
  assert.ok(deviceCodeWire.length > 0);
  assert.ok(deviceCodeWire.every(action => ['app', 'realmA'].includes(action.actorId)));
  const display = deviceTestStage(steps, 'display');
  assert.deepEqual(display.payload.map(item => item.name), ['verification_uri', 'user_code']);
  assert.equal(display.fields.includes('deviceCode'), false);
  for (const id of ['pending-poll', 'early-poll', 'final-poll']) {
    const poll = deviceTestStage(steps, id);
    assert.ok(poll.payload.some(item => item.name === 'device_code'));
    assert.equal(poll.fields.includes('deviceUserCode'), false);
    assert.equal(poll.payload.some(item => item.name === 'user_code'), false);
    assert.equal(poll.from, 'app'); assert.equal(poll.to, 'realmA');
  }
  for (const step of steps) if (step.from === 'browser' || step.to === 'browser') assert.equal(step.fields.includes('deviceCode'), false, step.id);
  assert.equal(steps.some(step => step.from === 'app' && step.to === 'browser'), false, 'The person opens an independent browser; no app browser redirect');
  assert.deepEqual(deviceTestStage(steps, 'open-verification').from, 'user');
});

test('device grant has no callback, authorization code, PKCE or invented nonce even on confidential variant', () => {
  const disallowed = new Set(['redirectApp', 'stateApp', 'nonceApp', 'codeVerifier', 'codeChallenge', 'codeChallengeMethod', 'codeA', 'clientIdBroker', 'codeB']);
  for (const architecture of ['native', 'web']) {
    const steps = getDeviceSteps({ mode: 'passkey', architecture });
    for (const step of steps) {
      assert.equal(step.fields.some(id => disallowed.has(id)), false, step.id);
      assert.equal(getStepAttributeOperations(step).some(action => disallowed.has(action.attributeId)), false, step.id);
    }
    for (const id of ['pending-poll', 'early-poll', 'final-poll']) {
      const poll = deviceTestStage(steps, id);
      assert.equal(poll.payload.find(item => item.name === 'grant_type').value, 'urn:ietf:params:oauth:grant-type:device_code');
      assert.equal(poll.payload.some(item => ['redirect_uri', 'code', 'code_verifier', 'nonce'].includes(item.name)), false);
    }
    const token = deviceTestStage(steps, 'l24');
    assert.deepEqual(token.idTokenClaimIds, ['issuerA', 'audience', 'subjectA', 'exp', 'iat']);
    assert.equal(token.payload.some(item => item.name === 'nonce'), false);
    assert.equal(deviceTestStage(steps, 'l25').from, 'app'); assert.equal(deviceTestStage(steps, 'l25').to, 'app');
  }
});

test('public identification and confidential Basic client authentication are correct on both device endpoint and each poll', () => {
  for (const architecture of ['native', 'web']) {
    const steps = getDeviceSteps({ architecture }), confidential = architecture === 'web';
    const client = confidential ? 'device-confidential' : 'device-client';
    for (const id of ['authorize-request', 'pending-poll', 'early-poll', 'final-poll']) {
      const stage = deviceTestStage(steps, id), wire = deviceTestWire(stage);
      assert.equal(stage.payload.some(item => item.name === 'Authorization'), confidential);
      assert.equal(stage.payload.some(item => item.name === 'client_id'), !confidential);
      assert.equal(stage.attributeValues.clientIdApp, client);
      assert.equal(wire.some(action => action.attributeId === 'clientSecretApp'), false, 'Secret transported within Basic, not separate client_secret field');
      assert.equal(wire.some(action => action.attributeId === 'authorizationHeaderApp'), confidential);
      assert.equal(wire.some(action => action.attributeId === 'clientIdApp'), !confidential);
      if (confidential) assert.ok(stage.attributeOperations.some(action => action.attributeId === 'clientSecretApp' && action.actorId === 'app' && action.kind === 'use'));
    }
    const token = deviceTestStage(steps, 'l24');
    assert.equal(token.payload.find(item => item.name === 'aud').value, client);
    assert.equal(deviceTestWire(token).some(action => action.attributeId === 'clientIdApp'), false, 'The response contains aud, not a client_id claim');
    assert.ok(deviceTestStage(steps, 'l25').attributeOperations.some(action => action.attributeId === 'clientIdApp' && action.kind === 'verify'));
  }
});

test('pending/slow_down are errors without tokens; slow_down derives local interval +5 and preserves future delay', () => {
  const steps = getDeviceSteps();
  for (const [id, error] of [['pending-response', 'authorization_pending'], ['slow-response', 'slow_down']]) {
    const stage = deviceTestStage(steps, id);
    assert.deepEqual(stage.payload.map(item => item.name), ['HTTP', 'error']);
    assert.equal(stage.attributeValues.deviceError, error);
    assert.deepEqual(deviceTestWire(stage).map(action => action.attributeId), ['deviceError', 'deviceError']);
    assert.equal(stage.fields.includes('idTokenA'), false);
    assert.equal(stage.fields.includes('accessTokenA'), false);
    assert.equal(stage.fields.includes('deviceInterval'), false, 'slow_down does not send a new interval member');
  }
  const increased = deviceTestStage(steps, 'increase-delay');
  assert.equal(increased.from, 'app'); assert.equal(increased.to, 'app');
  assert.equal(increased.attributeValues.deviceInterval, '10');
  assert.ok(increased.attributeOperations.some(action => action.attributeId === 'deviceInterval' && action.kind === 'derive'));
  assert.equal(deviceTestWire(increased).length, 0);
  assert.equal(deviceTestStage(steps, 'final-poll').attributeValues.deviceInterval, '10');
  assert.equal(deviceTestStage(steps, 'final-poll').payload.some(item => item.name === 'interval'), false, 'Scheduling delay stays local');
  assert.match(DEVICE_ATTRIBUTES.deviceInterval.origin, /default of 5/);
  assert.match(DEVICE_ATTRIBUTES.deviceError.purpose, /access_denied.*expired_token.*ends/);
});

test('verification factors and deliberate transaction approval precede successful token issuance', () => {
  const steps = getDeviceSteps({ mode: 'one-time-code' });
  const otpVerify = steps.findIndex(step => deviceTestCanonical(step) === 'm05');
  const approve = steps.indexOf(deviceTestStage(steps, 'approval-confirm'));
  const token = steps.indexOf(deviceTestStage(steps, 'l24'));
  assert.ok(otpVerify < approve && approve < token);
  assert.ok(deviceTestStage(steps, 'approval-confirm').attributeOperations.some(action => action.attributeId === 'deviceAuthorization' && action.kind === 'store'));
  assert.ok(deviceTestStage(steps, 'redeem').attributeOperations.some(action => action.attributeId === 'deviceAuthorization' && action.kind === 'verify'));
  assert.equal(deviceTestStage(steps, 'approval-confirm').payload.some(item => item.name === 'id_token'), false);
  const browserToken = deviceTestAllWire(steps).filter(action => ['idTokenA', 'accessTokenA', 'refreshToken'].includes(action.attributeId) && action.actorId === 'browser');
  assert.equal(browserToken.length, 0);
  assert.equal(steps.some(step => step.fields.includes('sessionCookieApp')), false);
  assert.match(DEVICE_ATTRIBUTES.deviceApproval.purpose, /not an RFC 8628 wire parameter/);
});

test('every device attribute has a meaningful focused lifecycle with honest local and wire operations', () => {
  const steps = getDeviceSteps({ mode: 'passkey-totp', architecture: 'web', authenticator: 'yubikey' });
  assert.deepEqual(DEVICE_TOPIC_IDS, Object.keys(DEVICE_ATTRIBUTES));
  for (const id of DEVICE_TOPIC_IDS) {
    const usages = getAttributeUsage(steps, id, 'yubikey');
    assert.ok(usages.length > 0, id);
    const definition = DEVICE_ATTRIBUTES[id];
    for (const field of ['name', 'meaning', 'origin', 'purpose', 'example', 'standard', 'source']) assert.ok(definition[field], id + ': ' + field);
  }
  const transaction = getAttributeUsage(steps, 'deviceAuthorization');
  assert.equal(transaction.some(usage => usage.actions.some(action => ['send', 'receive'].includes(action.kind))), false, 'Server transaction record never transmitted');
  const code = getAttributeUsage(steps, 'deviceCode');
  assert.ok(code[0].actions.some(action => action.kind === 'create' && action.actorId === 'realmA'));
  assert.ok(code.some(usage => usage.actions.some(action => action.kind === 'store' && action.actorId === 'app')));
  assert.ok(code.some(usage => usage.actions.some(action => action.kind === 'verify' && action.actorId === 'realmA')));
});

test('actor and glossary overrides distinguish requesting application from independent verification device', () => {
  for (const architecture of ['native', 'web']) {
    const config = { architecture, mode: 'password-totp' }, actors = getDeviceActorOverrides(config);
    const expected = architecture === 'web' ? 'device-confidential' : 'device-client';
    assert.equal(getDeviceActorOverrides(config), actors);
    assert.match(actors.browser.role, /separate device/);
    assert.match(actors.app.role, architecture === 'web' ? /Confidential/ : /Public/);
    assert.equal(actors.browser.attributes.some(entry => entry.id === 'deviceCode'), false);
    assert.equal(actors.app.attributes.some(entry => entry.id === 'codeVerifier'), false);
    assert.equal(actors.user.attributes.some(entry => entry.id === 'password'), true, 'Person retains the factor attribute appropriate to this method');
    const definitions = getDeviceAttributeOverrides(config), examples = getDeviceExampleOverrides(config);
    assert.equal(definitions.clientIdApp.example, expected);
    assert.equal(examples.clientIdApp, expected);
    assert.equal(definitions.audience.example, expected);
    assert.match(definitions.grantType.purpose, /device_code.*instead of.*authorization code/);
    assert.match(definitions.tokenEndpoint.purpose, /polls.*device_code/);
    assert.match(definitions.idTokenA.purpose, /no nonce/);
    assert.ok(DEVICE_SOURCES.every(source => source.url.startsWith('https://')));
  }
});

test('JWE adapter wraps actual device ID token while preserving real device claims and no invented nonce', () => {
  for (const architecture of ['native', 'web']) {
    const original = getDeviceSteps({ architecture }), before = JSON.stringify(original);
    const encrypted = applyJweProtection(original, { protection: 'app-jwe' });
    const wire = encrypted.find(step => step.jweStage === 'wire');
    assert.ok(wire); assert.equal(wire.oidcGrant, 'device_code');
    assert.equal(wire.from, 'realmA'); assert.equal(wire.to, 'app');
    const encryptedWire = deviceTestWire(wire);
    for (const id of ['issuerA', 'audience', 'subjectA', 'exp', 'iat', 'nonceApp']) assert.equal(encryptedWire.some(action => action.attributeId === id), false, id);
    assert.equal(wire.payload.some(item => ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'].includes(item.name)), false);
    const validation = encrypted.find(step => deviceTestCanonical(step) === 'l25');
    assert.ok(validation);
    assert.equal(getStepAttributeOperations(validation).some(action => action.attributeId === 'nonceApp'), false);
    assert.equal(JSON.stringify(original), before);
  }
});
