import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { ATTRIBUTE_TOPICS, FIDO_ATTRIBUTES, getAttributeContext, getAttributeIds, getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { VARIANT_ATTRIBUTES, getJourneySteps } from '../src/architecture-variants.js';
import { applyFidoTransport, getFidoSteps } from '../src/fido-direct.js';

const validKinds = new Set(['create', 'derive', 'send', 'receive', 'verify', 'store', 'use']);
const find = (usages, id) => usages.find(usage => usage.step.id === id);
const hasAction = (usage, id, kind, actor) => usage.actions.some(action => action.attributeId === id && action.kind === kind && action.actorId === actor);
const withFidoRegistry = callback => {
  const extensions = { ...VARIANT_ATTRIBUTES, ...FIDO_ATTRIBUTES };
  const previous = Object.fromEntries(Object.keys(extensions).map(id => [id, ATTRIBUTES[id]]));
  Object.assign(ATTRIBUTES, extensions);
  try { return callback(); }
  finally {
    for (const id of Object.keys(extensions)) {
      if (previous[id]) ATTRIBUTES[id] = previous[id]; else delete ATTRIBUTES[id];
    }
  }
};

test('every indexed attribute has a real operation in at least one journey', () => {
  for (const id of Object.keys(ATTRIBUTES)) {
    assert.ok(Object.values(FLOWS).some(steps => getAttributeUsage(steps, id).length), `${id} should have an explicit lifecycle operation`);
  }
  for (const topic of Object.values(ATTRIBUTE_TOPICS)) {
    assert.deepEqual(getAttributeIds(topic.id), topic.attributeIds);
  }
  assert.deepEqual(getAttributeIds('nonexistent'), []);
  assert.deepEqual(getAttributeUsage(FLOWS.login, 'nonexistent'), []);
});

test('PKCE walks creation, browser commitment, retained code binding and direct proof in order', () => {
  const usages = getAttributeUsage(FLOWS.login, 'pkce');
  assert.deepEqual(usages.map(usage => usage.step.id), ['l02', 'l03', 'l04', 'l20', 'l23']);
  assert.deepEqual(usages.map(usage => usage.index), [1, 2, 3, 19, 22]);
  assert.ok(hasAction(find(usages, 'l02'), 'codeVerifier', 'create', 'app'));
  assert.ok(hasAction(find(usages, 'l02'), 'codeVerifier', 'store', 'app'));
  assert.ok(hasAction(find(usages, 'l02'), 'codeChallenge', 'derive', 'app'));
  assert.deepEqual(find(usages, 'l02').wireAttributeIds, []);
  assert.deepEqual(find(usages, 'l03').wireAttributeIds, ['codeChallenge', 'codeChallengeMethod']);
  assert.ok(hasAction(find(usages, 'l04'), 'codeChallenge', 'receive', 'realmA'));
  assert.ok(hasAction(find(usages, 'l04'), 'codeChallenge', 'store', 'realmA'));
  assert.deepEqual(find(usages, 'l20').wireAttributeIds, []);
  assert.deepEqual(find(usages, 'l20').focusActors, ['realmA']);
  assert.deepEqual(find(usages, 'l23').wireAttributeIds, ['codeVerifier']);
  assert.ok(hasAction(find(usages, 'l23'), 'codeChallenge', 'derive', 'realmA'));
  assert.ok(hasAction(find(usages, 'l23'), 'codeChallenge', 'verify', 'realmA'));
  assert.ok(usages.every(usage => !usage.focusActors.includes('realmB')));
});

test('the verifier is first transmitted at the token request and never visits the browser', () => {
  for (const steps of [FLOWS.login, FLOWS.totpLogin, FLOWS.passkeyTotpLogin]) {
    const usages = getAttributeUsage(steps, 'codeVerifier');
    assert.equal(usages.filter(usage => usage.wireAttributeIds.includes('codeVerifier')).length, 1);
    assert.match(usages.find(usage => usage.wireAttributeIds.length).step.id, /l23$/);
    assert.ok(usages.every(usage => usage.actions.every(action => ['app', 'realmA'].includes(action.actorId))));
  }
});

test('a mere context declaration or text mention cannot create an inferred transmission', () => {
  const future = [{
    id: 'future-operation', from: 'app', to: 'browser', fields: ['codeVerifier'],
    detail: 'Text mentioning code_verifier does not specify a wire operation.',
    payload: [{ name: 'code_verifier', value: 'example' }],
  }];
  assert.deepEqual(getAttributeUsage(future, 'codeVerifier'), []);
  const context = getAttributeContext(future, 'codeVerifier');
  assert.equal(context.length, 1);
  assert.equal(context[0].actions[0].kind, 'inspect');
});

test('WebAuthn private credential keys and realm signing keys are never transport fields', () => {
  for (const steps of Object.values(FLOWS)) {
    for (const id of ['privateKey', 'realmSigningKey']) {
      const usages = getAttributeUsage(steps, id, 'yubikey');
      assert.ok(usages.every(usage => usage.wireAttributeIds.length === 0), id);
      assert.ok(usages.every(usage => usage.actions.every(action => action.kind !== 'send' && action.kind !== 'receive')), id);
    }
  }
  const enrollment = getAttributeUsage(FLOWS.enrollment, 'privateKey', 'yubikey');
  assert.equal(enrollment.length, 1);
  assert.equal(enrollment[0].step.id, 'e06');
  assert.ok(hasAction(enrollment[0], 'privateKey', 'create', 'yubikey'));
  assert.ok(hasAction(enrollment[0], 'privateKey', 'store', 'yubikey'));
});

test('browser produces client data locally and passes only its hash to the authenticator', () => {
  const json = getAttributeUsage(FLOWS.login, 'clientDataJSON');
  assert.ok(hasAction(find(json, 'l09'), 'clientDataJSON', 'create', 'browser'));
  assert.deepEqual(find(json, 'l09').wireAttributeIds, []);
  assert.deepEqual(find(json, 'l09').focusActors, ['browser']);
  const hash = getAttributeUsage(FLOWS.login, 'clientDataHash', 'yubikey');
  assert.ok(hasAction(find(hash, 'l09'), 'clientDataHash', 'derive', 'browser'));
  assert.ok(hasAction(find(hash, 'l09'), 'clientDataHash', 'receive', 'yubikey'));
  const registration = getAttributeUsage(FLOWS.enrollment, 'clientDataJSON');
  assert.deepEqual(find(registration, 'e06').wireAttributeIds, []);
  assert.deepEqual(find(registration, 'e06').focusActors, ['browser']);
  const origin = getAttributeUsage(FLOWS.login, 'origin');
  assert.ok(find(origin, 'l13').actions.some(action => action.carriedAs === 'response.clientDataJSON'));
});

test('TOTP secret intentionally travels during provisioning, then stays in prover and verifier', () => {
  const setup = getAttributeUsage(FLOWS.totpEnrollment, 'otpSecret');
  assert.deepEqual(setup.filter(usage => usage.wireAttributeIds.length).map(usage => usage.step.id), ['t03', 't04']);
  assert.ok(hasAction(find(setup, 't03'), 'otpSecret', 'create', 'realmB'));
  assert.ok(hasAction(find(setup, 't04'), 'otpSecret', 'store', 'totp'));
  assert.ok(hasAction(find(setup, 't07'), 'otpSecret', 'store', 'realmB'));
  assert.deepEqual(find(setup, 't07').wireAttributeIds, []);
  assert.equal(setup.some(usage => usage.step.id === 't08'), false);
  for (const steps of [FLOWS.totpLogin, FLOWS.passkeyTotpLogin]) {
    const login = getAttributeUsage(steps, 'otpSecret');
    assert.ok(login.every(usage => usage.wireAttributeIds.length === 0));
    assert.ok(login.every(usage => usage.focusActors.every(actor => ['totp', 'realmB'].includes(actor))));
  }
});

test('the short OTP takes the human/browser path to B without entering A or the local app', () => {
  const code = getAttributeUsage(FLOWS.totpLogin, 'otpCode');
  assert.deepEqual(code.map(usage => usage.step.id), ['m02', 'm03', 'm04', 'm05']);
  assert.deepEqual(code.filter(usage => usage.wireAttributeIds.length).map(usage => [usage.step.from, usage.step.to]), [
    ['totp', 'user'], ['user', 'browser'], ['browser', 'realmB'],
  ]);
  assert.ok(code.every(usage => !usage.focusActors.includes('realmA') && !usage.focusActors.includes('app')));
  assert.equal(getAttributeContext(FLOWS.totpLogin, 'otpCode')[0].step.id, 'm01');
  const clock = getAttributeUsage(FLOWS.totpLogin, 'otpTime');
  assert.deepEqual(clock.map(usage => usage.focusActors), [['totp'], ['realmB']]);
});

test('records preserve source steps, valid actors and canonical attributes without modifying data', () => {
  const before = JSON.stringify(FLOWS);
  for (const steps of Object.values(FLOWS)) {
    const usages = getAttributeUsage(steps, Object.keys(ATTRIBUTES), 'yubikey');
    for (const usage of usages) {
      assert.equal(usage.step, steps[usage.index]);
      for (const action of usage.actions) {
        assert.ok(ATTRIBUTES[action.attributeId], action.attributeId);
        assert.ok(ACTORS[action.actorId], action.actorId);
        assert.ok(validKinds.has(action.kind), action.kind);
        assert.ok(action.detail.length > 20);
      }
      for (const id of usage.wireAttributeIds) {
        assert.ok(hasAction(usage, id, 'send', usage.step.from === 'authenticator' ? 'yubikey' : usage.step.from));
        assert.ok(hasAction(usage, id, 'receive', usage.step.to === 'authenticator' ? 'yubikey' : usage.step.to));
      }
    }
  }
  assert.equal(JSON.stringify(FLOWS), before);
});

test('explicit web-client metadata adds backend authentication and cookie handling without changing PKCE wire fields', () => {
  const extensions = {
    clientSecretApp: { name: 'client_secret' }, authorizationHeaderApp: { name: 'Authorization' },
    sessionCookieApp: { name: 'Set-Cookie / Cookie' }, loginUsername: { name: 'username' },
  };
  const previous = Object.fromEntries(Object.keys(extensions).map(id => [id, ATTRIBUTES[id]]));
  Object.assign(ATTRIBUTES, extensions);
  try {
    const web = FLOWS.login.map(step => ({ ...step, id: 'web-' + step.id, architecture: 'web', clientKind: 'confidential-web' }));
    const pkce = getAttributeUsage(web, 'pkce');
    assert.deepEqual(pkce.at(-1).wireAttributeIds, ['codeVerifier']);
    assert.ok(getAttributeUsage(web, 'clientSecretApp').at(-1).wireAttributeIds.includes('clientSecretApp'));
    const secret = getAttributeUsage(web, 'clientSecretApp').at(-1);
    assert.deepEqual(secret.focusActors, ['app', 'realmA']);
    const cookie = getAttributeUsage(web, 'sessionCookieApp')[0];
    assert.equal(cookie.step.id, 'web-l25');
    assert.ok(hasAction(cookie, 'sessionCookieApp', 'create', 'app'));
    assert.ok(hasAction(cookie, 'sessionCookieApp', 'receive', 'browser'));
    assert.ok(hasAction(cookie, 'sessionCookieApp', 'store', 'browser'));
    assert.ok(cookie.actions.every(action => action.actorId !== 'user'));
    const usernameOnly = [
      { id: 'otp-u01', from: 'realmB', to: 'browser', fields: ['loginUsername', 'session'] },
      { id: 'otp-u02', from: 'user', to: 'browser', fields: ['loginUsername'] },
      { id: 'otp-u03', from: 'browser', to: 'realmB', fields: ['loginUsername', 'session'] },
    ];
    assert.deepEqual(getAttributeUsage(usernameOnly, 'loginUsername').map(usage => usage.step.id), ['otp-u02', 'otp-u03']);
  } finally {
    for (const id of Object.keys(extensions)) {
      if (previous[id]) ATTRIBUTES[id] = previous[id]; else delete ATTRIBUTES[id];
    }
  }
});

test('direct FIDO2 moves generation and assertion verification into the application with no OAuth proof', () => withFidoRegistry(() => {
  const direct = getFidoSteps('fido-login', 'yubikey');
  const fido = getAttributeUsage(direct, 'fido2', 'yubikey');
  assert.ok(fido.every(usage => usage.focusActors.every(actor => ['app', 'browser', 'user', 'yubikey'].includes(actor))));
  const challenge = getAttributeUsage(direct, 'challengeLogin', 'yubikey');
  assert.ok(hasAction(find(challenge, 'fido-l08'), 'challengeLogin', 'create', 'app'));
  assert.ok(hasAction(find(challenge, 'fido-l14'), 'challengeLogin', 'verify', 'app'));
  assert.ok(find(challenge, 'fido-l08').actions.every(action => !/\bB\b|Keycloak/.test(action.detail)));
  const key = getAttributeUsage(direct, 'credentialPublicKey', 'yubikey');
  assert.ok(hasAction(find(key, 'fido-l14'), 'credentialPublicKey', 'use', 'app'));
  assert.deepEqual(getAttributeUsage(direct, 'pkce', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(direct, 'state', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(direct, 'nonce', 'yubikey'), []);
  const cookie = getAttributeUsage(direct, 'sessionCookieApp', 'yubikey')[0];
  assert.equal(cookie.step.id, 'fido-d03');
  assert.ok(hasAction(cookie, 'sessionCookieApp', 'create', 'app'));
  assert.ok(hasAction(cookie, 'sessionCookieApp', 'receive', 'browser'));
}));

test('direct registration keeps the private key in the device and stores the public key and hint in the app', () => withFidoRegistry(() => {
  const direct = getFidoSteps('fido-enrollment', 'yubikey');
  const privateKey = getAttributeUsage(direct, 'privateKey', 'yubikey');
  assert.equal(privateKey.length, 1);
  assert.ok(hasAction(privateKey[0], 'privateKey', 'create', 'yubikey'));
  assert.deepEqual(privateKey[0].wireAttributeIds, []);
  const publicKey = getAttributeUsage(direct, 'credentialPublicKey', 'yubikey');
  assert.ok(hasAction(find(publicKey, 'fido-e07'), 'credentialPublicKey', 'receive', 'app'));
  assert.ok(hasAction(find(publicKey, 'fido-e08'), 'credentialPublicKey', 'store', 'app'));
  const transports = getAttributeUsage(direct, 'transports', 'yubikey');
  assert.ok(hasAction(find(transports, 'fido-e06-api'), 'transports', 'create', 'browser'));
  assert.ok(hasAction(find(transports, 'fido-e07'), 'transports', 'receive', 'app'));
  assert.ok(hasAction(find(transports, 'fido-e08'), 'transports', 'store', 'app'));
}));

test('protected PIN token and command authentication tag remain on the local client/key side', () => withFidoRegistry(() => {
  const direct = getFidoSteps('fido-login', 'yubikey');
  const token = getAttributeUsage(direct, 'pinUvAuthToken', 'yubikey');
  assert.ok(token.length > 0);
  assert.ok(token.every(usage => usage.focusActors.every(actor => ['browser', 'yubikey'].includes(actor))));
  assert.equal(token.filter(usage => usage.wireAttributeIds.includes('pinUvAuthToken')).length, 1);
  assert.equal(token.find(usage => usage.wireAttributeIds.length).step.ctapOperation, 'pin-uv');
  assert.ok(token.find(usage => usage.wireAttributeIds.length).actions.some(action => action.carriedAs === 'encrypted authenticatorClientPIN response'));
  const tag = getAttributeUsage(direct, 'pinUvAuthParam', 'yubikey');
  assert.equal(tag.length, 1);
  assert.equal(tag[0].step.ctapOperation, 'get-assertion');
  assert.ok(hasAction(tag[0], 'pinUvAuthParam', 'derive', 'browser'));
  assert.ok(hasAction(tag[0], 'pinUvAuthParam', 'receive', 'yubikey'));
  assert.ok(hasAction(tag[0], 'pinUvAuthParam', 'verify', 'yubikey'));
  assert.ok(tag.every(usage => !usage.focusActors.includes('app')));
  assert.ok(token[0].index < tag[0].index);
  assert.ok(getAttributeUsage(direct, 'localVerification', 'yubikey').every(usage => !usage.focusActors.includes('app')));
}));

test('CTAP commands require an explicit roaming-key stage while Windows Hello retains its platform path', () => withFidoRegistry(() => {
  const direct = getFidoSteps('fido-login', 'yubikey');
  const command = getAttributeUsage(direct, 'ctapGetAssertion', 'yubikey')[0];
  assert.equal(command.step.ctapOperation, 'get-assertion');
  assert.ok(hasAction(command, 'ctapGetAssertion', 'send', 'browser'));
  assert.ok(hasAction(command, 'ctapGetAssertion', 'receive', 'yubikey'));
  const hash = getAttributeUsage(direct, 'clientDataHash', 'yubikey');
  assert.deepEqual(find(hash, 'fido-l09').wireAttributeIds, []);
  assert.ok(hash.some(usage => usage.step.ctapOperation === 'get-assertion' && usage.wireAttributeIds.includes('clientDataHash')));
  const hello = getFidoSteps('fido-login', 'hello');
  for (const id of ['ctapGetAssertion', 'ctapMakeCredential', 'ctapResidentKey', 'pinUvAuthParam', 'pinUvAuthProtocol', 'pinUvAuthToken']) {
    assert.deepEqual(getAttributeUsage(hello, id, 'hello'), []);
  }
  const brokered = applyFidoTransport(getJourneySteps('passkey', 'web', 'external'), 'yubikey');
  assert.equal(getAttributeUsage(brokered, 'ctapGetAssertion', 'yubikey')[0].step.ctapOperation, 'get-assertion');
  assert.ok(getAttributeUsage(brokered, 'pinUvAuthToken', 'yubikey').every(usage => !usage.focusActors.includes('realmA') && !usage.focusActors.includes('realmB')));
}));

test('required WebAuthn resident-key policy becomes Boolean CTAP MakeCredential rk and stays absent from assertion/platform paths', () => withFidoRegistry(() => {
  assert.equal(FIDO_ATTRIBUTES.ctapResidentKey.name, 'options.rk');
  assert.equal(FIDO_ATTRIBUTES.ctapResidentKey.example, true);
  assert.ok(ATTRIBUTE_TOPICS.fido2.attributeIds.includes('ctapResidentKey'));
  const direct = getFidoSteps('fido-enrollment', 'yubikey');
  const commandStep = direct.find(step => step.ctapOperation === 'make-credential');
  assert.equal(commandStep.payload.find(field => field.name === 'options.rk').value, true);
  const setting = getAttributeUsage(direct, 'ctapResidentKey', 'yubikey');
  const command = setting.find(usage => usage.step === commandStep);
  assert.ok(hasAction(command, 'ctapResidentKey', 'derive', 'browser'));
  assert.ok(hasAction(command, 'ctapResidentKey', 'send', 'browser'));
  assert.ok(hasAction(command, 'ctapResidentKey', 'receive', 'yubikey'));
  assert.ok(hasAction(command, 'ctapResidentKey', 'use', 'yubikey'));
  assert.ok(command.actions.some(action => action.carriedAs === 'options.rk'));
  assert.ok(getAttributeUsage(direct, 'residentKey', 'yubikey').some(usage => usage.step === commandStep && hasAction(usage, 'residentKey', 'use', 'browser')));
  assert.ok(hasAction(find(setting, 'fido-e06'), 'ctapResidentKey', 'use', 'yubikey'));
  assert.deepEqual(getAttributeUsage(getFidoSteps('fido-login', 'yubikey'), 'ctapResidentKey', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(getFidoSteps('fido-enrollment', 'hello'), 'ctapResidentKey', 'hello'), []);
  const brokered = applyFidoTransport(getJourneySteps('enrollment', 'web', 'external'), 'yubikey');
  assert.ok(getAttributeUsage(brokered, 'ctapResidentKey', 'yubikey').some(usage => usage.step.ctapOperation === 'make-credential'));
}));

test('direct flags cannot turn reused OAuth preparation steps into a PKCE or nonce operation', () => withFidoRegistry(() => {
  const wronglyReused = FLOWS.login.map(step => ({ ...step, directFido: true, relyingPartyActor: 'app' }));
  assert.deepEqual(getAttributeUsage(wronglyReused, 'pkce', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(wronglyReused, 'nonce', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(wronglyReused, 'state', 'yubikey'), []);
}));

test('the application client_id stays configured and binds authorization, the code and the expected token audience', () => {
  assert.deepEqual(ATTRIBUTE_TOPICS.clientIdentity.attributeIds, ['clientIdApp']);
  const identity = getAttributeUsage(FLOWS.login, 'clientIdentity');
  assert.deepEqual(identity.map(usage => usage.step.id), ['l02', 'l03', 'l04', 'l20', 'l23', 'l24', 'l25']);
  assert.ok(identity.every(usage => usage.fieldIds.every(id => id === 'clientIdApp')));
  assert.ok(identity.every(usage => usage.actions.every(action => action.kind !== 'create')));
  assert.ok(hasAction(find(identity, 'l02'), 'clientIdApp', 'use', 'app'));
  assert.ok(hasAction(find(identity, 'l04'), 'clientIdApp', 'receive', 'realmA'));
  assert.ok(hasAction(find(identity, 'l04'), 'clientIdApp', 'verify', 'realmA'));
  assert.ok(hasAction(find(identity, 'l04'), 'clientIdApp', 'store', 'realmA'));
  assert.deepEqual(find(identity, 'l20').wireAttributeIds, []);
  assert.ok(hasAction(find(identity, 'l24'), 'clientIdApp', 'use', 'realmA'));
  assert.deepEqual(find(identity, 'l24').wireAttributeIds, []);
  assert.match(find(identity, 'l24').actions[0].detail, /aud/);
  assert.ok(hasAction(find(identity, 'l25'), 'clientIdApp', 'verify', 'app'));
  assert.deepEqual(find(identity, 'l25').wireAttributeIds, []);
});

test('the native token request carries client_id in its body while a web backend carries the identifier only as Basic username', () => withFidoRegistry(() => {
  const native = find(getAttributeUsage(getJourneySteps('passkey', 'native', 'keycloak'), 'clientIdentity'), 'l23');
  const nativeTransport = native.actions.filter(action => ['send', 'receive'].includes(action.kind));
  assert.equal(nativeTransport.length, 2);
  assert.ok(nativeTransport.every(action => action.carriedAs === 'application/x-www-form-urlencoded body'));
  const web = getAttributeUsage(getJourneySteps('passkey', 'web', 'keycloak'), 'clientIdentity').find(usage => /l23$/.test(usage.step.id));
  const webTransport = web.actions.filter(action => ['send', 'receive'].includes(action.kind));
  assert.equal(webTransport.length, 2);
  assert.ok(webTransport.every(action => action.carriedAs === 'Authorization: Basic'));
  assert.ok(webTransport.every(action => /username/.test(action.detail)));
  assert.ok(web.step.payload.some(field => field.name === 'Authorization'));
  assert.ok(web.step.payload.every(field => field.name !== 'client_id'));
  assert.deepEqual(getAttributeUsage(getFidoSteps('fido-login', 'yubikey'), 'clientIdentity', 'yubikey'), []);
  assert.deepEqual(getAttributeUsage(getFidoSteps('fido-enrollment', 'hello'), 'clientIdentity', 'hello'), []);
}));

test('explicit single-realm metadata remaps all factor types and enrollment operations to A and suppresses every broker operation', () => withFidoRegistry(() => {
  // Exercise the metadata contract independently from the UI deployment adapter.
  for (const steps of [...Object.values(FLOWS), getJourneySteps('password'), getJourneySteps('one-time-code')]) {
    const single = applyFidoTransport(steps, 'yubikey').map(step => ({ ...step, topology: 'single', upstreamKind: 'single-realm' }));
    const all = getAttributeUsage(single, Object.keys(ATTRIBUTES), 'yubikey');
    assert.ok(all.every(usage => !usage.focusActors.includes('realmB')));
    assert.ok(all.every(usage => !/(?:^|-)l(?:05|06|07|15|16|17|18|19)$/.test(usage.step.id)));
    const forbidden = ['clientIdBroker', 'clientSecret', 'redirectBroker', 'stateBroker', 'nonceBroker', 'codeB', 'idTokenB', 'accessTokenB', 'issuerB', 'subjectB', 'authorizationHeader'];
    assert.ok(all.every(usage => usage.fieldIds.every(id => !forbidden.includes(id))));
    for (const id of ['signature', 'credentialPublicKey', 'password', 'otpSecret', 'otpCode']) {
      const factor = getAttributeUsage(single, id, 'yubikey');
      assert.ok(factor.every(usage => usage.actions.every(action => action.actorId !== 'realmB')));
    }
    const complete = all.find(usage => /l20$/.test(usage.step.id));
    if (complete) {
      assert.ok(hasAction(complete, 'session', 'create', 'realmA'));
      assert.ok(hasAction(complete, 'subjectA', 'use', 'realmA'));
    }
  }
}));

test('an authoritative crypto ledger preserves its envelope while private keys and decrypted claims stay local', () => {
  const extensions = {
    fixtureJwe: { name: 'JWE Compact Serialization' },
    fixtureCek: { name: 'Content Encryption Key' },
    fixtureRecipientKey: { name: 'Recipient private decryption key' },
  };
  const previous = Object.fromEntries(Object.keys(extensions).map(id => [id, ATTRIBUTES[id]]));
  Object.assign(ATTRIBUTES, extensions);
  try {
    const step = {
      id: 'web-l23', from: 'realmA', to: 'app',
      architecture: 'web', topology: 'single', directFido: true,
      ctapOperation: 'get-assertion', authenticatorKind: 'yubikey',
      fields: ['fixtureJwe', 'fixtureCek', 'fixtureRecipientKey', 'issuerA', 'clientIdApp', 'codeVerifier'],
      payload: [{ name: 'id_token', value: 'protected.encryptedKey.iv.ciphertext.tag' }],
      attributeOperations: [
        { attributeId: 'fixtureJwe', kind: 'send', actorId: 'realmA', detail: 'Sends only the encrypted envelope.', carriedAs: 'id_token: JWE Compact Serialization' },
        { attributeId: 'fixtureJwe', kind: 'receive', actorId: 'app', detail: 'Receives the encrypted envelope.', carriedAs: 'id_token: JWE Compact Serialization' },
        { attributeId: 'fixtureRecipientKey', kind: 'use', actorId: 'app', detail: 'Uses the recipient private key locally to unwrap the CEK.' },
        { attributeId: 'fixtureCek', kind: 'use', actorId: 'app', detail: 'Uses the recovered CEK locally to decrypt and verify the tag.' },
        { attributeId: 'issuerA', kind: 'verify', actorId: 'app', detail: 'Verifies the inner signed token issuer after decryption.' },
      ],
    };
    const snapshot = JSON.stringify(step);
    const usages = getAttributeUsage([step], [...Object.keys(extensions), 'issuerA', 'clientIdApp', 'codeVerifier']);
    assert.equal(usages.length, 1);
    assert.deepEqual(usages[0].wireAttributeIds, ['fixtureJwe']);
    assert.deepEqual(usages[0].fieldIds, ['fixtureJwe', 'fixtureRecipientKey', 'fixtureCek', 'issuerA']);
    assert.ok(usages[0].actions.filter(action => action.kind === 'send' || action.kind === 'receive').every(action => action.carriedAs === 'id_token: JWE Compact Serialization'));
    assert.ok(hasAction(usages[0], 'issuerA', 'verify', 'app'));
    assert.deepEqual(getAttributeUsage([step], 'clientIdentity'), []);
    assert.deepEqual(getAttributeUsage([step], 'pkce'), []);
    const captured = getStepAttributeOperations(step);
    assert.notEqual(captured, step.attributeOperations);
    assert.ok(captured.every((action, index) => action !== step.attributeOperations[index]));
    captured[0].detail = 'Changed in an adapter copy.';
    usages[0].actions[0].carriedAs = 'Changed in a trace copy.';
    assert.equal(JSON.stringify(step), snapshot);
  } finally {
    for (const id of Object.keys(extensions)) {
      if (previous[id]) ATTRIBUTES[id] = previous[id]; else delete ATTRIBUTES[id];
    }
  }
});

test('an empty authoritative ledger suppresses canonical OAuth operations and leaves declared fields as context', () => {
  const step = { ...FLOWS.login.find(item => item.id === 'l23'), architecture: 'web', attributeOperations: [] };
  assert.deepEqual(getStepAttributeOperations(step), []);
  assert.deepEqual(getAttributeUsage([step], ['clientIdApp', 'codeVerifier', 'codeA']), []);
  const context = getAttributeContext([step], ['clientIdApp', 'codeVerifier', 'codeA']);
  assert.equal(context.length, 1);
  assert.deepEqual(new Set(context[0].actions.map(action => action.attributeId)), new Set(['clientIdApp', 'codeVerifier', 'codeA']));
  assert.ok(context[0].actions.every(action => action.kind === 'inspect'));
});

test('custom stages normalize the authenticator placeholder and keep omitted fields inspect-only', () => {
  const step = {
    id: 'saml-custom-stage', from: 'browser', to: 'authenticator',
    authenticatorKind: 'yubikey', fields: ['signature', 'privateKey', 'codeVerifier'],
    attributeOperations: [
      { attributeId: 'signature', kind: 'create', actorId: 'authenticator', detail: 'Creates a local proof.' },
      { attributeId: 'privateKey', kind: 'inspect', actorId: 'authenticator', detail: 'Private key remains local.' },
    ],
  };
  const operations = getStepAttributeOperations(step, 'hello');
  assert.ok(operations.every(action => action.actorId === 'yubikey'));
  assert.deepEqual(getAttributeIds(['signature', 'signature', 'unknown-extension']), ['signature']);
  const usage = getAttributeUsage([step], ['signature', 'privateKey', 'codeVerifier']);
  assert.deepEqual(usage[0].fieldIds, ['signature']);
  assert.deepEqual(usage[0].wireAttributeIds, []);
  const context = getAttributeContext([step], ['signature', 'privateKey', 'codeVerifier']);
  assert.deepEqual(context[0].actions.map(action => action.attributeId), ['privateKey', 'codeVerifier']);
  assert.ok(context[0].actions.every(action => action.kind === 'inspect' && action.actorId === 'yubikey'));
  assert.equal(context[0].actions[0].detail, 'Private key remains local.');
  const argumentSelected = { ...step, authenticatorKind: undefined };
  assert.ok(getStepAttributeOperations(argumentSelected, 'hello').every(action => action.actorId === 'hello'));
});

test('the complete ledger export captures reference operations and context without modifying the protocol data', () => {
  const brokerStep = FLOWS.login.find(step => step.id === 'l05');
  const snapshot = JSON.stringify(brokerStep);
  const operations = getStepAttributeOperations(brokerStep);
  assert.ok(operations.some(action => action.kind === 'inspect' && action.attributeId === 'clientSecret'));
  assert.ok(operations.some(action => action.kind === 'create' && action.attributeId === 'stateBroker'));
  operations[0].detail = 'Adapter-specific copied detail.';
  assert.equal(JSON.stringify(brokerStep), snapshot);
  const originalProof = FLOWS.login.find(step => step.id === 'l11');
  assert.ok(getStepAttributeOperations(originalProof, 'yubikey').every(action => action.actorId === 'yubikey'));
});
