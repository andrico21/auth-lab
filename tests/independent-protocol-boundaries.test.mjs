import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { VARIANT_ATTRIBUTES, getJourneySteps, getExampleOverrides } from '../src/architecture-variants.js';
import { FIDO_ATTRIBUTES, getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { getFidoSteps, applyFidoTransport } from '../src/fido-direct.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { applyJweProtection } from '../src/jwe-data.js';
import { getCibaSteps, getCibaAttributeOverrides, getCibaExampleOverrides } from '../src/ciba-data.js';
import { getDeviceSteps, getDeviceAttributeOverrides } from '../src/device-flow-data.js';
import { installHarness } from './dom-harness.mjs';

// Expected authorities and CTAP members come from independent OIDC Discovery
// §3 / Core §3.1.3.7 and CTAP 2.2 §§6.1.2, 6.2.2, 6.5.5 fixtures. Do not derive
// these expectations from the model or the overlay implementation.
Object.assign(ATTRIBUTES, VARIANT_ATTRIBUTES, FIDO_ATTRIBUTES);
const jwksA = 'https://idp1.example.test/realms/realm-a/protocol/openid-connect/certs';
const jwksB = 'https://idp2.example.test/realms/realm-b/protocol/openid-connect/certs';
const jwksExternal = 'https://login.partner.example.test/oauth2/jwks';
const canonical = item => String(item.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const operation = (step, id, kind, actor) => getStepAttributeOperations(step, 'yubikey').some(action => action.attributeId === id && action.kind === kind && action.actorId === actor);
const trace = (steps, id) => buildAttributeTrace(getAttributeUsage(steps, id, 'yubikey'));

test('F02: every core factor uses the validated issuer’s trusted JWKS on both token hops', () => {
  for (const architecture of ['native', 'web']) for (const upstream of ['keycloak', 'external', 'single']) {
    for (const mode of ['passkey', 'password', 'one-time-code', 'password-totp', 'passkey-totp']) {
      const base = getJourneySteps(mode, architecture, upstream);
      for (const steps of [base, applyJweProtection(base, { protection: 'both-jwe' })]) {
        const queue = buildAttributeTrace(getAttributeUsage(steps, 'jwksUri'), getExampleOverrides(architecture, upstream));
        const appChecks = queue.filter(item => /(?:^|-)l25$/.test(item.sourceStepId));
        assert.ok(appChecks.length, `${mode}/${architecture}/${upstream}: application checks exist`);
        for (const item of appChecks) {
          assert.equal(item.from, 'app'); assert.equal(item.to, 'app');
          assert.equal(item.payload.find(field => field.attributeId === 'jwksUri').value, jwksA);
        }
        const brokerChecks = queue.filter(item => /(?:^|-)l19$/.test(item.sourceStepId));
        if (upstream === 'single') assert.equal(brokerChecks.length, 0);
        else {
          assert.ok(brokerChecks.length, `${mode}/${architecture}/${upstream}: broker checks exist`);
          for (const item of brokerChecks) {
            assert.equal(item.from, 'realmA'); assert.equal(item.to, 'realmA');
            assert.equal(item.payload.find(field => field.attributeId === 'jwksUri').value, upstream === 'external' ? jwksExternal : jwksB);
          }
        }
      }
    }
  }
});

function assertionModels() {
  return [getFidoSteps('fido-login', 'yubikey'), ...['native', 'web'].flatMap(architecture => ['keycloak', 'external', 'single'].flatMap(upstream => ['passkey', 'passkey-totp'].map(mode => applyFidoTransport(getJourneySteps(mode, architecture, upstream), 'yubikey'))))];
}
function registrationModels() {
  return [getFidoSteps('fido-enrollment', 'yubikey'), ...['native', 'web'].flatMap(architecture => ['keycloak', 'external', 'single'].map(upstream => applyFidoTransport(getJourneySteps('enrollment', architecture, upstream), 'yubikey')))];
}

test('F05: all YubiKey assertions return canonical CTAP members before browser-local WebAuthn construction', () => {
  for (const steps of assertionModels()) {
    const returned = steps.find(item => canonical(item) === 'l12');
    const converted = steps.find(item => item.ctapOperation === 'assertion-api-conversion');
    const submitted = steps.find(item => canonical(item) === 'l13');
    assert.deepEqual(returned.payload.map(field => field.name), ['credential', 'authData', 'signature', 'user']);
    assert.equal(returned.from, 'authenticator'); assert.equal(returned.to, 'browser'); assert.equal(returned.channel, 'ctap2');
    assert.deepEqual(returned.payload.map(field => field.attributeId), ['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser']);
    assert.ok(returned.payload.find(field => field.name === 'credential').value.includes('type: "public-key"'));
    assert.ok(returned.payload.find(field => field.name === 'user').value.includes('id:'));
    assert.equal(converted.from, 'browser'); assert.equal(converted.to, 'browser'); assert.equal(converted.channel, 'internal');
    assert.equal(steps.indexOf(converted), steps.indexOf(returned) + 1);
    assert.ok(steps.indexOf(submitted) > steps.indexOf(converted));
    for (const id of ['credentialId', 'authenticatorData', 'signature', 'userHandle']) {
      assert.ok(operation(converted, id, 'derive', 'browser'), `${converted.id}: constructs ${id}`);
      assert.equal(operation(returned, id, 'send', 'yubikey'), false, `${returned.id}: no API alias on CTAP wire`);
    }
    const signatureTrace = trace(steps, 'ctapSignature');
    const transport = signatureTrace.filter(item => item.traceKind === 'send');
    assert.equal(transport.length, 1); assert.equal(transport[0].sourceStepId, returned.id);
    assert.equal(transport[0].from, 'yubikey'); assert.equal(transport[0].to, 'browser');
    assert.ok(signatureTrace.every(item => item.payload[0].value === 'Assertion signature bytes'), 'the signature bytes survive local construction, CTAP transport and browser mapping');
    for (const id of ['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser']) {
      assert.ok(getAttributeUsage(steps, id, 'yubikey').every(usage => usage.focusActors.every(actor => ['yubikey', 'browser'].includes(actor))), `${id} stays at the CTAP boundary`);
    }
  }
});

test('F05: all YubiKey registrations separate MakeCredential output from privacy-adjusted WebAuthn attestationObject', () => {
  for (const steps of registrationModels()) {
    const returned = steps.find(item => canonical(item) === 'e06');
    const converted = steps.find(item => item.ctapOperation === 'registration-api-conversion');
    const submitted = steps.find(item => canonical(item) === 'e07');
    assert.deepEqual(returned.payload.map(field => field.name), ['fmt', 'authData', 'attStmt']);
    assert.deepEqual(returned.payload.map(field => field.attributeId), ['ctapFmt', 'ctapAuthData', 'ctapAttStmt']);
    assert.equal(returned.channel, 'ctap2');
    assert.equal(returned.payload.find(field => field.name === 'fmt').value, 'packed');
    assert.match(returned.payload.find(field => field.name === 'authData').value, /attestedCredentialData.*credentialId.*credentialPublicKey/);
    assert.equal(steps.indexOf(converted), steps.indexOf(returned) + 1);
    assert.ok(steps.indexOf(submitted) > steps.indexOf(converted));
    assert.equal(converted.from, 'browser'); assert.equal(converted.to, 'browser');
    const attestation = converted.payload.find(field => field.attributeId === 'attestationObject');
    assert.match(attestation.value, /fmt: "none"/); assert.match(attestation.value, /attStmt: \{\}/);
    assert.ok(operation(converted, 'attestationObject', 'create', 'browser'));
    assert.equal(operation(returned, 'attestationObject', 'send', 'yubikey'), false);
    assert.equal(operation(returned, 'clientDataJSON', 'send', 'yubikey'), false);
    assert.equal(operation(returned, 'transports', 'create', 'browser'), false);
    assert.ok(operation(converted, 'transports', 'create', 'browser'));
    const publicKeyWire = getStepAttributeOperations(returned, 'yubikey').find(action => action.attributeId === 'credentialPublicKey' && action.kind === 'send');
    assert.equal(publicKeyWire.carriedAs, 'authData.attestedCredentialData');
    const attestationTrace = trace(steps, 'attestationObject');
    assert.equal(attestationTrace[0].sourceStepId, converted.id); assert.equal(attestationTrace[0].from, 'browser');
    assert.ok(getAttributeUsage(steps, 'privateKey', 'yubikey').every(usage => !usage.wireAttributeIds.length && usage.focusActors.every(actor => actor === 'yubikey')));
  }
});

test('F05: ClientPIN response excludes the already negotiated pinUvAuthProtocol, which is sent only in command requests', () => {
  for (const steps of [...assertionModels(), ...registrationModels()]) {
    const response = steps.find(item => item.ctapOperation === 'pin-uv');
    assert.deepEqual(response.payload.map(field => field.name), ['pinUvAuthToken']);
    const protocol = getAttributeUsage(steps, 'pinUvAuthProtocol', 'yubikey');
    const wires = protocol.filter(usage => usage.wireAttributeIds.length);
    assert.equal(wires.length, 1); assert.ok(['get-assertion', 'make-credential'].includes(wires[0].step.ctapOperation));
    assert.ok(wires[0].actions.some(action => action.kind === 'send' && action.actorId === 'browser'));
    assert.ok(protocol.every(usage => usage.focusActors.every(actor => ['browser', 'yubikey'].includes(actor))));
    assert.ok(getAttributeUsage(steps, 'pinUvAuthToken', 'yubikey').every(usage => usage.focusActors.every(actor => ['browser', 'yubikey'].includes(actor))));
  }
});

test('F05: Windows Hello keeps its existing platform representation and receives no CTAP response objects', () => {
  assert.equal(applyFidoTransport(FLOWS.login, 'hello'), FLOWS.login);
  assert.equal(getFidoSteps('fido-login', 'hello').length, 11);
  assert.equal(getFidoSteps('fido-enrollment', 'hello').length, 8);
  for (const steps of [getFidoSteps('fido-login', 'hello'), getFidoSteps('fido-enrollment', 'hello')]) {
    assert.ok(steps.every(item => item.channel !== 'ctap2' && !item.ctapOperation));
    for (const id of ['ctapCredential', 'ctapCredentialId', 'ctapAuthData', 'ctapSignature', 'ctapUser', 'ctapFmt', 'ctapAttStmt']) assert.deepEqual(getAttributeUsage(steps, id, 'hello'), []);
  }
});

test('F05: CIBA and Device factor adapters preserve CTAP account context through browser conversion and complete hover definitions', () => {
  for (const mode of ['passkey', 'passkey-totp']) {
    const config = { mode, authenticator: 'yubikey' };
    const ciba = getCibaSteps(config);
    const definitions = getCibaAttributeOverrides(config);
    const userTrace = buildAttributeTrace(getAttributeUsage(ciba, 'ctapUser', 'yubikey'), getCibaExampleOverrides(config));
    assert.ok(userTrace.length);
    for (const stage of userTrace) assert.equal(stage.payload[0].value, '{ id: opaque-auth-service-user-bytes }');
    for (const id of ['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser', 'userId']) {
      for (const field of ['name', 'meaning', 'origin', 'generator', 'purpose', 'standard', 'source']) assert.ok(definitions[id][field], `${id}: ${field}`);
      assert.doesNotMatch(JSON.stringify(definitions[id]), /idp2\.example\.test|opaque-user-B-bytes|\bRealm B\b/);
    }
    assert.equal(definitions.ctapUser.example, '{ id: opaque-auth-service-user-bytes }');
    for (const architecture of ['native', 'web']) {
      const deviceConfig = { ...config, architecture };
      const device = getDeviceSteps(deviceConfig);
      const deviceDefinitions = getDeviceAttributeOverrides(deviceConfig);
      const deviceUserTrace = trace(device, 'ctapUser');
      assert.ok(deviceUserTrace.length);
      for (const stage of deviceUserTrace) assert.equal(stage.payload[0].value, '{ id: opaque-user-A-bytes }');
      for (const id of ['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser']) assert.ok(deviceDefinitions[id].source, `${architecture}: ${id} definition remains complete`);
    }
  }
});

const harness = installHarness();
const { AuthFlowStudio } = await import('../src/app.js');
test('F05: active-step overlays and focused CTAP transfers show canonical members, and API construction has its own local overlay', () => {
  const app = new AuthFlowStudio(); harness.document.body.appendChild(app); app.connectedCallback();
  try {
    for (const mode of ['passkey', 'enrollment', 'fido-login', 'fido-enrollment']) {
      app.labScenarioId = 'core'; app.mode = mode; app.architecture = 'web'; app.upstream = 'external'; app.authenticator = 'yubikey'; app.applicationProtocol = 'oidc'; app.brokerProtocol = 'oidc'; app.oidcFlow = 'authorization-code'; app.renderAll();
      const registration = mode.includes('enrollment');
      const response = app.steps.find(item => item.ctapOperation === 'return');
      const names = app.stepAttributeItems(response).map(item => item.name);
      assert.deepEqual(names.sort(), (registration ? ['fmt', 'authData', 'attStmt', 'credentialId', 'credentialPublicKey', 'rpIdHash', 'UP', 'UV', 'signCount'] : ['credential', 'authData', 'signature', 'user', 'rpIdHash', 'UP', 'UV', 'signCount']).sort());
      assert.ok(!names.includes('authenticatorData')); assert.ok(!names.includes('attestationObject')); assert.ok(!names.includes('userHandle')); assert.ok(!names.includes('id / rawId'));
      const conversion = app.steps.find(item => item.ctapOperation === (registration ? 'registration-api-conversion' : 'assertion-api-conversion'));
      const conversionNames = app.stepAttributeItems(conversion).map(item => item.name);
      assert.ok(conversionNames.includes('id / rawId')); assert.ok(conversionNames.includes('clientDataJSON'));
      assert.ok(conversionNames.includes(registration ? 'attestationObject' : 'authenticatorData'));
      app.selectAttribute('ctapAuthData', false);
      const index = app.traceQueue.findIndex(item => item.sourceStepId === response.id && item.traceKind === 'send');
      assert.ok(index >= 0); app.selectStep(index, true);
      assert.equal(app.currentStep.payload[0].name, 'authData');
      assert.deepEqual(app.refs['step-attributes'].querySelectorAll('code').map(node => node.textContent).sort(), names.sort());
      app.player.pause();
    }
  } finally {
    app.disconnectedCallback(); harness.document.body.removeChild(app); harness.clock.frames.clear(); harness.clock.timers.clear();
  }
});
