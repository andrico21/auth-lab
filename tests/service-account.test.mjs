import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { SERVICE_ATTRIBUTES, SERVICE_TOPIC_IDS, SERVICE_SOURCES, getServiceAccountSteps, getServiceAccountActorOverrides, getServiceAccountAttributeOverrides, getServiceAccountExampleOverrides } from '../src/service-account-data.js';

Object.assign(ATTRIBUTES, SERVICE_ATTRIBUTES);
const serviceTestSteps = getServiceAccountSteps();
const serviceTestAllOperations = serviceTestSteps.flatMap(step => getStepAttributeOperations(step));
const serviceTestStage = stage => serviceTestSteps.find(step => step.id === 'service-' + stage);
const serviceTestUnusedHumanFields = ['idTokenA', 'idTokenB', 'codeA', 'codeB', 'redirectApp', 'redirectBroker', 'stateApp', 'stateBroker', 'nonceApp', 'nonceBroker', 'codeVerifier', 'codeChallenge', 'codeChallengeMethod', 'challengeLogin', 'challengeRegistration', 'privateKey', 'credentialPublicKey', 'otpCode', 'otpSecret', 'session', 'refreshToken'];

test('service-account definitions and topic retain canonical names and primary provenance', () => {
  assert.ok(SERVICE_SOURCES.some(source => source.url.includes('keycloak.org')));
  assert.ok(SERVICE_SOURCES.some(source => source.url.includes('rfc6749')));
  assert.equal(new Set(SERVICE_TOPIC_IDS).size, SERVICE_TOPIC_IDS.length);
  for (const id of SERVICE_TOPIC_IDS) {
    assert.ok(ATTRIBUTES[id], 'Registered attribute: ' + id);
    if (SERVICE_ATTRIBUTES[id]) {
      for (const field of ['name', 'meaning', 'origin', 'purpose', 'example', 'standard', 'source']) assert.ok(SERVICE_ATTRIBUTES[id][field], id + ': ' + field);
      assert.match(SERVICE_ATTRIBUTES[id].source, /^https:\/\/(www\.)?(rfc-editor\.org|keycloak\.org)\//);
    }
    assert.ok(getAttributeUsage(serviceTestSteps, id).length > 0, 'Explicitly animated lifecycle: ' + id);
  }
  assert.equal(SERVICE_ATTRIBUTES.serviceAccessSubject.name, 'sub');
  assert.equal(SERVICE_ATTRIBUTES.serviceAccessAudience.name, 'aud');
  assert.equal(SERVICE_ATTRIBUTES.serviceAccessRoles.name, 'resource_access.orders-api.roles');
});

test('client_credentials is a direct confidential-client flow independent of human login selections', () => {
  assert.equal(serviceTestSteps.length, 7);
  for (const config of [{}, { architecture: 'native', upstream: 'external', mode: 'totp', authenticator: 'yubikey' }, { architecture: 'web', upstream: 'keycloak', mode: 'passkey-register', authenticator: 'hello' }]) {
    assert.equal(getServiceAccountSteps(config), serviceTestSteps, 'Stable immutable model identity');
    assert.deepEqual([...new Set(getServiceAccountSteps(config).flatMap(step => [step.from, step.to]))].sort(), ['app', 'realmA']);
  }
  assert.equal(new Set(serviceTestSteps.map(step => step.id)).size, serviceTestSteps.length);
  for (const step of serviceTestSteps) {
    assert.equal(step.oidcGrant, 'client_credentials');
    assert.equal(step.architecture, 'web');
    assert.equal(step.upstream, 'single');
    assert.ok(Array.isArray(step.attributeOperations), 'Authoritative operation ledger');
    assert.ok(step.title && step.summary && step.detail);
    assert.ok(Array.isArray(step.payload) && Array.isArray(step.checks));
  }
  for (const id of serviceTestUnusedHumanFields) assert.equal(getAttributeUsage(serviceTestSteps, id).length, 0, id + ' must not imply an end-user or authorization-code flow');
});

test('token request has only OAuth grant/scope body fields and a single Basic authentication method', () => {
  const step = serviceTestStage('request');
  assert.equal(step.from, 'app');
  assert.equal(step.to, 'realmA');
  assert.equal(step.channel, 'backchannel');
  assert.ok(step.payload.find(item => item.name === 'HTTP').value.startsWith('POST https://'));
  assert.equal(step.payload.find(item => item.name === 'grant_type').value, 'client_credentials');
  assert.equal(step.payload.find(item => item.name === 'Content-Type').value, 'application/x-www-form-urlencoded');
  assert.match(step.payload.find(item => item.name === 'Authorization').value, /^Basic /);
  assert.equal(step.payload.some(item => ['client_id', 'client_secret', 'code', 'redirect_uri', 'code_verifier', 'username', 'password'].includes(item.name)), false);
  const sends = step.attributeOperations.filter(item => item.kind === 'send');
  assert.deepEqual(sends.map(item => item.attributeId).sort(), ['authorizationHeader', 'clientIdApp', 'clientSecret', 'grantType', 'scope'].sort());
  for (const id of ['clientIdApp', 'clientSecret']) assert.equal(sends.find(item => item.attributeId === id).carriedAs, 'Authorization: Basic');
  for (const action of sends) assert.equal(action.actorId, 'app');
});

test('Basic credentials are prepared locally, intentionally sent under TLS and verified by the issuer', () => {
  const prep = serviceTestStage('prepare'), request = serviceTestStage('request'), auth = serviceTestStage('authenticate');
  assert.match(prep.detail, /application\/x-www-form-urlencoded/);
  assert.match(prep.detail, /Base64 does not encrypt/);
  const secretUsage = getAttributeUsage(serviceTestSteps, 'clientSecret');
  assert.deepEqual(secretUsage.map(item => item.step.id), ['service-prepare', 'service-request', 'service-authenticate']);
  assert.equal(secretUsage.filter(item => item.wireAttributeIds.includes('clientSecret')).length, 1);
  assert.ok(request.attributeOperations.some(action => action.attributeId === 'clientSecret' && action.kind === 'receive' && action.actorId === 'realmA'));
  assert.ok(auth.attributeOperations.some(action => action.attributeId === 'clientSecret' && action.kind === 'verify' && action.actorId === 'realmA'));
  const tokenEndpointUsage = getAttributeUsage(serviceTestSteps, 'tokenEndpoint');
  assert.equal(tokenEndpointUsage.some(item => item.wireAttributeIds.includes('tokenEndpoint')), false, 'The endpoint is a configured destination, not a response/request member');
});

test('Keycloak capability and role intersection checks happen before access-token issuance', () => {
  const auth = serviceTestStage('authenticate'), roles = serviceTestStage('permissions'), issue = serviceTestStage('issue');
  for (const id of ['serviceClientAuthentication', 'serviceAccountEnabled']) assert.ok(auth.attributeOperations.some(action => action.attributeId === id && action.kind === 'verify' && action.actorId === 'realmA'));
  assert.ok(roles.attributeOperations.some(action => action.attributeId === 'serviceEffectiveRoles' && action.kind === 'derive'));
  assert.match(roles.detail, /intersects/);
  assert.match(roles.payload.find(item => item.name === 'Effective roles (local result)').value, /orders-api: read/);
  assert.ok(roles.checks.some(check => check.includes('Full Scope Allowed is not enabled')));
  assert.ok(issue.attributeOperations.some(action => action.attributeId === 'serviceEffectiveRoles' && action.kind === 'use'));
  for (const id of ['serviceAssignedRoles', 'serviceRoleScopeMappings', 'serviceEffectiveRoles']) {
    const usage = getAttributeUsage(serviceTestSteps, id);
    assert.equal(usage.some(item => item.wireAttributeIds.includes(id)), false, 'Local role configuration/result: ' + id);
    for (const step of buildAttributeTrace(usage)) assert.equal(step.from, step.to);
  }
  assert.ok(serviceTestSteps.indexOf(auth) < serviceTestSteps.indexOf(roles));
  assert.ok(serviceTestSteps.indexOf(roles) < serviceTestSteps.indexOf(issue));
});

test('service subject and resource audience use separate access-token claims with local realm signing', () => {
  const issue = serviceTestStage('issue');
  assert.equal(issue.payload.find(item => item.name === 'sub').value, 'service-account-id-204');
  assert.equal(issue.payload.find(item => item.name === 'aud').value, 'orders-api');
  assert.notEqual(issue.payload.find(item => item.name === 'aud').value, getServiceAccountExampleOverrides().clientApp);
  assert.ok(issue.attributeOperations.some(action => action.attributeId === 'serviceAccessSignature' && action.kind === 'derive'));
  assert.match(issue.detail, /does not require JWT serialization/);
  const signingUsage = getAttributeUsage(serviceTestSteps, 'realmSigningKey');
  assert.equal(signingUsage.length, 1);
  assert.equal(signingUsage[0].step.id, 'service-issue');
  assert.equal(signingUsage[0].wireAttributeIds.length, 0);
  assert.equal(serviceTestAllOperations.some(action => action.attributeId === 'realmSigningKey' && ['send', 'receive'].includes(action.kind)), false);
});

test('normal response includes access token metadata and nested signed claims, with no ID or refresh token', () => {
  const response = serviceTestStage('response');
  assert.equal(response.from, 'realmA');
  assert.equal(response.to, 'app');
  assert.equal(response.channel, 'backchannel');
  assert.deepEqual(response.payload.map(item => item.name), ['HTTP', 'Cache-Control', 'Pragma', 'access_token', 'token_type', 'expires_in', 'scope']);
  assert.equal(response.payload.find(item => item.name === 'token_type').value, 'Bearer');
  assert.equal(response.payload.find(item => item.name === 'Cache-Control').value, 'no-store');
  for (const id of ['serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope', 'serviceAccessSignature']) {
    const send = response.attributeOperations.find(action => action.attributeId === id && action.kind === 'send');
    assert.equal(send?.carriedAs, 'access_token (JWS)', id + ' is nested in the signed token');
    assert.ok(response.attributeOperations.some(action => action.attributeId === id && action.kind === 'receive' && action.actorId === 'app'));
  }
  const ready = serviceTestStage('ready');
  assert.ok(ready.attributeOperations.some(action => action.attributeId === 'accessTokenA' && action.kind === 'store'));
  assert.equal(ready.attributeOperations.some(action => /^serviceAccess/.test(action.attributeId) && action.kind === 'verify'), false, 'Service is not modeled as the resource server or an ID-token relying party');
  assert.match(ready.detail, /API request is outside this scenario/);
});

test('participant overrides describe the confidential service and only its relevant OAuth attributes', () => {
  const actors = getServiceAccountActorOverrides();
  assert.deepEqual(Object.keys(actors).sort(), ['app', 'realmA']);
  assert.equal(actors.app.name, 'Background service');
  assert.match(actors.app.role, /Confidential OAuth client/);
  assert.ok(actors.app.attributes.some(item => item.id === 'clientSecret' && item.kind === 'static'));
  assert.ok(actors.realmA.attributes.some(item => item.id === 'serviceAccountEnabled'));
  for (const actor of Object.values(actors)) {
    assert.equal(new Set(actor.attributes.map(item => item.id)).size, actor.attributes.length);
    for (const item of actor.attributes) {
      assert.ok(ATTRIBUTES[item.id], item.id);
      assert.equal(serviceTestUnusedHumanFields.includes(item.id), false);
    }
  }
  const overrides = getServiceAccountAttributeOverrides();
  assert.equal(overrides.grantType.example, 'client_credentials');
  assert.equal(overrides.clientIdApp.example, 'orders-service');
  assert.match(overrides.accessTokenA.meaning, /service account/);
  assert.match(overrides.clientSecret.purpose, /Basic header/);
});

test('model is deeply immutable while definitions and actor overrides are fresh for safe integration', () => {
  assert.ok(Object.isFrozen(serviceTestSteps));
  assert.ok(Object.isFrozen(serviceTestStage('response').payload));
  assert.ok(Object.isFrozen(serviceTestStage('response').attributeOperations[0]));
  assert.throws(() => serviceTestSteps.push({}), TypeError);
  const snapshot = JSON.stringify(serviceTestSteps);
  const firstActors = getServiceAccountActorOverrides(), firstDefs = getServiceAccountAttributeOverrides();
  firstActors.app.attributes.push({ id: 'session', kind: 'generated' });
  firstDefs.grantType.example = 'authorization_code';
  assert.equal(getServiceAccountActorOverrides().app.attributes.some(item => item.id === 'session'), false);
  assert.equal(getServiceAccountAttributeOverrides().grantType.example, 'client_credentials');
  assert.equal(JSON.stringify(serviceTestSteps), snapshot);
});
