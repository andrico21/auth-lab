import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { EXCHANGE_ATTRIBUTES, EXCHANGE_TOPIC_IDS, EXCHANGE_SOURCES, getTokenExchangeSteps, getTokenExchangeActorOverrides, getTokenExchangeAttributeOverrides, getTokenExchangeExampleOverrides } from '../src/token-exchange-data.js';

Object.assign(ATTRIBUTES, EXCHANGE_ATTRIBUTES);
const stages = getTokenExchangeSteps();
const at = id => stages.find(step => step.exchangeStage === id);
const wire = step => getStepAttributeOperations(step).filter(action => ['send', 'receive'].includes(action.kind));
const forbiddenFields = new Set(['stateApp', 'stateBroker', 'nonceApp', 'nonceBroker', 'codeVerifier', 'codeChallenge', 'codeChallengeMethod', 'codeA', 'codeB', 'idTokenA', 'idTokenB', 'refreshToken', 'redirectApp', 'redirectBroker', 'password']);

test('Standard V2 exchange is a cached same-realm backend operation without new user authentication', () => {
  const config = { mode: 'passkey', architecture: 'native', upstream: 'external' };
  const original = JSON.stringify(config);
  assert.equal(getTokenExchangeSteps(config), stages);
  assert.equal(JSON.stringify(config), original);
  assert.equal(new Set(stages.map(step => step.id)).size, stages.length);
  for (const step of stages) {
    assert.equal(step.architecture, 'web'); assert.equal(step.upstream, 'single');
    assert.equal(step.topology, 'single'); assert.equal(step.grantFlow, 'token-exchange');
    assert.ok(['app', 'realmA'].includes(step.from)); assert.ok(['app', 'realmA'].includes(step.to));
    assert.ok(ACTORS[step.from]); assert.ok(ACTORS[step.to]);
    for (const id of step.fields) { assert.ok(EXCHANGE_ATTRIBUTES[id], id); assert.equal(forbiddenFields.has(id), false); }
    assert.ok(Array.isArray(step.attributeOperations));
    for (const operation of getStepAttributeOperations(step)) {
      assert.ok(EXCHANGE_ATTRIBUTES[operation.attributeId], operation.attributeId);
      assert.ok(['app', 'realmA'].includes(operation.actorId));
    }
  }
  assert.match(at('prerequisite').detail, /earlier|previously/);
  assert.match(at('prerequisite').detail, /does not.*new user session/);
  assert.equal(stages.some(step => step.attributeOperations.some(action => action.attributeId === 'exchangeSubjectToken' && action.kind === 'create')), false);
  assert.equal(stages.some(step => step.payload.some(field => ['state', 'nonce', 'redirect_uri', 'code_verifier', 'id_token', 'refresh_token', 'actor_token', 'resource', 'requested_subject', 'subject_issuer'].includes(field.name))), false);
});

test('exchange request distinguishes subject-token authorization from confidential-client authentication', () => {
  const request = at('request');
  const values = Object.fromEntries(request.payload.map(field => [field.name, field.value]));
  assert.equal(values.grant_type, 'urn:ietf:params:oauth:grant-type:token-exchange');
  assert.equal(values.subject_token_type, 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(values.requested_token_type, 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(values.audience, 'orders-api'); assert.equal(values.scope, 'orders.read');
  assert.match(values.Authorization, /^Basic /);
  assert.match(values.HTTP, /^POST https:\/\/idp1\.example\.test\/realms\/realm-a\/protocol\/openid-connect\/token$/);
  assert.equal(values['Content-Type'], 'application/x-www-form-urlencoded');
  assert.equal(Object.hasOwn(values, 'client_id'), false); assert.equal(Object.hasOwn(values, 'client_secret'), false);
  for (const id of ['exchangeClientId', 'exchangeClientSecret']) {
    const actions = wire(request).filter(action => action.attributeId === id);
    assert.equal(actions.length, 2); assert.ok(actions.every(action => /Authorization: Basic over TLS/.test(action.carriedAs)));
  }
  for (const id of ['exchangeSourceIssuer', 'exchangeSourceSubject', 'exchangeSourceAudience', 'exchangeSourceExpiry', 'exchangeSourceScope']) {
    const actions = wire(request).filter(action => action.attributeId === id);
    assert.equal(actions.length, 2); assert.ok(actions.every(action => /subject_token/.test(action.carriedAs)));
    assert.match(actions[0].detail, /not as an independent request parameter/);
  }
  assert.ok(at('prepare').attributeOperations.some(action => action.attributeId === 'exchangeAuthorization' && action.kind === 'derive'));
});

test('source token and client eligibility are verified before new authorization is issued', () => {
  assert.ok(stages.indexOf(at('client-check')) < stages.indexOf(at('subject-check')));
  assert.ok(stages.indexOf(at('subject-check')) < stages.indexOf(at('policy')));
  assert.ok(stages.indexOf(at('policy')) < stages.indexOf(at('issue')));
  const clientVerified = new Set(at('client-check').attributeOperations.filter(action => action.kind === 'verify').map(action => action.attributeId));
  for (const id of ['exchangeAuthorization', 'exchangeClientId', 'exchangeClientSecret', 'exchangeEnabledPolicy', 'exchangeGrantType', 'exchangeSubjectTokenType', 'exchangeRequestedTokenType']) assert.ok(clientVerified.has(id), id);
  const sourceVerified = new Set(at('subject-check').attributeOperations.filter(action => action.kind === 'verify').map(action => action.attributeId));
  for (const id of ['exchangeSubjectToken', 'exchangeSourceIssuer', 'exchangeSourceAudience', 'exchangeSourceExpiry']) assert.ok(sourceVerified.has(id), id);
  assert.match(at('subject-check').detail, /requester-client is in its aud/);
  assert.match(EXCHANGE_ATTRIBUTES.exchangeSourceAudience.purpose, /exception.*issued to itself/);
  assert.match(at('client-check').detail, /legacy V1.*not required/);
});

test('downscoping is shown as an explicit client policy rather than an automatic Standard V2 restriction', () => {
  assert.match(EXCHANGE_ATTRIBUTES.exchangeScopeRequest.purpose, /can request additional configured optional scopes by default/);
  assert.match(at('prepare').detail, /explicit downscope-assertion-grant-enforcer/);
  assert.match(at('policy').detail, /defaults also participate/);
  assert.match(at('policy').detail, /cannot add an unconfigured target/);
  for (const id of ['exchangeScopePolicy', 'exchangeScopeRequest', 'exchangeAudienceRequest']) assert.ok(at('policy').attributeOperations.some(action => action.attributeId === id && action.kind === 'verify'), id);
  assert.ok(at('policy').attributeOperations.some(action => action.attributeId === 'exchangeScopeResponse' && action.kind === 'derive'));
  assert.ok(at('policy').attributeOperations.some(action => action.attributeId === 'exchangeResultAudience' && action.kind === 'derive'));
  assert.match(EXCHANGE_ATTRIBUTES.exchangeScopePolicy.purpose, /not a parameter sent/);
  assert.equal(wire(at('request')).some(action => action.attributeId === 'exchangeScopePolicy' || action.attributeId === 'exchangeEnabledPolicy'), false);
});

test('response type metadata and nested token claims follow RFC 8693 with a separate result token', () => {
  const response = at('response');
  const values = Object.fromEntries(response.payload.map(field => [field.name, field.value]));
  for (const field of ['access_token', 'issued_token_type', 'token_type', 'expires_in', 'scope']) assert.ok(Object.hasOwn(values, field), field);
  assert.equal(values.issued_token_type, 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(values.token_type, 'Bearer'); assert.notEqual(values.access_token, EXCHANGE_ATTRIBUTES.exchangeSubjectToken.example);
  for (const name of ['iss', 'sub', 'aud', 'exp', 'iat', 'id_token', 'refresh_token']) assert.equal(Object.hasOwn(values, name), false, name);
  for (const id of ['exchangeResultIssuer', 'exchangeResultSubject', 'exchangeResultAudience', 'exchangeResultExpiry', 'exchangeResultIssuedAt']) {
    const actions = wire(response).filter(action => action.attributeId === id);
    assert.equal(actions.length, 2); assert.ok(actions.every(action => /access_token → signed result JWT/.test(action.carriedAs)));
  }
  assert.equal(EXCHANGE_ATTRIBUTES.exchangeResultSubject.example, EXCHANGE_ATTRIBUTES.exchangeSourceSubject.example);
  assert.notEqual(EXCHANGE_ATTRIBUTES.exchangeResultAudience.example, EXCHANGE_ATTRIBUTES.exchangeSourceAudience.example);
  assert.ok(at('issue').attributeOperations.some(action => action.attributeId === 'exchangeSigningKey' && action.kind === 'use'));
  assert.equal(stages.flatMap(wire).some(action => action.attributeId === 'exchangeSigningKey' || action.attributeId === 'exchangeVerificationKey'), false);
});

test('exchange keeps original token and does not invent token consumption, revocation chain or actor delegation', () => {
  assert.ok(at('retain').attributeOperations.some(action => action.attributeId === 'exchangeSubjectToken' && action.kind === 'store'));
  assert.ok(at('retain').attributeOperations.some(action => action.attributeId === 'exchangeAccessToken' && action.kind === 'store'));
  assert.match(at('retain').detail, /does not consume or automatically revoke/);
  assert.match(at('retain').detail, /does not automatically revoke its exchanged access-token result/);
  assert.match(at('retain').detail, /may treat the access token as opaque/);
  assert.match(at('issue').detail, /does not claim a distinct RFC 8693 act\/may_act/);
  assert.match(EXCHANGE_ATTRIBUTES.exchangeResultSubject.purpose, /Preview and disabled by default/);
  assert.match(EXCHANGE_ATTRIBUTES.exchangeRequestedTokenType.purpose, /ID-token and conditional refresh-token.*does not animate/);
});

test('every exchange index field has an explicit lifecycle and actor attributes match the active grant', () => {
  assert.deepEqual(EXCHANGE_TOPIC_IDS, Object.keys(EXCHANGE_ATTRIBUTES));
  assert.ok(EXCHANGE_SOURCES.every(source => source.url.startsWith('https://')));
  for (const id of EXCHANGE_TOPIC_IDS) {
    assert.ok(getAttributeUsage(stages, id).length > 0, id);
    const definition = EXCHANGE_ATTRIBUTES[id];
    for (const property of ['name', 'meaning', 'origin', 'purpose', 'standard', 'source']) assert.ok(definition[property], id + '.' + property);
  }
  const overrides = getTokenExchangeActorOverrides();
  assert.deepEqual(Object.keys(overrides), ['app', 'realmA']);
  for (const actor of Object.values(overrides)) for (const attribute of actor.attributes) assert.ok(EXCHANGE_ATTRIBUTES[attribute.id]);
  assert.equal(overrides.app.attributes.some(attribute => attribute.id === 'exchangeSigningKey'), false);
  assert.ok(overrides.realmA.attributes.some(attribute => attribute.id === 'exchangeSigningKey' && attribute.kind === 'static'));
  assert.equal(getTokenExchangeAttributeOverrides(), EXCHANGE_ATTRIBUTES);
  assert.equal(getTokenExchangeExampleOverrides().exchangeClientId, 'requester-client');
  assert.match(overrides.realmA.notes.join(' '), /does not currently support the RFC resource parameter/);
});
