import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES } from '../src/protocol-data.js';
import { getStepAttributeOperations, getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { WEBLAB_ATTRIBUTES, WEBLAB_SOURCES, WEBLAB_SCENARIOS } from '../src/web-api-lab.js';

Object.assign(ATTRIBUTES, WEBLAB_ATTRIBUTES);
const webTestModel = id => WEBLAB_SCENARIOS.find(model => model.id === id);
const webTestStep = (modelId, stepId) => webTestModel(modelId).steps({}).find(step => step.id === stepId);
const webTestWire = step => getStepAttributeOperations(step).filter(op => ['send', 'receive'].includes(op.kind));
const webTestAllWire = steps => steps.flatMap(step => webTestWire(step).map(op => ({ step, ...op })));
const webTestOps = (modelId, id) => webTestModel(modelId).steps({}).flatMap(step => step.attributeOperations.filter(op => op.attributeId === id).map(op => ({ step, ...op })));

test('five SPA/API labs are immutable, use known actors and expose complete namespaced attribute ledgers', () => {
  assert.deepEqual(WEBLAB_SCENARIOS.map(model => model.id), ['lab-spa-api', 'lab-bff-api', 'lab-api-introspection', 'lab-api-errors', 'lab-jwks-rotation']);
  for (const model of WEBLAB_SCENARIOS) {
    const steps = model.steps({}), actors = model.actors({}), definitions = model.definitions({});
    assert.equal(model.steps({}), steps);
    assert.equal(Object.isFrozen(steps), true);
    assert.ok(steps.length >= 8 && steps.length <= 16);
    assert.equal(new Set(steps.map(step => step.id)).size, steps.length);
    for (const step of steps) {
      assert.equal(Object.isFrozen(step), true);
      assert.ok(Array.isArray(step.attributeOperations));
      for (const id of [step.from, step.to]) { assert.ok(ACTORS[id]); assert.ok(actors[id], model.id + ': ' + id); }
      for (const op of step.attributeOperations) {
        assert.ok(op.attributeId.startsWith('web'));
        assert.ok(definitions[op.attributeId], model.id + ': ' + op.attributeId);
        assert.ok(actors[op.actorId], model.id + ': ' + op.actorId);
      }
      assert.deepEqual(new Set(step.fields), new Set(step.attributeOperations.map(op => op.attributeId)));
    }
    for (const id of model.ids) for (const field of ['name', 'meaning', 'origin', 'purpose', 'example', 'standard', 'source']) assert.ok(definitions[id][field], id + ': ' + field);
    for (const actor of Object.values(actors)) {
      assert.ok(actor.notes.length > 0);
      assert.equal(new Set(actor.attributes.map(attr => attr.id)).size, actor.attributes.length);
      assert.ok(['user', 'app', 'browser', 'realmA', 'realmB', 'external', 'webapp'].includes(actor.art));
    }
  }
  assert.ok(WEBLAB_SOURCES.every(source => source.label && source.url.startsWith('https://')));
});

test('pure SPA is the public browser client: local PKCE/state/nonce, actual browser callback, no backend or secret', () => {
  const model = webTestModel('lab-spa-api'), steps = model.steps({});
  assert.equal(steps.some(step => step.from === 'app' || step.to === 'app'), false);
  assert.equal(steps.some(step => step.fields.includes('webClientSecret') || step.fields.includes('webClientAuth')), false);
  const prepare = webTestStep(model.id, 'web-spa-prepare');
  for (const id of ['webState', 'webNonce', 'webVerifier']) assert.ok(prepare.attributeOperations.some(op => op.attributeId === id && op.actorId === 'browser' && op.kind === 'create'));
  assert.ok(prepare.attributeOperations.some(op => op.attributeId === 'webChallenge' && op.actorId === 'browser' && op.kind === 'derive'));
  const authorize = webTestStep(model.id, 'web-spa-authorize');
  assert.ok(webTestWire(authorize).some(op => op.attributeId === 'webChallenge' && op.actorId === 'realmA'));
  assert.equal(webTestWire(authorize).some(op => op.attributeId === 'webVerifier'), false);
  const callback = webTestStep(model.id, 'web-spa-callback');
  assert.equal(callback.from, 'browser'); assert.equal(callback.to, 'browser');
  assert.ok(callback.attributeOperations.some(op => op.attributeId === 'webState' && op.kind === 'verify'));
  assert.ok(callback.attributeOperations.some(op => op.attributeId === 'webCode' && op.kind === 'store'));
  assert.match(webTestStep(model.id, 'web-spa-code-return').payload.find(p => p.attributeId === 'webLocation').value, /^https:\/\/spa\.example\.test\/callback\?/);
  assert.match(callback.detail, /browser JavaScript/);
  const verifierWire = webTestOps(model.id, 'webVerifier').filter(op => ['send', 'receive'].includes(op.kind));
  assert.deepEqual(verifierWire.map(op => [op.step.id, op.actorId, op.kind]), [['web-spa-token-request', 'browser', 'send'], ['web-spa-token-request', 'realmA', 'receive']]);
});

test('SPA code redemption uses client_id + original verifier and checks identity nonce locally', () => {
  const request = webTestStep('lab-spa-api', 'web-spa-token-request');
  assert.equal(request.from, 'browser'); assert.equal(request.to, 'realmA');
  for (const id of ['webClientId', 'webGrantType', 'webCode', 'webRedirectUri', 'webVerifier']) assert.ok(webTestWire(request).some(op => op.attributeId === id && op.kind === 'send'));
  assert.equal(webTestWire(request).some(op => op.attributeId === 'webChallenge'), false, 'Challenge is recomputed locally; not sent in token request');
  assert.ok(request.attributeOperations.some(op => op.attributeId === 'webChallenge' && op.kind === 'derive' && op.actorId === 'realmA'));
  const result = webTestStep('lab-spa-api', 'web-spa-tokens');
  assert.equal(result.to, 'browser');
  assert.equal(result.payload.find(p => p.attributeId === 'webIdAudience').value, 'spa-public');
  assert.equal(result.payload.find(p => p.attributeId === 'webApiAudience').value, 'orders-api');
  const identity = webTestStep('lab-spa-api', 'web-spa-identity');
  for (const id of ['webIdToken', 'webSignature', 'webAlgorithm', 'webIssuer', 'webIdAudience', 'webExpiry', 'webNonce']) assert.ok(identity.attributeOperations.some(op => op.attributeId === id && op.kind === 'verify'));
  assert.ok(identity.attributeOperations.some(op => op.attributeId === 'webAccessToken' && op.kind === 'store' && op.actorId === 'browser'));
  assert.match(identity.detail, /in memory/);
});

test('API calls use access tokens with API audience, never ID tokens or client/factor secrets', () => {
  for (const [modelId, requestId, verifyId] of [['lab-spa-api', 'web-spa-api-request', 'web-spa-api-verify'], ['lab-bff-api', 'web-bff-api-request', 'web-bff-api-verify']]) {
    const request = webTestStep(modelId, requestId), wire = webTestWire(request);
    for (const id of ['webAccessToken', 'webBearerHeader', 'webApiAudience', 'webSignature']) assert.ok(wire.some(op => op.attributeId === id));
    for (const id of ['webIdToken', 'webIdAudience', 'webNonce', 'webVerifier', 'webClientSecret', 'webRefreshToken', 'webCookie']) assert.equal(wire.some(op => op.attributeId === id), false, modelId + ': ' + id);
    const verify = webTestStep(modelId, verifyId);
    for (const id of ['webAlgorithm', 'webSignature', 'webIssuer', 'webApiAudience', 'webExpiry', 'webApiScope']) assert.ok(verify.attributeOperations.some(op => op.attributeId === id && op.kind === 'verify'));
    assert.ok(verify.attributeOperations.some(op => op.attributeId === 'webPermissions' && op.kind === 'use'));
    assert.equal(verify.from, 'realmB'); assert.equal(verify.to, 'realmB');
  }
});

test('cross-origin SPA CORS preflight carries header names, never a bearer token; actual request still authenticates', () => {
  const request = webTestStep('lab-spa-api', 'web-spa-preflight');
  assert.equal(request.payload[0].value.startsWith('OPTIONS '), true);
  const requestIds = new Set(webTestWire(request).map(op => op.attributeId));
  assert.deepEqual(requestIds, new Set(['webOrigin', 'webRequestedHeaders', 'webRequestedMethod']));
  assert.equal(request.fields.includes('webAccessToken'), false);
  const allow = webTestStep('lab-spa-api', 'web-spa-preflight-allow');
  assert.deepEqual(new Set(webTestWire(allow).map(op => op.attributeId)), new Set(['webAllowOrigin', 'webAllowedMethods', 'webAllowedHeaders']));
  assert.equal(allow.payload.find(p => p.attributeId === 'webAllowOrigin').value, 'https://spa.example.test');
  assert.ok(webTestWire(webTestStep('lab-spa-api', 'web-spa-api-request')).some(op => op.attributeId === 'webOrigin'));
  assert.ok(webTestWire(webTestStep('lab-spa-api', 'web-spa-api-response')).some(op => op.attributeId === 'webAllowOrigin'));
});

test('BFF preserves the browser-cookie/server-token boundary on every exchange', () => {
  const model = webTestModel('lab-bff-api'), steps = model.steps({});
  const forbiddenBrowser = new Set(['webClientSecret', 'webClientAuth', 'webVerifier', 'webIdToken', 'webAccessToken', 'webRefreshToken']);
  const browserWire = webTestAllWire(steps).filter(op => op.actorId === 'browser');
  assert.equal(browserWire.some(op => forbiddenBrowser.has(op.attributeId)), false);
  const prepare = webTestStep(model.id, 'web-bff-prepare');
  assert.ok(prepare.attributeOperations.some(op => op.attributeId === 'webVerifier' && op.kind === 'create' && op.actorId === 'app'));
  const tokens = webTestStep(model.id, 'web-bff-tokens'); assert.equal(tokens.to, 'app');
  assert.equal(tokens.payload.find(p => p.attributeId === 'webIdAudience').value, 'bff-web');
  const cookie = webTestStep(model.id, 'web-bff-cookie');
  assert.deepEqual(new Set(webTestWire(cookie).map(op => op.attributeId)), new Set(['webCookie']));
  assert.match(cookie.payload.find(p => p.attributeId === 'webCookie').value, /Secure; HttpOnly; SameSite=Lax/);
  assert.ok(webTestStep(model.id, 'web-bff-data-request').attributeOperations.some(op => op.attributeId === 'webSession' && op.kind === 'verify'));
  assert.equal(webTestStep(model.id, 'web-bff-api-request').from, 'app');
  assert.equal(webTestStep(model.id, 'web-bff-ui-response').fields.includes('webAccessToken'), false);
  assert.match(model.supportNote, /CSRF/);
});

test('introspection authenticates the API separately from the token under inspection and checks full policy', () => {
  const model = webTestModel('lab-api-introspection'), query = webTestStep(model.id, 'web-intro-query');
  assert.equal(query.from, 'realmB'); assert.equal(query.to, 'realmA');
  for (const id of ['webIntrospectionAuth', 'webIntrospectionToken', 'webTokenTypeHint']) assert.ok(webTestWire(query).some(op => op.attributeId === id));
  assert.equal(webTestWire(query).some(op => op.attributeId === 'webIntrospectionSecret'), false);
  assert.equal(webTestWire(query).some(op => op.attributeId === 'webIdToken'), false);
  assert.ok(webTestWire(query).some(op => op.attributeId === 'webAccessToken' && /token value/.test(op.carriedAs)));
  const prepare = webTestStep(model.id, 'web-intro-prepare');
  assert.ok(prepare.attributeOperations.some(op => op.attributeId === 'webIntrospectionSecret' && op.actorId === 'realmB' && op.kind === 'use'));
  assert.ok(prepare.attributeOperations.some(op => op.attributeId === 'webIntrospectionToken' && op.kind === 'derive'));
  const result = webTestStep(model.id, 'web-intro-result');
  for (const id of ['webActive', 'webSubject', 'webApiAudience', 'webApiScope', 'webExpiry']) assert.ok(webTestWire(result).some(op => op.attributeId === id));
  const check = webTestStep(model.id, 'web-intro-api-check');
  for (const id of ['webActive', 'webIssuer', 'webApiAudience', 'webExpiry', 'webApiScope']) assert.ok(check.attributeOperations.some(op => op.attributeId === id && op.kind === 'verify'));
  assert.match(model.supportNote, /remain JWTs/);
  assert.match(check.detail, /fails closed|fail.*closed/);
  const inactive = webTestStep(model.id, 'web-intro-inactive-note');
  assert.equal(inactive.payload[0].value, '200 OK');
  assert.equal(inactive.payload.find(p => p.attributeId === 'webActive').value, 'false');
  assert.deepEqual(new Set(webTestWire(inactive).map(op => op.attributeId)), new Set(['webActive']));
});

test('401 invalid_token and 403 insufficient_scope are independent cases and challenge auth-params', () => {
  const invalid = webTestStep('lab-api-errors', 'web-error-401'), scope = webTestStep('lab-api-errors', 'web-error-403');
  assert.equal(invalid.payload[0].value, '401 Unauthorized');
  assert.equal(invalid.payload.find(p => p.attributeId === 'webBearerError').value, 'invalid_token');
  assert.equal(scope.payload[0].value, '403 Forbidden');
  assert.equal(scope.payload.find(p => p.attributeId === 'webBearerError').value, 'insufficient_scope');
  assert.equal(scope.payload.find(p => p.attributeId === 'webRequiredScope').value, 'orders:write');
  for (const step of [invalid, scope]) {
    const errors = webTestWire(step).filter(op => op.attributeId === 'webBearerError');
    assert.ok(errors.every(op => /WWW-Authenticate/.test(op.carriedAs)));
    assert.equal(step.fields.includes('webResource'), false);
    assert.equal(step.fields.includes('webAccessToken'), false);
  }
  const validity = webTestStep('lab-api-errors', 'web-error-validity'), permission = webTestStep('lab-api-errors', 'web-error-permission');
  const steps = webTestModel('lab-api-errors').steps({});
  assert.ok(steps.indexOf(validity) < steps.indexOf(permission));
  assert.match(webTestStep('lab-api-errors', 'web-error-scope-request').detail, /separate request case/);
  assert.match(permission.detail, /cannot grant a missing scope/);
  assert.equal(webTestStep('lab-api-errors', 'web-error-success-response').payload[0].value, '200 OK');
});

test('an authentic unexpired token for other-api is rejected before scope checks at Orders API', () => {
  const model=webTestModel('lab-api-errors'),steps=model.steps({});
  const request=webTestStep(model.id,'web-error-audience-request');
  const trust=webTestStep(model.id,'web-error-audience-trust');
  const audience=webTestStep(model.id,'web-error-audience-check');
  const response=webTestStep(model.id,'web-error-audience-401');
  assert.equal(request.from,'app');assert.equal(request.to,'realmB');
  assert.equal(request.payload.find(p=>p.attributeId==='webApiAudience').value,'other-api');
  assert.equal(request.payload.find(p=>p.attributeId==='webApiScope').value,'orders:read');
  assert.match(request.payload.find(p=>p.attributeId==='webExpiry').value,/after.*current time/);
  for(const id of ['webAlgorithm','webSignature','webIssuer','webExpiry'])assert.ok(trust.attributeOperations.some(op=>op.attributeId===id&&op.kind==='verify'&&op.actorId==='realmB'));
  assert.match(trust.payload[0].value,/Signature, issuer and lifetime valid/);
  assert.equal(trust.attributeOperations.some(op=>op.attributeId==='webApiAudience'&&op.kind==='verify'),false,'Trust/time checks do not silently accept the recipient');
  assert.ok(audience.attributeOperations.some(op=>op.attributeId==='webExpectedApiAudience'&&op.kind==='use'&&op.actorId==='realmB'));
  assert.ok(audience.attributeOperations.some(op=>op.attributeId==='webApiAudience'&&op.kind==='verify'&&op.actorId==='realmB'));
  assert.equal(audience.payload.find(p=>p.attributeId==='webApiAudience').value,'other-api');
  assert.equal(audience.payload.find(p=>p.attributeId==='webExpectedApiAudience').value,'orders-api');
  for(const item of [trust,audience,response]){
    assert.equal(item.attributeOperations.some(op=>op.attributeId==='webApiScope'&&op.kind==='verify'),false,'Rejected credential never reaches permission checks');
    assert.equal(item.fields.includes('webResource'),false,'No protected data for this request');
  }
  assert.equal(response.payload[0].value,'401 Unauthorized');
  assert.equal(response.payload.find(p=>p.attributeId==='webBearerError').value,'invalid_token');
  assert.equal(response.fields.includes('webRequiredScope'),false,'Wrong recipient is a credential failure, not insufficient scope');
  assert.deepEqual([request,trust,audience,response].map(item=>steps.indexOf(item)),[3,4,5,6]);
  assert.ok(steps.indexOf(response)<steps.indexOf(webTestStep(model.id,'web-error-scope-request')));
  assert.equal(webTestAllWire(steps).some(op=>op.attributeId==='webExpectedApiAudience'),false,'Expected recipient stays in the API configuration');
  assert.match(model.summary,/wrong audience/);
});

test('audience-focused animations retain the received other-api claim and show expected orders-api only locally',()=>{
  const model=webTestModel('lab-api-errors'),steps=model.steps({});
  const actual=buildAttributeTrace(getAttributeUsage(steps,'webApiAudience'),model.examples({}));
  const wrong=actual.filter(frame=>frame.sourceStepId.startsWith('web-error-audience-'));
  assert.deepEqual(wrong.map(frame=>[frame.sourceStepId,frame.traceKind,frame.from,frame.to]),[
    ['web-error-audience-request','send','app','realmB'],
    ['web-error-audience-check','verify','realmB','realmB'],
  ]);
  for(const frame of wrong)assert.equal(frame.payload.find(member=>member.attributeId==='webApiAudience').value,'other-api');
  for(const frame of actual.filter(frame=>['web-error-scope-request','web-error-validity','web-error-success-request','web-error-success-check'].includes(frame.sourceStepId)))assert.equal(frame.payload.find(member=>member.attributeId==='webApiAudience').value,'orders-api','Later independent requests regain their own correct recipient');
  const expected=buildAttributeTrace(getAttributeUsage(steps,'webExpectedApiAudience'),model.examples({}));
  assert.deepEqual(expected.map(frame=>[frame.traceKind,frame.from,frame.to,frame.payload[0].value]),[['use','realmB','realmB','orders-api']]);
  const token=buildAttributeTrace(getAttributeUsage(steps,'webAccessToken'),model.examples({}));
  assert.match(token.find(frame=>frame.sourceStepId==='web-error-audience-request').payload[0].value,/aud=other-api/);
  assert.match(token.find(frame=>frame.sourceStepId==='web-error-invalid-check').payload[0].value,/Expired/);
  assert.equal(Object.isFrozen(webTestStep(model.id,'web-error-audience-check').attributeValues),true);
});

test('unknown kid causes one issuer-pinned JWKS refresh before verification and never transports a private signing key', () => {
  const model = webTestModel('lab-jwks-rotation'), steps = model.steps({});
  const fetch = webTestStep(model.id, 'web-rotation-jwks-request'), received = webTestStep(model.id, 'web-rotation-jwks-response'), verify = webTestStep(model.id, 'web-rotation-verify');
  assert.equal(steps.filter(step => step.payload.some(p => p.name === 'HTTP' && p.value.startsWith('GET https://idp1.example.test/realms/realm-a/protocol/openid-connect/certs'))).length, 1);
  assert.ok(fetch.attributeOperations.some(op => op.attributeId === 'webRefreshBudget' && op.kind === 'store'));
  assert.ok(received.attributeOperations.some(op => op.attributeId === 'webKeyCache' && op.kind === 'store'));
  assert.ok(steps.indexOf(fetch) < steps.indexOf(received) && steps.indexOf(received) < steps.indexOf(verify));
  assert.equal(webTestAllWire(steps).some(op => op.attributeId === 'webSigningPrivateKey'), false);
  assert.equal(webTestAllWire(steps).some(op => op.attributeId === 'webJku'), false);
  assert.match(webTestStep(model.id, 'web-rotation-unknown-kid').detail, /does not fetch arbitrary jku/);
  assert.match(fetch.detail, /one refresh/);
  assert.ok(verify.attributeOperations.some(op => op.attributeId === 'webSignature' && op.kind === 'verify'));
  const jwks = JSON.parse(received.payload.find(p => p.attributeId === 'webKeys').value);
  assert.deepEqual(jwks.keys.map(key => key.kid), ['realm-sign-1', 'realm-sign-2']);
  assert.equal(jwks.keys.some(key => Object.hasOwn(key, 'd')), false);
});

test('focused PKCE, API authorization and cookie traces have genuine create/send/verify moments at correct actors', () => {
  const spa = webTestModel('lab-spa-api').steps({});
  const verifier = getAttributeUsage(spa, 'webVerifier');
  assert.ok(verifier[0].actions.some(op => op.kind === 'create' && op.actorId === 'browser'));
  assert.ok(verifier.some(usage => usage.actions.some(op => op.kind === 'send' && op.actorId === 'browser')));
  assert.ok(verifier.some(usage => usage.actions.some(op => op.kind === 'verify' && op.actorId === 'realmA')));
  const access = getAttributeUsage(spa, 'webApiAudience');
  assert.ok(access.some(usage => usage.actions.some(op => op.kind === 'verify' && op.actorId === 'realmB')));
  const bff = webTestModel('lab-bff-api').steps({});
  const cookie = getAttributeUsage(bff, 'webCookie');
  assert.ok(cookie.some(usage => usage.actions.some(op => op.kind === 'create' && op.actorId === 'app')));
  assert.ok(cookie.some(usage => usage.actions.some(op => op.kind === 'receive' && op.actorId === 'browser')));
  assert.ok(cookie.some(usage => usage.actions.some(op => op.kind === 'verify' && op.actorId === 'app')));
  assert.equal(cookie.some(usage => usage.actions.some(op => op.actorId === 'realmB')), false);
});
