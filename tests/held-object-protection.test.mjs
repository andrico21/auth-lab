import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PROTLAB_SCENARIOS } from '../src/protection-lab.js';
import { WEBLAB_SCENARIOS } from '../src/web-api-lab.js';
import { buildProtectionHeldObjects } from '../src/held-object-protection.js';
import { compileHeldObjects, projectHeldObjects, inspectHeldObject, heldObjectTrace, assertHeldObjectCoverage } from '../src/held-object-state.js';

const models = [...PROTLAB_SCENARIOS, ...WEBLAB_SCENARIOS];
function fixture(id, contextId = id + ':test') {
  const model = models.find(item => item.id === id);
  const config = {}, steps = model.steps(config), actors = model.actors(config);
  const plan = buildProtectionHeldObjects({ model, steps, actors, config, choiceId: id, contextId });
  const compiled = compileHeldObjects(plan, { model, steps });
  const at = (event, milestone = 'complete') => projectHeldObjects(compiled, { eventIndex: steps.findIndex(step => step.id === event), milestone });
  return { model, plan, compiled, steps, at, initial: projectHeldObjects(compiled) };
}
const held = (snapshot, actor, artifact) => snapshot.holdings.filter(item => item.actorId === actor && item.artifactId === artifact);
const object = (snapshot, id) => snapshot.artifacts.find(item => item.artifactId === id);
const value = (artifact, attr) => artifact.representations[0].fields.find(field => field.attributeId === attr)?.value;

for (const model of models) test(model.id + ' has complete, deterministic, release-complete authored coverage', () => {
  const f = fixture(model.id);
  assert.equal(assertHeldObjectCoverage(f.compiled), true);
  for (let eventIndex = -1; eventIndex < f.steps.length; eventIndex++) {
    const cursor = { eventIndex, milestone: eventIndex < 0 ? 'initial' : 'complete' };
    const snapshot = projectHeldObjects(f.compiled, cursor);
    assert.equal(snapshot.coverageStatus, 'complete');
    assert.equal(snapshot.coverage.length, Object.keys(f.model.actors({})).length);
    assert.deepEqual(snapshot, projectHeldObjects(f.compiled, cursor));
  }
  const final = projectHeldObjects(f.compiled, { eventIndex: f.steps.length - 1, milestone: 'complete' });
  assert.equal(final.holdings.some(item => item.retention === 'temporary'), false);
  for (const event of Object.values(f.plan.events)) {
    const transfers = new Set();
    for (const message of event.messages || []) {
      const key = message.from + '->' + message.to;
      assert.equal(transfers.has(key), false, 'one atomic message per source transfer');
      transfers.add(key);
    }
  }
});

test('DPoP proof target comes from each exact contextual source event, not the filtered glossary', () => {
  const model = models.find(item => item.id === 'lab-dpop');
  assert.equal(Object.hasOwn(model.definitions({}), 'protTokenEndpoint'), false);
  const targets = {
    'prot-dpop-token-sign': 'https://configured.example.test/token',
    'prot-dpop-api-sign': 'https://configured-api.example.test/orders',
    'prot-dpop-api-retry-sign': 'https://configured-api.example.test/orders',
  };
  const steps = model.steps({}).map(step => Object.hasOwn(targets, step.id) ? { ...step, attributeValues: { ...step.attributeValues, protDpopHtu: targets[step.id] } } : step);
  const plan = buildProtectionHeldObjects({ model, steps, actors: model.actors({}), config: {}, choiceId: model.id, contextId: 'dpop:contextual-targets' });
  for (const [artifactId, event] of [['dpop-token-proof', 'prot-dpop-token-sign'], ['dpop-api-proof', 'prot-dpop-api-sign'], ['dpop-retry-proof', 'prot-dpop-api-retry-sign']]) {
    assert.equal(value(plan.artifacts.find(artifact => artifact.artifactId === artifactId), 'protDpopHtu'), targets[event]);
  }
});

test('DPoP has three exact JWT generations and distinct request-scoped replay/nonce knowledge', () => {
  const f = fixture('lab-dpop');
  assert.equal(object(f.initial, 'dpop-key'), undefined);
  const keys = f.at('prot-dpop-keys');
  assert.equal(held(keys, 'app', 'dpop-key').length, 1);
  assert.equal(held(keys, 'realmA', 'dpop-key').length, 0);
  const tokenProof = f.at('prot-dpop-token-sign');
  assert.equal(value(object(tokenProof, 'dpop-token-proof'), 'protDpopJti'), 'dpop_token_jti_51');
  assert.equal(value(object(tokenProof, 'dpop-token-proof'), 'protDpopAth'), undefined);
  assert.equal(value(object(tokenProof, 'dpop-token-proof'), 'protDpopHtm'), 'POST');
  assert.equal(held(f.at('prot-dpop-token-request', 'before'), 'realmA', 'dpop-token-proof').length, 0);
  assert.equal(held(f.at('prot-dpop-token-request'), 'realmA', 'dpop-token-proof').length, 1);
  assert.equal(held(f.at('prot-dpop-token-check'), 'realmA', 'dpop-token-proof').length, 0);
  const issued = f.at('prot-dpop-issue');
  assert.equal(held(issued, 'app', 'access-token').length, 0);
  const delivered = f.at('prot-dpop-token-response');
  assert.equal(held(delivered, 'app', 'access-token').length, 1);
  assert.equal(held(delivered, 'realmA', 'access-token').length, 0);
  const challenge = f.at('prot-dpop-api-challenge-create');
  assert.equal(held(challenge, 'app', 'api-nonce').length, 0);
  assert.equal(held(challenge, 'realmB', 'api-nonce').length, 1);
  assert.equal(value(object(challenge, 'dpop-api-proof'), 'protDpopJti'), 'dpop_api_jti_52');
  assert.equal(object(challenge, 'dpop-api-replay'), undefined);
  assert.equal(held(f.at('prot-dpop-api-challenge'), 'app', 'api-nonce').length, 1);
  const retry = f.at('prot-dpop-api-retry-sign');
  assert.equal(value(object(retry, 'dpop-retry-proof'), 'protDpopJti'), 'dpop_api_retry_jti_53');
  assert.equal(value(object(retry, 'dpop-retry-proof'), 'protDpopNonce'), 'api_nonce_random_32');
  assert.equal(held(retry, 'app', 'access-token')[0].holdingId, held(delivered, 'app', 'access-token')[0].holdingId);
  const accepted = f.at('prot-dpop-api-accept');
  assert.equal(value(object(accepted, 'dpop-as-replay'), 'protDpopJti'), 'dpop_token_jti_51');
  assert.equal(value(object(accepted, 'dpop-api-replay'), 'protDpopJti'), 'dpop_api_retry_jti_53');
  assert.equal(held(accepted, 'app', 'dpop-key').length, 1);
  assert.equal(held(accepted, 'app', 'access-token').length, 1);
  assert.equal(accepted.authority.some(item => item.artifactId === 'access-token'), false);
  assert.equal(accepted.observations.some(item => item.artifactId === 'dpop-api-proof' && item.result === 'accepted'), false);
  assert.equal(accepted.observations.some(item => item.artifactId === 'dpop-retry-proof' && item.requestId === 'dpop-api-retry' && item.result === 'accepted'), true);
});

test('mTLS keeps the private key local and uses separate token/API handshake proofs', () => {
  const f = fixture('lab-mtls');
  const token = f.at('prot-mtls-handshake');
  assert.equal(held(token, 'app', 'tls-key').length, 1);
  assert.equal(held(token, 'realmA', 'tls-key').length, 0);
  assert.equal(held(token, 'realmA', 'tls-token-proof').length, 1);
  const api = f.at('prot-mtls-api-request');
  assert.equal(held(api, 'realmB', 'tls-api-proof').length, 1);
  assert.equal(held(api, 'realmB', 'tls-token-proof').length, 0);
  assert.equal(held(api, 'app', 'tls-certificate').length, 1, 'public certificate send retains configured sender');
  assert.match(value(object(api, 'access-token'), 'protCertThumbprint'), /DER/);
  assert.equal(held(f.at('prot-mtls-api-check'), 'realmB', 'tls-api-proof').length, 0);
});

test('client authentication assertion and external subject grant have independent identities and replay records', () => {
  const client = fixture('lab-client-jwt');
  const signed = client.at('prot-client-jwt-sign');
  assert.equal(value(object(signed, 'client-assertion'), 'protCaSub'), 'protected-web-app');
  const accepted = client.at('prot-client-jwt-verify');
  assert.equal(value(object(accepted, 'client-jti-record'), 'protCaJti'), 'client_jwt_unique_12');
  assert.equal(held(accepted, 'app', 'client-key').length, 1);
  const grant = fixture('lab-jwt-grant');
  const received = grant.at('prot-jwt-grant-prerequisite');
  assert.equal(value(object(received, 'subject-assertion'), 'protGrantSub'), 'external-user-913');
  assert.equal(held(received, 'realmB', 'subject-assertion').length, 0, 'external issuer releases bearer output');
  assert.equal(held(received, 'realmB', 'external-key').length, 1);
  const completed = grant.at('prot-jwt-grant-result');
  assert.equal(completed.artifacts.some(item => /refresh/i.test(item.type + ' ' + item.label)), false);
  assert.equal(held(completed, 'realmA', 'transient-session').length, 0);
  assert.equal(value(object(completed, 'subject-jti-record'), 'protGrantJti'), 'external_assertion_unique_41');
});

test('PAR stores the request independently from browser/client handle and records one-use resolution', () => {
  const f = fixture('lab-par');
  const pushed = f.at('prot-par-store');
  assert.equal(held(pushed, 'realmA', 'par-stored-request').length, 1);
  assert.equal(held(pushed, 'app', 'par-handle').length, 0);
  const navigated = f.at('prot-par-browser');
  assert.equal(held(navigated, 'browser', 'par-handle').length, 1);
  assert.equal(held(navigated, 'browser', 'pkce-verifier').length, 0);
  const resolved = f.at('prot-par-resolve');
  assert.equal(resolved.authority.find(item => item.artifactId === 'par-stored-request').status, 'used');
  assert.equal(held(resolved, 'realmA', 'par-stored-request').length, 1);
});

test('signed JAR is browser-readable but does not invent a one-use jti cache', () => {
  const f = fixture('lab-jar');
  const browser = f.at('prot-jar-browser');
  const holding = held(browser, 'browser', 'request-object')[0];
  assert.equal(inspectHeldObject(browser, holding.holdingId).representation.readable, true);
  assert.equal(value(object(browser, 'request-object'), 'protRoJti'), 'request_object_unique_22');
  const verified = f.at('prot-jar-verify');
  assert.equal(verified.holdings.some(item => /replay/.test(item.store)), false);
  assert.equal(verified.authority.some(item => item.artifactId === 'request-object'), false);
});

test('JARM keeps nested code unchecked until full response validation', () => {
  const f = fixture('lab-jarm');
  const receipt = f.at('prot-jarm-callback');
  assert.equal(held(receipt, 'app', 'jarm-response').length, 1);
  assert.equal(held(receipt, 'app', 'authorization-code').length, 0);
  assert.equal(held(receipt, 'app', 'jarm-pending').length, 1);
  const accepted = f.at('prot-jarm-verify');
  assert.equal(held(accepted, 'app', 'authorization-code').length, 1);
  assert.equal(accepted.authority.find(item => item.artifactId === 'jarm-pending').status, 'consumed');
  assert.equal(held(f.at('prot-jarm-pkce-check'), 'app', 'authorization-code').length, 0);
});

for (const [id, p, client] of [['lab-spa-api', 'web-spa', 'browser'], ['lab-bff-api', 'web-bff', 'app']]) test(id + ' creates PKCE at actual client and preserves token ownership on API copies', () => {
  const f = fixture(id);
  assert.equal(held(f.at(p + '-prepare'), client, 'web-verifier').length, 1);
  if (client !== 'browser') assert.equal(held(f.at(p + '-prepare'), 'browser', 'web-verifier').length, 0);
  assert.deepEqual(object(f.at(p + '-prepare'), 'web-challenge').derivedFrom, ['web-verifier']);
  assert.equal(held(f.at(p + '-tokens', 'before'), client, 'access-token').length, 0);
  const token = f.at(p + '-tokens');
  assert.equal(held(token, client, 'access-token').length, 1);
  assert.equal(held(token, 'realmA', 'access-token').length, 0);
  const request = f.at(p + '-api-request');
  assert.equal(held(request, client, 'access-token').length, 1);
  assert.equal(held(request, 'realmB', 'access-token').length, 1);
  assert.equal(held(f.at(p + '-api-response'), 'realmB', 'access-token').length, 0);
  assert.equal(f.plan.artifacts.some(item => item.representations.some(rep => rep.fields.some(field => field.attributeId === 'webRefreshToken'))), false);
});

test('BFF HttpOnly cookie is browser-held but unreadable to frontend JavaScript', () => {
  const f = fixture('lab-bff-api');
  const snapshot = f.at('web-bff-cookie');
  const cookie = held(snapshot, 'browser', 'bff-cookie')[0];
  assert.ok(cookie);
  const inspection = inspectHeldObject(snapshot, cookie.holdingId);
  assert.equal(inspection.representation.readable, false);
  assert.equal(inspection.fields.every(field => field.redacted && !Object.hasOwn(field, 'value')), true);
  assert.equal(held(snapshot, 'app', 'bff-session').length, 1);
  assert.equal(held(snapshot, 'browser', 'access-token').length, 0);
  assert.equal(held(snapshot, 'browser', 'id-token').length, 0);
});

test('API independent wrong-audience and insufficient-scope cases do not globally invalidate tokens', () => {
  const f = fixture('lab-api-errors');
  const audience = f.at('web-error-audience-trust');
  assert.equal(audience.observations.some(item => item.artifactId === 'other-api-token' && item.result === 'passed'), true);
  assert.equal(audience.observations.some(item => item.artifactId === 'other-api-token' && item.result.includes('401')), false);
  const rejected = f.at('web-error-audience-check');
  assert.equal(value(object(rejected, 'other-api-token'), 'webApiAudience'), 'other-api');
  assert.match(rejected.observations.find(item => item.artifactId === 'other-api-token' && item.result === '401 invalid_token').policy, /stop before scope/);
  const forbidden = f.at('web-error-403');
  assert.equal(held(forbidden, 'app', 'read-only-token').length, 1);
  assert.equal(forbidden.authority.some(item => item.artifactId === 'read-only-token'), false);
  assert.equal(forbidden.observations.some(item => item.artifactId === 'read-only-token' && item.result === '403 insufficient_scope' && item.endpoint === 'POST /orders'), true);
  assert.equal(f.at('web-error-success-check').observations.some(item => item.artifactId === 'read-token' && item.result === '200 accepted'), true);
});

test('introspection active results are exact-token request observations, not a global cache', () => {
  const f = fixture('lab-api-introspection');
  assert.equal(held(f.initial, 'realmB', 'introspection-credential').length, 1);
  assert.equal(held(f.initial, 'app', 'introspection-credential').length, 0);
  assert.equal(value(object(f.at('web-intro-result'), 'introspected-token:status'), 'webActive'), true);
  assert.equal(held(f.at('web-intro-api-check'), 'realmB', 'introspected-token:status').length, 0);
  const inactive = f.at('web-intro-inactive-note');
  assert.equal(value(object(inactive, 'inactive-token:status'), 'webActive'), false);
  assert.equal(object(inactive, 'inactive-token:status').representations[0].fields.length, 1, 'inactive reply does not expose sensitive claims');
  assert.equal(inactive.observations.some(item => item.artifactId === 'introspected-token' && item.result === 'active=false'), false);
  assert.equal(f.at('web-intro-reject-inactive').observations.some(item => item.artifactId === 'inactive-token' && item.result === '401 invalid_token'), true);
});

test('issuer rollover publication does not mutate verifier C1 until authored response installation', () => {
  const f = fixture('lab-jwks-rotation');
  for (const event of ['web-rotation-cache', 'web-rotation-new-key', 'web-rotation-sign', 'web-rotation-api-request', 'web-rotation-unknown-kid', 'web-rotation-jwks-request']) {
    const snapshot = f.at(event);
    assert.equal(held(snapshot, 'realmB', 'jwks-cache-1').length, 1, event);
    assert.equal(held(snapshot, 'realmB', 'jwks-cache-2').length, 0, event);
    assert.deepEqual(value(object(snapshot, 'jwks-cache-1'), 'webKeyCache'), ['realm-sign-1']);
  }
  assert.equal(held(f.at('web-rotation-new-key'), 'realmB', 'issuer-jwks-2').length, 0);
  assert.equal(held(f.at('web-rotation-jwks-response', 'before'), 'realmB', 'jwks-cache-1').length, 1);
  const installed = f.at('web-rotation-jwks-response');
  assert.equal(held(installed, 'realmB', 'jwks-cache-1').length, 0);
  assert.deepEqual(value(object(installed, 'jwks-cache-2'), 'webKeyCache'), ['realm-sign-1', 'realm-sign-2']);
  assert.equal(held(installed, 'realmA', 'issuer-key-1').length, 1, 'no invented issuer key retirement');
  assert.equal(held(installed, 'realmA', 'issuer-key-2').length, 1);
  assert.equal(held(installed, 'realmA', 'issuer-jwks-2').length, 1, 'copy retains published JWKS');
  assert.equal(installed.observations.some(item => item.artifactId === 'access-token' && item.result === 'accepted'), false);
  assert.equal(f.at('web-rotation-verify').observations.filter(item => item.artifactId === 'access-token' && item.requestId === 'rotation-api-request').length, 3);
});

test('exact proof traces and random seeks share canonical immutable checkpoints and contexts', () => {
  const f = fixture('lab-dpop', 'dpop:context:one');
  const trace = heldObjectTrace(f.compiled, 'dpop-retry-proof');
  assert.ok(trace.length > 0);
  assert.equal(trace.some(row => row.sourceStepId === 'prot-dpop-api-sign'), false, 'same attribute does not merge P-A and P-R');
  for (const row of trace) assert.deepEqual(projectHeldObjects(f.compiled, row.heldCursorEnd), f.at(row.sourceStepId));
  const before = f.at('prot-dpop-api-retry', 'before');
  assert.equal(held(before, 'realmB', 'dpop-retry-proof').length, 0);
  const delivered = f.at('prot-dpop-api-retry');
  assert.equal(held(delivered, 'realmB', 'dpop-retry-proof').length, 1);
  assert.deepEqual(before, f.at('prot-dpop-api-retry', 'before'));
  const other = fixture('lab-dpop', 'dpop:context:two').at('prot-dpop-api-retry');
  assert.notEqual(held(delivered, 'app', 'access-token')[0].qualifiedArtifactId, held(other, 'app', 'access-token')[0].qualifiedArtifactId);
});

test('unowned choices do not receive speculative protection inventory', () => {
  assert.equal(buildProtectionHeldObjects({ model: { id: 'lab-unowned' } }), null);
  assert.equal(PROTLAB_SCENARIOS.length, 7);
  assert.equal(WEBLAB_SCENARIOS.length, 5);
});
