import test from 'node:test';
import assert from 'node:assert/strict';
import {ADLAB_SCENARIOS} from '../src/kerberos-ad-lab.js';
import {buildADHeldObjects} from '../src/held-object-ad.js';
import {compileHeldObjects, projectHeldObjects, inspectHeldObject, assertHeldObjectCoverage, heldObjectTrace} from '../src/held-object-state.js';

const scenario = id => ADLAB_SCENARIOS.find(model => model.id === id);
function fixture(model, revision = 'revision-1') {
  const steps = model.steps();
  const plan = buildADHeldObjects({model, steps, actors: model.actors(), config: {}, contextId: model.id + ':held-test:' + revision, choiceId: model.id});
  const compiled = compileHeldObjects(plan, {model, steps});
  const index = suffix => steps.findIndex(step => step.id === model.id + '-' + suffix);
  const frame = (suffix, milestone = 'complete') => projectHeldObjects(compiled, {eventIndex: index(suffix), milestone});
  return {model, steps, plan, compiled, index, frame, initial: () => projectHeldObjects(compiled, {eventIndex: -1, milestone: 'initial'}), final: () => projectHeldObjects(compiled, {eventIndex: steps.length - 1, milestone: 'complete'})};
}
const holding = (snapshot, artifactId, actorId, store) => snapshot.holdings.find(item => item.artifactId === artifactId && item.actorId === actorId && (!store || item.store === store));
const definition = (snapshot, id) => snapshot.artifacts.find(item => item.artifactId === id);
const observed = (snapshot, id, actor, kind) => snapshot.observations.filter(item => item.artifactId === id && item.actorId === actor && (!kind || item.kind === kind));
const inspected = (snapshot, id, actor, store) => inspectHeldObject(snapshot, holding(snapshot, id, actor, store).holdingId);

test('A21: all 27 AD and bridge choices compile with complete logical actor/store/category coverage and no final scratch holdings', () => {
  assert.equal(ADLAB_SCENARIOS.length, 27);
  for (const model of ADLAB_SCENARIOS) {
    const f = fixture(model);
    assert.doesNotThrow(() => assertHeldObjectCoverage(f.compiled), model.id);
    assert.deepEqual(new Set(f.plan.coverage.map(record => record.actorId)), new Set(Object.keys(model.actors())));
    assert.ok(f.plan.coverage.every(record => record.status === 'complete' && record.support === 'supported' && record.gaps.length === 0));
    assert.ok(f.final().holdings.every(item => item.retention === 'retained'), model.id);
    assert.ok(f.plan.bindings.some(binding => binding.path === 'credentials.unrelated'));
    assert.ok(f.plan.bindings.some(binding => binding.path === 'credentials.tgt'));
    for (let index = -1; index < f.steps.length; index++) {
      const cursor = index < 0 ? {eventIndex: -1, milestone: 'initial'} : {eventIndex: index, milestone: 'complete'};
      const snapshot = projectHeldObjects(f.compiled, cursor);
      assert.equal(snapshot.contextId, f.plan.contextId);
      assert.ok(holding(snapshot, 'credential:unrelated:01', 'adWorkstation'), model.id + ' unrelated credential retained');
    }
  }
  assert.equal(buildADHeldObjects({model: null}), null);
  assert.equal(buildADHeldObjects({model: {family: 'not-ad'}}), null);
});

test('A02/A19: cold user start retains independent configured keys and unrelated cache, while AS/TGS keep exact logical ownership', () => {
  const f = fixture(scenario('lab-ad-first-sign-in'));
  const start = f.initial();
  assert.equal(holding(start, 'ticket:tgt:01', 'adWorkstation'), undefined);
  assert.equal(holding(start, 'ticket:service:01', 'adWorkstation'), undefined);
  assert.equal(holding(start, 'ticket:host:01', 'adWorkstation'), undefined);
  assert.ok(holding(start, 'key:machine:ws01', 'adWorkstation', 'machine-account'));
  assert.ok(holding(start, 'key:user:alice:aes256', 'adAs', 'account-keys'));
  assert.ok(holding(start, 'key:krbtgt:A.EXAMPLE', 'adTgs', 'account-keys'));
  assert.ok(holding(start, 'key:krbtgt:A.EXAMPLE', 'adKdc', 'directory'));
  const unrelated = definition(start, 'credential:unrelated:01');
  assert.equal(unrelated.expiresAt, undefined);
  const unrelatedFields = inspected(start, unrelated.artifactId, 'adWorkstation').fields;
  assert.equal(unrelatedFields.find(field => field.attributeId === 'target').value, 'ldap/dc01.a.example');
  assert.equal(unrelatedFields.find(field => field.attributeId === 'validity').value, 'not specified by fixture');
  assert.equal(definition(f.frame('as-create'), 'ticket:tgt:01').creator, 'adAs');
  assert.equal(definition(f.frame('service-tgs-create'), 'ticket:service:01').creator, 'adTgs');
  assert.ok(holding(f.frame('local-logon'), 'session:local-logon', 'adWorkstation', 'sessions'));
});

for (const [scenarioId, event, artifactId, actorId, attributeId, expected] of [
  ['lab-ad-first-sign-in', 'password', 'password:domain', 'adWorkstation', 'adPassword', '<local password>'],
  ['lab-ad-first-sign-in', 'select-key', 'key:user:alice:aes256', 'adWorkstation', 'adUserKey', 'key:user:alice:aes256'],
  ['lab-kc-kerberos-sso', 'token-request', 'verifier:corporate:01', 'adKeycloak', 'adVerifier'],
  ['lab-kc-password-fresh-totp', 'password-fallback', 'password:provider', 'adBrowser', 'adPassword', '<provider password>'],
  ['lab-kc-password-fresh-totp', 'password-submit', 'password:provider', 'adKeycloak', 'adPassword', '<provider password>'],
  ['lab-kc-low-assurance-cookie', 'authorize', 'cookie:provider:earlier', 'adKeycloak', 'adCookie', 'KC-session=<opaque handle>'],
]) test('HC03: ' + scenarioId + '/' + event + ' permits inspection only after legitimate acquisition', () => {
  const f = fixture(scenario(scenarioId));
  assert.equal(holding(f.initial(), artifactId, actorId), undefined);
  const before = f.frame(event, 'before');
  assert.equal(holding(before, artifactId, actorId), undefined, 'reader permission alone never acquires the object');
  const delivered = f.frame(event);
  const inspection = inspected(delivered, artifactId, actorId);
  assert.equal(inspection.representation.readable, true);
  const field = inspection.fields.find(item => item.attributeId === attributeId);
  assert.equal(field.readable, true);
  assert.equal(field.redacted, undefined);
  const authored = definition(delivered, artifactId).representations.find(rep => rep.representationId === 'plain').fields.find(item => item.attributeId === attributeId);
  assert.equal(field.value, expected ?? authored.value);
  assert.notEqual(field.value, undefined);
  assert.deepEqual(f.frame(event, 'before'), before, 'rewind cannot retain a later acquisition');
});

test('HC03: explicit secret readers do not expose backend verifiers or protected Kerberos inner fields to transport holders', () => {
  const f = fixture(scenario('lab-kc-kerberos-sso'));
  for (let eventIndex = -1; eventIndex < f.steps.length; eventIndex++) {
    const snapshot = projectHeldObjects(f.compiled, {eventIndex, milestone: eventIndex < 0 ? 'initial' : 'complete'});
    assert.equal(holding(snapshot, 'verifier:corporate:01', 'adBrowser'), undefined);
    assert.equal(holding(snapshot, 'key:user:alice:aes256', 'adBrowser'), undefined);
    assert.equal(holding(snapshot, 'key:service-session:01', 'adBrowser'), undefined);
  }
  const carried = f.frame('gss-token');
  const ticket = inspected(carried, 'ticket:service:01', 'adBrowser');
  assert.equal(ticket.representation.representationId, 'opaque');
  for (const attributeId of ['adCName', 'adPAC', 'sessionKeyInstanceId']) {
    assert.equal(ticket.fields.some(field => field.attributeId === attributeId), false);
  }
  const proof = inspected(carried, 'authenticator:http:01', 'adBrowser');
  assert.equal(proof.representation.representationId, 'opaque');
  assert.deepEqual(proof.fields, []);
  const cold = fixture(scenario('lab-ad-first-sign-in'));
  const reply = inspected(cold.frame('as-reply'), 'reply:as:01', 'adWorkstation');
  assert.equal(reply.representation.representationId, 'opaque');
  assert.equal(reply.fields.some(field => field.attributeId === 'sessionKeyInstanceId'), false);
  assert.equal(holding(cold.frame('as-reply'), 'key:tgt-session:01', 'adWorkstation'), undefined);
});

test('A02/A04/A05: AS and TGS issuance, ciphertext receipt, decrypt/check and accepted cache are distinct atomic boundaries', () => {
  const f = fixture(scenario('lab-ad-first-sign-in'));
  for (const [kind, create, reply, cache] of [['tgt', 'as-create', 'as-reply', 'cache-tgt'], ['host', 'host-tgs-create', 'host-tgs-reply', 'host-cache'], ['service', 'service-tgs-create', 'service-tgs-reply', 'service-cache']]) {
    const ticket = 'ticket:' + kind + ':01';
    const key = kind === 'tgt' ? 'key:tgt-session:01' : 'key:' + kind + '-session:01';
    const issued = f.frame(create);
    assert.equal(holding(issued, ticket, 'adWorkstation'), undefined, 'issuance is not delivery');
    assert.equal(holding(f.frame(reply, 'before'), ticket, 'adWorkstation'), undefined);
    const arrived = f.frame(reply);
    assert.equal(holding(arrived, ticket, 'adWorkstation').store, 'reply-inbox');
    assert.equal(holding(arrived, key, 'adWorkstation'), undefined, 'no plaintext session key before protected reply check');
    assert.equal(arrived.state.credentials[kind], undefined);
    const checked = f.frame(cache);
    assert.ok(holding(checked, ticket, 'adWorkstation', 'credential-cache:' + kind));
    assert.ok(holding(checked, key, 'adWorkstation', 'credential-cache:' + kind));
    assert.equal(holding(checked, ticket, 'adWorkstation').holdingId, holding(arrived, ticket, 'adWorkstation').holdingId, 'promotion preserves holding identity');
    assert.equal(holding(checked, ticket, 'adWorkstation').retention, 'retained');
    assert.equal(checked.state.credentials[kind].ticketInstanceId, ticket);
    assert.equal(inspected(checked, ticket, 'adWorkstation').fields.some(field => field.attributeId === 'sessionKeyInstanceId'), false, 'opaque ticket inspector cannot expose protected ticket session material');
    assert.ok(observed(checked, ticket, 'adWorkstation', 'acceptance').length);
    assert.equal(f.plan.events[f.model.id + '-' + reply].messages.length, 1, 'one authored message, not per-field deliveries');
  }
  const sent = f.frame('ap-request');
  assert.ok(holding(sent, 'ticket:service:01', 'adWorkstation', 'credential-cache:service'), 'sending does not move the retained sender ticket');
  assert.ok(holding(sent, 'ticket:service:01', 'adService', 'request'));
  assert.equal(holding(sent, 'ticket:tgt:01', 'adService'), undefined);
});

test('A02: seeded TGT and service caches reuse their exact identities without fabricating missing AS/TGS exchanges', () => {
  for (const [id, cachedService] of [['lab-ad-cache-tgt', false], ['lab-ad-cache-service', true]]) {
    const f = fixture(scenario(id));
    assert.ok(holding(f.initial(), 'ticket:tgt:01', 'adWorkstation', 'credential-cache:tgt'));
    assert.equal(!!holding(f.initial(), 'ticket:service:01', 'adWorkstation'), cachedService);
    assert.equal(f.index('as-create'), -1);
    assert.equal(f.index('service-tgs-create') >= 0, !cachedService);
    assert.equal(holding(f.initial(), 'authenticator:ap:01', 'adWorkstation'), undefined);
    assert.ok(holding(f.frame('ap-create'), 'authenticator:ap:01', 'adWorkstation'));
    assert.equal(holding(f.final(), 'ticket:tgt:01', 'adWorkstation').artifactId, 'ticket:tgt:01');
  }
});

test('A03/A05/A06: expiry and acceptor rejection retain credentials; knowledge arrives later and resource denial is not credential revocation', () => {
  for (const [id, reason] of [['lab-ad-stale-service-key', 'stale'], ['lab-ad-clock-skew', 'skew'], ['lab-ad-expired-ticket', 'expired'], ['lab-ad-authenticator-replay', 'replay']]) {
    const f = fixture(scenario(id));
    const reject = f.frame('acceptor-reject');
    assert.ok(holding(reject, 'ticket:service:01', 'adWorkstation', 'credential-cache:service'));
    assert.equal(observed(reject, 'ticket:service:01', 'adWorkstation', 'knowledge').length, 0);
    assert.ok(observed(f.frame('acceptor-error'), 'ticket:service:01', 'adWorkstation', 'knowledge').some(item => item.result.includes(reason)));
    assert.equal(f.final().state.sessions.serviceAuthenticated, false);
    assert.equal(f.final().authority.find(item => item.artifactId === 'ticket:service:01')?.status, id === 'lab-ad-stale-service-key' ? 'issued' : 'previously-issued');
    if (reason === 'expired') {
      assert.equal(f.frame('time-advance').protocolClock, 5301);
      assert.equal(inspected(f.final(), 'ticket:service:01', 'adWorkstation').expired, true);
      assert.equal(definition(f.final(), 'ticket:service:01').expiresAt, 5000);
    }
  }
  const denied = fixture(scenario('lab-ad-access-denied'));
  assert.ok(holding(denied.final(), 'context:service:01', 'adService', 'sessions'));
  assert.ok(observed(denied.final(), 'context:service:01', 'adService', 'acceptance').some(item => item.result === 'resource permission denied'));
  assert.ok(holding(denied.final(), 'ticket:service:01', 'adWorkstation'));
  assert.equal(denied.final().state.sessions.serviceAuthenticated, true);
  assert.equal(denied.final().state.sessions.resourceAccess, false);
});

test('A05/A18: unknown SPN cannot invent target credentials and client learns acquisition failure only from the error receipt', () => {
  const f = fixture(scenario('lab-ad-unknown-spn'));
  assert.equal(f.plan.artifacts.some(item => item.artifactId === 'ticket:service:01'), false);
  assert.ok(holding(f.final(), 'ticket:tgt:01', 'adWorkstation'));
  assert.ok(holding(f.final(), 'credential:unrelated:01', 'adWorkstation'));
  assert.equal(f.frame('unknown-spn-check').state.knowledge.adWorkstation.failure, undefined);
  assert.equal(f.frame('unknown-spn-error').state.knowledge.adWorkstation.failure, 'unknown-spn');
});

test('A10: backend PKCE generation, public commitment, direct redemption, single use and transaction discard remain separate', () => {
  const f = fixture(scenario('lab-kc-kerberos-sso'));
  assert.equal(holding(f.initial(), 'verifier:corporate:01', 'adApp'), undefined);
  assert.ok(holding(f.frame('transaction'), 'verifier:corporate:01', 'adApp', 'transaction'));
  assert.deepEqual(definition(f.frame('transaction'), 'challenge:corporate:01').derivedFrom, ['verifier:corporate:01']);
  for (const suffix of ['open-browser', 'authorize', 'code-callback']) {
    const snapshot = f.frame(suffix);
    assert.equal(holding(snapshot, 'verifier:corporate:01', 'adBrowser'), undefined);
    assert.equal(holding(snapshot, 'secret:corporate', 'adBrowser'), undefined);
    assert.equal(holding(snapshot, 'verifier:corporate:01', 'adKeycloak'), undefined);
  }
  assert.ok(holding(f.frame('token-request'), 'verifier:corporate:01', 'adKeycloak', 'token-request'));
  assert.equal(f.frame('token-check').authority.find(item => item.artifactId === 'code:corporate:01').status, 'consumed');
  assert.ok(holding(f.frame('token-check'), 'code:corporate:01', 'adApp'), 'server consumption is not client discard');
  assert.equal(holding(f.frame('token-create'), 'token:id:corporate:01', 'adApp'), undefined);
  assert.ok(holding(f.frame('token-response'), 'token:id:corporate:01', 'adApp', 'token-inbox'));
  assert.equal(holding(f.frame('token-response'), 'session:app:01', 'adApp'), undefined);
  assert.ok(holding(f.final(), 'session:app:01', 'adApp'));
  assert.equal(holding(f.final(), 'verifier:corporate:01', 'adApp'), undefined);
  assert.equal(holding(f.final(), 'token:id:corporate:01', 'adKeycloak'), undefined, 'issuer signing does not imply indefinite token storage');
  assert.ok(holding(f.final(), 'secret:corporate', 'adApp'));
});

test('A05/A14: SPNEGO mechanism success does not pre-accept negotiation or realm assurance, and browser transport never gains session keys', () => {
  for (const id of ['lab-kc-spnego-missing-acceptor-mic', 'lab-kc-spnego-invalid-acceptor-mic']) {
    const f = fixture(scenario(id));
    assert.equal(f.frame('http-accept').state.sessions.gssMechanismAuthenticated, true);
    assert.equal(holding(f.frame('http-accept'), 'context:http:01', 'adKeycloak'), undefined);
    assert.equal(holding(f.final(), 'context:http:01', 'adKeycloak'), undefined);
    assert.equal(holding(f.final(), 'session:app:01', 'adApp'), undefined);
    assert.equal(f.plan.artifacts.some(item => item.artifactId === 'mic:initiator:01'), false);
    assert.equal(holding(f.frame('http-negotiate'), 'key:service-session:01', 'adBrowser'), undefined);
    assert.deepEqual(inspected(f.frame('gss-token'), 'authenticator:http:01', 'adBrowser').fields, []);
  }
  const f = fixture(scenario('lab-kc-kerberos-sso'));
  assert.notEqual(definition(f.final(), 'mic:acceptor:01').artifactId, definition(f.final(), 'mic:initiator:01').artifactId);
  assert.ok(holding(f.frame('spnego-complete'), 'context:http:01', 'adKeycloak'));
});

test('A14: TOTP enrollment, generated code, incorrect input and one-use state have independent lifecycles', () => {
  for (const [id, failed] of [['lab-kc-kerberos-fresh-totp', false], ['lab-kc-factor-failed', true]]) {
    const f = fixture(scenario(id));
    assert.ok(holding(f.initial(), 'secret:totp', 'adFactor'));
    assert.ok(holding(f.initial(), 'secret:totp', 'adKeycloak'));
    assert.equal(holding(f.initial(), 'otp:computed:01', 'adFactor'), undefined);
    assert.ok(holding(f.frame('totp-create'), 'otp:computed:01', 'adFactor'));
    assert.equal(holding(f.frame('totp-submit'), 'secret:totp', 'adBrowser'), undefined);
    assert.equal(!!holding(f.frame('totp-check'), 'replay:totp:33', 'adKeycloak'), !failed);
    assert.equal(holding(f.final(), 'otp:computed:01', 'adFactor'), undefined);
    assert.ok(holding(f.final(), 'secret:totp', 'adFactor'));
    if (failed) {
      assert.ok(definition(f.frame('totp-enter'), 'otp:wrong-input:01'));
      assert.equal(holding(f.final(), 'session:app:01', 'adApp'), undefined);
    }
  }
});

test('A14: WebAuthn private key stays on enrolled device; cancellation creates no assertion and UV rejection cannot create a session', () => {
  for (const [id, cancelled, uvFailed] of [['lab-kc-kerberos-fresh-webauthn', false, false], ['lab-kc-factor-cancelled', true, false], ['lab-kc-webauthn-uv-policy-fail', false, true]]) {
    const f = fixture(scenario(id));
    assert.ok(holding(f.initial(), 'credential:factor:private', 'adFactor'));
    assert.ok(holding(f.initial(), 'credential:factor:public', 'adKeycloak'));
    assert.equal(f.plan.artifacts.some(item => item.artifactId === 'webauthn:assertion:01'), !cancelled);
    for (const actor of ['adBrowser', 'adKeycloak', 'adApp', 'adWorkstation']) assert.equal(holding(f.final(), 'credential:factor:private', actor), undefined);
    assert.equal(!!holding(f.final(), 'session:app:01', 'adApp'), !cancelled && !uvFailed);
    if (uvFailed) assert.ok(observed(f.frame('wa-check'), 'webauthn:assertion:01', 'adKeycloak', 'acceptance').some(item => item.result.includes('UV=false')));
  }
});

test('A18/A21: context regeneration binds actual realm/SPN state; traces and rewind never carry another revision', () => {
  for (const id of ['lab-ad-first-sign-in', 'lab-ad-cache-service', 'lab-kc-kerberos-fresh-totp']) {
    const original = fixture(scenario(id));
    const contextual = scenario(id).contextualize({kerberosRealm: 'CORP.EXAMPLE', servicePrincipal: id.startsWith('lab-kc') ? 'HTTP/login.corp.example' : 'cifs/storage.corp.example'});
    const f = fixture(contextual, 'revision-2');
    const final = f.final();
    assert.notEqual(final.contextId, original.final().contextId);
    const ticket = definition(final, 'ticket:service:01');
    const clear = ticket.representations.find(rep => rep.representationId === 'opaque').fields;
    assert.equal(clear.find(field => field.attributeId === 'adTicketTarget').value, id.startsWith('lab-kc') ? 'HTTP/login.corp.example' : 'cifs/storage.corp.example');
    assert.equal(ticket.representations.find(rep => rep.representationId === 'plain').fields.find(field => field.attributeId === 'adClientRealm').value, 'CORP.EXAMPLE');
    assert.ok(holding(final, 'key:krbtgt:CORP.EXAMPLE', 'adTgs'));
    assert.equal(holding(final, 'key:krbtgt:A.EXAMPLE', 'adTgs'), undefined);
    assert.equal(original.final().state.credentials.tgt.crealm, 'A.EXAMPLE');
    for (const row of heldObjectTrace(f.compiled, 'ticket:service:01')) assert.deepEqual(projectHeldObjects(f.compiled, row.heldCursorEnd), projectHeldObjects(f.compiled, {eventIndex: row.sourceIndex, milestone: row.sourceIndex < 0 ? 'initial' : 'complete'}));
    assert.deepEqual(f.initial(), f.initial(), 'projection is pure after final and trace reads');
  }
});
