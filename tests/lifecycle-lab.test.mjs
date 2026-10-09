import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { LIFELAB_ATTRIBUTES, LIFELAB_SCENARIOS, LIFELAB_SOURCES } from '../src/lifecycle-lab.js';

Object.assign(ATTRIBUTES, LIFELAB_ATTRIBUTES);
const lifeTestScenario = id => LIFELAB_SCENARIOS.find(model => model.id === id);
const lifeTestSteps = id => lifeTestScenario(id).steps();
const lifeTestStep = (id, key) => lifeTestSteps(id).find(step => step.id === id + '-' + key);
const lifeTestAllSteps = LIFELAB_SCENARIOS.flatMap(model => model.steps());
const lifeTestAllOps = lifeTestAllSteps.flatMap(step => step.attributeOperations);
const lifeTestWireActions = (step, attributeId) => step.attributeOperations.filter(action => action.attributeId === attributeId && ['send', 'receive'].includes(action.kind));
const lifeTestHas = (step, attributeId, kind, actorId) => step.attributeOperations.some(action => action.attributeId === attributeId && action.kind === kind && (!actorId || action.actorId === actorId));

test('nine lifecycle stories expose primary sources, applicable policy and precise immutable scenario data', () => {
  assert.equal(LIFELAB_SCENARIOS.length, 9);
  assert.equal(new Set(LIFELAB_SCENARIOS.map(model => model.id)).size, 9);
  assert.equal(new Set(lifeTestAllSteps.map(step => step.id)).size, lifeTestAllSteps.length);
  for (const model of LIFELAB_SCENARIOS) {
    for (const key of ['id', 'title', 'summary', 'category', 'status', 'supportNote', 'source', 'architecture', 'protocol']) assert.ok(model[key], model.id + ':' + key);
    assert.equal(model.universalLab, true);
    assert.equal(model.factorSelectable, false);
    assert.equal(model.jweAdaptable, false);
    assert.ok(model.steps().length >= 6 && model.steps().length <= 16, model.id + ' scope');
    assert.equal(model.steps(), model.steps({ mode: 'password-totp', authenticator: 'yubikey', architecture: 'native' }), 'Fixed story ignores unrelated factor/deployment choices');
    assert.ok(Object.isFrozen(model.steps()));
    assert.ok(Object.isFrozen(model.steps()[0].attributeOperations));
    assert.throws(() => model.steps().push({}), TypeError);
    const actors = model.actors();
    for (const step of model.steps()) {
      assert.ok(actors[step.from], step.id + ' sender actor');
      assert.ok(actors[step.to], step.id + ' recipient actor');
      assert.ok(step.title && step.summary && step.detail);
      assert.ok(Array.isArray(step.attributeOperations) && step.attributeOperations.length, step.id + ' authoritative ledger');
      assert.ok(Object.isFrozen(step.payload));
      assert.ok(Object.isFrozen(step.attributeValues));
      for (const operation of step.attributeOperations) {
        assert.ok(actors[operation.actorId], step.id + ' operation actor');
        assert.match(operation.attributeId, /^life/);
        assert.ok(LIFELAB_ATTRIBUTES[operation.attributeId], step.id + ': ' + operation.attributeId);
        assert.ok(operation.detail);
      }
      for (const payload of step.payload) if (payload.attributeId) {
        assert.ok(step.fields.includes(payload.attributeId), step.id + ' payload has contextual field ' + payload.attributeId);
        assert.equal(payload.name, LIFELAB_ATTRIBUTES[payload.attributeId].name);
        assert.equal(step.attributeValues[payload.attributeId], payload.value);
      }
    }
  }
  for (const source of LIFELAB_SOURCES) assert.match(source.url, /^https:\/\/(www\.)?(rfc-editor\.org|openid\.net|keycloak\.org)\//);
});

test('all lifecycle attributes carry canonical names and have genuine explicit operations in at least one story', () => {
  const used = new Set(LIFELAB_SCENARIOS.flatMap(model => model.ids));
  for (const [id, definition] of Object.entries(LIFELAB_ATTRIBUTES)) {
    assert.ok(used.has(id), id + ' no unused placeholder');
    for (const key of ['name', 'meaning', 'origin', 'purpose', 'example', 'standard', 'source']) assert.ok(definition[key], id + ':' + key);
    assert.match(definition.source, /^https:\/\/(www\.)?(rfc-editor\.org|openid\.net|keycloak\.org)\//);
    assert.ok(LIFELAB_SCENARIOS.some(model => getAttributeUsage(model.steps(), id).length), id + ' lifecycle is animated');
  }
  assert.equal(LIFELAB_ATTRIBUTES.lifeRevokeToken.name, 'token');
  assert.equal(LIFELAB_ATTRIBUTES.lifeRefreshToken.name, 'refresh_token');
  assert.equal(LIFELAB_ATTRIBUTES.lifeOfflineToken.name, 'refresh_token');
  assert.equal(LIFELAB_ATTRIBUTES.lifeLogoutToken.name, 'logout_token');
  assert.equal(LIFELAB_ATTRIBUTES.lifePostLogoutRedirect.name, 'post_logout_redirect_uri');
});

test('private keys and provider-local grant/session/policy records never become wire attributes', () => {
  const local = ['lifePrivateSigningKey', 'lifePublicSigningKey', 'lifeRotationPolicy', 'lifeRotationState', 'lifeOriginalIdentity', 'lifeOfflineSession', 'lifeOfflinePolicy', 'lifeSsoSession', 'lifeSessionPolicy', 'lifeAppSession', 'lifeSessionMap', 'lifeReplayCache', 'lifeRevocationState', 'lifeApiRevocationPolicy', 'lifeExistingConsent', 'lifeExpiryDecision', 'lifeNonceAbsence'];
  for (const id of local) {
    assert.equal(lifeTestAllOps.some(action => action.attributeId === id && ['send', 'receive'].includes(action.kind)), false, id + ' stays local');
    for (const model of LIFELAB_SCENARIOS) {
      const usage = getAttributeUsage(model.steps(), id);
      assert.equal(usage.some(item => item.wireAttributeIds.includes(id)), false);
      for (const trace of buildAttributeTrace(usage)) assert.equal(trace.from, trace.to, id + ' focus animation remains local');
    }
  }
  for (const action of lifeTestAllOps.filter(action => action.attributeId === 'lifeClientSecret' && ['send', 'receive'].includes(action.kind))) {
    assert.ok(['app', 'realmA'].includes(action.actorId));
    assert.equal(action.carriedAs, 'Authorization: Basic over HTTPS');
  }
  for (const step of lifeTestAllSteps.filter(step => [step.from, step.to].includes('browser'))) assert.equal(lifeTestWireActions(step, 'lifeClientSecret').length, 0, step.id + ' secret never in browser');
});

test('online refresh authenticates the original client and preserves identity rather than generating a new login', () => {
  const id = 'lab-refresh-rotation', steps = lifeTestSteps(id), request = lifeTestStep(id, 'request'), prior = lifeTestStep(id, 'prior');
  assert.ok(lifeTestHas(prior, 'lifeRefreshToken', 'store', 'app'));
  assert.equal(lifeTestHas(prior, 'lifeRefreshToken', 'create', 'app'), false, 'Client does not create its own refresh token');
  assert.equal(request.attributeValues.lifeGrant, 'refresh_token');
  assert.equal(request.channel, 'backchannel');
  assert.ok(lifeTestHas(request, 'lifeRefreshToken', 'send', 'app'));
  assert.ok(lifeTestHas(request, 'lifeClientSecret', 'receive', 'realmA'));
  const check = lifeTestStep(id, 'check');
  for (const field of ['lifeRefreshToken', 'lifeClientId', 'lifeClientSecret', 'lifeScope', 'lifeSsoSession', 'lifeSessionPolicy', 'lifeRotationPolicy']) assert.ok(lifeTestHas(check, field, 'verify', 'realmA'));
  const issue = lifeTestStep(id, 'issue');
  assert.match(issue.detail, /does not require an ID token/);
  assert.match(issue.detail, /auth_time remains the original/);
  assert.match(issue.detail, /omits nonce/);
  assert.ok(lifeTestHas(issue, 'lifeAuthTime', 'use', 'realmA'));
  for (const unused of ['lifeNonce', 'lifeVerifier', 'lifeChallenge', 'lifeState', 'lifeCode', 'lifeConsent']) assert.equal(getAttributeUsage(steps, unused).length, 0, unused + ' no new browser sign-in');
  const response = lifeTestStep(id, 'response');
  for (const action of response.attributeOperations.filter(action => action.attributeId.startsWith('lifeId') && action.attributeId !== 'lifeIdToken')) assert.equal(action.carriedAs, 'id_token → signed JWT claims');
  assert.ok(lifeTestHas(lifeTestStep(id, 'replace'), 'lifeReplacementRefresh', 'store', 'app'));
});

test('configured refresh rotation consumes R0, issues R1 and returns invalid_grant for the queued old-token branch', () => {
  const id = 'lab-refresh-rotation';
  assert.ok(lifeTestHas(lifeTestStep(id, 'check'), 'lifeRotationState', 'store', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'issue'), 'lifeReplacementRefresh', 'create', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'reuse'), 'lifeRefreshToken', 'send', 'app'));
  assert.equal(lifeTestHas(lifeTestStep(id, 'reuse'), 'lifeReplacementRefresh', 'send'), false);
  assert.ok(lifeTestHas(lifeTestStep(id, 'reject'), 'lifeRotationState', 'verify', 'realmA'));
  for (const field of ['lifeClientId', 'lifeClientSecret']) assert.ok(lifeTestHas(lifeTestStep(id, 'reject'), field, 'verify', 'realmA'), field + ' authenticated before old-token rejection');
  assert.match(lifeTestStep(id, 'reject').detail, /depends on the product\/configured policy/);
  const error = lifeTestStep(id, 'error');
  assert.equal(error.attributeValues.lifeTokenError, 'invalid_grant');
  assert.equal(error.payload.some(member => ['access_token', 'refresh_token', 'id_token'].includes(member.name)), false);
  assert.deepEqual([...new Set(error.attributeOperations.map(action => action.attributeId))], ['lifeTokenError']);
});

test('offline access obtains explicit consent through code flow and keeps verifier/refresh credentials off the browser', () => {
  const id = 'lab-offline-access', steps = lifeTestSteps(id);
  assert.equal(steps.length, 12);
  const open = lifeTestStep(id, 'open');
  assert.equal(open.attributeValues.lifeScope, 'openid offline_access orders.read');
  assert.equal(open.attributeValues.lifeOfflinePrompt, 'consent');
  assert.equal(open.payload.filter(member => member.name === 'scope').length, 1, 'One scope query member');
  assert.ok(lifeTestHas(lifeTestStep(id, 'approve'), 'lifeConsent', 'create', 'user'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'accept'), 'lifeConsent', 'verify', 'realmA'));
  assert.equal(lifeTestStep(id, 'redeem').attributeValues.lifeGrant, 'authorization_code');
  assert.ok(lifeTestHas(lifeTestStep(id, 'redeem'), 'lifeVerifier', 'send', 'app'));
  for (const step of steps.filter(step => [step.from, step.to].includes('browser'))) {
    for (const field of ['lifeVerifier', 'lifeClientSecret', 'lifeOfflineToken', 'lifeOfflineReplacement']) assert.equal(lifeTestWireActions(step, field).length, 0, step.id + ':' + field);
  }
  const issue = lifeTestStep(id, 'issue');
  assert.ok(lifeTestHas(issue, 'lifeOfflineSession', 'create', 'realmA'));
  assert.ok(lifeTestHas(issue, 'lifeOfflineToken', 'receive', 'app'));
  assert.ok(lifeTestHas(issue, 'lifeOfflineToken', 'store', 'app'));
  assert.ok(lifeTestHas(issue, 'lifeNonce', 'verify', 'app'));
  assert.equal(lifeTestWireActions(issue, 'lifeOfflineSession').length, 0);
});

test('later offline refresh uses independent bounded sessions and the selected rotation response can omit id_token', () => {
  const id = 'lab-offline-access', later = lifeTestStep(id, 'refresh-later'), result = lifeTestStep(id, 'replacement');
  assert.equal(later.attributeValues.lifeGrant, 'refresh_token');
  assert.ok(lifeTestHas(later, 'lifeOfflineToken', 'send', 'app'));
  for (const field of ['lifeClientId', 'lifeClientSecret', 'lifeOfflineSession', 'lifeOfflinePolicy', 'lifeRotationPolicy']) assert.ok(lifeTestHas(later, field, 'verify', 'realmA'));
  assert.match(later.detail, /ordinary browser SSO session has ended/);
  assert.match(later.detail, /Offline Session Idle\/Max Limited/);
  assert.ok(lifeTestHas(result, 'lifeOfflineReplacement', 'create', 'realmA'));
  assert.ok(lifeTestHas(result, 'lifeOfflineReplacement', 'store', 'app'));
  assert.equal(result.payload.some(member => member.name === 'id_token'), false);
  assert.match(result.detail, /omits an ID token/);
  assert.match(LIFELAB_ATTRIBUTES.lifeOfflineToken.purpose, /not immortal/);
});

test('RFC7009 uses token/hint body fields and the same normal 200 for valid or unknown credentials', () => {
  const id = 'lab-token-revocation', request = lifeTestStep(id, 'request');
  assert.equal(request.payload.some(member => member.name === 'grant_type' || member.name === 'refresh_token'), false);
  assert.equal(request.attributeValues.lifeTokenTypeHint, 'refresh_token');
  assert.ok(request.payload.some(member => member.name === 'token'));
  assert.ok(lifeTestHas(request, 'lifeClientSecret', 'send', 'app'));
  for (const key of ['ok', 'unknown-ok']) {
    const step = lifeTestStep(id, key);
    assert.equal(step.attributeValues.lifeHttpStatus, '200 OK');
    assert.deepEqual(step.payload.map(member => member.name), ['HTTP status code']);
    assert.equal(step.payload.some(member => member.name === 'exists'), false);
  }
  assert.equal(lifeTestStep(id, 'unknown').attributeValues.lifeRevokeToken, 'unknown-value');
  assert.ok(lifeTestHas(lifeTestStep(id, 'unknown-check'), 'lifeClientSecret', 'verify', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'invalidate'), 'lifeRevocationState', 'store', 'realmA'));
  const api = lifeTestScenario(id).actors().realmB;
  assert.equal(api.role, 'Resource server');
  assert.match(lifeTestStep(id, 'api-caveat').detail, /does not demonstrate instant API denial/);
  assert.equal(getAttributeUsage(lifeTestSteps(id), 'lifeIdToken').length, 0, 'No ID token becomes an API credential');
});

test('RP logout uses independent state, a provider-issued hint and an exactly registered post-logout destination', () => {
  const id = 'lab-rp-initiated-logout', steps = lifeTestSteps(id);
  assert.ok(lifeTestHas(lifeTestStep(id, 'prepare'), 'lifeAppSession', 'store', 'app'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'prepare'), 'lifeLogoutState', 'create', 'app'));
  for (const key of ['open', 'request']) for (const field of ['lifeIdTokenHint', 'lifeClientId', 'lifePostLogoutRedirect', 'lifeLogoutState']) assert.ok(lifeTestWireActions(lifeTestStep(id, key), field).length);
  assert.ok(lifeTestHas(lifeTestStep(id, 'check'), 'lifePostLogoutRedirect', 'verify', 'realmA'));
  assert.match(lifeTestStep(id, 'check').detail, /valid expired ID-token hint can still be acceptable/);
  assert.match(lifeTestStep(id, 'check').detail, /mandatory when the hint is absent or mismatched/);
  assert.ok(lifeTestHas(lifeTestStep(id, 'end'), 'lifeSsoSession', 'store', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'redirect'), 'lifeSetCookie', 'send', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'finish'), 'lifeLogoutState', 'verify', 'app'));
  for (const field of ['lifeCode', 'lifeState', 'lifeRefreshToken', 'lifeGrant', 'lifeNonce', 'lifeVerifier', 'lifeLogoutToken']) assert.equal(getAttributeUsage(steps, field).length, 0, field + ' not confused with RP logout');
  assert.match(lifeTestStep(id, 'end').detail, /offline grants have their own rules/);
});

test('current-spec backchannel notification includes exp/events/sid or sub, prohibits nonce and keeps claims nested', () => {
  const id = 'lab-backchannel-logout', steps = lifeTestSteps(id), sign = lifeTestStep(id, 'sign'), notify = lifeTestStep(id, 'notify'), validate = lifeTestStep(id, 'validate');
  const required = ['lifeLogoutIssuer', 'lifeLogoutAudience', 'lifeLogoutIssuedAt', 'lifeLogoutExpiresAt', 'lifeLogoutJti', 'lifeLogoutEvents', 'lifeSid', 'lifeLogoutSubject'];
  for (const field of required) {
    assert.ok(lifeTestHas(sign, field, 'create', 'realmA'));
    assert.ok(lifeTestHas(notify, field, 'send', 'realmA'));
    assert.ok(lifeTestHas(validate, field, 'verify', 'app'));
  }
  assert.equal(notify.channel, 'backchannel');
  assert.equal(notify.payload.filter(member => member.name === 'logout_token').length, 1);
  for (const action of notify.attributeOperations.filter(action => action.attributeId !== 'lifeLogoutToken')) assert.equal(action.carriedAs, 'logout_token → JWS');
  assert.ok(lifeTestHas(validate, 'lifeNonceAbsence', 'verify', 'app'));
  assert.ok(lifeTestHas(validate, 'lifeLogoutTyp', 'verify', 'app'));
  assert.match(LIFELAB_ATTRIBUTES.lifeLogoutTyp.purpose, /legacy profiles may omit/);
  assert.equal(getAttributeUsage(steps, 'lifeNonce').length, 0, 'No nonce claim is invented');
  assert.equal(steps.some(step => [step.from, step.to].includes('browser')), false, 'Backchannel does not depend on a browser');
});

test('each backchannel RP gets a newly signed audience-specific event and uses an explicit optional replay cache', () => {
  const id = 'lab-backchannel-logout', second = lifeTestStep(id, 'second');
  assert.equal(second.to, 'realmB');
  assert.equal(second.attributeValues.lifeLogoutAudience, 'second-rp');
  assert.ok(lifeTestHas(second, 'lifePrivateSigningKey', 'use', 'realmA'));
  assert.ok(lifeTestHas(second, 'lifeLogoutSignature', 'derive', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'second-apply'), 'lifeLogoutAudience', 'verify', 'realmB'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'second-apply'), 'lifeAppSession', 'store', 'realmB'));
  assert.match(lifeTestScenario(id).actors().realmB.notes.join(' '), /not another identity realm/);
  assert.match(lifeTestStep(id, 'session').detail, /replay checking optional/);
  assert.ok(lifeTestHas(lifeTestStep(id, 'session'), 'lifeReplayCache', 'store', 'app'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'duplicate-check'), 'lifeReplayCache', 'verify', 'app'));
  assert.equal(lifeTestHas(lifeTestStep(id, 'duplicate-check'), 'lifeAppSession', 'create'), false);
});

test('frontchannel uses browser iframe GETs with paired iss/sid and an explicit policy-dependent storage failure', () => {
  const id = 'lab-frontchannel-logout', steps = lifeTestSteps(id);
  assert.equal(getAttributeUsage(steps, 'lifeLogoutToken').length, 0, 'No fictional signed logout token on iframe URLs');
  assert.equal(getAttributeUsage(steps, 'lifeLogoutSignature').length, 0);
  for (const key of ['first-get', 'second-get']) {
    const step = lifeTestStep(id, key);
    assert.equal(step.from, 'browser');
    assert.ok(lifeTestHas(step, 'lifeLogoutIssuer', 'send', 'browser'));
    assert.ok(lifeTestHas(step, 'lifeSid', 'send', 'browser'));
    assert.match(step.payload.find(member => member.name === 'HTTP').value, /^GET /);
  }
  assert.ok(lifeTestHas(lifeTestStep(id, 'first-get'), 'lifeAppCookie', 'send', 'browser'));
  assert.equal(lifeTestWireActions(lifeTestStep(id, 'second-get'), 'lifeAppCookie').length, 0, 'Blocked branch sends no fictional Cookie');
  assert.ok(lifeTestHas(lifeTestStep(id, 'first-clear'), 'lifeAppSession', 'store', 'app'));
  assert.ok(lifeTestStep(id, 'first-response').payload.some(member => member.name === 'Cache-Control' && member.value === 'no-store'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'blocked'), 'lifeLogoutCompletion', 'create', 'browser'));
  assert.match(lifeTestStep(id, 'blocked').detail, /does not magically see or clear/);
  assert.equal(lifeTestHas(lifeTestStep(id, 'blocked'), 'lifeAppSession', 'store'), false, 'No claim of guaranteed second-RP clear');
});

test('prompt=none success still performs code/PKCE validation and preserves the earlier authentication time', () => {
  const id = 'lab-sso-existing-session', steps = lifeTestSteps(id), prepare = lifeTestStep(id, 'prepare');
  assert.equal(prepare.attributeValues.lifeSilentPrompt, 'none');
  for (const field of ['lifeState', 'lifeNonce', 'lifeVerifier']) assert.ok(lifeTestHas(prepare, field, 'create', 'app'));
  assert.ok(lifeTestHas(prepare, 'lifeChallenge', 'derive', 'app'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'check'), 'lifeSsoSession', 'verify', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'check'), 'lifeExistingConsent', 'verify', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'redeem'), 'lifeVerifier', 'send', 'app'));
  const tokens = lifeTestStep(id, 'tokens');
  assert.ok(lifeTestHas(tokens, 'lifeAuthTime', 'use', 'realmA'));
  assert.ok(lifeTestHas(tokens, 'lifeNonce', 'send', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'validate'), 'lifeNonce', 'verify', 'app'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'validate'), 'lifeAppSession', 'create', 'app'));
  assert.equal(getAttributeUsage(steps, 'lifeAuthorizationError').length, 0);
  assert.equal(steps.some(step => ['passkey', 'password', 'otp', 'mfa'].includes(step.phase)), false, 'No newly performed factor is invented');
  for (const step of steps.filter(step => [step.from, step.to].includes('browser'))) assert.equal(lifeTestWireActions(step, 'lifeVerifier').length, 0);
});

test('missing-session prompt=none produces only login_required/state and never a code or tokens', () => {
  const id = 'lab-sso-login-required', steps = lifeTestSteps(id);
  assert.equal(lifeTestStep(id, 'prepare').attributeValues.lifeSilentPrompt, 'none');
  assert.equal(lifeTestWireActions(lifeTestStep(id, 'request'), 'lifeProviderCookie').length, 0);
  assert.equal(lifeTestStep(id, 'fail').attributeValues.lifeAuthorizationError, 'login_required');
  assert.ok(lifeTestHas(lifeTestStep(id, 'redirect'), 'lifeAuthorizationError', 'send', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'callback'), 'lifeState', 'verify', 'app'));
  for (const field of ['lifeCode', 'lifeAccessToken', 'lifeIdToken', 'lifeAppSession', 'lifeRefreshToken']) assert.equal(getAttributeUsage(steps, field).length, 0, field + ' no false success');
  assert.match(lifeTestStep(id, 'fail').detail, /displays no login\/consent page/);
  assert.match(lifeTestStep(id, 'next').detail, /new authorization transaction/);
});

test('session expiry rejects ordinary refresh while keeping access-token and offline grant semantics distinct', () => {
  const id = 'lab-session-expiry';
  assert.ok(lifeTestHas(lifeTestStep(id, 'deadline'), 'lifeExpiryDecision', 'derive', 'realmA'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'deadline'), 'lifeSsoSession', 'store', 'realmA'));
  assert.match(lifeTestStep(id, 'deadline').detail, /does not remove an absolute Max deadline/);
  assert.ok(lifeTestHas(lifeTestStep(id, 'request'), 'lifeClientSecret', 'send', 'app'));
  assert.ok(lifeTestHas(lifeTestStep(id, 'reject'), 'lifeExpiryDecision', 'verify', 'realmA'));
  const error = lifeTestStep(id, 'error');
  assert.equal(error.attributeValues.lifeTokenError, 'invalid_grant');
  assert.equal(error.payload.some(member => ['access_token', 'id_token', 'refresh_token'].includes(member.name)), false);
  assert.match(error.detail, /their own expiry\/status rules/);
  assert.equal(getAttributeUsage(lifeTestSteps(id), 'lifeOfflineToken').length, 0);
  assert.ok(lifeTestHas(lifeTestStep(id, 'recover'), 'lifeAppSession', 'store', 'app'));
  assert.equal(lifeTestSteps(id).some(step => lifeTestHas(step, 'lifeAccessToken', 'create')), false, 'Expiry failure issues no new access token');
});

test('scenario ledgers remain authoritative for focused traces rather than reviving old default realm fields', () => {
  for (const model of LIFELAB_SCENARIOS) {
    for (const step of model.steps()) assert.deepEqual(getStepAttributeOperations(step), step.attributeOperations);
    for (const old of ['clientIdApp', 'clientSecret', 'codeVerifier', 'nonceApp', 'stateApp', 'idTokenA', 'issuerA', 'accessTokenA', 'refreshToken', 'session']) assert.equal(getAttributeUsage(model.steps(), old).length, 0, model.id + ':' + old);
    const actors = model.actors();
    for (const actor of Object.values(actors)) {
      assert.equal(new Set(actor.attributes.map(attribute => attribute.id)).size, actor.attributes.length);
      for (const attribute of actor.attributes) assert.match(attribute.id, /^life/);
    }
  }
});
