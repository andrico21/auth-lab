import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { LIFELAB_ATTRIBUTES, LIFELAB_SCENARIOS } from '../src/lifecycle-lab.js';

Object.assign(ATTRIBUTES, LIFELAB_ATTRIBUTES);
const story = id => LIFELAB_SCENARIOS.find(model => model.id === id);
const step = (id, key) => story(id).steps().find(item => item.id === id + '-' + key);
const action = (item, id, kind, actor) => item.attributeOperations.some(op => op.attributeId === id && op.kind === kind && op.actorId === actor);
const back = key => step('lab-backchannel-logout', key);

// External oracle: OIDC Back-Channel Logout errata set 1 §§2.4-2.8.
// Values below are independent expected recipient/event fixtures, not read from
// the scenario's constructors or computed by its own value helpers.
test('F03: the actual event identifier and audience survive creation, transfer and recipient validation', () => {
  const journeys = [
    { keys: ['sign', 'notify', 'validate', 'session'], aud: 'lifecycle-client', jti: 'logout_event_J0' },
    { keys: ['second', 'second-apply'], aud: 'second-rp', jti: 'logout_event_J1' },
    { keys: ['duplicate', 'duplicate-check'], aud: 'lifecycle-client', jti: 'logout_event_J0' },
    { keys: ['fresh-sign', 'fresh-notify', 'fresh-apply'], aud: 'lifecycle-client', jti: 'logout_event_J2' },
  ];
  for (const { keys, aud, jti } of journeys) for (const key of keys) {
    const item = back(key);
    assert.equal(item.attributeValues.lifeLogoutJti, jti, key + ' jti');
    if (item.fields.includes('lifeLogoutAudience')) assert.equal(item.attributeValues.lifeLogoutAudience, aud, key + ' aud');
    for (const member of item.payload.filter(member => ['lifeLogoutAudience', 'lifeLogoutJti'].includes(member.attributeId))) {
      assert.equal(member.value, member.attributeId === 'lifeLogoutJti' ? jti : aud, key + ' visible message');
    }
  }
  assert.notEqual(back('notify').attributeValues.lifeLogoutToken, back('second').attributeValues.lifeLogoutToken);
  assert.equal(back('notify').attributeValues.lifeLogoutToken, back('duplicate').attributeValues.lifeLogoutToken);
  assert.equal(back('second').attributeValues.lifeLogoutToken, back('second-apply').attributeValues.lifeLogoutToken);
  assert.equal(back('second').attributeValues.lifeLogoutSignature, back('second-apply').attributeValues.lifeLogoutSignature);
});

test('F03: focused jti and audience animations display the checked recipient event rather than a global J0 example', () => {
  for (const [id, expected] of [['lifeLogoutJti', 'logout_event_J1'], ['lifeLogoutAudience', 'second-rp']]) {
    const trace = buildAttributeTrace(getAttributeUsage(story('lab-backchannel-logout').steps(), id));
    const delivery = trace.filter(frame => frame.sourceStepId.endsWith('-second'));
    const validation = trace.filter(frame => frame.sourceStepId.endsWith('-second-apply'));
    assert.ok(delivery.some(frame => frame.traceKind === 'send' && frame.to === 'realmB'));
    assert.ok(validation.some(frame => frame.traceKind === 'verify' && frame.from === 'realmB'));
    for (const frame of [...delivery, ...validation]) assert.equal(frame.payload.find(member => member.attributeId === id).value, expected);
  }
  assert.match(back('session').attributeValues.lifeReplayCache, /logout_event_J0/);
  assert.match(back('second-apply').attributeValues.lifeReplayCache, /logout_event_J1/);
});

test('F06: an enabled replay validation rejects the duplicate and sends HTTP 400 back to the provider', () => {
  const check = back('duplicate-check'), response = back('duplicate-response');
  for (const id of ['lifeLogoutIssuer', 'lifeLogoutJti', 'lifeReplayCache']) assert.ok(action(check, id, 'verify', 'app'));
  assert.equal(check.attributeValues.lifeLogoutJti, 'logout_event_J0');
  assert.equal(check.attributeValues.lifeHttpStatus, '400 Bad Request');
  assert.ok(action(check, 'lifeHttpStatus', 'create', 'app'));
  assert.equal(action(check, 'lifeReplayCache', 'store', 'app'), false, 'Rejected event is not newly accepted');
  assert.equal(action(check, 'lifeAppSession', 'create', 'app'), false);
  assert.equal(action(check, 'lifeAppSession', 'store', 'app'), false, 'No new session side effect');
  assert.equal(response.from, 'app');
  assert.equal(response.to, 'realmA');
  assert.equal(response.channel, 'backchannel');
  assert.equal(response.attributeValues.lifeHttpStatus, '400 Bad Request');
  assert.ok(action(response, 'lifeHttpStatus', 'send', 'app'));
  assert.ok(action(response, 'lifeHttpStatus', 'receive', 'realmA'));
  assert.deepEqual(response.payload.map(member => member.name), ['HTTP status code', 'Cache-Control']);
  assert.ok(response.payload.some(member => member.name === 'Cache-Control' && member.value === 'no-store'));
  assert.equal(back('ack').attributeValues.lifeHttpStatus, '200 OK', 'First valid logout remains successful');
});

test('F06: an authentic fresh event for an already-ended session passes validation and returns HTTP 200', () => {
  const first = back('notify'), request = back('fresh-notify'), apply = back('fresh-apply'), response = back('fresh-response');
  for (const id of ['lifeLogoutIssuer', 'lifeLogoutAudience', 'lifeSid', 'lifeLogoutSubject']) assert.equal(request.attributeValues[id], first.attributeValues[id]);
  assert.equal(request.attributeValues.lifeLogoutJti, 'logout_event_J2');
  assert.notEqual(request.attributeValues.lifeLogoutToken, first.attributeValues.lifeLogoutToken);
  for (const id of ['lifeLogoutIssuer', 'lifeLogoutAudience', 'lifeLogoutIssuedAt', 'lifeLogoutExpiresAt', 'lifeLogoutJti', 'lifeLogoutEvents', 'lifeSid', 'lifeLogoutSubject', 'lifeNonceAbsence', 'lifeReplayCache']) assert.ok(action(apply, id, 'verify', 'app'));
  assert.equal(apply.attributeValues.lifeAppSession, 'still ended');
  assert.equal(action(apply, 'lifeAppSession', 'create', 'app'), false);
  assert.equal(action(apply, 'lifeAppSession', 'store', 'app'), false);
  assert.ok(action(apply, 'lifeReplayCache', 'store', 'app'));
  assert.equal(apply.attributeValues.lifeHttpStatus, '200 OK');
  assert.equal(response.attributeValues.lifeHttpStatus, '200 OK');
  assert.equal(response.from, 'app');
  assert.equal(response.to, 'realmA');
  assert.equal(response.channel, 'backchannel');
});

test('all backchannel notifications have one form parameter and keep every claim inside their signed event', () => {
  for (const key of ['notify', 'second', 'duplicate', 'fresh-notify']) {
    const item = back(key);
    assert.deepEqual(item.payload.filter(member => member.attributeId).map(member => member.name), ['logout_token']);
    for (const op of item.attributeOperations.filter(op => ['send', 'receive'].includes(op.kind) && op.attributeId !== 'lifeLogoutToken')) {
      assert.equal(op.carriedAs, 'logout_token → JWS');
    }
    const target = key === 'second' ? 'realmB' : 'app';
    for (const id of ['lifeLogoutIssuer', 'lifeLogoutAudience', 'lifeLogoutIssuedAt', 'lifeLogoutExpiresAt', 'lifeLogoutJti', 'lifeLogoutEvents', 'lifeSid', 'lifeLogoutSubject']) assert.ok(action(item, id, 'receive', target));
  }
});

test('lifecycle branch values stay continuous for offline scope, missing-session hints and unknown revocation input', () => {
  const offline = story('lab-offline-access');
  for (const item of offline.steps().filter(item => item.fields.includes('lifeScope'))) assert.equal(item.attributeValues.lifeScope, 'openid offline_access orders.read', item.id);
  for (const key of ['prepare', 'open', 'request', 'fail']) {
    const item = step('lab-sso-login-required', key);
    if (item.fields.includes('lifeIdTokenHint')) assert.equal(item.attributeValues.lifeIdTokenHint, 'previous-session hint; no current usable session');
  }
  assert.equal(step('lab-token-revocation', 'unknown').attributeValues.lifeRevokeToken, 'unknown-value');
  assert.equal(step('lab-token-revocation', 'unknown-check').attributeValues.lifeRevokeToken, 'unknown-value');
  assert.equal(step('lab-session-expiry', 'deadline').attributeValues.lifeSsoSession, 'expired');
  assert.equal(step('lab-session-expiry', 'reject').attributeValues.lifeSsoSession, 'expired');
  for (const item of story('lab-sso-existing-session').steps().filter(item => item.fields.includes('lifeScope'))) assert.equal(item.attributeValues.lifeScope, 'openid orders.read', 'An actual scope list excludes explanatory prose');
});

test('each lifecycle step snapshots contextual values and strips construction-only fallback markers', () => {
  for (const model of LIFELAB_SCENARIOS) for (const item of model.steps()) {
    assert.ok(Object.isFrozen(item.attributeValues));
    for (const id of item.fields) assert.notEqual(item.attributeValues[id], undefined, item.id + ':' + id);
    for (const member of item.payload) assert.equal(Object.hasOwn(member, 'lifeExampleFallback'), false);
  }
  assert.equal(back('sign').attributeValues.lifeLogoutJti, 'logout_event_J0', 'Later J1/J2 construction cannot mutate J0');
});
