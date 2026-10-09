import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ADLAB_SCENARIOS } from '../src/kerberos-ad-lab.js';
import { CRYPTOLAB_SCENARIOS } from '../src/kerberos-crypto-lab.js';
import { FORESTLAB_SCENARIOS } from '../src/kerberos-forest-lab.js';
import { SSHLAB_SCENARIOS } from '../src/ssh-access-lab.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { buildProtocolInstances, reconstructProtocolState } from '../src/protocol-state.js';
import { projectScenarioContext } from '../src/scenario-context.js';

// Independent acceptance conditions from the 9 October code review. These
// compare actual field occurrences and chronology, rather than trusting a
// variant's authored terminal success/failure flag. No live crypto is claimed.
const allModels = [...ADLAB_SCENARIOS, ...CRYPTOLAB_SCENARIOS, ...FORESTLAB_SCENARIOS, ...SSHLAB_SCENARIOS];
const model = id => {
  const found = allModels.find(candidate => candidate.id === id);
  assert.ok(found, `Required reference preset ${id} exists`);
  return found;
};
const steps = fixture => fixture.steps();
const stateAt = (fixture, index) => reconstructProtocolState(fixture, index);
const finalState = fixture => stateAt(fixture, steps(fixture).length - 1);
const stage = (fixture, name) => {
  const found = steps(fixture).find(step => step.sshStage === name || step.labCryptoStage === name) || steps(fixture).find(step => step.id.endsWith('-' + name));
  assert.ok(found, `${fixture.id} contains ${name}`);
  return found;
};
const operations = fixture => steps(fixture).flatMap((step, index) => (step.attributeOperations || []).map(operation => ({ ...operation, step, index, name: fixture.definitions()[operation.attributeId]?.name })));
const named = (fixture, step, name, kind) => {
  const found = step.attributeOperations.find(operation => fixture.definitions()[operation.attributeId]?.name === name && (!kind || operation.kind === kind));
  assert.ok(found, `${step.id}: ${kind || 'operation'} ${name}`);
  return found;
};
const indexOf = (fixture, step) => steps(fixture).indexOf(step);
const focusedTrace = (fixture, attributeId) => buildAttributeTrace(steps(fixture).map((step, index) => ({ step, index, actions: step.attributeOperations.filter(operation => operation.attributeId === attributeId) })).filter(usage => usage.actions.length), fixture.examples(), fixture.protocolValues || {});
function assertFocusedOccurrence(fixture, original) {
  const eventId = original.step?.id || steps(fixture).find(step => step.attributeOperations.includes(original))?.id;
  const traceStep = focusedTrace(fixture, original.attributeId).find(step => step.sourceStepId === eventId && step.traceActions.some(operation => (operation.kind === original.kind && operation.actorId === original.actorId || original.kind === 'receive' && operation.kind === 'send' && step.to === original.actorId) && operation.instanceId === original.instanceId && operation.fieldPath === original.fieldPath && JSON.stringify(operation.value) === JSON.stringify(original.value)));
  assert.ok(traceStep, `${fixture.id}: field focus preserves ${original.kind} of ${original.instanceId} at ${eventId}`);
  assert.deepEqual(traceStep.payload.find(field => field.attributeId === original.attributeId)?.value, original.value, 'Focused inspector uses the exact occurrence value');
  assert.deepEqual(stateAt(fixture, traceStep.sourceIndex), stateAt(fixture, steps(fixture).findIndex(step => step.id === eventId)), 'Focused trace reconstructs the same complete source prefix');
}

test('F01: selected SPNEGO integrity exchange carries distinct reciprocal MICs in causal order', () => {
  const fixture = model('lab-kc-kerberos-sso');
  const mics = operations(fixture).filter(operation => operation.name === 'mechListMIC');
  const acceptorCreate = mics.find(operation => operation.kind === 'create' && operation.actorId === 'adKeycloak');
  assert.ok(acceptorCreate, 'The acceptor creates its own MIC');
  const acceptorSend = mics.find(operation => operation.kind === 'send' && operation.actorId === 'adKeycloak' && operation.instanceId === acceptorCreate.instanceId);
  const initiatorVerify = mics.find(operation => operation.kind === 'verify' && operation.actorId === 'adWorkstation' && operation.instanceId === acceptorCreate.instanceId);
  const initiatorCreate = mics.find(operation => operation.kind === 'create' && operation.actorId === 'adWorkstation');
  const initiatorSend = mics.find(operation => operation.kind === 'send' && operation.actorId === 'adBrowser' && operation.instanceId === initiatorCreate?.instanceId);
  const acceptorVerify = mics.find(operation => operation.kind === 'verify' && operation.actorId === 'adKeycloak' && operation.instanceId === initiatorCreate?.instanceId);
  for (const operation of [acceptorSend, initiatorVerify, initiatorCreate, initiatorSend, acceptorVerify]) assert.ok(operation);
  assert.notEqual(acceptorCreate.instanceId, initiatorCreate.instanceId, 'MIC direction does not reuse one immutable instance');
  const ordinal = operation => operation.index * 1000 + operation.step.attributeOperations.findIndex(candidate => candidate.kind === operation.kind && candidate.actorId === operation.actorId && candidate.instanceId === operation.instanceId);
  const sequence = [acceptorCreate, acceptorSend, initiatorVerify, initiatorCreate, initiatorSend, acceptorVerify];
  for (let i = 1; i < sequence.length; i++) assert.ok(ordinal(sequence[i]) > ordinal(sequence[i - 1]), 'Each MIC is delivered and checked before dependent completion');
  for (const operation of sequence) assertFocusedOccurrence(fixture, operation);
  assert.equal(stateAt(fixture, acceptorVerify.index - 1).sessions.applicationAuthenticated, false);
  assert.equal(finalState(fixture).sessions.applicationAuthenticated, true);
});

for (const condition of ['missing', 'invalid']) test(`F01: ${condition} required acceptor MIC stops before initiator proof or OIDC success`, () => {
  const fixture = model('lab-kc-spnego-' + condition + '-acceptor-mic');
  const all = operations(fixture);
  const mic = all.filter(operation => operation.name === 'mechListMIC');
  assert.ok(!mic.some(operation => operation.kind === 'create' && operation.actorId === 'adWorkstation'), 'A failed acceptor integrity check cannot produce initiator completion');
  assert.ok(!all.some(operation => operation.attributeId === 'adCode' || operation.attributeId === 'adIdToken'), 'Failed GSS negotiation cannot issue an OIDC authorization result');
  const receivedState = all.find(operation => operation.attributeId === 'adNegTokenResp' && operation.kind === 'receive' && operation.actorId === 'adWorkstation');
  assert.ok(receivedState);
  assert.match(receivedState.value, /request-mic/, 'The chosen negotiation explicitly requires MICs');
  if (condition === 'missing') {
    assert.ok(!mic.some(operation => operation.kind === 'send'), 'A missing MIC is not invented in the wire ledger');
    const check = all.find(operation => operation.attributeId === 'adNegTokenResp' && operation.kind === 'verify' && operation.actorId === 'adWorkstation');
    assert.ok(check, 'The initiator performs the required-container absence check');
    assertFocusedOccurrence(fixture, check);
  } else {
    const received = mic.find(operation => operation.kind === 'receive' && operation.actorId === 'adWorkstation');
    const verified = mic.find(operation => operation.kind === 'verify' && operation.actorId === 'adWorkstation');
    assert.ok(received && verified);
    assert.equal(received.instanceId, verified.instanceId);
    assert.equal(received.value, verified.value);
    assertFocusedOccurrence(fixture, verified);
  }
  for (let index = -1; index < steps(fixture).length; index++) {
    const state = stateAt(fixture, index);
    assert.equal(state.sessions.applicationAuthenticated, false);
    assert.ok(!state.transactions?.code?.instanceId);
    assert.ok(!buildProtocolInstances(fixture, index).some(instance => instance.occurrences.some(occurrence => occurrence.definitionId === 'adIdToken')));
  }
});

test('F02: ticket identity preserves independent clear sname/realm values in every affected source and focused view', () => {
  let checked = 0;
  for (const fixture of ADLAB_SCENARIOS) {
    const all = operations(fixture);
    for (const operation of all.filter(operation => ['adTgtTarget', 'adTicketTarget', 'adTicketRealm'].includes(operation.attributeId))) {
      const expected = operation.attributeId === 'adTgtTarget' ? 'krbtgt/A.EXAMPLE' : operation.attributeId === 'adTicketRealm' ? 'A.EXAMPLE' : operation.instanceId === 'ticket:host:01' ? 'host/ws01.a.example' : fixture.family === 'keycloak-bridge' ? 'HTTP/idp.a.example' : 'cifs/files.a.example';
      assert.equal(operation.value, expected, `${fixture.id} ${operation.step.id} ${operation.fieldPath}`);
      assertFocusedOccurrence(fixture, operation);
      const object = buildProtocolInstances(fixture, operation.index).find(instance => instance.instanceId === operation.instanceId);
      assert.ok(object, 'The scalar header retains its ticket instance identity');
      assert.ok(object.occurrences.some(occurrence => occurrence.definitionId === operation.attributeId && occurrence.value === operation.value));
      checked++;
    }
  }
  assert.ok(checked > 50, 'Scan includes first logon, host/service credentials and Keycloak bridge occurrences');
  const first = model('lab-ad-first-sign-in');
  const tgt = operations(first).find(operation => operation.attributeId === 'adTgt' && operation.kind === 'create');
  const target = operations(first).find(operation => operation.attributeId === 'adTgtTarget' && operation.kind === 'create');
  const realm = operations(first).find(operation => operation.attributeId === 'adTicketRealm' && operation.kind === 'create');
  assert.equal(tgt.instanceId, target.instanceId);
  assert.equal(tgt.instanceId, realm.instanceId);
  assert.notEqual(tgt.value, target.value);
  assert.notEqual(tgt.value, realm.value);
});

for (const id of ['lab-ad-first-sign-in', 'lab-kc-kerberos-sso']) test(`F02: ${id} keeps new ticket headers consistent with the applied request and credential target`, () => {
  const base = model(id), baseBefore = JSON.stringify({ initialState: base.initialState, steps: base.steps() });
  const context = { kerberosRealm: 'CORP.EXAMPLE', servicePrincipal: 'HTTP/operator.example' };
  const projected = projectScenarioContext(base, base.steps(), context);
  const fixture = { ...base, ...projected, steps: () => projected.steps };
  for (const occurrence of operations(fixture).filter(operation => ['adTgtTarget', 'adTicketTarget', 'adTicketRealm'].includes(operation.attributeId))) {
    const expected = occurrence.attributeId === 'adTgtTarget' ? 'krbtgt/CORP.EXAMPLE' : occurrence.attributeId === 'adTicketRealm' ? 'CORP.EXAMPLE' : occurrence.instanceId === 'ticket:host:01' ? 'host/ws01.a.example' : context.servicePrincipal;
    assert.equal(occurrence.value, expected, `${occurrence.step.id}: typed context changes clear header fields together`);
    assertFocusedOccurrence(fixture, occurrence);
  }
  assert.equal(finalState(fixture).credentials.service.target, context.servicePrincipal);
  assert.equal(finalState(fixture).credentials.service.crealm, context.kerberosRealm);
  assert.equal(JSON.stringify({ initialState: base.initialState, steps: base.steps() }), baseBefore, 'Operator projection does not rewrite the immutable base credential');
});

for (const base of CRYPTOLAB_SCENARIOS) test(`F03: ${base.id} rebuilds realm-dependent request/reply/cache fields as a fresh consistent fixture`, () => {
  const source = JSON.stringify({ state: base.initialState, steps: base.steps(), definitions: base.definitions() });
  assert.equal(typeof base.contextualize, 'function', 'Structured fixtures require a context-aware constructor');
  const fixture = base.contextualize({ kerberosRealm: 'CORP.EXAMPLE', servicePrincipal: 'HTTP/separate.example' }, { revision: 7 });
  const all = operations(fixture);
  const requests = all.filter(operation => /KDC-REQ-BODY$|KDC-REQ\.req-body|KrbFastReq\.req-body$/.test(operation.fieldPath));
  // Prerequisite/local-stop presets never construct or send an AS request.
  assert.equal(requests.length, operations(base).filter(operation => /KDC-REQ-BODY$|KDC-REQ\.req-body|KrbFastReq\.req-body$/.test(operation.fieldPath)).length, 'Applying context preserves the original protocol exchanges');
  assert.deepEqual(fixture.steps().map(step => step.id), base.steps().map(step => step.id));
  for (const operation of requests) {
    assert.ok(JSON.stringify(operation.value).includes('CORP.EXAMPLE'), `${operation.fieldPath} uses the applied realm`);
    assert.ok(!JSON.stringify(operation.value).includes('realm=A.EXAMPLE') && !JSON.stringify(operation.value).includes('krbtgt/A.EXAMPLE'));
    assertFocusedOccurrence(fixture, operation);
  }
  for (const operation of all.filter(operation => /Ticket|KrbFastFinished|Certificate|realm/.test(operation.fieldPath))) {
    if (/realm=A\.EXAMPLE|krbtgt\/A\.EXAMPLE|alice@A\.EXAMPLE|crealm=A\.EXAMPLE/.test(JSON.stringify(operation.value))) assert.fail(`${operation.fieldPath} retains a dependent identity from the base realm`);
  }
  const last = finalState(fixture);
  for (const credential of Object.values(last.credentials)) {
    if (credential.crealm !== undefined) assert.equal(credential.crealm, 'CORP.EXAMPLE');
    if (credential.target?.startsWith('krbtgt/')) assert.equal(credential.target, 'krbtgt/CORP.EXAMPLE');
    if (credential.sname?.startsWith('krbtgt/')) assert.equal(credential.sname, 'krbtgt/CORP.EXAMPLE');
    if (credential.principal?.includes('@')) assert.ok(credential.principal.endsWith('@CORP.EXAMPLE'));
  }
  if (base.runtimeBindings.some(binding => binding.field === 'servicePrincipal')) assert.ok(all.some(operation => operation.value === 'HTTP/separate.example'), 'The independent service principal retains its own typed setting');
  assert.equal(JSON.stringify({ state: base.initialState, steps: base.steps(), definitions: base.definitions() }), source, 'Apply does not mutate the issued base fixture');
  assert.notEqual(fixture.steps(), base.steps());
});

test('F04: missing implicit FAST subkey stops at its constructing owner without pretending the KDC received FAST', () => {
  const fixture = model('lab-ad-fast-tgs-missing-subkey');
  const last = finalState(fixture), rejection = stage(fixture, 'missing-subkey-reject');
  assert.equal(rejection.from, 'cryptoClient');
  assert.equal(rejection.to, 'cryptoClient');
  assert.ok(!operations(fixture).some(operation => ['send', 'receive'].includes(operation.kind)), 'No correctly protected request can be sent before an armor key exists');
  assert.ok(/ordinary.*(?:non.FAST|without FAST).*optional|optional.*(?:ordinary|non.FAST)/i.test(steps(fixture).map(step => step.detail).join(' ')), 'The ordinary non-FAST subkey rule remains optional');
  assert.deepEqual(last.credentials.userTgt, stateAt(fixture, -1).credentials.userTgt);
  assert.equal(last.credentials.service, undefined);
  assert.equal(last.keys.armorClient, undefined);
  assert.equal(last.knowledge.kdc.failure, undefined, 'The KDC has not learned a client-local construction failure');
  const ordinary = model('lab-ad-first-sign-in');
  assert.match(ordinary.definitions().adTGSReply.purpose, /omits a TGS authenticator subkey/);
  assert.ok(!operations(ordinary).some(operation => /Authenticator\.subkey|PA-FX-FAST/.test(operation.fieldPath)));
  assert.equal(finalState(ordinary).sessions.serviceAuthenticated, true, 'An explicitly ordinary no-subkey TGS exchange is allowed');
});

for (const id of ['lab-ad-fast-as-checksum', 'lab-ad-fast-as-challenge']) test(`F05: ${id} carries and checks a protected PA-FX-ERROR lineage before client failure knowledge`, () => {
  const fixture = model(id), all = operations(fixture);
  const error = stage(fixture, 'error-result'), decode = stage(fixture, 'decode-error');
  assert.ok(all.some(operation => operation.name === 'PA-FX-ERROR (137)'));
  assert.ok(all.some(operation => operation.fieldPath.includes('KRB-ERROR.e-data.METHOD-DATA.PA-FX-FAST')));
  for (const operation of error.attributeOperations) assert.ok(!operation.fieldPath.startsWith('KDC-REP'), 'Error packets do not use successful KDC-REP container paths');
  const inner = all.find(operation => operation.name === 'KRB-ERROR (inside PA-FX-ERROR)' && operation.kind === 'verify' && operation.actorId === 'cryptoClient');
  assert.ok(inner, 'The client checks the decoded inner error object');
  assert.ok(inner.fieldPath.includes('PA-FX-ERROR'));
  assert.equal(Object.hasOwn(inner.value, 'e-data'), false, 'The inner error has no recursive e-data');
  assert.equal(inner.value.pvno, 5);
  assert.equal(inner.value['msg-type'], 30);
  const methodData = named(fixture, error, 'METHOD-DATA (FAST error e-data)', 'send');
  assert.equal(methodData.value[0]['padata-type'], 136, 'The outer error carries PA-FX-FAST as METHOD-DATA');
  const fxError = named(fixture, decode, 'PA-FX-ERROR (137)', 'verify');
  assert.equal(fxError.value['padata-type'], 137);
  assert.deepEqual(fxError.value['padata-value'], inner.value, 'The checked inner error is the exact payload of the protected PA-FX-ERROR');
  assert.deepEqual(named(fixture, decode, 'KrbFastResponse (error)', 'verify').value.padata, [fxError.value]);
  assertFocusedOccurrence(fixture, inner);
  assert.equal(stateAt(fixture, indexOf(fixture, error)).knowledge.client.failure, undefined);
  assert.equal(stateAt(fixture, indexOf(fixture, decode) - 1).knowledge.client.failure, undefined);
  assert.ok(stateAt(fixture, indexOf(fixture, decode)).knowledge.client.failure);
  assert.ok(decode.attributeOperations.some(operation => operation.kind === 'use' && /enc-fast-rep/.test(operation.fieldPath)));
  assert.ok(decode.attributeOperations.some(operation => operation.kind === 'verify' && operation.fieldPath === 'KrbFastResponse'));
  assert.ok(/(?:verify\/decrypt|verify.*decrypt).*enc-fast-rep/.test(decode.detail));
  const final = finalState(fixture);
  assert.equal(final.credentials.userTgt, undefined);
  assert.ok(!all.some(operation => /KrbFastResponse\.(?:strengthen-key|finished)/.test(operation.fieldPath)), 'A protected failure does not issue successful response material');
});

test('F06: PA-ENCRYPTED-CHALLENGE teaching requires strengthening and distinct key roles before accepting a ticket', () => {
  const fixture = model('lab-ad-fast-as-success');
  const definition = Object.values(fixture.definitions()).find(definition => definition.name === 'strengthen-key');
  assert.ok(/required/i.test(definition.purpose));
  assert.ok(/PA-ENCRYPTED-CHALLENGE/.test(definition.purpose));
  assert.ok(/requires|require[ds]/i.test(stage(fixture, 'protect-response').detail));
  assert.ok(!/selects optional strengthening/i.test(stage(fixture, 'protect-response').detail));
  const decode = stage(fixture, 'decode-response');
  assert.ok(decode.attributeOperations.some(operation => operation.kind === 'verify' && operation.fieldPath === 'KrbFastResponse.strengthen-key'), 'Client explicitly checks required strengthening');
  const last = finalState(fixture);
  const ids = [last.keys.originalReplyClient.instanceId, last.keys.finalReplyClient.instanceId, last.keys.armorClient.instanceId, last.credentials.userTgt.sessionKeyInstanceId];
  assert.equal(new Set(ids).size, 4, 'Original reply, strengthened reply, armor and ticket-session keys are independent');
});

test('F07: expiry denial follows the server-clock endtime+skew boundary with a fresh proof and the same cached ticket', () => {
  const fixture = model('lab-ad-expired-ticket');
  const reject = stage(fixture, 'acceptor-reject'), rejection = stateAt(fixture, indexOf(fixture, reject));
  const proof = rejection.proofs.ap;
  const credential = rejection.credentials.service;
  assert.ok(rejection.acceptorClock > credential.validBefore + rejection.policy.skewSeconds, 'Server time is past expiry plus accepted skew');
  assert.ok(Math.abs(proof.clientTime - rejection.acceptorClock) <= rejection.policy.skewSeconds, 'The fresh authenticator itself is not skewed');
  const before = stateAt(fixture, -1);
  assert.equal(credential.ticketInstanceId, before.credentials.service.ticketInstanceId);
  assert.equal(proof.ticketInstanceId, credential.ticketInstanceId);
  const proofTime = named(fixture, stage(fixture, 'ap-create'), 'Authenticator.ctime / cusec', 'create');
  assert.match(proofTime.value, new RegExp('ctime=' + proof.clientTime + '(?:;|$)'));
  const boundary = steps(fixture).map((step, index) => ({ step, state: stateAt(fixture, index) })).find(entry => entry.state.acceptorClock === credential.validBefore + rejection.policy.skewSeconds);
  assert.ok(boundary, 'The lesson explicitly shows the last accepted expiration-skew boundary');
  assert.equal(boundary.state.failure, undefined);
  assert.equal(rejection.acceptorClock, boundary.state.acceptorClock + 1);
});

test('F08: missing acceptor key version uses BADKEYVER and preserves the correctly issued cached service ticket', () => {
  const fixture = model('lab-ad-stale-service-key'), reject = stage(fixture, 'acceptor-reject');
  const cache = stage(fixture, 'service-cache'), delivery = stage(fixture, 'ap-request');
  assert.ok(indexOf(fixture, cache) < indexOf(fixture, delivery) && indexOf(fixture, delivery) < indexOf(fixture, reject));
  const state = stateAt(fixture, indexOf(fixture, reject));
  assert.match(state.keys.serviceKdc, /kvno=7/);
  assert.match(state.keys.serviceInstalled, /kvno=6/);
  assert.deepEqual(state.keys.serviceInstalledVersions, [6]);
  assert.equal(state.credentials.service.keyVersion, 7);
  assert.equal(named(fixture, reject, 'Ticket.enc-part.kvno', 'verify').value, 7);
  const error = named(fixture, reject, 'KRB-ERROR.error-code');
  assert.match(error.value, /BADKEYVER/);
  assert.match(error.value, /44/);
  assert.ok(/(?:key.version availability check fails|kvno.*?only kvno|key version.*?(?:absent|missing|unavailable|not installed))/i.test(reject.detail + ' ' + error.detail));
  assert.deepEqual(state.credentials.service, stateAt(fixture, indexOf(fixture, cache)).credentials.service);
  assert.equal(state.proofs.apReply, undefined);
  assert.equal(state.sessions.serviceAuthenticated, false);
  assert.equal(state.knowledge.adWorkstation.failure, undefined, 'Only the acceptor knows its failure until the error is delivered');
  assertFocusedOccurrence(fixture, { ...error, step: reject });
});

test('F09: forest boundary classification follows explicit membership in both directions and keeps child hops local', () => {
  const aToB = model('lab-ad-forest-two-way-a-b'), bToA = model('lab-ad-forest-two-way-b-a');
  for (const fixture of [aToB, bToA]) {
    const issued = stage(fixture, 'issue-referral-1');
    assert.equal(issued.referralHop.forestBoundary, true);
    assert.notEqual(issued.referralHop.fromForest, issued.referralHop.toForest);
    assert.match(issued.detail, /forest boundary/);
    assert.ok(issued.referralHop.configuredTrust);
    assert.ok(issued.referralHop.pacPolicy);
  }
  const child = model('lab-ad-forest-child-domains');
  const hops = child.initialState.policies.referralHops;
  assert.deepEqual(hops.map(hop => hop.forestBoundary), [false, true, false]);
  assert.equal(hops[0].fromForest, hops[0].toForest);
  assert.equal(hops[2].fromForest, hops[2].toForest);
  assert.notEqual(hops[1].fromForest, hops[1].toForest);
});

test('F10: every successful bridge has Bearer token_type and correctly nested required ID-token claims', () => {
  const successful = ADLAB_SCENARIOS.filter(fixture => fixture.family === 'keycloak-bridge' && finalState(fixture).sessions.applicationAuthenticated);
  assert.equal(successful.length, 9);
  for (const fixture of successful) {
    const response = stage(fixture, 'token-response');
    const sent = response.attributeOperations.filter(operation => operation.kind === 'send');
    const names = new Set(sent.map(operation => fixture.definitions()[operation.attributeId].name));
    for (const name of ['id_token', 'access_token', 'token_type', 'iss', 'sub', 'aud', 'exp', 'iat']) assert.ok(names.has(name), `${fixture.id}: ${name}`);
    const tokenType = sent.find(operation => fixture.definitions()[operation.attributeId].name === 'token_type');
    assert.equal(tokenType.value, 'Bearer');
    assert.equal(tokenType.fieldPath, 'token_type');
    const token = sent.find(operation => fixture.definitions()[operation.attributeId].name === 'id_token');
    for (const name of ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']) {
      const claim = sent.find(operation => fixture.definitions()[operation.attributeId].name === name);
      assert.ok(claim);
      assert.equal(claim.instanceId, token.instanceId, 'A signed claim belongs to the ID-token instance');
      assert.equal(claim.fieldPath, 'id_token.payload.' + name);
      if (['iat', 'exp'].includes(name)) assert.equal(typeof claim.value, 'number');
      assertFocusedOccurrence(fixture, { ...claim, step: response });
    }
    const iat = sent.find(operation => fixture.definitions()[operation.attributeId].name === 'iat');
    const exp = sent.find(operation => fixture.definitions()[operation.attributeId].name === 'exp');
    assert.ok(exp.value > iat.value);
    assert.ok(operations(fixture).some(operation => operation.kind === 'create' && operation.attributeId === tokenType.attributeId && operation.actorId === 'adKeycloak'));
  }
  for (const fixture of ADLAB_SCENARIOS.filter(fixture => fixture.family === 'keycloak-bridge' && !finalState(fixture).sessions.applicationAuthenticated)) assert.ok(!operations(fixture).some(operation => operation.kind === 'send' && ['adCode', 'adIdToken', 'adAccessToken', 'adTokenType'].includes(operation.attributeId)), `${fixture.id}: failure does not issue a successful authorization result`);
});

test('F11: foreign callback state is checked against retained expected state without changing the received object', () => {
  const fixture = model('lab-ssh-cert-callback');
  const callback = stage(fixture, 'callback'), check = stage(fixture, 'callback-check');
  const bad = named(fixture, callback, 'state', 'receive');
  const verified = named(fixture, check, 'state', 'verify');
  assert.equal(verified.instanceId, bad.instanceId);
  assert.equal(verified.value, bad.value);
  const expected = check.attributeOperations.find(operation => operation.attributeId === bad.attributeId && operation.kind === 'use' && operation.instanceId !== bad.instanceId);
  assert.ok(expected, 'Expected transaction state remains a separate stored input');
  assert.notEqual(expected.value, bad.value);
  const comparison = stateAt(fixture, indexOf(fixture, check)).transaction.callbackComparison;
  assert.equal(comparison.receivedInstanceId, bad.instanceId);
  assert.equal(comparison.receivedState, bad.value);
  assert.equal(comparison.expectedInstanceId, expected.instanceId);
  assert.equal(comparison.expectedState, expected.value);
  assert.equal(comparison.matched, false);
  assert.equal(named(fixture, stage(fixture, 'prepare'), 'state', 'create').value, expected.value, 'The expected state is the original CLI transaction value');
  assert.equal(stateAt(fixture, indexOf(fixture, check)).transaction.expectedState, expected.value);
  assert.equal(stateAt(fixture, indexOf(fixture, check) - 1).failure, undefined);
  assertFocusedOccurrence(fixture, { ...verified, step: check });
});

test('F11: wrong PKCE verifier is valid syntax and its exact received instance reaches the failed S256 comparison', () => {
  const fixture = model('lab-ssh-cert-pkce');
  const request = stage(fixture, 'redeem'), check = stage(fixture, 'pkce-check');
  const bad = named(fixture, request, 'code_verifier', 'receive');
  assert.match(bad.value, /^[A-Za-z0-9._~-]{43,128}$/);
  const verified = named(fixture, check, 'code_verifier', 'verify');
  assert.equal(verified.instanceId, bad.instanceId);
  assert.equal(verified.value, bad.value);
  const expected = named(fixture, check, 'code_challenge', 'use');
  const derived = createHash('sha256').update(bad.value, 'ascii').digest('base64url');
  assert.notEqual(derived, expected.value);
  const originalVerifier = named(fixture, stage(fixture, 'prepare'), 'code_verifier', 'create');
  assert.equal(createHash('sha256').update(originalVerifier.value, 'ascii').digest('base64url'), expected.value, 'The independently recomputed original commitment is correct');
  const comparison = stateAt(fixture, indexOf(fixture, check)).transaction.pkceComparison;
  assert.equal(comparison.verifierInstanceId, bad.instanceId);
  assert.equal(comparison.derivedChallenge, derived);
  assert.equal(comparison.expectedChallenge, expected.value);
  assert.equal(comparison.matched, false);
  assert.equal(stateAt(fixture, indexOf(fixture, check)).transaction.storedChallenge, expected.value, 'The stored original commitment is immutable after a bad verifier arrives');
  assertFocusedOccurrence(fixture, { ...verified, step: check });
});

for (const [id, stageName, fieldName] of [['lab-ssh-cert-callback', 'callback', 'state'], ['lab-ssh-cert-pkce', 'redeem', 'code_verifier']]) test(`F11: ${id} never repairs the foreign input while traversing complete source prefixes`, () => {
  const fixture = model(id), delivery = stage(fixture, stageName), received = named(fixture, delivery, fieldName, 'receive');
  const arrival = indexOf(fixture, delivery);
  for (let index = -1; index < steps(fixture).length; index++) {
    const records = buildProtocolInstances(fixture, index);
    const badObject = records.find(record => record.instanceId === received.instanceId);
    if (index < arrival) {
      assert.equal(badObject, undefined, 'A future foreign object does not appear in earlier source-prefix knowledge');
    } else {
      assert.ok(badObject);
      for (const occurrence of badObject.occurrences.filter(occurrence => occurrence.definitionId === received.attributeId)) assert.equal(occurrence.value, received.value, 'Every observed representation keeps the actual received input');
      assert.ok(badObject.occurrences.every(occurrence => occurrence.eventIndex <= index));
    }
    assert.equal(stateAt(fixture, index).credentials.userCertificate, undefined, 'The bad enrollment never silently creates a valid SSH certificate');
  }
});

test('F12: root account denial signs the actual root request while the independent certificate principal stays alice', () => {
  const fixture = model('lab-ssh-cert-root');
  const userauth = stage(fixture, 'userauth');
  const account = named(fixture, userauth, 'user name', 'send');
  assert.equal(account.value, 'root');
  const signing = named(fixture, stage(fixture, 'userauth-input'), 'SSH publickey signed input (local)', 'derive');
  assert.match(signing.value, /string\(root\)/);
  assert.ok(!signing.value.includes('string(alice)'));
  assert.equal(signing.instanceId, account.instanceId);
  const agentInput = named(fixture, stage(fixture, 'agent-request'), 'SSH publickey signed input (local)', 'receive');
  assert.equal(agentInput.value, signing.value);
  assert.equal(agentInput.instanceId, signing.instanceId);
  const policy = stage(fixture, 'host-policy');
  assert.deepEqual(named(fixture, policy, 'valid principals', 'verify').value, ['alice']);
  const checks = stateAt(fixture, indexOf(fixture, policy)).hostChecks;
  assert.equal(checks.possessionProofAccepted, true);
  assert.equal(checks.principalAccountMapped, false);
});

test('F13: a second channel uses a new object and sender number on the existing authenticated connection', () => {
  const fixture = model('lab-ssh-cert-lifecycle');
  const first = stage(fixture, 'channel'), second = stage(fixture, 'additional-channel');
  const one = named(fixture, first, 'SSH_MSG_CHANNEL_OPEN', 'send');
  const two = named(fixture, second, 'SSH_MSG_CHANNEL_OPEN', 'send');
  assert.notEqual(one.instanceId, two.instanceId);
  assert.equal(one.value.sender_channel, 0);
  assert.equal(two.value.sender_channel, 1);
  const before = stateAt(fixture, indexOf(fixture, second) - 1), after = stateAt(fixture, indexOf(fixture, second));
  assert.equal(before.sessions.ssh.channels, 1);
  assert.equal(after.sessions.ssh.channels, 2);
  assert.equal(after.sessions.ssh.authenticated, true);
  assert.deepEqual(after.sessions.ssh.activeChannels.map(channel => channel.senderChannel).sort(), [0, 1]);
  assert.ok(!steps(fixture).slice(indexOf(fixture, first) + 1, indexOf(fixture, second)).some(step => /CHANNEL_CLOSE/.test(JSON.stringify(step.payload))), 'Channel zero remains active');
  assertFocusedOccurrence(fixture, { ...two, step: second });
});

test('F14: fresh Device responses include their own required lifetime and cannot inherit a cancelled transaction', () => {
  let successfulResponses = 0;
  for (const fixture of SSHLAB_SCENARIOS.filter(fixture => fixture.id.startsWith('lab-ssh-device-'))) {
    for (const step of steps(fixture).filter(step => ['response', 'restart-response'].includes(step.sshStage))) {
      const sent = step.attributeOperations.filter(operation => operation.kind === 'send');
      for (const name of ['device_code', 'user_code', 'verification_uri', 'expires_in']) assert.ok(sent.some(operation => fixture.definitions()[operation.attributeId].name.replace(/ \(.*\)$/, '') === name), `${fixture.id}/${step.sshStage}: ${name}`);
      successfulResponses++;
    }
  }
  assert.equal(successfulResponses, SSHLAB_SCENARIOS.filter(fixture => fixture.id.startsWith('lab-ssh-device-')).length + 1, 'Each Device lesson has an initial response; restart adds its own fresh response');
  const fixture = model('lab-ssh-device-restart'), response = stage(fixture, 'restart-response');
  const lifetime = named(fixture, response, 'expires_in (device transaction)', 'send'), code = named(fixture, response, 'device_code', 'send');
  assert.equal(lifetime.instanceId, code.instanceId);
  assert.equal(lifetime.value, 600);
  assert.ok(operations(fixture).some(operation => operation.kind === 'create' && operation.attributeId === lifetime.attributeId && operation.instanceId === lifetime.instanceId && operation.value === lifetime.value && operation.index < indexOf(fixture, response)), 'Transaction 2 creates its own expires_in before transmitting it');
  assert.equal(named(fixture, response, 'verification_uri', 'send').instanceId, code.instanceId);
  const received = stateAt(fixture, indexOf(fixture, response));
  assert.equal(received.transaction.expiresAt, received.protocolClock + lifetime.value);
  assert.equal(received.transaction.instanceId, code.instanceId);
  assert.equal(received.transaction.createdAt, received.protocolClock);
  assert.equal(received.transactions.old.status, 'cancelled');
  assert.notEqual(received.transactions.old.instanceId, received.transaction.instanceId);
  assertFocusedOccurrence(fixture, { ...lifetime, step: response });
});

for (const id of ['lab-ssh-device-cadence', 'lab-ssh-device-restart']) test(`F15: ${id} establishes local agent ownership before signing and network delivery`, () => {
  const fixture = model(id);
  const construction = stage(fixture, 'userauth-input'), request = stage(fixture, 'agent-request'), sign = stage(fixture, 'sign'), proof = stage(fixture, 'agent-proof'), network = stage(fixture, 'userauth');
  assert.deepEqual([construction, request, sign, proof, network].map(step => indexOf(fixture, step)), [construction, request, sign, proof, network].map(step => indexOf(fixture, step)).toSorted((a, b) => a - b));
  const input = named(fixture, construction, 'SSH publickey signed input (local)', 'derive');
  const agentReceived = named(fixture, request, 'SSH publickey signed input (local)', 'receive');
  assert.equal(input.actorId, 'sshCli');
  assert.equal(agentReceived.actorId, 'sshAgent');
  assert.equal(agentReceived.instanceId, input.instanceId);
  assert.equal(agentReceived.value, input.value);
  const createdProof = named(fixture, sign, 'signature (SSH user proof)', 'create');
  const cliReceived = named(fixture, proof, 'signature (SSH user proof)', 'receive');
  const transmitted = named(fixture, network, 'signature (SSH user proof)', 'send');
  for (const operation of [cliReceived, transmitted]) {
    assert.equal(operation.instanceId, createdProof.instanceId);
    assert.equal(operation.value, createdProof.value);
  }
  assert.equal(cliReceived.actorId, 'sshCli');
  const beforeAgent = buildProtocolInstances(fixture, indexOf(fixture, request) - 1).find(instance => instance.instanceId === input.instanceId);
  assert.ok(!beforeAgent.holders.includes('sshAgent'));
  assert.ok(buildProtocolInstances(fixture, indexOf(fixture, request)).find(instance => instance.instanceId === input.instanceId).holders.includes('sshAgent'));
  assert.ok(!network.attributeOperations.some(operation => ['send', 'receive'].includes(operation.kind) && /session identifier|private key/.test(fixture.definitions()[operation.attributeId].name)), 'Local signing context is not an extra SSH packet member');
});

test('F16: every SSSD field declared inside keyboard instructions occurs in the exact SSH envelope for zero/one prompts', () => {
  let promptCounts = new Set(), checked = 0;
  for (const fixture of SSHLAB_SCENARIOS.filter(fixture => fixture.id.startsWith('lab-ssh-sssd-'))) {
    const info = steps(fixture).find(step => step.sshStage === 'ssh-info');
    if (!info) continue;
    const envelope = named(fixture, info, 'SSH_MSG_USERAUTH_INFO_REQUEST', 'send').value;
    promptCounts.add(envelope.num_prompts);
    assert.equal(envelope.prompts.length, envelope.num_prompts);
    const humanText = [envelope.instruction, ...envelope.prompts.map(prompt => prompt.prompt)].join(' ');
    for (const operation of info.attributeOperations.filter(operation => operation.kind === 'send' && /instruction\/prompt text/.test(operation.carriedAs || ''))) {
      assert.ok(humanText.includes(String(operation.value)), `${fixture.id}: ${fixture.definitions()[operation.attributeId].name} is actually in the human-readable envelope`);
      const displayed = stage(fixture, 'terminal-display').attributeOperations.find(display => display.attributeId === operation.attributeId);
      assert.equal(displayed.value, operation.value);
      assert.equal(displayed.instanceId, operation.instanceId);
      assertFocusedOccurrence(fixture, { ...operation, step: info });
    }
    const workstationNames = info.attributeOperations.filter(operation => operation.kind === 'receive').map(operation => fixture.definitions()[operation.attributeId].name);
    assert.ok(!workstationNames.some(name => /device_code|client_secret|(?:id|access)_token/.test(name)));
    checked++;
  }
  assert.ok(checked >= 5);
  assert.deepEqual([...promptCounts].sort(), [0, 1]);
});

test('F17: denied account has a concrete denying host policy and exact result while certificate/key proof remain valid', () => {
  const fixture = model('lab-ssh-cert-account'), check = stage(fixture, 'host-policy');
  const result = named(fixture, check, 'PAM/account access result (local)', 'verify');
  assert.match(result.value, /denied/i);
  assert.ok(!/access allowed/i.test(result.value));
  const state = stateAt(fixture, indexOf(fixture, check));
  assert.equal(state.policy.hostAccountAccess.allowed, false);
  assert.ok(state.policy.hostAccountAccess.rule, 'A named supporting access rule is configured');
  assert.equal(state.hostChecks.certificateSignatureAccepted, true);
  assert.equal(state.hostChecks.possessionProofAccepted, true);
  assert.equal(state.hostChecks.principalAccountMapped, true);
  assert.equal(state.hostChecks.accountAccessAllowed, false);
  assert.equal(state.sessions.ssh.authenticated, false);
  assert.ok(!steps(fixture).some(step => step.sshStage === 'ssh-success' || step.sshStage === 'channel'));
  assertFocusedOccurrence(fixture, { ...result, step: check });
  const happy = model('lab-ssh-cert-success');
  assert.match(named(happy, stage(happy, 'host-policy'), 'PAM/account access result (local)', 'verify').value, /access allowed/i);
});

