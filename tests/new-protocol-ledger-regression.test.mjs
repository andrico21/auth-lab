import test from 'node:test';
import assert from 'node:assert/strict';
import { FORESTLAB_SCENARIOS } from '../src/kerberos-forest-lab.js';
import { ADLAB_SCENARIOS } from '../src/kerberos-ad-lab.js';
import { CRYPTOLAB_SCENARIOS } from '../src/kerberos-crypto-lab.js';
import { SSHLAB_SCENARIOS } from '../src/ssh-access-lab.js';
import { buildProtocolInstances, reconstructProtocolState, validateProtocolScenario } from '../src/protocol-state.js';
import { projectScenarioContext } from '../src/scenario-context.js';

const forestModel = id => FORESTLAB_SCENARIOS.find(model => model.id === id);
const adModel = id => ADLAB_SCENARIOS.find(model => model.id === id);
const cryptoModel = id => CRYPTOLAB_SCENARIOS.find(model => model.id === id);
const sshModel = id => SSHLAB_SCENARIOS.find(model => model.id === id);
const finalState = model => reconstructProtocolState(model, model.steps().length - 1);

for (const model of [...ADLAB_SCENARIOS, ...CRYPTOLAB_SCENARIOS, ...FORESTLAB_SCENARIOS, ...SSHLAB_SCENARIOS]) test(`${model.id}: every source prefix reconstructs stable frozen state and exact objects`, () => {
  const validation = validateProtocolScenario(model);
  assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  const sourceBefore = JSON.stringify({ initialState: model.initialState, steps: model.steps(), protocolValues: model.protocolValues });
  for (let index = -1; index < model.steps().length; index++) {
    const state = reconstructProtocolState(model, index);
    const objects = buildProtocolInstances(model, index);
    assert.ok(Object.isFrozen(state));
    assert.ok(Object.isFrozen(objects));
    assert.deepEqual(reconstructProtocolState(model, index), state);
    assert.deepEqual(buildProtocolInstances(model, index), objects);
    assert.ok(objects.flatMap(object => object.occurrences).every(occurrence => occurrence.eventIndex <= index));
  }
  assert.equal(JSON.stringify({ initialState: model.initialState, steps: model.steps(), protocolValues: model.protocolValues }), sourceBefore, 'inspection and replay leave authored source data intact');
});

test('child-to-child forest route preserves original identity across every client-driven referral', () => {
  const model = forestModel('lab-ad-forest-child-domains');
  const before = reconstructProtocolState(model, -1);
  assert.deepEqual(Object.keys(before.credentials), ['home'], 'no usable referral or service credential shortcuts the intro');
  const last = finalState(model);
  assert.deepEqual(last.knowledge.workstation.route, ['a.example', 'b.example', 'us.b.example']);
  assert.equal(last.identity.cname, 'alice');
  assert.equal(last.identity.crealm, 'EU.A.EXAMPLE');
  for (const credential of Object.values(last.credentials)) {
    assert.equal(credential.cname, 'alice');
    assert.equal(credential.crealm, 'EU.A.EXAMPLE');
  }
  const referralRequests = model.steps().filter(step => /-request-referral-[123]$/.test(step.id));
  const actors = model.actors();
  assert.deepEqual(referralRequests.map(step => [step.from, actors[step.to]?.parentId || step.to]), [
    ['workstation', 'kdcHome'], ['workstation', 'kdcRootA'], ['workstation', 'kdcRootB'],
  ]);
  assert.equal(last.credentials.service.issuerRealm, 'US.B.EXAMPLE');
  assert.equal(last.access.resource, 'allowed');
});

test('selective authentication, invalid PAC and resource ACL are distinct rejecting authorities and stages', () => {
  for (const id of ['lab-ad-forest-selective-denied', 'lab-ad-forest-invalid-pac']) {
    const model = forestModel(id), last = finalState(model);
    assert.equal(last.credentials.service, undefined);
    assert.equal(last.sessions.service, undefined);
    assert.ok(!model.steps().some(step => step.id.endsWith('-ap-request')));
    const failureActorId = last.knowledge.workstation.failure.actorId;
    assert.equal(model.actors()[failureActorId]?.parentId || failureActorId, 'kdcResource');
    assert.notEqual(last.access.resource, 'allowed');
  }
  const acl = finalState(forestModel('lab-ad-forest-acl-denied'));
  assert.ok(acl.credentials.service);
  assert.equal(acl.sessions.service.authenticated, true);
  assert.equal(acl.knowledge.service.authenticated, true);
  assert.equal(acl.access.resource, 'denied');
});

test('a chain of separate forest trusts does not invent access; explicit direct trust grants only its configured direction', () => {
  const denied = forestModel('lab-ad-forest-three-denied');
  const deniedState = finalState(denied);
  assert.equal(deniedState.credentials.service, undefined);
  assert.equal(deniedState.sessions.service, undefined);
  assert.notEqual(deniedState.access.resource, 'allowed');
  const direct = finalState(forestModel('lab-ad-forest-three-direct'));
  assert.equal(direct.credentials.service.targetRealm, 'C.EXAMPLE');
  assert.equal(direct.access.resource, 'allowed');
  const reverse = finalState(forestModel('lab-ad-forest-one-way-reverse'));
  assert.equal(reverse.credentials.service, undefined);
  assert.equal(reverse.sessions.service, undefined);
});

test('cached forest credentials retain their identities while fresh service proof has its own instance', () => {
  const model = forestModel('lab-ad-forest-cached-service');
  const initial = reconstructProtocolState(model, -1), last = finalState(model);
  assert.equal(last.credentials.service.id, initial.credentials.service.id);
  assert.equal(last.credentials.service.ticketBytes, initial.credentials.service.ticketBytes);
  assert.deepEqual(last.cache.workstation, initial.cache.workstation);
  assert.ok(!model.steps().some(step => /-request-(?:referral-\d|service)$/.test(step.id)));
  const credentialRecord = buildProtocolInstances(model, model.steps().length - 1).find(instance => instance.instanceId === initial.credentials.service.id);
  assert.ok(credentialRecord);
  assert.ok(credentialRecord.occurrences.every(occurrence => occurrence.sourceEventId === 'initial'));
  assert.ok(!credentialRecord.occurrences.some(occurrence => occurrence.kind === 'create'));
  assert.equal(last.replayCache.service.length, 1);
  assert.notEqual(last.replayCache.service[0], initial.credentials.service.id);
});

test('runtime scalar binding preserves acquisition chronology and never changes unrelated scalar occurrences', () => {
  const model = {
    initialState: { policy: { servicePrincipal: 'HTTP/files.example' }, credentials: {} },
    runtimeBindings: [{ field: 'servicePrincipal', attributeId: 'spn', example: 'HTTP/files.example', statePaths: ['policy.servicePrincipal', 'credentials.service.sname'] }],
  };
  const steps = [
    { id: 'request', payload: [{ attributeId: 'spn', value: 'HTTP/files.example' }, { attributeId: 'spn', value: 'host/ws.example' }], attributeOperations: [{ attributeId: 'spn', value: 'HTTP/files.example', representation: 'local-decoded' }] },
    { id: 'issue', protocolEffects: [{ op: 'put', path: 'credentials.service', value: { sname: 'HTTP/files.example', ticket: 'opaque-original-1' } }] },
  ];
  const projected = projectScenarioContext(model, steps, { servicePrincipal: 'HTTP/corp.example' });
  assert.deepEqual(projected.initialState.credentials, {});
  assert.equal(projected.steps[0].payload[0].value, 'HTTP/corp.example');
  assert.equal(projected.steps[0].payload[1].value, 'host/ws.example');
  assert.equal(projected.steps[1].protocolEffects[0].value.sname, 'HTTP/corp.example');
  assert.equal(projected.steps[1].protocolEffects[0].value.ticket, 'opaque-original-1');
  const projectedModel = { ...model, ...projected, steps: () => projected.steps };
  assert.equal(reconstructProtocolState(projectedModel, 0).credentials.service, undefined);
  assert.equal(reconstructProtocolState(projectedModel, 1).credentials.service.sname, 'HTTP/corp.example');
  assert.equal(steps[0].payload[0].value, 'HTTP/files.example');
  assert.deepEqual(model.initialState.credentials, {});
});

test('runtime projection does not patch an opaque operation merely because its attribute id matches a scalar binding', () => {
  const model = { initialState: {}, runtimeBindings: [{ field: 'kerberosRealm', attributeId: 'realm', example: 'A.EXAMPLE' }] };
  const steps = [{ id: 'opaque', attributeOperations: [
    { attributeId: 'realm', instanceId: 'request', fieldPath: 'realm', representation: 'wire-field', value: 'A.EXAMPLE' },
    { attributeId: 'realm', instanceId: 'opaque-ticket', fieldPath: 'Ticket.enc-part', representation: 'opaque-ciphertext', value: 'A.EXAMPLE' },
    { attributeId: 'realm', instanceId: 'signed-certificate', fieldPath: 'signature', representation: 'signed-wire-bytes', value: 'A.EXAMPLE' },
  ] }];
  const projected = projectScenarioContext(model, steps, { kerberosRealm: 'B.EXAMPLE' });
  assert.equal(projected.steps[0].attributeOperations[0].value, 'B.EXAMPLE');
  assert.equal(projected.steps[0].attributeOperations[1].value, 'A.EXAMPLE');
  assert.equal(projected.steps[0].attributeOperations[2].value, 'A.EXAMPLE');
});

test('R1 real AD preset: unknown SPN stops at the KDC and leaves unrelated credentials intact', () => {
  const model = adModel('lab-ad-unknown-spn');
  const before = reconstructProtocolState(model, -1), after = finalState(model);
  assert.equal(after.failure.actorId, 'adKdc');
  assert.equal(after.failure.stage, 'ticket-acquisition');
  assert.ok(model.steps().some(step => step.id === after.failure.eventId));
  assert.equal(after.credentials.service, undefined);
  assert.equal(after.proofs.ap, undefined);
  assert.ok(!model.steps().some(step => step.id.endsWith('-ap-request')));
  assert.equal(after.sessions.serviceAuthenticated, false);
  assert.equal(after.sessions.resourceAccess, false);
  assert.deepEqual(after.credentials.tgt, before.credentials.tgt);
  assert.deepEqual(after.credentials.unrelated, before.credentials.unrelated);
});

test('R1 real AD preset: stale acceptor key is checked only after issuance, caching and AP presentation', () => {
  const model = adModel('lab-ad-stale-service-key');
  const steps = model.steps(), cacheIndex = steps.findIndex(step => step.id.endsWith('-service-cache'));
  const apIndex = steps.findIndex(step => step.id.endsWith('-ap-request'));
  const rejectIndex = steps.findIndex(step => step.id.endsWith('-acceptor-reject'));
  assert.ok(cacheIndex >= 0 && apIndex > cacheIndex && rejectIndex > apIndex);
  const initial = reconstructProtocolState(model, -1), cached = reconstructProtocolState(model, cacheIndex);
  assert.equal(initial.credentials.service, undefined);
  assert.ok(cached.credentials.service);
  assert.equal(cached.failure, undefined, 'static inspector knowledge of the stale key does not cause an early KDC/client rejection');
  const presented = reconstructProtocolState(model, apIndex);
  assert.equal(presented.proofs.ap.ticketInstanceId, cached.credentials.service.ticketInstanceId);
  const rejected = reconstructProtocolState(model, rejectIndex);
  assert.deepEqual(rejected.credentials.service, cached.credentials.service);
  assert.equal(rejected.failure.actorId, 'adService');
  assert.equal(rejected.failure.eventId, steps[rejectIndex].id);
  assert.equal(rejected.sessions.serviceAuthenticated, false);
  assert.equal(rejected.sessions.resourceAccess, false);
  assert.equal(rejected.proofs.apReply, undefined);
  assert.equal(rejected.knowledge.adWorkstation.failure, undefined);
  assert.equal(finalState(model).knowledge.adWorkstation.failure, 'stale');
  assert.equal(reconstructProtocolState(model, cacheIndex).knowledge.adWorkstation.failure, undefined, 'rewind removes delivered failure knowledge');
});

test('PKINIT uses independent signed and KDC request nonces and keeps private key material out of network packets', () => {
  const model = cryptoModel('lab-ad-pkinit-success'), definitions = model.definitions();
  const allOperations = model.steps().flatMap(step => step.attributeOperations);
  const bodyNonce = allOperations.find(operation => operation.fieldPath === 'KDC-REQ-BODY.nonce');
  const signedNonce = allOperations.find(operation => operation.fieldPath === 'AuthPack.pkAuthenticator.nonce');
  assert.ok(bodyNonce && signedNonce);
  assert.notEqual(bodyNonce.value, signedNonce.value);
  assert.ok(allOperations.some(operation => operation.kind === 'verify' && operation.actorId === 'cryptoClient' && operation.fieldPath === 'EncASRepPart.nonce' && operation.value === bodyNonce.value));
  for (const step of model.steps().filter(step => step.channel === 'backchannel')) {
    for (const operation of step.attributeOperations.filter(operation => ['send', 'receive'].includes(operation.kind))) {
      assert.equal(definitions[operation.attributeId].localOnly, false, `${step.id} may not put a local secret on the network`);
    }
  }
  const state = finalState(model);
  assert.equal(state.keys.asReplyClient.instanceId, state.keys.asReplyKdc.instanceId);
  assert.notEqual(state.keys.asReplyClient.instanceId, state.credentials.userTgt.sessionKeyInstanceId);
  assert.equal(state.sessions.service.authenticated, true);
  const names = Object.values(definitions).map(definition => definition.name);
  for (const omitted of ['clientDHNonce', 'serverDHNonce', 'dhKeyExpiration']) assert.ok(!names.includes(omitted), `fresh non-reused DH omits ${omitted}`);
});

test('FAST checksum failure stops before decoding the protected authoritative inner request', () => {
  const model = cryptoModel('lab-ad-fast-as-checksum');
  const failedCheck = model.steps().find(step => step.labCryptoStage === 'request-binding');
  assert.ok(failedCheck);
  assert.ok(failedCheck.attributeOperations.some(operation => operation.kind === 'verify' && operation.fieldPath === 'KrbFastArmoredReq.req-checksum'));
  assert.ok(!failedCheck.attributeOperations.some(operation => operation.actorId === 'cryptoKdc' && operation.fieldPath.startsWith('KrbFastReq.')), 'a rejected bound checksum cannot expose/process the decoded inner body');
  const last = finalState(model);
  assert.equal(last.checks.fastRequestBinding, false);
  assert.equal(last.checks.userChallenge, undefined);
  assert.equal(last.credentials.userTgt, undefined);
  assert.ok(last.credentials.computerTgt);
});

test('FAST computer bootstrap exception does not grant a user ticket and ordinary TGS uses its mandatory subkey', () => {
  const bootstrap = finalState(cryptoModel('lab-ad-fast-as-bootstrap'));
  assert.equal(bootstrap.policy.kdcEnforceFAST, true);
  assert.equal(bootstrap.checks.bootstrapExceptionApplied, true);
  assert.ok(bootstrap.credentials.computerTgt);
  assert.equal(bootstrap.credentials.userTgt, undefined);
  const tgs = finalState(cryptoModel('lab-ad-fast-tgs-success'));
  assert.equal(tgs.keys.originalReplyClient.source, 'TGS authenticator subkey');
  assert.notEqual(tgs.keys.armorClient.instanceId, tgs.keys.originalReplyClient.instanceId);
  assert.notEqual(tgs.keys.finalReplyClient.instanceId, tgs.keys.originalReplyClient.instanceId);
  assert.equal(tgs.checks.fastStrengthenPresent, true);
  assert.ok(tgs.credentials.service);
});

test('native SSH enrollment and SSH user proof have separate recipient, key and transport boundaries', () => {
  const model = sshModel('lab-ssh-cert-success'), definitions = model.definitions(), steps = model.steps();
  const named = (stage, name, kind) => steps.find(step => step.sshStage === stage).attributeOperations.find(operation => definitions[operation.attributeId]?.name === name && (!kind || operation.kind === kind));
  assert.equal(named('ca-identity', 'aud', 'verify').value, 'step-ssh');
  assert.notEqual(named('ca-identity', 'aud', 'verify').value, finalState(model).target.caURL);
  const enrollment = steps.find(step => step.sshStage === 'enroll');
  const transmittedEnrollmentNames = enrollment.attributeOperations.filter(operation => operation.kind === 'send').map(operation => definitions[operation.attributeId].name);
  assert.ok(transmittedEnrollmentNames.includes('publicKey'));
  assert.ok(transmittedEnrollmentNames.includes('ott'));
  assert.ok(!transmittedEnrollmentNames.some(name => /signature|CSR|private key/i.test(name)), 'CA enrollment does not invent mandatory private-key possession proof');
  const token = named('tokens', 'id_token', 'send'), ott = named('enroll', 'ott', 'send');
  assert.equal(ott.value, token.value);
  assert.equal(ott.instanceId, token.instanceId);
  const userauth = steps.find(step => step.sshStage === 'userauth');
  const userauthOperations = userauth.attributeOperations.filter(operation => operation.kind === 'send');
  const userauthNames = userauthOperations.map(operation => definitions[operation.attributeId].name);
  assert.ok(!userauthNames.some(name => /session identifier|id_token|access_token|device_code|private key/i.test(name)));
  assert.ok(userauthNames.some(name => /^signature\b/.test(name)));
  const issuedCert = named('certificate', 'crt', 'send');
  const certAtHost = userauthOperations.find(operation => operation.instanceId === issuedCert.instanceId);
  assert.ok(certAtHost);
  assert.equal(certAtHost.value, issuedCert.value);
  for (const step of steps.filter(step => step.interactionType === 'network')) {
    assert.ok(!step.attributeOperations.some(operation => operation.kind === 'send' && /private key/i.test(definitions[operation.attributeId].name)), `${step.id} cannot send a private key to a network peer`);
  }
  assert.equal(finalState(model).sessions.ssh.authenticated, true);
});

test('wrong-audience SSH enrollment uses a separate foreign token after normal CLI validation', () => {
  const model = sshModel('lab-ssh-cert-audience'), definitions = model.definitions();
  const getAud = stage => model.steps().find(step => step.sshStage === stage).attributeOperations.find(operation => definitions[operation.attributeId]?.name === 'aud');
  const normal = getAud('validate-identity'), ca = getAud('ca-identity');
  assert.equal(normal.value, 'step-ssh');
  assert.equal(ca.value, 'another-client');
  assert.notEqual(ca.instanceId, normal.instanceId);
  assert.equal(finalState(model).failure.actor, 'sshCa');
  assert.equal(finalState(model).credentials.userCertificate, undefined);
});

test('Device reference honors default interval, repeated slow_down and timeout backoff using only protocol time', () => {
  const model = sshModel('lab-ssh-device-cadence'), steps = model.steps();
  const at = stage => reconstructProtocolState(model, steps.findIndex(step => step.sshStage === stage));
  assert.equal(at('default-interval').transaction.pollInterval, 5);
  assert.equal(at('apply-slow-1').transaction.pollInterval, 10);
  assert.equal(at('apply-slow-2').transaction.pollInterval, 15);
  assert.equal(at('backoff').transaction.pollInterval, 30);
  const expectedDelays = [['poll-1', 5], ['poll-2', 5], ['poll-3', 10], ['poll-4', 15], ['final-poll', 30]];
  let previousClock = reconstructProtocolState(model, -1).protocolClock;
  for (const [stage, delay] of expectedDelays) {
    const state = at(stage);
    assert.equal(state.protocolClock - previousClock, delay);
    previousClock = state.protocolClock;
  }
  const response = steps.find(step => step.sshStage === 'response');
  assert.ok(!response.payload.some(field => /^interval/.test(field.name)), 'omitted interval is a local default, not an invented response parameter');
});

test('Device cancellation rejects an in-flight successful result without accepting credentials or resuming polls', () => {
  const model = sshModel('lab-ssh-device-cancel'), last = finalState(model);
  assert.equal(last.transaction.status, 'cancelled');
  assert.equal(last.transaction.lateResultIgnored, true);
  assert.equal(last.credentials.idToken, undefined);
  assert.equal(last.credentials.userCertificate, undefined);
  assert.equal(last.sessions.ssh.authenticated, false);
  const cancelled = model.steps().findIndex(step => step.sshStage === 'cancel');
  assert.ok(!model.steps().slice(cancelled + 1).some(step => step.from === 'sshCli' && ['sshIdp', 'sshCa'].includes(step.to)));
});

test('remote SSSD owns Device authorization while SSH instructions contain only public human fields', () => {
  const model = sshModel('lab-ssh-sssd-success'), definitions = model.definitions();
  const deviceRequest = model.steps().find(step => step.sshStage === 'device-request');
  const poll = model.steps().find(step => step.sshStage === 'poll');
  assert.deepEqual([deviceRequest.from, deviceRequest.to], ['sssd', 'sshIdp']);
  assert.deepEqual([poll.from, poll.to], ['sssd', 'sshIdp']);
  const humanStages = new Set(['ssh-info', 'terminal-display', 'browser-open', 'browser-approve', 'conversation-response']);
  for (const step of model.steps().filter(step => humanStages.has(step.sshStage))) {
    assert.ok(!step.attributeOperations.some(operation => operation.kind === 'send' && /device_code|client_secret|access_token|id_token|Authorization/.test(definitions[operation.attributeId].name)), `${step.id} cannot expose the remote client's private credentials`);
  }
  const response = model.steps().find(step => step.sshStage === 'conversation-response').payload[0].value;
  assert.deepEqual(response, { num_responses: 1, responses: [''] });
  const state = finalState(model);
  assert.equal(state.credentials.interactiveToken.holder, 'sssd');
  assert.equal(state.policy.createLocalAccount, false);
  assert.equal(state.policy.createHome, false);
  assert.equal(state.policy.createKerberosTgt, false);
  assert.equal(state.sessions.ssh.authenticated, true);
});

test('browser approval of Bob or a same-name foreign identity cannot authenticate requested Alice at SSH', () => {
  for (const id of ['lab-ssh-sssd-bob', 'lab-ssh-sssd-domain']) {
    const model = sshModel(id), state = finalState(model);
    assert.equal(state.transaction.approved, true);
    assert.equal(state.transaction.status, 'complete');
    assert.equal(state.identityMatched, false);
    assert.equal(state.sessions.ssh.authenticated, false);
    assert.equal(state.sessions.ssh.channels, 0);
    assert.equal(state.failure.actor, 'sssd');
    assert.ok(!model.steps().some(step => step.sshStage === 'ssh-success' || step.sshStage === 'channel'));
  }
});

test('published revocation, installed host knowledge and an established SSH session keep independent histories', () => {
  const model = sshModel('lab-ssh-cert-lifecycle'), steps = model.steps();
  const at = stage => reconstructProtocolState(model, steps.findIndex(step => step.sshStage === stage));
  const published = at('publish-revocation'), installed = at('install-revocation');
  assert.deepEqual(published.authorities.ca.publishedRevocations, [1]);
  assert.deepEqual(published.knowledge.host.revokedSerials, []);
  assert.deepEqual(installed.knowledge.host.revokedSerials, [1]);
  assert.equal(installed.sessions.ssh.authenticated, true);
  assert.deepEqual(at('publish-revocation').knowledge.host.revokedSerials, [], 'backward seek removes future host knowledge');
  const after = finalState(model);
  assert.equal(after.sessions.idp.authenticated, false);
  assert.equal(after.credentials.idToken.status, 'expired');
  assert.equal(after.credentials.userCertificate.status, 'expired');
  assert.equal(after.sessions.ssh.authenticated, true);
  assert.equal(after.sessions.ssh.channels, 2, 'an additional channel need not repeat SSH user authentication');
});

test('Keycloak primary-only Alternative success is not relabeled MFA by optional token claims', () => {
  const model = adModel('lab-kc-kerberos-alternative-otp-skip'), state = finalState(model);
  assert.equal(state.assurance.primary.method, 'Kerberos');
  assert.equal(state.assurance.factor, undefined);
  assert.equal(state.assurance.factorSkipped, 'Forms path not entered');
  assert.equal(state.sessions.applicationAuthenticated, true);
  const tokenFields = model.steps().find(step => step.id.endsWith('-token-create')).fields;
  assert.ok(!tokenFields.includes('adACR'));
  assert.ok(!tokenFields.includes('adAMR'));
});

test('fresh factor belongs to the current OIDC transaction and age-bounded reuse preserves prior ceremony identity', () => {
  for (const id of ['lab-kc-kerberos-fresh-totp', 'lab-kc-password-fresh-totp', 'lab-kc-cookie-fresh-factor']) {
    const model = adModel(id), state = finalState(model);
    assert.equal(state.assurance.factor.freshFor, state.transactions.oidc.instanceId);
    assert.equal(state.transactions.provider.oidcTransactionId, state.transactions.oidc.instanceId);
    assert.equal(state.transactions.provider.pending, false);
    assert.equal(state.transactions.code.consumed, true);
    assert.equal(state.sessions.applicationAuthenticated, true);
    assert.ok(model.steps().some(step => step.id.endsWith('-totp-check')));
    assert.ok(!model.steps().some(step => step.attributeOperations.some(operation => ['send', 'receive'].includes(operation.kind) && operation.attributeId === 'adFlowPolicy')), 'realm flow policy is local state, not a transmitted factor-form parameter');
  }
  const reuse = adModel('lab-kc-cookie-age-reuse'), reusedState = finalState(reuse);
  assert.equal(reusedState.assurance.reusedFactor, true);
  assert.notEqual(reusedState.assurance.factor.freshFor, reusedState.transactions.oidc.instanceId);
  assert.ok(!reuse.steps().some(step => step.id.endsWith('-totp-create') || step.id.endsWith('-totp-check')));
});

test('failed required factors and unsupported/silent assurance produce no code or application success', () => {
  for (const id of ['lab-kc-factor-unenrolled', 'lab-kc-factor-failed', 'lab-kc-factor-cancelled', 'lab-kc-webauthn-uv-policy-fail', 'lab-kc-unsupported-assurance', 'lab-kc-prompt-none-factor-required']) {
    const model = adModel(id), state = finalState(model);
    assert.equal(state.sessions.applicationAuthenticated, false);
    assert.equal(state.transactions.code, undefined);
    assert.ok(!model.steps().some(step => step.id.endsWith('-token-create') || step.id.endsWith('-app-validate')));
  }
});

test('successful certificate reissuance creates a new serial/window and token while preserving the existing key identity', () => {
  const model = sshModel('lab-ssh-cert-reissue'), steps = model.steps();
  const firstIndex = steps.findIndex(step => step.sshStage === 'channel');
  const original = reconstructProtocolState(model, firstIndex), reissued = finalState(model);
  assert.equal(original.credentials.userCertificate.serial, 1);
  assert.equal(reissued.credentials.userCertificate.serial, 2);
  assert.notEqual(reissued.credentials.userCertificate.instanceId, original.credentials.userCertificate.instanceId);
  assert.notEqual(reissued.credentials.userCertificate.validBefore, original.credentials.userCertificate.validBefore);
  assert.equal(reissued.credentials.userKey.instanceId, original.credentials.userKey.instanceId);
  assert.equal(reissued.credentials.userCertificate.publicKeyInstance, original.credentials.userKey.instanceId);
  assert.notEqual(reissued.credentials.idToken.instanceId, original.credentials.idToken.instanceId);
  assert.notEqual(reissued.transaction.instanceId, original.transaction.instanceId);
  assert.deepEqual(reissued.transaction.factors, ['pwd', 'otp']);
  assert.ok(steps.some(step => step.sshStage === 'reissue-factor-check'));
  assert.ok(steps.some(step => step.sshStage === 'reissue-redeem'));
  assert.equal(reconstructProtocolState(model, firstIndex).credentials.userCertificate.serial, 1, 'reissuance does not rewrite past issued credentials');
  const certObjects = buildProtocolInstances(model, steps.length - 1).filter(instance => instance.instanceId.endsWith(':certificate-1') || instance.instanceId.endsWith(':certificate-2'));
  assert.equal(certObjects.length, 2);
});

test('runtime account context regenerates a separate valid fixture and preserves original source objects', () => {
  for (const base of SSHLAB_SCENARIOS) {
    const sourceBefore = JSON.stringify({ initialState: base.initialState, steps: base.steps(), definitions: base.definitions() });
    const contextual = base.contextualize({ unixAccount: 'bob' });
    assert.notEqual(contextual, base);
    const validation = validateProtocolScenario(contextual);
    assert.equal(validation.valid, true, `${base.id}: ${JSON.stringify(validation.errors)}`);
    for (let index = -1; index < contextual.steps().length; index++) {
      reconstructProtocolState(contextual, index);
      buildProtocolInstances(contextual, index);
    }
    assert.equal(JSON.stringify({ initialState: base.initialState, steps: base.steps(), definitions: base.definitions() }), sourceBefore);
  }
  const base = sshModel('lab-ssh-cert-success'), fresh = base.contextualize({ unixAccount: 'bob' });
  const original = finalState(base), contextual = finalState(fresh);
  assert.deepEqual(original.credentials.userCertificate.principals, ['alice']);
  assert.deepEqual(contextual.credentials.userCertificate.principals, ['bob']);
  const certificateBytes = model => model.steps().find(step => step.sshStage === 'certificate').payload[0].value;
  assert.notEqual(certificateBytes(fresh), certificateBytes(base), 'signed-container fixture bytes are regenerated for its explicit example principal');
  assert.equal(contextual.credentials.idToken.audience, 'step-ssh');
  assert.equal(fresh.contextualize({ unixAccount: 'alice' }), base);
});

test('fixture namespaces distinguish rebuilt local identities without mutating object references or exact bytes', () => {
  const base = sshModel('lab-ssh-cert-success'), index = base.steps().length - 1;
  const oldScope = { ...base, instanceScope: `${base.id}@context-1` };
  const newScope = { ...base, instanceScope: `${base.id}@context-2` };
  const oldRecord = buildProtocolInstances(oldScope, index).find(instance => instance.instanceId.endsWith(':certificate-1'));
  const newRecord = buildProtocolInstances(newScope, index).find(instance => instance.instanceId === oldRecord.instanceId);
  assert.equal(oldRecord.instanceId, newRecord.instanceId);
  assert.notEqual(oldRecord.qualifiedInstanceId, newRecord.qualifiedInstanceId);
  assert.equal(oldRecord.instanceScope, oldScope.instanceScope);
  assert.ok(oldRecord.occurrences.every(occurrence => occurrence.instanceScope === oldScope.instanceScope));
  assert.deepEqual(oldRecord.occurrences.map(occurrence => occurrence.value), newRecord.occurrences.map(occurrence => occurrence.value));
  assert.deepEqual(reconstructProtocolState(oldScope, index), reconstructProtocolState(newScope, index));
});
