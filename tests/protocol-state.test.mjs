import test from 'node:test';
import assert from 'node:assert/strict';
import { PROTOCOL_STATE_DEFAULTS, reconstructProtocolState, buildProtocolInstances, validateProtocolScenario } from '../src/protocol-state.js';

const put = (path, value) => ({ op: 'put', path, value });
const remove = path => ({ op: 'remove', path });
const event = (id, effects = [], operations = []) => ({ id, protocolEffects: effects, attributeOperations: operations });
const model = (initialState, steps, extra = {}) => ({ initialState, steps: () => steps, ...extra });
const tgt = { instanceId: 'home-tgt-1', client: 'alice@A.EXAMPLE', service: 'krbtgt/A.EXAMPLE', expires: 800 };
const unrelated = { instanceId: 'other-service-ticket', service: 'cifs/files.a.example' };
const targetTicket = { instanceId: 'http-ticket-1', client: 'alice@A.EXAMPLE', service: 'HTTP/web.a.example', encKeyVersion: 7, expires: 500 };

function unknownSpnFixture() {
  return model({ credentials: { tgt, unrelated }, caches: { serviceTickets: { unrelated } } }, [
    event('request-unknown-spn', [put('pending.tgs', { spn: 'HTTP/unknown.a.example' })]),
    event('kdc-rejects-unknown-spn', [remove('pending.tgs'), put('outcome', { actorId: 'kdc', error: 'unknown-service-principal', access: false })]),
  ]);
}

function acceptorKeyMismatchFixture() {
  return model({ credentials: { tgt, unrelated }, policy: { serviceKeyVersion: 6 }, knowledge: { client: {} } }, [
    event('request-valid-spn', [put('pending.tgs', { spn: 'HTTP/web.a.example' })]),
    event('kdc-issues-target-ticket', [put('credentials.target', targetTicket), remove('pending.tgs')]),
    event('client-validates-and-caches', [put('caches.serviceTickets.target', targetTicket)]),
    event('fresh-ap-req', [put('pending.serviceProof', { ticketInstanceId: 'http-ticket-1', authenticatorInstanceId: 'authenticator-1', nonce: 'auth-001' })]),
    event('acceptor-decrypts-and-rejects', [put('outcome', { actorId: 'service', error: 'ticket-key-mismatch', authenticatedContext: false, apRep: false, access: false })]),
    event('client-receives-failure', [put('knowledge.client.serviceFailure', 'ticket-key-mismatch')]),
  ]);
}

test('initial state is cloned and frozen, with stable defaults and no source events applied', () => {
  const fixture = acceptorKeyMismatchFixture();
  const before = reconstructProtocolState(fixture, -1);
  assert.equal(before.protocolClock, 0);
  assert.deepEqual(before.credentials.tgt, tgt);
  assert.equal(before.credentials.target, undefined);
  assert.equal(before.outcome.access, undefined);
  assert.ok(Object.isFrozen(before));
  assert.ok(Object.isFrozen(before.credentials.tgt));
  assert.notEqual(before.credentials.tgt, fixture.initialState.credentials.tgt);
  assert.throws(() => { before.credentials.tgt.expires = 2; }, TypeError);
  assert.equal(fixture.initialState.credentials.tgt.expires, 800);
  assert.ok(Object.isFrozen(PROTOCOL_STATE_DEFAULTS));
});

test('R1: unknown SPN fails at acquisition without a target cache entry or AP-REQ', () => {
  const fixture = unknownSpnFixture();
  const rejected = reconstructProtocolState(fixture, 1);
  assert.deepEqual(rejected.outcome, { actorId: 'kdc', error: 'unknown-service-principal', access: false });
  assert.equal(rejected.credentials.target, undefined);
  assert.equal(rejected.caches.serviceTickets.target, undefined);
  assert.equal(rejected.pending.serviceProof, undefined);
  assert.deepEqual(rejected.credentials.tgt, tgt);
  assert.deepEqual(rejected.credentials.unrelated, unrelated);
  assert.deepEqual(rejected.caches.serviceTickets.unrelated, unrelated);
});

test('R1: stale acceptor key does not prevent successful TGS acquisition, caching or fresh AP-REQ', () => {
  const fixture = acceptorKeyMismatchFixture();
  const acquired = reconstructProtocolState(fixture, 1);
  assert.deepEqual(acquired.credentials.target, targetTicket);
  assert.equal(acquired.outcome.error, undefined);
  const cached = reconstructProtocolState(fixture, 2);
  assert.deepEqual(cached.caches.serviceTickets.target, targetTicket);
  assert.equal(cached.pending.serviceProof, undefined);
  const presented = reconstructProtocolState(fixture, 3);
  assert.equal(presented.pending.serviceProof.ticketInstanceId, targetTicket.instanceId);
  assert.equal(presented.pending.serviceProof.authenticatorInstanceId, 'authenticator-1');
  assert.equal(presented.outcome.error, undefined);
  assert.equal(presented.knowledge.client.serviceFailure, undefined);
});

test('R1: service rejection retains the issued cached credential and knowledge is delivered later', () => {
  const fixture = acceptorKeyMismatchFixture();
  const rejected = reconstructProtocolState(fixture, 4);
  assert.deepEqual(rejected.outcome, { actorId: 'service', error: 'ticket-key-mismatch', authenticatedContext: false, apRep: false, access: false });
  assert.deepEqual(rejected.credentials.target, targetTicket);
  assert.deepEqual(rejected.caches.serviceTickets.target, targetTicket);
  assert.deepEqual(rejected.credentials.unrelated, unrelated);
  assert.equal(rejected.knowledge.client.serviceFailure, undefined, 'the client cannot know the local acceptor result before its response');
  assert.equal(reconstructProtocolState(fixture, 5).knowledge.client.serviceFailure, 'ticket-key-mismatch');
  assert.equal(reconstructProtocolState(fixture, 2).knowledge.client.serviceFailure, undefined, 'seeking backwards removes future knowledge');
});

test('full, direct seek, field and link projections reconstruct the same complete source prefix', () => {
  for (const fixture of [unknownSpnFixture(), acceptorKeyMismatchFixture()]) {
    const sourceIndex = fixture.steps().length - 1;
    const projection = { sourceIndex, sourceStepId: fixture.steps()[sourceIndex].id, fields: ['enc-part'] };
    const full = reconstructProtocolState(fixture, sourceIndex);
    const seek = reconstructProtocolState(fixture, sourceIndex);
    const field = reconstructProtocolState(fixture, projection.sourceIndex);
    const link = reconstructProtocolState(fixture, projection.sourceIndex);
    assert.deepEqual(seek, full);
    assert.deepEqual(field, full);
    assert.deepEqual(link, full);
    assert.equal(field.credentials.tgt.instanceId, 'home-tgt-1', 'earlier hidden credential acquisition remains in the source history');
  }
});

test('protocol time advances only through explicit source events, independently of visual replay', () => {
  const fixture = model({ protocolClock: 1700000000 }, [
    event('enroll', [put('credentials.sshCertificate', { instanceId: 'cert-1', validBefore: 1700000060 })]),
    event('wait', [{ op: 'advance', value: 60 }]),
    event('expired-new-login', [put('outcome', { newLogin: 'denied-expired' })]),
  ]);
  assert.equal(reconstructProtocolState(fixture, 0).protocolClock, 1700000000);
  assert.equal(reconstructProtocolState(fixture, 1).protocolClock, 1700000060);
  for (const speed of [0, .01, 1, 4]) {
    const filteredVisual = { speed, sourceIndex: 1 };
    assert.equal(reconstructProtocolState(fixture, filteredVisual.sourceIndex).protocolClock, 1700000060);
  }
  assert.equal(reconstructProtocolState(fixture, -1).protocolClock, 1700000000, 'Reset returns the preset clock');
  assert.equal(reconstructProtocolState(fixture, 0).outcome.newLogin, undefined);
});

test('issuer revocation knowledge, installed host revocation and existing session have separate chronology', () => {
  const fixture = model({
    credentials: { certificate: { instanceId: 'cert-1', serial: 41 } },
    knowledge: { issuer: {}, host: { revokedSerials: [] } },
    sessions: { ssh: { established: true, certificateSerial: 41 } },
  }, [
    event('idp-disable', [put('knowledge.idp', { aliceDisabled: true }), put('policy.enrollmentAllowed', false)]),
    event('ca-publishes-revocation', [put('knowledge.issuer.revokedSerials', [41])]),
    event('host-installs-revocation', [put('knowledge.host.revokedSerials', [41])]),
    event('new-ssh-login-rejected', [put('outcome.newLogin', 'revoked-at-host')]),
  ]);
  assert.deepEqual(reconstructProtocolState(fixture, 0).knowledge.host.revokedSerials, []);
  assert.deepEqual(reconstructProtocolState(fixture, 1).knowledge.issuer.revokedSerials, [41]);
  assert.deepEqual(reconstructProtocolState(fixture, 1).knowledge.host.revokedSerials, []);
  assert.deepEqual(reconstructProtocolState(fixture, 2).knowledge.host.revokedSerials, [41]);
  assert.equal(reconstructProtocolState(fixture, 3).sessions.ssh.established, true);
  assert.equal(reconstructProtocolState(fixture, 3).outcome.newLogin, 'revoked-at-host');
  assert.equal(reconstructProtocolState(fixture, 1).outcome.newLogin, undefined);
});

test('append and remove retain unrelated holdings, consumed tokens and replay-cache history', () => {
  const fixture = model({ credentials: { keep: tgt, discard: targetTicket } }, [
    event('consume-token', [put('tokenConsumption.ott1', true)]),
    event('accept-proof', [{ op: 'append', path: 'replayCache', value: { authenticatorInstanceId: 'auth-1' } }]),
    event('evict-one-entry', [remove('credentials.discard')]),
    event('remove-missing', [remove('notPresent.nested')]),
  ]);
  const final = reconstructProtocolState(fixture, 99);
  assert.deepEqual(final.credentials, { keep: tgt });
  assert.deepEqual(final.tokenConsumption, { ott1: true });
  assert.deepEqual(final.replayCache, [{ authenticatorInstanceId: 'auth-1' }]);
  assert.equal(final.notPresent, undefined);
  assert.deepEqual(reconstructProtocolState(fixture, 0).replayCache, []);
  assert.equal(fixture.initialState.credentials.discard.instanceId, 'http-ticket-1');
});

function occurrenceFixture() {
  const actors = { kdc: {}, workstation: {}, service: {} };
  const operation = (kind, actorId, fields = {}) => ({
    attributeId: 'ticketEncPart', instanceId: 'ticket-1', fieldPath: 'ticket.enc-part',
    representation: 'opaque-ciphertext', kind, actorId, creator: 'kdc',
    exactValueRef: 'ticket-1.enc-part', ...fields,
  });
  return model({}, [
    event('issue-ticket', [], [operation('create', 'kdc', { inspectors: ['kdc', 'service'] })]),
    event('receive-ticket', [], [operation('receive', 'workstation')]),
    event('cache-ticket', [], [operation('store', 'workstation')]),
    event('present-ticket', [], [operation('send', 'workstation'), operation('receive', 'service')]),
    event('decode-ticket', [], [operation('inspect', 'service', {
      fieldPath: 'ticket.enc-part.cname', representation: 'decoded-local',
      exactValueRef: 'ticket-1.cname', attributeId: 'cname',
    })]),
    event('fresh-authenticators', [], [
      { attributeId: 'nonce', instanceId: 'authenticator-1', fieldPath: 'nonce', representation: 'decoded-local', kind: 'create', actorId: 'workstation', value: 'auth-1-nonce' },
      { attributeId: 'nonce', instanceId: 'authenticator-2', fieldPath: 'nonce', representation: 'decoded-local', kind: 'create', actorId: 'workstation', value: 'auth-2-nonce' },
    ]),
  ], { actors: () => actors, protocolValues: { 'ticket-1.enc-part': 'ciphertext-instance-1', 'ticket-1.cname': 'alice@A.EXAMPLE' } });
}

test('issued, cached and presented credential has one identity; fresh authenticators remain distinct', () => {
  const fixture = occurrenceFixture();
  const records = buildProtocolInstances(fixture, 5);
  assert.deepEqual(records.map(record => record.instanceId), ['ticket-1', 'authenticator-1', 'authenticator-2']);
  const ticket = records[0];
  assert.equal(ticket.creator, 'kdc');
  assert.deepEqual(ticket.holders, ['kdc', 'workstation', 'service']);
  assert.deepEqual(ticket.inspectors, ['kdc', 'service']);
  assert.ok(!ticket.inspectors.includes('workstation'), 'possession of ciphertext does not grant decryption permission');
  assert.deepEqual(ticket.definitionIds, ['ticketEncPart', 'cname']);
  assert.equal(ticket.occurrences.filter(item => item.kind === 'create').length, 1);
  assert.equal(ticket.occurrences.filter(item => item.kind === 'send').length, 1);
  assert.equal(records[1].occurrences[0].value, 'auth-1-nonce');
  assert.equal(records[2].occurrences[0].value, 'auth-2-nonce');
  assert.ok(Object.isFrozen(ticket.occurrences[0]));
  assert.equal(validateProtocolScenario(fixture).valid, true);
});

test('wire bytes and decoded local fields keep their exact event-specific representations and values', () => {
  const fixture = occurrenceFixture();
  const beforeDecode = buildProtocolInstances(fixture, 3)[0];
  assert.ok(beforeDecode.occurrences.every(item => item.representation === 'opaque-ciphertext'));
  assert.ok(beforeDecode.occurrences.every(item => item.value === 'ciphertext-instance-1'));
  const decoded = buildProtocolInstances(fixture, 4)[0].occurrences.at(-1);
  assert.equal(decoded.eventId, 'decode-ticket');
  assert.equal(decoded.eventIndex, 4);
  assert.equal(decoded.actorId, 'service');
  assert.equal(decoded.fieldPath, 'ticket.enc-part.cname');
  assert.equal(decoded.representation, 'decoded-local');
  assert.equal(decoded.exactValueRef, 'ticket-1.cname');
  assert.equal(decoded.value, 'alice@A.EXAMPLE');
  assert.deepEqual(buildProtocolInstances(fixture, 3)[0], beforeDecode, 'later inspection cannot contaminate an earlier event');
});

test('initial objects and metadata aliases are normalized without invented wire fields', () => {
  const fixture = model({}, [event('use-initial', [], [{
    attributeId: 'computerTgt', instanceId: 'computer-tgt-initial', kind: 'use', actorId: 'workstation',
    sourceEventId: 'initial', fieldPath: '', representation: 'opaque-ticket', value: 'computer-tgt-bytes',
    creatorActorId: 'kdc', holderActorIds: ['workstation'], permittedInspectorActorIds: ['kdc'],
  }])], { actors: () => ({ kdc: {}, workstation: {} }) });
  const [record] = buildProtocolInstances(fixture, 0);
  assert.equal(record.creator, 'kdc');
  assert.deepEqual(record.holders, ['workstation']);
  assert.deepEqual(record.inspectors, ['kdc']);
  assert.equal(record.occurrences[0].sourceEventId, 'initial');
  assert.equal(record.occurrences[0].value, 'computer-tgt-bytes');
  assert.equal(validateProtocolScenario(fixture).valid, true);
  assert.equal(buildProtocolInstances(fixture, -1).length, 0);
});

test('exact operation value takes precedence and missing exact references never use generic examples', () => {
  const fixture = model({}, [event('one', [], [{ attributeId: 'nonce', instanceId: 'n1', kind: 'create', actorId: 'app', fieldPath: 'nonce', representation: 'local', exactValueRef: 'nonce', value: 'current-exact-nonce' }])], {
    protocolValues: { nonce: 'different-reference-nonce' }, examples: () => ({ nonce: 'glossary-nonce' }),
  });
  assert.equal(buildProtocolInstances(fixture, 0)[0].occurrences[0].value, 'current-exact-nonce');
  const missing = model({}, [event('missing', [], [{ attributeId: 'nonce', instanceId: 'n1', kind: 'use', actorId: 'app', representation: 'local', exactValueRef: 'unknown' }])], { examples: () => ({ nonce: 'glossary-nonce' }) });
  assert.equal(buildProtocolInstances(missing, 0)[0].occurrences[0].value, undefined);
  assert.equal(validateProtocolScenario(missing).errors[0].code, 'missing-exact-value');
});

test('validator rejects future knowledge, mutable instance creator and unknown actors', () => {
  const fixture = model({}, [
    event('first', [], [{ attributeId: 'ticket', instanceId: 'shared', kind: 'create', actorId: 'kdc', representation: 'wire', value: 'one', sourceEventId: 'future' }]),
    event('future', [], [{ attributeId: 'ticket', instanceId: 'shared', kind: 'create', actorId: 'intruder', representation: 'wire', value: 'two' }]),
  ], { actors: () => ({ kdc: {} }) });
  const checked = validateProtocolScenario(fixture);
  assert.equal(checked.valid, false);
  assert.ok(checked.errors.some(error => error.code === 'future-source-event'));
  assert.ok(checked.errors.some(error => error.code === 'changed-instance-creator'));
  assert.ok(checked.errors.some(error => error.code === 'unknown-actor'));
  assert.throws(() => buildProtocolInstances(fixture, 1), /cannot change creator/);
});

test('immutable instance fields cannot become different issued bytes at a later event', () => {
  const op = value => ({ attributeId: 'certificate', instanceId: 'cert-1', fieldPath: '', representation: 'ssh-wire-bytes', kind: 'use', actorId: 'host', value });
  const changed = model({}, [event('issued-original', [], [op('original-signed-bytes')]), event('present-rewritten', [], [op('silently-rewritten-bytes')])]);
  assert.equal(validateProtocolScenario(changed).valid, false);
  assert.ok(validateProtocolScenario(changed).errors.some(error => /immutable instance field/.test(error.message)));
  assert.throws(() => buildProtocolInstances(changed, 1), /immutable instance field/);
  assert.equal(buildProtocolInstances(changed, 0)[0].occurrences[0].value, 'original-signed-bytes');
  const reordered = model({}, [event('issued', [], [op({ serial: 41, principal: 'alice' })]), event('presented', [], [op({ principal: 'alice', serial: 41 })])]);
  assert.equal(validateProtocolScenario(reordered).valid, true, 'object key ordering does not change the fixture value');
});

test('effect validation rejects malformed paths, invalid clock changes and invalid append targets', () => {
  const invalidEffects = [
    put('__proto__.polluted', true), put('constructor.prototype.polluted', true),
    put('credentials..ticket', true), put('protocolClock', 100),
    { op: 'advance', value: -1 }, { op: 'advance', path: 'credentials', value: 1 },
    { op: 'append', path: 'policy.allow', value: true },
  ];
  for (const effect of invalidEffects) {
    const fixture = model({ policy: { allow: true } }, [event('bad', [effect])]);
    assert.equal(validateProtocolScenario(fixture).valid, false);
    assert.throws(() => reconstructProtocolState(fixture, 0));
  }
  assert.equal({}.polluted, undefined);
});

test('legacy models require no state annotations or synthetic object instances', () => {
  const fixture = { steps: () => [{ id: 'legacy', fields: ['nonce'], payload: [{ name: 'nonce', value: 'legacy-nonce' }], attributeOperations: [{ attributeId: 'nonce', kind: 'send', actorId: 'browser' }] }] };
  assert.deepEqual(reconstructProtocolState(fixture, 0), PROTOCOL_STATE_DEFAULTS);
  assert.deepEqual(buildProtocolInstances(fixture, 0), []);
  assert.deepEqual(validateProtocolScenario(fixture), { valid: true, errors: [], warnings: [] });
  assert.deepEqual(reconstructProtocolState({ steps: [] }, -1), PROTOCOL_STATE_DEFAULTS);
  assert.throws(() => reconstructProtocolState(fixture, -2), RangeError);
  assert.throws(() => reconstructProtocolState(fixture, .2), RangeError);
});
