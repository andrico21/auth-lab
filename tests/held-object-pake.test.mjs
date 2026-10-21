import test from 'node:test';
import assert from 'node:assert/strict';
import { PAKELAB_SCENARIOS } from '../src/pake-lab.js';
import { buildPakeHeldObjects } from '../src/held-object-pake.js';
import { compileHeldObjects, projectHeldObjects, inspectHeldObject, heldObjectTrace, assertHeldObjectCoverage } from '../src/held-object-state.js';

const manifest = [
  ['lab-pake-spake2-success', false, true],
  ['lab-pake-spake2-password-mismatch', false, false],
  ['lab-pake-spake2-transcript-reject', false, false],
  ['lab-pake-spake2plus-success', true, true],
  ['lab-pake-spake2plus-password-mismatch', true, false],
  ['lab-pake-spake2plus-transcript-reject', true, false],
  ['lab-pake-spake2plus-record-boundary', true, true],
];
function fixture(id, revision = 'context-1') {
  const model = PAKELAB_SCENARIOS.find(item => item.id === id);
  assert.ok(model, 'Missing committed preset ' + id);
  const steps = model.steps(), actors = model.actors();
  const plan = buildPakeHeldObjects({ model, steps, actors, config: {}, contextId: id + ':' + revision, choiceId: id });
  const compiled = compileHeldObjects(plan, { model, steps });
  const index = stage => {
    const result = steps.findIndex(step => step.pakeStage === stage);
    assert.notEqual(result, -1, id + ': missing ' + stage); return result;
  };
  const frame = (stage, milestone = 'complete') => projectHeldObjects(compiled, { eventIndex: index(stage), milestone });
  const objectId = key => id + ':' + key;
  const holding = (snapshot, key, actor, representationId) => snapshot.holdings.find(item => item.artifactId === objectId(key) && item.actorId === actor && (!representationId || item.representationId === representationId));
  return { model, steps, plan, compiled, index, frame, objectId, holding, initial: () => projectHeldObjects(compiled, { eventIndex: -1, milestone: 'initial' }), final: () => projectHeldObjects(compiled, { eventIndex: steps.length - 1, milestone: 'complete' }) };
}

for (const [id, plus, succeeds] of manifest) {
  test(id + ': complete cursor coverage and legitimate setup retention', () => {
    const f = fixture(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    assertHeldObjectCoverage(f.compiled);
    for (let i = -1; i < f.steps.length; i++) {
      const cursor = { eventIndex: i, milestone: i === -1 ? 'initial' : 'complete' };
      const snapshot = projectHeldObjects(f.compiled, cursor);
      assert.equal(snapshot.coverageStatus, 'complete');
    }
    const final = f.final();
    assert.equal(final.holdings.every(item => item.retention === 'retained'), true, 'No final scratch state');
    if (plus) {
      assert.ok(f.holding(final, 'prover-input', first));
      assert.ok(f.holding(final, 'verifier-record', second));
      assert.equal(f.holding(f.initial(), 'verifier-record', second), undefined);
    } else {
      assert.ok(f.holding(final, 'setup-a', first)); assert.ok(f.holding(final, 'setup-b', second));
    }
    for (const [key, actor] of [['key-a', first], ['key-b', second]]) assert.equal(!!f.holding(final, key, actor), succeeds);
    for (const key of ['scalar-a', 'scalar-b', 'schedule-a', 'schedule-b', 'invocation-a', 'registration-working']) assert.equal(final.holdings.some(item => item.artifactId === f.objectId(key)), false, key);
    const fresh = fixture(id, 'context-2');
    const oldHolding = final.holdings[0], newHolding = fresh.final().holdings[0];
    assert.notEqual(oldHolding.qualifiedHoldingId, newHolding.qualifiedHoldingId, 'Reset/context identities do not alias');
  });

  test(id + ': exact scalar, key schedule and output reader sets never leak to peers', () => {
    const f = fixture(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    for (const [key, owner] of [['scalar-a', first], ['scalar-b', second], ['schedule-a', first], ['schedule-b', second], ['key-a', first], ['key-b', second]]) {
      const artifact = f.plan.artifacts.find(item => item.artifactId === f.objectId(key));
      assert.deepEqual(artifact.representations.map(rep => rep.readableBy), [[owner]]);
      for (const rep of artifact.representations) for (const field of rep.fields) assert.deepEqual(field.readableBy, [owner], 'Secret field has only its actual endpoint reader');
      for (const event of Object.values(f.plan.events)) for (const message of event.messages || []) assert.equal(message.objects.some(object => object.artifactId === artifact.artifactId), false);
    }
    const firstFrame = f.frame('derive-a'), firstHolding = f.holding(firstFrame, 'schedule-a', first);
    assert.ok(inspectHeldObject(firstFrame, firstHolding.holdingId).fields.every(field => field.readable));
    assert.equal(firstFrame.holdings.some(item => item.artifactId === f.objectId('scalar-b') && item.actorId === first), false);
    assert.equal(firstFrame.holdings.some(item => item.artifactId === f.objectId('scalar-a') && item.actorId === second), false);
    for (const source of f.steps) for (const operation of source.attributeOperations) if (['pake_x', 'pake_y', 'pake_schedule', 'pake_transcript', 'pake_groupSecret'].includes(operation.attributeId)) {
      assert.deepEqual(operation.inspectors, [operation.creator]);
      assert.equal(operation.actorId, operation.creator);
      assert.equal(['send', 'receive'].includes(operation.kind), false);
    }
  });

  test(id + ': whole-share receipt is atomic and local group validation is separate', () => {
    const f = fixture(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    for (const [stage, key, receiver, check] of [['send-a', 'share-a', second, 'validate-a'], ['send-b', 'share-b', first, 'validate-b']]) {
      for (const progress of [0, 0.5, 0.999]) {
        const pending = projectHeldObjects(f.compiled, { eventIndex: f.index(stage), progress });
        assert.equal(f.holding(pending, key, receiver), undefined);
        assert.equal(pending.state.sessions.pake[receiver].groupValidated, false);
      }
      const received = f.frame(stage);
      assert.ok(f.holding(received, key, receiver, 'wire'));
      assert.equal(received.state.sessions.pake[receiver].groupValidated, false);
      assert.equal(f.frame(check).state.sessions.pake[receiver].groupValidated, true);
      const message = f.plan.events[f.steps[f.index(stage)].id].messages[0];
      assert.deepEqual([message.from, message.to, message.start, message.end], [receiver === first ? second : first, receiver, 0, 1]);
      const trace = heldObjectTrace(f.compiled, f.objectId(key));
      const receipt = trace.find(row => row.sourceStepId === f.steps[f.index(stage)].id);
      assert.equal(receipt.representationId, 'wire');
      assert.ok(receipt.payload.every(field => !field.redacted), 'Public share remains inspectable by its receiving endpoint');
      assert.equal(f.holding(f.frame(stage, 'before'), key, receiver), undefined, 'Rewind before receipt removes the receiver copy');
    }
  });
}

for (const [id, plus] of manifest.filter(row => row[2])) {
  test(id + ': confirmation in flight does not advance the receiving endpoint', () => {
    const f = fixture(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    const firstSide = plus ? 'b' : 'a', lastSide = plus ? 'a' : 'b';
    const firstSender = plus ? second : first, firstReceiver = plus ? first : second;
    for (const [side, receiver] of [[firstSide, firstReceiver], [lastSide, firstSender]]) {
      for (const progress of [0, 0.5, 0.999]) {
        const pending = projectHeldObjects(f.compiled, { eventIndex: f.index('send-confirm-' + side), progress });
        assert.equal(f.holding(pending, 'confirmation-' + side, receiver), undefined);
        const localSender = receiver === first ? second : first;
        assert.equal(pending.state.sessions.pake[localSender].ownConfirmationSent, true, 'Local handoff already occurred while delivery is in flight');
        if (side === lastSide) assert.equal(pending.state.sessions.pake[localSender].usable, true, 'Reciprocal sender completed independently of receipt');
        assert.equal(pending.state.sessions.pake[receiver].peerConfirmed, false);
        assert.equal(pending.state.sessions.pake[receiver].usable, false);
      }
      const delivered = f.frame('send-confirm-' + side);
      assert.ok(f.holding(delivered, 'confirmation-' + side, receiver));
      assert.equal(delivered.state.sessions.pake[receiver].peerConfirmed, false);
      assert.equal(delivered.state.sessions.pake[receiver].usable, false);
      assert.equal(f.frame('verify-confirm-' + side).state.sessions.pake[receiver].peerConfirmed, true);
    }
    assert.equal(f.frame('send-confirm-' + lastSide).state.sessions.pake[firstReceiver].usable, true);
    assert.equal(f.frame('verify-confirm-' + firstSide).state.sessions.pake[firstReceiver].usable, false);
  });
}

for (const [id, plus] of manifest.filter(row => row[1])) {
  test(id + ': setup wire, prover-local input and verifier-decoded record are distinct', () => {
    const f = fixture(id), before = f.frame('enroll-record', 'before'), received = f.frame('enroll-record');
    assert.equal(f.holding(before, 'verifier-record', 'pake-verifier'), undefined);
    const wire = f.holding(received, 'enrollment-envelope', 'pake-verifier', 'opaque-wire');
    const decoded = f.holding(received, 'enrollment-envelope', 'pake-verifier', 'verifier-decoded');
    assert.ok(wire && decoded);
    const wireFields = inspectHeldObject(received, wire.holdingId).fields;
    assert.deepEqual(wireFields.map(field => field.attributeId), ['pake_enrollment']);
    const record = inspectHeldObject(received, f.holding(received, 'verifier-record', 'pake-verifier').holdingId);
    assert.deepEqual(record.fields.map(field => field.attributeId), ['pake_w0', 'pake_L']);
    assert.deepEqual(inspectHeldObject(received, decoded.holdingId).fields.map(field => field.attributeId), ['pake_w0', 'pake_L']);
    assert.equal(received.holdings.some(item => item.actorId === 'pake-verifier' && item.artifactId === f.objectId('registration-working')), false);
    const exactReceipt = heldObjectTrace(f.compiled, f.objectId('enrollment-envelope')).find(row => row.sourceIndex === f.index('enroll-record'));
    assert.equal(exactReceipt.representationId, 'opaque-wire', 'Wire replay does not replace protected envelope with decoded w0,L');
    assert.deepEqual(exactReceipt.payload.map(field => field.attributeId), ['pake_enrollment']);
    const senderDisposed = f.frame('registration-dispose');
    for (const representation of ['prover-local', 'opaque-wire']) assert.equal(f.holding(senderDisposed, 'enrollment-envelope', 'pake-prover', representation), undefined, 'Sender disposes both local plaintext and wire scratch copies');
    assert.ok(f.holding(senderDisposed, 'prover-input', 'pake-prover'));
    assert.ok(f.holding(senderDisposed, 'enrollment-envelope', 'pake-verifier', 'opaque-wire'), 'Sender cleanup does not erase receiver wire knowledge');
    assert.ok(f.holding(senderDisposed, 'enrollment-envelope', 'pake-verifier', 'verifier-decoded'), 'Sender cleanup does not erase receiver decoded copy');
    const verifierDisposed = f.frame('dispose-b');
    assert.equal(f.holding(verifierDisposed, 'enrollment-envelope', 'pake-verifier'), undefined);
    assert.ok(f.holding(verifierDisposed, 'verifier-record', 'pake-verifier'), 'Verifier disposes transient receipts, not its legitimate persistent record');
    assert.equal(f.final().holdings.some(item => ['pake-prover', 'pake-verifier'].includes(item.actorId) && item.artifactId === f.objectId('enrollment-envelope')), false, 'Endpoint scratch is released independently of retained observer evidence');
  });
}

test('record disclosure is a separate capability, never ordinary network visibility or peer scalar access', () => {
  const f = fixture('lab-pake-spake2plus-record-boundary');
  const recorded = f.frame('enroll-record');
  const capture = f.holding(recorded, 'enrollment-envelope', 'pake-observer', 'opaque-wire');
  assert.ok(capture);
  assert.deepEqual(inspectHeldObject(recorded, capture.holdingId).fields.map(field => field.attributeId), ['pake_enrollment']);
  const senderDisposed = f.frame('registration-dispose');
  assert.equal(f.holding(senderDisposed, 'enrollment-envelope', 'pake-observer', 'opaque-wire').holdingId, capture.holdingId, 'Endpoint cleanup cannot erase independent recorded ciphertext');
  const before = f.frame('disclose-record', 'before'), after = f.frame('disclose-record');
  assert.equal(f.holding(before, 'enrollment-envelope', 'pake-observer', 'opaque-wire').holdingId, capture.holdingId);
  assert.ok(before.state.knowledge.pakeObserver.publicRecording.includes(f.objectId('enrollment-envelope')));
  assert.equal(before.state.knowledge.pakeObserver.recordDisclosed, false);
  for (const holding of before.holdings.filter(item => item.actorId === 'pake-observer')) assert.equal(inspectHeldObject(before, holding.holdingId).fields.some(field => ['pake_w0', 'pake_L'].includes(field.attributeId) && field.readable), false);
  assert.equal(before.holdings.some(item => item.actorId === 'pake-observer' && item.representationId === 'disclosed-record'), false);
  const record = f.holding(after, 'record-disclosure', 'pake-observer', 'disclosed-record');
  assert.ok(record);
  assert.deepEqual(inspectHeldObject(after, record.holdingId).fields.map(field => field.attributeId), ['pake_w0', 'pake_L']);
  assert.ok(f.holding(after, 'verifier-record', 'pake-verifier', 'local'));
  for (const key of ['share-a', 'share-b', 'confirmation-a', 'confirmation-b']) assert.ok(f.holding(before, key, 'pake-observer', 'wire'));
  assert.equal(f.holding(after, 'enrollment-envelope', 'pake-observer', 'opaque-wire').holdingId, capture.holdingId, 'Record disclosure does not replace the earlier captured ciphertext');
  for (const holding of after.holdings.filter(item => item.actorId === 'pake-observer')) {
    const inspected = inspectHeldObject(after, holding.holdingId);
    assert.equal(inspected.fields.some(field => ['pake_w1', 'pake_x', 'pake_y', 'pake_key', 'pake_transcript', 'pake_schedule'].includes(field.attributeId) && field.readable), false);
  }
});
