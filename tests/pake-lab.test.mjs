import test from 'node:test';
import assert from 'node:assert/strict';
import { PAKELAB_SCENARIOS } from '../src/pake-lab.js';
import { reconstructProtocolState } from '../src/protocol-state.js';

const expected = [
  ['lab-pake-spake2-success', false, 'success'],
  ['lab-pake-spake2-password-mismatch', false, 'password'],
  ['lab-pake-spake2-transcript-reject', false, 'transcript'],
  ['lab-pake-spake2plus-success', true, 'success'],
  ['lab-pake-spake2plus-password-mismatch', true, 'password'],
  ['lab-pake-spake2plus-transcript-reject', true, 'transcript'],
  ['lab-pake-spake2plus-record-boundary', true, 'disclosure'],
];
const get = id => {
  const model = PAKELAB_SCENARIOS.find(item => item.id === id);
  assert.ok(model, 'Missing committed preset ' + id); return model;
};
const index = (model, stage) => {
  const i = model.steps().findIndex(step => step.pakeStage === stage);
  assert.notEqual(i, -1, model.id + ': missing ' + stage); return i;
};
const stateAt = (model, stage) => reconstructProtocolState(model, index(model, stage));
const endpoint = (model, stage, actor) => stateAt(model, stage).sessions.pake[actor];


for (const [id, plus, branch] of expected) {
  test(id + ': candidate states, secret wire exclusion and terminal predicate', () => {
    const model = get(id), steps = model.steps();
    const first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    for (const step of steps) {
      if (step.from !== step.to) {
        assert.equal(new Set(step.payload.map(field => field.attributeId)).size, step.payload.length, 'One wire field, two operation occurrences');
        assert.ok(step.payload.every(field => !['pake_w', 'pake_w0', 'pake_w1', 'pake_L', 'pake_x', 'pake_y', 'pake_transcript', 'pake_schedule', 'pake_key'].includes(field.attributeId)) || step.pakeStage === 'disclose-record', 'Wire payload does not include decoded local secrets');
      }
      for (const op of step.attributeOperations) {
        if (['send', 'receive'].includes(op.kind) && !['enroll-record', 'disclose-record'].includes(step.pakeStage)) assert.ok(['pake_shareA', 'pake_shareB', 'pake_confirmA', 'pake_confirmB'].includes(op.attributeId), 'No secret transcript, scalar or MAC key packet');
      }
    }
    const initial = reconstructProtocolState(model, -1);
    for (const actor of [first, second]) assert.deepEqual([initial.sessions.pake[actor].candidate, initial.sessions.pake[actor].peerConfirmed, initial.sessions.pake[actor].usable], [false, false, false]);
    for (const stage of ['derive-a', 'derive-b']) {
      const current = stateAt(model, stage);
      assert.equal(current.sessions.pake[stage === 'derive-a' ? first : second].candidate, true);
      assert.equal(current.sessions.pake[first].peerConfirmed, false);
      assert.equal(current.sessions.pake[second].peerConfirmed, false);
      assert.equal(current.sessions.pake[first].usable, false);
      assert.equal(current.sessions.pake[second].usable, false);
    }
    const final = reconstructProtocolState(model, steps.length - 1);
    const succeeds = ['success', 'disclosure'].includes(branch);
    for (const actor of [first, second]) {
      assert.equal(final.sessions.pake[actor].peerConfirmed, succeeds);
      assert.equal(final.sessions.pake[actor].usable, succeeds);
      assert.equal(final.sessions.pake[actor].temporaryDisposed, true);
    }
    assert.equal(final.outcome.pake.applicationAuthorization, false);
    assert.equal(final.outcome.pake.status, succeeds ? 'confirmed-key-only' : 'confirmation-rejected');
    if (plus) assert.equal(final.credentials.pake.verifierRecord, true);
    else assert.deepEqual(final.credentials.pake, { setupA: true, setupB: true });
    assert.deepEqual(reconstructProtocolState(model, -1), initial, 'Rewind uses the immutable initial state');
  });
}

for (const [id, plus] of expected.filter(row => ['success', 'disclosure'].includes(row[2]))) {
  test(id + ': receipt, local confirmation and sender completion are endpoint-specific', () => {
    const model = get(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    const firstSide = plus ? 'b' : 'a', lastSide = plus ? 'a' : 'b';
    const sender = plus ? second : first, checker = plus ? first : second;
    assert.ok(index(model, 'send-confirm-' + firstSide) < index(model, 'verify-confirm-' + firstSide));
    assert.ok(index(model, 'verify-confirm-' + firstSide) < index(model, 'create-confirm-' + lastSide));
    assert.equal(endpoint(model, 'send-confirm-' + firstSide, checker).receivedConfirmation, true);
    assert.equal(endpoint(model, 'send-confirm-' + firstSide, checker).peerConfirmed, false);
    assert.equal(endpoint(model, 'verify-confirm-' + firstSide, checker).peerConfirmed, true);
    assert.equal(endpoint(model, 'verify-confirm-' + firstSide, checker).usable, false);
    assert.equal(endpoint(model, 'verify-confirm-' + firstSide, sender).peerConfirmed, false);
    assert.equal(endpoint(model, 'handoff-confirm-' + lastSide, checker).ownConfirmationSent, true);
    assert.equal(endpoint(model, 'handoff-confirm-' + lastSide, checker).usable, true);
    assert.equal(endpoint(model, 'handoff-confirm-' + lastSide, sender).receivedConfirmation, false);
    assert.equal(endpoint(model, 'handoff-confirm-' + lastSide, sender).usable, false);
    assert.equal(endpoint(model, 'send-confirm-' + lastSide, checker).usable, true);
    assert.equal(endpoint(model, 'send-confirm-' + lastSide, sender).usable, false);
    assert.equal(endpoint(model, 'send-confirm-' + lastSide, sender).peerConfirmed, false);
    assert.equal(endpoint(model, 'verify-confirm-' + lastSide, sender).usable, true);
  });
}

for (const [id, plus, branch] of expected.filter(row => ['password', 'transcript'].includes(row[2]))) {
  test(id + ': controlled mismatch rejects without inventing an error packet or erasing remote state', () => {
    const model = get(id), first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
    const rejector = plus ? first : second, waiting = plus ? second : first;
    const firstSide = plus ? 'b' : 'a', forbiddenSide = plus ? 'a' : 'b';
    assert.equal(model.steps().some(step => step.pakeStage === 'create-confirm-' + forbiddenSide), false);
    assert.equal(model.steps().some(step => step.pakeStage === 'send-confirm-' + forbiddenSide), false);
    const rejected = stateAt(model, 'verify-confirm-' + firstSide);
    assert.equal(rejected.sessions.pake[rejector].peerConfirmed, false);
    assert.equal(rejected.sessions.pake[rejector].failure, 'confirmation-mismatch');
    const cleaned = stateAt(model, plus ? 'dispose-a' : 'dispose-b');
    assert.equal(cleaned.sessions.pake[rejector].temporaryDisposed, true);
    assert.equal(cleaned.sessions.pake[waiting].temporaryDisposed, false);
    assert.equal(cleaned.sessions.pake[waiting].candidate, true, 'Remote candidate persists until its own timeout');
    assert.ok(index(model, plus ? 'timeout-b' : 'timeout-a') > index(model, plus ? 'dispose-a' : 'dispose-b'));
    const fields = key => model.pakeInventory.artifacts.find(artifact => artifact.artifactId === id + ':' + key).representations[0].fields;
    const fieldValue = (key, field) => fields(key).find(item => item.attributeId === 'pake_' + field)?.value;
    if (branch === 'transcript') {
      assert.equal(model.pakeVariant.changedField, plus ? 'Context' : 'B');
      assert.equal(fieldValue('schedule-a', 'groupSecret'), fieldValue('schedule-b', 'groupSecret'), 'Transcript disagreement does not change the group computation');
      assert.notEqual(fieldValue('schedule-a', 'transcript'), fieldValue('schedule-b', 'transcript'));
      if (plus) {
        assert.equal(fieldValue('schedule-a', 'context'), model.profile.algorithms.context + ' altered');
        assert.equal(fieldValue('schedule-b', 'context'), model.profile.algorithms.context);
      } else {
        assert.equal(fieldValue('schedule-a', 'identityB'), 'client-altered');
        assert.equal(fieldValue('schedule-b', 'identityB'), 'client');
      }
    } else {
      assert.equal(model.pakeVariant.changedField, plus ? 'w0,w1' : 'w');
      for (const name of plus ? ['w0', 'w1'] : ['w']) assert.notEqual(fieldValue('invocation-a', name), fieldValue(plus ? 'registration-working' : 'setup-a', name), 'Wrong invocation input differs from legitimate setup');
      assert.notEqual(fieldValue('schedule-a', 'groupSecret'), fieldValue('schedule-b', 'groupSecret'), 'Controlled wrong input changes independently computed group secrets');
      const legitimate = get(plus ? 'lab-pake-spake2plus-success' : 'lab-pake-spake2-success').pakeInventory.artifacts.find(artifact => artifact.artifactId.endsWith(':' + (plus ? 'verifier-record' : 'setup-b'))).representations[0].fields;
      assert.deepEqual(fields(plus ? 'verifier-record' : 'setup-b'), legitimate, 'Wrong invocation preserves the legitimate stored input');
    }
    assert.ok(model.steps().filter(step => step.pakeStage.startsWith('timeout-')).every(step => step.from === step.to));
  });
}

