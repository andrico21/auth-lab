import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { SSHLAB_SCENARIOS } from '../src/ssh-access-lab.js';
import { reconstructProtocolState, buildProtocolInstances, validateProtocolScenario } from '../src/protocol-state.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';

const model = suffix => SSHLAB_SCENARIOS.find(item => item.id === 'lab-ssh-' + suffix);
const event = (m, key) => m.steps().find(item => item.sshStage === key);
const after = (m, key) => reconstructProtocolState(m, m.steps().indexOf(event(m, key)));
const attr = (m, name) => Object.keys(m.definitions()).find(id => m.definitions()[id].name === name);
const exact = (m, key, name, kind, actor) => event(m, key).attributeOperations.find(op => op.attributeId === attr(m, name) && op.kind === kind && (!actor || op.actorId === actor));
const packet = (m, key, name) => event(m, key).payload.find(item => item.name === name)?.value;
const focused = (m, name) => {
  const attributeId = attr(m, name);
  const usages = m.steps().map((step, index) => ({ step, index, actions: step.attributeOperations.filter(op => op.attributeId === attributeId) })).filter(usage => usage.actions.length);
  return buildAttributeTrace(usages, {}, m.protocolValues);
};

test('F11 foreign callback reaches its failed exact-input check while original state stays immutable', () => {
  const m = model('cert-callback');
  const original = exact(m, 'prepare', 'state', 'create');
  const received = exact(m, 'callback', 'state', 'receive', 'sshCli');
  const verified = exact(m, 'callback-check', 'state', 'verify', 'sshCli');
  const expected = exact(m, 'callback-check', 'state', 'use', 'sshCli');
  assert.equal(verified.instanceId, received.instanceId);
  assert.equal(verified.value, received.value);
  assert.equal(expected.instanceId, original.instanceId);
  assert.equal(expected.value, original.value);
  assert.notEqual(verified.instanceId, expected.instanceId);
  assert.notEqual(verified.value, expected.value);
  const comparison = after(m, 'callback-check').transaction.callbackComparison;
  assert.equal(comparison.matched, false);
  assert.equal(comparison.receivedState, received.value);
  assert.equal(comparison.expectedState, original.value);
  assert.ok(focused(m, 'state').some(step => step.traceKind === 'verify' && step.traceActions.some(op => op.instanceId === received.instanceId && op.value === received.value)));
  const originalObject = buildProtocolInstances(m, m.steps().length - 1).find(item => item.instanceId === original.instanceId);
  assert.ok(originalObject.occurrences.filter(op => op.definitionId === original.definitionId).every(op => op.value === original.value));
  assert.equal(event(m, 'redeem'), undefined);
});

test('F11 alternate verifier is RFC-valid and its actual SHA256 result fails the retained challenge', () => {
  const m = model('cert-pkce');
  const received = exact(m, 'redeem', 'code_verifier', 'receive', 'sshIdp');
  const verified = exact(m, 'pkce-check', 'code_verifier', 'verify', 'sshIdp');
  assert.match(received.value, /^[A-Za-z0-9._~-]{43,128}$/);
  assert.equal(verified.value, received.value);
  assert.equal(verified.instanceId, received.instanceId);
  const calculated = createHash('sha256').update(received.value, 'ascii').digest('base64url');
  const derived = exact(m, 'pkce-check', 'code_challenge', 'derive', 'sshIdp');
  const expected = exact(m, 'pkce-check', 'code_challenge', 'use', 'sshIdp');
  assert.equal(derived.value, calculated);
  assert.equal(derived.creatorActorId, 'sshIdp');
  assert.notEqual(derived.value, expected.value);
  assert.notEqual(derived.instanceId, expected.instanceId);
  const comparison = after(m, 'pkce-check').transaction.pkceComparison;
  assert.equal(comparison.receivedVerifier, received.value);
  assert.equal(comparison.derivedChallenge, calculated);
  assert.equal(comparison.expectedChallenge, expected.value);
  assert.equal(comparison.verifierSyntaxValid, true);
  assert.equal(comparison.matched, false);
  assert.ok(focused(m, 'code_verifier').some(step => step.traceKind === 'verify' && step.traceActions.some(op => op.instanceId === received.instanceId && op.value === received.value)));
  assert.equal(event(m, 'enroll'), undefined);
});

test('F12 root signed input and actual wire request share one request identity with otherwise valid proof', () => {
  const m = model('cert-root');
  const input = exact(m, 'userauth-input', 'SSH publickey signed input (local)', 'derive', 'sshCli');
  const account = exact(m, 'userauth', 'user name', 'send', 'sshCli');
  assert.match(input.value, /string\(root\)/);
  assert.doesNotMatch(input.value, /string\(alice\)/);
  assert.equal(input.instanceId, account.instanceId);
  assert.equal(account.value, 'root');
  assert.deepEqual(exact(m, 'host-policy', 'valid principals', 'verify').value, ['alice']);
  assert.equal(after(m, 'host-policy').hostChecks.possessionProofAccepted, true);
  assert.equal(after(m, 'host-policy').hostChecks.certificateSignatureAccepted, true);
  assert.equal(after(m, 'host-policy').hostChecks.principalAccountMapped, false);
  assert.equal(after(m, 'host-policy').failure.reason, 'principal_account_mismatch');
  const custom = m.contextualize({ unixAccount: 'root' });
  assert.match(exact(custom, 'userauth-input', 'SSH publickey signed input (local)', 'derive').value, /string\(administrator\)/);
  assert.equal(packet(custom, 'userauth', 'user name'), 'administrator');
});

test('F13 additional channel has a distinct active sender ID and source-prefix seeking preserves one then two', () => {
  const m = model('cert-lifecycle');
  const first = exact(m, 'channel', 'SSH_MSG_CHANNEL_OPEN', 'send');
  const second = exact(m, 'additional-channel', 'SSH_MSG_CHANNEL_OPEN', 'send');
  assert.notEqual(first.instanceId, second.instanceId);
  assert.equal(first.value.sender_channel, 0);
  assert.equal(second.value.sender_channel, 1);
  const beforeIndex = m.steps().indexOf(event(m, 'additional-channel')) - 1;
  const before = reconstructProtocolState(m, beforeIndex);
  const afterOpen = after(m, 'additional-channel');
  assert.equal(before.sessions.ssh.channels, 1);
  assert.deepEqual(before.sessions.ssh.activeChannels, [{ instanceId: first.instanceId, senderChannel: 0 }]);
  assert.equal(afterOpen.sessions.ssh.channels, 2);
  assert.deepEqual(afterOpen.sessions.ssh.activeChannels, [{ instanceId: first.instanceId, senderChannel: 0 }, { instanceId: second.instanceId, senderChannel: 1 }]);
  assert.equal(afterOpen.sessions.ssh.sessionIdentifier, before.sessions.ssh.sessionIdentifier);
  assert.equal(afterOpen.sessions.ssh.authenticated, true);
  assert.match(event(m, 'additional-channel').detail, /confirmations are abstracted/);
});

test('F14 restarted Device response supplies all four required fields and its own independent expiry', () => {
  const m = model('device-restart');
  const expiry = exact(m, 'restart-response', 'expires_in (device transaction)', 'receive', 'sshCli');
  const original = exact(m, 'response', 'expires_in (device transaction)', 'receive', 'sshCli');
  assert.equal(expiry.value, 600);
  assert.notEqual(expiry.instanceId, original.instanceId);
  assert.ok(expiry.instanceId.endsWith(':device-transaction-2'));
  for (const name of ['device_code', 'user_code', 'verification_uri', 'expires_in (device transaction)']) assert.ok(packet(m, 'restart-response', name) !== undefined, name);
  assert.equal(packet(m, 'restart-response', 'interval'), undefined);
  const state = after(m, 'restart-response');
  assert.equal(state.protocolClock + expiry.value, state.transaction.expiresAt);
  assert.equal(state.transaction.createdAt, state.protocolClock);
  assert.equal(state.transactions.old.status, 'cancelled');
});

test('F15 Device enrollment proves CLI construction, agent receive/sign and CLI receive before exact wire send', () => {
  for (const suffix of ['device-cadence', 'device-restart']) {
    const m = model(suffix);
    const input = exact(m, 'userauth-input', 'SSH publickey signed input (local)', 'derive', 'sshCli');
    const receivedInput = exact(m, 'agent-request', 'SSH publickey signed input (local)', 'receive', 'sshAgent');
    const usedInput = exact(m, 'sign', 'SSH publickey signed input (local)', 'use', 'sshAgent');
    assert.equal(receivedInput.instanceId, input.instanceId);
    assert.equal(receivedInput.value, input.value);
    assert.equal(usedInput.value, receivedInput.value);
    const signed = exact(m, 'sign', 'signature (SSH user proof)', 'create', 'sshAgent');
    const returned = exact(m, 'agent-proof', 'signature (SSH user proof)', 'receive', 'sshCli');
    const transmitted = exact(m, 'userauth', 'signature (SSH user proof)', 'send', 'sshCli');
    assert.equal(returned.instanceId, signed.instanceId);
    assert.equal(returned.value, signed.value);
    assert.equal(transmitted.instanceId, returned.instanceId);
    assert.equal(transmitted.value, returned.value);
    const indexes = ['userauth-input', 'agent-request', 'sign', 'agent-proof', 'userauth'].map(key => m.steps().indexOf(event(m, key)));
    assert.deepEqual([...indexes].sort((a, b) => a - b), indexes);
    assert.equal(after(m, 'sign').credentials.userKey.privateAt, 'sshAgent');
    assert.ok(!event(m, 'userauth').payload.some(item => /session identifier|private key/.test(item.name)));
    assert.equal(event(m, 'agent-request').interactionType, 'local-ipc');
    assert.equal(event(m, 'agent-proof').interactionType, 'local-ipc');
  }
});

test('F16 every claimed human field is actually inside one/zero-prompt instruction, including rebuilt issuer', () => {
  for (const suffix of ['sssd-success', 'sssd-zero']) for (const context of [{}, { aIssuerURL: 'https://login.example.test/tenant' }]) {
    const m = model(suffix).contextualize(context);
    const envelope = packet(m, 'ssh-info', 'SSH_MSG_USERAUTH_INFO_REQUEST');
    const text = [envelope.instruction, ...envelope.prompts.map(item => item.prompt)].join('\n');
    for (const op of event(m, 'ssh-info').attributeOperations.filter(item => item.kind === 'receive' && item.carriedAs?.includes('instruction/prompt text'))) assert.ok(text.includes(op.value), `${suffix}: ${op.fieldPath}`);
    assert.equal(envelope.num_prompts, suffix === 'sssd-zero' ? 0 : 1);
    assert.doesNotMatch(text, /device-remote-sssd-1|interactive-user-access-token/);
  }
});

test('F17 account denial comes from explicit denied policy/result while certificate and proof independently pass', () => {
  const denied = model('cert-account'), allowed = model('cert-success');
  const result = exact(denied, 'host-policy', 'PAM/account access result (local)', 'verify', 'sshHost');
  const state = after(denied, 'host-policy');
  assert.match(result.value, /access denied/);
  assert.ok(result.value.includes(state.policy.hostAccountAccess.rule));
  assert.equal(state.policy.hostAccountAccess.allowed, false);
  assert.equal(state.hostChecks.certificateSignatureAccepted, true);
  assert.equal(state.hostChecks.possessionProofAccepted, true);
  assert.equal(state.hostChecks.principalAccountMapped, true);
  assert.equal(state.hostChecks.accountAccessAllowed, false);
  assert.equal(state.authorities.host.accountLocked, false, 'Named access denial does not invent an account lock.');
  assert.equal(state.sessions.ssh.authenticated, false);
  assert.equal(event(denied, 'channel'), undefined);
  assert.match(exact(allowed, 'host-policy', 'PAM/account access result (local)', 'verify').value, /access allowed/);
  assert.equal(after(allowed, 'host-policy').policy.hostAccountAccess.allowed, true);
  assert.ok(focused(denied, 'PAM/account access result (local)').some(step => step.payload.some(item => item.value === result.value)));
  for (const m of [denied, allowed, denied.contextualize({ unixAccount: 'charlie' })]) assert.deepEqual(validateProtocolScenario(m).errors, []);
});
