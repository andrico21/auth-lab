import test from 'node:test';
import assert from 'node:assert/strict';
import { SSHLAB_SCENARIOS } from '../src/ssh-access-lab.js';
import { buildSSHHeldObjects } from '../src/held-object-ssh.js';
import { compileHeldObjects, projectHeldObjects, inspectHeldObject, heldObjectTrace, assertHeldObjectCoverage } from '../src/held-object-state.js';

const model = suffix => SSHLAB_SCENARIOS.find(item => item.id === 'lab-ssh-' + suffix);
function fixture(m, revision = 'revision-1', actors = m.actors()) {
  const steps = m.steps();
  const plan = buildSSHHeldObjects({ model: m, steps, actors, config: {}, contextId: m.id + ':' + revision, choiceId: m.id });
  const compiled = compileHeldObjects(plan, { model: m, steps });
  const index = stage => {
    const result = steps.findIndex(step => step.sshStage === stage);
    assert.notEqual(result, -1, m.id + ': missing test source stage ' + stage);
    return result;
  };
  const frame = (stage, milestone = 'complete') => projectHeldObjects(compiled, { eventIndex: index(stage), milestone });
  return { model: m, steps, plan, compiled, index, frame, initial: () => projectHeldObjects(compiled, { eventIndex: -1, milestone: 'initial' }), final: () => projectHeldObjects(compiled, { eventIndex: steps.length - 1, milestone: 'complete' }) };
}
const holding = (snapshot, id, actor, store) => snapshot.holdings.find(item => item.artifactId === id && item.actorId === actor && (!store || item.store === store));
const artifact = (snapshot, id) => snapshot.artifacts.find(item => item.artifactId === id);
const observations = (snapshot, id, actor, kind) => snapshot.observations.filter(item => item.artifactId === id && item.actorId === actor && (!kind || item.kind === kind));
const fields = (snapshot, id) => artifact(snapshot, id).representations[0].fields;
const field = (snapshot, id, name) => fields(snapshot, id).find(item => item.name === name)?.value;

// Every choice exercises the engine's transition, binding and bounded temporary
// retention validation, not just the presence of a metadata object.
test('A21: all 29 SSH choices have complete logical actor/store/cursor coverage', () => {
  assert.equal(SSHLAB_SCENARIOS.length, 29);
  const counts = { cert: 0, device: 0, sssd: 0, gss: 0 };
  for (const m of SSHLAB_SCENARIOS) {
    counts[m.id.split('-')[2]]++;
    const f = fixture(m);
    assert.doesNotThrow(() => assertHeldObjectCoverage(f.compiled), m.id);
    assert.deepEqual(new Set(f.plan.coverage.map(item => item.actorId)), new Set(Object.keys(m.actors())));
    assert.ok(f.plan.coverage.every(item => item.status === 'complete' && item.support === 'supported' && item.gaps.length === 0), m.id);
    assert.ok(f.final().holdings.every(item => item.retention === 'retained'), m.id + ': no final proof/response scratch holding');
    for (let i = -1; i < f.steps.length; i++) {
      const cursor = i === -1 ? { eventIndex: -1, milestone: 'initial' } : { eventIndex: i, milestone: 'complete' };
      const snapshot = projectHeldObjects(f.compiled, cursor);
      assert.equal(snapshot.contextId, f.plan.contextId);
      assert.equal(snapshot.coverageStatus, 'complete');
      assert.equal(new Set(snapshot.holdings.map(item => item.holdingId)).size, snapshot.holdings.length);
    }
  }
  assert.deepEqual(counts, { cert: 13, device: 6, sssd: 8, gss: 2 });
  assert.equal(buildSSHHeldObjects({ model: null }), null);
  assert.equal(buildSSHHeldObjects({ model: { family: 'not-ssh' } }), null);
  assert.throws(() => buildSSHHeldObjects({ model: { family: 'ssh-access', id: 'lab-ssh-cert-unknown' } }), /Unsupported SSH/);
});

test('A01/A14: configured factors, keys and trust precede future key/token/certificate creation', () => {
  const f = fixture(model('cert-success'));
  const start = f.initial();
  for (const [id, actor, store] of [
    ['password', 'user', 'memorized credentials'],
    ['password-verifier', 'sshIdp', 'factor enrollment'],
    ['totp-seed', 'totp', 'authenticator secret store'],
    ['totp-seed', 'sshIdp', 'factor enrollment'],
    ['ca-private-key', 'sshCa', 'CA signing key store'],
    ['ca-public-key', 'sshCa', 'CA signing key store'],
    ['idp-signing-key', 'sshIdp', 'issuer signing key store'],
    ['host-private-key', 'sshHost', 'host key store'],
    ['host-public-key', 'sshHost', 'host key store'],
    ['known-host', 'sshCli', 'known_hosts'],
    ['https-trust', 'sshCli', 'HTTPS trust store'],
    ['user-ca-trust', 'sshHost', 'sshd trust policy'],
  ]) assert.ok(holding(start, id, actor, store), id);
  for (const id of ['user-private-key-1', 'totp-code-1', 'authorization-code-1', 'id-token-1', 'certificate-1', 'ssh-connection']) assert.equal(artifact(start, id), undefined, id);
  assert.notEqual('password', 'password-verifier');
  assert.equal(field(start, 'password-verifier', 'password verifier'), 'Configured password-verification material; not server plaintext');
  const earlyFailure = fixture(model('cert-callback')).initial();
  assert.ok(holding(earlyFailure, 'host-private-key', 'sshHost'), 'configured host material still exists in an early terminal branch');
});

test('A04/A05: certificate issuance, delivery, agent installation and offline host acceptance stay separate', () => {
  const f = fixture(model('cert-success'));
  assert.ok(holding(f.frame('issue'), 'certificate-1', 'sshCa'));
  assert.equal(holding(f.frame('issue'), 'certificate-1', 'sshCli'), undefined);
  assert.equal(holding(f.frame('certificate', 'before'), 'certificate-1', 'sshCli'), undefined);
  assert.ok(holding(f.frame('certificate'), 'certificate-1', 'sshCli', 'certificate files'));
  assert.equal(holding(f.frame('certificate'), 'certificate-1', 'sshCa'), undefined, 'CA response buffer was released, not treated as permanent archive');
  assert.equal(holding(f.frame('certificate'), 'certificate-1', 'sshAgent'), undefined);
  assert.ok(holding(f.frame('install'), 'certificate-1', 'sshAgent', 'agent certificate store'));
  assert.ok(holding(f.frame('install'), 'certificate-1', 'sshCli', 'certificate files'), 'installation copies the retained downloaded certificate');
  assert.ok(holding(f.frame('userauth'), 'certificate-1', 'sshHost', 'presented certificate'));
  assert.equal(observations(f.frame('userauth'), 'certificate-1', 'sshHost', 'acceptance').length, 0);
  assert.equal(observations(f.frame('host-policy'), 'certificate-1', 'sshHost', 'acceptance')[0].result, 'accepted_existing_account_policy');
  assert.equal(holding(f.frame('host-policy'), 'user-proof', 'sshHost'), undefined, 'one-use verification proof released');
  const tokenEvent = f.plan.events[f.steps[f.index('tokens')].id];
  assert.equal(tokenEvent.messages.length, 1, 'token response fields are one authored delivery');
  assert.equal(tokenEvent.messages[0].objects.length, 2, 'ID and access tokens retain distinct object identities within the response');
});

test('HC05: server acceptance does not authenticate the SSH client before success receipt', () => {
  for (const [suffix, check, result] of [
    ['cert-success', 'host-policy', 'ssh-success'],
    ['device-cadence', 'host-policy', 'ssh-success'],
    ['gss-success', 'mic-check', 'result'],
  ]) {
    const f = fixture(model(suffix));
    const beforeCheck = f.frame(check, 'before');
    const checking = projectHeldObjects(f.compiled, { eventIndex: f.index(check), progress: 0.5 });
    for (const snapshot of [beforeCheck, checking]) {
      assert.equal(holding(snapshot, 'ssh-connection', 'sshHost'), undefined, suffix);
      assert.equal(holding(snapshot, 'ssh-connection', 'sshCli'), undefined, suffix);
      assert.equal(snapshot.state.sessions.ssh.authenticated, false, suffix);
    }
    const accepted = f.frame(check);
    assert.ok(holding(accepted, 'ssh-connection', 'sshHost'), suffix);
    assert.equal(accepted.state.sessions.ssh.authenticated, true, 'family flag is the server decision');
    assert.equal(holding(accepted, 'ssh-connection', 'sshCli'), undefined, suffix);
    assert.equal(observations(accepted, 'ssh-connection', 'sshCli', 'acceptance').length, 0);
    for (const progress of [0, 0.5, 0.999]) {
      const pending = projectHeldObjects(f.compiled, { eventIndex: f.index(result), progress });
      assert.ok(holding(pending, 'ssh-connection', 'sshHost'), suffix);
      assert.equal(holding(pending, 'ssh-connection', 'sshCli'), undefined, suffix + ': client waits for whole success message');
      assert.equal(observations(pending, 'ssh-connection', 'sshCli', 'acceptance').length, 0);
    }
    const received = f.frame(result);
    assert.ok(holding(received, 'ssh-connection', 'sshHost'), suffix);
    assert.ok(holding(received, 'ssh-connection', 'sshCli'), suffix);
    assert.deepEqual(observations(received, 'ssh-connection', 'sshCli', 'acceptance').map(item => item.result), ['accepted_success_receipt']);
    assert.equal(holding(received, 'channel-1', 'sshCli'), undefined, 'authentication receipt does not open a channel');
    assert.ok(holding(f.frame('channel'), 'channel-1', 'sshCli'), suffix);
    assert.deepEqual(f.plan.bindings.filter(item => item.path === 'sessions.ssh.authenticated').map(item => item.actorId), ['sshHost']);
    const wire = f.plan.events[f.steps[f.index(result)].id].messages;
    assert.equal(wire.length, 1);
    assert.deepEqual([wire[0].from, wire[0].to, wire[0].start, wire[0].end], ['sshHost', 'sshCli', 0, 1]);
    assert.deepEqual(f.frame(check), accepted, 'rewinding must restore server-only acceptance');
    assert.equal(holding(f.frame(result, 'before'), 'ssh-connection', 'sshCli'), undefined, 'rewinding before receipt removes client completion');
  }
});

test('A14/A19: private keys remain local and CLI/agent are independent under visual collapse', () => {
  const m = model('cert-success');
  const f = fixture(m, 'collapsed', Object.fromEntries(Object.entries(m.actors()).map(([id, actor]) => [id, { ...actor, ...(id === 'sshAgent' ? { parentId: 'sshCli', collapsed: true } : {}) }])));
  const installed = f.frame('install');
  const cliKey = holding(installed, 'user-private-key-1', 'sshCli', 'local key file');
  const agentKey = holding(installed, 'user-private-key-1', 'sshAgent', 'agent key store');
  assert.ok(cliKey);
  assert.ok(agentKey);
  assert.notEqual(cliKey.holdingId, agentKey.holdingId);
  assert.equal(cliKey.artifactId, agentKey.artifactId);
  assert.ok(inspectHeldObject(installed, cliKey.holdingId).fields.every(item => item.readable));
  for (const event of Object.values(f.plan.events)) for (const wire of event.messages || []) {
    assert.equal(wire.objects.some(item => ['user-private-key-1', 'ca-private-key', 'host-private-key', 'totp-seed'].includes(item.artifactId)), false);
  }
  for (const actor of ['sshIdp', 'sshCa', 'sshHost', 'browser', 'user']) assert.equal(holding(f.final(), 'user-private-key-1', actor), undefined);
  assert.equal(holding(f.frame('agent-request'), 'user-proof', 'sshCli'), undefined);
  assert.ok(holding(f.frame('agent-proof'), 'user-proof', 'sshCli'));
  assert.equal(holding(f.frame('userauth'), 'user-proof', 'sshCli'), undefined);
});

test('A15: reissuance creates immutable generation 2 while explicit CLI file retention differs from agent selection', () => {
  const f = fixture(model('cert-reissue'));
  const issued = f.frame('reissue-issue');
  assert.ok(artifact(issued, 'certificate-1'));
  assert.ok(artifact(issued, 'certificate-2'));
  assert.notEqual(field(issued, 'certificate-1', 'crt'), field(issued, 'certificate-2', 'crt'));
  assert.equal(field(issued, 'certificate-1', 'serial'), 1);
  assert.equal(field(issued, 'certificate-2', 'serial'), 2);
  assert.deepEqual(artifact(issued, 'certificate-2').replaces, ['certificate-1']);
  assert.ok(holding(issued, 'certificate-1', 'sshAgent'));
  assert.equal(holding(issued, 'certificate-2', 'sshAgent'), undefined, 'issuance does not install');
  assert.ok(holding(f.frame('reissue-certificate'), 'certificate-2', 'sshCli'));
  assert.ok(holding(f.frame('reissue-install'), 'certificate-2', 'sshAgent'));
  assert.equal(holding(f.frame('reissue-install'), 'certificate-1', 'sshAgent'), undefined, 'agent previous selection explicitly released');
  assert.ok(holding(f.frame('reissue-install'), 'certificate-1', 'sshCli', 'certificate files'), 'old downloaded file retained by explicit metadata, not inferred from history');
  assert.ok(holding(f.final(), 'user-private-key-1', 'sshAgent'));
  assert.ok(holding(f.final(), 'ssh-connection', 'sshHost'));
  assert.equal(artifact(f.final(), 'certificate-1').expiresAt, 1791385200);
  assert.equal(f.final().protocolClock, 1791381720);
});

test('A03/A15: CA publication, installed host knowledge, token/certificate expiry and existing SSH connection are independent', () => {
  const f = fixture(model('cert-lifecycle'));
  const published = f.frame('publish-revocation');
  assert.ok(holding(published, 'published-krl', 'sshCa'));
  assert.equal(holding(published, 'installed-krl', 'sshHost'), undefined);
  assert.deepEqual(published.state.knowledge.host.revokedSerials, []);
  assert.ok(holding(published, 'certificate-1', 'sshCli'));
  const installed = f.frame('install-revocation');
  assert.ok(holding(installed, 'installed-krl', 'sshHost'));
  assert.deepEqual(installed.state.knowledge.host.revokedSerials, [1]);
  assert.equal(observations(f.frame('new-auth-revoked'), 'certificate-1', 'sshHost', 'acceptance').at(-1).result, 'new_authentication_rejected_revoked');
  const expired = f.frame('certificate-expiry');
  assert.ok(holding(expired, 'id-token-1', 'sshCli'), 'token expiry does not delete retained token bytes');
  assert.ok(holding(expired, 'certificate-1', 'sshCli'));
  const cert = holding(expired, 'certificate-1', 'sshAgent');
  assert.equal(inspectHeldObject(expired, cert.holdingId).expired, true);
  assert.ok(holding(expired, 'ssh-connection', 'sshHost'));
  assert.equal(expired.state.sessions.ssh.authenticated, true);
  const final = f.final();
  assert.ok(holding(final, 'channel-1', 'sshHost'));
  assert.ok(holding(final, 'channel-2', 'sshHost'));
  assert.equal(artifact(final, 'certificate-2'), undefined, 'hypothetical reissuance shape never becomes issued inventory');
  assert.equal(holding(f.frame('host-before-install'), 'installed-krl', 'sshHost'), undefined, 'rewinding restores absent installed knowledge');
});

test('A05/A06: wrong-audience token and rejected certificate remain held without invented success', () => {
  const audience = fixture(model('cert-audience'));
  const rejected = audience.final();
  assert.ok(holding(rejected, 'id-token-1', 'sshCli'));
  assert.ok(holding(rejected, 'id-token-alternate', 'sshCli'));
  assert.ok(holding(rejected, 'id-token-alternate', 'sshCa'));
  assert.equal(observations(rejected, 'id-token-alternate', 'sshCa', 'verification')[0].result, 'rejected_wrong_audience');
  assert.equal(artifact(rejected, 'certificate-1'), undefined);
  for (const suffix of ['userca', 'copy', 'session', 'account', 'root']) {
    const f = fixture(model('cert-' + suffix));
    assert.ok(holding(f.final(), 'certificate-1', 'sshCli'), suffix);
    assert.ok(holding(f.final(), 'certificate-1', 'sshAgent'), suffix);
    assert.equal(artifact(f.final(), 'ssh-connection'), undefined, suffix);
    assert.equal(f.final().state.sessions.ssh.authenticated, false);
  }
  const copy = fixture(model('cert-copy')).final();
  assert.equal(holding(copy, 'user-private-key-1', 'sshAgent'), undefined);
  assert.ok(holding(copy, 'user-private-key-2', 'sshAgent'));
  assert.ok(holding(copy, 'user-private-key-1', 'sshCli'), 'comparison recipient does not erase source workstation file');
});

test('A18: failed callback/PKCE cannot invent token/certificate acquisitions and retain expected transaction identity in history', () => {
  for (const suffix of ['callback', 'pkce']) {
    const f = fixture(model('cert-' + suffix));
    assert.equal(artifact(f.final(), 'id-token-1'), undefined);
    assert.equal(artifact(f.final(), 'certificate-1'), undefined);
    assert.equal(holding(f.final(), 'oidc-transaction-1', 'sshCli'), undefined, 'terminal transaction secrets released');
    assert.ok(artifact(f.final(), 'oidc-transaction-1'), 'exact immutable history remains');
    assert.ok(holding(f.final(), 'user-private-key-1', 'sshCli'));
  }
  const callback = fixture(model('cert-callback'));
  assert.notEqual(field(callback.final(), 'callback-1', 'state'), field(callback.final(), 'oidc-transaction-1', 'state'));
  const pkce = fixture(model('cert-pkce'));
  assert.notEqual(field(pkce.final(), 'redemption-1', 'code_verifier'), field(pkce.final(), 'oidc-transaction-1', 'code_verifier'));
});

test('A18: contextual account artifacts use the rebuilt fixture including actual new certificate wire bytes', () => {
  const base = fixture(model('cert-success'));
  const contextual = model('cert-success').contextualize({ unixAccount: 'casey', aIssuerURL: 'https://login.example.test/casey' });
  const f = fixture(contextual, 'revision-2');
  const source = contextual.steps().find(step => step.sshStage === 'issue');
  const certOp = source.attributeOperations.find(item => item.attributeId.endsWith('_cert'));
  assert.equal(field(f.final(), 'certificate-1', 'crt'), certOp.value);
  assert.notEqual(field(f.final(), 'certificate-1', 'crt'), field(base.final(), 'certificate-1', 'crt'));
  assert.deepEqual(field(f.final(), 'certificate-1', 'valid principals'), ['casey']);
  assert.equal(field(f.final(), 'id-token-1', 'iss'), 'https://login.example.test/casey');
  assert.equal(field(f.final(), 'userauth-input', 'user name'), 'casey');
  assert.notEqual(f.final().contextId, base.final().contextId);
  assert.throws(() => model('cert-success').contextualize({ unixAccount: 'invalid account' }), /valid example Unix account/);
  assert.deepEqual(field(base.final(), 'certificate-1', 'valid principals'), ['alice'], 'failed context cannot mutate canonical fixture');
  const root = fixture(model('cert-root').contextualize({ unixAccount: 'root' }));
  assert.deepEqual(field(root.final(), 'certificate-1', 'valid principals'), ['root']);
  assert.equal(field(root.final(), 'userauth-input', 'user name'), 'administrator', 'authored mismatch branch remains a mismatch after account rebuild');
  assert.equal(artifact(root.final(), 'ssh-connection'), undefined);
});

test('A18: cancelled and restarted Device results obey terminal state and independent generation identity', () => {
  const cancelled = fixture(model('device-cancel'));
  assert.ok(holding(cancelled.frame('late-response'), 'late-id-token', 'sshCli'));
  assert.equal(holding(cancelled.frame('ignore-late'), 'late-id-token', 'sshCli'), undefined);
  assert.equal(artifact(cancelled.final(), 'certificate-1'), undefined);
  assert.equal(cancelled.final().state.transaction.lateResultIgnored, true);
  const restarted = fixture(model('device-restart'));
  assert.ok(artifact(restarted.final(), 'device-code-1'));
  assert.ok(artifact(restarted.final(), 'device-code-2'));
  assert.equal(holding(restarted.final(), 'device-code-1', 'sshCli'), undefined);
  assert.equal(holding(restarted.final(), 'late-id-token', 'sshCli'), undefined);
  assert.ok(holding(restarted.final(), 'id-token-2', 'sshCli'));
  assert.equal(artifact(restarted.final(), 'id-token-1'), undefined);
  assert.ok(holding(restarted.final(), 'certificate-1', 'sshAgent'));
  const expired = fixture(model('device-expired'));
  const heldAtExpiry = expired.frame('expire-clock');
  const code = holding(heldAtExpiry, 'device-code-1', 'sshCli');
  assert.ok(code);
  assert.equal(inspectHeldObject(heldAtExpiry, code.holdingId).expired, true);
  assert.equal(holding(expired.final(), 'device-code-1', 'sshCli'), undefined, 'explicit terminal cleanup, not clock alone, releases it');
});

test('HC04: local Device cancellation preserves valid issuer state while clearing polling and display copies', () => {
  for (const suffix of ['device-cancel', 'device-restart']) {
    const f = fixture(model(suffix));
    const before = f.frame('cancel', 'before');
    const cancelling = projectHeldObjects(f.compiled, { eventIndex: f.index('cancel'), progress: 0.999 });
    const cancelled = f.frame('cancel');
    for (const snapshot of [before, cancelling]) {
      assert.ok(holding(snapshot, 'device-code-1', 'sshCli', 'private polling state'), suffix);
      assert.ok(holding(snapshot, 'device-instructions-1', 'sshCli', 'approval display'), suffix);
      assert.ok(holding(snapshot, 'device-instructions-1', 'user', 'approval display'), suffix);
      assert.notEqual(snapshot.state.transaction.status, 'cancelled');
    }
    assert.equal(cancelled.state.transaction.status, 'cancelled');
    for (const snapshot of [cancelled, f.frame('late-response'), f.frame('ignore-late'), f.final()]) {
      assert.equal(holding(snapshot, 'device-code-1', 'sshCli'), undefined, suffix);
      assert.equal(holding(snapshot, 'device-instructions-1', 'sshCli'), undefined, suffix);
      assert.equal(holding(snapshot, 'device-instructions-1', 'user'), undefined, suffix);
      for (const id of ['device-code-1', 'device-instructions-1']) {
        const issuer = holding(snapshot, id, 'sshIdp', 'pending Device transaction');
        assert.ok(issuer, suffix + '/' + id + ': no remote cancellation was authored');
        assert.deepEqual(issuer, holding(before, id, 'sshIdp', 'pending Device transaction'));
        assert.equal(issuer.retention, 'retained', 'issuer lifecycle can outlive the local walkthrough');
        assert.equal(inspectHeldObject(snapshot, issuer.holdingId).expired, false);
        assert.ok(snapshot.protocolClock < artifact(snapshot, id).expiresAt);
      }
      assert.equal(snapshot.authority.some(item => item.artifactId === 'device-code-1' && item.authorityId === 'sshIdp'), false, 'local cancellation is not issuer invalidation');
    }
    const late = f.frame('late-response');
    for (const id of ['late-id-token', 'late-access-token']) {
      assert.ok(holding(late, id, 'sshCli'), suffix);
      assert.equal(holding(f.frame('ignore-late'), id, 'sshCli'), undefined, suffix);
    }
    assert.equal(observations(f.frame('ignore-late'), 'late-id-token', 'sshCli', 'acceptance')[0].result, 'rejected_cancelled_transaction');
    assert.deepEqual(f.frame('cancel', 'before'), before, 'rewinding restores only authored local cleanup');
    if (suffix === 'device-restart') {
      const fresh = f.frame('restart-response');
      assert.ok(holding(fresh, 'device-code-1', 'sshIdp', 'pending Device transaction'));
      assert.ok(holding(fresh, 'device-code-2', 'sshIdp', 'pending Device transaction'));
      assert.ok(holding(fresh, 'device-code-2', 'sshCli', 'private polling state'));
      assert.notEqual(field(fresh, 'device-code-1', 'device_code'), field(fresh, 'device-code-2', 'device_code'));
      assert.notEqual(field(fresh, 'device-instructions-1', 'user_code'), field(fresh, 'device-instructions-2', 'user_code'));
      assert.notEqual(artifact(fresh, 'device-code-1').qualifiedArtifactId, artifact(fresh, 'device-code-2').qualifiedArtifactId);
      assert.equal(fresh.state.transactions.old.status, 'cancelled');
      assert.equal(fresh.state.transaction.instanceId, f.model.id + ':device-transaction-2');
      assert.equal(holding(f.frame('tokens'), 'device-code-2', 'sshIdp', 'pending Device transaction'), undefined, 'authored issuer token response completes only generation 2');
      assert.ok(holding(f.frame('tokens'), 'device-code-1', 'sshIdp', 'pending Device transaction'));
    }
  }
});

test('A06/A14/A19: SSSD keeps private client/code/token data remote and separates directory permission from user authentication', () => {
  for (const suffix of ['success', 'cached', 'bob', 'domain', 'account', 'zero']) {
    const f = fixture(model('sssd-' + suffix));
    const result = f.frame('token-result');
    assert.ok(holding(result, 'interactive-token', 'sssd'));
    assert.equal(holding(f.frame('provider-evaluation'), 'interactive-token', 'sssd'), undefined, 'tokenCache:false evaluation buffer is released');
    for (const actor of ['sshCli', 'browser', 'user', 'pam', 'sshHost']) {
      for (const id of ['remote-client-auth', 'lookup-secret', 'remote-device-code', 'interactive-token', 'directory-token']) assert.equal(holding(result, id, actor), undefined, suffix + '/' + actor + '/' + id);
    }
    if (['bob', 'domain', 'account'].includes(suffix)) assert.equal(artifact(f.final(), 'ssh-connection'), undefined);
    else assert.ok(holding(f.final(), 'ssh-connection', 'sshHost'));
  }
  const cached = fixture(model('sssd-cached'));
  assert.ok(holding(cached.initial(), 'provider-identity', 'sssd', 'NSS identity cache'));
  assert.ok(holding(cached.initial(), 'unix-identity', 'sssd', 'NSS identity cache'));
  assert.equal(artifact(cached.final(), 'directory-token'), undefined, 'cached lookup does not invent a service token');
  const denied = fixture(model('sssd-permission'));
  assert.ok(holding(denied.final(), 'directory-token', 'sssd'), 'API 403-like permission failure does not erase service token');
  assert.equal(artifact(denied.final(), 'remote-device-code'), undefined);
  assert.equal(artifact(denied.final(), 'interactive-token'), undefined);
});

test('A01/A06: GSS cached start, service credential, context and SSH authorization remain distinct', () => {
  const f = fixture(model('gss-account'));
  assert.ok(holding(f.initial(), 'home-tgt', 'sshCli'));
  assert.ok(holding(f.initial(), 'home-session-key', 'sshCli'));
  assert.ok(holding(f.initial(), 'host-service-key', 'sshHost'));
  assert.equal(artifact(f.initial(), 'host-ticket'), undefined);
  assert.equal(artifact(f.initial(), 'gss-context'), undefined);
  assert.ok(holding(f.frame('service-ticket'), 'host-ticket', 'sshCli'));
  assert.ok(holding(f.frame('context-complete'), 'gss-context', 'sshHost'));
  assert.equal(f.final().state.sessions.gss.established, true);
  assert.equal(f.final().state.sessions.ssh.authenticated, false);
  assert.equal(artifact(f.final(), 'ssh-connection'), undefined);
});

test('A16: exact-object replay uses full canonical prefix and is deterministic after renewal/rewind', () => {
  const f = fixture(model('cert-reissue'));
  const expected = f.frame('reissue-install');
  const rows = heldObjectTrace(f.compiled, 'certificate-2');
  assert.ok(rows.length > 0);
  const installed = rows.find(row => row.sourceStepId === f.steps[f.index('reissue-install')].id);
  assert.ok(installed);
  assert.deepEqual(projectHeldObjects(f.compiled, installed.heldCursorEnd), expected);
  const before = f.frame('certificate', 'before');
  f.final();
  assert.deepEqual(f.frame('certificate', 'before'), before);
  assert.deepEqual(f.frame('reissue-install'), expected);
  assert.equal(holding(before, 'certificate-1', 'sshCli'), undefined);
  assert.ok(holding(expected, 'user-private-key-1', 'sshAgent'), 'hidden original key installation survives exact certificate-2 replay');
});
