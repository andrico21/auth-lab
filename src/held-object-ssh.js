import { createHeldObjectPlan, heldArtifact, heldAt, heldAcquire, heldRelease, heldCoverage } from './held-object-authoring.js';

// These recipes name fixture fields and source events explicitly. Attribute
// operations supply contextualized values, never an inferred object inventory.
const EPOCH = 1791381600;
const CERT_CHOICES = ['success', 'audience', 'principal', 'host', 'userca', 'copy', 'session', 'account', 'root', 'callback', 'pkce', 'reissue', 'lifecycle'];
const DEVICE_CHOICES = ['cadence', 'cancel', 'restart', 'denied', 'expired', 'clienterror'];
const SSSD_CHOICES = ['success', 'cached', 'bob', 'domain', 'account', 'lookup', 'permission', 'zero'];
const GSS_CHOICES = ['success', 'account'];
const CERT_FIELDS = ['cert', 'serial', 'principal', 'validAfter', 'validBefore', 'caSignature'];

function author(args) {
  const { model, steps, actors } = args;
  const plan = createHeldObjectPlan(args);
  const stages = new Map(steps.map(step => [step.sshStage, step]));
  // The shipped schema uses underscores for punctuation in the choice prefix.
  const fieldPrefix = 'ssh' + model.id.replace(/^lab-ssh-/, '').replace(/[^a-zA-Z0-9]/g, '_') + '_';
  const stores = new Map(Object.keys(actors).map(actorId => [actorId, new Set()]));
  const categories = new Map(Object.keys(actors).map(actorId => [actorId, new Set()]));
  const declared = new Map();
  const at = (stage, ...effects) => {
    if (stage !== null && !stages.has(stage)) throw new TypeError('Unknown SSH held-object stage: ' + stage);
    heldAt(plan, stage === null ? null : stages.get(stage).id, ...effects);
  };
  const value = (stage, key, instance) => {
    const source = stages.get(stage);
    if (!source) throw new TypeError('Missing SSH fixture stage: ' + stage);
    const operation = source.attributeOperations.find(item => item.attributeId === fieldPrefix + key && (!instance || item.instanceId === model.id + ':' + instance));
    if (!operation) throw new TypeError('Missing contextual SSH field: ' + stage + '/' + key);
    return { attributeId: operation.attributeId, name: model.definitions()[operation.attributeId]?.name || key, value: operation.value };
  };
  const fields = (stage, keys, instance) => keys.map(key => value(stage, key, instance));
  const literal = (name, data) => ({ attributeId: fieldPrefix + 'held_' + name.replace(/[^A-Za-z0-9]/g, '_'), name, value: data });
  const define = (id, type, label, creator, objectFields, stage, options = {}) => {
    if (declared.has(id)) throw new TypeError('Duplicate SSH held object: ' + id);
    const definition = {
      artifactId: id, type, label, creator,
      representations: [{ representationId: 'plain', format: options.format || 'reference fixture', readableBy: options.readableBy || Object.keys(actors), fields: objectFields }],
      ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
      ...(options.derivedFrom ? { derivedFrom: options.derivedFrom } : {}),
      ...(options.replaces ? { replaces: options.replaces } : {}),
      ...(options.related ? { related: options.related } : {}),
      ...(options.details ? { details: options.details } : {}),
    };
    heldArtifact(plan, definition);
    declared.set(id, definition);
    at(stage, { op: 'create', artifactId: id });
    return id;
  };
  const hold = (stage, id, actorId, store, options = {}) => {
    if (!stores.has(actorId)) throw new TypeError('Unknown SSH holder: ' + actorId);
    stores.get(actorId).add(store);
    categories.get(actorId).add(declared.get(id).type);
    const effect = heldAcquire(id, actorId, store, options);
    at(stage, effect);
    return effect.holdingId;
  };
  const release = (stage, id, actorId, store, options = {}) => at(stage, heldRelease(id, actorId, store, options));
  const observe = (stage, id, actorId, kind, result, detail) => at(stage, { op: 'observe', artifactId: id, actorId, kind, result, ...(detail ? { detail } : {}) });
  const authority = (stage, id, authorityId, status) => at(stage, { op: 'authority', artifactId: id, authorityId, status });
  const transfer = (stage, id, from, to, store, releaseAt, options = {}) => {
    const holdingId = to + '|' + id + '|receipt|' + stage;
    hold(stage, id, to, store, { holdingId, retention: releaseAt ? 'temporary' : 'retained' });
    if (releaseAt) at(releaseAt, { op: 'release', holdingId });
    const stepId = stages.get(stage).id;
    const entry = plan.events[stepId];
    const messageId = stepId + ':' + from + '->' + to;
    const messages = entry.messages ||= [];
    let wire = messages.find(item => item.messageId === messageId);
    if (!wire) messages.push(wire = { messageId, from, to, objects: [], start: 0, end: 1 });
    wire.objects.push({ artifactId: id, representationId: 'plain' });
    if (options.releaseSender) release(stage, id, from, options.releaseSender);
  };
  // A source event may atomically produce and deliver a proof/result. Its
  // creation is committed at arrival, not invented as a percentage milestone.
  const message = (stage, id, type, label, from, to, keys, releaseAt, options = {}) => {
    define(id, type, label, from, fields(stage, keys, options.instance), stage, options);
    const outputId = from + '|' + id + '|output|' + stage;
    hold(stage, id, from, 'message output', { holdingId: outputId, retention: 'temporary' });
    at(stage, { op: 'release', holdingId: outputId });
    transfer(stage, id, from, to, options.store || 'message inbox', releaseAt);
  };
  const bind = (path, actorId, artifactId, store, equals) => plan.bindings.push({ path, actorId, artifactId, representationId: 'plain', store, ...(equals === undefined ? { presentWhen: 'truthy' } : { equals }) });
  const finish = () => {
    for (const actorId of Object.keys(actors)) heldCoverage(plan, actorId, {
      stores: [...stores.get(actorId)], categories: [...categories.get(actorId)], support: 'supported',
      rationale: 'Explicit SSH fixture initial, receipt, local-store and release recipes; complete over every authored source cursor.',
    });
    return plan;
  };
  return { plan, model, stages, at, value, fields, literal, define, hold, release, observe, authority, transfer, message, bind, finish };
}

function transportSetup(a) {
  const { define, literal, hold, fields, stages } = a;
  define('host-private-key', 'private-key', 'SSH server private host key', 'sshHost', [literal('protected host key', 'Configured host-private-key handle; secret bytes are not modeled')], null, { readableBy: ['sshHost'] });
  hold(null, 'host-private-key', 'sshHost', 'host key store');
  define('host-public-key', 'public-key', 'SSH server public host key', 'sshHost', stages.has('host-exchange') ? fields('host-exchange', ['hostKey']) : [literal('configured public host key', 'ssh-ed25519 host-key-reference')], null);
  hold(null, 'host-public-key', 'sshHost', 'host key store');
  define('known-host', 'trust-record', 'Configured SSH server trust', 'sshCli', [literal('host trust', 'Out-of-band expected host key and hostname; untrusted-host comparison intentionally fails')], null, { readableBy: ['sshCli'] });
  hold(null, 'known-host', 'sshCli', 'known_hosts');
}

function transport(a, family) {
  const { define, literal, hold, fields, message, observe, stages, bind } = a;
  const check = family === 'device' ? 'transport' : 'host-check';
  a.transfer('host-exchange', 'host-public-key', 'sshHost', 'sshCli', 'host key exchange', check);
  if (family !== 'gss') message('host-exchange', 'host-exchange-proof', 'signature', 'SSH host exchange signature', 'sshHost', 'sshCli', [family === 'sssd' ? 'hostProof' : 'hostSignature'], check, { derivedFrom: ['host-private-key'] });
  observe(check, 'host-public-key', 'sshCli', 'verification', a.model.id === 'lab-ssh-cert-host' ? 'rejected_untrusted_host_key' : 'accepted_expected_host');
  if (a.model.id !== 'lab-ssh-cert-host') {
    define('ssh-transport', 'transport', 'Established SSH transport', 'sshCli', [literal('transport', 'Host-authenticated protected SSH transport')], check, { related: ['host-public-key'] });
    hold(check, 'ssh-transport', 'sshCli', 'SSH connection');
    hold(check, 'ssh-transport', 'sshHost', 'SSH connection');
    bind('sessions.ssh.transportReady', 'sshCli', 'ssh-transport', 'SSH connection');
    bind('sessions.ssh.transportReady', 'sshHost', 'ssh-transport', 'SSH connection');
    if (family === 'certificate' && stages.has('transport-id')) {
      define('session-id', 'session-binding', 'First SSH exchange hash', 'sshCli', fields('transport-id', ['sessionId']), 'transport-id', { related: ['ssh-transport'], readableBy: ['sshCli', 'sshAgent', 'sshHost'] });
      hold('transport-id', 'session-id', 'sshCli', 'SSH connection');
      hold('transport-id', 'session-id', 'sshHost', 'SSH connection');
      bind('sessions.ssh.sessionIdentifier', 'sshCli', 'session-id', 'SSH connection');
    } else if (family === 'device' || family === 'gss') {
      define('session-id', 'session-binding', 'First SSH exchange hash', 'sshCli', fields(check, [family === 'gss' ? 'session' : 'sessionId']), check, { related: ['ssh-transport'], readableBy: ['sshCli', 'sshAgent', 'sshHost'].filter(id => a.model.actors()[id]) });
      hold(check, 'session-id', 'sshCli', 'SSH connection');
      hold(check, 'session-id', 'sshHost', 'SSH connection');
    }
  }
}

function certificateSetup(a, isDevice) {
  const { define, hold, fields, literal, stages, plan } = a;
  transportSetup(a);
  define('ca-private-key', 'private-key', 'SSH user-CA signing key', 'sshCa', [literal('protected CA key', 'Configured protected user-CA signing-key handle; secret bytes are not modeled')], null, { readableBy: ['sshCa'] });
  hold(null, 'ca-private-key', 'sshCa', 'CA signing key store');
  define('ca-public-key', 'public-key', 'SSH user-CA public key', 'sshCa', !isDevice && stages.has('issue') ? fields('issue', ['caPublic']) : [literal('user-CA public key', 'Configured user-CA public signing-key handle')], null, { derivedFrom: ['ca-private-key'] });
  hold(null, 'ca-public-key', 'sshCa', 'CA signing key store');
  define('user-ca-trust', 'trust-record', 'Trusted SSH user CA', 'sshHost', [literal('TrustedUserCAKeys', 'Configured user-CA public key; untrusted-user-CA comparison rejects this issuer')], null, { readableBy: ['sshHost'] });
  hold(null, 'user-ca-trust', 'sshHost', 'sshd trust policy');
  define('https-trust', 'trust-record', 'CA HTTPS transport trust', 'sshCli', [literal('CA HTTPS trust', 'Configured HTTPS CA endpoint trust, independent of SSH host and user-CA trust')], null, { readableBy: ['sshCli'] });
  hold(null, 'https-trust', 'sshCli', 'HTTPS trust store');
  define('idp-signing-key', 'private-key', 'IdP signing key', 'sshIdp', [literal('protected IdP signing key', 'Configured issuer signing-key handle; secret bytes are not modeled')], null, { readableBy: ['sshIdp'] });
  hold(null, 'idp-signing-key', 'sshIdp', 'issuer signing key store');
  define('idp-public-key', 'public-key', 'IdP public signing key', 'sshIdp', [literal('issuer public key', 'Configured issuer public signing-key handle')], null, { derivedFrom: ['idp-signing-key'] });
  hold(null, 'idp-public-key', 'sshIdp', 'issuer signing key store');
  define('oidc-trust', 'trust-record', 'Configured OIDC issuer signing trust', 'sshIdp', [literal('OIDC trust', 'Configured issuer and signing-key trust for this OIDC provisioner')], null, { readableBy: ['sshIdp', 'sshCli', 'sshCa'] });
  for (const actor of ['sshIdp', 'sshCli', 'sshCa']) hold(null, 'oidc-trust', actor, 'OIDC configuration');
  define('client-registration', 'client-registration', 'Enrollment public-client registration', 'sshIdp', fields(isDevice ? 'request' : 'prepare', ['client']), null);
  for (const actor of ['sshCli', 'sshIdp', 'sshCa']) hold(null, 'client-registration', actor, 'OIDC configuration');
  define('user-private-key-1', 'private-key', 'SSH user private key-1', 'sshCli', fields('prepare', ['privateKey']), 'prepare', { readableBy: ['sshCli', 'sshAgent'] });
  hold('prepare', 'user-private-key-1', 'sshCli', 'local key file');
  define('user-public-key-1', 'public-key', 'SSH user public key-1', 'sshCli', fields('prepare', ['publicKey']), 'prepare', { derivedFrom: ['user-private-key-1'] });
  hold('prepare', 'user-public-key-1', 'sshCli', 'local key file');
  if (stages.has('install')) {
    hold('install', 'user-private-key-1', 'sshAgent', 'agent key store');
    hold('install', 'user-public-key-1', 'sshAgent', 'agent key store');
  }
  plan.limitations.push('Synthetic cryptographic bytes and abstract configured secret/trust handles are teaching fixtures, not live usable credentials. No passkey ceremony is authored in these SSH choices.');
  plan.limitations.push('Explicit local retention policy: downloaded certificates remain in CLI certificate files; agent installation selects the new certificate and releases its previous certificate copy. CA response buffers are released on delivery, not treated as certificate history storage.');
  plan.limitations.push('CA enrollment authorization and host presented-certificate copies are explicitly retained as bounded-scenario request records for inspection; this is not a claim of permanent product token or certificate caching.');
}

function certificate(a, variant) {
  const { define, hold, fields, literal, transfer, message, observe, authority, release, stages, plan, bind } = a;
  certificateSetup(a, false);
  if (variant === 'host' || variant === 'userca') plan.limitations.push('Untrusted-host/user-CA comparisons author a failed trust-policy outcome; alternate key-set bytes are not specified by the shipped fixture.');
  define('password', 'password', 'Person password', 'user', fields('factor-input', ['password']), null, { readableBy: ['user', 'browser', 'sshIdp'] });
  hold(null, 'password', 'user', 'memorized credentials');
  define('password-verifier', 'password-verifier', 'IdP password verification material', 'sshIdp', [literal('password verifier', 'Configured password-verification material; not server plaintext')], null, { readableBy: ['sshIdp'] });
  hold(null, 'password-verifier', 'sshIdp', 'factor enrollment');
  define('totp-seed', 'otp-secret', 'Enrolled TOTP shared seed', 'sshIdp', [literal('enrolled TOTP seed', 'Configured shared seed; never sent with the one-time input')], null, { readableBy: ['totp', 'sshIdp'] });
  hold(null, 'totp-seed', 'totp', 'authenticator secret store');
  hold(null, 'totp-seed', 'sshIdp', 'factor enrollment');
  oidcCeremony(a, false);
  if (variant === 'callback' || variant === 'pkce') return;
  if (variant === 'audience') {
    define('id-token-alternate', 'id-token', 'Other-client ID token', 'sshIdp', fields('alternate-token-issued', ['token', 'iss', 'aud', 'sub', 'exp'], 'id-token-2'), 'alternate-token-issued', { expiresAt: EPOCH + 300, readableBy: ['sshIdp', 'sshCli', 'sshCa'] });
    hold('alternate-token-issued', 'id-token-alternate', 'sshIdp', 'token response buffer', { retention: 'temporary' });
    transfer('alternate-token-input', 'id-token-alternate', 'sshIdp', 'sshCli', 'comparison token input', null, { releaseSender: 'token response buffer' });
  }
  const token = variant === 'audience' ? 'id-token-alternate' : 'id-token-1';
  transfer('enroll', 'user-public-key-1', 'sshCli', 'sshCa', 'enrollment request', variant === 'audience' ? 'ca-identity' : variant === 'principal' ? 'ca-policy' : 'issue');
  transfer('enroll', token, 'sshCli', 'sshCa', 'enrollment authorization', null);
  define('enrollment-request-1', 'enrollment-request', 'Requested SSH certificate policy', 'sshCli', fields('enroll', ['certType', 'keyId', 'requestedPrincipals', 'validAfterRequest', 'validBeforeRequest']), 'enroll');
  hold('enroll', 'enrollment-request-1', 'sshCa', 'enrollment request');
  observe('ca-identity', token, 'sshCa', 'verification', variant === 'audience' ? 'rejected_wrong_audience' : 'accepted_provisioner_identity');
  if (variant === 'audience') return;
  observe('ca-policy', 'enrollment-request-1', 'sshCa', 'acceptance', variant === 'principal' ? 'rejected_unauthorized_principal' : 'approved_principal');
  if (variant === 'principal') return;
  issueAndUseCertificate(a, false, variant);
  if (variant === 'reissue') {
    oidcCeremony(a, true);
    transfer('reissue-enroll', 'user-public-key-1', 'sshCli', 'sshCa', 'enrollment request', 'reissue-issue');
    transfer('reissue-enroll', 'id-token-2', 'sshCli', 'sshCa', 'enrollment authorization', null);
    define('enrollment-request-2', 'enrollment-request', 'Second certificate request', 'sshCli', fields('reissue-enroll', ['certType', 'requestedPrincipals', 'validAfterRequest', 'validBeforeRequest']), 'reissue-enroll');
    hold('reissue-enroll', 'enrollment-request-2', 'sshCa', 'enrollment request');
    observe('reissue-policy', 'id-token-2', 'sshCa', 'verification', 'accepted_fresh_identity_and_policy');
    authority('reissue-policy', 'id-token-2', 'sshCa', 'consumed_for_enrollment');
    define('certificate-2', 'ssh-certificate', 'SSH user certificate-2', 'sshCa', [...fields('reissue-issue', CERT_FIELDS, 'certificate-2'), ...fields('reissue-issue', ['publicKey'])], 'reissue-issue', { format: 'base64 SSH certificate wire bytes and signed fields', expiresAt: EPOCH + 3720, derivedFrom: ['user-public-key-1', 'id-token-2'], replaces: ['certificate-1'], related: ['ca-public-key'] });
    hold('reissue-issue', 'certificate-2', 'sshCa', 'certificate response', { retention: 'temporary' });
    transfer('reissue-certificate', 'certificate-2', 'sshCa', 'sshCli', 'certificate files', null, { releaseSender: 'certificate response' });
    transfer('reissue-install', 'certificate-2', 'sshCli', 'sshAgent', 'agent certificate store', null);
    release('reissue-install', 'certificate-1', 'sshAgent', 'agent certificate store', { holdingId: 'sshAgent|certificate-1|receipt|install' });
    observe('reissue-install', 'certificate-2', 'sshAgent', 'acceptance', 'selected_with_existing_key_1');
  }
  if (variant === 'lifecycle') {
    authority('logout', 'idp-session', 'sshIdp', 'ended');
    release('logout', 'idp-session', 'sshIdp', 'SSO session store');
    authority('disable', 'idp-session', 'sshIdp', 'identity_disabled_for_future_sign_in');
    authority('deny-enrollment', 'certificate-1', 'sshCa', 'future_enrollment_denied');
    authority('token-expiry', 'id-token-1', 'sshIdp', 'expired');
    define('published-krl', 'revocation-record', 'CA published revocation serial 1', 'sshCa', [literal('revoked serials', [1])], 'publish-revocation', { related: ['certificate-1'] });
    hold('publish-revocation', 'published-krl', 'sshCa', 'published revocation store');
    authority('publish-revocation', 'certificate-1', 'sshCa', 'revocation_published');
    observe('host-before-install', 'certificate-1', 'sshHost', 'knowledge', 'no_installed_revocation_update');
    define('installed-krl', 'revocation-knowledge', 'Host installed revocation serial 1', 'sshHost', [literal('revoked serials', [1])], 'install-revocation', { derivedFrom: ['published-krl'], readableBy: ['sshHost'] });
    hold('install-revocation', 'installed-krl', 'sshHost', 'RevokedKeys/KRL store');
    bind('knowledge.host.revokedSerials', 'sshHost', 'installed-krl', 'RevokedKeys/KRL store', [1]);
    observe('install-revocation', 'certificate-1', 'sshHost', 'knowledge', 'revocation_installed');
    observe('new-auth-revoked', 'certificate-1', 'sshHost', 'acceptance', 'new_authentication_rejected_revoked');
    authority('account-lock', 'ssh-connection', 'sshHost', 'account_locked_for_future_authentication');
    authority('certificate-expiry', 'certificate-1', 'sshCa', 'expired');
    channel(a, 'additional-channel', 'channel-2');
    observe('reissue-policy', 'certificate-1', 'sshCa', 'acceptance', 'fresh_enrollment_denied_by_current_authorities');
    plan.limitations.push('The final hypothetical reissuance inspection is not a creation, issuance, delivery or installed holding. Existing SSH connections intentionally survive expiry, account lock and revocation in this reference policy.');
  }
}

function oidcCeremony(a, second) {
  const { define, fields, hold, transfer, observe, release, authority, stages, bind } = a;
  const n = second ? 2 : 1;
  const p = second ? 'reissue-' : '';
  const stage = key => p + key;
  const prepare = stage('prepare');
  const transaction = 'oidc-transaction-' + n;
  define(transaction, 'oidc-transaction', 'Pending OIDC transaction-' + n, 'sshCli', fields(prepare, ['verifier', 'state', 'oidcNonce', 'challenge']), prepare, { readableBy: ['sshCli'] });
  hold(prepare, transaction, 'sshCli', 'pending enrollment', { retention: 'temporary' });
  define('authorization-request-' + n, 'authorization-request', 'Public OIDC authorization request-' + n, 'sshCli', fields(second ? 'reissue-browser' : 'open-browser', ['client', 'redirect', 'responseType', 'scope', 'state', 'oidcNonce', 'challenge', 'challengeMethod']), prepare);
  hold(prepare, 'authorization-request-' + n, 'sshCli', 'authorization request', { retention: 'temporary' });
  transfer(second ? 'reissue-browser' : 'open-browser', 'authorization-request-' + n, 'sshCli', 'browser', 'browser navigation', stage('authorize'));
  transfer(stage('authorize'), 'authorization-request-' + n, 'browser', 'sshIdp', 'authorization transaction', second ? 'reissue-token-issue' : a.model.id === 'lab-ssh-cert-callback' ? 'callback-check' : 'pkce-check');
  const compute = second ? 'reissue-totp-compute' : 'totp-compute';
  const display = second ? 'reissue-totp-display' : 'totp-display';
  const input = second ? 'reissue-factors' : 'factor-input';
  const submit = second ? 'reissue-submit' : 'factor-submit';
  const check = second ? 'reissue-factor-check' : 'factor-check';
  define('totp-code-' + n, 'otp-input', 'TOTP one-time input-' + n, 'totp', fields(compute, ['totp']), compute, { expiresAt: EPOCH + (second ? 150 : 30), derivedFrom: ['totp-seed'], readableBy: ['totp', 'user', 'browser', 'sshIdp'] });
  hold(compute, 'totp-code-' + n, 'totp', 'code display', { retention: 'temporary' });
  transfer(display, 'totp-code-' + n, 'totp', 'user', 'factor input', input);
  release(display, 'totp-code-' + n, 'totp', 'code display');
  transfer(input, 'totp-code-' + n, 'user', 'browser', 'factor form', submit);
  transfer(input, 'password', 'user', 'browser', 'factor form', submit);
  transfer(submit, 'totp-code-' + n, 'browser', 'sshIdp', 'factor verification input', check);
  transfer(submit, 'password', 'browser', 'sshIdp', 'factor verification input', check);
  observe(check, 'totp-code-' + n, 'sshIdp', 'verification', 'accepted_enrolled_time_code');
  observe(check, 'password', 'sshIdp', 'verification', 'accepted_password_factor');
  if (!second) {
    define('idp-session', 'session', 'Authenticated IdP SSO session', 'sshIdp', [a.literal('SSO session', 'Authenticated reference session')], check, { expiresAt: EPOCH + 28800, readableBy: ['sshIdp'] });
    hold(check, 'idp-session', 'sshIdp', 'SSO session store');
    bind('sessions.idp.authenticated', 'sshIdp', 'idp-session', 'SSO session store');
  }
  const code = 'authorization-code-' + n;
  define(code, 'authorization-code', 'OIDC authorization code-' + n, 'sshIdp', fields(check, ['code']), check, { derivedFrom: ['authorization-request-' + n] });
  hold(check, code, 'sshIdp', 'authorization code ledger');
  transfer(stage('redirect'), code, 'sshIdp', 'browser', 'redirect response', stage('callback'));
  const callbackCheck = stage('callback-check');
  transfer(stage('callback'), code, 'browser', 'sshCli', 'callback input', a.model.id === 'lab-ssh-cert-callback' ? callbackCheck : second ? 'reissue-token-issue' : 'pkce-check');
  define('callback-' + n, 'callback', 'Received callback state-' + n, 'browser', fields(stage('callback'), ['state', 'redirect']), stage('callback'));
  hold(stage('callback'), 'callback-' + n, 'sshCli', 'callback comparison', { retention: 'temporary' });
  release(callbackCheck, 'callback-' + n, 'sshCli', 'callback comparison');
  observe(callbackCheck, 'callback-' + n, 'sshCli', 'verification', a.model.id === 'lab-ssh-cert-callback' ? 'rejected_state_mismatch' : 'accepted_state_correlation');
  const terminal = a.model.id === 'lab-ssh-cert-callback' ? callbackCheck : a.model.id === 'lab-ssh-cert-pkce' ? 'pkce-check' : second ? 'reissue-token' : 'validate-identity';
  release(terminal, transaction, 'sshCli', 'pending enrollment');
  release(terminal, 'authorization-request-' + n, 'sshCli', 'authorization request');
  if (!stages.has(stage('redeem'))) return;
  transfer(stage('redeem'), code, 'sshCli', 'sshIdp', 'code redemption', second ? 'reissue-token-issue' : 'pkce-check');
  define('redemption-' + n, 'token-request', 'Exact code redemption verifier-' + n, 'sshCli', fields(stage('redeem'), ['verifier', 'client', 'redirect']), stage('redeem'), { readableBy: ['sshCli', 'sshIdp'], related: [transaction, code] });
  hold(stage('redeem'), 'redemption-' + n, 'sshIdp', 'token request', { retention: 'temporary' });
  const pkceCheck = second ? 'reissue-token-issue' : 'pkce-check';
  release(pkceCheck, 'redemption-' + n, 'sshIdp', 'token request');
  observe(pkceCheck, 'redemption-' + n, 'sshIdp', 'verification', a.model.id === 'lab-ssh-cert-pkce' ? 'rejected_pkce_mismatch' : 'accepted_code_binding');
  authority(pkceCheck, code, 'sshIdp', a.model.id === 'lab-ssh-cert-pkce' ? 'redemption_rejected' : 'consumed');
  if (!stages.has(stage('token-issue'))) return;
  const token = 'id-token-' + n;
  define(token, 'id-token', 'OIDC identity token-' + n, 'sshIdp', fields(stage('token-issue'), ['token', 'iss', 'aud', 'sub', 'iat', 'exp', 'signedNonce', 'amr']), stage('token-issue'), { format: 'compact JWS reference and signed claims', expiresAt: EPOCH + (second ? 420 : 300), derivedFrom: [code], readableBy: ['sshIdp', 'sshCli', 'sshCa'] });
  hold(stage('token-issue'), token, 'sshIdp', 'token response buffer', { retention: 'temporary' });
  transfer(second ? 'reissue-token' : 'tokens', token, 'sshIdp', 'sshCli', 'enrollment tokens', null, { releaseSender: 'token response buffer' });
  observe(second ? 'reissue-token' : 'validate-identity', token, 'sshCli', 'verification', 'accepted_issuer_signature_audience_expiry_nonce');
  if (!second) {
    define('access-token-1', 'access-token', 'OAuth access token-1', 'sshIdp', fields('token-issue', ['access', 'tokenType', 'expires']), 'token-issue', { expiresAt: EPOCH + 300, derivedFrom: [code], readableBy: ['sshIdp', 'sshCli'] });
    hold('token-issue', 'access-token-1', 'sshIdp', 'token response buffer', { retention: 'temporary' });
    transfer('tokens', 'access-token-1', 'sshIdp', 'sshCli', 'OAuth token store', null, { releaseSender: 'token response buffer' });
  }
}

function issueAndUseCertificate(a, isDevice, variant) {
  const { define, fields, hold, transfer, release, observe, authority, bind, stages } = a;
  const token = isDevice && variant === 'restart' ? 'id-token-2' : 'id-token-1';
  const signedFields = isDevice ? CERT_FIELDS : ['cert', 'certNonce', 'serial', 'type', 'principal', 'validAfter', 'validBefore', 'critical', 'extensions', 'caPublic', 'caSignature'];
  define('certificate-1', 'ssh-certificate', 'SSH user certificate-1', 'sshCa', [...fields('issue', signedFields), ...fields('issue', ['publicKey'])], 'issue', { format: 'base64 SSH certificate wire bytes and signed fields', expiresAt: EPOCH + 3600, derivedFrom: ['user-public-key-1', token], related: ['ca-public-key'] });
  hold('issue', 'certificate-1', 'sshCa', 'certificate response', { retention: 'temporary' });
  authority('issue', token, 'sshCa', 'consumed_for_enrollment');
  transfer('certificate', 'certificate-1', 'sshCa', 'sshCli', 'certificate files', null, { releaseSender: 'certificate response' });
  transfer('install', 'certificate-1', 'sshCli', 'sshAgent', 'agent certificate store', null);
  if (variant === 'copy') {
    release('copy-alone', 'user-private-key-1', 'sshAgent', 'agent key store');
    release('copy-alone', 'user-public-key-1', 'sshAgent', 'agent key store');
    define('user-private-key-2', 'private-key', 'Unrelated recipient private key-2', 'sshAgent', fields('copy-alone', ['privateKey'], 'key-2'), 'copy-alone', { readableBy: ['sshAgent'] });
    hold('copy-alone', 'user-private-key-2', 'sshAgent', 'agent key store');
    bind('credentials.userKey.instanceId', 'sshAgent', 'user-private-key-2', 'agent key store', a.model.id + ':key-2');
  }
  transport(a, isDevice ? 'device' : 'certificate');
  if (!stages.has('userauth-input')) return;
  define('userauth-input', 'authentication-input', 'Session-bound SSH signing input', 'sshCli', fields('userauth-input', ['signingInput', 'account', 'service', 'method', 'algorithm']), 'userauth-input', { readableBy: ['sshCli', 'sshAgent', 'sshHost'], related: ['session-id', 'certificate-1'] });
  hold('userauth-input', 'userauth-input', 'sshCli', 'authentication buffer', { retention: 'temporary' });
  release('userauth', 'userauth-input', 'sshCli', 'authentication buffer');
  transfer('agent-request', 'userauth-input', 'sshCli', 'sshAgent', 'agent signing input', 'sign');
  transfer('agent-request', 'session-id', 'sshCli', 'sshAgent', 'agent signing input', 'sign');
  define('user-proof', 'signature', 'SSH private-key possession proof', 'sshAgent', fields('sign', ['userSignature']), 'sign', { derivedFrom: [variant === 'copy' ? 'user-private-key-2' : 'user-private-key-1', 'userauth-input'] });
  hold('sign', 'user-proof', 'sshAgent', 'agent signature output', { retention: 'temporary' });
  transfer('agent-proof', 'user-proof', 'sshAgent', 'sshCli', 'authentication proof', 'userauth', { releaseSender: 'agent signature output' });
  transfer('userauth', 'user-proof', 'sshCli', 'sshHost', 'authentication proof', 'host-policy');
  transfer('userauth', 'certificate-1', 'sshCli', 'sshHost', 'presented certificate', null);
  const failures = { userca: 'rejected_untrusted_user_ca', copy: 'rejected_wrong_private_key', session: 'rejected_wrong_transport_signature', account: 'rejected_account_access', root: 'rejected_principal_account_mismatch' };
  observe('host-policy', 'certificate-1', 'sshHost', 'verification', variant === 'userca' ? failures.userca : 'accepted_certificate_signature_and_window');
  observe('host-policy', 'user-proof', 'sshHost', 'verification', ['copy', 'session'].includes(variant) ? failures[variant] : 'accepted_transport_bound_signature');
  observe('host-policy', 'certificate-1', 'sshHost', 'acceptance', failures[variant] || 'accepted_existing_account_policy');
  if (stages.has('failure')) {
    messageResult(a, 'failure', ['failure']);
    return;
  }
  establish(a, 'host-policy', 'ssh-success');
  messageResult(a, 'ssh-success', ['success']);
  channel(a, 'channel', 'channel-1');
}

function establish(a, acceptedAt, receivedAt) {
  a.define('ssh-connection', 'connection', 'Authenticated SSH connection', 'sshHost', [a.literal('authenticated SSH connection', 'Established transport-bound SSH authentication; subsequent channels do not repeat user authentication')], acceptedAt, { related: ['ssh-transport'] });
  a.hold(acceptedAt, 'ssh-connection', 'sshHost', 'SSH connection');
  // The family flag records the host's decision, not the client's knowledge.
  a.bind('sessions.ssh.authenticated', 'sshHost', 'ssh-connection', 'SSH connection');
  a.hold(receivedAt, 'ssh-connection', 'sshCli', 'SSH connection');
  a.observe(receivedAt, 'ssh-connection', 'sshCli', 'acceptance', 'accepted_success_receipt');
}

function messageResult(a, stage, keys) {
  if (!a.stages.has(stage)) return;
  a.message(stage, 'result-' + stage, 'protocol-result', 'SSH authentication result', 'sshHost', 'sshCli', keys, stage);
}

function channel(a, stage, id) {
  a.define(id, 'channel', 'SSH session ' + id, 'sshCli', a.fields(stage, ['channel']), stage, { related: ['ssh-connection'] });
  a.hold(stage, id, 'sshCli', 'SSH channels');
  a.transfer(stage, id, 'sshCli', 'sshHost', 'SSH channels', null);
}

function device(a, variant) {
  const { define, fields, literal, hold, transfer, message, observe, authority, release, plan, stages } = a;
  certificateSetup(a, true);
  a.bind('credentials.userKey.instanceId', 'sshCli', 'user-private-key-1', 'local key file', a.model.id + ':key-1');
  plan.limitations.push('Device browser approval abstracts the configured IdP factor ceremony; it does not declare password, OTP or passkey enrollment. This is the RFC Device/OIDC reference, not a literal product retry trace.');
  plan.limitations.push('Local Device cancellation releases CLI polling and approval display copies only. The issuer retains the pending transaction and its response-defined expiry unless a separately authored issuer transition clears it; no remote cancellation or cleanup is implied.');
  const firstTerminal = ['cancel', 'restart'].includes(variant) ? 'cancel' : ['denied', 'expired', 'clienterror'].includes(variant) ? 'stop' : 'tokens';
  const deviceSet = (second) => {
    const n = second ? 2 : 1, start = second ? 'restart-created' : 'device-created';
    const locallyCancelled = !second && ['cancel', 'restart'].includes(variant);
    const issuerTerminal = locallyCancelled ? null : second ? 'tokens' : firstTerminal;
    const issuerRetention = issuerTerminal ? 'temporary' : 'retained';
    define('device-code-' + n, 'device-code', 'Private Device polling handle-' + n, 'sshIdp', fields(start, ['deviceCode']), start, { expiresAt: EPOCH + (second ? 605 : 600), readableBy: ['sshIdp', 'sshCli'] });
    hold(start, 'device-code-' + n, 'sshIdp', 'pending Device transaction', { retention: issuerRetention });
    if (issuerTerminal) release(issuerTerminal, 'device-code-' + n, 'sshIdp', 'pending Device transaction');
    transfer(second ? 'restart-response' : 'response', 'device-code-' + n, 'sshIdp', 'sshCli', 'private polling state', second ? 'tokens' : firstTerminal);
    define('device-instructions-' + n, 'approval-instructions', 'Human Device approval code and URI-' + n, 'sshIdp', fields(start, second ? ['userCode', 'verifyUri', 'deviceExpiry'] : ['userCode', 'verifyUri', 'verifyComplete', 'deviceExpiry']), start, { expiresAt: EPOCH + (second ? 605 : 600) });
    hold(start, 'device-instructions-' + n, 'sshIdp', 'pending Device transaction', { retention: issuerRetention });
    if (issuerTerminal) release(issuerTerminal, 'device-instructions-' + n, 'sshIdp', 'pending Device transaction');
    transfer(second ? 'restart-response' : 'response', 'device-instructions-' + n, 'sshIdp', 'sshCli', 'approval display', second ? 'tokens' : firstTerminal);
    transfer(second ? 'restart-display' : 'display', 'device-instructions-' + n, 'sshCli', 'user', 'approval display', second ? 'human-open' : variant === 'restart' || variant === 'cancel' ? 'cancel' : ['denied', 'expired', 'clienterror'].includes(variant) ? 'stop' : 'human-open');
  };
  deviceSet(false);
  if (variant === 'restart') deviceSet(true);
  const polls = ['poll-1', 'poll-2', 'poll-3', 'poll-4', 'terminal-poll', 'final-poll'].filter(stage => stages.has(stage));
  for (const poll of polls) {
    const n = variant === 'restart' && poll === 'final-poll' ? 2 : 1;
    const end = { 'poll-1': 'pending', 'poll-2': 'slow-1', 'poll-3': 'slow-2', 'poll-4': 'timeout', 'terminal-poll': 'terminal', 'final-poll': 'token-issue' }[poll];
    transfer(poll, 'device-code-' + n, 'sshCli', 'sshIdp', 'poll request', end);
  }
  for (const [stage, end] of [['pending', firstTerminal], ['slow-1', 'apply-slow-1'], ['slow-2', 'apply-slow-2'], ['terminal', 'stop']]) {
    if (stages.has(stage)) message(stage, 'response-' + stage, 'protocol-result', 'Device endpoint result', 'sshIdp', 'sshCli', ['error'], end);
  }
  if (variant === 'cancel' || variant === 'restart') {
    authority('cancel', 'device-code-1', 'sshCli', 'cancelled_locally');
    // The source explicitly delivers bytes after cancellation, with no earlier
    // token issuance event. Receipt is real; acceptance/installation is not.
    message('late-response', 'late-id-token', 'id-token', 'Late cancelled-transaction identity token', 'sshIdp', 'sshCli', ['token'], 'ignore-late', { expiresAt: EPOCH + 300 });
    message('late-response', 'late-access-token', 'access-token', 'Late cancelled-transaction access token', 'sshIdp', 'sshCli', ['access', 'tokenType', 'expires'], 'ignore-late', { expiresAt: EPOCH + 300 });
    observe('ignore-late', 'late-id-token', 'sshCli', 'acceptance', 'rejected_cancelled_transaction');
    if (variant === 'cancel') return;
  }
  if (['denied', 'expired', 'clienterror'].includes(variant)) {
    authority('terminal', 'device-code-1', 'sshIdp', variant === 'expired' ? 'expired' : variant === 'denied' ? 'approval_denied' : 'unauthorized_client');
    return;
  }
  const n = variant === 'restart' ? 2 : 1;
  transfer('human-open', 'device-instructions-' + n, 'user', 'browser', 'approval form', 'human-approve');
  transfer('human-approve', 'device-instructions-' + n, 'browser', 'sshIdp', 'approval input', 'approval');
  observe('approval', 'device-code-' + n, 'sshIdp', 'acceptance', 'browser_approval_recorded_not_token_delivery');
  const issuedAt = EPOCH + (variant === 'restart' ? 10 : 65);
  define('id-token-' + n, 'id-token', 'Device OIDC identity token-' + n, 'sshIdp', fields('token-issue', ['token', 'iss', 'aud', 'sub', 'exp', 'iat']), 'token-issue', { expiresAt: issuedAt + 300, derivedFrom: ['device-code-' + n], readableBy: ['sshIdp', 'sshCli', 'sshCa'] });
  define('access-token-' + n, 'access-token', 'Device OAuth access token-' + n, 'sshIdp', fields('token-issue', ['access', 'tokenType', 'expires']), 'token-issue', { expiresAt: issuedAt + 300, derivedFrom: ['device-code-' + n], readableBy: ['sshIdp', 'sshCli'] });
  for (const id of ['id-token-' + n, 'access-token-' + n]) {
    hold('token-issue', id, 'sshIdp', 'token response buffer', { retention: 'temporary' });
    transfer('tokens', id, 'sshIdp', 'sshCli', 'enrollment tokens', null, { releaseSender: 'token response buffer' });
  }
  a.bind('credentials.idToken.instanceId', 'sshCli', 'id-token-' + n, 'enrollment tokens', a.model.id + ':id-token-' + n);
  observe('validate', 'id-token-' + n, 'sshCli', 'verification', 'accepted_configured_oidc_device_profile');
  transfer('enroll', 'id-token-' + n, 'sshCli', 'sshCa', 'enrollment authorization', null);
  transfer('enroll', 'user-public-key-1', 'sshCli', 'sshCa', 'enrollment request', 'issue');
  observe('ca-policy', 'id-token-' + n, 'sshCa', 'verification', 'accepted_provisioner_and_principal');
  issueAndUseCertificate(a, true, variant);
}

function sssd(a, variant) {
  const { define, fields, literal, hold, transfer, message, release, observe, authority, bind, stages, plan } = a;
  transportSetup(a);
  transport(a, 'sssd');
  plan.limitations.push('SSSD prompt, provider token evaluation and identity matching are explicit reference fixtures, not verified release behavior. Browser factor enrollment is abstract. Interactive tokens are released after provider evaluation (tokenCache:false); independent directory tokens remain remote-held. No workstation OAuth token, OS account/home creation, Kerberos TGT or passkey is implied.');
  define('provider-account', 'identity-record', 'Configured provider directory account', 'sshIdp', [literal('configured identity', { issuer: a.value('example-context', 'configuredIssuer').value, domain: a.model.initialState.requestedIdentity.domain, providerId: 'person-204', name: a.model.initialState.requestedIdentity.name })], null, { readableBy: ['sshIdp'] });
  hold(null, 'provider-account', 'sshIdp', 'provider directory');
  define('remote-client-registration', 'client-registration', 'Remote SSSD Device client registration', 'sshIdp', [literal('client_id', 'sssd-remote-device')], null);
  hold(null, 'remote-client-registration', 'sssd', 'protected client configuration');
  hold(null, 'remote-client-registration', 'sshIdp', 'client registration');
  define('lookup-client-registration', 'client-registration', 'Directory lookup client registration', 'sshIdp', [literal('client_id', 'sssd-directory-reader')], null);
  hold(null, 'lookup-client-registration', 'sssd', 'protected lookup configuration');
  hold(null, 'lookup-client-registration', 'sshIdp', 'client registration');
  define('remote-client-auth', 'client-credential', 'Remote SSSD Device client authentication', 'sssd', [literal('protected client authentication', 'Configured remote-host client authentication; never workstation-held')], null, { readableBy: ['sssd', 'sshIdp'] });
  hold(null, 'remote-client-auth', 'sssd', 'protected client configuration');
  define('remote-client-verifier', 'client-verifier', 'IdP remote-client verification material', 'sshIdp', [literal('client verification material', 'Configured verification material for remote SSSD client; not an assumed plaintext copy')], null, { readableBy: ['sshIdp'] });
  hold(null, 'remote-client-verifier', 'sshIdp', 'client registration');
  define('lookup-secret', 'client-credential', 'SSSD directory lookup client secret', 'sssd', [literal('lookup secret', '<remote lookup-client secret>')], null, { readableBy: ['sssd', 'sshIdp'] });
  hold(null, 'lookup-secret', 'sssd', 'protected lookup configuration');
  define('lookup-verifier', 'client-verifier', 'IdP lookup-client verification material', 'sshIdp', [literal('lookup verification material', 'Configured lookup-client verification material; not server plaintext')], null, { readableBy: ['sshIdp'] });
  hold(null, 'lookup-verifier', 'sshIdp', 'client registration');
  define('requested-login', 'login-request', 'Requested SSH Unix identity', 'sshCli', fields('keyboard-request', ['name', 'service', 'method', 'language', 'submethods']), 'keyboard-request');
  hold('keyboard-request', 'requested-login', 'sshCli', 'SSH login request');
  transfer('keyboard-request', 'requested-login', 'sshCli', 'sshHost', 'SSH login request', null);
  message('pam-request', 'pam-request', 'local-request', 'PAM login request', 'sshHost', 'pam', ['pamRequest'], stages.has('lookup-failed') ? 'lookup-pam-failure' : 'sssd-pam-result');
  transfer('pam-request', 'requested-login', 'sshHost', 'pam', 'requested identity relay', 'sssd-request');
  transfer('sssd-request', 'requested-login', 'pam', 'sssd', 'identity request', null);
  define('configured-domain', 'identity-policy', 'Configured SSSD identity domain', 'sssd', fields('sssd-request', ['domain']), null, { readableBy: ['sssd', 'pam', 'sshHost'] });
  hold(null, 'configured-domain', 'sssd', 'identity configuration');
  if (variant === 'cached') {
    define('provider-identity', 'identity-record', 'Cached provider-backed NSS identity', 'sssd', [literal('cached identity', a.model.initialState.identityCache)], null, { readableBy: ['sssd', 'pam', 'sshHost'] });
    hold(null, 'provider-identity', 'sssd', 'NSS identity cache');
    bind('identityCache', 'sssd', 'provider-identity', 'NSS identity cache');
    observe('cached-lookup', 'provider-identity', 'sssd', 'knowledge', 'cached_identity_resolves_requested_account');
  } else {
    transfer('lookup-token-request', 'lookup-secret', 'sssd', 'sshIdp', 'lookup client authentication', 'lookup-token-issue');
    observe('lookup-token-issue', 'lookup-secret', 'sshIdp', 'verification', 'accepted_lookup_client');
    define('directory-token', 'access-token', 'Directory service access token', 'sshIdp', fields('lookup-token-issue', ['lookupToken', 'lookupType']), 'lookup-token-issue', { readableBy: ['sshIdp', 'sssd'] });
    hold('lookup-token-issue', 'directory-token', 'sshIdp', 'service token response', { retention: 'temporary' });
    transfer('lookup-token', 'directory-token', 'sshIdp', 'sssd', 'directory service token store', null, { releaseSender: 'service token response' });
    bind('credentials.directoryToken', 'sssd', 'directory-token', 'directory service token store');
    transfer('lookup-query', 'directory-token', 'sssd', 'sshIdp', 'directory API request', stages.has('lookup-failed') ? 'lookup-failed' : 'lookup-result');
    if (stages.has('lookup-failed')) {
      observe('lookup-failed', 'directory-token', 'sssd', 'acceptance', variant === 'permission' ? 'rejected_directory_api_permission' : 'directory_unavailable_not_token_invalidation', 'Provider identity API endpoint result; retained service token is not globally invalidated.');
      message('lookup-pam-failure', 'lookup-pam-result', 'protocol-result', 'Directory lookup PAM failure', 'sssd', 'pam', ['pamResult'], 'lookup-sshd-failure');
      transfer('lookup-sshd-failure', 'lookup-pam-result', 'pam', 'sshHost', 'PAM result', 'lookup-ssh-failure');
      messageResult(a, 'lookup-ssh-failure', ['failure']);
      return;
    }
    define('provider-identity', 'identity-record', 'Resolved provider identity', 'sshIdp', fields('lookup-result', ['providerIdentity']), 'lookup-result', { readableBy: ['sshIdp', 'sssd', 'pam', 'sshHost'] });
    hold('lookup-result', 'provider-identity', 'sshIdp', 'directory response', { retention: 'temporary' });
    release('lookup-result', 'provider-identity', 'sshIdp', 'directory response');
    transfer('lookup-result', 'provider-identity', 'sshIdp', 'sssd', 'NSS identity cache', null);
  }
  define('unix-identity', 'identity-record', 'Configured Unix NSS identity mapping', 'sssd', fields(variant === 'cached' ? 'cached-lookup' : 'nss-map', ['nss']), variant === 'cached' ? null : 'nss-map', { readableBy: ['sssd', 'pam', 'sshHost'], related: ['provider-identity'] });
  hold(variant === 'cached' ? null : 'nss-map', 'unix-identity', 'sssd', 'NSS identity cache');
  define('resolved-identity', 'identity-record', 'Resolved requested identity', 'sssd', fields(variant === 'cached' ? 'cached-lookup' : 'lookup-result', ['providerIdentity']), variant === 'cached' ? 'cached-lookup' : 'nss-map', { readableBy: ['sssd', 'pam', 'sshHost'], related: ['provider-identity'] });
  hold(variant === 'cached' ? 'cached-lookup' : 'nss-map', 'resolved-identity', 'sssd', 'resolved identity');
  bind('resolvedIdentity', 'sssd', 'resolved-identity', 'resolved identity');
  transfer('device-request', 'remote-client-auth', 'sssd', 'sshIdp', 'remote client authentication', 'device-created');
  observe('device-created', 'remote-client-auth', 'sshIdp', 'verification', 'accepted_remote_client');
  define('remote-device-code', 'device-code', 'Private remote SSSD Device handle', 'sshIdp', fields('device-created', ['device', 'expiry', 'interval']), 'device-created', { expiresAt: EPOCH + 600, readableBy: ['sssd', 'sshIdp'] });
  hold('device-created', 'remote-device-code', 'sshIdp', 'pending Device transaction', { retention: 'temporary' });
  release('token-result', 'remote-device-code', 'sshIdp', 'pending Device transaction');
  transfer('device-response', 'remote-device-code', 'sshIdp', 'sssd', 'private polling state', 'token-result');
  define('human-instructions', 'approval-instructions', 'SSSD human-only approval instructions', 'sshIdp', fields('device-created', ['uri', 'complete', 'userCode']), 'device-created');
  hold('device-created', 'human-instructions', 'sshIdp', 'pending Device transaction', { retention: 'temporary' });
  release('token-result', 'human-instructions', 'sshIdp', 'pending Device transaction');
  transfer('device-response', 'human-instructions', 'sshIdp', 'sssd', 'human instruction source', 'sssd-info');
  define('sssd-info', 'local-message', 'SSS_PAM_OAUTH2_INFO human-only object', 'sssd', fields('human-info-created', ['info']), 'human-info-created', { derivedFrom: ['human-instructions'] });
  hold('human-info-created', 'sssd-info', 'sssd', 'human IPC output', { retention: 'temporary' });
  transfer('sssd-info', 'sssd-info', 'sssd', 'pam', 'PAM instruction buffer', 'pam-info', { releaseSender: 'human IPC output' });
  transfer('pam-info', 'sssd-info', 'pam', 'sshHost', 'sshd instruction buffer', 'ssh-info');
  message('ssh-info', 'keyboard-prompt', 'protocol-message', 'Keyboard-interactive human prompt', 'sshHost', 'sshCli', ['prompt', 'count'], 'conversation-response', { derivedFrom: ['sssd-info'] });
  // Relay a separate exact human view. Never relay the private Device response.
  define('terminal-instructions', 'approval-instructions', 'Terminal approval URI and user code', 'sshHost', fields('ssh-info', ['uri', 'complete', 'userCode']), 'ssh-info', { derivedFrom: ['human-instructions'] });
  const terminalOutput = 'sshHost|terminal-instructions|ssh-info-output';
  hold('ssh-info', 'terminal-instructions', 'sshHost', 'message output', { holdingId: terminalOutput, retention: 'temporary' });
  a.at('ssh-info', { op: 'release', holdingId: terminalOutput });
  transfer('ssh-info', 'terminal-instructions', 'sshHost', 'sshCli', 'terminal instruction buffer', 'terminal-display');
  transfer('terminal-display', 'terminal-instructions', 'sshCli', 'user', 'approval display', 'browser-open');
  transfer('browser-open', 'terminal-instructions', 'user', 'browser', 'approval form', 'browser-approve');
  transfer('browser-approve', 'terminal-instructions', 'browser', 'sshIdp', 'approval input', 'approved-identity');
  define('approved-provider-identity', 'identity-record', 'Browser-approved provider identity', 'sshIdp', fields('approved-identity', ['approval']), 'approved-identity', { readableBy: ['sshIdp', 'sssd'] });
  hold('approved-identity', 'approved-provider-identity', 'sshIdp', 'approval record');
  bind('transaction.approvedIdentity', 'sshIdp', 'approved-provider-identity', 'approval record');
  message('conversation-response', 'conversation-answer', 'protocol-message', 'Keyboard-interactive response', 'sshCli', 'sshHost', ['response'], 'pam-response');
  transfer('pam-response', 'conversation-answer', 'sshHost', 'pam', 'conversation response', 'sssd-response');
  transfer('sssd-response', 'conversation-answer', 'pam', 'sssd', 'conversation response', 'poll');
  transfer('poll', 'remote-client-auth', 'sssd', 'sshIdp', 'poll authentication', 'user-token-issue');
  transfer('poll', 'remote-device-code', 'sssd', 'sshIdp', 'poll request', 'user-token-issue');
  define('interactive-token', 'access-token', 'Interactive user access token', 'sshIdp', fields('user-token-issue', ['userToken', 'type', 'lifetime']), 'user-token-issue', { expiresAt: EPOCH + 305, readableBy: ['sshIdp', 'sssd'], derivedFrom: ['remote-device-code'] });
  hold('user-token-issue', 'interactive-token', 'sshIdp', 'interactive token response', { retention: 'temporary' });
  transfer('token-result', 'interactive-token', 'sshIdp', 'sssd', 'provider evaluation buffer', 'provider-evaluation', { releaseSender: 'interactive token response' });
  observe('provider-evaluation', 'interactive-token', 'sssd', 'verification', 'evaluated_under_reference_provider_profile');
  hold('provider-evaluation', 'approved-provider-identity', 'sssd', 'evaluated provider identity');
  bind('approvedIdentity', 'sssd', 'approved-provider-identity', 'evaluated provider identity');
  observe('identity-match', 'approved-provider-identity', 'sssd', 'acceptance', ['bob', 'domain'].includes(variant) ? 'rejected_requested_identity_mismatch' : 'matched_requested_identity');
  message('sssd-pam-result', 'pam-auth-result', 'protocol-result', 'PAM authentication result', 'sssd', 'pam', ['pamResult'], 'pam-sshd-result');
  transfer('pam-sshd-result', 'pam-auth-result', 'pam', 'sshHost', 'PAM authentication result', stages.has('ssh-failure') ? 'ssh-failure' : 'account-policy');
  if (stages.has('ssh-failure')) { messageResult(a, 'ssh-failure', ['failure']); return; }
  message('account-result', 'pam-account-result', 'protocol-result', 'PAM account authorization result', 'pam', 'sshHost', ['account'], stages.has('account-failure') ? 'account-failure' : 'ssh-success');
  hold('account-policy', 'unix-identity', 'pam', 'account policy input', { retention: 'temporary' });
  release('account-result', 'unix-identity', 'pam', 'account policy input');
  observe('account-policy', 'unix-identity', 'pam', 'acceptance', variant === 'account' ? 'rejected_account_access' : 'accepted_existing_account');
  if (stages.has('account-failure')) { messageResult(a, 'account-failure', ['failure']); return; }
  establish(a, 'ssh-success', 'ssh-success');
  messageResult(a, 'ssh-success', ['success']);
  channel(a, 'channel', 'channel-1');
}

function gss(a, variant) {
  const { define, fields, literal, hold, transfer, message, release, observe, bind, plan } = a;
  transportSetup(a);
  transport(a, 'gss');
  define('kdc-key', 'private-key', 'KDC ticket-protection key', 'kdc', [literal('KDC key', 'Configured KDC protected key handle')], null, { readableBy: ['kdc'] });
  hold(null, 'kdc-key', 'kdc', 'KDC key store');
  define('host-service-key', 'private-key', 'Kerberos host service key', 'sshHost', [literal('service key', 'Configured host service-key handle')], null, { readableBy: ['sshHost', 'kdc'] });
  hold(null, 'host-service-key', 'sshHost', 'Kerberos keytab');
  hold(null, 'host-service-key', 'kdc', 'service key database');
  define('home-tgt', 'kerberos-tgt', 'Cached home TGT', 'kdc', fields('tgs', ['tgt']), null);
  hold(null, 'home-tgt', 'sshCli', 'Kerberos credential cache');
  bind('credentials.homeTgt', 'sshCli', 'home-tgt', 'Kerberos credential cache');
  define('home-session-key', 'session-key', 'Cached TGT session key', 'kdc', [literal('session key', 'Protected cached TGT session-key handle; not sent as a password')], null, { readableBy: ['sshCli', 'kdc'], related: ['home-tgt'] });
  hold(null, 'home-session-key', 'sshCli', 'Kerberos credential cache');
  transfer('tgs', 'home-tgt', 'sshCli', 'kdc', 'TGS request', 'service-ticket');
  message('service-ticket', 'host-ticket', 'kerberos-ticket', 'Kerberos host service ticket', 'kdc', 'sshCli', ['ticket'], null, { derivedFrom: ['home-tgt'], store: 'Kerberos credential cache' });
  bind('credentials.hostTicket', 'sshCli', 'host-ticket', 'Kerberos credential cache');
  define('host-ticket-session-key', 'session-key', 'Host credential session key', 'kdc', [literal('service session key', 'Protected initiator session-key handle from the abstract service credential response')], 'service-ticket', { readableBy: ['sshCli', 'sshHost'], related: ['host-ticket'] });
  hold('service-ticket', 'host-ticket-session-key', 'sshCli', 'Kerberos credential cache');
  message('gss-offer', 'gss-offer', 'authentication-request', 'GSS SSH userauth offer', 'sshCli', 'sshHost', ['account', 'service', 'method', 'mechanism'], 'mic-check');
  message('gss-select', 'gss-selection', 'protocol-message', 'Selected Kerberos mechanism', 'sshHost', 'sshCli', ['mechanism'], 'gss-init');
  define('gss-init-token', 'gss-token', 'Kerberos GSS initiator AP-REQ token', 'sshCli', fields('gss-init', ['token']), 'gss-init', { format: 'opaque Kerberos GSS token', derivedFrom: ['host-ticket', 'host-ticket-session-key'] });
  hold('gss-init', 'gss-init-token', 'sshCli', 'GSS output', { retention: 'temporary' });
  transfer('gss-token', 'gss-init-token', 'sshCli', 'sshHost', 'GSS acceptance input', 'gss-accept', { releaseSender: 'GSS output' });
  observe('gss-accept', 'gss-init-token', 'sshHost', 'verification', 'accepted_kerberos_service_context');
  hold('gss-accept', 'host-ticket-session-key', 'sshHost', 'GSS context');
  define('gss-reply', 'gss-token', 'Kerberos GSS acceptor AP-REP token', 'sshHost', fields('gss-accept', ['reply']), 'gss-accept', { format: 'opaque Kerberos GSS token', derivedFrom: ['gss-init-token'] });
  hold('gss-accept', 'gss-reply', 'sshHost', 'GSS output', { retention: 'temporary' });
  transfer('gss-response', 'gss-reply', 'sshHost', 'sshCli', 'GSS completion input', 'context-complete', { releaseSender: 'GSS output' });
  observe('context-complete', 'gss-reply', 'sshCli', 'verification', 'accepted_mutual_context');
  define('gss-context', 'security-context', 'Established Kerberos GSS context', 'sshCli', [literal('GSS context', 'Mutual Kerberos context, without delegation')], 'context-complete', { related: ['host-ticket'] });
  for (const actor of ['sshCli', 'sshHost']) {
    hold('context-complete', 'gss-context', actor, 'GSS context');
    bind('sessions.gss.established', actor, 'gss-context', 'GSS context');
  }
  define('gss-mic-input', 'authentication-input', 'Session-bound GSS MIC input', 'sshCli', fields('mic-create', ['micInput']), 'mic-create', { related: ['session-id', 'gss-context'], readableBy: ['sshCli', 'sshHost'] });
  hold('mic-create', 'gss-mic-input', 'sshCli', 'GSS signing input', { retention: 'temporary' });
  release('mic', 'gss-mic-input', 'sshCli', 'GSS signing input');
  define('gss-mic', 'integrity-proof', 'SSH GSS request MIC', 'sshCli', fields('mic-create', ['mic']), 'mic-create', { derivedFrom: ['gss-context', 'gss-mic-input'] });
  hold('mic-create', 'gss-mic', 'sshCli', 'GSS output', { retention: 'temporary' });
  transfer('mic', 'gss-mic', 'sshCli', 'sshHost', 'MIC verification input', 'mic-check', { releaseSender: 'GSS output' });
  observe('mic-check', 'gss-mic', 'sshHost', 'verification', 'accepted_transport_bound_mic');
  observe('mic-check', 'gss-context', 'sshHost', 'acceptance', variant === 'account' ? 'rejected_account_access' : 'accepted_account_mapping');
  if (variant === 'success') establish(a, 'mic-check', 'result');
  messageResult(a, 'result', ['result']);
  if (variant === 'success') channel(a, 'channel', 'channel-1');
  plan.limitations.push('Kerberos ticket/session-key handles describe the authored abstract GSS mechanism, not encoded ASN.1 or live cryptography. Credential delegation, SPNEGO and GSS key exchange are excluded by this fixture.');
}

export function buildSSHHeldObjects(args) {
  if (!args.model || args.model.family !== 'ssh-access') return null;
  const match = /^lab-ssh-(cert|device|sssd|gss)-(.+)$/.exec(args.model.id);
  const choices = { cert: CERT_CHOICES, device: DEVICE_CHOICES, sssd: SSSD_CHOICES, gss: GSS_CHOICES };
  if (!match || !choices[match[1]].includes(match[2])) throw new TypeError('Unsupported SSH held-object choice: ' + args.model.id);
  // Never re-contextualize, replace names in encoded bytes, or consult a global
  // unpersonalized scenario: args.model is the already rebuilt actual fixture.
  const a = author(args);
  ({ cert: certificate, device, sssd, gss })[match[1]](a, match[2]);
  return a.finish();
}
