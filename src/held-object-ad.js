import {ADLAB_SCENARIOS} from './kerberos-ad-lab.js';

const adHeldScenarioIds = new Set(ADLAB_SCENARIOS.map(model => model.id));

// Explicit inventory for the fixed AD DS and Keycloak bridge references.
// Source operations/attribute history never determine possession. The event keys
// below are the family contract; structured state supplies contextualized values.
export function buildADHeldObjects(args) {
  const {model, contextId, config = {}} = args;
  if (!model || !adHeldScenarioIds.has(model.id)) return null;
  const steps = args.steps || model.steps(config);
  const actors = args.actors || model.actors(config);
  const bridge = model.family === 'keycloak-bridge';
  const acceptor = bridge ? 'adKeycloak' : 'adService';
  const initialState = model.initialState;
  const source = new Map(steps.map(step => [step.id.slice(model.id.length + 1), step]));
  const plan = {scenarioId: model.id, contextId, artifacts: [], initial: [], events: {}, coverage: [], bindings: [], limitations: [
    'Fixed synthetic RFC 4120 / MS-KILE and configured Keycloak reference, not captured Windows traffic or an exported realm. Only explicit fixture stores and selected checks are represented.',
    'The pre-existing unrelated LDAP credential is a scoped opaque cache record. The fixture supplies its ID and target but no owner principal, encryption key or validity times; none are invented. It is retained independently of the requested user credential.',
  ], interactions: []};
  const live = new Map();
  const definitions = new Map();
  const stores = new Map(Object.keys(actors).map(id => [id, new Set()]));
  const categories = new Map(Object.keys(actors).map(id => [id, new Set()]));
  const at = (event, ...effects) => {
    if (event === null) plan.initial.push(...effects);
    else {
      const step = source.get(event);
      if (!step) throw new Error('Unknown AD held-object event: ' + event);
      (plan.events[step.id] ||= {milestones: [{id: 'complete', at: 1, effects: []}]}).milestones[0].effects.push(...effects);
    }
  };
  const has = event => source.has(event);
  const value = (event, attributeId, fallback) => source.get(event)?.payload.find(field => field.attributeId === attributeId)?.value ?? fallback;
  const field = (attributeId, value, readableBy) => ({attributeId, value, ...(readableBy ? {readableBy} : {})});
  function define(id, type, label, creator, fields, readers, options = {}) {
    if (definitions.has(id)) return id;
    const artifact = {artifactId: id, type, label, creator, representations: [{representationId: 'plain', format: 'local structured reference', readableBy: readers, fields}], ...options};
    plan.artifacts.push(artifact); definitions.set(id, artifact); return id;
  }
  function create(event, id) { at(event, {op: 'create', artifactId: id}); }
  function hold(event, id, actorId, store, retention = 'retained', representationId = 'plain') {
    const holdingId = [actorId, id, representationId, store].join('|');
    if (live.has(holdingId)) return holdingId;
    const effect = {op: 'acquire', holdingId, actorId, artifactId: id, representationId, store, retention};
    live.set(holdingId, effect); at(event, effect);
    stores.get(actorId)?.add(store); categories.get(actorId)?.add(definitions.get(id).type);
    return holdingId;
  }
  function release(event, holdingId) {
    if (!live.has(holdingId)) return;
    at(event, {op: 'release', holdingId}); live.delete(holdingId);
  }
  function releaseStore(event, actor, store) {
    for (const [id, holding] of [...live]) if (holding.actorId === actor && holding.store === store) release(event, id);
  }
  function promote(event, artifactId, actorId, fromStore, store, representationId = 'plain') {
    const entry = [...live].find(([, holding]) => holding.artifactId === artifactId && holding.actorId === actorId && holding.store === fromStore && holding.representationId === representationId);
    if (!entry) throw new Error('Missing AD receipt to promote: ' + artifactId);
    const [holdingId, holding] = entry;
    at(event, {op: 'move', holdingId, store, retention: 'retained'});
    live.set(holdingId, {...holding, store, retention: 'retained'});
    stores.get(actorId)?.add(store);
  }
  function observe(event, id, actorId, kind, result, extra = {}) {
    at(event, {op: 'observe', artifactId: id, actorId, kind, result, requestId: source.get(event).id, ...extra});
  }
  function authority(event, id, authorityId, status) { at(event, {op: 'authority', artifactId: id, authorityId, status}); }
  function send(event, id, from, to, {representationId = 'plain', store = 'request', retain = false} = {}) {
    // Encoded transport copies expose only the explicitly permitted representation.
    hold(event, id, to, store, retain ? 'retained' : 'temporary', representationId);
    const messageId = source.get(event).id + ':held-message:' + from + ':' + to;
    const entry = plan.events[source.get(event).id];
    const messages = entry.messages ||= [];
    let message = messages.find(item => item.messageId === messageId && item.from === from && item.to === to);
    if (!message) messages.push(message = {messageId, from, to, objects: [], start: 0, end: 1});
    message.objects.push({artifactId: id, representationId});
  }
  function local(event, id, type, label, actor, fields, {store = 'request', readers = [actor], retention = 'temporary', ...options} = {}) {
    define(id, type, label, actor, fields, readers, options); create(event, id); hold(event, id, actor, store, retention); return id;
  }
  function seed(id, type, label, creator, fields, holders, {readers = holders.map(([actor]) => actor), ...options} = {}) {
    define(id, type, label, creator, fields, readers, options); create(null, id);
    for (const [actor, store] of holders) hold(null, id, actor, store);
    return id;
  }
  function bind(path, actorId, artifactId, representationId = 'plain', store) {
    plan.bindings.push({path, actorId, artifactId, representationId, ...(store ? {store} : {}), presentWhen: 'truthy'});
  }
  const realm = initialState.credentials.tgt?.crealm || model.runtimeBindings.find(binding => binding.attributeId === 'adRealm').example;
  const target = initialState.credentials.service?.target || model.runtimeBindings.find(binding => binding.attributeId === 'adSPN').example;
  const userKey = initialState.keys.user;
  const krbtgtKey = initialState.keys.krbtgt;
  const machineKey = initialState.keys.machine;
  const kdcServiceKey = initialState.keys.serviceKdc;
  const installedKey = initialState.keys.serviceInstalled;
  seed(userKey, 'long-term-key', 'Alice account key', 'adKdc', [field('adUserKey', userKey)], [['adKdc', 'directory'], ['adAs', 'account-keys']], {readers: ['adKdc', 'adAs', 'adWorkstation']});
  seed(krbtgtKey, 'long-term-key', 'Realm krbtgt key', 'adKdc', [field('adKrbtgtKey', krbtgtKey)], [['adKdc', 'directory'], ['adAs', 'account-keys'], ['adTgs', 'account-keys']]);
  seed(machineKey, 'long-term-key', 'Workstation account key', 'adKdc', [field('adMachineKey', machineKey)], [['adKdc', 'directory'], ['adTgs', 'account-keys'], ['adWorkstation', 'machine-account']]);
  seed(kdcServiceKey, 'long-term-key', 'KDC service-account key', 'adKdc', [field('adServiceKey', kdcServiceKey), field('adTicketKeyVersion', initialState.keys.serviceKdcVersion)], [['adKdc', 'directory'], ['adTgs', 'account-keys'], ...(installedKey === kdcServiceKey ? [[acceptor, 'acceptor-keytab']] : [])]);
  if (installedKey !== kdcServiceKey) seed(installedKey, 'long-term-key', 'Installed acceptor key (stale version)', 'adKdc', [field('adServiceKey', installedKey), field('adTicketKeyVersion', initialState.keys.serviceInstalledVersions)], [[acceptor, 'acceptor-keytab']]);
  bind('keys.user', 'adAs', userKey); bind('keys.krbtgt', 'adTgs', krbtgtKey); bind('keys.machine', 'adWorkstation', machineKey);
  bind('keys.serviceKdc', 'adTgs', kdcServiceKey); bind('keys.serviceInstalled', acceptor, installedKey);
  seed('account:alice', 'account-record', 'Domain identity and PAC inputs', 'adKdc', [field('adCName', 'alice'), field('adClientRealm', realm), field('adPAC', 'Alice SID and selected group SIDs; exact SID bytes not specified')], [['adKdc', 'directory'], ['adAs', 'accounts'], ['adTgs', 'accounts']]);
  seed('configuration:workstation', 'configuration', 'Domain and workstation configuration', 'adKdc', [field('adRealm', realm), field('adSPN', target), field('adPacRequest', true)], [['adWorkstation', 'configuration']]);
  seed('policy:resource', 'policy', bridge ? 'HTTP acceptor context policy' : 'Resource ACL and acceptor policy', acceptor, [field('adAccessPolicy', initialState.policy.access), field('initialAcceptorClock', initialState.acceptorClock), field('adChannelBinding', bridge ? 'absent in this reference' : 'not selected'), field('allowableSkewSeconds', initialState.policy.skewSeconds)], [[acceptor, 'policy']]);
  seed('credential:unrelated:01', 'credential-record', 'Unrelated LDAP cached credential', 'adWorkstation', [field('instanceId', initialState.credentials.unrelated.instanceId), field('target', initialState.credentials.unrelated.target), field('cacheOwner', 'adWorkstation'), field('principal', 'not specified by fixture'), field('sessionKey', 'not specified by fixture'), field('validity', 'not specified by fixture'), field('retentionPolicy', 'retained; no eviction event in this fixture')], [['adWorkstation', 'credential-cache:unrelated']]);
  bind('credentials.unrelated', 'adWorkstation', 'credential:unrelated:01', 'plain', 'credential-cache:unrelated');
  seed('replay:acceptor', 'replay-record', 'Acceptor replay cache', acceptor, [field('adReplayCache', [...initialState.replayCache])], [[acceptor, 'replay-cache']]);
  if (initialState.sessions.localLogon) seed('session:local-logon', 'local-logon-session', 'Previously established workstation logon', 'adWorkstation', [field('principal', 'alice@' + realm), field('state', 'established before this fixture')], [['adWorkstation', 'sessions']]);
  bind('sessions.localLogon', 'adWorkstation', 'session:local-logon', 'plain', 'sessions');
  const credentials = {};
  function credential(kind) {
    const issuedEvent = kind === 'tgt' ? 'as-create' : kind + '-tgs-create';
    const receiptEvent = kind === 'tgt' ? 'as-reply' : kind + '-tgs-reply';
    const cacheEvent = kind === 'tgt' ? 'cache-tgt' : kind + '-cache';
    const issuer = kind === 'tgt' ? 'adAs' : 'adTgs';
    const state = initialState.credentials[kind] || source.get(issuedEvent)?.protocolEffects.find(effect => effect.path === 'issued.' + kind)?.value;
    if (!state) return;
    const ticket = state.ticketInstanceId, key = state.sessionKeyInstanceId;
    const encryptedFor = kind === 'tgt' ? 'adTgs' : state.encryptedFor;
    const publicFields = [field('instanceId', ticket), field(kind === 'tgt' ? 'adTgtTarget' : 'adTicketTarget', state.target), field('adTicketRealm', kind === 'service' ? (value(issuedEvent, 'adTicketRealm', realm)) : realm), ...(state.keyVersion ? [field('adTicketKeyVersion', state.keyVersion)] : [])];
    const protectedFields = [field('adCName', state.cname), field('adClientRealm', state.crealm), field('adTicketStart', state.validAfter), field('adTicketEnd', state.validBefore), field('adPAC', 'Alice SID and selected group SIDs; protected authorization inputs'), field('sessionKeyInstanceId', key)];
    define(ticket, 'kerberos-ticket', kind === 'tgt' ? 'TGT' : kind === 'host' ? 'Workstation host ticket' : 'Target-service ticket', issuer, protectedFields, [issuer, encryptedFor], {expiresAt: state.validBefore, bundle: state.instanceId, details: 'Ticket ciphertext and client session key are distinct objects. Expiry does not evict a retained credential.'});
    definitions.get(ticket).representations.push({representationId: 'opaque', format: 'Kerberos Ticket ciphertext and clear outer headers', readableBy: Object.keys(actors), fields: publicFields});
    define(key, 'session-key', kind + ' session key', issuer, [field('sessionKeyInstanceId', key)], [issuer, 'adWorkstation', encryptedFor], {expiresAt: state.validBefore, bundle: state.instanceId});
    credentials[kind] = {ticket, key, state};
    if (initialState.credentials[kind]) {
      create(null, ticket); create(null, key); hold(null, ticket, 'adWorkstation', 'credential-cache:' + kind, 'retained', 'opaque'); hold(null, key, 'adWorkstation', 'credential-cache:' + kind);
      authority(null, ticket, issuer, 'previously-issued');
    } else {
      create(issuedEvent, ticket); create(issuedEvent, key);
      hold(issuedEvent, ticket, issuer, 'reply-output', 'temporary', 'opaque'); hold(issuedEvent, key, issuer, 'reply-output', 'temporary');
      authority(issuedEvent, ticket, issuer, 'issued');
      const reply = kind === 'tgt' ? 'reply:as:01' : 'reply:tgs:' + kind + ':01';
      const replyKey = kind === 'tgt' ? userKey : 'key:tgt-session:01';
      local(issuedEvent, reply, 'encrypted-reply', kind === 'tgt' ? 'AS-REP encrypted client part' : 'TGS-REP encrypted client part', issuer, [field('adNonce', kind === 'tgt' ? 'nonce:as:01' : 'nonce:tgs:' + kind, [issuer, 'adWorkstation']), field('sessionKeyInstanceId', key, [issuer, 'adWorkstation']), field('target', state.target, [issuer, 'adWorkstation']), field('encryptionKey', replyKey)], {store: 'reply-output', readers: [issuer, 'adWorkstation'], related: [ticket, key]});
      // The protected reply is received as ciphertext; decoded fields are not
      // exposed through the transport representation before the cache check.
      definitions.get(reply).representations.push({representationId: 'opaque', format: 'EncryptedData', readableBy: Object.keys(actors), fields: [field('encryptionKey', replyKey)]});
      hold(issuedEvent, reply, issuer, 'reply-output', 'temporary', 'opaque');
      send(receiptEvent, ticket, issuer, 'adWorkstation', {representationId: 'opaque', store: 'reply-inbox'});
      send(receiptEvent, reply, issuer, 'adWorkstation', {representationId: 'opaque', store: 'reply-inbox'});
      releaseStore(receiptEvent, issuer, 'reply-output');
      observe(cacheEvent, reply, 'adWorkstation', 'verification', 'decrypted; nonce, target and validity checked');
      hold(cacheEvent, key, 'adWorkstation', 'credential-cache:' + kind);
      promote(cacheEvent, ticket, 'adWorkstation', 'reply-inbox', 'credential-cache:' + kind, 'opaque');
      observe(cacheEvent, ticket, 'adWorkstation', 'acceptance', 'accepted into credential cache');
      releaseStore(cacheEvent, 'adWorkstation', 'reply-inbox');
    }
    bind('credentials.' + kind, 'adWorkstation', ticket, 'opaque', 'credential-cache:' + kind);
    bind('credentials.' + kind, 'adWorkstation', key, 'plain', 'credential-cache:' + kind);
  }
  credential('tgt'); credential('host'); credential('service');
  if (has('password')) {
    seed('password:domain', 'password', 'Local domain password input', 'adUser', [field('adPassword', '<local password>')], [['adUser', 'user-secret']], {readers: ['adUser', 'adWorkstation']});
    send('password', 'password:domain', 'adUser', 'adWorkstation', {store: 'local-logon-input'});
    hold('select-key', userKey, 'adWorkstation', 'logon-key', 'temporary');
    releaseStore('select-key', 'adWorkstation', 'local-logon-input');
    local('select-key', 'preauth:as:01', 'kerberos-proof', 'AS timestamp preauthentication', 'adWorkstation', [field('adNonce', 'nonce:as:01'), field('adPreauth', 'EncryptedData(user-key, PA-ENC-TS-ENC)', ['adWorkstation', 'adAs'])], {readers: ['adWorkstation', 'adAs']});
    send('as-request', 'preauth:as:01', 'adWorkstation', 'adAs');
    observe('as-check', 'preauth:as:01', 'adAs', 'verification', 'account possession, timestamp and policy accepted');
    releaseStore('as-check', 'adAs', 'request'); releaseStore('cache-tgt', 'adWorkstation', 'request'); releaseStore('cache-tgt', 'adWorkstation', 'logon-key');
  }
  for (const kind of ['host', 'service']) {
    if (!has(kind + '-request-proof')) continue;
    const requestTarget = credentials[kind]?.state.target || target;
    const proof = 'authenticator:tgs:' + kind;
    local(kind + '-request-proof', proof, 'kerberos-authenticator', 'Fresh ' + kind + ' TGS authenticator', 'adWorkstation', [field('adAuthenticator', proof), field('adNonce', 'nonce:tgs:' + kind), field('adSPN', requestTarget), field('adAuthenticatorChecksum', 'Checksum(KDC-REQ-BODY; TGT session key)')], {readers: ['adWorkstation', 'adTgs'], related: ['ticket:tgt:01', 'key:tgt-session:01']});
    definitions.get(proof).representations.push({representationId: 'opaque', format: 'PA-TGS-REQ encrypted authenticator and clear request context', readableBy: Object.keys(actors), fields: [field('adNonce', 'nonce:tgs:' + kind), field('adSPN', requestTarget)]});
    hold(kind + '-request-proof', proof, 'adWorkstation', 'request', 'temporary', 'opaque');
    const requestStore = 'request:tgs:' + kind;
    send(kind + '-tgs-request', proof, 'adWorkstation', 'adTgs', {representationId: 'opaque', store: requestStore});
    send(kind + '-tgs-request', 'ticket:tgt:01', 'adWorkstation', 'adTgs', {representationId: 'opaque', store: requestStore});
    const result = has(kind + '-tgs-create') ? kind + '-tgs-create' : 'unknown-spn-check';
    observe(result, proof, 'adTgs', 'verification', result === 'unknown-spn-check' ? 'requested SPN has no account binding; no target credential issued' : 'TGT, fresh proof and checksum-bound target accepted');
    releaseStore(result, 'adTgs', requestStore);
    releaseStore(kind === 'host' ? 'host-cache' : has('service-cache') ? 'service-cache' : 'unknown-spn-error', 'adWorkstation', 'request');
  }
  if (has('local-logon')) {
    hold('local-logon', credentials.host.ticket, 'adWorkstation', 'local-acceptor', 'temporary');
    observe('local-logon', credentials.host.ticket, 'adWorkstation', 'acceptance', 'local workstation/PAC processing accepted; not remote resource authorization');
    local('local-logon', 'session:local-logon', 'local-logon-session', 'Accepted workstation logon', 'adWorkstation', [field('principal', 'alice@' + realm), field('state', 'host credential and local PAC processing accepted')], {store: 'sessions', retention: 'retained'});
    releaseStore('local-logon', 'adWorkstation', 'local-acceptor');
  }
  if (has('ap-create')) {
    const replay = initialState.replayCache.length > 0;
    const proof = replay ? 'authenticator:ap:already-accepted' : 'authenticator:ap:01';
    if (replay) seed(proof, 'kerberos-authenticator', 'Previously accepted AP authenticator (replayed)', 'adWorkstation', [field('adAuthenticator', proof), field('adAuthTime', 'ctime=1000; cusec=100001')], [['adWorkstation', 'replay-fixture']]);
    else local('ap-create', proof, 'kerberos-authenticator', 'Fresh service AP authenticator', 'adWorkstation', [field('adAuthenticator', proof), field('adAuthTime', value('ap-create', 'adAuthTime'))], {readers: ['adWorkstation', acceptor], related: ['ticket:service:01', 'key:service-session:01']});
    definitions.get(proof).representations.push({representationId: 'opaque', format: 'EncryptedData(service-session, Authenticator)', readableBy: Object.keys(actors), fields: []});
    hold('ap-create', proof, 'adWorkstation', 'request', 'temporary', 'opaque');
    send('ap-request', 'ticket:service:01', 'adWorkstation', acceptor, {representationId: 'opaque'});
    send('ap-request', proof, 'adWorkstation', acceptor, {representationId: 'opaque'});
    const check = has('ap-check') ? 'ap-check' : 'acceptor-reject';
    const reason = has('acceptor-reject') ? source.get(check).protocolEffects.find(effect => effect.path === 'failure').value.reason : null;
    observe(check, 'ticket:service:01', acceptor, 'verification', reason ? 'rejected: ' + reason : 'ticket decrypted; client identity, lifetime, proof and replay checks passed');
    observe(check, proof, acceptor, 'acceptance', reason ? 'request rejected: ' + reason : 'service authentication accepted', {endpoint: target});
    if (!reason) {
      hold(check, 'ticket:service:01', acceptor, 'authenticated-context', 'temporary');
      hold(check, 'key:service-session:01', acceptor, 'authenticated-context', 'temporary');
      local(check, 'context:service:01', 'authenticated-context', 'Authenticated service identity', acceptor, [field('adCName', 'alice'), field('adClientRealm', realm)], {store: 'sessions', retention: 'retained'});
      local(check, 'replay:ap:01', 'replay-record', 'Accepted AP proof identity', acceptor, [field('adReplayCache', proof)], {store: 'replay-cache', retention: 'retained', related: [proof]});
    }
    releaseStore(check, acceptor, 'request');
    releaseStore(check, 'adWorkstation', 'request');
    if (reason) {
      local('acceptor-reject', 'error:acceptor:01', 'protocol-error', 'Acceptor rejection', acceptor, [field('adError', value('acceptor-reject', 'adError'))], {store: 'reply-output', readers: [acceptor, 'adWorkstation']});
      send('acceptor-error', 'error:acceptor:01', acceptor, 'adWorkstation', {store: 'error-inbox'});
      observe('acceptor-error', 'ticket:service:01', 'adWorkstation', 'knowledge', 'service result learned: ' + reason + '; cached credential retained');
      releaseStore('acceptor-error', acceptor, 'reply-output'); releaseStore('acceptor-error', 'adWorkstation', 'error-inbox');
    } else {
      local('ap-reply', 'ap-reply:01', 'kerberos-proof', 'AP-REP mutual service proof', acceptor, [field('adAPReply', 'EncryptedData(service-session, ctime/cusec)')], {store: 'reply-output', readers: [acceptor, 'adWorkstation']});
      send('ap-reply', 'ap-reply:01', acceptor, 'adWorkstation', {store: 'reply-inbox'});
      releaseStore('ap-reply', acceptor, 'reply-output');
      observe('ap-reply-check', 'ap-reply:01', 'adWorkstation', 'verification', 'matching request timestamp and service session key verified');
      releaseStore('ap-reply-check', 'adWorkstation', 'reply-inbox'); releaseStore('ap-reply-check', acceptor, 'authenticated-context');
      observe('access-check', 'context:service:01', acceptor, 'acceptance', initialState.policy.access === 'deny' ? 'resource permission denied' : 'resource permission allowed', {endpoint: 'Quarterly report', policy: 'resource ACL'});
      if (has('resource')) {
        local('resource', 'resource:report:01', 'application-data', 'Quarterly report', acceptor, [field('adResource', 'Quarterly report: allowed')], {store: 'resource-output', readers: [acceptor, 'adWorkstation']});
        send('resource', 'resource:report:01', acceptor, 'adWorkstation', {store: 'application-data', retain: true}); releaseStore('resource', acceptor, 'resource-output');
      }
    }
  }
  if (has('unknown-spn-error')) {
    local('unknown-spn-check', 'error:tgs:01', 'protocol-error', 'Unknown SPN acquisition error', 'adTgs', [field('adError', 'KDC_ERR_S_PRINCIPAL_UNKNOWN (7)')], {store: 'reply-output', readers: ['adTgs', 'adWorkstation']});
    send('unknown-spn-error', 'error:tgs:01', 'adTgs', 'adWorkstation', {store: 'error-inbox'});
    observe('unknown-spn-error', 'error:tgs:01', 'adWorkstation', 'knowledge', 'target acquisition failed; existing credentials retained');
    releaseStore('unknown-spn-error', 'adTgs', 'reply-output'); releaseStore('unknown-spn-error', 'adWorkstation', 'error-inbox');
  }
  if (bridge) authorBridge();
  // Each scratch store has an explicit transaction-completion discard policy.
  // This never discards retained caches, sessions, registration or replay state.
  const finalEvent = steps.at(-1).id.slice(model.id.length + 1);
  for (const [id, holding] of [...live]) if (holding.retention === 'temporary') release(finalEvent, id);
  for (const actorId of Object.keys(actors)) plan.coverage.push({actorId, status: 'complete', stores: [...stores.get(actorId)], categories: [...categories.get(actorId)], gaps: [], support: 'supported', rationale: 'Explicit fixed-fixture stores; logical component identity is independent of collapsed rendering. An empty list means no held objects for this actor in the selected branch.'});
  return plan;

  function authorBridge() {
    const app = 'adApp', provider = 'adKeycloak', browser = 'adBrowser';
    const clientId = value('transaction', 'adClientId', 'corporate-web');
    const callback = value('transaction', 'adRedirectUri', 'https://portal.a.example/callback');
    const issuer = value('token-create', 'adIssuer', 'https://idp.a.example/realms/corporate');
    seed('registration:corporate', 'client-registration', 'Confidential OIDC registration', provider, [field('adClientId', clientId), field('adRedirectUri', callback), field('adResponseType', 'code'), field('adScope', 'openid profile'), field('adChallengeMethod', 'S256'), field('adIssuer', issuer)], [[app, 'configuration'], [provider, 'client-registrations']]);
    seed('secret:corporate', 'client-secret', 'Backend client credential', provider, [field('adClientSecret', '<backend-only secret>')], [[app, 'backend-credentials'], [provider, 'client-registrations']]);
    seed('policy:assurance', 'policy', 'Configured authentication and factor policy', provider, [field('adFlowPolicy', initialState.policy.assurance), field('factorMaxAgeSeconds', initialState.policy.factorMaxAgeSeconds), field('adIdentityMapping', 'alice@' + realm + ' -> alice-204')], [[provider, 'policy']]);
    seed('signing-key:oidc', 'signing-key', 'Configured realm signing key', provider, [field('key', '<realm-only private signing key>')], [[provider, 'signing-keys']]);
    seed('verification-key:oidc', 'verification-key', 'Trusted issuer verification key', provider, [field('issuer', issuer), field('key', '<configured issuer public verification key>')], [[app, 'verifier-configuration']]);
    // Initial account enrollment is declared independently of whether a ceremony
    // occurs. The unenrolled fixture explicitly has no factor credential.
    const unenrolled = model.id === 'lab-kc-factor-unenrolled';
    const webauthn = ['lab-kc-kerberos-fresh-webauthn', 'lab-kc-webauthn-uv-policy-fail', 'lab-kc-factor-cancelled'].includes(model.id);
    if (!unenrolled && webauthn) {
      seed('credential:factor:private', 'private-key', 'Enrolled authenticator signing key', 'adFactor', [field('adPrivateKey', '<authenticator-only private key>'), field('adCredentialId', 'credential:alice:01'), field('adRpId', 'idp.a.example')], [['adFactor', 'authenticator-credential']]);
      seed('credential:factor:public', 'public-key-record', 'Registered WebAuthn account credential', provider, [field('adPublicKey', 'registered COSE_Key'), field('adCredentialId', 'credential:alice:01'), field('adRpId', 'idp.a.example'), field('subject', 'alice-204')], [[provider, 'factor-enrollment']]);
    } else if (!unenrolled) {
      seed('secret:totp', 'totp-secret', 'Previously enrolled TOTP shared secret', 'adFactor', [field('adTotpSecret', '<enrolled shared secret>'), field('periodSeconds', 30), field('epoch', 0)], [['adFactor', 'factor-enrollment'], [provider, 'factor-enrollment']]);
    }
    seed('replay:totp', 'replay-record', 'Accepted TOTP counters', provider, [field('adOtpReplay', [...initialState.otpReplayCache])], [[provider, 'otp-replay-cache']]);
    if (initialState.sessions.provider) {
      seed('provider-session:earlier', 'provider-session', 'Existing provider session and assurance', provider, [field('session', initialState.sessions.provider), field('primary', initialState.assurance.primary), field('factor', initialState.assurance.factor || 'none')], [[provider, 'sessions']]);
      seed('cookie:provider:earlier', 'session-cookie', 'Opaque Keycloak SSO handle', provider, [field('adCookie', 'KC-session=<opaque handle>')], [[browser, 'cookies']], {readers: [browser, provider], related: ['provider-session:earlier']});
      send('authorize', 'cookie:provider:earlier', browser, provider, {store: 'cookie-inbox'});
      if (has('cookie-check')) observe('cookie-check', 'provider-session:earlier', provider, 'verification', value('cookie-check', 'adAssurance'));
    }
    local('transaction', 'oidc:corporate:01', 'oidc-transaction', 'Backend authorization transaction', app, [field('adState', value('transaction', 'adState')), field('adOidcNonce', value('transaction', 'adOidcNonce')), field('adClientId', clientId), field('adRedirectUri', callback)], {store: 'transaction', retention: 'temporary'});
    local('transaction', 'verifier:corporate:01', 'pkce-verifier', 'Backend PKCE verifier', app, [field('adVerifier', value('transaction', 'adVerifier'))], {store: 'transaction', readers: [app, provider]});
    local('transaction', 'challenge:corporate:01', 'pkce-challenge', 'S256 verifier commitment', app, [field('adChallenge', value('transaction', 'adChallenge')), field('adChallengeMethod', 'S256')], {store: 'transaction', readers: [app, browser, provider], derivedFrom: ['verifier:corporate:01']});
    local('transaction', 'request:oidc:01', 'authorization-request', 'Public authorization request', app, [field('adState', value('transaction', 'adState')), field('adOidcNonce', value('transaction', 'adOidcNonce')), field('adChallenge', value('transaction', 'adChallenge')), field('adChallengeMethod', 'S256'), field('adClientId', clientId), field('adRedirectUri', callback), field('adScope', value('transaction', 'adScope', 'openid profile')), ...(model.id === 'lab-kc-prompt-none-factor-required' ? [field('adPrompt', 'none')] : []), ...(model.id === 'lab-kc-unsupported-assurance' ? [field('adAcrValues', 'urn:auth-lab:unsupported-required-class')] : [])], {store: 'transaction', readers: [app, browser, provider], derivedFrom: ['challenge:corporate:01']});
    send('open-browser', 'request:oidc:01', app, browser, {store: 'navigation'});
    send('authorize', 'request:oidc:01', browser, provider, {store: 'authorization-transaction'});
    local('authorize', 'provider-auth:01', 'provider-transaction', 'Provider pending authorization state', provider, [field('transaction', 'oidc:corporate:01'), field('pkceCommitment', value('transaction', 'adChallenge'))], {store: 'authorization-transaction', related: ['request:oidc:01']});
    bind('transactions.oidc.pending', app, 'oidc:corporate:01', 'plain', 'transaction');
    if (has('gss-init')) {
      local('negotiate-challenge', 'http:negotiate-challenge', 'http-challenge', 'HTTP Negotiate challenge', provider, [field('adWWWAuthenticate', 'Negotiate')], {readers: [provider, browser]});
      send('negotiate-challenge', 'http:negotiate-challenge', provider, browser);
      local('gss-init', 'authenticator:http:01', 'kerberos-authenticator', 'Fresh HTTP service authenticator', 'adWorkstation', [field('adAuthenticator', 'authenticator:http:01'), field('adAuthTime', 'ctime=1000; cusec=100001')], {readers: ['adWorkstation', provider], related: ['ticket:service:01', 'key:service-session:01']});
      local('gss-init', 'spnego:init:01', 'spnego-token', 'SPNEGO initiator token', 'adWorkstation', [field('adNegTokenInit', 'mechTypes=[Kerberos OID], mechToken=AP-REQ')], {readers: ['adWorkstation', browser, provider], related: ['ticket:service:01', 'authenticator:http:01']});
      send('gss-token', 'spnego:init:01', 'adWorkstation', browser);
      send('gss-token', 'ticket:service:01', 'adWorkstation', browser, {representationId: 'opaque'});
      // The browser carries encrypted authenticator bytes, not readable proof fields.
      definitions.get('authenticator:http:01').representations.push({representationId: 'opaque', format: 'EncryptedData', readableBy: [browser, 'adWorkstation', provider], fields: []});
      hold('gss-init', 'authenticator:http:01', 'adWorkstation', 'gss-output', 'temporary', 'opaque');
      send('gss-token', 'authenticator:http:01', 'adWorkstation', browser, {representationId: 'opaque'});
      send('http-negotiate', 'spnego:init:01', browser, provider);
      send('http-negotiate', 'ticket:service:01', browser, provider, {representationId: 'opaque'});
      send('http-negotiate', 'authenticator:http:01', browser, provider, {representationId: 'opaque'});
      observe('http-accept', 'ticket:service:01', provider, 'verification', 'ticket decrypted; HTTP mechanism identity, freshness and replay accepted; SPNEGO not complete', {endpoint: target});
      hold('http-accept', 'key:service-session:01', provider, 'gss-context', 'temporary');
      local('http-accept', 'replay:http:01', 'replay-record', 'Accepted HTTP proof identity', provider, [field('adReplayCache', 'authenticator:http:01')], {store: 'replay-cache', retention: 'retained', related: ['authenticator:http:01']});
      local('http-accept', 'ap-reply:http:01', 'kerberos-proof', 'HTTP AP-REP mechanism proof', provider, [field('adAPReply', 'EncryptedData(service-session, ctime/cusec)', [provider, 'adWorkstation'])], {store: 'gss-context', readers: [provider, 'adWorkstation']});
      definitions.get('ap-reply:http:01').representations.push({representationId: 'opaque', format: 'EncryptedData', readableBy: [browser, provider, 'adWorkstation'], fields: []});
      const missing = model.id === 'lab-kc-spnego-missing-acceptor-mic';
      if (!missing) local('spnego-acceptor-integrity', 'mic:acceptor:01', 'spnego-mic', 'Acceptor mechanism-list MIC', provider, [field('adMechListMIC', value('spnego-acceptor-integrity', 'adMechListMIC'))], {store: 'gss-context', readers: [provider, browser, 'adWorkstation']});
      local('spnego-acceptor-integrity', 'spnego:acceptor:01', 'spnego-token', 'Acceptor SPNEGO continuation', provider, [field('adNegTokenResp', value('spnego-acceptor-integrity', 'adNegTokenResp'))], {store: 'gss-context', readers: [provider, browser, 'adWorkstation']});
      for (const [id, representationId] of [['spnego:acceptor:01', 'plain'], ['ap-reply:http:01', 'opaque'], ...(!missing ? [['mic:acceptor:01', 'plain']] : [])]) {
        send('spnego-continue', id, provider, browser, {representationId});
        send('spnego-local-check', id, browser, 'adWorkstation', {representationId});
      }
      const check = has('spnego-integrity-reject') ? 'spnego-integrity-reject' : 'spnego-acceptor-mic-check';
      observe(check, 'spnego:acceptor:01', 'adWorkstation', 'verification', has('spnego-integrity-reject') ? 'negotiation integrity rejected; no completed context' : 'AP-REP and exact acceptor MIC verified');
      if (has('spnego-integrity')) {
        local('spnego-integrity', 'mic:initiator:01', 'spnego-mic', 'Distinct initiator mechanism-list MIC', 'adWorkstation', [field('adMechListMIC', value('spnego-integrity', 'adMechListMIC'))], {readers: ['adWorkstation', browser, provider]});
        local('spnego-integrity', 'spnego:initiator:01', 'spnego-token', 'Initiator SPNEGO completion token', 'adWorkstation', [field('adNegTokenResp', value('spnego-integrity', 'adNegTokenResp'))], {readers: ['adWorkstation', browser, provider], related: ['mic:initiator:01']});
        for (const id of ['mic:initiator:01', 'spnego:initiator:01']) { send('spnego-local-result', id, 'adWorkstation', browser); send('spnego-mic', id, browser, provider); }
        observe('spnego-complete', 'mic:initiator:01', provider, 'verification', 'initiator MIC checked; SPNEGO complete; configured account mapping accepted');
        local('spnego-complete', 'context:http:01', 'authenticated-context', 'Completed HTTP SPNEGO context', provider, [field('principal', 'alice@' + realm), field('subject', 'alice-204'), field('channelBinding', 'absent')], {store: 'sessions', retention: 'retained'});
        local('spnego-complete', 'spnego:final:01', 'spnego-token', 'Final negotiation acknowledgement', provider, [field('adNegTokenResp', 'negState=accept-completed')], {readers: [provider, browser]});
        send('spnego-final', 'spnego:final:01', provider, browser);
      } else {
        local('spnego-integrity-reject', 'gss:error:01', 'local-api-error', 'Local GSS defective-token result', 'adWorkstation', [field('adGssStatus', 'GSS_S_DEFECTIVE_TOKEN')], {readers: ['adWorkstation', browser]});
        send('spnego-local-failure', 'gss:error:01', 'adWorkstation', browser);
        local('spnego-integrity-reject', 'spnego:reject:01', 'spnego-token', 'SPNEGO rejecting token', 'adWorkstation', [field('adNegTokenResp', 'negState=reject')], {readers: ['adWorkstation', browser, provider]});
        send('spnego-local-failure', 'spnego:reject:01', 'adWorkstation', browser); send('spnego-reject-return', 'spnego:reject:01', browser, provider);
      }
    }
    if (has('password-fallback')) {
      seed('password:provider', 'password', 'Provider password credential', 'adUser', [field('adPassword', '<provider password>')], [['adUser', 'user-secret']], {readers: ['adUser', browser, provider]});
      seed('account:provider-password', 'account-record', 'Configured provider credential verifier', provider, [field('credential', '<account credential / federation verifier>')], [[provider, 'account-credentials']]);
      send('password-fallback', 'password:provider', 'adUser', browser, {store: 'password-form'}); send('password-submit', 'password:provider', browser, provider, {store: 'password-input'});
      observe('password-check', 'password:provider', provider, 'verification', 'provider account credential accepted');
      local('password-check', 'identity:provider:01', 'authenticated-context', 'Verified provider primary identity', provider, [field('principal', 'alice@' + realm), field('subject', 'alice-204'), field('primaryMethod', 'password')], {store: 'sessions', retention: 'retained'});
      releaseStore('password-check', browser, 'password-form'); releaseStore('password-check', provider, 'password-input');
    }
    if (has('totp-create')) {
      local('totp-create', 'otp:computed:01', 'one-time-code', 'Computed current TOTP', 'adFactor', [field('adOtp', '123456 (symbolic)'), field('adTotpCounter', 33)], {readers: ['adFactor', 'adUser', browser, provider], related: ['secret:totp']});
      send('totp-display', 'otp:computed:01', 'adFactor', 'adUser', {store: 'otp-input'});
      const wrong = model.id === 'lab-kc-factor-failed';
      const submitted = wrong ? local('totp-enter', 'otp:wrong-input:01', 'one-time-code', 'Incorrect submitted TOTP input', 'adUser', [field('adOtp', '654321 (wrong selected code)')], {store: 'otp-input', readers: ['adUser', browser, provider]}) : 'otp:computed:01';
      send('totp-enter', submitted, 'adUser', browser, {store: 'otp-input'}); send('totp-submit', submitted, browser, provider, {store: 'otp-input'});
      observe('totp-check', submitted, provider, 'verification', wrong ? 'incorrect code rejected; no factor assurance achieved' : 'HOTP, bounded time window and selected one-use policy accepted');
      if (!wrong) local('totp-check', 'replay:totp:33', 'replay-record', 'Accepted TOTP counter 33', provider, [field('adOtpReplay', 33)], {store: 'otp-replay-cache', retention: 'retained', related: [submitted]});
      for (const actor of ['adFactor', 'adUser', browser, provider]) { releaseStore('totp-check', actor, 'otp-input'); if (actor === 'adFactor') releaseStore('totp-check', actor, 'request'); }
    }
    if (has('wa-challenge')) {
      local('wa-challenge', 'challenge:kc-factor:01', 'webauthn-challenge', 'Transaction-bound WebAuthn challenge', provider, [field('adWaChallenge', 'challenge:kc-factor:01'), field('adRpId', 'idp.a.example'), field('adUVPolicy', 'required')], {store: 'factor-transaction', readers: [provider, browser]});
      send('wa-challenge', 'challenge:kc-factor:01', provider, browser, {store: 'factor-transaction'});
      if (has('wa-cancel')) {
        local('wa-cancel', 'webauthn:cancelled', 'local-api-error', 'WebAuthn cancellation (no assertion)', browser, [field('adWaCancellation', 'NotAllowedError')], {store: 'factor-transaction'});
        observe('wa-cancel', 'challenge:kc-factor:01', browser, 'acceptance', 'ceremony cancelled; no authenticator assertion produced');
      } else {
        local('wa-client-data', 'webauthn:client-data:01', 'webauthn-client-data', 'Exact browser ceremony bytes', browser, [field('adClientData', value('wa-client-data', 'adClientData'))], {store: 'factor-transaction', readers: [browser, provider], related: ['challenge:kc-factor:01']});
        local('wa-client-data', 'webauthn:client-hash:01', 'digest', 'SHA-256 of exact clientDataJSON', browser, [field('adClientDataHash', value('wa-client-data', 'adClientDataHash'))], {store: 'factor-transaction', readers: [browser, 'adFactor'], derivedFrom: ['webauthn:client-data:01']});
        send('wa-authenticator', 'webauthn:client-hash:01', browser, 'adFactor', {store: 'factor-operation'});
        local('wa-sign', 'webauthn:assertion:01', 'webauthn-assertion', 'Signed enrolled factor assertion', 'adFactor', [field('adCredentialId', 'credential:alice:01'), field('adAuthData', value('wa-sign', 'adAuthData')), field('adUV', value('wa-sign', 'adUV')), field('adWaSignature', value('wa-sign', 'adWaSignature'))], {store: 'factor-operation', readers: ['adFactor', browser, provider], derivedFrom: ['webauthn:client-hash:01'], related: ['credential:factor:private', 'credential:factor:public']});
        send('wa-local-result', 'webauthn:assertion:01', 'adFactor', browser, {store: 'factor-transaction'});
        send('wa-submit', 'webauthn:assertion:01', browser, provider, {store: 'factor-transaction'}); send('wa-submit', 'webauthn:client-data:01', browser, provider, {store: 'factor-transaction'});
        observe('wa-check', 'webauthn:assertion:01', provider, 'verification', 'registered public key signature, challenge, origin and RP checked');
        observe('wa-check', 'webauthn:assertion:01', provider, 'acceptance', model.id === 'lab-kc-webauthn-uv-policy-fail' ? 'valid signature but UV=false violates required policy' : 'UP and required UV accepted');
        releaseStore('wa-check', 'adFactor', 'factor-operation'); releaseStore('wa-check', browser, 'factor-transaction'); releaseStore('wa-check', provider, 'factor-transaction');
      }
    }
    if (has('code-create')) {
      local('assurance-check', 'assurance:corporate:01', 'assurance-record', 'Checked authentication policy result', provider, [field('adAssurance', value('assurance-check', 'adAssurance'))], {store: 'sessions', retention: 'retained'});
      local('code-create', 'code:corporate:01', 'authorization-code', 'Client-bound single-use authorization code', provider, [field('adCode', 'code:corporate:01'), field('adClientId', clientId), field('adRedirectUri', callback), field('pkceCommitment', value('transaction', 'adChallenge'))], {store: 'authorization-codes', readers: [provider, browser, app], related: ['challenge:corporate:01']});
      authority('code-create', 'code:corporate:01', provider, 'issued; unconsumed');
      send('code-redirect', 'code:corporate:01', provider, browser, {store: 'callback'}); send('code-callback', 'code:corporate:01', browser, app, {store: 'callback'});
      local('code-redirect', 'callback:corporate:01', 'authorization-response', 'Code callback and original transaction state', provider, [field('adCode', 'code:corporate:01'), field('adState', value('transaction', 'adState')), field('adRedirectUri', callback)], {store: 'callback-output', readers: [provider, browser, app], related: ['code:corporate:01', 'oidc:corporate:01']});
      send('code-redirect', 'callback:corporate:01', provider, browser, {store: 'callback'}); send('code-callback', 'callback:corporate:01', browser, app, {store: 'callback'});
      observe('code-callback', 'oidc:corporate:01', app, 'verification', 'original state and callback context matched');
      send('token-request', 'code:corporate:01', app, provider, {store: 'token-request'}); send('token-request', 'verifier:corporate:01', app, provider, {store: 'token-request'});
      local('token-request', 'basic:corporate:01', 'client-authentication', 'Backend HTTP Basic client proof', app, [field('adClientAuthorization', 'Basic <encoded client-id:secret>', [app, provider])], {store: 'token-request', readers: [app, provider], derivedFrom: ['secret:corporate']});
      send('token-request', 'basic:corporate:01', app, provider, {store: 'token-request'});
      observe('token-check', 'code:corporate:01', provider, 'verification', 'client identity, callback, unconsumed code and recomputed S256 commitment checked');
      authority('token-check', 'code:corporate:01', provider, 'consumed');
      releaseStore('token-check', provider, 'authorization-codes'); releaseStore('token-check', provider, 'token-request'); releaseStore('token-check', app, 'token-request');
      local('token-create', 'token:id:corporate:01', 'id-token', 'Signed OIDC identity token', provider, ['adIssuer', 'adAudience', 'adSubject', 'adOidcNonce', 'adTokenIssuedAt', 'adTokenExpiry', ...((source.get('token-create').fields || []).includes('adACR') ? ['adACR'] : []), ...((source.get('token-create').fields || []).includes('adAMR') ? ['adAMR'] : [])].map(id => field(id, value('token-create', id))), {store: 'token-output', readers: [provider, app], expiresAt: 1300, related: ['assurance:corporate:01']});
      local('token-create', 'token:access:corporate:01', 'access-token', 'Realm resource access token', provider, [field('adAccessToken', '<realm access token>'), field('adTokenType', 'Bearer'), field('audiencePolicy', 'registered realm resource policy; no API request is modeled')], {store: 'token-output', readers: [provider, app]});
      authority('token-create', 'token:id:corporate:01', provider, 'issued'); authority('token-create', 'token:access:corporate:01', provider, 'issued');
      for (const id of ['token:id:corporate:01', 'token:access:corporate:01']) send('token-response', id, provider, app, {store: 'token-inbox'});
      releaseStore('token-response', provider, 'token-output');
      observe('app-validate', 'token:id:corporate:01', app, 'verification', 'signature, trusted issuer, client audience, nonce, numeric iat/exp, lifetime and configured assurance semantics checked');
      observe('app-validate', 'token:id:corporate:01', app, 'acceptance', 'accepted for this application login; not an API authorization result', {endpoint: callback});
      hold('app-validate', 'token:id:corporate:01', app, 'backend-tokens'); hold('app-validate', 'token:access:corporate:01', app, 'backend-tokens'); releaseStore('app-validate', app, 'token-inbox');
      local('app-validate', 'session:app:01', 'application-session', 'Validated application session', app, [field('adAppSession', 'alice-204 at ' + clientId)], {store: 'sessions', retention: 'retained', related: ['token:id:corporate:01']});
      bind('sessions.applicationAuthenticated', app, 'session:app:01', 'plain', 'sessions');
    } else {
      local('policy-reject', 'error:oidc:01', 'authorization-error', 'OIDC authorization failure', provider, [field('adOidcError', value('policy-reject', 'adOidcError')), field('adState', value('transaction', 'adState'))], {store: 'error-output', readers: [provider, browser, app]});
      send('error-redirect', 'error:oidc:01', provider, browser, {store: 'callback'}); send('error-callback', 'error:oidc:01', browser, app, {store: 'callback'});
      observe('error-callback', 'oidc:corporate:01', app, 'acceptance', 'state checked; transaction denied; no identity or app session accepted');
    }
  }
}
