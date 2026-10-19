import {createHeldObjectPlan, heldArtifact, heldAt, heldAcquire, heldCoverage} from './held-object-authoring.js';

// Inventory is authored by fixture event, never reconstructed from the historical
// attribute ledger. Attribute occurrences below bind exact field values/identities
// only; neither operation kinds nor cumulative holder lists establish possession.
export function buildKerberosHeldObjects(args) {
  const id = args.model?.id;
  if (CRYPTO_CHOICES.has(id)) return buildCrypto(args);
  if (FOREST_CHOICES.has(id)) return buildForest(args);
  return null;
}

const CRYPTO_CHOICES = new Set([
  ...['success', 'binding', 'trust', 'kdc-trust'].map(v => 'lab-ad-pkinit-' + v),
  ...['success', 'bootstrap', 'required-armor', 'unsupported-dc', 'optional-fallback', 'checksum', 'challenge', 'missing-response', 'response-nonce', 'ticket-binding'].map(v => 'lab-ad-fast-as-' + v),
  ...['success', 'missing-subkey', 'missing-strengthen'].map(v => 'lab-ad-fast-tgs-' + v),
]);
const FOREST_CHOICES = new Set(['one-way', 'one-way-reverse', 'two-way-a-b', 'two-way-b-a', 'child-domains', 'three-denied', 'three-direct', 'same-forest', 'selective-denied', 'sid-filtering', 'invalid-pac', 'acl-denied', 'cached-referrals', 'cached-service'].map(v => 'lab-ad-forest-' + v));

function author(args) {
  const plan = createHeldObjectPlan(args), steps = args.steps, definitions = new Map(), live = new Map();
  const event = suffix => steps.find(step => step.id === args.model.id + '-' + suffix)?.id;
  const at = (suffix, ...effects) => {
    const id = suffix === null ? null : event(suffix);
    if (suffix !== null && !id) throw new Error('Missing authored Kerberos event: ' + suffix);
    heldAt(plan, id, ...effects);
  };
  const declare = (artifactId, label, creator, representations, options = {}) => {
    if (!definitions.has(artifactId)) {
      const definition = {artifactId, type: options.type || 'kerberos-object', label, creator, representations, ...options};
      definitions.set(artifactId, heldArtifact(plan, definition));
    }
    return artifactId;
  };
  const create = (suffix, artifactId) => {
    if (!created.has(artifactId)) { at(suffix, {op: 'create', artifactId}); created.add(artifactId); }
  };
  const created = new Set();
  const acquire = (suffix, artifactId, actorId, store = 'working memory', representationId = 'plain', retention = 'temporary') => {
    const effect = heldAcquire(artifactId, actorId, store, {representationId, retention});
    if (!live.has(effect.holdingId)) { at(suffix, effect); live.set(effect.holdingId, effect); }
    return effect.holdingId;
  };
  const promote = (suffix, artifactId, actorId, representationId) => {
    const receipt = [...live.values()].find(holding => holding.actorId === actorId && holding.artifactId === artifactId && holding.representationId === representationId && holding.store === 'received bytes');
    if (!receipt) throw new Error('Cache acceptance requires authored delivery: ' + artifactId);
    at(suffix, {op: 'move', holdingId: receipt.holdingId, store: 'credential cache', retention: 'retained'});
    live.set(receipt.holdingId, {...receipt, store: 'credential cache', retention: 'retained'});
  };
  const observe = (suffix, artifactId, actorId, result, kind = 'verification') => at(suffix, {op: 'observe', artifactId, actorId, kind, result});
  const wire = (suffix, artifactId, from, to, representationId = 'plain', {fromStore = 'working memory', toStore = 'received bytes', retained = false} = {}) => {
    // The sender must already hold this exact representation. Sending copies it;
    // retained sender credentials are never consumed by presentation.
    const source = [...live.values()].find(holding => holding.actorId === from && holding.artifactId === artifactId && holding.representationId === representationId && holding.store === fromStore);
    if (!source) throw new Error('Unauthored Kerberos sender holding: ' + suffix + ' ' + artifactId + ' ' + from);
    const destination = heldAcquire(artifactId, to, toStore, {representationId, retention: retained ? 'retained' : 'temporary'});
    if (!live.has(destination.holdingId)) { at(suffix, destination); live.set(destination.holdingId, destination); }
    const key = event(suffix);
    const entry = plan.events[key] ||= {milestones: [{id: 'complete', at: 1, effects: []}]};
    const messageId = key + ':' + from + '->' + to;
    const messages = entry.messages ||= [];
    let message = messages.find(item => item.messageId === messageId);
    if (!message) { message = {messageId, from, to, objects: [], start: 0, end: 1}; messages.push(message); }
    if (!message.objects.some(item => item.artifactId === artifactId && item.representationId === representationId)) message.objects.push({artifactId, representationId});
  };
  const finish = () => {
    const last = steps.at(-1).id;
    // Explicit fixture policy: scratch material is discarded when this exchange
    // terminates. Configured keys, accepted caches and rejected response evidence
    // are retained. This is not a forensic-memory-erasure claim.
    for (const [holdingId, holding] of live) if (holding.retention === 'temporary') {
      heldAt(plan, last, {op: 'release', holdingId});
    }
    for (const actorId of Object.keys(args.actors)) heldCoverage(plan, actorId, {
      stores: ['configuration', 'credential cache', 'working memory', 'received bytes', 'rejected response', 'authenticated context', 'replay cache', 'knowledge'],
      categories: ['configured keys and trust', 'tickets and session keys', 'protected messages', 'local derivations', 'authentication and policy results'],
      rationale: 'Explicit symbolic fixture inventory. Scratch objects are released at terminal completion; no unshown persistent Windows store is claimed.',
    });
    return plan;
  };
  return {plan, event, at, declare, create, acquire, promote, observe, wire, finish, definitions};
}

const plain = (readableBy, fields) => ({representationId: 'plain', format: 'decoded local object', readableBy, fields});
const opaque = fields => ({representationId: 'opaque', format: 'protected Kerberos bytes', readableBy: [], fields});
const field = (attributeId, name, value, readableBy) => ({attributeId, name, value, ...(readableBy ? {readableBy} : {})});

function buildCrypto(args) {
  const a = author(args), {model, steps} = args, id = model.id;
  const prefix = 'crypto' + id.replace(/^lab-/, '').split('-').map(s => s[0].toUpperCase() + s.slice(1)).join('');
  const defs = model.definitions();
  const client = 'cryptoClient', computer = 'cryptoComputer', as = args.actors.cryptoAs ? 'cryptoAs' : 'cryptoKdc', tgs = args.actors.cryptoTgs ? 'cryptoTgs' : 'cryptoKdc', service = 'cryptoService', card = 'cryptoCard';
  const fastTgs = id.startsWith('lab-ad-fast-tgs-'), kdc = fastTgs ? tgs : as;
  const lookup = suffix => {
    const attributeId = prefix + suffix, def = defs[attributeId];
    if (!def) throw new Error('Missing authored crypto field: ' + id + ' ' + suffix);
    const occurrence = steps.flatMap(s => s.attributeOperations || []).find(o => o.attributeId === attributeId);
    if (!occurrence) throw new Error('Missing exact crypto identity: ' + attributeId);
    return {artifactId: occurrence.instanceId, attributeId, name: def.name, value: occurrence.value, path: occurrence.fieldPath};
  };
  const object = (suffix, creator, readers, protectedBytes = false, options = {}) => {
    readers = readers.filter(actor => args.actors[actor]);
    const f = lookup(suffix), rep = protectedBytes ? 'opaque' : 'plain';
    const fields = [field(f.attributeId, f.path, f.value, protectedBytes ? [] : readers)];
    const derivations = {
      ReplyKey: ['SharedSecret'],
      ArmorKey: ['ArmorTicketKey', 'Subkey'],
      ClientChallengeKey: ['ArmorKey', 'LongTermKey'],
      KdcChallengeKey: ['ArmorKey', 'LongTermKey'],
      FinalReplyKey: ['Strengthen', fastTgs ? 'Subkey' : 'LongTermKey'],
    };
    if (derivations[suffix]) options = {...options, derivedFrom: derivations[suffix].map(dependency => lookup(dependency).artifactId)};
    if (suffix === 'SharedSecret') options = {...options, details: 'Independently derived at each endpoint from its local private DH value and the validated peer public value. Neither private exponent nor shared secret is a wire field.'};
    a.declare(f.artifactId, f.name, creator, [protectedBytes ? opaque(fields) : plain(readers, fields)], options);
    const definition = a.definitions.get(f.artifactId);
    let representation = definition.representations.find(r => r.representationId === rep);
    if (!representation) { representation = protectedBytes ? opaque([]) : plain(readers, []); definition.representations.push(representation); }
    if (!representation.fields.some(entry => entry.attributeId === f.attributeId)) representation.fields.push(...fields);
    return f.artifactId;
  };
  const local = (event, suffix, actor, readers = [actor], store = 'working memory', retention = 'temporary', options = {}) => {
    const artifactId = object(suffix, actor, readers, false, options);
    a.create(event, artifactId); a.acquire(event, artifactId, actor, store, 'plain', retention); return artifactId;
  };
  const bytes = (event, suffix, actor, store = 'working memory', retention = 'temporary') => {
    const artifactId = object(suffix, actor, [], true);
    a.create(event, artifactId); a.acquire(event, artifactId, actor, store, 'opaque', retention); return artifactId;
  };
  const hold = (event, suffix, actor, {store = 'working memory', protectedBytes = false, retention = 'temporary', readers = [client, as, tgs, service, computer, card]} = {}) => {
    const artifactId = object(suffix, actor, readers, protectedBytes);
    a.acquire(event, artifactId, actor, store, protectedBytes ? 'opaque' : 'plain', retention); return artifactId;
  };
  const send = (event, suffix, from, to, options = {}) => {
    const f = lookup(suffix), protectedBytes = options.protectedBytes || false;
    a.wire(event, f.artifactId, from, to, protectedBytes ? 'opaque' : 'plain', options);
  };
  const transfer = (event, suffixes, from, to, protectedSuffixes = [], options = {}) => {
    for (const suffix of suffixes) send(event, suffix, from, to, {...options, protectedBytes: protectedSuffixes.includes(suffix)});
  };
  const configured = (name, actors, value, type = 'configured-key') => {
    const artifactId = id + ':configured:' + name;
    a.declare(artifactId, name, actors[0], [plain(actors, [field('kerberosConfiguredMaterial', name, value, actors)])], {type});
    a.create(null, artifactId);
    for (const actor of actors) if (args.actors[actor]) a.acquire(null, artifactId, actor, 'configuration', 'plain', 'retained');
    return artifactId;
  };
  // Configured capabilities are prerequisites, not issuance side effects.
  const keyOwners = [...new Set([as, tgs].filter(actor => args.actors[actor] && (actor !== 'cryptoKdc' || !args.actors.cryptoAs && !args.actors.cryptoTgs)))];
  configured('krbtgt long-term key', keyOwners, '<protected krbtgt key>');
  const serviceKeyOwners = args.actors.cryptoService ? [...new Set([tgs, service])] : [];
  if (serviceKeyOwners.length) configured('service account long-term key', serviceKeyOwners, '<protected service-account key>');
  const cache = (event, ticketSuffix, keySuffix, actor, path, initial = false) => {
    const ticket = object(ticketSuffix, kdc, [], true);
    const key = object(keySuffix, kdc, [actor, kdc, ...(keySuffix === 'ServiceKey' ? [service] : [])]);
    if (initial) {
      for (const artifactId of [ticket, key]) a.create(event, artifactId);
      a.acquire(event, ticket, actor, 'credential cache', 'opaque', 'retained');
      a.acquire(event, key, actor, 'credential cache', 'plain', 'retained');
    }
    else {
      a.promote(event, ticket, actor, 'opaque');
      a.acquire(event, key, actor, 'credential cache', 'plain', 'retained');
    }
    if (!initial) a.observe(event, ticket, actor, 'Credential reply validated and accepted', 'acceptance');
    a.plan.bindings.push({path, actorId: actor, artifactId: ticket, representationId: 'opaque', store: 'credential cache', presentWhen: 'truthy'});
    a.plan.bindings.push({path, actorId: actor, artifactId: key, representationId: 'plain', store: 'credential cache', presentWhen: 'truthy'});
    // Initial FAST state omits a sessionKeyInstanceId; inventory explicitly adds
    // its configured companion without pretending the stock state names it.
    return {ticket, key};
  };
  const verify = (event, suffix, actor, result) => a.observe(event, lookup(suffix).artifactId, actor, result);

  if (id.startsWith('lab-ad-pkinit-')) {
    local(null, 'SigningKey', card, [card], 'configuration', 'retained');
    local(null, 'UserCertificate', card, [card, client, as], 'configuration', 'retained');
    for (const suffix of ['StrongMapping', 'CertificateTrust']) local(null, suffix, as, [as], 'configuration', 'retained');
    configured('KDC certificate trust policy', [client], id.endsWith('kdc-trust') ? 'KDC certificate rejected' : 'Trusted KDC certificate, identity and permitted DH profile', 'trust-policy');
    if (defs[prefix + 'KdcSigningKey']) local(null, 'KdcSigningKey', as, [as], 'configuration', 'retained');
    else {
      const keyId = id + ':kdc-signing-key:1';
      a.declare(keyId, 'KDC signing private key', as, [plain([as], [field('kerberosKdcSigningKey', 'privateKey', '<protected KDC signing key>', [as])])]);
      a.create(null, keyId); a.acquire(null, keyId, as, 'configuration', 'plain', 'retained');
    }
    if (defs[prefix + 'KdcCertificate']) local(null, 'KdcCertificate', as, [as, client], 'configuration', 'retained');
    else {
      const certificateId = id + ':kdc-cert:1';
      a.declare(certificateId, 'KDC public certificate', as, [plain([as, client], [field('kerberosKdcCertificate', 'Certificate', '<DER KDC certificate>', [as, client])])]);
      a.create(null, certificateId); a.acquire(null, certificateId, as, 'configuration', 'plain', 'retained');
    }
    local('unlock', 'Pin', 'cryptoUser', ['cryptoUser', card]);
    hold('unlock', 'Pin', card, {readers: ['cryptoUser', card]});
    for (const suffix of ['Body', 'BodyNonce', 'Ctime', 'Cusec', 'PkNonce', 'Checksum', 'ClientDhPrivate', 'ClientPublic', 'AuthPack']) local('authpack', suffix, client, suffix === 'ClientDhPrivate' ? [client] : [client, card, as]);
    send('sign-input', 'AuthPack', client, card);
    local('card-sign', 'SignedAuthPack', card, [card, client, as]);
    send('signature-result', 'SignedAuthPack', card, client);
    send('signature-result', 'UserCertificate', card, client, {fromStore: 'configuration'});
    hold('signature-result', 'SignedAuthPack', client, {readers: [card, client, as]});
    hold('signature-result', 'UserCertificate', client, {readers: [card, client, as]});
  } else {
    // FAST's configured account key is distinct from the computer credential.
    if (defs[prefix + 'LongTermKey']) local(null, 'LongTermKey', kdc, [client, kdc], 'configuration', 'retained');
    else if (!fastTgs && id !== 'lab-ad-fast-as-bootstrap') {
      const accountKey = id + ':user-long-term-key:1';
      a.declare(accountKey, 'Configured Alice account key', kdc, [plain([kdc], [field('kerberosUserAccountKey', 'local.userLongTermKey', '<Alice long-term key; local only>', [kdc])])]);
      a.create(null, accountKey); a.acquire(null, accountKey, kdc, 'configuration', 'plain', 'retained');
    }
    if (defs[prefix + 'Policy']) {
      local(null, 'Policy', client, [client, kdc], 'configuration', 'retained');
      hold(null, 'Policy', kdc, {store: 'configuration', retention: 'retained', readers: [client, kdc]});
    } else configured('Required FAST policy', [client, kdc], model.initialState.policy, 'trust-policy');
    if (defs[prefix + 'Capability']) local(null, 'Capability', client, [client], 'configuration', 'retained');
    if (id !== 'lab-ad-fast-as-bootstrap') {
      const actor = fastTgs ? client : computer, path = fastTgs ? 'credentials.userTgt' : 'credentials.computerTgt';
      if (defs[prefix + 'ArmorTicket']) cache(null, 'ArmorTicket', 'ArmorTicketKey', actor, path, true);
      else {
        const credential = model.initialState.credentials[fastTgs ? 'userTgt' : 'computerTgt'];
        const ticketId = credential.instanceId, keyId = id + ':' + (fastTgs ? 'user' : 'computer') + '-tgt-session-key:1';
        a.declare(ticketId, 'Previously accepted ' + (fastTgs ? 'user' : 'computer') + ' TGT', kdc, [opaque([field('kerberosCachedTicket', 'Ticket', '<retained opaque TGT>', [])])]);
        a.declare(keyId, 'Previously accepted TGT session key', kdc, [plain([actor, kdc], [field('kerberosCachedSessionKey', 'credential.sessionKey', '<retained TGT session key>', [actor, kdc])])], {related: [ticketId]});
        for (const artifactId of [ticketId, keyId]) a.create(null, artifactId);
        a.acquire(null, ticketId, actor, 'credential cache', 'opaque', 'retained'); a.acquire(null, keyId, actor, 'credential cache', 'plain', 'retained');
        a.plan.bindings.push({path, actorId: actor, artifactId: ticketId, representationId: 'opaque', store: 'credential cache', presentWhen: 'truthy'});
        a.plan.bindings.push({path, actorId: actor, artifactId: keyId, representationId: 'plain', store: 'credential cache', presentWhen: 'truthy'});
      }
    }
    if (id === 'lab-ad-fast-as-bootstrap') {
      local(null, 'MachineKey', computer, [computer, as], 'configuration', 'retained');
      hold(null, 'MachineKey', as, {store: 'configuration', retention: 'retained', readers: [computer, as]});
      bytes('bootstrap-build', 'BootstrapProof', computer);
      transfer('bootstrap-request', ['BootstrapProof'], computer, as, ['BootstrapProof']);
      bytes('bootstrap-policy', 'ArmorTicket', as); local('bootstrap-policy', 'ArmorTicketKey', as, [as, computer]);
      bytes('bootstrap-response', 'BootstrapReply', as);
      transfer('bootstrap-response', ['ArmorTicket', 'BootstrapReply'], as, computer, ['ArmorTicket', 'BootstrapReply']);
      cache('bootstrap-cache', 'ArmorTicket', 'ArmorTicketKey', computer, 'credentials.computerTgt');
      return a.finish();
    }
    if (a.event('prerequisite-denied')) {
      local('prerequisite-denied', 'Failure', client, [client], 'knowledge', 'retained');
      return a.finish();
    }
    if (a.event('unarmored-request')) {
      local('unarmored-request', 'OuterBody', client, [client, as]); send('unarmored-request', 'OuterBody', client, as);
      local('enforce', 'Failure', as, [as, client]); send('enforce-result', 'Failure', as, client, {retained: true, toStore: 'knowledge'});
      return a.finish();
    }
    if (a.event('user-credential')) {
      local('user-credential', 'UserPassword', 'cryptoUser', ['cryptoUser', client]);
      hold('user-credential', 'UserPassword', client, {readers: ['cryptoUser', client]});
      hold('user-credential', 'LongTermKey', client, {readers: [client, as], store: 'configuration', retention: 'retained'});
    }
    if (a.event('fallback-policy')) {
      hold('fallback-proof', 'LongTermKey', client, {readers: [client, as], store: 'configuration', retention: 'retained'});
      bytes('fallback-proof', 'FallbackProof', client); send('fallback-request', 'FallbackProof', client, as, {protectedBytes: true});
      verify('fallback-check', 'FallbackProof', as, 'Explicit optional password fallback accepted; fixture issues no ticket');
      return a.finish();
    }
    if (fastTgs) {
      local('tgs-build', 'Spn', client, [client, tgs]);
      for (const suffix of ['OuterBody', 'InnerBody', 'FastOptions', 'Nonce']) local('tgs-build', suffix, client, [client, tgs]);
      bytes('tgs-build', 'ArmorApReq', client);
      hold('tgs-build', 'ArmorTicket', client, {protectedBytes: true});
      if (a.event('missing-subkey-reject')) {
        local('missing-subkey-reject', 'Failure', client, [client], 'knowledge', 'retained'); return a.finish();
      }
      local('tgs-build', 'Subkey', client, [client, tgs]);
      local('tgs-protect', 'ArmorKey', client, [client, tgs]);
      local('tgs-protect', 'ReqChecksum', client, [client, tgs]);
      for (const suffix of ['EncReq', 'FastRequest']) bytes('tgs-protect', suffix, client);
      transfer('tgs-request', ['ArmorApReq', 'OuterBody', 'FastRequest', 'ReqChecksum', 'EncReq'], client, tgs, ['ArmorApReq', 'FastRequest', 'EncReq']);
      for (const suffix of ['ArmorTicketKey', 'Subkey', 'ArmorKey', 'InnerBody', 'FastOptions', 'Nonce']) hold('tgs-check', suffix, tgs, {readers: [client, tgs]});
      hold('tgs-check', 'ArmorTicket', tgs, {protectedBytes: true});
      verify('tgs-check', 'ArmorApReq', tgs, 'User TGT and fresh subkey accepted; implicit armor independently derived');
    } else {
      local('computer-armor', 'Subkey', computer, [computer, as]);
      bytes('computer-armor', 'ArmorApReq', computer);
      local('computer-armor', 'ArmorKey', computer, [computer, client, as]);
      transfer('armor-local-api', ['ArmorApReq', 'ArmorKey'], computer, client, ['ArmorApReq']);
      hold('armor-local-api', 'ArmorApReq', client, {protectedBytes: true});
      hold('armor-local-api', 'ArmorKey', client, {readers: [computer, client, as]});
      local('user-challenge', 'ClientChallengeKey', client, [client, as]);
      local('user-challenge', 'Challenge', client, [client, as]);
      for (const suffix of ['OuterBody', 'InnerBody', 'FastOptions', 'Nonce', 'ReqChecksum']) local('protect-request', suffix, client, [client, as]);
      for (const suffix of ['Armor', 'EncReq', 'FastRequest']) bytes('protect-request', suffix, client);
      transfer('fast-request', ['OuterBody', 'FastRequest', 'Armor', 'ArmorApReq', 'ReqChecksum', 'EncReq'], client, as, ['FastRequest', 'Armor', 'ArmorApReq', 'EncReq']);
      hold('armor-kdc', 'ArmorTicket', as, {protectedBytes: true});
      for (const suffix of ['ArmorTicketKey', 'Subkey', 'ArmorKey']) hold('armor-kdc', suffix, as, {readers: suffix === 'ArmorKey' ? [computer, client, as] : [computer, as]});
      verify('armor-kdc', 'ArmorApReq', as, 'Computer armor authenticated; no Alice authentication implied');
      if (!id.endsWith('-checksum')) for (const suffix of ['InnerBody', 'FastOptions', 'Nonce']) hold('request-binding', suffix, as, {readers: [client, as]});
      if (a.event('user-check')) {
        hold('user-check', 'ClientChallengeKey', as, {readers: [client, as]});
        hold('user-check', 'Challenge', as, {readers: [client, as]});
        verify('user-check', 'Challenge', as, id.endsWith('-challenge') ? 'User challenge rejected' : 'Separate Alice challenge accepted');
      }
      if (a.event('kdc-reject')) {
        for (const suffix of ['Failure', 'InnerError', 'PaFxError', 'ErrorPadata', 'ErrorResponse', 'ReplyNonce']) local('kdc-reject', suffix, as, [as, client]);
        for (const suffix of ['EncRep', 'FastResponse']) bytes('kdc-reject', suffix, as);
        for (const suffix of ['ErrorMethodData', 'OuterError']) local('kdc-reject', suffix, as, [as, client]);
        transfer('error-result', ['OuterError', 'ErrorMethodData', 'FastResponse', 'EncRep'], as, client, ['FastResponse', 'EncRep']);
        for (const suffix of ['ErrorResponse', 'ReplyNonce', 'ErrorPadata', 'PaFxError', 'InnerError']) hold('decode-error', suffix, client, {readers: [client, as]});
        hold('decode-error', 'Failure', client, {store: 'knowledge', retention: 'retained', readers: [client, as]});
        verify('decode-error', 'EncRep', client, 'Protected error and nonce verified before learning inner failure');
        return a.finish();
      }
    }
    // Successful KDC processing can still be followed by a rejected client reply.
    object('OriginalReplyKey', kdc, [client, kdc]);
    verify('protect-response', fastTgs ? 'Subkey' : 'LongTermKey', kdc, fastTgs ? 'The same fresh TGS subkey is both armor input and original reply-key input' : 'The original AS reply key aliases Alice account key; it is not the issued ticket session key');
    bytes('protect-response', 'IssuedTicket', kdc);
    local('protect-response', 'IssuedSessionKey', kdc, [kdc, client]);
    for (const suffix of ['ReplyNonce', 'Finished', 'TicketChecksum']) local('protect-response', suffix, kdc, [kdc, client]);
    if (!id.endsWith('-missing-strengthen')) local('protect-response', 'Strengthen', kdc, [kdc, client]);
    if (!fastTgs) for (const suffix of ['KdcChallengeKey', 'KdcChallenge']) local('protect-response', suffix, kdc, [kdc, client]);
    if (!id.endsWith('-missing-strengthen')) local('protect-response', 'FinalReplyKey', kdc, [kdc, client]);
    for (const suffix of ['EncRep', 'FastResponse', 'ReplyEncPart']) bytes('protect-response', suffix, kdc);
    const rejected = !a.event('accept-ticket');
    transfer('fast-response', ['IssuedTicket', 'ReplyEncPart', ...(id.endsWith('-missing-response') ? [] : ['FastResponse', 'EncRep'])], kdc, client, ['IssuedTicket', 'ReplyEncPart', 'FastResponse', 'EncRep'], rejected ? {toStore: 'rejected response', retained: true} : {});
    if (a.event('decode-response')) {
      for (const suffix of ['ReplyNonce', 'Finished', 'TicketChecksum', ...(!id.endsWith('-missing-strengthen') ? ['Strengthen'] : []), ...(!fastTgs ? ['KdcChallengeKey', 'KdcChallenge'] : [])]) hold('decode-response', suffix, client, {readers: [client, kdc]});
      verify('decode-response', 'EncRep', client, rejected ? 'Decoded protected response fails selected nonce, ticket binding or strengthener check' : 'Protected nonce, finished ticket binding and factor checks accepted');
    }
    if (a.event('strengthen-local')) {
      hold('strengthen-local', 'FinalReplyKey', client, {readers: [client, kdc]});
      cache('accept-ticket', 'IssuedTicket', 'IssuedSessionKey', client, fastTgs ? 'credentials.service' : 'credentials.userTgt');
    }
    const rejectEvent = ['reply-policy-denied', 'response-reject'].find(key => a.event(key));
    if (rejectEvent) local(rejectEvent, 'Failure', client, [client], 'knowledge', 'retained');
    return a.finish();
  }

  // Continue the explicit PKINIT path. A signed result and public certificate
  // have different stores and retention policies.
  transfer('as-request', ['Body', 'SignedAuthPack', 'UserCertificate'], client, as);
  for (const suffix of ['AuthPack', 'Ctime', 'Cusec', 'PkNonce', 'Checksum', 'ClientPublic']) hold('request-check', suffix, as, {readers: [client, card, as]});
  verify('request-check', 'SignedAuthPack', as, 'Signature and request checksum checked separately from certificate trust and account mapping');
  if (a.event('kdc-reject')) {
    local('kdc-reject', 'Rejection', as, [as, client]); send('reject-result', 'Rejection', as, client, {toStore: 'knowledge', retained: true});
    return a.finish();
  }
  local('kdc-dh', 'KdcDhPrivate', as, [as]);
  for (const suffix of ['KdcPublic', 'DhReplyNonce', 'SharedSecret', 'ReplyKey', 'TgtSessionKey', 'AsReplyNonce', 'SignedDh']) local('kdc-dh', suffix, as, suffix === 'TgtSessionKey' && args.actors.cryptoTgs ? [as, client, tgs] : [as, client]);
  bytes('kdc-dh', 'Tgt', as); bytes('kdc-dh', 'AsEncPart', as);
  const reject = id.endsWith('kdc-trust');
  send('as-response', 'SignedDh', as, client, reject ? {toStore: 'rejected response', retained: true} : {});
  send('as-response', 'KdcCertificate', as, client, {fromStore: 'configuration', ...(reject ? {toStore: 'rejected response', retained: true} : {})});
  transfer('as-response', ['Tgt', 'AsEncPart'], as, client, ['Tgt', 'AsEncPart'], reject ? {toStore: 'rejected response', retained: true} : {});
  verify('kdc-reply-check', 'SignedDh', client, reject ? 'KDC certificate trust rejected; no client derivation or accepted cache' : 'KDC signature, trust, DH parameters and PKAuthenticator nonce verified');
  if (reject) { local('client-reject', 'Rejection', client, [client], 'knowledge', 'retained'); return a.finish(); }
  for (const suffix of ['KdcPublic', 'DhReplyNonce']) hold('kdc-reply-check', suffix, client, {readers: [as, client]});
  for (const suffix of ['SharedSecret', 'ReplyKey']) hold('client-key', suffix, client, {readers: [as, client]});
  hold('accept-tgt', 'AsReplyNonce', client, {readers: [as, client]});
  cache('accept-tgt', 'Tgt', 'TgtSessionKey', client, 'credentials.userTgt');
  local('tgs-build', 'Spn', client, [client, tgs]); local('tgs-build', 'TgsSubkey', client, [client, tgs]); bytes('tgs-build', 'TgsAuth', client);
  transfer('tgs-request', ['Spn', 'TgsAuth'], client, tgs, ['TgsAuth']);
  send('tgs-request', 'Tgt', client, tgs, {protectedBytes: true, fromStore: 'credential cache'});
  hold('tgs-issue', 'TgtSessionKey', tgs, {readers: [as, client, tgs]}); hold('tgs-issue', 'TgsSubkey', tgs, {readers: [client, tgs]});
  bytes('tgs-issue', 'ServiceTicket', tgs); local('tgs-issue', 'ServiceKey', tgs, [client, tgs, service]); bytes('tgs-issue', 'TgsReply', tgs);
  transfer('tgs-response', ['ServiceTicket', 'TgsReply'], tgs, client, ['ServiceTicket', 'TgsReply']);
  cache('service-cache', 'ServiceTicket', 'ServiceKey', client, 'credentials.service');
  bytes('service-proof', 'ServiceAuth', client);
  send('ap-request', 'ServiceTicket', client, service, {protectedBytes: true, fromStore: 'credential cache'}); send('ap-request', 'ServiceAuth', client, service, {protectedBytes: true});
  hold('service-check', 'ServiceKey', service, {readers: [client, tgs, service]}); bytes('service-check', 'ApReply', service);
  const session = id + ':authenticated-service-context';
  a.declare(session, 'Authenticated service context', service, [plain([service], [field('kerberosAuthenticatedContext', 'principal', model.initialState.credentials?.userTgt?.principal || 'alice@' + lookup('Realm').value, [service])])]);
  a.create('service-check', session); a.acquire('service-check', session, service, 'authenticated context', 'plain', 'retained');
  a.plan.bindings.push({path: 'sessions.service', actorId: service, artifactId: session, presentWhen: 'truthy'});
  const replay = id + ':service-replay-record';
  a.declare(replay, 'Service authenticator replay record', service, [plain([service], [field('kerberosReplayRecord', 'authenticatorId', lookup('ServiceAuth').artifactId, [service])])]);
  a.create('service-check', replay); a.acquire('service-check', replay, service, 'replay cache', 'plain', 'retained');
  send('ap-response', 'ApReply', service, client, {protectedBytes: true});
  verify('ap-response', 'ApReply', client, 'Mutual authentication time binding accepted');
  return a.finish();
}

function buildForest(args) {
  const a = author(args), {model, steps} = args, id = model.id, state = model.initialState;
  const actorForRealm = realm => Object.entries(args.actors).find(([actorId, actor]) => actorId.endsWith('Tgs') && actor.context?.some(entry => entry.key === 'realm' && entry.value === realm))?.[0]
    // The two three-forest fixtures explicitly declare this otherwise inactive
    // B KDC without a runtime realm control. Its authored realm is not inferred
    // from its name, prose, a suffix heuristic or historical holders.
    || (realm === 'B.EXAMPLE' && args.actors.kdcMiddleTgs ? 'kdcMiddleTgs' : undefined);
  const exactField = (event, attributeId, instanceId) => {
    const step = steps.find(entry => entry.id === id + '-' + event);
    const occurrence = step?.attributeOperations.find(entry => entry.attributeId === attributeId && (!instanceId || entry.instanceId === instanceId));
    if (!occurrence) throw new Error('Missing authored forest field: ' + id + ' ' + event + ' ' + attributeId);
    return occurrence;
  };
  const configuration = (name, holders, value, artifactId = id + ':configured:' + name) => {
    a.declare(artifactId, name, holders[0], [plain(holders, [field('forestConfiguredMaterial', name, value, holders)])], {type: 'configured-key-or-policy'});
    a.create(null, artifactId); for (const actor of holders) a.acquire(null, artifactId, actor, 'configuration', 'plain', 'retained');
    return artifactId;
  };
  const kdcs = Object.keys(args.actors).filter(actor => actor.endsWith('Tgs'));
  for (const actor of kdcs) configuration(actor + ' krbtgt key', [actor], '<protected local krbtgt key>');
  for (const [index, hop] of state.policies.referralHops.entries()) {
    const from = actorForRealm(hop.fromDomain.toUpperCase()), to = actorForRealm(hop.toDomain.toUpperCase());
    if (hop.configuredTrust && from && to) configuration('TDO-key-' + hop.fromDomain.toUpperCase() + '-to-' + hop.toDomain.toUpperCase(), [from, to], '<matching configured inter-realm counterpart key; no transfer>', id + '-trust-key-' + (index + 1));
  }
  // Configured relationships outside the selected route are still local trust
  // state. They never authorize an unconfigured transitive A-to-C referral.
  for (const trust of state.policies.trusts) {
    const inRoute = state.policies.referralHops.some(hop => hop.configuredTrust && hop.fromDomain === trust.account && hop.toDomain === trust.resource);
    const holders = [actorForRealm(trust.account.toUpperCase()), actorForRealm(trust.resource.toUpperCase())].filter(Boolean);
    if (!inRoute && holders.length) configuration('TDO-key-' + trust.account.toUpperCase() + '-to-' + trust.resource.toUpperCase(), holders, {account: trust.account, resource: trust.resource, type: trust.type, enabled: trust.enabled, key: '<configured inter-realm counterpart key>'});
  }
  const resource = actorForRealm((state.policies.suffixRouting instanceof Array ? state.policies.suffixRouting.at(-1) : '').toUpperCase()) || 'kdcResourceTgs';
  const serviceOccurrence = steps.find(step => step.id === id + '-issue-service')?.attributeOperations.find(o => o.attributeId === 'forestServiceKey') || steps.find(step => step.id === id + '-accept')?.attributeOperations.find(o => o.attributeId === 'forestServiceKey');
  configuration('target service-account key', [resource, 'service'].filter(actor => args.actors[actor]), serviceOccurrence?.value || '<configured target service-account key>', id + '-service-key');
  for (const actor of kdcs) configuration(actor + ' trust and routing policy', [actor], state.policies);
  configuration('resource ACL', ['service'], {allowed: state.policies.aclAllows});
  const credentials = new Map(Object.values(state.credentials).map(c => [c.id, c]));
  // Bind only explicit structured credential state values, never issuance prose.
  for (const step of steps) for (const effect of step.protocolEffects || []) if (effect.op === 'put' && /^credentials\./.test(effect.path) && effect.value?.sessionKeyId) credentials.set(effect.value.id, effect.value);
  const defineCredential = c => {
    const issuer = actorForRealm(c.issuerRealm) || 'kdcHomeTgs';
    const recipient = c.kind === 'service' ? 'service' : actorForRealm(c.targetRealm);
    const readers = [...new Set([issuer, recipient].filter(Boolean))];
    a.declare(c.id, c.kind + ' ticket: ' + c.sname, issuer, [
      {representationId: 'opaque', format: 'Ticket outer fields and encrypted enc-part', readableBy: ['workstation', ...readers], fields: [field('forestRealm', 'Ticket.realm', c.ticketRealm), field('forestSname', 'Ticket.sname', c.sname), field('forestTicketCipher', 'Ticket.enc-part', c.ticketBytes)]},
      plain(readers, [field('forestCname', 'EncTicketPart.cname', c.cname, readers), field('forestCrealm', 'EncTicketPart.crealm', c.crealm, readers), field('forestPac', 'EncTicketPart.authorization-data.AD-WIN2K-PAC', c.pac, readers)]),
    ], {type: 'kerberos-ticket', expiresAt: c.expiresAt});
    a.declare(c.sessionKeyId, c.kind + ' session key: ' + c.sname, issuer, [plain(['workstation', ...readers], [field('forestSessionKey', 'credential.sessionKey', c.sessionKeyId, ['workstation', ...readers])])], {type: 'session-key', related: [c.id]});
    return {issuer, recipient};
  };
  const accept = (event, c, path, initial = false) => {
    defineCredential(c);
    if (initial) { a.create(null, c.id); a.create(null, c.sessionKeyId); }
    if (initial) a.acquire(event, c.id, 'workstation', 'credential cache', 'opaque', 'retained');
    else a.promote(event, c.id, 'workstation', 'opaque');
    a.acquire(event, c.sessionKeyId, 'workstation', 'credential cache', 'plain', 'retained');
    if (!initial) a.observe(event, c.id, 'workstation', 'Protected reply, nonce, target and lifetime accepted', 'acceptance');
    a.plan.bindings.push({path, actorId: 'workstation', artifactId: c.id, representationId: 'opaque', store: 'credential cache', presentWhen: 'truthy'});
    a.plan.bindings.push({path, actorId: 'workstation', artifactId: c.sessionKeyId, representationId: 'plain', store: 'credential cache', presentWhen: 'truthy'});
  };
  for (const [name, c] of Object.entries(state.credentials)) accept(null, c, 'credentials.' + name, true);
  const home = state.credentials.home;
  const request = (key, receiver, c) => {
    const event = 'prepare-' + key, request = exactField(event, 'forestTgsReq'), auth = exactField(event, 'forestAuthenticator');
    a.declare(request.instanceId, 'TGS request: ' + key, 'workstation', [plain(['workstation', receiver], [field('forestTgsReq', 'KDC-REQ-BODY', request.value)])]);
    a.declare(auth.instanceId, 'Fresh protected authenticator: ' + key, 'workstation', [opaque([field('forestAuthenticator', 'AP-REQ.authenticator', auth.instanceId + '-encrypted-bytes', [])]), plain(['workstation', receiver], [field('forestAuthenticator', 'Authenticator', auth.value, ['workstation', receiver])])], {related: [c.id, c.sessionKeyId]});
    for (const artifactId of [request.instanceId, auth.instanceId]) { a.create(event, artifactId); a.acquire(event, artifactId, 'workstation', 'working memory', artifactId === auth.instanceId ? 'opaque' : 'plain'); }
    a.acquire(event, auth.instanceId, 'workstation', 'working memory', 'plain');
    a.wire('request-' + key, request.instanceId, 'workstation', receiver);
    a.wire('request-' + key, auth.instanceId, 'workstation', receiver, 'opaque');
    a.wire('request-' + key, c.id, 'workstation', receiver, 'opaque', {fromStore: 'credential cache'});
    for (const artifactId of [c.id, c.sessionKeyId, auth.instanceId]) a.acquire('validate-' + key, artifactId, receiver, 'working memory', 'plain');
    a.observe('validate-' + key, c.id, receiver, 'Incoming credential decrypted; original principal and fresh request binding verified');
    // An acceptor replay record contains the request identity, not its secret key.
    const replay = id + ':replay:' + key;
    a.declare(replay, 'Replay record: ' + key, receiver, [plain([receiver], [field('forestAuthenticator', 'authenticatorId', auth.instanceId, [receiver])])]);
    a.create('validate-' + key, replay); a.acquire('validate-' + key, replay, receiver, 'replay cache', 'plain', 'retained');
  };
  if (a.event('prepare-blocked')) request('blocked', 'kdcHomeTgs', home);
  let held = home;
  const referrals = [...credentials.values()].filter(c => c.kind === 'referral');
  for (let index = 0; index < referrals.length; index++) {
    const c = referrals[index], n = index + 1, key = 'referral-' + n, {issuer} = defineCredential(c);
    if (!state.credentials['referral' + n]) {
      request(key, issuer, held);
      a.create('issue-' + key, c.id); a.create('issue-' + key, c.sessionKeyId);
      a.acquire('issue-' + key, c.id, issuer, 'working memory', 'opaque'); a.acquire('issue-' + key, c.id, issuer, 'working memory', 'plain');
      a.acquire('issue-' + key, c.sessionKeyId, issuer, 'working memory', 'plain');
      const envelope = c.id + ':client-reply';
      a.declare(envelope, 'Protected referral client reply', issuer, [opaque([field('forestTgsRep', 'EncTGSRepPart', '<encrypted session key and nonce>', [])])], {related: [c.sessionKeyId, held.sessionKeyId]});
      a.create('issue-' + key, envelope); a.acquire('issue-' + key, envelope, issuer, 'working memory', 'opaque');
      a.wire('return-' + key, c.id, issuer, 'workstation', 'opaque'); a.wire('return-' + key, envelope, issuer, 'workstation', 'opaque');
      accept('cache-' + key, c, 'credentials.referral' + n);
    }
    held = c;
  }
  const serviceCredential = [...credentials.values()].find(c => c.kind === 'service');
  if (a.event('prepare-service')) request('service', resource, held);
  if (serviceCredential && !state.credentials.service) {
    const c = serviceCredential, {issuer} = defineCredential(c);
    a.create('issue-service', c.id); a.create('issue-service', c.sessionKeyId);
    a.acquire('issue-service', c.id, issuer, 'working memory', 'opaque'); a.acquire('issue-service', c.id, issuer, 'working memory', 'plain');
    a.acquire('issue-service', c.sessionKeyId, issuer);
    const envelope = c.id + ':client-reply';
    a.declare(envelope, 'Protected service client reply', issuer, [opaque([field('forestTgsRep', 'EncTGSRepPart', '<encrypted service session key and request nonce>', [])])], {related: [c.sessionKeyId, held.sessionKeyId]});
    a.create('issue-service', envelope); a.acquire('issue-service', envelope, issuer, 'working memory', 'opaque');
    a.wire('return-service', c.id, issuer, 'workstation', 'opaque'); a.wire('return-service', envelope, issuer, 'workstation', 'opaque');
    accept('cache-service', c, 'credentials.service');
  }
  for (const key of ['trust', 'pac', 'selective']) if (a.event('reject-' + key)) {
    const rejection = exactField('reject-' + key, 'forestError'), actor = steps.find(s => s.id === id + '-reject-' + key).from;
    a.declare(rejection.instanceId, 'Acquisition rejection', actor, [plain([actor, 'workstation'], [field('forestError', 'result', rejection.value)])]);
    a.create('reject-' + key, rejection.instanceId); a.acquire('reject-' + key, rejection.instanceId, actor);
    a.wire('error-' + key, rejection.instanceId, actor, 'workstation', 'plain', {toStore: 'knowledge', retained: true});
    a.observe('error-' + key, rejection.instanceId, 'workstation', 'Client learns acquisition denial; existing cache remains', 'knowledge');
  }
  if (serviceCredential && a.event('prepare-ap')) {
    const c = serviceCredential, auth = exactField('prepare-ap', 'forestAuthenticator');
    a.declare(auth.instanceId, 'Fresh application authenticator', 'workstation', [opaque([field('forestAuthenticator', 'AP-REQ.authenticator', auth.instanceId + '-encrypted-bytes', [])]), plain(['workstation', 'service'], [field('forestAuthenticator', 'Authenticator', auth.value, ['workstation', 'service'])])], {related: [c.id, c.sessionKeyId]});
    a.create('prepare-ap', auth.instanceId); a.acquire('prepare-ap', auth.instanceId, 'workstation', 'working memory', 'opaque'); a.acquire('prepare-ap', auth.instanceId, 'workstation');
    a.wire('ap-request', c.id, 'workstation', 'service', 'opaque', {fromStore: 'credential cache'}); a.wire('ap-request', auth.instanceId, 'workstation', 'service', 'opaque');
    for (const artifactId of [c.id, c.sessionKeyId, auth.instanceId]) a.acquire('accept', artifactId, 'service');
    a.observe('accept', c.id, 'service', 'Ticket and fresh proof authenticated; ACL is a separate decision');
    const context = exactField('accept', 'forestContext');
    a.declare(context.instanceId, 'Authenticated original-principal context', 'service', [plain(['service'], [field('forestContext', 'principal', context.value, ['service'])])], {related: [c.id]});
    a.create('accept', context.instanceId); a.acquire('accept', context.instanceId, 'service', 'authenticated context', 'plain', 'retained');
    a.plan.bindings.push({path: 'sessions.service', actorId: 'service', artifactId: context.instanceId, presentWhen: 'truthy'});
    const replay = id + ':replay:application';
    a.declare(replay, 'Application replay record', 'service', [plain(['service'], [field('forestAuthenticator', 'authenticatorId', auth.instanceId, ['service'])])]); a.create('accept', replay); a.acquire('accept', replay, 'service', 'replay cache', 'plain', 'retained');
    const reply = exactField('ap-reply', 'forestApRep');
    a.declare(reply.instanceId, 'Protected mutual authentication reply', 'service', [opaque([field('forestApRep', 'AP-REP', '<protected mutual authentication bytes>', [])])], {related: [c.sessionKeyId]});
    a.create('ap-reply', reply.instanceId); a.acquire('ap-reply', reply.instanceId, 'service', 'working memory', 'opaque'); a.wire('ap-reply', reply.instanceId, 'service', 'workstation', 'opaque');
    a.observe('ap-reply', reply.instanceId, 'workstation', 'Mutual authentication verified');
    a.observe('acl', context.instanceId, 'service', state.policies.aclAllows ? 'Requested resource action allowed' : 'Requested resource action denied; authentication and client credentials remain', 'acceptance');
  }
  return a.finish();
}
