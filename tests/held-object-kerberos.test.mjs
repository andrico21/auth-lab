import test from 'node:test';
import assert from 'node:assert/strict';
import {CRYPTOLAB_SCENARIOS} from '../src/kerberos-crypto-lab.js';
import {FORESTLAB_SCENARIOS} from '../src/kerberos-forest-lab.js';
import {buildKerberosHeldObjects} from '../src/held-object-kerberos.js';
import {compileHeldObjects, projectHeldObjects, inspectHeldObject, heldObjectTrace, assertHeldObjectCoverage} from '../src/held-object-state.js';

const models = [...CRYPTOLAB_SCENARIOS, ...FORESTLAB_SCENARIOS];
const fixture = (id, context) => {
  const source = models.find(model => model.id === id);
  const model = context ? source.contextualize(context) : source;
  const steps = model.steps(), actors = model.actors();
  const plan = buildKerberosHeldObjects({model, steps, actors, config: context || {}, contextId: id + ':' + JSON.stringify(context || {}), choiceId: id});
  const compiled = compileHeldObjects(plan, {model, steps});
  const index = key => steps.findIndex(step => step.id === id + '-' + key);
  const at = (key, milestone = 'complete') => projectHeldObjects(compiled, key === 'initial-state' ? {eventIndex: -1, milestone: 'initial'} : {eventIndex: index(key), milestone});
  return {model, steps, actors, plan, compiled, index, at, end: () => projectHeldObjects(compiled, {eventIndex: steps.length - 1, milestone: 'complete'})};
};
const held = (snapshot, artifactId, actorId, store) => snapshot.holdings.filter(h => h.artifactId === artifactId && h.actorId === actorId && (store === undefined || h.store === store));
const cryptoId = (model, name) => {
  const attributeId = Object.entries(model.definitions()).find(([, definition]) => definition.name === name)?.[0];
  return model.steps().flatMap(step => step.attributeOperations).find(operation => operation.attributeId === attributeId)?.instanceId;
};
const fieldValues = (snapshot, actorId) => snapshot.holdings.filter(h => h.actorId === actorId).flatMap(h => inspectHeldObject(snapshot, h.holdingId).fields.filter(f => f.readable).map(f => f.value));

test('all 17 crypto and 14 forest choices have complete explicit logical-owner coverage at every cursor', () => {
  assert.equal(CRYPTOLAB_SCENARIOS.length, 17);
  assert.equal(FORESTLAB_SCENARIOS.length, 14);
  for (const model of models) {
    const f = fixture(model.id);
    assert.equal(assertHeldObjectCoverage(f.compiled), true, model.id);
    for (let eventIndex = -1; eventIndex < f.steps.length; eventIndex++) {
      const cursor = {eventIndex, milestone: eventIndex < 0 ? 'initial' : 'complete'};
      const snapshot = projectHeldObjects(f.compiled, cursor);
      assert.equal(snapshot.coverageStatus, 'complete', model.id);
      assert.deepEqual(new Set(snapshot.coverage.map(c => c.actorId)), new Set(Object.keys(f.actors)));
      assert.equal(new Set(snapshot.holdings.map(h => h.holdingId)).size, snapshot.holdings.length);
      assert.ok(Object.isFrozen(snapshot));
      assert.deepEqual(projectHeldObjects(f.compiled, cursor), snapshot);
      for (const h of snapshot.holdings) assert.ok(snapshot.artifacts.some(a => a.artifactId === h.artifactId));
    }
    assert.ok(f.end().holdings.every(h => h.retention === 'retained'), model.id + ' explicitly discards terminal scratch material');
  }
});

test('cold PKINIT keeps provisioned signing and trust material but no future ticket or ephemeral exponent', () => {
  const f = fixture('lab-ad-pkinit-success'), initial = f.at('initial-state');
  const signing = cryptoId(f.model, 'Private signing key (local)');
  assert.equal(held(initial, signing, 'cryptoCard', 'configuration').length, 1);
  assert.equal(initial.holdings.some(h => h.store === 'credential cache'), false);
  for (const name of ['Client DH private value (local)', 'KDC DH private value (local)', 'ticket (TGT)', 'key (EncASRepPart)']) assert.equal(initial.artifacts.some(a => a.artifactId === cryptoId(f.model, name)), false);
  assert.ok(initial.holdings.some(h => h.actorId === 'cryptoAs' && h.store === 'configuration'));
  assert.equal(f.end().holdings.some(h => h.artifactId === signing && h.actorId !== 'cryptoCard'), false);
});

test('PKINIT fresh DH values stay at their local endpoints and client derivation follows KDC trust checks', () => {
  const f = fixture('lab-ad-pkinit-success');
  const a = cryptoId(f.model, 'Client DH private value (local)'), b = cryptoId(f.model, 'KDC DH private value (local)');
  const reply = cryptoId(f.model, 'AS reply key (local)'), session = cryptoId(f.model, 'key (EncASRepPart)');
  const signed = cryptoId(f.model, 'PA-PK-AS-REP.dhInfo.dhSignedData');
  assert.notEqual(a, b); assert.notEqual(reply, session);
  assert.equal(held(f.at('authpack'), a, 'cryptoClient').length, 1);
  assert.equal(held(f.at('as-request'), a, 'cryptoAs').length, 0);
  assert.equal(held(f.at('kdc-dh'), b, 'cryptoAs').length, 1);
  assert.equal(held(f.at('as-response'), b, 'cryptoClient').length, 0);
  assert.equal(held(f.at('as-response'), reply, 'cryptoClient').length, 0);
  assert.equal(held(f.at('kdc-reply-check'), reply, 'cryptoClient').length, 0);
  assert.equal(held(f.at('client-key'), reply, 'cryptoClient').length, 1);
  assert.ok(f.at('kdc-reply-check').observations.some(o => o.artifactId === signed && o.actorId === 'cryptoClient'));
  const forbidden = new Set([a, b, reply, session]);
  for (const event of Object.values(f.plan.events)) for (const message of event.messages || []) for (const object of message.objects) assert.equal(forbidden.has(object.artifactId), false);
});

test('AS ciphertext delivery is atomic and distinct from accepted TGT plus independent session key', () => {
  const f = fixture('lab-ad-pkinit-success');
  const ticket = cryptoId(f.model, 'ticket (TGT)'), key = cryptoId(f.model, 'key (EncASRepPart)');
  const delivery = f.index('as-response');
  const before = projectHeldObjects(f.compiled, {eventIndex: delivery, progress: 0.8});
  assert.equal(held(before, ticket, 'cryptoClient').length, 0);
  assert.equal(before.inFlight.length, 1);
  const arrived = f.at('as-response');
  assert.equal(held(arrived, ticket, 'cryptoClient', 'received bytes').length, 1);
  assert.equal(held(arrived, ticket, 'cryptoClient', 'credential cache').length, 0);
  assert.equal(held(arrived, key, 'cryptoClient').length, 0);
  assert.equal(arrived.state.credentials.userTgt, undefined);
  const holding = held(arrived, ticket, 'cryptoClient')[0];
  assert.ok(inspectHeldObject(arrived, holding.holdingId).fields.every(field => !field.readable));
  const accepted = f.at('accept-tgt');
  assert.equal(held(accepted, ticket, 'cryptoClient', 'credential cache').length, 1);
  assert.equal(held(accepted, key, 'cryptoClient', 'credential cache').length, 1);
  assert.equal(held(accepted, ticket, 'cryptoClient')[0].holdingId, holding.holdingId, 'promotion preserves exact holding selection');
  assert.equal(held(accepted, ticket, 'cryptoClient')[0].retention, 'retained');
  assert.equal(accepted.state.credentials.userTgt.instanceId, ticket);
  assert.equal(held(f.at('tgs-request'), ticket, 'cryptoClient', 'credential cache').length, 1, 'presentation copies a retained sender');
});

test('early certificate failures issue no ticket; untrusted KDC reply retains rejected protected evidence without client keys/cache', () => {
  for (const variant of ['binding', 'trust']) {
    const f = fixture('lab-ad-pkinit-' + variant);
    assert.equal(f.end().artifacts.some(a => a.artifactId.endsWith(':user-tgt:1')), false);
    assert.equal(f.end().state.credentials.userTgt, undefined);
  }
  const f = fixture('lab-ad-pkinit-kdc-trust');
  const ticket = cryptoId(f.model, 'ticket (TGT)'), reply = cryptoId(f.model, 'AS reply key (local)');
  assert.equal(held(f.at('as-response'), ticket, 'cryptoClient', 'rejected response').length, 1);
  assert.equal(held(f.end(), ticket, 'cryptoClient', 'rejected response').length, 1);
  assert.equal(held(f.end(), ticket, 'cryptoClient', 'credential cache').length, 0);
  assert.equal(held(f.end(), reply, 'cryptoClient').length, 0);
  assert.equal(f.end().state.keys.asReplyClient, undefined);
});

test('FAST computer bootstrap, independent computer armor and preexisting user TGT are different initial inventories', () => {
  const boot = fixture('lab-ad-fast-as-bootstrap');
  assert.equal(boot.at('initial-state').holdings.some(h => h.store === 'credential cache'), false);
  const machineTicket = cryptoId(boot.model, 'ticket (armor TGT)');
  assert.equal(held(boot.at('bootstrap-response'), machineTicket, 'cryptoComputer', 'received bytes').length, 1);
  assert.equal(held(boot.at('bootstrap-response'), machineTicket, 'cryptoComputer', 'credential cache').length, 0);
  assert.equal(held(boot.end(), machineTicket, 'cryptoComputer', 'credential cache').length, 1);
  assert.equal(boot.end().state.credentials.userTgt, undefined);
  const as = fixture('lab-ad-fast-as-success'), tgs = fixture('lab-ad-fast-tgs-success');
  assert.equal(as.at('initial-state').holdings.filter(h => h.store === 'credential cache' && h.actorId === 'cryptoComputer').length, 2);
  assert.equal(as.at('initial-state').holdings.filter(h => h.store === 'credential cache' && h.actorId === 'cryptoClient').length, 0);
  assert.equal(tgs.at('initial-state').holdings.filter(h => h.store === 'credential cache' && h.actorId === 'cryptoClient').length, 2);
  assert.equal(tgs.at('initial-state').holdings.some(h => h.actorId === 'cryptoComputer'), false);
  for (const variant of ['required-armor', 'unsupported-dc', 'optional-fallback']) {
    const f = fixture('lab-ad-fast-as-' + variant);
    assert.equal(f.at('initial-state').holdings.filter(h => h.actorId === 'cryptoComputer' && h.store === 'credential cache').length, 2);
    assert.equal(f.end().state.credentials.userTgt, undefined);
  }
});

test('FAST local IPC hands Alice only opaque armor proof and derived armor key, not the computer session key', () => {
  const f = fixture('lab-ad-fast-as-success');
  const machineKey = cryptoId(f.model, 'ticket_session_key (local armor input)'), armor = cryptoId(f.model, 'armor_key (local)');
  const issued = cryptoId(f.model, 'key (EncASRepPart)'), final = cryptoId(f.model, 'reply-key (FAST strengthened, local)');
  assert.equal(new Set([machineKey, armor, issued, final]).size, 4);
  assert.equal(held(f.at('armor-local-api'), armor, 'cryptoClient').length > 0, true);
  assert.equal(held(f.at('armor-local-api'), machineKey, 'cryptoClient').length, 0);
  for (let eventIndex = -1; eventIndex < f.steps.length; eventIndex++) {
    const snapshot = projectHeldObjects(f.compiled, {eventIndex, milestone: eventIndex < 0 ? 'initial' : 'complete'});
    assert.equal(held(snapshot, machineKey, 'cryptoClient').length, 0);
  }
  const initialMachine = held(f.at('initial-state'), machineKey, 'cryptoComputer', 'credential cache')[0];
  assert.equal(held(f.end(), machineKey, 'cryptoComputer', 'credential cache')[0].holdingId, initialMachine.holdingId);
  assert.equal(held(f.at('fast-response'), issued, 'cryptoClient').length, 0);
  assert.equal(held(f.at('decode-response'), final, 'cryptoClient').length, 0);
  assert.equal(held(f.at('strengthen-local'), final, 'cryptoClient').length, 1);
  assert.equal(held(f.end(), issued, 'cryptoClient', 'credential cache').length, 1);
  const forbidden = new Set([machineKey, armor, issued, final]);
  for (const step of f.steps) if (step.channel !== 'local-ipc') for (const message of f.plan.events[step.id]?.messages || []) for (const object of message.objects) assert.equal(forbidden.has(object.artifactId), false);
});

test('FAST failures retain received protected bytes but never install returned ticket/session keys or client final reply keys', () => {
  for (const variant of ['missing-response', 'response-nonce', 'ticket-binding']) {
    const f = fixture('lab-ad-fast-as-' + variant), ticket = cryptoId(f.model, 'ticket (user TGT)');
    assert.equal(held(f.at('fast-response'), ticket, 'cryptoClient', 'rejected response').length, 1);
    assert.equal(held(f.end(), ticket, 'cryptoClient', 'rejected response').length, 1);
    assert.equal(f.end().state.credentials.userTgt, undefined);
    assert.equal(f.end().state.keys.finalReplyClient, undefined);
    assert.equal(f.end().holdings.some(h => h.actorId === 'cryptoClient' && h.store === 'credential cache'), false);
    assert.ok(f.end().holdings.some(h => h.actorId === 'cryptoClient' && h.artifactId.endsWith(':user-long-term-key:1')));
  }
  const missing = fixture('lab-ad-fast-tgs-missing-subkey');
  assert.equal(Object.values(missing.plan.events).some(event => event.messages?.length), false);
  assert.equal(missing.end().state.credentials.service, undefined);
  assert.equal(missing.end().holdings.filter(h => h.store === 'credential cache' && h.actorId === 'cryptoClient').length, 2);
  const strength = fixture('lab-ad-fast-tgs-missing-strengthen');
  assert.ok(strength.end().holdings.some(h => h.store === 'rejected response'));
  assert.equal(strength.end().state.credentials.service, undefined);
});

test('FAST protected error transport does not expose inner failure knowledge before authenticated decode', () => {
  for (const variant of ['checksum', 'challenge']) {
    const f = fixture('lab-ad-fast-as-' + variant);
    const inner = cryptoId(f.model, 'KRB-ERROR (inside PA-FX-ERROR)');
    assert.equal(held(f.at('error-result'), inner, 'cryptoClient').length, 0);
    assert.equal(f.at('error-result').state.knowledge.client.failure, undefined);
    assert.equal(f.end().state.checks.protectedErrorDecoded, true);
    assert.equal(f.end().state.credentials.userTgt, undefined);
    assert.ok(f.end().holdings.some(h => h.actorId === 'cryptoClient' && h.store === 'knowledge'));
    assert.equal(f.end().artifacts.some(a => a.artifactId.endsWith(':issued-ticket:1')), false);
  }
});

test('multi-forest referral realm, next krbtgt and session-key identities are exact and delivered before accepted caching', () => {
  const f = fixture('lab-ad-forest-child-domains');
  const expected = [['EU.A.EXAMPLE', 'krbtgt/A.EXAMPLE'], ['A.EXAMPLE', 'krbtgt/B.EXAMPLE'], ['B.EXAMPLE', 'krbtgt/US.B.EXAMPLE']];
  for (let n = 1; n <= 3; n++) {
    const id = f.model.id + '-referral-' + n, key = id + '-session-key';
    assert.equal(held(f.at('return-referral-' + n), id, 'workstation', 'credential cache').length, 0);
    assert.equal(held(f.at('return-referral-' + n), id, 'workstation', 'received bytes').length, 1);
    assert.equal(held(f.at('return-referral-' + n), key, 'workstation').length, 0);
    const accepted = f.at('cache-referral-' + n), h = held(accepted, id, 'workstation', 'credential cache')[0];
    const fields = inspectHeldObject(accepted, h.holdingId).fields.filter(field => field.readable);
    assert.equal(fields.find(field => field.attributeId === 'forestRealm').value, expected[n - 1][0]);
    assert.equal(fields.find(field => field.attributeId === 'forestSname').value, expected[n - 1][1]);
    assert.equal(held(accepted, key, 'workstation', 'credential cache').length, 1);
    assert.equal(accepted.state.credentials['referral' + n].crealm, 'EU.A.EXAMPLE');
  }
  const cache = f.end().holdings.filter(h => h.actorId === 'workstation' && h.store === 'credential cache');
  assert.equal(cache.length, 10);
  assert.equal(new Set(cache.map(h => h.artifactId)).size, 10);
  for (const event of Object.values(f.plan.events)) for (const message of event.messages || []) assert.ok(message.from === 'workstation' || message.to === 'workstation');
  const target = f.model.id + '-service-ticket';
  assert.equal(f.end().state.credentials.service.sname, 'HTTP/files.us.b.example');
  assert.equal(held(f.end(), target, 'service').length, 0, 'acceptor scratch ticket is explicitly released, context remains');
  assert.ok(f.end().holdings.some(h => h.actorId === 'service' && h.store === 'authenticated context'));
});

test('forest trust counterparts are initial logical-KDC holdings, not transferred client secrets or physical-parent copies', () => {
  const f = fixture('lab-ad-forest-child-domains'), initial = f.at('initial-state');
  const pairs = [['kdcHomeTgs', 'kdcRootATgs'], ['kdcRootATgs', 'kdcRootBTgs'], ['kdcRootBTgs', 'kdcResourceTgs']];
  for (let index = 0; index < pairs.length; index++) {
    const id = f.model.id + '-trust-key-' + (index + 1);
    assert.deepEqual(new Set(initial.holdings.filter(h => h.artifactId === id).map(h => h.actorId)), new Set(pairs[index]));
    assert.equal(initial.holdings.some(h => h.artifactId === id && h.actorId === 'workstation'), false);
    for (const event of Object.values(f.plan.events)) for (const message of event.messages || []) assert.equal(message.objects.some(o => o.artifactId === id), false);
  }
  assert.equal(initial.holdings.some(h => ['kdcHome', 'kdcRootA', 'kdcRootB', 'kdcResource'].includes(h.actorId)), false);
});

test('forest opaque client tickets do not disclose protected account/PAC/session-key data at receipt or after caching', () => {
  const f = fixture('lab-ad-forest-sid-filtering');
  for (const eventIndex of [f.index('return-referral-1'), f.index('cache-referral-1'), f.index('return-service'), f.index('cache-service')]) {
    const snapshot = projectHeldObjects(f.compiled, {eventIndex, milestone: 'complete'});
    for (const h of snapshot.holdings.filter(h => h.actorId === 'workstation' && h.representationId === 'opaque')) {
      const fields = inspectHeldObject(snapshot, h.holdingId).fields;
      assert.equal(fields.some(field => field.readable && ['forestPac', 'forestCname', 'forestCrealm', 'forestSessionKey'].includes(field.attributeId)), false);
    }
  }
  assert.equal(fieldValues(f.at('return-service'), 'workstation').some(value => typeof value === 'object' && value?.accountSid), false);
});

test('forest denial preserves real cached credentials while ACL denial preserves accepted authentication', () => {
  for (const [choice, count] of [['three-denied', 2], ['one-way-reverse', 2], ['selective-denied', 4], ['invalid-pac', 4]]) {
    const f = fixture('lab-ad-forest-' + choice), end = f.end();
    assert.equal(end.holdings.filter(h => h.actorId === 'workstation' && h.store === 'credential cache').length, count);
    assert.equal(end.state.credentials.service, undefined);
    assert.equal(end.state.sessions.service, undefined);
    assert.equal(end.holdings.some(h => h.store === 'authenticated context'), false);
    assert.ok(end.holdings.some(h => h.actorId === 'workstation' && h.store === 'knowledge'));
  }
  const denied = fixture('lab-ad-forest-acl-denied');
  assert.equal(denied.end().state.access.resource, 'denied');
  assert.equal(denied.end().state.sessions.service.authenticated, true);
  assert.equal(denied.end().holdings.filter(h => h.actorId === 'workstation' && h.store === 'credential cache').length, 6);
  assert.ok(denied.end().holdings.some(h => h.actorId === 'service' && h.store === 'authenticated context'));
});

test('cached forest credentials begin present, keep exact identities and create no replacement acquisition responses', () => {
  for (const [choice, count] of [['cached-referrals', 4], ['cached-service', 6]]) {
    const f = fixture('lab-ad-forest-' + choice), initial = f.at('initial-state');
    const cache = initial.holdings.filter(h => h.actorId === 'workstation' && h.store === 'credential cache');
    assert.equal(cache.length, count);
    for (const h of cache) assert.equal(f.end().holdings.find(end => end.holdingId === h.holdingId)?.artifactId, h.artifactId);
    assert.equal(f.steps.some(step => step.id.endsWith('-return-referral-1')), false);
    if (choice === 'cached-service') assert.equal(Object.values(f.plan.events).flatMap(event => event.messages || []).some(message => message.from.endsWith('Tgs') || message.to.endsWith('Tgs')), false);
  }
});

test('exact-object focused rows project the same canonical checkpoints on seek, replay and rewind', () => {
  const f = fixture('lab-ad-forest-child-domains'), id = f.model.id + '-referral-2';
  const rows = heldObjectTrace(f.compiled, id);
  assert.ok(rows.length >= 3);
  for (const row of rows) {
    assert.equal(row.artifactId, id);
    const fromTrace = projectHeldObjects(f.compiled, row.heldCursorEnd);
    const canonical = projectHeldObjects(f.compiled, {eventIndex: row.sourceIndex, milestone: 'complete'});
    assert.deepEqual(fromTrace, canonical);
  }
  const accepted = f.at('cache-referral-2');
  f.end(); f.at('initial-state');
  assert.deepEqual(f.at('cache-referral-2'), accepted);
});

test('contextualized crypto models use projected realm and service identity without leaking across revisions', () => {
  const base = fixture('lab-ad-pkinit-success');
  const changed = fixture('lab-ad-pkinit-success', {kerberosRealm: 'CORP.TEST', servicePrincipal: 'HTTP/intranet.corp.test'});
  const end = changed.end(), ticket = cryptoId(changed.model, 'ticket (service ticket)');
  assert.equal(end.state.credentials.userTgt.crealm, 'CORP.TEST');
  assert.equal(end.state.credentials.service.sname, 'HTTP/intranet.corp.test');
  assert.equal(end.state.sessions.service.principal, 'alice@CORP.TEST');
  assert.notEqual(end.contextId, base.end().contextId);
  assert.notEqual(held(end, ticket, 'cryptoClient', 'credential cache')[0].qualifiedArtifactId, held(base.end(), ticket, 'cryptoClient', 'credential cache')[0].qualifiedArtifactId);
  assert.equal(base.end().state.credentials.service.sname, 'HTTP/intranet.a.example');
});

test('FAST original reply-key aliases retain exact object identity while armor, final reply and issued session keys remain distinct', () => {
  for (const choice of ['lab-ad-fast-as-success', 'lab-ad-fast-tgs-success']) {
    const f = fixture(choice), tgs = choice.includes('-tgs-');
    const original = cryptoId(f.model, 'padata-reply-key (local)');
    const input = cryptoId(f.model, tgs ? 'subkey (armor Authenticator)' : 'User long-term key (local)');
    assert.equal(original, input);
    const armor = cryptoId(f.model, 'armor_key (local)'), final = cryptoId(f.model, 'reply-key (FAST strengthened, local)');
    const issued = cryptoId(f.model, tgs ? 'key (EncTGSRepPart)' : 'key (EncASRepPart)');
    assert.equal(new Set([original, armor, final, issued]).size, 4);
    const snapshot = f.at('protect-response'), artifact = snapshot.artifacts.find(a => a.artifactId === original);
    assert.ok(artifact);
    assert.ok(artifact.representations.some(rep => rep.fields.some(field => field.name === (tgs ? 'Authenticator.subkey' : 'local.userLongTermKey'))));
    assert.equal(snapshot.artifacts.filter(a => a.artifactId === original).length, 1);
    assert.equal(held(snapshot, issued, 'cryptoClient').length, 0);
  }
});

test('otherwise inactive middle KDC in three-forest denial retains actual configured trust counterparts', () => {
  const f = fixture('lab-ad-forest-three-denied'), initial = f.at('initial-state');
  const keys = initial.artifacts.filter(a => a.label.startsWith('TDO-key-'));
  const ab = keys.find(a => a.label === 'TDO-key-A.EXAMPLE-to-B.EXAMPLE');
  const bc = keys.find(a => a.label === 'TDO-key-B.EXAMPLE-to-C.EXAMPLE');
  assert.ok(ab); assert.ok(bc);
  assert.deepEqual(new Set(initial.holdings.filter(h => h.artifactId === ab.artifactId).map(h => h.actorId)), new Set(['kdcHomeTgs', 'kdcMiddleTgs']));
  assert.deepEqual(new Set(initial.holdings.filter(h => h.artifactId === bc.artifactId).map(h => h.actorId)), new Set(['kdcMiddleTgs', 'kdcResourceTgs']));
  assert.equal(initial.artifacts.some(a => a.label === 'TDO-key-A.EXAMPLE-to-C.EXAMPLE'), false);
});

test('unrelated family returns null rather than marking unsupported inventory complete', () => {
  assert.equal(buildKerberosHeldObjects({model: {id: 'unrelated'}, steps: [], actors: {}, contextId: 'unrelated'}), null);
});
