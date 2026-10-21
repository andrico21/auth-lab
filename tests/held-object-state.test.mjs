import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  compileHeldObjects, projectHeldObjects, validateHeldObjects, assertHeldObjectCoverage,
  inspectHeldObject, heldObjectTrace, heldCursorForPlayback,
} from '../src/held-object-state.js';
import { reconstructProtocolState } from '../src/protocol-state.js';

const create = artifactId => ({ op: 'create', artifactId });
const acquire = (artifactId, actorId = 'client', store = 'credentials', options = {}) => ({
  op: 'acquire', artifactId, actorId, store, holdingId: `${actorId}:${artifactId}:${store}`,
  representationId: 'plain', retention: 'retained', ...options,
});
const release = holdingId => ({ op: 'release', holdingId });
const definition = (artifactId, options = {}) => ({
  artifactId, type: 'credential', label: 'Same visible label', creator: 'issuer',
  representations: [{ representationId: 'plain', format: 'token', readableBy: ['issuer', 'client'], fields: [{ attributeId: 'token', value: artifactId }] }],
  ...options,
});
function fixture() {
  const steps = [
    { id: 'prepare', from: 'issuer', to: 'issuer', payload: [], protocolEffects: [{ op: 'advance', value: 10 }] },
    { id: 'response', from: 'issuer', to: 'client', payload: [], protocolEffects: [{ op: 'put', path: 'caches.refresh', value: 'R1' }] },
    { id: 'logout', from: 'browser', to: 'issuer', payload: [] },
  ];
  const model = { id: 'rotation', steps, initialState: { caches: { refresh: 'R0' } } };
  const plan = {
    scenarioId: 'rotation', contextId: 'rotation:config:revision-1', actors: { issuer: {}, client: {}, browser: {}, api: {} },
    artifacts: ['R0', 'R1', 'AT1', 'offline', 'cookie'].map(id => definition(id)),
    initial: [create('R0'), acquire('R0'), create('offline'), acquire('offline'), create('cookie'), acquire('cookie', 'browser', 'cookies')],
    events: {
      prepare: { milestones: [{ id: 'complete', at: 1, effects: [
        { op: 'authority', artifactId: 'R0', authorityId: 'issuer', status: 'consumed' },
        create('R1'), create('AT1'), acquire('R1', 'issuer', 'output', { retention: 'temporary' }), acquire('AT1', 'issuer', 'output', { retention: 'temporary' }),
      ] }] },
      response: {
        messages: [{ messageId: 'M1', from: 'issuer', to: 'client', objects: [{ artifactId: 'R1', representationId: 'plain' }, { artifactId: 'AT1', representationId: 'plain' }], start: 0, end: .6 }],
        milestones: [
          { id: 'arrive', at: .6, effects: [acquire('R1', 'client', 'response', { retention: 'temporary' }), acquire('AT1', 'client', 'response', { retention: 'temporary' }), release('issuer:R1:output'), release('issuer:AT1:output')] },
          { id: 'check', at: .8, effects: [{ op: 'observe', artifactId: 'R1', actorId: 'client', kind: 'verification', requestId: 'refresh-1', result: 'accepted' }] },
          { id: 'complete', at: 1, effects: [
            { op: 'move', holdingId: 'client:R1:response', toHoldingId: 'client:R1:credentials', store: 'credentials', retention: 'retained' },
            release('client:AT1:response'), acquire('AT1'), release('client:R0:credentials'),
          ] },
        ],
      },
      logout: { milestones: [{ id: 'complete', at: 1, effects: [release('browser:cookie:cookies')] }] },
    },
    coverage: ['issuer', 'client', 'browser', 'api'].map(actorId => ({ actorId, status: 'complete', support: 'supported', stores: [], categories: [], gaps: [] })),
    bindings: [{ path: 'caches.refresh', equals: 'R0', actorId: 'client', artifactId: 'R0', store: 'credentials' }, { path: 'caches.refresh', equals: 'R1', actorId: 'client', artifactId: 'R1', store: 'credentials' }],
  };
  return { plan, model, steps };
}
const ids = snapshot => snapshot.holdings.map(item => item.artifactId);
const complete = eventIndex => ({ eventIndex, milestone: 'complete' });

describe('canonical held-object projection', () => {
  test('seeds current possession independently of an empty historical ledger', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps });
    const initial = projectHeldObjects(compiled);
    assert.deepEqual(ids(initial), ['R0', 'offline', 'cookie']);
    assert.equal(initial.artifacts.some(item => item.artifactId === 'R1'), false);
    assert.equal(initial.coverageStatus, 'complete');
    assert.equal(initial.state.caches.refresh, 'R0');
    assert.equal(model.steps[0].attributeOperations, undefined);
  });

  test('a provisioned-object replay stays at its initial checkpoint while paused mid-row', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps });
    const initial = projectHeldObjects(compiled);
    const row = heldObjectTrace(compiled, 'R0')[0];
    for (const fraction of [0, .001, .25, .5, .999, 1]) {
      const cursor = heldCursorForPlayback(compiled, {
        status: 'paused', kind: 'object', step: row, duration: 1000, stepElapsed: fraction * 1000,
      });
      assert.deepEqual(projectHeldObjects(compiled, cursor), initial);
    }
    const firstSource = heldCursorForPlayback(compiled, {
      status: 'paused', kind: 'step', step: steps[0], duration: 1000, stepElapsed: 500,
    });
    assert.equal(projectHeldObjects(compiled, firstSource).state.caches.refresh, 'R0');
    assert.equal(projectHeldObjects(compiled, firstSource).protocolClock, 0);
  });

  test('issuer consumption, delayed arrival, verification and client installation differ', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps });
    const issuing = projectHeldObjects(compiled, complete(0));
    assert.equal(issuing.authority[0].status, 'consumed');
    assert.equal(issuing.observations.length, 0);
    assert.equal(issuing.holdings.some(item => item.actorId === 'client' && item.artifactId === 'R1'), false);
    const flying = projectHeldObjects(compiled, { eventIndex: 1, progress: .59 });
    assert.equal(flying.inFlight.length, 1);
    assert.equal(flying.holdings.some(item => item.actorId === 'client' && item.artifactId === 'R1'), false);
    const arrived = projectHeldObjects(compiled, { eventIndex: 1, progress: .6 });
    assert.equal(arrived.inFlight.length, 0);
    assert.equal(arrived.holdings.find(item => item.actorId === 'client' && item.artifactId === 'R1').store, 'response');
    assert.equal(arrived.holdings.some(item => item.artifactId === 'R0'), true);
    assert.equal(arrived.observations.length, 0);
    const checked = projectHeldObjects(compiled, { eventIndex: 1, milestone: 'check' });
    assert.equal(checked.observations[0].requestId, 'refresh-1');
    const installed = projectHeldObjects(compiled, complete(1));
    assert.equal(installed.holdings.some(item => item.artifactId === 'R0'), false);
    assert.equal(installed.artifacts.some(item => item.artifactId === 'R0'), true);
    assert.equal(installed.holdings.find(item => item.artifactId === 'R1').store, 'credentials');
    assert.equal(installed.holdings.find(item => item.artifactId === 'R1').retention, 'retained');
    assert.equal(installed.holdings.find(item => item.artifactId === 'R1').ordinal, arrived.holdings.find(item => item.actorId === 'client' && item.artifactId === 'R1').ordinal);
    assert.deepEqual(installed.holdings.find(item => item.artifactId === 'R1').acquiredAt, arrived.cursor);
  });

  test('logout affects only explicitly released browser holdings and never informs all actors', () => {
    const { plan, model, steps } = fixture();
    const snapshot = projectHeldObjects(compileHeldObjects(plan, { model, steps }), complete(2));
    assert.equal(ids(snapshot).includes('cookie'), false);
    assert.equal(ids(snapshot).includes('offline'), true);
    assert.equal(snapshot.observations.some(item => item.actorId === 'api'), false);
  });

  test('rewind uses frozen reusable checkpoints and never mutates authoring input', () => {
    const { plan, model, steps } = fixture(), before = JSON.stringify({ plan, steps, initial: model.initialState });
    const compiled = compileHeldObjects(plan, { model, steps });
    const initial = projectHeldObjects(compiled), arrived = projectHeldObjects(compiled, { eventIndex: 1, milestone: 'arrive' });
    projectHeldObjects(compiled, complete(2));
    assert.equal(projectHeldObjects(compiled), initial);
    assert.equal(projectHeldObjects(compiled, { eventIndex: 1, progress: .7 }), arrived);
    assert.equal(JSON.stringify({ plan, steps, initial: model.initialState }), before);
    assert.ok(Object.isFrozen(arrived.state.caches));
    assert.throws(() => arrived.holdings.push({}), TypeError);
    assert.notEqual(initial.artifacts[0].qualifiedArtifactId, compileHeldObjects({ ...plan, contextId: 'other-revision' }, { model, steps }).contextId + '#R0');
  });

  test('protocol time follows explicit effects, not animation speed or pause', () => {
    const { plan, model, steps } = fixture();
    plan.artifacts[0].expiresAt = 5;
    const compiled = compileHeldObjects(plan, { model, steps });
    const snapshot = projectHeldObjects(compiled, complete(0));
    assert.equal(snapshot.protocolClock, 10);
    assert.equal(inspectHeldObject(snapshot, 'client:R0:credentials').expired, true);
    assert.equal(ids(snapshot).includes('R0'), true);
    assert.equal(projectHeldObjects(compiled, { eventIndex: 1, progress: .59 }).protocolClock, 10);
    assert.equal(reconstructProtocolState(model, 0).protocolClock, 10);
    assert.equal(reconstructProtocolState(model, -1).protocolClock, 0);
  });

  test('source state effects are partitioned only by explicit authored milestones', () => {
    const { plan, model, steps } = fixture();
    steps[1].protocolEffects.push({ op: 'put', path: 'knowledge.received', value: true });
    plan.events.response.milestones[0].stateEffects = [steps[1].protocolEffects[1]];
    const compiled = compileHeldObjects(plan, { model, steps });
    const arrived = projectHeldObjects(compiled, { eventIndex: 1, milestone: 'arrive' });
    assert.equal(arrived.state.knowledge.received, true);
    assert.equal(arrived.state.caches.refresh, 'R0');
    assert.equal(projectHeldObjects(compiled, complete(1)).state.caches.refresh, 'R1');
    assert.equal(reconstructProtocolState(model, 1).caches.refresh, 'R1');
  });

  test('compilation reads initial family state once and frame projection never reconstructs it', () => {
    const { plan, model, steps } = fixture();
    let reads = 0;
    const initial = model.initialState;
    model.initialState = () => { reads++; return initial; };
    const compiled = compileHeldObjects(plan, { model, steps });
    for (let frame = 0; frame <= 100; frame++) projectHeldObjects(compiled, { eventIndex: 1, progress: frame / 100 });
    assert.equal(reads, 1);
    assert.equal(assertHeldObjectCoverage(compiled), true);
  });

  test('retained sender copies survive a send and endpoint rejection remains scoped', () => {
    const { plan, model, steps } = fixture();
    plan.events.logout.milestones[0].effects.push(acquire('R1', 'api', 'request'), { op: 'observe', artifactId: 'R1', actorId: 'api', kind: 'acceptance', requestId: 'wrong-api', endpoint: '/admin', policy: 'audience', result: 'rejected' });
    plan.events.logout.messages = [{ messageId: 'M2', from: 'client', to: 'api', start: 0, end: 1, objects: [{ artifactId: 'R1', representationId: 'plain' }] }];
    const snapshot = projectHeldObjects(compileHeldObjects(plan, { model, steps }), complete(2));
    assert.equal(snapshot.holdings.filter(item => item.artifactId === 'R1').length, 2);
    assert.equal(snapshot.authority.some(item => item.artifactId === 'R1'), false);
    assert.equal(snapshot.observations.at(-1).endpoint, '/admin');
  });
});

describe('readability and coverage boundaries', () => {
  test('never unions actors, representations or protected field permissions', () => {
    const { plan, model, steps } = fixture();
    const secret = plan.artifacts.find(item => item.artifactId === 'cookie');
    secret.representations = [
      { representationId: 'plain', format: 'HttpOnly', readableBy: ['browser'], fields: [{ attributeId: 'cookie', value: 'SECRET', readableBy: ['issuer'] }, { attributeId: 'public', value: 'VISIBLE' }] },
      { representationId: 'issuer-view', format: 'plain', readableBy: ['issuer'], fields: [{ attributeId: 'private', value: 'ISSUER-SECRET' }] },
    ];
    const view = inspectHeldObject(projectHeldObjects(compileHeldObjects(plan, { model, steps })), 'browser:cookie:cookies');
    assert.equal(view.fields[0].redacted, true);
    assert.equal(view.fields[1].value, 'VISIBLE');
    assert.equal(JSON.stringify(view).includes('SECRET'), false);
    assert.equal(inspectHeldObject(projectHeldObjects(compileHeldObjects(plan, { model, steps })), 'absent'), null);
  });

  test('honest partial metadata is structurally valid but never passes the universal gate', () => {
    const { plan, model, steps } = fixture();
    plan.coverage.find(item => item.actorId === 'api').status = 'partial';
    plan.coverage.find(item => item.actorId === 'api').gaps = [{ store: 'trust', reason: 'Trust cache not modeled.' }];
    assert.deepEqual(validateHeldObjects(plan, { model, steps }), []);
    const compiled = compileHeldObjects(plan, { model, steps });
    assert.equal(projectHeldObjects(compiled).coverageStatus, 'partial');
    assert.throws(() => assertHeldObjectCoverage(compiled), /Incomplete supported/);
  });

  test('scoped declarations override broad coverage without claiming earlier completeness', () => {
    const { plan, model, steps } = fixture();
    plan.coverage.find(item => item.actorId === 'api').status = 'not-modeled';
    plan.coverage.push({ actorId: 'api', status: 'complete', support: 'supported', stores: ['trust'], categories: ['keys'], gaps: [], fromEvent: 1, fromMilestone: 'arrive', toEvent: 2 });
    const compiled = compileHeldObjects(plan, { model, steps });
    assert.equal(projectHeldObjects(compiled).coverage.find(item => item.actorId === 'api').status, 'not-modeled');
    assert.equal(projectHeldObjects(compiled, { eventIndex: 1, milestone: 'before' }).coverageStatus, 'not-modeled');
    assert.equal(projectHeldObjects(compiled, { eventIndex: 1, milestone: 'arrive' }).coverageStatus, 'complete');
    assert.throws(() => assertHeldObjectCoverage(compiled), /api at -1/);
  });

  test('missing actor declarations mean unknown rather than complete empty', () => {
    const { plan, model, steps } = fixture();
    plan.coverage = plan.coverage.filter(item => item.actorId !== 'api');
    const compiled = compileHeldObjects(plan, { model, steps });
    const record = projectHeldObjects(compiled).coverage.find(item => item.actorId === 'api');
    assert.equal(record.status, 'not-modeled');
    assert.equal(projectHeldObjects(compiled).holdings.filter(item => item.actorId === 'api').length, 0);
    assert.throws(() => assertHeldObjectCoverage(compiled), /api/);
  });
});

describe('exact traces and playback', () => {
  test('exact identity traces include predecessor context and equal-cursor projections', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps }), trace = heldObjectTrace(compiled, 'R1');
    assert.equal(heldObjectTrace(compiled, 'R1'), trace);
    assert.equal(trace.every(row => row.artifactId === 'R1'), true);
    assert.equal(new Set(trace.map(row => row.id)).size, trace.length);
    assert.throws(() => heldObjectTrace(compiled, 'refresh_token'), /exact artifact ID/);
    const receipt = trace.find(row => row.heldCursorEnd.milestone === 'arrive');
    const cursor = heldCursorForPlayback(compiled, { status: 'paused' }, receipt, { selected: true });
    assert.equal(projectHeldObjects(compiled, cursor), projectHeldObjects(compiled, { eventIndex: 1, progress: .6 }));
    assert.equal(ids(projectHeldObjects(compiled, cursor)).includes('R0'), true);
    assert.equal(projectHeldObjects(compiled, cursor).protocolClock, 10);
    const seed = heldObjectTrace(compiled, 'offline')[0];
    assert.equal(seed.traceKind, 'initial');
    assert.equal(projectHeldObjects(compiled, heldCursorForPlayback(compiled, {}, seed, { selected: true })), projectHeldObjects(compiled));
  });

  test('exact occurrences retain wire values and bind local checks to their decoded holding', () => {
    const { plan, model, steps } = fixture(), token = plan.artifacts.find(item => item.artifactId === 'R1');
    const compact = 'eyJhbGciOiJSU0EtT0FFUC0yNTYifQ.encrypted-key.iv.ciphertext.tag';
    token.representations = [
      { representationId: 'plain', format: 'JWE compact', readableBy: ['issuer', 'client'], fields: [{ attributeId: 'token', value: compact }] },
      { representationId: 'view', format: 'decrypted JWS', readableBy: ['client'], fields: [
        { attributeId: 'token', value: 'decoded-signed-token' }, { attributeId: 'issuer', value: 'https://issuer.example' },
        { attributeId: 'private', value: 'ISSUER-ONLY', readableBy: ['issuer'] },
      ] },
    ];
    const check = plan.events.response.milestones[1];
    check.effects.unshift(acquire('R1', 'client', 'decoded', { representationId: 'view' }));
    check.effects.find(effect => effect.op === 'observe').representationId = 'view';
    const compiled = compileHeldObjects(plan, { model, steps }), final = projectHeldObjects(compiled, complete(2));
    const rows = heldObjectTrace(compiled, 'R1'), wire = rows.find(row => row.heldCursorEnd.milestone === 'arrive'), local = rows.find(row => row.heldCursorEnd.milestone === 'check');
    assert.equal(wire.representationId, 'plain'); assert.equal(wire.holdingId, 'client:R1:response');
    assert.equal(wire.payload.find(field => field.attributeId === 'token').value, compact);
    assert.equal(wire.payload.some(field => field.attributeId === 'issuer'), false);
    assert.equal(local.representationId, 'view'); assert.equal(local.holdingId, 'client:R1:decoded');
    assert.equal(local.payload.find(field => field.attributeId === 'token').value, 'decoded-signed-token');
    assert.equal(local.payload.find(field => field.attributeId === 'issuer').value, 'https://issuer.example');
    assert.equal(local.payload.find(field => field.attributeId === 'private').redacted, true);
    assert.equal(JSON.stringify(rows).includes('ISSUER-ONLY'), false);
    for (const row of rows) assert.equal(projectHeldObjects(compiled, heldCursorForPlayback(compiled, { status: 'complete', step: row }, row)), projectHeldObjects(compiled, row.heldCursorEnd));
    assert.equal(projectHeldObjects(compiled, complete(2)), final);
  });

  test('message-only replay stops at receipt without installing later credentials', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps });
    const cursor = heldCursorForPlayback(compiled, { kind: 'connection', status: 'complete', step: steps[1] });
    assert.deepEqual(cursor, { eventIndex: 1, milestone: 'arrive' });
    const snapshot = projectHeldObjects(compiled, cursor);
    assert.equal(snapshot.holdings.find(item => item.actorId === 'client' && item.artifactId === 'R1').store, 'response');
    assert.equal(ids(snapshot).includes('R0'), true);
    assert.equal(snapshot.state.caches.refresh, 'R0');
  });

  test('atomic progress ignores field packet motion and adjacent rows do not recommit', () => {
    const { plan, model, steps } = fixture();
    const compiled = compileHeldObjects(plan, { model, steps });
    const rows = [1, 2].map(n => ({ id: `attribute-${n}`, sourceStepId: 'prepare', sourceIndex: 0 }));
    const playing = (row, queuePosition, elapsed) => heldCursorForPlayback(compiled, { status: 'paused', step: row, queue: rows, queuePosition, duration: 100, stepElapsed: elapsed, progress: 1 });
    assert.deepEqual(playing(rows[0], 0, 100), { eventIndex: 0, milestone: 'before' });
    assert.deepEqual(playing(rows[1], 1, 0), { eventIndex: 0, milestone: 'before' });
    assert.deepEqual(playing(rows[1], 1, 100), complete(0));
    assert.deepEqual(heldCursorForPlayback(compiled, {}, rows[0], { selected: true }), complete(0));
    assert.deepEqual(heldCursorForPlayback(compiled, {}, rows[0], { initial: true }), { eventIndex: -1, milestone: 'initial' });
    assert.deepEqual(heldCursorForPlayback(compiled, { status: 'paused', step: steps[0], duration: 100, elapsed: 99, progress: 1 }), { eventIndex: 0, milestone: 'before' });
    assert.deepEqual(heldCursorForPlayback(compiled, { status: 'idle' }, rows[0]), { eventIndex: -1, milestone: 'initial' });
  });

  test('exact rows from different context revisions cannot cross scenario boundaries', () => {
    const { plan, model, steps } = fixture();
    const first = compileHeldObjects(plan, { model, steps }), second = compileHeldObjects({ ...plan, contextId: 'revision-2' }, { model, steps });
    assert.throws(() => heldCursorForPlayback(second, {}, heldObjectTrace(first, 'R1')[0], { selected: true }), /different context/);
  });
});

describe('authored metadata rejection', () => {
  for (const [label, mutate, pattern] of [
    ['duplicate artifacts', p => p.artifacts.push(p.artifacts[0]), /Duplicate artifact/],
    ['unknown relation', p => { p.artifacts[0].derivedFrom = ['missing']; }, /Unknown artifact/],
    ['unknown actor', p => { p.initial[1].actorId = 'not-an-actor'; }, /Unknown logical actor/],
    ['unknown representation', p => { p.initial[1].representationId = 'missing'; }, /Unknown representation/],
    ['unaccounted temporary retention', p => { p.initial[3].retention = 'temporary'; }, /Unaccounted temporary/],
    ['release before acquisition', p => p.initial.unshift(release('missing')), /Release of absent/],
    ['duplicate acquisition', p => p.initial.push(acquire('R0')), /Duplicate holding/],
    ['future possession', p => p.initial.push(acquire('R1')), /precedes artifact creation/],
    ['unsafe binding path', p => p.bindings.push({ path: '__proto__.polluted', actorId: 'client', artifactId: 'R0' }), /Unsafe/],
    ['inconsistent cache bindings', p => { p.bindings[0].equals = 'impossible'; }, /binding disagrees/],
    ['duplicate milestone', p => p.events.response.milestones.splice(1, 0, p.events.response.milestones[0]), /Duplicate/],
    ['unknown source event', p => { p.events.absent = { milestones: [] }; }, /Unknown source event/],
    ['invalid explicit move retention', p => { p.events.response.milestones.at(-1).effects[0].retention = 'guess-from-store'; }, /Invalid move retention/],
    ['duplicate message representation', p => p.events.response.messages[0].objects.push(p.events.response.messages[0].objects[0]), /Duplicate message object/],
    ['reversed coverage', p => { p.coverage[0].fromEvent = 2; p.coverage[0].toEvent = 0; }, /reversed/],
    ['unknown coverage milestone', p => { p.coverage[0].fromEvent = 1; p.coverage[0].fromMilestone = 'invented'; }, /Unknown coverage milestone/],
    ['duplicate state transition', p => { p.events.prepare.milestones[0].stateEffects = [{ op: 'advance', value: 10 }, { op: 'advance', value: 10 }]; }, /absent or duplicated/],
    ['double protocol time advancement', p => p.events.prepare.milestones[0].effects.push({ op: 'advance', value: 10 }), /advanced twice/],
  ]) test(label, () => {
    const { plan, model, steps } = fixture(); mutate(plan);
    assert.match(validateHeldObjects(plan, { model, steps }).join('\n'), pattern);
    assert.throws(() => compileHeldObjects(plan, { model, steps }), pattern);
  });

  test('invalid cursors and mismatched source references fail rather than silently clamp', () => {
    const { plan, model, steps } = fixture(), compiled = compileHeldObjects(plan, { model, steps });
    assert.throws(() => projectHeldObjects(compiled, { eventIndex: 3 }), /out of range/);
    assert.throws(() => projectHeldObjects(compiled, { eventIndex: 1, milestone: 'invented' }), /Unknown cursor/);
    assert.throws(() => heldCursorForPlayback(compiled, {}, { sourceStepId: 'response', sourceIndex: 0 }, { selected: true }), /disagree/);
  });
});
