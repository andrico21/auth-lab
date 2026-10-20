import { reconstructProtocolState } from './protocol-state.js';

const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
const engines = new WeakMap();
const own = (value, key) => Object.hasOwn(value, key);
const initialCursor = Object.freeze({ eventIndex: -1, milestone: 'initial' });

function copy(value, seen = new Set()) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint' || typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('Held objects require finite plain data.');
    return value;
  }
  if (seen.has(value) || !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('Held objects require acyclic plain data.');
  seen.add(value);
  const result = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) {
    if (forbidden.has(key)) throw new TypeError('Unsafe held-object key.');
    result[key] = copy(value[key], seen);
  }
  seen.delete(value);
  return result;
}
function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
function requireValue(condition, message) { if (!condition) throw new TypeError(message); }
function text(value, name) { requireValue(typeof value === 'string' && value.length > 0, `${name} must be a non-empty string.`); }
function list(value, name) { requireValue(Array.isArray(value), `${name} must be an array.`); return value; }
function pathParts(path) {
  text(path, 'Binding/effect path');
  const parts = path.split('.');
  requireValue(parts.every(part => part && !forbidden.has(part)), 'Unsafe binding/effect path.');
  return parts;
}
function atPath(state, path) {
  let value = state;
  for (const part of pathParts(path)) {
    if (!value || typeof value !== 'object' || !own(value, part)) return { exists: false };
    value = value[part];
  }
  return { exists: true, value };
}
function identity(value) {
  if (Array.isArray(value)) return `[${value.map(identity).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${identity(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function applyState(state, effect) {
  requireValue(effect && typeof effect === 'object', 'A state effect must be an object.');
  if (effect.op === 'advance') {
    requireValue(effect.path === undefined || effect.path === 'protocolClock', 'advance can only target protocolClock.');
    requireValue(Number.isFinite(effect.value) && effect.value >= 0 && Number.isFinite(state.protocolClock + effect.value), 'Invalid protocol time advance.');
    state.protocolClock += effect.value;
    return;
  }
  requireValue(['put', 'remove', 'append'].includes(effect.op), 'Unknown family state effect.');
  const parts = pathParts(effect.path);
  requireValue(parts[0] !== 'protocolClock', 'Only advance may change protocolClock.');
  let parent = state;
  for (const part of parts.slice(0, -1)) {
    if (!own(parent, part)) {
      if (effect.op === 'remove') return;
      parent[part] = {};
    }
    requireValue(parent[part] !== null && typeof parent[part] === 'object', 'A family state path traverses a primitive.');
    parent = parent[part];
  }
  const leaf = parts.at(-1);
  if (effect.op === 'remove') delete parent[leaf];
  else {
    requireValue(own(effect, 'value'), 'A family state effect requires a value.');
    if (effect.op === 'put') parent[leaf] = copy(effect.value);
    else {
      if (!own(parent, leaf)) parent[leaf] = [];
      requireValue(Array.isArray(parent[leaf]), 'append requires an array.');
      parent[leaf].push(copy(effect.value));
    }
  }
}
function actorIds(plan) {
  if (Array.isArray(plan.actors)) return plan.actors.map(actor => typeof actor === 'string' ? actor : actor.id);
  if (plan.actors && typeof plan.actors === 'object') return Object.keys(plan.actors);
  return [...new Set((plan.coverage || []).map(record => record.actorId))];
}
function resolveSteps(model, steps) {
  const result = steps ?? (typeof model?.steps === 'function' ? model.steps() : model?.steps) ?? [];
  return list(result, 'Source steps');
}
function coveragePosition(record, prefix, data) {
  const index = record[`${prefix}Event`];
  const milestone = record[`${prefix}Milestone`];
  if (index === undefined) {
    requireValue(milestone === undefined, 'Coverage milestone requires an event index.');
    return prefix === 'from' ? -Infinity : Infinity;
  }
  requireValue(Number.isInteger(index) && index >= -1 && index < data.steps.length, 'Coverage event index is out of range.');
  if (index === -1) {
    requireValue(milestone === undefined || milestone === 'initial', 'Invalid initial coverage milestone.');
    return 0;
  }
  const row = data.events[index];
  const name = milestone ?? (prefix === 'from' ? 'before' : 'complete');
  const cursor = row.cursors.get(name);
  requireValue(cursor, 'Unknown coverage milestone.');
  return data.positions.get(cursor);
}
function applicableCoverage(data, position) {
  const records = [];
  for (const actorId of data.actors) {
    const candidates = data.coverage.filter(entry => entry.record.actorId === actorId && position >= entry.start && position <= entry.end);
    candidates.sort((a, b) => b.specificity - a.specificity || (a.end - a.start) - (b.end - b.start) || b.order - a.order);
    if (candidates.length) records.push(candidates[0].record);
    else records.push({ actorId, status: 'not-modeled', support: 'supported', stores: [], categories: [], gaps: [{ reason: 'No coverage declaration applies at this cursor.' }] });
  }
  return records;
}
function checkBindings(data, state, holdings) {
  for (const binding of data.plan.bindings || []) {
    const found = atPath(state, binding.path);
    const present = own(binding, 'equals') ? found.exists && identity(found.value) === identity(binding.equals) : binding.presentWhen === 'exists' ? found.exists : !!found.value;
    const held = [...holdings.values()].some(holding => holding.actorId === binding.actorId && holding.artifactId === binding.artifactId && (binding.representationId === undefined || holding.representationId === binding.representationId) && (binding.store === undefined || holding.store === binding.store));
    requireValue(present === held, `Family-state binding disagrees with holdings: ${binding.path} / ${binding.artifactId}.`);
  }
}

function build(planInput, { model = null, steps } = {}) {
  const plan = copy(planInput);
  requireValue(plan && typeof plan === 'object' && !Array.isArray(plan), 'A held-object plan must be an object.');
  text(plan.contextId, 'contextId');
  text(plan.scenarioId, 'scenarioId');
  const source = copy(resolveSteps(model, steps));
  const data = { plan, steps: source, actors: actorIds(plan), artifacts: new Map(), events: [], positions: new Map([[initialCursor, 0]]), coverage: [], checkpoints: new Map(), trace: new Map() };
  requireValue(new Set(data.actors).size === data.actors.length, 'Duplicate logical actor ID.');
  for (const id of data.actors) text(id, 'Actor ID');
  const actor = id => requireValue(data.actors.includes(id), `Unknown logical actor: ${id}.`);
  const artifact = id => { requireValue(data.artifacts.has(id), `Unknown artifact: ${id}.`); return data.artifacts.get(id); };
  const representation = (id, rep) => { const found = artifact(id).representations.find(item => item.representationId === rep); requireValue(found, `Unknown representation: ${id}/${rep}.`); return found; };
  for (const definition of list(plan.artifacts, 'artifacts')) {
    text(definition.artifactId, 'artifactId'); text(definition.type, 'Artifact type'); text(definition.label, 'Artifact label'); actor(definition.creator);
    requireValue(!data.artifacts.has(definition.artifactId), 'Duplicate artifact ID.');
    const reps = new Set();
    for (const rep of list(definition.representations, 'representations')) {
      text(rep.representationId, 'representationId'); text(rep.format, 'Representation format');
      requireValue(!reps.has(rep.representationId), 'Duplicate representation ID.'); reps.add(rep.representationId);
      list(rep.readableBy, 'readableBy').forEach(actor);
      const fields = new Set();
      for (const field of list(rep.fields, 'Representation fields')) {
        text(field.attributeId, 'attributeId'); requireValue(!fields.has(field.attributeId), 'Duplicate field ID within representation.'); fields.add(field.attributeId);
        requireValue(own(field, 'value'), 'A representation field requires an explicit value.');
        if (field.readableBy !== undefined) list(field.readableBy, 'Field readableBy').forEach(actor);
      }
    }
    requireValue(reps.size > 0, 'An artifact requires a representation.');
    if (definition.expiresAt !== undefined) requireValue(Number.isFinite(definition.expiresAt) && definition.expiresAt >= 0, 'Invalid artifact expiry.');
    data.artifacts.set(definition.artifactId, definition);
  }
  for (const definition of data.artifacts.values()) for (const key of ['derivedFrom', 'replaces', 'related']) {
    if (definition[key] !== undefined) for (const id of list(definition[key], key)) { artifact(id); requireValue(id !== definition.artifactId, 'An artifact relation cannot reference itself.'); }
  }
  if (plan.sourceStepIds !== undefined) requireValue(identity(plan.sourceStepIds) === identity(source.map(step => step.id)), 'Plan source step IDs disagree with the compiled journey.');
  const ids = new Set();
  let position = 1;
  const eventDefinitions = plan.events ?? {};
  requireValue(eventDefinitions && typeof eventDefinitions === 'object' && !Array.isArray(eventDefinitions), 'events must be keyed by source step ID.');
  for (const [index, step] of source.entries()) {
    text(step.id, 'Source step ID'); requireValue(!ids.has(step.id), 'Duplicate source step ID.'); ids.add(step.id);
    const event = eventDefinitions[step.id] ?? {};
    const milestones = copy(event.milestones ?? []);
    if (!milestones.some(item => item.id === 'complete')) milestones.push({ id: 'complete', at: 1, effects: [] });
    let previous = -1;
    const cursors = new Map([['before', freeze({ eventIndex: index, milestone: 'before' })]]);
    data.positions.set(cursors.get('before'), position++);
    for (const milestone of milestones) {
      text(milestone.id, 'Milestone ID');
      requireValue(!['before', 'initial'].includes(milestone.id) && !cursors.has(milestone.id), 'Duplicate/reserved milestone ID.');
      requireValue(Number.isFinite(milestone.at) && milestone.at >= 0 && milestone.at <= 1 && milestone.at > previous, 'Milestones must have strictly increasing normalized positions.');
      requireValue(milestone.id === 'complete' ? milestone.at === 1 : milestone.at < 1, 'Only complete may be positioned at 1.');
      previous = milestone.at;
      list(milestone.effects, 'Milestone effects');
      requireValue(new Set(milestone.effects.map(identity)).size === milestone.effects.length, 'Duplicate held transition within a milestone.');
      if (milestone.stateEffects !== undefined) list(milestone.stateEffects, 'Milestone stateEffects');
      const cursor = freeze({ eventIndex: index, milestone: milestone.id });
      cursors.set(milestone.id, cursor); data.positions.set(cursor, position++);
    }
    requireValue(milestones.at(-1).id === 'complete', 'The final milestone must be complete.');
    const stock = copy(step.protocolEffects ?? []);
    list(stock, 'protocolEffects');
    const remaining = stock.slice();
    for (const milestone of milestones) for (const effect of milestone.stateEffects || []) {
      const match = remaining.findIndex(candidate => identity(candidate) === identity(effect));
      requireValue(match >= 0, 'Partitioned state effect is absent or duplicated in the source event.'); remaining.splice(match, 1);
    }
    milestones.at(-1).stateEffects = [...(milestones.at(-1).stateEffects || []), ...remaining];
    requireValue(!(stock.some(effect => effect.op === 'advance') && milestones.some(milestone => milestone.effects.some(effect => effect.op === 'advance'))), 'Protocol time must not be advanced twice by stock and held effects.');
    data.events.push({ ...event, milestones, cursors });
  }
  for (const key of Object.keys(eventDefinitions)) requireValue(ids.has(key), `Unknown source event: ${key}.`);
  for (const [order, record] of list(plan.coverage ?? [], 'coverage').entries()) {
    actor(record.actorId); requireValue(['complete', 'partial', 'not-modeled'].includes(record.status), 'Unknown coverage status.');
    requireValue(['supported', 'excluded'].includes(record.support), 'Coverage support must be explicit.');
    list(record.stores, 'Coverage stores').forEach(store => text(store, 'Coverage store'));
    list(record.categories, 'Coverage categories').forEach(category => text(category, 'Coverage category'));
    list(record.gaps, 'Coverage gaps').forEach(gap => text(gap.reason, 'Coverage gap reason'));
    requireValue(record.status !== 'complete' || record.gaps.length === 0, 'Complete coverage cannot contain declared gaps.');
    if (record.support === 'excluded') text(record.rationale, 'Exclusion rationale');
    const start = coveragePosition(record, 'from', data), end = coveragePosition(record, 'to', data);
    requireValue(start <= end, 'Coverage range is reversed.');
    data.coverage.push({ record, start, end, order, specificity: ['fromEvent', 'toEvent', 'fromMilestone', 'toMilestone'].filter(key => own(record, key)).length });
  }
  for (const binding of list(plan.bindings ?? [], 'bindings')) {
    pathParts(binding.path); actor(binding.actorId); artifact(binding.artifactId);
    if (binding.representationId !== undefined) representation(binding.artifactId, binding.representationId);
    if (binding.store !== undefined) text(binding.store, 'Binding store');
    requireValue(binding.presentWhen === undefined || ['exists', 'truthy'].includes(binding.presentWhen), 'Invalid binding predicate.');
  }
  const messageIds = new Set();
  for (const event of data.events) for (const message of list(event.messages ?? [], 'messages')) {
    text(message.messageId, 'messageId'); requireValue(!messageIds.has(message.messageId), 'Duplicate message ID.'); messageIds.add(message.messageId);
    actor(message.from); actor(message.to);
    requireValue(Number.isFinite(message.start) && Number.isFinite(message.end) && message.start >= 0 && message.start < message.end && message.end <= 1, 'Invalid message interval.');
    requireValue(list(message.objects, 'Message objects').length > 0, 'A message requires objects.');
    requireValue(new Set(message.objects.map(object => identity([object.artifactId, object.representationId]))).size === message.objects.length, 'Duplicate message object representation.');
    for (const object of message.objects) representation(object.artifactId, object.representationId);
  }
  const state = copy(reconstructProtocolState(model, -1));
  const holdings = new Map(), created = new Set(), holdingIds = new Set(), observations = [], authority = new Map();
  let ordinal = 0;
  function apply(effect, cursor) {
    requireValue(effect && typeof effect === 'object', 'A held effect must be an object.');
    const timestamp = { ...cursor };
    if (effect.op === 'advance') { applyState(state, effect); return; }
    if (['create', 'acquire', 'observe', 'authority'].includes(effect.op)) artifact(effect.artifactId);
    if (effect.op === 'create') {
      requireValue(!created.has(effect.artifactId), 'Duplicate artifact creation transition.'); created.add(effect.artifactId);
    } else if (effect.op === 'acquire') {
      text(effect.holdingId, 'holdingId'); actor(effect.actorId); representation(effect.artifactId, effect.representationId); text(effect.store, 'Holding store');
      requireValue(created.has(effect.artifactId), 'Acquisition precedes artifact creation.');
      requireValue(!holdingIds.has(effect.holdingId), `Duplicate holding ID/acquisition transition: ${effect.holdingId} at ${cursor.eventIndex}/${cursor.milestone}.`);
      requireValue(['temporary', 'retained'].includes(effect.retention), 'Holding retention must be explicit.');
      if (effect.displayOrder !== undefined) requireValue(Number.isFinite(effect.displayOrder), 'Invalid display order.');
      holdingIds.add(effect.holdingId);
      holdings.set(effect.holdingId, { ...effect, contextId: plan.contextId, qualifiedArtifactId: `${plan.contextId}#${effect.artifactId}`, qualifiedHoldingId: `${plan.contextId}#${effect.holdingId}`, acquiredAt: timestamp, ordinal: ordinal++ });
    } else if (effect.op === 'release') {
      requireValue(holdings.has(effect.holdingId), `Release of absent holding: ${effect.holdingId}.`); holdings.delete(effect.holdingId);
    } else if (effect.op === 'move') {
      const holding = holdings.get(effect.holdingId); requireValue(holding, 'Move of absent holding.'); text(effect.store, 'Move store');
      requireValue(effect.retention === undefined || ['temporary', 'retained'].includes(effect.retention), 'Invalid move retention.');
      const id = effect.toHoldingId ?? effect.holdingId; text(id, 'Move holding ID');
      requireValue(id === effect.holdingId || !holdingIds.has(id), 'Duplicate moved holding ID.');
      requireValue(id !== effect.holdingId || effect.store !== holding.store || effect.retention !== undefined && effect.retention !== holding.retention, 'A move must change store, holding ID or explicit retention.');
      holdingIds.add(id); holdings.delete(effect.holdingId);
      holdings.set(id, { ...holding, holdingId: id, qualifiedHoldingId: `${plan.contextId}#${id}`, store: effect.store, retention: effect.retention ?? holding.retention, movedFrom: effect.holdingId, movedAt: timestamp });
    } else if (effect.op === 'observe') {
      requireValue(created.has(effect.artifactId), 'Observation precedes artifact creation.'); actor(effect.actorId);
      if (effect.representationId !== undefined) representation(effect.artifactId, effect.representationId);
      requireValue(['verification', 'acceptance', 'knowledge'].includes(effect.kind), 'Unknown observation kind.'); text(effect.result, 'Observation result');
      observations.push({ ...effect, cursor: timestamp, ordinal: observations.length });
    } else if (effect.op === 'authority') {
      requireValue(created.has(effect.artifactId), 'Authority state precedes artifact creation.'); actor(effect.authorityId); text(effect.status, 'Authority status');
      const key = JSON.stringify([effect.artifactId, effect.authorityId]);
      requireValue(authority.get(key)?.status !== effect.status, 'Duplicate authority transition.'); authority.set(key, { ...effect, cursor: timestamp });
    } else throw new TypeError('Unknown held-object effect operation.');
  }
  function checkpoint(cursor, at = 0) {
    const coverage = applicableCoverage(data, data.positions.get(cursor));
    const supported = coverage.filter(record => record.support === 'supported');
    const coverageStatus = supported.some(record => record.status === 'not-modeled') ? 'not-modeled' : supported.some(record => record.status === 'partial') ? 'partial' : 'complete';
    const event = data.events[cursor.eventIndex];
    const inFlight = (event?.messages || []).filter(message => at >= message.start && at < message.end);
    data.checkpoints.set(cursor, freeze({ contextId: plan.contextId, cursor, protocolClock: state.protocolClock,
      holdings: [...holdings.values()].sort((a, b) => (a.displayOrder ?? Infinity) - (b.displayOrder ?? Infinity) || a.ordinal - b.ordinal || a.holdingId.localeCompare(b.holdingId)),
      artifacts: [...created].map(id => ({ ...data.artifacts.get(id), contextId: plan.contextId, qualifiedArtifactId: `${plan.contextId}#${id}` })),
      inFlight: copy(inFlight), observations: observations.slice(), authority: [...authority.values()], coverage: copy(coverage), coverageStatus, state: copy(state) }));
  }
  for (const effect of list(plan.initial ?? [], 'initial effects')) apply(effect, initialCursor);
  checkBindings(data, state, holdings); checkpoint(initialCursor);
  for (const [index, event] of data.events.entries()) {
    checkpoint(event.cursors.get('before'));
    for (const milestone of event.milestones) {
      const cursor = event.cursors.get(milestone.id);
      for (const effect of milestone.stateEffects || []) applyState(state, effect);
      for (const effect of milestone.effects) apply(effect, cursor);
      if (milestone.id === 'complete') checkBindings(data, state, holdings);
      checkpoint(cursor, milestone.at);
    }
  }
  requireValue(![...holdings.values()].some(holding => holding.retention === 'temporary'), 'Unaccounted temporary retention at end of journey.');
  freeze(plan); freeze(source);
  const compiled = freeze({ plan, contextId: plan.contextId, steps: source, sourceSteps: source, actors: data.actors.slice(), cursors: [...data.checkpoints.keys()] });
  engines.set(compiled, data);
  return compiled;
}

/** Compile once per immutable scenario context; projection never replays effects. */
export function compileHeldObjects(plan, options = {}) { return build(plan, options); }
export function validateHeldObjects(plan, options = {}) {
  try { build(plan, options); return []; } catch (error) { return [error.message]; }
}
function engine(compiled) { const data = engines.get(compiled); requireValue(data, 'Expected a compiled held-object plan.'); return data; }
function canonical(data, cursor = initialCursor) {
  requireValue(cursor && typeof cursor === 'object', 'A cursor is required.');
  requireValue(Number.isInteger(cursor.eventIndex) && cursor.eventIndex >= -1 && cursor.eventIndex < data.steps.length, 'Cursor event index is out of range.');
  if (cursor.eventIndex === -1) {
    requireValue(cursor.milestone === undefined || cursor.milestone === 'initial', 'Invalid initial cursor.'); return initialCursor;
  }
  const event = data.events[cursor.eventIndex];
  if (cursor.progress !== undefined) {
    requireValue(Number.isFinite(cursor.progress) && cursor.progress >= 0 && cursor.progress <= 1, 'Cursor progress must be normalized.');
    let result = event.cursors.get('before');
    for (const milestone of event.milestones) if (milestone.at <= cursor.progress) result = event.cursors.get(milestone.id);
    return result;
  }
  const result = event.cursors.get(cursor.milestone ?? 'complete'); requireValue(result, 'Unknown cursor milestone.'); return result;
}
export function projectHeldObjects(compiled, cursor = initialCursor) {
  const data = engine(compiled); return data.checkpoints.get(canonical(data, cursor));
}
export function assertHeldObjectCoverage(compiledOrPlan, options = {}) {
  const compiled = engines.has(compiledOrPlan) ? compiledOrPlan : build(compiledOrPlan, options);
  const data = engine(compiled), errors = [];
  for (const snapshot of data.checkpoints.values()) for (const record of snapshot.coverage) if (record.support === 'supported' && record.status !== 'complete') errors.push(`${record.actorId} at ${snapshot.cursor.eventIndex}/${snapshot.cursor.milestone}: ${record.status}`);
  requireValue(errors.length === 0, `Incomplete supported held-object coverage: ${errors.join('; ')}`);
  return true;
}

function readableFields(representation, actorId) {
  const readable = representation.readableBy.includes(actorId);
  return representation.fields.map(field => {
    const allowed = readable && (field.readableBy === undefined || field.readableBy.includes(actorId));
    return allowed ? { ...field, readable: true } : { attributeId: field.attributeId, ...(field.name === undefined ? {} : { name: field.name }), readable: false, redacted: true };
  });
}

/** A holder can inspect only its exact representation and permitted fields. */
export function inspectHeldObject(snapshot, holdingId) {
  const holding = snapshot.holdings.find(item => item.holdingId === holdingId);
  if (!holding) return null;
  const artifact = snapshot.artifacts.find(item => item.artifactId === holding.artifactId);
  const representation = artifact.representations.find(item => item.representationId === holding.representationId);
  const readable = representation.readableBy.includes(holding.actorId);
  const fields = readableFields(representation, holding.actorId);
  const { representations, ...metadata } = artifact;
  return freeze({ holding, artifact: metadata, representation: { representationId: representation.representationId, format: representation.format, readable, fields }, fields,
    observations: snapshot.observations.filter(item => item.artifactId === artifact.artifactId && item.actorId === holding.actorId),
    expired: artifact.expiresAt !== undefined && snapshot.protocolClock >= artifact.expiresAt });
}

/** Exact immutable identity, never a field type or value match. */
export function heldObjectTrace(compiled, artifactId) {
  const data = engine(compiled); requireValue(data.artifacts.has(artifactId), 'Unknown exact artifact ID.');
  if (data.trace.has(artifactId)) return data.trace.get(artifactId);
  const artifact = data.artifacts.get(artifactId), rows = [], history = new Map();
  const remember = effect => {
    if (effect.op === 'acquire') history.set(effect.holdingId, effect);
    else if (effect.op === 'move') {
      const holding = history.get(effect.holdingId);
      history.set(effect.toHoldingId ?? effect.holdingId, { ...holding, holdingId: effect.toHoldingId ?? effect.holdingId, store: effect.store });
    }
  };
  for (const effect of data.plan.initial || []) remember(effect);
  const occurrence = (snapshot, before, actorId, representationId, preferred) => {
    const current = snapshot.holdings.filter(item => item.artifactId === artifactId && item.actorId === actorId && (representationId === undefined || item.representationId === representationId));
    const prior = before.holdings.filter(item => item.artifactId === artifactId && item.actorId === actorId && (representationId === undefined || item.representationId === representationId));
    const holding = preferred ?? current.at(-1) ?? prior.at(-1);
    const rep = artifact.representations.find(item => item.representationId === (representationId ?? holding?.representationId));
    const fields = rep ? readableFields(rep, actorId) : [];
    return { ...(holding ? { holdingId: holding.holdingId } : {}), ...(rep ? { representationId: rep.representationId } : {}), inspectionActorId: actorId,
      fields: fields.map(field => field.attributeId),
      payload: fields.map(field => ({ attributeId: field.attributeId, name: field.name ?? field.attributeId, ...(field.readable ? { value: field.value } : { value: 'Not readable by this holder', redacted: true }) })) };
  };
  const seeded = data.checkpoints.get(initialCursor);
  if (seeded.artifacts.some(item => item.artifactId === artifactId)) {
    const holding = seeded.holdings.find(item => item.artifactId === artifactId), owner = holding?.actorId ?? artifact.creator;
    rows.push(freeze({ id: `held-trace:${encodeURIComponent(compiled.contextId)}:${encodeURIComponent(artifactId)}:initial`,
      sourceIndex: -1, sourceStepId: null, artifactId, heldContextId: compiled.contextId, heldCursorStart: initialCursor, heldCursorEnd: initialCursor,
      traceKind: 'initial', title: `${artifact.label}: initial provisioned context`, from: owner, to: owner, channel: 'internal',
      ...occurrence(seeded, seeded, owner, holding?.representationId, holding),
      attributeOperations: [], attributeValues: {}, protocolEffects: [], checks: [] }));
  }
  for (const [index, event] of data.events.entries()) {
    let previous = event.cursors.get('before');
    for (const milestone of event.milestones) {
      const end = event.cursors.get(milestone.id), kinds = new Set(), related = [];
      for (const effect of milestone.effects) {
        const holding = history.get(effect.holdingId), id = effect.artifactId ?? holding?.artifactId;
        remember(effect);
        if (id === artifactId) {
          kinds.add(effect.op);
          related.push({ effect, holding: effect.op === 'acquire' ? effect : effect.op === 'move' ? history.get(effect.toHoldingId ?? effect.holdingId) : holding });
        }
      }
      const startAt = previous.milestone === 'before' ? 0 : event.milestones.find(item => item.id === previous.milestone).at;
      const messages = (event.messages || []).filter(message => message.objects.some(object => object.artifactId === artifactId) && message.end <= milestone.at && message.end > startAt);
      if (messages.length) kinds.add('send');
      if (kinds.size) {
        const message = messages.at(-1), object = message?.objects.find(item => item.artifactId === artifactId);
        const last = related.at(-1), actorId = message?.to ?? last?.effect.actorId ?? last?.effect.authorityId ?? last?.holding?.actorId ?? artifact.creator;
        const explicit = [...related].reverse().find(item => item.effect.actorId === actorId && item.effect.representationId !== undefined);
        const representationId = object?.representationId ?? explicit?.effect.representationId;
        const preferred = [...related].reverse().find(item => item.holding?.actorId === actorId && (representationId === undefined || item.holding.representationId === representationId))?.holding;
        const source = data.steps[index];
        rows.push(freeze({ ...source, id: `held-trace:${encodeURIComponent(compiled.contextId)}:${encodeURIComponent(artifactId)}:${index}:${encodeURIComponent(milestone.id)}`,
          sourceIndex: index, sourceStepId: source.id, artifactId, heldContextId: compiled.contextId, heldCursorStart: previous, heldCursorEnd: end,
          ...(message ? { messageId: message.messageId } : {}),
          traceKind: [...kinds].join('/'), title: `${artifact.label}: ${[...kinds].join(', ')}`, from: messages[0]?.from ?? actorId, to: message?.to ?? actorId,
          ...occurrence(data.checkpoints.get(end), data.checkpoints.get(previous), actorId, representationId, preferred),
          attributeOperations: [], attributeValues: {}, protocolEffects: [], checks: [] }));
      }
      previous = end;
    }
  }
  const trace = freeze(rows); data.trace.set(artifactId, trace); return trace;
}

/** Translate animation time only to explicitly authored semantic milestones. */
export function heldCursorForPlayback(compiled, playerSnapshot = {}, selectedStep, { initial = false, selected = false } = {}) {
  const data = engine(compiled);
  if (initial) return initialCursor;
  if (!selected && playerSnapshot.status === 'idle' && !playerSnapshot.step) return initialCursor;
  const row = selected ? selectedStep : playerSnapshot.step ?? selectedStep;
  if (!row) return initialCursor;
  if (row.heldContextId !== undefined) requireValue(row.heldContextId === compiled.contextId, 'Trace row belongs to a different context.');
  const stopped = selected || ['idle', 'complete', 'stopped'].includes(playerSnapshot.status);
  let progress;
  if (stopped || playerSnapshot.type === 'stepcomplete') progress = 1;
  else if (Number.isFinite(playerSnapshot.duration) && playerSnapshot.duration > 0) progress = Math.max(0, Math.min(1, (playerSnapshot.stepElapsed ?? playerSnapshot.elapsed ?? 0) / playerSnapshot.duration));
  else progress = 0;
  if (row.heldCursorStart && row.heldCursorEnd) {
    const start = canonical(data, row.heldCursorStart), end = canonical(data, row.heldCursorEnd);
    requireValue(data.positions.get(start) <= data.positions.get(end), 'Trace cursor interval is reversed.');
    if (progress >= 1) return end;
    if (progress <= 0) return start;
    if (start.eventIndex === end.eventIndex) {
      const event = data.events[end.eventIndex];
      const at = cursor => cursor.milestone === 'before' ? 0 : event.milestones.find(item => item.id === cursor.milestone).at;
      return canonical(data, { eventIndex: end.eventIndex, progress: at(start) + (at(end) - at(start)) * progress });
    }
    return start;
  }
  let index;
  if (row.sourceStepId !== undefined) index = data.steps.findIndex(step => step.id === row.sourceStepId);
  else if (row.sourceIndex !== undefined) index = row.sourceIndex;
  else index = data.steps.findIndex(step => step.id === row.id);
  requireValue(Number.isInteger(index) && index >= 0 && index < data.steps.length, 'Playback row has no valid source mapping.');
  if (row.sourceIndex !== undefined) requireValue(row.sourceIndex === index, 'Playback source ID/index disagree.');
  if (!selected && row.sourceStepId !== undefined && data.events[index].milestones.length === 1) {
    const queue = playerSnapshot.queue;
    if (Array.isArray(queue)) {
      const offset = Number.isInteger(playerSnapshot.queuePosition) ? playerSnapshot.queuePosition : queue.indexOf(row);
      const next = queue[offset + 1];
      if (next && (next.sourceStepId === data.steps[index].id || next.sourceIndex === index)) progress = 0;
    }
  }
  if (playerSnapshot.kind === 'connection' && !selected) {
    const messages = (data.events[index].messages || []).filter(message => message.from === row.from && message.to === row.to);
    if (messages.length) {
      const start = Math.min(...messages.map(message => message.start));
      const end = Math.max(...messages.map(message => message.end));
      progress = start + (end - start) * progress;
    }
  }
  // Adjacent attribute rows from an atomic event are independent views of the
  // same canonical interval, not independently applicable protocol effects.
  return canonical(data, { eventIndex: index, progress });
}
