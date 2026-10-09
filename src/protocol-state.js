/**
 * Source-event history for the offline protocol lab.
 *
 * Animation queues are projections of a scenario, never histories in their own
 * right. Pass a trace step's sourceIndex (or a full journey's step index) here.
 * Every preceding source event is applied, including events hidden by a filter.
 * Values are illustrative fixture data; this module performs no cryptography.
 */

function protocolClone(value, seen = new Set()) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') throw new TypeError('Protocol fixtures must contain plain data.');
    return value;
  }
  if (seen.has(value)) throw new TypeError('Protocol fixtures must not contain cycles.');
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new TypeError('Protocol fixtures must contain plain objects and arrays.');
  seen.add(value);
  const copy = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) {
    if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new TypeError('Unsafe protocol fixture key.');
    copy[key] = protocolClone(value[key], seen);
  }
  seen.delete(value);
  return copy;
}

function protocolFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(protocolFreeze);
    Object.freeze(value);
  }
  return value;
}

export const PROTOCOL_STATE_DEFAULTS = protocolFreeze({
  protocolClock: 0,
  credentials: {},
  caches: {},
  policy: {},
  knowledge: {},
  tokenConsumption: {},
  sessions: {},
  replayCache: [],
  outcome: {},
});

function protocolSteps(model) {
  const steps = typeof model?.steps === 'function' ? model.steps() : model?.steps;
  if (steps === undefined) return [];
  if (!Array.isArray(steps)) throw new TypeError('Scenario steps must be an array or a function returning an array.');
  return steps;
}

function protocolEndIndex(steps, eventIndex) {
  if (!Number.isInteger(eventIndex) || eventIndex < -1) throw new RangeError('Source event index must be an integer at least -1.');
  return Math.min(eventIndex, steps.length - 1);
}

function protocolInitialState(model) {
  const initial = typeof model?.initialState === 'function' ? model.initialState() : model?.initialState;
  if (initial !== undefined && (initial === null || Array.isArray(initial) || typeof initial !== 'object')) throw new TypeError('initialState must be a plain object.');
  const state = { ...protocolClone(PROTOCOL_STATE_DEFAULTS), ...protocolClone(initial || {}) };
  if (!Number.isFinite(state.protocolClock) || state.protocolClock < 0) throw new RangeError('The initial protocolClock must be non-negative finite seconds.');
  return state;
}

function protocolPath(path) {
  if (typeof path !== 'string' || !path.length) throw new TypeError('A protocol effect needs a non-empty path.');
  const parts = path.split('.');
  if (parts.some(part => !part.length || ['__proto__', 'prototype', 'constructor'].includes(part))) throw new TypeError('Unsafe or empty protocol effect path.');
  return parts;
}

function protocolEffectParent(state, parts, create) {
  let parent = state;
  for (const part of parts.slice(0, -1)) {
    if (!Object.hasOwn(parent, part)) {
      if (!create) return null;
      parent[part] = {};
    }
    if (parent[part] === null || typeof parent[part] !== 'object') throw new TypeError('A protocol path cannot traverse a primitive value.');
    parent = parent[part];
  }
  return parent;
}

function protocolApplyEffect(state, effect) {
  if (!effect || typeof effect !== 'object') throw new TypeError('A protocol effect must be an object.');
  const { op, path, value } = effect;
  if (op === 'advance') {
    if (path !== undefined && path !== 'protocolClock') throw new TypeError('advance may target only protocolClock.');
    if (!Number.isFinite(value) || value < 0) throw new RangeError('advance requires non-negative finite seconds.');
    const advanced = state.protocolClock + value;
    if (!Number.isFinite(advanced)) throw new RangeError('The protocolClock must remain finite.');
    state.protocolClock = advanced;
    return;
  }
  if (!['put', 'remove', 'append'].includes(op)) throw new TypeError('Unknown protocol effect operation.');
  const parts = protocolPath(path);
  if (parts[0] === 'protocolClock') throw new TypeError('Only advance may change protocolClock.');
  const parent = protocolEffectParent(state, parts, op !== 'remove');
  if (!parent) return;
  const leaf = parts.at(-1);
  if (op === 'remove') {
    delete parent[leaf];
  } else if (op === 'put') {
    if (!Object.hasOwn(effect, 'value')) throw new TypeError('put requires an explicit value.');
    parent[leaf] = protocolClone(value);
  } else {
    if (!Object.hasOwn(effect, 'value')) throw new TypeError('append requires an explicit value.');
    if (!Object.hasOwn(parent, leaf)) parent[leaf] = [];
    if (!Array.isArray(parent[leaf])) throw new TypeError('append requires an array at its path.');
    // An array value is one entry, not an implicit list of multiple events.
    parent[leaf].push(protocolClone(value));
  }
}

/**
 * Deeply frozen state after the inclusive source event index. -1 means the
 * preset's initial state, and an index beyond the end means the final state.
 * protocolClock is seconds and advances only through explicit advance effects.
 * A separate fixture field named clock is data, not an animation clock alias.
 */
export function reconstructProtocolState(model, eventIndex = -1) {
  const steps = protocolSteps(model);
  const end = protocolEndIndex(steps, eventIndex);
  const state = protocolInitialState(model);
  for (let index = 0; index <= end; index++) {
    const effects = steps[index].protocolEffects || [];
    if (!Array.isArray(effects)) throw new TypeError('protocolEffects must be an array.');
    for (const effect of effects) protocolApplyEffect(state, effect);
  }
  return protocolFreeze(state);
}

function protocolActorIds(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function protocolMetadata(operation) {
  return {
    creator: operation.creator ?? operation.creatorActorId,
    holders: protocolActorIds(operation.holders ?? operation.holderActorIds),
    inspectors: protocolActorIds(operation.inspectors ?? operation.permittedInspectorActorIds),
  };
}

function protocolValueTable(model) {
  const values = typeof model?.protocolValues === 'function' ? model.protocolValues() : model?.protocolValues;
  return values || {};
}

function protocolOccurrenceValue(operation, values) {
  if (Object.hasOwn(operation, 'value')) return protocolClone(operation.value);
  if (operation.exactValueRef !== undefined && Object.hasOwn(values, operation.exactValueRef)) return protocolClone(values[operation.exactValueRef]);
  return undefined;
}

function protocolValueIdentity(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify([typeof value, String(value)]);
  if (Array.isArray(value)) return JSON.stringify(['array', value.map(protocolValueIdentity)]);
  return JSON.stringify(['object', Object.keys(value).sort().map(key => [key, protocolValueIdentity(value[key])])]);
}

function protocolStableOccurrenceValue(operation, values, history) {
  const value = protocolOccurrenceValue(operation, values);
  if (value === undefined) return value;
  const key = JSON.stringify([operation.instanceId, operation.fieldPath ?? '', operation.representation ?? 'unspecified']);
  const identity = protocolValueIdentity(value);
  if (history.has(key) && history.get(key) !== identity) throw new TypeError('An immutable instance field cannot change its exact value in the same representation.');
  history.set(key, identity);
  return value;
}

/**
 * Object identity and exact field occurrences through the inclusive source
 * index. The returned array is ordered by first observed instance, with each
 * record containing {instanceId, definitionId, definitionIds, creator, holders,
 * inspectors, occurrences}. Each occurrence has eventId/eventIndex,
 * operationIndex, sourceEventId, actorId, kind, fieldPath, representation,
 * exactValueRef and its exact value. No glossary/example value is substituted.
 *
 * holders describe possession of the recorded representation. Receive/store
 * do not confer inspection permission; inspectors must be declared explicitly.
 * Deleting a cache does not erase its historical object/occurrence records.
 */
export function buildProtocolInstances(model, eventIndex = -1) {
  const steps = protocolSteps(model);
  const end = protocolEndIndex(steps, eventIndex);
  const values = protocolValueTable(model);
  const instances = new Map();
  const valueHistory = new Map();
  const instanceScope = model?.instanceScope;
  if (instanceScope !== undefined && (typeof instanceScope !== 'string' || !instanceScope)) throw new TypeError('instanceScope must be a non-empty fixture namespace.');
  for (let index = 0; index <= end; index++) {
    const step = steps[index];
    for (const [operationIndex, operation] of (step.attributeOperations || []).entries()) {
      if (!operation.instanceId) continue;
      const metadata = protocolMetadata(operation);
      const definitionId = operation.definitionId ?? operation.attributeId;
      const record = instances.get(operation.instanceId) || {
        instanceId: operation.instanceId, definitionId, definitionIds: [],
        creator: undefined, holders: [], inspectors: [], occurrences: [],
        ...(instanceScope !== undefined ? { instanceScope, qualifiedInstanceId: `${instanceScope}#${operation.instanceId}` } : {}),
      };
      if (definitionId !== undefined && !record.definitionIds.includes(definitionId)) record.definitionIds.push(definitionId);
      const creator = metadata.creator ?? (['create', 'derive'].includes(operation.kind) ? operation.actorId : undefined);
      if (creator !== undefined) {
        if (record.creator !== undefined && record.creator !== creator) throw new TypeError('An immutable protocol instance cannot change creator.');
        record.creator = creator;
      }
      for (const actorId of metadata.holders) if (!record.holders.includes(actorId)) record.holders.push(actorId);
      if (['create', 'derive', 'store', 'receive'].includes(operation.kind) && operation.actorId !== undefined && !record.holders.includes(operation.actorId)) record.holders.push(operation.actorId);
      for (const actorId of metadata.inspectors) if (!record.inspectors.includes(actorId)) record.inspectors.push(actorId);
      record.occurrences.push({
        definitionId,
        instanceId: operation.instanceId,
        ...(instanceScope !== undefined ? { instanceScope, qualifiedInstanceId: `${instanceScope}#${operation.instanceId}` } : {}),
        fieldPath: operation.fieldPath ?? '',
        representation: operation.representation ?? 'unspecified',
        eventId: step.id,
        sourceEventId: operation.sourceEventId ?? step.id,
        eventIndex: index,
        operationIndex,
        actorId: operation.actorId,
        kind: operation.kind,
        exactValueRef: operation.exactValueRef,
        value: protocolStableOccurrenceValue(operation, values, valueHistory),
        ...(operation.carriedAs ? { carriedAs: operation.carriedAs } : {}),
        creator: metadata.creator,
        holders: [...metadata.holders],
        inspectors: [...metadata.inspectors],
      });
      instances.set(operation.instanceId, record);
    }
  }
  return protocolFreeze([...instances.values()]);
}

/** Validate authored source events without requiring protocol data on legacy models. */
export function validateProtocolScenario(model) {
  const errors = [], warnings = [];
  const issue = (list, code, message, step, eventIndex, extra = {}) => list.push({ code, message, ...(step ? { eventId: step.id, eventIndex } : {}), ...extra });
  let steps, state, values, actors;
  try {
    steps = protocolSteps(model);
    state = protocolInitialState(model);
    values = protocolValueTable(model);
    actors = typeof model?.actors === 'function' ? model.actors() : model?.actors;
  } catch (error) {
    issue(errors, 'invalid-model', error.message);
    return protocolFreeze({ valid: false, errors, warnings });
  }
  const knownActors = actors && typeof actors === 'object' ? new Set(Object.keys(actors)) : null;
  if (model?.instanceScope !== undefined && (typeof model.instanceScope !== 'string' || !model.instanceScope)) issue(errors, 'invalid-instance-scope', 'instanceScope must be a non-empty fixture namespace.');
  const knownEvents = new Map();
  for (const [index, step] of steps.entries()) {
    if (!step.id || typeof step.id !== 'string') issue(errors, 'invalid-event-id', 'Every source event needs a string id.', step, index);
    else if (knownEvents.has(step.id)) issue(errors, 'duplicate-event-id', 'Source event ids must be unique.', step, index);
    else knownEvents.set(step.id, index);
  }
  const creators = new Map();
  const valueHistory = new Map();
  for (const [index, step] of steps.entries()) {
    const effects = step.protocolEffects || [];
    if (!Array.isArray(effects)) issue(errors, 'invalid-effects', 'protocolEffects must be an array.', step, index);
    else for (const [effectIndex, effect] of effects.entries()) {
      try { protocolApplyEffect(state, effect); }
      catch (error) { issue(errors, 'invalid-effect', error.message, step, index, { effectIndex, path: effect?.path }); }
    }
    const operations = step.attributeOperations || [];
    if (!Array.isArray(operations)) { issue(errors, 'invalid-operations', 'attributeOperations must be an array.', step, index); continue; }
    for (const [operationIndex, operation] of operations.entries()) {
      if (!operation || typeof operation !== 'object') { issue(errors, 'invalid-operation', 'An attribute operation must be an object.', step, index, { operationIndex }); continue; }
      if (knownActors && operation.actorId !== undefined && !knownActors.has(operation.actorId)) issue(errors, 'unknown-actor', 'An operation references an actor absent from the scenario registry.', step, index, { operationIndex, actorId: operation.actorId });
      if (!operation.instanceId) continue;
      const metadata = protocolMetadata(operation);
      if (typeof operation.instanceId !== 'string') issue(errors, 'invalid-instance-id', 'An immutable instanceId must be a string.', step, index, { operationIndex });
      if (typeof (operation.definitionId ?? operation.attributeId) !== 'string') issue(errors, 'missing-definition-id', 'An instance occurrence needs a definitionId or attributeId.', step, index, { operationIndex });
      if (operation.fieldPath !== undefined && typeof operation.fieldPath !== 'string') issue(errors, 'invalid-field-path', 'fieldPath must be a string; an empty string denotes the whole object.', step, index, { operationIndex });
      if (operation.representation === undefined) issue(warnings, 'unspecified-representation', 'Declare whether this occurrence is wire bytes, an opaque container or local decoded data.', step, index, { operationIndex });
      else if (typeof operation.representation !== 'string' || !operation.representation) issue(errors, 'invalid-representation', 'representation must be a non-empty string.', step, index, { operationIndex });
      if (operation.sourceEventId !== undefined && operation.sourceEventId !== 'initial') {
        const sourceIndex = knownEvents.get(operation.sourceEventId);
        if (sourceIndex === undefined) issue(errors, 'unknown-source-event', 'sourceEventId must identify an existing source event or initial.', step, index, { operationIndex });
        else if (sourceIndex > index) issue(errors, 'future-source-event', 'An occurrence cannot reference a future source event.', step, index, { operationIndex });
      }
      if (operation.exactValueRef !== undefined && typeof operation.exactValueRef !== 'string') issue(errors, 'invalid-value-reference', 'exactValueRef must be a string.', step, index, { operationIndex });
      else if (operation.exactValueRef !== undefined && !Object.hasOwn(operation, 'value') && !Object.hasOwn(values, operation.exactValueRef)) issue(errors, 'missing-exact-value', 'exactValueRef is absent from protocolValues and has no explicit operation value.', step, index, { operationIndex, exactValueRef: operation.exactValueRef });
      else if (!Object.hasOwn(operation, 'value') && operation.exactValueRef === undefined) issue(warnings, 'missing-exact-value', 'No exact occurrence value is supplied; the inspector will not substitute a glossary example.', step, index, { operationIndex });
      const creator = metadata.creator ?? (['create', 'derive'].includes(operation.kind) ? operation.actorId : undefined);
      if (creator !== undefined) {
        if (creators.has(operation.instanceId) && creators.get(operation.instanceId) !== creator) issue(errors, 'changed-instance-creator', 'An immutable instanceId cannot be reused for another creator.', step, index, { operationIndex, instanceId: operation.instanceId });
        else creators.set(operation.instanceId, creator);
      }
      for (const actorId of [metadata.creator, ...metadata.holders, ...metadata.inspectors].filter(id => id !== undefined)) {
        if (typeof actorId !== 'string') issue(errors, 'invalid-metadata-actor', 'Creator, holder and inspector identifiers must be strings.', step, index, { operationIndex });
        else if (knownActors && !knownActors.has(actorId)) issue(errors, 'unknown-metadata-actor', 'An instance metadata actor is absent from the scenario registry.', step, index, { operationIndex, actorId });
      }
      try { protocolStableOccurrenceValue(operation, values, valueHistory); }
      catch (error) { issue(errors, 'invalid-exact-value', error.message, step, index, { operationIndex }); }
    }
  }
  return protocolFreeze({ valid: errors.length === 0, errors, warnings });
}
