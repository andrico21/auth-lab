import { createHeldObjectPlan, heldArtifact, heldAt, heldCoverage } from './held-object-authoring.js';

export function buildPakeHeldObjects(args = {}) {
  const { model, steps, actors } = args;
  if (!['pake-spake2', 'pake-spake2plus'].includes(model?.family)) return null;
  if (!model.pakeInventory || !Array.isArray(model.pakeInventory.artifacts)) throw new TypeError('Unsupported PAKE model: explicit inventory ledger required for ' + model.id);
  const ledger = model.pakeInventory, plan = createHeldObjectPlan(args);
  for (const definition of ledger.artifacts) heldArtifact(plan, definition);
  heldAt(plan, null, ...ledger.initial);
  for (const step of steps) {
    const authored = ledger.events[step.id];
    if (!authored) throw new TypeError('Missing PAKE inventory event: ' + step.id);
    heldAt(plan, step.id, ...authored.effects);
    if (authored.messages.length) plan.events[step.id].messages = authored.messages.map(message => ({ ...message, objects: message.objects.map(object => ({ ...object })) }));
  }
  plan.bindings = ledger.bindings.map(binding => ({ ...binding }));
  plan.limitations = [...ledger.limitations];
  const actorIds = Array.isArray(actors) ? actors.map(actor => typeof actor === 'string' ? actor : actor.id) : Object.keys(actors);
  const definitions = new Map(ledger.artifacts.map(artifact => [artifact.artifactId, artifact]));
  const effects = [...ledger.initial, ...steps.flatMap(step => ledger.events[step.id].effects)];
  for (const actorId of actorIds) {
    const acquisitions = effects.filter(effect => effect.op === 'acquire' && effect.actorId === actorId);
    heldCoverage(plan, actorId, {
      stores: [...new Set(acquisitions.map(effect => effect.store))],
      categories: [...new Set(acquisitions.map(effect => definitions.get(effect.artifactId).type))],
      rationale: 'Complete explicit PAKE initial, local creation, atomic receipt, local verification and disposal ledger at every canonical source cursor. No possession inferred from field operations.',
    });
  }
  return plan;
}
