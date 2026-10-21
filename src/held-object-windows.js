import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

// The model owns an explicit object/event ledger. No operation-name, packet-text,
// field-name or label inference is used to manufacture inventory possession.
export function buildWindowsHeldObjects(args) {
  if(!args?.model?.id?.startsWith('lab-win-'))return null;
  const ledger=args.model.windowsInventory;
  if(!ledger)throw new TypeError('Owned Windows scenario is missing its explicit inventory ledger.');
  const plan=createHeldObjectPlan(args);
  for(const artifact of ledger.artifacts){
    const {artifactId,type,label,creator,generation,representations,derivedFrom}=artifact;
    heldArtifact(plan,{artifactId,type,label,creator,generation,representations,...(derivedFrom?{derivedFrom}:{})});
  }
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    const event=ledger.events[step.id];
    if(!event)throw new TypeError('Missing Windows inventory event: '+step.id);
    plan.events[step.id]={milestones:event.milestones.map(milestone=>({...milestone,effects:milestone.effects.map(effect=>({...effect}))})),...(event.messages?{messages:event.messages.map(message=>({...message,objects:message.objects.map(object=>({...object}))}))}:{})};
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(event=>event.milestones.flatMap(milestone=>milestone.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const acquisitions=effects.filter(effect=>effect.op==='acquire'&&effect.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(acquisitions.map(effect=>effect.store))],categories:[...new Set(acquisitions.map(effect=>plan.artifacts.find(artifact=>artifact.artifactId===effect.artifactId).type))],rationale:'Complete explicit initial, transfer, local validation, credential unwrap and release ledger for this fixed Windows reference fixture.'});
  }
  plan.limitations.push('Synthetic symbolic reference fixtures, not captured Windows traffic or live interoperability evidence. Grouped handshakes disclose their scoped omissions in the source events.');
  return plan;
}
