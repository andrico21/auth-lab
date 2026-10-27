import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildWindowsProtectionHeldObjects(args){
  if(!['windows-remote-administration','windows-protection'].includes(args?.model?.family))return null;
  const inventory=args.model.workstationInventory;
  if(!inventory)throw new TypeError('Windows protection model requires a source-owned inventory.');
  const plan=createHeldObjectPlan(args);
  for(const entry of inventory.artifacts){
    const {artifactId,type,label,creator,generation,representations}=entry;
    heldArtifact(plan,{artifactId,type,label,creator,generation,representations});
  }
  plan.initial=inventory.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    const event=inventory.events[step.id];
    if(!event)throw new TypeError('Missing Windows protection inventory event: '+step.id);
    plan.events[step.id]={milestones:event.milestones.map(milestone=>({...milestone,effects:milestone.effects.map(effect=>({...effect}))})),...(event.messages?{messages:event.messages.map(message=>({...message,objects:message.objects.map(object=>({...object}))}))}:{})};
  }
  plan.bindings=inventory.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(event=>event.milestones.flatMap(milestone=>milestone.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const acquired=effects.filter(effect=>effect.op==='acquire'&&effect.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(acquired.map(effect=>effect.store))],categories:[...new Set(acquired.map(effect=>plan.artifacts.find(artifact=>artifact.artifactId===effect.artifactId).type))],rationale:'Explicit source-owned policy, proof, target context, isolated operation, protected carrier, receipt and local access decision. Inspectability does not confer possession.'});
  }
  plan.limitations.push('Source-qualified symbolic Windows security reference. No installed Windows/DC run, observed native token fields, synthetic event XML capture or general platform conformance is claimed. Linked lessons start separate contexts and transfer no credential.');
  return plan;
}
