import {createHeldObjectPlan,heldArtifact,heldAt,heldAcquire,heldCoverage} from './held-object-authoring.js';

// Custody is explicit source data, not inferred from DNS names, prose or flags.
export function buildDNSSECHeldObjects(args){
  const {model,steps,actors}=args;
  if(!/^lab-dnssec\d{2}$/.test(model?.id||''))return null;
  const ledger=model.dnssecInventory;
  if(!ledger)throw new TypeError('DNSSEC model requires its source-owned inventory.');
  const plan=createHeldObjectPlan(args),definitions=new Map(),stores=new Map(Object.keys(actors).map(id=>[id,new Set()])),categories=new Map(Object.keys(actors).map(id=>[id,new Set()]));
  for(const definition of ledger.artifacts){heldArtifact(plan,definition);definitions.set(definition.artifactId,definition);}
  const effect=entry=>{
    if(entry.op==='acquire'){
      if(!stores.has(entry.actorId)||!definitions.has(entry.artifactId))throw new TypeError('Unknown DNSSEC holding actor/artifact.');
      stores.get(entry.actorId).add(entry.store);categories.get(entry.actorId).add(definitions.get(entry.artifactId).type);
      return heldAcquire(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain',retention:entry.retention,holdingId:entry.holdingId});
    }
    return {...entry};
  };
  heldAt(plan,null,...ledger.initial.map(effect));
  for(const step of steps){
    const event=ledger.events[step.id];if(!event)throw new TypeError('Missing explicit DNSSEC inventory event '+step.id);
    // Explicit milestones replace the default complete-held group. The existing reducer partitions source state effects.
    if(event.milestones)plan.events[step.id]={milestones:event.milestones.map(milestone=>({...milestone,effects:milestone.effects.map(effect),...(milestone.stateEffects?{stateEffects:milestone.stateEffects.map(entry=>({...entry}))}:{})}))};
    else heldAt(plan,step.id,...event.effects.map(effect));
    if(event.messages.length)plan.events[step.id].messages=event.messages.map(message=>({...message,objects:message.objects.map(object=>({...object}))}));
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  plan.limitations=['Deterministic synthetic DNS records; browser signature checks are reference-bound symbolic checks, not numerical crypto or live DNS.','Public records are readable before trust. The selected resolver and validator share memory; a local check creates neither a network hop nor a duplicate key holding.','Received records may remain in teaching inspection buffers. Only explicit cache-entry objects represent reusable cache state. Pre-signed authoritative data does not imply a private signing key at a serving node.','Transport confidentiality and endpoint authentication apply only to their explicitly declared hop; neither is a DNSSEC verdict.'];
  for(const actorId of Object.keys(actors))heldCoverage(plan,actorId,{stores:[...stores.get(actorId)],categories:[...categories.get(actorId)],status:'complete',rationale:'Complete for the explicit initial, creation, publication, message, observation, cache and disposal operations in this selected synthetic case.'});
  return plan;
}
