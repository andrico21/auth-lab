import {createHeldObjectPlan,heldArtifact,heldAt,heldAcquire,heldRelease,heldCoverage} from './held-object-authoring.js';

// The family-owned source ledger is authoritative. No custody is inferred from
// packet prose, field names, actor placement or apparent operation labels.
export function buildKubernetesHeldObjects(args){
  const {model,steps,actors}=args;
  if(!/^lab-k8s(?:0[1-9]|1[0-5])$/.test(model?.id||''))return null;
  const ledger=model.kubernetesInventory;
  if(!ledger)throw new TypeError('Owned Kubernetes model requires an explicit inventory.');
  const plan=createHeldObjectPlan(args),definitions=new Map(),stores=new Map(Object.keys(actors).map(id=>[id,new Set()])),categories=new Map(Object.keys(actors).map(id=>[id,new Set()]));
  for(const definition of ledger.artifacts){heldArtifact(plan,definition);definitions.set(definition.artifactId,definition);}
  const effect=entry=>{
    if(entry.op==='acquire'){
      if(!stores.has(entry.actorId))throw new TypeError('Unknown Kubernetes logical holder '+entry.actorId);
      if(!definitions.has(entry.artifactId))throw new TypeError('Unknown Kubernetes held artifact '+entry.artifactId);
      stores.get(entry.actorId).add(entry.store);categories.get(entry.actorId).add(definitions.get(entry.artifactId).type);
      return heldAcquire(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain',retention:entry.retention||'retained'});
    }
    if(entry.op==='release')return heldRelease(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain'});
    return {...entry};
  };
  heldAt(plan,null,...ledger.initial.map(effect));
  for(const step of steps){
    const event=ledger.events[step.id];
    if(!event)throw new TypeError('Missing explicit Kubernetes source event '+step.id);
    heldAt(plan,step.id,...event.effects.map(effect));
    if(event.messages.length)plan.events[step.id].messages=event.messages.map((message,index)=>({messageId:step.id+':wire:'+index,...message,objects:message.objects.map(object=>({...object}))}));
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  plan.limitations=['Synthetic encoded JWS and SYM signature evidence, not mathematical signature verification.','Offline request/configuration fixtures, not live Kubernetes conformance.','API authentication, RBAC and admission are local stages. A read boundary does not assert an etcd RPC.'];
  for(const actorId of Object.keys(actors))heldCoverage(plan,actorId,{stores:[...stores.get(actorId)],categories:[...categories.get(actorId)],status:'complete',rationale:'Explicit source artifact, generation, local verification, receipt and store effects over the bounded authored scope.'});
  return plan;
}
