import {createHeldObjectPlan,heldArtifact,heldAt,heldAcquire,heldRelease,heldCoverage} from './held-object-authoring.js';

// The model-owned ledger is authored alongside the protocol worksheet. This
// builder never infers possession from payload text or attribute operations.
export function buildNetworkHeldObjects(args){
  const {model,steps,actors}=args;
  if(!model?.id?.startsWith('lab-net-'))return null;
  if(!model.networkInventory)throw new TypeError('Owned network model requires an explicit inventory ledger.');
  const ledger=model.networkInventory,plan=createHeldObjectPlan(args);
  const stores=new Map(Object.keys(actors).map(id=>[id,new Set()]));
  const categories=new Map(Object.keys(actors).map(id=>[id,new Set()]));
  const definitions=new Map();
  for(const definition of ledger.artifacts){heldArtifact(plan,definition);definitions.set(definition.artifactId,definition);}
  const effect=entry=>{
    if(entry.op==='acquire'){
      if(!stores.has(entry.actorId))throw new TypeError('Unknown network holding actor '+entry.actorId);
      stores.get(entry.actorId).add(entry.store);categories.get(entry.actorId).add(definitions.get(entry.artifactId).type);
      return heldAcquire(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain',retention:entry.retention||(entry.store==='pending inbox'?'temporary':'retained')});
    }
    if(entry.op==='release')return heldRelease(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain'});
    return {...entry};
  };
  heldAt(plan,null,...ledger.initial.map(effect));
  for(const step of steps){
    const event=ledger.events[step.id];
    if(!event)throw new TypeError('Missing explicit network inventory event '+step.id);
    heldAt(plan,step.id,...event.effects.map(effect));
    if(event.messages.length)plan.events[step.id].messages=event.messages.map((message,index)=>({messageId:step.id+':wire:'+index,...message,objects:message.objects.map(object=>({...object}))}));
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  plan.limitations=['Synthetic symbolic values, not a packet capture or live implementation.','Complete inventory over authored protocol scope; no omitted wireless secure-association or MACsec keys are implied.'];
  for(const actorId of Object.keys(actors))heldCoverage(plan,actorId,{stores:[...stores.get(actorId)],categories:[...categories.get(actorId)],status:'complete',rationale:'Explicit initial, receive, local validation, enforcement and release ledger; no possession inference.'});
  return plan;
}
