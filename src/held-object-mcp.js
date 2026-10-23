import {createHeldObjectPlan,heldArtifact,heldAt,heldAcquire,heldRelease,heldCoverage} from './held-object-authoring.js';

// Source-owned operations are the sole authority. Neither labels nor payload
// parsing can manufacture credential possession or accepted authorization.
export function buildMCPHeldObjects(args){
  const {model,steps,actors}=args;
  if(!/^lab-mcp\d{2}$/.test(model?.id||''))return null;
  const ledger=model.mcpInventory;
  if(!ledger)throw new TypeError('MCP model requires its explicit inventory.');
  const plan=createHeldObjectPlan(args),stores=new Map(Object.keys(actors).map(id=>[id,new Set()])),categories=new Map(Object.keys(actors).map(id=>[id,new Set()])),definitions=new Map();
  for(const definition of ledger.artifacts){heldArtifact(plan,definition);definitions.set(definition.artifactId,definition);}
  const effect=entry=>{
    if(entry.op==='acquire'){
      if(!stores.has(entry.actorId)||!definitions.has(entry.artifactId))throw new TypeError('Unknown MCP holding actor/artifact.');
      stores.get(entry.actorId).add(entry.store);categories.get(entry.actorId).add(definitions.get(entry.artifactId).type);
      return heldAcquire(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain',retention:entry.retention,holdingId:entry.holdingId});
    }
    if(entry.op==='release')return heldRelease(entry.artifactId,entry.actorId,entry.store,{representationId:entry.representationId||'plain',holdingId:entry.holdingId});
    return {...entry};
  };
  heldAt(plan,null,...ledger.initial.map(effect));
  for(const step of steps){
    const event=ledger.events[step.id];
    if(!event)throw new TypeError('Missing explicit MCP inventory event '+step.id);
    heldAt(plan,step.id,...event.effects.map(effect));
    if(event.messages.length)plan.events[step.id].messages=event.messages.map((message,index)=>({messageId:step.id+':wire:'+index,...message,objects:message.objects.map(object=>({...object}))}));
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  plan.limitations=['Synthetic offline fixture values and symbolic signature/TLS evidence, not captured packets or live conformance.','Explicit inventory covers only authored client/resource/AS, proxy or local-process profile. TLS handshake and platform implementation internals are assumed, not fabricated.'];
  for(const actorId of Object.keys(actors))heldCoverage(plan,actorId,{stores:[...stores.get(actorId)],categories:[...categories.get(actorId)],status:'complete',rationale:'Explicit initial/create, protected wire receipt, local recovery, validation, policy and cleanup ledger.'});
  return plan;
}
