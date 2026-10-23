import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildWindowsWorkstationHeldObjects(args){
  const ledger=args?.model?.workstationInventory;
  if(!['windows-logon','windows-elevation'].includes(args?.model?.family))return null;
  if(!ledger)throw new TypeError('Windows workstation model requires an explicit inventory.');
  const plan=createHeldObjectPlan(args);
  for(const artifact of ledger.artifacts){const {artifactId,type,label,creator,generation,representations}=artifact;heldArtifact(plan,{artifactId,type,label,creator,generation,representations});}
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    if(!Object.hasOwn(ledger.events,step.id))throw new TypeError('Missing Windows workstation inventory event: '+step.id);
    const event=ledger.events[step.id];
    plan.events[step.id]={milestones:event.milestones.map(m=>({...m,effects:m.effects.map(effect=>({...effect}))})),...(event.messages?{messages:event.messages.map(m=>({...m,objects:m.objects.map(o=>({...o}))}))}:{})};
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  // A composed source may stop before its original cleanup. Close only live
  // temporary holdings, including the explicitly authored TGS inbox handoff.
  // Accepted credentials and preexisting authority/session holdings stay intact.
  const live=new Map();
  for(const effect of [...plan.initial,...args.steps.flatMap(step=>plan.events[step.id].milestones.flatMap(m=>m.effects))]){
    if(effect.op==='acquire')live.set(effect.holdingId,{...effect});
    else if(effect.op==='release')live.delete(effect.holdingId);
    else if(effect.op==='move'){
      const holding=live.get(effect.holdingId);
      if(!holding)throw new RangeError('Mapped Windows inventory moves an absent holding: '+effect.holdingId);
      live.delete(effect.holdingId);
      const holdingId=effect.toHoldingId||effect.holdingId;
      live.set(holdingId,{...holding,...effect,holdingId,retention:effect.retention??holding.retention});
    }
  }
  const terminal=plan.events[args.steps.at(-1).id].milestones.find(m=>m.id==='complete');
  for(const holding of live.values())if(holding.retention==='temporary')terminal.effects.push({op:'release',holdingId:holding.holdingId});
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(e=>e.milestones.flatMap(m=>m.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const acquired=effects.filter(e=>e.op==='acquire'&&e.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(acquired.map(e=>e.store))],categories:[...new Set(acquired.map(e=>plan.artifacts.find(a=>a.artifactId===e.artifactId).type))],rationale:'Explicit local, distinct-owner IPC, ticket receipt/acceptance, token lifecycle and credential cleanup holdings; inspection is not possession.'});
  }
  plan.limitations.push('Authored offline symbolic Windows workstation reference. No installed Windows build, token inspection, ETW, live smart card or DC interoperability evidence. Linked accepted SMB/AD lessons start their own contexts; navigation transfers no real credential.');
  return plan;
}
