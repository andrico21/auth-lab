import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildNFSHeldObjects(args){
  const ledger=args?.model?.nfsInventory;
  if(!ledger)return null;
  const plan=createHeldObjectPlan(args);
  for(const artifact of ledger.artifacts)heldArtifact(plan,artifact);
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    const entry=ledger.events[step.id];
    if(!entry)throw new TypeError('NFS canonical event lacks explicit inventory authoring: '+step.id);
    plan.events[step.id]={milestones:entry.milestones.map(m=>({...m,effects:m.effects.map(e=>({...e}))})),...(entry.messages?{messages:entry.messages.map(m=>({...m,objects:m.objects.map(o=>({...o}))}))}:{})};
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(event=>event.milestones.flatMap(m=>m.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const acquisitions=effects.filter(e=>e.op==='acquire'&&e.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(acquisitions.map(e=>e.store))],categories:[...new Set(acquisitions.map(e=>plan.artifacts.find(a=>a.artifactId===e.artifactId)?.type).filter(Boolean))],rationale:'Source-authored NFS inventory: separate user/machine credentials, GSS generations, client/session/slot state, local mapping/export/file policy, protected receipt and receiver-local acceptance.'});
  }
  plan.limitations.push('Symbolic documentation-backed protocol fixture. No native mount, kernel/build verification, cross-platform interoperability or computed cryptographic bytes. NFS14/GSSv3/pNFS/delegation deferred.');
  return plan;
}
