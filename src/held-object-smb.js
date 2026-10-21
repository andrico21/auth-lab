import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildSMBHeldObjects(args){
  if(!args?.model?.id?.startsWith('lab-smb-'))return null;
  const ledger=args.model.smbInventory;
  if(!ledger)throw new TypeError('SMB model has no explicit held-object ledger.');
  const plan=createHeldObjectPlan(args);
  for(const object of ledger.artifacts){const {artifactId,type,label,creator,generation,representations}=object;heldArtifact(plan,{artifactId,type,label,creator,generation,representations});}
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){const entry=ledger.events[step.id];if(!entry)throw new TypeError('SMB event has no held-object authoring: '+step.id);plan.events[step.id]={milestones:entry.milestones.map(m=>({...m,effects:m.effects.map(effect=>({...effect}))})),...(entry.messages?{messages:entry.messages.map(message=>({...message,objects:message.objects.map(object=>({...object}))}))}:{})};}
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(event=>event.milestones.flatMap(m=>m.effects))];
  for(const actorId of Object.keys(plan.actors)){const acquisitions=effects.filter(e=>e.op==='acquire'&&e.actorId===actorId);heldCoverage(plan,actorId,{stores:[...new Set(acquisitions.map(e=>e.store))],categories:[...new Set(acquisitions.map(e=>plan.artifacts.find(a=>a.artifactId===e.artifactId)?.type).filter(Boolean))],rationale:'Explicit fixed SMB3.1.1 profile inventory, including local desktop identity, mechanism credentials, signed SMB handles and independent authorization results.'});}
  plan.limitations.push('Symbolic protocol reference; no live OS/build interoperability, computed packet bytes or unmodeled SMB extensions.');
  return plan;
}
