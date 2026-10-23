import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildUnixWorkstationHeldObjects(args){
  if(!args?.model?.unixWorkstation)return null;
  const ledger=args.model.workstationInventory;
  if(!ledger)throw new TypeError('Unix workstation model requires explicit inventory.');
  const plan=createHeldObjectPlan(args);
  for(const artifact of ledger.artifacts)heldArtifact(plan,artifact);
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    const entry=ledger.events[step.id];
    if(!entry)throw new TypeError('Missing Unix workstation custody event: '+step.id);
    if(step.eventType==='message'){
      if(entry.messages?.length!==1||entry.messages[0].from!==step.from||entry.messages[0].to!==step.to)throw new TypeError('Unix workstation IPC endpoints must match their source event: '+step.id);
      if(!entry.messages[0].objects.length)throw new TypeError('Unix workstation message requires source-authored payload: '+step.id);
    }else if(entry.messages?.length)throw new TypeError('Unix workstation local operation cannot carry an IPC message: '+step.id);
    plan.events[step.id]={milestones:entry.milestones.map(m=>({...m,effects:m.effects.map(effect=>({...effect}))})),...(entry.messages?{messages:entry.messages.map(message=>({...message,objects:message.objects.map(object=>({...object}))}))}:{})};
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(e=>e.milestones.flatMap(m=>m.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const holdings=effects.filter(e=>e.op==='acquire'&&e.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(holdings.map(e=>e.store))],categories:[...new Set(holdings.map(e=>plan.artifacts.find(a=>a.artifactId===e.artifactId)?.type).filter(Boolean))],rationale:'Explicit local-owner inventory. Context-only display is inspection; policy evaluation and credential use have authored operations. Authentication, admission, session and operation grants have distinct source events.'});
  }
  plan.limitations.push('Documentation-backed deterministic fixture, not native Linux/macOS build or hardware conformance. Local IPC controls are symbolic authored call arguments/status, not private OS packet encodings. Opaque OS handles never stand in for transferred verifier/key bytes. Resource continuations select an explicit RFC4120 AP/KRB_PRIV reference service, not an SMB/NFS implementation or production cryptographic computation.');
  return plan;
}
