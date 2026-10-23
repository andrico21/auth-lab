import {createHeldObjectPlan,heldArtifact,heldCoverage} from './held-object-authoring.js';

export function buildJWTHeldObjects(args) {
  if(!/^lab-jwt\d{2}$/.test(args?.model?.id||''))return null;
  const ledger=args.model.jwtInventory;
  if(!ledger)throw new TypeError('JWT scenario requires an explicit source-owned inventory.');
  const plan=createHeldObjectPlan(args);
  for(const artifact of ledger.artifacts)heldArtifact(plan,artifact);
  plan.initial=ledger.initial.map(effect=>({...effect}));
  for(const step of args.steps){
    const event=ledger.events[step.id];
    if(!event)throw new TypeError('Missing JWT held event: '+step.id);
    plan.events[step.id]={milestones:event.milestones.map(m=>({...m,effects:m.effects.map(effect=>({...effect}))})),...(event.messages?{messages:event.messages.map(m=>({...m,objects:m.objects.map(object=>({...object}))}))}:{})};
  }
  plan.bindings=ledger.bindings.map(binding=>({...binding}));
  const effects=[...plan.initial,...Object.values(plan.events).flatMap(e=>e.milestones.flatMap(m=>m.effects))];
  for(const actorId of Object.keys(plan.actors)){
    const acquired=effects.filter(effect=>effect.op==='acquire'&&effect.actorId===actorId);
    heldCoverage(plan,actorId,{stores:[...new Set(acquired.map(e=>e.store))],categories:[...new Set(acquired.map(e=>plan.artifacts.find(a=>a.artifactId===e.artifactId).type))],rationale:'Explicit generation/representation ledger; readable-untrusted JWS, recipient-local decrypt, signature evidence and accepted claims remain distinct.'});
  }
  plan.limitations.push('Offline symbolic fixture verdicts are not production cryptographic verification, issuer availability or live-platform interoperability. Actual encoded JSON does not imply numerical signature or ciphertext validity.');
  return plan;
}
