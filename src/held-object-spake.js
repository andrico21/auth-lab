import {createHeldObjectPlan,heldArtifact,heldAt,heldAcquire,heldCoverage} from './held-object-authoring.js';

export function buildSpakeHeldObjects(args) {
  if(!args.model?.id?.startsWith('lab-krb-spake-'))return null;
  const plan=createHeldObjectPlan(args), id=args.model.id, ledger=args.model.heldObjectLedger;
  const live=new Map();
  const source=suffix=>suffix===null?null:id+'-'+suffix;
  const acquire=(event,object,actor,representationId,store='working memory',retention='temporary')=>{
    const effect=heldAcquire(object.instanceId,actor,store,{representationId,retention});
    if(!live.has(effect.holdingId)){heldAt(plan,event,effect);live.set(effect.holdingId,effect);}
  };
  for(const object of ledger.objects){
    heldArtifact(plan,{artifactId:object.instanceId,type:'kerberos-spake-object',label:object.label,creator:object.creator,sourceEventId:object.sourceEventId,generation:object.generation||0,protection:object.protection,keyRef:object.keyRef?id+':'+object.keyRef:undefined,representations:object.representations.map(rep=>({representationId:rep.id,format:rep.id==='opaque'?'protected Kerberos bytes':rep.id==='decoded'?'decoded protected fields':'symbolic protocol value',readableBy:rep.readers,fields:object.fields.filter(field=>!rep.fields||rep.fields.includes(field.name)).map(field=>({attributeId:field.id,name:field.name,value:field.value,readableBy:rep.readers,fieldPath:object.key+'.'+field.name}))}))});
    heldAt(plan,object.sourceEventId,{op:'create',artifactId:object.instanceId});
    if(object.created===null)for(const actor of object.initialHolders||[object.creator])acquire(null,object,actor,object.representations[0].id,object.key==='unrelated'?'credential cache':'configuration','retained');
    else for(const rep of object.representations)if(rep.id===object.representations[0].id||rep.readers.includes(object.creator))acquire(object.sourceEventId,object,object.creator,rep.id);
  }
  for(const event of ledger.events){
    const eventId=source(event.suffix), local=event.fromActor===event.toActor;
    for(const use of event.uses){
      const object=ledger.objects.find(item=>item.key===use.key);
      if(!object)throw new Error('Unauthored SPAKE holding '+use.key);
      const rep=object.representations.find(item=>item.id===use.representation);
      acquire(eventId,object,event.fromActor,rep.id);
      if(local)heldAt(plan,eventId,{op:'observe',artifactId:object.instanceId,actorId:event.fromActor,representationId:rep.id,kind:event.suffix.includes('validate')||event.suffix==='session'?'verification':'knowledge',result:event.detail});
      if(!local){
        acquire(eventId,object,event.toActor,rep.id,'received bytes');
        const target=plan.events[eventId];target.messages||=[];
        let message=target.messages.find(item=>item.from===event.fromActor&&item.to===event.toActor);
        if(!message){message={messageId:eventId+':'+event.fromActor+'->'+event.toActor,from:event.fromActor,to:event.toActor,objects:[],start:0,end:1};target.messages.push(message);}
        message.objects.push({artifactId:object.instanceId,representationId:rep.id});
      }
    }
  }
  for(const [suffix,keys] of [['cache',[['tgt','opaque'],['tgt-session','local']]],['service-cache',[['service-ticket','opaque'],['service-session','local']]]]){
    if(!ledger.events.some(event=>event.suffix===suffix))continue;
    for(const [key,rep] of keys){const object=ledger.objects.find(item=>item.key===key);acquire(source(suffix),object,'spake-client',rep,'credential cache','retained');}
    for(const [key,rep] of keys)heldAt(plan,source(suffix),{op:'observe',artifactId:id+':'+key,actorId:'spake-client',representationId:rep,kind:'acceptance',result:'Validated credential accepted into client cache at '+suffix});
    for(const [key,rep] of keys)plan.bindings.push({path:suffix==='cache'?'credentials.tgt':'credentials.serviceTicket',actorId:'spake-client',artifactId:id+':'+key,representationId:rep,store:'credential cache'});
  }
  const serviceSession=ledger.objects.find(object=>object.key==='service-session');
  if(serviceSession){acquire(source('service-validate'),serviceSession,'spake-service','local','authenticated context','retained');plan.bindings.push({path:'service.authenticatedClient',actorId:'spake-service',artifactId:serviceSession.instanceId,representationId:'local',store:'authenticated context'});}
  const cleanup={'spake-client':ledger.events.some(event=>event.suffix==='session')?'session':'client-cleanup','spake-kdc':'kdc-cleanup','spake-tgs':'tgs-cleanup','spake-service':'service-cleanup','spake-observer':'observer-cleanup'};
  for(const effect of live.values())if(effect.retention==='temporary'){
    const abandoned=effect.artifactId.startsWith(id+':optimistic-');
    const object=ledger.objects.find(item=>item.instanceId===effect.artifactId);
    const suffix=object.releaseAt?.[effect.actorId]||(abandoned?(effect.actorId==='spake-client'?'transcript-reset':'kdc-transcript-reset'):cleanup[effect.actorId]);
    if(!suffix||!ledger.events.some(event=>event.suffix===suffix))throw new Error('Missing endpoint-local SPAKE release event for '+effect.actorId);
    heldAt(plan,source(suffix),{op:'release',holdingId:effect.holdingId});
  }
  for(const actor of Object.keys(plan.actors))heldCoverage(plan,actor,{stores:['configuration','working memory','received bytes','credential cache','authenticated context'],categories:['configured trust','local key derivation','exact protected and decoded representations','accepted credentials','authenticated session key'],rationale:'Scenario-owned explicit protocol object ledger; acquisition uses exact receipt and validation events, never inferred attribute operations.'});
  return plan;
}
