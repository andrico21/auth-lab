// Inventory authoring primitives. These never infer possession from prose,
// attribute operation names, historical holders, or displayed field values.
export function createHeldObjectPlan({model,steps,actors,config={},contextId,choiceId}={}) {
  if(!Array.isArray(steps))throw new TypeError('Held-object authoring requires canonical source steps.');
  const sourceStepIds=steps.map(step=>step.id);
  if(sourceStepIds.some(id=>typeof id!=='string'||!id)||new Set(sourceStepIds).size!==sourceStepIds.length)throw new TypeError('Held-object source event IDs must be unique.');
  const registry=Array.isArray(actors)?Object.fromEntries(actors.map(actor=>[typeof actor==='string'?actor:actor.id,actor])):actors||{};
  return {
    scenarioId:model?.id||choiceId||'core',choiceId:choiceId||model?.id||'core',contextId,
    configuration:{...config},sourceStepIds,
    actors:Object.fromEntries(Object.entries(registry).map(([id,actor])=>[id,{id,name:actor?.name||id,...(actor?.parentId?{parentId:actor.parentId}:{})}])),
    artifacts:[],initial:[],events:{},bindings:[],limitations:[],interactions:[],
    coverage:Object.keys(registry).map(actorId=>({actorId,status:'not-modeled',stores:[],categories:[],gaps:[{reason:'Explicit inventory bindings have not been authored for this actor.'}],support:'supported'})),
  };
}

export function heldArtifact(plan,definition,{initial=false}={}) {
  if(!definition?.artifactId||plan.artifacts.some(artifact=>artifact.artifactId===definition.artifactId))throw new TypeError('Held-object artifact IDs must be unique: '+definition?.artifactId);
  const artifact={...definition,representations:(definition.representations||[]).map(representation=>({...representation,readableBy:[...(representation.readableBy||[])],fields:(representation.fields||[]).map(field=>({...field,...(field.readableBy?{readableBy:[...field.readableBy]}:{})}))}))};
  plan.artifacts.push(artifact);
  if(initial)plan.initial.push({op:'create',artifactId:artifact.artifactId});
  return artifact;
}

function heldAuthoredEvent(plan,sourceStepId) {
  if(!plan.sourceStepIds.includes(sourceStepId))throw new RangeError('Unknown held-object source event: '+sourceStepId);
  if(!Object.hasOwn(plan.events,sourceStepId))plan.events[sourceStepId]={milestones:[{id:'complete',at:1,effects:[]}]};
  return plan.events[sourceStepId];
}

export function heldAt(plan,sourceStepId,...effects) {
  const target=sourceStepId===null?plan.initial:heldAuthoredEvent(plan,sourceStepId).milestones.find(milestone=>milestone.id==='complete')?.effects;
  if(!target)throw new TypeError('This event has explicit milestones; append effects to its authored milestone.');
  for(const effect of effects.flat()){
    if(!effect||typeof effect!=='object')throw new TypeError('A held-object effect must be explicit data.');
    target.push(effect);
  }
  return plan;
}

function heldDefaultKey(artifactId,actorId,store,representationId) {
  if(![artifactId,actorId,store,representationId].every(value=>typeof value==='string'&&value.length))throw new TypeError('Holding identity requires an artifact, logical actor, representation and store.');
  return [actorId,artifactId,representationId,store].join('|');
}

export function heldAcquire(artifactId,actorId,store,{representationId='plain',retention='retained',holdingId,displayOrder}={}) {
  return {op:'acquire',holdingId:holdingId||heldDefaultKey(artifactId,actorId,store,representationId),actorId,artifactId,representationId,store,retention,...(displayOrder===undefined?{}:{displayOrder})};
}

export function heldRelease(artifactId,actorId,store,{representationId='plain',holdingId}={}) {
  return {op:'release',holdingId:holdingId||heldDefaultKey(artifactId,actorId,store,representationId)};
}

export function heldCoverage(plan,actorId,{stores=[],categories=[],gaps=[],status='complete',support='supported',...scope}={}) {
  if(!Object.hasOwn(plan.actors,actorId))throw new RangeError('Unknown held-object coverage actor: '+actorId);
  const record={actorId,status,stores:[...stores],categories:[...categories],gaps:gaps.map(gap=>typeof gap==='string'?{reason:gap}:{...gap}),support,...scope};
  const ranged=['fromEvent','toEvent','fromMilestone','toMilestone'].some(key=>Object.hasOwn(scope,key));
  if(!ranged)plan.coverage=plan.coverage.filter(previous=>previous.actorId!==actorId);
  else plan.coverage=plan.coverage.filter(previous=>previous.actorId!==actorId||['fromEvent','toEvent','fromMilestone','toMilestone'].some(key=>previous[key]!==record[key]));
  plan.coverage.push(record);
  return record;
}

// Objects in the same source transfer share one whole-message identity. Multiple
// animated attribute chips never become independent response deliveries.
export function heldWire(plan,sourceStepId,artifactId,from,to,{representationId='plain',fromStore='output',toStore='response',retention='temporary',releaseAt,releaseSender=true}={}) {
  if(retention==='temporary'&&!releaseAt)throw new TypeError('A temporary receipt requires an explicit release event.');
  const event=heldAuthoredEvent(plan,sourceStepId),messageId=sourceStepId+':'+from+'->'+to;
  if(!event.messages)event.messages=[];
  let message=event.messages.find(candidate=>candidate.messageId===messageId);
  if(!message){message={messageId,from,to,objects:[],start:0,end:1};event.messages.push(message);}
  if(message.objects.some(object=>object.artifactId===artifactId&&object.representationId===representationId))throw new TypeError('Duplicate held-object message representation.');
  message.objects.push({artifactId,representationId});
  heldAt(plan,sourceStepId,heldAcquire(artifactId,to,toStore,{representationId,retention}));
  if(releaseAt)heldAt(plan,releaseAt,heldRelease(artifactId,to,toStore,{representationId}));
  if(releaseSender)heldAt(plan,sourceStepId,heldRelease(artifactId,from,fromStore,{representationId}));
  return message;
}
