import { ACTORS } from './protocol-data.js';

// Shared authoring primitives. The operation ledger, rather than a field name
// appearing in explanatory text, is the authority for animated transmission.
export function labAttribute(name,meaning,origin,purpose,example,standard,source) {
  return {name,meaning,description:meaning,origin,generator:origin,purpose,example,standard,source};
}
export function labP(name,value,description,attributeId) {
  return {name,value,...(description?{description}:{}),...(attributeId?{attributeId}:{})};
}
export function labOp(ids,kind,actorId,detail,carriedAs) {
  return ids.map(attributeId=>({attributeId,kind,actorId,detail,...(carriedAs?{carriedAs}:{})}));
}
export function labWire(ids,from,to,detail,carriedAs) {
  return ids.flatMap(id=>[...labOp([id],'send',from,detail,carriedAs),...labOp([id],'receive',to,detail,carriedAs)]);
}
export function labStep(id,title,from,to,phase,channel,summary,detail,fields,payload,checks,attributeOperations) {
  return {id,title,from,to,phase,channel,summary,detail,fields,payload,checks,attributeOperations,universalLab:true};
}
function labFreeze(value) {
  if(value&&typeof value==='object'&&!Object.isFrozen(value)){
    Object.values(value).forEach(labFreeze);Object.freeze(value);
  }
  return value;
}
export function labActors(steps,specs) {
  const entries={};
  for(const step of steps)for(const operation of step.attributeOperations||[]){
    if(operation.kind==='inspect')continue;
    const id=operation.actorId;if(!entries[id])entries[id]=new Map();
    const kind=['create','derive'].includes(operation.kind)?'generated':operation.kind==='receive'?'received':'static';
    const weight={static:1,received:2,generated:3},old=entries[id].get(operation.attributeId);
    if(!old||weight[kind]>weight[old.kind])entries[id].set(operation.attributeId,{id:operation.attributeId,kind});
  }
  return Object.fromEntries(Object.entries(specs).map(([id,spec])=>[id,{...ACTORS[id],id,...spec,attributes:[...(entries[id]?.values()||[])],notes:spec.notes||[]}]));
}
export function labScenario(meta,attributes,stepsArray,actorSpecs) {
  const definitions=labFreeze({...attributes});
  const fixed=typeof stepsArray==='function'?null:labFreeze(stepsArray);
  const steps=config=>fixed||stepsArray(config||{});
  const fixedActors=fixed&&typeof actorSpecs!=='function'?labFreeze(labActors(fixed,actorSpecs)):null;
  const ids=[...new Set((fixed||steps({})).flatMap(step=>[...(step.fields||[]),...(step.attributeOperations||[]).map(op=>op.attributeId)]))];
  const model={...meta,universalLab:true,factorSelectable:false,jweAdaptable:false,
    ids,steps,actors:config=>fixedActors||labActors(steps(config),typeof actorSpecs==='function'?actorSpecs(config):actorSpecs),
    definitions:()=>definitions,examples:()=>Object.fromEntries(Object.entries(definitions).map(([id,def])=>[id,def.example]))};
  return model;
}
