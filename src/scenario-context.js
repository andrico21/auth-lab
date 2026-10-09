import {resolveKerberosContext} from './kerberos-context.js';

const contextClone=value=>Array.isArray(value)?value.map(contextClone):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,contextClone(item)])):value;
const contextSet=(object,path,value)=>{const keys=String(path).split('.');if(keys.some(key=>['__proto__','constructor','prototype'].includes(key)))return;let target=object;for(const key of keys.slice(0,-1)){if(!target[key]||typeof target[key]!=='object')target[key]={};target=target[key];}target[keys.at(-1)]=value;};
const contextGet=(object,path)=>String(path).split('.').reduce((value,key)=>value&&typeof value==='object'&&Object.hasOwn(value,key)?value[key]:undefined,object);
const contextOpaque=value=>/cipher|opaque|signature|signed[- ]?(?:wire|bytes)|encrypted|private|secret/i.test(String(value||''));
// A caller may retain the accepted qualified draft after constructing a fixture.
// Normalize that notation before scalar display projection; @REALM must never
// be reintroduced as part of the separately constructed service name.
function contextNormalizedPrincipal(model,context){
  const binding=(model.runtimeBindings||[]).find(item=>item.field==='servicePrincipal'&&item.regeneratesFixture);
  if(!binding||!context.servicePrincipal||!String(context.servicePrincipal).includes('@'))return context;
  const realm=(model.runtimeBindings||[]).find(item=>item.field==='kerberosRealm'&&!item.valueTemplate)?.example;
  const parsed=resolveKerberosContext({...context,kerberosRealm:context.kerberosRealm||realm||'A.EXAMPLE'},binding.example);
  return {...context,servicePrincipal:parsed.servicePrincipal};
}
export const scenarioBindingValue=(binding,context)=>binding.valueTemplate?String(binding.valueTemplate).replaceAll('{value}',()=>String(context[binding.field])):context[binding.field];
export function scenarioContextRows(model,actorId,context={}){
  context=contextNormalizedPrincipal(model,context);
  const actor=model.actors()[actorId];
  const fixed=(actor?.context||[]).map(row=>({...row,provenance:'example'}));
  const bound=(model.runtimeBindings||[]).filter(binding=>binding.actorId===actorId||binding.actorId===actor?.parentId).map(binding=>({key:binding.field,label:binding.label||binding.field,value:context[binding.field]?scenarioBindingValue(binding,context):binding.example||model.definitions()[binding.attributeId]?.example,provenance:context[binding.field]?'applied':'example'}));
  const seen=new Set();return [...fixed.filter(row=>!bound.some(binding=>binding.key===row.key)),...bound].filter(row=>{const key=JSON.stringify([row.key,row.label,row.value]);if(!row.value||seen.has(key))return false;seen.add(key);return true;});
}
// Rebuild a fixture from explicitly declared scalar paths. Opaque signed or
// encrypted representations are never text-patched. This is a simulation,
// not cryptographic issuance or a connection to the supplied addresses.
export function projectScenarioContext(model,steps,context={}){
  context=contextNormalizedPrincipal(model,context);
  const bindings=(model.runtimeBindings||[]).filter(binding=>context[binding.field]);
  const initialState=contextClone(model.initialState||{}),protocolValues=contextClone(model.protocolValues||{});
  const projected=steps.map(step=>{
    const next=contextClone(step);
    for(const binding of bindings){
      const value=scenarioBindingValue(binding,context);
      for(const item of next.payload||[])if(item.attributeId===binding.attributeId&&item.value===binding.example)item.value=value;
      for(const operation of next.attributeOperations||[])if(operation.attributeId===binding.attributeId&&operation.value===binding.example&&!contextOpaque(operation.representation)&&(!binding.fieldPaths||binding.fieldPaths.includes(operation.fieldPath)))operation.value=value;
      if(next.attributeValues?.[binding.attributeId]===binding.example)next.attributeValues[binding.attributeId]=value;
      for(const effect of next.protocolEffects||[])for(const path of binding.statePaths||[]){
        if(contextOpaque(path))continue;
        if(effect.path===path&&effect.value===binding.example)effect.value=value;
        else if(path.startsWith(effect.path+'.')&&effect.value&&typeof effect.value==='object'&&contextGet(effect.value,path.slice(effect.path.length+1))===binding.example)contextSet(effect.value,path.slice(effect.path.length+1),value);
      }
    }
    return next;
  });
  for(const binding of bindings){const value=scenarioBindingValue(binding,context);for(const path of binding.statePaths||[])if(!contextOpaque(path)&&contextGet(initialState,path)===binding.example)contextSet(initialState,path,value);for(const ref of binding.valueRefs||[])if(!contextOpaque(ref)&&protocolValues[ref]===binding.example)protocolValues[ref]=value;}
  return {steps:projected,initialState,protocolValues};
}
