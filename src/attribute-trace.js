import {ATTRIBUTES} from './protocol-data.js';

export const TRACE_ACTION_LABELS = {create:'Create',derive:'Compute',store:'Store',use:'Use',verify:'Check',inspect:'Inspect',encrypt:'Encrypt',decrypt:'Decrypt',evict:'Evict',dispose:'Dispose',send:'Send',receive:'Receive'};

const traceCanonicalNames = name => String(name).replace(/^response\./,'').split(' / ').map(n=>n.replace(/\s*\([^)]*\)/g,'').trim());
function traceFieldValue(id,step,examples) {
  const names=traceCanonicalNames(ATTRIBUTES[id]?.name||id);
  const exact=step.payload.find(p=>p.attributeId===id);
  const match=step.payload.find(p=>!p.attributeId&&traceCanonicalNames(p.name).some(n=>names.includes(n)));
  return exact?.value ?? step.attributeValues?.[id] ?? match?.value ?? examples[id] ?? ATTRIBUTES[id]?.example ?? 'Illustrative value';
}

function traceSameCursor(left,right){
  return left===right||!!left&&!!right&&left.eventIndex===right.eventIndex&&left.milestone===right.milestone&&left.progress===right.progress;
}
function traceSameInterval(left,right){
  return left.messageId===right.messageId&&traceSameCursor(left.heldCursorStart,right.heldCursorStart)&&traceSameCursor(left.heldCursorEnd,right.heldCursorEnd);
}

/** Project explicit operations into transfers and local processing moments.
 * A stored field never becomes a packet merely because it is mentioned in a
 * request. Each explicit message is emitted once, followed by its receiver's local checks.
 */
export function buildAttributeTrace(usages,examples={},exactValues={}) {
  const queue=[];
  for(const usage of usages){
    const wireGroups=new Map();
    for(const action of usage.actions)if(action.kind==='send'||action.kind==='receive'){
      let group=wireGroups.get(action.messageId);
      if(!group){group={send:[],receive:null,emitted:false};wireGroups.set(action.messageId,group);}
      if(action.kind==='send')group.send.push(action);
      else if(!group.receive)group.receive=action;
    }
    let local=[];let sequence=0;
    const emit=(actions,from,to,kind)=>{
      const ids=[...new Set(actions.map(a=>a.attributeId))];
      const names=ids.map(id=>ATTRIBUTES[id]?.name||id);
      const title=kind==='send'?'Send '+names.join(', '):TRACE_ACTION_LABELS[kind]+' '+names.join(', ');
      const descriptions=[...new Set(actions.map(a=>a.detail))];
      const context=actions[0];
      const traceStep={...usage.step,
        id:'trace-'+usage.step.id+'-'+(++sequence),sourceStepId:usage.step.id,sourceIndex:usage.index,
        from,to,channel:from===to?'internal':context.channel||(context.messageId!==undefined?'network':usage.step.channel),
        title,summary:descriptions.join(' '),detail:descriptions.join(' '),fields:ids,
        payload:ids.map(id=>({name:ATTRIBUTES[id]?.name||id,value:actions.find(a=>a.attributeId===id&&Object.hasOwn(a,'value'))?.value??exactValues[actions.find(a=>a.attributeId===id&&a.exactValueRef)?.exactValueRef]??traceFieldValue(id,usage.step,examples),attributeId:id,
          description:actions.find(a=>a.attributeId===id)?.carriedAs ? 'Carried inside '+actions.find(a=>a.attributeId===id).carriedAs+'.' : undefined})),
        checks:[],traceKind:kind,traceActions:actions.map(a=>({...a})),
        ...(context.messageId!==undefined?{messageId:context.messageId,...(kind==='send'?{eventType:'message'}:{})}:{}),
        ...(context.protocolLabel!==undefined?{protocolLabel:context.protocolLabel}:{}),
        ...(context.layers?{layers:context.layers}:{}),
        ...(context.heldCursorStart&&context.heldCursorEnd?{heldCursorStart:context.heldCursorStart,heldCursorEnd:context.heldCursorEnd}:{}),
      };
      queue.push(traceStep);
    };
    const flush=()=>{if(local.length){emit(local,local[0].actorId,local[0].actorId,local[0].kind);local=[];}};
    for(const action of usage.actions){
      if(action.kind==='send'||action.kind==='receive'){
        flush();
        const group=wireGroups.get(action.messageId);
        if(!group.emitted){
          if(group.send.length&&group.receive)emit(group.send,group.send[0].actorId,group.receive.actorId,'send');
          group.emitted=true;
        }
      }else{
        if(local.length&&(local[0].actorId!==action.actorId||local[0].kind!==action.kind||!traceSameInterval(local[0],action)))flush();
        local.push(action);
      }
    }
    flush();
  }
  return queue;
}
