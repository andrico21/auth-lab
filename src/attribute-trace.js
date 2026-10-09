import {ATTRIBUTES} from './protocol-data.js';

export const TRACE_ACTION_LABELS = {create:'Create',derive:'Compute',store:'Store',use:'Use',verify:'Check',send:'Send',receive:'Receive'};

const traceCanonicalNames = name => String(name).replace(/^response\./,'').split(' / ').map(n=>n.replace(/\s*\([^)]*\)/g,'').trim());
function traceFieldValue(id,step,examples) {
  const names=traceCanonicalNames(ATTRIBUTES[id]?.name||id);
  const exact=step.payload.find(p=>p.attributeId===id);
  const match=step.payload.find(p=>!p.attributeId&&traceCanonicalNames(p.name).some(n=>names.includes(n)));
  return exact?.value ?? step.attributeValues?.[id] ?? match?.value ?? examples[id] ?? ATTRIBUTES[id]?.example ?? 'Illustrative value';
}

/** Project explicit operations into transfers and local processing moments.
 * A stored field never becomes a packet merely because it is mentioned in a
 * request. A transfer is emitted once, followed by its receiver's local checks.
 */
export function buildAttributeTrace(usages,examples={}) {
  const queue=[];
  for(const usage of usages){
    let local=[];let wireEmitted=false;let sequence=0;
    const emit=(actions,from,to,kind)=>{
      const ids=[...new Set(actions.map(a=>a.attributeId))];
      const names=ids.map(id=>ATTRIBUTES[id]?.name||id);
      const title=kind==='send'?'Send '+names.join(', '):TRACE_ACTION_LABELS[kind]+' '+names.join(', ');
      const descriptions=[...new Set(actions.map(a=>a.detail))];
      const traceStep={...usage.step,
        id:'trace-'+usage.step.id+'-'+(++sequence),sourceStepId:usage.step.id,sourceIndex:usage.index,
        from,to,channel:from===to?'internal':usage.step.channel,
        title,summary:descriptions.join(' '),detail:descriptions.join(' '),fields:ids,
        payload:ids.map(id=>({name:ATTRIBUTES[id]?.name||id,value:traceFieldValue(id,usage.step,examples),attributeId:id,
          description:actions.find(a=>a.attributeId===id)?.carriedAs ? 'Carried inside '+actions.find(a=>a.attributeId===id).carriedAs+'.' : undefined})),
        checks:[],traceKind:kind,traceActions:actions.map(a=>({...a})),
      };
      queue.push(traceStep);
    };
    const flush=()=>{if(local.length){emit(local,local[0].actorId,local[0].actorId,local[0].kind);local=[];}};
    for(const action of usage.actions){
      if(action.kind==='send'||action.kind==='receive'){
        flush();
        if(!wireEmitted){
          const send=usage.actions.filter(a=>a.kind==='send');
          const receive=usage.actions.find(a=>a.kind==='receive');
          if(send.length&&receive)emit(send,send[0].actorId,receive.actorId,'send');
          wireEmitted=true;
        }
      }else{
        if(local.length&&(local[0].actorId!==action.actorId||local[0].kind!==action.kind))flush();
        local.push(action);
      }
    }
    flush();
  }
  return queue;
}
