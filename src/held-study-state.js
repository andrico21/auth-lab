import { buildHeldObjects } from './held-objects.js';
import { projectHeldObjects, inspectHeldObject, heldObjectTrace, heldCursorForPlayback } from './held-object-state.js';
import { scenarioActorIds } from './workspaces.js';
import { heldInspectionHtml } from './held-study-projection.js';

export const holdingControlKey = holding => JSON.stringify([holding.contextId, holding.actorId, holding.artifactId, holding.representationId, holding.holdingId]);
export function orderedHoldings(holdings) {
  return [...holdings].sort((a,b) => (a.displayOrder ?? Number.MAX_SAFE_INTEGER) - (b.displayOrder ?? Number.MAX_SAFE_INTEGER) || (a.ordinal ?? 0) - (b.ordinal ?? 0) || a.holdingId.localeCompare(b.holdingId));
}
export function holdingSlots(holdings, pinnedId) {
  const ordered = orderedHoldings(holdings);
  if (ordered.length <= 3) return { visible: ordered, hidden: [] };
  const visible = ordered.slice(0,2), pinned = ordered.find(item => item.holdingId === pinnedId);
  if (pinned && !visible.includes(pinned)) visible[1] = pinned;
  return { visible, hidden: ordered.filter(item => !visible.includes(item)) };
}
export function detachedHoldingStatus(compiled, snapshot, selection) {
  if (!snapshot.artifacts.some(item => item.artifactId === selection.artifactId)) return 'Not created';
  const cursors=compiled.cursors||[],current=cursors.findIndex(cursor=>cursor.eventIndex===snapshot.cursor.eventIndex&&cursor.milestone===snapshot.cursor.milestone);
  const acquired=cursors.findIndex(cursor=>cursor.eventIndex===selection.acquiredAt?.eventIndex&&cursor.milestone===selection.acquiredAt?.milestone);
  if(acquired>current)return 'Not yet held';
  return 'No longer held';
}
export function logicalStudyActors(app) {
  if(app.scenarioOwnedActors)return app.scenarioOwnedActors;
  const ids=new Set(scenarioActorIds(app.scenarioSnapshot().steps).filter(Boolean).map(id=>app.actor(id).id));
  return Object.fromEntries([...ids].map(id=>[id,app.actor(id)]));
}

/** One immutable compilation/cursor and safe inspection state, independent of DOM. */
export class HeldStudyState {
  constructor(app) {
    this.app=app;this.memo=new WeakMap();this.visible=true;this.selection=null;this.actorId=null;this.inventoryTrigger=null;this.expanded=new Set();this.lastKey='';this.initial=true;this.selected=false;this.lastSnapshot=null;
  }
  compiled() {
    const app=this.app,source=app.scenarioSnapshot();let compiled=this.memo.get(source);
    if(!compiled){
      const actors=logicalStudyActors(app),base=app.labModel;
      const config={...app.protocolConfig(),oidcFlow:app.oidcFlow,tokenProtection:app.tokenProtection};
      const contextParts=[app.labScenarioId,config,app.runtimeEnvironment.revision];
      if(base?.variantId&&base.variantId!=='default')contextParts.push('variant='+base.variantId);
      if(base?.subfixtureId)contextParts.push('subfixture='+base.subfixtureId);
      const contextId=JSON.stringify(contextParts);
      // Inherit the frozen model instead of enumerating lazy Full-layout getters.
      const model=base?Object.create(base,{
        steps:{value:()=>source.steps,enumerable:true},
        initialState:{value:source.initialState||base.initialState,enumerable:true},
        protocolValues:{value:source.protocolValues||base.protocolValues,enumerable:true},
      }):null;
      compiled=buildHeldObjects({model,steps:source.steps,actors,config,contextId,choiceId:app.labScenarioId});this.memo.set(source,compiled);
    }
    if(this.contextId!==compiled.contextId){
      this.contextId=compiled.contextId;this.selection=null;this.actorId=compiled.actors[0]||null;this.inventoryTrigger=null;this.focusedId=null;this.helpOpen=false;this.previousHoldings=null;this.expanded.clear();this.app.objectTraceSelection=null;this.initial=true;this.selected=false;this.lastKey='';this.lastSnapshot=null;
    }
    return compiled;
  }
  snapshot(event=this.app.player.snapshot()) {
    const compiled=this.compiled();
    const cursor=event.inspectionCursor||heldCursorForPlayback(compiled,{...event,queue:this.app.player.queue},this.app.currentStep,{initial:this.initial!==false&&!event.step,selected:this.selected===true});
    return projectHeldObjects(compiled,cursor);
  }
  reset() {
    this.initial=true;this.selected=false;this.selection=null;this.inventoryTrigger=null;this.helpOpen=false;this.expanded.clear();this.lastKey='';this.lastSnapshot=null;this.app.objectTraceSelection=null;
  }
  event(event) {
    if(event.inspectionBoundary==='initial'){this.initial=true;this.selected=false;}
    else if(event.step){this.initial=false;this.selected=false;}
    const snapshot=this.snapshot(event);
    if(snapshot===this.lastSnapshot)return;
    this.lastSnapshot=snapshot;
    if(this.selection){
      const current=snapshot.holdings.find(item=>item.holdingId===this.selection.holdingId);
      if(current)this.selection={...current,inspected:this.selection.inspected,authority:this.selection.authority};
    }
  }
  selectStep(){this.initial=false;this.selected=true;this.lastKey='';this.lastSnapshot=null;}
  select(holding){this.selection={...holding};this.actorId=holding.actorId;this.expanded.add(holding.actorId);this.helpOpen=false;this.lastKey='';}
  buildTrace(artifactId){return heldObjectTrace(this.compiled(),artifactId);}
  inspectionData(snapshot=this.snapshot(),compiled=this.compiled()) {
    const selection=this.selection;if(!selection)return null;
    const holding=snapshot.holdings.find(item=>item.holdingId===selection.holdingId);
    const status=holding?'Currently held':detachedHoldingStatus(compiled,snapshot,selection);
    const inspected=holding?inspectHeldObject(snapshot,holding.holdingId):null;
    const artifact=compiled.plan.artifacts.find(item=>item.artifactId===selection.artifactId);
    // A former holder can only retain fields actually inspected while it held them.
    if(inspected){selection.inspected=inspected;selection.authority=snapshot.authority.filter(item=>item.artifactId===selection.artifactId);}
    const safe=inspected||selection.inspected,fields=safe?.fields||[];
    const observations=holding?snapshot.observations.filter(item=>item.artifactId===selection.artifactId&&item.actorId===selection.actorId):selection.inspected?.observations||[];
    const authority=holding?snapshot.authority.filter(item=>item.artifactId===selection.artifactId):selection.authority||[];
    const related=[...new Set([...(artifact?.derivedFrom||[]),...(artifact?.replaces||[]),...(artifact?.related||[])])].map(id=>({id,held:snapshot.holdings.some(item=>item.artifactId===id&&item.actorId===selection.actorId)}));
    return {selection,holding,status,artifact,fields,observations,authority,related,protocolClock:snapshot.protocolClock};
  }
  inspectionHtml(snapshot=this.snapshot(),compiled=this.compiled()) {
    return heldInspectionHtml(this.inspectionData(snapshot,compiled),{contextId:this.contextId,helpOpen:this.helpOpen,objectTraceSelection:this.app.objectTraceSelection});
  }
}
