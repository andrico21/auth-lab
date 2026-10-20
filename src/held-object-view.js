import { buildHeldObjects } from './held-objects.js';
import { projectHeldObjects, inspectHeldObject, heldObjectTrace, heldCursorForPlayback } from './held-object-state.js';
import { getPositions } from './layout.js';
import { scenarioPositions } from './workspaces.js';

const html = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const valueText = value => typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '');
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

// Prefer authored columns, minimizing necessary moves when a column is crowded.
// Hidden components keep their cells; inventory changes never move actors.
export function fullDockGeometry(actorIds, visibleIds, pairs, width, height = 730, aliases = {}, referencePositions) {
  if (width < 1120 || height < 730 || actorIds.length > 9 || !actorIds.length ||
      actorIds.some(id=>!Number.isFinite(referencePositions?.[id]?.x)||!Number.isFinite(referencePositions?.[id]?.y))) return null;
  let columns=actorIds.length===1?1:actorIds.length===2||actorIds.length===4?2:3,groups;
  for(;;){
    groups=Array.from({length:columns},()=>[]);
    for(const id of actorIds){
      const column=Math.max(0,Math.min(columns-1,Math.round((referencePositions[id].x+76)*columns/1120-.5)));
      groups[column].push(id);
    }
    const used=groups.filter(group=>group.length).length;
    if(used===columns)break;
    columns=used;
  }
  columns=Math.max(columns,Math.ceil(actorIds.length/3));
  const ordered=[...actorIds].sort(),preferred=ordered.map(id=>Math.max(0,Math.min(columns-1,Math.round((referencePositions[id].x+76)*columns/1120-.5))));
  const populations=new Uint8Array(columns);for(const column of preferred)populations[column]++;
  const rows=Math.min(3,Math.max(Math.ceil(actorIds.length/columns),...populations));
  const cells=Array.from({length:columns*rows},(_,index)=>({x:Math.round((index%columns+.5)*1120/columns-76),y:Math.round((Math.floor(index/columns)+.5)*730/rows)}));
  const size=1<<cells.length,moves=new Uint8Array(size).fill(255),distances=new Float64Array(size).fill(Infinity),counts=new Uint8Array(size),previous=new Uint16Array(size),chosen=new Uint8Array(size);
  moves[0]=0;distances[0]=0;let finish=-1,bestMoves=255,bestDistance=Infinity;
  for(let mask=0;mask<size;mask++){
    if(mask)counts[mask]=counts[mask>>1]+(mask&1);
    if(!Number.isFinite(distances[mask]))continue;
    const index=counts[mask];
    if(index===ordered.length){
      if(moves[mask]<bestMoves||moves[mask]===bestMoves&&distances[mask]<bestDistance){finish=mask;bestMoves=moves[mask];bestDistance=distances[mask];}
      continue;
    }
    const anchor=referencePositions[ordered[index]];
    for(let cell=0;cell<cells.length;cell++){
      if(mask&(1<<cell))continue;
      const next=mask|(1<<cell),point=cells[cell],nextMoves=moves[mask]+(cell%columns!==preferred[index]?1:0),distance=distances[mask]+(point.x-anchor.x)**2+(point.y-anchor.y)**2;
      if(nextMoves<moves[next]||nextMoves===moves[next]&&distance<distances[next]){moves[next]=nextMoves;distances[next]=distance;previous[next]=mask;chosen[next]=cell;}
    }
  }
  if(finish<0)return null;
  const positions={},bounds={};
  for(let index=ordered.length-1,mask=finish;index>=0;index--){
    const id=ordered[index],{x,y}=cells[chosen[mask]];
    positions[id]={x,y};bounds[id]={left:x-82,right:x+234,top:y-87,bottom:y+87};mask=previous[mask];
  }
  for(const [id,slot] of Object.entries(aliases))if(positions[slot])positions[id]=positions[slot];
  const visible = Object.fromEntries(visibleIds.filter(id => positions[id]).map(id => [id,positions[id]]));
  const rectangles = Object.entries(bounds).map(([id,b]) => ({id,left:b.left-10,right:b.right+10,top:b.top-10,bottom:b.bottom+10}));
  const routes = new Map();
  for (const [from,to] of pairs) {
    const key = from+'>'+to;
    if (routes.has(key)) continue;
    if (!visible[from] || !visible[to]) return null;
    const route = compositeRoute(from,to,positions,rectangles);
    if (!route) return null;
    routes.set(key,route);
  }
  return {mode:'full',positions:visible,bounds,routes,key:JSON.stringify([actorIds,visibleIds,pairs,aliases,referencePositions,'316x174-authored-capacity-v3'])};
}

// Compact controls keep fixed final CSS sizes. Only their reserved world-space
// envelope scales with the base map; route endpoints use the actual actor box.
export function compactDockGeometry(positions,pairs,cssWidth,cssHeight=cssWidth*730/1120,visibleWidth=cssWidth) {
  if(Math.min(cssWidth,visibleWidth)<960||!Number.isFinite(cssHeight)||cssHeight<=0||Object.keys(positions).length>9)return null;
  const scaleX=cssWidth/1120,scaleY=cssHeight/730,bounds={},actorBounds={};
  if(164*scaleX<140||174*scaleY<140)return null;
  for(const [id,p] of Object.entries(positions)){
    if(!Number.isFinite(p.x)||!Number.isFinite(p.y))return null;
    const b={left:p.x-82,right:p.x+82,top:p.y-87,bottom:p.y+87};
    if(b.left<10||b.right>1110||b.top<10||b.bottom>720)return null;
    bounds[id]=b;
    actorBounds[id]={left:p.x-66/scaleX,right:p.x+16/scaleX,top:p.y-66/scaleY,bottom:p.y+66/scaleY};
  }
  const entries=Object.entries(bounds);
  for(let i=0;i<entries.length;i++)for(let j=i+1;j<entries.length;j++){
    const a=entries[i][1],b=entries[j][1];
    if(a.left<b.right+20&&a.right+20>b.left&&a.top<b.bottom+20&&a.bottom+20>b.top)return null;
  }
  const rectangles=entries.map(([id,b])=>({id,left:b.left-10,right:b.right+10,top:b.top-10,bottom:b.bottom+10})),routes=new Map();
  for(const [from,to] of pairs){
    if(!positions[from]||!positions[to])return null;
    const key=from+'>'+to;if(routes.has(key))continue;
    const route=compositeRoute(from,to,positions,rectangles,actorBounds);if(!route)return null;routes.set(key,route);
  }
  return {mode:'compact',positions,bounds,actorBounds,routes,scaleX,scaleY,key:JSON.stringify([positions,pairs,cssWidth,cssHeight,'140x140-css-82x132-44x44-v1'])};
}
function compositeRoute(from,to,positions,rectangles,actorBounds) {
  const ports = id => {
    const p = positions[id],b=actorBounds?.[id]||{left:p.x-82,right:p.x+82,top:p.y-87,bottom:p.y+87},cx=(b.left+b.right)/2,cy=(b.top+b.bottom)/2;
    return [{x:p.x-92,y:cy,base:{x:b.left,y:cy}}, {x:cx,y:p.y-97,base:{x:cx,y:b.top}}, {x:cx,y:p.y+97,base:{x:cx,y:b.bottom}}];
  };
  const inside = p => rectangles.some(r => p.x > r.left && p.x < r.right && p.y > r.top && p.y < r.bottom);
  const clear = (a,b) => !rectangles.some(r => a.x===b.x ? a.x>r.left && a.x<r.right && Math.max(a.y,b.y)>r.top && Math.min(a.y,b.y)<r.bottom : a.y>r.top && a.y<r.bottom && Math.max(a.x,b.x)>r.left && Math.min(a.x,b.x)<r.right);
  const starts = ports(from), ends = ports(to);
  if (from === to) {
    const left=starts[0],top=starts[1],points=[left.base,{x:left.x,y:left.y},{x:left.x,y:top.y},{x:top.x,y:top.y},top.base];
    if(points.some(p=>p.x<10||p.y<10||p.x>1110||p.y>720)||points.slice(1,-1).some(inside)||!clear(points[1],points[2])||!clear(points[2],points[3]))return null;
    return points.map((p,i) => (i?'L ':'M ')+p.x+' '+p.y).join(' ');
  }
  const xs = [...new Set([10,1110,...rectangles.flatMap(r => [r.left,r.right]),...starts.map(p=>p.x),...ends.map(p=>p.x)])].sort((a,b)=>a-b);
  const ys = [...new Set([10,720,...rectangles.flatMap(r => [r.top,r.bottom]),...starts.map(p=>p.y),...ends.map(p=>p.y)])].sort((a,b)=>a-b);
  const nodes = new Map();
  for (const y of ys) for (const x of xs) if (x>=10 && x<=1110 && y>=10 && y<=720 && !inside({x,y})) nodes.set(x+','+y,{x,y,cost:Infinity,previous:null});
  const pending = new Set();
  for (const port of starts) { const node=nodes.get(port.x+','+port.y); if(node){node.cost=0;node.origin=port;pending.add(node);} }
  let finish;
  while (pending.size) {
    let node; for (const candidate of pending) if (!node || candidate.cost<node.cost) node=candidate;
    pending.delete(node); if(node.visited)continue;node.visited=true;
    const end=ends.find(p=>p.x===node.x && p.y===node.y); if(end){finish={node,end};break;}
    const xi=xs.indexOf(node.x),yi=ys.indexOf(node.y);
    for(const [x,y] of [[xs[xi-1],node.y],[xs[xi+1],node.y],[node.x,ys[yi-1]],[node.x,ys[yi+1]]]) {
      const next=nodes.get(x+','+y);if(!next || next.visited || !clear(node,next))continue;
      const cost=node.cost+Math.abs(x-node.x)+Math.abs(y-node.y);
      if(cost<next.cost){next.cost=cost;next.previous=node;next.origin=node.origin;pending.add(next);}
    }
  }
  if(!finish)return null;
  const points=[finish.end.base];let node=finish.node;
  while(node){points.unshift({x:node.x,y:node.y});if(!node.previous)points.unshift(node.origin.base);node=node.previous;}
  return points.map((p,i)=>(i?'L ':'M ')+p.x+' '+p.y).join(' ');
}

export class HeldObjectView {
  constructor(app) {
    this.app=app;this.memo=new WeakMap();this.visible=true;this.selection=null;this.actorId=null;this.expanded=new Set();this.lastKey='';
    this.root=app.querySelector('#held-objects');this.docks=app.querySelector('#held-docks');this.inspector=app.querySelector('#held-inspector');
    this.click=event=>this.onClick(event);app.addEventListener('click',this.click);
    this.focus=event=>{const control=event.target.closest('[data-held-key]');if(control)this.focusedId=control.dataset.holdingId;};app.addEventListener('focusin',this.focus);
    this.toggle=()=>{this.visible=app.querySelector('#show-held-objects').checked;this.lastKey='';this.render();if(!this.visible)app.querySelector('#show-held-objects').focus();};
    app.querySelector('#show-held-objects').addEventListener('change',this.toggle);
    this.escape=event=>{
      if(event.key!=='Escape'||!event.target.closest('#held-objects, #held-inspector, #held-docks'))return;
      const actor=this.selection?.actorId||this.actorId;
      if(this.helpOpen){this.helpOpen=false;this.lastKey='';this.render();this.inspector.querySelector('[data-held-help]')?.focus();return;}
      this.expanded.delete(actor);this.lastKey='';this.render();this.recoverFocus(null,actor);
    };app.addEventListener('keydown',this.escape);
    const controls=app.querySelector('#map-controls'),measureControls=()=>app.refs.graph.style.setProperty('--map-controls-height',controls.getBoundingClientRect().height+'px');
    measureControls();
    this.resize=()=>{
      measureControls();
      const previous=app.heldGeometry?.key,active=document.activeElement,key=active?.dataset?.heldKey||active?.dataset?.heldAction,actor=active?.dataset?.heldActor||active?.closest?.('[data-held-owner]')?.dataset?.heldOwner||this.selection?.actorId,owned=!!active?.closest?.('#held-objects, #held-inspector, #held-docks'),actorFocus=active?.dataset?.actor;
      this.configureGeometry();if(previous===app.heldGeometry?.key)return;
      if(owned&&active?.dataset?.holdingId&&actor){this.actorId=actor;this.expanded.add(actor);}
      app.renderActors();app.renderConnections();app.renderPacket(app.player.snapshot());this.lastKey='';this.render();
      if(owned)this.recoverFocus(key,actor);else if(actorFocus)app.refs.actors.querySelector(`[data-actor="${actorFocus}"]`)?.focus();
    };
    this.observer=typeof ResizeObserver==='function'?new ResizeObserver(this.resize):null;this.observer?.observe(app.refs.graph);this.observer?.observe(app.refs.graph.parentElement);this.observer?.observe(controls);
    this.motion=window.matchMedia('(prefers-reduced-motion: reduce)');this.motionChange=()=>app.player.setReducedMotion(this.motion.matches);this.motion.addEventListener?.('change',this.motionChange);this.motionChange();
  }
  destroy(){this.observer?.disconnect();this.motion.removeEventListener?.('change',this.motionChange);this.app.querySelector('#show-held-objects').removeEventListener('change',this.toggle);this.app.removeEventListener('click',this.click);this.app.removeEventListener('focusin',this.focus);this.app.removeEventListener('keydown',this.escape);}
  compiled() {
    const app=this.app,source=app.scenarioSnapshot();let compiled=this.memo.get(source);
    if(!compiled){
      const actors=logicalActorsForView(app);
      const config={...app.protocolConfig(),oidcFlow:app.oidcFlow,tokenProtection:app.tokenProtection};
      const contextId=JSON.stringify([app.labScenarioId,config,app.runtimeEnvironment.revision]);
      const model=app.labModel?{...app.labModel,steps:()=>source.steps,initialState:source.initialState||app.labModel.initialState,protocolValues:source.protocolValues||app.labModel.protocolValues}:null;
      compiled=buildHeldObjects({model,steps:source.steps,actors,config,contextId,choiceId:app.labScenarioId});this.memo.set(source,compiled);
    }
    if(this.contextId!==compiled.contextId){const hadFocus=this.app.contains(document.activeElement)&&!!document.activeElement?.closest?.('#held-objects, #held-inspector, #held-docks');this.contextId=compiled.contextId;this.selection=null;this.actorId=null;this.focusedId=null;this.helpOpen=false;this.previousHoldings=null;this.expanded.clear();this.app.objectTraceSelection=null;this.initial=true;this.selected=false;this.lastKey='';if(hadFocus)this.app.querySelector('#lab-scenario-search').focus();}
    return compiled;
  }
  snapshot(event=this.app.player.snapshot()) {
    const compiled=this.compiled();
    const cursor=heldCursorForPlayback(compiled,{...event,queue:this.app.player.queue},this.app.currentStep,{initial:this.initial!==false && !event.step,selected:this.selected===true});
    return projectHeldObjects(compiled,cursor);
  }
  configureGeometry(){
    const app=this.app,actors=logicalActorsForView(app),ids=[...new Set(Object.keys(actors).map(id=>app.nodeId(id)))];
    const all=[...new Set(Object.keys(actors).map(id=>actors[id].parentId||id))],aliases={};
    const active=new Set(app.steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(op=>op.actorId)]));
    for(const parent of [...all]){
      const children=Object.keys(actors).filter(id=>actors[id].parentId===parent);
      if(!active.has(parent)&&children.length){aliases[children[0]]=parent;all.push(...children.slice(1));}
      else all.push(...children);
    }
    const base=app.basePositions,visible=ids.filter(id=>base[id]),rect=app.refs.graph.getBoundingClientRect(),viewport=app.refs.graph.parentElement.getBoundingClientRect();
    const pairs=[...app.steps,...(app.hasTrace?app.traceQueue:[])].map(step=>[app.nodeId(step.from),app.nodeId(step.to)]);
    const width=Math.min(rect.width,viewport.width),height=rect.height;
    const compactPositions=Object.fromEntries(visible.map(id=>[id,base[id]]));
    const authored=app.labModel?.positions||app.labModel?.actorPositions||app.labModel?.layout?.positions||app.labModel?.layout||{};
    const reference=app.scenarioOwnedActors?{...scenarioPositions(app.labModel,app.steps,actors,true),...authored}:getPositions(app.architecture);
    for(const [child,parent] of Object.entries(aliases))if(reference[child])reference[parent]=reference[child];
    const anchors=Object.fromEntries(all.map(id=>[id,reference[id]||actors[id]?.position]));
    const signature=JSON.stringify([all,visible,pairs,width>=1120,height>=730,viewport.width,app.moveParticipants,!!app.customLayouts[app.layoutKey],aliases,compactPositions,anchors]);
    if(this.geometrySignature!==signature){
      this.geometrySignature=signature;
      const eligible=!app.moveParticipants&&!app.customLayouts[app.layoutKey];
      app.heldGeometry=eligible&&visible.every(id=>Object.keys(actors).filter(owner=>app.nodeId(owner)===id).length<=3)?fullDockGeometry(all,visible,pairs,width,height,aliases,anchors):null;
      if(eligible&&!app.heldGeometry)app.heldGeometry=compactDockGeometry(compactPositions,pairs,viewport.width,viewport.width*730/1120,width);
      if(app.heldGeometry?.mode==='compact'&&app.heldGeometry.key===this.rejectedCompactKey)app.heldGeometry=null;
    }
    app.refs.graph.dataset.heldGeometry=app.heldGeometry?.mode||'external';
  }
  reset(){const owned=!!document.activeElement?.closest?.('#held-objects, #held-inspector, #held-docks');this.initial=true;this.selected=false;this.selection=null;this.helpOpen=false;this.expanded.clear();this.lastKey='';this.app.objectTraceSelection=null;if(owned)this.app.querySelector('#lab-scenario-search').focus();}
  event(event){if(event.step){this.initial=false;this.selected=false;}if(['step','frame','stepcomplete','complete','state'].includes(event.type))this.render(event);}
  selectStep(){this.initial=false;this.selected=true;this.lastKey='';}
  onClick(event){
    const control=event.target.closest('[data-holding-id], [data-held-actor], [data-held-trace], [data-held-related], [data-held-exit], [data-held-help], [data-held-help-close]');if(!control)return;
    if(control.hasAttribute('data-held-help')||control.hasAttribute('data-held-help-close')){this.helpOpen=!this.helpOpen;this.lastKey='';this.render();this.inspector.querySelector(this.helpOpen?'[data-held-help-close]':'[data-held-help]')?.focus();return;}
    if(control.hasAttribute('data-held-exit')){this.app.clearAttribute();return;}
    if(control.hasAttribute('data-held-trace')){this.trace(control.dataset.heldTrace);return;}
    if(control.hasAttribute('data-held-related')){const artifactId=control.dataset.heldRelated;const holding=this.snapshot().holdings.find(item=>item.artifactId===artifactId&&item.actorId===this.selection?.actorId);if(holding)this.select(holding);return;}
    if(control.dataset.holdingId){const holding=this.snapshot().holdings.find(item=>item.holdingId===control.dataset.holdingId);if(holding)this.select(holding);return;}
    const fromDock=!!control.closest('#held-docks');this.actorId=control.dataset.heldActor;this.expanded.has(this.actorId)?this.expanded.delete(this.actorId):this.expanded.add(this.actorId);this.lastKey='';this.render();
    if(fromDock&&this.expanded.has(this.actorId)){this.root.querySelector(`[data-held-owner="${this.actorId}"] [data-holding-id]`)?.focus();this.root.scrollIntoView?.({block:'nearest'});}else this.recoverFocus(null,this.actorId);
  }
  select(holding){this.selection={...holding};this.actorId=holding.actorId;this.expanded.add(holding.actorId);this.helpOpen=false;this.lastKey='';this.render();}
  trace(artifactId){
    const app=this.app,compiled=this.compiled(),selection=this.selection;
    const artifact=compiled.plan.artifacts.find(item=>item.artifactId===artifactId),representation=artifact?.representations.find(item=>item.representationId===selection?.representationId);
    const readable=representation?.readableBy.includes(selection?.actorId);
    const allowed=new Map((representation?.fields||[]).filter(field=>readable&&(!field.readableBy||field.readableBy.includes(selection.actorId))).map(field=>[field.attributeId,field]));
    const queue=heldObjectTrace(compiled,artifactId).map(row=>({...row,payload:row.payload.map(field=>({...field,value:allowed.has(field.attributeId)?allowed.get(field.attributeId).value:'Not readable by this holder',redacted:!allowed.has(field.attributeId)}))}));
    if(!queue.length)return;
    app.player.stop(false);app.attributeSelection=null;app.objectTraceSelection=artifactId;app.traceQueue=queue;app.traceIndex=0;app.index=queue[0].sourceIndex;this.initial=false;
    app.inspection={type:'step'};this.configureGeometry();app.renderActors();app.renderConnections();app.renderTimeline();app.renderFocus();app.ensureRunningSpeed();app.player.play(queue,'object');
  }
  recoverFocus(key,actorId){
    const candidates=[...this.app.querySelectorAll('[data-held-key], [data-held-actor], [data-held-action]')];
    const control=candidates.find(item=>key&&(item.dataset.heldKey===key||item.dataset.heldAction===key)&&!item.closest('[hidden]')) || candidates.find(item=>item.dataset.heldActor===actorId&&!item.closest('[hidden]'));
    if(control){control.focus();return;}
    const actor=this.app.refs.actors.querySelector(`[data-actor="${this.app.nodeId(actorId)}"]`);
    (actor&&!actor.hidden?actor:this.app.querySelector('#show-held-objects')).focus();
  }
  render(event){
    const snapshot=this.snapshot(event),compiled=this.compiled(),app=this.app;
    if(this.selection){const moved=snapshot.holdings.find(item=>item.holdingId===this.selection.holdingId || item.actorId===this.selection.actorId&&item.artifactId===this.selection.artifactId&&item.representationId===this.selection.representationId&&item.ordinal===this.selection.ordinal);if(moved)this.selection={...this.selection,...moved};}
    const row=event?.step||app.currentStep;
    const key=JSON.stringify([snapshot.cursor,this.visible,this.selection?.holdingId,this.selection?.store,this.actorId,[...this.expanded],app.heldGeometry?.key,app.showInternals,this.helpOpen,this.focusedId,row?.id]);if(key===this.lastKey)return;this.lastKey=key;
    const active=document.activeElement,focusKey=active?.dataset?.heldKey||active?.dataset?.heldAction,focusActor=active?.dataset?.heldActor||active?.closest?.('[data-held-owner]')?.dataset?.heldOwner||this.selection?.actorId,owned=!!active?.closest?.('#held-objects, #held-inspector, #held-docks');
    this.root.hidden=!this.visible;this.docks.hidden=!this.visible;this.inspector.hidden=!this.visible||!this.selection;
    const artifacts=new Map(snapshot.artifacts.map(item=>[item.artifactId,item]));
    const actors=compiled.actors;
    if(!this.actorId||!actors.includes(this.actorId))this.actorId=actors[0];
    const button=holding=>{const artifact=artifacts.get(holding.artifactId),expired=artifact?.expiresAt!=null&&snapshot.protocolClock>=artifact.expiresAt;return `<button class="held-object-control" data-holding-id="${html(holding.holdingId)}" data-held-key="${html(holdingControlKey(holding))}" aria-pressed="${holding.holdingId===this.selection?.holdingId}" title="${html(artifact?.label||holding.artifactId)} - ${html(holding.actorId)} - ${html(holding.store)}"><strong>${html(artifact?.label||holding.artifactId)}</strong><small>${expired?'Expired - still held':holding.retention==='temporary'?'Temporary':'Stored'} · ${html(holding.store)} · ${html(holding.representationId)}</small></button>`;};
    const compartment=(actorId,dock=false)=>{
      const holdings=orderedHoldings(snapshot.holdings.filter(item=>item.actorId===actorId)),coverage=snapshot.coverage.find(item=>item.actorId===actorId),slots=holdingSlots(holdings,this.focusedId||this.selection?.holdingId),expanded=this.expanded.has(actorId),status=coverage?.status||'not-modeled';
      const label=status==='complete'?(holdings.length?'Held objects':'No held objects'):status==='partial'?'Known held objects - incomplete model':'Inventory not modeled';
      return `<section class="held-compartment" data-held-owner="${html(actorId)}"><h3>${html(app.actor(actorId).name)} <small>${html(label)}</small></h3>${(dock?slots.visible:holdings).map(button).join('')}${dock&&slots.hidden.length?`<button class="held-summary-control" data-held-actor="${html(actorId)}" aria-controls="held-objects" aria-expanded="${expanded&&this.actorId===actorId}">+${slots.hidden.length} known objects</button>`:''}${!dock?`<p class="held-coverage">${html((coverage?.stores||[]).join(', '))}${(coverage?.gaps||[]).map(gap=>`<span>Model gap: ${html(gap.reason)}</span>`).join('')}</p>`:''}</section>`;
    };
    const atomic=row?.sourceStepId&&!row?.heldCursorStart&&(compiled.plan.events[row.sourceStepId]?.milestones?.length||0)<=1;
    const position=snapshot.cursor.eventIndex<0?'Before step 1':this.selected?'After step '+(snapshot.cursor.eventIndex+1):'Source event '+(snapshot.cursor.eventIndex+1)+' / '+snapshot.cursor.milestone;
    this.root.innerHTML=`<header><h2>Current held objects</h2><p>Protocol clock ${html(snapshot.protocolClock)} · ${position}${atomic?' · Atomic event - '+(snapshot.cursor.milestone==='complete'?'after':'before')+' completion':''}. Possession is not acceptance or authority.</p></header><div class="held-actor-picker" aria-label="Choose logical inventory owner">${actors.map(id=>`<button class="held-summary-control" data-held-actor="${html(id)}" aria-pressed="${id===this.actorId}">${html(app.actor(id).name)} · ${snapshot.holdings.filter(item=>item.actorId===id).length} known</button>`).join('')}</div>${this.actorId?(!app.heldGeometry||this.expanded.has(this.actorId)?compartment(this.actorId):'<p>Choose a logical owner above or open its dock overflow to inspect the complete known list and coverage.</p>'):'<p>Inventory not modeled.</p>'}`;
    this.docks.innerHTML=app.heldGeometry?Object.keys(app.heldGeometry.positions).map(id=>{
      const owners=actors.filter(owner=>app.nodeId(owner)===id);
      if(app.heldGeometry.mode==='compact'){
        const chosen=owners.includes(this.selection?.actorId)?this.selection.actorId:owners.includes(this.actorId)?this.actorId:owners[0],count=snapshot.holdings.filter(item=>owners.includes(item.actorId)).length;
        const records=owners.map(owner=>snapshot.coverage.find(record=>record.actorId===owner)),complete=records.every(record=>record?.status==='complete'),unknown=records.every(record=>!record||record.status==='not-modeled');
        const label=owners.map(owner=>app.actor(owner).name+': '+snapshot.holdings.filter(item=>item.actorId===owner).length+' known; '+(snapshot.coverage.find(record=>record.actorId===owner)?.status||'not-modeled')).join('. ');
        return `<div class="held-compact-summary" data-held-dock="${html(id)}"><button class="held-summary-control" data-held-actor="${html(chosen)}" aria-controls="held-objects" aria-expanded="${this.actorId===chosen&&this.expanded.has(chosen)}" aria-label="Open separate logical-owner inventories. ${html(label)}"><span>${unknown?'?':count}</span><small>${complete?'known':unknown?'model':'partial'}</small></button></div>`;
      }
      return `<div class="held-dock" data-held-dock="${html(id)}">${owners.length===1?compartment(owners[0],true):`<h3>Logical owner inventories</h3>${owners.map(owner=>`<button class="held-summary-control" data-held-actor="${html(owner)}">${html(app.actor(owner).name)} · ${snapshot.holdings.filter(item=>item.actorId===owner).length} known</button>`).join('')}`}</div>`;
    }).join(''):'';
    this.docks.querySelectorAll('[data-held-dock]').forEach(dock=>{const p=app.positions[dock.dataset.heldDock],compact=app.heldGeometry.mode==='compact';dock.style.left=(compact?p.x:p.x+90)/1120*100+'%';dock.style.top=(compact?p.y:p.y-87)/730*100+'%';});
    if(this.visible&&app.heldGeometry?.mode==='compact'){
      const targets=[...this.docks.querySelectorAll('button')],cards=[...app.refs.actors.querySelectorAll('[data-actor]')].filter(card=>!card.hidden);
      if(targets.some(control=>{const box=control.getBoundingClientRect();return box.width<44||box.height<44;})||cards.some(card=>{const box=card.getBoundingClientRect();return box.width<82||box.height<132;})){
        this.rejectedCompactKey=app.heldGeometry.key;this.geometrySignature='';app.heldGeometry=null;app.refs.graph.dataset.heldGeometry='external';this.lastKey='';
        if(focusActor){this.actorId=focusActor;this.expanded.add(focusActor);}
        app.renderActors();app.renderConnections();app.renderPacket(app.player.snapshot());if(owned)this.recoverFocus(focusKey,focusActor);return;
      }
    }
    if(this.selection)this.renderInspector(snapshot,compiled);
    const holdings=new Map(snapshot.holdings.map(item=>[item.holdingId,item.store]));
    if(this.previousHoldings&&this.visible&&!this.motion.matches)this.app.querySelectorAll('[data-holding-id]').forEach(control=>{const id=control.dataset.holdingId;if(!this.previousHoldings.has(id)||this.previousHoldings.get(id)!==holdings.get(id))control.animate?.([{opacity:.4},{opacity:1}],{duration:220});});
    this.previousHoldings=holdings;
    const announcement=JSON.stringify([snapshot.protocolClock,snapshot.holdings.map(item=>[item.holdingId,item.store]),snapshot.observations,snapshot.authority]);
    if(this.announcement!==announcement){app.querySelector('#held-announcement').textContent=snapshot.holdings.length+' known holdings at '+(snapshot.cursor.eventIndex<0?'the initial state':'source event '+(snapshot.cursor.eventIndex+1)+' '+snapshot.cursor.milestone)+'. '+snapshot.observations.length+' authored observations.';this.announcement=announcement;}
    if(owned&&this.visible)this.recoverFocus(focusKey,focusActor);
  }
  renderInspector(snapshot,compiled){
    const selection=this.selection,holding=snapshot.holdings.find(item=>item.holdingId===selection.holdingId);
    const status=holding?'Currently held':detachedHoldingStatus(compiled,snapshot,selection);
    const inspected=holding?inspectHeldObject(snapshot,holding.holdingId):null;
    const artifact=compiled.plan.artifacts.find(item=>item.artifactId===selection.artifactId);
    // Historical inspection never grants new fields or knowledge to a former holder.
    if(inspected){selection.inspected=inspected;selection.authority=snapshot.authority.filter(item=>item.artifactId===selection.artifactId);}
    const safe=inspected||selection.inspected,fields=safe?.fields||[];
    const observations=holding?snapshot.observations.filter(item=>item.artifactId===selection.artifactId&&item.actorId===selection.actorId):selection.inspected?.observations||[];
    const authority=holding?snapshot.authority.filter(item=>item.artifactId===selection.artifactId):selection.authority||[];
    const related=[...new Set([...(artifact?.derivedFrom||[]),...(artifact?.replaces||[]),...(artifact?.related||[])])];
    const action=(name)=>html(JSON.stringify([this.contextId,selection.artifactId,selection.actorId,name]));
    this.inspector.innerHTML=`
      <h2>Exact object inspector</h2><h3>${html(artifact?.label||selection.artifactId)}</h3>
      <p class="held-detached-status">${status}${holding?'':' - previously viewed historical snapshot, not current possession'}</p>
      <dl><dt>Exact artifact ID</dt><dd><code>${html(selection.artifactId)}</code></dd>
      <dt>Exact holding ID</dt><dd><code>${html(selection.holdingId)}</code></dd>
      <dt>Creator</dt><dd>${html(artifact?.creator)}</dd><dt>Logical holder</dt><dd>${html(selection.actorId)}</dd>
      <dt>Acquisition cursor</dt><dd>${html(valueText(selection.acquiredAt))}</dd>
      <dt>Store / retention / representation</dt><dd>${html(selection.store)} / ${html(selection.retention)} / ${html(selection.representationId)}</dd>
      ${artifact?.expiresAt!=null?`<dt>Expiry at protocol clock</dt><dd>${html(artifact.expiresAt)}${snapshot.protocolClock>=artifact.expiresAt?' - expired, possession unchanged':''}</dd>`:''}</dl>
      <p>${html(artifact?.details||'')}</p>
      <h3>Permission-scoped fields for ${html(selection.actorId)}</h3>
      ${fields.length?'<dl>'+fields.map(field=>`<dt>${html(field.name||field.attributeId)}</dt><dd><pre>${field.readable?html(valueText(field.value)):'Not readable by this holder'}</pre></dd>`).join('')+'</dl>':'<p>No readable fields in this representation. Opaque possession is not decryption.</p>'}
      <h3>Checks, request acceptance and knowledge of ${html(selection.actorId)}</h3>
      ${observations.length?observations.map(item=>`<p><strong>${html(item.actorId)} · ${html(item.kind)} · ${html(item.result)}</strong><br>Request ${html(item.requestId||'not specified')} · endpoint ${html(item.endpoint||'not specified')} · policy ${html(item.policy||'not specified')}<br>${html(item.detail||'')}</p>`).join(''):'<p>No authored observation for this holder at this cursor.</p>'}
      <h3>Authority state - not automatic holder knowledge</h3>
      ${authority.length?authority.map(item=>`<p>${html(item.authorityId)} · ${html(item.status)} · ${html(item.detail||'')}</p>`).join(''):'<p>No authored authority change at this cursor.</p>'}
      <h3>Related exact IDs</h3>
      ${related.map(id=>snapshot.holdings.some(item=>item.artifactId===id&&item.actorId===selection.actorId)?`<button class="held-related" data-held-action="${action('related:'+id)}" data-held-related="${html(id)}">${html(id)}</button>`:`<p><code>${html(id)}</code> - not held by this logical actor at this cursor</p>`).join('')||'<p>None declared.</p>'}
      <button class="held-summary-control" data-held-action="${action('trace')}" data-held-trace="${html(selection.artifactId)}">Replay exact object history</button>
      <button class="held-summary-control" data-held-action="${action('help')}" data-held-help aria-expanded="${!!this.helpOpen}">Inventory help</button>
      ${this.helpOpen?`<section class="held-help" role="dialog" aria-label="Inventory help"><p>Holding means possession of this representation in the named logical store. Receipt, local checks, request acceptance and issuer authority are separate authored observations. A detached snapshot is only previously viewed history. Replay follows this exact artifact, not every field with the same name.</p><button class="held-summary-control" data-held-action="${action('help-close')}" data-held-help-close>Close help</button></section>`:''}
      ${this.app.objectTraceSelection?'<button class="held-summary-control" data-held-exit>Return to full journey</button>':''}
      <p>History is not current possession. Exact replay uses the same canonical source prefix, not an attribute alias.</p>`;
  }
}
function logicalActorsForView(app){
  if(app.scenarioOwnedActors)return app.scenarioOwnedActors;
  const ids=new Set(app.scenarioSnapshot().steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(op=>op.actorId)]).filter(Boolean).map(id=>app.actor(id).id));
  return Object.fromEntries([...ids].map(id=>[id,app.actor(id)]));
}
