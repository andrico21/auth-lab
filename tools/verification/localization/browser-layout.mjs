// Browser-only diagnostics. No launch, timings, or claims about native text scaling.
import assert from 'node:assert/strict';

export async function text200(page){
  const result=await page.evaluate(()=>{
    const simulation=window.__localizationFonts??={records:[]};
    const root=document.documentElement,focus=document.activeElement,viewport={left:scrollX,top:scrollY};
    const anchor={value:root.style.getPropertyValue('overflow-anchor'),priority:root.style.getPropertyPriority('overflow-anchor')};
    const box=n=>n.getBoundingClientRect().toJSON();
    const calibration={before:{...viewport,focus:{id:focus.id,tag:focus.tagName,box:box(focus)}}};
    root.style.setProperty('overflow-anchor','none','important');
    const nodes=[...document.querySelectorAll('auth-flow-studio,auth-flow-studio *')];
    const records=nodes.map(node=>({node:new WeakRef(node),transition:node.style.getPropertyValue('transition-property'),transitionPriority:node.style.getPropertyPriority('transition-property')}));
    try{
      for(const node of nodes)node.style.setProperty('transition-property','none','important');
      for(const record of simulation.records){const node=record.node.deref();if(node&&node.style.getPropertyValue('font-size')===record.applied)record.inline?node.style.setProperty('font-size',record.inline,record.priority):node.style.removeProperty('font-size');}
      // Snapshot the entire computed baseline before writing any enlarged ancestor.
      for(let i=0;i<nodes.length;i++){const n=nodes[i],r=records[i];r.inline=n.style.getPropertyValue('font-size');r.priority=n.style.getPropertyPriority('font-size');r.baseline=parseFloat(getComputedStyle(n).fontSize);}
      for(let i=0;i<nodes.length;i++){const r=records[i];nodes[i].style.setProperty('font-size',r.baseline*2+'px','important');r.applied=nodes[i].style.getPropertyValue('font-size');}
      simulation.records=records;void root.offsetHeight;
      const mismatches=[],ratios=new Map();
      for(let i=0;i<nodes.length;i++){const expected=records[i].baseline*2,actual=parseFloat(getComputedStyle(nodes[i]).fontSize);const key=JSON.stringify([records[i].baseline,expected,actual]);ratios.set(key,(ratios.get(key)||0)+1);if(!Number.isFinite(actual)||Math.abs(actual-expected)>.02)mismatches.push({id:nodes[i].id,tag:nodes[i].tagName,baseline:records[i].baseline,expected,actual});}
      return {method:'Qualified 200% computed-font user-style simulation, not native browser/OS text scaling',nodes:nodes.length,calibration,ratios:[...ratios].map(([sizes,count])=>({sizes:JSON.parse(sizes),count})),mismatches};
    }finally{
      for(let i=0;i<nodes.length;i++){const r=records[i];r.transition?nodes[i].style.setProperty('transition-property',r.transition,r.transitionPriority):nodes[i].style.removeProperty('transition-property');}
      void root.offsetHeight;window.scrollTo({left:viewport.left,top:viewport.top,behavior:'instant'});
      anchor.value?root.style.setProperty('overflow-anchor',anchor.value,anchor.priority):root.style.removeProperty('overflow-anchor');
      calibration.after={left:scrollX,top:scrollY,focus:{id:document.activeElement.id,tag:document.activeElement.tagName,box:box(document.activeElement)}};calibration.focusUnchanged=document.activeElement===focus;
    }
  });
  assert.deepEqual(result.mismatches,[],'Exact2x current computed fonts within existing .02px bound');
  assert.equal(result.calibration.focusUnchanged,true,'Calibration never refocuses');
  assert.equal(result.calibration.before.left,result.calibration.after.left,'Calibration restores original horizontal viewport');
  assert.equal(result.calibration.before.top,result.calibration.after.top,'Calibration restores original vertical viewport');
  return result;
}

export async function layoutSnapshot(page){return page.evaluate(()=>{
  const app=document.querySelector('auth-flow-studio'),visible=n=>n.getClientRects().length&&getComputedStyle(n).visibility!=='hidden',box=n=>n.getBoundingClientRect().toJSON();
  const descriptor=n=>{const bounds=box(n),center=document.elementFromPoint(bounds.x+bounds.width/2,bounds.y+bounds.height/2);return {id:n.id,tag:n.tagName,name:n.getAttribute('aria-label')||n.textContent.slice(0,180),box:bounds,dir:n.getAttribute('dir'),computedDirection:getComputedStyle(n).direction,pointerEvents:getComputedStyle(n).pointerEvents,centerHit:center?{id:center.id,tag:center.tagName,class:center.getAttribute('class'),isSelfOrDescendant:center===n||n.contains(center)}:null,...(n instanceof SVGGeometryElement?{svg:{d:n.getAttribute('d'),strokeWidth:getComputedStyle(n).strokeWidth,totalLength:n.getTotalLength(),note:'Path bounding-box center need not hit the stroke; this snapshot does not activate or force any target'}}:{})};};
  const targets=[...app.querySelectorAll('button,input,select,textarea,summary,[tabindex="0"]')].filter(visible).map(descriptor);
  const values=[...app.querySelectorAll('pre,code,[data-copy-raw-json]')].filter(visible).map(n=>({...descriptor(n),scrollWidth:n.scrollWidth,clientWidth:n.clientWidth,overflow:getComputedStyle(n).overflowX,whiteSpace:getComputedStyle(n).whiteSpace,text:n.textContent}));
  const active=document.activeElement,r=active.getBoundingClientRect(),focusStyle=getComputedStyle(active);
  const pointsFor=b=>{const inset=Math.min(8,b.width/4,b.height/4);return [[b.left+inset,b.top+inset],[b.right-inset,b.top+inset],[b.left+inset,b.bottom-inset],[b.right-inset,b.bottom-inset],[(b.left+b.right)/2,(b.top+b.bottom)/2]];};
  const textInput=active instanceof HTMLTextAreaElement||active instanceof HTMLInputElement&&['text','search','email','password','tel','url','number'].includes(active.type);
  const content=textInput?{left:r.left+parseFloat(focusStyle.borderLeftWidth)+parseFloat(focusStyle.paddingLeft),right:r.right-parseFloat(focusStyle.borderRightWidth)-parseFloat(focusStyle.paddingRight),top:r.top+parseFloat(focusStyle.borderTopWidth)+parseFloat(focusStyle.paddingTop),bottom:r.bottom-parseFloat(focusStyle.borderBottomWidth)-parseFloat(focusStyle.paddingBottom)}:{left:r.left,right:r.right,top:r.top,bottom:r.bottom};
  content.width=content.right-content.left;content.height=content.bottom-content.top;
  const sampledAreaUsable=Object.values(content).every(Number.isFinite)&&content.width>0&&content.height>0;
  const hitAt=([x,y])=>{
    const node=document.elementFromPoint(x,y),button=node?.closest('button'),owner=active.parentElement;
    let ownedReservedAffordance=false;
    if(textInput&&sampledAreaUsable&&owner?.classList.contains('scenario-picker-control')&&button?.parentElement===owner){
      const b=button.getBoundingClientRect();
      ownedReservedAffordance=b.left>=r.left&&b.right<=r.right&&b.top>=r.top&&b.bottom<=r.bottom&&(b.right<=content.left||b.left>=content.right);
    }
    return {x,y,hit:node===active||active.contains(node),ownedReservedAffordance,target:node?{id:node.id,tag:node.tagName,class:node.getAttribute('class')}:null};
  };
  const ids=[...document.querySelectorAll('[id]')].map(n=>n.id);
  return {viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,visualScale:visualViewport?.scale},document:{width:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,bodyScrollWidth:document.body.scrollWidth},targets,smallTargets:targets.filter(n=>n.box.width<43.9||n.box.height<43.9),values,unreadableValues:values.filter(n=>n.clientWidth&&n.scrollWidth>n.clientWidth+1&&n.overflow==='hidden'),duplicateIds:[...new Set(ids.filter((id,i)=>ids.indexOf(id)!==i))],focus:{...descriptor(active),connected:active.isConnected,fullyVisible:r.top>=0&&r.left>=0&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1,focusVisible:active.matches(':focus-visible'),outline:focusStyle.outline,padding:{left:focusStyle.paddingLeft,right:focusStyle.paddingRight},sampledArea:{kind:textInput?'editable-content':'element',...content},sampledAreaUsable,hit:sampledAreaUsable?pointsFor(content).map(hitAt):[],outerHit:pointsFor(r).map(hitAt)},regions:[...app.querySelectorAll('.instance-table-scroll,.table-scroll')].filter(visible).map(n=>({...descriptor(n),role:n.getAttribute('role'),label:n.getAttribute('aria-label'),tabindex:n.getAttribute('tabindex'),overflow:n.scrollWidth>n.clientWidth+1}))};
});}
