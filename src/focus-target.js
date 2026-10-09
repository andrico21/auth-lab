/** Logical focus targets survive the inspector and attribute index being rebuilt. */
const focusTargetRegions=['inspector','attribute-index','actor-popup','actors','lab-cards'];
const focusTargetAttributeId=node=>node?.getAttribute?.('data-index-attribute')||node?.getAttribute?.('data-attribute')||null;
const focusTargetFind=(root,selector,value,attribute)=>{
  if(!root||value==null)return null;
  return [...root.querySelectorAll(selector)].find(node=>node.getAttribute(attribute)===String(value)&&isVisibleFocusTarget(root,node))||null;
};

export function isVisibleFocusTarget(root,node){
  if(!root?.contains(node)||typeof node?.focus!=='function'||node.disabled)return false;
  for(let current=node;current;current=current.parentElement){
    if(current.hidden||current.hasAttribute?.('inert')||current.getAttribute?.('aria-hidden')==='true')return false;
    const style=current.style;
    if(style?.display==='none'||style?.visibility==='hidden'||style?.visibility==='collapse')return false;
    const detailsOpen=typeof current.open==='boolean'?current.open:current.hasAttribute?.('open');
    if(current.tagName==='DETAILS'&&!detailsOpen){
      const summary=[...current.children].find(child=>child.tagName==='SUMMARY');
      if(!summary?.contains(node))return false;
    }
    if(current===root)break;
  }
  // Native layout adds CSS visibility to the structural checks. The offline test
  // harness deliberately does not pretend to compute style or element geometry.
  const view=node.ownerDocument?.defaultView;
  if(typeof view?.getComputedStyle==='function'){
    const style=view.getComputedStyle(node);
    if(style.display==='none'||style.visibility==='hidden'||style.visibility==='collapse')return false;
    if(typeof node.getClientRects==='function'&&!node.getClientRects().length)return false;
  }
  return true;
}

export function captureFocusTarget(root,node){
  if(!root?.contains(node))return null;
  const trigger=node.closest?.('[data-index-attribute], [data-attribute], [data-trace-topic], [data-actor], [data-lab-scenario]')||node;
  const region=focusTargetRegions.find(id=>root.querySelector('#'+id)?.contains(trigger))||null;
  const card=trigger.closest?.('[data-actor]');
  const actorId=card?.getAttribute('data-actor')||(region==='actor-popup'?root.actorAnchor?.getAttribute('data-actor'):null)||null;
  return Object.freeze({
    attributeId:focusTargetAttributeId(trigger),
    topicId:trigger.getAttribute?.('data-trace-topic')||null,
    actorId,
    scenarioId:trigger.getAttribute?.('data-lab-scenario')||null,
    region,
    elementId:trigger.id||null
  });
}

export function resolveFocusTarget(root,descriptor,{attributeId,fallbackSelector='#play',preferIndex=false}={}){
  if(!root)return null;
  const target=descriptor||{},field=attributeId??target.attributeId;
  const index=root.querySelector('#attribute-index');
  const indexTarget=()=>focusTargetFind(index,'[data-index-attribute]',field,'data-index-attribute')
    ||focusTargetFind(index,'[data-trace-topic]',target.topicId||field,'data-trace-topic');
  if(preferIndex){const node=indexTarget();if(node&&isVisibleFocusTarget(root,node))return node;}
  if(target.region){
    const region=root.querySelector('#'+target.region);
    const node=target.scenarioId?focusTargetFind(region,'[data-lab-scenario]',target.scenarioId,'data-lab-scenario')
      :target.topicId?focusTargetFind(region,'[data-trace-topic]',target.topicId,'data-trace-topic')
      :field?focusTargetFind(region,'[data-index-attribute], [data-attribute]',field,target.region==='attribute-index'?'data-index-attribute':'data-attribute')
      :target.actorId?focusTargetFind(region,'[data-actor]',target.actorId,'data-actor'):null;
    if(node&&isVisibleFocusTarget(root,node))return node;
  }
  const indexed=indexTarget();if(indexed&&isVisibleFocusTarget(root,indexed))return indexed;
  if(target.actorId){const actor=focusTargetFind(root,'[data-actor]',target.actorId,'data-actor');if(actor)return actor;}
  if(target.elementId){
    const node=[...root.querySelectorAll('[id]')].find(candidate=>candidate.id===target.elementId);
    if(node&&isVisibleFocusTarget(root,node))return node;
  }
  const fallback=root.querySelector(fallbackSelector);
  if(isVisibleFocusTarget(root,fallback))return fallback;
  const play=root.querySelector('#play');
  return isVisibleFocusTarget(root,play)?play:null;
}
