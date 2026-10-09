/**
 * Purpose-built offline DOM integration harness, not a browser or layout engine.
 * Parses the app's generated HTML/SVG, supports its selector/event APIs, and
 * supplies deterministic animation frames. Rectangles are explicit test fixtures;
 * SVG geometry is sampled from the actual absolute M/C connection path strings.
 */
const entities = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const decode = s => String(s).replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e) => e[0] === '#' ? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2),16) : Number(e.slice(1))) : entities[e.toLowerCase()]);
const escape = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const voidTags = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);

export class HarnessEvent {
  constructor(type, init={}) { Object.assign(this,{type,bubbles:true,cancelable:true,defaultPrevented:false,relatedTarget:null},init); }
  preventDefault() { if(this.cancelable)this.defaultPrevented=true; }
  stopPropagation() { this.propagationStopped=true; }
}
class EventTarget {
  constructor(){this.listeners=new Map();}
  addEventListener(type, listener){if(!this.listeners.has(type))this.listeners.set(type,new Set());this.listeners.get(type).add(listener);}
  removeEventListener(type, listener){this.listeners.get(type)?.delete(listener);}
  dispatchEvent(event){
    if(!event.target)event.target=this;
    let node=this;
    do { event.currentTarget=node; for(const fn of [...(node.listeners?.get(event.type)||[])])fn.call(node,event); node=event.bubbles&&!event.propagationStopped?node.parentElement:null; }while(node);
    return !event.defaultPrevented;
  }
}
class TextNode { constructor(text){this.data=decode(text);this.parentElement=null;} get textContent(){return this.data;} set textContent(v){this.data=String(v);} }
function selectorParts(selector){return selector.trim().split(/\s+(?=(?:[^\[\]]*\[[^\[\]]*\])*[^\[\]]*$)/);}
function matchesCompound(node,selector){
  if(!(node instanceof HarnessElement))return false;
  const tag=selector.match(/^[\w-]+|^\*/)?.[0];
  if(tag&&tag!=='*'&&node.tagName.toLowerCase()!==tag.toLowerCase())return false;
  for(const token of selector.matchAll(/#([\w-]+)|\.([\w-]+)|\[([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+)))?\]/g)){
    if(token[1]&&node.id!==token[1])return false;
    if(token[2]&&!node.classList.contains(token[2]))return false;
    if(token[3]){if(!node.hasAttribute(token[3]))return false;const value=token[4]??token[5]??token[6];if(value!==undefined&&node.getAttribute(token[3])!==decode(value))return false;}
  }
  return true;
}
function matchesSelector(node,selector){
  const parts=selectorParts(selector);let current=node;
  if(!matchesCompound(current,parts.pop()))return false;
  while(parts.length){const part=parts.pop();current=current.parentElement;while(current&&!matchesCompound(current,part))current=current.parentElement;if(!current)return false;}
  return true;
}
const toKebab=s=>String(s).replace(/[A-Z]/g,c=>'-'+c.toLowerCase());

export class HarnessElement extends EventTarget {
  constructor(tagName='element'){
    super();this.tagName=tagName.toUpperCase();this.attributes=new Map();this.childNodes=[];this.parentElement=null;this.style={setProperty(name,value){this[name]=String(value);},getPropertyValue(name){return this[name]||'';},removeProperty(name){const value=this[name]||'';delete this[name];return value;}};this.scrollCalls=[];this.animationCalls=[];
    this.dataset=new Proxy({}, {get:(_,k)=>this.getAttribute('data-'+toKebab(k))??undefined,set:(_,k,v)=>{this.setAttribute('data-'+toKebab(k),v);return true;}});
    this.classList={contains:c=>(this.getAttribute('class')||'').split(/\s+/).includes(c),add:(...cs)=>this.setAttribute('class',[...new Set([...(this.getAttribute('class')||'').split(/\s+/).filter(Boolean),...cs])].join(' ')),remove:(...cs)=>this.setAttribute('class',(this.getAttribute('class')||'').split(/\s+/).filter(c=>!cs.includes(c)).join(' ')),toggle:(c,force)=>{const present=this.classList.contains(c),add=force===undefined?!present:!!force;if(add)this.classList.add(c);else this.classList.remove(c);return add;}};
  }
  get id(){return this.getAttribute('id')||'';} set id(v){this.setAttribute('id',v);}
  get children(){return this.childNodes.filter(n=>n instanceof HarnessElement);}
  appendChild(node){if(node.parentElement)node.parentElement.removeChild(node);this.childNodes.push(node);node.parentElement=this;return node;}
  removeChild(node){const i=this.childNodes.indexOf(node);if(i>=0)this.childNodes.splice(i,1);node.parentElement=null;return node;}
  get textContent(){return this.childNodes.map(n=>n.textContent).join('');}
  set textContent(value){this.childNodes=[];this.appendChild(new TextNode(String(value)));}
  get innerHTML(){return this.childNodes.map(n=>n instanceof HarnessElement?n.outerHTML:escape(n.data)).join('');}
  set innerHTML(html){for(const child of this.childNodes)child.parentElement=null;this.childNodes=[];parseFragment(String(html),this);}
  get outerHTML(){return '<'+this.tagName.toLowerCase()+[...this.attributes].map(([k,v])=>' '+k+'="'+v.replace(/"/g,'&quot;')+'"').join('')+'>'+this.innerHTML+'</'+this.tagName.toLowerCase()+'>';}
  setAttribute(name,value){this.attributes.set(name,String(value));if(name==='style')for(const part of String(value).split(';')){const colon=part.indexOf(':');if(colon>=0)this.style[part.slice(0,colon).trim()]=part.slice(colon+1).trim();}}
  getAttribute(name){return this.attributes.get(name)??null;}
  hasAttribute(name){return this.attributes.has(name);}
  removeAttribute(name){this.attributes.delete(name);}
  get hidden(){return this.hasAttribute('hidden');} set hidden(value){value?this.setAttribute('hidden',''):this.removeAttribute('hidden');}
  get disabled(){return this.hasAttribute('disabled');} set disabled(value){value?this.setAttribute('disabled',''):this.removeAttribute('disabled');}
  get value(){if(this._value!==undefined)return this._value;if(this.tagName==='SELECT')return this.querySelector('option')?.getAttribute('value')||'';return this.getAttribute('value')||'';} set value(v){this._value=String(v);}
  querySelectorAll(selector){const groups=selector.split(',').map(s=>s.trim()),results=[];const visit=node=>{for(const child of node.children){if(groups.some(s=>matchesSelector(child,s)))results.push(child);visit(child);}};visit(this);return results;}
  querySelector(selector){return this.querySelectorAll(selector)[0]||null;}
  matches(selector){return selector.split(',').some(s=>matchesSelector(this,s.trim()));}
  closest(selector){let node=this;while(node){if(node.matches(selector))return node;node=node.parentElement;}return null;}
  contains(node){while(node){if(node===this)return true;node=node.parentElement;}return false;}
  click(){this.dispatchEvent(new HarnessEvent('click'));}
  focus(){this.dispatchEvent(new HarnessEvent('focusin'));}
  scrollIntoView(options){this.scrollCalls.push(options);}
  animate(frames,options){this.animationCalls.push({frames,options});return {cancel(){},finished:Promise.resolve()};}
  get offsetHeight(){return this.hidden?0:360;}
  getBoundingClientRect(){
    // Explicit viewport fixture: no CSS sizing/layout assertions use these values.
    const left=this.dataset.actor?parseFloat(this.style.left||'0')*11.2:100,top=this.dataset.actor?parseFloat(this.style.top||'0')*7.3:100;
    return {left,top,right:left+148,bottom:top+128,width:148,height:128,x:left,y:top};
  }
  curveSamples(){
    const d=this.getAttribute('d')||'';if(this._curveCache?.d===d)return this._curveCache.samples;
    const commands=d.match(/[a-z]/gi)||[],values=d.match(/-?\d*\.?\d+/g)?.map(Number)||[];
    if(commands[0]!=='M'||commands.slice(1).some(command=>command!=='C')||values.length<8||(values.length-2)%6!==0)throw new Error('Harness supports app absolute M/C path geometry only: '+d);
    let [x0,y0]=values,length=0;const samples=[{x:x0,y:y0,length:0}];
    for(let offset=2;offset<values.length;offset+=6){
      const [x1,y1,x2,y2,x3,y3]=values.slice(offset,offset+6);
      for(let i=1;i<=100;i++){const t=i/100,u=1-t,x=u*u*u*x0+3*u*u*t*x1+3*u*t*t*x2+t*t*t*x3,y=u*u*u*y0+3*u*u*t*y1+3*u*t*t*y2+t*t*t*y3,prev=samples.at(-1);length+=Math.hypot(x-prev.x,y-prev.y);samples.push({x,y,length});}
      x0=x3;y0=y3;
    }
    this._curveCache={d,samples};return samples;
  }
  getTotalLength(){return this.curveSamples().at(-1).length;}
  getPointAtLength(length){const samples=this.curveSamples();if(length<=0)return samples[0];for(let i=1;i<samples.length;i++)if(samples[i].length>=length){const a=samples[i-1],b=samples[i],t=(length-a.length)/(b.length-a.length);return {x:a.x+(b.x-a.x)*t,y:a.y+(b.y-a.y)*t};}return samples.at(-1);}
}
function parseFragment(html,root){
  const stack=[root],tokens=html.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g)||[];
  for(const token of tokens){if(token.startsWith('<!--')||token.startsWith('<!'))continue;if(token.startsWith('</')){const tag=token.slice(2).match(/^[\w:-]+/)?.[0].toUpperCase();while(stack.length>1){if(stack.pop().tagName===tag)break;}continue;}
    if(token[0]==='<'){const tag=token.slice(1).match(/^[\w:-]+/)?.[0];if(!tag)continue;const node=new HarnessElement(tag),attrString=token.slice(1+tag.length).replace(/\/?>$/,'');for(const match of attrString.matchAll(/([^\s=\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g))node.setAttribute(match[1],decode(match[2]??match[3]??match[4]??''));stack.at(-1).appendChild(node);if(!voidTags.has(tag.toLowerCase())&&!token.endsWith('/>'))stack.push(node);
    }else stack.at(-1).appendChild(new TextNode(token));
  }
}
export class HarnessClock {
  constructor(){this.time=0;this.nextId=1;this.frames=new Map();this.timers=new Map();this.totalFrameCallbacks=0;}
  requestFrame(callback){const id=this.nextId++;this.frames.set(id,callback);return id;}
  cancelFrame(id){this.frames.delete(id);}
  setTimeout(callback,delay){const id=this.nextId++;this.timers.set(id,{callback,at:this.time+Number(delay||0)});return id;}
  clearTimeout(id){this.timers.delete(id);}
  frame(delta=100){this.time+=delta;const callbacks=[...this.frames.values()];this.frames.clear();for(const callback of callbacks){this.totalFrameCallbacks++;callback(this.time);}for(const [id,timer] of [...this.timers])if(timer.at<=this.time&&this.timers.has(id)){this.timers.delete(id);timer.callback();}}
  advance(ms){while(ms>0){const delta=Math.min(100,ms);this.frame(delta);ms-=delta;}}
  until(predicate,maxFrames=20000){let frames=0;while(!predicate()){if(frames++>=maxFrames)throw new Error('Animation failed to settle after '+maxFrames+' frames');this.frame();}return frames;}
}
export function installHarness(target=globalThis){
  const clock=new HarnessClock(),registry=new Map(),window=new EventTarget(),document=new HarnessElement('document');
  document.body=new HarnessElement('body');document.appendChild(document.body);document.documentElement=new HarnessElement('html');document.createElement=tag=>registry.has(tag)?new (registry.get(tag))():new HarnessElement(tag);document.createElementNS=(_,tag)=>document.createElement(tag);document.getElementById=id=>document.querySelector('#'+id);
  Object.assign(window,{innerWidth:1440,innerHeight:1000,matchMedia:()=>({matches:false,addEventListener(){},removeEventListener(){}}),document});
  const globals={HTMLElement:HarnessElement,customElements:{define:(name,klass)=>registry.set(name,klass),get:name=>registry.get(name)},document,window,matchMedia:window.matchMedia,requestAnimationFrame:cb=>clock.requestFrame(cb),cancelAnimationFrame:id=>clock.cancelFrame(id),setTimeout:(cb,delay)=>clock.setTimeout(cb,delay),clearTimeout:id=>clock.clearTimeout(id)};
  for(const [key,value]of Object.entries(globals))target[key]=value;
  return {clock,window,document,registry};
}
