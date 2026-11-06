// A data SVG image gives the browser its normal HTML/SVG and system-font
// shaping engine without attaching clones to the live document. Only capture
// reads source nodes; encoding consumes the frozen serialization.
export const PNG_RENDER_LIMITS = Object.freeze({scale:2,maxEdge:8192,maxPixels:12582912,maxNodes:4000,maxDepth:80,maxBytes:12582912,maxLayers:24});

const pngSvgNamespace='http://www.w3.org/2000/svg';
const pngHtmlNamespace='http://www.w3.org/1999/xhtml';
const pngSnapshots=new WeakSet();
const pngIgnoredTags=new Set(['script','style','link','meta','base','template','title','desc']);
const pngUnsupportedTags=new Set(['canvas','video','audio','iframe','object','embed','input','textarea','select','math','animate','animatetransform','animatemotion','set']);

function pngError(code,message,cause) {
  const error=new Error(message);
  error.code=code;
  if(cause)error.cause=cause;
  return error;
}

function pngDimensions(width,height) {
  if(!Number.isFinite(width)||!Number.isFinite(height)||width<=0||height<=0)throw pngError('size','Invalid PNG dimensions.');
  const pixelWidth=Math.ceil(width*PNG_RENDER_LIMITS.scale),pixelHeight=Math.ceil(height*PNG_RENDER_LIMITS.scale);
  if(pixelWidth>PNG_RENDER_LIMITS.maxEdge||pixelHeight>PNG_RENDER_LIMITS.maxEdge||pixelWidth*pixelHeight>PNG_RENDER_LIMITS.maxPixels)throw pngError('size','The complete view exceeds the PNG allocation limit.');
  return {pixelWidth,pixelHeight};
}

/** Freeze the complete current composition synchronously. Layer dimensions are
 * border-box CSS pixels. Optional exclude selects controls, not content cards.
 * expand:true removes the selected root's scroll clipping, not descendant clips.
 * The caller supplies the padded union bounds, including overflow descendants.
 */
export function capturePngSnapshot({width,height,background,layers}={}) {
  const dimensions=pngDimensions(width,height);
  if(!Array.isArray(layers)||!layers.length)throw pngError('content','There is no visible composition to export.');
  if(layers.length>PNG_RENDER_LIMITS.maxLayers)throw pngError('size','Too many PNG composition layers.');
  if(typeof document==='undefined'||typeof XMLSerializer==='undefined'||typeof CSS==='undefined'||typeof CSS.supports!=='function'||typeof TextEncoder==='undefined')throw pngError('unsupported','DOM image capture is unavailable.');
  if(typeof background!=='string'||!background.trim()||!CSS.supports('color',background)||/\b(?:var|url)\s*\(/i.test(background))throw pngError('content','A resolved export background color is required.');
  const doc=document.implementation.createDocument(pngSvgNamespace,'svg',null),svg=doc.documentElement;
  svg.setAttribute('width',String(width));svg.setAttribute('height',String(height));svg.setAttribute('viewBox',`0 0 ${width} ${height}`);
  const backgroundRect=doc.createElementNS(pngSvgNamespace,'rect');
  backgroundRect.setAttribute('width','100%');backgroundRect.setAttribute('height','100%');backgroundRect.setAttribute('fill',background);svg.append(backgroundRect);
  const definitions=doc.createElementNS(pngSvgNamespace,'defs');svg.append(definitions);
  const foreign=doc.createElementNS(pngSvgNamespace,'foreignObject');foreign.setAttribute('width',String(width));foreign.setAttribute('height',String(height));svg.append(foreign);
  const composition=doc.createElementNS(pngHtmlNamespace,'div');
  composition.setAttribute('class','png-composition');foreign.append(composition);
  const ids=new Map(),copied=new Set(),references=new Set(),styles=new Map(),rules=[];
  let nodes=0,bytes=0,hasContent=false;
  const account=value=>{bytes+=value.length*2;if(bytes>PNG_RENDER_LIMITS.maxBytes)throw pngError('size','The PNG snapshot exceeds the serialization limit.');return value;};
  const count=depth=>{if(++nodes>PNG_RENDER_LIMITS.maxNodes||depth>PNG_RENDER_LIMITS.maxDepth)throw pngError('size','The PNG snapshot exceeds the DOM complexity limit.');};
  const idFor=element=>{if(!ids.has(element))ids.set(element,'png-node-'+ids.size);return ids.get(element);};
  const fragment=(value,owner)=>{
    let url;
    try{url=new URL(value,owner.baseURI);}catch{throw pngError('unsupported','An image reference cannot be resolved.');}
    const base=new URL(owner.ownerDocument.URL);base.hash='';
    const resource=new URL(url.href);resource.hash='';
    if(!url.hash||resource.href!==base.href)throw pngError('unsupported','PNG capture does not load external resources.');
    let id;try{id=decodeURIComponent(url.hash.slice(1));}catch{throw pngError('content','Invalid SVG fragment identifier.');}
    const target=owner.ownerDocument.getElementById(id);
    if(!target||target.namespaceURI!==pngSvgNamespace)throw pngError('content','An SVG fragment is missing from the current composition.');
    references.add(target);return '#'+idFor(target);
  };
  const selfContained=(value,owner)=>value.replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi,(_,double,single,bare)=>{
    const resource=(double??single??bare).trim();
    if(/^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/=\s]+$/i.test(resource))return 'url("'+resource+'")';
    return 'url("'+fragment(resource,owner)+'")';
  });
  const styleFor=(computed,owner,overrides={})=>{
    const declarations=[];
    for(let index=0;index<computed.length;index++){
      const property=computed[index];
      if(property.startsWith('--')||property.startsWith('animation')||property.startsWith('transition')||property==='content'||Object.hasOwn(overrides,property))continue;
      const value=computed.getPropertyValue(property);
      if(value)declarations.push(property+':'+selfContained(value,owner)+';');
    }
    declarations.push('animation:none!important;transition:none!important;caret-color:transparent!important;');
    for(const [property,value]of Object.entries(overrides))declarations.push(property+':'+value+'!important;');
    const text=declarations.join('');
    let className=styles.get(text);
    if(!className){className='png-style-'+styles.size;styles.set(text,className);rules.push(account('.'+className+'{'+text+'}'));}
    return className;
  };
  const pseudoText=content=>{
    if(content==='none'||content==='normal')return null;
    // Computed CSS strings are escaped strings, not HTML. Refuse counters,
    // images and quote/counter state rather than silently dropping content.
    let result='',rest=content.trim();
    while(rest){
      const match=rest.match(/^(["'])((?:\\[\s\S]|(?!\1)[^\\])*)\1\s*/);
      if(!match)throw pngError('unsupported','This generated content cannot be frozen faithfully.');
      result+=match[2].replace(/\\([0-9a-f]{1,6})(?:\s)?|\\([\s\S])/gi,(_,hex,char)=>hex?String.fromCodePoint(Math.min(parseInt(hex,16)||65533,1114111)):char);
      rest=rest.slice(match[0].length);
    }
    return result;
  };
  const addPseudo=(owner,clone,pseudo,depth)=>{
    if(owner.namespaceURI!==pngHtmlNamespace)return;
    const computed=owner.ownerDocument.defaultView.getComputedStyle(owner,pseudo);
    if(computed.display==='none'||computed.visibility==='hidden'||computed.visibility==='collapse')return;
    const text=pseudoText(computed.content);if(text===null)return;
    count(depth);
    const span=doc.createElementNS(pngHtmlNamespace,'span');span.setAttribute('class',styleFor(computed,owner));span.textContent=account(text);clone.append(span);
  };
  const copy=(source,{exclude,depth=0,definition=false,rootStyle=null}={})=>{
    count(depth);
    if(source.nodeType===3){hasContent ||= !!source.nodeValue.trim();return doc.createTextNode(account(source.nodeValue));}
    if(source.nodeType!==1)return null;
    const tag=source.localName.toLowerCase();
    if(pngIgnoredTags.has(tag)||(!definition&&exclude&&source.matches(exclude)))return null;
    const view=source.ownerDocument.defaultView;
    if(!view)throw pngError('unsupported','The source document is unavailable.');
    const computed=view.getComputedStyle(source);
    if(!definition&&(source.hasAttribute('hidden')||computed.display==='none'))return null;
    if(source.shadowRoot||pngUnsupportedTags.has(tag))throw pngError('unsupported','This visible element cannot be captured without changing its presentation.');
    if(source.namespaceURI!==pngHtmlNamespace&&source.namespaceURI!==pngSvgNamespace)throw pngError('unsupported','This element namespace cannot be captured.');
    if(!definition&&!rootStyle&&computed.position==='fixed')throw pngError('unsupported','Fixed-position content must be a separately positioned export layer.');
    const clone=doc.createElementNS(source.namespaceURI,source.localName);copied.add(source);
    for(const attribute of source.attributes){
      const name=attribute.name.toLowerCase();
      if(name==='style'||name==='class'||name==='xmlns'||name.startsWith('xmlns:')||name.startsWith('on')||name.startsWith('data-')||name.startsWith('aria-')||['title','role','tabindex','autofocus','draggable','name','for'].includes(name))continue;
      let value=attribute.value;
      if(name==='id')value=idFor(source);
      else if(name==='href'||name==='xlink:href'){
        if(tag==='a')continue;
        if(tag==='image'||tag==='img'){
          if(!/^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/=\s]+$/i.test(value))throw pngError('unsupported','Only self-contained raster image resources can be captured.');
        }else value=fragment(value,source);
      }else if(['src','srcset','poster'].includes(name)){
        if(name!=='src'||tag!=='img'||!/^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/=\s]+$/i.test(value))throw pngError('unsupported','PNG capture does not load external images.');
      }else value=selfContained(value,source);
      account(value);
      if(attribute.namespaceURI)clone.setAttributeNS(attribute.namespaceURI,attribute.name,value);else clone.setAttribute(attribute.name,value);
    }
    clone.setAttribute('class',styleFor(computed,source,rootStyle||{}));
    if(tag==='img'&&(!source.complete||!source.naturalWidth))throw pngError('content','An image has not finished loading.');
    if(!definition&&source.namespaceURI===pngSvgNamespace&&['path','rect','circle','ellipse','line','polyline','polygon','text','image','use'].includes(tag))hasContent=true;
    addPseudo(source,clone,'::before',depth+1);
    for(const child of source.childNodes){
      if(tag==='details'&&!source.open&&child.nodeType===1&&child.localName!=='summary')continue;
      const result=copy(child,{exclude,depth:depth+1,definition});if(result)clone.append(result);
    }
    addPseudo(source,clone,'::after',depth+1);
    return clone;
  };
  try{
    rules.push(account(`.png-composition{position:relative;width:${width}px;height:${height}px;overflow:visible;isolation:isolate;}`));
    for(const layer of layers){
      const {element,x,y,exclude,expand=false}=layer||{};
      if(!element||element.nodeType!==1||!Number.isFinite(x)||!Number.isFinite(y))throw pngError('content','Invalid PNG composition layer.');
      if(exclude!=null&&typeof exclude!=='string')throw pngError('content','Invalid PNG control exclusion.');
      const rect=element.getBoundingClientRect(),layerWidth=layer.width??rect.width,layerHeight=layer.height??rect.height;
      if(!Number.isFinite(layerWidth)||!Number.isFinite(layerHeight)||layerWidth<=0||layerHeight<=0||x<0||y<0||x+layerWidth>width+.5||y+layerHeight>height+.5)throw pngError('size','A PNG layer falls outside the complete export bounds.');
      const wrapper=doc.createElementNS(pngHtmlNamespace,'div');
      const layerClass='png-layer-'+rules.length;
      wrapper.setAttribute('class',layerClass);
      rules.push(account(`.${layerClass}{position:absolute;left:${x}px;top:${y}px;width:${layerWidth}px;height:${layerHeight}px;overflow:visible;}`));
      const root=copy(element,{exclude,rootStyle:{position:'relative',left:'auto',right:'auto',top:'auto',bottom:'auto',margin:'0',transform:'none',translate:'none',rotate:'none',scale:'none',width:layerWidth+'px',height:layerHeight+'px','min-width':'0','max-width':'none','min-height':'0','max-height':'none','box-sizing':'border-box',...(expand?{overflow:'visible'}:{})}});
      if(root&&!root.hasAttribute('lang')){
        const language=element.closest('[lang]')?.getAttribute('lang')||element.ownerDocument.documentElement.getAttribute('lang');
        if(language)root.setAttribute('lang',language);
      }
      if(root){wrapper.append(root);composition.append(wrapper);}
    }
    // Computed SVG styles commonly contain absolute document URLs. Rewrite
    // these to private local IDs and include definitions outside chosen layers.
    for(const reference of references)if(!copied.has(reference)){
      const definition=copy(reference,{definition:true});if(definition)definitions.append(definition);
    }
    if(!hasContent)throw pngError('content','The selected composition contains no visible content.');
    // Serializing CSS text avoids connecting a style element or HTML style
    // attributes to the source document, which retains its enforcing CSP.
    const serializer=new XMLSerializer(),markup=serializer.serializeToString(svg),head=markup.indexOf('>')+1;
    const css=rules.join('').replace(/[&<>]/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[character]));
    const serialized=markup.slice(0,head)+'<style>'+css+'</style>'+markup.slice(head);
    if(new TextEncoder().encode(serialized).byteLength>PNG_RENDER_LIMITS.maxBytes)throw pngError('size','The PNG snapshot exceeds the serialization limit.');
    const snapshot=Object.freeze({width,height,...dimensions,background,svg:serialized});pngSnapshots.add(snapshot);return snapshot;
  }catch(error){
    if(['size','unsupported','encoding','content'].includes(error.code))throw error;
    throw pngError('content','The current view could not be captured.',error);
  }
}

/** Rasterize only frozen image content. No source nodes or computed styles are
 * read here. The data URL is local and needs img-src data:, not blob: or fonts.
 */
export const encodePngSnapshot = async snapshot => {
  if(!snapshot||!pngSnapshots.has(snapshot))throw pngError('content','A captured immutable PNG snapshot is required.');
  const {pixelWidth,pixelHeight}=pngDimensions(snapshot.width,snapshot.height);
  if(typeof Image==='undefined'||typeof document==='undefined'||typeof SVGForeignObjectElement==='undefined')throw pngError('unsupported','HTML/SVG image rendering is unavailable.');
  let image=null,canvas=null,timer=null;
  try{
    canvas=document.createElement('canvas');canvas.width=pixelWidth;canvas.height=pixelHeight;
    const context=canvas.getContext('2d',{willReadFrequently:true});
    if(!context||canvas.width!==pixelWidth||canvas.height!==pixelHeight)throw pngError('size','The browser could not allocate the complete PNG canvas.');
    context.fillStyle=snapshot.background;context.fillRect(0,0,pixelWidth,pixelHeight);
    const base=context.getImageData(0,0,1,1).data;
    image=new Image();image.decoding='sync';
    await new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(pngError('encoding','The local PNG image did not decode in time.')),15000);
      image.onload=resolve;image.onerror=()=>reject(pngError('unsupported','The browser or its image policy does not support this HTML/SVG snapshot.'));
      image.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(snapshot.svg);
    });
    clearTimeout(timer);timer=null;image.onload=null;image.onerror=null;
    if(!image.naturalWidth||!image.naturalHeight)throw pngError('content','The captured image has no pixels.');
    context.drawImage(image,0,0,pixelWidth,pixelHeight);
    // Some engines load an SVG but omit foreignObject. Reject a background-only
    // result instead of downloading a plausible-looking blank PNG. Stripes cap
    // temporary readback memory and stop at the first painted content pixel.
    let painted=false;
    for(let y=0;y<pixelHeight&&!painted;y+=32){
      const pixels=context.getImageData(0,y,pixelWidth,Math.min(32,pixelHeight-y)).data;
      for(let offset=0;offset<pixels.length;offset+=4)if(pixels[offset]!==base[0]||pixels[offset+1]!==base[1]||pixels[offset+2]!==base[2]||pixels[offset+3]!==base[3]){painted=true;break;}
    }
    if(!painted)throw pngError('content','The browser rendered no visible snapshot content.');
    const blob=await new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(pngError('encoding','PNG encoding did not finish in time.')),15000);
      canvas.toBlob(result=>result?resolve(result):reject(pngError('encoding','The browser returned no PNG image.')),'image/png');
    });
    if(blob.type!=='image/png'||blob.size<8)throw pngError('encoding','The browser did not produce a PNG image.');
    const signature=new Uint8Array(await blob.slice(0,8).arrayBuffer());
    if(![137,80,78,71,13,10,26,10].every((value,index)=>signature[index]===value))throw pngError('encoding','The encoded image is not a PNG.');
    return blob;
  }catch(error){
    if(['size','unsupported','encoding','content'].includes(error.code))throw error;
    throw pngError('encoding','The complete snapshot could not be encoded as PNG.',error);
  }finally{
    clearTimeout(timer);
    if(image){image.onload=null;image.onerror=null;image.removeAttribute('src');}
    if(canvas){canvas.width=0;canvas.height=0;}
  }
};
