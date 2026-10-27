const pickerEscape = value => String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
// Keep '+' significant (SPAKE2 and SPAKE2+ are different mechanisms).
const pickerNormalize = value => String(value??'').normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase().replace(/[^a-z0-9+]+/g,' ').trim().replace(/\s+/g,' ');
const pickerSearchCache = new WeakMap();
const pickerValues = value => Array.isArray(value)?value:value==null?[]:[value];
const pickerUnique = values => [...new Set(values.map(pickerNormalize).filter(Boolean))];
const pickerFields = (phrases,identifiers,context) => {
  const strong=pickerUnique(phrases), exact=pickerUnique(identifiers);
  // Context contributes tokens only, so normalize the joined fragments once.
  const incidental=pickerNormalize(context.map(value=>String(value??'')).join(' '));
  return {strong,exact,tokens:new Set([...strong,...exact].flatMap(value=>value.split(' '))),contextTokens:new Set(incidental?incidental.split(' '):[])};
};
const pickerSearchIndex = option => {
  // Compare content, not just array references: in-place tag/variant edits must
  // invalidate. Serializing these small descriptors never touches a model trace.
  const signature=JSON.stringify([option.id,option.title,option.category,option.summary,option.searchText,option.searchTags,option.searchIdentifiers,option.searchContext,option.searchVariants]);
  let cached=pickerSearchCache.get(option);
  if(cached?.signature===signature)return cached;
  const phrases=[option.title,...pickerValues(option.searchTags)];
  const identifiers=[option.id,...pickerValues(option.searchIdentifiers)];
  const context=[option.category,option.summary,option.searchText,...pickerValues(option.searchContext)];
  // Normalize shared model metadata once; cases keep only their extra terms.
  cached={signature,base:pickerFields(phrases,identifiers,context),variants:(option.searchVariants||[]).map(variant=>({
    id:variant.id,label:variant.label||variant.id,
    fields:pickerFields([variant.label,...pickerValues(variant.searchTags)],[variant.id,...pickerValues(variant.searchIdentifiers)],pickerValues(variant.searchContext)),
  }))};
  pickerSearchCache.set(option,cached);
  return cached;
};
const pickerHasPrefix = (tokens,term) => {
  if(term.length<3)return false;
  const significantPlus=term+'+';
  for(const token of tokens)if(token!==significantPlus&&token.startsWith(term))return true;
  return false;
};
const pickerRank = (fields,phrase,terms,parent=null) => {
  if(fields.exact.includes(phrase)||fields.strong.includes(phrase)||parent?.exact.includes(phrase)||parent?.strong.includes(phrase))return 0;
  let rank=1;
  for(const term of terms){
    if(fields.tokens.has(term)||parent?.tokens.has(term))continue;
    if(pickerHasPrefix(fields.tokens,term)||(parent&&pickerHasPrefix(parent.tokens,term))){rank=Math.max(rank,2);continue;}
    if(fields.contextTokens.has(term)||parent?.contextTokens.has(term)||pickerHasPrefix(fields.contextTokens,term)||(parent&&pickerHasPrefix(parent.contextTokens,term))){rank=3;continue;}
    return null;
  }
  return rank;
};

export function filterScenarioOptions(options,query) {
  const phrase=pickerNormalize(query);
  if(!phrase)return options.filter((option,index)=>options.findIndex(row=>row.id===option.id)===index);
  const terms=[...new Set(phrase.split(' '))], rows=[], seen=new Set();
  for(const option of options){
    if(seen.has(option.id))continue;
    seen.add(option.id);
    const index=pickerSearchIndex(option),baseRank=pickerRank(index.base,phrase,terms);
    const matches=index.variants.map(variant=>({...variant,rank:pickerRank(variant.fields,phrase,terms,index.base)})).filter(variant=>variant.rank!==null&&(baseRank===null||variant.rank<baseRank));
    const variantRank=matches.length?Math.min(...matches.map(variant=>variant.rank)):null;
    if(baseRank===null&&variantRank===null)continue;
    if(baseRank!==null&&(variantRank===null||baseRank<=variantRank)){rows.push({option,rank:baseRank});continue;}
    // All matching cases remain explicit choices, not just the highest-ranked
    // case. Never select a success default for a variant-only denial query.
    const result=matches.length===1
      ?{...option,variantId:matches[0].id,caseLabel:matches[0].label}
      :{...option,matchingVariantIds:matches.map(variant=>variant.id),matchingCases:matches.map(({id,label})=>({id,label})),caseLabel:matches.length+' matching cases'};
    rows.push({option:result,rank:variantRank});
  }
  // Stable Array.sort preserves original catalog order for equal tiers. Counts,
  // repeated tags and repeated terms never contribute to the score.
  return rows.sort((left,right)=>left.rank-right.rank).map(row=>row.option);
}

/** An editable combobox. Filtering does not activate a scenario. */
export class ScenarioPicker {
  constructor(root,options,onSelect,outsideRoot,{prefix='lab-scenario',optionPrefix='scenario-option',optionAttribute='data-scenario-option',singular='scenario',plural='scenarios',emptyMessage='No matching scenarios. Try a protocol, profile, field or learning objective.'}={}) {
    this.root=root;this.options=options;this.onSelect=onSelect;this.selectedId='core';
    this.optionPrefix=optionPrefix;this.optionAttribute=optionAttribute;this.optionSelector='['+optionAttribute+']';
    this.singular=singular;this.plural=plural;this.emptyMessage=emptyMessage;
    this.opened=false;this.query='';this.activeIndex=-1;this.listeners=[];
    this.optionNodes=new Map();
    // Prepare static metadata before interaction, not on the first keystroke.
    // Content signatures still invalidate in-place edits when filtering.
    for(const option of options)pickerSearchIndex(option);
    this.input=root.querySelector('#'+prefix+'-search');this.menu=root.querySelector('#'+prefix+'-menu');
    this.list=root.querySelector('#'+prefix+'-results');this.status=root.querySelector('#'+prefix+'-search-status');
    this.clearButton=root.querySelector('#'+prefix+'-clear');this.toggleButton=root.querySelector('#'+prefix+'-toggle');
    this.listen(this.input,'focusin',()=>this.open());
    this.listen(this.input,'click',()=>this.open());
    this.listen(this.input,'input',()=>{this.query=this.input.value;if(this.opened)this.render();else this.open(true);});
    this.listen(this.input,'keydown',event=>this.keydown(event));
    this.listen(root,'focusout',event=>{if(!root.contains(event.relatedTarget))this.close();});
    this.listen(root,'pointerdown',event=>{if(event.target.closest('button'))event.preventDefault();});
    this.listen(this.list,'click',event=>{const option=event.target.closest(this.optionSelector);if(option)this.choose(option.getAttribute(this.optionAttribute));});
    this.listen(this.clearButton,'click',()=>{this.query='';this.input.value='';this.open();this.render();this.input.focus();});
    this.listen(this.toggleButton,'click',()=>{if(this.opened)this.close();else{this.open();this.input.focus();}});
    const closeOutside=event=>{if(!root.contains(event.target))this.close();};
    this.listen(document,'pointerdown',closeOutside);
    if(outsideRoot&&outsideRoot!==document)this.listen(outsideRoot,'pointerdown',closeOutside);
    this.setSelected(options.some(option=>option.id==='core')?'core':options[0]?.id);
  }
  listen(node,type,listener) {node.addEventListener(type,listener);this.listeners.push([node,type,listener]);}
  destroy() {this.listeners.forEach(([node,type,listener])=>node.removeEventListener(type,listener));this.listeners=[];this.optionNodes.clear();}
  setSelected(id) {if(!this.options.some(option=>option.id===id))return;this.selectedId=id;this.close();}
  open(fromInput=false) {
    if(this.opened)return;
    this.opened=true;
    // Native input owns the caret and IME composition; do not rewrite its value.
    if(!fromInput){this.query='';this.input.value='';}
    this.menu.hidden=false;
    this.input.setAttribute('aria-expanded','true');this.toggleButton.setAttribute('aria-expanded','true');
    this.root.classList.add('is-open');this.render();
  }
  close() {
    this.opened=false;this.query='';this.menu.hidden=true;this.clearButton.hidden=true;
    const selected=this.options.find(option=>option.id===this.selectedId);this.input.value=selected?.selectedLabel||selected?.title||'';
    this.input.setAttribute('aria-expanded','false');this.input.removeAttribute('aria-activedescendant');
    this.toggleButton.setAttribute('aria-expanded','false');this.root.classList.remove('is-open');
  }
  render() {
    this.results=filterScenarioOptions(this.options,this.query);
    this.activeIndex=this.query.trim()?0:Math.max(0,this.results.findIndex(option=>option.id===this.selectedId));
    if(!this.results.length)this.activeIndex=-1;
    this.clearButton.hidden=!this.query;
    this.status.textContent=this.results.length+' matching '+(this.results.length===1?this.singular:this.plural);
    const categories=[...new Set(this.results.map(option=>option.category))];
    const prepared=this.results.map(option=>{
      const markup=`<button type="button" role="option" tabindex="-1" class="scenario-picker-option" id="${this.optionPrefix}-${option.id}" ${this.optionAttribute}="${option.id}" aria-selected="${option.id===this.selectedId}"><span class="scenario-picker-option-text"><strong>${pickerEscape(option.title)}</strong><span>${pickerEscape(option.summary)}</span>${option.caseLabel?`<small class="scenario-picker-case">${pickerEscape(option.caseLabel)}</small>`:''}${this.query.trim()&&option.category?`<small>${pickerEscape(option.category)}</small>`:''}${option.profileLabel?`<small class="scenario-picker-profile">${pickerEscape(option.profileLabel)}</small>`:''}</span><span class="scenario-picker-option-check" aria-hidden="true">${option.id===this.selectedId?'✓':''}</span></button>`;
      const cached=this.optionNodes.get(option.id);
      return {option,markup,node:cached?.markup===markup?cached.node:null};
    });
    const missing=prepared.filter(row=>!row.node);
    if(missing.length){
      const wrapper=document.createElement('div');wrapper.innerHTML=missing.map(row=>row.markup).join('');
      missing.forEach((row,index)=>{row.node=wrapper.children[index];this.optionNodes.set(row.option.id,{markup:row.markup,node:row.node});});
    }
    this.list.innerHTML='';
    if(this.query.trim()){
      for(const row of prepared)this.list.appendChild(row.node);
    }else{
      for(const category of categories){
        const group=document.createElement('div');
        group.setAttribute('class','scenario-picker-group');
        if(category){
          const heading=document.createElement('div');
          group.setAttribute('role','group');group.setAttribute('aria-label',category);
          heading.setAttribute('class','scenario-picker-group-title');heading.textContent=category;group.appendChild(heading);
        }
        for(const row of prepared.filter(row=>row.option.category===category))group.appendChild(row.node);
        this.list.appendChild(group);
      }
    }
    if(!categories.length)this.list.innerHTML='<div class="scenario-picker-empty">'+pickerEscape(this.emptyMessage)+'</div>';
    this.updateActive();
  }
  updateActive(scroll=true) {
    const active=this.results?.[this.activeIndex];
    this.list.querySelectorAll(this.optionSelector).forEach(option=>option.classList.toggle('is-active',option.getAttribute(this.optionAttribute)===active?.id));
    if(active){this.input.setAttribute('aria-activedescendant',this.optionPrefix+'-'+active.id);if(scroll)this.list.querySelector('#'+this.optionPrefix+'-'+active.id)?.scrollIntoView({block:'nearest',inline:'nearest'});}
    else this.input.removeAttribute('aria-activedescendant');
  }
  choose(id) {const result=this.results?.find(option=>option.id===id);if(!result)return;this.close();this.onSelect(id,result);}
  keydown(event) {
    if(event.isComposing)return;
    if(event.key==='Escape'){event.preventDefault();this.close();return;}
    if(event.key==='Tab'){this.close();return;}
    // Leave modified navigation to the platform's text-editing shortcuts.
    if(event.shiftKey||event.ctrlKey||event.metaKey||event.altKey)return;
    if(event.key==='Enter'){if(this.opened){event.preventDefault();const active=this.results[this.activeIndex];if(active)this.choose(active.id);}return;}
    if(!['ArrowDown','ArrowUp','Home','End'].includes(event.key))return;
    if(['Home','End'].includes(event.key)&&!this.opened)return;
    event.preventDefault();const wasOpen=this.opened;this.open();if(!this.results.length)return;
    if(event.key==='Home')this.activeIndex=0;
    else if(event.key==='End')this.activeIndex=this.results.length-1;
    else if(!wasOpen)this.activeIndex=event.key==='ArrowDown'?0:this.results.length-1;
    else this.activeIndex=(this.activeIndex+(event.key==='ArrowDown'?1:-1)+this.results.length)%this.results.length;
    this.updateActive();
  }
}
