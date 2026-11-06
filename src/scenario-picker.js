import {createSearchFields,mergeSearchFields,prepareSearchQuery,rankSearchFields,localizedSearchIndex} from './locale-search.js';
const pickerEscape = value => String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const pickerSearchCache = new WeakMap();
const pickerValues = value => Array.isArray(value)?value:value==null?[]:[value];
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
  cached={signature,base:createSearchFields({phrases,identifiers,context}),variants:(option.searchVariants||[]).map(variant=>({
    id:variant.id,label:variant.label||variant.id,
    fields:createSearchFields({phrases:[variant.label,...pickerValues(variant.searchTags)],identifiers:[variant.id,...pickerValues(variant.searchIdentifiers)],context:pickerValues(variant.searchContext)}),
  }))};
  pickerSearchCache.set(option,cached);
  return cached;
};

export function filterScenarioOptions(options,query,localization=null,kind='scenario') {
  const prepared=prepareSearchQuery(query);
  if(prepared.empty)return options.filter((option,index)=>options.findIndex(row=>row.id===option.id)===index);
  if(!prepared.variants.length)return [];
  const rows=[],seen=new Set();
  const rank=(fields,localized,parent=null,localizedParent=null)=>{
    const original=rankSearchFields(fields,prepared,parent);
    if(original===0)return original;
    const translated=localized?rankSearchFields(localized,prepared,localizedParent):null;
    // Tiers are at least 0.5 apart: original exact names keep equal-quality
    // priority, but cannot demote a better localized prose match.
    const localizedRank=translated===null?null:translated+0.25;
    return original===null?localizedRank:localizedRank===null?original:Math.min(original,localizedRank);
  };
  for(const option of options){
    if(seen.has(option.id))continue;
    seen.add(option.id);
    const index=pickerSearchIndex(option),overlay=localizedSearchIndex(localization,kind,option.id,option);
    if(overlay&&!overlay.combined){
      const variants=new Map(overlay.variants.map(variant=>[variant.id,variant.fields]));
      overlay.combined={base:mergeSearchFields(index.base,overlay.base),variants:new Map(index.variants.map(variant=>[variant.id,mergeSearchFields(variant.fields,variants.get(variant.id))]))};
    }
    const baseRank=rank(index.base,overlay?.combined.base);
    const matches=index.variants.map(variant=>({...variant,rank:rank(variant.fields,overlay?.combined.variants.get(variant.id),index.base,overlay?.combined.base)})).filter(variant=>variant.rank!==null&&(baseRank===null||variant.rank<baseRank));
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
  constructor(root,options,onSelect,outsideRoot,{prefix='lab-scenario',optionPrefix='scenario-option',optionAttribute='data-scenario-option',singular='scenario',plural='scenarios',emptyMessage='No matching scenarios. Try a protocol, profile, field or learning objective.',localization=null,localizationKind=prefix==='workspace'?'workspace':'scenario'}={}) {
    this.root=root;this.options=options;this.onSelect=onSelect;this.selectedId='core';
    this.optionPrefix=optionPrefix;this.optionAttribute=optionAttribute;this.optionSelector='['+optionAttribute+']';
    this.singular=singular;this.plural=plural;this.emptyMessage=emptyMessage;
    this.localization=localization;this.localizationKind=localizationKind;
    this.composing=false;this.localeRefreshPending=false;
    this.opened=false;this.query='';this.activeIndex=-1;this.listeners=[];
    this.suspended=null;this.draft=null;
    this.optionNodes=new Map();
    // Prepare static metadata before interaction, not on the first keystroke.
    // Content signatures still invalidate in-place edits when filtering.
    for(const option of options)pickerSearchIndex(option);
    this.input=root.querySelector('#'+prefix+'-search');this.menu=root.querySelector('#'+prefix+'-menu');
    this.list=root.querySelector('#'+prefix+'-results');this.status=root.querySelector('#'+prefix+'-search-status');
    this.clearButton=root.querySelector('#'+prefix+'-clear');this.toggleButton=root.querySelector('#'+prefix+'-toggle');
    this.listen(this.input,'focusin',()=>this.open());
    this.listen(this.input,'click',()=>this.open());
    this.listen(this.input,'input',()=>{this.suspended=null;this.draft=null;this.query=this.input.value;if(this.composing)return;if(this.opened)this.render();else this.open(true);});
    this.listen(this.input,'compositionstart',()=>{this.composing=true;if(!this.opened)this.open(true);});
    this.listen(this.input,'compositionend',()=>{
      this.composing=false;
      if(this.opened)this.query=this.input.value;
      if(this.localeRefreshPending)this.refreshLocale();
      else if(this.opened)this.render();
    });
    this.listen(this.input,'keydown',event=>this.keydown(event));
    this.listen(root,'focusout',event=>{if(!root.contains(event.relatedTarget))this.close({preserveDraft:true});});
    this.listen(root,'pointerdown',event=>{if(event.target.closest('button'))event.preventDefault();});
    this.listen(this.list,'click',event=>{const option=event.target.closest(this.optionSelector);if(option)this.choose(option.getAttribute(this.optionAttribute));});
    this.listen(this.clearButton,'click',()=>{this.suspended=null;this.draft=null;this.query='';this.input.value='';this.open();this.render();this.input.focus();});
    this.listen(this.toggleButton,'click',()=>{if(this.opened)this.close();else{this.open();this.input.focus();}});
    const closeOutside=event=>{if(!root.contains(event.target))this.close({preserveDraft:true});};
    this.listen(document,'pointerdown',closeOutside);
    if(outsideRoot&&outsideRoot!==document)this.listen(outsideRoot,'pointerdown',closeOutside);
    this.refreshControls();
    this.setSelected(options.some(option=>option.id==='core')?'core':options[0]?.id);
  }
  listen(node,type,listener) {node.addEventListener(type,listener);this.listeners.push([node,type,listener]);}
  destroy() {this.listeners.forEach(([node,type,listener])=>node.removeEventListener(type,listener));this.listeners=[];this.optionNodes.clear();this.suspended=null;this.draft=null;}
  setSelected(id) {if(!this.options.some(option=>option.id===id))return;this.selectedId=id;this.close();}
  text(key,source,params={}) {return this.localization?.text(key,source,params)??source;}
  count(key,count,source) {return this.localization?.plural(key,count,source,{count})??source;}
  matchCount(count) {return this.count('ui.scenario-picker.'+this.localizationKind+'.match-count',count,count+' matching '+(count===1?this.singular:this.plural));}
  sourceOption(option) {return option.variantId||option.matchingVariantIds?this.options.find(source=>source.id===option.id)||option:option;}
  owner(option) {return (this.localizationKind==='workspace'?'workspace-option:':'lesson:')+option.id;}
  displayText(option,field,source,context={}) {
    if(source==null)return '';
    const canonical=this.sourceOption(option),entry=localizedSearchIndex(this.localization,this.localizationKind,canonical.id,canonical)?.entry;
    if(!context.variantId&&typeof entry?.[field]==='string')return entry[field];
    return this.localization?.explain(this.owner(canonical),field,source,context)??source;
  }
  displayHtml(option,field,source,context={}) {
    if(source==null)return '';
    return this.localization?.explainHtml
      ?this.localization.explainHtml(this.owner(option),field,source,context)
      :pickerEscape(this.displayText(option,field,source,context));
  }
  selectedLabel() {
    const option=this.options.find(option=>option.id===this.selectedId);
    return option?this.displayText(option,option.selectedLabel?'selectedLabel':'title',option.selectedLabel||option.title):'';
  }
  caseHtml(option) {
    if(option.matchingVariantIds)return pickerEscape(this.count('ui.scenario-picker.matching-cases',option.matchingVariantIds.length,option.caseLabel));
    return this.displayHtml(option,option.variantId?'searchVariants.label':'caseLabel',option.caseLabel,option.variantId?{variantId:option.variantId}:{});
  }
  refreshControls() {
    const workspace=this.localizationKind==='workspace',key='ui.scenario-picker.'+this.localizationKind+'.';
    this.clearButton.setAttribute('aria-label',this.text(key+'clear',workspace?'Clear workspace search':'Clear scenario search'));
    this.toggleButton.setAttribute('aria-label',this.text(key+'toggle',workspace?'Show workspace and family choices':'Show scenario choices'));
    this.list.setAttribute('aria-label',this.text(key+'results',workspace?'Workspaces and families':'Lab scenarios'));
    this.input.setAttribute('placeholder',this.text(key+'placeholder',workspace?'Search workspaces and families':'Search scenarios, protocols or attributes…'));
  }
  /** A locale refresh never starts a fresh search or promotes a first match. */
  refreshLocale() {
    if(this.composing){this.localeRefreshPending=true;return false;}
    this.localeRefreshPending=false;this.refreshControls();
    const activeId=this.results?.[this.activeIndex]?.id;
    this.optionNodes.clear();
    if(this.opened)this.render({preserveActive:true,activeId,scrollActive:false});
    else{
      this.list.innerHTML='';
      const retained=this.suspended||this.draft;
      this.results=filterScenarioOptions(this.options,retained?.query??this.query,this.localization,this.localizationKind);
      this.activeIndex=retained?this.results.findIndex(option=>option.id===retained.activeId):-1;
      if(retained&&this.activeIndex<0)retained.activeId=null;
      this.status.textContent=this.matchCount(this.results.length);
      if(!this.suspended)this.input.value=this.selectedLabel();
      this.input.removeAttribute('aria-activedescendant');
    }
    return true;
  }
  open(fromInput=false) {
    if(this.opened)return;
    this.opened=true;const suspended=this.suspended;this.suspended=null;this.draft=null;
    // Only an explicit presenter switch restores a draft. Ordinary reopening
    // starts fresh, while native input retains its caret and IME composition.
    if(suspended){this.query=suspended.query;this.input.value=this.query;}
    else if(!fromInput){this.query='';this.input.value='';}
    this.menu.hidden=false;
    this.input.setAttribute('aria-expanded','true');this.toggleButton.setAttribute('aria-expanded','true');
    this.root.classList.add('is-open');this.render({preserveActive:!!suspended,activeId:suspended?.activeId});
  }
  close({preserveDraft=false}={}) {
    if(preserveDraft){
      if(this.suspended)return;
      // A single candidate survives transient dismissal, not a search history.
      // Repeated blur/outside events must not overwrite it with the reset UI.
      if(this.opened)this.draft=this.query.trim()?{query:this.query,activeId:this.results?.[this.activeIndex]?.id}:null;
    }else{this.suspended=null;this.draft=null;}
    this.opened=false;this.query='';this.activeIndex=-1;this.menu.hidden=true;this.clearButton.hidden=true;
    this.input.value=this.selectedLabel();
    this.input.setAttribute('aria-expanded','false');this.input.removeAttribute('aria-activedescendant');
    this.toggleButton.setAttribute('aria-expanded','false');this.root.classList.remove('is-open');
  }
  /** Only a presenter switch promotes the last transiently dismissed draft. */
  suspend() {
    if(this.suspended)return;
    const draft=this.opened?{query:this.query,activeId:this.results?.[this.activeIndex]?.id}:this.draft;
    this.draft=null;
    if(!draft?.query.trim()){this.close();return;}
    this.suspended=draft;this.query=draft.query;this.input.value=this.query;
    this.opened=false;this.menu.hidden=true;this.clearButton.hidden=!this.query;
    this.input.setAttribute('aria-expanded','false');this.input.removeAttribute('aria-activedescendant');
    this.toggleButton.setAttribute('aria-expanded','false');this.root.classList.remove('is-open');
  }
  render({preserveActive=false,activeId,scrollActive=true}={}) {
    this.results=filterScenarioOptions(this.options,this.query,this.localization,this.localizationKind);
    this.activeIndex=preserveActive?this.results.findIndex(option=>option.id===activeId):(this.query.trim()?0:Math.max(0,this.results.findIndex(option=>option.id===this.selectedId)));
    if(!this.results.length)this.activeIndex=-1;
    this.clearButton.hidden=!this.query;
    this.status.textContent=this.matchCount(this.results.length);
    const categories=[...new Set(this.results.map(option=>option.category))];
    const prepared=this.results.map(option=>{
      const markup=`<button type="button" role="option" tabindex="-1" class="scenario-picker-option" id="${this.optionPrefix}-${option.id}" ${this.optionAttribute}="${option.id}" aria-selected="${option.id===this.selectedId}"><span class="scenario-picker-option-text"><strong>${this.displayHtml(option,'title',option.title)}</strong><span>${this.displayHtml(option,'summary',option.summary)}</span>${option.caseLabel?`<small class="scenario-picker-case">${this.caseHtml(option)}</small>`:''}${this.query.trim()&&option.category?`<small>${this.displayHtml(option,'category',option.category)}</small>`:''}${option.profileLabel?`<small class="scenario-picker-profile"><bdi dir="ltr" translate="no">${pickerEscape(option.profileLabel)}</bdi></small>`:''}</span><span class="scenario-picker-option-check" aria-hidden="true">${option.id===this.selectedId?'✓':''}</span></button>`;
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
          const source=this.results.find(option=>option.category===category);
          group.setAttribute('role','group');group.setAttribute('aria-label',this.displayText(source,'category',category));
          heading.setAttribute('class','scenario-picker-group-title');heading.innerHTML=this.displayHtml(source,'category',category);group.appendChild(heading);
        }
        for(const row of prepared.filter(row=>row.option.category===category))group.appendChild(row.node);
        this.list.appendChild(group);
      }
    }
    if(!categories.length)this.list.innerHTML='<div class="scenario-picker-empty">'+pickerEscape(this.text('ui.scenario-picker.'+this.localizationKind+'.empty',this.emptyMessage))+'</div>';
    this.updateActive(scrollActive);
  }
  updateActive(scroll=true) {
    const active=this.results?.[this.activeIndex];
    this.list.querySelectorAll(this.optionSelector).forEach(option=>option.classList.toggle('is-active',option.getAttribute(this.optionAttribute)===active?.id));
    if(active){this.input.setAttribute('aria-activedescendant',this.optionPrefix+'-'+active.id);if(scroll)this.list.querySelector('#'+this.optionPrefix+'-'+active.id)?.scrollIntoView({block:'nearest',inline:'nearest'});}
    else this.input.removeAttribute('aria-activedescendant');
  }
  choose(id) {if(this.composing)return;const result=this.results?.find(option=>option.id===id);if(!result)return;this.close();this.onSelect(id,result);}
  keydown(event) {
    if(this.composing||event.isComposing||event.keyCode===229)return;
    if(event.key==='Escape'){event.preventDefault();this.close();return;}
    if(event.key==='Tab'){this.close({preserveDraft:true});return;}
    // Leave modified navigation to the platform's text-editing shortcuts.
    if(event.shiftKey||event.ctrlKey||event.metaKey||event.altKey)return;
    if(event.key==='Enter'){if(this.opened){event.preventDefault();const active=this.results[this.activeIndex];if(active)this.choose(active.id);}return;}
    if(!['ArrowDown','ArrowUp','Home','End'].includes(event.key))return;
    if(['Home','End'].includes(event.key)&&!this.opened)return;
    event.preventDefault();const wasOpen=this.opened;this.open();if(!this.results.length)return;
    if(event.key==='Home')this.activeIndex=0;
    else if(event.key==='End')this.activeIndex=this.results.length-1;
    else if(!wasOpen||this.activeIndex<0)this.activeIndex=event.key==='ArrowDown'?0:this.results.length-1;
    else this.activeIndex=(this.activeIndex+(event.key==='ArrowDown'?1:-1)+this.results.length)%this.results.length;
    this.updateActive();
  }
}
