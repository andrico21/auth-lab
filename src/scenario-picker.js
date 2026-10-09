const pickerEscape = value => String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const pickerNormalize = value => String(value).normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase();

export function filterScenarioOptions(options,query) {
  const terms=pickerNormalize(query).trim().split(/\s+/).filter(Boolean);
  return options.filter(option=>terms.every(term=>pickerNormalize([option.title,option.category,option.summary,option.searchText].join(' ')).includes(term)));
}

/** An editable combobox. Filtering does not activate a scenario. */
export class ScenarioPicker {
  constructor(root,options,onSelect,outsideRoot) {
    this.root=root;this.options=options;this.onSelect=onSelect;this.selectedId='core';
    this.opened=false;this.query='';this.activeIndex=-1;this.listeners=[];
    this.input=root.querySelector('#lab-scenario-search');this.menu=root.querySelector('#lab-scenario-menu');
    this.list=root.querySelector('#lab-scenario-results');this.status=root.querySelector('#lab-scenario-search-status');
    this.clearButton=root.querySelector('#lab-scenario-clear');this.toggleButton=root.querySelector('#lab-scenario-toggle');
    this.listen(this.input,'focusin',()=>this.open());
    this.listen(this.input,'click',()=>this.open());
    this.listen(this.input,'input',()=>{const value=this.input.value;this.open();this.query=value;this.input.value=value;this.render();});
    this.listen(this.input,'keydown',event=>this.keydown(event));
    this.listen(root,'focusout',event=>{if(!root.contains(event.relatedTarget))this.close();});
    this.listen(root,'pointerdown',event=>{if(event.target.closest('button'))event.preventDefault();});
    this.listen(this.list,'click',event=>{const option=event.target.closest('[data-scenario-option]');if(option)this.choose(option.dataset.scenarioOption);});
    this.listen(this.clearButton,'click',()=>{this.query='';this.input.value='';this.open();this.render();this.input.focus();});
    this.listen(this.toggleButton,'click',()=>{if(this.opened)this.close();else{this.open();this.input.focus();}});
    const closeOutside=event=>{if(!root.contains(event.target))this.close();};
    this.listen(document,'pointerdown',closeOutside);
    if(outsideRoot&&outsideRoot!==document)this.listen(outsideRoot,'pointerdown',closeOutside);
    this.setSelected('core');
  }
  listen(node,type,listener) {node.addEventListener(type,listener);this.listeners.push([node,type,listener]);}
  destroy() {this.listeners.forEach(([node,type,listener])=>node.removeEventListener(type,listener));this.listeners=[];}
  setSelected(id) {if(!this.options.some(option=>option.id===id))return;this.selectedId=id;this.close();}
  open() {
    if(this.opened)return;
    this.opened=true;this.query='';this.input.value='';this.menu.hidden=false;
    this.input.setAttribute('aria-expanded','true');this.toggleButton.setAttribute('aria-expanded','true');
    this.root.classList.add('is-open');this.render();
  }
  close() {
    this.opened=false;this.query='';this.menu.hidden=true;this.clearButton.hidden=true;
    this.input.value=this.options.find(option=>option.id===this.selectedId)?.title||'';
    this.input.setAttribute('aria-expanded','false');this.input.removeAttribute('aria-activedescendant');
    this.toggleButton.setAttribute('aria-expanded','false');this.root.classList.remove('is-open');
  }
  render() {
    this.results=filterScenarioOptions(this.options,this.query);
    this.activeIndex=this.query.trim()?0:Math.max(0,this.results.findIndex(option=>option.id===this.selectedId));
    if(!this.results.length)this.activeIndex=-1;
    this.clearButton.hidden=!this.query;
    this.status.textContent=this.results.length+' matching '+(this.results.length===1?'scenario':'scenarios');
    const categories=[...new Set(this.results.map(option=>option.category))];
    this.list.innerHTML=categories.map(category=>`<div class="scenario-picker-group" role="group" aria-label="${pickerEscape(category)}"><div class="scenario-picker-group-title">${pickerEscape(category)}</div>${this.results.filter(option=>option.category===category).map(option=>`<button type="button" role="option" tabindex="-1" class="scenario-picker-option" id="scenario-option-${option.id}" data-scenario-option="${option.id}" aria-selected="${option.id===this.selectedId}"><span class="scenario-picker-option-text"><strong>${pickerEscape(option.title)}</strong><span>${pickerEscape(option.summary)}</span></span><span class="scenario-picker-option-check" aria-hidden="true">${option.id===this.selectedId?'✓':''}</span></button>`).join('')}</div>`).join('')||'<div class="scenario-picker-empty">No matching scenarios. Try “password”, “PKCE”, “SAML”, or “refresh”.</div>';
    this.updateActive();
  }
  updateActive(scroll=true) {
    const active=this.results?.[this.activeIndex];
    this.list.querySelectorAll('[data-scenario-option]').forEach(option=>option.classList.toggle('is-active',option.dataset.scenarioOption===active?.id));
    if(active){this.input.setAttribute('aria-activedescendant','scenario-option-'+active.id);if(scroll)this.list.querySelector('#scenario-option-'+active.id)?.scrollIntoView({block:'nearest',inline:'nearest'});}
    else this.input.removeAttribute('aria-activedescendant');
  }
  choose(id) {if(!this.options.some(option=>option.id===id))return;this.close();this.onSelect(id);}
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
