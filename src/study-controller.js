import { PresentationPreference } from './presentation-preference.js';
import { FullView } from './full-view.js';
import { CompactView } from './compact-view.js';
import { LAB_MODELS } from './lab-catalog.js';
import { getAttributeIds } from './attribute-usage.js';
import { heldCursorForPlayback, projectHeldObjects } from './held-object-state.js';
import { resolveActor } from './player.js';
import { captureFocusTarget, resolveFocusTarget, isVisibleFocusTarget } from './focus-target.js';
import { Localizer, LOCALES } from './localization.js';
import { LOCALIZATION_BINDINGS, LOCALIZATION_CATALOGS } from './localization-resources.js';
import { PNG_EXPORT_BINDINGS, PNG_EXPORT_CATALOGS } from './localization-png.js';
import { PngExporter } from './png-export.js';

const studyFocusAttributes = ['id','data-presentation-choice','data-compact-command','data-compact-action','data-compact-step-index','data-held-key','data-held-action','data-holding-id','data-index-attribute','data-attribute','data-trace-topic','data-actor','data-learning-detail','data-lesson-chapter','data-instance-history','href'];
const studyDetailAttributes = ['data-study-key','data-compact-disclosure','data-instance-history','data-pam-disclosure','data-remote-comparison'];
const studyDetailKey = node => {
  const key=node.id?'id:'+node.id:studyDetailAttributes.map(name=>node.hasAttribute(name)?name+':'+node.getAttribute(name):'').find(Boolean);
  if(!key)throw new Error('A study disclosure requires an explicit stable binding.');
  return key;
};
const studyLocaleEscape=value=>String(value??'').replace(/[&<>"']/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));

/** Shared methods on the one custom-element controller, not another session. */
export class StudyController extends HTMLElement {
  initializeLocale() {
    if(!this.localizer)this.localizer=new Localizer({host:window,catalogs:LOCALIZATION_CATALOGS,bindings:LOCALIZATION_BINDINGS,additionalBindings:PNG_EXPORT_BINDINGS,additionalCatalogs:PNG_EXPORT_CATALOGS});
    return this.localizer.initialPreparation;
  }
  clearLocaleFailure() {
    this.localeFailure=null;
    if(this.refs?.toast?.hasAttribute('data-locale-failure')){this.refs.toast.hidden=true;this.refs.toast.removeAttribute('data-locale-failure');}
  }
  reportLocaleFailure(tag,error) {
    this.pendingLocale=null;this.localizer.discardPrepared();
    this.localeFailure={tag,error};
    const requested=Localizer.metadata(tag).name,current=Localizer.metadata(this.localizer.locale).name;
    this.showToast('Could not load '+requested+'. '+current+' remains active. Choose another language or retry when offline language resources are available.','en');
    clearTimeout(this.toastTimer);this.toastTimer=null;this.refs.toast.setAttribute('data-locale-failure','');
    if(this.refs['language-select'])this.refs['language-select'].value=this.localizer.locale;
  }
  initializePresentation() {
    this.initializeLocale();
    this.localeCompositions=new Set();this.localeDeferredInputs=new Set();this.pendingLocale=null;this.localeFlushTimer=null;this.localePreparation=null;
    this.presentationPreference=new PresentationPreference(window);
    this.presentationMode=this.presentationPreference.mode;this.presentationSource=this.presentationPreference.source;
    this.presentationStates={full:{},compact:{}};this.sharedListeners=[];
    this.pngExporter=new PngExporter(this);
    this.fullView=new FullView(this);this.compactView=new CompactView(this);
  }
  cacheRefs() {
    this.refs={};for(const node of this.querySelectorAll('[id]'))this.refs[node.id]=node;
    this.applyLocaleMetadata();
    for(const input of this.querySelectorAll('input[type="search"]'))input.setAttribute('dir','auto');
  }
  applyLocaleMetadata() {
    if(!this.localizer)return;
    this.localizer.metadata(this,{documentOwner:this.hasAttribute('data-document-owner')});
    if(this.refs?.studio)this.localizer.metadata(this.refs.studio);
    // Toasts retain the language of the message actually shown, not the next UI locale.
    for(const id of ['actor-popup','attribute-popup','search-case-choice'])if(this.refs?.[id])this.localizer.metadata(this.refs[id]);
    if(this.refs?.['language-select'])this.refs['language-select'].value=this.localizer.locale;
  }
  languageSelectorHtml() {
    return '<label class="language-control" for="language-select"><span id="language-label">'+this.localizer.html('ui.locale.label','Language')+'</span><select id="language-select" aria-labelledby="language-label">'+LOCALES.map(locale=>'<option value="'+locale.tag+'" lang="'+locale.tag+'" dir="'+locale.direction+'"'+(locale.tag===this.localizer.locale?' selected':'')+'>'+studyLocaleEscape(locale.name)+'</option>').join('')+'</select></label>';
  }
  refreshSharedLocaleChrome() {
    // Re-render owned chrome only. Picker instances, inputs and live drafts stay mounted.
    const staging=document.createElement('div');staging.innerHTML=this.shell();
    for(const selector of ['.app-header','.sources-footer']){
      const previous=this.querySelector(selector),next=staging.querySelector(selector);
      previous.parentElement.replaceChild(next,previous);
    }
    for(const id of ['actor-popup','attribute-popup']){
      const previous=this.querySelector('#'+id),next=staging.querySelector('#'+id);
      if(previous.hasAttribute('aria-label'))previous.setAttribute('aria-label',next.getAttribute('aria-label'));
    }
    for(const picker of [this.scenarioPicker,this.workspacePicker]){
      const next=staging.querySelector('#'+picker.root.id);
      for(const attribute of ['aria-label','title'])if(next.hasAttribute(attribute))picker.root.setAttribute(attribute,next.getAttribute(attribute));
      const previousLabel=picker.root.querySelector('label'),nextLabel=next.querySelector('label');
      if(previousLabel&&nextLabel)previousLabel.innerHTML=nextLabel.innerHTML;
      const previousHint=picker.root.querySelector('.scenario-picker-hint'),nextHint=next.querySelector('.scenario-picker-hint');
      if(previousHint&&nextHint)previousHint.innerHTML=nextHint.innerHTML;
      const previousKeys=picker.root.querySelector('.scenario-picker-menu-heading > span:last-child'),nextKeys=next.querySelector('.scenario-picker-menu-heading > span:last-child');
      if(previousKeys&&nextKeys)previousKeys.innerHTML=nextKeys.innerHTML;
      picker.refreshLocale();
    }
    this.cacheRefs();this.renderPickerHints();
    if(this.searchCaseChoice)this.renderSearchCaseChoice();
  }
  captureLocaleAnchor() {
    if(typeof document.elementFromPoint!=='function')return null;
    let node=document.elementFromPoint(Math.min(36,window.innerWidth-1),Math.min(100,window.innerHeight-1));
    node=node?.closest('[data-index-attribute],[data-compact-step-index],[data-study-key],[id]');
    if(!node||!this.contains(node)||node.closest('.app-header'))return null;
    for(const attribute of ['data-index-attribute','data-compact-step-index','data-study-key','id'])if(node.hasAttribute(attribute))return {attribute,value:node.getAttribute(attribute),top:node.getBoundingClientRect().top};
    return null;
  }
  restoreLocaleAnchor(anchor) {
    if(!anchor||typeof window.scrollBy!=='function')return;
    const node=[...this.querySelectorAll('['+anchor.attribute+']')].find(candidate=>candidate.getAttribute(anchor.attribute)===anchor.value);
    if(node)window.scrollBy({top:node.getBoundingClientRect().top-anchor.top,behavior:'auto'});
  }
  changeLocale(tag,{explicit=true}={}) {
    if(!Localizer.valid(tag))throw new RangeError('Unknown display locale.');
    if(this.localePreparation){this.pendingLocale={tag,explicit};return this.localePreparation;}
    if(tag===this.localizer.locale){this.pendingLocale=null;this.localizer.discardPrepared();this.clearLocaleFailure();if(this.refs?.['language-select'])this.refs['language-select'].value=tag;return false;}
    if(this.localeCompositions.size||[this.scenarioPicker,this.workspacePicker].some(picker=>picker.composing)){
      this.pendingLocale={tag,explicit};return false;
    }
    if(!this.localizer.needsPreparation(tag))return this.commitLocale(tag,{explicit});
    // Pause before decoding. No source state is captured and later restored
    // across the asynchronous gap; a deliberate intervening user action wins.
    const suppressed=this.suppressStudyAnnouncement;this.suppressStudyAnnouncement=true;
    try{if(this.player.status==='playing')this.player.pause();}finally{this.suppressStudyAnnouncement=suppressed;}
    this.pendingLocale={tag,explicit};this.setAttribute('aria-busy','true');
    this.localePreparation=(async()=>{
      while(this.pendingLocale){
        let request=this.pendingLocale;this.pendingLocale=null;
        if(request.tag===this.localizer.locale){this.localizer.discardPrepared();this.clearLocaleFailure();return false;}
        if(this.localizer.needsPreparation(request.tag))try{await this.localizer.prepare(request.tag);}catch(error){
          const latest=this.pendingLocale;this.pendingLocale=null;this.localizer.discardPrepared();
          if(latest&&latest.tag!==request.tag){this.pendingLocale=latest;continue;}
          if(this.isConnected)this.reportLocaleFailure(request.tag,error);
          return false;
        }
        const latest=this.pendingLocale;this.pendingLocale=null;
        if(latest&&latest.tag!==request.tag){this.pendingLocale=latest;continue;}
        if(latest)request=latest;
        if(!this.isConnected)return false;
        if(this.localeCompositions.size||[this.scenarioPicker,this.workspacePicker].some(picker=>picker.composing)){this.pendingLocale=request;return false;}
        return this.commitLocale(request.tag,{explicit:request.explicit});
      }
      return false;
    })().finally(()=>{
      this.localePreparation=null;this.localizer.discardPrepared();this.removeAttribute('aria-busy');
      if(this.refs?.['language-select'])this.refs['language-select'].value=this.localizer.locale;
    });
    return this.localePreparation;
  }
  commitLocale(tag,{explicit=true}={}) {
    this.pendingLocale=null;
    const priorSuppression=this.suppressStudyAnnouncement;this.suppressStudyAnnouncement=true;
    try{
      // Player callbacks establish the exact postpause prefix before any display capture.
      if(this.player.status==='playing')this.player.pause();
      const paused=this.player.snapshot(),anchor=this.captureLocaleAnchor(),active=document.activeElement,focus=captureFocusTarget(this,active);
      const presentationOwned=this.querySelector('#presentation-host').contains(active),summaryKey=this.contains(active)&&active?.tagName==='SUMMARY'&&!presentationOwned?studyDetailKey(active.parentElement):null;
      this.capturePresentationState();
      const disclosures=new Map([...this.querySelectorAll('details')].map(node=>[studyDetailKey(node),node.hasAttribute('open')]));
      const help=['actor','attribute'].map(kind=>({kind,open:!this.refs[kind+'-popup'].hidden,target:this[kind+'FocusTarget'],id:this[kind+'HelpId']}));
      clearTimeout(this.closeTimer);clearTimeout(this.attributeTimer);
      // Validate the selected catalog before destroying the current presentation.
      try{this.localizer.activate(tag,{persist:explicit});}catch(error){this.reportLocaleFailure(tag,error);return false;}
      this.clearLocaleFailure();
      this.releaseActorDrag();this.presenter.unmount();this.querySelector('#presentation-host').innerHTML='';
      this.fieldSearchRecords=null;this.activeFieldTopicText=null;this.fieldSearchRevision=-1;
      this.refreshSharedLocaleChrome();
      this.mountPresentation('presentation',paused);
      this.restorePresentationState(null,undefined,{restoreFocus:false});
      for(const node of this.querySelectorAll('details'))if(disclosures.has(studyDetailKey(node))){
        const open=disclosures.get(studyDetailKey(node));node.open=open;if(open)node.setAttribute('open','');else node.removeAttribute('open');
      }
      for(const item of help){
        this.refs[item.kind+'-popup'].hidden=true;this[item.kind+'Anchor']=null;
        if(!item.open||!item.id)continue;
        const target=resolveFocusTarget(this,item.target);
        if(target)(item.kind==='actor'?this.showActorPopup(item.id,target):this.showAttributePopup(item.id,target));
      }
      this.applyLocaleMetadata();this.restoreLocaleAnchor(anchor);
      if(this.refs['held-announcement'])this.refs['held-announcement'].textContent='';
      if(explicit)this.refs['language-select'].focus({preventScroll:true});
      else if(presentationOwned)this.resolvePresentationFocus()?.focus({preventScroll:true});
      else if(summaryKey)[...this.querySelectorAll('details')].find(node=>studyDetailKey(node)===summaryKey)?.querySelector('summary')?.focus({preventScroll:true});
      else if(focus)this.restoreTargetFocus(focus,{preventScroll:true});
      if(explicit){
        const name=Localizer.metadata(tag).name;
        this.notify('ui.locale.changed','Language changed to '+name+'.',{language:name});
      }
      return true;
    }finally{this.suppressStudyAnnouncement=priorSuppression;}
  }
  finishLocaleComposition(target) {
    this.localeCompositions.delete(target);clearTimeout(this.localeFlushTimer);
    if(target.id==='attribute-search')this.attributeQuery=target.value;
    else if(target.id==='lab-search')this.catalogQuery=target.value;
    else if(target.id==='glossary-search')this.glossaryQuery=target.value;
    if(['attribute-search','lab-search','glossary-search'].includes(target.id))this.localeDeferredInputs.add(target);
    this.localeFlushTimer=setTimeout(()=>{
      if(this.localeCompositions.size)return;
      const inputs=[...this.localeDeferredInputs];this.localeDeferredInputs.clear();
      if(this.pendingLocale){const pending=this.pendingLocale;this.changeLocale(pending.tag,{explicit:pending.explicit});}
      else for(const input of inputs)if(input.isConnected)input.dispatchEvent(new Event('input',{bubbles:true}));
    },0);
  }
  listenShared(node,type,listener,options) {
    node.addEventListener(type,listener,options);this.sharedListeners.push([node,type,listener,options]);
  }
  listenFull(node,type,listener,options) {this.fullView.listen(node,type,listener,options);}
  bindShared() {
    this.listenShared(this,'click',event=>{
      if(event.target.closest('[data-png-export]')){this.pngExporter.save();return;}
      const choice=event.target.closest('[data-presentation-choice]');
      if(choice){this.switchPresentation(choice.dataset.presentationChoice);return;}
      if(event.target.closest('#theme-toggle')){this.theme=this.theme==='dark'?'light':'dark';this.refs.studio.dataset.theme=this.theme;}
      else if(event.target.closest('#index-open'))this.openFieldIndex();
      else if(event.target.closest('#glossary-open')){if(this.presentationMode==='compact')this.openFieldIndex();else{this.inspection={type:'glossary'};this.renderInspector();}}
    });
    this.listenShared(this,'change',event=>{if(event.target.id==='language-select')this.changeLocale(event.target.value);});
    this.listenShared(this,'compositionstart',event=>this.localeCompositions.add(event.target));
    this.listenShared(this,'compositionend',event=>this.finishLocaleComposition(event.target));
    for(const picker of [this.scenarioPicker,this.workspacePicker]){
      this.listenShared(picker.root,'focusin',()=>{if(this.presentationMode==='compact')this.pauseForStudy();});
      this.listenShared(picker.root,'pointerdown',()=>{if(this.presentationMode==='compact')this.pauseForStudy();});
    }
    this.listenShared(this.querySelector('#search-case-choice'),'click',event=>{
      const target=event.target.closest('[data-search-case]');
      if(target&&this.searchCaseChoice){const id=this.searchCaseChoice.id,variant=target.dataset.searchCase;this.closeSearchCaseChoice();this.selectLabScenario(id,{variant});this.querySelector('#play')?.focus();this.announceSelectedCase();}
      else if(event.target.closest('[data-cancel-search-case]'))this.closeSearchCaseChoice(true);
    });
    this.listenShared(this.querySelector('#search-case-choice'),'keydown',event=>{if(event.isComposing||event.keyCode===229)return;if(event.key==='Escape'){event.preventDefault();this.closeSearchCaseChoice(true);}});
    this.listenShared(this,'click',event=>{const target=event.target.closest('[data-compare-scenario]');if(target&&LAB_MODELS[target.dataset.compareScenario])this.selectJourneyFromControl(target,target.dataset.compareScenario,{variant:target.dataset.compareVariant||'default'});});
    this.routeListener=()=>this.openRoute();this.listenShared(window,'hashchange',this.routeListener);
    this.environmentPageHide=()=>this.resetEnvironment();this.environmentPageShow=event=>{if(event.persisted)this.resetEnvironment();};
    this.listenShared(window,'pagehide',this.environmentPageHide);this.listenShared(window,'pageshow',this.environmentPageShow);
    this.windowBlurListener=()=>{if(this.player.status==='playing')this.player.pause();};this.listenShared(window,'blur',this.windowBlurListener);
    this.motion=window.matchMedia('(prefers-reduced-motion: reduce)');this.motionChange=()=>this.player.setReducedMotion(this.motion.matches);
    this.motion.addEventListener?.('change',this.motionChange);this.motionChange();
  }
  openFieldIndex() {
    if(this.presentationMode==='compact'){
      this.pauseForStudy();const details=this.refs['attribute-index'].closest('details');details.open=true;details.setAttribute('open','');
    }
    this.refs['attribute-index'].hidden=false;this.renderAttributeIndex();this.refs['attribute-search'].focus();
  }
  updatePresentationControls() {
    this.refs.studio.dataset.presentationMode=this.presentationMode;
    for(const button of this.querySelectorAll('[data-presentation-choice]'))button.setAttribute('aria-pressed',String(button.dataset.presentationChoice===this.presentationMode));
  }
  invalidatePresentationCaches() {
    this.protocolRenderKey=null;this.pamRenderKey=null;this.remoteEvidenceKey=null;this.windowsComparisonKey=null;this.chapterControlsModel=null;this.attributeIndexRows=null;this.stepOverlayIdentity='';this.packetIdentity='';this.heldView.lastKey='';
  }
  mountPresentation(reason='initial',event=this.player.snapshot()) {
    this.releaseExactCopyDownload();
    this.presenter=this.presentationMode==='compact'?this.compactView:this.fullView;
    this.presenter.mount(this.querySelector('#presentation-host'));
    if(this.presentationMode==='compact')this.cacheRefs();
    this.refs['attribute-search'].value=this.attributeQuery;
    if(this.refs['lab-search'])this.refs['lab-search'].value=this.catalogQuery;
    if(this.presentationStates[this.presentationMode].indexHidden!==undefined)this.refs['attribute-index'].hidden=this.presentationStates[this.presentationMode].indexHidden;
    this.invalidatePresentationCaches();this.updatePresentationControls();this.presenter.render(reason,event);this.pngExporter.update();
  }
  capturePresentationState() {
    const host=this.querySelector('#presentation-host'),active=document.activeElement,state=this.presentationStates[this.presentationMode];
    state.indexHidden=this.refs['attribute-index'].hidden;
    state.scroll={x:window.scrollX||0,y:window.scrollY||0};state.focus=null;
    if(host.contains(active)){
      for(const attribute of studyFocusAttributes)if(active.hasAttribute(attribute)){state.focus={attribute,value:active.getAttribute(attribute)};break;}
      if(!state.focus&&active.tagName==='SUMMARY')state.focus={details:studyDetailKey(active.parentElement)};
      state.logicalFocus=captureFocusTarget(this,active);
    }
    state.disclosures=new Map([...host.querySelectorAll('details')].map(node=>[studyDetailKey(node),node.hasAttribute('open')]));
    if(this.presentationMode==='full'){const viewport=this.refs.graph.parentElement;state.graphScroll={x:viewport.scrollLeft,y:viewport.scrollTop};}
  }
  resolvePresentationFocus(commonFocus,target) {
    const state=this.presentationStates[this.presentationMode],host=this.querySelector('#presentation-host');let focus=null;
    if(target==='configuration'){
      const panel=this.querySelector('#advanced-configuration');panel.open=true;panel.setAttribute('open','');focus=[...panel.querySelectorAll('select,input,button,summary')].find(node=>isVisibleFocusTarget(this,node));
    }else if(target==='diagram'){focus=this.querySelector('#scenario-title');focus.setAttribute('tabindex','-1');}
    else if(commonFocus)focus=[...this.querySelectorAll('['+commonFocus.attribute+']')].find(node=>node.getAttribute(commonFocus.attribute)===commonFocus.value);
    else if(state.focus?.attribute)focus=[...host.querySelectorAll('['+state.focus.attribute+']')].find(node=>node.getAttribute(state.focus.attribute)===state.focus.value);
    else if(state.focus?.details)focus=[...host.querySelectorAll('details')].find(node=>studyDetailKey(node)===state.focus.details)?.querySelector('summary');
    if(!focus&&state.logicalFocus)focus=resolveFocusTarget(this,state.logicalFocus);
    return isVisibleFocusTarget(this,focus)?focus:this.querySelector('[data-presentation-choice="'+this.presentationMode+'"]');
  }
  restorePresentationState(commonFocus,target,{restoreFocus=true}={}) {
    const state=this.presentationStates[this.presentationMode],host=this.querySelector('#presentation-host');
    if(state.indexHidden!==undefined)this.refs['attribute-index'].hidden=state.indexHidden;
    if(state.disclosures)for(const details of host.querySelectorAll('details'))if(state.disclosures.has(studyDetailKey(details))){const open=state.disclosures.get(studyDetailKey(details));details.open=open;if(open)details.setAttribute('open','');else details.removeAttribute('open');}
    if(this.presentationMode==='full'&&state.graphScroll){const viewport=this.refs.graph.parentElement;viewport.scrollLeft=state.graphScroll.x;viewport.scrollTop=state.graphScroll.y;}
    if(!restoreFocus){if(state.scroll&&typeof window.scrollTo==='function')window.scrollTo(state.scroll.x,state.scroll.y);return;}
    const focus=this.resolvePresentationFocus(commonFocus,target);
    focus?.focus({preventScroll:true});
    if(target)focus?.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
    else if(state.scroll&&typeof window.scrollTo==='function')window.scrollTo(state.scroll.x,state.scroll.y);
    if(focus&&typeof window.getComputedStyle==='function'){
      const rect=focus.getBoundingClientRect();
      if(rect.top<8||rect.bottom>window.innerHeight-8||rect.left<0||rect.right>window.innerWidth)focus.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
      const bar=host.querySelector('.compact-playback');
      if(bar&&!bar.contains(focus)&&window.getComputedStyle(bar).position==='sticky'){
        const top=bar.getBoundingClientRect().top,bottom=focus.getBoundingClientRect().bottom;
        if(top>=0&&top<window.innerHeight&&bottom>top-8)window.scrollBy({top:bottom-top+8,behavior:'auto'});
      }
    }
  }
  switchPresentation(mode,{target}={}) {
    if(mode!=='compact'&&mode!=='full')throw new RangeError('Unknown presentation.');
    this.presentationPreference.select(mode);this.presentationSource=this.presentationPreference.source;
    if(mode===this.presentationMode){this.updatePresentationControls();if(target)this.restorePresentationState(null,target);return;}
    // Pause first; player callbacks establish the exact postpause canonical prefix.
    const wasPlaying=this.player.status==='playing';if(wasPlaying)this.player.pause();
    const paused=this.player.snapshot(),host=this.querySelector('#presentation-host'),active=document.activeElement;
    const commonFocus=!host.contains(active)&&this.contains(active)?studyFocusAttributes.filter(attribute=>active.hasAttribute(attribute)).map(attribute=>({attribute,value:active.getAttribute(attribute)}))[0]:null;
    this.capturePresentationState();this.hidePopups();
    for(const kind of ['actor','attribute']){this.refs[kind+'-popup'].innerHTML='';this[kind+'Anchor']=null;this[kind+'FocusTarget']=null;}
    this.scenarioPicker.suspend();this.workspacePicker.suspend();this.releaseActorDrag();
    this.presenter.unmount();host.innerHTML='';this.presentationMode=mode;
    // Mounting is presentation-only: no selection, configuration, route or reset.
    this.suppressStudyAnnouncement=true;
    try {this.mountPresentation('presentation',paused);this.restorePresentationState(commonFocus,target);}
    finally {this.suppressStudyAnnouncement=false;}
    if(mode==='compact')this.notify(wasPlaying?'ui.view.compact-paused':'ui.view.compact',wasPlaying?'Compact view. Playback paused.':'Compact view.');
    else this.notify(wasPlaying?'ui.view.full-paused':'ui.view.full',wasPlaying?'Full view. Playback paused.':'Full view.');
  }
  destroyPresentation() {
    this.releaseExactCopyDownload();
    this.pngExporter.dispose();
    this.presenter?.unmount();this.presenter=null;
    clearTimeout(this.localeFlushTimer);this.pendingLocale=null;this.localeCompositions?.clear();
    this.localeDeferredInputs?.clear();
    for(const [node,type,listener,options]of this.sharedListeners||[])node.removeEventListener(type,listener,options);
    if(this.sharedListeners)this.sharedListeners.length=0;
    this.motion?.removeEventListener?.('change',this.motionChange);
  }
  releaseActorDrag() {
    const drag=this.dragState;if(!drag)return;
    drag.card.classList.remove('is-dragging');
    if(typeof drag.card.releasePointerCapture==='function'&&(!drag.card.hasPointerCapture||drag.card.hasPointerCapture(drag.pointerId)))drag.card.releasePointerCapture(drag.pointerId);
    this.dragState=null;
  }
  pauseForStudy(){if(this.player.status==='playing')this.player.pause();}
  studyActor(id) {
    const actors=this.heldView.compiled().plan.actors;return actors[id]||actors[resolveActor(id,this.authenticator)]||this.actor(id);
  }
  studyQueue() {
    const playback=this.player.snapshot(),loaded=this.player.queue.length>0;
    const rows=loaded?this.player.queue:this.hasTrace?this.traceQueue:this.steps;
    const kind=loaded?playback.kind:this.objectTraceSelection?'object':this.attributeSelection?'attribute':'demo';
    const cursor=this.heldView.snapshot(playback).cursor;
    const initial=!rows.length?false:playback.inspectionBoundary==='initial'||!loaded&&this.heldView.initial!==false&&!this.heldView.selected;
    const position=initial?-1:loaded?this.player.position:Math.max(0,this.visibleIndex);
    const row=rows[Math.max(0,position)],atEnd=!initial&&!!row&&(loaded?playback.stepElapsed>=playback.duration:this.heldView.selected===true);
    const rowComplete=rows.map((_,index)=>!initial&&(index<position||index===position&&atEnd));
    const sourceIndex=row?.sourceIndex??this.steps.findIndex(step=>step.id===(row?.sourceStepId||row?.id));
    const sourceComplete=sourceIndex>=0&&cursor.eventIndex===sourceIndex&&cursor.milestone==='complete';
    const scoped=kind!=='demo'||this.hasTrace;
    const actionReplay=kind==='step'||kind==='attribute-step'||kind==='trace-step';
    const parentHistory=this.objectTraceSelection?'exact object history: '+this.objectTraceSelection:this.attributeSelection?'field history: '+this.selectionName():'';
    const label=actionReplay?'Selected action replay'+(parentHistory?' within '+parentHistory:''):kind==='connection'?'Connection replay':kind==='trace-connection'?'Connection replay within the selected history':kind==='object'?'Exact object history: '+this.objectTraceSelection:kind==='attribute'?'Field path: '+this.selectionName():'Journey';
    return {rows,kind,label,position,initial,atEnd,empty:!rows.length,playback:playback.status,playerSnapshot:playback,cursor,rowComplete,sourceComplete,scoped};
  }
  queueCursor(rows,position,edge,kind) {
    if(!rows.length)return this.heldView.snapshot().cursor;
    if(edge==='initial'&&kind==='demo')return projectHeldObjects(this.heldView.compiled(),{eventIndex:-1,milestone:'initial'}).cursor;
    const row=rows[position],duration=this.player.durationFor(row),elapsed=edge==='end'?duration:0;
    return heldCursorForPlayback(this.heldView.compiled(),{step:row,queue:rows,queuePosition:position,kind,status:'paused',elapsed,stepElapsed:elapsed,duration},row,{initial:false,selected:false});
  }
  inspectQueueBoundary(index,edge='end') {
    this.pauseForStudy();const queue=this.studyQueue();if(queue.empty)return false;
    if(!Number.isInteger(index)||index< -1||index>=queue.rows.length)throw new RangeError('Unknown active-queue row.');
    if(index===-1)edge='initial';if(!['initial','start','end'].includes(edge))throw new RangeError('Unknown active-queue boundary.');
    const position=edge==='initial'?0:index,cursor=this.queueCursor(queue.rows,position,edge,queue.kind);
    return this.player.inspectQueue(queue.rows,{position,elapsed:edge==='end'?this.player.durationFor(queue.rows[position]):0,kind:queue.kind,cursor,boundary:edge});
  }
  inspectSourceCursor(cursor) {
    this.pauseForStudy();const compiled=this.heldView.compiled(),canonical=projectHeldObjects(compiled,cursor).cursor,rows=this.steps;
    this.attributeSelection=null;this.objectTraceSelection=null;this.traceQueue=[];this.traceIndex=0;this.attributeUsages=[];this.inspection={type:'step'};
    if(!rows.length)return this.player.inspectQueue(rows,{cursor:canonical});
    const position=Math.max(0,canonical.eventIndex),row=rows[position];
    const at=canonical.eventIndex<0||canonical.milestone==='before'?0:canonical.milestone==='complete'?1:compiled.plan.events[row.id].milestones.find(item=>item.id===canonical.milestone).at;
    return this.player.inspectQueue(rows,{position,elapsed:this.player.durationFor(row)*at,kind:'demo',cursor:canonical,boundary:canonical.eventIndex<0?'initial':at===1?'end':at===0?'start':null});
  }
  enterFieldTrace(id) {
    this.pauseForStudy();id=this.labAttributeAlias(id);if(!getAttributeIds(id).length)return false;
    const previous=this.heldView.snapshot().cursor;
    this.objectTraceSelection=null;this.attributeSelection=id;this.traceIndex=0;this.attributeUsages=this.attributeUsage(this.steps,id);this.traceQueue=this.buildAttributeTrace(id,this.attributeUsages);this.inspection=this.traceInspection();
    const queue=this.traceQueue,cursor=queue.length?this.queueCursor(queue,0,'initial','attribute'):previous;
    return this.player.inspectQueue(queue,{kind:'attribute',cursor,boundary:queue.length?'initial':null});
  }
  enterObjectTrace(artifactId) {
    this.pauseForStudy();const previous=this.heldView.snapshot().cursor,queue=this.heldView.buildTrace(artifactId);
    this.attributeSelection=null;this.objectTraceSelection=artifactId;this.traceQueue=queue;this.traceIndex=0;this.inspection={type:'step'};
    const cursor=queue.length?this.queueCursor(queue,0,'initial','object'):previous;
    return this.player.inspectQueue(queue,{kind:'object',cursor,boundary:queue.length?'initial':null});
  }
  returnToJourney(){const cursor=this.heldView.snapshot().cursor;return this.inspectSourceCursor(cursor);}
  playCompact() {
    const queue=this.studyQueue();if(queue.empty)return;
    if(this.player.status==='playing'){this.player.pause();return;}
    this.ensureRunningSpeed();
    if(queue.initial||queue.position===queue.rows.length-1&&queue.atEnd){this.player.play(queue.rows,queue.kind);return;}
    if(this.player.queue!==queue.rows)this.player.inspectQueue(queue.rows,{position:Math.max(0,queue.position),elapsed:queue.atEnd?this.player.durationFor(queue.rows[Math.max(0,queue.position)]):0,kind:queue.kind,cursor:queue.cursor,boundary:queue.atEnd?'end':'start'});
    this.player.resume();
  }
  setLearningDetail(detail) {
    if(!['journey','fields','crypto'].includes(detail))throw new RangeError('Unknown lesson detail.');
    this.learningDetail=detail;
    if(this.presentationMode==='compact')this.compactView.render('detail');else{this.renderLearningProfile();this.updateStep();this.renderInspector();}
  }
  renderCompactEvidence() {
    this.renderScenarioDescription();this.renderLabSupport();this.renderLearningProfile();this.renderPamConfiguration();this.renderProtocolState();
    if(!this.refs['attribute-index'].hidden)this.renderAttributeIndex();
  }
  releaseExactCopyDownload() {
    if(!this.exactCopyDownloadURL)return;
    URL.revokeObjectURL(this.exactCopyDownloadURL);this.exactCopyDownloadURL=null;
    for(const link of this.querySelectorAll('[data-exact-copy-download]'))link.parentElement.removeChild(link);
  }
  async copyExactValue(value,trigger) {
    const text=typeof value==='string'?value:String(value);
    this.releaseExactCopyDownload();
    try {
      if(!globalThis.navigator?.clipboard?.writeText)throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(text);this.notify('ui.copy.exact-copied','Exact value copied.');return true;
    }catch{
      if(!this.contains(trigger))return false;
      this.releaseExactCopyDownload();
      const parent=trigger.parentElement;let field=parent.querySelector('[data-exact-copy-fallback]');
      if(!field){field=document.createElement('textarea');field.className='exact-copy-fallback';field.setAttribute('data-exact-copy-fallback','');field.readOnly=true;parent.appendChild(field);}
      field.setAttribute('aria-label',this.localizer.text('ui.copy.exact-fallback-label','Exact untruncated value to copy'));field.setAttribute('dir','ltr');field.setAttribute('translate','no');
      field.value=text;field.textContent=text;
      if(field.value!==text){
        // Textarea values normalize line endings. Export raw UTF-8 when manual copy cannot preserve them.
        parent.removeChild(field);const link=document.createElement('a');
        this.exactCopyDownloadURL=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8',endings:'transparent'}));
        link.href=this.exactCopyDownloadURL;link.download='auth-flow-studio-value.txt';link.className='button quiet';link.setAttribute('data-exact-copy-download','');
        link.innerHTML=this.localizer.html('ui.copy.save-exact','Save exact value');parent.appendChild(link);link.focus();
        this.notify('ui.copy.download-unavailable','Clipboard unavailable. Save the file to preserve the exact value.');return false;
      }
      field.focus();field.select?.();this.notify('ui.copy.unavailable','Clipboard unavailable. Select and copy the exact value in the text box.');return false;
    }
  }
  notify(key,source,parameters={}) {this.showToast(this.localizer.text(key,source,parameters),this.localizer.language(key));}
}
