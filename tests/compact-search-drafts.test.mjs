import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, unmount, document, window, HarnessEvent, canonical } from './compact-fixture.mjs';

// These deterministic event sequences cover application behavior, not native
// browser Tab traversal, layout or screen-reader announcements.
const kinds=['scenario','workspace'];
const other=mode=>mode==='compact'?'full':'compact';
const pickerFor=(app,kind)=>app[kind+'Picker'];
const rows=picker=>[...picker.list.querySelectorAll(picker.optionSelector)];
const rowIds=picker=>rows(picker).map(row=>row.getAttribute(picker.optionAttribute));
const active=picker=>{
  const id=picker.input.getAttribute('aria-activedescendant');
  return id?picker.root.querySelector('#'+id):null;
};
const key=(picker,value,init={})=>{
  const event=new HarnessEvent('keydown',{key:value,...init});picker.input.dispatchEvent(event);return event;
};
function type(picker,value) {
  picker.input.focus();picker.input.value=value;picker.input.dispatchEvent(new HarnessEvent('input'));
}
function selectedTitle(picker) {
  const option=picker.options.find(option=>option.id===picker.selectedId);
  return option.selectedLabel||option.title;
}
function dismissed(picker) {
  assert.equal(picker.menu.hidden,true);
  assert.equal(picker.input.value,selectedTitle(picker));
  assert.equal(picker.input.getAttribute('aria-expanded'),'false');
  assert.equal(picker.toggleButton.getAttribute('aria-expanded'),'false');
  assert.equal(picker.input.hasAttribute('aria-activedescendant'),false);
  assert.equal(picker.clearButton.hidden,true);
}
function fresh(picker) {
  picker.input.focus();
  assert.equal(picker.menu.hidden,false);assert.equal(picker.input.value,'');
  assert.equal(picker.input.getAttribute('aria-expanded'),'true');
  assert.equal(picker.clearButton.hidden,true);
  assert.deepEqual(rowIds(picker).sort(),[...new Set(picker.options.map(option=>option.id))].sort());
}
function beginDraft(picker,query='kerberos') {
  type(picker,query);assert.ok(rows(picker).length>1,'the draft has multiple real results');
  const ids=rowIds(picker);key(picker,'End');
  const highlighted=active(picker);
  assert.equal(highlighted?.getAttribute(picker.optionAttribute),ids.at(-1));
  assert.notEqual(highlighted?.getAttribute(picker.optionAttribute),ids[0],'restoration must not silently reset to the first match');
  return {query,ids,activeId:highlighted.id};
}
function restored(picker,draft) {
  picker.input.focus();
  assert.equal(picker.menu.hidden,false);assert.equal(picker.input.value,draft.query);
  assert.equal(picker.input.getAttribute('aria-expanded'),'true');
  assert.equal(picker.clearButton.hidden,false);
  assert.deepEqual(rowIds(picker),draft.ids);
  assert.equal(active(picker)?.id,draft.activeId);
  assert.equal(active(picker)?.classList.contains('is-active'),true);
}
function transfer(picker,target,method) {
  if(method==='keyboard')assert.equal(key(picker,'Tab',{shiftKey:true}).defaultPrevented,false);
  else target.dispatchEvent(new HarnessEvent('pointerdown'));
  picker.input.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:target}));
  target.focus();
}
function switchButton(app,mode) {return app.querySelector('[data-presentation-choice="'+mode+'"]');}
function state(app) {
  return {canonical:canonical(app),scenario:app.labScenarioId,workspace:app.workspace,family:app.family,
    config:app.protocolConfig(),variant:app.lessonVariant,route:window.location?.hash,
    player:app.player.snapshot(),attribute:app.attributeSelection,object:app.objectTraceSelection};
}

for(const kind of kinds)for(const mode of ['compact','full'])for(const method of ['keyboard','pointer'])test(kind+' draft and active result survive '+method+' '+mode+' view switching without selecting or evaluating',()=>{
  const app=mount({mode}),oldHistory=window.history,historyCalls=[];
  window.history={pushState:(...args)=>historyCalls.push(['push',...args]),replaceState:(...args)=>historyCalls.push(['replace',...args])};
  try{
    const picker=pickerFor(app,kind),source=app.scenarioSnapshot(),compiled=app.heldView.compiled(),before=state(app);
    const draft=beginDraft(picker),target=switchButton(app,other(mode));
    assert.deepEqual(state(app),before,'typing and result navigation are presentation-only');
    transfer(picker,target,method);dismissed(picker);
    // More focus transfers before activation must not replace the pending draft.
    target.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:document.body}));
    target.focus();target.click();assert.equal(app.presentationMode,other(mode));
    restored(picker,draft);
    assert.equal(app.scenarioSnapshot(),source,'browsing preserves the evaluated scenario object');
    assert.equal(app.heldView.compiled(),compiled,'browsing preserves the compiled canonical engine');
    assert.deepEqual(state(app),before);assert.deepEqual(historyCalls,[]);
    // Repeat in the other direction with the same draft and selected result.
    const back=switchButton(app,mode);transfer(picker,back,method);dismissed(picker);back.click();
    restored(picker,draft);assert.equal(app.presentationMode,mode);
    assert.deepEqual(state(app),before);assert.deepEqual(historyCalls,[]);
  }finally{unmount(app);if(oldHistory===undefined)delete window.history;else window.history=oldHistory;}
});

for(const kind of kinds)for(const mode of ['compact','full'])for(const method of ['keyboard','pointer'])test(kind+' empty visits keep the closed selected label across '+method+' '+mode+' view switches',()=>{
  const app=mount({mode}),oldHistory=window.history,historyCalls=[];
  window.history={pushState:(...args)=>historyCalls.push(['push',...args]),replaceState:(...args)=>historyCalls.push(['replace',...args])};
  try{
    const picker=pickerFor(app,kind),before=state(app),source=app.scenarioSnapshot(),compiled=app.heldView.compiled();
    for(const value of ['', ' \t '])for(const cause of ['Tab','blur','outside']){
      // Each visit traverses both directions. Whitespace is real input, while
      // the empty case is focused but untouched.
      for(const destination of [other(mode),mode]){
        fresh(picker);if(value)type(picker,value);
        const target=switchButton(app,destination);
        if(cause==='Tab')assert.equal(key(picker,'Tab').defaultPrevented,false);
        else if(cause==='blur')picker.input.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:target}));
        else if(cause==='outside')document.body.dispatchEvent(new HarnessEvent('pointerdown'));
        dismissed(picker);assert.equal(picker.draft,null);
        transfer(picker,target,method);target.click();
        assert.equal(app.presentationMode,destination);dismissed(picker);
        assert.equal(picker.draft,null);assert.equal(picker.suspended,null);
        fresh(picker);key(picker,'Escape');dismissed(picker);
        assert.deepEqual(state(app),before);assert.deepEqual(historyCalls,[]);
        assert.equal(app.scenarioSnapshot(),source);assert.equal(app.heldView.compiled(),compiled);
      }
    }
  }finally{unmount(app);if(oldHistory===undefined)delete window.history;else window.history=oldHistory;}
});

for(const kind of kinds)for(const mode of ['compact','full'])test(kind+' normal dismissals in '+mode+' reset the current field and never reopen an abandoned draft',()=>{
  const app=mount({mode});try{
    const picker=pickerFor(app,kind),target=switchButton(app,other(mode)),before=state(app);
    for(const cause of ['Tab','blur','outside']){
      beginDraft(picker);
      if(cause==='Tab')assert.equal(key(picker,'Tab').defaultPrevented,false);
      else if(cause==='blur')picker.input.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:target}));
      else document.body.dispatchEvent(new HarnessEvent('pointerdown'));
      dismissed(picker);
      // A normal reopen explicitly starts another search, even if the next
      // action is a presenter switch rather than more typing.
      fresh(picker);key(picker,'Escape');
      app.switchPresentation(other(app.presentationMode));fresh(picker);key(picker,'Escape');
      assert.deepEqual(state(app),before);
    }
  }finally{unmount(app);}
});

for(const kind of kinds)for(const mode of ['compact','full'])test(kind+' Escape, explicit cancel and clear in '+mode+' cannot resurrect cancelled text',()=>{
  const app=mount({mode});try{
    const picker=pickerFor(app,kind),before=state(app);
    for(const cancel of ['Escape','toggle','close','clear']){
      beginDraft(picker);
      if(cancel==='Escape')assert.equal(key(picker,'Escape').defaultPrevented,true);
      else if(cancel==='toggle')picker.toggleButton.click();
      else if(cancel==='close'){
        // Explicit cancellation also invalidates a transiently dismissed draft.
        key(picker,'Tab');picker.close();
      }else{
        picker.clearButton.click();assert.equal(picker.input.value,'');
        assert.equal(picker.menu.hidden,false);assert.equal(picker.clearButton.hidden,true);
        assert.deepEqual(rowIds(picker).sort(),[...new Set(picker.options.map(option=>option.id))].sort());
        key(picker,'Tab');
      }
      dismissed(picker);app.switchPresentation(other(app.presentationMode));fresh(picker);key(picker,'Escape');
      assert.deepEqual(state(app),before);
    }
    // Escape must cancel a draft already preserved by a prior view switch.
    beginDraft(picker);app.switchPresentation(other(app.presentationMode));key(picker,'Escape');
    app.switchPresentation(other(app.presentationMode));fresh(picker);
    assert.deepEqual(state(app),before);
  }finally{unmount(app);}
});

for(const kind of kinds)for(const mode of ['compact','full'])test(kind+' committed selection and context changes in '+mode+' invalidate prior drafts in both pickers',()=>{
  const app=mount({mode});try{
    const picker=pickerFor(app,kind),peer=pickerFor(app,kind==='scenario'?'workspace':'scenario');
    beginDraft(peer);key(peer,'Tab');
    type(picker,kind==='scenario'?'SAML Artifact':'SSH access');
    const id=kind==='scenario'?'lab-saml-artifact':'workspace-ssh';
    const chosen=rows(picker).find(row=>row.getAttribute(picker.optionAttribute)===id);
    assert.ok(chosen,'a real committed destination is available');chosen.click();
    assert.equal(app.labScenarioId,kind==='scenario'?'lab-saml-artifact':'lab-ssh-cert-success');
    dismissed(picker);dismissed(peer);
    app.switchPresentation(other(app.presentationMode));fresh(picker);key(picker,'Escape');fresh(peer);key(peer,'Escape');
    // A context change must invalidate a candidate closed before switching,
    // as well as one already promoted by an explicit presenter switch.
    for(const suspended of [false,true]){
      beginDraft(picker);key(picker,'Tab');
      if(suspended)app.switchPresentation(other(app.presentationMode));
      app.selectLabScenario(app.labScenarioId==='lab-dpop'?'lab-bff-api':'lab-dpop');
      const after=state(app);dismissed(picker);
      app.switchPresentation(other(app.presentationMode));fresh(picker);key(picker,'Escape');
      assert.deepEqual(state(app),after);
    }
    // Named-case changes retain the scenario ID but establish a new context.
    app.selectLabScenario('lab-pam01');beginDraft(picker);key(picker,'Tab');
    app.switchPresentation(other(app.presentationMode));
    app.selectLessonVariant('password-change-required');
    assert.equal(app.labScenarioId,'lab-pam01');assert.equal(app.lessonVariant,'password-change-required');
    const afterCase=state(app);dismissed(picker);
    app.switchPresentation(other(app.presentationMode));fresh(picker);assert.deepEqual(state(app),afterCase);
  }finally{unmount(app);}
});

for(const kind of kinds)test(kind+' switches retain only the newest unfinished query, including an empty result set',()=>{
  const app=mount();try{
    const picker=pickerFor(app,kind),before=state(app);
    beginDraft(picker);key(picker,'Tab');fresh(picker);
    type(picker,'zzzz-no-destination-zzzz');assert.equal(rows(picker).length,0);
    assert.equal(picker.input.hasAttribute('aria-activedescendant'),false);
    key(picker,'Tab');app.switchPresentation('full');picker.input.focus();
    assert.equal(picker.input.value,'zzzz-no-destination-zzzz');assert.equal(rows(picker).length,0);
    assert.equal(picker.input.hasAttribute('aria-activedescendant'),false);
    assert.equal(picker.menu.hidden,false);key(picker,'Enter');assert.deepEqual(state(app),before);
    key(picker,'Escape');app.switchPresentation('compact');fresh(picker);assert.deepEqual(state(app),before);
  }finally{unmount(app);}
});
