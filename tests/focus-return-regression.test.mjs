import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {captureFocusTarget,resolveFocusTarget,isVisibleFocusTarget} from '../src/focus-target.js';

// Explicit focus fixtures exercise application decisions, not native browser
// Tab order, focus navigation, computed CSS, or screen-reader announcements.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mount(){
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
function focus(node){
  assert.ok(node,'focus fixture exists');const previous=document.activeElement;document.activeElement=node;
  previous?.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:node}));node.dispatchEvent(new HarnessEvent('focusin',{relatedTarget:previous}));
}
function key(node,value){const event=new HarnessEvent('keydown',{key:value});node.dispatchEvent(event);return event;}
function returnedFocus(node){assert.ok(document.activeElement===node,'focus returns to the expected visible current control');}
function modelFocusRemoval(container){
  const property=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(container),'innerHTML'),removed=[];
  Object.defineProperty(container,'innerHTML',{
    configurable:true,
    get(){return property.get.call(this);},
    set(html){
      const focused=this.contains(document.activeElement)?document.activeElement:null;
      property.set.call(this,html);
      if(focused&&!document.contains(focused)){removed.push(focused);document.activeElement=document.body;}
    }
  });
  return removed;
}
function playToBasicRedirect(app){
  app.selectLabScenario('basic-keycloak');app.refs.play.click();
  clock.until(()=>app.currentStep.id==='single-web-password-l02');
  assert.equal(app.player.status,'playing');
}

test('logical targets resolve a rebuilt inspector field before trying its index entry',()=>{
  const app=mount();try{
    app.selectLabScenario('basic-keycloak');app.selectStep(app.steps.findIndex(step=>step.id==='single-web-password-l02'));
    const before=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');
    const target=captureFocusTarget(app,before);assert.equal(target.attributeId,'redirectApp');assert.equal(target.region,'inspector');
    app.renderInspector();const after=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');
    assert.notEqual(after,before);assert.equal(app.contains(before),false);assert.equal(resolveFocusTarget(app,target),after);
  }finally{unmount(app);}
});

test('closed dialogs and hidden index ancestors never become return targets',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const field=app.refs['actor-popup'].querySelector('[data-attribute="redirectApp"]');assert.ok(field);
    const target=captureFocusTarget(app,field);assert.equal(target.actorId,'app');
    app.hidePopups();app.refs['attribute-index'].hidden=true;
    assert.equal(isVisibleFocusTarget(app,field),false);
    assert.equal(resolveFocusTarget(app,target),card);
    card.hidden=true;assert.equal(resolveFocusTarget(app,target),app.refs.play);
  }finally{unmount(app);}
});

test('collapsed advanced details reject descendants while their summary remains visible',()=>{
  const root=document.createElement('section');root.innerHTML='<details><summary><button id="summary-action">Options</button></summary><button id="collapsed-action">Hidden control</button></details><button id="play">Play</button>';
  document.body.appendChild(root);try{
    const details=root.querySelector('details'),button=root.querySelector('#collapsed-action');
    const target=captureFocusTarget(root,button);
    assert.equal(isVisibleFocusTarget(root,button),false);assert.equal(resolveFocusTarget(root,target),root.querySelector('#play'));
    assert.equal(isVisibleFocusTarget(root,root.querySelector('#summary-action')),true);
    details.open=true;assert.equal(resolveFocusTarget(root,target),button);
    details.setAttribute('inert','');assert.equal(isVisibleFocusTarget(root,button),false);
  }finally{document.body.removeChild(root);}
});

test('R2: explanation Escape after ongoing playback resolves a current inspector field',()=>{
  const app=mount();try{
    playToBasicRedirect(app);
    const before=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(before);key(before,'F2');
    const source=document.activeElement;assert.ok(app.refs['attribute-popup'].contains(source));assert.equal(app.player.status,'playing');
    clock.until(()=>app.currentStep.id==='single-web-password-l03');
    assert.equal(app.contains(before),false);assert.equal(app.refs['attribute-popup'].hidden,false);
    const current=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');assert.ok(current,'next step also carries redirect_uri');
    key(source,'Escape');assert.equal(app.refs['attribute-popup'].hidden,true);
    returnedFocus(current);assert.equal(app.player.status,'playing');
    clock.advance(1000);assert.equal(app.refs['attribute-popup'].hidden,true,'focus return does not reopen the explanation');
  }finally{unmount(app);}
});

test('explanation Escape after its field disappears uses the visible attribute index',()=>{
  const app=mount();try{
    playToBasicRedirect(app);
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
    const source=document.activeElement;
    clock.until(()=>app.currentStep.id==='single-web-password-p01');
    assert.ok(!app.refs.inspector.querySelector('[data-attribute="redirectApp"]'),'current step no longer exposes redirect_uri');
    key(source,'Escape');
    const index=app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]');
    returnedFocus(index);assert.equal(app.refs['attribute-popup'].hidden,true);assert.equal(app.player.status,'playing');
  }finally{unmount(app);}
});

test('explanation Escape uses Play when its original field and index are unavailable',()=>{
  const app=mount();try{
    playToBasicRedirect(app);app.refs['attribute-index'].hidden=true;
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
    const source=document.activeElement;clock.until(()=>app.currentStep.id==='single-web-password-p01');key(source,'Escape');
    returnedFocus(app.refs.play);assert.equal(app.refs['attribute-popup'].hidden,true);assert.equal(app.player.status,'playing');
  }finally{unmount(app);}
});

test('activating a rebuilt inspector field transfers focus to its current selected index entry',()=>{
  const app=mount();try{
    playToBasicRedirect(app);
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);field.click();
    const index=app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]');
    assert.equal(app.attributeSelection,'redirectApp');assert.equal(app.contains(field),false);
    returnedFocus(index);assert.equal(index.getAttribute('aria-pressed'),'true');
    assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('activating a participant-panel field moves focus out of the closed panel',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const field=app.refs['actor-popup'].querySelector('[data-attribute="redirectApp"]');focus(field);field.click();
    const index=app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]');
    assert.equal(app.attributeSelection,'redirectApp');assert.equal(app.refs['actor-popup'].hidden,true);
    returnedFocus(index);assert.equal(index.getAttribute('aria-pressed'),'true');
    assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('activating a participant field with the index hidden falls back to its actor card',()=>{
  const app=mount();try{
    app.refs['attribute-index'].hidden=true;
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const field=app.refs['actor-popup'].querySelector('[data-attribute="redirectApp"]');focus(field);field.click();
    assert.equal(app.attributeSelection,'redirectApp');assert.equal(app.refs['actor-popup'].hidden,true);
    returnedFocus(card);assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('Basic startup hides advanced controls from focus targets and Custom configuration exposes them',()=>{
  const app=mount();try{
    assert.equal(app.labScenarioId,'basic-keycloak');
    assert.equal(isVisibleFocusTarget(app,app.refs.mode),false);
    assert.equal(isVisibleFocusTarget(app,app.refs['app-protocol']),false);
    app.selectLabScenario('core');
    assert.equal(isVisibleFocusTarget(app,app.refs.mode),true);
    assert.equal(isVisibleFocusTarget(app,app.refs['app-protocol']),true);
  }finally{unmount(app);}
});

test('ready-made SAML selection keeps its stable quick-preset button focused',()=>{
  const app=mount();try{
    const preset=app.querySelector('[data-learning-preset="basic-saml"]');focus(preset);preset.click();
    assert.equal(app.labScenarioId,'basic-saml');assert.equal(app.applicationProtocol,'saml');
    assert.ok(app.contains(preset));returnedFocus(preset);
    assert.equal(preset.getAttribute('aria-pressed'),'true');
  }finally{unmount(app);}
});

test('hiding the attribute index returns focus to its visible reopen button',()=>{
  const app=mount();try{
    const close=app.querySelector('#attribute-index-toggle');focus(close);close.click();
    assert.equal(app.refs['attribute-index'].hidden,true);
    returnedFocus(app.querySelector('#index-open'));
    assert.equal(isVisibleFocusTarget(app,document.activeElement),true);
  }finally{unmount(app);}
});

test('R5: later playback rebuild retains field focus after the repaired F2 and Escape path',()=>{
  const app=mount();try{
    const removed=modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);
    const first=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(first);key(first,'F2');
    const source=document.activeElement;clock.until(()=>app.currentStep.id==='single-web-password-l03');
    assert.ok(app.refs['attribute-popup'].contains(document.activeElement),'inspector rebuilding leaves explanation focus alone');
    key(source,'Escape');const second=document.activeElement;
    assert.equal(second.dataset.attribute,'redirectApp');assert.ok(app.refs.inspector.contains(second));
    clock.until(()=>app.currentStep.id==='single-web-password-l04');
    const third=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');
    assert.ok(removed.includes(second),'fixture invalidated the removed focused trigger');
    assert.ok(!app.contains(second));returnedFocus(third);assert.ok(second!==third);
    assert.equal(app.player.status,'playing');assert.equal(app.refs['attribute-popup'].hidden,true,'focus recovery suppresses popup reopening');
  }finally{unmount(app);}
});

test('inspector field focus moves to its visible index entry when the next message omits it',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'Escape');
    clock.until(()=>app.currentStep.id==='single-web-password-p01');
    const index=app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]');
    returnedFocus(index);assert.equal(app.player.status,'playing');assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('inspector field focus falls back to Play when its message and index are unavailable',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);app.refs['attribute-index'].hidden=true;
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'Escape');
    clock.until(()=>app.currentStep.id==='single-web-password-p01');
    returnedFocus(app.refs.play);assert.equal(app.player.status,'playing');assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('inspector playback updates never take focus away from another control',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);focus(app.refs.speed);
    clock.until(()=>app.currentStep.id==='single-web-password-l04');
    returnedFocus(app.refs.speed);assert.equal(app.player.status,'playing');
    const index=app.refs['attribute-index-list'].querySelector('[data-index-attribute="stateApp"]');focus(index);
    app.renderInspector();returnedFocus(index);
  }finally{unmount(app);}
});

test('R5: selecting the DPoP catalog card restores focus to its rebuilt selected card',()=>{
  const app=mount();try{
    const removed=modelFocusRemoval(app.refs['lab-cards']);app.querySelector('#lab-open').click();
    const card=app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-dpop"]');assert.ok(card);focus(card);card.click();
    const replacement=app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-dpop"]');
    assert.equal(app.labScenarioId,'lab-dpop');assert.ok(removed.includes(card));assert.ok(!app.contains(card));
    assert.ok(replacement!==card);returnedFocus(replacement);assert.equal(replacement.getAttribute('aria-pressed'),'true');
    assert.equal(isVisibleFocusTarget(app,replacement),true);
  }finally{unmount(app);}
});

test('a removed or hidden catalog card hands focus to the scenario picker, then Play if needed',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs['lab-cards']);app.querySelector('#lab-open').click();
    focus(app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-dpop"]'));
    app.catalogQuery='no-matching-scenario-in-this-fixture';app.renderCatalog();
    returnedFocus(app.querySelector('#lab-scenario-search'));
    app.catalogQuery='';app.renderCatalog();focus(app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-dpop"]'));
    app.refs['lab-catalog'].open=false;app.querySelector('#lab-scenario-picker').hidden=true;app.renderCatalog();
    returnedFocus(app.refs.play);assert.equal(isVisibleFocusTarget(app,document.activeElement),true);
  }finally{unmount(app);}
});

test('catalog refresh does not take focus from its search field or another region',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs['lab-cards']);app.querySelector('#lab-open').click();
    focus(app.refs['lab-search']);app.catalogQuery='DPoP';app.renderCatalog();returnedFocus(app.refs['lab-search']);
    focus(app.refs.speed);app.catalogQuery='';app.renderCatalog();returnedFocus(app.refs.speed);
  }finally{unmount(app);}
});

test('timeline seeking keeps focus on its range control while rebuilding the inspector',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
    assert.equal(app.refs['attribute-popup'].hidden,false);focus(app.refs.seek);
    for(const value of ['770','100','0','1000']){
      app.refs.seek.value=value;app.refs.seek.dispatchEvent(new HarnessEvent('input'));
      returnedFocus(app.refs.seek);assert.equal(app.player.status,'paused');
      assert.equal(app.refs['attribute-popup'].hidden,true);
      assert.ok(app.refs.seek.getAttribute('aria-valuetext').includes(' of '),'seek preview exposes its position');
    }
    const elapsed=app.player.elapsed;clock.advance(1000);assert.equal(app.player.elapsed,elapsed);returnedFocus(app.refs.seek);
  }finally{unmount(app);}
});

test('zero and slow speed controls preserve focus and explicit Play resumes without replacing its button',()=>{
  const app=mount();try{
    modelFocusRemoval(app.refs.inspector);playToBasicRedirect(app);focus(app.refs.speed);
    app.refs.speed.value='0';app.refs.speed.dispatchEvent(new HarnessEvent('input'));
    returnedFocus(app.refs.speed);assert.equal(app.player.status,'paused');assert.equal(app.player.speed,0);
    app.refs.speed.value='0.02';app.refs.speed.dispatchEvent(new HarnessEvent('input'));
    returnedFocus(app.refs.speed);assert.equal(app.player.status,'paused');assert.equal(app.player.speed,0.02);
    const play=app.refs.play;focus(play);play.click();returnedFocus(play);assert.equal(app.player.status,'playing');
    clock.advance(1000);returnedFocus(play);assert.ok(app.contains(play));
  }finally{unmount(app);}
});
