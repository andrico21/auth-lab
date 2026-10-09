import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// This harness cannot perform native Tab navigation or screen-reader testing.
// Explicit focus transitions below supply activeElement and relatedTarget;
// application-initiated focus is observed through its actual focusin event.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mount(){
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
function focus(node){const previous=document.activeElement;document.activeElement=node;previous?.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:node}));node.dispatchEvent(new HarnessEvent('focusin',{relatedTarget:previous}));}
function key(node,value,modifiers={}){const event=new HarnessEvent('keydown',{key:value,...modifiers});node.dispatchEvent(event);return event;}

test('attribute explanation is an accessible interactive dialog and retains focus beyond close timers',()=>{
  const app=mount();try{
    const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');
    focus(field);const popup=app.refs['attribute-popup'];
    assert.equal(popup.getAttribute('role'),'dialog');assert.equal(popup.getAttribute('aria-modal'),'false');
    assert.match(popup.getAttribute('aria-label'),/code_verifier/);
    assert.equal(field.getAttribute('aria-haspopup'),'dialog');assert.equal(field.getAttribute('aria-controls'),popup.id);
    assert.equal(key(field,'F2').defaultPrevented,true);
    const source=popup.querySelector('.source-link');assert.equal(document.activeElement,source);
    // A delayed pointer exit must not dismiss a panel containing keyboard focus.
    field.dispatchEvent(new HarnessEvent('mouseout'));popup.dispatchEvent(new HarnessEvent('mouseleave'));
    clock.advance(1000);assert.equal(popup.hidden,false);assert.ok(source.getAttribute('href').startsWith('https://'));
    focus(popup.querySelector('[data-close]'));clock.advance(1000);assert.equal(popup.hidden,false);
    key(document.activeElement,'Escape');assert.equal(popup.hidden,true);assert.equal(document.activeElement,field);
    assert.equal(field.getAttribute('aria-expanded'),'false');clock.advance(1000);assert.equal(popup.hidden,true,'focus return must not reopen it');
  }finally{unmount(app);}
});

test('participant and nested attribute dialogs retain focus and Escape returns to the correct trigger',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const actor=app.refs['actor-popup'];assert.ok(actor.contains(document.activeElement));
    card.dispatchEvent(new HarnessEvent('mouseout',{relatedTarget:actor}));clock.advance(1000);assert.equal(actor.hidden,false);
    const field=actor.querySelector('[data-attribute]');focus(field);key(field,'F2');
    const explanation=app.refs['attribute-popup'];assert.ok(explanation.contains(document.activeElement));
    actor.dispatchEvent(new HarnessEvent('mouseleave'));explanation.dispatchEvent(new HarnessEvent('mouseleave'));
    clock.advance(1000);assert.equal(actor.hidden,false);assert.equal(explanation.hidden,false);
    key(document.activeElement,'Escape');assert.equal(explanation.hidden,true);assert.equal(actor.hidden,false);assert.equal(document.activeElement,field);
    key(field,'Escape');assert.equal(actor.hidden,true);assert.equal(document.activeElement,card);
    clock.advance(1000);assert.equal(actor.hidden,true);assert.equal(explanation.hidden,true);
  }finally{unmount(app);}
});

test('close buttons return focus and a genuine outside focus transition dismisses help',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="realmA"]');focus(card);key(card,'F2');
    const close=app.refs['actor-popup'].querySelector('[data-close]');focus(close);close.click();
    assert.equal(document.activeElement,card);assert.equal(app.refs['actor-popup'].hidden,true);
    const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute="clientIdApp"]');focus(field);key(field,'F2');
    const attributeClose=app.refs['attribute-popup'].querySelector('[data-close]');focus(attributeClose);attributeClose.click();
    assert.equal(document.activeElement,field);assert.equal(app.refs['attribute-popup'].hidden,true);
    key(field,'F2');focus(app.refs.speed);clock.advance(1000);assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('re-hovering a participant or attribute preserves the focused dialog and nested return anchor',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const field=app.refs['actor-popup'].querySelector('[data-attribute]');focus(field);key(field,'F2');
    const source=document.activeElement;
    card.dispatchEvent(new HarnessEvent('mouseover'));field.dispatchEvent(new HarnessEvent('mouseover'));
    assert.ok(app.contains(field));assert.ok(app.contains(source));assert.equal(document.activeElement,source);
    app.refs.actors.querySelector('[data-actor="realmA"]').dispatchEvent(new HarnessEvent('mouseover'));
    assert.ok(app.contains(field));assert.ok(app.contains(source),'pointer hover cannot replace a dialog with keyboard focus');
    app.deferCloseActor();app.deferCloseAttribute();clock.advance(1000);
    assert.equal(app.refs['actor-popup'].hidden,false);assert.equal(app.refs['attribute-popup'].hidden,false);
    key(source,'Escape');assert.equal(document.activeElement,field);key(field,'Escape');assert.equal(document.activeElement,card);
  }finally{unmount(app);}
});

test('an attribute explanation outside the participant panel does not cancel that panel dismissal',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    const panelField=app.refs['actor-popup'].querySelector('[data-attribute]');focus(panelField);
    const indexField=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');focus(indexField);key(indexField,'F2');
    clock.advance(1000);assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(app.refs['attribute-popup'].hidden,false);
    assert.ok(app.refs['attribute-popup'].contains(document.activeElement));key(document.activeElement,'Escape');assert.equal(document.activeElement,indexField);
  }finally{unmount(app);}
});

test('leaving a participant attribute for the participant close button dismisses only its child explanation',()=>{
  const app=mount();try{
    const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
    focus(app.refs['actor-popup'].querySelector('[data-attribute]'));assert.equal(app.refs['attribute-popup'].hidden,false);
    focus(app.refs['actor-popup'].querySelector('[data-close]'));clock.advance(1000);
    assert.equal(app.refs['actor-popup'].hidden,false);assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('attribute and topic selection preserve focus after index regeneration',()=>{
  const app=mount();try{
    const before=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');focus(before);before.click();
    const after=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');
    assert.notEqual(after,before);assert.equal(document.activeElement,after);assert.ok(app.contains(after));assert.equal(after.getAttribute('aria-pressed'),'true');
    const topic=app.refs['attribute-topics'].querySelector('[data-trace-topic="pkce"]');focus(topic);topic.click();
    const replacement=app.refs['attribute-topics'].querySelector('[data-trace-topic="pkce"]');
    assert.notEqual(replacement,topic);assert.equal(document.activeElement,replacement);assert.equal(replacement.getAttribute('aria-pressed'),'true');
  }finally{unmount(app);}
});

test('scenario combobox preserves modified platform editing keys while ordinary navigation still selects',()=>{
  const app=mount();try{
    const picker=app.scenarioPicker,input=picker.input;focus(input);input.value='password';input.dispatchEvent(new HarnessEvent('input'));
    const initial=picker.activeIndex,current=app.labScenarioId;
    for(const modifier of ['shiftKey','ctrlKey','metaKey','altKey'])for(const value of ['Home','End','ArrowLeft','ArrowRight','ArrowUp','ArrowDown']){
      assert.equal(key(input,value,{[modifier]:true}).defaultPrevented,false,modifier+' + '+value+' stays native');
      assert.equal(picker.activeIndex,initial);assert.equal(app.labScenarioId,current);assert.equal(input.value,'password');
    }
    assert.equal(key(input,'End').defaultPrevented,true);assert.equal(picker.activeIndex,picker.results.length-1);
    assert.equal(key(input,'Home').defaultPrevented,true);assert.equal(picker.activeIndex,0);
    const chosen=picker.results[0].id;key(input,'Enter');assert.equal(app.labScenarioId,chosen);assert.equal(picker.opened,false);
  }finally{unmount(app);}
});

test('opening a late selected scenario scrolls its active option into view',()=>{
  const app=mount();try{
    const picker=app.scenarioPicker,last=picker.options.at(-1);picker.setSelected(last.id);focus(picker.input);
    const row=picker.list.querySelector('[data-scenario-option="'+last.id+'"]');
    assert.equal(picker.input.getAttribute('aria-activedescendant'),row.id);assert.ok(row.scrollCalls.length>0);
    assert.deepEqual(row.scrollCalls.at(-1),{block:'nearest',inline:'nearest'});
  }finally{unmount(app);}
});
