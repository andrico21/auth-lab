import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {isVisibleFocusTarget} from '../src/focus-target.js';

// These tests dispatch the actual window resize listener and supply explicit
// focus transitions. They verify application decisions, not native layout,
// browser Tab order, live-region announcements, or screen-reader behavior.
const {document,window,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mount(){
  window.innerWidth=1440;window.innerHeight=1000;
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
function focus(node){
  assert.ok(node,'focus fixture exists');const previous=document.activeElement;document.activeElement=node;
  previous?.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:node}));node.dispatchEvent(new HarnessEvent('focusin',{relatedTarget:previous}));
}
function key(node,value){node.dispatchEvent(new HarnessEvent('keydown',{key:value}));}
function resized(){window.innerWidth=720;window.innerHeight=640;window.dispatchEvent(new HarnessEvent('resize',{bubbles:false}));}
function sameFocus(node){assert.ok(document.activeElement===node,'focus remains on the expected usable control');assert.equal(isVisibleFocusTarget(node.closest('auth-flow-studio')||document,node),true);}
function indexHelp(app,id='codeVerifier'){
  const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute="'+id+'"]');focus(field);key(field,'F2');
  const source=document.activeElement;assert.ok(app.refs['attribute-popup'].contains(source));return {field,source};
}
function nestedHelp(app){
  const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);key(card,'F2');
  const field=app.refs['actor-popup'].querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
  return {card,field,source:document.activeElement};
}
function placementLog(app){
  const placed=[],original=app.placePopup;
  app.placePopup=function(popup,anchor,width){placed.push({popup,anchor,width});return original.call(this,popup,anchor,width);};
  return placed;
}

test('R10: resizing repositions an index explanation and preserves keyboard focus and playing state',()=>{
  const app=mount();try{
    app.refs.play.click();clock.advance(100);
    const {field,source}=indexHelp(app),queue=app.player.queue,elapsed=app.player.elapsed,placed=placementLog(app);
    resized();
    assert.equal(app.refs['attribute-popup'].hidden,false);sameFocus(source);
    assert.ok(placed.some(item=>item.popup===app.refs['attribute-popup']&&item.anchor===field));
    assert.equal(app.player.status,'playing');assert.ok(app.player.queue===queue);assert.equal(app.player.elapsed,elapsed);
    clock.advance(1000);assert.equal(app.refs['attribute-popup'].hidden,false);sameFocus(source);
  }finally{unmount(app);}
});

test('keyboard focus on a help trigger also survives resize without entering its popup',()=>{
  const app=mount();try{
    const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');focus(field);resized();
    assert.equal(app.refs['attribute-popup'].hidden,false);sameFocus(field);
    app.hidePopups();const card=app.refs.actors.querySelector('[data-actor="app"]');focus(card);resized();
    assert.equal(app.refs['actor-popup'].hidden,false);sameFocus(card);
  }finally{unmount(app);}
});

test('nested participant and attribute dialogs reposition together and retain their Escape return chain',()=>{
  const app=mount();try{
    const {card,field,source}=nestedHelp(app),placed=placementLog(app);resized();
    assert.equal(app.refs['actor-popup'].hidden,false);assert.equal(app.refs['attribute-popup'].hidden,false);sameFocus(source);
    assert.ok(placed.some(item=>item.popup===app.refs['actor-popup']&&item.anchor===card));
    assert.ok(placed.some(item=>item.popup===app.refs['attribute-popup']&&item.anchor===field));
    key(source,'Escape');sameFocus(field);assert.equal(app.refs['attribute-popup'].hidden,true);assert.equal(app.refs['actor-popup'].hidden,false);
    key(field,'Escape');sameFocus(card);assert.equal(app.refs['actor-popup'].hidden,true);
  }finally{unmount(app);}
});

test('resize closes hover-only participant and attribute help without moving outside focus',()=>{
  const app=mount();try{
    focus(app.refs.speed);
    app.refs.actors.querySelector('[data-actor="app"]').dispatchEvent(new HarnessEvent('mouseover'));
    app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]').dispatchEvent(new HarnessEvent('mouseover'));
    assert.equal(app.refs['actor-popup'].hidden,false);assert.equal(app.refs['attribute-popup'].hidden,false);
    resized();assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(app.refs.speed);
  }finally{unmount(app);}
});

test('an unrelated hover participant panel closes while keyboard-owned index help stays open',()=>{
  const app=mount();try{
    focus(app.refs.speed);app.refs.actors.querySelector('[data-actor="app"]').dispatchEvent(new HarnessEvent('mouseover'));
    const {source}=indexHelp(app);resized();
    assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(app.refs['attribute-popup'].hidden,false);sameFocus(source);
  }finally{unmount(app);}
});

test('a rebuilt index anchor closes its explanation and returns focus to the replacement field',()=>{
  const app=mount();try{
    const {field}=indexHelp(app);app.renderAttributeIndex();assert.equal(app.contains(field),false);
    const replacement=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(replacement);
    clock.advance(1000);assert.equal(app.refs['attribute-popup'].hidden,true);
  }finally{unmount(app);}
});

test('a hidden index anchor closes its explanation and returns focus to Play',()=>{
  const app=mount();try{
    indexHelp(app);app.refs['attribute-index'].hidden=true;resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(app.refs.play);
  }finally{unmount(app);}
});

test('a detached inspector anchor after playback advances resolves its current field on resize',()=>{
  const app=mount();try{
    app.refs.play.click();clock.until(()=>app.currentStep.id==='single-web-password-l02');
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
    clock.until(()=>app.currentStep.id==='single-web-password-l03');assert.equal(app.contains(field),false);
    const current=app.refs.inspector.querySelector('[data-attribute="redirectApp"]'),queue=app.player.queue,elapsed=app.player.elapsed;
    resized();assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(current);
    assert.equal(app.player.status,'playing');assert.ok(app.player.queue===queue);assert.equal(app.player.elapsed,elapsed);
  }finally{unmount(app);}
});

test('a detached inspector field absent from the current step returns focus to its visible index entry',()=>{
  const app=mount();try{
    app.refs.play.click();clock.until(()=>app.currentStep.id==='single-web-password-l02');
    const field=app.refs.inspector.querySelector('[data-attribute="redirectApp"]');focus(field);key(field,'F2');
    clock.until(()=>app.currentStep.id==='single-web-password-p01');resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);
    sameFocus(app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]'));assert.equal(app.player.status,'playing');
  }finally{unmount(app);}
});

test('a rebuilt nested attribute anchor returns to the current participant field while keeping its parent open',()=>{
  const app=mount();try{
    const {field}=nestedHelp(app),panel=app.refs['actor-popup'];panel.innerHTML=panel.innerHTML;
    assert.equal(app.contains(field),false);const replacement=panel.querySelector('[data-attribute="redirectApp"]');resized();
    assert.equal(panel.hidden,false);assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(replacement);
  }finally{unmount(app);}
});

test('a hidden nested attribute anchor returns to its index field without hiding keyboard focus',()=>{
  const app=mount();try{
    const {field}=nestedHelp(app);field.hidden=true;resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);
    sameFocus(app.refs['attribute-index-list'].querySelector('[data-index-attribute="redirectApp"]'));
  }finally{unmount(app);}
});

test('a rebuilt participant card closes both nested panels and returns to its current card',()=>{
  const app=mount();try{
    const {card}=nestedHelp(app);app.renderActors();assert.equal(app.contains(card),false);
    const replacement=app.refs.actors.querySelector('[data-actor="app"]');resized();
    assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(replacement);
  }finally{unmount(app);}
});

test('a hidden parent card closes nested help and returns focus to a stable fallback',()=>{
  const app=mount();try{
    const {card}=nestedHelp(app);card.hidden=true;resized();
    assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(app.refs.play);
  }finally{unmount(app);}
});

test('a hidden parent panel cannot leave its nested explanation holding keyboard focus after resize',()=>{
  const app=mount();try{
    const {card}=nestedHelp(app);app.refs['actor-popup'].hidden=true;resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(card);
  }finally{unmount(app);}
});

test('resize after focus leaves a dialog closes it without returning focus to its old trigger',()=>{
  const app=mount();try{
    indexHelp(app);focus(app.refs.seek);resized();
    assert.equal(app.refs['attribute-popup'].hidden,true);sameFocus(app.refs.seek);
  }finally{unmount(app);}
});
