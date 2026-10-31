import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, fixture, unmount, canonical, at, button, document, clock, HarnessEvent } from './compact-fixture.mjs';
import { ATTRIBUTES } from '../src/protocol-data.js';

const indexFields = app => [...app.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]')];
const scopeButton = (app,scope) => app.querySelector('[data-compact-field-scope="'+scope+'"]');
function search(app,query) {
  app.refs['attribute-search'].value=query;
  app.refs['attribute-search'].dispatchEvent(new HarnessEvent('input'));
}
function assertInlineControl(control) {
  assert.equal(control.hasAttribute('aria-haspopup'),false);
  assert.equal(control.hasAttribute('aria-keyshortcuts'),false);
  assert.equal(control.getAttribute('aria-controls'),'compact-field-definition');
}
function assertDefinition(app,id) {
  const target=app.refs['compact-field-definition'],definition=app.definition(id);
  assert.equal(target.hidden,false);
  assert.equal(target.getAttribute('role'),'region');
  assert.equal(target.getAttribute('tabindex'),'-1');
  assert.equal(document.activeElement,target,'keyboard reading starts at the explanation, not its trailing action');
  assert.ok(app.contains(target));
  assert.ok(target.textContent.includes(definition.name));
  assert.ok(target.textContent.includes(definition.meaning||definition.description));
  assert.ok(target.textContent.includes(definition.purpose));
  const example=definition.example===undefined?'':definition.example!==null&&typeof definition.example!=='object'?String(definition.example):JSON.stringify(definition.example,null,2);
  assert.equal(target.querySelector('dd code').textContent,example);
  assert.ok(target.querySelector('[data-compact-field-trace]'));
}

for(const lesson of ['basic-keycloak','core','lab-mcp09'])test('Compact '+lesson+' begins with current fields and bounds explicit global batches without dropping metadata',()=>{
  const app=mount();try {
    app.selectLabScenario(lesson);const before=canonical(app);app.openFieldIndex();
    const current=indexFields(app);
    assert.ok(current.length>0);assert.ok(current.length<=40,'the declared initial batch never mounts the whole global index');
    assert.equal(scopeButton(app,'current').getAttribute('aria-pressed'),'true');
    assert.ok(current.every(field=>!field.classList.contains('is-unavailable')||app.steps.some(step=>step.fields?.includes(field.dataset.indexAttribute))||app.labModel?.ids.includes(field.dataset.indexAttribute)));
    scopeButton(app,'global').click();
    const total=Object.keys(ATTRIBUTES).length,first=indexFields(app),firstIds=first.map(field=>field.dataset.indexAttribute);
    assert.ok(total>80);assert.equal(first.length,40);assert.equal(scopeButton(app,'global').getAttribute('aria-pressed'),'true');
    assert.ok(app.refs['attribute-index-meta'].textContent.includes('of '+total+' global fields'));
    assert.equal(app.refs['compact-field-more'].hidden,false);app.refs['compact-field-more'].click();
    const expanded=indexFields(app);
    assert.equal(expanded.length,80);assert.deepEqual(expanded.slice(0,40).map(field=>field.dataset.indexAttribute),firstIds);
    assert.equal(document.activeElement,expanded[40],'Show more starts keyboard exploration at the newly revealed batch');
    assert.ok(app.contains(document.activeElement));
    search(app,'PKCE');assert.ok(indexFields(app).length<=40);
    scopeButton(app,'current').click();assert.equal(app.attributeQuery,'');assert.ok(indexFields(app).length<=40);
    assert.equal(scopeButton(app,'current').getAttribute('aria-pressed'),'true');
    assert.deepEqual(canonical(app),before,'field browsing never evaluates or selects a protocol action');
  }finally{unmount(app);}
});

test('global search can find and explain a real out-of-lesson field without selecting or changing the journey',()=>{
  const app=mount();try {
    app.openFieldIndex();const currentIds=new Set(indexFields(app).map(field=>field.dataset.indexAttribute));
    const names=new Map();for(const definition of Object.values(ATTRIBUTES))names.set(definition.name,(names.get(definition.name)||0)+1);
    const [id]=Object.entries(ATTRIBUTES).find(([id,definition])=>!currentIds.has(id)&&definition.name.length>24&&names.get(definition.name)===1);
    const definition=app.definition(id),before=canonical(app),scenario=app.labScenarioId;
    search(app,definition.name);
    while(!indexFields(app).some(field=>field.dataset.indexAttribute===id)&&!app.refs['compact-field-more'].hidden)app.refs['compact-field-more'].click();
    const field=indexFields(app).find(field=>field.dataset.indexAttribute===id);
    assert.ok(field,'global lookup retains every matching definition beyond the initial current-lesson batch');
    assertInlineControl(field);field.focus();field.click();assertDefinition(app,id);
    assert.equal(app.attributeSelection,null);assert.equal(app.labScenarioId,scenario);assert.deepEqual(canonical(app),before);
  }finally{unmount(app);}
});

for(const surface of ['index','action'])test(surface+' field controls use inline semantics in Compact and retain Full F2/open/return',()=>{
  const app=mount();try {
    let controls;
    if(surface==='index'){app.openFieldIndex();controls=indexFields(app);}
    else {
      const index=app.steps.findIndex(step=>step.fields?.some(id=>ATTRIBUTES[id]));
      assert.ok(index>=0);app.inspectSourceCursor({eventIndex:index,milestone:'complete'});
      controls=[...app.refs['compact-data'].querySelectorAll('[data-attribute]')];
    }
    assert.ok(controls.length>0);for(const control of controls)assertInlineControl(control);
    const control=controls[0],id=control.dataset.indexAttribute||control.dataset.attribute,before=canonical(app);
    control.focus();const unsupported=new HarnessEvent('keydown',{key:'F2'});control.dispatchEvent(unsupported);
    assert.equal(app.refs['attribute-popup'].hidden,true);
    control.click();assertDefinition(app,id);assert.deepEqual(canonical(app),before);
    app.switchPresentation('full');
    if(surface==='index')app.openFieldIndex();
    const full=surface==='index'?[...app.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]')].find(node=>node.dataset.indexAttribute===id):[...app.refs.inspector.querySelectorAll('[data-attribute]')].find(node=>node.dataset.attribute===id);
    assert.ok(full);assert.equal(full.getAttribute('aria-haspopup'),'dialog');assert.equal(full.getAttribute('aria-keyshortcuts'),'F2');
    full.focus();const f2=new HarnessEvent('keydown',{key:'F2'});full.dispatchEvent(f2);
    assert.equal(app.refs['attribute-popup'].hidden,false);
    assert.ok(app.refs['attribute-popup'].contains(document.activeElement));
    const escape=new HarnessEvent('keydown',{key:'Escape'});document.activeElement.dispatchEvent(escape);
    assert.equal(app.refs['attribute-popup'].hidden,true);
    assert.ok(app.contains(document.activeElement));
    assert.equal(document.activeElement.dataset.attribute||document.activeElement.dataset.indexAttribute,id);
    app.switchPresentation('compact');
    for(const compact of app.querySelectorAll('[data-attribute],[data-index-attribute]'))assertInlineControl(compact);
  }finally{unmount(app);}
});

for(const id of ['clientIdApp','refreshToken'])test('explicit Follow and Return reveal a paused scope and its originating definition from a partial cursor: '+id,()=>{
  const {app}=fixture();try {
    at(app,0,'received');const original=canonical(app);app.compactView.showField(id);assertDefinition(app,id);
    app.querySelector('[data-compact-field-trace]').click();
    assert.equal(app.attributeSelection,id);assert.notEqual(app.player.status,'playing');assert.equal(clock.frames.size,0);
    assert.equal(document.activeElement,app.refs['compact-current-title']);
    assert.ok(app.querySelector('.compact-current').scrollCalls.length>0);
    assert.equal(button(app,'return').hidden,false);
    const scoped=canonical(app),queue=app.player.queue;
    if(id==='refreshToken'){assert.equal(queue.length,0);assert.deepEqual(scoped,original);assert.equal(button(app,'play').disabled,true);}
    else assert.ok(queue.length>0);
    button(app,'field-definition').click();assertDefinition(app,id);
    assert.equal(app.player.queue,queue);assert.deepEqual(canonical(app),scoped);
    button(app,'return').click();assert.equal(app.attributeSelection,null);assert.equal(app.player.kind,'demo');
    assert.deepEqual(canonical(app),scoped);assert.equal(document.activeElement,app.refs['compact-current-title']);
  }finally{unmount(app);}
});

test('automatic field-history playback does not repeatedly scroll or steal focus after explicit Follow',()=>{
  const {app}=fixture();try {
    app.compactView.showField('clientIdApp');app.querySelector('[data-compact-field-trace]').click();
    const card=app.querySelector('.compact-current'),scrolls=card.scrollCalls.length;
    button(app,'play').focus();button(app,'play').click();clock.frame();clock.frame(30);
    assert.equal(app.player.status,'playing');assert.equal(document.activeElement,button(app,'play'));
    assert.equal(card.scrollCalls.length,scrolls);
    app.player.pause();assert.equal(document.activeElement,button(app,'play'));
  }finally{unmount(app);}
});

test('explicitly returning to the field explanation pauses an in-progress investigation without replacing its queue',()=>{
  const {app}=fixture();try {
    app.compactView.showField('clientIdApp');app.querySelector('[data-compact-field-trace]').click();
    button(app,'play').focus();button(app,'play').click();clock.frame();clock.frame(30);
    assert.equal(app.player.status,'playing');
    const queue=app.player.queue,elapsed=app.player.elapsed;
    button(app,'field-definition').click();
    assert.equal(app.player.status,'paused');assert.equal(clock.frames.size,0);
    assert.equal(app.player.queue,queue);assert.equal(app.player.elapsed,elapsed);
    assertDefinition(app,'clientIdApp');
  }finally{unmount(app);}
});
