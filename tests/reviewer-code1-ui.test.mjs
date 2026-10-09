import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// These exercise actual application handlers and readable DOM values. Native
// layout, Tab order and CSP enforcement remain the separate browser gate.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});return app;}
function dispose(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
function focus(node){assert.ok(node);const previous=document.activeElement;document.activeElement=node;node.dispatchEvent(new HarnessEvent('focusin',{relatedTarget:previous}));}
function key(node,value){return node.dispatchEvent(new HarnessEvent('keydown',{key:value}));}

test('F18: channel, authentication failure and keyboard prompt values keep their JSON shape in every value view',()=>{
  const app=mount();try{
    let sawChannel=false,sawFailure=false,sawPrompts=false,sawBoolean=false;
    for(const scenario of ['lab-ssh-cert-success','lab-ssh-cert-account','lab-ssh-sssd-success','lab-ssh-sssd-zero']){
      app.selectLabScenario(scenario);
      for(const [stepIndex,step] of app.steps.entries()){
        const structured=step.payload.map((payload,index)=>({payload,index})).filter(({payload})=>payload.value!==null&&typeof payload.value==='object');
        if(!structured.length)continue;
        app.selectStep(stepIndex,false);
        for(const {payload,index} of structured){
          const row=app.refs.inspector.querySelectorAll('.payload-row')[index],value=row.querySelector('.field-value');
          assert.deepEqual(JSON.parse(value.textContent),payload.value,scenario+' / '+step.id);
          assert.ok(!value.textContent.includes('[object Object]'));
          if(payload.attributeId){
            const example=app.attributeHtml(payload.attributeId),holder=document.createElement('section');holder.innerHTML=example;
            const definition=app.definition(payload.attributeId);
            if(definition.example!==null&&typeof definition.example==='object')assert.deepEqual(JSON.parse(holder.querySelector('dd code').textContent),definition.example);
            const anchor=row.querySelector('[data-attribute]');
            if(anchor){assert.equal(app.showAttributePopup(payload.attributeId,anchor),true);assert.ok(!app.refs['attribute-popup'].textContent.includes('[object Object]'));app.hidePopups();}
          }
          app.packetIdentity='';app.renderPacket({step,packet:payload,packetIndex:index,status:'paused',visible:true,progress:.5});
          const chip=app.refs['packet-value'].textContent;
          assert.ok(chip.startsWith(Array.isArray(payload.value)?'[':'{'),step.id);
          assert.ok(!chip.includes('[object Object]'));
          if('channel_type' in payload.value){sawChannel=true;assert.equal(JSON.parse(value.textContent).sender_channel,0);}
          if('methods_that_can_continue' in payload.value){sawFailure=true;assert.equal(JSON.parse(value.textContent).partial_success,false);sawBoolean=true;}
          if('prompts' in payload.value){sawPrompts=true;const parsed=JSON.parse(value.textContent);assert.ok(Array.isArray(parsed.prompts));assert.equal(parsed.prompts.length,parsed.num_prompts);}
        }
      }
    }
    assert.ok(sawChannel&&sawFailure&&sawPrompts&&sawBoolean,'the independent examples include keys, arrays, numbers and false');
  }finally{dispose(app);}
});

test('F18: structured protocol text is escaped after formatting and never becomes markup',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ssh-cert-success');const original=app.steps.at(-1);
    const hostile={name:'<img src=x onerror=attack()>',nested:['</code><script>attack()</script>',false,0,null]};
    const step={...original,payload:[{name:'Structured input',value:hostile}]};
    app.refs.inspector.innerHTML=app.stepHtml(step,0);
    assert.deepEqual(JSON.parse(app.refs.inspector.querySelector('.field-value').textContent),hostile);
    assert.equal(app.refs.inspector.querySelector('script, img'),null);
    app.packetIdentity='';app.renderPacket({step,packet:step.payload[0],packetIndex:0,status:'paused',visible:true,progress:.5});
    assert.equal(app.refs['packet-value'].querySelector('img'),null);
    assert.ok(app.refs['packet-value'].textContent.startsWith('{"name":'));
  }finally{dispose(app);}
});

for(const scenario of ['lab-ssh-cert-success','lab-ad-first-sign-in','lab-ad-pkinit-success','lab-ad-fast-as-success','lab-ad-forest-child-domains','lab-kc-kerberos-fresh-totp','lab-kc-kerberos-fresh-webauthn','lab-ssh-gss-success','lab-ad-forest-three-denied']){
  test('F19: hover, focus, F2, nested help and Escape work for every participant in '+scenario,()=>{
    const app=mount();try{
      // An existing, now-hidden legacy panel must never be the F2 destination.
      const legacy=app.refs.actors.querySelector('[data-actor="app"]');focus(legacy);key(legacy,'F2');assert.equal(app.refs['actor-popup'].hidden,false);
      app.selectLabScenario(scenario);
      for(const expanded of [false,true]){
        if(expanded){const toggle=app.querySelector('#show-internals');toggle.checked=true;toggle.dispatchEvent(new HarnessEvent('change'));}
        const cards=[...app.refs.actors.querySelectorAll('[data-actor]')];assert.ok(cards.length);
        for(const card of cards){
          app.hidePopups();document.activeElement=document.body;
          card.dispatchEvent(new HarnessEvent('mouseover'));
          const popup=app.refs['actor-popup'];assert.equal(popup.hidden,false,card.dataset.actor+' hover');
          assert.equal(popup.querySelector('.popup-title').textContent,app.actor(card.dataset.actor).name);
          app.hidePopups();focus(card);assert.equal(popup.hidden,false,card.dataset.actor+' focus');
          key(card,'F2');assert.ok(popup.contains(document.activeElement),card.dataset.actor+' F2 enters the opened panel');
          const field=popup.querySelector('[data-attribute]');
          if(field){
            focus(field);key(field,'F2');const source=document.activeElement;
            assert.ok(app.refs['attribute-popup'].contains(source));assert.ok(source.matches('.source-link'));
            key(source,'Escape');assert.equal(app.refs['attribute-popup'].hidden,true);assert.equal(document.activeElement,field);
          }
          key(document.activeElement,'Escape');assert.equal(popup.hidden,true);assert.equal(document.activeElement,card);
        }
      }
    }finally{dispose(app);}
  });
}

test('F19: unavailable actor or field help does not throw or focus stale hidden content',()=>{
  const app=mount();try{
    const legacy=app.refs.actors.querySelector('[data-actor="app"]');focus(legacy);key(legacy,'F2');app.hidePopups();
    const invalid=document.createElement('button');invalid.setAttribute('data-actor','unknown-actor');app.refs.actors.appendChild(invalid);focus(invalid);
    assert.doesNotThrow(()=>key(invalid,'F2'));assert.equal(app.refs['actor-popup'].hidden,true);assert.equal(document.activeElement,invalid);
    invalid.removeAttribute('data-actor');invalid.setAttribute('data-attribute','unknown-field');
    assert.doesNotThrow(()=>key(invalid,'F2'));assert.equal(app.refs['attribute-popup'].hidden,true);assert.equal(document.activeElement,invalid);
    assert.equal(app.showActorPopup('app',null),false);assert.equal(app.showAttributePopup('clientIdApp',null),false);
  }finally{dispose(app);}
});

test('F19/G01: collapsing a keyboard-owned internal component returns focus to its parent without changing protocol state',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ad-first-sign-in');app.selectStep(4,false);
    const toggle=app.querySelector('#show-internals');toggle.checked=true;toggle.dispatchEvent(new HarnessEvent('change'));
    const child=app.refs.actors.querySelector('[data-actor="adAs"]');focus(child);key(child,'F2');
    const before=app.protocolSnapshot().state;
    toggle.checked=false;toggle.dispatchEvent(new HarnessEvent('change'));
    assert.equal(app.refs['actor-popup'].hidden,true);
    assert.equal(document.activeElement,app.refs.actors.querySelector('[data-actor="adKdc"]'));
    assert.deepEqual(app.protocolSnapshot().state,before);
    // Direct card focus, without an open panel, follows the same collapse rule.
    toggle.checked=true;toggle.dispatchEvent(new HarnessEvent('change'));focus(app.refs.actors.querySelector('[data-actor="adTgs"]'));
    toggle.checked=false;toggle.dispatchEvent(new HarnessEvent('change'));
    assert.equal(document.activeElement,app.refs.actors.querySelector('[data-actor="adKdc"]'));
  }finally{dispose(app);}
});
