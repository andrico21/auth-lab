import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {isVisibleFocusTarget} from '../src/focus-target.js';

// Mounted behavior only: the harness does not synthesize native keyboard
// activation, CSS layout or native Tab order. The native runner covers those.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {document,clock}=harness;
function mount(){
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});
  app.querySelector('#ready-journeys').open=true;app.querySelector('#lesson-reference').open=true;
  for(const id of ['workspace-presets','related-journeys'])modelFocusRemoval(app.querySelector('#'+id));
  return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
function modelFocusRemoval(container){
  const property=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(container),'innerHTML');
  Object.defineProperty(container,'innerHTML',{
    configurable:true,get(){return property.get.call(this);},
    set(html){const focused=this.contains(document.activeElement)?document.activeElement:null;property.set.call(this,html);if(focused&&!document.contains(focused))document.activeElement=document.body;}
  });
}
function focus(node){
  assert.ok(node,'navigation control exists');const previous=document.activeElement;document.activeElement=node;
  previous?.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:node}));node.dispatchEvent(new HarnessEvent('focusin',{relatedTarget:previous}));
}
function cryptoPanel(app,id){
  app.selectLabScenario(id,{navigate:false});app.querySelector('[data-learning-detail="crypto"]').click();
  const panel=app.querySelector('#learning-profile-crypto');assert.equal(isVisibleFocusTarget(app,panel),true);return panel;
}
function meaningfulJourneyFocus(app){
  const active=document.activeElement;
  assert.equal(document.contains(active),true,'focus is connected to the mounted document');
  assert.equal(isVisibleFocusTarget(app,active),true,'focus is visible and usable');
  if(active!==app.refs.play){
    assert.equal(active.dataset.labScenario,app.labScenarioId,'focus names the selected journey');
    assert.equal(active.getAttribute('aria-pressed'),'true');assert.ok(active.textContent.trim());
  }else assert.match(active.getAttribute('aria-label')||active.textContent,/play/i);
}

test('Windows crypto profiles expose structured fixture and mechanism parameters, including CredSSP binding inputs',()=>{
  const app=mount();try{
    for(const id of ['lab-win-ntlmv2-domain','lab-win-negotiate-kerberos','lab-win-credssp-v6-ntlm','lab-win-credssp-v6-kerberos']){
      const panel=cryptoPanel(app,id),detail=app.labModel.profile.cryptoDetail;
      assert.ok(panel.textContent.includes(detail.mechanism),id+' mechanism explanation is readable');
      for(const fixture of detail.fixtures)assert.ok(panel.textContent.includes(fixture),id+' fixture identity is readable');
      assert.ok(!panel.textContent.includes('[object Object]'));
      if(id.includes('credssp')){
        for(const key of ['clientMagic','serverMagic','nonceHex','nonceBytes','publicKeyEncoding','subjectPublicKeyFixture','fixture']){
          assert.ok(Object.hasOwn(detail.binding,key),key+' is an authored binding parameter');
          assert.ok(panel.textContent.includes(JSON.stringify(detail.binding[key])),key+' remains visible with literal NUL escaped');
        }
      }
    }
  }finally{unmount(app);}
});


test('structured crypto parameters are escaped as text rather than interpreted as markup',()=>{
  const app=mount();let profile,original;try{
    app.selectLabScenario('lab-win-credssp-v6-ntlm',{navigate:false});profile=app.labModel.profile;original=profile.cryptoDetail;
    const hostile='<img src=x onerror=bad()> & <script>bad()</script>';
    profile.cryptoDetail={...original,reviewEscaping:hostile};app.querySelector('[data-learning-detail="crypto"]').click();
    const panel=app.querySelector('#learning-profile-crypto');
    assert.ok(panel.textContent.includes(hostile),'hostile parameter remains literal readable text');
    assert.equal(panel.querySelector('img'),null);assert.equal(panel.querySelector('script'),null);
  }finally{if(profile)profile.cryptoDetail=original;unmount(app);}
});

test('reactivating the current ready-made journey retains meaningful live focus',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-win-ntlmv2-domain',{navigate:false});
    for(let repeat=0;repeat<2;repeat++){
      const button=app.querySelector('#workspace-presets [data-lab-scenario="lab-win-ntlmv2-domain"]');focus(button);button.click();
      assert.equal(app.labScenarioId,'lab-win-ntlmv2-domain');meaningfulJourneyFocus(app);
    }
  }finally{unmount(app);}
});

test('changing the related journey restores focus to a selected starter or persistent Play',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-win-ntlmv2-domain',{navigate:false});
    const button=app.querySelector('#related-journeys [data-compare-scenario="lab-win-negotiate-kerberos"]');focus(button);button.click();
    assert.equal(app.labScenarioId,'lab-win-negotiate-kerberos');meaningfulJourneyFocus(app);
  }finally{unmount(app);}
});

test('related navigation retains a real destination when the activated comparison no longer exists',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-net-radius-udp-radsec',{navigate:false});
    const button=app.querySelector('#related-journeys [data-compare-scenario="lab-net-radius11"]');focus(button);button.click();
    assert.equal(app.labScenarioId,'lab-net-radius11');
    assert.equal(app.querySelector('#related-journeys [data-compare-scenario="lab-net-radius11"]'),null,'the new comparison list excludes itself');
    meaningfulJourneyFocus(app);
  }finally{unmount(app);}
});

test('journey activation does not steal focus from an unrelated surviving control',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-win-ntlmv2-domain',{navigate:false});const search=app.querySelector('#lab-scenario-search');focus(search);
    app.querySelector('#related-journeys [data-compare-scenario="lab-win-negotiate-kerberos"]').click();
    assert.equal(app.labScenarioId,'lab-win-negotiate-kerberos');assert.equal(document.activeElement,search);assert.equal(isVisibleFocusTarget(app,search),true);
    app.querySelector('#workspace-presets [data-lab-scenario="lab-win-ntlmv2-domain"]').click();
    assert.equal(app.labScenarioId,'lab-win-ntlmv2-domain');assert.equal(document.activeElement,search);
  }finally{unmount(app);}
});
