import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {studioRoute}=await import('../src/workspaces.js');
const {LAB_MODELS}=await import('../src/lab-catalog.js');
const {document,window,clock}=harness;
const originalBrowser={location:window.location,history:window.history};
function mount(){window.location={hash:''};window.history={pushState(_state,_title,hash){window.location.hash=hash;},replaceState(_state,_title,hash){window.location.hash=hash;}};const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;}
function dispose(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();window.location=originalBrowser.location;window.history=originalBrowser.history;}
function end(app){app.selectStep(app.steps.length-1,false);return app.protocolSnapshot().state.workstation;}
function select(app,id,value){const control=app.querySelector('#'+id);control.value=value;control.dispatchEvent(new HarnessEvent('change'));}

test('switching a local/domain comparison replaces canonical steps, state, held context and inspection',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-wra01');
    const local=end(app),localContext=app.heldView.contextId;
    assert.equal(local.verifierAuthority,'TARGET SAM');assert.equal(local.token.mode,'filtered');assert.equal(local.resourceAllowed,false);
    const token=app.heldView.snapshot().holdings.find(holding=>holding.artifactId.endsWith(':target-token'));
    assert.ok(token);app.heldView.select(token);
    select(app,'lesson-subfixture','domain');
    assert.equal(app.lessonVariant,'default-filtered');assert.equal(app.labModel.subfixtureId,'domain');
    assert.notEqual(app.heldView.contextId,localContext);assert.equal(app.heldView.selection,null);
    assert.equal(app.steps.some(step=>step.smbStage==='sam-verify'),false);assert.ok(app.steps.some(step=>step.smbStage==='as-request'));
    const domain=end(app);assert.equal(domain.verifierAuthority,'CORP KDC');assert.equal(domain.token.mode,'full');assert.equal(domain.resourceAllowed,true);
    select(app,'lesson-subfixture','local');
    const again=end(app);assert.equal(again.verifierAuthority,'TARGET SAM');assert.equal(again.token.mode,'filtered');assert.equal(again.resourceAllowed,false);
    assert.equal(app.steps.some(step=>step.smbStage==='dc-request'),false);
  }finally{dispose(app);}
});

test('unknown and duplicate case links choose only the valid base scenario default',()=>{
  const app=mount();try{
    const base=studioRoute('lab-wra01',LAB_MODELS);
    for(const query of ['?case=unknown','?case=bad-password&case=bad-password']){
      app.selectLabScenario('lab-wra01',{variant:'bad-password'});assert.equal(end(app).credentialVerified,false);
      window.location.hash=base+query;app.openRoute();
      assert.equal(app.labScenarioId,'lab-wra01');assert.equal(app.lessonVariant,'default-filtered');assert.equal(window.location.hash,base);
      const safe=end(app);assert.equal(safe.credentialVerified,true);assert.equal(safe.token.mode,'filtered');assert.equal(safe.resourceAllowed,false);
    }
    const snapshot=app.scenarioSnapshot();assert.throws(()=>app.selectLabScenario('lab-wra01',{variant:'not-a-case'}),RangeError);assert.equal(app.scenarioSnapshot(),snapshot);
  }finally{dispose(app);}
});

test('ambiguous variant search pauses without replacing the demo until an actual denial case is chosen',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-wra01');const original=app.scenarioSnapshot(),context=app.heldView.contextId;
    const input=app.querySelector('#lab-scenario-search');input.value='substack';input.dispatchEvent(new HarnessEvent('input'));
    assert.equal(app.labScenarioId,'lab-wra01');assert.equal(app.scenarioSnapshot(),original);assert.equal(app.heldView.contextId,context);
    input.dispatchEvent(new HarnessEvent('keydown',{key:'Enter'}));
    assert.equal(app.labScenarioId,'lab-wra01');assert.equal(app.querySelector('#search-case-choice').hidden,false);
    app.querySelector('[data-search-case="substack-failure"]').click();
    assert.equal(app.labScenarioId,'lab-pam01');assert.equal(app.lessonVariant,'substack-failure');assert.equal(app.querySelector('#search-case-choice').hidden,true);
    const state=end(app);assert.equal(state.authenticated,false);assert.equal(state.admitted,false);assert.equal(state.session,false);
  }finally{dispose(app);}
});

test('PAM row selection follows physical configuration and retains a deferred failure before caller admission',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-pam01',{variant:'required-deferred-failure'});
    const index=app.steps.findIndex(step=>step.pamEvaluation?.executed===true),metadata=app.steps[index].pamEvaluation;
    app.selectStep(index,false);
    const active=app.querySelector('#pam-configuration-panel [aria-current="step"]');
    assert.equal(Number(active.dataset.pamLine),metadata.line);assert.equal(active.querySelector('code').textContent,metadata.text);
    const state=app.protocolSnapshot().state.workstation;
    assert.equal(state.pamEvaluation.accumulatorAfter.impression,'negative');assert.equal(state.pamEvaluation.accumulatorAfter.status,'PAM_AUTH_ERR');assert.equal(state.authenticated,false);assert.equal(state.admitted,false);
    const final=end(app);assert.equal(final.pamResults.authenticate,'PAM_AUTH_ERR');assert.equal(final.authenticated,false);assert.equal(final.session,false);
  }finally{dispose(app);}
});

test('ordinary-share comparison changes authorization without disabling target restrictions',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-wra01');const denied=end(app);
    assert.equal(denied.credentialVerified,true);assert.equal(denied.token.mode,'filtered');assert.equal(denied.resourceAllowed,false);
    app.querySelector('#lesson-inputs [data-compare-variant="ordinary-share-allowed"]').click();
    assert.equal(app.lessonVariant,'ordinary-share-allowed');assert.equal(app.protocolSnapshot().state.workstation.credentialVerified,false);
    const allowed=end(app);assert.equal(allowed.verifierAuthority,denied.verifierAuthority);assert.equal(allowed.token.mode,'filtered');assert.equal(allowed.resourceAllowed,true);
  }finally{dispose(app);}
});

test('the in-step PAM explanation starts its independent Linux fixture instead of transferring cached sign-in state',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-llog03');end(app);const previous=app.heldView.contextId;
    const index=app.steps.findIndex(step=>step.pamEvaluation?.hookCalled===true);assert.ok(index>=0);app.selectStep(index,false);
    app.querySelector('#pam-configuration-panel [data-compare-scenario="lab-pam01"]').click();
    assert.equal(app.labScenarioId,'lab-pam01');assert.equal(app.lessonVariant,'local-login-success');assert.notEqual(app.heldView.contextId,previous);
    const state=app.protocolSnapshot().state.workstation;assert.equal(state.authenticated,false);assert.equal(state.admitted,false);assert.equal(state.session,false);
  }finally{dispose(app);}
});

test('macOS has no invented Linux configuration and its comparison opens a fresh Linux model',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-mlog01');assert.equal(app.querySelector('#pam-configuration-panel').hidden,true);assert.equal(app.labModel.pamConfiguration,undefined);
    app.querySelector('#related-journeys [data-compare-scenario="lab-pam01"]').click();
    assert.equal(app.labScenarioId,'lab-pam01');assert.equal(app.querySelector('#pam-configuration-panel').hidden,false);assert.equal(app.labModel.family,'linux-logon');
    assert.equal(app.protocolSnapshot().state.workstation.authenticated,false);
  }finally{dispose(app);}
});
