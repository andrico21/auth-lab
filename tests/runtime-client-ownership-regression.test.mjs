import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {LAB_MODELS} from '../src/lab-catalog.js';
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const mount=()=>{const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;};
const dispose=app=>{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();};
const card=(app,id)=>app.refs.actors.querySelector('[data-actor="'+id+'"]');
const enter=(app,key,value)=>{const field=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(field,key+' is applicable');field.value=value;field.dispatchEvent(new HarnessEvent('input'));};
const apply=app=>app.querySelector('#environment-apply').click();
const display=app=>JSON.stringify([app.steps,app.actorContextRows(app.environmentOptions.clientActor),app.definition('branchRedirectUri')]);

test('browser execution and client ownership are explicit independently of graph layout',()=>{
  for(const id of ['lab-implicit','lab-hybrid']){assert.equal(LAB_MODELS[id].architecture,'native');assert.equal(LAB_MODELS[id].executionEnvironment,'browser');assert.equal(LAB_MODELS[id].clientActor,'app');}
  assert.equal(LAB_MODELS['lab-spa-api'].clientActor,'browser');assert.equal(LAB_MODELS['lab-spa-api'].executionEnvironment,'browser');
  assert.equal(LAB_MODELS['lab-bff-api'].clientActor,'app');assert.equal(LAB_MODELS['lab-bff-api'].executionEnvironment,'server');
});

test('desktop HTTP context is ignored in Implicit/Hybrid without resetting, and restored exactly for the native client',()=>{
  const app=mount();try{
    for(const scheme of ['http','HTTP','HtTp']){
      app.resetEnvironment();app.selectLabScenario('desktop-sign-in');
      const appURL=scheme+'://127.0.0.1:58749/app',callback=scheme+'://127.0.0.1:58749/return';
      enter(app,'appURL',appURL);enter(app,'appCallbackURL',callback);apply(app);
      assert.equal(app.refs['environment-errors'].hidden,true);
      assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,callback);
      const revision=app.runtimeEnvironment.revision;
      for(const id of ['lab-implicit','lab-hybrid']){
        app.selectLabScenario(id);assert.equal(app.architecture,'native');assert.equal(app.environmentOptions.executionEnvironment,'browser');
        assert.equal(app.definition('branchRedirectUri').example,'https://learning.example.test/callback');
        assert.equal(display(app).includes('127.0.0.1:58749'),false,id+' ignores native-only addresses in models/definitions/context');
        assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://learning.example.test');
        apply(app);assert.equal(app.refs['environment-errors'].hidden,false,id+' rejects still-entered HTTP fields');
        assert.equal(app.runtimeEnvironment.revision,revision,'failed Apply preserves applied state');
        assert.equal(app.runtimeEnvironment.applied.appCallbackURL,callback);
      }
      app.selectLabScenario('desktop-sign-in');assert.equal(app.environmentOptions.executionEnvironment,'native');
      assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,callback);
      assert.ok(JSON.stringify(app.steps).includes(callback));
      app.selectLabScenario('device-sign-in');assert.equal(app.environmentOptions.executionEnvironment,'native');assert.equal(app.actorContextRows('app').find(row=>row.key==='appURL').value,appURL,'native device context remains applicable');
    }
  }finally{dispose(app);}
});

test('browser lessons Apply exact HTTPS callbacks, and Reset clears the actor and protocol context',()=>{
  const app=mount();try{
    for(const id of ['lab-implicit','lab-hybrid']){
      app.resetEnvironment();app.selectLabScenario(id);
      enter(app,'appURL','HTTPS://Portal.Example/area');enter(app,'appCallbackURL','HtTpS://Callback.Example/exact?tenant=One');enter(app,'clientID','review-browser-client');
      assert.equal(app.actorContextRows('app').find(row=>row.key==='clientID').value,'learning-client','pending draft is not displayed');
      apply(app);assert.equal(app.refs['environment-errors'].hidden,true);
      assert.equal(app.definition('branchRedirectUri').example,'HtTpS://Callback.Example/exact?tenant=One');
      assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'HTTPS://Portal.Example/area');
      assert.equal(app.actorContextRows('app').find(row=>row.key==='clientID').value,'review-browser-client');
      app.inspectActor('app');assert.ok(app.refs.inspector.querySelector('.participant-context').textContent.includes('HtTpS://Callback.Example/exact?tenant=One'));
      app.resetEnvironment();assert.equal(display(app).includes('Callback.Example'),false);assert.equal(app.innerHTML.includes('review-browser-client'),false);assert.equal(app.definition('branchRedirectUri').example,'https://learning.example.test/callback');
    }
  }finally{dispose(app);}
});

test('SPA applied context appears on its browser client card, popup and inspector, with separate API/IdP ownership',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-spa-api');assert.equal(card(app,'app'),null,'no separate app participant is used by this SPA');
    assert.equal(card(app,'browser').querySelector('.actor-context-address').textContent,'https://spa.example.test');
    enter(app,'appURL','https://review-spa.example/area');enter(app,'clientID','review-spa-client');enter(app,'appCallbackURL','HTTPS://Review-SPA.Example/exact');enter(app,'keycloakABaseURL','https://sso.example/auth');enter(app,'realmA','Office');
    assert.equal(card(app,'browser').querySelector('.actor-context-address').textContent,'https://spa.example.test');
    apply(app);assert.equal(app.refs['environment-errors'].hidden,true);
    assert.equal(card(app,'browser').querySelector('.actor-context-address').textContent,'https://review-spa.example/area');
    assert.equal(card(app,'browser').getAttribute('aria-describedby'),'actor-context-browser');
    assert.deepEqual(app.actorContextRows('browser').map(row=>[row.key,row.value]),[['appURL','https://review-spa.example/area'],['appCallbackURL','HTTPS://Review-SPA.Example/exact'],['clientID','review-spa-client']]);
    assert.deepEqual(app.actorContextRows('app'),[]);assert.deepEqual(app.actorContextRows('realmB'),[]);assert.equal(card(app,'realmB').querySelector('.actor-context'),null);
    assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://sso.example/auth');
    assert.equal(app.definition('webRedirectUri').example,'HTTPS://Review-SPA.Example/exact');assert.equal(app.definition('webClientId').example,'review-spa-client');
    app.showActorPopup('browser',card(app,'browser'));assert.ok(app.refs['actor-popup'].querySelector('.participant-context').textContent.includes('HTTPS://Review-SPA.Example/exact'));
    app.inspectActor('browser');assert.ok(app.refs.inspector.querySelector('.participant-context').textContent.includes('review-spa-client'));
    app.resetEnvironment();assert.equal(card(app,'browser').querySelector('.actor-context-address').textContent,'https://spa.example.test');assert.equal(app.innerHTML.includes('review-spa.example'),false);
    app.selectLabScenario('lab-bff-api');assert.equal(app.actorContextRows('browser').length,0,'BFF browser is a frontend user agent');assert.equal(app.actorContextRows('app').find(row=>row.key==='clientID').value,'bff-web');
  }finally{dispose(app);}
});
