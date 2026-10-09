import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {LEARNING_PRESETS} from '../src/learning-presets.js';

// Exercises the real page data/events with deterministic animation frames.
// This harness cannot verify native layout, browser history or autocomplete.
const {document,window,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const mount=()=>{const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;};
const dispose=app=>{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();};
const change=(app,id,value)=>{const node=app.querySelector('#'+id);node.value=value;node.dispatchEvent(new HarnessEvent('change'));};
const enter=(app,key,value)=>{const node=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(node,key+' has its own field');node.value=value;node.dispatchEvent(new HarnessEvent('input'));};
const strings=app=>app.steps.flatMap(step=>[step.title,step.detail,...Object.values(step.attributeValues||{}),...(step.payload||[]).map(item=>item.value)]).join('\n');

test('every ready preset can play its complete real journey without editing configuration',()=>{
  const app=mount();try{
    app.player.setSpeed(4);
    assert.equal(app.labScenarioId,'basic-keycloak');
    assert.deepEqual(Object.keys(app.positions).sort(),['app','browser','realmA','user']);
    for(const preset of LEARNING_PRESETS){
      app.selectLabScenario(preset.id);const seen=[];
      const unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});
      app.refs.play.click();clock.until(()=>app.player.status!=='playing');unsubscribe();
      assert.equal(app.player.status,'complete',preset.id);
      assert.deepEqual(seen,app.steps.map(step=>step.id),preset.id+' runs the chosen model in order');
      assert.equal(app.refs.progress.style.width,'100%');
    }
  }finally{dispose(app);}
});

test('environment edits affect messages and attribute replay only after an explicit atomic apply',()=>{
  const app=mount();try{
    const originalVerifier=app.definition('codeVerifier').example;
    enter(app,'appURL','https://portal.corp.example/team');enter(app,'keycloakABaseURL','https://sso.corp.example/auth');enter(app,'realmA','Employees');
    enter(app,'clientID','employee-portal');enter(app,'appCallbackURL','https://portal.corp.example/team/return');
    assert.equal(strings(app).includes('sso.corp.example'),false,'typing has no effect on current protocol messages');
    app.querySelector('#environment-apply').click();assert.equal(app.runtimeEnvironment.active,true);
    assert.ok(strings(app).includes('https://sso.corp.example/auth/realms/Employees'));
    assert.ok(strings(app).includes('employee-portal'));
    assert.equal(app.definition('redirectApp').example,'https://portal.corp.example/team/return');
    assert.equal(app.definition('codeVerifier').example,originalVerifier,'addresses never change cryptographic proof material');
    app.selectAttribute('redirectApp',false);assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.some(step=>step.payload.some(item=>item.value.includes('https://portal.corp.example/team/return'))));
    const before=JSON.stringify(app.steps),revision=app.runtimeEnvironment.revision;
    enter(app,'appURL','javascript:alert(1)');app.querySelector('#environment-apply').click();
    assert.equal(app.refs['environment-errors'].hidden,false);assert.match(app.refs['environment-errors'].textContent,/Application URL/);
    assert.equal(app.runtimeEnvironment.revision,revision);assert.equal(JSON.stringify(app.steps),before,'invalid input cannot partially replace the animation');
    app.querySelector('#environment-reset').click();assert.equal(app.runtimeEnvironment.active,false);
    assert.equal(strings(app).includes('sso.corp.example'),false);
  }finally{dispose(app);}
});

test('external provider drafts and committed addresses remain isolated while switching OIDC and SAML',()=>{
  const app=mount();try{
    app.selectLabScenario('corporate-external');
    assert.ok(app.environmentFields().some(field=>field.path==='brokerAlias'));
    assert.equal(app.environmentFields().some(field=>field.path==='keycloakBBaseURL'),false);
    enter(app,'provider.issuerURL','https://entra.corp.example/exact-issuer');enter(app,'provider.authorizationURL','https://login.corp.example/start');
    enter(app,'brokerAlias','corp-sso');app.querySelector('#environment-apply').click();
    assert.ok(strings(app).includes('https://login.corp.example/start'));assert.ok(strings(app).includes('/broker/corp-sso/endpoint'));
    change(app,'provider-profile','okta');assert.equal(strings(app).includes('entra.corp.example'),false);assert.equal(strings(app).includes('login.corp.example/start'),false);
    enter(app,'provider.issuerURL','https://okta.corp.example'); // Uncommitted draft survives rendering but is not shown in messages.
    assert.equal(strings(app).includes('https://okta.corp.example'),false);
    change(app,'provider-profile','entra');assert.ok(strings(app).includes('entra.corp.example/exact-issuer'));
    change(app,'provider-profile','aws-identity-center');
    assert.equal(app.brokerProtocol,'saml');assert.ok(app.environmentFields().some(field=>field.path==='provider.samlEntityID'));
    assert.equal(app.environmentFields().some(field=>field.path==='provider.issuerURL'),false);
    enter(app,'provider.samlEntityID','urn:corp:workforce:idp');enter(app,'provider.ssoURL','https://workforce.corp.example/sso');app.querySelector('#environment-apply').click();
    assert.ok(strings(app).includes('urn:corp:workforce:idp'));assert.ok(strings(app).includes('https://workforce.corp.example/sso'));
    app.selectAttribute('samlIdpEntityB',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.some(step=>step.payload.some(item=>item.value==='urn:corp:workforce:idp')));
    change(app,'provider-profile','okta');assert.equal(app.runtimeEnvironment.applied.providers.okta,undefined,'another provider draft was never implicitly committed');
    assert.equal(app.refs['environment-fields'].querySelector('[data-environment-field="provider.issuerURL"]').value,'https://okta.corp.example');
  }finally{dispose(app);}
});

test('page lifecycle clears runtime values and disconnect removes lifecycle listeners',()=>{
  const app=mount();try{
    enter(app,'appURL','https://private-page.example');enter(app,'keycloakABaseURL','https://private-idp.example');app.querySelector('#environment-apply').click();
    app.showAttributePopup('issuerA',app.refs['attribute-index'].querySelector('[data-index-attribute="issuerA"]'));
    assert.ok(app.refs['attribute-popup'].innerHTML.includes('private-idp.example'));
    enter(app,'realmA','draft-only-private-realm');
    window.dispatchEvent(new HarnessEvent('pagehide',{persisted:true}));
    assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.draft.appURL,'');assert.equal(strings(app).includes('private-page.example'),false);
    assert.equal(JSON.stringify([...app.scenarioMemo.values()]).includes('private-idp.example'),false,'discarded environment snapshots do not remain in the application cache');
    assert.equal(app.refs['attribute-popup'].innerHTML,'');assert.equal(app.refs['actor-popup'].innerHTML,'');assert.equal(app.attributeAnchor,null);assert.equal(app.actorAnchor,null);
    assert.equal(JSON.stringify(app.runtimeEnvironment.draft).includes('draft-only-private-realm'),false);
    assert.equal(app.innerHTML.includes('private-idp.example'),false,'hidden application UI does not retain prior operator values');
    enter(app,'appURL','https://private-page.example');app.querySelector('#environment-apply').click();
    window.dispatchEvent(new HarnessEvent('pageshow',{persisted:true}));
    assert.equal(app.runtimeEnvironment.active,false);assert.equal(app.runtimeEnvironment.draft.appURL,'');
    assert.equal(app.refs['environment-fields'].querySelectorAll('input').every(input=>input.getAttribute('autocomplete')==='off'),true);
    assert.equal(window.listeners.get('pagehide').size,1);assert.equal(window.listeners.get('pageshow').size,1);
  }finally{dispose(app);}
  assert.equal(window.listeners.get('pagehide').size,0);assert.equal(window.listeners.get('pageshow').size,0);
});

test('native callback and ordinary SAML environment fields expose their distinct protocol identifiers',()=>{
  const app=mount();try{
    app.selectLabScenario('desktop-sign-in');enter(app,'appCallbackURL','http://127.0.0.1:58001/return');app.querySelector('#environment-apply').click();
    assert.equal(app.refs['environment-errors'].hidden,true);assert.equal(app.definition('redirectApp').example,'http://127.0.0.1:58001/return');
    app.resetEnvironment();app.selectLabScenario('basic-saml');const paths=app.environmentFields().map(field=>field.path);
    assert.ok(paths.includes('acsURL'));assert.ok(paths.includes('appEntityID'));assert.equal(paths.includes('appCallbackURL'),false);assert.equal(paths.includes('aAuthorizationURL'),false);
    enter(app,'acsURL','https://portal.corp.example/consume');enter(app,'appEntityID','urn:corp:portal:sp');app.querySelector('#environment-apply').click();
    assert.ok(strings(app).includes('https://portal.corp.example/consume'));assert.ok(strings(app).includes('urn:corp:portal:sp'));
  }finally{dispose(app);}
});

test('runtime personalization has no persistence, network, address navigation or URL serialization code',()=>{
  const runtime=fs.readFileSync(new URL('../src/runtime-environment.js',import.meta.url),'utf8');
  const app=fs.readFileSync(new URL('../src/app.js',import.meta.url),'utf8');
  for(const forbidden of [/\blocalStorage\b/,/\bsessionStorage\b/,/\bindexedDB\b/,/\bfetch\s*\(/,/\bXMLHttpRequest\b/,/\bsendBeacon\s*\(/,/\blocation\.(?:assign|replace)\s*\(/,/\bdocument\.cookie\b/]){
    assert.equal(forbidden.test(runtime),false,String(forbidden));assert.equal(forbidden.test(app),false,String(forbidden));
  }
  assert.equal(/\bhistory\./.test(runtime),false,'personalization does not serialize runtime addresses');
  assert.match(app,/history\.pushState\(null,'',route\)/,'navigation only writes the fixed registry route');
});

test('hidden desktop callback drafts cannot contaminate web sign-in or block a later SAML environment apply',()=>{
  const app=mount();try{
    app.selectLabScenario('desktop-sign-in');enter(app,'appCallbackURL','http://127.0.0.1:58011/return');app.querySelector('#environment-apply').click();
    app.selectLabScenario('basic-keycloak');assert.equal(strings(app).includes('http://127.0.0.1:58011/return'),false,'web policy retains an HTTPS callback');
    app.selectLabScenario('basic-saml');enter(app,'keycloakABaseURL','https://corporate-saml.example');app.querySelector('#environment-apply').click();
    assert.equal(app.refs['environment-errors'].hidden,true,'inapplicable callback draft is not validated or committed in SAML');
    assert.ok(strings(app).includes('corporate-saml.example'));
    for(const id of ['service-to-service','backend-token-exchange']){
      app.resetEnvironment();app.selectLabScenario(id);const paths=app.environmentFields().map(field=>field.path);
      assert.ok(paths.includes('clientID'),id+' has an actual client registration');assert.equal(paths.includes('appCallbackURL'),false,id+' has no callback');
      enter(app,'clientID','corporate-backend');app.querySelector('#environment-apply').click();assert.ok(strings(app).includes('corporate-backend'));
    }
  }finally{dispose(app);}
});
