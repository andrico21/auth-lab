import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const mount=()=>{const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;};
const dispose=app=>{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();};
const card=(app,id)=>app.refs.actors.querySelector('[data-actor="'+id+'"]');
const change=(app,id,value)=>{const node=app.querySelector('#'+id);node.value=value;node.dispatchEvent(new HarnessEvent('change'));};
const enter=(app,key,value)=>{const field=app.refs['environment-fields'].querySelector('[data-environment-field="'+key+'"]');assert.ok(field,key);field.value=value;field.dispatchEvent(new HarnessEvent('input'));};

test('ready sign-in cards show their actual application and realm context, with full addresses in help',()=>{
  const app=mount();try{
    assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://app.example.test');
    assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://idp1.example.test');
    assert.ok(card(app,'realmA').querySelector('.actor-context-identity').textContent.includes('realm-a'));
    assert.equal(card(app,'user').querySelector('.actor-context'),null);
    enter(app,'appURL','https://portal.example/team');enter(app,'keycloakABaseURL','https://sso.example/auth');enter(app,'realmA','Company');
    enter(app,'appCallbackURL','https://callbacks.example/return');
    assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://app.example.test','draft is not displayed on participants');
    app.querySelector('#environment-apply').click();
    assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://portal.example/team');
    assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://sso.example/auth');
    assert.ok(card(app,'realmA').querySelector('.actor-context-identity').textContent.includes('Company'));
    assert.equal(card(app,'realmA').getAttribute('aria-describedby'),'actor-context-realmA');
    app.showActorPopup('realmA',card(app,'realmA'));
    assert.ok(app.refs['actor-popup'].querySelector('.participant-context').textContent.includes('https://sso.example/auth/realms/Company'));
    app.inspectActor('app');assert.ok(app.refs.inspector.querySelector('.participant-context').textContent.includes('https://callbacks.example/return'));
    app.resetEnvironment();assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://app.example.test');
    assert.equal(app.innerHTML.includes('https://portal.example/team'),false,'reset clears all displayed participant context');
  }finally{dispose(app);}
});

test('separate Keycloak realm cards preserve deployment and realm ownership and escape display-only metadata',()=>{
  const app=mount();try{
    app.selectLabScenario('two-realms');
    enter(app,'keycloakABaseURL','https://one.example/auth');enter(app,'realmA','Office');
    enter(app,'keycloakBBaseURL','https://two.example/keycloak');enter(app,'realmB','Workers <HQ>');app.querySelector('#environment-apply').click();
    assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://one.example/auth');
    assert.equal(card(app,'realmB').querySelector('.actor-context-address').textContent,'https://two.example/keycloak');
    assert.ok(card(app,'realmB').querySelector('.actor-context-identity').textContent.includes('Workers <HQ>'));
    assert.equal(card(app,'realmB').querySelector('HQ'),null,'realm names cannot create markup');
    app.inspectActor('realmB');assert.ok(app.refs.inspector.textContent.includes('/realms/Workers%20%3CHQ%3E'));
    app.selectLabScenario('basic-keycloak');assert.equal(card(app,'realmB'),null,'unused upstream has no participant label');
  }finally{dispose(app);}
});

test('external cards show the selected provider context and retain Cognito issuer versus login-domain separation',()=>{
  const app=mount();try{
    app.selectLabScenario('corporate-external');change(app,'provider-profile','cognito');
    assert.match(card(app,'realmB').querySelector('.actor-context-address').textContent,/^https:\/\/cognito-idp\./);
    enter(app,'provider.issuerURL','https://idp.example/pool');enter(app,'provider.loginDomainURL','https://signin.example');app.querySelector('#environment-apply').click();
    assert.equal(card(app,'realmB').querySelector('.actor-context-address').textContent,'https://idp.example/pool');
    app.inspectActor('realmB');const text=app.refs.inspector.querySelector('.participant-context').textContent;
    assert.ok(text.includes('https://signin.example'));assert.ok(text.includes('https://signin.example/oauth2/authorize'));assert.ok(text.includes('https://idp.example/pool'));
    change(app,'provider-profile','okta');assert.equal(card(app,'realmB').textContent.includes('https://idp.example/pool'),false);
    change(app,'provider-profile','aws-identity-center');assert.ok(card(app,'realmB').querySelector('.actor-context-address').textContent.includes('/saml/sso'));
    assert.ok(card(app,'realmB').querySelector('.actor-context-identity').textContent.includes('entityID'));
  }finally{dispose(app);}
});

test('mixed-case native HTTP stays on the native card and cannot enter network cards or SAML context',()=>{
  const app=mount();try{
    for(const scheme of ['HTTP','HtTp']){
      app.resetEnvironment();app.selectLabScenario('desktop-sign-in');
      enter(app,'appURL',scheme+'://127.0.0.1:58000/app');enter(app,'appCallbackURL',scheme+'://127.0.0.1:58000/return');app.querySelector('#environment-apply').click();
      assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,scheme+'://127.0.0.1:58000/return');
      app.selectLabScenario('basic-keycloak');assert.equal(card(app,'app').textContent.includes('127.0.0.1:58000'),false);
      app.selectLabScenario('basic-saml');app.inspectActor('app');assert.equal(app.refs.inspector.textContent.includes('127.0.0.1:58000'),false);
    }
  }finally{dispose(app);}
});

test('Cognito selector cannot claim broker JWE; app-side Keycloak JWE and the Generic lesson remain independent',()=>{
  const app=mount();try{
    app.selectLabScenario('corporate-external');change(app,'provider-profile','cognito');
    for(const value of ['broker-jwe','both-jwe'])assert.equal(app.refs['token-protection'].querySelector('[value="'+value+'"]').disabled,true);
    assert.equal(app.refs['token-protection'].querySelector('[value="app-jwe"]').disabled,false);
    change(app,'token-protection','broker-jwe');assert.equal(app.tokenProtection,'signed');assert.equal(app.providerProfileId,'cognito');
    assert.equal(app.steps.some(step=>step.jweHop==='broker'||step.jweInboundHop==='broker'),false);
    change(app,'token-protection','both-jwe');assert.equal(app.tokenProtection,'app-jwe');
    assert.ok(app.steps.some(step=>step.jweHop==='app'));assert.equal(app.steps.some(step=>step.jweHop==='broker'),false);
    change(app,'provider-profile','generic');change(app,'token-protection','broker-jwe');assert.equal(app.tokenProtection,'broker-jwe');assert.ok(app.steps.some(step=>step.jweHop==='broker'));
  }finally{dispose(app);}
});

test('service application URL is visible participant context without inventing an OAuth wire parameter',()=>{
  const app=mount();try{
    app.selectLabScenario('service-to-service');enter(app,'appURL','https://worker.example/service');app.querySelector('#environment-apply').click();
    assert.equal(card(app,'app').querySelector('.actor-context-address').textContent,'https://worker.example/service');
    assert.equal(app.steps.some(step=>step.payload.some(item=>item.name==='appURL'||item.value==='https://worker.example/service')),false);
  }finally{dispose(app);}
});

test('standards-only CIBA actors display their actual OP issuer and never inherit Keycloak or signed-hint identities',()=>{
  const app=mount();try{
    enter(app,'keycloakABaseURL','https://sso.example/context');enter(app,'realmA','Company');app.querySelector('#environment-apply').click();
    for(const id of ['lab-ciba-push','lab-ciba-hint-token']){
      app.selectLabScenario(id);
      assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://ciba.example.test',id);
      assert.equal(card(app,'realmA').querySelector('.actor-context-identity'),null);
      app.inspectActor('realmA');const text=app.refs.inspector.querySelector('.participant-context').textContent;
      assert.ok(text.includes('https://ciba.example.test'));assert.equal(/Keycloak deployment|Company|sso\.example|trusted-hints\.example/.test(text),false,id);
      assert.equal(card(app,'realmB').querySelector('.actor-context'),null,'controlled authentication service is not a Keycloak realm');
      assert.equal(app.actorContextRows('app').find(row=>row.key==='clientID').value,'ciba-lab-client');
      assert.equal(app.actorContextRows('app').some(row=>row.key==='appCallbackURL'),false,'CIBA notification endpoint is not redirect_uri');
    }
    app.selectLabScenario('lab-ciba-ping');assert.equal(card(app,'realmA').querySelector('.actor-context-address').textContent,'https://sso.example/context');
  }finally{dispose(app);}
});

test('advanced clients use the current model owned client_id and redirect_uri instead of generic login examples',()=>{
  const app=mount();try{
    for(const [id,client,callback]of [
      ['lab-bff-api','bff-web','https://app.example.test/oidc/callback'],
      ['lab-offline-access','lifecycle-client','https://app.example.test/oidc/callback'],
      ['lab-par','protected-web-app','https://app.example.test/oauth/callback'],
      ['lab-jar','protected-web-app','https://app.example.test/oauth/callback'],
      ['lab-jarm','protected-web-app','https://app.example.test/oauth/callback'],
      ['lab-implicit','learning-client','https://learning.example.test/callback'],
      ['lab-hybrid','learning-client','https://learning.example.test/callback'],
      ['lab-consent-denial','learning-client','https://learning.example.test/callback'],
      ['service-to-service','orders-service',undefined],
      ['device-sign-in','device-client',undefined],
      ['backend-token-exchange','requester-client',undefined],
    ]){
      app.selectLabScenario(id);const rows=app.actorContextRows('app');
      assert.equal(rows.find(row=>row.key==='clientID')?.value,client,id+' client');
      assert.equal(rows.find(row=>row.key==='appCallbackURL')?.value,callback,id+' callback');
    }
    app.selectLabScenario('core');change(app,'oidc-flow','ciba');assert.equal(app.actorContextRows('app').find(row=>row.key==='clientID').value,'ciba-client');assert.equal(app.actorContextRows('app').some(row=>row.key==='appCallbackURL'),false);
    app.selectLabScenario('lab-par');enter(app,'appURL','https://portal.example/team');enter(app,'clientID','custom-portal');app.querySelector('#environment-apply').click();
    const rows=app.actorContextRows('app');assert.equal(rows.find(row=>row.key==='appURL').value,'https://portal.example/team');assert.equal(rows.find(row=>row.key==='clientID').value,'custom-portal');assert.equal(rows.find(row=>row.key==='appCallbackURL').value,'https://portal.example/team/oauth/callback');
  }finally{dispose(app);}
});

test('LAB assertion issuers remain separate from reused API, RP and controlled-authentication slots',()=>{
  const app=mount();try{
    for(const [id,issuer,label]of [['lab-jwt-grant','https://login.partner.example.test','Assertion issuer'],['lab-exchange-external-in','https://partner.example.test','Assertion issuer'],['lab-broker-account-link','https://login.partner.example.test','OIDC issuer']]){
      app.selectLabScenario(id);assert.deepEqual(app.actorContextRows('realmB').map(row=>[row.label,row.value]),[[label,issuer]],id);
      assert.equal(card(app,'realmB').querySelector('.actor-context-identity'),null,id+' has no Keycloak realm');
    }
    for(const id of ['lab-api-introspection','lab-bff-api','lab-backchannel-logout','lab-frontchannel-logout','lab-saml-metadata','lab-ciba-ping','lab-exchange-external-out']){
      app.selectLabScenario(id);assert.deepEqual(app.actorContextRows('realmB'),[],id+' has no declared IdP deployment');
    }
  }finally{dispose(app);}
});
