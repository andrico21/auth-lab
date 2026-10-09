import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function select(app,id,value){app.refs[id].value=value;app.refs[id].dispatchEvent(new HarnessEvent('change'));}
for(const mode of ['passkey','enrollment'])test('core '+mode+' participant panels identify CTAP response and browser API construction separately',()=>{
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  try{
    app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');
    select(app,'mode',mode);select(app,'authenticator','yubikey');
    const creating=mode==='enrollment';
    const wire=creating?['ctapFmt','ctapAuthData','ctapAttStmt']:['ctapCredential','ctapAuthData','ctapSignature','ctapUser'];
    const api=creating?['credentialId','authenticatorData','attestationObject']:['credentialId','authenticatorData','signature','userHandle'];
    const device=app.actor('yubikey'),browser=app.actor('browser');
    for(const id of wire){assert.ok(device.attributes.some(field=>field.id===id&&field.kind==='generated'));assert.ok(browser.attributes.some(field=>field.id===id&&field.kind==='received'));}
    for(const id of api)assert.ok(browser.attributes.some(field=>field.id===id&&field.kind==='generated'),id+' constructed locally');
    assert.ok(!device.attributes.some(field=>['signature','userHandle'].includes(field.id)));
    for(const actor of ['yubikey','browser']){
      app.showActorPopup(actor,app.refs.actors.querySelector('[data-actor="'+actor+'"]'));
      for(const id of wire)assert.ok(app.refs['actor-popup'].querySelector('[data-attribute="'+id+'"]'),id+' available in '+actor+' help');
    }
  }finally{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
});
