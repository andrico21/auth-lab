import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Event-boundary regressions for changing a protocol/factor after moving cards.
// The offline harness checks application state and actual SVG path availability;
// it does not establish native browser layout or physical pointer behavior.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {getPositions,validateLayoutRoutes}=await import('../src/layout.js');
const reportedMoves=[['yubikey',435,619],['hello',247,619],['browser',435,421],['totp',623,619]];

function select(app,id,value) {
  const control=app.querySelector('#'+id);assert.ok(control,id+' exists');
  control.value=value;control.dispatchEvent(new HarnessEvent('change'));
}
function mount() {
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  app.selectLabScenario('core');
  for(const [id,value]of [['mode','passkey'],['architecture','native'],['upstream','keycloak'],['authenticator','hello']])select(app,id,value);
  app.refs['move-participants'].checked=true;app.refs['move-participants'].dispatchEvent(new HarnessEvent('change'));
  return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function arrangeReportedMoves(app) {
  for(const [id,x,y]of reportedMoves)assert.equal(app.moveActor(id,x,y),true,id+' move was accepted with Windows Hello');
  assert.ok(app.customLayouts[app.layoutKey],'the reproduction really uses a stored custom layout');
}
function assertCoherent(app) {
  assert.deepEqual(app.steps,app.journeyFor(),'active journey corresponds to current configuration');
  const expected=app.visibleSteps;
  const timeline=app.refs.timeline.querySelectorAll('[data-step]');
  assert.equal(timeline.length,expected.length,'timeline and model contain the same number of stages');
  assert.deepEqual(timeline.map(row=>row.querySelector('.step-title').textContent),expected.map(step=>step.title),'timeline titles belong to the current model or focused trace');
  const values={'mode':app.mode,'authenticator':app.authenticator,'architecture':app.architecture,'upstream':app.upstream,'app-protocol':app.applicationProtocol,'broker-protocol':app.brokerProtocol,'oidc-flow':app.oidcFlow,'saml-binding':app.samlBinding,'saml-initiation':app.samlInitiation,'token-protection':app.tokenProtection,'assertion-protection':app.assertionProtection};
  for(const [id,value]of Object.entries(values))assert.equal(app.refs[id].value,value,id+' control matches the current model');
  for(const card of app.refs.actors.querySelectorAll('[data-actor]')) {
    const id=card.dataset.actor,position=app.positions[id];if(!position)continue;
    assert.equal(card.querySelector('.actor-name').textContent,app.actor(id).name,id+' card has the current actor role');
    assert.equal(parseFloat(card.style.left),position.x/1120*100,id+' card has the committed horizontal position');
    assert.equal(parseFloat(card.style.top),position.y/730*100,id+' card has the committed vertical position');
  }
  const pairs=[...app.steps,...app.traceQueue].map(step=>[app.nodeId(step.from),app.nodeId(step.to)]);
  assert.deepEqual(validateLayoutRoutes(app.positions,pairs),{ok:true},'every current journey and focused operation remains routable');
  for(const line of app.refs.connections.querySelectorAll('.connection-line'))assert.ok(line.getTotalLength()>0,'rendered route can carry animation packets');
}
function assertBothResets(app) {
  assert.doesNotThrow(()=>app.querySelector('#reset').click());assert.equal(app.player.status,'idle');assertCoherent(app);
  assert.doesNotThrow(()=>app.querySelector('#layout-reset').click());assertCoherent(app);
  assert.doesNotThrow(()=>app.querySelector('#reset').click());assert.equal(app.player.status,'idle');assertCoherent(app);
}

test('R1: changing the actual authenticator selector after accepted moves cannot leave a stale timeline',()=>{
  const app=mount();try {
    arrangeReportedMoves(app);assert.equal(app.steps.length,25,'the reproduction begins in the Hello model');
    const key=app.layoutKey;
    assert.doesNotThrow(()=>select(app,'authenticator','yubikey'));
    assert.equal(app.authenticator,'yubikey');assert.equal(app.steps.length,29,'the requested YubiKey model is selected');
    assert.equal(app.customLayouts[key],undefined,'the unavailable layout is removed before rendering the new model');
    assert.deepEqual(app.positions,getPositions('native'),'the requested model uses safe default positions');
    assertCoherent(app);assertBothResets(app);
  }finally{unmount(app);}
});

test('R1: a focused authenticator key survives a device change and both resets on the repaired layout',()=>{
  const app=mount();try {
    arrangeReportedMoves(app);app.selectAttribute('privateKey');assert.equal(app.player.status,'playing');
    assert.doesNotThrow(()=>select(app,'authenticator','yubikey'));
    assert.equal(app.player.status,'idle','configuration change cancels the old animation');
    assert.equal(clock.frames.size,0);assert.equal(app.attributeSelection,'privateKey');
    assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.some(step=>[step.from,step.to].includes('yubikey')),'the focused proof belongs to the new device');
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('hello')),'old authenticator operations do not survive the switch');
    assertCoherent(app);assertBothResets(app);assert.equal(app.attributeSelection,'privateKey');
    app.player.setSpeed(4);app.refs.play.click();clock.until(()=>app.player.status!=='playing');assert.equal(app.player.status,'complete');assertCoherent(app);
  }finally{unmount(app);}
});

test('moved layouts are validated when factors and application or broker protocols change',()=>{
  for(const [id,value]of [['mode','password-totp'],['mode','passkey-totp'],['mode','enrollment'],['mode','fido-login'],['broker-protocol','saml'],['app-protocol','saml']]) {
    const app=mount();try {
      arrangeReportedMoves(app);
      assert.doesNotThrow(()=>select(app,id,value),id+'='+value+' renders completely');
      assertCoherent(app);assertBothResets(app);
    }finally{unmount(app);}
  }
});

test('safe custom positions are preserved across factor, provider and protocol changes',()=>{
  const app=mount();try {
    assert.equal(app.moveActor('user',150,130),true);
    const nativeKey=app.layoutKey,nativeLayout=structuredClone(app.customLayouts[nativeKey]);
    for(const [id,value]of [['authenticator','yubikey'],['mode','password-totp'],['mode','passkey-totp'],['upstream','single'],['upstream','external'],['broker-protocol','saml'],['broker-protocol','oidc'],['token-protection','app-jwe']]) {
      select(app,id,value);assertCoherent(app);
      assert.deepEqual(app.customLayouts[nativeKey],nativeLayout,id+'='+value+' retains an available custom layout');
      assert.deepEqual(app.positions.user,{x:150,y:130});
    }
    select(app,'architecture','web');assert.equal(app.moveActor('user',150,130),true);
    const webKey=app.layoutKey,webLayout=structuredClone(app.customLayouts[webKey]);
    for(const [id,value]of [['app-protocol','saml'],['saml-binding','post'],['assertion-protection','encrypted'],['saml-initiation','idp']]) {
      select(app,id,value);assertCoherent(app);
      assert.deepEqual(app.customLayouts[webKey],webLayout,id+'='+value+' retains the available web layout');
    }
    assert.deepEqual(app.customLayouts[nativeKey],nativeLayout,'changes to the web layout leave the saved native layout intact');
  }finally{unmount(app);}
});
