import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Independent review reproductions at the actual application event boundary.
// This tests UI/model state and SVG availability, not native browser dragging,
// rendered card dimensions, focus navigation or visual animation readability.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {CARD_BOUNDS,validateLayoutRoutes}=await import('../src/layout.js');

function select(app,id,value) {
  const control=app.querySelector('#'+id);assert.ok(control,id+' exists');
  control.value=value;control.dispatchEvent(new HarnessEvent('change'));
}
function mountReportedScenario() {
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  app.selectLabScenario('core');select(app,'mode','password-totp');select(app,'architecture','web');select(app,'upstream','keycloak');select(app,'authenticator','hello');
  assert.equal(app.upstream,'keycloak','the reported scenario uses two Keycloak realms');
  assert.equal(app.authenticator,'hello','Windows Hello remains the default authenticator');
  app.refs['move-participants'].checked=true;app.refs['move-participants'].dispatchEvent(new HarnessEvent('change'));
  app.player.setSpeed(4);return app;
}
function unmount(app) {
  app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();
}
function assertTotpFocus(app) {
  assert.equal(app.attributeSelection,'otpCode');
  assert.ok(app.traceQueue.some(step=>step.from==='totp'&&step.to==='totp'),'focused replay contains the local TOTP processing that triggered F01');
  const line=app.refs.connections.querySelector('[data-pair="totp--totp"] .connection-line');
  assert.ok(line,'local processing has a rendered SVG connection');
  assert.ok(line.getTotalLength()>0,'local connection is usable by the packet player');
}
function finish(app) {
  clock.until(()=>app.player.status!=='playing');assert.equal(app.player.status,'complete');
  assert.equal(app.refs.progress.style.width,'100%');assert.equal(clock.frames.size,0);
}

test('F01 UI: moving before OTP focus preserves replay, playback Reset and Reset layout',()=>{
  const app=mountReportedScenario();try {
    const initial=structuredClone(app.positions);
    assert.equal(app.moveActor('user',634,399),true);assert.deepEqual(app.positions.user,{x:634,y:399});
    assert.doesNotThrow(()=>app.selectAttribute('otpCode',false));assertTotpFocus(app);
    const expected=app.traceQueue.map(step=>step.id),seen=[];
    const unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});
    app.refs.play.click();finish(app);unsubscribe();assert.deepEqual(seen,expected,'the complete focused sequence survives the move');
    assert.doesNotThrow(()=>app.querySelector('#reset').click());
    assert.equal(app.player.status,'idle');assert.equal(app.traceIndex,0);assertTotpFocus(app);
    assert.deepEqual(app.positions.user,{x:634,y:399},'playback Reset retains the chosen layout');
    app.refs.play.click();assert.equal(app.player.status,'playing');
    assert.doesNotThrow(()=>app.querySelector('#layout-reset').click());assert.deepEqual(app.positions,initial);
    assertTotpFocus(app);finish(app);
    assert.doesNotThrow(()=>app.querySelector('#reset').click());assert.equal(app.player.status,'idle');
  }finally{unmount(app);}
});

test('F01 UI: moving during OTP playback pauses safely and both reset controls remain usable',()=>{
  const app=mountReportedScenario();try {
    const initial=structuredClone(app.positions);
    app.selectAttribute('otpCode');assert.equal(app.player.status,'playing');assertTotpFocus(app);
    clock.advance(200);const before=app.player.snapshot(),elapsed=app.player.elapsed,queue=app.player.queue.map(step=>step.id);
    assert.equal(app.moveActor('user',634,399),true);
    assert.equal(app.player.status,'paused');assert.deepEqual(app.positions.user,{x:634,y:399});
    assert.equal(app.player.position,before.queuePosition);assert.equal(app.player.elapsed,elapsed,'movement does not restart the active packet');
    assert.deepEqual(app.player.queue.map(step=>step.id),queue,'movement keeps the exact focused playback queue');
    assertTotpFocus(app);assert.equal(clock.frames.size,0);
    assert.doesNotThrow(()=>app.querySelector('#reset').click());assert.equal(app.player.status,'idle');assertTotpFocus(app);
    assert.deepEqual(app.positions.user,{x:634,y:399});
    app.refs.play.click();finish(app);
    assert.doesNotThrow(()=>app.querySelector('#layout-reset').click());assert.deepEqual(app.positions,initial);assertTotpFocus(app);
    assert.doesNotThrow(()=>app.querySelector('#reset').click());assert.equal(app.player.status,'idle');
    app.refs.play.click();finish(app);
  }finally{unmount(app);}
});

test('an unavailable route rejects a non-colliding move before committing or pausing the player',()=>{
  const app=mountReportedScenario();try {
    // A valid controlled initial layout puts the application outside a ring
    // of four participants. Moving it into that ring blocks every fixed port
    // stub while still preserving the required spacing between all cards.
    app.customLayouts[app.layoutKey]={app:{x:820,y:400},user:{x:210,y:400},browser:{x:590,y:400},realmA:{x:400,y:200},realmB:{x:400,y:600},hello:{x:106,y:111},yubikey:{x:800,y:111},totp:{x:1014,y:619}};
    const pairs=app.steps.map(step=>[app.nodeId(step.from),app.nodeId(step.to)]);
    assert.deepEqual(validateLayoutRoutes(app.positions,pairs),{ok:true},'the starting fixture is routable');
    app.refreshMapGeometry();
    const proposed={...app.positions,app:{x:400,y:400}};
    for(const [id,p]of Object.entries(proposed))if(id!=='app') {
      assert.ok(Math.abs(p.x-400)>=CARD_BOUNDS.width+24||Math.abs(p.y-400)>=CARD_BOUNDS.height+24,'candidate does not collide with '+id);
    }
    const unavailable=validateLayoutRoutes(proposed,pairs);assert.equal(unavailable.ok,false);assert.match(unavailable.reason,/unobstructed graph port|unobstructed graph route/);
    const initial=structuredClone(app.positions),saved=structuredClone(app.customLayouts),paths=app.refs.connections.querySelectorAll('.connection-line').map(line=>line.getAttribute('d'));
    app.refs.play.click();clock.advance(200);const elapsed=app.player.elapsed,position=app.player.position;
    assert.equal(app.moveActor('app',400,400),false);assert.equal(app.player.status,'playing','a rejected candidate must not pause playback');
    assert.deepEqual(app.positions,initial);assert.deepEqual(app.customLayouts,saved,'no rejected coordinates are persisted');
    assert.deepEqual(app.refs.connections.querySelectorAll('.connection-line').map(line=>line.getAttribute('d')),paths,'rejection retains the rendered routes');
    assert.equal(app.player.elapsed,elapsed);assert.equal(app.player.position,position);
    assert.match(app.refs.toast.textContent,/Leave more room for connections/);
    clock.advance(100);assert.ok(app.player.elapsed>elapsed,'the pending animation continues after rejection');
  }finally{unmount(app);}
});
