import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness} from './dom-harness.mjs';

// Exercises the shipped model through the application and its real player,
// including the scalar trace values. This is not browser or live API testing.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {clock,document}=harness;
const mount=()=>{const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('lab-api-errors');return app;};
const unmount=app=>{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();};

test('aud index animates other-api delivery and recipient rejection without replacing it by expected orders-api',()=>{
  const app=mount();try{
    const actual=app.refs['attribute-index-list'].querySelector('[data-index-attribute="webApiAudience"]');
    assert.ok(actual);actual.click();app.player.stop(false);
    assert.equal(app.attributeSelection,'webApiAudience');
    const rejected=app.traceQueue.filter(frame=>frame.sourceStepId.startsWith('web-error-audience-'));
    assert.deepEqual(rejected.map(frame=>[frame.traceKind,frame.from,frame.to]),[['send','app','realmB'],['verify','realmB','realmB']]);
    assert.ok(rejected.every(frame=>frame.payload[0].value==='other-api'));
    const seen=[],unsubscribe=app.player.subscribe(event=>{if(event.type==='frame'&&event.visible&&event.step.sourceStepId.startsWith('web-error-audience-'))seen.push(event.packet.value);});
    app.player.setSpeed(4);app.playAttribute();clock.until(()=>app.player.status!=='playing');unsubscribe();
    assert.ok(seen.length);assert.ok(seen.every(value=>value==='other-api'));
    app.selectAttribute('webExpectedApiAudience',false);
    assert.deepEqual(app.traceQueue.map(frame=>[frame.from,frame.to,frame.traceKind,frame.payload[0].value]),[['realmB','realmB','use','orders-api']]);
    assert.match(app.refs.inspector.textContent,/local|configured/);
  }finally{unmount(app);}
});

test('full API demo shows four independent cases in model order with separate wrong-audience and scope outcomes',()=>{
  const app=mount();try{
    assert.equal(app.steps.length,14);
    const seen=[],responses=[],unsubscribe=app.player.subscribe(event=>{
      if(event.type!=='step')return;
      seen.push(event.step.id);
      if(['web-error-401','web-error-audience-401','web-error-403','web-error-success-response'].includes(event.step.id))responses.push([event.step.id,event.step.payload[0].value]);
    });
    app.player.setSpeed(4);app.refs.play.click();clock.until(()=>app.player.status!=='playing');unsubscribe();
    assert.equal(app.player.status,'complete');assert.deepEqual(seen,app.steps.map(step=>step.id));
    assert.deepEqual(responses,[['web-error-401','401 Unauthorized'],['web-error-audience-401','401 Unauthorized'],['web-error-403','403 Forbidden'],['web-error-success-response','200 OK']]);
    const wrongCheck=app.steps.find(step=>step.id==='web-error-audience-check');
    assert.equal(wrongCheck.attributeValues.webApiAudience,'other-api');assert.equal(wrongCheck.attributeValues.webExpectedApiAudience,'orders-api');
    assert.equal(wrongCheck.attributeOperations.some(op=>op.attributeId==='webApiScope'&&op.kind==='verify'),false);
  }finally{unmount(app);}
});
