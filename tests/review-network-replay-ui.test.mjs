import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Mounted production app with deterministic frames; native painting is a separate gate.
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('lab-net-radius-udp-radsec');return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}

for(const [suffix,name] of [['identity-backend','NAS-Identifier'],['serverflight-backend','EAP-Message'],['accept','Response Authenticator']])test('NET-05 mounted decoded field replay: '+suffix+' / '+name,()=>{
  const app=mount();try{
    const sourceId=app.labScenarioId+':radsec:'+suffix+'-decode';
    const index=app.steps.findIndex(step=>step.id===sourceId);assert.ok(index>=0);
    const source=app.steps[index],field=source.payload.find(item=>item.name===name);assert.ok(field);
    app.selectStep(index,false);app.player.seek([source],1,'step');
    const expected=app.heldView.snapshot();
    assert.equal(expected.cursor.eventIndex,index);assert.equal(expected.cursor.milestone,'complete');
    app.selectAttribute(field.attributeId,false);
    assert.equal(app.attributeUsages.length,1,'Operational usage, not configuration-only context');
    assert.equal(app.traceQueue.length,1);
    const trace=app.traceQueue[0];
    assert.equal(trace.traceKind,'decrypt');assert.equal(trace.sourceStepId,sourceId);assert.equal(trace.sourceIndex,index);
    assert.equal(app.refs.inspector.querySelector('.context-note'),null,'Operational field is not rendered as inspection/configuration-only context');
    assert.equal(trace.from,source.to);assert.equal(trace.to,source.to);assert.equal(trace.payload[0].value,field.value);
    assert.equal(trace.traceActions[0].representation,'radius-decoded');
    const replay=app.refs['attribute-focus'].querySelector('[data-trace-play]');assert.ok(replay);assert.equal(replay.disabled,false);
    app.refs.speed.value='4';app.refs.speed.dispatchEvent(new HarnessEvent('input'));
    replay.click();clock.until(()=>app.player.status!=='playing');assert.equal(app.player.status,'complete');
    const actual=app.heldView.snapshot();
    assert.deepEqual(actual.cursor,expected.cursor);
    assert.deepEqual(actual.state,expected.state);
    assert.deepEqual(actual.holdings,expected.holdings,'Focused playback preserves the same canonical completed prefix');
    assert.equal(app.protocolSnapshot().sourceIndex,index);
  }finally{unmount(app);}
});

test('NET-05 mounted genuine inspect context remains unplayable',()=>{
  const app=mount();try{
    const context=app.steps.flatMap(step=>step.attributeOperations||[]).find(action=>action.kind==='inspect');assert.ok(context);
    app.selectAttribute(context.attributeId,false);
    assert.equal(app.attributeUsages.length,0);assert.deepEqual(app.traceQueue,[]);
    assert.equal(app.refs.play.disabled,true);
    const replay=app.refs['attribute-focus'].querySelector('[data-trace-play]');
    if(replay)assert.equal(replay.disabled,true);
    app.playAttribute();assert.notEqual(app.player.status,'playing');
  }finally{unmount(app);}
});
