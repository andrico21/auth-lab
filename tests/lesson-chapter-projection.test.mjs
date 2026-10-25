import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness} from './dom-harness.mjs';

const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');

test('reset and trace exit restore the first chapter with its actors and initial trust state',()=>{
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  try{
    app.selectLabScenario('lab-dnssec01');
    const initialState=app.protocolSnapshot().state;
    const validation=app.labModel.chapters.find(chapter=>chapter.id==='validation');
    app.selectStep(app.steps.findIndex(step=>step.id===validation.stepIds[0]));
    assert.equal(app.positions.dnsApp,undefined,'The validation chapter does not draw the application');
    // Native held-object layouts cache the current chapter's geometry.
    // The DOM harness has no CSS layout, so retain the already projected positions explicitly.
    app.heldGeometry={positions:{...app.positions},routes:new Map()};
    app.querySelector('#reset').click();
    assert.equal(app.currentStep.id,app.labModel.chapters[0].stepIds[0]);
    assert.ok(app.positions.dnsApp,'Reset restores the application participant before drawing its routes');
    assert.ok(app.refs.connections.querySelector('[data-pair="dnsApp--dnsApp"]'));
    assert.deepEqual(app.protocolSnapshot().state,initialState,'Reset does not retain later validation');

    app.selectAttribute('dnssec_rrsig_originalTtl',false);
    assert.equal(app.hasTrace,true);
    app.querySelector('[data-clear-trace]').click();
    assert.equal(app.hasTrace,false);
    assert.equal(app.currentStep.id,app.labModel.chapters[0].stepIds[0]);
    assert.ok(app.positions.dnsApp);
    assert.deepEqual(app.protocolSnapshot().state,initialState,'Leaving a field history restores initial canonical state');
  }finally{
    app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();
  }
});
