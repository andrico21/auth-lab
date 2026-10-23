import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');

test('Mounted SMB family defaults to Kerberos and renders readable cryptographic parameters without changing state',()=>{
  const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();
  try{
    app.querySelector('#workspace-search').dispatchEvent(new HarnessEvent('focusin'));app.querySelector('[data-workspace-option="family-windows-windows-files"]').click();assert.equal(app.labScenarioId,'lab-smb-nonjoined-kerberos');app.querySelector('#lesson-reference').open=true;
    const index=app.steps.findIndex(s=>s.smbStage==='client-key-derivation');app.selectStep(index,false);const before=app.protocolSnapshot(),held=app.heldView.snapshot();
    app.querySelector('#learning-detail-crypto').click();const html=app.querySelector('#learning-profile-crypto').innerHTML;
    assert.match(html,/SHA512/);assert.match(html,/AES128-GCM/);assert.match(html,/SMB/);assert.doesNotMatch(html,/\[object Object\]/);assert.doesNotMatch(html,/undefined/);assert.deepEqual(app.protocolSnapshot(),before);assert.deepEqual(app.heldView.snapshot(),held);
  }finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
});
