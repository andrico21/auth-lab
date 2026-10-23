import test from 'node:test';
import assert from 'node:assert/strict';
import {buildWindowsElevationFixture} from '../src/windows-elevation-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const wetEnd=model=>reconstructProtocolState(model,model.steps().length-1).workstation;
const wetAt=(model,stage)=>{const index=model.steps().findIndex(s=>s.workstationStage===stage);assert.ok(index>=0,stage);return reconstructProtocolState(model,index).workstation;};

test('Classic split-token comparison uses real group attributes and enabled privilege flags',()=>{
  const model=buildWindowsElevationFixture('lab-welev01'),state=wetEnd(model);
  assert.equal(state.token.userSid,state.fullToken.userSid);
  assert.deepEqual(state.token.groups.find(g=>g.sid==='S-1-5-32-544').attributes,['deny-only']);
  assert.ok(state.fullToken.groups.find(g=>g.sid==='S-1-5-32-544').attributes.includes('enabled'));
  assert.equal(state.fullToken.privileges.find(p=>p.name==='SeDebugPrivilege').enabled,false);
  assert.equal(state.token.privileges.some(p=>p.name==='SeDebugPrivilege'),false);
  assert.equal(state.resourceAllowed,false);
  const highDenied=wetEnd(model.withVariant('high-integrity-still-denied'));
  assert.equal(highDenied.token.integrity,'high');assert.equal(highDenied.resourceAllowed,false);
  assert.equal(wetEnd(model.withVariant('standard-user')).fullToken,null);
});

test('Consent-only elevation never authenticates another account or replaces caller token',()=>{
  const model=buildWindowsElevationFixture('lab-welev02'),caller=model.initialState.workstation.callerToken;
  assert.equal(wetAt(model,'request').childToken,null);
  assert.equal(wetAt(model,'launch').childToken.userSid,caller.userSid);
  assert.equal(wetAt(model,'launch').childToken.integrity,'high');
  assert.deepEqual(wetEnd(model).callerToken,caller);assert.equal(wetEnd(model).credentialVerified,false);
  assert.equal(wetEnd(model).childRunning,false);
  const cancel=wetEnd(model.withVariant('cancel'));assert.equal(cancel.childToken,null);assert.deepEqual(cancel.callerToken,caller);
  const denied=wetEnd(model.withVariant('operation-denied'));assert.equal(denied.elevatedProcessCreated,true);assert.equal(denied.resourceAllowed,false);
});

test('Different-admin credentials and runas switch only the newly created process identity',()=>{
  for(const id of ['lab-welev03','lab-welev04']){
    const model=buildWindowsElevationFixture(id),state=wetEnd(model);
    assert.notEqual(state.childToken.userSid,state.callerToken.userSid);
    assert.deepEqual(state.callerToken,model.initialState.workstation.callerToken);
    assert.equal(state.alternateVerified,true);
    assert.equal(state.childToken.integrity,id==='lab-welev03'?'high':'medium');
  }
  const invalid=wetEnd(buildWindowsElevationFixture('lab-welev03','valid-nonadmin'));
  assert.equal(invalid.alternateVerified,true);assert.equal(invalid.childToken,null);
  const domain=buildWindowsElevationFixture('lab-welev03','domain-admin-credential');
  assert.equal(wetEnd(domain).childToken.account,'CORP\\admin2');
  assert.ok(domain.steps().some(s=>s.from==='wslDC'||s.to==='wslDC'));
  assert.equal(wetEnd(buildWindowsElevationFixture('lab-welev04','requires-elevation')).childRunning,false);
});

test('Netonly wrong password launches a local-identity child before first remote failure',()=>{
  const model=buildWindowsElevationFixture('lab-welev05','wrong-password-launches'),launch=wetAt(model,'context');
  assert.equal(launch.launchSucceeded,true);assert.equal(launch.childRunning,true);
  assert.equal(launch.networkAuthenticated,false);assert.equal(launch.credentialVerified,false);
  assert.equal(launch.childToken.userSid,launch.callerToken.userSid);
  assert.equal(launch.outboundAccount,'CORP\\alice');
  const final=wetEnd(model);assert.equal(final.failure.stage,'network');assert.equal(final.childRunning,true);
  assert.deepEqual(final.callerToken,model.initialState.workstation.callerToken);
  const reuse=buildWindowsElevationFixture('lab-welev05','connection-reuse');
  assert.equal(wetEnd(reuse).networkAuthenticated,false);
  assert.equal(reuse.steps().some(s=>s.layers?.length),false);
});

test('Administrator protection uses a separate identity/profile, not reusable classic full token',()=>{
  const model=buildWindowsElevationFixture('lab-welev06'),isolated=wetAt(model,'isolate'),state=wetEnd(model);
  assert.equal(isolated.fullToken,null);assert.notEqual(isolated.childToken.userSid,isolated.callerToken.userSid);
  assert.equal(isolated.inheritedSSO,false);assert.equal(isolated.separateProfile,true);
  assert.equal(state.isolatedTokenReleased,true);assert.equal(state.childRunning,false);
  assert.deepEqual(state.callerToken,model.initialState.workstation.callerToken);
  for(const variant of ['unsupported-build','policy-mode-mismatch','cancel-or-fail'])assert.equal(wetEnd(model.withVariant(variant)).childToken,null);
});

test('Unsupported elevation cases reject instead of choosing the default policy',()=>{
  assert.throws(()=>buildWindowsElevationFixture('lab-welev01','not-a-fixture'),RangeError);
});

