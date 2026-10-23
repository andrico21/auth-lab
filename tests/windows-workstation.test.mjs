import test from 'node:test';
import assert from 'node:assert/strict';
import {buildWindowsLogonFixture} from '../src/windows-logon-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const wstEnd=model=>reconstructProtocolState(model,model.steps().length-1).workstation;
const wstAt=(model,stage)=>{const index=model.steps().findIndex(s=>s.workstationStage===stage);assert.ok(index>=0,stage);return reconstructProtocolState(model,index).workstation;};

test('Local password input cannot create a token before SAM validation and local rights',()=>{
  const model=buildWindowsLogonFixture('lab-wlog01');
  for(const stage of ['collect','submit','verify','verify-return'])assert.equal(wstAt(model,stage).token,null);
  assert.equal(wstAt(model,'verify').credentialVerified,true);
  const authorized=wstAt(model,'authorize');
  assert.equal(authorized.consoleAllowed,true);assert.equal(authorized.desktopReady,false);
  assert.equal(authorized.token.userSid,'S-1-5-21-110-220-330-1001');
  assert.equal(authorized.token.groups[0].sid,'S-1-5-32-545');
  assert.deepEqual(authorized.token.privileges,[{name:'SeChangeNotifyPrivilege',enabled:true}]);
  assert.equal(authorized.token.integritySid,'S-1-16-8192');
  assert.equal(authorized.token.type,'primary');assert.ok(authorized.token.authenticationId.startsWith('LUID('));
  assert.equal(wstEnd(model).desktopReady,true);
  assert.equal(model.steps().some(s=>s.layers.length>0),false);
});

test('Each WLOG01 negative changes input and stops at the independent detector',()=>{
  const expected={
    'bad-password':{stage:'verify',detector:'wslSAM',verified:false,token:false},
    'disabled-account':{stage:'verify',detector:'wslSAM',verified:false,token:false},
    'deny-interactive':{stage:'authorize',detector:'wslLSA',verified:true,token:false},
    'profile-failure':{stage:'desktop',detector:'wslProcess',verified:true,token:true}
  };
  for(const [variant,e] of Object.entries(expected)){
    const model=buildWindowsLogonFixture('lab-wlog01',variant),state=wstEnd(model);
    assert.equal(state.failure.stage,e.stage);assert.equal(state.detector,e.detector);
    assert.equal(state.credentialVerified,e.verified);assert.equal(!!state.token,e.token);
    assert.equal(state.desktopReady,false);assert.equal(state.inputReleased,true);
    const detector=wstAt(model,e.stage);assert.equal(detector.clientKnowsResult,false);
    assert.equal(state.clientKnowsResult,true);
  }
});

test('Denied variant construction leaves the original successful logon intact and unknown cases reject',()=>{
  const model=buildWindowsLogonFixture('lab-wlog01'),before=wstEnd(model);
  const denied=model.withVariant('bad-password');
  assert.equal(wstEnd(denied).desktopReady,false);
  assert.equal(wstEnd(model).desktopReady,true);
  assert.deepEqual(wstEnd(model),before);
  assert.throws(()=>model.withVariant('missing'),RangeError);
});


test('Online logon separates AS ciphertext receipt, protected acceptance and local rights',()=>{
  const online=buildWindowsLogonFixture('lab-wlog02');
  assert.equal(wstAt(online,'as-reply').tgtAccepted,false);assert.equal(wstAt(online,'as-reply').token,null);
  assert.equal(wstAt(online,'as-accept').tgtAccepted,true);assert.equal(wstAt(online,'as-accept').desktopReady,false);
  const host= wstEnd(online.withVariant('host-key-mismatch'));assert.equal(host.tgtAccepted,true);assert.equal(host.hostTicketAccepted,false);assert.equal(host.token,null);
  const rights=wstEnd(online.withVariant('denied-local-logon'));assert.equal(rights.credentialVerified,true);assert.equal(rights.hostTicketAccepted,true);assert.equal(rights.token,null);
});

test('Explicit-local and cached authorities do not borrow a live domain grant',()=>{
  const local=buildWindowsLogonFixture('lab-wlog03');assert.equal(wstEnd(local).token.userSid,'S-1-5-21-110-220-330-1002');assert.equal(local.steps().some(s=>s.layers?.length),false);
  assert.equal(wstEnd(local.withVariant('domain-password-for-local-user')).token,null);
  const cached=buildWindowsLogonFixture('lab-wlog04');assert.equal(wstEnd(cached).desktopReady,true);assert.equal(wstEnd(cached).tgtAccepted,false);assert.equal(wstEnd(cached).freshDomainKnowledge,false);
  assert.equal(wstEnd(cached.withVariant('stale-password-or-disable')).staleKnowledge,true);
  const rejected=cached.withVariant('online-rejection');assert.equal(wstAt(rejected,'attempt').detector,'wslDC');assert.equal(wstEnd(rejected).token,null);assert.equal(rejected.steps().some(s=>s.workstationStage==='verify-cache'),false);
  assert.equal(wstEnd(cached.withVariant('protected-user')).token,null);
});

test('PKINIT and FAST preserve distinct computer, user and local-admission boundaries',()=>{
  const card=buildWindowsLogonFixture('lab-wlog05');assert.equal(wstEnd(card).passwordCredential,false);assert.equal(wstEnd(card).hostTicketAccepted,true);
  for(const variant of ['expired-user-cert','revoked-user-cert','untrusted-user-cert']){const denied=card.withVariant(variant);assert.equal(wstAt(denied,'pkinit').detector,'wslDC');assert.equal(wstEnd(denied).tgtAccepted,false);assert.equal(wstEnd(denied).token,null);}
  const fast=buildWindowsLogonFixture('lab-wlog06'),badUser=fast.withVariant('bad-user-proof');assert.equal(wstEnd(badUser).machineAccepted,true);assert.equal(wstEnd(badUser).tgtAccepted,false);
  const badReply=fast.withVariant('tampered-fast-reply');assert.equal(wstAt(badReply,'accept').detector,'wslLSA');assert.equal(wstEnd(badReply).token,null);
  assert.equal(wstEnd(fast).replyStrengthened,true);
});

test('Unlock preserves the existing token, logon session and processes, including stale cached facts',()=>{
  for(const variant of ['default','bad-credential','domain-required','domain-cached','cached-domain-change']){
    const model=buildWindowsLogonFixture('lab-wlog07',variant),initial=model.initialState.workstation,end=wstEnd(model);
    assert.equal(wstAt(model,'lock').locked,true);assert.deepEqual(end.token,initial.token);assert.equal(end.sessionId,initial.sessionId);assert.equal(end.processId,initial.processId);
  }
  assert.equal(wstEnd(buildWindowsLogonFixture('lab-wlog07','bad-credential')).locked,true);
  assert.equal(wstEnd(buildWindowsLogonFixture('lab-wlog07','cached-domain-change')).staleKnowledge,true);
});

test('Nonjoined outbound failures preserve the locally admitted desktop and local credential input',()=>{
  const base=buildWindowsLogonFixture('lab-wlog08');
  for(const variant of ['bad-network-password','resource-denial','no-kerberos-prerequisite']){
    const model=base.withVariant(variant),end=wstEnd(model);assert.equal(end.desktopReady,true);assert.equal(end.localAccount,'WORKGROUPPC\\bob');assert.equal(end.outboundAccount,'CORP\\alice');assert.equal(end.token.userSid,'S-1-5-21-110-220-330-1001');assert.equal(model.fixtureInputs.credentialCandidate,base.fixtureInputs.credentialCandidate);
  }
  const denied=wstEnd(base.withVariant('resource-denial'));assert.equal(denied.networkAuthenticated,true);assert.equal(denied.resourceAllowed,false);
});

