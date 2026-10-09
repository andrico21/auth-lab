import test from 'node:test';
import assert from 'node:assert/strict';
import {ACTORS} from '../src/protocol-data.js';
import {BRANCHLAB_ATTRIBUTES,BRANCHLAB_SCENARIOS} from '../src/branching-lab.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
const branchById=id=>BRANCHLAB_SCENARIOS.find(m=>m.id===id);
const branchOps=model=>model.steps().flatMap(s=>s.attributeOperations);

test('branch scenarios have complete authoritative ledgers and honest supported/legacy labels',()=>{
  assert.equal(BRANCHLAB_SCENARIOS.length,8);
  assert.equal(new Set(BRANCHLAB_SCENARIOS.map(m=>m.id)).size,8);
  for(const model of BRANCHLAB_SCENARIOS){
    assert.ok(model.status&&model.supportNote&&model.source);
    const stages=model.steps();assert.ok(stages.length>=6);assert.equal(new Set(stages.map(s=>s.id)).size,stages.length);
    for(const s of stages){assert.ok(ACTORS[s.from]&&ACTORS[s.to]);assert.ok(s.payload.length&&s.detail);assert.ok(s.attributeOperations.length);for(const op of s.attributeOperations){assert.ok(ACTORS[op.actorId]);assert.ok(BRANCHLAB_ATTRIBUTES[op.attributeId]);}}
    for(const id of model.ids){const def=model.definitions()[id];for(const key of ['name','meaning','origin','purpose','standard','source'])assert.ok(def[key],id+' '+key);}
  }
});
test('the deprecated direct grant carries user password and separate client authentication without browser/PKCE',()=>{
  const m=branchById('lab-direct-grant'),steps=m.steps();assert.match(m.supportNote,/MUST NOT/);
  const wire=branchOps(m).filter(op=>op.kind==='send');assert.ok(wire.some(op=>op.attributeId==='branchPassword'&&op.actorId==='app'));assert.ok(wire.some(op=>op.attributeId==='branchAuthorization'&&op.actorId==='app'));
  for(const id of ['branchClientId','branchClientSecret']){assert.ok(wire.some(op=>op.attributeId===id&&op.carriedAs==='Authorization: Basic'));assert.ok(branchOps(m).some(op=>op.attributeId===id&&op.kind==='verify'&&op.actorId==='realmA'));}
  assert.ok(steps.every(s=>![s.from,s.to].includes('browser')));
  assert.ok(!m.ids.includes('branchVerifier'));assert.ok(!m.ids.includes('branchCode'));
  assert.ok(branchOps(m).filter(o=>o.attributeId==='branchPasswordHash').every(o=>!['send','receive'].includes(o.kind)));
});
test('implicit omits code and refresh while hybrid validates c_hash/at_hash before separate PKCE redemption',()=>{
  const implicit=branchById('lab-implicit'),hybrid=branchById('lab-hybrid');
  assert.ok(!implicit.ids.includes('branchCode'));assert.ok(!implicit.ids.includes('branchRefreshToken'));assert.ok(!implicit.ids.includes('branchVerifier'));
  assert.ok(implicit.steps().some(s=>/fragment/.test(s.detail+s.summary)));
  const checks=hybrid.steps().findIndex(s=>s.id==='branch-hybrid-checks'),redeem=hybrid.steps().findIndex(s=>s.id==='branch-hybrid-redeem');assert.ok(checks<redeem);
  assert.ok(hybrid.steps()[checks].attributeOperations.some(o=>o.attributeId==='branchCHash'&&o.kind==='verify'));
  assert.ok(hybrid.steps()[checks].attributeOperations.some(o=>o.attributeId==='branchAtHash'&&o.kind==='verify'));
  assert.ok(branchOps(hybrid).filter(o=>o.attributeId==='branchVerifier'&&o.kind==='send').every(o=>o.actorId==='app'));
  assert.ok(!branchOps(hybrid).some(o=>o.attributeId==='branchVerifier'&&o.actorId==='browser'));
});
test('consent denial is a distinct attempt with state checks and no later issuance',()=>{
  const stages=branchById('lab-consent-denial').steps(),deny=stages.findIndex(s=>s.id==='branch-consent-deny');assert.ok(deny>0);
  assert.ok(stages.slice(deny).every(s=>!s.fields.includes('branchCode')&&!s.fields.includes('branchAccessToken')));
  assert.ok(stages.at(-1).attributeOperations.some(o=>o.attributeId==='branchState'&&o.kind==='verify'));
});
test('broker linking verifies existing-account control before changing the issuer/subject mapping',()=>{
  const stages=branchById('lab-broker-account-link').steps();
  const verified=stages.findIndex(s=>s.attributeOperations.some(o=>o.attributeId==='branchPassword'&&o.kind==='verify'));
  const linked=stages.findIndex(s=>s.attributeOperations.some(o=>o.attributeId==='branchIdentityLink'&&o.kind==='create'));
  assert.ok(verified>=0&&verified<linked);assert.match(stages.find(s=>s.id==='branch-link-match').checks.join(' '),/alone does not prove/);
});
test('WebAuthn cancellation stays local and any successful fallback requires a separate verified factor',()=>{
  const m=branchById('lab-passkey-cancel'),stages=m.steps();
  assert.ok(branchOps(m).filter(o=>o.attributeId==='branchNotAllowed').every(o=>o.actorId==='browser'&&!['send','receive'].includes(o.kind)));
  assert.ok(!m.ids.includes('signature'));assert.ok(!m.ids.includes('branchAccessToken'));
  assert.ok(stages.at(-1).attributeOperations.some(o=>o.attributeId==='branchPassword'&&o.kind==='verify'));
});
test('recovery checks signed account/action/lifetime/one-use state before accepting a replacement password',()=>{
  const stages=branchById('lab-account-recovery').steps(),check=stages.findIndex(s=>s.id==='branch-recovery-check'),input=stages.findIndex(s=>s.id==='branch-recovery-password');assert.ok(check<input);
  for(const id of ['branchActionToken','branchSubject','branchActionType','branchExp','branchJti'])assert.ok(stages[check].attributeOperations.some(o=>o.attributeId===id&&o.kind==='verify'));
  assert.ok(branchOps(branchById('lab-account-recovery')).filter(o=>o.attributeId==='branchSigningKey').every(o=>o.actorId==='realmA'&&o.kind==='use'));
  assert.ok(stages.at(-1).attributeOperations.some(o=>o.attributeId==='branchJti'&&o.kind==='store'));
});
test('concurrent-session revocation fails refresh without promising instant offline JWT invalidation',()=>{
  const stages=branchById('lab-concurrent-sessions').steps();assert.equal(stages.find(s=>s.id==='branch-sessions-reject').payload.find(p=>p.name==='error').value,'invalid_grant');
  assert.match(stages.at(-1).attributeOperations.map(o=>o.detail).join(' '),/additional state\/introspection/);assert.ok(stages.at(-1).fields.includes('branchExp'));
});
test('front-channel response_type stays valid on both browser hops and hybrid validates both identity results',()=>{
  for(const [id,value]of [['lab-implicit','id_token token'],['lab-hybrid','code id_token token']]){
    const stages=branchById(id).steps();
    for(const s of stages.filter(s=>/-navigate$|-request$/.test(s.id)))assert.equal(s.payload.find(p=>p.attributeId==='branchResponseType').value,value);
  }
  const hybrid=branchById('lab-hybrid').steps();
  assert.ok(hybrid.find(s=>s.id==='branch-hybrid-request').attributeOperations.some(o=>o.attributeId==='branchChallenge'&&o.kind==='store'&&o.actorId==='realmA'));
  assert.ok(hybrid.find(s=>s.id==='branch-hybrid-pkce').attributeOperations.some(o=>o.attributeId==='branchChallengeMethod'&&o.kind==='verify'));
  assert.ok(hybrid.at(-1).attributeOperations.some(o=>o.attributeId==='branchIdToken'&&o.kind==='verify'&&o.actorId==='app'));
});
test('hybrid ID tokens preserve the same explicit issuer and subject across both deliveries and local checks',()=>{
  const model=branchById('lab-hybrid'),stages=model.steps();
  const expected={iss:'https://idp1.example.test/realms/realm-a',sub:'person-in-realm-a-204'};
  const claims=s=>Object.fromEntries(s.payload.filter(p=>['branchIssuer','branchIdentitySubject'].includes(p.attributeId)).map(p=>[p.name,p.value]));
  for(const suffix of ['sign','fragment','callback','checks','tokens','final-checks']){
    const step=stages.find(s=>s.id==='branch-hybrid-'+suffix);
    assert.deepEqual(claims(step),expected,suffix+' retains the actual issued identity');
  }
  const front=stages.find(s=>s.id==='branch-hybrid-fragment'),back=stages.find(s=>s.id==='branch-hybrid-tokens');
  assert.notEqual(front.payload.find(p=>p.attributeId==='branchIdToken').value,back.payload.find(p=>p.attributeId==='branchIdToken').value,'Two symbolic ID-token values may differ while identifying the same issuer and subject.');
  for(const suffix of ['fragment','callback','tokens']){
    const step=stages.find(s=>s.id==='branch-hybrid-'+suffix);
    for(const id of ['branchIssuer','branchIdentitySubject']){
      assert.deepEqual(step.attributeOperations.filter(o=>o.attributeId===id).map(o=>o.kind).filter(k=>['send','receive'].includes(k)),['send','receive']);
      assert.ok(step.attributeOperations.filter(o=>o.attributeId===id&&['send','receive'].includes(o.kind)).every(o=>o.carriedAs==='id_token (JWS)'));
    }
  }
  const check=stages.find(s=>s.id==='branch-hybrid-checks'),final=stages.at(-1);
  const retained=JSON.parse(check.payload.find(p=>p.attributeId==='branchFirstIdentityPair').value);
  assert.deepEqual(retained,expected);
  assert.deepEqual(JSON.parse(final.payload.find(p=>p.attributeId==='branchFirstIdentityPair').value),expected);
  const ops=check.attributeOperations;
  assert.ok(ops.findIndex(o=>o.attributeId==='branchIdentitySubject'&&o.kind==='verify')<ops.findIndex(o=>o.attributeId==='branchFirstIdentityPair'&&o.kind==='derive'));
  assert.ok(ops.some(o=>o.attributeId==='branchFirstIdentityPair'&&o.kind==='store'));
  assert.ok(branchOps(model).filter(o=>o.attributeId==='branchFirstIdentityPair').every(o=>o.actorId==='app'&&!['send','receive'].includes(o.kind)));
  assert.ok(final.attributeOperations.some(o=>o.attributeId==='branchFirstIdentityPair'&&o.kind==='use'));
  assert.match(final.attributeOperations.filter(o=>o.kind==='verify').map(o=>o.detail).join(' '),/identical iss\/sub relationship required of issued tokens by §3\.3\.3\.6/);
  assert.match(final.attributeOperations.filter(o=>o.kind==='verify').map(o=>o.detail).join(' '),/not presented as a separate compare-sub bullet in §3\.3\.3\.7/);
  const usages=stages.map((step,index)=>({step,index,actions:step.attributeOperations.filter(o=>['branchIssuer','branchIdentitySubject'].includes(o.attributeId))})).filter(u=>u.actions.length);
  for(const projected of buildAttributeTrace(usages))for(const p of projected.payload)assert.equal(p.value,p.attributeId==='branchIssuer'?expected.iss:expected.sub,'Focused replay keeps the same issuer-specific identity value.');
});
test('hybrid preparation includes local S256 method selection before challenge derivation and transmission',()=>{
  const stages=branchById('lab-hybrid').steps(),prepare=stages[0];
  assert.equal(prepare.payload.find(p=>p.attributeId==='branchChallengeMethod').value,'S256');
  const selection=prepare.attributeOperations.findIndex(o=>o.attributeId==='branchChallengeMethod'&&o.kind==='use'&&o.actorId==='app');
  const derivation=prepare.attributeOperations.findIndex(o=>o.attributeId==='branchChallenge'&&o.kind==='derive');
  assert.ok(selection>=0&&selection<derivation);
  const projected=buildAttributeTrace([{step:prepare,index:0,actions:prepare.attributeOperations.filter(o=>o.attributeId==='branchChallengeMethod')}]);
  assert.equal(projected.length,1);assert.equal(projected[0].traceKind,'use');assert.equal(projected[0].payload[0].value,'S256');
});
test('provider password and recovery hover definitions describe their actual recipient and purpose',()=>{
  for(const id of ['lab-broker-account-link','lab-passkey-cancel']){
    const def=branchById(id).definitions().branchPassword;assert.match(def.purpose,/Neither the initiating OAuth application/);assert.doesNotMatch(def.purpose,/forwards it directly to the token endpoint/);
  }
  assert.match(branchById('lab-account-recovery').definitions().branchUsername.purpose,/authenticates nobody/);
});
test('each consent attempt sends its own state before the matching provider result',()=>{
  const stages=branchById('lab-consent-denial').steps();
  assert.equal(stages.find(s=>s.id==='branch-consent-deliver-A').payload.find(p=>p.attributeId==='branchState').value,'consent-state-A');
  assert.equal(stages.find(s=>s.id==='branch-consent-success').payload.find(p=>p.attributeId==='branchState').value,'consent-state-A');
  assert.equal(stages.find(s=>s.id==='branch-consent-deliver-B').payload.find(p=>p.attributeId==='branchState').value,'consent-state-B');
  assert.equal(stages.find(s=>s.id==='branch-consent-error').payload.find(p=>p.attributeId==='branchState').value,'consent-state-B');
  assert.ok(stages.findIndex(s=>s.id==='branch-consent-deliver-B')<stages.findIndex(s=>s.id==='branch-consent-deny'));
  assert.equal(stages.find(s=>s.id==='branch-consent-accept').payload[0].value,'approve');
});
test('the concurrent-session refresh authenticates its client before the session-dependent rejection',()=>{
  const request=branchById('lab-concurrent-sessions').steps().find(s=>s.id==='branch-sessions-refresh');
  assert.ok(request.attributeOperations.some(o=>o.attributeId==='branchAuthorization'&&o.kind==='send'&&o.actorId==='app'));
  assert.ok(request.attributeOperations.some(o=>o.attributeId==='branchClientSecret'&&o.kind==='verify'&&o.actorId==='realmA'));
});
