import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {WINDOWSREMOTELAB_SCENARIOS,WINDOWSREMOTELAB_ATTRIBUTES,buildWindowsRemoteAdministrationFixture,buildWindowsRemoteSmbReference,evaluateWindowsRemoteAccess} from '../src/windows-remote-administration-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildHeldObjects} from '../src/held-objects.js';
import {assertHeldObjectCoverage,projectHeldObjects} from '../src/held-object-state.js';

const remoteManifest=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/remote-cases.json',import.meta.url)));
const remoteProfiles=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/profiles-remote.json',import.meta.url)));
const remoteSources=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/sources-remote.json',import.meta.url)));
const remoteEnd=model=>reconstructProtocolState(model,model.steps().length-1).workstation;
const remoteAt=(model,stage)=>{const index=model.steps().findIndex(step=>step.workstationStage===stage);assert.ok(index>=0,stage);return reconstructProtocolState(model,index).workstation;};
const remoteEffects=event=>(event?.milestones||[]).flatMap(m=>m.effects||[]);

// No expected-answer function from production is imported. These are literal WP0
// answers frozen from the user plan and captured primary sources before evaluator.
for(const row of remoteManifest.cases)for(const fixture of row.subfixtures){
  test(row.id+'/'+fixture.id+' obeys independent source-only expectations',()=>{
    const model=buildWindowsRemoteAdministrationFixture(row.modelId,row.id.split('/')[1],fixture.id),end=remoteEnd(model),expected=fixture.expected;
    assert.equal(model.variantId,row.id.split('/')[1]);assert.equal(model.canonicalCaseId,row.id);assert.equal(model.subfixtureId,fixture.id);
    assert.equal(model.profile.id,fixture.profileId);assert.ok(Object.isFrozen(model.fixtureInputs));
    const profile=remoteProfiles.profiles.find(p=>p.id===fixture.profileId);assert.deepEqual(model.fixtureInputs,profile.inputs);
    for(const key of ['credentialVerified','admissionAllowed','resourceAllowed','serverAuthenticated','clientSessionAccepted','clientKnowsResult'])assert.equal(end[key],expected[key],key);
    assert.equal(end.token?.mode??null,expected.tokenMode);assert.equal(end.failureStage,expected.firstDetector);assert.equal(end.returnedResult,expected.returnedResult);
    assert.equal(Boolean(end.priorSession),expected.priorSessionRetained);assert.equal(end.localAccount,'WORKGROUPPC\\bob');assert.equal(end.remotePrompt,false);assert.equal(end.inputReleased,true);
    if(expected.firstDetector){const detected=remoteAt(model,expected.firstDetector);assert.equal(detected.clientKnowsResult,false);assert.equal(detected.detector,fixture.firstDetectingActor);}
    if(!expected.admissionAllowed){assert.equal(end.token,null);assert.equal(model.steps().some(s=>s.smbStage==='server-session'),false);assert.equal(model.steps().some(s=>s.smbStage==='share-check'),false);}
    if(expected.admissionAllowed&&expected.resourceAllowed===false){assert.equal(end.serverAuthenticated,true);assert.equal(end.clientSessionAccepted,true);}
    if(end.token){assert.equal(end.token.owner,'smbServer');assert.equal(end.token.type,'impersonation');assert.equal(end.token.integrity,'unknown');assert.equal(end.token.elevationType,'unknown');assert.equal(end.token.remotePrompt,false);}
    assert.equal(model.initialState.workstation.tokenComparison,null);assert.equal(model.initialState.workstation.appliedPolicy,null);assert.equal(model.initialState.workstation.verdictExplanation,null);
    if(expected.admissionAllowed){
      const comparison=end.tokenComparison;assert.ok(comparison);assert.equal(comparison.before.kind,'modeled-target-filter-input');assert.equal(comparison.before.usableToken,false);assert.equal(Object.hasOwn(comparison.before,'tokenId'),false);
      assert.equal(comparison.before.owner,'smbServer');assert.equal(comparison.after.owner,'smbServer');assert.equal(comparison.before.userSid,profile.inputs.sid);assert.equal(comparison.after.userSid,end.token.userSid);
      assert.deepEqual(comparison.after.groups,end.token.groups);assert.deepEqual(comparison.after.privileges,end.token.privileges);assert.equal(comparison.userSIDUnchanged,true);assert.equal(comparison.additionalTokenOrGrantCreated,false);
      assert.equal(remoteAt(model,'target-admission').tokenComparison,null);assert.equal(remoteAt(model,'target-token-comparison').credentialVerified,true);assert.equal(remoteAt(model,'target-token-comparison').admissionAllowed,true);
      for(const key of ['target-filter-input','token-comparison']){const object=model.workstationInventory.artifacts.find(o=>o.key===key);assert.ok(object);assert.deepEqual(object.readers,['smbServer']);assert.equal(model.workstationInventory.initial.some(e=>e.op==='create'&&e.artifactId===object.artifactId),false);}
    }else{assert.equal(end.tokenComparison,null);assert.equal(end.appliedPolicy,null);assert.equal(end.policyComparison.applied,null);}
    assert.equal(typeof end.verdictExplanation,'string');assert.ok(end.verdictExplanation.length>0);
    const union=new Set(model.catalogAttributeIds);for(const id of model.ids){assert.ok(union.has(id),id);assert.ok(WINDOWSREMOTELAB_ATTRIBUTES[id],id);}
    for(const actorId of Object.keys(model.actors())){assert.ok(model.compactPositions[actorId],actorId);assert.ok(model.expandedPositions[actorId],actorId);}
    // Every transferred representation must already be owned before its event.
    const inventory=model.workstationInventory,live=new Map();
    const apply=e=>{if(e.op==='acquire')live.set(e.holdingId,e);else if(e.op==='release')live.delete(e.holdingId);};inventory.initial.forEach(apply);
    for(const step of model.steps()){
      const event=inventory.events[step.id];assert.ok(event,step.id);
      for(const message of event.messages||[])for(const carried of message.objects)assert.ok([...live.values()].some(e=>e.actorId===message.from&&e.artifactId===carried.artifactId&&e.representationId===carried.representationId),step.id+' sender '+carried.artifactId+' '+carried.representationId);
      for(const operation of step.attributeOperations||[])assert.ok(inventory.events[operation.sourceEventId],operation.sourceEventId);
      remoteEffects(event).forEach(apply);
    }
    assert.equal([...live.values()].some(e=>e.retention==='temporary'),false,'all attempt scratch released');
    assert.ok([...live.values()].some(e=>e.actorId==='smbClient'&&e.artifactId.endsWith(':desktop')),'desktop survives');
    if(expected.admissionAllowed)assert.ok([...live.values()].some(e=>e.actorId==='smbServer'&&e.artifactId.endsWith(':session-context')),'accepted session survives later denial');
    if(expected.priorSessionRetained&&model.fixtureInputs.sessionMode==='prior-session-denial')assert.ok([...live.values()].some(e=>e.artifactId.endsWith(':prior-session')),'independent prior session survives proof rejection');
  });
}

test('WRA case denominator, canonical default aliases and all named subfixtures are exact',()=>{
  assert.equal(remoteManifest.canonicalCaseCount,38);assert.equal(remoteManifest.subfixtureCount,44);assert.equal(remoteManifest.cases.length,38);
  assert.equal(WINDOWSREMOTELAB_SCENARIOS.length,5);assert.equal(WINDOWSREMOTELAB_SCENARIOS.reduce((n,m)=>n+m.variantChoices.length,0),38);
  for(const descriptor of WINDOWSREMOTELAB_SCENARIOS){
    const rows=remoteManifest.cases.filter(row=>row.modelId===descriptor.id);assert.deepEqual(descriptor.variantChoices.map(c=>c.id),rows.map(row=>row.id.split('/')[1]));
    assert.equal(descriptor.defaultVariantId,rows[0].id.split('/')[1]);assert.equal(descriptor.withVariant('default').variantId,descriptor.defaultVariantId);assert.equal(descriptor.variantChoices.some(v=>v.id==='default'),false);
    assert.throws(()=>descriptor.withVariant('unknown'),RangeError);
    for(const row of rows){const selected=descriptor.withVariant(row.id.split('/')[1]);assert.deepEqual(selected.subfixtureChoices.map(f=>f.id),row.subfixtures.map(f=>f.id));assert.throws(()=>selected.withSubfixture('unknown'),RangeError);}
  }
  assert.throws(()=>buildWindowsRemoteAdministrationFixture('lab-missing'),RangeError);
});

test('Local SAM and domain NTLM really use distinct authorities and key paths',()=>{
  const local=buildWindowsRemoteAdministrationFixture('lab-wra01'),domain=buildWindowsRemoteAdministrationFixture('lab-wra03','domain-ntlm-explicit');
  assert.equal(remoteEnd(local).verifierAuthority,'TARGET SAM');assert.equal(remoteEnd(domain).verifierAuthority,'CORP domain DC through target machine secure channel');
  assert.ok(local.steps().some(s=>s.smbStage==='sam-verify'));assert.equal(local.steps().some(s=>s.smbStage==='dc-request'),false);assert.equal(local.steps().some(s=>s.smbStage==='as-request'),false);assert.equal(Object.hasOwn(local.actors(),'smbDC'),false);
  const lv=local.workstationInventory.artifacts.find(o=>o.key==='account-verifier');assert.equal(lv.creator,'smbSAM');assert.match(lv.value,/TARGET\\ops/);assert.match(lv.store,/SAM/);
  const dv=domain.workstationInventory.artifacts.find(o=>o.key==='account-verifier');assert.equal(dv.creator,'smbDC');assert.match(dv.value,/CORP\\ops/);assert.match(dv.store,/AD/);
  assert.ok(domain.steps().some(s=>s.smbStage==='dc-request'));assert.equal(domain.steps().some(s=>s.smbStage==='sam-verify'),false);
  assert.equal(remoteAt(local,'sam-verify').serverAuthenticated,false);assert.equal(remoteAt(domain,'dc-verify').serverAuthenticated,false);
});

test('Domain nonjoined Kerberos has explicit prerequisites and independent ticket/subkey histories',()=>{
  const model=buildWindowsRemoteAdministrationFixture('lab-wra03','domain-admin-nonjoined'),inventory=model.workstationInventory;
  assert.equal(model.profile.clientJoined,false);assert.match(model.profile.prerequisites.join(' '),/KDC/);assert.match(model.profile.prerequisites.join(' '),/cifs\/target/);
  for(const key of ['tgt','tgt-key','cifs-ticket','ticket-key','initiator-subkey','session-key','signing-key','c2s-key','s2c-key'])assert.ok(inventory.artifacts.some(o=>o.key===key),key);
  const key=inventory.artifacts.find(o=>o.key==='session-key');assert.equal(key.creator,'smbServer');assert.match(key.value,/acceptor subkey/);
  assert.equal(remoteAt(model,'as-reply').serverAuthenticated,false);assert.equal(remoteAt(model,'session-success').clientSessionAccepted,false);assert.equal(remoteAt(model,'client-session').clientSessionAccepted,true);
});

test('Deny-only SID matches deny, never allow; masks and privilege presence are actual inputs',()=>{
  const model=buildWindowsRemoteAdministrationFixture('lab-wra04','deny-only-sid'),token=remoteEnd(model).token;
  assert.deepEqual(token.groups.find(g=>g.sid==='S-1-5-32-544').attributes,['deny-only']);
  assert.equal(evaluateWindowsRemoteAccess(token,1,[{type:'allow',sid:'S-1-5-32-544',mask:1}]).allowed,false);
  const deny=evaluateWindowsRemoteAccess(token,1,[{type:'deny',sid:'S-1-5-32-544',mask:1},{type:'allow',sid:token.userSid,mask:1}]);assert.equal(deny.deniedMask,1);
  assert.equal(evaluateWindowsRemoteAccess(token,1,[{type:'allow',sid:token.userSid,mask:2}]).allowed,false);assert.equal(evaluateWindowsRemoteAccess(token,1,[{type:'allow',sid:token.userSid,mask:1}]).allowed,true);
  assert.ok(token.removedPrivileges.includes('SeDebugPrivilege'));assert.equal(token.privileges.some(p=>p.name==='SeDebugPrivilege'),false);
  const full=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01','filter-disabled')).token;assert.deepEqual(full.privileges.find(p=>p.name==='SeDebugPrivilege'),{name:'SeDebugPrivilege',present:true,enabled:false});
});

test('RID500 classification follows SID/RID, not display name, and native fields stay unknown',()=>{
  const base=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra02','rid500-aam-off')),renamed=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra02','renamed-rid500'));
  assert.equal(base.token.userSid,renamed.token.userSid);assert.equal(base.token.mode,renamed.token.mode);assert.equal(remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra02','name-is-not-rid')).token.mode,'filtered');
  const unusual=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra02','rid500-filter-disabled')).token;assert.equal(unusual.mode,'full');assert.equal(unusual.elevatedNativeFlag,null);assert.equal(unusual.integritySid,null);
});

test('Reused session binds original policy while fresh comparison applies changed policy',()=>{
  const reused=buildWindowsRemoteAdministrationFixture('lab-wra01','reused-session'),fresh=reused.withSubfixture('fresh');
  const original=remoteAt(reused,'client-session'),changed=remoteAt(reused,'configured-policy-change');
  assert.equal(original.effectivePolicy.LocalAccountTokenFilterPolicy,0);assert.equal(changed.effectivePolicy.LocalAccountTokenFilterPolicy,1);assert.deepEqual(original.token,changed.token);
  assert.equal(remoteEnd(reused).token.mode,'filtered');assert.equal(remoteEnd(fresh).token.mode,'full');
  const changeIndex=reused.steps().findIndex(s=>s.smbStage==='configured-policy-change');assert.equal(reused.steps().slice(changeIndex+1).some(s=>['sam-verify','server-session'].includes(s.smbStage)),false);
  const failed=reused.withSubfixture('later-proof-denial'),prior=failed.initialState.workstation.priorSession;assert.ok(prior);assert.deepEqual(remoteEnd(failed).priorSession,prior);assert.equal(remoteEnd(failed).serverAuthenticated,false);
});

test('Signed denial uses established SigningKey/AES-CMAC and separates result boundaries',()=>{
  const model=buildWindowsRemoteAdministrationFixture('lab-wra04','signed-denial'),denial=model.steps().find(s=>s.smbStage==='tree-denied'),key=model.workstationInventory.artifacts.find(o=>o.key==='signing-key');
  assert.equal(denial.smbFrame.signed,true);assert.equal(denial.smbFrame.encrypted,false);assert.equal(denial.layers[0].keyRef,key.artifactId);assert.match(denial.layers[0].protection,/AES-CMAC/);
  assert.equal(remoteAt(model,'share-check').responseTransmitted,false);assert.equal(remoteAt(model,'tree-denied-transmit').responseReceived,false);assert.equal(remoteAt(model,'tree-denied').responseReceived,true);assert.equal(remoteAt(model,'tree-denied').clientKnowsResult,false);assert.equal(remoteAt(model,'tree-denied-accept').clientKnowsResult,true);
});

test('Encrypted error uses S2C key and nonce, never C2S or SigningKey as encryption key',()=>{
  const model=buildWindowsRemoteAdministrationFixture('lab-wra04','encrypted-denial'),denial=model.steps().find(s=>s.smbStage==='create-denied'),inventory=model.workstationInventory;
  const s2c=inventory.artifacts.find(o=>o.key==='s2c-key'),c2s=inventory.artifacts.find(o=>o.key==='c2s-key');
  assert.equal(denial.smbFrame.encrypted,true);assert.equal(denial.smbFrame.signed,false);assert.equal(denial.layers[0].keyRef,s2c.artifactId);assert.notEqual(denial.layers[0].keyRef,c2s.artifactId);
  const transform=inventory.artifacts.find(o=>o.key==='create-denied-transform');assert.match(transform.value,/S2C nonce12 #1/);assert.match(s2c.value,/SMBS2CCipherKey/);assert.match(c2s.value,/SMBC2SCipherKey/);
  assert.equal(remoteAt(model,'create-denied').clientKnowsResult,false);assert.equal(remoteAt(model,'create-denied-unwrap').clientKnowsResult,false);assert.equal(remoteAt(model,'create-denied-accept').clientKnowsResult,true);assert.equal(remoteEnd(model).treeConnected,true);
});

test('AP broad/list exceptions are target-admin qualified and unresolved cases do not fabricate denial',()=>{
  for(const name of ['broad-allow','user-sid-match','group-sid-match','broad-overrides-list'])assert.equal(remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra05',name)).token.mode,'full');
  for(const name of ['default-non-elevated','no-list-match'])assert.equal(remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra05',name)).token.mode,'non-elevated');
  const unresolved=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra05','nonadmin-listed'));assert.equal(unresolved.returnedResult,'needs-evidence');assert.equal(unresolved.resourceAllowed,null);assert.equal(unresolved.token,null);assert.equal(unresolved.credentialVerified,true);
  assert.equal(unresolved.admissionDecision,'needs-evidence');assert.notEqual(unresolved.admissionDecision,'denied');
  const unavailable=buildWindowsRemoteAdministrationFixture('lab-wra05','unavailable-profile');assert.equal(remoteEnd(unavailable).returnedResult,'unavailable-profile');assert.equal(unavailable.steps().some(s=>s.smbStage==='as-request'),false);assert.match(unavailable.profile.supportStatus,/26100\.9278/);
});

test('Local nonadmin source composition returns actual SAM/SMB histories, not CORP captions',()=>{
  const source=buildWindowsRemoteSmbReference({authority:'TARGET',admin:false,resource:'reports',shareRule:'allow-user',fileRule:'allow-user'});
  assert.ok(source.smbInventory);assert.ok(source.steps().some(s=>s.smbStage==='sam-verify'));assert.ok(source.steps().some(s=>s.smbStage==='read-accept'));assert.equal(source.steps().some(s=>s.smbStage==='dc-request'),false);assert.equal(source.initialState.smb.networkIdentity,'TARGET\\ops');
  assert.throws(()=>buildWindowsRemoteSmbReference({authority:'TARGET',mechanism:'Kerberos'}),RangeError);assert.throws(()=>buildWindowsRemoteSmbReference({enableLua:0}),RangeError);
});

test('WP0 frozen manifest/profile/source byte bindings remain independently checkable',()=>{
  const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
  assert.equal(hash(readFileSync(new URL('../docs/windows-protection-expansion/remote-cases.json',import.meta.url))),remoteSources.expectationSHA256);
  assert.equal(hash(readFileSync(new URL('../docs/windows-protection-expansion/profiles-remote.json',import.meta.url))),remoteSources.profileSHA256);
  for(const source of remoteSources.captures){assert.equal(source.httpStatus,200);const bytes=readFileSync(new URL('../'+source.localURL,import.meta.url));assert.equal(bytes.length,source.bytes);assert.equal(hash(bytes),source.contentSHA256);assert.ok(source.title);assert.ok(source.revision);assert.ok(source.retrievedAt);assert.ok(source.claims.length);assert.ok(source.affectedCases.length);}
});

test('Target comparison records SID filtering and removed versus disabled privileges without inventing a prior token',()=>{
  const filtered=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01')),comparison=filtered.tokenComparison;
  const admin=comparison.groups.find(row=>row.sid==='S-1-5-32-544');assert.deepEqual(admin.beforeAttributes,['enabled']);assert.deepEqual(admin.afterAttributes,['deny-only']);assert.equal(admin.directoryMembershipUnchanged,true);
  const debug=comparison.privileges.find(row=>row.name==='SeDebugPrivilege');assert.deepEqual(debug.before,{present:true,enabled:false,state:'disabled'});assert.deepEqual(debug.after,{present:false,enabled:null,state:'removed'});
  assert.equal(comparison.before.integrity,'unknown');assert.equal(comparison.after.integrity,'unknown');assert.equal(comparison.before.elevationType,'unknown');assert.equal(comparison.after.elevationType,'unknown');
  const fullDenied=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01','full-token-acl-denied'));assert.equal(fullDenied.resourceAllowed,false);assert.deepEqual(fullDenied.tokenComparison.groups.find(row=>row.sid==='S-1-5-32-544').afterAttributes,['enabled']);assert.equal(fullDenied.tokenComparison.privileges.find(row=>row.name==='SeDebugPrivilege').after.state,'disabled');
  const standard=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01','local-standard-user')).tokenComparison;assert.equal(standard.before.groups.some(group=>group.sid==='S-1-5-32-544'),false);assert.equal(standard.after.groups.some(group=>group.sid==='S-1-5-32-544'),false);
});

test('Verdict and comparison state appear only at actual decision boundaries, not initial false flags',()=>{
  for(const [modelId,caseId] of [['lab-wra01','bad-password'],['lab-wra04','network-logon-denied'],['lab-wra05','nonadmin-listed'],['lab-wra05','unavailable-profile']]){
    const model=buildWindowsRemoteAdministrationFixture(modelId,caseId),end=remoteEnd(model);assert.equal(remoteAt(model,'identity').verdictExplanation,null);assert.equal(end.tokenComparison,null);assert.equal(end.appliedPolicy,null);
    const detected=remoteAt(model,end.failureStage);assert.equal(typeof detected.verdictExplanation,'string');assert.ok(detected.verdictExplanation.length>0);assert.equal(end.verdictExplanation,detected.verdictExplanation);
    assert.equal(model.steps().some(step=>step.smbStage==='target-token-comparison'),false);
  }
  const success=buildWindowsRemoteAdministrationFixture('lab-wra01','ordinary-share-allowed');assert.equal(remoteAt(success,'client-session').verdictExplanation,null);assert.equal(remoteAt(success,'read-success').verdictExplanation,null);assert.equal(typeof remoteAt(success,'read-accept').verdictExplanation,'string');
});

test('Readable configured policy stays separate from the snapshot applied to a reused context',()=>{
  const model=buildWindowsRemoteAdministrationFixture('lab-wra01','reused-session'),before=remoteAt(model,'client-session'),after=remoteAt(model,'configured-policy-change');
  assert.equal(before.policyComparison.configured.effectiveLATFP,0);assert.equal(before.policyComparison.applied.effectiveLATFP,0);
  assert.equal(after.configuredPolicy.LocalAccountTokenFilterPolicy,1);assert.equal(after.appliedPolicy.LocalAccountTokenFilterPolicy,0);assert.equal(after.policyComparison.configured.applyRemoteRestrictions,false);assert.equal(after.policyComparison.applied.applyRemoteRestrictions,true);
  assert.deepEqual(after.tokenComparison,before.tokenComparison);assert.equal(after.tokenComparison.appliedPolicy.LocalAccountTokenFilterPolicy,0);
  const fresh=remoteEnd(model.withSubfixture('fresh'));assert.equal(fresh.policyComparison.configured.effectiveLATFP,1);assert.equal(fresh.policyComparison.applied.effectiveLATFP,1);
  const absent=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01')),zero=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra01','explicit-zero'));
  assert.equal(absent.policyComparison.configured.rawLATFP,null);assert.equal(zero.policyComparison.configured.rawLATFP,0);assert.equal(absent.policyComparison.configured.effectiveLATFP,zero.policyComparison.configured.effectiveLATFP);assert.equal(absent.policyComparison.applied.applyRemoteRestrictions,true);
  const unresolved=remoteEnd(buildWindowsRemoteAdministrationFixture('lab-wra05','nonadmin-listed'));assert.equal(unresolved.admissionDecision,'needs-evidence');assert.equal(unresolved.policyComparison.applied,null);assert.equal(unresolved.tokenComparison,null);assert.equal(unresolved.resourceAllowed,null);
});

test('Bounded applicability and endpoint outcomes are locally created comparisons, not cross-host result transfers',()=>{
  for(const [modelId,caseId,resultKey,resultStage,acceptStage] of [
    ['lab-wra05','unavailable-profile','comparison-result','applicability-result','applicability-accept'],
    ['lab-wra05','nonadmin-listed','comparison-result','applicability-result','applicability-accept'],
    ['lab-wra04','management-endpoint-denied','endpoint-local-result','endpoint-result-local','endpoint-result-accept']
  ]){
    const model=buildWindowsRemoteAdministrationFixture(modelId,caseId),inventory=model.workstationInventory,end=remoteEnd(model);
    assert.equal(model.initialState.workstation.localComparisonKnown,false);
    const result=inventory.artifacts.find(artifact=>artifact.key===resultKey);assert.ok(result);assert.equal(result.creator,'smbClient');assert.deepEqual(result.readers,['smbClient']);assert.equal(result.value.resultDomain,'local-lesson-comparison');assert.equal(typeof result.value.qualification,'string');assert.ok(result.value.qualification.length>0);
    const localCreate=model.steps().find(step=>step.smbStage===resultStage),localAccept=model.steps().find(step=>step.smbStage===acceptStage);
    assert.equal(localCreate.from,'smbClient');assert.equal(localCreate.to,'smbClient');assert.equal(localCreate.channel,'internal');assert.equal(localCreate.layers.length,0);assert.equal(localAccept.channel,'internal');
    const createIndex=model.steps().indexOf(localCreate),beforeCreate=reconstructProtocolState(model,createIndex-1).workstation;
    assert.equal(beforeCreate.localComparisonKnown,false);assert.equal(remoteAt(model,resultStage).localComparisonKnown,true);assert.equal(remoteAt(model,resultStage).clientKnowsResult,true);assert.equal(remoteAt(model,acceptStage).localComparisonKnown,true);
    assert.equal(localAccept.protocolEffects.some(effect=>['workstation.localComparisonKnown','workstation.clientKnowsResult','workstation.returnedResult'].includes(effect.path)),false);
    assert.equal(end.localComparisonKnown,true);assert.equal(end.resultDomain,'local-lesson-comparison');assert.equal(end.localComparisonQualification,result.value.qualification);assert.equal(end.clientKnowsResult,true);assert.equal(end.returnedResult,result.value.status);
    const createdEffects=remoteEffects(inventory.events[localCreate.id]);assert.ok(createdEffects.some(effect=>effect.op==='create'&&effect.artifactId===result.artifactId));assert.ok(createdEffects.some(effect=>effect.op==='acquire'&&effect.artifactId===result.artifactId&&effect.actorId==='smbClient'));
    for(const step of model.steps()){
      const event=inventory.events[step.id];assert.equal((event.messages||[]).some(message=>message.objects.some(object=>object.artifactId===result.artifactId)),false);
      for(const effect of remoteEffects(event))if(effect.op==='acquire'&&effect.actorId==='smbClient'){
        const artifact=inventory.artifacts.find(candidate=>candidate.artifactId===effect.artifactId);
        if(['endpoint-result','comparison-result','endpoint-local-result'].includes(artifact.key))assert.equal(artifact.creator,'smbClient');
      }
      if([resultStage,acceptStage].includes(step.smbStage))assert.equal(step.protocolEffects.some(effect=>['workstation.responseTransmitted','workstation.responseReceived'].includes(effect.path)),false);
    }
    assert.equal(model.steps().some(step=>['applicability-transmit','applicability-receipt','endpoint-result-transfer'].includes(step.smbStage)),false);
    assert.equal(end.responseTransmitted,false);assert.equal(end.responseReceived,false);
    if(caseId==='management-endpoint-denied'){
      const accepted=remoteAt(model,'client-session');assert.equal(accepted.serverAuthenticated,true);assert.equal(accepted.clientSessionAccepted,true);assert.equal(end.serverAuthenticated,true);assert.equal(end.clientSessionAccepted,true);assert.deepEqual(end.token,accepted.token);
      assert.equal(inventory.artifacts.find(artifact=>artifact.key==='endpoint-result').readers.includes('smbClient'),false);
    }else{assert.equal(end.token,null);assert.equal(end.serverAuthenticated,false);}
  }
});

test('Real protected SMB operation responses retain their wire facts and are not relabeled local comparisons',()=>{
  for(const caseId of ['signed-denial','encrypted-denial']){
    const model=buildWindowsRemoteAdministrationFixture('lab-wra04',caseId),end=remoteEnd(model);
    assert.equal(end.responseTransmitted,true);assert.equal(end.responseReceived,true);assert.equal(end.localComparisonKnown,false);assert.equal(end.resultDomain,'SMB/NTSTATUS');assert.equal(end.localComparisonQualification,null);
    const acceptStage=caseId==='signed-denial'?'tree-denied-accept':'create-denied-accept';assert.equal(remoteAt(model,acceptStage).clientKnowsResult,true);
  }
});

for(const [modelId,caseId,subfixtureId,stage,bindingPath,artifactKey,owner] of [
  ['lab-wra01','reused-session','reused','configured-policy-change','workstation.priorSession','reused-session-record','smbServer'],
  ['lab-wra04','management-endpoint-denied','default','endpoint-result-local','workstation.localComparisonKnown','endpoint-local-result','smbClient'],
  ['lab-wra05','nonadmin-listed','default','applicability-result','workstation.localComparisonKnown','comparison-result','smbClient'],
  ['lab-wra05','unavailable-profile','default','applicability-result','workstation.localComparisonKnown','comparison-result','smbClient']
]){
  test(modelId+'/'+caseId+'/'+subfixtureId+' compiles held bindings and complete coverage at every source prefix',()=>{
    const model=buildWindowsRemoteAdministrationFixture(modelId,caseId,subfixtureId),steps=model.steps();
    const compiled=buildHeldObjects({model,steps,actors:model.actors(),config:{},contextId:'wra-binding-regression:'+modelId+':'+caseId+':'+subfixtureId,choiceId:model.id});
    assert.equal(assertHeldObjectCoverage(compiled),true);
    const artifact=model.workstationInventory.artifacts.find(candidate=>candidate.key===artifactKey),binding=compiled.plan.bindings.find(candidate=>candidate.path===bindingPath&&candidate.artifactId===artifact.artifactId);
    assert.ok(binding);assert.equal(binding.actorId,owner);
    for(const cursor of compiled.cursors){
      const snapshot=projectHeldObjects(compiled,cursor),value=bindingPath.split('.').reduce((current,key)=>current?.[key],snapshot.state);
      const held=snapshot.holdings.some(holding=>holding.artifactId===binding.artifactId&&holding.actorId===binding.actorId&&holding.representationId===binding.representationId&&holding.store===binding.store);
      assert.equal(Boolean(value),held,'binding at '+cursor.eventIndex+'/'+cursor.milestone);
      assert.equal(snapshot.coverageStatus,'complete');
    }
    const index=steps.findIndex(step=>step.smbStage===stage),before=projectHeldObjects(compiled,{eventIndex:index,milestone:'before'}),after=projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});
    assert.equal(before.holdings.some(holding=>holding.artifactId===artifact.artifactId),false);
    assert.ok(after.holdings.some(holding=>holding.artifactId===artifact.artifactId&&holding.actorId===owner));
    if(artifactKey==='reused-session-record'){
      assert.equal(before.state.workstation.priorSession,null);assert.deepEqual(after.state.workstation.priorSession,artifact.value);
      assert.ok(before.holdings.some(holding=>holding.artifactId===artifact.value.sessionContextRef&&holding.actorId==='smbServer'));
      assert.ok(after.holdings.some(holding=>holding.artifactId===artifact.value.tokenRef&&holding.actorId==='smbServer'));
      assert.equal(after.state.workstation.appliedPolicy.LocalAccountTokenFilterPolicy,0);assert.equal(after.state.workstation.configuredPolicy.LocalAccountTokenFilterPolicy,1);
    }else{
      assert.equal(before.state.workstation.localComparisonKnown,false);assert.equal(after.state.workstation.localComparisonKnown,true);assert.equal(after.state.workstation.clientKnowsResult,true);assert.equal(after.state.workstation.resultDomain,'local-lesson-comparison');
      const inspectStage=stage==='applicability-result'?'applicability-accept':'endpoint-result-accept',inspect=steps.findIndex(step=>step.smbStage===inspectStage),inspected=projectHeldObjects(compiled,{eventIndex:inspect,milestone:'complete'});
      assert.equal(inspected.state.workstation.localComparisonKnown,true);assert.equal(inspected.state.workstation.responseTransmitted,after.state.workstation.responseTransmitted);assert.equal(inspected.state.workstation.responseReceived,after.state.workstation.responseReceived);
    }
  });
}
