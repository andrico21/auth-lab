import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { WINDOWSPROTECTIONLAB_SCENARIOS, WINDOWSPROTECTIONLAB_ATTRIBUTES, WINDOWSPROTECTIONLAB_SUBFIXTURES, buildWindowsProtectionFixture, buildWindowsProtectionSubfixture } from '../src/windows-protection-lab.js';
import { buildWindowsLogonFixture } from '../src/windows-logon-lab.js';
import { reconstructProtocolState } from '../src/protocol-state.js';
import { buildHeldObjects } from '../src/held-objects.js';
import { assertHeldObjectCoverage, projectHeldObjects, inspectHeldObject } from '../src/held-object-state.js';

// This literal manifest was authored and hashed before the production module.
// Tests never import a production expected-answer function.
const wpExpectedBytes=readFileSync(new URL('../docs/windows-protection-expansion/protection-cases.json',import.meta.url));
const wpExpected=JSON.parse(wpExpectedBytes);
const wpProfiles=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/profiles-protection.json',import.meta.url)));
const wpMapping=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/protection-protocol-mapping.json',import.meta.url)));
const wpEnd=model=>reconstructProtocolState(model,model.steps().length-1).workstation;
const wpAt=(model,stage)=>{const index=model.steps().findIndex(step=>step.workstationStage===stage);assert.ok(index>=0,'Missing stage '+stage);return reconstructProtocolState(model,index).workstation;};
const wpModelCache=new Map();
const wpModel=row=>{if(!wpModelCache.has(row.id))wpModelCache.set(row.id,buildWindowsProtectionFixture(row.modelId,row.variantId));return wpModelCache.get(row.id);};
const wpLive=model=>{
 const live=new Map();
 const apply=effect=>{if(effect.op==='acquire')live.set(effect.holdingId,{...effect});else if(effect.op==='release')live.delete(effect.holdingId);else if(effect.op==='move'&&live.has(effect.holdingId))live.set(effect.holdingId,{...live.get(effect.holdingId),...effect,op:'acquire'});};
 model.workstationInventory.initial.forEach(apply);
 for(const step of model.steps())for(const milestone of model.workstationInventory.events[step.id].milestones)milestone.effects.forEach(apply);
 return [...live.values()];
};
const wpCheckpoint=(row,model)=>{
 const aliases={'protected-tgt-operation':'host-tgs-operation','normal-tgt-operation':'host-tgs-operation','host-ticket-accept':'host-tgs-accept'};
 const stage=wpMapping.checkpointBindings[row.id]?.stage||(row.id==='WPROT01/authority-still-usable'?'resource-authority-check':row.id.startsWith('WPROT04/')&&row.firstDetector.stage==='policy-selection'?'account-policy-selection':aliases[row.firstDetector.stage]||row.firstDetector.stage);
 return model.steps().find(step=>step.workstationStage===stage);
};

test('Protection independent source-only manifest remains frozen at 50 canonical cases and 11 explicit subfixtures',()=>{
 assert.equal(createHash('sha256').update(wpExpectedBytes).digest('hex'),'bec1d0447d4aeccd5c2d730c517c4f9b32b48e0a7789b9540c6f514f223a3672');
 assert.equal(wpExpected.authoredBeforeProduction,true);assert.equal(wpExpected.cases.length,50);assert.equal(wpExpected.subfixtures.length,11);
 assert.equal(wpProfiles.profiles.length,50);assert.equal(WINDOWSPROTECTIONLAB_SCENARIOS.length,5);
 assert.equal(new Set(wpExpected.cases.map(row=>row.id)).size,50);
 assert.deepEqual(WINDOWSPROTECTIONLAB_SUBFIXTURES.map(row=>row.id).sort(),wpExpected.subfixtures.map(row=>row.id).sort());
});

for(const row of wpExpected.cases)test(row.id+' matches independently authored outcome, detector and cleanup',()=>{
 const model=wpModel(row),state=wpEnd(model),profile=wpProfiles.profiles.find(entry=>entry.id===row.profileId);
 assert.equal(model.variantId,row.variantId);assert.equal(model.canonicalCaseId,row.id);assert.equal(model.profileId,row.profileId);assert.ok(profile);
 assert.ok(Object.isFrozen(model.fixtureInputs));assert.ok(Object.isFrozen(model.platformProfile));
 for(const [field,value] of Object.entries(row.expected))assert.deepEqual(state[field],value,row.id+' / '+field);
 const detector=wpCheckpoint(row,model);assert.ok(detector,row.id+' detector checkpoint');assert.equal(detector.from,wpMapping.checkpointBindings[row.id]?.actor||row.firstDetector.actor,row.id+' source-bound detector actor');
 assert.ok(model.workstationInventory.artifacts.length);assert.ok(model.steps().every(step=>model.workstationInventory.events[step.id]));
 assert.equal(wpLive(model).some(holding=>holding.retention==='temporary'),false,'No attempt scratch survives');
 assert.ok(model.decisionBindings.some(binding=>binding.path==='workstation.resultCode'));
 assert.ok(model.decisionBindings.some(binding=>binding.path==='workstation.clientKnowsResult'));
 if(row.modelId==='lab-wprot05')for(const field of ['policyAllowed','resourceAllowed'])assert.ok(model.decisionBindings.some(binding=>binding.path==='workstation.'+field));
 assert.equal(state.clientKnowsResult,true);
});

for(const row of wpExpected.subfixtures)test(row.id+' executes its independently authored comparison member',()=>{
 const model=buildWindowsProtectionSubfixture(row.id),state=wpEnd(model);
 assert.equal(model.canonicalCaseId,row.caseId);assert.equal(model.subfixtureId,row.id);
 assert.ok(model.subfixtureChoices.some(choice=>choice.id===row.id));
 for(const [field,value] of Object.entries(row.expected))assert.deepEqual(state[field],value,row.id+' / '+field);
 assert.deepEqual(wpEnd(model.withSubfixture(row.id)),state);
 assert.throws(()=>model.withSubfixture('unlisted-comparison'),RangeError);
 if(row.caseId!=='WPROT01/credential-manager-types')assert.throws(()=>model.withSubfixture('WPROT01/credential-manager-types/generic'),RangeError);
});

test('Canonical defaults are aliases, never extra selectable cases; old models are unaffected',()=>{
 for(const descriptor of WINDOWSPROTECTIONLAB_SCENARIOS){
  const rows=wpExpected.cases.filter(row=>row.modelId===descriptor.id);
  assert.deepEqual(descriptor.variantChoices.map(choice=>choice.id),rows.map(row=>row.variantId));
  assert.equal(descriptor.defaultVariantId,rows[0].variantId);assert.equal(descriptor.withVariant('default').variantId,rows[0].variantId);
  assert.throws(()=>descriptor.withVariant('unknown'),RangeError);
 }
 assert.throws(()=>buildWindowsProtectionFixture('missing'),RangeError);
 assert.throws(()=>buildWindowsProtectionSubfixture('missing'),RangeError);
 const old=buildWindowsLogonFixture('lab-wlog02');assert.equal(wpEnd(old).credentialVerified,true);assert.equal(wpEnd(old).hostTicketAccepted,true);
 assert.equal(old.steps().some(step=>step.workstationStage==='as-proof-check'),false);
 assert.equal(old.steps().some(step=>step.workstationStage==='compound-request-protect'),false);
});

test('Full static field metadata covers every actual case without constructing other variants',()=>{
 for(const descriptor of WINDOWSPROTECTIONLAB_SCENARIOS){
  const schema=new Set(descriptor.catalogAttributeIds),definitions=descriptor.definitions();
  assert.ok(schema.size);for(const id of schema){assert.ok(WINDOWSPROTECTIONLAB_ATTRIBUTES[id],id);assert.ok(definitions[id],id);}
  for(const row of wpExpected.cases.filter(row=>row.modelId===descriptor.id))for(const field of wpModel(row).ids)assert.ok(schema.has(field),row.id+' missing '+field);
 }
});

test('Every canonical message has sender possession before transfer; all actors have explicit positions',()=>{
 for(const row of wpExpected.cases){
  const model=wpModel(row),inventory=model.workstationInventory,actors=model.actors(),live=new Map();
  const apply=effect=>{if(effect.op==='acquire')live.set(effect.holdingId,effect);else if(effect.op==='release')live.delete(effect.holdingId);else if(effect.op==='move'&&live.has(effect.holdingId))live.set(effect.holdingId,{...live.get(effect.holdingId),...effect});};
  inventory.initial.forEach(apply);
  for(const step of model.steps()){
   assert.ok(Number.isFinite(actors[step.from]?.position?.x),row.id+' '+step.from);assert.ok(Number.isFinite(actors[step.to]?.position?.y),row.id+' '+step.to);
   const event=inventory.events[step.id];
   for(const message of event.messages||[])for(const object of message.objects)assert.ok([...live.values()].some(holding=>holding.actorId===message.from&&holding.artifactId===object.artifactId&&holding.representationId===object.representationId),row.id+' '+step.id+' unauthored sender '+message.from+' '+object.artifactId+' '+object.representationId);
   for(const milestone of event.milestones)milestone.effects.forEach(apply);
  }
 }
});

test('CG active versus off changes key custody and actual operation owner, not resource permission',()=>{
 const active=buildWindowsProtectionFixture('lab-wprot01','running-kerberos'),off=active.withVariant('disabled-comparison'),notRunning=active.withVariant('configured-not-running');
 for(const [model,owner] of [[active,'wslIso'],[off,'wslLSA'],[notRunning,'wslLSA']]){
  const key=model.workstationInventory.artifacts.find(object=>object.key==='tgt-session-key');
  assert.deepEqual(key.readers,['wslDC',owner]);
  const operation=model.steps().find(step=>step.workstationStage==='host-tgs-operation');assert.equal(operation.from,owner);
  assert.equal(wpEnd(model).resourceAllowed,true);
  for(const event of Object.values(model.workstationInventory.events))for(const message of event.messages||[])assert.equal(message.objects.some(object=>object.artifactId===key.artifactId),false,'No raw TGT-key transfer');
 }
 const service=active.workstationInventory.artifacts.find(object=>object.key==='host-session-key');
 assert.ok(wpLive(active).some(holding=>holding.artifactId===service.artifactId&&holding.actorId==='wslLSA'));
 assert.equal(service.readers.includes('wslIso'),false);
 assert.equal(off.initialState.workstation.effectivePolicy.credentialGuard.configured,false);
 assert.equal(notRunning.initialState.workstation.effectivePolicy.credentialGuard.configured,true);
 assert.equal(notRunning.initialState.workstation.effectivePolicy.credentialGuard.running,false);
 assert.ok(Array.isArray(active.initialState.workstation.effectivePolicy.credentialGuard.securityServicesRunning));
});

test('Signed-in NTLMv2 uses the exact accepted challenge in isolated custody; prompted input remains a different source',()=>{
 const signed=buildWindowsProtectionFixture('lab-wprot01','ntlmv2-operation'),prompted=signed.withVariant('explicit-prompted-input');
 assert.ok(signed.workstationInventory.reuse.some(record=>record.sourceId==='lab-smb-nonjoined-ntlm'));
 for(const key of ['credential','nt-hash','response-key']){
  const object=signed.workstationInventory.artifacts.find(entry=>entry.artifactId===signed.id+':smb:'+key);
  assert.equal(object.creator,'wslIso');assert.deepEqual(object.readers,['wslIso']);
  assert.equal(wpLive(signed).some(holding=>holding.artifactId===object.artifactId&&holding.actorId!=='wslIso'),false);
 }
 assert.equal(signed.steps().find(step=>step.workstationStage==='ntlm-operation-compute').from,'wslIso');
 assert.equal(signed.steps().find(step=>step.workstationStage==='smb:ntlm-derive').from,'wslNetwork');
 for(const key of ['session-key','ntlm-authenticate'])assert.equal(signed.workstationInventory.artifacts.find(object=>object.artifactId===signed.id+':smb:'+key).creator,'wslNetwork');
 assert.ok(signed.steps().some(step=>step.workstationStage==='ntlm-operation-request'));
 assert.ok(signed.steps().some(step=>step.workstationStage==='ntlm-operation-return'));
 assert.equal(prompted.steps().some(step=>step.workstationStage==='ntlm-operation-request'),false);
 assert.equal(wpEnd(prompted).promptedInputProtected,false);
 const pu=buildWindowsProtectionFixture('lab-wprot03','ntlm-denied');
 assert.equal(wpAt(pu,'ntlm-policy').credentialVerified,false);assert.equal(wpAt(pu,'ntlm-policy').clientKnowsResult,false);
 assert.ok(pu.steps().some(step=>step.workstationStage==='smb:dc-request'));
 assert.equal(pu.steps().some(step=>step.workstationStage==='smb:session-success'),false);
 assert.ok(pu.steps().some(step=>step.workstationStage==='pu-ntlm-client-process'));
});

test('NTLM attempt cleanup releases exact imported holding IDs at their owners while preserving accepted authority',()=>{
 const fixtures=[
  {model:buildWindowsProtectionFixture('lab-wprot01','explicit-prompted-input'),scratch:['credential','nt-hash','response-key','client-base-key'],accepted:true},
  {model:buildWindowsProtectionFixture('lab-wprot01','ntlmv2-operation'),scratch:['nt-hash','response-key','ntlm-proof','client-base-key','ntlm-authenticate'],accepted:true},
  {model:buildWindowsProtectionFixture('lab-wprot03','ntlm-denied'),scratch:['credential','nt-hash','response-key','client-base-key','session-key'],accepted:false}
 ];
 for(const {model,scratch,accepted} of fixtures){
  const inventory=model.workstationInventory,live=new Map(),released=new Set(),apply=effect=>{if(effect.op==='acquire')live.set(effect.holdingId,{...effect});else if(effect.op==='release')live.delete(effect.holdingId);else if(effect.op==='move'&&live.has(effect.holdingId))live.set(effect.holdingId,{...live.get(effect.holdingId),...effect,op:'acquire'});};
  inventory.initial.forEach(apply);
  for(const step of model.steps()){
   const ownerCleanup=step.workstationStage.startsWith('source-attempt-cleanup-');
   if(ownerCleanup){assert.equal(step.from,step.to);assert.equal(step.layers.length,0);assert.ok(step.attributeOperations.every(op=>op.actorId===step.from));}
   for(const milestone of inventory.events[step.id].milestones)for(const effect of milestone.effects){
    if(ownerCleanup&&effect.op==='release'){const prior=live.get(effect.holdingId);assert.ok(prior,'Release the exact live source identity');assert.equal(prior.actorId,step.from);assert.equal(prior.retention,'temporary');released.add(prior.artifactId);}
    apply(effect);
   }
  }
  for(const key of scratch){const id=model.id+':smb:'+key;assert.ok(released.has(id),model.canonicalCaseId+' '+key+' has an authored owner-local release');assert.equal([...live.values()].some(holding=>holding.artifactId===id),false);}
  for(const key of ['desktop','account-verifier','netlogon-channel'])assert.ok([...live.values()].some(holding=>holding.artifactId===model.id+':smb:'+key),'Preserve source '+key);
  assert.equal([...live.values()].some(holding=>holding.artifactId===model.id+':smb:session-key'&&holding.actorId==='wslNetwork'),accepted);
  if(model.variantId==='ntlmv2-operation')assert.ok([...live.values()].some(holding=>holding.artifactId===model.id+':smb:credential'&&holding.actorId==='wslIso'),'Retain only the protected sign-in source, not operation scratch');
 }
});

test('Protection canonical held compiler validates distinct NTLM, FAST AS and typed compound TGS prefixes',()=>{
 const affectedAs=new Set(['allowed-device','device-denied-audit','device-denied-enforce','forged-device-label','direct-policy']);
 const models=wpExpected.cases.filter(row=>row.modelId==='lab-wprot05'||row.modelId==='lab-wprot04'&&affectedAs.has(row.variantId)||row.id==='WPROT01/ntlmv2-operation').map(wpModel);
 models.push(...['user','managed-service','computer'].map(member=>buildWindowsProtectionSubfixture('WPROT05/account-type-selection/'+member)));
 for(const model of models){
  const steps=model.steps(),compiled=buildHeldObjects({model,steps,actors:model.actors(),config:{},contextId:'protection-regression:'+model.canonicalCaseId+':'+(model.subfixtureId||'canonical'),choiceId:model.id});
  assertHeldObjectCoverage(compiled);
  const eventIds=new Set(steps.map(step=>step.id));
  for(const step of steps)for(const op of step.attributeOperations||[]){
   assert.ok(eventIds.has(op.sourceEventId),model.canonicalCaseId+' occurrence '+op.sourceEventId);
  }
  const initial=projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'});
  for(let index=-1;index<steps.length;index++){
   const frame=projectHeldObjects(compiled,{eventIndex:index,milestone:index<0?'initial':'complete'});
   assert.equal(frame.coverageStatus,'complete');assert.deepEqual(frame.state,reconstructProtocolState(model,index));
   for(const holding of frame.holdings)assert.ok(['retained','temporary'].includes(holding.retention),'Explicit source holding lifetime');
  }
  assert.deepEqual(projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}),initial);
  if(model.id==='lab-wprot01'){
   const index=steps.findIndex(step=>step.workstationStage==='ntlm-operation-request'),frame=projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});
   const challenge=frame.holdings.find(holding=>holding.actorId==='wslIso'&&holding.artifactId===model.id+':smb:ntlm-challenge');
   assert.ok(challenge);assert.equal(challenge.retention,'temporary');assert.ok(inspectHeldObject(frame,challenge.holdingId).fields.every(field=>field.readable));
   assert.equal(frame.holdings.some(holding=>holding.actorId==='wslIso'&&holding.artifactId===model.id+':smb:ntlm-negotiate'),false);
  }
  const pac=model.workstationInventory.artifacts.find(artifact=>artifact.key==='computer-armor-pac');
  if(pac){
   assert.equal(model.workstationInventory.initial.some(effect=>effect.artifactId===pac.artifactId),false);
   const armorIndex=steps.findIndex(step=>step.workstationStage==='compound-kdc-armor'),factsIndex=steps.findIndex(step=>step.workstationStage==='compound-kdc-device-facts'),policyIndex=steps.findIndex(step=>['tgs-policy','tgs-context'].includes(step.workstationStage));
   assert.ok(armorIndex>=0&&armorIndex<factsIndex&&factsIndex<policyIndex);
   assert.equal(projectHeldObjects(compiled,{eventIndex:armorIndex,milestone:'complete'}).holdings.some(holding=>holding.artifactId===pac.artifactId),false);
   assert.equal(projectHeldObjects(compiled,{eventIndex:factsIndex,milestone:'complete'}).holdings.filter(holding=>holding.artifactId===pac.artifactId&&holding.actorId==='wslDC').length,1);
   const subkeyId=model.id+':host-reply-subkey',acquires=Object.values(model.workstationInventory.events).flatMap(event=>event.milestones.flatMap(milestone=>milestone.effects)).filter(effect=>effect.op==='acquire'&&effect.actorId==='wslDC'&&effect.artifactId===subkeyId);
   assert.equal(acquires.length,1,'Compound proof decoding installs its user subkey exactly once');
  }
 }
});

test('The local SAM comparison uses actual SAM proof/key/result processing and no domain grant',()=>{
 const model=buildWindowsProtectionFixture('lab-wprot01','local-account');
 assert.ok(model.steps().some(step=>step.workstationStage==='smb:sam-verify'&&step.from==='wslSAM'));
 assert.equal(model.steps().some(step=>step.workstationStage==='smb:dc-request'),false);
 assert.equal(model.steps().some(step=>step.workstationStage==='as'),false);
 assert.equal(wpEnd(model).tgtAccepted,false);assert.equal(wpEnd(model).isolationActive,false);
});

test('PPL audit/enforcement uses signing-level and shared-section metadata independently of CG',()=>{
 const audit=buildWindowsProtectionFixture('lab-wprot02','audit-plugin'),enforce=audit.withVariant('enforce-plugin');
 const am=audit.workstationInventory.artifacts.find(object=>object.key==='plugin-metadata').value,em=enforce.workstationInventory.artifacts.find(object=>object.key==='plugin-metadata').value;
 assert.equal(am.actualSigningLevel,em.actualSigningLevel);assert.equal(am.sharedSections,true);assert.equal(em.sharedSections,true);
 assert.equal(Object.hasOwn(am,'isSigned'),false);assert.equal(wpEnd(audit).pluginLoaded,true);assert.equal(wpEnd(enforce).pluginLoaded,false);
 assert.equal(wpEnd(audit).isolationActive,false);assert.equal(wpEnd(enforce).isolationActive,false);
 assert.equal(wpEnd(enforce.withVariant('unaffected-authentication')).credentialVerified,true);
});

test('PU ticket renewal boundary, retained local session and fresh lineage are independent',()=>{
 const expired=buildWindowsProtectionFixture('lab-wprot03','lifetime-expired'),fresh=expired.withVariant('fresh-authentication');
 assert.equal(wpEnd(expired).localSessionRetained,true);assert.equal(wpEnd(expired).newCredentialLineage,false);assert.equal(wpEnd(expired).tgtAccepted,false);
 assert.equal(wpEnd(fresh).localSessionRetained,true);assert.equal(wpEnd(fresh).newCredentialLineage,true);
 assert.ok(fresh.workstationInventory.artifacts.some(object=>object.key==='old-ticket-lineage'));
 assert.ok(fresh.workstationInventory.artifacts.some(object=>object.key==='tgt'));
 assert.equal(fresh.fixtureInputs.explicitAuthenticationPolicy,false);
 for(const variant of ['rc4-preauth-denied','des-preauth-denied']){const model=expired.withVariant(variant);assert.equal(wpEnd(model).tgtAccepted,false);assert.equal(model.steps().some(step=>step.workstationStage==='as-accept'),false);}
});

test('FAST AS policy gates occur after real user proof and before issuance; protected errors precede caller knowledge',()=>{
 const success=buildWindowsProtectionFixture('lab-wprot04','allowed-device'),denied=success.withVariant('device-denied-enforce');
 const index=(model,stage)=>model.steps().findIndex(step=>step.workstationStage===stage);
 assert.ok(index(success,'ad:user-check')<index(success,'as-policy'));
 assert.ok(index(success,'as-policy')<index(success,'ad:protect-response'));
 assert.equal(wpAt(success,'ad:fast-response').tgtAccepted,false);
 assert.equal(wpEnd(success).tgtAccepted,true);
 assert.equal(index(denied,'ad:protect-response'),-1);
 assert.ok(index(denied,'ad:error-result')<index(denied,'ad:decode-error'));
 assert.equal(wpAt(denied,'ad:error-result').clientKnowsResult,false);
 assert.equal(wpEnd(denied).clientPolicyErrorAccepted,true);
 assert.equal(wpEnd(denied).machineAccepted,true);
 const lifetime=success.withVariant('policy-lifetime');
 assert.equal(lifetime.steps().some(step=>step.workstationStage==='ad:fast-request'),false);
 assert.equal(wpEnd(lifetime).ticketEndMinutes,90);assert.equal(wpEnd(lifetime).ticketRenewMinutes,90);
 assert.equal(lifetime.fixtureInputs.protectedUser,false);
});

test('Target-service TGS policy, explicit compound armor and independent ACL gates retain their direction',()=>{
 const model=buildWindowsProtectionFixture('lab-wprot05','allowed-service'),denied=model.withVariant('target-rule-enforce'),acl=model.withVariant('ticket-then-acl-denial');
 const policy=model.workstationInventory.artifacts.find(object=>object.key==='target-policy').value;
 assert.equal(policy.account,'CORP\\PROTECTED$');assert.ok(policy.allowedTo.requiredUser);assert.equal(policy.source,'silo');
 const armor=model.workstationInventory.artifacts.find(object=>object.key==='compound-armor-key').value;
 assert.ok(armor.derivation.includes('" explicitarmor"'));assert.ok(armor.derivation.includes('" tgsarmor"'));
 const request=model.workstationInventory.artifacts.find(object=>object.key==='compound-fast-request').value;
 assert.ok(request.reqChecksum.includes('outer PA-TGS-REQ AP-REQ'));
 assert.ok(model.steps().some(step=>step.workstationStage==='compound-client-strengthen'));
 assert.equal(wpEnd(denied).hostTicketAccepted,false);assert.equal(wpEnd(denied).clientPolicyErrorAccepted,true);
 assert.equal(denied.steps().some(step=>step.workstationStage==='host-ticket'),false);
 assert.equal(wpAt(denied,'compound-error-response').clientKnowsResult,false);
 assert.equal(wpEnd(acl).hostTicketAccepted,true);assert.equal(wpEnd(acl).networkAuthenticated,true);assert.equal(wpEnd(acl).resourceAllowed,false);
 assert.equal(model.steps().some(step=>step.workstationStage==='local-ticket-submit'),false);
 const ap=model.steps().find(step=>step.workstationStage==='host-ap-request');assert.equal(ap.from,'wslLSA');assert.equal(ap.to,'wslFile');assert.equal(ap.layers[0].transport,'declared service application channel');
 assert.ok(model.steps().findIndex(step=>step.workstationStage==='host-mutual-accept')<model.steps().findIndex(step=>step.workstationStage==='host-operation'));
 const aclIndex=acl.steps().findIndex(step=>step.workstationStage==='resource-check'),replyIndex=acl.steps().findIndex(step=>step.workstationStage==='host-operation-result-check');
 assert.ok(aclIndex<replyIndex);assert.equal(reconstructProtocolState(acl,aclIndex).workstation.clientKnowsResult,false);
 assert.equal(acl.workstationInventory.artifacts.find(object=>object.key==='host-service-context').creator,'wslFile');
 const directory=model.workstationInventory.artifacts.find(object=>object.key==='target-directory-record').value,silo=model.workstationInventory.artifacts.find(object=>object.key==='target-silo-record').value;
 assert.equal(directory.assignedSilo,silo.siloId);assert.ok(silo.memberSids.includes(directory.sid));assert.deepEqual(directory.servicePrincipals,['host/protected.corp.example']);
 assert.equal(policy.enforcementRecordRef,model.workstationInventory.artifacts.find(object=>object.key==='target-silo-record').artifactId);
});

test('KCD and RBCD use service-owned S4U2proxy credentials, distinct backend AP proof and completed acceptor-key context',()=>{
 for(const suffix of ['kcd','rbcd']){
  const model=buildWindowsProtectionSubfixture('WPROT01/constrained-continuation/'+suffix),objects=model.workstationInventory.artifacts;
  const request=objects.find(object=>object.key==='s4u-request').value;
  assert.equal(request.cnameInAdditionalTicket,true);assert.ok(request.additionalTicketRef.endsWith(':host-ticket'));
  assert.ok(request.serviceTgtRef.endsWith(':s4u-service-tgt'));assert.equal(wpEnd(model).delegatedCredential,false);
  assert.equal(wpEnd(model).delegationAllowed,true);assert.equal(wpEnd(model).resourceAllowed,true);
  const ap=objects.find(object=>object.key==='s4u-ap-request'),proof=objects.find(object=>object.key==='s4u-authenticator');assert.notEqual(ap.artifactId,proof.artifactId);
  const initiator=objects.find(object=>object.key==='s4u-initiator-subkey'),acceptor=objects.find(object=>object.key==='s4u-acceptor-subkey');assert.notEqual(initiator.artifactId,acceptor.artifactId);
  assert.ok(model.steps().findIndex(step=>step.workstationStage==='s4u-mutual-accept')<model.steps().findIndex(step=>step.workstationStage==='s4u-operation'));
 }
 const pu=buildWindowsProtectionFixture('lab-wprot03','constrained-denied');assert.equal(wpEnd(pu).delegationAllowed,false);assert.equal(pu.steps().some(step=>step.workstationStage==='delegation-issue'),false);
});

test('Each case reconstructs deterministically at every prefix, preserves initial state and rejects cross-case subfixtures',()=>{
 for(const row of wpExpected.cases){
  const model=wpModel(row),initial=structuredClone(model.initialState);
  for(let index=-1;index<model.steps().length;index++)assert.deepEqual(reconstructProtocolState(model,index),reconstructProtocolState(model,index));
  assert.deepEqual(model.initialState,initial);
  assert.equal(new Set(model.steps().map(step=>step.id)).size,model.steps().length,row.id+' duplicate event IDs');
  assert.equal(new Set(model.workstationInventory.artifacts.map(object=>object.artifactId)).size,model.workstationInventory.artifacts.length,row.id+' duplicate object IDs');
 }
});

test('Pinned primary captures bind exact bytes; metadata distinguishes source claims from native observation',()=>{
 assert.equal(wpMapping.captures.length,32);
 for(const capture of wpMapping.captures){
  assert.equal(capture.status,200,capture.id);assert.ok(capture.retrievedAt);assert.ok(capture.finalURL);assert.ok(capture.title);assert.ok(capture.revision.length);
  const bytes=readFileSync(new URL('../'+capture.snapshot,import.meta.url));assert.equal(createHash('sha256').update(bytes).digest('hex'),capture.contentSHA256,capture.id);
 }
 assert.equal(wpMapping.independence.expectedSHA256,'bec1d0447d4aeccd5c2d730c517c4f9b32b48e0a7789b9540c6f514f223a3672');
 assert.ok(wpMapping.nativeLimits.some(line=>line.includes('unperformed')));
});
