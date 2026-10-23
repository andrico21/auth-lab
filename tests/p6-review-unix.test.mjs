import test from 'node:test';
import assert from 'node:assert/strict';
import {LINUXLOGONLAB_SCENARIOS} from '../src/linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS,createLinuxLSMCase} from '../src/linux-elevation-lab.js';
import {MACOSLOGONLAB_SCENARIOS,createMacPlatformSSOCase} from '../src/macos-logon-lab.js';
import {MACOSELEVLAB_SCENARIOS,createMacSudoCase} from '../src/macos-elevation-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildUnixWorkstationHeldObjects} from '../src/held-object-unix-workstation.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

const select=(models,id,variant='default')=>models.find(model=>model.id===id).withVariant(variant);
const has=(frame,key,actor,representation='plain')=>frame.holdings.some(h=>h.artifactId.endsWith(':'+key)&&h.actorId===actor&&h.representationId===representation);
function inspect(model){
  const steps=model.steps(),plan=compileHeldObjects(buildUnixWorkstationHeldObjects({model,steps,actors:model.actors(),choiceId:model.id,contextId:model.id+':'+(model.variantId||'probe')}),{model,steps});
  const index=key=>{const i=steps.findIndex(step=>step.id===model.id+':'+key);assert.ok(i>=0,'missing event '+key);return i;};
  return {model,steps,plan,index,frame:key=>projectHeldObjects(plan,{eventIndex:index(key),milestone:'complete'}),final:()=>projectHeldObjects(plan,{eventIndex:steps.length-1,milestone:'complete'}),initial:()=>projectHeldObjects(plan,{eventIndex:-1,milestone:'initial'}),step:key=>steps[index(key)]};
}
function operations(f,event,key){return f.step(event).attributeOperations.filter(op=>op.instanceId===f.model.id+':'+key).map(op=>[op.kind,op.actorId,op.representation]);}
function replayPrefixes(f,key){
  const artifactId=f.model.id+':'+key;
  const usages=f.steps.map((step,index)=>({step,index,actions:step.attributeOperations.filter(op=>op.instanceId===artifactId)})).filter(row=>row.actions.length);
  const field=buildAttributeTrace(usages,f.model.examples()),exact=heldObjectTrace(f.plan,artifactId);
  assert.ok(field.length&&exact.length,key+' has consumer-visible field and exact-object replay');
  for(const row of [...field,...exact])assert.deepEqual(projectHeldObjects(f.plan,{eventIndex:row.sourceIndex,milestone:row.sourceIndex<0?'initial':'complete'}).state,reconstructProtocolState(f.model,row.sourceIndex));
  return {field,exact};
}

test('UNIX-01 old-token readiness precedes collection; only a held candidate can receive a policy decision',()=>{
  for(const variant of ['default','new-policy-denied']){
    const f=inspect(select(LINUXLOGONLAB_SCENARIOS,'lab-llog04',variant));
    assert.ok(f.index('password-preliminary')<f.index('new-secret'));
    assert.ok(f.index('new-secret')<f.index('password-policy'));
    assert.equal(f.frame('password-preliminary').state.workstation.newPasswordPolicyAccepted,undefined);
    assert.equal(has(f.frame('password-preliminary'),'new-secret','pamChange'),false);
    assert.deepEqual(operations(f,'new-secret','new-secret'),[['send','pamChangeApp','plain'],['receive','pamChange','plain']]);
    for(const actor of ['pamChangeApp','pamChange'])assert.equal(has(f.frame('new-secret'),'new-secret',actor),true);
    assert.deepEqual(operations(f,'password-policy','new-secret'),[['use','pamChange','plain'],['verify','pamChange','plain']]);
    const decision=f.frame('password-policy').state.workstation;
    assert.equal(decision.newPasswordPolicyAccepted,variant==='default');assert.equal(decision.authorityGeneration,1);assert.equal(decision.session,false);
    for(const secret of ['old-secret','new-secret'])for(const actor of ['pamChangeApp','pamChange'])assert.equal(has(f.final(),secret,actor),false);
    if(variant==='new-policy-denied'){
      for(const event of ['password-authority-request','password-update','setcred','session-open'])assert.equal(f.steps.some(s=>s.id===f.model.id+':'+event),false,event);
      assert.equal(f.final().state.workstation.authorityGeneration,1);assert.equal(f.final().state.workstation.admitted,false);assert.equal(f.final().state.workstation.session,false);
      assert.equal(has(f.final(),'authority','pamChange'),true);assert.equal(has(f.final(),'backend-generation','pamPasswordAuthority'),true);
    }else assert.ok(f.index('password-policy')<f.index('password-authority-request'));
    const replay=replayPrefixes(f,'new-secret');
    assert.ok(replay.exact.some(row=>row.sourceStepId===f.model.id+':password-policy'));
    assert.ok(replay.exact.some(row=>row.sourceStepId===f.model.id+':new-secret-cleanup'));
  }
});

test('UNIX-02 exemption is never local proof; selected good and bad local passwords control admission',()=>{
  for(const variant of ['exempt-account','exempt-local-proof-failed']){
    const f=inspect(select(MACOSLOGONLAB_SCENARIOS,'lab-mlog05',variant)),accepted=variant==='exempt-account';
    for(let eventIndex=-1;eventIndex<=f.index('local-exemption');eventIndex++){
      const state=projectHeldObjects(f.plan,{eventIndex,milestone:eventIndex<0?'initial':'complete'}).state.workstation;
      assert.equal(state.authenticated,false);assert.equal(state.admitted,false);assert.equal(state.session,false);assert.equal(state.idpSSO,false);
    }
    assert.ok(f.index('local-exemption')<f.index('local-password-input'));assert.ok(f.index('local-password-input')<f.index('local-password'));
    assert.equal(has(f.frame('local-password-input'),'local-secret','pssoOS'),true);
    assert.deepEqual(operations(f,'local-password','local-secret'),[['use','pssoOS','plain'],['verify','pssoOS','plain'],['evict','pssoOS','plain']]);
    assert.equal(f.frame('local-password').state.workstation.authenticated,accepted);
    assert.equal(f.final().state.workstation.session,accepted);assert.equal(f.final().state.workstation.admitted,accepted);assert.equal(f.final().state.workstation.idpSSO,false);
    assert.equal(has(f.final(),'session','pssoSession'),accepted);assert.equal(has(f.final(),'local-secret','pssoOS'),false);
    for(const event of ['method-selection','login-policy','idp-request','idp-proof'])assert.equal(f.steps.some(s=>s.id===f.model.id+':'+event),false,event);
    replayPrefixes(f,'local-secret');
  }
  const fixture=select(MACOSLOGONLAB_SCENARIOS,'lab-mlog05','exempt-account').fixture;
  const probe=inspect(createMacPlatformSSOCase({...fixture,localPassword:false}));
  assert.equal(probe.final().state.workstation.session,false);assert.equal(probe.final().state.workstation.authenticated,false);
});

test('UNIX-05 concrete frozen AppArmor profile permits public reads and denies private reads without boolean overrides',()=>{
  for(const [variant,path,allowed] of [['apparmor-permitted','/srv/public/report',true],['apparmor-denied','/srv/private/report',false]]){
    const f=inspect(select(LINUXELEVLAB_SCENARIOS,'lab-lelev04',variant));
    assert.equal(f.model.fixture.resource,path);
    const policy=f.model.workstationInventory.artifacts.find(o=>o.key==='policy'),resource=f.model.workstationInventory.artifacts.find(o=>o.key==='resource');
    for(const fragment of ['profile=afs-backup','/srv/public/** r','deny /srv/private/** r',path])assert.ok(policy.value.includes(fragment),fragment);
    assert.equal(resource.value,'SYM(read '+path+'; profile=afs-backup)');
    assert.ok(f.step('access-request').payload.some(field=>field.value.includes('read '+path)));
    assert.deepEqual(operations(f,'enforcement','policy'),[['use','lsmKernel','plain']]);assert.deepEqual(operations(f,'enforcement','resource'),[['use','lsmKernel','plain']]);
    assert.equal(has(f.frame('enforcement'),'policy','lsmKernel'),true);assert.equal(has(f.frame('enforcement'),'resource','lsmKernel'),true);
    assert.equal(f.frame('enforcement').state.workstation.operation,allowed);assert.equal(f.frame('enforcement').state.workstation.mandatoryDecision,allowed?'allow':'deny');
    replayPrefixes(f,'policy');replayPrefixes(f,'resource');
  }
  const declared=select(LINUXELEVLAB_SCENARIOS,'lab-lelev04','apparmor-denied').fixture;
  assert.equal(inspect(createLinuxLSMCase({...declared,ruleAllows:true})).final().state.workstation.operation,false);
});

test('UNIX-06 expired network authority is evicted before fresh AS acquisition and generation2 is installed only after receipt validation',()=>{
  const f=inspect(select(MACOSLOGONLAB_SCENARIOS,'lab-mlog04','reacquire-after-expiry'));
  const ordered=['ticket-install','ticket-expired','expired-ticket-cleanup','reacquire-secret','reacquire-kerberos-handoff','reacquire-ticket-issued','reacquire-ticket-receipt','reacquire-ticket-install','service-tgs-request','service-auth','ticket-cleanup'];
  for(let i=1;i<ordered.length;i++)assert.ok(f.index(ordered[i-1])<f.index(ordered[i]),ordered[i]);
  const expired=f.frame('expired-ticket-cleanup');assert.equal(expired.state.workstation.tgtUsable,false);
  for(const key of ['tgt','tgt-session-key','as-client-result'])assert.equal(has(expired,key,'macKerbExtension'),false);
  const received=f.frame('reacquire-ticket-receipt');
  assert.equal(received.state.workstation.tgtGeneration,1);assert.equal(received.state.workstation.activeTgtGeneration,null);assert.equal(received.state.workstation.tgtUsable,false);
  assert.equal(has(received,'reacquire-tgt','macKerbExtension','wire'),true);assert.equal(has(received,'reacquire-tgt','macKerbExtension'),false);assert.equal(has(received,'reacquire-tgt-session-key','macKerbExtension'),false);
  const installed=f.frame('reacquire-ticket-install');
  assert.equal(installed.state.workstation.tgtGeneration,2);assert.equal(installed.state.workstation.activeTgtGeneration,2);assert.equal(installed.state.workstation.tgtUsable,true);
  assert.equal(has(installed,'reacquire-tgt','macKerbExtension'),true);assert.equal(has(installed,'reacquire-tgt-session-key','macKerbExtension'),true);assert.equal(has(installed,'tgt','macKerbExtension'),false);
  for(const [key,old] of [['reacquire-tgt','tgt'],['reacquire-tgt-session-key','tgt-session-key'],['reacquire-as-client-result','as-client-result']]){
    const object=f.model.workstationInventory.artifacts.find(o=>o.key===key);assert.equal(object.generation,2);assert.deepEqual(object.replaces,[f.model.id+':'+old]);
    const ops=f.steps.flatMap(s=>s.attributeOperations).filter(op=>op.instanceId===object.artifactId);assert.ok(ops.every(op=>op.exactValueRef===object.artifactId+':g2:'+op.representation));
    replayPrefixes(f,key);
  }
  const tgs=f.model.workstationInventory.artifacts.find(o=>o.key==='service-tgs-request');
  assert.deepEqual(tgs.related,['lab-mlog04:reacquire-tgt','lab-mlog04:reacquire-tgt-session-key']);
  const serviceRequest=f.step('service-tgs-request').attributeOperations.filter(op=>op.kind==='send');
  assert.ok(serviceRequest.some(op=>op.instanceId==='lab-mlog04:reacquire-tgt'&&op.representation==='wire'));
  assert.equal(serviceRequest.some(op=>op.instanceId==='lab-mlog04:tgt'),false);
  assert.equal(f.final().state.workstation.operation,true);assert.equal(f.final().state.workstation.tgt,false);
  for(const key of ['tgt','reacquire-tgt','tgt-session-key','reacquire-tgt-session-key','extension-secret','reacquire-secret'])assert.equal(f.final().holdings.some(h=>h.actorId!=='macKerbKDC'&&h.artifactId==='lab-mlog04:'+key),false,key);
});

test('UNIX-06 failed reacquisition, expiration-only and explicit sign-out clear network cache but retain the same local desktop',()=>{
  for(const variant of ['default','ticket-expired','reacquire-after-expiry','reacquire-denied']){
    const f=inspect(select(MACOSLOGONLAB_SCENARIOS,'lab-mlog04',variant));
    for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){
      const frame=projectHeldObjects(f.plan,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
      assert.equal(frame.state.workstation.localIdentity,'uid501');assert.equal(frame.state.workstation.session,true);assert.equal(frame.state.workstation.localPasswordUnchanged,true);assert.equal(has(frame,'desktop','macKerbUser'),true);
    }
    assert.equal(f.final().state.workstation.tgt,false);assert.equal(f.final().state.workstation.tgtUsable,false);assert.equal(f.final().state.workstation.activeTgtGeneration,null);
    if(variant==='reacquire-denied'){
      for(const event of ['reacquire-ticket-issued','reacquire-ticket-install','service-tgs-request','service-auth'])assert.equal(f.steps.some(s=>s.id===f.model.id+':'+event),false,event);
      assert.ok(f.index('expired-ticket-cleanup')<f.index('reacquire-kerberos-deny'));assert.ok(f.index('reacquire-kerberos-error-receipt')<f.index('reacquire-kerberos-error-process'));
      assert.equal(f.final().state.workstation.tgtGeneration,1);assert.equal(f.final().state.workstation.operation,false);
      assert.equal(f.model.workstationInventory.artifacts.some(o=>o.key==='reacquire-tgt'),false);
      for(const actor of ['macKerbUser','macKerbExtension'])assert.equal(has(f.final(),'reacquire-secret',actor),false);
      replayPrefixes(f,'reacquire-secret');replayPrefixes(f,'reacquire-as-error');
    }
  }
});

test('UNIX-03 fresh password and pam_tid select the same identity; cancellation and timestamp reuse are not fresh authentication',()=>{
  for(const [variant,event] of [['default','password-auth'],['touch-success','pam-tid-result'],['explicit-password-fallback','password-auth']]){
    const f=inspect(select(MACOSELEVLAB_SCENARIOS,'lab-melev02',variant)),state=f.frame(event).state.workstation;
    assert.equal(state.authenticated,true);assert.equal(state.authenticatedIdentity,'alice uid501');assert.equal(state.operation,false);
    assert.equal(f.frame('command-start').state.workstation.authenticated,true);assert.equal(f.frame('command-start').state.workstation.localIdentity,'uid501');
    if(variant==='touch-success'){
      assert.deepEqual(operations(f,'pam-tid-result','touch-decision'),[['create','macSudoPAM','plain'],['verify','macSudoPAM','plain']]);replayPrefixes(f,'touch-decision');
    }
    if(variant==='explicit-password-fallback')assert.equal(f.frame('pam-tid-result').state.workstation.authenticated,false);
  }
  for(const variant of ['touch-canceled','touch-failed']){
    const f=inspect(select(MACOSELEVLAB_SCENARIOS,'lab-melev02',variant));assert.equal(f.frame('pam-tid-result').state.workstation.authenticated,false);assert.equal(f.final().state.workstation.authenticated,false);assert.equal(f.final().state.workstation.authenticatedIdentity,null);assert.equal(f.final().state.workstation.operation,false);
  }
  const fallback=select(MACOSELEVLAB_SCENARIOS,'lab-melev02','explicit-password-fallback').fixture;
  const deniedFallback=inspect(createMacSudoCase({...fallback,password:'wrong'}));
  assert.equal(deniedFallback.frame('pam-tid-result').state.workstation.authenticated,false);assert.equal(deniedFallback.frame('password-auth').state.workstation.authenticated,false);assert.equal(deniedFallback.final().state.workstation.operation,false);
  const reuse=inspect(select(MACOSELEVLAB_SCENARIOS,'lab-melev02','timestamp-valid'));
  assert.equal(reuse.steps.some(s=>s.id.endsWith(':pam-tid-result')||s.id.endsWith(':password-auth')),false);assert.equal(reuse.final().state.workstation.authenticated,false);assert.equal(reuse.final().state.workstation.operation,true);
});

test('UNIX-04 selected root callers start and return as uid0, unlike a setuid effective-root executable',()=>{
  for(const [id,variant,caller,exit] of [['lab-lelev01','root-caller','lelevCaller','command-exit'],['lab-lelev02','real-root-bypass','suCaller','su-return']]){
    const f=inspect(select(LINUXELEVLAB_SCENARIOS,id,variant));
    assert.equal(f.initial().state.workstation.localIdentity,'uid0');assert.equal(f.frame(exit).state.workstation.localIdentity,'uid0');assert.equal(has(f.frame(exit),'caller',caller),true);
    assert.match(f.model.profile.startingSummary[0],/root/);assert.match(f.model.profile.startingSummary[0],/uid0|UID0/);
    const object=f.model.workstationInventory.artifacts.find(o=>o.key==='caller');assert.match(object.value,/uid0/);
    assert.equal(f.final().state.workstation.passwordCompared,false);assert.equal(f.final().state.workstation.operation,true);
  }
  const ordinary=inspect(select(LINUXELEVLAB_SCENARIOS,'lab-lelev02','setuid-not-real-root'));
  assert.equal(ordinary.initial().state.workstation.localIdentity,'uid1000');assert.equal(ordinary.frame('rootok').state.workstation.rootBypass,false);assert.equal(ordinary.final().state.workstation.passwordCompared,true);assert.equal(ordinary.final().state.workstation.operation,false);assert.equal(has(ordinary.final(),'caller','suCaller'),true);
});
