import test from 'node:test';
import assert from 'node:assert/strict';
import {LINUXLOGONLAB_SCENARIOS} from '../src/linux-logon-lab.js';
import {MACOSLOGONLAB_SCENARIOS} from '../src/macos-logon-lab.js';
import {buildUnixWorkstationHeldObjects} from '../src/held-object-unix-workstation.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {readFileSync} from 'node:fs';
import {LINUXELEVLAB_SCENARIOS} from '../src/linux-elevation-lab.js';
import {MACOSELEVLAB_SCENARIOS} from '../src/macos-elevation-lab.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

function fixture(m){const steps=m.steps(),raw=buildUnixWorkstationHeldObjects({model:m,steps,actors:m.actors(),choiceId:m.id,contextId:m.id+':'+m.variantId}),plan=compileHeldObjects(raw,{model:m,steps});return {m,steps,plan,frame:key=>projectHeldObjects(plan,{eventIndex:steps.findIndex(s=>s.id===m.id+':'+key),milestone:'complete'})};}
const has=(f,key,actor,rep='plain')=>f.holdings.some(h=>h.artifactId.endsWith(':'+key)&&h.actorId===actor&&h.representationId===rep);

test('PAM backend verifier never becomes application login token; transient secrets are removed',()=>{
  const base=LINUXLOGONLAB_SCENARIOS.find(m=>m.id==='lab-llog01');
  for(const choice of base.variantChoices){const f=fixture(base.withVariant(choice.id));
    for(let i=-1;i<f.steps.length;i++){
      const frame=projectHeldObjects(f.plan,{eventIndex:i,milestone:i<0?'initial':'complete'});
      assert.equal(has(frame,'verifier','llogLogin'),false);
      assert.equal(has(frame,'verifier','llogSession'),false);
    }
    const final=projectHeldObjects(f.plan,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(has(final,'entered-secret','llogLogin'),false);assert.equal(has(final,'entered-secret','llogPAM'),false);
    assert.equal(has(final,'identity','llogFiles'),true);
  }
});

test('Local IPC has actual source/receiver owners; configuration is not transmitted',()=>{
  const f=fixture(LINUXLOGONLAB_SCENARIOS[0]);const ev=f.plan.plan.events[f.m.id+':conversation'];
  assert.equal(ev.messages[0].from,'llogLogin');assert.equal(ev.messages[0].to,'llogPAM');
  assert.equal(ev.messages[0].objects[0].artifactId,f.m.id+':entered-secret');
  assert.equal(has(f.frame('conversation'),'entered-secret','llogPAM'),true);
  assert.equal(has(f.frame('pam-end'),'entered-secret','llogPAM'),false);
  const trace=heldObjectTrace(f.plan,f.m.id+':entered-secret');assert.ok(trace.some(e=>e.sourceStepId===f.m.id+':conversation'));assert.ok(trace.some(e=>e.sourceStepId===f.m.id+':pam-end'));
  const index=f.steps.findIndex(s=>s.id===f.m.id+':conversation'),before=projectHeldObjects(f.plan,{eventIndex:index,progress:0});
  assert.equal(has(before,'entered-secret','llogLogin'),true);assert.equal(has(before,'entered-secret','llogPAM'),false);
  assert.ok(trace.some(row=>row.sourceIndex<index&&row.from==='llogLogin'&&row.to==='llogLogin'&&row.traceKind.includes('create')));
});

test('Exact-object source cursor reconstructs full canonical prefix, not an isolated event',()=>{
  for(const m of [...LINUXLOGONLAB_SCENARIOS,...MACOSLOGONLAB_SCENARIOS]){
    const f=fixture(m);for(const step of f.steps){for(const op of step.attributeOperations||[]){assert.equal(op.sourceEventId,step.id);assert.ok(op.instanceId);assert.ok(op.exactValueRef);assert.ok(op.fieldPath);}}
    for(let i=0;i<f.steps.length;i++){const canonical=reconstructProtocolState(m,i);assert.equal(canonical.workstation.unrelatedSession,'other-user-session-retained');const frame=projectHeldObjects(f.plan,{eventIndex:i,milestone:'complete'});assert.equal(frame.coverageStatus,'complete');}
  }
});

const unixHeldModels=[...LINUXLOGONLAB_SCENARIOS,...LINUXELEVLAB_SCENARIOS,...MACOSLOGONLAB_SCENARIOS,...MACOSELEVLAB_SCENARIOS];
const unixHeldOracle=JSON.parse(readFileSync(new URL('../docs/next-expansion/unix-workstation-worksheet.json',import.meta.url),'utf8'));

test('Every independent exact holding predicate reconstructs actual complete source prefixes',()=>{
  for(const row of unixHeldOracle.rows){const base=unixHeldModels.find(m=>m.id===row.runtimeId);
    for(const c of row.canonicalCases){const f=fixture(base.withVariant(c.id));
      for(const a of c.assertions.filter(a=>a.target==='holding')){
        const eventIndex=a.at.end?f.steps.length-1:a.at.milestone==='initial'?-1:f.steps.findIndex(s=>s.id===a.at.stepId);
        assert.ok(eventIndex>=0||a.at.milestone==='initial',row.id+'/'+c.id+'/'+a.at.stepId);
        const frame=projectHeldObjects(f.plan,{eventIndex,milestone:eventIndex<0?'initial':a.at.milestone});
        const held=frame.holdings.some(h=>h.actorId===a.actorId&&h.artifactId===a.artifactId&&h.representationId===a.representation);
        assert.equal(held,a.present,row.id+'/'+c.id+'/'+a.artifactId+'/'+a.representation);
      }
    }
  }
});

test('Kerberos protected receipt and validated cache install remain distinct exact representations',()=>{
  for(const [id,owner,install] of [['lab-llog02','llogSSSD','ticket-install'],['lab-llog05','kinitUser','ticket-install'],['lab-mlog03','macAD','online-ticket'],['lab-mlog04','macKerbExtension','ticket-install']]){
    const m=unixHeldModels.find(m=>m.id===id),f=fixture(m),receipt=f.frame('ticket-receipt');
    assert.equal(has(receipt,'tgt',owner,'wire'),true);assert.equal(has(receipt,'tgt',owner),false);assert.equal(receipt.state.workstation.tgt,false);
    assert.equal(has(f.frame(install),'tgt',owner),true);assert.equal(f.frame(install).state.workstation.tgt,true);
    const artifact=m.workstationInventory.artifacts.find(o=>o.key==='tgt');
    for(const step of m.steps())for(const op of step.attributeOperations.filter(op=>op.instanceId===artifact.artifactId)){const rep=artifact.representations.find(r=>r.representationId===op.representation);assert.equal(op.value,rep.fields[0].value);}
    const receiptStep=m.steps().find(step=>step.id===id+':ticket-receipt'),wire=artifact.representations.find(rep=>rep.representationId==='wire');
    assert.equal(receiptStep.payload.find(field=>field.attributeId===artifact.attributeId).value,wire.fields[0].value);
    assert.notEqual(receiptStep.payload.find(field=>field.attributeId===artifact.attributeId).value,artifact.value);
    const trace=heldObjectTrace(f.plan,artifact.artifactId);assert.ok(trace.some(t=>t.sourceStepId===id+':ticket-receipt'&&t.representationId==='wire'));assert.ok(trace.some(t=>t.sourceStepId===id+':'+install&&t.representationId==='plain'));
  }
});

test('LDAP identity response is protected at the directory before receipt and interpreted only at the NSS owner',()=>{
  const base=LINUXLOGONLAB_SCENARIOS.find(m=>m.id==='lab-llog02');
  for(const choice of base.variantChoices){
    const f=fixture(base.withVariant(choice.id)),id=f.m.id,artifactId=id+':directory-identity';
    const initial=projectHeldObjects(f.plan,{eventIndex:-1,milestone:'initial'});
    assert.equal(has(initial,'directory-identity','llogDirectory'),true);
    assert.equal(has(initial,'directory-identity','llogDirectory','wire'),false);
    assert.equal(has(f.frame('directory-lookup'),'directory-identity','llogDirectory','wire'),false);
    if(choice.id==='missing-uid-mapping'){
      assert.equal(f.steps.some(step=>step.id===id+':directory-response-prepare'),false);
      assert.equal(has(f.frame('identity-deny'),'directory-identity','llogNSS','wire'),false);
      continue;
    }
    const prepared=f.frame('directory-response-prepare'),received=f.frame('identity-result'),decoded=f.frame('identity-decode');
    assert.equal(has(prepared,'directory-identity','llogDirectory','wire'),true);
    assert.equal(has(prepared,'directory-identity','llogNSS','wire'),false);
    const start=projectHeldObjects(f.plan,{eventIndex:f.steps.findIndex(step=>step.id===id+':identity-result'),progress:0});
    assert.equal(has(start,'directory-identity','llogDirectory','wire'),true);
    assert.equal(has(start,'directory-identity','llogNSS','wire'),false);
    assert.equal(has(received,'directory-identity','llogNSS','wire'),true);
    assert.equal(has(received,'directory-identity','llogNSS'),false);
    assert.equal(has(received,'directory-identity','llogApp'),false);
    assert.equal(has(decoded,'directory-identity','llogNSS'),true);
    assert.equal(has(f.frame('nss-result'),'directory-identity','llogApp'),true);
    for(const frame of [prepared,received,decoded,f.frame('nss-result')]){
      assert.equal(frame.state.workstation.authenticated,false);
      assert.equal(frame.state.workstation.admitted,false);
      assert.equal(frame.state.workstation.session,false);
    }
    const operations=f.steps.flatMap(step=>step.attributeOperations).filter(op=>op.instanceId===artifactId);
    assert.ok(operations.every(op=>op.creator==='llogDirectory'));
    assert.equal(operations.some(op=>op.kind==='create'),false);
    assert.ok(operations.some(op=>op.sourceEventId===id+':directory-response-prepare'&&op.kind==='encrypt'&&op.actorId==='llogDirectory'&&op.representation==='wire'));
    assert.ok(operations.some(op=>op.sourceEventId===id+':identity-decode'&&op.kind==='decrypt'&&op.actorId==='llogNSS'&&op.representation==='plain'));
  }
});

test('Field and exact-object replay retain source cursors, exact generations and full canonical prefix',()=>{
  for(const m of unixHeldModels){const f=fixture(m);
    for(const artifact of m.workstationInventory.artifacts){
      const usages=f.steps.map((step,index)=>({step,index,actions:step.attributeOperations.filter(op=>op.instanceId===artifact.artifactId)})).filter(u=>u.actions.length);
      const field=buildAttributeTrace(usages,m.examples()),exact=heldObjectTrace(f.plan,artifact.artifactId);
      for(const replay of [...field,...exact]){assert.deepEqual(reconstructProtocolState(m,replay.sourceIndex),projectHeldObjects(f.plan,{eventIndex:replay.sourceIndex,milestone:replay.sourceIndex<0?'initial':'complete'}).state);}
      for(const replay of field)for(const action of replay.traceActions){const rep=artifact.representations.find(r=>r.representationId===action.representation);assert.equal(action.value,rep.fields[0].value);assert.equal(action.instanceId,artifact.artifactId);assert.equal(action.exactValueRef,artifact.artifactId+':g'+artifact.generation+':'+action.representation);}
    }
  }
});

test('Unix cases compile concrete messages without transferring callee-local creations',()=>{
  for(const base of unixHeldModels)for(const choice of base.variantChoices){
    const f=fixture(base.withVariant(choice.id));
    const inventory=f.m.workstationInventory;
    for(const step of f.steps){
      const entry=inventory.events[step.id],messages=entry.messages||[];
      assert.equal(messages.length,step.from===step.to?0:1,step.id);
      for(const message of messages){
        assert.equal(message.from,step.from);assert.equal(message.to,step.to);
        const before=projectHeldObjects(f.plan,{eventIndex:f.steps.indexOf(step),progress:message.start});
        assert.ok(message.objects.length,step.id);
        for(const carried of message.objects){
          const artifact=inventory.artifacts.find(o=>o.artifactId===carried.artifactId);
          const representation=artifact.representations.find(r=>r.representationId===carried.representationId);
          assert.ok(representation.fields.every(field=>typeof field.value==='string'&&field.value.length>0),step.id);
          assert.ok(before.holdings.some(h=>h.actorId===message.from&&h.artifactId===artifact.artifactId&&h.representationId===carried.representationId),step.id+' exact sender custody before the call');
          assert.equal(['session','process-credential','verifier','private-key','session-key','key-handle','credential-authority-state'].includes(artifact.type)&&step.attributeOperations.some(op=>op.kind==='create'&&op.instanceId===artifact.artifactId&&op.actorId===step.to),false,step.id+' callee-local creation is not payload');
          for(const [kind,actor] of [['send',message.from],['receive',message.to]]){
            const operation=step.attributeOperations.find(op=>op.kind===kind&&op.actorId===actor&&op.instanceId===artifact.artifactId&&op.representation===carried.representationId);
            assert.ok(operation,step.id+' '+kind);assert.equal(operation.value,representation.fields[0].value);
          }
        }
      }
    }
    const final=projectHeldObjects(f.plan,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(has(final,'unrelated-session',Object.keys(f.m.actors())[0]),true);
    for(const secret of inventory.artifacts.filter(o=>o.type==='secret'))assert.equal(final.holdings.some(h=>h.artifactId===secret.artifactId),false,f.m.id+'/'+choice.id+' transient '+secret.key);
  }
});

test('NSS and pam_start carry exact input arguments, not fabricated identity/session grants',()=>{
  const f=fixture(LINUXLOGONLAB_SCENARIOS.find(m=>m.id==='lab-llog01'));
  for(const [event,key,value] of [
    ['lookup','lookup-control','SYM(getpwnam_r; name=alice; files NSS)'],
    ['pam-start','pam-start-control','SYM(pam_start; service=afs-login; user=alice; conversation=login application callback)'],
  ]){
    const entry=f.m.workstationInventory.events[f.m.id+':'+event],carried=entry.messages[0].objects;
    assert.deepEqual(carried,[{artifactId:f.m.id+':'+key,representationId:'plain'}]);
    const artifact=f.m.workstationInventory.artifacts.find(o=>o.key===key);
    assert.equal(artifact.creator,'llogLogin');assert.equal(artifact.value,value);
    assert.equal(has(f.frame(event),key,entry.messages[0].to),true);
  }
  assert.equal(has(f.frame('pam-start'),'pam-transaction','llogPAM'),true);
  assert.equal(has(f.frame('pam-start'),'pam-transaction','llogLogin'),false);
  assert.equal(has(f.frame('process-start'),'process-credentials','llogSession'),false);
  assert.equal(f.frame('lookup').state.workstation.authenticated,false);
});

test('Target launch transfers exec arguments while command credentials are created only at target',()=>{
  for(const [models,id,event,owner,target,key] of [
    [LINUXELEVLAB_SCENARIOS,'lab-lelev01','command-start','lelevSudo','lelevTarget','command'],
    [LINUXELEVLAB_SCENARIOS,'lab-lelev02','target-process','suPAM','suShell','shell'],
    [MACOSELEVLAB_SCENARIOS,'lab-melev02','command-start','macSudoPolicy','macSudoTarget','command'],
  ]){
    const f=fixture(models.find(m=>m.id===id)),step=f.steps.find(s=>s.id===id+':'+event),message=f.m.workstationInventory.events[step.id].messages[0];
    assert.equal(message.from,owner);assert.equal(message.to,target);
    assert.deepEqual(message.objects,[{artifactId:id+':'+event+'-control',representationId:'plain'}]);
    assert.ok(step.attributeOperations.some(op=>op.kind==='create'&&op.instanceId===id+':'+key&&op.creator===target&&op.actorId===target));
    assert.equal(has(f.frame(event),key,target),true);assert.equal(has(f.frame(event),key,owner),false);
  }
});

test('Fresh sudo authentication commits a valid exact scoped record, replacing only expired same-scope generations',()=>{
  for(const [models,id,owner,uid,invalidator,cases] of [
    [LINUXELEVLAB_SCENARIOS,'lab-lelev01','lelevSudo',1000,'invalidate',['default','expired-timestamp','different-terminal','rootpw','targetpw','runaspw']],
    [MACOSELEVLAB_SCENARIOS,'lab-melev02','macSudoPolicy',501,'timestamp-invalidate',['default','timestamp-expired','touch-success','explicit-password-fallback']],
  ]){
    const base=models.find(m=>m.id===id);
    for(const variant of cases){
      const f=fixture(base.withVariant(variant)),inventory=f.m.workstationInventory;
      const expired=['expired-timestamp','timestamp-expired'].includes(variant),other=variant==='different-terminal';
      const old=inventory.artifacts.find(a=>a.key==='timestamp'),current=inventory.artifacts.find(a=>a.key==='timestamp-current');
      const expectedIdentity=variant==='rootpw'?['root',0]:variant==='targetpw'?['backup',1100]:variant==='runaspw'?['operator',1101]:['alice',uid];
      assert.ok(current,id+'/'+variant+' fresh record');
      const record=JSON.parse(current.value.slice(4,-1));
      assert.deepEqual(Object.keys(record).sort(),['auth_uid','disabled','principal','sid','start_time','timeoutSeconds','ts','tty','type'].sort());
      assert.equal(record.type,'TS_TTY');assert.equal(record.principal,expectedIdentity[0]);assert.equal(record.auth_uid,expectedIdentity[1]);
      assert.equal(record.tty,f.m.fixture.terminal||'tty1');assert.equal(record.sid,101);assert.equal(record.start_time,100);
      assert.equal(record.disabled,false);assert.equal(record.ts,1000);assert.equal(record.timeoutSeconds,300);
      assert.ok(1001>=record.ts&&1001-record.ts<record.timeoutSeconds);
      assert.equal(current.generation,expired?2:1);
      assert.deepEqual(current.replaces||[],expired?[old.artifactId]:[]);
      assert.equal(current.creator,owner);assert.equal(current.store,'sudo timestamp store');
      const check=f.frame('timestamp-check');
      assert.equal(check.state.workstation.timestampReusable,false);assert.equal(check.state.workstation.timestampRecord,null);assert.equal(check.state.workstation.prompt,true);
      for(const event of ['pam-result','timestamp-refresh']){
        const frame=f.frame(event);
        assert.equal(has(frame,'timestamp-current',owner),event==='timestamp-refresh');
        assert.equal(has(frame,'timestamp',owner),!!old&&(event!=='timestamp-refresh'||!expired));
      }
      const refreshed=f.frame('timestamp-refresh'),repeat=f.frame('repeat-policy');
      assert.deepEqual(refreshed.state.workstation.timestampRecord,record);
      assert.equal(refreshed.state.workstation.timestampReusable,true);assert.equal(refreshed.state.workstation.admitted,true);
      assert.equal(repeat.state.workstation.repeatPolicyChecked,true);assert.equal(repeat.state.workstation.repeatPrompt,false);assert.equal(repeat.state.workstation.timestampReusable,true);
      const refreshStep=f.steps.find(s=>s.id===id+':timestamp-refresh');
      const created=refreshStep.attributeOperations.find(op=>op.kind==='create'&&op.instanceId===current.artifactId);
      assert.equal(created.exactValueRef,current.artifactId+':g'+current.generation+':plain');
      assert.deepEqual(JSON.parse(created.value.slice(4,-1)),record);
      assert.ok(f.steps.findIndex(s=>s.id===id+':'+(id==='lab-lelev01'?'pam-account':'account-session'))<f.steps.indexOf(refreshStep));
      const invalidated=f.frame(invalidator);
      assert.equal(has(invalidated,'timestamp-current',owner),false);assert.equal(invalidated.state.workstation.timestampRecord,null);
      assert.equal(invalidated.state.workstation.timestampReusable,false);assert.equal(invalidated.state.workstation.timestampRetained,false);
      assert.equal(invalidated.state.workstation.nextRequestNeedsAuth,true);
      assert.ok(f.steps.find(s=>s.id===id+':'+invalidator).attributeOperations.some(op=>op.kind==='evict'&&op.instanceId===current.artifactId));
      if(old){
        const prior=JSON.parse(old.value.slice(4,-1));
        assert.equal(old.generation,1);assert.equal(prior.ts,expired?600:900);
        assert.equal(prior.tty,other?'tty2':'tty1');
        assert.equal(prior.sid,other?102:101);assert.equal(prior.start_time,other?200:100);
        assert.equal(has(invalidated,'timestamp',owner),other);
        assert.equal(has(f.frame('command-exit'),'timestamp',owner),other);
        if(expired)assert.ok(1000-prior.ts>=prior.timeoutSeconds);
      }
      for(const entry of Object.values(inventory.events))for(const message of entry.messages||[]){
        assert.equal(message.objects.some(o=>o.artifactId===current.artifactId||o.artifactId===old?.artifactId),false,'timestamp records remain policy-owner-local');
      }
      assert.equal(invalidated.state.workstation.localIdentity,'uid'+uid);
      assert.equal(invalidated.state.workstation.session,true);
    }
  }
});

test('Sudo policy exemptions omit authentication without inventing a timestamp; valid reuse has a real scoped holding',()=>{
  const linux=LINUXELEVLAB_SCENARIOS.find(m=>m.id==='lab-lelev01');
  for(const variant of ['nopasswd','root-caller']){
    const f=fixture(linux.withVariant(variant)),repeat=f.frame('repeat-policy');
    assert.equal(f.steps.some(s=>s.id.endsWith(':timestamp-refresh')||s.id.endsWith(':invalidate')||s.id.endsWith(':pam-conversation')),false);
    assert.equal(repeat.state.workstation.timestampRecord,null);assert.equal(repeat.state.workstation.timestampReusable,false);
    assert.equal(repeat.state.workstation.passwordCompared,false);assert.equal(repeat.state.workstation.repeatPrompt,false);assert.equal(repeat.state.workstation.nextRequestNeedsAuth,false);
    assert.equal(repeat.state.workstation.admitted,true);assert.equal(has(repeat,'timestamp-current','lelevSudo'),false);
  }
  for(const [base,variant,owner,invalidate] of [
    [linux,'timestamp-reuse','lelevSudo','invalidate'],
    [MACOSELEVLAB_SCENARIOS.find(m=>m.id==='lab-melev02'),'timestamp-valid','macSudoPolicy','timestamp-invalidate'],
  ]){
    const f=fixture(base.withVariant(variant)),check=f.frame('timestamp-check'),record=JSON.parse(f.m.workstationInventory.artifacts.find(a=>a.key==='timestamp').value.slice(4,-1));
    assert.equal(record.ts,900);assert.equal(record.timeoutSeconds,300);assert.equal(record.disabled,false);
    assert.equal(has(check,'timestamp',owner),true);assert.equal(check.state.workstation.prompt,false);assert.equal(check.state.workstation.timestampReusable,true);
    assert.deepEqual(check.state.workstation.timestampRecord,record);
    assert.equal(f.steps.some(s=>['timestamp-refresh','pam-conversation','password-auth','pam-tid-result'].some(e=>s.id.endsWith(':'+e))),false);
    assert.equal(f.frame('repeat-policy').state.workstation.repeatPrompt,false);
    assert.equal(has(f.frame(invalidate),'timestamp',owner),false);assert.equal(f.frame(invalidate).state.workstation.nextRequestNeedsAuth,true);
  }
});

test('Failed sudo policy, authentication or account paths never materialize a fresh timestamp',()=>{
  for(const [models,id,owner,variants] of [
    [LINUXELEVLAB_SCENARIOS,'lab-lelev01','lelevSudo',['command-denied','runas-denied','cached-policy-denied','wrong-password','noninteractive','account-denied']],
    [MACOSELEVLAB_SCENARIOS,'lab-melev02','macSudoPolicy',['policy-denied','policy-denied-after-touch','touch-canceled','touch-failed','no-aqua','module-unsupported','hardware-unsupported','wrong-password']],
  ]){
    const base=models.find(m=>m.id===id);
    for(const variant of variants){
      const f=fixture(base.withVariant(variant));
      assert.equal(f.steps.some(s=>s.id===id+':timestamp-refresh'),false,id+'/'+variant);
      for(const step of f.steps)assert.equal(has(f.frame(step.id.slice(id.length+1)),'timestamp-current',owner),false);
      const final=f.frame(f.steps.at(-1).id.slice(id.length+1));
      assert.equal(final.state.workstation.operation,false);
      for(const secret of f.m.workstationInventory.artifacts.filter(a=>a.type==='secret'))assert.equal(final.holdings.some(h=>h.artifactId===secret.artifactId),false);
    }
  }
});

test('Reference service receives no TGT/plain keys and learns authentication before client mutual/result knowledge',()=>{
  for(const [id,owner,resource] of [['lab-llog05','kinitUser','kinitResource'],['lab-mlog04','macKerbExtension','macKerbResource']]){
    const base=unixHeldModels.find(m=>m.id===id);
    for(const variant of ['default',id==='lab-llog05'?'remote-acl-denied':'service-denied']){
      const f=fixture(base.withVariant(variant)),inventory=f.m.workstationInventory;
      assert.deepEqual(inventory.events[id+':service-auth'].messages[0].objects,[
        {artifactId:id+':service-ticket',representationId:'wire'},
        {artifactId:id+':service-authenticator',representationId:'wire'},
      ]);
      assert.equal(f.frame('service-auth').state.workstation.serviceAuthenticated,false);
      assert.equal(has(f.frame('service-auth'),'service-session-key',resource),false);
      assert.equal(f.frame('service-check').state.workstation.serviceAuthenticated,true);
      assert.equal(has(f.frame('service-check'),'service-session-key',resource),true);
      assert.equal(f.frame('service-check').state.workstation.clientKnowsServiceAuthentication,false);
      assert.equal(has(f.frame('service-reply-receipt'),'service-ap-reply',owner,'wire'),true);
      assert.equal(has(f.frame('service-reply-receipt'),'service-ap-reply',owner),false);
      assert.equal(f.frame('service-reply-check').state.workstation.clientKnowsServiceAuthentication,true);
      const received=f.frame('resource-response-receipt');
      assert.equal(has(received,'resource-result',owner,'wire'),true);assert.equal(has(received,'resource-result',owner),false);
      assert.equal(received.state.workstation.resourceDecisionKnown,false);
      const accepted=f.frame('resource-result');
      assert.equal(has(accepted,'resource-result',owner),true);assert.equal(accepted.state.workstation.resourceDecisionKnown,true);
      assert.equal(accepted.state.workstation.operation,variant==='default');
      for(const step of f.steps){
        const frame=f.frame(step.id.slice(id.length+1));
        assert.equal(has(frame,'tgt',resource),false);assert.equal(has(frame,'tgt',resource,'wire'),false);
        assert.equal(has(frame,'service-ticket',owner),false);
        for(const message of inventory.events[step.id].messages||[])for(const object of message.objects){
          const artifact=inventory.artifacts.find(o=>o.artifactId===object.artifactId);
          assert.equal(artifact.type==='private-key'||artifact.type==='session-key',false,step.id+' must carry protected envelope, not key');
        }
      }
    }
  }
});

test('Password update sends actual new input and status only; new backend generation remains creator-local',()=>{
  const base=LINUXLOGONLAB_SCENARIOS.find(m=>m.id==='lab-llog04');
  for(const variant of ['default','directory-online','update-failed']){
    const f=fixture(base.withVariant(variant)),inventory=f.m.workstationInventory;
    assert.deepEqual(inventory.events[f.m.id+':password-authority-request'].messages[0].objects,[
      {artifactId:f.m.id+':new-secret',representationId:'plain'},
      {artifactId:f.m.id+':password-authority-request-control',representationId:'plain'},
    ]);
    assert.deepEqual(inventory.events[f.m.id+':password-authority-result'].messages[0].objects,[{artifactId:f.m.id+':password-authority-result-control',representationId:'plain'}]);
    assert.equal(has(f.frame('password-update'),'backend-generation-g2','pamPasswordAuthority'),variant!=='update-failed');
    assert.equal(has(f.frame('password-update'),'backend-generation-g2','pamChange'),false);
    assert.equal(has(f.frame('password-update'),'backend-generation-g2','pamChangeApp'),false);
  }
});

test('Loaded LSM policy evaluation is kernel-local inspection, not a policy-server authentication exchange',()=>{
  const base=LINUXELEVLAB_SCENARIOS.find(m=>m.id==='lab-lelev04');
  for(const choice of base.variantChoices){
    const f=fixture(base.withVariant(choice.id)),step=f.steps.find(s=>s.id===f.m.id+':policy-inputs');
    assert.equal(step.from,'lsmKernel');assert.equal(step.to,'lsmKernel');assert.equal(step.eventType,'local');
    assert.equal(f.m.workstationInventory.events[step.id].messages,undefined);
    assert.ok(step.attributeOperations.some(op=>op.instanceId===f.m.id+':policy'&&op.kind==='inspect'&&op.actorId==='lsmKernel'));
    const initial=projectHeldObjects(f.plan,{eventIndex:-1,milestone:'initial'});
    assert.equal(has(initial,'policy','lsmKernel'),true);
    assert.equal(f.frame('enforcement').state.workstation.authenticated,true);
    assert.equal(f.frame('enforcement').state.workstation.processUid,f.m.fixture.uid);
  }
});

test('Unix adapter rejects missing or substituted payload/endpoints instead of suppressing genuine IPC',()=>{
  const model=LINUXLOGONLAB_SCENARIOS.find(m=>m.id==='lab-llog01'),steps=model.steps();
  const eventId=model.id+':lookup',original=model.workstationInventory.events[eventId];
  for(const replacement of [
    {...original,messages:[{...original.messages[0],objects:[]}]},
    {...original,messages:[{...original.messages[0],to:'llogLogin'}]},
    {...original,messages:[]},
  ]){
    const bad={...model,workstationInventory:{...model.workstationInventory,events:{...model.workstationInventory.events,[eventId]:replacement}}};
    assert.throws(()=>buildUnixWorkstationHeldObjects({model:bad,steps,actors:model.actors(),choiceId:model.id,contextId:model.id+':invalid'}),TypeError);
  }
});
