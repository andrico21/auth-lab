import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {NFSLAB_SCENARIOS,NFSLAB_CASE} from '../src/nfs-access-lab.js';
import {buildNFSHeldObjects} from '../src/held-object-nfs.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';

const worksheet=JSON.parse(readFileSync(new URL('../docs/next-expansion/nfs-worksheet.json',import.meta.url)));
function fixture(model){const steps=model.steps(),plan=buildNFSHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':'+model.variantId,choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});return {model,steps,plan,compiled,id:key=>model.id+':'+model.variantId+':'+key,frame(stage){const index=steps.findIndex(s=>s.nfsStage===stage);assert.notEqual(index,-1,stage);return projectHeldObjects(compiled,{eventIndex:index,milestone:'complete'});}};}
const holding=(frame,id,actor,rep)=>frame.holdings.find(h=>h.artifactId===id&&h.actorId===actor&&h.representationId===rep);
function fieldTrace(f,attributeId){
  // The app registers extension definitions before using the field picker.
  // Exercise that same catalog-backed API precondition without a shared import side effect.
  const previous=ATTRIBUTES[attributeId];
  ATTRIBUTES[attributeId]=f.model.definitions()[attributeId];
  try{return buildAttributeTrace(getAttributeUsage(f.steps,attributeId),f.model.examples());}
  finally{if(previous)ATTRIBUTES[attributeId]=previous;else delete ATTRIBUTES[attributeId];}
}

test('Independent exact-holding predicates compile all83 defaults and bounded named cases',async t=>{
  let fixtureCount=0;
  for(const row of worksheet.scenarios)for(const c of row.canonicalCases){fixtureCount++;await t.test(row.planId+'/'+c.id,()=>{const f=fixture(NFSLAB_CASE(row.planId,c.id));for(const predicate of c.assertions.filter(p=>p.target==='holding')){const index=predicate.at.end?f.steps.length-1:f.steps.findIndex(s=>s.id===predicate.at.stepId);assert.ok(index>=0,predicate.at.stepId);const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:predicate.at.milestone});assert.equal(!!holding(frame,predicate.artifactId,predicate.actorId,predicate.representation),predicate.present,row.planId+'/'+c.id+'/'+predicate.artifactId);}});}
  assert.equal(fixtureCount,83,'The13 core defaults and70 named cases remain required');
});

test('TGT and server service key never travel to the NFS peer/client; acceptor key has real local origin',()=>{
  const f=fixture(NFSLAB_CASE('NFS01'));
  for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){const frame=projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});assert.equal(frame.coverageStatus,'complete');assert.equal(holding(frame,f.id('user-tgt'),'nfsServer','plain'),undefined);assert.equal(holding(frame,f.id('machine-tgt'),'nfsServer','plain'),undefined);assert.equal(holding(frame,f.id('service-key'),'nfsClient','plain'),undefined);assert.equal(holding(frame,f.id('service-key'),'nfsHelper','plain'),undefined);}
  assert.ok(holding(f.frame('gss-server-accept'),f.id('acceptor-subkey'),'nfsServer','plain'));assert.equal(holding(f.frame('gss-mutual-reply'),f.id('acceptor-subkey'),'nfsHelper','plain'),undefined);assert.ok(holding(f.frame('gss-client-verify'),f.id('acceptor-subkey'),'nfsHelper','plain'));
  const wireMessages=Object.values(f.plan.events).flatMap(e=>e.messages||[]).filter(m=>m.from==='nfsServer'&&m.to==='nfsHelper');assert.equal(wireMessages.some(m=>m.objects.some(o=>o.artifactId===f.id('acceptor-subkey'))),false);
  const create=f.steps.flatMap(s=>s.attributeOperations).find(op=>op.instanceId===f.id('acceptor-subkey')&&op.kind==='create');assert.equal(create.actorId,'nfsServer');assert.equal(create.sourceEventId,f.id('gss-server-accept'));
});

test('Protected NFS receipt and exact field replay cannot acquire plaintext before unwrap',()=>{
  const f=fixture(NFSLAB_CASE('NFS01')),body=f.id('rpc-body'),data=f.id('file-result');assert.ok(holding(f.frame('rpc-request'),body,'nfsServer','wire'));assert.equal(holding(f.frame('rpc-request'),body,'nfsServer','plain'),undefined);assert.ok(holding(f.frame('rpc-body-verify'),body,'nfsServer','plain'));assert.ok(holding(f.frame('result-wire'),data,'nfsClient','wire'));assert.equal(holding(f.frame('result-wire'),data,'nfsClient','plain'),undefined);assert.ok(holding(f.frame('result-verify'),data,'nfsClient','plain'));
  const objectTrace=heldObjectTrace(f.compiled,data);assert.ok(objectTrace.some(r=>r.sourceStepId===f.id('result-wire')&&r.representationId==='wire'));assert.ok(objectTrace.some(r=>r.sourceStepId===f.id('result-verify')&&r.representationId==='plain'));
  const attributeId='nfs_nfs01_file_result',trace=fieldTrace(f,attributeId),wireIndex=f.steps.findIndex(s=>s.nfsStage==='result-wire'),verifyIndex=f.steps.findIndex(s=>s.nfsStage==='result-verify');
  const wireTrace=trace.find(step=>step.sourceIndex===wireIndex&&step.traceKind==='send');
  assert.ok(wireTrace);assert.equal(wireTrace.sourceStepId,f.id('result-wire'));assert.deepEqual([wireTrace.from,wireTrace.to],['nfsServer','nfsClient']);
  assert.deepEqual(wireTrace.payload.map(field=>field.value),['SYM(protected krb5p/none result; no decoded file bytes)']);
  const acceptedTrace=trace.find(step=>step.sourceIndex===verifyIndex&&step.traceKind==='decrypt');
  assert.ok(acceptedTrace);assert.equal(acceptedTrace.sourceStepId,f.id('result-verify'));assert.deepEqual([acceptedTrace.from,acceptedTrace.to],['nfsClient','nfsClient']);
  assert.deepEqual(acceptedTrace.payload.map(field=>field.value),['Synthetic report bytes: Alice may read this report. offset=0']);
  assert.ok(acceptedTrace.traceActions.every(action=>action.instanceId===data&&action.representation==='plain'&&action.sourceEventId===f.id('result-verify')&&action.exactValueRef===data+':plain'));
  const snapshot=JSON.stringify(f.frame('result-wire'));f.frame('result-verify');assert.equal(JSON.stringify(f.frame('result-wire')),snapshot,'Backward reconstruction restores only original wire receipt');
});

test('Integrity-only RPC fields are readable untrusted, not ciphertext or accepted body at receipt',()=>{
  const f=fixture(NFSLAB_CASE('NFS02','krb5i')),wire=holding(f.frame('rpc-request'),f.id('rpc-body'),'nfsServer','untrusted');assert.ok(wire);assert.equal(holding(f.frame('rpc-request'),f.id('rpc-body'),'nfsServer','plain'),undefined);const inspected=inspectHeldObject(f.frame('rpc-request'),wire.holdingId);assert.ok(inspected.fields.some(field=>String(field.value).includes('offset')));assert.ok(holding(f.frame('rpc-body-verify'),f.id('rpc-body'),'nfsServer','plain'));
});

test('TLS record receipt reveals no inner RPC and receiver uses its own directional secret',()=>{
  const f=fixture(NFSLAB_CASE('NFS11'));assert.ok(holding(f.frame('rpc-request'),f.id('tls-rpc-record'),'nfsServer','wire'));assert.equal(holding(f.frame('rpc-request'),f.id('rpc-body'),'nfsServer','plain'),undefined);assert.ok(holding(f.frame('rpc-decrypt'),f.id('rpc-body'),'nfsServer','plain'));assert.equal(holding(f.frame('rpc-decrypt'),f.id('tls-c2s-client'),'nfsServer','plain'),undefined);assert.ok(holding(f.frame('rpc-decrypt'),f.id('tls-c2s-server'),'nfsServer','plain'));assert.equal(holding(f.frame('tls-encrypted-flight'),f.id('tls-encrypted-flight'),'nfsClient','plain'),undefined);
  for(const model of NFSLAB_SCENARIOS.filter(m=>m.fixtureInputs.xprtsec!=='none')){const g=fixture(model),last=projectHeldObjects(g.compiled,{eventIndex:g.steps.length-1,milestone:'complete'});assert.equal(holding(last,g.id('tls-server-private'),'nfsClient','plain'),undefined);assert.equal(holding(last,g.id('tls-client-private'),'nfsServer','plain'),undefined);}
});

test('Repeated local principal receipts retain distinct deliveries of the same exact generation',()=>{
  const f=fixture(NFSLAB_CASE('NFS01')),id=f.id('authenticated-principal');
  const first=f.frame('open-policy-ipc'),second=f.frame('mapping-ipc');
  const firstCopies=first.holdings.filter(h=>h.artifactId===id&&h.actorId==='nfsPolicy');
  const secondCopies=second.holdings.filter(h=>h.artifactId===id&&h.actorId==='nfsPolicy');
  assert.equal(firstCopies.length,1);assert.equal(secondCopies.length,2);
  assert.equal(secondCopies[0].holdingId,firstCopies[0].holdingId);
  assert.notEqual(secondCopies[0].holdingId,secondCopies[1].holdingId);
  assert.deepEqual(secondCopies.map(h=>h.sourceEventId),[f.id('open-policy-ipc'),f.id('mapping-ipc')]);
  assert.ok(secondCopies.every(h=>h.retention==='retained'&&h.representationId==='plain'));
  for(const copy of secondCopies){const view=inspectHeldObject(second,copy.holdingId);assert.ok(view.fields.some(field=>String(field.value).includes('alice@CORP.EXAMPLE')));}
  assert.equal(second.artifacts.filter(a=>a.artifactId===id).length,1,'Receipt does not recreate the accepted principal generation');
  assert.deepEqual(f.frame('open-policy-ipc'),first,'Seeking backward retains only the first receipt');
});

test('Every NFS case carries real request/result objects rather than local context configuration or keys',()=>{
  for(const row of worksheet.scenarios)for(const c of row.canonicalCases){
    const f=fixture(NFSLAB_CASE(row.planId,c.id));
    const network=Object.values(f.plan.events).flatMap(e=>e.messages||[]).filter(m=>m.from!==m.to&&!((m.from==='nfsHelper'&&m.to==='nfsClient')||(m.from==='nfsClient'&&m.to==='nfsHelper')||(m.from==='nfsServer'&&m.to==='nfsPolicy')||(m.from==='nfsPolicy'&&m.to==='nfsServer')));
    for(const message of network)for(const carried of message.objects){const artifact=f.plan.artifacts.find(a=>a.artifactId===carried.artifactId);assert.notEqual(artifact.type,'key',row.planId+'/'+c.id+'/'+message.messageId);assert.notEqual(artifact.artifactId,f.id('machine-context'));assert.notEqual(artifact.artifactId,f.id('alternate-machine-context'));}
    for(const [stage,key] of [['exchange-id','exchange-id-arguments'],['create-session','create-session-arguments'],['setclientid','setclientid-arguments'],['setclientid-confirm','setclientid-confirm-arguments'],['setclientid-confirm-reply','setclientid-confirm-result']]){
      const event=f.plan.events[f.id(stage)];if(!event)continue;
      assert.ok(event.messages[0].objects.some(o=>o.artifactId===f.id(key)),row.planId+'/'+c.id+'/'+stage);
      assert.equal(event.messages[0].objects.some(o=>o.artifactId===f.id('clientid')),false,'A request/result is not a second transfer of the clientid reply');
    }
    if(f.model.fixtureInputs.sec==='sys'){const end=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});assert.equal(holding(end,f.id('machine-context'),'nfsServer','plain'),undefined,'AUTH_SYS client configuration is not a server-owned machine context');}
  }
});

test('Machine context and confirmed state generations become usable only at their real local acceptance',()=>{
  const f=fixture(NFSLAB_CASE('NFS01'));
  assert.equal(holding(f.frame('machine-gss-proof'),f.id('machine-context'),'nfsHelper','plain'),undefined);
  assert.ok(holding(f.frame('machine-gss-client-verify'),f.id('machine-context'),'nfsHelper','plain'));
  assert.equal(holding(f.frame('machine-gss-client-verify'),f.id('machine-context'),'nfsClient','plain'),undefined);
  assert.ok(holding(f.frame('machine-context-ipc'),f.id('machine-context'),'nfsClient','plain'));
  for(const variant of ['default','auth-sys']){
    const g=fixture(NFSLAB_CASE('NFS05',variant)),provisional=g.id('stateid'),confirmed=g.id('confirmed-stateid');
    assert.ok(holding(g.frame('open-accept'),provisional,'nfsClient','plain'));
    assert.equal(holding(g.frame('open-confirm-response'),confirmed,'nfsClient','plain'),undefined);
    assert.ok(holding(g.frame('open-confirm-accept'),confirmed,'nfsClient','plain'));
    assert.equal(holding(g.frame('open-confirm-accept'),provisional,'nfsClient','plain'),undefined);
    assert.equal(holding(g.frame('close-accept'),confirmed,'nfsClient','plain'),undefined);
    const artifact=g.plan.artifacts.find(a=>a.artifactId===confirmed);assert.equal(artifact.generation,variant+':2');
    assert.ok(holding(g.frame('state-client-accept'),g.id('clientid'),'nfsClient','plain'));
  }
});

test('Selected maintenance context and BIND response proof use real local owners before trust is granted',()=>{
  const wrong=fixture(NFSLAB_CASE('NFS06','wrong-machine-principal'));
  for(const stage of ['create-session-protect','create-session-verify']){
    const operations=wrong.steps.find(s=>s.nfsStage===stage).attributeOperations;
    assert.ok(operations.some(op=>op.kind==='use'&&op.instanceId===wrong.id('alternate-machine-context')));
    assert.ok(operations.some(op=>op.kind==='use'&&op.instanceId===wrong.id('alternate-machine-key')));
    assert.equal(operations.some(op=>op.kind==='use'&&op.instanceId===wrong.id('machine-context')),false);
  }
  const f=fixture(NFSLAB_CASE('NFS10')),wire=f.frame('bind-response'),accepted=f.frame('bind-client-accept');
  assert.equal(wire.state.nfs.serverConnection2,true);assert.equal(wire.state.nfs.connection2,false);
  assert.ok(holding(wire,f.id('connection-association'),'nfsClient','untrusted'));
  assert.equal(holding(wire,f.id('connection-association'),'nfsClient','plain'),undefined);
  assert.ok(holding(accepted,f.id('connection-association'),'nfsClient','plain'));
  const proof=f.steps.find(s=>s.nfsStage==='bind-response-protect').attributeOperations;
  assert.ok(proof.some(op=>op.kind==='derive'&&op.actorId==='nfsServer'&&op.instanceId===f.id('bind-response-verifier')));
  const verification=f.steps.find(s=>s.nfsStage==='bind-client-accept').attributeOperations;
  assert.ok(verification.some(op=>op.kind==='use'&&op.actorId==='nfsClient'&&op.instanceId===f.id('machine-context-key')));
});

test('Valid but wrong machine callers receive a correlated integrity error without gaining protected state',()=>{
  for(const [code,variant,stage] of [['NFS06','wrong-machine-principal','machine-maintenance'],['NFS10','wrong-principal','bind-verify']]){
    const f=fixture(NFSLAB_CASE(code,variant)),id=f.id(stage+'-failure'),wire=f.frame(stage+'-failure-wire'),accepted=f.frame(stage+'-failure-accept');
    assert.ok(holding(wire,id,'nfsClient','untrusted'));assert.equal(holding(wire,id,'nfsClient','plain'),undefined);
    const received=holding(wire,id,'nfsClient','untrusted'),view=inspectHeldObject(wire,received.holdingId);
    assert.ok(view.fields.some(field=>String(field.value).includes('machine-other-generation2')));
    assert.ok(holding(accepted,id,'nfsClient','plain'));assert.equal(accepted.state.nfs.connection2,false);
    const operations=f.steps.find(s=>s.nfsStage===stage+'-failure-accept').attributeOperations;
    assert.ok(operations.some(op=>op.kind==='use'&&op.actorId==='nfsClient'&&op.instanceId===f.id('alternate-machine-key')));
    assert.equal(operations.some(op=>op.kind==='use'&&op.instanceId===f.id('acceptor-subkey')),false,'Alice key does not validate a machine caller error');
  }
});

test('All83 NFS cases preserve exact source-operation field replay at canonical indices',async t=>{
  for(const row of worksheet.scenarios)for(const c of row.canonicalCases)await t.test(row.planId+'/'+c.id,()=>{
    const model=NFSLAB_CASE(row.planId,c.id),f={model,steps:model.steps()};
    const attributeIds=[...new Set(f.steps.flatMap(step=>step.attributeOperations.map(op=>op.attributeId)))];
    for(const attributeId of attributeIds){
      const trace=fieldTrace(f,attributeId);assert.ok(trace.length,attributeId);
      for(const replay of trace){
        const source=f.steps[replay.sourceIndex];assert.ok(source);assert.equal(replay.sourceStepId,source.id);
        assert.ok(replay.traceActions.length);
        for(const action of replay.traceActions){
          assert.equal(action.sourceEventId,source.id);
          assert.ok(source.attributeOperations.some(op=>op.attributeId===attributeId&&op.instanceId===action.instanceId&&op.kind===action.kind&&op.actorId===action.actorId&&op.representation===action.representation),'Replay must retain its actual source operation');
          const artifact=model.nfsInventory.artifacts.find(item=>item.artifactId===action.instanceId),representation=artifact?.representations.find(rep=>rep.representationId===action.representation);
          assert.ok(representation,action.instanceId+'/'+action.representation);
          assert.equal(action.exactValueRef,artifact.artifactId+':'+representation.representationId);
          assert.equal(action.value,representation.fields[0].value);
          assert.equal(replay.payload.find(field=>field.attributeId===attributeId)?.value,action.value);
        }
      }
      for(let index=0;index<f.steps.length;index++)for(const op of f.steps[index].attributeOperations.filter(op=>op.attributeId===attributeId&&op.kind!=='receive')){
        assert.ok(trace.some(replay=>replay.sourceIndex===index&&replay.traceActions.some(action=>action.instanceId===op.instanceId&&action.kind===op.kind&&action.actorId===op.actorId&&action.representation===op.representation)),'Missing canonical field occurrence '+f.steps[index].id+'/'+op.kind);
      }
    }
  });
});

test('NFS05 namespace failure has a real server creation, wire receipt and client-local acceptance trace',()=>{
  const f=fixture(NFSLAB_CASE('NFS05','sys-refused')),id=f.id('namespace-security-failure');
  assert.equal(holding(f.frame('namespace-security'),id,'nfsClient','plain'),undefined);
  assert.ok(holding(f.frame('namespace-security-failure-create'),id,'nfsServer','plain'));
  assert.ok(holding(f.frame('namespace-security-failure-wire'),id,'nfsClient','untrusted'));
  assert.equal(holding(f.frame('namespace-security-failure-wire'),id,'nfsClient','plain'),undefined);
  assert.ok(holding(f.frame('namespace-security-failure-accept'),id,'nfsClient','plain'));
  const trace=fieldTrace(f,'nfs_nfs05_namespace_security_failure');
  for(const [stage,kind,from,to,representation] of [
    ['namespace-security-failure-create','create','nfsServer','nfsServer','plain'],
    ['namespace-security-failure-wire','send','nfsServer','nfsClient','untrusted'],
    ['namespace-security-failure-accept','store','nfsClient','nfsClient','plain'],
    ['namespace-security-failure-accept','verify','nfsClient','nfsClient','plain'],
  ]){
    const replay=trace.find(step=>step.sourceStepId===f.id(stage)&&step.traceKind===kind);
    assert.ok(replay,stage+'/'+kind);assert.equal(replay.sourceIndex,f.steps.findIndex(step=>step.nfsStage===stage));
    assert.deepEqual([replay.from,replay.to],[from,to]);
    assert.ok(replay.traceActions.every(action=>action.instanceId===id&&action.representation===representation));
    assert.match(replay.payload[0].value,/NFS4ERR_WRONGSEC/);
  }
});

test('TLS handshake exact field replay separates signed plaintext derivation from ciphertext encryption',()=>{
  const model=NFSLAB_CASE('NFS11'),f={model,steps:model.steps()};
  for(const [key,stage,actor] of [['tls-encrypted-flight','tls-server-sign','nfsServer'],['tls-client-proof','tls-client-sign','nfsClient']]){
    const artifact=model.nfsInventory.artifacts.find(item=>item.key===key),trace=fieldTrace(f,artifact.attributeId);
    const creation=trace.find(step=>step.sourceStepId===model.id+':default:'+stage&&step.traceKind==='derive');
    const encryption=trace.find(step=>step.sourceStepId===model.id+':default:'+stage&&step.traceKind==='encrypt');
    assert.ok(creation);assert.ok(encryption);
    for(const [replay,representation] of [[creation,'plain'],[encryption,'wire']]){
      assert.equal(replay.sourceIndex,f.steps.findIndex(step=>step.nfsStage===stage));
      assert.deepEqual([replay.from,replay.to],[actor,actor]);
      assert.ok(replay.traceActions.every(action=>action.representation===representation&&action.exactValueRef===artifact.artifactId+':'+representation));
      assert.equal(replay.payload[0].value,artifact.representations.find(rep=>rep.representationId===representation).fields[0].value);
    }
    assert.notEqual(creation.payload[0].value,encryption.payload[0].value,'Plaintext fields and opaque ciphertext are not one replay value');
  }
});

test('NFS senders hold the exact transmitted representation before transfer begins',()=>{
  for(const code of ['NFS03','NFS09','NFS11']){
    const f=fixture(NFSLAB_CASE(code));
    for(const [eventIndex,step] of f.steps.entries()){
      const event=f.plan.events[step.id];
      for(const message of event.messages||[]){
        const start=projectHeldObjects(f.compiled,{eventIndex,progress:message.start});
        for(const carried of message.objects)assert.ok(holding(start,carried.artifactId,message.from,carried.representationId),step.id+'/'+carried.artifactId);
      }
      for(const operation of step.attributeOperations.filter(op=>op.kind==='create'||op.kind==='derive')){
        assert.equal(operation.actorId,operation.creator);
        assert.deepEqual([step.from,step.to],[operation.creator,operation.creator],'New objects originate in their actual creator-local event');
      }
    }
  }
});

test('Prepared Kerberos envelopes do not install credentials or context keys at protected receipt',()=>{
  const f=fixture(NFSLAB_CASE('NFS09'));
  for(const [stage,key,recipient,credential,accept] of [
    ['kinit-result','kinit-result','nfsHelper','user-tgt','kinit-accept'],
    ['tgs-reply','tgs-reply','nfsHelper','service-ticket','tgs-accept'],
    ['gss-init','gss-init','nfsServer','initiator-subkey','gss-server-accept'],
    ['gss-mutual-reply','gss-mutual-proof','nfsHelper','acceptor-subkey','gss-client-verify'],
    ['machine-tgs-reply','machine-tgs-reply','nfsHelper','machine-service-ticket','machine-tgs-accept'],
    ['machine-gss-init','machine-gss-init','nfsServer','machine-ticket-session-key','machine-gss-server'],
    ['machine-gss-proof','machine-gss-proof','nfsHelper','machine-context-key','machine-gss-client-verify'],
  ]){
    const received=f.frame(stage);
    assert.ok(holding(received,f.id(key),recipient,'wire'));
    assert.equal(holding(received,f.id(key),recipient,'plain'),undefined);
    assert.equal(holding(received,f.id(credential),recipient,'plain'),undefined);
    assert.ok(holding(f.frame(accept),f.id(credential),recipient,'plain'));
  }
});

test('Readable AUTH_SYS and GSS bodies are serialized locally without implying remote acceptance',()=>{
  for(const [code,variant,accept] of [['NFS03','default','rpc-decode'],['NFS02','krb5','rpc-body-verify'],['NFS02','krb5i','rpc-body-verify']]){
    const f=fixture(NFSLAB_CASE(code,variant)),id=f.id('rpc-body'),prepared=f.frame('rpc-protect'),received=f.frame('rpc-request');
    assert.ok(holding(prepared,id,'nfsClient','untrusted'));
    assert.equal(holding(prepared,id,'nfsServer','untrusted'),undefined);
    assert.ok(holding(received,id,'nfsServer','untrusted'));
    assert.equal(holding(received,id,'nfsServer','plain'),undefined);
    assert.ok(holding(f.frame(accept),id,'nfsServer','plain'));
    const body=f.plan.artifacts.find(artifact=>artifact.artifactId===id),serialized=fieldTrace(f,body.attributeId).find(step=>step.sourceStepId===f.id('rpc-protect')&&step.traceKind==='store');
    assert.ok(serialized);
    assert.deepEqual([serialized.from,serialized.to],['nfsClient','nfsClient']);
    assert.ok(serialized.traceActions.every(action=>action.instanceId===id&&action.representation==='untrusted'));
  }
});

test('TLS encrypts the policy-created Bob result without changing its immutable creator or granting READ',()=>{
  for(const variant of ['default','tls-only','forged-uid']){
    const f=fixture(NFSLAB_CASE('NFS11',variant)),id=f.id('second-user-decision'),artifact=f.plan.artifacts.find(item=>item.artifactId===id);
    assert.equal(artifact.creator,'nfsPolicy');
    assert.ok(holding(f.frame('second-user-policy'),id,'nfsPolicy','plain'));
    assert.ok(holding(f.frame('second-user-result-protect'),id,'nfsServer','wire'));
    const trace=fieldTrace(f,artifact.attributeId),encryption=trace.find(step=>step.sourceStepId===f.id('second-user-result-protect')&&step.traceKind==='encrypt');
    assert.ok(encryption);
    assert.deepEqual([encryption.from,encryption.to],['nfsServer','nfsServer']);
    assert.ok(encryption.traceActions.every(action=>action.creator==='nfsPolicy'&&action.actorId==='nfsServer'&&action.representation==='wire'));
    assert.equal(trace.some(step=>step.sourceStepId===f.id('second-user-result-protect')&&['create','derive'].includes(step.traceKind)),false);
    const received=f.frame('second-user-response'),accepted=f.frame('second-user-accept');
    assert.ok(holding(received,id,'nfsClient','wire'));
    assert.equal(holding(received,id,'nfsClient','plain'),undefined);
    assert.equal(received.state.nfs.secondUserClientAccepted,false);
    assert.ok(holding(accepted,id,'nfsClient','plain'));
    assert.equal(accepted.state.nfs.secondUserClientAccepted,true);
    assert.equal(accepted.state.nfs.secondUser.fileAllowed,false);
  }
});
