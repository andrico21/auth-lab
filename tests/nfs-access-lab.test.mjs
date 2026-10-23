import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {NFSLAB_SCENARIOS,NFSLAB_CASE,NFSLAB_ATTRIBUTES} from '../src/nfs-access-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const worksheet=JSON.parse(readFileSync(new URL('../docs/next-expansion/nfs-worksheet.json',import.meta.url)));
const at=(model,stage)=>{const index=model.steps().findIndex(step=>step.nfsStage===stage);assert.notEqual(index,-1,'Missing authored checkpoint '+stage);return reconstructProtocolState(model,index).nfs;};
const end=model=>reconstructProtocolState(model,model.steps().length-1).nfs;

test('Independent NFS worksheet rows and same-ID variant constructors stay aligned',async t=>{
  assert.equal(NFSLAB_SCENARIOS.length,13);
  for(const row of worksheet.scenarios){
    const model=NFSLAB_SCENARIOS.find(m=>m.id===row.runtimeId);assert.ok(model,row.planId);
    assert.deepEqual(model.variantChoices.map(c=>c.id).sort(),row.canonicalCases.map(c=>c.id).sort());
    for(const c of row.canonicalCases)await t.test(row.planId+'/'+c.id,()=>{const variant=model.withVariant(c.id);assert.equal(variant.id,model.id);assert.equal(variant.variantId,c.id);assert.ok(Object.isFrozen(variant.fixtureInputs));
      const expectedProfile=c.modelProfile||row.modelProfile;
      assert.deepEqual({name:variant.profile.name,version:variant.profile.version},expectedProfile,'Fixed case profile must match its independent version/sec/xprtsec contract');
      for(const fieldId of variant.ids){assert.ok(Object.hasOwn(NFSLAB_ATTRIBUTES,fieldId),'Branch field missing app catalog registration: '+fieldId);assert.ok(variant.catalogAttributeIds.includes(fieldId),'Branch field missing searchable family union: '+fieldId);}
      assert.ok(Object.isFrozen(variant.initialState.nfs));
      for(const predicate of c.assertions.filter(p=>p.target==='state')){const index=predicate.at.end?variant.steps().length-1:predicate.at.milestone==='initial'?-1:variant.steps().findIndex(step=>step.id===predicate.at.stepId);assert.ok(index>=0||predicate.at.milestone==='initial','Missing independent checkpoint '+predicate.at.stepId);const state=reconstructProtocolState(variant,index);const value=predicate.path.split('.').reduce((v,key)=>v?.[key],state);assert.deepEqual(value,predicate.equals,row.planId+'/'+c.id+'/'+predicate.path+' @ '+(predicate.at.stepId||'end'));}
    });
    assert.throws(()=>model.withVariant('not-authored'),RangeError);
  }
});

test('NFS01 does not grant client data at receipt; accepted authentication is not file authorization',()=>{
  const positive=NFSLAB_CASE('NFS01');assert.equal(at(positive,'gss-server-accept').authentication,true);assert.equal(at(positive,'gss-mutual-reply').clientContext,false);assert.equal(at(positive,'result-wire').clientBytes,null);assert.equal(at(positive,'result-wire').clientAccepted,false);assert.equal(at(positive,'result-verify').clientAccepted,true);assert.equal(end(positive).contextDestroyed,true);
  const denied=NFSLAB_CASE('NFS01','read-denied');assert.equal(end(denied).authentication,true);assert.equal(end(denied).clientAccepted,false);assert.equal(end(denied).dispatchCount,0);assert.equal(end(denied).stateid,null);assert.equal(end(denied).unrelatedBobContext,'accepted-bob-generation1');
  const corrupt=NFSLAB_CASE('NFS01','corrupt-result');assert.equal(end(corrupt).dispatchCount,1);assert.equal(end(corrupt).clientBytes,null);
});

test('Version-specific bootstrap and state counters cannot migrate across NFS versions',()=>{
  const operations=code=>NFSLAB_CASE(code).steps().flatMap(s=>s.nfsFrame?.operations||[]);
  assert.ok(NFSLAB_CASE('NFS03').steps().some(s=>s.nfsStage==='mount-request'));assert.ok(!operations('NFS03').some(op=>['SEQUENCE','OPEN','SETCLIENTID','EXCHANGE_ID'].includes(op)));
  const v40=operations('NFS05');assert.ok(v40.includes('SETCLIENTID'));assert.ok(v40.includes('SETCLIENTID_CONFIRM'));assert.ok(!v40.some(op=>['SEQUENCE','EXCHANGE_ID','CREATE_SESSION'].includes(op)));
  const v42=operations('NFS01');assert.ok(v42.includes('EXCHANGE_ID'));assert.ok(v42.includes('CREATE_SESSION'));assert.ok(v42.includes('SEQUENCE'));assert.ok(!v42.includes('SETCLIENTID'));
  assert.equal(at(NFSLAB_CASE('NFS06'),'exchange-id-policy').mustEnforce.includes('BIND_CONN_TO_SESSION'),true);
  const v41=NFSLAB_CASE('NFS06');assert.equal(v41.steps().find(s=>s.nfsStage==='create-session').nfsFrame.rpcContext,'machine');assert.equal(v41.steps().find(s=>s.nfsStage==='namespace-open').nfsFrame.rpcContext,'user');assert.equal(v41.steps().find(s=>s.nfsStage==='close-request').nfsFrame.rpcContext,'user','must_allow permits machine fallback but does not require machine CLOSE');
});

test('krb5 argument modification is not a fabricated body-MIC failure; replay differs from session retry',()=>{
  const weak=NFSLAB_CASE('NFS02','alter-krb5-argument');assert.equal(end(weak).clientAccepted,true);assert.equal(end(weak).failure,null);assert.match(end(weak).clientBytes,/offset=4096/);
  for(const id of ['alter-integrity-body','alter-privacy-ciphertext']){const model=NFSLAB_CASE('NFS02',id);assert.equal(end(model).firstDetector,'rpc-body-verify');assert.equal(end(model).dispatchCount,0);}
  const duplicate=NFSLAB_CASE('NFS02','repeat-gss-sequence');assert.equal(at(duplicate,'rpc-sequence-check').clientKnowsFailure,false);assert.equal(end(duplicate).dispatchCount,0);
  const retry=NFSLAB_CASE('NFS10','session-retry');assert.equal(end(retry).dispatchCount,1);assert.equal(end(retry).slotReplay,true);assert.equal(end(retry).gssSequence,9);assert.equal(at(retry,'result-verify').slotSequence,2);assert.equal(end(retry).slotSequence,3);assert.equal(at(retry,'response-timeout').clientBytes,null);assert.equal(at(retry,'response-timeout').slotSequence,1);assert.equal(at(retry,'response-timeout').serverSlotSequence,2);
});

test('AUTH_SYS assertion, squash and TLS host proof remain separate from user authentication',()=>{
  assert.equal(end(NFSLAB_CASE('NFS03','forged-uid')).authentication,false);assert.equal(end(NFSLAB_CASE('NFS03','forged-uid')).clientAccepted,true);
  const root=end(NFSLAB_CASE('NFS03','root-squash'));assert.equal(root.effectiveIdentity.uid,65534);assert.equal(root.clientAccepted,false);
  const tls=end(NFSLAB_CASE('NFS11','forged-uid'));assert.equal(tls.transportAccepted,true);assert.equal(tls.authentication,false);assert.equal(tls.clientAccepted,true);
});

test('Security discovery consumes the v4.1 filehandle and never weakens pinned privacy minimum',()=>{
  const normal=NFSLAB_CASE('NFS07');assert.equal(at(normal,'wrongsec').wrongsecOperation,'LOOKUP');assert.equal(at(normal,'secinfo-server').currentFilehandle,null);assert.equal(end(normal).selectedTuple.service,3);
  assert.equal(end(NFSLAB_CASE('NFS07','tampered-discovery')).dispatchCount,0);assert.equal(end(NFSLAB_CASE('NFS07','consumed-filehandle')).firstDetector,'secinfo-structure');
});

test('Required TLS and vendor unsupported profiles stop before invented protocol success',()=>{
  for(const c of worksheet.scenarios.find(r=>r.planId==='NFS12').canonicalCases){const model=NFSLAB_CASE('NFS12',c.id);assert.equal(end(model).transportAccepted,false);assert.equal(end(model).decodedRpc,false);assert.equal(end(model).dispatchCount,0);assert.equal(model.steps().some(s=>s.nfsStage==='rpc-request'),false);}
  const unsupported=NFSLAB_CASE('NFS12','unsupported-auth-tls');assert.equal(unsupported.steps().some(s=>s.nfsStage==='tls-clienthello'),false);
  for(const id of ['windows-client-v41','windows-server-v42']){const model=NFSLAB_CASE('NFS13',id);assert.equal(end(model).firstDetector,'profile-support');assert.equal(end(model).authentication,false);}
  assert.equal(end(NFSLAB_CASE('NFS13','mapping-failed')).authentication,true);assert.equal(end(NFSLAB_CASE('NFS13','acl-denied')).authentication,true);
});

test('SECINFO queries use the right cached handle, actual offered tuples and fresh NFS slot sequences',()=>{
  const named=NFSLAB_CASE('NFS07');assert.equal(at(named,'secinfo-putfh').currentFilehandle,'HANDLE(parent)');assert.equal(at(named,'secinfo-server').currentFilehandle,null);assert.equal(named.steps().find(s=>s.nfsStage==='namespace-open').nfsFrame.slotSequence,3);assert.equal(at(named,'result-verify').slotSequence,4);assert.equal(end(named).slotSequence,5);
  const noName=NFSLAB_CASE('NFS07','secinfo-no-name');assert.equal(at(noName,'secinfo-putfh').currentFilehandle,'HANDLE(private boundary)');assert.equal(at(noName,'secinfo-server').currentFilehandle,null);assert.equal(end(noName).clientAccepted,true);
  for(const id of ['no-common-tuple','tampered-discovery']){const denied=NFSLAB_CASE('NFS07',id);assert.equal(end(denied).selectedTuple,null);assert.equal(end(denied).dispatchCount,0);assert.equal(end(denied).sec,'krb5i');assert.equal(denied.steps().some(s=>s.nfsStage==='rpc-request'),false);}
  assert.equal(at(NFSLAB_CASE('NFS07','tampered-discovery'),'secinfo-server').secinfoQueryFlavor,1);
  const consumed=NFSLAB_CASE('NFS07','consumed-filehandle');assert.equal(consumed.steps().find(s=>s.nfsStage==='secinfo-query').nfsFrame.operations.includes('GETFH'),true);assert.equal(at(consumed,'secinfo-structure').serverKnowsFailure,true);assert.equal(at(consumed,'secinfo-structure').clientKnowsFailure,false);assert.equal(end(consumed).clientKnowsFailure,true);assert.equal(end(consumed).sec,'krb5i');
});

test('NFS05 AUTH_SYS refusal is server-local until the actual namespace error is received and accepted',()=>{
  const model=NFSLAB_CASE('NFS05','sys-refused');
  assert.equal(at(model,'namespace-security').serverKnowsFailure,true);
  for(const stage of ['namespace-security','namespace-security-failure-create','namespace-security-failure-wire']){
    assert.equal(at(model,stage).clientKnowsFailure,false,stage);
    assert.equal(at(model,stage).clientAccepted,false,stage);
  }
  assert.equal(at(model,'namespace-security-failure-accept').clientKnowsFailure,true);
  assert.equal(end(model).dispatchCount,0);assert.equal(end(model).stateid,null);
  assert.equal(model.steps().some(step=>step.nfsStage==='open-policy-ipc'),false,'The rejected namespace compound cannot proceed to OPEN authorization');
});
