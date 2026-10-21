import {test} from 'node:test';
import assert from 'node:assert/strict';
import {SPAKELAB_SCENARIOS} from '../src/kerberos-spake-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const modelFor=branch=>SPAKELAB_SCENARIOS.find(model=>model.id==='lab-krb-spake-'+branch);
const indexOf=(model,boundary)=>{
 const index=model.steps({}).findIndex(step=>step.id===model.id+'-'+boundary);
 assert.notEqual(index,-1,'Missing protocol boundary '+boundary);
 return index;
};
const at=(model,boundary)=>reconstructProtocolState(model,indexOf(model,boundary));
const before=(model,boundary)=>reconstructProtocolState(model,indexOf(model,boundary)-1);

for(const branch of ['success','downgrade-allowed','optimistic-accepted','optimistic-renegotiate','client-optimistic'])test(branch+': receipt, verification, cache acceptance and mutual authentication are separate',()=>{
 const model=modelFor(branch);
 const initial=reconstructProtocolState(model,-1);
 for(const boundary of ['as-create','as-receive','client-validate']){
  const state=at(model,boundary);
  assert.equal(state.credentials.tgt,false,boundary);
  assert.equal(state.credentials.serviceTicket,false,boundary);
  assert.equal(state.session.established,false,boundary);
  assert.deepEqual(state.unrelated,initial.unrelated,boundary);
 }
 assert.equal(before(model,'as-receive').as.received,undefined);
 assert.equal(at(model,'as-receive').as.received,true);
 assert.equal(at(model,'as-receive').as.validated,undefined);
 assert.equal(at(model,'client-validate').as.validated,true);
 assert.equal(before(model,'cache').credentials.tgt,false);
 assert.equal(at(model,'cache').credentials.tgt,true);
 assert.equal(at(model,'cache').credentials.mechanism,branch==='downgrade-allowed'?'encrypted-timestamp':'SPAKE');
 assert.equal(at(model,'tgs-reply').serviceTicket.received,true);
 assert.equal(at(model,'tgs-reply').credentials.serviceTicket,false);
 assert.equal(at(model,'tgs-reply').session.established,false);
 assert.equal(at(model,'service-cache').credentials.serviceTicket,true);
 assert.equal(before(model,'service-validate').service?.authenticatedClient,undefined);
 assert.equal(at(model,'service-validate').service.authenticatedClient,true);
 assert.equal(at(model,'ap-reply').session.established,false);
 assert.equal(at(model,'session').session.established,true);
 assert.deepEqual(at(model,'session').unrelated,initial.unrelated);
 const rewound=at(model,'as-receive');
 assert.equal(rewound.credentials.tgt,false);
 assert.equal(rewound.as.validated,undefined);
 assert.equal(rewound.session.established,false);
});

for(const branch of ['wrong-password','no-common-group','downgrade-blocked'])test(branch+': failed authentication never acquires credentials or erases unrelated state',()=>{
 const model=modelFor(branch),initial=reconstructProtocolState(model,-1),steps=model.steps({});
 for(let i=0;i<steps.length;i++){
  const state=reconstructProtocolState(model,i);
  assert.equal(state.credentials.tgt,false,'TGT at source prefix '+i);
  assert.equal(state.credentials.serviceTicket,false,'service credential at source prefix '+i);
  assert.equal(state.session.established,false,'application session at source prefix '+i);
  assert.equal(state.as?.created,undefined,'accepted AS reply at source prefix '+i);
  assert.deepEqual(state.unrelated,initial.unrelated,'unrelated state at source prefix '+i);
 }
 const final=reconstructProtocolState(model,steps.length-1);
 assert.equal(final.terminal,branch);
});

test('wrong password fails at the KDC before the client learns the failure',()=>{
 const model=modelFor('wrong-password');
 assert.equal(at(model,'response').response.received,true);
 assert.equal(at(model,'response').kdc?.factorValidated,undefined);
 assert.equal(at(model,'kdc-reject').kdc.factorValidated,false);
 assert.equal(at(model,'kdc-reject').kdc.error,'KDC_ERR_PREAUTH_FAILED');
 assert.equal(at(model,'kdc-reject').knowledge.client?.error,undefined);
 assert.equal(at(model,'error-receive').knowledge.client.error,'KDC_ERR_PREAUTH_FAILED');
 assert.equal(at(model,'error-receive').credentials.tgt,false);
});

test('disjoint configured groups reject without manufacturing a shared key',()=>{
 const model=modelFor('no-common-group');
 assert.equal(at(model,'group-reject').negotiation.commonGroup,false);
 assert.equal(at(model,'group-reject').kdc.error,'KDC_ERR_PREAUTH_FAILED');
 assert.equal(at(model,'group-reject').knowledge.client?.error,undefined);
 assert.equal(at(model,'error-receive').knowledge.client.error,'KDC_ERR_PREAUTH_FAILED');
 assert.equal(at(model,'group-reject').client?.keysDerived,undefined);
});

test('advertisement suppression changes only the explicitly selected timestamp fallback policy',()=>{
 const blocked=modelFor('downgrade-blocked'),allowed=modelFor('downgrade-allowed');
 for(const model of [blocked,allowed]){
  const delivered=at(model,'advertisement-stripped');
  assert.equal(delivered.negotiation.advertisementSuppressed,true);
  assert.equal(delivered.credentials.tgt,false);
  assert.equal(delivered.client?.keysDerived,undefined);
  assert.equal(delivered.kdc?.timestampValidated,undefined);
 }
 assert.equal(at(blocked,'policy-stop').policy.fallback,'blocked');
 assert.equal(at(blocked,'policy-stop').credentials.tgt,false);
 assert.equal(at(allowed,'fallback-policy').policy.fallback,'encrypted-timestamp');
 assert.equal(at(allowed,'timestamp-request').kdc?.timestampValidated,undefined);
 assert.equal(at(allowed,'timestamp-validate').kdc.timestampValidated,true);
 assert.equal(at(allowed,'timestamp-validate').credentials.tgt,false);
 assert.equal(at(allowed,'cache').credentials.mechanism,'encrypted-timestamp');
});

test('optimistic renegotiation resets endpoint transcript state before accepting generation1',()=>{
 const model=modelFor('optimistic-renegotiate');
 const proposed=at(model,'optimistic-challenge');
 assert.equal(proposed.negotiation.optimisticGroup,2);
 assert.equal(proposed.negotiation.generation,0);
 assert.equal(proposed.client?.keysDerived,undefined);
 const clientReset=at(model,'transcript-reset');
 assert.equal(clientReset.negotiation.generation,1);
 assert.equal(clientReset.negotiation.clientTranscriptReset,true);
 assert.equal(clientReset.negotiation.kdcTranscriptReset,undefined);
 assert.equal(clientReset.credentials.tgt,false);
 assert.equal(at(model,'kdc-transcript-reset').negotiation.kdcTranscriptReset,true);
 assert.equal(at(model,'challenge').client?.keysDerived,undefined);
 assert.equal(at(model,'client-derive').client.keysDerived,true);
 assert.equal(at(model,'client-derive').credentials.tgt,false);
});
