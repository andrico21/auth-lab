import {test} from 'node:test';
import assert from 'node:assert/strict';
import {SPAKELAB_SCENARIOS} from '../src/kerberos-spake-lab.js';
import {buildSpakeHeldObjects} from '../src/held-object-spake.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';

function fixture(branch){
 const model=SPAKELAB_SCENARIOS.find(item=>item.id==='lab-krb-spake-'+branch),steps=model.steps({});
 const plan=buildSpakeHeldObjects({model,steps,actors:model.actors({}),contextId:'ksp-behavior-'+branch});
 const compiled=compileHeldObjects(plan,{model,steps});
 const index=boundary=>{
  const value=steps.findIndex(step=>step.id===model.id+'-'+boundary);
  assert.notEqual(value,-1,'Missing protocol boundary '+boundary);
  return value;
 };
 const at=boundary=>projectHeldObjects(compiled,{eventIndex:index(boundary)});
 const before=boundary=>projectHeldObjects(compiled,{eventIndex:index(boundary),progress:0.99});
 const initial=projectHeldObjects(compiled,{eventIndex:-1});
 const holdings=(snapshot,key,actor)=>snapshot.holdings.filter(holding=>holding.artifactId===model.id+':'+key&&(!actor||holding.actorId===actor));
 const view=(snapshot,key,actor,representation)=>{
  const holding=holdings(snapshot,key,actor).find(item=>item.representationId===representation);
  assert.ok(holding,'Missing '+actor+' '+representation+' holding of '+key);
  return inspectHeldObject(snapshot,holding.holdingId);
 };
 return {model,steps,compiled,index,at,before,initial,holdings,view};
}

for(const branch of ['success','downgrade-allowed','optimistic-accepted','optimistic-renegotiate','client-optimistic'])test(branch+': ticket receipt, decoded validation and installed credentials have distinct holdings',()=>{
 const f=fixture(branch);
 assert.equal(f.holdings(f.initial,'tgt','spake-client').length,0);
 const before=f.before('as-receive'),received=f.at('as-receive');
 assert.equal(f.holdings(before,'tgt','spake-client').length,0);
 const opaque=f.view(received,'tgt','spake-client','opaque');
 assert.equal(opaque.representation.readable,true);
 assert.ok(opaque.fields.every(field=>field.readable));
 assert.ok(opaque.fields.some(field=>field.name==='ticket-bytes'));
 assert.ok(!opaque.fields.some(field=>['client','session-key','server'].includes(field.name)));
 assert.equal(f.holdings(received,'as-material','spake-client').filter(h=>h.representationId==='decoded').length,0);
 assert.equal(f.holdings(received,'tgt-session','spake-client').length,0);
 assert.ok(!f.holdings(received,'tgt','spake-client').some(h=>h.store==='credential cache'));
 const validated=f.at('client-validate');
 const decoded=f.view(validated,'as-material','spake-client','decoded');
 assert.ok(decoded.fields.every(field=>field.readable));
 const issued=f.view(f.at('as-create'),'tgt-session','spake-kdc','local');
 const accepted=f.view(validated,'tgt-session','spake-client','local');
 assert.equal(issued.artifact.artifactId,accepted.artifact.artifactId);
 assert.deepEqual(issued.fields,accepted.fields);
 const nonce=decoded.fields.find(field=>field.name==='nonce').value;
 const request=branch==='client-optimistic'?f.at('support'):f.at('request');
 assert.equal(nonce,f.view(request,'request','spake-client','wire').fields.find(field=>field.name==='nonce').value);
 assert.ok(!f.holdings(validated,'tgt','spake-client').some(h=>h.store==='credential cache'));
 assert.ok(f.holdings(f.at('cache'),'tgt','spake-client').some(h=>h.store==='credential cache'));
 assert.ok(!f.holdings(f.at('tgs-reply'),'service-session','spake-client').some(h=>h.store==='credential cache'));
 assert.ok(f.holdings(f.at('service-cache'),'service-session','spake-client').some(h=>h.store==='credential cache'));
 assert.ok(f.holdings(f.at('service-validate'),'service-session','spake-service').some(h=>h.store==='authenticated context'&&h.retention==='retained'));
 const trace=heldObjectTrace(f.compiled,f.model.id+':tgt');
 const receipt=trace.find(row=>row.sourceIndex===f.index('as-receive'));
 assert.equal(receipt.inspectionActorId,'spake-client');
 assert.ok(receipt.payload.every(field=>!field.redacted));
 assert.ok(receipt.payload.some(field=>field.name==='ticket-bytes'));
 assert.ok(!receipt.payload.some(field=>['client','session-key','server'].includes(field.name)));
 assert.ok(trace.some(row=>row.sourceIndex===f.index('cache')&&row.traceKind.includes('observe')));
 const replayed=projectHeldObjects(f.compiled,{eventIndex:f.index('as-receive')});
 assert.equal(f.holdings(replayed,'tgt-session','spake-client').length,0);
});

test('issuers hold their actual ticket keys while client carriers cannot decode ticket bodies or cookies',()=>{
 const f=fixture('success');
 assert.equal(f.view(f.initial,'realm-key','spake-kdc','local').representation.readable,true);
 assert.equal(f.view(f.initial,'service-key','spake-tgs','local').representation.readable,true);
 const issued=f.at('as-create');
 const reply=f.view(issued,'kdc-reply-key','spake-kdc','local');
 const realm=f.view(issued,'realm-key','spake-kdc','local');
 assert.notEqual(reply.artifact.artifactId,realm.artifact.artifactId);
 assert.notDeepEqual(reply.fields.map(field=>field.value),realm.fields.map(field=>field.value));
 assert.equal(f.view(issued,'tgt','spake-kdc','decoded').representation.readable,true);
 assert.equal(f.view(f.at('tgs-validate'),'tgt','spake-tgs','decoded').representation.readable,true);
 assert.equal(f.view(f.at('tgs-validate'),'service-ticket','spake-tgs','decoded').representation.readable,true);
 assert.equal(f.view(f.at('service-validate'),'service-ticket','spake-service','decoded').representation.readable,true);
 const cookie=f.view(f.at('challenge'),'cookie','spake-client','opaque');
 assert.equal(cookie.representation.readable,true);
 assert.ok(!cookie.fields.some(field=>field.name==='state'));
 assert.equal(f.view(f.at('kdc-challenge-create'),'cookie','spake-kdc','decoded').representation.readable,true);
 for(let i=0;i<f.steps.length;i++){
  const snapshot=projectHeldObjects(f.compiled,{eventIndex:i});
  for(const holding of snapshot.holdings.filter(item=>item.actorId==='spake-client')){
   assert.ok(!['x','kdc-shared','kdc-factor-key','kdc-reply-key','realm-key','service-key'].some(key=>holding.artifactId===f.model.id+':'+key));
   if(['tgt','service-ticket','cookie'].some(key=>holding.artifactId===f.model.id+':'+key))assert.notEqual(holding.representationId,'decoded');
  }
 }
 const validation=heldObjectTrace(f.compiled,f.model.id+':as-material').find(row=>row.sourceIndex===f.index('client-validate'));
 assert.ok(validation.traceKind.includes('observe'));
 assert.equal(validation.inspectionActorId,'spake-client');
 assert.ok(validation.payload.some(field=>field.name==='session-key'&&!field.redacted));
});

for(const branch of ['success','wrong-password','no-common-group','downgrade-allowed','downgrade-blocked','optimistic-accepted','optimistic-renegotiate','client-optimistic'])test(branch+': endpoint cleanup preserves other endpoints and unrelated configured credentials',()=>{
 const f=fixture(branch);
 const cleanups=[['kdc-cleanup','spake-kdc'],['tgs-cleanup','spake-tgs'],['service-cleanup','spake-service'],['observer-cleanup','spake-observer'],['client-cleanup','spake-client'],['session','spake-client']];
 for(const [boundary,actor] of cleanups){
  if(!f.steps.some(step=>step.id===f.model.id+'-'+boundary))continue;
  const before=f.before(boundary),after=f.at(boundary);
  const other=snapshot=>snapshot.holdings.filter(h=>h.actorId!==actor).map(h=>h.holdingId).sort();
  assert.deepEqual(other(after),other(before),'remote holdings at '+boundary);
  assert.ok(!after.holdings.some(h=>h.actorId===actor&&h.retention==='temporary'),'own scratch at '+boundary);
  for(const holding of before.holdings.filter(h=>h.actorId===actor&&h.retention==='retained'))assert.ok(after.holdings.some(h=>h.holdingId===holding.holdingId),'retained key or cache at '+boundary);
 }
 const final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1});
 assert.ok(f.holdings(final,'unrelated','spake-client').some(h=>h.store==='credential cache'));
});

for(const branch of ['wrong-password','no-common-group','downgrade-blocked'])test(branch+': every failed prefix has no issued ticket or accepted service key',()=>{
 const f=fixture(branch);
 for(let i=0;i<f.steps.length;i++){
  const snapshot=projectHeldObjects(f.compiled,{eventIndex:i});
  assert.equal(f.holdings(snapshot,'tgt').length,0);
  assert.equal(f.holdings(snapshot,'tgt-session').length,0);
  assert.equal(f.holdings(snapshot,'service-ticket').length,0);
  assert.equal(f.holdings(snapshot,'service-session').length,0);
  if(branch!=='wrong-password')for(const key of ['x','y','client-shared','kdc-shared','kdc-reply-key'])assert.equal(f.holdings(snapshot,key).length,0);
 }
});

test('timestamp fallback acquires no SPAKE secrets or strengthened reply key',()=>{
 const f=fixture('downgrade-allowed');
 for(let i=0;i<f.steps.length;i++){
  const snapshot=projectHeldObjects(f.compiled,{eventIndex:i});
  for(const key of ['x','y','client-shared','kdc-shared','client-transcript','kdc-transcript','client-reply-key','kdc-reply-key'])assert.equal(f.holdings(snapshot,key).length,0);
 }
 assert.equal(f.view(f.at('timestamp-validate'),'fallback-reply-key','spake-kdc','local').representation.readable,true);
 assert.equal(f.holdings(f.at('timestamp-request'),'tgt','spake-client').length,0);
 assert.ok(f.holdings(f.at('cache'),'tgt','spake-client').some(h=>h.store==='credential cache'));
});

test('rejected optimistic generation is disposed independently before generation1 derivation',()=>{
 const f=fixture('optimistic-renegotiate');
 const proposed=f.at('optimistic-challenge');
 assert.equal(f.view(proposed,'optimistic-challenge','spake-client','wire').fields.find(field=>field.name==='group').value,2);
 const oldScalar=f.holdings(proposed,'optimistic-x','spake-kdc')[0];
 assert.ok(oldScalar);
 const clientReset=f.at('transcript-reset');
 assert.equal(f.holdings(clientReset,'optimistic-challenge','spake-client').length,0);
 assert.equal(f.holdings(clientReset,'optimistic-cookie','spake-client').length,0);
 assert.ok(f.holdings(clientReset,'optimistic-x','spake-kdc').some(h=>h.holdingId===oldScalar.holdingId));
 const kdcReset=f.at('kdc-transcript-reset');
 assert.ok(!kdcReset.holdings.some(h=>h.artifactId.startsWith(f.model.id+':optimistic-')));
 assert.equal(f.holdings(kdcReset,'x','spake-kdc').length,0);
 const challenge=f.at('challenge');
 assert.equal(f.view(challenge,'challenge','spake-client','wire').fields.find(field=>field.name==='group').value,1);
 assert.deepEqual(f.view(challenge,'support','spake-kdc','wire').fields.find(field=>field.name==='groups').value,[1]);
 const fresh=f.view(challenge,'x','spake-kdc','local');
 assert.equal(fresh.artifact.generation,1);
 assert.notEqual(fresh.artifact.artifactId,oldScalar.artifactId);
 assert.equal(f.holdings(challenge,'client-shared','spake-client').length,0);
 const derived=f.at('client-derive');
 assert.equal(f.view(derived,'client-shared','spake-client','local').artifact.generation,1);
 assert.ok(!derived.holdings.some(h=>h.artifactId.startsWith(f.model.id+':optimistic-')));
});

for(const branch of ['optimistic-accepted','client-optimistic'])test(branch+': enctype, salt and challenge are received before local derivation',()=>{
 const f=fixture(branch),challenge=f.at('challenge');
 const etype=f.view(challenge,'etype','spake-client','wire');
 assert.equal(etype.fields.find(field=>field.name==='enctype').value,17);
 assert.ok(etype.fields.find(field=>field.name==='salt').readable);
 assert.equal(f.holdings(challenge,'initial-key','spake-client').length,0);
 assert.equal(f.holdings(challenge,'client-shared','spake-client').length,0);
 assert.equal(f.view(f.at('client-derive'),'initial-key','spake-client','local').representation.readable,true);
 assert.equal(f.holdings(f.at('client-derive'),'tgt','spake-client').length,0);
});

for(const branch of ['success','wrong-password','no-common-group'])test(branch+': initial conversation cookie is an exact opaque echo with independent replacement/disposal',()=>{
 const f=fixture(branch),advertisement=f.at('advertisement');
 const initial=f.view(advertisement,'initial-cookie','spake-client','opaque');
 assert.ok(initial.fields.every(field=>field.name==='cookie-bytes'&&field.readable));
 assert.ok(f.view(advertisement,'initial-cookie','spake-kdc','decoded').fields.every(field=>field.name==='state'&&field.readable));
 assert.ok(!f.holdings(advertisement,'initial-cookie','spake-client').some(holding=>holding.representationId==='decoded'));
 const echoed=f.view(f.at('support'),'initial-cookie','spake-kdc','opaque');
 assert.deepEqual(echoed.fields,initial.fields);
 const sent=f.steps.find(step=>step.id===f.model.id+'-support').payload.find(field=>field.attributeId==='kspInitialCookieCookieBytes');
 assert.equal(sent.value,initial.fields[0].value);
 if(branch==='no-common-group'){
  assert.equal(f.holdings(f.at('kdc-cleanup'),'initial-cookie','spake-kdc').length,0);
  assert.ok(f.holdings(f.at('kdc-cleanup'),'initial-cookie','spake-client').length);
  assert.equal(f.holdings(f.at('client-cleanup'),'initial-cookie','spake-client').length,0);
 }else{
  const created=f.at('kdc-challenge-create');
  assert.equal(f.holdings(created,'initial-cookie','spake-kdc').length,0);
  assert.ok(f.holdings(created,'initial-cookie','spake-client').length,'replacement is not yet received');
  const challenge=f.at('challenge');
  assert.equal(f.holdings(challenge,'initial-cookie','spake-client').length,0);
  const replacement=f.view(challenge,'cookie','spake-client','opaque');
  assert.notEqual(replacement.artifact.artifactId,initial.artifact.artifactId);
  assert.notDeepEqual(replacement.fields,initial.fields);
  assert.deepEqual(f.view(f.at('response'),'cookie','spake-kdc','opaque').fields,replacement.fields);
 }
 const final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1});
 assert.equal(f.holdings(final,'initial-cookie').length,0);
});

test('attribute local moments and exact holding events share derivation, cache and disposal source boundaries',()=>{
 const f=fixture('success');
 for(const [key,field,actor,boundaries] of [
  ['initial-key','kspInitialKeyKey','spake-client',[['client-derive','derive'],['session','evict']]],
  ['client-shared','kspClientSharedK','spake-client',[['client-derive','derive'],['session','evict']]],
  ['client-reply-key','kspClientReplyKeyKey','spake-client',[['client-derive','derive'],['client-validate','use'],['session','evict']]],
  ['tgt-session','kspTgtSessionKey','spake-client',[['client-validate','verify'],['cache','store'],['session','evict']]],
 ]){
  const trace=heldObjectTrace(f.compiled,f.model.id+':'+key);
  for(const [suffix,kind] of boundaries){
   const step=f.steps[f.index(suffix)];
   const operation=step.attributeOperations.find(item=>item.attributeId===field&&item.actorId===actor&&item.kind===kind);
   assert.ok(operation,key+' '+kind+' at '+suffix);
   if(kind==='evict'){
    assert.ok(f.holdings(f.before(suffix),key,actor).some(holding=>holding.retention==='temporary'));
    assert.ok(!f.holdings(f.at(suffix),key,actor).some(holding=>holding.retention==='temporary'));
   }else assert.ok(f.holdings(f.at(suffix),key,actor).length);
   assert.ok(trace.some(row=>row.sourceIndex===f.index(suffix)),key+' exact history at '+suffix);
  }
 }
});
