import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SPAKELAB_SCENARIOS} from '../src/kerberos-spake-lab.js';
import {PAKELAB_SCENARIOS} from '../src/pake-lab.js';
import {installHarness} from './dom-harness.mjs';
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
function mounted(run){const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();try{run(app);}finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}}
const spake=branch=>SPAKELAB_SCENARIOS.find(model=>model.id==='lab-krb-spake-'+branch);
const fixture=name=>JSON.parse(readFileSync(new URL('../tools/verification/expansion-crypto/fixtures/'+name+'.json',import.meta.url),'utf8'));

test('first-pass and post-support KRB-ERROR envelopes have explicit distinct codes',()=>{
 for(const [branch,suffix,code,name] of [['success','advertisement',25,'KDC_ERR_PREAUTH_REQUIRED'],['success','challenge',91,'KDC_ERR_MORE_PREAUTH_DATA_REQUIRED'],['optimistic-accepted','challenge',25,'KDC_ERR_PREAUTH_REQUIRED'],['optimistic-renegotiate','optimistic-challenge',25,'KDC_ERR_PREAUTH_REQUIRED'],['optimistic-renegotiate','challenge',91,'KDC_ERR_MORE_PREAUTH_DATA_REQUIRED'],['client-optimistic','challenge',91,'KDC_ERR_MORE_PREAUTH_DATA_REQUIRED']]){
  const model=spake(branch),step=model.steps({}).find(step=>step.id===model.id+'-'+suffix);
  assert.deepEqual(step.errorEnvelope,{messageType:'KRB-ERROR',code,name});
  assert.match(step.protocolLabel,new RegExp('^'+name+':'));
  assert.deepEqual(step.payload.find(field=>field.name==='KRB-ERROR').value,step.errorEnvelope);
 }
});

test('mounted SPAKE local attributes replay original derivation, validation, cache and eviction cursors',()=>mounted(app=>{
 app.selectLabScenario('lab-krb-spake-success',{navigate:false});
 for(const [field,boundaries] of [
  ['kspInitialKeyKey',[['client-derive','derive'],['session','evict']]],
  ['kspClientSharedK',[['client-derive','derive'],['session','evict']]],
  ['kspClientReplyKeyKey',[['client-derive','derive'],['client-validate','use'],['session','evict']]],
  ['kspTgtSessionKey',[['as-create','derive'],['client-validate','verify'],['cache','store'],['session','evict']]],
 ]){
  app.selectAttribute(field,false);
  for(const [suffix,kind] of boundaries){
   const row=app.traceQueue.find(row=>row.sourceStepId==='lab-krb-spake-success-'+suffix&&row.traceKind===kind);
   assert.ok(row,field+' '+kind+' at '+suffix);
   assert.equal(row.from,suffix==='as-create'?'spake-kdc':'spake-client');
   assert.ok(row.payload.some(item=>item.attributeId===field&&String(item.value).includes('symbolic')));
   assert.equal(row.sourceIndex,app.steps.findIndex(step=>step.id===row.sourceStepId));
   assert.deepEqual(row.protocolEffects,app.steps[row.sourceIndex].protocolEffects);
   assert.ok(!app.stepHtml(row,0).includes('undefined '));
  }
  assert.ok(!app.refs.inspector.textContent.includes('This is configured context;'));
 }
 app.selectLabScenario('lab-krb-spake-downgrade-blocked',{navigate:false});
 app.selectAttribute('kspPolicyDisableEncryptedTimestamp',false);
 assert.equal(app.traceQueue.length,0,'a genuine context-only policy reference stays non-replayable');
}));

test('PAKE attribute cleanup uses labeled eviction while canonical held effects release',()=>mounted(app=>{
 for(const id of ['lab-pake-spake2-success','lab-pake-spake2-transcript-reject','lab-pake-spake2plus-transcript-reject']){
  app.selectLabScenario(id,{navigate:false});
  for(const field of ['pake_x','pake_shareA']){
   app.selectAttribute(field,false);
   const cleanup=app.traceQueue.filter(row=>row.traceKind==='evict');
   assert.ok(cleanup.length,id+' '+field+' cleanup');
   for(const row of app.traceQueue)assert.ok(!app.stepHtml(row,0).includes('undefined '));
   assert.ok(cleanup.every(row=>row.title.startsWith('Evict ')));
  }
  const model=PAKELAB_SCENARIOS.find(model=>model.id===id);
  assert.ok(Object.values(model.pakeInventory.events).some(event=>event.effects.some(effect=>effect.op==='release')));
 }
}));

test('single role-asymmetric transcript exchange maps unchanged official endpoint and actual first confirmation',()=>{
 const synthetic=fixture('synthetic');
 for(const [plus,family,changed,unchanged] of [[false,'rfc9382','A','B'],[true,'rfc9383','P','V']]){
  const official=fixture(family),negative=synthetic[family].transcriptMismatch;
  const names=plus?['TT','K_main','K_confirmP','K_confirmV','K_shared']:['TT','Ke','Ka','KcA','KcB'];
  for(const name of names){assert.equal(negative[unchanged][name],official[name],unchanged+' official '+name);assert.notEqual(negative[changed][name],negative[unchanged][name],changed+' changed '+name);}
  const tag=plus?'confirmV':'cA',sender=plus?'V':'A',receiver=plus?'P':'B';
  assert.equal(negative[unchanged][tag],official[plus?'HMAC(K_confirmV, shareP)':'A conf']);
  assert.notEqual(negative[sender][tag],negative[receiver][tag],'actual first sent tag fails receiver expectation');
  const model=PAKELAB_SCENARIOS.find(model=>model.id==='lab-pake-'+(plus?'spake2plus':'spake2')+'-transcript-reject'),steps=model.steps({});
  const deriveA=steps.find(step=>step.pakeStage==='derive-a'),deriveB=steps.find(step=>step.pakeStage==='derive-b');
  const field=plus?'pake_context':'pake_identityB';
  assert.equal(deriveA.payload.find(item=>item.attributeId===field).value,plus?official.context+' altered':'client-altered');
  assert.equal(deriveB.payload.find(item=>item.attributeId===field).value,plus?official.context:'client');
  for(const [step,role] of [[deriveA,changed],[deriveB,unchanged]])assert.ok(step.payload.filter(item=>['pake_transcript','pake_schedule'].includes(item.attributeId)).every(item=>item.value.includes('#/'+family+'/transcriptMismatch/'+role)));
  const first=steps.find(step=>step.pakeStage==='create-confirm-'+(plus?'b':'a'));
  assert.ok(first.payload.some(item=>item.value.includes('/'+sender+'/'+tag)));
  assert.ok(!steps.some(step=>step.pakeStage==='create-confirm-'+(plus?'a':'b')),'no reciprocal tag after rejection');
  assert.ok(!steps.flatMap(step=>step.protocolEffects).some(effect=>effect.path?.endsWith('.usable')&&effect.value===true));
 }
});
