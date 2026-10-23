import test from 'node:test';
import assert from 'node:assert/strict';
import {createJWTScenario} from '../src/jwt-validation-lab.js';
import {jwtRefreshDecision,jwtCompleteRefresh,jwtDecryptFixture} from '../src/jwt-policy.js';
import {buildJWTHeldObjects} from '../src/held-object-jwt.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject} from '../src/held-object-state.js';

function fixture(number,variant){
  const model=createJWTScenario(number,variant),steps=model.steps();
  const plan=buildJWTHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+variant,choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const index=stage=>{const i=steps.findIndex(s=>s.jwtStage===stage);assert.notEqual(i,-1,'Missing '+stage);return i;};
  return {model,steps,index,artifact:key=>model.jwtInventory.artifacts.find(a=>a.attributeId==='jwt'+String(number).padStart(2,'0')+'_'+key),frame:stage=>projectHeldObjects(compiled,{eventIndex:stage==='initial'?-1:index(stage),milestone:stage==='initial'?'initial':'complete'})};
}
function held(frame,artifact,actor='jwtAPI'){
  return frame.holdings.find(h=>h.actorId===actor&&h.artifactId===artifact.artifactId);
}
function visible(frame,artifact){const h=held(frame,artifact);assert.ok(h,artifact.artifactId);return inspectHeldObject(frame,h.holdingId).fields[0].value;}

for(const variant of ['stale-cache','unknown-kid-flood'])test('JK-01 '+variant+' admits original only after the timely refreshed generation2 response',()=>{
  const f=fixture(6,variant),policy=f.artifact('refresh-policy').value;
  assert.equal(f.steps.filter(s=>s.jwtStage==='refresh-request').length,1);
  assert.equal(f.index('refresh-request')<f.index('refresh-response'),true);
  assert.equal(f.index('refresh-response')<f.index('refresh'),true);
  assert.equal(f.index('refresh')<f.index('signature'),true);
  assert.equal(f.index('signature')<f.index('accept'),true);
  assert.equal(f.steps.some(s=>s.jwtStage==='refresh-deny'),false);
  assert.equal(policy.requestInstanceId,'lab-jwt06:token:g1');
  assert.equal(policy.requestedKid,'generation2');
  assert.deepEqual(policy.originalTokenDecision,{action:'coalesced',code:'refresh-in-flight'});
  for(const stage of ['new-token','refresh-policy','refresh-response','refresh']){
    const frame=f.frame(stage);
    assert.equal(frame.state.jwt.validatedClaims,null);
    assert.equal(frame.state.jwt.signatureValid,false);
    assert.equal(held(frame,f.artifact('accepted')),undefined);
  }
  const response=f.frame('refresh-response');
  assert.ok(held(response,f.artifact('refresh-response')));
  const installed=f.frame('refresh');
  assert.equal(installed.state.jwt.clock,1792627201);
  assert.equal(visible(installed,f.artifact('cache1')).fetchedAt,1792627201);
  assert.equal(f.artifact('signature-evidence').value.evidence.keyId,'issuer-public-generation2');
  assert.equal(f.frame('accept').state.jwt.validatedClaims.sub,'alice');
  assert.equal(f.frame('accept').state.jwt.failure,null);
  assert.equal(f.frame('unrelated-old-validate').state.jwt.cachedOldAccepted,variant!=='stale-cache');
  if(variant==='stale-cache')assert.equal(f.artifact('cache0').value.fetchedAt,1792626900);
});

test('JK-01 all 32 concrete flood arrivals retain individual admission and rejection identities',()=>{
  const f=fixture(6,'unknown-kid-flood'),policy=f.artifact('refresh-policy').value;
  const expected=Array.from({length:32},(_,n)=>({requestInstanceId:'flood-token'+n,kid:'unknown'+n,action:n<15?'coalesced':'deny',code:n<15?'refresh-in-flight':'refresh-bounded'}));
  assert.deepEqual(policy.floodDecisions,expected);
  assert.equal(policy.fetchCount,1);
  assert.equal(policy.pendingKeyCount,16);
  for(let n=15;n<32;n++){
    const stage='flood-deny-flood-token'+n,frame=f.frame(stage),artifact=f.artifact('flood-rejection-flood-token'+n),error=visible(frame,artifact);
    assert.deepEqual({action:error.action,requestInstanceId:error.requestInstanceId,kid:error.kid,code:error.code},expected[n]);
    assert.equal(error.cache.inFlight,true);
    assert.deepEqual(error.cache.pendingKids,['generation2',...Array.from({length:15},(_,i)=>'unknown'+i)]);
    assert.equal(error.cache.negativeKids.length<=16,true);
    assert.equal(frame.state.jwt.failure,null);
    assert.equal(frame.state.jwt.claimsAccepted,false);
  }
  const completed=visible(f.frame('refresh'),f.artifact('cache1'));
  assert.deepEqual(completed.negativeKids.map(e=>e.kid),Array.from({length:15},(_,i)=>'unknown'+i));
  assert.equal(completed.pendingKids.length,0);
  assert.equal(f.frame('accept').state.jwt.claimsAccepted,true);
});

test('JK-01 pure cache transitions reserve original slot and bound negative storage independently of the author',()=>{
  const issuer='https://rotation.test',old={id:'old',issuer,kid:'old'},next={id:'new',issuer,kid:'new'},now=1000;
  let decision=jwtRefreshDecision({cache:{issuer,keys:[old],fetchedAt:700,lastRefreshAt:null,inFlight:false,negativeKids:[]},kid:'new',now});
  assert.equal(decision.action,'refresh');
  assert.equal(decision.code,'stale-cache');
  let cache=decision.cache;
  for(let n=0;n<32;n++){
    decision=jwtRefreshDecision({cache,kid:'pressure-'+n,now});cache=decision.cache;
    assert.equal(decision.action,n<15?'coalesced':'deny');
    assert.equal(cache.pendingKids.length,Math.min(n+2,16));
  }
  assert.equal(jwtRefreshDecision({cache,kid:'new',now}).action,'coalesced');
  assert.notEqual(jwtRefreshDecision({cache,kid:'old',now}).action,'cached');
  const completed=jwtCompleteRefresh({cache,keys:[old,next],now:1001,ok:true});
  assert.equal(completed.ok,true);
  assert.equal(completed.cache.negativeKids.length,15);
  assert.equal(jwtRefreshDecision({cache:completed.cache,kid:'new',now:1001}).action,'cached');
});

for(const variant of ['refresh-timeout','retry-budget'])test('JK-01 '+variant+' denial artifact names the actual original request',()=>{
  const f=fixture(6,variant),error=visible(f.frame('refresh-deny'),f.artifact('refresh-rejection'));
  assert.equal(error.action,'deny');
  assert.equal(error.requestInstanceId,'lab-jwt06:token:g1');
  assert.equal(error.kid,'generation2');
  assert.equal(error.code,variant==='refresh-timeout'?'refresh-timeout':'refresh-rate');
  assert.equal(f.steps.some(s=>s.jwtStage==='accept'),false);
});

for(const [variant,keyId,handle,code,opens] of [
  ['default','recipient-generation1','HANDLE(recipient-RSA-OAEP-256-private-generation1)','readable-untrusted-inner',true],
  ['wrong-recipient','recipient-other','HANDLE(recipient-RSA-OAEP-256-private-other)','recipient-key',false],
  ['changed-tag','recipient-generation1','HANDLE(recipient-RSA-OAEP-256-private-generation1)','aead-evidence',false],
  ['invalid-inner-signature','recipient-generation1','HANDLE(recipient-RSA-OAEP-256-private-generation1)','readable-untrusted-inner',true]
])test('JK-02 '+variant+' visible selected private key agrees with unwrap operations and verdict',()=>{
  const f=fixture(3,variant),key=f.artifact('recipient-private'),initial=f.frame('initial'),unwrapped=f.frame('unwrap');
  assert.deepEqual(visible(initial,key),{id:keyId,handle,alg:'RSA-OAEP-256',use:'enc'});
  assert.equal(visible(unwrapped,key).id,keyId);
  assert.equal(f.artifact('recipient-public').value.id,'recipient-generation1');
  assert.equal(f.model.fixtureInputs.decryptionEvidence.recipientKeyId,'recipient-generation1');
  const keyOps=f.steps[f.index('unwrap')].attributeOperations.filter(o=>o.instanceId===key.artifactId);
  assert.deepEqual(keyOps.map(o=>({kind:o.kind,actorId:o.actorId,value:o.value})),[{kind:'decrypt',actorId:'jwtAPI',value:{id:keyId,handle,alg:'RSA-OAEP-256',use:'enc'}}]);
  const verdict=visible(unwrapped,f.artifact('decrypt-evidence'));
  assert.equal(verdict.recipientArtifactId,key.artifactId);
  assert.equal(verdict.recipientKeyId,keyId);
  assert.equal(verdict.encryptionPublicKeyId,'recipient-generation1');
  assert.equal(verdict.code,code);
  assert.equal(verdict.valid,opens);
  const input=f.model.fixtureInputs;
  assert.equal(JSON.stringify(verdict).includes(input.token.compact),false,'Decrypt verdict must not expose hidden inner bytes');
  const result=jwtDecryptFixture({token:input.encryptedToken,recipientKeyId:visible(unwrapped,key).id,evidence:input.decryptionEvidence});
  assert.equal(result.code,code);
  assert.equal(Object.hasOwn(result,'innerCompact'),opens);
  for(const stage of ['initial','receive'])for(const name of ['inner','cek'])assert.equal(held(f.frame(stage),f.artifact(name)),undefined);
  for(const name of ['inner','cek']){
    assert.equal(!!held(unwrapped,f.artifact(name)),opens);
    assert.equal(held(unwrapped,f.artifact(name),'jwtClient'),undefined);
  }
  assert.equal(unwrapped.state.jwt.validatedClaims,null);
  if(variant==='invalid-inner-signature'){
    assert.equal(f.index('unwrap')<f.index('signature'),true);
    assert.equal(f.frame('signature').state.jwt.failure.code,'signature-evidence');
    assert.equal(f.steps.some(s=>s.jwtStage==='accept'),false);
  }
});
