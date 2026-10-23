import test from 'node:test';
import assert from 'node:assert/strict';
import {JWTLAB_SCENARIOS,createJWTScenario} from '../src/jwt-validation-lab.js';
import {buildJWTHeldObjects} from '../src/held-object-jwt.js';
import {compileHeldObjects,projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
function jwtHeldFixture(model){const steps=model.steps(),plan=buildJWTHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+model.variantId,choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});return {model,steps,plan,compiled,frame:stage=>projectHeldObjects(compiled,{eventIndex:steps.findIndex(step=>step.jwtStage===stage),milestone:'complete'}),artifact:key=>model.jwtInventory.artifacts.find(a=>a.attributeId==='jwt'+model.id.slice(-2)+'_'+key)};}
function jwtHeldFind(frame,artifact,actor,representation){return frame.holdings.find(h=>h.artifactId===artifact.artifactId&&h.actorId===actor&&(!representation||h.representationId===representation));}
test('JWT01 comparison shows readable-untrusted JWS but no JWE plaintext or accepted identity',()=>{const f=jwtHeldFixture(createJWTScenario(1)),received=f.frame('deliver'),inspected=f.frame('inspect');assert.equal(jwtHeldFind(received,f.artifact('decoded'),'jwtClient'),undefined);const readable=jwtHeldFind(inspected,f.artifact('decoded'),'jwtClient','readable-untrusted');assert.ok(readable);assert.equal(inspectHeldObject(inspected,readable.holdingId).fields[0].value.claims.sub,'alice');const encrypted=jwtHeldFind(received,f.artifact('encrypted'),'jwtClient','wire');assert.ok(encrypted);assert.ok(inspectHeldObject(received,encrypted.holdingId).fields.every(field=>!JSON.stringify(field.value).includes('"sub"')));const final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});assert.equal(final.state.jwt.validatedClaims,null);assert.equal(final.state.jwt.principal,null);assert.equal(final.state.jwt.authorized,false);});
test('All authored core/variant prefixes preserve explicit custody and backwards state',()=>{for(const base of JWTLAB_SCENARIOS)for(const variant of base.variantChoices){const f=jwtHeldFixture(base.withVariant(variant.id));for(let index=-1;index<f.steps.length;index++){const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:index<0?'initial':'complete'});assert.equal(frame.coverageStatus,'complete');assert.deepEqual(frame.state,reconstructProtocolState(f.model,index));for(const holding of frame.holdings.filter(h=>h.artifactId.endsWith(':issuer-private')))assert.equal(holding.actorId,'jwtIssuer');}const initial=projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'});assert.equal(initial.state.jwt.validatedClaims,null);assert.equal(initial.state.jwt.authorized,false);}});
test('Exact JWS artifact replay retains delivery plus meaningful local decode without replacing wire value',()=>{const f=jwtHeldFixture(createJWTScenario(1)),token=f.artifact('compact'),trace=heldObjectTrace(f.compiled,token.artifactId);const receive=trace.find(row=>row.sourceStepId==='lab-jwt01:deliver');assert.ok(receive);assert.equal(receive.representationId,'wire');assert.equal(receive.payload[0].value,f.model.fixtureInputs.token.compact);assert.ok(trace.some(row=>row.sourceStepId==='lab-jwt01:inspect'&&row.traceKind.includes('observe')));const snapshot=f.frame('inspect'),wire=jwtHeldFind(snapshot,token,'jwtClient','wire');assert.equal(inspectHeldObject(snapshot,wire.holdingId).fields[0].value,f.model.fixtureInputs.token.compact);});
test('Malformed comparison branches stop before any validated holding but preserve delivered bytes',()=>{for(const variant of ['malformed-segments','malformed-base64url','malformed-json']){const f=jwtHeldFixture(createJWTScenario(1,variant)),frame=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});assert.equal(frame.state.jwt.failure.stage,'parse');assert.equal(frame.state.jwt.validatedClaims,null);assert.ok(jwtHeldFind(frame,f.artifact('compact'),'jwtClient','wire'));assert.equal(frame.holdings.some(h=>h.representationId==='accepted'),false);}});
test('Foreign models do not acquire JWT plans',()=>assert.equal(buildJWTHeldObjects({model:{id:'foreign'}}),null));

test('Nested JWE keeps plaintext and CEK recipient-local, and inner failure never installs accepted claims',()=>{
  for(const variant of ['default','wrong-recipient','changed-tag','invalid-inner-signature']){
    const f=jwtHeldFixture(createJWTScenario(3,variant)),receipt=f.frame('receive'),inner=f.artifact('inner'),cek=f.artifact('cek');
    assert.equal(jwtHeldFind(receipt,inner,'jwtAPI'),undefined);
    assert.equal(jwtHeldFind(receipt,inner,'jwtClient'),undefined);
    assert.equal(jwtHeldFind(receipt,cek,'jwtAPI'),undefined);
    const unwrapped=f.frame('unwrap'),succeeds=variant==='default'||variant==='invalid-inner-signature';
    assert.equal(!!jwtHeldFind(unwrapped,inner,'jwtAPI','readable-untrusted'),succeeds);
    assert.equal(!!jwtHeldFind(unwrapped,cek,'jwtAPI','plain'),succeeds);
    assert.equal(unwrapped.state.jwt.validatedClaims,null);
    assert.equal(jwtHeldFind(unwrapped,inner,'jwtClient'),undefined);
    if(succeeds){const trace=heldObjectTrace(f.compiled,inner.artifactId);assert.ok(trace.some(row=>row.sourceStepId==='lab-jwt03:unwrap'&&row.traceKind.includes('observe')));}
    const final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
    assert.equal(!!final.state.jwt.validatedClaims,variant==='default');
    assert.equal(final.state.jwt.authorized,false);
  }
});

test('Bearer repeated receipts share exact artifact bytes but have distinct request-scoped holding identities',()=>{
  const f=jwtHeldFixture(createJWTScenario(9)),token=f.artifact('compact'),initialReceipt=f.frame('present'),replayed=f.frame('replay-present');
  const before=initialReceipt.holdings.filter(h=>h.actorId==='jwtAPI'&&h.artifactId===token.artifactId&&h.representationId==='wire');
  const after=replayed.holdings.filter(h=>h.actorId==='jwtAPI'&&h.artifactId===token.artifactId&&h.representationId==='wire');
  assert.equal(before.length,1);assert.equal(after.length,2);assert.notEqual(after[0].holdingId,after[1].holdingId);
  for(const holding of after)assert.equal(inspectHeldObject(replayed,holding.holdingId).fields[0].value,f.model.fixtureInputs.token.compact);
  assert.equal(replayed.state.jwt.completedActions,1);assert.equal(replayed.state.jwt.authorized,false);
  const final=projectHeldObjects(f.compiled,{eventIndex:f.steps.length-1,milestone:'complete'});
  assert.equal(final.state.jwt.completedActions,2);assert.equal(final.state.jwt.clientKnowsFailure,true);
  assert.ok(jwtHeldFind(final,f.artifact('first-result'),'jwtClient','wire'));
});

test('JWT decoding preserves issuer token provenance and creates only holder-local decoded evidence',()=>{
  for(const [number,key] of [[1,'compact'],[3,'inner']]){
    const f=jwtHeldFixture(createJWTScenario(number));
    assert.equal(f.artifact(key).creator,'jwtIssuer');
  }
  for(const base of JWTLAB_SCENARIOS)for(const variant of base.variantChoices){
    const f=jwtHeldFixture(base.withVariant(variant.id));
    for(const step of f.steps)for(const operation of step.attributeOperations){
      if(['create','derive'].includes(operation.kind)){
        assert.equal(operation.actorId,operation.creator,step.id+': '+operation.instanceId);
        assert.equal(step.from,operation.creator,step.id+': creation must execute at its origin');
      }
    }
    for(const step of f.steps.filter(step=>['parse','inspect','client-parse','resource-parse'].includes(step.jwtStage))){
      const source=step.attributeOperations.filter(operation=>operation.creator==='jwtIssuer');
      for(const operation of source)assert.equal(operation.kind,'inspect');
    }
  }
});

test('Every JWT transfer starts with sender custody of the exact representation and does not create it on receipt',()=>{
  for(const base of JWTLAB_SCENARIOS)for(const variant of base.variantChoices){
    const f=jwtHeldFixture(base.withVariant(variant.id));
    for(let index=0;index<f.steps.length;index++){
      const step=f.steps[index],messages=f.plan.events[step.id].messages||[];
      if(!messages.length)continue;
      const before=projectHeldObjects(f.compiled,{eventIndex:index-1,milestone:index===0?'initial':'complete'});
      for(const message of messages)for(const object of message.objects){
        assert.ok(before.holdings.some(holding=>holding.actorId===message.from&&holding.artifactId===object.artifactId&&holding.representationId===object.representationId),step.id+': sender lacks exact representation');
        assert.equal(step.attributeOperations.some(operation=>operation.instanceId===object.artifactId&&['create','derive'].includes(operation.kind)),false);
        assert.equal(f.plan.events[step.id].milestones.some(milestone=>milestone.effects.some(effect=>effect.op==='create'&&effect.artifactId===object.artifactId)),false);
      }
    }
  }
});
