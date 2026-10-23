import test from 'node:test';
import assert from 'node:assert/strict';
import {createKubernetesAuthCase} from '../src/kubernetes-auth-lab.js';
import {buildKubernetesHeldObjects} from '../src/held-object-kubernetes.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';

const k8sHeldFixture=(variant='default')=>{
  const model=createKubernetesAuthCase('K8S01',variant),steps=model.steps(),actors=model.actors();
  const plan=buildKubernetesHeldObjects({model,steps,actors,config:{},contextId:model.id+':'+variant,choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const frame=(key,milestone='complete')=>{const eventIndex=steps.findIndex(step=>step.id===model.id+':'+key);assert.notEqual(eventIndex,-1,key);return projectHeldObjects(compiled,{eventIndex,milestone});};
  const has=(frame,key,actor,representation)=>frame.holdings.some(holding=>holding.artifactId===model.id+':'+key+':g1'&&holding.actorId===actor&&(!representation||holding.representationId===representation));
  return {model,steps,plan,compiled,frame,has};
};

test('K8S01 exact token moves issuer -> plugin -> client -> API, never carrying refresh or PKCE to API',()=>{
  const f=k8sHeldFixture();
  assert.equal(f.has(f.frame('token-response','before'),'id-token','k8sPlugin'),false);
  assert.equal(f.has(f.frame('token-response'),'id-token','k8sPlugin','readable-untrusted'),true);
  assert.equal(f.has(f.frame('exec-return'),'id-token','k8sClient','readable-untrusted'),true);
  assert.equal(f.has(f.frame('api-request','before'),'id-token','k8sAPI'),false);
  assert.equal(f.has(f.frame('api-request'),'id-token','k8sAPI','readable-untrusted'),true);
  assert.equal(f.has(f.frame('api-request'),'validated-claims','k8sAPI'),false);
  assert.equal(f.has(f.frame('validate-claims'),'validated-claims','k8sAPI','accepted'),true);
  for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){
    const frame=projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
    assert.equal(frame.coverageStatus,'complete');
    for(const key of ['refresh-token','login-context','code-redemption'])assert.equal(f.has(frame,key,'k8sAPI'),false,key);
    for(const actor of ['k8sPlugin','k8sClient','k8sAPI'])assert.equal(f.has(frame,'issuer-private-key',actor),false,actor);
  }
  const token=f.plan.artifacts.find(artifact=>artifact.artifactId==='lab-k8s01:id-token:g1');
  assert.equal(token.creator,'k8sIssuer');assert.equal(token.representations[0].format,'readable-untrusted');
  const tokenHistory=heldObjectTrace(f.compiled,token.artifactId);
  assert.ok(tokenHistory.some(event=>event.sourceStepId==='lab-k8s01:api-request'));
  const value=token.representations[0].fields[0].value;
  assert.equal(value.split('.').length,3);
  const transfers=f.plan.events['lab-k8s01:api-request'].messages.flatMap(message=>message.objects);
  assert.ok(transfers.some(object=>object.artifactId===token.artifactId));
  assert.ok(!transfers.some(object=>/refresh|login-context|code-redemption|private-key/.test(object.artifactId)));
});

test('K8S01 protected result cannot be acquired before response receipt and seek rebuilds prior custody',()=>{
  const f=k8sHeldFixture();
  assert.equal(f.has(f.frame('authorize'),'pod-list','k8sClient'),false);
  assert.equal(f.has(f.frame('result','before'),'pod-list','k8sClient'),false);
  assert.equal(f.has(f.frame('result'),'pod-list','k8sClient'),true);
  assert.equal(f.has(f.frame('decode'),'pod-list','k8sClient'),false);
  assert.equal(f.has(f.frame('consume-login'),'login-context','k8sPlugin'),false);
  assert.equal(f.has(f.frame('plugin-validate'),'login-context','k8sPlugin'),true);
  const denied=k8sHeldFixture('no-binding');
  const end=projectHeldObjects(denied.compiled,{eventIndex:denied.steps.length-1,milestone:'complete'});
  assert.equal(denied.has(end,'pod-list','k8sClient'),false);
  assert.equal(denied.has(end,'userinfo','k8sAPI','accepted'),true);
  assert.equal(denied.has(end,'id-token','k8sAPI','readable-untrusted'),true);
});
