import test from 'node:test';
import assert from 'node:assert/strict';
import {createKubernetesAuthCase} from '../src/kubernetes-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildKubernetesHeldObjects} from '../src/held-object-kubernetes.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';

const k8sCase=(row,id='default')=>createKubernetesAuthCase(row,id);
const k8sAt=(model,key)=>{const index=model.steps().findIndex(step=>step.id===model.id+':'+key);assert.notEqual(index,-1,key);return reconstructProtocolState(model,index).kubernetes;};
const k8sEnd=model=>reconstructProtocolState(model,model.steps().length-1).kubernetes;
const k8sArtifact=(model,key,generation='g1')=>model.kubernetesInventory.artifacts.find(artifact=>artifact.artifactId===model.id+':'+key+':'+generation);
const k8sValue=(model,key,generation='g1')=>k8sArtifact(model,key,generation).representations[0].fields[0].value;
const k8sClaims=compact=>JSON.parse(atob(compact.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));

test('Projected issuance, actual file read, rotation generation and application reload are different boundaries',()=>{
  const model=k8sCase('K8S09'),first=k8sClaims(k8sValue(model,'sa-token')),next=k8sClaims(k8sValue(model,'sa-token','g2'));
  assert.equal(first.iss,'https://kubernetes.demo.example');assert.equal(first.sub,'system:serviceaccount:demo-dev:reader');assert.deepEqual(first.aud,['https://kubernetes.demo.example']);
  assert.deepEqual(first['kubernetes.io'],{namespace:'demo-dev',serviceaccount:{name:'reader',uid:'sa-1'},pod:{name:'demo-reader',uid:'pod-1'}});
  assert.equal(first.exp-first.iat,3600);assert.equal(next.iat,1792630081);assert.equal(next.exp,1792633681);
  assert.equal(first.nbf,first.iat);assert.equal(next.nbf,next.iat);assert.notEqual(first.jti,next.jti);
  assert.ok(!Object.hasOwn(first,'tenant'));assert.ok(!Object.hasOwn(first,'nonce'));assert.ok(!Object.hasOwn(first,'groups'));
  assert.equal(k8sAt(model,'project-token').projection.appToken,null);
  assert.equal(k8sAt(model,'workload-read').projection.appToken,'lab-k8s09:sa-token:g1');
  assert.equal(k8sAt(model,'rotation-project').projection.appToken,'lab-k8s09:sa-token:g1');
  assert.equal(k8sAt(model,'rotation-reload').projection.appToken,'lab-k8s09:sa-token:g2');
  assert.equal(k8sEnd(model).userInfo.username,'system:serviceaccount:demo-dev:reader');
  assert.equal(k8sEnd(model).status,403,'Issuance/rotation does not invent a pod reader binding');
  assert.equal(k8sEnd(model).resultReceived,false);
  const stale=k8sEnd(k8sCase('K8S09','cached-old-expired'));assert.equal(stale.firstDetector,'claims');assert.equal(stale.status,401);assert.equal(stale.rotation.reloaded,false);assert.equal(stale.projection.fileToken,'lab-k8s09:sa-token:g2');assert.equal(stale.projection.appToken,'lab-k8s09:sa-token:g1');
  assert.equal(k8sEnd(k8sCase('K8S09','automount-disabled')).rotation.reloaded,true);
  const none=k8sCase('K8S09','no-projection');assert.equal(k8sEnd(none).firstDetector,'workload-file');assert.ok(!none.steps().some(step=>step.id.endsWith(':issue-token')));
});

test('Workload RBAC matches exact ServiceAccount namespace or explicitly expanded group, not a copied human string',()=>{
  assert.equal(k8sEnd(k8sCase('K8S10')).status,403);
  assert.equal(k8sEnd(k8sCase('K8S10','explicit-binding')).status,200);
  const other=k8sEnd(k8sCase('K8S10','same-name-other-namespace'));assert.equal(other.userInfo.username,'system:serviceaccount:demo-prod:reader');assert.equal(other.status,403);
  assert.equal(k8sEnd(k8sCase('K8S10','namespace-group')).status,200);
  const expanded=k8sEnd(k8sCase('K8S10','global-group-other-sa'));assert.equal(expanded.status,200);assert.equal(expanded.requestAttributes.namespace,'demo-dev');assert.equal(expanded.userInfo.username,'system:serviceaccount:demo-prod:reader');
  const human=k8sEnd(k8sCase('K8S10','human-copied-sa-group'));assert.equal(human.userInfo.username,'oidc:alice');assert.ok(human.userInfo.groups.includes('team:system:serviceaccounts:demo-dev'));assert.equal(human.status,403);
});

test('TokenReview authenticates a reviewed subject under separate reviewer authority, audience and lifecycle checks',()=>{
  const model=k8sCase('K8S11'),body=JSON.parse(k8sValue(model,'review-request'));
  assert.equal(body.path,'/apis/authentication.k8s.io/v1/tokenreviews');assert.deepEqual(body.body.spec.audiences,['vault.demo.example']);assert.equal(body.body.spec.token,k8sValue(model,'sa-token'));assert.notEqual(body.Authorization,'Bearer '+body.body.spec.token);
  assert.equal(k8sAt(model,'reviewer-identity').reviewerInfo.username,'system:serviceaccount:demo-dev:token-reviewer');assert.equal(k8sAt(model,'reviewer-identity').userInfo,null);
  assert.equal(k8sAt(model,'review-response').userInfo,null,'Receipt is not relying-service acceptance');
  assert.equal(k8sAt(model,'identity').authorization,null,'Authentication does not grant external resource permission');
  const review=JSON.parse(k8sValue(model,'token-review-result'));assert.equal(review.httpStatus,201);assert.equal(review.stored,false);assert.equal(review.status.authenticated,true);assert.deepEqual(review.status.audiences,['vault.demo.example']);
  assert.equal(k8sEnd(k8sCase('K8S11','missing-returned-audience')).firstDetector,'review-consumer');
  for(const id of ['pod-deleted','pod-uid-changed','pending-delete-after-grace']){const failed=k8sCase('K8S11',id),state=k8sEnd(failed);assert.equal(state.firstDetector,'bound-object');assert.equal(state.status,401);assert.equal(state.userInfo,null);const result=JSON.parse(k8sValue(failed,'token-review-result'));assert.equal(result.httpStatus,201);assert.equal(result.status.authenticated,false);assert.equal(state.resultReceived,false);}
  assert.equal(k8sEnd(k8sCase('K8S11','pending-delete-within-grace')).status,200);
  const offline=k8sCase('K8S11','offline-deleted-pod');assert.equal(k8sEnd(offline).boundObject.checked,false);assert.equal(k8sEnd(offline).boundObject.offlineKnowledge,'cannot-observe-current-deletion');assert.equal(k8sEnd(offline).status,200);assert.ok(!offline.steps().some(step=>step.id.endsWith(':review-submit')));
  assert.equal(k8sEnd(k8sCase('K8S11','reviewer-denied')).firstDetector,'reviewer-rbac');
  const policy=k8sEnd(k8sCase('K8S11','external-policy-denied'));assert.equal(policy.userInfo.username,'system:serviceaccount:demo-dev:reader');assert.equal(policy.firstDetector,'external-policy');assert.equal(policy.resultReceived,false);
});

test('TokenReview defers issuer validation to the authorized API while offline validation remains local',()=>{
  const fixture=variant=>{
    const model=k8sCase('K8S11',variant),steps=model.steps(),plan=buildKubernetesHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':'+model.variantId,choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});
    return {model,initial:projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}),at:key=>{const eventIndex=steps.findIndex(step=>step.id===model.id+':'+key);assert.ok(eventIndex>=0,key);return projectHeldObjects(compiled,{eventIndex,milestone:'complete'});}};
  };
  const has=(frame,actor,key)=>frame.holdings.some(h=>h.actorId===actor&&h.artifactId==='lab-k8s11:'+key+':g1');
  const review=fixture('default');
  assert.equal(has(review.initial,'k8sAPI','issuer-trust'),true);
  assert.equal(has(review.initial,'k8sVault','issuer-trust'),false);
  for(const key of ['review-submit','reviewer-authorize']){
    const frame=review.at(key);assert.equal(frame.state.kubernetes.signatureValid,false);assert.equal(frame.state.kubernetes.validatedClaims,null);
    for(const actor of ['k8sVault','k8sAPI'])for(const artifact of ['signature-verdict','validated-claims','reviewed-validated-claims'])assert.equal(has(frame,actor,artifact),false);
  }
  const verified=review.at('reviewed-token-verify');
  assert.equal(verified.state.kubernetes.signatureValid,true);
  assert.equal(has(verified,'k8sAPI','signature-verdict'),true);
  assert.equal(has(verified,'k8sAPI','reviewed-validated-claims'),true);
  assert.equal(has(verified,'k8sVault','reviewed-validated-claims'),false);
  assert.equal(has(review.at('review-response'),'k8sVault','userinfo'),false,'Receiving review bytes does not yet accept the relying-service identity');
  assert.equal(has(review.at('identity'),'k8sVault','userinfo'),true);
  const denied=fixture('reviewer-denied').at('reviewer-rbac-reject');
  assert.equal(denied.state.kubernetes.signatureValid,false);assert.equal(denied.state.kubernetes.validatedClaims,null);
  assert.equal(has(denied,'k8sAPI','reviewed-validated-claims'),false);
  const offline=fixture('offline-deleted-pod');
  assert.equal(has(offline.initial,'k8sVault','issuer-trust'),true);
  assert.equal(has(offline.at('validate-claims'),'k8sVault','validated-claims'),true);
  assert.equal(offline.at('identity').state.kubernetes.boundObject.checked,false);
});

test('Separate target audiences and authoritative returned expiry prevent workload token substitution',()=>{
  const model=k8sCase('K8S12'),api=k8sClaims(k8sValue(model,'sa-token')),vault=k8sClaims(k8sValue(model,'sa-token-vault'));
  assert.equal(api.iss,'https://kubernetes.demo.example');assert.equal(vault.iss,api.iss);assert.equal(api.sub,vault.sub);assert.deepEqual(api.aud,['https://kubernetes.demo.example']);assert.deepEqual(vault.aud,['vault.demo.example']);assert.notEqual(k8sValue(model,'sa-token'),k8sValue(model,'sa-token-vault'));
  for(const id of ['vault-token-at-api','api-token-at-vault']){const state=k8sEnd(k8sCase('K8S12',id));assert.equal(state.firstDetector,'claims');assert.equal(state.status,401);assert.equal(state.userInfo,null);assert.equal(state.resultReceived,false);}
  const denied=k8sCase('K8S12','unauthorized-tokenrequest');assert.equal(k8sEnd(denied).firstDetector,'tokenrequest-rbac');assert.ok(!k8sArtifact(denied,'sa-token'));
  const short=k8sCase('K8S12','returned-shorter-lifetime'),response=JSON.parse(k8sValue(short,'token-request-response'));assert.equal(k8sClaims(response.status.token).exp-1792627200,1800);assert.equal(response.status.expirationTimestamp,'2026-10-22T00:30:00.000Z');
});

test('ServiceAccount private signer and kubelet private node credential are never carried to workload or vault',()=>{
  const model=k8sCase('K8S12'),steps=model.steps(),plan=buildKubernetesHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':'+model.variantId,choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});
  for(let eventIndex=-1;eventIndex<steps.length;eventIndex++){
    const frame=projectHeldObjects(compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
    for(const holder of frame.holdings){if(holder.artifactId.endsWith(':issuer-private-key:g1'))assert.equal(holder.actorId,'k8sAPI');if(holder.artifactId.endsWith(':node-credential:g1'))assert.equal(holder.actorId,'k8sKubelet');}
  }
  for(const event of Object.values(plan.events))for(const message of event.messages||[])assert.ok(!message.objects.some(object=>/issuer-private-key|node-credential/.test(object.artifactId)));
});
