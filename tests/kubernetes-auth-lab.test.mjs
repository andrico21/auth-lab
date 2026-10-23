import test from 'node:test';
import assert from 'node:assert/strict';
import {createKubernetesAuthCase,KUBERNETESAUTHLAB_SCENARIOS} from '../src/kubernetes-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const k8sAt=(model,key)=>{const index=model.steps().findIndex(step=>step.id===model.id+':'+key);assert.notEqual(index,-1,key);return reconstructProtocolState(model,index).kubernetes;};
const k8sEnd=model=>reconstructProtocolState(model,model.steps().length-1).kubernetes;

test('K8S01 readable claims, signature, validated claims, candidate mapping and accepted identity are separate',()=>{
  const model=createKubernetesAuthCase('K8S01');
  const decoded=k8sAt(model,'decode');
  assert.equal(decoded.userInfo,null);assert.equal(decoded.authorization,null);assert.equal(decoded.validatedClaims,null);
  assert.equal(decoded.untrustedClaims.sub,'alice');assert.equal(decoded.signatureValid,false);
  assert.equal(k8sAt(model,'signature').signatureValid,true);
  assert.equal(k8sAt(model,'signature').validatedClaims,null);
  assert.equal(k8sAt(model,'validate-claims').validatedClaims.aud,'kubernetes-demo');
  const candidate=k8sAt(model,'candidate-map');
  assert.deepEqual(candidate.candidateUserInfo,{username:'oidc:alice',groups:['team:readers']});
  assert.equal(candidate.userInfo,null);
  assert.deepEqual(k8sAt(model,'identity').userInfo,{username:'oidc:alice',groups:['team:readers','system:authenticated']});
  assert.equal(k8sAt(model,'identity').authorization,null);
  const allowed=k8sAt(model,'authorize');
  assert.deepEqual(allowed.requestAttributes,{resourceRequest:true,verb:'list',apiGroup:'',version:'v1',resource:'pods',subresource:'',namespace:'demo-dev',name:''});
  assert.equal(allowed.authorization.chain[0].decision,'NoOpinion');
  assert.equal(allowed.authorization.matches[0].binding.name,'read-pods');
  assert.equal(allowed.authorization.matches[0].role.name,'reader');
  assert.equal(allowed.resultReceived,false);assert.deepEqual(allowed.persisted,[]);
  assert.equal(k8sAt(model,'read-boundary').admission,'not-applicable-read');
  const final=k8sEnd(model);assert.equal(final.status,200);assert.equal(final.resultReceived,true);
  assert.deepEqual(reconstructProtocolState(model,-1).kubernetes.userInfo,null);
  assert.equal(reconstructProtocolState(model,model.steps().findIndex(step=>step.id===model.id+':decode')).kubernetes.resultReceived,false);
});

test('K8S01 wrong state, verifier and nonce stop before API identity and preserve exact variant ID',()=>{
  for(const [id,stage] of [['wrong-state','client-state'],['wrong-pkce','issuer-pkce'],['wrong-nonce','client-nonce']]){
    const model=createKubernetesAuthCase('K8S01',id),state=k8sEnd(model);
    assert.equal(model.id,'lab-k8s01');assert.equal(model.variantId,id);
    assert.equal(state.firstDetector,stage);assert.equal(state.status,null);assert.equal(state.userInfo,null);
    assert.equal(state.authorization,null);assert.equal(state.resultReceived,false);assert.deepEqual(state.persisted,[]);
    assert.ok(!model.steps().some(step=>step.id.endsWith(':api-request')));
  }
  assert.throws(()=>createKubernetesAuthCase('K8S01','unknown'),RangeError);
});

test('K8S01 missing reader binding retains authenticated Alice but never returns PodList',()=>{
  const state=k8sEnd(createKubernetesAuthCase('K8S01','no-binding'));
  assert.equal(state.userInfo.username,'oidc:alice');assert.equal(state.firstDetector,'rbac');
  assert.equal(state.status,403);assert.equal(state.authorization.allowed,false);
  assert.equal(state.resultReceived,false);assert.equal(state.admission,'not-reached');assert.deepEqual(state.persisted,[]);
});

test('K8S01 cache-hit request has no browser, plugin invocation or per-request issuer call',()=>{
  const model=createKubernetesAuthCase('K8S01','cache-hit');
  assert.equal(k8sEnd(model).client.cache,'hit');assert.equal(k8sEnd(model).status,200);
  assert.ok(!model.steps().some(step=>[step.from,step.to].includes('k8sIssuer')||step.id.endsWith(':exec-invoke')));
  assert.ok(Object.isFrozen(model));assert.ok(Object.isFrozen(model.fixtureInputs));
  assert.equal(KUBERNETESAUTHLAB_SCENARIOS.find(item=>item.id==='lab-k8s01').variantId,'default');
});
