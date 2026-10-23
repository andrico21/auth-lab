import test from 'node:test';
import assert from 'node:assert/strict';
import {createKubernetesRBACCase} from '../src/kubernetes-rbac-lab.js';
import {k8sRequest,k8sAuthorize,k8sBasePolicy} from '../src/kubernetes-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';

const k8sEnd=model=>reconstructProtocolState(model,model.steps().length-1).kubernetes;
const k8sAt=(model,key)=>{const index=model.steps().findIndex(step=>step.id===model.id+':'+key);assert.notEqual(index,-1,key);return reconstructProtocolState(model,index).kubernetes;};
const k8sCase=(row,id='default')=>createKubernetesRBACCase(row,id);

test('HTTP collection/named/subresource/non-resource requests retain exact authorization dimensions',()=>{
  assert.deepEqual(k8sRequest().attributes,{resourceRequest:true,verb:'list',apiGroup:'',version:'v1',resource:'pods',subresource:'',namespace:'demo-dev',name:''});
  assert.equal(k8sRequest({name:'demo-pod'}).attributes.verb,'get');
  assert.deepEqual(k8sRequest({name:'demo-pod',subresource:'log'}).attributes,{resourceRequest:true,verb:'get',apiGroup:'',version:'v1',resource:'pods',subresource:'log',namespace:'demo-dev',name:'demo-pod'});
  assert.equal(k8sRequest({resource:'nodes',name:'demo-node',namespace:'demo-dev'}).attributes.namespace,'');
  assert.deepEqual(k8sRequest({path:'/version'}).attributes,{resourceRequest:false,verb:'get',path:'/version'});
});

test('Namespaced exact binding grants Alice but neither Bob nor wrong namespace/verb/group',()=>{
  const policy=k8sBasePolicy(),alice={username:'oidc:alice',groups:['team:readers','system:authenticated']};
  const allow=k8sAuthorize(alice,k8sRequest().attributes,policy);
  assert.equal(allow.allowed,true);assert.equal(allow.matches[0].subject.name,'team:readers');
  assert.equal(allow.matches[0].binding.name,'read-pods');assert.equal(allow.matches[0].role.name,'reader');
  assert.deepEqual(allow.matches[0].rule,{apiGroups:[''],resources:['pods'],verbs:['get','list','watch']});
  for(const [user,request] of [[{username:'oidc:bob',groups:['team:observers','system:authenticated']},{}],[alice,{namespace:'demo-prod'}],[alice,{method:'DELETE',name:'demo-pod'}],[{username:'oidc:alice',groups:['team:reader']},{}]])assert.equal(k8sAuthorize(user,k8sRequest(request).attributes,policy).allowed,false);
  assert.equal(k8sEnd(k8sCase('K8S04','bob')).userInfo.username,'oidc:bob');
});

test('ClusterRole rules are reusable but binding scope and resourceNames still decide each request',()=>{
  for(const [id,allowed] of [['default',true],['namespaced-other-namespace',false],['namespaced-nodes',false],['clusterwide-dev',true],['clusterwide-prod',true],['clusterwide-not-nodes',false],['named-node',true],['unbound-clusterrole',false],['cross-namespace-role',false]])assert.equal(k8sEnd(k8sCase('K8S05',id)).authorization.allowed,allowed,id);
  const node=k8sEnd(k8sCase('K8S05','named-node'));
  assert.equal(node.requestAttributes.namespace,'');assert.equal(node.authorization.matches[0].rule.resourceNames[0],'demo-node');
  const immutable=k8sEnd(k8sCase('K8S05','immutable-roleref'));assert.equal(immutable.authorization.allowed,true);assert.equal(immutable.firstDetector,'rbac-object-validation');assert.equal(immutable.status,422);assert.deepEqual(immutable.persisted,[]);
});

test('Pod log and named ConfigMap rights are not implied by pod collection reads',()=>{
  for(const [id,status] of [['pod-log-denied',403],['pod-log-granted',200],['named-config',200],['other-config',403],['unrestricted-config-list',403],['cluster-scope',403],['non-resource',403]])assert.equal(k8sEnd(k8sCase('K8S06',id)).status,status,id);
  const model=k8sCase('K8S06','review-then-policy-change');
  assert.deepEqual(k8sAt(model,'can-i-evaluate').accessReview,{allowed:true,reusableGrant:false});
  assert.equal(k8sAt(model,'can-i-response').resultReceived,false);
  assert.equal(k8sAt(model,'authorize').authorization.allowed,false);
  assert.equal(k8sEnd(model).status,403);
  const review=JSON.parse(model.kubernetesInventory.artifacts.find(artifact=>artifact.artifactId==='lab-k8s06:access-review:g1').representations[0].fields[0].value);
  assert.deepEqual(review.spec.resourceAttributes,{namespace:'demo-dev',verb:'list',group:'',version:'v1',resource:'pods',subresource:'',name:''});
  assert.ok(!Object.hasOwn(review.spec.resourceAttributes,'resourceRequest'));
});

test('RBAC grant union has no subtractive deny rule and still denies unmatched secrets',()=>{
  for(const id of ['default','log-union','remove-log-still-pods','restrictive-role-no-subtraction'])assert.equal(k8sEnd(k8sCase('K8S07',id)).status,200,id);
  const denied=k8sEnd(k8sCase('K8S07','secrets-denied'));assert.equal(denied.userInfo.username,'oidc:bob');assert.equal(denied.authorization.allowed,false);assert.equal(denied.resultReceived,false);
  assert.equal(k8sEnd(k8sCase('K8S07','group-without-bindings')).status,403);
});

test('Write authz, typed decoding, mutation, exact VAP policy, storage conflict and persistence stay distinct',()=>{
  const accepted=k8sCase('K8S08');
  assert.equal(k8sAt(accepted,'authorize').authorization.allowed,true);assert.deepEqual(k8sAt(accepted,'authorize').persisted,[]);
  assert.equal(k8sAt(accepted,'mutate').admission,'mutating-no-op');assert.deepEqual(k8sAt(accepted,'admit').persisted,[]);
  assert.equal(k8sAt(accepted,'persist').persisted[0].metadata.uid,'config-1');assert.equal(k8sAt(accepted,'persist').resultReceived,false);assert.equal(k8sEnd(accepted).status,201);
  for(const [id,stage,status] of [['missing-label','admission',422],['invalid-schema','api-validation',400],['storage-conflict','storage',409]]){
    const model=k8sCase('K8S08',id),state=k8sEnd(model);assert.equal(state.firstDetector,stage);assert.equal(state.status,status);assert.equal(state.userInfo.username,'oidc:alice');assert.equal(state.authorization.allowed,true);assert.deepEqual(state.persisted,[]);assert.equal(state.resultReceived,false);
    if(id==='invalid-schema')assert.ok(!model.steps().some(step=>step.id.endsWith(':mutate')),'Typed decoding fails before admission');
  }
  assert.equal(k8sEnd(k8sCase('K8S08','read-bypass')).admission,'not-applicable-read');
});

test('Impersonation requires each attribute, then target authorization; constrained beta and fallback are separate',()=>{
  const success=k8sEnd(k8sCase('K8S14'));assert.equal(success.userInfo.username,'oidc:bob');assert.equal(success.audit.original.username,'oidc:operator');assert.equal(success.audit.impersonated.username,'oidc:bob');
  for(const id of ['unauthorized-user','unauthorized-group','unauthorized-extra','constrained-no-action','constrained-no-identity']){const state=k8sEnd(k8sCase('K8S14',id));assert.equal(state.firstDetector,'impersonation',id);assert.equal(state.userInfo.username,'oidc:operator');assert.equal(state.resultReceived,false);}
  assert.equal(k8sEnd(k8sCase('K8S14','constrained')).status,200);
  const fallback=k8sEnd(k8sCase('K8S14','legacy-fallback'));assert.equal(fallback.impersonation.legacyFallback,true);assert.equal(fallback.status,200);
  const denied=k8sEnd(k8sCase('K8S14','target-denied'));assert.equal(denied.firstDetector,'rbac');assert.equal(denied.userInfo.username,'oidc:bob');assert.equal(denied.audit.original.username,'oidc:operator');
});

test('Ordinary RBAC CRUD cannot bypass separate bind/escalate checks',()=>{
  for(const [id,stage] of [['default','escalate'],['bind-excess','bind'],['narrow-other-role','bind'],['namespace-not-cluster','rbac']]){const state=k8sEnd(k8sCase('K8S15',id));assert.equal(state.firstDetector,stage);assert.equal(state.status,403);assert.deepEqual(state.persisted,[]);assert.equal(state.resultReceived,false);}
  for(const [id,kind] of [['create-held-rights','Role'],['bind-held-rights','RoleBinding'],['explicit-narrow-bind','RoleBinding']]){const state=k8sEnd(k8sCase('K8S15',id));assert.equal(state.authorization.allowed,true);assert.equal(state.persisted[0].kind,kind);assert.equal(state.admission,'allowed');assert.equal(state.status,201);}
});
