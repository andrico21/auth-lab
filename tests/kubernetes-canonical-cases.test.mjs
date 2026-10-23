import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {KUBERNETESAUTHLAB_SCENARIOS,createKubernetesAuthCase,KUBERNETESAUTHLAB_ATTRIBUTES} from '../src/kubernetes-auth-lab.js';
import {KUBERNETESRBACLAB_SCENARIOS,createKubernetesRBACCase,KUBERNETESRBACLAB_ATTRIBUTES} from '../src/kubernetes-rbac-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildKubernetesHeldObjects} from '../src/held-object-kubernetes.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';

const k8sWorksheet=JSON.parse(await readFile(new URL('../docs/next-expansion/kubernetes-worksheet.json',import.meta.url),'utf8'));
const k8sModels=[...KUBERNETESAUTHLAB_SCENARIOS,...KUBERNETESRBACLAB_SCENARIOS];
const k8sAttributeCatalog={...KUBERNETESAUTHLAB_ATTRIBUTES,...KUBERNETESRBACLAB_ATTRIBUTES};
const k8sPath=(value,path)=>path.split('.').reduce((value,key)=>value?.[key],value);


for(const row of k8sWorksheet.rows)for(const fixture of row.canonicalCases)test(row.planId+'/'+fixture.id+' meets independent source-authored state and custody predicates',()=>{
  const base=k8sModels.find(model=>model.id===row.runtimeId),model=base.withVariant(fixture.id),steps=model.steps(),actors=model.actors();
  const plan=buildKubernetesHeldObjects({model,steps,actors,config:{},contextId:model.id+':'+fixture.id,choiceId:model.id}),compiled=compileHeldObjects(plan,{model,steps});
  assert.equal(model.id,base.id);assert.equal(model.variantId,fixture.id);
  for(const step of steps)for(const operation of step.attributeOperations||[])assert.ok(Object.hasOwn(k8sAttributeCatalog,operation.attributeId),'Real global catalog owns branch field '+operation.attributeId);
  for(const predicate of fixture.assertions){
    const at=predicate.at,eventIndex=at.end?steps.length-1:at.milestone==='initial'?-1:steps.findIndex(step=>step.id===at.stepId);
    if(at.stepId)assert.notEqual(eventIndex,-1,'Missing source checkpoint '+at.stepId);
    if(predicate.target==='state')assert.deepEqual(k8sPath(reconstructProtocolState(model,eventIndex),predicate.path),predicate.equals,row.planId+'/'+fixture.id+' '+predicate.path+' at '+(at.stepId||at.milestone));
    else{
      const snapshot=projectHeldObjects(compiled,{eventIndex,milestone:at.milestone});
      const present=snapshot.holdings.some(holding=>holding.actorId===predicate.actorId&&holding.artifactId===predicate.artifactId&&holding.representationId===predicate.representation);
      assert.equal(present,predicate.present,row.planId+'/'+fixture.id+' exact '+predicate.artifactId+' at '+(at.stepId||at.milestone));
    }
  }
  assert.equal(projectHeldObjects(compiled,{eventIndex:steps.length-1,milestone:'complete'}).coverageStatus,'complete');
  assert.equal(reconstructProtocolState(model,-1).kubernetes.resultReceived,false,'Backward reset cannot retain a result');
});

test('Invalid Kubernetes case names fail explicitly, never silently selecting a success fixture',()=>{
  assert.throws(()=>createKubernetesAuthCase('K8S03','not-a-case'),RangeError);
  assert.throws(()=>createKubernetesRBACCase('K8S04','not-a-case'),RangeError);
  assert.throws(()=>createKubernetesRBACCase('K8S16'),RangeError);
});
