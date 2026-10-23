import {k8sCreateRequestCase} from './kubernetes-request-model.js';
import {KUBERNETESAUTHLAB_SOURCES} from './kubernetes-auth-lab.js';

export const KUBERNETESRBACLAB_ATTRIBUTES={};
export const KUBERNETESRBACLAB_SOURCES=KUBERNETESAUTHLAB_SOURCES.filter(source=>source.standard.startsWith('Kubernetes'));
const k8sRbacRows=['K8S04','K8S05','K8S06','K8S07','K8S08','K8S14','K8S15'];
export function createKubernetesRBACCase(planId='K8S04',variantId='default'){
  if(!k8sRbacRows.includes(planId))throw new RangeError('Unknown Kubernetes RBAC row '+planId);
  return k8sCreateRequestCase(planId,variantId);
}
export const KUBERNETESRBACLAB_SCENARIOS=k8sRbacRows.map(planId=>{
  const model=createKubernetesRBACCase(planId);
  Object.assign(KUBERNETESRBACLAB_ATTRIBUTES,model.catalogDefinitions);
  return model;
});
