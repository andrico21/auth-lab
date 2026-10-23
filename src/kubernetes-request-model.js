import {k8sAuthor,k8sToken,k8sValidate,k8sPut,k8sBasePolicy,k8sAuthorize,k8sRequest,k8sBundle,k8sFreeze,k8sDerive} from './kubernetes-auth-lab.js';
import {jwtParseCompact} from './jwt-policy.js';
import {K8S_CASE_ROWS,K8S_VARIANT_INPUTS} from './kubernetes-case-data.js';

function k8sReadFixture(request){
  const attributes=request.attributes;
  if(!attributes.resourceRequest)return attributes.path==='/livez'?'ok\n':null;
  const pod={apiVersion:'v1',kind:'Pod',metadata:{name:attributes.name||'demo-pod',namespace:attributes.namespace,uid:'pod-1'},spec:{serviceAccountName:'reader'},status:{phase:'Running'}};
  if(attributes.resource==='pods')return attributes.subresource==='log'?'2026-10-22T00:00:00Z synthetic demo log line\n':attributes.name?pod:{apiVersion:'v1',kind:'PodList',metadata:{resourceVersion:'42'},items:[pod]};
  if(attributes.resource==='nodes')return {apiVersion:'v1',kind:'Node',metadata:{name:attributes.name,uid:'node-1',resourceVersion:'42'},spec:{},status:{conditions:[]}};
  if(attributes.resource==='configmaps'){const value=k8sBundle('admission-proposals').objects[0];value.metadata={...value.metadata,uid:'config-1',resourceVersion:'42'};return value;}
  return null;
}

export function k8sCatalogKeys(planId){
  const common=['issuer-private-key','issuer-trust','rbac-policy','id-token','request','decoded-claims','signature-verdict','validated-claims','candidate-userinfo','userinfo','request-attributes','grant','pod-list','response','self-review-grant','reviewed-validated-claims','discovery-request','jwks-request','resource-snapshot','authentication-config','serviceaccount-config','plugin-trust'];
  if(['K8S09','K8S12'].includes(planId))common.push('token-request-authorization');
  if(planId==='K8S12')common.push('vault-trust','vault-userinfo');
  const special={K8S01:['login-context','exec-input','authorization-request','callback','code-redemption','refresh-token','exec-credential'],K8S02:['self-review-grant','self-review'],K8S03:['discovery','jwks-refresh'],K8S05:['scope-comparison','role-ref-proposal'],K8S06:['access-review','access-review-result','changed-policy'],K8S07:['union-evidence'],K8S08:['proposal','mutation-verdict','admission-verdict','api-validation','persisted-object','readback'],K8S09:['node-credential','token-request','token-request-response','sa-token','projection','rotation-clock','rotation-request','rotation-response','rotation-projection'],K8S10:['sa-token','bound-object-check','subject-scope'],K8S11:['sa-token','reviewer-credential','review-request','reviewer-userinfo','reviewer-grant','bound-object-check','token-review-result','offline-observation','external-grant'],K8S12:['node-credential','token-request','token-request-response','sa-token','sa-token-vault','vault-token-request','vault-token-response','projection','vault-projection','external-grant','bound-object-check'],K8S13:['anonymous-config'],K8S14:['impersonation-request','impersonation-verdict','impersonated-userinfo','audit-identities'],K8S15:['rbac-proposal','delegation-check','persisted-object','later-policy']};
  const stages=({K8S01:['client-state','issuer-pkce','client-nonce','rbac'],K8S02:['mapping','claim-rule','user-validation','rbac'],K8S03:['signature','claims','trust','key','infrastructure'],K8S04:['rbac'],K8S05:['rbac','rbac-object-validation'],K8S06:['rbac'],K8S07:['rbac'],K8S08:['admission','api-validation','storage'],K8S09:['workload-file','claims','rbac'],K8S10:['rbac'],K8S11:['review-consumer','bound-object','reviewer-rbac','external-policy'],K8S12:['claims','tokenrequest-rbac'],K8S13:['authentication','signature','rbac'],K8S14:['impersonation','rbac'],K8S15:['escalate','bind','rbac']})[planId]||[];
  return [...new Set([...common,...(special[planId]||[]),...stages.map(stage=>stage+'-failure')])];
}
export function k8sCreateRequestCase(planId,variantId='default',register=false){
  const row=K8S_CASE_ROWS.find(entry=>entry.planId===planId),variants=K8S_VARIANT_INPUTS[planId];
  if(!row||!variants||!Object.hasOwn(variants,variantId))throw new RangeError('Unknown Kubernetes case '+planId+'/'+variantId);
  const o=JSON.parse(JSON.stringify(variants[variantId])),workload=o.serviceAccount===true,external=planId==='K8S11'||o.offline===true;
  const actorIds=workload?['k8sClient','k8sKubelet','k8sAPI','k8sStorage',...(planId==='K8S11'||planId==='K8S12'?['k8sVault']:[])]:['k8sClient','k8sIssuer','k8sAPI','k8sStorage'];
  const a=k8sAuthor(row,variantId,{...o,actorIds},register),baseNow=1792627200;
  let now=o.now??baseNow,subject=o.subject||'alice',policy=k8sBasePolicy(o),user=null,tokenRef,token,identitySources=[];
  const finish=()=>{const model=a.finish();model.variantChoices=Object.entries(variants).map(([id,input])=>({id,label:id==='default'?'Default fixed profile':id.replace(/-/g,' '),description:'Independent '+row.planId+' '+id+' input fixture; '+Object.keys(input).filter(key=>key!=='actorIds').join(', ')}));model.withVariant=id=>k8sCreateRequestCase(planId,id);return k8sFreeze(model);};
  const object=(...args)=>a.object(...args);
  const event=(...args)=>a.event(...args);
  const reject=(stage,status,refs=[],actor=external?'k8sVault':'k8sAPI',details={})=>{
    const failure=object(stage+'-failure',stage+' rejection',actor,{stage,status,identity:user?.username||null,...details});
    event(stage+'-reject','Stop at '+stage,actor,[...refs,failure],{create:[failure],kind:'verify',effects:[k8sPut('firstDetector',stage),k8sPut('status',status),k8sPut('response',{status,stage}),k8sPut('decisionStrip.result','denied at '+stage)]});
    if(status!==null){if(external&&actor==='k8sAPI'){event('review-failure-response','Receive API reviewer failure at external service',actor,[failure],{to:'k8sVault'});event('failure-response','External service denies protected operation','k8sVault',[failure],{to:'k8sClient',effects:[k8sPut('client.statusKnown',status)]});}else event('failure-response','Receive failure response without protected data',actor,[failure],{to:'k8sClient',effects:[k8sPut('client.statusKnown',status)]});}
    return finish();
  };
  const signer=workload?'k8sAPI':'k8sIssuer';
  const key=object('issuer-private-key','Issuer-local private signing key',signer,'HANDLE('+(workload?'cluster-old':o.kid||'human-old')+' private signing key)',{initial:true,type:'private-key',readers:[signer]});
  const trustActor=external&&o.offline?'k8sVault':'k8sAPI';
  const initialKeys=[{id:workload?'cluster-old':'human-old',kid:workload?'cluster-old':'human-old',issuer:workload?'https://kubernetes.demo.example':'https://issuer.demo.example',kty:'RSA',alg:'RS256',use:'sig',key_ops:['verify']}];
  const trust=object('issuer-trust','Configured issuer-scoped public verification trust',trustActor,{issuer:initialKeys[0].issuer,audience:o.expectedAudience||(external?'vault.demo.example':workload?'https://kubernetes.demo.example':'kubernetes-demo'),algorithm:'RS256; pinned-source default, not AuthenticationConfiguration.signingAlgs',keys:initialKeys},{initial:true,type:'trust-record',holders:[trustActor]});
  let verificationKeys=initialKeys,verifierKeysRef=trust;
  let authConfig=null;
  if(!workload){
    const configuration=k8sBundle(o.anonymous==='livez'?'anonymous-livez':'core-api-configuration').configurationFiles['authentication.yaml'];
    if(o.anonymous==='full')configuration.anonymous={enabled:true};
    if(o.usernameClaim)configuration.jwt[0].claimMappings.username.claim=o.usernameClaim;
    if(o.usernamePrefix!==undefined)configuration.jwt[0].claimMappings.username.prefix=o.usernamePrefix;
    if(o.groupPrefix!==undefined)configuration.jwt[0].claimMappings.groups.prefix=o.groupPrefix;
    authConfig=object('authentication-config','Exact selected AuthenticationConfiguration v1','k8sAPI',configuration,{initial:true,type:'policy'});
  }else authConfig=object('serviceaccount-config','ServiceAccount issuer and API audience authority','k8sAPI',{issuer:'https://kubernetes.demo.example',apiAudiences:['https://kubernetes.demo.example'],extendTokenExpiration:false,requestedLifetimeSeconds:3600,humanOIDCMappingUsed:false,jti:'GA v1.32 enabled; not replay prevention',optionalPodNodeInfo:'No observed scheduled node metadata supplied'},{initial:true,type:'policy'});
  if(o.removeVariantBindings)policy=policy.filter(entry=>!['bob-pods-in-dev','bob-one-node','bob-pods-all-namespaces'].includes(entry.metadata.name));
  if(o.restrictiveRole)policy.push({apiVersion:'rbac.authorization.k8s.io/v1',kind:'Role',metadata:{name:'restrictive-looking',namespace:'demo-dev'},rules:[{apiGroups:[''],resources:['pods'],verbs:['get']}]});
  if(planId==='K8S05'&&o.roleRefKind){policy.push({kind:'RoleBinding',metadata:{name:'invalid-cross-namespace-reference',namespace:o.bindingNamespace},subjects:[{kind:'User',name:'oidc:bob'}],roleRef:{kind:'Role',name:o.roleRefName}});}
  if(planId==='K8S15'&&o.rbacWrite==='bind-excess')policy.push(...k8sBundle('owner-seeded-high-role').objects);
  const bootstrap=['K8S02','K8S06'].includes(planId)?[{kind:'ClusterRole',metadata:{name:'system:basic-user'},rules:[{apiGroups:['authorization.k8s.io'],resources:['selfsubjectaccessreviews','selfsubjectrulesreviews'],verbs:['create']},{apiGroups:['authentication.k8s.io'],resources:['selfsubjectreviews'],verbs:['create']}]},{kind:'ClusterRoleBinding',metadata:{name:'system:basic-user'},subjects:[{kind:'Group',name:'system:authenticated'}],roleRef:{kind:'ClusterRole',name:'system:basic-user'}}]:[];
  policy.push(...bootstrap);
  if(o.mutateRoleRef)policy.push({kind:'Role',metadata:{name:'demo-binding-updater',namespace:'demo-dev'},rules:[{apiGroups:['rbac.authorization.k8s.io'],resources:['rolebindings'],verbs:['update'],resourceNames:['read-pods']}]},{kind:'RoleBinding',metadata:{name:'alice-binding-updater',namespace:'demo-dev'},subjects:[{kind:'User',name:'oidc:alice'}],roleRef:{kind:'Role',name:'demo-binding-updater'}});
  if(o.legacyFallback)policy.push(...k8sBundle('classic-impersonation').objects.filter(entry=>entry.metadata.name!=='bob-direct-reader'));
  if(o.routeGrant)policy.push({kind:'ClusterRole',metadata:{name:'demo-livez'},rules:[{verbs:['get'],nonResourceURLs:['/livez']}]},{kind:'ClusterRoleBinding',metadata:{name:'demo-livez'},subjects:[{kind:'Group',name:'system:unauthenticated'}],roleRef:{kind:'ClusterRole',name:'demo-livez'}});
  let policyRef=object('rbac-policy','Isolated exact policy snapshot','k8sAPI',policy,{initial:true,type:'policy'});
  const makeWorkloadToken=(audience,generation='g1',issuedAt=baseNow)=>k8sToken({iss:'https://kubernetes.demo.example',subject:'system:serviceaccount:'+(o.saNamespace||'demo-dev')+':reader',kid:'cluster-old',aud:[audience],instanceId:a.id+':sa-token:'+generation,claims:{iat:issuedAt,nbf:issuedAt,exp:issuedAt+(o.returnedLifetime||3600),jti:audience==='vault.demo.example'?'00000000-0000-4000-8000-000000000003':generation==='g2'?'00000000-0000-4000-8000-000000000002':'00000000-0000-4000-8000-000000000001','kubernetes.io':{namespace:o.saNamespace||'demo-dev',serviceaccount:{name:'reader',uid:'sa-1'},pod:{name:'demo-reader',uid:'pod-1'}}},serviceAccount:true});
  if(workload){
    const audience=o.audience||'https://kubernetes.demo.example';token=makeWorkloadToken(audience);
    if(['K8S09','K8S12'].includes(planId)){
      const node=object('node-credential','Kubelet node TLS credential handle','k8sKubelet','HANDLE(node client private key; never sent)',{initial:true,type:'private-key',readers:['k8sKubelet']});
      if(o.explicitProjection===false)return reject('workload-file',null,[],'k8sClient',{reason:'automount false and no explicit projection: no token file; manual issuance is not prohibited'});
      const request=object('token-request','Authorized TokenRequest body','k8sKubelet',{apiVersion:'authentication.k8s.io/v1',kind:'TokenRequest',spec:{audiences:[audience],expirationSeconds:3600,boundObjectRef:{kind:'Pod',apiVersion:'v1',name:'demo-reader',uid:'pod-1'}}});
      event('tokenrequest-prepare','Prepare node-authorized bound TokenRequest','k8sKubelet',[request,node],{create:[request],kind:'use'});
      event('tokenrequest','POST /api/v1/namespaces/demo-dev/serviceaccounts/reader/token','k8sKubelet',[request],{to:'k8sAPI',summary:'Node client authentication is separately provisioned TLS trust. The exact ServiceAccount endpoint and bound Pod must match the caller issuance authority.'});
      const issuanceGrants=o.tokenRequestAllowed===false?[]:[{caller:'system:node:demo-node',namespace:'demo-dev',serviceAccount:'reader',podUID:'pod-1',audiences:['https://kubernetes.demo.example','vault.demo.example']}];
      const issuance=object('token-request-authorization','Explicit node-bound issuance authority fixture','k8sAPI',{authority:'Preprovisioned kubelet-to-Pod issuance authorization; full Node authorizer graph is outside this bounded offline fixture',grants:issuanceGrants},{initial:true,type:'policy'});
      const submitted=JSON.parse(request.value),issuanceAllowed=issuanceGrants.some(grant=>grant.caller==='system:node:demo-node'&&grant.namespace==='demo-dev'&&grant.serviceAccount==='reader'&&grant.podUID===submitted.spec.boundObjectRef.uid&&submitted.spec.audiences.every(audience=>grant.audiences.includes(audience)));
      if(!issuanceAllowed)return reject('tokenrequest-rbac',403,[request,issuance],'k8sAPI',{caller:'system:node:demo-node',resource:'serviceaccounts/token',requestedIdentity:'demo-dev/reader'});
      event('tokenrequest-authorize','Match caller, target ServiceAccount, Pod binding and requested audiences','k8sAPI',[request,issuance],{kind:'verify',effects:[k8sPut('tokenRequest',{caller:'system:node:demo-node',authorized:issuanceAllowed,requestedLifetime:3600,returnedLifetime:o.returnedLifetime||3600})]});
      tokenRef=object('sa-token','Bound ServiceAccount JWS','k8sAPI',token.compact,{representation:'readable-untrusted',type:'credential'});
      k8sDerive(tokenRef,key,request,issuance);
      event('issue-token','Issue bounded token without creating a token Secret','k8sAPI',[tokenRef,key],{create:[tokenRef],kind:'use'});
      const response=object('token-request-response','TokenRequest authoritative response','k8sAPI',{apiVersion:'authentication.k8s.io/v1',kind:'TokenRequest',status:{token:token.compact,expirationTimestamp:new Date(token.claims.exp*1000).toISOString()}});
      event('tokenrequest-response-create','Create TokenRequest response with authoritative expiry','k8sAPI',[response],{create:[response]});
      event('tokenrequest-response','Receive issued token at kubelet','k8sAPI',[response,tokenRef],{to:'k8sKubelet'});
      const projection=object('projection','Projected API token file content','k8sKubelet',{path:'/var/run/demo-identity/api-token',tokenInstanceId:token.instanceId,expiration:token.claims.exp});
      event('project-token','Write explicitly configured projected token file','k8sKubelet',[tokenRef,projection],{create:[projection],kind:'use',effects:[k8sPut('projection',{generation:'g1',fileToken:token.instanceId,appToken:null})]});
      event('workload-read','Read projected token file into application memory','k8sKubelet',[tokenRef],{to:'k8sClient',transport:'local file access',protocol:'Projected token file read',effects:[k8sPut('projection.appToken',token.instanceId)]});
      if(o.dualAudience){
        const vault=makeWorkloadToken('vault.demo.example');vault.instanceId=a.id+':sa-token-vault:g1';vault.evidence.tokenInstanceId=vault.instanceId;
        const vaultRequest=object('vault-token-request','Separate vault-audience TokenRequest','k8sKubelet',{apiVersion:'authentication.k8s.io/v1',kind:'TokenRequest',spec:{audiences:['vault.demo.example'],expirationSeconds:3600,boundObjectRef:{kind:'Pod',apiVersion:'v1',name:'demo-reader',uid:'pod-1'}}});
        event('vault-tokenrequest-create','Prepare independent vault token request','k8sKubelet',[vaultRequest],{create:[vaultRequest]});event('vault-tokenrequest','Request separate external-audience token','k8sKubelet',[vaultRequest],{to:'k8sAPI'});
        const vaultAllowed=issuanceGrants.some(grant=>grant.caller==='system:node:demo-node'&&grant.podUID==='pod-1'&&grant.audiences.includes('vault.demo.example'));
        event('vault-tokenrequest-authorize','Recheck distinct vault-audience issuance request','k8sAPI',[vaultRequest,issuance],{kind:'verify'});
        if(!vaultAllowed)return reject('tokenrequest-rbac',403,[vaultRequest,issuance],'k8sAPI');
        const vaultRef=object('sa-token-vault','Vault-audience ServiceAccount JWS','k8sAPI',vault.compact,{representation:'readable-untrusted',type:'credential'});k8sDerive(vaultRef,key,vaultRequest,issuance);
        event('vault-issue','Issue exact separate vault token','k8sAPI',[vaultRef,key],{create:[vaultRef],kind:'use'});event('vault-token-response','Receive vault token at kubelet','k8sAPI',[vaultRef],{to:'k8sKubelet'});event('vault-workload-read','Read separate vault projection','k8sKubelet',[vaultRef],{to:'k8sClient',transport:'local file access',protocol:'Projected token file read'});event('vault-present','Present only vault-audience credential to external service','k8sClient',[vaultRef],{to:'k8sVault'});
        const vaultTrust=object('vault-trust','External service issuer-scoped trust and target audience','k8sVault',{issuer:'https://kubernetes.demo.example',audience:'vault.demo.example',keys:initialKeys,mode:'offline signature/issuer/audience/time; no current bound-object lookup'},{initial:true,type:'trust-record'});
        const checked=k8sValidate(vault,{serviceAccount:true,expectedAudience:'vault.demo.example',keys:initialKeys});
        if(!checked.ok)return reject('claims',401,[vaultRef,vaultTrust],'k8sVault',{reason:checked.code});
        const vaultIdentity=object('vault-userinfo','External service accepted workload principal','k8sVault',{username:checked.validatedClaims.sub,uid:'sa-1'},{representation:'accepted'});k8sDerive(vaultIdentity,vaultRef,vaultTrust);
        event('vault-token-validate','Accept target-specific token before external resource policy','k8sVault',[vaultRef,vaultTrust,vaultIdentity],{create:[vaultIdentity],kind:'verify',effects:[k8sPut('vault',{authenticated:true,authorized:false,userInfo:{username:checked.validatedClaims.sub,uid:'sa-1'},issuer:checked.validatedClaims.iss,audience:'vault.demo.example',policyAuthority:'external vault fixture'})]});
        const externalGrant=object('external-grant','Independent vault subject and action policy','k8sVault',{issuer:checked.validatedClaims.iss,subject:checked.validatedClaims.sub,audience:'vault.demo.example',endpoint:'https://vault.demo.example/demo/read',action:'read training data',allowed:true});
        event('vault-policy','Evaluate independent external action policy after authentication','k8sVault',[vaultIdentity,externalGrant],{create:[externalGrant],kind:'verify',effects:[k8sPut('vault.authorized',true)]});
      }
      if(o.rotation){
        now=o.now??baseNow+2881;
        const clock=object('rotation-clock','Explicit rotation clock and threshold','k8sKubelet',{now:baseNow+2881,issuedAt:baseNow,returnedExpiry:token.claims.exp,ttl:3600,threshold:'80% TTL or 24h; selected deterministic jitter 0; source adds up-to-10s jitter'});
        event('rotation-trigger','Reach documented kubelet rotation trigger','k8sKubelet',[clock],{create:[clock],effects:[k8sPut('rotation',{triggered:true,oldToken:token.instanceId,oldExpires:token.claims.exp,newToken:null,reloaded:false})]});
        const rotated=makeWorkloadToken(audience,'g2',baseNow+2881),replacement=object('sa-token','Rotated bounded ServiceAccount JWS','k8sAPI',rotated.compact,{generation:'g2',representation:'readable-untrusted',type:'credential'});
        replacement.definition.replaces=[tokenRef.artifactId];k8sDerive(replacement,key,request,issuance);
        event('rotation-request','Request replacement for same bound identity','k8sKubelet',[request],{to:'k8sAPI'});event('rotation-issue','Issue distinct token generation g2','k8sAPI',[replacement,key],{create:[replacement],kind:'use'});event('rotation-response','Receive replacement token generation','k8sAPI',[replacement],{to:'k8sKubelet'});
        event('rotation-project','Replace file content without revoking old token','k8sKubelet',[replacement],{kind:'use',effects:[k8sPut('projection.fileToken',rotated.instanceId),k8sPut('projection.generation','g2'),k8sPut('rotation.newToken',rotated.instanceId)]});
        if(o.reload!==false){event('rotation-reload','Application rereads replacement file bytes','k8sKubelet',[replacement],{to:'k8sClient',transport:'local file access',protocol:'Projected token file read',effects:[k8sPut('projection.appToken',rotated.instanceId),k8sPut('rotation.reloaded',true)]});token=rotated;tokenRef=replacement;}
      }
    }else{tokenRef=object('sa-token','Presented bound ServiceAccount JWS','k8sAPI',token.compact,{initial:true,holders:['k8sAPI','k8sClient'],representation:'readable-untrusted',type:'credential'});}
  }else if(o.credential!==false){
    const claims={};for(const field of ['sub','tenant','email','email_verified','exp'])if(Object.hasOwn(o,field))claims[field]=o[field];
    token=k8sToken({...o,subject,claims,deleteClaim:o.deleteClaim,instanceId:a.id+':id-token:g1'});tokenRef=object('id-token','Presented human ID-token JWS','k8sIssuer',token.compact,{initial:true,holders:['k8sIssuer','k8sClient'],representation:'readable-untrusted',type:'credential'});
  }
  const isWhoami=planId==='K8S02'&&!['pods','rbac'].includes(o.operation)&&!['bob','unprefixed-group','group-string-mismatch'].includes(variantId);
  let request=k8sRequest(o);
  if(isWhoami)request={method:'POST',path:'/apis/authentication.k8s.io/v1/selfsubjectreviews',attributes:{resourceRequest:true,verb:'create',apiGroup:'authentication.k8s.io',version:'v1',resource:'selfsubjectreviews',subresource:'',namespace:'',name:''}};
  if(planId==='K8S15'){const binding=o.rbacWrite.includes('bind'),cluster=o.rbacWrite==='cluster-binding';request=k8sRequest({method:'POST',resource:cluster?'clusterrolebindings':binding?'rolebindings':'roles',namespace:cluster?'':'demo-dev'});}
  if(o.mutateRoleRef)request=k8sRequest({method:'PUT',resource:'rolebindings',name:'read-pods',namespace:'demo-dev'});
  if(external)request={method:'POST',path:'https://vault.demo.example/demo/read',attributes:{resourceRequest:false,verb:'post',path:'/demo/read'}};
  const readValue=!external&&(request.method==='GET'||o.alreadyExists)?k8sReadFixture(request):null;
  const storageView=readValue!==null&&request.attributes.resourceRequest?object('resource-snapshot','Pre-existing API cache / storage view','k8sAPI',readValue,{initial:true,holders:['k8sAPI','k8sStorage'],readers:['k8sAPI','k8sStorage'],type:'resource-record'}):null;
  let proposalValue,proposalRef,rbacRole;
  if(planId==='K8S08'&&o.write){proposalValue=k8sBundle('admission-proposals').objects[o.training===null?1:0];if(o.dataType==='number')proposalValue.data.message=17;proposalRef=object('proposal','Original ConfigMap request proposal','k8sClient',proposalValue,{initial:true});}
  if(planId==='K8S15'){
    const mode=o.rbacWrite,binding=mode.includes('bind');
    rbacRole=mode.includes('excess')?k8sBundle(mode==='role-excess'?'rejected-escalation-request':'owner-seeded-high-role').objects[0]:k8sBundle('core-rbac').objects.find(entry=>entry.kind==='Role'&&entry.metadata.name==='reader');
    if(mode==='role-owned')rbacRole={...rbacRole,metadata:{name:'demo-owned-pod-reader',namespace:'demo-dev'}};
    proposalValue=mode==='bind-excess'?k8sBundle('rejected-bind-request').objects[0]:binding?{apiVersion:'rbac.authorization.k8s.io/v1',kind:mode==='cluster-binding'?'ClusterRoleBinding':'RoleBinding',metadata:{name:'editor-delegated-reader',...(mode==='cluster-binding'?{}:{namespace:'demo-dev'})},subjects:[{kind:'User',name:'oidc:bob',apiGroup:'rbac.authorization.k8s.io'}],roleRef:{kind:mode==='cluster-binding'?'ClusterRole':'Role',name:rbacRole.metadata.name,apiGroup:'rbac.authorization.k8s.io'}}:rbacRole;
    proposalRef=object('rbac-proposal','Exact RBAC proposal requiring independent delegation checks','k8sClient',proposalValue,{initial:true});
  }
  if(o.mutateRoleRef){proposalValue=k8sBundle('core-rbac').objects.find(entry=>entry.kind==='RoleBinding');proposalValue.roleRef.name='different-role';proposalRef=object('role-ref-proposal','Immutable roleRef mutation request','k8sClient',proposalValue,{initial:true});}
  const target=o.impersonateUser||'oidc:bob',headers=o.impersonation?object('impersonation-request','Requested impersonation attributes','k8sClient',{'Impersonate-User':target,...(o.impersonateGroups?{'Impersonate-Group':o.impersonateGroups}:{}),...Object.fromEntries(Object.entries(o.impersonateExtra||{}).map(([key,values])=>['Impersonate-Extra-'+encodeURIComponent(key),values]))},{initial:true}):null;
  const requestRef=object('request','Exact presented request','k8sClient',{method:request.method,path:request.path,...(token?{Authorization:'Bearer '+token.compact}:{}),...(proposalValue?{body:proposalValue}:{}),...(headers?{headers:JSON.parse(headers.value)}:{})});event('request-create','Construct exact action and bearer presentation','k8sClient',[requestRef],{create:[requestRef]});
  let accessReviewRef=null;
  if(planId==='K8S06'){const attrs=request.attributes,body={apiVersion:'authorization.k8s.io/v1',kind:'SelfSubjectAccessReview',spec:attrs.resourceRequest?{resourceAttributes:{namespace:attrs.namespace,verb:attrs.verb,group:attrs.apiGroup,version:attrs.version,resource:attrs.resource,subresource:attrs.subresource,name:attrs.name}}:{nonResourceAttributes:{verb:attrs.verb,path:attrs.path}}};accessReviewRef=object('access-review','SelfSubjectAccessReview exact question','k8sClient',body);event('can-i-create','Create exact advisory review before the actual resource request','k8sClient',[accessReviewRef],{create:[accessReviewRef]});}
  event('api-request',accessReviewRef?'POST SelfSubjectAccessReview with exact question':external?'Present workload credential to external resource':'Receive exact API request','k8sClient',[accessReviewRef||requestRef,...(tokenRef?[tokenRef]:[]),...(proposalRef?[proposalRef]:[]),...(headers?[headers]:[])],{to:external?'k8sVault':'k8sAPI',effects:[k8sPut('credential',tokenRef?.artifactId||null),k8sPut('decisionStrip.credential',token?'received-untrusted':'missing')]});
  let validator=external?'k8sVault':'k8sAPI';
  if(token){const parsed=jwtParseCompact(token.compact),decoded=object('decoded-claims','Readable untrusted token claims',validator,parsed.claims,{representation:'readable-untrusted'});k8sDerive(decoded,tokenRef);event('decode','Parse JWS without accepting identity',validator,[tokenRef,decoded],{create:[decoded],effects:[k8sPut('untrustedClaims',parsed.claims)]});}
  if(planId==='K8S03'){
    if(o.discoveryAvailable===false){const discovery=object('discovery-request','Configured issuer discovery request','k8sAPI',{method:'GET',url:'https://issuer.demo.example/.well-known/openid-configuration',expectedIssuer:'https://issuer.demo.example'});event('discovery-prepare','Prepare discovery only for configured issuer','k8sAPI',[discovery],{create:[discovery]});event('discovery-request','Request configured issuer metadata','k8sAPI',[discovery],{to:'k8sIssuer'});return reject('infrastructure',401,[trust],'k8sAPI',{failureClass:'issuer discovery unavailable; not proof token invalid'});}
    if(token.header.kid!=='human-old'){
      const fetch=object('jwks-request','Issuer-scoped JWKS cache refresh request','k8sAPI',{method:'GET',url:'https://issuer.demo.example/jwks',configuredIssuer:'https://issuer.demo.example',requestedKid:token.header.kid,cacheBefore:['human-old']});
      event('jwks-request-create','Prepare trusted-URI key refresh after cache miss','k8sAPI',[fetch],{create:[fetch]});event('jwks-request','Fetch only configured issuer public key set','k8sAPI',[fetch],{to:'k8sIssuer'});
      if(o.jwksAvailable===false)return reject('infrastructure',401,[fetch],'k8sAPI',{failureClass:'JWKS infrastructure failure, not signature invalidity'});
      const refresh=object('jwks-refresh','Exact public JWKS refresh response','k8sIssuer',{configuredIssuer:'https://issuer.demo.example',keys:(o.refreshKeys||[]).map(kid=>({id:kid,kid,issuer:'https://issuer.demo.example',kty:'RSA',alg:'RS256',use:'sig',key_ops:['verify']})),timing:'Implementation-specific; no JWT-foundations demo TTL claimed as Kubernetes default'});
      event('jwks-publish','Publish issuer public verification metadata','k8sIssuer',[refresh],{create:[refresh]});event('jwks-response','Receive configured issuer public JWKS response','k8sIssuer',[refresh],{to:'k8sAPI'});event('jwks-refresh','Accept issuer-scoped refreshed candidate set, not token identity','k8sAPI',[refresh,trust],{kind:'verify',effects:[k8sPut('keyCache',{issuer:'https://issuer.demo.example',kids:o.refreshKeys||[],tokenAccepted:false})]});
      if(!o.refreshKeys?.includes(token.header.kid))return reject('key',401,[tokenRef,refresh],'k8sAPI',{reason:'unknown key after issuer-scoped refresh'});
      verificationKeys=JSON.parse(refresh.value).keys;verifierKeysRef=refresh;
    }
    if(token.claims.iss!=='https://issuer.demo.example')return reject('trust',401,[tokenRef,trust],'k8sAPI',{reason:'configured issuer mismatch; isolated authenticator fixture'});
  }
  if(o.credential===false){
    const config=object('anonymous-config','Anonymous authentication eligibility','k8sAPI',{enabled:o.anonymous!=='disabled',conditions:o.anonymous==='livez'?[{path:'/livez'}]:[],configuredPath:request.path});event('anonymous-config','Check stable anonymous endpoint configuration','k8sAPI',[config],{create:[config],kind:'verify'});
    if(o.anonymous==='disabled'||o.anonymous==='livez'&&request.path!=='/livez')return reject('authentication',401,[config],'k8sAPI');
    user={username:'system:anonymous',groups:['system:unauthenticated']};
    identitySources=[config];
  }else{
    let check,accepted;
    if(!o.tokenReview){
      check=k8sValidate(token,{serviceAccount:workload,expectedAudience:o.expectedAudience||(external?'vault.demo.example':workload?'https://kubernetes.demo.example':'kubernetes-demo'),keys:verificationKeys,now});
      const sig=object('signature-verdict','Exact-token symbolic signature evidence verdict',validator,{tokenInstanceId:token.instanceId,keyId:check.keyId,signatureValid:check.signatureValid,evidenceKind:'SYM'});event('signature','Evaluate configured key and symbolic signature evidence',validator,[tokenRef,trust,...(verifierKeysRef!==trust?[verifierKeysRef]:[]),sig],{create:[sig],kind:'verify',effects:[k8sPut('signatureValid',check.signatureValid)]});
      k8sDerive(sig,tokenRef,verifierKeysRef);
      if(!check.ok){const stage=!workload&&['required-sub','claim-type-sub'].includes(check.code)?'mapping':check.stage==='signature'?'signature':check.stage==='key'?'key':check.stage==='trust'?'trust':'claims';return reject(stage,401,[tokenRef,sig],validator,{reason:check.code});}
      accepted=object('validated-claims','Context-validated token claims',validator,check.validatedClaims,{representation:'accepted'});event('validate-claims','Validate exact issuer, audience and NumericDate lifetime',validator,[accepted,tokenRef],{create:[accepted],kind:'verify',effects:[k8sPut('validatedClaims',check.validatedClaims)]});
      k8sDerive(accepted,tokenRef,sig);
    }
    if(workload){
      const saNamespace=o.saNamespace||'demo-dev';
      let reviewedResponse=null;
      if(o.tokenReview){
        const reviewer=object('reviewer-credential','Reviewer own bearer credential','k8sVault','SYM(token-reviewer credential; not the reviewed token)',{initial:true,type:'credential',readers:['k8sVault','k8sAPI']});
        const reviewerUser={username:'system:serviceaccount:demo-dev:token-reviewer',uid:'reviewer-1',groups:['system:serviceaccounts','system:serviceaccounts:demo-dev','system:authenticated']};
        const reviewRequest=object('review-request','TokenReview v1 exact body plus distinct header','k8sVault',{method:'POST',path:'/apis/authentication.k8s.io/v1/tokenreviews',Authorization:'Bearer '+reviewer.value,body:{apiVersion:'authentication.k8s.io/v1',kind:'TokenReview',spec:{token:token.compact,audiences:['vault.demo.example']}}});event('review-prepare','Create review with separate reviewer credential', 'k8sVault',[reviewRequest],{create:[reviewRequest]});event('review-submit','Submit TokenReview with expected custom audience','k8sVault',[reviewRequest,reviewer,tokenRef],{to:'k8sAPI'});
        const reviewerIdentity=object('reviewer-userinfo','Authenticated reviewer request identity','k8sAPI',reviewerUser,{representation:'accepted'});event('reviewer-identity','Authenticate reviewer independently of reviewed token','k8sAPI',[reviewerIdentity],{create:[reviewerIdentity],effects:[k8sPut('reviewerInfo',reviewerUser)]});
        let reviewerPolicy=[...policy,...k8sBundle('tokenreview-reviewer').objects];if(o.reviewerAllowed===false)reviewerPolicy=reviewerPolicy.filter(entry=>entry.kind!=='ClusterRoleBinding'||entry.metadata.name!=='demo-token-reviewer');
        const reviewerVerdict=k8sAuthorize(reviewerUser,{resourceRequest:true,verb:'create',apiGroup:'authentication.k8s.io',resource:'tokenreviews',subresource:'',namespace:'',name:''},reviewerPolicy),reviewerGrant=object('reviewer-grant','Reviewer authorization decision','k8sAPI',reviewerVerdict);event('reviewer-authorize','Authorize create tokenreviews before examining reviewed subject','k8sAPI',[reviewerGrant],{create:[reviewerGrant],kind:'verify'});if(!reviewerVerdict.allowed)return reject('reviewer-rbac',403,[reviewerGrant],'k8sAPI',{reviewedSubjectAccepted:false});
        validator='k8sAPI';
        const reviewCheck=k8sValidate(token,{serviceAccount:true,expectedAudience:'vault.demo.example',keys:verificationKeys,now});
        const sig=object('signature-verdict','Exact-token symbolic signature evidence verdict','k8sAPI',{tokenInstanceId:token.instanceId,keyId:reviewCheck.keyId,signatureValid:reviewCheck.signatureValid,evidenceKind:'SYM'});
        k8sDerive(sig,tokenRef,trust);
        event('signature','API verifies reviewed token only after reviewer authorization','k8sAPI',[tokenRef,trust,sig],{create:[sig],kind:'verify',effects:[k8sPut('signatureValid',reviewCheck.signatureValid)]});
        accepted=object('reviewed-validated-claims','API-local validated reviewed-token claims','k8sAPI',reviewCheck.validatedClaims,{representation:'accepted'});
        k8sDerive(accepted,tokenRef,sig);
        event('reviewed-token-verify','API independently verifies reviewed token after reviewer authorization','k8sAPI',[tokenRef,trust,accepted],{create:[accepted],kind:'verify',effects:[k8sPut('validatedClaims',reviewCheck.validatedClaims)]});
      }
      const boundOK=o.offline||o.podExists!==false&&(o.observedPodUID||'pod-1')==='pod-1'&&(o.deletionAge===undefined||o.deletionAge<60);
      const bound=object('bound-object-check','Bound-object validation scope',validator,{mode:o.offline?'offline-no-current-object-lookup':'API current object lookup',serviceAccount:{name:'reader',namespace:saNamespace,uid:'sa-1',exists:true},pod:{name:'demo-reader',tokenUID:'pod-1',observedUID:o.observedPodUID||'pod-1',exists:o.podExists!==false,deletionAge:o.deletionAge??null},accepted:Boolean(boundOK),knowledge:o.offline?'Signed claims cannot reveal current deletion':'Current existence/UID and documented deletion grace checked'});
      event('bound-object','Check authority-specific bound-object predicates',validator,[bound,accepted],{create:[bound],kind:'verify',effects:[k8sPut('boundObject',{checked:!o.offline,accepted:Boolean(boundOK),offlineKnowledge:o.offline?'cannot-observe-current-deletion':null})]});
      if(!boundOK){
        if(o.tokenReview){
          const response=object('token-review-result','TokenReview 201 unauthenticated response','k8sAPI',{apiVersion:'authentication.k8s.io/v1',kind:'TokenReview',status:{authenticated:false,audiences:[]},httpStatus:201,stored:false});
          event('bound-object-reject','API rejects reviewed subject, not reviewer HTTP authentication','k8sAPI',[bound,response],{create:[response],kind:'verify',effects:[k8sPut('firstDetector','bound-object')]});
          event('review-response','Receive negative current-bound-object review','k8sAPI',[response],{to:'k8sVault'});
          const failure=object('bound-object-failure','External service denies unauthenticated reviewed subject','k8sVault',{status:401,stage:'bound-object',reviewHTTPStatus:201});
          event('external-review-deny','Translate failed subject authentication to external resource denial','k8sVault',[response,failure],{create:[failure],kind:'verify',effects:[k8sPut('status',401),k8sPut('response',{status:401,stage:'bound-object'}),k8sPut('decisionStrip.result','external401 after negative TokenReview201')]});
          event('failure-response','Receive external denial without protected data','k8sVault',[failure],{to:'k8sClient',effects:[k8sPut('client.statusKnown',401)]});return finish();
        }
        return reject('bound-object',401,[bound],validator);
      }
      const mapped={username:token.claims.sub,uid:'sa-1',groups:['system:serviceaccounts','system:serviceaccounts:'+saNamespace,'system:authenticated']};
      if(o.tokenReview){
        reviewedResponse=object('token-review-result','TokenReview v1 accepted response','k8sAPI',{apiVersion:'authentication.k8s.io/v1',kind:'TokenReview',status:{authenticated:true,user:mapped,audiences:o.reviewAudiences||['vault.demo.example']},httpStatus:201,stored:false});k8sDerive(reviewedResponse,accepted,bound);
        event('review-response-create','Create unstored TokenReview result','k8sAPI',[reviewedResponse],{create:[reviewedResponse]});event('review-response','Receive review, not a resource permission grant','k8sAPI',[reviewedResponse],{to:'k8sVault'});
        if(!(o.reviewAudiences||['vault.demo.example']).includes('vault.demo.example'))return reject('review-consumer',403,[reviewedResponse],'k8sVault',{reason:'authenticated true without required returned audience is insufficient'});validator='k8sVault';
      }
      identitySources=reviewedResponse?[reviewedResponse]:[accepted,bound];
      if(!o.tokenReview){const offline=object('offline-observation','Offline validation knowledge boundary',external?'k8sVault':'k8sAPI',{signatureClaimsValid:true,currentPodDeletionObservable:false,expires:token.claims.exp,reason:'Public discovery/JWKS is not interactive OIDC login and cannot reveal live bound-object deletion'});event('offline-observation','Separate offline claim validation from current-object knowledge',external?'k8sVault':'k8sAPI',[offline],{create:[offline]});}user=mapped;
    }else{
      const c=check.validatedClaims,usernameClaim=o.usernameClaim||'sub';
      if(typeof c[usernameClaim]!=='string'||!c[usernameClaim]||!Array.isArray(c.groups)||!c.groups.every(group=>typeof group==='string'))return reject('mapping',401,[accepted],'k8sAPI',{reason:'Required username/groups mapping types are not coercible'});
      if(usernameClaim==='email'&&c.email_verified!==true)return reject('mapping',401,[accepted],'k8sAPI',{reason:'email mapping requires email_verified true'});
      const candidate={username:(o.usernamePrefix??'oidc:')+c[usernameClaim],groups:c.groups.map(group=>(o.groupPrefix??'team:')+group)},candidateRef=object('candidate-userinfo','Transient mapping before rule acceptance','k8sAPI',candidate);k8sDerive(candidateRef,accepted,authConfig);event('candidate-map','Construct transient candidate with exact prefix provenance','k8sAPI',[accepted,authConfig,candidateRef],{create:[candidateRef],effects:[k8sPut('candidateUserInfo',candidate)]});
      if(c.tenant!=='demo')return reject('claim-rule',401,[candidateRef,accepted],'k8sAPI',{reason:'Required tenant string demo absent or mismatched'});
      if(candidate.username.startsWith('system:')||candidate.groups.some(group=>group.startsWith('system:')))return reject('user-validation',401,[candidateRef],'k8sAPI',{reason:'Mapped human username/groups must not use system prefix'});
      event('claim-user-rules','Validate tenant then mapped-user CEL before identity','k8sAPI',[accepted,candidateRef],{kind:'verify'});user={username:candidate.username,groups:[...candidate.groups,'system:authenticated']};
      identitySources=[candidateRef,authConfig];
    }
  }
  let identity=object('userinfo','Accepted request principal',validator,user,{representation:'accepted'});k8sDerive(identity,...identitySources);event('identity','Accept principal separately from permissions',validator,[identity],{create:[identity],effects:[k8sPut('userInfo',user),k8sPut('decisionStrip.identity',user.username)]});
  if(external){
    const grant=object('external-grant','Independent external resource policy','k8sVault',{issuer:'https://kubernetes.demo.example',audience:'vault.demo.example',subject:user.username,action:'read synthetic training data',allowed:o.externalAllowed!==false,policyAuthority:'external vault fixture'});
    event('external-policy','Evaluate independent external action policy','k8sVault',[identity,grant],{create:[grant],kind:'verify',effects:[k8sPut('authorization',{allowed:o.externalAllowed!==false,authority:'external vault fixture'}),k8sPut('decisionStrip.action','read external training data'),k8sPut('decisionStrip.matchingGrant',o.externalAllowed===false?'none':'vault subject/action policy')]});
    if(o.externalAllowed===false)return reject('external-policy',403,[grant],'k8sVault');
    const response=object('response','Authorized external result','k8sVault',{status:200,data:'synthetic vault training data'});
    event('external-result-create','Create independently authorized external result','k8sVault',[response],{create:[response],effects:[k8sPut('status',200),k8sPut('response',{status:200,authority:'external vault fixture'})]});
    event('result','Receive protected external result','k8sVault',[response],{to:'k8sClient',effects:[k8sPut('firstDetector','result'),k8sPut('client.statusKnown',200),k8sPut('resultReceived',true),k8sPut('decisionStrip.result','200 external result received')]});
    return finish();
  }
  if(o.impersonation){
    const originalIdentity=identity,originalAudit=object('audit-identities','Original authenticated caller audit provenance','k8sAPI',{original:user,requestedTarget:target,impersonated:null,headersAreUntrusted:true},{type:'audit-record'});k8sDerive(originalAudit,identity,headers);
    event('audit-original','Retain original caller before accepting any impersonation header','k8sAPI',[identity,originalAudit],{create:[originalAudit],effects:[k8sPut('audit',{original:user,impersonated:null})]});
    // Every requested header was carried by the exact original API request.
    const constrained=o.bundle==='constrained-impersonation',extraPolicy=policy;
    const identityQuestion={resourceRequest:true,verb:constrained?'impersonate:user-info':'impersonate',apiGroup:constrained?'authentication.k8s.io':'',resource:'users',subresource:'',namespace:'',name:target};
    const identityPermission=k8sAuthorize(user,identityQuestion,extraPolicy),actionPermission=constrained?k8sAuthorize(user,{...request.attributes,verb:'impersonate-on:user-info:'+request.attributes.verb},extraPolicy):{allowed:true,matches:[]};
    const legacy=constrained&&o.legacyFallback?k8sAuthorize(user,{...identityQuestion,verb:'impersonate',apiGroup:''},extraPolicy):{allowed:false};
    const attributeChecks=[...(o.impersonateGroups||[]).map(group=>({attribute:'group',value:group,decision:k8sAuthorize(user,{resourceRequest:true,verb:'impersonate',apiGroup:'',resource:'groups',subresource:'',namespace:'',name:group},extraPolicy)})),...Object.entries(o.impersonateExtra||{}).flatMap(([name,values])=>values.map(value=>({attribute:'extra',name,value,decision:k8sAuthorize(user,{resourceRequest:true,verb:'impersonate',apiGroup:'authentication.k8s.io',resource:'userextras',subresource:name,namespace:'',name:value},extraPolicy)})))];
    const permitted=(identityPermission.allowed&&actionPermission.allowed||legacy.allowed)&&attributeChecks.every(check=>check.decision.allowed);
    const verdict=object('impersonation-verdict','Identity and action impersonation permission','k8sAPI',{original:user,requestedTarget:target,identityPermission,actionPermission,attributeChecks,legacyFallback:legacy.allowed,allowed:permitted,feature:constrained?{name:'ConstrainedImpersonation',maturity:'beta since v1.36',enabled:true}:null});event('impersonation','Authorize every requested impersonation attribute locally','k8sAPI',[identity,headers,verdict],{create:[verdict],kind:'verify',effects:[k8sPut('impersonation',{original:user.username,target,allowed:permitted,legacyFallback:legacy.allowed})]});if(!permitted)return reject('impersonation',403,[verdict],'k8sAPI');
    const original=user;user={username:target,groups:['system:authenticated']};identity=object('impersonated-userinfo','Permitted impersonated userInfo','k8sAPI',user,{representation:'accepted'});k8sDerive(identity,verdict,headers);
    const audit=object('audit-identities','Original and impersonated audit identities','k8sAPI',{original,impersonated:user,unionedPermissions:false},{generation:'g2',type:'audit-record'});k8sDerive(audit,originalAudit,originalIdentity,identity);
    event('impersonated-identity','Install permitted target with original audit provenance','k8sAPI',[identity,audit],{create:[identity,audit],effects:[k8sPut('userInfo',user),k8sPut('audit',{original,impersonated:user}),k8sPut('decisionStrip.identity',user.username)]});
  }
  if(bootstrap.length){const selfGrant=object('self-review-grant','Pinned-source standard basic-user self-review grant','k8sAPI',bootstrap,{initial:true,type:'policy'});event('self-review-policy','Use only explicitly declared bootstrap review rights','k8sAPI',[selfGrant],{kind:'use'});}
  const attrs=object('request-attributes','Exact request authorization attributes','k8sAPI',request.attributes);event('attributes','Derive action, API group, resource, subresource and scope','k8sAPI',[requestRef,attrs],{create:[attrs],effects:[k8sPut('requestAttributes',request.attributes),k8sPut('decisionStrip.action',request.attributes.verb+' '+(request.attributes.resource||request.attributes.path))]});
  if(planId==='K8S06'){
    const reviewPermission=k8sAuthorize(user,{resourceRequest:true,verb:'create',apiGroup:'authorization.k8s.io',resource:'selfsubjectaccessreviews',subresource:'',namespace:'',name:''},policy);
    const answer=k8sAuthorize(user,request.attributes,policy),reviewResult=object('access-review-result','Advisory SelfSubjectAccessReview result','k8sAPI',{apiVersion:'authorization.k8s.io/v1',kind:'SelfSubjectAccessReview',status:{allowed:answer.allowed,denied:false,reason:'Current Node,RBAC evaluation'},reviewCreateAllowed:reviewPermission.allowed,reusableGrant:false,stored:false});
    event('can-i-evaluate','Evaluate advisory question against current policy','k8sAPI',[accessReviewRef,reviewResult],{create:[reviewResult],kind:'verify',effects:[k8sPut('accessReview',{allowed:answer.allowed,reusableGrant:false})]});
    event('can-i-response','Receive advisory yes/no only','k8sAPI',[reviewResult],{to:'k8sClient'});
    if(o.removeBindingAfterReview){policy=policy.filter(entry=>entry.metadata.name!=='read-pods');const changed=object('changed-policy','Current policy changed after review','k8sAPI',policy);event('policy-change','Owner removes reader binding before actual execution','k8sAPI',[changed],{create:[changed]});policyRef=changed;}
    event('execute-request','Issue the actual resource request after can-i','k8sClient',[requestRef,tokenRef],{to:'k8sAPI'});
    event('execute-authenticate','Re-evaluate actual request credential, not reuse advisory grant','k8sAPI',[tokenRef,identity],{kind:'verify',summary:'Same deterministic token remains valid at this clock; current resource policy is evaluated anew.'});
  }
  const verdict=k8sAuthorize(user,request.attributes,policy),grant=object('grant','Node,RBAC matching grant evidence','k8sAPI',verdict);k8sDerive(grant,identity,attrs,policyRef);
  event('authorize','Resolve exact subject -> binding -> role -> matching rule','k8sAPI',[identity,attrs,grant,policyRef],{create:[grant],kind:'verify',effects:[k8sPut('authorization',verdict),k8sPut('decisionStrip.matchingGrant',verdict.allowed?verdict.matches.map(match=>match.binding.name+' -> '+match.role.name+' rule'+match.ruleIndex).join('; '):'none')]});if(!verdict.allowed)return reject('rbac',403,[identity,grant],'k8sAPI');
  if(o.mutateRoleRef)return reject('rbac-object-validation',422,[policyRef],'k8sAPI',{reason:'RoleBinding roleRef is immutable; replace binding under appropriate checks, never mutate as shortcut'});
  if(planId==='K8S08'&&o.write){
    const proposal=proposalValue,proposed=proposalRef;
    if(o.dataType==='number')return reject('api-validation',400,[proposed],'k8sAPI',{reason:'Typed ConfigMap JSON decoding rejects number for string data before admission; selected-tag transformDecodeError -> BadRequest'});
    const mutation=object('mutation-verdict','Core mutating admission no-op','k8sAPI',{matchedCustomMutation:false,changed:false});event('mutate','Run mutating phase without custom mutation','k8sAPI',[proposed,mutation],{create:[mutation],effects:[k8sPut('admission','mutating-no-op')]});
    const label=proposal.metadata.labels?.training==='approved',admission=object('admission-verdict','Exact ValidatingAdmissionPolicy verdict','k8sAPI',{policy:'demo-training-label',binding:'demo-training-label',validationActions:['Deny'],accepted:label,reason:label?'Admitted':'Invalid',httpStatus:label?null:422});event('admit','Evaluate training=approved policy against proposed object','k8sAPI',[proposed,admission],{create:[admission],kind:'verify',effects:[k8sPut('admission',label?'allowed':'denied'),k8sPut('decisionStrip.admission',label?'allowed':'denied by demo-training-label')]});if(!label)return reject('admission',422,[admission,identity],'k8sAPI',{reason:'Exact VAP omitted reason defaults Invalid ->422, not generic RBAC403'});
    if(o.alreadyExists)return reject('storage',409,[proposed],'k8sAPI',{reason:'ConfigMap already exists; no new persistence'});
    const stored={...proposal,metadata:{...proposal.metadata,uid:'config-1',resourceVersion:'43',creationTimestamp:'2026-10-22T00:00:00Z'}},persisted=object('persisted-object','Persisted accepted ConfigMap','k8sAPI',stored);event('persist','Persist separately accepted representation','k8sAPI',[persisted],{create:[persisted],effects:[k8sPut('persisted',[stored])]});const readback=object('readback','API read-back of stored representation','k8sAPI',stored);event('read-back','Read back exact persisted bytes through API storage boundary','k8sAPI',[persisted,readback],{create:[readback],kind:'use'});return result(201,readback);
  }
  if(planId==='K8S15'){
    const mode=o.rbacWrite,binding=mode.startsWith('bind'),role=rbacRole,proposal=proposalValue,proposed=proposalRef,targetRole=proposal.roleRef?.name||role.metadata.name;
    const heldRights=role.rules.every(rule=>(rule.apiGroups||[]).every(apiGroup=>(rule.resources||[]).every(resource=>rule.verbs.every(verb=>k8sAuthorize(user,{resourceRequest:true,verb,apiGroup,resource,subresource:'',namespace:'demo-dev',name:''},policy).allowed))));
    const explicit=k8sAuthorize(user,{resourceRequest:true,verb:binding?'bind':'escalate',apiGroup:'rbac.authorization.k8s.io',resource:'roles',subresource:'',namespace:'demo-dev',name:targetRole},policy).allowed;
    const allowed=heldRights||explicit,safeguard=object('delegation-check','Separate '+(binding?'bind':'escalate')+' safeguard','k8sAPI',{ordinaryCreateAllowed:true,check:binding?'bind':'escalate',alreadyOwnsEveryDelegatedPermission:heldRights,explicitScopedPrivilege:explicit,allowed,targetRole,namespace:'demo-dev'});
    event('delegation','Check every delegated rule against held rights or explicit scoped privilege','k8sAPI',[proposed,safeguard],{create:[safeguard],kind:'verify'});
    if(!allowed)return reject(binding?'bind':'escalate',403,[safeguard],'k8sAPI');
    event('rbac-admission','Run remaining core admission with no matching custom policy','k8sAPI',[safeguard],{kind:'verify',effects:[k8sPut('admission','allowed'),k8sPut('decisionStrip.admission','allowed: no matching custom policy')]});
    const stored={...proposal,metadata:{...proposal.metadata,uid:'rbac-1',resourceVersion:'44',creationTimestamp:'2026-10-22T00:00:00Z'}},persisted=object('persisted-object','Persisted checked RBAC object','k8sAPI',stored);event('persist','Persist only after create and delegation safeguards','k8sAPI',[persisted],{create:[persisted],effects:[k8sPut('persisted',[stored])]});
    const laterPolicy=[...policy,proposal],later=object('later-policy','Separate future-request permission consequence','k8sAPI',{subject:'oidc:bob',attributes:{verb:'list',apiGroup:'',resource:'pods',namespace:'demo-dev'},decision:k8sAuthorize({username:'oidc:bob',groups:['system:authenticated']},{resourceRequest:true,verb:'list',apiGroup:'',resource:'pods',subresource:'',namespace:'demo-dev',name:''},laterPolicy),warning:'Role existence alone grants nothing; only a checked persisted binding changes later matching grants.'});
    event('later-policy','Inspect policy consequence without granting a reusable review token','k8sAPI',[later],{create:[later],kind:'verify'});
    return result(201,persisted);
  }
  if(isWhoami)event('review-admission','Complete virtual self-review with no matching custom mutation or validation','k8sAPI',[grant],{kind:'verify',summary:'The configured custom policy matches ConfigMap CREATE, not SelfSubjectReview. This virtual review is not persisted and creates no User object.',effects:[k8sPut('admission','allowed-unpersisted-review'),k8sPut('decisionStrip.admission','no matching custom policy; review not stored')]});
  else event('read-boundary','Use allowed API read storage boundary','k8sAPI',[grant,...(storageView?[storageView]:[])],{kind:'use',summary:'Read uses an existing API watch-cache/storage view; no admission and no unconditional etcd RPC.',effects:[k8sPut('admission','not-applicable-read'),k8sPut('decisionStrip.admission','skipped: read')]});
  if(isWhoami){const review=object('self-review','SelfSubjectReview v1 accepted caller response','k8sAPI',{apiVersion:'authentication.k8s.io/v1',kind:'SelfSubjectReview',status:{userInfo:user}});event('self-review-create','Create unstored caller-mapping review result','k8sAPI',[review],{create:[review]});return result(201,review);}
  const data=readValue;
  if(data===null)throw new RangeError('No authored successful response fixture for '+request.attributes.resource);
  const response=object('pod-list','Authorized protected API result','k8sAPI',data);k8sDerive(response,...(storageView?[storageView]:[]),grant);event('result-create','Create result after current authorization','k8sAPI',[response],{create:[response]});return result(200,response);
  function result(status,response){event('result','Receive separately authorized API result','k8sAPI',[response],{to:'k8sClient',effects:[k8sPut('status',status),k8sPut('client.statusKnown',status),k8sPut('firstDetector','result'),k8sPut('resultReceived',true),k8sPut('response',{status,artifactId:response.artifactId}),k8sPut('decisionStrip.result',status+' result received')]});return finish();}
}
