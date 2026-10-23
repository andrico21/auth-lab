import {labAttribute,labP,labStep,labScenario} from './lab-common.js';
import {jwtParseCompact,jwtValidateFixture} from './jwt-policy.js';
import {K8S_PLAN_BUNDLES,K8S_PLAN_CONFIGURATIONS,K8S_SOURCE_PROFILE} from './kubernetes-fixtures.js';
import {K8S_CASE_ROWS} from './kubernetes-case-data.js';
import {k8sCreateRequestCase,k8sCatalogKeys} from './kubernetes-request-model.js';

export const KUBERNETESAUTHLAB_ATTRIBUTES={};
export const KUBERNETESAUTHLAB_SOURCES=[
  {name:'Kubernetes v1.37.1 release and implementation',standard:'Kubernetes v1.37.1',url:'https://github.com/kubernetes/kubernetes/releases/tag/v1.37.1',section:'Published patch; selected source commit',revision:K8S_SOURCE_PROFILE.commit,retrieved:'2026-10-22',publicationStatus:'Published stable patch',supportStatus:K8S_SOURCE_PROFILE.support},
  {name:'Kubernetes authentication',standard:'Kubernetes v1.37.1 authentication',url:'https://kubernetes.io/docs/reference/access-authn-authz/authentication/',section:'OIDC, exec credential plugins, anonymous requests',revision:'Rolling documentation snapshot retained 2026-10-22; implementation pinned separately',retrieved:'2026-10-22',publicationStatus:'Official implementation documentation'},
  {name:'Kubernetes RBAC',standard:'Kubernetes v1.37.1 RBAC',url:'https://kubernetes.io/docs/reference/access-authn-authz/rbac/',section:'Rules, binding subjects, scope and anti-escalation',revision:K8S_SOURCE_PROFILE.commit,retrieved:'2026-10-22',publicationStatus:'Official implementation documentation'},
  {name:'OpenID Connect Core 1.0',standard:'OpenID Connect Core 1.0',url:'https://openid.net/specs/openid-connect-core-1_0.html',section:'3.1.2; 3.1.3.7; 12',revision:'Errata set 2',retrieved:'2026-10-22',publicationStatus:'Final specification'},
  {name:'RFC 7636 PKCE',standard:'RFC 7636',url:'https://www.rfc-editor.org/rfc/rfc7636.html',section:'4',revision:'September 2015',retrieved:'2026-10-22',publicationStatus:'Standards Track'},
  {name:'RFC 8252 native OAuth',standard:'RFC 8252',url:'https://www.rfc-editor.org/rfc/rfc8252.html',section:'7; 8',revision:'October 2017',retrieved:'2026-10-22',publicationStatus:'Best Current Practice'},
  {name:'ExecCredential v1',standard:'Kubernetes client authentication v1',url:'https://kubernetes.io/docs/reference/config-api/client-authentication.v1/',section:'ExecCredentialSpec; ExecCredentialStatus',revision:'v1; selected client-go source '+K8S_SOURCE_PROFILE.commit,retrieved:'2026-10-22',publicationStatus:'Stable since Kubernetes v1.22'},
  ...[
    ['Kubernetes AuthenticationConfiguration v1','https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/','JWTAuthenticator; claim mapping; user validation; anonymous'],
    ['Kubernetes API authorization','https://kubernetes.io/docs/reference/access-authn-authz/authorization/','Request attributes; Node,RBAC chain; access reviews'],
    ['Kubernetes ServiceAccount lifecycle','https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/','Bound claims; UID/deletion checks; TokenReview and offline limits'],
    ['Kubernetes projected ServiceAccount tokens','https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/','Projection; audience; returned expiry; rotation'],
    ['Kubernetes TokenReview v1','https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/','spec.token/spec.audiences; status.authenticated/status.audiences/user'],
    ['Kubernetes ValidatingAdmissionPolicy','https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/','matchConstraints; validations; binding validationActions; default reason'],
    ['Kubernetes admission stages','https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/','Mutating then validating; read bypass'],
    ['Kubernetes impersonation','https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/','Classic attributes; constrained beta; action permission; legacy fallback'],
    ['Kubernetes self-review bootstrap policy','https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go','371-372; 722 - explicit system:basic-user self-review grant'],
  ].map(([name,url,section])=>({name,standard:name,url,section,revision:K8S_SOURCE_PROFILE.commit+' implementation; dated official documentation snapshots retained separately',retrieved:'2026-10-22',publicationStatus:'Official source/documentation; symbolic fixture, not live conformance'})),
];
export const k8sActors={
  k8sClient:{name:'kubectl / workload',art:'workstation',kind:'client',role:'Presents one exact credential for one API action',position:{x:145,y:120},color:'#38bdf8'},
  k8sPlugin:{name:'Exec plugin + browser',art:'workstation',kind:'client',role:'Local native OIDC client and private credential cache',parentId:'k8sClient',position:{x:145,y:365},color:'#a78bfa'},
  k8sIssuer:{name:'Human OIDC issuer',kind:'idp',role:'Human authentication and ID-token issuer',position:{x:560,y:120},color:'#22c55e'},
  k8sAPI:{name:'Kubernetes API server',kind:'service',role:'Local authentication, authorization and admission stages',position:{x:975,y:120},color:'#f59e0b'},
  k8sStorage:{name:'API watch cache / storage',kind:'service',parentId:'k8sAPI',role:'Symbolic API storage boundary, not an unconditional etcd RPC',position:{x:975,y:365},color:'#34d399'},
  k8sKubelet:{name:'Kubelet / projection',kind:'client',role:'Authorized TokenRequest client and projected volume writer',position:{x:560,y:365},color:'#a78bfa'},
  k8sVault:{name:'External vault fixture',kind:'service',role:'Independent token validator and resource policy authority',position:{x:560,y:610},color:'#e879f9'},
};
export function k8sFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(k8sFreeze);Object.freeze(value);}return value;}
export function k8sPut(path,value){return {op:'put',path:'kubernetes.'+path,value};}
export function k8sDerive(output,...inputs){output.definition.derivedFrom=inputs.map(input=>input.artifactId);return output;}
export function k8sBundle(id){const bundle=[...K8S_PLAN_BUNDLES,...K8S_PLAN_CONFIGURATIONS].find(entry=>entry.id===id);if(!bundle)throw new RangeError('Unknown Kubernetes bundle '+id);return JSON.parse(JSON.stringify(bundle));}
export function k8sBasePolicy(options={}){
  let objects=k8sBundle('core-rbac').objects;
  if(options.bundle)objects.push(...(k8sBundle(options.bundle).objects||[]));
  if(options.removeAllBindings)objects=objects.filter(object=>!['RoleBinding','ClusterRoleBinding'].includes(object.kind));
  if(options.removeBinding)objects=objects.filter(object=>object.metadata.name!==options.removeBinding);
  return objects;
}
export function k8sSubjectMatches(subject,user){return subject.kind==='User'?subject.name===user.username:subject.kind==='Group'?user.groups.includes(subject.name):subject.kind==='ServiceAccount'?user.username==='system:serviceaccount:'+subject.namespace+':'+subject.name:false;}
export function k8sAuthorize(user,attributes,objects){
  const matches=[];
  for(const binding of objects.filter(object=>['RoleBinding','ClusterRoleBinding'].includes(object.kind))){
    if(binding.kind==='RoleBinding'&&(!attributes.namespace||binding.metadata.namespace!==attributes.namespace))continue;
    const subject=binding.subjects.find(candidate=>k8sSubjectMatches(candidate,user));if(!subject)continue;
    const role=objects.find(object=>object.kind===binding.roleRef.kind&&object.metadata.name===binding.roleRef.name&&(object.kind==='ClusterRole'||object.metadata.namespace===binding.metadata.namespace));if(!role)continue;
    for(const [index,rule] of role.rules.entries()){
      const verb=rule.verbs.includes(attributes.verb)||rule.verbs.includes('*');
      const resource=attributes.resourceRequest?(rule.apiGroups||[]).some(group=>group===attributes.apiGroup||group==='*')&&(rule.resources||[]).some(name=>name===attributes.resource+(attributes.subresource?'/'+attributes.subresource:'')||name==='*'):Boolean(rule.nonResourceURLs?.some(path=>path===attributes.path||path.endsWith('*')&&attributes.path.startsWith(path.slice(0,-1))));
      const named=!rule.resourceNames?.length||Boolean(attributes.name&&rule.resourceNames.includes(attributes.name));
      if(verb&&resource&&named)matches.push({subject,binding:{kind:binding.kind,name:binding.metadata.name,namespace:binding.metadata.namespace||''},role:{kind:role.kind,name:role.metadata.name,namespace:role.metadata.namespace||''},ruleIndex:index,rule});
    }
  }
  return {allowed:matches.length>0,chain:[{authorizer:'Node',decision:'NoOpinion'},{authorizer:'RBAC',decision:matches.length?'Allow':'NoOpinion'}],matches,overall:matches.length?'Allow':'Deny'};
}
export function k8sRequest(options={}){
  if(options.path)return {method:options.method||'GET',path:options.path,attributes:{resourceRequest:false,verb:(options.method||'GET').toLowerCase(),path:options.path}};
  const resource=options.resource||'pods',namespace=resource==='nodes'?'':options.namespace??'demo-dev',name=options.name||'',subresource=options.subresource||'',method=options.method||(options.write||options.rbacWrite?'POST':'GET');
  const apiGroup=['roles','rolebindings','clusterrolebindings'].includes(resource)?'rbac.authorization.k8s.io':'';
  const prefix=apiGroup?'/apis/'+apiGroup+'/v1':'/api/v1';
  const path=prefix+(namespace?'/namespaces/'+namespace:'')+'/'+resource+(name?'/'+name:'')+(subresource?'/'+subresource:'');
  const verb=method==='GET'?(name?'get':'list'):method==='POST'?'create':method==='DELETE'?'delete':method==='PATCH'?'patch':'update';
  return {method,path,attributes:{resourceRequest:true,verb,apiGroup,version:'v1',resource,subresource,namespace,name}};
}
export function k8sToken(options={}){
  const issuer=options.iss||'https://issuer.demo.example',kid=options.kid||'human-old';
  const claims={iss:issuer,sub:options.subject||'alice',aud:options.aud||'kubernetes-demo',iat:1792627200,exp:1792630800,tenant:'demo',groups:options.groups||((options.subject||'alice')==='alice'?['readers']:options.subject==='bob'?['observers']:[]),nonce:options.idTokenNonce||'SYM(login-nonce)',...options.claims};
  if(options.deleteClaim)delete claims[options.deleteClaim];
  if(options.serviceAccount)for(const field of ['tenant','groups','nonce'])delete claims[field];
  const encode=value=>btoa(JSON.stringify(value)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const header={alg:'RS256',kid},signatureSegment=encode('SYM('+kid+' signature; not numeric crypto)');
  const compact=encode(header)+'.'+encode(claims)+'.'+signatureSegment,instanceId=options.instanceId||'k8s-human-idtoken:g1';
  const key={id:kid,kid,issuer,kty:'RSA',alg:'RS256',use:'sig',key_ops:['verify']};
  return {compact,instanceId,claims,header,key,evidence:{kind:'SYM',valid:options.signatureValid!==false,tokenInstanceId:instanceId,keyId:key.id,signingInput:compact.slice(0,compact.lastIndexOf('.')),signatureSegment}};
}
export function k8sValidate(token,options={}){
  return jwtValidateFixture({token:{compact:token.compact,instanceId:token.instanceId},profile:{id:options.serviceAccount?'k8s-service-account':'k8s-human-oidc',issuer:options.expectedIssuer||(options.serviceAccount?'https://kubernetes.demo.example':'https://issuer.demo.example'),audience:options.expectedAudience||(options.serviceAccount?'https://kubernetes.demo.example':'kubernetes-demo'),algorithms:['RS256'],requiredClaims:['iss','sub','aud','exp'],skewSeconds:0,audienceArray:true,purpose:options.serviceAccount?'service-account':'kubernetes-id',...(options.nonce?{nonce:options.nonce}:{})},keys:options.keys||[token.key],signatureEvidence:token.evidence,now:options.now??1792627200});
}
export function k8sAuthor(row,variantId,options={},register=false){
  const id=row.runtimeId,steps=[],definitions={},inventory={artifacts:[],initial:[],events:{},bindings:[]},actors=Object.fromEntries((options.actorIds||['k8sClient','k8sPlugin','k8sIssuer','k8sAPI','k8sStorage']).map(actor=>[actor,k8sActors[actor]]));
  const object=(key,label,creator,value,{initial=false,holders=[creator],store='local store',representation='plain',type='protocol-object',readers=Object.keys(actors),generation='g1',derivedFrom=[],replaces=[]}={})=>{
    const artifactId=id+':'+key+':'+generation,attributeId='k8s_'+row.planId.toLowerCase()+'_'+key.replace(/[^a-zA-Z0-9]/g,'_')+'_'+generation;
    const display=typeof value==='string'?value:JSON.stringify(value);
    const source=/policy|grant|role|delegation|impersonat|audit/.test(key)?KUBERNETESAUTHLAB_SOURCES[2]:/admission|mutation/.test(key)?KUBERNETESAUTHLAB_SOURCES.find(source=>source.standard==='Kubernetes ValidatingAdmissionPolicy'):options.serviceAccount?KUBERNETESAUTHLAB_SOURCES.find(source=>source.standard==='Kubernetes ServiceAccount lifecycle'):KUBERNETESAUTHLAB_SOURCES[1];
    definitions[attributeId]={...labAttribute(label,label+' is an exact synthetic '+representation+' representation; receipt, validation and permission are separate.',creator,'Inspect exact state and provenance without granting trust by inspection.',display,source.standard,source.url),section:source.section,synthetic:true,readers};
    const definition={artifactId,instanceId:artifactId,label,type,creator,sourceEventId:initial?'initial':null,...(derivedFrom.length?{derivedFrom}:{}),...(replaces.length?{replaces}:{}),representations:[{representationId:representation,format:representation,readableBy:readers,fields:[{attributeId,name:label,value:display,readableBy:readers,sourceEventId:initial?'initial':null,exactValueRef:artifactId+':'+representation+':'+label}]}]};
    const ref={artifactId,attributeId,label,value:display,creator,representation,instanceId:artifactId,definition};
    inventory.artifacts.push(definition);
    if(initial)inventory.initial.push({op:'create',artifactId},...holders.map(actorId=>({op:'acquire',artifactId,actorId,store,representationId:representation})));
    return ref;
  };
  const acquire=(ref,actorId,store='local store')=>({op:'acquire',artifactId:ref.artifactId,actorId,store,representationId:ref.representation});
  const event=(key,title,actor,refs=[],{to=actor,kind='inspect',create=[],effects=[],summary=title,transport,protocol}={})=>{
    const sourceEventId=id+':'+key,local=actor===to,operations=[];
    for(const ref of create){ref.definition.sourceEventId=sourceEventId;for(const field of ref.definition.representations[0].fields)field.sourceEventId=sourceEventId;}
    for(const ref of refs){const common={attributeId:ref.attributeId,instanceId:ref.instanceId,creator:ref.creator,holders:local?[actor]:[actor,to],inspectors:[actor,to],fieldPath:ref.label,representation:ref.representation,value:ref.value,sourceEventId,exactValueRef:ref.artifactId+':'+ref.representation+':'+ref.label,detail:summary};if(local)operations.push({...common,actorId:actor,kind:create.includes(ref)?'create':kind});else operations.push({...common,actorId:actor,kind:'send'},{...common,actorId:to,kind:'receive'});}
    const step=labStep(sourceEventId,title,actor,to,key,local||transport==='local IPC'||transport==='local file access'?'internal':'backchannel',summary,summary,refs.map(ref=>ref.attributeId),refs.map(ref=>labP(ref.label,ref.value,summary,ref.attributeId)),[],operations);
    step.eventType=local?'local':'message';step.protocolLabel=protocol||(local?'API/client local stage':transport==='local IPC'?'ExecCredential v1 local IPC':'HTTPS');step.layers=[{protocol:step.protocolLabel,transport:local?'local computation':transport||'TLS-protected HTTPS',from:actor,to,protection:local?'Actor-local computation; no fabricated RPC':transport==='local file access'?'Local read of projected file, not a network packet or stdout transfer':transport==='local IPC'?'Local process stdout/input boundary':protocol==='Native redirect'?'Issuer HTTPS response followed by exact loopback callback; no API-server browser redirect':'Synthetic TLS channel; endpoint verification assumed'}];step.protocolEffects=effects;step.cryptoDetail='SYM/HANDLE inputs are symbolic; no numeric signature or live cluster conformance.';
    const held=[...create.flatMap(ref=>[{op:'create',artifactId:ref.artifactId},acquire(ref,ref.creator)])];
    if(!local)held.push(...refs.map(ref=>acquire(ref,to,'received '+key)));
    if(local&&kind!=='inspect')for(const ref of refs)if(!create.includes(ref)){
      held.push({op:'observe',artifactId:ref.artifactId,actorId:actor,representationId:ref.representation,kind:['verify','decrypt'].includes(kind)?'verification':'knowledge',result:kind+' at '+key});
    }
    inventory.events[sourceEventId]={effects:held,messages:local?[]:[{from:actor,to,start:0,end:1,objects:refs.map(ref=>({artifactId:ref.artifactId,representationId:ref.representation}))}]};
    steps.push(step);return step;
  };
  const finish=()=>{
    const model=labScenario({id,title:row.title,summary:row.goal,workspace:'kubernetes',family:row.family,protocol:'Kubernetes',category:'Kubernetes',standard:'Kubernetes v1.37.1',source:KUBERNETESAUTHLAB_SOURCES[1].url,learningObjective:row.goal,prerequisites:row.preconditions||[],supportNote:K8S_SOURCE_PROFILE.schema,keywords:['Kubernetes','kubectl','OIDC','RBAC','TokenRequest',row.planId],variantId,fixtureInputs:options,initialState:{kubernetes:{credential:null,untrustedClaims:null,signatureValid:false,validatedClaims:null,candidateUserInfo:null,userInfo:null,requestAttributes:null,authorization:null,admission:'not-reached',persisted:[],response:null,resultReceived:false,firstDetector:null,status:null,client:{cache:'empty',login:'not-started'},decisionStrip:{credential:'not-presented',identity:'not-accepted',action:'not-parsed',matchingGrant:'not-evaluated',admission:'not-reached',result:'not-received'}}},kubernetesInventory:inventory,profile:{id:'k8s-v1.37.1-offline',name:'Kubernetes v1.37.1 - synthetic offline fixture',version:'v1.37.1',publicationStatus:'Published stable patch',supportStatus:K8S_SOURCE_PROFILE.support,implementation:K8S_SOURCE_PROFILE.commit,assumptions:['No live cluster, credentials or runtime network','Node,RBAC; Node has no opinion for these requests','Exact plan fixtures; isolated policy reset'],transports:['HTTPS','local IPC','local API processing'],completion:'Credential -> identity -> requested action -> matching grant -> admission when relevant -> result',algorithms:['RS256 symbolic signature evidence'],cryptoDetail:'No runtime production cryptography; fixture evidence binds exact encoded input.',startingSummary:['Alice starts with kubeconfig and trusted API CA, not a Kubernetes session.','The plugin alone owns login state and refresh credentials.','The API has issuer-scoped public keys and exact namespaced RBAC rules.'],sources:KUBERNETESAUTHLAB_SOURCES},relatedLessons:[{id:'lab-jwt08',title:'JWT purpose and Kubernetes',summary:'Independent lesson; navigation transfers no real credential.'},{id:'lab-k8s04',title:'Explain the reader grant',summary:'Same named policy, independently reset request identity.'}]},definitions,steps,actors);
    const schema={};
    model.initialState.kubernetes.client.statusKnown=null;
    if(row.planId==='K8S14')model.initialState.kubernetes.audit={original:null,impersonated:null};
    if(row.planId==='K8S12')model.initialState.kubernetes.vault={authenticated:false,authorized:false,userInfo:null};
    for(const key of k8sCatalogKeys(row.planId))for(const generation of ['sa-token','audit-identities'].includes(key)?['g1','g2']:['g1']){
      const attributeId='k8s_'+row.planId.toLowerCase()+'_'+key.replace(/[^a-zA-Z0-9]/g,'_')+'_'+generation;
      schema[attributeId]=labAttribute(key.replace(/-/g,' '),'Instance-specific Kubernetes fixture field; inspect the selected scenario generation for its exact value.','Declared Kubernetes source owner','Keep every named variant field discoverable without constructing all variants at startup.','Selected-case exact value','Kubernetes v1.37.1',KUBERNETESAUTHLAB_SOURCES[1].url);
    }
    model.catalogAttributeIds=[...new Set([...Object.keys(schema),...model.ids])];
    model.catalogDefinitions={...schema,...definitions};
    model.decisionBindings=[['Credential','credential'],['Identity','identity'],['Requested action','action'],['Matching grant','matchingGrant'],['Admission','admission'],['Result','result']].map(([label,key])=>({label,path:'kubernetes.decisionStrip.'+key}));
    if(row.planId==='K8S01')model.profile={...model.profile,startingSummary:options.clientCache==='valid'?['Client-go already holds an unexpired exact ID token.','No browser or exec-plugin round trip is needed for this cache hit.','API issuer/key trust and reader permission are still checked independently.']:['Alice starts with kubeconfig and trusted API CA, not an API credential.','The plugin will create PKCE/state/nonce and retain any issued refresh token locally.','The API already has issuer public keys and the exact reader binding.']};
    else model.profile={...model.profile,startingSummary:options.credential===false?['No credential is presented. Anonymous endpoint eligibility is not permission.','Only a permitted anonymous path can produce an anonymous principal.','An explicit route/resource grant is still required.']:options.serviceAccount?['K8S09','K8S12'].includes(row.planId)?['The kubelet has its node TLS credential; the workload has no projected token bytes yet.','A scoped authorized TokenRequest must issue a token before file projection and application read.','Token authentication and the later resource grant remain separate.']:['The workload already holds a bounded Kubernetes-issued token, not a human login.','Audience, object binding and expiry precede permission decisions.','Only an explicit matching grant permits protected resource data.']:['The caller presents an already issued synthetic credential.','Configured issuer trust and exact namespace policy are independent.','Identity acceptance never implies the requested action is allowed.']};
    if(row.planId==='K8S13')model.profile={...model.profile,startingSummary:[...model.profile.startingSummary,'Isolated no-grant RBAC snapshot: default system:public-info-viewer bootstrap bindings for system:authenticated and system:unauthenticated are excluded. This is not an untouched-cluster or live result.'],assumptions:[...model.profile.assumptions,'Anonymous eligibility is compared against an authored policy snapshot without default public-info bootstrap grants.']};
    if(options.bundle==='constrained-impersonation')model.profile={...model.profile,publicationStatus:'Published stable patch; ConstrainedImpersonation is beta since v1.36, explicitly enabled',assumptions:[...model.profile.assumptions,'Constrained identity and action permissions are separate. Legacy fallback exists only in the labelled fallback comparison.']};
    if(register)Object.assign(KUBERNETESAUTHLAB_ATTRIBUTES,model.catalogDefinitions);
    return model;
  };
  return {id,steps,inventory,definitions,object,event,acquire,finish};
}

const k8s01Row=K8S_CASE_ROWS.find(row=>row.planId==='K8S01');
const k8s01Variants={default:{},'wrong-state':{returnedState:'SYM(other-state)'},'wrong-pkce':{redeemedVerifier:'SYM(other-verifier)'},'wrong-nonce':{idTokenNonce:'SYM(other-nonce)'},'no-binding':{removeBinding:'read-pods'},'cache-hit':{clientCache:'valid'}};
export function createKubernetesAuthCase(planId='K8S01',variantId='default',register=false){
  if(planId!=='K8S01')return k8sCreateRequestCase(planId,variantId,register);
  if(!Object.hasOwn(k8s01Variants,variantId))throw new RangeError('Unknown Kubernetes variant '+variantId);
  const options={...k8s01Variants[variantId]},a=k8sAuthor(k8s01Row,variantId,options,register),now=1792627200;
  const token=k8sToken({idTokenNonce:options.idTokenNonce,instanceId:a.id+':id-token:g1'});
  const signingKey=a.object('issuer-private-key','Issuer private signing key','k8sIssuer','HANDLE(human-old private key)',{initial:true,type:'private-key',readers:['k8sIssuer']});
  const trust=a.object('issuer-trust','Configured issuer / public key','k8sAPI',{issuer:'https://issuer.demo.example',key:token.key,algorithmDefault:'RS256 from selected tag; not a signingAlgs configuration field'},{initial:true,type:'trust-record'});
  const authConfig=a.object('authentication-config','Exact AuthenticationConfiguration v1','k8sAPI',k8sBundle('core-api-configuration').configurationFiles['authentication.yaml'],{initial:true,type:'policy'});
  const pluginTrust=a.object('plugin-trust','Plugin-local OIDC trust and audience','k8sPlugin',{issuer:'https://issuer.demo.example',audience:'kubernetes-demo',publicKey:token.key},{initial:true,type:'trust-record',readers:['k8sPlugin']});
  const policy=a.object('rbac-policy','Reset core RBAC policy','k8sAPI',k8sBasePolicy(options),{initial:true,type:'policy'});
  const podData={apiVersion:'v1',kind:'PodList',metadata:{resourceVersion:'42'},items:[{apiVersion:'v1',kind:'Pod',metadata:{name:'demo-pod',namespace:'demo-dev',uid:'pod-1'}}]};
  const podView=a.object('resource-snapshot','Pre-existing API cache / storage view','k8sAPI',podData,{initial:true,holders:['k8sAPI','k8sStorage'],readers:['k8sAPI','k8sStorage'],type:'resource-record'});
  const tokenRef=a.object('id-token','ID token compact JWS','k8sIssuer',token.compact,{representation:'readable-untrusted',type:'credential'});
  const fail=(stage,status,actor,refs)=>{
    const result=a.object(stage+'-failure',stage+' rejection',actor,{stage,status,identity:stage==='rbac'?'oidc:alice':null,nextAction:stage==='rbac'?'Inspect namespace/binding, not login again.':'Start a fresh transaction with correct state, verifier and nonce.'});
    a.event(stage+'-reject','Stop at '+stage,actor,[...refs,result],{create:[result],kind:'verify',effects:[k8sPut('firstDetector',stage),k8sPut('status',status),k8sPut('response',{status,stage}),k8sPut('decisionStrip.result','denied')]});
    if(status!==null)a.event('failure-response','Receive Kubernetes Status only','k8sAPI',[result],{to:'k8sClient',effects:[k8sPut('client.statusKnown',status)]});
    else{if(actor==='k8sIssuer')a.event('issuer-login-error','Receive issuer PKCE rejection inside plugin',actor,[result],{to:'k8sPlugin'});a.event('login-error-response','Return local exec plugin failure without an API credential','k8sPlugin',[result],{to:'k8sClient',transport:'local IPC',effects:[k8sPut('client.login','rejected')]});}
    return finish();
  };
  const finish=()=>{const model=a.finish();model.variantChoices=Object.keys(k8s01Variants).map(id=>({id,label:id==='default'?'Successful first login':id.replace(/-/g,' '),description:id==='cache-hit'?'Second request uses an unexpired client-go credential cache; no login or issuer introspection.':'Fixed isolated '+id+' input fixture.'}));model.withVariant=id=>createKubernetesAuthCase('K8S01',id);return k8sFreeze(model);};
  if(options.clientCache==='valid'){
    a.inventory.initial.push({op:'create',artifactId:tokenRef.artifactId},a.acquire(tokenRef,'k8sClient','client-go credential cache'));
    a.event('cache-hit','Reuse unexpired cached ExecCredential','k8sClient',[tokenRef],{kind:'use',effects:[k8sPut('client.cache','hit'),k8sPut('client.login','not-needed')]});
  }else{
    const login=a.object('login-context','PKCE verifier, state and nonce','k8sPlugin',{verifier:'SYM(pkce-verifier)',challenge:'SYM(S256 challenge)',state:'SYM(login-state)',nonce:'SYM(login-nonce)'},{readers:['k8sPlugin'],type:'transaction'});
    const execInput=a.object('exec-input','ExecCredential v1 invocation','k8sClient',{apiVersion:'client.authentication.k8s.io/v1',kind:'ExecCredential',spec:{interactive:true}},{initial:true});
    a.event('exec-invoke','Invoke local exec credential plugin','k8sClient',[execInput],{to:'k8sPlugin',transport:'local IPC'});
    a.event('login-context','Create native login transaction','k8sPlugin',[login],{create:[login],effects:[k8sPut('client.login','pending')]});
    const authorization=a.object('authorization-request','Native authorization request','k8sPlugin',{client_id:'kubernetes-demo',response_type:'code',scope:'openid offline_access',redirect_uri:'http://127.0.0.1:49152/callback',code_challenge:'SYM(S256 challenge)',code_challenge_method:'S256',state:'SYM(login-state)',nonce:'SYM(login-nonce)'});
    a.event('prepare-authorization','Prepare browser authorization request','k8sPlugin',[authorization],{create:[authorization]});
    a.event('browser-authorize','Open system browser at configured issuer','k8sPlugin',[authorization],{to:'k8sIssuer'});
    const callback=a.object('callback','Authorization callback','k8sIssuer',{code:'SYM(single-use authorization-code)',state:options.returnedState||'SYM(login-state)'});
    a.event('issue-code','Authenticate Alice at issuer and issue code','k8sIssuer',[callback,signingKey],{create:[callback],kind:'use',summary:'Human password remains inside issuer authentication; no API-server password form or Kubernetes User object.'});
    a.event('callback','Receive native redirect callback','k8sIssuer',[callback],{to:'k8sPlugin',protocol:'Native redirect',transport:'Issuer HTTPS redirect followed by loopback HTTP 127.0.0.1 callback'});
    if(JSON.parse(callback.value).state!==JSON.parse(login.value).state)return fail('client-state',null,'k8sPlugin',[callback,login]);
    a.event('check-state','Validate exact transaction state','k8sPlugin',[callback,login],{kind:'verify'});
    const redemption=a.object('code-redemption','Code plus PKCE verifier','k8sPlugin',{grant_type:'authorization_code',code:'SYM(single-use authorization-code)',client_id:'kubernetes-demo',redirect_uri:'http://127.0.0.1:49152/callback',code_verifier:options.redeemedVerifier||'SYM(pkce-verifier)'});
    a.event('prepare-redemption','Prepare code redemption','k8sPlugin',[redemption],{create:[redemption]});
    a.event('redeem-code','Redeem code and verifier at issuer only','k8sPlugin',[redemption],{to:'k8sIssuer'});
    if(JSON.parse(redemption.value).code_verifier!==JSON.parse(login.value).verifier)return fail('issuer-pkce',null,'k8sIssuer',[redemption]);
    const refresh=a.object('refresh-token','Plugin-local refresh token','k8sIssuer','SYM(refresh-token issuer-bound)',{type:'credential',readers:['k8sIssuer','k8sPlugin']});
    a.event('issue-tokens','Issue exact ID token and refresh credential','k8sIssuer',[tokenRef,refresh,signingKey],{create:[tokenRef,refresh],kind:'use'});
    a.event('token-response','Receive token response inside plugin','k8sIssuer',[tokenRef,refresh],{to:'k8sPlugin'});
    const pluginCheck=k8sValidate(token,{nonce:'SYM(login-nonce)',now});
    if(!pluginCheck.ok)return fail('client-nonce',null,'k8sPlugin',[tokenRef,login]);
    a.event('plugin-validate','Validate ID token and transaction nonce','k8sPlugin',[tokenRef,login,pluginTrust],{kind:'verify',effects:[k8sPut('client.login','accepted'),k8sPut('client.cache','plugin-local refresh credential')]});
    const consumed=a.event('consume-login','Consume one-use login transaction','k8sPlugin',[login],{kind:'use',effects:[k8sPut('client.transaction','consumed')]});
    a.inventory.events[consumed.id].effects.push({op:'release',artifactId:login.artifactId,actorId:'k8sPlugin',store:'local store',representationId:login.representation});
    const exec=a.object('exec-credential','ExecCredential v1 status','k8sPlugin',{apiVersion:'client.authentication.k8s.io/v1',kind:'ExecCredential',status:{token:token.compact,expirationTimestamp:'2026-10-22T01:00:00Z'}});
    a.event('exec-create','Create ExecCredential status only','k8sPlugin',[exec],{create:[exec]});
    a.event('exec-return','Return ID token and expiration to client-go','k8sPlugin',[exec,tokenRef],{to:'k8sClient',transport:'local IPC',effects:[k8sPut('client.cache','valid until token expiry')]});
  }
  const request=k8sRequest(options),requestRef=a.object('request','Exact API request','k8sClient',{method:request.method,path:request.path,Authorization:'Bearer '+token.compact});
  a.event('request-create','Build exact pod collection request','k8sClient',[requestRef],{create:[requestRef]});
  a.event('api-request','Present bearer ID token over verified TLS','k8sClient',[requestRef,tokenRef],{to:'k8sAPI',effects:[k8sPut('credential',tokenRef.artifactId),k8sPut('decisionStrip.credential','received-untrusted')]});
  const parsed=jwtParseCompact(token.compact),decoded=a.object('decoded-claims','Decoded untrusted claims','k8sAPI',parsed.claims,{representation:'readable-untrusted'});
  k8sDerive(decoded,tokenRef);
  a.event('decode','Decode JWS without trusting claims','k8sAPI',[tokenRef,decoded],{create:[decoded],effects:[k8sPut('untrustedClaims',parsed.claims)]});
  const validated=k8sValidate(token,{now}),signature=a.object('signature-verdict','Exact-token symbolic signature verdict','k8sAPI',{tokenInstanceId:token.instanceId,keyId:validated.keyId,valid:validated.signatureValid,evidence:'SYM - not mathematical signature verification'});
  k8sDerive(signature,tokenRef,trust);
  a.event('signature','Verify symbolic signature evidence with configured key','k8sAPI',[tokenRef,trust,signature],{create:[signature],kind:'verify',effects:[k8sPut('signatureValid',validated.signatureValid)]});
  const accepted=a.object('validated-claims','Validated claims','k8sAPI',validated.validatedClaims,{representation:'accepted'});
  k8sDerive(accepted,tokenRef,signature);
  a.event('validate-claims','Validate issuer, audience and expiry','k8sAPI',[tokenRef,accepted],{create:[accepted],kind:'verify',effects:[k8sPut('validatedClaims',validated.validatedClaims)]});
  const candidate={username:'oidc:'+validated.validatedClaims.sub,groups:validated.validatedClaims.groups.map(group=>'team:'+group)},candidateRef=a.object('candidate-userinfo','Transient mapped candidate','k8sAPI',candidate);
  k8sDerive(candidateRef,accepted,authConfig);
  a.event('candidate-map','Map candidate username and issuer groups locally','k8sAPI',[accepted,authConfig,candidateRef],{create:[candidateRef],effects:[k8sPut('candidateUserInfo',candidate)]});
  a.event('claim-user-rules','Check tenant and mapped-user validation','k8sAPI',[accepted,candidateRef],{kind:'verify',summary:'Candidate mapping is transient. tenant=demo and mapped-name CEL checks must pass before accepting identity.'});
  const user={username:candidate.username,groups:[...candidate.groups,'system:authenticated']},identity=a.object('userinfo','Accepted request userInfo','k8sAPI',user,{representation:'accepted'});
  k8sDerive(identity,candidateRef,authConfig);
  a.event('identity','Accept userInfo and append authenticated group','k8sAPI',[identity],{create:[identity],effects:[k8sPut('userInfo',user),k8sPut('decisionStrip.identity',user.username)]});
  const attrs=a.object('request-attributes','Exact authorization attributes','k8sAPI',request.attributes);
  k8sDerive(attrs,requestRef);
  a.event('attributes','Derive list/core/pods/demo-dev attributes','k8sAPI',[requestRef,attrs],{create:[attrs],effects:[k8sPut('requestAttributes',request.attributes),k8sPut('decisionStrip.action','list core/pods namespace demo-dev')]});
  const verdict=k8sAuthorize(user,request.attributes,k8sBasePolicy(options)),grant=a.object('grant','Node,RBAC decision and exact grant path','k8sAPI',verdict);
  k8sDerive(grant,identity,attrs,policy);
  a.event('authorize','Resolve subject -> binding -> Role -> rule','k8sAPI',[identity,attrs,policy,grant],{create:[grant],kind:'verify',effects:[k8sPut('authorization',verdict),k8sPut('decisionStrip.matchingGrant',verdict.allowed?'read-pods -> reader rule0':'none')]});
  if(!verdict.allowed)return fail('rbac',403,'k8sAPI',[identity,grant]);
  a.event('read-boundary','Read API watch cache / symbolic storage boundary','k8sAPI',[grant,podView],{kind:'use',effects:[k8sPut('admission','not-applicable-read'),k8sPut('decisionStrip.admission','skipped: read')],summary:'Allowed list obtains the existing API view. No admission call and no unconditional etcd network RPC.'});
  const response=a.object('pod-list','Authorized PodList result','k8sAPI',podData);
  k8sDerive(response,podView,grant);
  a.event('result-create','Create authorized PodList response','k8sAPI',[response],{create:[response],effects:[k8sPut('response',{status:200,kind:'PodList'}),k8sPut('status',200)]});
  a.event('result','Receive protected result at kubectl','k8sAPI',[response],{to:'k8sClient',effects:[k8sPut('resultReceived',true),k8sPut('client.statusKnown',200),k8sPut('firstDetector','result'),k8sPut('decisionStrip.result','200 PodList received')]});
  return finish();
}
export const KUBERNETESAUTHLAB_SCENARIOS=['K8S01','K8S02','K8S03','K8S09','K8S10','K8S11','K8S12','K8S13'].map(id=>createKubernetesAuthCase(id,'default',true));
