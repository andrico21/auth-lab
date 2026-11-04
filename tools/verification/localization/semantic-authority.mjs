import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

// Verification-only authority. These expectations come from declared protocol
// members, actor records and case IDs, never from ProtectedRegistry output.
// Loading is explicit so source-table replay need not import/evaluate models.
export async function semanticAuthorityCases({root=fileURLToPath(new URL('../../../',import.meta.url))}={}){
  const load=module=>import(pathToFileURL(path.join(root,module)).href);
  const protocol=await load('src/protocol-data.js'),web=await load('src/web-api-lab.js'),ciba=await load('src/ciba-data.js'),service=await load('src/service-account-data.js'),spake=await load('src/kerberos-spake-lab.js'),dns=await load('src/dnssec-lab.js'),mcp=await load('src/mcp-auth-lab.js');
  const cases=[];
  const add=(id,english,required,ownerId,fieldPath,sourceModule,extra={})=>{
    if(typeof english!=='string'||required.some(value=>!english.includes(value)))throw new Error('Independent semantic authority drift: '+id);
    cases.push({id,english,required,ownerId,fieldPath,sourceModule,...extra});
  };
  const steps=model=>typeof model.steps==='function'?model.steps({}):model.steps;
  const models=(namespace,name)=>namespace[name];
  const step=(model,id)=>{const found=steps(model).find(item=>item.id===id);if(!found)throw new Error('Missing authority step '+id);return found;};
  const bff=web.WEBLAB_SCENARIOS.find(model=>model.id==='lab-bff-api');
  add('oauth-state-nonce',step(bff,'web-bff-redirect').detail,[protocol.ATTRIBUTES.stateApp.name,protocol.ATTRIBUTES.nonceApp.name],'step:web-bff-redirect','detail','src/web-api-lab.js');
  const single=await load('src/single-realm.js'),singleSteps=single.applySingleRealm(protocol.FLOWS.login);
  for(const [id,field,required]of [['single-l20','detail',['state']],['single-l24','detail',['nonce']],['single-l25','detail',['nonce']]]){
    const item=singleSteps.find(item=>item.id===id);add(id+'-'+field,item?.[field],required,'step:'+id,field,'src/single-realm.js');
  }
  const protection=await load('src/protection-lab.js');
  const protectionStep=id=>protection.PROTLAB_SCENARIOS.flatMap(model=>steps(model)).find(item=>item.id===id);
  for(const [id,field,required]of [['prot-jarm-sign','summary',['state']],['prot-par-push','detail',['state']],['prot-dpop-api-challenge-create','detail',['nonce']]]){
    const item=protectionStep(id);add(id+'-'+field,item?.[field],required,'step:'+id,field,'src/protection-lab.js');
  }
  add('dpop-resource-nonce-header',protection.PROTLAB_ATTRIBUTES.protDpopNonceHeader.meaning,['resource server','nonce'],'field:protDpopNonceHeader','meaning','src/protection-lab.js');
  const note=protocol.LEARNING_NOTES.find(item=>item.title==='Four different protections');
  add('callback-member-learning-note',note?.text,['state','nonce'],'learning-note:four-protections','text','src/protocol-data.js');
  const saml=await load('src/saml-data.js'),samlActor=saml.getSamlActorOverrides({upstream:'keycloak',brokerProtocol:'saml'}).realmB;
  add('saml-absence-names-oidc-members',samlActor?.notes.find(text=>text.includes('no OIDC code, state, nonce or token')),['state','nonce'],'actor:realmB','notes','src/saml-data.js');
  const fido=await load('src/fido-direct.js');
  add('fido-contrast-names-oauth-members',fido.getFidoAttributeOverrides().challengeLogin.purpose,['state','nonce'],'field:challengeLogin','purpose','src/fido-direct.js');
  add('realm-a',ciba.CIBA_ATTRIBUTES.cibaLoginHint.purpose,['Realm A'],'field:cibaLoginHint','purpose','src/ciba-data.js');
  add('realm-b',protocol.ATTRIBUTES.clientIdBroker.meaning,['Realm A','Realm B'],'field:clientIdBroker','meaning','src/protocol-data.js');
  add('resource-server',service.SERVICE_ATTRIBUTES.serviceAccessSignature.purpose,['resource server','Realm A'],'field:serviceAccessSignature','purpose','src/service-account-data.js');
  const discovery=mcp.MCPLAB_SCENARIOS.find(model=>model.id==='lab-mcp02');
  add('authorization-server',discovery.title,['authorization server'],'lesson:lab-mcp02','title','src/mcp-auth-lab.js');
  const kerberos=spake.SPAKELAB_SCENARIOS.find(model=>model.id==='lab-krb-spake-success'),actors=kerberos.actors({});
  if(!Object.hasOwn(actors,'spake-kdc'))throw new Error('Missing declared spake-kdc actor');
  const advertisement=step(kerberos,'lab-krb-spake-success-advertisement'),creation=advertisement.attributeOperations.find(operation=>operation.creator==='spake-kdc'&&operation.detail.startsWith('spake-kdc creates its '));
  add('authored-actor-id',creation?.detail,['spake-kdc'],'step:'+advertisement.id,'attributeOperations.detail','src/kerberos-spake-lab.js',{actors});
  const dns09=dns.buildDNSSECScenarioFixture('lab-dnssec09',{variant:'cname-bogus-target'});
  for(const [caseId,required] of [['cname-bogus-target',['cname','bogus']],['cname-insecure-target',['cname','insecure']]]){
    const choice=dns09.variantChoices.find(item=>item.caseId===caseId);
    add(caseId,choice?.label,required,'lesson:lab-dnssec09','variantChoices.label','src/dnssec-lab.js',{context:{variantId:choice.id},caseId});
  }
  const dns11=dns.buildDNSSECScenarioFixture('lab-dnssec11',{variant:'tcp-blocked'}),failure=steps(dns11).find(item=>item.title==='tcp failure not cryptographic bogus');
  add('transport-not-bogus',failure?.title,['tcp','bogus'],'step:'+failure?.id,'title','src/dnssec-network-cases.js');
  const resolution=dns.buildDNSSECScenarioFixture('lab-dnssec03');
  const nonBogus=steps(resolution).find(item=>item.title==='Accept non-bogus data or withhold a bogus answer');
  add('non-bogus-not-secure',nonBogus?.title,['non-bogus','bogus'],'step:'+nonBogus?.id,'title','src/dnssec-resolution-cases.js');
  // Independently sample the same semantic risk in adjacent authored families.
  // Select actual narrative consumers, not source-code string matches.
  for(const [module,exportName,token] of [
    ['src/windows-auth-lab.js','WINDOWSLAB_SCENARIOS','TSRequest'],
    ['src/smb-access-lab.js','SMBLAB_SCENARIOS','SessionId'],
    ['src/nfs-access-lab.js','NFSLAB_SCENARIOS','stateid'],
    ['src/kubernetes-auth-lab.js','KUBERNETESAUTHLAB_SCENARIOS','ExecCredential'],
  ]){
    const namespace=await load(module);let selected;
    for(const model of models(namespace,exportName)){
      for(const item of steps(model))for(const field of ['title','summary','detail'])if(!selected&&typeof item[field]==='string'&&item[field].includes(token))selected={model,item,field};
      if(selected)break;
    }
    if(!selected)throw new Error('Missing declared family authority '+token);
    add('family-'+token,selected.item[selected.field],[token],'step:'+selected.item.id,selected.field,module);
  }
  const pam=await load('src/pam-foundations-lab.js'),pamModel=pam.createPamFoundationsCase('requisite-immediate-failure');
  const physical=pamModel.pamConfiguration?.comparison?.changedLines?.[0];
  if(!physical)throw new Error('Missing physical PAM comparison authority');
  const comparison=pamModel.relatedLessons.find(item=>item.title==='Change only required to requisite');
  add('pam-physical-control',comparison?.title,['required','requisite'],'lesson:lab-pam01','relatedLessons.title','src/pam-foundations-lab.js',{canonicalConfigurationLine:physical.after});
  return cases;
}

export async function semanticAuthorityNegativeCases({root=fileURLToPath(new URL('../../../',import.meta.url))}={}){
  const load=module=>import(pathToFileURL(path.join(root,module)).href),result=[];
  const add=(id,english,ownerId,fieldPath,sourceModule)=>{
    if(typeof english!=='string'||!english.includes('state'))throw new Error('Independent ordinary-state authority drift: '+id);
    result.push({id,english,excluded:['state'],ownerId,fieldPath,sourceModule});
  };
  const findStep=(models,id)=>models.flatMap(model=>typeof model.steps==='function'?model.steps({}):model.steps).find(item=>item.id===id);
  const operation=(item,phrase)=>item?.attributeOperations.find(operation=>operation.detail?.includes(phrase))?.detail;
  const life=await load('src/lifecycle-lab.js'),sso=findStep(life.LIFELAB_SCENARIOS,'lab-sso-existing-session-check');
  add('ordinary-account-consent-request',operation(sso,'account/consent/request state'),'step:'+sso?.id,'attributeOperations.detail','src/lifecycle-lab.js');
  const logout=life.LIFELAB_SCENARIOS.find(model=>model.id==='lab-rp-initiated-logout');
  add('ordinary-local-rp-session',logout?.summary,'lesson:'+logout?.id,'summary','src/lifecycle-lab.js');
  const web=await load('src/web-api-lab.js'),intro=findStep(web.WEBLAB_SCENARIOS,'web-intro-evaluate');
  add('ordinary-issuer-status',operation(intro,'issuer state'),'step:'+intro?.id,'attributeOperations.detail','src/web-api-lab.js');
  const branch=await load('src/branching-lab.js'),jwt=findStep(branch.BRANCHLAB_SCENARIOS,'branch-sessions-jwt');
  add('ordinary-revocation-enforcement',operation(jwt,'state/introspection'),'step:'+jwt?.id,'attributeOperations.detail','src/branching-lab.js');
  const device=await load('src/device-flow-data.js'),pending=device.getDeviceSteps().find(item=>item.id==='device-codes-create');
  add('ordinary-device-transaction-status',operation(pending,'pending server-side transaction state'),'step:'+pending?.id,'attributeOperations.detail','src/device-flow-data.js');
  const ciba=await load('src/ciba-data.js'),approval=ciba.getCibaSteps().find(item=>item.id==='ciba-approved');
  add('ordinary-ciba-approval-status',operation(approval,'pending-request state'),'step:'+approval?.id,'attributeOperations.detail','src/ciba-data.js');
  return result;
}

export const SEMANTIC_NEGATIVE_CONTROLS=[
  {english:'The current protocol state remains local.',excluded:['state'],ownerId:'lesson:lab-bff-api',sourceModule:'src/web-api-lab.js'},
  {english:'A fresh browser session state is not an authorization response.',excluded:['state'],ownerId:'lesson:lab-bff-api',sourceModule:'src/web-api-lab.js'},
  {english:'A local encryption nonce is not the OIDC request claim.',excluded:['nonce'],ownerId:'lesson:lab-bff-api',sourceModule:'src/web-api-lab.js'},
  {english:'User and Client are required to include a nonce.',excluded:['User','Client','required','include','nonce'],ownerId:'fixture:human',sourceModule:'src/study-workspaces.js'},
  {english:'Use secure storage over an insecure connection; inspect the answer later.',excluded:['secure','insecure'],ownerId:'lesson:lab-dnssec09',sourceModule:'src/dnssec-lab.js'},
  {english:'An ordinary state and an insecure design.',excluded:['state','insecure'],ownerId:'fixture:human',sourceModule:'src/study-workspaces.js'},
];
