// Navigation is an allowlist over the same scenario registry used by the player.
// Neither transaction values nor operator-supplied addresses belong in routes.
export const STUDIO_WORKSPACES = Object.freeze([
  {id:'web',title:'Web sign-in',summary:'Keycloak, OAuth / OIDC, SAML, passkeys and MFA',defaultId:'basic-keycloak'},
  {id:'ssh',title:'SSH access',summary:'OIDC enrollment, certificates, device login and server-side PAM',defaultId:'lab-ssh-cert-success'},
  {id:'kerberos',title:'Kerberos',summary:'AD DS, PKINIT, FAST, forests, Keycloak and MIT standards profiles',defaultId:'lab-ad-first-sign-in'},
  {id:'windows',title:'Windows access',summary:'NTLMv2, Negotiate, CredSSP, remote desktop and remote management',defaultId:'lab-win-ntlmv2-domain'},
  {id:'network',title:'Network access',summary:'RADIUS, wired EAP-TLS, admission, accounting and session control',defaultId:'lab-net-eap-tls13-wired'},
  {id:'foundations',title:'Foundations',summary:'Standalone SPAKE2 and SPAKE2+ without an implied application login',defaultId:'lab-pake-spake2-success',secondary:true},
].map(Object.freeze));
export const STUDIO_FAMILIES = Object.freeze([
  {workspace:'kerberos',id:'ad-ds',title:'AD DS Kerberos',summary:'Password sign-in, smart cards, armoring and forests',defaultId:'lab-ad-first-sign-in',routeSegment:''},
  {workspace:'kerberos',id:'keycloak-bridge',title:'Kerberos to Keycloak',summary:'Kerberos-only desktop SSO continues into OIDC; no NTLM fallback',defaultId:'lab-kc-kerberos-sso',routeSegment:'keycloak'},
  {workspace:'kerberos',id:'mit-standards',title:'MIT Kerberos / standards',summary:'PA-SPAKE, reply-key strengthening and explicit timestamp fallback policy',defaultId:'lab-krb-spake-success',routeSegment:'mit'},
  {workspace:'windows',id:'windows-integrated',title:'NTLM, Negotiate and CredSSP',summary:'Identity proof, mechanism selection, target binding and credential custody',defaultId:'lab-win-ntlmv2-domain',routeSegment:'integrated'},
  {workspace:'windows',id:'windows-desktop',title:'Remote desktop',summary:'Ordinary RDP, Restricted Admin and Remote Credential Guard',defaultId:'lab-win-rdp-normal',routeSegment:'desktop'},
  {workspace:'windows',id:'windows-management',title:'Remote management',summary:'WinRM transports, delegation and independent second-hop access',defaultId:'lab-win-winrm-second-hop-denied',routeSegment:'management'},
  {workspace:'windows',id:'windows-files',title:'SMB file access',summary:'Workgroup client, explicit domain credentials, share and file permissions',defaultId:'lab-smb-nonjoined-kerberos',routeSegment:'files'},
  {workspace:'network',id:'network-access',title:'Access authentication',summary:'Credentials, certificates, network policy and the controlled port',defaultId:'lab-net-eap-tls13-wired',routeSegment:'access'},
  {workspace:'network',id:'network-lifecycle',title:'Accounting and session control',summary:'Delivery knowledge, policy changes and targeted disconnection',defaultId:'lab-net-radius-accounting-lifecycle',routeSegment:'lifecycle'},
  {workspace:'network',id:'network-transport',title:'Transport and proxying',summary:'UDP, RadSec, adjacent-peer protection and Experimental RADIUS/1.1',defaultId:'lab-net-radius-udp-radsec',routeSegment:'transport'},
  {workspace:'foundations',id:'pake-spake2',title:'SPAKE2',summary:'Balanced password-equivalent setup and endpoint-specific confirmation',defaultId:'lab-pake-spake2-success',routeSegment:'spake2'},
  {workspace:'foundations',id:'pake-spake2plus',title:'SPAKE2+',summary:'Augmented registration records and verifier-first confirmation',defaultId:'lab-pake-spake2plus-success',routeSegment:'spake2plus'},
].map(Object.freeze));
export function workspaceOf(model){
  if(model?.workspace===undefined)return 'web';
  if(STUDIO_WORKSPACES.some(workspace=>workspace.id===model.workspace))return model.workspace;
  throw new RangeError('Unsupported studio workspace: '+String(model.workspace));
}
export function studioRoute(id,models){
  const model=models[id],workspace=workspaceOf(model);
  const family=STUDIO_FAMILIES.find(item=>item.workspace===workspace&&item.id===model?.family);
  if(model?.family&&STUDIO_FAMILIES.some(item=>item.workspace===workspace)&&!family)throw new RangeError('Unsupported studio family: '+model.family);
  return '#/'+workspace+(family?.routeSegment?'/'+family.routeSegment:'')+'/'+id;
}
function studioDefaultScenario(workspace,models,family){
  const preferred=family?.defaultId||workspace.defaultId;
  if(Object.hasOwn(models,preferred)||workspace.id==='web'&&!family)return preferred;
  return Object.values(models).find(model=>workspaceOf(model)===workspace.id&&(!family||model.family===family.id))?.id||null;
}
export function parseStudioRoute(hash,models,presetIds=[]){
  const fallback={workspace:'web',scenarioId:'basic-keycloak',valid:false};
  if(!hash||hash==='#')return {...fallback,valid:true};
  const value=String(hash).replace(/^#\//,'');
  const workspace=STUDIO_WORKSPACES.find(item=>item.id===value);
  if(workspace){const scenarioId=studioDefaultScenario(workspace,models);return scenarioId?{workspace:workspace.id,scenarioId,valid:true}:fallback;}
  const family=STUDIO_FAMILIES.find(item=>item.routeSegment&&value===item.workspace+'/'+item.routeSegment);
  if(family){const owner=STUDIO_WORKSPACES.find(item=>item.id===family.workspace),scenarioId=studioDefaultScenario(owner,models,family);return scenarioId?{workspace:owner.id,scenarioId,valid:true}:fallback;}
  for(const id of new Set(['core',...presetIds,...Object.keys(models)]))if(hash===studioRoute(id,models))return {workspace:workspaceOf(models[id]),scenarioId:id,valid:true};
  return fallback;
}
export function visibleActorId(id,actors,expanded=false){
  let current=id;const visited=new Set();
  while(!expanded&&actors[current]?.parentId&&!visited.has(current)){visited.add(current);current=actors[current].parentId;}
  return current;
}
export function scenarioPositions(model,steps,actors,expanded=false){
  const ids=[...new Set(steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(op=>op.actorId)]).map(id=>visibleActorId(id,actors,expanded)))];
  const authored=model.positions||model.actorPositions||model.layout?.positions||model.layout||{};
  const grid=[{x:145,y:120},{x:560,y:120},{x:975,y:120},{x:145,y:365},{x:560,y:365},{x:975,y:365},{x:145,y:610},{x:560,y:610},{x:975,y:610}];
  return Object.fromEntries(ids.map((id,index)=>[id,authored[id]||actors[id]?.position||grid[index]]).filter(([,point])=>point&&Number.isFinite(point.x)&&Number.isFinite(point.y)));
}
