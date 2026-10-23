// Navigation is an allowlist over the same scenario registry used by the player.
// Neither transaction values nor operator-supplied addresses belong in routes.
export const STUDIO_WORKSPACES = Object.freeze([
  {id:'web',title:'Web sign-in',summary:'Keycloak, OAuth / OIDC, SAML, passkeys and MFA',defaultId:'basic-keycloak'},
  {id:'ssh',title:'SSH access',summary:'OIDC enrollment, certificates, device login and server-side PAM',defaultId:'lab-ssh-cert-success'},
  {id:'kerberos',title:'Kerberos',summary:'AD DS, PKINIT, FAST, forests, Keycloak and MIT standards profiles',defaultId:'lab-ad-first-sign-in'},
  {id:'windows',title:'Windows access',summary:'NTLMv2, Negotiate, CredSSP, remote desktop and remote management',defaultId:'lab-win-ntlmv2-domain'},
  {id:'network',title:'Network access',summary:'RADIUS, wired EAP-TLS, admission, accounting and session control',defaultId:'lab-net-eap-tls13-wired'},
  {id:'foundations',title:'Foundations',summary:'SPAKE2, SPAKE2+ and JWT validation without implied application authorization',defaultId:'lab-pake-spake2-success',secondary:true},
  {id:'workstations',title:'Workstations',summary:'Windows, Linux and macOS local sign-in, sessions and privilege boundaries',defaultId:'lab-wlog01'},
  {id:'files',title:'Files',summary:'NFS identity, transport and file policy; shortcut to the accepted SMB lessons',defaultId:'lab-nfs-v42-kerberos-read'},
  {id:'kubernetes',title:'Kubernetes',summary:'Human and workload credentials, accepted identities and API authorization',defaultId:'lab-k8s01'},
  {id:'mcp',title:'MCP',summary:'Protected-resource discovery, independent grants and host/tool policy',defaultId:'lab-mcp01'},
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
  {workspace:'files',id:'nfs',title:'NFS file access',summary:'NFS versions, security flavors, TLS transport and server-side permission',defaultId:'lab-nfs-v42-kerberos-read',routeSegment:'nfs'},
  {workspace:'workstations',id:'windows-logon',title:'Windows sign-in',summary:'Local and domain identities, LSASS packages, session creation and network credentials',defaultId:'lab-wlog01',routeSegment:'windows-logon'},
  {workspace:'workstations',id:'windows-elevation',title:'Windows elevation',summary:'Tokens, UAC, consent or credentials and service-side access checks',defaultId:'lab-welev01',routeSegment:'windows-elevation'},
  {workspace:'workstations',id:'linux-logon',title:'Linux sign-in',summary:'Identity lookup, configured PAM processing, admission and sessions',defaultId:'lab-llog01',routeSegment:'linux-logon'},
  {workspace:'workstations',id:'linux-elevation',title:'Linux elevation',summary:'sudo, su, polkit and distinct mandatory kernel policy',defaultId:'lab-lelev01',routeSegment:'linux-elevation'},
  {workspace:'workstations',id:'macos-logon',title:'macOS sign-in',summary:'Local login, FileVault, directory/Kerberos and bounded Platform SSO profiles',defaultId:'lab-mlog01',routeSegment:'macos-logon'},
  {workspace:'workstations',id:'macos-elevation',title:'macOS elevation',summary:'Scoped authorization, sudo/PAM and bounded network authorization',defaultId:'lab-melev01',routeSegment:'macos-elevation'},
  {workspace:'foundations',id:'jwt',title:'JWT validation',summary:'Readable untrusted structure, verifier trust, claims and separate authorization',defaultId:'lab-jwt01',routeSegment:'jwt'},
  {workspace:'kubernetes',id:'human-access',title:'Human access',summary:'External credentials and client certificates become API identities only after checks',defaultId:'lab-k8s01',routeSegment:'human-access'},
  {workspace:'kubernetes',id:'token-validation',title:'Token validation',summary:'Issuer, audience, signature evidence and configured claim mapping',defaultId:'lab-k8s03',routeSegment:'token-validation'},
  {workspace:'kubernetes',id:'authorization-rbac',title:'API authorization / RBAC',summary:'Request attributes, role rules, privilege safeguards and admission',defaultId:'lab-k8s04',routeSegment:'authorization-rbac'},
  {workspace:'kubernetes',id:'workload-identity',title:'Workload identity',summary:'Bound service-account tokens, rotation and independent resource grants',defaultId:'lab-k8s09',routeSegment:'workload-identity'},
  {workspace:'kubernetes',id:'delegation-extensions',title:'Delegation and extensions',summary:'Impersonation and extension-service trust boundaries',defaultId:'lab-k8s14',routeSegment:'delegation-extensions'},
  {workspace:'mcp',id:'authorization',title:'MCP authorization',summary:'Dated HTTP authorization profiles, proxy boundaries and distinct stdio/host policy',defaultId:'lab-mcp01',routeSegment:'authorization'},
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

/** Navigation destinations are shortcuts to existing choices, never new models. */
export function studioWorkspaceOptions(models){
  return STUDIO_WORKSPACES.flatMap(workspace=>{
    const scenarioId=studioDefaultScenario(workspace,models);if(!scenarioId)return [];
    const options=[{id:'workspace-'+workspace.id,workspace:workspace.id,scenarioId,title:workspace.title,category:workspace.title,summary:workspace.summary,searchText:workspace.id}];
    for(const family of STUDIO_FAMILIES.filter(item=>item.workspace===workspace.id)){
      const target=studioDefaultScenario(workspace,models,family);if(!target)continue;
      options.push({id:'family-'+workspace.id+'-'+family.id,workspace:workspace.id,family:family.id,scenarioId:target,title:family.title,selectedLabel:workspace.title+' / '+family.title,category:workspace.title,summary:family.summary,searchText:workspace.id+' '+family.id});
    }
    if(workspace.id==='files'&&models['lab-smb-nonjoined-kerberos'])options.push({id:'files-smb-shortcut',workspace:'windows',family:'windows-files',scenarioId:'lab-smb-nonjoined-kerberos',title:'SMB file access (Windows access)',category:workspace.title,summary:'Open the existing SMB3.1.1 lesson with explicit domain credentials; no duplicated model.',searchText:'smb cifs file share nonjoined workgroup kerberos'});
    return options;
  });
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
