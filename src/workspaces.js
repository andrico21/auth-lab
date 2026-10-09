// Navigation is an allowlist over the same scenario registry used by the player.
// Neither transaction values nor operator-supplied addresses belong in routes.
export const STUDIO_WORKSPACES = Object.freeze([
  {id:'web',title:'Web sign-in',summary:'Keycloak, OAuth / OIDC, SAML, passkeys and MFA',defaultId:'basic-keycloak'},
  {id:'ssh',title:'SSH access',summary:'OIDC enrollment, certificates, device login and server-side PAM',defaultId:'lab-ssh-cert-success'},
  {id:'kerberos',title:'Kerberos',summary:'AD DS tickets, PKINIT, FAST, forests and the Keycloak bridge',defaultId:'lab-ad-first-sign-in'},
]);
export function workspaceOf(model){return ['web','ssh','kerberos'].includes(model?.workspace)?model.workspace:'web';}
export function studioRoute(id,models){
  const model=models[id];return '#/'+workspaceOf(model)+(model?.family==='keycloak-bridge'?'/keycloak':'')+'/'+id;
}
export function parseStudioRoute(hash,models,presetIds=[]){
  const fallback={workspace:'web',scenarioId:'basic-keycloak',valid:false};
  if(!hash||hash==='#')return {...fallback,valid:true};
  const value=String(hash).replace(/^#\//,'');
  const workspace=STUDIO_WORKSPACES.find(item=>item.id===value);
  if(workspace){const candidates=Object.values(models).filter(model=>workspaceOf(model)===workspace.id);return {workspace:workspace.id,scenarioId:models[workspace.defaultId]?workspace.defaultId:workspace.id==='web'?'basic-keycloak':candidates[0]?.id||'basic-keycloak',valid:true};}
  for(const id of ['core',...presetIds,...Object.keys(models)])if(hash===studioRoute(id,models))return {workspace:workspaceOf(models[id]),scenarioId:id,valid:true};
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
