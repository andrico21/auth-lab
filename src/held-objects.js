import {buildADHeldObjects} from './held-object-ad.js';
import {buildKerberosHeldObjects} from './held-object-kerberos.js';
import {buildSSHHeldObjects} from './held-object-ssh.js';
import {buildProtectionHeldObjects} from './held-object-protection.js';
import {buildWebHeldObjects} from './held-object-web.js';
import {buildCoreHeldObjects} from './held-object-core.js';
import {buildWindowsHeldObjects} from './held-object-windows.js';
import {buildSMBHeldObjects} from './held-object-smb.js';
import {buildNetworkHeldObjects} from './held-object-network.js';
import {buildSpakeHeldObjects} from './held-object-spake.js';
import {buildPakeHeldObjects} from './held-object-pake.js';
import {buildNFSHeldObjects} from './held-object-nfs.js';
import {buildWindowsWorkstationHeldObjects} from './held-object-windows-workstation.js';
import {buildUnixWorkstationHeldObjects} from './held-object-unix-workstation.js';
import {buildJWTHeldObjects} from './held-object-jwt.js';
import {buildKubernetesHeldObjects} from './held-object-kubernetes.js';
import {buildMCPHeldObjects} from './held-object-mcp.js';
import {buildDNSSECHeldObjects} from './held-object-dnssec.js';
import {compileHeldObjects,assertHeldObjectCoverage} from './held-object-state.js';
import {ADLAB_SCENARIOS} from './kerberos-ad-lab.js';
import {CRYPTOLAB_SCENARIOS} from './kerberos-crypto-lab.js';
import {FORESTLAB_SCENARIOS} from './kerberos-forest-lab.js';
import {SSHLAB_SCENARIOS} from './ssh-access-lab.js';
import {PROTLAB_SCENARIOS} from './protection-lab.js';
import {WEBLAB_SCENARIOS} from './web-api-lab.js';
import {LIFELAB_SCENARIOS} from './lifecycle-lab.js';
import {GRANTLAB_SCENARIOS} from './extended-grants-lab.js';
import {SAMLLAB_SCENARIOS} from './saml-advanced-lab.js';
import {BRANCHLAB_SCENARIOS} from './branching-lab.js';
import {WINDOWSLAB_SCENARIOS} from './windows-auth-lab.js';
import {SMBLAB_SCENARIOS} from './smb-access-lab.js';
import {SMBMULTI_SCENARIOS} from './smb-multichannel-lab.js';
import {NETWORKLAB_SCENARIOS} from './network-access-lab.js';
import {SPAKELAB_SCENARIOS} from './kerberos-spake-lab.js';
import {PAKELAB_SCENARIOS} from './pake-lab.js';
import {NFSLAB_SCENARIOS} from './nfs-access-lab.js';
import {WINDOWSLOGONLAB_SCENARIOS} from './windows-logon-lab.js';
import {WINDOWSELEVLAB_SCENARIOS} from './windows-elevation-lab.js';
import {LINUXLOGONLAB_SCENARIOS} from './linux-logon-lab.js';
import {LINUXELEVLAB_SCENARIOS} from './linux-elevation-lab.js';
import {MACOSLOGONLAB_SCENARIOS} from './macos-logon-lab.js';
import {MACOSELEVLAB_SCENARIOS} from './macos-elevation-lab.js';
import {JWTLAB_SCENARIOS} from './jwt-validation-lab.js';
import {KUBERNETESAUTHLAB_SCENARIOS} from './kubernetes-auth-lab.js';
import {KUBERNETESRBACLAB_SCENARIOS} from './kubernetes-rbac-lab.js';
import {MCPLAB_SCENARIOS} from './mcp-auth-lab.js';
import {DNSSECLAB_SCENARIOS} from './dnssec-lab.js';

const heldObjectSources=new Map([
  [ADLAB_SCENARIOS,'src/kerberos-ad-lab.js'],[CRYPTOLAB_SCENARIOS,'src/kerberos-crypto-lab.js'],
  [FORESTLAB_SCENARIOS,'src/kerberos-forest-lab.js'],[SSHLAB_SCENARIOS,'src/ssh-access-lab.js'],
  [PROTLAB_SCENARIOS,'src/protection-lab.js'],[WEBLAB_SCENARIOS,'src/web-api-lab.js'],
  [LIFELAB_SCENARIOS,'src/lifecycle-lab.js'],[GRANTLAB_SCENARIOS,'src/extended-grants-lab.js'],
  [SAMLLAB_SCENARIOS,'src/saml-advanced-lab.js'],[BRANCHLAB_SCENARIOS,'src/branching-lab.js'],
  [WINDOWSLAB_SCENARIOS,'src/windows-auth-lab.js'],[NETWORKLAB_SCENARIOS,'src/network-access-lab.js'],
  [SMBLAB_SCENARIOS,'src/smb-access-lab.js'],[SMBMULTI_SCENARIOS,'src/smb-multichannel-lab.js'],
  [SPAKELAB_SCENARIOS,'src/kerberos-spake-lab.js'],[PAKELAB_SCENARIOS,'src/pake-lab.js'],
  [NFSLAB_SCENARIOS,'src/nfs-access-lab.js'],[WINDOWSLOGONLAB_SCENARIOS,'src/windows-logon-lab.js'],
  [WINDOWSELEVLAB_SCENARIOS,'src/windows-elevation-lab.js'],[LINUXLOGONLAB_SCENARIOS,'src/linux-logon-lab.js'],
  [LINUXELEVLAB_SCENARIOS,'src/linux-elevation-lab.js'],[MACOSLOGONLAB_SCENARIOS,'src/macos-logon-lab.js'],
  [MACOSELEVLAB_SCENARIOS,'src/macos-elevation-lab.js'],[JWTLAB_SCENARIOS,'src/jwt-validation-lab.js'],
  [KUBERNETESAUTHLAB_SCENARIOS,'src/kubernetes-auth-lab.js'],[KUBERNETESRBACLAB_SCENARIOS,'src/kubernetes-rbac-lab.js'],
  [MCPLAB_SCENARIOS,'src/mcp-auth-lab.js'],
  [DNSSECLAB_SCENARIOS,'src/dnssec-lab.js'],
].flatMap(([models,source])=>models.map(model=>[model.id,source])));
const heldObjectBuilders=new Map([
  ['src/kerberos-ad-lab.js',buildADHeldObjects],['src/kerberos-crypto-lab.js',buildKerberosHeldObjects],
  ['src/kerberos-forest-lab.js',buildKerberosHeldObjects],['src/ssh-access-lab.js',buildSSHHeldObjects],
  ['src/protection-lab.js',buildProtectionHeldObjects],['src/web-api-lab.js',buildProtectionHeldObjects],
  ['src/lifecycle-lab.js',buildWebHeldObjects],['src/extended-grants-lab.js',buildWebHeldObjects],
  ['src/saml-advanced-lab.js',buildWebHeldObjects],['src/branching-lab.js',buildWebHeldObjects],
  ['src/windows-auth-lab.js',buildWindowsHeldObjects],['src/network-access-lab.js',buildNetworkHeldObjects],
  ['src/smb-access-lab.js',buildSMBHeldObjects],['src/smb-multichannel-lab.js',buildSMBHeldObjects],
  ['src/kerberos-spake-lab.js',buildSpakeHeldObjects],['src/pake-lab.js',buildPakeHeldObjects],
  ['src/nfs-access-lab.js',buildNFSHeldObjects],['src/windows-logon-lab.js',buildWindowsWorkstationHeldObjects],
  ['src/windows-elevation-lab.js',buildWindowsWorkstationHeldObjects],['src/linux-logon-lab.js',buildUnixWorkstationHeldObjects],
  ['src/linux-elevation-lab.js',buildUnixWorkstationHeldObjects],['src/macos-logon-lab.js',buildUnixWorkstationHeldObjects],
  ['src/macos-elevation-lab.js',buildUnixWorkstationHeldObjects],['src/jwt-validation-lab.js',buildJWTHeldObjects],
  ['src/kubernetes-auth-lab.js',buildKubernetesHeldObjects],['src/kubernetes-rbac-lab.js',buildKubernetesHeldObjects],
  ['src/mcp-auth-lab.js',buildMCPHeldObjects],
  ['src/dnssec-lab.js',buildDNSSECHeldObjects],
]);

/** Build once per immutable scenario/configuration/context revision, not frame. */
export function buildHeldObjects(args) {
  if(!args||!Array.isArray(args.steps)||!args.contextId)throw new TypeError('Held objects require canonical steps and an immutable context identity.');
  const build=args.model?heldObjectBuilders.get(heldObjectSources.get(args.model.id)):buildCoreHeldObjects;
  const plan=build?.(args);
  if(!plan)throw new RangeError('No held-object authoring for scenario: '+(args.model?.id||args.choiceId||'core'));
  if(!plan.actors)plan.actors=Object.fromEntries(Object.entries(args.actors||{}).map(([id,actor])=>[id,{id,name:actor.name||id,...(actor.parentId?{parentId:actor.parentId}:{})}]));
  if(!plan.configuration)plan.configuration={...args.config};
  if(!plan.choiceId)plan.choiceId=args.choiceId||plan.scenarioId;
  return compileHeldObjects(plan,{model:args.model,steps:args.steps});
}

/** Review manifest derived from authored bindings, never from catalog counts. */
export function describeHeldObjectPlan(compiled,{choiceId,model,configuration,interactionCaseIds=[]}={}) {
  const plan=compiled.plan||compiled;
  const events=Object.entries(plan.events||{});
  return {
    choiceId:choiceId||plan.choiceId||plan.scenarioId,presetAlias:choiceId&&choiceId!==plan.scenarioId?choiceId:null,
    modelId:plan.scenarioId,contextId:plan.contextId,workspace:model?.workspace||'web',family:model?.family||model?.category||'core',
    sourceModule:heldObjectSources.get(model?.id)||'src/app.js::scenarioSnapshot',
    normalizedConfiguration:plan.normalizedConfiguration||configuration||plan.configuration||{},support:'supported',
    logicalActors:Object.keys(plan.actors||{}),parentProjection:Object.values(plan.actors||{}).filter(actor=>actor.parentId).map(actor=>({actorId:actor.id,parentId:actor.parentId})),
    initialHoldings:(plan.initial||[]).filter(effect=>effect.op==='acquire').map(effect=>({...effect})),
    artifacts:(plan.artifacts||[]).map(artifact=>({artifactId:artifact.artifactId,type:artifact.type,creator:artifact.creator,representations:artifact.representations.map(representation=>({representationId:representation.representationId,readableBy:representation.readableBy,fields:(representation.fields||[]).map(field=>({attributeId:field.attributeId,readableBy:field.readableBy||representation.readableBy}))})),derivedFrom:artifact.derivedFrom||[],replaces:artifact.replaces||[],related:artifact.related||[]})),
    eventMilestones:events.map(([sourceStepId,event])=>({sourceStepId,milestones:(event.milestones||[]).map(milestone=>({id:milestone.id,at:milestone.at,effects:milestone.effects.map(effect=>({...effect}))})),messages:event.messages||[]})),
    stateBindings:plan.bindings||[],coverageByActorAndCursor:plan.coverage||[],declaredLimitations:plan.limitations||[],
    interactionCaseIds:[...new Set([...(plan.interactions||[]),...interactionCaseIds])],
    reviewDisposition:'Implementation prepared for independent Astra review; not published.',
  };
}

export function getHeldObjectManifest(fixtures) {
  return fixtures.map(fixture=>{
    const compiled=fixture.compiled||buildHeldObjects(fixture);
    assertHeldObjectCoverage(compiled);
    return describeHeldObjectPlan(compiled,fixture);
  });
}
