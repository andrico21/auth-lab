import {buildADHeldObjects} from './held-object-ad.js';
import {buildKerberosHeldObjects} from './held-object-kerberos.js';
import {buildSSHHeldObjects} from './held-object-ssh.js';
import {buildProtectionHeldObjects} from './held-object-protection.js';
import {buildWebHeldObjects} from './held-object-web.js';
import {buildCoreHeldObjects} from './held-object-core.js';
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

const heldObjectSources=new Map([
  [ADLAB_SCENARIOS,'src/kerberos-ad-lab.js'],[CRYPTOLAB_SCENARIOS,'src/kerberos-crypto-lab.js'],
  [FORESTLAB_SCENARIOS,'src/kerberos-forest-lab.js'],[SSHLAB_SCENARIOS,'src/ssh-access-lab.js'],
  [PROTLAB_SCENARIOS,'src/protection-lab.js'],[WEBLAB_SCENARIOS,'src/web-api-lab.js'],
  [LIFELAB_SCENARIOS,'src/lifecycle-lab.js'],[GRANTLAB_SCENARIOS,'src/extended-grants-lab.js'],
  [SAMLLAB_SCENARIOS,'src/saml-advanced-lab.js'],[BRANCHLAB_SCENARIOS,'src/branching-lab.js'],
].flatMap(([models,source])=>models.map(model=>[model.id,source])));
const heldObjectBuilders=new Map([
  ['src/kerberos-ad-lab.js',buildADHeldObjects],['src/kerberos-crypto-lab.js',buildKerberosHeldObjects],
  ['src/kerberos-forest-lab.js',buildKerberosHeldObjects],['src/ssh-access-lab.js',buildSSHHeldObjects],
  ['src/protection-lab.js',buildProtectionHeldObjects],['src/web-api-lab.js',buildProtectionHeldObjects],
  ['src/lifecycle-lab.js',buildWebHeldObjects],['src/extended-grants-lab.js',buildWebHeldObjects],
  ['src/saml-advanced-lab.js',buildWebHeldObjects],['src/branching-lab.js',buildWebHeldObjects],
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
