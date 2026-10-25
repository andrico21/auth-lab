import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {buildDNSSECScenarioFixture} from '../src/dnssec-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {DNSSEC_BASE_CLOCK as T,dnssecProfile} from '../src/dnssec-fixtures.js';
import {dnssecPublicationBundle as bundle,dnssecPublicationValidate as validate,dnssecPublicationWindow as window,dnssecPublicationPolicyDetails as details} from '../src/dnssec-publication.js';

const oldKeys=['child-ksk-g1','child-zsk-g1'];
const bothKeys=[...oldKeys,'child-ed25519-g1'];
const both=()=>bundle(['child-dual-algorithm-dnskey-alg13','child-dual-algorithm-dnskey-alg15'],bothKeys);
const dualAnswer=()=>bundle(['www-a-complete-path-g1','www-a-complete-path-ed25519']);
const overlapDs=()=>bundle(['parent-ds-dual-algorithm-long-signature']);
const newDs=()=>bundle(['parent-ds-for-child-ed25519-g1-signature']);
const newChild=()=>bundle(['child-ed25519-g1-dnskey-signature'],['child-ed25519-g1']);
const modern=()=>dnssecProfile('dual-modern');
const modelFor=(lesson,variant)=>buildDNSSECScenarioFixture('lab-dnssec'+lesson,{variant});
const final=model=>reconstructProtocolState(model,model.steps().length-1);
function checkpoint(model,boundary){
  const index=model.steps().findIndex(step=>step.dnssecBoundary===boundary);
  assert.notEqual(index,-1,'The lesson exposes '+boundary+' as an explicit clock/publication event');
  return reconstructProtocolState(model,index);
}

// RFC 6781 section 4.1.4/Figure 8: withdrawal, convergence and old DS
// cache lifetime precede DNSKEY removal; old DNSKEY caches precede RRSIG removal.
test('DNS14 retires algorithms from withdrawal and convergence, not overlap addition',()=>{
  const model=modelFor('14','dual-algorithm-rollover'),state=final(model);
  assert.deepEqual(state.dnssec.timers.algorithmRetirement,{
    signaturesPublishedAt:T,childReadyAt:T+7800,parentDsAt:T+8100,
    parentOverlapConvergedAt:T+8700,oldDsRemovedAt:T+95100,parentConvergedAt:T+95700,
    oldDsTtl:86400,lastOldDsReceivedAt:T+95699,lastOldDsExpiresAt:T+182099,
    oldDsDependencyEnds:T+182100,childKeysRemovedAt:T+182100,childKeysConvergedAt:T+182400,
    oldDnskeyTtl:3600,oldDnskeyDependencyEnds:T+186000,
    oldSignaturesRemovedAt:T+186000,oldSignaturesConvergedAt:T+186300,
    maximumOldDataTtl:3600,ordinaryDataDependencyEnds:T+189900
  });
  const late=checkpoint(model,'late-old-containing-ds-cache');
  assert.equal(late.dnssec.cacheEntries.ds.receivedAt,T+95699);
  assert.equal(late.dnssec.cacheEntries.ds.expiresAt,T+182099);
  assert.equal(checkpoint(model,'parent-alg13-ds-converged').protocolClock,T+95700);
  const keysRemoved=checkpoint(model,'retire-alg13-after-ds-and-child-cache-dependencies');
  assert.equal(keysRemoved.protocolClock,T+182100);
  assert.deepEqual(keysRemoved.dnssec.publication.dnskeys,['child-ed25519-g1']);
  assert.deepEqual(keysRemoved.dnssec.publication.rrsetSignatureAlgorithms,[13,15]);
  const signaturesRemoved=checkpoint(model,'retire-alg13-ordinary-signatures');
  assert.equal(signaturesRemoved.protocolClock,T+186000);
  assert.deepEqual(signaturesRemoved.dnssec.publication.rrsetSignatureAlgorithms,[15]);
  assert.equal(state.protocolClock,T+189900);
  assert.equal(state.dnssec.securityStatus,'secure');
  assert.equal(state.dnssec.applicationResult.status,'answer');
});

test('DNS14 late algorithm13-only, fresh13-only and dual-capable cohorts retain their distinct supported paths',()=>{
  const model=modelFor('14','dual-algorithm-rollover');
  const convergence=checkpoint(model,'parent-alg13-ds-converged');
  assert.deepEqual(convergence.dnssec.publication.dnskeys,bothKeys);
  assert.deepEqual(convergence.dnssec.publication.rrsetSignatureAlgorithms,[13,15]);
  const receipt=T+95699,now=T+95701,policy13={...modern(),validationAlgorithms:[13]};
  const late=window(overlapDs(),{now,receivedAt:receipt,keys:bundle(['example-dnskey-path-long'],['example-ksk-g1','example-zsk-g1']).keys,policy:policy13});
  assert.equal(late.window.expiresAt,T+182099);
  assert.equal(late.window.remainingSeconds,86398);
  const cached=validate({child:both(),delegation:overlapDs(),answer:dualAnswer(),now,policy:policy13});
  assert.equal(cached.securityStatus,'secure');
  assert.ok(cached.selectedEvidence.some(item=>item.stage==='answer-signature'&&item.keyId==='child-zsk-g1'));
  const parentKeys=bundle(['example-dnskey-path-long'],['example-ksk-g1','example-zsk-g1']).keys;
  for(const [cohort,policy] of [['fresh13-only',policy13],['fresh-dual-capable',modern()]]){
    const receivedAt=T+95701,fresh=window(newDs(),{now,receivedAt,keys:parentKeys,policy});
    assert.equal(fresh.window.valid,true,cohort+' authenticates the parent DS RRset independently of child algorithm acceptance');
    assert.equal(fresh.window.expiresAt,T+182101,cohort+' DS receipt95701 + TTL86400');
    assert.equal(fresh.window.remainingSeconds,86400);
  }
  const dualLate=window(overlapDs(),{now,receivedAt:receipt,keys:parentKeys,policy:modern()});
  assert.equal(dualLate.window.expiresAt,T+182099,'Dual-capable late overlap receipt95699 retains its own deadline');
  assert.equal(validate({child:both(),delegation:overlapDs(),answer:dualAnswer(),now,policy:modern()}).securityStatus,'secure');
  assert.equal(validate({child:both(),delegation:newDs(),answer:dualAnswer(),now,policy:policy13}).securityStatus,'insecure');
  assert.equal(validate({child:both(),delegation:newDs(),answer:dualAnswer(),now,policy:modern()}).securityStatus,'secure');
  assert.equal(window(overlapDs(),{now:T+182100,receivedAt:receipt,keys:bundle(['example-dnskey-path-long'],['example-ksk-g1','example-zsk-g1']).keys,policy:policy13}).window.valid,false);
  assert.equal(validate({child:newChild(),delegation:newDs(),answer:bundle(['www-a-long-ed25519']),now:T+189900,policy:policy13}).securityStatus,'insecure');
  assert.equal(validate({child:newChild(),delegation:newDs(),answer:bundle(['www-a-long-ed25519']),now:T+189900,policy:modern()}).securityStatus,'secure');
});

test('DNS14 declared capabilities, arithmetic coverage, registry obligations and operator acceptance are independent',()=>{
  const policy=dnssecProfile('modern');
  assert.deepEqual(policy.implementationCapabilities.validationAlgorithms,[5,7,13,15]);
  assert.deepEqual(policy.implementationCapabilities.dsDigestTypes,[1,2,4]);
  assert.deepEqual(policy.fixtureCoverage.validationAlgorithms,[13,15]);
  assert.deepEqual(policy.signingAlgorithms,[13]);
  assert.deepEqual(policy.validationAlgorithms,[13,15]);
  const child=bundle(['child-dnskey-g1-path-long'],oldKeys);
  const sha=details({child,delegation:bundle(['parent-ds-archival-alg5-signature']),policy});
  assert.deepEqual(sha.implementationCapable,[5,7,13,15]);
  assert.deepEqual(sha.fixtureValidationAlgorithms,[13,15]);
  assert.equal(sha.unsupportedReason,'operator-policy');
  const narrowed=details({child,delegation:overlapDs(),policy:{...policy,validationAlgorithms:[13]}});
  assert.deepEqual(narrowed.implementationCapable,[5,7,13,15],'Changing operator acceptance cannot rewrite declared capability');
  assert.equal(narrowed.unsupportedReason,'operator-policy');
  const unsupported=details({child,delegation:bundle(['parent-ds-unsupported-alg17-signature']),policy});
  assert.equal(unsupported.unsupportedReason,'implementation-capability');
  const changedRegistry={...policy,registry:{...policy.registry,algorithms:policy.registry.algorithms.map(row=>({...row,implementForValidation:'MUST'}))}};
  assert.equal(details({child,delegation:bundle(['parent-ds-unsupported-alg17-signature']),policy:changedRegistry}).unsupportedReason,'implementation-capability','Registry requirements do not establish a declared installed capability');
  assert.equal(details({child,delegation:bundle(['parent-ds-unsupported-digest250-signature']),policy}).unsupportedReason,'digest-capability');
});

test('DNS14 all eight policy-observation prefixes match declared publisher generation without changing validation or digest policy',()=>{
  const worksheet=JSON.parse(readFileSync(new URL('../docs/dnssec-expansion/contract-errata/effective-review-corrections/worksheet-publication.json',import.meta.url),'utf8'));
  const declarations=worksheet.lessons.find(lesson=>lesson.planId==='DNS14').cases;
  const cases=[
    ['modern-baseline','inspect-four-policy-columns','modern',{operatorAccepted:true,signingAlgorithm:13,dsDigest:2,unsupportedReason:null}],
    ['dual-algorithm-rollover','select-usable-alg15-path','dual-modern',{operatorAccepted:[13,15],usedPathAlgorithm:15}],
    ['algorithm-unsupported','classify-authenticated-unsupported-algorithm','modern',{operatorAccepted:[13,15],unsupportedReason:'implementation-capability',usableDsPaths:0}],
    ['unsupported-digest-only','classify-authenticated-unsupported-digest','modern',{operatorAccepted:[13,15],unsupportedReason:'digest-capability',usableDsPaths:0}],
    ['modern-and-obsolete-paths','retain-valid-current-path','dual-modern',{
      operatorAccepted:[13,15],usedPathAlgorithm:13,usedDsDigest:2,unsupportedReason:'multiple-path-constraints',
      rejectedPaths:[
        {algorithm:5,digestType:2,reasons:['operator-policy'],primaryReason:'operator-policy'},
        {algorithm:12,digestType:3,reasons:['implementation-capability','operator-policy','digest-capability','digest-policy'],primaryReason:'implementation-capability'}
      ]
    }],
    ['sha1-signing-disabled','operator-rejects-archived-sha1-path','dual-modern',{operatorAccepted:[13,15],generationAllowed:false,operatorTreatAs:'unsupported',unsupportedReason:'operator-policy'}],
    ['sha1-digest-compatibility','inspect-distinct-digest-policy','legacy-ds-sha1',{operatorAccepted:true,dsDigest:1,compatibilityValidation:true,newDsCreated:false}],
    ['nsec3-sha1-not-signature-policy','inspect-three-independent-algorithms','modern',{operatorAccepted:true,signingAlgorithm:13,dsDigest:2,nsec3HashAlgorithm:1}]
  ];
  assert.equal(declarations.length,8);
  assert.deepEqual(new Set(cases.map(([variant])=>variant)),new Set(declarations.map(item=>item.id)));
  for(const [variant,boundary,profileId,controls] of cases){
    const declaration=declarations.find(item=>item.id===variant).setup.capabilities;
    const model=modelFor('14',variant),profile=model.profile.algorithms,observed=checkpoint(model,boundary).dnssec.algorithmPolicy;
    assert.deepEqual(declaration.signingAlgorithms,[13,15],variant+' retains the independently frozen signing declaration');
    assert.deepEqual(profile,{...dnssecProfile(profileId),signingAlgorithms:declaration.signingAlgorithms},variant+' overrides publisher generation only, not the selected profile');
    assert.deepEqual(observed.signingAlgorithms,declaration.signingAlgorithms,variant+' actual prefix retains the declared publisher policy');
    if(variant!=='nsec3-sha1-not-signature-policy')assert.deepEqual(observed.publisherSigningAlgorithms,declaration.signingAlgorithms,variant+' observes the actual publisher policy');
    assert.deepEqual(observed.implementationCapabilities.validationAlgorithms,declaration.validationAlgorithms,variant+' implementation capability is not operator acceptance');
    assert.deepEqual(observed.implementationCapabilities.dsDigestTypes,declaration.dsDigests,variant+' digest capability is not digest policy');
    assert.deepEqual(observed.fixtureCoverage.validationAlgorithms,declaration.fixtureValidationAlgorithms);
    assert.deepEqual(observed.validationAlgorithms,[13,15],variant+' keeps SHA1 signature operator rejection');
    assert.deepEqual(observed.acceptedDigestTypes??profile.dsDigestTypes,variant==='sha1-digest-compatibility'?[1,2,4]:[2,4],variant+' keeps historical digest compatibility separately scoped');
    for(const [key,value] of Object.entries(controls))assert.deepEqual(observed[key],value,variant+' retains '+key);
  }
  assert.deepEqual(dnssecProfile('modern').signingAlgorithms,[13],'DNS14 cannot mutate the shared modern publisher default');
  assert.deepEqual(dnssecProfile('legacy-ds-sha1').signingAlgorithms,[13],'The shared historical digest profile remains unchanged');
  assert.deepEqual(modelFor('12','zsk-prepublish').profile.algorithms,dnssecProfile('modern'),'Other lessons keep their original publisher policy');
});

test('DNS14 SHA1 rejection explains operator policy while modern and separately scoped SHA1 roles still work',()=>{
  for(const variant of ['sha1-signing-disabled','modern-and-obsolete-paths']){
    const state=final(modelFor('14',variant)).dnssec;
    assert.deepEqual(state.algorithmPolicy.implementationCapable,[5,7,13,15]);
    assert.deepEqual(state.algorithmPolicy.fixtureValidationAlgorithms,[13,15]);
    if(variant==='sha1-signing-disabled'){
      assert.equal(state.algorithmPolicy.unsupportedReason,'operator-policy');
      assert.deepEqual(state.algorithmPolicy.unsupportedReasons,['operator-policy']);
      assert.equal(state.algorithmPolicy.implementationValidationSupportRequired,true);
      assert.equal(state.algorithmPolicy.generationAllowed,false);
      assert.equal(state.algorithmPolicy.operatorTreatAs,'unsupported');
      assert.equal(state.securityStatus,'insecure');
    }else{
      assert.equal(state.algorithmPolicy.unsupportedReason,'multiple-path-constraints');
      assert.deepEqual(new Set(state.algorithmPolicy.unsupportedReasons),new Set(['operator-policy','implementation-capability','digest-capability','digest-policy']));
      assert.deepEqual(state.algorithmPolicy.rejectedPaths.find(path=>path.algorithm===5),{algorithm:5,digestType:2,reasons:['operator-policy'],primaryReason:'operator-policy'});
      assert.deepEqual(state.algorithmPolicy.rejectedPaths.find(path=>path.algorithm===12),{algorithm:12,digestType:3,reasons:['implementation-capability','operator-policy','digest-capability','digest-policy'],primaryReason:'implementation-capability'});
      assert.equal(state.algorithmPolicy.rejectedPaths.some(path=>path.algorithm===13),false,'The usable modern path is not rejected with unrelated obsolete extras');
      assert.equal(state.securityStatus,'secure');
    }
  }
  assert.equal(final(modelFor('14','algorithm-unsupported')).dnssec.algorithmPolicy.unsupportedReason,'implementation-capability');
  for(const variant of ['modern-baseline','sha1-digest-compatibility','nsec3-sha1-not-signature-policy'])assert.equal(final(modelFor('14',variant)).dnssec.securityStatus,'secure');
});

test('DNS12 declares deliberate fresh-keyset revalidation without revoking an ordinary secure cache',()=>{
  const model=modelFor('12','old-key-removed-too-early'),state=final(model).dnssec;
  assert.equal(state.publication.cacheRevalidation.mode,'fresh-keyset-recheck');
  assert.equal(state.publication.cacheRevalidation.ordinarySecureReuseAllowed,true);
  assert.match(state.publication.cacheRevalidation.explanation,/already.secure/i);
  assert.match(state.publication.cacheRevalidation.explanation,/does not revoke/i);
  assert.equal(state.cacheEntries.answer.securityStatus,'secure');
  assert.equal(state.cacheEntries.answer.receivedAt,T+300);
  assert.equal(state.cacheEntries.answer.expiresAt,T+7500);
  assert.equal(state.cacheEntries.answer.expiresAt-(T+4100),3400);
  assert.equal(state.securityStatus,'bogus');
  assert.equal(state.response.rcode,'SERVFAIL');
});
