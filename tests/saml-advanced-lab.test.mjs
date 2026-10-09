import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage } from '../src/attribute-usage.js';
import { SAMLLAB_ATTRIBUTES, SAMLLAB_SOURCES, SAMLLAB_SCENARIOS } from '../src/saml-advanced-lab.js';

Object.assign(ATTRIBUTES, SAMLLAB_ATTRIBUTES);
const slTestModel = id => SAMLLAB_SCENARIOS.find(slModel => slModel.id === id);
const slTestSteps = id => slTestModel(id).steps();
const slTestStage = (id,stage) => slTestSteps(id).find(slStep => slStep.id === stage);
const slTestWire = slStep => slStep.attributeOperations.filter(slOp => ['send','receive'].includes(slOp.kind));
const slTestPrivateIds = new Set(['slSpPrivateKey','slIdpPrivateKey','slOtherPrivateKey','slArtifactStore','slReplayCache','slAppSession','slOtherSession','slIdpSession','slMetadataTrust','slRejectState']);
const slTestHasAction = (slStep,id,kind,actor) => slStep.attributeOperations.some(slOp=>slOp.attributeId===id&&slOp.kind===kind&&(!actor||slOp.actorId===actor));
const slTestValue = (slStep,id) => slStep.payload.find(slPayload=>slPayload.attributeId===id)?.value ?? slStep.attributeValues?.[id];

test('SAML lab scenarios provide immutable authored models with genuine indexed operations and explicit product scope',()=>{
  assert.equal(SAMLLAB_SCENARIOS.length,6);assert.equal(new Set(SAMLLAB_SCENARIOS.map(slModel=>slModel.id)).size,6);
  for(const slModel of SAMLLAB_SCENARIOS){
    assert.ok(slModel.universalLab);assert.equal(slModel.architecture,'web');assert.equal(slModel.protocol,'saml');assert.equal(slModel.factorSelectable,false);assert.equal(slModel.jweAdaptable,false);
    for(const slKey of ['title','summary','status','supportNote','source'])assert.ok(slModel[slKey]);
    const slSteps=slModel.steps();assert.equal(slSteps,slModel.steps({architecture:'native',upstream:'external',mode:'passkey'}));assert.ok(Object.isFrozen(slSteps));
    assert.equal(new Set(slSteps.map(slStep=>slStep.id)).size,slSteps.length);
    for(const slStep of slSteps){
      assert.ok(Object.isFrozen(slStep));assert.ok(slStep.title&&slStep.summary&&slStep.detail&&slStep.payload.length);
      assert.ok(Array.isArray(slStep.attributeOperations));
      for(const slId of slStep.fields)assert.ok(SAMLLAB_ATTRIBUTES[slId],slId+' has canonical educational metadata');
      for(const slOp of slStep.attributeOperations){assert.ok(slStep.fields.includes(slOp.attributeId));assert.ok(slModel.actors()[slOp.actorId],slOp.actorId+' is explicitly modeled');}
    }
  }
  for(const [slId,slDefinition]of Object.entries(SAMLLAB_ATTRIBUTES)){
    for(const slKey of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(slDefinition[slKey],slId+': '+slKey);
    assert.ok(SAMLLAB_SCENARIOS.some(slModel=>getAttributeUsage(slModel.steps(),slId).length),'Actual lifetime use: '+slId);
  }
  assert.ok(SAMLLAB_SOURCES.some(slSource=>slSource.url.includes('oasis-open.org')));assert.ok(SAMLLAB_SOURCES.some(slSource=>slSource.url.includes('keycloak.org')));
});

test('artifact front channel contains the reference and embedded type/index/source/handle, never an assertion',()=>{
  const slId='lab-saml-artifact';
  for(const slStageId of ['sl-artifact-browser','sl-artifact-acs']){
    const slStep=slTestStage(slId,slStageId),slWire=slTestWire(slStep);
    for(const slField of ['slSamlart','slTypeCode','slEndpointIndex','slSourceID','slMessageHandle'])assert.equal(slWire.filter(slAction=>slAction.attributeId===slField).length,2);
    for(const slField of ['slResponse','slAssertion','slNameIDApp','slSessionIndexApp','slIdpPrivateKey','slArtifactStore'])assert.ok(!slWire.some(slAction=>slAction.attributeId===slField),slField+' absent on browser hop');
    assert.ok(slWire.every(slAction=>/SAMLart/.test(slAction.carriedAs)));
  }
  const slParse=slTestStage(slId,'sl-artifact-acs');assert.ok(slTestHasAction(slParse,'slSourceID','verify','app'));assert.ok(slTestHasAction(slParse,'slEndpointIndex','verify','app'));
});

test('artifact resolution authenticates the intended SP and consumes only once before returning the retained message',()=>{
  const slSteps=slTestSteps('lab-saml-artifact'),slResolve=slSteps.find(slStep=>slStep.id==='sl-artifact-resolve'),slConsume=slSteps.find(slStep=>slStep.id==='sl-artifact-consume'),slReply=slSteps.find(slStep=>slStep.id==='sl-artifact-response');
  assert.deepEqual([slResolve.from,slResolve.to,slResolve.channel],['app','realmA','backchannel']);assert.ok(slResolve.fields.includes('slArtifactResolve'));assert.ok(slResolve.fields.includes('slResolveID'));
  for(const slId of ['slArtifact','slIssuer','slSignature','slTrustedCert','slArtifactStore'])assert.ok(slTestHasAction(slConsume,slId,'verify','realmA'));
  assert.ok(slTestHasAction(slConsume,'slArtifactStore','store','realmA'));assert.ok(slSteps.indexOf(slConsume)<slSteps.indexOf(slReply));
  assert.match(slConsume.detail,/authenticated original recipient/);assert.match(slConsume.detail,/duplicate, expired/);assert.match(slConsume.detail,/empty ArtifactResponse/);
  assert.ok(slReply.fields.includes('slResponse')&&slReply.fields.includes('slAssertion'));
});

test('outer resolution correlation and original sign-in correlation remain independent, with all profile checks before session creation',()=>{
  const slReply=slTestStage('lab-saml-artifact','sl-artifact-response'),slValidate=slTestStage('lab-saml-artifact','sl-artifact-validate');
  assert.equal(slTestValue(slReply,'slOuterCorrelation'),'_resolve_demo_01');assert.equal(slTestValue(slReply,'slInnerCorrelation'),'_authn_demo_01');assert.notEqual(slTestValue(slReply,'slOuterCorrelation'),slTestValue(slReply,'slInnerCorrelation'));
  for(const slField of ['slOuterCorrelation','slInnerCorrelation','slStatus','slSignature','slIssuer','slAudience','slRecipient','slNotBefore','slNotOnOrAfter','slAssertionID'])assert.ok(slTestHasAction(slValidate,slField,'verify','app'),slField+' validated');
  assert.ok(slTestHasAction(slValidate,'slReplayCache','use','app'));assert.ok(slTestHasAction(slValidate,'slReplayCache','store','app'));
  const slCreate=slValidate.attributeOperations.findIndex(slAction=>slAction.attributeId==='slAppSession'&&slAction.kind==='create');assert.ok(slCreate>slValidate.attributeOperations.findIndex(slAction=>slAction.attributeId==='slNotOnOrAfter'&&slAction.kind==='verify'));
});

test('SP-initiated SLO keeps participant identifiers independent and returns its original correlated result after the other SP acknowledgment',()=>{
  const slSteps=slTestSteps('lab-saml-sp-slo'),slPreparation=slSteps[0];
  assert.ok(!slPreparation.fields.includes('slNameIDOther'),'SP 1 need not know another pairwise subject');assert.ok(!slPreparation.fields.includes('slOtherSession'));
  const slBuild=slTestStage('lab-saml-sp-slo','sl-sp-slo-origin-build'),slSecond=slTestStage('lab-saml-sp-slo','sl-sp-slo-second-build');
  assert.ok(slBuild.fields.includes('slSessionIndexApp'));assert.ok(slSecond.fields.includes('slSessionIndexOther'));
  assert.notEqual(slTestValue(slBuild,'slNameIDApp'),slTestValue(slSecond,'slNameIDOther'));assert.notEqual(slTestValue(slBuild,'slSessionIndexApp'),slTestValue(slSecond,'slSessionIndexOther'));
  assert.notEqual(slTestValue(slBuild,'slLogoutID'),slTestValue(slSecond,'slLogoutOtherID'));
  const slSecondResult=slTestStage('lab-saml-sp-slo','sl-sp-slo-second-response'),slFinal=slTestStage('lab-saml-sp-slo','sl-sp-slo-final-build');
  assert.ok(slSteps.indexOf(slSecondResult)<slSteps.indexOf(slFinal));assert.equal(slTestValue(slSecondResult,'slLogoutOtherCorrelation'),'_logout_sp2_01');assert.equal(slTestValue(slFinal,'slLogoutCorrelation'),'_logout_sp1_01');assert.match(slFinal.detail,/PartialLogout/);
  assert.equal(slTestModel('lab-saml-sp-slo').actors().realmB.role,'Second SAML session participant');
});

test('IdP initiation creates a separate request for each SP and no fabricated response to an original SP requester',()=>{
  const slSteps=slTestSteps('lab-saml-idp-slo');
  assert.ok(slSteps.some(slStep=>slStep.id==='sl-idp-slo-first-request'&&slStep.to==='app'));assert.ok(slSteps.some(slStep=>slStep.id==='sl-idp-slo-second-request'&&slStep.to==='realmB'));
  assert.ok(!slSteps.some(slStep=>slStep.from==='app'&&slStep.to==='browser'&&slStep.fields.includes('slLogoutRequest')),'SP 1 does not initiate IdP SLO');
  for(const slId of ['sl-idp-slo-first-response','sl-idp-slo-second-response'])assert.equal(slSteps.find(slStep=>slStep.id===slId).to,'realmA');
  const slLast=slSteps.at(-1);assert.deepEqual([slLast.from,slLast.to],['realmA','realmA']);assert.match(slLast.detail,/omits the original-SP request\/response leg/);
});

test('SOAP SLO reaches both participants directly without browser messages and validates actual acknowledgments',()=>{
  const slSteps=slTestSteps('lab-saml-soap-slo');assert.ok(slSteps.every(slStep=>![slStep.from,slStep.to].includes('browser')));
  for(const [slPrefix,slParticipant]of [['sl-soap-slo-first','app'],['sl-soap-slo-second','realmB']]){
    const slRequest=slSteps.find(slStep=>slStep.id===slPrefix+'-request'),slTermination=slSteps.find(slStep=>slStep.id===slPrefix+'-terminate'),slResponse=slSteps.find(slStep=>slStep.id===slPrefix+'-response');
    assert.deepEqual([slRequest.from,slRequest.to,slRequest.channel],['realmA',slParticipant,'backchannel']);assert.match(slTestValue(slRequest,'slDestination'),/\/soap$/);assert.equal(slTestValue(slRequest,'slDestination'),slTestValue(slTermination,'slDestination'));
    assert.ok(slSteps.indexOf(slTermination)<slSteps.indexOf(slResponse));assert.deepEqual([slResponse.from,slResponse.to], [slParticipant,'realmA']);assert.match(slResponse.attributeOperations.find(slAction=>slAction.kind==='send').carriedAs,/SOAP LogoutResponse/);
  }
  assert.ok(slSteps.at(-1).fields.includes('slLogoutCorrelation')&&slSteps.at(-1).fields.includes('slLogoutOtherCorrelation'));
});

test('metadata trust precedes key installation and rollover accepts public keys through existing trust only',()=>{
  const slSteps=slTestSteps('lab-saml-metadata'),slBootstrap=slSteps[0],slValidate=slTestStage('lab-saml-metadata','sl-meta-validate-sp'),slRollover=slTestStage('lab-saml-metadata','sl-meta-rollover');
  assert.ok(slTestHasAction(slBootstrap,'slMetadataTrust','store','realmA'));
  for(const slId of ['slMetadataEntityID','slMetadataSpRole','slMetadataTrust','slMetadataValidUntil','slMetadataCacheDuration'])assert.ok(slTestHasAction(slValidate,slId,'verify','realmA'));
  for(const slId of ['slMetadataSigningCert','slMetadataEncryptionCert'])assert.ok(slTestHasAction(slValidate,slId,'store','realmA'));
  const slWire=slTestWire(slTestStage('lab-saml-metadata','sl-meta-idp-response'));assert.ok(slWire.some(slAction=>slAction.attributeId==='slMetadataNextCert'));
  assert.ok(slTestHasAction(slRollover,'slMetadataTrust','verify','app'));assert.ok(slTestHasAction(slRollover,'slMetadataNextCert','verify','app'));assert.ok(slTestHasAction(slRollover,'slMetadataNextCert','store','app'));
  assert.match(slRollover.detail,/KeyInfo hint cannot bypass/);
});

test('expired, replayed and signed denied attempts create rejection state and never a new authenticated session',()=>{
  const slSteps=slTestSteps('lab-saml-validation-failures');assert.match(slSteps[0].detail,/three independent failed attempts/);
  assert.ok(slSteps.every(slStep=>!slStep.attributeOperations.some(slAction=>slAction.attributeId==='slAppSession'&&slAction.kind==='create')));
  for(const slReason of ['expired','replay','denied'])assert.ok(slSteps.some(slStep=>slStep.samlLabFailure===slReason&&slTestHasAction(slStep,'slRejectState','create','app')));
  assert.ok(slTestHasAction(slTestStage('lab-saml-validation-failures','sl-fail-expired-check'),'slNotOnOrAfter','verify','app'));
  assert.ok(slTestHasAction(slTestStage('lab-saml-validation-failures','sl-fail-replay-check'),'slReplayCache','verify','app'));
  const slDenied=slTestStage('lab-saml-validation-failures','sl-fail-denied-build');assert.equal(slTestValue(slDenied,'slStatus'),'urn:oasis:names:tc:SAML:2.0:status:Responder');assert.equal(slTestValue(slDenied,'slSubStatus'),'urn:oasis:names:tc:SAML:2.0:status:RequestDenied');assert.ok(!slDenied.fields.includes('slAssertion'));
});

test('private signing keys, session records, metadata trust, accepted IDs and artifact state never become network fields',()=>{
  for(const slModel of SAMLLAB_SCENARIOS)for(const slStep of slModel.steps())for(const slAction of slTestWire(slStep))assert.ok(!slTestPrivateIds.has(slAction.attributeId),slModel.id+' / '+slStep.id+' improperly transmits '+slAction.attributeId);
  for(const [slId,slActor]of [['slSpPrivateKey','app'],['slIdpPrivateKey','realmA'],['slOtherPrivateKey','realmB'],['slOtherSession','realmB']])for(const slModel of SAMLLAB_SCENARIOS)for(const slStep of slModel.steps())for(const slAction of slStep.attributeOperations.filter(slOp=>slOp.attributeId===slId))assert.equal(slAction.actorId,slActor,slId+' belongs only to its actor');
});
