import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { SAMLLAB_ATTRIBUTES, SAMLLAB_SCENARIOS } from '../src/saml-advanced-lab.js';

Object.assign(ATTRIBUTES,SAMLLAB_ATTRIBUTES);
const samlReviewSp = 'https://app.example.test/saml';
const samlReviewIdp = 'https://idp1.example.test/realms/realm-a';
const samlReviewOther = 'https://reports.example.test/saml';
const samlReviewAcs = 'https://app.example.test/saml/acs';
const samlReviewResolution = samlReviewIdp+'/protocol/saml';
const samlReviewSuccess = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const samlReviewResponder = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
const samlReviewDenied = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';
const samlReviewModel = id => SAMLLAB_SCENARIOS.find(model=>model.id===id);
const samlReviewTraceValue = (scenario,field,stage,kind) => {
  const model=samlReviewModel(scenario);
  const moment=buildAttributeTrace(getAttributeUsage(model.steps(),field),model.examples())
    .find(step=>step.sourceStepId===stage&&step.traceKind===kind);
  assert.ok(moment,`${scenario} / ${stage}: ${kind} ${field} must be animated`);
  return moment.payload.find(item=>item.attributeId===field)?.value;
};
const samlReviewExpect = (scenario,field,stage,kind,expected) =>
  assert.equal(samlReviewTraceValue(scenario,field,stage,kind),expected,`${scenario} / ${stage} / ${kind} ${field}`);

test('independent review: all 13 SAML trace observations retain the expected message authority, expiry and outcome',()=>{
  // Constants come from the partner roles and failure cases in the review,
  // independently of the implementation's payloads or authoring contexts.
  const cases=[
    ['lab-saml-artifact','slIssuer','sl-artifact-resolve-build','create',samlReviewSp],
    ['lab-saml-artifact','slIssuer','sl-artifact-resolve','send',samlReviewSp],
    ['lab-saml-artifact','slIssuer','sl-artifact-consume','verify',samlReviewSp],
    ['lab-saml-artifact','slDestination','sl-artifact-resolve-build','create',samlReviewResolution],
    ['lab-saml-artifact','slDestination','sl-artifact-resolve','send',samlReviewResolution],
    ['lab-saml-artifact','slDestination','sl-artifact-consume','verify',samlReviewResolution],
    ['lab-saml-validation-failures','slNotOnOrAfter','sl-fail-expired-wire','send','2026-10-07T13:55:00Z'],
    ['lab-saml-validation-failures','slNotOnOrAfter','sl-fail-expired-check','verify','2026-10-07T13:55:00Z'],
    ['lab-saml-validation-failures','slStatus','sl-fail-denied-browser','send',samlReviewResponder],
    ['lab-saml-validation-failures','slStatus','sl-fail-denied-submit','send',samlReviewResponder],
    ['lab-saml-validation-failures','slStatus','sl-fail-denied-submit','verify',samlReviewResponder],
    ['lab-saml-metadata','slMetadataEntityID','sl-meta-idp-response','send',samlReviewIdp],
    ['lab-saml-metadata','slMetadataEntityID','sl-meta-rollover','verify',samlReviewIdp],
  ];
  for(const args of cases)samlReviewExpect(...args);
});

test('ArtifactResolve authority changes only when the separate IdP response is created and returned',()=>{
  const artifact='Base64(type 0x0004 artifact; synthetic)';
  samlReviewExpect('lab-saml-artifact','slSamlart','sl-artifact-resolve-build','use',artifact);
  for(const [stage,kind]of [['sl-artifact-resolve-build','create'],['sl-artifact-resolve','send'],['sl-artifact-consume','verify']])
    samlReviewExpect('lab-saml-artifact','slArtifact',stage,kind,artifact);
  for(const [stage,kind]of [['sl-artifact-build','create'],['sl-artifact-response','send'],['sl-artifact-validate','verify']]){
    samlReviewExpect('lab-saml-artifact','slIssuer',stage,kind,samlReviewIdp);
    samlReviewExpect('lab-saml-artifact','slAudience',stage,kind,samlReviewSp);
    samlReviewExpect('lab-saml-artifact','slRecipient',stage,kind,samlReviewAcs);
    samlReviewExpect('lab-saml-artifact','slNotOnOrAfter',stage,kind,'2026-10-07T14:05:00Z');
  }
  samlReviewExpect('lab-saml-artifact','slOuterCorrelation','sl-artifact-response','send','_resolve_demo_01');
  samlReviewExpect('lab-saml-artifact','slInnerCorrelation','sl-artifact-response','send','_authn_demo_01');
});

test('independent SAML failure branches keep separate request contexts and never normalize a denial to Success',()=>{
  const scenario='lab-saml-validation-failures';
  samlReviewExpect(scenario,'slAssertion','sl-fail-expired-wire','send','<Assertion ID="_expired_assertion_01">…</Assertion>');
  for(const [stage,kind]of [['sl-fail-expired-wire','send'],['sl-fail-expired-check','verify']])
    samlReviewExpect(scenario,'slInnerCorrelation',stage,kind,'_authn_expired_01');
  samlReviewExpect(scenario,'slAuthnID','sl-fail-expired-check','verify','_authn_expired_01');
  for(const [stage,kind]of [['sl-fail-replay-wire','send'],['sl-fail-replay-check','verify']]){
    samlReviewExpect(scenario,'slAssertionID',stage,kind,'_assertion_demo_01');
    samlReviewExpect(scenario,'slInnerCorrelation',stage,kind,'_authn_demo_01');
  }
  for(const [stage,kind]of [['sl-fail-denied-build','create'],['sl-fail-denied-browser','send'],['sl-fail-denied-submit','send'],['sl-fail-denied-submit','verify']]){
    samlReviewExpect(scenario,'slStatus',stage,kind,samlReviewResponder);
    samlReviewExpect(scenario,'slSubStatus',stage,kind,samlReviewDenied);
    samlReviewExpect(scenario,'slInnerCorrelation',stage,kind,'_authn_denied_01');
  }
  samlReviewExpect(scenario,'slAuthnID','sl-fail-denied-submit','verify','_authn_denied_01');
  const steps=samlReviewModel(scenario).steps();
  for(const step of steps.filter(step=>step.samlLabFailure==='denied'))assert.ok(!step.fields.includes('slAssertion'));
  assert.ok(steps.every(step=>!step.attributeOperations.some(op=>op.attributeId==='slAppSession'&&op.kind==='create')));
});

test('SP and IdP metadata use their own entity, endpoint binding and public signing certificate at acceptance',()=>{
  const scenario='lab-saml-metadata';
  for(const [stage,kind]of [['sl-meta-sp-response','send'],['sl-meta-validate-sp','verify']]){
    samlReviewExpect(scenario,'slMetadataEntityID',stage,kind,samlReviewSp);
    samlReviewExpect(scenario,'slMetadataBinding',stage,kind,'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact');
    samlReviewExpect(scenario,'slMetadataLocation',stage,kind,samlReviewAcs);
    samlReviewExpect(scenario,'slMetadataSigningCert',stage,kind,'SP 1 public signing certificate; synthetic');
  }
  samlReviewExpect(scenario,'slMetadataEntityID','sl-meta-idp-response','send',samlReviewIdp);
  samlReviewExpect(scenario,'slMetadataEntityID','sl-meta-rollover','verify',samlReviewIdp);
  samlReviewExpect(scenario,'slMetadataBinding','sl-meta-idp-response','send','urn:oasis:names:tc:SAML:2.0:bindings:SOAP');
  samlReviewExpect(scenario,'slMetadataLocation','sl-meta-idp-response','send',samlReviewResolution);
  samlReviewExpect(scenario,'slMetadataSigningCert','sl-meta-idp-response','send','Realm A public signing certificate; synthetic');
});

test('SLO request and response traces keep participant-specific issuer, recipient and correlation at every boundary',()=>{
  const spSlo='https://app.example.test/saml/slo',otherSlo='https://reports.example.test/saml/slo';
  const exchanges=[
    ['lab-saml-sp-slo','sl-sp-slo-origin',samlReviewSp,samlReviewResolution,false,false],
    ['lab-saml-sp-slo','sl-sp-slo-second',samlReviewIdp,otherSlo,true,false],
    ['lab-saml-idp-slo','sl-idp-slo-first',samlReviewIdp,spSlo,false,false],
    ['lab-saml-idp-slo','sl-idp-slo-second',samlReviewIdp,otherSlo,true,false],
    ['lab-saml-soap-slo','sl-soap-slo-first',samlReviewIdp,spSlo+'/soap',false,true],
    ['lab-saml-soap-slo','sl-soap-slo-second',samlReviewIdp,otherSlo+'/soap',true,true],
  ];
  for(const [scenario,prefix,issuer,destination,other,soap]of exchanges){
    const requestStages=[[prefix+'-build','create'],[prefix+'-request','send']];
    if(prefix==='sl-sp-slo-origin')requestStages.push(['sl-sp-slo-idp-check','verify']);
    else requestStages.push([prefix+'-terminate','verify']);
    if(!soap)requestStages.push([prefix+'-to-browser','send']);
    for(const [stage,kind]of requestStages){
      samlReviewExpect(scenario,'slIssuer',stage,kind,issuer);
      samlReviewExpect(scenario,'slDestination',stage,kind,destination);
      samlReviewExpect(scenario,other?'slLogoutOtherID':'slLogoutID',stage,kind,other?'_logout_sp2_01':'_logout_sp1_01');
      samlReviewExpect(scenario,'slLogoutExpiry',stage,kind,'2026-10-07T14:05:00Z');
    }
    if(prefix==='sl-sp-slo-origin')continue;
    const responseIssuer=other?samlReviewOther:samlReviewSp;
    const responseStages=[[prefix+'-response-build','create'],[prefix+'-response','send'],[prefix+'-response','verify']];
    if(!soap)responseStages.push([prefix+'-response-browser','send']);
    for(const [stage,kind]of responseStages){
      samlReviewExpect(scenario,'slIssuer',stage,kind,responseIssuer);
      samlReviewExpect(scenario,'slDestination',stage,kind,samlReviewResolution);
      samlReviewExpect(scenario,other?'slLogoutOtherCorrelation':'slLogoutCorrelation',stage,kind,other?'_logout_sp2_01':'_logout_sp1_01');
      samlReviewExpect(scenario,'slStatus',stage,kind,samlReviewSuccess);
    }
  }
  for(const [stage,kind]of [['sl-sp-slo-final-build','create'],['sl-sp-slo-final-response-browser','send'],['sl-sp-slo-final-response','send'],['sl-sp-slo-final-response','verify']]){
    samlReviewExpect('lab-saml-sp-slo','slIssuer',stage,kind,samlReviewIdp);
    samlReviewExpect('lab-saml-sp-slo','slDestination',stage,kind,spSlo);
    samlReviewExpect('lab-saml-sp-slo','slLogoutCorrelation',stage,kind,'_logout_sp1_01');
  }
});
