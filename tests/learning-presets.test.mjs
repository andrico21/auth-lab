import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES } from '../src/protocol-data.js';
import { getJourneySteps, getActorOverrides, VARIANT_ATTRIBUTES } from '../src/architecture-variants.js';
import { getSamlSteps, getSamlActorOverrides, SAML_ATTRIBUTES } from '../src/saml-data.js';
import { LAB_MODELS } from '../src/lab-catalog.js';
import { getStepAttributeOperations, getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { applyJweProtection } from '../src/jwe-data.js';
import { LEARNING_PRESETS, PROVIDER_PROFILES, getLearningPreset, getProviderProfile, getPresetConfiguration, applyProviderProfile } from '../src/learning-presets.js';

const canonical=step=>String(step.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const find=(steps,id)=>steps.find(step=>canonical(step)===id);
const wire=(step,name)=>step.payload.find(item=>item.name===name)?.value;
const externalActors=()=>Object.fromEntries(Object.entries(ACTORS).map(([id,actor])=>[id,{...actor,...getActorOverrides('web','external')[id]}]));
const oidc=(mode='password')=>getJourneySteps(mode,'web','external');
const samlConfig={mode:'password-totp',architecture:'web',upstream:'external',applicationProtocol:'oidc',brokerProtocol:'saml',binding:'redirect',initiation:'sp'};

test('twelve complete choices include a one-click ordinary OIDC and ordinary SAML sign-in',()=>{
  assert.equal(LEARNING_PRESETS.length,12);
  assert.deepEqual(LEARNING_PRESETS.map(p=>p.common),[true,true,true,true,true,true,false,false,false,false,false,false]);
  assert.equal(new Set(LEARNING_PRESETS.map(p=>p.id)).size,12);
  const keys=['mode','architecture','upstream','authenticator','applicationProtocol','brokerProtocol','samlBinding','samlInitiation','tokenProtection','assertionProtection','oidcFlow'];
  for(const preset of LEARNING_PRESETS){const config=getPresetConfiguration(preset.id);for(const key of keys)assert.ok(config[key],preset.id+': '+key);}
  const basic=getPresetConfiguration('basic-keycloak');
  assert.equal(basic.mode,'password');assert.equal(basic.architecture,'web');assert.equal(basic.upstream,'single');assert.equal(basic.applicationProtocol,'oidc');assert.equal(basic.oidcFlow,'authorization-code');
  const saml=getPresetConfiguration('basic-saml');
  assert.equal(saml.applicationProtocol,'saml');assert.equal(saml.samlBinding,'redirect');assert.equal(saml.samlInitiation,'sp');assert.equal(saml.assertionProtection,'signed');
  assert.equal(getLearningPreset('basic-saml').summary.includes('POST'),true);
  for(const id of ['lab-spa-api','lab-bff-api'])assert.ok(LAB_MODELS[getLearningPreset(id).modelId]);
  assert.equal(getPresetConfiguration('service-to-service').oidcFlow,'client-credentials');
  assert.equal(getPresetConfiguration('device-sign-in').oidcFlow,'device');
  assert.equal(getPresetConfiguration('backend-token-exchange').oidcFlow,'token-exchange');
});

test('provider selection changes only the selectable external preset and selects its broker protocol',()=>{
  assert.equal(PROVIDER_PROFILES.length,5);
  for(const profile of PROVIDER_PROFILES){
    const config=getPresetConfiguration('corporate-external',profile.id);
    assert.equal(config.brokerProtocol,profile.protocol);assert.equal(config.applicationProtocol,'oidc');assert.equal(config.upstream,'external');assert.equal(config.providerManaged,true);
    assert.equal(getPresetConfiguration('basic-saml',profile.id).providerProfileId,'generic');
    assert.equal(getPresetConfiguration('basic-saml',profile.id).applicationProtocol,'saml');
    assert.ok(profile.sources.length);assert.ok(profile.sources.every(source=>/^https:\/\//.test(source.url)));
  }
  assert.throws(()=>getPresetConfiguration('missing'),RangeError);
  assert.throws(()=>getPresetConfiguration('corporate-external','missing'),RangeError);
  assert.throws(()=>{LEARNING_PRESETS[0].config.mode='passkey';},TypeError);
});

test('provider endpoint examples separate exact identity and transport for Entra, Okta, Cognito and SAML',()=>{
  const entra=getProviderProfile('entra').examples;
  assert.match(entra.issuer,/\/00000000-0000-4000-8000-000000000001\/v2\.0$/);
  assert.match(entra.authorizationEndpoint,/\/oauth2\/v2\.0\/authorize$/);
  assert.match(entra.jwksUri,/\/discovery\/v2\.0\/keys$/);
  const okta=getProviderProfile('okta');assert.equal(okta.examples.issuer,'https://company.okta.example.test');assert.match(okta.examples.authorizationEndpoint,/\/oauth2\/v1\/authorize$/);
  assert.ok(okta.assumptions.some(note=>/not an access credential for your own API/.test(note)));
  const cognito=getProviderProfile('cognito').examples;
  assert.notEqual(new URL(cognito.issuer).origin,new URL(cognito.loginDomain).origin);
  assert.equal(cognito.authorizationEndpoint,cognito.loginDomain+'/oauth2/authorize');assert.equal(cognito.jwksUri,cognito.issuer+'/.well-known/jwks.json');
  const aws=getProviderProfile('aws-identity-center').examples;
  assert.match(aws.entityID,/^urn:/);assert.match(aws.ssoUrl,/^https:/);assert.equal(aws.issuer,undefined);
});

test('named base profiles reject requested or pre-expanded broker JWE and retain independent Keycloak app JWE',()=>{
  for(const profile of PROVIDER_PROFILES.filter(profile=>profile.id!=='generic')) {
    assert.deepEqual(profile.brokerTokenProtection,['signed'],profile.id+' base capability is explicit');
    for(const applicationProtocol of ['oidc','saml']) {
      const config={...samlConfig,mode:'password',applicationProtocol,brokerProtocol:profile.protocol};
      const source=applicationProtocol==='oidc'&&profile.protocol==='oidc'?oidc():getSamlSteps(config);
      const actors=applicationProtocol==='saml'||profile.protocol==='saml'?getSamlActorOverrides(config):externalActors();
      const signed=applyProviderProfile(source,actors,profile.id,{...config,tokenProtection:'signed'});
      assert.equal(signed.steps.some(step=>step.jweHop==='broker'),false);
      const appProtected=applyJweProtection(source,{protection:'app-jwe'});
      const output=applyProviderProfile(appProtected,actors,profile.id,{...config,tokenProtection:'app-jwe'});
      assert.equal(output.steps.some(step=>step.jweHop==='broker'),false);
      if(applicationProtocol==='oidc') {
        assert.ok(output.steps.some(step=>step.jweHop==='app'&&step.jweStage==='wire'),profile.id+' retains actual application JWE');
        assert.ok(output.steps.filter(step=>step.jweHop==='app'&&step.jweStage==='encrypt').every(step=>step.from==='realmA'&&step.to==='realmA'));
      }
      for(const protection of ['broker-jwe','both-jwe']) {
        const expanded=applyJweProtection(source,{protection});
        assert.throws(()=>applyProviderProfile(expanded,actors,profile.id,{...config,tokenProtection:protection}),/signed broker identity results only/,profile.id+' '+applicationProtocol+' '+protection);
        // Request-level protection is also rejected before a caller expands it.
        assert.throws(()=>applyProviderProfile(source,actors,profile.id,{...config,tokenProtection:protection}),/signed broker identity results only/);
        if(expanded.some(step=>step.jweHop==='broker'))assert.throws(()=>applyProviderProfile(expanded,actors,profile.id,config),/signed broker identity results only/,'model-level guard does not depend on control state');
      }
    }
  }
});

test('generic broker JWE remains available and AWS application-leg copy describes the preset default',()=>{
  assert.deepEqual(getProviderProfile('generic').brokerTokenProtection,['signed','jwe']);
  for(const protection of ['broker-jwe','both-jwe']) {
    const source=applyJweProtection(oidc(),{protection});
    const output=applyProviderProfile(source,externalActors(),'generic',{upstream:'external',tokenProtection:protection});
    assert.ok(output.steps.some(step=>step.jweHop==='broker'&&step.jweStage==='wire'));
    if(protection==='both-jwe')assert.ok(output.steps.some(step=>step.jweHop==='app'&&step.jweStage==='wire'));
  }
  const notes=getProviderProfile('aws-identity-center').assumptions.join(' ');
  assert.match(notes,/ready preset uses OIDC/);assert.match(notes,/independently as OIDC or SAML/);assert.doesNotMatch(notes,/leg remains OIDC/);
});

test('branded sign-in preserves both OIDC clients and application PKCE while removing guessed credential ceremonies',()=>{
  for(const profileId of ['entra','okta','cognito'])for(const mode of ['password','password-totp','passkey']){
    const source=oidc(mode),actors=externalActors(),before=JSON.stringify({source,actors});
    const output=applyProviderProfile(source,actors,profileId,{upstream:'external'}),profile=getProviderProfile(profileId);
    assert.equal(JSON.stringify({source,actors}),before);
    assert.equal(output.steps.filter(step=>step.providerManaged).length,3);
    assert.equal(output.steps.some(step=>['password','mfa','passkey','otp'].includes(step.phase)),false);
    assert.equal(output.steps.some(step=>['totp','hello','yubikey','authenticator'].includes(step.from)||['totp','hello','yubikey','authenticator'].includes(step.to)),false);
    assert.equal(output.steps.some(step=>step.fields.includes('password')||step.fields.includes('otpCode')||step.fields.includes('signature')),false);
    assert.equal(wire(find(output.steps,'l03'),'client_id'),'web-app');assert.equal(wire(find(output.steps,'l03'),'code_challenge_method'),'S256');
    assert.equal(wire(find(output.steps,'l06'),'client_id'),profile.examples.clientIdBroker);
    assert.equal(wire(find(output.steps,'l06'),'Location'),profile.examples.authorizationEndpoint);
    assert.equal(wire(find(output.steps,'l06'),'code_challenge'),undefined);
    assert.equal(wire(find(output.steps,'l18'),'iss'),profile.examples.issuer);
    assert.equal(wire(find(output.steps,'l18'),'aud'),profile.examples.clientIdBroker);
    assert.equal(wire(find(output.steps,'l24'),'iss'),'https://idp1.example.test/realms/realm-a');
    assert.equal(find(output.steps,'l19').attributeValues.jwksUri,profile.examples.jwksUri);
    assert.equal(find(output.steps,'l25').attributeValues.jwksUri,'https://idp1.example.test/realms/realm-a/protocol/openid-connect/certs');
    assert.equal(output.actors.realmB.name,profile.title);
    assert.equal(output.actors.realmB.attributes.some(item=>item.id==='rpId'||item.id==='passwordHash'),false);
    for(const step of output.steps){assert.ok(step.payload.length);for(const id of step.fields)assert.ok(ATTRIBUTES[id]||SAML_ATTRIBUTES[id]||VARIANT_ATTRIBUTES[id],id);}
  }
});

test('Entra broker uses POST body client authentication without inventing a Basic header or browser secret',()=>{
  const output=applyProviderProfile(oidc(),externalActors(),'entra',{upstream:'external'});
  const token=find(output.steps,'l17');
  assert.equal(wire(token,'Authorization'),undefined);assert.ok(wire(token,'client_secret'));
  assert.equal(token.fields.includes('authorizationHeader'),false);
  const operations=getStepAttributeOperations(token);
  assert.equal(operations.some(op=>op.attributeId==='authorizationHeader'),false);
  assert.ok(operations.some(op=>op.attributeId==='clientSecret'&&op.kind==='send'&&op.actorId==='realmA'));
  assert.equal(output.steps.some(step=>(step.from==='browser'||step.to==='browser')&&step.payload.some(item=>item.name==='client_secret')),false);
  const issuerTrace=buildAttributeTrace(getAttributeUsage(output.steps,'issuerB'),output.exampleOverrides);
  assert.ok(issuerTrace.length);assert.ok(issuerTrace.every(step=>step.payload.every(item=>item.value===getProviderProfile('entra').examples.issuer)));
});

test('AWS profile keeps upstream SAML distinct from application OIDC and claims no fabricated assurance',()=>{
  const source=getSamlSteps(samlConfig),actors=getSamlActorOverrides(samlConfig),before=JSON.stringify({source,actors});
  const output=applyProviderProfile(source,actors,'aws-identity-center',{upstream:'external',providerManaged:true});
  assert.equal(JSON.stringify({source,actors}),before);
  assert.ok(output.steps.some(step=>step.id==='saml-broker-request-create'));
  assert.ok(output.steps.some(step=>step.id==='saml-broker-response-browser'));
  assert.ok(output.steps.some(step=>canonical(step)==='l23'));
  assert.equal(output.steps.some(step=>canonical(step)==='l17'),false);
  assert.equal(output.steps.some(step=>step.fields.includes('otpCode')),false);
  const request=output.steps.find(step=>step.id==='saml-broker-request-create');
  assert.equal(request.attributeValues.samlSsoB,getProviderProfile('aws-identity-center').examples.ssoUrl);
  assert.equal(request.attributeValues.samlIdpEntityB,getProviderProfile('aws-identity-center').examples.entityID);
  const response=output.steps.find(step=>step.id==='saml-broker-response-create');
  assert.equal(response.attributeValues.samlAuthnContextBroker,'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
  assert.equal(output.exampleOverrides.samlAcsBroker,'https://idp1.example.test/realms/realm-a/broker/aws-identity-center/endpoint');
  assert.throws(()=>applyProviderProfile(oidc(),externalActors(),'aws-identity-center'),RangeError);
  assert.throws(()=>applyProviderProfile(source,actors,'entra'),RangeError);
});

test('SAML application above an opaque OIDC provider does not fabricate a password authentication context',()=>{
  const config={...samlConfig,mode:'password',applicationProtocol:'saml',brokerProtocol:'oidc'};
  const output=applyProviderProfile(getSamlSteps(config),getSamlActorOverrides(config),'entra',config);
  const response=output.steps.find(step=>step.id==='saml-app-response-create');
  assert.ok(response);
  const unspecified='urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
  assert.equal(response.attributeValues.samlAuthnContextApp,unspecified);
  assert.equal(wire(response,'AuthnContextClassRef'),unspecified);
  assert.equal(output.exampleOverrides.samlAuthnContextApp,unspecified);
  assert.equal(output.attributeOverrides.samlAuthnContextApp.example,unspecified);
  assert.equal(output.steps.some(step=>step.fields.includes('password')),false);
});

test('generic detailed factors stay available; explicit provider boundary and irrelevant profile handling are predictable',()=>{
  const detailed=applyProviderProfile(oidc('password-totp'),externalActors(),'generic',{upstream:'external'});
  assert.ok(detailed.steps.some(step=>step.fields.includes('otpCode')));assert.equal(detailed.steps.some(step=>step.providerManaged),false);
  const managed=applyProviderProfile(oidc('password-totp'),externalActors(),'generic',{upstream:'external',providerManaged:true});
  assert.equal(managed.steps.some(step=>step.fields.includes('otpCode')),false);assert.equal(managed.steps.filter(step=>step.providerManaged).length,3);
  const local=getJourneySteps('password','web','single'),unchanged=applyProviderProfile(local,ACTORS,'entra',{upstream:'single'});
  assert.equal(unchanged.steps,local);assert.equal(unchanged.actors,ACTORS);assert.equal(unchanged.profile,null);
  assert.equal(applyProviderProfile(local,ACTORS,'aws-identity-center',{upstream:'single'}).steps,local);
  assert.throws(()=>applyProviderProfile(getJourneySteps('enrollment','web','external'),externalActors(),'entra',{upstream:'external'}),RangeError);
});

// Application integration uses the existing offline harness. These fixtures
// check configuration, message data and attribute ownership, not browser layout.
const {installHarness,HarnessEvent}=await import('./dom-harness.mjs');
const {document:presetDocument,clock:presetClock}=installHarness();
const {AuthFlowStudio:PresetStudio}=await import('../src/app.js');
function mountPresetStudio(){const app=new PresetStudio();presetDocument.body.appendChild(app);app.connectedCallback();return app;}
function unmountPresetStudio(app){app.disconnectedCallback();presetDocument.body.removeChild(app);presetClock.frames.clear();presetClock.timers.clear();}
function choosePresetControl(app,id,value){const control=app.querySelector('#'+id);control.value=value;control.dispatchEvent(new HarnessEvent('change'));}

test('ready choices initialize ordinary login and preserve SPA/BFF model ownership',()=>{
  const app=mountPresetStudio();try{
    assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(app.upstream,'single');assert.equal(app.mode,'password');
    assert.equal(app.querySelector('#advanced-configuration').hasAttribute('open'),false);
    for(const preset of LEARNING_PRESETS){
      app.selectLabScenario(preset.id);assert.equal(app.labScenarioId,preset.id);
      assert.ok(app.steps.length,preset.id);assert.equal(app.querySelector('#scenario-title').textContent,preset.title);
      if(preset.extended)assert.equal(app.labModel,LAB_MODELS[preset.modelId]);
      else assert.equal(app.labModel,null);
    }
    app.selectLabScenario('basic-saml');
    assert.equal(app.applicationProtocol,'saml');assert.equal(app.samlBinding,'redirect');assert.equal(app.samlInitiation,'sp');
    assert.ok(app.steps.some(step=>step.fields.includes('samlRequest')));assert.ok(app.steps.some(step=>step.fields.includes('samlResponse')));
    assert.equal(app.steps.some(step=>step.fields.includes('slArtifact')),false);
  }finally{unmountPresetStudio(app);}
});

test('corporate preset permits attribute inspection without mutating frozen runtime projections or probing vendor enrollment',()=>{
  const app=mountPresetStudio();try{
    app.selectLabScenario('corporate-external');assert.equal(app.providerProfileId,'entra');
    for(const id of ['clientIdApp','codeChallenge','issuerB']){
      assert.doesNotThrow(()=>app.selectAttribute(id,false),id+' can be inspected');
      assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length);
      assert.ok(app.currentStep);
    }
    app.clearAttribute();choosePresetControl(app,'provider-profile','aws-identity-center');
    for(const id of ['samlRequest','samlIdpEntityB','codeChallenge'])assert.doesNotThrow(()=>app.selectAttribute(id,false),id+' across mixed OIDC/SAML');
  }finally{unmountPresetStudio(app);}
});

test('branded provider selection removes unmodeled hardware attributes and constrains its broker protocol',()=>{
  const app=mountPresetStudio();try{
    app.selectLabScenario('core');choosePresetControl(app,'mode','passkey');choosePresetControl(app,'authenticator','yubikey');choosePresetControl(app,'upstream','external');
    choosePresetControl(app,'provider-profile','entra');
    assert.equal(app.steps.some(step=>step.fields.some(id=>/^(?:ctap|pinUv|password|otpCode|signature)/.test(id))),false);
    assert.equal(app.actor('browser').attributes.some(item=>/^(?:ctap|pinUv)/.test(item.id)),false,'opaque provider ceremony does not acquire invented CTAP attributes');
    assert.equal(app.refs['broker-protocol'].disabled,true,'brand-selected broker binding cannot be changed to an incompatible protocol');
    choosePresetControl(app,'provider-profile','generic');
    assert.equal(app.refs['broker-protocol'].disabled,false,'explicit generic protocol teaching remains configurable');
  }finally{unmountPresetStudio(app);}
});

test('inspector protocol shortcuts do not apply an incompatible branded broker profile',()=>{
  const app=mountPresetStudio();try{
    app.selectLabScenario('corporate-external');app.selectAttribute('samlIdpEntityB',false);
    const toSaml=app.refs.inspector.querySelector('[data-trace-protocol="saml"]');
    if(toSaml){assert.doesNotThrow(()=>toSaml.click());assert.equal(app.brokerProtocol,'saml');assert.ok(app.providerProfileId==='generic'||app.providerProfile.protocol==='saml');assert.ok(app.traceQueue.length);}
    else assert.equal(app.brokerProtocol,'oidc');
    app.clearAttribute();app.selectLabScenario('corporate-external');choosePresetControl(app,'provider-profile','aws-identity-center');app.selectAttribute('authorizationHeader',false);
    const toOidc=app.refs.inspector.querySelector('[data-trace-protocol="oidc"]');
    if(toOidc){assert.doesNotThrow(()=>toOidc.click());assert.equal(app.brokerProtocol,'oidc');assert.ok(app.providerProfileId==='generic'||app.providerProfile.protocol==='oidc');assert.ok(app.traceQueue.length);}
    else assert.equal(app.brokerProtocol,'saml');
  }finally{unmountPresetStudio(app);}
});
