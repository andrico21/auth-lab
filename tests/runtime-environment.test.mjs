import test from 'node:test';
import assert from 'node:assert/strict';
import {RuntimeEnvironment,RUNTIME_ENVIRONMENT_FIELDS,RUNTIME_PROVIDER_FIELDS} from '../src/runtime-environment.js';
import {getJourneySteps,getActorOverrides,JOURNEYS} from '../src/architecture-variants.js';
import {getSamlSteps,SAML_ATTRIBUTES} from '../src/saml-data.js';
import {getFidoSteps,getFidoExampleOverrides,getFidoActorOverrides} from '../src/fido-direct.js';
import {LEGACY_LAB_SCENARIOS as LAB_SCENARIOS} from '../src/lab-catalog.js';
import {ATTRIBUTES,ACTORS} from '../src/protocol-data.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {getProviderProfile,applyProviderProfile} from '../src/learning-presets.js';

const issuerA='https://idp1.example.test/realms/realm-a';
const issuerB='https://idp2.example.test/realms/realm-b';
const applied = (patch,options={}) => {const environment=new RuntimeEnvironment();environment.updateDraft(patch,options);assert.equal(environment.apply(options).ok,true);return environment;};
const displayStrings = steps => steps.flatMap(step=>[step.title,step.summary,step.detail,...(step.payload||[]).flatMap(item=>[item.value,item.description]),...Object.values(step.attributeValues||{}),...(step.attributeOperations||[]).map(operation=>operation.detail),...(step.checks||[])]).filter(value=>typeof value==='string');
const topology = steps => steps.map(step=>({id:step.id,from:step.from,to:step.to,channel:step.channel,phase:step.phase,fields:step.fields,operations:(step.attributeOperations||[]).map(({detail,...operation})=>operation),payloadKeys:step.payload?.map(item=>[item.name,item.attributeId]),checks:step.checks?.length}));

test('the optional runtime schema separates application addresses, identifiers and provider metadata',()=>{
  const keys=RUNTIME_ENVIRONMENT_FIELDS.map(field=>field.key);
  assert.ok(keys.includes('appURL')&&keys.includes('appCallbackURL')&&keys.includes('acsURL')&&keys.includes('appEntityID')&&keys.includes('clientID'));
  assert.equal(RUNTIME_ENVIRONMENT_FIELDS.find(field=>field.key==='appCallbackURL').advanced,true);
  assert.equal(RUNTIME_ENVIRONMENT_FIELDS.find(field=>field.key==='appEntityID').kind,'uri');
  assert.ok(RUNTIME_PROVIDER_FIELDS.some(field=>field.key==='issuerURL'));
  assert.ok(RUNTIME_PROVIDER_FIELDS.some(field=>field.key==='loginDomainURL'));
  assert.ok(Object.isFrozen(RUNTIME_ENVIRONMENT_FIELDS));
});

test('draft editing does not affect applied examples; apply and reset are atomic and revisioned',()=>{
  const environment=new RuntimeEnvironment();
  assert.equal(environment.active,false);assert.equal(environment.revision,0);
  environment.updateDraft({appURL:'https://corp.example/app'});
  assert.equal(environment.projectValue('https://app.example.test/login'),'https://app.example.test/login');
  assert.equal(environment.apply().ok,true);assert.equal(environment.revision,1);
  assert.equal(environment.projectValue('https://app.example.test/login'),'https://corp.example/app/login');
  const previous=environment.applied;
  environment.updateDraft({appURL:'javascript:alert(1)'});
  const failure=environment.apply();assert.equal(failure.ok,false);assert.ok(failure.errors.appURL);
  assert.equal(environment.applied,previous);assert.equal(environment.revision,1);
  environment.reset();assert.equal(environment.active,false);assert.equal(environment.revision,2);
  assert.equal(environment.draft.appURL,'');assert.deepEqual(environment.draft.providers,{});
});

test('deployment context paths and escaped realm/broker segments remain coherent',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.corp.example/auth/',realmA:'Sales / UAE',keycloakBBaseURL:'https://partner.corp.example/keycloak',realmB:'Workers',brokerAlias:'partner / SSO'});
  const a='https://sso.corp.example/auth/realms/Sales%20%2F%20UAE',b='https://partner.corp.example/keycloak/realms/Workers';
  assert.equal(environment.projectValue(issuerA),a);assert.equal(environment.projectValue(issuerB),b);
  assert.equal(environment.projectValue(issuerA+'/protocol/openid-connect/token'),a+'/protocol/openid-connect/token');
  assert.equal(environment.projectValue(issuerB+'/protocol/openid-connect/certs'),b+'/protocol/openid-connect/certs');
  assert.equal(environment.projectValue(issuerA+'/broker/realm-b/endpoint'),a+'/broker/partner%20%2F%20SSO/endpoint');
});

test('exact issuers are preserved and explicit endpoints independently override derived Keycloak paths',()=>{
  const exact='https://sso.example/ExactIssuer/';
  const environment=applied({aIssuerURL:exact,aAuthorizationURL:'https://authorize.example/start',aTokenURL:'https://tokens.example/exchange',aJwksURL:'https://keys.example/jwks'});
  assert.equal(environment.projectValue(issuerA),exact);
  assert.equal(environment.projectValue(issuerA+'/protocol/openid-connect/auth'),'https://authorize.example/start');
  assert.equal(environment.projectValue(issuerA+'/protocol/openid-connect/token'),'https://tokens.example/exchange');
  assert.equal(environment.projectValue(issuerA+'/protocol/openid-connect/certs'),'https://keys.example/jwks');
});

test('endpoint validation permits HTTP loopback only for native application/callback addresses',()=>{
  const environment=new RuntimeEnvironment();environment.updateDraft({appCallbackURL:'http://127.0.0.1:57231/return'});
  assert.equal(environment.validate({architecture:'web'}).ok,false);
  assert.equal(environment.apply({architecture:'native'}).ok,true);
  assert.equal(environment.projectValue('http://127.0.0.1:54321/callback'),'http://127.0.0.1:57231/return');
  environment.updateDraft({keycloakABaseURL:'http://localhost:8080/auth'});
  assert.equal(environment.validate({architecture:'native'}).ok,false);
  environment.updateDraft({keycloakABaseURL:'https://sso.example/auth?tenant=x'});
  assert.equal(environment.validate().ok,false);
  environment.updateDraft({keycloakABaseURL:'https://admin:password@sso.example'});
  assert.equal(environment.validate().ok,false);
  environment.updateDraft({keycloakABaseURL:'https://sso.example',realmA:'..'});
  assert.equal(environment.validate().ok,false);
});

test('app callback query, exact ACS and URI entityID are independent values',()=>{
  const environment=applied({appURL:'https://portal.example/company',appCallbackURL:'https://callbacks.example/oidc?tenant=uae',acsURL:'https://acs.example/consume',appEntityID:'urn:corp:portal:sp'});
  assert.equal(environment.projectValue('GET https://app.example.test/oidc/callback?code=C0&state=S'),'GET https://callbacks.example/oidc?tenant=uae&code=C0&state=S');
  assert.equal(environment.projectValue('https://app.example.test/saml/acs'),'https://acs.example/consume');
  assert.equal(environment.projectValue('https://app.example.test/saml'),'urn:corp:portal:sp');
  assert.equal(environment.projectValue('urn:example:app:sp'),'urn:corp:portal:sp');
  assert.equal(environment.projectValue('https://app.example.test/saml/metadata'),'https://portal.example/company/saml/metadata');
});

test('symbolic bindings do not rewrite unrelated URI suffixes, domains or newly inserted operator values',()=>{
  const environment=applied({appURL:'https://portal.example/desktop-app',clientID:'custom-client',aIssuerURL:'https://idp2.example.test/realms/realm-b'});
  assert.equal(environment.projectValue('https://app.example.test.evil/login'),'https://app.example.test.evil/login');
  assert.equal(environment.projectValue(issuerA+'/unbound/private/path'),issuerA+'/unbound/private/path');
  assert.equal(environment.projectValue('https://unrelated.example/desktop-app'),'https://unrelated.example/desktop-app');
  assert.equal(environment.projectValue(issuerA),'https://idp2.example.test/realms/realm-b');
  assert.equal(environment.projectValue('https://app.example.test/login'),'https://portal.example/desktop-app/login');
  assert.equal(environment.projectValue('https://www.rfc-editor.org/rfc/rfc6749'),'https://www.rfc-editor.org/rfc/rfc6749');
});

test('provider overrides are isolated, and another provider draft is not implicitly committed',()=>{
  const environment=new RuntimeEnvironment();
  environment.updateDraft({provider:{issuerURL:'https://entra.example/tenant/v2.0'}},{profileId:'entra'});
  assert.equal(environment.apply({profileId:'entra'}).ok,true);
  environment.updateDraft({provider:{issuerURL:'javascript:bad'}},{profileId:'generic'});
  environment.updateDraft({provider:{issuerURL:'https://okta.example/org',tokenURL:'https://okta.example/token'}},{profileId:'okta'});
  assert.equal(environment.apply({profileId:'okta'}).ok,true);
  assert.equal(environment.applied.providers.generic,undefined);
  assert.equal(environment.applied.providers.entra.issuerURL,'https://entra.example/tenant/v2.0');
  const entra=getProviderProfile('entra'),okta=getProviderProfile('okta');
  assert.equal(environment.projectValue(entra.examples.issuer,{profileId:'entra',providerProfile:entra}),'https://entra.example/tenant/v2.0');
  assert.equal(environment.projectValue(okta.examples.issuer,{profileId:'okta',providerProfile:okta}),'https://okta.example/org');
  assert.equal(environment.projectValue(entra.examples.issuer,{profileId:'okta',providerProfile:okta}),entra.examples.issuer);
});

test('an arbitrary external issuer never invents authorization, token or JWKS paths',()=>{
  const profile=getProviderProfile('cognito');
  const environment=applied({provider:{issuerURL:'https://custom-issuer.example/exact'}},{profileId:'cognito'});
  const options={profileId:'cognito',providerProfile:profile};
  assert.equal(environment.projectValue(profile.examples.issuer,options),'https://custom-issuer.example/exact');
  assert.equal(environment.projectValue(profile.examples.authorizationEndpoint,options),profile.examples.authorizationEndpoint);
  assert.equal(environment.projectValue(profile.examples.tokenEndpoint,options),profile.examples.tokenEndpoint);
  assert.equal(environment.projectValue(profile.examples.jwksUri,options),profile.examples.jwksUri);
  assert.equal(environment.projectValue(profile.examples.loginDomain,options),profile.examples.loginDomain);
});

test('Cognito managed-login overrides follow declared routes while keeping exact endpoints and user-pool trust independent',()=>{
  const profile=getProviderProfile('cognito'),options={profileId:'cognito',providerProfile:profile};
  const environment=applied({provider:{loginDomainURL:'https://corporate.auth.example/login'}},options);
  assert.equal(environment.projectValue(profile.examples.authorizationEndpoint,options),'https://corporate.auth.example/login/oauth2/authorize');
  assert.equal(environment.projectValue(profile.examples.tokenEndpoint,options),'https://corporate.auth.example/login/oauth2/token');
  assert.equal(environment.projectValue(profile.examples.issuer,options),profile.examples.issuer);
  assert.equal(environment.projectValue(profile.examples.jwksUri,options),profile.examples.jwksUri);
  environment.updateDraft({provider:{authorizationURL:'https://exact.example/authorize',tokenURL:'https://exact.example/redeem'}},options);assert.equal(environment.apply(options).ok,true);
  assert.equal(environment.projectValue(profile.examples.authorizationEndpoint,options),'https://exact.example/authorize');
  assert.equal(environment.projectValue(profile.examples.tokenEndpoint,options),'https://exact.example/redeem');
});

test('native loopback overrides do not leak into a web/SAML preset and inactive drafts cannot block or silently join its apply',()=>{
  const environment=applied({appURL:'http://127.0.0.1:58000/app',appCallbackURL:'http://127.0.0.1:58000/return'},{architecture:'native'});
  assert.equal(environment.projectValue('https://app.example.test/oidc/callback',{architecture:'native'}),'http://127.0.0.1:58000/return');
  assert.equal(environment.projectValue('https://app.example.test/oidc/callback',{architecture:'web'}),'https://app.example.test/oidc/callback');
  assert.equal(environment.projectValue('https://app.example.test/login',{architecture:'web'}),'https://app.example.test/login');
  assert.equal(environment.projectValue('https://app.example.test/saml/acs',{architecture:'web'}),'https://app.example.test/saml/acs');
  environment.updateDraft({keycloakABaseURL:'https://sso.example',realmA:'employees',appCallbackURL:'javascript:uncommitted',provider:{issuerURL:'javascript:other-uncommitted'}});
  const options={architecture:'web',activeFields:['keycloakABaseURL','realmA','acsURL','appEntityID']};
  assert.equal(environment.apply(options).ok,true);
  assert.equal(environment.applied.appCallbackURL,'http://127.0.0.1:58000/return');
  assert.equal(environment.applied.providers.generic,undefined);
  assert.equal(environment.draft.appCallbackURL,'javascript:uncommitted');
  assert.equal(environment.projectValue(issuerA,{architecture:'web'}),'https://sso.example/realms/employees');
  assert.equal(environment.projectValue('https://app.example.test/oidc/callback',{architecture:'web'}),'https://app.example.test/oidc/callback');
  assert.equal(environment.apply({architecture:'web',activeFields:['appCallbackURL']}).ok,false);
});

test('URL scheme applicability is parsed consistently without normalizing exact native or HTTPS values',()=>{
  for(const scheme of ['http','HTTP','HtTp']){
    const appURL=scheme+'://127.0.0.1:58000/app',appCallbackURL=scheme+'://127.0.0.1:58000/return';
    const environment=applied({appURL,appCallbackURL},{architecture:'native'});
    const native={architecture:'native',upstream:'single',applicationProtocol:'oidc'};
    assert.equal(environment.projectValue('https://app.example.test/oidc/callback',native),appCallbackURL);
    assert.equal(environment.participantContext('app',native).find(row=>row.key==='appURL').value,appURL);
    for(const options of [{architecture:'web',applicationProtocol:'oidc'},{architecture:'web',applicationProtocol:'saml'},{architecture:'web',directFido:true},{architecture:'native',directFido:true}]){
      assert.equal(environment.projectValue('https://app.example.test/login',options),'https://app.example.test/login');
      assert.equal(environment.projectValue('https://app.example.test/oidc/callback',options),'https://app.example.test/oidc/callback');
      assert.equal(environment.projectValue('https://app.example.test/saml/acs',options),'https://app.example.test/saml/acs');
      const steps=options.directFido?getFidoSteps('fido-login','yubikey'):options.applicationProtocol==='saml'?getSamlSteps({...options,upstream:'single',mode:'password'}):getJourneySteps('password','web','single');
      assert.ok(!displayStrings(environment.projectSteps(steps,options)).some(value=>value.includes('127.0.0.1:58000')),JSON.stringify(options));
      assert.ok(!environment.participantContext('app',options).some(row=>row.value.includes('127.0.0.1:58000')),JSON.stringify(options));
    }
    assert.equal(environment.applied.appURL,appURL);assert.equal(environment.applied.appCallbackURL,appCallbackURL);
    environment.updateDraft({appURL,appCallbackURL});
    assert.equal(environment.validate({architecture:'web'}).ok,false);
    assert.equal(environment.validate({architecture:'native',directFido:true}).ok,false);
  }
  const environment=applied({appURL:'HtTpS://Portal.Example/Team',appCallbackURL:'HTTPS://Callback.Example/exact?tenant=A',aIssuerURL:'HTTPS://SSO.Example/realms/Employees'});
  assert.equal(environment.projectValue('https://app.example.test/oidc/callback'),'HTTPS://Callback.Example/exact?tenant=A');
  assert.equal(environment.projectValue(issuerA),'HTTPS://SSO.Example/realms/Employees');
  assert.equal(environment.projectValue('origin equals '+issuerA),'origin equals https://sso.example');
  assert.equal(environment.participantContext('app').find(row=>row.key==='appURL').value,'HtTpS://Portal.Example/Team');
});

test('execution environment controls loopback applicability independently of public-client layout and resolver caches',()=>{
  for(const scheme of ['http','HTTP','HtTp']){
    const appURL=scheme+'://127.0.0.1:58749/app',appCallbackURL=scheme+'://127.0.0.1:58749/return';
    const native={architecture:'native',executionEnvironment:'native',clientActor:'app'};
    const environment=applied({appURL,appCallbackURL},native);
    for(const executionEnvironment of ['browser','server']){
      const options={...native,executionEnvironment};
      assert.equal(environment.projectValue('https://learning.example.test/callback',native),appCallbackURL);
      assert.equal(environment.projectValue('https://learning.example.test/callback',options),'https://learning.example.test/callback');
      assert.equal(environment.projectValue('https://learning.example.test/login',options),'https://learning.example.test/login');
      assert.equal(environment.validate(options).ok,false);
      assert.equal(environment.projectValue('https://learning.example.test/callback',native),appCallbackURL,'returning to native reuses exact applicable value');
      assert.ok(!environment.participantContext('app',{...options,exampleValues:{appURL:'https://learning.example.test',redirectApp:'https://learning.example.test/callback'}}).some(row=>row.value.includes('127.0.0.1:58749')));
    }
    assert.equal(environment.validate({...native,architecture:'web'}).ok,true,'execution can be native even with another layout');
    assert.equal(environment.applied.appCallbackURL,appCallbackURL);
  }
  const environment=applied({appURL:'HTTPS://Portal.Example/path',appCallbackURL:'HtTpS://Callback.Example/exact?tenant=A'},{architecture:'native',executionEnvironment:'browser'});
  assert.equal(environment.projectValue('https://learning.example.test/callback'),'HtTpS://Callback.Example/exact?tenant=A');
  assert.equal(environment.validate().ok,true);
});

test('application context follows its explicitly declared browser client and keeps IdP ownership separate',()=>{
  const environment=applied({appURL:'https://portal.example/area',appCallbackURL:'HTTPS://Portal.Example/callback',clientID:'browser-client',keycloakABaseURL:'https://sso.example/auth',realmA:'Office'});
  const options={architecture:'web',executionEnvironment:'browser',clientActor:'browser',upstream:'single',labScenarioId:'lab-spa-api',exampleValues:{clientIdApp:'spa-public',redirectApp:'https://spa.example.test/callback'}};
  assert.deepEqual(environment.participantContext('browser',options).map(row=>[row.key,row.value]),[['appURL','https://portal.example/area'],['appCallbackURL','HTTPS://Portal.Example/callback'],['clientID','browser-client']]);
  assert.deepEqual(environment.participantContext('app',options),[]);
  assert.deepEqual(environment.participantContext('realmB',options),[]);
  assert.equal(environment.participantContext('realmA',options).find(row=>row.key==='issuerURL').value,'https://sso.example/auth/realms/Office');
  environment.updateDraft({appURL:'https://draft.example'});assert.equal(environment.participantContext('browser',options)[0].value,'https://portal.example/area');
  environment.reset();assert.equal(environment.participantContext('browser',options)[0].value,'https://spa.example.test');
});

test('participant context is immutable applied display metadata, with effective paths and protocol-specific identifiers',()=>{
  const environment=new RuntimeEnvironment(),options={architecture:'web',upstream:'single',applicationProtocol:'oidc'};
  const original=environment.participantContext('app',options);
  environment.updateDraft({appURL:'https://draft.example/ignored',keycloakABaseURL:'https://draft.example/kc',realmA:'draft'});
  assert.deepEqual(environment.participantContext('app',options),original);
  assert.equal(environment.revision,0);assert.ok(Object.isFrozen(original)&&Object.isFrozen(original[0]));
  environment.updateDraft({appURL:'HTTPS://Portal.Example/team',keycloakABaseURL:'https://sso.example/auth',realmA:'Employees / West',appCallbackURL:'https://callback.example/exact',acsURL:'https://acs.example/exact',appEntityID:'urn:corp:portal:sp',aEntityID:'urn:corp:keycloak:idp',aSsoURL:'https://saml.example/exact',clientID:'portal-client'});
  assert.equal(environment.apply(options).ok,true);
  const app=environment.participantContext('app',options),kc=environment.participantContext('realmA',options);
  assert.deepEqual(app.map(row=>[row.key,row.value]),[['appURL','HTTPS://Portal.Example/team'],['appCallbackURL','https://callback.example/exact'],['clientID','portal-client']]);
  assert.deepEqual(kc.map(row=>[row.key,row.value]),[['keycloakBaseURL','https://sso.example/auth'],['realm','Employees / West'],['issuerURL','https://sso.example/auth/realms/Employees%20%2F%20West']]);
  assert.equal(kc.find(row=>row.key==='issuerURL').provenance,'derived');
  const saml={...options,applicationProtocol:'saml'};
  assert.deepEqual(environment.participantContext('app',saml).map(row=>[row.key,row.value]),[['appURL','HTTPS://Portal.Example/team'],['acsURL','https://acs.example/exact'],['samlEntityID','urn:corp:portal:sp']]);
  assert.deepEqual(environment.participantContext('realmA',saml).slice(-2).map(row=>[row.key,row.value]),[['samlEntityID','urn:corp:keycloak:idp'],['ssoURL','https://saml.example/exact']]);
  assert.deepEqual(environment.participantContext('realmB',options),[]);
  assert.deepEqual(environment.participantContext('realmA',{...options,actorKind:'resource'}),[]);
  assert.deepEqual(environment.participantContext('browser',options),[]);
  const fido=environment.participantContext('app',{...options,directFido:true});
  assert.deepEqual(fido.map(row=>[row.key,row.value]),[['appURL','HTTPS://Portal.Example/team'],['origin','https://portal.example'],['rpID','portal.example']]);
  assert.deepEqual(environment.participantContext('realmA',{...options,directFido:true}),[]);
  const revision=environment.revision;environment.participantContext('app',options);assert.equal(environment.revision,revision);
  environment.reset();assert.deepEqual(environment.participantContext('app',options),original);
});

test('participant provider metadata and aliases stay owner-scoped and never expose pending drafts or credentials',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.example/auth',realmA:'employees',brokerAlias:'custom / provider',keycloakBBaseURL:'https://second.example/kc',realmB:'partners'});
  for(const profileId of ['generic','entra','okta','cognito','aws-identity-center']){
    const profile=getProviderProfile(profileId),options={profileId,providerProfile:profile,upstream:'external',brokerProtocol:profile.protocol,applicationProtocol:'oidc',architecture:'web'};
    environment.updateDraft({provider:profile.protocol==='saml'?{samlEntityID:'urn:corp:'+profileId,ssoURL:'https://'+profileId+'.example/sso'}:{issuerURL:'https://'+profileId+'.example/exact',tokenURL:'https://'+profileId+'.example/token',...(profileId==='cognito'?{loginDomainURL:'https://managed.example/prefix'}:{})}},options);
    assert.equal(environment.apply(options).ok,true);
    environment.updateDraft({provider:{issuerURL:'https://unapplied.example',tokenURL:'https://unapplied.example/token'}},options);
    const rows=environment.participantContext('realmB',options);
    assert.ok(!rows.some(row=>row.value.includes('unapplied.example')));
    assert.ok(!rows.some(row=>row.key==='realm'||row.key==='keycloakBaseURL'||/secret|password/i.test(row.key)));
    assert.equal(rows[0].value,profile.protocol==='saml'?'urn:corp:'+profileId:'https://'+profileId+'.example/exact');
    if(profileId==='cognito'){
      assert.equal(rows.find(row=>row.key==='authorizationURL').value,'https://managed.example/prefix/oauth2/authorize');
      assert.equal(rows.find(row=>row.key==='jwksURL').value,profile.examples.jwksUri);
      assert.equal(rows.find(row=>row.key==='tokenURL').value,'https://cognito.example/token');
    }
    const realmA=environment.participantContext('realmA',options);
    assert.equal(realmA.find(row=>row.key==='brokerCallbackURL').value,'https://sso.example/auth/realms/employees/broker/custom%20%2F%20provider/endpoint');
  }
  const second=environment.participantContext('realmB',{upstream:'keycloak',brokerProtocol:'oidc'});
  assert.equal(second.find(row=>row.key==='issuerURL').value,'https://second.example/kc/realms/partners');
  environment.updateDraft({aIssuerURL:'https://unknown.example/exact'});assert.equal(environment.apply({activeFields:['aIssuerURL']}).ok,true);
  const exact=applied({aIssuerURL:'HTTPS://Issuer.Example/custom/exact'}).participantContext('realmA',{upstream:'single'});
  assert.deepEqual(exact.map(row=>[row.key,row.value]),[['issuerURL','HTTPS://Issuer.Example/custom/exact']]);
});

test('provider profiles use explicit endpoint and metadata overrides, including branded broker callbacks',()=>{
  for(const profileId of ['entra','okta','cognito','aws-identity-center']){
    const profile=getProviderProfile(profileId),environment=applied({keycloakABaseURL:'https://sso.example/auth',realmA:'company',provider:{issuerURL:profile.protocol==='oidc'?'https://upstream.example/exact':'',authorizationURL:'https://upstream.example/authorize',tokenURL:'https://upstream.example/token',jwksURL:'https://upstream.example/keys',samlEntityID:'urn:corp:external:idp',ssoURL:'https://upstream.example/sso'}},{profileId});
    const options={profileId,providerProfile:profile};
    if(profile.protocol==='oidc'){
      assert.equal(environment.projectValue(profile.examples.authorizationEndpoint,options),'https://upstream.example/authorize');
      assert.equal(environment.projectValue(profile.examples.tokenEndpoint,options),'https://upstream.example/token');
      assert.equal(environment.projectValue(profile.examples.jwksUri,options),'https://upstream.example/keys');
    }else{
      assert.equal(environment.projectValue(profile.examples.entityID,options),'urn:corp:external:idp');
      assert.equal(environment.projectValue(profile.examples.ssoUrl,options),'https://upstream.example/sso');
    }
    assert.equal(environment.projectValue(issuerA+'/broker/'+profileId+'/endpoint',options),'https://sso.example/auth/realms/company/broker/'+profileId+'/endpoint');
  }
});

test('runtime adaptation follows provider adaptation and retains its authentication boundary and wire fields',()=>{
  for(const profileId of ['entra','okta','cognito','aws-identity-center']){
    const profile=getProviderProfile(profileId),config={mode:'password',architecture:'web',upstream:'external',applicationProtocol:'oidc',brokerProtocol:profile.protocol};
    const original=profile.protocol==='saml'?getSamlSteps(config):getJourneySteps('password','web','external');
    const adapted=applyProviderProfile(original,{...ACTORS,...getActorOverrides('web','external')},profileId,config);
    const environment=applied({keycloakABaseURL:'https://sso.example/auth',realmA:'employees',provider:{issuerURL:profile.protocol==='oidc'?'https://partner.example/exact':'',samlEntityID:'urn:company:external:saml',ssoURL:'https://partner.example/sso',authorizationURL:'https://partner.example/authorize',tokenURL:'https://partner.example/token',jwksURL:'https://partner.example/keys'}},{profileId});
    const options={profileId,providerProfile:profile,upstream:'external'},steps=environment.projectSteps(adapted.steps,options);
    assert.deepEqual(topology(steps),topology(adapted.steps),profileId);
    assert.ok(steps.some(step=>step.providerManaged),profileId+' managed boundary');
    const exampleOverrides=environment.projectExamples(adapted.exampleOverrides,options);
    if(profile.protocol==='oidc'){
      assert.equal(exampleOverrides.issuerB,'https://partner.example/exact');
      assert.equal(exampleOverrides.redirectBroker,'https://sso.example/auth/realms/employees/broker/'+profileId+'/endpoint');
      const verify=steps.find(step=>step.id.endsWith('-l19'));
      assert.equal(verify.attributeValues.jwksUri,'https://partner.example/keys');
      assert.equal(verify.attributeValues.issuerB,'https://partner.example/exact');
      assert.equal(exampleOverrides.clientIdBroker,profile.examples.clientIdBroker);
    }else{
      assert.equal(exampleOverrides.samlIdpEntityB,'urn:company:external:saml');
      assert.equal(exampleOverrides.samlSsoB,'https://partner.example/sso');
      assert.equal(exampleOverrides.samlAcsBroker,'https://sso.example/auth/realms/employees/broker/'+profileId+'/endpoint');
    }
  }
});

test('core broker traces keep Realm A and upstream issuer/JWKS ownership separate',()=>{
  const original=getJourneySteps('password','web','keycloak');
  const environment=applied({keycloakABaseURL:'https://sso.example/kc',realmA:'employees',keycloakBBaseURL:'https://partner.example/kc',realmB:'partners'});
  const steps=environment.projectSteps(original);
  const upstream=steps.find(step=>step.id.endsWith('-l19')),app=steps.find(step=>step.id.endsWith('-l25'));
  assert.equal(upstream.attributeValues.jwksUri,'https://partner.example/kc/realms/partners/protocol/openid-connect/certs');
  assert.equal(app.attributeValues.jwksUri,'https://sso.example/kc/realms/employees/protocol/openid-connect/certs');
  const usage=[{step:upstream,index:0,actions:[{attributeId:'jwksUri',kind:'use',actorId:'realmA',detail:'Uses upstream keys'}]}];
  assert.equal(buildAttributeTrace(usage)[0].payload[0].value,upstream.attributeValues.jwksUri);
  assert.deepEqual(topology(steps),topology(original));
});

test('client_id projection updates app identity and nested claims without changing API audiences or credentials',()=>{
  const environment=applied({clientID:'corp-portal'});
  assert.equal(environment.projectValue('JWT: iss=A, aud=web-app, sub=user'),'JWT: iss=A, aud=corp-portal, sub=user');
  assert.equal(environment.projectValue('Basic base64(encoded-web-app:encoded-backend-secret)'),'Basic base64(encoded-corp-portal:encoded-backend-secret)');
  assert.equal(environment.projectValue('orders-api',{attributeId:'serviceAccessAudience'}),'orders-api');
  assert.equal(environment.projectValue('web-app',{attributeId:'clientSecretApp'}),'web-app');
  const projected=environment.projectSteps([{id:'secret-example',from:'app',to:'realmA',fields:['clientSecretApp'],payload:[{name:'client_secret',value:'web-app https://app.example.test'}]}]);
  assert.equal(projected[0].payload[0].value,'web-app https://app.example.test');
  const defs=environment.projectDefinition('clientIdApp',ATTRIBUTES.clientIdApp);
  assert.equal(defs.example,'corp-portal');assert.equal(defs.name,'client_id');assert.equal(defs.source,ATTRIBUTES.clientIdApp.source);
});

test('custom identifiers use the existing carrier encoding, while primitive attribute values stay raw',()=>{
  const environment=applied({clientID:'portal & reports',acsURL:'https://portal.example/acs?tenant=one&team=two',appEntityID:'urn:corp:portal&reports'});
  const url=issuerA+'/protocol/openid-connect/auth?client_id=learning-client&response_type=code';
  assert.equal(environment.projectValue(url),issuerA+'/protocol/openid-connect/auth?client_id=portal%20%26%20reports&response_type=code');
  assert.equal(environment.projectValue('learning-client',{attributeId:'branchClientId'}),'portal & reports');
  const xml='<samlp:AuthnRequest AssertionConsumerServiceURL="https://app.example.test/saml/acs"><saml:Issuer>urn:example:app:sp</saml:Issuer></samlp:AuthnRequest>';
  assert.equal(environment.projectValue(xml),'<samlp:AuthnRequest AssertionConsumerServiceURL="https://portal.example/acs?tenant=one&amp;team=two"><saml:Issuer>urn:corp:portal&amp;reports</saml:Issuer></samlp:AuthnRequest>');
  assert.equal(environment.projectValue('urn:example:app:sp'),'urn:corp:portal&reports');
});

test('known symbolic ID-token issuer labels become owner-specific addresses without altering other token material',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.example/auth',realmA:'employees',keycloakBBaseURL:'https://upstream.example/auth',realmB:'partners',clientID:'portal'});
  assert.equal(environment.projectValue('JWT: iss=A, aud=web-app, sub=user-A',{attributeId:'idTokenA'}),'JWT: iss=https://sso.example/auth/realms/employees, aud=portal, sub=user-A');
  assert.equal(environment.projectValue('JWT: iss=B, aud=realm-a-broker, sub=user-B',{attributeId:'idTokenB'}),'JWT: iss=https://upstream.example/auth/realms/partners, aud=realm-a-broker, sub=user-B');
  assert.equal(environment.projectValue('JWT: iss=A, aud=orders-api',{attributeId:'accessTokenA'}),'JWT: iss=A, aud=orders-api');
});

test('SAML entity overrides preserve different message issuers and recipient addresses',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.example',realmA:'employees',aEntityID:'urn:corp:keycloak:idp',appEntityID:'urn:corp:portal:sp',acsURL:'https://portal.example/acs',aSsoURL:'https://sso.example/company/saml'});
  const original=getSamlSteps({mode:'password',architecture:'web',upstream:'single',applicationProtocol:'saml',brokerProtocol:'oidc'});
  const steps=environment.projectSteps(original);
  const samlStages=steps.filter(step=>step.attributeValues?.samlIdpEntityA);
  assert.ok(samlStages.length>0);
  for(const step of samlStages){
    assert.equal(step.attributeValues.samlIdpEntityA,'urn:corp:keycloak:idp');
    assert.equal(step.attributeValues.samlSpEntityApp,'urn:corp:portal:sp');
    assert.equal(step.attributeValues.samlAudienceApp,'urn:corp:portal:sp');
    assert.equal(step.attributeValues.samlAcsApp,'https://portal.example/acs');
    assert.equal(step.attributeValues.samlSsoA,'https://sso.example/company/saml');
  }
  const response=steps.find(step=>step.payload.some(item=>item.name==='Issuer'));
  assert.equal(response.payload.find(item=>item.name==='Issuer').value,'urn:corp:keycloak:idp');
  const request=steps.find(step=>step.payload.some(item=>item.name==='AuthnRequest'));
  assert.ok(request.payload.find(item=>item.name==='AuthnRequest').value.includes('<saml:Issuer>urn:corp:portal:sp</saml:Issuer>'));
  assert.equal(environment.projectDefinition('samlIdpEntityA',SAML_ATTRIBUTES.samlIdpEntityA).example,'urn:corp:keycloak:idp');
  assert.deepEqual(topology(steps),topology(original));
});

test('direct WebAuthn personalization keeps origin and RP-ID examples coherent with the application',()=>{
  const environment=applied({appURL:'https://portal.example/company'});
  const examples=environment.projectExamples(getFidoExampleOverrides());
  assert.equal(examples.origin,'https://portal.example');assert.equal(examples.rpId,'portal.example');
  assert.equal(examples.rpIdHash,'SHA256("portal.example")');
  assert.ok(examples.clientDataJSON.includes('https://portal.example'));
  const original=getFidoSteps('fido-login','yubikey'),steps=environment.projectSteps(original);
  assert.ok(displayStrings(steps).some(value=>value.includes('https://portal.example/company/webauthn/assertion')));
  assert.ok(!displayStrings(steps).some(value=>value.includes('app.example.test')));
  assert.deepEqual(topology(steps),topology(original));
  const actor=environment.projectActor({...ACTORS.app,...getFidoActorOverrides('fido-login','yubikey').app});
  assert.ok(!actor.notes.some(value=>value.includes('app.example.test')));
});

test('all 43 extended models keep topology/operation keys and original objects while projecting Realm A addresses',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.example/context',realmA:'company',appURL:'https://portal.example/company'});
  assert.equal(LAB_SCENARIOS.length,43);
  for(const model of LAB_SCENARIOS){
    const original=model.steps({}),before=JSON.stringify(original),steps=environment.projectSteps(original);
    assert.deepEqual(topology(steps),topology(original),model.id);
    assert.equal(JSON.stringify(original),before,model.id+' original mutation');
    assert.ok(Object.isFrozen(steps)&&Object.isFrozen(steps[0])&&Object.isFrozen(steps[0].fields),model.id+' immutable snapshot');
    for(const value of displayStrings(steps))assert.ok(!value.includes(issuerA),model.id+' left old Realm A URL: '+value);
    const examples=environment.projectExamples(model.examples());
    for(const [id,value]of Object.entries(examples))if(typeof value==='string'&&!/private|secret|password/i.test(id))assert.ok(!value.includes(issuerA),model.id+' example '+id);
    for(const [id,actor]of Object.entries(model.actors({})))assert.equal(environment.projectActor(actor).id,id);
  }
});

test('every core journey remains structurally unchanged and projection does not freeze its mutable source',()=>{
  const environment=applied({keycloakABaseURL:'https://sso.example',realmA:'employees',keycloakBBaseURL:'https://partner.example',realmB:'partners',appURL:'https://portal.example'});
  for(const mode of Object.keys(JOURNEYS)){
    const original=getJourneySteps(mode,'web','keycloak'),before=JSON.stringify(original),steps=environment.projectSteps(original);
    assert.deepEqual(topology(steps),topology(original),mode);assert.equal(JSON.stringify(original),before,mode);
    for(const value of displayStrings(steps))assert.ok(!value.includes(issuerA)&&!value.includes(issuerB),mode+' address');
  }
  const source=[{id:'original',from:'app',to:'app',fields:['example'],payload:[{name:'URL',value:issuerA}],checks:[]}];
  environment.projectSteps(source);assert.equal(Object.isFrozen(source[0]),false);assert.equal(Object.isFrozen(source[0].fields),false);
});
