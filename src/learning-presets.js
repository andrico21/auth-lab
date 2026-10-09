import { ATTRIBUTES } from './protocol-data.js';
import { SAML_ATTRIBUTES } from './saml-data.js';
import { getStepAttributeOperations } from './attribute-usage.js';
import { getJweAttributeOverrides } from './jwe-data.js';

// Presets describe teaching choices, not deployed-server configuration. Provider
// examples are symbolic; this module never fetches discovery or stores input.
const presetFreeze = value => {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(presetFreeze);
    Object.freeze(value);
  }
  return value;
};
const presetDefaults = {
  mode:'password', architecture:'web', upstream:'single', authenticator:'hello',
  applicationProtocol:'oidc', brokerProtocol:'oidc', samlBinding:'redirect',
  samlInitiation:'sp', tokenProtection:'signed', assertionProtection:'signed',
  oidcFlow:'authorization-code', providerProfileId:'generic', providerManaged:false,
};
const presetEntry = (id,title,summary,common,config={},extra={}) => ({
  id,title,summary,common,category:common?'Common sign-in':'Applications and services',
  modelId:id,config:{...presetDefaults,...config},...extra,
});

export const LEARNING_PRESETS = presetFreeze([
  presetEntry('basic-keycloak','Basic Keycloak sign-in','One realm · password · web application · Code + PKCE',true),
  presetEntry('web-mfa','Web sign-in with MFA','One realm · password + TOTP · both checks at Keycloak',true,{mode:'password-totp'}),
  presetEntry('web-passkey','Passwordless web sign-in','One realm · passkey · Windows Hello · local user verification',true,{mode:'passkey'}),
  presetEntry('basic-saml','Basic SAML sign-in','One realm · password · signed Redirect request → POST response',true,{applicationProtocol:'saml'}),
  presetEntry('corporate-external','Corporate sign-in through an external IdP','Web app → Keycloak broker → your corporate identity provider',true,{upstream:'external',providerManaged:true},{providerSelectable:true}),
  presetEntry('two-realms','Sign-in across two Keycloak realms','Realm A brokers to realm B · password + TOTP checked at B',true,{upstream:'keycloak',mode:'password-totp'}),
  presetEntry('desktop-sign-in','Desktop app sign-in','Public native client · system browser · loopback callback · Code + PKCE',false,{architecture:'native'}),
  presetEntry('lab-spa-api','Browser app calling an API','Public browser client · Code + PKCE · separate access token for the API',false,{}, {extended:true}),
  presetEntry('lab-bff-api','Web frontend with a secure backend','Browser session cookie · tokens held by the BFF · backend calls the API',false,{}, {extended:true}),
  presetEntry('service-to-service','Service-to-service access','Service account · client_credentials · no person or MFA',false,{oidcFlow:'client-credentials'}),
  presetEntry('device-sign-in','Sign-in from a CLI or limited-input device','Separate browser · password + TOTP · device approval and polling',false,{architecture:'native',mode:'password-totp',oidcFlow:'device'}),
  presetEntry('backend-token-exchange','Backend access to another API','Existing same-realm access token · Standard V2 exchange · explicit downscoping',false,{oidcFlow:'token-exchange'}),
]);

const presetEntraTenant='00000000-0000-4000-8000-000000000001';
const presetEntraBase='https://login.microsoftonline.com/'+presetEntraTenant;
const presetOktaBase='https://company.okta.example.test';
const presetCognitoIssuer='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE';
const presetCognitoLogin='https://company.auth.us-east-1.amazoncognito.com';
export const PROVIDER_PROFILES = presetFreeze([
  {id:'generic',title:'Generic external IdP',protocol:'oidc',alternateProtocols:['oidc','saml'],clientAuthentication:'client_secret_basic',brokerTokenProtection:['signed','jwe'],checked:'2026-10-08',
    examples:{issuer:'https://login.partner.example.test',authorizationEndpoint:'https://login.partner.example.test/oauth2/authorize',tokenEndpoint:'https://login.partner.example.test/oauth2/token',jwksUri:'https://login.partner.example.test/oauth2/jwks',clientIdBroker:'realm-a-broker',entityID:'https://login.partner.example.test/saml/metadata',ssoUrl:'https://login.partner.example.test/saml/sso'},
    assumptions:['Endpoints and trust come from the configured provider metadata.','Provider-owned sign-in and MFA are a boundary; no vendor credential forms are assumed.'],
    sources:[{name:'OpenID Connect Discovery',url:'https://openid.net/specs/openid-connect-discovery-1_0.html'}]},
  {id:'entra',title:'Microsoft Entra ID',protocol:'oidc',clientAuthentication:'client_secret_post',brokerTokenProtection:['signed'],checked:'2026-10-08',
    examples:{tenantId:presetEntraTenant,issuer:presetEntraBase+'/v2.0',authorizationEndpoint:presetEntraBase+'/oauth2/v2.0/authorize',tokenEndpoint:presetEntraBase+'/oauth2/v2.0/token',jwksUri:presetEntraBase+'/discovery/v2.0/keys',clientIdBroker:'00000000-0000-4000-8000-000000000002'},
    assumptions:['Tenant-specific workforce OIDC v2 example; common and organizations are not accepted as the concrete token issuer.','The registered confidential broker uses client_secret_post in this teaching profile.','Entra owns authentication and Conditional Access; the animation does not infer MFA from the provider name.','This base profile uses signed upstream ID tokens. Encrypted variants require a separately documented provider configuration; Keycloak app-side JWE is independent.'],
    sources:[{name:'Microsoft identity platform OIDC',url:'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc'}]},
  {id:'okta',title:'Okta',protocol:'oidc',clientAuthentication:'client_secret_basic',brokerTokenProtection:['signed'],checked:'2026-10-08',
    examples:{issuer:presetOktaBase,authorizationEndpoint:presetOktaBase+'/oauth2/v1/authorize',tokenEndpoint:presetOktaBase+'/oauth2/v1/token',jwksUri:presetOktaBase+'/oauth2/v1/keys',clientIdBroker:'0oaExampleBrokerClient'},
    assumptions:['Org authorization server is selected for OIDC identity brokering.','Its access token is for Okta resources, not an access credential for your own API.','A custom authorization server and its policies are a separate API authorization profile.','This base profile uses signed upstream ID tokens. Encrypted variants require a separately documented provider configuration; Keycloak app-side JWE is independent.'],
    sources:[{name:'Okta authorization servers',url:'https://developer.okta.com/docs/concepts/auth-servers/'},{name:'Okta org authorization-server API',url:'https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/orgas'},{name:'Okta client authentication',url:'https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth/'}]},
  {id:'cognito',title:'Amazon Cognito user pool',protocol:'oidc',clientAuthentication:'client_secret_basic',brokerTokenProtection:['signed'],checked:'2026-10-08',
    examples:{issuer:presetCognitoIssuer,loginDomain:presetCognitoLogin,authorizationEndpoint:presetCognitoLogin+'/oauth2/authorize',tokenEndpoint:presetCognitoLogin+'/oauth2/token',jwksUri:presetCognitoIssuer+'/.well-known/jwks.json',clientIdBroker:'1example23456789'},
    assumptions:['A Cognito user pool is the OIDC provider; an identity pool is a different service role.','The example chooses the documented original issuer; updated issuer configurations must use their exact published issuer.','The managed-login domain hosts authorize/token; the user-pool issuer hosts discovery and signing keys.','Cognito ID/access tokens in this documented profile are signed three-part JWTs. Keycloak app-side JWE is a separate operation.'],
    sources:[{name:'Cognito issuer and relying-party endpoints',url:'https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html'},{name:'Cognito token endpoint',url:'https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html'},{name:'Cognito JWT verification and structure',url:'https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html'}]},
  {id:'aws-identity-center',title:'AWS IAM Identity Center',protocol:'saml',brokerTokenProtection:['signed'],checked:'2026-10-08',
    examples:{entityID:'urn:example:aws:identity-center:idp',ssoUrl:'https://aws-identity-center.example.test/saml/sso'},
    assumptions:['Customer-managed SAML application represents Keycloak as the upstream-facing SP.','Issuer/entityID, SSO URL and trusted signing certificate come from the application metadata; the examples are symbolic, not AWS endpoint templates.','Keycloak uses a separate broker ACS and SP entityID. The ready preset uses OIDC to the application; that leg can be explored independently as OIDC or SAML.'],
    sources:[{name:'IAM Identity Center customer-managed SAML applications',url:'https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-saml2-setup.html'},{name:'AWS custom SAML application integration guide',url:'https://static.global.sso.amazonaws.com/app-520727d4117d1647/instructions/index.htm'}]},
]);

export function getLearningPreset(id) {return LEARNING_PRESETS.find(preset=>preset.id===id)||null;}
export function getProviderProfile(id='generic') {return PROVIDER_PROFILES.find(profile=>profile.id===id)||null;}
export function getPresetConfiguration(id,providerId='generic') {
  const preset=getLearningPreset(id);
  if(!preset)throw new RangeError('Unknown learning preset: '+id);
  const profile=getProviderProfile(providerId);
  if(!profile)throw new RangeError('Unknown provider profile: '+providerId);
  return {...preset.config,labScenarioId:preset.modelId,providerProfileId:preset.providerSelectable?profile.id:'generic',
    ...(preset.providerSelectable?{brokerProtocol:profile.protocol,providerManaged:true}:{}),
  };
}

const presetClone=value=>JSON.parse(JSON.stringify(value));
const presetCanonical=step=>String(step.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const presetGenericValues=getProviderProfile('generic').examples;
const presetFactorPhases=new Set(['password','mfa','otp','passkey','enrollment']);
const presetUnspecifiedContext='urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
const presetFactorFields=new Set(['password','passwordHash','loginUsername','otpCode','otpSecret','otpUri','otpAlgorithm','otpDigits','otpPeriod','otpT0','otpTime','otpCounter','otpWindow','otpReplay','rpId','origin','userId','userVerification','residentKey','challengeLogin','challengeRegistration','allowCredentials','pubKeyCredParams','credentialId','credentialPublicKey','signature','clientDataJSON','clientDataHash','privateKey','authenticatorData','rpIdHash','flagsUP','flagsUV','signCount','userHandle','attestationObject','localVerification','ctapGetAssertion','ctapMakeCredential','ctapResidentKey','pinUvAuthProtocol','pinUvAuthToken','pinUvAuthParam','ctapCredential','ctapCredentialId','ctapAuthData','ctapSignature','ctapUser','ctapFmt','ctapAttStmt','transports']);
const presetOperations=(ids,kind,actorId,detail,carriedAs)=>ids.map(attributeId=>({attributeId,kind,actorId,detail,...(carriedAs?{carriedAs}:{})}));
const presetWire=(ids,from,to,detail)=>[...presetOperations(ids,'send',from,detail,'HTTPS form body'),...presetOperations(ids,'receive',to,detail,'HTTPS form body')];

function presetBoundary(profile) {
  const stage=(id,title,from,to,channel,summary,payload)=>({id:'provider-'+profile.id+'-'+id,title,from,to,phase:'broker',channel,summary,
    detail:'Authentication is owned by '+profile.title+'. Its UI, credential checks, existing sessions and required MFA depend on provider policy. This boundary does not copy Keycloak login forms, claim a particular authenticator, or assert an authentication assurance class.',
    fields:[],payload,checks:[],attributeOperations:[],providerProfileId:profile.id,providerManaged:true});
  return [
    stage('prompt','Open the corporate sign-in page','realmB','browser','https','The corporate provider presents its configured sign-in experience.',[{name:'HTTPS response',value:profile.title+' sign-in page · provider-specific UI'}]),
    stage('interaction','Complete corporate sign-in','user','browser','local','The person completes the corporate provider’s required checks.',[{name:'UI action',value:'Sign in and complete any required provider-managed MFA'}]),
    stage('authentication','Authenticate under corporate policy','realmB','realmB','internal','The provider completes authentication before issuing an identity result.',[{name:'Local process',value:'Provider-owned account verification and session policy'}]),
  ];
}

/** Pure presentation adapter. Pass an already generated EXTERNAL core journey.
 * It does not convert protocols: generate the profile's broker leg first. Set
 * providerManaged:true to collapse generic factor teaching into this boundary.
 * Branded profiles always keep their unmodeled credential ceremony opaque.
 * Output overrides are merged after the normal core/SAML definitions/actors.
 */
export function applyProviderProfile(steps,actors={},profileId='generic',config={}) {
  const profile=getProviderProfile(profileId);
  if(!profile)throw new RangeError('Unknown provider profile: '+profileId);
  if(config.upstream&&config.upstream!=='external')return {steps,actors,attributeOverrides:{},exampleOverrides:{},profile:null};
  const requestedProtection=config.tokenProtection||config.protection;
  const brokerJweRequested=requestedProtection==='broker-jwe'||requestedProtection==='both-jwe';
  const brokerJwePresent=steps.some(step=>step.jweHop==='broker'||step.jweInboundHop==='broker'||/-jwe-broker-/.test(String(step.id)));
  if((brokerJweRequested||brokerJwePresent)&&!profile.brokerTokenProtection.includes('jwe'))
    throw new RangeError(profile.title+' base profile supports signed broker identity results only in this lab. Choose Generic external IdP or a separately documented provider encryption profile for broker JWE. Keycloak app-side JWE remains independent.');
  const managed=config.providerManaged===true||profile.id!=='generic';
  const hasSamlBroker=steps.some(step=>String(step.id).startsWith('saml-broker-'));
  const brokerProtocol=hasSamlBroker?'saml':'oidc';
  if(profile.id!=='generic'&&profile.protocol!==brokerProtocol)throw new RangeError('Generate the '+profile.protocol+' broker leg before applying '+profile.title+'.');
  if(managed&&steps.some(step=>step.phase==='enrollment'))throw new RangeError('Provider-managed sign-in is not an enrollment ceremony.');
  const result=presetClone(steps),actorResult=presetClone(actors),examples=profile.examples;
  const alias=profile.id==='generic'?(hasSamlBroker?'saml-partner':'external-idp'):profile.id;
  const previousCallback='https://idp1.example.test/realms/realm-a/broker/'+(hasSamlBroker?'saml-partner':'external-idp')+'/endpoint';
  const callback='https://idp1.example.test/realms/realm-a/broker/'+alias+'/endpoint';
  const replacements=[[previousCallback,callback]];
  for(const key of ['authorizationEndpoint','tokenEndpoint','jwksUri','entityID','ssoUrl','issuer','clientIdBroker'])
    if(examples[key]&&presetGenericValues[key]&&examples[key]!==presetGenericValues[key])replacements.push([presetGenericValues[key],examples[key]]);
  replacements.sort((a,b)=>b[0].length-a[0].length);
  const replace=value=>typeof value==='string'?replacements.reduce((text,[from,to])=>text.split(from).join(to),value):value;
  const text=value=>replace(value).replaceAll('External OIDC provider',profile.title).replaceAll('External SAML IdP',profile.title);
  for(const step of result) {
    for(const key of ['title','summary','detail'])step[key]=text(step[key]||'');
    step.checks=(step.checks||[]).map(text);
    step.payload=(step.payload||[]).map(item=>({...item,value:replace(item.value),...(item.description?{description:text(item.description)}:{})}));
    step.attributeValues=Object.fromEntries(Object.entries(step.attributeValues||{}).map(([id,value])=>[id,replace(value)]));
    step.attributeOperations=getStepAttributeOperations(step,config.authenticator||'hello').map(op=>({...op,detail:text(op.detail||'')}));
    step.providerProfileId=profile.id;
    const canonical=presetCanonical(step);
    if(['l06','l07'].includes(canonical))step.attributeValues.authorizationEndpoint=examples.authorizationEndpoint;
    if(canonical==='l07'&&managed)step.detail='The provider validates the confidential broker registration, exact callback and request context. Authentication proceeds under '+profile.title+' policy; no specific credential method or MFA result is assumed.';
    if(canonical==='l17') {
      step.attributeValues.tokenEndpoint=examples.tokenEndpoint;
      step.payload=step.payload.map(item=>item.name==='HTTP'?{...item,value:'POST '+examples.tokenEndpoint}:item);
      if(profile.clientAuthentication==='client_secret_post') {
        step.fields=step.fields.filter(id=>id!=='authorizationHeader');
        for(const id of ['clientIdBroker','clientSecret'])if(!step.fields.includes(id))step.fields.push(id);
        step.payload=step.payload.filter(item=>item.name!=='Authorization');
        step.payload.push({name:'client_id',value:examples.clientIdBroker},{name:'client_secret',value:'<broker-client-secret; server-to-server only>'});
        step.detail='Keycloak posts the authorization code, identical broker redirect_uri, client_id and client_secret to the tenant-specific token endpoint over HTTPS. This teaching registration uses client_secret_post. Neither credential enters the browser; the upstream separately validates code/client/redirect binding.';
        step.attributeOperations=[...presetOperations(['tokenEndpoint'],'use','realmA','Uses the configured provider token_endpoint.'),...presetOperations(['clientIdBroker','clientSecret'],'use','realmA','Reads the confidential broker registration for client_secret_post.'),...presetWire(['grantType','codeB','redirectBroker','clientIdBroker','clientSecret'],'realmA','realmB','Direct confidential token request; no browser participant.'),...presetOperations(['codeB','redirectBroker','clientIdBroker','clientSecret'],'verify','realmB','Validates code/client/redirect binding and confidential client authentication.')];
      }
    }
    if(['l18','l19'].includes(canonical))Object.assign(step.attributeValues,{issuerB:examples.issuer,audience:examples.clientIdBroker});
    if(canonical==='l19')step.attributeValues.jwksUri=examples.jwksUri;
    if(canonical==='l18'&&profile.id==='okta')step.detail+=' The Okta org authorization-server access token is for Okta resources; it is not forwarded as an access token for the application’s API.';
    if(managed) {
      // Both SAML legs must avoid upgrading an opaque provider ceremony into a
      // fabricated password/passkey/MFA assurance statement.
      for(const id of ['samlAuthnContextBroker','samlAuthnContextApp'])if(id in step.attributeValues)step.attributeValues[id]=presetUnspecifiedContext;
      step.payload=step.payload.map(item=>['AuthnContextClassRef','Accepted context'].includes(item.name)?{...item,value:presetUnspecifiedContext}:item);
    }
  }
  let projected=result;
  if(managed) {
    const first=result.findIndex(step=>presetFactorPhases.has(step.phase));
    const factorSteps=result.filter(step=>presetFactorPhases.has(step.phase));
    if(first>=0)projected=[...result.slice(0,first),...presetBoundary(profile),...result.slice(first).filter(step=>!factorSteps.includes(step))];
  }
  for(const actor of Object.values(actorResult)) {
    actor.notes=(actor.notes||[]).map(text);
    if(managed)actor.attributes=(actor.attributes||[]).filter(item=>!presetFactorFields.has(item.id));
  }
  if(actorResult.realmA) {
    actorResult.realmA.notes=actorResult.realmA.notes.map(note=>note.replaceAll(hasSamlBroker?'saml-partner':'external-idp',alias));
    actorResult.realmA.notes.push(brokerProtocol==='saml'?'The upstream-facing SAML SP registration has its own entityID and broker ACS.':'The upstream-facing client uses '+profile.clientAuthentication+'; its callback and client ID differ from the application’s registration.');
    if(profile.clientAuthentication==='client_secret_post')actorResult.realmA.attributes=(actorResult.realmA.attributes||[]).filter(item=>item.id!=='authorizationHeader');
  }
  actorResult.realmB={...(actorResult.realmB||{}),name:profile.title,art:'external',role:brokerProtocol==='saml'?'Corporate SAML identity provider':'Corporate OpenID Provider',
    plainRole:'Owns corporate sign-in and returns a trusted identity result to Keycloak.',
    attributes:managed?(brokerProtocol==='saml'?[
      {id:'samlIdpEntityB',kind:'static'},{id:'samlSsoB',kind:'static'},{id:'samlSigningKeyB',kind:'static'},
      {id:'samlSpEntityBroker',kind:'static'},{id:'samlAcsBroker',kind:'static'},{id:'samlRequestIdBroker',kind:'received'},
      {id:'samlNameIdBroker',kind:'generated'},{id:'samlAssertion',kind:'generated'},{id:'samlResponse',kind:'generated'},
    ]:[{id:'issuerB',kind:'static'},{id:'realmSigningKey',kind:'static'},{id:'clientIdBroker',kind:'static'},
      {id:'subjectB',kind:'static'},{id:'codeB',kind:'generated'},{id:'idTokenB',kind:'generated'},{id:'accessTokenB',kind:'generated'}]):(actorResult.realmB?.attributes||[]),
    notes:[...profile.assumptions,'Keycloak validates the identity result and applies its own account-linking policy.','Provider branding alone does not establish MFA or a particular assurance level.']};
  if(managed&&actorResult.browser)actorResult.browser.notes=['Displays the web application and corporate provider pages.','Follows both independently correlated protocol legs.','Credential UI and MFA remain under the corporate provider’s policy; its credentials are not the application’s identity token.'];
  // Provider metadata describes the identity inside a protected token; it must
  // not replace that token's five-part outer representation with signed claims.
  const protectedBrokerToken=brokerJwePresent?getJweAttributeOverrides({protection:'broker-jwe',steps:projected}).idTokenB:null;
  const exampleOverrides=brokerProtocol==='saml'?{samlIdpEntityB:examples.entityID,samlSsoB:examples.ssoUrl,samlAcsBroker:callback,samlRecipientBroker:callback,...(managed?{samlAuthnContextBroker:presetUnspecifiedContext,samlAuthnContextApp:presetUnspecifiedContext}:{})}:{issuerB:examples.issuer,clientIdBroker:examples.clientIdBroker,redirectBroker:callback,idTokenB:protectedBrokerToken?.example||'JWT: iss='+examples.issuer+', aud='+examples.clientIdBroker+', sub=external-user-913, nonce=n_broker_f19d'};
  if(managed&&result.some(step=>(step.fields||[]).some(id=>id==='samlAuthnContextApp'||id==='samlAuthnContextBroker')))
    Object.assign(exampleOverrides,{samlAuthnContextApp:presetUnspecifiedContext,samlAuthnContextBroker:presetUnspecifiedContext});
  const attributeOverrides={};
  for(const [id,example]of Object.entries(exampleOverrides)) {
    const base=(id==='idTokenB'&&protectedBrokerToken)||ATTRIBUTES[id]||SAML_ATTRIBUTES[id];
    if(base)attributeOverrides[id]={...base,example};
  }
  if(protectedBrokerToken)Object.assign(attributeOverrides.idTokenB,{
    origin:profile.title+' signs its identity JWT, then encrypts it for Realm A\u2019s OIDC broker using the registered recipient encryption public key and a fresh CEK. The signed inner token identifies issuer '+examples.issuer+' and broker client '+examples.clientIdBroker+'.',
    generator:profile.title,
    purpose:protectedBrokerToken.purpose+' After decryption, the expected issuer is '+examples.issuer+' and the intended broker audience is '+examples.clientIdBroker+'.',
  });
  if(profile.clientAuthentication==='client_secret_post')attributeOverrides.clientSecret={...ATTRIBUTES.clientSecret,
    meaning:'The confidential broker client credential registered at '+profile.title+'.',description:'The confidential broker client credential registered at '+profile.title+'.',
    origin:'Provisioned for the upstream-facing broker client and retained on the Keycloak backend.',generator:'Provisioned for the upstream-facing broker client and retained on the Keycloak backend.',
    purpose:'Authenticates the broker’s direct token request using client_secret_post: client_id and client_secret are in the HTTPS form body. Neither enters the browser.',
    standard:'OIDC client_secret_post / RFC 6749 §2.3.1',source:'https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication'};
  return {steps:projected,actors:actorResult,attributeOverrides,exampleOverrides,profile};
}
