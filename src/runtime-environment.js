// Page-owned example context. This module has no browser persistence, logging,
// discovery, navigation or network code. Source protocol models stay immutable.
// Addresses are adapted only through declared symbolic entities and endpoints.

const runtimeField = (key, label, kind = 'url', extra = {}) => Object.freeze({key,label,kind,...extra});
export const RUNTIME_ENVIRONMENT_FIELDS = Object.freeze([
  runtimeField('appURL','Application URL'),
  runtimeField('keycloakABaseURL','Keycloak A deployment URL'),runtimeField('realmA','Realm A name','segment'),
  runtimeField('keycloakBBaseURL','Keycloak B deployment URL'),runtimeField('realmB','Realm B name','segment'),
  runtimeField('clientID','Application client_id','identifier',{advanced:true}),
  runtimeField('appCallbackURL','Application redirect_uri','callback',{advanced:true}),
  runtimeField('acsURL','Application SAML ACS URL','url',{advanced:true}),
  runtimeField('appEntityID','Application SAML entityID','uri',{advanced:true}),
  runtimeField('brokerAlias','Keycloak broker alias','segment',{advanced:true}),
  ...['a','b'].flatMap(prefix=>[
    runtimeField(prefix+'IssuerURL',`Exact ${prefix.toUpperCase()} OIDC issuer`,'issuer',{advanced:true}),
    runtimeField(prefix+'AuthorizationURL',`${prefix.toUpperCase()} authorization_endpoint`,'url',{advanced:true}),
    runtimeField(prefix+'TokenURL',`${prefix.toUpperCase()} token_endpoint`,'url',{advanced:true}),
    runtimeField(prefix+'JwksURL',`${prefix.toUpperCase()} jwks_uri`,'url',{advanced:true}),
    runtimeField(prefix+'SsoURL',`${prefix.toUpperCase()} SAML SSO URL`,'url',{advanced:true}),
    runtimeField(prefix+'EntityID',`${prefix.toUpperCase()} SAML entityID`,'uri',{advanced:true}),
  ]),
]);
export const RUNTIME_PROVIDER_FIELDS = Object.freeze([
  runtimeField('issuerURL','External OIDC issuer','issuer'),
  runtimeField('authorizationURL','External authorization_endpoint','url',{advanced:true}),
  runtimeField('tokenURL','External token_endpoint','url',{advanced:true}),
  runtimeField('jwksURL','External jwks_uri','url',{advanced:true}),
  runtimeField('loginDomainURL','External managed-login base URL','url',{advanced:true}),
  runtimeField('samlEntityID','External SAML entityID','uri'),
  runtimeField('ssoURL','External SAML SSO URL','url'),
]);

const runtimeCommonKeys = new Set(RUNTIME_ENVIRONMENT_FIELDS.map(field=>field.key));
const runtimeProviderKeys = new Set(RUNTIME_PROVIDER_FIELDS.map(field=>field.key));
const runtimeEmpty = () => ({...Object.fromEntries([...runtimeCommonKeys].map(key=>[key,''])),providers:{}});
const runtimeClone = value => Array.isArray(value)?value.map(runtimeClone):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,runtimeClone(item)])):value;
const runtimeFreeze = value => {
  if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(runtimeFreeze);Object.freeze(value);}return value;
};
const runtimeProfileKey = options => {const key=typeof options==='string'?options:String(options?.profileId||options?.providerProfile?.id||'generic');return ['__proto__','constructor','prototype'].includes(key)?'generic':key;};
const runtimeText = value => typeof value==='string'?value.trim():value==null?'':String(value).trim();
const runtimeHasControl = value => /[\u0000-\u001f\u007f]/.test(value);
const runtimeIsLoopback = hostname => hostname==='localhost'||hostname==='127.0.0.1'||hostname==='[::1]';
const runtimeParsedURL = value => {try{return new URL(value);}catch{return null;}};
const runtimeDecodeSegment = value => {try{return decodeURIComponent(value);}catch{return value;}};
// Execution is independent of graph layout and public/confidential client type.
// Older callers without explicit metadata retain their architecture default.
const runtimeExecutionEnvironment = options => options.directFido?'browser':options.executionEnvironment||(options.architecture==='native'?'native':'server');
const runtimeApplicableAppURL = (value,options) => {
  const parsed=runtimeParsedURL(value);
  return parsed&&(parsed.protocol==='https:'||parsed.protocol==='http:'&&runtimeExecutionEnvironment(options)==='native'&&runtimeIsLoopback(parsed.hostname))?value:'';
};
function runtimeValidateField(field,value,options) {
  if(!value)return '';
  if(runtimeHasControl(value))return 'Use a value without control characters.';
  if(field.kind==='segment')return value==='.'||value==='..'?'Use a named path segment.':'';
  if(field.kind==='identifier')return '';
  let parsed;
  try{parsed=new URL(value);}catch{return field.kind==='uri'?'Use an absolute URI, such as https://… or urn:….':'Use a complete HTTPS URL.';}
  if(field.kind==='uri')return parsed.protocol==='javascript:'||parsed.protocol==='data:'?'Use an identifier URI such as https://… or urn:….':'';
  if(parsed.username||parsed.password)return 'Use an address without embedded credentials.';
  const nativeLoopback=(field.kind==='callback'||field.key==='appURL')&&runtimeExecutionEnvironment(options)==='native'&&parsed.protocol==='http:'&&runtimeIsLoopback(parsed.hostname);
  if(parsed.protocol!=='https:'&&!nativeLoopback)return 'Use HTTPS; native callbacks may use HTTP on localhost.';
  if(parsed.hash)return 'Use an address without a fragment.';
  if((field.kind==='issuer'||/BaseURL$/.test(field.key))&&parsed.search)return 'Use an issuer or deployment address without a query.';
  return '';
}

const runtimeA = 'https://idp1.example.test/realms/realm-a';
const runtimeB = 'https://idp2.example.test/realms/realm-b';
const runtimeGenericProvider = Object.freeze({id:'generic',protocol:'oidc',examples:{
  issuer:'https://login.partner.example.test',authorizationEndpoint:'https://login.partner.example.test/oauth2/authorize',
  tokenEndpoint:'https://login.partner.example.test/oauth2/token',jwksUri:'https://login.partner.example.test/oauth2/jwks',
  entityID:'https://login.partner.example.test/saml/metadata',ssoUrl:'https://login.partner.example.test/saml/sso',
}});
const runtimeKcPaths = Object.freeze([
  'protocol/openid-connect/auth','protocol/openid-connect/token','protocol/openid-connect/certs',
  'protocol/openid-connect/userinfo','protocol/openid-connect/logout','protocol/openid-connect/revoke',
  'protocol/openid-connect/token/introspect','protocol/openid-connect/introspect',
  'protocol/openid-connect/auth/device','protocol/openid-connect/ext/ciba/auth',
  'protocol/openid-connect/ext/par/request','protocol/saml','protocol/saml/resolve',
  'protocol/saml/descriptor','protocol/saml/clients/app-saml',
]);
const runtimeAppPaths = Object.freeze([
  '/login','/oidc/callback','/oauth/callback','/callback','/signed-out',
  '/oidc/backchannel-logout','/oidc/frontchannel-logout','/api/orders','/ciba/notify',
  '/saml','/saml/acs','/saml/login','/saml/slo','/saml/metadata',
  '/webauthn/assertion','/webauthn/login-options','/webauthn/registration','/webauthn/registration-options',
]);
const runtimeAppOrigins = Object.freeze(['https://app.example.test','https://spa.example.test','https://learning.example.test']);
const runtimeAppClientSources = Object.freeze(['desktop-app','web-app','spa-public','bff-web','lifecycle-client','protected-web-app','learning-client','ciba-lab-client','orders-service','device-client','device-confidential','ciba-client','requester-client','exchange-client','actor-app']);
const runtimeAppClientIds = new Set(['clientIdApp','webClientId','lifeClientId','protClientId','branchClientId','exchangeClientId','grantCibaPingClient','grantCibaPushClient','grantCibaHintTokenClient']);
const runtimeAppAudienceIds = new Set(['webIdAudience','lifeIdAudience','branchAudience']);
const runtimeSensitive = id => /(?:secret|password|private|verifier|pinUvAuthToken|otpSecret|credentialPublicKey|signingKey|decryptKey)/i.test(id||'');
const runtimeEscapeRegExp = value => value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const runtimeXmlText = value => value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
const runtimeAppend = (base,path) => base.split(/[?#]/,1)[0].replace(/\/+$/,'')+'/'+path.replace(/^\/+/, '');

function runtimeResolve(context,options={}) {
  const profileId=runtimeProfileKey(options),profile=options.providerProfile||runtimeGenericProvider;
  const external=context.providers?.[profileId]||{};
  const aChanged=!!(context.keycloakABaseURL||context.realmA||context.aIssuerURL);
  const bChanged=!!(context.keycloakBBaseURL||context.realmB||context.bIssuerURL);
  const aIssuer=context.aIssuerURL||(aChanged?runtimeAppend(context.keycloakABaseURL||'https://idp1.example.test','realms/'+encodeURIComponent(context.realmA||'realm-a')):runtimeA);
  const bIssuer=context.bIssuerURL||(bChanged?runtimeAppend(context.keycloakBBaseURL||'https://idp2.example.test','realms/'+encodeURIComponent(context.realmB||'realm-b')):runtimeB);
  const map=new Map(),hosts=new Map();
  const add=(source,target)=>{if(typeof source==='string'&&typeof target==='string'&&source!==target&&source&&target)map.set(source,target);};
  const host=(source,target)=>{if(target){try{hosts.set(source,new URL(target).hostname);}catch{/* already validated context */}}};
  for(const [old,issuer,prefix,changed] of [[runtimeA,aIssuer,'a',aChanged],[runtimeB,bIssuer,'b',bChanged]]){
    if(changed)add(old,issuer);
    for(const path of runtimeKcPaths){
      const exact=path==='protocol/openid-connect/auth'?context[prefix+'AuthorizationURL']:path==='protocol/openid-connect/token'?context[prefix+'TokenURL']:path==='protocol/openid-connect/certs'?context[prefix+'JwksURL']:path==='protocol/saml'?context[prefix+'SsoURL']:'';
      if(changed||exact)add(old+'/'+path,exact||runtimeAppend(issuer,path));
    }
    if(changed){const oldOrigin=new URL(old).origin;add(oldOrigin,new URL(issuer).origin);host(new URL(old).hostname,issuer);}
  }
  const aEntity=context.aEntityID||aIssuer,bEntity=context.bEntityID||bIssuer;
  if(aChanged||context.brokerAlias){for(const alias of new Set(['realm-b','external-idp','saml-partner',...(profile.id&&profile.id!=='generic'?[profile.id]:[])]))add(runtimeA+'/broker/'+alias+'/endpoint',runtimeAppend(aIssuer,'broker/'+encodeURIComponent(context.brokerAlias||alias)+'/endpoint'));}
  const appURL=runtimeApplicableAppURL(context.appURL,options);
  const callbackURL=runtimeApplicableAppURL(context.appCallbackURL,options);
  if(appURL){
    const appOrigin=new URL(appURL).origin;
    for(const old of runtimeAppOrigins){
      add(old,appOrigin);host(new URL(old).hostname,appURL);
      for(const path of runtimeAppPaths)add(old+path,runtimeAppend(appURL,path));
    }
  }
  for(const old of runtimeAppOrigins){
    for(const path of ['/callback','/oidc/callback','/oauth/callback'])if(callbackURL)add(old+path,callbackURL);
    if(context.acsURL)add(old+'/saml/acs',context.acsURL);
    if(context.appEntityID)add(old+'/saml',context.appEntityID);
  }
  if(callbackURL)add('http://127.0.0.1:54321/callback',callbackURL);
  if(context.appEntityID)add('urn:example:app:sp',context.appEntityID);
  const ex=profile.examples||{};
  for(const [exampleKey,field]of [['issuer','issuerURL'],['authorizationEndpoint','authorizationURL'],['tokenEndpoint','tokenURL'],['jwksUri','jwksURL'],['entityID','samlEntityID'],['ssoUrl','ssoURL'],['loginDomain','loginDomainURL']])add(ex[exampleKey],external[field]);
  // This declared Cognito profile documents managed-login routes separately
  // from its user-pool issuer/JWKS. It is not a generic issuer-prefix rule.
  if(profile.id==='cognito'&&external.loginDomainURL){
    add(ex.authorizationEndpoint,external.authorizationURL||runtimeAppend(external.loginDomainURL,'oauth2/authorize'));
    add(ex.tokenEndpoint,external.tokenURL||runtimeAppend(external.loginDomainURL,'oauth2/token'));
  }
  // Non-branded LAB upstream examples are declared separately from Realm B.
  if(external.issuerURL){
    for(const old of ['https://login.partner.example.test','https://partner.example.test'])add(old,external.issuerURL);
    for(const old of ['login.partner.example.test','partner.example.test'])host(old,external.issuerURL);
    if(ex.issuer)host(new URL(ex.issuer).hostname,external.issuerURL);
  }
  if(external.authorizationURL)add(runtimeGenericProvider.examples.authorizationEndpoint,external.authorizationURL);
  if(external.tokenURL)add(runtimeGenericProvider.examples.tokenEndpoint,external.tokenURL);
  if(external.jwksURL)add(runtimeGenericProvider.examples.jwksUri,external.jwksURL);
  if(external.samlEntityID)add(runtimeGenericProvider.examples.entityID,external.samlEntityID);
  if(external.ssoURL)add(runtimeGenericProvider.examples.ssoUrl,external.ssoURL);
  for(const binding of options.bindings||[]){
    const target=binding.value??(binding.owner==='external'?external[binding.field]:context[binding.field]);
    add(binding.source,target);
  }
  return {context,options,profileId,profile,external,map,hosts,aIssuer,bIssuer,aEntity,bEntity,appURL,callbackURL,patternCache:new Map()};
}

// Replace a complete declared URI or a declared URI followed only by a query /
// fragment. Longer endpoint tokens cannot be rewritten by an issuer prefix.
function runtimeProjectText(value,resolved,{attributeId='',entity=false}={}) {
  if(typeof value!=='string'||runtimeSensitive(attributeId))return value;
  const xml=/<(?:saml(?:p)?:)?(?:AuthnRequest|Response|Assertion|Issuer|LogoutRequest|LogoutResponse|EntityDescriptor)\b/.test(value);
  const map=new Map(resolved.map);
  if(entity){
    if(resolved.context.aEntityID)map.set(runtimeA,resolved.aEntity);
    if(resolved.context.bEntityID)map.set(runtimeB,resolved.bEntity);
  }
  if(/^(?:origin|clientDataJSON|rpObject)$/.test(attributeId)&&resolved.external.issuerURL){
    const origin=new URL(resolved.external.issuerURL).origin;
    for(const source of [runtimeGenericProvider.examples.issuer,resolved.profile.examples?.issuer])if(source)map.set(source,origin);
  }
  if(attributeId==='idTokenA'&&(resolved.context.keycloakABaseURL||resolved.context.realmA||resolved.context.aIssuerURL))map.set('iss=A','iss='+resolved.aIssuer);
  if(attributeId==='idTokenB'){
    if(resolved.options.upstream==='external'&&resolved.external.issuerURL)map.set('iss=B','iss='+resolved.external.issuerURL);
    else if(resolved.context.keycloakBBaseURL||resolved.context.realmB||resolved.context.bIssuerURL)map.set('iss=B','iss='+resolved.bIssuer);
  }
  const clients=new Map();
  if(resolved.context.clientID){
    if(runtimeAppClientIds.has(attributeId)||runtimeAppAudienceIds.has(attributeId)&&runtimeAppClientSources.includes(value))return resolved.context.clientID;
    for(const source of runtimeAppClientSources){clients.set(source,resolved.context.clientID);clients.set('encoded-'+source,'encoded-'+resolved.context.clientID);}
  }
  const sources=[...new Set([...map.keys(),...resolved.hosts.keys(),...clients.keys()])].sort((a,b)=>b.length-a.length);
  if(!sources.length)return value;
  // One pass is intentional: operator-provided replacements are never fed
  // through other symbolic bindings or recursively rewritten.
  const cacheKey=JSON.stringify([entity,/^(?:origin|clientDataJSON|rpObject)$/.test(attributeId),attributeId==='idTokenA',attributeId==='idTokenB']);
  let pattern=resolved.patternCache.get(cacheKey);
  if(!pattern){pattern=new RegExp(sources.map(source=>runtimeEscapeRegExp(source)+(map.has(source)?'\\??':'')).join('|'),'g');resolved.patternCache.set(cacheKey,pattern);}
  return value.replace(pattern,(matched,index,text)=>{
    const hasQuery=matched.endsWith('?')&&map.has(matched.slice(0,-1));
    const source=hasQuery?matched.slice(0,-1):matched;
    const before=text[index-1]||'',after=text[index+source.length]||'';
    if(map.has(source)){
      if(/[A-Za-z0-9_/%.-]/.test(before)||/[A-Za-z0-9_/:%-]/.test(after)||after==='.'&&/[A-Za-z0-9]/.test(text[index+source.length+1]||''))return source;
      let target=map.get(source);
      // Explicit origin labels in prose describe an origin, not the issuer's
      // path. The payload/definition attribute binding has priority above.
      if(/\borigin(?:\s+(?:is|equals|must equal|of))?\s*[:=]?\s*["']?$/i.test(text.slice(Math.max(0,index-48),index))&&['http:','https:'].includes(runtimeParsedURL(target)?.protocol))target=new URL(target).origin;
      // Preserve an existing callback query while adding simulated result
      // parameters, rather than producing two question marks.
      const result=target+(hasQuery?(target.includes('?')?'&':'?'):'');
      return xml?runtimeXmlText(result):result;
    }
    if(resolved.hosts.has(source)){
      if(/[A-Za-z0-9_/:.-]/.test(before)||/[A-Za-z0-9_-]/.test(after)||after==='.'&&/[A-Za-z0-9]/.test(text[index+source.length+1]||''))return source;
      return resolved.hosts.get(source);
    }
    if(/[A-Za-z0-9_/-]/.test(before)||/[A-Za-z0-9_-]/.test(after))return source;
    const client=clients.get(source);
    if(/[?&]client_id=$/.test(text.slice(Math.max(0,index-24),index)))return encodeURIComponent(client);
    return xml?runtimeXmlText(client):client;
  });
}
const runtimeIsEntityAttribute = id => /^(?:saml(?:IdpEntity|SpEntity|Audience)|sl(?:Issuer|Audience|MetadataEntityID|MetadataIdpEntityID))/.test(id||'');
const runtimePayloadId = (payload,step) => payload.attributeId||(/(?:secret|password|private_key|code_verifier|pinUvAuthToken)/i.test(payload.name||'')?'secret:'+payload.name:(step.fields||[]).find(id=>runtimeAppClientIds.has(id)&&payload.name==='client_id'))||'';

export class RuntimeEnvironment {
  constructor(){this._draft=runtimeFreeze(runtimeEmpty());this._applied=runtimeFreeze(runtimeEmpty());this._revision=0;this._appliedArchitecture='web';this._appliedExecutionEnvironment='server';this._resolvedCache=new Map();}
  get draft(){return this._draft;}
  get applied(){return this._applied;}
  get revision(){return this._revision;}
  get active(){return [...runtimeCommonKeys].some(key=>!!this._applied[key])||Object.values(this._applied.providers).some(profile=>Object.values(profile).some(Boolean));}
  updateDraft(patch={},options={}) {
    const next=runtimeClone(this._draft),profileId=runtimeProfileKey(options);
    for(const key of runtimeCommonKeys)if(Object.hasOwn(patch,key))next[key]=runtimeText(patch[key]);
    if(patch.provider){const provider={...(next.providers[profileId]||{})};for(const key of runtimeProviderKeys)if(Object.hasOwn(patch.provider,key))provider[key]=runtimeText(patch.provider[key]);next.providers[profileId]=provider;}
    this._draft=runtimeFreeze(next);return this._draft;
  }
  validate(options={}) {
    options=this._options(options);
    const errors={},active=Array.isArray(options.activeFields)?new Set(options.activeFields):null;
    for(const field of RUNTIME_ENVIRONMENT_FIELDS){if(active&&!active.has(field.key))continue;const error=runtimeValidateField(field,this._draft[field.key],options);if(error)errors[field.key]=error;}
    const provider=this._draft.providers[runtimeProfileKey(options)]||{};
    for(const field of RUNTIME_PROVIDER_FIELDS){if(active&&!active.has('provider.'+field.key))continue;const error=runtimeValidateField(field,provider[field.key]||'',options);if(error)errors['provider.'+field.key]=error;}
    return {ok:!Object.keys(errors).length,errors};
  }
  apply(options={}) {
    options=this._options(options);
    const result=this.validate(options);
    if(!result.ok)return {...result,context:this._applied,revision:this._revision};
    const active=Array.isArray(options.activeFields)?new Set(options.activeFields):null;
    const next=runtimeClone(this._applied),profileId=runtimeProfileKey(options);
    for(const key of runtimeCommonKeys)if(!active||active.has(key))next[key]=this._draft[key];
    const provider={...(next.providers[profileId]||{})},draftProvider=this._draft.providers[profileId]||{};
    for(const key of runtimeProviderKeys)if((!active||active.has('provider.'+key))&&Object.hasOwn(draftProvider,key))provider[key]=draftProvider[key];
    if(Object.keys(provider).length)next.providers[profileId]=provider;
    this._applied=runtimeFreeze(next);this._revision++;this._appliedArchitecture=options.architecture;this._appliedExecutionEnvironment=runtimeExecutionEnvironment(options);this._resolvedCache.clear();
    return {...result,context:this._applied,revision:this._revision};
  }
  reset(){this._draft=runtimeFreeze(runtimeEmpty());this._applied=runtimeFreeze(runtimeEmpty());this._revision++;this._appliedArchitecture='web';this._appliedExecutionEnvironment='server';this._resolvedCache.clear();return this._applied;}
  _options(options={}){
    const architecture=options.architecture||this._appliedArchitecture;
    const executionEnvironment=options.executionEnvironment||(options.architecture?runtimeExecutionEnvironment(options):this._appliedExecutionEnvironment);
    return {architecture,executionEnvironment,...options};
  }
  _resolve(options){
    options=this._options(options);
    const signature=JSON.stringify([runtimeProfileKey(options),options.providerProfile?.examples,options.bindings,options.upstream,options.architecture,options.directFido,options.executionEnvironment,options.clientActor]);
    let resolved=this._resolvedCache.get(signature);
    if(!resolved){if(this._resolvedCache.size>=8)this._resolvedCache.clear();resolved=runtimeResolve(this._applied,options);this._resolvedCache.set(signature,resolved);}return resolved;
  }
  // Display metadata, separate from protocol attributes. Only the applied
  // context is read; callers may supply the current model's symbolic examples.
  participantContext(actorId,options={}) {
    options=this._options(options);
    const clientActor=['app','browser'].includes(options.clientActor)?options.clientActor:'app',native=runtimeExecutionEnvironment(options)==='native';
    if(![clientActor,'realmA','realmB'].includes(actorId)||options.actorKind==='resource'||actorId!==clientActor&&options.directFido||actorId==='realmB'&&options.upstream==='single')return runtimeFreeze([]);
    const resolved=runtimeResolve(this._applied,options),context=this._applied,rows=[],examples=options.exampleValues||{},lab=!!options.labScenarioId;
    const add=(key,label,value,provenance='example')=>{if(value)rows.push({key,label,value,provenance});};
    const projected=value=>runtimeProjectText(value,resolved);
    if(actorId===clientActor){
      const exampleApp=examples.appURL||(options.labScenarioId==='lab-spa-api'?'https://spa.example.test':options.directFido||!lab&&!native?'https://app.example.test':'');
      const appURL=resolved.appURL||exampleApp;
      add('appURL','Application URL',appURL,resolved.appURL?'applied':'example');
      if(options.directFido){const parsed=runtimeParsedURL(appURL);add('origin','WebAuthn origin',parsed?.origin, resolved.appURL?'derived':'example');add('rpID','WebAuthn RP ID',parsed?.hostname,resolved.appURL?'derived':'example');return runtimeFreeze(rows);}
      if(options.applicationProtocol==='saml'){
        add('acsURL','SAML ACS URL',context.acsURL||projected(examples.samlAcsApp||'https://app.example.test/saml/acs'),context.acsURL?'applied':resolved.appURL?'derived':'example');
        add('samlEntityID','SAML entityID',context.appEntityID||projected(examples.samlSpEntityApp||(!lab?'urn:example:app:sp':'https://app.example.test/saml')),context.appEntityID?'applied':resolved.appURL&&lab?'derived':'example');
      }else{
        const callback=examples.redirectApp||examples.webRedirectUri||examples.branchRedirectUri||(!lab?(native?'http://127.0.0.1:54321/callback':'https://app.example.test/oidc/callback'):options.labScenarioId==='lab-spa-api'?'https://spa.example.test/callback':options.labScenarioId==='lab-bff-api'?'https://app.example.test/oidc/callback':'');
        if(callback)add('appCallbackURL','Application callback',resolved.callbackURL||projected(callback),resolved.callbackURL?'applied':resolved.appURL&&!native?'derived':'example');
        add('clientID','Application client_id',context.clientID||examples.clientIdApp||examples.webClientId||(!lab?(options.architecture==='native'?'desktop-app':'web-app'):''),context.clientID?'applied':'example');
      }
    }else if(actorId==='realmB'&&options.upstream==='external'){
      const external=resolved.external,ex=resolved.profile.examples||{},saml=options.brokerProtocol==='saml'||resolved.profile.protocol==='saml';
      if(saml){add('samlEntityID','SAML entityID',external.samlEntityID||ex.entityID,external.samlEntityID?'applied':'example');add('ssoURL','SAML SSO URL',external.ssoURL||ex.ssoUrl,external.ssoURL?'applied':'example');}
      else{
        add('issuerURL','OIDC issuer',external.issuerURL||ex.issuer,external.issuerURL?'applied':'example');
        if(ex.loginDomain)add('loginDomainURL','Managed-login URL',external.loginDomainURL||ex.loginDomain,external.loginDomainURL?'applied':'example');
        for(const [key,label,source]of [['authorizationURL','Authorization endpoint','authorizationEndpoint'],['tokenURL','Token endpoint','tokenEndpoint'],['jwksURL','JWKS URL','jwksUri']]){
          const derived=resolved.profile.id==='cognito'&&external.loginDomainURL&&key!=='jwksURL';
          add(key,label,external[key]||(derived?runtimeAppend(external.loginDomainURL,key==='authorizationURL'?'oauth2/authorize':'oauth2/token'):ex[source]),external[key]?'applied':derived?'derived':'example');
        }
      }
    }else{
      const prefix=actorId==='realmA'?'a':'b',suffix=prefix.toUpperCase(),issuer=prefix==='a'?resolved.aIssuer:resolved.bIssuer,saml=prefix==='a'?options.applicationProtocol==='saml':options.brokerProtocol==='saml';
      // A standards-only OP is not a Keycloak deployment. Its own model
      // examples can identify it without presenting unused context overrides.
      if(options.actorKind==='external-provider'){add('issuerURL','OIDC issuer',examples.issuerURL||examples.issuerA||examples.issuerB);return runtimeFreeze(rows);}
      const exact=context[prefix+'IssuerURL'],known=exact?.match(/^(.*)\/realms\/([^/?#]+)\/?$/),base=context['keycloak'+suffix+'BaseURL']||(known?known[1]:!exact?'https://idp'+(prefix==='a'?1:2)+'.example.test':'');
      const realm=context['realm'+suffix]||(known?runtimeDecodeSegment(known[2]):!exact?'realm-'+prefix:'');
      add('keycloakBaseURL','Keycloak deployment',base,context['keycloak'+suffix+'BaseURL']?'applied':known?'derived':'example');
      add('realm','Realm',realm,context['realm'+suffix]?'applied':known?'derived':'example');
      const changed=context['keycloak'+suffix+'BaseURL']||context['realm'+suffix];
      if(saml){add('samlEntityID','SAML entityID',context[prefix+'EntityID']||(prefix==='a'?resolved.aEntity:resolved.bEntity),context[prefix+'EntityID']?'applied':changed||exact?'derived':'example');add('ssoURL','SAML SSO URL',context[prefix+'SsoURL']||runtimeAppend(issuer,'protocol/saml'),context[prefix+'SsoURL']?'applied':changed||exact?'derived':'example');}
      else add('issuerURL','OIDC issuer',issuer,exact?'applied':changed?'derived':'example');
      if(prefix==='a'&&options.upstream&&options.upstream!=='single'&&!lab){const alias=context.brokerAlias||(options.upstream==='external'?(resolved.profileId!=='generic'?resolved.profileId:options.brokerProtocol==='saml'?'saml-partner':'external-idp'):'realm-b');add('brokerCallbackURL','Broker callback',runtimeAppend(issuer,'broker/'+encodeURIComponent(alias)+'/endpoint'),changed||exact||context.brokerAlias?'derived':'example');}
    }
    return runtimeFreeze(rows);
  }
  projectValue(value,options={}){return runtimeProjectText(value,this._resolve(options),options);}
  projectSteps(steps,options={}) {
    const resolved=this._resolve(options);
    return runtimeFreeze(steps.map(step=>{
      const clone=runtimeClone(step);
      for(const key of ['title','summary','detail'])if(typeof step[key]==='string')clone[key]=runtimeProjectText(step[key],resolved);
      if(step.payload)clone.payload=step.payload.map(item=>{
        const id=runtimePayloadId(item,step),entity=runtimeIsEntityAttribute(id)||/^(?:Issuer|entityID|Audience|EntityDescriptor@entityID|AuthnRequest|SAMLResponse|Response|Assertion|ArtifactResolve|ArtifactResponse|LogoutRequest|LogoutResponse)$/.test(item.name||'');
        return {...item,value:runtimeProjectText(item.value,resolved,{attributeId:id,entity}),...(item.description?{description:runtimeProjectText(item.description,resolved)}:{})};
      });
      if(step.attributeValues)clone.attributeValues=Object.fromEntries(Object.entries(step.attributeValues).map(([id,value])=>[id,runtimeProjectText(value,resolved,{attributeId:id,entity:runtimeIsEntityAttribute(id)})]));
      if(step.attributeOperations)clone.attributeOperations=step.attributeOperations.map(operation=>({...operation,detail:runtimeProjectText(operation.detail,resolved)}));
      if(step.checks)clone.checks=step.checks.map(value=>runtimeProjectText(value,resolved));
      return clone;
    }));
  }
  projectActor(actor,options={}) {
    const resolved=this._resolve(options),clone=runtimeClone(actor);
    for(const key of ['name','role','plainRole'])if(typeof actor[key]==='string')clone[key]=runtimeProjectText(actor[key],resolved);
    if(actor.notes)clone.notes=actor.notes.map(value=>runtimeProjectText(value,resolved));
    if(actor.attributes)clone.attributes=actor.attributes.map(value=>({...value}));
    return runtimeFreeze(clone);
  }
  projectDefinition(id,definition,options={}) {
    const resolved=this._resolve(options),clone=runtimeClone(definition);
    for(const key of ['meaning','description','origin','generator','purpose','example'])if(typeof definition[key]==='string')clone[key]=runtimeProjectText(definition[key],resolved,{attributeId:key==='example'?id:'',entity:key==='example'&&runtimeIsEntityAttribute(id)});
    return runtimeFreeze(clone);
  }
  projectExamples(examples,options={}) {
    const resolved=this._resolve(options);
    return runtimeFreeze(Object.fromEntries(Object.entries(examples).map(([id,value])=>[id,runtimeProjectText(value,resolved,{attributeId:id,entity:runtimeIsEntityAttribute(id)})])));
  }
}
