import { createHeldObjectPlan, heldArtifact, heldAt, heldAcquire, heldRelease, heldCoverage, heldWire } from './held-object-authoring.js';

// These are declarative interaction predicates, not a Cartesian inventory. The
// projected source journey decides which explicit event bindings are applicable.
const coreInteractionFamilies = [
  { id:'core-01-ownership', dimensions:['architecture'], predicate:{oidcFlow:'authorization-code',applicationProtocol:'oidc'}, rationale:'Native and confidential backend own their verifier and tokens; only web creates an HttpOnly application cookie.' },
  { id:'core-02-generations', dimensions:['upstream'], predicate:{oidcFlow:'authorization-code'}, rationale:'Single realm excludes upstream state/nonce/code; broker generations remain separate.' },
  { id:'core-03-protocols', dimensions:['applicationProtocol','brokerProtocol','tokenProtection','encryptAssertions'], predicate:{oidcFlow:'authorization-code'}, rationale:'All four OIDC/SAML pairings; encryption applies independently to actual protocol legs.' },
  { id:'core-04-saml-initiation', dimensions:['binding','initiation'], predicate:{applicationProtocol:'saml'}, rationale:'Redirect/POST requests and POST responses; unsolicited application SSO has no pending request or correlation.' },
  { id:'core-05-factors', dimensions:['mode','upstream','authenticator'], predicate:{providerManaged:false}, rationale:'Password/TOTP/passkey combinations; Hello and YubiKey keep private keys local. TOTP-only is one factor.' },
  { id:'core-06-managed', dimensions:['providerProfileId','tokenProtection','brokerProtocol'], predicate:{upstream:'external',providerManaged:true}, rationale:'Generic, Entra, Okta, Cognito and AWS Identity Center ceremonies are opaque; no invented factor stores or achieved MFA. Named OIDC base profiles exclude broker JWE.' },
  { id:'core-07-device', dimensions:['architecture','mode','authenticator'], predicate:{oidcFlow:'device'}, rationale:'Private device_code remains with client/server; only user_code reaches verification browser. Pending and slow_down issue no tokens.' },
  { id:'core-08-ciba', dimensions:['mode','authenticator','tokenProtection'], predicate:{oidcFlow:'ciba'}, rationale:'Poll only; backend handle and protected service callback credential are separate from device UI and successful tokens.' },
  { id:'core-09-service-exchange', dimensions:['oidcFlow'], predicate:{oidcFlow:['client-credentials','token-exchange']}, rationale:'Single realm confidential service, no human/MFA/refresh. Standard V2 retains source and gives output exact lineage; no actor-token delegation is invented.' },
  { id:'core-10-enrollment', dimensions:['mode','upstream','authenticator'], predicate:{mode:['enrollment','totp-enrollment','fido-enrollment']}, rationale:'Verified account/session initially exists; new authenticator/server records appear only at authored enrollment events. Managed provider enrollment is excluded by source.' },
  { id:'core-11-context', dimensions:['contextId','choiceId'], predicate:{all:true}, rationale:'Artifact IDs are stable within immutable context; configuration projection is rebuilt without carrying previous holdings across Apply/Reset/scenario changes.' },
];
const coreDefaults = {mode:'passkey',architecture:'web',upstream:'single',authenticator:'hello',applicationProtocol:'oidc',brokerProtocol:'oidc',binding:'redirect',initiation:'sp',encryptAssertions:false,providerManaged:false,providerProfileId:'generic',oidcFlow:'authorization-code',tokenProtection:'signed'};
const coreInteractionConfigs = [
  ['native','web'].map(architecture=>({architecture})),
  ['single','keycloak','external'].map(upstream=>({upstream})),
  ['oidc','saml'].flatMap(applicationProtocol=>['oidc','saml'].flatMap(brokerProtocol=>['signed','app-jwe','broker-jwe','both-jwe'].map(tokenProtection=>({upstream:'keycloak',applicationProtocol,brokerProtocol,tokenProtection,encryptAssertions:true})))),
  ['redirect','post'].flatMap(binding=>['sp','idp'].map(initiation=>({applicationProtocol:'saml',binding,initiation}))),
  ['password','one-time-code','password-totp','passkey','passkey-totp'].flatMap(mode=>['single','keycloak','external'].flatMap(upstream=>['hello','yubikey'].map(authenticator=>({mode,upstream,authenticator})))),
  ['generic','entra','okta','cognito','aws-identity-center'].map(providerProfileId=>({upstream:'external',providerProfileId,providerManaged:true,brokerProtocol:providerProfileId==='aws-identity-center'?'saml':'oidc',tokenProtection:'app-jwe'})),
  ['native','web'].map(architecture=>({oidcFlow:'device',mode:'password-totp',architecture})),
  ['password-totp','passkey-totp'].map(mode=>({oidcFlow:'ciba',mode,authenticator:'yubikey',tokenProtection:'app-jwe'})),
  ['client-credentials','token-exchange'].map(oidcFlow=>({oidcFlow,mode:'passkey-totp',upstream:'external'})),
  ['enrollment','totp-enrollment','fido-enrollment'].flatMap(mode=>['single','keycloak','external'].flatMap(upstream=>['hello','yubikey'].map(authenticator=>({mode,upstream,authenticator})))),
  [{mode:'password',architecture:'native'},{mode:'passkey-totp',architecture:'web',upstream:'keycloak'}],
];
export const CORE_HELD_OBJECT_INTERACTIONS = Object.freeze(coreInteractionFamilies.flatMap((family,index)=>coreInteractionConfigs[index].map((config,caseIndex)=>Object.freeze({...family,familyId:family.id,id:family.id+'-'+String(caseIndex+1).padStart(2,'0'),config:Object.freeze({...coreDefaults,...config})}))));
export const CORE_HELD_OBJECT_SCOPE = Object.freeze({
  supported:'Every source-supported normalized Core journey and Core-backed preset; actual projected events are authoritative.',
  normalized:['SAML/direct FIDO use web','Single realm has no broker leg','Client credentials/exchange use confidential web and no human ceremony','Device uses a single realm','CIBA uses single realm/confidential web/Poll and separate controlled authentication service','Authenticator applies only to passkey methods','JWE applies only to present OIDC ID-token legs','SAML binding/initiation/encryption apply only to SAML legs','Enrollment has no OAuth token legs'],
  excluded:['SPA/BFF are separate LAB_MODELS fixtures, not a third Core architecture','Managed provider enrollment is not supported by the source adapter','Named managed OIDC base profiles do not support broker JWE','Standard V2 source is a same-realm access token; no actor_token or Preview delegation','CIBA Ping/Push are not modeled','Absent optional refresh responses are not fabricated'],
});

const canonical = step => String(step.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const payloadNames = {
  clientIdApp:'client_id',clientIdBroker:'client_id',clientSecret:'client_secret',clientSecretApp:'client_secret',
  stateApp:'state',stateBroker:'state',nonceApp:'nonce',nonceBroker:'nonce',codeVerifier:'code_verifier',codeChallenge:'code_challenge',
  codeA:'code',codeB:'code',idTokenA:'id_token',idTokenB:'id_token',accessTokenA:'access_token',accessTokenB:'access_token',refreshToken:'refresh_token',
  issuerA:'iss',issuerB:'iss',audience:'aud',subjectA:'sub',subjectB:'sub',exp:'exp',iat:'iat',scope:'scope',
  challengeLogin:'challenge',challengeRegistration:'challenge',signature:'signature',credentialId:'rawId',credentialPublicKey:'credentialPublicKey',
  password:'password',otpCode:'otp',otpSecret:'secret',otpUri:'Provisioning URI (de facto)',deviceCode:'device_code',deviceUserCode:'user_code',
  cibaAuthReqId:'auth_req_id',cibaBindingMessage:'binding_message',cibaChannelAuthorization:'Authorization',
  exchangeSubjectToken:'subject_token',exchangeAccessToken:'access_token',exchangeClientId:'client_id',exchangeClientSecret:'client_secret',
};

export function buildCoreHeldObjects(args) {
  if (args.model != null) return null;
  const { steps = [], actors = {}, config = {} } = args;
  const plan = createHeldObjectPlan(args);
  const find = id => steps.find(s => canonical(s) === id);
  const exact = id => steps.find(s => s.id === id);
  const stage = (hop, name) => steps.find(s => s.samlHop === hop && s.samlStage === name);
  const jwe = (hop, name) => steps.find(s => s.jweHop === hop && s.jweStage === name);
  const actor = id => id === 'authenticator' ? (config.authenticator === 'yubikey' ? 'yubikey' : 'hello') : id;
  const hasActor = id => Object.hasOwn(actors, actor(id));
  const end = steps.at(-1);
  const stores = new Map(Object.keys(actors).map(id => [id, new Set()]));
  const categories = new Map(Object.keys(actors).map(id => [id, new Set()]));
  const definitions = new Map();
  const eventId = event => event == null ? null : typeof event === 'string' ? event : event.id;
  const at = (event, ...effects) => heldAt(plan, eventId(event), ...effects);
  const value = (event, id) => {
    if (event?.attributeValues && Object.hasOwn(event.attributeValues, id)) return event.attributeValues[id];
    const named = event?.payload?.find(p => p.attributeId === id || p.name === (payloadNames[id] || id));
    return named ? named.value : id + ' (symbolic fixture value)';
  };
  const fields = (event, ids, readableBy) => ids.map(attributeId => ({attributeId, value:value(event, attributeId), ...(readableBy ? {readableBy:readableBy.map(actor)} : {})}));
  const declare = (id, type, label, creator, ids = [], event = null, extra = {}) => {
    if (definitions.has(id)) return id;
    const definition = {artifactId:id,type,label,creator:actor(creator),representations:[{representationId:'plain',format:type,readableBy:[actor(creator)],fields:fields(event,ids)}],...extra};
    const authored=heldArtifact(plan, definition); definitions.set(id, authored); return id;
  };
  const readers = (id, rep, ids) => {
    const r = definitions.get(id).representations.find(r => r.representationId === rep);
    for (const id of ids.map(actor)) if (!r.readableBy.includes(id)) r.readableBy.push(id);
  };
  const hold = (event, id, owner, store, {rep='plain',temporary=false,releaseAt} = {}) => {
    owner = actor(owner);
    if (!hasActor(owner)) throw new Error('Core held object references absent logical actor: ' + owner);
    stores.get(owner).add(store); categories.get(owner).add(definitions.get(id).type);
    at(event, heldAcquire(id, owner, store, {representationId:rep,retention:temporary?'temporary':'retained'}));
    if (temporary) at(releaseAt || end, heldRelease(id, owner, store, {representationId:rep}));
  };
  const create = (event, id, owner, store, options = {}) => {
    at(event, {op:'create',artifactId:id}); hold(event,id,owner,store,options);
  };
  const drop = (event,id,owner,store,rep='plain') => at(event,heldRelease(id,actor(owner),store,{representationId:rep}));
  const send = (event,id,from,to,{rep='plain',fromStore='output',toStore='request',temporary=true,releaseAt=end,releaseSender=false,read=true}={}) => {
    if (!event) return;
    from=actor(from);to=actor(to);
    if(read) readers(id,rep,[to]);
    stores.get(to).add(toStore);categories.get(to).add(definitions.get(id).type);
    heldWire(plan,event.id,id,from,to,{representationId:rep,fromStore,toStore,retention:temporary?'temporary':'retained',...(temporary?{releaseAt:eventId(releaseAt)}:{}),releaseSender});
  };
  const observe = (event,id,owner,policy,result='accepted',endpoint) => {
    if(event) at(event,{op:'observe',artifactId:id,actorId:actor(owner),kind:'verification',policy,result,...(endpoint?{endpoint}:{}),requestId:event.id});
  };
  const seed = (id,type,label,owner,ids=[],event=null,store='configuration') => {
    declare(id,type,label,owner,ids,event);create(null,id,owner,store);return id;
  };
  const configuredClient = (prefix,owner,issuer,secretId,source,method='client_secret_basic') => {
    const id=prefix+'-registration';
    seed(id,'client-registration',prefix+' client registration',owner,[prefix==='exchange'?'exchangeClientId':owner==='app'?'clientIdApp':'clientIdBroker',...(secretId?[secretId]:[])],source);
    definitions.get(id).details=secretId?'Confidential registration; '+method+' on the protected backchannel.':'Public registration; no embedded client secret.';
    const policyFields=prefix==='service'?['serviceClientAuthentication','serviceAccountEnabled','serviceAssignedRoles','serviceRoleScopeMappings']:prefix==='exchange'?['exchangeEnabledPolicy','exchangeScopePolicy']:prefix==='ciba'?['cibaDeliveryMode']:[owner==='app'?'clientIdApp':'clientIdBroker'];
    const server=seed(prefix+'-server-registration','client-registration',prefix+' registered client policy',issuer,policyFields,source);
    definitions.get(server).related=[id];return id;
  };
  const issuerTrust = (prefix,issuer,recipient,source) => {
    if(!hasActor(issuer)||!hasActor(recipient))return;
    seed(prefix+'-signing-key','private-key',prefix+' issuer signing key',issuer,[prefix==='exchange'?'exchangeSigningKey':'realmSigningKey'],source,'key-store');
    seed(prefix+'-trusted-jwks','verification-key-set',prefix+' trusted issuer keys',recipient,[prefix==='exchange'?'exchangeVerificationKey':'jwksUri'],source,'trust-cache');
  };
  const session = (event,owner,prefix) => {
    if(!event)return;
    declare(prefix+'-session','session',prefix+' authenticated server session',owner,['session'],event);
    create(event,prefix+'-session',owner,'session-store');
  };
  const cookie = (event,owner,prefix) => {
    if(!event||!hasActor('browser'))return;
    const id=prefix+'-cookie';
    const attribute=prefix==='application'?'sessionCookieApp':'session';
    declare(id,'cookie',prefix+' HttpOnly session cookie',owner,[attribute],event,{representations:[{representationId:'opaque',format:'HttpOnly cookie',readableBy:[actor(owner),'browser'],fields:fields(event,[attribute],[owner])}],details:'Browser cookie jar holds opaque bytes. HttpOnly forbids page-script access; cookie is not a token or verifier.'});
    create(event,id,owner,'session-store',{rep:'opaque'});
    send(event,id,owner,'browser',{rep:'opaque',fromStore:'session-store',toStore:'cookie-jar',temporary:false});
  };

  const flow = steps.some(s=>s.serviceAccount)?'client-credentials':steps.some(s=>s.exchangeStage)?'token-exchange':steps.some(s=>s.oidcGrant==='ciba')?'ciba':steps.some(s=>String(s.id).startsWith('device-'))?'device':config.oidcFlow||'authorization-code';
  const direct = steps.some(s=>s.directFido);
  const enrollment = !!find('e01') || !!find('t01');
  const managed = config.upstream==='external' && (config.providerManaged || (config.providerProfileId && config.providerProfileId!=='generic'));
  const rp = actor(steps.find(s=>s.relyingPartyActor)?.relyingPartyActor || (direct?'app':flow==='ciba'?'realmB':config.upstream==='single'?'realmA':'realmB'));
  const auth = actor('authenticator');

  // Human credentials are explicit initial prerequisites, never discovered by
  // scanning operations, prose, actor attribute catalogs or eventual holders.
  if(!managed && !['client-credentials','token-exchange'].includes(flow)) {
    if(enrollment) {
      seed('verified-account-context','verified-account','Existing verified account and enrollment authorization',rp,['userId','session'],find('e01')||find('t01'),'session-store');
      declare('verified-browser-cookie','cookie','Existing verified enrollment browser cookie',rp,[],null,{representations:[{representationId:'opaque',format:'HttpOnly session cookie',readableBy:[rp,'browser'],fields:[]}],related:['verified-account-context']});
      create(null,'verified-browser-cookie','browser','cookie-jar',{rep:'opaque'});
    }
    if(find('p02')) {
      seed('account-password','password','Account password knowledge','user',['password'],find('p02'),'knowledge');
      seed('password-verifier','password-verifier','Protected account password verifier',rp,['passwordHash'],find('p03'),'credential-store');
      send(find('p02'),'account-password','user','browser',{fromStore:'knowledge',toStore:'form-input',releaseAt:find('p03')});
      send(find('p03'),'account-password','browser',rp,{fromStore:'form-input',toStore:'request',releaseAt:find('p03')});
      observe(find('p03'),'account-password',rp,'Account credential provider; attempt limits; password verification');
    }
    if(find('m02') && hasActor('totp')) {
      seed('totp-secret','symmetric-key','Previously enrolled TOTP seed and settings',rp,['otpSecret','otpAlgorithm','otpDigits','otpPeriod','otpT0'],find('m02'),'credential-store');
      readers('totp-secret','plain',['totp']);hold(null,'totp-secret','totp','credential-store');
    }
    const otpCreate=find('m02')||find('t05'),otpInput=find('m03')||find('t06'),otpSubmit=find('m04')||find('t07'),otpCheck=find('m05')||find('t07');
    if(otpCreate) {
      const secretId=find('t01')?'totp-enrollment-secret':'totp-secret';
      declare('totp-input','one-time-code','Transient time-based code','totp',['otpCode','otpCounter','otpTime'],otpCreate,{derivedFrom:[secretId]});
      create(otpCreate,'totp-input','totp','display',{temporary:true,releaseAt:otpCheck});
      send(otpCreate,'totp-input','totp','user',{fromStore:'display',toStore:'short-term-input',releaseAt:otpCheck});
      send(otpInput,'totp-input','user','browser',{fromStore:'short-term-input',toStore:'form-input',releaseAt:otpCheck});
      send(otpSubmit,'totp-input','browser',rp,{fromStore:'form-input',toStore:'request',releaseAt:otpCheck});
      observe(otpCheck,'totp-input',rp,'Enrolled secret; time window; attempt and one-time replay policy');
    }
    if(find('t03')) {
      declare('totp-enrollment-secret','symmetric-key','New TOTP provisioning secret and settings',rp,['otpSecret','otpAlgorithm','otpDigits','otpPeriod','otpT0'],find('t03'));
      create(find('t03'),'totp-enrollment-secret',rp,'pending-enrollment',{temporary:true,releaseAt:find('t07')});
      send(find('t03'),'totp-enrollment-secret',rp,'browser',{fromStore:'pending-enrollment',toStore:'provisioning-page',releaseAt:find('t04')});
      send(find('t04'),'totp-enrollment-secret','browser','totp',{fromStore:'provisioning-page',toStore:'credential-store',temporary:false});
      hold(find('t07'),'totp-enrollment-secret',rp,'credential-store');
      declare('totp-provisioning-uri','provisioning-uri','Secret-bearing TOTP QR/URI',rp,['otpUri'],find('t03'),{derivedFrom:['totp-enrollment-secret']});
      create(find('t03'),'totp-provisioning-uri',rp,'output',{temporary:true,releaseAt:find('t04')});
      send(find('t03'),'totp-provisioning-uri',rp,'browser',{releaseAt:find('t04'),toStore:'provisioning-page'});
      send(find('t04'),'totp-provisioning-uri','browser','totp',{fromStore:'provisioning-page',toStore:'provisioning-input',releaseAt:find('t04')});
      observe(find('t07'),'totp-enrollment-secret',rp,'Existing verified enrollment session and matching confirmation code');
    }
    const challengeStep=find('l08')||find('e03');
    if(challengeStep) {
      const registering=!!find('e03'),keyEvent=registering?find('e06'):null;
      declare('fido-private-key','private-key','RP-scoped '+(auth==='yubikey'?'YubiKey':'Windows Hello')+' credential private key',auth,['privateKey','rpId','userId'],keyEvent||challengeStep);
      create(keyEvent,'fido-private-key',auth,'credential-store');
      declare('fido-rp-record','public-key-record','RP public key, credential ID and verified account binding',auth,['credentialPublicKey','credentialId','userId','rpId','signCount'],keyEvent||challengeStep,{derivedFrom:['fido-private-key']});
      if(registering) {
        create(keyEvent,'fido-rp-record',auth,'credential-store');
        hold(find('e08'),'fido-rp-record',rp,'credential-store');readers('fido-rp-record','plain',[rp,'browser']);
        send(keyEvent,'fido-rp-record',auth,'browser',{fromStore:'credential-store',toStore:'registration-response',releaseAt:find('e07')});
        send(find('e07'),'fido-rp-record','browser',rp,{fromStore:'registration-response',toStore:'registration-request',releaseAt:find('e08')});
      } else {
        create(null,'fido-rp-record',rp,'credential-store');readers('fido-rp-record','plain',[rp]);
      }
      declare('fido-challenge','challenge',registering?'Fresh registration challenge/options':'Fresh login challenge/options',rp,[registering?'challengeRegistration':'challengeLogin','rpId','origin','userVerification'],challengeStep);
      const proofCheck=find('l14')||find('e07');
      create(challengeStep,'fido-challenge',rp,'pending-ceremony',{temporary:true,releaseAt:proofCheck});
      send(challengeStep,'fido-challenge',rp,'browser',{fromStore:'pending-ceremony',toStore:'webauthn-options',releaseAt:proofCheck});
      const prepareRequest=find('l09')||find('e04');
      const request=steps.find(s=>['make-credential','get-assertion'].includes(s.ctapOperation))||prepareRequest;
      declare('fido-client-context','webauthn-client-context','Browser-created WebAuthn client data','browser',['clientDataJSON','clientDataHash','origin'],prepareRequest,{derivedFrom:['fido-challenge'],representations:[
        {representationId:'plain',format:'WebAuthn client data',readableBy:['browser',rp],fields:fields(prepareRequest,['clientDataJSON','clientDataHash','origin'])},
        {representationId:'command',format:'Local authenticator command',readableBy:['browser',auth],fields:fields(request,['clientDataHash','rpId',...(registering?['userId','residentKey']:[])])},
      ]});
      create(prepareRequest,'fido-client-context','browser','ceremony-context',{temporary:true,releaseAt:proofCheck});
      hold(prepareRequest,'fido-client-context','browser','command-output',{rep:'command',temporary:true,releaseAt:proofCheck});
      send(request,'fido-client-context','browser',auth,{rep:'command',fromStore:'command-output',toStore:'ceremony-input',releaseAt:proofCheck});
      const proofCreate=find('l11')||keyEvent,proofReturn=find('l12')||keyEvent,proofSubmit=find('l13')||find('e07');
      const conversion=steps.find(s=>['registration-api-conversion','assertion-api-conversion'].includes(s.ctapOperation));
      if(conversion) {
        declare('ctap-result','authenticator-response','Local CTAP '+(registering?'MakeCredential':'GetAssertion')+' result',auth,registering?['ctapFmt','ctapAuthData','ctapAttStmt']:['ctapCredential','ctapAuthData','ctapSignature','ctapUser'],proofReturn,{derivedFrom:['fido-private-key','fido-client-context']});
        create(proofCreate,'ctap-result',auth,'output',{temporary:true,releaseAt:conversion});
        send(proofReturn,'ctap-result',auth,'browser',{toStore:'ctap-input',releaseAt:conversion});
      }
      declare('fido-proof',registering?'registration-response':'authentication-proof',registering?'WebAuthn registration response':'Fresh WebAuthn assertion',conversion?'browser':auth,registering?['credentialId','attestationObject','clientDataJSON']:['credentialId','authenticatorData','signature','userHandle'],conversion||proofReturn,{derivedFrom:conversion?['ctap-result','fido-client-context']:['fido-private-key','fido-client-context']});
      if(conversion)create(conversion,'fido-proof','browser','webauthn-response',{temporary:true,releaseAt:proofCheck});
      else {
        create(proofCreate,'fido-proof',auth,'output',{temporary:true,releaseAt:proofCheck});
        send(proofReturn,'fido-proof',auth,'browser',{toStore:'webauthn-response',releaseAt:proofCheck});
      }
      send(proofSubmit,'fido-proof','browser',rp,{fromStore:'webauthn-response',toStore:'request',releaseAt:proofCheck});
      observe(proofCheck,'fido-proof',rp,'Current challenge; expected origin/RP; UP/UV; trusted credential key; counter/attestation policy');
      if(direct&&!registering)session(exact('fido-d03'),'app','application');
      if(direct&&!registering)cookie(exact('fido-d03'),'app','application');
    }
    // The roaming transport explicitly authors its own local authorization
    // token and command/result instances. No PIN or biometric is server data.
    const ctapRequest=steps.find(s=>s.ctapOperation==='pin-uv');
    if(ctapRequest) {
      declare('ctap-pin-uv-token','local-authorization','Local CTAP PIN/UV authorization token',auth,['pinUvAuthToken'],ctapRequest);
      create(ctapRequest,'ctap-pin-uv-token',auth,'local-ceremony',{temporary:true,releaseAt:end});
      send(ctapRequest,'ctap-pin-uv-token',auth,'browser',{fromStore:'local-ceremony',toStore:'local-ceremony',releaseAt:end});
    }
  }

  function tokens(hop, issuer, recipient, wire, check, issue=wire, accessId, refresh=false) {
    if(!wire)return;
    const id='oidc-'+hop+'-id-token',tokenId=hop==='broker'?'idTokenB':'idTokenA';
    const encrypted=!!jwe(hop,'wire'),signed=jwe(hop,'sign')||issue;
    const claims=['issuer'+(hop==='broker'?'B':'A'),'audience','subject'+(hop==='broker'?'B':'A'),'exp','iat',...(!['device','ciba'].includes(flow)?[hop==='broker'?'nonceBroker':'nonceApp']:[])];
    declare(id,'id-token',hop+' OIDC identity token',issuer,[tokenId,...claims],signed,encrypted?{representations:[
      {representationId:'signed',format:'JWS',readableBy:[issuer],fields:fields(signed,[tokenId,...claims])},
      {representationId:'encrypted',format:'JWE compact',readableBy:[issuer,recipient],fields:fields(wire,[tokenId,'jweProtectedHeader'+(hop==='broker'?'Broker':'App')])},
      {representationId:'view',format:'decrypted JWS',readableBy:[recipient],fields:fields(signed,[tokenId,...claims])},
    ]}:{});
    const rep=encrypted?'signed':'plain';
    create(signed,id,issuer,'token-output',{rep,temporary:true,releaseAt:wire});
    if(encrypted) {
      hold(jwe(hop,'wrap'),id,issuer,'encrypted-output',{rep:'encrypted',temporary:true,releaseAt:wire});
      send(wire,id,issuer,recipient,{rep:'encrypted',fromStore:'encrypted-output',toStore:'token-store',temporary:false});
      hold(jwe(hop,'decrypt'),id,recipient,'decoded-view',{rep:'view'});
      observe(jwe(hop,'decrypt'),id,recipient,'JWE algorithm allowlist, local recipient key and authenticated GCM tag','authenticated plaintext');
      observe(jwe(hop,'verify-inner'),id,recipient,'Expected issuer signing key and allowed inner JWS algorithm');
      const suffix=hop==='broker'?'Broker':'App';
      seed('jwe-'+hop+'-private-key','private-key',hop+' configured decryption private key',recipient,['jweRecipientPrivateKey'+suffix],jwe(hop,'unwrap'),'key-store');
      seed('jwe-'+hop+'-public-key','public-key',hop+' registered recipient encryption public key',issuer,['jweRecipientPublicKey'+suffix],jwe(hop,'prepare'),'trust-cache');
      declare('jwe-'+hop+'-cek','symmetric-key',hop+' per-token content encryption key',issuer,['jweCek'+suffix],jwe(hop,'prepare'));
      create(jwe(hop,'prepare'),'jwe-'+hop+'-cek',issuer,'encryption-workspace',{temporary:true,releaseAt:wire});
      hold(jwe(hop,'unwrap'),'jwe-'+hop+'-cek',recipient,'decryption-workspace',{temporary:true,releaseAt:jwe(hop,'decrypt')});readers('jwe-'+hop+'-cek','plain',[recipient]);
    } else send(wire,id,issuer,recipient,{fromStore:'token-output',toStore:'token-store',temporary:false});
    observe(check,id,recipient,'Exact issuer, intended OIDC client audience, lifetime'+(!['device','ciba'].includes(flow)?', original nonce':' and completed grant transaction')+'; signature required before identity acceptance');
    if(accessId) {
      declare('oidc-'+hop+'-access-token','access-token',hop+' issued access token',issuer,[accessId,'scope'],wire);
      create(issue,'oidc-'+hop+'-access-token',issuer,'token-output',{temporary:true,releaseAt:wire});
      send(wire,'oidc-'+hop+'-access-token',issuer,recipient,{fromStore:'token-output',toStore:'token-store',temporary:false});
    }
    // Optional response documentation is not an issued credential. Core has
    // no selected refresh issuance policy; concrete refresh/offline lessons do.
    if(refresh && wire.fields?.includes('refreshToken'))
      plan.limitations.push('Optional refresh_token is not a selected issued credential in this Core fixture; see concrete refresh/offline fixed lessons for holdings.');
  }

  function oidcLeg(hop) {
    const app=hop==='app',owner=app?'app':'realmA',issuer=app?'realmA':'realmB';
    const prepare=find(app?'l02':'l05');if(!prepare)return;
    const stateId=app?'stateApp':'stateBroker',nonceId=app?'nonceApp':'nonceBroker',p=hop+'-oidc';
    const reg=configuredClient(p,owner,issuer,app?(config.architecture==='web'?'clientSecretApp':null):'clientSecret',prepare,!app&&config.providerProfileId==='entra'?'client_secret_post':'client_secret_basic');
    issuerTrust(p,issuer,owner,find(app?'l25':'l19'));
    for(const [suffix,attribute]of [['state',stateId],['nonce',nonceId]]) {
      declare(p+'-'+suffix,suffix,hop+' independent '+suffix,owner,[attribute],prepare);
      create(prepare,p+'-'+suffix,owner,'pending-login',{temporary:true,releaseAt:find(app?'l25':'l19')||end});
    }
    declare(p+'-request','authorization-request',hop+' OIDC authorization request',owner,[app?'clientIdApp':'clientIdBroker',app?'redirectApp':'redirectBroker',stateId,nonceId,...(app?['codeChallenge','codeChallengeMethod']:[])],prepare,{derivedFrom:[p+'-state',p+'-nonce']});
    create(prepare,p+'-request',owner,'pending-login',{temporary:true,releaseAt:find(app?'l25':'l19')||end});
    const open=find(app?'l03':'l06'),deliver=find(app?'l04':'l07');
    send(open,p+'-request',owner,'browser',{fromStore:'pending-login',toStore:'navigation',releaseAt:deliver});
    send(deliver,p+'-request','browser',issuer,{fromStore:'navigation',toStore:'authentication-context',releaseAt:find(app?'l23':'l17')||end});
    if(app) {
      declare('app-pkce-verifier','pkce-verifier','Application PKCE verifier',owner,['codeVerifier'],prepare);
      create(prepare,'app-pkce-verifier',owner,'pending-login',{temporary:true,releaseAt:find('l24')||end});
      declare('app-pkce-challenge','pkce-challenge','S256 challenge derived from verifier',owner,['codeChallenge','codeChallengeMethod'],prepare,{derivedFrom:['app-pkce-verifier']});
      create(prepare,'app-pkce-challenge',owner,'pending-login',{temporary:true,releaseAt:find('l24')||end});
      definitions.get(p+'-request').derivedFrom.push('app-pkce-challenge');
      send(find('l23'),'app-pkce-verifier',owner,issuer,{fromStore:'pending-login',toStore:'token-request',releaseAt:find('l24')||end});
      observe(find('l23'),'app-pkce-verifier',issuer,'S256 recomputation matches code-bound challenge; registered client and redirect');
    }
    const code=p+'-code',issue=find(app?'l20':'l15'),callback=find(app?'l21':'l16'),redeem=find(app?'l23':'l17');
    if(issue) {
      declare(code,'authorization-code',hop+' single-use authorization code',issuer,[app?'codeA':'codeB',stateId],issue,{related:[p+'-request']});
      create(issue,code,issuer,'code-output',{temporary:true,releaseAt:issue});
      send(issue,code,issuer,'browser',{fromStore:'code-output',toStore:'navigation',releaseAt:callback});
      send(callback,code,'browser',owner,{fromStore:'navigation',toStore:'pending-login',releaseAt:redeem});
      send(redeem,code,owner,issuer,{fromStore:'pending-login',toStore:'token-request',releaseAt:find(app?'l24':'l18')||end});
      observe(app?find('l22'):callback,code,owner,'Callback state matches this pending '+hop+' request');
      at(redeem,{op:'authority',artifactId:code,authorityId:issuer,status:'consumed',detail:'Single redemption at the registered token endpoint; sender holdings release separately.'});
    }
    if(redeem&&(app?config.architecture==='web':true))send(redeem,reg,owner,issuer,{fromStore:'configuration',toStore:'client-auth-request',releaseAt:find(app?'l24':'l18')||end});
    tokens(hop,issuer,owner,find(app?'l24':'l18'),find(app?'l25':'l19'),find(app?'l24':'l18'),app?'accessTokenA':'accessTokenB',app);
    if(!app)session(find('l19'),'realmA','broker');
  }

  function samlLeg(hop) {
    const createRequest=stage(hop,'request-create'),response=stage(hop,'response-create');if(!response)return;
    const app=hop==='app',sp=app?'app':'realmA',issuer=app?'realmA':'realmB',suffix=app?'App':'Broker',p='saml-'+hop;
    seed(p+'-signing-key','private-key',hop+' SAML issuer signing key',issuer,['samlSigningKey'+(app?'A':'B')],response,'key-store');
    seed(p+'-trust','verification-key-set',hop+' trusted SAML IdP metadata/certificate',sp,['samlSigningCertificate'+(app?'A':'B')],response,'trust-cache');
    if(createRequest) {
      seed(p+'-sp-key','private-key',hop+' SAML SP request signing key',sp,['samlSigningKey'+(app?'App':'A')],createRequest,'key-store');
      seed(p+'-sp-trust','verification-key-set',hop+' registered SP signing certificate and ACS policy',issuer,['samlSpEntity'+suffix,'samlAcs'+suffix],createRequest,'trust-cache');
      declare(p+'-request','saml-authn-request',hop+' SAML AuthnRequest and correlation',sp,['samlAuthnRequest','samlRequestId'+suffix,'samlRelayState'+suffix,'samlSpEntity'+suffix,'samlAcs'+suffix],createRequest);
      create(createRequest,p+'-request',sp,'pending-login',{temporary:true,releaseAt:stage(hop,'response-verify')});
      send(stage(hop,'request-bind'),p+'-request',sp,'browser',{fromStore:'pending-login',toStore:'navigation',releaseAt:stage(hop,'request-browser')});
      send(stage(hop,'request-browser'),p+'-request','browser',issuer,{fromStore:'navigation',toStore:'authentication-context',releaseAt:stage(hop,'response-post')});
      observe(stage(hop,'request-verify'),p+'-request',issuer,'Registered SP, exact ACS/destination and '+(config.binding||config.samlBinding||'redirect')+' request signature');
    }
    const claims=['samlAssertionId'+suffix,'samlNameId'+suffix,'samlAudience'+suffix,'samlRecipient'+suffix,'samlNotBefore','samlNotOnOrAfter','samlAuthnContext'+suffix,...(createRequest?['samlInResponseTo'+suffix]:[])];
    const encrypted=!!stage(hop,'assertion-encrypt');
    declare(p+'-assertion','saml-assertion',hop+' signed SAML assertion',issuer,claims,response,{representations:[{representationId:'plain',format:'signed XML assertion',readableBy:encrypted?[issuer,sp]:[issuer,sp,'browser'],fields:fields(response,claims)}]});
    create(response,p+'-assertion',issuer,'assertion-output',{temporary:true,releaseAt:stage(hop,'response-post')});
    declare(p+'-response','saml-response',hop+' POST SAML response'+(encrypted?' with encrypted assertion':''),issuer,['samlResponseId'+suffix,'samlResponse','samlResponseXml'],stage(hop,'response-post'),{derivedFrom:[p+'-assertion'],representations:[{representationId:'opaque',format:encrypted?'XML EncryptedAssertion container':'Base64 signed XML response',readableBy:[issuer,sp,'browser'],fields:fields(stage(hop,'response-post'),['samlResponseId'+suffix,'samlResponse',...(encrypted?['samlEncryptedAssertion','samlEncryptedKey']:claims)])}]});
    create(stage(hop,'response-post'),p+'-response',issuer,'response-output',{rep:'opaque',temporary:true,releaseAt:stage(hop,'response-post')});
    send(stage(hop,'response-post'),p+'-response',issuer,'browser',{rep:'opaque',fromStore:'response-output',toStore:'navigation',releaseAt:stage(hop,'response-browser')});
    send(stage(hop,'response-browser'),p+'-response','browser',sp,{rep:'opaque',fromStore:'navigation',toStore:'saml-response',releaseAt:stage(hop,'response-verify')});
    if(encrypted) {
      seed(p+'-decryption-key','private-key',hop+' SP XML decryption key',sp,['samlDecryptionKey'+suffix],response,'key-store');
      seed(p+'-encryption-certificate','public-key',hop+' registered SP XML encryption certificate',issuer,['samlEncryptionCertificate'+suffix],response,'trust-cache');
      declare(p+'-content-key','symmetric-key',hop+' temporary XML content key',issuer,['samlContentEncryptionKey'],stage(hop,'assertion-encrypt'));
      create(stage(hop,'assertion-encrypt'),p+'-content-key',issuer,'encryption-workspace',{temporary:true,releaseAt:stage(hop,'response-post')});
      hold(stage(hop,'response-verify'),p+'-content-key',sp,'decryption-workspace',{temporary:true,releaseAt:stage(hop,'response-verify')});readers(p+'-content-key','plain',[sp]);
    }
    if(!encrypted) {
      send(stage(hop,'response-post'),p+'-assertion',issuer,'browser',{fromStore:'assertion-output',toStore:'navigation',releaseAt:stage(hop,'response-browser')});
      send(stage(hop,'response-browser'),p+'-assertion','browser',sp,{fromStore:'navigation',toStore:'assertion-view',temporary:false});
    } else hold(stage(hop,'response-verify'),p+'-assertion',sp,'assertion-view');
    observe(stage(hop,'response-verify'),p+'-assertion',sp,'Trusted signatures; exact issuer, SP audience/recipient, conditions and '+(createRequest?'saved request/RelayState correlation':'explicit unsolicited-response policy; no InResponseTo'));
    session(stage(hop,'map-account')||stage(hop,'session'),sp,p);
    if(app)cookie(stage(hop,'session'),sp,'application');
  }

  if(flow==='client-credentials'||flow==='token-exchange') {
    const exchange=flow==='token-exchange',p=exchange?'exchange':'service',prepare=exact(p+'-prepare'),issue=exact(p+'-issue'),response=exact(p+'-response'),check=exact(p+'-retain')||exact(p+'-ready');
    configuredClient(p,'app','realmA',exchange?'exchangeClientSecret':'clientSecret',prepare);
    issuerTrust(p,'realmA','app',issue);
    send(exact(p+'-request'),p+'-registration','app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:exact(p+'-client-check')||exact(p+'-authenticate')});
    let source;
    if(exchange) {
      source=seed('exchange-source-token','access-token','Previously delivered same-realm source token','app',['exchangeSubjectToken','exchangeSourceIssuer','exchangeSourceAudience','exchangeSourceScope'],exact('exchange-prerequisite'),'token-store');
      send(exact('exchange-request'),source,'app','realmA',{fromStore:'token-store',toStore:'exchange-request',releaseAt:response});
      observe(exact('exchange-subject-check'),source,'realmA','Same realm signature/issuer/lifetime; requester-client is source audience');
    }
    const id=p+'-access-token';
    declare(id,'access-token',exchange?'Distinct Standard V2 exchanged access token':'Service-account access token','realmA',exchange?['exchangeAccessToken','exchangeResultAudience','exchangeScopeResponse','exchangeResultSubject']:['accessTokenA','serviceAccessAudience','serviceAccessScope','serviceAccessSubject'],issue,exchange?{derivedFrom:[source]}:{});
    create(issue,id,'realmA','token-output',{temporary:true,releaseAt:response});
    send(response,id,'realmA','app',{fromStore:'token-output',toStore:'token-store',temporary:false});
    observe(check,id,'app','Response token type, effective scope and lifetime; resource-server authorization not performed here','response accepted');
  } else if(flow==='device') {
    configuredClient('device','app','realmA',config.architecture==='web'?'clientSecretApp':null,exact('device-configure'));
    issuerTrust('device','realmA','app',find('l25'));
    for(const [name,release]of [['authorize-request','codes-response'],['pending-poll','pending-response'],['early-poll','slow-response'],['final-poll','redeem']])
      send(exact('device-'+name),'device-registration','app','realmA',{fromStore:'configuration',toStore:name+'-client-auth',releaseAt:exact('device-'+release)});
    for(const [name,release]of [['pending-response','early-poll'],['slow-response','increase-delay']]) {
      const response=exact('device-'+name),id='device-'+name+'-error';
      declare(id,'protocol-response','Device '+(name==='pending-response'?'authorization_pending':'slow_down')+' response','realmA',['deviceError'],response);
      create(response,id,'realmA','output',{temporary:true,releaseAt:response});
      send(response,id,'realmA','app',{toStore:'poll-response:'+name,releaseAt:exact('device-'+release)});
      observe(response,id,'app','Polling response does not grant credentials',name==='pending-response'?'pending':'increase interval');
    }
    for(const [id,attribute,label] of [['device-private-code','deviceCode','Private device code'],['device-user-code','deviceUserCode','Human-visible device user code']]) {
      declare(id,'transaction-code',label,'realmA',[attribute],exact('device-codes-create'));
      create(exact('device-codes-create'),id,'realmA','device-transaction');
      send(exact('device-codes-response'),id,'realmA','app',{fromStore:'device-transaction',toStore:'pending-device',temporary:false});
    }
    send(exact('device-display'),'device-user-code','app','user',{fromStore:'pending-device',toStore:'device-instructions',releaseAt:exact('device-approval-confirm')});
    send(exact('device-enter-user-code'),'device-user-code','user','browser',{fromStore:'device-instructions',toStore:'form-input',releaseAt:exact('device-resolve-user-code')});
    send(exact('device-resolve-user-code'),'device-user-code','browser','realmA',{fromStore:'form-input',toStore:'verification-request',releaseAt:exact('device-resolve-user-code')});
    declare('device-transaction','transaction','Device client/scopes, code association and approval state','realmA',['deviceAuthorization','deviceInterval','deviceExpiresIn'],exact('device-codes-create'),{related:['device-private-code','device-user-code']});
    create(exact('device-codes-create'),'device-transaction','realmA','transaction-store');
    for(const name of ['pending-poll','early-poll','final-poll'])send(exact('device-'+name),'device-private-code','app','realmA',{fromStore:'pending-device',toStore:name,releaseAt:exact(name==='pending-poll'?'device-pending-response':name==='early-poll'?'device-slow-response':'device-redeem')});
    observe(exact('device-approval-confirm'),'device-transaction','realmA','Verified browser subject and explicit intended-device approval');
    at(exact('device-redeem'),{op:'authority',artifactId:'device-transaction',authorityId:'realmA',status:'consumed'});
    drop(find('l25'),'device-private-code','app','pending-device');drop(find('l25'),'device-user-code','app','pending-device');
    tokens('app','realmA','app',find('l24'),find('l25'),find('l24'),'accessTokenA',true);
  } else if(flow==='ciba') {
    configuredClient('ciba','app','realmA','clientSecretApp',exact('ciba-prepare'));
    issuerTrust('ciba','realmA','app',find('l25'));
    declare('ciba-pending-response','protocol-response','CIBA authorization_pending response','realmA',['cibaError'],exact('ciba-pending'));
    create(exact('ciba-pending'),'ciba-pending-response','realmA','output',{temporary:true,releaseAt:exact('ciba-pending')});
    send(exact('ciba-pending'),'ciba-pending-response','realmA','app',{toStore:'poll-response',releaseAt:exact('ciba-backoff')});
    observe(exact('ciba-pending'),'ciba-pending-response','app','Pending response only; no successful token response','pending');
    declare('ciba-handle','transaction-handle','Client-bound CIBA auth_req_id','realmA',['cibaAuthReqId','cibaExpiresIn','cibaInterval'],exact('ciba-accept'));
    create(exact('ciba-accept'),'ciba-handle','realmA','transaction-store');
    send(exact('ciba-handle'),'ciba-handle','realmA','app',{fromStore:'transaction-store',toStore:'pending-ciba',temporary:false});
    declare('ciba-channel-credential','service-credential','Protected authentication-service callback credential','realmA',['cibaChannelAuthorization'],exact('ciba-accept'),{related:['ciba-handle']});
    create(exact('ciba-accept'),'ciba-channel-credential','realmA','delegation-store',{temporary:true,releaseAt:exact('ciba-approved')});
    send(exact('ciba-delegate'),'ciba-channel-credential','realmA','realmB',{fromStore:'delegation-store',toStore:'delegation-store',releaseAt:exact('ciba-approved')});
    send(exact('ciba-result'),'ciba-channel-credential','realmB','realmA',{fromStore:'delegation-store',toStore:'callback-request',releaseAt:exact('ciba-approved')});
    declare('ciba-device-cue','transaction-cue','CIBA matching cue and delegated login context','app',['cibaBindingMessage','cibaLoginHint','scope'],exact('ciba-prepare'));
    create(exact('ciba-prepare'),'ciba-device-cue','app','pending-ciba',{temporary:true,releaseAt:end});
    send(exact('ciba-request'),'ciba-device-cue','app','realmA',{fromStore:'pending-ciba',toStore:'transaction-store',releaseAt:end});
    send(exact('ciba-delegate'),'ciba-device-cue','realmA','realmB',{fromStore:'transaction-store',toStore:'delegation-context',releaseAt:end});
    send(exact('ciba-notify-device'),'ciba-device-cue','realmB','browser',{fromStore:'delegation-context',toStore:'device-ui',releaseAt:end});
    send(exact('ciba-consumption-cue'),'ciba-device-cue','app','user',{fromStore:'pending-ciba',toStore:'displayed-cue',releaseAt:end});
    for(const name of ['request','poll-pending','poll-approved'])send(exact('ciba-'+name),'ciba-registration','app','realmA',{fromStore:'configuration',toStore:name+'-client-auth',releaseAt:exact(name==='request'?'ciba-accept':name==='poll-pending'?'ciba-pending':'ciba-issue')});
    for(const name of ['poll-pending','poll-approved'])send(exact('ciba-'+name),'ciba-handle','app','realmA',{fromStore:'pending-ciba',toStore:name+'-handle',releaseAt:exact(name==='poll-pending'?'ciba-pending':'ciba-issue')});
    observe(exact('ciba-approved'),'ciba-handle','realmA','Authenticated controlled-service result; matching subject, approval, delegation and lifetime');
    at(exact('ciba-issue'),{op:'authority',artifactId:'ciba-handle',authorityId:'realmA',status:'consumed'});
    drop(find('l25'),'ciba-handle','app','pending-ciba');
    tokens('app','realmA','app',find('l24'),find('l25'),exact('ciba-issue'),'accessTokenA',true);
  } else if(!enrollment&&!direct) {
    oidcLeg('app');oidcLeg('broker');samlLeg('app');samlLeg('broker');
    if(find('l25')&&config.architecture==='web') {session(find('l25'),'app','application');cookie(find('l25'),'app','application');}
  }
  // Provider SSO is a server session/cookie boundary, not proof of a particular
  // vendor factor store or an assurance level. Issued bearer tokens are released
  // from issuer output instead of being accumulated as issuer credentials.
  if(!enrollment&&!direct&&!['client-credentials','token-exchange'].includes(flow)) {
    const providerEvent=steps.find(s=>s.providerManaged&&String(s.id).endsWith('-authentication'))||find('l15')||find('l20')||stage(config.upstream==='single'?'app':'broker','response-create')||find('m05')||find('l14')||find('p03');
    if(providerEvent&&hasActor(rp)) {session(providerEvent,rp,'provider');cookie(providerEvent,rp,'provider');}
  }
  plan.interactions=CORE_HELD_OBJECT_INTERACTIONS.map(entry=>({...entry}));
  plan.normalizedConfiguration={...config,oidcFlow:flow,architecture:direct||['client-credentials','token-exchange','ciba'].includes(flow)||stage('app','response-create')?'web':config.architecture||'native',upstream:direct?'none':['client-credentials','token-exchange','device','ciba'].includes(flow)?'single':config.upstream||'keycloak',authenticator:find('l08')||find('e03')?auth:'none',providerManaged:!!managed};
  for(const id of Object.keys(actors)) heldCoverage(plan,id,{stores:[...stores.get(id)],categories:[...categories.get(id)],status:'complete',support:'supported',rationale:stores.get(id).size?'Explicit Core event lifecycle for this normalized configuration.':managed&&['hello','yubikey','totp'].includes(id)?'Managed provider factors are opaque and excluded from this journey; no credential inventory is asserted outside that boundary.':'No credential/message store participates for this logical actor in the normalized Core journey.'});
  // Atomic completion cleanup follows creates, copies and checks in this same
  // authored milestone, including immediate consumption of local input.
  for(const event of Object.values(plan.events))for(const milestone of event.milestones)
    milestone.effects.sort((a,b)=>(a.op==='release')-(b.op==='release'));
  return plan;
}
