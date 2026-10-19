import { LIFELAB_ATTRIBUTES, LIFELAB_SCENARIOS } from './lifecycle-lab.js';
import { GRANTLAB_ATTRIBUTES, GRANTLAB_SCENARIOS } from './extended-grants-lab.js';
import { SAMLLAB_ATTRIBUTES, SAMLLAB_SCENARIOS } from './saml-advanced-lab.js';
import { BRANCHLAB_ATTRIBUTES, BRANCHLAB_SCENARIOS } from './branching-lab.js';
import { createHeldObjectPlan, heldArtifact, heldAt, heldAcquire, heldRelease, heldCoverage } from './held-object-authoring.js';

const WEB_MODELS = new Map([...LIFELAB_SCENARIOS, ...GRANTLAB_SCENARIOS, ...SAMLLAB_SCENARIOS, ...BRANCHLAB_SCENARIOS].map(model => [model.id, model]));

// Explicit scope for every logical role. Empty roles are deliberate exclusions of
// objects from this fixed excerpt, not conclusions drawn from an operation scan.
const LIFE_EMPTY = {user:'No new factor/account credential input in this backend excerpt.',browser:'No browser credential, cookie or message transport in this backend excerpt.'};
const SAML_EMPTY = {user:'No new factor input; the stated SAML prerequisites already hold.',realmB:'SP 2 is not a participant in this sign-in/metadata excerpt.',browser:'No browser transport in this direct metadata/SOAP excerpt.'};
const BRANCH_EMPTY = {user:'No new human factor input in this focused excerpt.',browser:'No browser transport in this direct backend excerpt.',realmB:'No upstream/resource exchange in this excerpt.',hello:'No completed authenticator proof or private-key use in this excerpt.'};
const WEB_SCOPE = {
  'lab-refresh-rotation':{...LIFE_EMPTY,app:'Initial R0/AT0/ID0, protected configuration/session, queued duplicate bytes, separate receipt/install and conforming release.',realmA:'Online session, signing key, transient request/output and strict consumed-R0 authority.'},
  'lab-offline-access':{app:'Private code-flow protections and offline token generations remain backend-owned.',realmA:'Independent consented offline session/idle-max policy; online logout and offline rotation differ.',browser:'Provider cookie and temporary authorization/consent/code carriers; no offline token store.',user:'Only a bounded authenticated offline-consent decision.'},
  'lab-token-revocation':{...LIFE_EMPTY,app:'Revoked credential remains until explicit forget; unknown input has separate identity.',realmA:'Transient revocation inputs and issuer-only invalidation; no issued token or existence oracle.',realmB:'Only independent JWT revocation-visibility policy, without fabricated issuer notifications.'},
  'lab-rp-initiated-logout':{app:'Prior identity hint, RP session and independent bounded logout-state transaction.',realmA:'Existing online session/cookie context; hint checks precede OP termination.',browser:'OP cookie and temporary hint/state carriers; unrelated origin storage is untouched.',user:'Local sign-out choice is not an account authentication credential.'},
  'lab-backchannel-logout':{...LIFE_EMPTY,app:'First RP session mapping, trusted public key, J0/J2 receipts and independent replay records.',realmA:'OP session, private signing key and bounded recipient-specific notification/retry buffers.',realmB:'Independent second-RP trust/session mapping and J1 replay record.'},
  'lab-frontchannel-logout':{...LIFE_EMPTY,app:'First RP session association and allowed iframe receipt with explicit local removal.',realmA:'OP session and bounded iframe document; no signed logout token or guaranteed completion.',realmB:'Second RP session persists when required browser-state operation is blocked.',browser:'Origin cookies, bounded iframe document and separately retained second-origin state.'},
  'lab-sso-existing-session':{...LIFE_EMPTY,app:'Prior hint, fresh private protections, received code/tokens and post-validation local session.',realmA:'Existing OP session, one-use code and temporary output; no fresh factor ceremony.',browser:'Existing OP cookie and temporary public authorization/code carriers, not backend tokens.'},
  'lab-sso-login-required':{...LIFE_EMPTY,app:'Prior hint and private protections are bounded; correlated error grants no new session.',realmA:'No usable account session; only public request and terminal error output.',browser:'Temporary public request/error carriers; no valid provider cookie is seeded.'},
  'lab-session-expiry':{...LIFE_EMPTY,app:'R0/AT0/local session persist until explicitly authored recovery removals.',realmA:'Retained expired online session record, transient request/error and expired authority.'},
  'lab-ciba-ping':{app:'Pending handle/callback bearer cannot install tokens on Ping; token receipt/check/install differ.',realmA:'Private key, bounded pending/service records, handle and transient token output.',realmB:'Backend controlled-service credential and verified action/result; no client tokens.',browser:'Temporary controlled-device proof/approval input only.',user:'Bounded required-factor verification plus transaction-specific approval.'},
  'lab-ciba-push':{app:'Pending callback protection, received tokens and signed handle/hash checks before installation.',realmA:'Issuer key and bounded pending/service records plus distinct access/refresh/identity output.',realmB:'Controlled-service credential and verified action/result only.',browser:'Temporary device action, not callback bearer or successful client token store.',user:'Bounded verified-factor and explicit matching-request approval.'},
  'lab-ciba-hint-token':{app:'Signed identifying hint, Poll pending handle and independently validated delivered tokens.',realmA:'Hint public trust, issuer key and bounded client/service approval transaction.',realmB:'Controlled-service backend credential and verified device action; no notification bearer.',browser:'Temporary controlled device proof/approval only.',user:'Explicit verification and approval; the identifying hint is not an authentication proof.'},
  'lab-exchange-id-token':{app:'Retained original subject access token, client authentication and distinct ID-token output.',realmA:'Configured result policy and temporary request/output; no input consumption.'},
  'lab-exchange-refresh-token':{app:'Original input and distinct output access/refresh credentials under provider response semantics.',realmA:'Explicit Same-session issuance policy and temporary request/output, no new user session.'},
  'lab-exchange-delegation':{app:'Client auth, subject token, actor service credential and delegated result remain distinct.',realmA:'FGAP V2 permission, bounded consent/two-token request and delegated output without refresh.',browser:'Subject client retains its consented subject token while handing a copy to actor app.',realmB:'Temporary delegated API request and exact subject/actor authorization observation.',user:'Bounded explicit consent naming the permitted actor.'},
  'lab-exchange-external-in':{app:'Client auth plus retained assertion/local/narrowed tokens with exact separate lineage.',realmA:'External public trust/account link, consumed assertion-jti record and separate grant requests.',realmB:'External private key and bounded one-time assertion output.'},
  'lab-exchange-external-out':{app:'Retained realm subject, independent auth and received linked external token copy.',realmA:'Existing broker credential/account link; local retrieval preserves external-token identity.',realmB:'Explicit prior-delivery buffer only; retrieval triggers no new external issuance.'},
  'lab-saml-artifact':{...SAML_EMPTY,app:'Original request, private/public trust, artifact/resolve/received layers, then replay/session acceptance.',realmA:'Signing key, trusted SP, retained artifact message/recipient record and bounded SOAP output.',browser:'Temporary opaque artifact only; no assertion or private key reaches this carrier.'},
  'lab-saml-metadata':{...SAML_EMPTY,app:'Own publication, independent IdP trust policy, candidate metadata and later installed next key.',realmA:'Own publication and approved SP trust source, candidate metadata and validated public-key cache.'},
  'lab-saml-validation-failures':{...SAML_EMPTY,app:'Pending request/replay prerequisites and three distinct retained rejected receipts, no SP session.',realmA:'Signing/trust prerequisites and temporary signed denial, no assertion for the denied attempt.',browser:'Explicit prior expired/replayed forms and bounded denied-response carrier.'},
  'lab-saml-sp-slo':{app:'Own key/trust/session and original logout correlation, local invalidation precedes propagation.',realmA:'Authority state and independently correlated original/second-SP exchanges.',realmB:'Own key/trust and participant-specific NameID/session association.',browser:'Bounded signed XML request/response forms only.',user:'Local logout choice, not a new factor credential.'},
  'lab-saml-idp-slo':{app:'Own key/trust/session and independently checked participant request/result.',realmA:'Authority state and independent per-SP exchanges; no fabricated originating-SP request.',realmB:'Separate key/trust/session and second participant exchange.',browser:'Bounded signed XML forms for each participant.',user:'Local authority-logout action, no new account credential.'},
  'lab-saml-soap-slo':{...SAML_EMPTY,app:'Own key/trust/session and direct SOAP exchange, no browser cookie erasure.',realmA:'Authority session and two independently acknowledged SOAP exchanges.',realmB:'Separate key/trust/session and bounded second SOAP exchange.'},
  'lab-direct-grant':{...BRANCH_EMPTY,user:'Temporary legacy password input explicitly exposed to the app.',app:'Backend secret, temporary user password and retained direct token response.',realmA:'Local password verifier/signing key and bounded password request/token output.'},
  'lab-implicit':{...BRANCH_EMPTY,app:'Public JavaScript state/nonce, trusted public key and validated front-channel tokens; no secret.',realmA:'Signing key and bounded request/output after stated prior authentication, no refresh result.',browser:'Bounded authorization navigation and fragment removed on callback processing.'},
  'lab-hybrid':{...BRANCH_EMPTY,app:'Public client private protections, exact front/back generations and verified first identity pair.',realmA:'Signing key, saved one-use code/PKCE context and separate token-endpoint output.',browser:'Bounded token-bearing callback fragment, never the local PKCE verifier.'},
  'lab-consent-denial':{...BRANCH_EMPTY,app:'Independent A/B state and bounded denied callback; no B redemption or token.',realmA:'Separate approval/denial inputs, approved A code and denied B error.',browser:'Bounded decisions/error carrier and explicitly retained unredeemed A callback code.',user:'Separate bounded approval/refusal decisions for independent requests.'},
  'lab-broker-account-link':{...BRANCH_EMPTY,app:'No local password or upstream result is delivered to this initiating app.',realmA:'Upstream public trust/received identity, local account/verifier and verified link record.',realmB:'Own signing key and bounded upstream identity result, never the local password.',browser:'Only the bounded provider-local password form.',user:'Temporary local password proves control before account linking.'},
  'lab-passkey-cancel':{...BRANCH_EMPTY,app:'No successful token, assertion or app-session result in this cancellation excerpt.',realmA:'Fresh challenge, configured fallback and local password verifier/request.',browser:'Fresh challenge, local cancellation and separate bounded password input.',user:'Temporary independent fallback password input.',hello:'Cancellation creates no signed assertion and invokes no successful private-key operation.'},
  'lab-account-recovery':{...BRANCH_EMPTY,app:'Neither reset action credential nor replacement password reaches the OAuth app.',realmA:'Signing key, old/new password verifiers, action/password request and consumed-action replay record.',browser:'Bounded reset URL and replacement-password form.',user:'Reset credential from verified delivery, released on browser presentation.'},
  'lab-concurrent-sessions':{...BRANCH_EMPTY,app:'Backend secret plus retained prior AT/RT, terminal failure without replacement.',realmA:'Retained old session record, explicit revocation authority and bounded cookie/refresh/error.',browser:'Existing provider-cookie bytes remain after server-session revocation.',realmB:'Explicit existing access-token request and local JWT observation without live revocation notice.'},
};

// This table is authored protocol metadata, not a projection of operation verbs,
// attribute catalogs or narrative text. Fields are selected explicitly per object.
function author(args) {
  const plan = createHeldObjectPlan(args);
  const definitions = {...LIFELAB_ATTRIBUTES,...GRANTLAB_ATTRIBUTES,...SAMLLAB_ATTRIBUTES,...BRANCHLAB_ATTRIBUTES,...args.model.definitions()};
  const stores = new Map(Object.keys(args.actors).map(id => [id, new Set()]));
  const categories = new Map(Object.keys(args.actors).map(id => [id, new Set()]));
  const types = new Map();
  const installedIds = new Map();
  const remember = (actor, store, id) => {
    stores.get(actor)?.add(store);
    categories.get(actor)?.add(types.get(id));
  };
  const field = (attributeId, stepId, readableBy) => {
    const step = args.steps.find(item => item.id === stepId);
    const payload = step?.payload?.find(item => item.attributeId === attributeId);
    if(!definitions[attributeId])throw new Error('Unknown explicitly authored web field: '+attributeId);
    return {attributeId, name: definitions[attributeId]?.name || attributeId,
      value: step?.attributeValues?.[attributeId] ?? payload?.value ?? definitions[attributeId]?.example ?? attributeId,
      ...(readableBy ? {readableBy} : {})};
  };
  const at = (step, ...effects) => heldAt(plan, step, ...effects);
  const acquire = (id, actor, store, temporary = false, representationId = 'plain', holdingId) => {
    remember(actor, store, id);
    return heldAcquire(id, actor, store, {retention: temporary ? 'temporary' : 'retained', representationId, ...(holdingId ? {holdingId} : {})});
  };
  const release = (id, actor, store, representationId = 'plain', holdingId) => {
    holdingId ||= store==='credentials' ? installedIds.get(actor+'|'+id+'|'+representationId) : undefined;
    return heldRelease(id,actor,store,{representationId,...(holdingId?{holdingId}:{})});
  };
  const object = (id, type, label, creator, step, fields = [], options = {}) => {
    types.set(id, type);
    const readableBy = options.readableBy || [creator];
    heldArtifact(plan, {artifactId:id, type, label, creator,
      representations: options.representations || [{representationId:'plain', format: options.format || 'symbolic', readableBy,
        fields: fields.map(attributeId => ({...field(attributeId, options.fieldStep || step, readableBy),...(options.values && Object.hasOwn(options.values,attributeId)?{value:options.values[attributeId]}:{})}))}],
      ...(options.derivedFrom ? {derivedFrom:options.derivedFrom} : {}),
      ...(options.replaces ? {replaces:options.replaces} : {}),
      ...(options.related ? {related:options.related} : {}),
      ...(options.details ? {details:options.details} : {})});
    at(step, {op:'create', artifactId:id});
    if (options.store !== false) at(step, acquire(id, creator, options.store || 'credentials', !!options.temporary, options.representationId || 'plain'));
    if (options.releaseAt) at(options.releaseAt, release(id, creator, options.store || 'credentials', options.representationId || 'plain'));
    return id;
  };
  const send = (id, step, from, to, {fromStore = 'credentials', toStore = 'response', releaseAt, retain = false, releaseSender = false, representationId = 'plain', holdingId} = {}) => {
    holdingId ||= [to,id,representationId,toStore,...(retain?[]:[step])].join('|');
    const event = plan.events[step] ||= {milestones:[{id:'complete',at:1,effects:[]}]};
    const messageId=step+':'+from+'->'+to;
    event.messages ||= [];
    let message=event.messages.find(item=>item.messageId===messageId);
    if(!message)event.messages.push(message={messageId,from,to,objects:[],start:0,end:1});
    message.objects.push({artifactId:id,representationId});
    at(step, acquire(id,to,toStore,!retain,representationId,holdingId));
    if (releaseAt) at(releaseAt,release(id,to,toStore,representationId,holdingId));
    if (!retain && !releaseAt) throw new Error('Temporary web receipt needs release: ' + step + ':' + id);
    if (releaseSender) at(step,release(id,from,fromStore,representationId));
  };
  const observe = (id, step, actor, result, detail, kind = 'verification') => at(step,{op:'observe',artifactId:id,actorId:actor,kind,result,detail});
  const authority = (id, step, status, detail) => at(step,{op:'authority',artifactId:id,authorityId:'realmA',status,detail});
  const install = (id, step, actor = 'app', old) => {
    const event = plan.events[step];
    const receipt = Object.values(plan.events).flatMap(item => item.milestones.flatMap(milestone => milestone.effects))
      .find(effect => effect.op === 'acquire' && effect.artifactId === id && effect.actorId === actor && effect.store === 'response');
    if (!receipt) throw new Error('Installation needs an explicit receipt: ' + id);
    const effects = event.milestones.find(milestone => milestone.id === 'complete').effects;
    const removal = effects.findIndex(effect => effect.op === 'release' && effect.holdingId === receipt.holdingId);
    if (removal < 0) throw new Error('Installation needs its authored receipt boundary: ' + id);
    remember(actor,'credentials',id);
    effects[removal] = {op:'move',holdingId:receipt.holdingId,store:'credentials',retention:'retained'};
    installedIds.set(actor+'|'+id+'|plain',receipt.holdingId);
    if (old) at(step,release(old,actor,'credentials'));
  };
  const secret = (id, actor, attributeId, label = id) => object(id,'key',label,actor,null,[attributeId],{store:'configuration'});
  const token = (id, creator, step, attrs, options = {}) => object(id, options.type || 'token', options.label || id, creator,step,attrs,{store:'output',temporary:true,...options});
  const finish = () => {
    const scope=WEB_SCOPE[args.model.id];
    for (const actorId of Object.keys(args.actors)) {
      if (!scope?.[actorId]) throw new Error('Missing explicit web actor scope: '+args.model.id+':'+actorId);
      heldCoverage(plan,actorId,{stores:[...(stores.get(actorId) || [])],categories:[...(categories.get(actorId) || [])],rationale:scope[actorId]});
    }
    if (args.model.id.startsWith('lab-saml-')) plan.limitations.push('Advanced SAML choices are fixed signed-XML fixtures (jweAdaptable=false); encrypted assertion/container delivery is outside this fixed fixture scope. Core owns configured encrypted SAML representations.');
    return plan;
  };
  return {plan,args,at,field,object,send,release,acquire,observe,authority,install,secret,token,finish};
}

function lifeBase(b, {online = false, session = false, second = false, cookie = false, client = false, signing = false, trust = false, sessionPolicy} = {}) {
  if(client)b.secret('client-secret','app','lifeClientSecret','Confidential backend client secret');
  if(client)b.object('client-registration','client-registration','Registered confidential-client credential binding','realmA',null,['lifeClientId','lifeClientSecret'],{store:'configuration'});
  if(signing)b.secret('issuer-key','realmA','lifePrivateSigningKey','Issuer private signing key');
  if(trust)b.secret('issuer-trust','app','lifePublicSigningKey','Trusted issuer public key');
  if (second && trust) b.secret('second-issuer-trust','realmB','lifePublicSigningKey','Second RP issuer trust');
  if (online) b.object('op-session','session','Online OP session','realmA',null,['lifeSsoSession','lifeSessionPolicy'],{store:'sessions',...(sessionPolicy?{values:{lifeSessionPolicy:sessionPolicy}}:{})});
  if (cookie) b.object('op-cookie','cookie','Provider HttpOnly session cookie','realmA',null,['lifeProviderCookie'],{store:false,readableBy:['realmA','browser']});
  if (cookie) b.at(null,b.acquire('op-cookie','browser','cookies'));
  if (session) b.object('app-session','session','Application session and issuer/sid association','app',null,['lifeAppSession','lifeSessionMap','lifeSid'],{store:'sessions'});
  if (second) b.object('second-session','session','Second RP session and issuer/sid association','realmB',null,['lifeAppSession','lifeSessionMap','lifeSid'],{store:'sessions'});
}
function lifeAuth(b, requests) {
  for(const [request,check] of requests) {
    const id='basic:'+request;
    b.token(id,'app',request,['lifeBasic'],{type:'client-authentication',readableBy:['app','realmA'],derivedFrom:['client-secret']});
    b.send(id,request,'app','realmA',{fromStore:'output',toStore:'client-auth-request',releaseAt:check,releaseSender:true});
  }
}
function lifeRequest(b, prefix, {error = false, offline = false} = {}) {
  const p = key => prefix + '-' + key;
  b.object('state','transaction-secret','Authorization state','app',p('prepare'),['lifeState'],{store:'pending',temporary:true,releaseAt:p(error?'next':offline?'issue':'validate')});
  b.object('nonce','transaction-secret','OIDC nonce','app',p('prepare'),['lifeNonce'],{store:'pending',temporary:true,releaseAt:p(error?'next':offline?'issue':'validate')});
  b.object('verifier','transaction-secret','PKCE verifier','app',p('prepare'),['lifeVerifier'],{store:'pending',temporary:true,releaseAt:p(error?'next':'redeem'),readableBy:['app','realmA']});
  b.object('challenge','pkce-commitment','PKCE S256 challenge','app',p('prepare'),['lifeChallenge','lifeChallengeMethod'],{store:'pending',temporary:true,releaseAt:p(error?'next':'redeem'),derivedFrom:['verifier'],readableBy:['app','browser','realmA']});
  b.object('authorization-request','request','Authorization request','app',p('prepare'),['lifeClientId','lifeRedirect','lifeResponseType','lifeScope','lifeState','lifeNonce','lifeChallenge','lifeChallengeMethod',offline?'lifeOfflinePrompt':'lifeSilentPrompt'],{store:'pending',temporary:true,releaseAt:p(error?'next':'redeem'),readableBy:['app','browser','realmA']});
  b.send('authorization-request',p('open'),'app','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p(offline?'authorize':'request')});
  b.send('authorization-request',p(offline?'authorize':'request'),'browser','realmA',{fromStore:'navigation',toStore:'pending',releaseAt:p(error?'fail':offline?'redeem':'redeem')});
  b.send('challenge',p('open'),'app','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p(offline?'authorize':'request')});
  b.send('challenge',p(offline?'authorize':'request'),'browser','realmA',{fromStore:'navigation',toStore:'pending-pkce',releaseAt:p(error?'fail':'redeem')});
  if (!error) {
    b.object('code','authorization-code','One-use authorization code','realmA',p(offline?'accept':'check'),['lifeCode'],{store:'pending',temporary:true,releaseAt:p('redeem'),readableBy:['realmA','browser','app'],related:['challenge']});
    b.send('code',p('redirect'),'realmA','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p('callback')});
    b.send('code',p('callback'),'browser','app',{fromStore:'navigation',toStore:'pending',releaseAt:p('redeem')});
    b.send('verifier',p('redeem'),'app','realmA',{fromStore:'pending',toStore:'request',releaseAt:p('redeem')});
    b.authority('code',p('redeem'),'consumed','Successful client, redirect and S256-bound code redemption.');
  }
}
function lifeRotation(b) {
  const p = key => 'lab-refresh-rotation-' + key;
  lifeBase(b,{online:true,session:true,client:true,signing:true,trust:true});
  lifeAuth(b,[[p('request'),p('check')],[p('reuse'),p('reject')]]);
  b.object('R0','refresh-token','refresh_token R0','realmA',null,['lifeRefreshToken'],{store:false,readableBy:['app','realmA']});
  b.object('AT0','access-token','access_token AT0','realmA',null,['lifeAccessToken'],{store:false,readableBy:['app','realmA']});
  b.object('ID0','id-token','Original ID token and identity binding','realmA',null,['lifeOriginalIdentity','lifeIdToken','lifeAuthTime'],{store:false,readableBy:['app','realmA']});
  b.at(null,...['R0','AT0','ID0'].map(id=>b.acquire(id,'app','credentials')));
  // A queued request owns captured bytes, not a second current credential.
  b.object('queued-R0-request','request','Queued duplicate refresh request containing R0','app',p('prepare'),['lifeRefreshToken','lifeGrant'],{store:'queued-request',temporary:true,releaseAt:p('reuse'),related:['R0'],readableBy:['app','realmA']});
  b.send('R0',p('request'),'app','realmA',{toStore:'request',releaseAt:p('check')});
  b.authority('R0',p('check'),'consumed','Strict rotation/no accepted reuse. Client has not received a replacement.');
  for (const [id,attrs,old] of [['R1',['lifeReplacementRefresh'],'R0'],['AT1',['lifeAccessToken'],'AT0'],['ID1',['lifeIdToken','lifeIdIssuer','lifeIdSubject','lifeIdAudience','lifeIdIssuedAt','lifeIdExpiresAt','lifeAuthTime'],'ID0']]) {
    b.token(id,'realmA',p('issue'),attrs,{readableBy:['realmA','app'],derivedFrom:[old],replaces:[old]});
    b.send(id,p('response'),'realmA','app',{fromStore:'output',releaseAt:p('replace'),releaseSender:true});
    b.install(id,p('replace'),'app',old);
  }
  // These milestones are protocol boundaries authored here, not field-chip stages.
  const event=b.plan.events[p('response')];
  event.milestones=[{id:'delayed-response',at:0.25,effects:[]},{id:'received',at:0.75,effects:event.milestones[0].effects},{id:'complete',at:1,effects:[]}];
  for(const message of event.messages)message.end=0.75;
  b.observe('ID1',p('replace'),'app','accepted','Trusted signature, iss/sub/aud/auth_time and refreshed validity checked before installation.');
  b.send('queued-R0-request',p('reuse'),'app','realmA',{fromStore:'queued-request',toStore:'request',releaseAt:p('reject')});
  b.observe('R0',p('reject'),'realmA','invalid_grant','Old captured request rejected; current R1 and AT1 are not erased.');
  lifeError(b,p('reject'),p('error'),'R0');
}
function lifeError(b,create,delivery,related,attr='lifeTokenError') {
  const id=delivery+'-error';
  b.token(id,'realmA',create,[attr],{type:'error',readableBy:['realmA','app'],...(related?{related:[related]}:{})});
  b.send(id,delivery,'realmA','app',{fromStore:'output',toStore:'error-response',releaseAt:delivery,releaseSender:true});
  b.observe(id,delivery,'app','error received','Request-scoped failure; no replacement tokens or global API invalidation.','knowledge');
}
function lifeOffline(b) {
  const p=key=>'lab-offline-access-'+key;
  lifeBase(b,{online:true,cookie:true,client:true,signing:true,trust:true});
  lifeRequest(b,'lab-offline-access',{offline:true});
  lifeAuth(b,[[p('redeem'),p('issue')],[p('refresh-later'),p('replacement')]]);
  b.object('consent','consent','Authenticated offline consent','user',p('approve'),['lifeConsent'],{store:'decision',temporary:true,releaseAt:p('accept'),readableBy:['user','browser','realmA']});
  b.send('consent',p('approve'),'user','browser',{fromStore:'decision',toStore:'form',releaseAt:p('accept')});
  b.send('consent',p('accept'),'browser','realmA',{fromStore:'form',toStore:'request',releaseAt:p('issue')});
  b.object('offline-session','session','Offline grant/session with independent idle/max policy','realmA',p('issue'),['lifeOfflineSession','lifeOfflinePolicy'],{store:'offline-sessions',values:{lifeOfflinePolicy:{profile:'Illustrative authored local policy, not a product default',idleDeadlineClock:3600,maxLimited:true,maxDeadlineClock:86400,clientAllowed:true,revoked:false}}});
  for(const [id,attrs] of [['ROff0',['lifeOfflineToken']],['AT0',['lifeAccessToken']],['ID0',['lifeIdToken','lifeNonce','lifeAuthTime']]]) {
    b.token(id,'realmA',p('issue'),attrs,{readableBy:['realmA','app'],related:['offline-session']});
    b.send(id,p('issue'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  }
  b.at(p('refresh-later'),{op:'advance',value:600},b.release('op-cookie','browser','cookies'),b.release('op-session','realmA','sessions'));
  b.authority('op-session',p('refresh-later'),'ended','Intervening browser logout ends only the ordinary online session.');
  b.send('ROff0',p('refresh-later'),'app','realmA',{toStore:'request',releaseAt:p('replacement')});
  b.observe('offline-session',p('refresh-later'),'realmA','accepted','Authored clock 600 is before offline idle deadline 3600 and enabled max deadline 86400; client eligibility is true and revocation false. Online SSO termination is independent.');
  b.authority('ROff0',p('replacement'),'consumed','Chosen offline refresh rotation policy.');
  for(const [id,attrs,old] of [['ROff1',['lifeOfflineReplacement'],'ROff0'],['AT1',['lifeAccessToken'],'AT0']]) {
    b.token(id,'realmA',p('replacement'),attrs,{readableBy:['realmA','app'],derivedFrom:[old],replaces:[old],related:['offline-session']});
    b.send(id,p('replacement'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
    b.at(p('replacement'),b.release(old,'app','credentials'));
  }
}
function lifeRevocation(b) {
  const p=key=>'lab-token-revocation-'+key;
  lifeBase(b,{client:true});
  lifeAuth(b,[[p('request'),p('invalidate')],[p('unknown'),p('unknown-check')]]);
  b.object('R0','refresh-token','Previously issued refresh credential','realmA',null,['lifeRevokeToken'],{store:false,readableBy:['realmA','app']});
  b.at(null,b.acquire('R0','app','credentials'));
  b.send('R0',p('request'),'app','realmA',{toStore:'request',releaseAt:p('invalidate')});
  b.authority('R0',p('invalidate'),'revoked','Issuer revocation is independent of retained client bytes and API knowledge.');
  b.observe('R0',p('ok'),'app','revocation acknowledged','Bodyless 200 discloses no token existence/status at other APIs.','knowledge');
  b.at(p('forget'),b.release('R0','app','credentials'));
  b.object('unknown-token','unknown-credential','Deliberately unknown revocation input','app',p('unknown'),['lifeRevokeToken'],{store:'request',temporary:true,releaseAt:p('unknown-ok'),readableBy:['app','realmA'],fieldStep:p('unknown')});
  b.send('unknown-token',p('unknown'),'app','realmA',{fromStore:'request',toStore:'request',releaseAt:p('unknown-check')});
  b.observe('unknown-token',p('unknown-ok'),'app','revocation acknowledged','Same bodyless HTTP 200, without an exists flag.','knowledge');
  b.object('api-validation-policy','policy','Independent API JWT revocation visibility','realmB',null,['lifeApiRevocationPolicy'],{store:'configuration'});
  b.observe('api-validation-policy',p('api-caveat'),'realmB','no issuer notification','No token-specific status observation or automatic invalidation is authored.','knowledge');
}
function lifeRpLogout(b) {
  const p=key=>'lab-rp-initiated-logout-'+key;
  lifeBase(b,{online:true,session:true,cookie:true});
  b.object('ID-hint','id-token','Prior ID token used only as logout hint','realmA',null,['lifeIdTokenHint'],{store:false,readableBy:['realmA','app','browser']});
  b.at(null,b.acquire('ID-hint','app','credentials'));
  b.at(p('prepare'),b.release('app-session','app','sessions'));
  b.object('logout-state','transaction-secret','Independent logout callback state','app',p('prepare'),['lifeLogoutState'],{store:'pending',temporary:true,releaseAt:p('finish'),readableBy:['app','browser','realmA']});
  b.send('ID-hint',p('open'),'app','browser',{toStore:'navigation',releaseAt:p('request')});
  b.send('ID-hint',p('request'),'browser','realmA',{fromStore:'navigation',toStore:'request',releaseAt:p('check')});
  b.observe('ID-hint',p('check'),'realmA','accepted for logout','Issuer, client/session and exact post-logout URI checked; this is not login/API acceptance.');
  b.authority('op-session',p('end'),'ended','Online OP session terminated; no offline grant cascade.');
  b.at(p('end'),b.release('op-session','realmA','sessions'));
  b.at(p('redirect'),b.release('op-cookie','browser','cookies'));
  b.send('logout-state',p('open'),'app','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p('request')});
  b.send('logout-state',p('request'),'browser','realmA',{fromStore:'navigation',toStore:'pending',releaseAt:p('redirect')});
  b.send('logout-state',p('redirect'),'realmA','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p('callback')});
  b.send('logout-state',p('callback'),'browser','app',{fromStore:'navigation',toStore:'response',releaseAt:p('finish')});
  b.observe('logout-state',p('finish'),'app','matched','No new login/session is created.');
}
function lifeBackLogout(b) {
  const p=key=>'lab-backchannel-logout-'+key;
  lifeBase(b,{online:true,session:true,second:true,signing:true,trust:true});
  b.authority('op-session',p('trigger'),'ended','OP logout does not imply recipient delivery.');
  b.at(p('trigger'),b.release('op-session','realmA','sessions'));
  const attrs=['lifeLogoutToken','lifeLogoutIssuer','lifeLogoutAudience','lifeLogoutIssuedAt','lifeLogoutExpiresAt','lifeLogoutJti','lifeSid','lifeLogoutSubject','lifeLogoutEvents','lifeLogoutTyp'];
  for(const [id,create,deliver,apply,actor,session] of [['J0','sign','notify','session','app','app-session'],['J1','second','second','second-apply','realmB','second-session'],['J2','fresh-sign','fresh-notify','fresh-apply','app',null]]) {
    // J0's explicit delivery-retry buffer is retained until its duplicate leg.
    b.object(id,'logout-token','Recipient-specific signed logout event '+id,'realmA',p(create),attrs,{store:'notification-buffer',temporary:true,releaseAt:p(id==='J0'?'duplicate':id==='J1'?'second':'fresh-notify'),readableBy:['realmA',actor],fieldStep:p(create),related:[actor==='app'?'app-session':'second-session']});
    b.send(id,p(deliver),'realmA',actor,{fromStore:'notification-buffer',toStore:'logout-request',releaseAt:p(apply)});
    b.observe(id,p(apply),actor,'accepted','Exact recipient audience, issuer, exp/iat, purpose, sid/sub and local replay/session association verified.');
    b.object(id+'-replay','replay-record','Accepted issuer/jti '+id,actor,p(apply),['lifeReplayCache','lifeLogoutJti'],{store:'replay-cache',related:[id],fieldStep:p(apply)});
    if(session)b.at(p(apply),b.release(session,actor,'sessions'));
  }
  b.send('J0',p('duplicate'),'realmA','app',{fromStore:'notification-buffer',toStore:'duplicate-request',releaseAt:p('duplicate-check')});
  b.observe('J0',p('duplicate-check'),'app','replay rejected','Enabled issuer/J0 replay validation fails; HTTP 400, no repeated session mutation.');
  b.observe('J2',p('fresh-response'),'realmA','HTTP 200 acknowledged','Fresh valid event for an already-ended local session succeeds.','knowledge');
}
function lifeFrontLogout(b) {
  const p=key=>'lab-frontchannel-logout-'+key;
  lifeBase(b,{online:true,session:true,second:true,cookie:true});
  b.object('app-cookie','cookie','First RP browser session cookie','app',null,['lifeAppCookie'],{store:false,readableBy:['app','browser']});
  b.at(null,b.acquire('app-cookie','browser','cookies'));
  b.object('second-browser-state','session','Second RP browser login state','realmB',null,['lifeAppSession'],{store:false,readableBy:['realmB']});
  b.at(null,b.acquire('second-browser-state','browser','second-origin-storage'));
  b.at(p('start'),b.release('op-session','realmA','sessions'));
  b.object('iframes','logout-request','Registered first/second iframe destinations with issuer/sid','realmA',p('start'),['lifeIframe','lifeLogoutIssuer','lifeSid','lifeFrontchannelUri','lifeOtherFrontchannelUri'],{store:'output',temporary:true,releaseAt:p('page'),readableBy:['realmA','browser','app','realmB']});
  b.send('iframes',p('page'),'realmA','browser',{fromStore:'output',toStore:'document',releaseAt:p('blocked')});
  b.at(p('page'),b.release('op-cookie','browser','cookies'));
  b.send('iframes',p('first-get'),'browser','app',{fromStore:'document',toStore:'request',releaseAt:p('first-clear')});
  b.observe('iframes',p('first-clear'),'app','matched','Trusted issuer/sid mapping and allowed cookie select the first RP session.');
  b.at(p('first-clear'),b.release('app-session','app','sessions'));
  b.at(p('first-response'),b.release('app-cookie','browser','cookies'));
  b.send('iframes',p('second-get'),'browser','realmB',{fromStore:'document',toStore:'request',releaseAt:p('second-script')});
  b.observe('second-browser-state',p('blocked'),'browser','incomplete/unknown','The authored third-party storage policy blocks the required browser operation; second RP holdings remain.','knowledge');
}
function lifeSilent(b,error) {
  const prefix=error?'lab-sso-login-required':'lab-sso-existing-session',p=key=>prefix+'-'+key;
  lifeBase(b,{online:!error,cookie:!error,client:true,signing:!error,trust:!error});
  b.object('ID-hint','id-token','Prior-session ID-token hint','realmA',null,['lifeIdTokenHint'],{store:false,readableBy:['realmA','app']});
  b.at(null,b.acquire('ID-hint','app','credentials'));
  lifeRequest(b,prefix,{error});
  if(!error)lifeAuth(b,[[p('redeem'),p('tokens')]]);
  if(error) {
    b.token('silent-error','realmA',p('fail'),['lifeAuthorizationError'],{type:'error',readableBy:['realmA','browser','app']});
    b.send('silent-error',p('redirect'),'realmA','browser',{fromStore:'output',toStore:'navigation',releaseAt:p('callback'),releaseSender:true});
    b.send('silent-error',p('callback'),'browser','app',{fromStore:'navigation',toStore:'error-response',releaseAt:p('next')});
    b.observe('silent-error',p('callback'),'app','login_required received','State-correlated error, no code/tokens/app session.','knowledge');
  } else {
    b.observe('op-session',p('check'),'realmA','accepted','Existing authentication and consent suffice; no new factor ceremony.');
    for(const [id,attrs] of [['AT1',['lifeAccessToken']],['ID1',['lifeIdToken','lifeIdIssuer','lifeIdSubject','lifeIdAudience','lifeAuthTime','lifeNonce']]]) {
      b.token(id,'realmA',p('tokens'),attrs,{readableBy:['realmA','app']});
      b.send(id,p('tokens'),'realmA','app',{fromStore:'output',releaseAt:p('validate'),releaseSender:true});
      b.install(id,p('validate'));
    }
    b.observe('ID1',p('validate'),'app','accepted','Signature, issuer/audience/time and original request nonce checked.');
    b.object('app-session','session','Validated silent SSO application session','app',p('validate'),['lifeAppSession'],{store:'sessions',derivedFrom:['ID1']});
  }
}
function lifeExpiry(b) {
  const p=key=>'lab-session-expiry-'+key;
  lifeBase(b,{online:true,session:true,client:true,sessionPolicy:{profile:'Illustrative authored local policy, not a product default',idleDeadlineClock:1200,maxDeadlineClock:7200}});
  lifeAuth(b,[[p('request'),p('reject')]]);
  for(const [id,attr] of [['R0','lifeRefreshToken'],['AT0','lifeAccessToken']]) {
    b.object(id,id==='R0'?'refresh-token':'access-token',id,'realmA',null,[attr],{store:false,readableBy:['realmA','app']});
    b.at(null,b.acquire(id,'app','credentials'));
  }
  b.at(p('deadline'),{op:'advance',value:1201});
  b.authority('op-session',p('deadline'),'expired','Authored online idle/max deadline, not animation wall time.');
  b.send('R0',p('request'),'app','realmA',{toStore:'request',releaseAt:p('reject')});
  b.observe('R0',p('reject'),'realmA','invalid_grant','Expired online session; retained token bytes are not replacement authority.');
  lifeError(b,p('reject'),p('error'),'R0');
  b.at(p('recover'),b.release('R0','app','credentials'),b.release('app-session','app','sessions'));
}

function grantPrefix(id) { return 'grant'+id.replace(/^lab-/,'').split('-').map(part=>part[0].toUpperCase()+part.slice(1)).join(''); }
function grantBase(b,{external=false}={}) {
  const a=suffix=>grantPrefix(b.args.model.id)+suffix;
  const authentication=a(b.args.model.id.startsWith('lab-ciba-')?'ClientAuth':'Auth');
  b.object('client-auth','client-authentication','Configured confidential backend authentication','app',null,[authentication],{store:'configuration',readableBy:['app','realmA']});
  b.object('client-registration','client-registration','Registered confidential-client authentication binding','realmA',null,[authentication],{store:'configuration'});
  if(b.args.model.id.startsWith('lab-ciba-')) {
    b.secret('issuer-signing','realmA',a('SigningKey'),'Issuer private signing key');
    b.secret('issuer-trust','app',a('VerificationKey'),'Trusted issuer verification key');
  } else if(['lab-exchange-id-token','lab-exchange-refresh-token'].includes(b.args.model.id)) {
    b.secret('issuer-trust','app',a('Key'),'Trusted issuer verification key');
  }
  if(external) {
    b.secret('external-signing','realmB',a('SigningKey'),'External issuer private key');
    b.secret('external-trust','realmA',a('VerificationKey'),'Trusted external issuer public key');
  }
  return a;
}
function grantCiba(b) {
  const id=b.args.model.id,p=key=>id+'-'+key,a=grantBase(b),push=id==='lab-ciba-push',hint=id==='lab-ciba-hint-token';
  b.send('client-auth',p('request'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p(hint?'hint-check':'delegate')});
  if(!push)b.send('client-auth',p('fetch'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('tokens')});
  b.object('pending-client','transaction','Client pending CIBA transaction','app',p('prepare'),[a('Cue'),a('Delivery'),...(hint?[]:[a('NotificationToken'),a('Callback')])],{store:'pending',temporary:true,releaseAt:p('done')});
  if(hint) {
    b.secret('hint-trust','realmA',a('HintKey'),'Trusted signed-hint profile verification key');
    b.object('hint','identifying-hint','Signed login_hint_token (not login proof)','app',p('prepare'),[a('Hint'),a('HintIssuer'),a('HintSubject'),a('HintExpiry')],{store:'pending',temporary:true,releaseAt:p('done'),readableBy:['app','realmA']});
    b.send('hint',p('request'),'app','realmA',{fromStore:'pending',toStore:'request',releaseAt:p('hint-check')});
    b.observe('hint',p('hint-check'),'realmA','identification only','Configured hint signature, issuer and expiry checked; approval still pending.');
  } else {
    b.object('notification-secret','callback-credential','Client notification bearer credential','app',p('prepare'),[a('NotificationToken')],{store:'pending',temporary:true,releaseAt:p('done'),readableBy:['app','realmA']});
    b.send('notification-secret',p('request'),'app','realmA',{fromStore:'pending',toStore:'pending',releaseAt:p('ack')});
  }
  b.object('handle','transaction-handle','auth_req_id (pending, no tokens)','realmA',p('delegate'),[a('Handle'),a('Lifetime')],{store:'pending',temporary:true,releaseAt:p(push?'push':'tokens'),readableBy:['realmA','app'],related:['pending-client']});
  b.object('provider-pending','transaction','Provider pending CIBA approval record','realmA',p('delegate'),[a('Handle'),a('Hint'),a('Lifetime'),a('Cue')],{store:'transactions',temporary:true,releaseAt:p(push?'push':'tokens')});
  b.object('service-callback','callback-credential','Controlled-service callback credential','realmA',p('delegate'),[a('ChannelCredential')],{store:'pending',temporary:true,releaseAt:p('issuer'),readableBy:['realmA','realmB']});
  b.send('service-callback',p('delegate'),'realmA','realmB',{fromStore:'pending',toStore:'pending',releaseAt:p('controlled-result')});
  b.object('service-pending','transaction','Controlled-service intended person and matching request','realmB',p('delegate-ack'),[a('Hint'),a('Cue')],{store:'transactions',temporary:true,releaseAt:p('proof-check'),related:['provider-pending']});
  b.send('service-callback',p('controlled-result'),'realmB','realmA',{fromStore:'pending',toStore:'callback-request',releaseAt:p('issuer')});
  b.send('handle',p('handle'),'realmA','app',{fromStore:'pending',toStore:'pending',releaseAt:p('done')});
  if(!hint) {
    const callback=p(push?'push':'ping'),check=p(push?'push-check':'ping-check');
    b.send('notification-secret',callback,'realmA','app',{fromStore:'pending',toStore:'callback-request',releaseAt:check});
    b.send('handle',callback,'realmA','app',{fromStore:'pending',toStore:'callback-request',releaseAt:check});
  }
  b.object('approval-proof','factor-proof','Transaction-bound device verification and approval','user',p('approve'),[a('DeviceProof')],{store:'local-input',temporary:true,releaseAt:p('proof'),readableBy:['user','browser','realmB']});
  b.send('approval-proof',p('approve'),'user','browser',{fromStore:'local-input',toStore:'form',releaseAt:p('proof')});
  b.send('approval-proof',p('proof'),'browser','realmB',{fromStore:'form',toStore:'request',releaseAt:p('proof-check')});
  b.observe('approval-proof',p('proof-check'),'realmB','verified','Required factor, actual intended person, matching cue and explicit authorization verified.');
  b.object('controlled-result','authentication-result','Authenticated controlled-service outcome','realmB',p('proof-check'),[a('Status')],{store:'output',temporary:true,releaseAt:p('controlled-result'),readableBy:['realmB','realmA'],related:['approval-proof']});
  b.send('controlled-result',p('controlled-result'),'realmB','realmA',{fromStore:'output',toStore:'request',releaseAt:p('issuer')});
  b.observe('provider-pending',p('issuer'),'realmA','approved','Trusted service callback, client ownership, lifetime and explicit approval checked.');
  const claimAttrs=[a('Issuer'),a('Audience'),a('Expiry'),a('Subject'),a('IssuedAt'),...(push?[a('AtHash'),a('RtHash'),a('BoundHandle')]:[])];
  for(const [token,attrs] of [['AT',[a('Access')]],['RT',[a('Refresh')]],['ID',[a('Identity'),...claimAttrs]]]) {
    b.token(token,'realmA',p('issuer'),attrs,{readableBy:['realmA','app'],related:['provider-pending']});
    b.send(token,p(push?'push':'tokens'),'realmA','app',{fromStore:'output',releaseAt:p(push?'push-check':'validate'),releaseSender:true});
    b.install(token,p(push?'push-check':'validate'));
  }
  b.authority('handle',p(push?'push':'tokens'),'consumed','One successful result delivery/redeeming client-bound request.');
  b.observe('ID',p(push?'push-check':'validate'),'app','accepted',push?'Callback bearer and signed auth_req_id, at_hash, rt_hash plus issuer/audience/expiry verified.':'Issuer signature, exact issuer/client audience and token lifetime verified independently of notification.');
  if(!push&&!hint)b.observe('handle',p('ping-check'),'app','notification authenticated','Ping carries only handle; issued tokens are still absent from client inventory.');
}
function grantExchange(b) {
  const id=b.args.model.id,p=key=>id+'-'+key,a=grantBase(b),identity=id==='lab-exchange-id-token';
  b.send('client-auth',p('request'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('policy')});
  b.object('subject','access-token','Original same-realm subject access token','realmA',null,[a('Subject')],{store:false,readableBy:['realmA','app']});
  b.at(null,b.acquire('subject','app','credentials'));
  b.object('exchange-policy','policy','Configured allowed exchange result/session policy','realmA',null,[a('Permission')],{store:'configuration'});
  b.send('subject',p('request'),'app','realmA',{toStore:'request',releaseAt:p('policy')});
  b.observe('subject',p('policy'),'realmA','accepted','Requester authenticated and entitled to same-realm subject; result policy checked without consuming input.');
  for(const [token,attrs,type] of [['result',[a('Result'),a('Issuer'),a('Audience'),a('Expiry'),a('SubjectId'),a('IssuedAt')],identity?'id-token':'access-token'],...(!identity?[['refresh',[a('Refresh')],'refresh-token']]:[])]) {
    b.token(token,'realmA',p('policy'),attrs,{type,readableBy:['realmA','app'],derivedFrom:['subject']});
    b.send(token,p('response'),'realmA','app',{fromStore:'output',releaseAt:p('interpret'),releaseSender:true});
    b.install(token,p('interpret'));
  }
  b.observe('result',p('interpret'),'app','accepted',identity?'issued_token_type=id_token and token_type=N_A; validate identity, never API bearer authorization.':'Provider-specific refresh descriptor convention; distinct access and refresh credential, same online session required.');
}
function grantDelegation(b) {
  const id=b.args.model.id,p=key=>id+'-'+key,a=grantBase(b);
  b.send('client-auth',p('actor-request'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('actor-result')});
  b.send('client-auth',p('exchange'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('relationship')});
  b.object('permission','policy','FGAP V2 actor delegation permission','realmA',null,[a('Permission')],{store:'configuration'});
  b.object('consent','consent','Explicit named-actor delegation consent','user',p('consent'),[a('Consent')],{store:'decision',temporary:true,releaseAt:p('submit'),readableBy:['user','browser','realmA']});
  b.send('consent',p('consent'),'user','browser',{fromStore:'decision',toStore:'form',releaseAt:p('submit')});
  b.send('consent',p('submit'),'browser','realmA',{fromStore:'form',toStore:'pending',releaseAt:p('mint-subject')});
  b.token('subject','realmA',p('mint-subject'),[a('Subject'),a('MayAct'),a('SubjectId'),a('Audience')],{type:'access-token',readableBy:['realmA','browser','app'],related:['permission','consent']});
  b.send('subject',p('subject-response'),'realmA','browser',{fromStore:'output',toStore:'credentials',retain:true,releaseSender:true});
  b.send('subject',p('handoff'),'browser','app',{retain:true,toStore:'credentials'});
  b.token('actor','realmA',p('actor-result'),[a('Actor')],{type:'access-token',readableBy:['realmA','app']});
  b.send('actor',p('actor-result'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  for(const token of ['subject','actor'])b.send(token,p('exchange'),'app','realmA',{toStore:'request',releaseAt:p('relationship')});
  b.token('delegated','realmA',p('relationship'),[a('Result'),a('SubjectId'),a('Act')],{type:'access-token',readableBy:['realmA','app','realmB'],derivedFrom:['subject','actor']});
  b.send('delegated',p('result'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  b.send('delegated',p('api'),'app','realmB',{toStore:'request',releaseAt:p('api')});
  b.observe('delegated',p('api'),'realmB','authorized','Exact target audience/scopes, original subject and actual act checked for this resource request.','acceptance');
}
function grantExternalIn(b) {
  const id=b.args.model.id,p=key=>id+'-'+key,a=grantBase(b,{external:true});
  b.send('client-auth',p('jwt-request'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('trust')});
  b.send('client-auth',p('v2'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('v2-policy')});
  b.object('account-link','identity-link','Previously verified external subject/local account link','realmA',null,[a('AccountLink')],{store:'accounts'});
  b.token('assertion','realmB',p('external-sign'),[a('Assertion'),a('Issuer'),a('Subject'),a('Audience'),a('Expiry'),a('Jti')],{type:'jwt-grant-assertion',readableBy:['realmB','app','realmA']});
  b.send('assertion',p('assertion'),'realmB','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  b.send('assertion',p('jwt-request'),'app','realmA',{toStore:'request',releaseAt:p('trust')});
  b.authority('assertion',p('trust'),'consumed','One-time JWT grant assertion jti consumed; client copy is not implicitly erased.');
  b.object('assertion-replay','replay-record','Consumed external assertion jti','realmA',p('trust'),[a('Jti')],{store:'replay-cache',related:['assertion']});
  b.token('local','realmA',p('trust'),[a('Local'),a('LocalSubject')],{type:'access-token',readableBy:['realmA','app'],derivedFrom:['assertion'],related:['account-link']});
  b.send('local',p('local-result'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  b.send('local',p('v2'),'app','realmA',{toStore:'request',releaseAt:p('v2-policy')});
  b.token('narrowed','realmA',p('v2-policy'),[a('Result'),a('Target')],{type:'access-token',readableBy:['realmA','app'],derivedFrom:['local']});
  b.send('narrowed',p('final'),'realmA','app',{fromStore:'output',retain:true,toStore:'credentials',releaseSender:true});
  b.observe('narrowed',p('final'),'app','received','Separate permitted internal V2 audience result; original local and external inputs remain.','knowledge');
}
function grantExternalOut(b) {
  const id=b.args.model.id,p=key=>id+'-'+key,a=grantBase(b);
  b.send('client-auth',p('request'),'app','realmA',{fromStore:'configuration',toStore:'client-auth-request',releaseAt:p('retrieval')});
  b.object('subject','access-token','Existing entitled realm subject token','realmA',null,[a('Subject')],{store:false,readableBy:['realmA','app']});
  b.at(null,b.acquire('subject','app','credentials'));
  b.object('external','access-token','Previously issued linked external token','realmB',null,[a('External')],{store:'prior-delivery',temporary:true,releaseAt:p('earlier-provider'),readableBy:['realmB','realmA','app']});
  b.send('external',p('earlier-provider'),'realmB','realmA',{fromStore:'prior-delivery',retain:true,toStore:'broker-credentials'});
  b.object('account-link','identity-link','Stored broker token/account association','realmA',null,[a('Stored'),a('Permission')],{store:'accounts',related:['external']});
  b.send('subject',p('request'),'app','realmA',{toStore:'request',releaseAt:p('retrieval')});
  b.observe('external',p('retrieval'),'realmA','retrieval authorized','Legacy V1/FGAP V1 permission, entitled subject, provider alias and retained linked credential verified. No external issuance.');
  b.send('external',p('result'),'realmA','app',{fromStore:'broker-credentials',retain:true,toStore:'credentials'});
}

function samlBase(b,{second=false}={}) {
  b.secret('idp-private','realmA','slIdpPrivateKey','IdP private signing key');
  b.secret('sp-private','app','slSpPrivateKey','SP private signing key');
  b.secret('idp-trust','app','slTrustedCert','SP trusted IdP public certificate');
  b.secret('sp-trust','realmA','slTrustedCert','IdP trusted SP public certificate');
  if(second) {
    b.secret('second-private','realmB','slOtherPrivateKey','SP 2 private signing key');
    b.secret('second-idp-trust','realmB','slTrustedCert','SP 2 trusted IdP public certificate');
    b.secret('second-sp-trust','realmA','slTrustedCert','IdP trusted SP 2 public certificate');
  }
}
const ASSERTION_FIELDS=['slAssertion','slAssertionID','slIssuer','slAudience','slRecipient','slNotBefore','slNotOnOrAfter','slNameIDApp','slSessionIndexApp','slSignature'];
function samlArtifact(b) {
  samlBase(b);
  const p=key=>'sl-artifact-'+key;
  b.object('authn-request','transaction','Original SP AuthnRequest correlation','app',null,['slAuthnID'],{store:'pending',temporary:true,releaseAt:p('validate')});
  b.object('assertion','saml-assertion','Signed subject assertion','realmA',p('build'),ASSERTION_FIELDS,{store:'artifact-message',temporary:true,releaseAt:p('response'),readableBy:['realmA','app']});
  b.object('response','saml-response','Original signed SAML Response','realmA',p('build'),['slResponse','slInnerCorrelation','slStatus'],{store:'artifact-message',temporary:true,releaseAt:p('response'),readableBy:['realmA','app'],related:['assertion']});
  b.object('artifact','saml-artifact','Opaque one-use SAML artifact','realmA',p('build'),['slSamlart','slTypeCode','slEndpointIndex','slSourceID','slMessageHandle'],{store:'artifact-store',temporary:true,releaseAt:p('consume'),readableBy:['realmA','browser','app'],related:['response']});
  b.object('artifact-record','transaction','Artifact recipient/message/expiry/use association','realmA',p('build'),['slArtifactStore'],{store:'artifact-records',related:['artifact','response']});
  b.send('artifact',p('browser'),'realmA','browser',{fromStore:'artifact-store',toStore:'navigation',releaseAt:p('acs')});
  b.send('artifact',p('acs'),'browser','app',{fromStore:'navigation',toStore:'pending',releaseAt:p('validate')});
  b.object('resolve','saml-request','Signed ArtifactResolve with independent ID','app',p('resolve-build'),['slArtifactResolve','slResolveID','slArtifact','slIssuer','slDestination','slSignature'],{store:'pending',temporary:true,releaseAt:p('validate'),readableBy:['app','realmA'],related:['artifact']});
  b.send('resolve',p('resolve'),'app','realmA',{fromStore:'pending',toStore:'request',releaseAt:p('consume')});
  b.authority('artifact',p('consume'),'consumed','Authenticated intended SP, valid unused reference and expiry checked.');
  b.object('resolved-container','saml-artifact-response','Signed outer ArtifactResponse','realmA',p('consume'),['slArtifactResponse','slOuterCorrelation','slStatus'],{store:'output',temporary:true,releaseAt:p('response'),readableBy:['realmA','app'],related:['response','assertion','resolve']});
  for(const [id,store] of [['resolved-container','output'],['response','artifact-message'],['assertion','artifact-message']])b.send(id,p('response'),'realmA','app',{fromStore:store,toStore:'response',releaseAt:p('validate')});
  b.observe('assertion',p('validate'),'app','accepted','Outer resolve correlation and inner AuthnRequest correlation, signatures, recipient/audience/time and replay checks all succeed.');
  b.object('assertion-replay','replay-record','Accepted assertion/response IDs','app',p('validate'),['slReplayCache'],{store:'replay-cache',related:['assertion','response']});
  b.object('sp-session','session','SP session created after assertion acceptance','app',p('validate'),['slAppSession','slNameIDApp','slSessionIndexApp'],{store:'sessions',derivedFrom:['assertion']});
}
function samlMetadata(b) {
  samlBase(b);
  b.object('metadata-policy-idp','trust-policy','IdP approved SP metadata source/entity/trust','realmA',null,['slMetadataTrust','slMetadataURL','slMetadataEntityID'],{store:'configuration',fieldStep:'sl-meta-bootstrap'});
  b.object('metadata-policy-sp','trust-policy','SP independently approved IdP metadata trust','app',null,['slMetadataTrust','slMetadataURL'],{store:'configuration',fieldStep:'sl-meta-fetch-idp'});
  b.object('sp-metadata','metadata','SP EntityDescriptor and public signing/encryption certificates','app',null,['slMetadataDocument','slMetadataEntityID','slMetadataSpRole','slMetadataAcs','slMetadataBinding','slMetadataLocation','slMetadataSigningCert','slMetadataEncryptionCert','slMetadataValidUntil','slMetadataCacheDuration'],{store:'publication',readableBy:['app','realmA'],fieldStep:'sl-meta-sp-response'});
  b.send('sp-metadata','sl-meta-sp-response','app','realmA',{fromStore:'publication',toStore:'candidate-metadata',releaseAt:'sl-meta-validate-sp'});
  b.observe('sp-metadata','sl-meta-validate-sp','realmA','trusted and installed','Prior trust, expected entity/role, endpoint bindings and freshness checked before key installation.');
  b.object('installed-sp-trust','trust-cache','Installed SP public signing/encryption trust','realmA','sl-meta-validate-sp',['slMetadataSigningCert','slMetadataEncryptionCert'],{store:'trust-cache',derivedFrom:['sp-metadata']});
  b.object('idp-metadata','metadata','Candidate IdP metadata with current and next public certificates','realmA',null,['slMetadataDocument','slMetadataEntityID','slMetadataIdpRole','slMetadataBinding','slMetadataLocation','slMetadataSigningCert','slMetadataNextCert','slMetadataValidUntil','slMetadataCacheDuration'],{store:'publication',readableBy:['realmA','app'],fieldStep:'sl-meta-idp-response'});
  b.send('idp-metadata','sl-meta-idp-response','realmA','app',{fromStore:'publication',toStore:'candidate-metadata',releaseAt:'sl-meta-rollover'});
  b.observe('idp-metadata','sl-meta-rollover','app','trusted and installed','Independent metadata trust/freshness checks precede accepting next key; old signing key remains during overlap.');
  b.object('installed-idp-next','trust-cache','Installed next IdP certificate (overlap)','app','sl-meta-rollover',['slMetadataNextCert'],{store:'trust-cache',derivedFrom:['idp-metadata'],related:['idp-trust']});
}
function samlFailures(b) {
  samlBase(b);
  b.object('pending-signin','transaction','Independent pending sign-in IDs','app',null,['slAuthnID'],{store:'pending',temporary:true,releaseAt:'sl-fail-denied-submit'});
  b.object('prior-replay','replay-record','Previously accepted assertion ID','app',null,['slReplayCache'],{store:'replay-cache'});
  for(const kind of ['expired','replay']) {
    const wire='sl-fail-'+kind+'-wire',check='sl-fail-'+kind+'-check';
    b.object(kind+'-assertion','saml-assertion',kind==='expired'?'Expired signed assertion':'Same previously accepted assertion, replayed','realmA',null,ASSERTION_FIELDS,{store:false,fieldStep:wire,readableBy:['realmA','browser','app']});
    b.object(kind+'-response','saml-response','Independent '+kind+' SAML Response','realmA',null,['slResponse','slInnerCorrelation','slStatus'],{store:false,fieldStep:wire,readableBy:['realmA','browser','app'],related:[kind+'-assertion']});
    for(const id of [kind+'-assertion',kind+'-response']) {
      b.at(null,b.acquire(id,'browser','prior-form',true));
      b.send(id,wire,'browser','app',{fromStore:'prior-form',toStore:'received-rejected',retain:true,releaseSender:true});
    }
    b.observe(kind+'-assertion',check,'app','rejected',kind==='expired'?'Trusted signature cannot bypass expired NotOnOrAfter. Received bytes stay held as declared rejected evidence.':'Already accepted assertion ID fails local replay validation; receipt does not create another session.');
  }
  b.token('denied-response','realmA','sl-fail-denied-build',['slResponse','slIssuer','slDestination','slInnerCorrelation','slSignature','slStatus','slSubStatus'],{type:'saml-error-response',readableBy:['realmA','browser','app']});
  b.send('denied-response','sl-fail-denied-browser','realmA','browser',{fromStore:'output',toStore:'navigation',releaseAt:'sl-fail-denied-submit',releaseSender:true});
  b.send('denied-response','sl-fail-denied-submit','browser','app',{fromStore:'navigation',toStore:'received-rejected',retain:true});
  b.observe('denied-response','sl-fail-denied-submit','app','rejected','Authentic non-Success status: no assertion or authenticated SP session is invented.');
}
function samlLogout(b) {
  samlBase(b,{second:true});
  const id=b.args.model.id,sp=id==='lab-saml-sp-slo',soap=id==='lab-saml-soap-slo',root=sp?'sl-sp-slo':soap?'sl-soap-slo':'sl-idp-slo';
  for(const [name,actor,attrs] of [['sp-session','app',['slAppSession','slNameIDApp','slSessionIndexApp']],['second-session','realmB',['slOtherSession','slNameIDOther','slSessionIndexOther']],['idp-session','realmA',['slIdpSession','slNameIDApp','slSessionIndexApp','slNameIDOther','slSessionIndexOther']]])b.object(name,'session',name+' with participant-specific associations',actor,null,attrs,{store:'sessions'});
  b.at(root+(sp?'-start':soap?'-authority':'-start'),b.release(sp?'sp-session':'idp-session',sp?'app':'realmA','sessions'));
  const leg=(prefix,sender,recipient,other=false,origin=false)=>{
    const req=prefix+'-request-object',res=prefix+'-response-object';
    const responsePrefix=origin?'sl-sp-slo-final':prefix;
    b.object(req,'saml-logout-request','Signed participant-specific LogoutRequest',sender,prefix+'-build',['slLogoutRequest',other?'slLogoutOtherID':'slLogoutID',other?'slNameIDOther':'slNameIDApp',other?'slSessionIndexOther':'slSessionIndexApp','slIssuer','slDestination','slLogoutExpiry','slSignature'],{store:'pending-logout',temporary:true,releaseAt:responsePrefix+'-response',readableBy:[sender,recipient,...(soap?[]:['browser'])]});
    if(!soap)b.send(req,prefix+'-to-browser',sender,'browser',{fromStore:'pending-logout',toStore:'navigation',releaseAt:prefix+'-request'});
    const terminate=origin?'sl-sp-slo-idp-check':prefix+'-terminate';
    b.send(req,prefix+'-request',soap?sender:'browser',recipient,{fromStore:soap?'pending-logout':'navigation',toStore:'logout-request',releaseAt:terminate});
    b.observe(req,terminate,recipient,'accepted','Trusted sender signature, destination/time and this participant NameID/SessionIndex mapping verified.');
    b.at(terminate,b.release(recipient==='realmA'?'idp-session':other?'second-session':'sp-session',recipient,'sessions'));
    b.object(res,'saml-logout-response','Signed correlated participant LogoutResponse',recipient,responsePrefix+(origin?'-build':'-response-build'),['slLogoutResponse',other?'slLogoutOtherCorrelation':'slLogoutCorrelation','slIssuer','slDestination','slStatus','slSignature'],{store:'output',temporary:true,releaseAt:responsePrefix+(soap?'-response':'-response-browser'),readableBy:[sender,recipient,...(soap?[]:['browser'])],related:[req]});
    if(!soap)b.send(res,responsePrefix+'-response-browser',recipient,'browser',{fromStore:'output',toStore:'navigation',releaseAt:responsePrefix+'-response'});
    b.send(res,responsePrefix+'-response',soap?recipient:'browser',sender,{fromStore:soap?'output':'navigation',toStore:'logout-response',releaseAt:responsePrefix+'-response'});
    b.observe(res,responsePrefix+'-response',sender,'acknowledged','Independent signed response destination, outstanding request correlation and actual Status checked.');
  };
  if(sp) {
    leg('sl-sp-slo-origin','app','realmA',false,true);
    leg('sl-sp-slo-second','realmA','realmB',true);
  } else {
    leg(root+'-first','realmA','app');
    leg(root+'-second','realmA','realmB',true);
  }
}

function branchBase(b,{password=false,confidential=false,signing=false,trust=false}={}) {
  if(signing)b.secret('issuer-private','realmA','branchSigningKey','Realm private signing key');
  if(trust)b.secret('issuer-trust','app','branchVerificationKey','Client trusted issuer public key');
  if(password)b.secret('password-verifier','realmA','branchPasswordHash','Protected enrolled password verifier');
  if(confidential)b.secret('client-secret','app','branchClientSecret','Backend confidential client secret');
  if(confidential)b.object('client-registration','client-registration','Registered backend-client credential binding','realmA',null,['branchClientId','branchClientSecret'],{store:'configuration'});
}
function branchAuth(b,request,check) {
  const id='basic:'+request;
  b.token(id,'app',request,['branchAuthorization'],{type:'client-authentication',readableBy:['app','realmA'],derivedFrom:['client-secret']});
  b.send(id,request,'app','realmA',{fromStore:'output',toStore:'client-auth-request',releaseAt:check,releaseSender:true});
}
function branchPassword(b,{input,submit,check,direct=false,id='password-proof'}) {
  b.object(id,'password-input','One-time password input','user',input,['branchPassword'],{store:'input',temporary:true,releaseAt:submit,readableBy:['user',direct?'app':'browser','realmA']});
  b.send(id,input,'user',direct?'app':'browser',{fromStore:'input',toStore:'form',releaseAt:submit});
  b.send(id,submit,direct?'app':'browser','realmA',{fromStore:'form',toStore:'request',releaseAt:check});
  b.observe(id,check,'realmA','verified','Enrolled local password verified independently of client authentication or upstream identification.');
}
function branchDirect(b) {
  branchBase(b,{password:true,confidential:true,signing:true});
  branchAuth(b,'branch-direct-request','branch-direct-check');
  branchPassword(b,{input:'branch-direct-input',submit:'branch-direct-request',check:'branch-direct-check',direct:true});
  for(const [id,attr] of [['AT','branchAccessToken'],['ID','branchIdToken'],['RT','branchRefreshToken']]) {
    b.token(id,'realmA','branch-direct-issue',[attr],{readableBy:['realmA','app']});
    b.send(id,'branch-direct-response','realmA','app',{fromStore:'output',toStore:'credentials',retain:true,releaseSender:true});
  }
}
function branchFront(b,hybrid) {
  branchBase(b,{signing:true,trust:true});
  const p=key=>(hybrid?'branch-hybrid-':'branch-implicit-')+key,last=p(hybrid?'final-checks':'checks');
  for(const [id,attr] of [['state','branchState'],['nonce','branchNonce'],...(hybrid?[['verifier','branchVerifier']]:[])])b.object(id,'transaction-secret',id,'app',p('prepare'),[attr],{store:'pending',temporary:true,releaseAt:id==='verifier'?p('redeem'):last,readableBy:id==='verifier'?['app','realmA']:['app']});
  b.object('authorization-request','request','Browser authorization request','app',p('prepare'),['branchClientId','branchResponseType','branchRedirectUri','branchScope','branchState','branchNonce',...(hybrid?['branchChallenge','branchChallengeMethod']:[])],{store:'pending-request',temporary:true,releaseAt:p('checks'),readableBy:['app','browser','realmA']});
  b.send('authorization-request',p('navigate'),'app','browser',{fromStore:'pending-request',toStore:'navigation',releaseAt:p('request')});
  b.send('authorization-request',p('request'),'browser','realmA',{fromStore:'navigation',toStore:'pending-request',releaseAt:p(hybrid?'pkce':'sign')});
  for(const [id,attrs] of [['AT-front',['branchAccessToken']],['ID-front',['branchIdToken','branchIssuer','branchIdentitySubject','branchAudience','branchNonce','branchExp','branchAtHash',...(hybrid?['branchCHash']:[])]],...(hybrid?[['code',['branchCode']]]:[])]) {
    b.token(id,'realmA',p('sign'),attrs,{readableBy:['realmA','browser','app'],...(id==='ID-front'?{related:['AT-front',...(hybrid?['code']:[])]}:{})});
    b.send(id,p('fragment'),'realmA','browser',{fromStore:'output',toStore:'fragment',releaseAt:p('callback'),releaseSender:true});
    b.send(id,p('callback'),'browser','app',{fromStore:'fragment',toStore:'response',releaseAt:p('checks')});
    if(id==='code')b.at(p('checks'),b.acquire(id,'app','pending-code',true));
    else b.install(id,p('checks'));
  }
  b.observe('ID-front',p('checks'),'app','accepted','Signature, issuer/subject/audience/lifetime, state/nonce and exact token hash bindings validated.');
  if(hybrid) {
    b.object('first-identity','identity-record','Verified first (iss, sub) pair','app',p('checks'),['branchFirstIdentityPair'],{store:'identity',derivedFrom:['ID-front']});
    b.object('challenge','pkce-commitment','Saved S256 challenge','app',p('prepare'),['branchChallenge','branchChallengeMethod'],{store:'pending',temporary:true,releaseAt:p('redeem'),derivedFrom:['verifier'],readableBy:['app','browser','realmA']});
    b.send('challenge',p('navigate'),'app','browser',{fromStore:'pending',toStore:'navigation',releaseAt:p('request')});
    b.send('challenge',p('request'),'browser','realmA',{fromStore:'navigation',toStore:'pending-pkce',releaseAt:p('pkce')});
    b.send('code',p('redeem'),'app','realmA',{fromStore:'pending-code',toStore:'request',releaseAt:p('pkce')});
    b.at(p('redeem'),b.release('code','app','pending-code'));
    b.send('verifier',p('redeem'),'app','realmA',{fromStore:'pending',toStore:'request',releaseAt:p('pkce')});
    b.authority('code',p('pkce'),'consumed','One-use client/redirect and saved S256 binding validated.');
    for(const [id,attrs,old] of [['ID-back',['branchIdToken','branchIssuer','branchIdentitySubject','branchAudience','branchNonce','branchExp'],'ID-front'],['AT-back',['branchAccessToken'],'AT-front'],['RT',['branchRefreshToken'],null]]) {
      b.token(id,'realmA',p('tokens'),attrs,{readableBy:['realmA','app'],derivedFrom:['code'],...(old?{replaces:[old]}:{})});
      b.send(id,p('tokens'),'realmA','app',{fromStore:'output',releaseAt:last,releaseSender:true});
      b.install(id,last,'app',old);
    }
    b.observe('ID-back',last,'app','accepted','Normal OIDC checks and same verified issuer/subject as first identity result.');
  }
}
function branchConsent(b) {
  branchBase(b);
  const state=(name,create,finish)=>b.object(name,'transaction-secret',name,'app',create,['branchState'],{store:'pending',temporary:true,releaseAt:finish});
  state('state-A','branch-consent-prepare','branch-consent-new');
  state('state-B','branch-consent-new','branch-consent-check');
  for(const [name,event,submit] of [['approval','branch-consent-approve','branch-consent-accept'],['denial','branch-consent-deny','branch-consent-submit-B']]) {
    b.object(name,'consent',name+' for its independent request','user',event,['branchConsent'],{store:'decision',temporary:true,releaseAt:submit,readableBy:['user','browser','realmA']});
    b.send(name,event,'user','browser',{fromStore:'decision',toStore:'form',releaseAt:submit});
    b.send(name,submit,'browser','realmA',{fromStore:'form',toStore:'request',releaseAt:name==='approval'?'branch-consent-success':'branch-consent-error'});
  }
  b.token('approved-code','realmA','branch-consent-success',['branchCode','branchState'],{type:'authorization-code',readableBy:['realmA','browser']});
  b.send('approved-code','branch-consent-success','realmA','browser',{fromStore:'output',toStore:'unredeemed-callback',retain:true,releaseSender:true});
  b.token('denied-error','realmA','branch-consent-error',['branchError','branchErrorDescription','branchState'],{type:'error',readableBy:['realmA','browser','app']});
  b.send('denied-error','branch-consent-error','realmA','browser',{fromStore:'output',toStore:'navigation',releaseAt:'branch-consent-callback',releaseSender:true});
  b.send('denied-error','branch-consent-callback','browser','app',{fromStore:'navigation',toStore:'error-response',releaseAt:'branch-consent-check'});
  b.observe('denied-error','branch-consent-check','app','state-correlated denial','Attempt B creates no code/token/session; successful attempt A remains a distinct historical transaction.');
}
function branchLink(b) {
  branchBase(b,{password:true});
  b.secret('upstream-private','realmB','branchSigningKey','Independent upstream private signing key');
  b.secret('upstream-trust','realmA','branchVerificationKey','Broker trusted upstream public key');
  b.object('local-account','account','Existing local account','realmA',null,['branchLocalAccount'],{store:'accounts'});
  b.token('upstream-identity','realmB','branch-link-identity',['branchExternalIssuer','branchExternalSubject','branchEmail','branchEmailVerified'],{type:'id-token',readableBy:['realmB','realmA']});
  b.send('upstream-identity','branch-link-identity','realmB','realmA',{fromStore:'output',toStore:'pending-identity',releaseAt:'branch-link-store',releaseSender:true});
  b.observe('upstream-identity','branch-link-match','realmA','identity verified, link not authorized','Email lookup only suggests an existing account; local reauthentication remains required.');
  branchPassword(b,{input:'branch-link-password',submit:'branch-link-form',check:'branch-link-verify'});
  b.object('identity-link','identity-link','Verified upstream (issuer, subject) to local account link','realmA','branch-link-store',['branchIdentityLink'],{store:'accounts',derivedFrom:['upstream-identity'],related:['local-account','password-verifier']});
}
function branchCancel(b) {
  branchBase(b,{password:true});
  b.object('challenge','webauthn-challenge','Fresh cancelled WebAuthn challenge','realmA','branch-cancel-challenge',['branchChallengeLogin','branchRpId'],{store:'pending',temporary:true,releaseAt:'branch-cancel-local',readableBy:['realmA','browser']});
  b.send('challenge','branch-cancel-get','realmA','browser',{fromStore:'pending',toStore:'ceremony',releaseAt:'branch-cancel-local'});
  b.object('cancellation','local-error','NotAllowedError (no signed assertion)','browser','branch-cancel-local',['branchNotAllowed'],{store:'local-result',temporary:true,releaseAt:'branch-cancel-policy'});
  b.observe('challenge','branch-cancel-local','browser','cancelled','No authenticator proof, private-key use or successful login is authored.');
  b.object('fallback-policy','policy','Explicitly configured independent password alternative','realmA',null,['branchFallback'],{store:'configuration'});
  branchPassword(b,{input:'branch-cancel-input',submit:'branch-cancel-password',check:'branch-cancel-verify'});
}
function branchRecovery(b) {
  branchBase(b,{password:true,signing:true});
  b.token('reset-action','realmA','branch-recovery-create',['branchActionToken','branchSubject','branchActionType','branchExp','branchJti'],{type:'action-credential',readableBy:['realmA','user','browser']});
  b.send('reset-action','branch-recovery-delivery','realmA','user',{fromStore:'output',toStore:'verified-delivery',releaseAt:'branch-recovery-open',releaseSender:true});
  b.send('reset-action','branch-recovery-open','user','browser',{fromStore:'verified-delivery',toStore:'navigation',releaseAt:'branch-recovery-return'});
  b.send('reset-action','branch-recovery-return','browser','realmA',{fromStore:'navigation',toStore:'request',releaseAt:'branch-recovery-store'});
  b.observe('reset-action','branch-recovery-check','realmA','accepted for reset','Signature, exact subject/action, expiry and unused jti validated before password entry.');
  b.object('new-password','password-input','Replacement password on validated reset page','browser','branch-recovery-password',['branchNewPassword'],{store:'form',temporary:true,releaseAt:'branch-recovery-password',readableBy:['browser','realmA']});
  b.send('new-password','branch-recovery-password','browser','realmA',{fromStore:'form',toStore:'request',releaseAt:'branch-recovery-store'});
  b.object('new-password-verifier','key','Replacement protected password verifier','realmA','branch-recovery-store',['branchPasswordHash'],{store:'configuration',derivedFrom:['new-password'],replaces:['password-verifier']});
  b.at('branch-recovery-store',b.release('password-verifier','realmA','configuration'));
  b.authority('reset-action','branch-recovery-store','consumed','One-use action ID recorded only after password policy/update succeeds.');
  b.object('action-replay','replay-record','Consumed password-reset action ID','realmA','branch-recovery-store',['branchJti'],{store:'replay-cache',related:['reset-action']});
}
function branchSessions(b) {
  branchBase(b,{confidential:true});
  branchAuth(b,'branch-sessions-refresh','branch-sessions-reject');
  b.secret('api-trust','realmB','branchVerificationKey','API trusted issuer public key for independent JWT validation');
  b.object('old-session','session','Existing online user/client session','realmA',null,['branchSessionRecord','branchSessionPolicy'],{store:'sessions'});
  b.object('provider-cookie','cookie','Existing browser provider cookie','realmA',null,['branchCookie'],{store:false,readableBy:['realmA','browser']});
  b.at(null,b.acquire('provider-cookie','browser','cookies'));
  for(const [id,attr] of [['RT','branchRefreshToken'],['AT','branchAccessToken']]) {
    b.object(id,id==='RT'?'refresh-token':'access-token',id+' from prior session','realmA',null,[attr,'branchExp'],{store:false,readableBy:['realmA','app','realmB']});
    b.at(null,b.acquire(id,'app','credentials'));
  }
  b.at(null,b.acquire('AT','realmB','existing-request'));
  b.send('provider-cookie','branch-sessions-existing','browser','realmA',{fromStore:'cookies',toStore:'request',releaseAt:'branch-sessions-policy'});
  b.authority('old-session','branch-sessions-revoke','revoked','Configured concurrent-session action terminates this older server session.');
  b.send('RT','branch-sessions-refresh','app','realmA',{toStore:'request',releaseAt:'branch-sessions-reject'});
  b.token('refresh-error','realmA','branch-sessions-reject',['branchError'],{type:'error',readableBy:['realmA','app']});
  b.send('refresh-error','branch-sessions-reject','realmA','app',{fromStore:'output',toStore:'error-response',releaseAt:'branch-sessions-reject',releaseSender:true});
  b.observe('RT','branch-sessions-reject','app','invalid_grant received','No replacement credential; local bytes remain under explicit retention policy.','knowledge');
  b.observe('AT','branch-sessions-jwt','realmB','locally verifiable','An existing unexpired JWT can pass local checks; API received no live server-session invalidation.','acceptance');
}

export function buildWebHeldObjects(args) {
  const id=args.model?.id || args.choiceId;
  if(!WEB_MODELS.has(id))return null;
  const b=author({...args,model:args.model || WEB_MODELS.get(id)});
  switch(id) {
    case 'lab-refresh-rotation':lifeRotation(b);break;
    case 'lab-offline-access':lifeOffline(b);break;
    case 'lab-token-revocation':lifeRevocation(b);break;
    case 'lab-rp-initiated-logout':lifeRpLogout(b);break;
    case 'lab-backchannel-logout':lifeBackLogout(b);break;
    case 'lab-frontchannel-logout':lifeFrontLogout(b);break;
    case 'lab-sso-existing-session':lifeSilent(b,false);break;
    case 'lab-sso-login-required':lifeSilent(b,true);break;
    case 'lab-session-expiry':lifeExpiry(b);break;
    case 'lab-ciba-ping':case 'lab-ciba-push':case 'lab-ciba-hint-token':grantCiba(b);break;
    case 'lab-exchange-id-token':case 'lab-exchange-refresh-token':grantExchange(b);break;
    case 'lab-exchange-delegation':grantDelegation(b);break;
    case 'lab-exchange-external-in':grantExternalIn(b);break;
    case 'lab-exchange-external-out':grantExternalOut(b);break;
    case 'lab-saml-artifact':samlArtifact(b);break;
    case 'lab-saml-metadata':samlMetadata(b);break;
    case 'lab-saml-validation-failures':samlFailures(b);break;
    case 'lab-saml-sp-slo':case 'lab-saml-idp-slo':case 'lab-saml-soap-slo':samlLogout(b);break;
    case 'lab-direct-grant':branchDirect(b);break;
    case 'lab-implicit':branchFront(b,false);break;
    case 'lab-hybrid':branchFront(b,true);break;
    case 'lab-consent-denial':branchConsent(b);break;
    case 'lab-broker-account-link':branchLink(b);break;
    case 'lab-passkey-cancel':branchCancel(b);break;
    case 'lab-account-recovery':branchRecovery(b);break;
    case 'lab-concurrent-sessions':branchSessions(b);break;
    default:throw new Error('Missing explicit web held-object mapping: '+id);
  }
  return b.finish();
}
