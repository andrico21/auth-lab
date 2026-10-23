import {labAttribute,labP,labStep,labScenario} from './lab-common.js';
import {jwtParseCompact,jwtValidateFixture,jwtDecryptFixture,jwtRefreshDecision,jwtCompleteRefresh,jwtIntrospectionDecision} from './jwt-policy.js';

export const JWTLAB_ATTRIBUTES={};
const jwtLabCatalogExtras={1:['jwt01_parse-error'],5:['jwt05_discovery-rejection'],6:['jwt06_unknown-request-batch','jwt06_refresh-rejection'],7:['jwt07_parse-error']};
for(const [attributeId,name,meaning]of [
  ['jwt01_parse-error','Holder parse error','Malformed compact segment count, base64url or JSON stops before any trust decision.'],
  ['jwt05_discovery-rejection','Discovery issuer mismatch','The configured issuer must exactly match the returned discovery issuer before any JWKS trust.'],
  ['jwt06_unknown-request-batch','Concurrent unknown-kid request fixtures','Explicit macro group of separate untrusted bearer requests; bounded pending tracking never grants acceptance.'],
  ['jwt06_refresh-rejection','Request-specific cache rejection','The actual pure refresh-policy result rejects this token before signature acceptance; unrelated cached keys retain their own checks.'],
  ['jwt07_parse-error','Duplicate-claim parse rejection','This stricter demo parser rejects duplicate JSON claim names, including escaped duplicate spelling.']
])JWTLAB_ATTRIBUTES[attributeId]=labAttribute(name,meaning,['jwt01_parse-error','jwt06_unknown-request-batch'].includes(attributeId)?'jwtClient':'jwtAPI','Expose the actual fixture input or first rejection without accepted identity or authorization.',null,'RFC7519 7 / RFC8725 3','https://www.rfc-editor.org/rfc/rfc8725.html');
for(let n=15;n<32;n++){
  const attributeId='jwt06_flood-rejection-flood-token'+n;
  jwtLabCatalogExtras[6].push(attributeId);
  JWTLAB_ATTRIBUTES[attributeId]=labAttribute('Request-specific flood rejection','Capacity rejection belongs only to flood-token'+n+' / unknown'+n+'.','jwtAPI','Keep admitted generation2 refresh separate from this denied request.',null,'JWT-DEMO-R1 bounded refresh policy','https://www.rfc-editor.org/rfc/rfc8725.html');
}
export const JWTLAB_SOURCES=[
  ['RFC7519','3;4.1;5;7;11','https://www.rfc-editor.org/rfc/rfc7519.html','May 2015; updated by RFC8725'],
  ['RFC7515','3.1;4;5;10;Appendix A.2','https://www.rfc-editor.org/rfc/rfc7515.html','May 2015'],
  ['RFC7516','3.1;4;5;11','https://www.rfc-editor.org/rfc/rfc7516.html','May 2015'],
  ['RFC7517','4.2-4.5;5;9','https://www.rfc-editor.org/rfc/rfc7517.html','May 2015'],
  ['RFC8725 / BCP225','2;3.1-3.12','https://www.rfc-editor.org/rfc/rfc8725.html','February 2020; updates RFC7519'],
  ['OIDC Discovery1.0','3;4.3;7','https://openid.net/specs/openid-connect-discovery-1_0.html','Errata set2; captured snapshot'],
  ['OIDC Core1.0','2;3.1.2;3.1.3.7;12;16.15','https://openid.net/specs/openid-connect-core-1_0.html','Errata set2; captured snapshot'],
  ['RFC9068','2;4','https://www.rfc-editor.org/rfc/rfc9068.html','October 2021'],
  ['RFC6750','2;3;5','https://www.rfc-editor.org/rfc/rfc6750.html','October 2012'],
  ['RFC7662','2;4','https://www.rfc-editor.org/rfc/rfc7662.html','October 2015'],
  ['RFC9700 / BCP240','2;4.10;4.14','https://www.rfc-editor.org/rfc/rfc9700.html','January 2025']
].map(([standard,section,url,revision])=>({standard,name:standard,section,url,revision,retrieved:'2026-10-22',support:'Offline standards illustration; not live interoperability'}));
const jwtLabNow=1792627200,jwtLabIssuer='https://issuer.demo.example',jwtLabAudience='https://api.demo.example';
function jwtLabFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(jwtLabFreeze);Object.freeze(value);}return value;}
function jwtLabEncode(value){const text=typeof value==='string'?value:JSON.stringify(value);return btoa(String.fromCharCode(...new TextEncoder().encode(text))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}
function jwtLabCompact(header,claims,signature='SYM(RS256-signature-generation1)'){return [jwtLabEncode(header),jwtLabEncode(claims),jwtLabEncode(signature)].join('.');}
function jwtLabFixture(id){
  const header={alg:'RS256',kid:'generation1',typ:'JWT'},claims={iss:jwtLabIssuer,sub:'alice',aud:jwtLabAudience,iat:jwtLabNow-60,exp:jwtLabNow+300,groups:['readers'],jti:'demo-token1',client_id:'demo-native'};
  const profile={id:'JWT-DEMO-R1',issuer:jwtLabIssuer,audience:jwtLabAudience,algorithms:['RS256'],requiredClaims:['iss','sub','aud','exp','iat'],skewSeconds:30,audienceArray:true,purpose:'generic',claimTypes:{groups:'string-array'},maxAgeSeconds:600,maxLifetimeSeconds:900};
  const key={id:'issuer-public-generation1',kid:'generation1',issuer:jwtLabIssuer,kty:'RSA',alg:'RS256',use:'sig',key_ops:['verify']};
  const token={instanceId:id+':token:g1',compact:jwtLabCompact(header,claims)};
  const parts=token.compact.split('.'),signatureEvidence={kind:'SYM',valid:true,tokenInstanceId:token.instanceId,keyId:key.id,signingInput:parts.slice(0,2).join('.'),signatureSegment:parts[2]};
  return {header,claims,profile,key,keys:[key],token,signatureEvidence,now:jwtLabNow};
}
function jwtLabReissue(f){f.token.compact=jwtLabCompact(f.header,f.claims);const parts=f.token.compact.split('.');f.signatureEvidence={...f.signatureEvidence,signingInput:parts.slice(0,2).join('.'),signatureSegment:parts[2]};return f;}
const jwtLabActors={
  jwtIssuer:{name:'Issuer',role:'Claims and signing authority',plainRole:'Keeps the private signing key',kind:'idp',color:'#7c3aed',position:{x:145,y:120}},
  jwtClient:{name:'Bearer holder',role:'Synthetic token holder',plainRole:'Can read JWS payload, not encrypted content',kind:'client',color:'#2563eb',position:{x:560,y:120}},
  jwtAPI:{name:'Resource validator',role:'Configured relying party and separate policy',plainRole:'Checks trust and claims before authorization',kind:'service',color:'#08916d',position:{x:975,y:120}}
};
function jwtLabAuthor(number,title,objective,variantId,choices,fixture){
  const id='lab-jwt'+String(number).padStart(2,'0'),prefix='jwt'+String(number).padStart(2,'0')+'_',steps=[],definitions={},artifacts=[],initial=[],events={},bindings=[];
  const state={clock:jwtLabNow,received:false,parsed:false,decrypted:false,signatureValid:false,validatedClaims:null,claimsAccepted:false,untrustedStatus:'not-decoded',purposeStatus:'not-evaluated',principal:null,authorized:false,resultReceived:false,failure:null,failureDetector:null,serverKnowsFailure:false,clientKnowsFailure:false,issuerSessionActive:number===9?true:null,completedActions:0,clientLogin:false,resourceClaimsAccepted:false,cachedOldAccepted:false,oldKeyRetired:false};
  const acquire=(o,actor,representationId='plain',store='fixture context')=>({op:'acquire',holdingId:[actor,o.artifactId,representationId,store].join('|'),artifactId:o.artifactId,actorId:actor,representationId,store,retention:'retained'});
  function object(key,label,type,creator,value,readers,options={}){
    const attributeId=prefix+key,artifactId=id+':'+variantId+':'+key,representationId=options.representation||'plain';
    definitions[attributeId]=labAttribute(label,options.meaning||label+' for this exact fixture generation.',creator,options.purpose||'Explicit custody and trust boundary; receipt, readability, validation and authorization differ.',value,options.standard||'RFC7519 / RFC8725',options.source||JWTLAB_SOURCES[0].url);
    if(variantId==='default')JWTLAB_ATTRIBUTES[attributeId]=definitions[attributeId];
    const o={artifactId,attributeId,label,type,creator,generation:options.generation||1,representationId,value,readers,representations:[{representationId,format:options.format||'symbolic fixture',readableBy:readers,fields:[{attributeId,name:label,value,readableBy:readers}]}],...(options.derivedFrom?{derivedFrom:[options.derivedFrom.artifactId]}:{})};artifacts.push(o);return o;
  }
  function seed(o,holders=[o.creator]){initial.push({op:'create',artifactId:o.artifactId},...holders.map(actor=>acquire(o,actor,o.representationId)));return o;}
  function event(stage,title,actor,summary,{to=actor,objects=[],creates=[],receives=[],uses=[],releases=[],acquisitions=[],puts={},kind='inspect',observations=[]}={}){
    const stepId=id+':'+stage,wire=actor!==to,effects=[],ops=[];
    if(wire&&creates.length){
      event(stage+'-prepare','Prepare exact outgoing objects',actor,'Construct the outgoing representations locally before transferring them; recipient receipt does not create or validate their contents.',{creates,uses});
      creates=[];
    }
    for(const o of creates)effects.push({op:'create',artifactId:o.artifactId},acquire(o,o.creator,o.representationId));
    for(const o of receives)effects.push({...acquire(o,to,o.representationId,'message inbox'),holdingId:[to,o.artifactId,o.representationId,'message inbox',stepId].join('|')});
    effects.push(...acquisitions,...releases.map(o=>({op:'release',holdingId:[actor,o.artifactId,o.representationId,'fixture context'].join('|')})));
    for(const o of [...new Set([...objects,...creates,...uses,...releases])]){
      const base={attributeId:o.attributeId,instanceId:o.artifactId,creator:o.creator,holders:wire?[actor,to]:[actor],inspectors:o.readers,fieldPath:o.representationId+'.'+o.attributeId,representation:o.representationId,value:o.value,sourceEventId:stepId,exactValueRef:o.artifactId+':'+o.representationId};
      const opKind=wire?'send':releases.includes(o)?'dispose':creates.includes(o)?(kind==='inspect'?'create':kind):kind==='derive'?'inspect':kind;
      if(creates.includes(o)&&!['create','derive'].includes(opKind))ops.push({...base,actorId:o.creator,holders:[o.creator],kind:'create'});
      ops.push({...base,actorId:actor,kind:opKind});if(wire)ops.push({...base,actorId:to,kind:'receive'});
      if(!wire&&!creates.includes(o))effects.push({op:'observe',artifactId:o.artifactId,actorId:actor,representationId:o.representationId,kind:['verify','decrypt'].includes(kind)?'verification':'knowledge',result:kind+' at '+stage});
    }
    effects.push(...observations);
    const all=[...new Set([...objects,...creates,...uses,...releases])],step=labStep(stepId,title,actor,to,'JWT fixture policy',wire?'backchannel':'internal',summary,summary,all.map(o=>o.attributeId),all.map(o=>labP(o.label,o.value,definitions[o.attributeId].meaning,o.attributeId)),['Synthetic offline fixtures; no live request or production crypto.','Trust, identity and authorization remain separate.'],ops);
    const statePuts=Object.hasOwn(puts,'failure')?{...puts,failureDetector:actor,...(actor==='jwtAPI'?{serverKnowsFailure:true}:actor==='jwtClient'?{clientKnowsFailure:true}:{})}:puts;
    step.eventType=wire?'message':'local';step.jwtStage=stage;step.protocolEffects=Object.entries(statePuts).map(([path,value])=>({op:'put',path:'jwt.'+path,value}));step.layers=wire?[{protocol:'HTTPS / TLS fixture',transport:'TCP',from:actor,to,protection:'Authored transport assumption, not computed TLS bytes'}]:[];
    events[stepId]={milestones:[{id:'complete',at:1,effects}],...(wire&&receives.length?{messages:[{messageId:stepId+':'+actor+'->'+to,from:actor,to,objects:receives.map(o=>({artifactId:o.artifactId,representationId:o.representationId})),start:0,end:1}]}:{})};steps.push(step);return step;
  }
  function finish(extra={}){
    const model=labScenario({id,name:title,title,workspace:'foundations',family:'jwt',protocol:'JWT / JOSE',variantId,learningObjective:objective,prerequisites:['Synthetic issuer '+jwtLabIssuer,'Configured relying-party issuer/audience/public-key trust; no live endpoints','Fixed NumericDate clock '+jwtLabNow],supportNote:'Offline standards illustration. Authored SYM signature/decrypt evidence is not mathematical verification. Numeric QA is isolated and separately executed.',relatedLessons:[],profile:{name:'JWT-DEMO-2026-10-22',version:'1',publicationStatus:'RFC/BCP and OIDC published sources',supportStatus:'offline standards fixture',implementation:'Deterministic structural/header/trust/claims fixture policy; no production cryptographic verifier',assumptions:['Private keys remain with their owners','TLS carrier is a declared assumption'],transports:['Synthetic HTTPS'],completion:'Explicit final acceptance, denial or representation comparison; not live interoperability',algorithms:['RS256 symbolic signature evidence'],cryptoDetail:{mode:'symbolic',encoded:'Actual UTF-8/base64url header/payload; SYM signature/ciphertext contents are not valid crypto bytes',numericQA:'tools/verification/expansion-crypto/next-jwt-vectors.mjs'},sources:JWTLAB_SOURCES,startingSummary:['Issuer keeps private signing key','Holder starts without an API principal','Verifier trusts one configured issuer and public key']},initialState:{jwt:state},jwtInventory:{artifacts,initial,events,bindings},fixtureInputs:fixture,variantChoices:choices.map(choice=>({id:choice,label:choice==='default'?'Default profile':choice.replace(/-/g,' '),description:choice==='default'?'Fixed authored profile': 'Change the relevant fixture input and stop at its detector'})),...extra},definitions,steps,jwtLabActors);
    model.summary=objective;
    model.catalogAttributeIds=[...new Set([...Object.keys(definitions),...(jwtLabCatalogExtras[number]||[])])];
    model.decisionBindings=[{label:'Readable claims',path:'jwt.untrustedStatus'},{label:'Signature evidence',path:'jwt.signatureValid',values:{false:'Not accepted',true:'SYM evidence accepted'}},{label:'Claims',path:'jwt.claimsAccepted',values:{false:'Not accepted',true:'Profile claims accepted'}},{label:'Purpose / context',path:'jwt.purposeStatus'}];
    if(number===3)model.profile.algorithms=['RS256 inner SYM signature','RSA-OAEP-256 outer SYM key transport','A128GCM SYM authenticated encryption'];
    if(number===3)model.profile.startingSummary=['Issuer keeps the signing key and creates the CEK','Recipient alone owns the private decryption key','Carrier receives only the outer ciphertext envelope'];
    if(number===5)model.profile.startingSummary=['Verifier preconfigures one issuer and HTTPS trust','Discovery/JWKS candidates are not yet trusted token claims','No token-supplied key URL is followed'];
    if(number===6)model.profile.startingSummary=['Cache initially holds only the old issuer key','Holder already has an unrelated old-key bearer token','New-key requests stay pending or denied until their own validation'];
    if(number===8)model.profile.startingSummary=['OIDC client audience is demo-native','Ordinary API requires its own RFC9068 access-token profile','Client login and API authorization are independent'];
    if(number===9)model.profile.startingSummary=['Issuer session starts active, separately from token lifetime','Bearer possession supplies no sender binding','Opaque introspection uses an API-local credential and 15s result TTL'];
    model.withVariant=choice=>createJWTScenario(number,choice);return jwtLabFreeze(model);
  }
  return {id,object,seed,event,finish,steps,artifacts,initial,events,acquire,bindings};
}
function jwtLabPrivate(a,f){
  const key=a.seed(a.object('issuer-private','Issuer private signing key','key','jwtIssuer','HANDLE(issuer-RSA-private-generation1)',['jwtIssuer']));
  if(f){a.seed(a.object('source-claims','Issuer source claims','claims','jwtIssuer',f.claims,['jwtIssuer']));a.seed(a.object('configured-profile','Immutable relying-party profile','policy','jwtAPI',f.profile,['jwtAPI']));a.seed(a.object('public-key','Configured issuer public key metadata','key','jwtAPI',f.keys,['jwtAPI']));}
  return key;
}
function jwtLabToken(a,f,label='Signed JWT'){return a.object('compact',label,'token','jwtIssuer',f.token.compact,['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire',format:'Actual compact encoded JSON; signature segment encodes explicit SYM evidence',meaning:'Three compact JWS segments. Header and payload are readable without decryption; signature segment is explicitly symbolic, not mathematical proof.'});}
function jwtLabDelivery(a,token){a.event('issue','Issuer creates exact token','jwtIssuer','Private signing key stays issuer-local; token is a distinct artifact.',{creates:[token],uses:a.artifacts.filter(o=>o.creator==='jwtIssuer'&&o!==token)});a.event('deliver','Holder receives token over TLS','jwtIssuer','Receipt grants only these exact token bytes, not accepted claims.',{to:'jwtClient',objects:[token],receives:[token]});a.event('present','Bearer holder presents token','jwtClient','The API receives bytes; it has not accepted issuer, identity or permission.',{to:'jwtAPI',objects:[token],receives:[token],puts:{received:true}});}
function jwtLabValidation(a,f,token,{stagePrefix='',actor='jwtAPI'}={}){
  const parsed=jwtParseCompact(f.token.compact),result=jwtValidateFixture(f);
  if(!parsed.ok){const error=a.object(stagePrefix+'parse-error','Parse rejection','error',actor,{stage:'parse',code:parsed.code},[actor]);a.event(stagePrefix+'parse','Reject malformed compact input',actor,'Parse error before key lookup or trusted claims.',{objects:[token],creates:[error],puts:{failure:{stage:'parse',code:parsed.code}}});return result;}
  const decoded=a.object(stagePrefix+'decoded','Readable untrusted claims','claims',actor,parsed.claims,[actor],{representation:'readable-untrusted',derivedFrom:token,meaning:'Local base64url decoding, not decryption or acceptance.'});a.event(stagePrefix+'parse','Decode header and claims as UNTRUSTED',actor,'JWS payload is readable, but untrusted. No authenticated identity is installed.',{objects:[token],creates:[decoded],kind:'derive',puts:{parsed:true,untrustedClaims:parsed.claims,untrustedStatus:'readable-untrusted'}});
  const headerOK=!['trust','header','key'].includes(result.stage),selection=a.object(stagePrefix+'key-selection','Algorithm and issuer-bound key decision','policy',actor,{header:parsed.header,keyId:result.keyId,checks:result.observations.filter(o=>['trust','header','key'].includes(o.stage)),ok:headerOK},[actor]);a.event(stagePrefix+'select','Apply configured algorithm and issuer key constraints',actor,headerOK?'Candidate selected only within configured issuer trust. A key match is not verification.':'Reject at '+result.stage+': '+result.code+'. No signature-valid state exists.',{objects:[token],creates:[selection],kind:'verify',puts:headerOK?{}:{failure:{stage:result.stage,code:result.code}}});if(!headerOK)return result;
  const signature=a.object(stagePrefix+'signature-evidence','Authored SYM signature observation','verification',actor,{kind:'SYM',valid:result.signatureValid,evidence:f.signatureEvidence,code:result.signatureValid?'signature-valid':result.code},[actor],{derivedFrom:token,meaning:'Explicit authored fixture verdict bound to exact signing input/key/token generation. Not production cryptographic verification.'});a.event(stagePrefix+'signature','Evaluate exact-generation SYM signature evidence',actor,result.signatureValid?'Fixture signature observation succeeds; contextual claims remain unaccepted.':'Signature evidence fails for these exact bytes/key. Stop before accepted claims.',{objects:[token],creates:[signature],kind:'verify',puts:{signatureValid:result.signatureValid,...(!result.signatureValid?{failure:{stage:result.stage,code:result.code}}:{})}});if(!result.signatureValid)return result;
  const decision=a.object(stagePrefix+'claim-decision','Profile claim decision','policy',actor,{ok:result.ok,code:result.code,observations:result.observations.filter(o=>o.stage==='claims')},[actor]);a.event(stagePrefix+'claims','Check issuer, audience, time, types and purpose',actor,result.ok?'Configured checks succeed, independently from later policy.':'Stop at claims detector '+result.code+'. A valid signature is insufficient.',{objects:[decoded],creates:[decision],kind:'verify',puts:{purposeStatus:result.ok?'profile-accepted':result.code,...(!result.ok?{failure:{stage:result.stage,code:result.code}}:{})}});
  if(result.ok){const accepted=a.object(stagePrefix+'accepted','Validated claims','identity-evidence',actor,result.validatedClaims,[actor],{representation:'accepted',derivedFrom:token});a.event(stagePrefix+'accept','Store validated claims, not an access grant',actor,'Only this local acceptance creates validatedClaims. Principal mapping and authorization require separate decisions.',{creates:[accepted],kind:'store',puts:{validatedClaims:result.validatedClaims,claimsAccepted:true,[stagePrefix+'claimsAccepted']:true}});a.bindings.push({path:'jwt.'+stagePrefix+'claimsAccepted',actorId:actor,artifactId:accepted.artifactId,representationId:'accepted',presentWhen:'truthy'});}
  return result;
}
function jwtLabBearerError(a,stage,status,code){
  const response=a.object('error-response','OAuth bearer API error response','error','jwtAPI',{status,...(status===401?{headers:{'WWW-Authenticate':'Bearer error=\"invalid_token\"'}}:{}),code,format:'HTTP/OAuth bearer response, not Kubernetes Status'},['jwtAPI','jwtClient'],{representation:'wire'});
  a.event(stage+'-response','Deliver explicit API rejection','jwtAPI',status===401?'RFC6750 invalid_token response returns the actual credential rejection.':'Fail-closed temporary validator unavailability is 503, not a claim that the token is cryptographically invalid.',{to:'jwtClient',creates:[response],objects:[response],receives:[response]});
  a.event(stage+'-learn','Holder accepts correlated error response','jwtClient','The holder learns this request failed only now; prior successful responses and completed actions remain.',{objects:[response],kind:'verify',puts:{clientKnowsFailure:true}});
}
function jwtLab01(variantId){
  const choices=['default','malformed-segments','malformed-base64url','malformed-json','oauth-field-name'],f=jwtLabFixture('lab-jwt01');
  if(variantId==='malformed-segments')f.token.compact='two.segments';if(variantId==='malformed-base64url')f.token.compact='@@.e30.c2ln';if(variantId==='malformed-json')f.token.compact=jwtLabEncode('{')+'.'+jwtLabEncode(f.claims)+'.'+jwtLabEncode('SYM(signature)');
  f.oauthResponse={access_token:variantId==='oauth-field-name'?'HANDLE(opaque-reference-token1)':f.token.compact,token_type:'Bearer'};f.responseRepresentation=variantId==='oauth-field-name'?'opaque':'jws';
  const a=jwtLabAuthor(1,'JWT, JWS, JWE and opaque tokens','Which parts can the holder read, and which validator must decide acceptance?',variantId,choices,f);jwtLabPrivate(a,f);
  const signed=jwtLabToken(a,f),jwe=a.object('encrypted','Encrypted JWT compact envelope','token','jwtIssuer',[jwtLabEncode({alg:'RSA-OAEP-256',enc:'A128GCM',cty:'JWT'}),...['SYM(encrypted-CEK)','SYM(iv)','SYM(ciphertext-inner-JWS)','SYM(tag)'].map(jwtLabEncode)].join('.'),['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire',meaning:'Five compact JWE segments; ciphertext is explicitly SYM. Possession provides envelope inspection, not plaintext.'}),opaque=a.object('opaque','Opaque reference token','token','jwtIssuer','HANDLE(opaque-reference-token1)',['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire'});
  a.event('issue','Create three distinct token representations','jwtIssuer','JWT is a claims format, JWS protects integrity, JWE protects confidentiality/integrity, opaque describes client visibility.',{creates:[signed,jwe,opaque],uses:a.artifacts.filter(o=>['issuer-private','source-claims'].some(key=>o.attributeId.endsWith('_'+key)))});a.event('deliver','Deliver exact outputs to holder','jwtIssuer','Three exact artifacts, never a shared or substituted token identity.',{to:'jwtClient',objects:[signed,jwe,opaque],receives:[signed,jwe,opaque]});
  const parsed=jwtParseCompact(f.token.compact);if(!parsed.ok){const rejection=a.object('parse-error','Holder parse error','error','jwtClient',{stage:'parse',code:parsed.code},['jwtClient']);a.event('inspect','Reject malformed input before trust','jwtClient','No key lookup, validated claims, identity or access grant follows malformed input.',{objects:[signed],creates:[rejection],puts:{failure:{stage:'parse',code:parsed.code}}});return a.finish();}
  const decoded=a.object('decoded','JWS header/payload: readable UNTRUSTED','claims','jwtClient',{header:parsed.header,claims:parsed.claims},['jwtClient'],{representation:'readable-untrusted',derivedFrom:signed});a.event('inspect','Decode JWS; inspect JWE envelope and opaque bytes','jwtClient','Base64url decoding is not decryption. No JWE plaintext is acquired by this holder.',{objects:[signed,jwe,opaque],creates:[decoded],kind:'derive',puts:{parsed:true,untrustedClaims:parsed.claims,untrustedStatus:'readable-untrusted'}});
  const responseParse=jwtParseCompact(f.oauthResponse.access_token,{representation:f.responseRepresentation});
  const routing=a.object('validation-paths','Explicit representation and validator selection','policy','jwtAPI',{jws:'issuer-bound signature then profile claims',jwe:'recipient AEAD unwrap then inner signature and claims',opaque:'authenticated RFC7662 introspection',oauthResponse:f.oauthResponse,configuredRepresentation:f.responseRepresentation,actualParseCode:responseParse.code},['jwtAPI']);a.event('route','Select configured paths, not OAuth field-name guesses','jwtClient','Forward exact bytes without changing their representation or trust.',{to:'jwtAPI',objects:[signed,jwe,opaque],receives:[signed,jwe,opaque],puts:{received:true}});a.event('compare','Compare protection, readability and validators','jwtAPI','This lesson ends at the representation comparison, before acceptance or authorization. Opaque is not inherently weaker; not every JWS is a JWT.',{creates:[routing],objects:[signed,jwe,opaque],puts:{comparisonComplete:true,selectedRepresentation:f.responseRepresentation,responseParseCode:responseParse.code}});return a.finish();
}

function jwtLab02(variantId){
  const choices=['default','payload-tamper','signature-tamper','other-api'],f=jwtLabFixture('lab-jwt02');
  if(variantId==='payload-tamper'){f.claims.sub='alicf';f.token.compact=jwtLabCompact(f.header,f.claims);}
  if(variantId==='signature-tamper')f.token.compact=jwtLabCompact(f.header,f.claims,'SYM(RS256-signature-generation2)');
  if(variantId==='other-api'){f.claims.aud='https://other.demo.example';jwtLabReissue(f);}
  const a=jwtLabAuthor(2,'Signed JWT verification and tampering','What does a signature establish, and what remains to be checked?',variantId,choices,f);jwtLabPrivate(a,f);
  const token=jwtLabToken(a,f);jwtLabDelivery(a,token);jwtLabValidation(a,f,token);return a.finish();
}

function jwtLab03(variantId){
  const choices=['default','wrong-recipient','changed-tag','invalid-inner-signature'],f=jwtLabFixture('lab-jwt03');
  if(variantId==='invalid-inner-signature')f.signatureEvidence.valid=false;
  const original=[jwtLabEncode({alg:'RSA-OAEP-256',enc:'A128GCM',cty:'JWT'}),...['SYM(encrypted-CEK)','SYM(iv)','SYM(ciphertext-inner-JWS)','SYM(authentication-tag)'].map(jwtLabEncode)].join('.');
  f.encryptedToken={instanceId:'lab-jwt03:outer:g1',compact:variantId==='changed-tag'?original.split('.').slice(0,4).join('.')+'.'+jwtLabEncode('SYM(changed-tag)'):original};
  const selectedRecipientKey={id:variantId==='wrong-recipient'?'recipient-other':'recipient-generation1',handle:variantId==='wrong-recipient'?'HANDLE(recipient-RSA-OAEP-256-private-other)':'HANDLE(recipient-RSA-OAEP-256-private-generation1)',alg:'RSA-OAEP-256',use:'enc'};
  f.decryptionEvidence={kind:'SYM',valid:true,tokenInstanceId:f.encryptedToken.instanceId,recipientKeyId:'recipient-generation1',compact:original,innerCompact:f.token.compact};
  const a=jwtLabAuthor(3,'Encrypted and nested JWT acceptance','Why must authenticated decryption and inner signature/claims acceptance be separate?',variantId,choices,f);jwtLabPrivate(a,f);
  const recipient=a.seed(a.object('recipient-private','Recipient private decryption key','key','jwtAPI',selectedRecipientKey,['jwtAPI']));
  f.recipientKeyId=recipient.value.id;
  const publicRecipient=a.seed(a.object('recipient-public','Recipient public encryption key','key','jwtIssuer',{id:'recipient-generation1',alg:'RSA-OAEP-256',use:'enc'},['jwtIssuer']));
  const cek=a.object('cek','One-envelope content encryption key','key','jwtIssuer','HANDLE(A128GCM-CEK-envelope1)',['jwtIssuer','jwtAPI']);
  const inner=a.object('inner','Inner signed JWT, not yet issuer-accepted','token','jwtIssuer',f.token.compact,['jwtIssuer','jwtAPI'],{representation:'readable-untrusted',format:'Actual compact JSON with encoded SYM signature'});
  const outer=a.object('encrypted','Outer compact JWE envelope','token','jwtIssuer',f.encryptedToken.compact,['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire',format:'Five compact segments containing explicit SYM ciphertext',derivedFrom:inner,meaning:'Sign-then-encrypt envelope. Carrier has ciphertext and public header, never inner claims or CEK.'});
  a.event('nest','Issuer signs, then encrypts to recipient','jwtIssuer','Inner JWS and CEK are issuer-local; recipient alone owns the private decryption key.',{creates:[inner,cek,outer],uses:[publicRecipient,...a.artifacts.filter(o=>o.attributeId.endsWith('_issuer-private'))]});
  a.event('carrier','Carrier receives only outer JWE','jwtIssuer','Ciphertext envelope receipt does not grant inner bytes or the CEK.',{to:'jwtClient',objects:[outer],receives:[outer]});
  a.event('receive','Recipient receives the same JWE envelope','jwtClient','The recipient inbox still holds only ciphertext; decryption has not occurred.',{to:'jwtAPI',objects:[outer],receives:[outer],puts:{received:true}});
  const decrypted=jwtDecryptFixture({token:f.encryptedToken,recipientKeyId:recipient.value.id,evidence:f.decryptionEvidence});
  const verdict=a.object('decrypt-evidence','Authored SYM authenticated-decrypt decision','verification','jwtAPI',{kind:'SYM',recipientKeyId:recipient.value.id,recipientArtifactId:recipient.artifactId,encryptionPublicKeyId:publicRecipient.value.id,evidence:{kind:f.decryptionEvidence.kind,recipientKeyId:f.decryptionEvidence.recipientKeyId,tokenInstanceId:f.decryptionEvidence.tokenInstanceId,compact:f.decryptionEvidence.compact},code:decrypted.code,valid:decrypted.ok},['jwtAPI'],{derivedFrom:outer});
  a.event('unwrap','Check encryption parameters, recipient key and tag evidence','jwtAPI',decrypted.ok?'Recipient-local authenticated unwrap exposes inner bytes. Encryption alone has not established issuer identity.':'Reject '+decrypted.code+' before any plaintext/CEK acquisition.',{objects:[outer,recipient,...(decrypted.ok?[inner,cek]:[])],creates:[verdict],acquisitions:decrypted.ok?[a.acquire(inner,'jwtAPI',inner.representationId),a.acquire(cek,'jwtAPI')]:[],kind:'decrypt',puts:decrypted.ok?{decrypted:true}:{failure:{stage:'decrypt',code:decrypted.code}}});
  if(decrypted.ok)jwtLabValidation(a,f,inner);
  return a.finish({relatedLessons:[{id:'lab-jwt02',title:'Signed JWT validation',summary:'Inner signatures and profile claims remain required after JWE decryption.'}]});
}

function jwtLab04(variantId){
  const choices=['default','none','hs256-confusion','keytype-mismatch','wrong-use','wrong-key-ops','unknown-critical'],f=jwtLabFixture('lab-jwt04');
  if(variantId==='none')f.header.alg='none';if(variantId==='hs256-confusion')f.header.alg='HS256';
  if(variantId==='keytype-mismatch')f.keys[0].kty='oct';if(variantId==='wrong-use')f.keys[0].use='enc';if(variantId==='wrong-key-ops')f.keys[0].key_ops=['sign'];
  if(variantId==='unknown-critical'){f.header.crit=['unknown'];f.header.unknown=true;}jwtLabReissue(f);
  const a=jwtLabAuthor(4,'Algorithm and key-type confusion rejected','Who chooses the algorithm: the configured verifier or the untrusted token?',variantId,choices,f);jwtLabPrivate(a,f);
  const config=a.artifacts.find(o=>o.attributeId.endsWith('_configured-profile'));a.event('configure','Install immutable RS256-only accepting profile','jwtAPI','This profile rejects unsigned tokens and never reinterprets RSA public bytes as an HMAC secret. This is not a universal RFC7519 ban on unsecured JWT.',{objects:[config],puts:{allowedAlgorithms:['RS256']}});
  const token=jwtLabToken(a,f);jwtLabDelivery(a,token);jwtLabValidation(a,f,token);return a.finish();
}

function jwtLab05(variantId){
  const choices=['default','untrusted-jku','untrusted-x5u','unknown-kid','ambiguous-kid','discovery-issuer'],f=jwtLabFixture('lab-jwt05');
  if(variantId==='untrusted-jku')f.header.jku='https://evil.demo.example/jwks';if(variantId==='untrusted-x5u')f.header.x5u='https://evil.demo.example/cert';if(variantId==='unknown-kid')f.header.kid='unknown';if(variantId==='ambiguous-kid')f.keys.push({...f.key,id:'second-public-key'});
  f.discovery={issuer:variantId==='discovery-issuer'?'https://evil.demo.example':jwtLabIssuer,jwks_uri:jwtLabIssuer+'/keys',expectedJwksUri:jwtLabIssuer+'/keys',httpsTrusted:true};jwtLabReissue(f);
  const a=jwtLabAuthor(5,'Issuer trust, discovery, kid and JWKS','Why is a kid or a downloaded public key not proof of trust?',variantId,choices,f);jwtLabPrivate(a,{...f,keys:[]});
  const token=jwtLabToken(a,f);jwtLabDelivery(a,token);
  const query=a.object('discovery-request','Configured issuer discovery request','request','jwtAPI',{url:jwtLabIssuer+'/.well-known/openid-configuration'},['jwtAPI','jwtIssuer']);
  a.event('discovery-request','Request configured issuer metadata','jwtAPI','Only the preconfigured issuer is consulted. No token-supplied URL is followed.',{to:'jwtIssuer',creates:[query],objects:[query],receives:[query]});
  const metadata=a.object('metadata-wire','Issuer discovery response','metadata','jwtIssuer',{issuer:f.discovery.issuer,jwks_uri:f.discovery.jwks_uri},['jwtIssuer','jwtAPI'],{representation:'wire'});
  a.event('discover','Receive metadata over configured HTTPS trust','jwtIssuer','Metadata receipt precedes exact issuer and trusted JWKS URI validation.',{to:'jwtAPI',creates:[metadata],objects:[metadata],receives:[metadata]});
  if(f.discovery.issuer!==f.profile.issuer){const decision=a.object('discovery-rejection','Discovery issuer mismatch','error','jwtAPI',{expected:f.profile.issuer,actual:f.discovery.issuer},['jwtAPI']);a.event('select','Reject metadata for another issuer','jwtAPI','Discovery issuer mismatch stops before JWKS fetch or signature acceptance.',{objects:[metadata],creates:[decision],kind:'verify',puts:{failure:{stage:'trust',code:'discovery-issuer'}}});return a.finish();}
  const trusted=a.object('trusted-metadata','Validated issuer metadata revision','metadata','jwtAPI',{...f.discovery,revision:'snapshot1'},['jwtAPI'],{representation:'accepted',derivedFrom:metadata});
  a.event('metadata-validate','Validate configured issuer and JWKS location','jwtAPI','Exact issuer equality, configured HTTPS trust and trusted URI precede key retrieval.',{objects:[metadata],creates:[trusted],kind:'verify',puts:{metadataTrusted:true}});
  const jwksRequest=a.object('jwks-request','Trusted URI key request','request','jwtAPI',{url:f.discovery.jwks_uri},['jwtAPI','jwtIssuer']);a.event('jwks-request','Fetch only the trusted JWKS URI','jwtAPI','Public verification keys are scoped to this issuer, never arbitrary token URLs.',{to:'jwtIssuer',creates:[jwksRequest],objects:[jwksRequest],receives:[jwksRequest]});
  const keyset=a.object('jwks-wire','Public JWKS response','key-set','jwtIssuer',{issuer:jwtLabIssuer,keys:f.keys,revision:'jwks1'},['jwtIssuer','jwtAPI'],{representation:'wire'});
  a.event('fetch','Receive public key candidates','jwtIssuer','JWKS reception/cache is distinct from candidate filtering and signature verification. No issuer private key is published.',{to:'jwtAPI',creates:[keyset],objects:[keyset],receives:[keyset]});
  const cache=a.object('jwks-cache','Issuer-scoped candidate cache','key-set','jwtAPI',{issuer:jwtLabIssuer,revision:'jwks1',keys:f.keys},['jwtAPI'],{derivedFrom:keyset});a.event('cache','Store issuer-bound public candidates','jwtAPI','kid is only an untrusted selector within this key set, not a key or globally unique identity.',{objects:[keyset],creates:[cache],kind:'store',puts:{keyCacheRevision:'jwks1'}});
  jwtLabValidation(a,f,token);return a.finish();
}

function jwtLab06(variantId){
  const choices=['default','unknown-kid-flood','refresh-timeout','missing-new-key','stale-cache','retry-budget'],f=jwtLabFixture('lab-jwt06');
  const oldKey={...f.key},newKey={...f.key,id:'issuer-public-generation2',kid:'generation2'};f.header.kid=newKey.kid;f.key=newKey;f.keys=[newKey];f.signatureEvidence.keyId=newKey.id;jwtLabReissue(f);
  f.cache={issuer:jwtLabIssuer,keys:[oldKey],fetchedAt:f.now-10,lastRefreshAt:null,inFlight:false,negativeKids:[]};
  if(variantId==='retry-budget')f.cache.lastRefreshAt=f.now-29;if(variantId==='stale-cache')f.cache.fetchedAt=f.now-300;
  f.refreshKeys=variantId==='missing-new-key'?[oldKey]:[oldKey,newKey];
  f.unknownRequests=variantId==='unknown-kid-flood'?Array.from({length:32},(_,n)=>({instanceId:'flood-token'+n,kid:'unknown'+n,compact:jwtLabCompact({...f.header,kid:'unknown'+n},f.claims,'SYM(untrusted-signature)')})):[];
  f.refreshClock=variantId==='refresh-timeout'?f.now+2:f.now;
  f.unrelatedFixture=jwtLabFixture('lab-jwt06:unrelated-old');f.unrelatedFixture.now=f.refreshClock;f.unrelatedFixture.keys=[oldKey];
  const a=jwtLabAuthor(6,'JWKS rotation and bounded refresh','How can rotation recover an unknown key without an unbounded refresh loop?',variantId,choices,f);jwtLabPrivate(a,{...f,keys:[oldKey]});
  const signing2=a.seed(a.object('new-signing-private','Issuer signing key generation2','key','jwtIssuer','HANDLE(issuer-RSA-private-generation2)',['jwtIssuer'],{generation:2}));
  const cache0=a.seed(a.object('cache0','Initial issuer cache revision0','key-set','jwtAPI',f.cache,['jwtAPI']));
  const oldToken=a.seed(a.object('unrelated-old-token','Previously issued unrelated old-key bearer token','token','jwtIssuer',f.unrelatedFixture.token.compact,['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire'}),['jwtIssuer','jwtClient']);
  const publication=a.object('published-overlap','Issuer old/new public key overlap','key-set','jwtIssuer',{keys:[oldKey,newKey],retainedSigningKeys:['HANDLE(old-private)','HANDLE(new-private)']},['jwtIssuer']);
  a.event('overlap','Publish new key before new-kid issuance','jwtIssuer','The issuer retains signing generations during declared overlap; only public keys are published.',{creates:[publication]});
  const token=jwtLabToken(a,f);a.event('issue','Issue generation2 signed token','jwtIssuer','The token names the new key only after overlap publication.',{creates:[token],uses:[signing2]});a.event('deliver','Holder receives new-key token','jwtIssuer','No key refresh is required at the bearer holder.',{to:'jwtClient',objects:[token],receives:[token]});a.event('new-token','API receives a token with unknown new kid','jwtClient','Pending tokens remain unaccepted while the issuer-scoped cache policy decides.',{to:'jwtAPI',objects:[token],receives:[token],puts:{received:true}});
  let originalTokenDecision=jwtRefreshDecision({cache:f.cache,kid:newKey.kid,now:f.now}),cache=originalTokenDecision.cache,fetchCount=0;
  const start=a.object('refresh-start','Issuer-scoped cache-check inputs','policy','jwtAPI',{issuer:jwtLabIssuer,kid:newKey.kid,clock:f.now,fetchedAt:f.cache.fetchedAt,lastRefreshAt:f.cache.lastRefreshAt},['jwtAPI']);a.event('refresh-start','Read the fixed issuer cache and request inputs','jwtAPI','Clock, freshness and retry inputs are explicit. No accepted token or resource permission is created.',{objects:[cache0],creates:[start]});
  if(originalTokenDecision.action==='refresh'){const request=a.object('refresh-request','One coalesced JWKS refresh','request','jwtAPI',{issuer:jwtLabIssuer,url:jwtLabIssuer+'/keys',timeoutSeconds:2},['jwtAPI','jwtIssuer']);a.event('refresh-request','Fetch the configured issuer JWKS once','jwtAPI','Concurrent pending tokens share this bounded refresh; none is accepted while fetching.',{to:'jwtIssuer',creates:[request],objects:[request],receives:[request]});fetchCount++;}
  const floodDecisions=[];
  if(f.unknownRequests.length){
    const batch=a.object('unknown-request-batch','Concurrent unknown-kid request fixtures','request-batch','jwtClient',f.unknownRequests,['jwtClient','jwtAPI'],{representation:'wire',meaning:'Teaching macro groups separate HTTPS bearer requests; not an invented HTTP batch protocol. Every compact token remains untrusted.'});
    a.event('unknown-requests','Receive grouped unknown-kid pressure','jwtClient','Explicit macro for concurrent independent bearer requests while one issuer refresh is pending; none is signature/claims accepted.',{to:'jwtAPI',creates:[batch],objects:[batch],receives:[batch]});
    for(const input of f.unknownRequests){
      const decision=jwtRefreshDecision({cache,kid:input.kid,now:f.refreshClock});cache=decision.cache;
      floodDecisions.push({requestInstanceId:input.instanceId,kid:input.kid,action:decision.action,code:decision.code});
      if(decision.action==='deny'){
        const rejection=a.object('flood-rejection-'+input.instanceId,'Request-specific flood rejection','error','jwtAPI',{action:'deny',code:decision.code,requestInstanceId:input.instanceId,kid:input.kid,cache:decision.cache,clock:f.refreshClock},['jwtAPI']);
        a.event('flood-deny-'+input.instanceId,'Reject only the excess bearer request','jwtAPI','Capacity rejection belongs to '+input.instanceId+' / '+input.kid+'. The admitted generation2 request remains pending.',{objects:[batch],creates:[rejection],kind:'verify',puts:{lastFloodRejection:{requestInstanceId:input.instanceId,kid:input.kid,code:decision.code}}});
      }
    }
  }
  originalTokenDecision=jwtRefreshDecision({cache,kid:newKey.kid,now:f.refreshClock});cache=originalTokenDecision.cache;
  const oldDecision=jwtRefreshDecision({cache,kid:oldKey.kid,now:f.refreshClock}),oldResult=oldDecision.action==='cached'?jwtValidateFixture(f.unrelatedFixture):null,oldAccepted=oldResult?.ok===true;
  a.event('unrelated-old-present','Present an independent old-key request during rotation','jwtClient','This exact already-issued bearer token is not the pending new-kid token and follows its own cache freshness policy.',{to:'jwtAPI',objects:[oldToken],receives:[oldToken],puts:{clock:f.refreshClock}});
  const oldVerdict=a.object('unrelated-old-decision','Independent old-token validation observation','verification','jwtAPI',{cacheDecision:oldDecision.action,cacheCode:oldDecision.code,validation:oldResult},['jwtAPI']);a.event('unrelated-old-validate','Evaluate independent cached-key token, not a global outage','jwtAPI',oldAccepted?'Fresh issuer-bound cached key and this token profile still validate independently. No resource grant follows.':'No stale cached key is accepted for the independent token either.',{objects:[oldToken,cache0],creates:[oldVerdict],kind:'verify',puts:{cachedOldAccepted:oldAccepted,unrelatedValidatedClaims:oldAccepted?oldResult.validatedClaims:null}});
  const refreshDecision=a.object('refresh-policy','Bounded refresh/cache policy inputs','policy','jwtAPI',{clock:f.refreshClock,requestInstanceId:f.token.instanceId,requestedKid:newKey.kid,originalTokenDecision:{action:originalTokenDecision.action,code:originalTokenDecision.code},floodDecisions,fetchCount,pendingKeyCount:cache.pendingKids?.length||0,unrelatedCachedKeyAccepted:oldAccepted,policy:{ttlSeconds:300,minRefreshSeconds:30,timeoutSeconds:2,negativeCapacity:16,negativeTtlSeconds:30}},['jwtAPI']);
  a.event('refresh-policy','Inspect explicit one-flight, clock and capacity inputs','jwtAPI','Demo policy: TTL300s, minimum retry30s, timeout2s, bounded16-entry negative/pending cache. Every arrival retains its own decision; these are not universal RFC/Kubernetes timings.',{objects:[cache0,token],creates:[refreshDecision],puts:{clock:f.refreshClock,refreshFetchCount:fetchCount,pendingKeyCount:cache.pendingKids?.length||0,cachedOldAccepted:oldAccepted}});
  if(originalTokenDecision.action==='deny'){const code=originalTokenDecision.code,rejection=a.object('refresh-rejection','Actual request-specific cache rejection','error','jwtAPI',{action:'deny',code,requestInstanceId:f.token.instanceId,kid:newKey.kid,cache,clock:f.refreshClock},['jwtAPI']);a.event('refresh-deny','Enforce the actual cache-policy detector','jwtAPI','The pure policy returned '+code+' for this exact original request. Unrelated accepted cached-key evidence is preserved; no global revocation is invented.',{objects:[refreshDecision,token],creates:[rejection],kind:'verify',puts:{failure:{stage:'refresh',code},cachedOldAccepted:oldAccepted}});return a.finish();}
  const response=a.object('refresh-response','Rotation JWKS response','key-set','jwtIssuer',{issuer:jwtLabIssuer,keys:f.refreshKeys,revision:'jwks2'},['jwtIssuer','jwtAPI'],{representation:'wire',generation:2});a.event('refresh-response','Receive public overlap revision2','jwtIssuer','A received cache response is not token signature acceptance.',{to:'jwtAPI',creates:[response],objects:[response],receives:[response]});
  const completed=jwtCompleteRefresh({cache,keys:f.refreshKeys,now:f.now+1,ok:true}),cache1=a.object('cache1','Refreshed issuer cache revision2','key-set','jwtAPI',completed.cache,['jwtAPI'],{generation:2,derivedFrom:response});
  a.event('refresh','Install timely issuer cache revision2','jwtAPI','Only a timely successful issuer-scoped refresh replaces the old cache. Missing kid still fails selection.',{objects:[response],creates:[cache1],releases:[cache0],kind:'store',puts:{clock:f.now+1,keyCacheRevision:'jwks2'}});
  f.keys=completed.cache.keys;jwtLabValidation(a,{...f,now:f.now+1},token);
  if(variantId==='missing-new-key')return a.finish();
  const retired=a.object('retired-cache','Post-overlap cache retirement','key-set','jwtAPI',{clock:f.now+901,oldKeyRetired:true,staleKeysAccepted:false,remainingPublishedKeys:[newKey]},['jwtAPI'],{generation:3});
  a.event('retire','Expire cache and retire old key after declared overlap','jwtAPI','Retirement is not instantaneous universal revocation. Prior completed acceptance history remains, but no stale cached key can authenticate a new request.',{creates:[retired],releases:[cache1],puts:{clock:f.now+901,oldKeyRetired:true,retirementClock:f.now+901,cacheFresh:false}});return a.finish();
}

function jwtLab07(variantId){
  const choices=['default','wrong-issuer','wrong-audience','expired','not-yet-valid','missing-required','milliseconds','string-exp','duplicate-claim','invalid-groups','iat-age'],f=jwtLabFixture('lab-jwt07');
  if(variantId==='wrong-issuer')f.claims.iss='https://other.demo.example';if(variantId==='wrong-audience')f.claims.aud='other-api';if(variantId==='expired')f.claims.exp=f.now-30;if(variantId==='not-yet-valid')f.claims.nbf=f.now+31;if(variantId==='missing-required')delete f.claims.sub;if(variantId==='milliseconds')f.claims.exp=1792627200000;if(variantId==='string-exp')f.claims.exp=String(f.now+300);if(variantId==='invalid-groups')f.claims.groups=[1];if(variantId==='iat-age')f.claims.iat=f.now-631;
  jwtLabReissue(f);if(variantId==='duplicate-claim'){const raw='{\"sub\":\"other\",'+JSON.stringify(f.claims).slice(1);f.token.compact=jwtLabEncode(f.header)+'.'+jwtLabEncode(raw)+'.'+jwtLabEncode('SYM(signature)');f.signatureEvidence.signingInput=f.token.compact.split('.').slice(0,2).join('.');}
  const a=jwtLabAuthor(7,'Issuer, audience, time and claim types','Why does a correctly signed token still fail this API profile?',variantId,choices,f);jwtLabPrivate(a,f);const token=jwtLabToken(a,f);jwtLabDelivery(a,token);jwtLabValidation(a,f,token);return a.finish();
}

function jwtLab08(variantId){
  const choices=['default','id-substitution','typ-alone','nonce-mismatch'],idFixture=jwtLabFixture('lab-jwt08:id'),access=jwtLabFixture('lab-jwt08:access');
  idFixture.profile={...idFixture.profile,audience:'demo-native',purpose:'oidc-id',nonce:'SYM(transaction-nonce1)'};idFixture.claims.aud=variantId==='id-substitution'?['demo-native',jwtLabAudience]:'demo-native';idFixture.claims.azp='demo-native';idFixture.claims.nonce=variantId==='nonce-mismatch'?'SYM(other-nonce)':'SYM(transaction-nonce1)';jwtLabReissue(idFixture);
  access.profile={...access.profile,purpose:'rfc9068-access'};access.header.typ='at+jwt';access.claims.scope='read';if(variantId==='typ-alone')access.claims.aud='demo-native';jwtLabReissue(access);
  const resource=variantId==='id-substitution'?{...idFixture,profile:access.profile}:access;
  const a=jwtLabAuthor(8,'ID tokens, access tokens and cross-JWT substitution','Which token is intended for the client, ordinary resource API or deliberately configured Kubernetes integration?',variantId,choices,{idToken:idFixture,accessToken:access,resourceToken:resource});jwtLabPrivate(a,access);
  a.seed(a.object('client-profile','OIDC client issuer/audience/nonce profile','policy','jwtClient',idFixture.profile,['jwtClient']));
  a.seed(a.object('client-public-key','Client configured issuer public key','key','jwtClient',idFixture.keys,['jwtClient']));
  const idToken=a.object('id-token','Client ID token','token','jwtIssuer',idFixture.token.compact,['jwtIssuer','jwtClient',...(variantId==='id-substitution'?['jwtAPI']:[])],{representation:'wire'}),accessToken=a.object('access-token','RFC9068 API access token','token','jwtIssuer',access.token.compact,['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire'});
  a.event('issue-tokens','Issue distinct ID and API access token artifacts','jwtIssuer','ID token targets demo-native; access token targets the ordinary API and carries at+jwt. No mandatory typ=id_token is invented.',{creates:[idToken,accessToken]});
  a.event('deliver','OIDC client receives token response','jwtIssuer','Refresh credentials, if present in a real client, remain client-local and never reach the API. This fixed response contains no refresh token.',{to:'jwtClient',objects:[idToken,accessToken],receives:[idToken,accessToken]});
  const clientResult=jwtLabValidation(a,idFixture,idToken,{stagePrefix:'client-',actor:'jwtClient'});
  if(!clientResult.ok)return a.finish();
  const login=a.object('client-login','OIDC client login identity','session','jwtClient',{issuer:jwtLabIssuer,subject:'alice',audience:'demo-native',transactionNonce:idFixture.profile.nonce},['jwtClient']);a.event('client-login','Map validated ID token to client login state','jwtClient','Client login is not resource API permission.',{creates:[login],puts:{clientLogin:true}});
  const presented=variantId==='id-substitution'?idToken:accessToken;a.event('resource-present','Present selected token to ordinary API','jwtClient','The resource applies its own mutually exclusive token profile, not the client login verdict.',{to:'jwtAPI',objects:[presented],receives:[presented]});
  const resourceResult=jwtLabValidation(a,resource,presented,{stagePrefix:'resource-'});
  if(!resourceResult.ok)return a.finish();
  const principal=a.object('resource-principal','Resource relying-party principal','identity','jwtAPI',{issuer:jwtLabIssuer,subject:resourceResult.validatedClaims.sub},['jwtAPI']);a.event('resource-map','Map accepted resource claims to principal','jwtAPI','Principal mapping is separate from signature and claims acceptance.',{creates:[principal],puts:{resourceClaimsAccepted:true,principal:principal.value}});
  const allowed=typeof resourceResult.validatedClaims.scope==='string'&&resourceResult.validatedClaims.scope.split(' ').includes('read'),grant=a.object('resource-grant','Exact read authorization decision','authorization','jwtAPI',{action:'read',requiredScope:'read',actualScope:resourceResult.validatedClaims.scope,allowed},['jwtAPI']);a.event('resource-authorize','Authorize the exact API read using scope','jwtAPI','Validated claims alone grant nothing; the API separately checks the requested action.',{objects:[principal],creates:[grant],kind:'verify',puts:{authorized:allowed}});
  a.event('link-kubernetes','Compare the deliberate Kubernetes ID-token integration','jwtAPI','K8S01 deliberately configures an appropriate ID token as bearer credential. Ordinary APIs do not universally accept ID tokens, and token origin is not itself a magic Kubernetes check.',{objects:[grant]});
  return a.finish({relatedLessons:[{id:'lab-k8s01',title:'Human OIDC login to Kubernetes',summary:'A deliberately configured ID-token audience, issuer and mapping, not ordinary API substitution.'}]});
}

function jwtLab09(variantId){
  const choices=['default','introspection-timeout','inactive','expired-jwt','stale-introspection','wrong-introspection-audience'],f=jwtLabFixture('lab-jwt09');
  f.introspection={response:{active:variantId!=='inactive',sub:'alice',aud:variantId==='wrong-introspection-audience'?'other-api':jwtLabAudience,exp:f.now+300,scope:'read'},authenticated:true,expectedAudience:jwtLabAudience,now:f.now,cachedAt:variantId==='stale-introspection'?f.now-15:f.now,ttlSeconds:15,timeout:variantId==='introspection-timeout'};
  const a=jwtLabAuthor(9,'Bearer possession, replay and validation lifetime','Why can the same bearer token work twice, and why are logout, expiration and introspection different?',variantId,choices,f);jwtLabPrivate(a,f);
  const token=jwtLabToken(a,f);jwtLabDelivery(a,token);const result=jwtLabValidation(a,f,token);
  if(!result.ok)return a.finish();
  const principal=a.object('principal','Local resource principal','identity','jwtAPI',{issuer:jwtLabIssuer,subject:result.validatedClaims.sub},['jwtAPI']);a.event('map','Map accepted subject to API principal','jwtAPI','No proof-of-possession or sender binding has been established.',{creates:[principal],puts:{principal:principal.value}});
  const grant=a.object('first-grant','First exact resource authorization','authorization','jwtAPI',{action:'read',group:'readers',allowed:result.validatedClaims.groups.includes('readers')},['jwtAPI']);a.event('authorize','Authorize and complete first resource action','jwtAPI','The explicit readers grant, not jti or token format, permits the first read.',{objects:[principal],creates:[grant],kind:'verify',puts:{authorized:grant.value.allowed,completedActions:grant.value.allowed?1:0}});
  const firstResult=a.object('first-result','First protected API response','result','jwtAPI',{status:200,request:'read1',body:'synthetic protected resource'},['jwtAPI','jwtClient'],{representation:'wire'});a.event('respond','Return first response over TLS','jwtAPI','Response receipt is not a sender-constraint on the bearer credential.',{to:'jwtClient',creates:[firstResult],objects:[firstResult],receives:[firstResult]});a.event('result-accept','Accept first correlated response','jwtClient','The holder learns the completed first action only after its actual response.',{objects:[firstResult],kind:'verify',puts:{resultReceived:true}});
  const logout=a.object('issuer-session','Issuer logout/session status','status','jwtIssuer',{active:false,issuedTokenRevoked:false},['jwtIssuer']);a.event('issuer-logout','End issuer session without revoking every issued JWT','jwtIssuer','No revocation/introspection call is configured for the next local JWT validation.',{creates:[logout],puts:{issuerSessionActive:false}});
  a.event('replay-present','Present the exact same bearer bytes again','jwtClient','jti alone creates no replay cache, and signing/encryption alone do not bind a sender.',{to:'jwtAPI',objects:[token],receives:[token],puts:{authorized:false}});
  const second=jwtValidateFixture(f),secondDecision=a.object('replay-validation','Second local JWT validation decision','verification','jwtAPI',{ok:second.ok,signatureValid:second.signatureValid,issuerSessionChecked:false,introspectionCalled:false,replayCache:false},['jwtAPI']);a.event('replay-validate','Validate again with local cached key and context','jwtAPI','No per-request issuer session or revocation query occurs in this local JWT profile.',{objects:[token],creates:[secondDecision],kind:'verify'});
  const secondAllowed=second.ok&&second.validatedClaims.groups.includes('readers'),secondGrant=a.object('second-grant','Second exact read authorization','authorization','jwtAPI',{request:'read2',allowed:secondAllowed},['jwtAPI']);a.event('replay-authorize','Authorize second request independently','jwtAPI','The unchanged valid bearer token can authorize another requested read; this is not proof of possession.',{objects:[principal],creates:[secondGrant],kind:'verify',puts:{authorized:secondAllowed,completedActions:secondAllowed?2:1}});
  const secondResult=a.object('second-result','Second protected API response','result','jwtAPI',{status:200,request:'read2',body:'synthetic second result'},['jwtAPI','jwtClient'],{representation:'wire'});a.event('replay-response','Return second completed result','jwtAPI','Prior actions remain completed after later expiration or revocation changes.',{to:'jwtClient',creates:[secondResult],objects:[secondResult],receives:[secondResult]});
  const opaque=a.object('opaque','Opaque bearer comparison token','token','jwtIssuer','HANDLE(opaque-reference1)',['jwtIssuer','jwtClient','jwtAPI'],{representation:'wire'});a.event('opaque-issue','Create opaque comparison credential','jwtIssuer','Opaque client representation does not mean weaker validation.',{creates:[opaque]});a.event('opaque-deliver','Deliver opaque credential to holder','jwtIssuer','Only the selected reference bytes leave the issuer.',{to:'jwtClient',objects:[opaque],receives:[opaque]});a.event('opaque-present','Present opaque reference to API','jwtClient','The API must use the declared protected introspection profile, not guess JWT claims.',{to:'jwtAPI',objects:[opaque],receives:[opaque],puts:{authorized:false}});
  const authentication=a.seed(a.object('introspection-client-credential','API introspection authentication credential','key','jwtAPI','HANDLE(api-introspection-credential)',['jwtAPI']));
  a.event('introspection-authenticate','Use API-local introspection credential','jwtAPI','Only a separate authored authentication proof goes into the status request; private API credentials remain local.',{objects:[authentication],kind:'derive'});
  const query=a.object('introspection-request','Authenticated RFC7662 token-status request','request','jwtAPI',{token:opaque.value,clientAuthentication:'SYM(authenticated API client)',expectedAudience:jwtLabAudience},['jwtAPI','jwtIssuer']);
  a.event('introspection-request','Authenticate API to protected introspection endpoint','jwtAPI','Introspection uses its own API-client credential, not the issuer signing key or a user refresh token.',{to:'jwtIssuer',creates:[query],objects:[query],receives:[query]});
  let status=null;
  if(!f.introspection.timeout){status=a.object('introspection-status','Protected token-status response/cache entry','status','jwtIssuer',{...f.introspection.response,evaluatedAt:f.introspection.cachedAt,cacheTtlSeconds:15},['jwtIssuer','jwtAPI'],{representation:'wire'});a.event('introspection-response','Receive explicit active status evidence','jwtIssuer','Current status and cache evaluation time remain distinct from local JWT signature validity.',{to:'jwtAPI',creates:[status],objects:[status],receives:[status]});}
  const introspected=jwtIntrospectionDecision(f.introspection),statusDecision=a.object('introspection-decision','Opaque profile status decision','policy','jwtAPI',{ok:introspected.ok,code:introspected.code,evaluatedAt:f.introspection.now,cachedAt:f.introspection.cachedAt,ttlSeconds:15},['jwtAPI']);
  a.event('introspection-evaluate','Check active, audience, lifetime and bounded status age','jwtAPI',introspected.ok?'Authenticated current status is accepted for this resource; authorization would still be separate.':'Fail closed at '+introspected.code+' without a new grant. Completed JWT requests remain completed.',{objects:status?[status]:[query],uses:[authentication],creates:[statusDecision],kind:'verify',puts:introspected.ok?{opaqueActive:true}:{failure:{stage:'introspection',code:introspected.code},authorized:false}});
  if(!introspected.ok){jwtLabBearerError(a,'introspection-error',['timeout','stale-response'].includes(introspected.code)?503:401,introspected.code);return a.finish();}
  a.event('expire-present','Present bearer bytes after the selected expiration boundary','jwtClient','This next request must be validated again; prior completed actions and received results are retained.',{to:'jwtAPI',objects:[token],receives:[token],puts:{clock:f.claims.exp+30+(variantId==='expired-jwt'?1:0),authorized:false}});
  const expired=jwtValidateFixture({...f,now:f.claims.exp+30+(variantId==='expired-jwt'?1:0)}),inactive=jwtIntrospectionDecision({...f.introspection,now:f.claims.exp+30,cachedAt:f.claims.exp+30,response:{...f.introspection.response,active:false}});
  const lifetime=a.object('lifetime-decision','Later JWT lifetime versus opaque revocation decision','policy','jwtAPI',{clock:f.claims.exp+30+(variantId==='expired-jwt'?1:0),jwt:{ok:expired.ok,code:expired.code},introspection:{ok:inactive.ok,code:inactive.code},logoutDidNotRevokeLocalJWT:true,priorActionsUndone:false},['jwtAPI']);
  a.event('expire','Advance deterministic clock and compare rejection points','jwtAPI','JWT expiry stops the next request at local claims validation. Opaque status can separately become inactive. Logout/key retirement does not retroactively undo completed actions or universally revoke self-contained JWTs.',{objects:[token,statusDecision],creates:[lifetime],kind:'verify',puts:{failure:{stage:expired.stage,code:expired.code},authorized:false,opaqueActive:false,introspectionFailure:inactive.code}});jwtLabBearerError(a,'expired-error',401,expired.code);return a.finish();
}

const jwtLabFactories={1:jwtLab01,2:jwtLab02,3:jwtLab03,4:jwtLab04,5:jwtLab05,6:jwtLab06,7:jwtLab07,8:jwtLab08,9:jwtLab09};
const jwtLabChoices={
  1:['default','malformed-segments','malformed-base64url','malformed-json','oauth-field-name'],
  2:['default','payload-tamper','signature-tamper','other-api'],
  3:['default','wrong-recipient','changed-tag','invalid-inner-signature'],
  4:['default','none','hs256-confusion','keytype-mismatch','wrong-use','wrong-key-ops','unknown-critical'],
  5:['default','untrusted-jku','untrusted-x5u','unknown-kid','ambiguous-kid','discovery-issuer'],
  6:['default','unknown-kid-flood','refresh-timeout','missing-new-key','stale-cache','retry-budget'],
  7:['default','wrong-issuer','wrong-audience','expired','not-yet-valid','missing-required','milliseconds','string-exp','duplicate-claim','invalid-groups','iat-age'],
  8:['default','id-substitution','typ-alone','nonce-mismatch'],
  9:['default','introspection-timeout','inactive','expired-jwt','stale-introspection','wrong-introspection-audience']
};
export function createJWTScenario(number,variantId='default'){
  const numeric=typeof number==='string'?Number(number.replace(/^JWT|^lab-jwt/,'')):number;
  if(!jwtLabFactories[numeric])throw new RangeError('Unknown JWT lesson: '+number);
  if(!jwtLabChoices[numeric].includes(variantId))throw new RangeError('Unknown JWT variant: '+variantId);
  return jwtLabFactories[numeric](variantId);
}
export function createJWTNegativeFixture(number,variantId){if(typeof variantId!=='string'||variantId==='default')throw new RangeError('A negative/comparison fixture needs a named variant.');return createJWTScenario(number,variantId);}
export const JWTLAB_SCENARIOS=Object.freeze(Object.keys(jwtLabFactories).map(number=>createJWTScenario(Number(number))));
