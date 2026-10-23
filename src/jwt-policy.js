// Offline fixture decisions only. SYM evidence is authored, never cryptographic proof.
function jwtPolicyCopy(value) { return value == null ? value : JSON.parse(JSON.stringify(value)); }
function jwtPolicyJSON(text) {
  let at=0;
  const whitespace=()=>{while(/\s/.test(text[at]||'')&&at<text.length)at++;};
  const string=()=>{const start=at++;while(at<text.length){if(text[at]==='\\'){at+=2;continue;}if(text[at++]==='"')return JSON.parse(text.slice(start,at));}throw new Error('json');};
  const value=()=>{whitespace();if(text[at]==='{'){at++;const keys=new Set();whitespace();if(text[at]==='}'){at++;return;}while(at<text.length){whitespace();if(text[at]!=='"')throw new Error('json');const key=string();if(keys.has(key))throw new Error('duplicate-key');keys.add(key);whitespace();if(text[at++]!==':')throw new Error('json');value();whitespace();const end=text[at++];if(end==='}')return;if(end!==',')throw new Error('json');}throw new Error('json');}if(text[at]==='['){at++;whitespace();if(text[at]===']'){at++;return;}while(at<text.length){value();whitespace();const end=text[at++];if(end===']')return;if(end!==',')throw new Error('json');}throw new Error('json');}if(text[at]==='"'){string();return;}const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(at));if(!match)throw new Error('json');at+=match[0].length;};
  value();whitespace();if(at!==text.length)throw new Error('json');const parsed=JSON.parse(text);if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error('json-object');return parsed;
}
function jwtPolicySegment(segment) {
  if(typeof segment!=='string'||!/^[A-Za-z0-9_-]*$/.test(segment)||segment.length%4===1)throw new Error('base64url');
  let binary;try{binary=atob(segment.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-segment.length%4)%4));}catch{throw new Error('base64url');}
  if(btoa(binary).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==segment)throw new Error('base64url');
  return Uint8Array.from(binary,c=>c.charCodeAt(0));
}
function jwtPolicyText(segment) {try{return new TextDecoder('utf-8',{fatal:true}).decode(jwtPolicySegment(segment));}catch(error){throw new Error(error.message==='base64url'?'base64url':'utf8');}}
export function jwtParseCompact(compact,{representation='jws'}={}) {
  try{
    if(typeof compact!=='string'||!compact||compact.length>65536)throw new Error('token-size');
    if(representation==='opaque')return {ok:true,stage:'parsed',code:'opaque',opaque:compact};
    if(!['jws','jwe'].includes(representation))throw new Error('representation');
    const segments=compact.split('.');if(segments.length!==(representation==='jws'?3:5))throw new Error('segment-count');
    segments.forEach(jwtPolicySegment);if(!segments[0])throw new Error('json');const header=jwtPolicyJSON(jwtPolicyText(segments[0]));
    if(representation==='jwe'){if(segments.some(segment=>!segment))throw new Error('empty-segment');return {ok:true,stage:'parsed',code:'jwe-envelope',header,segments};}
    const claims=jwtPolicyJSON(jwtPolicyText(segments[1]));return {ok:true,stage:'parsed',code:'readable-untrusted',header,claims,segments,signingInput:segments.slice(0,2).join('.')};
  }catch(error){return {ok:false,stage:'parse',code:error.message};}
}
export function jwtValidateFixture({token,profile,keys=[],signatureEvidence,now,discovery}={}) {
  const parsed=jwtParseCompact(token?.compact),observations=[];
  const finish=(ok,stage,code,extra={})=>({ok,stage,code,observations,untrustedClaims:parsed.claims?jwtPolicyCopy(parsed.claims):null,validatedClaims:null,keyId:null,signatureValid:false,...extra});
  if(!parsed.ok)return finish(false,'parse',parsed.code);
  const check=(condition,stage,code,actual,expected)=>{observations.push({stage,code,ok:!!condition,actual:jwtPolicyCopy(actual),expected:jwtPolicyCopy(expected)});return !!condition;};
  const fail=(stage,code,extra)=>finish(false,stage,code,extra);
  if(!profile||!check(typeof profile.issuer==='string'&&profile.issuer.length>0&&typeof profile.audience==='string'&&profile.audience.length>0,'trust','configured-profile',profile?.id,'configured issuer and audience'))return fail('trust','configured-profile');
  if(discovery){if(!check(discovery.issuer===profile.issuer,'trust','discovery-issuer',discovery.issuer,profile.issuer))return fail('trust','discovery-issuer');if(!check(discovery.httpsTrusted===true&&/^https:\/\//.test(discovery.jwks_uri)&&discovery.jwks_uri===discovery.expectedJwksUri,'trust','discovery-uri',discovery.jwks_uri,discovery.expectedJwksUri))return fail('trust','discovery-uri');}
  const h=parsed.header,c=parsed.claims;
  if(!check(!('jku'in h)&&!('x5u'in h),'header','remote-key-url',h.jku||h.x5u,'configured issuer key source only'))return fail('header','remote-key-url');
  if(!check(Array.isArray(profile.algorithms)&&h.alg!=='none'&&profile.algorithms.includes(h.alg),'header','algorithm',h.alg,profile.algorithms))return fail('header','algorithm');
  if(!check(h.crit===undefined||(Array.isArray(h.crit)&&h.crit.length>0&&new Set(h.crit).size===h.crit.length&&h.crit.every(name=>typeof name==='string'&&name in h&&(profile.processedCriticalHeaders||[]).includes(name))),'header','critical-header',h.crit,profile.processedCriticalHeaders||[]))return fail('header','critical-header');
  if(!check(h.b64===undefined||h.b64===true,'header','payload-encoding',h.b64,'base64url JWT payload'))return fail('header','payload-encoding');
  if(!check(typeof h.kid==='string'&&h.kid.length>0,'key','kid-type',h.kid,'nonempty string'))return fail('key','kid-type');
  const candidates=keys.filter(key=>key.issuer===profile.issuer&&key.kid===h.kid);
  if(!check(candidates.length===1,'key',candidates.length?'ambiguous-kid':'unknown-kid',candidates.length,1))return fail('key',candidates.length?'ambiguous-kid':'unknown-kid');
  const key=candidates[0],keyContext={keyId:key.id};
  if(!check(h.alg==='RS256'&&key.kty==='RSA','key','key-type',key.kty,'RSA for explicit RS256 fixture'))return fail('key','key-type',keyContext);
  if(!check(!key.alg||key.alg===h.alg,'key','key-algorithm',key.alg,h.alg))return fail('key','key-algorithm',keyContext);
  if(!check(!key.use||key.use==='sig','key','key-use',key.use,'sig'))return fail('key','key-use',keyContext);
  if(!check(!key.key_ops||(Array.isArray(key.key_ops)&&key.key_ops.includes('verify')&&!key.key_ops.some(op=>['decrypt','encrypt','unwrapKey','wrapKey','deriveKey','deriveBits'].includes(op))),'key','key-ops',key.key_ops,['verify']))return fail('key','key-ops',keyContext);
  const e=signatureEvidence;
  if(!check(e?.kind==='SYM'&&e.valid===true&&e.tokenInstanceId===token.instanceId&&e.keyId===key.id&&e.signingInput===parsed.signingInput&&e.signatureSegment===parsed.segments[2]&&!!parsed.segments[2],'signature','signature-evidence',e,{kind:'SYM',tokenInstanceId:token.instanceId,keyId:key.id,signingInput:parsed.signingInput,signatureSegment:parsed.segments[2]}))return fail('signature','signature-evidence',keyContext);
  const signed={...keyContext,signatureValid:true};
  for(const claim of profile.requiredClaims||['iss','sub','aud','exp'])if(!check(Object.hasOwn(c,claim),'claims','required-'+claim,Object.hasOwn(c,claim),true))return fail('claims','required-'+claim,signed);
  for(const claim of ['iss','sub'])if(!check(typeof c[claim]==='string'&&c[claim].length>0,'claims','claim-type-'+claim,c[claim],'nonempty string'))return fail('claims','claim-type-'+claim,signed);
  if(!check(c.iss===profile.issuer,'claims','issuer',c.iss,profile.issuer))return fail('claims','issuer',signed);
  const audOK=typeof c.aud==='string'||(profile.audienceArray!==false&&Array.isArray(c.aud)&&c.aud.length>0&&c.aud.every(a=>typeof a==='string'&&a.length>0));
  if(!check(audOK,'claims','claim-type-aud',c.aud,'string or permitted string array'))return fail('claims','claim-type-aud',signed);
  if(!check((Array.isArray(c.aud)?c.aud:[c.aud]).includes(profile.audience),'claims','audience',c.aud,profile.audience))return fail('claims','audience',signed);
  for(const claim of ['exp','nbf','iat'])if(Object.hasOwn(c,claim)){if(!check(typeof c[claim]==='number'&&Number.isFinite(c[claim]),'claims','claim-type-'+claim,c[claim],'finite NumericDate seconds'))return fail('claims','claim-type-'+claim,signed);if(!check(Math.abs(c[claim])<(profile.numericDateMax??100000000000),'claims','numeric-date-'+claim,c[claim],'demo NumericDate range in seconds'))return fail('claims','numeric-date-'+claim,signed);}
  if(!check(Number.isFinite(now),'claims','clock',now,'explicit seconds'))return fail('claims','clock',signed);
  const skew=profile.skewSeconds??0;
  if(c.exp!==undefined&&!check(now< c.exp+skew,'claims','expired',now,c.exp+skew))return fail('claims','expired',signed);
  if(c.nbf!==undefined&&!check(now+skew>=c.nbf,'claims','not-yet-valid',now+skew,c.nbf))return fail('claims','not-yet-valid',signed);
  if(c.iat!==undefined&&!check(c.iat<=now+skew,'claims','issued-in-future',c.iat,now+skew))return fail('claims','issued-in-future',signed);
  if(profile.maxAgeSeconds!==undefined&&c.iat!==undefined&&!check(now-c.iat<=profile.maxAgeSeconds+skew,'claims','issued-too-old',now-c.iat,profile.maxAgeSeconds+skew))return fail('claims','issued-too-old',signed);
  if(profile.maxLifetimeSeconds!==undefined&&!check(typeof c.iat==='number'&&typeof c.exp==='number'&&c.exp>=c.iat&&c.exp-c.iat<=profile.maxLifetimeSeconds,'claims','lifetime',c.exp-c.iat,profile.maxLifetimeSeconds))return fail('claims','lifetime',signed);
  for(const [claim,type]of Object.entries(profile.claimTypes||{})){const v=c[claim];const ok=type==='string-array'?Array.isArray(v)&&v.every(x=>typeof x==='string'):type==='number'?typeof v==='number'&&Number.isFinite(v):typeof v===type;if(!check(ok,'claims','claim-type-'+claim,v,type))return fail('claims','claim-type-'+claim,signed);}
  for(const [claim,expected]of Object.entries(profile.requiredClaimValues||{}))if(!check(c[claim]===expected,'claims','claim-value-'+claim,c[claim],expected))return fail('claims','claim-value-'+claim,signed);
  if(profile.purpose==='rfc9068-access'){
    if(!check(['at+jwt','application/at+jwt'].includes(h.typ),'claims','purpose-type',h.typ,'at+jwt'))return fail('claims','purpose-type',signed);
    for(const claim of ['exp','aud','sub','client_id','iat','jti'])if(!check(Object.hasOwn(c,claim),'claims','required-'+claim,c[claim],'RFC9068 required claim'))return fail('claims','required-'+claim,signed);
    for(const claim of ['client_id','jti'])if(!check(typeof c[claim]==='string'&&c[claim].length>0,'claims','claim-type-'+claim,c[claim],'nonempty string'))return fail('claims','claim-type-'+claim,signed);
  }
  if(profile.nonce!==undefined&&!check(c.nonce===profile.nonce,'claims','nonce',c.nonce,profile.nonce))return fail('claims','nonce',signed);
  return finish(true,'accepted','accepted',{...signed,validatedClaims:jwtPolicyCopy(c)});
}
export function jwtDecryptFixture({token,recipientKeyId,evidence}={}) {
  const parsed=jwtParseCompact(token?.compact,{representation:'jwe'});if(!parsed.ok)return parsed;
  const h=parsed.header;if(h.alg!=='RSA-OAEP-256'||h.enc!=='A128GCM'||h.cty!=='JWT')return {ok:false,stage:'decrypt',code:'encryption-profile'};
  if(evidence?.recipientKeyId!==recipientKeyId)return {ok:false,stage:'decrypt',code:'recipient-key'};
  if(evidence?.kind!=='SYM'||evidence.valid!==true||evidence.tokenInstanceId!==token.instanceId||evidence.compact!==token.compact||typeof evidence.innerCompact!=='string')return {ok:false,stage:'decrypt',code:'aead-evidence'};
  return {ok:true,stage:'decrypted',code:'readable-untrusted-inner',innerCompact:evidence.innerCompact};
}
function jwtRefreshPolicy(policy={}) {return {ttlSeconds:300,minRefreshSeconds:30,timeoutSeconds:2,negativeTtlSeconds:30,negativeCapacity:16,...policy};}
export function jwtRefreshDecision({cache,kid,now,policy}={}) {
  const p=jwtRefreshPolicy(policy),next=jwtPolicyCopy(cache);next.negativeKids=(next.negativeKids||[]).filter(entry=>entry.until>now).slice(-p.negativeCapacity);next.pendingKids=(next.pendingKids||[]).slice(-p.negativeCapacity);const result=(action,code)=>({action,code,cache:next});
  if(next.keys.some(key=>key.issuer===next.issuer&&key.kid===kid)&&now<next.fetchedAt+p.ttlSeconds)return result('cached','fresh-key');
  if(next.inFlight){if(now>=next.startedAt+p.timeoutSeconds){next.inFlight=false;next.pendingKids=[];return result('deny','refresh-timeout');}if(!next.pendingKids.includes(kid)){if(next.pendingKids.length>=p.negativeCapacity)return result('deny','refresh-bounded');next.pendingKids.push(kid);}return result('coalesced','refresh-in-flight');}
  if(next.negativeKids.some(entry=>entry.kid===kid))return result('deny','negative-cache');
  if(next.lastRefreshAt!==null&&next.lastRefreshAt!==undefined&&now-next.lastRefreshAt<p.minRefreshSeconds)return result('deny','refresh-rate');
  next.inFlight=true;next.startedAt=now;next.lastRefreshAt=now;next.pendingKids=[kid];return result('refresh',now>=next.fetchedAt+p.ttlSeconds?'stale-cache':'unknown-kid');
}
export function jwtCompleteRefresh({cache,keys=[],now,ok,policy}={}) {
  const p=jwtRefreshPolicy(policy),next=jwtPolicyCopy(cache);const timely=next.inFlight&&now<next.startedAt+p.timeoutSeconds;next.inFlight=false;
  if(ok&&timely){next.keys=jwtPolicyCopy(keys.filter(key=>key.issuer===next.issuer));next.fetchedAt=now;}
  const missing=(next.pendingKids||[]).filter(kid=>!ok||!timely||!next.keys.some(key=>key.kid===kid));next.negativeKids=[...(next.negativeKids||[]).filter(entry=>entry.until>now&&!missing.includes(entry.kid)),...missing.map(kid=>({kid,until:now+p.negativeTtlSeconds}))].slice(-p.negativeCapacity);next.pendingKids=[];
  return {ok:!!ok&&!!timely,code:!timely?'refresh-timeout':ok?'refreshed':'refresh-failed',cache:next};
}
export function jwtIntrospectionDecision({response,authenticated,expectedAudience,now,cachedAt,ttlSeconds=15,timeout=false}={}) {
  const fail=code=>({ok:false,stage:'introspection',code,validatedClaims:null});
  if(timeout)return fail('timeout');if(authenticated!==true)return fail('endpoint-authentication');if(!Number.isFinite(now)||!Number.isFinite(cachedAt)||now<cachedAt||now>=cachedAt+ttlSeconds)return fail('stale-response');if(response?.active!==true)return fail('inactive');
  if(!(typeof response.aud==='string'||Array.isArray(response.aud)&&response.aud.every(a=>typeof a==='string')))return fail('audience');if(!(Array.isArray(response.aud)?response.aud:[response.aud]).includes(expectedAudience))return fail('audience');if(typeof response.exp!=='number'||!Number.isFinite(response.exp)||now>=response.exp)return fail('expired');
  return {ok:true,stage:'accepted',code:'active',validatedClaims:jwtPolicyCopy(response)};
}
