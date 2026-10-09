import { ATTRIBUTES } from './protocol-data.js';
import { getStepAttributeOperations } from './attribute-usage.js';

// Educational nested JWT adapter. It performs no live cryptography and never
// changes access-token protection, OAuth client authentication or SAML messages.
const jweRfc = 'https://www.rfc-editor.org/rfc/rfc7516';
const jweAlgorithmsRfc = 'https://www.rfc-editor.org/rfc/rfc7518';
const jweJwtRfc = 'https://www.rfc-editor.org/rfc/rfc7519';
const jweKeycloak = 'https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc_clients';
const jweBrokerDocs = 'https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc_identity_providers';
const jweDefinition = (name,meaning,origin,purpose,example,standard,source=jweRfc) => ({name,meaning,description:meaning,origin,generator:origin,purpose,example,standard,source});

export const JWE_SOURCES = [
  {name:'JSON Web Encryption',standard:'RFC 7516',url:jweRfc,note:'Authenticated encryption, protected headers and the five-part Compact Serialization.'},
  {name:'JSON Web Algorithms',standard:'RFC 7518',url:jweAlgorithmsRfc,note:'Illustrative RSA-OAEP-256 key management and A256GCM content encryption.'},
  {name:'JSON Web Token',standard:'RFC 7519',url:jweJwtRfc,note:'Nested JWTs: sign the identity token, then encrypt that signed result.'},
  {name:'OIDC encrypted ID tokens',standard:'OpenID Connect Core §2 / §10.2',url:'https://openid.net/specs/openid-connect-core-1_0.html',note:'Signed-then-encrypted nested ID tokens and recipient encryption key configuration.'},
  {name:'Keycloak signed and encrypted ID tokens',standard:'Keycloak Server Administration Guide',url:jweKeycloak,note:'OIDC client encryption configuration, fresh content-encryption keys and recipient RSA public keys.'},
  {name:'Keycloak broker JWE decryption',standard:'Keycloak OIDC identity providers',url:jweBrokerDocs,note:'The upstream provider encrypts to the broker realm’s public ENC-use key; Realm A keeps the matching realm encryption private key.'},
];

const jweHops = {
  app:{suffix:'App',issuer:'realmA',recipient:'app',canonical:'l24',token:'idTokenA',label:'application',claims:['issuerA','audience','subjectA','nonceApp','exp','iat'],issuerName:'Realm A',recipientName:'the application',kid:'app-enc-2026'},
  broker:{suffix:'Broker',issuer:'realmB',recipient:'realmA',canonical:'l18',token:'idTokenB',label:'broker',claims:['issuerB','audience','subjectB','nonceBroker','exp','iat'],issuerName:'the upstream OIDC provider',recipientName:'Realm A’s OIDC broker',kid:'broker-enc-2026'},
};
const jweId = (name,hop) => 'jwe'+name+jweHops[hop].suffix;
export const JWE_ATTRIBUTES = {};
for(const [hop,h] of Object.entries(jweHops)) {
  const context=' ('+h.label+' ID token)';
  const issuance=h.issuerName+' for '+h.recipientName;
  const publicKeyOrigin=hop==='broker'?'Realm A provisions separate ENC-use realm keys, publishes their public JWKs at its realm JWKS endpoint and configures that public key or JWKS for its upstream broker-client registration.':h.recipientName+' provisions its encryption key pair and registers its public JWK or trusted JWKS with the issuer before login.';
  const privateKeyOrigin=hop==='broker'?'Realm A retains its protected ENC-use realm private key, separate from its realm SIGN-use key and confidential broker client secret.':'The application provisions and retains its protected encryption private key locally; the issuer never receives it.';
  const defs={
    RecipientPublicKey:jweDefinition('public JWK · use: enc'+context,'The recipient’s registered RSA public encryption key, distinct from an issuer’s JWT signing key and any WebAuthn credential key.',publicKeyOrigin,'Lets '+h.issuerName+' encrypt this token’s fresh CEK for the intended recipient. A public encryption key is not a client secret and does not change a public client into a confidential client.','RSA public JWK: kty=RSA, use=enc, kid='+h.kid,'RFC 7517 §4 / RFC 7516 §5.1','https://www.rfc-editor.org/rfc/rfc7517'),
    RecipientPrivateKey:jweDefinition('private RSA decryption key'+context,'The recipient’s protected private counterpart to its registered public encryption key.',privateKeyOrigin,'Decrypts the RSA-OAEP-256 encrypted_key to recover the CEK. It is unrelated to account authentication, issuer signature creation or PKCE.','Protected recipient private RSA key; never transmitted','RFC 7516 §5.2 / RFC 7518 §4.3'),
    SigningPublicKey:jweDefinition('issuer JWS verification key'+context,'The trusted public key used to verify the signed inner ID token after decryption.',h.issuerName+' publishes its signing public key through trusted issuer metadata/JWKS.','Checks the inner JWS signature. Successful outer decryption alone does not establish the identity token’s issuer.','Trusted issuer signing public JWK, separate from recipient encryption keys','RFC 7519 §11.2 / OIDC Core §3.1.3.7',jweJwtRfc),
    InnerJws:jweDefinition('JWS · inner signed JWT'+context,'The signed ID token encrypted as the plaintext of the outer JWE.',issuance+' creates claims and signs the JWT before encryption. The recipient recovers it only after authenticated decryption.','Retains the issuer’s independently verifiable signature. The wire carries its encrypted representation rather than visible identity claims.','header.payload.signature (schematic signed JWT; local plaintext)','RFC 7519 §11.2',jweJwtRfc),
    Cek:jweDefinition('CEK'+context,'The secret Content Encryption Key used for this token’s content encryption.',h.issuerName+' generates a fresh cryptographically random 256-bit CEK for every A256GCM ID token. The recipient recovers the same key by unwrapping encrypted_key.','Encrypts and authenticates the inner signed JWT. The plaintext CEK remains local on each endpoint; only encrypted_key crosses the connection.','Fresh 32-byte secret; absent from HTTP token-response fields','RFC 7516 §5.1 / RFC 7518 §5.3'),
    Iv:jweDefinition('iv'+context,'The initialization vector for authenticated content encryption.',h.issuerName+' generates a fresh 96-bit IV for this A256GCM encryption, with the required uniqueness under its CEK.','Used by AES-GCM on encryption and decryption. The IV is public and is base64url-encoded as the third compact part.','12-byte IV → base64url(iv)','RFC 7516 §3.1 / RFC 7518 §5.3'),
    Alg:jweDefinition('alg'+context,'The protected-header algorithm identifying how the CEK is encrypted.',issuance+' selects the preconfigured allowed key-management algorithm.','RSA-OAEP-256 encrypts the fresh CEK with the recipient’s RSA public key. The recipient checks its allowlist before attempting decryption; it does not trust arbitrary alg values.','RSA-OAEP-256 (illustrative configured policy)','RFC 7516 §4.1.1 / RFC 7518 §4.3',jweAlgorithmsRfc),
    Enc:jweDefinition('enc'+context,'The protected-header algorithm identifying authenticated content encryption.',issuance+' selects its preconfigured allowed content-encryption algorithm.','A256GCM encrypts the signed JWT and produces its authentication tag using the CEK, IV and protected-header AAD.','A256GCM (illustrative configured policy)','RFC 7516 §4.1.2 / RFC 7518 §5.3',jweAlgorithmsRfc),
    Kid:jweDefinition('kid'+context,'A key identifier hint for selecting the recipient’s decryption key.',h.recipientName+' assigns a key identifier during key provisioning; the issuer copies it into the protected header.','Selects an already trusted recipient key. It is not authority to fetch or trust an attacker-chosen key or URL.',h.kid,'RFC 7516 §4.1.6'),
    Cty:jweDefinition('cty'+context,'The protected-header content type identifying a nested JWT.',h.issuerName+' sets cty=JWT because this JWE contains a signed JWT.','Tells the recipient that after successful decryption it must process and verify a nested JWT, rather than treating the plaintext as validated identity.','JWT','RFC 7516 §4.1.12 / RFC 7519 §5.2',jweJwtRfc),
    ProtectedHeader:jweDefinition('JWE Protected Header'+context,'The public algorithm/key/type metadata protected by the JWE authentication tag.',h.issuerName+' creates {alg, enc, kid, cty}, UTF-8 encodes it and base64url-encodes it.','Its encoded bytes are ASCII additional authenticated data (AAD) for compact JWE. The header is authenticated, not encrypted.','{ alg: "RSA-OAEP-256", enc: "A256GCM", kid: "'+h.kid+'", cty: "JWT" }','RFC 7516 §3.1 / §5.1'),
    EncryptedKey:jweDefinition('encrypted_key'+context,'The RSA-encrypted Content Encryption Key; the second compact JWE part.',h.issuerName+' applies RSA-OAEP-256 to the fresh CEK using the registered recipient public key.','Lets only the recipient holding the matching private key recover the content-encryption secret. This is encrypted key material, not a plaintext CEK.','base64url(RSA-OAEP-256(recipientPublicKey, CEK))','RFC 7516 §3.1 / RFC 7518 §4.3'),
    Ciphertext:jweDefinition('ciphertext'+context,'The AES-GCM encrypted signed JWT; the fourth compact JWE part.',h.issuerName+' encrypts the inner JWS using the fresh CEK, IV and protected-header AAD.','Hides the signed ID-token contents and claims from intermediaries. It does not encrypt the separate access_token or refresh_token response fields.','base64url(A256GCM ciphertext of inner signed ID token)','RFC 7516 §3.1 / §5.1'),
    Tag:jweDefinition('tag'+context,'The authentication tag for the encrypted content and protected header; the fifth compact JWE part.',h.issuerName+' produces a 128-bit tag during the A256GCM encryption.','The recipient authenticates the tag before releasing or interpreting plaintext. A failure rejects the encrypted token. This tag is distinct from the inner JWS signature.','16-byte AES-GCM authentication tag → base64url(tag)','RFC 7516 §3.1 / RFC 7518 §5.3'),
    Compact:jweDefinition('JWE Compact Serialization'+context,'The five-part string carried in the token response’s id_token field.',h.issuerName+' joins the base64url-encoded protected header, encrypted key, IV, ciphertext and tag with four periods.','Transports the signed-and-encrypted ID token over HTTPS. Its encrypted contents must be decrypted, inner-signature checked and claim validated before accepting identity.','protected.encrypted_key.iv.ciphertext.tag (five schematic parts)','RFC 7516 §3.1'),
  };
  for(const [name,def] of Object.entries(defs)) JWE_ATTRIBUTES[jweId(name,hop)]=def;
}
export const JWE_TOPIC_IDS = Object.keys(JWE_ATTRIBUTES);

const jweCanonical=step=>String(step.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const jwePolicy=protection=>['app-jwe','broker-jwe','both-jwe'].includes(protection)?protection:'signed';
const jweEnabled=(policy,hop)=>policy==='both-jwe'||policy===hop+'-jwe';
const jweRealHop=(step,hop)=> {
  const h=jweHops[hop];
  return !step.directFido && !step.samlHop && !step.jweHop && jweCanonical(step)===h.canonical && step.from===h.issuer && step.to===h.recipient && step.payload?.some(p=>p.name==='id_token');
};
const jweActions=(ids,kind,actorId,detail,extra={})=>ids.map(attributeId=>({attributeId,kind,actorId,detail,...extra}));
const jweTransfer=(ids,from,to,detail,carriedAs)=>[
  ...jweActions(ids,'send',from,detail,{carriedAs}),...jweActions(ids,'receive',to,detail,{carriedAs}),
];
const jwePayload=(name,value,description)=>({name,value,...(description?{description}:{})});
// Pure ASCII base64url avoids runtime dependencies in the offline bundle.
const jweAscii64=text=> {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';let result='';
  for(let i=0;i<text.length;i+=3){const a=text.charCodeAt(i),hasB=i+1<text.length,hasC=i+2<text.length,b=hasB?text.charCodeAt(i+1):0,c=hasC?text.charCodeAt(i+2):0;result+=alphabet[a>>2]+alphabet[((a&3)<<4)|(b>>4)]+(hasB?alphabet[((b&15)<<2)|(c>>6)]:'')+(hasC?alphabet[c&63]:'');}
  return result;
};
const jweCompactExample=hop=>jweAscii64(JSON.stringify({alg:'RSA-OAEP-256',enc:'A256GCM',kid:jweHops[hop].kid,cty:'JWT'}))+'.'+['encrypted_key','iv','ciphertext','tag'].map(part=>jweAscii64('schematic_'+hop+'_'+part)).join('.');

function jweExpand(base,hop,authenticator) {
  const h={...jweHops[hop],claims:base.idTokenClaimIds||jweHops[hop].claims},id=name=>jweId(name,hop),original=getStepAttributeOperations(base,authenticator);
  const hasNonce=h.claims.some(attribute=>['nonceApp','nonceBroker'].includes(attribute)),advancedGrant=!!base.oidcGrant&&base.oidcGrant!=='authorization_code';
  const plaintextNames=new Set(['iss','aud','sub','nonce','exp','iat','acr','amr',...h.claims.flatMap(attribute=>(ATTRIBUTES[attribute]?.name||attribute).replace(/\s*\([^)]*\)/g,'').split(' / ').map(name=>name.trim()))]);
  const localOriginal=original.filter(action=>!['send','receive'].includes(action.kind)&&action.attributeId!==h.token);
  const plaintextClaims=new Set([...h.claims,'acr','amr']);
  const otherWire=original.filter(action=>['send','receive'].includes(action.kind)&&action.attributeId!==h.token&&!plaintextClaims.has(action.attributeId));
  const local=(stage,title,actor,summary,detail,operations,payload,checks=[])=>({...base,id:base.id+'-jwe-'+hop+'-'+stage,from:actor,to:actor,channel:'internal',phase:'tokens',title,summary,detail,fields:[...new Set(operations.map(a=>a.attributeId))],payload,checks,attributeOperations:operations,jweHop:hop,jweStage:stage});
  const header={alg:'RSA-OAEP-256',enc:'A256GCM',kid:h.kid,cty:'JWT'};
  const prefix=base.upstreamKind==='external-oidc'?'The independently configured upstream provider':'The issuer';
  const signed=local('sign','Sign the inner ID token · '+h.label,h.issuer,
    'The issuer builds its identity claims and signs the ID token before encryption.',
    (advancedGrant?'After validating the '+base.oidcGrant+' transaction, applicable client authentication and required user approval, ':'After validating the authorization code and applicable client/PKCE checks, ')+h.issuerName+' builds the normal ID-token claims and signs them with its own private issuer signing key. The resulting JWS is local plaintext for the outer encryption. It is distinct from a passkey signature and the recipient’s RSA encryption key.',
    [...localOriginal,...jweActions([id('InnerJws')],'create',h.issuer,'Creates the signed inner JWT locally, before encrypting it.')],
    [jwePayload('JWS · inner signed JWT','header.payload.signature (schematic, local only)'),...base.payload.filter(p=>plaintextNames.has(p.name)),jwePayload('Issuer signing key','Issuer private signing key; never transmitted')],
    [advancedGrant?'Grant, client and user-approval checks already succeeded':'Code and required client/PKCE checks already succeeded','Issuer signs before encrypting']);
  const prepare=local('prepare','Create the content-encryption material · '+h.label,h.issuer,
    'A fresh secret and IV protect this one ID token; the header states the configured algorithms.',
    prefix+' must support the configured JWE policy and trust the intended recipient’s previously registered encryption key. This example allowlists RSA-OAEP-256 and A256GCM; algorithms are illustrative policy choices. The issuer generates a fresh 256-bit CEK and 96-bit IV and creates the protected header. In compact JWE, ASCII(BASE64URL(UTF8(protected header))) is the GCM additional authenticated data. Encryption is separate from TLS, client authentication, PKCE and issuer signing.',
    [...jweActions([id('RecipientPublicKey')],'use',h.issuer,'Uses the recipient public encryption key registered before sign-in; the private key is not shared.'),...jweActions([id('Alg'),id('Enc'),id('Kid'),id('Cty')],'use',h.issuer,'Selects the configured allowed algorithms and recipient key identifier; cty=JWT denotes a nested signed JWT.'),...jweActions([id('Cek'),id('Iv')],'create',h.issuer,'Generates fresh cryptographic content-encryption material locally for this token.'),...jweActions([id('ProtectedHeader')],'create',h.issuer,'Creates the protected header and its encoded AAD for authenticated encryption.')],
    [jwePayload('CEK','Fresh 32-byte secret; local only'),jwePayload('iv','Fresh 12-byte IV'),jwePayload('JWE Protected Header',JSON.stringify(header))],['Recipient public encryption key trusted','Configured algorithms allowlisted','Fresh CEK and valid IV']);
  const encrypt=local('encrypt','Encrypt the signed ID token · '+h.label,h.issuer,
    'AES-GCM hides the signed JWT and creates an authentication tag.',
    'A256GCM encrypts the exact inner-JWS bytes using the CEK and IV, authenticating the encoded protected header as AAD. It produces ciphertext and a 128-bit tag. The inner issuer signature remains inside the encrypted content. The CEK and unencrypted claims stay local; this demonstration does not perform live cryptography.',
    [...jweActions([id('InnerJws'),id('Cek'),id('Iv'),id('ProtectedHeader'),id('Enc')],'use',h.issuer,'Uses the inner signed JWT, CEK, IV and protected-header AAD for A256GCM.'),...jweActions([id('Ciphertext'),id('Tag')],'derive',h.issuer,'Computes ciphertext and its GCM authentication tag without transmitting plaintext.')],
    [jwePayload('ciphertext','A256GCM-encrypted inner JWS bytes'),jwePayload('tag','16-byte GCM authentication tag')]);
  const wrap=local('wrap','Encrypt the CEK and assemble five parts · '+h.label,h.issuer,
    'The recipient’s public RSA key protects the CEK; five encoded parts form the outer JWE.',
    'RSA-OAEP-256 encrypts the CEK with the recipient’s registered RSA public key. The issuer then constructs BASE64URL(protected header).BASE64URL(encrypted key).BASE64URL(IV).BASE64URL(ciphertext).BASE64URL(tag). The public protected header is authenticated, not encrypted. The plaintext CEK is not a compact part. Only the designated recipient’s protected private key can unwrap this encrypted key.',
    [...jweActions([id('Cek'),id('RecipientPublicKey'),id('Alg')],'use',h.issuer,'Uses the public RSA encryption key and configured RSA-OAEP-256 to wrap the fresh CEK.'),...jweActions([id('EncryptedKey')],'derive',h.issuer,'Encrypts the CEK under the recipient public key; this encrypted value can be transmitted.'),...jweActions([id('ProtectedHeader'),id('EncryptedKey'),id('Iv'),id('Ciphertext'),id('Tag')],'use',h.issuer,'Encodes the five compact JWE parts in their specified order.'),...jweActions([id('Compact'),h.token],'derive',h.issuer,'Replaces id_token’s wire representation with the nested signed-and-encrypted compact JWE.')],
    [jwePayload('encrypted_key','RSA-OAEP-256(recipientPublicKey, CEK)'),{...jwePayload('JWE Compact Serialization',jweCompactExample(hop),'Schematic value; not a usable cryptographic token.'),attributeId:h.token}]);
  // The local derive operation produces the same compact value as the next
  // wire step. Bind both names to this occurrence, independently of glossary
  // or provider examples; recovered inner-JWS stages keep their local values.
  wrap.attributeValues={...wrap.attributeValues,[h.token]:jweCompactExample(hop),[id('Compact')]:jweCompactExample(hop)};
  const wireIds=[id('Compact'),id('ProtectedHeader'),id('Alg'),id('Enc'),id('Kid'),id('Cty'),id('EncryptedKey'),id('Iv'),id('Ciphertext'),id('Tag')];
  const wire={...base,jweHop:hop,jweStage:'wire',title:'Return the signed-and-encrypted ID token · '+h.label,
    summary:'The HTTPS token response carries id_token as a five-part JWE; other token fields retain their usual form.',
    detail:'The issuer sends the encrypted ID token directly to its OIDC client over HTTPS. Its top-level id_token value is a nested JWE containing the signed JWT. Protected header metadata, encrypted_key, IV, ciphertext and tag are carried inside that compact value. iss, sub, aud, nonce and the CEK are not visible plaintext packets. Other response fields, including access_token and any refresh_token, are not encrypted by this setting. Their independent protection and policies are unchanged.',
    fields:[...new Set([...base.fields.filter(field=>!plaintextClaims.has(field)&&field!=='realmSigningKey'),...wireIds])],
    payload:base.payload.filter(p=>!plaintextNames.has(p.name)).map(p=>p.name==='id_token'?{...p,value:jweCompactExample(hop),description:'JWE Compact Serialization: five schematic parts; no usable cryptographic token.'}:{...p}),
    attributeValues:{...base.attributeValues,[id('Compact')]:wrap.attributeValues[id('Compact')]},
    checks:['Encrypted ID token delivered to its registered recipient','TLS still protects the token response'],
    attributeOperations:[...jweTransfer([h.token],h.issuer,h.recipient,'Top-level id_token contains the signed-and-encrypted JWE, with no plaintext ID-token claim fields.','HTTPS token response id_token'),...jweTransfer(wireIds,h.issuer,h.recipient,'Encoded component inside the compact JWE; not a separate HTTP response field.','id_token → JWE Compact Serialization'),...otherWire]};
  const unwrap=local('unwrap','Check JWE policy and recover the CEK · '+h.label,h.recipient,
    'The recipient checks the allowed algorithms, selects its own key and decrypts encrypted_key.',
    'The recipient parses exactly five compact parts, checks supported protected-header algorithms and cty=JWT, and selects an already trusted local private key using kid as a hint. It applies RSA-OAEP-256 with that protected private key to recover the CEK. The private key and recovered CEK stay local. These operations provide recipient confidentiality; they do not by themselves authenticate the claimed issuer or replace the original OAuth client authentication.',
    [...jweActions([id('Compact'),id('ProtectedHeader'),id('Alg'),id('Enc'),id('Kid'),id('Cty')],'verify',h.recipient,'Checks compact structure and configured JWE algorithm/type allowlists; key hints do not establish trust.'),...jweActions([id('RecipientPrivateKey'),id('EncryptedKey'),id('Alg')],'use',h.recipient,'Uses the protected recipient private RSA key locally to unwrap encrypted_key.'),...jweActions([id('Cek')],'derive',h.recipient,'Recovers the same secret CEK locally by RSA-OAEP-256 decryption.')],
    [jwePayload('Allowed alg / enc','RSA-OAEP-256 / A256GCM'),jwePayload('kid',h.kid),jwePayload('Recovered CEK','Local 32-byte secret; not sent anywhere')],['Five parts parse correctly','alg / enc / cty match configured policy','Trusted local recipient key selected','Encrypted CEK unwrap succeeds']);
  unwrap.attributeValues={...unwrap.attributeValues,[id('Compact')]:wire.attributeValues[id('Compact')]};
  const decrypt=local('decrypt','Authenticate and decrypt the content · '+h.label,h.recipient,
    'The recipient validates the GCM tag before accepting decrypted bytes.',
    'The recipient performs A256GCM authenticated decryption using the recovered CEK, IV, ciphertext, tag and original encoded protected-header AAD. A bad tag or malformed content rejects the token. Only successful authenticated decryption releases the original signed JWT for further verification. A valid outer JWE alone is not a valid identity statement.',
    [...jweActions([id('Cek'),id('Iv'),id('Ciphertext'),id('ProtectedHeader'),id('Enc')],'use',h.recipient,'Uses the recovered CEK and original protected-header AAD for authenticated decryption.'),...jweActions([id('Tag')],'verify',h.recipient,'Authenticates the GCM tag; reject on failure before trusting or interpreting plaintext.'),...jweActions([id('InnerJws')],'derive',h.recipient,'Recovers the signed inner JWT locally only after authenticated decryption succeeds.')],
    [jwePayload('tag check','Authenticate ciphertext and protected-header AAD'),jwePayload('JWS · inner signed JWT','Recovered local signed JWT; still requires issuer verification')],['GCM tag valid','Authenticated plaintext released locally']);
  const verify=local('verify-inner','Verify the issuer’s inner JWS · '+h.label,h.recipient,
    'The recipient checks the issuer’s signature using a separate trusted signing public key.',
    'After decryption, verify the signed inner JWT with the expected issuer’s trusted signing public key and allowed signing algorithm. This signing key is different from the recipient’s decryption key and a WebAuthn credential. Decryption and a valid GCM tag cannot replace the issuer signature. Claims are still checked against the original OIDC request before identity is accepted.',
    [...jweActions([id('SigningPublicKey')],'use',h.recipient,'Uses the expected issuer’s trusted signing public key, distinct from encryption and WebAuthn keys.'),...jweActions([id('InnerJws')],'verify',h.recipient,'Verifies the inner JWS signature and allowed signing algorithm after successful JWE decryption.'),...jweActions([h.token],'derive',h.recipient,'Makes the verified decrypted ID-token representation available for the ordinary OIDC validation stage.')],
    [jwePayload('Inner JWS signature check','Expected issuer signing public key verifies signed bytes'),jwePayload('id_token','Recovered inner JWS: header.payload.signature (schematic, local only)','Local decrypted ID-token representation; never forwarded to the browser.')],['Issuer signing key trusted','Inner signature and permitted signing algorithm valid']);
  const claims=local('validate-claims','Validate the decrypted identity claims · '+h.label,h.recipient,
    'Issuer, audience and lifetime'+(hasNonce?' and the original nonce':'')+' must match the completed OIDC request.',
    'The recipient extracts claims locally from the authenticated, signature-verified inner JWT, then checks the expected issuer, intended audience and expiry'+(hasNonce?' and original nonce':'')+' under the grant’s OIDC validation policy. No nonce check is invented for a grant that did not request one. Claims were encrypted in transit and are now local values. The following ordinary validation stage retains the grant’s transaction and authentication-context checks; identity acceptance waits for all required checks.',
    [...jweActions(h.claims,'derive',h.recipient,'Extracts the actual identity claims locally from the decrypted, signature-verified inner ID token.'),...jweActions(h.claims.filter(attribute=>!['subjectA','subjectB','iat'].includes(attribute)),'verify',h.recipient,'Checks exact expected issuer, registered client audience and lifetime'+(hasNonce?' and original pending-request nonce.':'; applies the completed grant’s validation policy.'))],
    [jwePayload('Local claim checks','Expected iss + registered aud + unexpired exp'+(hasNonce?' + original nonce':''))],['Exact issuer matches','Audience includes this OIDC client','Token lifetime valid',...(hasNonce?['Original nonce matches']:[])]);
  verify.attributeValues={[h.token]:'Recovered inner JWS: header.payload.signature (schematic, local only)'};
  return [signed,prepare,encrypt,wrap,wire,unwrap,decrypt,verify,claims];
}

const jweAdapterCache=new WeakMap();
export function applyJweProtection(steps,{protection='signed',authenticator='hello'}={}) {
  const policy=jwePolicy(protection);if(policy==='signed')return steps;
  let cache=jweAdapterCache.get(steps);if(!cache){cache=new Map();jweAdapterCache.set(steps,cache);}
  const key=policy+':'+authenticator;if(cache.has(key))return cache.get(key);
  let changed=false;const result=[],protectedHops=new Set();
  for(const step of steps){
    const hop=Object.keys(jweHops).find(name=>jweEnabled(policy,name)&&jweRealHop(step,name));
    if(hop){result.push(...jweExpand(step,hop,authenticator));protectedHops.add(hop);changed=true;}
    else {
      const validationHop=jweCanonical(step)==='l19'?'broker':jweCanonical(step)==='l25'?'app':null;
      if(validationHop&&protectedHops.has(validationHop))result.push({...step,jweInboundHop:validationHop,attributeValues:{...step.attributeValues,[jweHops[validationHop].token]:'Recovered inner JWS: header.payload.signature (schematic, local only)'}});
      else result.push(step);
    }
  }
  const value=changed?result:steps;cache.set(key,value);return value;
}

const jweActiveHops=config=> {
  const policy=jwePolicy(config?.protection);return Object.keys(jweHops).filter(hop=>jweEnabled(policy,hop)&&(config?.steps||[]).some(step=>step.jweHop===hop||jweRealHop(step,hop)));
};
export function getJweActorOverrides(config={}) {
  const result={};
  const append=(actor,ids,kind,note)=>{result[actor]||={attributes:[],notes:[]};for(const id of ids)if(!result[actor].attributes.some(entry=>entry.id===id))result[actor].attributes.push({id,kind});if(note)result[actor].notes.push(note);};
  for(const hop of jweActiveHops(config)) {
    const h=jweHops[hop],id=name=>jweId(name,hop);
    append(h.issuer,[id('RecipientPublicKey')],'static','Uses only the recipient’s registered RSA public encryption key; retains its separate private issuer signing key.');
    append(h.issuer,['Alg','Enc','Kid','Cty'].map(id),'static');
    append(h.issuer,['InnerJws','Cek','Iv','ProtectedHeader','EncryptedKey','Ciphertext','Tag','Compact'].map(id),'generated','Generates a fresh CEK/IV, signs the ID token and then encrypts it. The plaintext CEK and claims are not transmitted.');
    append(h.recipient,[id('RecipientPrivateKey'),id('RecipientPublicKey'),id('SigningPublicKey')],'static','Retains its protected private decryption key and trusts the issuer’s distinct signing public key. Encryption credentials do not change its OAuth client type.');
    append(h.recipient,['Compact','ProtectedHeader','Alg','Enc','Kid','Cty','EncryptedKey','Iv','Ciphertext','Tag'].map(id),'received');
    append(h.recipient,[id('Cek'),id('InnerJws')],'generated','Recovers the CEK and signed JWT locally, checks the GCM tag, issuer signature and OIDC claims before accepting identity.');
  }
  return result;
}

export function getJweAttributeOverrides(config={}) {
  const result={};
  for(const hop of jweActiveHops(config)) {
    const h=jweHops[hop];result[h.token]={...ATTRIBUTES[h.token],name:'id_token · nested JWE ('+h.label+' hop)',meaning:'The signed ID token encrypted for '+h.recipientName+' and returned as a five-part compact JWE.',description:'A nested signed-and-encrypted ID token; its claims are plaintext only at the issuer and authorized recipient.',origin:h.issuerName+' signs its identity JWT, then encrypts it using the registered recipient encryption public key and a fresh CEK.',generator:h.issuerName,purpose:'The recipient decrypts with its protected private RSA key, authenticates the GCM tag, verifies the inner issuer signature and checks OIDC claims. Separate access and refresh tokens are unchanged.',example:jweCompactExample(hop),standard:'RFC 7516 §3.1 / RFC 7519 §11.2',source:jweRfc};
  }
  return result;
}
