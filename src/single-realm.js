import { ACTORS, ATTRIBUTES, EXAMPLE } from './protocol-data.js';

// Reuses the existing factor and application-client journeys with one realm.
// This module deliberately does not import architecture-variants (which uses it).
const singleRealmRpId='idp1.example.test';
const singleRealmOrigin='https://idp1.example.test';
const singleRealmUserHandle='opaque-user-A-bytes';
const singleRealmSubject='user-in-A-204';
const singleRealmCanonical=item=>String(item.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const singleRealmRemovedSteps=new Set(['l05','l06','l07','l15','l16','l17','l18','l19']);
const singleRealmBrokerFields=new Set(['clientIdBroker','clientSecret','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','issuerB','subjectB','authorizationHeader']);
const singleRealmText=value=>String(value)
  .replaceAll(EXAMPLE.authB,EXAMPLE.authA).replaceAll(EXAMPLE.tokenB,EXAMPLE.tokenA)
  .replaceAll(EXAMPLE.issuerB,EXAMPLE.issuerA).replaceAll(EXAMPLE.origin,singleRealmOrigin).replaceAll(EXAMPLE.rpId,singleRealmRpId)
  .replaceAll('opaque-user-B-bytes',singleRealmUserHandle).replaceAll('user-in-B-913',singleRealmSubject)
  .replaceAll('Keycloak Realm B','Keycloak Realm A').replaceAll('Realm%20B','Realm%20A')
  .replaceAll('Realm B','Realm A').replaceAll('B’s','A’s').replaceAll("B's","A's")
  .replace(/\bB\b/g,'A');
const singleRealmModeDescription={
  passkey:'a previously enrolled discoverable passkey, with local user verification required',
  password:'the configured password-only method, with no TOTP requirement in this scenario',
  'one-time-code':'an explicitly configured passwordless TOTP method: identify the account and verify its already enrolled code credential; this is one possession factor, not MFA',
  'password-totp':'the account password followed by an already enrolled TOTP code',
  'passkey-totp':'an explicitly configured passkey check followed by required TOTP; enabling passkeys alone does not create this additional requirement',
};

const singleRealmJourneyCache=new WeakMap();
export function applySingleRealm(steps,mode='passkey') {
  let modeCache=singleRealmJourneyCache.get(steps);
  if(!modeCache){modeCache=new Map();singleRealmJourneyCache.set(steps,modeCache);}
  if(modeCache.has(mode))return modeCache.get(mode);
  const result=steps.filter(item=>!singleRealmRemovedSteps.has(singleRealmCanonical(item))).map(item=>{
    const copy={...item,id:'single-'+item.id,topology:'single',upstream:'single',upstreamKind:'single-realm',relyingPartyActor:'realmA',mode,
      from:item.from==='realmB'?'realmA':item.from,to:item.to==='realmB'?'realmA':item.to,
      fields:item.fields.filter(id=>!singleRealmBrokerFields.has(id)),
      payload:item.payload.map(p=>({...p,value:typeof p.value==='string'?singleRealmText(p.value):p.value,...(p.description?{description:singleRealmText(p.description)}:{})})),
      checks:item.checks.map(singleRealmText)};
    for(const field of ['title','summary','detail'])copy[field]=singleRealmText(copy[field]);
    const canonical=singleRealmCanonical(copy),web=copy.architecture==='web'||copy.clientKind==='confidential-web';
    const client=web?'web-app':EXAMPLE.clientApp;
    switch(canonical){
      case 'l04':
        copy.title='Ask the single realm for sign-in';
        copy.summary='The browser delivers the application’s authorization request to Realm A.';
        copy.detail='Realm A uses client_id '+client+' to select the registered application configuration: client type, allowed redirect_uri, scopes and authentication policy. The client identifier is public; it is not a password. A validates the callback and S256 PKCE parameters and starts its own authentication session. This single-realm scenario uses '+singleRealmModeDescription[mode]+'. No identity broker or second OIDC client is involved.';
        copy.checks=['Registered application client_id resolves the intended client','Allowed '+(web?'HTTPS backend':'native loopback')+' redirect_uri','S256 PKCE parameters valid','Realm A’s configured authentication method selected'];
        break;
      case 'l14':
        copy.detail=copy.detail.replace(/A successful check completes authentication in A\./,'A successful check satisfies the configured passkey method in this single realm.');
        break;
      case 'p01':
        copy.detail='Realm A displays its own username/password form. '+(mode==='password-totp'?'Its configured flow also requires a previously enrolled TOTP code after password verification.':'This scenario’s configured authentication method requires only the account password.')+' The app uses Authorization Code + PKCE; the account form is not the OAuth resource-owner password grant.';
        break;
      case 'p02':
        copy.detail='The person enters their Realm A username and account password on A’s HTTPS page. Realm A verifies this password; the application does not receive it. This account credential is distinct from the application’s registered client_id or a confidential backend client secret.';
        break;
      case 'm01':
        copy.detail='Realm A keeps this sign-in pending until the required, already enrolled TOTP credential is verified. '+(mode==='one-time-code'?'This is the only authentication factor in the explicitly configured passwordless TOTP flow; a username only identifies the account.':'The code is checked after the preceding password/passkey method in this configured flow.')+' A has not yet issued the application authorization code.';
        break;
      case 'm04':
        copy.detail='The browser posts the short OTP code to Realm A’s current HTTPS login action, associated with A’s pending authentication session. A already has the account’s enrolled shared secret; it is not provisioned again during login. The application does not receive this typed code or the shared secret.';
        break;
      case 'l20':
        copy.title='Issue the single realm’s application code';
        copy.summary='After its configured authentication succeeds, A returns its code and the original application state.';
        copy.detail='Realm A uses the authenticated existing local account '+singleRealmSubject+' and establishes its SSO session. It issues a short-lived, single-use authorization code bound to the registered application client_id '+client+', its original redirect_uri and S256 PKCE commitment. A redirects the browser to that application callback with code and original state. This step neither imports an upstream identity nor issues an upstream broker code.';
        copy.fields=[...new Set([...copy.fields,'clientIdApp','subjectA','session'])];
        copy.checks=['Realm A’s required authentication checks succeeded','Existing Realm A account authenticated','Code bound to the application client, callback and PKCE challenge'];
        break;
      case 'l23':
        copy.detail=web?'The web backend authenticates to Realm A using HTTP Basic: its registered web-app client_id is encoded as the Basic username and its backend-only client secret as the password. The HTTPS form body contains grant_type, code, identical redirect_uri and code_verifier. A resolves/authenticates that registered client, checks the code belongs to it, and compares S256 of the verifier with the commitment bound to the code. The browser receives neither secret.':'The native public app posts client_id '+EXAMPLE.clientApp+', grant_type, code, the identical redirect_uri and code_verifier to A’s HTTPS token endpoint. A uses client_id to select the registered public client and checks that the code belongs to that client and callback, then validates the S256 verifier against the commitment stored for the code. The app sends no client_secret; a public client_id by itself does not authenticate it.';
        break;
      case 'l24':
        copy.detail='The same Realm A that verified the account issues and signs the ID token with issuer '+EXAMPLE.issuerA+', audience '+client+', subject '+singleRealmSubject+' and the application’s original nonce. It returns its access token and any policy-authorized refresh token directly to the '+(web?'web backend, which stores them on the server.':'native app over HTTPS.')+' No broker token or factor secret is part of this application result.';
        copy.fields=[...new Set([...copy.fields,'clientIdApp'])];
        break;
      case 'l25':
        copy.detail='The '+(web?'web backend':'native app')+' validates A’s ID-token signature using A’s trusted verification keys, exact issuer, expiry and original application nonce. The aud claim must contain its own registered client_id '+client+'. The accepted account is ('+EXAMPLE.issuerA+', '+singleRealmSubject+'). '+(web?'The backend creates an application session and sends an opaque protected cookie; OIDC tokens stay on the backend. ':'The application displays its signed-in state. ')+'The assurance of this result depends on the configured Realm A authentication method and any agreed validated acr/amr semantics.';
        copy.fields=[...new Set([...copy.fields,'clientIdApp'])];
        break;
      case 'e01':
        copy.detail='Passkey enrollment begins in a verified Realm A account/session. Keycloak’s configured WebAuthn Register Passwordless action creates a credential for this account in A. Initial account verification and recovery are outside the diagram; enrollment must already be authorized.';
        break;
      case 'e02':
        copy.detail='Realm A checks the verified account/session and permission to enroll a credential, then prepares A’s own WebAuthn policy. This setup ceremony does not issue an OAuth authorization code.';
        break;
      case 'e08':
        copy.detail='Realm A stores the credential ID, credentialPublicKey, opaque A-account user-handle association and relevant counter/credential metadata. The authenticator keeps the private key. Later authentication in this same realm verifies signatures with the stored public key; the application still receives A’s OIDC result rather than the credential private key.';
        break;
      case 't08':
        copy.detail='Realm A’s verifier and the enrolled authenticator app both hold the symmetric secret K and matching settings. Later login submits only the short OTP code to Realm A. The application receives its ordinary OIDC result and does not receive the TOTP seed or typed OTP.';
        break;
    }
    return copy;
  });
  modeCache.set(mode,result);return result;
}

const singleRealmActorCache=new Map();
export function getSingleRealmActorOverrides(architecture='native') {
  if(singleRealmActorCache.has(architecture))return singleRealmActorCache.get(architecture);
  const web=architecture==='web',a=(id,kind)=>({id,kind});
  const result={};
  for(const id of ['user','app','browser','yubikey','hello','totp'])result[id]={notes:ACTORS[id].notes.map(singleRealmText)};
  result.user.plainRole='Chooses the configured method and approves the required sign-in checks.';
  result.app.notes=web?['Registered as confidential client web-app in the single Realm A.','The backend retains PKCE protections and receives its registered HTTPS callback.','Authenticates its direct token request to A using HTTP Basic and PKCE.','Validates ID-token aud against its own client_id; keeps tokens server-side and sends an application session cookie.']:['Registered as public native client desktop-app in the single Realm A.','Starts its loopback listener and opens the system browser with its public client_id and PKCE challenge.','Uses its client_id and secret PKCE verifier on the direct token exchange; there is no embedded client_secret.','Validates the ID-token issuer and aud against Realm A and its own registered client_id.'];
  result.browser.notes=['Shows the single Realm A’s HTTPS authentication pages.','WebAuthn uses RP ID idp1.example.test and origin https://idp1.example.test.','Carries A’s application callback; there is no upstream identity-provider redirect.',web?'Receives a separate application session cookie after the backend validates A’s tokens.':'Calls the application’s loopback listener on this computer.','Cannot read the credential private key.'];
  result.realmA={...ACTORS.realmA,name:'Keycloak · Realm A',role:'OIDC provider + authentication / WebAuthn relying party',plainRole:'Checks the required sign-in method itself and issues the application’s tokens.',
    attributes:[a('issuerA','static'),a('realmSigningKey','static'),a('clientIdApp','static'),a('redirectApp','static'),a('scope','static'),a('jwksUri','static'),a('authorizationEndpoint','static'),a('tokenEndpoint','static'),a('stateApp','received'),a('nonceApp','received'),a('codeChallenge','received'),a('codeChallengeMethod','received'),a('codeVerifier','received'),a('session','generated'),a('subjectA','static'),a('codeA','generated'),a('idTokenA','generated'),a('accessTokenA','generated'),a('refreshToken','generated'),
      ...ACTORS.realmB.attributes.filter(entry=>!singleRealmBrokerFields.has(entry.id)).map(entry=>({...entry})),...(web?[a('clientSecretApp','static'),a('authorizationHeaderApp','received')]:[])].filter((entry,index,list)=>list.findIndex(other=>other.id===entry.id)===index),
    notes:['A directly verifies the configured password, TOTP or WebAuthn method for its existing local account.','Uses application client_id to select the registered client configuration and bind the authorization code to that client.','This realm’s WebAuthn RP ID is idp1.example.test; credential signatures and OIDC token signatures use distinct keys.','There is one OIDC client hop: application ↔ Realm A. No broker credentials, upstream token, or imported-account mapping is involved.']};
  singleRealmActorCache.set(architecture,result);return result;
}

const singleRealmExampleCache=new Map();
export function getSingleRealmExampleOverrides(architecture='native') {
  if(singleRealmExampleCache.has(architecture))return singleRealmExampleCache.get(architecture);
  const client=architecture==='web'?'web-app':EXAMPLE.clientApp;
  const examples={clientIdApp:client,rpId:singleRealmRpId,origin:singleRealmOrigin,rpName:'Keycloak Realm A',rpObject:'{ id: "idp1.example.test", name: "Keycloak Realm A" }',rpIdHash:'SHA256("idp1.example.test")',userId:singleRealmUserHandle,userHandle:singleRealmUserHandle,userObject:'{ id: opaque-user-A-bytes, name: "alice", displayName: "Alice" }',subjectA:singleRealmSubject,issuerA:EXAMPLE.issuerA,audience:'ID token: '+client,idTokenA:'JWT: iss='+EXAMPLE.issuerA+', aud='+client+', sub='+singleRealmSubject+', nonce='+EXAMPLE.nonceApp,jwksUri:EXAMPLE.issuerA+'/protocol/openid-connect/certs',authorizationEndpoint:EXAMPLE.authA,tokenEndpoint:EXAMPLE.tokenA,realmSigningKey:'Realm A’s private OIDC signing key; not the account’s WebAuthn credential key',session:'Realm A’s pending authentication context / SSO session',clientDataJSON:'{ type: "webauthn.get", challenge: "…", origin: "https://idp1.example.test" }'};
  singleRealmExampleCache.set(architecture,examples);return examples;
}

const singleRealmDefinitionCache=new WeakMap();
export function getSingleRealmAttributeOverrides(architecture='native',definitions=ATTRIBUTES) {
  let archCache=singleRealmDefinitionCache.get(definitions);if(!archCache){archCache=new Map();singleRealmDefinitionCache.set(definitions,archCache);}
  if(archCache.has(architecture))return archCache.get(architecture);
  const result={};
  for(const [id,base] of Object.entries(definitions)){
    if(singleRealmBrokerFields.has(id))continue;
    const updated={...base};for(const field of ['meaning','description','origin','generator','purpose','example'])if(field in updated)updated[field]=singleRealmText(updated[field]);
    result[id]=updated;
  }
  const clientId=result.clientIdApp||ATTRIBUTES.clientIdApp;
  result.clientIdApp={...clientId,meaning:'The public identifier assigned to this application’s registration in Realm A.',description:'A static client registration identifier; it is not a generated login secret.',origin:'Assigned during application client registration in Realm A, then configured in the application.',generator:'Realm A’s administrator / client registration process',purpose:'The authorization request uses it to select the registered client configuration. A binds codes to this client; code redemption resolves the same client, and the app checks ID-token aud contains this client_id. The identifier alone does not authenticate a public client.'};
  if(result.subjectA)Object.assign(result.subjectA,{origin:'Assigned to the existing local account in Realm A during account creation.',generator:'Realm A’s local user store',purpose:'Identifies the authenticated local A account together with iss. This single-realm sign-in does not import or map an upstream subject.'});
  if(result.realmSigningKey)Object.assign(result.realmSigningKey,{origin:'Provisioned and retained by this Keycloak Realm A’s key provider.',generator:'Realm A’s key provider',purpose:'Signs Realm A’s OIDC tokens; applications verify with A’s published public keys. This key is distinct from any account’s WebAuthn credential key.'});
  if(result.idTokenA)Object.assign(result.idTokenA,{meaning:'Realm A’s signed identity statement for the application whose account it directly authenticated.',description:'An OIDC ID token from the single realm, issued to the application client.'});
  if(result.clientSecretApp)result.clientSecretApp.meaning='The confidential credential registered for the web application in Realm A and retained on its backend.';
  if(result.tokenEndpoint)result.tokenEndpoint.purpose='The application directly redeems Realm A’s application code at this realm’s HTTPS token endpoint.';
  if(result.session)Object.assign(result.session,{meaning:'The single Keycloak realm’s pending sign-in context and eventual SSO session; cookie details are implementation-specific.',description:'Realm A’s own authentication / SSO context; distinct from a web application’s session cookie.',origin:'Created and managed by Realm A during its own authentication flow.',generator:'Realm A'});
  for(const [id,example]of Object.entries(getSingleRealmExampleOverrides(architecture)))result[id]={...(result[id]||definitions[id]||ATTRIBUTES[id]),example};
  archCache.set(architecture,result);return result;
}
