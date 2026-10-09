import { ACTORS, ATTRIBUTES, EXAMPLE, FLOWS } from './protocol-data.js';
import { VARIANT_ATTRIBUTES } from './architecture-variants.js';
import { FIDO_ATTRIBUTES } from './attribute-usage.js';

// Direct FIDO2 authentication: the web application itself is the WebAuthn RP.
// This simulation contains no OAuth/OIDC exchange and never calls a device.
export const FIDO_JOURNEYS = {
  'fido-login': { title:'Direct FIDO2 · security-key sign-in',description:'The web application creates the challenge and verifies your security key’s proof itself. The browser connects to a YubiKey over CTAP2, or to Windows Hello through its platform interface.',passkey:true,requiresWeb:true,directFido:true,enrollment:false },
  'fido-enrollment': { title:'Direct FIDO2 · register a key',description:'Start with a verified application account. Register a credential for app.example.test; the application stores the public key and the authenticator keeps the private key.',passkey:true,requiresWeb:true,directFido:true,enrollment:true },
};

const directFidoOrigin = 'https://app.example.test';
const directFidoRpId = 'app.example.test';
const directFidoRpName = 'Example web application';
const directFidoUserHandle = 'opaque-app-user-bytes';
const directFidoWebAuthn = 'https://www.w3.org/TR/webauthn-3/';

const directFidoPayload = (name,value,description) => ({name,value,...(description?{description}:{})});
const directFidoStep = (id,title,from,to,phase,channel,summary,detail,fields,payload,checks=[]) => ({id,title,from,to,phase,channel,summary,detail,fields,payload,checks});
const directFidoText = value => String(value)
  .replaceAll(EXAMPLE.origin,directFidoOrigin).replaceAll(EXAMPLE.rpId,directFidoRpId)
  .replaceAll('Keycloak Realm B',directFidoRpName).replaceAll('opaque-user-B-bytes',directFidoUserHandle)
  .replaceAll('user-in-B-913','app-user-913').replaceAll('Realm B’s','the web application’s')
  .replaceAll('Realm B','the web application').replaceAll('B’s','the application’s')
  .replaceAll("B's",'the application’s').replace(/\bB\b/g,'the application');
const directFidoClone = item => ({...item,id:'fido-'+item.id,
  from:item.from==='realmB'?'app':item.from,to:item.to==='realmB'?'app':item.to,
  title:directFidoText(item.title),summary:directFidoText(item.summary),detail:directFidoText(item.detail),
  fields:[...item.fields],payload:item.payload.map(p=>({...p,value:directFidoText(p.value),...(p.description?{description:directFidoText(p.description)}:{})})),checks:item.checks.map(directFidoText)});

function directFidoLogin(authenticator) {
  const roaming = authenticator==='yubikey';
  const proof = FLOWS.login.slice(7,14).map(directFidoClone);
  proof[0].summary='The application backend sends its fresh WebAuthn sign-in options.';
  proof[0].detail='The application is the relying party. Its backend generates unpredictable challenge bytes, stores them in a short-lived pending authentication context, and returns the options over HTTPS. Its page turns encoded bytes into the ArrayBuffers expected by navigator.credentials.get({publicKey: options}). This discoverable-credential example uses allowCredentials: [] and requires local user verification. The credential must already be enrolled for app.example.test.';
  proof[1].title=roaming?'Ask the YubiKey through CTAP2':'Ask Windows Hello through the platform';
  proof[1].channel=roaming?'ctap2':'webauthn';
  proof[1].summary=roaming?'The browser/platform sends a CTAP2 GetAssertion request to the key.':'The browser/platform asks the local Windows Hello authenticator for an assertion.';
  proof[1].detail='The application page calls navigator.credentials.get(). The browser checks the secure origin and RP ID scope, constructs clientDataJSON with type webauthn.get, challenge, origin https://app.example.test and embedding context, then hashes the exact bytes. '+(roaming?'The browser/platform communicates with a FIDO2-capable YubiKey using CTAP2 over a supported local transport such as USB or NFC. GetAssertion conveys the RP ID and clientDataHash, with the relevant options and PIN/UV authorization. CTAP2 is this local client-to-key protocol, not a server HTTP protocol.':'The browser/platform invokes Windows Hello using its supported local platform authenticator interface. The web application uses the same WebAuthn API; this diagram does not label the platform operation as a USB/NFC CTAP2 exchange.');
  proof[1].payload.push(directFidoPayload('Local authenticator interface',roaming?'CTAP2 authenticatorGetAssertion · USB/NFC':'Platform authenticator operation', 'Transport and host support must match the selected authenticator. The application calls WebAuthn, while the client platform manages the local interface.'));
  proof[2].summary=roaming?'The person authorizes the YubiKey with its PIN and a touch.':'The person approves using a supported Hello PIN or biometric gesture.';
  proof[2].detail=roaming?'The system’s authenticator UI requests the security key PIN and a touch. CTAP2 PIN/UV protocols protect local PIN-related exchanges; this schematic does not send a plaintext PIN over USB or to the website. The PIN unlocks local verification and the touch establishes presence. The web application receives signed UP/UV flags, never the PIN.':'Windows Hello performs its supported local PIN or biometric verification and confirms presence. PINs and biometric samples do not travel to the web application. The server receives the signed verification flags and assertion, not the local unlock material.';
  proof[3].detail='The selected authenticator uses the existing credential scoped to app.example.test. It constructs authenticatorData with SHA256 of that RP ID, signed flags and its supported counter/metadata, then signs authenticatorData || SHA256(clientDataJSON bytes). The existing credential private key remains protected inside the authenticator/provider; sign-in does not create a replacement key.';
  proof[4].channel=roaming?'ctap2':'webauthn';
  proof[4].detail=(roaming?'The YubiKey returns its CTAP2 assertion response to the browser/platform. ':'Windows Hello returns the assertion through the local platform interface. ')+'The client obtains the credential identifier, authenticatorData, signature and discoverable user handle. The browser combines the result with its original clientDataJSON into the WebAuthn PublicKeyCredential. The private key is absent from the response.';
  proof[5].title='Submit the assertion to the web application';
  proof[5].summary='The browser sends the WebAuthn response directly to the application over HTTPS.';
  proof[5].detail='The application’s own page serializes the WebAuthn response fields for its own verification endpoint, for example using base64url to carry bytes in JSON. The property names shown are canonical WebAuthn members; the HTTP endpoint and serialization format are application-specific. It sends the original clientDataJSON, authenticatorData, signature, credential ID and userHandle. There is no identity-provider callback or OAuth authorization code in this ceremony.';
  proof[5].payload.unshift(directFidoPayload('HTTP','POST https://app.example.test/webauthn/assertion'));
  proof[6].title='Verify the FIDO2 proof in the application';
  proof[6].summary='The backend verifies its challenge, origin, RP binding and credential public-key signature.';
  proof[6].detail='The application backend resolves the stored credential and its account binding. It checks clientDataJSON.type is webauthn.get, the challenge belongs to the unexpired pending attempt and is used only once, origin equals an allowed https://app.example.test origin, and authenticatorData.rpIdHash equals SHA256("app.example.test"). It checks required presence and user verification flags, verifies the assertion signature with the registered credentialPublicKey and evaluates signCount and relevant credential/backup metadata. The returned userHandle must match the account associated with that credential. A successful verification can now establish an application session.';
  proof[6].fields.push('credentialId','userHandle');
  proof[6].checks=['Credential and userHandle resolve the same application account','Challenge is current, expected and single-use','Origin and RP ID hash match the application','Required UP = 1 and UV = 1','Assertion signature valid with stored credentialPublicKey','Counter and credential metadata evaluated according to policy'];
  return [
    directFidoStep('fido-d01','Choose security-key sign-in','user','browser','prepare','local','The person chooses Sign in with a security key on the web application.','The web application itself supports FIDO2/WebAuthn. This example starts without an authenticated app session and uses a previously enrolled discoverable credential for app.example.test. A YubiKey or the selected platform authenticator holds that credential.',[],[directFidoPayload('Browser UI action','Sign in at https://app.example.test')]),
    directFidoStep('fido-d02','Request options from the application','browser','app','prepare','https','The browser asks the application backend to start a fresh sign-in.','The browser makes a normal HTTPS request to the application’s options endpoint. The application backend creates and retains the authentication context for its WebAuthn challenge. Endpoint naming and session association are application-specific.',[],[directFidoPayload('HTTP','GET https://app.example.test/webauthn/login-options')]),
    ...proof,
    {...directFidoStep('fido-d03','Create the application session','app','browser','complete','https','The backend creates an authenticated application session and returns a protected cookie.','After successful WebAuthn verification, the backend consumes the pending challenge, binds a new server-side session to the verified application account and returns an opaque protected session cookie. Subsequent browser requests send this cookie according to browser cookie policy. The cookie is neither an ID token nor the credential private key. There is no OAuth code, PKCE verifier or client-secret exchange in this direct flow.',['challengeLogin','credentialId','userHandle','sessionCookieApp'],[directFidoPayload('Set-Cookie','__Host-app_session=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/'),directFidoPayload('HTTPS response','Signed-in web application page')],['Pending challenge consumed','Application session bound to the verified credential account']),directSessionCreated:true},
    directFidoStep('fido-d04','Show the signed-in application','browser','user','complete','local','The browser shows the person their signed-in application.','The browser renders the application response and stores its session cookie. The person sees the authenticated UI; this display step does not transfer credential keys or cookie values to the person.',[],[directFidoPayload('Browser UI','Signed in at app.example.test')]),
  ];
}

function directFidoEnrollment(authenticator) {
  const roaming=authenticator==='yubikey';
  const ceremony=FLOWS.enrollment.map(directFidoClone);
  ceremony[0].title='Begin from a verified application account';
  ceremony[0].summary='The person chooses to register a key in their verified application account.';
  ceremony[0].detail='Enrollment is authorized by an already verified application account/session. The web application must know which account owns this new credential before enrollment. Initial identity verification, recovery and account creation are outside this diagram; an unauthenticated visitor must not be allowed to attach a key to someone else’s account.';
  ceremony[0].payload=[directFidoPayload('Browser UI action','Add security key to verified application account')];
  ceremony[1].summary='The browser requests registration in its verified application session.';
  ceremony[1].detail='The application backend verifies the existing application session and permission to add a credential, then prepares its WebAuthn creation policy. This is a direct application enrollment endpoint, not an OIDC authorization endpoint.';
  ceremony[1].payload=[directFidoPayload('HTTP','GET https://app.example.test/webauthn/registration-options'),directFidoPayload('Application account','Verified app-user-913')];
  ceremony[2].summary='The application supplies its fresh challenge, RP identity and account handle.';
  ceremony[2].detail='The application backend generates a separate unpredictable registration challenge and binds it to the authorized enrollment attempt. Creation options name RP app.example.test, readable RP name Example web application and a stable opaque handle for this application account. This example requires a discoverable credential and local user verification, requests none attestation, and offers compatible ES256/RS256 algorithms; actual capability and policy must fit the chosen authenticator.';
  ceremony[3].title=roaming?'Create the credential through CTAP2':'Create the credential through Windows Hello';
  ceremony[3].channel=roaming?'ctap2':'webauthn';
  ceremony[3].summary=roaming?'The browser/platform sends a CTAP2 MakeCredential request to the security key.':'The browser/platform asks Windows Hello to create the credential.';
  ceremony[3].detail='The web page calls navigator.credentials.create({publicKey: options}) on https://app.example.test. The browser checks the RP domain scope and secure origin, constructs clientDataJSON with type webauthn.create, this challenge and application origin, and hashes its exact bytes. '+(roaming?'The browser/platform uses CTAP2 MakeCredential over a supported local USB/NFC transport to deliver the RP/account data, algorithm/policy options, clientDataHash and relevant PIN/UV authorization to the YubiKey.':'The browser/platform delivers creation options and clientDataHash through Windows Hello’s supported local platform interface. The website uses WebAuthn; this platform operation is not labelled as a USB/NFC CTAP2 exchange.');
  ceremony[3].payload.push(directFidoPayload('Local authenticator interface',roaming?'CTAP2 authenticatorMakeCredential · USB/NFC':'Platform authenticator operation'));
  ceremony[4].summary=roaming?'The person approves a new credential with the key PIN and touch.':'The person approves credential creation with supported Hello verification.';
  ceremony[4].detail=roaming?'The system UI requests the security-key PIN and touch. CTAP2 PIN/UV protocols protect the local PIN exchanges, and the web application receives no PIN. The key will return signed UP/UV flags as evidence of local presence and user verification.':'Windows Hello performs supported local PIN or biometric verification. The web application receives the registration result and flags, never the PIN or biometric sample.';
  ceremony[5].channel=roaming?'ctap2':'webauthn';
  ceremony[5].detail='The authenticator creates a new credential private/public-key pair scoped to app.example.test and bound to the opaque application user handle. The private key is stored in its protected credential source and is never sent to the web application. The local response contains attested credential data with credential ID/public key and flags. The browser returns a WebAuthn PublicKeyCredential with its own clientDataJSON and attestationObject; with the requested none-attestation privacy handling the final object has fmt none and an empty attStmt.';
  ceremony[6].title='Submit registration to the application';
  ceremony[6].summary='The browser posts the credential creation result to the application backend.';
  ceremony[6].detail='The browser posts the canonical WebAuthn response members over HTTPS to an application-specific registration endpoint. The backend verifies the registration challenge, webauthn.create type, allowed application origin, app.example.test RP ID hash, required UP/UV flags, credential algorithm, authorization for the verified account and applicable attestation policy. It consumes the pending registration challenge. No private credential key or OAuth tokens are submitted.';
  ceremony[6].payload.unshift(directFidoPayload('HTTP','POST https://app.example.test/webauthn/registration'));
  ceremony[7].title='Save the credential for the application account';
  ceremony[7].summary='The application stores the public key, credential ID and verified account binding.';
  ceremony[7].detail='The application backend persists the credential ID, credentialPublicKey, opaque user-handle association and relevant counter/credential metadata for this verified application account. It confirms enrollment to the browser. Later direct sign-in verifies the authenticator’s assertion with this public key; the server cannot create an assertion with it and does not receive the private key.';
  return ceremony;
}

const directFidoTransportCache=new WeakMap();
const directFidoCanonical = item => String(item.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
export function applyFidoTransport(steps,authenticator='hello') {
  if(authenticator!=='yubikey')return steps;
  if(directFidoTransportCache.has(steps))return directFidoTransportCache.get(steps);
  const output=[];let request=null;let options=null;
  for(const original of steps) {
    const copy={...original,fields:[...original.fields],payload:original.payload.map(p=>({...p})),checks:[...original.checks],authenticatorKind:'yubikey'};
    const canonical=directFidoCanonical(copy);
    if(canonical==='l08'||canonical==='e03')options=copy;
    if(canonical==='l09'||canonical==='e04') {
      request=copy;copy.from='browser';copy.to='browser';copy.channel='internal';copy.ctapOperation='prepare';
      copy.title=canonical==='l09'?'Invoke WebAuthn and select the security key':'Invoke WebAuthn credential creation';
      copy.summary='The page invokes WebAuthn; the browser prepares the context and selects the roaming key.';
      copy.detail='The relying-party page calls navigator.credentials.'+(canonical==='l09'?'get':'create')+'(). The browser verifies the secure origin and RP ID scope, creates the exact clientDataJSON bytes and derives clientDataHash. The browser/platform selects the FIDO2 security key and prepares the requested ceremony. The authenticated CTAP2 GetAssertion/MakeCredential command will be sent after local PIN/UV authorization is available. The application uses WebAuthn; the client platform manages the local CTAP2 exchange.';
      copy.payload=copy.payload.filter(p=>p.name!=='Local authenticator interface');
    }
    if((canonical==='l10'||canonical==='e05')&&request) {
      copy.ctapOperation='local-pin';copy.fields=['localVerification'];
      copy.title='Verify the security-key PIN locally';
      copy.summary='The person enters the key PIN in the system authenticator UI.';
      copy.detail='The client platform obtains local PIN verification through the CTAP2 PIN/UV protocol. This schematic abstracts key agreement and protected PIN-hash verification: it does not send a plaintext PIN over USB or to the relying-party server. The security key authorizes a local PIN/UV token. A separate touch will confirm presence after the authenticated signing/creation command is requested.';
      copy.payload=[directFidoPayload('Local operation','Security-key PIN verification'),directFidoPayload('Server-bound secrets','None: PIN verification is local')];
      output.push(copy);
      const creating=directFidoCanonical(request)==='e04';
      const rpId=request.payload.find(p=>p.name==='rpId'||p.name==='rp.id')?.value||directFidoRpId;
      const macroFlags={...Object.fromEntries(['directFido','relyingPartyActor','mode','architecture','clientKind','upstreamKind','topology','upstream'].filter(key=>key in copy).map(key=>[key,copy[key]])),authenticatorKind:'yubikey'};
      output.push({...directFidoStep(copy.id+'-c01','Receive protected PIN/UV authorization','authenticator','browser',copy.phase,'ctap2','The key returns protected local authorization-token material to the client platform.','After successful protected PIN verification, the key returns an encrypted PIN/UV authorization token under the negotiated protocol. The browser/platform recovers and retains the token locally. This teaching macro abstracts the local PIN/UV key-agreement and request/response sequence; the token and PIN-related values are never sent to the relying-party server. pinUvAuthProtocol is already negotiated local/request context, not a member of this ClientPIN response.',['pinUvAuthToken','pinUvAuthProtocol'],[directFidoPayload('pinUvAuthToken','Encrypted local PIN/UV authorization token')]),...macroFlags,ctapOperation:'pin-uv'});
      const commandFields=creating?['ctapMakeCredential','rpObject','rpId','userObject','userId','pubKeyCredParams','residentKey','ctapResidentKey','clientDataHash','pinUvAuthParam','pinUvAuthProtocol']:['ctapGetAssertion','rpId','clientDataHash','pinUvAuthParam','pinUvAuthProtocol'];
      const commandPayload=[directFidoPayload(creating?'authenticatorMakeCredential':'authenticatorGetAssertion',creating?'CTAP2 command 0x01':'CTAP2 command 0x02')];
      if(creating)commandPayload.push(directFidoPayload('rp',options?.payload.find(p=>p.name==='rp')?.value||'{ id: "'+rpId+'" }'),directFidoPayload('user',options?.payload.find(p=>p.name==='user')?.value||'Verified application user handle'),directFidoPayload('pubKeyCredParams',options?.payload.find(p=>p.name==='pubKeyCredParams')?.value||'Configured compatible signature algorithms'),directFidoPayload('options.rk',true,'The client translates WebAuthn authenticatorSelection.residentKey = required into the CTAP2 discoverable-credential option rk = true.'));
      else commandPayload.push(directFidoPayload('rpId',rpId));
      commandPayload.push(directFidoPayload('clientDataHash','SHA256(clientDataJSON bytes)'),directFidoPayload('pinUvAuthParam','authenticate(pinUvAuthToken, clientDataHash)','A local CTAP authentication tag; the PIN/UV token itself is not included in this command.'),directFidoPayload('pinUvAuthProtocol','2'));
      output.push({...directFidoStep(copy.id+'-c02',creating?'Send the authorized MakeCredential command':'Send the authorized GetAssertion command','browser','authenticator',copy.phase,'ctap2','The client platform sends the RP data, client-data hash and derived PIN/UV authentication tag to the key.','The client derives pinUvAuthParam from its local pinUvAuthToken and this command’s clientDataHash using the supported selected PIN/UV protocol. It then sends the authenticated CTAP2 '+(creating?'MakeCredential':'GetAssertion')+' command over a supported USB/NFC transport. '+(creating?'The WebAuthn creation policy requires residentKey, so the client maps authenticatorSelection.residentKey = required to CTAP2 options.rk = true; the key creates a discoverable credential. ':'')+'The key validates this command authorization and RP scope. This PIN-based YubiKey example does not claim an on-key biometric UV option; user verification comes from PIN/UV authorization. The relying-party server never receives the CTAP token or authentication tag.',commandFields,commandPayload),...macroFlags,ctapOperation:creating?'make-credential':'get-assertion'});
      output.push({...directFidoStep(copy.id+'-c03','Confirm presence with a touch','user','authenticator',copy.phase,'local','The person touches the security key when the system requests presence.','The requested credential operation waits for user presence, illustrated by touching the security key. The key later reports UP and successful PIN-based UV inside authenticatorData. These signed flags are constructed during the actual credential operation, not sent by the person as form input.',['localVerification','flagsUP'],[directFidoPayload('Local operation','Touch security-key sensor')]),...macroFlags,ctapOperation:'user-presence'});
      continue;
    }
    if(canonical==='l11') {
      copy.ctapOperation='assertion-sign';
      copy.fields=copy.fields.map(id=>id==='authenticatorData'?'ctapAuthData':id==='signature'?'ctapSignature':id);
      copy.detail='The key selects its existing RP-scoped credential, builds CTAP authData with the RP ID hash, flags and counter, and signs authData || clientDataHash. The protected credential private key remains in the authenticator. The browser will construct the WebAuthn response after receiving the CTAP result.';
      copy.payload=[{...directFidoPayload('authData','Binary signed authenticator data','rpIdHash || flags || signCount || optional data'),attributeId:'ctapAuthData'},{...directFidoPayload('signature','Assertion signature bytes','Sign(privateKey, authData || clientDataHash)'),attributeId:'ctapSignature'},directFidoPayload('privateKey','Never transmitted')];
    }
    if(canonical==='l12'||canonical==='e06') {
      const creating=canonical==='e06';
      const rawId=copy.payload.find(p=>p.name==='rawId')?.value||'credential-id-bytes';
      const authData=creating?'rpIdHash || flags || signCount || attestedCredentialData { credentialId, credentialPublicKey }':copy.payload.find(p=>p.name==='authenticatorData')?.value||'Binary signed authenticator data';
      const signature=copy.payload.find(p=>p.name==='signature')?.value||'Assertion signature bytes';
      const userHandle=copy.payload.find(p=>p.name==='userHandle')?.value||'opaque-user-bytes';
      copy.channel='ctap2';copy.ctapOperation='return';copy.ctapCeremony=creating?'registration':'assertion';
      copy.title=creating?'Return the CTAP MakeCredential result':'Return the CTAP GetAssertion result';
      copy.summary=creating?'The key returns fmt, authData and attStmt; the browser has not yet constructed the WebAuthn registration object.':'The key returns credential, authData, signature and user to the local client platform.';
      copy.detail=creating?'The authenticator creates a new credential private/public-key pair and stores its RP/account binding. CTAP MakeCredential returns fmt, authData and attStmt; the new credential ID and public key are nested in authData.attestedCredentialData. This example illustrates a compatible packed attestation response before browser privacy handling. The key sends neither its private key, browser clientDataJSON nor a WebAuthn attestationObject.':'The CTAP GetAssertion response carries a credential descriptor, the signed authData bytes, signature and user entity. This discoverable-credential example includes user.id for the selected enrolled account. Those are CTAP members; WebAuthn rawId, response.authenticatorData and response.userHandle are constructed by the browser in the next local step. The private key is absent.';
      copy.fields=creating?['privateKey','credentialPublicKey','ctapCredentialId','rpId','userId','ctapResidentKey','rpIdHash','flagsUP','flagsUV','signCount','ctapFmt','ctapAuthData','ctapAttStmt']:['credentialId','userId','rpIdHash','flagsUP','flagsUV','signCount','ctapCredential','ctapAuthData','ctapSignature','ctapUser'];
      if(creating)copy.attributeValues={...copy.attributeValues,ctapCredentialId:rawId};
      copy.payload=(creating?[['ctapFmt','fmt','packed'],['ctapAuthData','authData',authData],['ctapAttStmt','attStmt','{ alg: -7, sig: attestation-signature-bytes, x5c: [attestation-certificate] }']]:[['ctapCredential','credential','{ type: "public-key", id: '+rawId+' }'],['ctapAuthData','authData',authData],['ctapSignature','signature',signature],['ctapUser','user','{ id: '+userHandle+' }']]).map(([attributeId,name,value])=>({name,value,attributeId}));
      copy.attributeValues={...copy.attributeValues,...Object.fromEntries(copy.payload.map(p=>[p.attributeId,p.value]))};
      output.push(copy);
      const conversion={...copy,id:copy.id+'-api',from:'browser',to:'browser',channel:'internal',ctapOperation:creating?'registration-api-conversion':'assertion-api-conversion',
        title:creating?'Construct the WebAuthn registration response':'Construct the WebAuthn assertion response',
        summary:creating?'The browser applies attestation privacy policy and constructs the PublicKeyCredential API result.':'The browser maps the CTAP result into WebAuthn members and attaches its own clientDataJSON.',
        detail:creating?'The browser extracts the new credential ID from authData.attestedCredentialData and constructs PublicKeyCredential.id/rawId and type public-key. It processes fmt, authData and attStmt, then applies the requested attestation = none privacy policy: the final CBOR attestationObject uses fmt none, an empty attStmt and the required anonymized authenticator data. The credential public key remains in its attested credential data. The browser attaches its original clientDataJSON and reports optional response.getTransports() hints. This is a browser-local API conversion, not a CTAP packet or server message.':'The browser maps credential.id to PublicKeyCredential.rawId (and base64url id), preserves authData as response.authenticatorData and signature as response.signature, and maps the selected user.id to response.userHandle. It sets type public-key and attaches its original response.clientDataJSON. The CTAP user object is not submitted to the server. This is a browser-local API conversion before the relying-party page serializes the WebAuthn result over HTTPS.',
        fields:creating?['ctapFmt','ctapAuthData','ctapAttStmt','ctapCredentialId','credentialId','credentialType','credentialPublicKey','authenticatorData','attestation','attestationObject','clientDataJSON','transports']:['ctapCredential','ctapAuthData','ctapSignature','ctapUser','credentialId','credentialType','authenticatorData','signature','userHandle','clientDataJSON'],
        payload:creating?[{name:'rawId',value:rawId,attributeId:'credentialId'},{name:'type',value:'public-key',attributeId:'credentialType'},{name:'response.attestationObject',value:'CBOR { fmt: "none", authData: registration data with anonymized AAGUID, attStmt: {} }',attributeId:'attestationObject'},{name:'response.clientDataJSON',value:'Original browser registration context bytes',attributeId:'clientDataJSON'},{name:'response.getTransports()',value:'["usb", "nfc"] (when supported)',attributeId:'transports'}]:[{name:'rawId',value:rawId,attributeId:'credentialId'},{name:'type',value:'public-key',attributeId:'credentialType'},{name:'response.authenticatorData',value:authData,attributeId:'authenticatorData'},{name:'response.signature',value:signature,attributeId:'signature'},{name:'response.userHandle',value:userHandle,attributeId:'userHandle'},{name:'response.clientDataJSON',value:'Original browser authentication context bytes',attributeId:'clientDataJSON'}],checks:[]};
      output.push(conversion);
      continue;
    }
    if(['e07','e08'].includes(canonical)) {
      if(!copy.fields.includes('transports'))copy.fields.push('transports');
      if(canonical==='e07')copy.payload.push(directFidoPayload('transports','["usb", "nfc"] (when reported and supported)','Optional browser metadata obtained through registration response.getTransports(); it is a selection hint, not signed evidence of device type.'));
    }
    output.push(copy);
  }
  directFidoTransportCache.set(steps,output);return output;
}

const directFidoStepCache=new Map();
export function getFidoSteps(mode,authenticator='hello') {
  const selectedMode=mode==='fido-enrollment'?'fido-enrollment':'fido-login';
  const selectedAuthenticator=authenticator==='yubikey'?'yubikey':'hello';
  const key=selectedMode+':'+selectedAuthenticator;
  if (!directFidoStepCache.has(key)) {
    const baseSteps=selectedMode==='fido-enrollment'?directFidoEnrollment(selectedAuthenticator):directFidoLogin(selectedAuthenticator);
    const steps=applyFidoTransport(baseSteps,selectedAuthenticator);
    steps.forEach((item,index)=>Object.assign(item,{directFido:true,relyingPartyActor:'app',mode:selectedMode,architecture:'web',clientKind:'webauthn-rp',upstreamKind:'none',sourceIndex:index}));
    directFidoStepCache.set(key,steps);
  }
  return directFidoStepCache.get(key);
}

const directFidoActorCache=new Map();
export function getFidoActorOverrides(mode,authenticator='hello') {
  const enrollment=mode==='fido-enrollment';
  const key=(enrollment?'enrollment':'login')+':'+authenticator;
  if (directFidoActorCache.has(key)) return directFidoActorCache.get(key);
  const a=(id,kind)=>({id,kind});
  const result={
    app:{...ACTORS.app,name:'Web application',role:'WebAuthn relying party / FIDO2 verifier',plainRole:'Creates its own challenge, verifies the credential proof and establishes your application session.',
      attributes:[a('rpId','static'),a('origin','static'),a('rpName','static'),a('userVerification','static'),a('residentKey','static'),a('credentialId',enrollment?'received':'static'),a('credentialPublicKey',enrollment?'received':'static'),a('userId','static'),a('signCount','static'),a(enrollment?'challengeRegistration':'challengeLogin','generated'),a(enrollment?'rpObject':'allowCredentials','generated'),...(enrollment?[a('userObject','generated'),a('pubKeyCredParams','static'),a('authenticatorSelection','static'),a('attestation','static'),a('attestationObject','received')]:[a('authenticatorData','received'),a('signature','received'),a('userHandle','received'),a('sessionCookieApp','generated')]),a('clientDataJSON','received'),a('session','static')],
      notes:['The application is the relying party at RP ID app.example.test and HTTPS origin https://app.example.test.','Its backend generates the current WebAuthn challenge and verifies the response with the registered credential public key.','FIDO2 uses the WebAuthn API; the browser/platform handles the local CTAP2 exchange with an external security key.','This direct ceremony does not use an identity provider, OAuth authorization code, PKCE or OIDC token.']},
    browser:{...ACTORS.browser,name:'Web browser',role:'WebAuthn client / local authenticator mediator',plainRole:'Runs the application’s WebAuthn call and connects it to the selected authenticator.',
      attributes:[a('origin','static'),a(enrollment?'challengeRegistration':'challengeLogin','received'),a('rpId','received'),a('clientDataJSON','generated'),a('clientDataHash','generated'),a('clientDataType','generated'),a('crossOrigin','generated'),a('credentialId','received'),...(enrollment?[a('rpObject','received'),a('userObject','received'),a('authenticatorSelection','received'),a('attestationObject','received')]:[a('authenticatorData','received'),a('signature','received'),a('userHandle','received'),a('sessionCookieApp','received')])],
      notes:['Invokes WebAuthn on the application’s HTTPS page; no IdP page is involved.','The app calls navigator.credentials.create() or navigator.credentials.get(); the browser/platform manages device access.','A YubiKey uses a supported CTAP2 transport such as USB or NFC; Windows Hello uses its local platform interface.','Cannot read or send the credential private key.']},
    user:{...ACTORS.user,plainRole:enrollment?'Approves registering a security key for the verified application account.':'Approves the security-key assertion with local user verification.',attributes:[a('userName','static'),a('displayName','static'),a('localVerification','generated')],notes:['For the illustrated YubiKey, a security-key PIN and touch authorize the local operation.','Local PIN/biometric information is not sent to the application server.']},
  };
  for (const id of ['yubikey','hello']) result[id]={...ACTORS[id],attributes:ACTORS[id].attributes.map(item=>({...item,kind:!enrollment&&['privateKey','credentialPublicKey','credentialId'].includes(item.id)?'static':item.kind})),notes:id==='yubikey'?['A FIDO2-capable YubiKey communicates locally with the browser/platform using CTAP2 over a supported USB/NFC transport.','The protected credential is scoped to app.example.test.','CTAP2 PIN/UV protocols protect local PIN-related exchange; no plaintext PIN is a website credential.','This device is selected as an alternative to the platform authenticator.']:['A platform authenticator using its supported local Windows Hello interface.','The credential is scoped to app.example.test.','Local Hello verification uses a supported PIN or biometric gesture.','This device is selected as an alternative to the roaming security key.']};
  if(authenticator==='yubikey') {
    result.browser.attributes.push(a('pinUvAuthToken','received'),a('pinUvAuthParam','generated'),a('pinUvAuthProtocol','static'),a(enrollment?'ctapMakeCredential':'ctapGetAssertion','generated'));
    result.yubikey.attributes.push(a('pinUvAuthToken','generated'),a('pinUvAuthParam','received'),a('pinUvAuthProtocol','static'),a(enrollment?'ctapMakeCredential':'ctapGetAssertion','received'));
    const responseFields=enrollment?['ctapFmt','ctapAuthData','ctapAttStmt','ctapCredentialId']:['ctapCredential','ctapAuthData','ctapSignature','ctapUser'];
    result.browser.attributes.push(...responseFields.map(id=>a(id,'received')));
    result.yubikey.attributes=result.yubikey.attributes.filter(item=>!['signature','userHandle',...(enrollment?['credentialId']:[])].includes(item.id));
    result.yubikey.attributes.push(...responseFields.map(id=>a(id,'generated')));
    const constructed=new Set(enrollment?['credentialId','authenticatorData','attestationObject']:['credentialId','authenticatorData','signature','userHandle']);
    result.browser.attributes=result.browser.attributes.map(item=>constructed.has(item.id)?{...item,kind:'generated'}:item);
    result.browser.attributes.push(...[...constructed].filter(id=>!result.browser.attributes.some(item=>item.id===id)).map(id=>a(id,'generated')));
    if(enrollment){result.browser.attributes.push(a('transports','generated'),a('residentKey','received'),a('ctapResidentKey','generated'));result.yubikey.attributes.push(a('ctapResidentKey','received'));result.app.attributes.push(a('transports','received'));}
  }
  directFidoActorCache.set(key,result);return result;
}

const directFidoExamples=Object.freeze({rpId:directFidoRpId,origin:directFidoOrigin,rpName:directFidoRpName,rpObject:'{ id: "app.example.test", name: "Example web application" }',rpIdHash:'SHA256("app.example.test")',userId:directFidoUserHandle,userHandle:directFidoUserHandle,userObject:'{ id: opaque-app-user-bytes, name: "alice", displayName: "Alice" }',session:'Application-side pending WebAuthn context / verified application session',clientDataJSON:'{ type: "webauthn.get", challenge: "…", origin: "https://app.example.test", crossOrigin: false }'});
export function getFidoExampleOverrides() {return directFidoExamples;}

const directFidoDefinitionCache=new Map();
export function getFidoAttributeOverrides(mode='fido-login') {
  const enrollment=mode==='fido-enrollment';
  const key=enrollment?'enrollment':'login';
  if (directFidoDefinitionCache.has(key)) return directFidoDefinitionCache.get(key);
  const result={};
  const relevant=new Set(getFidoSteps(mode).flatMap(item=>item.fields));
  for (const actor of Object.values(getFidoActorOverrides(mode))) for (const entry of actor.attributes) relevant.add(entry.id);
  for (const id of relevant) {
    const base=ATTRIBUTES[id]||VARIANT_ATTRIBUTES[id]||FIDO_ATTRIBUTES[id];if(!base)continue;
    const updated={...base};
    for(const field of ['meaning','description','origin','generator','purpose','example'])updated[field]=directFidoText(updated[field]);
    updated.purpose=updated.purpose.replaceAll('Keycloak','the web application');
    updated.origin=updated.origin.replaceAll('WebAuthn Passwordless Policy','WebAuthn registration policy');updated.generator=updated.origin;
    result[id]=updated;
  }
  result.challengeLogin={...result.challengeLogin,origin:'Generated by the application backend and bound to a short-lived pending WebAuthn sign-in context.',generator:'The application backend',purpose:'The application verifies that the assertion matches its current single-use challenge. This challenge is not OAuth state, nonce or PKCE.'};
  result.challengeRegistration={...(ATTRIBUTES.challengeRegistration||{}),origin:'Generated by the web application backend after authorizing enrollment for its verified account.',generator:'The application backend',purpose:'The application matches the creation response to its single-use pending enrollment attempt.',example:EXAMPLE.registrationChallenge+' (fresh bytes; symbolic)'};
  result.privateKey={...result.privateKey,purpose:'Creates WebAuthn signatures within the authenticator’s protected environment. The application backend never receives this private credential key.'};
  result.userVerification={...result.userVerification,origin:'Configured by the web application’s WebAuthn policy.',generator:'The web application',purpose:'required asks the authenticator to verify the person locally. The server checks the signed UV flag.'};
  result.session={...ATTRIBUTES.session,name:'application authentication context / session',meaning:'The web application’s server-side pending WebAuthn attempt or verified account session; implementation-specific.',description:'A server-side application context, distinct from an OAuth/OIDC session or token.',origin:'Created and retained by the web application backend.',generator:'The web application backend',purpose:enrollment?'Authorizes credential enrollment for an already verified application account.':'Associates a fresh challenge with a pending attempt and later establishes the authenticated application account.',standard:'WebAuthn relying-party session policy; application-specific',source:directFidoWebAuthn};
  for(const [id,example] of Object.entries(directFidoExamples))result[id]={...(result[id]||ATTRIBUTES[id]||VARIANT_ATTRIBUTES[id]),example};
  if(enrollment)result.clientDataJSON.example='{ type: "webauthn.create", challenge: "…", origin: "https://app.example.test", crossOrigin: false }';
  directFidoDefinitionCache.set(key,result);return result;
}
