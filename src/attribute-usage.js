import { ATTRIBUTES } from './protocol-data.js';

/**
 * Explicit protocol operations for the attribute index.
 *
 * Step.fields is a glossary/context list, not a list of transmitted values.
 * These records distinguish local computation, stored data, nested message
 * members, and actual transport. No payload/detail string searching is used.
 * A step can perform local operations before and after its one message.
 *
 * getAttributeUsage(steps, attributeId | topicId, authenticator) returns:
 * [{ step, index, actions, focusActors, fieldIds, wireAttributeIds }].
 * Each action has {attributeId, kind, actorId, detail}; optional carriedAs
 * describes the enclosing wire object, and optional conditional marks policy-
 * dependent claims. The ordered actions can be projected into local self-loop
 * animations and directed transfers without sending a local secret by mistake.
 */

export const ATTRIBUTE_TOPICS = {
  clientIdentity: {
    id: 'clientIdentity', name: 'client_id · identify the application',
    attributeIds: ['clientIdApp'],
    summary: 'The registered public application identifier is configured in the app, sent during authorization and code exchange, bound to the code, and compared with the ID token’s audience. It is different from a client secret and the broker’s client identifier.',
  },
  pkce: {
    id: 'pkce', name: 'PKCE · protect the code exchange',
    attributeIds: ['codeVerifier', 'codeChallenge', 'codeChallengeMethod'],
    summary: 'The app creates a secret, sends only its public commitment through the browser, then proves the secret directly to Realm A.',
  },
  state: {
    id: 'state', name: 'state · match each browser callback',
    attributeIds: ['stateApp', 'stateBroker'],
    summary: 'The app and broker create independent labels and compare the label returned on their own callback.',
  },
  nonce: {
    id: 'nonce', name: 'nonce · match each identity token',
    attributeIds: ['nonceApp', 'nonceBroker'],
    summary: 'Each OIDC client creates its own nonce; its provider returns that value inside the signed ID token.',
  },
  webauthn: {
    id: 'webauthn', name: 'WebAuthn · create and verify a passkey proof',
    attributeIds: ['challengeLogin', 'challengeRegistration', 'rpId', 'origin', 'clientDataJSON', 'clientDataHash', 'privateKey', 'credentialPublicKey', 'credentialId', 'authenticatorData', 'rpIdHash', 'flagsUP', 'flagsUV', 'signCount', 'signature', 'userHandle', 'attestationObject'],
    summary: 'The relying party supplies a fresh challenge; the browser binds its website context and the authenticator signs locally. The relying party verifies with the registered public key.',
  },
  fido2: {
    id: 'fido2', name: 'FIDO2 · WebAuthn + CTAP2 security-key login',
    attributeIds: ['challengeLogin', 'challengeRegistration', 'rpId', 'origin', 'clientDataJSON', 'clientDataHash', 'privateKey', 'credentialPublicKey', 'credentialId', 'authenticatorData', 'rpIdHash', 'flagsUP', 'flagsUV', 'signCount', 'signature', 'userHandle', 'attestationObject', 'localVerification', 'userVerification', 'residentKey', 'ctapResidentKey', 'ctapGetAssertion', 'ctapMakeCredential', 'ctapCredential', 'ctapCredentialId', 'ctapAuthData', 'ctapSignature', 'ctapUser', 'ctapFmt', 'ctapAttStmt', 'pinUvAuthParam', 'pinUvAuthProtocol', 'pinUvAuthToken', 'transports'],
    summary: 'WebAuthn connects the website to the browser. CTAP2 connects the local browser/platform to a roaming security key. The relying-party server verifies the signed proof with its registered public key.',
  },
  totp: {
    id: 'totp', name: 'TOTP · shared secret to one-time code',
    attributeIds: ['otpSecret', 'otpUri', 'otpAlgorithm', 'otpDigits', 'otpPeriod', 'otpT0', 'otpTime', 'otpCounter', 'otpCode', 'otpWindow', 'otpReplay'],
    summary: 'Enrollment shares a secret with B and the authenticator app. Later sign-in sends only a short code; each side calculates it independently.',
  },
};

const FIDO_CTAP_SOURCE = 'https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html';
const FIDO_PIN_SOURCE = 'https://docs.yubico.com/yesdk/users-manual/application-fido2/pin-uv-auth-protocols.html';
const FIDO_WEBAUTHN_SOURCE = 'https://www.w3.org/TR/webauthn-3/';
const fidoAttribute = (name, meaning, origin, purpose, example, standard, source) => ({ name, meaning, description: meaning, origin, generator: origin, purpose, example, standard, source });

export const FIDO_ATTRIBUTES = {
  ctapCredential: fidoAttribute('credential', 'The CTAP GetAssertion response descriptor identifying the credential used for this proof.', 'The security key returns a PublicKeyCredentialDescriptor with type public-key and the credential identifier in its id member.', 'The browser maps credential.id to WebAuthn rawId and its base64url id. The CTAP descriptor is not itself a WebAuthn PublicKeyCredential.', '{ type: "public-key", id: credential-id-bytes }', 'FIDO CTAP2 §6.2.2', FIDO_CTAP_SOURCE),
  ctapCredentialId: fidoAttribute('credentialId (attested credential data)', 'The new credential identifier encoded inside registration authenticator data.', 'Generated by the authenticator and embedded in the attestedCredentialData portion of CTAP MakeCredential authData.', 'The browser extracts these bytes to construct WebAuthn rawId and id. This is a nested binary field, not a top-level CTAP rawId member.', 'New credential-id-bytes', 'WebAuthn §6.5.1 / CTAP2 §6.1.2', FIDO_WEBAUTHN_SOURCE),
  ctapAuthData: fidoAttribute('authData', 'The binary authenticator-data member returned by CTAP GetAssertion or MakeCredential.', 'Constructed by the key with the RP ID hash, signed flags, counter and applicable extension or attested credential data.', 'GetAssertion signs authData with clientDataHash; the browser maps these bytes to response.authenticatorData. MakeCredential includes the new credential ID/public key; the browser wraps it in attestationObject after applying attestation policy.', 'rpIdHash || flags || signCount || applicable credential / extension data', 'FIDO CTAP2 §6.1.2 / §6.2.2', FIDO_CTAP_SOURCE),
  ctapSignature: fidoAttribute('signature', 'The assertion signature byte string in a CTAP GetAssertion response.', 'The authenticator signs authData concatenated with the browser-provided clientDataHash using the selected credential private key.', 'The browser preserves these bytes as WebAuthn response.signature; the relying party later verifies the signed data with its registered public key.', 'Sign(privateKey, authData || clientDataHash)', 'FIDO CTAP2 §6.2.2', FIDO_CTAP_SOURCE),
  ctapUser: fidoAttribute('user', 'The account entity in a CTAP discoverable-credential GetAssertion response.', 'The security key reads the enrolled account association. In this discoverable-credential example, user.id contains its opaque account handle.', 'The browser maps only the selected user.id to WebAuthn response.userHandle, rather than forwarding this CTAP user object. Identifying names may be returned only after user verification; non-discoverable credentials may omit user.', '{ id: opaque-user-bytes }', 'FIDO CTAP2 §6.2.2', FIDO_CTAP_SOURCE),
  ctapFmt: fidoAttribute('fmt', 'The attestation format identifier in a CTAP MakeCredential response.', 'Chosen by the authenticator for the attestation statement it generates during credential creation.', 'The browser processes this format and statement, then applies the requested WebAuthn attestation policy. With attestation none, the final API object has fmt none; the original key response can use another format.', 'packed (illustrative compatible authenticator format)', 'FIDO CTAP2 §6.1.2', FIDO_CTAP_SOURCE),
  ctapAttStmt: fidoAttribute('attStmt', 'The attestation statement map in a CTAP MakeCredential response.', 'Generated by the authenticator using the attestation format and its permitted attestation material.', 'The browser combines fmt, authData and attStmt into a WebAuthn attestationObject, applying privacy policy before returning it to the page. The shown none policy removes the statement in the final object.', '{ alg: -7, sig: attestation-signature-bytes, x5c: [attestation-certificate] } (illustrative packed statement)', 'FIDO CTAP2 §6.1.2', FIDO_CTAP_SOURCE),
  ctapGetAssertion: fidoAttribute('authenticatorGetAssertion', 'The CTAP2 command that asks a roaming authenticator to create a sign-in assertion.', 'The browser/platform encodes command 0x02 after preparing the RP scope, client-data hash and required local verification authorization.', 'Connects the local client to the security key. The website origin itself is represented by clientDataHash, rather than sent as an origin string to the key.', 'CTAP2 command 0x02: rpId + clientDataHash + permitted options', 'FIDO CTAP2 §6.2', FIDO_CTAP_SOURCE),
  ctapMakeCredential: fidoAttribute('authenticatorMakeCredential', 'The CTAP2 command that asks a roaming authenticator to create a new credential.', 'The local browser/platform encodes command 0x01 using the authorized WebAuthn creation request.', 'Supplies RP/user data, algorithm choices and clientDataHash. The new private key remains protected on the security key.', 'CTAP2 command 0x01: rp + user + pubKeyCredParams + clientDataHash', 'FIDO CTAP2 §6.1', FIDO_CTAP_SOURCE),
  ctapResidentKey: fidoAttribute('options.rk', 'The CTAP2 Boolean requesting a discoverable credential during registration.', 'The browser/platform translates WebAuthn authenticatorSelection.residentKey = "required" into the MakeCredential option rk = true.', 'Requires the security key to create a credential it can later discover for its RP/account. This option belongs to MakeCredential; it is not sent in GetAssertion.', true, 'FIDO CTAP2 §6.1 / discoverable credentials', FIDO_CTAP_SOURCE),
  pinUvAuthParam: fidoAttribute('pinUvAuthParam', 'A command authentication tag made using a local PIN/UV authorization token.', 'The client/platform applies the selected PIN/UV protocol to pinUvAuthToken and this command’s clientDataHash.', 'Lets the key authorize this signing/registration operation after PIN verification. The server receives signed UV evidence, not the PIN, token or CTAP authentication tag.', 'authenticate(pinUvAuthToken, clientDataHash)', 'FIDO CTAP2 §6.1 / §6.2; PIN/UV protocol', FIDO_CTAP_SOURCE),
  pinUvAuthProtocol: fidoAttribute('pinUvAuthProtocol', 'The chosen version of the local CTAP PIN/UV protection protocol.', 'Selected by the client/platform from the protocols supported by the security key.', 'Both sides use matching encryption and authentication rules for protected PIN verification and later commands. This is separate from a website password or server login.', '2 in this teaching example; 1 is another protocol version', 'CTAP2 PIN/UV authentication protocols', FIDO_PIN_SOURCE),
  pinUvAuthToken: fidoAttribute('pinUvAuthToken', 'A secret local authorization token held by the authenticator and permitted client/platform.', 'Generated by the security key; returned encrypted after successful protected PIN/UV verification, then recovered by the client/platform.', 'Authorizes permitted local CTAP commands through derived authentication tags. It never goes to the relying-party server. The plaintext PIN is not sent to the key; the PIN protocol protects the verification material.', 'Protected local token; encrypted on the local transport; never sent to the website', 'CTAP2 PIN/UV authentication protocols', FIDO_PIN_SOURCE),
  transports: fidoAttribute('transports', 'WebAuthn hints describing ways a credential’s authenticator may be reached.', 'Learned by the browser during registration through response.getTransports(); the relying party can retain the list with the credential.', 'Helps later credential selection and transport discovery. A hint is not signed proof of device type. Discoverable requests with empty allowCredentials do not include per-credential transport hints.', '["usb", "nfc"] for a compatible roaming key; "internal" for a platform authenticator', 'WebAuthn §5.8.3 / §5.8.4', FIDO_WEBAUTHN_SOURCE),
};

export const FIDO_SOURCES = [
  { name: 'FIDO2 specifications overview', standard: 'FIDO Alliance', url: 'https://fidoalliance.org/specifications/', note: 'FIDO2 combines WebAuthn with the client-to-authenticator protocol.' },
  { name: 'Client to Authenticator Protocol', standard: 'FIDO CTAP2.2', url: FIDO_CTAP_SOURCE, note: 'Local roaming-key commands, protected PIN/UV authorization and transport bindings.' },
  { name: 'Yubico PIN/UV authentication protocols', standard: 'Yubico official developer documentation', url: FIDO_PIN_SOURCE, note: 'Encrypted PIN verification, local authorization tokens and authentication tags.' },
];

const operation = (ids, kind, actorId, detail, extra = {}) => ids.map(attributeId => ({
  attributeId, kind, actorId,
  detail: typeof detail === 'function' ? detail(attributeId) : detail,
  ...extra,
}));
const use = (ids, actorId, detail) => operation(ids, 'use', actorId, detail);
const create = (ids, actorId, detail) => operation(ids, 'create', actorId, detail);
const derive = (ids, actorId, detail) => operation(ids, 'derive', actorId, detail);
const store = (ids, actorId, detail) => operation(ids, 'store', actorId, detail);
const verify = (ids, actorId, detail) => operation(ids, 'verify', actorId, detail);
const inspect = (ids, actorId, detail) => operation(ids, 'inspect', actorId, detail);
const transfer = (ids, from, to, detail, carriedAs) => ids.flatMap(attributeId => [
  ...operation([attributeId], 'send', from, detail || `Sends ${ATTRIBUTES[attributeId]?.name || attributeId} in this message.`, carriedAs ? { carriedAs } : {}),
  ...operation([attributeId], 'receive', to, detail || `Receives ${ATTRIBUTES[attributeId]?.name || attributeId} from the sender.`, carriedAs ? { carriedAs } : {}),
]);
const appRequest = ['clientIdApp', 'redirectApp', 'stateApp', 'nonceApp', 'codeChallenge', 'codeChallengeMethod', 'scope', 'responseType'];
const brokerRequest = ['clientIdBroker', 'redirectBroker', 'stateBroker', 'nonceBroker', 'scope', 'responseType'];
const creationOptions = ['challengeRegistration', 'rpObject', 'rpId', 'rpName', 'userObject', 'userId', 'userName', 'displayName', 'pubKeyCredParams', 'authenticatorSelection', 'residentKey', 'userVerification', 'attestation'];
const totpSettings = ['otpAlgorithm', 'otpDigits', 'otpPeriod', 'otpT0'];
const totpInputs = ['otpSecret', 'otpAlgorithm', 'otpDigits', 'otpPeriod', 'otpT0'];

// Canonical IDs are shared by the cloned password/TOTP and passkey/TOTP modes.
// Each entry is deliberately maintained alongside the teaching protocol model.
const STEP_OPERATIONS = {
  l01: [
    ...inspect(['clientIdApp', 'redirectApp'], 'app', 'The client registration and callback are context for this sign-in button; this click does not transmit either field.'),
  ],
  l02: [
    ...use(['clientIdApp'], 'app', 'Reads the configured application client_id from its registration in Realm A. This public identifier is not a password and is not newly generated for each sign-in.'),
    ...use(['redirectApp'], 'app', 'Binds the loopback callback listener on this computer before opening the browser.'),
    ...create(['stateApp', 'nonceApp'], 'app', 'Creates independent unpredictable values for this one sign-in attempt.'),
    ...store(['stateApp', 'nonceApp'], 'app', 'Keeps the original value locally for a later callback or ID-token comparison.'),
    ...create(['codeVerifier'], 'app', 'Generates the high-entropy one-time code_verifier before opening the browser.'),
    ...store(['codeVerifier'], 'app', 'Retains code_verifier privately in the application client until the direct token request.'),
    ...use(['codeChallengeMethod'], 'app', 'Chooses S256, the SHA-256 derivation method.'),
    ...use(['codeVerifier'], 'app', 'Hashes its locally retained code_verifier to derive the public code_challenge; the verifier is not sent to the browser.'),
    ...derive(['codeChallenge'], 'app', 'Computes code_challenge = BASE64URL(SHA256(ASCII(code_verifier))), without padding.'),
  ],
  l03: [
    ...use(['authorizationEndpoint'], 'app', 'Uses A’s discovered authorization_endpoint as the destination opened in the system browser.'),
    ...transfer(appRequest, 'app', 'browser', 'Included in the authorization URL opened in the external browser. code_verifier is deliberately absent.'),
  ],
  l04: [
    ...use(['authorizationEndpoint'], 'browser', 'Navigates to A’s authorization_endpoint with the app’s request.'),
    ...transfer(appRequest, 'browser', 'realmA', 'The browser delivers this authorization-request parameter to Realm A.'),
    ...verify(['clientIdApp', 'redirectApp', 'responseType', 'scope', 'codeChallengeMethod'], 'realmA', 'Checks the registered application client, allowed redirect, requested operation/scopes and S256 policy.'),
    ...store(['clientIdApp'], 'realmA', 'Retains the registered application client binding with this authorization request so its later code and ID token are issued for this client.'),
    ...store(['stateApp', 'nonceApp'], 'realmA', 'Remembers the original app request value for its later response.'),
    ...store(['codeChallenge', 'codeChallengeMethod'], 'realmA', 'Stores the original PKCE commitment and method in the pending authorization context. The verifier has not arrived.'),
    ...create(['session'], 'realmA', 'Creates A’s pending authentication session for the browser request.'),
  ],
  l05: [
    ...use(['clientIdBroker', 'redirectBroker'], 'realmA', 'Uses its own confidential broker registration and HTTPS callback for a separate OIDC request to B.'),
    ...inspect(['clientSecret'], 'realmA', 'The broker secret is configured here but is not placed in the browser authorization request.'),
    ...create(['stateBroker', 'nonceBroker'], 'realmA', 'Generates separate broker state and nonce; these are not the app’s values.'),
    ...store(['stateBroker', 'nonceBroker'], 'realmA', 'Keeps each original broker value for its own later callback and ID-token checks.'),
  ],
  l06: [
    ...use(['authorizationEndpoint'], 'realmA', 'Uses B’s authorization_endpoint as the redirect destination.'),
    ...create(['location'], 'realmA', 'Constructs an HTTP Location URL containing the broker authorization request.'),
    ...transfer(['location'], 'realmA', 'browser', 'HTTP redirect response header points the browser at B’s authorization endpoint.'),
    ...transfer(brokerRequest, 'realmA', 'browser', 'Broker authorization-request parameter inside the Location URL.', 'Location URL query'),
  ],
  l07: [
    ...use(['authorizationEndpoint'], 'browser', 'Follows the redirect to B’s authorization_endpoint.'),
    ...transfer(brokerRequest, 'browser', 'realmB', 'Browser delivers the broker authorization-request parameter to B.'),
    ...verify(['clientIdBroker', 'redirectBroker'], 'realmB', 'Checks that the broker is registered and its HTTPS callback is allowed.'),
    ...store(['stateBroker', 'nonceBroker'], 'realmB', 'Remembers the broker’s value for the authorization response or ID-token claim.'),
    ...create(['session'], 'realmB', 'Starts B’s own pending authentication session; A and B have distinct sessions.'),
  ],
  l08: [
    ...create(['challengeLogin'], 'realmB', 'Generates fresh unpredictable bytes for this WebAuthn authentication attempt.'),
    ...store(['challengeLogin'], 'realmB', 'Binds the expected challenge to the pending B authentication session.'),
    ...use(['rpId', 'allowCredentials', 'userVerification', 'timeout'], 'realmB', 'Builds the WebAuthn request options from its credential records and policy.'),
    ...transfer(['challengeLogin', 'rpId', 'allowCredentials', 'userVerification', 'timeout'], 'realmB', 'browser', 'WebAuthn publicKey request option delivered to the HTTPS login page.'),
  ],
  l09: [
    ...verify(['rpId', 'origin'], 'browser', 'Checks that the requested RP ID is valid for B’s secure page origin.'),
    ...use(['challengeLogin'], 'browser', 'Copies B’s fresh challenge into the browser-produced clientDataJSON.'),
    ...create(['clientDataJSON', 'clientDataType', 'crossOrigin'], 'browser', 'Serializes the ceremony context with type webauthn.get, challenge, origin and frame context.'),
    ...use(['origin'], 'browser', 'Derives the origin from the currently loaded HTTPS page and embeds it in clientDataJSON.'),
    ...derive(['clientDataHash'], 'browser', 'Computes SHA256 over the exact clientDataJSON bytes. It does not send the JSON or origin to the authenticator.'),
    ...transfer(['rpId', 'clientDataHash', 'userVerification'], 'browser', 'authenticator', 'Local authenticator request carries RP scope, the client-data hash and the requested verification policy.'),
  ],
  l10: [
    ...use(['localVerification'], 'user', 'Supplies the selected device’s supported PIN or biometric interaction locally.'),
    ...verify(['localVerification'], 'authenticator', 'Checks local user verification and presence. Keycloak does not receive the PIN or biometric sample.'),
    ...inspect(['flagsUP', 'flagsUV'], 'authenticator', 'Successful local presence and verification will be represented by signed flags in the next authenticator-data step; no flags travel from the person.'),
  ],
  l11: [
    ...use(['rpId'], 'authenticator', 'Selects the existing credential registered for this RP ID before creating the assertion.'),
    ...use(['privateKey'], 'authenticator', 'Uses the existing protected credential private key to sign. The private key stays inside the authenticator/provider.'),
    ...derive(['rpIdHash'], 'authenticator', 'Computes SHA256 of the RP ID for the authenticator-data binding.'),
    ...create(['flagsUP', 'flagsUV'], 'authenticator', 'Sets the signed presence and verification flags after the successful local interaction.'),
    ...use(['signCount'], 'authenticator', 'Maintains the credential’s supported signature-counter value; some authenticators keep it zero.'),
    ...create(['authenticatorData'], 'authenticator', 'Builds binary authenticatorData containing RP ID hash, flags, counter and any applicable metadata.'),
    ...use(['clientDataHash'], 'authenticator', 'Concatenates the browser’s client-data hash after authenticatorData as the assertion signing input.'),
    ...derive(['signature'], 'authenticator', 'Computes Sign(privateKey, authenticatorData || clientDataHash).'),
  ],
  l12: [
    ...use(['credentialId', 'userHandle'], 'authenticator', 'Selects the registered discoverable credential and its stored account handle.'),
    ...transfer(['credentialId', 'authenticatorData', 'signature', 'userHandle'], 'authenticator', 'browser', 'Returned authenticator assertion response; the browser later attaches its own clientDataJSON.'),
  ],
  l13: [
    ...use(['credentialType'], 'browser', 'Labels the WebAuthn API result as a public-key credential.'),
    ...transfer(['credentialId', 'credentialType', 'clientDataJSON', 'authenticatorData', 'signature', 'userHandle'], 'browser', 'realmB', 'Canonical WebAuthn assertion member in the HTTPS form/action submission.'),
    ...transfer(['challengeLogin', 'origin', 'clientDataType', 'crossOrigin'], 'browser', 'realmB', 'Browser ceremony context is carried inside the original clientDataJSON bytes, not as a separate request.', 'response.clientDataJSON'),
    ...transfer(['rpIdHash', 'flagsUP', 'flagsUV', 'signCount'], 'browser', 'realmB', 'Signed authenticator metadata is carried inside authenticatorData, not as a separate request.', 'response.authenticatorData'),
  ],
  l14: [
    ...verify(['credentialId', 'userHandle'], 'realmB', 'Resolves the stored credential and checks its account association.'),
    ...verify(['clientDataType', 'challengeLogin', 'origin', 'rpIdHash', 'flagsUP', 'flagsUV', 'crossOrigin'], 'realmB', 'Checks the expected ceremony, current challenge, permitted origin/RP binding and required presence/verification context.'),
    ...use(['credentialPublicKey'], 'realmB', 'Uses the public key stored at registration to verify the assertion signature. This public key is not sent anew by the sign-in authenticator.'),
    ...verify(['signature'], 'realmB', 'Verifies the assertion over authenticatorData and SHA256(clientDataJSON) with the stored credential public key.'),
    ...verify(['signCount'], 'realmB', 'Evaluates supported counter/credential properties under the verification policy.'),
  ],
  l15: [
    ...create(['session'], 'realmB', 'Creates B’s completed SSO session after all configured required factors succeed.'),
    ...create(['codeB'], 'realmB', 'Issues a short-lived single-use code for the registered broker client.'),
    ...use(['stateBroker', 'redirectBroker'], 'realmB', 'Echoes the original broker state and uses the registered broker callback.'),
    ...create(['location'], 'realmB', 'Constructs the broker callback Location URL with code and state.'),
    ...transfer(['location'], 'realmB', 'browser', 'HTTP redirect tells the browser to visit A’s callback.'),
    ...transfer(['codeB', 'stateBroker', 'redirectBroker'], 'realmB', 'browser', 'Carried in the redirect destination URL; this response contains no ID token.', 'Location URL'),
  ],
  l16: [
    ...transfer(['codeB', 'stateBroker', 'redirectBroker'], 'browser', 'realmA', 'Browser calls the HTTPS broker callback URL with code and state.'),
    ...verify(['stateBroker'], 'realmA', 'Compares returned broker state with the value retained for its pending B request.'),
  ],
  l17: [
    ...use(['tokenEndpoint'], 'realmA', 'Calls B’s token_endpoint directly over HTTPS, without the browser.'),
    ...use(['clientIdBroker', 'clientSecret'], 'realmA', 'Uses confidential broker credentials to construct HTTP Basic client authentication.'),
    ...derive(['authorizationHeader'], 'realmA', 'Builds Authorization: Basic from the encoded broker client ID and client secret.'),
    ...transfer(['grantType', 'codeB', 'redirectBroker', 'authorizationHeader'], 'realmA', 'realmB', 'Direct HTTPS token request from the broker to B.'),
    ...transfer(['clientIdBroker', 'clientSecret'], 'realmA', 'realmB', 'Confidential client authentication is encoded in the HTTP Basic Authorization header, not sent through the browser.', 'Authorization: Basic'),
    ...verify(['codeB', 'redirectBroker', 'clientIdBroker', 'clientSecret'], 'realmB', 'Validates the code, matching callback/client binding and confidential broker authentication.'),
  ],
  l18: [
    ...use(['realmSigningKey'], 'realmB', 'Uses B’s own retained private realm key to sign its ID token. The realm signing key is never in the token response.'),
    ...create(['idTokenB', 'accessTokenB', 'tokenType', 'expiresIn', 'exp', 'iat'], 'realmB', 'Issues the broker-hop token response and its token lifetime/issuance metadata.'),
    ...create(['audience'], 'realmB', 'Sets the ID-token aud claim to include the broker client that requested this token.'),
    ...use(['issuerB', 'subjectB', 'nonceBroker'], 'realmB', 'Places issuer B, B’s subject and the original broker nonce in its ID token.'),
    ...transfer(['idTokenB', 'accessTokenB', 'tokenType', 'expiresIn'], 'realmB', 'realmA', 'Top-level field in B’s direct token response to the broker.'),
    ...transfer(['issuerB', 'audience', 'subjectB', 'nonceBroker', 'exp', 'iat'], 'realmB', 'realmA', 'Claim inside B’s signed ID token, not a separate top-level token response parameter.', 'id_token claims'),
  ],
  l19: [
    ...use(['jwksUri'], 'realmA', 'Uses B’s trusted discovery/verification-key configuration to obtain public signature verification keys.'),
    ...verify(['idTokenB', 'issuerB', 'audience', 'exp', 'nonceBroker'], 'realmA', 'Validates B’s token signature, exact issuer, intended broker audience, expiry and original broker nonce.'),
    ...use(['subjectB'], 'realmA', 'Uses the trusted (iss B, sub B) identity under broker account-linking policy.'),
    ...create(['subjectA'], 'realmA', 'Resolves or creates the mapped local A identity; sub A need not equal sub B.'),
    ...create(['session'], 'realmA', 'Completes A’s local session after trusted upstream identity mapping and required broker actions.'),
  ],
  l20: [
    ...use(['clientIdApp'], 'realmA', 'Reads the original registered application client_id and binds the authorization code to that application client; this identifier is not included in the callback URL.'),
    ...use(['codeChallenge', 'codeChallengeMethod'], 'realmA', 'Binds the new app authorization code to the original stored PKCE challenge and S256 method. Neither value is added to this redirect.'),
    ...create(['codeA'], 'realmA', 'Issues a single-use authorization code for the registered application client and its original protected request.'),
    ...use(['stateApp', 'redirectApp'], 'realmA', 'Echoes the original app state and chooses the app’s registered loopback callback.'),
    ...create(['location'], 'realmA', 'Constructs the loopback callback Location URL with the new code and original app state.'),
    ...transfer(['location'], 'realmA', 'browser', 'HTTP redirect tells the browser to call the app on this computer.'),
    ...transfer(['codeA', 'stateApp', 'redirectApp'], 'realmA', 'browser', 'Carried in the loopback Location URL. The PKCE commitment remains stored in A.', 'Location URL'),
  ],
  l21: [
    ...transfer(['redirectApp', 'codeA', 'stateApp'], 'browser', 'app', 'The browser follows the loopback URL and supplies code and state to the native app listener.'),
  ],
  l22: [
    ...verify(['stateApp', 'redirectApp'], 'app', 'Compares the returned state and callback context with its pending local sign-in attempt.'),
    ...store(['codeA'], 'app', 'Accepts the callback’s code for the following token request after validating the callback; the code is not yet a validated identity.'),
  ],
  l23: [
    ...use(['tokenEndpoint'], 'app', 'Calls A’s token_endpoint directly over HTTPS.'),
    ...transfer(['clientIdApp', 'grantType', 'codeA', 'redirectApp', 'codeVerifier'], 'app', 'realmA', 'Direct public native-client token request. client_id identifies the app and code_verifier proves its original PKCE request; code_challenge remains stored in A.', 'application/x-www-form-urlencoded body'),
    ...verify(['codeA', 'clientIdApp', 'redirectApp'], 'realmA', 'Checks the unexpired single-use code and its original public-client/redirect binding.'),
    ...use(['codeChallengeMethod'], 'realmA', 'Reads the S256 method retained with the original authorization request.'),
    ...derive(['codeChallenge'], 'realmA', 'Recomputes BASE64URL(SHA256(ASCII(received code_verifier))) locally. The request does not transmit code_challenge.'),
    ...verify(['codeVerifier', 'codeChallenge'], 'realmA', 'Compares the recomputed commitment with the original stored code_challenge. Tokens are issued only if the PKCE proof matches.'),
  ],
  l24: [
    ...use(['clientIdApp'], 'realmA', 'Uses the registered application client identifier to set the ID token’s aud claim. The response carries aud inside id_token, not a separate client_id claim.'),
    ...use(['realmSigningKey'], 'realmA', 'Signs with A’s own retained private realm key; this is different from B’s token key and the passkey key.'),
    ...create(['idTokenA', 'accessTokenA', 'tokenType', 'expiresIn', 'exp', 'iat'], 'realmA', 'Issues A’s own token response and its issuance/lifetime metadata for the app.'),
    ...operation(['refreshToken'], 'create', 'realmA', 'May issue a refresh token when this client and realm policy allow it.', { conditional: true }),
    ...create(['audience'], 'realmA', 'Sets the ID-token aud claim to include the application client that requested this token.'),
    ...use(['issuerA', 'subjectA', 'nonceApp'], 'realmA', 'Places A’s issuer, local A subject and original app nonce in its ID token.'),
    ...transfer(['idTokenA', 'accessTokenA', 'tokenType', 'expiresIn'], 'realmA', 'app', 'Top-level field in A’s direct token response to the app.'),
    ...transfer(['refreshToken'], 'realmA', 'app', 'Optional top-level refresh_token field, only if issued by policy.'),
    ...transfer(['issuerA', 'audience', 'subjectA', 'nonceApp', 'exp', 'iat'], 'realmA', 'app', 'Claim inside A’s signed ID token, not an independent top-level response field.', 'id_token claims'),
  ],
  l25: [
    ...use(['clientIdApp'], 'app', 'Reads its own configured application client_id as the expected recipient when validating A’s ID token.'),
    ...verify(['clientIdApp'], 'app', 'Checks that the ID token’s aud includes this configured application client_id. The token carries an aud claim, not a client_id claim.'),
    ...use(['jwksUri'], 'app', 'Uses A’s trusted discovered public keys for the realm token signature check.'),
    ...verify(['idTokenA', 'issuerA', 'audience', 'exp', 'iat', 'nonceApp'], 'app', 'Validates A’s ID token and the original app request context before accepting the identity.'),
    ...use(['subjectA'], 'app', 'Uses the validated (iss A, sub A) pair as its accepted local signed-in identity.'),
    ...operation(['acr', 'amr'], 'verify', 'app', 'If configured claims are present and the app requires an agreed assurance level, evaluates their agreed semantics. These claims do not automatically prove a fresh passkey/MFA ceremony.', { conditional: true }),
  ],
  e01: [
    ...inspect(['session', 'userId', 'userName'], 'browser', 'A previously verified B account/session is a prerequisite. This click does not yet transmit registration options.'),
  ],
  e02: [
    ...use(['session'], 'browser', 'Uses the existing authorized B browser context to request credential enrollment; session cookie details are implementation-specific.'),
    ...verify(['session'], 'realmB', 'Checks that the B account/session is authenticated and authorized to add this credential.'),
    ...use(['userId'], 'realmB', 'Resolves the verified account’s opaque WebAuthn user handle.'),
  ],
  e03: [
    ...create(['challengeRegistration'], 'realmB', 'Creates fresh random bytes for this independent passkey registration ceremony.'),
    ...store(['challengeRegistration'], 'realmB', 'Retains the expected challenge in the authorized B registration context.'),
    ...create(['rpObject', 'userObject'], 'realmB', 'Builds the RP identity and verified account identity objects for WebAuthn creation options.'),
    ...use(creationOptions.filter(id => !['challengeRegistration', 'rpObject', 'userObject'].includes(id)), 'realmB', 'Uses the configured RP, verified user account and required credential policy in the creation options.'),
    ...transfer(creationOptions, 'realmB', 'browser', 'Creation-option member, including nested rp/user/authenticatorSelection fields, in B’s HTTPS enrollment response.', 'publicKey creation options'),
  ],
  e04: [
    ...verify(['origin', 'rpId'], 'browser', 'Checks B’s secure origin and allowed RP ID scope before invoking creation.'),
    ...use(['origin', 'challengeRegistration'], 'browser', 'Embeds the current page origin and B’s registration challenge in browser-produced clientDataJSON.'),
    ...create(['clientDataJSON', 'clientDataType', 'crossOrigin'], 'browser', 'Creates exact browser context bytes for type webauthn.create.'),
    ...derive(['clientDataHash'], 'browser', 'Computes SHA256 over the exact clientDataJSON bytes for the local authenticator creation request.'),
    ...transfer(['rpObject', 'rpId', 'rpName', 'userObject', 'userId', 'userName', 'displayName', 'pubKeyCredParams', 'residentKey', 'userVerification', 'clientDataHash'], 'browser', 'authenticator', 'Local authenticator creation request uses RP/account information, compatible algorithm and verification/discoverability policy.'),
  ],
  e05: [
    ...use(['localVerification'], 'user', 'Approves creating a credential using the device’s local PIN or biometric interaction.'),
    ...verify(['localVerification'], 'authenticator', 'Performs local presence and verification before generating the credential; no server receives the unlock secret.'),
    ...inspect(['flagsUP', 'flagsUV'], 'authenticator', 'The next returned authenticator data reports successful local presence/verification in signed flags.'),
  ],
  e06: [
    ...create(['privateKey', 'credentialPublicKey', 'credentialId'], 'authenticator', 'Creates a new credential key pair and opaque credential identifier within the selected authenticator.'),
    ...store(['privateKey', 'rpId', 'userId', 'credentialId'], 'authenticator', 'Stores the protected credential source and account/RP binding. Its private key remains local.'),
    ...derive(['rpIdHash'], 'authenticator', 'Computes SHA256 of the registration RP ID inside authenticator data.'),
    ...create(['flagsUP', 'flagsUV', 'signCount', 'authenticatorData', 'attestationObject'], 'authenticator', 'Builds registration authenticator data with credential public key, RP binding and required flags; the final none-attestation response omits identifying evidence.'),
    ...transfer(['credentialId', 'credentialPublicKey', 'authenticatorData', 'attestationObject', 'rpIdHash', 'flagsUP', 'flagsUV', 'signCount'], 'authenticator', 'browser', 'Public registration data returned through the local platform interface. The private key is absent.', 'registration authenticator data'),
    ...use(['clientDataJSON'], 'browser', 'Attaches its previously created browser context to the final registration API result; this JSON did not come from the authenticator.'),
  ],
  e07: [
    ...use(['credentialType'], 'browser', 'Labels the new WebAuthn credential as public-key.'),
    ...transfer(['credentialId', 'credentialType', 'clientDataJSON', 'attestationObject'], 'browser', 'realmB', 'Canonical registration-response member submitted over HTTPS.'),
    ...transfer(['challengeRegistration', 'origin', 'clientDataType', 'crossOrigin'], 'browser', 'realmB', 'Registration browser context is nested inside the original clientDataJSON bytes.', 'response.clientDataJSON'),
    ...transfer(['credentialPublicKey', 'authenticatorData', 'rpIdHash', 'flagsUP', 'flagsUV', 'signCount'], 'browser', 'realmB', 'Registration public-key/authenticator metadata is nested inside the attestationObject.', 'response.attestationObject'),
    ...verify(['challengeRegistration', 'origin', 'rpIdHash', 'flagsUP', 'flagsUV', 'clientDataType', 'pubKeyCredParams', 'attestation'], 'realmB', 'Checks the authorized registration ceremony, challenge, secure website binding, flags and configured algorithm/attestation policy.'),
  ],
  e08: [
    ...store(['credentialId', 'credentialPublicKey', 'userId', 'signCount'], 'realmB', 'Persists the credential public key, opaque identifier, account association and relevant counter metadata for future sign-in. These fields are not sent in the success message.'),
  ],
  p01: [
    ...use(['session'], 'realmB', 'Keeps the password action within the pending B authentication session.'),
    ...inspect(['password'], 'browser', 'B displays a password input request; this form response does not contain the person’s password.'),
  ],
  p02: [
    ...use(['userName', 'password'], 'user', 'Supplies the B account username and secret password on the login page.'),
    ...transfer(['userName', 'password'], 'user', 'browser', 'Human input into B’s browser login form, outside OAuth authorization parameters.'),
  ],
  p03: [
    ...transfer(['userName', 'password'], 'browser', 'realmB', 'B’s HTTPS login-action submission carries username and password directly to B.'),
    ...use(['passwordHash'], 'realmB', 'Reads its protected password-verification record; this stored record is not sent by the browser.'),
    ...verify(['password'], 'realmB', 'Verifies the submitted password against its configured credential provider/hash record.'),
    ...use(['session'], 'realmB', 'Keeps this credential check attached to the provider’s configured authentication flow and pending account/session.'),
  ],
  u01: [
    ...use(['session'], 'realmB', 'Keeps the account-identification action attached to the pending provider authentication session.'),
    ...inspect(['loginUsername'], 'browser', 'Displays a username-only identification form. A username identifies an account but is not an authentication factor.'),
  ],
  u02: [
    ...transfer(['loginUsername'], 'user', 'browser', 'Person enters the account identifier in the provider page. The username is not a password or proof of possession.'),
  ],
  u03: [
    ...transfer(['loginUsername'], 'browser', 'realmB', 'Browser submits the account identifier to resolve which enrolled OTP credential should be checked.'),
    ...use(['loginUsername', 'session'], 'realmB', 'Resolves the account within the pending login. Identification alone does not authenticate the person.'),
  ],
  m01: [
    ...use(['session', 'otpWindow'], 'realmB', 'Keeps the OTP action attached to the pending B authentication and selected OTP acceptance policy.'),
    ...inspect(['otpCode'], 'browser', 'The page requests a current code; this response does not yet carry an OTP value.'),
  ],
  m02: [
    ...use(totpInputs, 'totp', 'Reads the enrolled shared secret K and agreed algorithm, digits and time-step settings locally.'),
    ...use(['otpTime'], 'totp', 'Reads this device’s current clock without contacting Keycloak.'),
    ...derive(['otpCounter'], 'totp', 'Calculates T = floor((Current Unix time − T0) / X).'),
    ...derive(['otpCode'], 'totp', 'Calculates TOTP = HOTP(K, T) with the selected HMAC and decimal truncation.'),
    ...transfer(['otpCode'], 'totp', 'user', 'Displays only the short numeric OTP to the person. The shared secret and clock/counter are not displayed in this sign-in transfer.'),
  ],
  m03: [
    ...transfer(['otpCode'], 'user', 'browser', 'Person copies the displayed code into B’s OTP form.'),
  ],
  m04: [
    ...transfer(['otpCode'], 'browser', 'realmB', 'Browser submits only the short OTP value to B over HTTPS. The enrolled shared secret is not resent.'),
    ...use(['session'], 'realmB', 'Resolves the pending B login action/account for this submitted OTP.'),
  ],
  m05: [
    ...use(totpInputs, 'realmB', 'Uses B’s stored symmetric secret and the matching configured algorithm/digits/time-step settings to calculate candidate HOTP(K, T) codes.'),
    ...use(['otpTime'], 'realmB', 'Reads B’s own server clock, independently from the authenticator device.'),
    ...derive(['otpCounter'], 'realmB', 'Derives the current candidate time-step counter and the limited permitted neighboring counters.'),
    ...use(['otpWindow'], 'realmB', 'Applies the configured clock-drift acceptance window; the display period alone does not define acceptance lifetime.'),
    ...verify(['otpCode', 'otpReplay'], 'realmB', 'Recomputes candidate HOTP(K, T) codes, matches the submitted value and applies configured one-time-use/replay policy.'),
    ...store(['otpReplay'], 'realmB', 'Records successful OTP use under the configured replay policy before completing the required factor.'),
  ],
  t01: [
    ...inspect(['session', 'otpSecret'], 'browser', 'An already verified B account is required; the setup click does not generate or transmit the new OTP secret yet.'),
  ],
  t02: [
    ...use(['session'], 'browser', 'Requests setup using the existing authorized B account/session context.'),
    ...verify(['session'], 'realmB', 'Checks authorization to bind a new OTP credential to this verified account.'),
    ...use(['otpAlgorithm', 'otpDigits', 'otpPeriod', 'otpT0'], 'realmB', 'Selects the agreed OTP configuration from B’s policy before provisioning.'),
  ],
  t03: [
    ...create(['otpSecret'], 'realmB', 'Generates a high-entropy per-credential symmetric secret K. The fixed displayed seed is a public RFC test example only.'),
    ...store(['otpSecret'], 'realmB', 'Retains the pending secret for setup-code validation and, after confirmation, future OTP checks.'),
    ...use(totpSettings, 'realmB', 'Uses the chosen OTP algorithm, digits, period and agreed time origin.'),
    ...create(['otpUri'], 'realmB', 'Builds a de facto otpauth provisioning URI and QR carrying secret K plus matching settings. This URI convention is not an RFC 6238 wire format.'),
    ...transfer(['otpUri', 'otpSecret', 'otpAlgorithm', 'otpDigits', 'otpPeriod'], 'realmB', 'browser', 'Secret and provisioning settings intentionally appear in the protected enrollment QR/URI. This is a one-time setup transfer.', 'otpauth URI / enrollment QR'),
  ],
  t04: [
    ...transfer(['otpUri', 'otpSecret', 'otpAlgorithm', 'otpDigits', 'otpPeriod'], 'browser', 'totp', 'Authenticator app decodes the QR displayed on the browser setup page; the person initiates this optical/local transfer.', 'enrollment QR'),
    ...store(['otpSecret', 'otpAlgorithm', 'otpDigits', 'otpPeriod'], 'totp', 'Stores the shared seed and agreed settings so it can compute matching codes offline.'),
    ...use(['otpT0'], 'totp', 'Uses the agreed default time origin T0 = 0; the de facto URI does not carry a T0 parameter in this model.'),
  ],
  t05: [
    ...use(totpInputs, 'totp', 'Reads the newly enrolled secret and agreed OTP settings locally.'),
    ...use(['otpTime'], 'totp', 'Reads the authenticator device’s own clock.'),
    ...derive(['otpCounter'], 'totp', 'Computes T = floor((Current Unix time − T0) / X).'),
    ...derive(['otpCode'], 'totp', 'Calculates the current confirmation code using HOTP(K, T).'),
    ...transfer(['otpCode'], 'totp', 'user', 'Displays the short setup-confirmation code to the person; the seed is not included.'),
  ],
  t06: [
    ...transfer(['otpCode'], 'user', 'browser', 'Person enters the displayed code into the setup confirmation form.'),
  ],
  t07: [
    ...transfer(['otpCode'], 'browser', 'realmB', 'Browser submits the confirmation code to the authorized B setup action. It does not resend the pending seed.'),
    ...verify(['session'], 'realmB', 'Checks that this setup is still authorized for the verified account.'),
    ...use([...totpInputs, 'otpWindow'], 'realmB', 'Uses the already pending seed and settings with the permitted server-clock time window.'),
    ...derive(['otpCounter'], 'realmB', 'Computes candidate time-step counters from its own current time and OTP settings.'),
    ...verify(['otpCode', 'otpReplay'], 'realmB', 'Checks that the submitted code matches the pending credential and applicable one-time-use policy.'),
    ...store(['otpSecret', 'otpReplay'], 'realmB', 'Activates and persists the account’s shared-secret credential and relevant replay state after successful confirmation.'),
  ],
  t08: [
    ...inspect(['otpSecret', 'otpAlgorithm', 'otpDigits', 'otpPeriod'], 'realmB', 'These are already stored credential properties. The success response contains only confirmation, not another copy of the seed or settings.'),
  ],
};

const canonicalStepId = id => String(id).match(/(?:^|-)([lemtpuwdc]\d{2})$/)?.[1] || String(id);
const resolveUsageActor = (actorId, authenticator) => actorId === 'authenticator' ? authenticator : actorId;

const directFidoFields = new Set([
  'session', 'sessionCookieApp', 'challengeLogin', 'challengeRegistration', 'rpId', 'rpName', 'origin',
  'allowCredentials', 'userVerification', 'timeout', 'residentKey', 'userId', 'userName', 'displayName',
  'pubKeyCredParams', 'attestation', 'rpObject', 'userObject', 'authenticatorSelection', 'credentialId',
  'credentialType', 'privateKey', 'credentialPublicKey', 'clientDataJSON', 'clientDataHash', 'clientDataType',
  'crossOrigin', 'authenticatorData', 'rpIdHash', 'flagsUP', 'flagsUV', 'signCount', 'signature', 'userHandle',
  'attestationObject', 'localVerification', ...Object.keys(FIDO_ATTRIBUTES),
]);
const singleRealmBrokerSteps = new Set(['l05', 'l06', 'l07', 'l15', 'l16', 'l17', 'l18', 'l19']);
const usageSingleRealmBrokerFields = new Set(['clientIdBroker', 'clientSecret', 'redirectBroker', 'stateBroker', 'nonceBroker', 'codeB', 'idTokenB', 'accessTokenB', 'authorizationHeader']);

function ctapOperations(step) {
  switch (step.ctapOperation) {
    case 'assertion-sign':
      return STEP_OPERATIONS.l11.map(action => ({ ...action,
        attributeId: action.attributeId === 'authenticatorData' ? 'ctapAuthData' : action.attributeId === 'signature' ? 'ctapSignature' : action.attributeId,
        detail: action.detail.replaceAll('authenticatorData', 'CTAP authData'),
      }));
    case 'return': {
      if (step.ctapCeremony === 'registration') return [
        ...use(['ctapResidentKey'], 'authenticator', 'Applies the accepted options.rk = true setting to create and store the discoverable credential.'),
        ...create(['privateKey', 'credentialPublicKey', 'ctapCredentialId'], 'authenticator', 'Creates the RP-scoped key pair and credential identifier. Its private key is protected and never transmitted.'),
        ...store(['privateKey', 'rpId', 'userId', 'ctapCredentialId'], 'authenticator', 'Stores the credential source and its RP/account binding inside the authenticator.'),
        ...derive(['rpIdHash'], 'authenticator', 'Computes the RP ID hash for the registration authData.'),
        ...create(['flagsUP', 'flagsUV', 'signCount', 'ctapAuthData', 'ctapFmt', 'ctapAttStmt'], 'authenticator', 'Builds the CTAP MakeCredential result, including attested credential data and the chosen attestation statement.'),
        ...transfer(['ctapFmt', 'ctapAuthData', 'ctapAttStmt'], 'authenticator', 'browser', 'CTAP MakeCredential success response members. The browser has not yet constructed a WebAuthn attestationObject.', 'authenticatorMakeCredential response'),
        ...transfer(['ctapCredentialId', 'credentialPublicKey'], 'authenticator', 'browser', 'New credential identifier and public key are nested in the binary registration authData, not top-level WebAuthn fields.', 'authData.attestedCredentialData'),
        ...transfer(['rpIdHash', 'flagsUP', 'flagsUV', 'signCount'], 'authenticator', 'browser', 'Authenticator metadata is nested in CTAP authData.', 'authData'),
      ];
      return [
        ...use(['credentialId', 'userId'], 'authenticator', 'Reads the existing discoverable credential identifier and enrolled account association.'),
        ...create(['ctapCredential', 'ctapUser'], 'authenticator', 'Builds the selected credential descriptor and account entity; user.id supplies the opaque handle in this discoverable-credential example.'),
        ...transfer(['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser'], 'authenticator', 'browser', 'CTAP GetAssertion success response: credential, authData, signature and user. WebAuthn response members are constructed locally afterwards.', 'authenticatorGetAssertion response'),
        ...transfer(['rpIdHash', 'flagsUP', 'flagsUV', 'signCount'], 'authenticator', 'browser', 'Signed metadata is nested in CTAP authData, rather than sent as top-level fields.', 'authData'),
      ];
    }
    case 'assertion-api-conversion':
      return [
        ...use(['ctapCredential', 'ctapAuthData', 'ctapSignature', 'ctapUser'], 'browser', 'Reads the CTAP response received by the local client platform.'),
        ...derive(['credentialId', 'authenticatorData', 'signature', 'userHandle'], 'browser', 'Maps credential.id to WebAuthn rawId/id, authData to response.authenticatorData, signature to response.signature and selected user.id to response.userHandle.'),
        ...create(['credentialType'], 'browser', 'Constructs PublicKeyCredential.type = public-key.'),
        ...use(['clientDataJSON'], 'browser', 'Attaches the original browser-created clientDataJSON to the WebAuthn assertion API result; it did not come from the key.'),
      ];
    case 'registration-api-conversion':
      return [
        ...use(['ctapFmt', 'ctapAuthData', 'ctapAttStmt', 'ctapCredentialId', 'credentialPublicKey'], 'browser', 'Processes the CTAP registration result and extracts its new credential identifier and public-key data.'),
        ...derive(['credentialId', 'authenticatorData'], 'browser', 'Extracts WebAuthn rawId/id from attested credential data and prepares the API authenticator data with required attestation privacy handling.'),
        ...use(['attestation'], 'browser', 'Applies the relying party’s attestation = none policy, removing identifying attestation evidence.'),
        ...create(['credentialType', 'attestationObject'], 'browser', 'Constructs a public-key credential and final CBOR attestationObject with fmt none, anonymized authenticator data and empty attStmt.'),
        ...use(['clientDataJSON'], 'browser', 'Attaches the original browser registration context to the WebAuthn API result.'),
        ...create(['transports'], 'browser', 'Reports optional browser-observed transport hints through response.getTransports(); these are not signed device-type evidence.'),
      ];
    case 'pin-uv':
      return [
        ...use(['pinUvAuthProtocol'], 'authenticator', 'Uses the negotiated local PIN/UV protection protocol to verify protected PIN material. The plaintext PIN is not sent to the key or website.'),
        ...create(['pinUvAuthToken'], 'authenticator', 'Creates a secret PIN/UV authorization token with permitted operations after successful protected PIN verification.'),
        ...transfer(['pinUvAuthToken'], 'authenticator', 'browser', 'Returns the token encrypted under the local PIN/UV protocol. This is a local key-to-client response, never a website-server message.', 'encrypted authenticatorClientPIN response'),
        ...use(['pinUvAuthProtocol'], 'browser', 'Applies the matching local PIN/UV protocol to recover the encrypted authorization token in the trusted client/platform.'),
        ...store(['pinUvAuthToken'], 'browser', 'Retains this local token within the browser/platform authentication component, with its permission and lifetime limits. Page JavaScript and the website server do not receive it.'),
      ];
    case 'get-assertion':
    case 'make-credential': {
      const creating = step.ctapOperation === 'make-credential';
      const command = creating ? 'ctapMakeCredential' : 'ctapGetAssertion';
      const fields = creating
        ? ['rpObject', 'rpId', 'userObject', 'userId', 'userName', 'displayName', 'pubKeyCredParams', 'clientDataHash', 'pinUvAuthParam', 'pinUvAuthProtocol']
        : ['rpId', 'clientDataHash', 'pinUvAuthParam', 'pinUvAuthProtocol'];
      return [
        ...use(['pinUvAuthToken', 'pinUvAuthProtocol', 'clientDataHash'], 'browser', 'Uses the protected local token and selected PIN/UV protocol to authorize this command’s exact client-data hash.'),
        ...derive(['pinUvAuthParam'], 'browser', 'Computes authenticate(pinUvAuthToken, clientDataHash). This tag authorizes the command without sending the token or PIN in the command.'),
        ...(creating ? [
          ...use(['residentKey'], 'browser', 'Reads the WebAuthn authenticatorSelection.residentKey = "required" registration policy.'),
          ...derive(['ctapResidentKey'], 'browser', 'Translates the required discoverable-credential policy into the CTAP2 Boolean options.rk = true for MakeCredential.'),
        ] : []),
        ...use([command], 'browser', creating ? 'Encodes CTAP2 authenticatorMakeCredential (0x01) for the authorized credential creation.' : 'Encodes CTAP2 authenticatorGetAssertion (0x02) for the scoped credential assertion.'),
        ...transfer([command, ...fields], 'browser', 'authenticator', 'Local CTAP2 command over the selected security-key transport. PIN-based UV is proved with pinUvAuthParam; this does not claim the non-biometric key supports a built-in options.uv=true method.'),
        ...(creating ? transfer(['ctapResidentKey'], 'browser', 'authenticator', 'MakeCredential sends the Boolean rk = true in its options map, requiring a discoverable credential.', 'options.rk') : []),
        ...verify(['pinUvAuthParam', 'pinUvAuthProtocol'], 'authenticator', 'Verifies the command authentication tag using its local token and matching protocol, with the required permission/RP binding.'),
        ...(creating ? use(['ctapResidentKey'], 'authenticator', 'Uses options.rk = true to select discoverable-credential creation, requiring compatible capability and storage.') : []),
        ...use([command], 'authenticator', 'Begins the authorized CTAP2 operation and waits for the required user-presence interaction before completing it.'),
      ];
    }
    case 'user-presence':
      return [
        ...use(['localVerification'], 'user', 'Touches the security key to confirm user presence for the pending operation; PIN verification was performed separately.'),
        ...verify(['localVerification'], 'authenticator', 'Checks the required touch/presence before completing the pending sign-in or creation command.'),
        ...inspect(['flagsUP'], 'authenticator', 'Successful touch is later represented by UP = 1 in the returned authenticator data; no flag is sent by the person.'),
      ];
    default:
      return null;
  }
}

function stepOperations(step, authenticator = 'hello') {
  // Protocol extensions may define an exact operation ledger. An empty ledger
  // is authoritative too: it must not fall through to legacy OAuth operations
  // just because an extension reused a familiar source-step ID.
  if (Array.isArray(step.attributeOperations)) return step.attributeOperations.map(action => ({ ...action }));
  const canonical = canonicalStepId(step.id);
  const web = step.clientKind === 'confidential-web' || step.architecture === 'web';
  const external = step.upstreamKind === 'external-oidc' || step.upstream === 'external';
  const single = step.topology === 'single' || step.upstreamKind === 'single-realm';
  let records = (STEP_OPERATIONS[canonical] || []).map(action => ({ ...action }));
  if (!records.length && !STEP_OPERATIONS[canonical]) {
    records = inspect((step.fields || []).filter(id => ATTRIBUTES[id]), step.to,
      'Related glossary context declared by this step. No transport or lifecycle operation has been specified.');
  }
  // Username form fields are distinct from WebAuthn's user.name. The explicit
  // declaration added by the journey variant selects that canonical glossary ID.
  if ((canonical === 'p02' || canonical === 'p03') && step.fields?.includes('loginUsername')) {
    records = records.map(action => action.attributeId === 'userName' ? { ...action, attributeId: 'loginUsername' } : action);
  }
  if (web && canonical === 'l02') {
    records = records.map(action => action.attributeId === 'redirectApp'
      ? { ...action, detail: 'Prepares the registered HTTPS backend callback and retains the authorization-request context on the application server.' }
      : action);
    records.push(...inspect(['clientSecretApp'], 'app', 'The confidential web client secret is configured on the backend. It is not generated per login or exposed in the browser request.'));
  }
  if (web && canonical === 'l20') {
    records = records.map(action => {
      if (action.attributeId === 'redirectApp') return { ...action, detail: 'Uses the registered HTTPS backend callback for this app; the redirect carries code and original state.' };
      if (action.attributeId === 'location') return { ...action, detail: action.kind === 'create' ? 'Constructs the HTTPS backend callback Location URL with code and original state.' : 'HTTP redirect tells the browser to visit the application backend callback.' };
      if (action.carriedAs) return { ...action, detail: 'Carried in the HTTPS backend callback Location URL. The PKCE commitment remains stored in A.' };
      return action;
    });
  }
  if (web && canonical === 'l21') {
    records = records.map(action => ({ ...action, detail: 'Browser follows the registered HTTPS callback and delivers code and state to the application backend.' }));
  }
  if (web && canonical === 'l23') {
    // HTTP Basic authenticates this confidential backend with client_id as its
    // encoded username. Do not also invent a client_id form-body parameter.
    records = records.filter(action => !(action.attributeId === 'clientIdApp' && ['send', 'receive'].includes(action.kind)));
    records = records.map(action => ['send', 'receive'].includes(action.kind)
      ? { ...action, detail: 'Direct confidential-backend token request body carries the code, matching redirect and PKCE verifier. The app client identifier and secret authenticate through HTTP Basic instead of this form body.' }
      : action);
    const authentication = [
      ...use(['clientIdApp', 'clientSecretApp'], 'app', 'Uses the confidential application registration and secret retained only on the backend.'),
      ...derive(['authorizationHeaderApp'], 'app', 'Builds the backend client’s HTTP Basic Authorization header from its app client ID and app client secret.'),
      ...transfer(['authorizationHeaderApp', 'clientSecretApp'], 'app', 'realmA', 'Backend authenticates directly to A using HTTP Basic over HTTPS, in addition to sending its PKCE verifier. The browser never receives this client secret.', 'Authorization: Basic'),
      ...transfer(['clientIdApp'], 'app', 'realmA', 'The application client_id is encoded as HTTP Basic’s username with the backend secret. It is absent from this token request’s form body.', 'Authorization: Basic'),
      ...verify(['authorizationHeaderApp', 'clientIdApp', 'clientSecretApp'], 'realmA', 'Authenticates the registered confidential web application client through its HTTP Basic credentials at A’s token endpoint before accepting the code exchange.'),
    ];
    records = [...records.slice(0, 1), ...authentication, ...records.slice(1)];
  }
  if (web && canonical === 'l25') {
    records.push(
      ...create(['sessionCookieApp'], 'app', 'Creates an application session after validating A’s identity result; OAuth tokens remain on the backend.'),
      ...transfer(['sessionCookieApp'], 'app', 'browser', 'HTTPS backend response sets an application session cookie using its configured secure cookie policy.', 'Set-Cookie'),
      ...store(['sessionCookieApp'], 'browser', 'Stores the application session cookie for permitted later requests to the application. The cookie is not sent to the person.'),
    );
  }
  if (external) {
    records = records.map(action => ({
      ...action,
      detail: action.detail.replace(/\bRealm B\b/g, 'the upstream provider').replace(/\bB’s\b/g, 'the upstream provider’s').replace(/\bB\b/g, 'the upstream provider'),
    }));
  }
  const selectedKey = step.authenticatorKind || step.selectedAuthenticator || authenticator;
  if (selectedKey === 'yubikey') {
    const ctap = ctapOperations(step);
    if (ctap) records = ctap;
    if (step.ctapOperation === 'prepare') {
      records = records.filter(action => action.kind !== 'send' && action.kind !== 'receive');
      const pending = canonical === 'e04' ? ['rpId', 'userId', 'userVerification', 'residentKey'] : ['rpId', 'userVerification'];
      records.push(...use(pending, 'browser', 'Prepares the WebAuthn request and local security-key selection. The authenticated CTAP2 command is sent after the protected PIN verification step.'));
    }
    if ((canonical === 'l10' || canonical === 'e05') && ['pin-input', 'local-pin'].includes(step.ctapOperation)) {
      records = [
        ...use(['localVerification'], 'user', 'Enters the security-key PIN into the trusted local browser/platform prompt. The relying-party website and page JavaScript do not receive it.'),
        ...use(['pinUvAuthProtocol'], 'browser', 'Selects the supported local PIN/UV protocol for protected PIN verification with the security key.'),
        ...verify(['localVerification'], 'authenticator', 'The local PIN/UV exchange checks protected PIN verification material. The plaintext PIN is not sent to the authenticator or the website; touch/presence follows the authorized command.'),
      ];
    }
  } else if (step.ctapOperation && step.ctapOperation !== 'prepare') {
    // Platform authenticators use their OS interface in this teaching model.
    // Never synthesize roaming CTAP commands or a PIN token for Windows Hello.
    records = [];
  }
  if (canonical === 'e06') {
    if (!(selectedKey === 'yubikey' && step.ctapOperation === 'return')) records.push(...create(['transports'], 'browser', 'Reports the authenticator transport hints through response.getTransports() in the registration API result. The list is a routing hint, not signed device-type proof.'));
  }
  if (canonical === 'e07' && step.fields?.includes('transports')) {
    records.push(...transfer(['transports'], 'browser', 'realmB', 'Optional browser-observed transport hints sent with the registration response for later credential discovery.', 'registration response transports hint'));
  }
  if (canonical === 'e08' && step.fields?.includes('transports')) {
    records.push(...store(['transports'], 'realmB', 'Stores the optional credential transport hints for future browser credential discovery, without treating them as signed proof of a device type.'));
  }
  if (single && !step.directFido) {
    if (singleRealmBrokerSteps.has(canonical)) records = [];
    if (canonical === 'l20') records.unshift(
      ...use(['subjectA'], 'realmA', 'Uses the current authenticated account already belonging to Realm A; no upstream broker import or account mapping is performed.'),
      ...create(['session'], 'realmA', 'Completes Realm A’s own configured authentication factors and establishes its local SSO session before issuing the application authorization code.'),
    );
    records = records.map(action => ({
      ...action,
      attributeId: action.attributeId === 'issuerB' ? 'issuerA' : action.attributeId === 'subjectB' ? 'subjectA' : action.attributeId,
      actorId: action.actorId === 'realmB' ? 'realmA' : action.actorId,
      detail: action.detail.replace(/\bRealm B\b/g, 'Realm A').replace(/\bB’s\b/g, 'A’s').replace(/\bB\b/g, 'A').replace(/the upstream provider/g, 'Realm A'),
    })).filter(action => !usageSingleRealmBrokerFields.has(action.attributeId));
  }
  if (step.directFido) {
    const rpActor = step.relyingPartyActor || 'app';
    const ceremonyStep = /^l(08|09|10|11|12|13|14)$/.test(canonical) || /^e0[1-8]$/.test(canonical);
    if (!ceremonyStep && !step.ctapOperation && !step.directSessionCreated) records = [];
    if (canonical === 'l08') records.unshift(...create(['session'], rpActor, 'Creates a pending application-side WebAuthn authentication context for the current fresh challenge. This is not an OAuth/OIDC session.'));
    if (step.directSessionCreated) records = [
      ...use(['challengeLogin'], rpActor, 'Consumes the successfully verified pending WebAuthn challenge so this attempt cannot be accepted again.'),
      ...use(['credentialId', 'userHandle'], rpActor, 'Uses the validated credential/account association to bind the new authenticated application session to the correct account.'),
      ...create(['session'], rpActor, 'Establishes server-side application session state after the direct WebAuthn verification succeeds.'),
      ...create(['sessionCookieApp'], rpActor, 'After directly verifying the WebAuthn assertion with its stored public key, the web application creates its own authenticated session.'),
      ...transfer(['sessionCookieApp'], rpActor, 'browser', 'Application HTTPS response sets an opaque protected session cookie. There is no OAuth authorization code or token exchange in this direct FIDO2 path.', 'Set-Cookie'),
      ...store(['sessionCookieApp'], 'browser', 'Stores the application session cookie for permitted later requests to the application; the user sees only the signed-in UI.'),
    ];
    records = records.filter(action => directFidoFields.has(action.attributeId) && action.actorId !== 'realmA').map(action => ({
      ...action,
      actorId: action.actorId === 'realmB' ? rpActor : action.actorId,
      detail: action.detail.replace(/\bRealm B\b/g, 'the web application').replace(/\bB’s\b/g, 'the web application’s').replace(/\bB\b/g, 'the web application').replace(/\bKeycloak\b/g, 'the web application').replace(/the upstream provider/g, 'the web application'),
    }));
  }
  return records;
}

/** Return the complete operation ledger, preserving explicit extension records
 * and normalizing only the selected-authenticator placeholder. Callers can
 * capture and adapt a reference step without mutating its original operations.
 */
export function getStepAttributeOperations(step, authenticator = 'hello') {
  return stepOperations(step, authenticator).map(action => ({
    ...action,
    actorId: resolveUsageActor(action.actorId, step.authenticatorKind || step.selectedAuthenticator || authenticator),
  }));
}

export function getAttributeIds(idOrTopic) {
  if (Array.isArray(idOrTopic)) return [...new Set(idOrTopic)].filter(id => ATTRIBUTES[id]);
  if (ATTRIBUTE_TOPICS[idOrTopic]) return [...ATTRIBUTE_TOPICS[idOrTopic].attributeIds];
  return ATTRIBUTES[idOrTopic] ? [idOrTopic] : [];
}

export function getAttributeUsage(steps, idOrTopic, authenticator = 'hello') {
  const selected = new Set(getAttributeIds(idOrTopic));
  if (!selected.size || !Array.isArray(steps)) return [];
  return steps.flatMap((step, index) => {
    const explicit = getStepAttributeOperations(step, authenticator);
    // Unknown future steps get context-only records for explicitly declared
    // glossary references, never inferred transports. Current flows are covered.
    const records = explicit.length ? explicit : inspect(
      (step.fields || []).filter(id => ATTRIBUTES[id]), step.to,
      'Related glossary context declared by this step. No transport or lifecycle operation has been specified.',
    );
    const actions = records
      .filter(action => selected.has(action.attributeId) && action.kind !== 'inspect')
      .map(action => ({ ...action }));
    if (!actions.length) return [];
    const fieldIds = [...new Set(actions.map(action => action.attributeId))];
    const wireAttributeIds = fieldIds.filter(id => actions.some(action => action.attributeId === id && action.kind === 'send') && actions.some(action => action.attributeId === id && action.kind === 'receive'));
    return [{ step, index, actions, focusActors: [...new Set(actions.map(action => action.actorId))], fieldIds, wireAttributeIds }];
  });
}

// Expose related context separately so glossary references can be inspected
// without accidentally becoming a replayable message.
export function getAttributeContext(steps, idOrTopic, authenticator = 'hello') {
  const selected = new Set(getAttributeIds(idOrTopic));
  return (Array.isArray(steps) ? steps : []).flatMap((step, index) => {
    const ledger = getStepAttributeOperations(step, authenticator);
    const covered = new Set(ledger.map(action => action.attributeId));
    const undeclaredOperations = [...new Set(step.fields || [])].filter(id => selected.has(id) && ATTRIBUTES[id] && !covered.has(id));
    const actions = [
      ...ledger.filter(action => selected.has(action.attributeId) && action.kind === 'inspect'),
      ...inspect(undeclaredOperations, resolveUsageActor(step.to, step.authenticatorKind || step.selectedAuthenticator || authenticator), 'Related glossary context declared by this step. No transport or lifecycle operation has been specified.'),
    ];
    return actions.length ? [{ step, index, actions }] : [];
  });
}
