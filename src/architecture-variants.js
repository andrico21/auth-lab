import { ACTORS, ATTRIBUTES, EXAMPLE, FLOWS } from './protocol-data.js';
import { applySingleRealm, getSingleRealmActorOverrides, getSingleRealmAttributeOverrides, getSingleRealmExampleOverrides } from './single-realm.js';

// The protocol data remains the reference native + Keycloak scenario. These
// adapters change deployment and upstream provider independently of the factor.
// No example in this module performs authentication or contains a real secret.
export const JOURNEYS = {
  passkey: { title: 'Sign in with a passkey', description: 'The upstream provider checks a proof created by your chosen passkey device.', flow: 'login', passkey: true, factorCount: 'Policy-dependent passkey assurance' },
  password: { title: 'Password only', description: 'The upstream provider checks an account password. No TOTP or passkey is required in this configured scenario.', flow: 'passwordLogin', passkey: false, factorCount: 'One factor: knowledge' },
  'one-time-code': { title: 'One-time code only · TOTP', description: 'Identify the account, then enter a changing authenticator-app code. This explicitly configured passwordless TOTP example uses one possession factor.', flow: 'oneTimeCodeLogin', passkey: false, factorCount: 'One factor: possession', caveat: 'TOTP only is a custom authentication flow for previously enrolled accounts. It is not the default Keycloak browser flow and is not MFA. Username identification must not allow access by itself. Email/SMS codes and recovery codes are different methods.' },
  'password-totp': { title: 'Password + TOTP', description: 'Two upstream checks: an account password followed by a changing authenticator-app code.', flow: 'totpLogin', passkey: false, factorCount: 'Two factors: knowledge + possession' },
  'passkey-totp': { title: 'Passkey + TOTP', description: 'An explicit upstream policy requires a passkey and a separate TOTP code.', flow: 'passkeyTotpLogin', passkey: true, factorCount: 'Explicitly configured additional factor' },
  enrollment: { title: 'Register a passkey', description: 'Start with a verified upstream account. Create a protected credential and store its public key.', flow: 'enrollment', passkey: true, enrollment: true },
  'totp-enrollment': { title: 'Set up TOTP', description: 'Start with a verified upstream account. Provision the shared secret to an authenticator app.', flow: 'totpEnrollment', passkey: false, enrollment: true },
};

export const ARCHITECTURES = {
  native: { title: 'Local native app · loopback callback', label: 'Local native app', callback: EXAMPLE.appCallback, clientKind: 'public-native', description: 'A desktop or CLI application opens the system browser and receives its callback on 127.0.0.1. It uses PKCE and has no embedded client secret.' },
  web: { title: 'Network web app · HTTPS callback', label: 'Network web app', callback: 'https://app.example.test/oidc/callback', clientKind: 'confidential-web', description: 'A server-hosted application redirects the browser, receives an HTTPS callback, exchanges the code with PKCE and confidential client authentication, then creates a browser session. Tokens and the verifier stay on the backend.' },
};

export const UPSTREAMS = {
  single: { title:'Single Keycloak realm',label:'Single Keycloak realm',description:'The application signs in directly through Realm A. This one realm checks the chosen authentication method, enrolls credentials and issues the app’s tokens; no identity brokering is involved.' },
  keycloak: { title: 'Keycloak Realm B', label: 'Another Keycloak realm', description: 'Realm A brokers to another realm of the same product. B can be on the same Keycloak deployment or on a separate Keycloak server; the example uses separate hosts.' },
  external: { title: 'Independent external OIDC provider', label: 'External OIDC provider', description: 'Realm A brokers to a different identity-provider product via standard OIDC. This generic example assumes that provider supports and has configured the chosen sign-in method. Its login forms, policies and credential storage are provider-specific.' },
};

const variantsOAuth = 'https://www.rfc-editor.org/rfc/rfc6749';
const variantsOidc = 'https://openid.net/specs/openid-connect-core-1_0.html';
const variantsKeycloak = 'https://www.keycloak.org/docs/latest/server_admin/index.html';
const variantsAttribute = (name, meaning, origin, purpose, example, standard, source) => ({ name, meaning, description: meaning, origin, generator: origin, purpose, example, standard, source });

export const VARIANT_ATTRIBUTES = {
  password: { ...ATTRIBUTES.password, purpose:'Provides the knowledge factor when the configured upstream flow requires an account password. It is neither the confidential client secret nor the OAuth resource-owner password grant.' },
  clientSecretApp: variantsAttribute('client_secret (web backend)', 'The registered confidential credential of the server-hosted application, separate from A’s upstream broker credential.', 'Provisioned for the web-app client in Realm A and stored only in the application backend.', 'Authenticates the backend’s token request to A. This example carries it using HTTP Basic, alongside PKCE.', 'web-backend secret; never sent to the browser', 'RFC 6749 §2.3.1 and §10.1', variantsOAuth),
  authorizationHeaderApp: variantsAttribute('Authorization (web backend → A)', 'The HTTP request header authenticating the web backend at A’s token endpoint.', 'The backend encodes its registered client ID and secret according to HTTP Basic client authentication.', 'Identifies the confidential application. PKCE additionally binds this code exchange to the original request.', 'Basic base64(encoded-web-app:encoded-backend-secret)', 'RFC 6749 §2.3.1', variantsOAuth),
  sessionCookieApp: variantsAttribute('Set-Cookie / Cookie (application session)', 'An opaque browser session handle for the web application, distinct from an OIDC ID token.', 'After validating A’s ID token, the backend creates server-side session state and sends a protected cookie to the browser.', 'Lets later browser requests refer to the authenticated backend session while the OIDC tokens stay server-side. The browser stores the cookie; the person sees the signed-in page.', '__Host-app_session=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/', 'RFC 6265 + current browser cookie attributes; application-specific session policy', 'https://www.rfc-editor.org/rfc/rfc6265'),
  loginUsername: variantsAttribute('username (login form field)', 'A readable account identifier typed into an upstream sign-in form; different from WebAuthn’s user.name registration member.', 'Chosen or provisioned during account creation, then entered by the person.', 'Lets the upstream resolve the account whose password or enrolled TOTP secret it will verify. A username alone does not authenticate the person.', 'alice', 'Keycloak/provider browser form; not an OAuth/OIDC parameter', variantsKeycloak),
};

const variantsExternal = {
  issuer: 'https://login.partner.example.test',
  authorizationEndpoint: 'https://login.partner.example.test/oauth2/authorize',
  tokenEndpoint: 'https://login.partner.example.test/oauth2/token',
  jwksUri: 'https://login.partner.example.test/oauth2/jwks',
  origin: 'https://login.partner.example.test', rpId: 'login.partner.example.test',
  callback: 'https://idp1.example.test/realms/realm-a/broker/external-idp/endpoint',
  code: 'c_external_83ab', subject: 'external-user-913',
};
const variantsWebClient = 'web-app';
const variantsWebCallback = ARCHITECTURES.web.callback;
const variantsCanonicalStep = id => String(id).match(/(?:^|-)([a-z]\d{2})$/)?.[1] || id;
const variantsClone = (item, prefix) => ({ ...item, id: prefix ? prefix + '-' + item.id : item.id, fields: [...item.fields], payload: item.payload.map(p => ({ ...p })), checks: [...item.checks] });
const variantsPayload = (name, value, description) => ({ name, value, ...(description ? { description } : {}) });
const variantsStep = (id, title, from, to, phase, channel, summary, detail, fields, payload, checks = []) => ({ id, title, from, to, phase, channel, summary, detail, fields, payload, checks });

function variantsPasswordOnly() {
  const start = FLOWS.login.slice(0, 7).map(s => variantsClone(s, 'password'));
  start[6].detail = 'B validates the broker client and allowed callback, then starts the configured password-only browser flow. This scenario requires no OTP execution; existing-session and account-policy actions are outside this fresh-login demonstration.';
  const password = FLOWS.totpLogin.filter(s => /^p0[123]$/.test(s.id)).map(s => variantsClone(s, 'password'));
  password[0].detail = 'B displays its username/password login form. A verifies the eventual OIDC result; the application still uses Authorization Code + PKCE, not the resource-owner password grant.';
  password[1].detail = 'The person enters the upstream account username and password on B’s HTTPS page. Neither Realm A nor the application receives this account password.';
  password[2].detail = 'B resolves the account and verifies the password with its configured credential provider and protected hash record, applying its attempt-limit policy. In this specifically configured password-only flow, that successful check satisfies the required authentication method. B can now issue its OIDC authorization response.';
  for (const item of password) item.fields = item.fields.map(id => id === 'userName' ? 'loginUsername' : id);
  const finish = FLOWS.login.slice(14).map(s => variantsClone(s, 'password'));
  finish[3].detail = 'B validates the code and confidential broker client and returns an ID token signed by its provider key, plus an access token. The token describes the authenticated B account. The account password is not included in the token response.';
  finish[9].detail = 'A issues its own ID token and access token for the application. B’s ID token and the account password are not forwarded as the application login result. A refresh token is optional according to A’s policy.';
  finish[10].detail = 'The app validates A’s ID-token signature, exact issuer, audience, expiry and original nonce using A’s trusted public keys. Its accepted identity is (iss A, sub user-in-A-204). Password-only authentication does not provide MFA assurance.';
  finish[4].payload = finish[4].payload.filter(p => p.name !== 'Passkey re-check in A');
  return [...start, ...password, ...finish];
}

function variantsOtpOnly() {
  const start = FLOWS.login.slice(0, 7).map(s => variantsClone(s, 'otp'));
  start[6].detail = 'B validates the broker registration and callback, then starts an explicitly configured passwordless TOTP flow. The account must already have an enrolled TOTP credential; a fresh sign-in must not allow an unverified user to enroll a new secret instead of proving possession of the existing one. Username entry identifies the account, and required OTP validation authenticates it. This is one factor, not MFA, and is not Keycloak’s default browser flow.';
  const identity = [
    variantsStep('otp-u01', 'Identify the account first', 'realmB', 'browser', 'otp', 'https',
      'B asks which account owns the enrolled TOTP credential.',
      'A username-only identification form resolves the account before the OTP verifier runs. It does not request a password and it must not authenticate the account by itself. In Keycloak, this teaching configuration uses a Username Form followed by a required OTP execution with previously enrolled credentials.',
      ['loginUsername', 'session'], [variantsPayload('HTTPS response', 'Username-only identification form')]),
    variantsStep('otp-u02', 'Enter the account name', 'user', 'browser', 'otp', 'local',
      'The person enters the account name, without a password.',
      'This identifier selects the enrolled credential that B should validate. Knowing the username is not proof of identity; the current TOTP code will provide the possession proof.',
      ['loginUsername'], [variantsPayload('username', 'alice', 'A login-form field, not an OAuth request parameter.')]),
    variantsStep('otp-u03', 'Resolve the account in B', 'browser', 'realmB', 'otp', 'https',
      'The browser sends the identifier to B’s pending sign-in action.',
      'B resolves the account, preserves the pending authentication session, and checks that an enrolled TOTP credential exists. Sign-in is still incomplete. Do not provide unauthenticated OTP enrollment as a fallback for this single-factor flow.',
      ['loginUsername', 'session'], [variantsPayload('HTTP', 'POST current Realm B login action'), variantsPayload('username', 'alice')], ['Account identified, not yet authenticated', 'Previously enrolled TOTP credential required']),
  ];
  const otp = FLOWS.totpLogin.filter(s => /^m0[1-5]$/.test(s.id)).map(s => variantsClone(s, 'otp'));
  otp[0].title = 'Request the one-time sign-in code';
  otp[0].detail = 'B requires the current code from the account’s already enrolled TOTP app. This is the only authentication factor in this explicitly configured passwordless flow. Username entry identifies the account but does not count as a factor. The browser authentication session stays pending until the OTP is verified.';
  otp[4].title = 'Validate the one-time sign-in code';
  otp[4].summary = 'B checks the enrolled secret, current time window and replay protection.';
  otp[4].detail = 'B recomputes TOTP candidates from the account’s stored shared secret and matching settings, applies its limited drift window, attempt protection and replay policy, then completes this single-factor authentication. A wrong or missing code must reject sign-in; a new unauthenticated enrollment must not replace the possession check.';
  for (const item of otp) { item.phase = 'otp'; item.factorKind = 'single-factor-totp'; }
  const finish = FLOWS.login.slice(14).map(s => variantsClone(s, 'otp'));
  finish[3].detail = 'B validates the code and confidential broker client and returns its provider-signed ID token plus an access token. Neither the TOTP secret nor the typed code is part of this OIDC identity result.';
  finish[9].detail = 'A issues its own ID token and access token for the application. B’s ID token, TOTP secret and typed OTP are not forwarded as the application login result. A refresh token is optional according to A’s policy.';
  finish[10].detail = 'The app validates A’s ID-token signature, issuer, audience, expiry and original nonce. This mode demonstrates one possession factor. It does not establish MFA, nor prove an agreed assurance class unless deployment policy and validated claims define it.';
  finish[4].payload = finish[4].payload.filter(p => p.name !== 'Passkey re-check in A');
  return [...start, ...identity, ...otp, ...finish];
}

const variantsNewJourneys = { password: variantsPasswordOnly(), 'one-time-code': variantsOtpOnly(),
  'password-totp':FLOWS.totpLogin.map(item => { const copy=variantsClone(item);if (/^p0[23]$/.test(copy.id)) copy.fields=copy.fields.map(id=>id==='userName'?'loginUsername':id);return copy; }) };
for (const steps of Object.values(variantsNewJourneys)) for (const item of steps) { item.architecture='native';item.upstream='keycloak';item.clientKind='public-native';item.upstreamKind='keycloak-realm'; }
const variantsJourneyCache = new Map();

function variantsWebText(text) {
  return String(text).replaceAll(EXAMPLE.appCallback, variantsWebCallback)
    .replaceAll(EXAMPLE.clientApp, variantsWebClient)
    .replaceAll('the native application', 'the web backend')
    .replaceAll('the native app', 'the web backend')
    .replaceAll('native app', 'web backend')
    .replaceAll('the local app', 'the web backend');
}

function variantsWebJourney(steps, enrollment) {
  const result = steps.map(item => {
    const clone = variantsClone(item, 'web');
    clone.architecture = 'web'; clone.clientKind = 'confidential-web';
    for (const key of ['title', 'summary', 'detail']) clone[key] = variantsWebText(clone[key]);
    clone.checks = clone.checks.map(variantsWebText);
    clone.payload = clone.payload.map(p => ({ ...p, value: variantsWebText(p.value), ...(p.description ? { description: variantsWebText(p.description) } : {}) }));
    if (clone.attributeValues) clone.attributeValues = Object.fromEntries(Object.entries(clone.attributeValues).map(([id,value]) => [id, typeof value === 'string' ? variantsWebText(value) : value]));
    if (enrollment) return clone;
    switch (variantsCanonicalStep(clone.id)) {
      case 'l01':
        Object.assign(clone, { title: 'Start sign-in on the web app', from: 'user', to: 'browser', channel: 'local', fields: [], summary: 'The person opens the network application and chooses Sign in.', detail: 'The application is hosted at https://app.example.test. Its UI runs in the browser; its confidential OIDC client and token storage run on the server.', payload: [variantsPayload('Browser UI action', 'Sign in at https://app.example.test')] });
        break;
      case 'l02':
        Object.assign(clone, { title: 'Prepare the request on the backend', summary: 'The backend creates state, nonce and the PKCE verifier, then derives the challenge.', detail: 'The web backend keeps state, nonce and code_verifier in its pending server-side login context, associated with the initiating browser session. It computes BASE64URL(SHA256(ASCII(code_verifier))) without padding. The callback is a registered HTTPS endpoint on this backend. The confidential client secret is configured separately and is never exposed to browser JavaScript.', fields: ['redirectApp','stateApp','nonceApp','codeVerifier','codeChallenge','codeChallengeMethod','clientSecretApp'], payload: [variantsPayload('redirect_uri', variantsWebCallback), variantsPayload('state', EXAMPLE.stateApp), variantsPayload('nonce', EXAMPLE.nonceApp), variantsPayload('code_verifier', EXAMPLE.verifier, 'Stored on the backend; absent from the authorization URL.'), variantsPayload('code_challenge', EXAMPLE.challenge), variantsPayload('code_challenge_method', 'S256')] });
        break;
      case 'l03':
        Object.assign(clone, { title: 'Redirect the browser to Realm A', channel: 'redirect', summary: 'The backend sends an HTTP redirect to A’s authorization endpoint.', detail: 'An HTTP 302 Location carries the public authorization parameters to A via the browser. The backend neither launches an operating-system browser nor opens a localhost listener. The PKCE verifier and client secret remain on the backend.', payload: [variantsPayload('HTTP','302 Found'), variantsPayload('Location',EXAMPLE.authA), ...clone.payload.filter(p => p.name !== 'URL')] });
        break;
      case 'l04':
        clone.detail = 'A validates the registered confidential web client, its exact allowed HTTPS redirect_uri, requested scopes and S256 PKCE parameters. A creates its authentication session and the configured redirector selects the upstream provider. The application’s backend secret is not present on this browser authorization request.';
        clone.checks = ['Known confidential web client','Allowed HTTPS callback','S256 PKCE present'];
        break;
      case 'l20':
        clone.title = 'Issue A’s code for the web backend';
        clone.summary = 'A redirects the browser to the application’s HTTPS callback.';
        clone.detail = 'A issues a new code for web-app, bound to its original PKCE challenge, and returns the original app state. The browser receives a redirect to https://app.example.test/oidc/callback. This is a separate authorization code from the upstream broker code.';
        break;
      case 'l21':
        Object.assign(clone, { title: 'Reach the HTTPS callback', channel: 'https', summary: 'The browser delivers code and state to the web backend over the network.', detail: 'The browser follows the HTTPS redirect to app.example.test/oidc/callback. The callback is handled on the application server; 127.0.0.1 and a local listener are not involved. Keycloak sends the redirect to the browser, and the browser makes this request.', payload: [variantsPayload('HTTP','GET '+variantsWebCallback), variantsPayload('code',EXAMPLE.codeA), variantsPayload('state',EXAMPLE.stateApp)] });
        break;
      case 'l22':
        clone.title = 'Check the backend callback';
        clone.summary = 'The backend matches the callback to its pending sign-in context.';
        clone.detail = 'The backend compares returned state with the pending server-side value bound to this browser login context, checks the expected redirect and handles errors. It obtains the matching stored PKCE verifier. A browser callback alone is not yet a validated identity.';
        break;
      case 'l23':
        Object.assign(clone, { title: 'Redeem the code from the backend', summary: 'The backend sends A the code, PKCE verifier and its confidential client authentication.', detail: 'The backend makes an HTTPS POST to A’s token endpoint. It authenticates using HTTP Basic with its registered web-app client ID and backend-only client secret, and sends grant_type, code, identical redirect_uri and code_verifier. A authenticates the confidential client, recomputes S256 and compares the result to the stored challenge bound to the code. PKCE and client authentication are distinct checks. Neither secret passes through the browser.', fields: ['clientIdApp','grantType','codeA','redirectApp','codeVerifier','codeChallenge','clientSecretApp','authorizationHeaderApp'], payload: [variantsPayload('HTTP','POST token_endpoint A'), variantsPayload('Authorization','Basic base64(encoded-web-app:encoded-backend-secret)'), variantsPayload('grant_type','authorization_code'), variantsPayload('code',EXAMPLE.codeA), variantsPayload('redirect_uri',variantsWebCallback), variantsPayload('code_verifier',EXAMPLE.verifier)], checks: ['Confidential web client authenticated','Single-use code bound to client and HTTPS redirect','S256 verifier matches original challenge'] });
        break;
      case 'l24':
        clone.title = 'Return tokens to the web backend';
        clone.summary = 'A sends the application’s tokens directly to its server.';
        clone.detail = 'A issues its own ID token for web-app and its own access token, with an optional refresh token according to policy. These tokens are delivered to the confidential backend over HTTPS and stored there. They are not placed in the browser redirect or application session cookie.';
        break;
      case 'l25':
        Object.assign(clone, { title: 'Validate identity and create a browser session', from: 'app', to: 'browser', channel: 'https', summary: 'The backend checks A’s ID token and returns a signed-in page with a session cookie.', detail: 'The backend validates A’s token signature using trusted keys, exact issuer, audience web-app, expiry and original nonce, with the remaining required OIDC checks. It creates server-side application session state and sends a protected opaque session cookie. The cookie is not an ID token and does not contain the backend PKCE verifier or client secret. Subsequent browser requests send Cookie to this application according to browser cookie policy. Authentication assurance still depends on the configured upstream flow and validated claim semantics.', fields: ['idTokenA','jwksUri','issuerA','audience','exp','iat','nonceApp','subjectA','acr','amr','sessionCookieApp'], payload: [variantsPayload('Validated identity','Realm A / user-in-A-204'), variantsPayload('Set-Cookie','__Host-app_session=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/'), variantsPayload('HTTPS response','Signed-in application page')], checks: ['A signature and exact issuer valid','ID-token audience contains web-app','Expiry and original app nonce valid','Protected server-side application session created'] });
        break;
    }
    return clone;
  });
  if (!enrollment) {
    result.splice(1, 0, { ...variantsStep('web-w00','Request sign-in from the backend','browser','app','prepare','https','The browser asks the hosted application to begin sign-in.','The browser makes a normal HTTPS request to the application’s sign-in endpoint. The backend will construct the OIDC authorization request and keep its secrets on the server.',[],[variantsPayload('HTTP','GET https://app.example.test/login')]), architecture:'web',clientKind:'confidential-web' });
    result.push({ ...variantsStep('web-w01','Show the signed-in application','browser','user','complete','local','The person sees the signed-in web application.','The browser renders the backend’s response. The browser stores the application session cookie; it does not pass the OIDC tokens, verifier, backend secret or cookie value to the person as part of this UI step.',[],[variantsPayload('Browser UI','Signed in at app.example.test')]), architecture:'web',clientKind:'confidential-web' });
  }
  return result;
}

function variantsExternalText(text) {
  return String(text)
    .replaceAll(EXAMPLE.authB, variantsExternal.authorizationEndpoint).replaceAll(EXAMPLE.tokenB, variantsExternal.tokenEndpoint)
    .replaceAll(EXAMPLE.issuerB, variantsExternal.issuer).replaceAll(EXAMPLE.brokerCallback, variantsExternal.callback)
    .replaceAll(EXAMPLE.origin, variantsExternal.origin).replaceAll(EXAMPLE.rpId, variantsExternal.rpId)
    .replaceAll(EXAMPLE.codeB, variantsExternal.code).replaceAll('user-in-B-913', variantsExternal.subject)
    .replaceAll('opaque-user-B-bytes', 'opaque-external-user-bytes')
    .replaceAll('Keycloak Realm B', 'External OIDC provider').replaceAll('Realm%20B', 'External%20IdP').replaceAll('Realm B', 'the external IdP')
    .replaceAll('B-issued', 'Upstream-issued').replaceAll('B’s', 'the upstream’s').replaceAll("B's", 'the upstream’s')
    .replace(/\bB\b/g, 'the upstream IdP');
}

function variantsExternalJourney(steps) {
  return steps.map(item => {
    const clone = variantsClone(item, 'external');
    clone.upstream = 'external'; clone.upstreamKind = 'external-oidc';
    for (const key of ['title','summary','detail']) clone[key] = variantsExternalText(clone[key]);
    clone.checks = clone.checks.map(variantsExternalText);
    clone.payload = clone.payload.map(p => ({ ...p, value: variantsExternalText(p.value), ...(p.description ? { description: variantsExternalText(p.description) } : {}) }));
    if (clone.from === 'realmB' || clone.to === 'realmB' || clone.fields.some(id => ['password','otpCode','otpSecret'].includes(id))) {
      clone.detail = clone.detail.replaceAll('Keycloak', 'the upstream provider').replaceAll('realm’s OTP policy', 'provider’s OTP policy').replaceAll('realm signing key', 'provider signing key');
      clone.payload = clone.payload.map(p => ({ ...p, ...(p.description ? { description: p.description.replaceAll('Keycloak', 'Illustrative upstream provider') } : {}) }));
    }
    const canonical = variantsCanonicalStep(clone.id);
    if (canonical === 'l19') clone.attributeValues = { ...clone.attributeValues, jwksUri: variantsExternal.jwksUri };
    if (canonical === 'l07') clone.detail += ' The external provider is an independent OIDC product, not another Keycloak realm. Its support for this chosen login method and its configuration are prerequisites of the teaching example.';
    if (canonical === 'e01') clone.detail = 'Enrollment begins with an already verified account/session at the external provider. Its provider-specific account page or enrollment action initiates this separate WebAuthn ceremony. Initial identity verification, account recovery and vendor UI are outside this diagram.';
    if (canonical === 't02') clone.detail = 'The external provider verifies the account’s authenticated session and enrollment authorization, then prepares its configured OTP algorithm, digit count and time step. Its account-console and setup actions are provider-specific; this is not a Keycloak Configure OTP required action.';
    if (canonical === 'u01') clone.detail = 'The external provider’s username-only identification page resolves the account before its required OTP verifier runs. A username must not authenticate the account by itself. This illustrative provider is assumed to support an explicitly configured passwordless TOTP flow for previously enrolled credentials.';
    if (canonical === 'l18') clone.detail = 'The independent upstream provider validates the authorization code and broker client, then returns an ID token signed by its own provider key plus an access token. The issuer is https://login.partner.example.test, the audience is realm-a-broker and nonce is A’s broker nonce. Passwords, typed OTP codes, shared OTP secrets and passkey private keys are not the OIDC identity result.';
    if (canonical === 'l05') clone.detail += ' In A, the external-idp broker alias is configured with this provider’s OIDC discovery/authorization/token endpoints, exact issuer and trusted verification keys.';
    return clone;
  });
}

export function getJourneySteps(mode, architecture = 'native', upstream = 'keycloak') {
  const selectedMode = JOURNEYS[mode] ? mode : 'passkey';
  const selectedArchitecture = ARCHITECTURES[architecture] ? architecture : 'native';
  const selectedUpstream = UPSTREAMS[upstream] ? upstream : 'keycloak';
  const base = variantsNewJourneys[selectedMode] || FLOWS[JOURNEYS[selectedMode].flow];
  if (selectedArchitecture === 'native' && selectedUpstream === 'keycloak') return base;
  const key = selectedMode + ':' + selectedArchitecture + ':' + selectedUpstream;
  if (!variantsJourneyCache.has(key)) {
    let steps = selectedArchitecture === 'web' ? variantsWebJourney(base, !!JOURNEYS[selectedMode].enrollment) : base.map(s => variantsClone(s));
    if (selectedUpstream === 'external') steps = variantsExternalJourney(steps);
    if (selectedUpstream === 'single') steps = applySingleRealm(steps,selectedMode);
    for (const item of steps) {
      item.architecture = selectedArchitecture; item.upstream = selectedUpstream;
      item.clientKind = ARCHITECTURES[selectedArchitecture].clientKind;
      item.upstreamKind = selectedUpstream === 'single' ? 'single-realm' : selectedUpstream === 'external' ? 'external-oidc' : 'keycloak-realm';
    }
    variantsJourneyCache.set(key, steps);
  }
  return variantsJourneyCache.get(key);
}

const variantsActorCache = new Map();
export function getActorOverrides(architecture = 'native', upstream = 'keycloak') {
  const cacheKey=architecture+':'+upstream;
  if (variantsActorCache.has(cacheKey)) return variantsActorCache.get(cacheKey);
  const actors = {};
  if (architecture === 'web') {
    actors.app = { ...ACTORS.app, name:'Web application',role:'Confidential server-side OIDC client',plainRole:'A network backend receives the HTTPS callback, keeps tokens and creates your web session.',
      attributes:[...ACTORS.app.attributes,{id:'clientSecretApp',kind:'static'},{id:'authorizationHeaderApp',kind:'generated'},{id:'sessionCookieApp',kind:'generated'}],
      notes:['HTTPS callback on app.example.test; the browser calls this network backend.','Generates and retains the PKCE verifier, state and nonce on the server.','Uses PKCE plus separate confidential client authentication at A’s token endpoint.','Keeps OIDC tokens on the backend and sends an opaque application session cookie to the browser.'] };
    actors.browser = { ...ACTORS.browser, role:'Browser UI / user-agent / WebAuthn client', attributes:[...ACTORS.browser.attributes,{id:'sessionCookieApp',kind:'received'}], notes:['Displays the network application and follows HTTPS redirects.','WebAuthn still executes on the upstream provider’s HTTPS origin.','Receives the web application session cookie, not its PKCE verifier, backend client secret or OIDC tokens.'] };
  }
  if (upstream === 'external') {
    actors.realmB = { ...ACTORS.realmB,name:'External OIDC IdP',role:'Independent OIDC provider + selected factor verifier',plainRole:'A different identity-provider product checks the chosen method and returns its OIDC result.',notes:['This provider is independent of Keycloak and has its own issuer, keys, accounts and sessions.','The chosen password, TOTP or WebAuthn method must be supported and configured by this provider.','Realm A trusts the validated OIDC result; provider-specific authentication forms are outside the OIDC standard.','For passkeys, the RP ID is login.partner.example.test and the browser origin is https://login.partner.example.test.'] };
    actors.realmA = { ...ACTORS.realmA,notes:['Keycloak Realm A acts as the confidential OIDC broker client of an independent external provider.','The external-idp alias defines the HTTPS broker callback registered at that provider.','Validates the upstream issuer, audience, nonce and signature, then maps the external account to A.','Issues its own A tokens to the application; it does not re-check the upstream WebAuthn signature.'] };
    const browser = actors.browser || ACTORS.browser;
    actors.browser = { ...browser,notes:browser.notes.map(variantsExternalText) };
  }
  if(upstream==='single')for(const [id,override]of Object.entries(getSingleRealmActorOverrides(architecture)))actors[id]={...(actors[id]||ACTORS[id]),...override};
  variantsActorCache.set(cacheKey,actors);
  return actors;
}

const variantsExampleCache = new Map();
export function getExampleOverrides(architecture = 'native', upstream = 'keycloak') {
  const cacheKey=architecture+':'+upstream;
  if (variantsExampleCache.has(cacheKey)) return variantsExampleCache.get(cacheKey);
  const examples = {};
  if (architecture === 'web') Object.assign(examples,{ clientIdApp:variantsWebClient,redirectApp:variantsWebCallback,audience:'ID token A: web-app; ID token upstream: realm-a-broker',idTokenA:'JWT: iss=A, aud=web-app, sub=user-in-A, nonce=n_app_a92c' });
  if (upstream === 'external') Object.assign(examples,{ issuerB:variantsExternal.issuer,redirectBroker:variantsExternal.callback,rpId:variantsExternal.rpId,origin:variantsExternal.origin,rpName:'External OIDC provider',rpObject:'{ id: "login.partner.example.test", name: "External OIDC provider" }',rpIdHash:'SHA256("login.partner.example.test")',codeB:variantsExternal.code,subjectB:variantsExternal.subject,userId:'opaque-external-user-bytes',userHandle:'opaque-external-user-bytes',idTokenB:'JWT: iss=https://login.partner.example.test, aud=realm-a-broker, sub=external-user-913, nonce=n_broker_f19d',otpWindow:'Provider-configured limited clock-drift window',otpReplay:'Provider must reject already successfully used OTP time steps' });
  if(upstream==='single')Object.assign(examples,getSingleRealmExampleOverrides(architecture));
  variantsExampleCache.set(cacheKey,examples);
  return examples;
}

const variantsDefinitionCache = new Map();
export function getAttributeOverrides(architecture = 'native', upstream = 'keycloak') {
  const cacheKey=architecture+':'+upstream;
  if (variantsDefinitionCache.has(cacheKey)) return variantsDefinitionCache.get(cacheKey);
  const overrides = {};
  if (architecture === 'web') {
    const updates = {
      clientIdApp:{meaning:'The public registration identifier of the confidential web backend.',origin:'Registered for the server-hosted web application in Realm A.',purpose:'Tells A which web client requests sign-in; the identifier itself is not a secret.'},
      redirectApp:{meaning:'The registered HTTPS callback handled by the application backend.',origin:'Configured on the web server and registered as an allowed redirect in Realm A.',purpose:'Lets the browser deliver A’s authorization code and state to the network backend.',standard:'RFC 6749 §3.1.2 / §4.1.1',source:variantsOAuth},
      stateApp:{origin:'Generated by the web backend and kept in a pending server-side login context associated with the browser session.',purpose:'The backend compares the returned value before accepting this browser callback.'},
      nonceApp:{origin:'Generated and retained by the web backend for its OIDC request.',purpose:'The backend checks A’s ID token contains the original nonce for this login.'},
      codeVerifier:{origin:'Generated and retained on the web backend before its authorization redirect.',purpose:'A validates this secret during backend code exchange to bind redemption to the original PKCE request.'},
      codeChallenge:{origin:'The web backend computes BASE64URL(SHA256(ASCII(code_verifier))) without padding.',purpose:'A stores this public commitment from the browser request and compares it with the received verifier at code redemption.'},
      idTokenA:{purpose:'The backend validates it to establish the user, then creates an application session. Its audience is web-app.'},
      accessTokenA:{purpose:'The backend may use it for an appropriate API. This teaching application keeps it on the server.'},
      tokenEndpoint:{purpose:'The web backend and Realm A’s broker call their own configured token endpoints directly over HTTPS.'},
    };
    for (const [id, update] of Object.entries(updates)) overrides[id] = { ...ATTRIBUTES[id],...update,...(update.meaning ? {description:update.meaning} : {}),...(update.origin ? {generator:update.origin} : {}) };
  }
  if (upstream === 'external') {
    for (const [id, base] of Object.entries({ ...ATTRIBUTES,...VARIANT_ATTRIBUTES,...overrides })) {
      const updated = { ...base };
      for (const key of ['meaning','description','origin','generator','purpose','example']) updated[key] = variantsExternalText(updated[key]);
      if (id === 'realmSigningKey') { updated.name = 'provider / realm signing key (private)'; updated.origin = 'Retained by each issuer: Keycloak Realm A and the independent upstream provider.';updated.generator=updated.origin;updated.standard='OIDC Core §2';updated.source=variantsOidc; }
      if (id === 'passwordHash') { updated.origin='Created by the external provider’s configured password verifier during account password setup.';updated.generator=updated.origin;updated.standard='Provider-specific password credential storage';updated.source=variantsOidc; }
      if (['password','otpCode','loginUsername'].includes(id)) updated.standard = 'Provider-specific browser form; TOTP algorithm is RFC 6238 where applicable';
      if (id === 'otpWindow') updated.purpose='Allows limited clock drift under the external provider’s configured verification policy; a display period is not the whole acceptance window.';
      if (id === 'otpReplay') updated.purpose='A conforming one-time verifier rejects a second successful use of the same OTP; enforcement is specific to the external provider implementation.';
      overrides[id] = updated;
    }
  }
  if(upstream==='single')Object.assign(overrides,getSingleRealmAttributeOverrides(architecture,{...ATTRIBUTES,...VARIANT_ATTRIBUTES,...overrides}));
  for (const [id,example] of Object.entries(getExampleOverrides(architecture,upstream))) overrides[id] = { ...(overrides[id] || ATTRIBUTES[id] || VARIANT_ATTRIBUTES[id]),example };
  variantsDefinitionCache.set(cacheKey,overrides);
  return overrides;
}
