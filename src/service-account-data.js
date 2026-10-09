// OAuth client-credentials teaching model: symbolic credentials, no real network.
// This grant authenticates a confidential application. No person signs in.

const serviceOAuthSource = 'https://www.rfc-editor.org/rfc/rfc6749';
const serviceJwtSource = 'https://www.rfc-editor.org/rfc/rfc7519';
const serviceJwsSource = 'https://www.rfc-editor.org/rfc/rfc7515';
const serviceKeycloakSource = 'https://www.keycloak.org/docs/latest/server_admin/index.html';
const serviceAttribute = (name, meaning, origin, purpose, example, standard, source) => ({ name, meaning, description: meaning, origin, generator: origin, purpose, example, standard, source });

export const SERVICE_ATTRIBUTES = {
  serviceClientAuthentication: serviceAttribute('Client authentication (Keycloak setting)', 'The client-registration capability requiring the service to authenticate itself.', 'An administrator enables Client authentication for the OIDC client in Realm A.', 'Makes this a confidential client eligible for the illustrated client_credentials grant. It is an administrative setting, not an OAuth request parameter.', 'On', 'Keycloak · OIDC client capabilities / RFC 6749 §4.4', serviceKeycloakSource),
  serviceAccountEnabled: serviceAttribute('Service account roles (Keycloak setting)', 'The client-registration capability allowing this application to obtain its own access token.', 'An administrator enables Service account roles on the confidential client.', 'Allows the client_credentials grant to use the client’s service-account identity. No end-user password or MFA ceremony is involved.', 'Enabled', 'Keycloak · Using a service account', serviceKeycloakSource),
  serviceAssignedRoles: serviceAttribute('Service account roles (local configuration)', 'Roles assigned to the account representing this client.', 'An administrator assigns roles to the client’s built-in service account in Realm A.', 'Forms one side of the role intersection used when constructing the service’s access token. These configuration records remain inside Keycloak.', 'orders-api: read, write', 'Keycloak · Service account roles', serviceKeycloakSource),
  serviceRoleScopeMappings: serviceAttribute('Role scope mappings (local configuration)', 'The roles this client and its applied client scopes allow into tokens.', 'An administrator explicitly configures client role scope mappings, including mappings inherited from linked client scopes.', 'Forms the other side of the service-account role intersection. This local configuration is different from the OAuth scope string.', 'orders-api: read', 'Keycloak · Role mappings in the token', serviceKeycloakSource),
  serviceEffectiveRoles: serviceAttribute('Effective roles (local result)', 'The permitted roles remaining after service-account assignments are intersected with client role scope mappings.', 'Realm A resolves the service-account role assignments and the applied client/client-scope role mappings.', 'Feeds the configured role protocol mappers. It prevents an assigned role outside the client’s permitted scope from appearing in this illustrated token.', 'orders-api: read; write excluded', 'Keycloak · Using a service account', serviceKeycloakSource),
  serviceAccessIssuer: serviceAttribute('iss', 'The issuer identifier inside this service-account access token.', 'Realm A inserts its configured issuer identifier when building the JWT access token.', 'Identifies the authorization server for a resource server’s later token validation. This is an access-token claim, not an OIDC ID-token login result.', 'https://idp1.example.test/realms/realm-a', 'RFC 7519 §4.1.1', serviceJwtSource),
  serviceAccessSubject: serviceAttribute('sub', 'The subject identifier of the Keycloak service-account identity.', 'Keycloak assigns an internal identity to the client’s built-in service account and maps its subject into the access token.', 'Identifies the service account; it does not name a person or promise a user authentication event.', 'service-account-id-204 (symbolic)', 'RFC 7519 §4.1.2 / Keycloak service account', serviceJwtSource),
  serviceAccessAudience: serviceAttribute('aud', 'The intended resource-server recipient of the illustrated access token.', 'Realm A’s configured audience mapper adds the orders-api audience.', 'A resource server later checks that the token was issued for that API. This value is not automatically the application’s client_id.', 'orders-api (explicit audience mapper in this example)', 'RFC 7519 §4.1.3 / Keycloak audience support', serviceJwtSource),
  serviceAccessIssuedAt: serviceAttribute('iat', 'The time at which this access token is issued, as seconds since the Unix epoch.', 'Realm A sets the JWT NumericDate during token construction.', 'Records when this service token was created. Receiving a new token does not start an end-user SSO session.', 'issued-at epoch seconds (symbolic)', 'RFC 7519 §4.1.6', serviceJwtSource),
  serviceAccessExpiresAt: serviceAttribute('exp', 'The time after which this access token must be rejected.', 'Realm A calculates a JWT NumericDate from its configured access-token lifetime.', 'Bounds the token’s validity. When it expires, this service normally authenticates again with client_credentials.', 'iat + 300 (illustrative)', 'RFC 7519 §4.1.4', serviceJwtSource),
  serviceAccessRoles: serviceAttribute('resource_access.orders-api.roles', 'The client-role claim added by the illustrated Keycloak role protocol mapper.', 'Realm A’s client-role mapper writes the effective orders-api roles into resource_access.', 'Tells the API which mapped permissions the token conveys. A role name alone is not a substitute for signature, issuer, audience and expiry checks.', '["read"]', 'Keycloak · Role mappings in the token', serviceKeycloakSource),
  serviceAccessScope: serviceAttribute('scope', 'The granted scope string carried inside this illustrative JWT access token.', 'Realm A resolves the requested scope and its client-scope configuration when building the token.', 'Describes granted token permissions in the configured token format. The token-response scope is a separate occurrence of the same OAuth concept.', 'orders.read', 'RFC 6749 §3.3 / Keycloak protocol mappers', serviceOAuthSource),
  serviceAccessSignature: serviceAttribute('JWS signature (access token)', 'The signature protecting the JWT access-token header and claims.', 'Realm A signs the JWS signing input with its configured private token-signing key.', 'Allows a resource server to verify the token using the corresponding trusted public key. The private signing key stays in Realm A.', 'RS256 signature bytes (symbolic; realm policy selects algorithm)', 'RFC 7515 §5.1', serviceJwsSource),
};

export const SERVICE_TOPIC_IDS = ['clientIdApp', 'clientSecret', 'authorizationHeader', 'grantType', 'tokenEndpoint', 'scope', ...Object.keys(SERVICE_ATTRIBUTES), 'realmSigningKey', 'accessTokenA', 'tokenType', 'expiresIn'];

export const SERVICE_SOURCES = [
  { name: 'OAuth client credentials grant', standard: 'RFC 6749 §2.3.1 / §4.4 / §5.1', url: serviceOAuthSource, note: 'Confidential-client authentication, grant request and normal access-token response.' },
  { name: 'Keycloak service accounts', standard: 'Keycloak Server Administration Guide', url: serviceKeycloakSource + '#_service_accounts', note: 'Enable client authentication and service-account roles; filter roles by client and client-scope mappings.' },
  { name: 'JSON Web Token claims', standard: 'RFC 7519 §4.1', url: serviceJwtSource, note: 'Issuer, subject, resource audience and NumericDate claims in the illustrated JWT access token.' },
  { name: 'JSON Web Signature', standard: 'RFC 7515 §5.1', url: serviceJwsSource, note: 'Local signing and later verification of the token; JWT is the Keycloak example format, not a requirement of the client-credentials grant.' },
];

const serviceExamples = Object.freeze({
  clientApp: 'orders-service',
  tokenA: 'https://idp1.example.test/realms/realm-a/protocol/openid-connect/token',
  issuerA: 'https://idp1.example.test/realms/realm-a',
  scope: 'orders.read',
  secret: 'configured secret (symbolic)',
  authorization: 'Basic BASE64(FORM_ENCODE(orders-service) + ":" + FORM_ENCODE(client_secret))',
  accessToken: 'header.claims.signature (symbolic JWT; not an ID token)',
});

const serviceOp = (ids, kind, actorId, detail, carriedAs) => ids.map(attributeId => ({ attributeId, kind, actorId, detail, ...(carriedAs ? { carriedAs } : {}) }));
const serviceTransfer = (ids, from, to, detail, carriedAs) => ids.flatMap(attributeId => [
  ...serviceOp([attributeId], 'send', from, detail, carriedAs),
  ...serviceOp([attributeId], 'receive', to, detail, carriedAs),
]);
const servicePayload = (name, value, description) => ({ name, value, ...(description ? { description } : {}) });
const serviceStep = (id, title, from, to, phase, channel, summary, detail, fields, payload, checks, attributeOperations) => ({
  id: 'service-' + id, title, from, to, phase, channel, summary, detail, fields, payload, checks, attributeOperations,
  oidcGrant: 'client_credentials', architecture: 'web', upstream: 'single', serviceAccount: true,
});

const serviceCreateSteps = () => [
  serviceStep('prepare', 'The service prepares its own credentials', 'app', 'app', 'prepare', 'internal',
    'A background application needs permission to do its own work.',
    'The service reads its registered client_id, securely configured client_secret, token_endpoint and requested scope. It constructs HTTP Basic client authentication: each credential is application/x-www-form-urlencoded encoded before joining them with a colon and Base64 encoding. Base64 does not encrypt the secret; HTTPS protects this request. There is no browser, redirect_uri, state, nonce or PKCE exchange.',
    ['clientIdApp', 'clientSecret', 'authorizationHeader', 'tokenEndpoint', 'grantType', 'scope'],
    [servicePayload('client_id', serviceExamples.clientApp, 'Configured locally; this Basic-authentication example does not duplicate it in the form body.'), servicePayload('client_secret', serviceExamples.secret, 'Local configured credential; the next HTTPS request carries it only inside Authorization: Basic.'), servicePayload('Authorization', serviceExamples.authorization), servicePayload('grant_type', 'client_credentials'), servicePayload('scope', serviceExamples.scope)],
    ['A confidential application keeps its credentials on the server'],
    [...serviceOp(['clientIdApp', 'clientSecret', 'tokenEndpoint', 'scope'], 'use', 'app', 'Reads registered client configuration and credentials from the service’s protected server environment.'), ...serviceOp(['grantType'], 'use', 'app', 'Selects the client_credentials grant; this does not authenticate an end user.'), ...serviceOp(['authorizationHeader'], 'derive', 'app', 'Builds HTTP Basic authentication using form-encoded client_id and client_secret, then Base64 encodes the joined credential string.')]),

  serviceStep('request', 'Ask for an application access token', 'app', 'realmA', 'tokens', 'backchannel',
    'The service sends one HTTPS token request directly to Realm A.',
    'POST token_endpoint with Content-Type: application/x-www-form-urlencoded. The form body contains grant_type=client_credentials and this example’s optional scope. Authorization: Basic carries the client credentials. Client authentication and the selected grant are distinct request concerns; no authorization code or user password is submitted.',
    ['tokenEndpoint', 'authorizationHeader', 'clientIdApp', 'clientSecret', 'grantType', 'scope'],
    [servicePayload('HTTP', 'POST ' + serviceExamples.tokenA), servicePayload('Authorization', serviceExamples.authorization), servicePayload('Content-Type', 'application/x-www-form-urlencoded'), servicePayload('grant_type', 'client_credentials'), servicePayload('scope', serviceExamples.scope)],
    ['TLS protects the confidential request', 'One client authentication method is used'],
    [...serviceOp(['tokenEndpoint'], 'use', 'app', 'Calls the configured Realm A token endpoint over HTTPS.'), ...serviceTransfer(['authorizationHeader'], 'app', 'realmA', 'HTTP request header carries Basic client authentication.'), ...serviceTransfer(['clientIdApp', 'clientSecret'], 'app', 'realmA', 'The encoded client identifier and secret are carried inside the Basic header, not duplicated in the request body.', 'Authorization: Basic'), ...serviceTransfer(['grantType', 'scope'], 'app', 'realmA', 'OAuth form-encoded token-request member.')]),

  serviceStep('authenticate', 'Realm A authenticates the client', 'realmA', 'realmA', 'tokens', 'internal',
    'Realm A checks that this is the registered confidential service.',
    'Realm A resolves the Basic client identifier, checks the configured client credential, and verifies that the client is enabled with Client authentication On and Service account roles enabled. The server accepts the requested grant only under its client policies. This proves the application’s credentials, not the identity or presence of a human.',
    ['clientIdApp', 'clientSecret', 'authorizationHeader', 'grantType', 'serviceClientAuthentication', 'serviceAccountEnabled'],
    [servicePayload('client_id', serviceExamples.clientApp), servicePayload('Client authentication (Keycloak setting)', 'On'), servicePayload('Service account roles (Keycloak setting)', 'Enabled'), servicePayload('grant_type', 'client_credentials')],
    ['Registered and enabled confidential client', 'Valid configured client credential', 'Service account capability enabled'],
    [...serviceOp(['authorizationHeader'], 'use', 'realmA', 'Parses the incoming Basic authentication header.'), ...serviceOp(['clientIdApp', 'clientSecret'], 'verify', 'realmA', 'Resolves the registered client and validates the incoming client credential under its authentication policy.'), ...serviceOp(['grantType', 'serviceClientAuthentication', 'serviceAccountEnabled'], 'verify', 'realmA', 'Checks grant eligibility, client authentication capability and the service-account capability.')]),

  serviceStep('permissions', 'Keep only the permitted service roles', 'realmA', 'realmA', 'tokens', 'internal',
    'Realm A calculates which permissions the service may receive.',
    'The service account has orders-api roles read and write; the client’s explicitly configured role scope mappings permit only read. Realm A intersects those local role sets and resolves the requested orders.read client scope. In this example, the configured role mapper includes read and excludes write. Role scope mappings and OAuth scope are related configuration inputs, but they are not the same object.',
    ['scope', 'serviceAssignedRoles', 'serviceRoleScopeMappings', 'serviceEffectiveRoles'],
    [servicePayload('Service account roles (local configuration)', 'orders-api: read, write'), servicePayload('Role scope mappings (local configuration)', 'orders-api: read'), servicePayload('Effective roles (local result)', 'orders-api: read'), servicePayload('scope', serviceExamples.scope)],
    ['Assigned service roles ∩ permitted client/client-scope role mappings', 'Explicit mappings; Full Scope Allowed is not enabled'],
    [...serviceOp(['serviceAssignedRoles', 'serviceRoleScopeMappings'], 'use', 'realmA', 'Resolves local assigned service-account roles and permitted role scope mappings, including applicable linked client scopes.'), ...serviceOp(['scope'], 'verify', 'realmA', 'Checks and resolves the requested OAuth scope under this client’s configuration.'), ...serviceOp(['serviceEffectiveRoles'], 'derive', 'realmA', 'Intersects assigned roles and permitted role scope mappings; only orders-api read remains.')]),

  serviceStep('issue', 'Create and sign the service access token', 'realmA', 'realmA', 'tokens', 'internal',
    'Realm A creates a token representing the application’s service account.',
    'The illustrated Keycloak token is a signed JWT. Its sub identifies the service account, and its aud is orders-api because this example explicitly configures an audience mapper. Realm A includes the effective client roles and lifetime, then signs locally. OAuth client_credentials does not require JWT serialization. No ID token, refresh token or end-user SSO session is created in this default service-account scenario.',
    ['serviceEffectiveRoles', 'serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope', 'realmSigningKey', 'serviceAccessSignature', 'accessTokenA', 'tokenType', 'expiresIn', 'scope'],
    [servicePayload('iss', serviceExamples.issuerA), servicePayload('sub', 'service-account-id-204'), servicePayload('aud', 'orders-api'), servicePayload('iat', 'issued-at epoch seconds'), servicePayload('exp', 'iat + 300'), servicePayload('resource_access.orders-api.roles', '["read"]'), servicePayload('scope', serviceExamples.scope), servicePayload('JWS signature (access token)', 'Sign(realm signing key, JWS signing input)'), servicePayload('access_token', serviceExamples.accessToken)],
    ['Service-account subject; no person is signed in', 'API audience comes from configured mapper', 'Private signing key remains in Realm A'],
    [...serviceOp(['serviceEffectiveRoles', 'scope'], 'use', 'realmA', 'Uses the locally authorized role result and resolved scope to build claims.'), ...serviceOp(['serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope'], 'create', 'realmA', 'Builds JWT access-token claims for the service account under the configured protocol mappers and token lifetime.'), ...serviceOp(['realmSigningKey'], 'use', 'realmA', 'Uses the realm private signing key locally; it is never a token-response field.'), ...serviceOp(['serviceAccessSignature'], 'derive', 'realmA', 'Signs the access-token JWS signing input with the realm’s configured signing key.'), ...serviceOp(['accessTokenA', 'tokenType', 'expiresIn'], 'create', 'realmA', 'Serializes the signed access token and constructs its Bearer usage and response lifetime metadata.')]),

  serviceStep('response', 'Return the access token to the service', 'realmA', 'app', 'tokens', 'backchannel',
    'The direct HTTPS response returns an access token and its usage details.',
    'The JSON token response contains access_token, token_type, expires_in and scope. JWT claims are nested inside the access_token value, not extra top-level response members. This normal client-credentials response has no id_token or refresh_token. Cache-Control: no-store and Pragma: no-cache protect the token response from HTTP caching.',
    ['accessTokenA', 'tokenType', 'expiresIn', 'scope', 'serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope', 'serviceAccessSignature'],
    [servicePayload('HTTP', '200 OK'), servicePayload('Cache-Control', 'no-store'), servicePayload('Pragma', 'no-cache'), servicePayload('access_token', serviceExamples.accessToken), servicePayload('token_type', 'Bearer'), servicePayload('expires_in', '300'), servicePayload('scope', serviceExamples.scope)],
    ['No ID token in this grant', 'No refresh token by default', 'Claims travel inside access_token, not as sibling response fields'],
    [...serviceTransfer(['accessTokenA', 'tokenType', 'expiresIn', 'scope'], 'realmA', 'app', 'OAuth JSON token-response member carried on the HTTPS backchannel.'), ...serviceTransfer(['serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope', 'serviceAccessSignature'], 'realmA', 'app', 'Member of the issued signed access token, nested within access_token.', 'access_token (JWS)')]),

  serviceStep('ready', 'The service is ready for its permitted API work', 'app', 'app', 'tokens', 'internal',
    'The application retains the access token securely for its next API request.',
    'The service reads token_type=Bearer, records the returned lifetime and granted scope, and retains the access token in its protected server environment. It must not treat that access token as a human login or perform OIDC ID-token nonce/audience checks. A subsequent resource server will enforce its own token validation and permissions; that API request is outside this scenario. When this token expires, the service normally requests another one by authenticating again.',
    ['accessTokenA', 'tokenType', 'expiresIn', 'scope'],
    [servicePayload('access_token', 'Retained in protected server memory'), servicePayload('token_type', 'Bearer'), servicePayload('expires_in', '300'), servicePayload('scope', serviceExamples.scope)],
    ['Protect the bearer token', 'Resource server validation is required on a later API request', 'Request another client_credentials token after expiry'],
    [...serviceOp(['tokenType'], 'verify', 'app', 'Checks the advertised access-token usage scheme is supported.'), ...serviceOp(['expiresIn', 'scope'], 'use', 'app', 'Records the token lifetime and granted scope; this is not an ID-token identity validation.'), ...serviceOp(['accessTokenA'], 'store', 'app', 'Retains the issued bearer access token securely for a later API request.')]),
];

const serviceDeepFreeze = value => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) serviceDeepFreeze(child);
  }
  return value;
};
const serviceSteps = serviceDeepFreeze(serviceCreateSteps());

export function getServiceAccountSteps(config = {}) {
  // Deliberately independent of selected human factors and broker topology.
  return serviceSteps;
}

export function getServiceAccountAttributeOverrides(config = {}) {
  return {
    clientIdApp: serviceAttribute('client_id', 'The public identifier of this confidential service’s OIDC client registration in Realm A.', 'Assigned during registration and configured in the service; not generated per token request.', 'Selects the registered service client. In this example it travels inside Authorization: Basic and is not duplicated in the request body. The identifier alone does not authenticate the application.', serviceExamples.clientApp, 'RFC 6749 §2.2 / §2.3.1', serviceOAuthSource),
    clientSecret: serviceAttribute('client_secret', 'The confidential application credential configured for this service.', 'Provisioned for the registered service client in Realm A, then stored in the service’s protected server environment.', 'Authenticates this client’s HTTPS token request through HTTP Basic. It is intentionally carried to Realm A inside the protected Basic header; it is not an end-user password.', serviceExamples.secret, 'RFC 6749 §2.3.1', serviceOAuthSource),
    authorizationHeader: serviceAttribute('Authorization', 'The HTTP request header containing this service’s Basic client authentication.', 'The service form-encodes the client identifier and secret, joins them with a colon, then Base64 encodes the credentials.', 'Authenticates the confidential client directly to Realm A over HTTPS. Base64 is encoding, not encryption.', serviceExamples.authorization, 'RFC 6749 §2.3.1', serviceOAuthSource),
    grantType: serviceAttribute('grant_type', 'The token-endpoint grant selected for this application-only request.', 'The service sets client_credentials in the form-encoded token request.', 'Requests permission for the application’s service account without authenticating an end user or redeeming an authorization code.', 'client_credentials', 'RFC 6749 §4.4.2', serviceOAuthSource),
    tokenEndpoint: serviceAttribute('token_endpoint', 'The Realm A HTTPS endpoint issuing this service’s access token.', 'Configured in the service or obtained from the realm’s authorization-server metadata.', 'Receives the direct POST request with client authentication and grant_type=client_credentials.', serviceExamples.tokenA, 'RFC 6749 §3.2 / Keycloak OIDC endpoints', serviceOAuthSource),
    scope: serviceAttribute('scope', 'The optional space-separated permissions requested and granted to this service.', 'The application requests orders.read; Realm A resolves that configured client scope and returns the granted scope.', 'Constrains this token request under the client configuration. It does not request OIDC end-user sign-in; openid is not used in this example.', serviceExamples.scope, 'RFC 6749 §3.3 / §4.4.2 / §5.1', serviceOAuthSource),
    accessTokenA: serviceAttribute('access_token', 'The bearer authorization token issued for this application’s service account.', 'Realm A issues it after validating the confidential client and resolving its permitted service-account roles and scopes.', 'Authorizes later API work as the service account. It is not an OIDC ID token and does not establish an end-user login. The example uses a signed JWT, while OAuth leaves the token format open.', serviceExamples.accessToken, 'RFC 6749 §1.4 / §4.4.3', serviceOAuthSource),
    tokenType: serviceAttribute('token_type', 'The access-token usage scheme advertised in the service token response.', 'Realm A sets Bearer in this token response.', 'Tells the service how this token will be used for resource access; possession of a bearer token requires careful protection.', 'Bearer', 'RFC 6749 §5.1', serviceOAuthSource),
    expiresIn: serviceAttribute('expires_in', 'The lifetime of this access token in seconds from the response.', 'Realm A derives it from its configured access-token lifetime.', 'Lets the service track when to obtain another client_credentials token. A refresh token is not returned in this default scenario.', '300 (illustrative)', 'RFC 6749 §5.1 / §4.4.3', serviceOAuthSource),
    realmSigningKey: serviceAttribute('realm signing key (private)', 'Realm A’s private token-signing key, retained inside Keycloak.', 'Provisioned in Realm A’s configured key provider.', 'Signs the service-account access-token JWT. It is different from the client_secret used to authenticate the requesting service and is never sent to that service.', 'Realm A signing key; never transmitted', 'Keycloak realm keys / RFC 7515 §5.1', serviceKeycloakSource),
  };
}

export function getServiceAccountActorOverrides(config = {}) {
  const serviceActorAttribute = (id, kind) => ({ id, kind });
  return {
    app: {
      name: 'Background service', role: 'Confidential OAuth client', plainRole: 'Obtains permission to act as its own service account.',
      attributes: ['clientIdApp', 'clientSecret', 'tokenEndpoint', 'grantType', 'scope'].map(id => serviceActorAttribute(id, 'static')).concat(['authorizationHeader'].map(id => serviceActorAttribute(id, 'generated')), ['accessTokenA', 'tokenType', 'expiresIn'].map(id => serviceActorAttribute(id, 'received'))),
      notes: ['Runs in a protected server environment; this is not browser JavaScript.', 'Authenticates with client_secret_basic and uses grant_type=client_credentials.', 'No end-user sign-in, passkey, TOTP, authorization code or PKCE is involved.', 'Retains the issued token securely; a later API call is outside this scenario.'],
    },
    realmA: {
      name: 'IdP 1 · Realm A', role: 'OAuth authorization server', plainRole: 'Checks the service credentials and issues its permitted access token.',
      attributes: ['clientIdApp', 'serviceClientAuthentication', 'serviceAccountEnabled', 'serviceAssignedRoles', 'serviceRoleScopeMappings', 'realmSigningKey'].map(id => serviceActorAttribute(id, 'static')).concat(['authorizationHeader', 'clientSecret', 'grantType', 'scope'].map(id => serviceActorAttribute(id, 'received')), ['serviceEffectiveRoles', 'serviceAccessIssuer', 'serviceAccessSubject', 'serviceAccessAudience', 'serviceAccessIssuedAt', 'serviceAccessExpiresAt', 'serviceAccessRoles', 'serviceAccessScope', 'serviceAccessSignature', 'accessTokenA', 'tokenType', 'expiresIn'].map(id => serviceActorAttribute(id, 'generated'))),
      notes: ['Client authentication On and Service account roles enabled for the service client.', 'Effective roles = service-account roles ∩ client/client-scope role mappings.', 'An explicitly configured audience mapper adds orders-api in this example.', 'Default client-credentials response: access token; no ID token, refresh token or end-user SSO session.'],
    },
  };
}

export function getServiceAccountExampleOverrides(config = {}) {
  return { clientApp: serviceExamples.clientApp, tokenA: serviceExamples.tokenA, issuerA: serviceExamples.issuerA };
}
