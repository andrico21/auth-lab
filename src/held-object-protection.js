import { createHeldObjectPlan, heldArtifact, heldAt, heldAcquire, heldRelease, heldCoverage, heldWire } from './held-object-authoring.js';

const PROTECTION_CHOICES = new Set(['lab-client-jwt', 'lab-mtls', 'lab-par', 'lab-jar', 'lab-jarm', 'lab-dpop', 'lab-jwt-grant']);
const WEB_CHOICES = new Set(['lab-spa-api', 'lab-bff-api', 'lab-api-introspection', 'lab-api-errors', 'lab-jwks-rotation']);
const PROT_REQUEST = ['protClientId', 'protRedirect', 'protResponseType', 'protScope', 'protState', 'protChallenge', 'protChallengeMethod'];
const WEB_REQUEST = ['webClientId', 'webRedirectUri', 'webResponseType', 'webRequestScope', 'webState', 'webNonce', 'webChallenge', 'webChallengeMethod'];
const WEB_ACCESS = ['webAccessToken', 'webIssuer', 'webApiAudience', 'webSubject', 'webExpiry', 'webIssuedAt', 'webApiScope', 'webAlgorithm', 'webSignature', 'webKid'];

// Every object and transition below is bound to a particular fixture event. The
// glossary supplies contextual values, never evidence that an object is held.
export function buildProtectionHeldObjects(args) {
  const choice = args.choiceId || args.model?.id;
  if (!PROTECTION_CHOICES.has(choice) && !WEB_CHOICES.has(choice)) return null;
  const plan = createHeldObjectPlan(args);
  const definitions = args.model.definitions(args.config || {});
  const actors = Object.keys(args.actors || args.model.actors(args.config || {}));
  const fields = (ids, values = {}, readableBy) => ids.map(attributeId => ({ attributeId, name: definitions[attributeId]?.name || attributeId, value: Object.hasOwn(values, attributeId) ? values[attributeId] : definitions[attributeId]?.example, ...(readableBy ? { readableBy } : {}) }));
  const put = (event, id, label, actor, ids, store, options = {}) => {
    const readableBy = options.readableBy || [actor];
    const { values = {}, derivedFrom, related, replaces, details, type = 'credential' } = options;
    heldArtifact(plan, { artifactId: id, type, label, creator: actor, representations: [{ representationId: 'plain', format: options.format || 'synthetic', readableBy, fields: fields(ids, values, options.fieldReaders) }], ...(derivedFrom ? { derivedFrom } : {}), ...(related ? { related } : {}), ...(replaces ? { replaces } : {}), ...(details ? { details } : {}) });
    heldAt(plan, event, { op: 'create', artifactId: id }, heldAcquire(id, actor, store, { retention: options.releaseAt || store === 'output' ? 'temporary' : 'retained' }));
    if (options.releaseAt) heldAt(plan, options.releaseAt, heldRelease(id, actor, store));
    return id;
  };
  const copy = (event, id, from, to, fromStore, toStore, releaseAt, retainedSender = true) => heldWire(plan, event, id, from, to, { fromStore, toStore, retention: releaseAt ? 'temporary' : 'retained', ...(releaseAt ? { releaseAt } : {}), releaseSender: !retainedSender });
  const drop = (event, id, actor, store) => heldAt(plan, event, heldRelease(id, actor, store));
  const see = (event, id, actor, result, policy, requestId = event, endpoint) => heldAt(plan, event, { op: 'observe', artifactId: id, actorId: actor, kind: 'verification', requestId, result, policy, ...(endpoint ? { endpoint } : {}) });
  const authority = (event, id, actor, status) => heldAt(plan, event, { op: 'authority', artifactId: id, authorityId: actor, status });
  const protIssuer = () => {
    put(null, 'issuer-key', 'Realm A signing private key', 'realmA', ['protRealmSigningKey'], 'signing-keys');
    if (actors.includes('realmB') && choice !== 'lab-jwt-grant') put(null, 'api-trust', 'Trusted Realm A public verification key', 'realmB', ['protRealmPublicKey'], 'trust');
  };
  const basic = (event, request, check) => {
    put(null, 'client-secret', 'Registered confidential client credential', 'app', ['protClientId', 'protClientSecret'], 'client-credentials');
    put(null, 'client-registration', 'Realm client authentication registration', 'realmA', ['protClientId', 'protClientSecret'], 'client-registration');
    put(event, 'basic-auth', 'Basic client authentication request', 'app', ['protBasic'], 'output', { readableBy: ['app', 'realmA'], derivedFrom: ['client-secret'] });
    copy(request, 'basic-auth', 'app', 'realmA', 'output', 'client-auth-request', check, false);
  };
  const protToken = (issue, response, binding = [], related = []) => {
    put(issue, 'access-token', binding.includes('protDpopJkt') ? 'AT-D - DPoP-bound access token' : 'API access token', 'realmA', ['protAccessToken', 'protApiAudience', 'protScope', 'protTokenType', 'protExpiresIn', ...binding], 'output', { readableBy: ['realmA', 'app', ...(actors.includes('realmB') && choice !== 'lab-jwt-grant' ? ['realmB'] : [])], related, values: { protTokenType: choice === 'lab-dpop' ? 'DPoP' : 'Bearer' } });
    copy(response, 'access-token', 'realmA', 'app', 'output', 'tokens', null, false);
  };
  if (PROTECTION_CHOICES.has(choice)) protIssuer();

  if (choice === 'lab-client-jwt') {
    put(null, 'client-key', 'Client signing private key', 'app', ['protClientPrivateKey'], 'signing-keys');
    put(null, 'client-public', 'Registered client public key', 'realmA', ['protClientPublicKey'], 'trust');
    put('prot-client-jwt-sign', 'client-assertion', 'Fresh client authentication assertion', 'app', ['protCaJwt', 'protCaType', 'protCaIss', 'protCaSub', 'protCaAud', 'protCaExp', 'protCaIat', 'protCaJti'], 'output', { readableBy: ['app', 'realmA'], derivedFrom: ['client-key'] });
    copy('prot-client-jwt-request', 'client-assertion', 'app', 'realmA', 'output', 'client-assertion-request', 'prot-client-jwt-verify', false);
    see('prot-client-jwt-verify', 'client-assertion', 'realmA', 'accepted', 'Registered key/algorithm, client iss/sub, exact single audience, time, fresh jti; service-account grant/scopes separately allowed');
    put('prot-client-jwt-verify', 'client-jti-record', 'Accepted client assertion jti', 'realmA', ['protCaJti'], 'client-assertion-replay', { related: ['client-assertion'], details: 'Retained through assertion validity window; request consumption does not erase the JWT history.' });
    authority('prot-client-jwt-verify', 'client-assertion', 'realmA', 'consumed-jti');
    protToken('prot-client-jwt-issue', 'prot-client-jwt-response');
  }
  if (choice === 'lab-mtls') {
    put(null, 'tls-key', 'Client TLS private key', 'app', ['protTlsPrivateKey'], 'tls-keys');
    put(null, 'tls-certificate', 'Client X.509 certificate', 'app', ['protTlsCertificate'], 'tls-credentials', { readableBy: ['app', 'realmA', 'realmB'], related: ['tls-key'] });
    put(null, 'mtls-registration', 'Registered certificate trust and independent binding policy', 'realmA', ['protTlsAuthMethod', 'protTlsBoundSetting', 'protClientId'], 'trust');
    put(null, 'api-tls-trust', 'API TLS certificate trust policy', 'realmB', ['protTlsAuthMethod'], 'tls-trust', { values: { protTlsAuthMethod: 'Independently configured trusted client CA and certificate possession verification' } });
    put('prot-mtls-prepare', 'tls-token-proof', 'Token connection CertificateVerify', 'app', ['protTlsProof'], 'output', { readableBy: ['app', 'realmA'], derivedFrom: ['tls-key'], details: 'Token TLS transcript; not the API connection proof.' });
    copy('prot-mtls-handshake', 'tls-token-proof', 'app', 'realmA', 'output', 'tls-token-request', 'prot-mtls-bind', false);
    copy('prot-mtls-handshake', 'tls-certificate', 'app', 'realmA', 'tls-credentials', 'tls-token-certificate', 'prot-mtls-bind');
    see('prot-mtls-bind', 'tls-token-proof', 'realmA', 'accepted', 'Certificate chain/registered client identity and TLS possession authenticate client; certificate-bound issuance separately enabled');
    protToken('prot-mtls-issue', 'prot-mtls-response', ['protCertThumbprint'], ['tls-certificate']);
    put('prot-mtls-api-proof', 'tls-api-proof', 'API connection CertificateVerify', 'app', ['protTlsProof'], 'output', { readableBy: ['app', 'realmB'], derivedFrom: ['tls-key'], values: { protTlsProof: 'Fresh API TLS transcript CertificateVerify (distinct from token connection)' } });
    copy('prot-mtls-api-request', 'tls-api-proof', 'app', 'realmB', 'output', 'api-tls-request', 'prot-mtls-api-check', false);
    copy('prot-mtls-api-request', 'tls-certificate', 'app', 'realmB', 'tls-credentials', 'api-tls-certificate', 'prot-mtls-api-check');
    copy('prot-mtls-api-request', 'access-token', 'app', 'realmB', 'tokens', 'api-token-request', 'prot-mtls-api-check');
    see('prot-mtls-api-check', 'tls-api-proof', 'realmB', 'accepted', 'Current TLS certificate possession verified independently', 'mtls-api-request');
    see('prot-mtls-api-check', 'access-token', 'realmB', 'accepted', 'Issuer signature/time/audience/scope and full DER certificate SHA-256 equals cnf.x5t#S256', 'mtls-api-request');
  }
  if (choice === 'lab-dpop') {
    basic('prot-dpop-token-sign', 'prot-dpop-token-request', 'prot-dpop-token-check');
    put('prot-dpop-keys', 'dpop-key', 'K-D - client-local DPoP private key', 'app', ['protDpopPrivate'], 'dpop-keys');
    put('prot-dpop-keys', 'dpop-public', 'J-D - public-only DPoP JWK', 'app', ['protDpopJwk'], 'dpop-keys', { readableBy: ['app', 'realmA', 'realmB'], derivedFrom: ['dpop-key'] });
    const proof = (event, id, label, jti, api, nonce) => put(event, id, label, 'app', [api ? 'protDpopApiProof' : 'protDpopTokenProof', 'protDpopTyp', 'protDpopAlg', 'protDpopJwk', 'protDpopJti', 'protDpopHtm', 'protDpopHtu', 'protDpopIat', ...(api ? ['protDpopAth'] : []), ...(nonce ? ['protDpopNonce'] : [])], 'output', { readableBy: ['app', api ? 'realmB' : 'realmA'], derivedFrom: ['dpop-key', ...(api ? ['access-token'] : [])], ...(nonce ? { related: ['api-nonce'] } : {}), values: { protDpopJti: jti, protDpopHtm: api ? 'GET' : 'POST', protDpopHtu: args.steps.find(step => step.id === event).attributeValues.protDpopHtu, protDpopIat: api ? nonce ? 'Fresh retry creation time (P-R)' : 'Fresh API request creation time (P-A)' : 'Fresh token request creation time (P-T)' } });
    proof('prot-dpop-token-sign', 'dpop-token-proof', 'P-T - token request proof', 'dpop_token_jti_51', false, false);
    copy('prot-dpop-token-request', 'dpop-token-proof', 'app', 'realmA', 'output', 'dpop-token-request', 'prot-dpop-token-check', false);
    see('prot-dpop-token-check', 'dpop-token-proof', 'realmA', 'accepted', 'Public-only JWK, typ/alg/signature, POST/token htu, freshness and unused jti; independent Basic client/grant checks');
    put('prot-dpop-token-check', 'dpop-as-replay', 'Realm A accepted jti-51', 'realmA', ['protDpopJti'], 'dpop-replay', { values: { protDpopJti: 'dpop_token_jti_51' }, related: ['dpop-token-proof'], details: 'Realm A replay window only; no authorization-server nonce in this fixture.' });
    protToken('prot-dpop-issue', 'prot-dpop-token-response', ['protDpopJkt'], ['dpop-public']);
    proof('prot-dpop-api-sign', 'dpop-api-proof', 'P-A - first API request proof', 'dpop_api_jti_52', true, false);
    copy('prot-dpop-api-request', 'dpop-api-proof', 'app', 'realmB', 'output', 'dpop-first-request', 'prot-dpop-api-challenge-create', false);
    copy('prot-dpop-api-request', 'access-token', 'app', 'realmB', 'tokens', 'api-first-token', 'prot-dpop-api-challenge-create');
    see('prot-dpop-api-challenge-create', 'dpop-api-proof', 'realmB', 'nonce-required', 'Request context examined; no access acceptance or accepted-jti-52 record', 'dpop-api-first');
    see('prot-dpop-api-challenge-create', 'access-token', 'realmB', '401 use_dpop_nonce', 'Resource request requires API nonce; token is not revoked', 'dpop-api-first');
    put('prot-dpop-api-challenge-create', 'api-nonce', 'N-A - API-specific nonce', 'realmB', ['protDpopNonceHeader', 'protDpopNonce'], 'nonce-policy', { readableBy: ['realmB', 'app'], details: 'API freshness state, independent from Realm A replay policy.' });
    copy('prot-dpop-api-challenge', 'api-nonce', 'realmB', 'app', 'nonce-policy', 'resource-nonce', null);
    put('prot-dpop-api-challenge-create', 'dpop-challenge-response', 'API 401 nonce-required challenge', 'realmB', ['protDpopChallenge', 'protDpopNonceHeader'], 'output', { type: 'response', readableBy: ['realmB', 'app'], related: ['api-nonce', 'dpop-api-proof'], details: 'HTTP 401 resource challenge; not token revocation or authorization-server nonce.' });
    copy('prot-dpop-api-challenge', 'dpop-challenge-response', 'realmB', 'app', 'output', 'challenge-response', 'prot-dpop-save-nonce', false);
    see('prot-dpop-save-nonce', 'api-nonce', 'app', 'stored-for-resource', 'Opaque API nonce retained for a fresh retry; same continuing DPoP key and token', 'dpop-api-retry');
    proof('prot-dpop-api-retry-sign', 'dpop-retry-proof', 'P-R - fresh nonce-bound retry proof', 'dpop_api_retry_jti_53', true, true);
    copy('prot-dpop-api-retry', 'dpop-retry-proof', 'app', 'realmB', 'output', 'dpop-retry-request', 'prot-dpop-api-accept', false);
    copy('prot-dpop-api-retry', 'access-token', 'app', 'realmB', 'tokens', 'api-retry-token', 'prot-dpop-api-accept');
    see('prot-dpop-api-accept', 'dpop-retry-proof', 'realmB', 'accepted', 'Exact request method/htu, typ/alg/public-JWK/signature, current iat, unused jti-53, API nonce, cnf.jkt equality and exact-token ath', 'dpop-api-retry');
    see('prot-dpop-api-accept', 'access-token', 'realmB', 'accepted', 'Issuer signature/time, orders-api audience and allowed scopes, plus request-specific DPoP binding', 'dpop-api-retry');
    put('prot-dpop-api-accept', 'dpop-api-replay', 'API accepted jti-53', 'realmB', ['protDpopJti'], 'dpop-replay', { values: { protDpopJti: 'dpop_api_retry_jti_53' }, related: ['dpop-retry-proof', 'api-nonce'], details: 'API replay window only; P-A was challenged, not accepted.' });
  }
  if (['lab-par', 'lab-jar', 'lab-jarm'].includes(choice)) {
    const p = 'prot-' + choice.slice(4);
    basic(p + '-start', p + '-redeem', p + '-pkce-check');
    put(p + '-start', 'pending-state', 'Original backend state', 'app', ['protState'], 'pending-attempt');
    put(p + '-start', 'pkce-verifier', 'Backend-only PKCE verifier', 'app', ['protVerifier'], 'pending-attempt', { readableBy: ['app', 'realmA'] });
    put(p + '-start', 'pkce-challenge', 'Public S256 PKCE commitment', 'app', ['protChallenge', 'protChallengeMethod'], 'pending-attempt', { readableBy: ['app', 'browser', 'realmA'], derivedFrom: ['pkce-verifier'] });
    put(p + '-start', 'authorization-request', 'Public authorization request', 'app', PROT_REQUEST, 'pending-attempt', { readableBy: ['app', 'browser', 'realmA'], related: ['pending-state', 'pkce-challenge'] });
    if (choice === 'lab-par') {
      copy('prot-par-push', 'authorization-request', 'app', 'realmA', 'pending-attempt', 'par-receipt', 'prot-par-store');
      // PAR also authenticates the push; this is a copy, not consumption of the backend credential.
      copy('prot-par-push', 'basic-auth', 'app', 'realmA', 'output', 'par-auth-receipt', 'prot-par-store');
      put('prot-par-store', 'par-stored-request', 'PAR stored request, client binding and expiry', 'realmA', [...PROT_REQUEST, 'protParStoredRequest', 'protParExpiresIn'], 'par-requests', { related: ['authorization-request'], details: 'Selected one-use acceptance; 60-second illustrative expiry; retained use record distinguishes request data from handle.' });
      put('prot-par-store', 'par-handle', 'Expiring PAR request_uri handle', 'realmA', ['protRequestUri', 'protParExpiresIn', 'protClientId'], 'output', { readableBy: ['realmA', 'app', 'browser'], related: ['par-stored-request'] });
      copy('prot-par-reference', 'par-handle', 'realmA', 'app', 'output', 'par-handle', 'prot-par-authorize', false);
      copy('prot-par-browser', 'par-handle', 'app', 'browser', 'par-handle', 'navigation', 'prot-par-authorize');
      copy('prot-par-authorize', 'par-handle', 'browser', 'realmA', 'navigation', 'par-handle-receipt', 'prot-par-resolve');
      see('prot-par-resolve', 'par-handle', 'realmA', 'accepted', 'Original authenticated client, unexpired reference, selected one-use policy');
      authority('prot-par-resolve', 'par-stored-request', 'realmA', 'used');
    } else {
      if (choice === 'lab-jar') {
        put(null, 'client-key', 'Request Object signing private key', 'app', ['protClientPrivateKey'], 'signing-keys');
        put(null, 'client-public', 'Registered Request Object public key', 'realmA', ['protClientPublicKey'], 'trust');
        put('prot-jar-sign', 'request-object', 'Signed JAR Request Object', 'app', ['protRequestObject', ...PROT_REQUEST, 'protRoIss', 'protRoAud', 'protRoExp', 'protRoJti'], 'output', { readableBy: ['app', 'browser', 'realmA'], derivedFrom: ['client-key'], related: ['authorization-request'], details: 'Signed, not encrypted. jti is correlation only; no invented one-use cache.' });
        copy('prot-jar-browser', 'request-object', 'app', 'browser', 'output', 'navigation', 'prot-jar-authorize', false);
        copy('prot-jar-authorize', 'request-object', 'browser', 'realmA', 'navigation', 'jar-receipt', 'prot-jar-verify');
        see('prot-jar-verify', 'request-object', 'realmA', 'accepted', 'Registered signature/algorithm, outer/inner client equality, intended server/expiry, signed inner redirect/scope/PKCE; jti correlation only; nbf absent');
      } else {
        put(null, 'jarm-trust', 'Expected issuer public verification key', 'app', ['protRealmPublicKey'], 'trust');
        put('prot-jarm-pending', 'jarm-pending', 'JARM pending issuer/client/state policy', 'app', ['protJarmPending', 'protJarmAlg', 'protResponseMode'], 'pending-attempt', { related: ['pending-state', 'pkce-verifier'] });
        copy('prot-jarm-browser', 'authorization-request', 'app', 'browser', 'pending-attempt', 'navigation', 'prot-jarm-authorize');
        copy('prot-jarm-authorize', 'authorization-request', 'browser', 'realmA', 'navigation', 'authorization-context', 'prot-jarm-code');
      }
    }
    put(p + '-code', 'authorization-code', 'One-time authorization code and original callback state', 'realmA', ['protCode', 'protState', 'protClientId', 'protRedirect', 'protChallenge'], 'code-record', { readableBy: ['realmA', 'browser', 'app'], related: ['pkce-challenge'] });
    if (choice === 'lab-jarm') {
      put('prot-jarm-sign', 'jarm-response', 'Signed JARM authorization response (not ID token)', 'realmA', ['protJarmResponse', 'protJarmIss', 'protJarmAud', 'protJarmExp', 'protJarmAlg', 'protCode', 'protState'], 'output', { readableBy: ['realmA', 'browser', 'app'], derivedFrom: ['issuer-key'], related: ['authorization-code'] });
      copy('prot-jarm-redirect', 'jarm-response', 'realmA', 'browser', 'output', 'callback-response', 'prot-jarm-callback', false);
      copy('prot-jarm-callback', 'jarm-response', 'browser', 'app', 'callback-response', 'unchecked-response', 'prot-jarm-verify');
      see('prot-jarm-verify', 'jarm-response', 'app', 'accepted', 'Exact expected issuer/client audience/expiry, trusted signature and algorithm allowlist (not none), original state and pending context before code processing');
      authority('prot-jarm-verify', 'jarm-pending', 'app', 'consumed');
      heldAt(plan, 'prot-jarm-verify', heldAcquire('authorization-code', 'app', 'redeemable-code', { retention: 'temporary' }));
    } else {
      copy(p + '-redirect', 'authorization-code', 'realmA', 'browser', 'code-record', 'callback-code', p + '-callback');
      copy(p + '-callback', 'authorization-code', 'browser', 'app', 'callback-code', 'redeemable-code', p + '-pkce-check');
      see(p + '-state-check', 'pending-state', 'app', 'matched', 'Original pending callback state; code remains subject to token-endpoint checks');
    }
    copy(p + '-redeem', 'authorization-code', 'app', 'realmA', 'redeemable-code', 'redemption-code', p + '-pkce-check');
    copy(p + '-redeem', 'pkce-verifier', 'app', 'realmA', 'pending-attempt', 'redemption-verifier', p + '-pkce-check');
    see(p + '-pkce-check', 'authorization-code', 'realmA', 'accepted', 'Authenticated client, unexpired single-use code/client/redirect binding and original S256 commitment equality');
    authority(p + '-pkce-check', 'authorization-code', 'realmA', 'consumed');
    if (choice === 'lab-jarm') drop(p + '-pkce-check', 'authorization-code', 'app', 'redeemable-code');
    for (const id of ['pending-state', 'pkce-verifier', 'pkce-challenge', 'authorization-request']) drop(p + '-pkce-check', id, 'app', 'pending-attempt');
    protToken(p + '-issue', p + '-tokens');
  }
  if (choice === 'lab-jwt-grant') {
    basic('prot-jwt-grant-sign', 'prot-jwt-grant-request', 'prot-jwt-grant-validate');
    put(null, 'external-key', 'Trusted external issuer signing private key', 'realmB', ['protGrantPrivate'], 'signing-keys');
    put(null, 'external-trust', 'Configured external issuer public key and grant policy', 'realmA', ['protGrantPublic', 'protGrantPolicy'], 'external-trust');
    put(null, 'subject-link', 'Existing external-to-local subject link', 'realmA', ['protGrantLink'], 'subject-links');
    put('prot-jwt-grant-sign', 'subject-assertion', 'External subject assertion (not client_assertion)', 'realmB', ['protGrantAssertion', 'protGrantIss', 'protGrantSub', 'protGrantAud', 'protGrantExp', 'protGrantIat', 'protGrantJti'], 'output', { readableBy: ['realmB', 'app', 'realmA'], derivedFrom: ['external-key'], related: ['subject-link'] });
    copy('prot-jwt-grant-prerequisite', 'subject-assertion', 'realmB', 'app', 'output', 'subject-grant', 'prot-jwt-grant-validate', false);
    copy('prot-jwt-grant-request', 'subject-assertion', 'app', 'realmA', 'subject-grant', 'subject-grant-request', 'prot-jwt-grant-validate');
    see('prot-jwt-grant-validate', 'subject-assertion', 'realmA', 'accepted', 'Independent Basic client authentication; allowed external issuer/key/algorithm, linked existing subject, exact single audience/time and unused jti');
    authority('prot-jwt-grant-validate', 'subject-assertion', 'realmA', 'consumed');
    put('prot-jwt-grant-validate', 'subject-jti-record', 'Consumed external subject assertion jti', 'realmA', ['protGrantJti'], 'subject-assertion-replay', { related: ['subject-assertion'], details: 'Retained until assertion expiration; independent of client authentication replay state.' });
    put('prot-jwt-grant-validate', 'transient-session', 'Linked subject transient session', 'realmA', ['protTransientSession'], 'transient-sessions', { related: ['subject-link', 'subject-assertion'], releaseAt: 'prot-jwt-grant-response' });
    protToken('prot-jwt-grant-issue', 'prot-jwt-grant-response', [], ['subject-assertion', 'transient-session']);
  }

  const webTrust = (client) => {
    put(null, 'issuer-key', 'Realm A signing private key', 'realmA', ['webSigningPrivateKey'], 'signing-keys');
    put(null, 'api-trust', 'Configured trusted issuer JWKS and API policy', 'realmB', ['webJwksUri', 'webKeys', 'webPermissions'], 'trust');
    if (client) put(null, 'client-trust', 'OIDC client trusted issuer verification material', client, ['webJwksUri', 'webKeys', 'webClientId'], 'trust');
  };
  const webApi = (request, check, response, client, token = 'access-token', policy = 'Allowed algorithm/signature, exact issuer, intended orders-api audience, time and required orders:read permission') => {
    copy(request, token, client, 'realmB', 'tokens', request + ':token', response);
    see(check, token, 'realmB', 'accepted', policy, request, 'GET /orders');
  };
  const resource = (event, recipient, releaseAt = event) => {
    const id = event + ':resource';
    put(event, id, 'Authorized orders response', 'realmB', ['webResource', 'webHttpStatus'], 'output', { readableBy: ['realmB', recipient], values: { webHttpStatus: '200 OK' }, type: 'response' });
    copy(event, id, 'realmB', recipient, 'output', 'application-data', releaseAt, false);
    return id;
  };
  if (choice === 'lab-spa-api' || choice === 'lab-bff-api') {
    const bff = choice === 'lab-bff-api', p = bff ? 'web-bff' : 'web-spa', client = bff ? 'app' : 'browser';
    webTrust(client);
    if (bff) {
      put(null, 'bff-secret', 'BFF confidential client credential', 'app', ['webClientSecret', 'webClientId'], 'client-credentials');
      put(null, 'bff-registration', 'BFF client authentication registration', 'realmA', ['webClientSecret', 'webClientId'], 'client-registration');
    }
    for (const [id, attr, label] of [['web-state', 'webState', 'Original OIDC state'], ['oidc-nonce', 'webNonce', 'Original OIDC nonce']]) put(p + '-prepare', id, label, client, [attr], 'pending-attempt');
    put(p + '-prepare', 'web-verifier', 'Actual client PKCE verifier', client, ['webVerifier'], 'pending-attempt', { readableBy: [client, 'realmA'] });
    put(p + '-prepare', 'web-challenge', 'Public S256 commitment', client, ['webChallenge', 'webChallengeMethod'], 'pending-attempt', { readableBy: [client, 'realmA', 'browser'], derivedFrom: ['web-verifier'] });
    put(p + '-prepare', 'web-request', 'Public OIDC authorization request', client, WEB_REQUEST, 'pending-attempt', { readableBy: [client, 'realmA', 'browser'], related: ['web-state', 'oidc-nonce', 'web-challenge'] });
    if (bff) copy(p + '-redirect', 'web-request', 'app', 'browser', 'pending-attempt', 'authorization-navigation', p + '-authorize');
    copy(p + '-authorize', 'web-request', bff ? 'browser' : client, 'realmA', bff ? 'authorization-navigation' : 'pending-attempt', 'authorization-context', p + '-token-request');
    put(bff ? p + '-account-check' : p + '-auth-complete', 'account-context', 'Verified realm account and authorization context', 'realmA', ['webAuthContext'], 'account-context');
    put(p + '-code-return', 'web-code', 'Client/redirect/PKCE-bound code and callback state', 'realmA', ['webCode', 'webState', 'webClientId', 'webRedirectUri', 'webChallenge'], 'code-record', { readableBy: ['realmA', 'browser', client], related: ['web-challenge', 'account-context'] });
    copy(p + '-code-return', 'web-code', 'realmA', 'browser', 'code-record', 'callback-code', p + '-token-request');
    if (bff) copy(p + '-callback', 'web-code', 'browser', 'app', 'callback-code', 'callback-code', p + '-token-request');
    see(p + '-callback', 'web-state', client, 'matched', 'Original state and registered callback context before redemption');
    copy(p + '-token-request', 'web-code', client, 'realmA', 'callback-code', 'redemption-code', p + '-token-request');
    copy(p + '-token-request', 'web-verifier', client, 'realmA', 'pending-attempt', 'redemption-verifier', p + '-token-request');
    if (bff) {
      put(p + '-token-request', 'bff-basic', 'BFF Basic client authentication', 'app', ['webClientAuth'], 'output', { readableBy: ['app', 'realmA'], derivedFrom: ['bff-secret'] });
      copy(p + '-token-request', 'bff-basic', 'app', 'realmA', 'output', 'redemption-client-auth', p + '-token-request', false);
    }
    see(p + '-token-request', 'web-code', 'realmA', 'accepted', 'Single-use code, client/exact callback binding and S256 verifier equality' + (bff ? '; independent confidential client authentication' : '; public SPA client, no secret'));
    authority(p + '-token-request', 'web-code', 'realmA', 'consumed');
    put(p + '-tokens', 'id-token', 'OIDC ID token for ' + (bff ? 'BFF' : 'SPA'), 'realmA', ['webIdToken', 'webIssuer', 'webIdAudience', 'webSubject', 'webExpiry', 'webIssuedAt', 'webNonce', 'webAlgorithm', 'webSignature', 'webKid'], 'output', { readableBy: ['realmA', client], derivedFrom: ['issuer-key'], related: ['oidc-nonce'] });
    put(p + '-tokens', 'access-token', 'Orders API access token', 'realmA', WEB_ACCESS, 'output', { readableBy: ['realmA', client, 'realmB'], derivedFrom: ['issuer-key'] });
    copy(p + '-tokens', 'id-token', 'realmA', client, 'output', 'tokens', null, false);
    copy(p + '-tokens', 'access-token', 'realmA', client, 'output', 'tokens', null, false);
    const identity = bff ? p + '-session-create' : p + '-identity';
    see(identity, 'id-token', client, 'accepted', 'Trusted source/signature/algorithm, exact issuer, client audience/time and original nonce; not API permission');
    for (const id of ['web-state', 'oidc-nonce', 'web-verifier', 'web-challenge', 'web-request']) drop(identity, id, client, 'pending-attempt');
    plan.limitations.push('This fixture labels refresh_token optional without asserting a concrete issuance policy/value. This projection does not invent a refresh credential; ID and access tokens are issued.');
    if (bff) {
      put(identity, 'bff-session', 'Backend session and server token-store mapping', 'app', ['webSession'], 'sessions', { related: ['id-token', 'access-token'] });
      put(identity, 'bff-cookie', 'HttpOnly BFF browser cookie', 'app', ['webCookie'], 'output', { readableBy: ['app'], type: 'cookie', related: ['bff-session'], details: 'Browser cookie jar possesses opaque bytes. Browser frontend JavaScript cannot read HttpOnly value; no OAuth token is embedded.' });
      copy(p + '-cookie', 'bff-cookie', 'app', 'browser', 'output', 'http-only-cookie-jar', null, false);
      copy(p + '-data-request', 'bff-cookie', 'browser', 'app', 'http-only-cookie-jar', 'session-request', p + '-data-request');
      see(p + '-data-request', 'bff-session', 'app', 'accepted', 'Opaque cookie resolves local session; expiry and request policy checked', p + '-data-request', 'GET /api/orders');
    }
    webApi(p + '-api-request', p + '-api-verify', p + '-api-response', client);
    const response = resource(p + '-api-response', client, bff ? p + '-ui-response' : p + '-api-response');
    if (bff) {
      // BFF forwards only application data, never its token-store contents.
      plan.artifacts.find(item => item.artifactId === response).representations[0].readableBy.push('browser');
      copy(p + '-ui-response', response, 'app', 'browser', 'application-data', 'display-response', p + '-ui-response');
    }
  }
  if (choice === 'lab-api-errors') {
    put(null, 'api-trust', 'Configured issuer public keys and endpoint policy', 'realmB', ['webJwksUri', 'webKeys', 'webExpectedApiAudience', 'webPermissions'], 'trust');
    const cases = [
      ['expired-token', 'Expired credential', 'web-error-invalid-request', 'web-error-invalid-check', 'web-error-401', { webAccessToken: '<expired-access-token>', webExpiry: 'An instant before the API current time' }, '401 invalid_token', 'Token expiry fails; no protected data'],
      ['other-api-token', 'Authentic token intended for other-api', 'web-error-audience-request', 'web-error-audience-check', 'web-error-audience-401', { webAccessToken: 'Access-token JWS: aud=other-api, scope=orders:read; signed and unexpired', webApiAudience: 'other-api', webExpiry: 'An instant after the API current time' }, '401 invalid_token', 'Received aud other-api does not include locally configured orders-api; stop before scope checks'],
      ['read-only-token', 'Valid read token presented to POST', 'web-error-scope-request', 'web-error-permission', 'web-error-403', {}, '403 insufficient_scope', 'POST /orders needs orders:write; token grants only orders:read; token not revoked'],
      ['read-token', 'Independent successful GET credential', 'web-error-success-request', 'web-error-success-check', 'web-error-success-response', {}, '200 accepted', 'GET /orders intended audience, trust/time and orders:read accepted'],
    ];
    for (const [id, label, request, check, response, values, result, policy] of cases) {
      put(null, id, label, 'app', WEB_ACCESS, 'tokens', { readableBy: ['app', 'realmB'], values, details: 'Prior independently approved issuance; not repaired or replaced by another case response.' });
      copy(request, id, 'app', 'realmB', 'tokens', request + ':token', response);
      see(check, id, 'realmB', result, policy, request, id === 'read-only-token' ? 'POST /orders' : 'GET /orders');
      if (id === 'other-api-token') see('web-error-audience-trust', id, 'realmB', 'passed', 'Signature, exact issuer and time only; audience not checked yet', request);
      if (id === 'read-only-token') see('web-error-validity', id, 'realmB', 'passed', 'Signature, exact issuer/audience and time; permission not checked yet', request);
      if (id !== 'read-token') {
        const error = id + ':outcome';
        put(check, error, result + ' response', 'realmB', ['webHttpStatus', 'webChallengeHeader', 'webBearerError', ...(id === 'read-only-token' ? ['webRequiredScope'] : [])], 'output', { type: 'response', readableBy: ['realmB', 'app'], related: [id], values: { webHttpStatus: id === 'read-only-token' ? '403 Forbidden' : '401 Unauthorized', webChallengeHeader: id === 'read-only-token' ? 'Bearer error="insufficient_scope", scope="orders:write"' : 'Bearer error="invalid_token"', webBearerError: id === 'read-only-token' ? 'insufficient_scope' : 'invalid_token' } });
        copy(response, error, 'realmB', 'app', 'output', 'api-outcome', response, false);
      } else resource(response, 'app');
    }
  }
  if (choice === 'lab-api-introspection') {
    put(null, 'introspection-credential', 'API confidential introspection credential', 'realmB', ['webIntrospectionClientId', 'webIntrospectionSecret', 'webIntrospectionEndpoint'], 'introspection-credentials');
    put(null, 'introspection-registration', 'Registered API introspection client', 'realmA', ['webIntrospectionClientId', 'webIntrospectionSecret'], 'client-registration');
    for (const [id, request, query, response, check, end, active] of [
      ['introspected-token', 'web-intro-client-request', 'web-intro-query', 'web-intro-result', 'web-intro-api-check', 'web-intro-resource', true],
      ['inactive-token', 'web-intro-expired-request', 'web-intro-inactive-query', 'web-intro-inactive-note', 'web-intro-reject-inactive', 'web-intro-reject-inactive', false],
    ]) {
      put(null, id, active ? 'Prior-issued lightweight access token' : 'Independent expired access token', 'app', ['webAccessToken'], 'tokens', { readableBy: ['app', 'realmB', 'realmA'], values: { webAccessToken: active ? '<lightweight-access-token>' : '<expired-access-token>' } });
      copy(request, id, 'app', 'realmB', 'tokens', request + ':token', end);
      copy(query, id, 'realmB', 'realmA', request + ':token', query + ':token', response);
      const auth = id + ':query-auth';
      put(active ? 'web-intro-prepare' : query, auth, 'API Basic introspection authentication', 'realmB', ['webIntrospectionAuth'], 'output', { readableBy: ['realmB', 'realmA'], derivedFrom: ['introspection-credential'] });
      copy(query, auth, 'realmB', 'realmA', 'output', 'introspection-auth:' + id, query, false);
      see(query, auth, 'realmA', 'accepted', 'Authorized confidential API introspection caller; independent from bearer token status', query);
      const status = id + ':status';
      put(active ? 'web-intro-evaluate' : response, status, active ? 'Exact-token active=true result' : 'Exact-token active=false result', 'realmA', active ? ['webActive', 'webIssuer', 'webSubject', 'webApiAudience', 'webApiScope', 'webExpiry'] : ['webActive'], 'output', { type: 'introspection-response', readableBy: ['realmA', 'realmB'], related: [id], values: { webActive: active }, details: 'No persistent introspection cache: request-scoped receipt released after policy evaluation. Future requests require a new query.' });
      copy(response, status, 'realmA', 'realmB', 'output', 'introspection-status:' + id, check, false);
      see(response, id, 'realmB', active ? 'active=true' : 'active=false', 'Trusted endpoint/TLS and API client context; status belongs only to this exact token/query; no cache', query);
      see(check, id, 'realmB', active ? 'accepted' : '401 invalid_token', active ? 'active=true plus required claims, exact trusted issuer, orders-api audience, time and orders:read' : 'active=false prevents protected resource access; introspection HTTP 200 is not API acceptance', request, 'GET /orders');
    }
    resource('web-intro-resource', 'app');
    put('web-intro-reject-inactive', 'inactive-outcome', 'API 401 for inactive bearer token', 'realmB', ['webHttpStatus', 'webChallengeHeader', 'webBearerError'], 'output', { type: 'response', readableBy: ['realmB', 'app'], related: ['inactive-token'], values: { webHttpStatus: '401 Unauthorized', webChallengeHeader: 'Bearer error="invalid_token"', webBearerError: 'invalid_token' } });
    copy('web-intro-reject-inactive', 'inactive-outcome', 'realmB', 'app', 'output', 'api-outcome', 'web-intro-reject-inactive', false);
  }
  if (choice === 'lab-jwks-rotation') {
    put(null, 'issuer-key-1', 'K1 - issuer signing private key realm-sign-1', 'realmA', ['webSigningPrivateKey'], 'signing-keys', { values: { webSigningPrivateKey: 'Realm A private key realm-sign-1; local only' } });
    put(null, 'issuer-jwks-1', 'J1 - public realm-sign-1', 'realmA', ['webKeys'], 'published-jwks', { readableBy: ['realmA', 'realmB'], values: { webKeys: { keys: [{ kty: 'RSA', kid: 'realm-sign-1', use: 'sig', n: 'synthetic-public-modulus-1', e: 'AQAB' }] } }, related: ['issuer-key-1'] });
    put(null, 'jwks-cache-1', 'C1 - verifier cache {realm-sign-1}', 'realmB', ['webKeyCache'], 'jwks-cache', { values: { webKeyCache: ['realm-sign-1'] }, related: ['issuer-jwks-1'] });
    put(null, 'jwks-endpoint-policy', 'Pinned trusted JWKS URI and bounded refresh policy', 'realmB', ['webJwksUri', 'webRefreshBudget', 'webPermissions'], 'trust');
    put('web-rotation-new-key', 'issuer-key-2', 'K2 - issuer signing private key realm-sign-2', 'realmA', ['webSigningPrivateKey'], 'signing-keys');
    put('web-rotation-new-key', 'issuer-jwks-2', 'J2 - published overlapping public keys', 'realmA', ['webKeys'], 'published-jwks', { readableBy: ['realmA', 'realmB'], related: ['issuer-key-1', 'issuer-key-2'], values: { webKeys: { keys: [{ kty: 'RSA', kid: 'realm-sign-1', use: 'sig', n: 'synthetic-public-modulus-1', e: 'AQAB' }, { kty: 'RSA', kid: 'realm-sign-2', use: 'sig', n: 'synthetic-public-modulus-2', e: 'AQAB' }] } } });
    drop('web-rotation-new-key', 'issuer-jwks-1', 'realmA', 'published-jwks');
    put('web-rotation-sign', 'access-token', 'AT2 - token signed with realm-sign-2', 'realmA', WEB_ACCESS, 'output', { readableBy: ['realmA', 'app', 'realmB'], derivedFrom: ['issuer-key-2'], values: { webAccessToken: 'JWT signed with realm-sign-2', webKid: 'realm-sign-2' } });
    copy('web-rotation-issue', 'access-token', 'realmA', 'app', 'output', 'tokens', null, false);
    copy('web-rotation-api-request', 'access-token', 'app', 'realmB', 'tokens', 'rotation-request', 'web-rotation-success');
    see('web-rotation-unknown-kid', 'access-token', 'realmB', 'unknown-kid', 'C1 contains only realm-sign-1; not signature success. One trusted-source refresh allowed; token key hints ignored', 'rotation-api-request');
    see('web-rotation-jwks-request', 'jwks-endpoint-policy', 'realmB', 'refresh-budget-consumed', 'One refresh from pinned issuer endpoint; no arbitrary jku fetch', 'rotation-api-request');
    copy('web-rotation-jwks-response', 'issuer-jwks-2', 'realmA', 'realmB', 'published-jwks', 'jwks-response', 'web-rotation-jwks-response');
    put('web-rotation-jwks-response', 'jwks-cache-2', 'C2 - installed cache {realm-sign-1, realm-sign-2}', 'realmB', ['webKeyCache'], 'jwks-cache', { values: { webKeyCache: ['realm-sign-1', 'realm-sign-2'] }, derivedFrom: ['issuer-jwks-2'], replaces: ['jwks-cache-1'] });
    drop('web-rotation-jwks-response', 'jwks-cache-1', 'realmB', 'jwks-cache');
    see('web-rotation-verify', 'access-token', 'realmB', 'signature-verified', 'Exact AT2 signed with trusted key2 installed in C2; allowed RS256 and issuer checked', 'rotation-api-request');
    see('web-rotation-verify', 'access-token', 'realmB', 'accepted', 'Independent orders-api audience/time and orders:read authorization for this GET', 'rotation-api-request', 'GET /orders');
    resource('web-rotation-success', 'app');
  }
  // Complete each atomic delivery/check before releasing its temporary buffers.
  // Forwarding uses the same retained bytes until its explicitly authored send.
  for (const event of Object.values(plan.events)) for (const milestone of event.milestones) {
    milestone.effects = [...milestone.effects.filter(effect => effect.op !== 'release'), ...milestone.effects.filter(effect => effect.op === 'release')];
  }
  for (const actorId of actors) {
    const stores = [...new Set([...plan.initial, ...Object.values(plan.events).flatMap(event => event.milestones.flatMap(milestone => milestone.effects))].filter(effect => effect.op === 'acquire' && effect.actorId === actorId).map(effect => effect.store))];
    heldCoverage(plan, actorId, { stores, categories: actorId === 'user' ? ['summarized local interaction; no credential inventory asserted by this fixture'] : ['explicit fixture credentials, trust, request receipts, policy observations and release lifecycle'], rationale: 'Complete for this selected authored fixture. Configured factor ceremonies summarized by the source do not assert additional credential holdings.' });
  }
  return plan;
}
