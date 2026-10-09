import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES, ACTORS } from '../src/protocol-data.js';
import { getAttributeUsage, getStepAttributeOperations } from '../src/attribute-usage.js';
import { PROTLAB_ATTRIBUTES, PROTLAB_SOURCES, PROTLAB_SCENARIOS } from '../src/protection-lab.js';

Object.assign(ATTRIBUTES, PROTLAB_ATTRIBUTES);
const scenario = id => PROTLAB_SCENARIOS.find(model => model.id === id);
const step = (model, id) => model.steps().find(item => item.id === id);
const wire = item => getStepAttributeOperations(item).filter(action => ['send', 'receive'].includes(action.kind));
const operations = (item, kind) => getStepAttributeOperations(item).filter(action => action.kind === kind);
const has = (item, id, kind) => operations(item, kind).some(action => action.attributeId === id);
const value = (item, id) => item.payload.find(field => field.attributeId === id)?.value;
const privateIds = new Set(['protClientPrivateKey', 'protRealmSigningKey', 'protTlsPrivateKey', 'protDpopPrivate', 'protGrantPrivate']);

test('all seven protection scenarios use immutable precise ledgers and only existing active actors', () => {
  assert.equal(PROTLAB_SCENARIOS.length, 7);
  const ids = new Set();
  for (const model of PROTLAB_SCENARIOS) {
    const config = { mode:'totp', architecture:'native', upstream:'external' }, before = JSON.stringify(config);
    const steps = model.steps(config), actors = model.actors(config), definitions = model.definitions(config);
    assert.equal(JSON.stringify(config), before); assert.equal(model.steps({}), steps);
    assert.equal(model.architecture, 'web'); assert.equal(model.protocol, 'oauth');
    assert.equal(model.universalLab, true); assert.equal(model.factorSelectable, false); assert.equal(model.jweAdaptable, false);
    assert.equal(new Set(steps.map(item => item.id)).size, steps.length);
    assert.ok(Object.isFrozen(steps)); assert.ok(Object.isFrozen(definitions));
    for (const item of steps) {
      assert.ok(Object.isFrozen(item)); assert.ok(Array.isArray(item.attributeOperations));
      assert.ok(ACTORS[item.from] && ACTORS[item.to]); assert.ok(actors[item.from] && actors[item.to]);
      for (const action of getStepAttributeOperations(item)) {
        assert.ok(definitions[action.attributeId], model.id + ': ' + action.attributeId);
        assert.ok(actors[action.actorId], action.actorId); ids.add(action.attributeId);
      }
      for (const field of item.fields) assert.ok(definitions[field], field);
    }
    for (const id of model.ids) assert.ok(getAttributeUsage(steps, id).length, model.id + ': ' + id);
    for (const actor of Object.values(actors)) for (const attribute of actor.attributes) assert.ok(definitions[attribute.id]);
    assert.ok(Object.keys(actors).length <= 4);
  }
  assert.deepEqual([...ids].sort(), Object.keys(PROTLAB_ATTRIBUTES).sort(), 'No orphaned index attributes.');
});

test('all private crypto keys stay within their owner and never appear in transmission operations', () => {
  const owner = {protClientPrivateKey:'app',protRealmSigningKey:'realmA',protTlsPrivateKey:'app',protDpopPrivate:'app',protGrantPrivate:'realmB'};
  for (const model of PROTLAB_SCENARIOS) for (const item of model.steps()) {
    for (const action of getStepAttributeOperations(item)) if (privateIds.has(action.attributeId)) {
      assert.equal(action.actorId, owner[action.attributeId]);
      assert.equal(['send','receive'].includes(action.kind), false, item.id + ': ' + action.attributeId);
      assert.equal(item.from, item.to, 'Private-key operation is local.');
    }
    assert.equal(wire(item).some(action => privateIds.has(action.attributeId)), false);
  }
});

test('private_key_jwt authenticates a separate grant using client_assertion and one configured audience', () => {
  const model = scenario('lab-client-jwt'), sign = step(model,'prot-client-jwt-sign'), request = step(model,'prot-client-jwt-request');
  assert.equal(value(request,'protServiceGrant'), 'client_credentials');
  assert.equal(value(request,'protCaType'), 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  assert.equal(PROTLAB_ATTRIBUTES.protCaIss.example, PROTLAB_ATTRIBUTES.protClientId.example);
  assert.equal(PROTLAB_ATTRIBUTES.protCaSub.example, PROTLAB_ATTRIBUTES.protClientId.example);
  assert.equal(typeof PROTLAB_ATTRIBUTES.protCaAud.example, 'string');
  assert.equal(PROTLAB_ATTRIBUTES.protCaAud.example, 'https://idp1.example.test/realms/realm-a');
  assert.ok(has(sign,'protClientPrivateKey','use')); assert.ok(has(sign,'protCaJwt','derive'));
  assert.equal(request.payload.some(field => field.name === 'assertion' || field.name === 'client_secret'), false);
  for (const id of ['protCaIss','protCaSub','protCaAud','protCaExp','protCaIat','protCaJti']) {
    const entries = wire(request).filter(action => action.attributeId === id);
    assert.equal(entries.length, 2); assert.ok(entries.every(action => action.carriedAs === 'client_assertion → signed JWT'));
  }
});

test('client-assertion replay and lifetime policy finishes before token issuance', () => {
  const model = scenario('lab-client-jwt'), verify = step(model,'prot-client-jwt-verify');
  for (const id of ['protClientId','protCaJwt','protCaIss','protCaSub','protCaAud','protCaExp','protCaIat','protCaJti','protCaReplay']) assert.ok(has(verify,id,'verify'), id);
  assert.ok(has(verify,'protClientPublicKey','use')); assert.ok(has(verify,'protCaReplay','store'));
  assert.match(verify.detail, /not declared universally mandatory in RFC 7523/);
  assert.ok(model.steps().indexOf(verify) < model.steps().indexOf(step(model,'prot-client-jwt-issue')));
  assert.equal(model.steps().some(item => ['browser','user'].includes(item.from) || ['browser','user'].includes(item.to)), false);
});

test('mutual TLS authentication and certificate binding are explicit separate settings', () => {
  const model = scenario('lab-mtls'), prepare = step(model,'prot-mtls-prepare'), bind = step(model,'prot-mtls-bind');
  assert.equal(PROTLAB_ATTRIBUTES.protTlsAuthMethod.example, 'tls_client_auth');
  assert.equal(PROTLAB_ATTRIBUTES.protTlsBoundSetting.example, 'true');
  assert.ok(has(prepare,'protTlsAuthMethod','use')); assert.ok(has(prepare,'protTlsBoundSetting','use'));
  assert.ok(has(bind,'protTlsAuthMethod','verify')); assert.ok(has(bind,'protTlsBoundSetting','verify'));
  assert.match(bind.detail, /DER\(whole X\.509 certificate\)/);
  assert.match(PROTLAB_ATTRIBUTES.protCertThumbprint.purpose, /not a public-key hash or JWK thumbprint/);
  const response = step(model,'prot-mtls-response');
  assert.equal(value(response,'protTokenType'), 'Bearer');
  assert.ok(wire(response).some(action => action.attributeId === 'protCertThumbprint' && action.carriedAs === 'access_token → signed JWT'));
});

test('the resource enforces the TLS certificate possession and exact token confirmation binding', () => {
  const model = scenario('lab-mtls'), request = step(model,'prot-mtls-api-request'), check = step(model,'prot-mtls-api-check');
  assert.match(value(request,'protBearerHeader'), /^Bearer /);
  for (const id of ['protTlsCertificate','protTlsProof','protCertThumbprint','protAccessToken','protApiAudience','protScope']) assert.ok(has(check,id,'verify'), id);
  assert.match(check.detail, /reject a missing or different certificate/);
  assert.match(check.detail, /generic adapters do not automatically provide this certificate-binding enforcement/);
  assert.equal(model.actors().realmB.role, 'OAuth resource server');
});

test('PAR pushes the complete request authenticated before returning an expiring reference', () => {
  const model = scenario('lab-par'), push = step(model,'prot-par-push'), store = step(model,'prot-par-store'), reference = step(model,'prot-par-reference');
  for (const id of ['protClientId','protRedirect','protResponseType','protScope','protState','protChallenge','protChallengeMethod','protBasic']) assert.ok(wire(push).some(action => action.attributeId === id), id);
  assert.equal(wire(push).some(action => action.attributeId === 'protVerifier'), false);
  assert.ok(has(store,'protParStoredRequest','store')); assert.ok(has(store,'protRequestUri','create'));
  assert.ok(has(store,'protBasic','verify'));
  assert.equal(reference.payload.find(field => field.name === 'HTTP').value, '201 Created');
  assert.equal(value(reference,'protRequestUri'), 'urn:ietf:params:oauth:request_uri:random_handle_14');
  assert.equal(value(reference,'protParExpiresIn'), '60 (illustrative)');
  assert.ok(model.steps().indexOf(store) < model.steps().indexOf(reference));
});

test('PAR browser request contains only client identity and handle, with binding/expiry/one-use checks', () => {
  const model = scenario('lab-par'), browser = step(model,'prot-par-browser'), resolve = step(model,'prot-par-resolve');
  assert.deepEqual([...new Set(wire(browser).map(action => action.attributeId))].sort(), ['protClientId','protRequestUri']);
  assert.match(browser.payload[0].value, /client_id=.*&request_uri=/);
  assert.doesNotMatch(browser.payload[0].value, /code_challenge|code_verifier|state=/);
  for (const id of ['protRequestUri','protClientId','protParExpiresIn','protParStoredRequest']) assert.ok(has(resolve,id,'verify'), id);
  assert.match(resolve.detail, /expired reference is rejected/);
  assert.match(resolve.detail, /permits deliberate duplicate handling for a browser refresh/);
});

test('JAR signs all request fields and forbids unsigned query fallback or client identity mismatch', () => {
  const model = scenario('lab-jar'), sign = step(model,'prot-jar-sign'), request = step(model,'prot-jar-authorize'), verify = step(model,'prot-jar-verify');
  assert.ok(has(sign,'protClientPrivateKey','use')); assert.ok(has(sign,'protRequestObject','derive'));
  for (const id of ['protClientId','protRedirect','protResponseType','protScope','protState','protChallenge','protChallengeMethod','protRoIss','protRoAud','protRoExp']) {
    assert.ok(wire(request).some(action => action.attributeId === id && action.carriedAs === 'request → signed Request Object'), id);
    assert.ok(has(verify,id,'verify'), id);
  }
  assert.match(verify.detail, /Outer and inner client_id must be identical/);
  assert.match(verify.checks.join(' '), /Only signed inner parameters used/);
  assert.match(step(model,'prot-jar-browser').detail, /omitted inner parameters cannot be recovered from unsigned query extras/);
  assert.ok(has(verify,'protClientPublicKey','use')); assert.ok(has(verify,'protRoReplay','verify'));
  assert.ok(has(verify,'protRoJti','use')); assert.equal(has(verify,'protRoJti','verify'), false);
  assert.equal(has(verify,'protRoReplay','store'), false);
  assert.match(verify.detail, /does not claim a stock Keycloak one-use jti cache/);
  assert.match(verify.detail, /disables that policy’s optional nbf check/);
  assert.equal(wire(request).some(action => action.attributeId === 'protCaJwt' || action.attributeId === 'protVerifier'), false);
});

test('JARM carries the code and original state only inside a response JWT on the browser callback', () => {
  const model = scenario('lab-jarm'), redirect = step(model,'prot-jarm-redirect'), callback = step(model,'prot-jarm-callback');
  assert.equal(PROTLAB_ATTRIBUTES.protResponseMode.example, 'query.jwt');
  assert.equal(redirect.payload[0].name, 'Location'); assert.match(redirect.payload[0].value, /\?response=/);
  assert.doesNotMatch(redirect.payload[0].value, /[?&](code|state)=/);
  assert.deepEqual(callback.payload.map(field => field.name), ['response']);
  for (const id of ['protCode','protState','protJarmIss','protJarmAud','protJarmExp']) assert.ok(wire(callback).some(action => action.attributeId === id && action.carriedAs === 'response → signed JARM JWT'), id);
  assert.equal(model.steps().some(item => item.payload.some(field => field.name === 'id_token')), false);
  assert.match(PROTLAB_ATTRIBUTES.protJarmResponse.purpose, /not an OIDC ID token/);
});

test('all JARM verification completes before grant-specific code processing and redemption', () => {
  const model = scenario('lab-jarm'), verify = step(model,'prot-jarm-verify'), ledger = getStepAttributeOperations(verify);
  const codeDerived = ledger.findIndex(action => action.attributeId === 'protCode' && action.kind === 'derive');
  for (const id of ['protJarmResponse','protJarmIss','protJarmAud','protJarmExp','protJarmAlg','protState']) {
    const index = ledger.findIndex(action => action.attributeId === id && action.kind === 'verify');
    assert.ok(index >= 0 && index < codeDerived, id);
  }
  assert.ok(has(verify,'protRealmPublicKey','use')); assert.ok(has(verify,'protJarmPending','store'));
  assert.match(verify.detail, /reject alg=none/);
  assert.ok(model.steps().indexOf(verify) < model.steps().indexOf(step(model,'prot-jarm-redeem')));
  assert.ok(has(step(model,'prot-jarm-sign'),'protRealmSigningKey','use'));
});

test('PAR, JAR and JARM preserve ordinary callback state and direct PKCE code redemption', () => {
  for (const id of ['lab-par','lab-jar','lab-jarm']) {
    const model = scenario(id), prefix = 'prot-' + id.slice(4), steps = model.steps();
    const start = step(model,prefix+'-start'), redeem = step(model,prefix+'-redeem'), verify = step(model,prefix+'-pkce-check');
    assert.ok(has(start,'protVerifier','create')); assert.ok(has(start,'protChallenge','derive'));
    const verifierWire = steps.flatMap(wire).filter(action => action.attributeId === 'protVerifier');
    assert.equal(verifierWire.length, 2); assert.equal(redeem.from, 'app'); assert.equal(redeem.to, 'realmA');
    assert.ok(has(verify,'protVerifier','verify')); assert.ok(has(verify,'protChallenge','verify'));
    assert.ok(steps.indexOf(step(model,prefix+'-approve')) < steps.indexOf(step(model,prefix+'-code')));
    for (const item of steps) if (item.from === 'browser' || item.to === 'browser') assert.equal(wire(item).some(action => ['protVerifier','protClientSecret'].includes(action.attributeId)), false, item.id);
  }
});

test('DPoP token and API proofs are separate, fresh and bound to the exact HTTP request', () => {
  const model = scenario('lab-dpop'), tokenSign = step(model,'prot-dpop-token-sign'), apiSign = step(model,'prot-dpop-api-sign'), retrySign = step(model,'prot-dpop-api-retry-sign');
  assert.equal(value(tokenSign,'protDpopHtm'), 'POST'); assert.equal(value(apiSign,'protDpopHtm'), 'GET');
  assert.equal(value(tokenSign,'protDpopHtu'), 'https://idp1.example.test/realms/realm-a/protocol/openid-connect/token');
  assert.equal(value(apiSign,'protDpopHtu'), 'https://orders.example.test/orders');
  assert.notEqual(value(tokenSign,'protDpopJti'), value(apiSign,'protDpopJti'));
  assert.notEqual(value(apiSign,'protDpopJti'), value(retrySign,'protDpopJti'));
  assert.equal(tokenSign.fields.includes('protDpopAth'), false); assert.equal(tokenSign.fields.includes('protDpopNonce'), false);
  assert.ok(has(apiSign,'protDpopAth','derive')); assert.equal(apiSign.fields.includes('protDpopNonce'), false);
  assert.ok(has(retrySign,'protDpopNonce','use'));
  for (const item of [tokenSign,apiSign,retrySign]) { assert.ok(has(item,'protDpopPrivate','use')); assert.ok(has(item,'protDpopJwk','use')); assert.equal(has(item,'protDpopPrivate','create'), false); }
  assert.equal(PROTLAB_ATTRIBUTES.protDpopTyp.example, 'dpop+jwt');
});

test('DPoP scheme and JWK confirmation are distinct from client authentication and certificate binding', () => {
  const model = scenario('lab-dpop'), tokenRequest = step(model,'prot-dpop-token-request'), response = step(model,'prot-dpop-token-response'), apiRequest = step(model,'prot-dpop-api-request');
  assert.ok(wire(tokenRequest).some(action => action.attributeId === 'protBasic')); assert.ok(wire(tokenRequest).some(action => action.attributeId === 'protDpopTokenProof'));
  assert.equal(value(response,'protTokenType'), 'DPoP'); assert.match(value(apiRequest,'protDpopAuthorization'), /^DPoP /);
  assert.match(PROTLAB_ATTRIBUTES.protDpopJkt.origin, /RFC 7638.*canonical required public JWK members/);
  assert.match(PROTLAB_ATTRIBUTES.protDpopJkt.purpose, /not an X.509 certificate thumbprint/);
  assert.match(PROTLAB_ATTRIBUTES.protDpopJwk.example, /no d/);
  assert.equal(model.steps().some(item => item.fields.includes('protCertThumbprint')), false);
});

test('API nonce challenge uses HTTP 401 and resource-specific nonce, then signs a new retry proof', () => {
  const model = scenario('lab-dpop'), challenge = step(model,'prot-dpop-api-challenge'), retry = step(model,'prot-dpop-api-retry');
  assert.equal(challenge.payload.find(field => field.name === 'HTTP').value, '401 Unauthorized');
  assert.equal(value(challenge,'protDpopChallenge'), 'DPoP error="use_dpop_nonce"');
  assert.ok(wire(challenge).some(action => action.attributeId === 'protDpopNonceHeader'));
  assert.match(challenge.detail, /token endpoint.*HTTP 400/);
  assert.match(step(model,'prot-dpop-api-challenge-create').detail, /API and authorization-server nonces are separate contexts/);
  assert.ok(wire(retry).some(action => action.attributeId === 'protDpopNonce' && /fresh nonce-bound API proof/.test(action.carriedAs)));
  assert.ok(model.steps().indexOf(challenge) < model.steps().indexOf(step(model,'prot-dpop-api-retry-sign')));
});

test('resource DPoP enforcement verifies ordinary token policy, proof-key thumbprint, exact ath and nonce', () => {
  const model = scenario('lab-dpop'), accept = step(model,'prot-dpop-api-accept');
  for (const id of ['protAccessToken','protApiAudience','protScope','protDpopApiProof','protDpopTyp','protDpopAlg','protDpopJwk','protDpopJti','protDpopHtm','protDpopHtu','protDpopIat','protDpopAth','protDpopNonce','protDpopJkt','protDpopReplay']) assert.ok(has(accept,id,'verify'), id);
  assert.ok(has(accept,'protRealmPublicKey','use')); assert.ok(has(accept,'protDpopReplay','store'));
  assert.match(accept.detail, /ASCII\(received access_token\)/);
  assert.match(accept.checks.join(' '), /Proof key thumbprint equals cnf.jkt/);
  assert.match(accept.checks.join(' '), /ath equals exact received access-token hash/);
});

test('JWT authorization grant assertion represents a linked external subject and authenticates the client separately', () => {
  const model = scenario('lab-jwt-grant'), request = step(model,'prot-jwt-grant-request'), verify = step(model,'prot-jwt-grant-validate');
  assert.equal(value(request,'protJwtGrant'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  assert.ok(request.payload.some(field => field.name === 'assertion')); assert.equal(request.payload.some(field => field.name === 'client_assertion'), false);
  assert.ok(wire(request).some(action => action.attributeId === 'protBasic'));
  assert.notEqual(PROTLAB_ATTRIBUTES.protGrantSub.example, PROTLAB_ATTRIBUTES.protClientId.example);
  for (const id of ['protGrantAssertion','protGrantIss','protGrantSub','protGrantAud','protGrantExp','protGrantIat','protGrantJti','protGrantPolicy','protGrantLink','protGrantReplay']) assert.ok(has(verify,id,'verify'), id);
  assert.ok(has(verify,'protGrantPublic','use')); assert.ok(has(verify,'protGrantReplay','store')); assert.ok(has(verify,'protTransientSession','create'));
  assert.equal(has(verify,'protGrantLink','create'), false, 'Existing linking is prerequisite.');
  assert.match(verify.detail, /exactly one configured issuer\/token-endpoint audience/);
  assert.match(step(model,'prot-jwt-grant-result').detail, /never issues a refresh token/);
  assert.equal(model.steps().some(item => item.payload.some(field => ['refresh_token','code','redirect_uri','code_verifier'].includes(field.name))), false);
});

test('support labels and source links distinguish current Keycloak features from explicit profile choices', () => {
  assert.ok(PROTLAB_SOURCES.every(source => source.url.startsWith('https://')));
  for (const model of PROTLAB_SCENARIOS) { assert.equal(model.status, 'Keycloak supported'); assert.ok(model.source.startsWith('https://')); assert.ok(model.supportNote); }
  for (const id of ['lab-par','lab-dpop','lab-jwt-grant']) assert.match(scenario(id).supportNote, /enabled by default/);
  assert.match(scenario('lab-dpop').supportNote, /explicit RFC 9449 resource-server policy/);
  assert.match(scenario('lab-jarm').supportNote, /other transports\/encryption remain variants/);
  assert.match(PROTLAB_ATTRIBUTES.protRoJti.purpose, /does not make it mandatory/);
  assert.match(PROTLAB_ATTRIBUTES.protGrantJti.purpose, /RFC 7523 itself makes jti optional/);
});
