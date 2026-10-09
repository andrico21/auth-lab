import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES, FLOWS } from '../src/protocol-data.js';
import { JOURNEYS, VARIANT_ATTRIBUTES, getJourneySteps } from '../src/architecture-variants.js';
import { FIDO_ATTRIBUTES, getStepAttributeOperations } from '../src/attribute-usage.js';
import { applyFidoTransport } from '../src/fido-direct.js';
import { SAML_ATTRIBUTES, SAML_TOPIC_IDS, SAML_SOURCES, normalizeSamlConfig, getSamlSteps, getSamlActorOverrides, getSamlAttributeOverrides, getSamlExampleOverrides } from '../src/saml-data.js';

Object.assign(ATTRIBUTES, VARIANT_ATTRIBUTES, FIDO_ATTRIBUTES, SAML_ATTRIBUTES);
const signModes=Object.keys(JOURNEYS).filter(mode=>!JOURNEYS[mode].enrollment);
const canonical=s=>s.id.match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const stage=(steps,hop,key)=>steps.find(s=>s.samlHop===hop&&s.samlStage===key);
const wireOps=s=>getStepAttributeOperations(s).filter(o=>['send','receive'].includes(o.kind));
const appOauth=new Set(['clientIdApp','clientSecretApp','authorizationHeaderApp','redirectApp','stateApp','nonceApp','codeVerifier','codeChallenge','codeChallengeMethod','codeA','idTokenA','accessTokenA','refreshToken']);
const brokerOauth=new Set(['clientIdBroker','clientSecret','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','issuerB','subjectB','authorizationHeader']);

test('SAML composes all factor methods, topologies, architectures and protocol hops without mutating reference data',()=>{
  const original=JSON.stringify(FLOWS);
  let combinations=0;
  for(const mode of Object.keys(JOURNEYS))for(const architecture of ['native','web'])for(const upstream of ['single','keycloak','external'])for(const applicationProtocol of ['oidc','saml'])for(const brokerProtocol of ['oidc','saml'])for(const binding of ['redirect','post'])for(const initiation of ['sp','idp'])for(const encryptAssertions of [false,true]){
    const config={mode,architecture,upstream,applicationProtocol,brokerProtocol,binding,initiation,encryptAssertions,authenticator:'yubikey'};
    const steps=getSamlSteps(config);assert.equal(getSamlSteps(config),steps,'Reuse cached model.');
    assert.equal(new Set(steps.map(s=>s.id)).size,steps.length);
    for(const s of steps){
      for(const actor of [s.from,s.to])assert.ok(actor==='authenticator'||ACTORS[actor],s.id+': '+actor);
      for(const id of s.fields)assert.ok(ATTRIBUTES[id],s.id+': '+id);
      for(const op of getStepAttributeOperations(s,'yubikey'))assert.ok(ATTRIBUTES[op.attributeId],s.id+': '+op.attributeId);
      if(upstream==='single')assert.ok(s.from!=='realmB'&&s.to!=='realmB',s.id);
    }
    if(JOURNEYS[mode].enrollment){assert.equal(steps.some(s=>s.samlHop),false);continue;}
    if(applicationProtocol==='saml'){
      assert.equal(normalizeSamlConfig(config).architecture,'web');
      assert.equal(steps.some(s=>s.fields.some(id=>appOauth.has(id))),false,JSON.stringify(config));
      assert.ok(stage(steps,'app','response-verify'));assert.ok(stage(steps,'app','session'));
    }
    if(upstream!=='single'&&brokerProtocol==='saml'){
      assert.equal(steps.some(s=>s.fields.some(id=>brokerOauth.has(id))),false,JSON.stringify(config));
      assert.ok(stage(steps,'broker','request-create'));assert.ok(stage(steps,'broker','map-account'));
    }
    const verifyId=mode==='password'?'p03':mode==='passkey'?'l14':'m05';
    const factor=steps.find(s=>canonical(s)===verifyId);assert.ok(factor,mode);
    const firstResult=steps.findIndex(s=>s.samlStage==='response-create'||canonical(s)==='l15'||canonical(s)==='l20');
    assert.ok(steps.indexOf(factor)<firstResult,mode+' required factors before identity result');
    assert.equal(steps.filter(s=>canonical(s)===verifyId).length,1);
    combinations++;
  }
  assert.equal(combinations,960);assert.equal(JSON.stringify(FLOWS),original);
});

test('mixed protocol compositions preserve only the OIDC client hop they actually implement',()=>{
  const a=getSamlSteps({mode:'passkey',upstream:'keycloak',applicationProtocol:'oidc',brokerProtocol:'saml',architecture:'native'});
  for(const id of ['l01','l02','l03','l04','l20','l21','l22','l23','l24','l25'])assert.ok(a.some(s=>canonical(s)===id),id);
  assert.equal(a.some(s=>['l05','l06','l07','l15','l16','l17','l18','l19'].includes(canonical(s))),false);
  const tokens=a.find(s=>canonical(s)==='l24');assert.equal(tokens.samlHop,undefined);assert.ok(tokens.payload.some(p=>p.name==='id_token'));
  assert.equal(stage(a,'broker','request-create').from,'realmA');assert.equal(stage(a,'broker','response-browser').to,'realmA');
  const b=getSamlSteps({upstream:'external',applicationProtocol:'saml',brokerProtocol:'oidc'});
  assert.ok(b.some(s=>canonical(s)==='l18'));assert.equal(b.find(s=>canonical(s)==='l18').samlHop,undefined);
  assert.equal(b.some(s=>canonical(s)==='l24'),false);assert.equal(stage(b,'app','response-browser').to,'app');
  const both=getSamlSteps({upstream:'external',applicationProtocol:'saml',brokerProtocol:'saml'});
  assert.equal(both.some(s=>s.payload.some(p=>p.name==='id_token')),false);
  assert.equal(stage(both,'broker','request-create').attributeValues.samlRequestDestination,'https://login.partner.example.test/saml/sso');
  assert.equal(stage(both,'app','request-create').attributeValues.samlRequestDestination,'https://idp1.example.test/realms/realm-a/protocol/saml');
  assert.notEqual(stage(both,'broker','response-browser').attributeValues.samlResponseDestination,stage(both,'app','response-browser').attributeValues.samlResponseDestination);
  const password=getSamlSteps({mode:'password-totp',upstream:'keycloak',applicationProtocol:'oidc',brokerProtocol:'saml'}).find(s=>canonical(s)==='p01');
  assert.match(password.detail,/A-B.*SAML/);assert.match(password.detail,/app-A.*OIDC/);assert.doesNotMatch(password.detail,/authorization code flow.*between A and B/);
});

test('Redirect and POST request bindings carry nested XML fields in honest chronological ledgers',()=>{
  for(const binding of ['redirect','post']){
    const steps=getSamlSteps({binding,upstream:'keycloak',applicationProtocol:'saml',brokerProtocol:'saml'});
    for(const hop of ['app','broker']){
      const suffix=hop==='app'?'App':'Broker',bind=stage(steps,hop,'request-bind'),browser=stage(steps,hop,'request-browser');
      const xmlIds=['samlAuthnRequest','samlRequestId'+suffix,'samlSpEntity'+suffix,'samlAcs'+suffix,'samlIssueInstant','samlRequestDestination','samlProtocolBinding'];
      for(const s of [bind,browser])for(const id of xmlIds){
        const operations=wireOps(s).filter(o=>o.attributeId===id);assert.equal(operations.length,2,id);assert.ok(operations.every(o=>/inside encoded SAMLRequest/.test(o.carriedAs)));
      }
      assert.equal(bind.samlBinding,binding);assert.equal(browser.samlBinding,binding);
      const ops=bind.attributeOperations;
      const encode=ops.findIndex(o=>o.attributeId==='samlRequest'&&o.kind==='derive');
      if(binding==='redirect'){
        assert.match(JSON.stringify(bind.payload),/RAW_DEFLATE/);assert.match(JSON.stringify(bind.payload),/SAMLRequest=.*&RelayState=.*&SigAlg=.*&Signature=/);
        assert.ok(encode<ops.findIndex(o=>o.attributeId==='samlRedirectSignature'&&o.kind==='derive'));
        assert.equal(bind.fields.includes('samlXmlSignature'),false);assert.match(bind.detail,/exact encoded/);
      }else{
        assert.match(JSON.stringify(bind.payload),/BASE64\(signed AuthnRequest XML\)/);assert.doesNotMatch(JSON.stringify(bind.payload),/RAW_DEFLATE/);
        assert.ok(ops.findIndex(o=>o.attributeId==='samlXmlSignature'&&o.kind==='derive')<encode);
        assert.equal(bind.fields.includes('samlSigAlg'),false);assert.match(bind.detail,/not the RelayState/);
      }
      for(const key of ['response-post','response-browser','response-verify'])assert.equal(stage(steps,hop,key).samlBinding,'post');
    }
  }
});

test('IdP-initiated app responses omit request correlation while broker requests remain independently SP-initiated',()=>{
  for(const upstream of ['single','keycloak','external']){
    const steps=getSamlSteps({upstream,initiation:'idp',brokerProtocol:'saml'}),app=steps.filter(s=>s.samlHop==='app');
    assert.equal(app.some(s=>s.samlStage.startsWith('request-')),false);
    assert.equal(app.some(s=>s.fields.includes('samlRequestIdApp')||s.fields.includes('samlInResponseToApp')),false);
    assert.equal(app.some(s=>s.attributeOperations.some(o=>['samlRequestIdApp','samlInResponseToApp','samlAuthnRequest'].includes(o.attributeId))),false);
    assert.doesNotMatch(JSON.stringify(stage(steps,'app','response-create').payload),/InResponseTo/);
    assert.ok(stage(steps,'app','response-verify').attributeOperations.some(o=>o.attributeId==='samlUnsolicitedPolicy'&&o.kind==='verify'));
    assert.match(stage(steps,'app','response-verify').detail,/login-CSRF/);
    if(upstream!=='single'){assert.equal(stage(steps,'broker','request-create').samlInitiation,'sp');assert.ok(stage(steps,'broker','response-create').fields.includes('samlInResponseToBroker'));}
    const actors=getSamlActorOverrides({upstream,initiation:'idp',brokerProtocol:'saml'});
    assert.equal(actors.app.attributes.some(a=>a.id==='samlRequestIdApp'),false);
    if(upstream==='single')assert.equal(actors.browser.attributes.some(a=>a.id==='samlRequest'),false);
  }
});

test('XML Encryption keeps plaintext claims and keys local and authenticates ciphertext before validating decrypted XML',()=>{
  const steps=getSamlSteps({upstream:'keycloak',applicationProtocol:'saml',brokerProtocol:'saml',encryptAssertions:true});
  const sensitive=new Set(['samlContentEncryptionKey','samlSigningKeyApp','samlSigningKeyA','samlSigningKeyB','samlDecryptKeyApp','samlDecryptKeyBroker']);
  for(const s of steps)for(const o of wireOps(s))assert.equal(sensitive.has(o.attributeId),false,s.id+': '+o.attributeId);
  for(const hop of ['app','broker']){
    const suffix=hop==='app'?'App':'Broker';
    for(const key of ['response-post','response-browser']){
      const s=stage(steps,hop,key);assert.ok(s.fields.includes('samlEncryptedAssertion'));
      for(const id of ['samlAssertion','samlNameId'+suffix,'samlAudience'+suffix,'samlRecipient'+suffix,'samlAuthnContext'+suffix,'samlAssertionId'+suffix])assert.equal(wireOps(s).some(o=>o.attributeId===id),false,id);
      assert.doesNotMatch(JSON.stringify(s.payload),/a-persistent-204|b-persistent-913/);
    }
    const encrypt=stage(steps,hop,'assertion-encrypt');
    assert.ok(encrypt.attributeOperations.some(o=>o.attributeId==='samlEncryptionAlgorithm'&&o.kind==='use'));
    const verify=stage(steps,hop,'response-verify'),ops=verify.attributeOperations;
    const outer=ops.findIndex(o=>o.attributeId==='samlXmlSignature'&&o.kind==='verify'),algorithm=ops.findIndex(o=>o.attributeId==='samlEncryptionAlgorithm'&&o.kind==='verify');
    const unwrap=ops.findIndex(o=>o.attributeId==='samlContentEncryptionKey'&&o.kind==='derive'),tag=ops.findIndex(o=>o.attributeId==='samlEncryptedAssertion'&&o.kind==='verify'),plain=ops.findIndex(o=>o.attributeId==='samlAssertion'&&o.kind==='derive');
    const inner=ops.findLastIndex(o=>o.attributeId==='samlXmlSignature'&&o.kind==='verify');
    assert.ok(outer<algorithm&&algorithm<unwrap&&unwrap<tag&&tag<plain&&plain<inner);
    assert.match(ops[tag].detail,/invalid authentication tag.*before releasing plaintext/);
    assert.match(encrypt.detail,/XML Encryption, not JWE/);
  }
});

test('assertion validation distinguishes audience, recipient, confirmation expiry and replay from authentication method policy',()=>{
  for(const mode of signModes){
    const steps=getSamlSteps({mode});const create=stage(steps,'app','response-create'),verify=stage(steps,'app','response-verify');
    assert.ok(create.payload.some(p=>p.name==='Conditions.NotBefore'));assert.ok(create.payload.some(p=>p.name==='SubjectConfirmationData.NotOnOrAfter'));
    assert.equal(create.payload.some(p=>p.name==='SubjectConfirmationData.NotBefore'),false);
    const validated=new Set(verify.attributeOperations.filter(o=>o.kind==='verify').map(o=>o.attributeId));
    for(const id of ['samlIdpEntityA','samlAudienceApp','samlRecipientApp','samlResponseDestination','samlNotBefore','samlNotOnOrAfter','samlSubjectExpiry','samlAuthnContextApp','samlReplayState','samlInResponseToApp'])assert.ok(validated.has(id),id);
    assert.ok(verify.attributeOperations.some(o=>o.attributeId==='samlReplayState'&&o.kind==='store'));
    const examples=getSamlExampleOverrides({mode});assert.equal(examples.samlAuthnContextApp,create.attributeValues.samlAuthnContextApp);
    assert.equal(examples.samlAuthnContextBroker,create.attributeValues.samlAuthnContextApp);
    assert.match(SAML_ATTRIBUTES.samlAuthnContextApp.purpose,/not an automatic MFA guarantee/);
  }
});

test('enrollment remains a verified-account credential ceremony rather than generating a fake SAML sign-in',()=>{
  for(const mode of ['enrollment','totp-enrollment'])for(const upstream of ['single','keycloak','external']){
    const config={mode,upstream,applicationProtocol:'saml',brokerProtocol:'saml',encryptAssertions:true,authenticator:'yubikey'};
    assert.equal(getSamlSteps(config),applyFidoTransport(getJourneySteps(mode,'web',upstream),'yubikey'));
    assert.equal(getSamlActorOverrides(config).app.attributes.some(a=>a.id==='samlSpEntityApp'),false);
  }
});

test('actors and index descriptions follow active protocols and never assign private server keys to the browser',()=>{
  assert.ok(SAML_SOURCES.every(s=>s.url.startsWith('https://')));assert.deepEqual(SAML_TOPIC_IDS,Object.keys(SAML_ATTRIBUTES));
  for(const upstream of ['single','keycloak','external'])for(const applicationProtocol of ['oidc','saml'])for(const brokerProtocol of ['oidc','saml']){
    const config={upstream,applicationProtocol,brokerProtocol,encryptAssertions:true},actors=getSamlActorOverrides(config),definitions=getSamlAttributeOverrides(config);
    assert.equal(getSamlActorOverrides(config),actors);assert.equal(getSamlAttributeOverrides(config),definitions);
    assert.equal(actors.browser.attributes.some(a=>/samlSigningKey|samlDecryptKey|samlContentEncryptionKey/.test(a.id)),false);
    if(applicationProtocol==='saml'){
      assert.equal(actors.app.attributes.some(a=>appOauth.has(a.id)),false);
      assert.match(definitions.sessionCookieApp.origin,/validating the signed SAML assertion/);assert.doesNotMatch(definitions.sessionCookieApp.purpose,/ID token/);
      assert.ok(actors.app.attributes.some(a=>a.id==='samlDecryptKeyApp'));
      if(upstream==='single')assert.doesNotMatch(actors.realmA.notes.join(' '),/OIDC|authorization code|tokens/);
    }else assert.ok(actors.app.attributes.some(a=>a.id==='clientIdApp'));
    if(upstream!=='single'&&brokerProtocol==='saml'){assert.doesNotMatch(actors.realmA.notes.join(' '),/confidential OIDC client.*upstream/);assert.doesNotMatch(actors.realmB.notes.join(' '),/returns (?:its own |an? )?OIDC|OIDC tokens/);}
  }
});
