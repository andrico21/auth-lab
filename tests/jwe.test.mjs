import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { JOURNEYS, getJourneySteps } from '../src/architecture-variants.js';
import { getFidoSteps } from '../src/fido-direct.js';
import { getSamlSteps } from '../src/saml-data.js';
import { getStepAttributeOperations, getAttributeUsage } from '../src/attribute-usage.js';
import { JWE_ATTRIBUTES, JWE_TOPIC_IDS, JWE_SOURCES, applyJweProtection, getJweActorOverrides, getJweAttributeOverrides } from '../src/jwe-data.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';

Object.assign(ATTRIBUTES,JWE_ATTRIBUTES);
const jweStages=['sign','prepare','encrypt','wrap','wire','unwrap','decrypt','verify-inner','validate-claims'];
const jweCanonical=step=>String(step.id).match(/(?:^|-)([a-z]\d{2})$/)?.[1];
const jweHopsOf=steps=>[...new Set(steps.map(step=>step.jweHop).filter(Boolean))].sort();
const jweWire=steps=>steps.filter(step=>step.jweStage==='wire');
const jweAllOperations=steps=>steps.flatMap(step=>getStepAttributeOperations(step));
const jweClaimIds=new Set(['issuerA','issuerB','subjectA','subjectB','audience','nonceApp','nonceBroker','exp','iat','acr','amr']);

test('JWE registry gives each hop RFC names, provenance, purpose and primary sources',()=>{
  assert.equal(JWE_TOPIC_IDS.length,30);assert.equal(new Set(JWE_TOPIC_IDS).size,30);
  for(const id of JWE_TOPIC_IDS){const def=JWE_ATTRIBUTES[id];for(const field of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(def[field],id+' '+field);assert.match(def.source,/rfc-editor\.org/);}
  assert.ok(JWE_SOURCES.some(source=>source.url.includes('keycloak.org')));
  assert.ok(JWE_ATTRIBUTES.jweRecipientPrivateKeyApp.purpose.includes('unrelated'));
  assert.match(JWE_ATTRIBUTES.jweProtectedHeaderApp.purpose,/AAD/);
});

test('all sign-in methods and architectures apply JWE independently to real OIDC hops',()=>{
  for(const mode of Object.keys(JOURNEYS))for(const architecture of ['native','web'])for(const upstream of ['single','keycloak','external'])for(const protection of ['signed','app-jwe','broker-jwe','both-jwe']){
    const base=getJourneySteps(mode,architecture,upstream),snapshot=JSON.stringify(base);
    const encrypted=applyJweProtection(base,{protection});
    const expected=[];
    if(!JOURNEYS[mode].enrollment){if(protection==='app-jwe'||protection==='both-jwe')expected.push('app');if(upstream!=='single'&&(protection==='broker-jwe'||protection==='both-jwe'))expected.push('broker');}
    assert.deepEqual(jweHopsOf(encrypted),expected,mode+':'+architecture+':'+upstream+':'+protection);
    assert.equal(JSON.stringify(base),snapshot,'JWE adapter must not mutate the reference steps');
    assert.equal(applyJweProtection(base,{protection}),encrypted,'Cached reference identity remains stable');
    if(!expected.length)assert.equal(encrypted,base);
    assert.equal(new Set(encrypted.map(step=>step.id)).size,encrypted.length);
    for(const hop of expected)assert.deepEqual(encrypted.filter(step=>step.jweHop===hop).map(step=>step.jweStage),jweStages);
  }
});

test('encrypted token wire has exactly five compact parts and no plaintext claims or secrets',()=>{
  for(const architecture of ['native','web'])for(const upstream of ['keycloak','external']){
    const encrypted=applyJweProtection(getJourneySteps('passkey',architecture,upstream),{protection:'both-jwe'});
    for(const wire of jweWire(encrypted)){
      assert.equal(wire.channel,'backchannel');assert.equal(wire.from==='realmB'?'realmA':'app',wire.to);
      const value=wire.payload.find(field=>field.name==='id_token').value,parts=value.split('.');assert.equal(parts.length,5);for(const part of parts)assert.match(part,/^[A-Za-z0-9_-]+$/);
      const header=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));assert.equal(header.alg,'RSA-OAEP-256');assert.equal(header.enc,'A256GCM');assert.equal(header.cty,'JWT');assert.equal(header.kid,wire.jweHop==='app'?'app-enc-2026':'broker-enc-2026');
      assert.equal(wire.payload.some(field=>['iss','aud','sub','nonce','exp','iat'].includes(field.name)),false);
      assert.equal(wire.attributeOperations.some(action=>jweClaimIds.has(action.attributeId)),false);
      assert.equal(wire.attributeOperations.some(action=>/Cek|PrivateKey|InnerJws|SigningPublicKey/.test(action.attributeId)),false);
      assert.equal(wire.payload.some(field=>/private|plaintext CEK/i.test(field.name)),false);
      assert.ok(wire.payload.some(field=>field.name==='access_token'),'ID-token encryption leaves the access-token response present');
    }
  }
});

test('CEK, decryption private key and signed plaintext have only local operations in selected traces',()=>{
  const encrypted=applyJweProtection(getJourneySteps('password','web'),{protection:'both-jwe'});
  for(const hop of ['App','Broker'])for(const kind of ['Cek','RecipientPrivateKey','InnerJws','SigningPublicKey']){
    const id='jwe'+kind+hop,usage=getAttributeUsage(encrypted,id),trace=buildAttributeTrace(usage);
    assert.ok(usage.length,id+' has real lifecycle steps');assert.equal(usage.some(item=>item.wireAttributeIds.includes(id)),false,id+' is not sent as plaintext');
    for(const step of trace)assert.equal(step.from,step.to,id+' stays local');
  }
  const appCek=getAttributeUsage(encrypted,'jweCekApp');
  assert.ok(appCek.some(item=>item.actions.some(action=>action.kind==='create'&&action.actorId==='realmA')));
  assert.ok(appCek.some(item=>item.actions.some(action=>action.kind==='derive'&&action.actorId==='app')));
  assert.ok(getAttributeUsage(encrypted,'jweEncryptedKeyApp').some(item=>item.wireAttributeIds.includes('jweEncryptedKeyApp')),'Only the encrypted CEK representation is carried');
});

test('code/client/PKCE checks precede encryption and identity mapping or sessions follow authenticated decryption',()=>{
  for(const architecture of ['native','web']){
    const encrypted=applyJweProtection(getJourneySteps('password-totp',architecture),{protection:'both-jwe'});
    for(const [hop,code,ordinary] of [['broker','l17','l19'],['app','l23','l25']]){
      const index=stage=>encrypted.findIndex(step=>step.jweHop===hop&&step.jweStage===stage);
      const codeIndex=encrypted.findIndex(step=>jweCanonical(step)===code),ordinaryIndex=encrypted.findIndex(step=>jweCanonical(step)===ordinary);
      assert.ok(codeIndex<index('sign'));assert.ok(index('sign')<index('encrypt'));assert.ok(index('encrypt')<index('wire'));assert.ok(index('unwrap')<index('decrypt'));assert.ok(index('decrypt')<index('verify-inner'));assert.ok(index('verify-inner')<index('validate-claims'));assert.ok(index('validate-claims')<ordinaryIndex);
    }
    const issuerUsage=getAttributeUsage(encrypted,'issuerA');assert.equal(issuerUsage.some(item=>item.step.jweHop==='app'&&item.wireAttributeIds.includes('issuerA')),false);
    assert.ok(issuerUsage.some(item=>item.step.jweStage==='validate-claims'&&item.actions.some(action=>action.kind==='derive'&&action.actorId==='app')));
    const ordinary=encrypted.find(step=>jweCanonical(step)==='l19');assert.ok(getStepAttributeOperations(ordinary).some(action=>action.attributeId==='subjectA'&&action.kind==='create'),'Original broker identity mapping remains');
  }
});

test('separate access/refresh token operations and public-native client authentication retain their boundaries',()=>{
  const base=getJourneySteps('password','native','single'),encrypted=applyJweProtection(base,{protection:'app-jwe'});
  const original=base.find(step=>jweCanonical(step)==='l24'),wire=jweWire(encrypted)[0];
  for(const id of ['accessTokenA','refreshToken','tokenType','expiresIn']){
    const expected=getStepAttributeOperations(original).filter(action=>action.attributeId===id&&['send','receive'].includes(action.kind));
    const actual=getStepAttributeOperations(wire).filter(action=>action.attributeId===id);assert.deepEqual(actual,expected);
    assert.equal(wire.payload.find(field=>field.name===ATTRIBUTES[id].name)?.value,original.payload.find(field=>field.name===ATTRIBUTES[id].name)?.value);
  }
  const tokenRequest=encrypted.find(step=>jweCanonical(step)==='l23');assert.equal(tokenRequest.payload.some(field=>field.name==='Authorization'||field.name==='client_secret'),false);
  assert.ok(getJweActorOverrides({protection:'app-jwe',steps:encrypted}).app.attributes.some(field=>field.id==='jweRecipientPrivateKeyApp'));
  assert.match(JWE_ATTRIBUTES.jweRecipientPublicKeyApp.purpose,/does not change a public client/);
});

test('only participating issuer/recipient actors gain JWE attributes; configuration cannot activate missing hops',()=>{
  const single=getJourneySteps('passkey','native','single');
  const actorOverrides=getJweActorOverrides({protection:'both-jwe',steps:single});
  assert.deepEqual(Object.keys(actorOverrides).sort(),['app','realmA']);assert.equal(Object.values(actorOverrides).flatMap(value=>value.attributes).some(attribute=>attribute.id.endsWith('Broker')),false);
  const issuer=actorOverrides.realmA.attributes.map(attribute=>attribute.id);assert.ok(issuer.includes('jweRecipientPublicKeyApp'));assert.equal(issuer.includes('jweRecipientPrivateKeyApp'),false);
  const defs=getJweAttributeOverrides({protection:'both-jwe',steps:single});assert.ok(defs.idTokenA);assert.equal(defs.idTokenB,undefined);
  assert.deepEqual(getJweActorOverrides({protection:'signed',steps:single}),{});
  assert.deepEqual(getJweAttributeOverrides({protection:'app-jwe',steps:getFidoSteps('fido-login','yubikey')}),{});
  assert.equal(jweAllOperations(applyJweProtection(getFidoSteps('fido-login'),{protection:'both-jwe'})).some(action=>action.attributeId.startsWith('jwe')),false);
});

test('mixed SAML composition encrypts only remaining OIDC token responses',()=>{
  const raw=getJourneySteps('password','web');
  // Protocol adapters replace the selected OIDC hop with SAML messages; final
  // JWE adaptation must inspect the resulting exchange rather than topology.
  const appSaml=raw.filter(step=>!['l20','l21','l22','l23','l24','l25'].includes(jweCanonical(step))).concat([{id:'saml-app-response',from:'realmA',to:'browser',samlHop:'app',fields:[],payload:[{name:'SAMLResponse',value:'base64(SAML XML)'}],attributeOperations:[]}]);
  const brokerSaml=raw.filter(step=>!['l05','l06','l07','l15','l16','l17','l18','l19'].includes(jweCanonical(step))).concat([{id:'saml-broker-response',from:'realmB',to:'browser',samlHop:'broker',fields:[],payload:[{name:'SAMLResponse',value:'base64(SAML XML)'}],attributeOperations:[]}]);
  assert.deepEqual(jweHopsOf(applyJweProtection(appSaml,{protection:'both-jwe'})),['broker']);
  assert.deepEqual(jweHopsOf(applyJweProtection(brokerSaml,{protection:'both-jwe'})),['app']);
  const onlySaml=[{id:'saml-l24',from:'realmA',to:'app',samlHop:'app',fields:[],payload:[{name:'SAMLResponse',value:'base64(SAML XML)'}],attributeOperations:[]}];
  assert.equal(applyJweProtection(onlySaml,{protection:'both-jwe'}),onlySaml);
});

test('real mixed SAML/OIDC adapters preserve independent encryption policies at both hops',()=>{
  for(const mode of ['password','passkey-totp'])for(const architecture of ['native','web'])for(const upstream of ['single','keycloak','external'])for(const [applicationProtocol,brokerProtocol] of [['saml','oidc'],['oidc','saml'],['saml','saml']])for(const encryptAssertions of [false,true])for(const protection of ['signed','app-jwe','broker-jwe','both-jwe']){
    const base=getSamlSteps({mode,architecture,upstream,applicationProtocol,brokerProtocol,encryptAssertions,authenticator:'yubikey'}),snapshot=JSON.stringify(base);
    const encrypted=applyJweProtection(base,{protection,authenticator:'yubikey'}),expected=[];
    if(applicationProtocol==='oidc'&&(protection==='app-jwe'||protection==='both-jwe'))expected.push('app');
    if(upstream!=='single'&&brokerProtocol==='oidc'&&(protection==='broker-jwe'||protection==='both-jwe'))expected.push('broker');
    assert.deepEqual(jweHopsOf(encrypted),expected,[applicationProtocol,brokerProtocol,upstream,protection].join(':'));
    assert.equal(JSON.stringify(base),snapshot,'JWE must not mutate SAML messages or factors');
    for(const step of encrypted.filter(step=>step.samlHop))assert.equal(step.jweHop,undefined,'XML assertions never become JWE');
    for(const wire of jweWire(encrypted))assert.equal(wire.payload.some(field=>field.name==='SAMLResponse'),false);
  }
});

test('local decrypted ID-token values never add plaintext tokens to application browser responses',()=>{
  const base=getJourneySteps('password','web'),encrypted=applyJweProtection(base,{protection:'both-jwe'});
  for(const [canonical,id] of [['l19','idTokenB'],['l25','idTokenA']]){
    const stage=encrypted.find(step=>jweCanonical(step)===canonical),original=base.find(step=>jweCanonical(step)===canonical);
    assert.match(stage.attributeValues[id],/Recovered inner JWS/);
    assert.deepEqual(stage.payload,original.payload,'Local trace values must not become wire payload fields');
    assert.deepEqual(getStepAttributeOperations(stage),getStepAttributeOperations(original),'Existing OIDC identity validation semantics remain unchanged');
  }
  const webSession=encrypted.find(step=>jweCanonical(step)==='l25');assert.equal(webSession.payload.some(field=>field.name==='id_token'),false);
});
