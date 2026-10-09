import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// DOM/runtime interaction checks only. The harness does not render CSS or
// replace an actual browser, SAML verifier, JOSE implementation, or IdP.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {clock,document}=harness;
const text=node=>node.textContent.replace(/\s+/g,' ').trim();
const value=(step,name)=>step.payload.find(field=>field.name===name)?.value;
const options=node=>node.querySelectorAll('option').map(option=>option.getAttribute('value')).sort();
// Protocol assertions intentionally exercise the native / two-realm / passkey
// core instead of depending on the beginner startup preset.
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function select(app,id,value){const control=app.querySelector('#'+id);assert.ok(control,id+' selector exists');control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
function finish(app){clock.until(()=>app.player.status!=='playing');}
function encryptedWires(app){return app.steps.filter(step=>step.jweStage==='wire');}
const appOAuthFields=new Set(['clientIdApp','clientSecretApp','authorizationHeaderApp','redirectApp','stateApp','nonceApp','codeA','codeVerifier','codeChallenge','codeChallengeMethod','idTokenA','accessTokenA','refreshToken']);

test('protocol controls expose both app and broker protocols, SAML bindings and separate XML/JWE protection choices',()=>{
  const app=mount();try{
    const expected={
      'app-protocol':['oidc','saml'],'broker-protocol':['oidc','saml'],
      'saml-binding':['redirect','post'],'saml-initiation':['sp','idp'],
      'token-protection':['signed','app-jwe','broker-jwe','both-jwe'],
      'assertion-protection':['signed','encrypted'],
    };
    for(const [id,values]of Object.entries(expected)){const control=app.querySelector('#'+id);assert.ok(control);assert.deepEqual(options(control),values.sort());}
    assert.equal(app.querySelector('#app-protocol').value,'oidc');assert.equal(app.querySelector('#broker-protocol').value,'oidc');
    assert.equal(app.querySelector('#token-protection').value,'signed');assert.equal(app.querySelector('#assertion-protection').value,'signed');
    assert.equal(app.querySelector('#saml-binding').disabled,true);assert.equal(app.querySelector('#saml-initiation').disabled,true);assert.equal(app.querySelector('#assertion-protection').disabled,true);
    assert.ok(app.refs['attribute-topics'].querySelector('[data-trace-topic="saml"]'));assert.ok(app.refs['attribute-topics'].querySelector('[data-trace-topic="jwe"]'));
    select(app,'upstream','single');assert.equal(app.querySelector('#broker-protocol').disabled,true);assert.equal(app.querySelector('#token-protection [value="broker-jwe"]').disabled,true);
    select(app,'mode','fido-login');
    for(const id of Object.keys(expected))assert.equal(app.querySelector('#'+id).disabled,true,id+' does not change a direct WebAuthn ceremony');
    app.selectAttribute('saml',false);assert.equal(app.traceQueue.length,0);app.selectAttribute('jwe',false);assert.equal(app.traceQueue.length,0);
    select(app,'mode','passkey');assert.equal(app.querySelector('#app-protocol').disabled,false);assert.equal(app.querySelector('#broker-protocol').disabled,true);
  }finally{unmount(app);}
});

test('single-realm app SAML uses the web SP and browser assertion delivery instead of application OAuth parameters',()=>{
  const app=mount();try{
    select(app,'upstream','single');select(app,'app-protocol','saml');
    assert.equal(app.architecture,'web');assert.equal(app.refs.architecture.value,'web');assert.equal(app.refs.architecture.disabled,true);
    assert.equal(app.querySelector('#broker-protocol').disabled,true);assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,true);
    assert.ok(app.steps.some(step=>step.samlHop==='app'));assert.ok(app.steps.every(step=>![step.from,step.to].includes('realmB')));
    assert.ok(app.steps.every(step=>step.fields.every(id=>!appOAuthFields.has(id))),'application SAML has no OAuth client_id/code/nonce/PKCE/token exchange');
    const response=app.steps.filter(step=>step.samlHop==='app'&&step.payload.some(field=>field.name==='SAMLResponse'));
    assert.ok(response.some(step=>step.from==='realmA'&&step.to==='browser'));assert.ok(response.some(step=>step.from==='browser'&&step.to==='app'));
    app.selectAttribute('saml',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmB')));
    for(const id of ['pkce','clientIdentity','codeA','idTokenA']){app.selectAttribute(id,false);assert.equal(app.traceQueue.length,0,id+' is not an app SAML lifecycle');}
    app.clearAttribute();select(app,'app-protocol','oidc');assert.equal(app.refs.architecture.disabled,false);
  }finally{unmount(app);}
});

test('SAML request binding and initiation controls change the actual browser messages',()=>{
  const app=mount();try{
    select(app,'upstream','single');select(app,'app-protocol','saml');select(app,'saml-initiation','sp');
    for(const binding of ['redirect','post']){
      select(app,'saml-binding',binding);
      const requests=app.steps.filter(step=>step.samlHop==='app'&&String(step.samlStage).startsWith('request-'));
      assert.ok(requests.length,'SP initiation creates and delivers its AuthnRequest');
      assert.ok(requests.every(step=>step.samlBinding===binding),'the selected request binding is represented in the replayable protocol model');
      const transported=app.steps.filter(step=>step.samlHop==='app'&&step.payload.some(field=>field.name==='SAMLRequest'));
      assert.ok(transported.some(step=>step.from==='browser'&&step.to==='realmA'));
      const responses=app.steps.filter(step=>step.samlHop==='app'&&step.payload.some(field=>field.name==='SAMLResponse'));
      assert.ok(responses.some(step=>step.from==='browser'&&step.to==='app'));
      assert.ok(responses.every(step=>step.samlBinding==='post'),'Web SSO responses use the POST binding in both request scenarios');
    }
    app.selectAttribute('samlInResponseToApp',false);assert.ok(app.traceQueue.length,'SP-initiated response is correlated to its request');
    select(app,'saml-initiation','idp');
    assert.ok(app.steps.every(step=>!String(step.samlStage).startsWith('request-')),'IdP initiation does not invent an AuthnRequest');
    assert.ok(app.steps.every(step=>!step.payload.some(field=>field.name==='SAMLRequest')));
    app.selectAttribute('samlRequestIdApp',false);assert.equal(app.traceQueue.length,0);app.selectAttribute('samlInResponseToApp',false);assert.equal(app.traceQueue.length,0,'unsolicited response does not echo a nonexistent SP request');
    app.selectAttribute('samlResponseIdApp',false);assert.ok(app.traceQueue.length,'IdP initiation still creates and validates a SAML response');
  }finally{unmount(app);}
});

test('application and broker protocol controls support both mixed directions and two independent SAML hops',()=>{
  const app=mount();try{
    select(app,'broker-protocol','saml');
    assert.ok(app.steps.some(step=>step.samlHop==='broker'));assert.ok(app.steps.every(step=>step.samlHop!=='app'));
    assert.ok(app.steps.some(step=>step.fields.includes('codeVerifier')),'OIDC application PKCE is preserved with a SAML upstream');
    assert.ok(app.steps.some(step=>step.from==='realmA'&&step.to==='app'&&step.payload.some(field=>field.name==='id_token')));
    assert.ok(app.steps.every(step=>!step.fields.includes('idTokenB')),'the SAML upstream returns assertions rather than an OIDC broker ID token');
    select(app,'upstream','external');assert.match(text(app.refs.actors.querySelector('[data-actor="realmB"]')),/SAML/i,'external upstream is labelled for its actual SAML protocol');
    select(app,'app-protocol','saml');select(app,'broker-protocol','oidc');
    assert.match(text(app.refs['protocol-summary']),/SAML application.*OIDC broker/);
    assert.ok(app.steps.some(step=>step.samlHop==='app'));assert.ok(app.steps.every(step=>step.samlHop!=='broker'));
    assert.ok(app.steps.some(step=>step.from==='realmB'&&step.to==='realmA'&&step.payload.some(field=>field.name==='id_token')));
    assert.ok(app.steps.every(step=>step.fields.every(id=>!appOAuthFields.has(id))),'a SAML application does not acquire its own OIDC authorization/token exchange');
    app.selectAttribute('clientIdBroker',false);assert.ok(app.traceQueue.length,'Realm A still has its confidential OIDC broker registration');
    app.selectAttribute('clientIdentity',false);assert.equal(app.traceQueue.length,0,'the SAML SP entity identifier is not an application OAuth client_id');
    select(app,'broker-protocol','saml');assert.deepEqual([...new Set(app.steps.filter(step=>step.samlHop).map(step=>step.samlHop))].sort(),['app','broker']);
    assert.equal(app.querySelector('#token-protection').disabled,true);assert.equal(app.querySelector('#saml-binding').disabled,false);assert.equal(app.querySelector('#assertion-protection').disabled,false);
    assert.ok(app.steps.every(step=>!step.payload.some(field=>field.name==='id_token')),'two SAML hops contain no OIDC token response');
    for(const id of ['samlSpEntityApp','samlSpEntityBroker']){app.selectAttribute(id,false);assert.ok(app.traceQueue.length,'both SP registrations have explicit independent lifecycles');}
    app.selectAttribute('saml',false);assert.ok(app.traceQueue.some(step=>step.from==='realmB'||step.to==='realmB'));assert.ok(app.traceQueue.some(step=>step.from==='app'||step.to==='app'));
  }finally{unmount(app);}
});

test('encrypted SAML assertions use XML Encryption while signing keys, decryption keys and plaintext content keys stay local',()=>{
  const app=mount();try{
    select(app,'app-protocol','saml');select(app,'broker-protocol','saml');select(app,'assertion-protection','encrypted');
    assert.ok(app.steps.some(step=>step.samlHop==='app'&&step.fields.includes('samlEncryptedAssertion')));assert.ok(app.steps.some(step=>step.samlHop==='broker'&&step.fields.includes('samlEncryptedAssertion')));
    assert.equal(encryptedWires(app).length,0,'XML assertion encryption is not a five-part JWE ID token');
    app.selectAttribute('samlEncryptedAssertion',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.some(step=>step.from!==step.to),'the encrypted assertion is carried through browser response hops');
    for(const [id,actor]of [['samlSigningKeyApp','app'],['samlSigningKeyA','realmA'],['samlSigningKeyB','realmB'],['samlDecryptKeyApp','app'],['samlDecryptKeyBroker','realmA']]){
      app.selectAttribute(id,false);assert.ok(app.traceQueue.length,id+' is used in the selected signed/encrypted SAML journey');
      assert.ok(app.traceQueue.every(step=>step.from===actor&&step.to===actor),id+' remains with its owner');
    }
    app.selectAttribute('samlContentEncryptionKey',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>step.from===step.to),'the plaintext XML content-encryption key never becomes a browser or server packet');
    app.selectAttribute('samlNameIdApp',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>step.from===step.to),'the assertion subject is plaintext only before encryption and after recipient decryption');
    select(app,'token-protection','both-jwe');assert.equal(encryptedWires(app).length,0,'the JWE adapter does not reinterpret SAML XML messages');
  }finally{unmount(app);}
});

test('JWE remains available only on the OIDC side of a mixed SAML/OIDC journey',()=>{
  const app=mount();try{
    select(app,'broker-protocol','saml');select(app,'token-protection','both-jwe');assert.deepEqual(encryptedWires(app).map(step=>step.jweHop),['app']);
    select(app,'app-protocol','saml');select(app,'broker-protocol','oidc');select(app,'token-protection','both-jwe');assert.deepEqual(encryptedWires(app).map(step=>step.jweHop),['broker']);
    select(app,'broker-protocol','saml');assert.equal(encryptedWires(app).length,0);
  }finally{unmount(app);}
});

test('JWE app, broker and combined choices expand only their actual OIDC token-response hop',()=>{
  const app=mount();try{
    for(const [policy,hops]of [['signed',[]],['app-jwe',['app']],['broker-jwe',['broker']],['both-jwe',['app','broker']]]){
      select(app,'token-protection',policy);const wires=encryptedWires(app);
      assert.deepEqual(wires.map(step=>step.jweHop).sort(),hops);
      for(const wire of wires){
        assert.equal(wire.channel,'backchannel');assert.ok(![wire.from,wire.to].includes('browser'));
        const compact=value(wire,'id_token');assert.equal(typeof compact,'string');assert.equal(compact.split('.').length,5);
        for(const part of compact.split('.'))assert.match(part,/^[A-Za-z0-9_-]+$/,'compact parts are schematic base64url values');
        assert.ok(wire.payload.every(field=>!['iss','sub','aud','nonce','exp','iat','acr','amr','CEK','privateKey'].includes(field.name)),'encrypted response does not animate decoded claims or private material as wire fields');
        assert.deepEqual([wire.from,wire.to],wire.jweHop==='app'?['realmA','app']:['realmB','realmA']);
      }
      assert.ok(app.steps.filter(step=>step.channel==='redirect'||step.from==='browser'||step.to==='browser').every(step=>!step.jweHop),'encrypted ID tokens are not put into the browser redirect sequence');
    }
    select(app,'upstream','single');select(app,'token-protection','both-jwe');assert.deepEqual(encryptedWires(app).map(step=>step.jweHop),['app'],'single realm has no broker token response to encrypt');assert.equal(app.tokenProtection,'both-jwe','the chosen all-hop policy persists when only one actual OIDC hop exists');
    select(app,'mode','fido-login');assert.equal(encryptedWires(app).length,0);
  }finally{unmount(app);}
});

test('JWE study keeps recipient private keys and plaintext CEKs local and validates the inner identity after decrypting',()=>{
  const app=mount();try{
    select(app,'token-protection','both-jwe');
    for(const [suffix,issuer,recipient]of [['App','realmA','app'],['Broker','realmB','realmA']]){
      app.selectAttribute('jweRecipientPrivateKey'+suffix,false);assert.ok(app.traceQueue.length);
      assert.ok(app.traceQueue.every(step=>step.from===recipient&&step.to===recipient),'only the intended recipient uses its decryption private key');
      app.selectAttribute('jweCek'+suffix,false);assert.ok(app.traceQueue.length);
      assert.ok(app.traceQueue.every(step=>step.from===step.to&&[issuer,recipient].includes(step.from)),'plaintext CEK never becomes a network packet');
      assert.ok(app.traceQueue.some(step=>step.from===issuer&&step.traceKind==='create'));assert.ok(app.traceQueue.some(step=>step.from===recipient&&step.traceKind==='derive'));
      app.selectAttribute('jweInnerJws'+suffix,false);assert.ok(app.traceQueue.every(step=>step.from===step.to),'the signed JWT is plaintext only at issuer and recipient');
      const processing=app.steps.filter(step=>step.jweHop===suffix.toLowerCase());
      const wire=processing.findIndex(step=>step.jweStage==='wire'),unwrap=processing.findIndex(step=>step.jweStage==='unwrap'),decrypt=processing.findIndex(step=>step.jweStage==='decrypt'),signature=processing.findIndex(step=>step.jweStage==='verify-inner'),claims=processing.findIndex(step=>step.jweStage==='validate-claims');
      assert.ok(wire>=0&&unwrap>wire&&decrypt>unwrap&&signature>decrypt&&claims>signature,'authenticated decryption precedes inner issuer verification and claim acceptance');
    }
    app.selectAttribute('jwe',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('browser')));
    const queue=app.traceQueue.map(step=>step.id),seen=[];app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.player.setSpeed(4);app.playAttribute();clock.frame();clock.advance(500);
    app.refs.play.click();assert.equal(app.player.status,'paused');const elapsed=app.player.elapsed;clock.advance(500);assert.equal(app.player.elapsed,elapsed);
    app.refs.play.click();assert.equal(app.player.status,'playing');finish(app);assert.deepEqual(seen,queue);assert.equal(app.refs.progress.style.width,'100%');
    assert.equal(app.refs['attribute-index'].hidden,false);
  }finally{unmount(app);}
});

test('inactive index fields can activate the specific SAML or JWE configuration needed for their lifecycle',()=>{
  const cases=[
    {id:'samlSigningKeyB',protocol:'saml',setup:()=>{},verify:app=>{
      assert.equal(app.applicationProtocol,'oidc');assert.equal(app.brokerProtocol,'saml');
      assert.ok(app.traceQueue.every(step=>step.from==='realmB'&&step.to==='realmB'));
    }},
    {id:'samlUnsolicitedPolicy',protocol:'saml',setup:()=>{},verify:app=>{
      assert.equal(app.applicationProtocol,'saml');assert.equal(app.samlInitiation,'idp');
      assert.ok(app.steps.every(step=>step.samlHop!=='app'||!String(step.samlStage).startsWith('request-')));
      assert.ok(app.traceQueue.every(step=>step.from==='app'&&step.to==='app'));
    }},
    {id:'samlDecryptKeyApp',protocol:'saml',setup:()=>{},verify:app=>{
      assert.equal(app.applicationProtocol,'saml');assert.equal(app.assertionProtection,'encrypted');
      assert.ok(app.traceQueue.every(step=>step.from==='app'&&step.to==='app'));
    }},
    {id:'samlSigAlg',protocol:'saml',setup:app=>{select(app,'app-protocol','saml');select(app,'saml-binding','post');},verify:app=>{
      assert.equal(app.samlBinding,'redirect');assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='realmA'));
    }},
    {id:'jweRecipientPrivateKeyBroker',protocol:'jwe',setup:app=>{select(app,'upstream','single');select(app,'app-protocol','saml');},verify:app=>{
      assert.equal(app.upstream,'keycloak');assert.equal(app.applicationProtocol,'saml');assert.equal(app.brokerProtocol,'oidc');assert.equal(app.tokenProtection,'broker-jwe');
      assert.ok(app.traceQueue.every(step=>step.from==='realmA'&&step.to==='realmA'));
    }},
  ];
  for(const scenario of cases){const app=mount();try{
    scenario.setup(app);app.refs['attribute-index'].querySelector('[data-index-attribute="'+scenario.id+'"]').click();
    assert.equal(app.attributeSelection,scenario.id);assert.equal(app.traceQueue.length,0,scenario.id+' begins outside the selected protocol');
    const helper=app.refs.inspector.querySelector('[data-trace-protocol="'+scenario.protocol+'"]');assert.ok(helper,scenario.id+' has an activation helper');helper.click();
    assert.equal(app.attributeSelection,scenario.id);assert.ok(app.traceQueue.length,scenario.id+' now has a replayable path');assert.equal(app.player.status,'playing');assert.equal(app.player.kind,'attribute');
    assert.ok(app.traceQueue.every(step=>step.payload.every(field=>field.attributeId===scenario.id)),'activation preserves the focused field');
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.traceQueue.length);scenario.verify(app);
    app.player.setSpeed(4);finish(app);assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');
  }finally{unmount(app);}}
});

test('factor journeys remain selectable across SAML and JWE setups, and whole demos complete their protocol sequence',()=>{
  const app=mount();try{
    const configurations=[
      {'upstream':'single','app-protocol':'saml','broker-protocol':'oidc','token-protection':'signed','assertion-protection':'encrypted'},
      {'upstream':'keycloak','app-protocol':'oidc','broker-protocol':'saml','token-protection':'both-jwe','assertion-protection':'encrypted'},
      {'upstream':'keycloak','app-protocol':'saml','broker-protocol':'oidc','token-protection':'both-jwe','assertion-protection':'encrypted'},
    ];
    app.player.setSpeed(4);
    for(const configuration of configurations){
      app.clearAttribute();for(const [id,value]of Object.entries(configuration))select(app,id,value);
      for(const mode of ['passkey','password','one-time-code','password-totp','passkey-totp']){
        select(app,'mode',mode);assert.ok(app.steps.length);assert.equal(new Set(app.steps.map(step=>step.id)).size,app.steps.length,'protocol stages have distinct replay IDs');
        assert.ok(app.steps.every(step=>step.title&&step.summary&&step.detail&&step.payload.length));assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
        assert.equal(app.refs.authenticator.disabled,!['passkey','passkey-totp'].includes(mode));
      }
      const expected=app.steps.map(step=>step.id),seen=[],unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.refs.play.click();finish(app);unsubscribe();
      assert.deepEqual(seen,expected);assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');assert.equal(clock.frames.size,0);
    }
    for(const mode of ['enrollment','totp-enrollment']){
      select(app,'mode',mode);assert.ok(app.steps.length);assert.ok(app.steps.every(step=>!step.samlHop&&!step.jweHop),'credential enrollment is separate from SAML SSO and OIDC token encryption');
      for(const id of ['saml-binding','saml-initiation','token-protection','assertion-protection'])assert.equal(app.querySelector('#'+id).disabled,true,id+' is inactive in credential enrollment');
      assert.match(text(app.refs['protocol-summary']),/Credential enrollment/);
      assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
    }
  }finally{unmount(app);}
});
