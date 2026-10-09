import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// UI/model integration only: this harness does not perform network OAuth,
// cryptography, native device authentication, or actual browser rendering.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {SERVICE_ATTRIBUTES}=await import('../src/service-account-data.js');
const {DEVICE_ATTRIBUTES}=await import('../src/device-flow-data.js');
const {CIBA_ATTRIBUTES}=await import('../src/ciba-data.js');
const {EXCHANGE_ATTRIBUTES}=await import('../src/token-exchange-data.js');
const {clock,document}=harness;
const text=node=>node.textContent.replace(/\s+/g,' ').trim();
const loginModes=['passkey','password','one-time-code','password-totp','passkey-totp'];
const disabledModes=['enrollment','totp-enrollment','fido-login','fido-enrollment'];
const forbiddenCodeFields=new Set(['codeA','codeB','codeVerifier','codeChallenge','codeChallengeMethod','stateApp','stateBroker','nonceApp','nonceBroker','redirectApp','redirectBroker']);
// Grant integration below starts from the explicitly configured legacy core;
// the beginner startup preset is covered by its own learning-preset suite.
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function select(app,id,value){const control=app.querySelector('#'+id);assert.ok(control,id+' selector exists');control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
function finish(app){clock.until(()=>app.player.status!=='playing');}
function clearAndSelectFlow(app,flow){app.clearAttribute();select(app,'oidc-flow',flow);assert.equal(app.oidcFlow,flow);assert.ok(app.steps.length);}
function fieldPaths(app,id){app.selectAttribute(id,false);assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length,id+' has actual replayable operations');assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.traceQueue.length);return app.traceQueue;}
function assertSingleOidc(app){assert.equal(app.upstream,'single');assert.equal(app.refs.upstream.value,'single');assert.equal(app.applicationProtocol,'oidc');assert.equal(app.refs['app-protocol'].value,'oidc');}
function assertNoAuthorizationCode(app){assert.ok(app.steps.every(step=>step.fields.every(id=>!forbiddenCodeFields.has(id))),'the grant does not invent authorization-code, nonce, redirect or PKCE objects');}
function hover(node){assert.ok(node,'hover target exists');node.dispatchEvent(new HarnessEvent('mouseover',{relatedTarget:null}));}

test('the grant selector activates distinct single-realm models and retains the optional overlay preference',()=>{
  const app=mount();try{
    assert.deepEqual(app.refs['oidc-flow'].querySelectorAll('option').map(option=>option.getAttribute('value')).sort(),['authorization-code','client-credentials','device','ciba','token-exchange'].sort());
    assert.equal(app.refs['oidc-flow'].value,'authorization-code');
    const toggle=app.refs['show-step-attributes'];toggle.checked=false;toggle.dispatchEvent(new HarnessEvent('change'));
    select(app,'upstream','external');select(app,'app-protocol','saml');
    for(const flow of ['client-credentials','device','ciba','token-exchange']){
      clearAndSelectFlow(app,flow);assertSingleOidc(app);assert.equal(app.player.status,'idle');assert.equal(app.refs['step-attributes'].hidden,true);assert.equal(toggle.checked,false);
      if(flow!=='device'){assert.equal(app.architecture,'web');assert.equal(app.refs.architecture.disabled,true);}
      assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);assert.equal(new Set(app.steps.map(step=>step.id)).size,app.steps.length,'replayable stages have unique IDs');
      assert.ok(app.steps.every(step=>step.attributeOperations&&step.title&&step.summary&&step.detail&&step.payload.length));
      const summary=text(app.refs['protocol-summary']);assert.ok(/client.credentials|service account|Device|CIBA|exchange/i.test(summary),'summary explains the selected grant instead of an authorization-code login');
      app.player.setSpeed(4);const expected=app.steps.map(step=>step.id),seen=[],unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.refs.play.click();finish(app);unsubscribe();
      assert.deepEqual(seen,expected);assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');assert.equal(app.refs['step-attributes'].hidden,true);
    }
    clearAndSelectFlow(app,'authorization-code');assert.equal(app.isAdvancedFlow,false);assert.equal(app.refs.mode.disabled,false);assert.equal(app.refs.architecture.disabled,false);assert.equal(toggle.checked,false);
  }finally{unmount(app);}
});

test('service-account UI distinguishes application authentication from human MFA and traces the correct registered client',()=>{
  const app=mount();try{
    clearAndSelectFlow(app,'client-credentials');assertSingleOidc(app);assert.equal(app.refs.mode.disabled,true);assert.equal(app.refs.authenticator.disabled,true);assert.equal(app.refs['token-protection'].disabled,true);
    assert.ok(app.steps.every(step=>[step.from,step.to].every(id=>['app','realmA'].includes(id))));assertNoAuthorizationCode(app);
    assert.ok(app.steps.every(step=>!step.fields.includes('idTokenA')&&!step.fields.includes('refreshToken')),'the default service account receives access permission without an ID/refresh token');
    assert.equal(app.definition('clientIdApp').example,'orders-service');assert.equal(app.definition('grantType').example,'client_credentials');assert.match(app.definition('clientSecret').meaning,/service|application/i);
    const identity=fieldPaths(app,'clientIdApp');assert.ok(identity.some(step=>step.from==='app'&&step.to==='realmA'),'client ID is carried inside authenticated HTTPS Basic credentials');assert.ok(identity.every(step=>step.payload.every(field=>field.value==='orders-service')),'shared client_id examples belong to this registration');
    const signing=fieldPaths(app,'realmSigningKey');assert.ok(signing.every(step=>step.from==='realmA'&&step.to==='realmA'),'issuer private signing key remains local');
    for(const id of ['idTokenA','pkce','nonceApp']){app.selectAttribute(id,false);assert.equal(app.traceQueue.length,0,id+' is not a service-account identity flow');}
    for(const id of Object.keys(SERVICE_ATTRIBUTES))assert.ok(app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]'),id+' is available in the separate index');
  }finally{unmount(app);}
});

test('Device UI supports public native and confidential server clients with separate human and secret codes',()=>{
  const app=mount();try{
    clearAndSelectFlow(app,'device');assertSingleOidc(app);assert.equal(app.refs.mode.disabled,false);assert.equal(app.refs.architecture.disabled,false);assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,true);
    for(const mode of disabledModes)assert.equal(app.refs.mode.querySelector('[value="'+mode+'"]').disabled,true,mode+' cannot replace the device authorization factor ceremony');
    for(const architecture of ['native','web']){
      select(app,'architecture',architecture);assert.equal(app.architecture,architecture);assert.equal(app.definition('clientIdApp').example,architecture==='native'?'device-client':'device-confidential');
      assert.equal(app.actor('app').attributes.some(field=>field.id==='clientSecretApp'),architecture==='web');
      for(const mode of loginModes){
        select(app,'mode',mode);assert.ok(app.steps.some(step=>step.deviceStage==='factor'));assertNoAuthorizationCode(app);
        assert.ok(app.steps.every(step=>![step.from,step.to].includes('realmB')),'the configured factor runs in Realm A');
        assert.equal(app.refs.authenticator.disabled,!['passkey','passkey-totp'].includes(mode));
      }
      const privateCode=fieldPaths(app,'deviceCode');assert.ok(privateCode.some(step=>step.from==='app'&&step.to==='realmA'));
      assert.ok(privateCode.every(step=>![step.from,step.to].some(actor=>['browser','user','hello','yubikey'].includes(actor))),'private device_code never appears on the verification device');
      const humanCode=fieldPaths(app,'deviceUserCode');assert.ok(humanCode.some(step=>[step.from,step.to].includes('browser')||[step.from,step.to].includes('user')),'user_code connects the independent browser and device approval');
      app.selectAttribute('pkce',false);assert.equal(app.traceQueue.length,0);app.clearAttribute();
    }
    for(const id of Object.keys(DEVICE_ATTRIBUTES))assert.ok(app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]'));
  }finally{unmount(app);}
});

test('CIBA UI shows its controlled authentication service without turning it into another realm or broker',()=>{
  const app=mount();try{
    clearAndSelectFlow(app,'ciba');assertSingleOidc(app);assert.equal(app.architecture,'web');assert.equal(app.refs.mode.disabled,false);
    const service=app.refs.actors.querySelector('[data-actor="realmB"]');assert.equal(service.hidden,false);assert.match(text(service),/Trusted authentication service/);assert.match(text(service),/authentication.channel|controlled|CIBA/i);
    assert.equal(app.definition('clientIdApp').example,'ciba-client');assert.match(app.definition('clientSecretApp').meaning,/CIBA/);assertNoAuthorizationCode(app);
    for(const mode of disabledModes)assert.equal(app.refs.mode.querySelector('[value="'+mode+'"]').disabled,true);
    for(const mode of loginModes){select(app,'mode',mode);assert.ok(app.steps.some(step=>step.cibaStage==='factor'));assert.equal(app.refs.authenticator.disabled,!['passkey','passkey-totp'].includes(mode));}
    assert.match(app.definition('rpId').example,/authenticate\.example\.test/,'the authentication service owns its own WebAuthn RP');
    const channel=fieldPaths(app,'cibaChannelAuthorization');assert.ok(channel.some(step=>step.from==='realmA'&&step.to==='realmB'));assert.ok(channel.some(step=>step.from==='realmB'&&step.to==='realmA'));
    assert.ok(channel.every(step=>[step.from,step.to].every(actor=>['realmA','realmB'].includes(actor))),'callback bearer credentials are confined to the controlled server integration');
    const client=fieldPaths(app,'clientIdApp');assert.ok(client.every(step=>step.payload.every(field=>field.value==='ciba-client')),'focused shared client ID uses the consumption backend registration');
    for(const id of Object.keys(CIBA_ATTRIBUTES))assert.ok(app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]'));
  }finally{unmount(app);}
});

test('Token exchange UI starts with an existing token, shows requested resource audience, and produces no new login ceremony',()=>{
  const app=mount();try{
    clearAndSelectFlow(app,'token-exchange');assertSingleOidc(app);assert.equal(app.refs.mode.disabled,true);assert.equal(app.refs.authenticator.disabled,true);assert.equal(app.refs['token-protection'].disabled,true);
    assert.ok(app.steps.every(step=>[step.from,step.to].every(actor=>['app','realmA'].includes(actor))));assertNoAuthorizationCode(app);
    assert.ok(app.steps.every(step=>!step.payload.some(field=>field.name==='id_token')&&!step.jweStage));
    assert.equal(app.definition('exchangeClientId').example,'requester-client');assert.equal(app.definition('exchangeAudienceRequest').example,'orders-api');
    const source=fieldPaths(app,'exchangeSubjectToken');assert.ok(source.some(step=>step.traceKind==='store'&&step.from==='app'&&step.to==='app'));assert.ok(!source.some(step=>step.traceKind==='create'),'exchange never creates its prerequisite token');assert.ok(source.some(step=>step.from==='app'&&step.to==='realmA'));
    const target=fieldPaths(app,'exchangeAudienceRequest');assert.ok(target.some(step=>step.from==='app'&&step.to==='realmA'));
    const privateKey=fieldPaths(app,'exchangeSigningKey');assert.ok(privateKey.every(step=>step.from==='realmA'&&step.to==='realmA'));
    for(const id of Object.keys(EXCHANGE_ATTRIBUTES))assert.ok(app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]'));
  }finally{unmount(app);}
});

test('Device and CIBA can encrypt their app ID token without manufacturing nonce, PKCE or plaintext encrypted claims',()=>{
  const app=mount();try{
    for(const flow of ['device','ciba']){
      clearAndSelectFlow(app,flow);select(app,'token-protection','app-jwe');assert.equal(app.refs['token-protection'].disabled,false);assertNoAuthorizationCode(app);
      const wires=app.steps.filter(step=>step.jweStage==='wire');assert.equal(wires.length,1);assert.equal(wires[0].jweHop,'app');assert.deepEqual([wires[0].from,wires[0].to],['realmA','app']);
      assert.equal(wires[0].payload.find(field=>field.name==='id_token').value.split('.').length,5);
      const forbidden=new Set(['iss','sub','aud','nonce','exp','iat','auth_time','CEK','privateKey']);assert.ok(wires[0].payload.every(field=>!forbidden.has(field.name)),'encrypted wire does not show decrypted claim or secret-key packets');
      app.selectStep(app.steps.indexOf(wires[0]),true);const overlay=app.refs['step-attributes'];assert.equal(overlay.hidden,false);const displayed=overlay.querySelectorAll('code').map(text);assert.ok(displayed.includes('id_token'));assert.ok(displayed.includes('ciphertext'));assert.ok(displayed.every(name=>!forbidden.has(name)),'the link context also respects ciphertext boundaries');
      const recipient=fieldPaths(app,'jweRecipientPrivateKeyApp');assert.ok(recipient.every(step=>step.from==='app'&&step.to==='app'));
      for(const id of ['pkce','nonceApp','nonceBroker']){app.selectAttribute(id,false);assert.equal(app.traceQueue.length,0);}
      app.clearAttribute();app.player.setSpeed(4);const expected=app.steps.map(step=>step.id),seen=[],unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.refs.play.click();finish(app);unsubscribe();assert.deepEqual(seen,expected);assert.equal(app.player.status,'complete');
    }
  }finally{unmount(app);}
});

test('inactive grant fields and topics offer a working switch that preserves the selected lifecycle',()=>{
  const cases=[
    {flow:'client-credentials',field:'serviceAccountEnabled',topic:'serviceAccounts'},
    {flow:'device',field:'deviceCode',topic:'deviceFlow'},
    {flow:'ciba',field:'cibaAuthReqId',topic:'ciba'},
    {flow:'token-exchange',field:'exchangeSubjectToken',topic:'tokenExchange'},
  ];
  for(const scenario of cases)for(const kind of ['field','topic']){
    const app=mount();try{
      if(scenario.initial)clearAndSelectFlow(app,scenario.initial);
      const id=scenario[kind],selector=kind==='field'?'[data-index-attribute="'+id+'"]':'[data-trace-topic="'+id+'"]';
      app.refs['attribute-index'].querySelector(selector).click();assert.equal(app.attributeSelection,id);assert.equal(app.traceQueue.length,0,id+' is unused in the starting grant');
      const helper=app.refs.inspector.querySelector('[data-trace-grant="'+scenario.flow+'"]');assert.ok(helper,id+' offers its actual matching grant');helper.click();
      assert.equal(app.oidcFlow,scenario.flow);assertSingleOidc(app);assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length);assert.equal(app.player.kind,'attribute');assert.equal(app.player.status,'playing');
      assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.traceQueue.length);
      assert.ok(app.traceQueue.every(moment=>app.steps.some(source=>source.id===moment.sourceStepId)),'the projected moments belong to the newly selected grant');
      if(kind==='field')assert.ok(app.traceQueue.every(moment=>moment.payload.every(field=>field.attributeId===id)),'the exact clicked field stays selected');
      app.player.setSpeed(4);finish(app);assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');
    }finally{unmount(app);}
  }
});

test('machine-grant study can restore an actual JWE login or PKCE lifecycle through its inactive-field helpers',()=>{
  for(const machine of ['client-credentials','token-exchange'])for(const study of ['jwe','pkce']){
    const app=mount();try{
      clearAndSelectFlow(app,machine);const id=study==='jwe'?'jweRecipientPrivateKeyApp':'pkce';
      app.selectAttribute(id,false);assert.equal(app.traceQueue.length,0,'machine grants have no '+study+' identity lifecycle');
      const selector=study==='jwe'?'[data-trace-protocol="jwe"]':'[data-trace-grant="authorization-code"]';const helper=app.refs.inspector.querySelector(selector);assert.ok(helper);helper.click();
      assert.equal(app.oidcFlow,'authorization-code');assert.equal(app.isAdvancedFlow,false);assert.equal(app.applicationProtocol,'oidc');assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length);assert.equal(app.player.status,'playing');
      if(study==='jwe'){
        assert.equal(app.tokenProtection,'app-jwe');assert.ok(app.steps.some(step=>step.jweStage==='wire'&&step.jweHop==='app'));assert.ok(app.traceQueue.every(moment=>moment.from==='app'&&moment.to==='app'),'decryption key study remains with its owner');
      }else{
        assert.ok(app.traceQueue.some(moment=>moment.traceKind==='create'&&moment.payload.some(field=>field.attributeId==='codeVerifier')));
        assert.ok(app.traceQueue.some(moment=>moment.from==='app'&&moment.to==='realmA'&&moment.payload.some(field=>field.attributeId==='codeVerifier')));
        assert.ok(app.traceQueue.every(moment=>![moment.from,moment.to].includes('realmB')),'restored app PKCE is scoped to Realm A');
      }
      app.player.setSpeed(4);finish(app);assert.equal(app.player.status,'complete');
    }finally{unmount(app);}
  }
});

test('CIBA participant hover explains the controlled service RP and callback instead of upstream-realm attributes',()=>{
  const app=mount();try{
    clearAndSelectFlow(app,'ciba');hover(app.refs.actors.querySelector('[data-actor="realmB"] .actor-art'));
    const popup=app.refs['actor-popup'];assert.equal(popup.hidden,false);assert.match(text(popup),/Trusted authentication service/);
    for(const id of ['rpId','origin','rpIdHash','userHandle','cibaChannelAuthorization']){
      const field=popup.querySelector('[data-attribute="'+id+'"]');assert.ok(field,id+' belongs to the controlled service participant');hover(field.querySelector('code'));
      const tip=app.refs['attribute-popup'],definition=app.definition(id);assert.equal(tip.hidden,false);
      for(const value of [definition.meaning,definition.origin,definition.purpose,definition.example])assert.ok(text(tip).includes(String(value).replace(/\s+/g,' ').trim()),id+' exposes its scenario-specific metadata');
      assert.equal(tip.querySelector('a').getAttribute('href'),definition.source);
      assert.doesNotMatch(text(tip),/Realm B|B’s loaded|B checks|B compares|idp2\.example\.test/,'the authentication service is not the earlier upstream Realm B');
      if(['rpId','origin','rpIdHash'].includes(id))assert.match(text(tip),/authenticate\.example\.test/,'credential scope and browser origin belong to the controlled service');
      else if(id==='userHandle')assert.match(definition.purpose,/login_hint|authentication service|controlled service/i,'credential account mapping belongs to the delegated service verification');
      else assert.match(text(tip),/callback|result notification|notification/i);
    }
  }finally{unmount(app);}
});

test('machine-grant inactive factor helpers restore a compatible human factor and CTAP selects YubiKey',()=>{
  const factors=[
    {id:'password',modes:['password','password-totp']},
    {id:'otpCode',modes:['one-time-code','password-totp','passkey-totp']},
    {id:'privateKey',modes:['passkey','passkey-totp','enrollment','fido-login','fido-enrollment']},
    {id:'ctapGetAssertion',modes:['passkey','passkey-totp','fido-login'],authenticator:'yubikey'},
  ];
  for(const flow of ['client-credentials','token-exchange'])for(const scenario of factors){
    const app=mount();try{
      clearAndSelectFlow(app,flow);app.selectAttribute(scenario.id,false);assert.equal(app.traceQueue.length,0,'the machine has no '+scenario.id+' factor operation');
      const helper=app.refs.inspector.querySelector('[data-trace-grant="authorization-code"]');assert.ok(helper,scenario.id+' offers a real compatible human journey');
      assert.ok(scenario.modes.includes(helper.dataset.grantMode));if(scenario.authenticator)assert.equal(helper.dataset.grantAuthenticator,scenario.authenticator);
      helper.click();assert.equal(app.oidcFlow,'authorization-code');assert.ok(scenario.modes.includes(app.mode));assert.equal(app.attributeSelection,scenario.id);assert.ok(app.traceQueue.length);assert.equal(app.player.status,'playing');
      assert.ok(app.traceQueue.every(moment=>moment.payload.every(field=>field.attributeId===scenario.id)),'fallback preserves the selected factor object');
      if(scenario.authenticator){assert.equal(app.authenticator,'yubikey');assert.ok(app.steps.some(step=>step.channel==='ctap2'&&step.fields.includes('ctapGetAssertion')),'a CTAP trace comes from an actual local FIDO2 ceremony');}
      if(scenario.id==='privateKey')assert.ok(app.traceQueue.every(moment=>moment.from===moment.to&&['hello','yubikey'].includes(moment.from)),'private credential-key operations stay inside their authenticator');
      app.player.setSpeed(4);finish(app);assert.equal(app.player.status,'complete');
    }finally{unmount(app);}
  }
});

test('shared service-account topic fields do not animate an authorization-code journey under a service-account title',()=>{
  const app=mount();try{
    assert.equal(app.oidcFlow,'authorization-code');app.selectAttribute('clientIdApp',false);assert.ok(app.traceQueue.length,'the current auth-code registration genuinely uses client_id');
    app.selectAttribute('serviceAccounts',false);assert.equal(app.traceQueue.length,0,'the owning grant controls the service-account topic even though client_id is shared');
    assert.equal(app.player.status,'idle');assert.equal(app.refs.play.disabled,true);const helper=app.refs.inspector.querySelector('[data-trace-grant="client-credentials"]');assert.ok(helper);helper.click();
    assert.equal(app.oidcFlow,'client-credentials');assert.equal(app.attributeSelection,'serviceAccounts');assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(moment=>moment.sourceStepId.startsWith('service-')));assert.equal(app.player.status,'playing');
    app.player.setSpeed(4);finish(app);assert.equal(app.player.status,'complete');
  }finally{unmount(app);}
});

test('unsupported ID-token protection is normalized when changing to a grant without that token or broker',()=>{
  const app=mount();try{
    for(const flow of ['client-credentials','token-exchange']){
      clearAndSelectFlow(app,'authorization-code');select(app,'upstream','keycloak');select(app,'token-protection','app-jwe');assert.ok(app.steps.some(step=>step.jweStage==='wire'));
      clearAndSelectFlow(app,flow);assert.equal(app.tokenProtection,'signed');assert.equal(app.refs['token-protection'].value,'signed');assert.equal(app.refs['token-protection'].disabled,true);assert.ok(app.steps.every(step=>!step.jweStage));assert.ok(!/JWE/.test(text(app.refs['protocol-summary'])),'no encryption claim is shown for absent ID tokens');
    }
    for(const flow of ['device','ciba']){
      clearAndSelectFlow(app,'authorization-code');select(app,'upstream','keycloak');select(app,'token-protection','broker-jwe');assert.ok(app.steps.some(step=>step.jweStage==='wire'&&step.jweHop==='broker'));
      clearAndSelectFlow(app,flow);assert.equal(app.tokenProtection,'signed');assert.equal(app.refs['token-protection'].value,'signed');assert.equal(app.refs['token-protection'].querySelector('[value="broker-jwe"]').disabled,true);assert.ok(app.steps.every(step=>!step.jweStage),'a single-realm grant cannot retain an inactive broker-only encryption claim');
      select(app,'token-protection','app-jwe');assert.ok(app.steps.some(step=>step.jweStage==='wire'&&step.jweHop==='app'),'valid app protection remains available');
    }
  }finally{unmount(app);}
});
