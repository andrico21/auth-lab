import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Interaction and protocol-routing regressions. This harness is not a browser
// layout engine and does not make assertions about CSS geometry or rendering.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {ATTRIBUTES}=await import('../src/protocol-data.js');
const {ATTRIBUTE_TOPICS}=await import('../src/attribute-usage.js');
const {clock,document}=harness;
const text=node=>node.textContent.replace(/\s+/g,' ').trim();
const ids=steps=>[...new Set(steps.map(step=>step.sourceStepId))];
// Existing ownership and trace assertions target the explicitly configured
// native / two-realm / passkey core, independent of the beginner startup preset.
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function select(app,id,value){const control=app.querySelector('#'+id);assert.ok(control,id+' control exists');control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
function hover(node){node.dispatchEvent(new HarnessEvent('mouseover',{relatedTarget:null}));}
function finish(app){clock.until(()=>app.player.status!=='playing');}
function has(queue,{source,from,to,kind,attribute}){
  return queue.some(step=>(!source||step.sourceStepId===source)&&step.from===from&&step.to===to&&step.traceKind===kind&&step.payload.some(field=>field.attributeId===attribute));
}

test('the separate index stays available while participants and exchanges are inspected',()=>{
  const app=mount();try{
    const index=app.querySelector('aside#attribute-index');assert.ok(index);assert.equal(index.hidden,false);
    assert.ok(index.parentElement.classList.contains('study-sidebar'));
    assert.equal(index.querySelectorAll('[data-index-attribute]').length,Object.keys(ATTRIBUTES).length);
    const coreTopics=Object.entries(ATTRIBUTE_TOPICS).filter(([,topic])=>!topic.labScenarioId).map(([id])=>id).sort();
    assert.deepEqual(index.querySelectorAll('[data-trace-topic]').map(button=>button.dataset.traceTopic).sort(),coreTopics,'the core shows its shared topics; scenario-specific topics appear in their selected lab');
    app.refs.actors.querySelector('[data-actor="app"]').click();assert.equal(app.inspection.type,'actor');
    assert.equal(app.querySelector('#attribute-index'),index);assert.equal(index.hidden,false);
    app.refs.timeline.querySelector('[data-step="2"]').click();assert.equal(app.inspection.type,'step');
    assert.equal(app.querySelector('#attribute-index'),index);
    index.querySelector('#attribute-index-toggle').click();assert.equal(index.hidden,true);
    app.querySelector('#index-open').click();assert.equal(index.hidden,false);
  }finally{unmount(app);}
});

test('attribute search finds canonical names and distinguishes matching definitions from an empty result',()=>{
  const app=mount();try{
    const search=app.refs['attribute-search'];search.value='code_verifier';search.dispatchEvent(new HarnessEvent('input'));
    const visible=app.refs['attribute-index'].querySelectorAll('[data-index-attribute]').filter(button=>!button.hidden);
    assert.ok(visible.some(button=>button.dataset.indexAttribute==='codeVerifier'));
    assert.ok(visible.length<Object.keys(ATTRIBUTES).length,'search filters the separate index');
    search.value='no-such-protocol-field-42';search.dispatchEvent(new HarnessEvent('input'));
    assert.equal(app.refs['attribute-index'].querySelectorAll('[data-index-attribute]').filter(button=>!button.hidden).length,0);
    assert.equal(app.refs['attribute-index-empty'].hidden,false);
    search.value='';search.dispatchEvent(new HarnessEvent('input'));assert.equal(app.refs['attribute-index-empty'].hidden,true);
  }finally{unmount(app);}
});

test('PKCE selection shows birth, browser commitment, code binding and local server validation without exposing the verifier',()=>{
  const app=mount();try{
    app.refs['attribute-topics'].querySelector('[data-trace-topic="pkce"]').click();
    assert.equal(app.attributeSelection,'pkce');assert.equal(app.player.kind,'attribute');assert.equal(app.player.status,'playing');
    const queue=app.traceQueue;assert.ok(queue.length>5,'local processing is animated separately from transport');
    assert.deepEqual(ids(queue),['l02','l03','l04','l20','l23']);
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,queue.length);
    assert.equal(app.refs.inspector.querySelectorAll('[data-trace-step]').length,queue.length);
    assert.equal(app.refs['attribute-focus'].hidden,false);assert.ok(text(app.refs['attribute-focus']).includes('PKCE'));
    assert.ok(has(queue,{source:'l02',from:'app',to:'app',kind:'create',attribute:'codeVerifier'}));
    assert.ok(has(queue,{source:'l02',from:'app',to:'app',kind:'derive',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l03',from:'app',to:'browser',kind:'send',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l04',from:'browser',to:'realmA',kind:'send',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l04',from:'realmA',to:'realmA',kind:'store',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l20',from:'realmA',to:'realmA',kind:'use',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l23',from:'app',to:'realmA',kind:'send',attribute:'codeVerifier'}));
    assert.ok(has(queue,{source:'l23',from:'realmA',to:'realmA',kind:'derive',attribute:'codeChallenge'}));
    assert.ok(has(queue,{source:'l23',from:'realmA',to:'realmA',kind:'verify',attribute:'codeVerifier'}));
    for(const moment of queue){
      assert.ok(![moment.from,moment.to].includes('realmB'),'native PKCE is not forwarded to Realm B');
      assert.ok(moment.payload.length);assert.ok(moment.payload.every(field=>ATTRIBUTE_TOPICS.pkce.attributeIds.includes(field.attributeId)),'unrelated objects are excluded from focused playback');
      assert.equal(app.steps[moment.sourceIndex].id,moment.sourceStepId,'source journey index remains accurate');
      if(moment.from!==moment.to&&moment.payload.some(field=>field.attributeId==='codeVerifier'))assert.deepEqual([moment.sourceStepId,moment.from,moment.to],['l23','app','realmA']);
      if(moment.sourceStepId==='l20'||moment.sourceStepId==='l23'&&moment.payload.some(field=>field.attributeId==='codeChallenge'))assert.equal(moment.from,moment.to,'stored challenge is only processed locally');
    }
    assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').classList.contains('is-outside-trace'),true);
    assert.ok(app.actor('browser').attributes.some(field=>field.id==='codeChallenge'&&field.kind==='received'));
    assert.ok(app.actor('realmA').attributes.some(field=>field.id==='codeVerifier'&&field.kind==='received'));
    assert.ok(app.actor('realmA').attributes.some(field=>field.id==='codeChallenge'&&field.kind==='received'));
    const seen=[],packets=[];app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);if(event.type==='frame'&&event.visible)packets.push(event.packet.attributeId);});
    app.player.setSpeed(4);finish(app);
    assert.deepEqual(seen,queue.slice(1).map(moment=>moment.id),'subscription begins after the first selected moment');
    assert.ok(packets.includes('codeVerifier')&&packets.includes('codeChallenge'));
    assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');
    assert.equal(app.refs['attribute-index'].hidden,false);
  }finally{unmount(app);}
});

test('individual field clicks and actor-popup clicks open the same focused lifecycle',()=>{
  const app=mount();try{
    app.refs['attribute-index'].querySelector('[data-index-attribute="codeChallenge"]').click();
    assert.equal(app.attributeSelection,'codeChallenge');assert.ok(app.traceQueue.every(moment=>moment.payload.every(field=>field.attributeId==='codeChallenge')));
    assert.deepEqual(ids(app.traceQueue),['l02','l03','l04','l20','l23']);
    assert.ok(has(app.traceQueue,{source:'l23',from:'realmA',to:'realmA',kind:'verify',attribute:'codeChallenge'}));
    const appActor=app.refs.actors.querySelector('[data-actor="app"]');hover(appActor);
    const field=app.refs['actor-popup'].querySelector('[data-attribute="codeVerifier"]');assert.ok(field);field.click();
    assert.equal(app.attributeSelection,'codeVerifier');assert.deepEqual(app.inspection,{type:'attribute',id:'codeVerifier'});
    assert.equal(app.refs['actor-popup'].hidden,true);
    assert.deepEqual(ids(app.traceQueue),['l02','l23']);
    assert.ok(app.traceQueue.every(moment=>moment.payload.every(packet=>packet.attributeId==='codeVerifier')));
    assert.deepEqual(app.traceQueue.map(moment=>[moment.from,moment.to,moment.traceKind]),[
      ['app','app','create'],['app','app','store'],['app','app','use'],['app','realmA','send'],['realmA','realmA','verify'],
    ]);
  }finally{unmount(app);}
});

test('a connection in attribute mode replays only the selected field and unrelated connections cannot enter its queue',()=>{
  const app=mount();try{
    app.selectAttribute('codeChallenge',false);
    const local=app.refs.connections.querySelector('[data-pair="realmA--realmA"]');assert.ok(local);
    const expected=app.traceQueue.filter(step=>step.from==='realmA'&&step.to==='realmA');assert.ok(expected.length>1);
    local.querySelector('.connection-hit').click();assert.equal(app.player.kind,'attribute-connection');assert.deepEqual(app.player.queue,expected);
    const packets=[];app.player.subscribe(event=>{if(event.type==='frame'&&event.visible)packets.push(event.packet.attributeId);});
    const unrelated=app.refs.connections.querySelector('[data-pair="realmA--realmB"]');assert.ok(unrelated);assert.equal(unrelated.classList.contains('is-outside-trace'),true);
    assert.equal(unrelated.querySelector('.connection-hit').getAttribute('tabindex'),'-1');
    unrelated.querySelector('.connection-hit').click();assert.deepEqual(app.player.queue,expected);assert.equal(app.player.kind,'attribute-connection');
    app.player.setSpeed(4);finish(app);assert.ok(packets.length);assert.ok(packets.every(id=>id==='codeChallenge'));
    assert.equal(app.attributeSelection,'codeChallenge');assert.equal(app.refs['attribute-index'].hidden,false);
  }finally{unmount(app);}
});

test('focused playback controls preserve the selected field and clearing focus restores the full journey',()=>{
  const app=mount();try{
    app.selectAttribute('pkce');assert.equal(app.player.status,'playing');clock.frame();clock.advance(500);
    app.refs.play.click();assert.equal(app.player.status,'paused');const elapsed=app.player.elapsed;clock.advance(500);assert.equal(app.player.elapsed,elapsed);
    app.refs.speed.value='2';app.refs.speed.dispatchEvent(new HarnessEvent('input'));assert.equal(app.player.speed,2);
    app.refs.play.click();assert.equal(app.player.status,'playing');assert.equal(app.player.kind,'attribute');assert.equal(app.attributeSelection,'pkce');
    app.refs.inspector.querySelector('[data-trace-step="2"]').click();assert.equal(app.traceIndex,2);assert.equal(app.player.kind,'attribute-step');assert.equal(app.player.queue.length,1);
    assert.equal(app.player.queue[0],app.traceQueue[2]);
    app.refs.timeline.querySelector('[data-step="1"]').click();assert.equal(app.traceIndex,1);assert.equal(app.player.queue[0],app.traceQueue[1]);
    app.querySelector('#next').click();assert.equal(app.traceIndex,2);app.querySelector('#previous').click();assert.equal(app.traceIndex,1);
    app.querySelector('#reset').click();assert.equal(app.player.status,'idle');assert.equal(clock.frames.size,0);assert.equal(app.attributeSelection,'pkce');assert.equal(app.traceIndex,0);
    app.clearAttribute();assert.equal(app.attributeSelection,null);assert.equal(app.player.status,'idle');assert.equal(app.refs['attribute-focus'].hidden,true);
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
    app.refs.play.click();assert.equal(app.player.kind,'demo');assert.deepEqual(app.player.queue,app.steps);
  }finally{unmount(app);}
});

test('changing the journey or passkey device refreshes selected usages and cancels stale frames',()=>{
  const app=mount();try{
    app.selectAttribute('privateKey');assert.ok(app.traceQueue.some(step=>step.from==='hello'));
    select(app,'authenticator','yubikey');assert.equal(app.attributeSelection,'privateKey');assert.equal(app.player.status,'idle');assert.equal(clock.frames.size,0);
    assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>step.from==='yubikey'&&step.to==='yubikey'));
    select(app,'mode','password-totp');assert.equal(app.attributeSelection,'privateKey');assert.equal(app.traceQueue.length,0);assert.equal(app.player.status,'idle');
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,0);assert.ok(text(app.refs.inspector).match(/not used|no .*usage|no .*operation/i));
    app.selectAttribute('otpCode');assert.equal(app.player.kind,'attribute');assert.ok(app.traceQueue.some(step=>step.from==='totp'&&step.to==='totp'));
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='realmB'));
    assert.ok(app.traceQueue.some(step=>step.from==='realmB'&&step.to==='realmB'&&step.traceKind==='verify'));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('app')),'native application is not an OTP recipient');
  }finally{unmount(app);}
});

test('actor shortcuts refresh a focused trace and keep direct FIDO2 in the application RP journey',()=>{
  const app=mount();try{
    select(app,'mode','fido-login');app.selectAttribute('privateKey');
    app.inspectActor('hello');app.refs.inspector.querySelector('[data-use-authenticator="hello"]').click();
    assert.equal(app.mode,'fido-login');assert.equal(app.authenticator,'hello');assert.equal(app.player.status,'idle');
    assert.equal(app.attributeSelection,'privateKey');assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.every(step=>step.from==='hello'&&step.to==='hello'));
    assert.ok(app.steps.every(step=>step.directFido));
    app.inspectActor('totp');app.refs.inspector.querySelector('[data-use-totp]').click();
    assert.equal(app.mode,'password-totp');assert.equal(app.traceQueue.length,0);
    assert.ok(app.steps.some(step=>step.fields.includes('otpCode')));
    assert.ok(app.steps.every(step=>!step.directFido));assert.equal(clock.frames.size,0);
  }finally{unmount(app);}
});

test('web and independent-provider selections change callback and actor context while preserving PKCE boundaries',()=>{
  const app=mount();try{
    app.selectAttribute('pkce');select(app,'architecture','web');
    assert.equal(app.architecture,'web');assert.equal(app.attributeSelection,'pkce');assert.equal(app.player.status,'idle');assert.equal(clock.frames.size,0);
    assert.ok(text(app.refs.actors.querySelector('[data-actor="app"]')).includes('Web application'));
    const callback=app.steps.find(step=>step.from==='browser'&&step.to==='app'&&step.payload.some(field=>field.name==='code'));
    assert.ok(callback);assert.equal(callback.channel,'https');assert.ok(callback.payload.some(field=>String(field.value).includes('https://app.example.test/oidc/callback')));
    assert.ok(app.traceQueue.filter(step=>step.from!==step.to).every(step=>!step.payload.some(field=>field.attributeId==='codeVerifier')||step.from==='app'&&step.to==='realmA'));
    app.selectAttribute('clientSecretApp');assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.some(step=>step.from==='app'&&step.to==='realmA'&&step.traceKind==='send'));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('browser')),'confidential web client secret remains outside browser');
    select(app,'upstream','external');assert.equal(app.upstream,'external');assert.equal(app.attributeSelection,'clientSecretApp');
    const external=app.refs.actors.querySelector('[data-actor="realmB"]');
    assert.equal(text(external.querySelector('.actor-name')),'Generic external IdP');
    assert.equal(text(external.querySelector('.actor-role')),'Independent OIDC provider');
    app.selectAttribute('rpId',false);assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.every(step=>step.payload.every(field=>String(field.value).includes('login.partner.example.test'))));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmA')),'upstream WebAuthn RP remains separate from the broker');
    select(app,'architecture','native');app.selectAttribute('clientSecretApp',false);assert.equal(app.traceQueue.length,0);
  }finally{unmount(app);}
});

test('password-only and TOTP-only journeys identify the account and animate only their selected factor',()=>{
  const app=mount();try{
    select(app,'mode','password');assert.equal(app.refs.authenticator.disabled,true);
    assert.ok(app.steps.some(step=>step.fields.includes('password')));assert.ok(app.steps.every(step=>!step.fields.includes('otpCode')&&!step.fields.includes('signature')));
    app.selectAttribute('password');assert.ok(app.traceQueue.some(step=>step.from==='user'&&step.to==='browser'));
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='realmB'));
    assert.ok(app.traceQueue.some(step=>step.from==='realmB'&&step.to==='realmB'&&step.traceKind==='verify'));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('app')&&![step.from,step.to].includes('realmA')));
    select(app,'mode','one-time-code');assert.equal(app.attributeSelection,'password');assert.equal(app.traceQueue.length,0);
    assert.ok(app.steps.every(step=>!step.fields.includes('password')&&!step.fields.includes('signature')));
    const identify=app.steps.findIndex(step=>step.from==='browser'&&step.to==='realmB'&&step.fields.includes('loginUsername'));
    const otp=app.steps.findIndex(step=>step.from==='browser'&&step.to==='realmB'&&step.fields.includes('otpCode'));
    assert.ok(identify>=0&&otp>identify,'OTP-only flow identifies the account before requesting its enrolled factor');
    app.selectAttribute('loginUsername');assert.deepEqual(app.traceQueue.filter(step=>step.traceKind==='send').map(step=>[step.from,step.to]),[['user','browser'],['browser','realmB']]);
    app.selectAttribute('otpCode');assert.ok(app.traceQueue.some(step=>step.traceKind==='derive'&&step.from==='totp'&&step.to==='totp'));
    assert.ok(app.traceQueue.some(step=>step.traceKind==='verify'&&step.from==='realmB'&&step.to==='realmB'));
    const selected=app.traceQueue.map(step=>step.id),seen=[];app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.player.setSpeed(4);app.playAttribute();finish(app);
    assert.deepEqual(seen,selected);assert.equal(app.refs.progress.style.width,'100%');
  }finally{unmount(app);}
});

test('direct FIDO2 login makes the web application the RP and offers the selected authenticator without an OIDC broker',()=>{
  const app=mount();try{
    select(app,'mode','fido-login');assert.equal(app.architecture,'web');assert.equal(app.refs.architecture.value,'web');
    assert.equal(app.refs.architecture.disabled,true);assert.equal(app.refs.upstream.disabled,true);assert.equal(app.refs.authenticator.disabled,false);
    assert.ok(app.steps.length);assert.ok(app.steps.every(step=>step.directFido===true));
    assert.ok(app.steps.every(step=>![step.from,step.to].includes('realmA')&&![step.from,step.to].includes('realmB')));
    const oidc=new Set(['clientIdApp','clientIdBroker','clientSecret','clientSecretApp','redirectApp','redirectBroker','stateApp','stateBroker','nonceApp','nonceBroker','codeA','codeB','codeVerifier','codeChallenge','idTokenA','idTokenB','accessTokenA','accessTokenB']);
    assert.ok(app.steps.every(step=>step.fields.every(id=>!oidc.has(id))),'the direct RP ceremony contains no OIDC or native PKCE fields');
    const challenge=app.steps.find(step=>step.from==='app'&&step.to==='browser'&&step.fields.includes('challengeLogin'));assert.ok(challenge,'RP server supplies its own fresh challenge');
    const verify=app.steps.find(step=>step.from==='app'&&step.to==='app'&&step.fields.includes('signature'));assert.ok(verify,'the application RP verifies the assertion itself');
    assert.equal(app.definition('rpId').example,'app.example.test');assert.equal(app.definition('origin').example,'https://app.example.test');
    for(const id of ['realmA','realmB'])assert.equal(app.refs.actors.querySelector(`[data-actor="${id}"]`).classList.contains('is-muted'),true);
    select(app,'authenticator','yubikey');
    assert.ok(app.steps.some(step=>app.nodeId(step.from)==='browser'&&app.nodeId(step.to)==='yubikey'&&/ctap/i.test(step.channel)),'roaming security-key request uses CTAP2');
    assert.ok(app.refs.connections.querySelector('[data-pair="browser--yubikey"]'));
    assert.equal(app.refs.actors.querySelector('[data-actor="hello"]').classList.contains('is-muted'),true);
    app.selectAttribute('privateKey',false);assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.every(step=>step.from==='yubikey'&&step.to==='yubikey'&&step.traceKind==='use'),'sign-in uses an existing key; only enrollment creates one');
  }finally{unmount(app);}
});

test('the FIDO2 topic animates only application, browser, person and selected security-key operations',()=>{
  const app=mount();try{
    select(app,'mode','fido-login');select(app,'authenticator','yubikey');
    const topic=app.refs['attribute-topics'].querySelector('[data-trace-topic="fido2"]');assert.ok(topic);topic.click();
    assert.equal(app.attributeSelection,'fido2');assert.equal(app.player.kind,'attribute');assert.ok(app.traceQueue.length);
    const allowed=new Set(['user','app','browser','yubikey']);
    assert.ok(app.traceQueue.every(step=>allowed.has(step.from)&&allowed.has(step.to)),'direct proof excludes both Keycloak realms and the unselected device');
    assert.ok(app.traceQueue.some(step=>step.from==='app'&&step.to==='browser'&&step.payload.some(field=>field.attributeId==='challengeLogin')));
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='yubikey'&&/ctap/i.test(step.channel)));
    assert.ok(app.traceQueue.some(step=>step.from==='app'&&step.to==='app'&&step.traceKind==='verify'&&step.payload.some(field=>field.attributeId==='signature')));
    assert.ok(app.traceQueue.every(step=>step.payload.every(field=>!['codeVerifier','codeChallenge','codeChallengeMethod'].includes(field.attributeId))));
    const queue=app.traceQueue.map(step=>step.id),seen=[];app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.player.setSpeed(4);app.playAttribute();finish(app);
    assert.deepEqual(seen,queue);assert.equal(app.refs.progress.style.width,'100%');
    app.selectAttribute('pkce',false);assert.equal(app.traceQueue.length,0);assert.equal(app.player.status,'idle');
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,0);
  }finally{unmount(app);}
});

test('protected CTAP PIN/UV authorization stays between the client platform and roaming key',()=>{
  const app=mount();try{
    select(app,'mode','fido-login');select(app,'authenticator','yubikey');
    for(const id of ['pinUvAuthToken','pinUvAuthParam','pinUvAuthProtocol','ctapGetAssertion']){
      app.selectAttribute(id,false);assert.ok(app.traceQueue.length,id+' has explicit local CTAP operations');
      assert.ok(app.traceQueue.every(step=>['browser','yubikey'].includes(step.from)&&['browser','yubikey'].includes(step.to)),id+' never reaches the RP or identity providers');
      assert.ok(app.traceQueue.every(step=>step.payload.every(field=>field.attributeId===id)));
    }
    app.selectAttribute('pinUvAuthToken',false);
    assert.ok(app.traceQueue.some(step=>step.from==='yubikey'&&step.to==='browser'&&step.traceKind==='send'),'the key returns its protected token to the local client');
    app.selectAttribute('pinUvAuthParam',false);
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='yubikey'&&step.traceKind==='send'),'the client authenticates its CTAP command to the key');
    app.selectAttribute('localVerification',false);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('app')),'the RP receives signed verification evidence, not the local PIN operation');
    select(app,'authenticator','hello');app.selectAttribute('fido2',false);
    assert.ok(app.traceQueue.every(step=>step.from!=='yubikey'&&step.to!=='yubikey'));
    assert.ok(app.traceQueue.every(step=>!/ctap/i.test(step.channel)),'platform Hello is not labelled as the USB/NFC CTAP2 path');
    app.selectAttribute('pinUvAuthToken',false);assert.equal(app.traceQueue.length,0,'the roaming-key PIN protocol is not inserted into Hello');
  }finally{unmount(app);}
});

test('direct FIDO2 enrollment creates the private key only inside the authenticator and brokered modes restore their controls',()=>{
  const app=mount();try{
    select(app,'mode','fido-enrollment');select(app,'authenticator','yubikey');app.selectAttribute('privateKey');
    assert.ok(app.traceQueue.some(step=>step.traceKind==='create'));
    assert.ok(app.traceQueue.every(step=>step.from==='yubikey'&&step.to==='yubikey'),'credential private key stays local during creation and storage');
    assert.ok(app.traceQueue.every(step=>step.payload.every(field=>field.attributeId==='privateKey')));
    app.selectAttribute('credentialPublicKey');
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='app'),'registration sends only public credential data to the application RP');
    assert.ok(app.traceQueue.some(step=>step.from==='app'&&step.to==='app'&&step.traceKind==='store'),'the RP stores the public verification key');
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmB')));
    select(app,'mode','passkey');assert.equal(app.refs.architecture.disabled,false);assert.equal(app.refs.upstream.disabled,false);
    app.clearAttribute();select(app,'architecture','native');assert.equal(app.architecture,'native');
    assert.ok(app.steps.some(step=>step.from==='realmA'&&step.to==='realmB'));assert.ok(app.steps.some(step=>step.fields.includes('codeVerifier')));
    assert.ok(app.steps.every(step=>!step.directFido));
  }finally{unmount(app);}
});

test('single-realm setup makes A the factor verifier, RP and issuer while removing the broker participant',()=>{
  const app=mount();try{
    assert.deepEqual(app.refs.upstream.querySelectorAll('option').map(option=>option.getAttribute('value')).sort(),['external','keycloak','single']);
    select(app,'upstream','single');assert.equal(app.upstream,'single');assert.equal(app.isSingleRealm,true);
    const second=app.refs.actors.querySelector('[data-actor="realmB"]');assert.ok(second);assert.equal(second.hidden,true);assert.equal(second.classList.contains('is-muted'),true);
    assert.doesNotMatch(text(app.refs.actors.querySelector('[data-actor="realmA"]')),/broker/i);
    assert.equal(app.definition('rpId').example,'idp1.example.test');assert.equal(app.definition('origin').example,'https://idp1.example.test');
    assert.ok(app.steps.every(step=>![step.from,step.to].includes('realmB')));
    assert.ok(app.refs.connections.querySelectorAll('[data-pair]').every(connection=>!connection.dataset.pair.includes('realmB')));
    const brokerOnly=new Set(['clientIdBroker','clientSecret','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','issuerB','subjectB']);
    assert.ok(app.steps.every(step=>step.fields.every(id=>!brokerOnly.has(id))),'single-realm steps contain no upstream broker request, code or token fields');
    assert.ok(app.steps.some(step=>step.from==='realmA'&&step.to==='browser'&&step.fields.includes('challengeLogin')),'A supplies the WebAuthn challenge');
    assert.ok(app.steps.some(step=>step.from==='realmA'&&step.to==='realmA'&&step.fields.includes('signature')),'A verifies the credential proof');
    const callback=app.steps.find(step=>step.from==='browser'&&step.to==='app'&&step.fields.includes('codeA'));assert.ok(callback);assert.equal(callback.channel,'local');
    assert.ok(callback.payload.some(field=>String(field.value).includes('http://127.0.0.1:54321/callback')));
    const response=app.steps.find(step=>step.from==='realmA'&&step.to==='app'&&step.fields.includes('idTokenA'));assert.ok(response);
    assert.equal(response.payload.find(field=>field.name==='aud')?.value,'desktop-app');
    select(app,'authenticator','yubikey');app.selectAttribute('fido2',false);
    assert.ok(app.traceQueue.some(step=>step.from==='browser'&&step.to==='yubikey'&&/ctap/i.test(step.channel)));
    assert.ok(app.traceQueue.some(step=>step.from==='realmA'&&step.to==='realmA'&&step.traceKind==='verify'&&step.payload.some(field=>field.attributeId==='signature')));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmB')));
  }finally{unmount(app);}
});

test('factor and enrollment attribute traces target the single Keycloak realm',()=>{
  const app=mount();try{
    select(app,'upstream','single');select(app,'authenticator','yubikey');
    const cases=[
      ['passkey','signature','verify'],['password','password','verify'],['one-time-code','otpCode','verify'],
      ['password-totp','otpCode','verify'],['passkey-totp','otpCode','verify'],
      ['enrollment','credentialPublicKey','store'],['totp-enrollment','otpSecret','create'],
    ];
    for(const [mode,attribute,kind]of cases){
      select(app,'mode',mode);app.selectAttribute(attribute,false);assert.ok(app.traceQueue.length,mode+' has a replayable selected factor');
      assert.ok(app.traceQueue.some(step=>step.from==='realmA'&&step.to==='realmA'&&step.traceKind===kind),mode+' checks or stores the selected attribute in A');
      assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmB')),mode+' excludes B');
      assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,true);
    }
    select(app,'mode','enrollment');app.selectAttribute('rpId',false);assert.ok(app.traceQueue.length);
    assert.ok(app.traceQueue.every(step=>step.payload.every(field=>String(field.value).includes('idp1.example.test'))));
    select(app,'upstream','keycloak');assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,false);
    assert.ok(app.steps.some(step=>step.from==='browser'&&step.to==='realmB'));
  }finally{unmount(app);}
});

test('client_id is configured before sign-in, then selects and binds the native client without becoming a token claim',()=>{
  const app=mount();try{
    select(app,'upstream','single');
    const client=app.actor('app').attributes.find(attribute=>attribute.id==='clientIdApp');assert.ok(client);assert.equal(client.kind,'static');
    assert.equal(app.definition('clientIdApp').name,'client_id');assert.equal(app.definition('clientIdApp').example,'desktop-app');
    assert.match(app.definition('clientIdApp').origin,/register|administrator|configur/i);
    assert.match(app.definition('clientIdApp').meaning+' '+app.definition('clientIdApp').purpose,/public identifier|not a password|not a secret|not secret/i);
    const topic=app.refs['attribute-topics'].querySelector('[data-trace-topic="clientIdentity"]');assert.ok(topic);topic.click();
    assert.equal(app.attributeSelection,'clientIdentity');const queue=app.traceQueue;assert.ok(queue.length);
    assert.match(text(app.refs.inspector),/not a secret|not secret/i,'the pinned client identity explanation makes its public nature explicit');
    assert.ok(queue.every(step=>step.payload.every(field=>field.attributeId==='clientIdApp')));
    assert.ok(queue.every(step=>step.traceKind!=='create'),'the application does not generate a new client registration ID per sign-in');
    assert.ok(has(queue,{source:'single-l02',from:'app',to:'app',kind:'use',attribute:'clientIdApp'}));
    assert.ok(has(queue,{source:'single-l03',from:'app',to:'browser',kind:'send',attribute:'clientIdApp'}));
    assert.ok(has(queue,{source:'single-l04',from:'browser',to:'realmA',kind:'send',attribute:'clientIdApp'}));
    assert.ok(has(queue,{source:'single-l04',from:'realmA',to:'realmA',kind:'verify',attribute:'clientIdApp'}));
    assert.ok(has(queue,{source:'single-l20',from:'realmA',to:'realmA',kind:'use',attribute:'clientIdApp'}));
    const exchange=queue.find(step=>/l23$/.test(step.sourceStepId)&&step.from==='app'&&step.to==='realmA'&&step.traceKind==='send');assert.ok(exchange);
    assert.match(exchange.payload[0].description,/application\/x-www-form-urlencoded body/i);assert.equal(exchange.payload[0].value,'desktop-app');
    const audience=queue.filter(step=>/l24$/.test(step.sourceStepId));assert.ok(audience.length);assert.ok(audience.every(step=>step.from==='realmA'&&step.to==='realmA'),'the issuer uses its client registration ID locally when setting aud');
    assert.ok(queue.some(step=>/l25$/.test(step.sourceStepId)&&step.from==='app'&&step.to==='app'&&step.traceKind==='verify'),'the app compares token audience with its configured client_id');
    assert.ok(queue.every(step=>![step.from,step.to].includes('realmB')));
    const tokenResponse=app.steps.find(step=>step.from==='realmA'&&step.to==='app'&&step.fields.includes('idTokenA'));assert.ok(tokenResponse);assert.equal(tokenResponse.payload.some(field=>field.name==='client_id'),false);
    app.selectAttribute('clientIdApp',false);assert.deepEqual(app.traceQueue.map(step=>step.sourceStepId),queue.map(step=>step.sourceStepId),'the individual field and grouped client identity topic have the same lifecycle');
  }finally{unmount(app);}
});

test('web single-realm client_id is carried as Basic username, and direct FIDO has no OAuth client identity',()=>{
  const app=mount();try{
    select(app,'upstream','single');select(app,'architecture','web');app.selectAttribute('clientIdentity',false);
    assert.equal(app.definition('clientIdApp').example,'web-app');
    const exchange=app.steps.find(step=>step.from==='app'&&step.to==='realmA'&&step.channel==='backchannel'&&step.fields.includes('codeVerifier'));assert.ok(exchange);
    assert.ok(exchange.payload.some(field=>field.name==='Authorization'&&String(field.value).startsWith('Basic ')));
    assert.equal(exchange.payload.some(field=>field.name==='client_id'),false,'this configured confidential client uses HTTP Basic rather than duplicating client_id in the form');
    const transfer=app.traceQueue.find(step=>/l23$/.test(step.sourceStepId)&&step.from==='app'&&step.to==='realmA'&&step.traceKind==='send');assert.ok(transfer);
    assert.match(transfer.payload[0].description,/Authorization: Basic/i);assert.equal(transfer.payload[0].value,'web-app');
    const callback=app.steps.find(step=>step.from==='browser'&&step.to==='app'&&step.fields.includes('codeA'));assert.ok(callback);assert.equal(callback.channel,'https');
    assert.ok(callback.payload.some(field=>String(field.value).includes('https://app.example.test/oidc/callback')));
    assert.ok(app.traceQueue.every(step=>![step.from,step.to].includes('realmB')));
    app.player.setSpeed(4);app.playAttribute();finish(app);assert.equal(app.refs.progress.style.width,'100%');
    select(app,'mode','fido-login');app.selectAttribute('clientIdentity',false);assert.equal(app.traceQueue.length,0);assert.equal(app.player.status,'idle');
    app.selectAttribute('clientIdApp',false);assert.equal(app.traceQueue.length,0);assert.ok(app.steps.every(step=>!step.fields.includes('clientIdApp')));
  }finally{unmount(app);}
});
