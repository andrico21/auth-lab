import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Runtime checks for the animated link's optional names-only context card.
// The DOM harness does not render CSS or prove browser collision avoidance.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {clock,document}=harness;
const normalize=value=>String(value).replace(/\s+/g,' ').trim();
// Semantic fixtures: HTTP/API annotations are excluded, while real parameters
// nested in a carried object are included. These are not computed by the app's
// overlay helper or generated from its DOM.
const defaultNames={
  l01:[],
  l02:['client_id','redirect_uri','state','nonce','code_verifier','code_challenge_method','code_challenge'],
  l03:['client_id','redirect_uri','state','nonce','code_challenge','code_challenge_method','scope','response_type'],
  l04:['client_id','redirect_uri','state','nonce','code_challenge','code_challenge_method','scope','response_type'],
  l05:['client_id','redirect_uri','state','nonce'],
  l06:['Location','client_id','redirect_uri','state','nonce','scope','response_type'],
  l07:['client_id','redirect_uri','state','nonce','scope','response_type'],
  l08:['challenge','rpId / rp.id','allowCredentials','userVerification','timeout'],
  l09:['rpId / rp.id','clientDataHash','userVerification'],
  l10:['User verification'],
  l11:['rpId / rp.id','privateKey','rpIdHash','UP','UV','signCount','authenticatorData','clientDataHash','signature'],
  l12:['id / rawId','authenticatorData','signature','userHandle'],
  l13:['id / rawId','type','clientDataJSON','authenticatorData','signature','userHandle','challenge','origin','clientDataJSON.type','crossOrigin','rpIdHash','UP','UV','signCount'],
  l14:['id / rawId','userHandle','clientDataJSON.type','challenge','origin','rpIdHash','UP','UV','crossOrigin','credentialPublicKey','signature','signCount'],
  l15:['Location','code','state','redirect_uri'],
  l16:['code','state','redirect_uri'],
  l17:['grant_type','code','redirect_uri','Authorization','client_id','client_secret'],
  l18:['id_token','access_token','token_type','expires_in','iss','aud','sub','nonce','exp','iat'],
  l19:['jwks_uri','id_token','iss','aud','exp','nonce','sub','authentication session / SSO session'],
  l20:['Location','code','state','redirect_uri'],
  l21:['redirect_uri','code','state'],
  l22:['state','redirect_uri','code'],
  l23:['client_id','grant_type','code','redirect_uri','code_verifier'],
  l24:['id_token','access_token','token_type','expires_in','refresh_token','iss','aud','sub','nonce','exp','iat'],
  l25:['client_id','jwks_uri','id_token','iss','aud','exp','iat','nonce','sub','acr','amr'],
};
// The fixed l01-l25 name sets describe the explicitly configured legacy
// native / two-realm / passkey core, not the beginner startup preset.
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function select(app,id,value){const control=app.querySelector('#'+id);assert.ok(control,id+' selector exists');control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
function overlay(app){const node=app.querySelector('#step-attributes');assert.ok(node,'animated-step attribute overlay exists');return node;}
function shownNames(app){return overlay(app).querySelectorAll('code').map(node=>normalize(node.textContent));}
function assertNameSet(app,expected){
  const node=overlay(app);if(!expected.length){assert.equal(node.hidden,true,'steps without real attributes have no overlay');return;}
  assert.equal(node.hidden,false);
  assert.deepEqual(shownNames(app).sort(),expected.map(normalize).sort(),'the complete name list is stable independently of the moving packet');
  let extraText=node.textContent;for(const name of expected)extraText=extraText.replace(name,'');
  assert.equal(normalize(extraText),'','the card contains names without values or explanations');
}
function finish(app){clock.until(()=>app.player.status!=='playing');}
function toggle(app,checked){const control=app.querySelector('#show-step-attributes');assert.ok(control);control.checked=checked;control.dispatchEvent(new HarnessEvent('change'));}

test('the names-only overlay is optional, initially enabled, and hidden before animation',()=>{
  const app=mount();try{
    const control=app.querySelector('#show-step-attributes');assert.ok(control);assert.equal(control.getAttribute('type'),'checkbox');
    assert.ok(control.hasAttribute('checked'),'initial checkbox markup enables the overlay');assert.equal(overlay(app).hidden,true);
    const step=app.steps.find(step=>step.id==='l03');app.selectStep(app.steps.indexOf(step),true);
    assertNameSet(app,defaultNames.l03);
    for(const field of step.payload)if(String(field.value).length>12&&!defaultNames.l03.includes(String(field.value)))assert.ok(!overlay(app).textContent.includes(String(field.value)),'synthetic example values remain outside the names-only card');
    assert.ok(!overlay(app).textContent.includes(step.summary));assert.ok(!overlay(app).textContent.includes(step.detail));
    assert.equal(overlay(app).querySelectorAll('[data-attribute]').length,0,'the card has no tooltip triggers or glossary descriptions');
  }finally{unmount(app);}
});

test('the full parameter set stays visible during lead-in, packet gaps, pause and tail, then hides at completion',()=>{
  const app=mount();try{
    const step=app.steps.find(step=>step.id==='l03');assert.ok(step&&step.payload.length>1);app.selectStep(app.steps.indexOf(step),true);
    assert.equal(app.player.snapshot().visible,false);assertNameSet(app,defaultNames.l03);
    clock.frame();clock.advance(1500);assert.equal(app.player.snapshot().visible,false,'the first packet has reached its inter-packet gap');assert.equal(app.refs.packet.hidden,true);assertNameSet(app,defaultNames.l03);
    app.refs.play.click();assert.equal(app.player.status,'paused');const elapsed=app.player.elapsed;
    clock.advance(800);assert.equal(app.player.elapsed,elapsed);assertNameSet(app,defaultNames.l03);
    app.refs.play.click();assert.equal(app.player.status,'playing');
    clock.until(()=>app.player.elapsed>=380+step.payload.length*1290);assert.equal(app.player.status,'playing');assert.equal(app.player.snapshot().visible,false,'final packet tail has begun');assertNameSet(app,defaultNames.l03);
    finish(app);assert.equal(app.player.status,'complete');assert.equal(overlay(app).hidden,true);
  }finally{unmount(app);}
});

test('whole demos and clicked links replace the overlay set at each ordered step',()=>{
  const app=mount();try{
    const seen=[];const unsubscribe=app.player.subscribe(event=>{if(event.type==='step'){assertNameSet(app,defaultNames[event.step.id]);seen.push(event.step.id);}});
    app.player.setSpeed(4);app.refs.play.click();finish(app);assert.deepEqual(seen,app.steps.map(step=>step.id));assert.equal(overlay(app).hidden,true);
    seen.length=0;const edge=app.refs.connections.querySelectorAll('[data-pair]').find(edge=>app.steps.filter(step=>[app.nodeId(step.from),app.nodeId(step.to)].sort().join('--')===edge.dataset.pair).length>1);assert.ok(edge);
    edge.querySelector('.connection-hit').click();assert.equal(app.player.kind,'connection');const expected=app.player.queue.map(step=>step.id);finish(app);assert.deepEqual(seen,expected);assert.equal(overlay(app).hidden,true);unsubscribe();
  }finally{unmount(app);}
});

test('focused PKCE transport keeps the complete source request next to the link without adding the local verifier',()=>{
  const app=mount();try{
    app.selectAttribute('codeChallenge',false);const index=app.traceQueue.findIndex(step=>step.sourceStepId==='l03'&&step.traceKind==='send');assert.ok(index>=0);
    app.selectStep(index,true);
    assert.deepEqual(app.currentStep.payload.map(field=>field.name),['code_challenge'],'only the selected attribute animates');assertNameSet(app,defaultNames.l03);
    assert.ok(shownNames(app).includes('client_id'));assert.ok(shownNames(app).includes('nonce'));assert.ok(!shownNames(app).includes('code_verifier'),'the secret never becomes a browser request parameter');
    clock.frame();clock.advance(500);assert.equal(app.refs['packet-name'].textContent,'code_challenge');assertNameSet(app,defaultNames.l03);
    assert.deepEqual(overlay(app).querySelectorAll('.is-current').map(node=>normalize(node.textContent)),['code_challenge'],'the moving field is highlighted within the complete request');
    finish(app);assert.equal(overlay(app).hidden,true);
  }finally{unmount(app);}
});

test('stored PKCE challenge appears in local server checks while the token request carries only the verifier',()=>{
  const app=mount();try{
    app.selectAttribute('codeChallenge',false);const check=app.traceQueue.findIndex(step=>step.sourceStepId==='l23'&&step.traceKind==='verify');assert.ok(check>=0);app.selectStep(check,true);
    assert.equal(app.currentStep.from,'realmA');assert.equal(app.currentStep.to,'realmA');assertNameSet(app,['code','client_id','redirect_uri','code_challenge_method','code_challenge','code_verifier']);
    assert.ok(shownNames(app).includes('code_challenge'),'stored challenge participates in a local server comparison');
    app.selectAttribute('codeVerifier',false);const send=app.traceQueue.findIndex(step=>step.sourceStepId==='l23'&&step.traceKind==='send');assert.ok(send>=0);app.selectStep(send,true);assertNameSet(app,defaultNames.l23);
    assert.ok(!shownNames(app).includes('code_challenge'),'the stored challenge does not become a token-request field');
    assert.ok(!shownNames(app).includes('code_challenge_method'),'the token request does not resend the stored PKCE method');
  }finally{unmount(app);}
});

test('the live checkbox hides and restores an active or paused overlay without changing animation state',()=>{
  const app=mount();try{
    app.selectStep(app.steps.findIndex(step=>step.id==='l03'),true);clock.frame();clock.advance(600);const queue=app.player.queue,elapsed=app.player.elapsed,position=app.player.position;
    toggle(app,false);assert.equal(overlay(app).hidden,true);assert.equal(app.player.status,'playing');assert.equal(app.player.queue,queue);assert.equal(app.player.elapsed,elapsed);assert.equal(app.player.position,position);
    clock.advance(200);assert.equal(overlay(app).hidden,true);assert.ok(app.player.elapsed>elapsed);
    toggle(app,true);assert.equal(app.player.status,'playing');assertNameSet(app,defaultNames.l03);
    app.refs.play.click();assert.equal(app.player.status,'paused');const paused=app.player.elapsed;
    toggle(app,false);assert.equal(overlay(app).hidden,true);toggle(app,true);assertNameSet(app,defaultNames.l03);assert.equal(app.player.status,'paused');assert.equal(app.player.elapsed,paused);
    app.refs.play.click();finish(app);toggle(app,false);toggle(app,true);assert.equal(overlay(app).hidden,true,'enabling after completion does not resurrect old context');
    app.querySelector('#reset').click();toggle(app,false);toggle(app,true);assert.equal(overlay(app).hidden,true,'idle selection has no animated context');
  }finally{unmount(app);}
});

test('reset, focus changes, cancellation and protocol configuration discard stale overlay context',()=>{
  const app=mount();try{
    const start=()=>app.selectStep(app.steps.findIndex(step=>step.id==='l03'),true);
    start();assert.equal(overlay(app).hidden,false);app.querySelector('#reset').click();assert.equal(overlay(app).hidden,true);
    start();app.selectAttribute('codeChallenge',false);assert.equal(overlay(app).hidden,true);
    app.playAttribute();assert.equal(overlay(app).hidden,false);app.clearAttribute();assert.equal(overlay(app).hidden,true);
    start();app.player.stop();assert.equal(overlay(app).hidden,true);
    start();select(app,'app-protocol','saml');assert.equal(app.player.status,'idle');assert.equal(overlay(app).hidden,true);
  }finally{unmount(app);}
});

test('encrypted SAML and JWE wire overlays list actual message names without plaintext claims or key material',()=>{
  const app=mount();try{
    select(app,'app-protocol','saml');select(app,'assertion-protection','encrypted');
    const saml=app.steps.find(step=>step.samlHop==='app'&&step.samlStage==='response-browser');assert.ok(saml);app.selectStep(app.steps.indexOf(saml),true);assertNameSet(app,['SAMLResponse','Response','Response/@ID','Issuer / entityID','IssueInstant','Destination','StatusCode','InResponseTo','ds:Signature','RelayState','EncryptedAssertion','xenc:EncryptedKey','xenc:EncryptionMethod/@Algorithm']);
    assert.ok(shownNames(app).includes('SAMLResponse'));assert.ok(shownNames(app).includes('RelayState'));
    for(const forbidden of ['NameID','CEK','privateKey'])assert.ok(!shownNames(app).includes(forbidden),forbidden+' is not an encrypted SAML browser field');
    select(app,'app-protocol','oidc');select(app,'token-protection','both-jwe');
    for(const hop of ['app','broker']){
      const wire=app.steps.find(step=>step.jweStage==='wire'&&step.jweHop===hop);assert.ok(wire);app.selectStep(app.steps.indexOf(wire),true);assertNameSet(app,['id_token','JWE Compact Serialization','JWE Protected Header','alg','enc','kid','cty','encrypted_key','iv','ciphertext','tag','access_token','token_type','expires_in',...(hop==='app'?['refresh_token']:[])]);
      assert.ok(shownNames(app).includes('id_token'));
      for(const forbidden of ['iss','sub','aud','nonce','exp','iat','CEK','privateKey'])assert.ok(!shownNames(app).includes(forbidden),forbidden+' is not exposed on the encrypted OIDC response');
    }
  }finally{unmount(app);}
});
