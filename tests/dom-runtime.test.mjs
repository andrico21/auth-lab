import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {execFileSync} from 'node:child_process';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// These are DOM/runtime integration tests, not browser layout or accessibility QA.
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {ACTORS,ATTRIBUTES,FLOWS}=await import('../src/protocol-data.js');
const {getJourneySteps}=await import('../src/architecture-variants.js');
const {getFidoSteps,applyFidoTransport}=await import('../src/fido-direct.js');
const {clock,document,window}=harness;
const scenarios={passkey:'login',password:'passwordLogin','one-time-code':'oneTimeCodeLogin','password-totp':'totpLogin','passkey-totp':'passkeyTotpLogin',enrollment:'enrollment','totp-enrollment':'totpEnrollment','fido-login':'fidoLogin','fido-enrollment':'fidoEnrollment'};
const text=node=>node.textContent.replace(/\s+/g,' ').trim();
// These legacy-core regressions deliberately exercise native passkey login
// through two realms. Product startup is tested separately as Basic sign-in.
function configureCore(app){app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');}
function mount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();configureCore(app);return app;}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function select(app,id,value){const select=app.querySelector('#'+id);select.value=value;select.dispatchEvent(new HarnessEvent('change'));}
function hover(node){node.dispatchEvent(new HarnessEvent('mouseover',{relatedTarget:null}));}
function finish(app){return clock.until(()=>app.player.status!=='playing');}
function expectedActors(step,authenticator){return [step.from,step.to].map(id=>id==='authenticator'?authenticator:id).sort().join('--');}

// Guard the harness essentials so app assertions cannot pass with empty selectors.
test('DOM harness parses nested markup, bubbles events, and samples actual SVG paths',()=>{
  const node=document.createElement('div');node.innerHTML='<section id="parent"><button data-field="a"><code>id &amp; state</code></button><svg><path class="line" d="M 0 0 C 0 10, 10 10, 10 0"/></svg></section>';
  assert.equal(node.querySelectorAll('section button[data-field="a"]').length,1);
  assert.equal(text(node.querySelector('code')),'id & state');
  let target;node.querySelector('#parent').addEventListener('click',event=>target=event.target);
  node.querySelector('code').click();assert.equal(target,node.querySelector('code'));
  const path=node.querySelector('svg .line');assert.ok(path.getTotalLength()>10);assert.ok(Math.abs(path.getPointAtLength(path.getTotalLength()/2).x-5)<.01);
  path.setAttribute('d','M 0 0 C 0 0, 10 0, 10 0 C 10 0, 10 10, 10 10');
  assert.ok(Math.abs(path.getTotalLength()-20)<.01);assert.ok(Math.abs(path.getPointAtLength(15).x-10)<.01);assert.ok(Math.abs(path.getPointAtLength(15).y-5)<.01);
});

test('configured core render exposes every illustrated actor and journey step, and reconnecting is idempotent',()=>{
  const app=mount();try{
    const nodes=app.refs.actors.querySelectorAll('[data-actor]');
    assert.equal(nodes.length,8);assert.deepEqual(nodes.map(n=>n.dataset.actor).sort(),Object.keys(ACTORS).sort());
    for(const node of nodes){assert.ok(node.querySelector('svg'),'actor has vector artwork');assert.ok(node.getAttribute('aria-label'));}
    assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,FLOWS.login.length);
    assert.ok(app.refs.connections.querySelectorAll('[data-pair]').length>3);
    const previousPlayer=app.player;app.connectedCallback();assert.equal(app.player,previousPlayer);assert.equal(app.querySelectorAll('#studio').length,1);
    assert.equal(app.querySelector('#previous').disabled,true);assert.equal(app.querySelector('#next').disabled,false);
  }finally{unmount(app);}
});

test('all nine modes select their real flow, reset progress, and enable the appropriate devices',()=>{
  const app=mount();try{
    assert.deepEqual(app.refs.mode.querySelectorAll('option').map(n=>n.getAttribute('value')).sort(),Object.keys(scenarios).sort());
    for(const [mode,flow]of Object.entries(scenarios)){
      select(app,'mode',mode);assert.equal(app.mode,mode);
      const expected=mode.startsWith('fido-')?getFidoSteps(mode,app.authenticator):applyFidoTransport(getJourneySteps(mode,app.architecture,app.upstream),app.authenticator);
      assert.deepEqual(app.steps,expected);assert.equal(app.index,0);assert.equal(app.player.status,'idle');
      assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
      assert.equal(app.refs.progress.style.width,'0%');assert.equal(app.refs.authenticator.disabled,!['passkey','passkey-totp','enrollment','fido-login','fido-enrollment'].includes(mode));
      const keys=[...new Set(app.steps.map(step=>expectedActors(step,app.authenticator)))].sort();
      assert.deepEqual(app.refs.connections.querySelectorAll('[data-pair]').map(n=>n.dataset.pair).sort(),keys);
    }
    for(const choice of ['yubikey','hello']){
      select(app,'mode','passkey');select(app,'authenticator',choice);assert.equal(app.authenticator,choice);
      assert.ok(app.refs.connections.querySelector(`[data-pair="${['browser',choice].sort().join('--')}"]`));
      const alternative=choice==='hello'?'yubikey':'hello';assert.equal(app.refs.actors.querySelector(`[data-actor="${alternative}"]`).classList.contains('is-muted'),true);
    }
  }finally{unmount(app);}
});

test('single-realm setup renders and completes every factor and enrollment journey for native and web applications',()=>{
  const app=mount();try{
    assert.deepEqual(app.refs.upstream.querySelectorAll('option').map(option=>option.getAttribute('value')).sort(),['external','keycloak','single']);
    select(app,'upstream','single');app.player.setSpeed(4);
    for(const architecture of ['native','web']){
      select(app,'architecture',architecture);
      for(const mode of ['passkey','password','one-time-code','password-totp','passkey-totp','enrollment','totp-enrollment']){
        select(app,'mode',mode);const expected=applyFidoTransport(getJourneySteps(mode,architecture,'single'),app.authenticator);
        assert.deepEqual(app.steps,expected);assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,true);
        assert.ok(app.steps.every(step=>step.from!=='realmB'&&step.to!=='realmB'),architecture+' '+mode);
        const expectedPairs=[...new Set(app.steps.map(step=>expectedActors(step,app.authenticator)))].sort();
        assert.deepEqual(app.refs.connections.querySelectorAll('[data-pair]').map(connection=>connection.dataset.pair).sort(),expectedPairs);
        assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
        const seen=[],unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});app.refs.play.click();finish(app);unsubscribe();
        assert.deepEqual(seen,app.steps.map(step=>step.id));assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');assert.equal(clock.frames.size,0);
      }
    }
    select(app,'upstream','keycloak');assert.equal(app.refs.actors.querySelector('[data-actor="realmB"]').hidden,false);
    assert.ok(app.steps.some(step=>step.from==='realmB'||step.to==='realmB'));
  }finally{unmount(app);}
});

test('actor hover lists stored, generated, and verified attributes; fields explain meaning, origin, and purpose',()=>{
  const app=mount();try{
    for(const actor of Object.values(ACTORS)){
      const node=app.refs.actors.querySelector(`[data-actor="${actor.id}"]`);hover(node.querySelector('.actor-art'));
      const popup=app.refs['actor-popup'];assert.equal(popup.hidden,false);assert.ok(text(popup).includes(actor.name));
      const expected=app.actor(actor.id).attributes.filter(a=>ATTRIBUTES[a.id]);assert.deepEqual(popup.querySelectorAll('[data-attribute]').map(n=>n.dataset.attribute).sort(),expected.map(a=>a.id).sort());
      const groups=popup.querySelectorAll('.attribute-group');assert.equal(groups.length,new Set(expected.map(a=>a.kind)).size);
      for(const field of popup.querySelectorAll('[data-attribute]')){
        const definition=ATTRIBUTES[field.dataset.attribute];hover(field.querySelector('code'));
        const tip=app.refs['attribute-popup'];assert.equal(tip.hidden,false);
        for(const value of [definition.name,definition.meaning,definition.origin,definition.purpose,definition.example])assert.ok(text(tip).includes(String(value).replace(/\s+/g,' ').trim()),definition.name+' explanation includes '+value);
        assert.equal(tip.querySelector('a').getAttribute('href'),definition.source);
      }
      node.click();assert.equal(app.inspection.type,'actor');assert.equal(app.inspection.id,actor.id);assert.equal(popup.hidden,true);
      assert.equal(node.classList.contains('is-selected'),true);
    }
    hover(app.refs.actors.querySelector('[data-actor="app"]'));
    const field=app.refs['actor-popup'].querySelector('[data-attribute]'),id=field.dataset.attribute;field.click();assert.deepEqual(app.inspection,{type:'attribute',id});assert.equal(app.refs['attribute-popup'].hidden,true);
    assert.ok(text(app.refs.inspector).includes(ATTRIBUTES[id].purpose));
    app.dispatchEvent(new HarnessEvent('keydown',{key:'Escape'}));assert.equal(app.refs['actor-popup'].hidden,true);
  }finally{unmount(app);}
});

test('field guide searches canonical names and keyboard focus opens explanations',()=>{
  const app=mount();try{
    app.querySelector('#glossary-open').click();assert.equal(app.inspection.type,'glossary');
    const fields=app.refs.inspector.querySelectorAll('[data-search]');assert.equal(fields.length,Object.keys(ATTRIBUTES).length);
    const search=app.querySelector('#glossary-search');search.value='signature';search.dispatchEvent(new HarnessEvent('input'));
    assert.ok(fields.some(n=>!n.hidden));assert.ok(fields.some(n=>n.hidden));for(const n of fields)assert.equal(n.hidden,!n.dataset.search.includes('signature'));
    const visible=fields.find(n=>!n.hidden);visible.focus();assert.equal(app.refs['attribute-popup'].hidden,false);assert.ok(text(app.refs['attribute-popup']).includes(ATTRIBUTES[visible.dataset.attribute].purpose));
  }finally{unmount(app);}
});

test('clicking a connection replays its exchanges and named objects in the original journey order',()=>{
  const app=mount();try{
    const groups=app.refs.connections.querySelectorAll('[data-pair]');
    const edge=groups.find(g=>app.steps.filter(step=>expectedActors(step,app.authenticator)===g.dataset.pair).length>1);
    assert.ok(edge);const expected=app.steps.filter(step=>expectedActors(step,app.authenticator)===edge.dataset.pair),seen=[],packets=new Map();
    app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);if(event.type==='frame'&&event.visible){if(!packets.has(event.step.id))packets.set(event.step.id,[]);const list=packets.get(event.step.id);if(list.at(-1)!==event.packetIndex)list.push(event.packetIndex);assert.equal(app.refs['packet-name'].textContent,event.packet.name);}});
    edge.querySelector('.connection-hit').click();assert.equal(app.inspection.type,'connection');assert.equal(app.player.kind,'connection');assert.deepEqual(app.player.queue,expected);
    assert.equal(app.refs.inspector.querySelectorAll('[data-exchange-step]').length,expected.length);
    finish(app);assert.deepEqual(seen,expected.map(s=>s.id));
    for(const step of expected)assert.deepEqual(packets.get(step.id),step.payload.map((_,i)=>i));
    assert.equal(app.refs.packet.hidden,true);assert.equal(clock.frames.size,0);
    edge.dispatchEvent(new HarnessEvent('keydown',{key:'Enter'}));assert.equal(app.player.status,'playing');
  }finally{unmount(app);}
});

test('demo controls pause, resume, change speed, complete every journey, and reset cancels frames',()=>{
  const app=mount();try{
    const play=app.refs.play;play.click();assert.equal(app.player.status,'playing');clock.frame();clock.advance(500);
    assert.equal(app.refs.packet.hidden,false);assert.ok(Number.isFinite(parseFloat(app.refs.packet.style.left)));assert.ok(app.refs.packet.querySelector('.packet-chip').animationCalls.length>0);
    play.click();assert.equal(app.player.status,'paused');const paused=app.player.elapsed,callbacks=clock.totalFrameCallbacks;clock.advance(1000);assert.equal(app.player.elapsed,paused);assert.equal(clock.totalFrameCallbacks,callbacks);
    play.click();assert.equal(app.player.status,'playing');clock.frame();const before=app.player.elapsed;app.refs.speed.value='2';app.refs.speed.dispatchEvent(new HarnessEvent('input'));clock.frame();assert.equal(app.player.elapsed-before,200);assert.equal(app.refs['speed-label'].textContent,'2×');
    app.querySelector('#reset').click();assert.equal(app.player.status,'idle');assert.equal(clock.frames.size,0);const stoppedCallbacks=clock.totalFrameCallbacks;clock.advance(1000);assert.equal(clock.totalFrameCallbacks,stoppedCallbacks);assert.equal(app.index,0);assert.equal(app.refs.packet.hidden,true);
    app.refs.speed.value='4';app.refs.speed.dispatchEvent(new HarnessEvent('input'));
    for(const mode of Object.keys(scenarios)){
      select(app,'mode',mode);const seen=[];const unsubscribe=app.player.subscribe(event=>{if(event.type==='step')seen.push(event.step.id);});play.click();finish(app);unsubscribe();
      assert.equal(app.player.status,'complete');assert.deepEqual(seen,app.steps.map(s=>s.id));assert.equal(app.index,app.steps.length-1);assert.equal(app.refs.progress.style.width,'100%');assert.equal(app.refs.progress.parentElement.getAttribute('aria-valuenow'),'100');assert.equal(app.refs.packet.hidden,true);assert.equal(clock.frames.size,0);
      assert.ok(text(app.refs.toast).includes('complete'));assert.equal(app.refs.toast.hidden,false);
    }
    play.click();window.dispatchEvent(new HarnessEvent('blur',{bubbles:false}));assert.equal(app.player.status,'paused');
  }finally{unmount(app);}
});

test('timeline controls replay selected steps and disconnect stops frame callbacks',()=>{
  const app=mount();try{
    app.refs.timeline.querySelector('[data-step="2"]').querySelector('.step-title').click();assert.equal(app.index,2);assert.equal(app.player.kind,'step');assert.equal(app.player.queue.length,1);assert.equal(app.player.queue[0],app.steps[2]);
    app.querySelector('#previous').click();assert.equal(app.index,1);app.querySelector('#next').click();assert.equal(app.index,2);
    clock.frame();clock.advance(100);const callbacks=clock.totalFrameCallbacks;app.disconnectedCallback();clock.advance(1000);assert.equal(clock.totalFrameCallbacks,callbacks);assert.equal(app.player.status,'idle');assert.equal(clock.frames.size,0);
  }finally{unmount(app);}
});


test('message payload objects and form inputs expose their own hover definitions',()=>{
  const app=mount();try{
    const checks=[
      ['enrollment','e03',['rp','user','authenticatorSelection']],
      ['password-totp','p02',['username']],
      ['password-totp','p03',['username']],
      ['totp-enrollment','t03',['Provisioning URI (de facto)']],
      ['totp-enrollment','t06',['Enrollment OTP input (form-specific)']],
      ['totp-enrollment','t07',['OTP input']],
    ];
    for(const [mode,stepId,names]of checks){
      select(app,'mode',mode);const index=app.steps.findIndex(step=>step.id===stepId);assert.ok(index>=0,stepId+' exists');app.selectStep(index);
      for(const name of names){
        const field=app.refs.inspector.querySelectorAll('.payload-row .field-name').find(button=>text(button.querySelector('code'))===name);
        assert.ok(field,name+' is visible as a message object');assert.ok(field.dataset.attribute,name+' has a definition association');
        const definition=ATTRIBUTES[field.dataset.attribute];assert.ok(definition,name+' definition exists');hover(field.querySelector('code'));
        const tooltip=app.refs['attribute-popup'];assert.equal(tooltip.hidden,false);
        for(const value of [definition.meaning,definition.origin,definition.purpose])assert.ok(text(tooltip).includes(String(value).replace(/\s+/g,' ').trim()),name+' explains its meaning, origin, and purpose');
        assert.equal(tooltip.querySelector('a').getAttribute('href'),definition.source);
      }
    }
  }finally{unmount(app);}
});

test('the built standalone HTML has no external runtime assets and its inline bundle boots',()=>{
  const root=new URL('../',import.meta.url);
  // Exercise the build itself, ensuring this checks current source rather than stale output.
  execFileSync(process.execPath,[new URL('../build.mjs',import.meta.url).pathname],{cwd:root.pathname,stdio:'pipe'});
  const html=fs.readFileSync(new URL('../dist/auth-flow-studio.html',import.meta.url),'utf8');
  const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];assert.equal(scripts.length,1);
  const sandbox={},built=installHarness(sandbox);built.document.body.innerHTML=html.replace(/<script(?:\s[^>]*)?>[\s\S]*?<\/script>/gi,'').replace(/<style(?:\s[^>]*)?>[\s\S]*?<\/style>/gi,'');
  assert.equal(built.document.querySelectorAll('script[src]').length,0);assert.equal(built.document.querySelectorAll('link[rel="stylesheet"]').length,0);
  const styles=[...html.matchAll(/<style(?:\s[^>]*)?>([\s\S]*?)<\/style>/gi)].map(match=>match[1]).join('\n');
  assert.ok(styles.length>1000);assert.doesNotMatch(styles,/@import\b|url\(\s*['"]?(?:https?:)?\/\//i,'CSS has no remote imports, images, or fonts');
  assert.doesNotMatch(html,/<script\b[^>]*\bsrc\s*=/i,'JavaScript is embedded');assert.doesNotMatch(html,/<link\b[^>]*\brel=["'](?:stylesheet|preload)["']/i,'Styles and fonts are embedded');
  const compiled=new vm.Script(scripts[0][1],{filename:'dist/auth-flow-studio.html:inline-script'});compiled.runInContext(vm.createContext(sandbox),{timeout:5000});
  const Component=built.registry.get('auth-flow-studio');assert.equal(typeof Component,'function');
  const app=new Component();built.document.body.appendChild(app);app.connectedCallback();configureCore(app);
  assert.equal(app.refs.actors.querySelectorAll('[data-actor]').length,Object.keys(ACTORS).length);
  assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,FLOWS.login.length);
  app.refs.play.click();built.clock.frame();built.clock.advance(500);assert.equal(app.player.status,'playing');assert.equal(app.refs.packet.hidden,false);assert.ok(app.refs['packet-name'].textContent);
  app.disconnectedCallback();assert.equal(built.clock.frames.size,0);built.clock.timers.clear();
});
