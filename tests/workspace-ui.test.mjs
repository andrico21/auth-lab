import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {LAB_MODELS}=await import('../src/lab-catalog.js');
const {reconstructProtocolState}=await import('../src/protocol-state.js');
const {pairKey}=await import('../src/player.js');
function mount(){const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();return app;}
function cleanup(app){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
test('workspace defaults and every family selector retain their owning workspace',()=>{
  const app=mount();try{
    for(const [workspace,scenarioId,families] of [
      ['ssh','lab-ssh-cert-success',[]],
      ['kerberos','lab-ad-first-sign-in',[['keycloak-bridge','lab-kc-kerberos-sso'],['mit-standards','lab-krb-spake-success'],['ad-ds','lab-ad-first-sign-in']]],
      ['windows','lab-win-ntlmv2-domain',[['windows-integrated','lab-win-ntlmv2-domain'],['windows-desktop','lab-win-rdp-normal'],['windows-management','lab-win-winrm-second-hop-denied']]],
      ['network','lab-net-eap-tls13-wired',[['network-access','lab-net-eap-tls13-wired'],['network-lifecycle','lab-net-radius-accounting-lifecycle'],['network-transport','lab-net-radius-udp-radsec']]],
      ['foundations','lab-pake-spake2-success',[['pake-spake2','lab-pake-spake2-success'],['pake-spake2plus','lab-pake-spake2plus-success']]],
    ]){
      app.querySelector(`[data-workspace="${workspace}"]`).click();
      assert.equal(app.workspace,workspace);assert.equal(app.labScenarioId,scenarioId);
      for(const [family,id] of families){
        const button=app.querySelector(`[data-family="${family}"]`);assert.ok(button,family);
        button.click();assert.equal(app.workspace,workspace,family);assert.equal(app.labScenarioId,id,family);
        assert.equal(app.labModel.family,family);assert.equal(app.querySelector('#quick-start').hidden,true);
        assert.equal(app.querySelector('#protocol-state-panel').hidden,false);
      }
    }
    const selected=app.labScenarioId;app.selectWorkspace('unknown');assert.equal(app.labScenarioId,selected);
    app.querySelector('[data-workspace="web"]').click();assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(app.mode,'password');
  }finally{cleanup(app);}
});
test('progressive profile views preserve the canonical held and protocol snapshots at an unchanged cursor',()=>{
  const app=mount();try{
    for(const id of ['lab-win-ntlmv2-domain','lab-win-credssp-v6-kerberos','lab-win-credssp-v6-ntlm','lab-net-radius-password-accept','lab-net-eap-tls13-wired','lab-krb-spake-success','lab-pake-spake2-success','lab-pake-spake2plus-success']){
      app.selectLabScenario(id);
      assert.equal(app.querySelector('#learning-profile').hidden,false,id);
      for(const index of [Math.floor(app.steps.length/2),app.steps.length-1]){
        app.selectStep(index,false);
        const held=app.heldView.snapshot(),protocol=app.protocolSnapshot();
        for(const detail of ['fields','crypto','journey']){
          app.querySelector('#learning-detail-'+detail).click();
          assert.equal(app.querySelector('#learning-detail-'+detail).getAttribute('aria-pressed'),'true',id+': '+detail);
          assert.equal(app.querySelector('#learning-profile-crypto').hidden,detail!=='crypto');
          assert.equal(app.index,index);assert.deepEqual(app.heldView.snapshot(),held,id+': '+detail);
          assert.deepEqual(app.protocolSnapshot(),protocol,id+': '+detail);
        }
      }
    }
  }finally{cleanup(app);}
});
test('profile attribute index searches other protocols through input and restores its scope without changing state',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-pake-spake2-success');app.selectStep(Math.floor(app.steps.length/2),false);
    const ids=()=>app.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]').filter(button=>!button.hidden).map(button=>button.dataset.indexAttribute).sort();
    const scoped=ids(),held=app.heldView.snapshot(),protocol=app.protocolSnapshot();
    assert.ok(scoped.length>0);assert.equal(app.refs['attribute-index-list'].querySelector('[data-index-attribute="adSPN"]'),null);
    assert.equal(app.refs['attribute-topics'].querySelector('[data-trace-topic="pkce"]'),null);
    const input=app.refs['attribute-search'];input.value='service principal';input.dispatchEvent(new HarnessEvent('input'));
    const foreign=app.refs['attribute-index-list'].querySelector('[data-index-attribute="adSPN"]');
    assert.ok(foreign);assert.equal(foreign.hidden,false);
    assert.deepEqual(app.heldView.snapshot(),held);assert.deepEqual(app.protocolSnapshot(),protocol);
    input.value='';input.dispatchEvent(new HarnessEvent('input'));
    assert.deepEqual(ids(),scoped);assert.equal(app.refs['attribute-index-list'].querySelector('[data-index-attribute="adSPN"]'),null);
    assert.deepEqual(app.heldView.snapshot(),held);assert.deepEqual(app.protocolSnapshot(),protocol);
  }finally{cleanup(app);}
});
test('hashchange and Back/Forward route traversal restore model selection without writing new entries',()=>{
  const oldLocation=window.location,oldHistory=window.history,entries=[''],calls=[];
  let cursor=0,app;
  const visit=hash=>{window.location.hash=hash;window.dispatchEvent(new HarnessEvent('hashchange'));};
  window.location={hash:''};
  window.history={
    pushState(_state,_title,route){entries.splice(cursor+1);entries.push(route);cursor++;window.location.hash=route;calls.push(route);},
    replaceState(_state,_title,route){entries[cursor]=route;window.location.hash=route;calls.push(route);},
    back(){if(cursor>0)visit(entries[--cursor]);},
    forward(){if(cursor+1<entries.length)visit(entries[++cursor]);},
  };
  try{
    app=mount();
    app.selectLabScenario('lab-win-rdp-normal');app.selectLabScenario('lab-net-radius-accounting-lifecycle');app.selectLabScenario('lab-pake-spake2plus-success');
    const written=calls.length;
    window.history.back();assert.equal(app.labScenarioId,'lab-net-radius-accounting-lifecycle');assert.equal(app.workspace,'network');
    window.history.back();assert.equal(app.labScenarioId,'lab-win-rdp-normal');assert.equal(app.workspace,'windows');
    window.history.forward();assert.equal(app.labScenarioId,'lab-net-radius-accounting-lifecycle');assert.equal(app.workspace,'network');
    assert.equal(calls.length,written);
    visit('#/kerberos/mit');assert.equal(app.labScenarioId,'lab-krb-spake-success');assert.equal(app.workspace,'kerberos');
    visit('#/foundations/spake2');assert.equal(app.labScenarioId,'lab-pake-spake2-success');assert.equal(app.workspace,'foundations');
    assert.equal(calls.length,written,'valid hash traversal must not append or replace history');
    visit('#/windows/desktop/lab-win-ntlmv2-domain');assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(app.workspace,'web');
    assert.equal(calls.length,written+1,'invalid paths are normalized with one replacement');
    assert.equal(window.location.hash,'#/web/basic-keycloak');
    visit('#/web/basic-keycloak');assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(calls.length,written+1);
  }finally{if(app)cleanup(app);window.location=oldLocation;window.history=oldHistory;}
});
test('component expansion, card movement and zero-speed frames preserve source state',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ad-first-sign-in');app.selectStep(4,false);
    const before=app.protocolSnapshot(),toggle=app.querySelector('#show-internals');
    toggle.checked=true;toggle.dispatchEvent(new HarnessEvent('change'));
    assert.deepEqual(app.protocolSnapshot().state,before.state);assert.equal(app.index,4);
    assert.ok(app.refs.actors.querySelector('[data-actor="adAs"]'));
    toggle.checked=false;toggle.dispatchEvent(new HarnessEvent('change'));assert.deepEqual(app.protocolSnapshot().state,before.state);
    const id=Object.keys(app.positions)[0],p=app.positions[id];app.moveActor(id,p.x+12,p.y);
    assert.deepEqual(app.protocolSnapshot().state,before.state);
    app.player.play([app.currentStep],'step');app.player.setSpeed(0);const frozen=app.protocolSnapshot().state;
    for(let i=0;i<20;i++)harness.clock.frame(1000);
    assert.deepEqual(app.protocolSnapshot().state,frozen);assert.equal(app.player.speed,0);
  }finally{cleanup(app);}
});
test('collapsed connection replay follows logical component events and uses the complete source prefix',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ad-first-sign-in');
    const pair=pairKey('adWorkstation','adKdc');
    const expected=app.steps.filter(step=>pairKey(app.nodeId(step.from),app.nodeId(step.to))===pair);
    assert.ok(expected.length>1);app.replayConnection(pair);
    assert.deepEqual(app.player.queue.map(step=>step.id),expected.map(step=>step.id));
    const snapshot=app.protocolSnapshot();assert.deepEqual(snapshot.state,reconstructProtocolState(snapshot.model,snapshot.sourceIndex));
  }finally{cleanup(app);}
});
test('attribute focus reveals its internal owner; full, field and seek views share event state',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ad-forest-child-domains');
    const attribute='forestTgsRep';app.selectAttribute(attribute,false);
    assert.equal(app.showInternals,true);assert.ok(app.traceQueue.length);
    app.selectStep(Math.floor(app.traceQueue.length/2),false);
    const focused=app.protocolSnapshot(),sourceIndex=focused.sourceIndex;
    assert.deepEqual(focused.state,reconstructProtocolState(focused.model,sourceIndex));
    app.clearAttribute();app.selectStep(sourceIndex,false);assert.deepEqual(app.protocolSnapshot().state,focused.state);
    const clock=app.studyClock(),fraction=(clock.offsets[sourceIndex]+clock.durations[sourceIndex])/clock.total;
    app.seekPlayback(fraction);assert.equal(app.protocolSnapshot().sourceIndex,sourceIndex);assert.deepEqual(app.protocolSnapshot().state,focused.state);
  }finally{cleanup(app);}
});
test('runtime edits are visible on actors, rebuild at the beginning and never enter navigation history',()=>{
  const app=mount(),oldLocation=window.location,oldHistory=window.history,calls=[];
  window.location={hash:''};window.history={pushState(_state,_title,route){calls.push(route);window.location.hash=route;},replaceState(_state,_title,route){calls.push(route);window.location.hash=route;}};
  try{
    app.selectLabScenario('lab-ad-first-sign-in');app.selectStep(5,false);
    const input=app.refs['environment-fields'].querySelector('[data-environment-field="servicePrincipal"]');assert.ok(input);input.value='cifs/files.corp.example';
    app.applyEnvironment();assert.equal(app.index,0);assert.equal(app.refs['environment-errors'].hidden,true);
    assert.ok(app.querySelector('#scenario-environment').textContent.includes('cifs/files.corp.example'));
    assert.equal(app.definition('adSPN').example,'cifs/files.corp.example');
    assert.ok(calls.every(route=>!route.includes('files.corp.example')));
    const count=calls.length;window.location.hash='';app.openRoute();assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(calls.length,count,'Back to the initial URL creates no history entry');
    window.location.hash='#/kerberos/not-registered?spn=secret';app.openRoute();assert.equal(app.labScenarioId,'basic-keycloak');
    app.resetEnvironment();assert.equal(app.runtimeEnvironment.active,false);
  }finally{window.location=oldLocation;window.history=oldHistory;cleanup(app);}
});
test('contextual account rebuild changes policy and certificate bytes coherently without mutating the base fixture',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ssh-cert-success');const base=LAB_MODELS[app.labScenarioId],original=JSON.stringify(base.steps());
    app.runtimeEnvironment.updateDraft({unixAccount:'charlie'});assert.equal(app.runtimeEnvironment.apply({...app.environmentOptions,activeFields:['unixAccount']}).ok,true);app.refreshConfiguration();
    app.selectStep(app.steps.length-1,false);const state=app.protocolSnapshot().state;
    assert.deepEqual(state.credentials.userCertificate.principals,['charlie']);assert.equal(state.policy.identityMapping.account,'charlie');assert.equal(state.sessions.ssh.authenticated,true);
    assert.equal(JSON.stringify(base.steps()),original);assert.notEqual(JSON.stringify(app.steps),original);
    assert.ok(app.querySelector('#scenario-environment').textContent.includes('charlie'));
    app.resetEnvironment();assert.equal(app.runtimeEnvironment.applied.unixAccount,'');
  }finally{cleanup(app);}
});
test('four lifetime displays rewind issuer and host knowledge independently from an established SSH session',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ssh-cert-lifecycle');app.selectStep(app.steps.length-1,false);
    const panel=app.querySelector('#lifetime-strip');assert.equal(panel.hidden,false);assert.equal(panel.querySelectorAll('[data-lifetime]').length,4);
    assert.match(panel.querySelector('[data-lifetime="sshSession"]').textContent,/Open/);
    assert.match(panel.querySelector('[data-lifetime="oauthToken"]').textContent,/Expired/);
    assert.match(panel.querySelector('[data-lifetime="sshCertificate"]').textContent,/installed the revocation/);
    app.selectStep(0,false);assert.deepEqual(app.protocolSnapshot().state.knowledge.host.revokedSerials,[]);
    assert.doesNotMatch(panel.textContent,/installed the revocation/);assert.match(panel.textContent,/Not established/);
  }finally{cleanup(app);}
});

test('global field availability and replay update when returning between Core and a legacy fixed model',()=>{
  const app=mount();try{
    const verifier=()=>app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');
    verifier().click();app.player.pause();
    assert.ok(app.traceQueue.some(step=>step.from==='realmA'&&step.to==='realmA'&&step.traceKind==='verify'));
    app.selectLabScenario('lab-refresh-rotation');
    assert.equal(Number(verifier().querySelector('.attribute-index-count').textContent),0);
    verifier().click();assert.equal(app.traceQueue.length,0,'A refresh-only journey cannot invent a PKCE history');
    app.selectLabScenario('basic-keycloak');verifier().click();app.player.pause();
    assert.ok(app.traceQueue.some(step=>step.from==='realmA'&&step.to==='realmA'&&step.traceKind==='verify'));
    assert.equal(app.attributeSelection,'codeVerifier');
  }finally{cleanup(app);}
});
