import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {LAB_SCENARIOS,LAB_MODELS}=await import('../src/lab-catalog.js');
const {reconstructProtocolState}=await import('../src/protocol-state.js');
const {pairKey}=await import('../src/player.js');
const models=LAB_SCENARIOS.filter(model=>model.workspace);
function mount(){const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();return app;}
function cleanup(app){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
test('all added presets use their owning workspace and scenario actor registry',()=>{
  const app=mount();try{
    assert.equal(new Set(LAB_SCENARIOS.map(model=>model.id)).size,LAB_SCENARIOS.length);
    assert.equal(models.length,87);
    for(const model of models){
      app.selectLabScenario(model.id);assert.equal(app.workspace,model.workspace,model.id);
      assert.deepEqual(app.steps.map(step=>step.id),model.steps().map(step=>step.id));
      const used=[...new Set(app.steps.flatMap(step=>[app.nodeId(step.from),app.nodeId(step.to),...step.attributeOperations.map(op=>app.nodeId(op.actorId))]))].sort();
      assert.deepEqual(app.refs.actors.querySelectorAll('[data-actor]').map(card=>card.dataset.actor).sort(),used,model.id);
      assert.deepEqual(Object.keys(app.positions).sort(),used,model.id);
      assert.equal(app.querySelector('#quick-start').hidden,true);assert.equal(app.querySelector('#protocol-state-panel').hidden,false);
      assert.equal(app.querySelector('#workspace-families').hidden,model.workspace!=='kerberos');
    }
  }finally{cleanup(app);}
});
test('workspace defaults and sibling Kerberos families require no custom knobs',()=>{
  const app=mount();try{
    app.selectWorkspace('ssh');assert.equal(app.labScenarioId,'lab-ssh-cert-success');
    app.selectWorkspace('kerberos');assert.equal(app.labScenarioId,'lab-ad-first-sign-in');
    app.querySelector('[data-family="keycloak-bridge"]').click();assert.equal(app.labModel.family,'keycloak-bridge');
    app.querySelector('[data-family="ad-ds"]').click();assert.equal(app.labModel.family,'ad-ds');
    app.selectWorkspace('web');assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(app.mode,'password');
    app.selectWorkspace('unknown');assert.equal(app.labScenarioId,'basic-keycloak');
  }finally{cleanup(app);}
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
    const clock=app.studyClock(),fraction=(clock.offsets[sourceIndex]+1)/clock.total;
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
