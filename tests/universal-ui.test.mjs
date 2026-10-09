import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Offline DOM integration: this harness verifies selection, model projection,
// event handling and animation state. It does not implement protocol endpoints,
// cryptography, a browser layout engine or native authentication devices.
const universalHarness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {LAB_SCENARIOS,LAB_ATTRIBUTES}=await import('../src/lab-catalog.js');
const {LEARNING_PRESETS}=await import('../src/learning-presets.js');
const {GRAPH_WIDTH,GRAPH_HEIGHT,CARD_BOUNDS}=await import('../src/layout.js');
const {clock,document}=universalHarness;
const universalText=node=>String(node.textContent).replace(/\s+/g,' ').trim();
const universalLegacyControls=['mode','authenticator','architecture','upstream','oidc-flow','app-protocol','broker-protocol','saml-binding','saml-initiation','token-protection','assertion-protection'];
function universalMount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;}
function universalUnmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function universalSelect(app,id,value){const control=app.querySelector('#'+id);assert.ok(control,id+' selector exists');control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
function universalToggle(app,id,value){const control=app.querySelector('#'+id);control.checked=value;control.dispatchEvent(new HarnessEvent('change'));}
function universalFinish(app){clock.until(()=>app.player.status!=='playing');}
function universalHover(node){assert.ok(node,'hover target exists');node.dispatchEvent(new HarnessEvent('mouseover',{relatedTarget:null}));}
function universalTrace(app,id){app.selectAttribute(id,false);assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length,id+' has real operations');return app.traceQueue;}

test('the universal selector exposes every model with its own participants, support note and primary source',()=>{
  const app=universalMount();try{
    assert.equal(LAB_SCENARIOS.length,43,'all 43 extended scenarios are registered');
    const options=app.refs['lab-scenario'].querySelectorAll('option').map(option=>option.getAttribute('value'));
    const expectedIds=[...new Set([...LEARNING_PRESETS.map(preset=>preset.id),'core',...LAB_SCENARIOS.map(model=>model.id)])];
    assert.deepEqual(options.slice().sort(),expectedIds.sort());assert.equal(options.length,54,'ready-to-run presets and extended models have no duplicate choices');
    assert.equal(new Set(options).size,options.length);
    for(const model of LAB_SCENARIOS){
      universalSelect(app,'lab-scenario',model.id);assert.equal(app.labModel,model);assert.equal(app.labScenarioId,model.id);
      assert.deepEqual(app.steps.map(step=>step.id),model.steps(app.protocolConfig()).map(step=>step.id));
      assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,app.steps.length);
      for(const id of universalLegacyControls)assert.equal(app.refs[id].disabled,true,model.id+' fixes '+id+' to its own policy');
      assert.equal(universalText(app.refs.mode.querySelector('[value="'+app.mode+'"]')),'Defined by this scenario');
      const preset=LEARNING_PRESETS.find(preset=>preset.id===model.id);
      assert.equal(app.querySelector('#scenario-title').textContent,preset?.title||model.title);
      assert.equal(app.querySelector('#scenario-description').textContent,preset?.summary||model.summary);
      assert.equal(app.refs['lab-support'].hidden,false);assert.ok(universalText(app.refs['lab-support']).includes(model.status));assert.ok(universalText(app.refs['lab-support']).includes(model.supportNote));
      assert.equal(app.refs['lab-support'].querySelector('a').getAttribute('href'),model.source);
      const used=new Set(app.steps.flatMap(step=>[app.nodeId(step.from),app.nodeId(step.to),...step.attributeOperations.map(op=>app.nodeId(op.actorId))]));
      assert.deepEqual(Object.keys(app.positions).sort(),[...used].sort(),model.id+' reserves only used participant positions');
      const cards=app.refs.actors.querySelectorAll('[data-actor]').filter(card=>!card.hidden);
      assert.deepEqual(cards.map(card=>card.dataset.actor).sort(),[...used].sort(),model.id+' shows exactly its participants');
      for(const card of cards){const actor=model.actors(app.protocolConfig())[card.dataset.actor];assert.equal(universalText(card.querySelector('.actor-name')),actor.name);assert.equal(universalText(card.querySelector('.actor-role')),actor.role);}
      app.selectLabScenario('this-scenario-does-not-exist');assert.equal(app.labScenarioId,model.id,'invalid scenario IDs cannot discard the active model');
    }
  }finally{universalUnmount(app);}
});

test('all extended demos complete in exact model order and update the names-only overlay for each stage',()=>{
  const app=universalMount();try{
    app.player.setSpeed(4);
    for(const model of LAB_SCENARIOS){
      app.clearAttribute();universalSelect(app,'lab-scenario',model.id);const seen=[];
      const unsubscribe=app.player.subscribe(event=>{if(event.type!=='step')return;seen.push(event.step.id);
        const overlay=app.refs['step-attributes'];if(!event.step.attributeOperations.some(op=>op.kind!=='inspect')){assert.equal(overlay.hidden,true,'plain UI actions have no protocol-attribute context');return;}assert.equal(overlay.hidden,false,model.id+' stage '+event.step.id+' has names-only context');assert.equal(overlay.dataset.step,event.step.id);
        const names=overlay.querySelectorAll('code').map(universalText);assert.ok(names.length);let rest=overlay.textContent;for(const name of names)rest=rest.replace(name,'');assert.equal(rest.trim(),'','context lists names without values or descriptions');
        for(const node of overlay.querySelectorAll('[data-step-attribute]'))for(const id of node.dataset.stepAttribute.split(' '))assert.ok(event.step.fields.includes(id),id+' belongs to this model stage');
      });
      app.refs.play.click();universalFinish(app);unsubscribe();
      assert.deepEqual(seen,app.steps.map(step=>step.id));assert.equal(app.player.status,'complete');assert.equal(app.refs.progress.style.width,'100%');assert.equal(app.refs['step-attributes'].hidden,true);
    }
  }finally{universalUnmount(app);}
});

test('catalog browsing searches scenario titles and attributes and opens the selected model',()=>{
  const app=universalMount();try{
    assert.equal(app.refs['lab-cards'].querySelectorAll('[data-lab-scenario]').length,LAB_SCENARIOS.length);
    app.querySelector('#lab-open').click();assert.equal(app.refs['lab-catalog'].open,true);
    const search=app.refs['lab-search'];search.value='Artifact';search.dispatchEvent(new HarnessEvent('input'));
    const artifact=app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-saml-artifact"]');assert.ok(artifact);artifact.querySelector('strong').click();assert.equal(app.labModel.id,'lab-saml-artifact');
    assert.equal(app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-saml-artifact"]').getAttribute('aria-pressed'),'true');
    search.value='code_verifier';search.dispatchEvent(new HarnessEvent('input'));assert.ok(app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-bff-api"]'),'parameter-name searches find actual owning models');
    search.value='zzzz-no-such-scenario-zzzz';search.dispatchEvent(new HarnessEvent('input'));assert.equal(app.refs['lab-cards'].querySelectorAll('[data-lab-scenario]').length,0);assert.match(universalText(app.refs['lab-cards']),/No matching scenarios/);
    search.value='';search.dispatchEvent(new HarnessEvent('input'));assert.equal(app.refs['lab-cards'].querySelectorAll('[data-lab-scenario]').length,LAB_SCENARIOS.length);
  }finally{universalUnmount(app);}
});

test('scenario-specific scalar fields and topics offer working switches from an inactive index',()=>{
  const app=universalMount();try{
    for(const model of LAB_SCENARIOS){
      app.clearAttribute();app.selectLabScenario('core');
      const id=model.ids[0],field=app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]');assert.ok(field,id+' appears in the separate attribute index');field.click();
      assert.equal(app.attributeSelection,id);assert.equal(app.traceQueue.length,0,'extended scalar has no fabricated core operations');
      let helper=app.refs.inspector.querySelector('[data-trace-lab="'+model.id+'"]');assert.ok(helper,id+' offers its owning lab scenario');helper.click();
      assert.equal(app.labModel,model);assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length);assert.equal(app.player.status,'playing');
      assert.ok(app.traceQueue.every(moment=>moment.payload.every(field=>field.attributeId===id)),'the clicked scalar stays the exact field');
      app.player.stop();app.clearAttribute();app.selectLabScenario('core');
      const topic='topic-'+model.id;app.selectAttribute(topic,false);assert.equal(app.traceQueue.length,0,'inactive topic never animates another model under its title');
      helper=app.refs.inspector.querySelector('[data-trace-lab="'+model.id+'"]');assert.ok(helper);helper.click();assert.equal(app.labModel,model);assert.equal(app.attributeSelection,topic);assert.ok(app.traceQueue.length);assert.equal(app.player.kind,'attribute');
      assert.ok(app.refs['attribute-index'].querySelector('[data-trace-topic="'+topic+'"]'),'the selected model exposes its own topic in the index');assert.ok(app.traceQueue.every(moment=>app.steps.some(source=>source.id===moment.sourceStepId)),'topic moments belong to the newly selected model');app.player.stop();
    }
  }finally{universalUnmount(app);}
});

test('SAML scalar traces preserve distinct pairwise subjects and the actual sender issuer on each wire',()=>{
  const app=universalMount();try{
    app.selectLabScenario('lab-saml-sp-slo');
    for(const [id,expected]of [['slNameIDApp','pairwise-person-for-sp1'],['slNameIDOther','pairwise-person-for-sp2'],['slSessionIndexApp','_session_sp1_01'],['slSessionIndexOther','_session_sp2_01']]){
      const trace=universalTrace(app,id);assert.ok(trace.every(moment=>moment.payload.every(field=>field.attributeId===id&&field.value===expected)),id+' never borrows the identically named parameter for the other SP');
    }
    const issuer=universalTrace(app,'slIssuer').filter(moment=>moment.traceKind==='send');assert.ok(issuer.length>=4);
    const actualIssuers=new Set();for(const moment of issuer){const source=app.steps.find(step=>step.id===moment.sourceStepId);const carried=source.payload.find(field=>field.attributeId==='slIssuer');assert.ok(carried);assert.equal(moment.payload[0].value,carried.value);actualIssuers.add(moment.payload[0].value);}
    assert.ok(actualIssuers.has('https://app.example.test/saml'));assert.ok(actualIssuers.has('https://reports.example.test/saml'));assert.ok(actualIssuers.has('https://idp1.example.test/realms/realm-a'));
  }finally{universalUnmount(app);}
});

test('inactive lab fields retain their exact participant identity instead of aliasing a same-named active field',()=>{
  const app=universalMount();try{
    app.selectLabScenario('lab-saml-artifact');const id='slNameIDOther';
    const field=app.refs['attribute-index'].querySelector('[data-index-attribute="'+id+'"]');assert.ok(field);field.click();
    assert.equal(app.attributeSelection,id,'SP 2 NameID must never silently become SP 1 NameID');assert.equal(app.traceQueue.length,0,'SP 2 has no operation in the SP 1 artifact scenario');
    const helper=app.refs.inspector.querySelector('[data-trace-lab="lab-saml-sp-slo"]');assert.ok(helper,'the actual second-SP lifecycle is offered');helper.click();
    assert.equal(app.labModel.id,'lab-saml-sp-slo');assert.equal(app.attributeSelection,id);assert.ok(app.traceQueue.length);assert.ok(app.traceQueue.every(moment=>moment.payload.every(p=>p.attributeId===id&&p.value==='pairwise-person-for-sp2')));
    app.player.stop();app.clearAttribute();app.selectLabScenario('lab-hybrid');app.selectAttribute('branchExternalIssuer',false);assert.equal(app.attributeSelection,'branchExternalIssuer','an upstream issuer must never become the realm issuer merely because both claims are iss');assert.equal(app.traceQueue.length,0);assert.ok(app.refs.inspector.querySelector('[data-trace-lab="lab-broker-account-link"]'));
    app.selectAttribute('codeVerifier',false);assert.equal(app.attributeSelection,'branchVerifier','the existing core alias still selects the current model’s canonical PKCE proof');assert.ok(app.traceQueue.length);
  }finally{universalUnmount(app);}
});

test('participant and parameter hovers expose complete model metadata with API and secondary-SP roles',()=>{
  const app=universalMount();try{
    for(const model of LAB_SCENARIOS){
      app.clearAttribute();app.selectLabScenario(model.id);
      for(const card of app.refs.actors.querySelectorAll('[data-actor]')){
        universalHover(card.querySelector('.actor-art'));const actor=app.actor(card.dataset.actor),popup=app.refs['actor-popup'];assert.equal(popup.hidden,false);assert.ok(universalText(popup).includes(actor.name));
        const sample=actor.attributes.find(field=>LAB_ATTRIBUTES[field.id]);if(!sample)continue;
        const node=popup.querySelector('[data-attribute="'+sample.id+'"]');assert.ok(node,sample.id+' is attached to the actual participant');universalHover(node.querySelector('code'));
        const tip=app.refs['attribute-popup'],definition=app.definition(sample.id);assert.equal(tip.hidden,false);for(const key of ['meaning','origin','purpose','example'])assert.ok(universalText(tip).includes(String(definition[key]).replace(/\s+/g,' ').trim()),model.id+' '+sample.id+' '+key);assert.equal(tip.querySelector('a').getAttribute('href'),definition.source);
      }
    }
    app.selectLabScenario('lab-spa-api');let other=app.refs.actors.querySelector('[data-actor="realmB"]');assert.match(universalText(other),/API/);assert.doesNotMatch(universalText(other),/Realm B|IdP 2/);
    app.selectLabScenario('lab-saml-sp-slo');other=app.refs.actors.querySelector('[data-actor="realmB"]');assert.match(universalText(other),/Reports application|SP 2/);assert.doesNotMatch(universalText(other),/Realm B|IdP 2/);
  }finally{universalUnmount(app);}
});

test('the shared PKCE topic traces the active client and keeps the BFF verifier outside browser messages',()=>{
  const app=universalMount();try{
    app.selectLabScenario('lab-bff-api');const pkce=universalTrace(app,'pkce');assert.ok(pkce.some(moment=>moment.traceKind==='create'&&moment.from==='app'&&moment.fields.includes('webVerifier')));assert.ok(pkce.some(moment=>moment.traceKind==='send'&&moment.from==='app'&&moment.to==='realmA'&&moment.fields.includes('webVerifier')));
    assert.ok(pkce.every(moment=>!moment.fields.includes('webVerifier')||![moment.from,moment.to].includes('browser')),'the confidential BFF retains and redeems its own proof');
    const challenge=pkce.findIndex(moment=>moment.traceKind==='send'&&moment.from==='app'&&moment.to==='browser'&&moment.fields.includes('webChallenge'));assert.ok(challenge>=0);app.selectStep(challenge,true);const names=app.refs['step-attributes'].querySelectorAll('code').map(universalText);assert.ok(names.includes('code_challenge'));assert.ok(names.includes('client_id'));assert.ok(!names.includes('code_verifier'));
    universalToggle(app,'show-step-attributes',false);assert.equal(app.refs['step-attributes'].hidden,true);app.player.pause();universalToggle(app,'show-step-attributes',true);assert.equal(app.refs['step-attributes'].hidden,false);assert.equal(app.player.status,'paused');
    app.clearAttribute();app.selectLabScenario('lab-spa-api');const spa=universalTrace(app,'pkce');assert.ok(spa.some(moment=>moment.traceKind==='create'&&moment.from==='browser'&&moment.fields.includes('webVerifier')),'SPA JavaScript is itself the public OAuth client');assert.ok(spa.some(moment=>moment.traceKind==='send'&&moment.from==='browser'&&moment.to==='realmA'&&moment.fields.includes('webVerifier')));
    assert.ok(spa.filter(moment=>moment.sourceStepId==='web-spa-authorize').every(moment=>!moment.fields.includes('webVerifier')),'SPA authorization navigation still omits the secret verifier');
    app.clearAttribute();app.selectLabScenario('lab-direct-grant');app.selectAttribute('pkce',false);assert.equal(app.traceQueue.length,0,'the password grant does not manufacture PKCE');
  }finally{universalUnmount(app);}
});

test('OIDC identity-token nonce study stays separate from a DPoP resource freshness challenge',()=>{
  const app=universalMount();try{
    app.selectLabScenario('lab-dpop');app.selectAttribute('nonce',false);assert.equal(app.traceQueue.length,0,'the identity-token topic cannot animate an API-generated DPoP nonce');
    for(const id of ['nonceApp','nonceBroker']){app.selectAttribute(id,false);assert.equal(app.attributeSelection,id,'OIDC request nonce does not alias the unrelated same-named proof claim');assert.equal(app.traceQueue.length,0);}
    const dpop=universalTrace(app,'protDpopNonce');assert.ok(dpop.some(moment=>moment.from==='app'&&moment.to==='realmB'),'the actual DPoP nonce remains individually traceable');assert.match(app.definition('protDpopNonce').purpose,/not an OIDC ID-token nonce/);
    app.clearAttribute();app.selectLabScenario('lab-bff-api');const oidc=universalTrace(app,'nonce');assert.ok(oidc.some(moment=>moment.traceKind==='create'&&moment.from==='app'&&moment.fields.includes('webNonce')));assert.ok(oidc.some(moment=>moment.traceKind==='send'&&moment.from==='realmA'&&moment.to==='app'&&moment.fields.includes('webNonce')),'OIDC request binding still returns inside the real ID-token result');
  }finally{universalUnmount(app);}
});

test('participant movement clamps to the canvas, rejects card collisions and recomputes paused connection context',()=>{
  const app=universalMount();try{
    app.selectLabScenario('lab-api-errors');const initial=structuredClone(app.positions),before=app.refs.connections.querySelectorAll('.connection-line').map(node=>node.getAttribute('d'));
    const wire=app.steps.findIndex(step=>step.from==='app'&&step.to==='realmB');assert.ok(wire>=0);app.selectStep(wire,true);assert.equal(app.refs['step-attributes'].hidden,false);
    assert.equal(app.moveActor('app',app.positions.realmB.x,app.positions.realmB.y),false);assert.deepEqual(app.positions,initial,'overlapping a card does not alter layout');assert.equal(app.player.status,'playing','a rejected move does not pause animation');
    assert.equal(app.moveActor('app',-10000,-10000),true);assert.equal(app.player.status,'paused');assert.deepEqual(app.positions.app,{x:CARD_BOUNDS.width/2+24,y:CARD_BOUNDS.height/2+24});
    const after=app.refs.connections.querySelectorAll('.connection-line').map(node=>node.getAttribute('d'));assert.notDeepEqual(after,before,'routing is recomputed after movement');assert.equal(app.refs['step-attributes'].hidden,false);assert.equal(app.refs['step-attributes'].dataset.step,app.steps[wire].id);
    assert.equal(app.moveActor('no-such-actor',2,3),false);assert.equal(app.moveActor('app',NaN,100),false);
    assert.equal(app.moveActor('app',10000,10000),true);assert.deepEqual(app.positions.app,{x:GRAPH_WIDTH-CARD_BOUNDS.width/2-24,y:GRAPH_HEIGHT-CARD_BOUNDS.height/2-24});
    app.querySelector('#layout-reset').click();assert.deepEqual(app.positions,initial);assert.equal(app.player.status,'paused');assert.equal(app.refs['step-attributes'].hidden,false);
    app.selectLabScenario('lab-saml-artifact');assert.ok(!app.customLayouts[app.layoutKey],'scenario layouts are isolated');app.selectLabScenario('lab-api-errors');assert.deepEqual(app.positions,initial,'reset persists on return to the scenario');
  }finally{universalUnmount(app);}
});

test('moving participants supports explicit pointer and keyboard controls and core configuration survives lab visits',()=>{
  const app=universalMount();try{
    universalSelect(app,'mode','password-totp');universalSelect(app,'authenticator','yubikey');universalSelect(app,'architecture','web');universalSelect(app,'upstream','external');universalSelect(app,'broker-protocol','saml');universalSelect(app,'assertion-protection','encrypted');
    const keys=['mode','authenticator','architecture','upstream','applicationProtocol','brokerProtocol','samlBinding','samlInitiation','tokenProtection','assertionProtection','oidcFlow'],saved=Object.fromEntries(keys.map(key=>[key,app[key]]));universalToggle(app,'show-step-attributes',false);
    app.selectLabScenario('lab-api-errors');const card=app.refs.actors.querySelector('[data-actor="app"]'),initial={...app.positions.app};
    card.dispatchEvent(new HarnessEvent('keydown',{key:'ArrowDown'}));assert.deepEqual(app.positions.app,initial,'movement is disabled by default');card.dispatchEvent(new HarnessEvent('pointerdown',{button:0,pointerId:7,clientX:100,clientY:100}));assert.equal(app.dragState,null);
    universalToggle(app,'move-participants',true);assert.equal(app.moveParticipants,true);assert.equal(app.refs.graph.classList.contains('is-move-mode'),true);card.dispatchEvent(new HarnessEvent('keydown',{key:'ArrowDown'}));assert.deepEqual(app.positions.app,{x:initial.x,y:initial.y+12});
    card.dispatchEvent(new HarnessEvent('pointerdown',{button:0,pointerId:7,clientX:100,clientY:100}));assert.equal(app.dragState.id,'app');const before={...app.positions.app};card.dispatchEvent(new HarnessEvent('pointermove',{pointerId:8,clientX:103,clientY:100}));assert.deepEqual(app.positions.app,before,'another pointer cannot move the selected card');card.dispatchEvent(new HarnessEvent('pointermove',{pointerId:7,clientX:103,clientY:100}));assert.ok(app.positions.app.x>before.x);card.dispatchEvent(new HarnessEvent('pointerup',{pointerId:7}));assert.equal(app.dragState,null);assert.equal(card.classList.contains('is-dragging'),false);
    app.selectLabScenario('lab-saml-metadata');app.selectLabScenario('lab-spa-api');universalSelect(app,'lab-scenario','core');assert.equal(app.labModel,null);for(const key of keys)assert.equal(app[key],saved[key],key+' returns to its prior core preference');assert.equal(app.refs['show-step-attributes'].checked,false);assert.equal(app.refs['lab-support'].hidden,true);assert.equal(app.refs.mode.disabled,false);
  }finally{universalUnmount(app);}
});
