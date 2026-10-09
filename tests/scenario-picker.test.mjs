import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

// Interaction tests only: the offline harness does not implement browser layout,
// screen-reader announcements or the platform's native focus navigation.
const pickerHarness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {LAB_SCENARIOS,LAB_ATTRIBUTES}=await import('../src/lab-catalog.js');
const {LEARNING_PRESETS}=await import('../src/learning-presets.js');
const pickerAllIds=[...new Set([...LEARNING_PRESETS.map(preset=>preset.id),'core',...LAB_SCENARIOS.map(model=>model.id)])];
const {clock,document}=pickerHarness;
const pickerText=node=>String(node?.textContent||'').replace(/\s+/g,' ').trim();
function pickerMount(){const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();return app;}
function pickerUnmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function pickerInput(app){return app.querySelector('#lab-scenario-search');}
function pickerMenu(app){return app.querySelector('#lab-scenario-menu');}
function pickerRows(app){return app.querySelector('#lab-scenario-results').querySelectorAll('[data-scenario-option]');}
function pickerIds(app){return pickerRows(app).map(row=>row.dataset.scenarioOption);}
function pickerOpen(app){pickerInput(app).dispatchEvent(new HarnessEvent('focusin'));}
function pickerType(app,value){const input=pickerInput(app);input.value=value;input.dispatchEvent(new HarnessEvent('input'));}
function pickerKey(app,key){const event=new HarnessEvent('keydown',{key});pickerInput(app).dispatchEvent(event);return event;}
function pickerTitle(app,id){return pickerText(app.refs['lab-scenario'].querySelector('[value="'+id+'"]'));}
function pickerActive(app){const id=pickerInput(app).getAttribute('aria-activedescendant');return id?app.querySelector('#'+id):null;}
function pickerChoose(app,id){const row=pickerRows(app).find(option=>option.dataset.scenarioOption===id);assert.ok(row,'matching scenario is selectable');row.click();}
const pickerCanonical=name=>String(name).replace(/\s*\([^)]*\)/g,'').trim();
function pickerExpected(query){const terms=query.toLowerCase().trim().split(/\s+/);return LAB_SCENARIOS.filter(model=>{
  const text=[model.title,model.summary,model.category,model.status,...model.ids.map(id=>pickerCanonical(LAB_ATTRIBUTES[id]?.name||id))].join(' ').toLowerCase();
  return terms.every(term=>text.includes(term));
}).map(model=>model.id);}

test('the scenario field exposes an inline combobox while preserving the complete native selection contract',()=>{
  const app=pickerMount();try{
    const input=pickerInput(app),menu=pickerMenu(app),list=app.querySelector('#lab-scenario-results'),status=app.querySelector('#lab-scenario-search-status');
    assert.ok(app.querySelector('#lab-scenario-picker'));assert.ok(input);assert.ok(menu);assert.ok(status);
    assert.equal(input.getAttribute('role'),'combobox');assert.equal(input.getAttribute('aria-expanded'),'false');assert.equal(input.getAttribute('aria-controls'),list.id);assert.equal(list.getAttribute('role'),'listbox');assert.equal(menu.hidden,true);
    const options=app.refs['lab-scenario'].querySelectorAll('option').map(option=>option.getAttribute('value'));
    assert.deepEqual(options.slice().sort(),pickerAllIds.slice().sort());assert.equal(new Set(options).size,54);
    assert.equal(app.refs['lab-scenario'].hidden,true,'the old native selector is retained without a duplicate visible control');
    assert.equal(input.value,pickerTitle(app,'basic-keycloak'));
    pickerOpen(app);assert.equal(menu.hidden,false);assert.equal(input.getAttribute('aria-expanded'),'true');assert.equal(pickerRows(app).length,54);assert.equal(pickerIds(app)[0],'basic-keycloak','the basic sign-in preset is the first suggestion');
    assert.ok(pickerRows(app).every(row=>row.getAttribute('role')==='option'&&row.id),'results have usable option identities');
    assert.ok(status.getAttribute('aria-live')||status.getAttribute('role')==='status','result feedback can be announced');
  }finally{pickerUnmount(app);}
});

test('inline search matches case-insensitive terms across titles, categories, status and canonical attributes',()=>{
  const app=pickerMount();try{
    pickerOpen(app);
    for(const query of ['SAML ARTIFACT','DPoP nonce','CODE_VERIFIER','Standards only','token session lifecycle']){
      pickerType(app,query);const expected=pickerExpected(query);assert.ok(expected.length,'the query has actual scenario matches');
      assert.deepEqual(pickerIds(app).filter(id=>LAB_SCENARIOS.some(model=>model.id===id)).slice().sort(),expected.slice().sort(),query+' matches every requested term across scenario metadata');
      assert.equal(app.labScenarioId,'basic-keycloak','search itself never chooses a scenario');
    }
    pickerType(app,'artifact');pickerChoose(app,'lab-saml-artifact');assert.equal(app.labScenarioId,'lab-saml-artifact');assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,pickerTitle(app,'lab-saml-artifact'));
  }finally{pickerUnmount(app);}
});

test('typing and clearing results preserve the active journey, selected attribute and running playback',()=>{
  const app=pickerMount();try{
    app.selectLabScenario('lab-bff-api');app.selectAttribute('pkce',false);app.playAttribute();const before=app.player.snapshot(),queue=app.player.queue.slice(),selection=app.attributeSelection;
    assert.equal(before.status,'playing');pickerOpen(app);pickerType(app,'artifact');
    assert.equal(app.labScenarioId,'lab-bff-api');assert.equal(app.attributeSelection,selection);assert.equal(app.player.status,'playing');assert.equal(app.player.kind,before.kind);assert.deepEqual(app.player.queue,queue);
    app.querySelector('#lab-scenario-clear').click();assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'');assert.equal(pickerRows(app).length,54);assert.equal(app.labScenarioId,'lab-bff-api');assert.equal(app.player.status,'playing');
  }finally{pickerUnmount(app);}
});

test('keyboard navigation changes only the highlighted option until Enter selects it',()=>{
  const app=pickerMount();try{
    pickerOpen(app);pickerType(app,'saml');const ids=pickerIds(app);assert.ok(ids.length>2);
    assert.equal(pickerKey(app,'Home').defaultPrevented,true);assert.equal(pickerActive(app)?.dataset.scenarioOption,ids[0]);
    pickerKey(app,'ArrowDown');assert.equal(pickerActive(app)?.dataset.scenarioOption,ids[1]);pickerKey(app,'ArrowUp');assert.equal(pickerActive(app)?.dataset.scenarioOption,ids[0]);
    pickerKey(app,'End');assert.equal(pickerActive(app)?.dataset.scenarioOption,ids.at(-1));assert.equal(app.labScenarioId,'basic-keycloak');
    assert.equal(pickerKey(app,'Enter').defaultPrevented,true);assert.equal(app.labScenarioId,ids.at(-1));assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,pickerTitle(app,ids.at(-1)));assert.equal(pickerInput(app).getAttribute('aria-expanded'),'false');
  }finally{pickerUnmount(app);}
});

test('no results and Enter cannot accidentally switch or reset the active scenario',()=>{
  const app=pickerMount();try{
    app.selectLabScenario('lab-dpop');const title=pickerTitle(app,'lab-dpop');pickerOpen(app);pickerType(app,'zzzz-no-such-scenario-zzzz');
    assert.equal(pickerRows(app).length,0);assert.match(pickerText(app.querySelector('#lab-scenario-search-status')),/no|0/i);assert.ok(!pickerInput(app).getAttribute('aria-activedescendant'),'no missing option is exposed as active');
    for(const key of ['ArrowDown','ArrowUp','Home','End','Enter'])pickerKey(app,key);
    assert.equal(app.labScenarioId,'lab-dpop');assert.equal(pickerRows(app).length,0);pickerKey(app,'Escape');assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,title);
  }finally{pickerUnmount(app);}
});

test('Escape, Tab and outside focus dismiss a query and restore the selected title',()=>{
  const app=pickerMount();try{
    app.selectLabScenario('lab-saml-artifact');const title=pickerTitle(app,'lab-saml-artifact');
    pickerOpen(app);pickerType(app,'DPoP');assert.equal(pickerKey(app,'Escape').defaultPrevented,true);assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,title);
    pickerOpen(app);pickerType(app,'nonce');assert.equal(pickerKey(app,'Tab').defaultPrevented,false,'native Tab navigation stays available');assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,title);
    pickerOpen(app);pickerType(app,'CIBA');pickerInput(app).dispatchEvent(new HarnessEvent('focusout',{relatedTarget:app.refs.play}));assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,title);
    pickerOpen(app);pickerType(app,'refresh');app.querySelector('#scenario-title').dispatchEvent(new HarnessEvent('pointerdown'));assert.equal(pickerMenu(app).hidden,true);assert.equal(pickerInput(app).value,title);assert.equal(app.labScenarioId,'lab-saml-artifact');
  }finally{pickerUnmount(app);}
});

test('native, catalog and programmatic selections all synchronize the inline scenario title',()=>{
  const app=pickerMount();try{
    const native=app.refs['lab-scenario'];native.value='lab-dpop';native.dispatchEvent(new HarnessEvent('change'));assert.equal(pickerInput(app).value,pickerTitle(app,'lab-dpop'));
    pickerOpen(app);pickerType(app,'nonce');app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-saml-artifact"]').click();assert.equal(app.labScenarioId,'lab-saml-artifact');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-saml-artifact'));assert.equal(pickerMenu(app).hidden,true);
    app.selectLabScenario('lab-bff-api');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-bff-api'));app.selectLabScenario('this-id-does-not-exist');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-bff-api'));
  }finally{pickerUnmount(app);}
});

test('typing into a closed field preserves the query, including immediately after selecting without another focus event',()=>{
  const app=pickerMount();try{
    assert.equal(pickerMenu(app).hidden,true);pickerType(app,'SAML Artifact');assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'SAML Artifact');assert.deepEqual(pickerIds(app),['lab-saml-artifact']);
    pickerChoose(app,'lab-saml-artifact');assert.equal(pickerMenu(app).hidden,true);assert.equal(app.labScenarioId,'lab-saml-artifact');
    // Clicking an option keeps focus in the editable field in the real browser;
    // the next input event must work even though no new focusin event fires.
    pickerType(app,'DPoP nonce');assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'DPoP nonce');assert.deepEqual(pickerIds(app).filter(id=>LAB_SCENARIOS.some(model=>model.id===id)).slice().sort(),pickerExpected('DPoP nonce').slice().sort());assert.equal(app.labScenarioId,'lab-saml-artifact','a reopened search still does not select a result');
  }finally{pickerUnmount(app);}
});

test('choosing Core lab through the inline search restores the configurable setup saved before visiting a scenario',()=>{
  const app=pickerMount();try{
    for(const [id,value]of [['mode','password-totp'],['architecture','web'],['upstream','external']]){const control=app.refs[id];control.value=value;control.dispatchEvent(new HarnessEvent('change'));}
    const saved={mode:app.mode,architecture:app.architecture,upstream:app.upstream};pickerOpen(app);pickerType(app,'DPoP nonce');pickerChoose(app,'lab-dpop');assert.equal(app.labScenarioId,'lab-dpop');
    pickerOpen(app);pickerType(app,'Core lab');assert.ok(pickerIds(app).includes('core'));pickerChoose(app,'core');assert.equal(app.labScenarioId,'core');assert.deepEqual({mode:app.mode,architecture:app.architecture,upstream:app.upstream},saved);assert.equal(app.refs.mode.disabled,false);assert.equal(pickerInput(app).value,pickerTitle(app,'core'));
  }finally{pickerUnmount(app);}
});

test('the first Basic Keycloak sign-in preset shows a single-realm browser password login with Code and PKCE',()=>{
  const app=pickerMount();try{
    app.selectLabScenario('lab-dpop');pickerOpen(app);pickerType(app,'Basic Keycloak sign-in');pickerChoose(app,'basic-keycloak');
    assert.equal(app.labScenarioId,'basic-keycloak');assert.equal(app.labModel,null,'the preset reuses the configurable core');assert.equal(app.mode,'password');assert.equal(app.architecture,'web');assert.equal(app.upstream,'single');assert.equal(app.applicationProtocol,'oidc');assert.equal(app.brokerProtocol,'oidc');assert.equal(app.oidcFlow,'authorization-code');assert.equal(app.tokenProtection,'signed');assert.equal(app.assertionProtection,'signed');
    assert.equal(pickerInput(app).value,'Basic Keycloak sign-in');assert.equal(app.refs.mode.disabled,false,'the preset remains configurable');
    assert.ok(app.steps.some(step=>step.fields.includes('password')),'the provider receives an account password');assert.ok(app.steps.some(step=>step.fields.includes('codeA')),'Realm A issues the app authorization code');assert.ok(app.steps.some(step=>step.fields.includes('codeVerifier')),'the application uses PKCE');
    const broker=app.refs.actors.querySelector('[data-actor="realmB"]');assert.ok(!broker||broker.hidden,'the single-realm preset does not display a second identity provider');
    assert.ok(app.steps.every(step=>![step.from,step.to].includes('realmB')),'there is no upstream broker');assert.ok(app.steps.every(step=>!step.fields.some(id=>['codeB','clientIdBroker','otpCode','otpSecret','credentialPrivateKey','assertionSignature'].includes(id))),'no second-realm exchange, OTP or passkey factor is inserted');
    assert.equal(LAB_SCENARIOS.length,43,'the quick preset is not counted as another extended model');
  }finally{pickerUnmount(app);}
});
