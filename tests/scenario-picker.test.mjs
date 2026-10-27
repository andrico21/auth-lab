import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {readFileSync} from 'node:fs';
import {filterScenarioOptions} from '../src/scenario-picker.js';
const expansionPlan=JSON.parse(readFileSync(new URL('../docs/expansion/plan-manifest.json',import.meta.url),'utf8')).scenarios;

// Interaction tests only: the offline harness does not implement browser layout,
// screen-reader announcements or the platform's native focus navigation.
const pickerHarness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {LAB_SCENARIOS}=await import('../src/lab-catalog.js');
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
function pickerTitle(app,id){const option=app.scenarioPicker.options.find(option=>option.id===id);assert.ok(option,'selected scenario has picker metadata');return option.selectedLabel||option.title;}
function pickerActive(app){const id=pickerInput(app).getAttribute('aria-activedescendant');return id?app.querySelector('#'+id):null;}
function pickerChoose(app,id){const row=pickerRows(app).find(option=>option.dataset.scenarioOption===id);assert.ok(row,'matching scenario is selectable');row.click();}

test('the scenario field exposes the complete journey inventory through an inline combobox',()=>{
  const app=pickerMount();try{
    const input=pickerInput(app),menu=pickerMenu(app),list=app.querySelector('#lab-scenario-results'),status=app.querySelector('#lab-scenario-search-status');
    assert.ok(app.querySelector('#lab-scenario-picker'));assert.ok(input);assert.ok(menu);assert.ok(status);
    assert.equal(input.getAttribute('role'),'combobox');assert.equal(input.getAttribute('aria-expanded'),'false');assert.equal(input.getAttribute('aria-controls'),list.id);assert.equal(list.getAttribute('role'),'listbox');assert.equal(menu.hidden,true);
    assert.equal(input.value,pickerTitle(app,'basic-keycloak'));assert.equal(app.scenarioPicker.selectedId,app.labScenarioId);
    pickerOpen(app);assert.equal(menu.hidden,false);assert.equal(input.getAttribute('aria-expanded'),'true');
    assert.deepEqual(pickerIds(app).slice().sort(),pickerAllIds.slice().sort());assert.equal(new Set(pickerIds(app)).size,pickerAllIds.length);assert.equal(pickerIds(app)[0],'basic-keycloak','the basic sign-in preset is the first suggestion');
    assert.ok(pickerRows(app).every(row=>row.getAttribute('role')==='option'&&row.id),'results have usable option identities');
    assert.ok(status.getAttribute('aria-live')||status.getAttribute('role')==='status','result feedback can be announced');
  }finally{pickerUnmount(app);}
});
test('independently planned expansion presets are discoverable and cross-protocol choices activate their owning models',()=>{
  const app=pickerMount();try{
    pickerOpen(app);
    const available=new Set(pickerIds(app));
    for(const {id} of expansionPlan)assert.ok(available.has(id),id+' is selectable from the real picker');
    for(const [query,id,workspace] of [
      ['NTLMV2','lab-win-ntlmv2-domain','windows'],
      ['EAP-TLS','lab-net-eap-tls13-wired','network'],
      ['SPAKE','lab-krb-spake-success','kerberos'],
      ['SPAKE2+','lab-pake-spake2plus-success','foundations'],
    ]){
      pickerType(app,query);pickerChoose(app,id);
      assert.equal(app.labScenarioId,id);assert.equal(app.workspace,workspace);assert.equal(pickerMenu(app).hidden,true);
      assert.equal(pickerInput(app).getAttribute('aria-expanded'),'false');
    }
  }finally{pickerUnmount(app);}
});

test('inline search matches folded terms, canonical fields and named cases without activating a result',()=>{
  const app=pickerMount();try{
    pickerOpen(app);
    for(const [query,included,excluded] of [
      ['SAML ARTIFACT','lab-saml-artifact','lab-dpop'],
      ['DPoP nonce','lab-dpop','lab-smb-nonjoined-kerberos'],
      ['CODE_VERIFIER','lab-mcp02','lab-ad-first-sign-in'],
      ['LAB-WIN-CREDSSP-V6-KERBEROS','lab-win-credssp-v6-kerberos','lab-win-credssp-v6-ntlm'],
      ['post-change-account-denied','lab-llog04','lab-llog01'],
    ]){
      pickerType(app,query);const matches=pickerIds(app);
      assert.ok(matches.includes(included),query+' finds its declared journey');assert.equal(matches.includes(excluded),false,query+' excludes a different protocol/case');
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
    app.querySelector('#lab-scenario-clear').click();assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'');assert.equal(pickerRows(app).length,pickerAllIds.length);assert.equal(app.labScenarioId,'lab-bff-api');assert.equal(app.player.status,'playing');
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

test('visible picker, catalog and programmatic selections synchronize the inline scenario title and identity',()=>{
  const app=pickerMount();try{
    pickerOpen(app);pickerType(app,'DPoP nonce');pickerChoose(app,'lab-dpop');assert.equal(app.labScenarioId,'lab-dpop');assert.equal(app.scenarioPicker.selectedId,'lab-dpop');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-dpop'));
    app.querySelector('#ready-journeys').open=true;app.querySelector('#lab-open').click();
    pickerOpen(app);pickerType(app,'nonce');app.refs['lab-cards'].querySelector('[data-lab-scenario="lab-saml-artifact"]').click();assert.equal(app.labScenarioId,'lab-saml-artifact');assert.equal(app.scenarioPicker.selectedId,'lab-saml-artifact');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-saml-artifact'));assert.equal(pickerMenu(app).hidden,true);
    app.selectLabScenario('lab-bff-api');assert.equal(app.scenarioPicker.selectedId,'lab-bff-api');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-bff-api'));app.selectLabScenario('this-id-does-not-exist');assert.equal(app.labScenarioId,'lab-bff-api');assert.equal(app.scenarioPicker.selectedId,'lab-bff-api');assert.equal(pickerInput(app).value,pickerTitle(app,'lab-bff-api'));
  }finally{pickerUnmount(app);}
});

test('typing into a closed field preserves the query, including immediately after selecting without another focus event',()=>{
  const app=pickerMount();try{
    assert.equal(pickerMenu(app).hidden,true);pickerType(app,'SAML Artifact');assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'SAML Artifact');assert.deepEqual(pickerIds(app),['lab-saml-artifact']);
    pickerChoose(app,'lab-saml-artifact');assert.equal(pickerMenu(app).hidden,true);assert.equal(app.labScenarioId,'lab-saml-artifact');
    // Clicking an option keeps focus in the editable field in the real browser;
    // the next input event must work even though no new focusin event fires.
    pickerType(app,'DPoP nonce');assert.equal(pickerMenu(app).hidden,false);assert.equal(pickerInput(app).value,'DPoP nonce');assert.ok(pickerIds(app).includes('lab-dpop'));assert.equal(pickerIds(app).includes('lab-saml-artifact'),false);assert.equal(app.labScenarioId,'lab-saml-artifact','a reopened search still does not select a result');
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
  }finally{pickerUnmount(app);}
});

test('repeated folded search reflects changes to the actual option metadata',()=>{
  const option={id:'mutable',title:'Café sign-in',category:'Web',summary:'Code with PKCE',searchText:'code_verifier'},options=[option];
  const ids=query=>filterScenarioOptions(options,query).map(value=>value.id);
  assert.deepEqual(ids('CAFE code_verifier'),['mutable']);
  option.title='Directory logon';
  assert.deepEqual(ids('cafe'),[]);
  option.searchText='kerberos ticket';
  assert.deepEqual(ids('directory ticket'),['mutable']);
  assert.deepEqual(ids('code_verifier'),[]);
  option.category='Mac';option.summary='Platform SSO';
  assert.deepEqual(ids('mac platform'),['mutable']);
  assert.deepEqual(ids('web pkce'),[]);
});

test('SEARCH01 ranks exact phrases, tokens, boundary prefixes and incidental context without tag-count boosting',()=>{
  const options=[
    {id:'context',title:'Other lesson',category:'A',summary:'A remote token filtering explanation'},
    {id:'prefix',title:'Token filterings',category:'B'},
    {id:'tokens',title:'Filtering local token',category:'A'},
    {id:'phrase',title:'Remote administration',category:'B',searchTags:['token filtering']},
    {id:'tie',title:'Another lesson',category:'A',searchTags:['token filtering','token filtering','token filtering']},
  ];
  assert.deepEqual(filterScenarioOptions(options,'token filtering').map(row=>row.id),['phrase','tie','tokens','prefix','context']);
  assert.deepEqual(filterScenarioOptions(options,'').map(row=>row.id),options.map(row=>row.id));
  assert.deepEqual(filterScenarioOptions([...options,options[3]],'token filtering').map(row=>row.id),['phrase','tie','tokens','prefix','context']);
});

test('SEARCH01 preserves identifiers and significant plus while excluding acronym interiors and short prefixes',()=>{
  const options=[
    {id:'lab-punctuation',title:'Café EAP-TLS',searchIdentifiers:['CODE_VERIFIER'],searchTags:['SPAKE2+']},
    {id:'balanced',title:'SPAKE2'},
    {id:'unrelated',title:'TLS alert',summary:'tlsalert is not an LSA lesson'},
    {id:'isolated',title:'Local authority',searchTags:['lsa','lsass','RunAsPPL']},
  ];
  assert.deepEqual(filterScenarioOptions(options,' CAFE__eap-tls ').map(row=>row.id),['lab-punctuation']);
  assert.deepEqual(filterScenarioOptions(options,'CODE_VERIFIER').map(row=>row.id),['lab-punctuation']);
  assert.deepEqual(filterScenarioOptions(options,'LAB-PUNCTUATION').map(row=>row.id),['lab-punctuation']);
  assert.deepEqual(filterScenarioOptions(options,'SPAKE2+').map(row=>row.id),['lab-punctuation']);
  assert.deepEqual(filterScenarioOptions(options,'SPAKE2').map(row=>row.id),['balanced']);
  // Context explicitly says LSA above, so remove that actual token before testing interiors.
  options[2].summary='tlsalert';
  assert.deepEqual(filterScenarioOptions(options,'lsa').map(row=>row.id),['isolated']);
  assert.deepEqual(filterScenarioOptions(options,'ru').map(row=>row.id),[]);
  assert.deepEqual(filterScenarioOptions(options,'run').map(row=>row.id),['isolated']);
});

test('SEARCH01 keeps all query terms in one case and invalidates nested mutable metadata',()=>{
  const option={id:'case-model',title:'Sign-in',searchTags:['pam'],searchVariants:[
    {id:'offline',label:'Offline denial',searchTags:['cached logon']},
    {id:'protected',label:'Protected user',searchTags:['protected users']},
  ]};
  assert.deepEqual(filterScenarioOptions([option],'offline protected'),[]);
  const [offline]=filterScenarioOptions([option],'offline');
  assert.equal(offline.variantId,'offline');assert.equal(offline.caseLabel,'Offline denial');
  assert.equal(option.variantId,undefined);
  option.searchVariants[0].searchTags.push('protected users');
  assert.deepEqual(filterScenarioOptions([option],'protected users')[0].matchingVariantIds,['offline','protected']);
  option.searchVariants[0].searchTags.splice(0);
  assert.equal(filterScenarioOptions([option],'protected users')[0].variantId,'protected');
  option.searchTags[0]='renamed';
  assert.deepEqual(filterScenarioOptions([option],'pam'),[]);
});

test('SEARCH01 combines shared model terms with only the selected case terms at their original rank',()=>{
  const option={id:'shared',title:'Kernel',searchContext:['fallback'],searchVariants:[
    {id:'direct',label:'Direct',searchTags:['handoff']},
    {id:'cached',label:'Cached',searchContext:['deferred']},
  ]},context={id:'incidental',title:'Other lesson',searchContext:['kernel handoff']},options=[context,option];
  const direct=filterScenarioOptions(options,'kernel handoff');
  assert.deepEqual(direct.map(row=>row.id),['shared','incidental']);
  assert.equal(direct[0].variantId,'direct');
  assert.equal(filterScenarioOptions(options,'kernel deferred')[0].variantId,'cached');
  assert.equal(filterScenarioOptions(options,'fallback handoff')[0].variantId,'direct');
  assert.deepEqual(filterScenarioOptions(options,'handoff deferred'),[]);
  option.searchContext[0]='updated';
  assert.deepEqual(filterScenarioOptions(options,'fallback handoff'),[]);
  assert.equal(filterScenarioOptions(options,'updated handoff')[0].variantId,'direct');
  option.searchVariants[0].searchTags[0]='replacement';
  assert.deepEqual(filterScenarioOptions(options,'updated handoff'),[]);
  assert.equal(filterScenarioOptions(options,'updated replacement')[0].variantId,'direct');
});

test('uncategorized lessons stay selectable without an invented category group',()=>{
  const app=pickerMount();try{
    const picker=app.scenarioPicker,selected=[];
    picker.options=[
      {id:'uncategorized',title:'First proof',summary:'An existing lesson without an optional category'},
      {id:'known',title:'Other proof',summary:'A categorized lesson',category:'Protocol group'},
    ];
    picker.onSelect=id=>selected.push(id);
    pickerOpen(app);
    const groupNames=()=>[...picker.list.querySelectorAll('[role="group"]')].map(row=>row.getAttribute('aria-label'));
    assert.deepEqual(groupNames(),['Protocol group']);
    pickerType(app,'proof');assert.deepEqual(pickerIds(app),['uncategorized','known']);
    pickerKey(app,'Home');pickerKey(app,'Enter');assert.deepEqual(selected,['uncategorized']);
    picker.options[0].category='Additional group';
    pickerOpen(app);assert.deepEqual(groupNames(),['Additional group','Protocol group']);
  }finally{pickerUnmount(app);}
});

test('SEARCH01 visible nonempty order equals keyboard order and selecting passes the case row',()=>{
  const app=pickerMount();try{
    const picker=app.scenarioPicker,selected=[];
    picker.options=[
      {id:'incidental',title:'Incidental',category:'First category',summary:'filtering'},
      {id:'exact',title:'Exact',category:'Second category',searchTags:['filtering'],searchVariants:[{id:'case-one',label:'Unique offline case',searchTags:['offline']}]},
      {id:'whole',title:'Filtering lesson',category:'First category'},
    ];
    picker.onSelect=(id,result)=>selected.push({id,result});
    pickerOpen(app);pickerType(app,'filtering');
    assert.deepEqual(pickerIds(app),['exact','whole','incidental']);
    assert.deepEqual(pickerIds(app),picker.results.map(row=>row.id));
    pickerKey(app,'ArrowDown');assert.equal(pickerActive(app).dataset.scenarioOption,'whole');
    pickerKey(app,'Enter');assert.equal(selected[0].id,'whole');
    pickerType(app,'offline');
    assert.equal(pickerRows(app)[0].querySelector('.scenario-picker-case').textContent,'Unique offline case');
    pickerKey(app,'Enter');assert.equal(selected[1].id,'exact');assert.equal(selected[1].result.variantId,'case-one');
  }finally{pickerUnmount(app);}
});

test('SEARCH01 leaves IME and modified navigation to the editable native input',()=>{
  const app=pickerMount();try{
    pickerOpen(app);pickerType(app,'pkinit');
    const before=pickerInput(app).getAttribute('aria-activedescendant');
    for(const init of [{key:'Enter',isComposing:true},{key:'ArrowDown',ctrlKey:true},{key:'Home',shiftKey:true}]){
      const event=new HarnessEvent('keydown',init);pickerInput(app).dispatchEvent(event);
      assert.equal(event.defaultPrevented,false);
      assert.equal(pickerInput(app).getAttribute('aria-activedescendant'),before);
      assert.equal(app.labScenarioId,'basic-keycloak');
    }
  }finally{pickerUnmount(app);}
});
