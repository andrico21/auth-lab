import test from 'node:test';
import assert from 'node:assert/strict';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {ScenarioPicker,filterScenarioOptions} from '../src/scenario-picker.js';
import {normalizeSearchIdentifier,normalizeSearchProse,searchAliases,prepareSearchQuery,createSearchFields,mergeSearchFields,rankSearchFields,localizedSearchIndex} from '../src/locale-search.js';

// Isolated search/picker behavior, not browser IME, layout or a translation
// corpus acceptance claim. No app, model evaluator or production catalog loads.
const {document}=installHarness();
const escape=value=>String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const ids=rows=>rows.map(row=>row.id);
function localization(catalogs,locale='uk',messages={}) {
  return {
    locale,revision:1,calls:[],pluralCalls:[],
    activate(tag){this.locale=tag;this.revision++;},
    searchEntry(kind,id,record){this.calls.push({kind,id,record});return this.locale==='en'?null:catalogs[this.locale]?.[id]||{};},
    explain(owner,field,source,context={}){
      if(this.locale==='en')return source;
      const entry=catalogs[this.locale]?.[owner.slice(owner.indexOf(':')+1)];
      return field==='searchVariants.label'?entry?.searchVariants?.find(variant=>variant.id===context.variantId)?.label??source:entry?.[field]??source;
    },
    explainHtml(owner,field,source,context={}){return escape(this.explain(owner,field,source,context));},
    text(key,source){return messages[this.locale]?.[key]??source;},
    plural(key,count,source,params){this.pluralCalls.push({key,count,source,params});const message=messages[this.locale]?.[key];return typeof message==='function'?message(count):source;},
  };
}
function mount(options,localizer=null,settings={}) {
  const root=document.createElement('div'),selected=[];
  root.innerHTML='<input id="locale-test-search"><button id="locale-test-clear" hidden>×</button><button id="locale-test-toggle"></button><div id="locale-test-menu" hidden><span id="locale-test-search-status"></span><div id="locale-test-results"></div></div>';
  document.body.appendChild(root);
  const picker=new ScenarioPicker(root,options,(id,result)=>selected.push({id,result}),document.body,{prefix:'locale-test',optionPrefix:'locale-option',optionAttribute:'data-test-option',localization:localizer,...settings});
  return {picker,selected,dispose(){picker.destroy();document.body.removeChild(root);}};
}
const type=(picker,value)=>{picker.input.value=value;picker.input.dispatchEvent(new HarnessEvent('input'));};
const key=(picker,value,init={})=>{const event=new HarnessEvent('keydown',{key:value,...init});picker.input.dispatchEvent(event);return event;};
const active=picker=>picker.results?.[picker.activeIndex]?.id;
const options=()=>[{id:'alpha',title:'Alpha lesson',summary:'Original explanation',category:'Original group'},{id:'beta',title:'Beta lesson',summary:'Other explanation',category:'Original group'}];

test('native Cyrillic, Hebrew, Arabic and mixed protocol queries use public filtering without rewriting metadata',()=>{
  const records=options();records[0].searchTags=['PKINIT'];
  const before=JSON.stringify(records),localizer=localization({
    ru:{alpha:{title:'Проверка подписи',summary:'Проверка доверия'}},
    uk:{alpha:{title:'Перевірка підпису',summary:'Довіра до відповіді'}},
    he:{alpha:{title:'אימות חתימה',summary:'בדיקת אמון'}},
    'ar-AE':{alpha:{title:'التحقق من التوقيع',summary:'التحقق من الثقة'}},
  });
  for(const [locale,query,mixed] of [['ru','подписи','PKINIT подписи'],['uk','підпису','PKINIT підпису'],['he','חתימה','PKINIT חתימה'],['ar-AE','التوقيع','PKINIT التوقيع']]){
    localizer.activate(locale);
    assert.deepEqual(ids(filterScenarioOptions(records,query,localizer)),['alpha']);
    assert.deepEqual(ids(filterScenarioOptions(records,mixed,localizer)),['alpha']);
  }
  assert.equal(JSON.stringify(records),before);
});

test('only genuinely empty or whitespace queries return the full deduplicated inventory',()=>{
  const records=options(),localizer=localization({uk:{alpha:{title:'Перевірка'}}});
  for(const query of ['中文','איןהתאמה','لايوجدتطابق','неіснуючий','!!!','___','\u0301','+','🧪']){
    assert.equal(prepareSearchQuery(query).empty,false);
    assert.deepEqual(filterScenarioOptions(records,query,localizer),[],query);
  }
  for(const query of ['', ' \t\n\u00a0 '])assert.deepEqual(ids(filterScenarioOptions([...records,records[0]],query,localizer)),['alpha','beta']);
});

test('Unicode normalization preserves Ukrainian and other distinct Cyrillic letters',()=>{
  assert.equal(normalizeSearchProse('І Ї Є Ґ Й И'),'і ї є ґ й и');
  assert.deepEqual(searchAliases('і ї є ґ й'),[]);
  const records=['і','ї','є','ґ','й','и','е','г'].map((letter,index)=>({id:'letter-'+index,title:letter}));
  for(const record of records)assert.deepEqual(ids(filterScenarioOptions(records,record.title.toUpperCase())),[record.id]);
  assert.equal(normalizeSearchIdentifier(' CÓDE_VERIFIER+ '),'códe_verifier+');
  assert.equal(normalizeSearchIdentifier('pam.d'),'pam.d');
});

test('Latin prose aliases explicitly support accents, German umlaut spellings and Polish ł',()=>{
  const records=[{id:'fr',title:'Vérification du café'},{id:'de',title:'Ärger über Größen'},{id:'pl',title:'Zażółć gęślą jaźń'}];
  for(const [query,id] of [['verification cafe','fr'],['arger uber grossen','de'],['aerger ueber groessen','de'],['zazolc gesla jazn','pl']])assert.deepEqual(ids(filterScenarioOptions(records,query)),[id]);
  assert.deepEqual(searchAliases('ą ć ę ł ń ó ś ź ż'),['a c e l n o s z z']);
  assert.equal(records[2].title,'Zażółć gęślą jaźń');
  const strict=createSearchFields({identifiers:['żółć','CÓDE_VERIFIER']});
  assert.equal(rankSearchFields(strict,prepareSearchQuery('zolc')),null);
  assert.equal(rankSearchFields(strict,prepareSearchQuery('code_verifier')),null);
  assert.equal(rankSearchFields(createSearchFields({identifiers:['zolc']}),prepareSearchQuery('żółć')),null);
  assert.equal(rankSearchFields(strict,prepareSearchQuery('CÓDE_VERIFIER')),0);
  assert.equal(rankSearchFields(createSearchFields({phrases:['Café'],aliases:false}),prepareSearchQuery('cafe',{aliases:false})),null);
});

test('vowel aliases affect Hebrew and Arabic prose copies without folding meaningful letter distinctions',()=>{
  const records=[{id:'he',title:'בְּדִיקָה'},{id:'ar',title:'تَحَقُّق'},{id:'hamza',title:'أمان'},{id:'shin',title:'שׁיר'}];
  assert.deepEqual(ids(filterScenarioOptions(records,'בדיקה')),['he']);
  assert.deepEqual(ids(filterScenarioOptions(records,'تحقق')),['ar']);
  assert.deepEqual(filterScenarioOptions(records,'امان'),[],'Arabic hamza is not a vowel alias');
  assert.deepEqual(filterScenarioOptions(records,'שיר'),[],'Hebrew shin/sin dots are not discarded');
  assert.equal(records[0].title,'בְּדִיקָה');assert.equal(records[1].title,'تَحَقُّق');
});

test('SPAKE2 and SPAKE2+ remain separate in every lane, including localized prose',()=>{
  const records=[{id:'balanced',title:'SPAKE2'},{id:'augmented',title:'SPAKE2+'}];
  const localizer=localization({uk:{balanced:{title:'Підтвердження SPAKE2'},augmented:{title:'Підтвердження SPAKE2+'}}});
  assert.deepEqual(ids(filterScenarioOptions(records,'SPAKE2',localizer)),['balanced']);
  assert.deepEqual(ids(filterScenarioOptions(records,'SPAKE2+',localizer)),['augmented']);
  assert.deepEqual(ids(filterScenarioOptions(records,'підтвердження SPAKE2',localizer)),['balanced']);
  assert.deepEqual(ids(filterScenarioOptions(records,'підтвердження SPAKE2+',localizer)),['augmented']);
  assert.deepEqual(ids(filterScenarioOptions(records,'SPAKE',localizer)),['balanced','augmented']);
});

test('every original English tier outranks additive localized prose and duplicate tags never boost it',()=>{
  const records=[{id:'localized',title:'Unrelated'},{id:'context',title:'Other lesson',summary:'PKINIT explanation'},{id:'technical',title:'PKINIT'},{id:'tie',title:'Another lesson',searchTags:['PKINIT','PKINIT','PKINIT']}];
  const localizer=localization({uk:{localized:{title:'PKINIT',searchTags:['PKINIT','PKINIT']}}});
  assert.deepEqual(ids(filterScenarioOptions(records,'PKINIT',localizer)),['technical','tie','context','localized']);
  assert.deepEqual(ids(filterScenarioOptions([...records,records[0]],'PKINIT',localizer)),['technical','tie','context','localized']);
  localizer.activate('en');
  assert.deepEqual(filterScenarioOptions(records,'PKINIT',localizer),filterScenarioOptions(records,'PKINIT'));
});

test('localized cases retain canonical labels, explicit denial selection and single-case term boundaries',()=>{
  const record={id:'model',title:'PKINIT',searchVariants:[{id:'denied',label:'Offline denial'},{id:'success',label:'Online success'}]};
  const localizer=localization({uk:{model:{title:'Перевірка',searchVariants:[{id:'denied',label:'Відмова без мережі'},{id:'success',label:'Успіх у мережі'}]}}});
  const [row]=filterScenarioOptions([record],'PKINIT відмова',localizer);
  assert.equal(row.variantId,'denied');assert.equal(row.caseLabel,'Offline denial');assert.equal(row.title,'PKINIT');
  assert.deepEqual(filterScenarioOptions([record],'відмова успіх',localizer),[]);
  assert.equal(record.variantId,undefined);
  localizer.activate('uk');localizer.searchEntry=()=>({searchVariants:[{id:'denied',label:'Відмова',searchTags:['відмова','відмова']},{id:'success',label:'Відмова'}]});
  const [multiple]=filterScenarioOptions([record],'відмова',localizer);
  assert.deepEqual(multiple.matchingVariantIds,['denied','success']);
  assert.deepEqual(multiple.matchingCases,[{id:'denied',label:'Offline denial'},{id:'success',label:'Online success'}]);
  assert.equal(multiple.caseLabel,'2 matching cases');
});

test('identical translated captions do not merge distinct scenario identities or change stable ties',()=>{
  const records=options(),localizer=localization({uk:{alpha:{title:'Одна назва'},beta:{title:'Одна назва'}}});
  assert.deepEqual(ids(filterScenarioOptions(records,'одна назва',localizer)),['alpha','beta']);
  assert.notEqual(filterScenarioOptions(records,'одна назва',localizer)[0],filterScenarioOptions(records,'одна назва',localizer)[1]);
});

test('active-revision overlay indexes invalidate mutable metadata without evaluating or enumerating model traces',()=>{
  const record={id:'model',title:'Original',searchVariants:[{id:'denied',label:'Denial',searchTags:['old']}],evaluate(){throw new Error('No evaluation during search');}};
  Object.defineProperty(record,'trace',{get(){throw new Error('No trace access during search');}});
  const localizer=localization({uk:{model:{title:'Перший'}},ru:{model:{title:'Второй'}}});
  const first=localizedSearchIndex(localizer,'scenario',record.id,record);
  assert.equal(localizedSearchIndex(localizer,'scenario',record.id,record),first);assert.equal(localizer.calls.length,1);
  record.searchVariants[0].searchTags.push('new');
  assert.notEqual(localizedSearchIndex(localizer,'scenario',record.id,record),first);assert.equal(localizer.calls.length,2);
  localizer.activate('ru');
  assert.deepEqual(ids(filterScenarioOptions([record],'второй',localizer)),['model']);
  assert.deepEqual(filterScenarioOptions([record],'перший',localizer),[]);
  localizer.activate('uk');assert.deepEqual(ids(filterScenarioOptions([record],'перший',localizer)),['model']);
  localizer.activate('en');assert.equal(localizedSearchIndex(localizer,'scenario',record.id,record),null);
});

test('reusable field/glossary helpers combine protected names and active localized explanations',()=>{
  const record={id:'codeVerifier',name:'code_verifier',meaning:'An original English explanation'};
  const localizer=localization({uk:{codeVerifier:{meaning:'Підтвердження запиту'}}});
  const original=createSearchFields({identifiers:[record.id,record.name],context:[record.meaning]});
  const overlay=localizedSearchIndex(localizer,'field',record.id,record),combined=mergeSearchFields(original,overlay.base);
  assert.equal(rankSearchFields(original,prepareSearchQuery('code_verifier')),0);
  assert.equal(rankSearchFields(combined,prepareSearchQuery('code_verifier підтвердження')),3);
  assert.equal(rankSearchFields(combined,prepareSearchQuery('немає')),null);
  assert.equal(record.meaning,'An original English explanation');
});

test('picker localizes presentation, full counts and accessible controls while callbacks stay canonical',()=>{
  const records=options();records[0].profileLabel='MIT profile · reviewed';
  const localizer=localization({uk:{alpha:{title:'Перевірка <підпису>',summary:'Пояснення',category:'Навчання'},beta:{title:'Інший урок',summary:'Деталі',category:'Навчання'}}},'uk',{uk:{
    'ui.scenario-picker.scenario.clear':'Очистити пошук',
    'ui.scenario-picker.scenario.toggle':'Показати уроки',
    'ui.scenario-picker.scenario.results':'Уроки',
    'ui.scenario-picker.scenario.placeholder':'Знайти урок',
    'ui.scenario-picker.scenario.empty':'Немає збігів.',
    'ui.scenario-picker.scenario.match-count':count=>count+' результатів пошуку',
  }});
  const fixture=mount(records,localizer),{picker,selected}=fixture;
  try{
    assert.equal(picker.input.value,'Перевірка <підпису>');picker.open();
    assert.equal(picker.input.getAttribute('placeholder'),'Знайти урок');
    assert.equal(picker.clearButton.getAttribute('aria-label'),'Очистити пошук');
    assert.equal(picker.toggleButton.getAttribute('aria-label'),'Показати уроки');
    assert.equal(picker.list.getAttribute('aria-label'),'Уроки');
    assert.equal(picker.status.textContent,'2 результатів пошуку');
    assert.equal(picker.list.querySelector('strong').textContent,'Перевірка <підпису>');
    assert.equal(picker.list.querySelector('[role="group"]').getAttribute('aria-label'),'Навчання');
    const profile=picker.list.querySelector('.scenario-picker-profile bdi');
    assert.equal(profile.textContent,records[0].profileLabel);assert.equal(profile.getAttribute('dir'),'ltr');assert.equal(profile.getAttribute('translate'),'no');
    type(picker,'Перевірка');key(picker,'Enter');
    assert.equal(selected[0].id,'alpha');assert.equal(selected[0].result,records[0]);assert.equal(selected[0].result.title,'Alpha lesson');
    type(picker,'немаєзбігів');assert.equal(picker.list.querySelector('.scenario-picker-empty').textContent,'Немає збігів.');
    assert.equal(localizer.pluralCalls.at(-1).count,0);assert.deepEqual(localizer.pluralCalls.at(-1).params,{count:0});
  }finally{fixture.dispose();}
});

test('multiple matching cases use a full plural message without changing canonical case payloads',()=>{
  const records=[{id:'model',title:'Original',searchVariants:[{id:'one',label:'First denial'},{id:'two',label:'Second denial'}]}];
  const localizer=localization({uk:{model:{searchVariants:[{id:'one',label:'Відмова'},{id:'two',label:'Відмова'}]}}},'uk',{uk:{'ui.scenario-picker.matching-cases':count=>count+' варіанти'}});
  const fixture=mount(records,localizer),{picker,selected}=fixture;
  try{
    type(picker,'відмова');assert.equal(picker.list.querySelector('.scenario-picker-case').textContent,'2 варіанти');
    key(picker,'Enter');assert.equal(selected[0].result.caseLabel,'2 matching cases');assert.deepEqual(selected[0].result.matchingVariantIds,['one','two']);
  }finally{fixture.dispose();}
});

test('workspace display overlays use their own owner/kind and retain selected-label canonical options',()=>{
  const records=[{id:'family-web-signin',title:'Sign-in',selectedLabel:'Web / Sign-in',summary:'Original',category:'Web',scenarioId:'alpha'}];
  const localizer=localization({uk:{'family-web-signin':{title:'Вхід',selectedLabel:'Веб / Вхід',category:'Веб'}}});
  const fixture=mount(records,localizer,{localizationKind:'workspace',singular:'learning destination',plural:'learning destinations'}),{picker,selected}=fixture;
  try{
    assert.equal(picker.input.value,'Веб / Вхід');type(picker,'вхід');key(picker,'Enter');
    assert.equal(selected[0].result,records[0]);assert.equal(records[0].selectedLabel,'Web / Sign-in');
    assert.ok(localizer.calls.some(call=>call.kind==='workspace'));
    assert.ok(localizer.pluralCalls.some(call=>call.key==='ui.scenario-picker.workspace.match-count'));
  }finally{fixture.dispose();}
});

test('locale refresh retains raw open query, caret and active stable ID even when ranking changes',()=>{
  const records=options(),localizer=localization({ru:{alpha:{title:'Пошук'},beta:{title:'Пошук'}},uk:{alpha:{title:'Інше',summary:'Пошук'},beta:{title:'Пошук'}}},'ru');
  const fixture=mount(records,localizer),{picker,selected}=fixture;
  try{
    const raw='  Пошук\t ';type(picker,raw);key(picker,'End');assert.equal(active(picker),'beta');
    picker.input.selectionStart=3;picker.input.selectionEnd=5;
    localizer.activate('uk');assert.equal(picker.refreshLocale(),true);
    assert.equal(picker.opened,true);assert.equal(picker.query,raw);assert.equal(picker.input.value,raw);assert.equal(active(picker),'beta');
    assert.equal(picker.input.selectionStart,3);assert.equal(picker.input.selectionEnd,5);assert.deepEqual(selected,[]);
  }finally{fixture.dispose();}
});

test('a locale-removed active row leaves no Enter selection even when another result still matches',()=>{
  const records=options(),localizer=localization({ru:{alpha:{title:'Пошук'},beta:{title:'Пошук'}},uk:{alpha:{title:'Інше'},beta:{title:'Пошук'}}},'ru');
  const fixture=mount(records,localizer),{picker,selected}=fixture;
  try{
    type(picker,'Пошук');assert.equal(active(picker),'alpha');localizer.activate('uk');picker.refreshLocale();
    assert.deepEqual(ids(picker.results),['beta']);assert.equal(picker.activeIndex,-1);assert.equal(picker.input.hasAttribute('aria-activedescendant'),false);
    key(picker,'Enter');assert.deepEqual(selected,[]);assert.equal(picker.opened,true);
    key(picker,'ArrowUp');assert.equal(active(picker),'beta');key(picker,'Enter');assert.equal(selected[0].id,'beta');
  }finally{fixture.dispose();}
});

test('new locale matches do not create a default active row for a previously unmatched draft',()=>{
  const localizer=localization({ru:{},uk:{beta:{title:'Пошук'}}},'ru'),fixture=mount(options(),localizer),{picker,selected}=fixture;
  try{
    type(picker,'Пошук');assert.equal(picker.activeIndex,-1);localizer.activate('uk');picker.refreshLocale();
    assert.deepEqual(ids(picker.results),['beta']);assert.equal(picker.activeIndex,-1);key(picker,'Enter');assert.deepEqual(selected,[]);
    type(picker,'Beta');assert.equal(active(picker),'beta');
  }finally{fixture.dispose();}
});

test('transient and suspended nonempty drafts preserve raw bytes and invalidate missing active IDs on locale changes',()=>{
  const localizer=localization({ru:{alpha:{title:'Пошук'},beta:{title:'Пошук'}},uk:{alpha:{title:'Інше'},beta:{title:'Пошук'}},he:{alpha:{title:'אימות'},beta:{title:'בדיקה'}}},'ru');
  const fixture=mount(options(),localizer),{picker,selected}=fixture;
  try{
    const raw=' \tПошук  ';type(picker,raw);key(picker,'End');picker.close({preserveDraft:true});
    const draft=picker.draft;assert.equal(draft.query,raw);assert.equal(draft.activeId,'beta');
    localizer.activate('uk');picker.refreshLocale();assert.equal(picker.opened,false);assert.equal(picker.draft,draft);assert.equal(draft.query,raw);assert.equal(draft.activeId,'beta');
    picker.suspend();const suspended=picker.suspended;assert.equal(suspended.query,raw);assert.equal(picker.input.value,raw);
    localizer.activate('he');picker.refreshLocale();assert.equal(picker.suspended,suspended);assert.equal(suspended.query,raw);assert.equal(suspended.activeId,null);assert.equal(picker.input.value,raw);
    picker.open();assert.equal(picker.query,raw);assert.equal(picker.input.value,raw);assert.equal(picker.activeIndex,-1);key(picker,'Enter');assert.deepEqual(selected,[]);
    key(picker,'Escape');picker.suspend();picker.open();assert.equal(picker.input.value,'');assert.equal(picker.draft,null);assert.equal(picker.suspended,null);
  }finally{fixture.dispose();}
});

test('empty and whitespace visits never turn into retained MC-R06 drafts during locale refreshes',()=>{
  const localizer=localization({ru:{alpha:{title:'Первый'}},uk:{alpha:{title:'Перший'}}},'ru'),fixture=mount(options(),localizer),{picker}=fixture;
  try{
    for(const raw of ['', ' \t ']){
      picker.open();if(raw)type(picker,raw);picker.close({preserveDraft:true});assert.equal(picker.draft,null);
      localizer.activate('uk');picker.refreshLocale();assert.equal(picker.opened,false);assert.equal(picker.input.value,'Перший');assert.equal(picker.draft,null);
      picker.suspend();assert.equal(picker.suspended,null);assert.equal(picker.input.value,'Перший');
      picker.open();assert.equal(picker.input.value,'');key(picker,'Escape');
    }
  }finally{fixture.dispose();}
});

test('composition tracking defers refresh and prevents stale/default selection until committed native input is filtered',()=>{
  const localizer=localization({uk:{alpha:{title:'Перевірка'}}}),fixture=mount(options(),localizer),{picker,selected}=fixture;
  try{
    type(picker,'Alpha');assert.equal(active(picker),'alpha');
    picker.input.dispatchEvent(new HarnessEvent('compositionstart'));type(picker,'未完成');assert.equal(picker.composing,true);assert.equal(active(picker),'alpha');
    localizer.activate('uk');assert.equal(picker.refreshLocale(),false);assert.equal(picker.localeRefreshPending,true);assert.equal(picker.input.value,'未完成');
    for(const value of ['Enter','Escape','ArrowDown'])assert.equal(key(picker,value,{isComposing:false}).defaultPrevented,false);
    assert.deepEqual(selected,[]);assert.equal(picker.opened,true);
    picker.input.dispatchEvent(new HarnessEvent('compositionend'));assert.equal(picker.composing,false);assert.equal(picker.localeRefreshPending,false);
    assert.equal(picker.query,'未完成');assert.deepEqual(picker.results,[]);assert.equal(picker.activeIndex,-1);key(picker,'Enter');assert.deepEqual(selected,[]);
    picker.clearButton.click();assert.equal(picker.query,'');assert.equal(picker.input.value,'');assert.deepEqual(ids(picker.results),['alpha','beta']);assert.deepEqual(selected,[]);
    type(picker,'Beta');assert.equal(active(picker),'beta');
  }finally{fixture.dispose();}
});

test('isComposing and legacy keyCode 229 each guard Enter and native navigation independently',()=>{
  const fixture=mount(options()),{picker,selected}=fixture;
  try{
    type(picker,'Alpha');
    for(const init of [{isComposing:true},{keyCode:229}])for(const value of ['Enter','Escape','ArrowDown','Home']){
      assert.equal(key(picker,value,init).defaultPrevented,false);assert.equal(active(picker),'alpha');assert.equal(picker.opened,true);assert.deepEqual(selected,[]);
    }
    key(picker,'Escape');assert.equal(picker.opened,false);
    // A paste is a new native input event, not a resurrection of the old result.
    type(picker,'غيرمطابق');key(picker,'Enter');assert.deepEqual(selected,[]);assert.equal(picker.activeIndex,-1);
  }finally{fixture.dispose();}
});

for(const [locale,title,query] of [['ru','Проверка подписи','подписи'],['uk','Перевірка підпису','підпису'],['he','אימות חתימה','חתימה'],['ar-AE','التحقق من التوقيع','التوقيع']])test(locale+' native input events filter visible picker rows without activation or model evaluation',()=>{
  const records=options();records[0].evaluate=()=>{throw new Error('Search must not evaluate a model');};
  const localizer=localization({[locale]:{alpha:{title}}},locale),fixture=mount(records,localizer),{picker,selected}=fixture;
  try{
    const raw='  '+query+' ';type(picker,raw);
    assert.equal(picker.input.value,raw);assert.equal(picker.query,raw);
    assert.deepEqual(picker.list.querySelectorAll('[data-test-option]').map(row=>row.getAttribute('data-test-option')),['alpha']);
    assert.equal(picker.list.querySelector('strong').textContent,title);assert.deepEqual(selected,[]);
    type(picker,'!!!');assert.equal(picker.list.querySelectorAll('[data-test-option]').length,0);key(picker,'Enter');assert.deepEqual(selected,[]);
  }finally{fixture.dispose();}
});

test('IME input after a committed choice reopens the still-focused closed picker without another focus event',()=>{
  const localizer=localization({uk:{beta:{title:'Перевірка'}}}),fixture=mount(options(),localizer),{picker,selected}=fixture;
  try{
    type(picker,'Alpha');key(picker,'Enter');assert.equal(picker.opened,false);assert.equal(selected.length,1);
    picker.input.dispatchEvent(new HarnessEvent('compositionstart'));type(picker,'Перевірка');
    assert.equal(picker.opened,true);key(picker,'Enter',{keyCode:229});assert.equal(selected.length,1);
    picker.input.dispatchEvent(new HarnessEvent('compositionend'));
    assert.equal(picker.input.value,'Перевірка');assert.equal(picker.query,'Перевірка');assert.deepEqual(ids(picker.results),['beta']);
    assert.equal(selected.length,1,'composition commits text, not the matched scenario');
  }finally{fixture.dispose();}
});

test('identifier names repeated in prose cannot promote punctuation-forgiving matches above duplicate true names',()=>{
  for(const names of [
    ['Conditions@NotBefore','Conditions/@NotBefore'],
    ['id token','id_token'],
    ['user/name','user-name','user.name'],
    ['pam-d','pam.d'],
    ['SPAKE2+','SPAKE2'],
  ]){
    const records=[...names,...names].map((name,index)=>({id:'field-'+index,name,fields:createSearchFields({identifiers:[name],phrases:[name]})}));
    for(const name of [...names].reverse()){
      const query=prepareSearchQuery(name),rows=records.map(record=>({...record,rank:rankSearchFields(record.fields,query)})).filter(record=>record.rank!==null).sort((a,b)=>a.rank-b.rank);
      const expected=records.filter(record=>record.name===name).map(record=>record.id);
      assert.deepEqual(rows.slice(0,expected.length).map(record=>record.id),expected,name+' exact duplicate identities precede every folded spelling');
      if(name==='SPAKE2'||name==='SPAKE2+')assert.ok(rows.every(record=>record.name===name),'The + mechanism boundary stays distinct');
    }
  }
  const records=['Conditions@NotBefore','Conditions/@NotBefore'].map(name=>createSearchFields({identifiers:[name],phrases:[name]}));
  assert.ok(records.every(fields=>rankSearchFields(fields,prepareSearchQuery('Conditions-NotBefore'))!==null),'Punctuation-forgiving discovery is retained below true identifier identity');
});

test('scenario general prose/title exact matches retain stable priority over token and context discovery',()=>{
  const records=[
    {id:'context',title:'Other lesson',summary:'token filtering'},
    {id:'tokens',title:'Token policy filtering'},
    {id:'title',title:'Token filtering'},
    {id:'tag',title:'Remote policy',searchTags:['token filtering']},
  ];
  assert.deepEqual(ids(filterScenarioOptions(records,'token filtering')),['title','tag','tokens','context']);
});
