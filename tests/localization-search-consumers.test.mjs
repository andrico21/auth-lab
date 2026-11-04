import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {installHarness,HarnessElement,HarnessEvent} from './dom-harness.mjs';

// Select an already-built current candidate; this suite never builds or replaces
// resources. Both modes exercise the real catalog and public input handlers.
const emitted=process.env.LOCALIZATION_SEARCH_DOM_BUNDLE;
const sandbox=emitted?{structuredClone,Response,DecompressionStream,atob}:globalThis;
const {document,window,clock,registry}=installHarness(sandbox);
let AuthFlowStudio;
if(emitted){
  const scripts=[...fs.readFileSync(emitted,'utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length,1);
  new vm.Script(scripts[0][1],{filename:'localization-search:standalone'}).runInContext(vm.createContext(sandbox));
  AuthFlowStudio=registry.get('auth-flow-studio');
}else ({AuthFlowStudio}=await import('../src/app.js'));
const operators=JSON.parse(fs.readFileSync(new URL('../docs/windows-protection-expansion/search-fixtures.json',import.meta.url),'utf8')).fixtures;
const nativeQueries={
  ru:{filtering:['фильтрация','фильтрации','фильтрация токена','фильтрация токенов','фильтрации токена'],protection:['защита LSA','защита LSASS','защищённый процесс'],isolated:['изолированная LSA','изоляция учётных данных']},
  uk:{filtering:['фільтрація','фільтрації','фільтрація токена','фільтрація токенів','фільтрації токена'],protection:['захист LSA','захист LSASS','захищений процес'],isolated:['ізольована LSA','ізоляція облікових даних']},
  he:{filtering:['סינון','סינון אסימון','סינון אסימונים','אסימון מסונן'],protection:['הגנת LSA','הגנת LSASS','תהליך מוגן'],isolated:['LSA מבודדת','בידוד אישורים']},
  de:{filtering:['Filterung','Tokenfilterung','Filterung von Token','gefiltertes Token'],protection:['LSA-Schutz','Schutz der LSA','geschützter Prozess'],isolated:['isolierte LSA','Isolation von Anmeldeinformationen']},
  'ar-AE':{filtering:['تصفية','تصفية الرمز المميز','تصفية الرموز المميزة','رمز مميز مصفى'],protection:['حماية LSA','حماية LSASS','عملية محمية'],isolated:['LSA المعزولة','عزل بيانات الاعتماد']},
  fr:{filtering:['filtrage','filtrage du jeton','filtrage des jetons','jeton filtré'],protection:['protection LSA','protection de la LSA','processus protégé'],isolated:['LSA isolée','isolation des informations d’identification']},
  pl:{filtering:['filtrowanie','filtrowania','filtrowanie tokenu','filtrowanie tokenów','filtrowania tokenu','filtrowany token'],protection:['ochrona LSA','ochrona LSASS','proces chroniony'],isolated:['izolowany LSA','izolacja poświadczeń']},
};
const originalReplaceChild=Object.getOwnPropertyDescriptor(HarnessElement.prototype,'replaceChild');
async function mount(locale){
  window.innerWidth=390;window.localStorage={getItem:key=>key==='auth-flow-studio.locale.v1'?'en':'compact',setItem(){}};
  if(!originalReplaceChild)Object.defineProperty(HarnessElement.prototype,'replaceChild',{configurable:true,writable:true,value(next,old){this.insertBefore(next,old);this.removeChild(old);return old;}});
  const app=new AuthFlowStudio();Object.defineProperty(app,'isConnected',{get:()=>document.body.contains(app)});document.body.appendChild(app);
  app.addEventListener('focusin',event=>{document.activeElement=event.target;});await app.connectedCallback();
  await app.changeLocale(locale,{explicit:false});
  assert.equal(app.localizer.locale,locale);assert.ok(app.localizer.catalog,'Real compiled locale catalog loaded');
  return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();if(originalReplaceChild)Object.defineProperty(HarnessElement.prototype,'replaceChild',originalReplaceChild);else delete HarnessElement.prototype.replaceChild;}
function input(node,value){node.value=value;node.dispatchEvent(new HarnessEvent('input',{bubbles:true}));}
const fields=app=>Array.from(app.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]'),node=>({id:node.dataset.indexAttribute,name:app.definition(node.dataset.indexAttribute).name}));
function fieldQuery(app,query){input(app.refs['attribute-search'],query);const rows=fields(app);if(app.presentationMode==='compact')assert.ok(rows.length<=app.compactView.fieldBrowser.limit,'Compact search preserves its actual batch limit');return rows;}
function pickerQuery(app,query){input(app.scenarioPicker.input,query);return Array.from(app.scenarioPicker.results);}
function contains(rows,id,query){assert.ok(rows.some(row=>row.id===id),query+' discovers '+id);}

for(const locale of Object.keys(nativeQueries)){
  test(locale+' actual complete Full field input orders punctuation-exact names and retains Compact batches',async()=>{
    const app=await mount(locale);try{
      app.switchPresentation('full');app.openFieldIndex();fieldQuery(app,'Conditions/@NotBefore');
      // A global nonempty query visits the actual complete field corpus. Derive
      // duplicate-name identities from those canonical definitions, never ranks.
      const corpus=Array.from(app.definitionMemo.values,([id,definition])=>({id,name:definition.name}));
      assert.ok(corpus.length>10000,'The full app field corpus, not a micro-fixture');
      for(const query of ['Conditions/@NotBefore','Conditions@NotBefore','id_token','id token','user.name']){
        const expected=corpus.filter(row=>row.name.toLowerCase()===query.toLowerCase()).map(row=>row.id).sort();
        assert.ok(expected.length>0,'Actual canonical exact names exist: '+query);
        const rows=fieldQuery(app,query);
        assert.deepEqual(rows.slice(0,expected.length).map(row=>row.id).sort(),expected,'Every duplicate exact '+query+' precedes punctuation/prose matches');
        assert.ok(rows.slice(0,expected.length).every(row=>row.name.toLowerCase()===query.toLowerCase()));
      }
      assert.ok(corpus.filter(row=>row.name.toLowerCase()==='id_token').length>1,'Duplicate exact-name coverage is real');
      for(const query of ['Conditions-NotBefore','user-name','user/name'])assert.ok(fieldQuery(app,query).length>0,'Forgiving nonexact discovery remains: '+query);
      assert.ok(fieldQuery(app,'SPAKE2').some(row=>/^SPAKE2\s/u.test(row.name)),'Actual balanced PAKE fields remain discoverable');
      assert.ok(fieldQuery(app,'SPAKE2+').some(row=>/^SPAKE2\+/u.test(row.name)),'Actual augmented PAKE fields remain discoverable');
      for(const [query,expected] of [['client_id','clientIdApp'],['client_id client','clientIdApp'],['code_verifier','codeVerifier']])contains(fieldQuery(app,query),expected,query);
      const before=app.player.queue,selection=app.labScenarioId;
      fieldQuery(app,'id_token');assert.equal(app.player.queue,before);assert.equal(app.labScenarioId,selection);
      app.switchPresentation('compact');app.openFieldIndex();
      input(app.refs['attribute-search'],'');app.querySelector('[data-compact-field-scope="global"]').click();
      const first=fields(app);assert.equal(first.length,40);app.refs['compact-field-more'].click();
      assert.equal(fields(app).length,80);assert.deepEqual(fields(app).slice(0,40),first);
    }finally{unmount(app);}
  });

  test(locale+' actual picker input discovers bounded filtering/LSA aliases and preserves explicit denial identities',async()=>{
    const app=await mount(locale);try{
      const selected=app.labScenarioId,variant=app.lessonVariant,queue=app.player.queue,originalSnapshot=app.scenarioSnapshot,originalSelect=app.selectLabScenario;
      // Search may inspect immutable metadata only. Even reaching a cached
      // model snapshot or a selection callback while typing is a regression.
      app.scenarioSnapshot=()=>{throw new Error('No model snapshot during picker input');};
      app.selectLabScenario=()=>{throw new Error('No scenario selection during picker input');};
      try{
        const queries=nativeQueries[locale];
        for(const query of queries.filtering){
          const rows=pickerQuery(app,query);
          for(const id of ['lab-welev01','lab-wra01','lab-wra02'])contains(rows,id,query);
          for(const row of rows.filter(row=>['lab-welev01','lab-wra01','lab-wra02'].includes(row.id)))assert.equal(row.variantId,undefined,'Concept alias does not silently choose a success or denial case');
        }
        for(const query of queries.protection)contains(pickerQuery(app,query),'lab-wprot02',query);
        for(const query of queries.isolated)contains(pickerQuery(app,query),'lab-wprot01',query);
        for(const query of ['lsa','LSA','lsass'])for(const id of ['lab-wprot01','lab-wprot02'])contains(pickerQuery(app,query),id,query);
        contains(pickerQuery(app,'SID filtering'),'lab-ad-forest-sid-filtering','SID filtering');
        contains(pickerQuery(app,'token filtering'),'lab-wra01','token filtering');
        const picker=app.scenarioPicker;
        picker.input.dispatchEvent(new HarnessEvent('compositionstart',{bubbles:true}));
        const composingRows=picker.results;
        input(picker.input,queries.filtering[0]);
        assert.equal(picker.results,composingRows,'IME draft does not prematurely replace results');
        picker.input.dispatchEvent(new HarnessEvent('keydown',{key:'Enter',isComposing:true}));
        picker.input.dispatchEvent(new HarnessEvent('compositionend',{bubbles:true}));
        contains(Array.from(picker.results),'lab-wra01','Committed native IME query');
        picker.input.dispatchEvent(new HarnessEvent('keydown',{key:'Escape'}));
        assert.equal(picker.opened,false,'Escape cancels discovery without selecting a case');
        for(const fixture of operators){
          const rows=pickerQuery(app,fixture.query);
          for(const expected of fixture.required){
            contains(rows,expected.id,fixture.query);const row=rows.find(row=>row.id===expected.id);
            if(expected.variantId)assert.equal(row.variantId,expected.variantId,fixture.query);
            for(const id of expected.matchingVariantIds||[])assert.ok(row.matchingVariantIds?.includes(id),fixture.query+' retains explicit case '+id);
          }
          if(fixture.first)assert.equal(rows[0]?.id,fixture.first,fixture.query);
        }
        assert.ok(pickerQuery(app,'Kerberos').length>0,'Original English protocol remains discoverable');
        assert.equal(pickerQuery(app,'неіснуючийאבגغثقف').length,0,'Unknown native query does not fall back to the whole catalog');
        for(const id of ['lab-wra01','lab-wprot02']){
          const option=app.scenarioPicker.options.find(row=>row.id===id);
          contains(pickerQuery(app,option.title),id,option.title);contains(pickerQuery(app,id),id,id);
        }
        assert.equal(app.labScenarioId,selected);assert.equal(app.lessonVariant,variant);assert.equal(app.player.queue,queue);
        for(const [id,denial] of [['lab-wra01','default-filtered'],['lab-welev01','filtered-admin-access'],['lab-wprot02','protected-access-blocked']]){
          const query=id+' '+denial,rows=pickerQuery(app,query),row=rows.find(row=>row.id===id);
          assert.ok(row,query);assert.equal(row.variantId,denial,'A denial-only query retains its explicit variant payload');
        }
      }finally{app.scenarioSnapshot=originalSnapshot;app.selectLabScenario=originalSelect;}
      pickerQuery(app,'lab-wra01 default-filtered');
      assert.equal(app.labScenarioId,selected,'Typing the denial still does not activate it');
      app.scenarioPicker.list.querySelector('[data-scenario-option="lab-wra01"]').click();
      assert.equal(app.labScenarioId,'lab-wra01');assert.equal(app.lessonVariant,'default-filtered','Explicit public row selection opens denial, not success');
    }finally{unmount(app);}
  });
}
