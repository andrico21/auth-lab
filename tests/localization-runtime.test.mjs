import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {installHarness} from './dom-harness.mjs';
import {Localizer,LOCALES,LOCALE_PREFERENCE_KEY} from '../src/localization.js';
import {localizedSearchIndex,prepareSearchQuery,rankSearchFields} from '../src/locale-search.js';
import {ProtectedRegistry} from '../tools/verification/localization/protected.mjs';
import {compileResources} from '../tools/verification/localization/resources.mjs';

// Authored native micro-fixtures exercise runtime boundaries, not production
// corpus coverage, linguistic approval, browser layout or model evaluation.
const {document}=installHarness();
const escape=value=>String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const stable=value=>JSON.stringify(sort(value));
function sort(value){
  if(Array.isArray(value))return value.map(sort);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])]));
  return value;
}
const sha=value=>createHash('sha256').update(value).digest('hex');
function contract(key,english,parameters={},extra={}){
  const typed=Object.fromEntries(Object.entries(parameters).map(([name,definition])=>[name,Object.fromEntries(Object.entries(definition).filter(([field])=>field!=='sourcePath'))]));
  return {key,english,parameters,sourceSha256:sha(stable({english,parameters:typed})),owner:{semanticId:'fixture:'+key,fieldPath:'message'},context:{},classification:Object.keys(parameters).length?'mixed':'human',...(typeof english==='string'?{exactEnglishSourceSha256:sha(english)}:{}),...extra};
}
const entry=(binding,message)=>({sourceSha256:binding.sourceSha256,message});
function fixture(messages,translations,locale='fr',extra={}){
  return new Localizer({host:{},initialLocale:locale,bindings:{messages},catalogs:{[locale]:{locale,entries:Object.fromEntries(messages.filter(message=>Object.hasOwn(translations,message.key)).map(message=>[message.key,entry(message,translations[message.key])]))}},...extra});
}
function fragment(html){const root=document.createElement('div');root.innerHTML=html;return root;}

const raw='SPAKE2+ / CN="A&B" <tag> \\path\n\tend';
const protectedMessage=contract('protected','Inspect {value}.',{value:{kind:'protected',value:raw}});

test('protected bytes survive text, escaped HTML and renderer-owned raw code attributes',()=>{
  const localizer=fixture([protectedMessage],{protected:'Vérifier {value}.'});
  const source='Inspect '+raw+'.';
  assert.equal(localizer.text('protected',source),'Vérifier '+raw+'.');
  const html=localizer.html('protected',source);
  assert.equal(html,'Vérifier <bdi dir="ltr" translate="no">'+escape(raw)+'</bdi>.');
  const root=fragment(html),isolate=root.querySelector('bdi');
  assert.equal(root.textContent,'Vérifier '+raw+'.');
  assert.equal(isolate.textContent,raw);assert.equal(isolate.getAttribute('translate'),'no');assert.equal(isolate.getAttribute('dir'),'ltr');
  const rich=fragment(localizer.rich('protected','Inspect {value}.',{value:{kind:'protected',value:raw,node:{tag:'code'}}}));
  const code=rich.querySelector('code');
  assert.equal(rich.textContent,'Vérifier '+raw+'.');assert.equal(code.textContent,raw);
  assert.equal(JSON.parse(code.getAttribute('data-copy-raw-json')),raw);
  assert.equal(code.getAttribute('translate'),'no');assert.equal(code.getAttribute('dir'),'ltr');
  assert.equal(localizer.language('protected'),'fr');
});

test('rich English fallback retains raw bytes, renderer structure and language metadata',()=>{
  const localizer=fixture([protectedMessage],{});
  const html=localizer.rich('protected','Inspect {value}.',{value:{kind:'protected',value:raw,node:{tag:'code'}}});
  const root=fragment(html),wrapper=root.querySelector('span'),code=root.querySelector('code');
  assert.equal(root.textContent,'Inspect '+raw+'.');assert.equal(wrapper.getAttribute('lang'),'en');assert.equal(wrapper.getAttribute('dir'),'ltr');
  assert.equal(JSON.parse(code.getAttribute('data-copy-raw-json')),raw);assert.equal(localizer.language('protected'),'en');
});

for(const [name,change] of [
  ['markup',()=>({message:'Vérifier <strong>{value}</strong>.'})],
  ['URL',()=>({message:'Vérifier https://example.invalid/{value}.'})],
  ['bidi',()=>({message:'Vérifier \u202e{value}.'})],
  ['missing',()=>null],
  ['stale hash',()=>({sourceSha256:'0'.repeat(64),message:'Vérifier {value}.'})],
  ['missing parameter',()=>({message:'Vérifier.'})],
  ['duplicated parameter',()=>({message:'Vérifier {value} et {value}.'})],
  ['unknown parameter',()=>({message:'Vérifier {other}.'})],
])test(name+' translation falls back to the complete exact English message',()=>{
  const localizer=fixture([protectedMessage],{protected:'Vérifier {value}.'});
  const changed=change();if(changed)localizer.catalog.entries.protected={...entry(protectedMessage,'Vérifier {value}.'),...changed};else delete localizer.catalog.entries.protected;
  const source='Inspect '+raw+'.';
  assert.equal(localizer.text('protected',source),source);assert.equal(localizer.language('protected'),'en');
  assert.equal(localizer.html('protected',source),'<span lang="en" dir="ltr">'+escape(source)+'</span>');
  assert.equal(fragment(localizer.html('protected',source)).textContent,source);
});

test('missing, ambiguous and source/parameter mismatches never partially translate',()=>{
  const ambiguous={...protectedMessage,classification:'ambiguous'};
  const localizer=fixture([ambiguous],{protected:'Vérifier {value}.'});
  for(const [key,source,params] of [
    ['protected','Inspect '+raw+'.',{}],['unknown','  Exact <English> & bytes\n',{}],
  ]){
    assert.equal(localizer.text(key,source,params),source);assert.equal(localizer.language(key),'en');
    assert.equal(localizer.html(key,source,params),'<span lang="en" dir="ltr">'+escape(source)+'</span>');
  }
  const valid=fixture([protectedMessage],{protected:'Vérifier {value}.'});
  for(const [source,params] of [['Inspect changed.',{}],['Inspect '+raw+'.',{value:'changed'}],['Inspect '+raw+'.',{extra:'x'}]]){
    assert.equal(valid.text('protected',source,params),source);assert.equal(valid.language('protected'),'en');
  }
});

test('an invalid unselected plural branch invalidates the whole translated message',()=>{
  const binding=contract('count',{plural:{one:'{count} result',other:'{count} results'}},{count:{kind:'count'}});
  const localizer=fixture([binding],{count:{plural:{one:'{count} résultat',other:'<b>{count}</b> résultats'}}});
  assert.equal(localizer.plural('count',1,'1 result'),'1 result');assert.equal(localizer.language('count'),'en');
  assert.equal(localizer.html('count','1 result',{count:1}),'<span lang="en" dir="ltr">1 result</span>');
});

test('structured human references translate prose but preserve protected formal names',()=>{
  const child=contract('role','Inspect {formal}',{formal:{kind:'protected',value:'PKINIT / SPAKE2+'}},{owner:{semanticId:'actor:client',fieldPath:'plainRole'}});
  const parent=contract('parent','Selected: {role}.',{role:{kind:'human',dynamic:true}});
  const localizer=fixture([child,parent],{role:'Vérifier {formal}',parent:'Sélection : {role}.'});
  const role={key:'role',source:'Inspect PKINIT / SPAKE2+'};
  assert.equal(localizer.text('parent','Selected: '+role.source+'.',{role}),'Sélection : Vérifier PKINIT / SPAKE2+.');
  assert.equal(fragment(localizer.html('parent','Selected: '+role.source+'.',{role})).textContent,'Sélection : Vérifier PKINIT / SPAKE2+.');
  const ownerRef={ownerId:'actor:client',fieldPath:'plainRole',source:role.source};
  assert.equal(localizer.text('parent','Selected: '+role.source+'.',{role:ownerRef}),'Sélection : Vérifier PKINIT / SPAKE2+.');
  assert.equal(localizer.text('parent','Selected: '+role.source+'.',{role:role.source}),'Selected: '+role.source+'.');
  assert.equal(localizer.language('parent'),'en');
});

test('a failed nested human reference falls back atomically instead of mixing languages',()=>{
  const child=contract('role','Inspect {formal}',{formal:{kind:'protected',value:'PKINIT'}});
  const parent=contract('parent','Selected: {role}.',{role:{kind:'human',dynamic:true}});
  const localizer=fixture([child,parent],{parent:'Sélection : {role}.'});
  const role={key:'role',source:'Inspect PKINIT'},source='Selected: Inspect PKINIT.';
  assert.equal(localizer.text('parent',source,{role}),source);
  assert.equal(localizer.language('parent'),'en');
  assert.equal(localizer.html('parent',source,{role}),'<span lang="en" dir="ltr">'+source+'</span>');
});

function storageHost(stored,{denied=false}={}){
  const writes=[];
  return {writes,host:{navigator:{language:'he',languages:['he','ar-AE']},localStorage:{getItem(key){assert.equal(key,LOCALE_PREFERENCE_KEY);if(denied)throw new Error('Storage denied');return stored;},setItem(key,value){if(denied)throw new Error('Storage denied');writes.push([key,value]);}}}};
}
test('only allowlisted explicit/stored choices select locales and initialization never persists',()=>{
  for(const stored of [null,'fr-FR','FR','__proto__','he-u-nu-latn','']){
    const {host,writes}=storageHost(stored),localizer=new Localizer({host});
    assert.equal(localizer.locale,'en');assert.equal(localizer.source,'default');assert.deepEqual(writes,[]);
  }
  for(const {tag} of LOCALES){
    const {host,writes}=storageHost(tag),localizer=new Localizer({host});
    assert.equal(localizer.locale,tag);assert.equal(localizer.source,'stored');assert.deepEqual(writes,[]);
  }
  const {host,writes}=storageHost('he'),localizer=new Localizer({host,initialLocale:'fr'});
  assert.equal(localizer.locale,'fr');assert.deepEqual(writes,[]);
  assert.equal(localizer.activate('de'),true);assert.deepEqual(writes,[[LOCALE_PREFERENCE_KEY,'de']]);assert.equal(localizer.source,'explicit-stored');
  const revision=localizer.revision;
  assert.equal(localizer.activate('de'),false);assert.equal(localizer.revision,revision);assert.equal(writes.length,1);
  assert.throws(()=>localizer.activate('de-DE'),RangeError);assert.equal(localizer.locale,'de');assert.equal(writes.length,1);
  localizer.activate('he',{persist:false});assert.equal(writes.length,1);
});

test('denied storage permits memory-only explicit choices without implicit language detection',()=>{
  const {host}=storageHost('he',{denied:true}),localizer=new Localizer({host});
  assert.equal(localizer.locale,'en');assert.equal(localizer.activate('he'),true);
  assert.equal(localizer.locale,'he');assert.equal(localizer.direction,'rtl');assert.equal(localizer.source,'explicit-memory');
  const root=document.createElement('section');root.ownerDocument=document;
  document.documentElement.setAttribute('lang','fr');document.documentElement.setAttribute('dir','ltr');
  localizer.metadata(root);assert.equal(document.documentElement.getAttribute('lang'),'fr');assert.equal(document.documentElement.getAttribute('dir'),'ltr');
  localizer.metadata(root,{documentOwner:true});
  assert.equal(root.getAttribute('lang'),'he');assert.equal(root.getAttribute('dir'),'rtl');
  assert.equal(document.documentElement.getAttribute('lang'),'he');assert.equal(document.documentElement.getAttribute('dir'),'rtl');
  localizer.activate('en',{persist:false});localizer.metadata(root,{documentOwner:true});
  assert.equal(root.getAttribute('lang'),'en');assert.equal(document.documentElement.getAttribute('dir'),'ltr');
});

const cardinalCases={
  en:[[0,'other'],[1,'one'],[2,'other'],[0.5,'other']],
  ru:[[1,'one'],[2,'few'],[5,'many'],[11,'many'],[21,'one'],[22,'few'],[1.5,'other']],
  uk:[[1,'one'],[2,'few'],[5,'many'],[11,'many'],[21,'one'],[22,'few'],[1.5,'other']],
  he:[[0,'other'],[0.1,'one'],[0.5,'one'],[1,'one'],[2,'two'],[10,'other'],[1.5,'other']],
  de:[[0,'other'],[1,'one'],[2,'other'],[1.5,'other']],
  'ar-AE':[[0,'zero'],[1,'one'],[2,'two'],[3,'few'],[10,'few'],[11,'many'],[99,'many'],[100,'other'],[0.5,'other']],
  fr:[[0,'one'],[0.5,'one'],[1,'one'],[1.5,'one'],[2,'other'],[1000000,'many'],[2000000,'many']],
  pl:[[0,'many'],[1,'one'],[2,'few'],[5,'many'],[12,'many'],[21,'many'],[22,'few'],[1.5,'other']],
};
for(const [locale,cases] of Object.entries(cardinalCases))test(locale+' cardinal categories match ordinary-decimal CLDR boundaries',()=>{
  const localizer=new Localizer({host:{},initialLocale:locale});
  for(const [count,expected] of cases){assert.equal(localizer.cardinal(count),expected,String(count));assert.equal(localizer.fallbackCardinal(count),expected,String(count));}
  for(const invalid of [-1,NaN,Infinity,'1',null])assert.throws(()=>localizer.cardinal(invalid),TypeError);
});

test('plural messages select native branches rather than English singular/plural rules',()=>{
  const binding=contract('results',{plural:{one:'{count} result',other:'{count} results'}},{count:{kind:'count'}});
  const forms={
    ru:{one:'{count} результат',few:'{count} результата',many:'{count} результатов',other:'{count} результата'},
    uk:{one:'{count} результат',few:'{count} результати',many:'{count} результатів',other:'{count} результату'},
    he:{one:'{count} תוצאה',two:'{count} תוצאות',other:'{count} תוצאות'},
    de:{one:'{count} Ergebnis',other:'{count} Ergebnisse'},
    'ar-AE':{zero:'{count} نتيجة',one:'{count} نتيجة',two:'{count} نتيجتان',few:'{count} نتائج',many:'{count} نتيجة',other:'{count} نتيجة'},
    fr:{one:'{count} résultat',many:'{count} résultats',other:'{count} résultats'},
    pl:{one:'{count} wynik',few:'{count} wyniki',many:'{count} wyników',other:'{count} wyniku'},
  };
  for(const [locale,native] of Object.entries(forms)){
    const localizer=fixture([binding],{results:{plural:native}},locale);
    for(const [count,category] of cardinalCases[locale]){
      const source=count+(count===1?' result':' results');
      const decimal=['ru','uk','de','fr','pl'].includes(locale)?String(count).replace('.',','):String(count);
      assert.equal(localizer.plural('results',count,source),native[category].replace('{count}',decimal),locale+' '+count);
      assert.equal(localizer.language('results'),locale);
    }
  }
});

for(const mode of ['missing','wrong locale','wrong rules'])test(mode+' Intl data uses deterministic cardinal and number fallback',()=>{
  const pluralDescriptor=Object.getOwnPropertyDescriptor(Intl,'PluralRules'),numberDescriptor=Object.getOwnPropertyDescriptor(Intl,'NumberFormat');
  try{
    const broken=kind=>class {
      static supportedLocalesOf(){return ['fr'];}
      resolvedOptions(){return {locale:mode==='wrong locale'?'en':'fr'};}
      select(){return 'other';}
      format(){return 'WRONG';}
    };
    Object.defineProperty(Intl,'PluralRules',{configurable:true,writable:true,value:mode==='missing'?undefined:broken('plural')});
    Object.defineProperty(Intl,'NumberFormat',{configurable:true,writable:true,value:mode==='missing'?undefined:mode==='wrong rules'?class {static supportedLocalesOf(){return [];} }:broken('number')});
    const localizer=new Localizer({host:{},initialLocale:'fr'});
    assert.equal(localizer.cardinal(0),'one');assert.equal(localizer.cardinal(1000000),'many');assert.equal(localizer.cardinal(2),'other');
    assert.equal(localizer.formatCount(1234.5),'1234,5');
    assert.equal(localizer.diagnostics().pluralDataSource,'CLDR 49 ordinary-decimal fallback');
    assert.equal(localizer.diagnostics().numberDataSource,'CLDR 49 Latin-digit decimal-separator fallback');
  }finally{Object.defineProperty(Intl,'PluralRules',pluralDescriptor);Object.defineProperty(Intl,'NumberFormat',numberDescriptor);}
});

test('only the active lazy catalog is loaded, with no-op preserving live caches and revision',()=>{
  const binding=contract('title','Signature check',{}, {owner:{semanticId:'lesson:demo',fieldPath:'title'}}),loaded=[];
  const catalogs=Object.fromEntries([['fr','Vérification de signature'],['de','Signaturprüfung']].map(([locale,message])=>[locale,()=>{loaded.push(locale);return {locale,entries:{title:entry(binding,message)}};}]));
  const localizer=new Localizer({host:{},catalogs,bindings:{messages:[binding]}});
  assert.deepEqual(loaded,[]);assert.equal(localizer.diagnostics().activeCatalog,null);
  localizer.activate('fr',{persist:false});const record={id:'demo',title:'Signature check'};
  const first=localizer.searchEntry('scenario','demo',record),revision=localizer.revision;
  assert.equal(first.title,'Vérification de signature');assert.deepEqual(loaded,['fr']);
  assert.equal(localizer.activate('fr'),false);assert.equal(localizer.revision,revision);assert.equal(localizer.searchEntry('scenario','demo',record),first);
  localizer.activate('de',{persist:false});assert.equal(localizer.diagnostics().activeSearchEntries,0);
  assert.equal(localizer.searchEntry('scenario','demo',record).title,'Signaturprüfung');assert.deepEqual(loaded,['fr','de']);
  assert.equal(localizer.diagnostics().inactiveParsedCatalogs,0);assert.equal(localizer.diagnostics().activeCatalog,'de');
  localizer.activate('en',{persist:false});assert.equal(localizer.catalog,null);assert.equal(localizer.searchEntry('scenario','demo',record),null);assert.equal(localizer.diagnostics().activeSearchEntries,0);
});

test('dynamic matchers are bounded and eviction never reuses stale captured bytes',()=>{
  const binding=contract('dynamic','Inspect {name}: {value}.',{name:{kind:'source',dynamic:true},value:{kind:'exact',dynamic:true}});
  const localizer=fixture([binding],{dynamic:'Vérifier {name} : {value}.'});
  for(let index=0;index<520;index++)assert.equal(localizer.text('dynamic','Inspect item'+index+': raw'+index+'.',{name:'item'+index}),'Vérifier item'+index+' : raw'+index+'.');
  assert.equal(localizer.diagnostics().activeSourceMatchers,512);
  assert.equal(localizer.text('dynamic','Inspect item0: new <&> bytes.',{name:'item0'}),'Vérifier item0 : new <&> bytes.');
  assert.equal(localizer.diagnostics().activeSourceMatchers,512);
  assert.equal(localizer.text('dynamic','Inspect item0: conflicting.',{name:'item0',value:'different'}),'Inspect item0: conflicting.');
  localizer.activate('en',{persist:false});assert.equal(localizer.diagnostics().activeSourceMatchers,0);
});

test('adjacent dynamic captures fail closed rather than guessing protected boundaries',()=>{
  const binding=contract('adjacent','Inspect {first}{second}.',{first:{kind:'protected',dynamic:true},second:{kind:'exact',dynamic:true}});
  const localizer=fixture([binding],{adjacent:'Vérifier {first}{second}.'});
  assert.equal(localizer.text('adjacent','Inspect ab.'),'Inspect ab.');assert.equal(localizer.language('adjacent'),'en');
  assert.equal(localizer.text('adjacent','Inspect ab.',{first:'a',second:'b'}),'Vérifier ab.');
});

test('mutable search captions invalidate translations and cannot leave stale native hits',()=>{
  const binding=contract('title','Signature check',{}, {owner:{semanticId:'lesson:demo',fieldPath:'title'}});
  const localizer=fixture([binding],{title:'Vérification de signature'}),record={id:'demo',title:'Signature check'};
  const first=localizedSearchIndex(localizer,'scenario','demo',record);
  assert.equal(rankSearchFields(first.base,prepareSearchQuery('vérification')),1);
  record.title='New canonical caption';
  const changed=localizedSearchIndex(localizer,'scenario','demo',record);
  assert.notEqual(changed,first);assert.equal(changed.entry.title,'New canonical caption');
  assert.equal(rankSearchFields(changed.base,prepareSearchQuery('vérification')),null);
  assert.equal(rankSearchFields(changed.base,prepareSearchQuery('New canonical caption')),0);
  assert.equal(localizer.diagnostics().activeSearchEntries,1);
});

test('replacing mutable variant tags/context never returns an obsolete cached search hit',()=>{
  const binding=contract('case','Offline denial',{}, {owner:{semanticId:'lesson:demo',fieldPath:'searchVariants.label'},context:{variantId:'denied'}});
  const localizer=fixture([binding],{case:'Refus hors ligne'}),record={id:'demo',searchVariants:[{id:'denied',label:'Offline denial',searchTags:['ancien'],searchContext:['contexteancien']}]};
  const first=localizedSearchIndex(localizer,'scenario','demo',record);
  assert.equal(rankSearchFields(first.variants[0].fields,prepareSearchQuery('ancien')),0);
  record.searchVariants[0].searchTags=['nouveau'];record.searchVariants[0].searchContext=['contextenouveau'];
  const changed=localizedSearchIndex(localizer,'scenario','demo',record);
  assert.equal(rankSearchFields(changed.variants[0].fields,prepareSearchQuery('ancien')),null);
  assert.equal(rankSearchFields(changed.variants[0].fields,prepareSearchQuery('nouveau')),0);
  assert.equal(rankSearchFields(changed.variants[0].fields,prepareSearchQuery('contexteancien')),null);
  assert.equal(rankSearchFields(changed.variants[0].fields,prepareSearchQuery('contextenouveau')),3);
  assert.equal(changed.entry.searchVariants[0].label,'Refus hors ligne');
  assert.equal(record.searchVariants[0].label,'Offline denial');
});

function compactFixture(){
  const binding=contract('unused-schema-key','Inspect signature');
  const source={
    schemaVersion:2,format:'auth-lab-l10n-source-table',
    schemas:[[binding.sourceSha256,binding.english,binding.parameters,{}]],
    owners:['lesson:alpha','lesson:beta'],fields:['searchVariants.label'],
    contexts:[{variantId:'denied'},{variantId:'success'}],classifications:['human'],
    bindings:[[0,0,0,0,0],[0,0,0,1,0],[0,1,0,0,0]],
    keys:{'alpha.denied':0,'alpha.success':1,'beta.denied':2},
  };
  source.sourceSetSha256=sha(stable(source));
  const catalog=(locale,messages,bindings=[0,1,2])=>({schemaVersion:2,format:'auth-lab-l10n-catalog-table',locale,sourceSetSha256:source.sourceSetSha256,messages,bindings});
  return {source,catalog,fr:catalog('fr',['Vérifier la signature','Examiner la signature','Contrôler la signature'])};
}

test('shared compact schemas retain distinct semantic owners and context-filtered translations',()=>{
  const {source,fr}=compactFixture(),localizer=new Localizer({host:{},initialLocale:'fr',bindings:source,catalogs:{fr}});
  assert.equal(localizer.explain('lesson:alpha','searchVariants.label','Inspect signature',{variantId:'denied'}),'Vérifier la signature');
  assert.equal(localizer.explain('lesson:alpha','searchVariants.label','Inspect signature',{variantId:'success'}),'Examiner la signature');
  assert.equal(localizer.explain('lesson:beta','searchVariants.label','Inspect signature',{variantId:'denied'}),'Contrôler la signature');
  assert.equal(localizer.explain('lesson:beta','searchVariants.label','Inspect signature',{variantId:'success'}),'Inspect signature');
  assert.equal(localizer.explain('lesson:alpha','searchVariants.label','Inspect signature'),'Inspect signature');
  assert.equal(localizer.text('alpha.success','Inspect signature'),'Examiner la signature');
  assert.equal(localizer.text('beta.denied','Inspect signature'),'Contrôler la signature');
});

for(const [name,mutate] of [
  ['source-set digest',table=>{table.sourceSetSha256='0'.repeat(64);}],
  ['short binding vector',table=>{table.bindings.pop();}],
  ['long binding vector',table=>{table.bindings.push(0);}],
  ['out-of-range pool index',table=>{table.bindings[1]=table.messages.length;}],
  ['negative pool index other than omission',table=>{table.bindings[1]=-2;}],
  ['fractional pool index',table=>{table.bindings[1]=0.5;}],
])test('invalid compact '+name+' rejects the catalog with exact English fallback',()=>{
  const {source,fr}=compactFixture();mutate(fr);
  const localizer=new Localizer({host:{},initialLocale:'fr',bindings:source,catalogs:{fr}});
  assert.equal(localizer.locale,'en');
  assert.equal(localizer.initialFailure?.tag,'fr');
  for(const key of ['alpha.denied','alpha.success','beta.denied']){
    assert.equal(localizer.text(key,'Inspect signature'),'Inspect signature');
    assert.equal(localizer.language(key),'en');
  }
});

test('compact omission is an English fallback, not the final native pool message or catalog rejection',()=>{
  const {source,fr}=compactFixture();fr.bindings[1]=-1;
  const localizer=new Localizer({host:{},initialLocale:'fr',bindings:source,catalogs:{fr}});
  assert.equal(localizer.text('alpha.denied','Inspect signature'),'Vérifier la signature');
  assert.equal(localizer.text('alpha.success','Inspect signature'),'Inspect signature');
  assert.equal(localizer.language('alpha.success'),'en');
  assert.equal(localizer.html('alpha.success','Inspect signature'),'<span lang="en" dir="ltr">Inspect signature</span>');
  assert.equal(localizer.text('beta.denied','Inspect signature'),'Contrôler la signature');
  assert.equal(localizer.language('beta.denied'),'fr');
});

test('compact activation loads only the selected native table and releases the previous cache identity',()=>{
  const {source,fr,catalog}=compactFixture(),loads=[];
  const de=catalog('de',['Signatur prüfen','Signatur untersuchen','Signatur kontrollieren']);
  const localizer=new Localizer({host:{},bindings:()=>source,catalogs:{fr:()=>{loads.push('fr');return fr;},de:()=>{loads.push('de');return de;}}});
  const record={id:'alpha',searchVariants:[{id:'denied',label:'Inspect signature'}]};
  assert.deepEqual(loads,[]);
  localizer.activate('fr',{persist:false});
  const french=localizedSearchIndex(localizer,'scenario','alpha',record),frenchCache=localizer.searchCache;
  assert.equal(french.entry.searchVariants[0].label,'Vérifier la signature');
  assert.deepEqual(loads,['fr']);
  assert.equal(localizer.activate('fr',{persist:false}),false);
  assert.equal(localizer.searchCache,frenchCache);
  assert.equal(localizedSearchIndex(localizer,'scenario','alpha',record),french);
  localizer.activate('de',{persist:false});
  assert.notEqual(localizer.searchCache,frenchCache);
  assert.equal(localizer.diagnostics().activeSearchEntries,0);
  assert.deepEqual(loads,['fr','de']);
  const german=localizedSearchIndex(localizer,'scenario','alpha',record);
  assert.equal(german.entry.searchVariants[0].label,'Signatur prüfen');
  assert.equal(rankSearchFields(german.variants[0].fields,prepareSearchQuery('Vérifier')),null);
  assert.equal(rankSearchFields(german.variants[0].fields,prepareSearchQuery('Signatur prüfen')),0);
  assert.equal(localizer.diagnostics().inactiveParsedCatalogs,0);
  const germanCache=localizer.searchCache;
  localizer.activate('en',{persist:false});
  assert.notEqual(localizer.searchCache,germanCache);
  assert.equal(localizer.diagnostics().activeSearchEntries,0);
  assert.equal(localizer.catalog,null);
});

test('missing native cardinal branches invalidate the whole message instead of borrowing other',()=>{
  const binding=contract('results',{plural:{one:'{count} result',other:'{count} results'}},{count:{kind:'count'}});
  const complete={one:'{count} wynik',few:'{count} wyniki',many:'{count} wyników',other:'{count} wyniku'};
  for(const omitted of Object.keys(complete)){
    const forms={...complete};delete forms[omitted];
    const localizer=fixture([binding],{results:{plural:forms}},'pl');
    // Exercise one even when the invalid branch would not be selected.
    assert.equal(localizer.plural('results',1,'1 result'),'1 result',omitted);
    assert.equal(localizer.language('results'),'en');
    assert.equal(localizer.plural('results',21,'21 results'),'21 results',omitted);
  }
});

test('native string/plural shape mismatch never silently ignores the English contract',()=>{
  const plural=contract('results',{plural:{one:'{count} result',other:'{count} results'}},{count:{kind:'count'}});
  const plain=contract('plain','Inspect signature');
  const localizer=fixture([plural,plain],{results:'{count} résultats',plain:{plural:{one:'Vérifier la signature',many:'Examiner la signature',other:'Contrôler la signature'}}});
  assert.equal(localizer.plural('results',2,'2 results'),'2 results');
  assert.equal(localizer.language('results'),'en');
  assert.equal(localizer.text('plain','Inspect signature'),'Inspect signature');
  assert.equal(localizer.language('plain'),'en');
});

test('explanations prefer the exact scoped owner and never borrow an unscoped translation',()=>{
  const owner={semanticId:'field:public-id',fieldPath:'meaning'},english='A public identifier.';
  const base=contract('base',english,{}, {owner});
  const scoped=contract('scoped',english,{}, {owner,context:{scenarioId:'case-a',subfixtureId:null}});
  const localizer=fixture([base,scoped],{base:'Un identifiant public.',scoped:'Un identifiant public dans ce cas.'});
  assert.equal(localizer.explain('field:public-id','meaning',english,{scenarioId:'case-a',subfixtureId:null}),'Un identifiant public dans ce cas.');
  assert.equal(localizer.explain('field:public-id','meaning',english,{scenarioId:'case-a',subfixtureId:'comparison'}),'Un identifiant public.');
  delete localizer.catalog.entries.scoped;
  assert.equal(fragment(localizer.explainHtml('field:public-id','meaning',english,{scenarioId:'case-a',subfixtureId:null})).querySelector('[lang="en"]').textContent,english);
  assert.equal(localizer.language('field:public-id.meaning'),'en');
});

test('equally specific explanation bindings fall back rather than selecting an arbitrary context',()=>{
  const owner={semanticId:'actor:client',fieldPath:'plainRole'},english='The requesting client.';
  const scenario=contract('scenario-role',english,{}, {owner,context:{scenarioId:'case-a'}});
  const variant=contract('variant-role',english,{}, {owner,context:{variantId:'confidential'}});
  for(const messages of [[scenario,variant],[variant,scenario]]){
    const localizer=fixture(messages,{'scenario-role':'Le client demandeur.','variant-role':'Le client à l’origine de la demande.'});
    const html=fragment(localizer.explainHtml('actor:client','plainRole',english,{scenarioId:'case-a',variantId:'confidential'}));
    assert.equal(html.textContent,english);assert.equal(html.querySelector('[lang="en"]').getAttribute('dir'),'ltr');
    assert.equal(localizer.language('actor:client.plainRole'),'en');
    assert.ok(localizer.diagnostics().fallbacks.some(row=>row.key==='actor:client.plainRole\0ambiguous-explanation-binding'));
  }
});

test('ambiguous implicit protected-value partitions keep the complete exact English source',()=>{
  const binding=contract('bind','Bind {first} / {second}',{first:{kind:'protected',dynamic:true,value:'A'},second:{kind:'protected',dynamic:true,value:'B'}});
  const localizer=fixture([binding],{bind:'Lier {first} à {second}'}),source='Bind one / two / three';
  assert.equal(localizer.text('bind',source),source);
  assert.equal(localizer.html('bind',source),'<span lang="en" dir="ltr">'+source+'</span>');
  assert.equal(localizer.language('bind'),'en');
  assert.equal(localizer.text('bind',source,{first:'one / two'}),'Lier one / two à three');
  assert.equal(localizer.text('bind',source,{second:'two / three'}),'Lier one à two / three');
});

test('repeated implicit protected values retain one consistent value rather than arbitrary captures',()=>{
  const binding=contract('repeat','Compare {value} / {value}',{value:{kind:'protected',dynamic:true,value:'A'}});
  const localizer=fixture([binding],{repeat:'Comparer {value} et {value}'});
  assert.equal(localizer.text('repeat','Compare one / two / one / two'),'Comparer one / two et one / two');
  assert.equal(localizer.text('repeat','Compare one / two / three'),'Compare one / two / three');
});

test('exact pinned sources outrank generic captures only within equally specific owner contexts',()=>{
  const owner={semanticId:'field:binding',fieldPath:'meaning'},parameters=value=>({value:{kind:'protected',dynamic:true,value}});
  const alpha=contract('alpha','Bind {value}',parameters('alpha'),{owner});
  const beta=contract('beta','Bind {value}',parameters('beta'),{owner});
  const localizer=fixture([alpha,beta],{alpha:'Lier {value}',beta:'Associer {value}'});
  assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Bind alpha'),'Lier alpha');
  assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Bind beta'),'Associer beta');
  assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Bind gamma'),'Bind gamma');
  assert.equal(localizer.language(owner.semanticId+'.'+owner.fieldPath),'en');
});

test('fixed source literals outrank implicit example values without hiding genuine ambiguity',()=>{
  const owner={semanticId:'lesson:certificate',fieldPath:'title'};
  const fixed=contract('fixed','Certificate alice rejected',{}, {owner});
  const dynamic=contract('dynamic','Certificate {account} rejected',{account:{kind:'protected',dynamic:true,value:'alice'}},{owner});
  for(const messages of [[fixed,dynamic],[dynamic,fixed]]){
    const localizer=fixture(messages,{fixed:'Certificat alice refusé',dynamic:'Compte {account} refusé'});
    assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Certificate alice rejected'),'Certificat alice refusé');
    assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Certificate bob rejected'),'Compte bob refusé');
    assert.equal(localizer.explain(owner.semanticId,owner.fieldPath,'Certificate alice rejected',{parameters:{account:'alice'}}),'Compte alice refusé');
    const duplicate=contract('other-meaning',fixed.english,{}, {owner});
    const ambiguous=fixture([...messages,duplicate],{fixed:'Certificat alice refusé',dynamic:'Compte {account} refusé','other-meaning':'Identité alice rejetée'});
    assert.equal(ambiguous.explain(owner.semanticId,owner.fieldPath,fixed.english),fixed.english);
    assert.equal(ambiguous.language(owner.semanticId+'.'+owner.fieldPath),'en');
  }
});

test('caption reference roles translate incidental human words but preserve formal field references',()=>{
  const cases=[
    {source:'Signed JWT verification',ownerId:'lesson:lab-jwt02',fieldPath:'title',module:'src/jwt-validation-lab.js',ref:{value:'Signed JWT',formal:true,kind:'field-name',owner:'field:jwt02_compact',sourcePath:'field:jwt02_compact.name'},translation:'Vérification du {protected1} signé',expected:'Vérification du JWT signé'},
    {source:'Issuer trust and JWT',ownerId:'lesson:lab-jwt05',fieldPath:'title',module:'src/jwt-validation-lab.js',ref:{value:'Issuer',formal:true,kind:'actor-name',owner:'actor:jwtIssuer',sourcePath:'actor:jwtIssuer.name'},translation:'Confiance en l’émetteur et {protected1}',expected:'Confiance en l’émetteur et JWT'},
    {source:'Derived SMB application key',ownerId:'artifact:application-key',fieldPath:'label',module:'src/smb-access-lab.js',ref:{value:'Derived SMB application key',formal:true,kind:'field-name',owner:'field:application-key',sourcePath:'field:application-key.name'},translation:'Clé d’application {protected1} dérivée',expected:'Clé d’application SMB dérivée'},
    {source:'Inspect Signed JWT',ownerId:'field:jwt02_compact',fieldPath:'meaning',module:'src/jwt-validation-lab.js',ref:{value:'Signed JWT',formal:true,kind:'field-name',owner:'field:jwt02_compact',sourcePath:'field:jwt02_compact.name'},translation:'Inspecter {protected1}',expected:'Inspecter Signed JWT'},
  ];
  for(const item of cases){
    const typed=new ProtectedRegistry().references(item.source,[item.ref],{ownerId:item.ownerId,fieldPath:item.fieldPath,sourceModule:item.module});
    const binding=contract('caption-role',typed.template,typed.parameters,{owner:{semanticId:item.ownerId,fieldPath:item.fieldPath},classification:typed.classification});
    const localizer=fixture([binding],{'caption-role':item.translation}),root=fragment(localizer.explainHtml(item.ownerId,item.fieldPath,item.source));
    assert.equal(root.textContent,item.expected);assert.equal(localizer.language(item.ownerId+'.'+item.fieldPath),'fr');
    assert.equal(root.querySelectorAll('bdi').length,1);assert.equal(root.querySelector('bdi').getAttribute('translate'),'no');
  }
});

test('retained caption replay restores typed identities only within the semantic source membership',async()=>{
  const {reclassifyInventory}=await import('../tools/verification/localization/inventory.mjs');
  const directory=mkdtempSync(path.join(tmpdir(),'auth-lab-caption-replay-')),input=path.join(directory,'input'),out=path.join(directory,'output');
  mkdirSync(input);
  try{
    const registry=new ProtectedRegistry(),messages=[];
    const add=(key,ownerId,fieldPath,english,references)=>{
      const protection=registry.references(english,references,{ownerId,fieldPath,sourceModule:'fixture:caption'});
      messages.push({key,owner:{semanticId:ownerId,fieldPath,module:'fixture:caption'},english,sourceSha256:sha(english),...protection,context:{},runtimeContext:{},runtime:true,sourceBinding:'exact-syntax-literal'});
    };
    add('alice-navigation','lesson:alice','summary','Alice authenticates.',[]);
    add('alice-runtime','lesson:alice','summary','Alice authenticates.',[{value:'Alice',formal:true,kind:'actor-name',owner:'actor:alice',sourcePath:'actor:alice.name'}]);
    add('other-owner','lesson:other','summary','Alice authenticates.',[]);
    add('spake-navigation','lesson:spake','title','Kerberos SPAKE: success',[]);
    add('spake-runtime','lesson:spake','title','Kerberos SPAKE: success',[{value:'Kerberos SPAKE',formal:true,kind:'protocol',owner:'lesson:spake',sourcePath:'protocol'}]);
    const rows={'messages.jsonl.gz':messages,'protected.jsonl.gz':registry.toJSON(),'ambiguities.jsonl.gz':[],'occurrences.jsonl.gz':messages.map(message=>({messageKey:message.key,ownerId:message.owner.semanticId,fieldPath:message.owner.fieldPath}))};
    for(const [name,entries]of Object.entries(rows))writeFileSync(path.join(input,name),gzipSync(entries.map(row=>JSON.stringify(row)+'\n').join('')));
    writeFileSync(path.join(input,'summary.json'),JSON.stringify({root:'fixture:caption',artifacts:Object.keys(rows).map(file=>({file})),counts:{},unresolved:{}}));
    await reclassifyInventory({input,out});
    const bindings=gunzipSync(readFileSync(path.join(out,'runtime-bindings.jsonl.gz'))).toString().trim().split('\n').map(line=>JSON.parse(line));
    const translations=Object.fromEntries(bindings.map(binding=>[binding.key,binding.owner.semanticId==='lesson:alice'?'{protected1} s’authentifie.':binding.owner.semanticId==='lesson:spake'?'{protected1} : réussite':'Une autre personne s’authentifie.']));
    const localizer=fixture(bindings,translations);
    assert.equal(bindings.length,3);
    assert.equal(localizer.explain('lesson:alice','summary','Alice authenticates.'),'Alice s’authentifie.');
    assert.equal(localizer.explain('lesson:spake','title','Kerberos SPAKE: success'),'Kerberos SPAKE : réussite');
    assert.equal(localizer.explain('lesson:other','summary','Alice authenticates.'),'Une autre personne s’authentifie.');
    const mapping=gunzipSync(readFileSync(path.join(out,'runtime-key-map.jsonl.gz'))).toString().trim().split('\n').map(line=>JSON.parse(line));
    assert.equal(mapping.find(row=>row.inventoryKey==='alice-navigation').runtimeKey,mapping.find(row=>row.inventoryKey==='alice-runtime').runtimeKey);
    assert.notEqual(mapping.find(row=>row.inventoryKey==='other-owner').runtimeKey,mapping.find(row=>row.inventoryKey==='alice-runtime').runtimeKey);
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('truthy or forged identity metadata never promotes English prose to native coverage',()=>{
  const binding=contract('identity','Inspect signature');
  for(const identityJustification of [true,'approved',{}, {approvalId:'',reason:' '},{kind:'structural-template',sourceSha256:binding.sourceSha256}]){
    const localizer=fixture([binding],{identity:binding.english});
    localizer.catalog.entries.identity.identityJustification=identityJustification;
    assert.equal(localizer.html('identity',binding.english),'<span lang="en" dir="ltr">Inspect signature</span>');
    assert.equal(localizer.language('identity'),'en');
    assert.equal(localizer.diagnostics().exercisedMessages,0);
  }
});

test('structural identity requires the exact source fingerprint and no literal human words',()=>{
  const binding=contract('structure','{first} / {second}',{first:{kind:'protected',value:'SPAKE2'},second:{kind:'protected',value:'SPAKE2+'}});
  const localizer=fixture([binding],{structure:binding.english}),source='SPAKE2 / SPAKE2+';
  localizer.catalog.entries.structure.identityJustification={kind:'structural-template',sourceSha256:'0'.repeat(64)};
  assert.equal(localizer.html('structure',source),'<span lang="en" dir="ltr">'+source+'</span>');
  localizer.catalog.entries.structure.identityJustification={kind:'structural-template',sourceSha256:binding.sourceSha256};
  assert.equal(localizer.html('structure',source),'<bdi dir="ltr" translate="no">SPAKE2</bdi> / <bdi dir="ltr" translate="no">SPAKE2+</bdi>');
  assert.equal(localizer.language('structure'),'fr');
});

test('ordinary profile labels are not URI schemes but actual catalog file URLs remain forbidden',()=>{
  const binding=contract('profile','Test profiles: {value}',{value:{kind:'protected',value:'default'}});
  const localizer=fixture([binding],{profile:'Prüfprofile: {value}'},'de');
  assert.equal(localizer.text('profile','Test profiles: default'),'Prüfprofile: default');
  localizer.catalog.entries.profile.message='Prüfprofile file:/etc/passwd: {value}';
  assert.equal(localizer.html('profile','Test profiles: default'),'<span lang="en" dir="ltr">Test profiles: default</span>');
  assert.equal(localizer.language('profile'),'en');
});

test('English boot does not require decompression and an inactive corrupt locale is never decoded',async()=>{
  const {source,fr,catalog}=compactFixture(),pack=value=>'gzip:'+gzipSync(JSON.stringify(value)).toString('base64');
  const de=catalog('de',['Signatur prüfen','Signatur untersuchen','Signatur kontrollieren']);
  const descriptor=Object.getOwnPropertyDescriptor(globalThis,'DecompressionStream');
  let localizer;
  try{
    Object.defineProperty(globalThis,'DecompressionStream',{configurable:true,writable:true,value:class {constructor(){throw new Error('English boot attempted decompression');}}});
    localizer=new Localizer({host:{},bindings:pack(source),catalogs:{fr:pack(fr),de:pack(de),he:'gzip:invalid-unused-bytes'}});
    assert.equal(localizer.initialPreparation,null);
    assert.equal(localizer.text('alpha.denied','Inspect signature'),'Inspect signature');
    assert.equal(localizer.diagnostics().englishContracts,0);
  }finally{Object.defineProperty(globalThis,'DecompressionStream',descriptor);}
  assert.throws(()=>localizer.activate('fr',{persist:false}),/Prepare/);
  await localizer.prepare('fr');assert.equal(localizer.locale,'en');
  localizer.activate('fr',{persist:false});
  assert.equal(localizer.explain('lesson:alpha','searchVariants.label','Inspect signature',{variantId:'denied'}),'Vérifier la signature');
  await localizer.prepare('de');localizer.activate('de',{persist:false});
  assert.equal(localizer.explain('lesson:beta','searchVariants.label','Inspect signature',{variantId:'denied'}),'Signatur kontrollieren');
  assert.equal(localizer.prepared,null);assert.equal(localizer.bindingResource,null);
  localizer.activate('en',{persist:false});assert.equal(localizer.catalog,null);
  assert.equal(localizer.html('alpha.denied','Inspect signature'),'Inspect signature');
});

test('a saved packed locale is prepared before its native render and never writes a startup preference',async()=>{
  const {source,fr}=compactFixture(),pack=value=>'gzip:'+gzipSync(JSON.stringify(value)).toString('base64'),{host,writes}=storageHost('fr');
  const localizer=new Localizer({host,bindings:pack(source),catalogs:{fr:pack(fr),he:'gzip:invalid-inactive'}});
  assert.ok(localizer.initialPreparation instanceof Promise);
  await localizer.initialPreparation;
  assert.equal(localizer.locale,'fr');assert.equal(localizer.source,'stored');
  assert.equal(localizer.text('alpha.success','Inspect signature'),'Examiner la signature');
  assert.equal(localizer.initialPreparation,null);assert.equal(localizer.prepared,null);
  assert.deepEqual(writes,[]);
});

test('canceling a prepared native choice cannot borrow it for a later locale',async()=>{
  const {source,fr,catalog}=compactFixture(),pack=value=>'gzip:'+gzipSync(JSON.stringify(value)).toString('base64');
  const de=catalog('de',['Signatur prüfen','Signatur untersuchen','Signatur kontrollieren']);
  const localizer=new Localizer({host:{},bindings:pack(source),catalogs:{fr:pack(fr),de:pack(de)}});
  await localizer.prepare('fr');assert.equal(localizer.activate('en',{persist:false}),false);
  assert.throws(()=>localizer.activate('fr',{persist:false}),/Prepare/);
  await localizer.prepare('de');localizer.activate('de',{persist:false});
  assert.equal(localizer.text('alpha.denied','Inspect signature'),'Signatur prüfen');
  assert.equal(localizer.prepared,null);
});

test('private compact binding indices preserve semantic owner separation without automatic audit-key aliases',()=>{
  const {source,fr}=compactFixture();delete source.keys['beta.denied'];delete source.sourceSetSha256;
  source.sourceSetSha256=sha(stable(source));fr.sourceSetSha256=source.sourceSetSha256;
  const localizer=new Localizer({host:{},initialLocale:'fr',bindings:source,catalogs:{fr}});
  assert.equal(localizer.explain('lesson:beta','searchVariants.label','Inspect signature',{variantId:'denied'}),'Contrôler la signature');
  assert.equal(localizer.explain('lesson:alpha','searchVariants.label','Inspect signature',{variantId:'denied'}),'Vérifier la signature');
  assert.equal(localizer.text('beta.denied','Inspect signature'),'Inspect signature');
  assert.equal(localizer.language('beta.denied'),'en');
});

test('a French queue caption is prose while actual whitespace-prefixed file and data URLs remain forbidden',()=>{
  const binding=contract('queue','Queue: pending requests.'),localizer=fixture([binding],{queue:'File: requêtes en attente.'});
  assert.equal(localizer.text('queue',binding.english),'File: requêtes en attente.');
  assert.equal(localizer.language('queue'),'fr');
  for(const url of ['file: /tmp/example','file: C:\\example','data: ,body','data: text/plain,body','javascript: alert(1)']){
    localizer.catalog.entries.queue.message='File: '+url;
    assert.equal(localizer.html('queue',binding.english),'<span lang="en" dir="ltr">'+binding.english+'</span>');
    assert.equal(localizer.language('queue'),'en');
  }
});

test('source-bound structured examples preserve JSON quotes and nested constructor braces',()=>{
  for(const raw of ['{"administrator":false,"note":"a } stays { quoted"}','TSCredentials{credType=1,credentials=TSPasswordCreds{domainName="CORP",password=""}}']){
    const english='Inspect '+raw+'.',owner={semanticId:'fixture:structured-example',fieldPath:'detail'};
    const source=new ProtectedRegistry().references(english,[],{ownerId:owner.semanticId,fieldPath:owner.fieldPath,sourceModule:'fixture:structured-example'});
    const binding=contract('structured-example',source.template,source.parameters,{owner,classification:source.classification});
    const localizer=fixture([binding],{'structured-example':'Inspecter {protected1}.'});
    const root=fragment(localizer.html('structured-example',english)),code=root.querySelector('bdi');
    assert.equal(root.textContent,'Inspecter '+raw+'.');
    assert.equal(code.textContent,raw);assert.equal(code.getAttribute('dir'),'ltr');assert.equal(code.getAttribute('translate'),'no');
    assert.equal(localizer.language('structured-example'),'fr');
  }
});

test('a shared editorial decision authorizes only its explicitly reviewed source bindings',()=>{
  const bindings=[
    contract('mode-passkey','Passkey + TOTP',{}, {owner:{semanticId:'mode:passkey-totp',fieldPath:'title'}}),
    contract('lesson-passkey','Passkey + TOTP',{}, {owner:{semanticId:'lesson:passkey-totp',fieldPath:'title'}}),
  ],id='fixture-de-established-term',reason='Fixture: established German Passkey terminology, not human approval.';
  const approvals=bindings.map(binding=>({id,locale:'de',key:binding.key,sourceSha256:binding.sourceSha256,reason,status:'approved'}));
  const compile=(messages,authorizations=approvals)=>compileResources({
    inventory:messages,ui:{messages:[],occurrences:[],unresolved:[],residual:[],summary:{complete:true}},
    summary:{unresolved:{},counts:{}},locales:['de'],pilot:true,approvals:{approvals:authorizations},
    catalogs:{de:{locale:'de',entries:Object.fromEntries(messages.map(binding=>[binding.key,{
      ...entry(binding,binding.english),identityJustification:{approvalId:id,reason},
    }]))}},
  }).report;
  const reviewed=compile(bindings);assert.equal(reviewed.ok,true,JSON.stringify(reviewed.errors));
  const other=contract('unreviewed-passkey','Passkey + TOTP',{}, {owner:{semanticId:'lesson:unreviewed',fieldPath:'title'}});
  const unreviewed=compile([...bindings,other]);
  assert.equal(unreviewed.ok,false);
  assert.ok(unreviewed.errors.some(error=>error.code==='invalid-identity-justification'&&error.key===other.key));
  const duplicate=compile(bindings,[...approvals,approvals[0]]);
  assert.equal(duplicate.ok,false);
  assert.ok(duplicate.errors.some(error=>error.code==='approval-id-invalid'&&error.key===bindings[0].key));
});

test('formal names and complete wire expressions remain one LTR island in RTL prose',()=>{
  const registry=new ProtectedRegistry();
  registry.registerTypedName('subkey (armor Authenticator)',{owner:'field:fixture-subkey',sourcePath:'field:fixture-subkey.name'});
  for(const [raw,ownerId,fieldPath,sourceModule] of [
    ['subkey (armor Authenticator)','artifact:fast-subkey','label','src/held-object-kerberos.js'],
    ['disable_encrypted_timestamp=false','lesson:lab-krb-spake-downgrade-allowed','prerequisites','src/kerberos-crypto-lab.js'],
    ['deny-only','lesson:lab-wra01','searchTags','src/scenario-search-metadata.js'],
    ['P->U/C->P','lesson:lab-opaque01','purpose','src/pake-lab.js'],
    ['now > endtime + maxClockSkew','lesson:lab-krb01','purpose','src/kerberos-lab.js'],
    ['DNSKEY child-zsk-g2','artifact:lab-dnssec16:bundle-9-key-child-zsk-g2','label','src/dnssec-signing-cases.js'],
  ]){
    const source=registry.references(raw,[],{ownerId,fieldPath,sourceModule});
    const binding=contract('wire-expression',source.template,source.parameters,{owner:{semanticId:ownerId,fieldPath},classification:source.classification});
    const localizer=fixture([binding],{'wire-expression':source.template},'he'),root=fragment(localizer.html('wire-expression',raw));
    const islands=root.querySelectorAll('bdi');
    assert.equal(root.textContent,raw);assert.equal(islands.length,1);
    assert.equal(islands[0].textContent,raw);assert.equal(islands[0].getAttribute('dir'),'ltr');
    assert.equal(islands[0].getAttribute('translate'),'no');assert.equal(localizer.language('wire-expression'),'he');
  }
});

test('a human DNSKEY caption localizes without splitting its technical record identity',()=>{
  const raw='Public DNSKEY / child-mx.example.net-zsk-g1',owner={semanticId:'artifact:lab-dnssec17:chain-key-child-mx',fieldPath:'label'};
  const source=new ProtectedRegistry().references(raw,[],{ownerId:owner.semanticId,fieldPath:owner.fieldPath,sourceModule:'src/dnssec-network-cases.js'});
  const binding=contract('dnskey-caption',source.template,source.parameters,{owner,classification:source.classification});
  const localizer=fixture([binding],{'dnskey-caption':'ציבורי {protected1}'},'he'),root=fragment(localizer.html('dnskey-caption',raw));
  assert.equal(root.textContent,'ציבורי DNSKEY / child-mx.example.net-zsk-g1');
  assert.equal(root.querySelector('bdi').textContent,'DNSKEY / child-mx.example.net-zsk-g1');
  assert.equal(localizer.language('dnskey-caption'),'he');
});

test('source-declared DNS operands retain absolute dots, wildcards and root in one LTR island',()=>{
  const cases=[
    ['Evaluate example. DS under authenticated prerequisites','example.','step:lab-dnssec04:signature-expired:check-evidence-1','title'],
    ['Published *.lab.example. A','*.lab.example.','artifact:lab-dnssec09:published-answer','label'],
    ['Received occurrence / example. DNSKEY: acquire, send','example.','artifact:lab-dnssec10:received-fresh-chain-2','trace.title'],
    ['Construct Query . DNSKEY','.','step:lab-dnssec01:cold-secure:root-key:q-construct','title'],
    ['Request example. DNSKEY / DNS message','example.','artifact:lab-dnssec02:ancestor-2-query-message','label'],
    ['Receive NOERROR / www.lab.example. / opaque TLS carrier: create, acquire','www.lab.example.','artifact:lab-dnssec06:upstream:r-tls-carrier','trace.title'],
    ['Check dnskey-rrset-signature for .','.','step:lab-dnssec02:combined-key:check-selected-record-1','title'],
    ['Retrieve lab.example. CDNSKEY at 2001:db8::53','lab.example.','lesson:lab-dnssec16','chapters.label'],
    ['example. DNSKEY / exact zone generation','example.','artifact:lab-dnssec16:bundle-5-rrset','label'],
    ['DNSKEY . / root-ksk-g1','.','artifact:lab-dnssec01:dnskey-root-ksk-g1','label'],
    ['g0 *.lab.example. RRSIG(1)','*.lab.example.','artifact:lab-dnssec19:g0-signature-5','label'],
  ];
  for(const [raw,dnsOwner,ownerId,fieldPath] of cases){
    const registry=new ProtectedRegistry(),source=registry.references(raw,[],{ownerId,fieldPath,sourceModule:'src/dnssec-lab.js'});
    const binding=contract('dns-owner',source.template,source.parameters,{owner:{semanticId:ownerId,fieldPath},classification:source.classification});
    // A structural marker changes the prose without claiming Native authorship.
    const localizer=fixture([binding],{'dns-owner':'RTL '+source.template},'he'),root=fragment(localizer.html('dns-owner',raw));
    assert.equal(root.textContent,'RTL '+raw);
    const start=raw.indexOf(dnsOwner),end=start+dnsOwner.length;
    const references=source.protectedReferences.filter(ref=>ref.start<=start&&ref.end>=end);
    assert.equal(references.length,1,raw);
    const reference=references[0],parameter=source.parameters[reference.parameter],entry=registry.entries.get(reference.registryId);
    assert.equal(parameter.role,'canonical-technical-identity',raw);
    assert.equal(entry.source.englishSourceSha256,sha(raw));assert.ok(entry.source.evidence.includes('src/dnssec-'));
    const island=[...root.querySelectorAll('bdi')].find(node=>node.textContent===parameter.value);
    assert.ok(island,raw);assert.equal(island.getAttribute('dir'),'ltr');assert.equal(island.getAttribute('translate'),'no');
    // Existing exact DNSKEY/generation compounds may contain the whole owner.
    assert.ok(parameter.value.includes(dnsOwner));
    for(const word of ['Evaluate','Published','Received','Construct','Query','Request','Receive','Check','Retrieve'])assert.ok(!Object.values(source.parameters).some(definition=>definition.value.includes(word)),raw);
  }
});

test('DNS operand protection does not turn ordinary examples or punctuation into identities',()=>{
  const context={ownerId:'step:lab-dnssec04:example-prose',fieldPath:'title',sourceModule:'src/dnssec-lab.js'};
  for(const raw of ['For example.','Use an example.','No exact example is declared.','Evaluate example under authenticated prerequisites.','Evaluate example. DS under authenticated prerequisites.','Query bad..example. A','Query prefix*.lab.example. A','Query example. A sentence.']){
    const registry=new ProtectedRegistry(),source=registry.references(raw,[],context);
    assert.ok(!registry.toJSON().some(entry=>entry.kind==='source-bound-technical-identity'),raw);
    assert.ok(!Object.values(source.parameters).some(parameter=>parameter.value==='example.'||parameter.value==='.'),raw);
    assert.equal(source.template.replace(/\{(protected\d+)\}/g,(_,name)=>source.parameters[name].value),raw);
  }
  const unrelated=new ProtectedRegistry().references('Evaluate example. DS under authenticated prerequisites',[],{...context,ownerId:'step:lab-krb01:example'});
  assert.ok(!Object.values(unrelated.parameters).some(parameter=>parameter.value==='example.'));
});

test('PAM configuration operands retain complete literal controls and code boundaries in RTL prose',()=>{
  const cases=[
    ['Evaluate /etc/pam.d/afs-login:2 required pam_unix.so',['/etc/pam.d/afs-login:2 required pam_unix.so'],'step:lab-pam01:evaluation-authenticate-afs-login-2-default','src/pam-foundations-lab.js'],
    ['Skip /etc/pam.d/afs-child:2 [success=2 default=ignore] pam_debug.so',['/etc/pam.d/afs-child:2 [success=2 default=ignore] pam_debug.so'],'step:lab-pam01:evaluation-authenticate-afs-child-2-default','src/pam-foundations-lab.js'],
    ['Change only required to requisite',['required','requisite'],'lesson:lab-pam01','src/pam-foundations-lab.js'],
    ['numeric jump skips 1 current-scope item(s); substack counts as one',['substack'],'step:lab-pam01:evaluation-authenticate-afs-child-2-default','src/pam-foundations-lab.js'],
    ['Synthetic afs-login service: auth/account/password required pam_unix; session required pam_unix; optional pam_systemd when selected. No nullok baseline.',['afs-login','auth/account/password required pam_unix','session required pam_unix','optional pam_systemd','nullok'],'lesson:lab-llog01','src/linux-logon-lab.js'],
    ['Declared sufficient pam_rootok bypasses password comparison for real UID0',['sufficient pam_rootok'],'step:lab-lelev02:su-auth','src/linux-elevation-lab.js'],
  ];
  for(const [raw,operands,ownerId,sourceModule] of cases){
    const source=new ProtectedRegistry().references(raw,[],{ownerId,fieldPath:'detail',sourceModule});
    const binding=contract('pam-controls',source.template,source.parameters,{owner:{semanticId:ownerId,fieldPath:'detail'},classification:source.classification});
    const localizer=fixture([binding],{'pam-controls':'RTL '+source.template},'he'),root=fragment(localizer.html('pam-controls',raw));
    assert.equal(root.textContent,'RTL '+raw);
    for(const operand of operands){
      const island=[...root.querySelectorAll('bdi')].find(node=>node.textContent===operand);
      assert.ok(island,raw+' - '+operand);assert.equal(island.getAttribute('dir'),'ltr');assert.equal(island.getAttribute('translate'),'no');
    }
  }
});

test('ordinary actor and policy words remain translatable outside exact technical roles',()=>{
  const registry=new ProtectedRegistry();
  for(const name of ['User','Client'])registry.registerTypedName(name,{owner:'field:fixture-'+name,sourcePath:'field:fixture-'+name+'.name'});
  for(const [raw,translated,ownerId,sourceModule] of [
    ['User and Client are required to include a nonce.','Utilisateur et client doivent inclure une valeur à usage unique.','fixture:human','src/study-workspaces.js'],
    ['This optional PAM step is required for the user.','Cette étape facultative de {protected1} est obligatoire pour la personne.','lesson:lab-pam01','src/pam-foundations-lab.js'],
  ]){
    const source=registry.references(raw,[],{ownerId,fieldPath:'description',sourceModule});
    const binding=contract('human-words',source.template,source.parameters,{owner:{semanticId:ownerId,fieldPath:'description'},classification:source.classification});
    const localizer=fixture([binding],{'human-words':translated}),root=fragment(localizer.html('human-words',raw));
    assert.equal(root.textContent,translated.replace('{protected1}','PAM'));
    assert.equal(localizer.language('human-words'),'fr');
    for(const word of ['User','Client','optional','required','include','nonce'])assert.ok(!Object.values(source.parameters).some(parameter=>parameter.value===word));
  }
});
