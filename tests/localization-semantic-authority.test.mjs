import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {gzipSync,gunzipSync} from 'node:zlib';
import {installHarness} from './dom-harness.mjs';
import {Localizer} from '../src/localization.js';
import {ProtectedRegistry,sha256,stableJson,semanticParameters} from '../tools/verification/localization/protected.mjs';
import {runtimeBinding,reclassifyInventory} from '../tools/verification/localization/inventory.mjs';
import {compileResources} from '../tools/verification/localization/resources.mjs';
import {semanticAuthorityCases,semanticAuthorityNegativeCases,SEMANTIC_NEGATIVE_CONTROLS} from '../tools/verification/localization/semantic-authority.mjs';
import {PROVIDER_PROFILES} from '../src/learning-presets.js';

const {document}=installHarness();
const authority=semanticAuthorityCases();
const restore=source=>source.template.replace(/\{(protected\d+)\}/g,(_,name)=>source.parameters[name].value);
const fragment=html=>{const element=document.createElement('div');element.innerHTML=html;return element;};
function classify(item){
  const registry=new ProtectedRegistry();
  for(const [id,actor] of Object.entries(item.actors||{}))registry.record(actor,'actor:'+id);
  return {registry,source:registry.references(item.english,[],item)};
}
function assertAuthority(item,source){
  assert.equal(restore(source),item.english,item.id+' exact English bytes');
  for(const literal of item.required){
    let offset=-1;
    while((offset=item.english.indexOf(literal,offset+1))!==-1){
      assert.ok(source.protectedReferences.some(reference=>reference.start<=offset&&reference.end>=offset+literal.length),item.id+' missing semantic occurrence '+literal+' at '+offset);
    }
  }
}
function binding(item,source){
  return runtimeBinding({key:'authority:'+item.id,owner:{semanticId:item.ownerId,fieldPath:item.fieldPath,module:item.sourceModule},english:item.english,sourceSha256:sha256(item.english),...source,runtimeContext:item.context||{},sourceBinding:'independent-declared-model-authority'});
}

test('declared entities, field names and case IDs independently require their actual narrative occurrences',async()=>{
  for(const item of await authority){
    const before=stableJson(item),{source}=classify(item);
    assertAuthority(item,source);
    assert.equal(stableJson(item),before,item.id+' canonical authority unchanged');
  }
});

test('provider chooser captions do not inherit a whole descriptive graph actor name',()=>{
  const registry=new ProtectedRegistry(),profile=PROVIDER_PROFILES.find(profile=>profile.id==='generic');
  const reference={value:profile.title,formal:true,kind:'actor-name',owner:'actor:realmB',sourcePath:'actor:realmB.name'};
  const source=registry.references(profile.title,[reference],{ownerId:'provider:'+profile.id,fieldPath:'title',sourceModule:'src/learning-presets.js'});
  assert.equal(restore(source),profile.title);
  assert.ok(Object.values(source.parameters).some(parameter=>parameter.value==='IdP'),'The formal role remains literal');
  assert.ok(!Object.values(source.parameters).some(parameter=>parameter.value===profile.title),'Chooser adjectives remain translatable');
  const actor=registry.references(profile.title,[reference],{ownerId:'actor:realmB',fieldPath:'name',sourceModule:'src/learning-presets.js'});
  assert.ok(Object.values(actor.parameters).some(parameter=>parameter.value===profile.title),'Actual canonical graph actor.name is unchanged');
  for(const branded of PROVIDER_PROFILES.filter(profile=>['Microsoft Entra ID','Okta','AWS IAM Identity Center'].includes(profile.title))){
    const source=registry.references(branded.title,[{...reference,value:branded.title}],{ownerId:'provider:'+branded.id,fieldPath:'title',sourceModule:'src/learning-presets.js'});
    assert.ok(Object.values(source.parameters).some(parameter=>parameter.value===branded.title),'Actual product names remain literal');
  }
});

test('protocol context does not turn ordinary state, actor or insecure prose into protected names',async()=>{
  for(const item of [...SEMANTIC_NEGATIVE_CONTROLS,...await semanticAuthorityNegativeCases()]){
    const {source}=classify({...item,fieldPath:item.fieldPath||'detail'});
    for(const value of item.excluded)assert.ok(!Object.values(source.parameters).some(parameter=>parameter.value===value),item.english+' overprotected '+value);
    assert.equal(restore(source),item.english);
  }
});

test('source HTTP request-line sentence punctuation is human prose, not part of the wire target',()=>{
  const english='The client sends GET /userinfo.',item={english,ownerId:'step:web-userinfo',fieldPath:'detail',sourceModule:'src/web-api-lab.js'}, {source}=classify(item);
  assert.ok(Object.values(source.parameters).some(parameter=>parameter.value==='GET /userinfo'));
  assert.ok(!Object.values(source.parameters).some(parameter=>parameter.value.endsWith('/userinfo.')));
  const localizer=new Localizer({host:{},initialLocale:'de',bindings:{messages:[binding({...item,id:'http-boundary'},source)]},catalogs:{de:{locale:'de',entries:{}}}});
  assert.equal(fragment(localizer.explainHtml(item.ownerId,item.fieldPath,english)).textContent,english);
});

test('independent real-model contracts survive compiler output and production HTML/rich consumers',async()=>{
  const items=await authority,registry=new Map(),inventory=[],entries={};
  for(const item of items){
    const classified=classify(item);assertAuthority(item,classified.source);
    for(const record of classified.registry.toJSON())registry.set(record.id,record);
    const contract=binding(item,classified.source);inventory.push(contract);
    entries[contract.key]={sourceSha256:contract.sourceSha256,message:'Prüfen: '+contract.english};
  }
  // Rich renderers address declared display keys; semantic prose resolves by owner.
  const compiled=compileResources({inventory,ui:{messages:inventory,occurrences:[],unresolved:[],residual:[],summary:{complete:true}},summary:{counts:{},unresolved:{}},locales:['de'],pilot:true,protectedEntries:[...registry.values()],catalogs:{de:{locale:'de',entries}}});
  assert.equal(compiled.report.ok,true,JSON.stringify(compiled.report.errors));
  assert.equal(compiled.report.counts.omittedMessages,0,'semantic cases may not silently disappear from the compiler');
  const emitted=await import('data:text/javascript;base64,'+Buffer.from(compiled.code).toString('base64'));
  const localizer=new Localizer({host:{},bindings:emitted.LOCALIZATION_BINDINGS,catalogs:emitted.LOCALIZATION_CATALOGS});
  await localizer.prepare('de');localizer.activate('de',{persist:false});
  for(const item of items){
    const {source}=classify(item),contract=binding(item,source),before=stableJson(item),root=fragment(localizer.explainHtml(item.ownerId,item.fieldPath,item.english,item.context||{}));
    assert.equal(root.textContent,'Prüfen: '+item.english,item.id+' compiled resolver');
    const protectedNodes=[...root.querySelectorAll('bdi')];
    for(const literal of item.required)assert.ok(protectedNodes.some(node=>node.textContent.includes(literal)),item.id+' rendered protected '+literal);
    for(const node of protectedNodes){assert.equal(node.getAttribute('translate'),'no');assert.equal(node.getAttribute('dir'),'ltr');}
    const parameters=Object.fromEntries(Object.entries(source.parameters).map(([name,definition])=>[name,{...definition,node:{tag:'code'}}]));
    const rich=fragment(localizer.rich(contract.key,source.template,parameters));
    assert.equal(rich.textContent,'Prüfen: '+item.english);
    assert.deepEqual([...rich.querySelectorAll('code')].map(node=>JSON.parse(node.getAttribute('data-copy-raw-json'))),Object.values(source.parameters).map(parameter=>parameter.value),item.id+' raw clipboard bytes');
    localizer.activate('en',{persist:false});assert.equal(localizer.explain(item.ownerId,item.fieldPath,item.english,item.context||{}),item.english);
    await localizer.prepare('de');localizer.activate('de',{persist:false});
    assert.equal(stableJson(item),before,item.id+' canonical state unchanged');
  }
});

test('reclassification retains previously unreferenced actor and field declarations without evaluating models',async()=>{
  const item=(await authority).find(item=>item.id==='authored-actor-id'),directory=mkdtempSync(path.join(tmpdir(),'auth-lab-semantic-replay-')),input=path.join(directory,'input'),out=path.join(directory,'out');mkdirSync(input);
  try{
    const registry=new ProtectedRegistry();
    // This is the pre-fix capture shape: the authored actor declaration exists,
    // but no protected occurrence points to it and the actor has no own id field.
    registry.add('formal-name',item.actors['spake-kdc'].name,'actor:spake-kdc','name');
    registry.add('formal-name','state','field:stateApp','name');
    registry.add('actor-name',item.actors['spake-kdc'].name,'actor:spake-kdc','actor:spake-kdc.name');
    registry.add('field-name','state','field:stateApp','field:stateApp.name');
    const raw=[{...item,key:'raw-actor',owner:{semanticId:item.ownerId,fieldPath:item.fieldPath,module:item.sourceModule}},{key:'raw-state',english:'Compare state with the original pending transaction.',owner:{semanticId:'field:stateApp',fieldPath:'purpose',module:'src/protocol-data.js'}}].map(record=>({key:record.key,owner:record.owner,english:record.english,sourceSha256:sha256(record.english),template:record.english,parameters:{},protectedReferences:[],classification:'prose',runtime:true,runtimeContext:{},context:{},sourceBinding:'independent-declared-model-authority'}));
    const request='The client sends GET /userinfo.',value='GET /userinfo.',start=request.indexOf(value),sourcePath='step:web-userinfo.detail:old:code:old',registryId=registry.add('source-bound-code-example',value,'step:web-userinfo',sourcePath);
    raw.push({key:'raw-http',owner:{semanticId:'step:web-userinfo',fieldPath:'detail',module:'src/web-api-lab.js'},english:request,sourceSha256:sha256(request),template:'The client sends {protected1}',parameters:{protected1:{kind:'protected',value,sourcePath}},protectedReferences:[{parameter:'protected1',occurrences:1,start,end:start+value.length,registryId}],classification:'mixed',runtime:true,runtimeContext:{},context:{},sourceBinding:'independent-declared-model-authority'});
    const rows={'messages.jsonl.gz':raw,'protected.jsonl.gz':registry.toJSON(),'ambiguities.jsonl.gz':[],'occurrences.jsonl.gz':raw.map(message=>({messageKey:message.key,ownerId:message.owner.semanticId,fieldPath:message.owner.fieldPath}))};
    for(const [file,values] of Object.entries(rows))writeFileSync(path.join(input,file),gzipSync(values.map(value=>JSON.stringify(value)+'\n').join('')));
    writeFileSync(path.join(input,'summary.json'),JSON.stringify({root:'fixture:semantic-replay',artifacts:Object.keys(rows).map(file=>({file})),counts:{},unresolved:{}}));
    const summary=await reclassifyInventory({input,out});assert.equal(summary.canonicalEvaluations,0);
    const decode=file=>gunzipSync(readFileSync(path.join(out,file))).toString().trim().split('\n').filter(Boolean).map(JSON.parse),bindings=decode('runtime-bindings.jsonl.gz'),records=decode('protected.jsonl.gz');
    assert.ok(records.some(record=>record.semanticId==='actor:spake-kdc'&&record.fieldPath==='name'));
    assert.ok(records.some(record=>record.semanticId==='field:stateApp'&&record.fieldPath==='name'&&record.value==='state'));
    assert.ok(records.some(record=>record.semanticId==='actor:spake-kdc'&&record.fieldPath==='actor:spake-kdc.name'));
    assert.ok(records.some(record=>record.semanticId==='field:stateApp'&&record.fieldPath==='field:stateApp.name'));
    for(const literal of ['spake-kdc','state'])assert.ok(bindings.some(message=>Object.values(message.parameters).some(parameter=>parameter.value===literal)),literal+' reclassified');
    const http=bindings.find(message=>message.owner.semanticId==='step:web-userinfo');
    assert.ok(Object.values(http.parameters).some(parameter=>parameter.value==='GET /userinfo'));
    assert.ok(!Object.values(http.parameters).some(parameter=>parameter.value==='GET /userinfo.'));
    for(const message of bindings)assert.equal(message.sourceSha256,sha256(stableJson({english:message.english,parameters:semanticParameters(message.parameters)})));
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('semantic source aliases retain one protected meaning without crossing runtime contexts',async()=>{
  const directory=mkdtempSync(path.join(tmpdir(),'auth-lab-semantic-alias-')),input=path.join(directory,'input'),out=path.join(directory,'out');mkdirSync(input);
  try{
    const descriptions=[
      ['realm-definition','field:challengeLogin','origin','src/protocol-data.js','Generated by Realm A and bound to its current authentication attempt.',{},'WebAuthn §5.5'],
      ['realm-search','field:challengeLogin','origin','src/scenario-search-metadata.js','Generated by Realm A and bound to its current authentication attempt.',{},'WebAuthn §5.5'],
      ['callback-definition','topic:callback','name','src/attribute-usage.js','SSH callback state mismatch',{realm:'single'},''],
      ['callback-navigation','topic:callback','name','src/lab-catalog.js','SSH callback state mismatch',{realm:'single'},''],
      ['separate-context','topic:callback','name','src/lab-catalog.js','SSH callback state mismatch',{realm:'direct'},'']
    ];
    const messages=descriptions.map(([key,semanticId,fieldPath,module,english,runtimeContext,standard])=>({key,owner:{semanticId,fieldPath,module},english,sourceSha256:sha256(english),template:english,parameters:{},protectedReferences:[],classification:'prose',runtime:true,runtimeContext,context:{},protectionContext:{standard},sourceBinding:'independent-declared-model-authority'}));
    const rows={'messages.jsonl.gz':messages,'protected.jsonl.gz':[],'ambiguities.jsonl.gz':[],'occurrences.jsonl.gz':messages.map(message=>({messageKey:message.key,ownerId:message.owner.semanticId,fieldPath:message.owner.fieldPath}))};
    for(const [file,values] of Object.entries(rows))writeFileSync(path.join(input,file),gzipSync(values.map(value=>JSON.stringify(value)+'\n').join('')));
    writeFileSync(path.join(input,'summary.json'),JSON.stringify({root:'fixture:semantic-alias',artifacts:Object.keys(rows).map(file=>({file})),counts:{},unresolved:{}}));
    await reclassifyInventory({input,out});
    const bindings=gunzipSync(readFileSync(path.join(out,'runtime-bindings.jsonl.gz'))).toString().trim().split('\n').map(JSON.parse);
    const entries=Object.fromEntries(bindings.map(contract=>[contract.key,{sourceSha256:contract.sourceSha256,message:contract.owner.semanticId==='field:challengeLogin'?'Von {protected1} für den aktuellen Anmeldeversuch erzeugt.':contract.context.realm==='single'?'{protected1}: Rückruf mit abweichendem {protected2}.':'{protected1}: abweichender Rückrufzustand.'}]));
    const localizer=new Localizer({host:{},initialLocale:'de',bindings:{messages:bindings},catalogs:{de:{locale:'de',entries}}});
    const realm=fragment(localizer.explainHtml('field:challengeLogin','origin',descriptions[0][4]));
    assert.equal(realm.textContent,'Von Realm A für den aktuellen Anmeldeversuch erzeugt.');
    assert.equal(realm.querySelector('bdi[translate="no"][dir="ltr"]').textContent,'Realm A');
    const callback=fragment(localizer.explainHtml('topic:callback','name',descriptions[2][4],{realm:'single'}));
    assert.equal(callback.textContent,'SSH: Rückruf mit abweichendem state.');
    assert.deepEqual([...callback.querySelectorAll('bdi[translate="no"][dir="ltr"]')].map(node=>node.textContent),['SSH','state']);
    const separate=fragment(localizer.explainHtml('topic:callback','name',descriptions[4][4],{realm:'direct'}));
    assert.equal(separate.textContent,'SSH: abweichender Rückrufzustand.');
    assert.deepEqual([...separate.querySelectorAll('bdi')].map(node=>node.textContent),['SSH']);
    assert.deepEqual(localizer.diagnostics().fallbacks,[]);
  }finally{rmSync(directory,{recursive:true,force:true});}
});
