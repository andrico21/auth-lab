#!/usr/bin/env bun
// Bounded bilingual evidence only. This producer does not perform linguistic review.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {sha256,stableJson,semanticParameters} from './protected.mjs';

const root=fs.realpathSync(fileURLToPath(new URL('../../../',import.meta.url)));
const locales=['ru','uk','he','de','ar-AE','fr','pl'];
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const same=(left,right)=>stableJson(left)===stableJson(right);
const identity=file=>{const bytes=fs.readFileSync(file);return {path:path.resolve(file),bytes:bytes.length,sha256:sha256(bytes)};};
const load=file=>JSON.parse((file.endsWith('.gz')?gunzipSync(fs.readFileSync(file)):fs.readFileSync(file)).toString('utf8'));
const HELP=`Usage: bun tools/verification/localization/semantic-sample.mjs
  --source-table=FILE --selection=ENGLISH_SELECTION_JSON --catalog=OWN_NATIVE_JSON --out=NEW_DIRECTORY
Constructs fresh Native pairs from exact Source schemas and selected canonical memberships,
splitting a selector when its members have different actual Native messages. Adds every
otherwise-uncovered exact Native override. Source/Native identity is checked before and after.
Representative protected values are retained English evidence, not new model evaluations.
This is not the full resource compiler, independent linguistic review, human/AT or acceptance.`;

function main(argv=process.argv.slice(2)){
  if(argv.includes('--help')){console.log(HELP);return;}
  const options={},allowed=new Set(['source-table','selection','catalog','out']);
  for(const argument of argv){
    const match=/^--([^=]+)=(.+)$/.exec(argument);
    assert.ok(match&&allowed.has(match[1]),'Unknown argument '+argument+'\n'+HELP);
    assert.ok(!Object.hasOwn(options,match[1]),'Duplicate option '+match[1]);
    options[match[1]]=match[2];
  }
  for(const key of allowed)assert.ok(options[key],'Required --'+key+'\n'+HELP);
  const requestedOut=path.resolve(options.out);
  assert.ok(requestedOut!==root&&!requestedOut.startsWith(root+path.sep),'Output must be outside the checkout');
  fs.mkdirSync(path.dirname(requestedOut),{recursive:true});
  const out=path.join(fs.realpathSync(path.dirname(requestedOut)),path.basename(requestedOut));
  assert.ok(out!==root&&!out.startsWith(root+path.sep),'Output must physically remain outside the checkout');
  fs.mkdirSync(out);
  const json=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
  const inputs=Object.fromEntries(['source-table','selection','catalog'].map(key=>[key,identity(options[key])]));
  const producer=identity(fileURLToPath(import.meta.url));
  const report={schemaVersion:1,kind:'auth-lab-l10n-source-bound-Native-semantic-sample',status:'constructing',startedAt:new Date().toISOString(),inputs,producer,runtime:{executable:process.execPath,version:process.version,bun:globalThis.Bun?.version||null,argv:[process.execPath,...process.argv.slice(1)]},errors:[]};
  let exitCode=0;
  try{
    const table=load(options['source-table']),selection=load(options.selection),catalog=load(options.catalog);
    assert.equal(table.schemaVersion,2);assert.equal(table.format,'auth-lab-l10n-source-table');
    assert.ok(Array.isArray(table.schemas)&&Array.isArray(table.bindings));
    const {sourceSetSha256,...unsigned}=table;
    assert.equal(sha256(stableJson(unsigned)),sourceSetSha256,'Source-table set fingerprint');
    assert.equal(selection.schemaVersion,1);
    assert.equal(selection.kind,'auth-lab-l10n-English-semantic-sample-selection');
    assert.equal(selection.sourceSetSha256,sourceSetSha256,'Selection Source set');
    assert.equal(selection.sourceTableGzipSha256,inputs['source-table'].sha256,'Selection exact Source table bytes');
    assert.ok(Array.isArray(selection.records)&&selection.records.length>0);
    assert.equal(catalog.schemaVersion,2);assert.equal(catalog.format,'auth-lab-l10n-authored-catalog');
    assert.ok(locales.includes(catalog.locale),'Allowlisted own Native locale');
    assert.equal(catalog.sourceSetSha256,sourceSetSha256,'Native catalog Source set');
    assert.ok(Array.isArray(catalog.messages));assert.equal(catalog.messages.length,table.schemas.length,'Complete schema-aligned Native messages');
    assert.ok(catalog.overrides===undefined||object(catalog.overrides));
    const overrides=catalog.overrides||{},byKey=new Map(),explicit=table.keys||{};
    function bindingAt(index,key){
      assert.ok(Number.isInteger(index)&&index>=0&&index<table.bindings.length,'Canonical binding index');
      const row=table.bindings[index],schema=table.schemas[row[0]];
      const owner={semanticId:table.owners[row[1]],fieldPath:table.fields[row[2]]},context=table.contexts[row[3]];
      assert.ok(schema&&typeof owner.semanticId==='string'&&typeof owner.fieldPath==='string'&&object(context));
      // The same exact recipe as inventory.runtimeBinding; no value/text-derived aliasing.
      const runtimeKey='runtime:'+sha256(stableJson({ownerId:owner.semanticId,fieldPath:owner.fieldPath,context,sourceSha256:schema[0]})).slice(0,32);
      if(key!==undefined)assert.ok(explicit[key]===index||key===runtimeKey,'Canonical audit key for selected membership');
      return {key:key??runtimeKey,bindingIndex:index,owner,context,classification:table.classifications[row[4]]};
    }
    for(let index=0;index<table.bindings.length;index++){
      const member=bindingAt(index);
      assert.ok(!byKey.has(member.key),'Unambiguous runtime audit key');byKey.set(member.key,index);
    }
    for(const [key,index]of Object.entries(explicit)){
      assert.ok(!byKey.has(key)||byKey.get(key)===index,'Unambiguous explicit UI key');byKey.set(key,index);
    }
    function nativeAt(member){
      const row=table.bindings[member.bindingIndex],schema=table.schemas[row[0]],override=overrides[member.key];
      if(override!==undefined){assert.ok(object(override));assert.equal(override.sourceSha256,schema[0],'Exact override Source SHA');}
      const message=override===undefined?catalog.messages[row[0]]:override.message;
      assert.ok(typeof message==='string'||object(message)&&object(message.plural),'Complete Native message shape');
      assert.ok((typeof message==='string'?[message]:Object.values(message.plural)).every(value=>typeof value==='string'&&value.length>0),'Nonempty Native forms');
      return {message,origin:override===undefined?'schema-default':'exact-binding-override'};
    }
    const records=[],coveredOverrides=new Set(),selectedIds=new Set();
    function appendSelection(record){
      assert.ok(typeof record.sampleId==='string'&&!selectedIds.has(record.sampleId),'Unique English selector ID');selectedIds.add(record.sampleId);
      assert.ok(Number.isInteger(record.schemaIndex)&&record.schemaIndex>=0&&record.schemaIndex<table.schemas.length);
      const schema=table.schemas[record.schemaIndex];
      assert.equal(record.sourceSha256,schema[0],'Selected Source SHA');assert.ok(same(record.english,schema[1]),'Exact selected English template');
      assert.ok(object(record.parameters)&&same(semanticParameters(record.parameters),schema[2]),'Selected typed parameter semantics');
      assert.equal(sha256(stableJson({english:record.english,parameters:semanticParameters(record.parameters)})),schema[0],'Selected typed Source fingerprint');
      assert.ok(Array.isArray(record.reviewedBindings)&&record.reviewedBindings.length>0,'Explicit reviewed memberships');
      const groups=new Map(),seenMembers=new Set();
      for(const member of record.reviewedBindings){
        assert.ok(!seenMembers.has(member.key),'No duplicate membership within one selector');seenMembers.add(member.key);
        assert.equal(byKey.get(member.key),member.bindingIndex,'Exact selected key/index');
        assert.ok(same(bindingAt(member.bindingIndex,member.key),member),'Exact selected owner/field/context/classification');
        assert.equal(table.bindings[member.bindingIndex][0],record.schemaIndex,'Selected membership belongs to Source schema');
        const native=nativeAt(member),encoded=stableJson(native.message);
        if(!groups.has(encoded))groups.set(encoded,{message:native.message,members:[],origins:new Set()});
        const group=groups.get(encoded);group.members.push(member);group.origins.add(native.origin);
        if(Object.hasOwn(overrides,member.key))coveredOverrides.add(member.key);
      }
      let branch=0;
      for(const group of groups.values())records.push({...record,sampleId:catalog.locale+'-'+record.sampleId+(groups.size>1?'-Native-'+(++branch):''),native:group.message,nativeOrigins:[...group.origins].sort(),reviewedBindings:group.members,scopeLimit:'Only these explicit memberships and this actual own-locale Native message are review scope. An interned schema is not blanket semantic or linguistic acceptance.'});
    }
    for(const record of selection.records)appendSelection(record);
    const uncoveredOverrideKeys=Object.keys(overrides).filter(key=>!coveredOverrides.has(key)).sort();
    for(const key of uncoveredOverrideKeys){
      assert.ok(byKey.has(key),'Native override resolves to actual Source membership');
      const member=bindingAt(byKey.get(key),key),schemaIndex=table.bindings[member.bindingIndex][0],schema=table.schemas[schemaIndex];
      appendSelection({sampleId:'otherwise-uncovered-override-'+key.replace(/[^A-Za-z0-9_-]/g,'_'),sampleKind:'exact-binding-editorial-override',schemaIndex,sourceSha256:schema[0],english:schema[1],parameters:schema[2],reviewedBindings:[member],parameterEvidence:'Typed Source template roles only. No representative protected values or newly evaluated raw operand bytes are invented for this additional override. Use exact owner/context and supplied operation-source evidence.',scopeLimit:'Exact Native override only.'});
    }
    assert.equal(coveredOverrides.size,Object.keys(overrides).length,'Every exact Native override is in the actual sample');
    const sample={schemaVersion:1,kind:'auth-lab-l10n-fresh-own-Native-semantic-sample',locale:catalog.locale,sourceSetSha256,sourceTableGzipSha256:inputs['source-table'].sha256,selectionSha256:inputs.selection.sha256,nativeCatalogSha256:inputs.catalog.sha256,selection:selection.selection,qualification:'Fresh own-Native messages, including exact overrides, are paired with actual typed English schemas and explicit memberships. Typed/source identity validation is mechanical, not translation-quality approval. Representative raw values/source locators are retained evidence, not new runtime evaluations. Human and actual native AT remain unperformed by this producer.',records};
    json('sample.json',sample);
    report.locale=catalog.locale;report.sourceSetSha256=sourceSetSha256;
    report.counts={EnglishSelectionRecords:selection.records.length,actualNativeSampleRecords:records.length,explicitBindingPairs:records.reduce((sum,row)=>sum+row.reviewedBindings.length,0),distinctBindings:new Set(records.flatMap(row=>row.reviewedBindings.map(member=>member.key))).size,distinctSourceSchemas:new Set(records.map(row=>row.sourceSha256)).size,exactNativeOverrides:Object.keys(overrides).length,exactNativeOverridesCovered:coveredOverrides.size,otherwiseUncoveredOverridesAdded:uncoveredOverrideKeys.length};
    report.output=identity(path.join(out,'sample.json'));
    report.status='constructed-source-bound-pairs-not-linguistic-review';
  }catch(error){exitCode=1;report.status='failed';report.errors.push(String(error.stack||error));}
  try{
    for(const [key,before]of Object.entries(inputs))assert.ok(same(identity(options[key]),before),'Input changed during sample construction: '+key);
    assert.ok(same(identity(fileURLToPath(import.meta.url)),producer),'Producer changed during sample construction');
    report.postChecks='all-input-and-producer-bytes-unchanged';
  }catch(error){exitCode=1;report.status='failed';report.errors.push(String(error.stack||error));}
  report.finishedAt=new Date().toISOString();json('summary.json',report);
  console.log(JSON.stringify({status:report.status,locale:report.locale,counts:report.counts,errors:report.errors,report:path.join(out,'summary.json')}));
  if(exitCode)process.exitCode=exitCode;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main();
