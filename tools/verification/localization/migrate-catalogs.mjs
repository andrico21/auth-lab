import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import {createGunzip, gunzipSync, gzipSync} from 'node:zlib';
import {sha256, stableJson, semanticParameters} from './protected.mjs';
import {encodeSourceTable, RESOURCE_SCHEMA, compileResources} from './resources.mjs';

// Preparation and explicit externally staged reviewed application; never live edits.
// The source-delta contract is reused: strong schema identities and exact
// authoring storageBindingIndex memberships, never a positional before/after zip.
const producer=fileURLToPath(import.meta.url);
const root=path.resolve(path.dirname(producer),'../../..');
const usage='bun tools/verification/localization/migrate-catalogs.mjs --before=SOURCE_TABLE.gz --after=SOURCE_TABLE.gz --before-authoring=AUTHORING.jsonl.gz --after-authoring=AUTHORING.jsonl.gz --catalog-dir=CATALOGS --out=NEW_EXTERNAL_DIRECTORY';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const same=(a,b)=>stableJson(a)===stableJson(b);
const assert=(condition,message)=>{if(!condition)throw new Error(message);};
const digest=/^[a-f0-9]{64}$/;
const compare=(a,b)=>a<b?-1:a>b?1:0;
const forms=value=>typeof value==='string'?{source:value}:value?.plural;
const placeholders=text=>{const result={};for(const match of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g))result[match[1]]=(result[match[1]]||0)+1;return result;};
const identity=file=>{const bytes=fs.readFileSync(file);return {path:file,bytes:bytes.length,sha256:sha256(bytes)};};
const own=(value,key)=>Object.hasOwn(value||{},key);
const optional=(name,value)=>value===undefined?{}:{[name]:value};
const id=value=>sha256(stableJson(value));

function readTable(file){
  const table=JSON.parse(gunzipSync(fs.readFileSync(file)).toString('utf8'));
  assert(table.schemaVersion===2&&table.format==='auth-lab-l10n-source-table','Unsupported source table: '+file);
  const {sourceSetSha256,...payload}=table;
  assert(digest.test(sourceSetSha256)&&sha256(stableJson(payload))===sourceSetSha256,'Source-set fingerprint mismatch: '+file);
  for(const key of ['schemas','owners','fields','contexts','classifications','bindings'])assert(Array.isArray(table[key]),'Missing source dimension: '+key);
  assert(object(table.keys),'Missing explicit UI keys');
  for(const key of ['owners','fields','contexts','classifications'])assert(new Set(table[key].map(stableJson)).size===table[key].length,'Duplicate source dimension: '+key);
  const hashes=new Set();
  for(const schema of table.schemas){
    assert(Array.isArray(schema)&&schema.length===4&&digest.test(schema[0])&&!hashes.has(schema[0]),'Invalid/duplicate strong schema');hashes.add(schema[0]);
    assert(object(schema[2])&&same(schema[2],semanticParameters(schema[2]))&&object(schema[3]),'Invalid typed parameter schema');
    assert(sha256(stableJson({english:schema[1],parameters:schema[2]}))===schema[0],'Strong schema fingerprint mismatch');
    assert(object(forms(schema[1]))&&Object.values(forms(schema[1])).every(text=>typeof text==='string'&&same(placeholders(text),schema[3])),'Invalid English placeholder contract');
  }
  const explicit=new Map();
  for(const [key,index] of Object.entries(table.keys)){
    assert(key&&Number.isInteger(index)&&index>=0&&index<table.bindings.length&&!explicit.has(index),'Invalid explicit UI key');explicit.set(index,key);
  }
  return {table,explicit};
}

async function readAuthoring(file,source){
  const {table,explicit}=source,bindings=new Array(table.bindings.length),groups=new Array(table.schemas.length),keys=new Set();
  const input=fs.createReadStream(file),decoded=input.pipe(createGunzip());input.on('error',error=>decoded.destroy(error));
  for await(const line of readline.createInterface({input:decoded,crlfDelay:Infinity})){
    if(!line.trim())continue;
    const group=JSON.parse(line),schema=table.schemas[group.schemaIndex];
    assert(schema&&schema[0]===group.sourceSha256&&!groups[group.schemaIndex],'Unknown/duplicate authoring schema');
    assert(same(schema[1],group.english)&&same(schema[2],semanticParameters(group.parameters)),'Authoring schema mismatch');
    assert(Array.isArray(group.bindings)&&group.bindings.length,'Empty authoring group');
    groups[group.schemaIndex]={schemaIndex:group.schemaIndex,sourceSha256:group.sourceSha256,english:group.english,parameters:group.parameters,bindings:[]};
    for(const binding of group.bindings){
      const index=binding.storageBindingIndex,row=table.bindings[index];
      assert(Number.isInteger(index)&&index>=0&&row&&!bindings[index]&&Array.isArray(row)&&row.length===5&&row[0]===group.schemaIndex,'Invalid authoring storageBindingIndex');
      assert(typeof binding.key==='string'&&binding.key&&!keys.has(binding.key)&&object(binding.owner)&&object(binding.context),'Invalid/duplicate authoring binding');
      assert(binding.owner.semanticId===table.owners[row[1]]&&binding.owner.fieldPath===table.fields[row[2]]&&same(binding.context,table.contexts[row[3]])&&binding.classification===table.classifications[row[4]],'Authoring membership mismatch: '+binding.key);
      assert(!explicit.has(index)||explicit.get(index)===binding.key,'Explicit UI authoring mismatch');
      assert(!own(table.keys,binding.key)||table.keys[binding.key]===index,'Explicit UI storage mismatch');
      if(own(binding,'sourceSha256'))assert(binding.sourceSha256===schema[0],'Binding source SHA mismatch');
      if(own(binding,'english'))assert(same(binding.english,schema[1]),'Binding English mismatch');
      if(own(binding,'parameters'))assert(same(semanticParameters(binding.parameters),schema[2]),'Binding parameter mismatch');
      keys.add(binding.key);
      const record={...binding,schemaIndex:group.schemaIndex,sourceSha256:group.sourceSha256,explicitUI:explicit.has(index)};
      record.witness=reconstruct(schema[1],schema[2]);
      bindings[index]=record;groups[group.schemaIndex].bindings.push(index);
    }
  }
  assert(groups.filter(Boolean).length===table.schemas.length&&bindings.filter(Boolean).length===table.bindings.length,'Truncated authoring source');
  // Reuse the resource encoder to check canonical row order, UI keys, schema
  // interning, and source-set identity against the independently supplied table.
  const canonical=encodeSourceTable(bindings.map(binding=>({key:binding.key,owner:binding.owner,context:binding.context,classification:binding.classification,sourceSha256:binding.sourceSha256,english:table.schemas[binding.schemaIndex][1],parameters:table.schemas[binding.schemaIndex][2]})),Object.keys(table.keys));
  assert(same(canonical,table),'Authoring does not reproduce canonical source table');
  return {...source,bindings,groups};
}

// Literal substitution preserves every character, including punctuation. Values
// unavailable at source time stay typed symbolic tokens, never invented English.
function reconstruct(english,parameters){
  const symbolic={},dynamicSpans=[];
  const rendered=Object.fromEntries(Object.entries(forms(english)).map(([branch,text])=>{
    let offset=0,cursor=0;
    const result=text.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(token,name,index)=>{
      const definition=parameters[name];assert(object(definition),'Unknown source parameter: '+name);
      offset+=index-cursor;
      const literal=['protected','source','exact'].includes(definition.kind)&&['string','number','boolean'].includes(typeof definition.value);
      const value=literal?String(definition.value):token;
      if(!literal)symbolic[name]=definition;
      if(definition.dynamic)dynamicSpans.push({branch,start:offset,end:offset+value.length,kind:definition.kind,...optional('value',definition.value)});
      offset+=value.length;cursor=index+token.length;return value;
    });
    return [branch,result];
  }));
  return {forms:rendered,symbolic,dynamicSpans};
}
function lineageKey(binding){
  return stableJson(binding.explicitUI?{uiKey:binding.key}:{owner:binding.owner.semanticId,field:binding.owner.fieldPath,context:binding.context,witness:binding.witness});
}
const bindingRef=binding=>({key:binding.key,schemaIndex:binding.schemaIndex,sourceSha256:binding.sourceSha256,storageBindingIndex:binding.storageBindingIndex,owner:binding.owner,context:binding.context,classification:binding.classification,explicitUI:binding.explicitUI,witness:binding.witness,parameterSources:binding.parameterSources||{}});
function mapLineage(before,after){
  const candidates=new Map(),priors=new Map(),unresolved=[],mapping=[],used=new Set(),mappedOld=new Set(),newUI=[];
  const append=(map,binding)=>{const key=lineageKey(binding),list=map.get(key)||[];list.push(binding);map.set(key,list);};
  for(const binding of after.bindings)append(candidates,binding);
  for(const binding of before.bindings)append(priors,binding);
  const link=(old,next,evidence)=>{used.add(next.storageBindingIndex);mappedOld.add(old.storageBindingIndex);mapping.push({before:old.storageBindingIndex,after:next.storageBindingIndex,evidence});};
  // Exact canonical-key anchors are corroborated by semantic membership and the
  // complete reconstructed witness. They disambiguate distinct same-English
  // bindings without selecting one by array order.
  for(const old of before.bindings){
    const exact=(candidates.get(lineageKey(old))||[]).filter(next=>next.key===old.key);
    if(exact.length===1)link(old,exact[0],'exact-key-and-semantic-witness');
  }
  for(const old of before.bindings)if(!mappedOld.has(old.storageBindingIndex)){
    const candidatesForOld=candidates.get(lineageKey(old))||[],options=candidatesForOld.filter(next=>!used.has(next.storageBindingIndex));
    if(options.length===1)link(old,options[0],'unique-semantic-witness-and-dynamic-spans');
    else if(!options.length&&candidatesForOld.length===1)link(old,candidatesForOld[0],'unique-converged-semantic-witness-and-dynamic-spans');
    else unresolved.push({kind:options.length?'ambiguous-lineage':'missing-lineage',before:bindingRef(old),candidates:candidatesForOld.map(bindingRef)});
  }
  for(const next of after.bindings)if(!used.has(next.storageBindingIndex)){
    if(next.explicitUI&&!own(before.table.keys,next.key)){newUI.push(next.storageBindingIndex);continue;}
    const options=priors.get(lineageKey(next))||[];
    // A protection refinement can add a second typed variant while retaining
    // the old variant. This is a witnessed source split, not new English.
    if(!next.explicitUI&&options.length===1&&mappedOld.has(options[0].storageBindingIndex))link(options[0],next,'unique-witnessed-additional-typed-variant');
    else unresolved.push({kind:'unmapped-new-non-UI-binding',after:bindingRef(next),candidates:options.map(bindingRef)});
  }
  mapping.sort((a,b)=>a.before-b.before||a.after-b.after);
  return {mapping,newUI,unresolved,mappedOldBindings:mappedOld.size,additionalTypedVariants:mapping.length-mappedOld.size,convergedOldBindings:mapping.length-used.size};
}

// A role/audit-only change can retain Native bytes. Renaming is permitted only
// when the exact rendered English spans identify a bijection and literal runs
// have not changed. Source value occurrences, not Native words, are evidence.
function compatibility(old,next){
  const oldParameters=old[2],newParameters=next[2];
  const parameterCore=definition=>Object.fromEntries(Object.entries(definition).filter(([name])=>name!=='role'));
  const tokenize=(schema,branch)=>{
    const text=forms(schema[1])[branch],tokens=[];let cursor=0,offset=0;
    for(const match of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)){
      const literal=text.slice(cursor,match.index);tokens.push({literal});offset+=literal.length;
      const parameter=match[1],definition=schema[2][parameter],value=['string','number','boolean'].includes(typeof definition.value)?String(definition.value):null;
      tokens.push({parameter,start:offset,end:value===null?null:offset+value.length,value,definition:parameterCore(definition)});offset+=value===null?match[0].length:value.length;cursor=match.index+match[0].length;
    }
    tokens.push({literal:text.slice(cursor)});return tokens;
  };
  if(!same(Object.keys(forms(old[1])).sort(),Object.keys(forms(next[1])).sort()))return {disposition:'authored-native-required',reason:'English form shape changed'};
  const rename={},reverse={},evidence=[];
  for(const branch of Object.keys(forms(old[1]))){
    const a=tokenize(old,branch),b=tokenize(next,branch);
    if(a.length!==b.length)return {disposition:'authored-native-required',reason:'Protected parameter boundaries changed'};
    for(let i=0;i<a.length;i++){
      if(own(a[i],'literal')){if(!same(a[i],b[i]))return {disposition:'authored-native-required',reason:'English literal prose or parameter boundary changed'};continue;}
      const x=a[i],y=b[i];
      if(!y.parameter||!same(x.definition,y.definition)||x.start!==y.start||x.end!==y.end)return {disposition:'authored-native-required',reason:'Parameter kind/value/dynamic contract or protected span changed'};
      if((own(rename,x.parameter)&&rename[x.parameter]!==y.parameter)||(own(reverse,y.parameter)&&reverse[y.parameter]!==x.parameter))return {disposition:'authored-native-required',reason:'Ambiguous placeholder lineage'};
      rename[x.parameter]=y.parameter;reverse[y.parameter]=x.parameter;evidence.push({branch,oldParameter:x.parameter,newParameter:y.parameter,start:x.start,end:x.end,value:x.value});
    }
  }
  // Include non-rendered plural selectors in the compatibility contract.
  for(const name of Object.keys(oldParameters))if(!own(rename,name)){
    if(!own(newParameters,name)||!same(parameterCore(oldParameters[name]),parameterCore(newParameters[name])))return {disposition:'authored-native-required',reason:'Non-rendered selector contract changed'};
    rename[name]=name;reverse[name]=name;
  }
  if(!same(Object.keys(reverse).sort(),Object.keys(newParameters).sort()))return {disposition:'authored-native-required',reason:'Parameter set changed'};
  return {disposition:Object.entries(rename).every(([a,b])=>a===b)?'mechanical-byte-preservation':'mechanical-placeholder-rename',placeholderMap:rename,spanEvidence:evidence};
}
function renameMessage(message,map){
  const text=value=>value.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(token,name)=>{assert(own(map,name),'Native placeholder absent from exact map: '+name);return '{'+map[name]+'}';});
  return typeof message==='string'?text(message):{plural:Object.fromEntries(Object.entries(message.plural).map(([branch,value])=>[branch,text(value)]))};
}
function validateMessage(message,schema,locale){
  const branches=forms(message),plural=typeof schema[1]!=='string';
  const categories={ru:['one','few','many','other'],uk:['one','few','many','other'],he:['one','two','other'],de:['one','other'],'ar-AE':['zero','one','two','few','many','other'],fr:['one','many','other'],pl:['one','few','many','other']};
  assert(object(branches)&&same(Object.keys(branches).sort(),(plural?categories[locale]:['source']).slice().sort()),'Invalid Native form shape for '+locale);
  for(const value of Object.values(branches))assert(typeof value==='string'&&value.trim()&&same(placeholders(value),schema[3])&&!/[{}]/.test(value.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'')),'Invalid Native placeholder contract for '+locale);
}
function readCatalog(file,locale,before){
  const catalog=JSON.parse(fs.readFileSync(file,'utf8'));
  assert(catalog.schemaVersion===2&&catalog.format==='auth-lab-l10n-authored-catalog'&&catalog.locale===locale&&catalog.sourceSetSha256===before.table.sourceSetSha256&&Array.isArray(catalog.messages)&&catalog.messages.length===before.groups.length,'Catalog/source mismatch: '+locale);
  assert(!own(catalog,'entries')&&(!own(catalog,'overrides')||object(catalog.overrides))&&(!own(catalog,'schemaIdentityJustifications')||object(catalog.schemaIdentityJustifications)),'Invalid authored catalog containers');
  catalog.messages.forEach((message,index)=>validateMessage(message,before.table.schemas[index],locale));
  const byKey=new Map(before.bindings.map(binding=>[binding.key,binding]));
  for(const [key,override] of Object.entries(catalog.overrides||{})){
    const binding=byKey.get(key);assert(binding&&object(override)&&override.sourceSha256===binding.sourceSha256,'Unknown/wrong-source override: '+key);validateMessage(override.message,before.table.schemas[binding.schemaIndex],locale);
  }
  for(const key of Object.keys(catalog.schemaIdentityJustifications||{}))assert(/^(0|[1-9][0-9]*)$/.test(key)&&Number(key)<before.groups.length,'Invalid identity schema index');
  return catalog;
}

function localePacket(locale,catalog,before,after,lineage){
  const units=new Map(),defaultTargets=[],overrideTargets=[],identityScopes=[],oldDefaults=[],oldOverrides=[],transitions=new Map(),variantSets=new Map();
  const oldForNew=new Map();
  for(const relation of lineage.mapping){const priors=oldForNew.get(relation.after)||[];priors.push(before.bindings[relation.before]);oldForNew.set(relation.after,priors);}
  const schemaRelations=new Map(),destinationsByOld=new Map();
  for(const relation of lineage.mapping){
    const next=after.bindings[relation.after],old=before.bindings[relation.before],set=schemaRelations.get(next.schemaIndex)||new Set(),destinations=destinationsByOld.get(old.schemaIndex)||new Set();
    set.add(old.schemaIndex);schemaRelations.set(next.schemaIndex,set);destinations.add(next.schemaIndex);destinationsByOld.set(old.schemaIndex,destinations);
  }
  const ensureUnit=(newIndex,oldIndex,native,context)=>{
    const next=after.table.schemas[newIndex],prior=oldIndex===null?null:before.table.schemas[oldIndex];
    const transitionKey=oldIndex+':'+newIndex;
    if(!transitions.has(transitionKey))transitions.set(transitionKey,prior?compatibility(prior,next):{disposition:'authored-native-required',reason:'New explicit UI key requires Native authoring'});
    const transition=transitions.get(transitionKey);
    if(transition.disposition!=='authored-native-required'&&context.kind!=='schema-default')context={kind:'mechanical-compatible-variant'};
    const key={newSchemaIndex:newIndex,oldSchemaIndex:oldIndex,oldNative:native??null,sourceContext:context};
    const unitId=id(key);
    if(!units.has(unitId)){
      const proposed=transition.disposition==='authored-native-required'?undefined:transition.disposition==='mechanical-byte-preservation'?native:renameMessage(native,transition.placeholderMap);
      if(proposed!==undefined)validateMessage(proposed,next,locale);
      units.set(unitId,{unitId,newSchemaIndex:newIndex,newSourceSha256:next[0],oldSchemaIndex:oldIndex,oldSourceSha256:prior?.[0]??null,oldEnglish:prior?.[1]??null,newEnglish:next[1],oldParameters:prior?.[2]??null,newParameters:next[2],oldNative:native??null,sourceContext:context,transition,...optional('proposedMessage',proposed),messageDisposition:proposed===undefined?'pending-native-authoring':'mechanically-preserved-not-native-review-acceptance',targets:[],sourceWitnesses:[],oldNativeVariants:[]});
    }
    return units.get(unitId);
  };
  const addTarget=(unit,target,old,next,variant)=>{
    unit.targets.push(target);
    if(next)unit.sourceWitnesses.push({beforeStorageBindingIndex:old?.storageBindingIndex??null,afterStorageBindingIndex:next.storageBindingIndex,reference:'migration-plan.json.gz mappings/newExplicitUI'});
    const variantKey=stableJson(variant),seen=variantSets.get(unit.unitId)||new Set();
    if(!seen.has(variantKey)){unit.oldNativeVariants.push(variant);seen.add(variantKey);variantSets.set(unit.unitId,seen);}
  };
  // Prefer an unchanged strong hash, regardless of schema-index shifts. A merged
  // changed schema never replaces an existing unchanged default message.
  const oldHash=new Map(before.table.schemas.map((schema,index)=>[schema[0],index]));
  for(let newIndex=0;newIndex<after.groups.length;newIndex++){
    const hash=after.table.schemas[newIndex][0],relations=[...(schemaRelations.get(newIndex)||[])].sort((a,b)=>a-b);
    const oldIndex=oldHash.has(hash)?oldHash.get(hash):relations[0]??null;
    const native=oldIndex===null?undefined:catalog.messages[oldIndex];
    const unit=ensureUnit(newIndex,oldIndex,native,{kind:'schema-default'});
    const target={kind:'default',schemaIndex:newIndex,sourceSha256:hash,unitId:unit.unitId,scopeStorageBindingIndices:after.groups[newIndex].bindings};defaultTargets.push(target);addTarget(unit,target,null,null,{kind:'default',oldSchemaIndex:oldIndex,message:native??null});
    if(oldIndex!==null)oldDefaults.push({schemaIndex:oldIndex,newSchemaIndex:newIndex,message:native,identityJustification:catalog.schemaIdentityJustifications?.[oldIndex]??null});
  }
  const defaultBySchema=new Map(defaultTargets.map(target=>[target.schemaIndex,units.get(target.unitId)]));
  for(const next of after.bindings){
    const priors=oldForNew.get(next.storageBindingIndex)||[],exact=priors.filter(old=>old.key===next.key);
    assert(exact.length<=1&&(!priors.length||priors.length===1||exact.length===1),'Merged semantic aliases require one exact canonical Native anchor, never array-order selection');
    const old=exact[0]||priors[0]||null;
    const overridden=old&&own(catalog.overrides,old.key),entry=old?(overridden?catalog.overrides[old.key]:{message:catalog.messages[old.schemaIndex],...optional('identityJustification',catalog.schemaIdentityJustifications?.[old.schemaIndex])}):null;
    const unit=ensureUnit(next.schemaIndex,old?.schemaIndex??null,entry?.message,{owner:next.owner.semanticId,field:next.owner.fieldPath,context:next.context});
    const fallback=defaultBySchema.get(next.schemaIndex);
    // Every original override stays an explicit override, even when redundant.
    // Merged distinct translations are also explicit, never silently chosen away.
    const needsOverride=!!overridden||unit.messageDisposition==='pending-native-authoring'||fallback.messageDisposition==='pending-native-authoring'||!same(unit.proposedMessage,fallback.proposedMessage);
    const target={kind:needsOverride?'override':'effective-default',key:next.key,storageBindingIndex:next.storageBindingIndex,schemaIndex:next.schemaIndex,sourceSha256:next.sourceSha256,unitId:unit.unitId,...optional('oldKey',old?.key)};
    if(needsOverride)overrideTargets.push(target);
    addTarget(unit,target,old,next,{kind:overridden?'override':old?'effective-default':'new-ui',...optional('oldKey',overridden?old.key:undefined),oldSchemaIndex:old?.schemaIndex??null,message:entry?.message??null,identityJustification:entry?.identityJustification??null});
    if(overridden)oldOverrides.push({oldKey:old.key,newKey:next.key,oldSchemaIndex:old.schemaIndex,newSchemaIndex:next.schemaIndex,entry:catalog.overrides[old.key]});
    // Default identities must be valid even where an override masks the default.
    for(const candidate of [{kind:'default',oldSchemaIndex:fallback.oldSchemaIndex,justification:fallback.oldSchemaIndex===null?undefined:catalog.schemaIdentityJustifications?.[fallback.oldSchemaIndex]},...(needsOverride?[{kind:'override',oldSchemaIndex:old?.schemaIndex,justification:entry?.identityJustification}]:[])]){
      if(!candidate.justification)continue;
      const previous=old&&candidate.oldSchemaIndex===old.schemaIndex?old:null;
      const unchangedScope=previous&&previous.key===next.key&&previous.sourceSha256===next.sourceSha256;
      identityScopes.push({kind:candidate.kind,oldKey:previous?.key??null,newKey:next.key,oldSchemaIndex:candidate.oldSchemaIndex,newSchemaIndex:next.schemaIndex,oldSourceSha256:candidate.oldSchemaIndex===null?null:before.table.schemas[candidate.oldSchemaIndex][0],newSourceSha256:next.sourceSha256,justification:candidate.justification,disposition:unchangedScope?'retain-exact-existing-scope':'review-required-no-authorization',reason:unchangedScope?'Exact locale/key/source approval scope unchanged':'Changed or newly covered binding; old approval does not authorize this scope'});
    }
  }
  // Retain every prior schema default as a variant, including defaults masked
  // by overrides everywhere and defaults that merge into another strong schema.
  const defaultVariants=[];
  for(let oldIndex=0;oldIndex<before.groups.length;oldIndex++){
    const destinations=[...(destinationsByOld.get(oldIndex)||[])].sort((a,b)=>a-b);
    defaultVariants.push({oldSchemaIndex:oldIndex,oldSourceSha256:before.table.schemas[oldIndex][0],message:catalog.messages[oldIndex],identityJustification:catalog.schemaIdentityJustifications?.[oldIndex]??null,newSchemaIndices:destinations});
  }
  const list=[...units.values()].sort((a,b)=>compare(a.unitId,b.unitId));
  const counts={units:list.length,pendingNativeUnits:list.filter(unit=>unit.messageDisposition==='pending-native-authoring').length,pendingDefaultMessages:defaultTargets.filter(target=>units.get(target.unitId).messageDisposition==='pending-native-authoring').length,pendingOverrideMessages:overrideTargets.filter(target=>units.get(target.unitId).messageDisposition==='pending-native-authoring').length,mechanicalPlaceholderRenameUnits:list.filter(unit=>unit.transition.disposition==='mechanical-placeholder-rename').length,identityScopes:identityScopes.length,pendingIdentityScopes:identityScopes.filter(scope=>scope.disposition==='review-required-no-authorization').length,defaults:defaultTargets.length,overrides:overrideTargets.length,originalOverrides:Object.keys(catalog.overrides||{}).length,newUIBindings:lineage.newUI.length};
  const preservedOldOverrideKeys=new Set(oldOverrides.map(override=>override.oldKey));
  assert(preservedOldOverrideKeys.size===Object.keys(catalog.overrides||{}).length,'Original override lineage was dropped');
  counts.preservedOriginalOverrides=preservedOldOverrideKeys.size;
  counts.overrideScopeMoves=oldOverrides.filter(override=>override.oldKey!==override.newKey).length;
  counts.aliasCategories=Object.keys(catalog.aliases||{}).length;
  counts.aliasValues=Object.values(catalog.aliases||{}).reduce((sum,entries)=>sum+Object.values(entries).reduce((n,values)=>n+values.length,0),0);
  counts.aliasesSha256=id(catalog.aliases||{});
  return {schemaVersion:1,format:'auth-lab-l10n-catalog-migration-authoring-packet',locale,parentSourceSetSha256:before.table.sourceSetSha256,sourceSetSha256:after.table.sourceSetSha256,status:'authoring-packet-not-a-catalog',counts,aliases:catalog.aliases||{},defaultTargets,overrideTargets,identityScopes,units:list,oldDefaults,oldOverrides,allPriorSchemaDefaultVariants:defaultVariants,originalSchemaIdentityJustifications:catalog.schemaIdentityJustifications||{}};
}

// Interface for the later all-or-nothing application step, deliberately not an
// implicit fallback writer. Decisions bind exact unit IDs and approval scopes.
const applicationContract={
  mode:'Preparation only; this tool never writes incomplete authored catalogs.',
  reviewedPacket:{schemaVersion:1,locale:'one of the seven exact locales',packetSha256:'SHA256 of the compressed locale packet',messages:{'<unitId>':{message:'string or {plural:{...}}',reviewId:'nonempty Native review evidence ID'}},identityScopes:[{kind:'default|override',newKey:'exact canonical audit key',newSourceSha256:'exact strong SHA',decision:'approved|remove-justification',justification:'compiler identity justification when approved',reviewId:'exact scope review evidence ID'}]},
  applicationRules:[
    'Bind reviewed inputs to packet and source-set hashes; require decisions for every pending-native-authoring unit and every review-required-no-authorization identity scope.',
    'Set messages[newSchemaIndex] from defaultTargets unit messages. Mechanically preserved defaults must remain byte-identical unless an explicit separately reviewed replacement is supplied.',
    'Write every overrideTargets key with its exact new sourceSha256 and resolved unit message. Do not drop redundant original overrides or merged-schema Native variants.',
    'Preserve all alias categories and values exactly. Keep allPriorSchemaDefaultVariants as provenance even when no longer selected as the new default.',
    'Reindex unchanged default schema justifications only if every covered binding retains its exact authorized scope. Otherwise use explicit per-binding justifications and resolve the default justification separately; never promote one binding approval to an entire schema.',
    'Preserve unchanged identity scopes; changed key/hash/default coverage requires explicit review. Emit corresponding exact locale/key/source approval records, not a blanket schema approval.',
    'Validate both defaults and effective overrides with the existing full compileResources compiler and complete source inventory/UI/protected/glossary/approval inputs. Do not bypass default validation or use partial/pilot catalogs.',
    'Only after all seven catalogs and approvals compile without holes, write them atomically into a previously absent external output directory. Never overwrite live catalogs or emit partial catalogs.'
  ]
};
function writePacked(out,name,value){const raw=Buffer.from(stableJson(value)+'\n'),bytes=gzipSync(raw,{level:9});fs.writeFileSync(path.join(out,name),bytes,{flag:'wx'});return {path:name,bytes:bytes.length,sha256:sha256(bytes),decodedBytes:raw.length,decodedSha256:sha256(raw)};}
function writeJson(out,name,value){fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});}
export async function prepareMigration(args){
  const out=path.resolve(args.out),parent=fs.realpathSync(path.dirname(out)),relative=path.relative(fs.realpathSync(root),parent);
  assert(relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative),'Output must be external to repository');
  fs.mkdirSync(out); // Exclusive creation; prior candidates and failures stay immutable.
  const report={schemaVersion:1,format:'auth-lab-l10n-catalog-migration-report',status:'unperformed',usage,scope:'Source lineage and mechanically justified Native preservation only; no Native acceptance, approval, waiver, live catalog or resource emission.',inputs:{},producers:[],artifacts:{},applicationContract};
  try{
    for(const key of ['before','after','before-authoring','after-authoring'])report.inputs[key]=identity(path.resolve(args[key]));
    for(const locale of RESOURCE_SCHEMA.locales)report.inputs['catalog:'+locale]=identity(path.join(path.resolve(args['catalog-dir']),locale+'.json'));
    report.producers=[producer,path.join(path.dirname(producer),'protected.mjs'),path.join(path.dirname(producer),'resources.mjs'),path.join(path.dirname(producer),'source-delta.mjs')].map(identity);
    const before=await readAuthoring(args['before-authoring'],readTable(args.before)),after=await readAuthoring(args['after-authoring'],readTable(args.after));
    const lineage=mapLineage(before,after);
    report.parentSourceSetSha256=before.table.sourceSetSha256;report.sourceSetSha256=after.table.sourceSetSha256;
    report.counts={beforeSchemas:before.groups.length,afterSchemas:after.groups.length,beforeBindings:before.bindings.length,afterBindings:after.bindings.length,mappedOldBindings:lineage.mappedOldBindings,mappingRelations:lineage.mapping.length,additionalTypedVariants:lineage.additionalTypedVariants,convergedOldBindings:lineage.convergedOldBindings,newExplicitUIBindings:lineage.newUI.length,unresolvedLineage:lineage.unresolved.length};
    report.artifacts.lineage=writePacked(out,'migration-plan.json.gz',{schemaVersion:1,format:'auth-lab-l10n-catalog-migration-plan',parentSourceSetSha256:before.table.sourceSetSha256,sourceSetSha256:after.table.sourceSetSha256,beforeSchemas:before.table.schemas,afterSchemas:after.table.schemas,mappings:lineage.mapping.map(row=>({before:bindingRef(before.bindings[row.before]),after:bindingRef(after.bindings[row.after]),evidence:row.evidence})),newExplicitUI:lineage.newUI.map(index=>bindingRef(after.bindings[index])),unresolved:lineage.unresolved,applicationContract});
    assert(!lineage.unresolved.length,'Unresolved source lineage; no per-locale packets generated. See migration-plan.json.gz');
    report.locales={};
    for(const locale of RESOURCE_SCHEMA.locales){
      const catalog=readCatalog(path.join(args['catalog-dir'],locale+'.json'),locale,before),packet=localePacket(locale,catalog,before,after,lineage);
      report.locales[locale]={counts:packet.counts,artifact:writePacked(out,locale+'.authoring-packet.json.gz',packet)};
    }
    report.status='prepared-review-required';
  }catch(error){report.status='failed';report.error={name:error.name,message:error.message,stack:error.stack};}
  const inputs=[...Object.values(report.inputs),...report.producers];
  report.identityRecheck=inputs.map(prior=>{try{const current=identity(prior.path);return {...current,unchanged:same(prior,current)};}catch(error){return {path:prior.path,unchanged:false,error:error.message};}});
  if(report.identityRecheck.some(item=>!item.unchanged)){report.status='failed';report.identityError='Input or producer bytes changed during preparation; artifacts must not be applied';}
  writeJson(out,'migration-summary.json',report);return report;
}
// Application manifests name exact bytes, not mutable directory conventions.
// Every file descriptor is {path,sha256}; paths are relative to the manifest.
export async function applyReviewedMigration(manifestFile,outDirectory){
  const out=path.resolve(outDirectory),parent=fs.realpathSync(path.dirname(out)),relative=path.relative(fs.realpathSync(root),parent);
  assert(relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative),'Output must be external to repository');
  assert(!fs.existsSync(out),'Application output already exists');
  const staging=fs.mkdtempSync(path.join(parent,path.basename(out)+'.application-staging-'));
  const report={schemaVersion:1,format:'auth-lab-l10n-reviewed-application',status:'failed',qualification:'AI correction evidence only; no human, linguistic or publication acceptance',inputs:[],locales:{},producers:[],staging};
  const base=path.dirname(path.resolve(manifestFile)),seen=new Map();
  const load=(descriptor,kind='json')=>{
    assert(object(descriptor)&&typeof descriptor.path==='string'&&digest.test(descriptor.sha256),'Invalid exact-input descriptor');
    const file=fs.realpathSync(path.resolve(base,descriptor.path)),bytes=fs.readFileSync(file);
    assert(sha256(bytes)===descriptor.sha256,'Exact input SHA mismatch: '+file);
    const prior=identity(file);seen.set(file,prior);
    if(kind==='path')return file;
    const text=(file.endsWith('.gz')?gunzipSync(bytes):bytes).toString('utf8');
    return kind==='jsonl'?text.split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line)):JSON.parse(text);
  };
  try{
    const manifestIdentity=identity(path.resolve(manifestFile));seen.set(manifestIdentity.path,manifestIdentity);
    const manifest=JSON.parse(fs.readFileSync(manifestFile,'utf8'));
    assert(manifest.schemaVersion===1&&digest.test(manifest.sourceSetSha256),'Invalid application manifest');
    assert(same(Object.keys(manifest.locales||{}).sort(),RESOURCE_SCHEMA.locales.slice().sort()),'All seven exact locales required');
    report.sourceSetSha256=manifest.sourceSetSha256;
    report.producers=[producer,path.join(path.dirname(producer),'resources.mjs'),path.join(path.dirname(producer),'protected.mjs')].map(identity);
    const before=await readAuthoring(load(manifest.beforeAuthoring,'path'),readTable(load(manifest.before,'path')));
    const after=await readAuthoring(load(manifest.afterAuthoring,'path'),readTable(load(manifest.after,'path')));
    assert(after.table.sourceSetSha256===manifest.sourceSetSha256,'Application source-set mismatch');
    const lineage=mapLineage(before,after);assert(!lineage.unresolved.length,'Unresolved application lineage');
    const approvals=load(manifest.approvals),catalogs={},provenance={};
    assert(Array.isArray(approvals.approvals),'Complete approvals input required');
    const nonempty=value=>typeof value==='string'&&value.trim();
    for(const locale of RESOURCE_SCHEMA.locales){
      const input=manifest.locales[locale],old=readCatalog(load(input.catalog,'path'),locale,before);
      const packet=load(input.packet),expected=localePacket(locale,old,before,after,lineage);
      assert(same(packet,expected),'Packet does not reproduce exact complete migration: '+locale);
      const groups=load(input.groups,'jsonl'),author=load(input.authorDecisions),review=load(input.reviewReceipt);
      for(const document of [author,review]){
        assert(document.locale===locale&&document.sourceSetSha256===manifest.sourceSetSha256&&document.packetSha256===input.packet.sha256&&document.groupsSha256===input.groups.sha256,'Authorship/review input binding mismatch: '+locale);
      }
      assert(nonempty(author.authorId)&&review.authorDecisionsSha256===input.authorDecisions.sha256&&nonempty(review.reviewerId),'Explicit author and independent review identities required: '+locale);
      assert(review.reviewerId!==author.authorId&&review.reviewerId!==author.reviewerId,'Review must be separate from author');
      const groupMap=new Map(groups.map(group=>[group.groupId,group]));
      assert(groupMap.size===groups.length&&groups.length>0,'Duplicate/empty groups');
      assert(same(Object.keys(author.decisions||{}).sort(),[...groupMap.keys()].sort()),'Author must decide every group exactly');
      assert(Array.isArray(review.acceptedGroupIds)&&object(review.corrections),'Incomplete review receipt');
      const reviewed=[...review.acceptedGroupIds,...Object.keys(review.corrections)];
      assert(new Set(reviewed).size===reviewed.length&&same(reviewed.slice().sort(),[...groupMap.keys()].sort()),'Review must cover every group exactly without extras');
      assert(!own(review,'pending')&&!own(review,'rejections')&&!own(review,'rejectedGroupIds'),'Pending or rejected review is not applicable');
      const units=new Map(packet.units.map(unit=>[unit.unitId,unit])),resolved=new Map(),counts={groups:groups.length,acceptedGroups:review.acceptedGroupIds.length,correctedGroups:Object.keys(review.corrections).length,authoredUnits:0,mechanicalUnits:0};
      for(const group of groups){
        const authored=author.decisions[group.groupId],decision=own(review.corrections,group.groupId)?review.corrections[group.groupId]:authored;
        assert(object(decision)&&nonempty(decision.reviewId)&&nonempty(decision.rationale),'Missing exact-group review evidence');
        assert(Array.isArray(group.unitIds)&&group.unitIds.length,'Empty group membership');
        for(const unitId of group.unitIds){
          const unit=units.get(unitId);
          assert(unit&&unit.messageDisposition==='pending-native-authoring'&&!resolved.has(unitId),'Unknown, duplicate or mechanical grouped unit');
          assert(group.newSourceSha256===unit.newSourceSha256&&same(group.newEnglish,unit.newEnglish)&&same(group.newParameters,unit.newParameters)&&same(group.oldNative,unit.oldNative)&&same(group.oldEnglish,unit.oldEnglish)&&same(group.oldParameters,unit.oldParameters),'Group/unit exact witness mismatch');
          validateMessage(decision.message,after.table.schemas[unit.newSchemaIndex],locale);
          resolved.set(unitId,decision.message);counts.authoredUnits++;
        }
      }
      for(const unit of packet.units){
        if(unit.messageDisposition==='pending-native-authoring')assert(resolved.has(unit.unitId),'Missing pending unit decision');
        else{assert(own(unit,'proposedMessage'),'Mechanical proposal missing');resolved.set(unit.unitId,unit.proposedMessage);counts.mechanicalUnits++;}
      }
      const catalog={schemaVersion:2,format:'auth-lab-l10n-authored-catalog',locale,sourceSetSha256:manifest.sourceSetSha256,messages:packet.defaultTargets.map(target=>resolved.get(target.unitId)),overrides:{},schemaIdentityJustifications:{},aliases:JSON.parse(JSON.stringify(packet.aliases))};
      assert(packet.defaultTargets.every((target,index)=>target.schemaIndex===index)&&catalog.messages.length===after.table.schemas.length,'Incomplete defaults');
      for(const target of packet.overrideTargets)catalog.overrides[target.key]={sourceSha256:target.sourceSha256,message:resolved.get(target.unitId)};
      // An existing human approval may only survive its exact previous scope.
      // Structural justification is allowed solely by the compiler's own rule.
      const structural=schema=>Object.values(forms(schema[1])).every(text=>!/\p{L}/u.test(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'')));
      const defaultScopes=new Map(),overrideScopes=new Map(),priorDefaults=new Map(packet.oldDefaults.map(row=>[row.newSchemaIndex,row]));
      for(const scope of packet.identityScopes){
        const index=scope.kind==='default'?defaultScopes:overrideScopes,key=scope.kind==='default'?scope.newSchemaIndex:scope.newKey;
        const entries=index.get(key)||[];entries.push(scope);index.set(key,entries);
      }
      for(const target of packet.defaultTargets){
        const evidence=defaultScopes.get(target.schemaIndex)||[];
        const oldJustification=priorDefaults.get(target.schemaIndex)?.identityJustification;
        if(oldJustification&&oldJustification.kind!=='structural-template'){
          assert(evidence.length===target.scopeStorageBindingIndices.length&&evidence.every(scope=>scope.disposition==='retain-exact-existing-scope'&&same(scope.justification,oldJustification)),'Default approval scope changed; no new approval authorized');
          catalog.schemaIdentityJustifications[target.schemaIndex]=oldJustification;
        }else if(structural(after.table.schemas[target.schemaIndex]))catalog.schemaIdentityJustifications[target.schemaIndex]={kind:'structural-template',sourceSha256:target.sourceSha256};
      }
      for(const target of packet.overrideTargets){
        const scopes=overrideScopes.get(target.key)||[];
        assert(scopes.length<=1,'Ambiguous override identity scope');
        if(scopes.length&&scopes[0].justification.kind!=='structural-template'){assert(scopes[0].disposition==='retain-exact-existing-scope','Override approval scope changed; no new approval authorized');catalog.overrides[target.key].identityJustification=scopes[0].justification;}
        else if(structural(after.table.schemas[target.schemaIndex]))catalog.overrides[target.key].identityJustification={kind:'structural-template',sourceSha256:target.sourceSha256};
      }
      if(input.aliasAdditions){
        const additions=load(input.aliasAdditions),receipt=load(input.aliasReviewReceipt);
        assert(additions.locale===locale&&additions.sourceSetSha256===manifest.sourceSetSha256&&receipt.locale===locale&&receipt.sourceSetSha256===manifest.sourceSetSha256&&receipt.aliasAdditionsSha256===input.aliasAdditions.sha256&&receipt.accepted===true&&nonempty(additions.authorId)&&nonempty(receipt.reviewerId)&&receipt.reviewerId!==additions.authorId,'Unreviewed alias additions');
        assert(object(additions.aliases),'Invalid alias additions');
        for(const [kind,entries] of Object.entries(additions.aliases)){
          assert(object(entries),'Invalid alias category');catalog.aliases[kind]||={};
          for(const [canonical,values] of Object.entries(entries)){
            assert(Array.isArray(values)&&values.every(nonempty),'Invalid alias strings');
            catalog.aliases[kind][canonical]=[...new Set([...(catalog.aliases[kind][canonical]||[]),...values])];
          }
        }
      }
      catalogs[locale]=catalog;report.locales[locale]={...counts,defaults:catalog.messages.length,overrides:Object.keys(catalog.overrides).length,aliasesSha256:id(catalog.aliases),packetSha256:input.packet.sha256,groupsSha256:input.groups.sha256,authorDecisionsSha256:input.authorDecisions.sha256,reviewReceiptSha256:input.reviewReceipt.sha256,reviewerId:review.reviewerId};
      provenance[locale]={allPriorSchemaDefaultVariants:packet.allPriorSchemaDefaultVariants,oldOverrides:packet.oldOverrides,identityScopes:packet.identityScopes};
    }
    const inventory=load(manifest.inventory,'jsonl'),summary=load(manifest.summary),ui=load(manifest.ui),protectedEntries=[...load(manifest.protected,'jsonl'),...load(manifest.uiProtected)],glossary=load(manifest.glossary);
    assert(object(manifest.nativeGlossaries)&&same(Object.keys(manifest.nativeGlossaries).sort(),['en',...RESOURCE_SCHEMA.locales].sort()),'Complete native glossaries required');
    glossary.nativeGlossaries=Object.fromEntries(Object.entries(manifest.nativeGlossaries).map(([locale,descriptor])=>[locale,load(descriptor)]));
    const result=compileResources({inventory,summary,ui,protectedEntries,glossary,approvals,catalogs});
    writeJson(staging,'compiler-report.json',result.report);
    assert(result.report.ok&&result.report.releaseComplete&&result.report.inventoryComplete&&result.report.engineeringComplete,'Full compiler rejected application; see retained compiler-report.json');
    assert(result.report.sourceSetSha256===after.table.sourceSetSha256&&result.report.counts.messages===after.table.bindings.length,'Compiler inventory/source identity mismatch');
    report.inputs=[...seen.values()];
    for(const prior of [...report.inputs,...report.producers])assert(same(identity(prior.path),prior),'Input or producer changed during application: '+prior.path);
    fs.mkdirSync(path.join(staging,'catalogs'));
    for(const [locale,catalog] of Object.entries(catalogs))writeJson(path.join(staging,'catalogs'),locale+'.json',catalog);
    writeJson(staging,'approvals.json',approvals);writePacked(staging,'migration-provenance.json.gz',provenance);
    fs.writeFileSync(path.join(staging,'localization-resources.js'),result.code,{flag:'wx'});
    report.generatedResources={path:'localization-resources.js',bytes:Buffer.byteLength(result.code),sha256:sha256(result.code)};
    report.status='complete-reviewed-application';report.output=out;
    writeJson(staging,'application-report.json',report);
    fs.renameSync(staging,out);return report;
  }catch(error){
    report.inputs=[...seen.values()];report.error={name:error.name,message:error.message,stack:error.stack};
    report.retainedFailure=staging;writeJson(staging,'application-report.json',report);return report;
  }
}

async function main(){
  if(process.argv[2]?.startsWith('--apply-reviewed=')){
    assert(process.argv.length===4&&process.argv[3].startsWith('--out='),'Use --apply-reviewed=EXACT_MANIFEST.json --out=NEW_EXTERNAL_DIRECTORY');
    const report=await applyReviewedMigration(process.argv[2].slice('--apply-reviewed='.length),process.argv[3].slice('--out='.length));
    if(report.status==='failed')process.exitCode=1;
    console.log(JSON.stringify(report));return;
  }
  const args={};for(const argument of process.argv.slice(2)){const match=/^--(before|after|before-authoring|after-authoring|catalog-dir|out)=(.+)$/.exec(argument);assert(match&&!own(args,match[1]),usage);args[match[1]]=path.resolve(match[2]);}
  assert(Object.keys(args).length===6,usage);
  const report=await prepareMigration(args);if(report.status==='failed')process.exitCode=1;
  console.log(JSON.stringify({status:report.status,report:path.join(args.out,'migration-summary.json'),counts:report.counts,locales:Object.fromEntries(Object.entries(report.locales||{}).map(([locale,value])=>[locale,value.counts])),error:report.error?.message}));
}
if(process.argv[1]&&path.resolve(process.argv[1])===producer)main().catch(error=>{console.error(error.stack);process.exitCode=1;});
