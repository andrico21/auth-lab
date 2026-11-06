import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync,gunzipSync} from 'node:zlib';
import {sha256,stableJson,semanticParameters} from './protected.mjs';

export const RESOURCE_SCHEMA={version:2,locales:['ru','uk','he','de','ar-AE','fr','pl','hi','ur','sw','ha','yo','ig','ml','fil','bn','el','es-CO','es-ES','it','pt-PT','pt-BR','sr-Cyrl','sr-Latn','hr'],catalog:'{locale,entries:{[key]:{sourceSha256,message:string|{plural:{category:string}},identityJustification?:{approvalId:string,reason:string}|{kind:"structural-template",sourceSha256:string}}},aliases?:{[kind]:{[canonicalId]:string[]}}}',glossary:'{terms:[{id,source,translations:{[locale]:string},messageKeys?:string[]}]} or --glossary-dir native conceptual glossary files',approvals:'{approvals:[{id,locale,key,sourceSha256,reason,status:"approved"}]}',exports:['LOCALIZATION_BINDINGS','LOCALIZATION_CATALOGS','LOCALIZATION_RESOURCE_METADATA']};
RESOURCE_SCHEMA.compactCatalog='{schemaVersion:2,format:"auth-lab-l10n-authored-catalog",locale,sourceSetSha256,messages:[nativeMessage aligned to English schemas],overrides?:{[canonicalAuditId]:{sourceSha256,message,identityJustification?}},schemaIdentityJustifications?:{[schemaIndex]:identityJustification},aliases?}';
const categories={en:['one','other'],de:['one','other'],he:['one','two','other'],ru:['one','few','many','other'],uk:['one','few','many','other'],pl:['one','few','many','other'],fr:['one','many','other'],'ar-AE':['zero','one','two','few','many','other'],hi:['one','other'],ur:['one','other'],sw:['one','other'],ha:['one','other'],yo:['other'],ig:['other'],ml:['one','other'],fil:['one','other'],bn:['one','other'],el:['one','other'],'es-CO':['one','many','other'],'es-ES':['one','many','other'],it:['one','many','other'],'pt-PT':['one','many','other'],'pt-BR':['one','many','other'],'sr-Cyrl':['one','few','other'],'sr-Latn':['one','few','other'],hr:['one','few','other']};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const same=(a,b)=>stableJson(a)===stableJson(b);
const digest=/^[a-f0-9]{64}$/;
const unsafe=/<[^>]*>|(?<![a-z0-9+.-])(?:[a-z][a-z0-9+.-]*:\/\/|javascript:|(?:data|file):(?=\S)|data:\s*(?:[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+)?(?:;[^\s,]*)*,|file:\s*(?:[/\\]|[a-z]:[/\\]))|\bwww\.|[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/iu;
const counts=text=>{const result={};for(const match of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g))result[match[1]]=(result[match[1]]||0)+1;return result;};
const forms=value=>typeof value==='string'?{source:value}:object(value)&&object(value.plural)?value.plural:null;
// One editorial decision may name several bindings, but each exact scope is authorized separately.
const approvalScope=(id,locale,key,sourceSha256)=>JSON.stringify([id,locale,key,sourceSha256]);
const size=value=>{const json=stableJson(value);return {jsonBytes:Buffer.byteLength(json),gzipBytes:gzipSync(json,{level:9}).length,sha256:sha256(json)};};
function load(file){const raw=fs.readFileSync(file),text=(file.endsWith('.gz')?gunzipSync(raw):raw).toString('utf8');return file.replace(/\.gz$/,'').endsWith('.jsonl')?text.split('\n').filter(Boolean).map(line=>JSON.parse(line)):JSON.parse(text);}
function escapeJS(value){return JSON.stringify(value).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');}

// Audit keys stay in authoring/report data, never in automatic runtime bindings.
const sourceRows=new WeakMap();
/** Default emits no explicit UI keys. Pass their exact iterable as argument two. */
export function encodeSourceTable(messages,explicitUIKeys=[]){
  const sorted=[...messages].sort((a,b)=>a.key<b.key?-1:a.key>b.key?1:0),schemas=new Map();
  for(const message of sorted){
    const schema=[message.sourceSha256,message.english,semanticParameters(message.parameters),counts(typeof message.english==='string'?message.english:message.english.plural.other)];
    if(schemas.has(message.sourceSha256)&&!same(schemas.get(message.sourceSha256),schema))throw new Error('Source schema fingerprint collision: '+message.key);
    schemas.set(message.sourceSha256,schema);
  }
  const table={schemaVersion:2,format:'auth-lab-l10n-source-table',schemas:[...schemas.values()].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0),owners:[...new Set(sorted.map(message=>message.owner.semanticId))].sort(),fields:[...new Set(sorted.map(message=>message.owner.fieldPath))].sort(),contexts:[...new Set(sorted.map(message=>stableJson(message.context||{})))].sort().map(JSON.parse),classifications:[...new Set(sorted.map(message=>message.classification))].sort()};
  const index=values=>new Map(values.map((value,i)=>[value,i])),schemaIndex=index(table.schemas.map(schema=>schema[0])),ownerIndex=index(table.owners),fieldIndex=index(table.fields),contextIndex=index(table.contexts.map(value=>stableJson(value))),classIndex=index(table.classifications);
  const rows=sorted.map(message=>({key:message.key,row:[schemaIndex.get(message.sourceSha256),ownerIndex.get(message.owner.semanticId),fieldIndex.get(message.owner.fieldPath),contextIndex.get(stableJson(message.context||{})),classIndex.get(message.classification)]}));
  rows.sort((a,b)=>{for(let i=0;i<4;i++)if(a.row[i]!==b.row[i])return a.row[i]-b.row[i];return a.key<b.key?-1:a.key>b.key?1:0;});
  table.bindings=rows.map(item=>item.row);
  const byKey=new Map(rows.map((item,i)=>[item.key,i]));
  table.keys=Object.fromEntries([...new Set(explicitUIKeys)].sort().map(key=>{if(!byKey.has(key))throw new Error('Unknown explicit UI key: '+key);return [key,byKey.get(key)];}));
  table.sourceSetSha256=sha256(stableJson(table));
  sourceRows.set(table,rows.map(item=>item.key));
  return table;
}

export function encodeCatalogTable(catalog,sourceTable){
  const keys=sourceRows.get(sourceTable);
  if(!keys)throw new Error('Catalog encoding requires the original encoded source table.');
  const entry=key=>catalogEntry(catalog,key,sourceTable);
  const values=[...new Set(keys.filter(key=>entry(key)!==undefined).map(key=>stableJson(entry(key).message)))].sort(),indices=new Map(values.map((value,index)=>[value,index]));
  const table={schemaVersion:2,format:'auth-lab-l10n-catalog-table',locale:catalog.locale,sourceSetSha256:sourceTable.sourceSetSha256,messages:values.map(JSON.parse),bindings:keys.map(key=>entry(key)!==undefined?indices.get(stableJson(entry(key).message)):-1)};
  const identityJustifications={};
  keys.forEach((key,bindingIndex)=>{const authored=entry(key)?.identityJustification;if(authored)identityJustifications[bindingIndex]=authored.kind==='structural-template'?{kind:'structural-template',sourceSha256:authored.sourceSha256}:{approvalId:authored.approvalId,reason:authored.reason};});
  if(Object.keys(identityJustifications).length)table.identityJustifications=identityJustifications;
  if(catalog.aliases)table.aliases=catalog.aliases;
  return table;
}

// Authored messages align to strong English schemas, not English text equality.
// Overrides remain canonical audit-key entries, including their source digest.
// Schema identities are checked against every semantic binding they cover;
// approved identities therefore still require exact locale/key/source approval.
const authoredFormat='auth-lab-l10n-authored-catalog';
const compact=catalog=>catalog?.format===authoredFormat;
const sourceKeyIndices=new WeakMap();
function catalogEntry(catalog,key,table){
  if(!compact(catalog))return catalog?.entries?.[key];
  let indices=sourceKeyIndices.get(table);
  if(!indices){indices=new Map(sourceRows.get(table).map((key,i)=>[key,i]));sourceKeyIndices.set(table,indices);}
  if(Object.hasOwn(catalog.overrides||{},key))return catalog.overrides[key];
  const binding=indices.get(key),schema=table.bindings[binding]?.[0];
  if(schema===undefined||!Object.hasOwn(catalog.messages||[],schema))return undefined;
  return {sourceSha256:table.schemas[schema][0],message:catalog.messages[schema],...(Object.hasOwn(catalog.schemaIdentityJustifications||{},schema)?{identityJustification:catalog.schemaIdentityJustifications[schema]}:{})};
}

// Encoded strings remain compressed until the runtime prepares a target locale.
// Module evaluation performs neither decompression nor JSON parsing.
function generatedModule(bindings,payloads,metadata){
  const pack=text=>'gzip:'+gzipSync(text,{level:9}).toString('base64');
  const packed=Object.fromEntries(Object.entries(payloads).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([locale,text])=>[locale,pack(text)]));
  const encodedMetadata={...metadata,resourceEncoding:'gzip-base64',resourcePrefix:'gzip:',decodePolicy:'lazy-source-and-target-preparation',moduleLoadDecoding:false};
  return '// Generated by tools/verification/localization/resources.mjs. Do not edit.\n'
    +'export const LOCALIZATION_BINDINGS = '+escapeJS(pack(stableJson(bindings)))+';\n'
    +'export const LOCALIZATION_CATALOGS = Object.freeze('+escapeJS(packed)+');\n'
    +'export const LOCALIZATION_RESOURCE_METADATA = Object.freeze('+stableJson(encodedMetadata)+');\n';
}

/** Pure validation/generation entry point. Occurrence maps never enter payloads. */
export function compileResources({inventory,ui,catalogs,locales=RESOURCE_SCHEMA.locales,pilot=false,pilotPartialCatalogs=false,summary,protectedEntries=[],glossary={terms:[]},approvals={approvals:[]}}){
  const errors=[],warnings=[],omittedMessages=[],fail=(code,details={})=>errors.push({code,...details}),incomplete=(code,details={})=>(pilot?warnings:errors).push({code,...details});
  if(pilotPartialCatalogs&&!pilot)fail('partial-catalogs-require-explicit-pilot');
  if(!Array.isArray(inventory)||!inventory.length)fail('inventory-missing-or-empty');
  if(!object(ui)||!Array.isArray(ui.messages)||!Array.isArray(ui.occurrences)||!Array.isArray(ui.unresolved))fail('ui-contract-schema');
  if(ui?.unresolved?.length)incomplete('unresolved-ui-contracts',{count:ui.unresolved.length,omittedContracts:ui.unresolved});
  if(ui?.summary?.complete!==true||!Array.isArray(ui?.residual)||ui.residual.length)incomplete('ui-completeness-unproven',{complete:ui?.summary?.complete,residualCount:ui?.residual?.length});
  if(!summary)fail('inventory-summary-required');
  for(const [name,value] of Object.entries(summary?.unresolved||{}))if(typeof value==='number'&&value>0)incomplete('unresolved-inventory-contracts',{name,count:value});
  if(summary?.counts?.unclassifiedGeneratedStrings>0)incomplete('unclassified-generated-strings',{count:summary.counts.unclassifiedGeneratedStrings});
  if(!Array.isArray(locales)||!locales.length||new Set(locales).size!==locales.length||locales.some(locale=>!RESOURCE_SCHEMA.locales.includes(locale)))fail('locale-set-invalid');
  if(!pilot&&!same([...locales].sort(),[...RESOURCE_SCHEMA.locales].sort()))fail('release-requires-all-locales');
  const messages=new Map(),ownerSlots=new Map(),registry=new Map();
  const uiOccurrences=new Map(),uiSourceFiles=new Map((ui?.sourceFiles||[]).map(file=>[file.module,file.sourceSha256]));
  for(const occurrence of ui?.occurrences||[]){const list=uiOccurrences.get(occurrence.messageKey)||[];list.push(occurrence);uiOccurrences.set(occurrence.messageKey,list);}
  const dynamicBound=(message,reference)=>{
    const definition=message.parameters[reference.parameter],sites=uiOccurrences.get(message.key)||[];
    if(!reference.dynamic||!definition?.dynamic||!['protected','source','exact'].includes(definition.kind)||reference.kind!==definition.kind||typeof definition.sourcePath!=='string'||!sites.length)return false;
    const branch=forms(message.english)?.[reference.form||'source'];
    if(typeof branch!=='string'||counts(branch)[reference.parameter]!==reference.occurrences)return false;
    let definitionBound=false;
    for(const site of sites){
      const parameter=site.parameters?.[reference.parameter];
      if(typeof parameter?.source!=='string'||!parameter.source||parameter.sourceSha256!==sha256(parameter.source)||!digest.test(site.callSha256||'')||!digest.test(site.sourceFileSha256||'')||uiSourceFiles.get(site.module)!==site.sourceFileSha256||!Number.isInteger(site.start)||!Number.isInteger(site.end)||site.start<0||site.end<=site.start||typeof site.referenceEnglishSource!=='string'||site.referenceSha256!==sha256(site.referenceEnglishSource))return false;
      if(parameter.source===definition.sourcePath)definitionBound=true;
    }
    return definitionBound;
  };
  for(const entry of [...protectedEntries,...(Array.isArray(ui?.protectedReferences)?ui.protectedReferences:[])]){if(!object(entry)||typeof entry.id!=='string'||typeof entry.value!=='string'||entry.sourceSha256!==sha256(entry.value)){fail('protected-registry-entry-invalid',{id:entry?.id});continue;}const prior=registry.get(entry.id);if(prior&&['kind','semanticId','fieldPath','value','sourceSha256'].some(field=>!same(prior[field],entry[field])))fail('protected-registry-collision',{id:entry.id});registry.set(entry.id,entry);}
  for(const message of [...(Array.isArray(inventory)?inventory:[]),...(ui?.messages||[])]){
    const key=message?.key;
    if(message?.classification==='ambiguous'||message?.sourceBinding==='unresolved'||message?.source?.module?.startsWith('<unresolved')){
      const omission={key,classification:message.classification,sourceBinding:message.sourceBinding,source:message.source};
      if(pilot){if(!omittedMessages.some(message=>message.key===key))omittedMessages.push(omission);continue;}fail('unresolved-message-contract',omission);continue;
    }
    if(!object(message)||typeof key!=='string'||!key||!object(message.parameters)||!object(message.owner)||typeof message.owner.semanticId!=='string'||typeof message.owner.fieldPath!=='string'||!object(message.context)||!['prose','human','human-only','mixed','protected-only'].includes(message.classification)){fail('message-schema',{key});continue;}
    const branches=forms(message.english);
    if(!branches||Object.values(branches).some(text=>typeof text!=='string')||(typeof message.english!=='string'&&!same(Object.keys(branches).sort(),['one','other']))) {fail('english-forms-invalid',{key});continue;}
    if(typeof message.english!=='string'&&message.parameters.count?.kind!=='count')fail('plural-selector-required',{key});
    const fingerprint=sha256(stableJson({english:message.english,parameters:semanticParameters(message.parameters)}));
    if(!digest.test(message.sourceSha256||'')||message.sourceSha256!==fingerprint)fail('source-fingerprint-mismatch',{key,expected:fingerprint,actual:message.sourceSha256});
    if(message.exactEnglishSourceSha256&&typeof message.exactEnglish==='string'&&sha256(message.exactEnglish)!==message.exactEnglishSourceSha256)fail('exact-english-fingerprint-mismatch',{key});
    let expected;
    for(const [branch,text] of Object.entries(branches)){
      const found=counts(text),rendered=Object.keys(message.parameters).filter(name=>!(message.parameters[name].kind==='count'&&message.parameters[name].role==='selector'&&!Object.hasOwn(found,name)));if(!same(Object.keys(found).sort(),rendered.sort()))fail('english-parameter-names',{key,branch,found});
      if(expected&&!same(found,expected))fail('english-branch-placeholder-counts',{key,branch});expected=found;
      if(unsafe.test(text))fail('unsafe-english-template',{key,branch});
      if(/[{}]/.test(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'')))fail('malformed-placeholder',{key,branch});
    }
    for(const [name,definition] of Object.entries(message.parameters)){
      if(!object(definition)||!['human','protected','source','exact','count'].includes(definition.kind))fail('parameter-type-invalid',{key,name});
      if(definition.role==='selector'&&(definition.kind!=='count'||name!=='count'||typeof message.english==='string'))fail('invalid-plural-selector',{key,name});
      if(definition.kind==='human'&&Object.hasOwn(definition,'value')&&!object(definition.value))fail('raw-human-parameter',{key,name});
    }
    for(const reference of message.protectedReferences||[]){
      const definition=message.parameters[reference.parameter],entry=registry.get(reference.registryId);
      if(reference.registryId){if(!entry||!definition||!Object.hasOwn(definition,'value')||String(definition.value)!==entry.value)fail('dangling-protected-reference',{key,registryId:reference.registryId,parameter:reference.parameter});}
      else if(!dynamicBound(message,reference))fail('unbound-dynamic-protected-reference',{key,parameter:reference.parameter});
    }
    if(message.sourceBinding==='unresolved'||message.source?.module?.startsWith('<unresolved'))fail('unresolved-owner-binding',{key});
    if(messages.has(key)){if(!same(messages.get(key),message))fail('message-key-collision',{key});continue;}
    messages.set(key,message);
    const slot=stableJson({owner:message.owner.semanticId,field:message.owner.fieldPath,context:message.context,sourceSha256:message.sourceSha256,english:message.english,parameters:semanticParameters(message.parameters)});
    if(ownerSlots.has(slot)&&ownerSlots.get(slot)!==key)fail('owner-binding-collision',{key,previous:ownerSlots.get(slot)});else ownerSlots.set(slot,key);
  }
  const omittedKeys=new Set(omittedMessages.map(message=>message.key));
  for(const occurrence of ui?.occurrences||[])if(!messages.has(occurrence.messageKey)&&!omittedKeys.has(occurrence.messageKey))fail('dangling-ui-occurrence',{id:occurrence.id,key:occurrence.messageKey});
  const approvalMap=new Map();
  if(!Array.isArray(approvals.approvals))fail('approval-schema');
  for(const approval of approvals.approvals||[]){const scope=approvalScope(approval.id,approval.locale,approval.key,approval.sourceSha256);if(!approval.id||approvalMap.has(scope))fail('approval-id-invalid',{id:approval.id,locale:approval.locale,key:approval.key,sourceSha256:approval.sourceSha256});approvalMap.set(scope,approval);}
  const bindings=encodeSourceTable([...messages.values()],(ui?.messages||[]).map(message=>message.key).filter(key=>messages.has(key)));
  const coverage={},payloads={};
  for(const locale of locales){
    const catalog=catalogs?.[locale],before=errors.length;
    coverage[locale]={required:messages.size,present:0,valid:0,missing:[],extra:[],identicalJustified:0,structuralIdentities:0,protectedIdentities:0,translatedProse:0};
    const cov=coverage[locale];
    if(!object(catalog)||catalog.locale!==locale||(!compact(catalog)&&!object(catalog.entries))){fail('catalog-missing-or-invalid',{locale});cov.missing=[...messages.keys()].sort();continue;}
    if(compact(catalog)){
      if(catalog.schemaVersion!==2||catalog.sourceSetSha256!==bindings.sourceSetSha256||!Array.isArray(catalog.messages)||catalog.messages.length!==bindings.schemas.length||Object.hasOwn(catalog,'entries'))fail('compact-catalog-schema-or-source',{locale});
      if(catalog.overrides!==undefined&&!object(catalog.overrides))fail('compact-overrides-schema',{locale});
      if(catalog.schemaIdentityJustifications!==undefined&&!object(catalog.schemaIdentityJustifications))fail('compact-identity-schema',{locale});
      for(const index of Object.keys(catalog.schemaIdentityJustifications||{}))if(!/^(0|[1-9][0-9]*)$/.test(index)||Number(index)>=bindings.schemas.length)fail('compact-identity-index',{locale,index});
      // Validate every schema, including schemas whose bindings all have overrides.
      for(let index=0;index<bindings.schemas.length;index++)if(!Object.hasOwn(catalog.messages||[],index))fail('compact-schema-message-missing',{locale,index});
    }
    for(const key of Object.keys(compact(catalog)?catalog.overrides||{}:catalog.entries))if(!messages.has(key)){cov.extra.push(key);fail('catalog-extra-key',{locale,key});}
    for(const [key,source] of messages){
      const effective=catalogEntry(catalog,key,bindings),start=errors.length;
      const present=compact(catalog)?Object.hasOwn(catalog.overrides||{},key)||Object.hasOwn(catalog.messages||[],bindings.bindings[sourceKeyIndices.get(bindings)?.get(key)]?.[0]):Object.hasOwn(catalog.entries,key);
      if(!present){cov.missing.push(key);(pilot&&pilotPartialCatalogs&&!compact(catalog)?warnings:errors).push({code:'catalog-entry-missing',locale,key});continue;}cov.present++;
      const candidates=[effective];
      if(compact(catalog)&&Object.hasOwn(catalog.overrides||{},key)){
        const schema=bindings.bindings[sourceKeyIndices.get(bindings)?.get(key)]?.[0];
        candidates.unshift({sourceSha256:source.sourceSha256,message:catalog.messages?.[schema],...(Object.hasOwn(catalog.schemaIdentityJustifications||{},schema)?{identityJustification:catalog.schemaIdentityJustifications[schema]}:{})});
      }
      for(const entry of candidates){
      if(!object(entry)){fail('catalog-entry-invalid',{locale,key});continue;}
      if(entry.sourceSha256!==source.sourceSha256)fail('catalog-source-fingerprint',{locale,key,expected:source.sourceSha256,actual:entry.sourceSha256});
      const translated=forms(entry.message),english=forms(source.english),plural=typeof source.english!=='string';
      const structural=Object.values(english).every(text=>!/\p{L}/u.test(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'')));
      const justification=entry.identityJustification,approval=justification?.approvalId?approvalMap.get(approvalScope(justification.approvalId,locale,key,source.sourceSha256)):undefined,structuralApproved=object(justification)&&structural&&justification.kind==='structural-template'&&justification.sourceSha256===source.sourceSha256,approvalApproved=object(justification)&&typeof justification.approvalId==='string'&&justification.approvalId.trim()&&typeof justification.reason==='string'&&justification.reason.trim()&&approval?.status==='approved'&&approval.locale===locale&&approval.key===key&&approval.sourceSha256===source.sourceSha256&&approval.reason===justification.reason;
      if(Object.hasOwn(entry,'identityJustification')&&!structuralApproved&&!approvalApproved)fail('invalid-identity-justification',{locale,key});
      if(!translated||plural!==(typeof entry.message!=='string')||!same(Object.keys(translated||{}).sort(),(plural?categories[locale]:['source']).slice().sort())){fail('catalog-plural-categories',{locale,key,expected:plural?categories[locale]:['source']});continue;}
      for(const [branch,text] of Object.entries(translated)){
        if(typeof text!=='string'||!text.trim()){fail('catalog-empty-branch',{locale,key,branch});continue;}
        if(unsafe.test(text))fail('catalog-prohibited-content',{locale,key,branch});
        if(/[{}]/.test(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'')))fail('catalog-malformed-placeholder',{locale,key,branch});
        if(!same(counts(text),counts(Object.values(english)[0])))fail('catalog-placeholder-contract',{locale,key,branch,expected:counts(Object.values(english)[0]),actual:counts(text)});
        if(Object.values(english).includes(text)&&source.classification!=='protected-only'){
          if(!structuralApproved&&!approvalApproved)fail('unapproved-identical-english',{locale,key,branch});
          else if(approvalApproved&&entry===effective)cov.identicalJustified++;
        }
      }
      if(entry===effective&&start===errors.length){cov.valid++;if(source.classification==='protected-only')cov.protectedIdentities++;else if(structural)cov.structuralIdentities++;else cov.translatedProse++;}
      }
    }
    const aliases=catalog.aliases||{};
    if(!object(aliases))fail('alias-schema',{locale});
    else for(const [kind,entries] of Object.entries(aliases)){
      const prefix=({field:'field:',actor:'actor:',topic:'topic:',workspace:'workspace-option:','workspace-option':'workspace-option:',lesson:'lesson:',scenario:'lesson:'})[kind];
      if(!prefix||!object(entries)){fail('alias-kind-schema',{locale,kind});continue;}
      for(const [id,values] of Object.entries(entries)){
        if(![...messages.values()].some(message=>message.owner.semanticId===prefix+id)&&![...registry.values()].some(entry=>entry.semanticId===prefix+id))fail('alias-unknown-canonical-id',{locale,kind,id});
        if(!Array.isArray(values)||!values.length||values.some(value=>typeof value!=='string'||!value.trim()||unsafe.test(value))||new Set(values.map(value=>typeof value==='string'?value.normalize('NFC').toLocaleLowerCase(locale):value)).size!==values.length)fail('alias-values-invalid',{locale,kind,id});
      }
    }
    payloads[locale]=stableJson(catalog);cov.errors=errors.length-before;cov.sizing=size(catalog);
  }
  const termIds=new Set();
  if(!Array.isArray(glossary.terms))fail('glossary-schema');
  for(const term of glossary.terms||[]){
    if(!term.id||termIds.has(term.id)||typeof term.source!=='string'||!object(term.translations)){fail('glossary-term-schema',{id:term.id});continue;}termIds.add(term.id);
    for(const key of term.messageKeys||[])if(!messages.has(key))fail('glossary-dangling-message',{id:term.id,key});
    for(const locale of locales){const translated=term.translations[locale];if(typeof translated!=='string'||!translated.trim()||unsafe.test(translated)){fail('glossary-translation-invalid',{id:term.id,locale});continue;}
      for(const key of term.messageKeys||[])for(const text of Object.values(forms(catalogEntry(catalogs?.[locale],key,bindings)?.message)||{}))if(!text.includes(translated))fail('glossary-usage-mismatch',{id:term.id,locale,key});
    }
  }
  if(glossary.nativeGlossaries){
    const canonical=glossary.nativeGlossaries.en;
    if(!object(canonical?.concepts)||!Object.keys(canonical.concepts).length)fail('native-glossary-canonical-missing');
    for(const locale of ['en',...locales]){
      const native=glossary.nativeGlossaries[locale];
      if(native?.schemaVersion!==1||native.locale!==locale||!object(native.concepts)||!same(Object.keys(native.concepts||{}).sort(),Object.keys(canonical?.concepts||{}).sort())){fail('native-glossary-schema',{locale});continue;}
      for(const [id,concept] of Object.entries(native.concepts)){
        const source=canonical.concepts[id];
        if(concept.englishTerm!==source.englishTerm||concept.englishDefinition!==source.englishDefinition||!same(concept.literalForms,source.literalForms))fail('native-glossary-source-mismatch',{locale,id});
        for(const field of ['term','definition'])if(typeof concept.conceptualProse?.[field]!=='string'||!concept.conceptualProse[field].trim()||unsafe.test(concept.conceptualProse[field]))fail('native-glossary-prose-invalid',{locale,id,field});
      }
    }
  }
  const runtimeMessages=[...messages.values()].sort((a,b)=>a.key<b.key?-1:a.key>b.key?1:0).map(message=>{
    const result={key:message.key,english:message.english,sourceSha256:message.sourceSha256,parameters:semanticParameters(message.parameters),owner:{semanticId:message.owner.semanticId,fieldPath:message.owner.fieldPath},context:message.context,classification:message.classification};
    result.placeholderCounts=counts(typeof message.english==='string'?message.english:message.english.plural.other);
    return result;
  });
  const sourceSetSha256=bindings.sourceSetSha256,plainBindings={messages:runtimeMessages},plainPayloads={...payloads};
  if(!errors.length)for(const locale of locales)payloads[locale]=stableJson(encodeCatalogTable(catalogs[locale],bindings));
  const report={schemaVersion:1,ok:errors.length===0,mode:pilot?'pilot-partial':'release',releaseComplete:!pilot&&errors.length===0,locales:[...locales].sort(),omittedLocales:RESOURCE_SCHEMA.locales.filter(locale=>!locales.includes(locale)),sourceSetSha256,counts:{messages:messages.size,uiOccurrences:ui?.occurrences?.length||0,protectedEntries:registry.size,glossaryTerms:termIds.size},coverage,errors,warnings,sizing:{plainBindings:size(plainBindings),bindings:size(bindings),plainCatalogs:size(plainPayloads),catalogs:size(payloads),encoding:'Version 2 schema-grouped semantic binding tables; deterministic standard gzip/base64; browser-native decompression to serialized strings only, without inactive catalog parsing.'}};
  report.authoringMapping={sourceSetSha256,canonicalAuditIds:sourceRows.get(bindings)};
  report.omittedMessages=omittedMessages;
  report.inventoryComplete=errors.length===0&&warnings.length===0&&omittedMessages.length===0;
  report.counts.omittedMessages=omittedMessages.length;
  report.engineeringComplete=!pilot&&report.inventoryComplete&&Object.values(coverage).every(item=>item.missing.length===0);
  report.pilotPartialCatalogs=pilotPartialCatalogs;
  const metadata={schemaVersion:1,mode:report.mode,locales:report.locales,sourceSetSha256,inventoryComplete:report.inventoryComplete,engineeringComplete:report.engineeringComplete,pilotPartialCatalogs,missingEntries:Object.fromEntries(Object.entries(coverage).map(([locale,item])=>[locale,item.missing.length])),omittedMessages:omittedMessages.length,releaseComplete:report.releaseComplete};
  const code=errors.length?null:generatedModule(bindings,payloads,metadata);
  if(code)report.sizing.generated={bytes:Buffer.byteLength(code),gzipBytes:gzipSync(code,{level:9}).length,sha256:sha256(code)};
  if(code)report.sizing.compressedResources=Object.fromEntries([['en',stableJson(bindings)],...Object.entries(payloads)].map(([locale,text])=>{const compressed=gzipSync(text,{level:9});return [locale,{rawBytes:Buffer.byteLength(text),gzipBytes:compressed.length,base64Bytes:Buffer.byteLength(compressed.toString('base64'))}];}));
  return {report,code};
}

export function runCLI(args=process.argv.slice(2)){
  const options={},catalogFiles={};
  for(let index=0;index<args.length;index++){
    const flag=args[index];
    if(flag==='--help'){console.log('resources.mjs --inventory DIR --ui FILE --catalog-dir DIR --report FILE [--out FILE] [--pilot de,he [--pilot-partial-catalogs]] [--glossary-dir DIR] [--approvals FILE]\nDefault release requires every configured native catalog. Partial catalogs require explicit pilot; absent entries use -1 fallback indices and engineeringComplete:false.');return 0;}
    if(flag==='--pilot-partial-catalogs'){if(options[flag])throw new Error('Repeated option: '+flag);options[flag]=true;continue;}
    if(!['--inventory','--ui','--ui-protected','--catalog-dir','--report','--out','--pilot','--glossary','--glossary-dir','--approvals'].includes(flag)||!args[index+1]||args[index+1].startsWith('--')||Object.hasOwn(options,flag))throw new Error('Unknown, repeated, or valueless option: '+flag);
    options[flag]=args[++index];
  }
  if(!options['--report'])throw new Error('--report is required for machine-readable failures.');
  let result;
  try{
    for(const flag of ['--inventory','--ui','--catalog-dir'])if(!options[flag])throw new Error(flag+' is required.');
    const directory=options['--inventory'],locales=options['--pilot']?options['--pilot'].split(','):RESOURCE_SCHEMA.locales;
    for(const locale of locales){const filename=path.join(options['--catalog-dir'],locale+'.json');if(fs.existsSync(filename))catalogFiles[locale]=load(filename);}
    const uiProtected=options['--ui-protected']||path.join(path.dirname(options['--ui']),'protected-references.json');
    const ui=load(options['--ui']),uiRegistry=options['--ui-protected']||!Array.isArray(ui.protectedReferences)?load(uiProtected):[];
    const glossary=options['--glossary']?load(options['--glossary']):{terms:[]};
    if(options['--glossary-dir']){
      glossary.nativeGlossaries=Object.fromEntries(['en',...locales].map(locale=>[locale,load(path.join(options['--glossary-dir'],locale+'.json'))]));
    }
    result=compileResources({inventory:load(path.join(directory,'runtime-bindings.jsonl.gz')),summary:load(path.join(directory,'summary.json')),protectedEntries:[...load(path.join(directory,'protected.jsonl.gz')),...uiRegistry],ui,catalogs:catalogFiles,locales,pilot:Object.hasOwn(options,'--pilot'),pilotPartialCatalogs:options['--pilot-partial-catalogs']===true,glossary,...(options['--approvals']?{approvals:load(options['--approvals'])}:{})});
  }catch(error){result={report:{schemaVersion:1,ok:false,mode:options['--pilot']?'pilot-partial':'release',releaseComplete:false,errors:[{code:'input-load-or-schema-error',message:error.message}]},code:null};}
  if(result.code&&options['--out']){fs.mkdirSync(path.dirname(path.resolve(options['--out'])),{recursive:true});fs.writeFileSync(options['--out'],result.code);}
  fs.mkdirSync(path.dirname(path.resolve(options['--report'])),{recursive:true});fs.writeFileSync(options['--report'],stableJson(result.report)+'\n');console.log(stableJson(result.report));return result.report.ok?0:1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))try{process.exitCode=runCLI();}catch(error){console.error(error.message);process.exitCode=1;}
