import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {gzipSync,createGunzip} from 'node:zlib';
import {createInterface} from 'node:readline';
import {parse} from 'acorn';
import * as walk from 'acorn-walk';
import {parseFragment} from 'parse5';
import {ProtectedRegistry,sha256,stableJson,semanticParameters,PROTECTED_FIELDS,SOURCE_CITATION_FIELDS} from './protected.mjs';
import {compactEnumerate,compactEncode} from '../compact-view-fixtures.mjs';

const ownRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const COLLECTOR_FILES=['inventory.mjs','protected.mjs'].map(name=>({module:'tools/verification/localization/'+name,sourceSha256:sha256(fs.readFileSync(path.join(ownRoot,'tools/verification/localization',name)))}));
const HUMAN_FIELDS=new Set(['title','label','summary','detail','details','description','meaning','origin','generator','purpose','plainRole','notes','learningObjective','supportNote','learningQuestion','question','implementation','completion','startingSummary','assumptions','prerequisites','explanation','rationale','reason','checks','beginnerSummary','protocolDetail','cryptoDetail','protection','parentDecision','chapterCaption','decisionPanelLabel','evidenceLabel','boundary','mechanism','text','note','caption','searchTags','searchVariants','keywords','verdictExplanation']);
const STATIC_MODULES=['src/protocol-data.js','src/lab-catalog.js','src/attribute-usage.js','src/architecture-variants.js','src/fido-direct.js','src/workspaces.js','src/learning-presets.js','src/runtime-environment.js','src/scenario-search-metadata.js','src/windows-security-comparisons.js','src/dnssec-lessons.js'];
const GENERATED_MODULES=new Set(['src/app.js','src/compact-view.js','src/held-object-view.js','src/held-study-projection.js','src/held-study-state.js','src/held-object-state.js','src/attribute-trace.js','src/scenario-picker.js','src/runtime-environment.js','src/scenario-context.js']);
const bytes=text=>Buffer.byteLength(text);
const importAt=(root,name)=>import(pathToFileURL(path.join(root,name)).href);
const propertyName=node=>node?.type==='Identifier'?node.name:node?.value;
const declarationField=entry=>entry.fieldPath?.startsWith(entry.semanticId+'.')?entry.fieldPath.slice(entry.semanticId.length+1):entry.fieldPath;
const literal=node=>node?.type==='Literal'&&typeof node.value==='string'?node.value:node?.type==='TemplateLiteral'&&!node.expressions.length?node.quasis[0].value.cooked:null;
const NOTE_BINDINGS_BY_FINGERPRINT=new Map([
  ['a3130b3be6249261d5d203b3a9eaf10efdf8422420190d99740b07555228db9c','one-authenticator-per-attempt'],
  ['b3bf45f2a2a6a93b6fcd6c89e6c73b8f7e3f7e41506a46c5c756f1ce586eade1','sessions-can-shorten-sign-in'],
  ['08bdf93789e3e31272b5d228ba503acc63cb95cad172ec3f5a53eb0192dc80cf','configured-passkey-totp-flow'],
  ['d062aee334999005bb35876a0907ce38c96e3f7bb641b77253718d6ee4a10678','totp-phishing-boundary'],
]);

// Frozen inputs deliberately omit verification tools. Reuse the existing fixture
// helper, rebinding its parsed relative imports to the requested immutable root.
// No source file is rewritten and no mutable renderer is imported.
async function baselineRegistry(root,index=null){
  const helperPath=path.join(ownRoot,'tools/verification/held-object-fixtures.mjs');
  let source=fs.readFileSync(helperPath,'utf8');
  const ast=parse(source,{ecmaVersion:'latest',sourceType:'module'}),imports=[];
  walk.simple(ast,{ImportDeclaration(node){imports.push(node.source);},ImportExpression(node){if(literal(node.source)!==null)imports.push(node.source);}});
  for(const node of imports.sort((a,b)=>b.start-a.start)){
    const specifier=literal(node);
    if(!specifier?.startsWith('../../'))throw new Error('Unexpected fixture import: '+specifier);
    source=source.slice(0,node.start)+JSON.stringify(pathToFileURL(path.join(root,specifier.slice(6))).href)+source.slice(node.end);
  }
  const helper=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
  const catalog=await importAt(root,'src/lab-catalog.js'),catalogSource=fs.readFileSync(path.join(root,'src/lab-catalog.js'),'utf8'),catalogAst=parse(catalogSource,{ecmaVersion:'latest',sourceType:'module'}),importedNames=new Map(),descriptors=[],declarations={models:new Map(),fields:new Map()};
  walk.simple(catalogAst,{
    ImportDeclaration(node){for(const specifier of node.specifiers)if(specifier.type==='ImportSpecifier')importedNames.set(specifier.local.name,specifier.imported.name);},
    ObjectExpression(node){
      const properties=new Map(node.properties.filter(property=>property.type==='Property').map(property=>[propertyName(property.key),property.value])),module=literal(properties.get('source'));
      if(module?.startsWith('src/')&&properties.get('scenarios')?.type==='Identifier'&&properties.get('attributes')?.type==='Identifier')descriptors.push({module,models:properties.get('scenarios').name,fields:properties.get('attributes').name});
    }
  });
  for(const descriptor of descriptors){
    const namespace=await importAt(root,descriptor.module),sourceFileSha256=index?.files.get(descriptor.module)?.sourceSha256||sha256(fs.readFileSync(path.join(root,descriptor.module)));
    const modelExport=importedNames.get(descriptor.models)||descriptor.models,fieldExport=importedNames.get(descriptor.fields)||descriptor.fields;
    for(const model of namespace[modelExport]||[])declarations.models.set(model.id,{module:descriptor.module,export:modelExport,sourceFileSha256});
    for(const id of Object.keys(namespace[fieldExport]||{}))declarations.fields.set(id,{module:descriptor.module,export:fieldExport,sourceFileSha256});
  }
  return {root,...await importAt(root,'src/learning-presets.js'),...catalog,...helper,declarations,fixtureHelper:{module:'tools/verification/held-object-fixtures.mjs',sourceSha256:sha256(fs.readFileSync(helperPath))}};
}

// A cheap, explicitly partial first sizing, before realizing case branches.
// Counts use semantic field owners, not a global English-string deduplication.
export async function registeredDefinitionSizing(root){
  root=fs.realpathSync(root);
  const registry=await baselineRegistry(root),protocol=await importAt(root,'src/protocol-data.js');
  const definitions={...protocol.ATTRIBUTES,...registry.LAB_ATTRIBUTES},fields={},sources=new Set();let words=0;
  for(const [id,definition] of Object.entries(definitions))for(const field of ['meaning','origin','purpose']){
    const english=definition[field];if(typeof english!=='string'||!english)continue;
    fields[field]||={units:0,englishBytes:0};fields[field].units++;fields[field].englishBytes+=bytes(english);
    words+=(english.match(/[\p{L}\p{N}]+/gu)||[]).length;sources.add(sha256(english));
  }
  return {root,scope:'Registered field meaning/origin/purpose only; excludes all case overrides, aliases, scenario/step/actor/held/generated/UI prose. Not the complete inventory.',definitions:Object.keys(definitions).length,messageUnits:Object.values(fields).reduce((n,f)=>n+f.units,0),englishBytes:Object.values(fields).reduce((n,f)=>n+f.englishBytes,0),words,distinctExactEnglishStrings:sources.size,fields,fixtureHelper:registry.fixtureHelper};
}

class JsonlGzip {
  constructor(filename){this.filename=filename;this.buffer=[];this.bufferBytes=0;this.rawBytes=0;this.count=0;fs.writeFileSync(filename,'',{flag:'wx'});}
  add(value){const line=JSON.stringify(value)+'\n';this.buffer.push(line);this.bufferBytes+=bytes(line);this.rawBytes+=bytes(line);this.count++;if(this.bufferBytes>=1024*1024)this.flush();}
  flush(){if(this.buffer.length)fs.appendFileSync(this.filename,gzipSync(this.buffer.join(''),{level:6}));this.buffer=[];this.bufferBytes=0;}
  close(){this.flush();if(!this.count)fs.appendFileSync(this.filename,gzipSync(''));return {file:path.basename(this.filename),records:this.count,rawBytes:this.rawBytes,encodedBytes:fs.statSync(this.filename).size,sha256:sha256(fs.readFileSync(this.filename)),encoding:'gzip-concatenated-members; utf8-jsonl'};}
}

export function runtimeBinding(message){
  const english=message.template,parameters=message.parameters||{},placeholderCounts={};
  for(const match of english.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g))placeholderCounts[match[1]]=(placeholderCounts[match[1]]||0)+1;
  const fingerprintParameters=semanticParameters(parameters);
  const sourceSha256=sha256(stableJson({english,parameters:fingerprintParameters})),context=message.runtimeContext||{};
  const identity={ownerId:message.owner.semanticId,fieldPath:message.owner.fieldPath,context,sourceSha256};
  return {key:'runtime:'+sha256(stableJson(identity)).slice(0,32),owner:{semanticId:message.owner.semanticId,fieldPath:message.owner.fieldPath},english,exactEnglish:message.english,exactEnglishSourceSha256:message.sourceSha256,sourceSha256,fingerprintAlgorithm:'sha256(stableJson({english,parameters:semanticParameters}))',parameters,protectedReferences:message.protectedReferences,classification:message.classification,sourceBinding:message.sourceBinding,context,placeholderCounts};
}

async function* readJsonlGzip(filename){
  const input=fs.createReadStream(filename),decoder=createGunzip();
  input.on('error',error=>decoder.destroy(error));
  const lines=createInterface({input:input.pipe(decoder),crlfDelay:Infinity});
  for await(const line of lines)if(line)yield JSON.parse(line);
}
// Recover only durably completed cases. Bytes emitted by an interrupted next
// case remain in the immutable input but never masquerade as completed coverage.
export async function recoverInventory({input,out,expected,registeredSummary}){
  const manifestBytes=fs.readFileSync(expected),manifest=JSON.parse(manifestBytes),base=JSON.parse(fs.readFileSync(registeredSummary,'utf8'));
  const expectedIds=new Set(manifest.cases.map(entry=>entry.id)),completed=[],completedIds=new Set(),metadataIds=new Set();
  for await(const entry of readJsonlGzip(path.join(input,'completed-cases.jsonl.gz'))){
    if(!expectedIds.has(entry.id)||completedIds.has(entry.id))throw new Error('Unknown or duplicate completed case: '+entry.id);
    completed.push(entry);completedIds.add(entry.id);
  }
  out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  const sinks=Object.fromEntries(['messages','occurrences','protected','completed-cases','presentation-metadata','registered-fields','ambiguities'].map(name=>[name,new JsonlGzip(path.join(out,name+'.jsonl.gz'))]));
  const keys=new Set(),requiredProtected=new Set(),interruptedCases=new Map();let ignoredOccurrences=0,ignoredMessages=0,sourceEnglishBytes=0;
  for await(const occurrence of readJsonlGzip(path.join(input,'occurrences.jsonl.gz'))){
    if(occurrence.caseId&&!completedIds.has(occurrence.caseId)){ignoredOccurrences++;interruptedCases.set(occurrence.caseId,(interruptedCases.get(occurrence.caseId)||0)+1);continue;}
    sinks.occurrences.add(occurrence);keys.add(occurrence.messageKey);
  }
  const classifications={},sourceBindings={};let runtimeMessageUnits=0;
  for await(const message of readJsonlGzip(path.join(input,'messages.jsonl.gz'))){
    if(!keys.has(message.key)){ignoredMessages++;continue;}
    if(sha256(message.english)!==message.sourceSha256)throw new Error('Retained English fingerprint mismatch: '+message.key);
    sinks.messages.add(message);sourceEnglishBytes+=bytes(message.english);classifications[message.classification]=(classifications[message.classification]||0)+1;
    sourceBindings[message.sourceBinding]=(sourceBindings[message.sourceBinding]||0)+1;if(message.runtime!==false)runtimeMessageUnits++;
    for(const reference of message.protectedReferences||[])requiredProtected.add(reference.registryId);
  }
  for await(const entry of readJsonlGzip(path.join(input,'protected.jsonl.gz'))){
    // Typed actor/field declarations remain replay authority even if an earlier
    // classifier missed every occurrence. Referenced-island filtering alone
    // would permanently discard exactly the missing names we need to repair.
    if(requiredProtected.has(entry.id)||/^(?:field|actor):/.test(entry.semanticId||'')&&['id','name','role','standard'].includes(declarationField(entry))||entry.fieldPath==='protocol')sinks.protected.add(entry);
  }
  for(const entry of completed)sinks['completed-cases'].add(entry);
  for await(const entry of readJsonlGzip(path.join(input,'presentation-metadata.jsonl.gz'))){
    if(!completedIds.has(entry.caseId))continue;
    if(metadataIds.has(entry.caseId))throw new Error('Duplicate presentation metadata: '+entry.caseId);
    metadataIds.add(entry.caseId);sinks['presentation-metadata'].add(entry);
  }
  if(metadataIds.size!==completedIds.size)throw new Error('Completed-case presentation metadata missing.');
  for await(const entry of readJsonlGzip(path.join(input,'registered-fields.jsonl.gz')))sinks['registered-fields'].add(entry);
  const artifacts=Object.values(sinks).map(sink=>sink.close()),missing=manifest.cases.filter(entry=>!completedIds.has(entry.id));
  const coverage={expectedManifest:{path:path.resolve(expected),sha256:sha256(manifestBytes)},expectedCases:manifest.cases.length,completedCases:completed.length,missingCases:missing.length,missing,unknownCases:[],duplicateCases:[],interruptedCases:[...interruptedCases].map(([caseId,occurrences])=>({caseId,occurrences})),ignoredUnfinishedOccurrences:ignoredOccurrences,ignoredUnfinishedMessages:ignoredMessages,durableSummaryPresent:fs.existsSync(path.join(input,'summary.json'))};
  fs.writeFileSync(path.join(out,'case-coverage.json'),JSON.stringify(coverage,null,2)+'\n',{flag:'wx'});
  const summary={...base,kind:'source-bound-localization-recovered-capture',root:base.root,registeredOnly:false,canonicalEvaluations:0,caseEvaluationScope:missing.length?'durable-completed-subset-partial':'durable-full-finite-case-set',counts:{...manifest.counts,constructedCases:completed.length,uniqueMessageUnits:sinks.messages.count,runtimeMessageUnits,occurrenceBindings:sinks.occurrences.count,protectedRegistryEntries:sinks.protected.count,ambiguities:0},sourceEnglishBytes,classifications,sourceBindings,artifacts,inheritedArtifacts:[],coverage,unresolved:{sourceBindings:sourceBindings.unresolved||0,missingCases:missing.length},scope:'Lossless retained completed-case English and occurrences; unfinished next-case fragments excluded. No canonical scenario evaluation. Source/protection replay still required.'};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});return summary;
}
function declaredProducer(message,sourceFiles){
  const owner=message.owner,field=owner.fieldPath,id=owner.semanticId;
  let module=null,exportName=null,expression=null;
  if(id.startsWith('environment-field:')&&field==='label'){module='src/runtime-environment.js';exportName='runtimeField';expression='RUNTIME_ENVIRONMENT_FIELDS / RUNTIME_PROVIDER_FIELDS: prefix + label';}
  else if(id.startsWith('workspace-option:')&&field==='selectedLabel'){module='src/workspaces.js';exportName='studioWorkspaceOptions';expression="workspace.title+' / '+family.title";}
  else if(id.startsWith('topic:topic-lab-')&&['name','summary'].includes(field)){module='src/lab-catalog.js';exportName='LAB_TOPICS';expression=field==='name'?'model.title':'model.summary';}
  else if(id.startsWith('field:saml')&&['meaning','description','origin','generator','purpose'].includes(field)){module='src/saml-data.js';exportName='SAML_ATTRIBUTES';expression='samlAttr with typed suffix/actor: description=meaning; generator=origin';}
  else if(id.startsWith('field:jwe')&&['meaning','description','origin','generator','purpose'].includes(field)){module='src/jwe-data.js';exportName='JWE_ATTRIBUTES';expression='jweDefinition with typed hop issuer/recipient: description=meaning; generator=origin';}
  if(!module)return null;
  const source=sourceFiles.find(source=>source.module===module);if(!source)return null;
  return {module,export:exportName,sourceFileSha256:source.sourceSha256,expression,...(message.templateContract?{renderTransform:message.templateContract}:{})};
}

export async function mergeInventories({inputs,out,expected,supplements=[]}){
  const manifestBytes=fs.readFileSync(expected),manifest=JSON.parse(manifestBytes),expectedIds=new Set(manifest.cases.map(entry=>entry.id)),completedIds=new Set(),messageKeys=new Map(),occurrenceKeys=new Set(),protectedIds=new Set(),metadataIds=new Set(),fieldIds=new Set();
  out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  const sinks=Object.fromEntries(['messages','occurrences','protected','completed-cases','presentation-metadata','registered-fields','ambiguities'].map(name=>[name,new JsonlGzip(path.join(out,name+'.jsonl.gz'))]));
  let base=null,sourceEnglishBytes=0;const inputProofs=[],classifications={};
  for(const directory of [...inputs,...supplements]){
    const encoded=fs.readFileSync(path.join(directory,'summary.json')),summary=JSON.parse(encoded),supplement=supplements.includes(directory);
    base||=summary;if(summary.root!==base.root||stableJson(summary.sourceFiles)!==stableJson(base.sourceFiles))throw new Error('Inventory source roots/files differ: '+directory);
    inputProofs.push({path:directory,summarySha256:sha256(encoded),supplement,caseEvaluationScope:summary.caseEvaluationScope});
    const sources=new Map([...summary.inheritedArtifacts||[],...summary.artifacts.map(artifact=>({...artifact,path:artifact.path||path.join(directory,artifact.file)}))].map(artifact=>[artifact.file,artifact.path]));
    const source=name=>sources.get(name)||path.join(directory,name);
    if(!supplement)for await(const entry of readJsonlGzip(source('completed-cases.jsonl.gz'))){
      if(!expectedIds.has(entry.id)||completedIds.has(entry.id))throw new Error('Unknown or repeated case evaluation: '+entry.id);
      completedIds.add(entry.id);sinks['completed-cases'].add(entry);
    }
    for await(const message of readJsonlGzip(source('messages.jsonl.gz'))){
      if(sha256(message.english)!==message.sourceSha256)throw new Error('Merged raw English fingerprint mismatch: '+message.key);
      if(messageKeys.has(message.key)){if(messageKeys.get(message.key)!==message.sourceSha256)throw new Error('Merged message-key collision: '+message.key);continue;}
      messageKeys.set(message.key,message.sourceSha256);sinks.messages.add(message);sourceEnglishBytes+=bytes(message.english);classifications[message.classification]=(classifications[message.classification]||0)+1;
    }
    for await(const entry of readJsonlGzip(source('occurrences.jsonl.gz'))){
      if(entry.caseId&&!expectedIds.has(entry.caseId))throw new Error('Unknown occurrence case: '+entry.caseId);
      const identity=entry.id+'\0'+entry.messageKey;if(occurrenceKeys.has(identity))continue;occurrenceKeys.add(identity);sinks.occurrences.add(entry);
    }
    for await(const entry of readJsonlGzip(source('protected.jsonl.gz')))if(!protectedIds.has(entry.id)){protectedIds.add(entry.id);sinks.protected.add(entry);}
    if(!supplement)for await(const entry of readJsonlGzip(source('presentation-metadata.jsonl.gz'))){if(metadataIds.has(entry.caseId))throw new Error('Repeated case presentation metadata: '+entry.caseId);metadataIds.add(entry.caseId);sinks['presentation-metadata'].add(entry);}
    for await(const entry of readJsonlGzip(source('registered-fields.jsonl.gz')))if(!fieldIds.has(entry.id)){fieldIds.add(entry.id);sinks['registered-fields'].add(entry);}
  }
  if(metadataIds.size!==completedIds.size)throw new Error('Merged completed-case presentation metadata mismatch.');
  const missing=manifest.cases.filter(entry=>!completedIds.has(entry.id)),artifacts=Object.values(sinks).map(sink=>sink.close());
  const summary={...base,kind:'source-bound-localization-inventory-union',canonicalEvaluations:0,registeredOnly:false,caseEvaluationScope:missing.length?'finite-case-union-partial':'full-finite-case-union',inputProofs,counts:{...manifest.counts,constructedCases:completedIds.size,uniqueMessageUnits:messageKeys.size,occurrenceBindings:sinks.occurrences.count,protectedRegistryEntries:protectedIds.size,ambiguities:0},coverage:{expectedManifest:{path:path.resolve(expected),sha256:sha256(manifestBytes)},expectedCases:expectedIds.size,completedCases:completedIds.size,missingCases:missing.length,missing,unknownCases:[],duplicateCases:[]},sourceEnglishBytes,classifications,artifacts,inheritedArtifacts:[],unresolved:{missingCases:missing.length},scope:'Union preserves strong semantic message keys, every distinct case occurrence, registered defaults and per-case presentation metadata. Supplemental display projection does not add case coverage. Canonical construction is never performed by this merge.'};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});return summary;
}

export async function declareReducerFallbacks({input,out}){
  const summary=JSON.parse(fs.readFileSync(path.join(input,'summary.json'),'utf8')),index=indexSources(summary.root),english='No coverage declaration applies at this cursor.';
  const candidates=(index.strings.get(english)||[]).filter(site=>site.module==='src/held-object-state.js'&&site.export==='applicableCoverage');
  if(candidates.length!==1)throw new Error('Reducer fallback requires its unique actual source literal.');
  const site=candidates[0],actors=new Set();
  for await(const entry of readJsonlGzip(path.join(input,'protected.jsonl.gz')))if(entry.semanticId.startsWith('actor:')&&entry.fieldPath==='name')actors.add(entry.semanticId);
  out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  const sinks=Object.fromEntries(['messages','occurrences','protected','completed-cases','presentation-metadata','registered-fields','ambiguities'].map(name=>[name,new JsonlGzip(path.join(out,name+'.jsonl.gz'))]));
  const sourceSha256=sha256(english),sourceDeclared={kind:'reducer-human-fallback',execution:'not-observed-in-completed-finite-cases',source:site,actorDomain:'Actual actor IDs retained from completed-case typed names; never a wildcard English lookup.'};
  for(const semanticId of [...actors].sort()){
    const owner={module:site.module,export:site.export,semanticId,fieldPath:'coverage.gaps.reason'},identity={owner,sourceSha256,sourceDeclared:site.start},key='message:'+sha256(stableJson(identity)).slice(0,32);
    sinks.messages.add({key,owner,english,sourceSha256,parameters:{},protectedReferences:[],classification:'prose',template:english,context:{},runtime:true,runtimeContext:{},sourceSites:[site],sourceCandidateFingerprint:sourceSha256,sourceCandidateCount:1,sourceBinding:'exact-syntax-literal',sourceDeclared});
    sinks.occurrences.add({id:'source-occurrence:'+sha256(stableJson(identity)).slice(0,32),messageKey:key,ownerId:semanticId,fieldPath:owner.fieldPath,surface:'source-declared-reducer-fallback',sourceSha256,sourceDeclared});
  }
  const result={schemaVersion:1,kind:'source-declared-reducer-fallbacks',root:summary.root,sourceFiles:summary.sourceFiles,canonicalEvaluations:0,caseEvaluationScope:'source-declaration-only-never-adds-case-coverage',counts:{declaredFallbackOwners:actors.size,uniqueMessageUnits:sinks.messages.count,occurrenceBindings:sinks.occurrences.count},sourceEnglishBytes:actors.size*bytes(english),artifacts:Object.values(sinks).map(sink=>sink.close()),sourceDeclared};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});return result;
}

export async function auditSourceObligations({inventory,obligations,uiContracts,out,supplements=[]}){
  const summary=JSON.parse(fs.readFileSync(path.join(inventory,'summary.json'),'utf8')),bundle=JSON.parse(fs.readFileSync(uiContracts,'utf8'));
  if(!bundle.summary?.complete||bundle.unresolved.length)throw new Error('Current renderer source coverage is not complete.');
  const index=indexSources(summary.root),sites=new Set(),producers=new Map(),humanSources=new Map(),uiSources=new Set();
  for(const message of bundle.messages){
    if(typeof message.sourceEnglish==='string')uiSources.add(message.sourceEnglish);
    if(typeof message.english==='string')uiSources.add(message.english.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(whole,name)=>{const value=message.parameters?.[name]?.value;return ['string','number','boolean'].includes(typeof value)?String(value):whole;}));
  }
  for(const directory of [inventory,...supplements])for await(const message of readJsonlGzip(path.join(directory,'messages.jsonl.gz'))){
    for(const site of message.sourceSites||[])sites.add(site.module+':'+site.start);
    const module=message.owner.declaration?.module;if(module)producers.set(module,(producers.get(module)||0)+1);
    if(typeof message.english==='string'){const modules=humanSources.get(message.english)||new Set();modules.add(message.owner.module);humanSources.set(message.english,modules);}
  }
  const uiModules=new Map(bundle.sourceFiles.map(source=>[source.module,source])),syntax=new Map();
  for(const [module,info] of index.files)walk.ancestor(info.ast,{Literal(node,ancestors){syntax.set(module+':'+node.start,{node,ancestors:[...ancestors]});},TemplateLiteral(node,ancestors){syntax.set(module+':'+node.start,{node,ancestors:[...ancestors]});}});
  const markupOnly=quasis=>{
    const fragment=parseFragment(quasis.join('')),human=[];
    const visit=node=>{if(node.nodeName==='#text'&&/[\p{L}]/u.test(node.value||''))human.push(node.value);for(const attribute of node.attrs||[])if(['aria-label','title','alt','placeholder'].includes(attribute.name)&&/[\p{L}]/u.test(attribute.value))human.push(attribute.value);for(const child of node.childNodes||[])visit(child);};visit(fragment);
    return !human.length;
  };
  out=path.resolve(out);fs.mkdirSync(out,{recursive:false});const sink=new JsonlGzip(path.join(out,'source-obligations.jsonl.gz')),counts={},unresolved=[];
  for await(const record of readJsonlGzip(obligations)){
    const site=record.site||record,module=site.module,info=index.files.get(module);let disposition=null,evidence=null;
    if(info?.sourceSha256!==site.sourceFileSha256)throw new Error('Source obligation module fingerprint mismatch: '+module);
    const ast=syntax.get(module+':'+site.start),parent=ast?.ancestors.at(-2),call=[...(ast?.ancestors||[])].reverse().find(node=>node.type==='CallExpression'),callee=call?.callee;
    const property=parent?.type==='Property'?propertyName(parent.key):null,method=callee?.type==='MemberExpression'?propertyName(callee.property):callee?.name;
    if(record.status==='source-branch-not-an-execution-coverage-claim')disposition='control-flow-audit-not-a-message';
    else if(sites.has(module+':'+site.start))disposition='bound-semantic-source-site';
    else if(uiModules.get(module)?.role==='renderer'){disposition='renderer-clean-cutover';evidence={previousSourceSha256:site.sourceFileSha256,currentSourceSha256:uiModules.get(module).sourceSha256,uiSourceSetSha256:bundle.summary.sourceSetSha256,boundCallsites:bundle.summary.counts.boundCallsites,boundFactorySites:bundle.summary.counts.boundFactorySites};}
    else if(record.source&&uiSources.has(record.source)){disposition='explicit-ui-producer-reference';evidence={uiSourceSetSha256:bundle.summary.sourceSetSha256,sourceEnglishSha256:sha256(record.source)};}
    else if(record.quasis&&markupOnly(record.quasis)){disposition='structural-markup-no-human-text';evidence={parser:'parse5',scope:'Static text nodes and human-facing attributes only; dynamic values remain producer obligations.'};}
    else if(producers.has(module)){disposition='authored-schema-producer';evidence={sourceSha256:info.sourceSha256,boundSemanticRealizations:producers.get(module),scope:'Source-owned model/field schema producer; not a claim that every syntax branch executed.'};}
    else if(record.source&&humanSources.get(record.source)?.has(module))disposition='source-owned-captured-human-field';
    else if(ast?.ancestors.some(node=>node.type==='NewExpression'&&['Error','TypeError','RangeError'].includes(node.callee?.name))||module==='src/held-object-state.js'&&(['requireValue','text','list'].includes(method)||site.export==='assertHeldObjectCoverage'))disposition='developer-invariant-diagnostic';
    else if(module==='src/runtime-environment.js'&&site.export==='RUNTIME_ENVIRONMENT_FIELDS'&&record.quasis){disposition='finite-prefix-field-label-factory';evidence={semanticOwner:'environment-field:<a|b><endpoint>',fieldPath:'label',producer:'runtimeField(prefix+field,label)',sourceSha256:info.sourceSha256};}
    else if(module==='src/attribute-trace.js'&&record.source==='Illustrative value'){disposition='canonical-example-fallback';evidence={producer:'traceFieldValue',consumer:'payload.value -> formatProtocolValue',sourceSha256:info.sourceSha256};}
    else if(module==='src/attribute-trace.js'&&['Send ','Carried inside '].includes(record.source)){disposition='explicit-ui-trace-template';evidence={keys:record.source==='Send '?['ui.trace.title.send']:['ui.trace.carried-inside'],uiSourceSetSha256:bundle.summary.sourceSetSha256};}
    else if(module==='src/attribute-usage.js'&&site.export==='transfer'){disposition='semantic-operation-detail-factory';evidence={semanticOwner:'step:<sourceStepId>',fieldPath:'attributeOperations.detail',parameters:{fieldName:'ATTRIBUTES[attributeId].name'},sourceSha256:info.sourceSha256};}
    else if(module==='src/held-object-state.js'&&site.export==='heldObjectTrace'&&record.quasis?.[1]===': initial provisioned context'){disposition='semantic-held-trace-title-factory';evidence={semanticOwner:'artifact:<artifactId>',fieldPath:'trace.title',sourceSha256:info.sourceSha256};}
    else if(module==='src/actor-art.js'&&record.quasis?.[0]==='actor-art-'||module==='src/layout.js'&&['straightSegment','roundedPath'].includes(site.export)||module==='src/dnssec-validation.js'&&record.quasis?.[0]==='signature-'){disposition='typed-svg-identity-geometry-or-reason-code';evidence={sourceSha256:info.sourceSha256,export:site.export};}
    else if(record.site||record.quasis){
      if(parent?.type==='BinaryExpression'||parent?.type==='LogicalExpression'||parent?.type==='MemberExpression'||parent?.type==='ImportDeclaration'||property&&!HUMAN_FIELDS.has(property)&&!['name','factorCount','caveat'].includes(property)||['includes','has','get','set','split','join','startsWith','endsWith','replace','replaceAll','querySelector','querySelectorAll','closest','getAttribute','setAttribute','removeAttribute','createElement','matches','add','remove','toggle','Error','TypeError'].includes(method))disposition='typed-code-selector-or-schema-token';
      else if(!record.quasis&&!/\s/.test(record.source)&&!/[<>]/.test(record.source))disposition='single-schema-token';
    }
    if(!disposition){disposition='unresolved-human-producer-role';unresolved.push(record);}
    counts[disposition]=(counts[disposition]||0)+1;sink.add({...record,disposition,...(evidence?{evidence}:{})});
  }
  const artifact=sink.close(),report={schemaVersion:1,scope:'Source-role classification, not branch execution or native translation acceptance. Frozen syntax obligations are reconciled with semantic captured owners and the explicit current-renderer clean cutover.',input:{path:path.resolve(obligations),sha256:sha256(fs.readFileSync(obligations))},uiSourceSetSha256:bundle.summary.sourceSetSha256,counts,unresolved:unresolved.length,unresolvedRecords:unresolved,artifact};
  report.witnesses={completedCases:summary.coverage?.completedCases||summary.counts.constructedCases,sourceOnlySupplements:supplements.map(directory=>{const encoded=fs.readFileSync(path.join(directory,'summary.json')),source=JSON.parse(encoded);return {path:path.resolve(directory),summarySha256:sha256(encoded),kind:source.kind,counts:source.counts,execution:source.sourceDeclared?.execution};})};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});return report;
}

// Replace only the renderer sidecar; body prose and case witnesses are copied.
export async function refreshUIInventory({input,out,uiContracts,sourceAudit=null}){
  const encoded=fs.readFileSync(path.join(input,'summary.json')),previous=JSON.parse(encoded),bundle=JSON.parse(fs.readFileSync(uiContracts,'utf8'));
  if(bundle.summary?.complete!==true||bundle.unresolved.length)throw new Error('UI refresh requires complete source contracts.');
  const sources=new Map([...previous.inheritedArtifacts||[],...previous.artifacts.map(artifact=>({...artifact,path:artifact.path||path.join(input,artifact.file)}))].map(artifact=>[artifact.file,artifact]));
  const source=name=>sources.get(name)?.path||path.join(input,name);out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  const sinks=Object.fromEntries(['messages','runtime-bindings','occurrences','protected','ambiguities'].map(name=>[name,new JsonlGzip(path.join(out,name+'.jsonl.gz'))]));
  const registry=new ProtectedRegistry(),keys=new Map(),oldUI=new Set(),schemas=new Set(),englishHashes=new Set(),classifications={},surfaces={},families={};let sourceEnglishBytes=0,realizedRuntime=0,uiUnresolved=0,templateBytes=0,proseWords=0,runtimeEnglishBytes=0;
  const uiBytes=new Map(bundle.messages.map(message=>[message.key,typeof message.sourceEnglish==='string'?bytes(message.sourceEnglish):typeof message.english==='string'?bytes(message.english):Object.values(message.english.plural).reduce((sum,form)=>sum+bytes(form),0)]));
  const accountOccurrence=occurrence=>{const ui=uiBytes.has(occurrence.messageKey),surface=occurrence.surface||(ui?'runtime-ui':'unknown'),family=occurrence.family||(ui?'ui':occurrence.sourceDeclared?'source-declared':'shared'),englishBytes=keys.get(occurrence.messageKey)||uiBytes.get(occurrence.messageKey)||0;for(const [table,name] of [[surfaces,surface],[families,family]]){table[name]||={occurrences:0,englishBytes:0};table[name].occurrences++;table[name].englishBytes+=englishBytes;}};
  const account=message=>{const raw=message.sourceEnglish||message.english,forms=typeof raw==='string'?[raw]:Object.values(raw.plural),englishBytes=forms.reduce((sum,form)=>sum+bytes(form),0),template=message.template||message.english;sourceEnglishBytes+=englishBytes;for(const form of forms)englishHashes.add(sha256(form));for(const form of typeof template==='string'?[template]:Object.values(template.plural)){templateBytes+=bytes(form);proseWords+=(form.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'').match(/[\p{L}\p{N}]+/gu)||[]).length;}classifications[message.classification]=(classifications[message.classification]||0)+1;if(message.runtime!==false){realizedRuntime++;runtimeEnglishBytes+=englishBytes;}};
  for await(const message of readJsonlGzip(source('messages.jsonl.gz'))){if(message.owner.semanticId.startsWith('ui:')){oldUI.add(message.key);continue;}keys.set(message.key,bytes(message.english));sinks.messages.add(message);account(message);}
  for await(const message of readJsonlGzip(source('runtime-bindings.jsonl.gz')))if(!message.owner.semanticId.startsWith('ui:')){sinks['runtime-bindings'].add(message);schemas.add(message.sourceSha256);}
  for await(const occurrence of readJsonlGzip(source('occurrences.jsonl.gz')))if(!oldUI.has(occurrence.messageKey)){sinks.occurrences.add(occurrence);accountOccurrence(occurrence);}
  for await(const entry of readJsonlGzip(source('protected.jsonl.gz')))registry.entries.set(entry.id,entry);
  for await(const entry of readJsonlGzip(source('ambiguities.jsonl.gz')))if(!entry.kind.startsWith('unresolved-explicit-ui')&&entry.kind!=='ui-protected-reference-registry-unavailable')sinks.ambiguities.add(entry);
  const target={messages:keys,protected:registry,occurrences:{add:occurrence=>{sinks.occurrences.add(occurrence);accountOccurrence(occurrence);}},totals:{classifications:{},surfaces:{},families:{},sourceEnglishBytes:0},ambiguity:(kind,owner,fieldPath,details)=>{uiUnresolved++;sinks.ambiguities.add({kind,owner,fieldPath,details});}};
  for(const message of mergeUIContracts(target,bundle)){sinks.messages.add(message);sinks['runtime-bindings'].add(message);schemas.add(message.sourceSha256);account(message);}
  for(const entry of registry.toJSON())sinks.protected.add(entry);
  const artifacts=Object.values(sinks).map(sink=>sink.close()),inheritedArtifacts=[...sources.values()].filter(artifact=>!artifacts.some(replacement=>replacement.file===artifact.file));
  const result={...previous,kind:'source-bound-localization-current-ui-merge',canonicalEvaluations:0,counts:{...previous.counts,uniqueMessageUnits:sinks.messages.count,runtimeMessageUnits:sinks['runtime-bindings'].count,realizedRuntimeMessageUnits:realizedRuntime,auditOnlyRealizedUnits:sinks.messages.count-realizedRuntime,occurrenceBindings:sinks.occurrences.count,protectedRegistryEntries:registry.entries.size,ambiguities:sinks.ambiguities.count,explicitRuntimeContracts:bundle.messages.length},classifications,sourceEnglishBytes,artifacts,inheritedArtifacts,uiSourceFiles:bundle.sourceFiles,uiSidecar:{path:path.resolve(uiContracts),sourceSha256:sha256(fs.readFileSync(uiContracts)),sourceSetSha256:bundle.summary.sourceSetSha256},uiRefresh:{inputSummarySha256:sha256(encoded),collectorFiles:COLLECTOR_FILES,scope:'Renderer replacement only; body classification and all case witnesses unchanged.'},sizing:{...previous.sizing,uniqueExactEnglishStrings:englishHashes.size,distinctTypedRuntimeSchemas:schemas.size,distinctSemanticRuntimeBindings:sinks['runtime-bindings'].count}};
  result.unresolved={...previous.unresolved,uiReferences:uiUnresolved};result.surfaces=surfaces;result.families=families;
  result.telemetry={stage:'current-ui-source-merge',completedCases:previous.coverage.completedCases,canonicalEvaluations:0};
  result.occurrenceByteScope='Canonical English bytes per recorded source binding; UI records use declared English forms, not realized DOM byte estimates.';
  Object.assign(result.sizing,{templateBytes,proseWords,runtimeEnglishBytes,ownerAndParameterBoundTemplateGroups:previous.sizing.ownerAndParameterBoundTemplateGroups-oldUI.size+bundle.messages.length});
  if(sourceAudit){const auditBytes=fs.readFileSync(path.join(sourceAudit,'summary.json')),audit=JSON.parse(auditBytes);if(audit.uiSourceSetSha256!==bundle.summary.sourceSetSha256)throw new Error('Source-role audit/UI source set mismatch.');result.sourceRoleAudit={path:path.resolve(sourceAudit),summarySha256:sha256(auditBytes),counts:audit.counts,unresolved:audit.unresolved};result.counts.unclassifiedGeneratedStrings=audit.unresolvedRecords.filter(record=>record.site).length;result.unresolved.generatedSourceObligations=audit.unresolvedRecords.filter(record=>record.quasis).length;result.unresolved.sourceRoleObligations=audit.unresolved;}
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});return result;
}

// Reclassifies retained English and typed occurrences, never imports an app or
// evaluates a scenario. Raw case/occurrence artifacts remain immutable inputs.
export async function reclassifyInventory({input,out,uiRoot=null,uiContracts=null,supplements=[]}){
  input=fs.realpathSync(input);out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  if(uiRoot&&uiContracts)throw new TypeError('Choose --ui-root or --ui-contracts, not both.');
  const sourceText=fs.readFileSync(path.join(input,'summary.json'),'utf8'),sourceSummary=JSON.parse(sourceText);
  const sources=new Map([...sourceSummary.inheritedArtifacts||[],...sourceSummary.artifacts.map(artifact=>({...artifact,path:artifact.path||path.join(input,artifact.file)}))].map(artifact=>[artifact.file,artifact]));
  const sourcePath=name=>sources.get(name)?.path||path.join(input,name);
  const supplementProofs=supplements.map(directory=>{const encoded=fs.readFileSync(path.join(directory,'summary.json')),summary=JSON.parse(encoded);if(summary.root!==sourceSummary.root||stableJson(summary.sourceFiles)!==stableJson(sourceSummary.sourceFiles))throw new Error('Supplement source identity mismatch.');return {path:path.resolve(directory),summarySha256:sha256(encoded),summary};});
  async function* sourceRows(name){yield* readJsonlGzip(sourcePath(name));for(const supplement of supplementProofs)yield* readJsonlGzip(path.join(supplement.path,name));}
  const uiBundle=uiContracts?JSON.parse(fs.readFileSync(uiContracts,'utf8')):uiRoot?await(await import('./ui-contracts.mjs')).extractUIContracts({root:uiRoot}):null;
  const requiredRegistryIds=new Set();
  for await(const message of sourceRows('messages.jsonl.gz'))for(const reference of message.protectedReferences||[])if(reference.registryId)requiredRegistryIds.add(reference.registryId);
  const registry=new ProtectedRegistry({locate:()=>({module:'tools/verification/localization/protected.mjs',export:'references'})}),standards=new Map(),protocols=new Map(),fieldNames=new Map();
  for await(const entry of sourceRows('protected.jsonl.gz')){
    if(entry.kind==='profile-name'||entry.kind==='official-citation'&&/(?:^|\.)(?:note|errata)$/.test(entry.fieldPath)||uiBundle&&entry.kind==='ui-protected-parameter')continue;
    const field=declarationField(entry);
    if(!requiredRegistryIds.has(entry.id)&&!(/^(?:field|actor):/.test(entry.semanticId)&&['id','name','role','standard'].includes(field))&&field!=='protocol')continue;
    registry.entries.set(entry.id,entry);
    if(entry.semanticId.startsWith('field:')&&field==='name'){registry.registerTypedName(entry.value,{owner:entry.semanticId,sourcePath:entry.semanticId+'.name'});const names=fieldNames.get(entry.semanticId)||new Set();names.add(entry.value);fieldNames.set(entry.semanticId,names);}
    if(entry.semanticId.startsWith('actor:')){
      const owner=entry.semanticId,id=owner.slice(6);
      registry.registerTypedName(id,{owner,sourcePath:owner+'.id',kind:'actor-identifier'});
      if(field==='name')registry.registerTypedName(entry.value,{owner,sourcePath:owner+'.name',kind:'actor-name'});
    }
    if(field==='standard')standards.set(entry.semanticId,[standards.get(entry.semanticId),entry.value].filter(Boolean).join('; '));
    if(field==='protocol')protocols.set(entry.semanticId,entry.value);
  }
  // A semantic field may be collected by its definition, navigation and search
  // producers. Share their protocol evidence within the exact runtime slot;
  // an incidental collecting module must not change its protected meaning.
  const semanticScope=message=>stableJson([message.owner.semanticId,message.owner.fieldPath,message.runtimeContext||{}]);
  const semanticSourceModules=new Map();
  // Caption references still require their actual typed local declarations,
  // never a global English-string lookup.
  const captionReferences=new Map(),captionScope=message=>/^(?:title|summary)$/.test(message.owner.fieldPath)&&message.owner.semanticId.startsWith('lesson:')||message.owner.fieldPath==='label'&&message.owner.semanticId.startsWith('artifact:')?semanticScope(message):null;
  for await(const message of sourceRows('messages.jsonl.gz')){
    const slot=semanticScope(message),modules=semanticSourceModules.get(slot)||new Set();
    if(message.owner.module)modules.add(message.owner.module);
    semanticSourceModules.set(slot,modules);
    const scope=captionScope(message);if(!scope)continue;
    for(const ref of message.protectedReferences||[]){
      const definition=message.parameters?.[ref.parameter],declared=registry.entries.get(ref.registryId);
      if(!declared||definition?.dynamic||typeof definition?.value!=='string'||!(definition.sourcePath==='protocol'||/^actor:.*\.name$/.test(definition.sourcePath||'')))continue;
      const references=captionReferences.get(scope)||new Map(),reference={value:definition.value,sourcePath:definition.sourcePath,owner:declared.semanticId,kind:declared.kind,formal:true};
      references.set(stableJson(reference),reference);captionReferences.set(scope,references);
    }
  }
  const messageSink=new JsonlGzip(path.join(out,'messages.jsonl.gz')),bindingSink=new JsonlGzip(path.join(out,'runtime-bindings.jsonl.gz')),ambiguitySink=new JsonlGzip(path.join(out,'ambiguities.jsonl.gz')),occurrenceSink=new JsonlGzip(path.join(out,'occurrences.jsonl.gz'));
  const runtimeMapSink=new JsonlGzip(path.join(out,'runtime-key-map.jsonl.gz')),sourceAuditSink=new JsonlGzip(path.join(out,'source-binding-audit.jsonl.gz'));
  const runtimeKeys=new Set(),runtimeKeyMap=new Map(),runtimeSchemas=new Set(),sourceResolutions=new Set(),usedProtectedIds=new Set();let unresolvedRuntimeSources=0,runtimeAmbiguities=0,sourceDeclaredOnlyContracts=0;
  const bind=message=>{
    const binding=runtimeBinding(message);runtimeKeyMap.set(message.key,binding.key);runtimeMapSink.add({inventoryKey:message.key,runtimeKey:binding.key,sourceSha256:binding.sourceSha256});
    if(runtimeKeys.has(binding.key))return;
    runtimeKeys.add(binding.key);runtimeSchemas.add(binding.sourceSha256);bindingSink.add(binding);
    for(const reference of binding.protectedReferences||[])if(reference.registryId)usedProtectedIds.add(reference.registryId);
    if(binding.sourceBinding==='unresolved')unresolvedRuntimeSources++;
    if(binding.classification==='ambiguous')runtimeAmbiguities++;
  };
  const classifications={},changes={parameterContracts:0,classification:0,uiSourceRefreshRequired:0,genericTracePayloadsMadeAuditOnly:0};
  const oldUiKeys=new Set(),seenKeys=new Set(),templatesByKey=new Map(),exactEnglish=new Set(),fieldOwners=new Set(),boundGroups=new Set(),factoryGroups=new Map();
  let runtimeMessageUnits=0,runtimeEnglishBytes=0,sourceEnglishBytes=0,templateBytes=0,proseWords=0,explicitRuntimeContracts=0;
  const account=message=>{
    seenKeys.add(message.key);classifications[message.classification]=(classifications[message.classification]||0)+1;
    const raw=message.sourceEnglish||message.exactEnglish||message.english,forms=typeof raw==='string'?[raw]:Object.values(raw?.plural||{}),template=message.template||message.english,templateForms=typeof template==='string'?[template]:Object.values(template?.plural||{});
    const englishBytes=forms.reduce((sum,form)=>sum+bytes(form),0);sourceEnglishBytes+=englishBytes;for(const form of forms)exactEnglish.add(sha256(form));
    for(const form of templateForms){templateBytes+=bytes(form);proseWords+=(form.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'').match(/[\p{L}\p{N}]+/gu)||[]).length;}
    boundGroups.add(sha256(stableJson({owner:message.owner,context:message.context,template,parameters:semanticParameters(message.parameters)})));
    if(message.owner.semanticId.startsWith('field:'))fieldOwners.add(message.owner.semanticId);
    if(message.sourceDeclared)sourceDeclaredOnlyContracts++;
    if(message.runtime!==false){runtimeMessageUnits++;runtimeEnglishBytes+=englishBytes;}
    if(message.templateContract?.key)templatesByKey.set(message.key,message.templateContract.key);
    const candidate=factoryOpportunity(message);if(candidate){const id=sha256(stableJson(candidate)),group=factoryGroups.get(id)||{id,...candidate,messageKeys:[],owners:[]};group.messageKeys.push(message.key);group.owners.push(message.owner.semanticId);factoryGroups.set(id,group);}
  };
  for await(const original of sourceRows('messages.jsonl.gz')){
    if(original.fingerprintAlgorithm&&original.owner?.semanticId?.startsWith('ui:')){
      oldUiKeys.add(original.key);if(uiBundle)continue;
      messageSink.add(original);bindingSink.add(original);runtimeKeys.add(original.key);runtimeSchemas.add(original.sourceSha256);explicitRuntimeContracts++;changes.uiSourceRefreshRequired++;account(original);continue;
    }
    if(typeof original.english!=='string'||sha256(original.english)!==original.sourceSha256)throw new Error('Raw English fingerprint mismatch: '+original.key);
    const references=[...captionReferences.get(captionScope(original))?.values()||[]];
    const names=fieldNames.get(original.owner.semanticId);if(names?.size===1)references.push({value:[...names][0],formal:true,kind:'field-name',owner:original.owner.semanticId,sourcePath:original.owner.semanticId+'.name'});
    for(const ref of original.protectedReferences||[]){
      const definition=original.parameters[ref.parameter],sourcePath=definition?.sourcePath,declared=registry.entries.get(ref.registryId);
      // Retain typed declarations, not a previous classifier's derived spans.
      // Otherwise an old longer request-line island would swallow the newly
      // corrected human sentence punctuation on every replay.
      if(!definition||typeof definition.value!=='string'||/^(?:source-identifier|canonical-technical-identity|literal-structured-example):/.test(sourcePath||'')||declared?.kind==='source-bound-code-example'||sourcePath==='profile.name'&&original.owner.fieldPath!=='profile.name')continue;
      references.push({value:definition.value,sourcePath,owner:declared?.semanticId,kind:declared?.kind,formal:true,...(definition.role?{role:definition.role}:{}),...(definition.dynamic?{dynamic:true}:{})});
    }
    const protectionContext=original.protectionContext||{standard:standards.get(original.owner.semanticId),protocol:protocols.get('lesson:'+original.owner.scenarioId)};
    const protection=registry.references(original.english,references,{...protectionContext,ownerId:original.owner.semanticId,fieldPath:original.owner.fieldPath,sourceModule:original.owner.module,semanticSourceModules:[...semanticSourceModules.get(semanticScope(original))||[]],ui:original.owner.semanticId.startsWith('ui:')});
    const externalParameters=Object.fromEntries(Object.entries(original.parameters||{}).filter(([,definition])=>definition.kind!=='protected'));
    const message={...original,template:protection.template,parameters:{...protection.parameters,...externalParameters},protectedReferences:protection.protectedReferences,classification:protection.classification,protectionContext};
    if(message.sourceBinding==='unresolved'){
      const producer=declaredProducer(message,sourceSummary.sourceFiles||[]);
      if(producer){message.sourceBinding='explicit-semantic-producer';message.sourceProducer=producer;changes.resolvedProducerBindings=(changes.resolvedProducerBindings||0)+1;}
    }
    if(message.sourceBinding!=='unresolved')sourceResolutions.add(stableJson([message.owner.semanticId,message.owner.fieldPath,message.sourceSha256]));
    if(original.owner.semanticId.startsWith('step:')&&original.owner.fieldPath==='phase'){message.runtime=false;message.auditReason='canonical-phase-enum';}
    if(/^(?:protocolEffects|initialState)(?:\.|$)/.test(original.owner.fieldPath)){message.runtime=false;message.auditReason='canonical-state-dump-not-a-prose-producer';}
    if(original.owner.fieldPath==='payload.description'&&original.context?.operationKind&&original.english.startsWith('Carried inside ')&&original.english.endsWith('.')){
      message.runtime=false;message.auditReason='generic-trace-carried-container-ui-template';message.templateContract={key:'ui.trace.carried-inside',english:'Carried inside {container}.',parameters:{container:{kind:'protected',value:original.english.slice(15,-1),dynamic:true}},factory:{module:'src/attribute-trace.js',export:'buildAttributeTrace',slot:'payload.description'}};changes.genericTracePayloadsMadeAuditOnly++;
    }
    if(message.runtime!==false&&/^step:lab-dnssec\d+:/.test(message.owner.semanticId)&&message.owner.fieldPath==='payload.description'){
      // dnssecAuthorPresentation forwards one description argument to every
      // detailed item. Attribute identity affects data, not this shared prose.
      message.runtimeContext={};
      if(Object.keys(original.runtimeContext||{}).length)changes.sharedDnssecDescriptionContexts=(changes.sharedDnssecDescriptionContexts||0)+1;
    }
    if(stableJson(original.parameters)!==stableJson(message.parameters))changes.parameterContracts++;
    if(original.classification!==message.classification)changes.classification++;
    account(message);messageSink.add(message);if(message.runtime!==false)bind(message);
    if(protection.ambiguousReferences.length)ambiguitySink.add({kind:'unclassified-uppercase-fragments',owner:message.owner.semanticId,fieldPath:message.owner.fieldPath,details:{sourceSha256:message.sourceSha256,references:protection.ambiguousReferences}});
  }
  for await(const original of sourceRows('ambiguities.jsonl.gz')){
    if(original.kind==='unclassified-uppercase-fragments'||uiBundle&&original.kind.startsWith('unresolved-explicit-ui'))continue;
    if(/source-binding|multiple-source-module-candidates/.test(original.kind)){
      const resolved=sourceResolutions.has(stableJson([original.owner,original.fieldPath,original.details?.sourceSha256]));
      sourceAuditSink.add({...original,status:resolved?'resolved-by-preserved-source-producer':'unresolved'});if(resolved)continue;
    }
    ambiguitySink.add(original);
  }
  for await(const occurrence of sourceRows('occurrences.jsonl.gz'))if(!(uiBundle&&oldUiKeys.has(occurrence.messageKey)))occurrenceSink.add({...occurrence,...(runtimeKeyMap.has(occurrence.messageKey)?{runtimeMessageKey:runtimeKeyMap.get(occurrence.messageKey)}:{}),...(templatesByKey.has(occurrence.messageKey)?{templateKey:templatesByKey.get(occurrence.messageKey)}:{})});
  let uiTotals=null;
  if(uiBundle){
    const mergeTarget={messages:new Map([...seenKeys].map(key=>[key,null])),protected:registry,occurrences:occurrenceSink,totals:{classifications:{},surfaces:{},families:{},sourceEnglishBytes:0},ambiguity:(kind,owner,fieldPath,details)=>ambiguitySink.add({kind,owner,fieldPath,details})};
    for(const contract of mergeUIContracts(mergeTarget,uiBundle)){messageSink.add(contract);bindingSink.add(contract);runtimeKeys.add(contract.key);runtimeSchemas.add(contract.sourceSha256);for(const reference of contract.protectedReferences||[])if(reference.registryId)usedProtectedIds.add(reference.registryId);account(contract);explicitRuntimeContracts++;}
    uiTotals=mergeTarget.totals;
  }
  const protectedSink=new JsonlGzip(path.join(out,'protected.jsonl.gz')),identifierSink=new JsonlGzip(path.join(out,'source-identifiers.jsonl.gz'));
  let camelCaseWitnesses=0,jwtIdentifierWitnesses=0;
  for(const entry of registry.toJSON()){protectedSink.add(entry);if(usedProtectedIds.has(entry.id)&&['source-identifier','opaque-jwt-identifier'].includes(entry.kind)){identifierSink.add(entry);if(entry.kind==='source-identifier')camelCaseWitnesses++;else jwtIdentifierWitnesses++;}}
  const candidates=[...factoryGroups.values()].filter(group=>group.messageKeys.length>1).map(group=>({...group,runtimeKeys:[...new Set(group.messageKeys.map(key=>runtimeKeyMap.get(key)).filter(Boolean))].sort(),owners:[...new Set(group.owners)].sort()}));
  const opportunities=JSON.stringify({scope:'Candidates only. Exact source-factory/literal identity, semantic field role, runtime context and typed parameter agreement are required; every raw realization remains audit-bound. runtimeKeys distinguishes actual translation reuse candidates from already-collapsed case/prefix duplicates.',groups:candidates},null,2)+'\n';
  fs.writeFileSync(path.join(out,'template-opportunities.json'),opportunities,{flag:'wx'});
  const artifacts=[messageSink.close(),bindingSink.close(),protectedSink.close(),identifierSink.close(),ambiguitySink.close(),occurrenceSink.close(),runtimeMapSink.close(),sourceAuditSink.close(),{file:'template-opportunities.json',rawBytes:bytes(opportunities),encodedBytes:bytes(opportunities),sha256:sha256(opportunities)}];
  const inheritedArtifacts=[...sources.values()].filter(artifact=>!artifacts.some(replacement=>replacement.file===artifact.file));
  const summary={...sourceSummary,kind:'source-bound-localization-reclassification',inputSummary:{path:path.join(input,'summary.json'),sourceSha256:sha256(sourceText)},canonicalEvaluations:0,counts:{...sourceSummary.counts,uniqueMessageUnits:messageSink.count,runtimeMessageUnits,auditOnlyRealizedUnits:messageSink.count-runtimeMessageUnits,occurrenceBindings:occurrenceSink.count,protectedRegistryEntries:registry.entries.size,ambiguities:ambiguitySink.count,explicitRuntimeContracts},sourceEnglishBytes,classifications,sizing:{uniqueExactEnglishStrings:exactEnglish.size,uniqueFieldOwners:fieldOwners.size,ownerAndParameterBoundTemplateGroups:boundGroups.size,templateBytes,proseWords,runtimeEnglishBytes,templateDedupCandidates:candidates.length},changes,artifacts,inheritedArtifacts,collectorFiles:COLLECTOR_FILES,scope:'Lexical replay and optional explicit UI-contract merge. Original source cases and canonical models are not evaluated or mutated. Existing UI contracts require separate current-source regeneration when listed.'};
  summary.counts.realizedRuntimeMessageUnits=runtimeMessageUnits;summary.counts.runtimeMessageUnits=bindingSink.count;
  summary.sizing.distinctTypedRuntimeSchemas=runtimeSchemas.size;summary.sizing.distinctSemanticRuntimeBindings=runtimeKeys.size;
  summary.sizing.runtimeFactoryDedupCandidates=candidates.filter(group=>group.runtimeKeys.length>1).length;
  summary.counts.sourceDeclaredOnlyContracts=sourceDeclaredOnlyContracts;summary.counts.sourceIdentifierWitnesses=identifierSink.count;
  summary.counts.camelCaseIdentifierWitnesses=camelCaseWitnesses;summary.counts.jwtIdentifierWitnesses=jwtIdentifierWitnesses;
  summary.identifierPolicy='Whole CamelCase identifiers and domain-scoped opaque JWT/JOSE identifiers are bound to semantic owner, field, exact English SHA-256 and offset. No global English-word, ordinary User/Client, scope/use/roles/groups or conceptual nonce masking. Full identifiers, wire roles and registry witness IDs are retained.';
  summary.unresolved={...summary.unresolved,sourceBindings:unresolvedRuntimeSources,runtimeAmbiguities};
  summary.supplements=supplementProofs.map(({summary,...proof})=>({...proof,kind:summary.kind,counts:summary.counts,caseEvaluationScope:summary.caseEvaluationScope}));
  if(uiBundle){summary.uiSourceFiles=uiBundle.sourceFiles||uiBundle.summary?.modules||[];summary.uiSidecar=uiContracts?{path:path.resolve(uiContracts),sourceSha256:sha256(fs.readFileSync(uiContracts))}:null;summary.uiRoot=uiRoot;summary.surfaces={...summary.surfaces,...uiTotals.surfaces};summary.families={...summary.families,...uiTotals.families};}
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});return summary;
}

function factoryOpportunity(message){
  if(!message.owner.semanticId.startsWith('field:'))return null;
  const sites=(message.sourceSites||[]).filter(site=>site.module===message.owner.module);
  const factory=sites.length===1?{kind:'exact-author-literal',module:sites[0].module,export:sites[0].export,start:sites[0].start,end:sites[0].end,sourceFileSha256:sites[0].sourceFileSha256}:message.templateContract?.factory?{...message.templateContract.factory,declaration:message.owner.declaration,originalEnglishSha256:message.templateContract.originalEnglishSha256}:null;
  if(!factory)return null;
  const parameters=Object.fromEntries(Object.entries(semanticParameters(message.parameters)).map(([name,definition])=>[name,{...definition,...(definition.dynamic?{value:'<captured-canonical-English>'}:{}),referenceRole:message.parameters[name].sourcePath?.startsWith(message.owner.semanticId+'.')?message.parameters[name].sourcePath.slice(message.owner.semanticId.length+1):message.parameters[name].sourcePath||null}]));
  return {factory,ownerKind:'field',fieldPath:message.owner.fieldPath,runtimeContext:message.runtimeContext||message.context||{},template:message.template||message.english,parameters};
}

export function indexSources(root){
  const files=new Map(),strings=new Map(),semanticIds=new Map(),templates=[],branches=[];
  function scan(relative){
    for(const item of fs.readdirSync(path.join(root,relative),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
      const name=relative+'/'+item.name;
      if(item.isDirectory())scan(name);
      else if(item.isFile()&&/\.(?:m?js)$/.test(name)){
        const source=fs.readFileSync(path.join(root,name),'utf8'),ast=parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true});
        const info={module:name,sourceSha256:sha256(source),bytes:bytes(source),ast,source};files.set(name,info);
        walk.ancestor(ast,{
          Literal(node,ancestors){if(typeof node.value!=='string')return;const site=siteFor(info,node,ancestors);if(!strings.has(node.value))strings.set(node.value,[]);strings.get(node.value).push(site);const parent=ancestors.at(-2);if(parent?.type==='Property'&&propertyName(parent.key)==='id'){if(!semanticIds.has(node.value))semanticIds.set(node.value,[]);semanticIds.get(node.value).push(site);}},
          Property(node,ancestors){const id=propertyName(node.key);if(typeof id==='string'&&node.value&&['ObjectExpression','CallExpression'].includes(node.value.type)&&!HUMAN_FIELDS.has(id)&&!PROTECTED_FIELDS.has(id)){if(!semanticIds.has(id))semanticIds.set(id,[]);semanticIds.get(id).push(siteFor(info,node,ancestors));}},
          TemplateLiteral(node,ancestors){const site=siteFor(info,node,ancestors);templates.push({...site,quasis:node.quasis.map(q=>q.value.cooked),expressions:node.expressions.map(e=>source.slice(e.start,e.end)),source:source.slice(node.start,node.end)});},
          ConditionalExpression(node,ancestors){branches.push({...siteFor(info,node,ancestors),kind:'conditional',test:source.slice(node.test.start,node.test.end)});},
          IfStatement(node,ancestors){branches.push({...siteFor(info,node,ancestors),kind:'if',test:source.slice(node.test.start,node.test.end)});}
        });
      }
    }
  }
  scan('src');return {files,strings,semanticIds,templates,branches};
}
function siteFor(info,node,ancestors){
  const enclosing=[...ancestors].reverse().find(a=>a.type==='FunctionDeclaration'||a.type==='FunctionExpression'||a.type==='ArrowFunctionExpression'||a.type==='MethodDefinition');
  const declaration=[...ancestors].reverse().find(a=>a.type==='VariableDeclarator');
  const exported=ancestors.find(a=>a.type==='ExportNamedDeclaration'||a.type==='ExportDefaultDeclaration');
  return {module:info.module,export:enclosing?.id?.name||propertyName(enclosing?.key)||declaration?.id?.name||(exported?'default':'<module>'),start:node.start,end:node.end,line:node.loc.start.line,column:node.loc.start.column,sourceFileSha256:info.sourceSha256};
}

export class CorpusInventory {
  constructor(root,out,index){
    this.root=root;this.out=out;this.index=index;this.protected=new ProtectedRegistry({locate:(value,owner)=>{const sites=this.locate(value,owner),site=sites[0]||this.index.semanticIds.get(owner.replace(/^[^:]+:/,''))?.[0];return site?{...site,candidateCount:sites.length,sourceCandidateFingerprint:sha256(value)}:{module:'<unresolved-typed-source>',export:'<schema>',sourceCandidateFingerprint:sha256(value)};}});this.messages=new Map();this.ambiguities=[];this.cases=[];this.totals={families:{},surfaces:{},classifications:{},sourceEnglishBytes:0};
    this.occurrences=new JsonlGzip(path.join(out,'occurrences.jsonl.gz'));
    this.presentationMetadata=new JsonlGzip(path.join(out,'presentation-metadata.jsonl.gz'));
    this.ambiguityKeys=new Set();this.sourceSites=new Set();
    this.locationCache=new Map();this.protectionCache=new WeakMap();this.sourceFingerprints=new Map();this.emptyReferences=[];
    this.messageSink=new JsonlGzip(path.join(out,'messages.jsonl.gz'));this.protectedSink=new JsonlGzip(path.join(out,'protected.jsonl.gz'));this.caseSink=new JsonlGzip(path.join(out,'completed-cases.jsonl.gz'));this.defaultsSink=new JsonlGzip(path.join(out,'registered-fields.jsonl.gz'));
    this.protected.onEntry=entry=>this.protectedSink.add(entry);this.seenStaticFields=new Set();this.defaultTokenFields=new Map();this.started=performance.now();this.checkpointPath=path.join(out,'checkpoints.jsonl');fs.writeFileSync(this.checkpointPath,'',{flag:'wx'});
  }
  checkpoint(stage,entry=null){
    for(const sink of [this.messageSink,this.protectedSink,this.occurrences,this.presentationMetadata,this.caseSink,this.defaultsSink])sink.flush();
    const memory=process.memoryUsage(),record={stage,...(entry?{caseId:entry.id,choiceId:entry.choiceId,variantId:entry.variant,subfixtureId:entry.member}:{}),completedCases:this.cases.length,messageUnits:this.messages.size,occurrences:this.occurrences.count,elapsedMs:Math.round(performance.now()-this.started),rssBytes:memory.rss,heapUsedBytes:memory.heapUsed};
    fs.appendFileSync(this.checkpointPath,JSON.stringify(record)+'\n');this.lastCheckpoint=record;
    if(stage!=='case-complete'||this.cases.length%100===0)console.log(JSON.stringify({inventoryCheckpoint:record}));
  }
  ambiguity(kind,owner,fieldPath,details){const key=stableJson({kind,owner,fieldPath,details});if(!this.ambiguityKeys.has(key)){this.ambiguityKeys.add(key);this.ambiguities.push({kind,owner,fieldPath,details});}}
  fingerprint(value){let result=this.sourceFingerprints.get(value);if(!result){result=sha256(value);this.sourceFingerprints.set(value,result);}return result;}
  declaration(owner,context={}){const id=owner.replace(/^[^:]+:/,'');return owner.startsWith('field:')?this.declarations?.fields.get(id):owner.startsWith('lesson:')?this.declarations?.models.get(id):this.declarations?.models.get(context.modelId||context.scenarioId);}
  locate(english,owner,preferred){
    preferred||=this.declaration(owner)?.module;
    const cacheKey=owner+'\0'+(preferred||'')+'\0'+this.fingerprint(english);
    if(this.locationCache.has(cacheKey))return this.locationCache.get(cacheKey);
    const sites=this.index.strings.get(english)||[];
    const ownerSites=this.index.semanticIds.get(owner.replace(/^[^:]+:/,''))||[];
    const modules=new Set([preferred,...ownerSites.map(s=>s.module)].filter(Boolean));
    const selected=sites.filter(s=>modules.has(s.module));
    const result=selected.length?selected:sites;this.locationCache.set(cacheKey,result);return result;
  }
  add(owner,fieldPath,english,context={},options={}){
    if(typeof english!=='string'||!english.trim())return;
    const declared=this.declaration(owner,context),sites=options.site?[options.site]:this.locate(english,owner,options.module||declared?.module);
    const owners=this.index.semanticIds.get((context.scenarioId||owner.replace(/^[^:]+:/,'')))||[];
    const source=(new Set(sites.map(site=>site.module)).size>1?declared:null)||sites[0]||declared||owners[0]||{module:options.module||'<unresolved-source-factory>',export:options.export||'<generated>'};
    const references=options.references||this.emptyReferences;let cache=this.protectionCache.get(references);
    if(!cache){cache=new Map();this.protectionCache.set(references,cache);}
    const protectionKey=JSON.stringify([english,owner,fieldPath,source.module,options.standard,context.protocol]);
    let protection=cache.get(protectionKey);
    if(!protection){
      protection=this.protected.references(english,references,{ui:owner.startsWith('ui:'),ownerId:owner,fieldPath,sourceModule:source.module,standard:options.standard,protocol:context.protocol});
      if(this.runtimeProjectionTokens?.size)protection={...protection,parameters:Object.fromEntries(Object.entries(protection.parameters).map(([name,definition])=>[name,[...this.runtimeProjectionTokens].some(token=>definition.value?.includes(token))?{...definition,dynamic:true}:definition]))};
      cache.set(protectionKey,protection);
    }
    if(options.parameters)protection={...protection,parameters:{...protection.parameters,...options.parameters}};
    const sourceSha256=this.fingerprint(english);
    const semanticContext={...(context.operationKind?{operationKind:context.operationKind}:{}),...(context.binding?{binding:context.binding}:{})};
    const runtimeContext=options.runtimeContext||(fieldPath.startsWith('searchVariants.')?{variantId:context.variantId}:{});
    const identity={module:source.module,export:source.export,semanticId:owner,fieldPath,sourceSha256,semanticContext,runtimeContext,runtime:options.runtime!==false,parameters:protection.parameters};
    const key=options.key||'message:'+sha256(stableJson(identity)).slice(0,32);
    if(!this.messages.has(key)){
      this.messages.set(key,{key,owner:{module:source.module,export:source.export,semanticId:owner,fieldPath,...(context.scenarioId?{scenarioId:context.scenarioId}:{}),...(declared?{declaration:declared}:{})},english,sourceSha256,parameters:protection.parameters,protectedReferences:protection.protectedReferences,classification:protection.classification,template:protection.template,context:semanticContext,sourceSites:sites.length<=8?sites:[],sourceCandidateFingerprint:sourceSha256,sourceCandidateCount:sites.length,sourceBinding:sites.length?'exact-syntax-literal':declared||owners.length?'semantic-factory-realization':'unresolved'});
      Object.assign(this.messages.get(key),{runtime:options.runtime!==false,runtimeContext,...(options.templateContract?{templateContract:options.templateContract}:{}),...(options.composedFrom?{composedFrom:options.composedFrom}:{})});
      this.messages.get(key).protectionContext={...(options.standard?{standard:options.standard}:{}),...(context.protocol?{protocol:context.protocol}:{})};
      if(options.auditReason)this.messages.get(key).auditReason=options.auditReason;
      if(protection.ambiguousReferences.length)this.ambiguity('unclassified-uppercase-fragments',owner,fieldPath,{sourceSha256,references:protection.ambiguousReferences});
      this.totals.sourceEnglishBytes+=bytes(english);
      this.totals.classifications[protection.classification]=(this.totals.classifications[protection.classification]||0)+1;
      if(!sites.length)this.ambiguity(declared||owners.length?'generated-source-binding':'unresolved-source-binding',owner,fieldPath,{sourceSha256,module:source.module,context:semanticContext});
      if(new Set(sites.map(site=>site.module)).size>1)this.ambiguity('multiple-source-module-candidates',owner,fieldPath,{sourceSha256,modules:[...new Set(sites.map(site=>site.module))]});
      for(const site of sites)this.sourceSites.add(site.module+':'+site.start);
      this.messageSink.add(this.messages.get(key));
    }
    else if(options.key&&this.messages.get(key).english!==english)this.ambiguity('explicit-key-source-conflict',owner,fieldPath,{key,firstSourceSha256:this.messages.get(key).sourceSha256,sourceSha256,site:options.site});
    const surface=options.surface||owner.split(':')[0],family=context.family||'shared';
    const binding={ownerId:owner,fieldPath,...context,surface,sourceSha256};
    this.occurrences.add({id:'occurrence:'+sha256(stableJson(binding)).slice(0,32),messageKey:key,...binding,...(options.templateContract?{templateKey:options.templateContract.key}:{})});
    for(const [group,name] of [[this.totals.surfaces,surface],[this.totals.families,family]]){group[name]||={occurrences:0,englishBytes:0};group[name].occurrences++;group[name].englishBytes+=bytes(english);}
    return key;
  }
  fields(record,owner,context,options={}){
    if(!record||typeof record!=='object')return;
    this.protected.record(record,owner,{module:options.module,fieldRole:options.prefix});
    options={...options,standard:record.standard||options.standard};
    if(owner.startsWith('field:')){
      const references=[...(options.references||[])],id=owner.slice(6);
      if(record.name)references.push({value:record.name,formal:true,kind:'field-name',owner,sourcePath:owner+'.name'});
      for(const binding of this.runtimeFieldBindings?.get(id)||[])references.push({value:binding.example,formal:true,dynamic:true,kind:'runtime-binding-example',owner,sourcePath:owner+'.runtimeBindings.'+binding.field});
      options={...options,references};
    }
    for(const field of options.fields||HUMAN_FIELDS){
      const value=record[field],fieldPath=(options.prefix?options.prefix+'.':'')+field;
      const alias=owner.startsWith('field:')&&['description','generator'].includes(field),fieldOptions=alias?{...options,runtime:false,auditReason:'canonical-definition-fallback-alias'}:options;
      if(typeof value==='string'){
        const identifier=field==='label'?[record.id,record.value].find(id=>typeof id==='string'&&(value===id||value.startsWith(id+':'))):null;
        this.add(owner,fieldPath,value,context,identifier?{...fieldOptions,references:[...(options.references||[]),{value:identifier,formal:true,kind:'identifier',owner,sourcePath:owner+'.id'}]}:fieldOptions);
        if(owner.startsWith('field:')&&field==='meaning'||owner.startsWith('topic:')&&field==='summary')this.realmVariants(owner,fieldPath,value,context,fieldOptions);
      }
      else if(Array.isArray(value)){
        const seen=new Map();
        for(const item of value){
          if(typeof item!=='string'){if(item!=null)this.ambiguity('non-string-human-array',owner,fieldPath,{type:typeof item,canonicalValue:compactEncode(item)});continue;}
          const fingerprint=sha256(item).slice(0,20),duplicate=seen.get(fingerprint)||0;seen.set(fingerprint,duplicate+1);
          // The source fingerprint and semantic slot survive unrelated insertions.
          const binding=fieldPath+':source:'+fingerprint+(duplicate?':duplicate:'+duplicate:'');
          if(duplicate)this.ambiguity('duplicate-array-source',owner,fieldPath,{fingerprint,duplicate});
          this.add(owner,fieldPath,item,{...context,binding},fieldOptions);
        }
      }else if(value&&typeof value==='object'&&!(field==='cryptoDetail'&&options.prefix==='profile'))this.ambiguity('structured-human-field',owner,fieldPath,{keys:Object.keys(value),canonicalValue:compactEncode(value)});
    }
    if(owner.startsWith('field:'))for(const [primary,fallback] of [['meaning','description'],['origin','generator']])if(!record[primary]&&typeof record[fallback]==='string')this.add(owner,primary,record[fallback],{...context,canonicalSourceField:fallback},options);
  }
  realmVariants(owner,fieldPath,english,context,options){
    if(!/\bB\b/.test(english))return;
    for(const [realm,replacement] of [['single','Realm A'],['direct','the web application'],['external','the upstream provider']]){
      const references=realm==='single'?[...(options.references||[]),{value:replacement,formal:true,kind:'realm-display-name',owner:'runtime-realm:single',sourcePath:'src/app.js:realm-reference'}]:options.references;
      this.add(owner,fieldPath,english.replace(/\bB\b/g,replacement),{...context,binding:'realm-reference:'+realm},{...options,references,runtimeContext:{...(options.runtimeContext||{}),realm},templateContract:{kind:'canonical-English-render-transform',originalEnglishSha256:sha256(english),realm,factory:{module:'src/app.js',export:'AuthFlowStudio',methods:['renderAttributeTopics','traceHtml']}}});
    }
  }
  list(records,owner,pathName,context,options={}){
    for(const record of records||[]){
      if(!record||typeof record!=='object')continue;
      const id=record.id??record.attributeId??record.artifactId??record.fieldId??record.path??record.key??record.name??record.value;
      const binding=id!==undefined?String(id):'source:'+sha256(stableJson(record)).slice(0,20);
      this.fields(record,owner,{...context,binding:pathName+':'+binding},{...options,prefix:pathName});
    }
  }
  model(model,context,refs){
    if(!model)return;
    const owner='lesson:'+model.id,options={references:refs};
    this.fields(model,owner,context,options);
    if(typeof model.category==='string')this.add(owner,'category',model.category,context,options);
    for(const field of ['family','workspace'])if(typeof model[field]==='string')this.protected.add('identifier',model[field],owner,field);
    this.fields(model.profile,owner,context,{...options,prefix:'profile'});
    this.add(owner,'status',model.status,context,options);
    if(typeof model.clientKind==='string')this.add(owner,'clientKind',model.clientKind,context,{...options,references:[...refs,{value:model.clientKind,formal:true,kind:'client-kind',owner,sourcePath:'clientKind'}]});
    if(Array.isArray(model.profile?.startingSummary))this.add(owner,'profile.startingSummary.joined',model.profile.startingSummary.join(' '),context,options);
    if(Array.isArray(model.prerequisites))this.add(owner,'prerequisites.startingSummary',model.prerequisites.slice(0,2).join(' '),context,options);
    for(const fieldPath of ['numericalVerification','clock','encoded','binding.publicKeyEncoding']){
      const value=fieldPath.split('.').reduce((record,key)=>record?.[key],model.profile?.cryptoDetail);
      this.add(owner,'profile.cryptoDetail.'+fieldPath,value,context,options);
    }
    for(const source of model.profile?.sources||[])this.add(owner,'profile.sources.errata',source.errata,{...context,binding:'profile.sources:'+JSON.stringify([source.url,source.standard,source.section])},options);
    if(typeof model.pamConfiguration?.revision==='string')this.protected.add('configuration-revision',model.pamConfiguration.revision,owner,'pamConfiguration.revision');
    this.fields(model.pamConfiguration,owner,context,{...options,prefix:'pamConfiguration',fields:['assumption']});
    this.fields(model.fixture,owner,context,{...options,prefix:'fixture',fields:['evidence']});
    if(typeof model.threatExplanation==='string')this.add(owner,'threatExplanation',model.threatExplanation,context,options);
    for(const field of ['variantChoices','subfixtureChoices','chapters','chapterComparison','profileControls','runtimeBindings','decisionBindings'])this.list(model[field],owner,field,context,options);
    for(const related of model.relatedLessons||[])this.fields(related,owner,{...context,binding:'relatedLessons:'+related.id+'|'+(related.variantId||'default'),sourceOrigin:'authored'},{...options,prefix:'relatedLessons',fields:['title','summary']});
    for(const variant of model.variantChoices||[])this.fields(variant,owner,{...context,variantId:variant.id,binding:'searchVariants:'+variant.id},{...options,prefix:'searchVariants',fields:['label','description']});
    for(const control of model.profileControls||[])this.list(control.options,owner,'profileControls['+control.id+'].options',context,options);
    for(const decision of model.decisionBindings||[])for(const [value,label] of Object.entries(decision.values||{}))this.add(owner,'decisionBindings.values',label,{...context,binding:'decision:'+decision.path+':'+value},options);
    this.fields(model.protocolTimeline,owner,context,{...options,prefix:'protocolTimeline'});
    for(const entry of model.protocolTimeline?.entries||[])this.fields(entry,owner,{...context,binding:'protocolTimeline.entries:'+entry.id},{...options,prefix:'protocolTimeline.entries.'+entry.id,fields:['label','detail','onElapsed']});
    this.fields(model.dnssecContext,owner,context,{...options,prefix:'dnssecContext'});
    this.list(model.dnssecContext?.records,owner,'dnssecContext.records',context,options);
  }
  step(step,context,refs,surface='step'){
    const sourceId=step.sourceStepId||step.id,owner='step:'+sourceId,options={references:refs,surface};
    this.protected.add('phase',step.phase,owner,'phase');
    if(surface==='attribute-trace'){
      this.fields(step,owner,context,{...options,runtime:false,fields:[...HUMAN_FIELDS].filter(field=>!['title','summary','detail'].includes(field))});
      const names=(step.payload||[]).map(payload=>payload.name).join(', ');
      this.add(owner,'title',step.title,context,{...options,runtime:false,templateContract:{key:'ui.trace.title.'+step.traceKind,parameters:{names:{kind:'protected',value:names,dynamic:true}},factory:{module:'src/attribute-trace.js',export:'buildAttributeTrace',slot:'emit.title'}}});
      const composedFrom=(step.traceActions||[]).map(action=>({ownerId:owner,fieldPath:'attributeOperations.detail',context:{attributeId:action.attributeId,actorId:action.actorId,operationKind:action.kind,messageId:action.messageId}}));
      for(const field of ['summary','detail'])this.add(owner,field,step[field],context,{...options,runtime:false,composedFrom});
    }else this.fields(step,owner,context,options);
    // Detailed DNSSEC message projections can contain more fields than the
    // overview payload. Both are actual renderer consumers of this same slot.
    const payloadBindings=new Set();
    const detailed=new Set(step.detailedPayload||[]),sharedDescription=/^step:lab-dnssec\d+:/.test(owner)&&detailed.size>0;
    if(sharedDescription&&[...detailed].some(payload=>payload.description!==step.detailedPayload[0].description))throw new Error('DNSSEC detailed descriptions no longer share their source argument: '+sourceId);
    for(const payload of [...step.payload||[],...step.detailedPayload||[]]){
      const identity=stableJson([payload.attributeId,payload.name,payload.description]);if(payloadBindings.has(identity))continue;payloadBindings.add(identity);
      this.protected.record(payload,owner,{fieldRole:'payload'});
      const runtimeContext=sharedDescription&&detailed.has(payload)?{}:{...(payload.attributeId?{attributeId:payload.attributeId}:{}),...(payload.name!==undefined?{payloadName:payload.name}:{})};
      const action=step.traceActions?.find(item=>item.attributeId===payload.attributeId),references=action?.carriedAs?[...refs,{value:action.carriedAs,formal:true,kind:'representation-name',owner,sourcePath:'attributeOperations.carriedAs'}]:refs;
      const carriedTemplate=surface==='attribute-trace'&&!detailed.has(payload)&&typeof action?.carriedAs==='string'&&typeof payload.description==='string'?{runtime:false,auditReason:'generic-trace-carried-container-ui-template',templateContract:{key:'ui.trace.carried-inside',english:'Carried inside {container}.',parameters:{container:{kind:'protected',value:action.carriedAs,dynamic:true}},factory:{module:'src/attribute-trace.js',export:'buildAttributeTrace',slot:'payload.description'}}}:{};
      this.add(owner,'payload.description',payload.description,{...context,...runtimeContext,binding:'payload:'+stableJson(runtimeContext)},{...options,references,runtimeContext,...carriedTemplate});
    }
    for(const layer of step.layers||[]){
      const runtimeContext={protocol:layer.protocol,transport:layer.transport,from:layer.from,to:layer.to};
      this.fields(layer,owner,{...context,binding:'layers:'+stableJson(runtimeContext)},{...options,prefix:'layers',fields:['protection'],runtimeContext});
    }
    this.fields(step.pamEvaluation,owner,context,{...options,prefix:'pamEvaluation',fields:['inapplicable','skipStopReason']});
    this.fields(step.pamEvaluation?.resourceConfiguration,owner,context,{...options,prefix:'pamEvaluation.resourceConfiguration',fields:['applicationResult']});
    this.fields(step.pamRelatedLesson,owner,context,{...options,prefix:'pamRelatedLesson',fields:['title']});
    for(const action of step.traceActions||step.attributeOperations||[])this.action(action,sourceId,context,refs,surface);
    // Protocol-effect values are canonical state, rendered with formatProtocolValue.
    // Explanatory workstation projections are collected from the actual snapshots.
  }
  action(action,sourceId,context,refs,surface='attribute-operation'){
    const runtimeContext={attributeId:action.attributeId,actorId:action.actorId,operationKind:action.kind,...(action.messageId!==undefined?{messageId:action.messageId}:{})};
    this.add('step:'+sourceId,'attributeOperations.detail',action.detail,{...context,...runtimeContext,binding:'operation:'+stableJson({...runtimeContext,exactValueRef:action.exactValueRef})},{references:refs,surface,runtimeContext});
  }
}
function decodePresentation(value){
  const [tag,data]=value;
  if(tag==='undefined')return undefined;if(tag==='null')return null;
  if(tag==='string'||tag==='boolean')return data;if(tag==='number')return data==='-0'?-0:Number(data);
  if(tag==='array')return data.map(decodePresentation);
  if(tag==='object')return Object.fromEntries(data.map(([key,item])=>[key,decodePresentation(item)]));
  if(tag==='map')return new Map(data.map(([key,item])=>[decodePresentation(key),decodePresentation(item)]));
  if(tag==='set')return new Set(data.map(decodePresentation));
  throw new Error('Unsupported retained presentation tag: '+tag);
}

// Replays only the display projector against durable English definitions. No
// fixture, variant, subfixture, steps or protocol model is constructed here.
export async function replayPresentationProjection({input,out,root}){
  const summary=JSON.parse(fs.readFileSync(path.join(input,'summary.json'),'utf8'));
  root=fs.realpathSync(root||summary.root);out=path.resolve(out);fs.mkdirSync(out,{recursive:false});
  const sources=new Map([...summary.inheritedArtifacts||[],...summary.artifacts.map(artifact=>({...artifact,path:artifact.path||path.join(input,artifact.file)}))].map(artifact=>[artifact.file,artifact.path]));
  const source=name=>sources.get(name)||path.join(input,name),definitions=new Map(),cases=new Map(),index=indexSources(root);
  for await(const entry of readJsonlGzip(source('registered-fields.jsonl.gz')))definitions.set(entry.id,decodePresentation(entry.value));
  for await(const entry of readJsonlGzip(source('completed-cases.jsonl.gz')))cases.set(entry.id,entry);
  const inventory=new CorpusInventory(root,out,index),{RuntimeEnvironment}=await importAt(root,'src/runtime-environment.js'),environment=new RuntimeEnvironment();
  const fields=['meaning','description','origin','generator','purpose'],candidateCache=new Map();let metadataCases=0,projectedFields=0;
  for await(const metadata of readJsonlGzip(source('presentation-metadata.jsonl.gz'))){
    const entry=cases.get(metadata.caseId);if(!entry)throw new Error('Presentation metadata without durable completed case: '+metadata.caseId);
    metadataCases++;const value=decodePresentation(metadata.value),options=value.environmentOptions||{},projection=value.projection;
    const resolved=environment._resolve(options);
    if(stableJson([...resolved.map])!==stableJson([...projection.map])||stableJson([...resolved.hosts])!==stableJson([...projection.hosts]))throw new Error('Retained projector mapping mismatch: '+metadata.caseId);
    const tokens=[...new Set([...resolved.map.keys(),...resolved.hosts.keys()])],signature=stableJson(tokens.sort());
    let candidates=candidateCache.get(signature);
    if(!candidates){candidates=[];for(const [id,definition] of definitions)if(fields.some(field=>typeof definition[field]==='string'&&tokens.some(token=>definition[field].includes(token))))candidates.push(id);candidateCache.set(signature,candidates);}
    inventory.runtimeProjectionTokens=new Set([...resolved.map.values(),...resolved.hosts.values()]);
    const references=Object.entries(value.actorContexts||{}).flatMap(([actor,rows])=>(rows||[]).filter(row=>typeof row.value==='string'&&row.value).map(row=>({value:row.value,formal:true,dynamic:true,kind:'runtime-context-value',owner:'actor:'+actor,sourcePath:'actor:'+actor+'.contextRows.'+row.key+'.value'})));
    const context={caseId:entry.id,scenarioId:entry.choiceId,variantId:entry.variant,subfixtureId:entry.member,family:entry.family||'core',binding:'retained-projector-replay'};
    for(const id of candidates){
      const definition=definitions.get(id),projected=environment.projectDefinition(id,definition,options),overridden=new Set(metadata.fieldDefaults?.overrides?.[id]||[]);
      const changed=fields.filter(field=>!overridden.has(field)&&typeof projected[field]==='string'&&projected[field]!==definition[field]);
      if(!changed.length)continue;
      projectedFields+=changed.length;inventory.fields(projected,'field:'+id,context,{references,fields:changed,module:'src/runtime-environment.js',export:'RuntimeEnvironment.projectDefinition'});
    }
  }
  const artifacts=[inventory.messageSink,inventory.protectedSink,inventory.occurrences,inventory.presentationMetadata,inventory.caseSink,inventory.defaultsSink].map(sink=>sink.close()),ambiguitySink=new JsonlGzip(path.join(out,'ambiguities.jsonl.gz'));
  for(const ambiguity of inventory.ambiguities)ambiguitySink.add(ambiguity);artifacts.push(ambiguitySink.close());
  const result={schemaVersion:1,kind:'retained-presentation-projector-replay',root,canonicalEvaluations:0,caseEvaluationScope:'supplement-only-never-adds-case-coverage',sourceFiles:summary.sourceFiles,counts:{metadataCases,projectedFields,uniqueMessageUnits:inventory.messages.size,occurrenceBindings:inventory.occurrences.count},artifacts,collectorFiles:COLLECTOR_FILES,projectionContract:{module:'src/runtime-environment.js',export:'RuntimeEnvironment.projectDefinition',sourceSha256:index.files.get('src/runtime-environment.js').sourceSha256,selection:'Exact substring candidate discovery; canonical projector retains URI prefix/query/fragment boundaries. Overridden fields are already retained and never replaced with defaults.'}};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});return result;
}

// Recover the shared DNSSEC description argument, not missing protocol values.
// No model, source step, operation ledger or case is constructed by this pass.
export async function declareDetailedPayloadDescriptions({input,out,root}){
  const encoded=fs.readFileSync(path.join(input,'summary.json')),summary=JSON.parse(encoded);
  root=fs.realpathSync(root||summary.root);out=path.resolve(out);
  const sources=new Map([...summary.inheritedArtifacts||[],...summary.artifacts.map(artifact=>({...artifact,path:artifact.path||path.join(input,artifact.file)}))].map(artifact=>[artifact.file,artifact.path]));
  const source=name=>sources.get(name)||path.join(input,name),index=indexSources(root),module='src/dnssec-authoring.js',info=index.files.get(module);
  if(!info||summary.sourceFiles.find(file=>file.module===module)?.sourceSha256!==info.sourceSha256)throw new Error('DNSSEC presentation source differs from the retained canonical input.');
  let presentation=null,local=null;
  walk.simple(info.ast,{
    FunctionDeclaration(node){if(node.id?.name==='dnssecAuthorPresentation')presentation=node;},
    VariableDeclarator(node){if(node.id?.name==='local'&&node.init?.type==='ArrowFunctionExpression')local=node.init;},
  });
  if(!presentation||!local)throw new Error('DNSSEC shared-description factory is unavailable.');
  const calls=node=>{const result=[];walk.simple(node,{CallExpression(call){result.push(call);}});return result;};
  const labPayloads=calls(presentation).filter(call=>call.callee.type==='Identifier'&&call.callee.name==='labP');
  if(labPayloads.length!==1||labPayloads[0].arguments[2]?.type!=='Identifier'||labPayloads[0].arguments[2].name!=='description')throw new Error('Detailed payload no longer forwards its shared description argument.');
  const localCalls=calls(local),projection=localCalls.find(call=>call.callee.type==='Identifier'&&call.callee.name==='dnssecAuthorPresentation'),step=localCalls.find(call=>call.callee.type==='Identifier'&&call.callee.name==='labStep');
  if(projection?.arguments[1]?.type!=='Identifier'||projection.arguments[1].name!=='detail'||step?.arguments[7]?.type!=='Identifier'||step.arguments[7].name!=='detail')throw new Error('Local detail and detailed-payload description no longer share their source argument.');
  const andParts=node=>node.type==='LogicalExpression'&&node.operator==='&&'?[...andParts(node.left),...andParts(node.right)]:[node];
  const member=(node,object,property)=>node?.type==='MemberExpression'&&!node.computed&&node.object.type==='Identifier'&&node.object.name===object&&node.property.name===property;
  let overviewGuarantee=false;
  walk.simple(presentation,{IfStatement(node){
    const terms=andParts(node.test);
    if(terms.length!==3||!terms.some(term=>term.type==='Identifier'&&term.name==='message')||!terms.some(term=>term.type==='UnaryExpression'&&term.operator==='!'&&member(term.argument,'payload','length'))||!terms.some(term=>member(term,'detailedPayload','length')))return;
    overviewGuarantee=calls(node.consequent).some(call=>member(call.callee,'payload','push')&&call.arguments[0]?.type==='MemberExpression'&&call.arguments[0].object.name==='detailedPayload'&&call.arguments[0].computed&&call.arguments[0].property.value===0);
  }});
  if(!overviewGuarantee)throw new Error('Message detailed items are no longer guaranteed an overview representative.');
  const descriptions=new Set(),details=new Map();
  for await(const message of readJsonlGzip(source('messages.jsonl.gz'))){
    if(message.runtime===false||!/^step:lab-dnssec\d+:/.test(message.owner?.semanticId||''))continue;
    if(message.owner.fieldPath==='payload.description')descriptions.add(message.owner.semanticId);
    if(message.owner.fieldPath!=='detail')continue;
    const signature=stableJson({english:message.english,parameters:semanticParameters(message.parameters)}),previous=details.get(message.owner.semanticId);
    if(previous&&previous.signature!==signature)throw new Error('Ambiguous retained DNSSEC detail argument: '+message.owner.semanticId);
    details.set(message.owner.semanticId,{signature,message});
  }
  fs.mkdirSync(out,{recursive:false});
  const sinks=Object.fromEntries(['messages','occurrences','protected','completed-cases','presentation-metadata','registered-fields','ambiguities'].map(name=>[name,new JsonlGzip(path.join(out,name+'.jsonl.gz'))]));
  const parentKeys=new Map(),requiredProtected=new Set(),seenParents=new Set();
  const factory={module,export:'dnssecAuthorPresentation',sourceFileSha256:info.sourceSha256,expression:'Every detailed labP.description receives the same description argument; local forwards that exact argument to sourceStep.detail.',sourceSpan:{start:presentation.start,end:presentation.end},localSpan:{start:local.start,end:local.end}};
  for(const [owner,{message:parent}]of details){
    if(descriptions.has(owner))continue;
    const sourceDeclared={kind:'dnssec-shared-detailed-description',execution:'source-derived-slot-association; no additional branch, field or case execution claimed',factory,parent:{key:parent.key,semanticId:owner,fieldPath:'detail',sourceSha256:parent.sourceSha256},condition:'A source step with detailed items but no overview representative is local: message factories retain an overview representative. Its detailed descriptions share the retained detail argument.'};
    const identity={owner,fieldPath:'payload.description',sourceSha256:parent.sourceSha256,parameters:semanticParameters(parent.parameters),factory:info.sourceSha256},key='message:'+sha256(stableJson(identity)).slice(0,32);
    const message={...parent,key,owner:{...parent.owner,module,export:'dnssecAuthorPresentation',fieldPath:'payload.description'},context:{binding:'dnssecAuthorPresentation.description'},runtime:true,runtimeContext:{},sourceBinding:'explicit-semantic-producer',sourceProducer:factory,sourceDeclared};
    delete message.templateContract;delete message.auditReason;delete message.composedFrom;
    sinks.messages.add(message);parentKeys.set(parent.key,{key,sourceDeclared});
    for(const reference of parent.protectedReferences||[])if(reference.registryId)requiredProtected.add(reference.registryId);
  }
  for await(const occurrence of readJsonlGzip(source('occurrences.jsonl.gz'))){
    const projected=parentKeys.get(occurrence.messageKey);if(!projected)continue;seenParents.add(occurrence.messageKey);
    const {runtimeMessageKey,templateKey,...retained}=occurrence;
    sinks.occurrences.add({...retained,id:'source-occurrence:'+sha256(stableJson([occurrence.id,projected.key])).slice(0,32),messageKey:projected.key,fieldPath:'payload.description',surface:'source-declared-detailed-description',sourceDeclared:projected.sourceDeclared});
  }
  if(seenParents.size!==parentKeys.size)throw new Error('Retained detail occurrence missing for a projected DNSSEC owner.');
  for await(const entry of readJsonlGzip(source('protected.jsonl.gz')))if(requiredProtected.delete(entry.id))sinks.protected.add(entry);
  if(requiredProtected.size)throw new Error('Retained detailed-description protected identities missing.');
  const result={schemaVersion:1,kind:'source-declared-dnssec-detailed-descriptions',root:summary.root,sourceFiles:summary.sourceFiles,canonicalEvaluations:0,caseEvaluationScope:'source-declaration-only-never-adds-case-coverage',input:{directory:path.resolve(input),summarySha256:sha256(encoded)},counts:{retainedStepDetailOwners:details.size,existingOverviewDescriptionOwners:descriptions.size,declaredSharedDescriptionOwners:sinks.messages.count,uniqueMessageUnits:sinks.messages.count,occurrenceBindings:sinks.occurrences.count},artifacts:Object.values(sinks).map(sink=>sink.close()),collectorFiles:COLLECTOR_FILES,projectionContract:factory,scope:'Exact retained description values and actual source-step owners; no protocol payload values or unseen field IDs are reconstructed. Per-field overview contexts normalize to this shared source argument during classification.'};
  fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});return result;
}


async function collectCase(inventory,registry,entry,modules){
  const fixture=registry.makeHeldObjectFixture(entry.choiceId,{...entry.configuration,lessonVariant:entry.variant,lessonSubfixture:entry.member});
  const {app,model,steps,actors,config}=fixture;
  for(const [field,value] of Object.entries(config))if(['string','number','boolean'].includes(typeof value))inventory.protected.add('configuration-value',String(value),'configuration:'+entry.id,field);
  const context={scenarioId:entry.choiceId,modelId:model?.id,variantId:entry.variant,subfixtureId:entry.member,caseId:entry.id,family:model?.family||model?.workspace||'core'};
  const selectedIds=new Set([...(model?.catalogAttributeIds||model?.ids||[]),...steps.flatMap(step=>[...(step.fields||[]),...(step.attributeOperations||[]).map(action=>action.attributeId)]),...Object.values(actors).flatMap(actor=>(actor.attributes||[]).map(field=>field.id))]);
  const activeIds=new Set(steps.flatMap(step=>[...(step.fields||[]),...(step.payload||[]).map(payload=>payload.attributeId),...(step.attributeOperations||[]).map(action=>action.attributeId)]).filter(Boolean));
  app.definition(activeIds.values().next().value||'clientIdApp');
  const changedIds=new Set(),humanFields=['meaning','description','origin','generator','purpose'];
  for(const [id,override] of Object.entries(app.definitionMemo.overrides)){
    const baseline=inventory.defaultDefinitions[id]||{};
    if([...humanFields,'name','example'].some(field=>override[field]!==undefined&&override[field]!==baseline[field]))changedIds.add(id);
  }
  const resolved=app.runtimeEnvironment._resolve(app.environmentOptions);
  inventory.projectionTokenCache||=new Map();
  for(const token of [...resolved.map.keys(),...resolved.hosts.keys()]){
    let fields=inventory.projectionTokenCache.get(token);
    if(!fields){fields=new Set();for(const [value,ids] of inventory.defaultTokenFields)if(value.includes(token))for(const id of ids)fields.add(id);inventory.projectionTokenCache.set(token,fields);}
    for(const id of fields)changedIds.add(id);
  }
  const ids=new Set([...activeIds,...changedIds]),definitions=new Map([...ids].map(id=>[id,changedIds.has(id)||!inventory.defaultDefinitions[id]?app.definition(id):inventory.defaultDefinitions[id]])),actorContexts=Object.fromEntries(Object.keys(actors).map(id=>[id,app.actorContextRows(id)]));
  const refs=[];
  for(const [id,definition] of definitions){if(definition?.name)refs.push({value:definition.name,kind:'field-name',sourcePath:'field:'+id+'.name',owner:'field:'+id});if(changedIds.has(id))inventory.protected.record(definition,'field:'+id,{caseId:entry.id});}
  for(const [id,actor] of Object.entries(actors)){inventory.protected.record(actor,'actor:'+id);refs.push({value:id,formal:true,kind:'actor-identifier',sourcePath:'actor:'+id+'.id',owner:'actor:'+id});for(const field of ['name','role'])if(actor[field])refs.push({value:actor[field],formal:true,kind:'actor-'+field,sourcePath:'actor:'+id+'.'+field,owner:'actor:'+id});}
  for(const [field,value] of [['standard',model?.standard],['protocol',model?.protocol]])if(typeof value==='string'&&value)refs.push({value,formal:true,kind:field,owner:'lesson:'+entry.choiceId,sourcePath:field});
  for(const [id,rows] of Object.entries(actorContexts))for(const row of rows)if(typeof row.value==='string'&&row.value)refs.push({value:row.value,formal:true,dynamic:true,kind:'runtime-context-value',sourcePath:'actor:'+id+'.contextRows.'+row.key+'.value',owner:'actor:'+id});
  inventory.model(model,context,refs);
  for(const zone of model?.trustZones||[])if(!Object.values(actors).some(actor=>actor.name===zone.title))inventory.add('lesson:'+model.id,'trustZones.title',zone.title,{...context,binding:'trust-zone:'+zone.id},{references:refs,runtimeContext:{zoneId:zone.id},surface:'scenario-environment'});
  const fieldOverrides={};
  for(const [id,definition] of definitions){
    const baseline=inventory.defaultDefinitions[id]||{},fields=humanFields.filter(field=>definition?.[field]!==baseline[field]);
    if(fields.length){fieldOverrides[id]=fields;inventory.fields(definition,'field:'+id,context,{references:refs,fields});}
  }
  for(const [id,actor] of Object.entries(actors))inventory.fields(actor,'actor:'+id,context,{references:refs,fields:['plainRole','notes'],runtimeContext:{scenarioId:model?.id||entry.choiceId}});
  // Context values above are canonical projector outputs, never localized DOM.
  for(const [id,rows] of Object.entries(actorContexts))for(const row of rows)inventory.add('actor:'+id,'contextRows.'+row.key+'.label',row.label,{...context,binding:'contextRows:'+row.key},{references:refs,surface:'environment-context',runtimeContext:{scenarioId:model?.id||entry.choiceId,phase:'environment-context',rowKey:row.key}});
  const meta=modules.modeMetadata[app.mode];
  if(meta){
    const canonical=app.isSingleRealm?meta.description.replace(/the upstream provider/gi,'the Keycloak realm').replace(/upstream/gi,'Realm A'):meta.description;
    inventory.add('mode:'+app.mode,'description',canonical,{...context,projected:false},{references:refs,surface:'scenario-description'});
    inventory.add('mode:'+app.mode,'description',app.runtimeEnvironment.projectValue(canonical,app.environmentOptions),{...context,projected:true},{references:refs,surface:'scenario-description'});
  }
  if(app.advancedFlow)inventory.fields(app.advancedFlow,'lesson:'+(app.advancedFlow.id||app.oidcFlow),context,{references:refs,surface:'scenario-description',fields:['title','summary']});
  if(model)for(const related of modules.comparison.windowsSecurityRelatedLessons(model.id))inventory.fields(related,'lesson:'+model.id,{...context,binding:'relatedLessons:'+related.id+'|'+(related.variantId||'default'),sourceOrigin:'windows-security'},{references:refs,prefix:'relatedLessons',fields:['title','summary'],surface:'navigation'});
  for(const step of steps)inventory.step(step,context,refs);
  const usages=modules.usage.getAttributeUsage(steps,[...ids],app.authenticator);
  for(const usage of usages)for(const action of usage.actions)inventory.action(action,usage.step.id,context,refs);
  const trace=modules.trace.buildAttributeTrace(usages,app.examples||{});
  for(const step of trace)inventory.step(step,{...context,operationKind:step.traceKind,binding:[step.sourceStepId,step.traceKind,step.from,step.to,step.messageId||'',...(step.fields||[])].join(':')},refs,'attribute-trace');
  const heldModel=model?{...model,steps:()=>steps}:null;
  const compiled=modules.held.buildHeldObjects({...fixture,model:heldModel,contextId:entry.id});
  const plan=compiled.plan;
  for(const artifact of plan.artifacts||[]){
    const owner='artifact:'+artifact.artifactId;
    inventory.fields(artifact,owner,context,{references:refs,surface:'held-artifact'});
    for(const status of ['Currently held','Not created','Not yet held','No longer held'])inventory.add(owner,'holdingStatus',status,{...context,binding:'holdingStatus:'+status},{references:refs,surface:'held-generated-status',module:'src/held-study-state.js'});
    for(const representation of artifact.representations||[]){inventory.protected.record(representation,owner);for(const field of representation.fields||[])inventory.protected.record(field,owner,{fieldRole:'representation.fields'});}
    for(const event of modules.heldState.heldObjectTrace(compiled,artifact.artifactId)){
      const traceContext={...context,binding:[event.sourceStepId||'initial',event.inspectionActorId||event.from||'',event.traceKind||'',event.messageId||'',event.holdingId||'',event.representationId||''].join(':')};
      const traceRefs=[...refs,...(event.traceKind==='initial'?[]:(event.traceKind||'').split('/')).map(value=>({value,formal:true,kind:'operation-kind',owner,sourcePath:'traceKind'}))];
      inventory.add(owner,'trace.title',event.title,traceContext,{references:traceRefs,surface:'held-trace',module:'src/held-object-state.js'});
      inventory.step({...event,title:undefined},traceContext,refs,'held-trace');
    }
  }
  const coverage=Array.isArray(plan.coverage)?plan.coverage:Object.values(plan.coverage||{});
  for(const item of coverage){inventory.fields(item,'actor:'+item.actorId,context,{references:refs,prefix:'coverage',surface:'coverage'});inventory.list(item.gaps,'actor:'+item.actorId,'coverage.gaps',context,{references:refs,surface:'coverage'});}
  for(const [sourceEventId,event] of Object.entries(plan.events||{}))for(const milestone of event.milestones||[])for(const effect of milestone.effects||[]){
    if(!['observe','authority'].includes(effect.op))continue;
    const owner=effect.op==='authority'?'authority:'+effect.authorityId:'observation:'+JSON.stringify([effect.sourceEventId||sourceEventId,effect.actorId,effect.kind,effect.requestId]);
    inventory.fields(effect,owner,{...context,binding:[sourceEventId,milestone.id,effect.artifactId,effect.representationId||'',effect.requestId||''].join(':')},{references:refs,fields:['detail'],surface:effect.op==='authority'?'authority':'observation'});
  }
  inventory.fields({limitations:plan.limitations},'lesson:'+entry.choiceId,context,{references:refs,fields:['limitations'],surface:'coverage'});
  const workstationPaths=['verdictExplanation','localComparisonQualification','policyComparison.label','policyComparison.configured.restrictionsDisplay','policyComparison.applied.restrictionsDisplay','policyComparison.polarity','policyComparison.appliedStatus','policyComparison.scope','tokenComparison.before.label','tokenComparison.before.scope','tokenComparison.before.nativeFields','tokenComparison.after.label','tokenComparison.after.nativeFields','tokenComparison.evidenceLevel','tokenComparison.policyAtContextCreation.label','tokenComparison.policyAtContextCreation.polarity','tokenComparison.policyAtContextCreation.appliedStatus','tokenComparison.policyAtContextCreation.scope'];
  for(let sourceIndex=-1;sourceIndex<steps.length;sourceIndex++){
    const snapshot=modules.heldState.projectHeldObjects(compiled,sourceIndex<0?undefined:{eventIndex:sourceIndex,milestone:'complete'}),sourceEventId=steps[sourceIndex]?.id||'initial';
    for(const pathName of workstationPaths){
      const value=pathName.split('.').reduce((record,key)=>record?.[key],snapshot.state?.workstation);
      if(typeof value!=='string')continue;
      inventory.add('lesson:'+entry.choiceId,'snapshot.state.workstation.'+pathName,value,{...context,sourceEventId},{references:refs,surface:'projected-state'});
    }
    const endedBy=snapshot.state?.sessions?.idp?.endedBy;
    if(typeof endedBy==='string'&&/\s/.test(endedBy))inventory.add('lesson:'+entry.choiceId,'state.sessions.idp.endedBy',endedBy,{...context,sourceEventId},{references:refs,surface:'projected-state'});
  }
  inventory.presentationMetadata.add({caseId:entry.id,ownerId:'lesson:'+(model?.id||entry.choiceId),encoding:'compactEncode tagged canonical data',fieldDefaults:{registry:'registered-fields.jsonl.gz',allRegistered:true,selectedAttributeIds:[...selectedIds],overrides:fieldOverrides},value:compactEncode({profile:model?.profile,pamConfiguration:model?.pamConfiguration,fixtureEvidence:model?.fixture?.evidence,runtimeBindings:model?.runtimeBindings,protocolTimeline:model?.protocolTimeline,dnssecContext:model?.dnssecContext,relatedLessons:model?.relatedLessons,actorContexts,environmentOptions:app.environmentOptions,projection:{map:resolved.map,hosts:resolved.hosts},coverage:plan.coverage,limitations:plan.limitations})});
  const completed={...entry,family:context.family,counts:{steps:steps.length,actors:Object.keys(actors).length,selectedFieldIds:selectedIds.size,materializedDefinitions:definitions.size,explanatoryOverrides:Object.keys(fieldOverrides).length,attributeTraceSteps:trace.length,artifacts:plan.artifacts?.length||0,statePrefixes:steps.length+1}};
  inventory.cases.push(completed);inventory.caseSink.add(completed);inventory.checkpoint('case-complete',entry);
}

async function collectStatic(inventory,root){
  for(const name of STATIC_MODULES){
    if(!inventory.index.files.has(name))continue;
    const module=await importAt(root,name);
    for(const [exportName,value] of Object.entries(module)){
      if(!value||typeof value!=='object')continue;
      if(name==='src/lab-catalog.js'&&!['LAB_ATTRIBUTES','LAB_TOPICS','LAB_SOURCES'].includes(exportName))continue;
      const records=Array.isArray(value)?value:Object.entries(value).map(([key,record])=>typeof record==='object'&&record?{...record,__inventoryId:key}:null).filter(Boolean);
      for(const record of records){
        if(!record||typeof record!=='object')continue;
        const id=record.id||record.key||record.__inventoryId||'source:'+sha256(stableJson(record)).slice(0,20);
        const domain=exportName==='RUNTIME_ENVIRONMENT_FIELDS'?'environment-field:'+id:exportName==='RUNTIME_PROVIDER_FIELDS'?'environment-field:provider.'+id:exportName==='PROVIDER_PROFILES'?'provider:'+id:exportName==='JOURNEYS'||exportName==='FIDO_JOURNEYS'?'mode:'+id:exportName==='ARCHITECTURES'?'architecture:'+id:exportName==='UPSTREAMS'?'upstream:'+id:null;
        const owner=domain||(exportName==='WINDOWS_SECURITY_COMPARISONS'?'windows-security-comparison:'+record.targets?.[0]?.id:exportName==='SCENARIO_SEARCH_REGISTRY'||exportName==='LEARNING_PRESETS'?'lesson:'+id:exportName.includes('TOPIC')?'topic:'+id:exportName.includes('ATTRIBUTES')?'field:'+id:exportName.includes('ACTORS')?'actor:'+id:'registry:'+exportName+':'+id);
        if(owner.startsWith('field:')){
          if(inventory.seenStaticFields.has(id))continue;inventory.seenStaticFields.add(id);
          inventory.defaultsSink.add({id,encoding:'compactEncode',value:compactEncode(inventory.defaultDefinitions[id]||record)});
        }
        if(exportName.includes('SOURCES')){
          for(const [field,value] of Object.entries(record))if(typeof value==='string'&&SOURCE_CITATION_FIELDS.has(field))inventory.protected.add('official-citation',value,owner,field,{module:name,export:exportName});
          inventory.fields(record,'source:'+(record.url||id),{family:'sources'},{module:name,export:exportName,surface:'source-explanation',fields:['note','summary','description']});continue;
        }
        if(exportName!=='LEARNING_NOTES')inventory.fields(record,owner,{family:'shared'},{module:name,export:exportName,surface:'registry',...(domain?{fields:[...HUMAN_FIELDS,'name','factorCount','caveat']}:{})});
        if(exportName==='JOURNEYS'||exportName==='FIDO_JOURNEYS')inventory.fields(record,'lesson:'+id,{family:'configuration'},{module:name,export:exportName,surface:'learning-question',fields:['title']});
        if(exportName.includes('TOPIC')&&record.name)inventory.add(owner,'name',record.name,{family:'shared'},{module:name,export:exportName,surface:'topic'});
        if(exportName==='WINDOWS_SECURITY_COMPARISONS')for(const target of record.targets||[])inventory.add('lesson:'+target.id,'securityComparison.title',target.title,{scenarioId:target.id,variantId:target.variantId||'default',family:'navigation',binding:'security-comparison-target:'+target.id+':'+(target.variantId||'default')},{module:name,export:exportName,surface:'security-comparison'});
        if(exportName==='LEARNING_NOTES'){
          const fingerprint=sha256(record.title+'\0'+record.text),noteId=NOTE_BINDINGS_BY_FINGERPRINT.get(fingerprint)||'source-'+fingerprint.slice(0,24);
          inventory.fields(record,'learning-note:'+noteId,{family:'notes',binding:'protocol-data.LEARNING_NOTES:'+fingerprint},{module:name,export:exportName,surface:'learning-note',fields:['title','text']});
        }
      }
    }
  }
}

async function collectNavigation(inventory,registry,catalog){
  const workspace=await importAt(registry.root,'src/workspaces.js'),search=await importAt(registry.root,'src/scenario-search-metadata.js');
  for(const option of workspace.studioWorkspaceOptions(registry.LAB_MODELS))inventory.fields(option,'workspace-option:'+option.id,{family:'navigation'},{module:'src/workspaces.js',surface:'search',fields:['title','summary','category','selectedLabel']});
  for(const choice of catalog.choices){
    const owner='lesson:'+choice.id;
    inventory.fields({...choice,title:choice.label},owner,{scenarioId:choice.id,family:'navigation'},{surface:'search',fields:['title','summary','category']});
    const model=registry.LAB_MODELS[choice.modelId||choice.id]||registry.LEARNING_PRESETS.find(preset=>preset.id===choice.id);
    if(!model)continue;
    const metadata=search.createScenarioSearchMetadata(model,registry.LAB_ATTRIBUTES);
    inventory.fields(metadata,owner,{scenarioId:choice.id,family:'search'},{module:'src/scenario-search-metadata.js',surface:'search',fields:['title','summary','category','searchTags']});
    for(const variant of metadata.searchVariants||[]){
      const context={scenarioId:choice.id,variantId:variant.id,family:'search',binding:'searchVariants:'+variant.id};
      inventory.fields(variant,owner,context,{surface:'search',prefix:'searchVariants',fields:['label','searchTags']});
    }
  }
}

export function mergeUIContracts(inventory,bundle){
  if(!bundle||!Array.isArray(bundle.messages)||!Array.isArray(bundle.occurrences)||!Array.isArray(bundle.unresolved))throw new TypeError('UI sidecar requires messages, occurrences and unresolved arrays.');
  for(const entry of bundle.protectedReferences||[]){
    if(typeof entry?.id!=='string'||typeof entry.value!=='string'||entry.sourceSha256!==sha256(entry.value))throw new TypeError('Invalid UI protected registry entry.');
    if(!inventory.protected.entries.has(entry.id)){inventory.protected.entries.set(entry.id,entry);inventory.protected.onEntry?.(entry);}
  }
  const keys=new Set(inventory.messages.keys());let englishBytes=0;
  for(const contract of bundle.messages){
    if(!contract||typeof contract.key!=='string'||keys.has(contract.key)||!/^[a-f0-9]{64}$/.test(contract.sourceSha256||''))throw new TypeError('Invalid or duplicate source-bound UI contract.');
    if(contract.sourceSha256!==sha256(stableJson({english:contract.english,parameters:semanticParameters(contract.parameters)})))throw new TypeError('UI parameter/source fingerprint mismatch: '+contract.key);
    const unresolvedReferences=(contract.protectedReferences||[]).filter(reference=>{
      if(reference.registryId)return !inventory.protected.entries.has(reference.registryId);
      const definition=contract.parameters?.[reference.parameter];
      if(reference.dynamic!==true||definition?.dynamic!==true||typeof definition.sourcePath!=='string'||!definition.sourcePath)return true;
      return !bundle.occurrences.some(occurrence=>occurrence.messageKey===contract.key&&occurrence.parameters?.[reference.parameter]?.source&&occurrence.parameters[reference.parameter].sourceSha256===sha256(occurrence.parameters[reference.parameter].source)&&bundle.sourceFiles?.some(source=>source.module===occurrence.module&&source.sourceSha256===occurrence.sourceFileSha256));
    });
    if(unresolvedReferences.length)inventory.ambiguity('ui-protected-reference-registry-unavailable',contract.owner?.semanticId||'ui:'+contract.key,'message',{key:contract.key,registryIds:[...new Set(unresolvedReferences.map(reference=>reference.registryId))]});
    keys.add(contract.key);
    const forms=typeof contract.english==='string'?[contract.english]:Object.values(contract.english?.plural||{});
    if(!forms.length||forms.some(form=>typeof form!=='string'))throw new TypeError('UI English must be a string or explicit plural forms.');
    for(const form of forms)englishBytes+=bytes(form);
    for(const [name,definition] of Object.entries(contract.parameters||{}))if(definition.kind==='protected'&&typeof definition.value==='string')inventory.protected.add('ui-protected-parameter',definition.value,contract.owner?.semanticId||'ui:'+contract.key,definition.sourcePath||name,{module:contract.owner?.module,export:contract.owner?.export});
    const classification=contract.classification||'ambiguous';inventory.totals.classifications[classification]=(inventory.totals.classifications[classification]||0)+1;
  }
  for(const occurrence of bundle.occurrences){if(!keys.has(occurrence.messageKey))throw new TypeError('UI occurrence has no English contract.');inventory.occurrences.add(occurrence);}
  for(const record of bundle.unresolved)inventory.ambiguity('unresolved-explicit-ui-contract','ui',record.key||record.method||'source',record);
  inventory.totals.sourceEnglishBytes+=englishBytes;
  inventory.totals.surfaces['runtime-ui']={occurrences:bundle.occurrences.length,englishBytes,byteScope:'Unique contract English forms; not realized DOM byte estimates.'};
  inventory.totals.families.ui={...inventory.totals.surfaces['runtime-ui']};
  return bundle.messages;
}

export async function mergeRuntimeContracts(inventory,root){
  const {extractUIContracts}=await import('./ui-contracts.mjs');
  return mergeUIContracts(inventory,await extractUIContracts({root}));
}

export async function extractInventory({root,out,uiRoot=null,uiContracts=null,registeredOnly=false,caseIds=null}){
  root=fs.realpathSync(root);out=path.resolve(out);
  if(out===root||out.startsWith(root+path.sep)&&!out.startsWith(path.join(root,'docs/localization/inventory')+path.sep))throw new Error('Output must be a new external directory or owned docs/localization/inventory child');
  fs.mkdirSync(out,{recursive:false});
  const index=indexSources(root),inventory=new CorpusInventory(root,out,index),registry=await baselineRegistry(root,index);
  let catalog;
  if(caseIds){
    const selection=JSON.parse(fs.readFileSync(caseIds,'utf8')),manifest=selection.expectedManifest;
    if(!manifest?.path||!/^[a-f0-9]{64}$/.test(manifest.sha256||''))throw new TypeError('Case selection requires an exact expectedManifest path and SHA-256.');
    const encoded=fs.readFileSync(manifest.path);if(sha256(encoded)!==manifest.sha256)throw new Error('Expected case manifest fingerprint mismatch.');
    catalog=JSON.parse(encoded);const wanted=new Set(selection.caseIds);
    if(!Array.isArray(selection.caseIds)||wanted.size!==selection.caseIds.length||!wanted.size)throw new TypeError('Case selection must be a nonempty array of distinct IDs.');
    const cases=catalog.cases.filter(entry=>wanted.has(entry.id));
    if(cases.length!==wanted.size)throw new Error('Case selection contains unknown IDs.');
    catalog={...catalog,cases,counts:{...catalog.counts,selectedCases:cases.length}};
  }else catalog=registeredOnly?{choices:[],cases:[],counts:{pickerIdentities:new Set(['core',...registry.LEARNING_PRESETS.map(record=>record.id),...registry.LAB_SCENARIOS.map(record=>record.id)]).size,presets:registry.LEARNING_PRESETS.length,registeredModels:Object.keys(registry.LAB_MODELS).length}}:compactEnumerate(registry);
  inventory.declarations=registry.declarations;
  inventory.defaultDefinitions=(await importAt(root,'src/protocol-data.js')).ATTRIBUTES;
  for(const [id,definition] of Object.entries(inventory.defaultDefinitions))inventory.protected.registerTypedName(definition.name,{owner:'field:'+id,sourcePath:'field:'+id+'.name'});
  const environmentModule=await importAt(root,'src/runtime-environment.js'),environment=new environmentModule.RuntimeEnvironment();
  inventory.runtimeProjectionTokens=new Set();inventory.runtimeFieldBindings=new Map();
  for(const upstream of ['single','external']){
    const projected=environment._resolve({upstream});
    for(const value of [projected.aIssuer,projected.bIssuer,projected.aEntity,projected.bEntity,projected.appURL,projected.callbackURL,...projected.map.keys(),...projected.hosts.keys()])if(typeof value==='string'&&value)inventory.runtimeProjectionTokens.add(value);
  }
  for(const model of Object.values(registry.LAB_MODELS))for(const binding of model.runtimeBindings||[]){
    if(!binding.attributeId||typeof binding.example!=='string'||!binding.example)continue;
    const bindings=inventory.runtimeFieldBindings.get(binding.attributeId)||[];if(!bindings.some(item=>item.example===binding.example&&item.field===binding.field))bindings.push(binding);inventory.runtimeFieldBindings.set(binding.attributeId,bindings);
  }
  const modules={usage:await importAt(root,'src/attribute-usage.js'),trace:await importAt(root,'src/attribute-trace.js'),held:await importAt(root,'src/held-objects.js'),heldState:await importAt(root,'src/held-object-state.js'),modeMetadata:{...(await importAt(root,'src/architecture-variants.js')).JOURNEYS,...(await importAt(root,'src/fido-direct.js')).FIDO_JOURNEYS},comparison:await importAt(root,'src/windows-security-comparisons.js')};
  await collectStatic(inventory,root);
  if(!registeredOnly)await collectNavigation(inventory,registry,catalog);
  for(const message of inventory.messages.values())if(message.owner.semanticId.startsWith('field:'))for(const definition of Object.values(message.parameters)){
    if(typeof definition.value!=='string')continue;const id=message.owner.semanticId.slice(6),set=inventory.defaultTokenFields.get(definition.value)||new Set();set.add(id);inventory.defaultTokenFields.set(definition.value,set);
  }
  inventory.checkpoint('registered-complete');
  for(const entry of catalog.cases)await collectCase(inventory,registry,entry,modules);
  if(uiRoot&&uiContracts)throw new TypeError('Choose --ui-root or --ui-contracts, not both.');
  const uiBundle=uiContracts?JSON.parse(fs.readFileSync(uiContracts,'utf8')):null;
  const runtimeContracts=uiBundle?mergeUIContracts(inventory,uiBundle):uiRoot?await mergeRuntimeContracts(inventory,uiRoot):[];
  // Unexecuted renderer branches remain visible source obligations, not translated
  // prose silently labelled protected and not a claim of completed localization.
  const generated=[];
  for(const template of index.templates)generated.push({...template,binding:'syntax:'+template.module+':'+template.export+':'+sha256(template.source).slice(0,20),status:inventory.sourceSites.has(template.module+':'+template.start)?'realized-source':GENERATED_MODULES.has(template.module)?'requires-explicit-runtime-contract':'requires-schema-template-classification'});
  const strings=[];
  for(const [english,sites] of index.strings)for(const site of sites)if(GENERATED_MODULES.has(site.module)&&/[A-Za-z]{2,}/.test(english)&&!inventory.sourceSites.has(site.module+':'+site.start))strings.push({source:english,sourceSha256:sha256(english),site,status:'requires-human-surface-classification'});
  const output=(name,value)=>{const encoded=JSON.stringify(value,null,2)+'\n';fs.writeFileSync(path.join(out,name),encoded,{flag:'wx'});return {file:name,rawBytes:bytes(encoded),encodedBytes:bytes(encoded),sha256:sha256(encoded)};};
  const messageSink=inventory.messageSink;
  for(const contract of runtimeContracts)messageSink.add(contract);
  const bindingSink=new JsonlGzip(path.join(out,'runtime-bindings.jsonl.gz'));for(const message of inventory.messages.values())if(message.runtime!==false)bindingSink.add(runtimeBinding(message));
  for(const contract of runtimeContracts)bindingSink.add(contract);
  const protectedSink=inventory.protectedSink;
  const ambiguitySink=new JsonlGzip(path.join(out,'ambiguities.jsonl.gz'));for(const ambiguity of inventory.ambiguities)ambiguitySink.add(ambiguity);
  const generatedSink=new JsonlGzip(path.join(out,'generated-source-obligations.jsonl.gz'));for(const value of [...generated,...strings,...index.branches.map(branch=>({...branch,status:'source-branch-not-an-execution-coverage-claim'}))])generatedSink.add(value);
  const sourceSink=new JsonlGzip(path.join(out,'source-locations.jsonl.gz'));for(const [english,sites] of index.strings)sourceSink.add({sourceSha256:sha256(english),sites});
  const artifacts=[messageSink.close(),bindingSink.close(),inventory.occurrences.close(),protectedSink.close(),ambiguitySink.close(),generatedSink.close(),sourceSink.close(),output('cases.json',{counts:catalog.counts,choices:catalog.choices,cases:inventory.cases}),output('runtime-contracts.json',runtimeContracts)];
  artifacts.push(inventory.presentationMetadata.close());
  artifacts.push(inventory.caseSink.close(),inventory.defaultsSink.close());
  const templateGroups=new Map(),factoryGroups=new Map(),uniqueEnglish=new Set(),uniqueFields=new Set();let templateBytes=0,proseWords=0;
  for(const message of inventory.messages.values()){
    uniqueEnglish.add(message.sourceSha256);if(message.owner.semanticId.startsWith('field:'))uniqueFields.add(message.owner.semanticId);
    templateBytes+=bytes(message.template);proseWords+=(message.template.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'').match(/[\p{L}\p{N}]+/gu)||[]).length;
    const identity={owner:message.owner,context:message.context,template:message.template,parameters:Object.fromEntries(Object.entries(message.parameters).map(([name,definition])=>[name,{kind:definition.kind,sourcePath:definition.sourcePath}]))};
    const id=sha256(stableJson(identity)),group=templateGroups.get(id)||{id,owner:message.owner,context:message.context,template:message.template,messageKeys:[]};group.messageKeys.push(message.key);templateGroups.set(id,group);
    const opportunity=factoryOpportunity(message);if(opportunity){const proofId=sha256(stableJson(opportunity)),proof=factoryGroups.get(proofId)||{id:proofId,...opportunity,messageKeys:[],owners:[]};proof.messageKeys.push(message.key);proof.owners.push(message.owner.semanticId);factoryGroups.set(proofId,proof);}
  }
  artifacts.push(output('template-opportunities.json',{scope:'Candidates only. Exact source-factory/literal identity, semantic field role, runtime context and typed parameter agreement are required; realized units remain separate.',groups:[...factoryGroups.values()].filter(group=>group.messageKeys.length>1)}));
  const summary={schemaVersion:1,kind:'source-bound-localization-inventory',root,uiRoot,sourceFiles:[...index.files.values()].map(({module,sourceSha256,bytes})=>({module,sourceSha256,bytes})),counts:{...catalog.counts,constructedCases:inventory.cases.length,uniqueMessageUnits:inventory.messages.size,occurrenceBindings:inventory.occurrences.count,protectedRegistryEntries:inventory.protected.entries.size,ambiguities:inventory.ambiguities.length,generatedTemplates:generated.length,unclassifiedGeneratedStrings:strings.length,sourceBranches:index.branches.length,explicitRuntimeContracts:runtimeContracts.length},...inventory.totals,artifacts,unresolved:{sourceBindings:inventory.ambiguities.filter(a=>a.kind.includes('source-binding')).length,arrayDuplicates:inventory.ambiguities.filter(a=>a.kind==='duplicate-array-source').length,generatedSourceObligations:generated.filter(g=>g.status!=='realized-source').length,unclassifiedGeneratedStrings:strings.length},scope:'Actual baseline canonical cases and generated traces/held plans. Static syntax branch obligations are separate from realized variants. No model mutation, localization completeness, test, browser, human or release acceptance claim.'};
  summary.sizing={uniqueExactEnglishStrings:uniqueEnglish.size,uniqueFieldOwners:uniqueFields.size,ownerAndParameterBoundTemplateGroups:templateGroups.size,templateBytes,proseWords,templateDedupCandidates:[...factoryGroups.values()].filter(group=>group.messageKeys.length>1).length};
  summary.counts.uniqueMessageUnits+=runtimeContracts.length;
  summary.counts.runtimeMessageUnits=[...inventory.messages.values()].filter(message=>message.runtime!==false).length+runtimeContracts.length;
  summary.counts.auditOnlyRealizedUnits=inventory.messages.size+runtimeContracts.length-summary.counts.runtimeMessageUnits;
  summary.uiSourceFiles=uiBundle?.sourceFiles||[];
  summary.sourceOwnership={models:registry.declarations.models.size,fields:registry.declarations.fields.size,unmappedModels:Object.keys(registry.LAB_MODELS).filter(id=>!registry.declarations.models.has(id))};
  summary.uiSidecar=uiContracts?{path:path.resolve(uiContracts),sourceSha256:sha256(fs.readFileSync(uiContracts))}:null;
  summary.sizing.runtimeEnglishBytes=[...inventory.messages.values()].filter(message=>message.runtime!==false).reduce((n,message)=>n+bytes(message.english),0)+runtimeContracts.reduce((n,contract)=>n+(typeof contract.english==='string'?bytes(contract.english):Object.values(contract.english.plural).reduce((sum,form)=>sum+bytes(form),0)),0);
  summary.collectorFiles=COLLECTOR_FILES;
  summary.fixtureHelper=registry.fixtureHelper;
  summary.registeredOnly=registeredOnly;summary.caseEvaluationScope=registeredOnly?'not-run-registered-static-pilot':caseIds?'selected-finite-cases-partial-until-manifest-union':'exhaustive-finite-cases';summary.telemetry=inventory.lastCheckpoint;
  if(caseIds)summary.caseSelection={path:path.resolve(caseIds),sourceSha256:sha256(fs.readFileSync(caseIds))};
  output('summary.json',summary);return summary;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2),options={};
  for(let i=0;i<args.length;i++){const arg=args[i];if(arg==='--registered-only'){options.registeredOnly=true;continue;}if(arg.startsWith('--case-ids=')){options['case-ids']=arg.slice(11);if(!options['case-ids'])throw new Error('Empty case selection path.');continue;}if(!['--root','--out','--ui-root','--ui-contracts','--reclassify','--declare-detailed-payload','--case-ids'].includes(arg)||!args[i+1])throw new Error('Usage: bun inventory.mjs (--root BASELINE | --reclassify INPUTDIR | --declare-detailed-payload INPUTDIR) --out NEWDIR [--registered-only] [--case-ids SELECTION_JSON] [--ui-root CURRENT | --ui-contracts JSON]');options[arg.slice(2)]=args[++i];}
  if(!options.out||['root','reclassify','declare-detailed-payload'].filter(key=>options[key]).length!==1)throw new Error('Require --out and exactly one inventory, reclassification or detailed-description mode.');
  const summary=options['declare-detailed-payload']?await declareDetailedPayloadDescriptions({input:options['declare-detailed-payload'],out:options.out}):options.reclassify?await reclassifyInventory({input:options.reclassify,out:options.out,uiRoot:options['ui-root'],uiContracts:options['ui-contracts']}):await extractInventory({root:options.root,out:options.out,uiRoot:options['ui-root'],uiContracts:options['ui-contracts'],registeredOnly:options.registeredOnly,caseIds:options['case-ids']});
  console.log(JSON.stringify({counts:summary.counts,sourceEnglishBytes:summary.sourceEnglishBytes,artifacts:summary.artifacts,unresolved:summary.unresolved},null,2));
}
