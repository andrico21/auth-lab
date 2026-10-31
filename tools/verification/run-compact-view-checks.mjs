#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline';
import {gzipSync,brotliDecompressSync} from 'node:zlib';
import {COMPACT_ROOT,COMPACT_CONTROL,compactHash,compactStable,compactId,compactImport,compactInputIdentity,compactRegistry,compactEnumerate,compactDeepFixtures,compactFixture} from './compact-view-fixtures.mjs';
import {ValueGraph,ValueGraphEncoder,ValueGraphDecoder,compareCompactValues,readValueGraphFrames,FORMAT as GRAPH_FORMAT,ROOT_DIGEST_ALGORITHM as GRAPH_DIGEST} from './compact-value-graph.mjs';
import {captureInputs as captureCanonicalInputs} from './compact-mobile-browser.mjs';

const producer=fileURLToPath(import.meta.url),argv=process.argv.slice(2);
const mode=argv.shift();
const option=(name,fallback)=>{const index=argv.indexOf(name);if(index<0)return fallback;assert.ok(argv[index+1]&&!argv[index+1].startsWith('--'),'Value required for '+name);return argv[index+1];};
const root=path.resolve(option('--root',COMPACT_ROOT)),control=path.resolve(option('--control',COMPACT_CONTROL));
const phase0=path.resolve(option('--manifest-dir',path.join(COMPACT_ROOT,'docs/compact-view/phase-0')));
const catalogPath=path.join(phase0,'catalog-and-cases.json'),deepPath=path.join(phase0,'deep-fixtures.json');
const helper=fileURLToPath(new URL('./compact-view-fixtures.mjs',import.meta.url));
const json=filename=>JSON.parse(fs.readFileSync(filename,'utf8'));
const writeNew=(filename,value)=>{fs.mkdirSync(path.dirname(filename),{recursive:true});fs.writeFileSync(filename,JSON.stringify(value,null,2)+'\n',{flag:'wx'});};
const shaFile=filename=>compactHash(fs.readFileSync(filename));
const help=`Usage: bun tools/verification/run-compact-view-checks.mjs <freeze|parity|dom|deep|all> [options]
  --root PATH             Candidate checkout (default: producer checkout)
  --control PATH          Immutable candidate-07 accepted checkout
  --manifest-dir PATH     Frozen catalog/deep manifest directory
  --output PATH           New evidence directory, never an existing directory
  --loading source|emitted  DOM/deep loading path (default: source)
  --case ID               Optional exact frozen case ID for a focused attempt
  --choice ID             Optional exact picker identity for a focused DOM attempt
  --operation ID          Parity diagnostic: one frozen operation plus authored context
  --workers 1..4          Isolated parity processes (default: 4 full, 1 diagnostic)
  --archive-existing PATH  freeze only: preserve prior generated metadata before replacement
freeze: registry metadata only on accepted control; writes catalogs and input identity.
parity: every authored canonical prefix and Compact read projection; raw differences retained.
dom: every actual picker identity, Full/Compact, initial/terminal in one loading path.
deep: MC17 source/emitted every-prefix, rewind, field/exact history and view switches.
all: parity, source/emitted DOM and source/emitted deep, isolated in sequential child processes.
Every collection freezes its explicit operation manifest first, preserves failed attempts, and rejects changed inputs.
DOM evidence is an offline harness result, not native browser, mobile, device or AT acceptance.
The complete final bun run test gate is intentionally separate and parent-owned.`;
if(!mode||mode==='--help'||mode==='-h'){console.log(help);process.exit(mode?0:1);}
assert.ok(['freeze','parity','dom','deep','all'].includes(mode),help);
const codecFile=fileURLToPath(new URL('./compact-evidence-codec.mjs',import.meta.url));
const graphFile=fileURLToPath(new URL('./compact-value-graph.mjs',import.meta.url));
const canonicalHelperFile=fileURLToPath(new URL('./compact-mobile-browser.mjs',import.meta.url));
const parityDefinitionPath=fileURLToPath(new URL('../../docs/compact-view/parity-operation-definition.json',import.meta.url));
function compare(actual,expected,label){assert.ok(compareCompactValues(actual,expected),label);}

if(mode==='freeze'){
  const before=compactInputIdentity(control,[producer,helper,path.join(control,'tools/verification/held-object-fixtures.mjs')]);
  assert.equal(before.htmlSha256,'9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694','Accepted HTML binding');
  const registry=await compactRegistry(control),catalog=compactEnumerate(registry),deep=compactDeepFixtures(catalog);
  compare(compactInputIdentity(control,[producer,helper,path.join(control,'tools/verification/held-object-fixtures.mjs')]),before,'Metadata enumeration cannot mutate frozen inputs');
  catalog.controlHtmlSha256=before.htmlSha256;
  catalog.acceptedFilesSha256=compactHash(compactStable(before.files));
  deep.catalogSha256=compactHash(JSON.stringify(catalog,null,2)+'\n');
  const metadata=[[catalogPath,catalog],[deepPath,deep],[path.join(phase0,'accepted-input-identity.json'),before]];
  const archive=option('--archive-existing',null);
  if(archive){
    const directory=path.resolve(archive);assert.ok(!fs.existsSync(directory),'Metadata archive must be new');
    fs.mkdirSync(directory,{recursive:true});
    for(const [filename] of metadata){assert.ok(fs.lstatSync(filename).isFile(),'Existing generated metadata');fs.copyFileSync(filename,path.join(directory,path.basename(filename)),fs.constants.COPYFILE_EXCL);}
    writeNew(path.join(directory,'superseded.json'),{reason:'Metadata precision revision before acceptance collection; original artifacts and their exact hashes preserved.',status:'metadata-only-superseded',semanticAcceptance:'unperformed',files:Object.fromEntries(metadata.map(([filename])=>[path.basename(filename),shaFile(filename)]))});
    for(const [filename,value] of metadata)fs.writeFileSync(filename,JSON.stringify(value,null,2)+'\n');
  }else for(const [filename,value] of metadata)writeNew(filename,value);
  console.log(JSON.stringify({mode,status:'metadata-frozen',semanticAcceptance:'unperformed',counts:catalog.counts,deepCounts:deep.counts,catalogSha256:shaFile(catalogPath),deepSha256:shaFile(deepPath)},null,2));
  process.exit(0);
}

const parityDefinition=json(parityDefinitionPath);
assert.equal(parityDefinition.kind,'compact-frozen-parity-semantic-operation-definition');
assert.equal(parityDefinition.portableManifest?.encoding,'standard-brotli-original-bytes','Exact portable frozen manifest encoding');
assert.ok(typeof parityDefinition.portableManifest.path==='string'&&!path.isAbsolute(parityDefinition.portableManifest.path),'Portable frozen manifest has a relative path');
const parityManifestPath=path.resolve(path.dirname(parityDefinitionPath),parityDefinition.portableManifest.path);
const bindingFiles=()=>[producer,helper,codecFile,graphFile,canonicalHelperFile,parityDefinitionPath,parityManifestPath,catalogPath,deepPath,path.join(phase0,'accepted-input-identity.json'),path.join(root,'tools/verification/held-object-fixtures.mjs'),path.join(control,'tools/verification/held-object-fixtures.mjs')];
const catalog=json(catalogPath),deep=json(deepPath),acceptedIdentity=json(path.join(phase0,'accepted-input-identity.json'));
const allCases=[...catalog.cases,...deep.sourceOnlyCases],caseFilter=option('--case',null),choiceFilter=option('--choice',null);
if(caseFilter)assert.ok(allCases.some(c=>c.id===caseFilter),'Unknown frozen case ID');
if(choiceFilter)assert.ok(catalog.choices.some(c=>c.id===choiceFilter),'Unknown frozen choice');
const operationFilter=option('--operation',null),assignmentPath=option('--parity-assignment',null),sourcePass=option('--source-pass',null),baselineEvidence=option('--baseline-evidence',null);
assert.ok(!operationFilter||['parity','all'].includes(mode),'--operation is a parity diagnostic');
assert.ok(!assignmentPath||mode==='parity','Parity assignments are worker-only');
assert.ok(!sourcePass||assignmentPath&&['baseline','candidate'].includes(sourcePass),'Source passes require an exact worker assignment');
assert.ok(!baselineEvidence||sourcePass==='candidate','Only the candidate source pass consumes baseline evidence');
assert.ok(sourcePass!=='candidate'||baselineEvidence,'Candidate source pass requires complete baseline evidence');
const workerOption=option('--workers',null);
if(workerOption!==null)assert.match(workerOption,/^[1-4]$/,'--workers must be an integer from 1 through 4');
const diagnostic=Boolean(caseFilter||choiceFilter||operationFilter||sourcePass);
const workerCount=workerOption===null?(diagnostic?1:4):Number(workerOption);
if(operationFilter)assert.ok(allCases.some(entry=>operationFilter.startsWith(entry.id+'/')),'Unknown frozen operation case');
const out=path.resolve(option('--output',path.join(root,'.compact-view-evidence',mode+'-'+new Date().toISOString().replaceAll(':','-')+'-'+process.pid)));
assert.ok(!fs.existsSync(out),'Refusing to overwrite any previous attempt: '+out);fs.mkdirSync(out,{recursive:true});
const before={candidate:compactInputIdentity(root,bindingFiles()),control:compactInputIdentity(control,bindingFiles())};
const report={schemaVersion:1,kind:'compact-view-'+mode,mode,status:'attempted',startedAt:new Date().toISOString(),argv:[process.execPath,...process.argv.slice(1)],runtime:{executable:process.execPath,version:process.version,bun:process.versions.bun||null},nativeBrowser:false,deviceAcceptance:'unperformed',humanAT:'unperformed',finalRepositoryRegression:'unperformed-parent-owned',catalogSha256:shaFile(catalogPath),deepSha256:shaFile(deepPath),inputIdentity:before,items:[],failures:[]};
writeNew(path.join(out,'attempt-start.json'),{status:'attempted',mode,startedAt:report.startedAt,inputIdentity:before,catalogSha256:report.catalogSha256,deepSha256:report.deepSha256});
const append=(filename,value)=>fs.appendFileSync(path.join(out,filename),JSON.stringify(value)+'\n');
function planned(items){
  assert.ok(items.length,'A collection must have planned operations');
  assert.equal(new Set(items.map(item=>item.id)).size,items.length,'Unique planned operation IDs');
  writeNew(path.join(out,'execution-manifest.json'),{schemaVersion:1,mode,catalogSha256:report.catalogSha256,deepSha256:report.deepSha256,items:items.map(item=>({...item,status:'unperformed'}))});
  report.executionManifestSha256=shaFile(path.join(out,'execution-manifest.json'));
  report.items=items.map(item=>({id:item.id,status:'unperformed'}));
}
function attempt(index,fn){
  const item=report.items[index];item.status='attempted';append('attempts.jsonl',{...item,at:new Date().toISOString()});
  try{fn();item.status='passed';}catch(error){item.status='failed';item.error=String(error.stack||error);report.failures.push({id:item.id,error:item.error});}
  append('attempts.jsonl',item);
}
function exactData(filename,data){
  const target=path.join(out,filename+'.graph.jsonl.gz'),encoder=new ValueGraphEncoder(),{frames,record}=encoder.encode({encoding:GRAPH_FORMAT,data});
  const descriptor=fs.openSync(target,'wx'),frameBindings=[];
  try{for(const frame of frames){
    const wire=JSON.stringify(frame)+'\n';fs.writeSync(descriptor,gzipSync(wire));
    frameBindings.push({frameIndex:frame.frameIndex,frameSha256:frame.sha256,wireSha256:compactHash(wire),wireBytes:Buffer.byteLength(wire)});
  }}
  finally{fs.closeSync(descriptor);}
  const receipt={format:GRAPH_FORMAT,records:1,frames:frames.length,lastFrameSha256:frames.at(-1).sha256,rootDigestAlgorithm:GRAPH_DIGEST,frameBindings,recordProofs:[{recordIndex:record.recordIndex,frameIndex:record.frameIndex,root:record.root,rootDigest:record.rootDigest,frameSha256:record.sha256}],graphProducerSha256:shaFile(graphFile),producerSha256:shaFile(producer),frozenOperationAuthority,...artifactBinding(target)};
  writeNew(target+'.receipt.json',receipt);
  return receipt.sha256;
}
const semanticDefinitions=items=>items.map(item=>({id:item.id,caseId:item.caseId,...(item.cursor?{cursor:item.cursor}:{})}));
const definitionHash=items=>compactHash(JSON.stringify(semanticDefinitions(items)));
const parityDefinitions=(entry,cursors)=>[
  {id:entry.id+'/authored',caseId:entry.id},
  ...cursors.map(cursor=>({id:entry.id+'/'+cursor.eventIndex+'/'+cursor.milestone,caseId:entry.id,cursor}))
];
const definitionsFrom=manifest=>semanticDefinitions(manifest.items);
const artifactBinding=filename=>({sha256:shaFile(filename),bytes:fs.statSync(filename).size});
const frozenOperationAuthority={descriptor:artifactBinding(parityDefinitionPath),portableManifest:artifactBinding(parityManifestPath)};
report.frozenOperationAuthority=frozenOperationAuthority;
function frozenParityDefinitions(){
  const portable=parityDefinition.portableManifest,compressed=fs.readFileSync(parityManifestPath);
  assert.equal(compressed.length,portable.bytes,'Exact portable frozen manifest byte count');
  assert.equal(compactHash(compressed),portable.sha256,'Exact portable frozen manifest compressed identity');
  const decoded=brotliDecompressSync(compressed);
  assert.equal(decoded.length,portable.decodedBytes,'Exact restored original manifest byte count');
  assert.equal(compactHash(decoded),portable.decodedSha256,'Exact restored original manifest identity');
  assert.equal(decoded.length,parityDefinition.originalManifest.bytes,'Portable copy restores the original frozen manifest length');
  assert.equal(portable.decodedSha256,parityDefinition.originalManifest.sha256,'Portable copy restores the original frozen manifest hash');
  const manifest=JSON.parse(decoded.toString('utf8'));
  assert.equal(manifest.schemaVersion,1);assert.equal(manifest.mode,'parity');
  assert.equal(manifest.catalogSha256,report.catalogSha256);assert.equal(manifest.deepSha256,report.deepSha256);
  assert.ok(Array.isArray(manifest.items),'Frozen original operation list');
  const definitions=definitionsFrom(manifest),normalized=JSON.stringify(definitions);
  assert.equal(definitions.length,parityDefinition.operations,'Exact full frozen operation count before selection');
  assert.equal(Buffer.byteLength(normalized),parityDefinition.definitionsBytes,'Exact normalized frozen definition byte count');
  assert.equal(compactHash(normalized),parityDefinition.definitionsSha256,'Exact ordered original IDs, case IDs and raw cursors before selection');
  assert.equal(new Set(definitions.map(item=>item.id)).size,definitions.length,'Every original frozen operation ID is unique');
  const caseIds=[...new Set(definitions.map(item=>item.caseId))];
  assert.equal(caseIds.length,parityDefinition.cases,'Exact full frozen case count before selection');
  assert.deepEqual(caseIds,allCases.map(entry=>entry.id),'Frozen operations cover the exact ordered finite case inventory');
  return definitions;
}
async function prepare(label,fn){
  const startedAt=new Date().toISOString(),start=performance.now();
  append('preparation.jsonl',{label,status:'attempted',at:startedAt});
  try{
    const value=await fn();
    append('preparation.jsonl',{label,status:'passed',at:new Date().toISOString(),milliseconds:performance.now()-start});
    return value;
  }catch(error){
    append('preparation.jsonl',{label,status:'failed',at:new Date().toISOString(),milliseconds:performance.now()-start,error:String(error.stack||error)});
    throw error;
  }
}
function verifyArtifacts(directory,child){
  assert.ok(child.artifacts&&Object.keys(child.artifacts).length,'Child binds every raw artifact');
  const actual=fs.readdirSync(directory,{withFileTypes:true}).filter(entry=>entry.isFile()&&entry.name!=='status.json').map(entry=>entry.name).sort();
  assert.deepEqual(Object.keys(child.artifacts).sort(),actual,'No unbound child raw streams');
  for(const name of actual)assert.deepEqual(artifactBinding(path.join(directory,name)),child.artifacts[name],'Child artifact binding: '+name);
  return {status:artifactBinding(path.join(directory,'status.json')),artifacts:child.artifacts};
}
async function verifyComparisons(directory,assignment,definitions){
  const byId=new Map(definitions.map(item=>[item.id,item])),seen=new Set(),contexts=new Set();
  const expected=new Set(assignment.cases.flatMap(entry=>entry.operationIds));
  const expectedContexts=new Set(assignment.cases.filter(entry=>!entry.operationIds.includes(entry.caseId+'/authored')).map(entry=>entry.caseId));
  const lines=createInterface({input:fs.createReadStream(path.join(directory,'comparisons.jsonl')),crlfDelay:Infinity});
  for await(const line of lines){
    const row=JSON.parse(line),authored=row.kind==='authored';
    assert.equal(row.equal,true,'Complete independent baseline-node versus candidate-raw equality');
    assert.equal(row.comparisonMethod,'independent-baseline-node-vs-candidate-raw-v1');
    assert.equal(row.candidateRawValueChecked,true,'The actual candidate value was independently walked');
    assert.equal(row.rootDigestAlgorithm,GRAPH_DIGEST);
    assert.match(row.expectedGraphDigest,/^[a-f0-9]{64}$/);assert.match(row.expectedFrameSha256,/^[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(row.expectedRoot)&&row.expectedRoot>=0,'Expected root is a decoded baseline value, not a fabricated candidate digest');
    if(authored&&row.role==='context'){
      assert.ok(expectedContexts.has(row.caseId)&&!contexts.has(row.caseId),'Exactly one assigned authored context comparison per diagnostic case');contexts.add(row.caseId);continue;
    }
    const id=authored?row.caseId+'/authored':row.caseId+'/'+row.cursor?.eventIndex+'/'+row.cursor?.milestone;
    assert.ok(expected.has(id)&&!seen.has(id),'Actual raw comparison IDs execute once');
    if(authored)assert.equal(row.role,'operation','Diagnostic context cannot count as an operation');
    else {
      assert.deepEqual(row.cursor,byId.get(id).cursor,'Actual raw cursor matches the authoritative manifest');
      assert.equal(row.projectionEqual,true);assert.equal(row.projectionValid,true);
      assert.deepEqual(row.projectionErrors,{baseline:[],candidate:[]},'Both actual source passes retain every original positive projection contract');
    }
    seen.add(id);
  }
  assert.equal(seen.size,expected.size,'Every assigned operation has a complete actual candidate comparison');
  assert.equal(contexts.size,expectedContexts.size,'Every diagnostic case retains its authored comparison context');
  return {operations:seen.size,authoredContextComparisons:contexts.size};
}
async function verifyGraphStream(directory,receipt,assignedCase,definitions,onRecord){
  const expected=definitions.map(item=>({role:'operation',operationId:item.id,selector:{caseId:item.caseId,kind:item.cursor?'prefix':'authored',...(item.cursor?{cursor:item.cursor}:{})}}));
  if(!assignedCase.operationIds.includes(assignedCase.caseId+'/authored'))expected.unshift({role:'context',operationId:assignedCase.caseId+'/authored',selector:{caseId:assignedCase.caseId,kind:'authored-context'}});
  assert.equal(receipt.recordProofs.length,expected.length,'Every raw graph record has one proof receipt');
  assert.equal(receipt.frameBindings.length,receipt.frames,'Every raw graph frame has one actual wire binding');
  const decoder=new ValueGraphDecoder();let frameCount=0,recordCount=0,lastFrameSha256=null;
  for await(const frame of readValueGraphFrames(path.join(directory,receipt.path))){
    const accepted=decoder.accept(frame),wire=JSON.stringify(frame)+'\n';
    assert.deepEqual(receipt.frameBindings[frameCount],{frameIndex:frame.frameIndex,frameSha256:frame.sha256,wireSha256:compactHash(wire),wireBytes:Buffer.byteLength(wire)},'Every frame payload chain and actual serialized wire bytes are bound');
    frameCount++;lastFrameSha256=frame.sha256;
    if(frame.kind==='record'){
      assert.ok(accepted,'Independent decoder accepted the record');
      const operation=expected[recordCount];assert.ok(operation,'No extra graph record');
      assert.ok(decoder.matches(frame,operation.selector),'Graph record matches the exact assigned case/kind/cursor');
      assert.deepEqual(receipt.recordProofs[recordCount],{recordIndex:frame.recordIndex,frameIndex:frame.frameIndex,root:frame.root,rootDigest:frame.rootDigest,frameSha256:frame.sha256,role:operation.role,operationId:operation.operationId},'Every graph root proof and operation/context receipt is exact');
      if(onRecord)onRecord(decoder,frame,operation);
      recordCount++;
    }
  }
  assert.equal(frameCount,receipt.frames,'Complete graph stream frame count');
  assert.equal(recordCount,receipt.records,'Complete graph stream record count');
  assert.equal(recordCount,expected.length,'Exactly the assigned operations and required context');
  assert.equal(lastFrameSha256,receipt.lastFrameSha256,'Externally bound complete graph stream tail');
  return {frames:frameCount,records:recordCount,lastFrameSha256};
}
function paritySourceRecord(projector,fixture,item,role,comparisonGraph){
  if(!item.cursor)return {errors:[],value:role==='context'?
    {caseId:item.caseId,kind:'authored-context',role:'context',operationId:item.id,encoding:GRAPH_FORMAT,data:fixture.authored}:
    {caseId:item.caseId,kind:'authored',encoding:GRAPH_FORMAT,data:fixture.authored}};
  const snapshot=fixture.project(item.cursor),result=compactProjection(projector,fixture,snapshot,comparisonGraph);
  return {errors:result.errors,value:{caseId:item.caseId,kind:'prefix',cursor:item.cursor,encoding:GRAPH_FORMAT,baseline:snapshot,projection:result.projection}};
}
async function paritySourcePass(assignment,items,byId,indexById){
  assert.equal(assignment.cases.length,1,'A source process owns exactly one case fixture');
  const assignedCase=assignment.cases[0],{caseId,operationIds}=assignedCase,entry=allCases.find(item=>item.id===caseId);
  assert.ok(entry,'Actual frozen source case');report.sourcePass=sourcePass;
  report.coverage.scope='source-'+sourcePass+'-case-subset';report.coverage.fullAcceptance=false;
  const registry=await prepare(sourcePass+' registry',()=>compactRegistry(sourcePass==='baseline'?control:root));
  const fixture=await prepare(caseId+' '+sourcePass+' fixture compilation',()=>compactFixture(registry,entry));
  await prepare(caseId+' complete '+sourcePass+' compiler cursor-definition verification',()=>{
    assert.deepEqual(parityDefinitions(entry,fixture.compiled.cursors),items,'Every actual source cursor matches the exact sealed original case definitions');
  });
  report.sourceCompilerDefinitions={status:'passed',source:sourcePass,caseId,operations:items.length,definitionSha256:definitionHash(items)};
  const {compactReadProjection}=await compactImport(root,'src/compact-view.js');assert.equal(typeof compactReadProjection,'function');
  const comparisonGraph=new ValueGraph(),authoredId=caseId+'/authored',needsContext=!operationIds.includes(authoredId);
  if(sourcePass==='baseline'){
    const criticalPath=caseId+'.graph.jsonl.gz',encoder=new ValueGraphEncoder(comparisonGraph);
    const receipt={caseId,path:criticalPath,format:GRAPH_FORMAT,encoding:GRAPH_FORMAT,operationIds,contextRecords:0,operationRecords:0,records:0,frames:0,lastFrameSha256:null,rootDigestAlgorithm:GRAPH_DIGEST,graphProducerSha256:shaFile(graphFile),producerSha256:shaFile(producer),frozenOperationAuthority,frameBindings:[],recordProofs:[]};
    const capture=(item,role)=>{
      const actual=paritySourceRecord(compactReadProjection,fixture,item,role,comparisonGraph),{frames,record}=encoder.encode(actual.value);
      for(const frame of frames){
        const wire=JSON.stringify(frame)+'\n';fs.appendFileSync(path.join(out,criticalPath),gzipSync(wire));
        receipt.frameBindings.push({frameIndex:frame.frameIndex,frameSha256:frame.sha256,wireSha256:compactHash(wire),wireBytes:Buffer.byteLength(wire)});
        receipt.frames++;receipt.lastFrameSha256=frame.sha256;
      }
      receipt.recordProofs.push({recordIndex:record.recordIndex,frameIndex:record.frameIndex,root:record.root,rootDigest:record.rootDigest,frameSha256:record.sha256,role,operationId:item.id});
      receipt.records++;if(role==='context')receipt.contextRecords++;else receipt.operationRecords++;
      if(item.cursor)append('source-positive-contracts.jsonl',{caseId,cursor:item.cursor,errors:actual.errors});
      assert.deepEqual(actual.errors,[],'Every baseline positive canonical/action projection contract');
    };
    if(needsContext)await prepare(caseId+' complete authored context capture',()=>capture(byId.get(authoredId),'context'));
    for(const id of operationIds)attempt(indexById.get(id),()=>capture(byId.get(id),'operation'));
    assert.equal(receipt.operationRecords,operationIds.length,'Every selected baseline operation has its complete raw record');
    assert.equal(receipt.contextRecords,needsContext?1:0);assert.equal(receipt.records,receipt.operationRecords+receipt.contextRecords);
    Object.assign(receipt,artifactBinding(path.join(out,criticalPath)));writeNew(path.join(out,caseId+'.receipt.json'),receipt);
    report.criticalExact={format:GRAPH_FORMAT,encoding:GRAPH_FORMAT,streams:[receipt],records:receipt.records,frames:receipt.frames,rootDigestAlgorithm:GRAPH_DIGEST,graphProducerSha256:shaFile(graphFile),selfCheck:'Every complete actual baseline record is independently decoded and checked before writing; candidate equivalence is a separate real-source process, not inferred here.'};
  }else {
    const directory=path.resolve(baselineEvidence),statusPath=path.join(directory,'status.json'),receiptPath=path.join(directory,caseId+'.receipt.json');
    const baseline=json(statusPath),receipt=json(receiptPath),streamPath=path.join(directory,receipt.path);
    assert.equal(baseline.status,'passed','Complete baseline source pass is a prerequisite');assert.equal(baseline.sourcePass,'baseline');
    compare(baseline.inputIdentity,before,'Baseline binds these exact unchanged inputs');compare(baseline.afterInputIdentity,before,'Baseline inputs stayed unchanged');
    assert.deepEqual(baseline.requiredOperationIds,operationIds,'Candidate consumes the same exact operation assignment');
    assert.deepEqual(baseline.criticalExact.streams,[receipt],'Standalone baseline receipt is exactly the completed source report');
    assert.deepEqual(receipt.operationIds,operationIds);assert.equal(receipt.caseId,caseId);
    const bindings={status:artifactBinding(statusPath),receipt:artifactBinding(receiptPath),stream:artifactBinding(streamPath)};
    assert.deepEqual(bindings.stream,{bytes:receipt.bytes,sha256:receipt.sha256},'Exact externally bound complete baseline stream');
    const validation=await verifyGraphStream(directory,receipt,assignedCase,operationIds.map(id=>byId.get(id)),(decoder,frame,operation)=>{
      const item=byId.get(operation.operationId);assert.ok(item,'Actual source record has one frozen definition');
      const check=()=>{
        const actual=paritySourceRecord(compactReadProjection,fixture,item,operation.role,comparisonGraph);let equal=true,error=null;
        try{decoder.assertValue(frame,actual.value);}catch(failure){equal=false;error=String(failure.stack||failure);}
        append('comparisons.jsonl',{caseId,kind:item.cursor?'prefix':'authored',...(item.cursor?{cursor:item.cursor}:{}),role:operation.role,equal,comparisonMethod:'independent-baseline-node-vs-candidate-raw-v1',candidateRawValueChecked:equal,rootDigestAlgorithm:GRAPH_DIGEST,expectedRoot:frame.root,expectedGraphDigest:frame.rootDigest,expectedFrameSha256:frame.sha256,...(item.cursor?{projectionEqual:equal?true:null,projectionValid:!actual.errors.length,projectionErrors:{baseline:[],candidate:actual.errors}}:{}),...(error?{error}:{})});
        if(!equal||actual.errors.length)exactData(compactId('candidate-difference',{caseId,cursor:item.cursor||null})+'.json',{candidate:actual.value,candidateProjectionErrors:actual.errors,expectedBaselineRecord:{root:frame.root,rootDigest:frame.rootDigest,frameSha256:frame.sha256,stream:bindings.stream}});
        assert.ok(equal,error||'Complete candidate raw value differs from its independently decoded baseline');
        assert.deepEqual(actual.errors,[],'Every candidate positive canonical/action projection contract');
      };
      if(operation.role==='context')check();else attempt(indexById.get(item.id),check);
    });
    assert.deepEqual({status:artifactBinding(statusPath),receipt:artifactBinding(receiptPath),stream:artifactBinding(streamPath)},bindings,'Consumed baseline report, receipt and complete stream remain byte-identical');
    report.comparisonEvidence={method:'independent-baseline-node-vs-candidate-raw-v1',baselineDirectory:directory,bindings,validation,completeRawRecordsChecked:validation.records};
  }
  report.uniqueCases=1;report.cursorComparisons=operationIds.filter(id=>byId.get(id).cursor).length;
}
function verifySourcePassArtifacts(directory,result,assignment,definitions){
  assert.equal(result.sourcePasses.length,assignment.cases.length*2,'Both real source passes exist for every complete case');
  const seen=new Set();
  for(const member of result.sourcePasses){
    const assigned=assignment.cases.find(entry=>entry.caseId===member.caseId);assert.ok(assigned,'Source pass belongs to its actual assigned case');
    assert.ok(['baseline','candidate'].includes(member.role));const key=member.caseId+'/'+member.role;
    assert.ok(!seen.has(key),'Each source pass executed once');seen.add(key);assert.equal(member.directory,key);
    assert.equal(member.result.code,0);assert.equal(member.result.signal,null);
    const childDirectory=path.join(directory,key),child=json(path.join(childDirectory,'status.json'));
    assert.deepEqual(verifyArtifacts(childDirectory,child),member.bindings,'Every nested source artifact and status byte is independently bound');
    assert.equal(child.status,'passed');assert.equal(child.sourcePass,member.role);assert.equal(child.coverage.fullAcceptance,false);
    compare(child.inputIdentity,before,'Source pass exact input identity');compare(child.afterInputIdentity,before,'Source pass inputs stayed unchanged');
    assert.deepEqual(child.frozenOperationAuthority,frozenOperationAuthority);assert.deepEqual(child.requiredOperationIds,assigned.operationIds);
    const expected=definitions.filter(item=>item.caseId===member.caseId),actual=definitionsFrom(json(path.join(childDirectory,'execution-manifest.json')));
    assert.deepEqual(actual,expected,'Every nested source manifest retains its complete actual case definitions');
    assert.deepEqual(child.sourceCompilerDefinitions,{status:'passed',source:member.role,caseId:member.caseId,operations:expected.length,definitionSha256:definitionHash(expected)},'Each real source independently derives every frozen case cursor');
    const selected=new Set(assigned.operationIds);
    assert.equal(child.items.length,expected.length);
    for(const [index,item]of child.items.entries()){assert.equal(item.id,expected[index].id);assert.equal(item.status,selected.has(item.id)?'passed':'unperformed');}
    if(member.role==='candidate'){
      const receipt=result.criticalExact.streams.find(stream=>stream.caseId===member.caseId);assert.ok(receipt);
      const baselineDirectory=path.join(directory,member.caseId,'baseline');
      assert.equal(child.comparisonEvidence.method,'independent-baseline-node-vs-candidate-raw-v1');
      assert.equal(child.comparisonEvidence.baselineDirectory,baselineDirectory);
      assert.deepEqual(child.comparisonEvidence.bindings,{status:artifactBinding(path.join(baselineDirectory,'status.json')),receipt:artifactBinding(path.join(baselineDirectory,member.caseId+'.receipt.json')),stream:artifactBinding(path.join(directory,receipt.path))},'Candidate checked the exact portable baseline bytes');
      assert.deepEqual(child.comparisonEvidence.validation,{frames:receipt.frames,records:receipt.records,lastFrameSha256:receipt.lastFrameSha256});
      assert.equal(child.comparisonEvidence.completeRawRecordsChecked,receipt.records);
    }
  }
  return {sourcePasses:seen.size,cases:assignment.cases.length,comparisonMethod:'independent-baseline-node-vs-candidate-raw-v1'};
}

async function parityWorker(){
  const frozen=await prepare('portable original frozen manifest verification',()=>frozenParityDefinitions()),assignment=json(path.resolve(assignmentPath));
  report.assignmentBinding=artifactBinding(path.resolve(assignmentPath));
  assert.equal(assignment.schemaVersion,1);assert.equal(assignment.kind,'compact-parity-assignment');
  assert.ok(Array.isArray(assignment.cases)&&assignment.cases.length,'Worker owns complete cases');
  assert.deepEqual(assignment.frozenOperationAuthority,frozenOperationAuthority);
  assert.equal(shaFile(assignment.manifestPath),assignment.manifestSha256,'Worker authoritative manifest binding');
  const authoritative=definitionsFrom(json(assignment.manifestPath)),authoritativeCases=new Set(authoritative.map(item=>item.caseId));
  assert.equal(definitionHash(authoritative),assignment.definitionSha256);
  assert.deepEqual(authoritative,frozen.filter(item=>authoritativeCases.has(item.caseId)),'Parent plan retains the complete original ordered case definitions');
  const byId=new Map(authoritative.map(item=>[item.id,item])),selectedIds=assignment.cases.flatMap(entry=>entry.operationIds),ownedCases=new Set(assignment.cases.map(entry=>entry.caseId)),items=authoritative.filter(item=>ownedCases.has(item.caseId));
  assert.equal(byId.size,authoritative.length);assert.equal(new Set(selectedIds).size,selectedIds.length);assert.equal(ownedCases.size,assignment.cases.length);
  for(const assigned of assignment.cases){const selected=new Set(assigned.operationIds);assert.ok(selected.size);assert.deepEqual(assigned.operationIds,items.filter(item=>item.caseId===assigned.caseId&&selected.has(item.id)).map(item=>item.id),'Selected operations retain exact original case ownership and order');}
  planned(items);const indexById=new Map(items.map((item,index)=>[item.id,index]));
  report.coverage={scope:'diagnostic-case-assigned-subset',fullAcceptance:false,authoritativeManifestSha256:assignment.manifestSha256,definitionSha256:assignment.definitionSha256,originalFullDefinitionSha256:parityDefinition.definitionsSha256,originalFullOperations:parityDefinition.operations,plannedOperations:items.length,selectedOperationIds:selectedIds,excludedOperations:items.length-selectedIds.length,excludedStatus:'unperformed'};
  report.requiredOperationIds=selectedIds;report.scheduler={role:assignment.schedulerRole,caseIds:assignment.cases.map(entry=>entry.caseId),operationLoad:selectedIds.length};
  if(sourcePass)return paritySourcePass(assignment,items,byId,indexById);
  report.sourcePasses=[];report.criticalExact={format:GRAPH_FORMAT,encoding:GRAPH_FORMAT,streams:[],records:0,frames:0,rootDigestAlgorithm:GRAPH_DIGEST,graphProducerSha256:shaFile(graphFile),comparisonMethod:'independent-baseline-node-vs-candidate-raw-v1'};
  for(const assigned of assignment.cases){
    const {caseId,operationIds}=assigned,caseAssignment=path.join(out,caseId+'.source-assignment.json'),sourceReports={};
    writeNew(caseAssignment,{...assignment,cases:[assigned]});
    for(const role of ['baseline','candidate']){
      const relative=caseId+'/'+role,directory=path.join(out,relative),command=[producer,'parity','--root',root,'--control',control,'--manifest-dir',phase0,'--output',directory,'--parity-assignment',caseAssignment,'--source-pass',role,...(role==='candidate'?['--baseline-evidence',path.join(out,caseId,'baseline')]:[])];
      append('source-passes.jsonl',{caseId,role,status:'attempted',at:new Date().toISOString()});
      const result=await runParityProcess(command,directory);
      assert.equal(result.code,0,'Complete '+role+' real-source process: '+caseId);assert.equal(result.signal,null);
      const child=json(path.join(directory,'status.json')),bindings=verifyArtifacts(directory,child);
      assert.equal(child.status,'passed');assert.equal(child.sourcePass,role);assert.deepEqual(child.requiredOperationIds,operationIds);
      compare(child.inputIdentity,before,'Real-source pass binds the same exact inputs');compare(child.afterInputIdentity,before,'Real-source pass inputs unchanged');
      report.sourcePasses.push({caseId,role,directory:relative,result,bindings});sourceReports[role]=child;
      append('source-passes.jsonl',{caseId,role,status:'passed',at:new Date().toISOString(),statusSha256:bindings.status.sha256});
    }
    const baseline=sourceReports.baseline,candidate=sourceReports.candidate;
    assert.equal(baseline.criticalExact.streams.length,1,'One complete baseline stream per case');
    const original=baseline.criticalExact.streams[0],receipt={...original,path:caseId+'/baseline/'+original.path,sourceReceiptPath:caseId+'/baseline/'+caseId+'.receipt.json'};
    writeNew(path.join(out,caseId+'.receipt.json'),receipt);
    report.criticalExact.streams.push(receipt);report.criticalExact.records+=receipt.records;report.criticalExact.frames+=receipt.frames;
    for(const item of candidate.items){const index=indexById.get(item.id);assert.notEqual(index,undefined);report.items[index]={...item};}
    const lines=createInterface({input:fs.createReadStream(path.join(out,caseId,'candidate','comparisons.jsonl')),crlfDelay:Infinity});
    for await(const line of lines)append('comparisons.jsonl',JSON.parse(line));
  }
  verifySourcePassArtifacts(out,report,assignment,items);
  await verifyComparisons(out,assignment,items);
  report.acceptedCompilerDefinitions={status:'passed',cases:ownedCases.size,operations:items.length,definitionSha256:definitionHash(items)};
  report.candidateCompilerDefinitions={...report.acceptedCompilerDefinitions};
  report.uniqueCases=ownedCases.size;report.cursorComparisons=selectedIds.filter(id=>byId.get(id).cursor).length;
}
async function runParityProcess(command,directory){
  const logStem=path.relative(out,directory).split(path.sep).join('__'),stdout=fs.openSync(path.join(out,logStem+'.stdout.txt'),'wx'),stderr=fs.openSync(path.join(out,logStem+'.stderr.txt'),'wx');
  try{
    return await new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,command,{stdio:['ignore',stdout,stderr]});
      child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));
    });
  }finally{fs.closeSync(stdout);fs.closeSync(stderr);}
}
async function parity(){
  if(assignmentPath)return parityWorker();
  const frozen=await prepare('portable original frozen manifest verification',()=>frozenParityDefinitions());
  const oldRegistry=await prepare('accepted registry',()=>compactRegistry(control)),newRegistry=await prepare('candidate registry',()=>compactRegistry(root));
  compare(compactEnumerate(oldRegistry),compactEnumerate(newRegistry),'Candidate registry metadata equals accepted finite inventory');
  const {controlHtmlSha256,acceptedFilesSha256,...frozenCatalog}=catalog;
  compare(JSON.parse(JSON.stringify(compactEnumerate(oldRegistry))),frozenCatalog,'Accepted registry metadata matches the frozen catalog exactly');
  const entries=allCases.filter(entry=>(!caseFilter||entry.id===caseFilter)&&(!choiceFilter||entry.choiceId===choiceFilter)&&(!operationFilter||operationFilter.startsWith(entry.id+'/')));
  const entryIds=new Set(entries.map(entry=>entry.id)),items=frozen.filter(item=>entryIds.has(item.caseId));
  planned(items);
  const definitionSha256=definitionHash(items);
  if(!diagnostic){
    assert.equal(items.length,parityDefinition.operations,'Exact full frozen operation count');
    assert.equal(entries.length,parityDefinition.cases,'Exact full frozen case count');
    assert.equal(definitionSha256,parityDefinition.definitionsSha256,'Every frozen operation ID, exact cursor and order matches the original accepted compiler plan');
  }
  const selected=operationFilter?items.filter(item=>item.id===operationFilter):items;
  assert.ok(selected.length,'Unknown frozen operation or incompatible filters');
  const selectedIds=selected.map(item=>item.id),required=new Set(selectedIds),indexById=new Map(items.map((item,index)=>[item.id,index]));
  report.requiredOperationIds=selectedIds;
  report.coverage={scope:diagnostic?'diagnostic-subset':'full-frozen-parity',fullAcceptance:false,plannedOperations:items.length,selectedOperations:selected.length,excludedOperations:items.length-selected.length,excludedStatus:'unperformed',definitionSha256,originalFullDefinitionSha256:parityDefinition.definitionsSha256,originalFullOperations:parityDefinition.operations};
  const selectedByCase=new Map();
  for(const item of selected){if(!selectedByCase.has(item.caseId))selectedByCase.set(item.caseId,[]);selectedByCase.get(item.caseId).push(item.id);}
  const cases=[...selectedByCase].map(([caseId,operationIds])=>({caseId,operationIds})),heavyThreshold=512;
  const heavy=cases.filter(entry=>entry.operationIds.length>heavyThreshold),light=cases.filter(entry=>entry.operationIds.length<=heavyThreshold);
  const heavyDedicated=!diagnostic&&workerCount>1&&heavy.length>0;
  const assignments=[];
  const balanced=(entries,count,role)=>{
    const workers=Array.from({length:Math.min(count,entries.length)},()=>({cases:[],load:0,schedulerRole:role}));
    for(const entry of [...entries].sort((a,b)=>b.operationIds.length-a.operationIds.length)){
      const target=workers.reduce((a,b)=>a.load<=b.load?a:b);target.cases.push(entry);target.load+=entry.operationIds.length;
    }
    return workers;
  };
  if(heavyDedicated){
    assignments.push({cases:[...heavy].sort((a,b)=>b.operationIds.length-a.operationIds.length),load:heavy.reduce((sum,entry)=>sum+entry.operationIds.length,0),schedulerRole:'dedicated-heavy'});
    assignments.push(...balanced(light,workerCount-1,'balanced-light'));
  }else assignments.push(...balanced(cases,cases.length===1?1:workerCount,cases.length===1?'single-case':workerCount===1?'serial-all-cases':'balanced-whole-cases'));
  const assignedCases=assignments.flatMap(assignment=>assignment.cases);
  assert.equal(assignments.length>0&&assignments.length<=4,true,'At most four case-affine workers');
  assert.equal(new Set(assignedCases.map(entry=>entry.caseId)).size,cases.length,'Every selected case has exactly one process owner');
  assert.equal(assignedCases.length,cases.length,'No case is split or assigned twice');
  assert.deepEqual(assignedCases.flatMap(entry=>entry.operationIds).sort(),[...selectedIds].sort(),'Scheduling preserves every selected operation exactly once');
  report.scheduler={strategy:heavyDedicated?'exclusive-heavy-then-balanced-light':assignments[0].schedulerRole,heavyThreshold,requestedWorkers:workerCount,actualWorkers:assignments.length,sourceFixturePolicy:'baseline-and-candidate-in-separate-sequential-processes',heavyRunsExclusively:heavyDedicated,heavyCaseIds:heavy.map(entry=>entry.caseId),assignments:assignments.map((assignment,index)=>({worker:index,role:assignment.schedulerRole,caseIds:assignment.cases.map(entry=>entry.caseId),operationLoad:assignment.load}))};
  append('preparation.jsonl',{label:'whole-case worker assignment',status:'passed',at:new Date().toISOString(),...report.scheduler});
  const manifestPath=path.join(out,'execution-manifest.json'),manifestSha256=shaFile(manifestPath);
  const launch=async(assignment,index)=>{
    const assignmentFile=path.join(out,'worker-'+index+'-assignment.json'),directory=path.join(out,'worker-'+index);
    writeNew(assignmentFile,{schemaVersion:1,kind:'compact-parity-assignment',manifestPath,manifestSha256,definitionSha256,frozenOperationAuthority,schedulerRole:assignment.schedulerRole,cases:assignment.cases});
    const command=[producer,'parity','--root',root,'--control',control,'--manifest-dir',phase0,'--output',directory,'--parity-assignment',assignmentFile];
    try{return {index,directory,assignment,result:await runParityProcess(command,directory)};}
    catch(error){return {index,directory,assignment,error:String(error.stack||error)};}
  };
  const children=[];
  if(heavyDedicated){children.push(await launch(assignments[0],0));children.push(...await Promise.all(assignments.slice(1).map((assignment,index)=>launch(assignment,index+1))));}
  else children.push(...await Promise.all(assignments.map(launch)));
  const seen=new Set();report.workers=[];report.criticalExact={format:GRAPH_FORMAT,encoding:GRAPH_FORMAT,streams:[],records:0,frames:0,rootDigestAlgorithm:GRAPH_DIGEST,graphProducerSha256:shaFile(graphFile)};
  for(const child of children){
    const {index,directory,assignment}=child;
    const workerRecord={index,result:child.result||null,error:child.error||null,assignment:artifactBinding(path.join(out,'worker-'+index+'-assignment.json')),artifacts:fs.existsSync(directory)?Object.fromEntries(fs.readdirSync(directory,{withFileTypes:true}).filter(entry=>entry.isFile()).map(entry=>[entry.name,artifactBinding(path.join(directory,entry.name))])):{}};
    report.workers.push(workerRecord);
    try{
    assert.ok(!child.error,child.error);assert.equal(child.result.code,0,'Parity worker '+index+' completed: '+child.result.signal);
    const result=json(path.join(directory,'status.json')),bindings=verifyArtifacts(directory,result);
    assert.equal(result.status,'passed','Worker subset completed');assert.equal(result.coverage.scope,'diagnostic-case-assigned-subset');assert.equal(result.coverage.fullAcceptance,false,'Worker cannot claim complete acceptance');
    assert.equal(result.coverage.authoritativeManifestSha256,manifestSha256);assert.equal(result.coverage.definitionSha256,definitionSha256);
    compare(result.inputIdentity,before,'Worker binds the same exact inputs');compare(result.afterInputIdentity,before,'Worker inputs unchanged');
    assert.deepEqual(result.frozenOperationAuthority,frozenOperationAuthority,'Worker binds descriptor and portable original binary');
    const expectedIds=assignment.cases.flatMap(entry=>entry.operationIds),expected=new Set(expectedIds);
    assert.deepEqual(result.requiredOperationIds,expectedIds,'Worker did not change its assignment');
    assert.deepEqual(result.scheduler,{role:assignment.schedulerRole,caseIds:assignment.cases.map(entry=>entry.caseId),operationLoad:assignment.load},'Worker reports its actual whole-case scheduler assignment');
    const workerDefinitions=definitionsFrom(json(path.join(directory,'execution-manifest.json'))),cases=new Set(assignment.cases.map(entry=>entry.caseId));
    assert.deepEqual(workerDefinitions,items.filter(item=>cases.has(item.caseId)),'Worker full-case definitions match authoritative plan');
    assert.deepEqual(result.acceptedCompilerDefinitions,{status:'passed',cases:cases.size,operations:workerDefinitions.length,definitionSha256:definitionHash(workerDefinitions)},'Every worker rederived every complete accepted-source case definition');
    assert.deepEqual(result.candidateCompilerDefinitions,result.acceptedCompilerDefinitions,'Candidate independently derived the same complete actual cursor definitions');
    workerRecord.sourcePasses=verifySourcePassArtifacts(directory,result,assignment,workerDefinitions);
    workerRecord.actualComparisons=await verifyComparisons(directory,assignment,workerDefinitions);
    assert.equal(result.items.length,workerDefinitions.length,'Worker outcomes exactly cover its full case manifest');
    for(const [position,item] of result.items.entries()){
      assert.equal(item.id,workerDefinitions[position].id,'Worker outcome order and IDs');
      if(!expected.has(item.id)){assert.equal(item.status,'unperformed','Excluded worker rows stay unperformed');continue;}
      assert.ok(required.has(item.id)&&!seen.has(item.id),'No missing, duplicate or extra actual operation IDs');seen.add(item.id);
      assert.equal(item.status,'passed','Actual assigned operation passed');
      report.items[indexById.get(item.id)]={...item};
      append('joined-outcomes.jsonl',{...item,worker:index,definition:items[indexById.get(item.id)]});
    }
    assert.equal(result.criticalExact.streams.length,assignment.cases.length,'Every assigned case has one independent complete critical stream');
    assert.equal(new Set(result.criticalExact.streams.map(stream=>stream.caseId)).size,assignment.cases.length,'No duplicate case stream receipts');
    for(const assignedCase of assignment.cases){
      const receipt=result.criticalExact.streams.find(stream=>stream.caseId===assignedCase.caseId);assert.ok(receipt,'Critical case receipt exists');
      assert.equal(receipt.path,assignedCase.caseId+'/baseline/'+assignedCase.caseId+'.graph.jsonl.gz','One exact standalone baseline stream per actual case');
      assert.deepEqual(receipt.operationIds,assignedCase.operationIds,'Critical stream binds actual operations');
      assert.equal(receipt.operationRecords,assignedCase.operationIds.length);assert.equal(receipt.contextRecords,assignedCase.operationIds.includes(assignedCase.caseId+'/authored')?0:1);assert.equal(receipt.records,receipt.operationRecords+receipt.contextRecords);
      assert.equal(receipt.format,GRAPH_FORMAT);assert.equal(receipt.encoding,GRAPH_FORMAT);assert.equal(receipt.rootDigestAlgorithm,GRAPH_DIGEST);
      assert.deepEqual(receipt.frozenOperationAuthority,frozenOperationAuthority,'Case receipt binds both frozen operation inputs');
      assert.equal(receipt.graphProducerSha256,shaFile(graphFile));assert.equal(receipt.producerSha256,shaFile(producer));assert.ok(receipt.lastFrameSha256&&receipt.frames>=receipt.records);
      assert.deepEqual(artifactBinding(path.join(directory,receipt.path)),{sha256:receipt.sha256,bytes:receipt.bytes},'Critical raw stream exact binding');
      const stored=json(path.join(directory,assignedCase.caseId+'.receipt.json'));assert.deepEqual(stored,receipt,'Stored case receipt');
      assert.equal(receipt.sourceReceiptPath,assignedCase.caseId+'/baseline/'+assignedCase.caseId+'.receipt.json');
      const sourceReceipt=json(path.join(directory,receipt.sourceReceiptPath)),{sourceReceiptPath,...relocatedReceipt}=receipt;
      assert.deepEqual({...sourceReceipt,path:receipt.path},relocatedReceipt,'Relocated receipt preserves every original source stream proof');
      await verifyGraphStream(directory,receipt,assignedCase,assignedCase.operationIds.map(id=>items[indexById.get(id)]));
      report.criticalExact.streams.push({...receipt,path:'worker-'+index+'/'+receipt.path});report.criticalExact.records+=receipt.records;report.criticalExact.frames+=receipt.frames;
    }
    Object.assign(workerRecord,{bindings,counts:result.counts,coverage:result.coverage});
    }catch(error){workerRecord.validationError=String(error.stack||error);report.failures.push({kind:'parity-worker',worker:index,error:workerRecord.validationError});}
  }
  assert.equal(seen.size,required.size,'Every required original operation ID executed exactly once');
  for(const id of required)assert.ok(seen.has(id),'Missing actual original operation: '+id);
  report.uniqueCases=entries.length;report.cursorComparisons=selected.filter(item=>item.cursor).length;
  report.coverage.executedOperations=seen.size;report.coverage.fullAcceptance=!diagnostic&&!report.failures.length&&seen.size===parityDefinition.operations;
}

function compactProjection(projector,fixture,snapshot,comparisonGraph){
  const compare=(actual,expected,label)=>assert.equal(comparisonGraph.capture(actual).root,comparisonGraph.capture(expected).root,label);
  const {cursor}=snapshot,rows=fixture.source.steps,position=cursor.eventIndex,row=rows[Math.max(0,position)];
  const completed=cursor.eventIndex>=0&&cursor.milestone==='complete',initial=cursor.eventIndex<0;
  const playback={kind:'journey',status:initial?'idle':'paused',queue:rows,queuePosition:position,step:row,progress:initial?0:cursorPosition(fixture.compiled,cursor),stepElapsed:0,duration:0};
  const queue={rows,position,initial,empty:!rows.length,label:'Journey',kind:'journey',playback:playback.status,playerSnapshot:playback,scoped:false,cursor,rowComplete:rows.map((_,i)=>i<cursor.eventIndex||i===cursor.eventIndex&&completed),sourceComplete:completed,atEnd:completed};
  const adapter={steps:rows,labModel:fixture.model,learningDetail:'journey',player:{status:playback.status,snapshot:()=>playback},studyQueue:()=>queue,studyActor:fixture.studyActor};
  let result;const errors=[];
  try{
    result=projector(adapter,playback,snapshot);
  for(const [field,key] of Object.entries({cursor:'cursor',protocolClock:'protocolClock',state:'state',currentHoldings:'holdings',coverage:'coverage',observations:'observations',authority:'authority'})){
    assert.ok(Object.hasOwn(result,field),'Compact projection includes '+field);
    compare(result[field],snapshot[key],'Compact '+field+' is the exact supplied canonical prefix');
  }
  compare(result.row,row,'Compact action is exactly the active authored row');
  compare(result.from,fixture.studyActor(row.from),'Compact sender is the logical actor, not a folded card');
  compare(result.to,fixture.studyActor(row.to),'Compact receiver is the logical actor, not a folded card');
  assert.equal(result.sourceIndex,Math.max(0,position),'Compact action retains the authored source index');
  compare(result.authored,rows[Math.max(0,position)],'Compact authored action is the exact source row');
  assert.equal(result.initial,initial,'Compact explicit initial state');
  assert.equal(result.sourceComplete,completed,'Compact completion follows the supplied canonical milestone');
  }catch(error){errors.push(String(error.stack||error));}
  return {projection:result,errors};
}

async function boot(loading){
  assert.ok(['source','emitted'].includes(loading));
  const {installHarness}=await compactImport(root,'tests/dom-harness.mjs');
  const sandbox=loading==='emitted'?{structuredClone}:globalThis,harness=installHarness(sandbox);let Component,parse=JSON.parse;
  if(loading==='emitted'){
    const html=fs.readFileSync(path.join(root,'dist/auth-flow-studio.html'),'utf8'),scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];assert.equal(scripts.length,1,'Actual emitted script');
    const context=vm.createContext(sandbox);parse=vm.runInContext('JSON.parse',context);
    new vm.Script(scripts[0][1],{filename:'auth-flow-studio.actual-emitted.js'}).runInContext(context,{timeout:5000});Component=harness.registry.get('auth-flow-studio');
  }else ({AuthFlowStudio:Component}=await compactImport(root,'src/app.js'));
  assert.equal(typeof Component,'function');
  const app=new Component();harness.document.body.appendChild(app);app.connectedCallback();
  return {app,harness,parse,close(){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}};
}
function renderedProjection(app){
  if(app.presentationMode!=='compact')return;
  const actual=app.presenter.projection,snapshot=app.heldView.snapshot(),queue=app.studyQueue();
  try{
    assert.ok(actual,'Active emitted/source Compact presenter has a real projection');
    for(const [field,key] of Object.entries({cursor:'cursor',protocolClock:'protocolClock',state:'state',currentHoldings:'holdings',coverage:'coverage',observations:'observations',authority:'authority'}))compare(actual[field],snapshot[key],'Rendered Compact '+field+' is exactly canonical');
    compare(actual.rows,queue.rows,'Rendered Compact uses the actual active queue');
    assert.equal(actual.position,queue.position,'Rendered Compact exact active position');
    assert.equal(actual.initial,queue.initial,'Rendered Compact before-active-queue flag');
    assert.equal(actual.sourceComplete,queue.sourceComplete,'Rendered Compact source completion is not active-row completion');
    compare(actual.row,queue.rows[Math.max(0,queue.position)]||null,'Rendered Compact exact current action');
    assert.equal(app.querySelector('#compact-current-title')?.textContent,actual.row?.title||'No matching steps in this scope','Rendered current action title');
  }catch(error){
    exactData(compactId('rendered-projection-invalid',{contextId:snapshot.contextId,cursor:snapshot.cursor,kind:queue.kind,position:queue.position})+'-'+report.failures.length+'.json',{snapshot,projection:actual,queue});
    throw error;
  }
}
function switchExact(app,presentation){
  const beforeSwitch=app.player.snapshot(),held=app.heldView.snapshot();
  app.switchPresentation(presentation);
  const after=app.player.snapshot();
  compare(after,beforeSwitch,'Switch preserves the exact paused queue/player snapshot');
  compare(app.heldView.snapshot(),held,'Switch preserves full canonical holdings/state');
  assert.equal(app.presentationMode,presentation,'Actual active presentation choice');
  if(presentation==='compact')renderedProjection(app);
}
function inspectBoundary(app,index,edge='end'){
  app.inspectQueueBoundary(index,edge);
  const queue=app.studyQueue();
  assert.equal(queue.position,index,'Exact active queue index');
  assert.equal(app.player.snapshot().queuePosition,index,'Actual player queue position');
  renderedProjection(app);
  return app.heldView.snapshot();
}
function smoke(app,choiceId,presentation,boundary){
  assert.equal(app.labScenarioId,choiceId,'Actual selection');
  assert.ok(app.steps.length,'Authored source steps');
  const queue=app.studyQueue();assert.ok(queue.rows.length,'Journey queue');
  if(boundary==='terminal')inspectBoundary(app,queue.rows.length-1);else assert.equal(app.heldView.snapshot().cursor.eventIndex,-1,'Explicit initial state');
  assert.ok(app.querySelector('#scenario-title')?.textContent.trim(),'Visible scenario context');
  assert.ok(app.querySelector('#scenario-description')?.textContent.trim(),'Visible summary');
  assert.ok(app.querySelector('#lesson-inputs'),'Existing lesson evidence');
  assert.ok(app.querySelector('#protocol-state-panel'),'Canonical protocol evidence');
  assert.ok(app.querySelector('#held-inspector'),'Permission-scoped held evidence');
  assert.ok(app.querySelector(presentation==='compact'?'[data-compact-command="play"]':'#play'),'Actual presentation playback command');
  const text=app.textContent;assert.ok(!/\[object Object\]|\bundefined\b|\bNaN\b/.test(app.querySelector('#scenario-title').textContent),'Safe context text');
  assert.ok(!app.querySelector('script'),'No generated script elements in active app');
  assert.ok(text.length,'Rendered safe text');
  const snapshot=app.heldView.snapshot(),canonical=new ValueGraph().capture(snapshot);
  append('dom-observations.jsonl',{choiceId,presentation,boundary,cursor:snapshot.cursor,rootDigestAlgorithm:GRAPH_DIGEST,canonicalGraphDigest:canonical.digest,steps:app.steps.length,queueRows:queue.rows.length,contextTitle:app.querySelector('#scenario-title').textContent});
}
async function dom(){
  const loading=option('--loading','source'),choices=catalog.choices.filter(c=>!choiceFilter||c.id===choiceFilter),items=[];
  for(const choice of choices)for(const presentation of ['compact','full'])for(const boundary of ['initial','terminal'])items.push({id:'dom/'+loading+'/'+choice.id+'/'+presentation+'/'+boundary,choiceId:choice.id,loading,presentation,boundary,property:'Actual selection, controls, context, safe text and evidence'});
  const reachable=catalog.cases.filter(entry=>entry.kind!=='supported-core-configuration'&&(!choiceFilter||entry.choiceId===choiceFilter)&&(!caseFilter||entry.id===caseFilter));
  for(const entry of reachable)for(const presentation of ['compact','full'])items.push({id:'reachability/'+loading+'/'+entry.id+'/'+presentation,caseId:entry.id,choiceId:entry.choiceId,variant:entry.variant,member:entry.member,loading,presentation,boundary:'initial',property:'Actual registered case and comparison-member control reachability'});
  planned(items);const session=await boot(loading),{app}=session;
  try{
    compare(app.scenarioPicker.options.map(option=>option.id),catalog.choices.map(choice=>choice.id),'All actual picker identities/order');
    for(const option of app.scenarioPicker.options){
      const choice=catalog.choices.find(choice=>choice.id===option.id);
      assert.equal(option.title,choice.label,'Exact picker label: '+choice.id);
      assert.equal(option.summary,choice.summary,'Exact picker summary: '+choice.id);
      assert.equal(option.category,choice.category,'Exact picker category: '+choice.id);
      if(choice.kind==='registered-model'){
        const expected=choice.profile?[choice.profile.name,choice.profile.publicationStatus,choice.profile.supportStatus].filter(Boolean).join(' · '):'';
        assert.equal(option.profileLabel,expected,'Exact profile qualifications: '+choice.id);
      }
    }
    let index=0;
    for(const choice of choices)for(const presentation of ['compact','full'])for(const boundary of ['initial','terminal'])attempt(index++,()=>{
      // Reselecting creates the actual initial state instead of synthesizing a seek.
      app.selectLabScenario(choice.id);app.pauseForStudy();switchExact(app,presentation);smoke(app,choice.id,presentation,boundary);
    });
    for(const entry of reachable)for(const presentation of ['compact','full'])attempt(index++,()=>{
      resetSelection(app,entry,null);switchExact(app,presentation);
      assert.equal(app.labScenarioId,entry.choiceId);assert.equal(app.lessonVariant,entry.variant);
      assert.equal(app.lessonSubfixture||null,entry.member);
      if(app.baseLabModel?.variantChoices?.length)assert.equal(app.querySelector('#lesson-case')?.value,entry.variant,'Named case control reachability');
      const members=app.labModel?.subfixtureChoices||[],memberSelectable=members.length>1;
      if(entry.member){
        assert.ok(members.some(member=>member.id===entry.member),'Selected comparison member is declared');
        if(memberSelectable)assert.equal(app.querySelector('#lesson-subfixture')?.value,entry.member,'Real comparison member control reachability');
        else assert.equal(app.querySelector('#lesson-subfixture'),null,'Singleton member renders no selector');
      }
      append('reachability.jsonl',{caseId:entry.id,presentation,choiceId:app.labScenarioId,variant:app.lessonVariant,member:app.lessonSubfixture||null,memberSelectable});
    });
  }finally{session.close();}
  report.uniquePickerIdentities=choices.length;report.reachableCases=reachable.length;report.loading=loading;
}
function bridgeModel(model,parse){
  const bridged=parse(JSON.stringify(model));
  for(const [key,value] of Object.entries(model))if(typeof value==='function')bridged[key]=(...args)=>{const result=value.apply(model,args);return result===undefined?undefined:parse(JSON.stringify(result));};
  return bridged;
}
function resetSelection(app,entry,sourceOnlyModel){
  if(Object.hasOwn(app,'labModel'))delete app.labModel;
  if(sourceOnlyModel)Object.defineProperty(app,'labModel',{configurable:true,value:sourceOnlyModel});
  app.selectLabScenario(entry.choiceId,{variant:entry.variant});
  if(entry.member)app.selectLessonSubfixture(entry.member);
  if(entry.kind==='supported-core-configuration'){Object.assign(app,entry.configuration);if(Object.hasOwn(entry.configuration,'binding'))app.samlBinding=entry.configuration.binding;if(Object.hasOwn(entry.configuration,'initiation'))app.samlInitiation=entry.configuration.initiation;if(Object.hasOwn(entry.configuration,'encryptAssertions'))app.assertionProtection=entry.configuration.encryptAssertions?'encrypted':'signed';app.refreshConfiguration();}
  app.pauseForStudy();
}
function cursorPosition(compiled,cursor){
  if(cursor.eventIndex<0)return null;
  const step=compiled.steps[cursor.eventIndex];assert.ok(step,'Canonical source step for cursor');
  // The compiler supplies before/complete even when a source step has no held effects.
  if(cursor.milestone==='before')return 0;
  if(cursor.milestone==='complete')return 1;
  const milestone=compiled.plan.events[step.id]?.milestones?.find(m=>m.id===cursor.milestone);
  assert.ok(milestone,'Authored intermediate milestone');return milestone.at;
}
async function deepChecks(){
  const loading=option('--loading','source'),entries=deep.fixtures.map(f=>allCases.find(c=>c.id===f.caseId)).filter(c=>(!caseFilter||c.id===caseFilter)&&(!choiceFilter||c.choiceId===choiceFilter));
  const registry=await compactRegistry(root),fixtures=[];
  for(const entry of entries){const fixture=await compactFixture(registry,entry);fixtures.push({entry,cursors:fixture.compiled.cursors});}
  const items=[];
  for(const {entry,cursors} of fixtures)for(const presentation of ['compact','full']){
    for(const cursor of cursors)items.push({id:'deep/'+loading+'/'+entry.id+'/'+presentation+'/'+cursor.eventIndex+'/'+cursor.milestone,caseId:entry.id,presentation,loading,cursor,property:'Exact authored prefix and bidirectional view continuity'});
    items.push({id:'deep/'+loading+'/'+entry.id+'/'+presentation+'/rewind',caseId:entry.id,presentation,loading,operation:'rewind',property:'Rewind restores all authored prefixes'});
    items.push({id:'deep/'+loading+'/'+entry.id+'/'+presentation+'/field-history',caseId:entry.id,presentation,loading,operation:'field-history',property:'Actual field queue exact boundaries and switch continuity'});
    items.push({id:'deep/'+loading+'/'+entry.id+'/'+presentation+'/exact-history',caseId:entry.id,presentation,loading,operation:'exact-history',property:'Every available artifact exact queue and switch continuity'});
  }
  planned(items);const session=await boot(loading),{app}=session;
  try{
    let index=0;
    for(const {entry} of fixtures){
      const fixture=await compactFixture(registry,entry);
      for(const presentation of ['compact','full']){
      const injected=entry.kind==='source-only-factory'?bridgeModel(fixture.model,session.parse):null;
      resetSelection(app,entry,injected);switchExact(app,presentation);
      const actualCompiled=app.heldView.compiled();
      const {buildHeldObjects}=await compactImport(root,'src/held-objects.js');
      const {projectHeldObjects}=await compactImport(root,'src/held-object-state.js');
      // Build independently from real source factory outputs, with only the app's
      // immutable context identity supplied at compilation, never normalized afterward.
      const independent=buildHeldObjects({choiceId:entry.choiceId,model:fixture.model,steps:fixture.source.steps,actors:fixture.actors,config:{...app.protocolConfig(),oidcFlow:app.oidcFlow,tokenProtection:app.tokenProtection},contextId:actualCompiled.contextId});
      const independentProject=cursor=>projectHeldObjects(independent,cursor);
      const observed=[],comparisonGraph=new ValueGraph();
      for(const cursor of fixture.compiled.cursors)attempt(index++,()=>{
        app.inspectSourceCursor(cursor);
        const actual=app.heldView.snapshot();
        renderedProjection(app);
        compare(actual.cursor,cursor,'Exact canonical milestone');
        const expected=independentProject(cursor),actualValue=comparisonGraph.capture(actual),independentValue=comparisonGraph.capture(expected),equal=actualValue.root===independentValue.root;
        append('deep-observations.jsonl',{caseId:entry.id,presentation,loading,cursor,rootDigestAlgorithm:GRAPH_DIGEST,actualRoot:actualValue.root,independentRoot:independentValue.root,actualGraphDigest:actualValue.digest,independentGraphDigest:independentValue.digest,equal});
        if(!equal)exactData(compactId('deep-difference',{entry:entry.id,presentation,cursor})+'.json',{actual,expected});
        assert.equal(actualValue.root,independentValue.root,'Actual app full canonical prefix equals independent source-model compilation');
        observed.push({cursor,root:actualValue.root});
        switchExact(app,presentation==='compact'?'full':'compact');switchExact(app,presentation);
      });
      attempt(index++,()=>{
        for(const row of [...observed].reverse()){
          app.inspectSourceCursor(row.cursor);
          renderedProjection(app);
          assert.equal(comparisonGraph.capture(app.heldView.snapshot()).root,row.root,'Rewind restores the full canonical prefix');
        }
      });
      attempt(index++,()=>{
        resetSelection(app,entry,injected);
        const ids=[...new Set(fixture.source.steps.flatMap(step=>[...(step.fields||[]),...(step.attributeOperations||[]).map(op=>op.attributeId)]))];
        const operations=[];
        for(const attributeId of ids){
          app.enterFieldTrace(attributeId);const queue=app.studyQueue();
          assert.ok(Array.isArray(queue.rows),'Actual active field queue');
          switchExact(app,presentation==='compact'?'full':'compact');switchExact(app,presentation);
          for(let row=0;row<queue.rows.length;row++){inspectBoundary(app,row,'start');switchExact(app,presentation==='compact'?'full':'compact');switchExact(app,presentation);inspectBoundary(app,row,'end');}
          operations.push({attributeId,rows:queue.rows.length,empty:queue.empty});app.returnToJourney();
        }
        append('deep-history.jsonl',{caseId:entry.id,presentation,kind:'field',operations});
      });
      attempt(index++,()=>{
        resetSelection(app,entry,injected);const operations=[];
        for(const artifact of actualCompiled.plan.artifacts){
          app.enterObjectTrace(artifact.artifactId);const queue=app.studyQueue();
          switchExact(app,presentation==='compact'?'full':'compact');switchExact(app,presentation);
          for(let row=0;row<queue.rows.length;row++){inspectBoundary(app,row,'start');switchExact(app,presentation==='compact'?'full':'compact');switchExact(app,presentation);inspectBoundary(app,row,'end');}
          operations.push({artifactId:artifact.artifactId,rows:queue.rows.length,empty:queue.empty});app.returnToJourney();
        }
        append('deep-history.jsonl',{caseId:entry.id,presentation,kind:'exact',operations});
      });
    }
    }
  }finally{session.close();}
  report.uniqueCases=fixtures.length;report.loading=loading;
}

try{
  assert.equal(shaFile(catalogPath),deep.catalogSha256,'Deep cases bind the frozen catalog');
  assert.equal(shaFile(catalogPath),parityDefinition.catalogSha256,'Parity descriptor binds the frozen catalog');
  assert.equal(shaFile(deepPath),parityDefinition.deepSha256,'Parity descriptor binds the frozen deep cases');
  compare(before.control.files,acceptedIdentity.files,'Accepted control inputs changed since phase-0 freeze');
  const canonicalControl=captureCanonicalInputs(control),canonicalCandidate=captureCanonicalInputs(root);
  report.canonicalSourceBindings={
    control:{algorithm:canonicalControl.sourceAlgorithm,files:canonicalControl.sourceFileCount,sha256:canonicalControl.canonicalSha256},
    candidate:{algorithm:canonicalCandidate.sourceAlgorithm,files:canonicalCandidate.sourceFileCount,sha256:canonicalCandidate.canonicalSha256}
  };
  assert.equal(canonicalControl.canonicalSha256,parityDefinition.acceptedCanonicalSourceSha256,'Actual accepted canonical source binding');
  assert.equal(canonicalCandidate.canonicalSha256,parityDefinition.candidateCanonicalSourceSha256,'Actual candidate canonical source binding');
  if(mode==='parity')await parity();
  else if(mode==='dom')await dom();
  else if(mode==='deep')await deepChecks();
  else {
    const jobs=[['parity'],['dom','--loading','source'],['dom','--loading','emitted'],['deep','--loading','source'],['deep','--loading','emitted']];
    planned(jobs.map(args=>({id:args.join('/'),args,property:'Independent sequential complete collection'})));
    for(const [index,args] of jobs.entries())attempt(index,()=>{
      const command=[producer,...args,'--root',root,'--control',control,'--manifest-dir',phase0,'--output',path.join(out,'child-'+index),...(caseFilter?['--case',caseFilter]:[]),...(choiceFilter?['--choice',choiceFilter]:[]),...(args[0]==='parity'?['--workers',String(workerCount),...(operationFilter?['--operation',operationFilter]:[])]:[])];
      const child=spawnSync(process.execPath,command,{encoding:'utf8',maxBuffer:64*1024*1024});
      fs.writeFileSync(path.join(out,'child-'+index+'.stdout.txt'),child.stdout||'',{flag:'wx'});fs.writeFileSync(path.join(out,'child-'+index+'.stderr.txt'),child.stderr||'',{flag:'wx'});
      const directory=path.join(out,'child-'+index);
      report.children??=[];
      const childRecord={index,args,result:{status:child.status,signal:child.signal},artifacts:fs.existsSync(directory)?Object.fromEntries(fs.readdirSync(directory,{withFileTypes:true}).filter(entry=>entry.isFile()).map(entry=>[entry.name,artifactBinding(path.join(directory,entry.name))])):{}};
      report.children.push(childRecord);
      assert.ifError(child.error);assert.equal(child.status,0,'Complete child collection: '+args.join(' '));
      const result=json(path.join(directory,'status.json'));childRecord.bindings=verifyArtifacts(directory,result);
      assert.equal(result.status,'passed','Child reports completed collection');
      compare(result.inputIdentity,before,'Child binds the same exact inputs');compare(result.afterInputIdentity,before,'Child inputs unchanged');
      if(args[0]==='parity'&&!diagnostic){assert.equal(result.coverage.scope,'full-frozen-parity');assert.equal(result.coverage.fullAcceptance,true);assert.equal(result.coverage.executedOperations,parityDefinition.operations);}
      childRecord.coverage=result.coverage||{scope:diagnostic?'diagnostic-subset':'complete-phase'};
    });
    report.coverage={scope:diagnostic?'diagnostic-subset':'complete-five-phases',fullAcceptance:!diagnostic&&report.items.every(item=>item.status==='passed')};
  }
}catch(error){report.failures.push({kind:'producer',error:String(error.stack||error)});}
finally{
  try{
    report.afterInputIdentity={candidate:compactInputIdentity(root,bindingFiles()),control:compactInputIdentity(control,bindingFiles())};
    compare(report.afterInputIdentity,before,'Bound source, HTML, helper, producer and manifests remain unchanged');
    if(report.executionManifestSha256)assert.equal(shaFile(path.join(out,'execution-manifest.json')),report.executionManifestSha256,'Frozen execution manifest unchanged');
    if(assignmentPath&&report.assignmentBinding)assert.deepEqual(artifactBinding(path.resolve(assignmentPath)),report.assignmentBinding,'Exact source/worker operation assignment remains unchanged');
    report.inputsUnchanged=true;
  }catch(error){report.inputsUnchanged=false;report.failures.push({kind:'changed-inputs',error:String(error.stack||error)});}
  report.finishedAt=new Date().toISOString();report.counts=Object.fromEntries(['passed','failed','unperformed'].map(status=>[status,report.items.filter(item=>item.status===status).length]));report.counts.attempted=report.items.filter(item=>item.status!=='unperformed').length;report.counts.inFlight=report.items.filter(item=>item.status==='attempted').length;
  const required=report.requiredOperationIds?new Set(report.requiredOperationIds):null;
  report.counts.requiredUnperformed=required?report.items.filter(item=>required.has(item.id)&&item.status!=='passed'&&item.status!=='failed').length:report.counts.unperformed;
  report.status=report.failures.length||report.counts.requiredUnperformed||report.counts.failed||report.counts.inFlight?'failed':'passed';
  if(!report.coverage)report.coverage={scope:diagnostic?'diagnostic-subset':'complete-phase',fullAcceptance:false};
  if(report.status!=='passed')report.coverage.fullAcceptance=false;
  report.completion=report.status==='passed'?(report.coverage.scope.includes('subset')?'subset-complete-not-full-acceptance':'complete'):'incomplete-or-failed';
  report.artifacts=Object.fromEntries(fs.readdirSync(out,{withFileTypes:true}).filter(entry=>entry.isFile()).map(entry=>{const name=entry.name,absolute=path.join(out,name);return [name,{sha256:shaFile(absolute),bytes:fs.statSync(absolute).size}];}));
  writeNew(path.join(out,'status.json'),report);console.log(JSON.stringify({mode,status:report.status,counts:report.counts,failures:report.failures.length,output:out},null,2));
  if(report.status!=='passed')process.exitCode=1;
}
