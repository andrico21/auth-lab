#!/usr/bin/env bun
// Replays observed renderer inputs through the actual source-resolution path.
// Missing translations are deliberate here, never evidence of native coverage.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {fileURLToPath,pathToFileURL} from 'node:url';

const ownRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const identity=file=>{const bytes=fs.readFileSync(file);return {path:fs.realpathSync(file),bytes:bytes.length,sha256:digest(bytes)};};
const load=file=>JSON.parse((file.endsWith('.gz')?gunzipSync(fs.readFileSync(file)):fs.readFileSync(file)).toString('utf8'));
const sourceFailures=new Set(['missing-source-contract','ambiguous-source-contract','stale-source-or-parameter-contract','ambiguous-explanation-binding','missing-explanation-binding']);
const translationFailures=new Set(['missing-translation','stale-or-invalid-translation','missing-human-translation']);
const HELP=`Usage: bun tools/verification/localization/renderer-bindings.mjs
  --source-table=FILE --requests=FILE --out=NEW_DIRECTORY [--root=CHECKOUT]
  [--resources=GENERATED_MODULE --locale=NATIVE_TAG]
Inputs are a compact English source table and actual pilot-families request capture:
historical schema 1 monolithic JSON or schema 2 manifest with same-directory chunks.
Both may be gzip-compressed. Output is exclusive and outside input/candidate roots.
Default mode checks source selection using an empty diagnostic German catalog;
deliberate missing-translation fallbacks are recorded, never native coverage.
The paired resources/locale options use actual compiled native data and reject every
fallback, including nested human-reference failures. No approvals are manufactured.
Every unmatched request and matched semantic binding is retained without sampling.
Neither mode establishes actual native browser, linguistic, human or release acceptance.`;

// These are the capture producer's exact tagged scalar encodings, not translations.
function revive(value){
  if(Array.isArray(value))return value.map(revive);
  if(value&&typeof value==='object'){
    const keys=Object.keys(value);
    if(keys.length===1&&keys[0]==='$undefined'&&value.$undefined===true)return undefined;
    if(keys.length===1&&keys[0]==='$bigint')return BigInt(value.$bigint);
    return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,revive(item)]));
  }
  return value;
}

const positive=value=>Number.isSafeInteger(value)&&value>0;
function validateRequests(requests,label){
  assert.ok(Array.isArray(requests),label+': requests must be an array');
  let calls=0;
  for(const request of requests){
    assert.ok(request&&typeof request==='object'&&!Array.isArray(request),label+': invalid request');
    assert.ok(['resolve','rich','explanation'].includes(request.method),label+': invalid method');
    assert.ok(positive(request.count),label+': invalid request multiplicity');
    assert.ok(Array.isArray(request.surfaces)&&request.surfaces.every(surface=>typeof surface==='string'),label+': invalid surfaces');
    calls+=request.count;assert.ok(Number.isSafeInteger(calls),label+': call count overflow');
  }
  return calls;
}
function* requestBatches(capture,manifestPath,report){
  assert.equal(capture.kind,'actual-renderer-family-localizer-requests','Unexpected capture kind');
  assert.ok(positive(capture.requestCalls),'Invalid global call count');
  report.capture={schemaVersion:capture.schemaVersion,kind:capture.kind,locale:capture.locale,requestCalls:capture.requestCalls};
  if(capture.schemaVersion===1){
    const calls=validateRequests(capture.requests,'Historical schema 1');
    assert.equal(calls,capture.requestCalls,'Historical call accounting mismatch');
    report.capture.format='historical-schema-1-monolithic';
    report.capture.recordQualification='Globally deduplicated captured request records';
    report.capture.requestRecords=capture.requests.length;
    yield {requests:capture.requests,chunkIndex:null};
    return;
  }
  assert.equal(capture.schemaVersion,2,'Unsupported capture schema version');
  report.capture.format='schema-2-chunk-manifest';
  report.capture.recordQualification='Sum of per-chunk deduplicated request records; not global unique requests';
  report.capture.requestRecords=capture.requestRecords;
  assert.ok(positive(capture.requestRecords),'Invalid manifest record count');
  assert.ok(Array.isArray(capture.requestChunks)&&capture.requestChunks.length,'Missing request chunks');
  assert.ok(!Object.hasOwn(capture,'requests'),'Chunk manifest must not contain monolithic requests');
  const directory=path.dirname(manifestPath),seen=new Set();
  report.inputs.requestChunks=[];
  let records=0,calls=0;
  for(let index=0;index<capture.requestChunks.length;index++){
    const descriptor=capture.requestChunks[index];
    assert.ok(descriptor&&typeof descriptor==='object','Invalid chunk descriptor');
    assert.equal(descriptor.chunkIndex,index+1,'Chunk indices must be contiguous and 1-based');
    const basename=descriptor.path;
    assert.ok(typeof basename==='string'&&basename!=='.'&&basename!=='..'&&/^[A-Za-z0-9][A-Za-z0-9._-]*\.json\.gz$/.test(basename),'Chunk path must be a safe gzip JSON basename');
    assert.ok(!seen.has(basename),'Duplicate chunk path');seen.add(basename);
    assert.ok(positive(descriptor.bytes)&&positive(descriptor.decodedBytes)&&positive(descriptor.requestRecords)&&positive(descriptor.requestCalls),'Invalid chunk sizes or counts');
    assert.ok(/^[a-f0-9]{64}$/.test(descriptor.sha256)&&/^[a-f0-9]{64}$/.test(descriptor.decodedSha256),'Invalid chunk hashes');
    const file=path.join(directory,basename);
    assert.equal(fs.realpathSync(file),file,'Chunk must not resolve through a symlink');
    const encoded=fs.readFileSync(file);
    assert.equal(encoded.length,descriptor.bytes,'Chunk encoded byte mismatch');
    assert.equal(digest(encoded),descriptor.sha256,'Chunk encoded SHA256 mismatch');
    const decoded=gunzipSync(encoded);
    assert.equal(decoded.length,descriptor.decodedBytes,'Chunk decoded byte mismatch');
    assert.equal(digest(decoded),descriptor.decodedSha256,'Chunk decoded SHA256 mismatch');
    report.inputs.requestChunks.push({path:file,bytes:encoded.length,sha256:digest(encoded),decodedBytes:decoded.length,decodedSha256:digest(decoded),chunkIndex:index+1,requestRecords:descriptor.requestRecords,requestCalls:descriptor.requestCalls});
    const chunk=JSON.parse(decoded.toString('utf8'));
    assert.equal(chunk.schemaVersion,1,'Unexpected chunk schema');
    assert.equal(chunk.kind,'actual-renderer-family-localizer-request-chunk','Unexpected chunk kind');
    assert.equal(chunk.chunkIndex,index+1,'Chunk payload index mismatch');
    assert.equal(typeof chunk.stage,'string','Chunk stage is required');
    assert.equal(chunk.requestRecords,descriptor.requestRecords,'Chunk record metadata mismatch');
    assert.equal(chunk.requestCalls,descriptor.requestCalls,'Chunk call metadata mismatch');
    assert.equal(validateRequests(chunk.requests,basename),chunk.requestCalls,'Chunk call accounting mismatch');
    assert.equal(chunk.requests.length,chunk.requestRecords,'Chunk record accounting mismatch');
    records+=chunk.requestRecords;calls+=chunk.requestCalls;
    assert.ok(Number.isSafeInteger(records)&&Number.isSafeInteger(calls),'Manifest count overflow');
    yield {requests:chunk.requests,chunkIndex:index+1};
  }
  assert.equal(records,capture.requestRecords,'Manifest record accounting mismatch');
  assert.equal(calls,capture.requestCalls,'Manifest call accounting mismatch');
}

export async function main(argv=process.argv.slice(2)){
  if(argv.includes('--help')){console.log(HELP);return 0;}
  const options={};
  for(const arg of argv){
    const match=/^--(source-table|requests|out|root|resources|locale)=(.+)$/.exec(arg);
    assert.ok(match,'Unknown or valueless option: '+arg+'\n'+HELP);
    assert.ok(!Object.hasOwn(options,match[1]),'Repeated option: '+match[1]);
    options[match[1]]=match[2];
  }
  for(const key of ['source-table','requests','out'])assert.ok(options[key],'Required --'+key+'\n'+HELP);
  const native=Object.hasOwn(options,'resources');
  assert.equal(native,Object.hasOwn(options,'locale'),'--resources and --locale must be supplied together');
  const root=fs.realpathSync(options.root||ownRoot),tablePath=fs.realpathSync(options['source-table']),requestsPath=fs.realpathSync(options.requests);
  const out=path.resolve(options.out);fs.mkdirSync(path.dirname(out),{recursive:true});
  const destination=path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
  for(const input of [root,path.dirname(tablePath),path.dirname(requestsPath)])assert.ok(destination!==input&&!destination.startsWith(input+path.sep),'Output must not mutate an input root');
  fs.mkdirSync(out);
  const report={
    schemaVersion:2,kind:'observed-renderer-source-bindings',mode:native?'actual-native-catalog':'source-selection-only',status:'collecting',
    argv:[process.execPath,...process.argv.slice(1)],startedAt:new Date().toISOString(),
    scope:'Captured renderer source-contract selection'+(native?' and actual compiled native-contract rendering':' only')+'. No browser execution, full-corpus translation completion, linguistic/human/AT, performance or release acceptance.',
    method:native?'Unmodified Localizer with actual compiled native resources and observer wrappers. Every fallback, including a nested missing human reference, fails this mechanical replay.':'Unmodified Localizer with observer wrappers and an explicitly empty diagnostic German catalog. Deliberate missing-translation fallbacks count as neither failures nor translation success.',
    inputs:{sourceTable:identity(tablePath),requests:identity(requestsPath),localizer:identity(path.join(root,'src/localization.js')),producer:identity(fileURLToPath(import.meta.url)),runtime:identity(process.execPath),...(native?{resources:identity(options.resources)}:{})},
    summary:{requestRecords:0,observedCalls:0,matchedSourceRecords:0,matchedSourceCalls:0,emptyExplanationRecords:0,unmatchedRecords:0,unmatchedCalls:0,methods:{},sourceFailureReasons:{},nativeTranslationFailureReasons:{},deliberateTranslationFallbackReasons:{}},errors:[]
  };
  const unmatched=[],resolutions=[];
  try{
    const table=load(tablePath),capture=load(requestsPath);
    assert.equal(table.format,'auth-lab-l10n-source-table');assert.equal(table.schemaVersion,2);
    report.captureEvidence={methods:capture.methods,events:capture.events,errors:capture.errors,diagnostics:capture.diagnostics,storage:capture.storage};
    assert.deepEqual(capture.errors||[],[],'Capture producer errors must not be discarded');
    const {Localizer}=await import(pathToFileURL(path.join(root,'src/localization.js')).href);
    let catalogs={de:{locale:'de',entries:{}}},locale='de';
    if(native){
      assert.ok(Localizer.valid(options.locale)&&options.locale!=='en','Actual native replay requires an allowlisted non-English locale');
      const resources=await import(pathToFileURL(report.inputs.resources.path).href),metadata=resources.LOCALIZATION_RESOURCE_METADATA;
      assert.equal(metadata.sourceSetSha256,table.sourceSetSha256,'Compiled native data must match the exact source checkpoint');
      assert.ok(metadata.locales.includes(options.locale)&&Object.hasOwn(resources.LOCALIZATION_CATALOGS,options.locale),'Requested compiled native catalog must actually exist');
      catalogs=resources.LOCALIZATION_CATALOGS;locale=options.locale;
      report.locale=locale;report.resourceMetadata=metadata;
    }
    const localizer=new Localizer({host:{},bindings:table,catalogs,initialLocale:locale});
    if(localizer.initialPreparation)await localizer.initialPreparation;
    localizer.ensureContracts();report.sourceSetSha256=localizer.sourceSetSha256;
    const originalResolve=localizer.resolve.bind(localizer),originalFallback=localizer.fallback.bind(localizer);
    let current;
    localizer.resolve=(...args)=>{if(current)current.selectedKeys.add(args[0]);return originalResolve(...args);};
    localizer.fallback=(key,source,reason,html)=>{if(current)current.reasons.push(reason);return originalFallback(key,source,reason,html);};
    let index=0;
    for(const batch of requestBatches(capture,requestsPath,report)){
      for(let chunkRecordIndex=0;chunkRecordIndex<batch.requests.length;chunkRecordIndex++,index++){
      const request=batch.requests[chunkRecordIndex],count=request.count;
      const location={requestIndex:index,chunkIndex:batch.chunkIndex,chunkRecordIndex};
      assert.ok(Number.isSafeInteger(count)&&count>0,'Actual request multiplicity is required');
      report.summary.requestRecords++;report.summary.observedCalls+=count;
      report.summary.methods[request.method]=(report.summary.methods[request.method]||0)+1;
      current={selectedKeys:new Set(),reasons:[]};
      try{
        const parameters=revive(request.parameters||{}),context=revive(request.context||{});
        if(request.method==='explanation'){
          // The capture stores structured parameters separately from scalar context.
          localizer.explanation(request.owner,request.field,request.exactEnglish,{...context,parameters},request.html);
        }else if(request.method==='resolve')localizer.resolve(request.key,request.exactEnglish,parameters,request.html,revive(request.rich||{}));
        else if(request.method==='rich'){
          if(typeof request.template==='string')localizer.rich(request.key,request.template,parameters);
          else{
            // Older captures retain the exact rendered English and typed descriptors.
            // This is precisely rich()'s native resolve boundary, not a fake template.
            const values=Object.fromEntries(Object.entries(parameters).map(([name,descriptor])=>[name,descriptor.value]));
            localizer.resolve(request.key,request.exactEnglish,values,true,parameters);
          }
        }else throw new TypeError('Unknown captured renderer method: '+request.method);
      }catch(error){current.reasons.push('exception:'+error.message);}
      const failures=[];
      for(const reason of current.reasons){
        if(translationFailures.has(reason)){
          if(native){report.summary.nativeTranslationFailureReasons[reason]=(report.summary.nativeTranslationFailureReasons[reason]||0)+1;failures.push(reason);}
          else report.summary.deliberateTranslationFallbackReasons[reason]=(report.summary.deliberateTranslationFallbackReasons[reason]||0)+1;
        }else failures.push(sourceFailures.has(reason)||reason.startsWith('exception:')?reason:'unknown-fallback-reason:'+reason);
      }
      const emptyExplanation=request.method==='explanation'&&request.exactEnglish==='';
      if(!emptyExplanation&&!current.selectedKeys.size&&!failures.length)failures.push('no-selected-source-binding');
      if(failures.length){
        report.summary.unmatchedRecords++;report.summary.unmatchedCalls+=count;
        for(const reason of failures)if(!translationFailures.has(reason))report.summary.sourceFailureReasons[reason]=(report.summary.sourceFailureReasons[reason]||0)+1;
        unmatched.push({...request,...location,sourceFailureReasons:failures.filter(reason=>!translationFailures.has(reason)),nativeTranslationFailureReasons:failures.filter(reason=>translationFailures.has(reason))});
      }else if(emptyExplanation){
        report.summary.emptyExplanationRecords++;
        resolutions.push({...location,method:request.method,count,bindings:[],emptyExplanation:true});
      }else{
        report.summary.matchedSourceRecords++;report.summary.matchedSourceCalls+=count;
        const bindings=[...current.selectedKeys].map(key=>{
          const contract=localizer.contracts.get(key);assert.ok(contract,'Selected binding must exist');
          return {key,sourceSha256:contract.sourceSha256,owner:contract.owner,context:contract.context,classification:contract.classification};
        });
        resolutions.push({...location,method:request.method,count,bindings});
      }
      current=null;
    }
    }
    assert.equal(report.summary.observedCalls,capture.requestCalls,'Every captured call multiplicity is accounted for');
    assert.equal(report.summary.requestRecords,report.capture.requestRecords,'Every captured record is accounted for');
    assert.equal(report.summary.requestRecords,report.summary.matchedSourceRecords+report.summary.emptyExplanationRecords+report.summary.unmatchedRecords);
    assert.deepEqual(identity(tablePath),report.inputs.sourceTable,'Source table changed during replay');
    assert.deepEqual(identity(requestsPath),report.inputs.requests,'Captured requests changed during replay');
    assert.deepEqual(identity(path.join(root,'src/localization.js')),report.inputs.localizer,'Localizer changed during replay');
    if(native)assert.deepEqual(identity(options.resources),report.inputs.resources,'Actual compiled native resources changed during replay');
    assert.deepEqual(identity(fileURLToPath(import.meta.url)),report.inputs.producer,'Replay producer changed during execution');
    report.status=unmatched.length?(native?'failed-native-catalog-bindings':'failed-source-bindings'):(native?'passed-native-catalog-bindings-only':'passed-source-bindings-only');
  }catch(error){report.errors.push(String(error.stack||error));report.status='failed-producer';}
  finally{
    for(const chunk of report.inputs.requestChunks||[]){
      try{
        assert.deepEqual(identity(chunk.path),{path:chunk.path,bytes:chunk.bytes,sha256:chunk.sha256},'Captured chunk changed during replay');
        const decoded=gunzipSync(fs.readFileSync(chunk.path));
        assert.equal(decoded.length,chunk.decodedBytes,'Chunk decoded bytes changed during replay');
        assert.equal(digest(decoded),chunk.decodedSha256,'Chunk decoded SHA256 changed during replay');
      }catch(error){report.errors.push(String(error.stack||error));report.status='failed-producer';}
    }
  }
  const packed=(name,rows)=>{
    const decoded=Buffer.from(rows.map(row=>JSON.stringify(row)).join('\n')+(rows.length?'\n':'')),encoded=gzipSync(decoded);
    fs.writeFileSync(path.join(out,name),encoded,{flag:'wx'});
    return {path:name,bytes:encoded.length,sha256:digest(encoded),decodedBytes:decoded.length,decodedSha256:digest(decoded),records:rows.length};
  };
  report.artifacts={unmatched:packed('unmatched.jsonl.gz',unmatched),resolutions:packed('resolutions.jsonl.gz',resolutions)};
  report.finishedAt=new Date().toISOString();
  fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({status:report.status,sourceSetSha256:report.sourceSetSha256,summary:report.summary,errors:report.errors,report:path.join(out,'report.json')}));
  return ['passed-source-bindings-only','passed-native-catalog-bindings-only'].includes(report.status)?0:1;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{process.exitCode=await main();}catch(error){console.error(String(error.stack||error));process.exitCode=1;}
}
