#!/usr/bin/env bun
// Reuse the established JSON evidence codec; preserve complete original report bytes.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync,gunzipSync,brotliDecompressSync,createGunzip} from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Readable} from 'node:stream';
import {finished} from 'node:stream/promises';
import {EvidenceEncoder,EvidenceDecoder} from './compact-evidence-codec.mjs';

const self=fileURLToPath(import.meta.url),codec=fileURLToPath(new URL('./compact-evidence-codec.mjs',import.meta.url));
const streamName='original-json.dag.jsonl.gz',indexName='record-index.json',proofName='encoding-proof.json';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=message=>{throw new Error('Compact JSON evidence: '+message);};
const help=`Usage:
  bun tools/verification/compact-json-evidence.mjs encode --manifest=INPUT.json --out=FRESH_DIRECTORY
  bun tools/verification/compact-json-evidence.mjs restore --input=original-json.dag.jsonl.gz --record-index=N --expected-records=N --expected-last-sha256=HEX --out=NEW_FILE
  bun tools/verification/compact-json-evidence.mjs restore --input=original-json.dag.jsonl.gz --case-id=ARCHIVE_PATH --expected-records=N --expected-last-sha256=HEX --out=NEW_FILE
  bun tools/verification/compact-json-evidence.mjs restore-all --input=original-json.dag.jsonl.gz --expected-records=N --expected-last-sha256=HEX --out=FRESH_DIRECTORY
  restore/restore-all accept --compression=gzip|brotli (default gzip).

Manifest: {"schemaVersion":1,"entries":[{"source":"FILE","path":"review/report.json","compression":"none|gzip|brotli"}]}.
Sources are resolved relative to the manifest. Paths identify the exact original
JSON reports after any standard carrier decoding, not an interpretation of them.
Only JSON.stringify-compatible serialization is accepted. Every reconstructed
original UTF8 byte is independently compared before the report enters the stream.
Whitespace prefix/suffix and indentation are retained. Noncanonical JSON fails
closed instead of silently normalizing or omitting it.

The existing compact-evidence-structural-v1 codec shares repeated report data
across records. No fields, observations, failures or qualifiers are removed.
Successful output: ${streamName}, ${indexName}, ${proofName}, stream-consumer.json, encoding-status.jsonl.
Only the final proof with status ready establishes readiness. Failed fresh
outputs are retained with encoding-failure.json; existing directories/files are
never overwritten. All input, producer, codec and runtime identities are bound.

Restore uses the established codec decoder with BOTH external complete-tail
bindings before releasing the selected original report. It verifies original
byte count/SHA256 and creates the output exclusively. Restore-all decodes once,
checks every original report and publishes reports/ plus restoration-proof.json
only after the complete input tail and all source identities pass. Failed
private stages are retained; existing outputs are never overwritten.
This is byte-preserving transport, not application or reviewer acceptance.
`;

function regular(filename,directory=false){
  const absolute=path.resolve(filename),stat=fs.lstatSync(absolute);
  if(fs.realpathSync(absolute)!==absolute||stat.isSymbolicLink()||(directory?!stat.isDirectory():!stat.isFile()))fail('Expected symlink-free '+(directory?'directory: ':'file: ')+absolute);
  return absolute;
}
function fingerprint(filename){
  const absolute=regular(filename),fd=fs.openSync(absolute,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),digest=createHash('sha256'),buffer=Buffer.allocUnsafe(65536);let bytes=0;
  try{let count;while((count=fs.readSync(fd,buffer,0,buffer.length,null))){digest.update(buffer.subarray(0,count));bytes+=count;}}finally{fs.closeSync(fd);}
  return {bytes,sha256:digest.digest('hex')};
}
function identical(actual,expected,label){if(actual.bytes!==expected.bytes||actual.sha256!==expected.sha256)fail(label+' changed');}
function memberName(value){
  if(typeof value!=='string'||!value||value.startsWith('/')||/[\\\x00-\x1f]/.test(value)||value.split('/').some(part=>!part||part==='.'||part==='..'))fail('Unsafe original report path');
  return value;
}
function writeNew(filename,value){fs.writeFileSync(filename,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function parseArguments(){
  const [command,...argv]=process.argv.slice(2);
  if(command==='--help'||command==='-h'){if(argv.length)fail('Unexpected help arguments');return null;}
  if(!['encode','restore','restore-all'].includes(command))fail(help);
  const allowed=command==='encode'?['manifest','out']:['input','compression','expected-records','expected-last-sha256','out',...(command==='restore'?['record-index','case-id']:[])],options={};
  for(const argument of argv){const match=/^--([a-z0-9-]+)=(.+)$/.exec(argument);if(!match||!allowed.includes(match[1])||Object.hasOwn(options,match[1]))fail('Unknown or duplicate argument: '+argument);options[match[1]]=match[2];}
  for(const name of command==='encode'?['manifest','out']:['input','expected-records','expected-last-sha256','out'])if(!options[name])fail('Required --'+name);
  if(command!=='encode'){
    if(command==='restore'&&Object.hasOwn(options,'record-index')===Object.hasOwn(options,'case-id'))fail('Choose exactly one report selector');
    for(const name of ['record-index','expected-records'])if(options[name]!==undefined&&(!/^(0|[1-9][0-9]*)$/.test(options[name])||!Number.isSafeInteger(Number(options[name]))||(name==='expected-records'&&Number(options[name])===0)))fail('Invalid --'+name);
    if(!/^[a-f0-9]{64}$/.test(options['expected-last-sha256']))fail('Invalid final SHA256');
    if(options['case-id'])memberName(options['case-id']);
    if(options.compression!==undefined&&!['gzip','brotli'].includes(options.compression))fail('Unknown compression');
  }
  return {command,options};
}
function originalRecord(bytes,caseId){
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),prefix=/^\s*/.exec(text)[0],suffix=/\s*$/.exec(text)[0],body=text.slice(prefix.length,text.length-suffix.length),value=JSON.parse(body);
  const indentation=/\n([ \t]+)\S/.exec(body)?.[1],space=indentation??null;
  const serialization={prefix,space,suffix};
  const restored=Buffer.from(prefix+JSON.stringify(value,null,space)+suffix,'utf8');
  if(!restored.equals(bytes))fail('Noncanonical JSON serialization: '+caseId);
  return {caseId,kind:'original-json-file',originalBytes:bytes.length,originalSha256:hash(bytes),serialization,value};
}
function restoreRecord(record){
  if(!record||record.kind!=='original-json-file'||typeof record.caseId!=='string'||!Number.isSafeInteger(record.originalBytes)||record.originalBytes<0||!/^[a-f0-9]{64}$/.test(record.originalSha256))fail('Invalid original report record');
  const serialization=record.serialization;
  if(!serialization||typeof serialization.prefix!=='string'||typeof serialization.suffix!=='string'||!(serialization.space===null||typeof serialization.space==='string')||!Object.hasOwn(record,'value'))fail('Invalid original serialization');
  const bytes=Buffer.from(serialization.prefix+JSON.stringify(record.value,null,serialization.space)+serialization.suffix,'utf8');
  if(bytes.length!==record.originalBytes||hash(bytes)!==record.originalSha256)fail('Restored original report bytes differ');
  return bytes;
}
function identities(){return {producer:{path:self,...fingerprint(self)},codec:{path:codec,...fingerprint(codec)},runtime:{executable:fs.realpathSync(process.execPath),...fingerprint(fs.realpathSync(process.execPath)),bun:process.versions.bun,versions:{...process.versions}}};}
function unchanged(before){for(const name of ['producer','codec'])identical(fingerprint(before[name].path),before[name],name);identical(fingerprint(before.runtime.executable),before.runtime,'runtime');}

function originalBytes(source,compression){
  if(compression==='gzip')return gunzipSync(source);
  if(compression==='none')return source;
  const result=brotliDecompressSync(source,{info:true});
  if(result.engine.bytesWritten!==source.length)fail('Unused compressed Brotli input tail');
  return result.buffer;
}
function encode(options){
  const manifestFile=regular(options.manifest),manifestBytes=fs.readFileSync(manifestFile),manifest=JSON.parse(manifestBytes.toString('utf8')),out=path.resolve(options.out);
  if(manifest.schemaVersion!==1||!Array.isArray(manifest.entries)||!manifest.entries.length)fail('Expected a nonempty schemaVersion1 manifest');
  const seen=new Set(),entries=manifest.entries.map(entry=>{
    const name=memberName(entry.path),folded=name.toLowerCase();if(seen.has(folded))fail('Duplicate original report path: '+name);seen.add(folded);
    if(typeof entry.source!=='string'||!['none','gzip','brotli'].includes(entry.compression))fail('Explicit source/compression required');
    return {source:regular(path.resolve(path.dirname(manifestFile),entry.source)),path:name,compression:entry.compression};
  });
  regular(path.dirname(out),true);fs.mkdirSync(out,{mode:0o700});
  let fd=null;
  const startedAt=new Date().toISOString(),before=identities(),rows=[],encoder=new EvidenceEncoder(),decoder=new EvidenceDecoder();
  try{
    fd=fs.openSync(path.join(out,streamName+'.stage'),'wx',0o600);
    const journal=value=>fs.appendFileSync(path.join(out,'encoding-status.jsonl'),JSON.stringify(value)+'\n',{mode:0o600});
    journal({phase:'encoding',startedAt,records:entries.length});
    let lastSha256=null,totalOriginalBytes=0;
    for(const [recordIndex,entry]of entries.entries()){
      const sourceBytes=fs.readFileSync(entry.source),sourceBefore={bytes:sourceBytes.length,sha256:hash(sourceBytes)},bytes=originalBytes(sourceBytes,entry.compression);
      const record=originalRecord(bytes,entry.path),chunk=encoder.encode(record),decoded=decoder.decode(chunk),restored=restoreRecord(decoded);
      if(!restored.equals(bytes))fail('Independent original-byte comparison failed: '+entry.path);
      fs.writeFileSync(fd,gzipSync(JSON.stringify(chunk)+'\n',{level:9}));
      identical(fingerprint(entry.source),sourceBefore,'Input '+entry.path);
      rows.push({recordIndex,path:entry.path,originalBytes:bytes.length,originalSha256:record.originalSha256,input:{path:entry.source,compression:entry.compression,...sourceBefore},chunkSha256:chunk.sha256});
      lastSha256=chunk.sha256;totalOriginalBytes+=bytes.length;journal({phase:'record-verified',recordIndex,path:entry.path,originalBytes:bytes.length,chunkSha256:chunk.sha256});
    }
    fs.closeSync(fd);fd=null;
    const staged=path.join(out,streamName+'.stage'),streamIdentity=fingerprint(staged),consumerArgs=[codec,'check','--input='+staged,'--expected-records='+rows.length,'--expected-last-sha256='+lastSha256],consumer=spawnSync(process.execPath,consumerArgs,{encoding:'utf8',maxBuffer:1024*1024});
    writeNew(path.join(out,'stream-consumer.json'),{argv:[process.execPath,...consumerArgs],status:consumer.status,signal:consumer.signal,error:consumer.error?String(consumer.error):null,stdout:consumer.stdout,stderr:consumer.stderr});
    if(consumer.error||consumer.signal||consumer.status!==0)fail('Stored complete stream failed independent CLI validation');
    const checked=JSON.parse(consumer.stdout);
    if(checked.records!==rows.length||checked.lastSha256!==lastSha256||checked.status!=='checked')fail('Stored stream consumer bindings differ');
    identical(fingerprint(staged),streamIdentity,'Stored stream');
    for(const row of rows)identical(fingerprint(row.input.path),row.input,'Final input '+row.path);
    identical(fingerprint(manifestFile),{bytes:manifestBytes.length,sha256:hash(manifestBytes)},'Manifest');unchanged(before);
    const index={schemaVersion:1,kind:'original-json-byte-preserving-record-index',format:'compact-evidence-structural-v1',stream:streamName,records:rows.length,lastSha256,totalOriginalBytes,entries:rows};
    writeNew(path.join(out,indexName),index);
    const proof={schemaVersion:1,kind:'shared-original-json-evidence',status:'ready',startedAt,finishedAt:new Date().toISOString(),scope:'Original JSON byte transport only; no omitted fields, observations, failures or changed outcomes. Not application/reviewer acceptance.',codecFormat:'compact-evidence-structural-v1',stream:{path:streamName,...streamIdentity,records:rows.length,lastSha256},originalBytes:totalOriginalBytes,index:{path:indexName,...fingerprint(path.join(out,indexName))},consumer:{path:'stream-consumer.json',...fingerprint(path.join(out,'stream-consumer.json'))},manifest:{path:manifestFile,bytes:manifestBytes.length,sha256:hash(manifestBytes)},identities:before,checks:{everyRecordIndependentDecodedByteComparison:true,storedStreamIndependentCompleteTailCheck:true,allInputsAndProducerUnchanged:true},argv:[...process.argv],execArgv:[...process.execArgv]};
    writeNew(path.join(out,proofName+'.stage'),proof);
    fs.linkSync(staged,path.join(out,streamName));fs.unlinkSync(staged);
    fs.linkSync(path.join(out,proofName+'.stage'),path.join(out,proofName));
    let retainedProofStage=false;
    try{fs.unlinkSync(path.join(out,proofName+'.stage'));}catch{retainedProofStage=true;}
    return {status:'ready',out,records:rows.length,originalBytes:totalOriginalBytes,stream:proof.stream,index:proof.index,retainedProofStage};
  }catch(error){
    if(fd!==null){fs.closeSync(fd);fd=null;}
    writeNew(path.join(out,'encoding-failure.json'),{schemaVersion:1,status:'failed',error:String(error.stack||error),completedRecords:rows.length,readiness:'Not ready. Preserve failed output and use a fresh directory.'});throw error;
  }
}
async function* chunks(filename,compression){
  const input=fs.createReadStream(filename),decoded=compression==='brotli'?Readable.fromWeb(ReadableStream.from(input).pipeThrough(new DecompressionStream('brotli'))):createGunzip(),inputDone=finished(input),decodedDone=finished(decoded);
  inputDone.catch(()=>{});decodedDone.catch(()=>{});
  if(compression==='gzip'){input.on('error',error=>decoded.destroy(error));input.pipe(decoded);}
  const utf8=new TextDecoder('utf-8',{fatal:true});let pending='',count=0;
  try{
    for await(const bytes of decoded){
      pending+=utf8.decode(bytes,{stream:true});let newline;
      while((newline=pending.indexOf('\n'))!==-1){const line=pending.slice(0,newline);pending=pending.slice(newline+1);if(!line.length)fail('Empty evidence frame');count++;yield JSON.parse(line);}
    }
    await inputDone;await decodedDone;pending+=utf8.decode();
    if(pending.length||!count)fail('Missing final LF or empty evidence stream');
  }finally{input.destroy();decoded.destroy();}
}
async function consume(options,fn){
  const decoder=new EvidenceDecoder();let count=0,lastSha256=null;
  for await(const chunk of chunks(options.input,options.compression??'gzip')){fn(decoder,chunk,count++);lastSha256=chunk.sha256;}
  if(count!==Number(options['expected-records'])||lastSha256!==options['expected-last-sha256'])fail('Externally bound complete stream identity differs');
  return {records:count,lastSha256,compression:options.compression??'gzip'};
}
function writeRecordTokens(filename,tokens){
  const fd=fs.openSync(filename,'wx',0o600);let pending='';
  try{for(const token of tokens){pending+=token;if(pending.length>=65536){fs.writeFileSync(fd,pending);pending='';}}if(pending)fs.writeFileSync(fd,pending);}finally{fs.closeSync(fd);}
}
async function restore(options){
  const input=regular(options.input),out=path.resolve(options.out);regular(path.dirname(out),true);
  if(fs.existsSync(out))fail('Refusing to overwrite output');
  const before=identities(),inputBefore=fingerprint(input),temporary=fs.mkdtempSync(path.join(path.dirname(out),'.original-json-extract-')),recordFile=path.join(temporary,'record.json');let found=0;
  try{
    const consumer=await consume({...options,input},(decoder,chunk,index)=>{
      decoder.check(chunk);
      if(options['record-index']!==undefined?index===Number(options['record-index']):decoder.matches(chunk,{caseId:options['case-id'],kind:'original-json-file'})){
        if(++found!==1)fail('Ambiguous original report selector');
        writeRecordTokens(recordFile,decoder.json(chunk));
      }
    });
    if(found!==1)fail('Original report selector did not match');
    const record=JSON.parse(fs.readFileSync(recordFile,'utf8')),bytes=restoreRecord(record);
    identical(fingerprint(input),inputBefore,'Input');unchanged(before);
    writeNew(path.join(temporary,'consumer.json'),consumer);
    const staged=path.join(temporary,'original.json');fs.writeFileSync(staged,bytes,{flag:'wx',mode:0o600});
    identical(fingerprint(staged),{bytes:record.originalBytes,sha256:record.originalSha256},'Staged original report');
    fs.linkSync(staged,out);
    let retainedTemporary=false;
    try{fs.unlinkSync(staged);fs.unlinkSync(recordFile);fs.unlinkSync(path.join(temporary,'consumer.json'));fs.rmdirSync(temporary);}catch{retainedTemporary=true;}
    return {status:'restored',path:out,caseId:record.caseId,bytes:bytes.length,sha256:hash(bytes),completeTailValidated:true,retainedTemporary:retainedTemporary?temporary:null};
  }catch(error){writeNew(path.join(temporary,'restoration-failure.json'),{status:'failed',error:String(error.stack||error),readiness:'No original-report output released.'});throw error;}
}
async function restoreAll(options){
  const input=regular(options.input),out=path.resolve(options.out);regular(path.dirname(out),true);fs.mkdirSync(out,{mode:0o700});
  const staged=path.join(out,'.reports.stage');fs.mkdirSync(staged,{mode:0o700});
  const before=identities(),inputBefore=fingerprint(input),rows=[],seen=new Set();let committed=false;
  try{
    const consumer=await consume({...options,input},(decoder,chunk,recordIndex)=>{
      const record=decoder.decode(chunk),name=memberName(record.caseId),folded=name.toLowerCase();if(seen.has(folded))fail('Duplicate original report identity');seen.add(folded);
      const bytes=restoreRecord(record),filename=path.join(staged,name);fs.mkdirSync(path.dirname(filename),{recursive:true});fs.writeFileSync(filename,bytes,{flag:'wx',mode:0o600});
      rows.push({recordIndex,path:name,bytes:bytes.length,sha256:record.originalSha256});
    });
    for(const row of rows)identical(fingerprint(path.join(staged,row.path)),row,'Restored '+row.path);
    identical(fingerprint(input),inputBefore,'Input');unchanged(before);
    const proof={schemaVersion:1,kind:'complete-original-json-restoration',status:'ready',input:{path:input,...inputBefore},consumer,identities:before,reports:rows,completeTailValidated:true,everyOriginalReportByteCountAndHashVerified:true,scope:'Original report byte restoration, not application or reviewer acceptance.'};
    writeNew(path.join(out,'restoration-proof.json.stage'),proof);
    fs.renameSync(staged,path.join(out,'reports'));
    fs.linkSync(path.join(out,'restoration-proof.json.stage'),path.join(out,'restoration-proof.json'));committed=true;
    let retainedProofStage=false;try{fs.unlinkSync(path.join(out,'restoration-proof.json.stage'));}catch{retainedProofStage=true;}
    return {status:'ready',out,reports:rows.length,originalBytes:rows.reduce((n,row)=>n+row.bytes,0),completeTailValidated:true,retainedProofStage};
  }catch(error){if(!committed)writeNew(path.join(out,'restoration-failure.json'),{status:'failed',error:String(error.stack||error),reportsStaged:rows.length,readiness:'Not ready without restoration-proof.json.'});throw error;}
}
try{
  if(!process.versions.bun)fail('Use the provisioned Bun runtime');
  const args=parseArguments();
  if(args===null)process.stdout.write(help);
  else process.stdout.write(JSON.stringify(args.command==='encode'?encode(args.options):args.command==='restore'?await restore(args.options):await restoreAll(args.options),null,2)+'\n');
}catch(error){process.stderr.write(String(error.stack||error)+'\n');process.exitCode=1;}
