#!/usr/bin/env bun
// Byte transport only. No parsing or semantic validation of the decompressed input.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {Transform,Writable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {constants as zlibConstants,createGunzip,createBrotliCompress,createBrotliDecompress} from 'node:zlib';
import {fileURLToPath} from 'node:url';

const SELF=fileURLToPath(import.meta.url);
const CARRIER='evidence.jsonl.br',PROOF='encoding-proof.json',JOURNAL='encoding-status.jsonl',FAILURE='encoding-failure.json';
const CARRIER_STAGE=CARRIER+'.stage',PROOF_STAGE=PROOF+'.stage';
const QUALITY=9,WINDOW_BITS=24;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=message=>{throw new Error('Compact evidence carrier: '+message);};
const help=`Usage:
  bun tools/verification/compact-evidence-carrier.mjs --input=ORIGINAL.jsonl.gz --out=FRESH_DIRECTORY
  bun tools/verification/compact-evidence-carrier.mjs --help

Convert a regular, symlink-free gzip input into standard Brotli, quality 9,
window 24. Stream every decompressed byte without parsing JSON, filtering,
rewriting, sampling or changing any field. Gzip CRC/trailers and all concatenated
members are checked. Independently decode the original gzip and staged Brotli,
directly compare every byte across chunk boundaries, and exhaust both tails.

The output parent must already exist and be symlink-free. The output directory
must not exist, even if empty. It is created privately; existing files are never
overwritten. The original input and producer source are opened read-only, hashed
before/after, and required to remain unchanged. Runtime executable identity,
versions, arguments and all three compressed/wire/carrier identities are bound.

Successful output:
  ${CARRIER}       Standard Brotli containing every original gunzip byte.
  ${PROOF}     Final success receipt, promoted last after all checks.
  ${JOURNAL}   Append-only phase journal, not a success receipt.
Only the final ${PROOF} with status "ready" establishes carrier readiness;
this is exact-wire transport proof, not graph/protocol/application acceptance.

During work, ${CARRIER_STAGE} and ${PROOF_STAGE} are private staging names.
On failure, retain stages and ${FAILURE} (status "failed") for diagnosis;
never retry into the same directory. If final receipt promotion fails, a carrier
may already have its final name but is NOT ready without the final receipt.
A harmless proof-stage hard link may remain if post-commit cleanup is refused.

Standard decoding (no packages required):
  brotli --decompress --stdout ${CARRIER} > restored.jsonl
  Or pipe fs.createReadStream('${CARRIER}') through
  node:zlib.createBrotliDecompress() into a fresh output stream.
This tool does not parse graph frames. Complete-tail graph validation is a
separate consumer check. No network access or external commands are used.
`;

function argumentsFor(argv){
  if(argv.length===1&&(argv[0]==='--help'||argv[0]==='-h'))return null;
  const result={};
  for(const argument of argv){
    const match=/^--(input|out)=(.+)$/.exec(argument);
    if(!match||Object.hasOwn(result,match[1]))fail('Expected unique --input=PATH and --out=FRESH_DIRECTORY; see --help');
    result[match[1]]=path.resolve(match[2]);
  }
  if(!result.input||!result.out)fail('Both --input=PATH and --out=FRESH_DIRECTORY are required; see --help');
  return result;
}

// Check every component, not just the leaf; open additionally uses O_NOFOLLOW.
function regularPath(filename,directory=false){
  const absolute=path.resolve(filename),root=path.parse(absolute).root;
  const components=absolute.slice(root.length).split(path.sep).filter(Boolean);
  let current=root;
  const rootStat=fs.lstatSync(root,{bigint:true});
  if(rootStat.isSymbolicLink()||!rootStat.isDirectory())fail('Unsafe root: '+root);
  let stat=rootStat;
  for(let index=0;index<components.length;index++){
    current=path.join(current,components[index]);
    stat=fs.lstatSync(current,{bigint:true});
    const needDirectory=index<components.length-1||directory;
    if(stat.isSymbolicLink()||(needDirectory?!stat.isDirectory():!stat.isFile()))fail('Expected symlink-free '+(needDirectory?'directory: ':'regular file: ')+current);
  }
  if(!directory&&!stat.isFile())fail('Expected regular file: '+absolute);
  return stat;
}
function statIdentity(stat){
  if(stat.size>BigInt(Number.MAX_SAFE_INTEGER))fail('File size exceeds exact byte-count range');
  return {
    device:String(stat.dev),inode:String(stat.ino),mode:String(stat.mode),links:String(stat.nlink),
    uid:String(stat.uid),gid:String(stat.gid),bytes:Number(stat.size),
    mtimeNs:String(stat.mtimeNs??stat.mtimeMs*1000000n),
    ctimeNs:String(stat.ctimeNs??stat.ctimeMs*1000000n)
  };
}
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
function requireIdentity(actual,expected,label){
  if(actual.bytes!==expected.bytes||actual.sha256!==expected.sha256)fail(label+' byte/SHA256 identity changed');
}
function meter(){
  const digest=createHash('sha256');
  let bytes=0,result;
  const stream=new Transform({transform(chunk,encoding,callback){
    try{
      if(!Buffer.isBuffer(chunk))fail('Expected binary stream chunks');
      bytes+=chunk.length;
      if(!Number.isSafeInteger(bytes))fail('Stream exceeds exact byte-count range');
      digest.update(chunk);callback(null,chunk);
    }catch(error){callback(error);}
  }});
  return {stream,get bytes(){return bytes;},identity(){
    if(!stream.writableFinished)fail('Cannot finalize an incomplete byte stream');
    return result??=( {bytes,sha256:digest.digest('hex')} );
  }};
}
function pin(filename,pins){
  regularPath(filename);
  if(typeof fs.constants.O_NOFOLLOW!=='number')fail('This runtime lacks required O_NOFOLLOW support');
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|(fs.constants.O_NONBLOCK??0));
  try{
    const stat=fs.fstatSync(fd,{bigint:true});
    if(!stat.isFile())fail('Expected regular file: '+filename);
    const pinned={path:filename,fd,stat:statIdentity(stat)};
    assertPinned(pinned);
    pins.add(pinned);
    return pinned;
  }catch(error){fs.closeSync(fd);throw error;}
}
function assertPinned(pinned){
  const pathname=statIdentity(regularPath(pinned.path));
  const descriptor=statIdentity(fs.fstatSync(pinned.fd,{bigint:true}));
  if(!same(pathname,pinned.stat)||!same(descriptor,pinned.stat))fail('File path or metadata changed: '+pinned.path);
}
function readPinned(pinned){
  assertPinned(pinned);
  return fs.createReadStream(pinned.path,{fd:pinned.fd,autoClose:false,start:0,highWaterMark:64*1024});
}
async function fingerprint(pinned){
  const measured=meter();
  await pipeline(readPinned(pinned),measured.stream,new Writable({write(chunk,encoding,callback){callback();}}));
  assertPinned(pinned);
  const identity=measured.identity();
  if(identity.bytes!==pinned.stat.bytes)fail('Incomplete file read: '+pinned.path);
  return {...identity,stat:pinned.stat};
}
function closePins(pins){
  const errors=[];
  for(const pinned of pins){
    try{fs.closeSync(pinned.fd);}catch(error){errors.push(error);}
    pins.delete(pinned);
  }
  if(errors.length)throw new AggregateError(errors,'Could not close pinned file descriptors');
}
function writeExclusive(filename,bytes){
  const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function gunzip(){
  // Default strict finish, explicitly retained: never accept a truncated trailer.
  return createGunzip({finishFlush:zlibConstants.Z_FINISH});
}

async function compareDecoded(original,carrier){
  const originalCompressed=meter(),carrierCompressed=meter(),originalWire=meter(),carrierWire=meter();
  const streams=[originalCompressed.stream,carrierCompressed.stream,originalWire.stream,carrierWire.stream],jobs=[];
  const track=stream=>{streams.push(stream);return stream;};
  let complete=false,comparedBytes=0;
  try{
    const left=[track(readPinned(original)),originalCompressed.stream,track(gunzip()),originalWire.stream];
    const right=[track(readPinned(carrier)),carrierCompressed.stream,track(createBrotliDecompress()),carrierWire.stream];
    for(const parts of [left,right]){
      const job=pipeline(...parts);
      // A decoder may fail while the other iterator is awaited. Handle now,
      // then await both jobs below so no rejection or tail error is discarded.
      job.catch(()=>{});jobs.push(job);
    }
    const iterators=[originalWire.stream[Symbol.asyncIterator](),carrierWire.stream[Symbol.asyncIterator]()];
    const chunks=[null,null],offsets=[0,0],done=[false,false];
    while(true){
      await Promise.all(iterators.map(async(iterator,index)=>{
        if(chunks[index]!==null||done[index])return;
        const next=await iterator.next();
        done[index]=next.done;
        if(!next.done){chunks[index]=next.value;offsets[index]=0;}
      }));
      if(done[0]&&done[1])break;
      if(done[0]||done[1])fail('Decoded lengths differ at byte '+comparedBytes);
      const length=Math.min(chunks[0].length-offsets[0],chunks[1].length-offsets[1]);
      if(!chunks[0].subarray(offsets[0],offsets[0]+length).equals(chunks[1].subarray(offsets[1],offsets[1]+length))){
        let index=0;
        while(index<length&&chunks[0][offsets[0]+index]===chunks[1][offsets[1]+index])index++;
        fail('Direct decoded-byte mismatch at byte '+(comparedBytes+index));
      }
      comparedBytes+=length;
      if(!Number.isSafeInteger(comparedBytes))fail('Comparison exceeds exact byte-count range');
      for(let index=0;index<2;index++){
        offsets[index]+=length;
        if(offsets[index]===chunks[index].length)chunks[index]=null;
      }
    }
    await Promise.all(jobs);
    assertPinned(original);assertPinned(carrier);
    complete=true;
    return {
      method:'direct every-byte Buffer comparison across independent decoder chunk boundaries',
      comparedBytes,originalTailExhausted:true,carrierTailExhausted:true,
      originalCompressed:originalCompressed.identity(),carrierCompressed:carrierCompressed.identity(),
      originalWire:originalWire.identity(),carrierWire:carrierWire.identity()
    };
  }finally{
    if(!complete)for(const stream of streams)stream.destroy();
    await Promise.allSettled(jobs);
  }
}

async function encode(args){
  const startedAt=new Date().toISOString(),pins=new Set(),observed={};
  let owned=null,statusFd=null,phase='preflight',committed=false;
  const filename=name=>path.join(args.out,name);
  const assertOwned=()=>{
    const current=regularPath(args.out,true);
    if(!owned||String(current.dev)!==owned.device||String(current.ino)!==owned.inode||String(current.uid)!==owned.uid)fail('Output directory ownership changed');
  };
  const journal=(status,details={})=>{
    assertOwned();
    fs.writeFileSync(statusFd,JSON.stringify({at:new Date().toISOString(),status,phase,...details})+'\n');
    fs.fsyncSync(statusFd);
  };
  const advance=next=>{phase=next;journal('staging');};
  const promote=(stage,final,expected,receipt=false)=>{
    assertOwned();
    if(!same(statIdentity(regularPath(filename(stage))),expected))fail('Staged output changed before promotion: '+stage);
    // link is exclusive, unlike rename, and cannot overwrite a pre-existing leaf.
    fs.linkSync(filename(stage),filename(final));
    if(receipt){committed=true;return;}
    const linked=statIdentity(regularPath(filename(final)));
    if(linked.device!==expected.device||linked.inode!==expected.inode||linked.bytes!==expected.bytes)fail('Promoted file is not the checked stage: '+final);
  };
  try{
    const original=pin(args.input,pins),producer=pin(SELF,pins);
    const executable=fs.realpathSync(process.execPath),runtime=pin(executable,pins);
    regularPath(path.dirname(args.out),true);
    fs.mkdirSync(args.out,{mode:0o700}); // Not recursive; EEXIST also rejects empty directories.
    const directory=regularPath(args.out,true);
    owned={device:String(directory.dev),inode:String(directory.ino),uid:String(directory.uid)};
    statusFd=fs.openSync(filename(JOURNAL),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    advance('capturing-before-identities');
    observed.originalBefore=await fingerprint(original);
    observed.producerBefore=await fingerprint(producer);
    observed.runtimeBefore=await fingerprint(runtime);

    advance('encoding');
    const compressed=meter(),wire=meter(),encoded=meter();
    await pipeline(
      readPinned(original),compressed.stream,gunzip(),wire.stream,
      createBrotliCompress({params:{
        [zlibConstants.BROTLI_PARAM_QUALITY]:QUALITY,
        [zlibConstants.BROTLI_PARAM_LGWIN]:WINDOW_BITS
      }}),encoded.stream,
      fs.createWriteStream(filename(CARRIER_STAGE),{flags:'wx',mode:0o600})
    );
    assertPinned(original);
    observed.encoding={originalCompressed:compressed.identity(),wire:wire.identity(),carrier:encoded.identity()};
    requireIdentity(observed.encoding.originalCompressed,observed.originalBefore,'Encoding original gzip');
    const staged=pin(filename(CARRIER_STAGE),pins);
    observed.carrierBefore=await fingerprint(staged);
    requireIdentity(observed.carrierBefore,observed.encoding.carrier,'Staged Brotli');

    advance('independent-direct-roundtrip');
    observed.comparison=await compareDecoded(original,staged);
    requireIdentity(observed.comparison.originalCompressed,observed.originalBefore,'Comparison original gzip');
    requireIdentity(observed.comparison.carrierCompressed,observed.carrierBefore,'Comparison Brotli');
    requireIdentity(observed.comparison.originalWire,observed.encoding.wire,'Independent original gunzip');
    requireIdentity(observed.comparison.carrierWire,observed.encoding.wire,'Independent Brotli decode');
    if(observed.comparison.comparedBytes!==observed.encoding.wire.bytes)fail('Direct comparison did not cover every wire byte');

    advance('capturing-after-identities');
    observed.carrierAfter=await fingerprint(staged);
    observed.originalAfter=await fingerprint(original);
    observed.producerAfter=await fingerprint(producer);
    observed.runtimeAfter=await fingerprint(runtime);
    for(const key of ['carrier','original','producer','runtime'])requireIdentity(observed[key+'After'],observed[key+'Before'],'Stable '+key);
    assertOwned();
    const carrierStat=staged.stat;
    closePins(pins);

    const proof={
      schemaVersion:1,kind:'compact-evidence-exact-wire-carrier',status:'ready',
      scope:'Exact-wire byte transport only; no graph, protocol, application or reviewer acceptance.',
      semanticTransformation:'None. No JSON parsing, field rewriting, filtering, record/cursor sampling or loss.',
      originalGzip:{path:args.input,before:observed.originalBefore,after:observed.originalAfter,stable:true},
      wire:{...observed.encoding.wire,meaning:'Every original decompressed byte, in original order, including the complete tail.'},
      carrier:{path:CARRIER,compression:'standard brotli',quality:QUALITY,windowBits:WINDOW_BITS,
        bytes:observed.carrierAfter.bytes,sha256:observed.carrierAfter.sha256,
        before:observed.carrierBefore,after:observed.carrierAfter,stable:true},
      encoding:observed.encoding,comparison:observed.comparison,
      producer:{path:SELF,before:observed.producerBefore,after:observed.producerAfter,stable:true},
      runtime:{executable,requestedExecutable:process.execPath,before:observed.runtimeBefore,after:observed.runtimeAfter,stable:true,
        version:process.version,versions:{...process.versions},release:{...process.release},platform:process.platform,arch:process.arch},
      execution:{argv:[...process.argv],execArgv:[...process.execArgv],cwd:process.cwd(),startedAt,verifiedAt:new Date().toISOString()},
      release:{successReceipt:PROOF,failedStatus:FAILURE,journal:JOURNAL,
        rule:'Only the final success receipt establishes readiness; a .stage receipt or a carrier alone does not.'}
    };
    advance('staging-verified-proof');
    const proofBytes=Buffer.from(JSON.stringify(proof,null,2)+'\n');
    const proofSha256=hash(proofBytes);
    writeExclusive(filename(PROOF_STAGE),proofBytes);
    const proofStat=statIdentity(regularPath(filename(PROOF_STAGE)));
    phase='promoting';journal('verified',{readiness:'Not ready until final '+PROOF+' is exclusively linked.'});
    fs.closeSync(statusFd);statusFd=null;
    promote(CARRIER_STAGE,CARRIER,carrierStat);
    fs.unlinkSync(filename(CARRIER_STAGE));
    promote(PROOF_STAGE,PROOF,proofStat,true);
    // The receipt link is the commit point. All required checks and fallible
    // stream/descriptor work precede it; cleanup cannot invalidate byte proof.
    let retainedProofStage=false;
    try{fs.unlinkSync(filename(PROOF_STAGE));}catch{retainedProofStage=true;}
    return {status:'ready',out:args.out,carrier:{path:filename(CARRIER),bytes:proof.carrier.bytes,sha256:proof.carrier.sha256},
      wire:proof.wire,proof:{path:filename(PROOF),bytes:proofBytes.length,sha256:proofSha256},retainedProofStage};
  }catch(error){
    const reportingErrors=[];
    try{closePins(pins);}catch(closeError){reportingErrors.push(String(closeError));}
    if(owned&&!committed){
      const failure={schemaVersion:1,kind:'compact-evidence-exact-wire-carrier',status:'failed',phase,
        input:args.input,out:args.out,startedAt,failedAt:new Date().toISOString(),
        error:{name:error?.name,message:String(error?.message??error),code:error?.code,stack:error?.stack},
        observed,readiness:'Not ready. Preserve all staged/final artifacts; use a new output directory for another attempt.'};
      try{
        assertOwned();
        writeExclusive(filename(FAILURE),Buffer.from(JSON.stringify(failure,null,2)+'\n'));
      }catch(reportError){reportingErrors.push('Could not create exclusive failure status: '+String(reportError));}
      if(statusFd!==null)try{journal('failed',{error:String(error?.message??error)});}catch(reportError){reportingErrors.push('Could not append failure journal: '+String(reportError));}
    }
    if(reportingErrors.length)throw new AggregateError([error,...reportingErrors],String(error?.message??error)+'; '+reportingErrors.join('; '));
    throw error;
  }finally{
    if(statusFd!==null)fs.closeSync(statusFd);
  }
}

try{
  const args=argumentsFor(process.argv.slice(2));
  if(args===null)process.stdout.write(help);
  else process.stdout.write(JSON.stringify(await encode(args),null,2)+'\n');
}catch(error){
  process.stderr.write(String(error?.stack??error)+'\n');
  process.exitCode=1;
}
