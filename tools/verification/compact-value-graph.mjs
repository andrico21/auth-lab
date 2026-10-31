import {createHash} from 'node:crypto';
import {createReadStream,createWriteStream} from 'node:fs';
import {once} from 'node:events';
import {finished} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {createGunzip} from 'node:zlib';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

export const FORMAT='compact-typed-value-graph-v1';
export const SCHEMA=1;
export const ROOT_DIGEST_ALGORITHM='compact-typed-value-merkle-sha256-v1';
// Definitions are bounded to 4096 nodes and grouped toward 1 MiB of JSON.
// An indivisible scalar/container definition can occupy a frame of its own.
const MAX_FRAME_NODES=4096,TARGET_FRAME_CHARS=1024*1024;
const NODE_FIELDS=['format','schema','kind','frameIndex','offset','nodes','previous','sha256'];
const RECORD_FIELDS=['format','schema','kind','frameIndex','recordIndex','root','rootDigest','previous','sha256'];
const hash=value=>createHash('sha256').update(value).digest('hex');
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const fail=message=>{throw new TypeError('Compact value graph: '+message);};
class ValueMismatch extends TypeError {
  constructor(message){super('Compact value graph expected-value mismatch: '+message);}
}
const mismatch=message=>{throw new ValueMismatch(message);};
function fields(value,names){
  if(value===null||typeof value!=='object'||Array.isArray(value))return false;
  const prototype=Object.getPrototypeOf(value);
  if(prototype!==Object.prototype&&prototype!==null)return false;
  if(Reflect.ownKeys(value).length!==names.length)return false;
  return names.every(key=>{
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    return descriptor&&Object.hasOwn(descriptor,'value')&&descriptor.enumerable;
  });
}
function dense(value){
  if(!Array.isArray(value)||Reflect.ownKeys(value).length!==value.length+1)fail('invalid dense array');
  for(let i=0;i<value.length;i++){
    const descriptor=Object.getOwnPropertyDescriptor(value,String(i));
    if(!descriptor||!Object.hasOwn(descriptor,'value')||!descriptor.enumerable)fail('invalid array entry');
  }
  return value;
}
function hex(value){return typeof value==='string'&&value.length%2===0&&/^[a-f0-9]*$/.test(value);}
function numberText(value){return Object.is(value,-0)?'-0':String(value);}
function validNumber(value){
  return typeof value==='string'&&(['NaN','Infinity','-Infinity','-0'].includes(value)||Number.isFinite(Number(value))&&String(Number(value))===value);
}
// Only ordinary, fully frozen, data-only containers can retain an identity
// proof. Ignored extra/symbol/nonenumerable properties conservatively disable
// memoization, but do not change compactStable's enumerable-data semantics.
function immutableContainer(value,array,keys){
  const prototype=Object.getPrototypeOf(value);
  if(array?prototype!==Array.prototype:prototype!==Object.prototype&&prototype!==null)return false;
  if(Object.isExtensible(value))return false;
  const own=Reflect.ownKeys(value);
  if(!array&&own.length!==keys.length)return false;
  for(const key of own){
    if(typeof key!=='string')return false;
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    if(!descriptor||!Object.hasOwn(descriptor,'value')||descriptor.writable||descriptor.configurable)return false;
    if(array&&key==='length')continue;
    if(!descriptor.enumerable)return false;
    if(array){const index=Number(key);if(!integer(index)||String(index)!==key||index>=value.length)return false;}
  }
  return true;
}
// Proof retention is only a speed cache, never a coverage or value-size bound.
// A transaction keeps its own bounded overlay; failure discards it without
// retaining one rollback entry for every object in a very large source tree.
const MAX_IMMUTABLE_PROOFS=65536,MAX_CAPTURE_ROOT_PROOFS=32;
class ProofCache {
  #values=new Map();#ring=[];#next=0;#limit;
  constructor(limit=MAX_IMMUTABLE_PROOFS){this.#limit=limit;}
  get(value){return this.#values.get(value);}
  set(value,id){
    if(this.#values.has(value)){this.#values.set(value,id);return;}
    if(this.#values.size===this.#limit)this.#values.delete(this.#ring[this.#next]);
    this.#ring[this.#next]=value;this.#next=(this.#next+1)%this.#limit;
    this.#values.set(value,id);
  }
  merge(other){for(const [value,id]of other.#values)this.set(value,id);}
}

// u undefined, h array hole, z null, n number text, i bigint text,
// s string, b boolean, t typed constructor+hex, v buffer hex, d ISO date,
// a array refs, o sorted [key,ref] entries, m ordered [keyRef,valueRef],
// e ordered set refs. Prototype distinctions follow compactEncode, not JSON.
function nodeDigest(node,digests){
  const [type,value]=node;
  let content=node;
  if(type==='a'||type==='e')content=[type,value.map(id=>digests[id])];
  else if(type==='o')content=[type,value.map(([key,id])=>[key,digests[id]])];
  else if(type==='m')content=[type,value.map(([key,id])=>[digests[key],digests[id]])];
  return hash(ROOT_DIGEST_ALGORITHM+'\0'+JSON.stringify(content));
}
function copyNode(node){
  const [type,value]=node;
  if(type==='a'||type==='e')return [type,[...value]];
  if(type==='o'||type==='m')return [type,value.map(entry=>[...entry])];
  return [...node];
}
class GraphStore {
  nodes=[];digests=[];signatures=[];pool=new Map();immutable=new ProofCache();
  #portableDigests;
  constructor(portableDigests=true){this.#portableDigests=portableDigests;}
  // Independently proven capture roots survive unrelated descendant scans.
  captureRoots=new ProofCache(MAX_CAPTURE_ROOT_PROOFS);
  checkpoint(){return {offset:this.nodes.length,proofs:new ProofCache(),roots:new ProofCache(MAX_CAPTURE_ROOT_PROOFS)};}
  rollback(transaction){
    for(let id=transaction.offset;id<this.signatures.length;id++)this.pool.delete(this.signatures[id]);
    this.nodes.length=transaction.offset;if(this.#portableDigests)this.digests.length=transaction.offset;this.signatures.length=transaction.offset;
  }
  commit(transaction){this.immutable.merge(transaction.proofs);this.captureRoots.merge(transaction.roots);}
  intern(node){
    const signature=JSON.stringify(node),existing=this.pool.get(signature);
    if(existing!==undefined)return existing;
    const id=this.nodes.length;
    this.pool.set(signature,id);this.nodes.push(node);this.signatures.push(signature);
    if(this.#portableDigests)this.digests.push(nodeDigest(node,this.digests));return id;
  }
  capture(value,transaction){
    const result=[],active=new Set(),stack=[{value,target:result,key:0}];
    while(stack.length){
      const task=stack[stack.length-1];let id,immutable=true;
      if(task.info){
        const info=task.info;
        if(info.next<info.count){
          const i=info.next++;let child,target,key,hole=false;
          if(info.type==='a'){
            hole=!Object.hasOwn(task.value,i);child=hole?undefined:task.value[i];target=info.entries;key=i;
          }else if(info.type==='o'){
            const name=info.keys[i],entry=[name];info.entries[i]=entry;
            child=task.value[name];target=entry;key=1;
          }else if(info.type==='m'){
            const pair=Math.floor(i/2),position=i%2;
            if(position===0)info.entries[pair]=[];
            child=info.values[pair][position];target=info.entries[pair];key=position;
          }else {child=info.values[i];target=info.entries;key=i;}
          stack.push({value:child,target,key,hole});continue;
        }
        active.delete(task.value);id=this.intern([info.type,info.entries]);immutable=info.immutable;
        if(immutable)transaction.proofs.set(task.value,id);
      }else {
        const raw=task.value,type=typeof raw;
        if(task.hole)id=this.intern(['h']);
        else if(raw===undefined)id=this.intern(['u']);
        else if(raw===null)id=this.intern(['z']);
        else if(type==='number')id=this.intern(['n',numberText(raw)]);
        else if(type==='bigint')id=this.intern(['i',String(raw)]);
        else if(type==='string'||type==='boolean')id=this.intern([type==='string'?'s':'b',raw]);
        else {
          if(type!=='object')fail('unsupported raw '+type);
          const memo=transaction.proofs.get(raw)??transaction.roots.get(raw)??this.captureRoots.get(raw)??this.immutable.get(raw);
          if(memo!==undefined){id=memo;transaction.proofs.set(raw,id);}
          else {
            if(active.has(raw))fail('cyclic raw value');
            if(ArrayBuffer.isView(raw)){
              const name=raw.constructor.name;if(typeof name!=='string')fail('unsupported typed constructor name');
              id=this.intern(['t',name,Buffer.from(raw.buffer,raw.byteOffset,raw.byteLength).toString('hex')]);immutable=false;
            }else if(raw instanceof ArrayBuffer){id=this.intern(['v',Buffer.from(raw).toString('hex')]);immutable=false;}
            else if(raw instanceof Date){id=this.intern(['d',raw.toISOString()]);immutable=false;}
            else {
              let info;
              if(Array.isArray(raw))info={type:'a',count:raw.length,immutable:immutableContainer(raw,true)};
              else if(raw instanceof Map){const values=[...raw];info={type:'m',values,count:values.length*2,immutable:false};}
              else if(raw instanceof Set){const values=[...raw];info={type:'e',values,count:values.length,immutable:false};}
              else {const keys=Object.keys(raw).sort();info={type:'o',keys,count:keys.length,immutable:immutableContainer(raw,false,keys)};}
              info.next=0;info.entries=[];task.info=info;active.add(raw);continue;
            }
          }
        }
      }
      stack.pop();task.target[task.key]=id;
      if(!stack.length&&immutable&&task.value!==null&&typeof task.value==='object')transaction.roots.set(task.value,id);
      if(!immutable&&stack.length)stack[stack.length-1].info.immutable=false;
    }
    return {root:result[0],digest:this.digests[result[0]]};
  }
}
const GRAPHS=new WeakMap();
export class ValueGraph {
  constructor(){GRAPHS.set(this,new GraphStore());}
  capture(value){
    const store=GRAPHS.get(this),transaction=store.checkpoint();
    try{const result=store.capture(value,transaction);store.commit(transaction);return result;}
    catch(error){store.rollback(transaction);throw error;}
  }
}
export function compareCompactValues(actual,expected){
  // A shared exact interning domain is the equality oracle, not a digest.
  // Its weak immutable proofs safely reuse shared frozen descendants; both
  // mutable graphs are fully read, including when their identities coincide.
  const store=new GraphStore(false),transaction=store.checkpoint();
  try{
    const actualRoot=store.capture(actual,transaction).root;
    const expectedRoot=store.capture(expected,transaction).root;
    store.commit(transaction);return actualRoot===expectedRoot;
  }catch(error){store.rollback(transaction);throw error;}
}
function validatedNode(input,nodes){
  dense(input);const [type,value]=input;
  if(type==='u'||type==='h'||type==='z'){
    if(input.length!==1)fail('invalid scalar arity');return [type];
  }
  if(type==='t'){
    if(input.length!==3||typeof value!=='string'||!hex(input[2]))fail('invalid typed bytes');return [...input];
  }
  if(input.length!==2)fail('invalid node arity');
  if(type==='s'){if(typeof value!=='string')fail('invalid string');return [type,value];}
  if(type==='b'){if(typeof value!=='boolean')fail('invalid boolean');return [type,value];}
  if(type==='n'){if(!validNumber(value))fail('invalid number');return [type,value];}
  if(type==='i'){
    if(typeof value!=='string'||! /^-?(0|[1-9][0-9]*)$/.test(value)||value==='-0')fail('invalid bigint');return [type,value];
  }
  if(type==='v'){if(!hex(value))fail('invalid buffer');return [type,value];}
  if(type==='d'){
    if(typeof value!=='string')fail('invalid date');
    try{if(new Date(value).toISOString()!==value)fail('noncanonical date');}catch{fail('invalid date');}
    return [type,value];
  }
  if(!['a','o','m','e'].includes(type))fail('unknown node type');
  dense(value);
  const ref=(id,hole=false)=>{
    if(!integer(id)||id>=nodes.length||!hole&&nodes[id][0]==='h')fail('invalid or forward node reference');
    return id;
  };
  if(type==='a'||type==='e')return [type,value.map(id=>ref(id,type==='a'))];
  let previous;
  return [type,value.map((entry,index)=>{
    dense(entry);if(entry.length!==2)fail('invalid entry arity');
    if(type==='m')return [ref(entry[0]),ref(entry[1])];
    const [key,id]=entry;
    if(typeof key!=='string'||index&&previous>=key)fail('unsorted or duplicate object key');
    previous=key;return [key,ref(id)];
  })];
}
function framePayload(frame){
  const {format,schema,kind,frameIndex,previous}=frame;
  return kind==='nodes'?{format,schema,kind,frameIndex,offset:frame.offset,nodes:frame.nodes,previous}:
    {format,schema,kind,frameIndex,recordIndex:frame.recordIndex,root:frame.root,rootDigest:frame.rootDigest,previous};
}
function signedFrame(payload){return {...payload,sha256:hash(JSON.stringify(payload))};}
// This is a second, independent raw walker. It does not invoke GraphStore,
// content interning, tagged encoding or a digest as the expected-value oracle.
function assertRaw(state,root,expected){
  const stack=[{id:root,raw:expected}],active=new Set(),pending=new ProofCache();
  while(stack.length){
    const task=stack[stack.length-1],node=state.nodes[task.id];let immutable=true;
    if(task.info){
      const info=task.info;
      if(info.next<info.count){
        const i=info.next++;let raw,id,hole=false;
        if(info.type==='a'){hole=!Object.hasOwn(task.raw,i);raw=hole?undefined:task.raw[i];id=node[1][i];}
        else if(info.type==='o'){raw=task.raw[info.keys[i]];id=node[1][i][1];}
        else if(info.type==='m'){const pair=Math.floor(i/2),position=i%2;raw=info.values[pair][position];id=node[1][pair][position];}
        else {raw=info.values[i];id=node[1][i];}
        stack.push({id,raw,hole});continue;
      }
      active.delete(task.raw);immutable=info.immutable;
      if(immutable)pending.set(task.raw,task.id);
    }else {
      const raw=task.raw,type=typeof raw,tag=node[0],data=node[1];
      if(task.hole){if(tag!=='h')mismatch('array hole');}
      else if(raw===undefined){if(tag!=='u')mismatch('undefined');}
      else if(raw===null){if(tag!=='z')mismatch('null');}
      else if(type==='number'){if(tag!=='n'||data!==numberText(raw))mismatch('number');}
      else if(type==='bigint'){if(tag!=='i'||data!==String(raw))mismatch('bigint');}
      else if(type==='string'||type==='boolean'){if(tag!==(type==='string'?'s':'b')||data!==raw)mismatch(type);}
      else {
        if(type!=='object')fail('unsupported expected '+type);
        const proof=pending.get(raw)??state.proofs.get(raw);
        if(proof===task.id)pending.set(raw,task.id);
        else {
          if(active.has(raw))fail('cyclic expected value');
          if(ArrayBuffer.isView(raw)){
            if(tag!=='t'||data!==raw.constructor.name||node[2]!==Buffer.from(raw.buffer,raw.byteOffset,raw.byteLength).toString('hex'))mismatch('typed class/bytes');
            immutable=false;
          }else if(raw instanceof ArrayBuffer){if(tag!=='v'||data!==Buffer.from(raw).toString('hex'))mismatch('buffer bytes');immutable=false;}
          else if(raw instanceof Date){if(tag!=='d'||data!==raw.toISOString())mismatch('date');immutable=false;}
          else {
            let info;
            if(Array.isArray(raw)){
              if(tag!=='a'||data.length!==raw.length)mismatch('array type/length');
              info={type:'a',count:raw.length,immutable:immutableContainer(raw,true)};
            }else if(raw instanceof Map){
              if(tag!=='m')mismatch('map type');const values=[...raw];if(data.length!==values.length)mismatch('map length');
              info={type:'m',values,count:values.length*2,immutable:false};
            }else if(raw instanceof Set){
              if(tag!=='e')mismatch('set type');const values=[...raw];if(data.length!==values.length)mismatch('set length');
              info={type:'e',values,count:values.length,immutable:false};
            }else {
              if(tag!=='o')mismatch('object type');const keys=Object.keys(raw).sort();
              if(data.length!==keys.length||keys.some((key,i)=>key!==data[i][0]))mismatch('object keys');
              info={type:'o',keys,count:keys.length,immutable:immutableContainer(raw,false,keys)};
            }
            info.next=0;task.info=info;active.add(raw);continue;
          }
        }
      }
    }
    stack.pop();if(!immutable&&stack.length)stack[stack.length-1].info.immutable=false;
  }
  state.proofs.merge(pending);
}
class DecoderState {
  nodes=[];digests=[];proofs=new ProofCache();frameIndex=0;recordIndex=0;previous=null;records=[];
  checkpoint(){return {nodes:this.nodes.length,frameIndex:this.frameIndex,recordIndex:this.recordIndex,previous:this.previous};}
  rollback(checkpoint){
    this.nodes.length=checkpoint.nodes;this.digests.length=checkpoint.nodes;
    this.frameIndex=checkpoint.frameIndex;this.recordIndex=checkpoint.recordIndex;this.previous=checkpoint.previous;this.records.length=checkpoint.recordIndex;
  }
  accept(frame){
    if(!fields(frame,frame?.kind==='nodes'?NODE_FIELDS:RECORD_FIELDS)||frame.format!==FORMAT||frame.schema!==SCHEMA||!['nodes','record'].includes(frame.kind))fail('invalid frame schema');
    if(frame.frameIndex!==this.frameIndex||frame.previous!==this.previous)fail('frame sequence/chain mismatch');
    if(!digest(frame.sha256)||hash(JSON.stringify(framePayload(frame)))!==frame.sha256)fail('frame hash mismatch');
    const checkpoint=this.checkpoint();
    try {
      if(frame.kind==='nodes'){
        if(frame.offset!==this.nodes.length)fail('node offset mismatch');dense(frame.nodes);
        if(!frame.nodes.length||frame.nodes.length>MAX_FRAME_NODES)fail('node frame size');
        for(const input of frame.nodes){
          const node=validatedNode(input,this.nodes);this.nodes.push(node);this.digests.push(nodeDigest(node,this.digests));
        }
      }else {
        if(frame.recordIndex!==this.recordIndex||!integer(frame.root)||frame.root>=this.nodes.length||this.nodes[frame.root][0]==='h')fail('invalid record index/root');
        if(!digest(frame.rootDigest)||frame.rootDigest!==this.digests[frame.root])fail('root digest mismatch');
        this.records.push({root:frame.root,rootDigest:frame.rootDigest,sha256:frame.sha256,frameIndex:frame.frameIndex,previous:frame.previous});this.recordIndex++;
      }
      this.previous=frame.sha256;this.frameIndex++;
      return frame.kind==='record'?{recordIndex:frame.recordIndex,frameIndex:frame.frameIndex,root:frame.root,rootDigest:frame.rootDigest,sha256:frame.sha256}:null;
    }catch(error){this.rollback(checkpoint);throw error;}
  }
  record(frame){
    if(!fields(frame,RECORD_FIELDS)||!integer(frame.recordIndex))fail('invalid accepted-record reference');
    const saved=this.records[frame?.recordIndex];
    if(!saved||frame.kind!=='record'||frame.format!==FORMAT||frame.schema!==SCHEMA||saved.sha256!==frame.sha256||saved.root!==frame.root||saved.rootDigest!==frame.rootDigest||saved.frameIndex!==frame.frameIndex||saved.previous!==frame.previous)fail('record was not accepted');
    return saved.root;
  }
}
const DECODERS=new WeakMap();
function ownField(state,root,name){
  const node=state.nodes[root];if(node[0]!=='o')return undefined;
  return node[1].find(entry=>entry[0]===name)?.[1];
}
function* taggedTokens(nodes,root){
  const stack=[root];
  while(stack.length){
    const item=stack.pop();if(typeof item==='string'){yield item;continue;}
    const [type,value,extra]=nodes[item];
    if(type==='u'||type==='h'||type==='z'){yield type==='u'?'["undefined"]':type==='h'?'["hole"]':'["null"]';continue;}
    if(type==='n'||type==='i'||type==='s'||type==='b'){
      yield '['+JSON.stringify(type==='n'?'number':type==='i'?'bigint':type==='s'?'string':'boolean')+','+JSON.stringify(value)+']';continue;
    }
    if(type==='t'){yield '["typed",'+JSON.stringify(value)+','+JSON.stringify(extra)+']';continue;}
    if(type==='v'||type==='d'){yield '['+JSON.stringify(type==='v'?'buffer':'date')+','+JSON.stringify(value)+']';continue;}
    yield '["'+(type==='a'?'array':type==='o'?'object':type==='m'?'map':'set')+'",[';stack.push(']]');
    for(let i=value.length-1;i>=0;i--){
      if(i<value.length-1)stack.push(',');
      if(type==='a'||type==='e')stack.push(value[i]);
      else if(type==='o'){stack.push(']');stack.push(value[i][1]);stack.push(',');stack.push(JSON.stringify(value[i][0]));stack.push('[');}
      else {stack.push(']');stack.push(value[i][1]);stack.push(',');stack.push(value[i][0]);stack.push('[');}
    }
  }
}
export class ValueGraphDecoder {
  constructor(){DECODERS.set(this,new DecoderState());}
  accept(frame){return DECODERS.get(this).accept(frame);}
  assertValue(recordFrame,expectedRawValue){const state=DECODERS.get(this);assertRaw(state,state.record(recordFrame),expectedRawValue);return true;}
  matches(recordFrame,selector){
    const state=DECODERS.get(this),root=state.record(recordFrame);
    if(selector===null||typeof selector!=='object'||Array.isArray(selector))fail('invalid selector');
    for(const [key,expected] of Object.entries(selector)){
      if(!['caseId','kind','cursor'].includes(key))fail('unsupported selector field');
      const id=ownField(state,root,key);if(id===undefined)return false;
      try{assertRaw(state,id,expected);}catch(error){if(error instanceof ValueMismatch)return false;throw error;}
    }
    return true;
  }
  taggedJson(recordFrame,fieldName){
    const state=DECODERS.get(this);let root=state.record(recordFrame);
    if(fieldName!==undefined){if(typeof fieldName!=='string')fail('invalid field name');root=ownField(state,root,fieldName);if(root===undefined)fail('selected own field is absent');}
    return taggedTokens(state.nodes,root);
  }
}
export class ValueGraphEncoder {
  #store;#decoder=new ValueGraphDecoder();#emittedNodes=0;#frameIndex=0;#recordIndex=0;#previous=null;
  constructor(comparisonGraph){
    if(comparisonGraph!==undefined&&!GRAPHS.has(comparisonGraph))fail('invalid comparison graph');
    this.#store=comparisonGraph===undefined?new GraphStore():GRAPHS.get(comparisonGraph);
  }
  encode(rawRecord){
    const transaction=this.#store.checkpoint(),state=DECODERS.get(this.#decoder),checkpoint=state.checkpoint();
    try {
      const {root,digest:rootDigest}=this.#store.capture(rawRecord,transaction),frames=[];
      let frameIndex=this.#frameIndex,previous=this.#previous;
      for(let offset=this.#emittedNodes;offset<this.#store.nodes.length;){
        const start=offset,nodes=[];let chars=2;
        while(offset<this.#store.nodes.length&&nodes.length<MAX_FRAME_NODES){
          const length=this.#store.signatures[offset].length+1;
          if(nodes.length&&chars+length>TARGET_FRAME_CHARS)break;
          nodes.push(copyNode(this.#store.nodes[offset]));chars+=length;offset++;
        }
        const frame=signedFrame({format:FORMAT,schema:SCHEMA,kind:'nodes',frameIndex:frameIndex++,offset:start,nodes,previous});
        frames.push(frame);previous=frame.sha256;
      }
      const record=signedFrame({format:FORMAT,schema:SCHEMA,kind:'record',frameIndex:frameIndex++,recordIndex:this.#recordIndex,root,rootDigest,previous});
      frames.push(record);
      for(const frame of frames)this.#decoder.accept(frame);
      this.#decoder.assertValue(record,rawRecord);
      this.#store.commit(transaction);
      this.#emittedNodes=this.#store.nodes.length;this.#frameIndex=frameIndex;this.#recordIndex++;this.#previous=record.sha256;
      return {frames,record};
    }catch(error){state.rollback(checkpoint);this.#store.rollback(transaction);throw error;}
  }
}
// Consumers must exhaust this iterator before trusting a stream. Fatal UTF8,
// final LF, complete carrier trailers and a terminal record are all required.
// An externally bound count/final SHA detects otherwise valid truncated suffixes.
export async function* readValueGraphFrames(filename,{compression='gzip'}={}){
  if(compression!=='gzip'&&compression!=='brotli')fail('unsupported compression: '+compression);
  const input=createReadStream(filename);
  // Bun 1.4.2's node:zlib Brotli stream can ignore unused input, and its
  // bytesWritten accounting does not reliably prove consumption. Its standard
  // Web decoder rejects trailing bytes and incomplete streams while retaining
  // backpressure. Adapt the async iterator, not Readable.toWeb: the latter can
  // enqueue after cancellation on this runtime when malformed input is rejected.
  const decompress=compression==='gzip'?createGunzip():Readable.fromWeb(
    ReadableStream.from(input).pipeThrough(new DecompressionStream('brotli'))
  );
  const inputDone=finished(input),decompressDone=finished(decompress);
  inputDone.catch(()=>{});decompressDone.catch(()=>{});
  if(compression==='gzip'){input.on('error',error=>decompress.destroy(error));input.pipe(decompress);}
  const decoder=new TextDecoder('utf-8',{fatal:true});let pending='',lastKind,count=0;
  try {
    for await(const bytes of decompress){
      pending+=decoder.decode(bytes,{stream:true});let newline;
      while((newline=pending.indexOf('\n'))!==-1){
        const line=pending.slice(0,newline);pending=pending.slice(newline+1);
        if(!line.length)fail('empty JSONL frame');
        const frame=JSON.parse(line);lastKind=frame?.kind;count++;yield frame;
      }
    }
    await inputDone;await decompressDone;
    pending+=decoder.decode();if(pending.length)fail('truncated JSONL frame (missing final LF)');
    if(!count||lastKind!=='record')fail('empty stream or incomplete definition tail');
  }finally{input.destroy();decompress.destroy();}
}
async function writeTokens(stream,tokens){
  let pending='';
  for(const token of tokens){pending+=token;if(pending.length>=65536){if(!stream.write(pending))await once(stream,'drain');pending='';}}
  if(!stream.write(pending+'\n'))await once(stream,'drain');
}
async function cli(){
  const [command,...args]=process.argv.slice(2),options=new Map();
  if(!['check','extract'].includes(command))fail('usage: check|extract --input=FILE --expected-records=N --expected-last-sha256=HEX [--compression=gzip|brotli] [--record-index=N | --case-id=ID --kind=K [--cursor=JSON]] [--field=baseline|projection|data] [--out=NEW_FILE]');
  for(const arg of args){
    const match=/^--([a-z0-9-]+)=(.*)$/.exec(arg);
    if(!match||options.has(match[1])||!['input','compression','expected-records','expected-last-sha256','record-index','case-id','kind','cursor','field','out'].includes(match[1]))fail('unknown or duplicate option: '+arg);
    options.set(match[1],match[2]);
  }
  if(!options.get('input'))fail('--input is required');
  const compression=options.has('compression')?options.get('compression'):'gzip';
  if(compression!=='gzip'&&compression!=='brotli')fail('unsupported compression: '+compression);
  if(!options.has('expected-records')||!options.has('expected-last-sha256'))fail(command+' requires externally bound record count and final SHA256');
  if(options.has('expected-records')&&(!/^[1-9][0-9]*$/.test(options.get('expected-records'))||!integer(Number(options.get('expected-records')))))fail('invalid expected record count');
  if(options.has('expected-last-sha256')&&!digest(options.get('expected-last-sha256')))fail('invalid expected final hash');
  let selectedIndex,selector;
  if(command==='check'){
    if(['record-index','case-id','kind','cursor','field','out'].some(key=>options.has(key)))fail('check does not accept extraction options');
  }else {
    if(options.has('field')&&!['baseline','projection','data'].includes(options.get('field')))fail('invalid extraction field');
    if(options.has('record-index')){
      if(!/^(0|[1-9][0-9]*)$/.test(options.get('record-index'))||!integer(Number(options.get('record-index')))||['case-id','kind','cursor'].some(key=>options.has(key)))fail('choose one exact selector');
      selectedIndex=Number(options.get('record-index'));
    }else {
      if(!options.get('case-id')||!options.get('kind'))fail('exact --case-id and --kind are required');
      selector={caseId:options.get('case-id'),kind:options.get('kind')};
      if(options.has('cursor')){
        const cursor=JSON.parse(options.get('cursor'));
        if(!fields(cursor,['eventIndex','milestone'])||!Number.isSafeInteger(cursor.eventIndex)||typeof cursor.milestone!=='string')fail('invalid cursor selector');
        selector.cursor=cursor;
      }
    }
  }
  const decoder=new ValueGraphDecoder();let records=0,frames=0,lastFrameSha256,selected,found=0;
  for await(const frame of readValueGraphFrames(options.get('input'),{compression})){
    const record=decoder.accept(frame);frames++;lastFrameSha256=frame.sha256;
    if(record){
      records++;
      if(command==='extract'&&(selectedIndex!==undefined?frame.recordIndex===selectedIndex:decoder.matches(frame,selector))){
        if(++found!==1)fail('selector matches multiple records');selected=frame;
      }
    }
  }
  if(options.has('expected-records')&&records!==Number(options.get('expected-records')))fail('expected record count mismatch');
  if(options.has('expected-last-sha256')&&lastFrameSha256!==options.get('expected-last-sha256'))fail('expected final hash mismatch');
  if(command==='check'){
    process.stdout.write(JSON.stringify({format:FORMAT,schema:SCHEMA,records,frames,lastFrameSha256,rootDigestAlgorithm:ROOT_DIGEST_ALGORITHM,status:'checked'})+'\n');return;
  }
  if(found!==1)fail('selector matched no record');
  const tokens=decoder.taggedJson(selected,options.get('field'));
  if(options.has('out')){
    const stream=createWriteStream(options.get('out'),{flags:'wx'}),done=finished(stream);done.catch(()=>{});
    try{await writeTokens(stream,tokens);stream.end();await done;}catch(error){stream.destroy();throw error;}
  }else await writeTokens(process.stdout,tokens);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))cli().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
