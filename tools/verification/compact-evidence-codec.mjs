import {createHash} from 'node:crypto';
import {createReadStream, createWriteStream} from 'node:fs';
import {once} from 'node:events';
import {finished} from 'node:stream/promises';
import {createGunzip} from 'node:zlib';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const FORMAT='compact-evidence-structural-v1';
const FIELDS=['format','version','index','offset','nodes','root','jsonBytes','jsonSha256','previous','sha256'];
const TYPES=new Set(['z','b','n','s','a','o','p']);
const hash=text=>createHash('sha256').update(text).digest('hex');
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const fail=message=>{throw new TypeError('Compact evidence: '+message);};
function payload(chunk){
  const {format,version,index,offset,nodes,root,jsonBytes,jsonSha256,previous}=chunk;
  return {format,version,index,offset,nodes,root,jsonBytes,jsonSha256,previous};
}
function keysExactly(value,keys){
  return value!==null&&typeof value==='object'&&!Array.isArray(value)&&
    Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
}
function reference(ref,nodes,limit){
  if(!Array.isArray(ref)||ref.length!==2||!TYPES.has(ref[0])||!integer(ref[1])||ref[1]>=limit||nodes[ref[1]]?.[0]!==ref[0])fail('invalid, forward or mistyped reference');
}
function validateNode(node,nodes,id){
  if(!Array.isArray(node)||!TYPES.has(node[0]))fail('invalid node type');
  const [type,value]=node;
  if(type==='z'){if(node.length!==1)fail('invalid null node');return;}
  if(node.length!==2)fail('invalid node arity');
  if(type==='s'){if(typeof value!=='string')fail('invalid string');return;}
  if(type==='b'){if(typeof value!=='boolean')fail('invalid boolean');return;}
  if(type==='n'){
    if(typeof value!=='string'||!Number.isFinite(Number(value))||(value!=='-0'&&String(Number(value))!==value))fail('invalid number');
    return;
  }
  if(!Array.isArray(value))fail('invalid child list');
  if(type==='a'){for(const ref of value)reference(ref,nodes,id);return;}
  const keys=new Set();
  const ordered={};
  for(const entry of value){
    if(!Array.isArray(entry)||entry.length!==2)fail('invalid object entry');
    reference(entry[0],nodes,id);reference(entry[1],nodes,id);
    if(entry[0][0]!=='s')fail('object key is not a string');
    const key=nodes[entry[0][1]][1];
    if(keys.has(key))fail('duplicate object key');
    keys.add(key);Object.defineProperty(ordered,key,{value:null,enumerable:true});
  }
  if(Object.keys(ordered).some((key,i)=>key!==nodes[value[i][0][1]][1]))fail('noncanonical object key order');
}

const FRAGMENT_MIN_BYTES=256,FRAGMENT_MAX_BYTES=65536,FRAGMENT_CACHE_BYTES=32*1024*1024,FRAGMENT_CACHE_ENTRIES=32768;
class SerializedFragments {
  #entries=new Map();#bytes=0;
  get(id){
    const bytes=this.#entries.get(id);
    if(bytes){this.#entries.delete(id);this.#entries.set(id,bytes);}
    return bytes;
  }
  add(id,bytes){
    // LRU eviction keeps both retained UTF8 bytes and tiny-entry metadata
    // bounded. Buffers never escape the decoder or become caller-owned.
    while(this.#entries.size>=FRAGMENT_CACHE_ENTRIES||this.#bytes+bytes.length>FRAGMENT_CACHE_BYTES){
      const oldest=this.#entries.keys().next().value;
      this.#bytes-=this.#entries.get(oldest).length;this.#entries.delete(oldest);
    }
    this.#entries.set(id,bytes);this.#bytes+=bytes.length;
  }
  rollback(offset){
    for(const [id,bytes] of this.#entries)if(id>=offset){
      this.#bytes-=bytes.length;this.#entries.delete(id);
    }
  }
}
function serializedSize(node,sizes){
  const [type,value]=node;
  if(type==='z')return 4;
  if(type==='b')return value?4:5;
  if(type==='n')return value==='-0'?1:value.length;
  if(type==='s')return Math.min(FRAGMENT_MAX_BYTES+1,Buffer.byteLength(JSON.stringify(value),'utf8'));
  let bytes=2+Math.max(0,value.length-1);
  for(const entry of value){
    if(bytes>FRAGMENT_MAX_BYTES)break;
    bytes+=type==='a'?sizes[entry[1]]:sizes[entry[0][1]]+1+sizes[entry[1][1]];
  }
  return Math.min(FRAGMENT_MAX_BYTES+1,bytes);
}

// Both walkers use explicit stacks: tagged protocol data can be deeply nested.
// The optional private byte mode collapses small validated DAG subtrees. The
// public json() path supplies no cache and continues to yield only text tokens.
function* jsonTokens(nodes,root,fragments,sizes,cacheMisses=true){
  const stack=[root[1]];
  while(stack.length){
    const item=stack.pop();
    if(typeof item==='string'){yield item;continue;}
    if(fragments){
      const cached=fragments.get(item);
      if(cached){yield cached;continue;}
      // Keys and short tag strings recur even inside a missing composite. Keep
      // their exact escaped UTF8 under the same byte and entry bounds.
      if(nodes[item][0]==='s'&&sizes[item]<=FRAGMENT_MAX_BYTES){
        const bytes=Buffer.from(JSON.stringify(nodes[item][1]),'utf8');
        fragments.add(item,bytes);yield bytes;continue;
      }
      if(cacheMisses&&sizes[item]>=FRAGMENT_MIN_BYTES&&sizes[item]<=FRAGMENT_MAX_BYTES){
        const parts=[];let pending='';
        // A missing parent can reuse existing child bytes too. Do not populate
        // overlapping new composite fragments while building this bounded parent.
        for(const token of jsonTokens(nodes,[nodes[item][0],item],fragments,sizes,false)){
          if(typeof token==='string')pending+=token;
          else {
            if(pending){parts.push(Buffer.from(pending,'utf8'));pending='';}
            parts.push(token);
          }
        }
        if(pending)parts.push(Buffer.from(pending,'utf8'));
        const bytes=parts.length===1?parts[0]:Buffer.concat(parts,sizes[item]);
        fragments.add(item,bytes);yield bytes;continue;
      }
    }
    const [type,value]=nodes[item];
    if(type==='z'){yield 'null';continue;}
    if(type==='s'){yield JSON.stringify(value);continue;}
    if(type==='b'){yield value?'true':'false';continue;}
    if(type==='n'){yield value==='-0'?'0':value;continue;}
    const array=type==='a';
    yield array?'[':'{';stack.push(array?']':'}');
    for(let i=value.length-1;i>=0;i--){
      if(i<value.length-1)stack.push(',');
      if(array)stack.push(value[i][1]);
      else {
        stack.push(value[i][1][1]);stack.push(':');
        stack.push(value[i][0][1]);
      }
    }
  }
}
function verifyBytes(nodes,chunk,expected,fragments,sizes){
  const sha=createHash('sha256');let bytes=0,pending='';
  const accept=buffer=>{
    if(expected&&!buffer.equals(expected.subarray(bytes,bytes+buffer.length)))fail('self-check reconstructed bytes differ');
    bytes+=buffer.length;sha.update(buffer);
  };
  const flush=()=>{
    if(!pending)return;
    accept(Buffer.from(pending,'utf8'));pending='';
  };
  // Cached fragments are actual reconstructed UTF8, not trusted hashes: every
  // byte still reaches expected-byte comparison and this record's fresh SHA.
  for(const token of jsonTokens(nodes,chunk.root,fragments,sizes)){
    if(typeof token==='string'){pending+=token;if(pending.length>=65536)flush();}
    else {flush();accept(token);}
  }
  flush();
  if(bytes!==chunk.jsonBytes||sha.digest('hex')!==chunk.jsonSha256||expected&&bytes!==expected.length)fail('reconstructed JSON byte count/hash mismatch');
}
function materialize(nodes,root){
  let result;
  const stack=[{ref:root,assign:value=>{result=value;}}];
  while(stack.length){
    const {ref,assign}=stack.pop(),[type,data]=nodes[ref[1]];
    if(type==='z'){assign(null);continue;}
    if(type==='s'||type==='b'){assign(data);continue;}
    if(type==='n'){assign(data==='-0'?-0:Number(data));continue;}
    const value=type==='a'?[]:type==='p'?Object.create(null):{};
    assign(value);
    for(let i=data.length-1;i>=0;i--){
      const key=type==='a'?i:nodes[data[i][0][1]][1];
      stack.push({ref:type==='a'?data[i]:data[i][1],assign:child=>{
        Object.defineProperty(value,key,{value:child,writable:true,enumerable:true,configurable:true});
      }});
    }
  }
  return result;
}

export class EvidenceDecoder {
  #nodes=[];#sizes=[];#fragments=new SerializedFragments();#index=0;#previous=null;#root=null;
  #accept(chunk,expected){
    if(!keysExactly(chunk,FIELDS)||chunk.format!==FORMAT||chunk.version!==1)fail('invalid format/version/fields');
    if(chunk.index!==this.#index||chunk.offset!==this.#nodes.length)fail('out-of-order index/node offset');
    if(chunk.previous!==this.#previous||!digest(chunk.sha256)||hash(JSON.stringify(payload(chunk)))!==chunk.sha256)fail('chunk chain/hash mismatch');
    if(!integer(chunk.jsonBytes)||!digest(chunk.jsonSha256)||!Array.isArray(chunk.nodes))fail('invalid JSON binding/nodes');
    const offset=this.#nodes.length;
    try {
      // Copy definitions so a caller mutating its chunk cannot poison the pool.
      for(const node of chunk.nodes){
        validateNode(node,this.#nodes,this.#nodes.length);
        const type=node[0];
        this.#nodes.push(type==='z'?['z']:['s','n','b'].includes(type)?[type,node[1]]:
          [type,node[1].map(entry=>type==='a'?[...entry]:[[...entry[0]],[...entry[1]]])]);
        this.#sizes.push(serializedSize(this.#nodes[this.#nodes.length-1],this.#sizes));
      }
      reference(chunk.root,this.#nodes,this.#nodes.length);
      verifyBytes(this.#nodes,chunk,expected,this.#fragments,this.#sizes);
    }catch(error){
      this.#nodes.length=offset;this.#sizes.length=offset;this.#fragments.rollback(offset);
      throw error;
    }
    this.#index++;this.#previous=chunk.sha256;this.#root=[...chunk.root];
  }
  // Checks exact reconstructed JSON bytes without allocating a decoded snapshot.
  check(chunk){this.#accept(chunk);return {index:chunk.index,jsonBytes:chunk.jsonBytes,jsonSha256:chunk.jsonSha256};}
  decode(chunk){this.#accept(chunk);return materialize(this.#nodes,chunk.root);}
  // Encoder-only byte-for-byte self-check, in addition to the public hash check.
  selfCheck(chunk,expected){this.#accept(chunk,expected);}
  matches(chunk,selector){
    if(chunk.index!==this.#index-1||chunk.sha256!==this.#previous)fail('selector requires the most recently checked chunk');
    const [type,entries]=this.#nodes[this.#root[1]];
    if(type!=='o'&&type!=='p')return false;
    const field=name=>entries.find(entry=>this.#nodes[entry[0][1]][1]===name)?.[1];
    for(const [key,expected] of Object.entries(selector)){
      const ref=field(key);
      if(!ref)return false;
      const actual=materialize(this.#nodes,ref);
      if(key==='cursor'){
        if(!keysExactly(actual,Object.keys(expected))||Object.keys(expected).some(name=>actual[name]!==expected[name]))return false;
      }else if(!Object.is(actual,expected))return false;
    }
    return true;
  }
  *json(chunk){
    if(chunk.index!==this.#index-1||chunk.sha256!==this.#previous)fail('extraction requires the most recently checked chunk');
    yield* jsonTokens(this.#nodes,this.#root);
  }
}

export class EvidenceEncoder {
  #pool=new Map();#immutable=new WeakMap();#decoder=new EvidenceDecoder();#index=0;#previous=null;
  #intern(type,value,nodes,added){
    let node;
    // Primitive values need neither a temporary definition nor JSON escaping to
    // form an unambiguous private key. Structural keys still bind every edge.
    const signature=type==='a'||type==='o'||type==='p'?JSON.stringify(node=[type,value]):type==='z'?'z':type+value;
    let id=this.#pool.get(signature);
    if(id===undefined){
      id=this.#pool.size;this.#pool.set(signature,id);added.push(signature);
      nodes.push(node??(type==='z'?['z']:[type,value]));
    }
    return [type,id];
  }
  encode(value,expectedJSON){
    if(expectedJSON!==undefined&&typeof expectedJSON!=='string'&&!Buffer.isBuffer(expectedJSON))fail('expected JSON must be a string or Buffer');
    const nodes=[],offset=this.#pool.size,added=[],memoized=[],active=new Set(),result=[];
    const stack=[{value,target:result,key:0}];
    try {
      while(stack.length){
        const task=stack[stack.length-1];
        let ref,immutable=true;
        if(task.children){
          if(task.next<task.values.length){
            const i=task.next++;
            if(task.array)stack.push({value:task.values[i],target:task.children,key:i});
            else {
              const entry=[this.#intern('s',task.keys[i],nodes,added)];
              task.children[i]=entry;
              stack.push({value:task.values[i],target:entry,key:1});
            }
            continue;
          }
          active.delete(task.value);
          ref=this.#intern(task.type,task.children,nodes,added);
          immutable=task.immutable;
          if(immutable){
            // Keep a private reference: returned chunks remain caller-owned.
            this.#immutable.set(task.value,{type:ref[0],id:ref[1]});
            memoized.push(task.value);
          }
        }else {
          const item=task.value,type=typeof item;
          if(item===null)ref=this.#intern('z',null,nodes,added);
          else if(type==='string'||type==='boolean')ref=this.#intern(type==='string'?'s':'b',item,nodes,added);
          else if(type==='number'){
            if(!Number.isFinite(item))fail('unsupported nonfinite number');
            ref=this.#intern('n',Object.is(item,-0)?'-0':String(item),nodes,added);
          }else {
            if(type!=='object')fail('unsupported '+type);
            const memo=this.#immutable.get(item);
            if(memo)ref=[memo.type,memo.id];
            else {
              if(active.has(item))fail('cyclic input');
              const array=Array.isArray(item),prototype=Object.getPrototypeOf(item);
              if(array?prototype!==Array.prototype:prototype!==Object.prototype&&prototype!==null)fail('unsupported object prototype');
              const keys=Reflect.ownKeys(item),values=[];
              let frozen=!Object.isExtensible(item),length;
              if(array){
                const descriptor=Object.getOwnPropertyDescriptor(item,'length');
                length=descriptor.value;
                if(keys.length!==length+1)fail('sparse array or extra array property; use tagged lossless data');
                if(descriptor.writable||descriptor.configurable)frozen=false;
              }
              // Inspect descriptors once, without constructing a second object
              // containing all descriptors or invoking any source accessor.
              for(let i=0;i<keys.length;i++){
                const key=keys[i];
                if(typeof key!=='string')fail('unsupported symbol key');
                if(array&&key==='length')continue;
                let index=i;
                if(array){
                  index=Number(key);
                  if(!integer(index)||String(index)!==key||index>=length)fail('sparse array or extra array property; use tagged lossless data');
                }
                const descriptor=Object.getOwnPropertyDescriptor(item,key);
                if(!descriptor||!Object.hasOwn(descriptor,'value')||!descriptor.enumerable)fail('unsupported accessor/nonenumerable property');
                if(descriptor.writable||descriptor.configurable)frozen=false;
                values[index]=descriptor.value;
              }
              active.add(item);
              task.array=array;task.keys=keys;task.values=values;task.next=0;
              task.type=array?'a':prototype===null?'p':'o';task.children=[];task.immutable=frozen;
              continue;
            }
          }
        }
        stack.pop();task.target[task.key]=ref;
        if(!immutable&&stack.length)stack[stack.length-1].immutable=false;
      }
      // Callers with an already serialized original record may avoid another
      // native traversal; the decoder still reconstructs and compares all bytes.
      const bytes=Buffer.isBuffer(expectedJSON)?expectedJSON:Buffer.from(expectedJSON===undefined?JSON.stringify(value):expectedJSON,'utf8'),root=result[0];
      const chunk={format:FORMAT,version:1,index:this.#index,offset,nodes,root,jsonBytes:bytes.length,jsonSha256:hash(bytes),previous:this.#previous};
      chunk.sha256=hash(JSON.stringify(chunk));
      this.#decoder.selfCheck(chunk,bytes);
      this.#index++;this.#previous=chunk.sha256;
      return chunk;
    }catch(error){
      // A failed parent or byte reconstruction must not leave references to
      // definitions removed from this transaction's node pool.
      for(const item of memoized)this.#immutable.delete(item);
      for(const signature of added)this.#pool.delete(signature);
      throw error;
    }
  }
}

// Fatal UTF-8 decoding plus a required final LF distinguish malformed/truncated
// JSONL from successful EOF. Gunzip verifies every concatenated member's CRC.
async function* readChunks(filename){
  const input=createReadStream(filename),gunzip=createGunzip();
  input.on('error',error=>gunzip.destroy(error));input.pipe(gunzip);
  const decoder=new TextDecoder('utf-8',{fatal:true});let pending='';
  try {
    for await(const bytes of gunzip){
      pending+=decoder.decode(bytes,{stream:true});
      let newline;
      while((newline=pending.indexOf('\n'))!==-1){
        const line=pending.slice(0,newline);pending=pending.slice(newline+1);
        if(!line.length)fail('empty JSONL record');
        yield JSON.parse(line);
      }
    }
    pending+=decoder.decode();
    if(pending.length)fail('truncated JSONL record (missing final LF)');
  }finally{input.destroy();gunzip.destroy();}
}
async function writeTokens(stream,tokens){
  let pending='';
  for(const token of tokens){
    pending+=token;
    if(pending.length>=65536){if(!stream.write(pending))await once(stream,'drain');pending='';}
  }
  if(!stream.write(pending+'\n'))await once(stream,'drain');
}
async function cli(){
  const [command,...args]=process.argv.slice(2),options=new Map();
  if(!['check','extract'].includes(command))fail('usage: check|extract --input=FILE [--record-index=N | --case-id=ID --kind=K [--cursor=JSON]] [--out=NEW_FILE]');
  for(const arg of args){
    const match=/^--([a-z0-9-]+)=(.*)$/.exec(arg);
    if(!match||options.has(match[1])||!['input','record-index','case-id','kind','cursor','out','expected-records','expected-last-sha256'].includes(match[1]))fail('unknown or duplicate option: '+arg);
    options.set(match[1],match[2]);
  }
  if(!options.get('input'))fail('--input is required');
  let selectedIndex=null,selector=null;
  if(command==='check'&&['record-index','case-id','kind','cursor','out'].some(key=>options.has(key)))fail('check does not accept extraction options');
  if(options.has('expected-records')&&(!/^[1-9][0-9]*$/.test(options.get('expected-records'))||!integer(Number(options.get('expected-records')))))fail('invalid expected record count');
  if(options.has('expected-last-sha256')&&!digest(options.get('expected-last-sha256')))fail('invalid expected final hash');
  if(command==='extract'){
    if(options.has('record-index')){
      if(!/^(0|[1-9][0-9]*)$/.test(options.get('record-index')))fail('invalid record index');
      selectedIndex=Number(options.get('record-index'));
      if(!integer(selectedIndex)||['case-id','kind','cursor'].some(key=>options.has(key)))fail('choose one exact selector');
    }else {
      if(!options.get('case-id')||!options.get('kind'))fail('exact --case-id and --kind are required');
      selector={caseId:options.get('case-id'),kind:options.get('kind')};
      if(options.has('cursor')){
        const cursor=JSON.parse(options.get('cursor'));
        if(!keysExactly(cursor,['eventIndex','milestone'])||!Number.isSafeInteger(cursor.eventIndex)||typeof cursor.milestone!=='string')fail('cursor requires eventIndex and milestone');
        selector.cursor={eventIndex:cursor.eventIndex,milestone:cursor.milestone};
      }
    }
  }
  const decoder=new EvidenceDecoder();let count=0,bytes=0,found=0,selectedTokens,lastSha256;
  // Validate all later records and the gzip trailer too. Only a selected record's
  // serialized tokens are retained, never the expanded corpus or snapshots.
  for await(const chunk of readChunks(options.get('input'))){
    const receipt=decoder.check(chunk);count++;bytes+=receipt.jsonBytes;lastSha256=chunk.sha256;
    if(command==='extract'&&(selectedIndex!==null?chunk.index===selectedIndex:decoder.matches(chunk,selector))){
      if(++found!==1)fail('selector matches multiple records; supply an exact cursor/index');
      selectedTokens=[...decoder.json(chunk)];
    }
  }
  if(!count)fail('empty evidence stream');
  if(options.has('expected-records')&&count!==Number(options.get('expected-records')))fail('expected record count mismatch');
  if(options.has('expected-last-sha256')&&lastSha256!==options.get('expected-last-sha256'))fail('expected final hash mismatch');
  if(command==='check'){process.stdout.write(JSON.stringify({format:FORMAT,records:count,jsonBytes:bytes,lastSha256,status:'checked'})+'\n');return;}
  if(found!==1)fail('selector matched no record');
  if(options.has('out')){
    const stream=createWriteStream(options.get('out'),{flags:'wx'});
    // Observe asynchronous open/write errors even when the token buffer is small.
    const done=finished(stream);done.catch(()=>{});
    try{await writeTokens(stream,selectedTokens);stream.end();await done;}
    catch(error){stream.destroy();throw error;}
  }else await writeTokens(process.stdout,selectedTokens);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  cli().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
}
