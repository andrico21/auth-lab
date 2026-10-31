import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {EvidenceEncoder,EvidenceDecoder} from '../tools/verification/compact-evidence-codec.mjs';
import {compactStable} from '../tools/verification/compact-view-fixtures.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const copy=value=>JSON.parse(JSON.stringify(value));
const wire=chunk=>copy(chunk);
const cli=fileURLToPath(new URL('../tools/verification/compact-evidence-codec.mjs',import.meta.url));
function reseal(chunk){
  const {sha256,...body}=chunk;
  chunk.sha256=sha(JSON.stringify(body));return chunk;
}
function session(values){
  const encoder=new EvidenceEncoder();return values.map(value=>wire(encoder.encode(value)));
}
function fixture(t,records){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'compact-codec-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const filename=path.join(directory,'evidence.jsonl.gz');
  const chunks=session(records);
  fs.writeFileSync(filename,Buffer.concat(chunks.map(chunk=>gzipSync(JSON.stringify(chunk)+'\n'))));
  const run=(command,...options)=>spawnSync(process.execPath,[cli,command,'--input='+filename,...options],{encoding:'utf8',maxBuffer:16*1024*1024});
  return {directory,filename,chunks,run};
}

const records=[
  {caseId:'case/a',kind:'authored',encoding:'compact-tagged-lossless-v1',data:['object',[
    ['token',['undefined']],
    ['list',['array',[
      ['hole'],['number','-0'],['typed','Uint8Array','00ff']
    ]]]
  ]]},
  {caseId:'case/a',kind:'prefix',cursor:{eventIndex:0,milestone:'before'},baseline:['object',[['token',['string','unchanged']]]],projection:['null']},
  {caseId:'case/a',kind:'prefix',cursor:{eventIndex:0,milestone:'complete'},baseline:['object',[['token',['string','changed']]]],projection:['null']},
  {caseId:'case/b',kind:'authored',data:['string','\u0000 astral \u{1f512}, combining e\u0301, lone \ud800']}
];

test('ordered shared-pool records rehydrate exact original UTF-8 JSON bytes and hashes',()=>{
  const encoder=new EvidenceEncoder(),decoder=new EvidenceDecoder();
  for(const value of records){
    const original=Buffer.from(JSON.stringify(value));
    const chunk=wire(encoder.encode(value));
    assert.equal(chunk.jsonBytes,original.length);
    assert.equal(chunk.jsonSha256,sha(original));
    const result=decoder.decode(chunk);
    assert.deepEqual(Buffer.from(JSON.stringify(result)),original);
    assert.deepEqual(result,value);
  }
});

test('deep actual tagged lossless values retain sparse, typed, undefined and map/set representations',()=>{
  const sparse=[];sparse.length=3;sparse[1]=undefined;sparse[2]=-0;
  let value={sparse,bytes:new Uint8Array([0,255,9]),map:new Map([['x',undefined]]),set:new Set([1,'1']),date:new Date('2026-10-27T00:00:00Z'),big:12n};
  for(let i=0;i<250;i++)value={level:i,child:[value]};
  const tagged={encoding:'compact-tagged-lossless-v1',data:JSON.parse(compactStable(value))};
  const chunk=new EvidenceEncoder().encode(tagged),decoded=new EvidenceDecoder().decode(wire(chunk));
  assert.equal(JSON.stringify(decoded),JSON.stringify(tagged));
  let leaf=decoded.data;
  for(let i=0;i<250;i++)leaf=leaf[1].find(entry=>entry[0]==='child')[1][1][0];
  const fields=Object.fromEntries(leaf[1]);
  assert.deepEqual(fields.sparse,['array',[['hole'],['undefined'],['number','-0']]]);
  assert.deepEqual(fields.bytes,['typed','Uint8Array','00ff09']);
  assert.deepEqual(fields.map,['map',[[['string','x'],['undefined']]]]);
});

test('typed nodes do not conflate null, false, strings, numbers, zero or negative zero',()=>{
  const value=[null,false,true,'false','null',0,-0,'0','-0',1,'1',1e+30,1e-7];
  const decoded=new EvidenceDecoder().decode(wire(new EvidenceEncoder().encode(value)));
  assert.deepEqual(decoded,value);assert.ok(Object.is(decoded[6],-0));assert.ok(!Object.is(decoded[5],-0));
});

test('object key order and prototype-sensitive names survive without prototype pollution',()=>{
  const ordinary=JSON.parse('{"10":"ten","2":"two","z":1,"__proto__":{"polluted":true},"constructor":2,"prototype":3,"a":4}');
  const bare=Object.create(null);bare.__proto__='data';bare.constructor='own';bare.z=1;
  const decoded=new EvidenceDecoder().decode(wire(new EvidenceEncoder().encode([ordinary,bare])));
  assert.equal(JSON.stringify(decoded),JSON.stringify([ordinary,bare]));
  assert.deepEqual(Object.keys(decoded[0]),Object.keys(ordinary));
  assert.equal(Object.getPrototypeOf(decoded[0]),Object.prototype);
  assert.equal(Object.getPrototypeOf(decoded[1]),null);
  assert.equal(decoded[0].__proto__.polluted,true);assert.equal({}.polluted,undefined);
});

test('new nodes are emitted once and pool offsets advance only for novel structures',()=>{
  const encoder=new EvidenceEncoder(),decoder=new EvidenceDecoder();
  const value={a:[1,2,{unchanged:'long repeated string'}],b:[1,2,{unchanged:'long repeated string'}]};
  const first=encoder.encode(value),second=encoder.encode(copy(value));
  assert.ok(first.nodes.length>0);assert.equal(second.nodes.length,0);
  assert.equal(second.offset,first.nodes.length);assert.equal(second.index,1);assert.equal(second.previous,first.sha256);
  assert.deepEqual(decoder.decode(wire(first)),value);assert.deepEqual(decoder.decode(wire(second)),value);
});

test('mutating an aliased input between records cannot reuse a stale object snapshot',()=>{
  const encoder=new EvidenceEncoder(),decoder=new EvidenceDecoder(),shared={token:'old',list:[1]};
  const value={a:shared,b:shared};
  const before=wire(encoder.encode(value));
  shared.token='new';shared.list.push(2);value.extra=true;
  const after=wire(encoder.encode(value));
  const left=decoder.decode(before),right=decoder.decode(after);
  assert.deepEqual(left,{a:{token:'old',list:[1]},b:{token:'old',list:[1]}});
  assert.deepEqual(right,value);assert.notEqual(left.a,left.b);assert.notEqual(left.a,right.a);
  left.a.list.push(9);assert.deepEqual(left.b.list,[1]);assert.deepEqual(right.b.list,[1,2]);
});

test('mutating a decoded result or previously supplied chunk cannot poison later decoding',()=>{
  const [first,second]=session([{state:{value:'original'}},{state:{value:'original'}}]);
  const decoder=new EvidenceDecoder(),value=decoder.decode(first);
  value.state.value='consumer mutation';
  for(const node of first.nodes)if(node[0]==='s')node[1]='chunk mutation';
  first.root=['s',0];
  assert.deepEqual(decoder.decode(second),{state:{value:'original'}});
});

test('encoder state rolls back after unsupported input or cycles',()=>{
  const encoder=new EvidenceEncoder(),decoder=new EvidenceDecoder();
  decoder.decode(wire(encoder.encode('first')));
  const cycle={name:'must-not-leak'};cycle.self=cycle;
  assert.throws(()=>encoder.encode(cycle),TypeError);
  assert.throws(()=>encoder.encode({ok:'must-not-leak',bad:undefined}),TypeError);
  assert.deepEqual(decoder.decode(wire(encoder.encode({ok:'final'}))),{ok:'final'});
});

test('unsupported raw values are rejected rather than silently normalized by JSON.stringify',()=>{
  const sparse=Array(1),extra=[];extra.flag=true;
  const accessor={};let calls=0;Object.defineProperty(accessor,'value',{enumerable:true,get(){calls++;return 1;}});
  const hidden={};Object.defineProperty(hidden,'hidden',{value:1});
  const symbol={};symbol[Symbol('secret')]=1;
  for(const value of [undefined,NaN,Infinity,-Infinity,1n,()=>1,Symbol('x'),sparse,extra,accessor,hidden,symbol,new Date(),new Map(),new Uint8Array([1]),Object.create({inherited:1})]){
    assert.throws(()=>new EvidenceEncoder().encode(value),TypeError);
  }
  assert.equal(calls,0);
});

test('dropped, reordered, repeated and wrong-offset chunks fail closed without advancing state',()=>{
  const chunks=session(['first','second','third']),decoder=new EvidenceDecoder();
  assert.throws(()=>decoder.decode(chunks[1]),TypeError);
  assert.equal(decoder.decode(chunks[0]),'first');
  assert.throws(()=>decoder.decode(chunks[0]),TypeError);
  assert.throws(()=>decoder.decode(chunks[2]),TypeError);
  const bad=copy(chunks[1]);bad.offset++;reseal(bad);
  assert.throws(()=>decoder.decode(bad),TypeError);
  assert.equal(decoder.decode(chunks[1]),'second');assert.equal(decoder.decode(chunks[2]),'third');
});

test('chunk corruption, chain corruption, unknown versions and truncated schemas are rejected',()=>{
  const chunk=session([{nested:[true,'text']}])[0];
  const mutations=[
    c=>{c.nodes[0][1]='corrupt';},c=>{c.previous='a'.repeat(64);reseal(c);},
    c=>{c.version=2;reseal(c);},c=>{delete c.root;reseal(c);},
    c=>{c.extra=true;reseal(c);},c=>{c.nodes.pop();reseal(c);}
  ];
  for(const mutate of mutations){const bad=copy(chunk);mutate(bad);assert.throws(()=>new EvidenceDecoder().decode(bad),TypeError);}
});

test('valid outer hashes do not hide wrong original JSON hashes or byte counts',()=>{
  const chunk=session([{message:'\u{1f512}'}])[0];
  for(const mutate of [c=>{c.jsonBytes--;},c=>{c.jsonSha256='0'.repeat(64);},c=>{c.nodes.find(n=>n[0]==='s'&&n[1]==='\u{1f512}')[1]='other';}]){
    const bad=copy(chunk);mutate(bad);reseal(bad);
    const decoder=new EvidenceDecoder();
    assert.throws(()=>decoder.decode(bad),TypeError);
    assert.deepEqual(decoder.decode(chunk),{message:'\u{1f512}'});
  }
});

test('forward, mistyped, dangling and cyclic references are rejected even with resealed chunk hashes',()=>{
  const chunk=session([['leaf']])[0];
  const mutations=[
    c=>{c.nodes[1][1][0]=['s',1];},
    c=>{c.nodes[1][1][0]=['n',0];},
    c=>{c.root=['a',999];},
    c=>{c.nodes[1][1][0]=['a',1];}
  ];
  for(const mutate of mutations){const bad=copy(chunk);mutate(bad);reseal(bad);assert.throws(()=>new EvidenceDecoder().decode(bad),TypeError);}
});

test('duplicate keys, noncanonical numeric keys and invalid primitive node payloads are rejected',()=>{
  const chunk=session([{a:1,b:2}])[0];
  const duplicate=copy(chunk),object=duplicate.nodes.find(node=>node[0]==='o');
  object[1][1][0]=copy(object[1][0][0]);reseal(duplicate);
  assert.throws(()=>new EvidenceDecoder().decode(duplicate),TypeError);
  const ordered=session([{'2':'two','10':'ten'}])[0];
  ordered.nodes.find(node=>node[0]==='o')[1].reverse();reseal(ordered);
  assert.throws(()=>new EvidenceDecoder().decode(ordered),TypeError);
  for(const invalid of [['n','NaN'],['n','01'],['n',1],['b','false'],['z',null],['s',5],['unknown']]){
    const bad=session(['valid'])[0];bad.nodes[0]=invalid;reseal(bad);
    assert.throws(()=>new EvidenceDecoder().decode(bad),TypeError);
  }
});

test('check hashes a record without returning a mutable snapshot and exact selector extraction is byte-identical',()=>{
  const decoder=new EvidenceDecoder(),chunks=session(records);
  for(let i=0;i<chunks.length;i++){
    const receipt=decoder.check(chunks[i]);
    assert.equal(receipt.jsonSha256,sha(JSON.stringify(records[i])));
    assert.equal([...decoder.json(chunks[i])].join(''),JSON.stringify(records[i]));
    assert.equal(decoder.matches(chunks[i],{caseId:'case/a',kind:'prefix',cursor:{milestone:'complete',eventIndex:0}}),i===2);
  }
});

test('streaming CLI checks concatenated gzip members and extracts exactly one original record',t=>{
  const {run,chunks,directory}=fixture(t,records);
  const checked=run('check','--expected-records=4','--expected-last-sha256='+chunks.at(-1).sha256);
  assert.equal(checked.status,0,checked.stderr);
  const receipt=JSON.parse(checked.stdout);assert.equal(receipt.records,4);assert.equal(receipt.lastSha256,chunks.at(-1).sha256);
  const selected=run('extract','--case-id=case/a','--kind=prefix','--cursor={"milestone":"complete","eventIndex":0}');
  assert.equal(selected.status,0,selected.stderr);assert.equal(selected.stdout,JSON.stringify(records[2])+'\n');
  const output=path.join(directory,'selected.json');
  const indexed=run('extract','--record-index=3','--out='+output);
  assert.equal(indexed.status,0,indexed.stderr);assert.equal(fs.readFileSync(output,'utf8'),JSON.stringify(records[3])+'\n');
  const existing=run('extract','--record-index=0','--out='+output);
  assert.notEqual(existing.status,0);assert.equal(fs.readFileSync(output,'utf8'),JSON.stringify(records[3])+'\n');
});

test('CLI rejects ambiguous and missing selectors, duplicate options and wrong expected stream identity',t=>{
  const {run}=fixture(t,records);
  for(const options of [
    ['extract','--case-id=case/a','--kind=prefix'],['extract','--case-id=absent','--kind=authored'],
    ['extract','--record-index=99'],['extract','--record-index=0','--case-id=case/a'],
    ['check','--input=duplicate'],['check','--expected-records=5'],['check','--expected-last-sha256='+'f'.repeat(64)]
  ]){const [command,...args]=options,result=run(command,...args);assert.notEqual(result.status,0);assert.equal(result.stdout,'');}
});

test('CLI validates the entire tail before releasing an otherwise selected record',t=>{
  const {run,filename,chunks}=fixture(t,records);
  const complete=run('extract','--record-index=0');assert.equal(complete.status,0);assert.equal(complete.stdout,JSON.stringify(records[0])+'\n');
  const bad=copy(chunks.at(-1));bad.jsonSha256='0'.repeat(64);reseal(bad);
  fs.writeFileSync(filename,Buffer.concat([...chunks.slice(0,-1),bad].map(chunk=>gzipSync(JSON.stringify(chunk)+'\n'))));
  const result=run('extract','--record-index=0');
  assert.notEqual(result.status,0);assert.equal(result.stdout,'');
});

test('CLI rejects invalid UTF-8, broken JSON, missing final LF and truncated or corrupt gzip',t=>{
  const {run,filename,chunks}=fixture(t,[records[0]]);
  const line=JSON.stringify(chunks[0])+'\n',compressed=gzipSync(line);
  const damaged=Buffer.from(compressed);damaged[damaged.length-8]^=1;
  const invalid=[gzipSync(Buffer.from([0xff,0x0a])),gzipSync('{broken}\n'),gzipSync(line.slice(0,-1)),compressed.subarray(0,-5),damaged,gzipSync(''),gzipSync('\n')];
  for(const bytes of invalid){fs.writeFileSync(filename,bytes);const result=run('check');assert.notEqual(result.status,0);assert.equal(result.stdout,'');}
});

test('a complete missing suffix is detected using the externally bound final receipt',t=>{
  const {run,filename,chunks}=fixture(t,records);
  const complete=run('check','--expected-records=4','--expected-last-sha256='+chunks.at(-1).sha256);assert.equal(complete.status,0);
  fs.writeFileSync(filename,Buffer.concat(chunks.slice(0,-1).map(chunk=>gzipSync(JSON.stringify(chunk)+'\n'))));
  const result=run('check','--expected-records=4','--expected-last-sha256='+chunks.at(-1).sha256);
  assert.notEqual(result.status,0);assert.equal(result.stdout,'');
});
