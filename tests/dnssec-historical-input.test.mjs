import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {historicalInputPath} from '../tools/verification/dnssec-historical-input.mjs';

const repository=fileURLToPath(new URL('../',import.meta.url));
const input={path:'tools/verification/dnssec-crypto/requirements.txt',bytes:382,sha256:'24c62a92f1a8992f2469ba6cf381a8d07e4c21ae0e058592c596221947b6fd41'};
const before={originalPath:input.path,path:'docs/dnssec-expansion/numeric/runtime-50.0.0-dnspython-2.9.0/inputs/legacy-pins.input',bytes:input.bytes,sha256:input.sha256};
const profilePath='tools/verification/dnssec-crypto-current/profile.json';
function fixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'dnssec-historical-input-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const put=(name,bytes)=>{const file=path.join(root,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,bytes);return file;};
  const profile={historical:{requirementsBefore:{...before}}};
  const save=()=>put(profilePath,JSON.stringify(profile));
  save();
  put(before.path,fs.readFileSync(path.join(repository,before.path)));
  put(input.path,'dnspython==2.9.2\ncryptography==50.0.2\n');
  return {root,put,profile,save};
}

test('only the exact original requirement resolves to verified retained bytes, not the current manifest',t=>{
  const {root,put}=fixture(t);
  assert.equal(historicalInputPath(root,input),path.join(root,before.path));
  assert.notDeepEqual(fs.readFileSync(path.join(root,input.path)),fs.readFileSync(historicalInputPath(root,input)));
  const other={path:'tools/verification/dnssec-crypto-current/requirements.txt',bytes:input.bytes,sha256:input.sha256};
  put(other.path,'independent current manifest');
  assert.equal(historicalInputPath(root,other),path.join(root,other.path));
});

test('a missing retained requirement is rejected even when the live file exists',t=>{
  const {root}=fixture(t);
  fs.unlinkSync(path.join(root,before.path));
  assert.throws(()=>historicalInputPath(root,input),/ENOENT/);
});

for(const sameLength of [true,false])test(`tampered retained bytes are rejected (${sameLength?'same':'different'} length)`,t=>{
  const {root,put}=fixture(t);
  const bytes=fs.readFileSync(path.join(root,before.path));
  if(sameLength){bytes[0]^=1;put(before.path,bytes);}else put(before.path,Buffer.concat([bytes,Buffer.from('\n')]));
  assert.throws(()=>historicalInputPath(root,input),/Frozen historical requirements changed/);
});

for(const [field,value] of [['originalPath','tools/verification/dnssec-crypto-current/requirements.txt'],['path','../outside.txt'],['bytes',381],['sha256','0'.repeat(64)],['unexpected',true]])test(`wrong historical descriptor ${field} is rejected`,t=>{
  const {root,profile,save}=fixture(t);
  profile.historical.requirementsBefore[field]=value;save();
  assert.throws(()=>historicalInputPath(root,input),/Wrong historical requirementsBefore binding/);
});

test('missing historical descriptor and profile are rejected',t=>{
  const {root,profile,save}=fixture(t);
  delete profile.historical.requirementsBefore;save();
  assert.throws(()=>historicalInputPath(root,input),/Wrong historical requirementsBefore binding/);
  fs.unlinkSync(path.join(root,profilePath));
  assert.throws(()=>historicalInputPath(root,input),/ENOENT/);
});

test('a changed frozen identity cannot authorize another retained hash or byte count',t=>{
  const {root}=fixture(t);
  for(const wrong of [{...input,bytes:381},{...input,sha256:'0'.repeat(64)}])assert.throws(()=>historicalInputPath(root,wrong),/Wrong frozen historical requirements identity/);
});

test('symlinked retained bytes and unsafe historical paths are rejected',t=>{
  const {root,put}=fixture(t);
  const target=put('copy.txt',fs.readFileSync(path.join(root,before.path)));
  fs.unlinkSync(path.join(root,before.path));fs.symlinkSync(target,path.join(root,before.path));
  assert.throws(()=>historicalInputPath(root,input),/not a regular file/);
  for(const name of ['../outside.txt','/etc/passwd','tools/../copy.txt','tools\\copy.txt'])assert.throws(()=>historicalInputPath(root,{path:name}),/Unsafe historical input path/);
});
