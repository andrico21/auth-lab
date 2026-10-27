import test, {describe} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const repository=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const relativeTools='tools/verification/dnssec-crypto-current';
const runtime={python:'3.14.4',uv:'0.12.10',platform:'Linux',machine:'x86_64',packages:{dnspython:'2.8.0',cryptography:'50.0.0',cffi:'2.1.1',pycparser:'3.12'}};

// Each test has a private miniature captured repository. No committed artifact,
// retained venv, network, package manager or installed crypto module is touched.
function withBundle(run){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'dnssec-current-offline-'));
  const tools=path.join(root,relativeTools);
  fs.mkdirSync(tools,{recursive:true});
  fs.copyFileSync(path.join(repository,relativeTools,'run.py'),path.join(tools,'run.py'));
  function put(name,content){
    const bytes=Buffer.from(content);
    fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});
    fs.writeFileSync(path.join(root,name),bytes);
    return {path:name,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};
  }
  const packages=Object.entries(runtime.packages).map(([name,version])=>{
    const base=`bundle/${name}-${version}`;
    const wheel={...put(`${base}-py3-none-any.whl`,`${name} wheel captured bytes`),url:`https://files.pythonhosted.org/${name}-${version}-py3-none-any.whl`};
    const source={...put(`${base}.tar.gz`,`${name} source captured bytes`),url:`https://files.pythonhosted.org/${name}-${version}.tar.gz`};
    const metadata={...put(`${base}.json`,JSON.stringify({info:{name,version},urls:[['bdist_wheel',wheel],['sdist',source]].map(([packagetype,artifact])=>({filename:path.basename(artifact.path),digests:{sha256:artifact.sha256},size:artifact.bytes,url:artifact.url,packagetype,yanked:false}))})),url:`https://pypi.org/pypi/${name}/${version}/json`};
    return {name,version,wheel,source,metadata};
  });
  const requirements=put(`${relativeTools}/requirements.txt`,packages.map(p=>`${p.name}==${p.version} --hash=sha256:${p.wheel.sha256}\n`).join(''));
  const frozen=put('docs/frozen.txt','original frozen payload\n');
  const authority=put('docs/dnssec-expansion/contract-freeze.json',JSON.stringify({inputs:[frozen]}));
  const final=put('docs/dnssec-expansion/numeric/FINAL-CONTENTS.json',JSON.stringify({files:[frozen]}));
  const profile={schemaVersion:1,kind:'dnssec-current-offline-crypto-profile',runtime:structuredClone(runtime),requirements,packages,historical:{authorities:[authority,final],files:[frozen]}};
  const save=()=>fs.writeFileSync(path.join(tools,'profile.json'),JSON.stringify(profile));
  const check=()=>{save();return spawnSync('python3',['-B',path.join(tools,'run.py'),'--check'],{encoding:'utf8',env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});};
  try{run({root,tools,put,profile,check,save});}finally{fs.rmSync(root,{recursive:true,force:true});}
}
function rejects(result,pattern){
  assert.ifError(result.error);
  assert.equal(result.status,1,`${result.stdout}\n${result.stderr}`);
  assert.match(result.stderr,pattern);
}

describe('Linux x86_64 offline crypto profile',{skip:process.platform!=='linux'||process.arch!=='x64'},()=>{

test('offline bundle rejects a missing cryptography 50 wheel before setup',()=>withBundle(({root,profile,check})=>{
  fs.unlinkSync(path.join(root,profile.packages.find(p=>p.name==='cryptography').wheel.path));
  rejects(check(),/Missing bundled file: .*cryptography-50/);
}));

test('offline bundle rejects artifact tampering even when filename and pinned version remain plausible',()=>withBundle(({root,profile,check})=>{
  fs.appendFileSync(path.join(root,profile.packages[1].wheel.path),'changed wheel');
  rejects(check(),/hash\/size mismatch: .*cryptography-50/);
}));

test('offline bundle rejects requirement hash disagreement with the captured wheel',()=>withBundle(({put,profile,check})=>{
  profile.requirements=put(profile.requirements.path,profile.packages.map(p=>`${p.name}==${p.version} --hash=sha256:${p.name==='cryptography'?'0'.repeat(64):p.wheel.sha256}\n`).join(''));
  rejects(check(),/Requirement\/wheel hash disagreement: cryptography/);
}));

test('offline bundle rejects a locally rehashed wheel which is not the captured upstream artifact',()=>withBundle(({put,profile,check})=>{
  const pkg=profile.packages[1];
  pkg.wheel={...pkg.wheel,...put(pkg.wheel.path,'substituted locally rehashed wheel')};
  profile.requirements=put(profile.requirements.path,profile.packages.map(p=>`${p.name}==${p.version} --hash=sha256:${p.wheel.sha256}\n`).join(''));
  rejects(check(),/Artifact\/upstream metadata disagreement/);
}));

test('offline bundle rejects a wheel for an incompatible Python ABI',()=>withBundle(({put,profile,check})=>{
  const pkg=profile.packages[1];
  pkg.wheel={...pkg.wheel,...put(pkg.wheel.path.replace('py3-none-any','cp315-cp315-any'),'future interpreter wheel')};
  profile.requirements=put(profile.requirements.path,profile.packages.map(p=>`${p.name}==${p.version} --hash=sha256:${p.wheel.sha256}\n`).join(''));
  rejects(check(),/Incompatible CPython 3.14 wheel/);
}));

test('offline bundle rejects upstream Python compatibility incompatible with the pinned interpreter',()=>withBundle(({root,put,profile,check})=>{
  const pkg=profile.packages[1];
  const metadata=JSON.parse(fs.readFileSync(path.join(root,pkg.metadata.path),'utf8'));
  metadata.info.requires_python='>=3.15';
  pkg.metadata={...pkg.metadata,...put(pkg.metadata.path,JSON.stringify(metadata))};
  rejects(check(),/Incompatible Requires-Python declaration/);
}));

test('offline bundle rejects stale cryptography pins rather than accepting an old offline environment',()=>withBundle(({profile,check})=>{
  profile.runtime.packages.cryptography='46.0.3';
  rejects(check(),/Unsupported runtime\/package pins/);
}));

test('offline bundle rejects frozen payload drift',()=>withBundle(({root,profile,check})=>{
  fs.writeFileSync(path.join(root,profile.historical.files[0].path),'changed frozen payload\n');
  rejects(check(),/hash\/size mismatch: docs\/frozen.txt/);
}));

test('offline bundle rejects historical inventory shrinkage even if remaining identities validate',()=>withBundle(({profile,put,check})=>{
  profile.historical.files=[put('docs/unrelated.txt','unrelated')];
  rejects(check(),/Historical authority reference missing\/mismatched: docs\/frozen.txt/);
}));

test('bootstrap preserves existing outputs without invoking setup',()=>withBundle(({root,tools,profile,save})=>{
  save();
  const out=fs.mkdtempSync(path.join(os.tmpdir(),'dnssec-existing-output-'));
  try{
    fs.writeFileSync(path.join(out,'sentinel'),'keep retained environment');
    const result=spawnSync('python3',['-B',path.join(tools,'run.py'),'--out',out],{encoding:'utf8'});
    rejects(result,/Output already exists/);
    assert.equal(fs.readFileSync(path.join(out,'sentinel'),'utf8'),'keep retained environment');
    assert.deepEqual(fs.readdirSync(out),['sentinel']);
  }finally{fs.rmSync(out,{recursive:true,force:true});}
}));

test('missing setup executable preserves its actual OS error before failing',()=>withBundle(({tools})=>{
  const outside=fs.mkdtempSync(path.join(os.tmpdir(),'dnssec-setup-failure-'));
  const out=path.join(outside,'new-output');
  const code=`import importlib.util, os, pathlib\nspec=importlib.util.spec_from_file_location('offline_runner', ${JSON.stringify(path.join(tools,'run.py'))})\nm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\nout=pathlib.Path(${JSON.stringify(out)}); out.mkdir()\ntry:\n m.capture(out, 'setup-uv-version', [${JSON.stringify(path.join(outside,'missing-uv'))}, '--version'], dict(os.environ))\nexcept ValueError:\n raise SystemExit(1)\n`;
  try{
    const result=spawnSync('python3',['-B','-c',code],{encoding:'utf8'});
    assert.ifError(result.error);
    assert.equal(result.status,1,result.stderr);
    const receipt=JSON.parse(fs.readFileSync(path.join(out,'setup-uv-version.json'),'utf8'));
    assert.equal(receipt.exitCode,127);
    assert.match(receipt.stderr,/No such file/);
  }finally{fs.rmSync(outside,{recursive:true,force:true});}
}));

});
