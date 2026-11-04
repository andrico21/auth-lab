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
const runtime={python:'3.14.4',uv:'0.12.10',platform:'Linux',machine:'x86_64',packages:{dnspython:'2.9.0',cryptography:'50.0.0',cffi:'2.1.1',pycparser:'3.12'}};

// Each test has a private miniature captured repository. No committed artifact,
// retained venv, network, package manager or installed crypto module is touched.
function withBundle(run){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'dnssec-current-offline-'));
  const tools=path.join(root,relativeTools);
  fs.mkdirSync(tools,{recursive:true});
  for(const name of ['run.py','historical_inputs.py','license_binding.py'])fs.copyFileSync(path.join(repository,relativeTools,name),path.join(tools,name));
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
  put('tools/verification/dnssec-crypto/requirements.txt',fs.readFileSync(path.join(root,requirements.path)));
  const frozen=put('docs/frozen.txt','original frozen payload\n');
  const authority=put('docs/dnssec-expansion/contract-freeze.json',JSON.stringify({inputs:[frozen]}));
  const final=put('docs/dnssec-expansion/numeric/FINAL-CONTENTS.json',JSON.stringify({files:[frozen]}));
  const profile={schemaVersion:1,kind:'dnssec-current-offline-crypto-profile',runtime:structuredClone(runtime),requirements,packages,historical:{authorities:[authority,final],files:[frozen]}};
  const save=()=>fs.writeFileSync(path.join(tools,'profile.json'),JSON.stringify(profile));
  const check=()=>{save();return spawnSync('python3',['-B',path.join(tools,'run.py'),'--check'],{encoding:'utf8',env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});};
  try{run({root,tools,put,profile,check,save});}finally{fs.rmSync(root,{recursive:true,force:true});}
}

function withCapturedLicense(run){
  return withBundle(bundle=>{
    const {put,profile}=bundle;
    const data=Buffer.from('captured upstream ISC license\n');
    const upstreamBlob=createHash('sha1').update(Buffer.from(`blob ${data.length}\0`)).update(data).digest('hex');
    const upstreamTree='a'.repeat(40);
    const treeMetadata=put('bundle/dnspython-upstream-tree.json',JSON.stringify({sha:upstreamTree,truncated:false,tree:[{path:'LICENSE',type:'blob',sha:upstreamBlob}]}));
    const license={...put('bundle/dnspython-LICENSE.txt',data),upstreamBlob,upstreamTree,treeMetadata};
    profile.packages[0].license=license;
    run({...bundle,license});
  });
}

function withArchivedRequirements(run){
  return withBundle(bundle=>{
    const {put,profile}=bundle;
    const originalPath='tools/verification/dnssec-crypto/requirements.txt';
    const originalText='dnspython==2.8.0\ncryptography==46.0.3\n';
    const original=put(originalPath,originalText);
    const snapshot=put('docs/history/requirements.input.txt',originalText);
    put(originalPath,fs.readFileSync(path.join(bundle.root,profile.requirements.path)));
    profile.historical.requirementsBefore={originalPath,...snapshot};
    profile.historical.files.push(original);
    profile.historical.authorities[0]=put('docs/dnssec-expansion/contract-freeze.json',JSON.stringify({inputs:profile.historical.files}));
    profile.historical.authorities[1]=put('docs/dnssec-expansion/numeric/FINAL-CONTENTS.json',JSON.stringify({files:profile.historical.files}));
    run(bundle);
  });
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

test('offline bundle rejects a substituted separately captured upstream license',()=>withBundle(({root,put,profile,check})=>{
  profile.packages[0].license=put('bundle/dnspython-LICENSE.txt','captured upstream ISC license\n');
  fs.appendFileSync(path.join(root,profile.packages[0].license.path),'changed license');
  rejects(check(),/hash\/size mismatch: bundle\/dnspython-LICENSE\.txt/);
}));

test('offline bundle rejects a rehashed replacement license not belonging to the upstream blob',()=>withCapturedLicense(({put,license,check})=>{
  Object.assign(license,put(license.path,'different locally approved license\n'));
  rejects(check(),/Upstream license blob mismatch/);
}));

for(const boundary of ['tree identity','LICENSE blob']){
  test(`offline bundle rejects rehashed upstream metadata with the wrong ${boundary}`,()=>withCapturedLicense(({root,put,license,check})=>{
    const tree=JSON.parse(fs.readFileSync(path.join(root,license.treeMetadata.path),'utf8'));
    if(boundary==='tree identity')tree.sha='f'.repeat(40);
    else tree.tree[0].sha='f'.repeat(40);
    license.treeMetadata=put(license.treeMetadata.path,JSON.stringify(tree));
    rejects(check(),/Upstream license tree mismatch/);
  }));
}

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

test('offline bundle rejects the affected dnspython version before setup',()=>withBundle(({profile,check})=>{
  profile.runtime.packages.dnspython='2.8.0';
  rejects(check(),/Unsupported runtime\/package pins/);
}));

test('offline bundle rejects legacy live pins drifting independently of the patched active profile',()=>withBundle(({put,check})=>{
  put('tools/verification/dnssec-crypto/requirements.txt','dnspython==2.8.0\ncryptography==46.0.3\n');
  rejects(check(),/hash\/size mismatch: tools\/verification\/dnssec-crypto\/requirements\.txt/);
}));

test('offline bundle rejects frozen payload drift',()=>withBundle(({root,profile,check})=>{
  fs.writeFileSync(path.join(root,profile.historical.files[0].path),'changed frozen payload\n');
  rejects(check(),/hash\/size mismatch: docs\/frozen.txt/);
}));

test('offline bundle rejects historical inventory shrinkage even if remaining identities validate',()=>withBundle(({profile,put,check})=>{
  profile.historical.files=[put('docs/unrelated.txt','unrelated')];
  rejects(check(),/Historical authority reference missing\/mismatched: docs\/frozen.txt/);
}));

test('patched live requirements coexist with the exact archived frozen requirement identity',()=>withArchivedRequirements(({root,profile,check})=>{
  const result=check();
  assert.ifError(result.error);
  assert.equal(result.status,0,`${result.stdout}\n${result.stderr}`);
  const before=profile.historical.requirementsBefore;
  assert.notEqual(fs.readFileSync(path.join(root,before.originalPath),'utf8'),fs.readFileSync(path.join(root,before.path),'utf8'));
  assert.equal(createHash('sha256').update(fs.readFileSync(path.join(root,before.path))).digest('hex'),profile.historical.files[1].sha256);
}));

test('historical checks reject tampered archived requirements even when live pins are patched',()=>withArchivedRequirements(({root,profile,check})=>{
  fs.appendFileSync(path.join(root,profile.historical.requirementsBefore.path),'substituted history');
  rejects(check(),/hash\/size mismatch: .*requirements\.input\.txt/);
}));

test('historical checks reject a snapshot rehashed away from the original frozen identity',()=>withArchivedRequirements(({put,profile,check})=>{
  const before=profile.historical.requirementsBefore;
  profile.historical.requirementsBefore={originalPath:before.originalPath,...put(before.path,'dnspython==2.9.0\ncryptography==50.0.0\n')};
  rejects(check(),/Historical requirements snapshot differs from frozen identity/);
}));

test('historical checks do not fall back to the changed live requirements when the snapshot is absent',()=>withArchivedRequirements(({profile,check})=>{
  delete profile.historical.requirementsBefore;
  rejects(check(),/Missing exact historical requirements snapshot/);
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
  const code=`import importlib.util, os, pathlib, sys\nsys.path.insert(0, ${JSON.stringify(tools)})\nspec=importlib.util.spec_from_file_location('offline_runner', ${JSON.stringify(path.join(tools,'run.py'))})\nm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\nout=pathlib.Path(${JSON.stringify(out)}); out.mkdir()\ntry:\n m.capture(out, 'setup-uv-version', [${JSON.stringify(path.join(outside,'missing-uv'))}, '--version'], dict(os.environ))\nexcept ValueError:\n raise SystemExit(1)\n`;
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
