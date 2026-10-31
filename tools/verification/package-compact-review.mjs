#!/usr/bin/env bun
// Explicit payload only. Packaging integrity is not functional or reviewer acceptance.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {captureReviewInputs} from './review-input-identity.mjs';
import {captureInputs} from './compact-mobile-browser.mjs';

const self=fileURLToPath(import.meta.url), helper=path.join(path.dirname(self),'compact-review-archive.py');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=message=>{throw new Error(message);};
function regular(filename, directory=false) {
  const absolute=path.resolve(filename), parsed=path.parse(absolute);
  let current=parsed.root;
  const parts=absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  for(let i=0;i<parts.length;i++) {
    current=path.join(current,parts[i]);
    const s=fs.lstatSync(current);
    if(s.isSymbolicLink() || (i<parts.length-1 || directory ? !s.isDirectory() : !s.isFile())) fail('Unsafe filesystem path: '+current);
  }
  return absolute;
}
function safe(name) {
  if(typeof name!=='string'||!name||name.includes('\\')||name.includes(':')||/[\x00-\x1f\x7f]/.test(name)||path.posix.isAbsolute(name)||name.split('/').some(p=>!p||['.','..','.git'].includes(p))) fail('Unsafe archive member: '+name);
  return name;
}
function fresh(filename, directory=false) {
  regular(path.dirname(filename),true);
  if(fs.existsSync(filename)||fs.lstatSync(path.dirname(filename)).isSymbolicLink()) fail('Output already exists: '+filename);
  if(directory) fs.mkdirSync(filename); else fs.writeFileSync(filename,'',{flag:'wx'});
}
function within(a,b) {const r=path.relative(a,b);return r===''||(!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));}
const args={};
for(const arg of process.argv.slice(2)) {const m=/^--(root|manifest|html|start|out|verify-dir|receipt|bun)=(.+)$/.exec(arg);if(!m||args[m[1]])fail('Expected unique --root/manifest/html/start/out/verify-dir/receipt/bun=PATH');args[m[1]]=path.resolve(m[2]);}
for(const key of ['root','manifest','html','start','out','verify-dir','receipt','bun'])if(!args[key])fail('Missing --'+key);
regular(args.root,true);
for(const key of ['out','verify-dir','receipt'])if(within(args.root,args[key]))fail(key+' must be external to source root');
if(within(args.out,args['verify-dir'])||within(args['verify-dir'],args.out)||within(args.out,args.receipt)||within(args['verify-dir'],args.receipt))fail('Output, verification directory and receipt must be disjoint');
for(const key of ['manifest','html','start','bun'])regular(args[key]);
fresh(args.receipt);
const report={schemaVersion:1,kind:'compact-review-packaging',passed:false,acceptance:'Packaging integrity only; no independent functional acceptance or publication.',started:new Date().toISOString(),arguments:args,runnerSha256:hash(fs.readFileSync(self)),helperSha256:hash(fs.readFileSync(helper)),commands:[],checks:{}};
const save=()=>fs.writeFileSync(args.receipt,JSON.stringify(report,null,2)+'\n');
try {
  fresh(args.out,true);fresh(args['verify-dir'],true);
  const stage=path.join(args['verify-dir'],'stage');fs.mkdirSync(stage);
  const run=(command,argv,cwd,label,env=process.env)=>{
    const result=spawnSync(command,argv,{cwd,env,encoding:'utf8',maxBuffer:64*1024*1024});
    const log=path.join(args['verify-dir'],label+'.log');
    const bytes=Buffer.from((result.stdout||'')+(result.stderr||'')+(result.error?'\n'+String(result.error):''));fs.writeFileSync(log,bytes,{flag:'wx'});
    report.commands.push({command:[command,...argv],cwd,exit:result.status,signal:result.signal,log,logSha256:hash(bytes),environment:label==='rebuild'?env:undefined});save();
    if(result.error||result.status!==0)fail(label+' failed; see '+log);
    return result.stdout.trim();
  };
  const version=run(args.bun,['--version'],args.root,'bun-version');
  if(version!=='1.4.3')fail('Pinned Bun 1.4.3 required, received '+version);
  const manifestBytes=fs.readFileSync(args.manifest), manifest=JSON.parse(manifestBytes);
  report.manifestSha256=hash(manifestBytes);
  if(manifest.schemaVersion!==1||manifest.kind!=='compact-review-payload'||!Array.isArray(manifest.entries))fail('Invalid manifest schema');
  const identity=captureReviewInputs(args.root,self);report.inputIdentity=identity;
  const names=new Set(), folded=new Set(), entries=[], originals=[];
  for(const item of manifest.entries) {
    const name=safe(item.path);if(name.toLowerCase()==='review/sha256sums'||names.has(name)||folded.has(name.toLowerCase()))fail('Reserved or duplicate member: '+name);
    if(!name.startsWith('source/')&&!name.startsWith('review/'))fail('Members must use source/ or review/: '+name);
    names.add(name);folded.add(name.toLowerCase());
    if(typeof item.source!=='string')fail('Missing explicit source');
    const source=regular(path.resolve(args.root,item.source));
    if(source.split(path.sep).includes('.git'))fail('Git input forbidden');
    const data=fs.readFileSync(source), entry={path:name,bytes:data.length,sha256:hash(data)};
    const target=path.join(stage,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,data,{flag:'wx'});
    entries.push(entry); originals.push({source,...entry});
  }
  const required={...identity.sourceFiles,'docs/next-expansion/scenario-manifest.json':identity.manifestSha256};
  for(const [name,sha] of Object.entries(required))if(!entries.some(e=>e.path==='source/'+name&&e.sha256===sha))fail('Missing exact canonical source/'+name);
  const deliveredDist=entries.find(e=>e.path==='source/dist/auth-flow-studio.html');
  if(deliveredDist&&deliveredDist.sha256!==identity.standaloneSha256)fail('Optional source/dist must match canonical standalone');
  const html=fs.readFileSync(args.html);if(hash(html)!==identity.standaloneSha256)fail('Standalone differs from canonical dist');
  const canonicalIdentity=captureInputs(args.root),canonicalSha256=canonicalIdentity.canonicalSha256;
  report.canonicalSourceSha256=canonicalSha256;report.sourceAlgorithm=canonicalIdentity.sourceAlgorithm;
  report.sourceFileMapSha256=hash(Buffer.from(JSON.stringify(identity.sourceFiles)));
  const zipName='auth-flow-studio-compact-source-and-review.zip', htmlName='auth-flow-studio-compact.html';
  const startBytes=fs.readFileSync(args.start);report.startTemplateSha256=hash(startBytes);
  if(startBytes.toString('utf8').includes('{{REVIEW_ZIP_SHA256}}'))fail('START cannot contain the ZIP hash: its checksum is bound inside the ZIP');
  const start=startBytes.toString('utf8').replaceAll('{{STANDALONE_SHA256}}',hash(html)).replaceAll('{{SOURCE_CANONICAL_SHA256}}',canonicalSha256);
  if(/\{\{[^}]+\}\}/.test(start))fail('Unresolved START template placeholder');
  const contentsName='CONTENTS.json';
  const contents={
    schemaVersion:1,kind:'compact-review-contents',
    source:{prefix:'source/',algorithm:canonicalIdentity.sourceAlgorithm,sha256:canonicalSha256,files:canonicalIdentity.sources},
    standalone:{path:htmlName,bytes:html.length,sha256:hash(html)},
    entrypoint:{path:'START-HERE.md',bytes:Buffer.byteLength(start),sha256:hash(Buffer.from(start))},
    files:entries.slice().sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0),
    omitted:manifest.omitted||[],
    checksum:{path:'review/SHA256SUMS',excluded:[contentsName,'review/SHA256SUMS'],binding:'The external checksum binds the final ZIP; the internal checksum binds payloads and the two companion uploads without a self-reference.'},
    acceptance:report.acceptance
  };
  const contentsBytes=Buffer.from(JSON.stringify(contents,null,2)+'\n');
  fs.writeFileSync(path.join(stage,contentsName),contentsBytes,{flag:'wx'});
  const sums=entries.slice().sort((a,b)=>a.path<b.path?-1:1).map(e=>e.sha256+'  '+e.path+'\n').join('')+hash(html)+'  '+htmlName+'\n'+hash(Buffer.from(start))+'  START-HERE.md\n';
  const checksumPath=path.join(stage,'review/SHA256SUMS');fs.mkdirSync(path.dirname(checksumPath),{recursive:true});fs.writeFileSync(checksumPath,sums,{flag:'wx'});
  entries.push({path:'review/SHA256SUMS',bytes:Buffer.byteLength(sums),sha256:hash(Buffer.from(sums))});
  entries.push({path:contentsName,bytes:contentsBytes.length,sha256:hash(contentsBytes)});
  const descriptor=path.join(args['verify-dir'],'inventory.json');fs.writeFileSync(descriptor,JSON.stringify({entries},null,2)+'\n',{flag:'wx'});report.inventorySha256=hash(fs.readFileSync(descriptor));
  const zip=path.join(args.out,zipName), extracted=path.join(args['verify-dir'],'extracted');
  run('python3',[helper,'create',descriptor,zip,stage],args.root,'archive');report.checks.archive=true;
  run('python3',[helper,'extract',descriptor,zip,extracted],args.root,'extract');report.checks.inventoryAndEveryExtractedByte=true;
  fs.writeFileSync(path.join(args.out,htmlName),html,{flag:'wx'});
  fs.writeFileSync(path.join(extracted,htmlName),html,{flag:'wx'});
  fs.writeFileSync(path.join(extracted,'START-HERE.md'),start,{flag:'wx'});
  fs.writeFileSync(path.join(args.out,'START-HERE.md'),start,{flag:'wx'});
  const external=[zipName,htmlName,'START-HERE.md'].map(name=>hash(fs.readFileSync(path.join(args.out,name)))+'  '+name+'\n').join('');
  fs.writeFileSync(path.join(args.out,'SHA256SUMS'),external,{flag:'wx'});
  function checkSums(base,text) {for(const line of text.trimEnd().split('\n')) {const m=/^([a-f0-9]{64})  (.+)$/.exec(line);if(!m||hash(fs.readFileSync(regular(path.join(base,safe(m[2])))))!==m[1])fail('Checksum mismatch: '+line);}}
  checkSums(extracted,fs.readFileSync(path.join(extracted,'review/SHA256SUMS'),'utf8'));checkSums(args.out,fs.readFileSync(path.join(args.out,'SHA256SUMS'),'utf8'));report.checks.internalAndExternalChecksums=true;
  const sourceRoot=path.join(extracted,'source');
  const before=()=>{
    const result={};
    const walk=(directory,prefix)=>{
      for(const entry of fs.readdirSync(directory,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)) {
        const filename=path.join(directory,entry.name),name=prefix+'/'+entry.name;
        if(entry.isDirectory()) {regular(filename,true);walk(filename,name);}
        else if(name!=='source/dist/auth-flow-studio.html') result[name]=hash(fs.readFileSync(regular(filename)));
      }
    };
    walk(sourceRoot,'source');return result;
  };
  const snapshot=before();
  const bin=path.join(args['verify-dir'],'bin');fs.mkdirSync(bin);fs.symlinkSync(args.bun,path.join(bin,'bun'));
  // Minimal environment: no inherited preload, version override, registry credentials or install configuration.
  const env={PATH:bin,HOME:args['verify-dir'],TMPDIR:args['verify-dir'],BUN_INSTALL_AUTO:'disable',BUN_BE_BUN:'1',LANG:'C.UTF-8',TZ:'UTC'};
  run(args.bun,['run','build','--source-version'],sourceRoot,'rebuild',env);
  if(hash(fs.readFileSync(regular(path.join(sourceRoot,'dist/auth-flow-studio.html'))))!==hash(html))fail('Extracted rebuild HTML differs');
  if(JSON.stringify(snapshot)!==JSON.stringify(before()))fail('Extracted source payload mutated by build');
  report.checks.offlinePinnedRebuild=true;report.checks.byteIdenticalHTML=true;report.checks.extractedSourceUnchanged=true;
  const extractedIdentity=captureInputs(sourceRoot);
  if(extractedIdentity.canonicalSha256!==canonicalSha256||JSON.stringify(extractedIdentity.sources)!==JSON.stringify(canonicalIdentity.sources))fail('Extracted canonical source identity differs');
  report.extractedCanonicalSourceSha256=extractedIdentity.canonicalSha256;report.checks.extractedCanonicalIdentity=true;
  for(const e of originals)if(hash(fs.readFileSync(regular(e.source)))!==e.sha256)fail('Original payload changed: '+e.source);
  if(hash(fs.readFileSync(args.manifest))!==report.manifestSha256||hash(fs.readFileSync(args.start))!==report.startTemplateSha256||hash(fs.readFileSync(args.html))!==hash(html))fail('Packaging inputs changed');
  const finalIdentity=captureReviewInputs(args.root,self);if(JSON.stringify(identity)!==JSON.stringify(finalIdentity))fail('Canonical input identity changed');
  checkSums(args.out,external);
  if(fs.readdirSync(args.out).sort().join('\n')!==[zipName,htmlName,'START-HERE.md','SHA256SUMS'].sort().join('\n'))fail('Unexpected upload-folder files');
  report.checks.originalInputsUnchanged=true;report.outputs=Object.fromEntries(fs.readdirSync(args.out).sort().map(name=>[name,{bytes:fs.statSync(path.join(args.out,name)).size,sha256:hash(fs.readFileSync(path.join(args.out,name)))}]));
  report.offlineScope='No install command; automatic installs disabled. OS network denial was not enforced.';
  report.passed=true;
} catch(error) {report.error=String(error?.stack||error);process.exitCode=1;}
finally {report.finished=new Date().toISOString();save();}
console.log(JSON.stringify({passed:report.passed,receipt:args.receipt,error:report.error||null}));
