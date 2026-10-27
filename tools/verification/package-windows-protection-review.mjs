#!/usr/bin/env bun
// Explicit compact packaging only. Evidence is copied, never regenerated or accepted.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const runner = fileURLToPath(import.meta.url);
const ZIP = 'auth-flow-studio-windows-protection-source-and-review.zip';
const HTML = 'auth-flow-studio-windows-protection.html';
const INNER_SUMS = 'review/SHA256SUMS';
const usage = `Usage: bun tools/verification/package-windows-protection-review.mjs --root=PATH --manifest=FILE --entrypoint=FILE --out=NEW_EXTERNAL_DIRECTORY
Requires pinned Bun 1.4.2 and existing zip/unzip binaries. FILE paths are root-relative.
Manifest schemaVersion:1:
  candidate:{sourceIdentity:{algorithm:'sha256-path-nul-bytes-nul-v1',sha256,files:{relativePath:sha256}},standalone:{path,sha256,bytes},sourceVersion:'1.0'},
  source:[{path,sha256,bytes}], review:[{path,member,sha256,bytes}],
  frozenInputs:[{path,sha256,bytes}], omitted:[{path,sha256,bytes,reason}], openConditions:[...]
review.member must start review/; source members are source/<path>. All membership is explicit.
Source must contain all canonical app/test inputs plus this packager. Curate build support docs explicitly.
Emits exactly ZIP, exact HTML, START-HERE.md, SHA256SUMS.txt, packaging-status.json.
Three uploads: ${ZIP}, ${HTML}, START-HERE.md.
Performs only inventory/hash checks and one extracted-source offline build:
  bun --no-install build.mjs --source-version
No tests, browser runs, timing reruns, installation or acceptance/publication claims.
CONTENTS.json inventories all ZIP payloads except itself (self-reference excluded explicitly).
review/SHA256SUMS binds every selected payload, the standalone and START-HERE.
It excludes itself and CONTENTS.json. The exact package manifest is included as review/PACKAGING-INPUT.json.
SHA256SUMS.txt covers four sibling files except itself; status checksums exclude itself and SHA256SUMS.txt.
ZIP target is below 10 MiB; oversized required inputs are retained with a warning.
On error, output and owned Linux stage are preserved with failed status; use a new output leaf.`;
const assert = (ok, message) => { if (!ok) throw new Error(message); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const inside = (base, name) => name === base || name.startsWith(base + path.sep);
function relative(name) {
  assert(typeof name === 'string' && name && !name.startsWith('-') && !/[\\\x00-\x1f\x7f]/.test(name) && !path.isAbsolute(name) && name.split('/').every(p => p && p !== '.' && p !== '..'), 'Unsafe relative path: '+name);
  return name;
}
function inspect(filename, directory = false) {
  let cursor = path.parse(filename).root;
  for (const part of filename.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    assert(!fs.lstatSync(cursor).isSymbolicLink(), 'Symlink refused: '+cursor);
  }
  const stat = fs.lstatSync(filename);
  assert(directory ? stat.isDirectory() : stat.isFile(), 'Special/wrong file type: '+filename);
  return stat;
}
function walk(base, prefix = '', canonical = false) {
  const result = [];
  for (const entry of fs.readdirSync(path.join(base,prefix), {withFileTypes:true})) {
    if (canonical && ['.git','node_modules'].includes(entry.name)) continue;
    const name = relative(prefix ? prefix+'/'+entry.name : entry.name);
    assert(!entry.isSymbolicLink(), 'Symlink refused: '+name);
    if (entry.isDirectory()) result.push(...walk(base,name,canonical));
    else { assert(entry.isFile(), 'Special file refused: '+name); result.push(name); }
  }
  return result.sort();
}
function identity(base) {
  const names = ['index.html','build.mjs','security-policy.mjs','package.json', ...['assets','src','tests'].flatMap(dir => {
    inspect(path.join(base,dir),true);
    return walk(path.join(base,dir),'',true).map(name => dir+'/'+name);
  })].sort();
  const digest = createHash('sha256'), files = {};
  for (const name of names) {
    inspect(path.join(base,name));
    const bytes = fs.readFileSync(path.join(base,name));
    digest.update(name+'\0'); digest.update(bytes); digest.update('\0'); files[name] = hash(bytes);
  }
  return {algorithm:'sha256-path-nul-bytes-nul-v1',sha256:digest.digest('hex'),files};
}
const equalIdentity = (a,b) => a?.algorithm === b.algorithm && a?.sha256 === b.sha256 && a.files && JSON.stringify(Object.entries(a.files).sort()) === JSON.stringify(Object.entries(b.files).sort());
function main() {
  if (process.argv.slice(2).some(arg => arg === '--help' || arg === '-h')) { console.log(usage); return; }
  const options = {};
  for (const arg of process.argv.slice(2)) {
    const match = /^--(root|manifest|entrypoint|out)=(.+)$/.exec(arg);
    assert(match && !Object.hasOwn(options,match[1]), 'Unknown/duplicate option: '+arg);
    options[match[1]] = match[2];
  }
  assert(['root','manifest','entrypoint','out'].every(key => options[key]), usage);
  const root = path.resolve(options.root); inspect(root,true);
  const output = path.resolve(options.out); inspect(path.dirname(output),true);
  assert(!inside(root,output) && !inside(output,root) && !fs.existsSync(output), 'Output must be new and external');
  fs.mkdirSync(output, {mode:0o700});
  const status = {schemaVersion:1,kind:'windows-protection-compact-review-package',status:'in-progress',actualArgv:[process.execPath,...process.argv.slice(1)],commands:[],checksums:{},checks:{},openConditions:null,publication:'No new acceptance, independent review, release, commit, push or deployment claims.'};
  let stage;
  const statusFile = path.join(output,'packaging-status.json');
  const save = () => fs.writeFileSync(statusFile,JSON.stringify(status,null,2)+'\n');
  const tracked = new Map();
  function capture(name) {
    relative(name); const file = path.join(root,name), stat = inspect(file), bytes = fs.readFileSync(file);
    const item = {path:name,sha256:hash(bytes),bytes:stat.size};
    assert(bytes.length === stat.size,'Input changed during read: '+name);
    if (tracked.has(name)) assert(JSON.stringify(tracked.get(name)) === JSON.stringify(item),'Input changed: '+name);
    tracked.set(name,item); return item;
  }
  function ref(row) {
    assert(row && typeof row === 'object','Invalid file reference');
    const actual = capture(row.path);
    assert(/^[a-f0-9]{64}$/.test(row.sha256) && actual.sha256 === row.sha256 && Number.isSafeInteger(row.bytes) && actual.bytes === row.bytes,'Hash/size mismatch: '+row.path);
    return actual;
  }
  function execute(argv,cwd,input) {
    const result = spawnSync(argv[0],argv.slice(1),{cwd,input,encoding:'utf8',maxBuffer:64*1024*1024,env:{...process.env,BUN_INSTALL_AUTO:'disable',npm_config_offline:'true'}});
    const record = {argv,cwd,exitStatus:result.status,signal:result.signal,stdout:result.stdout ?? '',stderr:result.stderr ?? '',error:result.error?.message ?? null};
    status.commands.push(record); save();
    assert(!result.error && result.status === 0,'Command failed: '+JSON.stringify(argv)); return record;
  }
  function copyInput(row,destination) {
    fs.mkdirSync(path.dirname(destination),{recursive:true});
    fs.copyFileSync(path.join(root,row.path),destination,fs.constants.COPYFILE_EXCL);
    const bytes = fs.readFileSync(destination);
    assert(bytes.length === row.bytes && hash(bytes) === row.sha256,'Input changed copying: '+row.path);
  }
  try {
    assert(process.platform === 'linux' && process.versions.bun === '1.4.2','Requires Linux and pinned current Bun 1.4.2');
    status.runtime = {bun:process.versions.bun,executable:process.execPath,executableSha256:hash(fs.readFileSync(process.execPath)),platform:process.platform,arch:process.arch};
    const manifestRef = capture(options.manifest), entrypoint = capture(options.entrypoint);
    const manifest = JSON.parse(fs.readFileSync(path.join(root,manifestRef.path),'utf8'));
    assert(manifest.schemaVersion === 1 && manifest.candidate?.sourceVersion === '1.0','Invalid manifest/sourceVersion');
    for (const key of ['source','review','frozenInputs','omitted','openConditions']) assert(Array.isArray(manifest[key]),'Missing array: '+key);
    status.openConditions = manifest.openConditions;
    status.manifest = manifestRef; status.entrypoint = entrypoint;
    const before = identity(root);
    assert(equalIdentity(manifest.candidate.sourceIdentity,before),'Incomplete/stale canonical source identity');
    status.sourceIdentity = before;
    const standalone = ref(manifest.candidate.standalone);
    const inputPaths = new Set(), members = new Set(['CONTENTS.json',INNER_SUMS]);
    const payloads = [];
    function add(row,role,member) {
      const item = ref(row); assert(!inputPaths.has(item.path),'Duplicate input membership: '+item.path); inputPaths.add(item.path);
      relative(member);
      assert(!members.has(member) && ![...members].some(other => other.startsWith(member+'/') || member.startsWith(other+'/')),'Overlapping/duplicate archive member: '+member);
      assert(item.path !== standalone.path,'Duplicate standalone payload refused');
      members.add(member); payloads.push({...item,member,role});
    }
    for (const row of manifest.source) add(row,'source','source/'+relative(row.path));
    for (const row of manifest.review) { assert(typeof row.member === 'string' && row.member.startsWith('review/'),'Review member must be under review/'); add(row,'review',row.member); }
    add(manifestRef,'packaging-manifest','review/PACKAGING-INPUT.json');
    status.frozenInputs = manifest.frozenInputs.map(row => {
      const actual = ref(row), payload = payloads.find(item => item.path === actual.path);
      assert(payload,'Frozen authority/test input is not in the upload: '+actual.path);
      return {...actual,member:payload.member};
    });
    for (const row of manifest.omitted) {
      ref(row); assert(typeof row.reason === 'string' && row.reason.trim(),'Omission requires reason');
      assert(!inputPaths.has(row.path),'Duplicate/overlapping omitted input: '+row.path); inputPaths.add(row.path);
    }
    const sourcePaths = new Set(payloads.filter(row => row.role === 'source').map(row => row.path));
    for (const name of Object.keys(before.files)) assert(sourcePaths.has(name),'Canonical source missing: '+name);
    assert(inside(root,runner) && sourcePaths.has(path.relative(root,runner).split(path.sep).join('/')),'Packager itself must be in source');
    const base = path.join(os.homedir(),'.cache');
    if (!fs.existsSync(base)) fs.mkdirSync(base,{mode:0o700});
    inspect(base,true);
    assert(fs.statSync(base).uid === process.getuid() && !inside('/mnt',base),'Stage base must be owned Linux storage');
    const filesystem = fs.statfsSync(base);
    assert(![0x01021994,0x01021997,0x53464846,0x4d44].includes(Number(filesystem.type)),'Stage base is tmpfs or Windows/network-backed storage');
    stage = fs.mkdtempSync(path.join(base,'windows-protection-review-')); fs.chmodSync(stage,0o700);
    status.stage = {path:stage,filesystemType:Number(filesystem.type)};
    const archiveRoot = path.join(stage,'payload'); fs.mkdirSync(archiveRoot);
    for (const row of payloads) copyInput(row,path.join(archiveRoot,row.member));
    const checksumRows = [...payloads.map(row => ({path:row.member,sha256:row.sha256})),{path:HTML,sha256:standalone.sha256},{path:'START-HERE.md',sha256:entrypoint.sha256}].sort((a,b)=>a.path.localeCompare(b.path));
    const checksumText = checksumRows.map(row=>row.sha256+'  '+row.path).join('\n')+'\n';
    fs.mkdirSync(path.dirname(path.join(archiveRoot,INNER_SUMS)),{recursive:true});
    fs.writeFileSync(path.join(archiveRoot,INNER_SUMS),checksumText,{flag:'wx'});
    status.inUploadChecksum = {member:INNER_SUMS,sha256:hash(Buffer.from(checksumText)),bytes:Buffer.byteLength(checksumText),entries:checksumRows.length,base:'Delivery root after extracting ZIP beside standalone and START-HERE',excluded:[INNER_SUMS,'CONTENTS.json']};
    const contents = {schemaVersion:1,base:'archive-root',payloads,frozenInputs:status.frozenInputs,inUploadChecksum:status.inUploadChecksum,omitted:manifest.omitted,openConditions:manifest.openConditions,sourceIdentity:before,selfReference:{path:'CONTENTS.json',role:'inventory',sha256:null,bytes:null,reason:'Inventory cannot contain its own hash or byte count; verified against staged bytes and ZIP checksum externally.'}};
    fs.writeFileSync(path.join(archiveRoot,'CONTENTS.json'),JSON.stringify(contents,null,2)+'\n',{flag:'wx'});
    const inventory = [...members].sort();
    const zip = path.join(output,ZIP);
    execute(['zip','-X','-9','-q',zip,'-@'],archiveRoot,inventory.join('\n')+'\n');
    const listing = execute(['unzip','-Z1',zip],stage).stdout.trimEnd().split('\n');
    assert(JSON.stringify(listing.slice().sort()) === JSON.stringify(inventory),'Actual ZIP inventory mismatch/duplicates');
    const extracted = path.join(stage,'extracted'); fs.mkdirSync(extracted);
    execute(['unzip','-q',zip,'-d',extracted],stage);
    assert(JSON.stringify(walk(extracted)) === JSON.stringify(inventory),'Extracted inventory mismatch');
    for (const member of inventory) {
      inspect(path.join(extracted,member));
      assert(fs.readFileSync(path.join(extracted,member)).equals(fs.readFileSync(path.join(archiveRoot,member))),'Extracted bytes mismatch: '+member);
    }
    status.inventory = inventory.map(member => {const bytes = fs.readFileSync(path.join(extracted,member)); return {member,sha256:hash(bytes),bytes:bytes.length};});
    assert(equalIdentity(identity(path.join(extracted,'source')),before),'Extracted canonical source identity mismatch');
    status.checks.archiveInventoryAndEveryMemberBytes = true;
    copyInput(standalone,path.join(output,HTML)); copyInput(entrypoint,path.join(output,'START-HERE.md'));
    for (const name of [HTML,'START-HERE.md']) fs.copyFileSync(path.join(output,name),path.join(extracted,name),fs.constants.COPYFILE_EXCL);
    const relocatedSums = fs.readFileSync(path.join(extracted,INNER_SUMS),'utf8').trimEnd().split('\n');
    assert(relocatedSums.length===checksumRows.length,'In-upload checksum entry count differs');
    for (const line of relocatedSums) {
      const match = /^([a-f0-9]{64})  (.+)$/.exec(line); assert(match,'Malformed in-upload checksum');
      const name = relative(match[2]); inspect(path.join(extracted,name));
      assert(hash(fs.readFileSync(path.join(extracted,name)))===match[1],'In-upload relocated checksum mismatch: '+name);
    }
    status.checks.inUploadChecksumsIncludingExternalUploads = true;
    status.rebuild = execute([process.execPath,'--no-install','build.mjs','--source-version'],path.join(extracted,'source'));
    const rebuilt = path.join(extracted,'source/dist/auth-flow-studio.html'); inspect(rebuilt);
    assert(fs.readFileSync(rebuilt).equals(fs.readFileSync(path.join(output,HTML))),'Extracted-source rebuild differs from exact delivered standalone');
    status.rebuild = {...status.rebuild,byteIdentical:true,sha256:hash(fs.readFileSync(rebuilt)),bytes:fs.statSync(rebuilt).size,automaticInstalls:'disabled',sourceVersion:'1.0'};
    for (const [name,expected] of tracked) assert(JSON.stringify(capture(name)) === JSON.stringify(expected),'Input changed after packaging: '+name);
    assert(equalIdentity(identity(root),before),'Canonical source changed during packaging');
    status.checks.inputsUnchanged = true;
    status.omitted = manifest.omitted;
    status.uploads = [ZIP,HTML,'START-HERE.md'];
    status.zipSize = {bytes:fs.statSync(zip).size,targetBelowBytes:10*1024*1024,warning:fs.statSync(zip).size >= 10*1024*1024 ? 'Over single-digit MiB target; all explicit required inputs retained.' : null};
    for (const name of [ZIP,HTML,'START-HERE.md']) { const bytes = fs.readFileSync(path.join(output,name)); status.checksums[name] = {sha256:hash(bytes),bytes:bytes.length}; }
    status.checksumExclusions = {status:['packaging-status.json','SHA256SUMS.txt'],sha256sums:['SHA256SUMS.txt']};
    status.status = 'packaging-integrity-verified-not-acceptance';
    status.stage.retained = false; save();
    const sums = [...status.uploads,'packaging-status.json'].sort().map(name => hash(fs.readFileSync(path.join(output,name)))+'  '+name).join('\n')+'\n';
    fs.writeFileSync(path.join(output,'SHA256SUMS.txt'),sums,{flag:'wx'});
    for (const line of fs.readFileSync(path.join(output,'SHA256SUMS.txt'),'utf8').trimEnd().split('\n')) {
      const [,expected,name] = /^([a-f0-9]{64})  (.+)$/.exec(line);
      assert(hash(fs.readFileSync(path.join(output,name))) === expected,'Final delivery checksum mismatch: '+name);
    }
    fs.rmSync(stage,{recursive:true,force:true}); stage = undefined;
    console.log(JSON.stringify({output,status:status.status,uploads:status.uploads,zipSize:status.zipSize,openConditions:status.openConditions},null,2));
  } catch (error) {
    status.status = 'failed-not-reviewable'; status.error = error.stack || String(error);
    if (stage) status.stage = {...status.stage,path:stage,retained:true};
    save(); throw error;
  }
}
try { main(); } catch (error) { console.error(error.stack || String(error)); process.exitCode = 1; }