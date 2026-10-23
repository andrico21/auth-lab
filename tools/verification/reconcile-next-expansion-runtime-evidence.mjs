#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {captureReviewInputs} from './review-input-identity.mjs';

// Reuse actual browser/timing output only when every application byte is unchanged.
// This does not execute the browser or manufacture a new measurement.
const runner=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(runner),'../..');
const options={};
for(const arg of process.argv.slice(2)){const match=/^--(type|input|repairs|out)=(.+)$/.exec(arg);assert(match&&!options[match[1]],'Unknown/duplicate option');options[match[1]]=match[2];}
assert(['native','performance'].includes(options.type)&&options.input&&options.repairs&&options.out);
assert(process.versions.bun);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function local(name){const file=path.resolve(root,name);assert(file.startsWith(root+path.sep),'Repository input required');let current=root;for(const segment of path.relative(root,file).split(path.sep)){current=path.join(current,segment);if(fs.existsSync(current))assert(!fs.lstatSync(current).isSymbolicLink(),'No symlink input');}return file;}
function ref(name){const file=local(name);assert(fs.lstatSync(file).isFile());const bytes=fs.readFileSync(file);return {path:path.relative(root,file).split(path.sep).join('/'),sha256:sha(bytes),bytes:bytes.length};}
const read=name=>JSON.parse(fs.readFileSync(local(name),'utf8'));
const input=read(options.input),repairs=read(options.repairs),inputRef=ref(options.input),repairsRef=ref(options.repairs),output=local(options.out);
assert(!fs.existsSync(output),'Output must be a new file');
assert.equal(repairs.schemaVersion,1);assert.equal(repairs.kind,'next-expansion-test-only-input-repair');
const before=captureReviewInputs(root,runner),sourceFiles=before.sourceFiles;
const originalMaps=options.type==='native'?[input.before.canonicalSourceFiles,input.after.canonicalSourceFiles]:[input.identities.candidate.canonicalSourceFiles];
const expectedPaths=Object.keys(sourceFiles).sort(),original=originalMaps[0];
for(const map of originalMaps)assert.deepEqual(map,original,'Producer source changed during execution');
assert.deepEqual(Object.keys(original).sort(),expectedPaths,'No removed or added canonical input');
assert.deepEqual(original,repairs.beforeSource.files,'Repair boundary must match the actual producer input');
const changed=expectedPaths.filter(name=>original[name]!==sourceFiles[name]);
assert(changed.length,'Explicit repair delta required');
assert.deepEqual(changed,repairs.changes.map(row=>row.path).sort());
const restored=createHash('sha256'),runtimeFiles={};
for(const name of expectedPaths){
 const change=repairs.changes.find(row=>row.path===name);
 const current=ref(name);
 if(change){
  assert(name.startsWith('tests/'),'Only tests/harness inputs may differ');
  assert.equal(change.beforeSha256,original[name]);assert.equal(change.afterSha256,current.sha256);
  const retained=ref(change.originalInput.path);assert.deepEqual(retained,change.originalInput);assert.equal(retained.sha256,original[name]);
 }else assert.equal(current.sha256,original[name]);
 const originalBytes=fs.readFileSync(local(change?change.originalInput.path:name));
 restored.update(name+'\0');restored.update(originalBytes);restored.update('\0');
 if(!name.startsWith('tests/')){assert.equal(current.sha256,original[name]);runtimeFiles[name]=current.sha256;}
}
assert.equal(restored.digest('hex'),repairs.beforeSource.sha256,'Original full195 snapshot must be reproducible');
assert.equal(before.standaloneSha256,repairs.standalone.sha256);assert.equal(before.manifestSha256,repairs.manifest.sha256);
let producerRunner,producerStatus;
const auxiliaryChanges=[];
if(options.type==='native'){
 assert.equal(input.kind,'next-expansion-serial-native');assert.equal(input.phase,'final');assert.equal(input.passed,true);assert.equal(input.complete,true);assert.equal(input.exitCode,0);
 for(const snapshot of [input.before,input.after]){assert.equal(snapshot.html.sha256,before.standaloneSha256);assert.equal(snapshot.entries['docs/next-expansion/scenario-manifest.json'].sha256,before.manifestSha256);}
 producerRunner=ref('tools/verification/run-next-expansion-native.mjs');
 assert.equal(input.before.runner.sha256,producerRunner.sha256);assert.equal(input.after.runner.sha256,producerRunner.sha256);
 for(const [name,entry]of Object.entries(input.before.entries)){
  const current=ref(name);if(current.sha256===entry.sha256)continue;
  if(name.startsWith('tests/')){assert(repairs.changes.some(row=>row.path===name&&row.beforeSha256===entry.sha256&&row.afterSha256===current.sha256));continue;}
  const declared=(repairs.auxiliaryChanges||[]).find(row=>row.path===name);assert(declared,'Undeclared producer auxiliary-input change: '+name);
  assert(name.startsWith('docs/')||name==='tools/verification/package-next-expansion-review.mjs','Only retained documentation or the packaging-only producer may differ; no browser/timing runner, consumer helper or model changes');assert.equal(declared.beforeSha256,entry.sha256);assert.equal(declared.afterSha256,current.sha256);
  const retained=ref(declared.originalInput.path);assert.deepEqual(retained,declared.originalInput);assert.equal(retained.sha256,entry.sha256);auxiliaryChanges.push(declared);
 }
 producerStatus=input.status;
}else{
 assert.equal(input.kind,'next-expansion-performance');assert.equal(input.mode,'compare');assert.equal(input.collectionComplete,true);assert.equal(input.identityUnchanged,true);assert.equal(input.errors.length,0);
 assert.equal(input.identities.candidate.standalone.sha256,before.standaloneSha256);assert.equal(input.manifest.sha256,before.manifestSha256);
 producerRunner=ref('tools/verification/run-next-expansion-performance.mjs');assert.equal(producerRunner.sha256,input.runner.sha256);producerStatus=input.currentMeasurementStatus;
 assert(['passed','partial'].includes(producerStatus));assert.equal(input.exitCode,producerStatus==='passed'?0:2);
}
const after=captureReviewInputs(root,runner);assert.deepEqual(after,before,'Inputs changed during actual applicability check');
const report={schemaVersion:1,kind:'unchanged-runtime-evidence-applicability',type:options.type,recordedAt:new Date().toISOString(),argv:[process.execPath,...process.argv.slice(1)],root,runtime:{bun:process.versions.bun,version:process.version,platform:process.platform,arch:process.arch},inputIdentity:before,sourceUnchanged:true,applicabilityPassed:true,status:producerStatus,exitCode:producerStatus==='passed'?0:2,browserExecutedByThisInvocation:false,timingsCollectedByThisInvocation:false,producerReport:inputRef,producerRunner,repairBoundary:repairsRef,compatibility:{allCanonicalPathSetsMatched:true,runtimeInputCount:Object.keys(runtimeFiles).length,runtimeInputFiles:runtimeFiles,changedCanonicalInputs:repairs.changes,auxiliaryNonRuntimeChanges:auxiliaryChanges,originalFullSourceReconstructed:true,originalSourceSha256:repairs.beforeSource.sha256,standaloneUnchanged:true,manifestUnchanged:true,producerRunnerUnchanged:true},producer:input,limits:'This invocation proves applicability to byte-identical application inputs after explicitly retained test-only repairs. It is not a new browser run or new timing measurement. Original producer argv, runtime, full source/test maps, raw report bytes, statuses, scope, failures and distributions remain unchanged. Current full regression and source/compiled/held/numeric gates must execute separately. ManualG01, current/historical performance and live-platform limits are not closed.'};
fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({output:path.relative(root,output),status:report.status,applicabilityPassed:true,unchangedRuntimeInputs:report.compatibility.runtimeInputCount,changedTests:changed,standaloneSha256:before.standaloneSha256,newBrowserRun:false,newTimingMeasurement:false},null,2));
process.exitCode=report.exitCode;
