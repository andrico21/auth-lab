#!/usr/bin/env bun
// Metadata/identity checks only. No app execution, functional suite, browser or timing collection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureInputs,fileIdentity,runtimeIdentity} from './compact-mobile-browser.mjs';

const root=fs.realpathSync(fileURLToPath(new URL('../../',import.meta.url)));
const args={};
for(const argument of process.argv.slice(2)){
  const match=/^--(out|packet)=(.+)$/.exec(argument);
  assert.ok(match&&!args[match[1]],'Expected unique --out/packet=VALUE');args[match[1]]=match[2];
}
assert.ok(args.packet,'Required --packet=EXISTING_ACCEPTED_DIRECTORY');
const packet=fs.realpathSync(args.packet);
const reportRelative='docs/compact-view/closure-review01-documentation-check.json';
const out=path.resolve(args.out||path.join(root,reportRelative));
assert.ok(!fs.existsSync(out),'Fresh output required; retain failed diagnostics and use a new --out');
const readJSON=relative=>JSON.parse(fs.readFileSync(path.join(root,relative),'utf8'));
const closure=readJSON('docs/compact-view/independent-closure-review01.json');
const ledger=readJSON('docs/compact-view/response-ledger.json');
const progress=readJSON('docs/compact-view/current-progress.json');
const gates=readJSON('docs/compact-view/open-gates.json');
const verification=readJSON('docs/compact-view/review02-verification.json');
const ids=Array.from({length:7},(_,n)=>'MC-R'+String(n+1).padStart(2,'0'));
const closed='independently-closed-reviewed-functional-scope';
const canonical='01f4f40fc980868085d7bcdc941e6cafd3a83de845f94f5c348c549eae6da430';
const standalone={bytes:5668235,sha256:'52479dd292643231ca5945c99fd2df41288d502de530013a07f08a28a93398a5'};
const report={schemaVersion:1,kind:'compact-independent-closure-documentation-only-check',status:'running',startedAt:new Date().toISOString(),runtime:runtimeIdentity(),producer:{path:'tools/verification/check-compact-closure.mjs',...fileIdentity(fileURLToPath(import.meta.url))},checks:[],qualification:'Actual metadata, authority, links and byte-identity checks only. No new application/test/build behavior, functional/fullCI/native/performance execution or publication acceptance. Independent and worker execution remain attributed to their original records.'};
fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
function check(id,run){
  try{run();report.checks.push({id,status:'passed'});}
  catch(error){report.checks.push({id,status:'failed',error:String(error.stack||error)});}
}
function bound(base,descriptor){
  const resolved=path.resolve(base,descriptor.path);
  assert.ok(resolved.startsWith(base+path.sep),'Bound path must stay inside its declared root');
  assert.ok(fs.lstatSync(resolved).isFile(),'Expected a regular bound file');
  assert.deepEqual(fileIdentity(resolved),{bytes:descriptor.bytes,sha256:descriptor.sha256});
}
check('exact-new-independent-authority',()=>{
  assert.equal(closure.authority.originalFilename,'auth-flow-studio-compact-closure-review.html');
  assert.equal(closure.authority.bytes,80869);
  assert.equal(closure.authority.sha256,'ab912ba1100a176cd23b71a6aa18df712083d34a1e501a40422895a4f5c241da');
  bound(root,closure.authority);
});
check('only-seven-reviewed-functional-findings-closed',()=>{
  assert.equal(closure.decision.status,closed);assert.deepEqual(closure.decision.findings,ids);
  assert.equal(closure.decision.reviewedFunctionalScopeOnly,true);assert.equal(closure.decision.additionalRequiredImplementationCorrections,0);
  assert.equal(ledger.status,closed);assert.equal(progress.status,closed);
  assert.deepEqual(ledger.independentClosure,progress.independentClosure);
  assert.deepEqual(gates.independentCompactFindings.findings,ids);
});
for(const id of ids)check('independent-ledger-binding-'+id,()=>{
  const row=ledger.requirements.find(item=>item.id===id);assert.ok(row);
  assert.equal(row.status,closed);assert.equal(row.independentClosure.status,closed);
  assert.equal(row.independentClosure.canonicalSha256,canonical);assert.deepEqual(row.independentClosure.standalone,standalone);
  assert.equal(row.independentClosure.authority.sha256,closure.authority.sha256);
  assert.ok(row.response&&row.verification);assert.equal(row.independentClosure.record,'docs/compact-view/independent-closure-review01.json');
});
check('no-unrelated-requirement-closure',()=>assert.equal(ledger.requirements.filter(row=>row.status===closed).length,7));
const before=captureInputs(root);
check('unchanged-reviewed-application-tests-build-and-html',()=>{
  assert.equal(Object.keys(before.sources).length,271);assert.equal(before.canonicalSha256,canonical);assert.deepEqual(before.standalone,standalone);
  assert.equal(Object.keys(before.sources).filter(name=>/^tests\/[^/]+\.test\.mjs$/.test(name)).length,143);
  assert.equal(closure.candidate.version,'1.1.1');assert.equal(closure.candidate.checkpoint,'142fccdff9c452f6491b8886b83726bc188f49cd');
  assert.equal(closure.candidate.canonicalSha256,canonical);assert.deepEqual(closure.candidate.standalone,standalone);
});
const jsonChanges={
  'response-ledger.json':['status','independentClosure','openGates','openIndependentGates','currentExecutionScope/qualification',...Array.from({length:7},(_,n)=>['closure','status','independentClosure'].map(key=>'requirements/'+(20+n)+'/'+key)).flat()],
  'current-progress.json':['status','independentClosure','openGates','requiredBeforePublication','note'],
  'assertion-interfaces.json':['independentClosure'],
  'changed-files.json':['publication','independentClosure','closureReconciliation'],
  'review02-verification.json':['status','independentClosure','reviewResponses/closure','openGates','currentOpenGates']
};
function withoutChanges(value,pointers){
  const copy=structuredClone(value);
  for(const pointer of pointers){const pieces=pointer.split('/'),key=pieces.pop();let parent=copy;for(const piece of pieces)parent=parent?.[piece];if(parent)delete parent[key];}
  return copy;
}
assert.equal(closure.metadataReconciliation.files.length,9);
for(const row of closure.metadataReconciliation.files){
  check('paired-exact-before-'+row.path,()=>{
    assert.ok(row.exactBefore.path.startsWith('docs/compact-view/inputs/closure-review01-before/'));
    assert.notEqual(path.resolve(root,row.path),path.resolve(root,row.exactBefore.path));bound(root,row.exactBefore);
  });
  check('reconciled-current-metadata-'+row.path,()=>{assert.equal(row.after.path,row.path);bound(root,row.after);});
  if(row.path.endsWith('.json'))check('preserved-worker-and-history-fields-'+row.path,()=>{
    const allowed=jsonChanges[path.basename(row.path)];assert.ok(allowed,'Explicit metadata change set required');
    assert.deepEqual(withoutChanges(readJSON(row.path),allowed),withoutChanges(readJSON(row.exactBefore.path),allowed));
  });
}
for(const row of closure.preservedFiles)check('unchanged-prior-authority-or-history-'+row.path,()=>bound(root,row));
check('preserved-gates-not-blanket-acceptance',()=>{
  assert.equal(gates.performance.status,'open-unaccepted-unwaived');assert.equal(gates.performance.ownerAcceptance,false);
  assert.equal(gates.performance.current.flaggedRows,63);assert.equal(gates.performance.current.comparisonFlaggedRows,51);assert.equal(gates.performance.current.candidateActionFlaggedRows,12);
  assert.equal(gates.performance.current.ordinarySwitchTargetMisses,6);assert.equal(gates.performance.current.fieldVariabilityFlags,5);
  assert.equal(gates.performance.historicalCorrected01.flaggedRows,60);assert.equal(gates.performance.historicalB91.flaggedRows,37);
  assert.equal(gates.humanG01.status,'open-unperformed');assert.equal(gates.externalCompactMatrix.cells,14);assert.equal(gates.externalCompactMatrix.independentlyRecountedByThisReducedClosureReview,false);
  assert.equal(gates.nativeWindowsDC.cases,88);assert.deepEqual([gates.installedPAM.matches,gates.installedPAM.qualifiedDivergences,gates.installedPAM.calls],[164,1,165]);
  for(const state of Object.values(gates.publication))assert.equal(state,false);
  for(const state of Object.values(ledger.publication))assert.equal(state,false);
  assert.equal(progress.requiredBeforePublication.length,1);assert.ok(!verification.openGates.includes('Astra finding/whole review closure'));
  assert.ok(!Object.hasOwn(ledger.openIndependentGates,'astraIndependentReview'));assert.ok(!Object.hasOwn(ledger.openIndependentGates,'review01IndependentClosure'));
});
check('independent-and-worker-results-not-restamped-or-rerun',()=>{
  assert.equal(closure.independentExecution.attribution,'Astra-supplied closure authority; not rerun by worker during documentation reconciliation');
  assert.equal(closure.independentExecution.runtime,'Node v24.22.1');assert.equal(closure.independentExecution.regression.passed,218);assert.equal(closure.independentExecution.regression.files,12);
  assert.equal(closure.workerExecutionAudited.completeCI.passed,2527);assert.equal(closure.workerExecutionAudited.completeCI.runnableFiles,143);
  assert.equal(closure.workerExecutionAudited.independentlyRerunByAstra,false);assert.equal(closure.reconciliationExecution.functionalOrFullCIRerun,false);
});
for(const row of closure.acceptedPacket.files)check('accepted-packet-sibling-unchanged-'+row.path,()=>bound(packet,row));
check('accepted-outer-checksum-list-still-binds-three-uploads',()=>{
  const rows=fs.readFileSync(path.join(packet,'SHA256SUMS'),'utf8').trim().split('\n');assert.equal(rows.length,3);
  for(const line of rows){const match=/^([a-f0-9]{64})  (.+)$/.exec(line);assert.ok(match);assert.equal(closure.acceptedPacket.files.find(row=>row.path===match[2])?.sha256,match[1]);}
});
const markdown=['README.md','docs/compact-view/implementation.md','docs/compact-view/review02-implementation.md','docs/compact-view/reproduce.md','docs/compact-view/START-HERE.md'];
const links=text=>Array.from(text.matchAll(/\[[^\]]*\]\(([^\s()]+)\)/g),match=>match[1]);
const newTargets=new Map();
for(const relative of markdown){
  const row=closure.metadataReconciliation.files.find(item=>item.path===relative);
  const previous=new Set(row?links(fs.readFileSync(path.join(root,row.exactBefore.path),'utf8')):[]);
  for(const target of links(fs.readFileSync(path.join(root,relative),'utf8'))){
    if(previous.has(target)||/^(?:[a-z][a-z0-9+.-]*:|#)/i.test(target))continue;
    const resolved=path.resolve(root,path.dirname(relative),decodeURIComponent(target.split('#')[0]));
    newTargets.set(resolved,(newTargets.get(resolved)||[]).concat(relative));
  }
}
for(const [target,origins] of newTargets)check('new-navigation-target-'+path.relative(root,target),()=>{
  assert.ok(target.startsWith(root+path.sep),'New documentation links stay inside repository');assert.ok(fs.statSync(target).isFile(),'Missing target from '+origins.join(','));
});
for(const row of closure.newAuthoredFiles)check('new-authored-binding-and-ascii-hyphens-'+row.path,()=>{
  bound(root,row);assert.ok(!/[\u2013\u2014]/.test(fs.readFileSync(path.join(root,row.path),'utf8')),'Use ASCII hyphens in authored files, not in byte-exact raw authority snapshots');
});
check('reviewed-byte-identity-stable-through-documentation-check',()=>assert.deepEqual(captureInputs(root),before));
report.observedCandidate={canonicalFiles:Object.keys(before.sources).length,canonicalSha256:before.canonicalSha256,standalone:before.standalone};
report.checkedMetadataPreimages=closure.metadataReconciliation.files.length;
report.checkedPreservedAuthoritiesAndHistoricalFiles=closure.preservedFiles.length;
report.checkedAcceptedPacketSiblings=closure.acceptedPacket.files.length;
report.checkedNewNavigationTargets=newTargets.size;
report.passed=report.checks.filter(row=>row.status==='passed').length;report.failed=report.checks.length-report.passed;
report.status=report.failed?'failed':'passed';report.finishedAt=new Date().toISOString();
fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({status:report.status,passed:report.passed,failed:report.failed,metadataPreimages:report.checkedMetadataPreimages,preservedAuthoritiesAndHistory:report.checkedPreservedAuthoritiesAndHistoricalFiles,acceptedSiblings:report.checkedAcceptedPacketSiblings,newNavigationTargets:report.checkedNewNavigationTargets,report:out,qualification:report.qualification},null,2));
process.exitCode=report.failed?1:0;
