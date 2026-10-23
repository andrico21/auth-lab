#!/usr/bin/env bun
// Static traceability only. Independent predicates remain authored worksheet inputs.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const runner=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(runner),'../..');
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/refresh-next-expansion-ledger.mjs --review-input=PATH\nRefresh the existing static implementation ledger from the frozen manifest and complete authored worksheets. No app imports, builds, tests, network or behavior/acceptance claims.');process.exit(0);}
assert.equal(process.argv.length,3,'One explicit --review-input=PATH is required');
assert.ok(process.argv[2].startsWith('--review-input='));
const reviewPath=path.resolve(root,process.argv[2].slice('--review-input='.length));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const read=name=>JSON.parse(fs.readFileSync(path.join(root,name),'utf8'));
const ref=file=>{const bytes=fs.readFileSync(file);return {path:path.relative(root,file).split(path.sep).join('/'),sha256:sha(bytes),bytes:bytes.length};};
const target='docs/next-expansion/implementation-ledger.json',ledger=read(target),previous=ref(path.join(root,target));
const manifest=read('docs/next-expansion/scenario-manifest.json'),sources=read('docs/next-expansion/source-ledger.json');
const worksheets=new Map(),allWorksheetRows=[];
for(const family of ['nfs','windows-workstation','unix-workstation','jwt','kubernetes','mcp']){
  const filename='docs/next-expansion/'+family+'-worksheet.json',value=read(filename),key=Array.isArray(value.rows)?'rows':'scenarios';
  assert.ok(Array.isArray(value[key]),'Authored row array '+filename);
  worksheets.set(filename,{value,key});allWorksheetRows.push(...value[key].map((row,index)=>({row,index,filename,key})));
}
const core=manifest.scenarios.filter(row=>!row.optional),optional=manifest.scenarios.filter(row=>row.optional);
assert.equal(allWorksheetRows.length,core.length,'Exactly one authored worksheet row per core lesson');
const kinds=['local','protected-receipt','acceptance'],audits=[];
const audit=(check,fn,detail)=>{fn();audits.push({check,result:'pass',detail});};
const unique=values=>assert.equal(new Set(values).size,values.length);
const sameSet=(a,b)=>assert.deepEqual([...a].sort(),[...b].sort());
for(const entry of ledger.rows){
  const planned=core.find(row=>row.id===entry.planID);assert.ok(planned);
  const matches=allWorksheetRows.filter(({row})=>(row.planId||row.id)===entry.planID);assert.equal(matches.length,1);
  const {row,index,filename,key}=matches[0];assert.equal(row.runtimeId,entry.runtimeID);sameSet(row.sourceRowIds||row.sourceRows,planned.sourceRowIds);
  const cases=row.canonicalCases;assert.ok(Array.isArray(cases));unique(cases.map(value=>value.id));
  entry.worksheet={...entry.worksheet,path:filename,rowKey:key,rowPointer:'/'+key+'/'+index,declaredPlanID:entry.planID,declaredRuntimeID:row.runtimeId,caseCount:cases.length,declaredPredicateCount:cases.reduce((sum,value)=>sum+value.assertions.length,0)};
  entry.cases=cases.map(value=>({caseId:value.id,qualifiedCaseId:entry.planID+'/'+value.id,...(value.modelProfile?{modelProfileOverride:value.modelProfile}:{})}));
  const fixtures=row.nativeReplay||[];
  for(const fixture of fixtures){assert.ok(kinds.includes(fixture.kind));assert.ok(cases.some(value=>value.id===(fixture.caseId||'default')));assert.ok(fixture.at?.stepId?.startsWith(row.runtimeId+':'));assert.ok(fixture.at.milestone&&fixture.fieldId&&fixture.holding?.actorId&&fixture.holding?.artifactId&&fixture.holding?.representation);}
  entry.nativeReplay={...entry.nativeReplay,declaredFixtureCount:fixtures.length,fixtures,missingKinds:kinds.filter(kind=>!fixtures.some(value=>value.kind===kind)),fixtureCaseIds:[...new Set(fixtures.map(value=>value.caseId||'default'))]};
  entry.sources.runtimeIdLiteralPresentInFamilySource=entry.sources.modules.some(name=>fs.readFileSync(path.join(root,name),'utf8').includes(entry.runtimeID));
}
for(const family of ledger.families){
  const rows=ledger.rows.filter(row=>row.workspace===family.workspace&&row.family===family.family);
  family.coreCaseCount=rows.reduce((sum,row)=>sum+row.cases.length,0);family.coreDeclaredPredicateCount=rows.reduce((sum,row)=>sum+row.worksheet.declaredPredicateCount,0);
  family.nativeReplay={...family.nativeReplay,fixtureCount:rows.reduce((sum,row)=>sum+row.nativeReplay.fixtures.length,0),rowsWithFixtures:rows.filter(row=>row.nativeReplay.fixtures.length).map(row=>row.planID),rowsWithoutFixtures:rows.filter(row=>!row.nativeReplay.fixtures.length).map(row=>row.planID)};
  for(const [kind,key]of [['local','missingLocalDeclaration'],['protected-receipt','missingProtectedReceiptDeclaration'],['acceptance','missingAcceptanceDeclaration']])family.nativeReplay[key]=rows.filter(row=>row.nativeReplay.missingKinds.includes(kind)).map(row=>row.planID);
}
const cases=ledger.rows.flatMap(row=>row.cases),fixtures=ledger.rows.flatMap(row=>row.nativeReplay.fixtures),total=cases.length,overrides=cases.filter(value=>value.modelProfileOverride).length;
Object.assign(ledger.counts,{coreWorksheetRows:allWorksheetRows.length,coreCasesCollected:total,uniqueQualifiedCaseIds:new Set(cases.map(value=>value.qualifiedCaseId)).size,perCaseProfileOverrides:overrides,inheritedRowProfiles:total-overrides,declaredPredicates:ledger.rows.reduce((sum,row)=>sum+row.worksheet.declaredPredicateCount,0),nativeReplayFixtures:fixtures.length,rowsWithNativeReplay:ledger.rows.filter(row=>row.nativeReplay.fixtures.length).length,rowsWithoutNativeReplay:ledger.rows.filter(row=>!row.nativeReplay.fixtures.length).length,rowsMissingLocalDeclaration:ledger.rows.filter(row=>row.nativeReplay.missingKinds.includes('local')).length,rowsMissingProtectedReceiptDeclaration:ledger.rows.filter(row=>row.nativeReplay.missingKinds.includes('protected-receipt')).length,rowsMissingAcceptanceDeclaration:ledger.rows.filter(row=>row.nativeReplay.missingKinds.includes('acceptance')).length,coreRuntimeIdLiteralsInFamilySource:ledger.rows.filter(row=>row.sources.runtimeIdLiteralPresentInFamilySource).length});
audit('manifest row partition',()=>{assert.equal(manifest.scenarios.length,85);assert.equal(core.length,81);assert.equal(optional.length,4);},'85 frozen plan rows = 81 core + 4 deferred; no catalog rows added.');
audit('planID and runtimeID uniqueness',()=>{unique(manifest.scenarios.map(row=>row.id));unique(manifest.scenarios.map(row=>row.runtimeId));},'Every frozen plan/runtime identifier remains unique.');
audit('runtimeId freeze',()=>{for(const row of manifest.scenarios)assert.equal(row.runtimeId,row.proposedRuntimeId);},'No frozen runtime-ID remapping.');
audit('target route derivation and uniqueness',()=>{unique(ledger.rows.map(row=>row.targetRoute));for(const row of ledger.rows)assert.equal(row.targetRoute,'#/'+row.workspace+'/'+row.family+'/'+row.runtimeID);},'81 distinct declared workspace/family/lesson routes; no runtime routing result claimed.');
audit('worksheet row identity and source references',()=>{sameSet(ledger.rows.map(row=>row.planID),core.map(row=>row.id));for(const row of core)sameSet(sources.scenarioSourceReferences[row.id],row.sourceRowIds);},'Every core lesson has one authored worksheet owner and the frozen primary-source references.');
audit('canonical and qualified case identity',()=>{unique(cases.map(value=>value.qualifiedCaseId));},total+' uniquely qualified authored cases; behavior execution is separate.');
audit('independently declared case aggregates',()=>{const unix=worksheets.get('docs/next-expansion/unix-workstation-worksheet.json').value,mcp=worksheets.get('docs/next-expansion/mcp-worksheet.json').value;assert.equal(unix.implementation.canonicalCases,unix.rows.reduce((sum,row)=>sum+row.canonicalCases.length,0));assert.equal(mcp.modelCaseCount,mcp.scenarios.reduce((sum,row)=>sum+row.canonicalCases.length,0));},'Authored Unix and MCP aggregate declarations match their canonical case arrays.');
audit('per-case profile overrides',()=>assert.equal(overrides+ledger.counts.inheritedRowProfiles,total),overrides+' per-case profiles; '+(total-overrides)+' inherited row profiles.');
audit('native replay fixture integrity',()=>assert.equal(fixtures.length,ledger.counts.nativeReplayFixtures),fixtures.length+' complete authored field/holding/checkpoint fixtures; no native execution is implied.');
audit('runtime ID literals in family source',()=>assert.equal(ledger.counts.coreRuntimeIdLiteralsInFamilySource,81),'All 81 core runtime IDs still have their declared family source owners.');
audit('optional row worksheet coverage',()=>{for(const row of optional)assert.ok(!allWorksheetRows.some(entry=>entry.row.runtimeId===row.runtimeId));},'NFS14, WELEV07, K8S16 and MCP14 remain deliberately deferred and unregistered.');
ledger.recordedAt=new Date().toISOString();ledger.audits=audits;
for(const input of ledger.provenance.inputs)input.sha256=ref(path.join(root,input.path)).sha256;
const retained=path.join(path.dirname(reviewPath),'implementation-ledger-'+previous.sha256+'.json');
if(fs.existsSync(retained))assert.equal(ref(retained).sha256,previous.sha256);else fs.copyFileSync(path.join(root,target),retained,fs.constants.COPYFILE_EXCL);
ledger.provenance.correctionRefresh={previousLedger:{...ref(retained),originalPath:previous.path},review:ref(reviewPath),generator:ref(runner),method:'Static authored-data reconciliation only; never derives expected predicate values from model execution.'};
ledger.contracts.caseIdentity.uniqueness=total+' unique qualified ids; caseId alone repeats across rows by design.';
ledger.contracts.verificationBoundary.notClaimed[1]=total+'-case current source/compiled/native execution matrix';
ledger.contracts.replayDeclaration.missingSemantics='Missing kinds list absent exact worksheet fixtures; '+ledger.counts.rowsWithoutNativeReplay+' core rows declare none. No artifact, checkpoint or execution result was invented.';
ledger.openItems=ledger.openItems.map(item=>({...item,item:item.item.replace(/\b604-case\b/,total+'-case').replace(/\b42 declared\b/,fixtures.length+' declared')}));
const mcp03=ledger.rows.find(row=>row.planID==='MCP03');
mcp03.currentReviewClarification={finding:'P6-MCP-04',authority:ref(reviewPath),historicalManifestRetained:true,sequence:['C selects URL client_id and creates the complete authorization transaction.','A receives client_id, redirect_uri, state, PKCE, resource and requested scopes before uncached CIMD resolution.','A resolves CIMD identity and exact redirect policy for that same received transaction.','Only then may authentication, consent and code issuance continue; there is no standalone A-to-C registration acknowledgment.'],existingRegistrationPreferred:true,deprecatedDCRExplicitlySeparate:true};
fs.writeFileSync(path.join(root,target),JSON.stringify(ledger,null,2)+'\n');
console.log(JSON.stringify({status:'refreshed-static-authored-inventory-not-behavior-acceptance',output:target,counts:ledger.counts,identity:ref(path.join(root,target)),review:ref(reviewPath)},null,2));
