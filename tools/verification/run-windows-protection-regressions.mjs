#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {captureReviewInputs} from './review-input-identity.mjs';
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/run-windows-protection-regressions.mjs [project-directory]\nBuild first. Runs compiled standalone boot exclusively, then every other tests/*.test.mjs file in four isolated Bun workers with exact ./tests/ selectors and unchanged timeouts. Set AUTH_LAB_HELD_EVIDENCE_DIR to a new evidence directory.');process.exit(0);}
const root=path.resolve(process.argv[2]||path.join(path.dirname(fileURLToPath(import.meta.url)),'../..'));
const output=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(root,'docs/verification/windows-protection-expansion/regression-02'));
fs.mkdirSync(path.join(output,'regression-logs'),{recursive:true});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const files=fs.readdirSync(path.join(root,'tests')).filter(name=>name.endsWith('.test.mjs')).sort();
const exclusiveFiles=files.filter(name=>name==='standalone-runtime.test.mjs'),parallelFiles=files.filter(name=>name!=='standalone-runtime.test.mjs');
const report={kind:'windows-protection-full-source-regressions',timestamp:new Date().toISOString(),runtime:{executable:process.execPath,version:process.version,bun:Bun.version},runnerSha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),regenerationCommand:[process.execPath,...process.argv.slice(1)],workers:4,perTestTimeoutMs:900000,perFileProcessTimeoutMs:1800000,inputIdentity:captureReviewInputs(root,fileURLToPath(import.meta.url)),plannedFiles:files,runningFiles:[],files:[],passed:false,complete:false,interruptions:[]};
report.scheduling={kind:'exclusive-compiled-boot-then-four-workers',exclusiveFiles,parallelFiles,reason:'The standalone VM has a five-second wall-clock limit; no other test process from this runner overlaps its bootstrap. All files and consumer assertions remain unchanged.'};
const statusFile=path.join(output,'regression-status.json');
const save=()=>fs.writeFileSync(statusFile,JSON.stringify(report,null,2)+'\n');
const children=new Set();let next=0,interrupted=false;
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{interrupted=true;report.interruptions.push({signal,at:new Date().toISOString()});save();for(const child of children)child.kill('SIGTERM');});
save();
async function worker(queue){
  while(!interrupted){
    const file=queue[next++];if(!file)return;
    const command=[process.execPath,'test','--isolate','--timeout=900000','./tests/'+file],start=performance.now();
    const log='regression-logs/'+file+'.log',absolute=path.join(output,log),fd=fs.openSync(absolute,'wx');
    report.runningFiles.push(file);save();
    let child,exitCode=null,error=null;
    try{child=Bun.spawn(command,{cwd:root,stdout:fd,stderr:fd,timeout:1800000});children.add(child);exitCode=await child.exited;}
    catch(caught){error=String(caught.stack||caught);}
    finally{if(child)children.delete(child);fs.closeSync(fd);}
    const text=fs.readFileSync(absolute,'utf8'),passes=[...text.matchAll(/(?:^|\n)\s*(\d+) pass\b/g)],failures=[...text.matchAll(/(?:^|\n)\s*(\d+) fail\b/g)];
    const testsPassed=passes.length?Number(passes.at(-1)[1]):null,testsFailed=failures.length?Number(failures.at(-1)[1]):null;
    const result={file,argv:command,exitCode,signal:child?.signalCode??null,error,testsPassed,testsFailed,seconds:Number(((performance.now()-start)/1000).toFixed(3)),log,logSha256:hash(text),logBytes:Buffer.byteLength(text),passed:exitCode===0&&testsPassed!==null&&testsFailed===0};
    report.runningFiles=report.runningFiles.filter(name=>name!==file);report.files.push(result);save();console.log(JSON.stringify(result));
  }
}
await worker(exclusiveFiles);
next=0;
await Promise.all(Array.from({length:report.workers},()=>worker(parallelFiles)));
report.files.sort((a,b)=>a.file.localeCompare(b.file));
report.afterIdentity=captureReviewInputs(root,fileURLToPath(import.meta.url));
report.identityUnchanged=JSON.stringify(report.afterIdentity)===JSON.stringify(report.inputIdentity);
report.totalFiles=files.length;report.totalPassed=report.files.reduce((sum,file)=>sum+(file.testsPassed||0),0);report.totalFailed=report.files.reduce((sum,file)=>sum+(file.testsFailed||0),0);
report.unperformedFiles=files.filter(name=>!report.files.some(file=>file.file===name));
report.complete=report.files.length===files.length&&!report.interruptions.length;
report.passed=report.complete&&report.identityUnchanged&&report.files.every(file=>file.passed);
report.status=report.passed?'passed':report.complete?'failed':'incomplete';report.exitCode=report.passed?0:1;report.finishedAt=new Date().toISOString();save();
console.log(JSON.stringify({passed:report.passed,complete:report.complete,totalFiles:report.totalFiles,totalPassed:report.totalPassed,totalFailed:report.totalFailed,failures:report.files.filter(file=>!file.passed).map(file=>file.file),unperformedFiles:report.unperformedFiles,identityUnchanged:report.identityUnchanged,evidenceDirectory:output},null,2));
if(!report.passed)process.exitCode=1;
