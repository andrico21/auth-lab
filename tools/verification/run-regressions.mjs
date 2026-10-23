#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {captureReviewInputs} from './review-input-identity.mjs';
if(process.argv.includes('--help')){console.log('Usage: bun tools/verification/run-regressions.mjs [project-directory]\nBuild first. Runs every tests/*.test.mjs file in four isolated Bun workers. Evidence: AUTH_LAB_HELD_EVIDENCE_DIR or docs/verification/held-objects.');process.exit(0);}
const root=path.resolve(process.argv[2]||path.join(path.dirname(fileURLToPath(import.meta.url)),'../..'));
const output=path.resolve(process.env.AUTH_LAB_HELD_EVIDENCE_DIR||path.join(root,'docs/verification/held-objects'));
fs.mkdirSync(path.join(output,'regression-logs'),{recursive:true});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const files=fs.readdirSync(path.join(root,'tests')).filter(name=>name.endsWith('.test.mjs')).sort();
const report={kind:'held-objects-full-source-regressions',timestamp:new Date().toISOString(),runtime:{executable:process.execPath,version:process.version,bun:Bun.version},runnerSha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),regenerationCommand:[process.execPath,...process.argv.slice(1)],workers:4,inputIdentity:captureReviewInputs(root,fileURLToPath(import.meta.url)),files:[],passed:false};
let next=0;
async function worker(){
  for(;;){
    const file=files[next++];if(!file)return;
    const command=[process.execPath,'test','--isolate','--timeout=900000','tests/'+file],start=performance.now();
    const child=Bun.spawn(command,{cwd:root,stdout:'pipe',stderr:'pipe',timeout:1800000});
    const [stdout,stderr,exitCode]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);
    const text=stdout+stderr,passes=[...text.matchAll(/(?:^|\n)\s*(\d+) pass\b/g)],failures=[...text.matchAll(/(?:^|\n)\s*(\d+) fail\b/g)];
    const testsPassed=passes.length?Number(passes.at(-1)[1]):null,testsFailed=failures.length?Number(failures.at(-1)[1]):null;
    const log='regression-logs/'+file+'.log';fs.writeFileSync(path.join(output,log),text);
    const result={file,argv:command,command:command.join(' '),exitCode,testsPassed,testsFailed,seconds:Number(((performance.now()-start)/1000).toFixed(3)),log,logSha256:hash(text),passed:exitCode===0&&testsPassed!==null&&testsFailed===0};
    report.files.push(result);console.log(JSON.stringify(result));
  }
}
await Promise.all(Array.from({length:report.workers},()=>worker()));
report.files.sort((a,b)=>a.file.localeCompare(b.file));
report.identityUnchanged=JSON.stringify(captureReviewInputs(root,fileURLToPath(import.meta.url)))===JSON.stringify(report.inputIdentity);
report.totalFiles=files.length;report.totalPassed=report.files.reduce((sum,file)=>sum+(file.testsPassed||0),0);report.totalFailed=report.files.reduce((sum,file)=>sum+(file.testsFailed||0),0);
report.passed=report.identityUnchanged&&report.files.length===files.length&&report.files.every(file=>file.passed);
report.status=report.passed?'passed':'failed';report.exitCode=report.passed?0:1;
fs.writeFileSync(path.join(output,'held-objects-regression-status.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({passed:report.passed,totalFiles:report.totalFiles,totalPassed:report.totalPassed,totalFailed:report.totalFailed,failures:report.files.filter(file=>!file.passed).map(file=>file.file),identityUnchanged:report.identityUnchanged,evidenceDirectory:output},null,2));
if(!report.passed)process.exitCode=1;
