#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const runner=fileURLToPath(import.meta.url);
const root=path.resolve(path.dirname(runner),'../..');
const usage='Usage: bun tools/verification/run-review-corrections-crypto.mjs --bun142=/absolute/path/to/bun --bun143=/absolute/path/to/bun [--out=docs/verification/review-corrections/crypto]';
if(process.argv.includes('--help')){console.log(usage);process.exit(0);}
if(!process.versions.bun)throw new Error('Bun is required.');
const options={};
for(const arg of process.argv.slice(2)){
 const match=/^--(bun142|bun143|out)=(.+)$/.exec(arg);
 if(!match||options[match[1]])throw new Error(usage);
 options[match[1]]=match[2];
}
if(!options.bun142||!options.bun143)throw new Error(usage);
const output=path.resolve(root,options.out||'docs/verification/review-corrections/crypto');
if(!output.startsWith(root+path.sep))throw new Error('Evidence must remain inside the checkout.');
fs.mkdirSync(output,{recursive:true});
const hash=value=>createHash('sha256').update(value).digest('hex');
const execution={kind:'review-corrections-crypto-execution',timestamp:new Date().toISOString(),passed:false,runnerSha256:hash(fs.readFileSync(runner)),regenerationCommand:[process.execPath,...process.argv.slice(1)],runs:[]};
for(const [option,version] of [['bun142','1.4.2'],['bun143','1.4.3']]){
 const executable=path.resolve(options[option]);
 const argv=[executable,'tools/verification/expansion-crypto/check-vectors.mjs'];
 const child=Bun.spawn(argv,{cwd:root,stdout:'pipe',stderr:'pipe',timeout:120000});
 const [stdout,stderr,exitCode]=await Promise.all([new Response(child.stdout).text(),new Response(child.stderr).text(),child.exited]);
 const file=path.join(output,'crypto-vectors-'+option+'-status.json');
 fs.writeFileSync(file,stdout);
 let result,parseError;
 try{result=JSON.parse(stdout);}catch(error){parseError=error.message;}
 const passed=exitCode===0&&result?.passed===true&&result.runtime?.bun===version&&result.summary?.total===31&&result.summary?.passed===31&&result.summary?.failed===0;
 execution.runs.push({argv,exitCode,stderr,report:path.relative(root,file).split(path.sep).join('/'),sha256:hash(stdout),runtime:result?.runtime,summary:result?.summary,passed,...(parseError?{parseError}:{})});
}
execution.passed=execution.runs.length===2&&execution.runs.every(run=>run.passed);
fs.writeFileSync(path.join(output,'execution.json'),JSON.stringify(execution,null,2)+'\n');
console.log(JSON.stringify({passed:execution.passed,runs:execution.runs.map(({runtime,summary,passed})=>({runtime,summary,passed})),report:path.relative(root,path.join(output,'execution.json'))},null,2));
if(!execution.passed)process.exitCode=1;
