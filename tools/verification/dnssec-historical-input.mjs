import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

const originalPath='tools/verification/dnssec-crypto/requirements.txt';
const before={originalPath,path:'docs/dnssec-expansion/numeric/runtime-50.0.0-dnspython-2.9.0/inputs/historical-requirements.input.txt',bytes:382,sha256:'24c62a92f1a8992f2469ba6cf381a8d07e4c21ae0e058592c596221947b6fd41'};
const profilePath='tools/verification/dnssec-crypto-current/profile.json';

function regularInput(root,name){
  if(typeof name!=='string'||!name||name.includes('\\')||path.posix.isAbsolute(name)||name.split('/').some(part=>!part||part==='.'||part==='..'))throw new Error('Unsafe historical input path: '+name);
  let file=path.resolve(root);
  const parts=name.split('/');
  for(const [index,part] of parts.entries()){
    file=path.join(file,part);
    const stat=fs.lstatSync(file);
    if(index===parts.length-1?!stat.isFile():!stat.isDirectory())throw new Error('Historical input is not a regular '+(index===parts.length-1?'file: ':'directory: ')+file);
  }
  return file;
}

// Only the exact original frozen requirement row may resolve to retained bytes.
// The live manifest remains a separate current input, never assigned its old hash.
export function historicalInputPath(root,input){
  if(input?.path!==originalPath)return regularInput(root,input?.path);
  if(input.bytes!==before.bytes||input.sha256!==before.sha256)throw new Error('Wrong frozen historical requirements identity');
  const profile=JSON.parse(fs.readFileSync(regularInput(root,profilePath),'utf8'));
  if(!isDeepStrictEqual(profile.historical?.requirementsBefore,before))throw new Error('Wrong historical requirementsBefore binding');
  const file=regularInput(root,before.path),bytes=fs.readFileSync(file);
  if(bytes.length!==input.bytes||createHash('sha256').update(bytes).digest('hex')!==input.sha256)throw new Error('Frozen historical requirements changed: '+before.path);
  return file;
}
