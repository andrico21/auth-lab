import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Identity context only: hashing product bytes is not execution of their behavior.
export function captureReviewInputs(root, runner) {
  const digest = filename => {
    if (!fs.lstatSync(filename).isFile()) throw new TypeError('Review input is not a regular file: '+filename);
    return createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
  };
  const files = directory => {
    const absolute = path.join(root,directory);
    if (!fs.lstatSync(absolute).isDirectory()) throw new TypeError('Review input is not a regular directory: '+absolute);
    return fs.readdirSync(absolute,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(entry => {
      if (['node_modules','.git'].includes(entry.name)) return [];
      const name = directory+'/'+entry.name;
      if (entry.isSymbolicLink()) throw new TypeError('Review input symlink: '+name);
      if (entry.isDirectory()) return files(name);
      if (!entry.isFile()) throw new TypeError('Unsupported review input: '+name);
      return [name];
    });
  };
  const identities = names => Object.fromEntries(names.sort().map(name=>[name,digest(path.join(root,name))]));
  return {
    sourceFiles: identities(['index.html','build.mjs','package.json','security-policy.mjs',...['assets','src','tests'].flatMap(files)]),
    verificationFiles: identities(files('tools/verification')),
    manifestSha256: digest(path.join(root,'docs/next-expansion/scenario-manifest.json')),
    standaloneSha256: digest(path.join(root,'dist/auth-flow-studio.html')),
    runnerSha256: digest(runner),
    identityHelperSha256: digest(fileURLToPath(import.meta.url))
  };
}
