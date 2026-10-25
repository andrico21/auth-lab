import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Public data projection only; no application imports or browser cryptography.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),mode=process.argv[2];
assert.ok(['--write','--check'].includes(mode)&&process.argv.length===3,'Use --write or --check');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const catalogPath='docs/dnssec-expansion/numeric/review-corrections/PUBLIC-CATALOG.json';
const catalogBytes=fs.readFileSync(path.join(root,catalogPath));
assert.equal(hash(catalogBytes),'7f2eba596704ba73bddc3d20a1616b8ecce9cd6b8b4a57229df0a511b1c43f28','Sealed independent review-correction catalog');
const catalog=JSON.parse(catalogBytes);
const load=ref=>{const bytes=fs.readFileSync(path.join(root,ref.path));assert.equal(bytes.length,ref.bytes,'Independent byte count: '+ref.path);assert.equal(hash(bytes),ref.sha256,'Independent hash: '+ref.path);return JSON.parse(bytes);};
const fixture=load(catalog.fixture),projection=load(catalog.publicProjection),verification=load(catalog.verification.report);
assert.equal(verification.fixture.sha256,catalog.fixture.sha256,'Independent verifier binds exact fixture');
assert.equal(verification.execution.exitCode,0);assert.equal(verification.execution.observedPredicates,105);assert.equal(verification.execution.observedOpenSslSignatureChecks,7);
assert.equal(verification.opensslObservations.length,7);for(const row of verification.opensslObservations)assert.equal(row.exitCode,0,'Observed independent OpenSSL signature: '+row.id);
const fields={
  keys:['id','owner','flags','protocol','algorithm','lineage','keyTag','publicKeyBase64','publicKeyHex','dnskeyRdataHex','text'],
  rrsets:['id','owner','type','typeCode','class','ttl','records','canonicalRdataHex'],
  signatures:['id','rrsetId','keyId','algorithm','typeCovered','labels','originalTtl','expiration','inception','keyTag','signer','signatureHex','rrsigRdataHex','rrsigText','canonicalRrsetHex','signingInputHex','signingInputSha256','rrsigRdataSha256','verificationAt'],
  nsec3:['id','owner','ownerWireHex','hashAlgorithm','iterations','saltHex','initialHashHex','finalHashHex','hashBase32hex','totalHashApplications']
};
assert.deepEqual(Object.keys(projection).sort(),Object.keys(fields).sort(),'Only declared public namespaces');
const sort=value=>Array.isArray(value)?value.map(sort):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;
const canonical=value=>JSON.stringify(sort(value)).replace(/[\u007f-\uffff]/g,char=>'\\u'+char.charCodeAt(0).toString(16).padStart(4,'0'))+'\n';
assert.equal(hash(canonical(projection)),catalog.publicProjection.canonicalSortedProjectionSha256,'Independent sorted public projection');
const entries={keys:[],rrsets:[],signatures:[],ds:[],nsec3:[],vectors:[]};
for(const [kind,allowed]of Object.entries(fields))for(const [id,value]of Object.entries(projection[kind])){
  assert.equal(value.id,id);assert(Object.keys(value).every(key=>allowed.includes(key)),'Unexpected public field');
  const exact=Object.fromEntries(allowed.filter(key=>Object.hasOwn(fixture[kind][id],key)).map(key=>[key,fixture[kind][id][key]]));
  assert.deepEqual(value,exact,'Public projection preserves exact allowlisted numeric fields: '+id);entries[kind].push([id,value,0]);
}
function noPrivate(value){if(!value||typeof value!=='object')return;for(const[key,child]of Object.entries(value)){assert(!/^(?:private|secret|seed|scalar|pem|generation|derivation|expected|assertion|verificationResult)/i.test(key)&&!['fixtureOnlyPrivateHex','publicKeyPem','provenance','result','valid','verified','verification','checks','passed'].includes(key),'No private/generator/outcome field: '+key);noPrivate(child);}}
noPrivate(entries);
const identity={path:catalogPath,bytes:catalogBytes.length,sha256:hash(catalogBytes),postFreeze:true,replacesFrozenCatalog:false};
const datasets=[{kind:fixture.kind,fixture:catalog.fixture,report:catalog.verification.report,postFreeze:true}];
const text=[
  '// Generated strict public projection of independently verified additive DNSSEC review inputs.',
  '// No private material, producer outcomes, expected classifications or runtime cryptography.',
  'function dnssecReviewFreeze(value){if(value&&typeof value===\'object\'&&!Object.isFrozen(value)){for(const child of Object.values(value))dnssecReviewFreeze(child);Object.freeze(value);}return value;}',
  'export const DNSSEC_REVIEW_CATALOG=dnssecReviewFreeze('+JSON.stringify(identity)+');',
  'export const DNSSEC_REVIEW_DATASETS=dnssecReviewFreeze('+JSON.stringify(datasets)+');',
  'export const DNSSEC_REVIEW_ENTRIES=dnssecReviewFreeze('+JSON.stringify(entries)+');',''
].join('\n');
assert(!/[\u2013\u2014]/.test(text),'Authored projection uses ASCII hyphens');
const output='src/dnssec-review-fixtures.js';
if(mode==='--write')fs.writeFileSync(path.join(root,output),text);else assert.equal(fs.readFileSync(path.join(root,output),'utf8'),text,'Reproducible strict review projection');
console.log(JSON.stringify({result:mode==='--write'?'written':'checked',output,bytes:Buffer.byteLength(text),sha256:hash(text),counts:Object.fromEntries(Object.entries(entries).map(([kind,rows])=>[kind,rows.length])),catalog:identity}));
