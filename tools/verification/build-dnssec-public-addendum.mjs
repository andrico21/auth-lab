import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),mode=process.argv[2];
assert.ok(mode==='--write'||mode==='--check','Use --write to regenerate the public module or --check');
assert.equal(process.argv.length,3,'Unexpected arguments');
const sha=value=>createHash('sha256').update(value).digest('hex');
const catalogPath='docs/dnssec-expansion/numeric/post-freeze-contract-errata/POST-FREEZE-CATALOG.json';
const catalogBytes=fs.readFileSync(path.join(root,catalogPath)),catalog=JSON.parse(catalogBytes);
assert.equal(sha(catalogBytes),'2c8c7a134e56714d09be1371c8b8cd6f90cb8dc1737fe381f78d59f0e53fa7c5');
const fields={
  keys:['id','owner','flags','protocol','algorithm','lineage','keyTag','publicKeyBase64','publicKeyHex','dnskeyRdataHex','text'],
  rrsets:['id','owner','type','typeCode','class','ttl','records','canonicalRdataHex'],
  signatures:['id','rrsetId','keyId','algorithm','typeCovered','labels','originalTtl','expiration','inception','keyTag','signer','signatureHex','rrsigRdataHex','rrsigText','canonicalRrsetHex','signingInputHex','signingInputSha256','rrsigRdataSha256','verificationAt'],
  ds:['id','owner','keyId','keyTag','algorithm','digestType','digestInputHex','digestHex','dsRdataHex','text']
};
const entries={keys:[],rrsets:[],signatures:[],ds:[],nsec3:[],vectors:[]},datasets=[];
function publicValue(value){
  if(Array.isArray(value))return value.map(publicValue);
  if(!value||typeof value!=='object')return value;
  const kind=value.dnskeyRdataHex&&value.publicKeyHex?'keys':value.signatureHex&&value.signingInputHex?'signatures':value.records&&value.type?'rrsets':value.dsRdataHex?'ds':null;
  const allowed=kind?new Set(fields[kind]):null;
  return Object.fromEntries(Object.entries(value).filter(([key])=>allowed?allowed.has(key):!/^(?:private|secret|seed|scalar|pem|expected|assertion|verificationResult)/i.test(key)&&!['fixtureOnlyPrivateHex','publicKeyPem','result','valid','verified','verification','checks','passed'].includes(key)).map(([key,child])=>[key,publicValue(child)]));
}
for(const item of catalog.activeDatasetsAndReports){
  assert.equal(item.result,'pass','Only independently passed active material is application input');
  for(const ref of [item.fixture,item.report]){
    const bytes=fs.readFileSync(path.join(root,ref.path));assert.equal(bytes.length,ref.bytes);assert.equal(sha(bytes),ref.sha256);
  }
  const data=JSON.parse(fs.readFileSync(path.join(root,item.fixture.path))),index=datasets.length;
  datasets.push({kind:data.kind,fixture:item.fixture,report:item.report,postFreeze:true});
  for(const [kind,allowed] of Object.entries(fields))for(const [id,value] of Object.entries(data[kind]||{})){
    const projected=publicValue(Object.fromEntries(allowed.filter(key=>Object.hasOwn(value,key)).map(key=>[key,value[key]])));
    assert.equal(projected.id,id,'Exact public object identity');entries[kind].push([id,projected,index]);
  }
  if(data.signalingChains)entries.vectors.push(['post-freeze-publication:signalingChains',publicValue(data.signalingChains),index]);
  if(data.opaqueDsPayloadProvenance)entries.vectors.push(['post-freeze-publication:opaqueDsPayloadProvenance',publicValue(data.opaqueDsPayloadProvenance),index]);
  if(data.bootstrapSetup){
    const allowed=['child','childClaimKeyId','parentSideNsRrsetId','selectedParentNoDsRrsetId','selectedParentNoDsSignatureId','selectedParentNoDsSource'];
    entries.vectors.push(['post-freeze-publication:bootstrapSetup',Object.fromEntries(allowed.map(key=>[key,data.bootstrapSetup[key]])),index]);
  }
}
assert.equal(entries.keys.length,12);assert.equal(entries.rrsets.length,32);assert.equal(entries.signatures.length,30);assert.equal(entries.ds.length,6);
function noPrivate(value){
  if(!value||typeof value!=='object')return;
  for(const [key,child] of Object.entries(value)){
    assert.ok(!/^(?:private|secret|seed|scalar|pem|expected|assertion|verificationResult)/i.test(key)&&!['fixtureOnlyPrivateHex','publicKeyPem','result','valid','verified','verification','checks','passed'].includes(key),'No private/producer-outcome field: '+key);
    noPrivate(child);
  }
}
noPrivate(entries);
const identity={path:catalogPath,bytes:catalogBytes.length,sha256:sha(catalogBytes),postFreeze:true,replacesFrozenCatalog:false};
const text=[
  '// Generated public projection of the independently verified post-freeze contract addendum.',
  '// No private custody labels, scalar/PEM input, producer assertions or expected lesson outcomes.',
  'function dnssecAddendumFreeze(value){if(value&&typeof value===\'object\'&&!Object.isFrozen(value)){for(const child of Object.values(value))dnssecAddendumFreeze(child);Object.freeze(value);}return value;}',
  'export const DNSSEC_ADDENDUM_CATALOG=dnssecAddendumFreeze('+JSON.stringify(identity)+');',
  'export const DNSSEC_ADDENDUM_DATASETS=dnssecAddendumFreeze('+JSON.stringify(datasets)+');',
  'export const DNSSEC_ADDENDUM_ENTRIES=dnssecAddendumFreeze('+JSON.stringify(entries)+');',''
].join('\n');
assert.ok(!/[\u2013\u2014]/.test(text),'Authored source uses ASCII hyphens; never silently rewrite signed data');
const output='src/dnssec-addendum-fixtures.js';
if(mode==='--write')fs.writeFileSync(path.join(root,output),text);
else assert.equal(fs.readFileSync(path.join(root,output),'utf8'),text,'Reproducible public-only projection');
console.log(JSON.stringify({result:mode==='--write'?'written':'checked',output,bytes:Buffer.byteLength(text),sha256:sha(text),counts:Object.fromEntries(Object.entries(entries).map(([kind,values])=>[kind,values.length])),catalog:identity}));
