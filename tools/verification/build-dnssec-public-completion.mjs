import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Public data projection only. No application imports and no runtime cryptographic implementation.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),mode=process.argv[2];
assert.ok(mode==='--write'||mode==='--check','Use --write to regenerate the public module or --check');
assert.equal(process.argv.length,3,'Unexpected arguments');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sort=value=>Array.isArray(value)?value.map(sort):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;
const canonical=value=>JSON.stringify(sort(value)).replace(/[\u007f-\uffff]/g,character=>'\\u'+character.charCodeAt(0).toString(16).padStart(4,'0'))+'\n';
const catalogPath='docs/dnssec-expansion/numeric/post-freeze-completion/POST-FREEZE-COMPLETION-CATALOG.json';
const catalogBytes=fs.readFileSync(path.join(root,catalogPath));
assert.equal(hash(catalogBytes),'5cbea7727bdcea3eb75a2e3be542eb38ab6788c1b54f644927ef56613029a0ee','Sealed independent completion catalog');
const catalog=JSON.parse(catalogBytes);
const fields={
  keys:['id','owner','flags','protocol','algorithm','lineage','keyTag','publicKeyBase64','publicKeyHex','dnskeyRdataHex','text'],
  rrsets:['id','owner','type','typeCode','class','ttl','records','canonicalRdataHex'],
  signatures:['id','rrsetId','keyId','algorithm','typeCovered','labels','originalTtl','expiration','inception','keyTag','signer','signatureHex','rrsigRdataHex','rrsigText','canonicalRrsetHex','signingInputHex','signingInputSha256','rrsigRdataSha256','verificationAt'],
  ds:['id','owner','keyId','keyTag','algorithm','digestType','digestInputHex','digestHex','dsRdataHex','text'],
  nsec3:['id','owner','ownerWireHex','hashAlgorithm','iterations','saltHex','initialHashHex','finalHashHex','hashBase32hex','totalHashApplications']
};
const entries={keys:[],rrsets:[],signatures:[],ds:[],nsec3:[],vectors:[]},datasets=[];
function at(value,pointer){return pointer.split('.').reduce((current,key)=>current&&Object.hasOwn(current,key)?current[key]:undefined,value);}
function load(ref){
  const bytes=fs.readFileSync(path.join(root,ref.path));
  assert.equal(bytes.length,ref.bytes,'Exact independent input byte count');
  assert.equal(hash(bytes),ref.sha256,'Exact independent input hash');
  return JSON.parse(bytes);
}
function publicValue(value){
  if(Array.isArray(value))return value.map(publicValue);
  if(!value||typeof value!=='object')return value;
  return Object.fromEntries(Object.entries(value).filter(([key])=>!/^(?:private|secret|seed|scalar|pem|generation|derivation|expected|assertion|verificationResult)/i.test(key)&&!['fixtureOnlyPrivateHex','publicKeyPem','provenance','result','valid','verified','verification','checks','passed'].includes(key)).map(([key,child])=>[key,publicValue(child)]));
}
function projectNamespaces(data,namespaces){
  return Object.fromEntries(Object.entries(namespaces).map(([name,spec])=>{
    if(typeof spec==='string'){
      assert.ok(Object.hasOwn(data,spec),'Declared public namespace exists: '+spec);
      return [name,data[spec]];
    }
    assert.ok(spec&&typeof spec.sourceField==='string'&&Array.isArray(spec.publicFields),'Explicit namespace projection');
    assert.ok(data[spec.sourceField]&&typeof data[spec.sourceField]==='object','Declared public namespace is structured');
    return [name,Object.fromEntries(Object.entries(data[spec.sourceField]).map(([id,value])=>[id,Object.fromEntries(spec.publicFields.filter(key=>Object.hasOwn(value,key)).map(key=>[key,value[key]]))]))];
  }));
}
for(const item of catalog.activeDatasetsAndReports){
  assert.equal(item.referenceVerification,'observed-success');
  const data=load(item.fixture),report=load(item.report),evidence=item.reportSuccessEvidence;
  assert.equal(at(report,item.reportBindingPath),item.fixture.sha256,'Report binds the exact fixture bytes');
  if(evidence.kind==='result')assert.equal(at(report,evidence.path),evidence.value,'Independent reference verification passed');
  else{
    assert.equal(evidence.kind,'signature-observations');
    const observations=at(report,evidence.path);
    assert.equal(observations.length,evidence.count,'Exact independently recorded observation count');
    for(const row of observations)for(const [pointer,value] of Object.entries(evidence.fields))assert.equal(at(row,pointer),value,'Actual independent signature observation: '+pointer);
  }
  const upstream=projectNamespaces(data,item.publicNamespaces);
  assert.equal(hash(canonical(upstream)),item.applicationProjectionSha256,'Independent explicit public-namespace projection');
  const index=datasets.length;
  datasets.push({kind:data.kind||'dnssec-independent-completion-'+item.id,fixture:item.fixture,report:item.report,postFreeze:true});
  for(const [kind,allowed] of Object.entries(fields))for(const [id,value] of Object.entries(upstream[kind]||{})){
    const projected=publicValue(Object.fromEntries(allowed.filter(key=>Object.hasOwn(value,key)).map(key=>[key,value[key]])));
    assert.equal(projected.id,id,'Exact public object identity');
    if(kind==='keys')assert.ok(projected.dnskeyRdataHex&&projected.publicKeyHex,'DNSKEYs, never TSIG descriptors, enter the DNSKEY namespace');
    entries[kind].push([id,projected,index]);
  }
  if(item.id==='dns19'){
    assert.equal(data.id,'dns19-public-reference-vectors');
    const keys=Object.fromEntries(Object.entries(upstream.tsigKeys).map(([id,value])=>[id,publicValue(value)]));
    const vector={id:data.id,baseClock:data.baseClock,keys,messages:publicValue(upstream.messages),streams:publicValue(upstream.streams),updates:publicValue(upstream.updates),macReferenceTuples:publicValue(upstream.macReferenceTuples),zonemdReferenceTuples:publicValue(upstream.zonemdReferenceTuples),managementPolicy:publicValue(upstream.tsigManagementPolicy)};
    entries.vectors.push([data.id,vector,index]);
  }
}
function noPrivate(value){
  if(!value||typeof value!=='object')return;
  for(const [key,child] of Object.entries(value)){
    assert.ok(!/^(?:private|secret|seed|scalar|pem|generation|derivation|expected|assertion|verificationResult)/i.test(key)&&!['fixtureOnlyPrivateHex','publicKeyPem','provenance','result','valid','verified','verification','checks','passed'].includes(key),'No private/generator/outcome field: '+key);
    noPrivate(child);
  }
}
noPrivate(entries);
const identity={path:catalogPath,bytes:catalogBytes.length,sha256:hash(catalogBytes),postFreeze:true,replacesFrozenCatalog:false};
const text=[
  '// Generated public projection of independently verified post-freeze completion references.',
  '// No private bytes, generator derivation labels, producer assertions or expected lesson outcomes.',
  'function dnssecCompletionFreeze(value){if(value&&typeof value===\'object\'&&!Object.isFrozen(value)){for(const child of Object.values(value))dnssecCompletionFreeze(child);Object.freeze(value);}return value;}',
  'export const DNSSEC_COMPLETION_CATALOG=dnssecCompletionFreeze('+JSON.stringify(identity)+');',
  'export const DNSSEC_COMPLETION_DATASETS=dnssecCompletionFreeze('+JSON.stringify(datasets)+');',
  'export const DNSSEC_COMPLETION_ENTRIES=dnssecCompletionFreeze('+JSON.stringify(entries)+');',''
].join('\n');
assert.ok(!/[\u2013\u2014]/.test(text),'Authored source uses ASCII hyphens; never rewrite signed bytes');
const output='src/dnssec-completion-fixtures.js';
if(mode==='--write')fs.writeFileSync(path.join(root,output),text);
else assert.equal(fs.readFileSync(path.join(root,output),'utf8'),text,'Reproducible public-only completion projection');
console.log(JSON.stringify({result:mode==='--write'?'written':'checked',output,bytes:Buffer.byteLength(text),sha256:hash(text),counts:Object.fromEntries(Object.entries(entries).map(([kind,values])=>[kind,values.length])),catalog:identity}));
