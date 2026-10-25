#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {captureReviewInputs} from './review-input-identity.mjs';

const dnRunner=fileURLToPath(import.meta.url),dnRoot=path.resolve(path.dirname(dnRunner),'../..');
const dnArgs=process.argv.slice(2);
if(dnArgs.includes('--help')){console.log('Usage: bun tools/verification/check-dnssec-numeric.mjs --out NEW_DIRECTORY\nChecks public source arithmetic/reference matching against all four sealed independent numeric catalogs. No live DNS or native cryptography is performed by this runner.');process.exit(0);}
assert.equal(dnArgs.length,2);assert.equal(dnArgs[0],'--out');
const dnOut=path.resolve(dnArgs[1]);fs.mkdirSync(dnOut,{recursive:false});
const dnSha=bytes=>createHash('sha256').update(bytes).digest('hex');
const dnRefs=new Map();
function dnLoad(relative,expected){
  const bytes=fs.readFileSync(path.join(dnRoot,relative)),ref={path:relative,bytes:bytes.length,sha256:dnSha(bytes)};
  if(expected)assert.equal(ref.sha256,expected,'Exact sealed independent input: '+relative);
  dnRefs.set(relative,ref);return JSON.parse(bytes);
}
const dnReport={schemaVersion:1,kind:'DNSSEC-independent-numeric-to-source-gate',passed:false,scope:'Public source canonicalization, key tags, reference-bound mathematical matching, eligibility, DS, serial arithmetic, TTL and chain boundaries. Independent native cryptographic calculations are the separately captured pinned Python/OpenSSL producer reports, not browser execution or live DNS.',argv:process.argv,runtime:{executable:process.execPath,bun:process.versions.bun,version:process.version},runner:{path:path.relative(dnRoot,dnRunner),sha256:dnSha(fs.readFileSync(dnRunner))},cases:[],failures:[]};
const dnBefore=captureReviewInputs(dnRoot,dnRunner);
function dnTest(name,fn){try{const details=fn();dnReport.cases.push({name,passed:true,...details});}catch(error){dnReport.cases.push({name,passed:false});dnReport.failures.push({name,error:String(error.stack||error)});}}
try{
  const catalogs=[
    ['docs/dnssec-expansion/numeric/FINAL-FIXTURE-IDENTITIES.json','97b4e87155826dbfd184687c821bf842a5a68901c567977a84ba3ce93577027f'],
    ['docs/dnssec-expansion/numeric/post-freeze-contract-errata/POST-FREEZE-CATALOG.json','2c8c7a134e56714d09be1371c8b8cd6f90cb8dc1737fe381f78d59f0e53fa7c5'],
    ['docs/dnssec-expansion/numeric/post-freeze-completion/POST-FREEZE-COMPLETION-CATALOG.json','5cbea7727bdcea3eb75a2e3be542eb38ab6788c1b54f644927ef56613029a0ee']
  ].map(([file,hash])=>dnLoad(file,hash));
  const reviewCatalog=dnLoad('docs/dnssec-expansion/numeric/review-corrections/PUBLIC-CATALOG.json','7f2eba596704ba73bddc3d20a1616b8ecce9cd6b8b4a57229df0a511b1c43f28');
  assert.equal(reviewCatalog.verification.observedPredicates,105);
  assert.equal(reviewCatalog.verification.observedOpenSslSignatureChecks,7);
  catalogs.push({activeDatasetsAndReports:[{fixture:reviewCatalog.fixture,report:reviewCatalog.verification.report}]});
  const inputs=[];
  for(const catalog of catalogs)for(const item of catalog.datasetsAndReports||catalog.activeDatasetsAndReports){
    const data=dnLoad(item.fixture.path,item.fixture.sha256);
    assert.equal(dnRefs.get(item.fixture.path).bytes,item.fixture.bytes);
    dnLoad(item.report.path,item.report.sha256);assert.equal(dnRefs.get(item.report.path).bytes,item.report.bytes);
    inputs.push({data,fixture:item.fixture,report:item.report});
  }
  const independent={keys:new Map(),rrsets:new Map(),signatures:new Map(),ds:new Map(),nsec3:new Map()};
  const scalarInputs=new Set();
  for(const input of inputs){
    const data=input.data;
    for(const key of Object.values(data.keys||{}))if(key.generation?.fixtureOnlyPrivateHex)scalarInputs.add(key.generation.fixtureOnlyPrivateHex);
    for(const kind of Object.keys(independent)){
      const values=kind==='keys'?(data.dnssecKeys||data.keys||data.keyReferences||{}):data[kind]||{};
      for(const [id,value] of Object.entries(values)){
        if(kind==='keys'&&!value.dnskeyRdataHex)continue; // TSIG descriptors are a different namespace.
        if(!independent[kind].has(id))independent[kind].set(id,{value,origins:[input.fixture.path]});
        else independent[kind].get(id).origins.push(input.fixture.path);
      }
    }
  }
  const material=await import(pathToFileURL(path.join(dnRoot,'src/dnssec-fixtures.js')).href);
  const math=await import(pathToFileURL(path.join(dnRoot,'src/dnssec-validation.js')).href);
  const m=material.DNSSEC_MATERIAL;
  for(const kind of Object.keys(independent))dnTest('complete-public-'+kind,()=>{
    assert.deepEqual(Object.keys(m[kind]).sort(),[...independent[kind].keys()].sort(),'All independently declared public objects are present, without TSIG/DNSKEY confusion');
    return {objects:independent[kind].size};
  });
  for(const [id,{value:key,origins}] of independent.keys)dnTest('key-tag-and-public-bytes:'+id,()=>{
    const actual=m.keys[id];
    for(const field of ['id','owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex','keyTag'])assert.deepEqual(actual[field],key[field],field);
    assert.equal(math.dnssecKeyTag(actual.dnskeyRdataHex),key.keyTag);return {origins};
  });
  for(const [id,{value:rrset,origins}] of independent.rrsets)dnTest('immutable-rrset:'+id,()=>{
    for(const field of ['id','owner','type','typeCode','class','ttl','records'])assert.deepEqual(m.rrsets[id][field],rrset[field],field);
    return {origins};
  });
  for(const [id,{value:signature,origins}] of independent.signatures)dnTest('canonical-signature-reference:'+id,()=>{
    const rrset=m.rrsets[signature.rrsetId],sig=m.signatures[id],key=m.keys[signature.keyId];
    assert.ok(rrset&&sig&&key,'Independent exact RRset/signature/public-key tuple resolves');
    for(const field of ['keyId','rrsetId','algorithm','typeCovered','labels','originalTtl','inception','expiration','keyTag','signer','signatureHex','rrsigRdataHex'])assert.deepEqual(sig[field],signature[field],field);
    assert.equal(m.provenance.signatureRdataSha256[id],dnSha(Buffer.from(signature.rrsigRdataHex,'hex')),'Displayed public RRSIG fingerprint is bound to independently sealed wire bytes');
    assert.equal(math.dnssecCanonicalInput(rrset,sig),signature.signingInputHex,'Actual rebuilt canonical signed bytes match independent calculation');
    const span=(signature.expiration-signature.inception)>>>0;
    assert.ok(span<2147483648,'Selected positive fixture has an unambiguous serial validity interval');
    const now=(signature.inception+Math.floor(span/2))>>>0;
    const checked=math.dnssecCheckSignature({rrset,signatures:[sig],keys:[key],now,policy:material.dnssecProfile(),expectedSigner:signature.signer});
    assert.equal(checked.mathematicalResult,true,'Known positive independent tuple comparison');
    if(key.protocol!==3||(key.flags&256)===0)assert.equal(checked.valid,false,'Mathematical validity cannot repair ineligible DNSKEY metadata');
    const changed={...sig,signatureHex:(parseInt(sig.signatureHex.slice(0,2),16)^1).toString(16).padStart(2,'0')+sig.signatureHex.slice(2)};
    assert.equal(math.dnssecCheckSignature({rrset,signatures:[changed],keys:[key],now,policy:material.dnssecProfile(),expectedSigner:signature.signer}).valid,false,'Changed signature bytes never pass on object IDs');
    return {origins,clock:now,mathematicalResult:checked.mathematicalResult,usable:checked.valid};
  });
  for(const [id,{value:ds,origins}] of independent.ds)dnTest('owner-key-ds-digest:'+id,()=>{
    for(const field of ['id','owner','keyId','keyTag','algorithm','digestType','digestInputHex','digestHex','dsRdataHex'])assert.deepEqual(m.ds[id][field],ds[field],field);
    const policy=material.dnssecProfile(ds.digestType===1?'legacy-ds-sha1':'modern');
    assert.equal(math.dnssecDsMatchesKey(m.ds[id],m.keys[ds.keyId],policy).valid,true,'Exact public owner/DNSKEY digest input');
    const changed={...m.ds[id],digestHex:'00'+m.ds[id].digestHex.slice(2)};
    if(changed.digestHex!==m.ds[id].digestHex)assert.equal(math.dnssecDsMatchesKey(changed,m.keys[ds.keyId],policy).valid,false,'Digest mutation is not a key-tag match');
    return {origins,digestType:ds.digestType};
  });
  for(const [id,{value:tuple,origins}] of independent.nsec3)dnTest('independent-nsec3-reference:'+id,()=>{
    for(const field of ['id','owner','hashAlgorithm','iterations','saltHex','hashBase32hex'])assert.deepEqual(m.nsec3[id][field],tuple[field],field);
    return {origins};
  });
  for(const input of inputs)for(const vector of input.data.vectors?.['signature-time']||[])dnTest('serial-time:'+vector.id,()=>{
    assert.equal(math.dnssecSignatureTime(vector.now,vector.inception,vector.expiration).reason,vector.expected);return {source:input.fixture.path};
  });
  for(const [field,expected] of [['receivedTtl',11],['rrsigTtl',12],['originalTtl',13],['signatureExpiration',14]])dnTest('ttl-limiting-term:'+field,()=>{
    const values={receivedTtl:300,rrsigTtl:300,originalTtl:300,signatureExpiration:1792713900,now:1792713600};values[field]=field==='signatureExpiration'?1792713600+expected:expected;
    assert.equal(math.dnssecTtlWindow(values).remainingSeconds,expected);
  });
  dnTest('actual-key-and-rdata-mutations',()=>{
    const rrset=m.rrsets['www-a'],signature=m.signatures['www-a-signature'],key=m.keys['child-zsk-g1'];
    const options={rrset,signatures:[signature],keys:[key],now:1792713600};
    assert.equal(math.dnssecCheckSignature({...options,rrset:{...rrset,records:['192.0.2.82','192.0.2.81']}}).valid,false);
    assert.equal(math.dnssecCheckSignature({...options,keys:[{...key,publicKeyHex:'00'+key.publicKeyHex.slice(2)}]}).valid,false);
  });
  dnTest('signature-mathematics-versus-time-eligibility',()=>{
    const rrset=m.rrsets['www-a'],signature=m.signatures['www-a-signature'],key=m.keys['child-zsk-g1'];
    for(const now of [signature.inception-1,signature.expiration+1]){
      const result=math.dnssecCheckSignature({rrset,signatures:[signature],keys:[key],now});
      assert.equal(result.mathematicalResult,true);assert.equal(result.valid,false);
    }
  });
  dnTest('same-tag-different-public-key-candidates',()=>{
    let collisions=0;
    for(const signature of Object.values(m.signatures)){
      const correct=m.keys[signature.keyId];
      const wrong=Object.values(m.keys).find(key=>key.owner===correct.owner&&key.algorithm===correct.algorithm&&key.keyTag===correct.keyTag&&key.publicKeyHex!==correct.publicKeyHex);
      if(!wrong||correct.protocol!==3||(correct.flags&256)===0)continue;
      const now=(signature.inception+Math.floor(((signature.expiration-signature.inception)>>>0)/2))>>>0;
      const options={rrset:m.rrsets[signature.rrsetId],signatures:[signature],now,expectedSigner:signature.signer};
      assert.equal(math.dnssecCheckSignature({...options,keys:[wrong]}).valid,false);
      assert.equal(math.dnssecCheckSignature({...options,keys:[wrong,correct]}).valid,true);collisions++;
    }
    assert.ok(collisions,'Actual fixed colliding public-key candidates were exercised');return {collisions};
  });
  dnTest('public-projection-has-no-private-scalar-input',()=>{
    const names=['src/dnssec-fixtures.js','src/dnssec-addendum-fixtures.js','src/dnssec-completion-fixtures.js','src/dnssec-review-fixtures.js','dist/auth-flow-studio.html'];
    for(const name of names){const text=fs.readFileSync(path.join(dnRoot,name),'utf8');assert.ok(!text.includes('fixtureOnlyPrivateHex'),name);assert.ok(!text.includes('synthetic-private-regeneration:'),name);for(const scalar of scalarInputs)assert.ok(!text.includes(scalar),'Synthetic private scalar is absent from '+name);}
    return {sourceFiles:names,independentSyntheticScalarInputsChecked:scalarInputs.size};
  });
  dnReport.totals=Object.fromEntries(Object.entries(independent).map(([kind,items])=>[kind,items.size]));
  dnReport.independentInputs=[...dnRefs.values()];
  dnReport.inputIdentity=dnBefore;
  dnReport.identityUnchanged=JSON.stringify(captureReviewInputs(dnRoot,dnRunner))===JSON.stringify(dnBefore);
  assert.ok(dnReport.identityUnchanged,'Source/tools/HTML inputs unchanged during the gate');
  dnReport.passed=dnReport.failures.length===0;
}catch(error){dnReport.failures.push({name:'setup-or-integrity',error:String(error.stack||error)});}
dnReport.status=dnReport.passed?'passed':'failed';dnReport.exitCode=dnReport.passed?0:1;
fs.writeFileSync(path.join(dnOut,'numeric-status.json'),JSON.stringify(dnReport,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:dnReport.passed,checks:dnReport.cases.length,totals:dnReport.totals,failures:dnReport.failures}));
process.exitCode=dnReport.exitCode;
