import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync,gunzipSync,createGunzip} from 'node:zlib';
import readline from 'node:readline';
import {stableJson,sha256,semanticParameters} from './protected.mjs';

// Exact semantic membership comparison; packed storage positions are not identity.
const producer=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(producer),'../../..');
const usage='bun tools/verification/localization/source-delta.mjs --before=OLD_SOURCE_TABLE.gz --after=NEW_SOURCE_TABLE.gz --before-authoring=OLD_AUTHORING.jsonl.gz --after-authoring=NEW_AUTHORING.jsonl.gz --out=NEW_DIR';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const same=(a,b)=>stableJson(a)===stableJson(b);
const digest=/^[a-f0-9]{64}$/;
const assert=(condition,message)=>{if(!condition)throw new Error(message);};
const identity=file=>{const bytes=fs.readFileSync(file);return {path:file,bytes:bytes.length,sha256:sha256(bytes)};};
const forms=value=>typeof value==='string'?[value]:object(value)&&object(value.plural)&&same(Object.keys(value.plural).sort(),['one','other'])?Object.values(value.plural):null;
const words=text=>(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,'').match(/[A-Za-z]+(?:['-][A-Za-z]+)*/g)||[]).length;
const placeholders=text=>{const result={};for(const match of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g))result[match[1]]=(result[match[1]]||0)+1;return result;};
const signature=binding=>stableJson({key:binding.key,owner:{semanticId:binding.owner.semanticId,fieldPath:binding.owner.fieldPath},context:binding.context,classification:binding.classification});
function table(file){
  const value=JSON.parse(gunzipSync(fs.readFileSync(file)).toString('utf8'));
  assert(value.schemaVersion===2&&value.format==='auth-lab-l10n-source-table','Unsupported source-table format: '+file);
  for(const key of ['schemas','owners','fields','contexts','classifications','bindings'])assert(Array.isArray(value[key]),'Missing source-table array: '+key);
  assert(object(value.keys)&&digest.test(value.sourceSetSha256),'Invalid explicit keys or source-set SHA');
  const {sourceSetSha256,...payload}=value;
  assert(sha256(stableJson(payload))===sourceSetSha256,'Source-set fingerprint mismatch: '+file);
  for(const key of ['owners','fields','classifications'])assert(value[key].every(item=>typeof item==='string'&&item.length)&&new Set(value[key]).size===value[key].length,'Invalid '+key);
  assert(value.classifications.every(item=>['prose','human','human-only','mixed','protected-only'].includes(item)),'Invalid classification');
  assert(value.contexts.every(object)&&new Set(value.contexts.map(stableJson)).size===value.contexts.length,'Invalid contexts');
  const schemas=new Map();
  for(const schema of value.schemas){
    assert(Array.isArray(schema)&&schema.length===4&&digest.test(schema[0])&&!schemas.has(schema[0]),'Invalid or duplicate strong schema');
    const english=forms(schema[1]);
    assert(english&&english.every(text=>typeof text==='string')&&object(schema[2])&&object(schema[3]),'Invalid English/parameters schema');
    assert(same(schema[2],semanticParameters(schema[2])),'Nonsemantic schema parameters');
    for(const definition of Object.values(schema[2]))assert(object(definition)&&['human','protected','source','exact','count'].includes(definition.kind),'Invalid typed parameter');
    assert(sha256(stableJson({english:schema[1],parameters:semanticParameters(schema[2])}))===schema[0],'Strong schema fingerprint mismatch');
    assert(english.every(text=>same(placeholders(text),schema[3])),'Placeholder counts mismatch');
    schemas.set(schema[0],schema);
  }
  const dimensions=[value.schemas,value.owners,value.fields,value.contexts,value.classifications];
  for(const row of value.bindings)assert(Array.isArray(row)&&row.length===5&&row.every((index,i)=>Number.isInteger(index)&&index>=0&&index<dimensions[i].length),'Invalid binding tuple');
  const explicit=new Map();
  for(const [key,index] of Object.entries(value.keys)){assert(key.length&&Number.isInteger(index)&&index>=0&&index<value.bindings.length&&!explicit.has(index),'Invalid explicit UI key');explicit.set(index,key);}
  return {value,schemas,explicit};
}
async function collect(file,source){
  const {value,schemas,explicit}=source,memberships=new Map(),seen=new Uint8Array(value.bindings.length),keys=new Set();
  const workload={schemaVersion:1,scope:'Distinct typed English source workload and editorial candidates, not asserted cross-owner translation equality or native acceptance.',englishForms:0,englishTemplateBytes:0,literalEnglishWordTokens:0,sharedStrongSchemaCandidates:0,shortSharedSchemaCandidatesIncludingProtectedOnly:0,shortSharedHumanProseReviewCandidates:0,shortSharedHumanProseCandidates:[]};
  const input=fs.createReadStream(file),decoded=input.pipe(createGunzip());
  input.on('error',error=>decoded.destroy(error));
  for await(const line of readline.createInterface({input:decoded,crlfDelay:Infinity})){
    if(!line.trim())continue;
    const group=JSON.parse(line),schema=schemas.get(group.sourceSha256);
    assert(schema&&!memberships.has(group.sourceSha256)&&Number.isInteger(group.schemaIndex)&&value.schemas[group.schemaIndex]===schema,'Unknown/duplicate authoring group or schema index');
    assert(same(group.english,schema[1])&&object(group.parameters)&&same(semanticParameters(group.parameters),schema[2]),'Authoring English/typed parameters mismatch');
    assert(Array.isArray(group.bindings)&&group.bindings.length,'Missing authoring memberships');
    const signatures=new Set(),ownerIds=new Set(),fields=new Set();
    for(const binding of group.bindings){
      const index=binding.storageBindingIndex,row=value.bindings[index];
      assert(Number.isInteger(index)&&index>=0&&row&&!seen[index]&&row[0]===group.schemaIndex,'Invalid, duplicate or wrong-schema authoring binding');
      assert(typeof binding.key==='string'&&binding.key.length&&!keys.has(binding.key)&&object(binding.owner)&&object(binding.context),'Invalid/duplicate authoring key or membership');
      assert(binding.owner.semanticId===value.owners[row[1]]&&binding.owner.fieldPath===value.fields[row[2]]&&same(binding.context,value.contexts[row[3]])&&binding.classification===value.classifications[row[4]],'Authoring semantic binding mismatch');
      assert(!explicit.has(index)||explicit.get(index)===binding.key,'Explicit UI key mismatch');
      if(Object.hasOwn(value.keys,binding.key))assert(value.keys[binding.key]===index,'Explicit UI index mismatch');
      if(Object.hasOwn(binding,'sourceSha256'))assert(binding.sourceSha256===group.sourceSha256,'Binding source SHA mismatch');
      if(Object.hasOwn(binding,'english'))assert(same(binding.english,group.english),'Binding English mismatch');
      if(Object.hasOwn(binding,'parameters'))assert(same(semanticParameters(binding.parameters),schema[2]),'Binding typed parameters mismatch');
      const sig=signature(binding);assert(!signatures.has(sig),'Duplicate semantic membership');
      signatures.add(sig);keys.add(binding.key);seen[index]=1;ownerIds.add(binding.owner.semanticId);fields.add(binding.owner.fieldPath);
    }
    memberships.set(group.sourceSha256,signatures);
    const english=forms(group.english);
    workload.englishForms+=english.length;workload.englishTemplateBytes+=english.reduce((sum,text)=>sum+Buffer.byteLength(text),0);workload.literalEnglishWordTokens+=english.reduce((sum,text)=>sum+words(text),0);
    if(ownerIds.size>1){workload.sharedStrongSchemaCandidates++;if(english.every(text=>words(text)<=4)){workload.shortSharedSchemaCandidatesIncludingProtectedOnly++;if(english.some(text=>words(text)>0))workload.shortSharedHumanProseCandidates.push({sourceSha256:group.sourceSha256,english:group.english,ownerCount:ownerIds.size,bindingCount:group.bindings.length,fieldPaths:[...fields].sort()});}}
  }
  assert(memberships.size===schemas.size&&seen.every(item=>item===1)&&keys.size===value.bindings.length,'Authoring groups or binding memberships truncated/missing');
  workload.shortSharedHumanProseCandidates.sort((a,b)=>a.sourceSha256.localeCompare(b.sourceSha256));
  workload.shortSharedHumanProseReviewCandidates=workload.shortSharedHumanProseCandidates.length;
  return {memberships,workload};
}
function writeJson(out,name,value){fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});}
function writePacked(out,name,value){const raw=Buffer.from(stableJson(value)+'\n'),packed=gzipSync(raw,{level:9});assert(gunzipSync(packed).equals(raw),'Gzip decode identity failure');fs.writeFileSync(path.join(out,name),packed,{flag:'wx'});return {path:name,format:'gzip JSON',bytes:packed.length,sha256:sha256(packed),decodedBytes:raw.length,decodedSha256:sha256(raw),decodeIdentityVerified:true};}
async function main(){
  const args={};for(const argument of process.argv.slice(2)){const match=/^--(before|after|before-authoring|after-authoring|out)=(.+)$/.exec(argument);assert(match&&!Object.hasOwn(args,match[1]),usage);args[match[1]]=path.resolve(match[2]);}
  assert(Object.keys(args).length===5,usage);
  const out=args.out,parent=fs.realpathSync(path.dirname(out));
  const relative=path.relative(fs.realpathSync(root),parent);assert(relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative),'Output must be external to repository');
  fs.mkdirSync(out); // Exclusive creation: an existing directory is never reused.
  const report={schemaVersion:1,status:'unperformed',scope:'Exact strong schemas and complete semantic memberships. English interning is storage only. Unchanged strong SHA with changed membership NEEDS context review; no automatic Native acceptance, verdict rebase, approval or waiver.',usage,argv:process.argv.slice(),runtime:{execPath:process.execPath,version:process.version,versions:process.versions},repositoryRoot:root,outputDirectory:out,inputs:{},producers:[],checks:{collection:'unperformed',identityRecheck:'unperformed'}};
  try{
    report.producers=[producer,path.join(path.dirname(producer),'protected.mjs')].map(identity);
    report.runtime.executable=identity(process.execPath);
    for(const key of ['before','after','before-authoring','after-authoring'])report.inputs[key]=identity(args[key]);
    const before=table(args.before),after=table(args.after);
    const old=await collect(args['before-authoring'],before),current=await collect(args['after-authoring'],after);
    const unchanged=[],added=[],removed=[],changes=[],unchangedMembershipSchemas=[];
    for(const hash of before.schemas.keys())if(!after.schemas.has(hash))removed.push(hash);
    for(const hash of after.schemas.keys()){
      if(!before.schemas.has(hash)){added.push(hash);continue;}
      unchanged.push(hash);assert(same(before.schemas.get(hash),after.schemas.get(hash)),'Strong schema collision across inputs');
      const prior=old.memberships.get(hash),next=current.memberships.get(hash),plus=[...next].filter(item=>!prior.has(item)).sort(),minus=[...prior].filter(item=>!next.has(item)).sort();
      if(plus.length||minus.length)changes.push({sourceSha256:hash,beforeBindings:prior.size,afterBindings:next.size,added:plus.map(JSON.parse),removed:minus.map(JSON.parse),reviewObligation:'NEEDS context review'});else unchangedMembershipSchemas.push(hash);
    }
    for(const list of [unchanged,added,removed,unchangedMembershipSchemas])list.sort();changes.sort((a,b)=>a.sourceSha256.localeCompare(b.sourceSha256));
    const strong={schemaVersion:1,scope:report.scope,parentSourceSetSha256:before.value.sourceSetSha256,currentSourceSetSha256:after.value.sourceSetSha256,before:{schemas:before.schemas.size,bindings:before.value.bindings.length},after:{schemas:after.schemas.size,bindings:after.value.bindings.length},unchanged,added,removed};
    const membership={schemaVersion:1,scope:report.scope,unchangedStrongSchemasWithUnchangedMembership:unchangedMembershipSchemas.length,unchangedStrongSchemasWithChangedMembership:changes.length,unchangedMembershipSchemas,changes};
    // Added/removed schemas retain every exact binding as well as their strong SHA lists.
    strong.addedSchemas=added.map(sourceSha256=>({sourceSha256,schema:after.schemas.get(sourceSha256),bindings:[...current.memberships.get(sourceSha256)].sort().map(JSON.parse)}));
    strong.removedSchemas=removed.map(sourceSha256=>({sourceSha256,schema:before.schemas.get(sourceSha256),bindings:[...old.memberships.get(sourceSha256)].sort().map(JSON.parse)}));
    report.checks.collection='passed';
    const identities=[...Object.values(report.inputs),...report.producers,report.runtime.executable];
    const rechecked=identities.map(item=>{const current=identity(item.path);return {...current,unchanged:same(item,current)};});
    report.identityRecheck=rechecked;assert(rechecked.every(item=>item.unchanged),'Input or producer bytes changed during collection');report.checks.identityRecheck='passed';
    report.parentSourceSetSha256=strong.parentSourceSetSha256;report.currentSourceSetSha256=strong.currentSourceSetSha256;report.before=strong.before;report.after=strong.after;
    report.counts={unchanged:unchanged.length,added:added.length,removed:removed.length,unchangedStrongSchemasWithUnchangedMembership:unchangedMembershipSchemas.length,unchangedStrongSchemasWithChangedMembership:changes.length,addedMemberships:changes.reduce((n,row)=>n+row.added.length,0),removedMemberships:changes.reduce((n,row)=>n+row.removed.length,0)};
    report.artifacts={strongSchemaDelta:writePacked(out,'strong-schema-delta.json.gz',strong),schemaMembershipDelta:writePacked(out,'schema-membership-delta.json.gz',membership),sourceWorkload:writePacked(out,'source-workload.json.gz',current.workload)};
    report.status='collected';report.acceptance='Not performed; context review remains required for every changed membership.';
  }catch(error){report.status='failed';report.error={name:error.name,message:error.message,stack:error.stack};process.exitCode=1;}
  writeJson(out,'source-delta-summary.json',report);console.log(JSON.stringify({status:report.status,report:path.join(out,'source-delta-summary.json'),counts:report.counts,error:report.error?.message}));
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
