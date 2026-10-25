import {readFile,readdir,lstat} from 'node:fs/promises';
import {resolve,relative,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const docs='docs/dnssec-expansion';
const freezePath=join(root,docs,'contract-freeze.json');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=async path=>JSON.parse(await readFile(join(root,path),'utf8'));
const assert=(condition,message)=>{if(!condition)throw new Error(message);};
async function identity(path){const bytes=await readFile(join(root,path));return {path,bytes:bytes.length,sha256:hash(bytes)};}
async function walk(path){
  const entries=await readdir(join(root,path),{withFileTypes:true});const files=[];
  for(const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))){
    if(['.venv','.offline-venv','__pycache__'].includes(entry.name))continue;
    const child=path+'/'+entry.name,stat=await lstat(join(root,child));
    assert(!stat.isSymbolicLink(),'Refusing symlink '+child);
    if(stat.isDirectory())files.push(...await walk(child));else if(stat.isFile())files.push(child);
  }
  return files;
}
async function checkIdentity(record){
  const actual=await identity(record.path);
  assert(actual.bytes===record.bytes&&actual.sha256===record.sha256,'Frozen input changed: '+record.path);
  return actual;
}
async function checkExisting(){
  const frozen=JSON.parse(await readFile(freezePath,'utf8'));
  assert(frozen.kind==='dnssec-pre-evaluator-contract-freeze','Wrong freeze kind');
  for(const input of frozen.inputs)await checkIdentity(input);
  console.log(JSON.stringify({kind:'dnssec-contract-integrity',result:'pass',inputs:frozen.inputs.length,lessons:frozen.totals.lessons,namedCases:frozen.totals.namedCases}));
}
async function seal(){
  const existing=await readdir(join(root,docs));
  assert(!existing.includes('contract-freeze.json'),'Contract already sealed; use --check. Never silently replace an independent oracle.');
  const production=await readdir(join(root,'src'));
  assert(!production.some(name=>/^dnssec.*\.js$/.test(name)),'Seal must precede all production DNSSEC modules');
  const manifest=await json(docs+'/scenario-manifest.json');
  const resolution=await json(docs+'/worksheet-resolution.json');
  const publication=await json(docs+'/worksheet-publication.json');
  assert(resolution.independentOfProduction===true&&publication.independentOfProduction===true,'Both worksheets must be independent');
  const lessons=[...resolution.lessons,...publication.lessons].sort((a,b)=>a.planId.localeCompare(b.planId));
  assert(lessons.length===22&&manifest.rows.length===22,'Expected22 lessons');
  let cases=0;
  for(const row of manifest.rows){
    const lesson=lessons.find(item=>item.planId===row.planId);
    assert(lesson&&lesson.runtimeId===row.runtimeId,'Missing independent lesson '+row.planId);
    assert(lesson.defaultCaseId===row.defaultCaseId,'Default case mismatch '+row.planId);
    assert(JSON.stringify(lesson.cases.map(item=>item.id))===JSON.stringify(row.caseIds),'Case coverage mismatch '+row.planId);
    const seen=new Set();
    for(const item of lesson.cases){
      assert(!seen.has(item.id),'Duplicate named case '+row.planId+'/'+item.id);seen.add(item.id);
      assert(item.setup&&item.profile&&item.ownership&&item.outcome,'Missing literal inputs/expectations '+item.id);
      assert(item.sequence.length&&item.checkpoints.length&&item.sourceSections.length,'Missing sequence/checkpoints/source sections '+item.id);
      assert(item.checkpoints.every(point=>point.name&&point.actorId&&point.expected),'Incomplete checkpoint '+item.id);
      cases++;
    }
  }
  assert(cases===159,'Expected159 named cases, not runtime alias copies');
  const a=await json(docs+'/source-ledger-resolution.json'),b=await json(docs+'/source-ledger-publication.json');
  const groups=[...a.ownedGroups,...b.groups.map(group=>group.id)].sort();
  assert(groups.length===29&&new Set(groups).size===29,'Source groups must cover all29 exactly once');
  assert(groups.every((id,index)=>id==='S'+String(index+1).padStart(2,'0')),'Missing source group');
  assert(!a.unresolvedCaptures?.length,'Unresolved resolution source capture');
  const captures=[...a.captures.map(capture=>({...capture,path:capture.path})),...b.groups.flatMap(group=>group.sources).map(capture=>({...capture,path:docs+'/'+capture.rawPath}))];
  for(const capture of captures){
    assert(capture.path&&capture.sha256&&capture.bytes!=null,'Incomplete capture identity');
    await checkIdentity(capture);
  }
  assert(b.groups.every(group=>group.sources.every(source=>source.httpStatus===200&&source.usableStandard)),'Publication primary capture missing');
  const numeric=await json(docs+'/numeric/FINAL-FIXTURE-IDENTITIES.json');
  assert(numeric.independentOfProduction===true,'Numeric material must be independent');
  assert(numeric.datasetCount===12&&numeric.datasetsAndReports.length===12,'Expected12 independently verified datasets');
  for(const dataset of numeric.datasetsAndReports){
    await checkIdentity(dataset.fixture);
    await checkIdentity(dataset.report);
    assert(dataset.result==='pass'&&dataset.assertions>0,'Numeric verification did not pass '+dataset.fixture.path);
  }
  const merged={schemaVersion:1,kind:'dnssec-independent-worksheet',researchCutoff:'2026-10-23',independentOfProduction:true,totals:{lessons:22,namedCases:159},shards:await Promise.all(['worksheet-resolution.json','worksheet-publication.json'].map(name=>identity(docs+'/'+name))),lessons};
  const mergedPath=docs+'/worksheet.json';
  await writeFile(join(root,mergedPath),JSON.stringify(merged,null,2)+'\n',{flag:'wx'});
  const normalizedLedger={schemaVersion:1,kind:'dnssec-source-ledger',researchCutoff:'2026-10-23',sourceGroups:groups,originalLedgers:await Promise.all(['source-ledger-resolution.json','source-ledger-publication.json'].map(name=>identity(docs+'/'+name))),captures:captures.map(capture=>({group:capture.group,requestedUrl:capture.requestedUrl||capture.url,finalUrl:capture.finalUrl,retrievedAt:capture.retrievedAt,httpStatus:capture.httpStatus,path:capture.path,bytes:capture.bytes,sha256:capture.sha256,usable:!!(capture.usablePrimary||capture.usableStandard)})),failedAttemptPolicy:'Original shard ledgers and numeric provenance retain every failed capture/authoring attempt; failures are not standards.'};
  await writeFile(join(root,docs,'source-ledger.json'),JSON.stringify(normalizedLedger,null,2)+'\n',{flag:'wx'});
  const inputs=[
    docs+'/inputs/worker-plan.html',docs+'/scenario-manifest.json',docs+'/source-groups.json',docs+'/baseline.json',
    docs+'/worksheet-resolution.json',docs+'/worksheet-publication.json',mergedPath,
    docs+'/source-ledger-resolution.json',docs+'/source-ledger-publication.json',docs+'/source-ledger.json',
    docs+'/source-dispositions-resolution.md',docs+'/source-dispositions-publication.md',
    'docs/verification/dnssec-expansion/baseline-location.json','docs/verification/dnssec-expansion/baseline-extract.json',
    'tools/verification/run-next-expansion-performance.mjs',
    ...await walk(docs+'/sources'),...await walk(docs+'/numeric'),...await walk('tools/verification/dnssec-crypto'),
    relative(root,fileURLToPath(import.meta.url)),
  ];
  const frozen={schemaVersion:1,kind:'dnssec-pre-evaluator-contract-freeze',sealedAt:new Date().toISOString(),productionDnssecModulesPresent:false,totals:{sourceGroups:29,lessons:22,namedCases:159,runtimeDefaultAliases:'Alias only; not an extra case'},method:'Independent literal worksheet, immutable primary/errata captures and independently verified numerical inputs sealed before implementing any production DNSSEC evaluator. Browser symbolic execution is not the numeric oracle.',baseline:await identity(docs+'/baseline.json'),inputs:await Promise.all([...new Set(inputs)].sort().map(identity))};
  await writeFile(freezePath,JSON.stringify(frozen,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({kind:frozen.kind,result:'sealed',totals:frozen.totals,inputs:frozen.inputs.length,freeze:await identity(docs+'/contract-freeze.json')}));
}
const mode=process.argv[2];
if(mode==='--check')await checkExisting();else if(mode==='--seal')await seal();else throw new Error('Usage: bun tools/verification/freeze-dnssec-contract.mjs --seal|--check');
