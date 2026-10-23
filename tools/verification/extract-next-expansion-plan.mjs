#!/usr/bin/env bun
/** Extract planning contracts only. Does not import product code, fetch sources or run QA. */
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const input=process.argv[2];
if(!input)throw new Error('Usage: bun tools/verification/extract-next-expansion-plan.mjs <authoritative-plan.html> [baseline-compiled-status.json]');
const inventoryPath=path.resolve(process.argv[3]||path.join(root,'docs/verification/review-corrections-recheck/compiled/compiled-bundle-status.json'));
const expectedInputSha256='5a8478ea904e0862da5b0a6e978b7e7389399ffb62890d4e1c7bbee92774a4a0';
const hash=value=>createHash('sha256').update(value).digest('hex');
const decode=value=>value.replace(/&(quot|amp|lt|gt|#x27|#\d+|#x[0-9a-f]+);/gi,(all,key)=>({quot:'"',amp:'&',lt:'<',gt:'>', '#x27':"'"}[key]??(key[0]==='#'?String.fromCodePoint(key[1].toLowerCase()==='x'?parseInt(key.slice(2),16):parseInt(key.slice(1),10)):all)));
const normalize=value=>JSON.parse(JSON.stringify(value).replace(/[\u2013\u2014]/g,'-'));
const raw=fs.readFileSync(input);
if(hash(raw)!==expectedInputSha256)throw new Error('Authoritative input identity mismatch; no files written.');
const html=raw.toString('utf8');
const match=html.match(/<pre\b[^>]*\bid="worker-scenario-ledger"[^>]*>([\s\S]*?)<\/pre>/);
if(!match)throw new Error('Missing worker-scenario-ledger.');
const decoded=decode(match[1]);
const ledger=normalize(JSON.parse(decoded));
const inventoryRaw=fs.readFileSync(inventoryPath),inventory=JSON.parse(inventoryRaw);
const baselineIds=inventory.scenarios.map(row=>row.id);
if(inventory.htmlSha256!==ledger.baselineStandaloneSha256||baselineIds.length!==214||new Set(baselineIds).size!==214)throw new Error('Baseline inventory does not identify all 214 accepted choices.');
const proposedIds=ledger.scenarios.map(row=>row.proposedRuntimeId);
const conflicts=proposedIds.filter((id,index)=>!id||baselineIds.includes(id)||proposedIds.indexOf(id)!==index);
if(conflicts.length)throw new Error('Runtime ID conflicts; no remapping or writes: '+JSON.stringify(conflicts));
if(ledger.scenarios.length!==85||ledger.scenarios.filter(row=>!row.optional).length!==81)throw new Error('Authoritative scope count mismatch.');
const optionalIds=ledger.scenarios.filter(row=>row.optional).map(row=>row.id);
if(JSON.stringify(optionalIds)!==JSON.stringify(['NFS14','WELEV07','K8S16','MCP14']))throw new Error('Optional scope mismatch.');
const lineAt=offset=>html.slice(0,offset).split('\n').length;
const plain=value=>normalize(decode(value.replace(/<br\s*\/?\s*>/gi,'\n').replace(/<[^>]*>/g,' ')).replace(/[\t\r\n ]+/g,' ').trim());
const links=value=>[...value.matchAll(/<a\b[^>]*\bhref="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g)].map(m=>({url:decode(m[1]),label:plain(m[2])}));
const humanEnd=html.indexOf('<section id="ledger"');
const human=html.slice(0,humanEnd);
const domains=[...human.matchAll(/<(?:div|section)\b[^>]*\bid="(domain-[^"]+|handoff|baseline|phases|requirements|phase-zero|catalog|delivery)"[^>]*>/g)].map(m=>({offset:m.index,id:m[1]}));
const domainAt=offset=>domains.filter(item=>item.offset<=offset).at(-1)?.id||'document';
const humanRequirements=[];
let heading=null;
for(const m of human.matchAll(/<(h[1-4]|p|li|tr|pre|summary)\b([^>]*)>([\s\S]*?)<\/\1>/g)){
  if(/^h/.test(m[1]))heading=plain(m[3]);
  const value=m[1]==='pre'?normalize(decode(m[3])):plain(m[3]);
  if(!value)continue;
  humanRequirements.push({id:'human-'+String(humanRequirements.length+1).padStart(4,'0'),domain:domainAt(m.index),heading,element:m[1],sourceLine:lineAt(m.index),text:value,links:links(m[3])});
}
// Source-table rows also retain original columns; plan research is not a retrieved snapshot.
const humanSourceRows=[];
let tableDomain=null;
for(const m of human.matchAll(/<h[234]\b[^>]*>([\s\S]*?)<\/h[234]>|<tr\b([^>]*)>([\s\S]*?)<\/tr>/g)){
  if(m[1]!==undefined){tableDomain=/source.*(?:ledger|register|table)|primary source/i.test(plain(m[1]))?domainAt(m.index):null;continue;}
  if(!tableDomain)continue;
  const columns=[...m[3].matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/g)].map(cell=>plain(cell[1]));
  const rowLinks=links(m[3]).filter(link=>/^https?:/.test(link.url));
  if(!columns.length||!rowLinks.length)continue;
  const anchor=m[2].match(/\bid="([^"]+)"/)?.[1]||null;
  humanSourceRows.push({domain:tableDomain,anchor,columns,links:rowLinks,sourceLine:lineAt(m.index)});
}
const familyDefinitions=[
  {workspace:'files',family:'nfs',label:'NFS access',prefixes:['NFS']},
  {workspace:'workstations',family:'windows-logon',label:'Windows sign-in',prefixes:['WLOG']},
  {workspace:'workstations',family:'windows-elevation',label:'Windows elevation',prefixes:['WELEV']},
  {workspace:'workstations',family:'linux-logon',label:'Linux sign-in',prefixes:['LLOG']},
  {workspace:'workstations',family:'linux-elevation',label:'Linux elevation and local authorization',prefixes:['LELEV']},
  {workspace:'workstations',family:'macos-logon',label:'macOS sign-in',prefixes:['MLOG']},
  {workspace:'workstations',family:'macos-elevation',label:'macOS elevation and local authorization',prefixes:['MELEV']},
  {workspace:'foundations',family:'jwt',label:'JWT foundations',prefixes:['JWT']},
  ...Object.entries(ledger.jwtKubernetesMetadataAndManifests.navigation.kubernetes.families).map(([label,planIds])=>({workspace:'kubernetes',family:({'Human access':'human-access','Token validation':'token-validation','Authorization and RBAC':'authorization-rbac','Workload identity':'workload-identity','Delegation and extensions':'delegation-extensions'})[label],label,planIds})),
  {workspace:'mcp',family:'authorization',label:'MCP authorization',prefixes:['MCP']}
];
const familyOf=row=>familyDefinitions.find(family=>family.planIds?.includes(row.id)||family.prefixes?.some(prefix=>row.id.startsWith(prefix)));
const sourceNamespace=row=>row.id.startsWith('NFS')?'nfs':/^W(?:LOG|ELEV)/.test(row.id)?'windows':/^(?:LLOG|LELEV|MLOG|MELEV)/.test(row.id)?'unix':row.id.startsWith('MCP')?'mcp':'tokens';
const tableNamespace=domain=>({'domain-nfs':'nfs','domain-windows':'windows','domain-unix':'unix','domain-jwt-kubernetes':'tokens','domain-mcp':'mcp'})[domain]||'integration';
const sourceRows=[],sourceIndex=new Map();
function addSource(namespace,source,origin){
  const original=typeof source==='string'?{url:source}:source;
  const key=namespace+'\0'+JSON.stringify(original);
  if(sourceIndex.has(key)){const row=sourceIndex.get(key);row.origins.push(origin);return row.id;}
  const originalId=original.id||null;
  const base='next-'+namespace+'-'+(originalId||'url-'+hash(original.url).slice(0,12));
  const id=sourceRows.some(row=>row.id===base)?base+'-'+hash(JSON.stringify(original)).slice(0,10):base;
  const matchingTables=humanSourceRows.filter(row=>tableNamespace(row.domain)===namespace&&row.links.some(link=>link.url===original.url));
  const row={id,namespace,originalId,original,primaryDocumentUrl:original.url,title:original.title||matchingTables[0]?.links.find(link=>link.url===original.url)?.label||null,sections:original.sections||null,revision:original.revision||original.version||null,planReportedRetrievalDate:original.retrieved||original.retrievedAt||ledger.researchDate,planSourceTableRows:matchingTables,origins:[origin],sourceSnapshotStatus:'pending',snapshot:{requestedReference:original.snapshotReference||null,capturedPath:null,finalUrl:null,retrievedAt:null,sha256:null,bytes:null},disposition:'Plan reference only; no source-page bytes have been retrieved or support/errata status newly verified by this extraction.'};
  sourceRows.push(row);sourceIndex.set(key,row);return id;
}
const sourceReferences=new Map();
for(const row of ledger.scenarios)sourceReferences.set(row.id,row.sources.map((source,index)=>addSource(sourceNamespace(row),source,{type:'scenario',planId:row.id,pointer:'/scenarios/'+ledger.scenarios.indexOf(row)+'/sources/'+index})));
ledger.windowsSourceCatalog.forEach((source,index)=>addSource('windows',source,{type:'windows-source-catalog',pointer:'/windowsSourceCatalog/'+index}));
Object.entries(ledger.jwtKubernetesMetadataAndManifests.sources).forEach(([id,source])=>addSource('tokens',{id,...source},{type:'token-source-catalog',pointer:'/jwtKubernetesMetadataAndManifests/sources/'+id}));
// Include human-only sources and revision/status relationships, including optional followups.
for(const row of humanSourceRows)for(const link of row.links){
  const namespace=tableNamespace(row.domain);
  if(sourceRows.some(source=>source.namespace===namespace&&source.primaryDocumentUrl===link.url))continue;
  addSource(namespace,{...(row.anchor?{id:row.anchor.replace(/^nfs-source-/, '')}:{}),title:link.label,url:link.url,planTableColumns:row.columns},{type:'human-source-table',sourceLine:row.sourceLine});
}
const provenance={
  input:{path:path.relative(root,path.resolve(input)),fileName:path.basename(input),sha256:hash(raw),bytes:raw.length,ledgerSelector:'pre#worker-scenario-ledger',decodedLedgerSha256:hash(decoded)},
  normalization:{policy:'Replace each U+2013 en dash and U+2014 em dash with one ASCII hyphen, preserving adjacent spacing. Decode HTML entities before JSON parsing. The original HTML is not modified.',decodedLedgerCounts:{enDash:(decoded.match(/\u2013/g)||[]).length,emDash:(decoded.match(/\u2014/g)||[]).length},wholeInputCounts:{enDash:(html.match(/\u2013/g)||[]).length,emDash:(html.match(/\u2014/g)||[]).length},scope:'All authored JSON text, including retained human requirements; input identity and input hashes refer to original raw bytes.'},
  baselineInventory:{path:path.relative(root,inventoryPath),sha256:hash(inventoryRaw),standaloneSha256:inventory.htmlSha256,choiceCount:baselineIds.length,choiceIds:baselineIds,evidenceClass:'historical accepted compiled inventory; reused only for runtime-ID preservation/collision checking, not a fresh product result'},
  generator:{path:'tools/verification/extract-next-expansion-plan.mjs',sha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),argv:['bun','tools/verification/extract-next-expansion-plan.mjs',path.relative(root,path.resolve(input)),path.relative(root,inventoryPath)],networkAccess:false,productExecution:false}
};
const releaseGates=[
  {id:'G01',status:'open-manual',requirement:'Actual screen-reader speech/comprehension with named browser/AT/OS, owner, steps and observed results; automated DOM/native screenshots do not close this gate.'},
  {id:'sibling-key-origins',status:'disclosed-historical-omissions',count:6,requirement:'Retain six disclosed sibling-key-origin omissions; this extraction does not close or recharacterize them.'},
  {id:'historical-performance',status:'open-historical-comparison',count:7,artifactSha256:'92ab17825e1a410940edc7b52a4a1a2f8f7e252c3dd340499a7ce420e3775775',requirement:'Fresh expansion comparisons do not clear the seven predecessor flags.'},
  {id:'source-and-platform',status:'pending-snapshots-and-support-gates',requirement:'Research metadata is not captured bytes, native interoperability or installed OS/build evidence. Resolve the plan source discrepancies before corresponding support claims.'},
  {id:'evidence-boundaries',status:'required',requirement:'Distinguish historical, fresh automated, mounted, native, actual touch/zoom, human manual and live-platform evidence; no execution result is supplied by these planning manifests.'}
];
const contracts=ledger.scenarios.map(row=>({...row,runtimeId:row.proposedRuntimeId,family:familyOf(row).family,sourceRowIds:sourceReferences.get(row.id)}));
const acceptanceEntries=[];
const acceptanceFields=['goal','profile','actors','preconditions','steps','negativeCases','acceptance','heldArtifacts','crossLinks','researchGates','sources'];
for(const row of contracts)for(const field of acceptanceFields){
  if(row[field]===undefined)continue;
  const values=Array.isArray(row[field])?row[field]:[row[field]];
  values.forEach((requirement,index)=>acceptanceEntries.push({id:row.id+':'+field+':'+String(index+1).padStart(3,'0'),planId:row.id,runtimeId:row.runtimeId,kind:field,requirement,sourcePointer:'/scenarios/'+contracts.indexOf(row)+'/'+field+(Array.isArray(row[field])?'/'+index:''),sourceRowIds:field==='sources'?[row.sourceRowIds[index]]:row.sourceRowIds,status:'required-not-executed',evidenceIds:[],compoundRequirementPolicy:field==='negativeCases'?'Retain this complete requirement. Family worksheets must expand every named/compound mutation and independently specify the detector, stopping boundary, preserved state and outcome before modeling; no extra picker choice is created.':undefined}));
}
const evidenceBoundary='Planning contracts only. No implementation, test, native, manual, numeric or live-platform pass is claimed.';
const planLedger={schemaVersion:1,kind:'next-expansion-frozen-plan-ledger',provenance,counts:ledger.counts,countRule:ledger.countRule,runtimeIdPolicy:ledger.runtimeIdPolicy,evidenceBoundary,originalPlanMetadata:Object.fromEntries(Object.entries(ledger).filter(([key])=>key!=='scenarios')),humanRequirements,humanSourceRows,releaseGates};
const scenarioManifest={schemaVersion:1,kind:'next-expansion-independent-scenario-contract',provenance,counts:ledger.counts,countRule:ledger.countRule,evidenceBoundary,runtimeIdFreeze:{status:'frozen',policy:'runtimeId equals authoritative proposedRuntimeId for all 85 rows; no remapping. Checked against every accepted baseline choice and every proposed ID.',baselineChoiceCount:214,conflicts:[]},familyMappings:familyDefinitions,filesSmbShortcut:{kind:'navigation-only',canonicalWorkspace:'windows',canonicalFamily:'files',canonicalRoutePattern:'#/windows/files/<existing-smb-runtime-id>',newPickerChoices:0,rule:'Use an existing accepted canonical SMB scenario ID. Never register a duplicate model or migrate its route.'},optionalDeferred:optionalIds.map(planId=>({planId,runtimeId:contracts.find(row=>row.id===planId).runtimeId,status:'optional/deferred',includedInCoreTotal:false})),implementationDisposition:contracts.map(row=>({planId:row.id,runtimeId:row.runtimeId,status:row.optional?'optional/deferred':'not-implemented',reason:'Frozen plan contract; implementation and execution evidence are outside this extraction.',evidenceIds:[]})),scenarios:contracts,acceptanceEntries,releaseGates};
const sourceLedger={schemaVersion:1,kind:'next-expansion-namespaced-source-ledger',provenance,evidenceBoundary,snapshotPolicy:'All snapshots are pending. Plan-reported retrieval dates and source-table research statements are historical planning metadata, not fresh fetched bytes. Null captured fields must remain null until actual source artifacts exist.',sources:sourceRows,scenarioSourceReferences:Object.fromEntries(sourceReferences),humanSourceRows,windowsSourceCatalog:ledger.windowsSourceCatalog,windowsSharedContracts:ledger.windowsSharedContracts,jwtKubernetesMetadataAndManifests:ledger.jwtKubernetesMetadataAndManifests,sourceGateRequirements:humanRequirements.filter(row=>/source|version|profile|research|revision|build|errat|support|discrepanc|draft/i.test(row.heading||'')),releaseGates};
const outputs={'plan-ledger.json':planLedger,'scenario-manifest.json':scenarioManifest,'source-ledger.json':sourceLedger};
const destination=path.join(root,'docs/next-expansion');
fs.mkdirSync(destination,{recursive:true});
for(const [name,value]of Object.entries(outputs))fs.writeFileSync(path.join(destination,name),JSON.stringify(normalize(value),null,2)+'\n');
console.log(JSON.stringify({outputDirectory:'docs/next-expansion',inputSha256:hash(raw),counts:ledger.counts,acceptanceEntries:acceptanceEntries.length,sourceRows:sourceRows.length,humanRequirementBlocks:humanRequirements.length,conflicts:[],evidenceBoundary},null,2));
