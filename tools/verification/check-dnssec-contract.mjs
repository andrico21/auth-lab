#!/usr/bin/env bun
/** Independent DNSSEC worksheet gate and canonical projection references.
 * Neither mode performs DNS, native crypto, native browser or accessibility acceptance.
 * Emitted mode evaluates the original script, then uses its App and lexical helpers.
 * journal.jsonl and exclusive cases/ fragments preserve bounded diagnostics and
 * completed projections if interrupted; neither substitutes for final all-case
 * status.json and the complete aggregate canonical-prefix reference.
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {performance} from 'node:perf_hooks';
import {captureReviewInputs} from './review-input-identity.mjs';

const dcRunner=fileURLToPath(import.meta.url);
const dcSha=value=>createHash('sha256').update(value).digest('hex');
const dcHash=value=>dcSha(JSON.stringify(value));
const dcJson=file=>JSON.parse(fs.readFileSync(file,'utf8'));
const dcOwn=(value,key)=>value!=null&&Object.hasOwn(value,key);
const dcNormalize=frame=>frame.holdings.map(({artifactId,actorId,store,representationId,holdingId})=>({artifactId,actorId,store,representationId,holdingId})).sort((a,b)=>a.holdingId.localeCompare(b.holdingId));
const dcCopy=value=>JSON.parse(JSON.stringify(value));
// Only recursively frozen, accessor-free ordinary data may reuse a JSON-shaped
// copy. Mutable records and replacements are read again at every prefix.
function dcPreservedValue(value,memo,active=new Set()){
  if(value===null||typeof value!=='object'){
    if(typeof value==='bigint')throw new TypeError('Cannot JSON-copy a BigInt.');
    return {value:typeof value==='number'?Number.isFinite(value)?value===0?0:value:null:['function','symbol'].includes(typeof value)?undefined:value,immutable:true};
  }
  const cached=memo.get(value);if(cached)return cached;
  if(active.has(value))throw new TypeError('Cannot JSON-copy cyclic preservation data.');
  const ordinary=Array.isArray(value)||[Object.prototype,null].includes(Object.getPrototypeOf(value));
  if(!ordinary||typeof value.toJSON==='function')return {value:dcCopy(value),immutable:false};
  active.add(value);
  let immutable=Object.isFrozen(value);
  const result=Array.isArray(value)?[]:{};
  const read=key=>{
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    if(!descriptor||!dcOwn(descriptor,'value'))immutable=false;
    const child=dcPreservedValue(value[key],memo,active);immutable=immutable&&child.immutable;return child.value;
  };
  if(Array.isArray(value)){
    for(let index=0;index<value.length;index++){const child=read(String(index));result.push(child===undefined?null:child);}
  }else{
    for(const key of Object.keys(value)){const child=read(key);if(child!==undefined)Object.defineProperty(result,key,{value:child,writable:true,enumerable:true,configurable:true});}
  }
  active.delete(value);
  const projected={value:result,immutable};if(immutable)memo.set(value,projected);return projected;
}
let dcJournal=null;
const dcActiveStages=new WeakMap();
function dcNote(row,kind,stage,detail={}){
  if(!dcJournal)return;
  const counters={};
  for(const key of ['assertions','prefixes','messages','dnsPackets','replayPositions','backwardPositions','replayedFields','fieldRows','exactObjects','exactRows'])counters[key]=row[key]||0;
  const line=JSON.stringify({schemaVersion:1,kind,id:row.id??null,caseId:row.caseId??null,variant:row.variant??null,stage,elapsedMs:Number((performance.now()-dcJournal.started).toFixed(3)),...counters,failures:row.failures.length,...detail})+'\n';
  if(fs.writeSync(dcJournal.fd,line)!==Buffer.byteLength(line))throw new Error('Incomplete diagnostic journal write.');
}
function dcTimed(row,name,fn){
  // Prefix assertions remain granular; their progress is journaled in bounded
  // aggregates rather than two journal records for every canonical cursor.
  if(name.startsWith('prefix:'))return fn();
  const previous=dcActiveStages.get(row),started=performance.now(),assertions=row.assertions,failures=row.failures.length;
  dcActiveStages.set(row,name);dcNote(row,'stage-start',name);
  let thrown;
  try{return fn();}catch(error){thrown=error;throw error;}
  finally{
    dcNote(row,'stage-end',name,{stageElapsedMs:Number((performance.now()-started).toFixed(3)),assertionsDelta:row.assertions-assertions,failuresDelta:row.failures.length-failures,...(thrown?{threw:true,error:dcBound(String(thrown.stack||thrown))}:{})});
    if(previous===undefined)dcActiveStages.delete(row);else dcActiveStages.set(row,previous);
  }
}
const dcHelp='Usage: bun tools/verification/check-dnssec-contract.mjs --root PATH --worksheet PATH --out NEW_DIRECTORY --mode source|emitted\nWorksheet paths are relative to --root unless absolute. Build first for emitted mode. Output parent must exist; output directory must not exist. No output is overwritten. status.json contains every failure; canonical-prefix-reference.json is projection equivalence data, not an independent outcome oracle. journal.jsonl preserves bounded per-case/stage/failure diagnostics during execution; a partial journal is never acceptance.';
function dcArgs(){
  const args={};
  for(let n=2;n<process.argv.length;n++){
    const key=process.argv[n];
    if(['--help','-h'].includes(key)){console.log(dcHelp);process.exit(0);}
    if(!['--root','--worksheet','--out','--mode'].includes(key)||!process.argv[n+1]||process.argv[n+1].startsWith('--'))throw new Error(dcHelp+'\nInvalid argument: '+key);
    if(dcOwn(args,key.slice(2)))throw new Error('Duplicate argument: '+key);
    args[key.slice(2)]=process.argv[++n];
  }
  for(const key of ['root','worksheet','out','mode'])if(!args[key])throw new Error('Required --'+key+'\n'+dcHelp);
  if(!['source','emitted'].includes(args.mode))throw new Error('Mode must be source or emitted');
  args.root=path.resolve(args.root);args.worksheet=path.resolve(args.root,args.worksheet);args.out=path.resolve(args.out);
  return args;
}
function dcBound(value){
  if(value===undefined)return {type:'undefined'};
  const text=JSON.stringify(value);
  return text.length<=8192?value:{sha256:dcSha(text),bytes:Buffer.byteLength(text),preview:text.slice(0,8192)};
}
function dcJournalFailureValue(value){
  if(dcOwn(value,'dnssec')||dcOwn(value?.state,'dnssec')){
    const text=JSON.stringify(value);return {type:'protocol-state',sha256:dcSha(text),bytes:Buffer.byteLength(text)};
  }
  return dcBound(value);
}
function dcFailure(row,check,location,expected,actual,detail){
  const failure={check,path:location,expected:dcBound(expected),actual:dcBound(actual),...(detail?{detail}:{} )};
  row.failures.push(failure);
  dcNote(row,'failure',dcActiveStages.get(row)||(row.id?'case-execution':'runner'),{failureIndex:row.failures.length-1,failure:{...failure,expected:dcJournalFailureValue(expected),actual:dcJournalFailureValue(actual),...(detail?{detail:dcBound(detail)}:{})}});
}
function dcCheck(row,condition,check,location,expected,actual){
  row.assertions++;
  if(!condition)dcFailure(row,check,location,expected,actual);
  return !!condition;
}
function dcEqual(row,actual,expected,check,location){return dcCheck(row,isDeepStrictEqual(actual,expected),check,location,expected,actual);}
function dcStage(row,name,fn){
  return dcTimed(row,name,()=>{try{return fn();}catch(error){dcFailure(row,name,name,'Stage completes',null,String(error.stack||error));return undefined;}});
}
function dcVisit(value,fn,location=''){
  fn(value,location);
  if(value&&typeof value==='object')for(const [key,child] of Object.entries(value))dcVisit(child,fn,location?location+'.'+key:key);
}
function dcInputFiles(root,worksheet,manifest){
  const names=new Set([worksheet,manifest,path.join(root,'docs/dnssec-expansion/contract-freeze.json')]);
  for(const input of dcJson(path.join(root,'docs/dnssec-expansion/contract-freeze.json')).inputs||[])names.add(path.resolve(root,input.path));
  const pending=[worksheet],visited=new Set();
  while(pending.length){
    const file=pending.pop();if(visited.has(file))continue;visited.add(file);
    dcVisit(dcJson(file),value=>{
      if(!value||typeof value!=='object')return;
      if(typeof value.numericFile==='string')names.add(path.resolve(root,value.numericFile));
      const links=[value.effectivePath,value.original?.path,value.patches?.path,value.previousEffective?.path].filter(value=>typeof value==='string');
      for(const link of links){const target=path.resolve(root,link);names.add(target);if(target.endsWith('.json')&&!visited.has(target))pending.push(target);}
    });
  }
  // The complete independent numeric catalog is an input even when a management
  // worksheet describes its bindings outside numericFile properties.
  const visit=dir=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,entry.name);if(entry.isSymbolicLink())throw new Error('Symlink in numeric inputs: '+file);if(entry.isDirectory())visit(file);else if(entry.isFile())names.add(file);}};
  visit(path.join(root,'docs/dnssec-expansion/numeric'));
  return [...names].sort();
}
function dcCapture(args,files){
  return {review:captureReviewInputs(args.root,dcRunner),independentFiles:Object.fromEntries(files.map(file=>{
    if(!fs.lstatSync(file).isFile())throw new Error('Independent input is not a regular file: '+file);
    return [path.relative(args.root,file),dcSha(fs.readFileSync(file))];
  }))};
}
async function dcRuntime(args,report){
  if(args.mode==='source'){
    const load=name=>import(pathToFileURL(path.join(args.root,'src',name)).href);
    const [lab,protocol,held,state,usage,trace,data,fields]=await Promise.all(['dnssec-lab.js','protocol-state.js','held-objects.js','held-object-state.js','attribute-usage.js','attribute-trace.js','protocol-data.js','dnssec-fields.js'].map(load));
    Object.assign(data.ATTRIBUTES,fields.DNSSEC_ATTRIBUTES);
    return {...lab,...protocol,...held,...state,...usage,...trace,ATTRIBUTES:data.ATTRIBUTES};
  }
  const {installHarness}=await import(pathToFileURL(path.join(args.root,'tests/dom-harness.mjs')).href);
  const harness=installHarness();
  report.harnessInstalled=true;
  const html=fs.readFileSync(path.join(args.root,'dist/auth-flow-studio.html'),'utf8');
  const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
  const styles=[...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map(match=>match[1]);
  if(scripts.length!==1||styles.length!==1)throw new Error('Expected exactly one emitted script and style');
  const policy=html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)?.[1];
  const cspHash=value=>"'sha256-"+createHash('sha256').update(value).digest('base64')+"'";
  if(!policy?.includes('script-src '+cspHash(scripts[0]))||!policy.includes('style-src '+cspHash(styles[0]))||!policy.includes("connect-src 'none'")||/unsafe-inline|unsafe-eval/.test(policy))throw new Error('Emitted CSP does not bind original script/style with offline restrictions');
  report.emittedScriptSha256=dcSha(scripts[0]);
  // This is the original emitted string, not instrumented, rewritten or rebuilt.
  new vm.Script(scripts[0],{filename:'auth-flow-studio.emitted.js'}).runInThisContext();
  const Klass=harness.registry.get('auth-flow-studio');
  if(!Klass)throw new Error('Emitted script did not register auth-flow-studio');
  const app=new Klass();harness.document.body.appendChild(app);app.connectedCallback();
  // Bundle helpers are IIFE-private. Do not rewrite/instrument the script to
  // expose them. Probe the existing App/held-view methods that close over the
  // emitted functions. The separate pure protocol reducer is only an independent
  // assertion over this actual emitted model; no Source case registry is loaded.
  const protocol=await import(pathToFileURL(path.join(args.root,'src/protocol-state.js')).href);
  const usageFields=new WeakMap();
  const assertContext=compiled=>{
    if(app.heldView.compiled().contextId!==compiled.contextId)throw new Error('Emitted App context changed during canonical projection');
  };
  const snapshot=(event,{initial=false}={})=>{
    const view=app.heldView,previous={initial:view.initial,selected:view.selected,queue:app.player.queue};
    try{
      view.initial=initial;view.selected=false;app.player.queue=event.queue||[];
      return view.snapshot(event);
    }finally{view.initial=previous.initial;view.selected=previous.selected;app.player.queue=previous.queue;}
  };
  const api={
    reconstructProtocolState:protocol.reconstructProtocolState,
    validateProtocolScenario:protocol.validateProtocolScenario,
    projectHeldObjects(compiled,cursor={eventIndex:-1,milestone:'initial'}){
      assertContext(compiled);
      if(cursor.eventIndex===-1)return snapshot({status:'idle'},{initial:true});
      const source=app.steps[cursor.eventIndex];
      if(!source)throw new Error('Emitted source cursor has no actual App step');
      if(dcOwn(cursor,'progress'))return snapshot({status:'paused',kind:'demo',step:source,duration:1,stepElapsed:cursor.progress});
      // An exact source-cursor interval uses the production trace mapper without
      // recomputing state or changing any source/emitted application bytes.
      const row={...source,heldContextId:compiled.contextId,heldCursorStart:cursor,heldCursorEnd:cursor};
      const frame=snapshot({status:'paused',kind:'object',step:row,duration:1,stepElapsed:0});
      if(!isDeepStrictEqual(frame.cursor,cursor))throw new Error('Emitted mapper did not resolve exact requested source cursor');
      return frame;
    },
    heldCursorForPlayback(compiled,event={},selectedStep,options={}){
      assertContext(compiled);
      if(options.initial||!options.selected&&event.status==='idle'&&!event.step)return snapshot({status:'idle'},{initial:true}).cursor;
      const actual=options.selected?{status:'complete',step:selectedStep,queue:[]}:{...event,step:event.step??selectedStep};
      return snapshot(actual).cursor;
    },
    heldObjectTrace(compiled,artifactId){
      assertContext(compiled);
      return app.heldView.buildTrace(artifactId);
    },
    getAttributeUsage(steps,fieldId){
      const usages=app.attributeUsage(steps,fieldId);usageFields.set(usages,fieldId);return usages;
    },
    buildAttributeTrace(usages){
      const fieldId=usageFields.get(usages);if(!fieldId)throw new Error('Emitted field replay requires actual App usages');
      return app.buildAttributeTrace(fieldId,usages);
    },
    ATTRIBUTES:new Proxy({}, {get(_target,id){const definition=app.definition(id);return definition?.name?definition:undefined;}})
  };
  report.emittedInspection={script:'Unaltered original emitted script',canonicalProjectionOnly:'Zero-length source-cursor intervals probe canonical projection only; they are not consumer playback evidence',consumerPlayback:'All actual App-generated full/field/exact rows pass the emitted mapper at before/intermediate/complete, forward/backward; UI controls are exercised separately at independent checkpoint/chapter boundaries and representative field/exact rows in every named case',traces:'Production App.buildAttributeTrace and heldView.buildTrace methods also used by selectAttribute and heldView.trace, without their DOM rendering side effects',independentProtocolAssertion:'src/protocol-state.js reducer and validator applied only to the actual emitted App-consumed model; no Source DNSSEC registry'};
  return {...api,app,harness};
}
function dcBijection(row,map,reverse,expected,actual,location){
  dcCheck(row,typeof expected===typeof actual,'logical-id-type',location,typeof expected,typeof actual);
  if(map.has(expected))return dcEqual(row,actual,map.get(expected),'logical-id-consistency',location);
  if(reverse.has(actual)&&reverse.get(actual)!==expected){dcFailure(row,'logical-id-bijection',location,reverse.get(actual),expected);return false;}
  map.set(expected,actual);reverse.set(actual,expected);return true;
}
function dcBindings(oracle){
  const values=[];
  dcVisit(oracle.setup,value=>{if(value&&typeof value==='object'&&value.numericFile&&value.rrsetId)values.push(value);});
  return values;
}
function dcRecord(artifact,kind){return artifact?.representations.flatMap(rep=>rep.fields).find(field=>field.attributeId==='dnssec_'+kind+'_record')?.value;}
function dcDeclaredEvidence(ctx,ref){
  return dcBindings(ctx.oracle).filter(binding=>binding.occurrenceId===ref);
}
function dcEvidenceNamespaces(ctx,ref){
  if(!ctx.evidenceNamespaces){
    ctx.evidenceNamespaces=new Map();
    for(const point of ctx.oracle.checkpoints)dcVisit(point.expected,value=>{
      if(!value||typeof value!=='object'||!Array.isArray(value.evidenceRefs))return;
      const view=value.view??value.key?.[0],trustStore=value.trustStore??value.key?.[1];
      if(view===undefined||trustStore===undefined)return;
      for(const id of value.evidenceRefs){
        const entries=ctx.evidenceNamespaces.get(id)||[];
        if(!entries.some(item=>item.view===view&&item.trustStore===trustStore))entries.push({view,trustStore});
        ctx.evidenceNamespaces.set(id,entries);
      }
    });
  }
  return ctx.evidenceNamespaces.get(ref)||[{view:ctx.oracle.setup.view,trustStore:ctx.oracle.setup.trustStore}];
}
function dcCreationCursors(ctx){
  if(!ctx.creationCursors){
    ctx.creationCursors=new Map();
    for(const effect of ctx.compiled.plan.initial||[])if(effect.op==='create')ctx.creationCursors.set(effect.artifactId,{eventIndex:-1,milestone:'initial'});
    for(const [eventIndex,step] of ctx.steps.entries())for(const milestone of ctx.compiled.plan.events[step.id]?.milestones||[])for(const effect of milestone.effects||[])if(effect.op==='create')ctx.creationCursors.set(effect.artifactId,{eventIndex,milestone:milestone.id});
  }
  return ctx.creationCursors;
}
function dcEvidenceCreationScope(ctx,artifactId){
  const cursor=dcCreationCursors(ctx).get(artifactId);
  return cursor?ctx.api.projectHeldObjects(ctx.compiled,cursor).state.dnssec:null;
}
function dcEvidenceReceiptSignatures(ctx,bodyIds,until){
  if(!ctx.receiptPackets){
    ctx.receiptPackets=[];
    for(const [eventIndex,step] of ctx.steps.entries())for(const message of ctx.compiled.plan.events[step.id]?.messages||[]){
      for(const object of message.objects){
        let artifact=ctx.artifacts.get(object.artifactId);
        const plaintext=dcRecord(artifact,'event')?.plaintextRef;
        if(plaintext)artifact=ctx.artifacts.get(plaintext);
        const packet=dcRecord(artifact,'header');
        if(packet?.flags?.QR===1)ctx.receiptPackets.push({eventIndex,messageId:message.messageId,objects:(packet.objects||[]).map(item=>item.artifactId)});
      }
    }
  }
  const packets=ctx.receiptPackets.filter(packet=>packet.eventIndex<=until&&packet.objects.some(id=>bodyIds.includes(id)));
  return {messageIds:packets.map(packet=>packet.messageId),signatures:packets.flatMap(packet=>packet.objects.map(id=>dcRecord(ctx.artifacts.get(id),'rrsig')).filter(Boolean))};
}
function dcAssociationLinks(ctx,rootId){
  const linked=new Set(),pending=[rootId];
  while(pending.length){
    const id=pending.pop();if(linked.has(id))continue;
    const artifact=ctx.artifacts.get(id);if(!artifact)continue;linked.add(id);
    pending.push(...artifact.derivedFrom||[]);
    const value=dcRecord(artifact,'trust')||dcRecord(artifact,'header')||dcRecord(artifact,'rrsig');
    if(!value)continue;
    for(const name of ['receivedObjectRef','rrsetRef','signatureRef','inputObjectRef','actualDecisionArtifact'])if(typeof value[name]==='string')pending.push(value[name]);
    for(const item of value.objects||[])if(typeof item.artifactId==='string')pending.push(item.artifactId);
    if(typeof value.rrsetId==='string')for(const candidate of ctx.artifacts.values())if(dcRecord(candidate,'rrset')?.id===value.rrsetId)pending.push(candidate.artifactId);
  }
  return linked;
}
function dcUnreceivedModelInputLinks(ctx,value,binding){
  if(value.evidenceClass!=='raw-input'||value.checkerInvoked!==false)return [];
  const input=ctx.model.dnssecNumericBindings?.answer;if(!input)return [];
  const questions=(value.responseMetadata||[]).flatMap(metadata=>{
    const step=ctx.steps.find(step=>step.id===metadata.query?.id);
    return (step?.attributeOperations||[]).filter(op=>op.attributeId==='dnssec_header_record'&&op.value?.flags?.QR===0).map(op=>op.value.question);
  });
  if(!questions.some(question=>question?.qname===binding.owner&&question.qtype===binding.type&&question.qclass===binding.class))return [];
  // This is an explicit actual-model input pointer plus an actual prepared
  // question, not a producer/role-name guess or a fabricated remote receipt.
  return [...ctx.artifacts.values()].filter(artifact=>dcRecord(artifact,'rrset')?.id===input.rrsetId||(input.signatureIds||[]).includes(dcRecord(artifact,'rrsig')?.id)).map(artifact=>artifact.artifactId);
}
function dcDnsLabels(name){
  if(name==='.')return [];
  if(typeof name!=='string'||!name.length)return null;
  const labels=[];let label=[],rooted=false;
  for(let index=0;index<name.length;index++){
    let octet=name.charCodeAt(index);
    if(octet===46){if(!label.length||label.length>63)return null;labels.push(label);label=[];rooted=true;continue;}
    rooted=false;
    if(octet===92){
      if(++index>=name.length)return null;
      const decimal=name.slice(index,index+3);
      if(/^\d{3}$/.test(decimal)){octet=Number(decimal);index+=2;}else octet=name.charCodeAt(index);
    }else if(octet>127)return null;
    if(octet>255)return null;
    label.push(octet>=65&&octet<=90?octet+32:octet);
  }
  return rooted&&!label.length&&labels.reduce((bytes,item)=>bytes+item.length+1,1)<=255?labels:null;
}
const dcNameWire=labels=>labels.map(label=>label.length.toString(16).padStart(2,'0')+Buffer.from(label).toString('hex')).join('')+'00';
function dcCanonicalSigningInput(body,signature,rdata,typeCode){
  const owner=dcDnsLabels(body.owner),signer=dcDnsLabels(signature.signer),classes={IN:1,CH:3,HS:4,NONE:254,ANY:255},classCode=dcOwn(classes,body.class)?classes[body.class]:undefined;
  if(!owner||!signer||classCode===undefined||typeCode!==signature.typeCovered||dcOwn(body,'typeCode')&&body.typeCode!==typeCode)return null;
  const integers=[[signature.typeCovered,16],[signature.algorithm,8],[signature.labels,8],[signature.originalTtl,32],[signature.expiration,32],[signature.inception,32],[signature.keyTag,16]];
  if(!integers.every(([value,bits])=>Number.isInteger(value)&&value>=0&&value<2**bits)||signature.labels>owner.length||!Array.isArray(rdata)||!rdata.every(value=>typeof value==='string'&&/^(?:[0-9a-f]{2})*$/.test(value)&&value.length/2<=65535))return null;
  const uint=(value,bits)=>value.toString(16).padStart(bits/4,'0');
  const wireOwner=dcNameWire(signature.labels<owner.length?[[42],...owner.slice(owner.length-signature.labels)]:owner);
  const prefix=integers.map(([value,bits])=>uint(value,bits)).join('')+dcNameWire(signer);
  if(prefix+signature.signatureHex!==signature.rrsigRdataHex)return null;
  const rrPrefix=wireOwner+uint(typeCode,16)+uint(classCode,16)+uint(signature.originalTtl,32);
  return {input:prefix+rdata.slice().sort().map(value=>rrPrefix+uint(value.length/2,16)+value).join(''),wireOwner,ownerLabelCount:owner.length};
}
function dcWildcardAssociation(ctx,item,binding,signature,actualSignatures,until){
  const body=item.value,query=ctx.oracle.setup.query;
  if(!signature||!binding.owner?.startsWith('*.')||body.expandedFrom!==binding.owner||body.owner!==query?.qname||body.type!==query.qtype||body.class!==query.qclass)return null;
  if(!['type','class','records'].every(name=>isDeepStrictEqual(body[name],binding[name])))return null;
  const carried=actualSignatures.find(actual=>['signatureHex','rrsigRdataHex','algorithm','labels','originalTtl','inception','expiration','signer','keyId','keyTag','typeCovered'].every(name=>isDeepStrictEqual(actual[name],signature[name])));
  if(!carried)return null;
  const numeric=ctx.numeric(binding.numericFile),sealed=numeric.rrsets?.[binding.rrsetId],key=ctx.oracle.setup.keyBindings?.[signature.keyId]||numeric.keys?.[signature.keyId],original=dcDnsLabels(binding.owner);
  if(!sealed||!key||!original||sealed.type!==body.type||sealed.class!==body.class||!isDeepStrictEqual(sealed.records,body.records)||!isDeepStrictEqual(sealed.canonicalRdataHex,binding.canonicalRdataHex))return null;
  const canonical=dcCanonicalSigningInput(body,carried,binding.canonicalRdataHex,sealed.typeCode);
  if(!canonical||carried.labels>=canonical.ownerLabelCount||canonical.wireOwner!==dcNameWire(original))return null;
  const publicKeyMatch=[...ctx.artifacts.values()].some(artifact=>{
    const value=dcRecord(artifact,'dnskey');
    if(value?.id===signature.keyId&&['owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex'].every(name=>isDeepStrictEqual(value[name],key[name])))return true;
    const rrset=dcRecord(artifact,'rrset');
    if(rrset?.type!=='DNSKEY'||rrset.owner!==key.owner||rrset.class!=='IN'||!rrset.canonicalRdataHex?.includes(key.dnskeyRdataHex))return false;
    return rrset.records.some(record=>{
      const parts=record.trim().split(/\s+/),publicBase64=parts.slice(3).join('');
      if(parts.length<4||!parts.slice(0,3).every(part=>/^\d+$/.test(part))||!publicBase64||Buffer.from(publicBase64,'base64').toString('base64')!==publicBase64)return false;
      const [flags,protocol,algorithm]=parts.slice(0,3).map(Number),publicKeyHex=Buffer.from(publicBase64,'base64').toString('hex');
      return flags===key.flags&&protocol===key.protocol&&algorithm===key.algorithm&&publicKeyHex===key.publicKeyHex&&flags.toString(16).padStart(4,'0')+protocol.toString(16).padStart(2,'0')+algorithm.toString(16).padStart(2,'0')+publicKeyHex===key.dnskeyRdataHex;
    });
  });
  if(!publicKeyMatch)return null;
  const receipts=dcEvidenceReceiptSignatures(ctx,[item.id],until);
  if(!receipts.signatures.some(value=>value.rrsigRdataHex===carried.rrsigRdataHex))return null;
  if(canonical.input!==signature.signingInputHex||binding.signingInputSha256&&dcSha(Buffer.from(canonical.input,'hex'))!==binding.signingInputSha256)return null;
  return {receivedOwner:body.owner,expandedFrom:body.expandedFrom,labels:carried.labels,ownerLabelCount:canonical.ownerLabelCount,signedOwnerWireHex:canonical.wireOwner,canonicalInputSha256:dcSha(Buffer.from(canonical.input,'hex')),signatureRdataSha256:dcSha(Buffer.from(carried.rrsigRdataHex,'hex')),keyRdataSha256:dcSha(Buffer.from(key.dnskeyRdataHex,'hex')),meaning:'Exact expanded received occurrence and RFC4034 Labels reconstruction only; no denial proof, authentication or acceptance is inferred'};
}
function dcEvidenceProof(ctx,actualRef,expectedRef){
  const errors=[],check=(ok,path,expected,actual)=>{if(!ok)errors.push({path,expected:dcBound(expected),actual:dcBound(actual)});};
  const declarations=dcDeclaredEvidence(ctx,expectedRef);
  if(declarations.length!==1)return {ok:false,errors:[{path:'independentOccurrence',expected:'One exact independent occurrence declaration',actual:declarations.length}]};
  const binding=declarations[0],artifact=ctx.artifacts.get(actualRef);
  const value=dcRecord(artifact,'trust')||dcRecord(artifact,'rrset')||dcRecord(artifact,'rrsig')||dcRecord(artifact,'header');
  if(!artifact||!value)return {ok:false,errors:[{path:'actualAssociationArtifact',expected:'Actual immutable input or observation artifact',actual:actualRef}]};
  const sourceIndex=ctx.steps.findIndex(step=>step.id===ctx.step?.id),frame=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:sourceIndex,milestone:'complete'});
  // typedRoots: an evidenceRef is an association, not authentication, invocation,
  // ownership, possession or validity. Observation records must actually exist;
  // an input definition may be inspectable without ever having been received.
  if(artifact.type==='dns-trust'&&['valid','checkedAt','checks','answerCheck','selectedEvidence','responseMetadata'].some(name=>dcOwn(value,name)))check(frame.artifacts.some(item=>item.artifactId===actualRef),'observationExistsByBoundary',true,false);
  if(dcOwn(value,'evidenceMode'))check(value.evidenceMode==='symbolic-reference-bound','evidenceMode','symbolic-reference-bound',value.evidenceMode);
  const linked=dcAssociationLinks(ctx,actualRef);
  for(const id of dcUnreceivedModelInputLinks(ctx,value,binding))linked.add(id);
  const bodies=[...linked].map(id=>({id,value:dcRecord(ctx.artifacts.get(id),'rrset')})).filter(item=>item.value);
  const mutation=binding.explicitReceivedMutation||((binding===ctx.oracle.setup.numericBindings?.primary)?ctx.oracle.setup.mutation:null)||{};
  const expectedBody={owner:mutation.owner??binding.owner,type:binding.type,class:binding.class,records:mutation.receivedRecords??mutation.records??binding.records};
  const numeric=ctx.numeric(binding.numericFile),signature=numeric.signatures?.[binding.signatureId],signatures=[...linked].map(id=>dcRecord(ctx.artifacts.get(id),'rrsig')).filter(Boolean),wildcards=new Map();
  const matching=bodies.filter(item=>{
    if(Object.entries(expectedBody).every(([name,wanted])=>wanted===undefined||isDeepStrictEqual(item.value[name],wanted)))return true;
    const wildcard=dcWildcardAssociation(ctx,item,binding,signature,signatures,sourceIndex);
    if(wildcard)wildcards.set(item.id,wildcard);
    return !!wildcard;
  });
  check(matching.length>0,'exactInputRrsetAssociation',expectedBody,bodies.map(item=>({artifactId:item.id,owner:item.value.owner,type:item.value.type,class:item.value.class,records:item.value.records})));
  if(value.receivedObjectRef){
    check(matching.some(item=>item.id===value.receivedObjectRef),'receivedObjectRef',matching.map(item=>item.id),value.receivedObjectRef);
    check(frame.artifacts.some(item=>item.artifactId===value.receivedObjectRef),'explicitReceivedObjectExists',value.receivedObjectRef,null);
    const received=matching.find(item=>item.id===value.receivedObjectRef);
    if(received&&binding.receivedRrsetTtl!==undefined)check(received.value.ttl===binding.receivedRrsetTtl,'explicitReceivedTtl',binding.receivedRrsetTtl,received.value.ttl);
  }
  if(binding.signatureId)check(!!signature,'independentSignature',binding.signatureId,null);
  if(signature){
    for(const [name,wanted] of Object.entries(binding.signedMetadata||{}))check(isDeepStrictEqual(signature[name],wanted),'independentSignatureTuple.'+name,wanted,signature[name]);
    if(binding.signatureRdataSha256)check(dcSha(Buffer.from(signature.rrsigRdataHex,'hex'))===binding.signatureRdataSha256,'independentSignatureRdataHash',binding.signatureRdataSha256,dcSha(Buffer.from(signature.rrsigRdataHex,'hex')));
    if(binding.signingInputSha256&&signature.signingInputHex)check(dcSha(Buffer.from(signature.signingInputHex,'hex'))===binding.signingInputSha256,'independentSigningInputHash',binding.signingInputSha256,dcSha(Buffer.from(signature.signingInputHex,'hex')));
  }
  const relevant=signature?signatures.filter(item=>item.rrsigRdataHex===signature.rrsigRdataHex||item.typeCovered===signature.typeCovered&&item.signer===signature.signer):[];
  const exactSignature=signature&&relevant.some(item=>['signatureHex','rrsigRdataHex','algorithm','labels','originalTtl','inception','expiration','signer','typeCovered'].every(name=>!dcOwn(signature,name)||isDeepStrictEqual(item[name],signature[name])));
  if(relevant.length)check(!!exactSignature,'exactAssociatedRrsigBytesAndTuple',signature?.rrsigRdataHex,relevant.map(item=>item.rrsigRdataHex));
  const receipts=dcEvidenceReceiptSignatures(ctx,value.receivedObjectRef?[value.receivedObjectRef]:matching.map(item=>item.id),sourceIndex);
  const receivedSignature=!!signature&&receipts.signatures.some(item=>item.rrsigRdataHex===signature.rrsigRdataHex);
  if(receipts.messageIds.length&&binding.signaturePresentInReceivedOccurrence===false)check(!receivedSignature,'declaredAbsentReceivedSignature',false,receivedSignature);
  if(receipts.messageIds.length&&binding.signaturePresentInReceivedOccurrence===true)check(receivedSignature,'declaredPresentReceivedSignature',true,receivedSignature);
  const key=signature&&(ctx.oracle.setup.keyBindings?.[signature.keyId]||numeric.keys?.[signature.keyId]);
  if(signature)check(!!key,'independentPublicKey',signature.keyId,null);
  const selected=[];
  dcVisit(value,item=>{if(item&&typeof item==='object'&&item.signatureHex===signature?.signatureHex&&typeof item.dnskeyRdataHex==='string')selected.push(item);});
  if(key)for(const item of selected.filter(item=>item.valid===true||item.usable===true))check(item.dnskeyRdataHex===key.dnskeyRdataHex,'explicitSuccessfulTuplePublicKey',key.dnskeyRdataHex,item.dnskeyRdataHex);
  const creation=dcEvidenceCreationScope(ctx,actualRef)||ctx.model.initialState?.dnssec;
  const namespaces=dcEvidenceNamespaces(ctx,expectedRef),actualNamespace={view:value.view??creation?.view??creation?.cacheNamespace?.view,trustStore:value.trustStore??creation?.trustStore??creation?.cacheNamespace?.trustStore};
  check(namespaces.some(namespace=>Object.entries(namespace).every(([name,wanted])=>wanted===undefined||isDeepStrictEqual(actualNamespace[name],wanted))),'independentInputNamespace',namespaces,actualNamespace);
  // Explicit owner/status/check-clock/observerWitness expectations are compared
  // by dcCompare. Never synthesize any of them from this association proof.
  return {ok:errors.length===0,errors,proof:{expectedRef,actualRef,meaning:'Exact input/observation association only',rrset:value.receivedObjectRef??matching[0]?.id,inputObjectRefs:matching.map(item=>item.id),producer:artifact.creator,receivedObjectRef:value.receivedObjectRef??null,signatureAssociated:!!exactSignature,actualNamespace,sourceValidationOwner:dcOwn(value,'validationOwner')?value.validationOwner:null,sourceValidityClaim:value.valid??value.result?.valid??value.answerCheck?.valid??null,sourceCheckedAt:value.checkedAt??null,...(wildcards.has(value.receivedObjectRef)?{wildcardAssociation:wildcards.get(value.receivedObjectRef)}:{}),independentTupleSha256:dcHash({body:expectedBody,signature:signature?.rrsigRdataHex,key: key?{owner:key.owner,flags:key.flags,protocol:key.protocol,algorithm:key.algorithm,publicKeyHex:key.publicKeyHex,dnskeyRdataHex:key.dnskeyRdataHex}:null,namespaces})}};
}
function dcEvidenceArray(ctx,actual,expected,location){
  if(!dcCheck(ctx.row,Array.isArray(actual),'checkpoint-array',location,'Evidence reference array',actual))return;
  dcEqual(ctx.row,actual.length,expected.length,'checkpoint-array-length',location);
  const unused=new Set(actual.map((_,index)=>index));
  for(const [index,ref] of expected.entries()){
    const mapped=ctx.refs.get(ref),eligible=[...unused].filter(n=>mapped===undefined||actual[n]===mapped);
    const proofs=eligible.map(n=>({index:n,...dcEvidenceProof(ctx,actual[n],ref)}));
    const exact=proofs.filter(proof=>proof.ok&&actual[proof.index]===ref),valid=exact.length?exact:proofs.filter(proof=>proof.ok);
    if(!dcCheck(ctx.row,valid.length===1,'independent-evidence-bijection',location+'.'+index,{ref,required:'One exact tuple/scope-bound actual evidence occurrence'},valid.length?valid.map(proof=>actual[proof.index]):proofs.map(proof=>({actualRef:actual[proof.index],errors:proof.errors}))))continue;
    const chosen=valid[0];unused.delete(chosen.index);dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,ref,actual[chosen.index],location+'.'+index);
    ctx.row.logicalEvidenceBindings??=[];if(!ctx.row.logicalEvidenceBindings.some(item=>item.expectedRef===ref))ctx.row.logicalEvidenceBindings.push(chosen.proof);
  }
  for(const index of unused)dcFailure(ctx.row,'unexpected-unbound-evidence',location+'.actual.'+index,'No extra evidence without independent occurrence authorization',actual[index]);
}
function dcCacheIdentity(ctx,actual,expected,location,failuresBefore){
  if(ctx.row.failures.length!==failuresBefore){dcCompare(ctx,actual.id,expected.id,location+'.id');return;}
  const fields=Object.keys(expected).filter(field=>!['remainingTtl','remaining','usable','eligibleForReuse','expired','status','reused'].includes(field));
  const index=ctx.steps.findIndex(step=>step.id===ctx.step?.id),frame=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:index,milestone:'complete'});
  const records=frame.artifacts.filter(artifact=>artifact.type==='dns-cache').filter(artifact=>{
    const value=dcRecord(artifact,'cache');
    return value?.id===actual.id&&fields.every(field=>!dcOwn(actual,field)||isDeepStrictEqual(dcCopy({value:value[field]}),dcCopy({value:actual[field]})));
  });
  if(dcCheck(ctx.row,records.length===1,'cache-logical-id-exact-artifact',location,{id:actual.id,required:'One already-created immutable cache with the full checked namespace/clock/owner/status/evidence tuple'},records.map(artifact=>artifact.artifactId)))dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected.id,actual.id,location+'.id');
  dcCompare(ctx,actual.id,expected.id,location+'.id');
}
function dcAnchor(ctx,actual,expected,location){
  const bindingObject=location.endsWith('.anchorBinding')&&expected&&typeof expected==='object';
  const reference=location.endsWith('.anchorRef')&&typeof expected==='string';
  if(!bindingObject&&!reference)return false;
  const independent=bindingObject?expected:ctx.expectedAnchorBinding;
  if(!independent||independent.keyId!==(bindingObject?expected.keyId:expected))return false;
  const before=ctx.row.failures.length;
  const actualBinding=bindingObject?actual:ctx.currentState?.anchorBinding;
  const anchorId=ctx.currentState?.anchorRef;
  const anchor=ctx.artifacts.get(anchorId);
  const trust=dcRecord(anchor,'trust');
  const key=ctx.oracle.setup.keyBindings?.[independent.keyId];
  const declaredKeys=['keyId','owner','scope','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex'];
  for(const keyName of declaredKeys){
    dcCheck(ctx.row,dcOwn(independent,keyName),'anchor-complete-independent-binding',location+'.'+keyName,'Explicit bound value',independent[keyName]);
    dcEqual(ctx.row,actualBinding?.[keyName],independent[keyName],'anchor-exact-tuple-scope',location+'.'+keyName);
  }
  if(trust){
    dcEqual(ctx.row,trust.keyRef,independent.keyId,'anchor-artifact-logical-key',location);
    dcEqual(ctx.row,trust.zone,independent.scope,'anchor-artifact-scope',location);
  }else dcCheck(ctx.row,actual===independent.keyId,'anchor-resolves-concrete-material',location,'Resolved anchor artifact or exact logical key',actual);
  const publicKeys=[...ctx.artifacts.values()].map(artifact=>dcRecord(artifact,'dnskey')).filter(value=>value?.id===independent.keyId);
  dcCheck(ctx.row,publicKeys.length>0||!!trust?.anchorBinding,'anchor-public-material-present',location,'Actual exact DNSKEY or embedded anchor material',publicKeys.length);
  for(const value of publicKeys)for(const name of ['owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex'])dcEqual(ctx.row,value[name],independent[name],'anchor-public-artifact-binding',location+'.'+name);
  for(const [name,wanted] of Object.entries(independent)){
    if(declaredKeys.includes(name))continue;
    if(['type','anchorRefType','keyTag','provisioning','anchorSource'].includes(name)){dcEqual(ctx.row,actualBinding?.[name],wanted,'anchor-declared-semantics',location+'.'+name);continue;}
    if(name==='publicKeySha256'||name==='dnskeyRdataSha256'){
      const hex=actualBinding?.[name==='publicKeySha256'?'publicKeyHex':'dnskeyRdataHex'];
      dcEqual(ctx.row,typeof hex==='string'?dcSha(Buffer.from(hex,'hex')):null,wanted,'anchor-independent-byte-hash',location+'.'+name);continue;
    }
    if(name==='keyBindingPath'||name==='anchorInputPath'){
      const input=wanted.split('/').slice(1).reduce((value,part)=>value?.[part.replaceAll('~1','/').replaceAll('~0','~')],ctx.oracle);
      dcCheck(ctx.row,!!input,'anchor-independent-path-resolves',location+'.'+name,wanted,input);
      if(input)for(const field of name==='keyBindingPath'?['owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex']:['keyRef','owner','provisioning']){
        const wantedField=field==='keyRef'?independent.keyId:independent[field];
        dcEqual(ctx.row,input[field],wantedField,'anchor-independent-path-tuple',location+'.'+name+'.'+field);
      }
      continue;
    }
    if(['alphaConversionRule','hashCanonicalization'].includes(name)){ctx.row.referenceAnnotations??=[];if(!ctx.row.referenceAnnotations.some(item=>item.path===location+'.'+name))ctx.row.referenceAnnotations.push({path:location+'.'+name,declaration:wanted,implementation:'Exact tuple, scope, path and decoded-byte hash checks above; annotation is independent contract metadata, not a demanded product echo'});continue;}
    dcFailure(ctx.row,'unknown-anchor-binding-semantics',location+'.'+name,'Explicit implemented binding check',wanted);
  }
  if(key)for(const name of ['owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex'])dcEqual(ctx.row,key[name],independent[name],'anchor-independent-key-binding',location+'.'+name);
  if(reference&&ctx.row.failures.length===before)dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
  return true;
}
function dcReferenceEvidence(ctx,artifactId,occurrenceId,location){
  const mapped=ctx.refs.get(occurrenceId);
  const candidates=[...ctx.artifacts.values()].filter(artifact=>(mapped===undefined||artifact.artifactId===mapped)&&((artifact.derivedFrom||[]).includes(artifactId)||dcRecord(artifact,'trust')?.receivedObjectRef===artifactId));
  const proofs=candidates.map(artifact=>({artifactId:artifact.artifactId,...dcEvidenceProof(ctx,artifact.artifactId,occurrenceId)}));
  const exact=proofs.filter(proof=>proof.ok&&proof.artifactId===occurrenceId),valid=exact.length?exact:proofs.filter(proof=>proof.ok);
  if(!dcCheck(ctx.row,valid.length===1,'reference-independent-occurrence',location,{occurrenceId,required:'One exact independent tuple/scope-bound witness linked to this actual checked object'},valid.length?valid.map(proof=>proof.artifactId):proofs.map(proof=>({artifactId:proof.artifactId,errors:proof.errors}))))return;
  dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,occurrenceId,valid[0].artifactId,location+'.evidenceRef');
}
function dcMathematicalReference(ctx,actual,expected,location){
  if(!location.endsWith('.mathematicalReferenceResultRef')||typeof expected!=='string'||!expected.startsWith('/'))return false;
  const before=ctx.row.failures.length,parts=expected.slice(1).split('/').map(part=>part.replaceAll('~1','/').replaceAll('~0','~'));
  if(!dcCheck(ctx.row,parts.length===5&&parts[0]==='checkpoints'&&/^(0|[1-9]\d*)$/.test(parts[1])&&parts[2]==='expected'&&parts[3]==='validators','decision-reference-independent-pointer',location,'Exact independent checkpoint/validator JSON pointer',expected))return true;
  const point=ctx.oracle.checkpoints[Number(parts[1])],owner=parts[4],wanted=point?.expected?.validators?.[owner];
  if(!dcCheck(ctx.row,!!wanted&&typeof wanted==='object','decision-reference-independent-target',location,'Declared validator decision object',wanted))return true;
  const boundary=ctx.model.dnssecCheckpointAliases?.[point.name]||point.name;
  const targets=ctx.steps.flatMap((step,index)=>step.id===actual&&step.dnssecBoundary===boundary?[{step,index}]:[]);
  if(!dcCheck(ctx.row,targets.length===1,'decision-reference-actual-boundary',location,{boundary,required:'One exact actual Source event ID'},actual))return true;
  const {step,index}=targets[0],current=ctx.steps.findIndex(item=>item.id===ctx.step?.id);
  dcCheck(ctx.row,index<=current,'decision-reference-observed-before-use',location,current,index);
  dcEqual(ctx.row,point.actorId,owner,'decision-reference-declared-checker',location);
  dcCheck(ctx.row,step.attributeOperations?.some(op=>op.actorId===owner&&op.kind==='verify'),'decision-reference-actual-decision-operation',location,'Actual observed decision/check operation, not an inferred crypto invocation',step.id);
  const observed=ctx.api.reconstructProtocolState(ctx.model,index).dnssec,previousStep=ctx.step,previousState=ctx.currentState;
  try{ctx.step=step;ctx.currentState=observed;dcCompare(ctx,observed.validators?.[owner],wanted,location+'.resolved.validators.'+owner);}
  finally{ctx.step=previousStep;ctx.currentState=previousState;}
  if(ctx.row.failures.length===before){
    dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
    ctx.row.logicalDecisionBindings??=[];
    if(!ctx.row.logicalDecisionBindings.some(item=>item.expectedRef===expected))ctx.row.logicalDecisionBindings.push({expectedRef:expected,actualRef:actual,checkpoint:point.name,owner,eventIndex:index,decisionSha256:dcHash(observed.validators[owner]),meaning:'Independent pointer resolves the actual earlier observed decision; no mathematical validity is inferred from the reference'});
  }
  return true;
}
function dcSignatureLabel(ctx,actual,expected,location){
  const field=location.match(/\.validators\.([^.]+)\.(usableValidSignatures|additionalInvalidSignatures)\.\d+$/),label=typeof expected==='string'&&expected.match(/^(valid|invalid)-(.+)$/);
  if(!field||!label)return false;
  const before=ctx.row.failures.length,owner=field[1],valid=field[2]==='usableValidSignatures',keyId=label[2];
  dcEqual(ctx.row,label[1],valid?'valid':'invalid','signature-label-decision-category',location);
  const inputs=(ctx.oracle.setup.signatureInputs||[]).filter(input=>input.expectedValid===valid&&input.binding?.signedMetadata?.keyId===keyId);
  if(!dcCheck(ctx.row,inputs.length===1,'signature-label-independent-input',location,'One independently sealed signature input for this exact key and decision category',inputs.map(input=>input.id)))return true;
  const input=inputs[0],binding=input.binding,numeric=ctx.numeric(binding.numericFile),fixed=numeric.signatures?.[binding.signatureId],key=ctx.oracle.setup.keyBindings?.[keyId]||numeric.keys?.[keyId],primary=ctx.oracle.setup.numericBindings?.primary;
  if(!dcCheck(ctx.row,!!fixed&&!!key&&!!primary&&input.attachedTo===primary.rrsetId,'signature-label-sealed-attachment',location,'Exact independent signature, key and separately declared current RRset attachment',{signatureId:binding.signatureId,keyId,attachedTo:input.attachedTo,primary:primary?.rrsetId}))return true;
  for(const [name,wanted] of Object.entries(binding.signedMetadata||{}))dcEqual(ctx.row,fixed[name],wanted,'signature-label-independent-signed-tuple',location+'.'+name);
  for(const [name,hex] of [['signatureRdataSha256',fixed.rrsigRdataHex],['signingInputSha256',fixed.signingInputHex]])if(binding[name])dcEqual(ctx.row,typeof hex==='string'?dcSha(Buffer.from(hex,'hex')):null,binding[name],'signature-label-independent-byte-hash',location+'.'+name);
  const verified=new Set((ctx.step.attributeOperations||[]).filter(op=>op.kind==='verify'&&op.actorId===owner).map(op=>op.instanceId));
  const signatures=[...verified].map(id=>ctx.artifacts.get(id)).filter(artifact=>dcRecord(artifact,'rrsig')?.id===actual);
  const bodies=[...verified].map(id=>ctx.artifacts.get(id)).filter(artifact=>dcRecord(artifact,'rrset')?.id===input.attachedTo);
  if(!dcCheck(ctx.row,signatures.length===1&&bodies.length===1,'signature-label-actual-checked-objects',location,'One exact signature and current RRset in this actual validator decision',{signatures:signatures.map(item=>item.artifactId),rrsets:bodies.map(item=>item.artifactId)}))return true;
  const signature=dcRecord(signatures[0],'rrsig'),body=dcRecord(bodies[0],'rrset');
  for(const name of ['signatureHex','rrsigRdataHex','algorithm','labels','originalTtl','inception','expiration','signer','keyId','keyTag','typeCovered','rrsetId'])dcEqual(ctx.row,signature[name],fixed[name],'signature-label-actual-sealed-tuple',location+'.'+name);
  for(const [name,wanted] of Object.entries({owner:primary.owner,type:primary.type,class:primary.class,records:primary.records,ttl:primary.receivedRrsetTtl}))if(wanted!==undefined)dcEqual(ctx.row,body[name],wanted,'signature-label-current-attachment',location+'.'+name);
  const index=ctx.steps.findIndex(step=>step.id===ctx.step.id),frame=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:index,milestone:'complete'}),created=new Set(frame.artifacts.map(item=>item.artifactId));
  const keyArtifacts=frame.artifacts.filter(artifact=>dcRecord(artifact,'dnskey')?.id===keyId);
  dcCheck(ctx.row,keyArtifacts.length>0,'signature-label-actual-public-key',location,'Actual created exact public key material',keyId);
  for(const artifact of keyArtifacts)for(const name of ['owner','flags','protocol','algorithm','publicKeyHex','dnskeyRdataHex'])dcEqual(ctx.row,dcRecord(artifact,'dnskey')[name],key[name],'signature-label-full-public-key',location+'.'+name);
  dcCheck(ctx.row,created.has(signatures[0].artifactId)&&created.has(bodies[0].artifactId),'signature-label-created-before-decision',location,'Both concrete objects exist by this decision',index);
  const receipts=dcEvidenceReceiptSignatures(ctx,[bodies[0].artifactId],index);
  dcCheck(ctx.row,receipts.signatures.some(item=>item.id===actual&&item.rrsigRdataHex===fixed.rrsigRdataHex),'signature-label-actual-received-attachment',location,'Actual response carries this exact signature with the current RRset',receipts.messageIds);
  const candidates=(ctx.currentState.validators?.[owner]?.candidates||[]).filter(candidate=>candidate.signatureId===actual&&candidate.keyId===keyId);
  if(dcCheck(ctx.row,candidates.length===1,'signature-label-actual-candidate',location,'One concrete candidate decision for this signature and exact key',candidates.length)){
    const candidate=candidates[0];
    dcEqual(ctx.row,candidate.dnskeyRdataHex,key.dnskeyRdataHex,'signature-label-candidate-key-bytes',location);
    dcEqual(ctx.row,candidate.signatureHex,fixed.signatureHex,'signature-label-candidate-signature-bytes',location);
    for(const name of ['originalTtl','inception','expiration'])dcEqual(ctx.row,candidate[name],fixed[name],'signature-label-candidate-signed-metadata',location+'.'+name);
    const currentFixture=ctx.numeric(primary.numericFile).rrsets?.[primary.rrsetId],canonical=currentFixture&&dcCanonicalSigningInput(body,signature,primary.canonicalRdataHex,currentFixture.typeCode);
    dcCheck(ctx.row,!!canonical,'signature-label-canonical-current-context',location,'Independently encoded current attachment with actual RRSIG Labels/OriginalTTL',primary.rrsetId);
    if(canonical)dcEqual(ctx.row,candidate.canonicalInputHex,canonical.input,'signature-label-exact-current-canonical-input',location);
    dcEqual(ctx.row,candidate.checked,true,'signature-label-actual-comparison',location);
    dcEqual(ctx.row,candidate.usable,input.expectedValid,'signature-label-current-usability',location);
    dcEqual(ctx.row,candidate.valid,input.expectedValid,'signature-label-current-decision',location);
    dcEqual(ctx.row,candidate.mathematicalResult,input.expectedValid,'signature-label-current-tuple-result',location);
    if(input.intentionalMisassociation)dcCheck(ctx.row,binding.rrsetId!==input.attachedTo,'signature-label-independent-misassociation',location,'Original signed tuple differs from its explicitly declared current attachment',{original:binding.rrsetId,current:input.attachedTo});
  }
  if(ctx.row.failures.length===before){
    dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
    ctx.row.logicalSignatureBindings??=[];if(!ctx.row.logicalSignatureBindings.some(item=>item.expectedRef===expected))ctx.row.logicalSignatureBindings.push({expectedRef:expected,actualRef:actual,signatureArtifact:signatures[0].artifactId,currentRrsetArtifact:bodies[0].artifactId,keyId,owner,eventIndex:index,signatureRdataSha256:binding.signatureRdataSha256,currentDecision:input.expectedValid,meaning:'Exact sealed signature/public-key bytes plus actual received attachment and validator candidate decision, never status normalization'});
  }
  return true;
}
function dcRetryReference(ctx,actual,expected,location){
  if(!location.endsWith('.correlatedRetryOf')||typeof expected!=='string')return false;
  const declarations=(ctx.oracle.outcome.flags?.hops||[]).filter(hop=>hop.query?.id===expected);
  if(!declarations.length)return false;
  const before=ctx.row.failures.length;
  if(!dcCheck(ctx.row,declarations.length===1,'retry-reference-independent-query',location,'One independently declared original query occurrence',declarations.length))return true;
  const original=declarations[0],current=ctx.steps.findIndex(step=>step.id===ctx.step?.id),packets=dcActualPackets(ctx).filter(item=>item.index<=current);
  const queries=packets.filter(item=>item.step.id===actual&&item.packet.flags?.QR===0&&item.message.from===original.from&&item.message.to===original.to);
  if(!dcCheck(ctx.row,queries.length===1,'retry-reference-actual-query',location,'One actual earlier concrete query Source event',actual))return true;
  const query=queries[0],question=original.question;
  if(!dcCheck(ctx.row,!!question?.qclass,'retry-reference-independent-question',location,'Independently declared qname/qtype/qclass',question))return true;
  const packetFields=(item,hop,direction)=>{
    const descriptor=hop[direction];
    dcEqual(ctx.row,item.packet.transport,hop.transport,'retry-reference-transport',location+'.'+direction);
    dcCompare(ctx,item.packet.question,hop.question,location+'.'+direction+'.question');
    for(const name of ['flags','edns','rcode'])if(dcOwn(descriptor,name))dcCompare(ctx,item.packet[name],descriptor[name],location+'.'+direction+'.'+name);
    if(descriptor?.messageId!==undefined){
      if(item.packet.tsig||item.packet.wireHex)dcEqual(ctx.row,item.packet.messageId,descriptor.messageId,'retry-reference-fixed-signed-id',location+'.'+direction);
      dcBijection(ctx.row,ctx.wireIds,ctx.reverseWireIds,hop.id+'|'+descriptor.messageId,hop.id+'|'+item.packet.messageId,location+'.'+direction+'.messageId');
    }
  };
  packetFields(query,original,'query');
  dcEqual(ctx.row,original.transport,'UDP','retry-reference-original-transport',location);
  const responses=packets.filter(item=>item.packet.flags?.QR===1&&item.message.from===original.to&&item.message.to===original.from&&item.packet.messageId===query.packet.messageId&&dcSubset(item.packet.question,question)&&dcOccurrenceBefore(query,item)&&dcReplyMatches(ctx,item,query));
  if(!dcCheck(ctx.row,responses.length===1,'retry-reference-truncated-response',location,'One exact correlated original response',responses.map(item=>item.message.messageId)))return true;
  const response=responses[0];packetFields(response,original,'response');
  dcEqual(ctx.row,response.packet.flags.TC,1,'retry-reference-actual-truncation',location);
  const retries=(ctx.oracle.outcome.flags.hops||[]).filter(hop=>hop.transport==='TCP'&&hop.from===original.from&&hop.to===original.to&&isDeepStrictEqual(hop.question,question));
  if(!dcCheck(ctx.row,retries.length===1,'retry-reference-independent-retry',location,'One independently declared same-question TCP retry',retries.length))return true;
  const retry=retries[0],tcpQueries=packets.filter(item=>item.packet.flags?.QR===0&&item.packet.transport==='TCP'&&item.message.from===retry.from&&item.message.to===retry.to&&dcSubset(item.packet.question,question)&&dcOccurrenceBefore(response,item));
  if(!dcCheck(ctx.row,tcpQueries.length===1,'retry-reference-actual-tcp-query',location,'One actual subsequent TCP query occurrence',tcpQueries.map(item=>item.message.messageId)))return true;
  const tcpQuery=tcpQueries[0];packetFields(tcpQuery,retry,'query');
  const tcpResponses=packets.filter(item=>item.packet.flags?.QR===1&&item.message.from===retry.to&&item.message.to===retry.from&&item.packet.messageId===tcpQuery.packet.messageId&&dcSubset(item.packet.question,question)&&dcOccurrenceBefore(tcpQuery,item)&&dcReplyMatches(ctx,item,tcpQuery));
  if(!dcCheck(ctx.row,tcpResponses.length===1,'retry-reference-actual-tcp-response',location,'One actual complete correlated TCP response',tcpResponses.map(item=>item.message.messageId)))return true;
  const tcpResponse=tcpResponses[0];packetFields(tcpResponse,retry,'response');dcEqual(ctx.row,tcpResponse.packet.flags.TC,0,'retry-reference-complete-response',location);
  if(ctx.row.failures.length===before){
    dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
    for(const [wanted,item] of [[original.response?.id,response],[retry.query?.id,tcpQuery],[retry.response?.id,tcpResponse]])if(wanted)dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,wanted,item.step.id,location);
    ctx.row.logicalRetryBindings??=[];if(!ctx.row.logicalRetryBindings.some(item=>item.expectedRef===expected))ctx.row.logicalRetryBindings.push({expectedRef:expected,actualRef:actual,originalQueryUid:query.message.messageId,truncatedResponseUid:response.message.messageId,retryQueryUid:tcpQuery.message.messageId,completeResponseUid:tcpResponse.message.messageId,question});
  }
  return true;
}
function dcMutationActorReference(ctx,actual,expected,location){
  if(!location.endsWith('.queryOptRemovedBy')||!ctx.hopPair||expected!==ctx.oracle.setup.wire?.queryOptRemovedBy)return false;
  const before=ctx.row.failures.length,{actual:hop,expected:independent}=ctx.hopPair,wire=ctx.oracle.setup.wire,current=ctx.steps.findIndex(step=>step.id===ctx.step?.id);
  dcCheck(ctx.row,!!ctx.model.actors()[actual],'mutation-actor-actual-identity',location,'Declared actual model actor',actual);
  const queries=dcActualPackets(ctx).filter(item=>item.index<=current&&item.step.id===hop.query?.id&&item.packet.flags?.QR===0&&item.message.from===independent.from&&item.message.to===independent.to);
  if(!dcCheck(ctx.row,queries.length===1,'mutation-actor-exact-delivered-query',location,'One actual query occurrence on the independently declared path',queries.map(item=>item.message.messageId)))return true;
  const query=queries[0],modified=ctx.artifacts.get(query.packet.pathMutationEvidenceId),value=dcRecord(modified,'header');
  if(!dcCheck(ctx.row,!!value&&modified.creator===actual,'mutation-actor-concrete-derivation',location,'Delivered query explicitly references the header derived by this actor',query.packet.pathMutationEvidenceId))return true;
  const originals=(modified.derivedFrom||[]).map(id=>ctx.artifacts.get(id)).filter(artifact=>dcRecord(artifact,'header'));
  if(!dcCheck(ctx.row,originals.length===1,'mutation-actor-original-input',location,'One exact original query header',originals.map(item=>item.artifactId)))return true;
  const original=dcRecord(originals[0],'header');
  for(const name of ['qname','qtype','qclass']){dcEqual(ctx.row,original.question?.[name],independent.question?.[name],'mutation-actor-original-question',location+'.'+name);dcEqual(ctx.row,query.packet.question?.[name],independent.question?.[name],'mutation-actor-delivered-question',location+'.'+name);}
  dcEqual(ctx.row,original.messageId,query.packet.messageId,'mutation-actor-original-wire-id',location);
  dcEqual(ctx.row,value.messageId,query.packet.messageId,'mutation-actor-modified-wire-id',location);
  dcEqual(ctx.row,original.edns?.present,true,'mutation-actor-original-opt',location);dcEqual(ctx.row,original.flags?.DO,1,'mutation-actor-original-do',location);
  dcEqual(ctx.row,value.flags,query.packet.flags,'mutation-actor-exact-forwarded-flags',location);dcEqual(ctx.row,value.edns,query.packet.edns,'mutation-actor-exact-forwarded-opt',location);
  for(const name of Object.keys(original.flags||{}))if(!['DO','CO'].includes(name))dcEqual(ctx.row,value.flags?.[name],original.flags[name],'mutation-actor-preserved-other-flags',location+'.'+name);
  dcEqual(ctx.row,value.edns?.present,false,'mutation-actor-opt-removed',location);dcEqual(ctx.row,value.flags?.DO,null,'mutation-actor-do-absent',location);dcEqual(ctx.row,value.flags?.CO,null,'mutation-actor-co-absent',location);
  dcEqual(ctx.row,wire.authoritySeesDO,0,'mutation-actor-independent-absent-do',location);dcEqual(ctx.row,wire.authorityReturnsAuxiliaryDnssec,false,'mutation-actor-independent-auxiliary-policy',location);
  const derive=ctx.steps.slice(0,query.index+1).some(step=>step.attributeOperations?.some(op=>op.actorId===actual&&op.instanceId===modified.artifactId&&op.kind==='derive'));
  dcCheck(ctx.row,derive,'mutation-actor-observed-operation',location,'Actual derive operation before this query transfer',actual);
  if(ctx.row.failures.length===before){
    dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
    ctx.row.logicalActorBindings??=[];if(!ctx.row.logicalActorBindings.some(item=>item.expectedRef===expected))ctx.row.logicalActorBindings.push({expectedRef:expected,actualRef:actual,originalArtifact:originals[0].artifactId,modifiedArtifact:modified.artifactId,queryArtifact:query.header.artifactId,queryUid:query.message.messageId,meaning:'Exact declared on-path OPT mutation and original/derived/delivered bytes, not a same-role-label match'});
  }
  return true;
}
function dcReference(ctx,actual,expected,location){
  if(typeof actual!=='string'||typeof expected!=='string'||!expected.startsWith(ctx.model.id+':')||!/^.*\.validators\.[^.]+\.(rrsetRef|signatureRef)$/.test(location))return false;
  const signature=location.endsWith('.signatureRef'),kind=signature?'rrsig':'rrset';
  const artifact=ctx.artifacts.get(actual),value=dcRecord(artifact,kind);
  if(!value){dcFailure(ctx.row,'reference-resolves-actual-artifact',location,'Actual immutable '+kind+' artifact',actual);return true;}
  const declared=dcBindings(ctx.oracle);
  // A validator reference denotes the independently declared primary received
  // occurrence. Never choose a tuple using a same-role label or actual key tag.
  const primary=ctx.oracle.setup.numericBindings?.primary;
  const explicit=declared.filter(binding=>binding.occurrenceId===expected||binding.artifactId===expected||binding.rrsetRef===expected||binding.signatureRef===expected);
  const candidates=explicit.length?explicit:primary?[primary]:[];
  if(candidates.length!==1){dcFailure(ctx.row,'reference-independent-tuple-prerequisite',location,'Exactly one independently declared numeric tuple',candidates.length);return true;}
  const binding=candidates[0];
  const before=ctx.row.failures.length;
  const sourceIndex=ctx.steps.findIndex(step=>step.id===ctx.step?.id);
  const operation=ctx.steps.slice(0,sourceIndex+1).some(step=>step.attributeOperations?.some(op=>op.instanceId===actual&&op.kind==='verify'));
  dcCheck(ctx.row,operation,'reference-actual-verification',location,true,operation);
  if(signature){
    const numeric=ctx.numeric(binding.numericFile),fixed=numeric.signatures?.[binding.signatureId];
    dcCheck(ctx.row,!!fixed,'reference-independent-signature',location,binding.signatureId,fixed?.id);
    if(fixed){for(const key of ['signatureHex','rrsigRdataHex','algorithm','labels','originalTtl','inception','expiration','signer','keyId','keyTag','typeCovered'])if(dcOwn(fixed,key))dcEqual(ctx.row,value[key],fixed[key],'reference-exact-signature',location+'.'+key);}
    if(binding.signatureRdataSha256&&value.rrsigRdataHex)dcEqual(ctx.row,dcSha(Buffer.from(value.rrsigRdataHex,'hex')),binding.signatureRdataSha256,'reference-signature-hash',location);
  }else{
    const mutation=ctx.oracle.setup.mutation||{};
    for(const [key,wanted] of Object.entries({owner:mutation.owner??binding.owner,type:binding.type,class:binding.class,records:mutation.receivedRecords??binding.records,ttl:binding.receivedRrsetTtl}))if(wanted!==undefined)dcEqual(ctx.row,value[key],wanted,'reference-exact-rrset',location+'.'+key);
  }
  if(binding.occurrenceId)dcReferenceEvidence(ctx,actual,binding.occurrenceId,location);
  if(ctx.row.failures.length===before)dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected,actual,location);
  return true;
}
function dcNameOrder(left,right){
  const a=dcDnsLabels(left),b=dcDnsLabels(right);if(!a||!b)return null;
  for(let index=1;index<=Math.min(a.length,b.length);index++){
    const order=Buffer.compare(Buffer.from(a.at(-index)),Buffer.from(b.at(-index)));if(order)return order;
  }
  return a.length-b.length;
}
function dcOpenInterval(owner,next,value,compare){
  const span=compare(owner,next),left=compare(owner,value),right=compare(value,next);
  if([span,left,right].some(item=>item===null))return false;
  return span<0?left<0&&right<0:span>0?left<0||right<0:left!==0;
}
function dcCachedProof(ctx,actual,expected,location){
  if(!/\.cacheEntries\.\d+\.proofs\.\d+$/.test(location)||!actual||!expected||typeof actual!=='object'||typeof expected!=='object'||typeof actual.id!=='string'||typeof expected.id!=='string'||typeof actual.role!=='string'||typeof expected.role!=='string')return false;
  const before=ctx.row.failures.length,bindings=(ctx.oracle.setup.numericBindings?.proofs||[]).filter(item=>item.rrsetId===actual.id);
  if(!dcCheck(ctx.row,bindings.length===1,'cached-proof-exact-independent-tuple',location,'One selected independent proof tuple',bindings.length))return true;
  const binding=bindings[0],numeric=ctx.numeric(binding.numericFile),rrset=numeric.rrsets?.[binding.rrsetId],signature=numeric.signatures?.[binding.signatureId],zone=ctx.oracle.setup.initialCache?.zone;
  if(!dcCheck(ctx.row,!!rrset&&!!signature&&['NSEC','NSEC3'].includes(rrset.type)&&signature.signer===zone,'cached-proof-signed-zone',location,{zone,rrsetId:binding.rrsetId,signatureId:binding.signatureId},rrset?.owner))return true;
  const index=ctx.steps.findIndex(step=>step.id===ctx.step?.id),frame=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:index,milestone:'complete'});
  const bodies=frame.artifacts.filter(artifact=>{const value=dcRecord(artifact,'rrset');return value?.id===rrset.id&&['owner','type','class','records','canonicalRdataHex'].every(name=>isDeepStrictEqual(value[name],rrset[name]));});
  const signatures=frame.artifacts.filter(artifact=>dcRecord(artifact,'rrsig')?.rrsigRdataHex===signature.rrsigRdataHex);
  dcCheck(ctx.row,bodies.length>0&&signatures.length>0,'cached-proof-created-literal-material',location,'Already-created exact proof body and RRSIG',bodies.map(item=>item.artifactId));
  const parts=rrset.records[0].trim().split(/\s+/),roles=actual.role.split(/,\s*/),wanted=/^covers (?:wildcard )?(\S+\.)$/.exec(expected.role),predicates={};
  let witness=false;
  if(rrset.type==='NSEC'){
    dcEqual(ctx.row,[expected.zone,expected.owner,expected.next],[zone,rrset.owner,parts[0]],'cached-nsec-interval-tuple',location);
    dcEqual(ctx.row,expected.types.slice().sort(),parts.slice(1).sort(),'cached-nsec-type-set',location);
    const covers=name=>dcOpenInterval(rrset.owner,parts[0],name,dcNameOrder);
    witness=!!wanted&&covers(wanted[1]);
    predicates['requested-name-interval']=covers(ctx.oracle.setup.query.qname);
    predicates['closest-wildcard-interval']=covers('*.'+zone);
  }else{
    const profile=ctx.oracle.setup.nsec3,hashes=profile?.hashOutputs||{},wire=profile?.wireInputsHex||{},owner=rrset.owner.split('.')[0].toUpperCase(),next=parts[4].toUpperCase();
    const hashOf=name=>{const labels=dcDnsLabels(name);return labels&&wire[name]===dcNameWire(labels)?hashes[name]??null:null;};
    const ancestors=Object.keys(hashes).filter(name=>ctx.oracle.setup.query.qname===name||ctx.oracle.setup.query.qname.endsWith('.'+name)).sort((a,b)=>b.split('.').length-a.split('.').length);
    const closest=ancestors.find(name=>(ctx.oracle.setup.initialCache.proofs||[]).some(proof=>proof.ownerHash===hashOf(name))),labels=ctx.oracle.setup.query.qname.split('.').filter(Boolean),closestLabels=closest?.split('.').filter(Boolean).length,nextCloser=closest?labels.slice(-(closestLabels+1)).join('.')+'.':null;
    const covers=name=>{const value=name&&hashOf(name);return !!value&&dcOpenInterval(owner,next,value,(a,b)=>a<b?-1:a>b?1:0);};
    dcEqual(ctx.row,[Number(parts[0]),Number(parts[1]),Number(parts[2]),parts[3]==='-'?'':parts[3].toLowerCase()],[profile?.hashAlgorithm,expected.flags,profile?.iterations,profile?.saltHex],'cached-nsec3-parameter-tuple',location);
    dcEqual(ctx.row,[expected.ownerHash,expected.nextHash,hashOf(expected.originalOwner)],[owner,next,owner],'cached-nsec3-owner-preimage-tuple',location);
    dcEqual(ctx.row,expected.types.slice().sort(),parts.slice(5).sort(),'cached-nsec3-type-set',location);
    witness=expected.role==='matches closest encloser'?!!closest&&owner===hashOf(closest):!!wanted&&covers(wanted[1]);
    predicates['matching-closest-encloser-hash']=!!closest&&owner===hashOf(closest);
    predicates['covering-next-closer-hash']=covers(nextCloser);
    predicates['covering-closest-wildcard-hash']=!!closest&&covers('*.'+closest);
  }
  dcCheck(ctx.row,witness,'cached-proof-original-annotation-witness',location+'.role',expected.role,{owner:rrset.owner,records:rrset.records});
  dcCheck(ctx.row,roles.length>0&&roles.every(role=>predicates[role]===true),'cached-proof-actual-role-predicates',location+'.role','Every actual role follows independently from the signed interval and selected query',roles);
  for(const key of Object.keys(expected))if(!['id','role'].includes(key)){
    if(dcCheck(ctx.row,dcOwn(actual,key),'checkpoint-field-present',location+'.'+key,true,dcOwn(actual,key)))dcCompare(ctx,actual[key],expected[key],location+'.'+key);
  }
  if(ctx.row.failures.length===before){
    dcBijection(ctx.row,ctx.refs,ctx.reverseRefs,expected.id,actual.id,location+'.id');
    ctx.row.logicalProofBindings??=[];ctx.row.logicalProofBindings.push({location,expectedAlias:expected.id,actualRrsetId:rrset.id,signatureRdataSha256:dcSha(Buffer.from(signature.rrsigRdataHex,'hex')),originalAnnotation:expected.role,actualRoles:roles,meaning:'Exact cached proof identity and independently checked interval predicates; no status, ownership or authentication inferred'});
  }
  return true;
}
function dcHopPayloadReference(ctx,hop,expected,key,location){
  const pointer=typeof expected.bindingRef==='string'?/^(docs\/dnssec-expansion\/numeric\/[^#]+\.json)#([^#]+)$/.exec(expected.bindingRef):null;
  if(!pointer||!['bindingRef','signatureRef'].includes(key))return false;
  const numeric=ctx.numeric(pointer[1]),rrset=numeric.rrsets?.[pointer[2]],signature=numeric.signatures?.[expected.signatureRef];
  if(!dcCheck(ctx.row,!!rrset&&!!signature&&signature.rrsetId===rrset.id,'hop-payload-independent-tuple',location,{bindingRef:expected.bindingRef,signatureRef:expected.signatureRef},null))return true;
  const until=ctx.steps.findIndex(step=>step.id===ctx.step?.id),packets=dcActualPackets(ctx);
  const queries=packets.filter(item=>item.index<=until&&item.packet.flags?.QR===0&&item.message.from===hop.from&&item.message.to===hop.to&&dcSubset(item.packet.question,hop.question)&&(hop.query?.id==null||dcOccurrenceReference(ctx,item,hop.query.id))&&(hop.query?.messageId===undefined||item.packet.messageId===hop.query.messageId));
  if(!dcCheck(ctx.row,queries.length===1,'hop-payload-concrete-query',location,'One exact already-observed request occurrence',queries.map(item=>item.message.messageId)))return true;
  const query=queries[0],responses=packets.filter(item=>item.index<=until&&item.packet.flags?.QR===1&&item.message.from===hop.to&&item.message.to===hop.from&&item.packet.messageId===query.packet.messageId&&dcSubset(item.packet.question,hop.question)&&dcOccurrenceBefore(query,item)&&dcReplyMatches(ctx,item,query));
  if(!dcCheck(ctx.row,responses.length===1,'hop-payload-concrete-response',location,'One exact correlated response, not a summary payload claim',responses.map(item=>item.message.messageId)))return true;
  const objects=responses[0].packet.objects||[],matched=objects.filter(object=>{
    const artifact=ctx.artifacts.get(object.artifactId);
    if(key==='signatureRef')return dcRecord(artifact,'rrsig')?.rrsigRdataHex===signature.rrsigRdataHex;
    const value=dcRecord(artifact,'rrset');
    return value&&['owner','type','class','records','canonicalRdataHex'].every(name=>isDeepStrictEqual(value[name],rrset[name]));
  });
  if(dcCheck(ctx.row,matched.length===1,'hop-payload-reference-exact-attachment',location,{reference:expected[key],required:'One literal attached immutable input'},matched.map(item=>item.artifactId))){
    ctx.row.logicalPayloadBindings??=[];ctx.row.logicalPayloadBindings.push({location,expectedRef:expected[key],queryMessageId:query.message.messageId,responseMessageId:responses[0].message.messageId,artifactId:matched[0].artifactId,meaning:'Independent input pointer bound to the actual response attachment, not an additional wire field or an authentication claim'});
  }
  return true;
}
function dcCompare(ctx,actual,expected,location){
  const row=ctx.row;
  if(dcCachedProof(ctx,actual,expected,location))return;
  if(dcAnchor(ctx,actual,expected,location))return;
  if(dcMathematicalReference(ctx,actual,expected,location)||dcSignatureLabel(ctx,actual,expected,location)||dcRetryReference(ctx,actual,expected,location)||dcMutationActorReference(ctx,actual,expected,location))return;
  if(Array.isArray(expected)&&location.endsWith('.evidenceRefs')){dcEvidenceArray(ctx,actual,expected,location);return;}
  if(Array.isArray(expected)&&location.endsWith('.hops')){
    if(!dcCheck(row,Array.isArray(actual),'checkpoint-array',location,'array',typeof actual))return;
    const trace=ctx.currentState?.response?.traceHops;
    if(actual.length!==expected.length&&Array.isArray(trace)&&trace.length===expected.length&&expected.every((hop,index)=>['from','to','transport','question'].every(key=>isDeepStrictEqual(trace[index]?.[key],hop[key])))){
      actual=trace;row.logicalHopViewBindings??=[];
      row.logicalHopViewBindings.push({location,view:'complete trace',actualHopIds:trace.map(hop=>hop.id),meaning:'Same concrete conversations, including prerequisites; not extra deliveries or leaf-response payload'});
    }
    dcEqual(row,actual.length,expected.length,'checkpoint-array-length',location);
    for(let index=0;index<Math.min(actual.length,expected.length);index++){
      const a=actual[index],e=expected[index];
      if(!a||!e||typeof a!=='object'||typeof e!=='object')continue;
      const previousScope=ctx.hopWireScope,previousPair=ctx.hopPair;
      ctx.hopWireScope=e.id||JSON.stringify([index,e.from,e.to,e.question]);ctx.hopPair={actual:a,expected:e};
      try{
        const route=['from','to','transport','question'].every(key=>isDeepStrictEqual(a[key],e[key]));
        if(route){
          for(const [x,y] of [[e.id,a.id],[e.query?.id,a.query?.id],[e.response?.id,a.response?.id]])if(x!==undefined&&y!==undefined)dcBijection(row,ctx.refs,ctx.reverseRefs,x,y,location+'.'+index+'.id');
          for(const [x,y] of [[e.query?.messageId,a.query?.messageId],[e.response?.messageId,a.response?.messageId]])if(x!==undefined&&y!==undefined)dcBijection(row,ctx.wireIds,ctx.reverseWireIds,ctx.hopWireScope+'|'+x,ctx.hopWireScope+'|'+y,location+'.'+index+'.messageId');
        }
        if(a.response&&a.query){
          if(dcOwn(a.response,'inReplyTo'))dcEqual(row,a.response.inReplyTo,a.query.id??a.query.messageId,'hop-response-correlation',location+'.'+index);
          if(dcOwn(a.response,'messageId')&&dcOwn(a.query,'messageId'))dcEqual(row,a.response.messageId,a.query.messageId,'hop-wire-id-correlation',location+'.'+index);
        }
        dcCompare(ctx,a,e,location+'.'+index);
      }finally{ctx.hopWireScope=previousScope;ctx.hopPair=previousPair;}
    }
    return;
  }
  if(expected&&typeof expected==='object'){
    if(!dcCheck(row,actual!==null&&typeof actual==='object','checkpoint-structure',location,'object',actual))return;
    if(Array.isArray(expected)){
      if(!dcCheck(row,Array.isArray(actual),'checkpoint-array',location,'array',actual))return;
      dcEqual(row,actual.length,expected.length,'checkpoint-array-length',location);
    }
    const cacheIdentity=!Array.isArray(expected)&&typeof expected.id==='string'&&typeof actual.id==='string'&&actual.id!==expected.id&&['kind','key','receivedAt','expiresAt','securityStatus','validationOwner'].every(field=>dcOwn(expected,field))&&/cacheEntries/.test(location);
    const failuresBefore=ctx.row.failures.length;
    const previousEvidenceScope=ctx.evidenceScope;
    if(dcOwn(expected,'evidenceRefs'))ctx.evidenceScope=expected;
    try{
      for(const key of Object.keys(expected)){
        if(cacheIdentity&&key==='id')continue;
        if(!dcOwn(actual,key)&&ctx.hopPair?.actual===actual&&dcHopPayloadReference(ctx,actual,expected,key,location+'.'+key))continue;
        if(!dcCheck(row,dcOwn(actual,key),'checkpoint-field-present',location+'.'+key,true,dcOwn(actual,key)))continue;
        dcCompare(ctx,actual[key],expected[key],location+'.'+key);
      }
    }finally{ctx.evidenceScope=previousEvidenceScope;}
    if(cacheIdentity)dcCacheIdentity(ctx,actual,expected,location,failuresBefore);
    return;
  }
  if(dcReference(ctx,actual,expected,location))return;
  if(isDeepStrictEqual(actual,expected)){row.assertions++;return;}
  if(typeof expected==='string'&&ctx.refs.has(expected)){dcEqual(row,actual,ctx.refs.get(expected),'checkpoint-correlated-ref',location);return;}
  if(typeof expected==='number'&&location.endsWith('.messageId')&&ctx.hopWireScope&&ctx.wireIds.has(ctx.hopWireScope+'|'+expected)){dcEqual(row,ctx.hopWireScope+'|'+actual,ctx.wireIds.get(ctx.hopWireScope+'|'+expected),'checkpoint-correlated-wire-id',location);return;}
  dcEqual(row,actual,expected,'independent-checkpoint-value',location);
}
function dcOccurrenceBefore(left,right){
  return left.index<right.index||left.index===right.index&&left.message.end<=right.message.start;
}
const dcOccurrenceOrder=(left,right)=>left.index-right.index||left.message.start-right.message.start||left.message.end-right.message.end||left.message.messageId.localeCompare(right.message.messageId);
function dcOccurrenceReference(ctx,item,ref){
  if([item.message.messageId,item.step.id,item.packet.occurrenceId,item.packet.id,item.packet.messageId].includes(ref))return true;
  if(typeof ref!=='string')return false;
  const prefix=ctx.model.id+':',relative=ref.startsWith(prefix)?ref.slice(prefix.length):ref;
  return item.step.id===prefix+ctx.model.caseId+':'+relative;
}
function dcReplyMatches(ctx,reply,query){
  if(reply.message.inReplyTo!=null&&reply.message.inReplyTo!==query.message.messageId)return false;
  const ref=reply.packet.inReplyTo;
  if(ref==null)return true;
  return dcOccurrenceReference(ctx,query,ref);
}
function dcActualPackets(ctx){
  if(ctx.packetOccurrences)return ctx.packetOccurrences;
  const packets=[];
  for(const [index,step] of ctx.steps.entries())for(const message of ctx.compiled.plan.events[step.id]?.messages||[]){
    const headers=[];
    for(const object of message.objects){
      const artifact=ctx.artifacts.get(object.artifactId);
      if(artifact?.type==='dns-header')headers.push(artifact);
      const plaintext=dcRecord(artifact,'event')?.plaintextRef;
      if(plaintext){const header=ctx.artifacts.get(plaintext);if(header?.type==='dns-header')headers.push(header);}
    }
    for(const header of headers){const packet=dcRecord(header,'header');if(packet)packets.push({index,step,message,header,packet});}
  }
  return ctx.packetOccurrences=packets.sort(dcOccurrenceOrder);
}
const dcWireOpKey=(kind,actor,instance,attribute,representation,messageId)=>JSON.stringify([kind,actor,instance,attribute,representation,messageId===undefined?null:[messageId]]);
const dcOpCount=entry=>entry===undefined?0:Array.isArray(entry)?entry.length:1;
function dcWireValues(row,entry,expected,location){
  if(Array.isArray(entry)){for(const op of entry)dcEqual(row,op.value,expected,'wire-exact-field-value',location);}
  else if(entry!==undefined)dcEqual(row,entry.value,expected,'wire-exact-field-value',location);
}
function dcWire(ctx){
  const {row,compiled,api}=ctx,packets=[];
  const privateHandles=[...ctx.artifacts.values()].filter(artifact=>artifact.type==='private-key-handle').map(artifact=>dcRecord(artifact,'secret')?.handle).filter(value=>typeof value==='string'&&value.length);
  const exactHolding=(frame,actor,object)=>frame.holdings.some(h=>h.actorId===actor&&h.artifactId===object.artifactId&&h.representationId===object.representationId);
  for(const [index,step] of ctx.steps.entries()){
    const event=compiled.plan.events[step.id];
    const operations=new Map();
    for(const op of step.attributeOperations||[]){
      if(op.kind!=='send'&&op.kind!=='receive')continue;
      const key=dcWireOpKey(op.kind,op.actorId,op.instanceId,op.attributeId,op.representation,op.messageId),existing=operations.get(key);
      if(existing===undefined)operations.set(key,op);
      else if(Array.isArray(existing))existing.push(op);
      else operations.set(key,[existing,op]);
    }
    if((step.attributeOperations?.length||0)>=10000)dcNote(row,'stage-progress','concrete-wire',{phase:'field-index-ready',eventIndex:index,stepId:step.id,operations:step.attributeOperations.length,indexedOperationKeys:operations.size});
    for(const message of event?.messages||[]){
      row.messages++;
      // Batch transfers may start and end inside one event. Project precisely at
      // the authored interval, not at the containing event's outer boundaries.
      const before=api.projectHeldObjects(compiled,{eventIndex:index,progress:message.start});
      const after=api.projectHeldObjects(compiled,{eventIndex:index,progress:message.end});
      for(const object of message.objects){
        const artifact=ctx.artifacts.get(object.artifactId),rep=artifact?.representations.find(item=>item.representationId===object.representationId);
        const wireText=JSON.stringify(rep?.fields||[]);
        for(const handle of privateHandles)dcCheck(row,!wireText.includes(JSON.stringify(handle).slice(1,-1)),'wire-no-private-handle-value',message.messageId,'Private handle never appears in any carried representation',object.artifactId);
        const senderHas=exactHolding(before,message.from,object),receiverHas=exactHolding(after,message.to,object);
        dcCheck(row,senderHas,'wire-sender-custody',message.messageId,object,senderHas?undefined:dcNormalize(before));
        dcCheck(row,receiverHas,'wire-receiver-custody',message.messageId,object,receiverHas?undefined:dcNormalize(after));
        dcCheck(row,artifact?.type!=='private-key-handle','wire-private-containment',message.messageId,'Public representation only',artifact?.type);
        for(const direction of ['send','receive'])for(const field of rep?.fields||[]){
          const actor=direction==='send'?message.from:message.to;
          const tagged=operations.get(dcWireOpKey(direction,actor,object.artifactId,field.attributeId,object.representationId,message.messageId));
          const legacy=event.messages.length===1?operations.get(dcWireOpKey(direction,actor,object.artifactId,field.attributeId,object.representationId,undefined)):undefined;
          const count=dcOpCount(tagged)+dcOpCount(legacy),location=message.messageId+'.'+field.attributeId;
          dcCheck(row,count>0,'wire-concrete-field-operation',location,{direction,actor,artifactId:object.artifactId},tagged??legacy);
          dcCheck(row,count<=1,'wire-unambiguous-field-operation',location,'At most one exact matching operation',count);
          dcWireValues(row,tagged,field.value,location);dcWireValues(row,legacy,field.value,location);
        }
      }
      const headers=message.objects.map(object=>ctx.artifacts.get(object.artifactId)).filter(artifact=>artifact?.type==='dns-header');
      // Publication channels legitimately carry RRsets without DNS headers.
      // Encrypted DNS carries an opaque artifact whose exact plaintextRef is checked.
      for(const object of message.objects){
        const artifact=ctx.artifacts.get(object.artifactId);
        const carrier=dcRecord(artifact,'event');
        if(carrier?.plaintextRef){const header=ctx.artifacts.get(carrier.plaintextRef);dcCheck(row,header?.type==='dns-header','tls-concrete-plaintext',message.messageId,'dns-header',header?.type);if(header)headers.push(header);}
      }
      for(const header of headers){
        const packet=dcRecord(header,'header');
        dcCheck(row,!!packet&&typeof packet==='object','wire-concrete-header',message.messageId,'Concrete DNS packet',packet);
        if(!packet)continue;
        packets.push({packet,message,step,index,header});row.dnsPackets++;
        dcCheck(row,Number.isInteger(packet.messageId)&&packet.messageId>=0&&packet.messageId<=65535,'wire-u16-id',message.messageId,'Unsigned 16-bit DNS ID',packet.messageId);
        if(packet.question){for(const key of ['qname','qtype','qclass'])dcCheck(row,typeof packet.question[key]==='string'&&packet.question[key].length>0,'wire-concrete-question',message.messageId+'.'+key,'Nonempty question field',packet.question[key]);}
        dcEqual(row,packet.questionCount,packet.question?(packet.question.qdcount??1):0,'wire-question-count',message.messageId);
        dcCheck(row,Array.isArray(packet.objects),'wire-concrete-body',message.messageId,'objects array',packet.objects);
        const body=new Map((packet.objects||[]).map(object=>[object.artifactId,object]));
        for(const object of packet.objects||[]){
          const target=ctx.artifacts.get(object.artifactId);
          dcCheck(row,!!target,'wire-body-reference',message.messageId,object.artifactId,target?.artifactId);
          const values=target?.representations.flatMap(rep=>rep.fields).filter(field=>/^dnssec_.*_record$/.test(field.attributeId)).map(field=>field.value)||[];
          dcCheck(row,values.some(value=>isDeepStrictEqual(value,object.value)),'wire-body-exact-tuple',message.messageId+'.'+object.artifactId,values,object.value);
        }
        for(const section of ['answer','authority','additional']){
          const members=packet.recordSections?.[section];
          if(!dcCheck(row,Array.isArray(members),'wire-concrete-section',message.messageId+'.'+section,'Ordered concrete record section',members))continue;
          let count=section==='additional'&&packet.edns?.present?1:0;
          for(const item of members){const object=body.get(item.artifactId),target=ctx.artifacts.get(item.artifactId),rr=dcRecord(target,'rrset')||dcRecord(target,'glue'),sig=dcRecord(target,'rrsig');dcCheck(row,!!object,'wire-section-object',message.messageId+'.'+section,item.artifactId,object?.artifactId);dcCheck(row,Number.isInteger(item.recordCount)&&item.recordCount>=0,'wire-section-record-count',message.messageId+'.'+section,'Nonnegative integer',item.recordCount);if(rr?.records)dcEqual(row,item.recordCount,rr.records.length,'wire-section-rrset-count',message.messageId+'.'+section);else if(sig)dcEqual(row,item.recordCount,1,'wire-section-rrsig-count',message.messageId+'.'+section);count+=item.recordCount;}
          dcEqual(row,packet[section+'Count'],count,'wire-header-section-count',message.messageId+'.'+section);
        }
        if(packet.referral)dcEqual(row,packet.referral.glueAuthenticated,false,'referral-not-trust',message.messageId);
      }
      if(row.messages%128===0)dcNote(row,'stage-progress','concrete-wire',{phase:'messages',eventIndex:index,stepId:step.id});
    }
  }
  // Use concrete delivery intervals within a Source event, not SourceIndex alone.
  // Numeric IDs, exact questions, endpoints and explicit reply identities still
  // have to correlate; a batch never creates a request by mere array position.
  const ordered=packets.slice().sort(dcOccurrenceOrder);
  for(const item of ordered.filter(item=>item.packet.flags?.QR===1)){
    const p=item.packet,requester=p.intendedReceiver||item.message.to;
    let question=p.question;
    if(!question&&p.questionCount===0&&p.flags.OPCODE==='QUERY'){
      const origins=ordered.filter(other=>dcOccurrenceBefore(other,item)&&other.packet.messageId===p.messageId&&other.packet.flags?.QR===1&&other.message.from===item.message.from&&other.message.to===item.message.to&&['AXFR','IXFR'].includes(other.packet.question?.qtype));
      const distinct=[...new Map(origins.map(other=>[JSON.stringify(other.packet.question),other.packet.question])).values()];
      if(distinct.length===1)question=distinct[0];
      dcCheck(row,distinct.length===1,'transfer-continuation-question-scope',item.message.messageId,'One exact earlier same-route transfer question',distinct);
    }
    const samePacket=other=>other.packet.messageId===p.messageId&&(isDeepStrictEqual(other.packet.question,question)||!other.packet.question&&other.packet.questionCount===0&&['AXFR','IXFR'].includes(question?.qtype));
    const earlier=ordered.filter(other=>dcOccurrenceBefore(other,item)&&samePacket(other));
    const replies=earlier.filter(q=>{
      if(q.packet.flags?.QR!==0||q.message.from!==requester||!dcReplyMatches(ctx,item,q))return false;
      const reachable=new Map([[q.message.to,q]]);
      for(const forwarded of earlier)if(forwarded.packet.flags?.QR===1&&dcOccurrenceBefore(q,forwarded)){
        const receipt=reachable.get(forwarded.message.from);
        if(receipt&&dcOccurrenceBefore(receipt,forwarded))reachable.set(forwarded.message.to,forwarded);
      }
      const receipt=reachable.get(item.message.from);
      return !!receipt&&dcOccurrenceBefore(receipt,item);
    });
    dcCheck(row,replies.length>0,'wire-response-has-concrete-request',item.message.messageId,'Earlier exact-question request with an exact correlated forwarding path',replies.map(q=>q.message.messageId));
  }
  return ordered;
}
function dcSubset(actual,expected){
  if(expected===null||typeof expected!=='object')return isDeepStrictEqual(actual,expected);
  if(actual===null||typeof actual!=='object'||Array.isArray(expected)!==Array.isArray(actual))return false;
  if(Array.isArray(expected)&&actual.length!==expected.length)return false;
  return Object.keys(expected).every(key=>dcOwn(actual,key)&&dcSubset(actual[key],expected[key]));
}
function dcBoundInputQuestion(ctx,declared){
  const input=ctx.oracle.setup,selection=input.numericBindings;
  if(input.qname!==declared.qname||input.qtype!==declared.qtype||typeof selection?.fixtures!=='string')return null;
  const file=selection.fixtures.startsWith('numeric/')?'docs/dnssec-expansion/'+selection.fixtures:selection.fixtures,numeric=ctx.numeric(file);
  let records;
  if(selection.rrsetId){
    const rrset=numeric.rrsets?.[selection.rrsetId];
    if(!rrset||rrset.type!==input.qtype)return null;
    if(selection.mutationId){
      const mutations=(numeric.vectors?.mutations||[]).filter(item=>item.id===selection.mutationId&&item.rrsetId===selection.rrsetId&&item.signatureId===selection.signatureId&&item.owner===input.qname&&item.type===input.qtype);
      if(mutations.length!==1||dcOwn(mutations[0],'class')&&mutations[0].class!==rrset.class)return null;
    }else if(rrset.owner!==input.qname||!isDeepStrictEqual(rrset.records,input.answer))return null;
    records=[rrset];
  }else records=Object.values(numeric.rrsets||{}).filter(rrset=>rrset.owner===input.qname&&rrset.type===input.qtype&&isDeepStrictEqual(rrset.records,input.answer));
  const classes=new Set(records.map(rrset=>rrset.class));
  if(!records.length||classes.size!==1||typeof records[0].class!=='string'||!records[0].class.length)return null;
  const question={qname:input.qname,qtype:input.qtype,qclass:records[0].class};
  ctx.row.logicalQuestionClassBindings??=[];
  if(!ctx.row.logicalQuestionClassBindings.some(item=>isDeepStrictEqual(item.question,question)))ctx.row.logicalQuestionClassBindings.push({question,numericFile:file,rrsetIds:records.map(rrset=>rrset.id),mutationId:selection.mutationId??null,meaning:'Class from exact independently declared RRset or its explicit mutation, never a default'});
  return question;
}
function dcHopQuestion(ctx,hop){
  const declared=hop.question||hop.query?.question;
  if(!declared)return null;
  const candidates=[];
  for(const point of ctx.oracle.checkpoints)dcVisit(point.expected,value=>{
    if(value&&typeof value==='object'&&value.from===hop.from&&value.to===hop.to){
      const question=value.question||value.query?.question;
      if(question&&dcSubset(question,declared))candidates.push(question);
    }
  });
  if(ctx.oracle.setup.query&&dcSubset(ctx.oracle.setup.query,declared))candidates.push(ctx.oracle.setup.query);
  const boundInput=dcBoundInputQuestion(ctx,declared);if(boundInput)candidates.push(boundInput);
  const complete=[...new Map(candidates.filter(question=>question.qclass).map(question=>[JSON.stringify(question),question])).values()];
  // Filling an omitted summary field requires an independently declared exact
  // question. The original summary still undergoes the checkpoint comparison.
  if(complete.length){
    const fields=[...new Set(complete.flatMap(question=>Object.keys(question)))];
    if(fields.every(field=>new Set(complete.filter(question=>dcOwn(question,field)).map(question=>JSON.stringify(question[field]))).size===1)){
      const question=Object.assign({},...complete);
      if(declared.qclass!==undefined)dcEqual(ctx.row,declared.qclass,question.qclass,'hop-summary-independent-question-class',hop.id??'hop.question');
      return {...declared,...question};
    }
  }
  return declared.qclass?declared:null;
}
function dcIndependentHop(ctx,hop){
  const declarations=new Map();
  for(const point of ctx.oracle.checkpoints)for(const expected of point.expected.response?.hops||[])if(expected.id===hop.id||ctx.refs.get(expected.id)===hop.id)declarations.set(expected.id,expected);
  for(const expected of ctx.oracle.outcome.flags?.hops||[])if(expected.id===hop.id||ctx.refs.get(expected.id)===hop.id)declarations.set(expected.id,expected);
  return declarations.size===1?[...declarations.values()][0]:null;
}
function dcUndeliveredHop(ctx,hop,expected,question,location){
  const delivery=expected.delivery;
  dcCompare(ctx,hop.delivery,delivery,'concrete-hop.'+location+'.delivery');
  dcEqual(ctx.row,hop.response,null,'attempt-only-no-response-descriptor',location);
  const attempts=hop.attempts?.length?hop.attempts:[{query:hop.query,response:hop.response}];
  dcEqual(ctx.row,attempts.length,delivery.attempts??1,'attempt-only-exact-attempt-count',location);
  const used=new Set();
  for(const [index,attempt] of attempts.entries()){
    const path=location+'.attempt.'+index,stepIndex=ctx.steps.findIndex(step=>step.id===attempt.query?.id),step=ctx.steps[stepIndex];
    if(!dcCheck(ctx.row,stepIndex>=0&&!used.has(stepIndex),'attempt-only-concrete-local-step',path,'Distinct actual local attempt source step',attempt.query?.id))continue;
    used.add(stepIndex);
    const event=ctx.compiled.plan.events[step.id],frame=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:stepIndex,milestone:'complete'});
    dcEqual(ctx.row,[step.from,step.to],[expected.from,expected.from],'attempt-only-local-actor',path);
    dcEqual(ctx.row,step.channel,'internal','attempt-only-local-channel',path);
    dcEqual(ctx.row,event.messages?.length??0,0,'attempt-only-no-invented-wire-transfer',path);
    dcEqual(ctx.row,attempt.response,null,'attempt-only-no-retry-response',path);
    const records=(step.attributeOperations||[]).filter(op=>op.attributeId==='dnssec_event_record').map(op=>op.value);
    dcCheck(ctx.row,records.some(value=>dcSubset(value,{transport:expected.transport,intendedReceiver:expected.to,delivered:false})),'attempt-only-explicit-intent',path,{transport:expected.transport,intendedReceiver:expected.to,delivered:false},records);
    const ids=new Set((step.attributeOperations||[]).filter(op=>op.kind==='create').map(op=>op.instanceId));
    const headers=[...ids].map(id=>ctx.artifacts.get(id)).filter(artifact=>artifact?.type==='dns-header').filter(artifact=>dcSubset(dcRecord(artifact,'header')?.question,question));
    if(!dcCheck(ctx.row,headers.length===1,'attempt-only-exact-unsent-header',path,'One actual prepared DNS query artifact',headers.map(artifact=>artifact.artifactId)))continue;
    const artifact=headers[0],packet=dcRecord(artifact,'header');
    dcCheck(ctx.row,frame.holdings.some(h=>h.artifactId===artifact.artifactId&&h.actorId===expected.from&&h.retention==='temporary'),'attempt-only-output-custody',path,{artifactId:artifact.artifactId,actorId:expected.from,retention:'temporary'},dcNormalize(frame));
    dcCheck(ctx.row,!frame.holdings.some(h=>h.artifactId===artifact.artifactId&&h.actorId===expected.to),'attempt-only-no-server-receipt',path,'No receiver holding of the undelivered query',expected.to);
    dcEqual(ctx.row,packet.flags.QR,0,'attempt-only-query-not-response',path);
    dcCheck(ctx.row,Number.isInteger(packet.messageId)&&packet.messageId>=0&&packet.messageId<=65535,'attempt-only-u16-id',path,'Unsigned 16-bit DNS ID',packet.messageId);
    for(const name of ['flags','edns'])if(dcOwn(expected.query,name))dcCompare(ctx,packet[name],expected.query[name],'attempt-only.'+path+'.'+name);
    dcEqual(ctx.row,packet.messageId,attempt.query.messageId,'attempt-only-artifact-id-correlation',path);
    ctx.seenTransportAttempts??=new Set();
    if(!ctx.seenTransportAttempts.has(step.id)){ctx.seenTransportAttempts.add(step.id);ctx.row.localTransportAttempts=(ctx.row.localTransportAttempts||0)+1;}
  }
}
function dcHopPackets(ctx,final,packets){
  const used=new Map(),claims=new Map(),seen=new Set();
  const families=[['response',final.response?.hops||[]],['evidence',final.response?.evidenceHops||[]],['trace',final.response?.traceHops||[]],['management',final.publication?.managementHops||[]],['management-extra',final.managementHops||[]],['anchor-management',final.management?.hops||[]]];
  ctx.row.hopSummaryViews=Object.fromEntries(families.map(([name,hops])=>[name,hops.length]));ctx.row.hopSummaryReferences=0;
  for(const [family,hops] of families)for(const [index,hop] of hops.entries())dcStage(ctx.row,'concrete-'+family+'-hop:'+index,()=>{
    ctx.row.hopSummaryReferences++;
    const location=family+'.'+index,identity=hop.id??JSON.stringify([hop.from,hop.to,hop.transport,hop.question,hop.query?.id??hop.query?.messageId,hop.response?.id??hop.response?.messageId]),scope=family+':'+identity,summary=dcCopy(hop),known=claims.get(identity),sameDescriptor=!known||isDeepStrictEqual(summary,known);
    dcCheck(ctx.row,!seen.has(scope),'hop-summary-unique-within-view',location,'One reference to an actual hop in each summary view',scope);seen.add(scope);
    if(known)dcEqual(ctx.row,summary,known,'hop-cross-view-exact-descriptor',location);else claims.set(identity,summary);
    const question=dcHopQuestion(ctx,hop);
    if(!dcCheck(ctx.row,!!question,'hop-independent-question-scope',location,'Concrete qname/qtype/qclass, independently scoped when a summary omits class',hop.question||hop.query?.question))return;
    const independent=dcIndependentHop(ctx,hop);
    if(independent?.delivery?.attempted===true&&independent.delivery.queryDelivered===false&&independent.delivery.responseReceived===false){dcUndeliveredHop(ctx,hop,independent,question,location);return;}
    const route=packets.filter(item=>item.packet.flags?.QR===0&&item.message.from===hop.from&&item.message.to===hop.to&&dcSubset(item.packet.question,question)&&(!hop.transport||item.packet.transport===hop.transport)&&(!used.has(item.message.messageId)||sameDescriptor&&used.get(item.message.messageId)===identity)&&(hop.query?.id==null||dcOccurrenceReference(ctx,item,hop.query.id))&&(hop.query?.messageId===undefined||item.packet.messageId===hop.query.messageId));
    const matching=route.filter(item=>['flags','edns'].every(key=>!dcOwn(hop.query,key)||dcSubset(item.packet[key],hop.query[key])));
    const candidates=matching.length?matching:route,selected=candidates.length===1?candidates[0]:null;
    if(!dcCheck(ctx.row,!!selected,'hop-concrete-query',location,{required:'One exact request occurrence',from:hop.from,to:hop.to,question,queryId:hop.query?.id,messageId:hop.query?.messageId,flags:hop.query?.flags,transport:hop.transport},candidates.map(item=>({messageId:item.message.messageId,packet:item.packet}))))return;
    used.set(selected.message.messageId,identity);
    const numeric=new Map(),reverseNumeric=new Map();
    const comparePacket=(item,direction)=>{
      const descriptor=hop[direction];
      for(const key of ['flags','edns','rcode'])if(dcOwn(descriptor,key))dcCompare(ctx,item.packet[key],descriptor[key],'concrete-hop.'+location+'.'+direction+'.'+key);
      if(hop.transport)dcEqual(ctx.row,item.packet.transport,hop.transport,'hop-concrete-transport',location+'.'+direction);
      const id=descriptor?.messageId??(typeof descriptor?.id==='number'?descriptor.id:undefined);
      if(id!==undefined){
        if(item.packet.wireHex||item.packet.tsig)dcEqual(ctx.row,item.packet.messageId,id,'fixed-signed-wire-id-not-alpha-converted',location+'.'+direction);
        dcBijection(ctx.row,numeric,reverseNumeric,id,item.packet.messageId,'actual-wire-occurrence.'+scope+'.'+direction);
      }
    };
    comparePacket(selected,'query');
    const queryPosition=packets.indexOf(selected);
    const responses=packets.filter((item,position)=>{
      if(position<=queryPosition||!dcOccurrenceBefore(selected,item)||item.packet.flags?.QR!==1||item.message.to!==hop.from||item.packet.messageId!==selected.packet.messageId||!dcSubset(item.packet.question,question)||!dcReplyMatches(ctx,item,selected))return false;
      if(item.message.from===hop.to)return true;
      const reachable=new Map([[hop.to,selected]]);
      for(const prior of packets.slice(queryPosition+1,position).filter(prior=>prior.packet.flags?.QR===1&&prior.packet.messageId===selected.packet.messageId&&dcSubset(prior.packet.question,question))){
        const receipt=reachable.get(prior.message.from);
        if(receipt&&dcOccurrenceBefore(receipt,prior))reachable.set(prior.message.to,prior);
      }
      const receipt=reachable.get(item.message.from);
      return !!receipt&&dcOccurrenceBefore(receipt,item);
    });
    if(hop.response===null){dcEqual(ctx.row,responses.length,0,'hop-no-invented-response',location);return;}
    dcCheck(ctx.row,responses.length>0,'hop-concrete-response',location,{from:hop.to,to:hop.from,question,actualDnsId:selected.packet.messageId},responses.map(item=>item.message.messageId));
    if(dcOwn(hop.query,'messageId')&&dcOwn(hop.response,'messageId'))dcEqual(ctx.row,hop.response.messageId,hop.query.messageId,'summary-occurrence-id-correlation',location);
    for(const item of responses){comparePacket(item,'response');dcEqual(ctx.row,item.packet.messageId,selected.packet.messageId,'actual-query-response-id-correlation',location);}
    ctx.row.logicalHopBindings??=[];ctx.row.logicalHopBindings.push({scope,queryMessageId:selected.message.messageId,responseMessageIds:responses.map(item=>item.message.messageId),actualDnsId:selected.packet.messageId,question});
  });
}
function dcConfiguredTrustStores(stores){
  const fields=['anchors','provisioning','scope','view','installedBy','provenance','anchorSource','anchorRef','anchorBinding','owner'];
  return Object.fromEntries(Object.entries(stores||{}).flatMap(([id,store])=>{
    const configured=Object.fromEntries(fields.filter(field=>dcOwn(store,field)).map(field=>[field,store[field]]));
    return Object.keys(configured).length?[[id,dcCopy(configured)]]:[];
  }));
}
function dcPreservation(ctx,frames){
  const {row}=ctx,artifacts=new Map(),caches=new Map(),memo=new WeakMap(),artifactValues=new WeakMap();
  let checkedPrefixes=0;
  for(const frame of frames){
    for(const artifact of frame.artifacts){
      let value=artifactValues.get(artifact);
      if(value===undefined){
        const projected=dcPreservedValue(artifact,memo);value={...projected.value};delete value.contextId;delete value.qualifiedArtifactId;
        if(projected.immutable)artifactValues.set(artifact,value);
      }
      if(artifacts.has(artifact.artifactId))dcEqual(row,value,artifacts.get(artifact.artifactId),'immutable-earlier-artifact',artifact.artifactId);
      else artifacts.set(artifact.artifactId,value);
      if(artifact.type==='private-key-handle'){
        for(const rep of artifact.representations){dcEqual(row,rep.readableBy,[artifact.creator],'private-representation-readers',artifact.artifactId);for(const field of rep.fields)if(field.readableBy)dcEqual(row,field.readableBy,[artifact.creator],'private-field-readers',artifact.artifactId+'.'+field.attributeId);}
      }
    }
    for(const holding of frame.holdings){
      const artifact=ctx.artifacts.get(holding.artifactId);
      if(artifact?.type==='private-key-handle')dcEqual(row,holding.actorId,artifact.creator,'private-every-prefix-custody',holding.holdingId);
      if(holding.actorId==='dnsValidator'&&['dns-header','dns-rrset','dns-rrsig','dns-dnskey','dns-ds','dns-glue'].includes(artifact?.type))dcCheck(row,!frame.holdings.some(other=>other.actorId==='dnsResolver'&&other.artifactId===holding.artifactId&&other.representationId===holding.representationId),'in-process-validator-no-buffer-copy',holding.holdingId,'No invented duplicate resolver buffer',holding);
    }
    const dns=frame.state.dnssec;
    // Cache observations of the same immutable generation keep their original
    // receipt, provenance and deadline; current remaining TTL may legitimately age.
    dcVisit(dns,(value,location)=>{
      if(!value||typeof value!=='object'||Array.isArray(value)||!dcOwn(value,'id')||!dcOwn(value,'expiresAt')||!dcOwn(value,'receivedAt'))return;
      const stable=Object.fromEntries(Object.entries(value).filter(([key])=>!['remainingTtl','remaining','usable','eligibleForReuse','expired','status','reused'].includes(key)));
      if(Number.isFinite(value.signatureDeadline))dcCheck(row,value.expiresAt<=value.signatureDeadline,'cache-deadline-within-signature',location,value.signatureDeadline,value.expiresAt);
      const projected=dcPreservedValue(stable,memo).value;
      if(caches.has(value.id))dcEqual(row,projected,caches.get(value.id),'immutable-cache-generation',location+'.'+value.id);else caches.set(value.id,projected);
    });
    checkedPrefixes++;
    if(checkedPrefixes%128===0||checkedPrefixes===frames.length)dcNote(row,'stage-progress','immutable-generations',{checkedPrefixes,immutableArtifacts:artifacts.size,immutableCacheGenerations:caches.size});
  }
  const declarations=ctx.oracle.outcome.preservedState||[];
  if(declarations.some(text=>/anchors?.*(unchanged|remain unchanged)/i.test(text)))dcEqual(row,dcConfiguredTrustStores(frames.at(-1).state.dnssec.trustStores),dcConfiguredTrustStores(frames[0].state.dnssec.trustStores),'declared-trust-store-preservation','outcome.preservedState');
  row.preservation={declarations,immutableArtifacts:artifacts.size,immutableCacheGenerations:caches.size,checkedAtPrefixes:frames.length,assertions:dcPreservedOutcomes(ctx,frames)};
}
function dcPreservedOutcomes(ctx,frames){
  const final=frames.at(-1).state.dnssec,initial=frames[0].state.dnssec,proofs=[];
  const read=(value,name)=>name.split('.').reduce((value,key)=>value?.[key],value);
  const latest=new Map();
  for(const point of ctx.oracle.checkpoints)dcVisit(point.expected,(value,name)=>{if(value===null||typeof value!=='object'||Array.isArray(value))latest.set(name,value);});
  const independentFields=(prefixes,location)=>{
    const selected=[...latest].filter(([name])=>prefixes.some(prefix=>name===prefix||name.startsWith(prefix+'.')));
    dcCheck(ctx.row,selected.length>0,'preserved-independent-field-prerequisite',location,prefixes,selected.map(([name])=>name));
    for(const [name,expected] of selected)dcCompare(ctx,read(final,name),expected,location+'.'+name);
  };
  const rootAnchor=location=>{
    const anchors=[];dcVisit(final.trustStores,(value,name)=>{if(name.endsWith('anchors')&&Array.isArray(value))anchors.push(...value);});
    dcCheck(ctx.row,anchors.includes('root-ksk-g1'),'preserved-exact-root-anchor',location,'root-ksk-g1',anchors);
  };
  for(const [index,declaration] of (ctx.oracle.outcome.preservedState||[]).entries()){
    const location='outcome.preservedState.'+index,before=ctx.row.failures.length,assertionsBefore=ctx.row.assertions;
    switch(declaration){
      case 'Configured trust anchors remain unchanged.':
      case 'All anchors and unrelated caches remain unchanged.':
        dcEqual(ctx.row,dcConfiguredTrustStores(final.trustStores),dcConfiguredTrustStores(initial.trustStores),'preserved-configured-trust-store',location);break;
      case 'Signer-only private keys remain at dnsSigner.':
      case 'Private signing keys remain signer-only.':
      case 'Private keys remain signer-only.':{
        const handles=ctx.compiled.plan.artifacts.filter(artifact=>artifact.type==='private-key-handle');
        dcCheck(ctx.row,handles.length>0,'preserved-private-capability-prerequisite',location,'Actual signer handles',handles.length);
        for(const frame of frames)for(const h of frame.holdings){const artifact=ctx.artifacts.get(h.artifactId);if(artifact?.type==='private-key-handle')dcEqual(ctx.row,h.actorId,artifact.creator,'preserved-signer-only-custody',location);}
        break;
      }
      case 'Unrelated valid cache entries retain their original provenance and expiry.':
      case 'Unrelated negative/positive caches retain provenance.':
      case 'Authenticated CNAME RRset can remain separately cached with original expiry.':
      case 'existing RRSIGs':
        // The earlier every-prefix pass checks every generation, including
        // expired/unused objects, rather than only the eventual selected answer.
        dcCheck(ctx.row,!ctx.row.failures.some(f=>['immutable-earlier-artifact','immutable-cache-generation'].includes(f.check)),'preserved-immutable-generations',location,'No generation/provenance mutation',ctx.row.preservation?.immutableCacheGenerations??'Every-prefix immutable generation pass');break;
      case 'Previously received raw public records remain readable; failed records are not promoted to a trusted answer.':
      case 'Target failure never rewrites alias origin or confers target trust.':
        if(final.securityStatus==='bogus')dcEqual(ctx.row,final.acceptedForUse,false,'preserved-failed-data-not-promoted',location);
        dcCheck(ctx.row,!ctx.row.failures.some(f=>f.check==='immutable-earlier-artifact'),'preserved-raw-public-records',location,'No prior public object mutation',true);break;
      case 'root trust anchor':case 'root anchor':case 'Positive root trust anchor unchanged.':
        rootAnchor(location);dcEqual(ctx.row,dcConfiguredTrustStores(final.trustStores),dcConfiguredTrustStores(initial.trustStores),'preserved-root-trust-configuration',location);break;
      case 'authenticated parent DS and child DNSKEY':
        rootAnchor(location);
        dcCheck(ctx.row,frames.some(frame=>frame.state.dnssec.chainEstablished===true),'preserved-authenticated-chain-evidence',location,'Actual authenticated chain prefix',false);break;
      case 'valid new DNSKEY RRset':
        independentFields(['cacheEntries.dnskeys','publication.dnskeys','publication.dnskeySignatures'],location);break;
      case 'root/parent trust path':
        rootAnchor(location);
        dcCheck(ctx.row,[...ctx.artifacts.values()].some(artifact=>artifact.type==='dns-ds'||dcRecord(artifact,'rrset')?.type==='DS'),'preserved-parent-path-material',location,'Actual parent DS artifact',false);break;
      case 'cached old answer remains untrusted for this use':
        independentFields(['cacheEntries.answer'],location);dcEqual(ctx.row,final.acceptedForUse,false,'preserved-old-answer-not-accepted',location);break;
      case 'authenticated old parent DS cache':
        independentFields(['cacheEntries.ds'],location);break;
      case 'stale A trust configuration until explicit operator repair':
        independentFields(['trustStores','timers.keyStates'],location);break;
      case 'ds0 K0 unchanged':case 'ds0 K0':case 'parent ds0':
        dcEqual(ctx.row,final.publication.parentDsGeneration,'ds0','preserved-parent-ds0',location);
        dcEqual(ctx.row,final.publication.parentDsKeys,initial.publication.parentDsKeys,'preserved-parent-ds0-key-tuple',location);break;
      case 'ordinary polling remains available':
        dcEqual(ctx.row,final.publication.automationSuspended,false,'preserved-normal-automation-availability',location);break;
      case 'authenticated parent no-DS state':case 'no DS at parent':case 'no DS':
        dcEqual(ctx.row,final.publication.parentDsKeys,[],'preserved-no-parent-ds',location);
        dcEqual(ctx.row,final.publication.bootstrap?.parentDsAbsent,true,'preserved-bootstrap-parent-absence',location);break;
      case 'manual enrollment channel':case 'manual/out-of-band enrollment remains possible':case 'external manual recovery interface':
        dcEqual(ctx.row,final.publication.manualRecoveryChannelAvailable,true,'preserved-independent-recovery-channel',location);break;
      case 'both existing provider DS records':
        independentFields(['publication.parentDsGeneration','publication.parentDsKeys'],location);
        dcEqual(ctx.row,final.publication.parentDsKeys?.length,2,'preserved-both-provider-delegations',location);break;
      case 'g0 zone data':case 'g0 data':case 'previous complete g0 serving generation':
        dcEqual(ctx.row,final.publication.childGeneration,'g0','preserved-serving-generation',location);
        dcEqual(ctx.row,final.publication.activeSecondaryObjects,initial.publication.activeSecondaryObjects,'preserved-exact-serving-objects',location);break;
      case 'old SOA serial':case 'SOA serial':
        dcEqual(ctx.row,final.publication.transfer?.serial,ctx.oracle.setup.zoneOperations?.serialOld,'preserved-old-soa-serial',location);break;
      case 'DNSSEC secure status of authenticated SOA/ZONEMD, not whole-zone completeness':
        dcEqual(ctx.row,final.securityStatus,'secure','preserved-zonemd-rrset-security',location);
        dcEqual(ctx.row,final.publication.zonemd?.expectedDigestAuthenticated,true,'preserved-zonemd-expected-authentication',location);
        dcEqual(ctx.row,final.publication.zonemd?.matched,false,'preserved-separate-whole-zone-failure',location);break;
      case 'Failure-cache expiry permits new work but does not itself mark data secure.':
        for(const [sourceIndex,step] of ctx.steps.entries())if(step.protocolEffects?.some(effect=>effect.op==='advance')){
          const prior=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:sourceIndex,milestone:'before'}).state.dnssec,after=ctx.api.projectHeldObjects(ctx.compiled,{eventIndex:sourceIndex,milestone:'complete'}).state.dnssec;
          if(prior.securityStatus!=='secure')dcCheck(ctx.row,after.securityStatus!=='secure','preserved-expiry-not-validation',location,'Clock advance alone does not establish secure',after.securityStatus);
        }
        dcCheck(ctx.row,ctx.steps.some(step=>step.protocolEffects?.some(effect=>effect.op==='advance')),'preserved-expiry-clock-boundary',location,'Actual represented expiry transition',false);break;
      default:dcFailure(ctx.row,'unsupported-preserved-outcome',location,'Explicit implemented independent preservation semantics',declaration);
    }
    proofs.push({declaration,assertions:ctx.row.assertions-assertionsBefore,passed:ctx.row.failures.length===before});
  }
  return proofs;
}
function dcProjectionEqual(ctx,actual,cursor,check,location){
  const expected=ctx.api.projectHeldObjects(ctx.compiled,cursor);
  dcEqual(ctx.row,actual.cursor,expected.cursor,check+'-cursor',location);
  const a=dcFrameDigest(ctx,actual),e=dcFrameDigest(ctx,expected);
  dcEqual(ctx.row,a.state,e.state,check+'-state-sha256',location);
  dcEqual(ctx.row,a.holdings,e.holdings,check+'-normalized-custody-sha256',location);
}
function dcFrameDigest(ctx,frame){
  let digest=ctx.digests.get(frame);
  if(!digest){digest={state:dcHash(frame.state),holdings:dcHash(dcNormalize(frame))};ctx.digests.set(frame,digest);}
  return digest;
}
function dcReplay(ctx){
  const {row,api,compiled,steps}=ctx;
  const stepIndexes=new Map(),events=[],usedFields=new Set(),actionableFields=new Set(),intervalProgress=[0,0.5,1];
  for(const [index,step] of steps.entries()){
    dcCheck(row,!stepIndexes.has(step.id),'replay-unique-source-event',step.id,'Unique actual Source event ID',step.id);stepIndexes.set(step.id,index);
    const event=compiled.plan.events[step.id];
    if(!event||!Array.isArray(event.milestones))throw new Error('Missing actual held-event milestone declaration: '+step.id);
    const milestones=event.milestones.some(item=>item.id==='complete')?event.milestones:[...event.milestones,{id:'complete',at:1}];
    const milestoneAt=new Map([['before',0]]),messageById=new Map();
    for(const milestone of milestones){
      dcCheck(row,!milestoneAt.has(milestone.id),'replay-unique-milestone',step.id,'Unique actual milestone ID',milestone.id);milestoneAt.set(milestone.id,milestone.at);
    }
    for(const message of event.messages||[]){
      dcCheck(row,!messageById.has(message.messageId),'replay-unique-message-identity',step.id,'Unique actual message UID',message.messageId);
      if(messageById.has(message.messageId))messageById.set(message.messageId,null);else messageById.set(message.messageId,message);
    }
    events[index]={event,milestones,milestoneAt,messageById,probeProgress:[...new Set([...intervalProgress,...milestones.map(milestone=>milestone.at)])].sort((a,b)=>a-b)};
    for(const op of step.attributeOperations||[]){usedFields.add(op.attributeId);if(op.kind!=='inspect')actionableFields.add(op.attributeId);}
  }
  const sourceIndexOf=item=>item.sourceIndex??stepIndexes.get(item.sourceStepId??item.id)??-1;
  const at=cursor=>{
    if(cursor.progress!==undefined){
      if(!Number.isFinite(cursor.progress)||cursor.progress<0||cursor.progress>1)throw new Error('Replay cursor progress is not finite and normalized.');
      return cursor.progress;
    }
    if(cursor.eventIndex===-1&&cursor.milestone==='initial')return 0;
    const value=events[cursor.eventIndex]?.milestoneAt.get(cursor.milestone??'complete');
    if(value===undefined)throw new Error('Unknown replay cursor milestone: '+cursor.eventIndex+'/'+cursor.milestone);
    return value;
  };
  const canonicalEndpoint=cursor=>{
    if(!Number.isInteger(cursor.eventIndex)||cursor.eventIndex< -1||cursor.eventIndex>=steps.length)throw new Error('Replay interval event index is out of range.');
    if(cursor.eventIndex===-1){
      if(cursor.milestone!==undefined&&cursor.milestone!=='initial')throw new Error('Invalid initial replay interval milestone.');
      return {eventIndex:-1,milestone:'initial'};
    }
    const info=events[cursor.eventIndex];
    if(cursor.progress===undefined){at(cursor);return {eventIndex:cursor.eventIndex,milestone:cursor.milestone??'complete'};}
    const progress=at(cursor);
    let lo=0,hi=info.milestones.length;
    while(lo<hi){const mid=(lo+hi)>>>1;if(info.milestones[mid].at<=progress)lo=mid+1;else hi=mid;}
    return {eventIndex:cursor.eventIndex,milestone:lo?info.milestones[lo-1].id:'before'};
  };
  const mapRow=(queue,item,index,progress,kind)=>api.heldCursorForPlayback(compiled,{status:'paused',kind,step:item,stepElapsed:progress,duration:1,queue,queuePosition:index},item);
  const expectedCursor=(queue,item,index,progress)=>{
    if(item.heldCursorStart&&item.heldCursorEnd){
      // The consumer canonicalizes both declared endpoints before interpolating.
      // This includes finite progress endpoints that lie between milestones.
      const start=canonicalEndpoint(item.heldCursorStart),end=canonicalEndpoint(item.heldCursorEnd);
      if(progress<=0)return start;
      if(progress>=1)return end;
      if(start.eventIndex!==end.eventIndex||start.milestone===end.milestone)return start;
      const startAt=at(start),endAt=at(end);
      return {eventIndex:end.eventIndex,progress:startAt+(endAt-startAt)*progress};
    }
    const eventIndex=sourceIndexOf(item),event=events[eventIndex];
    let sourceProgress=progress;
    if(item.sourceStepId!==undefined&&event?.milestones.length===1&&(queue[index+1]?.sourceStepId===steps[eventIndex].id||queue[index+1]?.sourceIndex===eventIndex))sourceProgress=0;
    return {eventIndex,progress:sourceProgress};
  };
  ctx.expectedPlaybackCursor=expectedCursor;
  const exercise=(queue,kind,label=kind)=>{
    dcCheck(row,queue.length>0,'replay-nonempty',kind,'At least one mapped row',queue.length);
    const observations=[];
    for(const [index,item] of queue.entries()){
      const sourceIndex=sourceIndexOf(item);
      dcCheck(row,Number.isInteger(sourceIndex)&&sourceIndex>=-1&&sourceIndex<steps.length,'replay-source-index',kind+'.'+index,'Actual canonical source index',sourceIndex);
      if(sourceIndex>=0&&item.sourceStepId!==undefined)dcEqual(row,item.sourceStepId,steps[sourceIndex]?.id,'replay-source-id',kind+'.'+index);
      const sourceInfo=events[sourceIndex],sourceEvent=sourceInfo?.event,boundMessage=item.messageId&&sourceInfo?.messageById.get(item.messageId);
      if(item.messageId)dcCheck(row,!!boundMessage,'replay-exact-message-identity',kind+'.'+index,item.messageId,boundMessage?undefined:[...(sourceInfo?.messageById.keys()||[])]);
      if(kind==='attribute'&&item.from!==item.to&&sourceEvent?.messages?.length>1){
        dcCheck(row,!!boundMessage&&!!item.heldCursorStart&&!!item.heldCursorEnd,'batch-field-concrete-message-interval',kind+'.'+index,'Actual message UID and canonical interval',{messageId:item.messageId,start:item.heldCursorStart,end:item.heldCursorEnd});
        if(boundMessage&&item.heldCursorStart&&item.heldCursorEnd){
          dcEqual(row,[item.from,item.to],[boundMessage.from,boundMessage.to],'batch-field-message-route',kind+'.'+index);
          dcEqual(row,item.heldCursorStart.eventIndex,sourceIndex,'batch-field-start-source-event',kind+'.'+index);
          dcEqual(row,item.heldCursorEnd.eventIndex,sourceIndex,'batch-field-end-source-event',kind+'.'+index);
          const startAt=at(item.heldCursorStart),endAt=at(item.heldCursorEnd);
          dcCheck(row,startAt<=boundMessage.start,'batch-field-start-before-transfer',kind+'.'+index,boundMessage.start,startAt);
          dcEqual(row,endAt,boundMessage.end,'batch-field-end-at-receipt',kind+'.'+index);
        }
      }
      const progressValues=item.heldCursorStart?intervalProgress:sourceInfo?.probeProgress||intervalProgress;
      for(const progress of progressValues){
        const cursor=mapRow(queue,item,index,progress,kind),frame=api.projectHeldObjects(compiled,cursor);
        dcCheck(row,ctx.cursorKeys.has(cursor.eventIndex+'/'+cursor.milestone),'replay-canonical-cursor',kind+'.'+index,cursor,frame.cursor);
        dcProjectionEqual(ctx,frame,expectedCursor(queue,item,index,progress),'source-cursor-projection-equivalence',kind+'.'+index+'/'+progress);
        // Full/field rows without an explicit held interval map by canonical
        // source progress. Adjacent atomic field rows deliberately stay before
        // the event until the last row, per the actual mapping helper.
        if(item.heldCursorStart&&item.heldCursorEnd){if(progress===0)dcEqual(row,cursor,api.projectHeldObjects(compiled,item.heldCursorStart).cursor,'exact-replay-start',kind+'.'+index);if(progress===1)dcEqual(row,cursor,api.projectHeldObjects(compiled,item.heldCursorEnd).cursor,'exact-replay-end',kind+'.'+index);}
        if(cursor.milestone==='complete')dcEqual(row,dcFrameDigest(ctx,frame).state,ctx.canonicalStateHashes.get(cursor.eventIndex),'replay-canonical-complete-state-sha256',kind+'.'+index);
        observations.push({index,progress,cursor,...dcFrameDigest(ctx,frame)});row.replayPositions++;
        if(row.replayPositions%2048===0)dcNote(row,'stage-progress','all-replay-projections',{phase:'forward',kind,label,queuePosition:index,sourceEventIndex:sourceIndex});
      }
    }
    for(let position=observations.length-1;position>=0;position--){
      const observed=observations[position];
      const cursor=mapRow(queue,queue[observed.index],observed.index,observed.progress,kind),frame=api.projectHeldObjects(compiled,cursor);
      dcEqual(row,{cursor,...dcFrameDigest(ctx,frame)},{cursor:observed.cursor,state:observed.state,holdings:observed.holdings},'backward-canonical-replay',kind+'.'+observed.index);row.backwardPositions++;
      if(row.backwardPositions%2048===0)dcNote(row,'stage-progress','all-replay-projections',{phase:'backward',kind,label,queuePosition:observed.index});
    }
    return observations;
  };
  dcNote(row,'stage-progress','all-replay-projections',{phase:'full',plannedRows:steps.length});
  exercise(steps,'demo');row.fullRows=steps.length;
  const fieldIds=[...usedFields].sort();
  row.usedFields=fieldIds.length;row.fieldRows=0;row.contextOnlyFields=[];
  dcNote(row,'stage-progress','all-replay-projections',{phase:'all-used-fields',plannedFields:fieldIds.length});
  for(const fieldId of fieldIds){
    dcCheck(row,!!api.ATTRIBUTES[fieldId],'used-field-definition',fieldId,'Registered actual field definition',api.ATTRIBUTES[fieldId]);
    const usages=api.getAttributeUsage(steps,fieldId),queue=api.buildAttributeTrace(usages,ctx.model.exampleOverrides||{},ctx.model.protocolValues||{});
    if(!queue.length){
      const actionable=actionableFields.has(fieldId);
      dcCheck(row,!actionable,'used-field-replay-coverage',fieldId,'Trace for every non-inspect operation',queue.length);row.contextOnlyFields.push(fieldId);continue;
    }
    exercise(queue,'attribute',fieldId);row.fieldRows+=queue.length;row.replayedFields++;
    if(row.replayedFields%16===0)dcNote(row,'stage-progress','all-replay-projections',{phase:'all-used-fields',fieldId,plannedFields:fieldIds.length});
  }
  row.catalogDefinitionsNotCreated=[];
  const creations=dcCreationCursors(ctx);
  dcNote(row,'stage-progress','all-replay-projections',{phase:'all-exact-objects',plannedObjects:creations.size,catalogDefinitions:compiled.plan.artifacts.length});
  for(const artifact of compiled.plan.artifacts){
    if(!creations.has(artifact.artifactId)){
      row.catalogDefinitionsNotCreated.push(artifact.artifactId);
      for(const cursor of compiled.cursors){const frame=api.projectHeldObjects(compiled,cursor);dcCheck(row,!frame.artifacts.some(item=>item.artifactId===artifact.artifactId)&&!frame.holdings.some(item=>item.artifactId===artifact.artifactId),'catalog-definition-is-not-possession',artifact.artifactId,'No creation/holding in any actual prefix',cursor);}
      continue;
    }
    const queue=api.heldObjectTrace(compiled,artifact.artifactId);
    if(!queue.length)dcFailure(row,'created-object-exact-trace-coverage',artifact.artifactId,'Every actually created object has a real exact-object trace',queue.length);
    exercise(queue,'object',artifact.artifactId);row.exactObjects++;row.exactRows+=queue.length;
    if(row.exactObjects%16===0)dcNote(row,'stage-progress','all-replay-projections',{phase:'all-exact-objects',artifactId:artifact.artifactId,plannedObjects:creations.size});
  }
  dcNote(row,'stage-progress','all-replay-projections',{phase:'chapter-endpoints-and-reset'});
  for(const chapter of ctx.model.chapters||[]){
    dcCheck(row,Array.isArray(chapter.stepIds),'chapter-authored-steps',chapter.id,'Source step ID list',chapter.stepIds);
    if(!chapter.stepIds?.length){row.disabledChapters++;continue;}
    for(const id of [chapter.stepIds[0],chapter.stepIds.at(-1)]){
      const index=stepIndexes.get(id)??-1;
      if(!dcCheck(row,index>=0,'chapter-source-endpoint',chapter.id,id,index))continue;
      const cursor=api.heldCursorForPlayback(compiled,{},steps[index],{selected:true}),frame=api.projectHeldObjects(compiled,cursor);
      dcEqual(row,frame.state,api.reconstructProtocolState(ctx.model,index),'chapter-canonical-endpoint',chapter.id+'.'+id);row.chapterEndpoints++;
    }
  }
  const initial=api.heldCursorForPlayback(compiled,{},steps[0],{initial:true});
  dcEqual(row,api.projectHeldObjects(compiled,initial).state,api.reconstructProtocolState(ctx.model,-1),'reset-initial-projection','reset');row.resets++;
  return fieldIds;
}
function dcOutcome(ctx,final,packets){
  const {row,oracle}=ctx;
  for(const [key,value] of Object.entries(oracle.outcome)){
    if(['flags','preservedState'].includes(key))continue;
    const actual=['rcode','ede'].includes(key)?final.response?.[key]:final[key];
    dcCompare(ctx,actual,value,'outcome.'+key);
  }
  const flags=oracle.outcome.flags;
  if(!dcCheck(row,!!flags&&typeof flags==='object','outcome-required-flags','outcome.flags','Independent flags object',flags))return;
  if(dcOwn(flags,'hops'))dcCompare(ctx,final.response?.hops,flags.hops,'outcome.response.hops');
  const authorities=new Set(['dnsRoot','dnsParent','dnsChild','dnsPrimary','dnsSecondary','dnsProviderB']),roles={};
  for(const {packet,message} of packets){
    let role;
    if(message.from==='dnsStub'&&message.to==='dnsResolver'&&packet.flags?.QR===0)role='stubQuery';
    else if(message.from==='dnsResolver'&&authorities.has(message.to)&&packet.flags?.QR===0)role='authoritativeQuery';
    else if(authorities.has(message.from)&&message.to==='dnsResolver'&&packet.flags?.QR===1)role='authoritativeResponse';
    else if(message.from==='dnsResolver'&&message.to==='dnsStub'&&packet.flags?.QR===1)role='resolverResponse';
    if(role&&flags[role]){dcCompare(ctx,packet.flags,{...flags[role],...(packet.referral?{AA:0}:{})},'outcome.flags.'+role);roles[role]=(roles[role]||0)+1;}
  }
  for(const key of Object.keys(flags)){
    if(['hops','scope'].includes(key))continue;
    if(!['stubQuery','authoritativeQuery','authoritativeResponse','resolverResponse'].includes(key)){dcFailure(row,'unsupported-independent-outcome-flag','outcome.flags.'+key,'Explicit implemented flag semantics',flags[key]);continue;}
    dcCheck(row,(roles[key]||0)>0,'outcome-wire-role-exercised',key,'At least one actual packet checked',roles[key]||0);
  }
  row.wireRoles=roles;
  if(flags.scope){
    row.managementScope=flags.scope;
    if(Array.isArray(flags.hops)&&flags.hops.length===0){
      dcCheck(row,!packets.some(({message})=>message.from==='dnsStub'||message.to==='dnsStub'||message.from==='dnsApp'||message.to==='dnsApp'),'management-no-invented-leaf-query','outcome.flags.scope','No stub/application DNS transfer',packets.map(({message})=>({from:message.from,to:message.to})));
      dcEqual(row,final.cached,false,'management-no-invented-cache','outcome.cached');dcEqual(row,final.returnedToStub,false,'management-no-invented-stub-return','outcome.returnedToStub');
    }
  }
}
function dcAppReplay(ctx,fieldId,inspection){
  const {app}=ctx.api;if(!app)return;
  const {row}=ctx;
  const observe=(cursor,kind)=>{dcProjectionEqual(ctx,app.heldView.snapshot(),cursor,'emitted-app-'+kind,kind);dcEqual(row,app.protocolSnapshot().state,ctx.api.projectHeldObjects(ctx.compiled,cursor).state,'emitted-app-protocol-snapshot',kind);row.appPositions++;};
  const seekPaths=kind=>{
    for(const fraction of [0,0.137,1,0.863,0]){
      app.seekPlayback(fraction);
      const state=app.player.snapshot(),queue=app.player.queue,index=state.queuePosition,item=state.step;
      if(!dcCheck(row,!!item&&queue[index]===item,'emitted-consumer-seek-queue',kind,'Actual App-generated playback row',item?.id))continue;
      const progress=Math.max(0,Math.min(1,state.stepElapsed/state.duration));
      const expected=ctx.expectedPlaybackCursor(queue,item,index,progress);
      observe(expected,'consumer-seek:'+kind);row.appSeekPositions=(row.appSeekPositions||0)+1;
    }
  };
  const traceControls=kind=>{
    const positions=[...new Set([0,Math.floor((app.traceQueue.length-1)/2),app.traceQueue.length-1])];
    for(const indexes of [positions,positions.slice().reverse()])for(const index of indexes){const item=app.traceQueue[index],cursor=ctx.api.heldCursorForPlayback(ctx.compiled,{},item,{selected:true});app.selectStep(index,false);observe(cursor,kind);}
    seekPaths(kind);
  };
  // Every semantic replay row/prefix remains exhaustive in dcReplay. Here the
  // actual UI controls cover every independent checkpoint and chapter endpoint,
  // plus field/exact selection, representative rows and forward/backward seek.
  const fullPositions=new Set([0,ctx.steps.length-1,...row.checkpoints.map(point=>point.eventIndex)]);
  const chapters=new Map();
  for(const chapter of ctx.model.chapters||[])if(chapter.stepIds?.length)for(const id of [chapter.stepIds[0],chapter.stepIds.at(-1)]){
    const index=ctx.steps.findIndex(step=>step.id===id);fullPositions.add(index);
    if(!chapters.has(index))chapters.set(index,[]);
    chapters.get(index).push({chapter,id});
  }
  app.clearAttribute();
  const ordered=[...fullPositions].sort((a,b)=>a-b);
  for(const indexes of [ordered,ordered.slice().reverse()])for(const index of indexes){
    app.selectStep(index,false);observe({eventIndex:index,milestone:'complete'},'full');
    for(const {chapter,id} of chapters.get(index)||[])dcEqual(row,app.graphChapter?.id,chapter.id,'emitted-app-chapter-projection',id);
  }
  seekPaths('full');
  dcCheck(row,!!fieldId,'emitted-app-field-representative','inspection','Replayable exact held-object field',fieldId);
  if(fieldId){
    app.selectAttribute(fieldId,false);
    dcEqual(row,app.attributeSelection,fieldId,'emitted-app-field-selection',fieldId);
    dcCheck(row,app.traceQueue.length>0,'emitted-app-field-queue',fieldId,'Actual mapped trace',app.traceQueue.length);
    if(app.traceQueue.length)traceControls('field:'+fieldId);
  }
  app.clearAttribute();app.seekPlayback(1);
  if(inspection){
    const holding=app.heldView.snapshot().holdings.find(item=>item.holdingId===inspection.holdingId);
    dcCheck(row,!!holding,'emitted-app-exact-selected-holding','inspection',inspection,holding);
    if(holding)app.heldView.select(holding);
    app.heldView.trace(inspection.artifactId);app.player.stop(false);
    dcEqual(row,app.objectTraceSelection,inspection.artifactId,'emitted-app-exact-selection','inspection');
    dcCheck(row,app.traceQueue.length>0,'emitted-app-exact-queue','inspection','Actual mapped trace',app.traceQueue.length);
    if(app.traceQueue.length)traceControls('exact');
  }
  app.clearAttribute();app.reset();observe({eventIndex:-1,milestone:'initial'},'reset');row.appResets++;
}
function dcCaseRow(identity){
  return {id:identity.id,caseId:identity.caseId,variant:null,passed:false,assertions:0,failures:[],events:0,checkpoints:[],prefixes:0,messages:0,dnsPackets:0,replayPositions:0,backwardPositions:0,fullRows:0,usedFields:0,replayedFields:0,fieldRows:0,exactObjects:0,exactRows:0,chapterEndpoints:0,disabledChapters:0,resets:0,appPositions:0,appResets:0};
}
function dcCase(api,model,oracle,manifestCase,args,row){
  row.variant=model.variantId;
  dcEqual(row,model.id,manifestCase.id,'actual-model-identity','model.id');dcEqual(row,model.caseId,manifestCase.caseId,'actual-case-identity','model.caseId');
  const expectedVariant=manifestCase.defaultCase?'default':manifestCase.caseId;dcEqual(row,model.variantId,expectedVariant,'actual-variant-identity','model.variantId');
  const steps=dcTimed(row,'actual-source-events',()=>model.steps());row.events=steps.length;
  dcCheck(row,steps.length>0,'actual-source-events','steps','Nonempty case',steps.length);
  dcStage(row,'protocol-scenario',()=>dcEqual(row,api.validateProtocolScenario(model).errors,[],'protocol-scenario-invariants','model'));
  const compiled=dcStage(row,'held-plan',()=>api.app?api.app.heldView.compiled():api.buildHeldObjects({model,steps,actors:model.actors(),config:{},contextId:'dnssec-contract:'+model.id+':'+manifestCase.caseId}));
  if(!compiled)return row;
  const numericCache=new Map();
  const ctx={row,model,oracle,steps,compiled,api,artifacts:new Map(compiled.plan.artifacts.map(a=>[a.artifactId,a])),refs:new Map(),reverseRefs:new Map(),wireIds:new Map(),reverseWireIds:new Map(),numeric:name=>{const file=path.resolve(args.root,name);if(!numericCache.has(file))numericCache.set(file,dcJson(file));return numericCache.get(file);}};
  ctx.digests=new WeakMap();ctx.canonicalStateHashes=new Map();ctx.cursorKeys=new Set(compiled.cursors.map(cursor=>cursor.eventIndex+'/'+cursor.milestone));
  row.artifactDefinitions=compiled.plan.artifacts.length;row.createdArtifactDefinitions=dcCreationCursors(ctx).size;row.catalogOnlyDefinitions=row.artifactDefinitions-row.createdArtifactDefinitions;
  const before=dcTimed(row,'case-inputs-before-sha256',()=>dcHash({initialState:model.initialState,steps,inventory:model.dnssecInventory,plan:compiled.plan}));
  const boundaries=new Set();
  for(const point of oracle.checkpoints){
    dcStage(row,'checkpoint:'+point.name,()=>{
      dcCheck(row,!boundaries.has(point.name),'independent-checkpoint-unique',point.name,'Unique named checkpoint',point.name);boundaries.add(point.name);
      const boundary=model.dnssecCheckpointAliases?.[point.name]||point.name,indexes=steps.flatMap((step,index)=>step.dnssecBoundary===boundary?[index]:[]);
      if(!dcEqual(row,indexes.length,1,'independent-checkpoint-boundary',point.name))return;
      const index=indexes[0];ctx.step=steps[index];
      ctx.expectedAnchorBinding=point.expected.anchorBinding||oracle.checkpoints.find(p=>p.expected.anchorBinding)?.expected.anchorBinding;
      const state=api.reconstructProtocolState(model,index).dnssec;
      ctx.currentState=state;
      dcCheck(row,steps[index].from===point.actorId||steps[index].to===point.actorId||steps[index].attributeOperations?.some(op=>op.actorId===point.actorId),'independent-checkpoint-actor',point.name,point.actorId,{from:steps[index].from,to:steps[index].to});
      const count=row.failures.length;dcCompare(ctx,state,point.expected,'checkpoint.'+point.name);
      row.checkpoints.push({name:point.name,actorId:point.actorId,boundary,eventIndex:index,sourceEventId:steps[index].id,stateSha256:dcHash(state),passed:row.failures.length===count});
    });
  }
  dcEqual(row,row.checkpoints.length,oracle.checkpoints.length,'all-independent-checkpoints-exercised','checkpoints');
  const frames=[],prefixes=[];
  dcStage(row,'canonical-prefixes',()=>{
    for(const cursor of compiled.cursors)dcStage(row,'prefix:'+cursor.eventIndex+'/'+cursor.milestone,()=>{
      const frame=api.projectHeldObjects(compiled,cursor);frames.push(frame);row.prefixes++;
      const digest=dcFrameDigest(ctx,frame);prefixes.push({eventIndex:cursor.eventIndex,milestone:cursor.milestone,stateSha256:digest.state,holdingsSha256:digest.holdings,normalizedHoldingsSha256:digest.holdings});
      const dns=frame.state.dnssec,location=cursor.eventIndex+'/'+cursor.milestone;
      dcCheck(row,['not-checked','secure','insecure','bogus','indeterminate'].includes(dns.securityStatus),'explicit-security-status',location,'Declared DNSSEC status enum',dns.securityStatus);
      dcEqual(row,dns.evidenceMode,'symbolic-reference-bound','honest-runtime-evidence-mode',location);
      for(const field of ['received','signatureChecked','chainEstablished','denialChecked','acceptedForUse','cached','returnedToStub'])dcEqual(row,typeof dns[field],'boolean','separate-semantic-boundary-flag',location+'.'+field);
      for(const [owner,validator] of Object.entries(dns.validators||{}))if(dcOwn(validator,'runtimeCryptographicOperationPerformed'))dcEqual(row,validator.runtimeCryptographicOperationPerformed,false,'no-invented-runtime-crypto',location+'.validators.'+owner);
      if(cursor.eventIndex<0||cursor.milestone==='complete'){
        const canonicalHash=dcHash(api.reconstructProtocolState(model,cursor.eventIndex));ctx.canonicalStateHashes.set(cursor.eventIndex,canonicalHash);
        dcEqual(row,digest.state,canonicalHash,'canonical-protocol-held-prefix-sha256',cursor.eventIndex+'/'+cursor.milestone);
      }
      if(row.prefixes%128===0||row.prefixes===compiled.cursors.length)dcNote(row,'stage-progress','canonical-prefixes',{expectedPrefixes:compiled.cursors.length,eventIndex:cursor.eventIndex,milestone:cursor.milestone});
    });
  });
  const packets=dcStage(row,'concrete-wire',()=>dcWire(ctx))||[];
  dcStage(row,'immutable-generations',()=>dcPreservation(ctx,frames));
  const fieldIds=dcStage(row,'all-replay-projections',()=>dcReplay(ctx))||[];
  const final=api.reconstructProtocolState(model,steps.length-1).dnssec;ctx.step=steps.at(-1);ctx.currentState=final;
  dcStage(row,'complete-independent-outcome',()=>dcOutcome(ctx,final,packets));
  dcStage(row,'hop-to-message-correlation',()=>dcHopPackets(ctx,final,packets));
  const last=api.projectHeldObjects(compiled,{eventIndex:steps.length-1,milestone:'complete'});
  const cache=ctx.artifacts.get(final.resultCacheArtifact);
  const answer=cache?.derivedFrom?.find(ref=>ctx.artifacts.get(ref)?.type==='dns-rrset');
  const lastUse=new Map();for(const [index,step] of steps.entries())for(const op of step.attributeOperations||[])if(op.instanceId)lastUse.set(op.instanceId,index);
  const ranked=last.holdings.filter(h=>ctx.artifacts.get(h.artifactId)?.type!=='private-key-handle').map(h=>({holding:h,artifact:ctx.artifacts.get(h.artifactId)})).sort((a,b)=>{
    const score=item=>item.holding.artifactId===answer?-Infinity:-(lastUse.get(item.holding.artifactId)??-1);
    return score(a)-score(b)||a.holding.holdingId.localeCompare(b.holding.holdingId);
  });
  const selected=ranked.find(({artifact})=>artifact?.representations.some(rep=>rep.fields.some(field=>fieldIds.includes(field.attributeId)&&api.getAttributeUsage(steps,field.attributeId).length)));
  const inspection=selected?Object.fromEntries(['artifactId','actorId','representationId','holdingId'].map(key=>[key,selected.holding[key]])):null;
  const fieldId=selected?.artifact.representations.find(rep=>rep.representationId===selected.holding.representationId)?.fields.find(field=>fieldIds.includes(field.attributeId)&&api.getAttributeUsage(steps,field.attributeId).length)?.attributeId;
  dcCheck(row,!!inspection&&!!fieldId,'actual-representative-inspection','inspection','Real final held object and replayable exact field',{inspection,fieldId});
  dcStage(row,'emitted-app-controls',()=>dcAppReplay(ctx,fieldId,inspection));
  dcStage(row,'case-inputs-after-sha256',()=>dcEqual(row,dcHash({initialState:model.initialState,steps,inventory:model.dnssecInventory,plan:compiled.plan}),before,'immutable-case-inputs-before-after','model'));
  row.final={securityStatus:final.securityStatus,applicationResult:final.applicationResult};row.passed=row.failures.length===0;
  return {row,reference:{id:model.id,caseId:manifestCase.caseId,variant:model.variantId,steps:steps.map(step=>({id:step.id,boundary:step.dnssecBoundary??null})),prefixes,final:row.final,inspection,fieldId,...(answer?{answerArtifact:answer}:{})}};
}

let dcOptions;
try{dcOptions=dcArgs();}catch(error){console.error(String(error.message||error));process.exit(2);}
// mkdir is exclusive. Final evidence files use wx once; the diagnostic journal
// is exclusively created and then appended synchronously, never resumed.
fs.mkdirSync(dcOptions.out,{recursive:false});
fs.mkdirSync(path.join(dcOptions.out,'cases'),{recursive:false});
dcJournal={fd:fs.openSync(path.join(dcOptions.out,'journal.jsonl'),'wx'),started:performance.now()};
const dcReport={schemaVersion:1,kind:'DNSSEC-independent-contract-check',mode:dcOptions.mode,passed:false,status:'failed',startedAt:new Date().toISOString(),root:dcOptions.root,worksheet:path.relative(dcOptions.root,dcOptions.worksheet),runnerSha256:dcSha(fs.readFileSync(dcRunner)),runtime:{executable:process.execPath,version:process.version,bun:process.versions.bun??null},argv:[process.execPath,...process.argv.slice(1)],regenerationCommand:[process.execPath,...process.argv.slice(1)],nativeBrowser:false,independentOutcomes:true,limitations:['No native DNSSEC crypto or live DNS/service interoperability','No native browser, cross-engine or human assistive-technology acceptance','No performance, regression, release or independent-review approval'],assertions:0,failures:[],cases:[]};
dcReport.evidenceJournal={path:'journal.jsonl',diagnosticOnly:true,partialRunIsNeverPassing:true};
dcReport.caseEvidence={directory:'cases',scope:'Exclusive current-run case evidence only; fragments never imply complete-run acceptance and are never loaded for resume',files:[]};
const dcWrite=(name,value)=>{
  const text=JSON.stringify(value,null,2)+'\n',file=path.join(dcOptions.out,name),fd=fs.openSync(file,'wx');
  try{fs.writeFileSync(fd,text);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  return {path:name,sha256:dcSha(text),bytes:Buffer.byteLength(text)};
};
function dcPersistCase(row,reference,caseReturned,ordinal){
  const prefix='cases/'+String(ordinal).padStart(3,'0');
  const identities={runnerSha256:dcReport.runnerSha256,worksheetSha256:dcReport.worksheetSha256,manifestSha256:dcReport.manifestSha256,standaloneSha256:dcReport.htmlSha256,inputsBefore:{...dcReport.beforeCaptureArtifact,path:'../inputs-before.json'}};
  const shared={schemaVersion:1,mode:dcOptions.mode,passed:false,complete:false,requiredCases:159,runAcceptance:false,id:row.id,caseId:row.caseId,variant:row.variant,casePassed:row.passed,caseReturned,identities};
  const projection=dcWrite(prefix+'-reference.json',{...shared,kind:'DNSSEC-case-canonical-prefix-reference-fragment',scope:'Source projection equivalence reference only, never an independent outcome oracle or complete-run acceptance',cases:reference?[reference]:[]});
  const status=dcWrite(prefix+'-status.json',{...shared,kind:'DNSSEC-completed-case-contract-evidence',scope:'Completed current-run case checks only; before/after whole-run capture and all159 cases are still required',runtime:dcReport.runtime,argv:dcReport.argv,referenceArtifact:projection,row});
  const files={id:row.id,caseId:row.caseId,status,reference:projection,referencePresent:!!reference};
  dcReport.caseEvidence.files.push(files);return files;
}
dcWrite('run-start.json',{...dcReport});
dcNote(dcReport,'run-start','runner',{passed:false,complete:false,diagnosticOnly:true,mode:dcOptions.mode,expectedCases:159,runnerSha256:dcReport.runnerSha256});
let dcApi,dcBefore,dcFiles,dcReferenceRows=[],dcExpectedIdentities=[];
try{
  const manifestPath=path.join(dcOptions.root,'docs/dnssec-expansion/scenario-manifest.json'),manifest=dcJson(manifestPath),worksheet=dcJson(dcOptions.worksheet);
  dcExpectedIdentities=manifest.rows.flatMap(lesson=>lesson.caseIds.map(caseId=>({id:lesson.runtimeId,caseId})));
  dcFiles=dcTimed(dcReport,'independent-input-discovery',()=>dcInputFiles(dcOptions.root,dcOptions.worksheet,manifestPath));
  dcBefore=dcTimed(dcReport,'immutable-inputs-before',()=>dcCapture(dcOptions,dcFiles));dcReport.inputIdentity=dcBefore;
  dcReport.worksheetSha256=dcSha(fs.readFileSync(dcOptions.worksheet));dcReport.manifestSha256=dcSha(fs.readFileSync(manifestPath));dcReport.htmlSha256=dcBefore.review.standaloneSha256;
  dcReport.typedRoots=worksheet.typedRoots??null;
  dcReport.beforeCaptureArtifact=dcWrite('inputs-before.json',dcBefore);
  dcEqual(dcReport,manifest.rows.length,22,'exact-required-lesson-count','manifest.rows');
  dcEqual(dcReport,manifest.totals.namedCases,159,'frozen-case-count','manifest.totals');
  dcEqual(dcReport,dcBefore.independentFiles['docs/dnssec-expansion/contract-freeze.json'],'b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19','immutable-D0-identity','contract-freeze.json');
  const frozen=dcJson(path.join(dcOptions.root,'docs/dnssec-expansion/contract-freeze.json'));
  for(const input of frozen.inputs)dcEqual(dcReport,dcBefore.independentFiles[input.path],input.sha256,'immutable-frozen-D0-input',input.path);
  dcReport.frozenInputsChecked=frozen.inputs.length;
  dcEqual(dcReport,manifest.totals.requiredLessons,22,'frozen-required-lessons','manifest.totals');
  dcEqual(dcReport,worksheet.totals.lessons,22,'exact-independent-worksheet-lessons','worksheet.totals');
  dcEqual(dcReport,worksheet.totals.namedCases,159,'exact-independent-worksheet-cases','worksheet.totals');
  dcEqual(dcReport,worksheet.independentOfProduction,true,'independent-oracle-declaration','worksheet');
  const identities=manifest.rows.flatMap((lesson,index)=>{
    dcEqual(dcReport,lesson.planId,'DNS'+String(index+1).padStart(2,'0'),'exact-manifest-plan-id','manifest.'+index);
    dcEqual(dcReport,lesson.runtimeId,'lab-dnssec'+String(index+1).padStart(2,'0'),'exact-manifest-runtime-id','manifest.'+index);
    dcEqual(dcReport,lesson.defaultCaseId,lesson.caseIds[0],'default-is-first-named-alias',lesson.runtimeId);
    dcEqual(dcReport,lesson.caseCount,lesson.caseIds.length,'exact-lesson-case-count',lesson.runtimeId);
    return lesson.caseIds.map((caseId,n)=>({id:lesson.runtimeId,caseId,defaultCase:n===0}));
  });
  dcEqual(dcReport,identities.length,159,'exact-manifest-identities','manifest');
  dcEqual(dcReport,new Set(identities.map(item=>item.id+'/'+item.caseId)).size,159,'unique-manifest-identities','manifest');
  dcEqual(dcReport,worksheet.lessons.length,22,'exact-worksheet-lessons','worksheet.lessons');
  const oracleIds=worksheet.lessons.flatMap(lesson=>lesson.cases.map(c=>lesson.runtimeId+'/'+c.id));
  dcEqual(dcReport,oracleIds.slice().sort(),identities.map(item=>item.id+'/'+item.caseId).sort(),'exact-independent-worksheet-case-set','worksheet.lessons');
  const runtimeStarted=performance.now();let runtimeReady=false;
  dcActiveStages.set(dcReport,'runtime-bootstrap');dcNote(dcReport,'stage-start','runtime-bootstrap');
  try{dcApi=await dcRuntime(dcOptions,dcReport);runtimeReady=true;}
  finally{dcNote(dcReport,'stage-end','runtime-bootstrap',{stageElapsedMs:Number((performance.now()-runtimeStarted).toFixed(3)),threw:!runtimeReady});dcActiveStages.delete(dcReport);}
  if(!dcApi.app){
    dcEqual(dcReport,Object.keys(dcApi.DNSSECLAB_CASE_BUILDERS).sort(),manifest.rows.map(row=>row.runtimeId).sort(),'actual-source-lesson-set','DNSSECLAB_CASE_BUILDERS');
    for(const lesson of manifest.rows)dcEqual(dcReport,Object.keys(dcApi.DNSSECLAB_CASE_BUILDERS[lesson.runtimeId]||{}).sort(),lesson.caseIds.slice().sort(),'actual-source-case-set',lesson.runtimeId);
  }
  for(const identity of identities){
    const row=dcCaseRow(identity),caseStarted=performance.now();dcReport.cases.push(row);
    let caseReturned=false,referenceCreated=false,caseReference=null;
    dcNote(row,'case-start','case',{requestedVariant:identity.defaultCase?'default':identity.caseId,expectedCases:159});
    try{
      const oracle=worksheet.lessons.find(lesson=>lesson.runtimeId===identity.id)?.cases.find(c=>c.id===identity.caseId);
      if(!oracle)throw new Error('Independent named case absent: '+identity.id+'/'+identity.caseId);
      if(!Array.isArray(oracle.checkpoints)||!oracle.checkpoints.length||!oracle.outcome)throw new Error('Independent checkpoint/outcome contract missing');
      const model=dcTimed(row,'actual-case-model',()=>{
        let model;
        if(dcApi.app){
          const app=dcApi.app;
          app.selectLabScenario(identity.id,{navigate:false});
          const variant=identity.defaultCase?'default':identity.caseId;
          app.selectLessonVariant(variant);
          if(app.labScenarioId!==identity.id||app.lessonVariant!==variant)throw new Error('Actual App case control did not select '+identity.id+'/'+variant);
          const control=app.querySelector('#lesson-case');
          if(!control||control.value!==variant)throw new Error('Actual DOM #lesson-case disagrees with requested case '+identity.caseId);
          const choices=app.baseLabModel?.variantChoices?.map(choice=>choice.caseId).sort();
          if(!isDeepStrictEqual(choices,manifest.rows.find(lesson=>lesson.runtimeId===identity.id).caseIds.slice().sort()))throw new Error('Actual emitted case picker does not expose the complete exact named case set');
          model=app.protocolSnapshot().model;
        }else{
          const factory=dcApi.DNSSECLAB_CASE_BUILDERS[identity.id]?.[identity.caseId];
          if(typeof factory!=='function')throw new Error('Missing actual factory '+identity.id+'/'+identity.caseId);
          model=factory();
        }
        row.variant=model.variantId;return model;
      });
      const result=dcCase(dcApi,model,oracle,identity,dcOptions,row);caseReturned=true;
      if(result?.reference){caseReference=result.reference;dcReferenceRows.push(result.reference);referenceCreated=true;}
    }catch(error){
      dcFailure(row,'case-execution',identity.id+'/'+identity.caseId,'Complete named case executes',null,String(error.stack||error));row.passed=false;
    }finally{
      const evidence=dcTimed(row,'persist-case-evidence',()=>dcPersistCase(row,caseReference,caseReturned,dcReport.cases.length));
      dcNote(row,'case-end','case',{caseElapsedMs:Number((performance.now()-caseStarted).toFixed(3)),caseReturned,referenceCreated,casePassed:row.passed,final:row.final??null,finishedCases:dcReport.cases.length,referenceCases:dcReferenceRows.length,evidence});
    }
  }
  dcEqual(dcReport,dcReport.cases.length,159,'all-required-cases-observed','cases');
  dcEqual(dcReport,dcReferenceRows.length,159,'all-required-reference-cases','reference.cases');
  dcEqual(dcReport,dcReport.caseEvidence.files.length,159,'all-required-case-evidence-persisted','caseEvidence.files');
  dcEqual(dcReport,dcReport.caseEvidence.files.filter(item=>item.referencePresent).length,159,'all-required-case-prefix-fragments-persisted','caseEvidence.files');
  dcEqual(dcReport,dcReferenceRows.filter(row=>row.variant==='default').length,22,'exact-default-aliases','reference.cases');
}catch(error){dcFailure(dcReport,'runner-execution','runner','All prerequisites available',null,String(error.stack||error));}
finally{
  if(dcApi?.app){try{dcApi.app.disconnectedCallback();dcApi.harness.document.body.removeChild(dcApi.app);dcApi.harness.clock.frames.clear();dcApi.harness.clock.timers.clear();}catch(error){dcFailure(dcReport,'harness-cleanup','runner','Clean disconnection',null,String(error.stack||error));}}
  for(const identity of dcExpectedIdentities)if(!dcReport.cases.some(row=>row.id===identity.id&&row.caseId===identity.caseId)){
    const row={...identity,passed:false,notExecuted:true,assertions:0,failures:[]};
    dcFailure(row,'case-not-executed',identity.id+'/'+identity.caseId,'Actual named factory/App case and all required checks execute','Unavailable after runner prerequisite failure');dcReport.cases.push(row);
  }
  if(dcBefore){
    try{dcTimed(dcReport,'immutable-inputs-after',()=>{const after=dcCapture(dcOptions,dcFiles);dcWrite('inputs-after.json',after);dcReport.sourceUnchanged=dcEqual(dcReport,after,dcBefore,'immutable-inputs-before-after','inputs');});}
    catch(error){dcReport.sourceUnchanged=false;dcFailure(dcReport,'immutable-input-capture','inputs','Capture succeeds',null,String(error.stack||error));}
  }
  dcReport.counts={requiredLessons:22,requiredCases:159,observedCases:dcReport.cases.length,passedCases:dcReport.cases.filter(row=>row.passed).length,failedCases:dcReport.cases.filter(row=>!row.passed).length,referenceCases:dcReferenceRows.length};
  dcReport.counts.attemptedCases=dcReport.cases.filter(row=>!row.notExecuted).length;
  dcReport.counts.persistedCaseRows=dcReport.caseEvidence.files.length;
  dcReport.counts.persistedCaseReferences=dcReport.caseEvidence.files.filter(item=>item.referencePresent).length;
  dcReport.counts.hopSummaryReferences=dcReport.cases.reduce((sum,row)=>sum+(row.hopSummaryReferences||0),0);
  dcReport.counts.actualCaseModels=dcReport.cases.filter(row=>row.events>0).length;
  dcReport.counts.independentCheckpoints=dcReport.cases.reduce((sum,row)=>sum+(row.checkpoints?.length||0),0);
  for(const key of ['assertions','events','prefixes','messages','dnsPackets','localTransportAttempts','artifactDefinitions','createdArtifactDefinitions','catalogOnlyDefinitions','replayPositions','backwardPositions','fullRows','usedFields','replayedFields','fieldRows','exactObjects','exactRows','chapterEndpoints','disabledChapters','resets','appPositions','appSeekPositions','appResets'])dcReport.counts[key]=dcReport.cases.reduce((sum,row)=>sum+(row[key]||0),0);
  dcReport.counts.assertions+=dcReport.assertions;dcReport.counts.failures=dcReport.failures.length+dcReport.cases.reduce((sum,row)=>sum+row.failures.length,0);
  dcReport.passed=dcReport.counts.observedCases===159&&dcReport.counts.passedCases===159&&dcReport.counts.referenceCases===159&&dcReport.counts.persistedCaseRows===159&&dcReport.counts.persistedCaseReferences===159&&dcReport.sourceUnchanged===true&&dcReport.failures.length===0;
  dcReport.status=dcReport.passed?'passed':'failed';dcReport.exitCode=dcReport.passed?0:1;dcReport.finishedAt=new Date().toISOString();
  dcWrite('canonical-prefix-reference.json',{schemaVersion:1,kind:'DNSSEC-canonical-source-prefix-reference',mode:dcOptions.mode,scope:'Source projection equivalence references only, never an independent DNSSEC outcome oracle',passed:dcReport.passed,complete:dcReferenceRows.length===159,identities:{sourceFiles:dcBefore?.review.sourceFiles||{},standaloneSha256:dcReport.htmlSha256??null,manifestSha256:dcReport.manifestSha256??null,worksheetSha256:dcReport.worksheetSha256??null,runnerSha256:dcReport.runnerSha256},cases:dcReferenceRows});
  dcWrite('status.json',dcReport);
  dcNote(dcReport,'run-end','runner',{passed:dcReport.passed,complete:dcReport.counts.observedCases===159&&dcReport.counts.referenceCases===159,counts:dcReport.counts,exitCode:dcReport.exitCode});
  fs.closeSync(dcJournal.fd);dcJournal=null;
  console.log(JSON.stringify({passed:dcReport.passed,mode:dcOptions.mode,out:dcOptions.out,counts:dcReport.counts}));process.exitCode=dcReport.exitCode;
}
