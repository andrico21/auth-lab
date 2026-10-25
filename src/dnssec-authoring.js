import {labP,labStep,labScenario} from './lab-common.js';
import {dnssecLessonMeta} from './dnssec-lessons.js';
import {DNSSEC_ATTRIBUTES,DNSSEC_SOURCES,dnssecFields} from './dnssec-fields.js';
import {DNSSEC_BASE_CLOCK,dnssecProfile} from './dnssec-fixtures.js';

function dnssecAuthorFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(dnssecAuthorFreeze);Object.freeze(value);}return value;}
function dnssecAuthorRead(value,path){return path?path.split('.').reduce((current,key)=>current!=null&&Object.hasOwn(current,key)?current[key]:undefined,value):value;}
function dnssecAuthorText(value){return typeof value==='string'?value:JSON.stringify(value);}
const DNSSEC_AUTHOR_OVERVIEW_FIELDS=['dnssec_question_qname','dnssec_question_qtype','dnssec_header_rcode','dnssec_rrset_owner','dnssec_rrset_type','dnssec_rrset_ttl','dnssec_rrsig_keyTag','dnssec_dnskey_keyTag','dnssec_ds_keyTag','dnssec_secret_keyId'];
function dnssecAuthorPresentation(ops,description,message=false){
  const seen=new Set(),byField=new Map(),detailedPayload=[];
  for(const op of ops){
    const identity=op.attributeId+'\0'+op.instanceId+'\0'+op.fieldPath;if(seen.has(identity))continue;seen.add(identity);
    const item=labP(DNSSEC_ATTRIBUTES[op.attributeId].name,dnssecAuthorText(op.value),description,op.attributeId);detailedPayload.push(item);
    if(!byField.has(op.attributeId))byField.set(op.attributeId,item);
  }
  const fields=[],payload=[];
  for(const id of DNSSEC_AUTHOR_OVERVIEW_FIELDS)if(byField.has(id)){fields.push(id);payload.push(byField.get(id));if(fields.length===3)break;}
  if(message&&!payload.length&&detailedPayload.length){fields.push(ops[0].attributeId);payload.push(detailedPayload[0]);}
  return {fields,payload,detailedPayload};
}
export const DNSSEC_ACTOR_SPECS=dnssecAuthorFreeze({
  dnsApp:{name:'Application',kind:'application',role:'Application / local stub',position:{x:145,y:120},notes:['Uses the result only after the stub returns it. The selected application and stub share a process.']},
  dnsStub:{name:'Stub resolver',kind:'client',role:'DNS stub responsibility',parentId:'dnsApp',position:{x:145,y:365},notes:['Separate DNS stub responsibility inside the selected application process; not an invented network hop.']},
  dnsResolver:{name:'Recursive resolver',kind:'server',role:'Recursive lookup / cache',position:{x:560,y:120},notes:['Owns queries, received public records and explicitly modeled cache entries.']},
  dnsValidator:{name:'In-process DNSSEC validator',kind:'server',role:'Local DNSSEC validation',parentId:'dnsResolver',position:{x:560,y:365},notes:['Reads resolver-owned buffers in the same process. Read access is not a duplicate holding or a DNS hop.']},
  dnsRoot:{name:'. - Root authority',kind:'server',role:'Root authoritative service',position:{x:975,y:120},notes:['Serves signed public records. Any private-key custody explicitly denotes a selected co-located signer.']},
  dnsParent:{name:'example. - Parent authority',kind:'server',role:'example. authoritative',position:{x:975,y:365},notes:['Publishes the child DS independently of child DNSKEY publication.']},
  dnsChild:{name:'lab.example. - Child authority',kind:'server',role:'lab.example. authoritative',position:{x:560,y:365},notes:['Serves the selected immutable zone generation, not a live DNS service.']},
  dnsSigner:{name:'Child signing service / HSM',kind:'server',role:'Zone signing capability',position:{x:145,y:365},notes:['Only this signer holds its private-key handles. DNSKEY and RRSIG never carry private signing material.']},
  dnsOperator:{name:'Zone / trust operator',kind:'user',role:'Configured policy / clock',position:{x:145,y:610},notes:['Provisioning, publication and acceptance are separately authored actions.']},
  dnsUpstream:{name:'Upstream recursive resolver',kind:'server',role:'Selected upstream resolver',position:{x:975,y:120},notes:['Its validation result is a remote assertion unless this resolver independently checks the data.']},
  dnsParentAgent:{name:'Parent DS automation agent',kind:'server',role:'Delegation automation',position:{x:145,y:365},notes:['Queries child signals and applies parent policy; child intent is not parent publication.']},
  dnsPrimary:{name:'Signed-zone primary',kind:'server',role:'Signed-zone publication',position:{x:560,y:120},notes:['A server publishing pre-signed records need not hold a signing private key.']},
  dnsSecondary:{name:'Signed-zone secondary',kind:'server',role:'Transferred-zone publication',position:{x:975,y:120},notes:['Has the actually transferred generation, not whatever the primary has just published.']},
  dnsProviderB:{name:'Independent provider B / signer',kind:'server',role:'Alternative authority / signer',position:{x:975,y:365},notes:['Private keys remain at this provider; shared public DNSKEY material does not copy private keys.']},
  dnsAdversary:{name:'On-path response adversary',kind:'server',role:'Public-data path attacker',position:{x:145,y:365},notes:['Controls an explicitly unprotected response path, not a trust anchor or private signing key.']},
});
export const dnssecPut=(path,value)=>({op:'put',path:'dnssec.'+path,value});
export const dnssecAppend=(path,value)=>({op:'append',path:'dnssec.'+path,value});

/** Author source operations once. Playback and inventory use the existing reducers. */
export function dnssecAuthor(number,caseId,{profileId='modern',publisherSigningAlgorithms,actorOverrides={}}={}){
  const meta=dnssecLessonMeta(number);
  if(!meta.caseIds.includes(caseId))throw new RangeError('Unknown DNSSEC case '+meta.planId+'/'+caseId);
  const profile=dnssecProfile(profileId),policy=publisherSigningAlgorithms===undefined?profile:dnssecAuthorFreeze({...profile,signingAlgorithms:[...publisherSigningAlgorithms]}),id=meta.id,steps=[],inventory={artifacts:[],initial:[],events:{},bindings:[]},objects=new Map();
  const actorSpecs={...DNSSEC_ACTOR_SPECS};
  for(const [actor,spec] of Object.entries(actorOverrides))actorSpecs[actor]={...actorSpecs[actor],...spec};
  const actorIds=Object.keys(actorSpecs),holdings=new Map(),created=new Set(),chapters=new Map();let serial=0,clock=DNSSEC_BASE_CLOCK,chapter=null;
  const initialState={protocolClock:clock,dnssec:{caseId,profileId,clock,received:false,signatureChecked:false,chainEstablished:false,denialChecked:false,acceptedForUse:false,cached:false,returnedToStub:false,securityStatus:'not-checked',reasonCode:'awaiting-data',anchorRef:null,validationOwner:null,verificationKind:null,evidenceMode:'symbolic-reference-bound',evidenceRefs:[],algorithmPolicy:policy,checkedAt:null,failureStage:null,firstDetector:null,applicationResult:{status:'pending'},response:{rcode:null,ede:{present:false},hops:[]},validators:{},cacheEntries:[],trustStores:{},transport:{attempted:false,completed:false,encrypted:false,authenticatedEndpoint:false,failure:null},timers:{},publication:{},messages:[]}};
  const actor=id=>{if(!actorSpecs[id])throw new RangeError('Unknown DNSSEC actor '+id);return id;};
  const object=id=>{const result=objects.get(id);if(!result)throw new RangeError('Unknown DNSSEC object '+id);return result;};
  const holdingKey=(artifactId,actorId,store,representationId)=>[artifactId,actorId,store,representationId].join('|');
  const has=(artifactId,actorId,store,representationId=object(artifactId).representation)=>[...holdings.values()].some(h=>h.artifactId===artifactId&&h.actorId===actorId&&(store===undefined||h.store===store)&&h.representationId===representationId);
  const acquire=(artifactId,actorId,store='Local data',representationId=object(artifactId).representation,retention='retained')=>{
    object(artifactId);actor(actorId);const key=holdingKey(artifactId,actorId,store,representationId);
    if(holdings.has(key))throw new TypeError('Duplicate DNSSEC holding '+key);
    const effect={op:'acquire',artifactId,actorId,store,representationId,retention,holdingId:id+':'+caseId+':holding:'+ ++serial};holdings.set(key,effect);return effect;
  };
  const release=(artifactId,actorId,store='Local data',representationId=object(artifactId).representation)=>{
    const key=holdingKey(artifactId,actorId,store,representationId),holding=holdings.get(key);
    if(!holding)throw new TypeError('No DNSSEC holding to release '+key);holdings.delete(key);return {op:'release',holdingId:holding.holdingId};
  };
  const create=(artifactId,actorId=object(artifactId).creator,store='Local data',representationId=object(artifactId).representation,retention='retained')=>{
    if(created.has(artifactId))throw new TypeError('DNSSEC object recreated '+artifactId);created.add(artifactId);return [{op:'create',artifactId},acquire(artifactId,actorId,store,representationId,retention)];
  };
  const fieldsFor=(kind,value,prefix=kind)=>dnssecFields(kind).flatMap(attributeId=>{
    const definition=DNSSEC_ATTRIBUTES[attributeId],exact=dnssecAuthorRead(value,definition.dnssecPath);
    return exact===undefined?[]:[{attributeId,name:definition.name,fieldPath:prefix+'.'+(definition.dnssecPath||'record'),value:exact}];
  });
  const artifact=(key,label,creator,value,{kind='rrset',initial=false,holders=[creator],store='Published public records',privateKey=false,representation='plain',readers=privateKey?[creator]:actorIds,extraFields=[],derivedFrom=[],related=[],replaces=[]}={})=>{
    actor(creator);const artifactId=id+':'+key;if(objects.has(artifactId))throw new TypeError('Duplicate DNSSEC object '+artifactId);
    const fields=[...fieldsFor(kind,value),...extraFields];if(!fields.length)throw new TypeError('DNSSEC object has no declared exact fields '+artifactId);
    if(new Set(fields.map(field=>field.attributeId)).size!==fields.length)throw new TypeError('Duplicate DNSSEC representation field '+artifactId);
    const entry={artifactId,label,creator,value:dnssecAuthorFreeze(value),kind,representation,privateKey,fields};objects.set(artifactId,entry);
    inventory.artifacts.push({artifactId,label,creator,type:privateKey?'private-key-handle':'dns-'+kind,...(derivedFrom.length?{derivedFrom}:{}),...(related.length?{related}:{}),...(replaces.length?{replaces}:{}),representations:[{representationId:representation,format:privateKey?'opaque signer handle':representation,readableBy:[...readers],fields:fields.map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:[...readers]}))}]});
    if(initial){if(created.has(artifactId))throw new TypeError('Duplicate initial DNSSEC object');created.add(artifactId);inventory.initial.push({op:'create',artifactId},...holders.map(holder=>acquire(artifactId,holder,store,representation)));}
    return artifactId;
  };
  const operations=(artifactId,actorId,kind,sourceEventId,{holders:knownHolders,representation=object(artifactId).representation,carriedAs}={})=>{
    const entry=object(artifactId),owners=knownHolders||[...new Set([...holdings.values()].filter(h=>h.artifactId===artifactId&&h.representationId===representation).map(h=>h.actorId))];
    return entry.fields.map(field=>({attributeId:field.attributeId,kind,actorId,instanceId:artifactId,creator:entry.creator,holders:owners,inspectors:entry.privateKey?[entry.creator]:actorIds,fieldPath:field.fieldPath,representation,value:field.value,sourceEventId,exactValueRef:artifactId+':'+representation+':'+field.fieldPath,...(carriedAs?{carriedAs}:{})}));
  };
  const local=(key,title,actorId,{values={},effects=[],refs=[],held=[],kind='inspect',summary=title,detail=summary,boundary=key,checks=[]}={})=>{
    actor(actorId);const sourceEventId=id+':'+caseId+':'+key;if(inventory.events[sourceEventId])throw new TypeError('Duplicate DNSSEC source event '+sourceEventId);
    const recordFields=fieldsFor('event',values),ops=recordFields.map(field=>({attributeId:field.attributeId,kind:'inspect',actorId,instanceId:sourceEventId+':record',creator:actorId,holders:[actorId],inspectors:[actorId],fieldPath:field.fieldPath,representation:'observation',value:field.value,sourceEventId,exactValueRef:sourceEventId+':'+field.fieldPath}));
    for(const ref of refs){const target=typeof ref==='string'?{artifactId:ref}:ref;ops.push(...operations(target.artifactId,actorId,target.kind||kind,sourceEventId,target));}
    const presentation=dnssecAuthorPresentation(ops,detail);
    const step=labStep(sourceEventId,title,actorId,actorId,chapter||key,'internal',summary,detail,presentation.fields,presentation.payload,checks,ops);
    step.overviewFields=presentation.fields;step.detailedPayload=presentation.detailedPayload;
    step.eventType='local';step.protocolLabel='Local DNS operation';step.protocolEffects=effects;step.dnssecBoundary=boundary;steps.push(step);
    const heldEffects=[...held];for(const ref of refs){const target=typeof ref==='string'?{artifactId:ref}:ref,operation=target.kind||kind;if(['inspect','create'].includes(operation)||held.some(effect=>effect.op==='create'&&effect.artifactId===target.artifactId))continue;heldEffects.push({op:'observe',artifactId:target.artifactId,actorId,representationId:target.representation||object(target.artifactId).representation,kind:operation==='verify'?'verification':'knowledge',result:operation+' at '+key});}
    inventory.events[step.id]={effects:heldEffects,messages:[]};if(chapter)chapters.get(chapter).stepIds.push(step.id);return step;
  };
  const useChapter=(key,label)=>{chapter=key;if(!chapters.has(key))chapters.set(key,{id:key,label,stepIds:[]});};
  const clockEffects=next=>{
    if(!Number.isFinite(next)||next<clock)throw new RangeError('DNSSEC protocol time cannot reverse');const delta=next-clock;clock=next;
    return [{op:'advance',value:delta},dnssecPut('clock',clock)];
  };
  const advanceTo=(next,key='clock-'+steps.length,label='Advance represented protocol time')=>{
    const effects=clockEffects(next);
    return local(key,label,'dnsOperator',{values:{seconds:effects[0].value,now:clock,playbackTimeIsNotProtocolTime:true},effects});
  };
  const send=(key,title,from,to,refs=[],message={},effects=[],transport='UDP')=>{
    actor(from);actor(to);const route=typeof transport==='string'?{protocol:transport,encrypted:false,authenticatedEndpoint:false}:transport;
    const entries=refs.map(ref=>typeof ref==='string'?ref:ref.artifactId);
    for(const ref of entries){const entry=object(ref);if(entry.privateKey)throw new TypeError('A DNS message cannot carry private signing material');if(!has(ref,from))throw new TypeError('DNS sender lacks exact object '+from+' '+ref);}
    const recordSections={answer:[],authority:[],additional:[]},counts={answer:0,authority:0,additional:message.edns?.present?1:0};
    for(const [index,ref] of entries.entries()){
      const entry=object(ref),descriptor=typeof refs[index]==='string'?{}:refs[index];
      const count=descriptor.recordCount??(entry.kind==='rrset'||entry.kind==='glue'?entry.value.records.length:entry.kind==='rrsig'?1:0);
      if(!count)continue;
      const section=descriptor.section||(entry.kind==='glue'?'additional':message.referral?'authority':'answer');
      if(!Object.hasOwn(recordSections,section)||!Number.isInteger(count)||count<0)throw new TypeError('Invalid authored DNS record section/count');
      recordSections[section].push({artifactId:ref,recordCount:count});counts[section]+=count;
    }
    const packetValue={...message,opcode:message.opcode??message.flags?.OPCODE,questionCount:message.question?message.question.qdcount??1:0,answerCount:counts.answer,authorityCount:counts.authority,additionalCount:counts.additional,recordSections,transport:route.protocol,encrypted:!!route.encrypted,authenticatedEndpoint:route.authenticatedEndpoint||false,objects:entries.map(ref=>({artifactId:ref,value:object(ref).value}))};
    const extraFields=[...message.question?fieldsFor('question',message.question):[],...message.edns?fieldsFor('opt',message.edns):[]];
    const packet=artifact(key+'-message',title+' / DNS message',from,packetValue,{kind:'header',store:'DNS output',readers:route.encrypted?[from,to]:actorIds,extraFields,related:entries});
    local(key+'-construct','Construct '+title,from,{values:{messageId:message.messageId??message.id,question:message.question||null,transport:route.protocol},refs:[...entries.map(artifactId=>({artifactId,kind:'inspect'})),{artifactId:packet,kind:'create'}],held:create(packet,from,'DNS output','plain','temporary'),kind:'create',detail:'Construct this exact message occurrence. Sender custody precedes transfer; a query or public record does not become authenticated by being sent.'});
    let carrier=packet,carrierRep='plain';
    if(route.encrypted){
      carrier=artifact(key+'-tls-carrier',title+' / opaque TLS carrier',from,{ciphertext:'SYM(TLS carried DNS message '+key+')',plaintextRef:packet,transport:route.protocol,authenticatedEndpoint:route.authenticatedEndpoint||false},{kind:'event',representation:'wire',readers:actorIds,derivedFrom:[packet,...entries]});carrierRep='wire';
      local(key+'-protect','Protect the DNS message on the declared TLS hop',from,{values:{transport:route.protocol,authenticatedEndpoint:route.authenticatedEndpoint||false,dnssecVerdictCreated:false},refs:[{artifactId:packet,kind:'inspect'},{artifactId:carrier,kind:'derive'}],held:[...create(carrier,from,'TLS output','wire','temporary'),release(packet,from,'DNS output')],kind:'derive'});
    }
    const sourceEventId=id+':'+caseId+':'+key,wireObjects=route.encrypted?[carrier]:[packet,...entries];
    const ops=wireObjects.flatMap(ref=>[...operations(ref,from,'send',sourceEventId,{holders:[from],representation:ref===carrier?carrierRep:object(ref).representation}),...operations(ref,to,'receive',sourceEventId,{holders:[to],representation:ref===carrier?carrierRep:object(ref).representation})]);
    const presentation=dnssecAuthorPresentation(ops.filter(op=>op.kind==='send'),'Exact transmitted representation',true);
    const step=labStep(sourceEventId,title,from,to,chapter||key,'backchannel',title,route.encrypted?'The established TLS hop protects this message only; it creates no DNSSEC trust.':'Public DNS data is readable. Receipt, checking and accepted use are separate boundaries.',presentation.fields,presentation.payload,[],ops);
    step.overviewFields=presentation.fields;step.detailedPayload=presentation.detailedPayload;
    step.eventType='message';step.protocolLabel=route.protocol;step.layers=[{protocol:'DNS',transport:route.protocol,from,to,protection:route.encrypted?'Declared established-hop confidentiality; independent DNSSEC validation':'No DNSSEC confidentiality'}];step.dnssecBoundary=key;step.protocolEffects=route.encrypted?[]:effects;steps.push(step);if(chapter)chapters.get(chapter).stepIds.push(step.id);
    const receiveData=()=>entries.flatMap(ref=>has(ref,to,'Received public records')?[]:[acquire(ref,to,'Received public records')]);
    const wireEffects=[release(carrier,from,route.encrypted?'TLS output':'DNS output',carrierRep),acquire(carrier,to,route.encrypted?'TLS inbox':'DNS inbox',carrierRep,'temporary'),...route.encrypted?[]:receiveData()];
    inventory.events[step.id]={effects:wireEffects,messages:[{messageId:sourceEventId+':wire',from,to,start:0,end:1,objects:wireObjects.map(artifactId=>({artifactId,representationId:artifactId===carrier?carrierRep:object(artifactId).representation}))}]};
    if(route.encrypted)return local(key+'-recover','Recover the DNS message from this TLS hop',to,{values:{messageId:message.messageId??message.id,dnssecVerdictCreated:false},effects,refs:[packet,...entries].map(artifactId=>({artifactId,kind:'decrypt'})),held:[acquire(packet,to,'DNS inbox','plain','temporary'),...receiveData(),release(carrier,to,'TLS inbox','wire')],kind:'decrypt',boundary:key});
    local(key+'-parse','Parse the received public DNS message',to,{values:{messageId:message.messageId??message.id,trustCreatedByParsing:false},refs:[packet,...entries],held:[release(packet,to,'DNS inbox')],detail:'Parse readable public fields without converting them into a trusted answer. This teaching fixture retains received records for inspection; caches are modeled separately.'});
    return step;
  };
  const publish=(key,title,from,to,refs,{effects=[],store='Published public records',transport='Declared public-zone publication channel'}={})=>{
    actor(from);actor(to);const sourceEventId=id+':'+caseId+':'+key;
    if(inventory.events[sourceEventId])throw new TypeError('Duplicate DNSSEC source event '+sourceEventId);
    for(const ref of refs){if(object(ref).privateKey)throw new TypeError('Publication cannot export a signing private key');if(!has(ref,from))throw new TypeError('Publisher lacks exact public record '+ref);}
    const ops=refs.flatMap(ref=>[...operations(ref,from,'send',sourceEventId,{holders:[from]}),...operations(ref,to,'receive',sourceEventId,{holders:[to]})]);
    const presentation=dnssecAuthorPresentation(ops.filter(op=>op.kind==='send'),title,true);
    const step=labStep(sourceEventId,title,from,to,chapter||key,'backchannel',title,'Publish these exact public representations, not private signing capabilities or an implied remote-cache flush.',presentation.fields,presentation.payload,[],ops);
    step.overviewFields=presentation.fields;step.detailedPayload=presentation.detailedPayload;
    step.eventType='message';step.protocolLabel=transport;step.protocolEffects=effects;step.dnssecBoundary=key;steps.push(step);
    if(chapter)chapters.get(chapter).stepIds.push(step.id);
    inventory.events[step.id]={effects:refs.flatMap(ref=>has(ref,to,store)?[]:[acquire(ref,to,store)]),messages:[{messageId:sourceEventId+':publication',from,to,start:0,end:1,objects:refs.map(artifactId=>({artifactId,representationId:object(artifactId).representation}))}]};
    return step;
  };
  const clearPacket=(packet,actorId)=>release(packet,actorId,'DNS inbox');
  // Null/false state does not mean an object is held. Reused reference slots can bind one exact generation.
  const bind=(path,artifactId,actorId,store,condition={})=>{
    inventory.bindings.push({path:'dnssec.'+path,artifactId,actorId,representationId:object(artifactId).representation,...(store?{store}:{}),...(Object.hasOwn(condition,'equals')?{equals:condition.equals}:{})});
  };
  const finish=(extra={})=>{
    const remaining=[...holdings.values()].filter(holding=>holding.retention==='temporary');
    if(remaining.length){const byActor=new Map();for(const holding of remaining){if(!byActor.has(holding.actorId))byActor.set(holding.actorId,[]);byActor.get(holding.actorId).push(holding);}for(const [owner,entries] of byActor)local('release-buffers-'+owner,'Release consumed DNS transport buffers',owner,{values:{cacheInvalidated:false,signatureValidityChanged:false},refs:entries.map(entry=>({artifactId:entry.artifactId,kind:'dispose'})),held:entries.map(entry=>release(entry.artifactId,entry.actorId,entry.store,entry.representationId)),kind:'dispose'});}
    const usedSources=DNSSEC_SOURCES.filter(source=>meta.sourceGroups.includes(source.groupId)).map(source=>({...source,section:source.note,revision:source.researchCutoff,retrieved:source.captures[0]?.retrievedAt||'See frozen source ledger',errata:'Verified corrections and Held/Rejected dispositions are recorded separately in the frozen source/errata ledger.'}));
    const model=labScenario({id,title:meta.title,workspace:'dnssec',family:meta.family,category:'DNSSEC / '+meta.family,protocol:'DNS / DNSSEC',standard:'DNSSEC RFC/IANA snapshot 2026-10-23',source:usedSources[0]?.url||DNSSEC_SOURCES[0].url,status:'Synthetic standards teaching profile',summary:meta.learningQuestion,learningObjective:meta.learningQuestion,prerequisites:['Synthetic fixed zone data; no live DNS requests','Explicitly provisioned trust anchor, routing and selected resolver/application policy','Represented protocol clock1792713600; playback never advances protocol time'],supportNote:'Offline symbolic DNSSEC model bound to independently verified fixed numerical material. Not browser cryptographic validation or live resolver/signer interoperability. Private key handles stay with their declared signers.',runtimeBindings:[],initialState,dnssecInventory:inventory,caseId,variantId:caseId===meta.defaultCaseId?'default':caseId,instanceScope:id+':'+caseId+':'+profileId,profile:{id:'dnssec-'+profileId+'-2026-10-23',name:meta.title,version:'2026-10-23',publicationStatus:'Dated RFC/IANA/errata snapshot',supportStatus:'Synthetic standards illustration; no product conformance',implementation:'Lazy deterministic source-owned fixture, reference-bound symbolic signature checks',startingSummary:['Application/stub and resolver/validator are separate responsibilities in two selected processes.','Received public records remain untrusted until the explicitly shown check and acceptance boundaries.'],completion:'Follow the selected DNSSEC decision, its cache/return boundary and separate application or management outcome.',assumptions:['Fixed synthetic records and explicit trust-store/view identity','No live queries, implicit trust learning or wall-clock aging'],transports:['UDP / TCP DNS; selected already-established authenticated DoT hop only where declared'],algorithms:policy,cryptoDetail:{evidenceMode:'symbolic-reference-bound',numericalVerification:'Pinned independent verification-only fixtures; actual canonical bytes, signatures, DNSKEY and DS tuples',clock:'Explicit protocol seconds; RFC1982 signature time is distinct from cache TTL and hold-down eligibility'},sources:usedSources},decisionPanelLabel:'DNSSEC receipt, validation and application result',decisionBindings:[{label:'Data received',path:'dnssec.received'},{label:'Checked by',path:'dnssec.validationOwner'},{label:'Trust start',path:'dnssec.anchorRef'},{label:'Current status',path:'dnssec.securityStatus'},{label:'Reason',path:'dnssec.reasonCode'},{label:'Application received',path:'dnssec.applicationResult.status'}],chapterCaption:'Chapters share one canonical DNS evidence history. Seeking does not validate data, publish records or flush caches.',chapters:[...chapters.values()],protocolTimeline:{label:'DNSSEC protocol clock and evidence windows',explanation:'Playback speed and pause do not age DNS data. Only explicit protocol-clock steps advance these independent cache, signature or hold-down windows.',entries:[{id:'answer-cache',label:'Current cache focus',startPath:'dnssec.cacheEntries.0.receivedAt',deadlinePath:'dnssec.cacheEntries.0.expiresAt',statusPath:'dnssec.cacheEntries.0.securityStatus',detail:'A publication elsewhere does not flush an already received cache generation.'},{id:'answer-signature',label:'Selected answer RRSIG',startPath:'dnssec.timers.signature.inception',deadlinePath:'dnssec.timers.signature.expiration',detail:'This signed validity window is independent of the received TTL and animation duration.'}]},...extra},DNSSEC_ATTRIBUTES,steps,actorSpecs);
    return model;
  };
  return {id,number,caseId,meta,policy,actorIds,actorSpecs,initialState,steps,inventory,objects,get clock(){return clock;},artifact,object,fieldsFor,operations,acquire,release,create,has,local,send,publish,clearPacket,chapter:useChapter,clockEffects,advanceTo,bind,finish};
}
