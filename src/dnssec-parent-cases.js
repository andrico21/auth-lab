import {dnssecAuthor,dnssecPut,dnssecAppend} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,DNSSEC_MATERIAL,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecLookupPath,dnssecLookupMessage} from './dnssec-lookup.js';
import {dnssecValidateChain,dnssecCheckSignature,dnssecCanonicalInput,dnssecCanonicalName,dnssecTtlWindow} from './dnssec-validation.js';
import {dnssecCheckDenial} from './dnssec-denial.js';
import {dnssecParentEligibleDigests,dnssecParentDsRecords,dnssecParentKeyRecords,dnssecParentIntent,dnssecParentCompareSignals,dnssecParentContinuity,dnssecParentLockPolicy,dnssecParentManualChange,dnssecParentDsyncEndpoint} from './dnssec-parent-automation.js';

const dnssecParentRr=id=>dnssecMaterial('rrsets',id);
const dnssecParentSig=id=>dnssecMaterial('signatures',id);
const dnssecParentKey=id=>dnssecMaterial('keys',id);
const dnssecParentDs=id=>dnssecMaterial('ds',id);
const dnssecParentAllKeys=()=>Object.values(DNSSEC_MATERIAL.keys);
const dnssecParentSetEqual=(left,right)=>left.length===right.length&&left.every(value=>right.includes(value));
const dnssecParentSourcePath=path=>path.replace('docs/dnssec-expansion/','');
function dnssecParentSourceMetadata(rrsetId){
  const provenance=DNSSEC_MATERIAL.provenance,origin=provenance.objects.rrsets[rrsetId][0],catalog=[provenance.completionCatalog,provenance.postFreezeCatalog,provenance.catalog].find(item=>origin.fixture.path.startsWith(item.path.slice(0,item.path.lastIndexOf('/')+1)));
  return {sourceDataset:dnssecParentSourcePath(origin.fixture.path),sourceSha256:origin.fixture.sha256,sourceBytes:origin.fixture.bytes,verificationPath:dnssecParentSourcePath(origin.report.path),verificationSha256:origin.report.sha256,verificationBytes:origin.report.bytes,catalogPath:dnssecParentSourcePath(catalog.path),catalogSha256:catalog.sha256};
}
const dnssecParentActors={
  dnsParentAgent:{name:'Parent DS automation agent',kind:'server',role:'Registry delegation management / independent validating queries',position:{x:145,y:120},notes:['Queries all configured addresses; local validation is in this management process, not a second DNS validator hop.']},
  dnsRoot:{name:'. root authority / signer',kind:'server',role:'Explicit co-located root signer',position:{x:975,y:610}},
  dnsParent:{name:'example. parent authority / signer',kind:'server',role:'Parent publication and explicitly co-located signer',position:{x:975,y:365}},
  dnsChild:{name:'lab.example. child authority',kind:'server',role:'Four explicitly addressed authoritative endpoints',position:{x:975,y:120}},
  dnsSigner:{name:'Child signer / HSM',kind:'server',role:'Explicit child private capability custodian',position:{x:560,y:365}},
  dnsResolver:{name:'Independent remote caching resolver',kind:'server',role:'Old-generation cache observer',position:{x:560,y:120}},
  dnsSignalNet:{name:'net. authority / signer',kind:'server',role:'Independent root-authenticated net. delegation',position:{x:975,y:120}},
  dnsSignalOrg:{name:'org. authority / signer',kind:'server',role:'Independent root-authenticated org. delegation',position:{x:975,y:120}},
  dnsSignalExampleNet:{name:'example.net. authority / signer',kind:'server',role:'Independent operator ancestor',position:{x:975,y:120}},
  dnsSignalExampleOrg:{name:'example.org. authority / signer',kind:'server',role:'Independent operator ancestor',position:{x:975,y:120}},
  dnsSignalProviderNet:{name:'provider.example.net. authority / signer',kind:'server',role:'Out-of-domain operator signaling zone',position:{x:975,y:120}},
  dnsSignalProviderOrg:{name:'provider.example.org. authority / signer',kind:'server',role:'Out-of-domain operator signaling zone',position:{x:975,y:120}},
};
const dnssecParentCustody={
  dnsRoot:['root-ksk-g1','root-zsk-g1'],dnsParent:['example-ksk-g1','example-zsk-g1'],
  dnsSigner:['child-ksk-g1','child-ksk-g2','child-zsk-g1','child-zsk-g2'],
  dnsSignalNet:['signal-net-ksk-g1','signal-net-zsk-g1'],dnsSignalOrg:['signal-org-ksk-g1','signal-org-zsk-g1'],
  dnsSignalExampleNet:['signal-example-net-ksk-g1','signal-example-net-zsk-g1'],dnsSignalExampleOrg:['signal-example-org-ksk-g1','signal-example-org-zsk-g1'],
  dnsSignalProviderNet:['signal-provider-net-ksk-g1','signal-provider-net-zsk-g1'],dnsSignalProviderOrg:['signal-provider-org-ksk-g1','signal-provider-org-zsk-g1'],
};
const dnssecParentAddresses=[
  {nameserver:'ns1.provider.example.net.',address:'192.0.2.53'},
  {nameserver:'ns1.provider.example.net.',address:'2001:db8::53'},
  {nameserver:'ns2.provider.example.org.',address:'198.51.100.53'},
  {nameserver:'ns2.provider.example.org.',address:'2001:db8:1::53'},
];
const dnssecParentIntentPairs={
  overlap:['child-cds-intent','child-cdnskey-intent'],
  old:['postfreeze-child-cds-claim','postfreeze-child-cdnskey-claim'],
  deletion:['child-cds-delete-singleton','child-cdnskey-delete-singleton'],
};

function dnssecParentContext(number,caseId,{bootstrap=false}={}){
  const a=dnssecAuthor(number,caseId,{actorOverrides:dnssecParentActors}),anchor={zone:'.',keys:[dnssecParentKey('root-ksk-g1')],provenance:'Explicit independent out-of-band root provisioning'},paths=dnssecLookupPath();
  let sequence=0,retrievalRound=0;const bundleCache=new Map(),capabilities=new Map(),hops=[],evidence=[],timers={},checkpoints={};
  const anchorRef=a.artifact('parent-agent-root-anchor','Parent agent explicitly configured root anchor','dnsOperator',{zone:'.',keyRef:'root-ksk-g1',dnskeyRdataHex:anchor.keys[0].dnskeyRdataHex,provenance:anchor.provenance,trustStore:'parent-agent-root-v1'},{kind:'trust',initial:true,holders:['dnsParentAgent'],store:'Independent parent-agent trust store'});
  Object.assign(a.initialState.dnssec,{anchorRef,view:'parent-direct-authorities',trustStore:'parent-agent-root-v1',validationOwner:null,verificationKind:null,managementOnly:true,stoppedAction:null,cacheEntries:{},retainedDelegationCaches:{},publication:{parentDsGeneration:bootstrap?'absent':'ds0',parentDsKeys:bootstrap?[]:['child-ksk-g1'],parentAccepted:false,parentPublished:false,automationSuspended:false,manualRecoveryChannelAvailable:true,remoteCachesInvalidated:false,childStillSigning:true,reports:[],authorities:{},managementHops:[],bootstrap:bootstrap?{parentDsAbsent:true}:null},trustStores:{'parent-agent-root-v1':{anchors:['root-ksk-g1'],provisioning:anchor.provenance}},applicationResult:{status:'pending',reason:'No leaf lookup/application acceptance in this management case.'}});
  a.bind('anchorRef',anchorRef,'dnsParentAgent','Independent parent-agent trust store');
  for(const [owner,trustStore] of [['dnsResolver','remote-root-v1'],['dnsChild','child-notification-root-v1']]){
    const ref=a.artifact(owner+'-independent-root-anchor','Separately provisioned root anchor for '+owner,'dnsOperator',{zone:'.',keyRef:'root-ksk-g1',dnskeyRdataHex:anchor.keys[0].dnskeyRdataHex,provenance:anchor.provenance,trustStore},{kind:'trust',initial:true,holders:[owner],store:'Independent configured root anchors'});
    a.initialState.dnssec.trustStores[trustStore]={anchors:['root-ksk-g1'],provisioning:anchor.provenance,owner,anchorRef:ref};a.bind('trustStores.'+trustStore+'.anchorRef',ref,owner,'Independent configured root anchors');
  }
  for(const [custodian,keyIds] of Object.entries(dnssecParentCustody))for(const keyId of keyIds){
    if(!bootstrap&&custodian.startsWith('dnsSignal'))continue;
    const ref=a.artifact('private-'+keyId,'Opaque private signing capability '+keyId,custodian,{handle:'HSM('+keyId+')',keyId,custodian,capability:'sign'},{kind:'secret',privateKey:true,initial:true,holders:[custodian],store:'Signer-only capability pool'});capabilities.set(keyId,{custodian,ref});
  }
  const signerFor=keyId=>{const entry=capabilities.get(keyId);if(!entry)throw new TypeError('Unprovisioned parent lesson signer '+keyId);return entry.custodian;};
  const bundle=(rrsetId,signatureIds,owner,{initial=true,ttl=null,store='Published public zone generation'}={})=>{
    const identity=[rrsetId,...signatureIds,owner,ttl,initial,store].join('|');if(bundleCache.has(identity))return bundleCache.get(identity);
    const fixed=dnssecParentRr(rrsetId),rrset=ttl===null?fixed:{...fixed,ttl},signatures=signatureIds.map(dnssecParentSig),creator=signatures.length?signerFor(signatures[0].keyId):owner,prefix='bundle-'+ ++sequence;
    const rr=a.artifact(prefix+'-rrset',rrset.owner+' '+rrset.type+' / exact zone generation',creator,rrset,{kind:'rrset',initial,holders:[owner],store});
    const sigs=signatures.map((signature,index)=>a.artifact(prefix+'-rrsig-'+index,'RRSIG('+rrset.type+') '+signature.keyId,signerFor(signature.keyId),signature,{kind:'rrsig',initial,holders:[owner],store,derivedFrom:[rr]}));
    const keys=rrset.type==='DNSKEY'?dnssecParentKeyRecords(rrset,dnssecParentAllKeys()).filter(Boolean):[];
    const atoms=keys.map(key=>a.artifact(prefix+'-key-'+key.id,'DNSKEY '+key.id,creator,key,{kind:'dnskey',initial,holders:[owner],store,derivedFrom:[rr]}));
    const value={rrset,signatures,owner,rr,sigs,atoms,keys,refs:[rr,...sigs,...atoms],initial};bundleCache.set(identity,value);return value;
  };
  const fetch=(item,{from='dnsParentAgent',to=item.owner,address=null,key='fetch-'+ ++sequence,section='answer',question:questionOverride=null,extraRefs=[],retrievalId=null}={})=>{
    a.chapter(key,'Retrieve '+item.rrset.owner+' '+item.rrset.type+(address?' at '+address:''));
    const id=23000+ ++sequence,question={qname:item.rrset.owner,qtype:item.rrset.type,qclass:'IN',...questionOverride},query=dnssecLookupMessage(id,question,{flags:{CD:1}}),response=dnssecLookupMessage(id,question,{response:true,authoritative:true});
    a.send(key+'-q','Query exact '+question.qtype+' without a cache',from,to,[],{...query,destinationAddress:address,cacheBypass:true,retrievalId},[dnssecPut('transport.attempted',true)]);
    const occurrence=a.artifact(key+'-receipt','Received occurrence '+item.rrset.owner+' '+item.rrset.type,to,item.rrset,{kind:'rrset',derivedFrom:[item.rr]});
    const receivedSigs=item.signatures.map((signature,index)=>a.artifact(key+'-receipt-rrsig-'+index,'Received RRSIG occurrence '+signature.id,to,signature,{kind:'rrsig',derivedFrom:[item.sigs[index]]}));
    a.local(key+'-prepare','Prepare exact response occurrences without creating new signed bytes',to,{values:{receivedRrsetTtl:item.rrset.ttl,signedOriginalTtls:item.signatures.map(sig=>sig.originalTtl)},refs:[item.rr,...item.sigs.map(artifactId=>({artifactId,kind:'inspect'})),{artifactId:occurrence,kind:'derive'},...receivedSigs.map(artifactId=>({artifactId,kind:'derive'}))],held:[...a.create(occurrence,to,'Response occurrence'),...receivedSigs.flatMap(ref=>a.create(ref,to,'Response occurrence'))],kind:'derive'});
    const refs=[{artifactId:occurrence,section},...receivedSigs.map(artifactId=>({artifactId,section})),...item.atoms.map(artifactId=>({artifactId,recordCount:0})),...extraRefs];
    const hop={id:key,from,to,address,retrievalId,question:query.question,query:{messageId:id,flags:query.flags,edns:query.edns},response:{messageId:id,inReplyTo:key+'-q',flags:response.flags,edns:response.edns,rcode:'NOERROR'}};hops.push(hop);
    a.send(key+'-r','Receive readable '+question.qtype+' before management trust',to,from,refs,{...response,sourceAddress:address,inReplyTo:key+'-q',retrievalId},[dnssecPut('received',true),dnssecPut('transport.completed',true),dnssecAppend('publication.managementHops',hop)]);
    return {...item,sigs:receivedSigs,occurrence,receivedAt:a.clock,message:hop};
  };
  const observe=(boundary,title,values={},effects=[],refs=[],actor='dnsParentAgent',held=[])=>{
    checkpoints[boundary]=boundary;return a.local(boundary,title,actor,{boundary,values,effects,refs,held});
  };
  const evidenceFor=(key,result,refs,actor='dnsParentAgent')=>{
    const ref=a.artifact('evidence-'+key,'Reference-bound evidence '+key,actor,{checkedAt:a.clock,validationOwner:actor,verificationKind:'local-check',evidenceMode:'symbolic-reference-bound',result},{kind:'trust',derivedFrom:refs});
    a.local('create-evidence-'+key,'Record exact canonical/signature/path evidence',actor,{values:{checkedAt:a.clock,result},refs:[...refs,{artifactId:ref,kind:'derive'}],held:a.create(ref,actor,'Management validation evidence'),kind:'derive'});evidence.push(ref);return ref;
  };
  const chainBundles=(links,tag,{requester='dnsParentAgent'}={})=>{
    const refs=[];for(const [index,link] of links.entries()){
      const owner=link.zone==='.'?'dnsRoot':link.zone==='example.'?'dnsParent':link.zone==='lab.example.'?'dnsChild':link.zone==='net.'?'dnsSignalNet':link.zone==='org.'?'dnsSignalOrg':link.zone==='example.net.'?'dnsSignalExampleNet':link.zone==='example.org.'?'dnsSignalExampleOrg':link.zone==='provider.example.net.'?'dnsSignalProviderNet':'dnsSignalProviderOrg';
      if(link.dsRrset){const parentOwner=links[index-1].zone==='.'?'dnsRoot':links[index-1].zone==='example.'?'dnsParent':links[index-1].zone==='net.'?'dnsSignalNet':links[index-1].zone==='org.'?'dnsSignalOrg':links[index-1].zone==='example.net.'?'dnsSignalExampleNet':'dnsSignalExampleOrg';refs.push(fetch(bundle(link.dsRrset.id,link.dsSignatures.map(sig=>sig.id),parentOwner),{from:requester,key:tag+'-ds-'+index,section:'authority'}));}
      refs.push(fetch(bundle(link.dnskeyRrset.id,link.dnskeySignatures.map(sig=>sig.id),owner),{from:requester,key:tag+'-keys-'+index}));
    }return refs;
  };
  const parentLinks=paths.slice(0,2),parentEvidence=()=>chainBundles(parentLinks,'parent-chain');
  const childLinks=({dnskeyRrset=dnssecParentRr('child-dnskey-rollover'),signatures=[dnssecParentSig('child-dnskey-rollover-old-long')],dsRrset=dnssecParentRr('example-child-ds-rollover-ttl86400'),dsSignatures=[dnssecParentSig('example-child-ds-rollover-long')]}={})=>[...parentLinks,{zone:'lab.example.',dsRrset,dsSignatures,ds:dnssecParentDsRecords(dsRrset),dnskeyRrset,dnskeySignatures:signatures,keys:dnssecParentKeyRecords(dnskeyRrset,dnssecParentAllKeys()).filter(Boolean)}];
  const validate=(item,links)=>dnssecValidateChain({anchor,links,answer:{rrset:item.rrset,signatures:item.signatures},now:a.clock,policy:a.policy});
  const publishDs=(key,keys,{bootstrap:boot=false,deletion=false}={})=>{
    a.chapter(key,'Parent publication is a separate scheduled operation');
    const source=deletion?bundle('denial-parent-unsigned-lab',['denial-parent-unsigned-lab-signature'],'dnsParent',{initial:false}):boot?bundle('example-child-ds',['example-child-ds-path-long'],'dnsParent',{initial:false,ttl:600}):bundle('parent-ds-overlap-g1-g2',['parent-ds-overlap-g1-g2-signature'],'dnsParent',{initial:false,ttl:600});
    const privateRefs=source.signatures.map(sig=>capabilities.get(sig.keyId).ref),verified=dnssecCheckSignature({rrset:source.rrset,signatures:source.signatures,keys:parentLinks[1].keys,now:a.clock,policy:a.policy,expectedSigner:'example.'});
    if(!verified.valid)throw new TypeError('Parent publication lacks exact usable signature '+key);
    a.local(key+'-sign','Parent signer prepares the exact new public generation','dnsParent',{values:{proposedKeyIds:keys,signingResult:verified,privateKeysPublished:false,canonicalInputHex:dnssecCanonicalInput(source.rrset,source.signatures[0])},refs:[...privateRefs,...source.refs.map(artifactId=>({artifactId,kind:'create'}))],held:source.refs.flatMap(ref=>a.create(ref,'dnsParent','Parent publication output')),kind:'create'});
    a.publish(key,'Publish parent '+(deletion?'authenticated no-DS state':'DS generation'),'dnsParent','dnsParentAgent',source.refs,{effects:[dnssecPut('publication.parentAccepted',true),dnssecPut('publication.parentPublished',true),dnssecPut('publication.parentDsGeneration',deletion?'ds-absent':boot?'ds-boot':'ds01'),dnssecPut('publication.parentDsKeys',keys),dnssecPut('publication.dsTtl',deletion?null:600),dnssecPut('publication.remoteCachesInvalidated',false),dnssecPut('publication.automationSuspended',false)]});checkpoints[key]=key;return source;
  };
  const finish=(result)=>{
    a.chapter('management-result','Management result - no application lookup');
    observe('management-result-classification','Classify management authentication separately from update acceptance',{result,evidenceRefs:evidence},[],[],result.resultActor||'dnsParentAgent');
    const dnssecContext=number===16?{
      title:'CSYNC synchronization versus CDS / CDNSKEY DS intent',
      explanation:'CSYNC requests NS and address/glue synchronization. It does not request DS replacement. CDS and CDNSKEY instead express child intent for the parent DS set.',
      records:[{label:'CSYNC - NS/glue synchronization',fieldId:'dnssec_csync_record'},{label:'CDS - proposed DS intent',fieldId:'dnssec_cds_record'},{label:'CDNSKEY - public-key intent for DS',fieldId:'dnssec_cdnskey_record'}],
      parentDecision:'The parent independently authenticates eligible records and applies its processing policy. CSYNC never authorizes a DS change; CDS/CDNSKEY intent is not acceptance or publication of parent DS records.',
    }:null;
    const final=a.steps[a.steps.length-1];final.protocolEffects=[dnssecPut('securityStatus',result.securityStatus),dnssecPut('reasonCode',result.reasonCode),dnssecPut('validationOwner',result.validationOwner===undefined?'dnsParentAgent':result.validationOwner),dnssecPut('verificationKind',result.verificationKind||'local-check'),dnssecPut('failureStage',result.failureStage||null),dnssecPut('firstDetector',result.firstDetector||null),dnssecPut('stoppedAction',result.stoppedAction||null),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('returnedToStub',false),dnssecPut('applicationResult',{status:'pending',reason:'No leaf lookup/application acceptance in this management case.'}),dnssecPut('evidenceRefs',evidence)];
    return a.finish({dnssecContext,dnssecCheckpointAliases:checkpoints,decisionPanelLabel:'Parent management: receipt, authentication, policy, publication',decisionBindings:[{label:'Signal status',path:'dnssec.securityStatus'},{label:'Reason',path:'dnssec.reasonCode'},{label:'Intent accepted',path:'dnssec.publication.parentAccepted'},{label:'Parent published',path:'dnssec.publication.parentPublished'},{label:'Current DS generation',path:'dnssec.publication.parentDsGeneration'},{label:'Automation suspended',path:'dnssec.publication.automationSuspended'}],protocolTimeline:{label:'Independent parent publication and remote-cache timers',explanation:'Playback never ages a cache or triggers management acceptance. Retry, publication propagation, cache expiration and signed validity are independent represented seconds.',entries:[{id:'retry',label:'Full-retrieval retry',startPath:'dnssec.timers.retryStartedAt',deadlinePath:'dnssec.timers.retryAt',detail:'Timeout is not NODATA. Retry asks every configured address again.'},{id:'remote-ds',label:'Remote old DS dependency',startPath:'dnssec.cacheEntries.ds.receivedAt',deadlinePath:'dnssec.cacheEntries.ds.expiresAt',detail:'A parent publication and a shorter new TTL do not invalidate this earlier cache generation.'},{id:'remote-no-ds',label:'Remote no-DS cache',startPath:'dnssec.cacheEntries.delegation.receivedAt',deadlinePath:'dnssec.cacheEntries.delegation.expiresAt',detail:'Authenticated absence cached before enrollment can remain independently usable.'},{id:'signal',label:'Exact signal RRSIG window',startPath:'dnssec.timers.signature.inception',deadlinePath:'dnssec.timers.signature.expiration',detail:'Signature lifetime is independent of retry and publication.'}]}});
  };
  return {a,anchor,anchorRef,paths,parentLinks,bundle,fetch,observe,evidenceFor,chainBundles,parentEvidence,childLinks,validate,publishDs,finish,capabilities,hops,evidence,timers,checkpoints,nextRetrievalId:()=> 'retrieval-'+ ++retrievalRound};
}

function dnssecParentReadSignals(c,{pairs=dnssecParentAddresses.map(()=>dnssecParentIntentPairs.overlap),links,tag='intent',timeoutAddress=null,nodataAddress=null,authenticate=true,providedBundles=new Map()}={}){
  const {a}=c,responses=[],allRefs=[],authorities={},transportObservations={},receiptId=c.nextRetrievalId(),boundary=tag==='intent'?'receive-signed-child-intent':tag==='notified'?'retrieve-after-notify':tag+'-received';
  for(const [index,endpoint] of dnssecParentAddresses.entries()){
    const entry={...endpoint,transport:endpoint.address===timeoutAddress?'timeout':'received'};
    if(entry.transport==='timeout'){
      a.chapter(tag+'-timeout','All-address retrieval: distinguish timeout from a DNS response');
      for(const type of ['CDS','CDNSKEY']){const id=27000+index*2+(type==='CDS'?0:1),query=dnssecLookupMessage(id,{qname:'lab.example.',qtype:type},{flags:{CD:1}}),key=tag+'-timeout-'+type,hop={id:key,from:'dnsParentAgent',to:'dnsChild',address:endpoint.address,retrievalId:receiptId,transport:'UDP',question:query.question,query:{messageId:id,flags:query.flags,edns:query.edns},response:null};a.send(key+'-q','Query '+type+' at unreachable '+endpoint.address,'dnsParentAgent','dnsChild',[],{...query,destinationAddress:endpoint.address,cacheBypass:true,retrievalId:receiptId},[dnssecPut('transport.attempted',true),dnssecAppend('publication.managementHops',hop)]);}
      a.local(tag+'-timeout-observation','No response arrives at this address','dnsParentAgent',{values:{address:endpoint.address,response:null,transport:'timeout',dnssecVerdictInvented:false,receiptId},effects:[dnssecPut('transport.status','timeout')]});transportObservations[endpoint.address]={response:null,transport:'timeout'};responses.push(entry);continue;
    }
    for(const [typeIndex,type] of ['CDS','CDNSKEY'].entries()){
      const noData=endpoint.address===nodataAddress,rrsetId=noData?'child-nsec':pairs[index][typeIndex],signatureId=rrsetId+'-signature',item=providedBundles.get(rrsetId)||c.bundle(rrsetId,[signatureId],'dnsChild');
      let received;
      if(noData)received=c.fetch(item,{address:endpoint.address,key:tag+'-'+index+'-'+type,section:'authority',question:{qname:'lab.example.',qtype:type},retrievalId:receiptId});
      else received=c.fetch(item,{address:endpoint.address,key:tag+'-'+index+'-'+type,retrievalId:receiptId});
      allRefs.push(received.occurrence,...received.sigs);
      const result=authenticate?c.validate(received,links):null;
      let denial=null;if(noData&&result?.securityStatus==='secure')denial=dnssecCheckDenial({qname:'lab.example.',qtype:type,zone:'lab.example.',proofs:[{rrset:item.rrset,signatures:item.signatures}],keys:links[links.length-1].keys,now:a.clock,policy:a.policy,purpose:'nodata'});
      entry[type]={rrset:noData?null:item.rrset,signatures:item.signatures,received,chainResult:result,denial,authenticated:authenticate&&result?.securityStatus==='secure'&&(!noData||denial.valid)};
    }
    const cds=dnssecParentIntent(entry.CDS.rrset,dnssecParentAllKeys(),a.policy),cdnskey=dnssecParentIntent(entry.CDNSKEY.rrset,dnssecParentAllKeys(),a.policy);
    const describe=(parsed,item)=>parsed.kind==='update'?parsed.keys:item.rrset?.records||[];
    authorities[endpoint.address]={response:endpoint.address===nodataAddress?'NOERROR-NODATA':'NOERROR',generation:cdnskey.kind==='delete'?'intent-delete':dnssecParentSetEqual(cdnskey.keys,['child-ksk-g1'])?'intent0':'intent1',keys:cdnskey.keys,CDS:describe(cds,entry.CDS),CDNSKEY:describe(cdnskey,entry.CDNSKEY),wireRecords:{CDS:entry.CDS.rrset?.records||[],CDNSKEY:entry.CDNSKEY.rrset?.records||[]},validKeyReferences:cds.validKeyReferences||cds.keys,malformedCdnskeyHasNoKeyReference:cdnskey.kind==='malformed'&&cdnskey.validKeyReferences.length===0,meaning:cdnskey.kind==='no-change'?'no-change':cdnskey.kind,receiptId,messages:{CDS:entry.CDS.received.message,CDNSKEY:entry.CDNSKEY.received.message},numericBindings:{CDS:{rrsetId:entry.CDS.received.rrset.id,signatureIds:entry.CDS.signatures.map(sig=>sig.id),source:dnssecParentSourceMetadata(entry.CDS.received.rrset.id)},CDNSKEY:{rrsetId:entry.CDNSKEY.received.rrset.id,signatureIds:entry.CDNSKEY.signatures.map(sig=>sig.id),source:dnssecParentSourceMetadata(entry.CDNSKEY.received.rrset.id)}}};responses.push(entry);
  }
  const first=responses.find(entry=>entry.CDS),intentFor=item=>{const parsed=dnssecParentIntent(item.rrset,dnssecParentAllKeys(),a.policy);return parsed.kind==='update'?parsed.keys:item.rrset?.records||[];},intent=first?{CDS:intentFor(first.CDS),CDNSKEY:intentFor(first.CDNSKEY)}:{CDS:[],CDNSKEY:[]};
  a.chapter(tag+'-receipt','Raw child intent before management authentication');
  const notReceived=responses.filter(entry=>entry.transport!=='received').map(entry=>entry.address);
  c.observe(boundary,'Observe exact child signals without yet accepting them',{addressesQueried:responses.map(entry=>entry.address),intent,authorities,receiptId,notReceived},[dnssecPut('received',responses.some(entry=>entry.transport==='received')),dnssecPut('signatureChecked',false),dnssecPut('securityStatus','not-checked'),dnssecPut('timers.signature',first?{inception:first.CDS.signatures[0].inception,expiration:first.CDS.signatures[0].expiration}:null),dnssecPut('publication.childIntent',intent),dnssecPut('publication.authorities',authorities),dnssecPut('publication.receiptId',receiptId),dnssecPut('publication.sameReceiptAs',null),dnssecPut('publication.notReceived',notReceived),dnssecPut('publication.retrievalComplete',notReceived.length===0),dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)],allRefs);
  return {responses,allRefs,authorities,intent,receiptId,boundary,notReceived,transportObservations};
}

function dnssecParentCheckSignals(c,read,{links,boundary='authenticate-check-and-accept-intent',acceptPolicy=true}={}){
  const {a}=c,comparison=dnssecParentCompareSignals({addresses:dnssecParentAddresses.map(item=>item.address),responses:read.responses,keys:dnssecParentAllKeys(),policy:a.policy}),authenticated=read.responses.filter(item=>item.transport==='received').every(item=>item.CDS.authenticated&&item.CDNSKEY.authenticated),checks=read.responses.flatMap(item=>['CDS','CDNSKEY'].flatMap(type=>item[type]?[item[type].chainResult]:[])).filter(Boolean),signatureChecked=checks.some(check=>check.signatureChecked),chainEstablished=checks.some(check=>check.chainEstablished),proposedDs=comparison.keys.map(key=>dnssecParentDs(key+'-sha256'));
  const finalLink=links[links.length-1],continuity=comparison.kind==='delete'?{checked:true,valid:true,reason:'deletion-retains-child-signing-through-old-ds-cache'}:dnssecParentContinuity({ds:proposedDs,dnskeyRrset:finalLink.dnskeyRrset,signatures:finalLink.dnskeySignatures,keys:finalLink.keys,now:a.clock,policy:a.policy});
  const accepted=comparison.valid&&authenticated&&continuity.valid&&acceptPolicy;
  const metadata={comparison,continuity,authenticated,checks,accepted};c.evidenceFor(boundary,metadata,read.allRefs);
  a.chapter(boundary,'Authenticate, compare actual key identities, then apply management policy');
  c.observe(boundary,'Evaluate signal authentication, consistency and resulting validation path',metadata,[dnssecPut('signatureChecked',signatureChecked),dnssecPut('chainEstablished',chainEstablished),dnssecPut('denialChecked',read.responses.some(item=>item.CDS?.denial?.checked)),dnssecPut('securityStatus',authenticated?'secure':checks.find(check=>check.securityStatus!=='secure')?.securityStatus||'indeterminate'),dnssecPut('validationOwner','dnsParentAgent'),dnssecPut('verificationKind','local-check'),dnssecPut('publication.signalsAuthenticated',authenticated),dnssecPut('publication.consistencyChecked',true),dnssecPut('publication.consistent',comparison.consistent),dnssecPut('publication.continuityChecked',continuity.checked),dnssecPut('publication.resultingChildDnskeyHasDsMatchedValidSignature',continuity.valid),dnssecPut('publication.singletonDeleteValid',comparison.kind==='delete'&&comparison.valid),dnssecPut('publication.parentAccepted',accepted),dnssecPut('publication.parentPublished',false)],read.allRefs);
  a.steps[a.steps.length-1].protocolEffects.push(dnssecPut('publication.receiptId',read.receiptId),dnssecPut('publication.sameReceiptAs',read.boundary),dnssecPut('publication.authorities',{...read.authorities,...read.transportObservations}));
  return metadata;
}

function dnssecParentRemoteDs(c,{receivedAt=DNSSEC_BASE_CLOCK,observeAt=c.a.clock,boundary='old-remote-ds-cache-independent',initial=false}={}){
  const {a}=c,source=c.bundle('example-child-ds-rollover-ttl86400',['example-child-ds-rollover-long'],'dnsParent'),proof=c.validate(source,c.parentLinks),sig=source.signatures[0],window=dnssecTtlWindow({receivedTtl:86400,rrsigTtl:86400,originalTtl:sig.originalTtl,signatureExpiration:sig.expiration,receivedAt,now:observeAt});
  if(proof.securityStatus!=='secure'||!window.valid)throw new TypeError('Remote DS cache must be authenticated and live');
  const cacheKey=['remote-public','remote-root-v1','lab.example.','DS','IN'];
  const entry={generation:'ds0',keys:['child-ksk-g1'],receivedAt,expiresAt:window.expiresAt,status:'secure',securityStatus:'secure',validationOwner:'dnsResolver',view:cacheKey[0],trustStore:cacheKey[1],key:cacheKey,checkingContext:'local-dnssec-checking',evidenceMode:'symbolic-reference-bound',evidenceRefs:proof.selectedEvidence};
  let body,signatureRefs=source.sigs;
  if(initial){
    body=a.artifact('remote-ds-body-'+receivedAt,'Remote earlier received DS occurrence','dnsParent',source.rrset,{kind:'rrset',initial:true,holders:['dnsResolver'],store:'Independent remote DS data',derivedFrom:[source.rr]});
    const prior=[...c.parentLinks.flatMap(link=>[c.bundle(link.dnskeyRrset.id,link.dnskeySignatures.map(signature=>signature.id),link.zone==='.'?'dnsRoot':'dnsParent'),...link.dsRrset?[c.bundle(link.dsRrset.id,link.dsSignatures.map(signature=>signature.id),'dnsRoot')]:[]]),source];
    for(const item of prior)for(const ref of item.refs)if(!a.has(ref,'dnsResolver','Prior authenticated chain data'))a.inventory.initial.push(a.acquire(ref,'dnsResolver','Prior authenticated chain data'));
  }else {c.chainBundles(c.parentLinks,'remote-late-chain',{requester:'dnsResolver'});const receipt=c.fetch(source,{from:'dnsResolver',key:'late-old-ds-receipt'});body=receipt.occurrence;signatureRefs=receipt.sigs;}
  const cache=a.artifact('remote-ds-cache-'+receivedAt,'Remote cache retains old DS generation','dnsResolver',entry,{kind:'cache',initial,holders:['dnsResolver'],store:'Independent remote delegation cache',derivedFrom:[body,...signatureRefs]});
  const retainedPath='retainedDelegationCaches.ds0-'+receivedAt;
  if(initial){a.initialState.dnssec.cacheEntries.ds=entry;a.initialState.dnssec.retainedDelegationCaches['ds0-'+receivedAt]=cache;}
  else {a.chapter(boundary,'Independent remote cache still requires child signatures');a.local(boundary+'-cache','Retain independently validated old DS generation','dnsResolver',{values:{validation:proof,window,publicationDoesNotFlushRemoteCache:true},refs:[body,...signatureRefs,{artifactId:cache,kind:'derive'}],held:a.create(cache,'dnsResolver','Independent remote delegation cache'),effects:[dnssecPut('cacheEntries.ds',entry),dnssecPut(retainedPath,cache)],kind:'derive'});}
  a.bind(retainedPath,cache,'dnsResolver','Independent remote delegation cache',{equals:cache});
  if(!initial)c.observe(boundary,'Observe the old remote DS cache independently of parent publication',{entry,remainingSeconds:window.remainingSeconds},[dnssecPut('cacheEntries.ds',entry),dnssecPut('publication.childStillSigning',true)],[body,cache,...signatureRefs],'dnsResolver');return {entry,body,cache};
}

function dnssecParentUpdateCase(number,caseId,input={}){
  const c=dnssecParentContext(number,caseId),{a}=c,links=c.childLinks(),pairs=dnssecParentAddresses.map(()=>dnssecParentIntentPairs[input.signal||'overlap']);
  if(input.lastPair)pairs[3]=input.lastPair;if(input.cdsPair)for(let index=0;index<pairs.length;index++)pairs[index]=input.cdsPair;
  if(input.notify==='invalid'){
    const received=['scheme0','scheme99','port0','missing-target'].map(suffix=>c.fetch(c.bundle('parent-dsync-'+suffix,['parent-dsync-'+suffix+'-signature'],'dnsParent'),{from:'dnsChild',key:'unusable-dsync-'+suffix}));
    const entries=received.flatMap(item=>dnssecParentDsyncEndpoint(item.rrset,[]).entries.map((entry,index)=>({...entry,record:item.rrset.records[index],rrsetId:item.rrset.id,signatureId:item.signatures[0].id}))),endpoints={entries,selected:entries.find(entry=>entry.usable)||null},source=dnssecParentSourceMetadata(received[0].rrset.id);
    c.observe('ignore-unusable-dsync-entries','Ignore null/unsupported schemes, port zero and unresolved targets',{entries:endpoints.entries,source},[dnssecPut('publication.notifications',{entries:endpoints.entries,sent:false,...source})],received.map(item=>item.occurrence),'dnsChild');
    return c.finish({securityStatus:'not-checked',reasonCode:endpoints.selected?'usable-notification-endpoint':'no-usable-notification-endpoint',validationOwner:null,verificationKind:'not-performed',failureStage:'notify-endpoint-discovery',firstDetector:'dnsChild',stoppedAction:'send-notify',resultActor:'dnsChild'});
  }
  c.chainBundles(links,'management-chain');
  dnssecParentRemoteDs(c,{initial:true});
  const providedBundles=new Map();
  if(input.notify){
    const prior=c.bundle('postfreeze-child-cdnskey-claim',['postfreeze-child-cdnskey-claim-signature'],'dnsChild'),changed=c.bundle('child-cdnskey-intent',['child-cdnskey-intent-signature'],'dnsSigner',{initial:false}),privateKey=c.capabilities.get('child-ksk-g1').ref;
    a.chapter('cdnskey-only-signing','Child signer changes CDNSKEY while existing CDS already describes the overlap');
    a.local('sign-cdnskey-only-change','Sign the exact CDNSKEY-only new generation','dnsSigner',{values:{unchangedCds:'child-cds-intent',previousCdnskey:prior.rrset.records,newCdnskey:changed.rrset.records,canonicalInputHex:dnssecCanonicalInput(changed.rrset,changed.signatures[0]),privateKeysPublished:false},refs:[privateKey,...changed.refs.map(artifactId=>({artifactId,kind:'create'}))],held:changed.refs.flatMap(ref=>a.create(ref,'dnsSigner','Signed CDNSKEY publication output')),kind:'create'});
    a.advanceTo(DNSSEC_BASE_CLOCK+300,'signals-converged','Allow child publication convergence before notification');
    a.publish('publish-cdnskey-only-change','Publish the changed public CDNSKEY at all configured child endpoints','dnsSigner','dnsChild',changed.refs,{effects:[dnssecPut('publication.childGeneration','intent1'),dnssecPut('publication.cdnskeyConvergedAt',a.clock),dnssecPut('publication.cdsChanged',false)]});changed.owner='dnsChild';providedBundles.set(changed.rrset.id,changed);
    c.chainBundles(c.parentLinks,'child-notification-chain',{requester:'dnsChild'});
    const dsync=c.fetch(c.bundle('parent-dsync-cds',['parent-dsync-cds-signature'],'dnsParent'),{from:'dnsChild',key:'discover-dsync'}),address=c.fetch(c.bundle('parent-dsync-notify-address',['parent-dsync-notify-address-signature'],'dnsParent'),{from:'dnsChild',key:'discover-notify-address'}),checked=c.validate(dsync,c.parentLinks),checkedAddress=c.validate(address,c.parentLinks),endpoint=dnssecParentDsyncEndpoint(dsync.rrset,[address.rrset]).selected;
    c.evidenceFor('dsync-endpoint',{dsync:checked,address:checkedAddress},[dsync.occurrence,...dsync.sigs,address.occurrence,...address.sigs],'dnsChild');
    c.observe('discover-authenticated-dsync-endpoint','Child discovers parent-published DSYNC endpoint',{endpoint,checked,checkedAddress},[dnssecPut('publication.notifications',{lookup:dsync.rrset.owner,RRtype:endpoint.rrtype,scheme:endpoint.scheme,port:endpoint.port,target:endpoint.target,address:endpoint.addresses[0],endpointValidated:checked.securityStatus==='secure'&&checkedAddress.securityStatus==='secure'})],[dsync.occurrence,address.occurrence],'dnsChild');
    a.advanceTo(DNSSEC_BASE_CLOCK+301,'notify-time','Notification follows convergence, not acceptance');
    const message=dnssecLookupMessage(31000,{qname:'lab.example.',qtype:'CDS'},{flags:{opcode:4,AA:1,CD:0},edns:false}),ack=dnssecLookupMessage(31000,message.question,{response:true,flags:{opcode:4,AA:0,CD:0},edns:false});
    a.send('notify-cds','Child-side agent sends NOTIFY(CDS) for CDS or CDNSKEY changes','dnsChild','dnsParentAgent',[],{...message,destinationAddress:endpoint.addresses[0],destinationPort:endpoint.port});
    a.send('notify-ack','Parent acknowledges a retrieval hint, not a DS update','dnsParentAgent','dnsChild',[],{...ack,inReplyTo:'notify-cds'},[dnssecAppend('publication.managementHops',{id:'notify-cds',from:'dnsChild',to:'dnsParentAgent',address:endpoint.addresses[0],port:endpoint.port,transport:'UDP',question:message.question,query:{messageId:message.messageId,flags:message.flags,edns:message.edns},response:{messageId:ack.messageId,inReplyTo:'notify-cds',flags:ack.flags,edns:ack.edns,rcode:ack.rcode}})]);
    c.observe('send-and-ack-notify-cds','NOTIFY acknowledgment does not authenticate or publish child intent',{queryFlags:message.flags,responseFlags:ack.flags},[dnssecPut('publication.notifications',{queryFlags:message.flags,responseFlags:ack.flags,qname:'lab.example.',qtype:'CDS',ackRcode:'NOERROR',meaning:'hint-only'}),dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)]);
  }
  const read=dnssecParentReadSignals(c,{pairs,links,tag:input.notify?'notified':'intent',timeoutAddress:input.timeout?'2001:db8:1::53':null,nodataAddress:input.nodata?'192.0.2.53':null,providedBundles});
  let boundary=input.safety?'continuity-simulation':input.nodata?'nodata-is-received-no-change':input.signal==='deletion'?'validate-exact-singleton-delete':input.digest?'compare-eligible-referenced-keys':input.lastPair?'stale-response-detects-keyset-conflict':input.malformed?'reject-malformed-signed-delete':input.cdsPair?'cross-type-keyset-comparison-fails':'authenticate-check-and-accept-intent';
  let check=dnssecParentCheckSignals(c,read,{links,boundary});
  if(input.safety&&!check.continuity.valid){const report=dnssecParentReport(c,'continuity-failure',[{recipient:'child-DNS-operator',condition:'continuity-failure',channel:'configured-report-channel'}]);c.observe('resulting-delegation-continuity-fails','Cancel the requested sole-K1 delegation because no K1-valid DNSKEY signature exists',{continuity:check.continuity},[dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)],[report.ref,...read.allRefs]);}
  if(input.digest){const eligible=dnssecParentEligibleDigests(a.policy);a.steps[a.steps.length-1].protocolEffects.push(dnssecPut('algorithmPolicy.eligibleCdsConsistencyDigestTypes',eligible),dnssecPut('algorithmPolicy.ignoredForConsistencyDigestTypes',[1,3,4,250]),dnssecPut('algorithmPolicy.publishDigestType',2),dnssecPut('publication.consistencyComparison','key identity, not byte-identical CDS RRsets'));c.observe('digest-policy-record','Keep current MUST-implement consistency digests separate from publication choice',{eligible,comparison:check.comparison});}
  if(input.timeout){
    c.observe('one-address-times-out','Defer under selected retry policy without inventing NODATA',{missing:check.comparison.missing},[dnssecPut('transport.status','timeout'),dnssecPut('transport.dnssecVerdictInvented',false),dnssecPut('timers.retryStartedAt',a.clock),dnssecPut('timers.retryAt',a.clock+300),dnssecPut('publication.parentAccepted',false)]);
    a.advanceTo(a.clock+300,'retry-time','Wait the selected first retry interval');
    const retry=dnssecParentReadSignals(c,{pairs,links,tag:'retry'});check=dnssecParentCheckSignals(c,retry,{links,boundary:'full-retry-all-addresses-agree'});
  }
  if(!check.accepted){const reason=check.comparison.valid&&!check.continuity.valid?'requested-ds-would-break-validation':check.comparison.reason,failure=reason==='malformed-delete-signal'?'delete-signal-syntax':reason==='requested-ds-would-break-validation'?'continuity-check':'signal-consistency';return c.finish({securityStatus:check.authenticated?'secure':'indeterminate',reasonCode:reason,failureStage:failure,firstDetector:'dnsParentAgent',stoppedAction:reason==='requested-ds-would-break-validation'?'replace-parent-ds':input.signal==='deletion'||input.nodata||input.malformed?'remove-parent-ds':'alter-parent-ds'});}
  a.advanceTo(a.clock+600,'publication-opportunity','Wait for the next selected parent publication opportunity');
  c.publishDs(input.signal==='deletion'?'parent-publishes-authenticated-no-ds':'parent-ds-publication',check.comparison.kind==='delete'?[]:check.comparison.keys,{deletion:check.comparison.kind==='delete'});
  if(check.comparison.kind==='delete'){
    a.advanceTo(DNSSEC_BASE_CLOCK+1200,'old-parent-edge','Model the last old-DS visibility at a remote parent edge');
    const remote=dnssecParentRemoteDs(c,{receivedAt:a.clock,observeAt:a.clock,boundary:'old-ds-cache-still-needs-child-signatures'});
    a.advanceTo(remote.entry.expiresAt,'last-old-ds-expires','Wait until the last independently cached old DS dependency expires');
    const retired=[...a.objects.values()].filter(item=>item.kind==='rrsig'&&item.value.signer==='lab.example.'&&a.has(item.artifactId,'dnsChild','Published public zone generation')).map(item=>item.artifactId);
    c.observe('safe-child-unsigning-after-last-old-ds','Only now retire the child authoritative signatures; remote retained evidence remains intact',{oldDsExpiresAt:remote.entry.expiresAt,retiredPublicSignatures:retired,privateCapabilitiesDestroyed:false},[dnssecPut('publication.childStillSigning',a.clock<remote.entry.expiresAt)],retired.map(artifactId=>({artifactId,kind:'dispose'})),'dnsChild',retired.map(ref=>a.release(ref,'dnsChild','Published public zone generation')));
  }else if(!input.timeout&&!input.notify&&!input.digest){a.advanceTo(a.clock+1,'remote-observation-time');c.observe('old-remote-ds-cache-independent','New publication did not flush the old remote DS cache',{remoteCachesInvalidated:false},[],[],'dnsResolver');}
  const reason=input.signal==='deletion'?'authenticated-ds-removal-published':input.timeout?'parent-ds-update-after-retry':input.notify?'notified-checked-ds-update-published':input.digest?'eligible-keysets-consistent':'parent-ds-update-published';
  return c.finish({securityStatus:'secure',reasonCode:reason});
}

function dnssecParentSignalingLinks(branch){
  const graph=dnssecMaterial('vectors','post-freeze-publication:signalingChains')[branch],links=[];
  for(const step of graph.chain){
    if(step.role==='dnskey'){
      const rrset=dnssecParentRr(step.rrsetId),link={zone:rrset.owner,dnskeyRrset:rrset,dnskeySignatures:[dnssecParentSig(step.signatureId)],keys:dnssecParentKeyRecords(rrset,dnssecParentAllKeys()).filter(Boolean)};
      const previous=graph.chain[graph.chain.indexOf(step)-1];
      if(previous?.role==='ds'){link.dsRrset=dnssecParentRr(previous.rrsetId);link.dsSignatures=[dnssecParentSig(previous.signatureId)];link.ds=dnssecParentDsRecords(link.dsRrset);}
      links.push(link);
    }
  }
  return {graph,links};
}
function dnssecParentCopiedRdata(rrset){
  return rrset.records.map(record=>{const parts=String(record).trim().split(/\s+/);return rrset.type==='CDS'?[Number(parts[0]),Number(parts[1]),Number(parts[2]),parts.slice(3).join('').toLowerCase()].join(' '):[Number(parts[0]),Number(parts[1]),Number(parts[2]),parts.slice(3).join('')].join(' ');}).sort();
}
function dnssecParentReadBootstrap(c,{mode='authenticated',registrarAllowsDnssecDisable=true}={}){
  const {a}=c,setup=dnssecMaterial('vectors','post-freeze-publication:bootstrapSetup'),parentProof=c.bundle(setup.selectedParentNoDsRrsetId,[setup.selectedParentNoDsSignatureId],'dnsParent'),parentChain=c.parentEvidence(),noDsReceipt=c.fetch(parentProof,{key:'bootstrap-parent-no-ds',section:'authority',question:{qname:'lab.example.',qtype:'DS'}}),parentChecked=c.validate(parentProof,c.parentLinks),noDs=dnssecCheckDenial({qname:'lab.example.',qtype:'DS',zone:'example.',proofs:[{rrset:parentProof.rrset,signatures:parentProof.signatures}],keys:c.parentLinks[1].keys,now:a.clock,policy:a.policy,purpose:'no-ds'});
  c.evidenceFor('bootstrap-parent-no-ds',{parentChecked,noDs},[...parentChain.flatMap(item=>[item.occurrence,...item.sigs]),noDsReceipt.occurrence,...noDsReceipt.sigs]);
  const nameservers=mode==='in-domain'?['ns1.lab.example.','ns2.lab.example.']:dnssecParentAddresses.map(item=>item.nameserver).filter((value,index,array)=>array.indexOf(value)===index),eligible=nameservers.filter(name=>!dnssecCanonicalName(name).endsWith(dnssecCanonicalName('lab.example.'))),parentAbsent=parentChecked.securityStatus==='secure'&&noDs.valid;
  const ns=a.artifact('parent-nameserver-configuration','Parent-delegated nameservers and complete discovered addresses','dnsParent',{owner:'lab.example.',type:'NS',class:'IN',ttl:3600,records:nameservers,addressDiscovery:{validatingResolver:true,parentGlueIncluded:true,configuredAddresses:dnssecParentAddresses},routingOnly:true},{kind:'rrset',initial:true,holders:['dnsParent','dnsParentAgent'],store:'Delegation routing configuration'});
  if(mode==='in-domain'){
    c.observe('check-bootstrap-independent-namespace-prerequisite','Reject an exclusively in-domain delegation before circular signal validation',{parentAbsent,nameservers,eligible},[dnssecPut('publication.bootstrap',{parentDsAbsent:parentAbsent,eligibleOutOfDomainNs:eligible.length>0}),dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)],[ns,noDsReceipt.occurrence]);
    return {accepted:false,securityStatus:'indeterminate',reason:'bootstrap-only-in-domain-nameservers',failureStage:'bootstrap-prerequisite',verificationKind:'not-performed',stoppedAction:'use-circular-signaling-domain'};
  }
  const childKeys=c.fetch(c.bundle('child-dnskey-g1',['child-dnskey-g1-path-long'],'dnsChild'),{key:'untrusted-child-keys'});
  const apex=dnssecParentReadSignals(c,{pairs:dnssecParentAddresses.map(()=>dnssecParentIntentPairs.old),links:[],tag:'bootstrap-apex',authenticate:false});
  c.observe('retrieve-child-untrusted-claim','Child self-signed public records are a claim, not initial trust',{apexKeys:['child-ksk-g1'],childSelfSignaturesUsedForInitialTrust:false},[dnssecPut('publication.childIntent',['child-ksk-g1']),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('securityStatus','not-checked')],apex.allRefs);
  if(mode==='child-only'){
    c.observe('reject-circular-bootstrap-trust','A child-only claim cannot create the missing delegation trust',{parentAbsent,independentClaimRecords:[],acceptAfterDelaySelected:false,manualRecoveryChannelAvailable:true},[dnssecPut('publication.bootstrap.independentAuthenticatedClaim',false),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false)],apex.allRefs);
    return {accepted:false,securityStatus:'indeterminate',reason:'bootstrap-no-independent-authentication',failureStage:'bootstrap-authentication',verificationKind:'not-performed',stoppedAction:'create-parent-ds'};
  }
  let secure=true,equal=true,signalChecked=false;const results=[],refs=[];
  for(const branch of ['net','org']){
    const {graph,links}=dnssecParentSignalingLinks(branch),operator=branch==='net'?'dnsSignalProviderNet':'dnsSignalProviderOrg';
    if(mode==='insecure'){
      const authenticatedAncestors=links.slice(0,-1);c.chainBundles(authenticatedAncestors,'insecure-signal-'+branch);
      const proof=c.bundle('provider-'+branch+'-nods',['provider-'+branch+'-nods-signature'],branch==='net'?'dnsSignalExampleNet':'dnsSignalExampleOrg'),received=c.fetch(proof,{key:'insecure-provider-no-ds-'+branch,section:'authority',question:{qname:'provider.example.'+branch+'.',qtype:'DS'}}),ancestorCheck=c.validate(proof,authenticatedAncestors),absence=dnssecCheckDenial({qname:'provider.example.'+branch+'.',qtype:'DS',zone:'example.'+branch+'.',proofs:[{rrset:proof.rrset,signatures:proof.signatures}],keys:authenticatedAncestors[authenticatedAncestors.length-1].keys,now:a.clock,policy:a.policy,purpose:'no-ds'});
      const unsignedLinks=[...authenticatedAncestors,{zone:'provider.example.'+branch+'.',dnskeyRrset:links[links.length-1].dnskeyRrset,dnskeySignatures:[],keys:[],noDsProof:{rrset:proof.rrset,signatures:proof.signatures,zone:'example.'+branch+'.',delegation:'provider.example.'+branch+'.'}}];
      refs.push(received.occurrence,...received.sigs);
      for(const step of graph.claimSteps){const unsigned=c.bundle(step.rrsetId,[],operator),claim=c.fetch(unsigned,{key:'unsigned-signal-'+branch+'-'+unsigned.rrset.type}),result=c.validate(unsigned,unsignedLinks);results.push({branch,type:unsigned.rrset.type,result,ancestorCheck,absence});refs.push(claim.occurrence);secure&&=result.securityStatus==='secure';}
      continue;
    }
    const chain=c.chainBundles(links,'signaling-'+branch);refs.push(...chain.flatMap(item=>[item.occurrence,...item.sigs]));
    for(const step of graph.claimSteps){
      const claim=c.fetch(c.bundle(step.rrsetId,[step.signatureId],operator),{key:'signaling-'+branch+'-'+dnssecParentRr(step.rrsetId).type}),result=c.validate(claim,links),copied=dnssecParentCopiedRdata(claim.rrset),apexRdata=dnssecParentCopiedRdata(dnssecParentRr(step.copiedApexRrsetId)),matches=dnssecParentSetEqual(copied,apexRdata)&&apex.responses.every(response=>dnssecParentSetEqual(copied,dnssecParentCopiedRdata(response[claim.rrset.type].rrset)));
      results.push({branch,type:claim.rrset.type,result,copiedRdata:copied,apexRdata,matches});refs.push(claim.occurrence,...claim.sigs);secure&&=result.securityStatus==='secure';equal&&=matches;signalChecked||=result.signatureChecked;
    }
  }
  c.evidenceFor('independent-signaling',{parentAbsent,eligible,results,secure,equal},refs);
  if(mode==='insecure'){
    const independentlyInsecure=results.every(item=>item.result.securityStatus==='insecure'&&item.ancestorCheck.securityStatus==='secure'&&item.absence.valid);
    c.observe('signaling-path-not-secure','Authenticated ancestor absence proves the signaling zones insecure, not independently secure',{results,independentlyInsecure},[dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('securityStatus',independentlyInsecure?'insecure':'bogus'),dnssecPut('publication.bootstrap.signalingZonesSecure',false),dnssecPut('publication.parentAccepted',false)],refs);
    return {accepted:false,securityStatus:independentlyInsecure?'insecure':'bogus',reason:independentlyInsecure?'bootstrap-signaling-zone-insecure':'bootstrap-signaling-proof-invalid',failureStage:'signaling-dnssec-validation',verificationKind:'local-check',stoppedAction:'create-parent-ds'};
  }
  const allAddresses=apex.responses.length===dnssecParentAddresses.length&&apex.responses.every(response=>response.transport==='received'),bootstrap={parentDsAbsent:parentAbsent,eligibleOutOfDomainNs:eligible.length>0,signalingZonesSecure:secure,allApexAndSignalContentsEqual:equal,allAddressesQueried:allAddresses,independentAuthenticatedClaim:secure&&equal};
  c.observe('validate-independent-signaling-zone','Authenticate both complete independent root-to-operator chains and copied child RDATA',{bootstrap,results},[dnssecPut('signatureChecked',signalChecked),dnssecPut('chainEstablished',secure),dnssecPut('securityStatus',secure?'secure':'bogus'),dnssecPut('validationOwner','dnsParentAgent'),dnssecPut('verificationKind','local-check'),dnssecPut('publication.bootstrap',bootstrap),dnssecPut('publication.parentAccepted',false)],refs);
  const proposed=[dnssecParentDs('child-ksk-g1-sha256')],continuity=dnssecParentContinuity({ds:proposed,dnskeyRrset:childKeys.rrset,signatures:childKeys.signatures,keys:childKeys.keys,now:a.clock,policy:a.policy}),accepted=parentAbsent&&eligible.length>0&&secure&&equal&&allAddresses&&continuity.valid&&registrarAllowsDnssecDisable;
  const boundary=registrarAllowsDnssecDisable?'verify-continuity-and-accept-bootstrap':'parent-acceptance-policy-declines';
  c.observe(boundary,'A sound signal still needs resulting-path continuity and parent acceptance policy',{continuity,registrarAllowsDnssecDisable,selectedEnrollment:'RFC9615',olderAcceptAfterDelaySelected:false,manualRecoveryChannel:'authenticated operator portal independent of child DNS keys'},[dnssecPut('publication.continuityChecked',continuity.checked),dnssecPut('publication.resultingChildDnskeyHasDsMatchedValidSignature',continuity.valid),dnssecPut('publication.parentPolicy',{registrarAllowsDnssecDisable}),dnssecPut('publication.parentAccepted',accepted),dnssecPut('publication.parentPublished',false)],[childKeys.occurrence,...childKeys.sigs,...childKeys.atoms]);
  return {accepted,securityStatus:secure?'secure':'bogus',reason:!registrarAllowsDnssecDisable?'parent-policy-declines-bootstrap':accepted?'authenticated-bootstrap-published':'bootstrap-input-check-failed',failureStage:accepted?null:!registrarAllowsDnssecDisable?'parent-acceptance-policy':'bootstrap-authentication',verificationKind:'local-check',stoppedAction:accepted?null:'create-parent-ds',noDsReceipt,parentProof};
}
function dnssecParentBootstrapCase(caseId,input={}){
  const c=dnssecParentContext(17,caseId,{bootstrap:true}),{a}=c,result=dnssecParentReadBootstrap(c,input);
  if(!result.accepted)return c.finish({securityStatus:result.securityStatus,reasonCode:result.reason,failureStage:result.failureStage,firstDetector:'dnsParentAgent',verificationKind:result.verificationKind,stoppedAction:result.stoppedAction});
  a.advanceTo(DNSSEC_BASE_CLOCK+500,'remote-no-ds-receipt-time','Independent resolver reaches a still-old parent edge before publication');
  c.chainBundles(c.parentLinks,'remote-bootstrap-chain',{requester:'dnsResolver'});
  const soaBundle=c.bundle('example-soa-negative-cache',['example-soa-negative-cache-signature'],'dnsParent'),soa={...soaBundle,occurrence:soaBundle.rr};
  const proof=c.fetch(result.parentProof,{from:'dnsResolver',key:'remote-before-bootstrap-no-ds',section:'authority',question:{qname:'lab.example.',qtype:'DS'},extraRefs:soaBundle.refs.map(artifactId=>({artifactId,section:'authority'}))});
  const check=c.validate(proof,c.parentLinks),soaCheck=c.validate(soa,c.parentLinks),remoteDenial=dnssecCheckDenial({qname:'lab.example.',qtype:'DS',zone:'example.',proofs:[{rrset:proof.rrset,signatures:proof.signatures}],keys:c.parentLinks[1].keys,now:a.clock,policy:a.policy,purpose:'no-ds'}),selected=proof.signatures[0];
  const soaMinimum=Number(soa.rrset.records[0].trim().split(/\s+/).at(-1)),negativeTtl=Math.min(soa.rrset.ttl,soaMinimum,proof.rrset.ttl);
  const window=dnssecTtlWindow({receivedTtl:negativeTtl,rrsigTtl:proof.rrset.ttl,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,receivedAt:a.clock,now:a.clock});
  if(check.securityStatus!=='secure'||soaCheck.securityStatus!=='secure'||!remoteDenial.valid||!window.valid)throw new TypeError('Remote no-DS cache requires its own live authenticated denial and SOA');
  const cacheKey=['remote-public','remote-root-v1','lab.example.','DS','IN'];
  const entry={generation:'no-ds-before-bootstrap',status:'insecure',securityStatus:'insecure',receivedAt:a.clock,expiresAt:window.expiresAt,originalTtl:selected.originalTtl,negativeTtl,sourceRrsetId:proof.rrset.id,sourceSignatureId:selected.id,sourceDataset:'numeric/resolution-profile-fixtures.json',applicableSoaRrsetId:soa.rrset.id,applicableSoaSignatureId:soa.signatures[0].id,applicableSoaDataset:'numeric/parent-negative-fixtures.json',applicableSoaMinimum:soaMinimum,applicableSoaRrsetTtl:soa.rrset.ttl,provenance:'later pre-publication remote receipt at base+'+(a.clock-DNSSEC_BASE_CLOCK)+'; TTL '+negativeTtl+' from NSEC/SOA minimum; cache persists at base+601 and expires at base+'+(window.expiresAt-DNSSEC_BASE_CLOCK),validationOwner:'dnsResolver',view:cacheKey[0],trustStore:cacheKey[1],key:cacheKey,checkingContext:'local-dnssec-checking',evidenceRefs:[...check.selectedEvidence,...soaCheck.selectedEvidence]};
  const cache=a.artifact('remote-no-ds-cache','Independent old authenticated no-DS cache','dnsResolver',entry,{kind:'cache',derivedFrom:[proof.occurrence,...proof.sigs,soa.occurrence,...soa.sigs]});
  a.local('cache-remote-no-ds','Remote resolver caches its independently checked exact no-DS proof','dnsResolver',{values:{check,soaCheck,remoteDenial,negativeTtl,window},refs:[proof.occurrence,...proof.sigs,soa.occurrence,...soa.sigs,{artifactId:cache,kind:'derive'}],held:a.create(cache,'dnsResolver','Independent remote delegation cache'),effects:[dnssecPut('cacheEntries.delegation',entry)],kind:'derive'});a.bind('cacheEntries.delegation',cache,'dnsResolver','Independent remote delegation cache');
  a.advanceTo(DNSSEC_BASE_CLOCK+600,'bootstrap-publication-opportunity');c.publishDs('parent-ds-publication',['child-ksk-g1'],{bootstrap:true});
  a.advanceTo(DNSSEC_BASE_CLOCK+601,'remote-bootstrap-observation');
  c.observe('remote-no-ds-cache-persists','New DS publication cannot invalidate an independent old no-DS cache',{entry,remainingSeconds:entry.expiresAt-a.clock,remoteCachesInvalidated:false},[dnssecPut('cacheEntries.delegation',entry)],[cache,proof.occurrence,...proof.sigs],'dnsResolver');
  return c.finish({securityStatus:result.securityStatus,reasonCode:result.reason});
}

function dnssecParentReport(c,key,entries){
  const {a}=c,unique=[...new Map(entries.map(entry=>[[entry.recipient,entry.channel,entry.condition].join('|'),entry])).values()],ref=a.artifact('report-'+key,'Management report '+key,'dnsParentAgent',{reports:unique,condition:unique.map(entry=>entry.condition),createdAt:a.clock,deduplicationKey:key},{kind:'publication'});
  a.chapter('report-'+key,'Management reports use a configured channel, not a DNS verdict');
  a.local('report-'+key+'-create','Create one deduplicated exact management report','dnsParentAgent',{values:{uniqueReports:unique},refs:[{artifactId:ref,kind:'create'}],held:a.create(ref,'dnsParentAgent','Management report outbox'),effects:[dnssecPut('publication.reports',unique)],kind:'create'});
  a.publish('report-'+key+'-deliver','Deliver the configured management report','dnsParentAgent','dnsOperator',[ref],{store:'Management reports',transport:'Configured authenticated operator report channel'});
  return {ref,entries:unique};
}
function dnssecParentConcurrentCase(){
  const c=dnssecParentContext(17,'concurrent-manual-update'),{a}=c,current=c.childLinks();c.chainBundles(current,'initial-current-chain');
  let state={ds:[dnssecParentDs('child-ksk-g1-sha256')],generation:'ds0',automationSuspended:false};
  const scheduled=[];
  a.initialState.dnssec.publication.publicParentDsGeneration='ds0';
  const publishManual=()=>{for(const item of scheduled.filter(entry=>!entry.published&&entry.publishAt<=a.clock)){a.chapter('scheduled-'+item.key,'Scheduled manual publication leaves independent caches intact');a.publish('scheduled-'+item.key,'Publish the previously scheduled manual parent generation','dnsParent','dnsParentAgent',item.bundle.refs,{effects:[dnssecPut('publication.publicParentDsGeneration',item.generation),dnssecPut('publication.publicParentDsKeys',item.keys),dnssecPut('publication.remoteCachesInvalidated',false)]});item.published=true;}};
  const manual=(key,ds,{fullRemoval=false}={})=>{
    const request=a.artifact('manual-'+key,'Authenticated manual recovery request '+key,'dnsOperator',{channel:'independently authenticated operator portal',authenticatedPrincipal:'configured registrant',ds,requestAt:a.clock,manualRecoveryChannelAvailable:true},{kind:'publication'});
    a.local(key+'-request','Operator creates an independently authenticated recovery request','dnsOperator',{values:{ds,channel:'independent manual recovery'},refs:[{artifactId:request,kind:'create'}],held:a.create(request,'dnsOperator','Authenticated recovery outbox'),kind:'create'});
    a.publish(key+'-submit','Submit through the manual recovery channel','dnsOperator','dnsParent',[request],{store:'Authenticated manual requests',transport:'Authenticated operator recovery portal'});
    const evaluated=dnssecParentManualChange(state,{source:'manual-recovery',ds,authenticated:true});state=evaluated;
    const item=fullRemoval?c.bundle('denial-parent-unsigned-lab',['denial-parent-unsigned-lab-signature'],'dnsParent',{store:'Prepared manual publication candidates'}):c.bundle('example-child-ds-g2-ttl86400',['example-child-ds-g2-long'],'dnsParent',{store:'Prepared manual publication candidates'}),checked=c.validate(item,c.parentLinks);
    if(checked.securityStatus!=='secure')throw new TypeError('Manual DS publication requires exact parent signature');
    scheduled.push({key,bundle:item,generation:evaluated.generation,keys:ds.map(record=>record.keyId),publishAt:a.clock+600,published:false});
    a.publish(key+'-parent-view','Install the manual change in the current administrative authorization database','dnsParent','dnsParentAgent',item.refs,{store:'Current administrative delegation',transport:'Authenticated parent management database update',effects:[dnssecPut('publication.parentDsGeneration',evaluated.generation),dnssecPut('publication.parentDsKeys',ds.map(record=>record.keyId)),dnssecPut('publication.automationSuspended',evaluated.automationSuspended),dnssecPut('publication.manualRecoveryChannelAvailable',true),dnssecPut('timers.nextManualPublicationAt',a.clock+600)]});
    c.observe(key,'Apply current administrative authorization before its separate scheduled public publication',{evaluated,checked,scheduledPublicationAt:a.clock+600,publicZoneMayStillServeOlderGeneration:true},[],[request,...item.refs],'dnsOperator');return item;
  };
  const manualDs=manual('manual-nonempty-ds-change',[dnssecParentDs('child-ksk-g2-sha256')]);
  a.advanceTo(DNSSEC_BASE_CLOCK+1,'auto-request-after-manual');
  const oldOnly=c.childLinks({dsRrset:manualDs.rrset,dsSignatures:manualDs.signatures}),read=dnssecParentReadSignals(c,{pairs:dnssecParentAddresses.map(()=>dnssecParentIntentPairs.overlap),links:oldOnly,tag:'old-auto'}),oldCheck=dnssecParentCheckSignals(c,read,{links:oldOnly,boundary:'old-auto-authentication',acceptPolicy:!state.automationSuspended});
  c.observe('old-k0-only-auto-request-not-authorized','Old K0 authorization cannot overwrite the later manual K1 delegation',{authentication:oldCheck,scheduledAutomaticPublication:null},[dnssecPut('publication.requestSigner','child-ksk-g1'),dnssecPut('publication.requestAuthenticatesAgainstCurrentDs',oldCheck.authenticated),dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)]);
  a.advanceTo(DNSSEC_BASE_CLOCK+600,'manual-removal-time');publishManual();manual('out-of-band-full-removal-suspends',[],{fullRemoval:true});
  a.advanceTo(DNSSEC_BASE_CLOCK+1200,'manual-reprovision-time');publishManual();const resumed=manual('nonempty-manual-provision-resumes',[dnssecParentDs('child-ksk-g2-sha256')]);
  a.advanceTo(DNSSEC_BASE_CLOCK+1800,'authorized-in-band-delete-time');publishManual();
  const newPath=c.childLinks({dsRrset:resumed.rrset,dsSignatures:resumed.signatures,signatures:[dnssecParentSig('child-dnskey-rollover-old-long'),dnssecParentSig('child-dnskey-rollover-new-long')]}),newChain=c.chainBundles(newPath,'new-current-chain'),deletion=dnssecParentReadSignals(c,{pairs:dnssecParentAddresses.map(()=>['child-cds-delete-by-newk','child-cdnskey-delete-by-newk']),links:newPath,tag:'current-delete'}),check=dnssecParentCheckSignals(c,deletion,{links:newPath,boundary:'authenticate-current-key-delete',acceptPolicy:!state.automationSuspended});
  if(!check.accepted)return c.finish({securityStatus:'bogus',reasonCode:'current-manual-ds-delete-not-authorized',failureStage:'signal-authentication',firstDetector:'dnsParentAgent',stoppedAction:'remove-parent-ds'});
  state=dnssecParentManualChange(state,{source:'in-band',ds:[],authenticated:check.accepted});
  const absent=c.bundle('denial-parent-unsigned-lab',['denial-parent-unsigned-lab-signature'],'dnsParent');a.publish('current-delete-publication','Publish the authorized in-band removal in the still-open1800-second publication opportunity','dnsParent','dnsParentAgent',absent.refs,{effects:[dnssecPut('publication.parentDsGeneration','absent'),dnssecPut('publication.publicParentDsGeneration','absent'),dnssecPut('publication.parentDsKeys',[]),dnssecPut('publication.parentAccepted',true),dnssecPut('publication.parentPublished',true),dnssecPut('publication.automationSuspended',state.automationSuspended)]});
  c.observe('validated-in-band-delete-keeps-automation','Validated in-band DELETE is distinct from manual full removal',{state,authentication:check,independentCurrentChain:newChain.map(item=>item.rrset.id)},[dnssecPut('publication.childIntent',{CDS:['0 0 0 00'],CDNSKEY:['0 3 0 AA==']})],deletion.allRefs);
  return c.finish({securityStatus:check.authenticated?'secure':'bogus',reasonCode:'manual-and-automatic-channel-state-distinguished'});
}
function dnssecParentReportRetryCase(){
  const c=dnssecParentContext(17,'report-and-retry'),{a}=c,links=c.childLinks();c.chainBundles(links,'report-current-chain');dnssecParentRemoteDs(c,{initial:true});
  const pairs=dnssecParentAddresses.map(()=>dnssecParentIntentPairs.overlap);pairs[3]=dnssecParentIntentPairs.old;
  const initial=dnssecParentReadSignals(c,{pairs,links,tag:'conflicting'}),check=dnssecParentCheckSignals(c,initial,{links,boundary:'detect-reportable-conflict'}),contacts=[{recipient:'child-DNS-operator',channel:'configured-report-channel',condition:'signal-inconsistent'},{recipient:'technical-contact',channel:'configured-email',condition:'signal-inconsistent'}];
  if(check.accepted)throw new TypeError('Conflicting concrete address signals unexpectedly accepted');
  const report=dnssecParentReport(c,'initial-signal-conflict',contacts);
  c.observe('cancel-and-report-inconsistency','Cancel the inconsistent request, preserve DS and retain manual recovery',{report:report.entries,registrantNotification:'defer unless persistent3days'},[dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false),dnssecPut('publication.registrantNotification','defer unless persistent3days'),dnssecPut('publication.manualRecoveryChannelAvailable',true),dnssecPut('timers.retryStartedAt',a.clock),dnssecPut('timers.retryAt',a.clock+300),dnssecPut('timers.persistentReportAt',a.clock+3*86400)],[report.ref]);
  a.advanceTo(DNSSEC_BASE_CLOCK+300,'report-retry-time');
  const registrarClient=dnssecParentLockPolicy({automationActor:'registrar',clientUpdateProhibited:true}),registryClient=dnssecParentLockPolicy({automationActor:'registry',clientUpdateProhibited:true}),registrarServer=dnssecParentLockPolicy({automationActor:'registrar',serverUpdateProhibited:true}),registryServer=dnssecParentLockPolicy({automationActor:'registry',serverUpdateProhibited:true}),transferDelete=dnssecParentLockPolicy({automationActor:'registry',transferProhibited:true,deleteProhibited:true}),lockPolicy={selectedAutomationActor:'registry',clientUpdateProhibitedAlone:{registrarAutomationSuspended:registrarClient.automationSuspended,registryAutomationSuspended:registryClient.automationSuspended},serverUpdateProhibitedAlone:{registrarEppUpdateRejected:registrarServer.registrarEppUpdateRejected,registryAutomationSuspended:registryServer.automationSuspended},transferOrDeleteLockAloneSuspendsAutomation:transferDelete.automationSuspended};
  c.observe('apply-lock-scope-matrix','Distinguish registrar EPP rejection from the registry automation policy',{registrarClient,registryClient,registrarServer,registryServer,transferDelete},[dnssecPut('publication.lockPolicy',lockPolicy),dnssecPut('publication.automationSuspended',registryServer.automationSuspended)]);
  const retry=dnssecParentReadSignals(c,{links,tag:'report-retry'}),retryCheck=dnssecParentCheckSignals(c,retry,{links,boundary:'retry-consistent-and-continuous',acceptPolicy:registryServer.allowed});
  if(!retryCheck.accepted)return c.finish({securityStatus:retryCheck.authenticated?'secure':'bogus',reasonCode:retryCheck.comparison.reason,failureStage:'signal-consistency',firstDetector:'dnsParentAgent',stoppedAction:'alter-parent-ds'});
  a.advanceTo(DNSSEC_BASE_CLOCK+900,'report-retry-publication');c.publishDs('parent-ds-publication',retryCheck.comparison.keys);
  a.advanceTo(DNSSEC_BASE_CLOCK+901,'registrar-change-report-time');const changed=dnssecParentReport(c,'published-ds-change',[{recipient:'registrar',channel:'EPP-change-poll',condition:'DS-changed'}]);
  c.observe('registrar-informed-and-ttl-retained-remotely','Inform registrar while preserving independently cached old TTLs',{report:changed.entries,newDsTtl:600,oldDsTtl:86400},[dnssecPut('publication.newDsTtl',600),dnssecPut('publication.restoreNormalTtlNoEarlierThan',DNSSEC_BASE_CLOCK+900+86400),dnssecPut('publication.remoteCachesInvalidated',false)],[changed.ref]);
  return c.finish({securityStatus:retryCheck.authenticated?'secure':'bogus',reasonCode:'reported-and-retried-update-published'});
}

export const DNSSEC_PARENT_CASE_BUILDERS={
  'lab-dnssec16':{
    'consistent-update':()=>dnssecParentUpdateCase(16,'consistent-update'),
    'consistent-ds-removal':()=>dnssecParentUpdateCase(16,'consistent-ds-removal',{signal:'deletion'}),
    'one-authority-stale':()=>dnssecParentUpdateCase(16,'one-authority-stale',{lastPair:dnssecParentIntentPairs.old}),
    'cds-cdnskey-keyset-disagreement':()=>dnssecParentUpdateCase(16,'cds-cdnskey-keyset-disagreement',{cdsPair:['child-cds-newk-only','child-cdnskey-intent']}),
    'nodata-versus-removal':()=>dnssecParentUpdateCase(16,'nodata-versus-removal',{signal:'deletion',nodata:true}),
    'unreachable-authority-retry':()=>dnssecParentUpdateCase(16,'unreachable-authority-retry',{timeout:true}),
    'digest-policy-comparison':()=>dnssecParentUpdateCase(16,'digest-policy-comparison',{digest:true,lastPair:['child-cds-mixed-ds4','child-cdnskey-intent']}),
    'dsync-notify-trigger':()=>dnssecParentUpdateCase(16,'dsync-notify-trigger',{notify:'valid'}),
    'invalid-dsync-target':()=>dnssecParentUpdateCase(16,'invalid-dsync-target',{notify:'invalid'}),
    'malformed-delete-signal':()=>dnssecParentUpdateCase(16,'malformed-delete-signal',{malformed:true,cdsPair:['child-cds-malformed-delete-plus-newk','child-cdnskey-malformed-delete']}),
  },
  'lab-dnssec17':{
    'authenticated-rfc9615-bootstrap':()=>dnssecParentBootstrapCase('authenticated-rfc9615-bootstrap'),
    'unauthenticated-child-only-claim':()=>dnssecParentBootstrapCase('unauthenticated-child-only-claim',{mode:'child-only'}),
    'signaling-zone-not-secure':()=>dnssecParentBootstrapCase('signaling-zone-not-secure',{mode:'insecure'}),
    'only-in-domain-nameservers':()=>dnssecParentBootstrapCase('only-in-domain-nameservers',{mode:'in-domain'}),
    'parent-policy-declines':()=>dnssecParentBootstrapCase('parent-policy-declines',{registrarAllowsDnssecDisable:false}),
    'update-would-break-validation':()=>dnssecParentUpdateCase(17,'update-would-break-validation',{safety:true,cdsPair:['child-cds-newk-only','child-cdnskey-newk-only']}),
    'concurrent-manual-update':dnssecParentConcurrentCase,
    'report-and-retry':dnssecParentReportRetryCase,
  },
};
