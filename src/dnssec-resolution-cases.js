import {dnssecAuthor,dnssecPut} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecLookupPath,dnssecLookupSelectedPath,dnssecLookupMessage} from './dnssec-lookup.js';
import {dnssecValidateChain,dnssecCheckSignature,dnssecSignatureTime,dnssecTtlWindow} from './dnssec-validation.js';

const dnssecResolutionMaterial=(kind,id)=>dnssecMaterial(kind,id);
const dnssecResolutionSignature=id=>dnssecResolutionMaterial('signatures',id);
const dnssecResolutionRrset=id=>dnssecResolutionMaterial('rrsets',id);
const dnssecResolutionKey=id=>dnssecResolutionMaterial('keys',id);
const dnssecResolutionOwner=zone=>zone==='.'?'dnsRoot':zone==='example.'?'dnsParent':'dnsChild';
function dnssecResolutionChild(path,rrsetId,signatureId,keyIds){
  return path.map(link=>link.zone==='lab.example.'?{...link,dnskeyRrset:dnssecResolutionRrset(rrsetId),dnskeySignatures:[dnssecResolutionSignature(signatureId)],keys:keyIds.map(dnssecResolutionKey)}:link);
}

/** Concrete input records, clocks and local policy, not expected case outcomes. */
function dnssecResolutionCase(number,caseId,input={}){
  const a=dnssecAuthor(number,caseId),question={qname:'www.lab.example.',qtype:'A',qclass:'IN'};
  const path=input.path||dnssecLookupPath(),anchorKey=input.anchor===null?null:dnssecResolutionKey(input.anchor||'root-ksk-g1');
  const anchor=anchorKey?{zone:anchorKey.owner,keys:[anchorKey],provenance:'Independent out-of-band operator configuration'}:null;
  const links=dnssecLookupSelectedPath(path,anchor),view='public-v1',trustStore=input.trustStore||'resolver-public-v1';
  const now=input.now??DNSSEC_BASE_CLOCK,validatorNow=now+(input.clockOffset||0);
  const signatures=(input.signatures??['www-a-signature']).map(dnssecResolutionSignature),published=dnssecResolutionRrset('www-a');
  const rrset={...published,ttl:300,...input.records?{records:input.records}:{}};
  const evaluation=dnssecValidateChain({anchor,links,answer:{rrset,signatures},now:validatorNow,policy:a.policy});
  const leafCheck=evaluation.checks.find(check=>check.stage==='answer-signature')?.result;
  const status=evaluation.securityStatus,secure=status==='secure',accepted=status!=='bogus';
  const bundles=[],hops=[],evidenceRefs=[];
  const anchorBinding=anchor?{type:'logical-key-reference',anchorRefType:'keyId-string',keyId:anchorKey.id,owner:anchorKey.owner,scope:anchor.zone,keyTag:anchorKey.keyTag,flags:anchorKey.flags,protocol:anchorKey.protocol,algorithm:anchorKey.algorithm,publicKeyHex:anchorKey.publicKeyHex,dnskeyRdataHex:anchorKey.dnskeyRdataHex,provisioning:'explicit trusted local configuration',anchorSource:'out-of-band'}:null;
  const anchorRef=anchor?a.artifact(caseId+':anchor','Configured independent trust anchor','dnsOperator',{zone:anchor.zone,keyRef:anchorKey.id,trustStore,provenance:anchor.provenance,anchorBinding},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Configured trust anchors'}):null;
  for(const keyId of ['root-ksk-g1','root-zsk-g1','example-ksk-g1','example-zsk-g1','child-ksk-g1','child-zsk-g1']){
    a.artifact(caseId+':private:'+keyId,'Explicit signer-only capability '+keyId,'dnsSigner',{handle:'HSM('+keyId+')',keyId,custodian:'dnsSigner',capability:'sign'},{kind:'secret',privateKey:true,initial:true,holders:['dnsSigner'],store:'Signer-only key capabilities'});
  }
  Object.assign(a.initialState.dnssec,{query:question,view,trustStore,cacheNamespace:{view,trustStore},anchorRef,anchorBinding,validatorClockOffset:input.clockOffset||0,trustStores:{[trustStore]:{anchors:anchorKey?[anchorKey.id]:[],scope:anchorKey?.owner||null,provisioning:'explicit out-of-band configuration'}},cacheKind:null,stoppedAction:null});
  if(anchorRef)a.bind('anchorRef',anchorRef,'dnsValidator','Configured trust anchors');
  const unrelated=a.artifact(caseId+':unrelated-cache','Unrelated cache survives this lookup','dnsResolver',{id:'unrelated.example./A',kind:'answer',receivedAt:DNSSEC_BASE_CLOCK-20,expiresAt:DNSSEC_BASE_CLOCK+500,view,trustStore},{kind:'cache',initial:true,holders:['dnsResolver'],store:'Independent cache'});
  a.initialState.dnssec.unrelatedCache={artifactRef:unrelated,expiresAt:DNSSEC_BASE_CLOCK+500};a.bind('unrelatedCache',unrelated,'dnsResolver','Independent cache');
  const addBundle=(body,sigs,owner,stage,zone,keys=[],cached=false,section='answer')=>{
    const index=bundles.length,key=caseId+':numericBindings-'+(stage==='answer-signature'?'primary':'chain-'+index)+':'+body.id;
    const canonical=a.artifact(caseId+':published:'+index,'Published '+body.owner+' '+body.type,owner,body,{kind:'rrset',initial:true,holders:[owner],store:'Published zone'});
    const signatureRefs=sigs.map((sig,j)=>a.artifact(caseId+':signature:'+index+':'+j,'RRSIG '+sig.id,owner,sig,{kind:'rrsig',initial:true,holders:[owner],store:'Published signatures',derivedFrom:[canonical]}));
    const keyRefs=keys.map((key,j)=>a.artifact(caseId+':key:'+index+':'+j,'Public DNSKEY '+key.id,owner,key,{kind:'dnskey',initial:true,holders:[owner],store:'Published public keys',derivedFrom:[canonical]}));
    if(body.type==='DS')for(const [j,record] of body.records.entries()){
      const [keyTag,algorithm,digestType,...digest]=record.split(/\s+/);
      keyRefs.push(a.artifact(caseId+':ds:'+index+':'+j,'Exact parent DS record',owner,{owner:body.owner,keyTag:Number(keyTag),algorithm:Number(algorithm),digestType:Number(digestType),digestHex:digest.join('')},{kind:'ds',initial:true,holders:[owner],store:'Published parent DS',derivedFrom:[canonical]}));
    }
    const occurrence=a.artifact(caseId+':received:'+index,(cached?'Earlier cached ':'Received ')+body.owner+' '+body.type,owner,{...(stage==='answer-signature'?rrset:body),ttl:300},{kind:'rrset',initial:cached,holders:['dnsResolver'],store:'Earlier received cache bodies',derivedFrom:[canonical]});
    const bundle={body,sigs,owner,stage,zone,keys,cached,section,canonical,signatureRefs,keyRefs,occurrence,evidenceKey:key,evidenceId:a.id+':'+key};bundles.push(bundle);if(sigs.length||stage==='answer-signature'&&status!=='insecure')evidenceRefs.push(bundle.evidenceId);
    if(cached)for(const ref of [...signatureRefs,...keyRefs])a.inventory.initial.push(a.acquire(ref,'dnsResolver','Earlier received cache bodies'));
    return bundle;
  };
  for(const [index,link] of (anchor?links:[]).entries()){
    const cached=!!input.cachedAncestors&&index<links.length-1||!!input.cachedChild&&index===links.length-1;
    if(index&&link.dsRrset)addBundle(link.dsRrset,link.dsSignatures||[],dnssecResolutionOwner(links[index-1].zone),'parent-ds-signature',link.zone,[],!!input.cachedParent&&index===links.length-1||!!input.cachedAncestors&&index<links.length-1);
    if(index&&link.noDsProof)addBundle(link.noDsProof.rrset,link.noDsProof.signatures,dnssecResolutionOwner(links[index-1].zone),'parent-no-ds-proof',link.zone,[],false,'authority');
    if(link.dnskeyRrset&&(index===0||evaluation.checks.some(check=>check.stage==='ds-digest'&&check.zone===link.zone)))addBundle(link.dnskeyRrset,link.dnskeySignatures||[],dnssecResolutionOwner(link.zone),'dnskey-rrset-signature',link.zone,link.keys||[],cached);
  }
  const leaf=addBundle(published,signatures,'dnsChild','answer-signature',links.at(-1).zone);
  const unsupportedDsBundle=bundles.find(bundle=>bundle.stage==='parent-ds-signature'&&evaluation.checks.some(check=>check.stage==='ds-policy'&&check.zone===bundle.zone&&!check.valid));
  if(unsupportedDsBundle){const index=evidenceRefs.indexOf(unsupportedDsBundle.evidenceId);evidenceRefs.splice(index,1);evidenceRefs.push(unsupportedDsBundle.evidenceId);}
  const priorNow=input.priorReceivedAt??DNSSEC_BASE_CLOCK-60;
  const priorPath=input.priorPath||path,priorAnchor={zone:'.',keys:[dnssecResolutionKey('root-ksk-g1')]};
  const prior=dnssecValidateChain({anchor:priorAnchor,links:priorPath,answer:{rrset:published,signatures:[dnssecResolutionSignature('www-a-signature')]},now:priorNow,policy:a.policy});
  for(const bundle of bundles.filter(item=>item.cached)){
    const result=prior.checks.find(check=>check.stage===bundle.stage&&check.zone===bundle.zone)?.result;
    if(!result?.valid)throw new TypeError('Declared cache lacks authenticated earlier evidence for '+bundle.body.id);
    const selected=bundle.sigs.find(sig=>sig.id===result.selectedSignatureId);
    const window=dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,receivedAt:priorNow,now});
    const contextMatches=trustStore==='resolver-public-v1'&&anchorKey?.id==='root-ksk-g1';
    const cache={id:bundle.evidenceId+':cache',kind:bundle.body.type==='DNSKEY'?'dnskey':'chain',zone:bundle.zone,receivedAt:priorNow,expiresAt:window.expiresAt,view,trustStore:'resolver-public-v1',validated:true,securityStatus:'secure',validationOwner:'dnsValidator',evidenceRefs:[bundle.evidenceId],usableInCurrentContext:contextMatches&&window.valid};
    const cacheRef=a.artifact(caseId+':cache-prerequisite:'+bundles.indexOf(bundle),'Earlier authenticated evidence with explicit context','dnsResolver',cache,{kind:'cache',initial:true,holders:['dnsResolver'],store:'Chain cache',derivedFrom:[bundle.occurrence,...bundle.signatureRefs,...bundle.keyRefs]});
    const witness=a.artifact(bundle.evidenceKey,'Earlier reference-bound verification','dnsValidator',{rrsetId:bundle.body.id,checkedAt:priorNow,validationOwner:'dnsValidator',evidenceMode:'symbolic-reference-bound',valid:result.valid,reason:result.reason,selectedEvidence:result.selectedEvidence},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Validation evidence',derivedFrom:[bundle.occurrence,...bundle.signatureRefs]});
    bundle.witness=witness;bundle.cached=contextMatches&&window.valid;
    a.initialState.dnssec.prerequisiteCacheEntries||=[];const slot=a.initialState.dnssec.prerequisiteCacheEntries.push(cache)-1;a.bind('prerequisiteCacheEntries.'+slot,cacheRef,'dnsResolver','Chain cache');
  }
  a.chapter('request','1. Application and resolver');
  if(now>DNSSEC_BASE_CLOCK)a.advanceTo(now,'selected-clock','Advance to the selected represented observation time');
  a.local('app-request','Application requests an address under a separate trust policy','dnsApp',{values:{question,applicationPolicy:input.secureOnly?'secure-only':'accept non-bogus unverified answers'}});
  const stubId=16641,stubQuery=dnssecLookupMessage(stubId,question,{recursive:true,flags:{AD:1,CD:0}});
  a.send('stub:q','Stub requests recursive resolution','dnsStub','dnsResolver',[],stubQuery,[]);
  a.chapter('lookup','2. Retrieve exact public evidence');
  let queryIndex=0;
  const retrieve=(bundle,key)=>{
    const q=bundle.stage==='answer-signature'?question:{qname:bundle.body.owner,qtype:bundle.stage==='parent-no-ds-proof'?'DS':bundle.body.type,qclass:'IN'},qid=16642+queryIndex++;
    const query=dnssecLookupMessage(qid,q,{flags:{CD:1}}),response=dnssecLookupMessage(qid,q,{response:true,authoritative:true,flags:{CD:0,AD:0}});
    a.send(key+':q','Query '+q.qname+' '+q.qtype,'dnsResolver',bundle.owner,[],query,[dnssecPut('transport.attempted',true),dnssecPut('transport.authorityQueries',queryIndex)]);
    a.local(key+':construct','Prepare a distinct response occurrence without changing OriginalTTL',bundle.owner,{values:{receivedRrsetTtl:300,receivedRrsigTtl:300},refs:[bundle.canonical,{artifactId:bundle.occurrence,kind:'create'}],held:a.has(bundle.occurrence,'dnsResolver')?[]:a.create(bundle.occurrence,bundle.owner,'DNS response data'),kind:'derive'});
    const refs=[{artifactId:bundle.occurrence,section:bundle.section},...bundle.signatureRefs.map(artifactId=>({artifactId,section:bundle.section})),...bundle.keyRefs.map(artifactId=>({artifactId,recordCount:0}))];
    a.send(key+':r','Receive public records before local trust',bundle.owner,'dnsResolver',refs,response,[dnssecPut('transport.completed',true)]);
    hops.push({id:a.id+':'+caseId+':'+key,from:'dnsResolver',to:bundle.owner,transport:'UDP',question:query.question,query:{id:a.id+':'+caseId+':'+key+':q',messageId:qid,flags:query.flags,edns:query.edns},response:{id:a.id+':'+caseId+':'+key+':r',inReplyTo:a.id+':'+caseId+':'+key+':q',messageId:qid,flags:response.flags,rcode:'NOERROR',edns:response.edns},...(number===4&&bundle!==leaf&&!input.cachedAncestors?{bindingRef:(bundle.body.id==='child-dnskey-rollover'?'docs/dnssec-expansion/numeric/lifecycle-fixtures.json':'docs/dnssec-expansion/numeric/long-profile-fixtures.json')+'#'+bundle.body.id,signatureRef:bundle.sigs[0].id}:{}),evidenceRefs:bundle.sigs.length?[bundle.evidenceId]:[]});
  };
  const retrievalOrder=number===4?[leaf,...bundles.filter(bundle=>bundle!==leaf)]:bundles;
  for(const bundle of retrievalOrder)if(!bundle.cached)retrieve(bundle,'evidence-'+bundles.indexOf(bundle));
  if(input.refetchChild){
    const bundle=bundles.find(item=>item.stage==='dnskey-rrset-signature'&&item.zone===links.at(-1).zone);
    const occurrence=a.artifact(caseId+':refetched-child','Bounded DNSKEY refetch occurrence',bundle.owner,{...bundle.body,ttl:300},{kind:'rrset',derivedFrom:[bundle.canonical]});
    retrieve({...bundle,occurrence},'bounded-child-key-refetch');
  }
  if(input.requeryMissingDs){
    const q={qname:links.at(-1).zone,qtype:'DS',qclass:'IN'},qid=16642+queryIndex++,query=dnssecLookupMessage(qid,q,{flags:{CD:1}}),response=dnssecLookupMessage(qid,q,{response:true,authoritative:true});
    a.send('parent-ds-requery:q','Query parent again: missing DS is not authenticated absence','dnsResolver','dnsParent',[],query,[]);
    a.send('parent-ds-requery:r','Parent returns neither DS nor an absence proof','dnsParent','dnsResolver',[],response,[]);
    hops.push({id:a.id+':'+caseId+':parent-ds-requery',from:'dnsResolver',to:'dnsParent',transport:'UDP',question:query.question,query:{id:a.id+':'+caseId+':parent-ds-requery:q',messageId:qid,flags:query.flags,edns:query.edns},response:{id:a.id+':'+caseId+':parent-ds-requery:r',inReplyTo:a.id+':'+caseId+':parent-ds-requery:q',messageId:qid,flags:response.flags,rcode:'NOERROR',edns:response.edns}});
  }
  a.chapter('validation','3. Authenticate before accepting');
  a.local('raw-response-received-before-trust','Raw public answer is not a trust decision','dnsResolver',{values:{publicReadable:true,confidentialityFromDnssec:false},effects:[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked')],refs:[leaf.occurrence,...leaf.signatureRefs]});
  for(const bundle of bundles){
    if(bundle===leaf&&signatures.some(sig=>!dnssecSignatureTime(validatorNow,sig.inception,sig.expiration).valid)&&evaluation.chainEstablished){
      const prerequisiteChecks=evaluation.checks.filter(check=>check.stage!=='answer-signature'&&check.result?.selectedSignatureId),deadline=Math.min(...prerequisiteChecks.map(check=>bundles.flatMap(item=>item.sigs).find(sig=>sig.id===check.result.selectedSignatureId).expiration));
      a.local('long-upper-path-checked-before-leaf-time-failure','Authenticate fresh prerequisite evidence at the selected validator clock','dnsValidator',{values:{prerequisiteChecks},effects:[dnssecPut('clock',{now}),dnssecPut('chainEstablished',evaluation.chainEstablished),dnssecPut('validators.dnsValidator',{prerequisiteSignatureChecked:prerequisiteChecks.every(check=>check.result.checked),prerequisiteChainEstablished:evaluation.chainEstablished,prerequisiteCheckedAt:validatorNow,prerequisiteSignatureDeadline:deadline,leafTimeChecked:false})],refs:bundles.filter(item=>item!==leaf).map(item=>item.witness),kind:'verify'});
    }
    const result=evaluation.checks.find(check=>check.stage===bundle.stage&&check.zone===bundle.zone)?.result||{checked:false,valid:false,reason:'prerequisite-not-authenticated',candidates:[]};
    if(!bundle.witness){bundle.witness=a.artifact(bundle.evidenceKey,'Reference-bound exact-record evidence','dnsValidator',{rrsetId:bundle.body.id,signatureIds:bundle.sigs.map(sig=>sig.id),receivedObjectRef:bundle.occurrence,checkedAt:validatorNow,validationOwner:result.valid?'dnsValidator':null,evidenceClass:result.valid?'authenticated-evidence':result.checked||result.candidates.length?'failed-attempt':'raw-input',authenticated:!!result.valid,checkerInvoked:!!result.checked||result.candidates.length>0,observerWitness:{owner:'dnsValidator',valid:!!result.valid,reason:result.reason,authenticated:!!result.valid,evidenceRefs:[bundle.evidenceId]},evidenceMode:'symbolic-reference-bound',valid:result.valid,reason:result.reason,selectedEvidence:result.selectedEvidence||null,candidates:result.candidates},{kind:'trust',derivedFrom:[bundle.occurrence,...bundle.signatureRefs,...bundle.keyRefs,...anchorRef?[anchorRef]:[]]});
      a.local('check-evidence-'+bundles.indexOf(bundle),'Evaluate '+bundle.body.owner+' '+bundle.body.type+' under authenticated prerequisites','dnsValidator',{values:result,refs:[bundle.occurrence,...bundle.signatureRefs,...bundle.keyRefs,{artifactId:bundle.witness,kind:'create'}],held:a.create(bundle.witness,'dnsValidator','Validation evidence'),kind:'verify'});
    }
  }
  const child=links.at(-1),dsCheck=evaluation.checks.find(check=>check.stage==='parent-ds-signature'&&check.zone===child.zone),keyCheck=evaluation.checks.find(check=>check.stage==='dnskey-rrset-signature'&&check.zone===child.zone),digest=evaluation.checks.find(check=>check.stage==='ds-digest'&&check.zone===child.zone&&check.valid);
  const candidates=leafCheck?.candidates||[],candidateKey=child.keys?.find(key=>key.id===(leafCheck?.selectedKeyId||signatures[0]?.keyId)),noDs=evaluation.checks.find(check=>check.stage==='parent-no-ds-proof'),proof=child.noDsProof;
  const proofTypes=proof?.rrset.records[0].split(/\s+/).slice(1)||[];
  const eligibleKeySelected=candidates.some(item=>item.eligibility?.key===true&&item.eligibility?.algorithm===true&&item.eligibility?.signer===true&&item.eligibility?.type===true&&item.eligibility?.labels===true);
  const eligibilityFailure=!signatures.some(sig=>sig.signer===child.zone)?'signer-or-key-mismatch':!candidateKey?'no-matching-dnskey':candidateKey.protocol!==3?'protocol-not-3':!(candidateKey.flags&256)?'zone-flag-clear':null;
  const validator={
    verificationKind:'local-check',evidenceMode:'symbolic-reference-bound',checkedAt:validatorNow,candidates,
    selectedSignatureId:leafCheck?.selectedSignatureId||null,keyRef:candidateKey?.id||null,
    protocol:candidateKey?.protocol??null,flags:candidateKey?.flags??null,SEP:!!(candidateKey?.flags&1),Zone:!!(candidateKey?.flags&256),
    candidateProtocol:candidateKey?.protocol??null,candidateFlags:candidateKey?.flags??null,candidateUsable:!!leafCheck?.valid,usable:!!leafCheck?.valid,
    eligibility:candidates.map(item=>item.eligibility),mathematicalResult:leafCheck?.mathematicalResult??null,tupleAttempted:!!leafCheck?.checked,
    candidateTupleMatchAttempted:candidates.length>0,candidateTupleMatchResult:eligibilityFailure==='signer-or-key-mismatch'?'signer-or-key-mismatch':eligibilityFailure==='no-matching-dnskey'?'no-matching-key':eligibilityFailure?'candidate-ineligible':leafCheck?.mathematicalResult===true?'match':leafCheck?.mathematicalResult===false?'mismatch':'not-attempted',
    eligibleKeySelected,conceptualVerificationInvoked:eligibleKeySelected&&!!leafCheck?.checked,runtimeCryptographicOperationPerformed:false,
    knownMathematicalSignatureValid:leafCheck?.mathematicalResult??null,knownMathematicalReferenceOnly:true,
    knownMathematicalSignatureValidForReceivedRrset:leafCheck?.mathematicalResult===true,
    eligibilityFailure,signatureCheckedMeaning:'decision-path-only',
    matchingKeyPresent:!!candidateKey,matchingAuthenticatedCandidate:!!candidateKey&&signatures.some(sig=>sig.signer===child.zone),signerZoneMatches:signatures.some(sig=>sig.signer===child.zone),
    cryptographicResult:leafCheck?.mathematicalResult??null,mathematicalSignatureMatches:leafCheck?.mathematicalResult===true,rrsetCanonicalInputMatches:leafCheck?.mathematicalResult===true,
    usableSignatures:candidates.filter(item=>item.usable).length,usableValidSignatures:candidates.filter(item=>item.usable).map(item=>item.signatureId),additionalInvalidSignatures:candidates.filter(item=>!item.usable).map(item=>item.signatureId),acceptAnyValidPath:true,
    clockOffset:input.clockOffset||0,clockNow:validatorNow,timeValidAtReferenceClock:signatures.some(sig=>dnssecSignatureTime(now,sig.inception,sig.expiration).valid),timeValidAtResolverClock:signatures.some(sig=>dnssecSignatureTime(validatorNow,sig.inception,sig.expiration).valid),
  };
  for(const [index,signature] of signatures.filter(signature=>signature.rrsetId&&signature.rrsetId!==published.id).entries()){
    const original=dnssecResolutionRrset(signature.rrsetId),key=dnssecResolutionKey(signature.keyId);
    const reference=dnssecCheckSignature({rrset:original,signatures:[signature],keys:[key],now:validatorNow,policy:a.policy,expectedSigner:key.owner});
    const originalRef=a.artifact(caseId+':reference-rrset:'+index,'Original signed RRset - reference only','dnsValidator',original,{kind:'rrset',initial:true,holders:['dnsValidator'],store:'Independent public reference material'});
    const keyRef=a.artifact(caseId+':reference-key:'+index,'Original public key - reference only','dnsValidator',key,{kind:'dnskey',initial:true,holders:['dnsValidator'],store:'Independent public reference material'});
    const witness=a.artifact(caseId+':numericBindings-additional-'+index+':'+original.id,'Original signature tuple - never current answer trust','dnsValidator',{rrsetId:original.id,signatureIds:[signature.id],checkedAt:validatorNow,validationOwner:'dnsValidator',evidenceMode:'symbolic-reference-bound',valid:reference.valid,reason:reference.reason,selectedEvidence:reference.selectedEvidence,referenceOnly:true},{kind:'trust',derivedFrom:[originalRef,keyRef]});
    a.local('inspect-original-reference-'+index,'Distinguish the original signature binding from the received answer','dnsValidator',{values:{referenceOnly:true,receivedAnswerAccepted:false,originalMathematicalResult:reference.mathematicalResult},refs:[originalRef,keyRef,witness],held:a.create(witness,'dnsValidator','Reference-only evidence'),kind:'verify'});
    evidenceRefs.push(witness);
    if(!validator.signerZoneMatches&&reference.mathematicalResult===true&&original.owner!==rrset.owner)validator.knownMathematicalReferenceResult='valid-only-for-original-other-owner-rrset';
  }
  const clockObservation={now,...signatures.length?{inception:signatures[0].inception,expiration:signatures[0].expiration,validAtExactExpiration:dnssecSignatureTime(signatures[0].expiration,signatures[0].inception,signatures[0].expiration).valid,validOneSecondAfter:dnssecSignatureTime(signatures[0].expiration+1,signatures[0].inception,signatures[0].expiration).valid,validAtExactInception:dnssecSignatureTime(signatures[0].inception,signatures[0].inception,signatures[0].expiration).valid,validOneSecondBefore:dnssecSignatureTime(signatures[0].inception-1,signatures[0].inception,signatures[0].expiration).valid}:{}};
  const supportedDs=(child.dsRrset?.records||[]).filter(record=>{const fields=record.split(/\s+/);return a.policy.validationAlgorithms.includes(Number(fields[1]))&&a.policy.dsDigestTypes.includes(Number(fields[2]));}).length;
  a.local(input.boundary||(number===3?'parent-to-child-authentication':'valid-non-sep-zone-key-is-usable'),'Expose the actual selected path and signature eligibility',input.requeryMissingDs?'dnsResolver':'dnsValidator',{values:{checks:evaluation.checks,candidates,selectedSignatureId:leafCheck?.selectedSignatureId||null,clock:validatorNow},effects:[dnssecPut('clock',clockObservation),dnssecPut('chainEstablished',evaluation.chainEstablished),dnssecPut('securityStatus',status),dnssecPut('denialChecked',!!noDs?.valid),dnssecPut('transport.parentDsQueries',input.requeryMissingDs?1:0),dnssecPut('publication',{dsPublisher:links.length>1?links.at(-2).zone:null,dsAuthenticated:!!dsCheck?.valid,matchingChildKey:digest?.result.keyId||null,dsDigestMatches:!!digest,childDnskeyAccepted:!!keyCheck?.valid,dnskeyRrsetAuthenticated:!!keyCheck?.valid,parentNsecAuthenticated:!!noDs?.valid,NS:proofTypes.includes('NS'),DS:proofTypes.includes('DS'),SOA:proofTypes.includes('SOA'),absenceInPacketIsNotProof:!child.dsRrset&&!proof,noDsProved:!!noDs?.valid}),dnssecPut('algorithmPolicy',{...a.policy,supportedAlgorithms:a.policy.validationAlgorithms,supportedDigests:a.policy.dsDigestTypes,supportedAuthenticatedDsRemaining:dsCheck?.valid?supportedDs:null}),dnssecPut('validators.dnsValidator',validator)],refs:[leaf.occurrence,...leaf.signatureRefs],kind:'verify'});
  const observerWitness=!anchor?{owner:'dnsValidator',valid:false,reason:'prerequisite-not-authenticated',authenticated:false,evidenceRefs}:null;
  a.local('local-verification-bound-to-evidence','Bind the decision to the exact records and current trust store','dnsValidator',{values:{referenceBound:true,notBrowserCryptography:true},effects:[dnssecPut('signatureChecked',leafCheck?signatures.length>0:evaluation.signatureChecked),dnssecPut('signatureCheckKind',eligibilityFailure?'candidate-eligibility-only':'reference-bound-verification'),dnssecPut('runtimeCryptographicOperationPerformed',false),dnssecPut('knownMathematicalReferenceOnly',true),dnssecPut('mathematicalReferenceResultRef',a.id+':'+caseId+':'+(input.boundary||(number===3?'parent-to-child-authentication':'valid-non-sep-zone-key-is-usable'))),dnssecPut('chainEstablished',evaluation.chainEstablished),dnssecPut('chainTarget',child.zone+' DNSKEY RRset'),dnssecPut('chainEstablishedSemantics','authenticated path to target zone DNSKEY RRset; not leaf signature key availability'),dnssecPut('leafSignatureKeyAvailable',!!candidateKey),dnssecPut('missingRrsigKey',signatures.length&&!candidateKey?signatures[0].keyId:null),dnssecPut('denialChecked',evaluation.checks.some(check=>check.stage==='parent-no-ds-proof'&&check.valid)),dnssecPut('validationOwner',anchor?'dnsValidator':null),...observerWitness?[dnssecPut('observerWitness',observerWitness)]:[],dnssecPut('verificationKind',anchor?'local-check':'not-performed'),dnssecPut('evidenceRefs',evidenceRefs),dnssecPut('checkedAt',validatorNow)],refs:evidenceRefs});
  const failed=status==='bogus';
  let reason=evaluation.reasonCode;
  if(secure)reason=anchor.zone!=='.'?'independently-provisioned-child-anchor':candidates.some(item=>!item.usable)?'one-usable-valid-signature-is-sufficient':number===3?'authenticated-parent-ds-and-child-key':'usable-signature-over-exact-rrset';
  else if(!anchor)reason='no-applicable-trust-anchor-anywhere';
  else if(noDs?.valid)reason='authenticated-parent-proves-unsigned-delegation';
  else if(dsCheck?.valid&&!supportedDs)reason='authenticated-ds-has-no-supported-algorithm-or-digest-path';
  else if(dsCheck?.valid&&!digest&&!keyCheck)reason='authenticated-supported-ds-has-no-matching-child-key';
  else if(input.requeryMissingDs&&!child.dsRrset&&!proof)reason='missing-authenticated-delegation-proof-after-parent-requery';
  else if(leafCheck){
    if(input.clockOffset&&validator.timeValidAtReferenceClock&&!validator.timeValidAtResolverClock)reason='resolver-clock-skew-causes-time-validation-failure';
    else if(candidates.some(item=>item.time?.reason==='expired'))reason='rrsig-expired-at-resolver-clock';
    else if(candidates.some(item=>item.time?.reason==='not-yet-valid'))reason='rrsig-inception-after-resolver-clock';
    else if(!signatures.length)reason='secure-delegation-answer-missing-required-rrsig';
    else if(!validator.signerZoneMatches)reason='rrsig-signer-or-key-does-not-match-authoritative-zone';
    else if(!candidateKey)reason='required-matching-dnskey-absent-after-refetch';
    else if(candidateKey.protocol!==3)reason='dnskey-protocol-field-invalid-for-verification';
    else if(!(candidateKey.flags&256))reason='dnskey-without-zone-flag-cannot-verify-rrset';
    else if(leafCheck.mathematicalResult===false)reason='canonical-rrset-differs-from-signed-input';
  }
  a.local('classification-with-independent-failure-context','Classify DNSSEC independently of application policy','dnsValidator',{values:{status,reason},effects:[dnssecPut('securityStatus',status),dnssecPut('reasonCode',reason),dnssecPut('failureStage',failed?'validation':null),dnssecPut('firstDetector',failed?'dnsValidator':null),dnssecPut('stoppedAction',failed?'trusted-positive-answer':null)]});
  const selected=signatures.find(sig=>sig.id===leafCheck?.selectedSignatureId),window=selected?dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,now:validatorNow,receivedAt:validatorNow}):{remainingSeconds:300,expiresAt:now+300,limits:{receivedTtl:300}};
  const checkingContext='CD'+stubQuery.flags.CD,cacheEntry={id:a.id+':cache-'+caseId,kind:accepted?'answer':'failure',key:[view,trustStore,question.qname,question.qtype,question.qclass,...failed?[checkingContext]:[]],...failed?{checkingContext}:{},receivedAt:validatorNow,expiresAt:accepted?validatorNow+window.remainingSeconds:validatorNow+5,signatureDeadline:secure?selected.expiration:null,securityStatus:status,validationOwner:anchor?'dnsValidator':null,...observerWitness?{observerWitness,evidenceClass:'raw-input-only'}:{},evidenceRefs};
  const cacheRef=a.artifact(caseId+':result-cache','Bounded lookup cache entry','dnsResolver',cacheEntry,{kind:'cache',derivedFrom:[leaf.occurrence,...evidenceRefs]});
  a.local('accepted-use-and-cache-boundary','Accept non-bogus data or withhold a bogus answer','dnsResolver',{values:{acceptedForUse:accepted,cacheLimits:window.limits},effects:[dnssecPut('acceptedForUse',accepted),dnssecPut('cached',true),dnssecPut('cacheKind',cacheEntry.kind),dnssecPut('cacheEntries',[cacheEntry]),dnssecPut('resultCacheArtifact',cacheRef)],refs:[cacheRef],held:a.create(cacheRef,'dnsResolver','Answer cache'),kind:'store'});a.bind('resultCacheArtifact',cacheRef,'dnsResolver','Answer cache');
  a.chapter('result','4. Return and apply application policy');
  let returned=leaf.occurrence;
  if(accepted&&window.remainingSeconds!==300){returned=a.artifact(caseId+':returned-answer','Returned representation bounded by selected usable signature','dnsResolver',{...rrset,ttl:window.remainingSeconds},{kind:'rrset',derivedFrom:[leaf.occurrence,cacheRef]});a.local('bound-returned-answer-ttl','Bound returned TTL without changing signed metadata','dnsResolver',{values:{remainingTtl:window.remainingSeconds,originalTtl:selected?.originalTtl},refs:[leaf.occurrence,returned],held:a.create(returned,'dnsResolver','DNS response data'),kind:'derive'});}
  const rcode=accepted?'NOERROR':'SERVFAIL',ede=input.diagnostics&&failed?{present:true,code:validator.timeValidAtResolverClock===false&&signatures.length&&candidates.some(item=>item.time?.reason==='expired')?7:candidates.some(item=>item.time?.reason==='not-yet-valid')?8:!signatures.length?10:!candidateKey?9:6,textPolicy:input.diagnosticText||'selected, optional'}:{present:false},response={...dnssecLookupMessage(stubId,question,{response:true,recursive:true,rcode,flags:{AD:secure?1:0,CD:0}}),ede};
  if(ede.present)response.edns={...response.edns,ede:{infoCode:ede.code,extraText:''}};
  hops.push({id:a.id+':stub',from:'dnsStub',to:'dnsResolver',transport:'UDP',question:stubQuery.question,query:{id:a.id+':stub:q',messageId:stubId,flags:stubQuery.flags,edns:stubQuery.edns},response:{id:a.id+':stub:r',inReplyTo:a.id+':stub:q',messageId:stubId,flags:response.flags,rcode,edns:response.edns}});
  a.send('stub:r','Return '+rcode+' without implying application use','dnsResolver','dnsStub',accepted?[returned,...leaf.signatureRefs]:[],response,[dnssecPut('returnedToStub',true),dnssecPut('response',{rcode,ede,flags:response.flags,hops})]);
  a.local('stub-receives-response-before-application-use','Stub receipt precedes application use','dnsStub',{values:{rcode,applicationUseStillPending:true}});
  const appAccept=accepted&&(!input.secureOnly||secure),applicationResult=appAccept?{status:'answer',qname:question.qname,addresses:rrset.records,trust:status}:input.secureOnly&&accepted?{status:'refused',policy:'secure-only',reason:status+'-not-bogus',positiveAnswerAccepted:false}:{status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false};
  const app=a.artifact(caseId+':application-result','Application policy result','dnsApp',applicationResult,{kind:'event',derivedFrom:appAccept?[returned]:[]});
  a.local('application-result-boundary','Apply the independent application acceptance policy','dnsApp',{values:applicationResult,effects:[dnssecPut('applicationResult',applicationResult),dnssecPut('applicationResultArtifact',app)],refs:[app],held:a.create(app,'dnsApp','Application result'),kind:'derive'});a.bind('applicationResultArtifact',app,'dnsApp','Application result');
  return a.finish({dnssecNumericBindings:{answer:{rrsetId:published.id,signatureIds:signatures.map(sig=>sig.id)},chain:bundles.filter(bundle=>bundle!==leaf).map(bundle=>({rrsetId:bundle.body.id,signatureIds:bundle.sigs.map(sig=>sig.id)}))}});
}

const dnssecResolutionCached={cachedAncestors:true,cachedParent:true,cachedChild:true};
const dnssecResolutionParentCached={cachedAncestors:true};
export const DNSSEC_RESOLUTION_CASE_BUILDERS={
  'lab-dnssec03':{
    'signed-child':()=>dnssecResolutionCase(3,'signed-child',dnssecResolutionParentCached),
    'proved-no-ds':()=>{const path=dnssecLookupPath();path[2]={zone:'lab.example.',noDsProof:{zone:'example.',delegation:'lab.example.',rrset:dnssecResolutionRrset('denial-parent-unsigned-lab'),signatures:[dnssecResolutionSignature('denial-parent-unsigned-lab-signature')]}};return dnssecResolutionCase(3,'proved-no-ds',{...dnssecResolutionParentCached,path,signatures:[],secureOnly:true,boundary:'signed-parent-no-ds-is-positive-evidence'});},
    'supported-ds-mismatch':()=>dnssecResolutionCase(3,'supported-ds-mismatch',{...dnssecResolutionParentCached,path:dnssecResolutionChild(dnssecLookupPath(),'child-dnskey-g2-final','child-dnskey-g2-final-long',['child-ksk-g2','child-zsk-g2']),signatures:['www-a-complete-path-g2'],boundary:'supported-path-fails-before-child-key-acceptance'}),
    'missing-ds-proof':()=>{const path=dnssecLookupPath();delete path[2].dsRrset;delete path[2].dsSignatures;delete path[2].ds;return dnssecResolutionCase(3,'missing-ds-proof',{...dnssecResolutionParentCached,path,requeryMissingDs:true,boundary:'mandatory-parent-ds-requery'});},
    'no-covering-anchor':()=>dnssecResolutionCase(3,'no-covering-anchor',{anchor:null,trustStore:'empty-v1',boundary:'empty-trust-store-not-proved-insecure'}),
    'signed-island-with-local-anchor':()=>dnssecResolutionCase(3,'signed-island-with-local-anchor',{anchor:'child-ksk-g1',trustStore:'island-lab-v1',boundary:'island-anchor-restores-independent-path'}),
    'unsupported-only-ds':()=>{const path=dnssecLookupPath();path[2]={...path[2],dsRrset:dnssecResolutionRrset('parent-ds-unsupported-alg250'),dsSignatures:[dnssecResolutionSignature('parent-ds-unsupported-alg250-signature')]};delete path[2].ds;return dnssecResolutionCase(3,'unsupported-only-ds',{...dnssecResolutionParentCached,path,boundary:'disregard-unsupported-only-authenticated-paths'});},
  },
  'lab-dnssec04':{
    'valid':()=>dnssecResolutionCase(4,'valid',dnssecResolutionCached),
    'signature-expired':()=>dnssecResolutionCase(4,'signature-expired',{now:1792717201,diagnostics:true,diagnosticText:'selected short diagnostic; not a signed or universally required string',boundary:'expired-time-boundary'}),
    'signature-not-yet-valid':()=>dnssecResolutionCase(4,'signature-not-yet-valid',{path:dnssecResolutionChild(dnssecLookupPath(),'child-dnskey-rollover','child-dnskey-rollover-old-long',['child-ksk-g1','child-zsk-g1','child-ksk-g2','child-zsk-g2']),signatures:['www-a-successor-long'],diagnostics:true,boundary:'not-yet-valid-boundary'}),
    'wrong-clock':()=>dnssecResolutionCase(4,'wrong-clock',{clockOffset:3601,diagnostics:true,diagnosticText:'selected, optional; does not prove attack or actual signature age',boundary:'resolver-not-signer-clock-is-wrong'}),
    'missing-dnskey':()=>dnssecResolutionCase(4,'missing-dnskey',{...dnssecResolutionCached,path:dnssecResolutionChild(dnssecLookupPath(),'child-dnskey-zsk-missing','child-dnskey-zsk-missing-signature',['child-ksk-g1']),priorReceivedAt:DNSSEC_BASE_CLOCK-1,refetchChild:true,diagnostics:true,boundary:'missing-key-is-not-unsigned-proof'}),
    'missing-rrsig':()=>dnssecResolutionCase(4,'missing-rrsig',{...dnssecResolutionCached,signatures:[],diagnostics:true,boundary:'missing-signature-cannot-downgrade'}),
    'wrong-signer-or-key':()=>dnssecResolutionCase(4,'wrong-signer-or-key',{...dnssecResolutionCached,signatures:['other-www-a-signature'],boundary:'signer-and-candidate-identity-check'}),
    'wrong-covered-data':()=>dnssecResolutionCase(4,'wrong-covered-data',{...dnssecResolutionCached,records:['192.0.2.82','192.0.2.81'],boundary:'canonical-data-cryptographic-failure'}),
    'one-valid-plus-one-invalid-signature':()=>dnssecResolutionCase(4,'one-valid-plus-one-invalid-signature',{...dnssecResolutionCached,signatures:['www-a-signature','wildcard-a-signature'],boundary:'additional-unusable-signature-does-not-veto-valid-path'}),
    'dnskey-protocol-not-three':()=>dnssecResolutionCase(4,'dnskey-protocol-not-three',{...dnssecResolutionCached,path:dnssecResolutionChild(dnssecLookupPath(),'child-zsk-protocol2-dnskey','child-zsk-protocol2-dnskey-signature',['child-ksk-g1','child-zsk-protocol2']),priorReceivedAt:DNSSEC_BASE_CLOCK-1,signatures:['child-zsk-protocol2-leaf-signature'],boundary:'protocol-invalid-key-cannot-verify'}),
    'zone-key-flag-clear':()=>dnssecResolutionCase(4,'zone-key-flag-clear',{...dnssecResolutionCached,path:dnssecResolutionChild(dnssecLookupPath(),'child-zsk-zoneflag-clear-dnskey','child-zsk-zoneflag-clear-dnskey-signature',['child-ksk-g1','child-zsk-zoneflag-clear']),priorReceivedAt:DNSSEC_BASE_CLOCK-1,signatures:['child-zsk-zoneflag-clear-leaf-signature'],boundary:'sep-does-not-repair-clear-zone-flag'}),
  },
};
