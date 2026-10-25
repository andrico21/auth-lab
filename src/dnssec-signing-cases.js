import {dnssecAuthor,dnssecPut,dnssecAppend} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecCanonicalInput,dnssecCheckSignature,dnssecSignatureTime,dnssecTtlWindow,dnssecDsMatchesKey} from './dnssec-validation.js';
import {dnssecLookupCase,dnssecLookupMessage} from './dnssec-lookup.js';
import {dnssecCheckDenial} from './dnssec-denial.js';
import {dnssecPublicationBundle,dnssecPublicationDs,dnssecPublicationPath,dnssecPublicationValidate,dnssecPublicationWindow,dnssecPublicationReadyAt,dnssecPublicationDecodeMxPacket,dnssecPublicationSignalIntent,dnssecPublicationCanonicalParts,dnssecPublicationCanonicalRdatas,dnssecPublicationApplicationRecords,dnssecPublicationPolicyDetails} from './dnssec-publication.js';

const dnssecSigningOldKeys=['child-ksk-g1','child-zsk-g1'];
const dnssecSigningZskOverlap=['child-ksk-g1','child-zsk-g1','child-zsk-g2'];
const dnssecSigningKskOverlap=['child-ksk-g1','child-ksk-g2','child-zsk-g1'];
const dnssecSigningProviderKeys=['child-ksk-g1','child-zsk-g1','provider-b-zsk-g1'];
const dnssecSigningProviderBKeys=['provider-b-ksk-g1','child-zsk-g1','provider-b-zsk-g1'];
const dnssecSigningOrdinaryCustody={dnsSigner:['child-ksk-g1','child-ksk-g2','child-zsk-g1','child-zsk-g2','child-csk-g1','child-csk-g2'],dnsRoot:['root-ksk-g1','root-zsk-g1'],dnsParent:['example-ksk-g1','example-zsk-g1']};
const dnssecSigningTuple=(ids,keys=[])=>dnssecPublicationBundle(Array.isArray(ids)?ids:[ids],keys);
const dnssecSigningOldChild=()=>dnssecSigningTuple('child-dnskey-g1-path-long',dnssecSigningOldKeys);
const dnssecSigningOldDs=()=>dnssecSigningTuple('example-child-ds-rollover-long');
const dnssecSigningOldAnswer=()=>dnssecSigningTuple('www-a-rollover-old-long');
const dnssecSigningNewAnswer=()=>dnssecSigningTuple('www-a-rollover-new-long');
const dnssecSigningZskFinal=()=>dnssecSigningTuple('child-dnskey-zsk-only-final-long-signature',['child-ksk-g1','child-zsk-g2']);
const dnssecSigningKskFinal=()=>dnssecSigningTuple('child-dnskey-ksk-only-final-long-signature',['child-ksk-g2','child-zsk-g1']);
const dnssecSigningKskBoth=()=>dnssecSigningTuple(['child-dnskey-ksk-overlap3-by-child-ksk-g1-long','child-dnskey-ksk-overlap3-by-child-ksk-g2-long'],dnssecSigningKskOverlap);
const dnssecSigningNewDs=()=>dnssecSigningTuple('example-child-ds-g2-long');

function dnssecSigningClassify({evaluated,secure,status,answer,child,delegation,policy,cachedAnswer,answerSource,mutation,denialResult}){
  if(secure)return {reason:'valid-path',stage:null,stopped:null};
  if(status==='insecure'){
    const ds=dnssecPublicationDs(delegation.rrset),supportedAlgorithm=ds.some(record=>policy.validationAlgorithms.includes(record.algorithm));
    return {reason:!supportedAlgorithm?(ds.every(record=>[5,7].includes(record.algorithm))?'operator-unsupported-sha1-signature':'authenticated-unsupported-signing-algorithm'):'authenticated-unsupported-ds-digest',stage:null,stopped:null};
  }
  if(denialResult&&!denialResult.valid)return {reason:denialResult.reason,stage:'denial-verification',stopped:'accept-negative-answer'};
  if(evaluated.reasonCode==='no-matching-supported-ds-key')return {reason:'supported-ds-no-matching-key',stage:'ds-dnskey-binding',stopped:'accept-child-dnskey'};
  const leaf=evaluated.checks.find(check=>check.stage==='answer-signature')?.result;
  if(leaf?.candidates.some(candidate=>candidate.time?.reason==='expired'))return {reason:'signature-expired',stage:'signature-time',stopped:'accept-expired-answer'};
  const available=answer.signatures.some(signature=>child.keys.some(key=>key.algorithm===signature.algorithm&&key.keyTag===signature.keyTag));
  if(!available){
    if(cachedAnswer)return {reason:'cached-signature-key-unavailable',stage:'key-selection',stopped:'accept-old-answer'};
    if(answerSource==='dnsSecondary')return {reason:'lagged-signature-key-unavailable',stage:'key-selection',stopped:'accept-secondary-old-answer'};
    if(answerSource==='dnsProviderB')return {reason:'cross-provider-key-unavailable',stage:'answer-key-selection',stopped:'accept-provider-b-answer'};
  }
  if(mutation&&leaf?.mathematicalResult===false)return {reason:'signature-mismatch',stage:'rrsig-verification',stopped:mutation.owner&&mutation.owner.toLowerCase()!==dnssecMaterial('rrsets',answer.signatures[0].rrsetId).owner.toLowerCase()?'accept-rebound-owner':answer.rrset.type==='TXT'?'accept-mutated-txt':'accept-mutated-a'};
  return {reason:evaluated.reasonCode,stage:'signature-or-chain',stopped:'accept-cache-use'};
}
/** Source operations share the existing author/reducer; this is only publication domain orchestration. */
function dnssecSigningSession(number,caseId,{profileId='modern',custody=dnssecSigningOrdinaryCustody,child=dnssecSigningOldChild(),delegation=dnssecSigningOldDs(),answer=dnssecSigningOldAnswer(),provider='dnsChild',validator='dnsValidator',initialChildGeneration='g0',multiSignerModel=null,actorOverrides={}}={}){
  // DNS14 declares alg13/15 publisher generation independently of operator validation and digest compatibility.
  const a=dnssecAuthor(number,caseId,{profileId,publisherSigningAlgorithms:number===14?[13,15]:undefined,actorOverrides:{dnsChild:{position:{x:975,y:610}},dnsPrimary:{name:'Provider A / authoritative signer',position:{x:975,y:610}},dnsSecondary:{position:{x:560,y:610}},dnsProviderB:{name:'Provider B / authoritative signer',position:{x:560,y:610}},...actorOverrides}});
  const handles=new Map(),objects=new Map(),bundles=new Map(),cache=new Map(),timers={},aliases={},generations=new Map(),providerSets=new Map();let occurrence=0,messageId=24576;
  let currentChild=child,currentDs=delegation,currentAnswer=answer,currentProvider=provider,currentGeneration=initialChildGeneration;
  const tupleId=bundle=>bundle.signatures.map(signature=>signature.id).join('|'),remember=(bundle,generation)=>{generations.set(tupleId(bundle),generation);return bundle;};
  remember(child,initialChildGeneration);remember(answer,initialChildGeneration);remember(delegation,'ds0');providerSets.set(provider,{child,answer,generation:initialChildGeneration});
  const ownerFor=keyId=>{const owners=Object.entries(custody).filter(([,ids])=>ids.includes(keyId)).map(([owner])=>owner);if(owners.length!==1)throw new TypeError('Private capability must have exactly one explicit custodian: '+keyId);return owners[0];};
  for(const [owner,ids] of Object.entries(custody))for(const keyId of ids){dnssecMaterial('keys',keyId);handles.set(keyId,a.artifact('signer-capability-'+keyId,'Opaque signer capability / '+keyId,owner,{handle:'HSM('+keyId+')',keyId,custodian:owner,capability:'sign'},{kind:'secret',initial:true,privateKey:true,store:'Signer-only capabilities'}));}
  const delegationIdentities=bundle=>dnssecPublicationDs(bundle.rrset).flatMap(ds=>Object.values(custody).flat().map(id=>dnssecMaterial('keys',id)).filter(key=>dnssecDsMatchesKey(ds,key,a.policy).valid).map(key=>key.id));
  const object=(kind,value,holder,{fresh=false}={})=>{
    const identity=kind+':'+value.id;if(objects.has(identity))return objects.get(identity);
    const creator=kind==='rrsig'?ownerFor(value.keyId):holder;
    const ref=a.artifact('material-'+kind+'-'+value.id,kind.toUpperCase()+' / '+value.id,creator,value,{kind,initial:!fresh,holders:[holder],store:fresh?'Signing input':'Published public records'});objects.set(identity,ref);return ref;
  };
  const ensure=(bundle,holder,{fresh=false}={})=>{
    const key=bundle.signatures.map(signature=>signature.id).join('|');
    if(!bundles.has(key))bundles.set(key,{bundle,rr:object('rrset',bundle.rrset,holder),signatures:bundle.signatures.map(signature=>object('rrsig',signature,holder,{fresh})),keys:bundle.keys.map(key=>object('dnskey',key,holder))});
    const result=bundles.get(key);
    for(const ref of [result.rr,...result.signatures,...result.keys])if(!a.has(ref,holder)){
      const source=a.actorIds.find(actor=>a.has(ref,actor));
      if(source)a.publish('coordinate-public-'+ ++occurrence,'Coordinate this exact public representation without copying private capabilities',source,holder,[ref]);
      else if(!fresh)throw new TypeError('Uncreated signature cannot be published or received');
    }
    return result;
  };
  const refs=bundle=>{const item=bundles.get(tupleId(bundle))||ensure(bundle,ownerFor(bundle.signatures[0].keyId));return [item.rr,...item.signatures,...item.keys];};
  const privateKeysCopied=()=>[...handles.entries()].some(([keyId,ref])=>a.actorIds.some(actor=>actor!==ownerFor(keyId)&&a.has(ref,actor)));
  const providerMetadata=()=>({...(multiSignerModel?{multiSignerModel,privateKeysCopied:privateKeysCopied(),...multiSignerModel===1?{commonDnskeys:currentChild.keys.map(key=>key.id)}:{providers:Object.fromEntries([...providerSets].filter(([actor])=>['dnsPrimary','dnsProviderB'].includes(actor)).map(([actor,state])=>[actor==='dnsPrimary'?'A':'B',{dnskeys:state.child.keys.map(key=>key.id),dnskeySignatures:state.child.signatures.map(signature=>signature.keyId)}]))}}:{})});
  const publicState=(bundle,generation,ordinary=currentAnswer)=>({childGeneration:generation,dnskeys:bundle.keys.map(key=>key.id),dnskeySignatures:bundle.signatures.map(signature=>signature.keyId),dnskeyAlgorithms:[...new Set(bundle.keys.map(key=>key.algorithm))],dnskeySignatureAlgorithms:[...new Set(bundle.signatures.map(signature=>signature.algorithm))],answerSignatures:ordinary.signatures.map(signature=>signature.keyId),rrsetSignatureAlgorithms:[...new Set(ordinary.signatures.map(signature=>signature.algorithm))]});
  ensure(child,provider);ensure(delegation,'dnsParent');ensure(answer,provider);
  const rootPath=dnssecPublicationPath(child,delegation);
  const root=dnssecSigningTuple('root-dnskey-path-long',['root-ksk-g1','root-zsk-g1']),parentDs=dnssecSigningTuple('root-example-ds-path-long'),parent=dnssecSigningTuple('example-dnskey-path-long',['example-ksk-g1','example-zsk-g1']);
  ensure(root,'dnsRoot');ensure(parentDs,'dnsRoot');ensure(parent,'dnsParent');
  const anchor=a.artifact('root-anchor','Explicitly provisioned root trust anchor','dnsOperator',{zone:'.',keyRef:'root-ksk-g1',dnskeyRdataHex:rootPath[0].keys[0].dnskeyRdataHex,trustStore:'publication-resolver',provenance:'Out-of-band operator configuration'},{kind:'trust',initial:true,holders:[validator],store:'Configured trust anchors'});
  const unrelated=a.artifact('unrelated-cache','Unrelated previously accepted cache entry','dnsResolver',{id:'unrelated.example./A',kind:'positive',receivedAt:DNSSEC_BASE_CLOCK-30,expiresAt:DNSSEC_BASE_CLOCK+1000000,provenance:{view:'synthetic-public',trustStore:'publication-resolver',validationOwner:'dnsValidator'}},{kind:'cache',initial:true,store:'Independent cache'});
  Object.assign(a.initialState.dnssec,{anchorRef:anchor,view:'synthetic-public',trustStore:'publication-resolver',trustStores:{'publication-resolver':{anchors:['root-ksk-g1'],validationOwner:validator,provenance:'Explicit out-of-band root provisioning'}},cacheEntries:{},cacheHistory:{},managementHops:[],publication:{...publicState(child,initialChildGeneration),publishedChildGeneration:initialChildGeneration,publishedState:publicState(child,initialChildGeneration),parentDsGeneration:'ds0',parentDsKeys:delegationIdentities(delegation),privateKeysPublished:privateKeysCopied()},unrelatedCache:{artifactRef:unrelated},stoppedAction:null});
  a.bind('anchorRef',anchor,validator,'Configured trust anchors');a.bind('unrelatedCache',unrelated,'dnsResolver','Independent cache');
  const at=offset=>{if(a.clock<DNSSEC_BASE_CLOCK+offset)a.advanceTo(DNSSEC_BASE_CLOCK+offset,'time-'+offset,'Advance the explicit publication/cache clock');};
  const observe=(boundary,title,actor,values={},effects=[],recordRefs=[])=>a.local(boundary,title,actor,{values:{now:a.clock,...values},effects,refs:recordRefs});
  const sign=(boundary,bundle)=>{
    const item=ensure(bundle,ownerFor(bundle.signatures[0].keyId),{fresh:true});
    for(const [index,signature] of bundle.signatures.entries()){
      const custodian=ownerFor(signature.keyId),handle=handles.get(signature.keyId);if(!handle||!a.has(handle,custodian))throw new TypeError('Signer has no private capability');
      if(!a.policy.signingAlgorithms.includes(signature.algorithm))throw new TypeError('Signing algorithm prohibited by publisher policy');
      const proof=dnssecCheckSignature({rrset:bundle.rrset,signatures:[signature],keys:[dnssecMaterial('keys',signature.keyId)],now:a.clock,policy:a.policy,expectedSigner:signature.signer});
      if(!proof.valid)throw new TypeError('Signing tuple does not match exact independently verified input: '+signature.id);
      const ref=item.signatures[index],isNew=!a.has(ref,custodian),held=isNew?a.create(ref,custodian,'Signing output'):[],parts=dnssecPublicationCanonicalParts(bundle.rrset,signature);
      a.local(boundary+(bundle.signatures.length>1?'-'+index:''),'Use only '+custodian+' private capability to sign '+bundle.rrset.type,custodian,{values:{canonicalInputHex:dnssecCanonicalInput(bundle.rrset,signature),...parts,signatureOctetsExcluded:parts.signatureOctetsExcludedFromInput,privateKeyPublished:privateKeysCopied(),result:proof,reusedExactOutput:!isNew},effects:[dnssecPut('publication.pending'+(bundle.rrset.type==='DNSKEY'?'Dnskey':'Answer')+'Signatures',bundle.signatures.map(value=>value.keyId))],refs:[handle,item.rr,...item.keys,{artifactId:ref,kind:isNew?'create':'inspect'}],held,kind:'create'});
    }
    return bundle;
  };
  const stageGeneration=(boundary,nextChild,nextAnswer,generation)=>{
    if(tupleId(nextChild)!==tupleId(currentChild))sign(boundary+'-dnskey',nextChild);
    if(tupleId(nextAnswer)!==tupleId(currentAnswer))sign(boundary+'-answer',nextAnswer);
    const state={...publicState(nextChild,generation,nextAnswer),createdAt:a.clock,publisher:currentProvider,published:false,rrsetIds:[nextChild.rrset.id,nextAnswer.rrset.id],signatureIds:[...nextChild.signatures,...nextAnswer.signatures].map(signature=>signature.id)};
    const artifact=a.artifact('signed-generation-'+generation,'Locally completed signed generation '+generation,ownerFor(nextAnswer.signatures[0].keyId),state,{kind:'publication',derivedFrom:[...refs(nextChild),...refs(nextAnswer)]});
    const keyChanged=JSON.stringify([...new Set(currentAnswer.signatures.map(signature=>signature.keyId))].sort())!==JSON.stringify([...new Set(nextAnswer.signatures.map(signature=>signature.keyId))].sort()),expiration=Math.max(...nextAnswer.signatures.map(signature=>signature.expiration));
    a.local(boundary,'Complete the exact locally signed generation without publishing it',ownerFor(nextAnswer.signatures[0].keyId),{values:{signedGeneration:state,publishedGenerationUnchanged:currentGeneration},effects:[...Object.entries(publicState(nextChild,generation,nextAnswer)).map(([key,value])=>dnssecPut('publication.'+key,value)),dnssecPut('publication.signedGeneration',state),dnssecPut('publication.keyChanged',keyChanged),dnssecPut('publication.rrsigExpiration',expiration)],refs:[{artifactId:artifact,kind:'create'}],held:a.create(artifact,ownerFor(nextAnswer.signatures[0].keyId),'Locally signed generations'),kind:'create'});return state;
  };
  const publishChild=(boundary,bundle,generation,{to=currentProvider,signFirst=true,from=ownerFor(bundle.signatures[0].keyId)}={})=>{
    if(signFirst)sign(boundary+'-sign',bundle);const item=ensure(bundle,from),all=[item.rr,...item.signatures,...item.keys],removedKsk=currentChild.keys.some(key=>(key.flags&1)&&!bundle.keys.some(next=>next.dnskeyRdataHex===key.dnskeyRdataHex));
    for(const ref of all)if(!a.has(ref,from))throw new TypeError('Publication source lacks exact public representation');
    currentChild=bundle;currentProvider=to;currentGeneration=generation;remember(bundle,generation);providerSets.set(to,{child:bundle,answer:currentAnswer,generation});
    const state={...publicState(bundle,generation),...providerMetadata()};
    a.publish(boundary,'Publish immutable DNSKEY generation '+generation,from,to,all,{effects:[...Object.entries(state).map(([key,value])=>dnssecPut('publication.'+key,value)),dnssecPut('publication.publishedChildGeneration',generation),dnssecPut('publication.publishedState',state),...removedKsk?[dnssecPut('publication.oldKskState','removed')]:[]]});return bundle;
  };
  const publishAnswer=(boundary,bundle,{to=currentProvider,from=ownerFor(bundle.signatures[0].keyId),signFirst=true,generation=currentGeneration,effects=[]}={})=>{
    if(signFirst)sign(boundary+'-sign',bundle);const item=ensure(bundle,from);currentAnswer=bundle;currentGeneration=generation;remember(bundle,generation);providerSets.set(to,{child:currentChild,answer:bundle,generation});
    const state={...publicState(currentChild,generation,bundle),...providerMetadata()};
    a.publish(boundary,'Publish exact answer/RRSIG generation',from,to,[item.rr,...item.signatures],{effects:[...Object.entries(state).map(([key,value])=>dnssecPut('publication.'+key,value)),dnssecPut('publication.publishedChildGeneration',generation),dnssecPut('publication.publishedState',state),...effects]});return bundle;
  };
  const replicateGeneration=(boundary,to,generation=currentGeneration)=>{
    const state=providerSets.get(currentProvider);if(!state)throw new TypeError('No concrete published source generation');
    providerSets.set(to,{...state,generation});const authorities=Object.fromEntries([...providerSets].filter(([actor])=>[currentProvider,to].includes(actor)).map(([actor,value])=>[actor==='dnsSecondary'?'198.51.100.53':'192.0.2.53',value.generation]));
    return a.publish(boundary,'Replicate the complete exact public generation',currentProvider,to,[...new Set([...refs(state.child),...refs(state.answer)])],{effects:[dnssecPut('publication.authorities',authorities)]});
  };
  const parentPublish=(boundary,bundle,generation,{ttl=bundle.rrset.ttl}={})=>{
    ensure(bundle,'dnsParent');const item=ensure(bundle,'dnsParent');
    const oldKeys=delegationIdentities(currentDs),newKeys=delegationIdentities(bundle),withdrawn=oldKeys.filter(key=>!newKeys.includes(key)),oldKeyState=currentChild.keys.some(key=>withdrawn.includes(key.id))?'retired':'removed';
    observe(boundary,'Parent publishes its separately signed delegation generation','dnsParent',{dsRrset:bundle.rrset,receivedTtl:ttl,childPublicationDoesNotFlushCache:true},[dnssecPut('publication.parentAccepted',true),dnssecPut('publication.parentPublished',true),dnssecPut('publication.parentDsGeneration',generation),dnssecPut('publication.parentDsKeys',newKeys),dnssecPut('publication.dsAlgorithms',[...new Set(dnssecPublicationDs(bundle.rrset).map(record=>record.algorithm))]),dnssecPut('publication.dsTtl',ttl),...withdrawn.length?[dnssecPut('publication.oldKskState',oldKeyState)]:[]], [item.rr,...item.signatures]);currentDs=ttl===bundle.rrset.ttl?bundle:{...bundle,rrset:{...bundle.rrset,ttl}};remember(currentDs,generation);return currentDs;
  };
  const receive=(boundary,bundle,from,{qname=bundle.rrset.owner,qtype=bundle.rrset.type,receivedTtl=bundle.rrset.ttl,to='dnsResolver',section='answer'}={})=>{
    const item=ensure(bundle,from),id=++messageId,question={qname,qtype,qclass:bundle.rrset.class},query=dnssecLookupMessage(id,question,{flags:{CD:0}}),response={...dnssecLookupMessage(id,question,{response:true,authoritative:true}),inReplyTo:a.id+':'+caseId+':'+boundary+'-query',receivedRrsetTtl:receivedTtl,receivedRrsigTtl:receivedTtl,signedOriginalTtls:bundle.signatures.map(signature=>signature.originalTtl)};
    a.send(boundary+'-query','Request '+qname+' '+qtype,to,from,[],query);
    const received=a.artifact('received-'+ ++occurrence,'Exact received occurrence / '+bundle.rrset.id,from,{...bundle.rrset,ttl:receivedTtl},{kind:'rrset',derivedFrom:[item.rr]});
    a.local(boundary+'-response','Create the received-TTL representation without altering signed metadata',from,{refs:[item.rr,{artifactId:received,kind:'create'}],held:a.create(received,from,'DNS response data'),kind:'derive'});
    const hop={id:a.id+':'+caseId+':'+boundary,from:to,to:from,transport:'UDP',question:query.question,query:{id:a.id+':'+caseId+':'+boundary+'-query',messageId:id,flags:query.flags,edns:query.edns},response:{id:a.id+':'+caseId+':'+boundary,inReplyTo:response.inReplyTo,messageId:id,flags:response.flags,rcode:response.rcode,edns:response.edns}};
    a.send(boundary,'Receive '+bundle.rrset.type+' before local trust',from,to,[{artifactId:received,section},...item.signatures.map(artifactId=>({artifactId,section})),...item.keys],response,[dnssecPut('transport.completed',true),dnssecPut('transport.attempted',true),dnssecAppend(to==='dnsParentAgent'?'managementHops':'response.hops',hop)]);
    return {bundle:{...bundle,rrset:a.object(received).value},ref:received,refs:[received,...item.signatures,...item.keys],receivedAt:a.clock,receivedTtl};
  };
  const receiveNegative=(boundary,selected,from,question)=>{
    const id=++messageId,query=dnssecLookupMessage(id,question,{flags:{CD:0}}),response={...dnssecLookupMessage(id,question,{response:true,authoritative:true}),inReplyTo:a.id+':'+caseId+':'+boundary+'-query'};
    a.send(boundary+'-query','Request the original negative-answer question','dnsResolver',from,[],query);
    const preparation=[],held=[],wire=[];
    const received=selected.map(bundle=>{
      const item=ensure(bundle,from),ref=a.artifact('received-'+ ++occurrence,'Exact negative authority occurrence / '+bundle.rrset.id,from,bundle.rrset,{kind:'rrset',derivedFrom:[item.rr]});
      preparation.push(item.rr,{artifactId:ref,kind:'create'});held.push(...a.create(ref,from,'DNS response data'));
      const objects=[ref,...item.signatures];wire.push(...objects.map(artifactId=>({artifactId,section:'authority'})));
      return {bundle,ref,refs:objects,receivedAt:a.clock,receivedTtl:bundle.rrset.ttl};
    });
    a.local(boundary+'-prepare','Prepare the complete signed NODATA authority section',from,{values:{question,proofRrsetIds:selected.map(bundle=>bundle.rrset.id)},refs:preparation,held,kind:'derive'});
    a.send(boundary,'Receive the complete proof, SOA and signatures in the original answer',from,'dnsResolver',wire,response,[dnssecPut('transport.completed',true),dnssecPut('transport.attempted',true),dnssecAppend('response.hops',{id:a.id+':'+caseId+':'+boundary,from:'dnsResolver',to:from,transport:'UDP',question:query.question,query:{id:a.id+':'+caseId+':'+boundary+'-query',messageId:id,flags:query.flags,edns:query.edns},response:{id:a.id+':'+caseId+':'+boundary,inReplyTo:response.inReplyTo,messageId:id,flags:response.flags,rcode:response.rcode,edns:response.edns}})]);
    return received;
  };
  const validate=(c=currentChild,d=currentDs,ans=currentAnswer)=>dnssecPublicationValidate({child:c,delegation:d,answer:ans,now:a.clock,policy:a.policy});
  const checkPath=(boundary,c=currentChild,d=currentDs,ans=currentAnswer,{cachedKeys=false,cachedDs=false,cachedAnswer=false,source=currentProvider}={})=>{
    for(const [index,tuple] of [root,parentDs,parent].entries())receive(boundary+'-ancestor-'+index,tuple,index<2?'dnsRoot':'dnsParent');
    if(!cachedDs)receive(boundary+'-delegation',d,'dnsParent');else cached('ds');
    if(!cachedKeys)receive(boundary+'-dnskeys',c,currentProvider);else cached('dnskeys');
    if(!cachedAnswer)receive(boundary+'-answer',ans,source);else cached('answer');
    return validate(c,d,ans);
  };
  const cacheBundle=(boundary,kind,bundle,{keys=bundle.keys,ttl=bundle.rrset.ttl,provider:source=currentProvider,sourceAddress=null}={})=>{
    for(const [index,tuple] of [root,parentDs,parent].entries())receive(boundary+'-ancestor-'+index,tuple,index<2?'dnsRoot':'dnsParent');
    if(kind!=='ds')receive(boundary+'-parent-ds',currentDs,'dnsParent');
    if(kind==='answer')receive(boundary+'-zone-keys',currentChild,currentProvider);
    const got=receive(boundary+'-receipt',bundle,kind==='ds'?'dnsParent':source),check=dnssecPublicationWindow(bundle,{now:a.clock,receivedTtl:ttl,rrsigTtl:ttl,keys,policy:a.policy});
    const path=kind==='ds'?dnssecPublicationValidate({child:currentChild,delegation:bundle,answer:currentAnswer,now:a.clock,policy:a.policy}):kind==='answer'?validate(currentChild,currentDs,bundle):validate(bundle,currentDs,currentAnswer);
    const stage=kind==='ds'?'parent-ds-signature':kind==='answer'?'answer-signature':'dnskey-rrset-signature',authenticated=path.checks.some(item=>item.zone==='lab.example.'&&item.stage===stage&&item.valid);
    if(!check.window.valid||!authenticated)throw new TypeError('Cannot declare an unauthenticated publication cache');
    const selected=bundle.signatures.find(signature=>signature.id===check.result.selectedSignatureId),generation=generations.get(tupleId(bundle));
    if(generation===undefined)throw new TypeError('Received cache generation has not been authored');
    const value={id:boundary,kind,key:['synthetic-public','publication-resolver',bundle.rrset.owner,bundle.rrset.type,bundle.rrset.class||'IN'],rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(signature=>signature.id),signatureKey:selected.keyId,signatureExpiresAt:selected.expiration,keys:kind==='ds'?delegationIdentities(bundle):bundle.keys.map(key=>key.id),provider:source==='dnsPrimary'?'A':source==='dnsProviderB'?'B':source,generation,receivedTtl:ttl,rrsigTtl:ttl,originalTtl:selected.originalTtl,receivedAt:a.clock,...check.window,securityStatus:'secure',provenance:{view:'synthetic-public',trustStore:'publication-resolver',checkingContext:'checking-CD0',validationOwner:'dnsValidator',sourceAddress,receivedObjectRef:got.ref,evidence:check.result.selectedEvidence,pathEvidence:path.selectedEvidence}};
    const artifact=a.artifact('cache-'+boundary,'Authenticated earlier '+kind+' cache','dnsResolver',value,{kind:'cache',derivedFrom:got.refs});
    a.local(boundary+'-authenticate','Authenticate the exact received '+kind+' generation','dnsValidator',{values:{result:check.result,window:check.window,pathAuthenticated:authenticated},refs:got.refs.map(artifactId=>({artifactId,kind:'verify'})),kind:'verify'});
    a.local(boundary,'Store the authenticated generation in the resolver cache','dnsResolver',{values:{generation,window:check.window,cacheKey:value.key},effects:[dnssecPut('cacheEntries.'+kind,value),dnssecPut('cacheHistory.'+boundary,artifact)],refs:[...got.refs,{artifactId:artifact,kind:'create'}],held:a.create(artifact,'dnsResolver','Publication cache'),kind:'store'});
    a.bind('cacheHistory.'+boundary,artifact,'dnsResolver','Publication cache');
    cache.set(kind,{...got,artifact,entry:value,bundle});return value;
  };
  const cached=(kind)=>{const entry=cache.get(kind);if(!entry||entry.entry.expiresAt<=a.clock)throw new TypeError('Selected cached generation is unavailable');return entry;};
  const timer=(key,value)=>{timers[key]=value;observe('timer-'+key,'Record concrete publication/cache dependencies','dnsOperator',value,[dnssecPut('timers.'+key,value)]);};
  const finishLookup=({child:chosenChild=currentChild,delegation:chosenDs=currentDs,answer:chosenAnswer=currentAnswer,answerSource=currentProvider,cachedChild=false,cachedDs=false,cachedAnswer=false,mutation=null,comparison=null,denial=null}={})=>{
    a.chapter('lookup','Retrieve the exact selected public generations');
    const question={qname:mutation?.owner||chosenAnswer.rrset.owner,qtype:denial?'AAAA':chosenAnswer.rrset.type,qclass:(denial?denial[0]:chosenAnswer).rrset.class},stubId=++messageId;
    observe('application-request','Application requests the selected DNS data','dnsApp',{question});
    a.send('stub-query','Stub requests a checking recursive lookup','dnsStub','dnsResolver',[],dnssecLookupMessage(stubId,question,{recursive:true,flags:{AD:1,CD:0}}));
    for(const [index,item] of [root,parentDs,parent].entries())receive('ancestor-'+index,item,index<2?'dnsRoot':'dnsParent');
    const dsGot=cachedDs?cached('ds'):receive('delegation',chosenDs,'dnsParent');
    const keyGot=cachedChild?cached('dnskeys'):receive('child-keyset',chosenChild,currentProvider);
    const receivedAnswer=denial?denial[0]:chosenAnswer,negativeReceipts=denial?receiveNegative('negative-answer',[...denial,dnssecSigningTuple('child-soa-signature')],answerSource,question):[];
    const answerGot=denial?negativeReceipts[0]:cachedAnswer?cached('answer'):receive('answer',receivedAnswer,answerSource,{qname:question.qname,qtype:question.qtype});
    let actualAnswer={...receivedAnswer,rrset:{...receivedAnswer.rrset,ttl:answerGot.receivedTtl??receivedAnswer.rrset.ttl,...mutation||{}}},answerRef=answerGot.ref;
    if(mutation){const changed=a.artifact('changed-received-answer','Changed public received representation','dnsAdversary',actualAnswer.rrset,{kind:'rrset',derivedFrom:[answerRef]});a.local('mutate-received-data','Change the received representation, not the frozen signed tuple','dnsAdversary',{values:{before:chosenAnswer.rrset,after:actualAnswer.rrset,unchangedSignatures:chosenAnswer.signatures.map(signature=>signature.id)},refs:[answerRef,{artifactId:changed,kind:'create'}],held:a.create(changed,'dnsAdversary','Modified public data'),kind:'derive'});a.publish('deliver-mutated-data','Deliver changed public data without signing capability','dnsAdversary','dnsResolver',[changed]);answerRef=changed;}
    observe('raw-answer-received','Receive readable records before checking and accepted use','dnsResolver',{publicReadable:true,signatureUnchanged:true},[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked')],[answerRef]);
    if(comparison){
      const signature=chosenAnswer.signatures[0],before=dnssecCanonicalInput(chosenAnswer.rrset,signature),after=dnssecCanonicalInput(actualAnswer.rrset,signature),parts=dnssecPublicationCanonicalParts(actualAnswer.rrset,signature),beforeRdata=dnssecPublicationCanonicalRdatas(chosenAnswer.rrset),afterRdata=dnssecPublicationCanonicalRdatas(actualAnswer.rrset);
      const mutationDescription=chosenAnswer.rrset.owner.toLowerCase()!==actualAnswer.rrset.owner.toLowerCase()?chosenAnswer.rrset.owner+' -> '+actualAnswer.rrset.owner:actualAnswer.rrset.type==='TXT'?'TXT '+beforeRdata.join(',')+' -> '+afterRdata.join(','):actualAnswer.rrset.type+' RDATA';
      const canonicalization={...comparison.values,canonicalInputEqual:before===after,rrsigMetadataIncluded:parts.rrsigMetadataIncluded,signatureOctetsExcludedFromInput:parts.signatureOctetsExcludedFromInput,...before!==after?{mutation:mutationDescription}:{}};
      observe(comparison.boundary,'Compare actual rebuilt canonical signing input','dnsValidator',{canonicalInputHex:after,originalCanonicalInputHex:before,...parts,...canonicalization},[dnssecPut('publication.canonicalization',canonicalization)],[answerRef,...ensure(chosenAnswer,answerSource).signatures]);
    }
    const evaluated=validate(chosenChild,chosenDs,actualAnswer),leaf=evaluated.checks.find(check=>check.stage==='answer-signature')?.result;
    for(const [index,check] of evaluated.checks.entries())if(['parent-ds-signature','dnskey-rrset-signature','answer-signature','ds-policy'].includes(check.stage))observe('check-selected-record-'+index,'Check '+check.stage+' for '+check.zone,'dnsValidator',{result:check,verificationIsNotDecryption:true},check.stage==='dnskey-rrset-signature'&&check.zone==='lab.example.'?[dnssecPut('chainEstablished',check.valid),dnssecPut('validators.dnsValidator.zoneKeysAuthenticated',check.valid)]:[],[...dsGot.refs,...keyGot.refs,answerRef].map(artifactId=>({artifactId,kind:'verify'})));
    if(comparison?.collision){const checks=leaf?.candidates||[],keyTagIsUnique=new Set(chosenChild.keys.map(key=>key.keyTag)).size===chosenChild.keys.length;for(const [index,candidate] of checks.entries())observe(index===0?'first-collision-candidate-fails':'second-collision-candidate-verifies','Try the actual same-tag public key candidate','dnsValidator',{result:candidate,keyTagIsUnique},[dnssecPut('publication.candidateChecks',checks.slice(0,index+1).map(value=>({key:value.keyId,signatureValid:value.valid,mathematicalResult:value.mathematicalResult,eligibility:value.eligibility}))),dnssecPut('publication.keyTagIsUnique',keyTagIsUnique),dnssecPut('publication.selectedKey',leaf.selectedKeyId)]);}
    let denialResult=null,denialRefs=[],negativeInputs=[];
    if(denial){
      const soa=dnssecSigningTuple('child-soa-signature');
      negativeInputs=negativeReceipts;denialRefs=negativeInputs.flatMap(got=>got.refs);
      denialResult=dnssecCheckDenial({qname:question.qname,qtype:question.qtype,zone:'lab.example.',proofs:denial.map(bundle=>({rrset:bundle.rrset,signatures:bundle.signatures})),keys:chosenChild.keys,now:a.clock,policy:a.policy,purpose:'negative'});
      const soaCheck=dnssecCheckSignature({rrset:soa.rrset,signatures:soa.signatures,keys:chosenChild.keys,now:a.clock,policy:a.policy,expectedSigner:'lab.example.'});
      if(!soaCheck.valid)denialResult={...denialResult,valid:false,reason:'unauthenticated-negative-soa'};
      observe('validate-nsec3-denial','Validate signed exact-match NSEC3 denial under authenticated zone keys','dnsValidator',{result:denialResult,soaCheck},[dnssecPut('denialChecked',denialResult.checked),dnssecPut('publication.proofResult',denialResult.valid?'authenticated-NODATA':denialResult.reason)],denialRefs);
    }
    const secure=evaluated.securityStatus==='secure'&&(!denial||denialResult.valid),status=denial&&!denialResult.valid?'bogus':evaluated.securityStatus;
    const classification=dnssecSigningClassify({evaluated,secure,status,answer:actualAnswer,child:chosenChild,delegation:chosenDs,policy:a.policy,cachedAnswer,answerSource,mutation,denialResult}),reason=classification.reason;
    a.chapter('validation','Check, accept, cache and return separately');
    const evidence=a.artifact('local-validation-evidence','Exact reference-bound validation evidence','dnsValidator',{zone:'lab.example.',checkedAt:a.clock,validationOwner:'dnsValidator',verificationKind:'local-check',evidenceMode:'symbolic-reference-bound',result:evaluated,denial:denialResult,selectedEvidence:evaluated.selectedEvidence,receivedObjectRef:answerRef},{kind:'trust',derivedFrom:[anchor,answerRef,...keyGot.refs||[],...dsGot.refs||[],...denialRefs]});
    a.local('local-validation-complete','Complete local validation without accepting or caching data','dnsValidator',{values:{result:evaluated,denial:denialResult},effects:[dnssecPut('signatureChecked',status==='insecure'?false:evaluated.signatureChecked),dnssecPut('chainEstablished',secure),dnssecPut('validators.dnsValidator.zoneKeysAuthenticated',evaluated.chainEstablished),dnssecPut('securityStatus',status),dnssecPut('reasonCode',reason),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind','local-check'),dnssecPut('evidenceRefs',[evidence]),dnssecPut('checkedAt',a.clock),dnssecPut('failureStage',classification.stage),dnssecPut('firstDetector',status==='bogus'?'dnsValidator':null),dnssecPut('stoppedAction',classification.stopped)],refs:[{artifactId:answerRef,kind:'verify'},{artifactId:evidence,kind:'create'}],held:a.create(evidence,'dnsValidator','Validation evidence'),kind:'verify'});
    const selected=actualAnswer.signatures.find(signature=>signature.id===leaf?.selectedSignatureId),receivedAt=answerGot.receivedAt??a.clock,ttl=Math.min(answerGot.receivedTtl??actualAnswer.rrset.ttl,actualAnswer.rrset.ttl),rrsigTtl=answerGot.receivedTtl??actualAnswer.rrset.ttl;
    let window=selected?dnssecTtlWindow({receivedTtl:ttl,rrsigTtl,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,now:a.clock,receivedAt}):{valid:status==='insecure',remainingSeconds:status==='insecure'?ttl:0,expiresAt:a.clock+(status==='insecure'?ttl:0),limits:{unsignedTtl:ttl}};
    if(denial&&secure){
      const limits=negativeInputs.map(got=>dnssecPublicationWindow(got.bundle,{keys:chosenChild.keys,now:a.clock,receivedAt:got.receivedAt,receivedTtl:got.receivedTtl,rrsigTtl:got.receivedTtl,policy:a.policy}).window),soa=negativeInputs.at(-1).bundle.rrset,minimum=Number(soa.records[0].trim().split(/\s+/).at(-1)),remaining=Math.min(window.remainingSeconds,minimum,...limits.map(limit=>limit.remainingSeconds));
      window={...window,valid:remaining>0,remainingSeconds:remaining,expiresAt:a.clock+remaining,limits:{...window.limits,soaMinimum:minimum,proofLimits:limits.map(limit=>limit.limits)}};
    }
    const accepted=(secure||status==='insecure')&&window.valid,cacheValue={id:'answer-'+caseId,kind:denial?'negative':'positive',key:['synthetic-public','publication-resolver',question.qname,question.qtype,question.qclass],securityStatus:status,receivedAt,expiresAt:window.expiresAt,remainingSeconds:window.remainingSeconds,receivedTtl:ttl,rrsigTtl,originalTtl:selected?.originalTtl??null,signatureExpiration:selected?.expiration??null,provenance:{view:'synthetic-public',trustStore:'publication-resolver',checkingContext:'checking-CD0',validationOwner:'dnsValidator',evidenceRefs:[evidence],receivedObjectRef:answerRef},limits:window.limits};
    const acceptedCache=accepted?a.artifact('accepted-cache','Accepted result cache with all four TTL bounds','dnsResolver',cacheValue,{kind:'cache',derivedFrom:[answerRef,evidence,...denialRefs]}):null;
    if(acceptedCache)a.bind('resultCacheEntry',acceptedCache,'dnsResolver','Answer cache');
    a.local('accepted-answer-cache-decision','Apply resolver policy and cache only the accepted result','dnsResolver',{values:{accepted,window,unrelatedCachePreserved:true,oldGenerationsPreserved:true},effects:[dnssecPut('acceptedForUse',accepted),dnssecPut('cached',accepted),...accepted?[dnssecPut('resultCacheEntry',cacheValue)]:[]],refs:[evidence,unrelated,...acceptedCache?[{artifactId:acceptedCache,kind:'create'}]:[]],held:acceptedCache?a.create(acceptedCache,'dnsResolver','Answer cache'):[]});
    const outgoing=[];if(accepted&&!denial){const returned=a.artifact('returned-answer','Outgoing remaining-TTL answer representation','dnsResolver',{...actualAnswer.rrset,ttl:window.remainingSeconds},{kind:'rrset',derivedFrom:[answerRef]});a.local('construct-returned-answer','Bound outgoing TTL by remaining authenticated lifetime','dnsResolver',{values:{remainingTtl:window.remainingSeconds,signedMetadataChanged:false},refs:[{artifactId:returned,kind:'create'}],held:a.create(returned,'dnsResolver','Stub response data'),kind:'derive'});outgoing.push(returned,...answerGot.refs.slice(1).filter(ref=>a.object(ref).kind==='rrsig'));}
    if(accepted&&denial)for(const [index,got] of negativeInputs.entries()){
      const returned=a.artifact('returned-negative-'+index,'Outgoing remaining-TTL negative proof','dnsResolver',{...got.bundle.rrset,ttl:window.remainingSeconds},{kind:'rrset',derivedFrom:[got.ref,evidence]});
      a.local('construct-negative-return-'+index,'Bound the outgoing proof TTL without changing its signed metadata','dnsResolver',{refs:[{artifactId:returned,kind:'create'}],held:a.create(returned,'dnsResolver','Stub response data'),kind:'derive'});outgoing.push({artifactId:returned,section:'authority'},...got.refs.slice(1).filter(ref=>a.object(ref).kind==='rrsig').map(artifactId=>({artifactId,section:'authority'})));
    }
    const response={...dnssecLookupMessage(stubId,question,{response:true,recursive:true,rcode:accepted?'NOERROR':'SERVFAIL',flags:{AD:secure&&accepted?1:0,CD:0}}),receivedRrsetTtl:accepted?window.remainingSeconds:0,receivedRrsigTtl:accepted?window.remainingSeconds:0};
    a.send('stub-response-received','Return the checking resolver result to the stub','dnsResolver','dnsStub',outgoing,{...response,inReplyTo:a.id+':'+caseId+':stub-query'},[dnssecPut('returnedToStub',true),dnssecPut('response.rcode',response.rcode),dnssecPut('response.flags',response.flags),dnssecPut('response.ede',{present:false}),dnssecAppend('response.hops',{id:a.id+':'+caseId+':stub',from:'dnsStub',to:'dnsResolver',transport:'UDP',question,query:{messageId:stubId,flags:dnssecLookupMessage(stubId,question,{recursive:true,flags:{AD:1,CD:0}}).flags},response:{messageId:stubId,inReplyTo:a.id+':'+caseId+':stub-query',flags:response.flags,rcode:response.rcode}})]);
    const application=accepted?(denial?{status:'negative',kind:'NODATA',...question}:{status:'answer',...question,data:dnssecPublicationApplicationRecords(actualAnswer.rrset)}):{status:'error',reason};
    const applicationArtifact=a.artifact('application-result','Application result, separate from DNS receipt','dnsApp',application,{kind:'event',derivedFrom:accepted?[evidence,...outgoing.map(ref=>typeof ref==='string'?ref:ref.artifactId)]:[evidence]});
    a.local('application-acceptance','Application applies only the returned resolver result','dnsApp',{values:{result:application},effects:[dnssecPut('applicationResult',application),dnssecPut('applicationResultArtifact',applicationArtifact)],refs:[{artifactId:applicationArtifact,kind:'create'}],held:a.create(applicationArtifact,'dnsApp','Application result'),kind:'derive'});a.bind('applicationResultArtifact',applicationArtifact,'dnsApp','Application result');
    return finish();
  };
  const finish=()=>a.finish({dnssecCheckpointAliases:aliases,protocolTimeline:{label:'DNSSEC publication, signature and cache clocks',explanation:'Only explicit represented protocol-clock events age these independent generations. Publication does not flush remote caches.',entries:[{id:'accepted-publication-answer',label:'Accepted answer cache',startPath:'dnssec.resultCacheEntry.receivedAt',deadlinePath:'dnssec.resultCacheEntry.expiresAt',statusPath:'dnssec.resultCacheEntry.securityStatus'},{id:'cached-dnskeys',label:'Earlier DNSKEY generation',startPath:'dnssec.cacheEntries.dnskeys.receivedAt',deadlinePath:'dnssec.cacheEntries.dnskeys.expiresAt',statusPath:'dnssec.cacheEntries.dnskeys.securityStatus'},{id:'cached-delegation',label:'Earlier parent DS generation',startPath:'dnssec.cacheEntries.ds.receivedAt',deadlinePath:'dnssec.cacheEntries.ds.expiresAt',statusPath:'dnssec.cacheEntries.ds.securityStatus'},...Object.entries(timers).flatMap(([key,value])=>Object.keys(value).filter(field=>field.endsWith('At')).map(field=>({id:key+'-'+field,label:key+' / '+field,deadlinePath:'dnssec.timers.'+key+'.'+field})))],clockUnit:'seconds',playbackAdvancesClock:false,timers}});
  a.chapter('publication','Private custody and immutable public generations');
  return {a,at,observe,sign,stageGeneration,publishChild,publishAnswer,replicateGeneration,parentPublish,receive,cacheBundle,cached,validate,checkPath,timer,finishLookup,finish,ensure,refs,providerMetadata,aliases,get child(){return currentChild;},get delegation(){return currentDs;},get answer(){return currentAnswer;},get provider(){return currentProvider;}};
}

function dnssecSigningFoundation(){
  const model=dnssecLookupCase(2,'split-ksk-zsk',{signFirst:true,successReason:'valid-path',applicationData:true});
  return {...model,dnssecCheckpointAliases:{'raw-answer-received':'raw-response-received-before-trust','local-validation-complete':'classification-with-independent-failure-context','accepted-answer-cache-decision':'accepted-use-and-cache-boundary','stub-response-received':'stub:r','application-acceptance':'application-result-boundary'}};
}
function dnssecSigningCombined(){
  const s=dnssecSigningSession(2,'combined-key'),child=dnssecSigningTuple('child-csk-g1-dnskey-signature',['child-csk-g1']),answer=dnssecSigningTuple('www-a-csk'),ds=dnssecSigningTuple('parent-ds-for-child-csk-g1-signature');
  s.stageGeneration('sign-both-rrsets-with-csk',child,answer,'g1');
  s.at(600);s.publishAnswer('publish-csk-answer',answer,{signFirst:false,generation:'g1'});s.publishChild('publish-csk-dnskey',child,'g1',{signFirst:false});s.parentPublish('publish-csk-and-parent-ds',ds,'ds-c0');return s.finishLookup();
}
function dnssecSigningCanonical(caseId,{answer=dnssecSigningTuple('www-a-signature'),mutation=null,boundary,values={},collision=false}){
  const child=collision?dnssecSigningTuple('child-dnskey-collision-by-ksk',['child-ksk-g1','collision-a','collision-b']):dnssecSigningOldChild();
  const s=dnssecSigningSession(2,caseId,{child,answer,custody:collision?{...dnssecSigningOrdinaryCustody,dnsSigner:[...dnssecSigningOrdinaryCustody.dnsSigner,'collision-a','collision-b']}:dnssecSigningOrdinaryCustody});
  return s.finishLookup({mutation,comparison:{boundary,values,collision}});
}
function dnssecSigningEquivalent(){
  const compressed=dnssecPublicationDecodeMxPacket(dnssecMaterial('vectors','mx-compressed').wireHex),uncompressed=dnssecPublicationDecodeMxPacket(dnssecMaterial('vectors','mx-uncompressed').wireHex),signature=dnssecMaterial('signatures','child-mx-signature');
  return dnssecSigningCanonical('equivalent-presentation',{answer:dnssecSigningTuple('child-mx-signature'),mutation:{owner:compressed.owner,records:compressed.records,ttl:42},boundary:'canonical-input-compared',values:{rrOrderingChanged:JSON.stringify(compressed.records)!==JSON.stringify(uncompressed.records),domainNameCaseChanged:JSON.stringify(compressed)!==JSON.stringify(uncompressed),wireCompressionChanged:dnssecMaterial('vectors','mx-compressed').wireHex!==dnssecMaterial('vectors','mx-uncompressed').wireHex,transportCanonicalInputEqual:dnssecCanonicalInput(compressed,signature)===dnssecCanonicalInput(uncompressed,signature),transportEncoding:{compressed,uncompressed}}});
}
function dnssecSigningRefresh(outage){
  const old=dnssecSigningTuple('www-a-refresh-old-expiry10000'),s=dnssecSigningSession(12,outage?'signature-refresh-outage':'resign-before-expiry',{answer:old});
  s.timer('refresh',{inception:old.signatures[0].inception,expiration:old.signatures[0].expiration,refreshPlannedAt:DNSSEC_BASE_CLOCK+6000,convergedAt:DNSSEC_BASE_CLOCK+6300});
  if(outage){s.at(9000);s.observe('refresh-service-fails','Signer service is unavailable; preserve the old published tuple','dnsSigner',{serviceAvailable:false,newSignatureCreated:false},[dnssecPut('publication.refreshAvailable',false),dnssecPut('publication.keyChanged',false)]);s.at(10001);const time=dnssecSignatureTime(s.a.clock,old.signatures[0].inception,old.signatures[0].expiration);s.observe('old-signature-expired','Compare the concrete signature deadline with the resolver clock','dnsValidator',{result:time},[dnssecPut('publication.rrsigExpiration',old.signatures[0].expiration)]);return s.finishLookup();}
  s.cacheBundle('cache-old-refresh-answer','answer',old,{keys:s.child.keys});s.at(6000);
  const refreshed=dnssecSigningTuple('www-a-refresh-same-key-new');s.stageGeneration('same-key-refresh-created',s.child,refreshed,'g1');
  s.at(6300);s.publishAnswer('publish-refreshed-primary',refreshed,{signFirst:false,generation:'g1'});s.replicateGeneration('refresh-publication-converged','dnsSecondary');
  s.at(7000);const cached=s.cached('answer'),check=dnssecPublicationWindow(old,{keys:s.child.keys,now:s.a.clock,receivedAt:cached.receivedAt,policy:s.a.policy});s.observe('cached-old-signature-still-valid','A different authority generation does not invalidate the old cached signature','dnsResolver',{result:check,unchangedCacheDeadline:cached.entry.expiresAt},[],[cached.artifact]);return s.finishLookup();
}
function dnssecSigningZskPrepublish(){
  const s=dnssecSigningSession(12,'zsk-prepublish'),overlap=dnssecSigningTuple('child-dnskey-zsk-overlap3-by-child-ksk-g1-long',dnssecSigningZskOverlap),times=dnssecPublicationReadyAt({propagation:300,priorTtl:3600,lastOldSignatureAt:DNSSEC_BASE_CLOCK+4500,maximumDataTtl:7200});
  s.timer('zskPrepublish',times);s.publishChild('prepublish-z1',overlap,'g1');s.at(times.activationAt-DNSSEC_BASE_CLOCK);s.publishAnswer('z1-ready-and-active',dnssecSigningNewAnswer(),{generation:'g2'});s.at(times.retirementAt-DNSSEC_BASE_CLOCK);s.publishChild('old-signature-cache-drained',dnssecSigningZskFinal(),'g3');s.at(12000);s.cacheBundle('resolver-new-generation','dnskeys',s.child);return s.finishLookup({cachedChild:true});
}
function dnssecSigningZskDouble(){
  const s=dnssecSigningSession(12,'zsk-double-sign'),oldChild=s.child,overlap=dnssecSigningTuple('child-dnskey-zsk-overlap3-by-child-ksk-g1-long',dnssecSigningZskOverlap),dual=dnssecSigningTuple(['www-a-rollover-old-long','www-a-rollover-new-long']);
  s.cacheBundle('cache-old-dnskey-generation','dnskeys',oldChild);s.publishAnswer('publish-both-zsk-signatures',dual,{generation:'g1'});s.publishChild('publish-double-signatures',overlap,'g1');s.timer('doubleSignOverlap',{convergedAt:DNSSEC_BASE_CLOCK+300,oldDnskeyDeadline:DNSSEC_BASE_CLOCK+3600,oldDataDeadline:DNSSEC_BASE_CLOCK+7500,retirementAt:DNSSEC_BASE_CLOCK+7500});s.at(2000);
  const selected=s.checkPath('double-signature-selection',oldChild,s.delegation,dual,{cachedKeys:true});s.observe('old-key-cache-uses-old-signature','Cached old DNSKEY membership selects the usable old signature','dnsResolver',{result:selected},[dnssecPut('publication.selectedAnswerSignature',selected.checks.find(check=>check.stage==='answer-signature')?.result.selectedKeyId)], [s.cached('dnskeys').artifact]);
  s.at(7500);s.publishAnswer('retire-z0-signature',dnssecSigningNewAnswer(),{generation:'g2'});s.publishChild('retire-z0-after-overlap',dnssecSigningZskFinal(),'g2');return s.finishLookup();
}
function dnssecSigningZskPremature(){
  const s=dnssecSigningSession(12,'old-key-removed-too-early');s.cacheBundle('cache-original-dnskeys','dnskeys',s.child);s.at(300);s.cacheBundle('cache-old-answer','answer',s.answer,{keys:s.child.keys});s.at(4000);s.publishChild('premature-z0-withdrawal',dnssecSigningZskFinal(),'g2');s.at(4100);
  const old=s.cached('answer'),cacheRevalidation={mode:'fresh-keyset-recheck',ordinarySecureReuseAllowed:true,explanation:'This fixture deliberately rechecks an already-secure cached answer against a newly fetched DNSKEY set to expose its missing-old-key dependency. Ordinary secure-cache reuse can continue until the existing authenticated deadline; withdrawing a published DNSKEY does not revoke that accepted cache.'};
  s.observe('declare-cached-answer-revalidation-policy','Deliberately revalidate here; ordinary reuse of a still-valid secure cache is different','dnsValidator',cacheRevalidation,[dnssecPut('publication.cacheRevalidation',cacheRevalidation)],[old.artifact]);
  s.cacheBundle('cache-fresh-authenticated-dnskeys','dnskeys',s.child);s.observe('fresh-keyset-cannot-check-cached-signature','The deliberate fresh-keyset recheck fails, not an automatic revocation of cached secure data','dnsValidator',{result:s.checkPath('cached-answer-selection',s.child,s.delegation,old.bundle,{cachedAnswer:true,cachedKeys:true}),cacheExpiresAt:old.entry.expiresAt,cacheRevalidation},[],[old.artifact,s.cached('dnskeys').artifact]);return s.finishLookup({answer:old.bundle,cachedAnswer:true,cachedChild:true});
}
function dnssecSigningSecondaryLag(){
  const old=dnssecSigningOldAnswer(),s=dnssecSigningSession(12,'secondary-lags',{provider:'dnsPrimary'});s.ensure(old,'dnsSecondary');s.at(7500);s.publishAnswer('primary-new-answer',dnssecSigningNewAnswer(),{generation:'g2'});s.publishChild('primary-retired-old-key',dnssecSigningZskFinal(),'g2',{to:'dnsPrimary'});s.at(8000);
  s.observe('secondary-still-old','Secondary continues serving its independently held g0 tuple','dnsSecondary',{generation:old.rrset.id,signature:old.signatures[0].id},[dnssecPut('publication.authorities',{'192.0.2.53':'g2','198.51.100.53':'g0'}),dnssecPut('publication.secondaryAnswerSignature',old.signatures[0].keyId)],s.refs(old));
  s.cacheBundle('cache-primary-current-keyset','dnskeys',s.child);s.observe('resolver-mixed-authority-evidence','The selected route gets DNSKEY from primary and answer from lagging secondary','dnsResolver',{dnskeySource:'primary',answerSource:'secondary',secondaryDnskeyAvailable:false});return s.finishLookup({answer:old,answerSource:'dnsSecondary',cachedChild:true});
}
function dnssecSigningDoubleDs(){
  const s=dnssecSigningSession(13,'ksk-double-ds'),oldDs=s.delegation;s.cacheBundle('double-ds-old-parent-cache','ds',oldDs,{keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id))});
  s.observe('submit-new-ds','Submit child intent without changing the parent publication','dnsOperator',{candidateKeys:['child-ksk-g1','child-ksk-g2']},[dnssecPut('publication.childIntent',['child-ksk-g1','child-ksk-g2']),dnssecPut('publication.parentAccepted',false),dnssecPut('publication.parentPublished',false)]);
  s.at(600);s.parentPublish('parent-publishes-both-ds',dnssecSigningTuple('parent-ds-overlap-g1-g2-signature'),'ds01');
  s.observe('double-ds-old-cache-continuity','A resolver retaining the original DS still has the old complete path','dnsValidator',{result:s.checkPath('double-ds-old-cache-path',s.child,oldDs,s.answer,{cachedDs:true})},[],[s.cached('ds').artifact]);
  s.timer('doubleDs',{parentConvergedAt:DNSSEC_BASE_CLOCK+600,oldDsDeadline:DNSSEC_BASE_CLOCK+87000,childSwitchAt:DNSSEC_BASE_CLOCK+87600,childConvergedAt:DNSSEC_BASE_CLOCK+87900,oldDnskeyDeadline:DNSSEC_BASE_CLOCK+91500});
  s.at(87599);s.cacheBundle('double-ds-last-old-dnskeys','dnskeys',s.child);const oldChild=s.child;
  s.at(87600);s.publishChild('change-child-ksk',dnssecSigningKskFinal(),'g1');
  s.observe('double-ds-cached-and-current-child-paths','Both the retained old DNSKEY cache and current KSK generation compose with the double DS','dnsValidator',{old:s.checkPath('double-ds-cached-child',oldChild,s.delegation,s.answer,{cachedKeys:true}),current:s.checkPath('double-ds-current-child')},[],[s.cached('dnskeys').artifact]);
  s.at(91500);s.parentPublish('remove-old-ds-after-child-cache-drain',dnssecSigningNewDs(),'ds1');return s.finishLookup();
}
function dnssecSigningDoubleKsk(){
  const s=dnssecSigningSession(13,'ksk-double-ksk-method'),oldDs=s.delegation;
  s.publishChild('double-ksk-publish-and-sign',dnssecSigningKskBoth(),'g1');s.at(3900);
  s.observe('double-ksk-ready','The propagated keyset has outlasted earlier DNSKEY cache lifetimes','dnsOperator',{childReady:true},[dnssecPut('publication.childReady',true),dnssecPut('publication.parentAccepted',false)]);
  s.observe('submit-single-replacement-ds','Parent automation accepts the replacement request, not yet a published DS','dnsParentAgent',{replacement:['child-ksk-g2']},[dnssecPut('publication.childIntent',['child-ksk-g2']),dnssecPut('publication.parentAccepted',true),dnssecPut('publication.parentPublished',false)]);
  s.at(4500);s.parentPublish('replace-parent-single-ds',dnssecSigningNewDs(),'ds1');s.at(5100);
  s.cacheBundle('last-old-parent-generation','ds',oldDs,{keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id)),sourceAddress:'198.51.100.54 - last old parent generation at propagation boundary'});
  s.observe('retain-old-key-for-old-ds-cache','Use the retained old DS with both exact DNSKEY signatures','dnsResolver',{oldCachePath:s.checkPath('double-ksk-retained-old-ds',s.child,oldDs,s.answer,{cachedDs:true})},[],[s.cached('ds').artifact]);
  s.timer('doubleKsk',{parentReplacementAt:DNSSEC_BASE_CLOCK+4500,parentPropagation:600,oldDsTtl:86400,retirementAt:DNSSEC_BASE_CLOCK+91500});s.at(91500);s.publishChild('dead-and-remove-old-ksk',dnssecSigningKskFinal(),'g2');return s.finishLookup();
}
function dnssecSigningCskRollover(){
  const child=dnssecSigningTuple('child-csk-g1-dnskey-signature',['child-csk-g1']),delegation=dnssecSigningTuple('parent-ds-for-child-csk-g1-signature'),answer=dnssecSigningTuple('www-a-long-csk-g1'),s=dnssecSigningSession(13,'combined-key-rollover',{child,delegation,answer});
  s.cacheBundle('csk-old-parent-cache','ds',delegation,{keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id))});
  s.publishAnswer('csk-overlap-ordinary-signatures',dnssecSigningTuple(['www-a-long-csk-g1','www-a-long-csk-g2']),{generation:'g1'});
  s.publishChild('csk-overlap-publication',dnssecSigningTuple(['child-dnskey-csk-overlap2-by-child-csk-g1-long','child-dnskey-csk-overlap2-by-child-csk-g2-long'],['child-csk-g1','child-csk-g2']),'g1');
  s.at(8100);s.parentPublish('csk-ds-replacement',dnssecSigningTuple('parent-ds-for-child-csk-g2-signature'),'ds-c1');
  s.timer('cskRetirement',{childReadinessAt:DNSSEC_BASE_CLOCK+7500,dsReplacementAt:DNSSEC_BASE_CLOCK+8100,parentPropagation:600,oldDsTtl:86400,retirementAt:DNSSEC_BASE_CLOCK+95100});
  s.at(95100);s.publishAnswer('retire-old-csk-ordinary-signatures',dnssecSigningTuple('www-a-long-csk-g2'),{generation:'g2'});s.publishChild('csk-old-path-retirement',dnssecSigningTuple('child-csk-g2-dnskey-signature',['child-csk-g2']),'g2');return s.finishLookup();
}
function dnssecSigningDelayedDs(){
  const s=dnssecSigningSession(13,'parent-ds-delayed');s.publishChild('prepare-double-ksk-keyset',dnssecSigningKskBoth(),'g1');s.at(4000);
  s.observe('parent-ack-without-publication','Parent automation acknowledges submission while the authority still publishes the old DS','dnsParentAgent',{currentDs:s.delegation.rrset.id},[dnssecPut('publication.parentAccepted',true),dnssecPut('publication.parentPublished',false)]);
  s.at(10000);const oldPath=s.checkPath('delayed-parent-old-path');s.observe('child-retains-old-path','Retain the old public key and its exact DNSKEY signature until actual parent publication','dnsChild',{result:oldPath,retainedKeys:s.child.keys.map(key=>key.id)},[],s.refs(s.child));s.at(20000);s.parentPublish('actual-ds-publication',dnssecSigningNewDs(),'ds1');return s.finishLookup();
}
function dnssecSigningOldDsCache(premature){
  const s=dnssecSigningSession(13,premature?'premature-old-key-removal':'old-ds-cache'),oldDs=s.delegation;
  s.cacheBundle('cache-original-parent-ds','ds',oldDs,{keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id))});s.publishChild('publish-ksk-overlap',dnssecSigningKskBoth(),'g1');s.at(4500);s.parentPublish(premature?'parent-publishes-new-ds':'new-parent-short-ttl',dnssecSigningNewDs(),'ds1',{ttl:600});
  s.at(5000);if(premature)s.publishChild('remove-ksk-before-ds-cache-drains',dnssecSigningKskFinal(),'g2');else s.observe('old-ds-still-cached','New published TTL cannot shorten this previously received DS cache','dnsResolver',{receivedAt:s.cached('ds').entry.receivedAt,expiresAt:s.cached('ds').entry.expiresAt,result:s.checkPath('old-ds-selection',s.child,oldDs,s.answer,{cachedDs:true})},[dnssecPut('publication.selectedDnskeySignature','child-ksk-g1')],[s.cached('ds').artifact]);
  if(premature){s.at(5100);s.observe('old-ds-meets-new-only-child','Compare old authenticated DS with the fresh DNSKEY membership','dnsResolver',{result:s.checkPath('old-ds-mismatched-keyset',s.child,oldDs,s.answer,{cachedDs:true})},[],[s.cached('ds').artifact]);}return s.finishLookup({delegation:oldDs,cachedDs:true});
}

function dnssecSigningPolicyObservation(s,boundary,{actor='dnsValidator',focus='capabilities',result=null,authenticate=false}={}){
  const evaluated=authenticate?s.checkPath(boundary+'-authenticated-evidence'):result,details=dnssecPublicationPolicyDetails({child:s.child,delegation:s.delegation,policy:s.a.policy,result:evaluated,focus});
  s.observe(boundary,'Inspect independent publisher, implementation, operator and digest policy',actor,{...details,registry:s.a.policy.registry,result:evaluated},[...Object.entries(details).map(([key,value])=>dnssecPut('algorithmPolicy.'+key,value)),dnssecPut('algorithmPolicy.acceptedDigestTypes',s.a.policy.dsDigestTypes),dnssecPut('algorithmPolicy.receivedFixtureAlgorithm',dnssecPublicationDs(s.delegation.rrset)[0].algorithm)],s.refs(s.delegation));
  return details;
}
function dnssecSigningModern(){
  const s=dnssecSigningSession(14,'modern-baseline',{answer:dnssecSigningTuple('www-a-signature')});dnssecSigningPolicyObservation(s,'inspect-four-policy-columns',{actor:'dnsOperator',focus:'selected'});return s.finishLookup();
}
function dnssecSigningDualAlgorithm(){
  const s=dnssecSigningSession(14,'dual-algorithm-rollover',{profileId:'dual-modern',answer:dnssecSigningTuple('www-a-complete-path-g1'),custody:{...dnssecSigningOrdinaryCustody,dnsSigner:[...dnssecSigningOrdinaryCustody.dnsSigner,'child-ed25519-g1']}});
  const both=dnssecSigningTuple(['child-dual-algorithm-dnskey-alg13','child-dual-algorithm-dnskey-alg15'],['child-ksk-g1','child-zsk-g1','child-ed25519-g1']),dualAnswer=dnssecSigningTuple(['www-a-complete-path-g1','www-a-complete-path-ed25519']),alg15=dnssecSigningTuple('www-a-long-ed25519'),overlapDs=dnssecSigningTuple('parent-ds-dual-algorithm-long-signature');
  const childPropagation=300,parentPropagation=600,oldDataTtl=dualAnswer.rrset.ttl,oldDnskeyTtl=both.rrset.ttl,oldDsTtl=overlapDs.rrset.ttl;
  // RFC 6781 section 4.1.4/Figure 8: prepublish ordinary signatures,
  // then the new DNSKEY, then DS; retirement follows the reverse dependencies.
  const keysPublishedAt=childPropagation+oldDataTtl,childReadyAt=keysPublishedAt+childPropagation+oldDnskeyTtl,parentDsAt=childReadyAt+300,oldDsRemovedAt=95100,parentConvergedAt=oldDsRemovedAt+parentPropagation;
  const oldDsDependencyEnds=parentConvergedAt+oldDsTtl,childKeysConvergedAt=oldDsDependencyEnds+childPropagation,oldDnskeyDependencyEnds=childKeysConvergedAt+oldDnskeyTtl,oldSignaturesConvergedAt=oldDnskeyDependencyEnds+childPropagation,ordinaryDataDependencyEnds=oldSignaturesConvergedAt+oldDataTtl;
  s.stageGeneration('complete-dual-algorithm-signatures',both,dualAnswer,'alg13-15');s.publishAnswer('publish-alg13-and-alg15-ordinary-signatures',dualAnswer,{signFirst:false,generation:'alg13-15'});
  s.at(keysPublishedAt);s.publishChild('publish-dual-algorithm-signed-zone',both,'alg13-15',{signFirst:false});
  s.at(parentDsAt);s.parentPublish('publish-dual-algorithm-ds',overlapDs,'ds13-15');s.at(parentDsAt+parentPropagation);
  s.observe('parent-dual-algorithm-ds-converged','All represented parent authorities now serve the overlap DS set','dnsParent',{parentConvergedAt:s.a.clock,dsAlgorithms:[13,15]});
  const check=s.checkPath('ed25519-selected-path',{...both,signatures:both.signatures.filter(signature=>signature.algorithm===15)},s.delegation,alg15);dnssecSigningPolicyObservation(s,'select-usable-alg15-path',{result:check});
  s.timer('algorithmRetirement',{signaturesPublishedAt:DNSSEC_BASE_CLOCK,childReadyAt:DNSSEC_BASE_CLOCK+childReadyAt,parentDsAt:DNSSEC_BASE_CLOCK+parentDsAt,parentOverlapConvergedAt:DNSSEC_BASE_CLOCK+parentDsAt+parentPropagation,oldDsRemovedAt:DNSSEC_BASE_CLOCK+oldDsRemovedAt,parentConvergedAt:DNSSEC_BASE_CLOCK+parentConvergedAt,oldDsTtl,lastOldDsReceivedAt:DNSSEC_BASE_CLOCK+parentConvergedAt-1,lastOldDsExpiresAt:DNSSEC_BASE_CLOCK+oldDsDependencyEnds-1,oldDsDependencyEnds:DNSSEC_BASE_CLOCK+oldDsDependencyEnds,childKeysRemovedAt:DNSSEC_BASE_CLOCK+oldDsDependencyEnds,childKeysConvergedAt:DNSSEC_BASE_CLOCK+childKeysConvergedAt,oldDnskeyTtl,oldDnskeyDependencyEnds:DNSSEC_BASE_CLOCK+oldDnskeyDependencyEnds,oldSignaturesRemovedAt:DNSSEC_BASE_CLOCK+oldDnskeyDependencyEnds,oldSignaturesConvergedAt:DNSSEC_BASE_CLOCK+oldSignaturesConvergedAt,maximumOldDataTtl:oldDataTtl,ordinaryDataDependencyEnds:DNSSEC_BASE_CLOCK+ordinaryDataDependencyEnds});
  s.at(oldDsRemovedAt);s.parentPublish('retire-alg13-parent-ds',dnssecSigningTuple('parent-ds-for-child-ed25519-g1-signature'),'ds15');
  s.at(parentConvergedAt-1);s.cacheBundle('late-old-containing-ds-cache','ds',overlapDs,{keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id)),sourceAddress:'198.51.100.54 - last old-containing parent DS before convergence'});
  s.at(parentConvergedAt);s.observe('parent-alg13-ds-converged','Parent convergence stops new old-containing DS receipts; existing caches retain their deadlines','dnsParent',{parentConvergedAt:s.a.clock,lastOldDsReceivedAt:s.cached('ds').entry.receivedAt,lastOldDsExpiresAt:s.cached('ds').entry.expiresAt},[],[s.cached('ds').artifact]);
  s.at(oldDsDependencyEnds);s.publishChild('retire-alg13-after-ds-and-child-cache-dependencies',dnssecSigningTuple('child-ed25519-g1-dnskey-signature',['child-ed25519-g1']),'alg15');
  s.at(childKeysConvergedAt);s.observe('child-alg13-key-removal-converged','Child DNSKEY convergence stops old keyset receipts; retain old ordinary signatures until DNSKEY caches drain','dnsChild',{childKeysConvergedAt:s.a.clock,oldDnskeyDependencyEnds:DNSSEC_BASE_CLOCK+oldDnskeyDependencyEnds});
  s.at(oldDnskeyDependencyEnds);s.publishAnswer('retire-alg13-ordinary-signatures',alg15,{generation:'alg15'});
  s.at(oldSignaturesConvergedAt);s.observe('child-alg13-signature-removal-converged','All represented child authorities now serve algorithm15-only ordinary signatures','dnsChild',{oldSignaturesConvergedAt:s.a.clock});
  s.at(ordinaryDataDependencyEnds);s.observe('old-alg13-data-dependencies-ended','Earlier dual-signed data has aged out; fresh algorithm13-only resolvers are insecure, not broken supported paths','dnsChild',{ordinaryDataDependencyEnds:s.a.clock,publicationDoesNotRevokeAcceptedCache:true});return s.finishLookup();
}
function dnssecSigningUnsupported(digest){
  const ds=dnssecSigningTuple(digest?'parent-ds-unsupported-digest250-signature':'parent-ds-unsupported-alg17-signature'),s=dnssecSigningSession(14,digest?'unsupported-digest-only':'algorithm-unsupported',{delegation:ds,answer:dnssecSigningTuple('www-a-signature')});
  dnssecSigningPolicyObservation(s,digest?'classify-authenticated-unsupported-digest':'classify-authenticated-unsupported-algorithm',{authenticate:true});return s.finishLookup();
}
function dnssecSigningObsoleteExtras(){
  const s=dnssecSigningSession(14,'modern-and-obsolete-paths',{profileId:'dual-modern',delegation:dnssecSigningTuple('parent-ds-modern-obsolete-signature'),answer:dnssecSigningTuple('www-a-signature')});
  dnssecSigningPolicyObservation(s,'retain-valid-current-path',{authenticate:true});return s.finishLookup();
}
function dnssecSigningSha1SigningDisabled(){
  const ds=dnssecSigningTuple('parent-ds-archival-alg5-signature'),s=dnssecSigningSession(14,'sha1-signing-disabled',{profileId:'dual-modern',delegation:ds,answer:dnssecSigningTuple('www-a-signature')}),requested=[5,7],cells=s.a.policy.registry.algorithms.filter(row=>requested.includes(Number(row.number)));
  const decision={requestedSigningAlgorithms:requested,generationAllowed:requested.every(algorithm=>s.a.policy.signingAlgorithms.includes(algorithm)),implementationValidationSupportRequired:cells.every(row=>row.implementForValidation==='MUST'),registryUseForValidation:cells.every(row=>row.useForValidation===cells[0].useForValidation)?cells[0].useForValidation:cells.map(row=>row.useForValidation),operatorTreatAs:requested.every(algorithm=>!s.a.policy.validationAlgorithms.includes(algorithm))?'unsupported':'supported',newDsCreated:false};
  s.observe('reject-new-sha1-signing','Apply publisher generation policy before any signing or DS creation','dnsSigner',{...decision,registry:cells},Object.entries(decision).map(([key,value])=>dnssecPut('algorithmPolicy.'+key,value)));
  dnssecSigningPolicyObservation(s,'operator-rejects-archived-sha1-path',{authenticate:true});return s.finishLookup();
}
function dnssecSigningSha1Digest(){
  const s=dnssecSigningSession(14,'sha1-digest-compatibility',{profileId:'legacy-ds-sha1',delegation:dnssecSigningTuple('parent-ds-historical-sha1-signature'),answer:dnssecSigningTuple('www-a-signature')});
  dnssecSigningPolicyObservation(s,'inspect-distinct-digest-policy',{focus:'digest'});return s.finishLookup();
}
function dnssecSigningNsec3Roles(){
  const s=dnssecSigningSession(14,'nsec3-sha1-not-signature-policy',{answer:dnssecSigningTuple('www-a-signature')}),proofs=[0,1,2].map(index=>dnssecSigningTuple('nsec3-proof-'+index+'-signature')),parameters=proofs[0].rrset.records[0].trim().split(/\s+/);
  const roles={signingAlgorithm:proofs[0].signatures[0].algorithm,dsDigest:dnssecPublicationDs(s.delegation.rrset)[0].digestType,nsec3HashAlgorithm:Number(parameters[0]),nsec3AdditionalIterations:Number(parameters[2]),nsec3SaltHex:parameters[3]==='-'?'':parameters[3].toLowerCase(),operatorAccepted:s.a.policy.validationAlgorithms.includes(proofs[0].signatures[0].algorithm)&&Number(parameters[0])===s.a.policy.nsec3.hashAlgorithm&&Number(parameters[2])===s.a.policy.nsec3.iterations};
  s.observe('inspect-three-independent-algorithms','Keep NSEC3 hashing, DS digest and RRSIG signing algorithms independent','dnsValidator',roles,Object.entries(roles).map(([key,value])=>dnssecPut('algorithmPolicy.'+key,value)));return s.finishLookup({denial:proofs});
}

function dnssecSigningProviderCustody(separate=false,rollover=false){
  return {dnsSigner:separate?[]:['child-ksk-g1'],dnsPrimary:[...separate?['child-ksk-g1']:[],'child-zsk-g1',...rollover?['child-zsk-g2']:[]],dnsProviderB:[...separate?['provider-b-ksk-g1']:[],'provider-b-zsk-g1'],dnsParent:dnssecSigningOrdinaryCustody.dnsParent,dnsRoot:dnssecSigningOrdinaryCustody.dnsRoot};
}
function dnssecSigningSharedProvider({cached=false,missing=false}={}){
  const caseId=missing?'missing-cross-provider-key':cached?'cached-keys-provider-switch':'shared-ksk-model',child=missing?dnssecSigningOldChild():dnssecSigningTuple(cached?'provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-1h':'provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long',dnssecSigningProviderKeys),answer=dnssecSigningTuple(cached||missing?'www-a-provider-b':'www-a-long-provider-b'),s=dnssecSigningSession(18,caseId,{child,custody:dnssecSigningProviderCustody(),provider:'dnsPrimary',multiSignerModel:1,initialChildGeneration:missing?'a-broken':cached?'a1':'g0'});
  if(cached||missing){
    s.cacheBundle(missing?'cache-incomplete-provider-a-set':'cache-a-authenticated-public-keys','dnskeys',child);
    s.sign('provider-b-signs-own-answer',answer);s.at(1000);const firstReceipt=s.receive('provider-b-answer-before-key-selection',answer,'dnsProviderB');
    const compatibility=dnssecCheckSignature({rrset:firstReceipt.bundle.rrset,signatures:firstReceipt.bundle.signatures,keys:child.keys,now:s.a.clock,policy:s.a.policy,expectedSigner:'lab.example.'}),compatible=compatibility.valid;
    s.observe('provider-b-signer-key-selection','Check the received B answer against the authenticated cached A keyset','dnsValidator',{result:compatibility},[],[...firstReceipt.refs,s.cached('dnskeys').artifact].map(artifactId=>({artifactId,kind:'verify'})));
    const attempts=[];
    if(!compatible)for(const [index,offset] of [1100,1150].entries()){
      s.at(offset);const request=dnssecLookupMessage(30901+index,{qname:'lab.example.',qtype:'DNSKEY'},{flags:{CD:0}});s.a.send('cross-provider-key-retry-'+index,'Request an alternative compatible DNSKEY set on the selected failing route','dnsResolver','dnsProviderB',[],request);attempts.push({messageId:request.messageId,sentAt:s.a.clock,response:null,timeoutAt:DNSSEC_BASE_CLOCK+1200});
    }
    s.at(1200);if(attempts.length)s.observe('cross-provider-key-retries-exhausted','Every configured alternative key retrieval timed out; timeout is not a DNSSEC verdict','dnsResolver',{attempts,remainingRoutes:[],compatibleReceivedKeyset:false},[dnssecPut('transport.keyRetrieval',{attempts,completed:false,failure:'timeout',exhausted:true})]);
    s.publishAnswer(missing?'b-answer-has-no-cached-key':'receive-b-answer-using-a-cached-keys',answer,{to:'dnsProviderB',from:'dnsProviderB',signFirst:false,effects:[dnssecPut('publication.dnskeyRefetchNeeded',!compatible),dnssecPut('publication.availableAlternativePath',compatible),dnssecPut('publication.answerSource','B')]});
    s.observe('provider-switch-cache-context','Select the exact held A keyset and the actually available alternative evidence','dnsResolver',{dnskeyRefetchNeeded:!compatible,availableAlternativePath:compatible,attempts},[dnssecPut('publication.dnskeyRefetchNeeded',!compatible),dnssecPut('publication.availableAlternativePath',compatible),dnssecPut('publication.answerSource','B')]);return s.finishLookup({answerSource:'dnsProviderB',child,cachedChild:true});
  }
  s.publishChild('owner-distributes-signed-combined-keyset',child,'shared-a1',{to:'dnsPrimary'});s.a.publish('distribute-identical-signed-set-to-b','Owner distributes the identical public signed set to provider B','dnsPrimary','dnsProviderB',s.refs(child));s.observe('declare-model-one-custody','The owner alone holds the KSK; each provider holds only its own ZSK','dnsOperator',{custody:dnssecSigningProviderCustody()},[dnssecPut('publication.multiSignerModel',1),dnssecPut('publication.commonDnskeys',child.keys.map(key=>key.id)),dnssecPut('publication.privateKeysCopied',false)]);s.publishAnswer('provider-b-signs-only-own-zone-data',answer,{to:'dnsProviderB',from:'dnsProviderB'});return s.finishLookup({answerSource:'dnsProviderB'});
}
function dnssecSigningSeparateProvider(migration=false){
  const aKeys=dnssecSigningTuple('provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long',dnssecSigningProviderKeys),bKeys=dnssecSigningTuple('provider-dnskey-model2-b-kb-z0-zb-by-provider-b-ksk-g1-long',dnssecSigningProviderBKeys),s=dnssecSigningSession(18,migration?'provider-migration':'separate-ksk-model',{child:aKeys,custody:dnssecSigningProviderCustody(true),provider:'dnsPrimary',multiSignerModel:2});
  s.publishChild(migration?'prepare-provider-b-public-path':'provider-b-publishes-own-three-key-set',bKeys,'b1',{to:'dnsProviderB'});
  if(migration)s.at(600);s.parentPublish(migration?'add-b-ds-path':'parent-publishes-both-provider-paths',dnssecSigningTuple('parent-ds-provider-overlap-long-signature'),'ds-ab');
  if(!migration){
    s.a.publish('coordinate-b-public-set-with-a','Coordinate only the public provider-B keyset','dnsProviderB','dnsPrimary',s.refs(bKeys));
    s.observe('separate-provider-dnskey-generations','Provider A confirms both independently signed public provider paths','dnsPrimary',s.providerMetadata(),[],[...s.refs(aKeys),...s.refs(bKeys)]);
  }
  s.publishAnswer('provider-b-produces-own-ordinary-signature',dnssecSigningTuple('www-a-long-provider-b'),{to:'dnsProviderB',from:'dnsProviderB'});
  if(migration){
    s.timer('providerMigration',{newPathPublishedAt:DNSSEC_BASE_CLOCK+600,oldDsTtl:86400,nsSwitchAt:DNSSEC_BASE_CLOCK+87600,oldNsDependencyEnds:DNSSEC_BASE_CLOCK+175200});s.at(87600);
    s.observe('switch-parent-ns-after-cache-readiness','Move routing only after the public key/path cache dependencies','dnsParent',{oldProviderStillServes:true,parentNs:['ns2.provider.example.org.']},[dnssecPut('publication.parentNs',['ns2.provider.example.org.']),dnssecPut('publication.oldProviderStillServes',true)]);s.at(175200);
    s.observe('stop-retired-provider-service','Old provider stops only after its earlier dependencies elapsed','dnsPrimary',{oldProviderStillServes:false},[dnssecPut('publication.oldProviderStillServes',false)]);
    s.parentPublish('withdraw-old-path-after-prior-dependencies',dnssecSigningTuple('parent-ds-provider-b-only-long-signature'),'ds-b');
  }
  return s.finishLookup({answerSource:'dnsProviderB'});
}
function dnssecSigningCoordinated(){
  const shared=dnssecSigningTuple('provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long',dnssecSigningProviderKeys),s=dnssecSigningSession(18,'coordinated-rollover',{child:shared,custody:dnssecSigningProviderCustody(false,true),provider:'dnsPrimary',multiSignerModel:1,actorOverrides:{dnsChild:{name:'Zone-owner public-key distribution coordinator',position:{x:975,y:120}}}}),overlap=dnssecSigningTuple('child-dnskey-provider-model1-overlap4-by-child-ksk-g1-long',['child-ksk-g1','child-zsk-g1','child-zsk-g2','provider-b-zsk-g1']),generation='keys-with-Z1';
  s.publishChild('import-z1-and-sign-both-provider-keysets',overlap,generation);
  s.a.publish('owner-distribution-copy','The owner places the exact signed public set at its distribution coordinator','dnsSigner','dnsChild',s.refs(overlap));s.at(600);
  s.a.publish('all-provider-keysets-converged','The coordinator completes the exact public generation distribution to B','dnsChild','dnsProviderB',s.refs(overlap),{effects:[dnssecPut('publication.authorities',{A:generation,B:generation})]});
  s.timer('coordinatedZsk',{convergedAt:DNSSEC_BASE_CLOCK+600,priorDnskeyTtl:3600,activationAt:DNSSEC_BASE_CLOCK+4200,lastOldSignatureAt:DNSSEC_BASE_CLOCK+4800,maximumDataTtl:7200,retirementAt:DNSSEC_BASE_CLOCK+12000});
  s.at(4200);s.publishAnswer('activate-a-new-zsk',dnssecSigningNewAnswer(),{from:'dnsPrimary'});s.at(12000);
  const final=dnssecSigningTuple('child-dnskey-provider-model1-final3-by-child-ksk-g1-long',['child-ksk-g1','child-zsk-g2','provider-b-zsk-g1']);s.publishChild('retire-a-old-zsk-after-data-caches',final,'keys-without-Z0');s.a.publish('converge-retired-provider-keyset','Both providers serve the exact final public keyset','dnsPrimary','dnsProviderB',s.refs(final));return s.finishLookup();
}
function dnssecSigningConflictingIntent(){
  const aKeys=dnssecSigningTuple('provider-dnskey-shared-k0-z0-zb-by-child-ksk-g1-long',dnssecSigningProviderKeys),bKeys=dnssecSigningTuple('provider-dnskey-model2-b-kb-z0-zb-by-provider-b-ksk-g1-long',dnssecSigningProviderBKeys),ds=dnssecSigningTuple('parent-ds-provider-overlap-long-signature'),s=dnssecSigningSession(18,'conflicting-cds-intent',{child:aKeys,delegation:ds,custody:dnssecSigningProviderCustody(true),provider:'dnsPrimary',validator:'dnsParentAgent'});
  for(const [index,tuple] of [dnssecSigningTuple('root-dnskey-path-long',['root-ksk-g1','root-zsk-g1']),dnssecSigningTuple('root-example-ds-path-long'),dnssecSigningTuple('example-dnskey-path-long',['example-ksk-g1','example-zsk-g1']),ds].entries())s.receive('management-chain-evidence-'+index,tuple,index<2?'dnsRoot':'dnsParent',{to:'dnsParentAgent'});
  const signals=[{address:'192.0.2.53',provider:'dnsPrimary',keys:aKeys,cds:dnssecSigningTuple('postfreeze-child-cds-claim-signature'),cdnskey:dnssecSigningTuple('postfreeze-child-cdnskey-claim-signature')},{address:'198.51.100.53',provider:'dnsProviderB',keys:bKeys,cds:dnssecSigningTuple('provider-b-cds-intent-signature'),cdnskey:dnssecSigningTuple('provider-b-cdnskey-intent-signature')}],received=[];
  for(const [index,signal] of signals.entries()){
    s.receive('intent-provider-keys-'+index,signal.keys,signal.provider,{to:'dnsParentAgent'});
    for(const kind of ['cds','cdnskey'])received.push({signal,kind,...s.receive('intent-'+index+'-'+kind,signal[kind],signal.provider,{to:'dnsParentAgent'})});
  }
  const receivedAuthorities=Object.fromEntries(signals.map(signal=>{const parsed=dnssecPublicationSignalIntent({cds:signal.cds.rrset,cdnskey:signal.cdnskey.rrset,keys:signal.keys.keys,policy:s.a.policy});return [signal.address,{CDS:parsed.cdsKeyIds,CDNSKEY:parsed.cdnskeyIds}];}));
  s.observe('fetch-every-provider-intent','Fetch CDS and CDNSKEY from every configured provider address','dnsParentAgent',{addresses:signals.map(signal=>signal.address),allReceived:received.length===signals.length*2,publicClaims:receivedAuthorities,claimsAuthenticated:false},[dnssecPut('received',received.length===signals.length*2),dnssecPut('signatureChecked',false),dnssecPut('publication.parentDsGeneration','ds-ab'),dnssecPut('publication.authorities',receivedAuthorities)]);
  const paths=signals.map(signal=>s.validate(signal.keys,ds,{rrset:signal.cds.rrset,signatures:signal.cds.signatures})),checks=received.map(item=>dnssecCheckSignature({rrset:item.bundle.rrset,signatures:item.bundle.signatures,keys:item.signal.keys.keys,now:s.a.clock,policy:s.a.policy,expectedSigner:'lab.example.'}));
  const intents=signals.map(signal=>dnssecPublicationSignalIntent({cds:signal.cds.rrset,cdnskey:signal.cdnskey.rrset,keys:signal.keys.keys,policy:s.a.policy})),identities=intents.map(intent=>intent.keyIds),consistent=intents.every(intent=>intent.consistent&&intent.allEligibleDigestsMatched)&&identities.every(identity=>JSON.stringify(identity)===JSON.stringify(identities[0])),authenticated=paths.every(path=>path.securityStatus==='secure')&&checks.every(check=>check.valid);
  s.observe('valid-signatures-but-inconsistent-intent','Authenticated provider signals still require equal eligible key intent','dnsParentAgent',{checks,paths,intents,identities,consistent,authenticated},[dnssecPut('signatureChecked',checks.some(check=>check.checked)),dnssecPut('chainEstablished',authenticated),dnssecPut('securityStatus',authenticated?'secure':'bogus'),dnssecPut('publication.signalsAuthenticated',authenticated),dnssecPut('publication.consistent',consistent),dnssecPut('publication.parentAccepted',authenticated&&consistent),dnssecPut('publication.parentPublished',false)],received.flatMap(item=>item.refs));
  const reason=authenticated&&!consistent?'conflicting-provider-cds-intent':!authenticated?'unauthenticated-provider-intent':'consistent-provider-intent';
  s.observe('management-result-classification','Reject inconsistent management intent without a leaf lookup or parent DS replacement','dnsParentAgent',{reason,parentDsPreserved:ds.rrset.id,privateKeysCopied:false},[dnssecPut('reasonCode',reason),dnssecPut('validationOwner','dnsParentAgent'),dnssecPut('verificationKind','local-check'),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('returnedToStub',false),dnssecPut('failureStage',!consistent?'signal-consistency':!authenticated?'signal-authentication':null),dnssecPut('firstDetector',!consistent||!authenticated?'dnsParentAgent':null),dnssecPut('stoppedAction',!consistent?'remove-other-provider-ds':null),dnssecPut('applicationResult',{status:'pending',reason:'No leaf lookup/application acceptance in this management case.'})]);return s.finish();
}

export const DNSSEC_SIGNING_CASE_BUILDERS={
  'lab-dnssec02':{
    'split-ksk-zsk':dnssecSigningFoundation,
    'combined-key':dnssecSigningCombined,
    'equivalent-presentation':dnssecSigningEquivalent,
    'changed-rdata':()=>dnssecSigningCanonical('changed-rdata',{mutation:{records:['192.0.2.82','192.0.2.81']},boundary:'covered-a-octets-differ',values:{mutation:'A RDATA'}}),
    'opaque-rdata-case-change':()=>dnssecSigningCanonical('opaque-rdata-case-change',{answer:dnssecSigningTuple('child-txt-signature'),mutation:{records:['\"opaquecase\"']},boundary:'opaque-txt-octets-differ',values:{opaquePayloadCaseFolded:false,mutation:'TXT opaque octets'}}),
    'changed-owner':()=>dnssecSigningCanonical('changed-owner',{mutation:{owner:'other.lab.example.'},boundary:'owner-name-input-differs',values:{mutation:'covered owner'}}),
    'keytag-collision':()=>dnssecSigningCanonical('keytag-collision',{answer:dnssecSigningTuple('www-a-collision'),boundary:'collision-canonical-input',collision:true}),
  },
  'lab-dnssec12':{
    'resign-before-expiry':()=>dnssecSigningRefresh(false),
    'zsk-prepublish':dnssecSigningZskPrepublish,
    'zsk-double-sign':dnssecSigningZskDouble,
    'old-key-removed-too-early':dnssecSigningZskPremature,
    'secondary-lags':dnssecSigningSecondaryLag,
    'signature-refresh-outage':()=>dnssecSigningRefresh(true),
  },
  'lab-dnssec13':{
    'ksk-double-ds':dnssecSigningDoubleDs,
    'ksk-double-ksk-method':dnssecSigningDoubleKsk,
    'combined-key-rollover':dnssecSigningCskRollover,
    'parent-ds-delayed':dnssecSigningDelayedDs,
    'old-ds-cache':()=>dnssecSigningOldDsCache(false),
    'premature-old-key-removal':()=>dnssecSigningOldDsCache(true),
  },
  'lab-dnssec14':{
    'modern-baseline':dnssecSigningModern,
    'dual-algorithm-rollover':dnssecSigningDualAlgorithm,
    'algorithm-unsupported':()=>dnssecSigningUnsupported(false),
    'unsupported-digest-only':()=>dnssecSigningUnsupported(true),
    'modern-and-obsolete-paths':dnssecSigningObsoleteExtras,
    'sha1-signing-disabled':dnssecSigningSha1SigningDisabled,
    'sha1-digest-compatibility':dnssecSigningSha1Digest,
    'nsec3-sha1-not-signature-policy':dnssecSigningNsec3Roles,
  },
  'lab-dnssec18':{
    'shared-ksk-model':()=>dnssecSigningSharedProvider(),
    'separate-ksk-model':()=>dnssecSigningSeparateProvider(),
    'cached-keys-provider-switch':()=>dnssecSigningSharedProvider({cached:true}),
    'missing-cross-provider-key':()=>dnssecSigningSharedProvider({missing:true,cached:true}),
    'coordinated-rollover':dnssecSigningCoordinated,
    'provider-migration':()=>dnssecSigningSeparateProvider(true),
    'conflicting-cds-intent':dnssecSigningConflictingIntent,
  },
};
