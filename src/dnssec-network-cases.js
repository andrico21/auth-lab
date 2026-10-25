import {dnssecAuthor,dnssecPut} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,DNSSEC_MATERIAL,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecLookupPath,dnssecLookupMessage} from './dnssec-lookup.js';
import {dnssecValidateChain,dnssecCheckSignature,dnssecTtlWindow,dnssecDsMatchesKey} from './dnssec-validation.js';

const dnssecNetworkKey=id=>dnssecMaterial('keys',id);
const dnssecNetworkRrset=id=>dnssecMaterial('rrsets',id);
const dnssecNetworkSig=id=>dnssecMaterial('signatures',id);
function dnssecNetworkNumericEvidence(rrset,signature,receivedTtl){
  return {rrsetId:rrset.id,signatureId:signature.id,numericFile:DNSSEC_MATERIAL.provenance.objects.signatures[signature.id][0].fixture.path,
    owner:rrset.owner,type:rrset.type,class:rrset.class||'IN',records:rrset.records,canonicalRdataHex:rrset.canonicalRdataHex,
    publishedRrsetTtl:rrset.ttl,receivedRrsetTtl:receivedTtl,receivedRrsigTtl:receivedTtl,
    signedMetadata:{algorithm:signature.algorithm,expiration:signature.expiration,inception:signature.inception,keyId:signature.keyId,keyTag:signature.keyTag,labels:signature.labels,originalTtl:signature.originalTtl,signer:signature.signer,typeCovered:signature.typeCovered},
    signatureRdataSha256:DNSSEC_MATERIAL.provenance.signatureRdataSha256[signature.id],signingInputSha256:signature.signingInputSha256,
    rrsigRdataHex:signature.rrsigRdataHex,signingInputHex:signature.signingInputHex,
    bindingRule:'Signed records, OriginalTTL, signer/key identity and validity fields are immutable; only received/cache TTL may decrease. Any explicit mutation is a separate occurrence, not a re-signed record.'};
}
const dnssecNetworkChangedRecords=['192.0.2.82','192.0.2.81'];
const dnssecNetworkTls={protocol:'DoT',encrypted:true,authenticatedEndpoint:'resolver.example.'};
// Explicit custodian provisioning, independent of DNSKEY membership or received signatures.
const dnssecNetworkPublicSigningPool=['root-ksk-g1','root-zsk-g1','example-ksk-g1','example-zsk-g1','child-ksk-g1','child-zsk-g1'];
const dnssecNetworkActors={
  dnsApp:{position:{x:145,y:120}},dnsStub:{position:{x:145,y:365}},
  dnsResolver:{position:{x:425,y:120}},dnsValidator:{position:{x:425,y:365}},
  dnsUpstream:{position:{x:705,y:120}},
  dnsUpstreamValidator:{name:'Upstream DNSSEC validator',kind:'server',role:'Independent upstream checking context',parentId:'dnsUpstream',position:{x:705,y:365},notes:['Own upstream-public-v1 trust store. No upstream decision is copied into a local independent check.']},
  dnsChild:{position:{x:985,y:120}},dnsRoot:{position:{x:985,y:365}},dnsParent:{position:{x:985,y:610}},
  dnsOperator:{position:{x:145,y:610}},dnsSigner:{position:{x:425,y:610}},dnsAdversary:{position:{x:705,y:610}},
};

function dnssecNetworkPrivatePath(generation=1){
  const second=generation===2;
  return [{zone:'lab.example.',dnskeyRrset:dnssecNetworkRrset(second?'child-csk-g2-dnskey':'private-child-dnskey'),dnskeySignatures:[dnssecNetworkSig(second?'child-csk-g2-dnskey-signature':'private-child-dnskey-signature')],keys:[dnssecNetworkKey(second?'child-csk-g2':'child-csk-g1')]}];
}
function dnssecNetworkInput(options={}){
  const privateView=options.view==='private-v1',generation=options.generation||1;
  const links=privateView?dnssecNetworkPrivatePath(generation):dnssecLookupPath();
  if(options.publicExpectation){const publicLinks=dnssecLookupPath();publicLinks[2]={...publicLinks[2],...links[0]};links.splice(0,links.length,...publicLinks);}
  const rrset=dnssecNetworkRrset(options.requestedType==='DNSKEY'?'child-dnskey-g1':privateView&&generation===1?'private-www-a':'www-a');
  const signature=dnssecNetworkSig(options.requestedType==='DNSKEY'?'child-dnskey-g1-by-ksk':privateView?(generation===2?'www-a-complete-path-csk-g2':'private-www-a-signature'):'www-a-signature');
  const anchorId=Object.hasOwn(options,'anchor')?options.anchor:privateView&&!options.publicExpectation?'child-csk-g1':'root-ksk-g1';
  return {...options,view:options.view||'public-v1',trustStore:options.trustStore||(privateView?'resolver-private-v1':'resolver-public-v1'),links,rrset:{...rrset,ttl:300,...options.records?{records:[...options.records]}:{}},signatures:options.strip?[]:[signature],published:rrset,originalSignatures:[signature],anchor:anchorId?{zone:dnssecNetworkKey(anchorId).owner,keys:[dnssecNetworkKey(anchorId)],provenance:'Explicit trusted operator provisioning; never learned from route or public receipt'}:null,question:{qname:rrset.owner,qtype:rrset.type,qclass:'IN'}};
}
function dnssecNetworkEvaluate(input,now,policy){
  const result=dnssecValidateChain({anchor:input.anchor,links:input.links,answer:{rrset:input.rrset,signatures:input.signatures},now,policy});
  const answerCheck=dnssecCheckSignature({rrset:input.rrset,signatures:input.signatures,keys:input.anchor?input.links.at(-1).keys:[],now,policy,expectedSigner:input.links.at(-1).zone});
  return {result,answerCheck};
}
function dnssecNetworkProof(result,owner){
  const invoked=result!==null&&result!==undefined,authenticated=invoked&&result.valid===true;
  return {evidenceClass:authenticated?'authenticated-evidence':invoked?'failed-attempt':'raw-input',checkerInvoked:invoked,authenticated,valid:invoked?authenticated:null,validationOwner:authenticated?owner:null,verificationKind:invoked?'local-check':'not-performed',observerWitness:{owner:invoked?owner:null,valid:invoked?authenticated:null,reason:result?.reason||'not-checked',authenticated}};
}
function dnssecNetworkCacheKey(input,checkingContext){const questionKey=[input.view,input.trustStore,input.question.qname,input.question.qtype,input.question.qclass];return checkingContext===undefined?questionKey:[...questionKey,checkingContext];}
function dnssecNetworkHopDescriptors(hops){
  return hops.filter(hop=>!hop.retryOf).map(hop=>{
    const retries=hops.filter(attempt=>attempt.retryOf===hop.id);
    return retries.length?{...hop,delivery:{...hop.delivery,attempts:retries.length+1},attempts:[hop,...retries].map(attempt=>({query:attempt.query,response:attempt.response}))}:hop;
  });
}
function dnssecNetworkHopSummary(hops,{downstreamFirst=false,completionOrder=null}={}){
  const primary=dnssecNetworkHopDescriptors(hops).filter(hop=>hop.purpose==='primary'||hop.hopRole==='additional-prerequisite-evidence');
  const hasPrerequisites=primary.some(hop=>hop.hopRole==='additional-prerequisite-evidence');
  const roleOrder=hop=>hop.hopRole==='primary-conversation'?0:hop.hopRole==='resolver-prerequisite'?1:2+(hop.prerequisiteOrder||0);
  return primary.sort((left,right)=>hasPrerequisites?roleOrder(left)-roleOrder(right):completionOrder?completionOrder.get(left.response?.id||left.query.id)-completionOrder.get(right.response?.id||right.query.id):((left.from==='dnsStub'?1:0)-(right.from==='dnsStub'?1:0))*(downstreamFirst?-1:1));
}

/** Inputs are routing, policy, actual records and clocks. No worksheet/outcome data enters this module. */
function dnssecNetworkBuild(number,caseId,options={}){
  const input=dnssecNetworkInput(options),a=dnssecAuthor(number,caseId,{actorOverrides:{...dnssecNetworkActors,...options.view==='private-v1'?{dnsChild:{...dnssecNetworkActors.dnsChild,name:'lab.example. - Private authority',role:'Selected private-v1 authoritative service'},dnsUpstream:{...dnssecNetworkActors.dnsUpstream,name:'Conditional private forwarder',role:'Routes lab.example. to198.51.100.53; does not provision anchors'}}:{}}});
  const hops=[],evidenceRefs=[],pendingEvidence=[],cacheEntries=[],unrelatedEntries=[],recordRefs=new Map(),anchorRefs=new Map();let sequence=16640,authorityQueries=0,upstreamQueries=0,returnedEarly=false;
  const forward=!!options.forward||!!options.tls,source=forward?'dnsUpstream':'dnsChild';
  const availableUpstreamAnswer=!!options.upstreamError||(number===11&&!!options.tls);
  const localOwner=options.stubMode==='validating'?'dnsStub':'dnsValidator';
  const localStore=options.stubMode==='validating'?'stub-public-v1':input.trustStore;
  const resultOwner=options.stubMode==='validating'?'dnsStub':'dnsResolver';
  const trustedStubChannel=!!options.stubTrust||!!options.warm;
  const localInput={...input,trustStore:localStore};
  Object.assign(a.initialState.dnssec,{query:input.question,view:input.view,trustStore:localStore,cacheNamespace:{view:input.view,trustStore:localStore},cacheKind:null,stoppedAction:null,unrelatedCacheEntries:unrelatedEntries,stub:{mode:options.stubMode||'aware-nonvalidating'},preservedState:['Configured anchors remain unchanged.','Private signing capabilities remain with their explicitly provisioned custodian.','Unrelated caches preserve provenance and expiry.','Raw public bodies remain readable without becoming accepted positive data.']});
  if(options.stubMode==='validating')a.initialState.dnssec.initialCache={authenticatedParentDs:false,authenticatedChildDnskey:false};
  const observe=(key,title,actor,values={},effects=[],refs=[],extra={})=>a.local(key,title,actor,{values,effects,refs,...extra});
  if(options.nta||options.expireFailure)a.initialState.dnssec.clock={now:a.clock};
  const advance=(next,key,title)=>{const step=a.advanceTo(next,key,title);if(options.nta||options.expireFailure)step.protocolEffects.push(dnssecPut('clock',{now:next}));return step;};
  a.initialState.dnssec.timers.signature={inception:input.originalSignatures[0].inception,expiration:input.originalSignatures[0].expiration};
  if(options.tls){
    const configuredTls=a.artifact('configured-established-dot','Explicit established Strict Privacy DoT endpoint policy','dnsOperator',{endpoint:'resolver.example.',port:853,profile:'RFC8310 Strict Privacy',provisioning:'trusted static local configuration',certificateNameMatches:true,pkixChainTrusted:true,encrypted:true,opportunisticFallbackAllowed:false,handshakeAlreadyEstablished:true,dnssecTrustCreated:false},{kind:'trust',initial:true,holders:['dnsResolver'],store:'Transport endpoint configuration'});
    a.initialState.dnssec.configuredTlsArtifact=configuredTls;a.bind('configuredTlsArtifact',configuredTls,'dnsResolver','Transport endpoint configuration');
  }
  if(trustedStubChannel){
    const channel=a.artifact('configured-stub-channel','Explicit stub reliance on the local resolver and authenticated IPC channel','dnsOperator',{resolver:'dnsResolver',channel:'local IPC',channelAuthenticated:true,channelTrusted:true,encrypted:false,integrityProtected:true,trustResolverForDnssec:true,independentStubValidation:false},{kind:'trust',initial:true,holders:['dnsStub'],store:'Stub channel trust policy'});
    a.initialState.dnssec.stubChannelArtifact=channel;a.bind('stubChannelArtifact',channel,'dnsStub','Stub channel trust policy');
  }
  const checkpoint=(key,actor,values={},effects=[],refs=[],extra={})=>observe(key,key.split('-').join(' '),actor,values,effects,refs,extra);
  const provision=(owner,store,anchor,view)=>{
    a.initialState.dnssec.trustStores[store]={anchors:anchor?anchor.keys.map(key=>key.id):[],applicableAnchors:anchor?anchor.keys.map(key=>key.id):[],scope:anchor?.zone||null,view,installedBy:'trusted-operator-configuration',provenance:'out-of-band local configuration'};
    if(!anchor)return null;
    const artifact=a.artifact('anchor-'+store,'Configured trust anchor / '+store,'dnsOperator',{...anchor,trustStore:store,view},{kind:'trust',initial:true,holders:[owner],store:'Configured trust anchors'});anchorRefs.set(owner,artifact);return artifact;
  };
  const configured=provision(localOwner,localStore,options.remoteOnly||options.forged?null:input.anchor,input.view);
  if(options.anchorGeneration!==undefined)a.initialState.dnssec.trustStores[localStore].generation=options.anchorGeneration;
  if(options.publicExpectation)a.initialState.dnssec.trustStores[localStore].privateAnchor=null;
  a.initialState.dnssec.anchorRef=options.remoteOnly||options.forged?null:input.anchor?.keys[0].id||null;
  if(configured)a.bind('configuredAnchorArtifact',configured,localOwner,'Configured trust anchors');
  if(configured)a.initialState.dnssec.configuredAnchorArtifact=configured;
  if(options.upstreamValidates)provision('dnsUpstreamValidator','upstream-public-v1',{zone:'.',keys:[dnssecNetworkKey('root-ksk-g1')],provenance:'Independent upstream operator configuration'},'public-v1');
  if(options.stubMode==='validating')provision('dnsValidator','resolver-fetch-only-v1',null,input.view);
  const signerKeys=input.view==='private-v1'?(options.publicExpectation?[...dnssecNetworkPublicSigningPool,'child-csk-g1']:[options.generation===2?'child-csk-g2':'child-csk-g1']):dnssecNetworkPublicSigningPool;
  for(const keyId of signerKeys)a.artifact('private-capability-'+keyId,'Signer-only opaque capability / '+keyId,'dnsSigner',{handle:'HSM('+keyId+')',keyId,custodian:'dnsSigner',capability:'sign'},{kind:'secret',privateKey:true,initial:true,holders:['dnsSigner'],store:'Signer-only capabilities'});
  const artifactRecord=(key,label,value,kind,holder,store='Published public records')=>a.artifact(key,label,kind==='cache'?holder:'dnsSigner',kind==='rrsig'?{...value,ttl:300}:value,{kind,initial:true,holders:[holder],store});
  const published=artifactRecord('published-answer','Published exact '+input.published.owner+' '+input.published.type,input.published,'rrset','dnsChild');
  const signatures=input.originalSignatures.map(sig=>a.artifact('signature-'+sig.id,'Published RRSIG('+input.published.type+')','dnsSigner',{...sig,ttl:300},{kind:'rrsig',initial:true,holders:availableUpstreamAnswer?['dnsChild','dnsUpstream']:['dnsChild'],store:availableUpstreamAnswer?'Available upstream signed buffers':'Published public records'}));
  const body=a.artifact('received-answer','Selected response occurrence / '+input.question.qname+' '+input.question.qtype,'dnsChild',input.rrset,{kind:'rrset',derivedFrom:[published],initial:availableUpstreamAnswer,holders:['dnsUpstream'],store:'Available upstream signed buffers'});
  let answerRefs=[body,...options.strip?[]:signatures],chainRefs=[];
  const chainBundles=[];
  for(const [index,link] of input.links.entries()){
    const add=(rrset,sigs,keys,ds)=>{
      const holder=rrset.owner==='.'?'dnsRoot':rrset.type==='DS'?(rrset.owner==='example.'?'dnsRoot':'dnsParent'):rrset.owner==='example.'?'dnsParent':'dnsChild';
      const rr=artifactRecord('chain-published-'+rrset.id,'Published '+rrset.owner+' '+rrset.type,rrset,'rrset',holder);
      const ss=sigs.map(sig=>artifactRecord('chain-signature-'+sig.id,'RRSIG('+rrset.type+') / '+sig.id,sig,'rrsig',holder));
      const atoms=keys.map(key=>artifactRecord('chain-key-'+key.id,'Public DNSKEY / '+key.id,key,'dnskey',holder));
      const dd=ds.map(record=>artifactRecord('chain-ds-'+record.keyId+'-'+record.digestType,'Public parent DS / '+record.keyId,record,'ds',holder));
      chainBundles.push({rrset,signatures:sigs,refs:[rr,...ss,...atoms,...dd],holder,index:chainBundles.length});
    };
    if(link.dsRrset)add(link.dsRrset,link.dsSignatures,[],link.ds||[]);
    add(link.dnskeyRrset,link.dnskeySignatures,link.keys,[]);
  }
  const priorInput={...input,anchor:options.remoteOnly||options.forged||options.stubMode==='validating'?null:input.anchor,rrset:{...input.published,ttl:300},signatures:input.originalSignatures};
  const prior=dnssecNetworkEvaluate(priorInput,DNSSEC_BASE_CLOCK-60,a.policy);
  // These are explicit earlier-received buffers, not invisible runtime DNS acquisitions.
  const initialReceivers=new Set(options.stubMode==='validating'?[]:['dnsResolver',...forward?['dnsUpstream']:[]]);
  for(const bundle of chainBundles){
    const privateDnskey=input.view==='private-v1'&&bundle.rrset.type==='DNSKEY'&&bundle.rrset.owner==='lab.example.';
    for(const receiver of privateDnskey?[]:initialReceivers){
      const occurrence=artifactRecord('earlier-'+receiver+'-'+bundle.rrset.id,'Earlier received '+bundle.rrset.owner+' '+bundle.rrset.type,{...bundle.rrset,ttl:300},'rrset',receiver,'Earlier received chain material');
      const refs=[occurrence,...bundle.refs.slice(1)];
      for(const ref of refs.slice(1))a.inventory.initial.push(a.acquire(ref,receiver,'Earlier received chain material'));
      if(receiver==='dnsResolver')chainRefs.push(...refs);
      recordRefs.set(receiver+'|'+bundle.rrset.id,refs);
    }
    const evidenceKey=caseId+':numericBindings-'+(privateDnskey?'privateDnskey':'chain-'+bundle.index)+':'+bundle.rrset.id;
    if(privateDnskey||options.stubMode==='validating'){pendingEvidence.push({bundle,key:evidenceKey});evidenceRefs.push(a.id+':'+evidenceKey);}
    else{
      const stage=bundle.rrset.type==='DS'?'parent-ds-signature':'dnskey-rrset-signature',actualCheck=prior.result.checks.find(check=>check.stage===stage&&check.zone===bundle.rrset.owner);
      const evidence=a.artifact(evidenceKey,'Reference-bound chain evidence / '+bundle.rrset.owner+' '+bundle.rrset.type,'dnsValidator',{rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(sig=>sig.id),checkedAt:DNSSEC_BASE_CLOCK-60,evidenceMode:'symbolic-reference-bound',checks:actualCheck?[actualCheck]:[],...dnssecNetworkProof(actualCheck?.result,'dnsValidator'),receivedAt:DNSSEC_BASE_CLOCK-60,expiresAt:DNSSEC_BASE_CLOCK+240,view:input.view,trustStore:localStore},{kind:'trust',initial:true,holders:['dnsResolver'],store:'Earlier chain observations',derivedFrom:recordRefs.get('dnsResolver|'+bundle.rrset.id)});evidenceRefs.push(evidence);
    }
  }
  const primaryEvidenceId=a.id+':'+caseId+':numericBindings-primary:'+input.published.id;evidenceRefs.push(primaryEvidenceId);
  if(input.view==='private-v1'){const privateRef=evidenceRefs.splice(evidenceRefs.length-2,1)[0];evidenceRefs.push(privateRef);}
  const unrelated={id:a.id+':unrelated-context',kind:'answer',key:['other-view','other-store','unrelated.example.','A','IN'],namespace:{cacheOwner:'dnsResolver',checkingOwner:'dnsValidator',view:'other-view',trustStore:'other-store'},receivedAt:DNSSEC_BASE_CLOCK-20,expiresAt:DNSSEC_BASE_CLOCK+500,securityStatus:'secure',validationOwner:'dnsValidator'};
  const unrelatedArtifact=artifactRecord('unrelated-context','Unrelated retained cache namespace',unrelated,'cache','dnsResolver','Unrelated cache');unrelatedEntries.push(unrelated);a.initialState.dnssec.unrelatedCacheArtifact=unrelatedArtifact;a.bind('unrelatedCacheArtifact',unrelatedArtifact,'dnsResolver','Unrelated cache');
  const stubFlags={AD:options.stubMode==='unaware'||options.stubMode==='validating'?0:1,CD:options.stubMode==='validating'||options.diagnostic||options.warm?1:0,DO:options.stubMode==='unaware'?null:options.stubDo??1};
  const transport=options.tls?{...dnssecNetworkTls,protocol:number===11?'TLS':'DoT',application:'DoT'}:'UDP';
  const packet=(id,question,response,recursive,flags={},rcode='NOERROR',edns=true)=>({...dnssecLookupMessage(id,question,{response,recursive,authoritative:response&&!recursive,flags,rcode,edns}),port:options.tls?853:53});
  const query=(key,from,to,question,{recursive=false,flags={},route='UDP',edns=true,failedAttempt=false,purpose='primary',retryOf=null,wireInput=null}={})=>{
    const messageId=sequence++,q={...(wireInput||packet(messageId,question,false,recursive,flags,'NOERROR',edns)),port:typeof route==='object'&&route.protocol==='local IPC'?null:typeof route==='object'&&route.encrypted?853:53};
    let step;
    if(failedAttempt){
      const unsent=a.artifact(key+'-undelivered-query','Exact DNS query waiting for an unavailable transport',from,q,{kind:'header',extraFields:[...a.fieldsFor('question',q.question),...a.fieldsFor('opt',q.edns)]});
      step=observe(key+':q','Attempt the unavailable transport without inventing a server receipt',from,{messageId,question,transport:typeof route==='string'?route:route.protocol,intendedReceiver:to,delivered:false},[dnssecPut('transport.attempted',true)],[{artifactId:unsent,kind:'create'}],{held:a.create(unsent,from,'Unsent DNS output','plain','temporary'),kind:'create'});
    }else step=a.send(key+':q','Query '+question.qname+' '+question.qtype,from,to,[],q,[dnssecPut('transport.attempted',true)],route);
    // Encrypted send() returns a recovery event; replies correlate to the actual wire-send event.
    const queryStepId=failedAttempt?step.id:a.id+':'+caseId+':'+key+':q';
    const hop={id:a.id+':'+key,from,to,purpose,...retryOf?{retryOf}:{},transport:typeof route==='string'?route:route.protocol,question:q.question,query:{id:queryStepId,messageId,flags:q.flags,edns:q.edns,...failedAttempt?{delivered:false}:{}},response:null,delivery:{attempted:true,queryDelivered:!failedAttempt,responseReceived:false,...failedAttempt?{responseAbsentReason:route==='TCP'?'tcp-blocked':options.networkFailure==='unreachable'?'network-unreachable':'timeout',...options.networkFailure?{attempts:1}:{}}:{}}};
    if(from==='dnsStub'&&to==='dnsResolver')Object.assign(hop,{hopRole:'primary-conversation',dataDirection:'resolver-to-stub',receiverBeforeCheck:'dnsStub',...typeof route==='object'&&route.protocol==='local IPC'?{channelAuthenticated:true,channelTrusted:true}:{}});
    const checkingOwner=from==='dnsStub'?localOwner:from==='dnsUpstream'?(options.upstreamValidates?'dnsUpstreamValidator':null):options.stubMode==='validating'?null:options.remoteOnly?'dnsUpstreamValidator':'dnsValidator';
    const relianceOwner=from==='dnsStub'&&trustedStubChannel?'dnsStub':from==='dnsResolver'&&options.remoteOnly?'dnsResolver':null;
    Object.assign(hop,{checkingOwner,relianceOwner,...options.upstreamError&&key==='upstream'?{priorContextId:retainedFailure.id}:{}});
    hops.push(hop);step.protocolEffects.push(dnssecPut('response.traceHops',structuredClone(dnssecNetworkHopDescriptors(hops))));return {key,from,to,question,q,hop,route,recursive,edns};
  };
  const respond=(request,refs,{flags={},rcode='NOERROR',effects=[],sender=request.to,edns=request.edns,values={}}={})=>{
    const r=packet(request.q.messageId,request.question,true,request.recursive,{CD:request.recursive?request.q.flags.CD:0,DO:request.q.flags.DO,...flags},rcode,edns);
    const rrsets=refs.map(ref=>a.object(typeof ref==='string'?ref:ref.artifactId)).filter(entry=>entry.kind==='rrset');
    const rrsetTtl=rrsets.length?Math.min(...rrsets.map(entry=>entry.value.ttl)):null;
    refs=refs.map((ref,index)=>{
      const entry=a.object(typeof ref==='string'?ref:ref.artifactId);
      if(entry.kind!=='rrsig')return ref;
      const covered=rrsets.filter(rrset=>rrset.value.typeCode===entry.value.typeCovered);
      const ttl=Math.min(entry.value.ttl,...covered.map(rrset=>rrset.value.ttl));
      if(entry.value.ttl===ttl)return ref;
      const occurrence=a.artifact(request.key+'-outgoing-rrsig-'+index,'Outgoing ordinary RRSIG TTL occurrence',sender,{...entry.value,ttl},{kind:'rrsig',derivedFrom:[entry.artifactId]});
      observe(request.key+'-bound-rrsig-'+index,'Bound ordinary signature TTL without altering signed RDATA',sender,{remainingTtl:ttl,signedOriginalTtl:entry.value.originalTtl},[],[entry.artifactId,{artifactId:occurrence,kind:'derive'}],{held:a.create(occurrence,sender,'DNS response data'),kind:'derive'});
      return typeof ref==='string'?occurrence:{...ref,artifactId:occurrence};
    });
    const carriedSignatures=refs.map(ref=>a.object(typeof ref==='string'?ref:ref.artifactId)).filter(entry=>entry.kind==='rrsig');
    const signatureTtl=carriedSignatures.length?Math.min(...carriedSignatures.map(entry=>entry.value.ttl)):null;
    const step=a.send(request.key+':r','Receive '+rcode+' / '+request.question.qname,sender,request.from,refs,{...r,port:typeof request.route==='object'&&request.route.protocol==='local IPC'?null:typeof request.route==='object'&&request.route.encrypted?853:53,inReplyTo:request.hop.query.id,...values,receivedRrsetTtl:rrsetTtl,receivedRrsigTtl:signatureTtl},effects,request.route);
    request.hop.response={id:a.id+':'+caseId+':'+request.key+':r',inReplyTo:request.hop.query.id,messageId:r.messageId,flags:r.flags,rcode,edns:r.edns};request.hop.delivery.responseReceived=true;
    step.protocolEffects.push(dnssecPut('response.traceHops',structuredClone(dnssecNetworkHopDescriptors(hops))));return r;
  };
  const retrieveChain=(prefix,fetcher='dnsResolver',selected=()=>true,purpose='evidence')=>{
    for(const bundle of chainBundles.filter(selected)){
      const key=prefix+'-'+bundle.index,question={qname:bundle.rrset.owner,qtype:bundle.rrset.type,qclass:'IN'};
      const request=query(key,fetcher,bundle.holder,question,{flags:{AD:0,CD:1,DO:1},purpose});authorityQueries++;
      if(options.stubMode==='validating'&&bundle.rrset.type==='DNSKEY'&&bundle.rrset.owner==='lab.example.')Object.assign(request.hop,{purpose:'primary',hopRole:'resolver-prerequisite',dataDirection:'resolver-to-child',receiverBeforeCheck:'dnsResolver'});
      const occurrence=a.artifact(key+'-received-rrset','Fresh received '+bundle.rrset.owner+' '+bundle.rrset.type,bundle.holder,{...bundle.rrset,ttl:300},{kind:'rrset',derivedFrom:[bundle.refs[0]]});
      observe(key+'-prepare','Prepare a fresh receipt occurrence without re-signing',bundle.holder,{receivedAt:a.clock,receivedTtl:300,originalTtl:bundle.signatures[0].originalTtl},[],[...bundle.refs,{artifactId:occurrence,kind:'derive'}],{held:a.create(occurrence,bundle.holder,'DNS response data'),kind:'derive'});
      const refs=[occurrence,...bundle.refs.slice(1)];respond(request,refs);recordRefs.set(fetcher+'|'+bundle.rrset.id,refs);
      if(fetcher==='dnsUpstream'){
        const forwardRequest=query(key+'-forward','dnsResolver','dnsUpstream',question,{recursive:true,flags:{AD:1,CD:1,DO:1},route:transport,purpose});upstreamQueries++;
        respond(forwardRequest,refs,{flags:{AD:0}});recordRefs.set('dnsResolver|'+bundle.rrset.id,refs);
      }
    }
    chainRefs=chainBundles.flatMap(bundle=>recordRefs.get('dnsResolver|'+bundle.rrset.id)||[]);
  };
  const prepareBody=()=>observe('prepare-answer-occurrence','Prepare exact response bytes without changing signed metadata','dnsChild',{publishedRecords:input.published.records,receivedRecords:input.rrset.records,signatureUnchanged:true},[],[published,...signatures,{artifactId:body,kind:'derive'}],{held:a.create(body,'dnsChild','DNS response data'),kind:'derive'});
  const raw=(owner='dnsResolver')=>checkpoint('raw-response-received-before-trust',owner,{publicReadable:true,dnssecIsNotConfidentiality:true},[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked'),dnssecPut('transport.authorityQueries',authorityQueries),dnssecPut('transport.upstreamQueries',upstreamQueries)],answerRefs);
  const localCheck=(owner,selectedInput,key='local-independent-check',extraEffects=[])=>{
    const evaluated=dnssecNetworkEvaluate(selectedInput,a.clock,a.policy),result=evaluated.result,check=evaluated.answerCheck;
    const checked=result.signatureChecked||check.checked;
    const observation={signatureChecked:options.strip?check.checked:checked,chainEstablished:result.chainEstablished,securityStatus:result.securityStatus,reasonCode:result.reasonCode,cryptographicResult:check.mathematicalResult,verificationKind:selectedInput.anchor?'local-check':'not-performed',checkedAt:a.clock,view:selectedInput.view,trustStore:selectedInput.trustStore,evidenceMode:'symbolic-reference-bound',keyIdentity:check.selectedKeyId||selectedInput.signatures[0]?.keyId||null,checks:result.checks,answerCheck:check,expectedSignedAnswer:result.chainEstablished,receivedRequiredSignature:selectedInput.signatures.length>0};
    const selectedChainRefs=owner==='dnsUpstreamValidator'?chainBundles.flatMap(bundle=>recordRefs.get('dnsUpstream|'+bundle.rrset.id)||[]):chainRefs;
    const refs=answerRefs.concat(selectedChainRefs),anchorRef=anchorRefs.get(owner);
    if(anchorRef)refs.push(anchorRef);
    const decision=a.artifact(key+'-checked-evidence','Actual '+owner+' validation observation',owner,{...observation,...dnssecNetworkProof(selectedInput.anchor?{valid:result.securityStatus==='secure',reason:result.reasonCode}:null,owner),checks:result.checks,selectedEvidence:result.selectedEvidence||[]},{kind:'trust',derivedFrom:refs});
    checkpoint(key,owner,{...observation,verificationIsNotDecryption:true},[dnssecPut('validators.'+owner,{...observation,decisionArtifact:decision}),...owner===localOwner?[dnssecPut('signatureChecked',observation.signatureChecked),dnssecPut('chainEstablished',observation.chainEstablished),dnssecPut('securityStatus',observation.securityStatus)]:[],...extraEffects],[...refs.map(artifactId=>({artifactId,kind:'verify'})),{artifactId:decision,kind:'create'}],{held:a.create(decision,owner,'Validation evidence'),kind:'verify'});
    for(const pending of pendingEvidence){
      if(a.objects.has(a.id+':'+pending.key))continue;
      const stage=pending.bundle.rrset.type==='DS'?'parent-ds-signature':'dnskey-rrset-signature',actualCheck=result.checks.find(item=>item.stage===stage&&item.zone===pending.bundle.rrset.owner);
      const witness=a.artifact(pending.key,'Observed DNSKEY/DS trust decision',owner,{rrsetId:pending.bundle.rrset.id,signatureIds:pending.bundle.signatures.map(signature=>signature.id),checkedAt:a.clock,view:selectedInput.view,trustStore:selectedInput.trustStore,securityStatus:result.securityStatus,evidenceMode:'symbolic-reference-bound',checks:actualCheck?[actualCheck]:[],...dnssecNetworkProof(actualCheck?.result,owner)},{kind:'trust',derivedFrom:[...selectedChainRefs,...anchorRef?[anchorRef]:[]]});
      checkpoint(key+(pendingEvidence.length>1?'-chain-evidence-'+pending.bundle.index:'-dnskey-evidence'),owner,{rrsetId:pending.bundle.rrset.id,trustStore:selectedInput.trustStore},[],[{artifactId:witness,kind:'create'}],{held:a.create(witness,owner,'Validation evidence'),kind:'derive'});
    }
    return {evaluated,observation,witness:decision};
  };
  const priorFailureInput={...input,rrset:{...input.rrset,records:[...dnssecNetworkChangedRecords]},signatures:input.originalSignatures};
  let retainedFailure=null,retainedFailureArtifact=null,initialFailureEvaluation=null,warmCacheArtifact=null;
  if(options.cachedFailure||options.upstreamError){
    if(options.cachedFailure)initialFailureEvaluation=dnssecNetworkEvaluate(priorFailureInput,DNSSEC_BASE_CLOCK,a.policy);
    const remote=!!options.upstreamError;
    retainedFailure={id:a.id+(remote?':upstream-cd0-error':':bad-cache'),kind:'failure',key:dnssecNetworkCacheKey(input,'CD0'),namespace:{cacheOwner:'dnsResolver',checkingOwner:remote?'dnsUpstream':'dnsValidator',view:input.view,trustStore:input.trustStore},receivedAt:DNSSEC_BASE_CLOCK-(remote?1:0),expiresAt:DNSSEC_BASE_CLOCK+(remote?4:5),signatureDeadline:null,validationOwner:remote?'dnsUpstream':'dnsValidator',securityStatus:remote?'not-checked':initialFailureEvaluation.result.securityStatus,reasonCode:remote?'upstream-SERVFAIL-context':initialFailureEvaluation.answerCheck.mathematicalResult===false?'leaf-signature-verification-failed':initialFailureEvaluation.result.reasonCode,firstDetector:remote?'dnsUpstream':'dnsValidator',validatedAt:remote?null:DNSSEC_BASE_CLOCK,trustedPositiveData:false,locallyEstablished:!remote};
    Object.assign(retainedFailure,{source:remote?'dnsUpstream':'dnsValidator',rcode:'SERVFAIL',queryCD:0,checkingContext:'CD0',view:input.view,trustStore:input.trustStore});
    retainedFailureArtifact=artifactRecord('retained-failure','Earlier retained '+(remote?'upstream CD0 error context':'local validation failure'),retainedFailure,'cache','dnsResolver','Failure cache');
    if(remote)a.initialState.dnssec.upstreamErrorEntries=[retainedFailure];else cacheEntries.push(retainedFailure);
    a.initialState.dnssec.cacheEntries=[...cacheEntries];a.initialState.dnssec.retainedFailureArtifact=retainedFailureArtifact;a.bind('retainedFailureArtifact',retainedFailureArtifact,'dnsResolver','Failure cache');
    if(!remote){
      const oldBody=artifactRecord('prior-failed-body','Earlier received changed A occurrence',priorFailureInput.rrset,'rrset','dnsResolver','Earlier failed response');
      for(const ref of signatures)a.inventory.initial.push(a.acquire(ref,'dnsResolver','Earlier failed response'));
      if(!options.expireFailure)answerRefs=[oldBody,...signatures];
      const oldCheck=a.artifact('prior-failure-evidence','Prior local reference-bound failed check','dnsValidator',{...initialFailureEvaluation.result,answerCheck:initialFailureEvaluation.answerCheck,checkedAt:DNSSEC_BASE_CLOCK,view:input.view,trustStore:localStore},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Failure evidence',derivedFrom:[oldBody,...signatures,...configured?[configured]:[]]});
      a.initialState.dnssec.priorFailureEvidence=oldCheck;a.bind('priorFailureEvidence',oldCheck,'dnsValidator','Failure evidence');a.initialState.dnssec.priorFailedBody=oldBody;a.bind('priorFailedBody',oldBody,'dnsResolver','Earlier failed response');
    }
  }
  a.chapter('request','1. Client policy and separate checking contexts');
  checkpoint('app-request','dnsApp',{question:input.question,applicationPolicy:'Never use bogus or diagnostic data as a trusted address; ordinary no-anchor DNS is explicitly permissive.'});
  let stubRequest=query('stub','dnsStub','dnsResolver',input.question,{recursive:true,flags:stubFlags,edns:options.stubMode!=='unaware',route:trustedStubChannel?{protocol:'local IPC',encrypted:false,authenticatedEndpoint:'configured local resolver process'}:'UDP'});
  let localResult=null,upstreamResult=null,selectedResult=null,verificationKind=input.anchor?'local-check':'not-performed',validationOwner=localOwner,failureStage=null,firstDetector=null,reasonCode=null,complete=true,received=false;
  a.initialState.dnssec.validators.dnsStub={signatureChecked:false,chainEstablished:false,securityStatus:'not-checked',verificationKind:'not-performed'};
  a.initialState.dnssec.validators.dnsValidator={signatureChecked:false,chainEstablished:false,securityStatus:'not-checked',verificationKind:'not-performed'};
  if(forward)a.initialState.dnssec.validators.dnsUpstream={signatureChecked:false,chainEstablished:false,securityStatus:'not-checked',verificationKind:'not-performed',trustStore:'upstream-public-v1',view:'public-v1'};
  if(options.upstreamError){
    checkpoint('cached-cd-zero-servfail-is-not-local-bad-cache','dnsResolver',{context:retainedFailure,selectedKey:dnssecNetworkCacheKey(input,'CD1'),mustBypassDifferentCheckingContext:retainedFailure.key.at(-1)!=='CD1'},[dnssecPut('timers.upstreamErrorContext',{queryCD:0,rcode:'SERVFAIL',expiresAt:retainedFailure.expiresAt}),dnssecPut('timers.failureCache',null),dnssecPut('validators.dnsValidator.locallyEstablishedFailure',false)],[retainedFailureArtifact]);
  }
  if(options.cachedFailure){
    const repairedAt=DNSSEC_BASE_CLOCK+(options.expireFailure?3:1);
    advance(repairedAt,'publisher-repair-clock','Advance represented clock to independent publisher repair');
    checkpoint('publisher-repairs-without-flushing-remote-cache','dnsChild',{generation:2,repairedAt,cacheFlush:false},[dnssecPut('publication',{generation:2,repairedAt,doesNotInvalidateRemoteFailureCache:true})],[published,...signatures]);
    advance(DNSSEC_BASE_CLOCK+(options.expireFailure?6:2),'failure-cache-clock','Advance represented clock independently of playback');
    if(a.clock>=retainedFailure.expiresAt){
      cacheEntries.splice(cacheEntries.indexOf(retainedFailure),1);
      checkpoint('expire-retained-local-failure','dnsResolver',{now:a.clock,expiredAt:retainedFailure.expiresAt},[dnssecPut('retainedFailureArtifact',null),dnssecPut('timers.failureCache',null),dnssecPut('cacheEntries',[...cacheEntries])],[{artifactId:retainedFailureArtifact,kind:'dispose'}],{held:[a.release(retainedFailureArtifact,'dnsResolver','Failure cache')],kind:'dispose'});
    }else{
      const requestedKey=dnssecNetworkCacheKey(localInput,'CD'+stubFlags.CD);
      if(retainedFailure.key.length!==requestedKey.length||!retainedFailure.key.every((value,index)=>value===requestedKey[index])||retainedFailure.namespace.checkingOwner!=='dnsValidator'||retainedFailure.namespace.cacheOwner!=='dnsResolver'||!retainedFailure.locallyEstablished)throw new TypeError('Declared failure-cache suppression does not match its actual owner/checking/view/trust context');
      complete=false;
      const reused={signatureChecked:false,chainEstablished:initialFailureEvaluation.result.chainEstablished,securityStatus:retainedFailure.securityStatus,verificationKind:'local-check',reusedFailureCheckedAt:retainedFailure.validatedAt,freshCheckPerformed:false,checkedAt:a.clock,trustStore:localStore,view:input.view};
      selectedResult={...initialFailureEvaluation.result,signatureChecked:false};
      checkpoint('local-failure-suppression-not-rfc6840-upstream-context','dnsResolver',{key:retainedFailure.key,live:a.clock<retainedFailure.expiresAt,publisherRepairDoesNotInvalidate:true},[dnssecPut('validators.dnsValidator',reused),dnssecPut('transport.authorityQueries',0),dnssecPut('transport.upstreamQueries',0),dnssecPut('timers.failureCache',{expiresAt:retainedFailure.expiresAt,remaining:retainedFailure.expiresAt-a.clock,locallyEstablished:true}),dnssecPut('timers.upstreamErrorContext',null)],[retainedFailureArtifact]);
      reasonCode='cached-locally-established-failure-suppresses-network';failureStage='cached-local-validation-failure';firstDetector='dnsValidator';
    }
  }
  if(options.warm){
    complete=false;
    const window=dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:input.originalSignatures[0].originalTtl,signatureExpiration:input.originalSignatures[0].expiration,receivedAt:DNSSEC_BASE_CLOCK-60,now:a.clock});
    const warmEntry={id:a.id+':warm-answer',kind:'answer',key:dnssecNetworkCacheKey(localInput),namespace:{cacheOwner:'dnsResolver',checkingOwner:'dnsValidator',view:input.view,trustStore:localStore},receivedAt:DNSSEC_BASE_CLOCK-60,expiresAt:window.expiresAt,signatureDeadline:input.originalSignatures[0].expiration,validationOwner:'dnsValidator',securityStatus:prior.result.securityStatus,validatedAt:DNSSEC_BASE_CLOCK-60,remainingTtl:window.remainingSeconds,reused:true,verificationKind:'local-check',evidence:prior.result,evidenceRefs:[...evidenceRefs]};
    const requestedKey=dnssecNetworkCacheKey(localInput);
    if(warmEntry.securityStatus!=='secure'||warmEntry.validationOwner!=='dnsValidator'||!window.valid||a.clock>=warmEntry.expiresAt||warmEntry.key.length!==requestedKey.length||!warmEntry.key.every((value,index)=>value===requestedKey[index]))throw new TypeError('Declared authenticated answer cache is not live in its actual trust/view/owner namespace');
    const warmBody=artifactRecord('warm-answer-body','Earlier received authenticated answer occurrence',{...input.rrset,ttl:300},'rrset','dnsResolver','Validated answer cache');
    for(const ref of signatures)if(!a.has(ref,'dnsResolver'))a.inventory.initial.push(a.acquire(ref,'dnsResolver','Validated answer cache'));
    a.artifact(caseId+':numericBindings-primary:'+input.published.id,'Retained earlier authenticated answer evidence','dnsValidator',{...prior.result,...dnssecNetworkProof({valid:prior.result.securityStatus==='secure',reason:prior.result.reasonCode},'dnsValidator'),answerCheck:prior.answerCheck,rrsetId:input.published.id,signatureIds:input.originalSignatures.map(signature=>signature.id),checkedAt:DNSSEC_BASE_CLOCK-60,view:input.view,trustStore:localStore,evidenceMode:'symbolic-reference-bound'},{kind:'trust',initial:true,holders:['dnsResolver'],store:'Validated answer cache proof',derivedFrom:[warmBody,...signatures,...chainRefs,...configured?[configured]:[]]});
    const warmArtifact=artifactRecord('warm-cache','Earlier authenticated exact answer',warmEntry,'cache','dnsResolver','Validated answer cache');warmCacheArtifact=warmArtifact;cacheEntries.push(warmEntry);answerRefs=[warmBody,...signatures];selectedResult={...prior.result,signatureChecked:false};
    a.initialState.dnssec.warmCacheArtifact=warmArtifact;a.bind('warmCacheArtifact',warmArtifact,'dnsResolver','Validated answer cache');
    a.initialState.dnssec.cacheEntries=[...cacheEntries];
    checkpoint('copy-cd-and-do-do-not-clear-cached-ad','dnsResolver',{queryCD:stubFlags.CD,queryDO:stubFlags.DO,responseDOUsedAsSecurityInput:false,remainingTtl:window.remainingSeconds},[dnssecPut('validators.dnsValidator',{securityStatus:prior.result.securityStatus,signatureChecked:false,chainEstablished:prior.result.chainEstablished,reusedAuthenticatedCache:true,freshVerification:false,checkedAt:DNSSEC_BASE_CLOCK-60}),dnssecPut('transport.authorityQueries',0),dnssecPut('stub',{queryCD:stubFlags.CD,responseCD:stubFlags.CD,queryDO:stubFlags.DO,responseDO:stubFlags.DO,responseDOUsedAsSecurityInput:false,queryAD:stubFlags.AD,responseAD:prior.result.securityStatus==='secure'?1:0})],[warmArtifact,warmBody]);
    reasonCode='authenticated-cache-can-retain-ad-for-cd-one';
  }
  a.chapter('transport','2. Correlated messages and literal per-hop flags');
  if(complete){
    if(options.networkFailure){
      complete=false;
      let retryOf=null;
      for(let attempt=0;attempt<3;attempt++){const request=query('attempt-'+(attempt+1),'dnsResolver',source,input.question,{recursive:forward,flags:{AD:forward?1:0,CD:1,DO:1},failedAttempt:true,purpose:attempt?'retry':'primary',retryOf});retryOf||=request.hop.id;}
      const failure=forward?'upstream-unreachable':'timeout';
      checkpoint(forward?'route-failure-no-dnssec-verdict':'three-total-attempts-then-bounded-failure-cache','dnsResolver',{failure,attempts:3,timeoutSeconds:3,completion:false},[dnssecPut('transport',{attempted:true,completed:false,failure,attempts:3,timeoutSeconds:3}),dnssecPut('timers.failureCache',{duration:5,expiresAt:a.clock+5,kind:'transport-failure'})]);
      selectedResult={securityStatus:'not-checked',signatureChecked:false,chainEstablished:false,checks:[]};verificationKind='not-performed';failureStage='transport';firstDetector='dnsResolver';reasonCode=forward?'forwarding-route-unreachable-after-bounded-attempts':'all-authority-attempts-time-out-before-proof-receipt';
    }else if(options.forged){
      const attackerRequest=query('forged-authority','dnsResolver','dnsAdversary',input.question,{flags:{AD:0,CD:1,DO:1},purpose:'attack'});
      const forged=a.artifact('forged-answer','Forged A occurrence on an untrusted last hop','dnsAdversary',{...input.rrset,records:['192.0.2.99']},{kind:'rrset'});
      observe('forge-ad-and-address','Forge an AD assertion without an anchor or a private signing capability','dnsAdversary',{AD:1,records:['192.0.2.99'],signedEvidenceCreated:false},[],[{artifactId:forged,kind:'create'}],{held:a.create(forged,'dnsAdversary','Forged DNS output'),kind:'create'});answerRefs=[forged];
      respond(attackerRequest,answerRefs,{flags:{AD:1,AA:0}});received=true;
      raw('dnsResolver');
      respond(stubRequest,answerRefs,{flags:{AD:1},effects:[dnssecPut('returnedToStub',true)]});returnedEarly=true;
      checkpoint('untrusted-ad-not-promoted','dnsStub',{responseAD:1,channelTrusted:false,resolverTrusted:false,assertionAccepted:false,untrustedRelay:'dnsResolver',forgedInputFrom:'dnsAdversary'},[dnssecPut('stub',{responseAD:1,channelTrusted:false,resolverTrusted:false,assertionAccepted:false})],answerRefs);
      selectedResult={securityStatus:'indeterminate',signatureChecked:false,chainEstablished:false,checks:[]};verificationKind='not-performed';validationOwner='dnsStub';reasonCode='ad-without-trusted-resolver-and-channel-is-insufficient';failureStage='last-hop-trust';firstDetector='dnsStub';
    }else{
      if(!availableUpstreamAnswer)prepareBody();
      let upstreamRequest=null;
      if(forward){upstreamRequest=query('upstream','dnsResolver','dnsUpstream',input.question,{recursive:true,flags:{AD:1,CD:options.upstreamCd??1,DO:1},route:transport});upstreamQueries++;}
      const fetcher=forward?'dnsUpstream':'dnsResolver';
      if(!availableUpstreamAnswer){
        let forwardedQuery=null;
        if(options.ednsRemoved){
          const original=packet(sequence,input.question,false,false,{AD:0,CD:1,DO:1});
          const intent=a.artifact('authority-query-before-opt-removal','Original unprotected EDNS query on the selected path',fetcher,original,{kind:'header',extraFields:[...a.fieldsFor('question',original.question),...a.fieldsFor('opt',original.edns)]});
          observe('prepare-original-edns-query','Prepare the original query before on-path OPT removal',fetcher,{messageId:sequence,DO:original.flags.DO,edns:original.edns},[],[{artifactId:intent,kind:'create'}],{held:a.create(intent,fetcher,'DNS output'),kind:'create'});
          forwardedQuery={...original,flags:{...original.flags,DO:null,CO:null},edns:{...original.edns,present:false,version:null,udpPayloadSize:null,DO:null,CO:null}};
          const modified=a.artifact('authority-query-after-opt-removal','Actual public query after on-path OPT removal','dnsAdversary',forwardedQuery,{kind:'header',derivedFrom:[intent],extraFields:[...a.fieldsFor('question',forwardedQuery.question),...a.fieldsFor('opt',forwardedQuery.edns)]});
          checkpoint('remove-edns-opt-on-path','dnsAdversary',{originalTarget:'dnsChild',originalMessageId:original.messageId,originalDO:original.flags.DO,forwardedOPT:forwardedQuery.edns.present,forwardedFlags:forwardedQuery.flags,authorityTreatsAbsentDOAsZero:true,signatureMaterialNotRequested:true},[],[intent,{artifactId:modified,kind:'derive'}],{held:[a.acquire(intent,'dnsAdversary','Observed unprotected on-path query'),...a.create(modified,'dnsAdversary','Modified unprotected query')],kind:'derive'});
          forwardedQuery={...forwardedQuery,pathMutationEvidenceId:modified};
        }
        const request=query('authority',fetcher,'dnsChild',input.question,{flags:{AD:0,CD:1,DO:options.strip?0:1},edns:forwardedQuery?forwardedQuery.edns.present:true,wireInput:forwardedQuery,purpose:options.nta?'pre-bypass':options.stubMode==='validating'||number===22&&forward?'evidence':'primary'});authorityQueries++;
        if(options.ednsRemoved)request.hop.mutation={queryOptRemovedBy:'dnsAdversary',authoritySeesDO:request.q.edns.present?request.q.flags.DO:0,authorityReturnsAuxiliaryDnssec:false};
        if(options.truncated){
          respond(request,[],{flags:{TC:1},effects:[dnssecPut('received',true),dnssecPut('transport.protocol','UDP'),dnssecPut('transport.TC',1),dnssecPut('transport.completeProof',false)],values:{responseBytes:1232,fullResponseBytes:1800}});
          checkpoint('raw-response-received-before-trust','dnsResolver',{TC:1,partialPacketNotAnAnswer:true},[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked')]);
          checkpoint('truncated-response-cannot-complete-proof','dnsResolver',{TC:1,completeProof:false},[],[]);
          const tcp=query('tcp-retry',fetcher,'dnsChild',input.question,{flags:{AD:0,CD:1,DO:1},route:'TCP',failedAttempt:!!options.tcpBlocked});tcp.hop.correlatedRetryOf=request.hop.query.id;
          if(options.tcpBlocked){
            complete=false;selectedResult={securityStatus:'not-checked',signatureChecked:false,chainEstablished:false,checks:[]};verificationKind='not-performed';failureStage='transport-completion';firstDetector='dnsResolver';reasonCode='transport-fails-before-complete-validation-input';
            checkpoint('tcp-failure-not-cryptographic-bogus','dnsResolver',{failure:'blocked',completeProof:false},[dnssecPut('transport',{attempted:true,completed:false,protocol:'TCP',failure:'blocked',completeProof:false}),dnssecPut('signatureChecked',false),dnssecPut('securityStatus','not-checked')]);
          }else{respond(tcp,answerRefs,{effects:[dnssecPut('transport',{attempted:true,completed:true,protocol:'TCP',TC:0,completeProof:true,correlatedRetryOf:request.hop.query.id,authenticatedEndpoint:null})],values:{responseBytes:1800,tcpLengthPrefixBytes:2}});received=true;checkpoint('correlated-tcp-response-completes-proof-input','dnsResolver',{correlatedRetryOf:request.hop.query.id,completeProof:true},[],answerRefs);}
        }else{respond(request,answerRefs,{edns:!options.ednsRemoved,flags:options.ednsRemoved?{DO:null,CO:null}:{},effects:[dnssecPut('transport',{attempted:true,completed:true,protocol:'UDP',TC:0,responseBytes:options.responseBytes||1100,udpPayloadAdvertised:1232,authenticatedEndpoint:null})]});received=true;}
      }else{
        // A fresh CD1 query is answered from the upstream's actual signed buffers.
        observe('upstream-recovery-buffer','Select the actually held signed upstream answer in this checking context','dnsUpstream',{checkingContext:'CD1',oldContextRetained:!!options.upstreamError,availableAtStart:true},[],answerRefs);received=true;
      }
      if(complete&&input.view==='private-v1')retrieveChain('private-dnskey',fetcher,bundle=>bundle.rrset.type==='DNSKEY'&&bundle.rrset.owner==='lab.example.');
      if(complete&&forward){
        if(options.upstreamValidates){
          const upstreamInput={...input,anchor:{zone:'.',keys:[dnssecNetworkKey('root-ksk-g1')]},trustStore:'upstream-public-v1'};
          upstreamResult=localCheck('dnsUpstreamValidator',upstreamInput,'upstream-independent-validation');
          checkpoint('upstream-check-does-not-satisfy-local-check','dnsResolver',{upstreamOwner:'dnsUpstreamValidator',localCheckStillPending:true},[dnssecPut('validators.dnsUpstream',{...upstreamResult.observation,owner:'dnsUpstreamValidator',validationReason:upstreamResult.observation.reasonCode,reasonCode:upstreamResult.evaluated.answerCheck.mathematicalResult===false?'bad-signature':upstreamResult.observation.reasonCode}),dnssecPut('validators.dnsValidator',{signatureChecked:false,chainEstablished:false,securityStatus:'not-checked'})]);
        }
        const upstreamWithholds=options.upstreamValidates&&options.upstreamCd===0&&upstreamResult.observation.securityStatus==='bogus';
        const upstreamAd=options.upstreamValidates&&upstreamResult.observation.securityStatus==='secure'?1:0;
        respond(upstreamRequest,upstreamWithholds?[]:answerRefs,{flags:{AD:upstreamAd},rcode:upstreamWithholds?'SERVFAIL':'NOERROR',effects:[dnssecPut('response.upstreamAD',upstreamAd),dnssecPut('response.upstreamQueryCD',upstreamRequest.q.flags.CD),dnssecPut('response.downstreamQueryCD',stubFlags.CD),dnssecPut('response.upstreamRcode',upstreamWithholds?'SERVFAIL':'NOERROR'),dnssecPut('response.rawAnswerReceived',!upstreamWithholds),...options.tls?[dnssecPut('transport',{attempted:true,completed:true,protocol:'DoT',transport:'DoT',port:853,encrypted:true,authenticatedEndpoint:'resolver.example.',strictProfile:true,established:true})]:[]]});
        if(upstreamWithholds){received=false;selectedResult={securityStatus:'not-checked',signatureChecked:false,chainEstablished:false,checks:[]};verificationKind='remote-assertion';validationOwner='dnsUpstream';reasonCode='upstream-validation-failure-no-raw-data-for-local-check';failureStage='upstream-validation';firstDetector='dnsUpstream';checkpoint('upstream-servfail-not-local-bogus-proof','dnsResolver',{rawAnswerReceived:false,upstreamRcode:'SERVFAIL'},[],[]);}
        if(options.upstreamError)checkpoint('mandatory-fresh-cd-one-query','dnsResolver',{cacheKey:dnssecNetworkCacheKey(input,'CD1'),checkingOwner:'dnsUpstream',oldErrorCacheKey:retainedFailure.key},[dnssecPut('transport.upstreamFreshQueries',upstreamQueries),dnssecPut('transport.upstreamQueryCD',1),dnssecPut('response.freshRcode','NOERROR')],[retainedFailureArtifact,...answerRefs]);
      }
      if(complete&&received&&!selectedResult){
        if(!options.truncated&&options.stubMode!=='validating')raw();
        if(options.expireFailure)checkpoint('advance-protocol-clock-past-failure-cache','dnsResolver',{now:a.clock,expiredAt:retainedFailure.expiresAt,freshResponseReceived:true},[dnssecPut('timers.failureCache',null),dnssecPut('transport.authorityQueries',authorityQueries)]);
        if(options.truncated)checkpoint('correlated-tcp-response-completes-proof-input-after-receipt','dnsResolver',{completeProof:true,signatureChecked:false},[],answerRefs);
        if(number===11&&!options.truncated&&!options.strip&&!options.tls)checkpoint('complete-udp-is-not-yet-trusted','dnsResolver',{responseBytes:1100,udpPayloadAdvertised:1232},[],answerRefs);
        if(options.tls)checkpoint('tls-authentication-does-not-validate-dns-rrset','dnsResolver',{configuredEndpoint:'resolver.example.',encrypted:true,dnssecVerdictCreated:false},[],answerRefs);
        if(options.forward&&input.view==='private-v1')checkpoint('route-selects-destination-but-not-anchor','dnsResolver',{suffix:'lab.example.',address:'198.51.100.53',installsAnchor:false},[dnssecPut('transport.selectedRoute','conditional lab.example. to198.51.100.53'),dnssecPut('transport.queryCD',1),dnssecPut('transport.upstreamAD',0)],configured?[configured]:[]);
        if(options.stubMode==='validating'){
          // Transfer actual chain records with their own questions; in-process checking is not a DNS hop.
          retrieveChain('validating-stub-child-key','dnsResolver',()=>true,'evidence');
          for(const bundle of chainBundles){
            const request=query('stub-evidence-'+bundle.index,'dnsStub','dnsResolver',{qname:bundle.rrset.owner,qtype:bundle.rrset.type,qclass:'IN'},{recursive:true,flags:{AD:0,CD:1,DO:1},purpose:'evidence'});
            const zoneLabel=bundle.rrset.owner==='.'?'root':bundle.rrset.owner.split('.')[0],next=chainBundles[bundle.index+1],signature=bundle.signatures[0];
            const requiredFor=next?next.rrset.type==='DNSKEY'?'authenticate '+zoneLabel+' DNSKEY':'authenticate '+zoneLabel+'-'+(next.rrset.owner===input.links.at(-1).zone?'child':next.rrset.owner.split('.')[0])+' DS':'verify '+input.rrset.owner.split('.')[0]+' '+input.rrset.type+' RRSIG';
            Object.assign(request.hop,{hopRole:'additional-prerequisite-evidence',dataDirection:'resolver-to-stub',receiverBeforeCheck:'dnsStub',prerequisiteOrder:bundle.index+1,validationTarget:zoneLabel+' '+bundle.rrset.type+' RRset',requiredFor,evidenceRefs:[a.id+':'+caseId+':numericBindings-chain-'+bundle.index+':'+bundle.rrset.id],numericEvidence:dnssecNetworkNumericEvidence(bundle.rrset,signature,300)});
            respond(request,recordRefs.get('dnsResolver|'+bundle.rrset.id),{flags:{AD:0}});
          }
          respond(stubRequest,answerRefs,{flags:{AD:0}});returnedEarly=true;raw('dnsStub');
          checkpoint('stub-receives-data-before-own-check','dnsStub',{ownAnchor:input.anchor.keys[0].id},[],answerRefs);
        }
      }
    }
  }
  a.chapter('validation','3. Actual validator responsibility and reference-bound evidence');
  if(complete&&received&&!selectedResult){
    if(options.remoteOnly){
      selectedResult={...upstreamResult.evaluated.result,signatureChecked:false,chainEstablished:false};verificationKind='remote-assertion';validationOwner='dnsUpstream';
      checkpoint('upstream-check-distinct-from-local-reliance','dnsResolver',{trustedUpstream:'dnsUpstream',trustedChannel:'configured established DoT resolver.example.',independentLocalCheck:false},[dnssecPut('validators.dnsValidator',{signatureChecked:false,chainEstablished:false,securityStatus:selectedResult.securityStatus,verificationKind:'remote-assertion'})]);
    }else{
      localResult=localCheck(localOwner,localInput,options.stubMode==='validating'?'stub-owns-independent-anchor-and-validation':'local-independent-check-completes');selectedResult=localResult.evaluated.result;
      if(options.strip)selectedResult={...selectedResult,signatureChecked:localResult.evaluated.answerCheck.checked};
      if(options.generation===2)selectedResult={...selectedResult,signatureChecked:localResult.evaluated.answerCheck.checked||selectedResult.signatureChecked};
      if(options.stubMode==='validating')reasonCode='stub-independently-validates-with-own-anchor';
      if(options.stubMode==='unaware')checkpoint('resolver-checks-even-without-downstream-do','dnsValidator',{DO:stubFlags.DO,validationNotDisabled:true},[dnssecPut('stub',{mode:'unaware',receivedDnssecAuxiliaryRecords:false,AD:0})]);
      if(options.stubTrust){
        respond(stubRequest,[answerRefs[0],...stubFlags.DO===1?answerRefs.slice(1):[]],{flags:{AD:selectedResult.securityStatus==='secure'?1:0},effects:[dnssecPut('returnedToStub',true)]});returnedEarly=true;
        const assertionAccepted=stubRequest.hop.response.flags.AD===1&&stubRequest.route.authenticatedEndpoint==='configured local resolver process';
        verificationKind=assertionAccepted?'remote-assertion':'not-performed';
        checkpoint('actual-resolver-verifies-before-ad','dnsValidator',{trustedResolver:'dnsResolver',trustedChannel:'authenticated local IPC',resolverCheck:localResult.observation,assertionAccepted},[dnssecPut('validators.dnsStub',{signatureChecked:false,chainEstablished:false,verificationKind}),dnssecPut('stub',{resolverTrusted:true,channelTrusted:true,queryAD:stubFlags.AD,queryDO:stubFlags.DO,auxiliaryDnssecRecordsReceived:stubFlags.DO===1,responseAD:stubRequest.hop.response.flags.AD,assertionAccepted})]);
      }
      if(options.requestedType==='DNSKEY'){
        respond(stubRequest,[answerRefs[0]],{flags:{AD:selectedResult.securityStatus==='secure'?1:0},effects:[dnssecPut('returnedToStub',true)]});returnedEarly=true;
        checkpoint('explicit-requested-type-survives-do-zero','dnsStub',{queryDO:0,returnedRequestedType:'DNSKEY',returnedAuxiliaryRrsig:false,privateKeyTransferred:false},[dnssecPut('stub',{queryDO:0,returnedRequestedType:'DNSKEY',returnedAuxiliaryRrsig:false,privateKeyTransferred:false})],[answerRefs[0]]);
      }
      if(options.strip){const key=options.ednsRemoved?'edns-stripping-not-validation-off':'stripping-is-not-insecure-delegation';checkpoint(key,'dnsValidator',{expectedSignedAnswer:localResult.evaluated.result.chainEstablished,receivedRequiredSignature:false,missingRrsig:true},[dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',localResult.evaluated.result.chainEstablished),dnssecPut('validators.dnsValidator.expectedSignedData',true),dnssecPut('validators.dnsValidator.missingRrsig',true)],answerRefs);}
      if(options.forward)checkpoint(options.upstreamError?'locally-check-retrieved-data':options.records?'upstream-cd-one-does-not-disable-local-downstream-check':options.upstreamValidates?'independent-upstream-and-local-validation':'upstream-transmission-does-not-own-local-validation','dnsValidator',{upstreamCD:options.upstreamCd??1,downstreamCD:stubFlags.CD},[dnssecPut('response.downstreamCD',stubFlags.CD),dnssecPut('response.upstreamCD',options.upstreamCd??1),...options.upstreamError?[dnssecPut('timers.upstreamErrorContext',null),dnssecPut('timers.failureCache',null)]:[]]);
      if(options.tls)checkpoint('dnssec-independently-checks-after-tls','dnsValidator',{transportAuthenticationIsNotDnssec:true,answerCheck:localResult.evaluated.answerCheck},[],answerRefs);
      if(input.view==='private-v1'){
        if(!input.anchor)checkpoint('no-applicable-anchor-anywhere','dnsValidator',{applicableAnchors:[],notAuthenticatedInsecurity:true},[dnssecPut('securityStatus',selectedResult.securityStatus),dnssecPut('signatureChecked',false)]);
        else if(options.publicExpectation)checkpoint('public-anchor-creates-specific-conflicting-expectation','dnsValidator',{publicDsPublisher:'example.',digestChecks:selectedResult.checks.filter(check=>check.stage==='ds-digest')},[dnssecPut('publication.publicDsAuthenticated',selectedResult.checks.some(check=>check.stage==='parent-ds-signature'&&check.zone==='lab.example.'&&check.valid)),dnssecPut('publication.publicDsMatchesPrivateDnskey',input.links.at(-1).keys.some(key=>dnssecDsMatchesKey(dnssecMaterial('ds','child-ksk-g1-sha256'),key,a.policy).valid)),dnssecPut('securityStatus',selectedResult.securityStatus)]);
        else if(options.generation===2)checkpoint('stale-anchor-is-configured-expectation-not-no-anchor','dnsValidator',{configuredAnchor:input.anchor.keys[0].id,currentKeys:input.links.at(-1).keys.map(key=>key.id),mathematicalCheck:localResult.evaluated.answerCheck},[dnssecPut('publication.servedDnskeyGeneration',2),dnssecPut('publication.anchorMatchesCurrentDnskey',selectedResult.checks.some(check=>check.stage==='anchor'&&check.valid))]);
        else checkpoint(options.forward?'local-verification-under-private-store':'private-anchor-acceptance-is-explicit','dnsValidator',{view:input.view,trustStore:localStore,explicitAnchor:input.anchor.keys[0].id},[],configured?[configured]:[]);
      }
      if(options.expireFailure)checkpoint('fresh-validation-after-expired-failure','dnsValidator',{freshCheckPerformed:true,checkedAt:a.clock,generation:2},[dnssecPut('validators.dnsValidator.freshCheckPerformed',true),dnssecPut('timers.failureCache',null)]);
    }
  }
  if(options.nta){
    stubRequest.hop.purpose='pre-bypass';
    const initialFailure={id:a.id+':pre-nta-failure',kind:'failure',key:dnssecNetworkCacheKey(localInput,'CD'+stubFlags.CD),namespace:{cacheOwner:'dnsResolver',checkingOwner:'dnsValidator',view:input.view,trustStore:localStore},receivedAt:a.clock,expiresAt:a.clock+5,securityStatus:localResult.evaluated.result.securityStatus,validationOwner:'dnsValidator',reasonCode:localResult.evaluated.result.reasonCode,signatureDeadline:null,answerCheck:localResult.evaluated.answerCheck};
    const initialFailureCache=a.artifact('pre-nta-failure-cache','Bounded local failure before the explicit operator override','dnsResolver',initialFailure,{kind:'cache',derivedFrom:[...answerRefs,...configured?[configured]:[]]});
    checkpoint('pre-nta-failure-cache','dnsResolver',{reason:initialFailure.reasonCode,expiresAt:initialFailure.expiresAt},[dnssecPut('cacheEntries',[initialFailure]),dnssecPut('cached',true),dnssecPut('cacheKind','failure'),dnssecPut('timers.failureCache',{receivedAt:initialFailure.receivedAt,expiresAt:initialFailure.expiresAt,duration:5,kind:'validation-failure'})],[{artifactId:initialFailureCache,kind:'create'}],{held:a.create(initialFailureCache,'dnsResolver','Failure cache'),kind:'store'});
    respond(stubRequest,[],{rcode:'SERVFAIL',flags:{AD:0},effects:[dnssecPut('returnedToStub',true)]});
    const refused={status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false};
    const firstRefusal=a.artifact('pre-nta-application-refusal','Application refusal before manual operator bypass','dnsApp',refused,{kind:'event'});
    checkpoint('pre-nta-application-refusal','dnsApp',refused,[dnssecPut('applicationResult',refused)],[{artifactId:firstRefusal,kind:'derive'}],{held:a.create(firstRefusal,'dnsApp','Application result'),kind:'derive'});
    const nta={owner:'lab.example.',expiresAt:DNSSEC_BASE_CLOCK+600,manual:true};
    checkpoint('operator-explicitly-installs-scoped-temporary-bypass','dnsOperator',{...nta,installedAt:a.clock,automatic:false,flushesMatchingFailureContext:initialFailure.key},[dnssecPut('trustStores.'+localStore+'.nta',nta),dnssecPut('timers.nta',{installedAt:a.clock,expiresAt:nta.expiresAt,status:'active'}),dnssecPut('timers.failureCache',null),dnssecPut('cacheEntries',[]),dnssecPut('cached',false),dnssecPut('cacheKind',null)],[{artifactId:initialFailureCache,kind:'dispose'}],{held:[a.release(initialFailureCache,'dnsResolver','Failure cache')],kind:'dispose'});
    advance(DNSSEC_BASE_CLOCK+1,'nta-active-clock','Advance to a lookup while the scoped operator bypass is active');
    const bypassApplies=nta.manual&&a.clock<nta.expiresAt&&(input.question.qname===nta.owner||input.question.qname.endsWith('.'+nta.owner));
    if(!bypassApplies)throw new TypeError('The explicitly installed NTA does not cover this query and represented clock');
    const activeRequest=query('nta-active-stub','dnsStub','dnsResolver',input.question,{recursive:true,flags:{AD:1,CD:0,DO:1}});
    const bypassEntry={id:a.id+':nta-insecure-cache',kind:'answer',key:dnssecNetworkCacheKey(localInput,'NTA:lab.example.'),namespace:{cacheOwner:'dnsResolver',checkingOwner:'dnsOperator',view:input.view,trustStore:localStore},receivedAt:DNSSEC_BASE_CLOCK,expiresAt:Math.min(DNSSEC_BASE_CLOCK+300,nta.expiresAt),securityStatus:'insecure',validationOwner:'dnsOperator',ntaExpiresAt:nta.expiresAt};
    const bypassArtifact=a.artifact('nta-insecure-cache','Scoped unverified NTA answer cache','dnsResolver',bypassEntry,{kind:'cache',derivedFrom:answerRefs});
    checkpoint('accept-scoped-operator-bypass','dnsResolver',{operatorBypass:bypassApplies,cryptographicRepair:false},[dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('securityStatus','insecure'),dnssecPut('reasonCode','operator-nta-validation-bypass'),dnssecPut('acceptedForUse',bypassApplies),dnssecPut('cached',true),dnssecPut('cacheKind','answer'),dnssecPut('cacheEntries',[bypassEntry])],[...answerRefs,{artifactId:bypassArtifact,kind:'create'}],{held:a.create(bypassArtifact,'dnsResolver','NTA scoped cache'),kind:'store'});
    const bypassBody=a.artifact('nta-returned-answer','Returned operator-bypass answer / remaining ordinary TTL','dnsResolver',{...input.rrset,ttl:bypassEntry.expiresAt-a.clock},{kind:'rrset',derivedFrom:[answerRefs[0],bypassArtifact]});
    observe('nta-bound-returned-ttl','Bound the unverified answer by its original receipt and bypass scope','dnsResolver',{remainingTtl:bypassEntry.expiresAt-a.clock,dnssecAuthenticated:false},[],[{artifactId:bypassBody,kind:'derive'}],{held:a.create(bypassBody,'dnsResolver','DNS response data'),kind:'derive'});
    respond(activeRequest,[bypassBody,...signatures],{flags:{AD:0},values:{receivedRrsetTtl:bypassEntry.expiresAt-a.clock}});
    const bypassApplication={status:'answer',addresses:input.rrset.records,trust:'operator-bypass-insecure'};
    const bypassUse=a.artifact('nta-application-result','Application use under the explicit insecure operator bypass','dnsApp',bypassApplication,{kind:'event',derivedFrom:[bypassBody]});
    checkpoint('nta-application-use','dnsApp',bypassApplication,[dnssecPut('applicationResult',bypassApplication),dnssecPut('ntaApplicationResultArtifact',bypassUse)],[bypassBody,{artifactId:bypassUse,kind:'derive'}],{held:a.create(bypassUse,'dnsApp','Application result'),kind:'derive'});a.bind('ntaApplicationResultArtifact',bypassUse,'dnsApp','Application result');
    checkpoint('active-nta-is-insecure-not-repaired-secure','dnsResolver',{operatorBypass:true,rrsigStillInvalid:localResult.evaluated.answerCheck.mathematicalResult===false},[dnssecPut('response.rcode','NOERROR'),dnssecPut('response.AD',0)]);
    advance(nta.expiresAt,'nta-expiry-clock','Reach the explicit operator bypass expiry');
    checkpoint('nta-expiry-removes-bypass-and-scope-cache','dnsOperator',{scope:nta.owner,expiredAt:a.clock,unrelatedCachePreserved:true},[dnssecPut('trustStores.'+localStore+'.nta',null),dnssecPut('timers.nta.status','expired'),dnssecPut('cacheEntries',[]),dnssecPut('cached',false),dnssecPut('cacheKind',null),dnssecPut('acceptedForUse',false),dnssecPut('applicationResult',{status:'pending'})],[{artifactId:bypassArtifact,kind:'dispose'}],{held:[a.release(bypassArtifact,'dnsResolver','NTA scoped cache')],kind:'dispose'});
    advance(nta.expiresAt+1,'nta-recheck-clock','Re-enable validation and perform a fresh lookup');
    stubRequest=query('post-nta-stub','dnsStub','dnsResolver',input.question,{recursive:true,flags:stubFlags});
    retrieveChain('post-nta-chain');
    const requery=query('post-nta-authority','dnsResolver','dnsChild',input.question,{flags:{AD:0,CD:1,DO:1}});
    const freshBody=a.artifact('post-nta-answer','Fresh post-bypass received answer occurrence','dnsChild',input.rrset,{kind:'rrset',derivedFrom:[published]});
    observe('post-nta-response-occurrence','Construct new receipt bytes after bypass expiry, not an old insecure cache success','dnsChild',{receivedAt:a.clock,signatureStillUnchanged:true},[],[published,...signatures,{artifactId:freshBody,kind:'derive'}],{held:a.create(freshBody,'dnsChild','DNS response data'),kind:'derive'});
    answerRefs=[freshBody,...signatures];respond(requery,answerRefs);authorityQueries++;
    localResult=localCheck('dnsValidator',localInput,'expired-bypass-does-not-preserve-insecure-success');selectedResult=localResult.evaluated.result;
    reasonCode='temporary-operator-bypass-expires-and-unrepaired-zone-fails-again';failureStage='post-nta-expiry-validation';
  }
  const status=selectedResult.securityStatus,secure=status==='secure';
  if(!reasonCode){
    if(status==='bogus')reasonCode=input.view==='private-v1'?(options.publicExpectation?'private-dnskey-conflicts-with-authenticated-public-ds':'configured-private-anchor-no-longer-authenticates-new-key-generation'):options.diagnostic?'unchecked-diagnostic-response-not-accepted-application-answer':options.tls?'authenticated-transport-with-independent-bogus-dnssec':options.strip?(options.ednsRemoved?'known-secure-answer-with-required-dnssec-data-stripped':'known-secure-path-missing-stripped-dnssec-records'):options.forward?'local-check-fails-on-unchecked-upstream-answer':'leaf-signature-verification-failed';
    else if(status==='indeterminate')reasonCode='empty-applicable-trust-store-not-authenticated-insecurity';
    else reasonCode=input.view==='private-v1'?(options.forward?'private-route-plus-independent-locally-provisioned-anchor':'local-private-anchor-authenticates-declared-view'):options.expireFailure?'failure-cache-expired-requery-and-revalidate-repaired-data':options.upstreamError?'fresh-cd-one-query-bypasses-cd-zero-upstream-error-context':options.requestedType==='DNSKEY'?'explicit-dnskey-answer-not-suppressed-by-do-zero':options.stubTrust?'trusted-resolver-ad-assertion-not-stub-independent-check':options.stubMode==='unaware'?'resolver-checks-unaware-stub-does-not':options.remoteOnly?'declared-trusted-upstream-remote-assertion':options.forward?(options.upstreamValidates?'independent-upstream-and-local-checks':'local-checks-data-fetched-by-upstream'):options.tls?'authenticated-transport-with-independent-secure-dnssec':options.truncated?'truncated-udp-not-complete-correlated-tcp-retry-validates':'complete-edns-udp-answer-validated';
  }
  if(status==='bogus'){failureStage||=options.diagnostic?'leaf-signature':'validation';firstDetector||='dnsValidator';}
  const accepted=(secure||status==='insecure'||status==='indeterminate'&&!options.forged)&&!options.diagnostic;
  const cacheable=!options.forged,rcode=accepted||options.diagnostic||options.forged?'NOERROR':'SERVFAIL';
  const ede=options.ede&&status==='bogus'?{present:true,code:6,textPolicy:'selected short DNSSEC Bogus; optional unsigned diagnostic'}:{present:false};
  const actualDecision=localResult?.witness||upstreamResult?.witness||null;
  const actualLocalCheck=verificationKind==='local-check'&&input.anchor?{valid:status==='secure',reason:selectedResult.reasonCode||reasonCode}:null;
  const witness=options.warm?primaryEvidenceId:a.artifact(caseId+':numericBindings-primary:'+input.published.id,'Selected local/remote reference-bound observation',localOwner,{...selectedResult,...dnssecNetworkProof(actualLocalCheck,localOwner),answerCheck:localResult?.evaluated.answerCheck||null,selectedValidationOwner:validationOwner,actualDecisionArtifact:actualDecision,verificationKind,evidenceMode:'symbolic-reference-bound',view:input.view,trustStore:localStore,checkedAt:a.clock,responseMetadata:hops.map(hop=>({query:hop.query,response:hop.response}))},{kind:'trust',derivedFrom:[...selectedResult.securityStatus==='not-checked'?[]:answerRefs,...configured?[configured]:[],...retainedFailureArtifact?[retainedFailureArtifact]:[],...actualDecision?[actualDecision]:[]]});
  observe('record-selected-evidence','Retain the actual checking observation separately from public input',resultOwner,{validationOwner,verificationKind,reused:!!options.warm},[],[{artifactId:witness,kind:options.warm?'inspect':'create'}],{held:options.warm?[]:a.create(witness,resultOwner,'Validation evidence'),kind:options.warm?'inspect':'derive'});
  const retainedEvidenceRefs=evidenceRefs.filter(ref=>ref!==primaryEvidenceId||received||options.warm||initialFailureEvaluation!==null||upstreamResult!==null);
  if(options.publicExpectation){
    const responseHop=hops.find(hop=>hop.from==='dnsResolver'&&hop.to==='dnsUpstream'&&hop.question.qname===input.question.qname&&hop.question.qtype===input.question.qtype);
    responseHop.evidenceRefs=[witness,...pendingEvidence.map(pending=>a.id+':'+pending.key)];
  }
  const verifyBoundary=verificationKind==='remote-assertion'?'remote-assertion-not-local-verification':'local-verification-bound-to-evidence';
  checkpoint(verifyBoundary,verificationKind==='remote-assertion'?'dnsResolver':validationOwner,{notBrowserCryptography:true,selectedEvidence:selectedResult.selectedEvidence||[],localCheckPerformed:verificationKind==='local-check'},[dnssecPut('signatureChecked',verificationKind==='remote-assertion'?false:selectedResult.signatureChecked),dnssecPut('chainEstablished',verificationKind==='remote-assertion'?false:selectedResult.chainEstablished),dnssecPut('denialChecked',false),dnssecPut('validationOwner',validationOwner),dnssecPut('verificationKind',verificationKind),dnssecPut('evidenceRefs',[...retainedEvidenceRefs]),dnssecPut('checkedAt',a.clock),dnssecPut('acceptedForUse',false)],[witness]);
  if(number===20&&options.records&&!options.nta&&!options.diagnostic)checkpoint('first-local-detector-before-external-diagnostic','dnsValidator',{unsignedDiagnosticIsNotEvidence:true},[dnssecPut('firstDetector',firstDetector),dnssecPut('failureStage','leaf-signature'),dnssecPut('response.rcode',rcode),dnssecPut('response.ede',ede)],[witness]);
  if(options.diagnostic)checkpoint('raw-data-can-be-returned-with-cd-one-without-trust','dnsResolver',{rawRecords:input.rrset.records,applicationPolicyRejects:true},[dnssecPut('securityStatus',status),dnssecPut('response',{rcode,CD:1,AD:0,containsRawAnswer:true,containsValidationEvidence:true})],answerRefs);
  const stoppedAction=accepted?null:options.forged?'application-use-of-forged-answer':options.diagnostic?'application-use-of-diagnostic-data':options.nta?'application-use-after-bypass-expires':options.cachedFailure&&!options.expireFailure?'network-retry-before-failure-expiry':failureStage==='upstream-validation'?'local-independent-verification-without-data':options.networkFailure?(forward?'further-forwarding-until-failure-cache-expiry':'repeated-identical-queries-during-failure-cache'):options.tcpBlocked?'validation-and-trusted-use-with-incomplete-data':options.tls?'application-use-of-bogus-dns-data':'trusted-positive-answer';
  checkpoint('classification-with-independent-failure-context',validationOwner,{status,reasonCode,transportIsNotDnssec:true},[dnssecPut('securityStatus',status),dnssecPut('reasonCode',reasonCode),dnssecPut('failureStage',failureStage),dnssecPut('firstDetector',firstDetector),dnssecPut('stoppedAction',stoppedAction)],[witness]);
  const usableSignature=input.originalSignatures.find(sig=>sig.id===localResult?.evaluated.answerCheck.selectedSignatureId)||input.originalSignatures[0];
  const receivedAt=options.warm?DNSSEC_BASE_CLOCK-60:a.clock;
  const window=dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:usableSignature.originalTtl,signatureExpiration:usableSignature.expiration,receivedAt,now:a.clock});
  let selectedCache=options.warm?cacheEntries.find(entry=>entry.kind==='answer'):options.cachedFailure&&!options.expireFailure?retainedFailure:null;
  if(cacheable&&!selectedCache){
    selectedCache={id:a.id+':cache-'+caseId,kind:accepted?'answer':'failure',key:dnssecNetworkCacheKey(localInput,accepted?undefined:'CD'+stubFlags.CD),namespace:{cacheOwner:resultOwner,checkingOwner:validationOwner,view:input.view,trustStore:localStore},receivedAt:a.clock,expiresAt:accepted?window.expiresAt:a.clock+5,signatureDeadline:accepted&&secure?usableSignature.expiration:null,validationOwner,securityStatus:status,evidenceRefs:[...retainedEvidenceRefs],...options.expireFailure?{generation:2}: {}};cacheEntries.push(selectedCache);
  }
  const reusedCacheArtifact=warmCacheArtifact||(retainedFailureArtifact&&selectedCache===retainedFailure&&a.has(retainedFailureArtifact,'dnsResolver','Failure cache')?retainedFailureArtifact:null);
  const cacheArtifact=cacheable?(reusedCacheArtifact||a.artifact('selected-result-cache','Selected '+(accepted?'answer':'failure')+' cache context',resultOwner,selectedCache,{kind:'cache',derivedFrom:[witness,...accepted?answerRefs:[]]})):null;
  checkpoint('accepted-use-and-cache-boundary',resultOwner,{acceptedForUse:accepted,cacheReused:!!reusedCacheArtifact,cacheLimits:accepted?window.limits:null,failureIsNotAuthenticatedDenial:!accepted,checkingContext:'CD'+stubFlags.CD},[dnssecPut('acceptedForUse',accepted),dnssecPut('cached',cacheable),dnssecPut('cacheKind',cacheable?(accepted?'answer':'failure'):null),dnssecPut('cacheEntries',[...cacheEntries]),dnssecPut('transport.authorityQueries',authorityQueries),dnssecPut('transport.upstreamQueries',upstreamQueries),...cacheArtifact?[dnssecPut('resultCacheArtifact',cacheArtifact)]:[]],cacheArtifact?[{artifactId:cacheArtifact,kind:reusedCacheArtifact?'inspect':'create'}]:[],{held:cacheArtifact&&!reusedCacheArtifact?a.create(cacheArtifact,resultOwner,'Result cache'):[],kind:reusedCacheArtifact?'inspect':'store'});
  if(options.expireFailure)checkpoint('new-work-required-after-expiry','dnsValidator',{freshCheckPerformed:true,checkedAt:a.clock,cacheEntry:selectedCache},[],[witness,cacheArtifact]);
  checkpoint('selected-cache-and-timer-focus',resultOwner,{cacheKey:selectedCache?.key||null},[dnssecPut('selectedCache',selectedCache),...cacheable&&!accepted?[dnssecPut('timers.failureCache',{receivedAt:selectedCache.receivedAt,expiresAt:selectedCache.expiresAt,duration:selectedCache.expiresAt-selectedCache.receivedAt,kind:status==='bogus'?'validation-failure':'resolution-failure'})]:[]],cacheArtifact?[cacheArtifact]:[]);
  if(cacheArtifact&&!reusedCacheArtifact)a.bind('resultCacheArtifact',cacheArtifact,resultOwner,'Result cache');
  a.chapter('result','4. Stub receipt is not application acceptance');
  let returnedRefs=[];
  if(returnedEarly&&accepted)returnedRefs=[answerRefs[0],...stubFlags.DO===1?answerRefs.slice(1):[]];
  else if((accepted||options.diagnostic)&&answerRefs.length){
    const sourceBody=answerRefs[0],returnedBody=a.artifact('returned-answer','Returned immutable answer / remaining lifetime','dnsResolver',{...a.object(sourceBody).value,ttl:accepted?window.remainingSeconds:300},{kind:'rrset',derivedFrom:[sourceBody,...cacheArtifact?[cacheArtifact]:[]]});
    observe('bound-returned-answer-ttl','Bound outgoing TTL without modifying signed Original TTL','dnsResolver',{remainingTtl:accepted?window.remainingSeconds:300,signedOriginalTtl:usableSignature.originalTtl},[],[{artifactId:returnedBody,kind:'derive'},sourceBody],{held:a.create(returnedBody,'dnsResolver','DNS response data'),kind:'derive'});returnedRefs=[returnedBody,...stubFlags.DO===1?answerRefs.slice(1):[]];
  }
  const downstreamAd=secure&&(stubFlags.AD===1||stubFlags.DO===1)&&options.stubMode!=='validating'?1:0;
  if(!returnedEarly)respond(stubRequest,returnedRefs,{flags:{AD:downstreamAd},rcode,effects:[dnssecPut('returnedToStub',true)],values:{ede}});
  const completionOrder=options.nta?new Map(a.steps.map((step,index)=>[step.id,index])):null;
  const primaryHops=dnssecNetworkHopSummary(hops,{downstreamFirst:number===6||options.stubMode==='validating',completionOrder});
  checkpoint('stub-receives-response-before-application-use','dnsStub',{rcode,AD:options.forged?1:downstreamAd,responseDOIgnoredForSecurity:true},[dnssecPut('returnedToStub',true),dnssecPut('response.rcode',rcode),dnssecPut('response.ede',ede),dnssecPut('response.hops',primaryHops),dnssecPut('response.traceHops',structuredClone(dnssecNetworkHopDescriptors(hops))),dnssecPut('response.evidenceHops',hops.filter(hop=>hop.purpose==='evidence')),dnssecPut('response.flags',stubRequest.hop.response.flags),dnssecPut('applicationResult',{status:'pending'})],returnedRefs);
  const applicationResult=options.forged?{status:'refused',reason:'untrusted-ad-assertion',positiveAnswerAccepted:false}:options.diagnostic?{status:'refused',reason:'diagnostic-data-not-validated-for-use',positiveAnswerAccepted:false,rawDataAvailableForInspection:true}:!accepted?{status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false}:options.requestedType==='DNSKEY'?{status:'answer',requestedType:'DNSKEY',publicKeys:input.links.at(-1).keys.map(key=>key.id),privateKeys:[],stubDnssecVerified:false}:input.view==='private-v1'?{status:'answer',addresses:input.rrset.records,view:input.view,trust:secure?'secure-local-private-anchor':'indeterminate-no-anchor',...!secure?{dnssecVerified:false}:{}}:options.stubMode==='unaware'?{status:'answer',addresses:input.rrset.records,stubDnssecVerified:false,trust:'ordinary configured DNS service'}:options.stubTrust?{status:'answer',addresses:input.rrset.records,trust:'declared-resolver-and-channel',stubDnssecVerified:false}:{status:'answer',qname:input.question.qname,addresses:input.rrset.records,trust:status};
  const application=a.artifact('application-result','Application result independent of DNS receipt','dnsApp',applicationResult,{kind:'event',derivedFrom:accepted?returnedRefs:[]});
  observe('application-result-boundary','Apply the application policy to the returned result','dnsApp',applicationResult,[dnssecPut('applicationResult',applicationResult),dnssecPut('applicationResultArtifact',application)],[{artifactId:application,kind:'derive'},...accepted?returnedRefs:[]],{held:a.create(application,'dnsApp','Application result'),kind:'derive'});a.bind('applicationResultArtifact',application,'dnsApp','Application result');
  return a.finish({dnssecNumericBindings:{answer:{rrsetId:input.published.id,signatureIds:input.originalSignatures.map(sig=>sig.id)},chain:chainBundles.map(bundle=>({rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(sig=>sig.id)}))},protocolTimeline:{label:'DNSSEC transport, signature, cache and operator-policy clocks',explanation:'Only authored protocol-clock events age the selected retained context. Playback never changes signature validity, cache expiry or the operator bypass.',entries:[{id:'selected-result-cache',label:'Selected cache context',startPath:'dnssec.selectedCache.receivedAt',deadlinePath:'dnssec.selectedCache.expiresAt',statusPath:'dnssec.selectedCache.securityStatus',detail:'Owner, checking context, view and trust store are part of this exact entry. Other retained contexts coexist.'},{id:'answer-signature',label:'Immutable answer signature',startPath:'dnssec.timers.signature.inception',deadlinePath:'dnssec.timers.signature.expiration',detail:'Signed validity does not start a cache or repair a transport failure.'},{id:'failure-cache',label:'Bounded failure context',startPath:'dnssec.timers.failureCache.receivedAt',deadlinePath:'dnssec.timers.failureCache.expiresAt',detail:'A retained failure is not an authenticated negative answer.'},{id:'negative-trust-anchor',label:'Explicit temporary operator bypass',startPath:'dnssec.timers.nta.installedAt',deadlinePath:'dnssec.timers.nta.expiresAt',statusPath:'dnssec.timers.nta.status',detail:'Expiry removes the scoped bypass and requires a new lookup and check.'}]}});
}

function dnssecNetworkDifferentClients(){
  const caseId='different-client-trust-stores',a=dnssecAuthor(22,caseId,{actorOverrides:dnssecNetworkActors});
  const contexts=[
    {name:'clientA',actor:'dnsResolver',validator:'dnsValidator',server:'dnsChild',input:dnssecNetworkInput({trustStore:'clientA-public-v1'})},
    {name:'clientB',actor:'dnsResolver',validator:'dnsValidator',server:'dnsUpstream',input:dnssecNetworkInput({view:'private-v1',trustStore:'clientB-private-v1',forward:true})},
  ],hops=[],entries=[],witnesses=[],clientResults={},validatorResults={},returned=[];
  let messageId=16640;
  const event=(key,title,actor,values,effects=[],refs=[],held=[],kind='inspect')=>a.local(key,title,actor,{values,effects,refs,held,kind});
  const request=(key,from,to,question,{recursive=false,cd=1}={})=>{
    const id=messageId++,q=dnssecLookupMessage(id,question,{recursive,flags:{AD:recursive?1:0,CD:cd,DO:1}});
    const send=a.send(key+':q','Query '+question.qname+' '+question.qtype,from,to,[],q);
    const hop={id:a.id+':'+key,from,to,purpose:'primary',transport:'UDP',question:q.question,query:{id:send.id,messageId:id,flags:q.flags,edns:q.edns},response:null,delivery:{attempted:true,queryDelivered:true,responseReceived:false}};
    hops.push(hop);return {key,hop,q,recursive};
  };
  const response=(pending,refs,{ad=0,rcode='NOERROR'}={})=>{
    const {key,hop,q,recursive}=pending,r=dnssecLookupMessage(q.messageId,q.question,{response:true,recursive,authoritative:!recursive,rcode,flags:{AD:ad,CD:recursive?q.flags.CD:0,DO:q.flags.DO}});
    const records=refs.map(ref=>a.object(typeof ref==='string'?ref:ref.artifactId)),rrsets=records.filter(entry=>entry.kind==='rrset'),signatures=records.filter(entry=>entry.kind==='rrsig');
    const receive=a.send(key+':r','Receive '+rcode+' / '+q.question.qname,hop.to,hop.from,refs,{...r,inReplyTo:hop.query.id,receivedRrsetTtl:rrsets.length?Math.min(...rrsets.map(entry=>entry.value.ttl)):null,receivedRrsigTtl:signatures.length?Math.min(...signatures.map(entry=>entry.value.ttl)):null});
    hop.response={id:receive.id,inReplyTo:hop.query.id,messageId:r.messageId,flags:r.flags,rcode,edns:r.edns};hop.delivery.responseReceived=true;
  };
  a.initialState.dnssec.initialCache={authenticatedParentDs:true,authenticatedChildDnskey:true,answer:false,failure:false};
  a.initialState.dnssec.validators.dnsValidator={clients:{},signatureChecked:false,chainEstablished:false,securityStatus:'not-checked'};
  const capabilityIds=[...dnssecNetworkPublicSigningPool,'child-csk-g1'];
  for(const keyId of capabilityIds)a.artifact('private-capability-'+keyId,'Signer-only capability '+keyId,'dnsSigner',{handle:'HSM('+keyId+')',keyId,custodian:'dnsSigner',capability:'sign'},{kind:'secret',privateKey:true,initial:true,store:'Signer-only capabilities'});
  for(const context of contexts){
    const {input,actor,validator,name}=context;
    a.initialState.dnssec.trustStores[input.trustStore]={anchors:input.anchor.keys.map(key=>key.id),applicableAnchors:input.anchor.keys.map(key=>key.id),owner:validator,view:input.view,scope:input.anchor.zone,installedBy:'trusted-operator-configuration'};
    context.anchor=a.artifact(name+'-anchor','Explicit '+name+' anchor / '+input.trustStore,'dnsOperator',{...input.anchor,trustStore:input.trustStore,view:input.view},{kind:'trust',initial:true,holders:[validator],store:'Independent client anchor'});
    a.initialState.dnssec.validators.dnsValidator.clients[name]={signatureChecked:false,chainEstablished:false,securityStatus:'not-checked',view:input.view,trustStore:input.trustStore};
    context.bundles=[];context.received=[];context.numericEvidence={};
    const prior=dnssecNetworkEvaluate(input,DNSSEC_BASE_CLOCK-60,a.policy);
    for(const [index,link] of input.links.entries()){
      const items=[];
      if(link.dsRrset)items.push({rrset:link.dsRrset,signatures:link.dsSignatures,keys:[],holder:index===1?'dnsRoot':'dnsParent'});
      items.push({rrset:link.dnskeyRrset,signatures:link.dnskeySignatures,keys:link.keys,holder:link.zone==='.'?'dnsRoot':link.zone==='example.'?'dnsParent':'dnsChild'});
      for(const item of items){
        const prefix=name+'-'+item.rrset.id,rr=a.artifact(prefix,'Published '+name+' '+item.rrset.owner+' '+item.rrset.type,'dnsSigner',item.rrset,{kind:'rrset',initial:true,holders:[item.holder],store:'Published '+input.view});
        const sigs=item.signatures.map(sig=>a.artifact(prefix+'-'+sig.id,'RRSIG('+item.rrset.type+') / '+name,'dnsSigner',{...sig,ttl:300},{kind:'rrsig',initial:true,holders:[item.holder],store:'Published signatures'}));
        const keys=item.keys.map(key=>a.artifact(prefix+'-'+key.id,'Public key '+key.id,'dnsSigner',key,{kind:'dnskey',initial:true,holders:[item.holder],store:'Published DNSKEY members'}));
        const received=a.artifact(prefix+'-earlier-receipt','Earlier received '+name+' '+item.rrset.owner+' '+item.rrset.type,item.holder,{...item.rrset,ttl:300},{kind:'rrset',initial:true,holders:[actor],store:'Earlier received '+input.trustStore,derivedFrom:[rr]});
        for(const ref of [...sigs,...keys])a.inventory.initial.push(a.acquire(ref,actor,'Earlier received '+input.trustStore));
        const refs=[received,...sigs,...keys],slot=name==='clientA'?'chain-'+context.bundles.length:'additional-1';
        const stage=item.rrset.type==='DS'?'parent-ds-signature':'dnskey-rrset-signature',check=prior.result.checks.find(check=>check.stage===stage&&check.zone===item.rrset.owner);
        const proof=a.artifact(caseId+':numericBindings-'+slot+':'+item.rrset.id,'Earlier authenticated '+name+' '+item.rrset.type,validator,{rrsetId:item.rrset.id,signatureIds:item.signatures.map(sig=>sig.id),result:check?.result||null,...dnssecNetworkProof(check?.result,validator),receivedAt:DNSSEC_BASE_CLOCK-60,checkedAt:DNSSEC_BASE_CLOCK-60,expiresAt:DNSSEC_BASE_CLOCK+240,client:name,view:input.view,trustStore:input.trustStore,evidenceMode:'symbolic-reference-bound'},{kind:'trust',initial:true,holders:[actor],store:'Earlier authenticated '+input.trustStore,derivedFrom:[...refs,context.anchor]});
        context.numericEvidence[slot]=proof;context.received.push(...refs);
        context.bundles.push({...item,refs});
      }
    }
    const rr=a.artifact(name+'-answer','Published answer in '+input.view,'dnsSigner',input.published,{kind:'rrset',initial:true,holders:['dnsChild'],store:'Published '+input.view});
    const sigs=input.signatures.map(sig=>a.artifact(name+'-answer-'+sig.id,'Answer signature in '+input.view,'dnsSigner',{...sig,ttl:300},{kind:'rrsig',initial:true,holders:name==='clientB'?['dnsChild','dnsUpstream']:['dnsChild'],store:name==='clientB'?'Available private upstream signed buffers':'Published signatures'}));
    const body=a.artifact(name+'-received-answer','Selected immutable '+input.view+' response occurrence',context.server,input.rrset,{kind:'rrset',initial:name==='clientB',holders:[context.server],store:'Available private upstream signed buffers',derivedFrom:[rr]});
    context.answer={rrset:input.rrset,signatures:input.signatures,keys:[],holder:context.server,refs:[body,...sigs],publishedRef:rr};context.bundles.push(context.answer);
    if(name==='clientB')a.initialState.dnssec.privateUpstreamBuffer={receivedAt:a.clock,expiresAt:a.clock+300,view:input.view,trustStore:input.trustStore,answerRef:body,signatureRefs:sigs};
  }
  let stubRequest=null;
  for(const context of contexts){
    const {name,input,actor,server}=context;
    a.chapter(name+'-lookup',name==='clientA'?'1. Public client context':'2. Conditional private client context');
    event(name+'-request','Select '+input.view+' without merging trust stores',actor,{question:input.question,view:input.view,trustStore:input.trustStore,conditionalForwardInstallsAnchor:false});
    const pending=request(name==='clientA'?'leaf':caseId+':clientB-private',actor,server,input.question,{recursive:name==='clientB'});
    if(name==='clientA')event(name+'-prepare-answer','Prepare the public response occurrence without changing signed bytes',server,{receivedAt:a.clock,receivedTtl:300,OriginalTTL:input.signatures[0].originalTtl},[],[context.answer.publishedRef,...context.answer.refs.slice(1),{artifactId:context.answer.refs[0],kind:'derive'}],a.create(context.answer.refs[0],server,'DNS response data'),'derive');
    response(pending,context.answer.refs);context.hop=pending.hop;
    context.answerRefs=context.answer.refs;context.received.push(...context.answerRefs);
    if(name==='clientA')stubRequest=request('stub','dnsStub','dnsResolver',input.question,{recursive:true,cd:0});
  }
  a.chapter('independent-checks','3. One checker, separate client contexts and anchor stores');
  event('raw-response-received-before-trust','Both client contexts have readable answers; neither answer has been checked','dnsResolver',{views:contexts.map(context=>context.input.view)},[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked')]);
  for(const context of contexts){
    const {input,validator,name}=context,evaluated=dnssecNetworkEvaluate(input,a.clock,a.policy),result=evaluated.result,answerCheck=evaluated.answerCheck;
    context.evaluated=evaluated;
    // The pre-authenticated chain remains an earlier receipt; only this answer is newly received.
    const observation={signatureChecked:result.signatureChecked,chainEstablished:result.chainEstablished,securityStatus:result.securityStatus,verificationKind:'local-check',owner:validator,client:name,checkedAt:a.clock,view:input.view,trustStore:input.trustStore,keyIdentity:answerCheck.selectedKeyId,cryptographicResult:answerCheck.mathematicalResult};
    validatorResults[name]=observation;
    const witness=a.artifact(name+'-verification','Independent '+name+' reference-bound decision',validator,{...observation,...dnssecNetworkProof({valid:result.securityStatus==='secure',reason:result.reasonCode},validator),checks:result.checks,selectedEvidence:result.selectedEvidence,evidenceMode:'symbolic-reference-bound'},{kind:'trust',derivedFrom:[context.anchor,...context.received]});witnesses.push(witness);
    event(name+'-verify','Verify '+input.view+' with only '+input.trustStore,validator,{...observation,checks:result.checks},[dnssecPut('validators.dnsValidator.clients.'+name,observation)],[...context.received.map(artifactId=>({artifactId,kind:'verify'})),{artifactId:context.anchor,kind:'verify'},{artifactId:witness,kind:'create'}],a.create(witness,validator,'Independent validation evidence'),'verify');
    const bundle=context.answer,slot=name==='clientA'?'primary':'additional-0',stage='answer-signature';
    const check=result.checks.find(item=>item.stage===stage&&item.zone===input.links.at(-1).zone);
    const evidence=a.artifact(caseId+':numericBindings-'+slot+':'+bundle.rrset.id,'Exact '+name+' '+bundle.rrset.type+' check',validator,{rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(signature=>signature.id),result:check?.result||null,...dnssecNetworkProof(check?.result,validator),checkedAt:a.clock,client:name,view:input.view,trustStore:input.trustStore,evidenceMode:'symbolic-reference-bound'},{kind:'trust',derivedFrom:[...context.received,context.anchor]});
    context.numericEvidence[slot]=evidence;
    event(name+'-bound-answer-evidence','Retain the exact '+bundle.rrset.type+' observation in '+input.trustStore,validator,{stage,result:check?.result||null},[],[{artifactId:evidence,kind:'create'}],a.create(evidence,validator,'Reference-bound validation evidence'),'derive');
  }
  event('trust-stores-do-not-merge','Keep independent checks and key identities distinct','dnsValidator',{clients:validatorResults,stores:contexts.map(context=>context.input.trustStore)},[dnssecPut('validators.dnsValidator',{clients:validatorResults,verificationKind:'local-check'})],witnesses);
  const secure=contexts.every(context=>context.evaluated.result.securityStatus==='secure'),failed=contexts.find(context=>context.evaluated.result.securityStatus!=='secure'),status=secure?'secure':failed.evaluated.result.securityStatus;
  const numericEvidence=[...contexts[0].bundles.map((bundle,index)=>contexts[0].numericEvidence[bundle===contexts[0].answer?'primary':'chain-'+index]),contexts[1].numericEvidence['additional-0'],contexts[1].numericEvidence['additional-1']];
  event('local-verification-bound-to-evidence','Record both independently checked paths, not one copied verdict','dnsValidator',{checks:contexts.map(context=>({validator:context.validator,result:context.evaluated.result}))},[dnssecPut('signatureChecked',contexts.every(context=>context.evaluated.result.signatureChecked)),dnssecPut('chainEstablished',contexts.every(context=>context.evaluated.result.chainEstablished)),dnssecPut('denialChecked',false),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind','local-check'),dnssecPut('evidenceRefs',numericEvidence),dnssecPut('checkedAt',a.clock),dnssecPut('acceptedForUse',false)],numericEvidence);
  event('classification-with-independent-failure-context','Classify the comparison without merging anchors or answers','dnsValidator',{status},[dnssecPut('securityStatus',status),dnssecPut('reasonCode',secure?'same-owner-two-explicit-views-independently-authenticated':failed.evaluated.result.reasonCode),dnssecPut('firstDetector',secure?null:failed.validator),dnssecPut('failureStage',secure?null:'validation'),dnssecPut('stoppedAction',secure?null:'trusted-positive-answer')],witnesses);
  for(const context of contexts){
    const {input,validator,actor,name}=context,result=context.evaluated.result,signature=input.signatures.find(sig=>sig.id===context.evaluated.answerCheck.selectedSignatureId),accepted=result.securityStatus==='secure';
    const window=signature?dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:signature.originalTtl,signatureExpiration:signature.expiration,receivedAt:a.clock,now:a.clock}):null;
    const contextEvidence=numericEvidence.filter(ref=>Object.values(context.numericEvidence).includes(ref));
    context.hop.evidenceRefs=[...contextEvidence];
    const entry={id:name==='clientA'?a.id+':cache-'+caseId:a.id+':'+caseId+':clientB-private-cache',kind:accepted?'answer':'failure',key:dnssecNetworkCacheKey(input,accepted?undefined:'CD1'),namespace:{cacheOwner:actor,checkingOwner:validator,view:input.view,trustStore:input.trustStore},answer:accepted?[...input.rrset.records]:[],receivedAt:a.clock,expiresAt:accepted?window.expiresAt:a.clock+5,signatureDeadline:signature?.expiration||null,validationOwner:validator,validatorRef:'/validators/dnsValidator/clients/'+name,client:name,evidenceRefs:contextEvidence,securityStatus:result.securityStatus,view:input.view,trustStore:input.trustStore};
    entries.push(entry);const artifact=a.artifact(name+'-cache','Independent '+name+' cache namespace',actor,entry,{kind:'cache',derivedFrom:[...context.answerRefs,...contextEvidence]});
    event(name+'-store','Store only in '+input.trustStore,actor,{key:entry.key,accepted,namespace:entry.namespace},[dnssecPut('clients.'+name,{actor,validator,view:input.view,trustStore:input.trustStore,cacheEntry:entry})],[...contextEvidence,{artifactId:artifact,kind:'create'}],[...a.create(artifact,actor,'Independent client cache'),...contextEvidence.filter(ref=>!a.has(ref,actor,'Independent client cache proof')).map(ref=>a.acquire(ref,actor,'Independent client cache proof'))],'store');
    clientResults[name]={addresses:accepted?input.rrset.records:[],view:input.view,securityStatus:result.securityStatus};returned.push(...context.answerRefs);
  }
  event('identical-owner-distinct-cache-namespaces','Identical owner names do not identify an interchangeable cache entry','dnsResolver',{keys:entries.map(entry=>entry.key),merged:false},[dnssecPut('cacheEntries',entries)],witnesses);
  event('accepted-use-and-cache-boundary','Apply the separately evaluated decisions to their own caches','dnsResolver',{acceptedForUse:secure},[dnssecPut('acceptedForUse',secure),dnssecPut('cached',true),dnssecPut('cacheKind',secure?'answer':'failure'),dnssecPut('cacheEntries',entries)],witnesses);
  a.chapter('result','4. Separate client results and application use');
  const publicContext=contexts[0],publicAccepted=publicContext.evaluated.result.securityStatus==='secure';
  response(stubRequest,publicAccepted?publicContext.answerRefs:[],{ad:publicAccepted?1:0,rcode:publicAccepted?'NOERROR':'SERVFAIL'});
  const primaryHops=[contexts[0].hop,contexts[1].hop,stubRequest.hop];
  event('stub-receives-response-before-application-use','The selected public answer has reached the stub; the resolver retains both context results','dnsStub',{clients:clientResults},[dnssecPut('returnedToStub',true),dnssecPut('response',{rcode:publicAccepted?'NOERROR':'SERVFAIL',ede:{present:false},hops:primaryHops,traceHops:[...hops]}),dnssecPut('applicationResult',{status:'pending'})],publicAccepted?publicContext.answerRefs:[]);
  const result=secure?{status:'answer',results:clientResults}:{status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false,results:clientResults};
  const application=a.artifact('application-result','Application comparison of two independently authenticated views','dnsApp',result,{kind:'event',derivedFrom:returned});
  event('application-result-boundary','Use the two view-specific results without merging their identities','dnsApp',result,[dnssecPut('applicationResult',result),dnssecPut('applicationResultArtifact',application)],[{artifactId:application,kind:'derive'}],a.create(application,'dnsApp','Application result'),'derive');a.bind('applicationResultArtifact',application,'dnsApp','Application result');
  return a.finish({dnssecNumericBindings:{answer:{rrsetId:contexts[0].input.published.id,signatureIds:contexts[0].input.signatures.map(signature=>signature.id)},chain:contexts[0].bundles.filter(bundle=>bundle!==contexts[0].answer).map(bundle=>({rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(signature=>signature.id)})),additional:[contexts[1].answer,...contexts[1].bundles.filter(bundle=>bundle!==contexts[1].answer)].map(bundle=>({rrsetId:bundle.rrset.id,signatureIds:bundle.signatures.map(signature=>signature.id)})),clients:contexts.map(context=>({client:context.name,rrsetId:context.input.published.id,signatureIds:context.input.signatures.map(signature=>signature.id),view:context.input.view,trustStore:context.input.trustStore}))},protocolTimeline:{label:'Independent public and private evidence lifetimes',explanation:'The identical owner has two view/store-specific caches. Playback never merges or ages either context.',entries:contexts.map((context,index)=>({id:context.name+'-cache',label:context.name+' / '+context.input.view,startPath:'dnssec.cacheEntries.'+index+'.receivedAt',deadlinePath:'dnssec.cacheEntries.'+index+'.expiresAt',statusPath:'dnssec.cacheEntries.'+index+'.securityStatus',detail:context.input.trustStore+'; validator '+context.validator+'; independent anchor '+context.input.anchor.keys[0].id}))}});
}

export const DNSSEC_NETWORK_CASE_BUILDERS={
  'lab-dnssec05':{
    'unaware-stub':()=>dnssecNetworkBuild(5,'unaware-stub',{stubMode:'unaware'}),
    'trusted-resolver-ad':()=>dnssecNetworkBuild(5,'trusted-resolver-ad',{stubTrust:true}),
    'ad-interest-without-do':()=>dnssecNetworkBuild(5,'ad-interest-without-do',{stubTrust:true,stubDo:0}),
    'validating-stub':()=>dnssecNetworkBuild(5,'validating-stub',{stubMode:'validating'}),
    'forged-ad-untrusted-hop':()=>dnssecNetworkBuild(5,'forged-ad-untrusted-hop',{forged:true}),
    'do-zero-explicit-dnskey-query':()=>dnssecNetworkBuild(5,'do-zero-explicit-dnskey-query',{requestedType:'DNSKEY',stubDo:0}),
    'response-flags-and-cached-ad':()=>dnssecNetworkBuild(5,'response-flags-and-cached-ad',{warm:true}),
  },
  'lab-dnssec06':{
    'local-validates-upstream-fetches':()=>dnssecNetworkBuild(6,'local-validates-upstream-fetches',{forward:true}),
    'upstream-validates-local-relies':()=>dnssecNetworkBuild(6,'upstream-validates-local-relies',{forward:true,upstreamValidates:true,upstreamCd:0,remoteOnly:true,tls:true}),
    'both-validate':()=>dnssecNetworkBuild(6,'both-validate',{forward:true,upstreamValidates:true}),
    'upstream-servfail-cd-zero':()=>dnssecNetworkBuild(6,'upstream-servfail-cd-zero',{forward:true,upstreamValidates:true,upstreamCd:0,records:dnssecNetworkChangedRecords}),
    'local-checks-cd-one-data':()=>dnssecNetworkBuild(6,'local-checks-cd-one-data',{forward:true,records:dnssecNetworkChangedRecords}),
    'dnssec-stripping-forwarder':()=>dnssecNetworkBuild(6,'dnssec-stripping-forwarder',{forward:true,strip:true}),
    'forwarder-loop-or-unreachable':()=>dnssecNetworkBuild(6,'forwarder-loop-or-unreachable',{forward:true,networkFailure:'unreachable'}),
    'cached-upstream-servfail-cd-zero-then-cd-one':()=>dnssecNetworkBuild(6,'cached-upstream-servfail-cd-zero-then-cd-one',{forward:true,upstreamError:true}),
  },
  'lab-dnssec11':{
    'udp-complete':()=>dnssecNetworkBuild(11,'udp-complete',{responseBytes:1100}),
    'udp-truncated-tcp-retry':()=>dnssecNetworkBuild(11,'udp-truncated-tcp-retry',{truncated:true}),
    'tcp-blocked':()=>dnssecNetworkBuild(11,'tcp-blocked',{truncated:true,tcpBlocked:true}),
    'edns-stripped':()=>dnssecNetworkBuild(11,'edns-stripped',{strip:true,ednsRemoved:true}),
    'dot-authenticated-resolver':()=>dnssecNetworkBuild(11,'dot-authenticated-resolver',{tls:true}),
    'encrypted-but-bogus-dns-data':()=>dnssecNetworkBuild(11,'encrypted-but-bogus-dns-data',{tls:true,records:dnssecNetworkChangedRecords}),
  },
  'lab-dnssec20':{
    'bogus-servfail-with-ede':()=>dnssecNetworkBuild(20,'bogus-servfail-with-ede',{records:dnssecNetworkChangedRecords,ede:true}),
    'same-failure-without-ede':()=>dnssecNetworkBuild(20,'same-failure-without-ede',{records:dnssecNetworkChangedRecords}),
    'cd-one-diagnostic-data':()=>dnssecNetworkBuild(20,'cd-one-diagnostic-data',{records:dnssecNetworkChangedRecords,diagnostic:true}),
    'transport-timeout':()=>dnssecNetworkBuild(20,'transport-timeout',{networkFailure:'timeout'}),
    'failure-cache-suppresses-retry':()=>dnssecNetworkBuild(20,'failure-cache-suppresses-retry',{cachedFailure:true}),
    'retry-after-expiry':()=>dnssecNetworkBuild(20,'retry-after-expiry',{cachedFailure:true,expireFailure:true}),
    'temporary-negative-trust-anchor':()=>dnssecNetworkBuild(20,'temporary-negative-trust-anchor',{records:dnssecNetworkChangedRecords,nta:true}),
  },
  'lab-dnssec22':{
    'private-signed-zone-local-anchor':()=>dnssecNetworkBuild(22,'private-signed-zone-local-anchor',{view:'private-v1'}),
    'private-signed-zone-no-covering-anchor':()=>dnssecNetworkBuild(22,'private-signed-zone-no-covering-anchor',{view:'private-v1',anchor:null,trustStore:'empty-private-v1'}),
    'conditional-forward-with-local-validation':()=>dnssecNetworkBuild(22,'conditional-forward-with-local-validation',{view:'private-v1',forward:true}),
    'different-client-trust-stores':()=>dnssecNetworkDifferentClients(),
    'stale-private-anchor':()=>dnssecNetworkBuild(22,'stale-private-anchor',{view:'private-v1',generation:2,anchorGeneration:1}),
    'private-view-versus-public-chain':()=>dnssecNetworkBuild(22,'private-view-versus-public-chain',{view:'private-v1',publicExpectation:true,anchor:'root-ksk-g1',trustStore:'public-only-v1',forward:true}),
  },
};
