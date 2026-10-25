import {dnssecAuthor,dnssecPut,dnssecAppend} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecValidateChain,dnssecCheckSignature,dnssecCanonicalInput,dnssecTtlWindow} from './dnssec-validation.js';

const dnssecLookupKey=id=>dnssecMaterial('keys',id);
const dnssecLookupRrset=id=>dnssecMaterial('rrsets',id);
const dnssecLookupSignature=id=>dnssecMaterial('signatures',id);
const dnssecLookupDs=id=>dnssecMaterial('ds',id);
export function dnssecLookupPath(){
  return [
    {zone:'.',dnskeyRrset:dnssecLookupRrset('root-dnskey-g1'),dnskeySignatures:[dnssecLookupSignature('root-dnskey-path-long')],keys:['root-ksk-g1','root-zsk-g1'].map(dnssecLookupKey)},
    {zone:'example.',dsRrset:dnssecLookupRrset('root-example-ds'),dsSignatures:[dnssecLookupSignature('root-example-ds-path-long')],ds:[dnssecLookupDs('example-ksk-g1-sha256')],dnskeyRrset:dnssecLookupRrset('example-dnskey-g1'),dnskeySignatures:[dnssecLookupSignature('example-dnskey-path-long')],keys:['example-ksk-g1','example-zsk-g1'].map(dnssecLookupKey)},
    {zone:'lab.example.',dsRrset:dnssecLookupRrset('example-child-ds'),dsSignatures:[dnssecLookupSignature('example-child-ds-path-long')],ds:[dnssecLookupDs('child-ksk-g1-sha256')],dnskeyRrset:dnssecLookupRrset('child-dnskey-g1'),dnskeySignatures:[dnssecLookupSignature('child-dnskey-g1-path-long')],keys:['child-ksk-g1','child-zsk-g1'].map(dnssecLookupKey)},
  ];
}

/** Select the actual independently provisioned trust point, never an array position. */
export function dnssecLookupSelectedPath(links,anchor){
  if(!Array.isArray(links)||!links.length)throw new TypeError('A concrete ordered DNSSEC path is required');
  if(!anchor)return links;
  const zone=anchor.zone||anchor.keys?.[0]?.owner||anchor.key?.owner;
  const index=links.findIndex(link=>link.zone.toLowerCase()===zone?.toLowerCase());
  return index<0?links:links.slice(index);
}
export function dnssecLookupMessage(id,question,{response=false,authoritative=false,recursive=false,flags={},rcode='NOERROR',edns=true,udpPayloadSize=1232}={}){
  const bits={QR:response?1:0,AA:response&&authoritative?1:0,TC:0,RD:recursive?1:0,RA:response&&recursive?1:0,AD:0,CD:0,DO:edns?1:null,CO:edns?0:null,opcode:0,Z:0,...flags};
  bits.OPCODE=({0:'QUERY',4:'NOTIFY',5:'UPDATE'})[bits.opcode]||'OPCODE'+bits.opcode;
  return {id,messageId:id,question:{qclass:'IN',qdcount:1,...question},flags:bits,...response?{rcode}:{},edns:{present:edns,version:edns?0:null,udpPayloadSize:edns?udpPayloadSize:null,DO:bits.DO,CO:bits.CO}};
}

/** Fixed typed inputs drive checks; the independent worksheet is never imported. */
export function dnssecLookupCase(number,caseId,options={}){
  const a=dnssecAuthor(number,caseId,{profileId:options.profileId||'modern'}),links=options.links||dnssecLookupPath();
  const question={qname:options.qname||'www.lab.example.',qtype:options.qtype||'A',qclass:'IN'},view=options.view||'public-v1',trustStore=options.trustStore||'resolver-public-v1';
  const receivedTtl=options.receivedTtl??300,rrsigTtl=options.rrsigTtl??300,answerFixed=options.answerRrset||dnssecLookupRrset('www-a'),answerSignatures=options.answerSignatures||[dnssecLookupSignature('www-a-signature')];
  const answerInput={...answerFixed,ttl:receivedTtl,...options.mutation?{records:options.mutation}:{}},anchorKey=options.anchorKeyId===null?null:dnssecLookupKey(options.anchorKeyId||'root-ksk-g1');
  const anchor=anchorKey?{zone:anchorKey.owner,keys:[anchorKey],provenance:'Explicit out-of-band operator provisioning'}:null,validatorNow=DNSSEC_BASE_CLOCK+(options.signFirst?300:0)+(options.validatorClockOffset||0);
  const warm=options.warm===true,cachedParent=warm||options.cachedParent===true,cachedChild=warm||options.cachedChild===true,cachedAncestors=cachedParent||options.cachedAncestors===true;
  Object.assign(a.initialState.dnssec,{query:question,view,trustStore,cacheNamespace:{view,trustStore},validatorClockOffset:options.validatorClockOffset||0,trustStores:{[trustStore]:{anchors:anchorKey?[anchorKey.id]:[],provisioning:'explicit out-of-band configuration'}},publication:{childGeneration:'g0',glueAuthenticated:false}});
  a.initialState.dnssec.cacheKind=null;a.initialState.dnssec.stoppedAction=null;
  const keyObjects=new Map(),signatureObjects=new Map(),bundles=[],evidenceRefs=[];
  const signerFor=zone=>options.signingOwners?.[zone]||'dnsSigner';
  const publicKey=(key,owner)=>{
    if(keyObjects.has(key.id))return keyObjects.get(key.id);
    const artifact=a.artifact('dnskey-'+key.id,'DNSKEY '+key.owner+' / '+key.id,signerFor(key.owner),key,{kind:'dnskey',initial:true,holders:[owner],store:'Published public keys'});keyObjects.set(key.id,artifact);return artifact;
  };
  const bundle=(rrset,signatures,owner,keys=[],{answer=false,ds=[]}={})=>{
    const signer=signerFor(signatures[0]?.signer||rrset.owner),initialOwner=options.signFirst&&owner==='dnsChild'?'dnsSigner':owner;
    const previous=[];
    if(options.signFirst&&owner==='dnsChild'){
      const old=a.artifact('g0-published-'+rrset.id,'Previously published g0 / '+rrset.owner+' '+rrset.type,signer,rrset,{kind:'rrset',initial:true,holders:['dnsChild'],store:'Published generation g0'});previous.push(old);
      for(const signature of signatures)previous.push(a.artifact('g0-rrsig-'+signature.id,'Previously published g0 RRSIG('+rrset.type+')',signer,signature,{kind:'rrsig',initial:true,holders:['dnsChild'],store:'Published generation g0',derivedFrom:[old]}));
      a.initialState.dnssec.publication.previousGenerationObjects||=[];
      for(const artifact of previous){const index=a.initialState.dnssec.publication.previousGenerationObjects.push(artifact)-1;a.bind('publication.previousGenerationObjects.'+index,artifact,'dnsChild','Published generation g0');}
    }
    const canonical=a.artifact('published-'+rrset.id,'Published RRset '+rrset.owner+' '+rrset.type,signer,rrset,{kind:'rrset',initial:true,holders:[initialOwner],store:initialOwner==='dnsSigner'?'Unsigned zone input':'Published zone',replaces:previous.length?[previous[0]]:[]});
    const sigs=signatures.map((signature,index)=>{
      if(signatureObjects.has(signature.id))return signatureObjects.get(signature.id);
      const sig=a.artifact('rrsig-'+signature.id,'RRSIG('+rrset.type+') / '+signature.id,signer,signature,{kind:'rrsig',initial:!(options.signFirst&&owner==='dnsChild'),holders:[initialOwner],store:'Published signatures',derivedFrom:[canonical],replaces:previous[index+1]?[previous[index+1]]:[]});signatureObjects.set(signature.id,sig);return sig;
    });
    const atoms=keys.map(key=>publicKey(key,initialOwner));
    const dsAtoms=ds.map(record=>a.artifact('parent-ds-'+record.keyId,'Parent DS for '+record.keyId,signer,record,{kind:'ds',initial:true,holders:[initialOwner],store:'Published parent DS',derivedFrom:[canonical]}));
    const index=bundles.length,evidenceKey=caseId+':numericBindings-'+(answer?'primary':'chain-'+index)+':'+rrset.id;
    const value={rrset,signatures,owner,canonical,sigs,atoms,dsAtoms,keys,answer,index,evidenceKey,evidenceId:a.id+':'+evidenceKey,occurrence:null};bundles.push(value);evidenceRefs.push(value.evidenceId);return value;
  };
  const root=bundle(links[0].dnskeyRrset,links[0].dnskeySignatures,'dnsRoot',links[0].keys);
  const parentDs=bundle(links[1].dsRrset,links[1].dsSignatures,'dnsRoot',[],{ds:links[1].ds});
  const parentKeys=bundle(links[1].dnskeyRrset,links[1].dnskeySignatures,'dnsParent',links[1].keys);
  const childDs=bundle(links[2].dsRrset,links[2].dsSignatures,'dnsParent',[],{ds:links[2].ds});
  const childKeys=bundle(links[2].dnskeyRrset,links[2].dnskeySignatures,'dnsChild',links[2].keys);
  const leaf=bundle(answerFixed,answerSignatures,'dnsChild',[],{answer:true});
  const anchorArtifact=anchorKey?a.artifact('anchor-'+anchorKey.id,'Explicit trust anchor '+anchorKey.owner,'dnsOperator',{zone:anchorKey.owner,keyRef:anchorKey.id,dnskeyRdataHex:anchorKey.dnskeyRdataHex,provenance:anchor.provenance,trustStore},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Configured trust anchors',derivedFrom:[keyObjects.get(anchorKey.id)].filter(Boolean)}):null;
  a.initialState.dnssec.anchorRef=anchorArtifact;
  if(anchorArtifact)a.bind('anchorRef',anchorArtifact,'dnsValidator','Configured trust anchors');
  const unrelated=a.artifact('unrelated-cache','Unrelated earlier cache entry','dnsResolver',{id:'unrelated.example./A',kind:'answer',receivedAt:DNSSEC_BASE_CLOCK-20,expiresAt:DNSSEC_BASE_CLOCK+500,view,trustStore,status:'unchanged unrelated context'},{kind:'cache',initial:true,holders:['dnsResolver'],store:'Independent cache entry'});
  a.initialState.dnssec.unrelatedCache={artifactRef:unrelated,expiresAt:DNSSEC_BASE_CLOCK+500};a.bind('unrelatedCache',unrelated,'dnsResolver','Independent cache entry');
  const privateKeyOwners=options.privateKeysByCustodian||{dnsSigner:['root-ksk-g1','root-zsk-g1','example-ksk-g1','example-zsk-g1','child-ksk-g1','child-zsk-g1']},privateCapabilities=new Map();
  for(const [custodian,keyIds] of Object.entries(privateKeyOwners))for(const keyId of keyIds){
    dnssecLookupKey(keyId);
    const artifact=a.artifact('private-'+keyId,'Opaque signer capability '+keyId,custodian,{handle:'HSM('+keyId+')',keyId,custodian,capability:'sign'},{kind:'secret',privateKey:true,initial:true,holders:[custodian],store:'Signer-only key capabilities'});
    privateCapabilities.set(custodian+'|'+keyId,artifact);
  }
  const childPrivate=options.signFirst?[...new Set([...childKeys.signatures,...leaf.signatures].map(signature=>signature.keyId))].map(keyId=>{const capability=privateCapabilities.get('dnsSigner|'+keyId);if(!capability)throw new TypeError('Signing requires an explicitly provisioned private capability: '+keyId);return capability;}):[];
  const chainInput={anchor,links,answer:{rrset:answerInput,signatures:answerSignatures},now:validatorNow,policy:a.policy};
  const evaluated=dnssecValidateChain(chainInput),prior=cachedAncestors||cachedChild?dnssecValidateChain({...chainInput,answer:{rrset:answerFixed,signatures:answerSignatures},now:DNSSEC_BASE_CLOCK-60}):null;
  const evidenceValue=(item,result,checkedAt)=>({rrsetId:item.rrset.id,signatureIds:item.signatures.map(sig=>sig.id),receivedObjectRef:item.occurrence||item.canonical,checkedAt,validationOwner:'dnsValidator',evidenceMode:'symbolic-reference-bound',valid:result.valid,reason:result.reason,canonicalInputHex:result.selectedEvidence?.canonicalInputHex||dnssecCanonicalInput(item.answer?answerInput:item.rrset,item.signatures[0]),independentInputHex:item.signatures[0].signingInputHex,selectedEvidence:result.selectedEvidence||null});
  const evidence=(item,result,{initial=false,checkedAt=a.clock}={})=>{
    if(a.objects.has(item.evidenceId))return item.evidenceId;
    return a.artifact(item.evidenceKey,'Validation evidence / '+item.rrset.owner+' '+item.rrset.type,'dnsValidator',evidenceValue(item,result,checkedAt),{kind:'trust',initial,holders:['dnsValidator'],store:'Validation evidence',derivedFrom:[item.occurrence||item.canonical,...item.sigs,...item.atoms,...item.dsAtoms,...anchorArtifact?[anchorArtifact]:[]]});
  };
  const signatureResult=item=>{
    const stage=item.answer?'answer-signature':item.rrset.type==='DS'?'parent-ds-signature':'dnskey-rrset-signature',zone=item.answer?links[2].zone:item.rrset.owner;
    return evaluated.checks.find(check=>check.stage===stage&&check.zone===zone)?.result||{checked:false,valid:false,reason:'prerequisite-not-authenticated',selectedEvidence:null,candidates:[]};
  };
  for(const item of bundles){
    const cached=!item.answer&&(cachedAncestors&&item.index<(cachedParent?4:3)||cachedChild&&item===childKeys)||warm&&item.answer;
    if(cached){
      item.occurrence=a.artifact('cached-rrset-'+item.rrset.id,'Earlier received cached RRset '+item.rrset.owner+' '+item.rrset.type,item.owner,{...item.rrset,ttl:receivedTtl},{kind:'rrset',initial:true,holders:['dnsResolver'],store:'Previously validated data',derivedFrom:[item.canonical]});
      for(const ref of [...item.sigs,...item.atoms,...item.dsAtoms])if(!a.has(ref,'dnsResolver','Previously validated data'))a.inventory.initial.push(a.acquire(ref,'dnsResolver','Previously validated data'));
      const oldResult=dnssecCheckSignature({rrset:a.object(item.occurrence).value,signatures:item.signatures,keys:item.answer?links[2].keys:item.rrset.type==='DS'?(item.owner==='dnsRoot'?links[0].keys:links[1].keys):item.keys,now:DNSSEC_BASE_CLOCK-60,policy:a.policy,expectedSigner:item.signatures[0].signer});
      const stage=item.answer?'answer-signature':item.rrset.type==='DS'?'parent-ds-signature':'dnskey-rrset-signature',zone=item.answer?links[2].zone:item.rrset.owner,authenticated=prior.checks.find(check=>check.stage===stage&&check.zone===zone)?.valid;
      if(!oldResult.valid||!authenticated)throw new TypeError('Invalid declared prior DNSSEC cache evidence');evidence(item,oldResult,{initial:true,checkedAt:DNSSEC_BASE_CLOCK-60});
    }
  }
  let parentCacheEntry=null,parentCacheArtifact=null;
  const cachedAncestorBundles=bundles.filter(item=>!item.answer&&item.index<(cachedParent?4:cachedAncestors?3:0));
  if(cachedAncestors||cachedChild)a.initialState.dnssec.prerequisiteCacheEntries=[];
  if(cachedAncestors){
    const window=dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:3600,signatureExpiration:Math.min(...cachedAncestorBundles.flatMap(item=>item.signatures.map(sig=>sig.expiration))),now:a.clock,receivedAt:DNSSEC_BASE_CLOCK-60});
    const authenticated=prior.checks.some(check=>check.stage==='dnskey-rrset-signature'&&check.zone===links[1].zone&&check.valid)&&(!cachedParent||prior.checks.some(check=>check.stage==='parent-ds-signature'&&check.zone===links[2].zone&&check.valid));
    parentCacheEntry={id:a.id+':parent-chain-cache',kind:'chain',zone:links[1].zone,validated:authenticated,securityStatus:'secure',validationOwner:'dnsValidator',receivedAt:DNSSEC_BASE_CLOCK-60,expiresAt:window.expiresAt,view,trustStore,evidenceRefs:cachedAncestorBundles.map(item=>item.evidenceId)};
    if(!window.valid||!parentCacheEntry.validated)throw new TypeError('Cached parent prerequisites are not live and authenticated');
    parentCacheArtifact=a.artifact('parent-chain-cache','Prior authenticated parent-chain cache','dnsResolver',parentCacheEntry,{kind:'cache',initial:true,holders:['dnsResolver'],store:'Chain cache',derivedFrom:cachedAncestorBundles.flatMap(item=>[item.occurrence,...item.sigs,...item.atoms,...item.dsAtoms])});
    a.initialState.dnssec.prerequisiteCacheEntries.push(parentCacheEntry);a.bind('prerequisiteCacheEntries.0',parentCacheArtifact,'dnsResolver','Chain cache');
  }
  if(cachedChild){
    const window=dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:childKeys.signatures[0].originalTtl,signatureExpiration:Math.min(...childKeys.signatures.map(sig=>sig.expiration)),now:a.clock,receivedAt:DNSSEC_BASE_CLOCK-60});
    if(!window.valid||!prior.checks.some(check=>check.stage==='dnskey-rrset-signature'&&check.zone===links[2].zone&&check.valid))throw new TypeError('Cached child DNSKEY evidence is not live and authenticated');
    const entry={id:a.id+':child-dnskey-cache',kind:'dnskey',zone:links[2].zone,validated:true,securityStatus:'secure',validationOwner:'dnsValidator',receivedAt:DNSSEC_BASE_CLOCK-60,expiresAt:window.expiresAt,view,trustStore,evidenceRefs:[childKeys.evidenceId]};
    const artifact=a.artifact('child-dnskey-cache','Prior authenticated child DNSKEY cache','dnsResolver',entry,{kind:'cache',initial:true,holders:['dnsResolver'],store:'Chain cache',derivedFrom:[childKeys.occurrence,...childKeys.sigs,...childKeys.atoms,childKeys.evidenceId]});
    const index=a.initialState.dnssec.prerequisiteCacheEntries.push(entry)-1;a.bind('prerequisiteCacheEntries.'+index,artifact,'dnsResolver','Chain cache');
  }
  const cacheKey=[view,trustStore,question.qname,question.qtype,question.qclass];
  let warmEntry=null,warmArtifact=null;
  if(warm){
    warmEntry={id:a.id+':warm-answer',kind:'positive',key:cacheKey,receivedAt:DNSSEC_BASE_CLOCK-60,expiresAt:DNSSEC_BASE_CLOCK+240,signatureDeadline:answerSignatures[0].expiration,remainingTtl:240,securityStatus:prior.securityStatus,validationOwner:'dnsValidator',evidenceRefs:[...evidenceRefs]};
    warmArtifact=a.artifact('warm-answer','Previously validated exact-answer cache','dnsResolver',warmEntry,{kind:'cache',initial:true,holders:['dnsResolver'],store:'Answer cache',derivedFrom:[leaf.occurrence,...leaf.sigs,...evidenceRefs]});a.initialState.dnssec.cacheEntries=[warmEntry];
    a.initialState.dnssec.resultCacheArtifact=warmArtifact;
  }
  if(options.signFirst){
    a.chapter('signing','1. Sign and publish');
    const signing=[childKeys,leaf];
    a.local('sign-zone-rrsets','Signer creates DNSKEY and answer signatures from exact canonical input','dnsSigner',{values:{dnskeySigner:links[2].dnskeySignatures[0].keyId,answerSigner:answerSignatures[0].keyId,privateKeysPublished:false,canonicalInputs:signing.map(item=>dnssecCanonicalInput(item.rrset,item.signatures[0])),browserOperation:'Symbolic HSM operation; independently produced fixed signature bytes'},effects:[dnssecPut('publication.childGeneration','g1'),dnssecPut('publication.dnskeySignatures',[links[2].dnskeySignatures[0].keyId]),dnssecPut('publication.answerSignatures',[answerSignatures[0].keyId]),dnssecPut('publication.privateKeysPublished',false)],refs:[...childPrivate,...signing.map(item=>item.canonical),...signing.flatMap(item=>item.sigs).map(artifactId=>({artifactId,kind:'create'}))],held:signing.flatMap(item=>item.sigs.flatMap(ref=>a.create(ref,'dnsSigner','Published signatures'))),kind:'derive'});
    a.advanceTo(DNSSEC_BASE_CLOCK+300,'publication-propagation','Advance the selected publication propagation interval');
    a.publish('publish-signed-zone','Publish public signed records without the private capabilities','dnsSigner','dnsChild',[...new Set(signing.flatMap(item=>[item.canonical,...item.sigs,...item.atoms]))],{effects:[dnssecPut('publication.childGeneration','g1'),dnssecPut('publication.publicRecords',['DNSKEY(K0,Z0)','RRSIG(DNSKEY,K0)','A','RRSIG(A,Z0)'])]});
  }
  const queries=[];
  if(!warm){
    if(!cachedAncestors)queries.push({key:'root-key',owner:'dnsRoot',question:{qname:'.',qtype:'DNSKEY'},item:root},{key:'example-ds',owner:'dnsRoot',question,item:parentDs,referral:true},{key:'example-key',owner:'dnsParent',question:{qname:'example.',qtype:'DNSKEY'},item:parentKeys});
    if(!cachedParent)queries.push({key:'lab-ds',owner:'dnsParent',question:cachedAncestors?{qname:links[2].zone,qtype:'DS'}:question,item:childDs,referral:!cachedAncestors});
    if(!cachedChild)queries.push({key:'lab-key',owner:'dnsChild',question:{qname:links[2].zone,qtype:'DNSKEY'},item:childKeys});
    queries.push({key:'leaf',owner:'dnsChild',question,item:leaf});
  }
  const hops=[],stubId=16640+queries.length,stubQuery=dnssecLookupMessage(stubId,question,{recursive:true,flags:{AD:1,CD:0}});
  a.chapter('request',options.signFirst?'2. Application and resolver':'1. Application and resolver');
  a.local('app-request','Application requests an address, not a DNSSEC verdict','dnsApp',{values:{question,view,trustStore,applicationPolicy:'Never use a bogus address; do not confuse receipt with validation.'}});
  a.send('stub:q','Stub asks the recursive resolver','dnsStub','dnsResolver',[],stubQuery,[]);
  a.chapter('lookup',options.signFirst?'3. Retrieve public evidence':'2. Retrieve public evidence');
  let authorityQueries=0;
  for(const [index,request] of queries.entries()){
    const qid=16640+index,q=dnssecLookupMessage(qid,request.question,{flags:{CD:number===2?0:1}}),r=dnssecLookupMessage(qid,request.question,{response:true,authoritative:!request.referral});
    a.send(request.key+':q','Query '+request.question.qname+' '+request.question.qtype,'dnsResolver',request.owner,[],q,[dnssecPut('transport.attempted',true),dnssecPut('transport.authorityQueries',++authorityQueries)]);
    const item=request.item,occurrence=a.artifact((item.answer?(options.mutation?'original-response-answer':'rrset-answer-v1'):'rrset-'+item.rrset.id),'Received RRset '+item.rrset.owner+' '+item.rrset.type,request.owner,{...item.rrset,ttl:receivedTtl},{kind:'rrset',derivedFrom:[item.canonical]});item.occurrence=occurrence;
    a.local(request.key+'-response-construct','Prepare this response occurrence without changing signed input',request.owner,{values:{receivedRrsetTtl:receivedTtl,receivedRrsigTtl:rrsigTtl,signedOriginalTtl:item.signatures[0].originalTtl},refs:[item.canonical,...item.sigs,{artifactId:occurrence,kind:'create'}],held:a.create(occurrence,request.owner,'DNS response data'),kind:'derive'});
    const refs=[occurrence,...item.sigs,...item.atoms,...item.dsAtoms];
    if(request.referral){
      const zone=item.rrset.owner,target='ns.'+zone,routeAddress=zone==='example.'?'192.0.2.2':'192.0.2.3';
      const nameservers=a.artifact(request.key+'-ns','Unsigned delegation routing NS '+zone,request.owner,{owner:zone,type:'NS',class:'IN',ttl:receivedTtl,records:[target],role:'delegation-routing-only',securityStatus:'not-checked'},{kind:'rrset',initial:true,holders:[request.owner],store:'Referral routing data'});
      const glue=a.artifact(request.key+'-glue','Unsigned routing glue '+target,request.owner,{owner:target,type:'A',class:'IN',ttl:300,records:[routeAddress],role:'routing-only',securityStatus:'not-checked'},{kind:'glue',initial:true,holders:[request.owner],store:'Referral routing data'});
      refs.push(nameservers,glue);r.referral={zone,nameserver:target,glueAddress:routeAddress,glueAuthenticated:false};
    }
    if(item.answer&&options.mutation){
      a.send(request.key+':intercept','Unprotected answer passes through an on-path adversary',request.owner,'dnsAdversary',refs,{...r,intendedReceiver:'dnsResolver',receivedRrsetTtl:receivedTtl,receivedRrsigTtl:rrsigTtl},[]);
      const changed=a.artifact('rrset-answer-v1','Tampered received A RRset','dnsAdversary',answerInput,{kind:'rrset',derivedFrom:[occurrence]});item.occurrence=changed;
      a.local('tamper-answer','Change covered A RDATA and keep the original RRSIG','dnsAdversary',{values:{before:item.rrset.records,after:answerInput.records,signatureUnchanged:true,privateSigningCapability:false},refs:[occurrence,...item.sigs,{artifactId:changed,kind:'create'}],held:a.create(changed,'dnsAdversary','Modified response data'),kind:'derive'});
      a.send(request.key+':r','Forward altered public records with the unchanged signature','dnsAdversary','dnsResolver',[changed,...item.sigs],{...r,receivedRrsetTtl:receivedTtl,receivedRrsigTtl:rrsigTtl},[dnssecPut('transport.completed',true)]);
    }else a.send(request.key+':r','Receive '+item.rrset.owner+' '+item.rrset.type+' before trust',request.owner,'dnsResolver',refs,{...r,receivedRrsetTtl:receivedTtl,receivedRrsigTtl:rrsigTtl},[dnssecPut('transport.completed',true)]);
    hops.push({id:a.id+':'+request.key,from:'dnsResolver',to:request.owner,transport:'UDP',question:q.question,query:{id:a.id+':'+request.key+':q',messageId:qid,flags:q.flags,edns:q.edns},response:{id:a.id+':'+request.key+':r',inReplyTo:a.id+':'+request.key+':q',messageId:qid,flags:r.flags,rcode:'NOERROR',edns:r.edns},evidenceRefs:[item.evidenceId]});
  }
  a.chapter('validation',options.signFirst?'4. Validate before use':'3. Validate before use');
  if(warm){
    const live=a.clock<warmEntry.expiresAt&&a.clock<answerSignatures[0].expiration&&JSON.stringify(warmEntry.key)===JSON.stringify(cacheKey)&&warmEntry.securityStatus==='secure';if(!live)throw new TypeError('Selected warm fixture has no usable exact cache entry');
    a.local('cache-hit-no-authority-query','Reuse an exact validated cache entry under its original clock and trust context','dnsResolver',{values:{remainingTtl:warmEntry.expiresAt-a.clock,authorityQueries:0,priorCheckedAt:DNSSEC_BASE_CLOCK-60,newSignatureCheck:false},effects:[dnssecPut('received',false),dnssecPut('signatureChecked',false),dnssecPut('validators.dnsValidator',{verificationKind:'local-check',checkedAt:DNSSEC_BASE_CLOCK-60,reused:true,securityStatus:'secure'}),dnssecPut('transport.authorityQueries',0)],refs:[warmArtifact,leaf.occurrence,...evidenceRefs]});
  }else{
    a.local('raw-response-received-before-trust','Public answer exists, but no local trust decision has occurred','dnsResolver',{values:{publicReadable:true,confidentialityFromDnssec:false},effects:[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('securityStatus','not-checked'),dnssecPut('timers.signature',{inception:answerSignatures[0].inception,expiration:answerSignatures[0].expiration})],refs:[leaf.occurrence,...leaf.sigs]});
    if(cachedAncestors)a.local('parent-chain-reused-child-key-still-untrusted','Reuse only the authenticated parent evidence actually held in this cache context','dnsResolver',{values:{view,trustStore,freshChildKeyRequired:!cachedChild,expiresAt:parentCacheEntry.expiresAt,publicationDidNotFlushCache:true},effects:[dnssecPut('chainEstablished',false),dnssecPut('cacheEntries',[parentCacheEntry]),dnssecPut('transport.rootQueries',queries.filter(query=>query.owner==='dnsRoot').length),dnssecPut('transport.parentQueries',queries.filter(query=>query.owner==='dnsParent').length),dnssecPut('transport.childQueries',queries.filter(query=>query.owner==='dnsChild').length)],refs:[parentCacheArtifact,...cachedAncestorBundles.flatMap(item=>[item.canonical,...item.sigs,...item.atoms,...item.dsAtoms])]});
    const verifyBundle=(item,boundary,title,effects=[])=>{
      const result=signatureResult(item),witness=evidence(item,result),refs=[item.occurrence||item.canonical,...item.sigs,...item.atoms,...item.dsAtoms,...anchorArtifact?[anchorArtifact]:[]];
      const observation={rrsetRef:item.occurrence||item.canonical,signatureRef:item.sigs[0],signatureChecked:result.checked,cryptographicResult:result.mathematicalResult??null,checkedAt:validatorNow,verificationKind:'local-check',evidenceMode:'symbolic-reference-bound'};
      a.local(boundary,title,'dnsValidator',{values:{valid:result.valid,reason:result.reason,canonicalInputHex:dnssecCanonicalInput(item.answer?answerInput:item.rrset,item.signatures[0]),verificationIsNotDecryption:true},effects:[dnssecPut('signatureChecked',result.checked),...Object.entries(observation).map(([key,value])=>dnssecPut('validators.dnsValidator.'+key,value)),...effects],refs:[...refs.map(artifactId=>({artifactId,kind:'verify'})),{artifactId:witness,kind:'create'}],held:a.create(witness,'dnsValidator','Validation evidence'),kind:'verify'});return result;
    };
    if(!cachedAncestors){
      const rootCheck=evaluated.checks.find(check=>check.stage==='dnskey-rrset-signature'&&check.zone==='.');
      verifyBundle(root,'root-anchor-accepts-root-dnskey','The configured anchor authenticates the root DNSKEY RRset',[dnssecPut('trustStores.'+trustStore+'.rootDnskeyAuthenticated',!!rootCheck?.valid),dnssecPut('chainEstablished',false)]);
      const rootDsCheck=evaluated.checks.find(check=>check.stage==='parent-ds-signature'&&check.zone==='example.');
      verifyBundle(parentDs,'root-authenticated-example-ds','Authenticate example. DS under the root, not the referral glue',[dnssecPut('publication.exampleDsPublisher','.'),dnssecPut('publication.exampleDsAuthenticated',!!rootDsCheck?.valid),dnssecPut('publication.glueAuthenticated',false)]);
      verifyBundle(parentKeys,'example-dnskey-set-authenticated','Match parent DS, then authenticate the entire example. DNSKEY RRset');
    }
    if(!cachedParent){
      a.local('parent-ds-received-before-child-key-trust','The child DS is received but has not authenticated the child keys','dnsResolver',{values:{publisher:'example.',child:'lab.example.',glueIsTrustAnchor:false},effects:[dnssecPut('publication.labDsPublisher','example.'),dnssecPut('publication.labDsReceived',true),dnssecPut('publication.labDsAuthenticated',false),dnssecPut('publication.glueAuthenticated',false)],refs:[childDs.occurrence,...childDs.sigs,...childDs.dsAtoms]});
      const parentDsCheck=evaluated.checks.find(check=>check.stage==='parent-ds-signature'&&check.zone==='lab.example.');
      verifyBundle(childDs,'parent-authenticates-child-ds','The parent key authenticates the child DS RRset',[dnssecPut('publication.labDsAuthenticated',!!parentDsCheck?.valid)]);
    }
    if(!cachedChild){
      const digest=evaluated.checks.find(check=>check.stage==='ds-digest'&&check.zone==='lab.example.'&&check.valid);
      a.local('ds-matches-child-key-before-dnskey-set-acceptance','DS binds a candidate KSK; it does not by itself authenticate the ZSK','dnsValidator',{values:{digestMatch:digest?.result.keyId||null,dnskeySetNotYetAccepted:true},effects:[dnssecPut('validators.dnsValidator.dsDigestMatches',digest?.result.keyId||null),dnssecPut('validators.dnsValidator.dnskeySelfSignatureChecked',false),dnssecPut('chainEstablished',false)],refs:[...childDs.dsAtoms,...childKeys.atoms],kind:'verify'});
      const childCheck=evaluated.checks.find(check=>check.stage==='dnskey-rrset-signature'&&check.zone==='lab.example.');
      verifyBundle(childKeys,'child-dnskey-set-authenticated','Authenticate the child DNSKEY RRset before using its ZSK',[dnssecPut('validators.dnsValidator.dnskeySelfSignatureChecked',!!childCheck?.valid),dnssecPut('validators.dnsValidator.acceptedDnskeys',childCheck?.valid?links[2].keys.map(key=>key.id):[]),dnssecPut('chainEstablished',!!childCheck?.valid)]);
    }
    verifyBundle(leaf,options.mutation?'tampered-rrset-check-fails':'answer-signature-checked',options.mutation?'Unchanged signature rejects the changed A bytes':'Check a usable signature over the exact received RRset');
  }
  const secure=warm?prior.securityStatus==='secure':evaluated.securityStatus==='secure',status=secure?'secure':evaluated.securityStatus;
  const successReason=options.successReason||(warm?'validated-exact-answer-cache-reuse':cachedParent?'cached-parent-chain-fresh-child-and-answer':'complete-anchor-ds-dnskey-answer-path');
  const reason=secure?successReason:options.mutation&&evaluated.reasonCode==='signature-reference-tuple-mismatch'?'answer-rdata-does-not-match-signature':evaluated.reasonCode;
  if(number===3)a.local('parent-to-child-authentication','Keep parent DS authentication and child DNSKEY acceptance separate','dnsValidator',{values:{parentPublisher:links[1].zone,childZone:links[2].zone,matchedDsDoesNotBlessGlue:true},effects:[dnssecPut('publication.dsPublisher',links[1].zone),dnssecPut('publication.dsAuthenticated',!!evaluated.checks.find(check=>check.stage==='parent-ds-signature'&&check.zone===links[2].zone)?.valid),dnssecPut('publication.matchingChildKey',evaluated.checks.find(check=>check.stage==='ds-digest'&&check.zone===links[2].zone&&check.valid)?.result.keyId||null),dnssecPut('publication.dnskeyRrsetAuthenticated',!!evaluated.checks.find(check=>check.stage==='dnskey-rrset-signature'&&check.zone===links[2].zone)?.valid)],refs:[...childDs.dsAtoms,...childKeys.atoms],kind:'verify'});
  if(number===4){const key=links[2].keys.find(key=>key.id===answerSignatures[0].keyId);a.local('valid-non-sep-zone-key-is-usable','A valid non-SEP zone key can verify ordinary data','dnsValidator',{values:{flags:key?.flags,sepIsOperationalRoleNotValidationRequirement:true,usable:evaluated.securityStatus==='secure'},effects:[dnssecPut('validators.dnsValidator.keyRef',key?.id||null),dnssecPut('validators.dnsValidator.protocol',key?.protocol??null),dnssecPut('validators.dnsValidator.flags',key?.flags??null),dnssecPut('validators.dnsValidator.SEP',!!(key?.flags&1))],refs:childKeys.atoms,kind:'verify'});}
  a.local('local-verification-bound-to-evidence','Bind this local decision to exact evidence and this trust store','dnsValidator',{values:{referenceBound:true,notBrowserCryptography:true,priorCacheReused:warm,fullPath:!warm?evaluated.checks.map(check=>({stage:check.stage,zone:check.zone,valid:check.valid,reason:check.reason})):[]},effects:[dnssecPut('signatureChecked',warm?false:evaluated.signatureChecked),dnssecPut('chainEstablished',warm?true:evaluated.chainEstablished),dnssecPut('denialChecked',false),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind','local-check'),dnssecPut('evidenceRefs',[...evidenceRefs]),dnssecPut('checkedAt',a.clock+(options.validatorClockOffset||0)),dnssecPut('acceptedForUse',false)],refs:evidenceRefs});
  a.local('classification-with-independent-failure-context','Classify the data independently of transport and application use','dnsValidator',{values:{status,reason,transportIsNotDnssec:true},effects:[dnssecPut('securityStatus',status),dnssecPut('reasonCode',reason),dnssecPut('failureStage',secure?null:'validation'),dnssecPut('firstDetector',secure?null:'dnsValidator'),dnssecPut('stoppedAction',secure?null:'trusted-positive-answer')],refs:[leaf.occurrence||leaf.canonical,...leaf.sigs],kind:'verify'});
  const cacheWindow=dnssecTtlWindow({receivedTtl,rrsigTtl,originalTtl:answerSignatures[0].originalTtl,signatureExpiration:answerSignatures[0].expiration,now:a.clock,receivedAt:warm?warmEntry.receivedAt:a.clock});
  const cacheEntry=warm?warmEntry:{id:a.id+':cache-'+caseId,kind:secure?'answer':'failure',key:secure?cacheKey:[...cacheKey,'CD'+stubQuery.flags.CD],receivedAt:a.clock,expiresAt:secure?cacheWindow.expiresAt:a.clock+5,signatureDeadline:secure?answerSignatures[0].expiration:null,validationOwner:'dnsValidator',securityStatus:status,evidenceRefs:[...evidenceRefs]};
  const cacheArtifact=warm?warmArtifact:a.artifact('cache-'+caseId,secure?'Accepted answer cache':'Bounded DNSSEC failure cache','dnsResolver',cacheEntry,{kind:'cache',derivedFrom:[leaf.occurrence||leaf.canonical,...evidenceRefs]});
  a.local('accepted-use-and-cache-boundary',secure?'Accept the selected evidence and cache only for its effective lifetime':'Withhold the positive answer and cache only the bounded failure','dnsResolver',{values:{acceptedForUse:secure,kind:cacheEntry.kind,cacheLimits:cacheWindow.limits,publicationDoesNotFlushOtherCaches:true},effects:[dnssecPut('acceptedForUse',secure),dnssecPut('cached',true),dnssecPut('cacheKind',secure?'answer':'failure'),dnssecPut('cacheEntries',[cacheEntry]),dnssecPut('resultCacheArtifact',cacheArtifact)],refs:[{artifactId:cacheArtifact,kind:warm?'inspect':'create'}],held:warm?[]:a.create(cacheArtifact,'dnsResolver','Answer cache'),kind:'store'});a.bind('resultCacheArtifact',cacheArtifact,'dnsResolver','Answer cache');
  a.chapter('result',options.signFirst?'5. Stub and application result':'4. Stub and application result');
  let returnedAnswer=leaf.occurrence||leaf.canonical;
  if(secure&&a.object(returnedAnswer).value.ttl!==cacheWindow.remainingSeconds){
    const bounded=a.artifact('stub-answer-bounded-ttl','Answer representation with its remaining authenticated TTL','dnsResolver',{...a.object(returnedAnswer).value,ttl:cacheWindow.remainingSeconds},{kind:'rrset',derivedFrom:[returnedAnswer,cacheArtifact]});
    a.local('bound-returned-answer-ttl','Return only the remaining lifetime without changing signed Original TTL','dnsResolver',{values:{receivedAt:cacheEntry.receivedAt,expiresAt:cacheEntry.expiresAt,remainingTtl:cacheWindow.remainingSeconds,originalTtl:answerSignatures[0].originalTtl},refs:[returnedAnswer,cacheArtifact,{artifactId:bounded,kind:'derive'}],held:a.create(bounded,'dnsResolver','DNS response data'),kind:'derive'});returnedAnswer=bounded;
  }
  const rcode=secure?'NOERROR':'SERVFAIL',stubResponse=dnssecLookupMessage(stubId,question,{response:true,recursive:true,rcode,flags:{AD:secure?1:0,CD:0}});
  const stubHop={id:a.id+':stub',from:'dnsStub',to:'dnsResolver',transport:'UDP',question:stubQuery.question,query:{id:a.id+':stub:q',messageId:stubId,flags:stubQuery.flags,edns:stubQuery.edns},response:{id:a.id+':stub:r',inReplyTo:a.id+':stub:q',messageId:stubId,flags:stubResponse.flags,rcode,edns:stubResponse.edns}};hops.push(stubHop);
  a.send('stub:r','Return '+rcode+' to the stub, not an application acceptance','dnsResolver','dnsStub',secure?[returnedAnswer,...leaf.sigs]:[],{...stubResponse,...secure?{receivedRrsetTtl:cacheWindow.remainingSeconds,receivedRrsigTtl:cacheWindow.remainingSeconds}:{}},[dnssecPut('returnedToStub',true),dnssecPut('response',{rcode,ede:{present:false},hops:[...hops],flags:stubResponse.flags})]);
  a.local('stub-receives-response-before-application-use','The stub has the response; the application has not used an address','dnsStub',{values:{rcode,applicationUseStillPending:true},effects:[dnssecPut('applicationResult',{status:'pending'})]});
  const applicationResult=secure?{status:'answer',qname:question.qname,...options.applicationData?{qtype:question.qtype,data:answerInput.records}:{addresses:answerInput.records,trust:status}}:{status:'error',code:'DNS_RESOLUTION_FAILED',positiveAnswerAccepted:false};
  const application=a.artifact('application-result','Application result, separate from DNS receipt','dnsApp',applicationResult,{kind:'event',derivedFrom:secure?[returnedAnswer]:[]});
  a.local('application-result-boundary',secure?'Application accepts the returned address under its selected policy':'Application learns resolution failed, not the tampered address','dnsApp',{values:applicationResult,effects:[dnssecPut('applicationResult',applicationResult),dnssecPut('applicationResultArtifact',application)],refs:[...secure?[returnedAnswer]:[],application],held:a.create(application,'dnsApp','Application result'),kind:'derive'});a.bind('applicationResultArtifact',application,'dnsApp','Application result');
  return a.finish({relatedLessons:[{id:'lab-dnssec02',title:'From zone data to signatures',summary:'See signing keys, canonical input and public publication.'},{id:'lab-dnssec03',title:'Cross a delegation boundary',summary:'Separate parent DS and child DNSKEY authentication.'},{id:'lab-dnssec04',title:'Explain a validation decision',summary:'Compare a usable signature with precise refusal reasons.'}],dnssecNumericBindings:{answer:{rrsetId:answerFixed.id,signatureIds:answerSignatures.map(sig=>sig.id)},chain:bundles.filter(item=>!item.answer).map(item=>({rrsetId:item.rrset.id,signatureIds:item.signatures.map(sig=>sig.id)}))}});
}
