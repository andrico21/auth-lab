import {dnssecAuthor,dnssecPut,dnssecAppend} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,DNSSEC_MATERIAL,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecCanonicalInput,dnssecCheckSignature,dnssecKeyTag} from './dnssec-validation.js';
import {dnssecLookupMessage} from './dnssec-lookup.js';

const dnssecAnchorDay=86400;
const dnssecAnchorHoldDown=30*dnssecAnchorDay;
const dnssecAnchorKey=id=>dnssecMaterial('keys',id);
const dnssecAnchorRrset=id=>dnssecMaterial('rrsets',id);
const dnssecAnchorSignature=id=>dnssecMaterial('signatures',id);
const dnssecAnchorPublicLineage=key=>[key.owner.toLowerCase(),key.protocol,key.algorithm,key.publicKeyHex].join('|');
const dnssecAnchorWireMember=(record,key)=>{
  const fields=record.trim().split(/\s+/);
  return Number(fields[0])===key.flags&&Number(fields[1])===key.protocol&&Number(fields[2])===key.algorithm&&fields.slice(3).join('')===key.publicKeyBase64;
};
const dnssecAnchorMembers=rrset=>Object.values(DNSSEC_MATERIAL.keys).filter(key=>key.owner.toLowerCase()===rrset.owner.toLowerCase()&&rrset.records.some(record=>dnssecAnchorWireMember(record,key)));
const dnssecAnchorIntervals=(signature,now)=>({
  refreshInterval:Math.max(3600,Math.min(15*dnssecAnchorDay,signature.originalTtl/2,(signature.expiration-now)/2)),
  retryInterval:Math.max(3600,Math.min(dnssecAnchorDay,signature.originalTtl*.1,(signature.expiration-now)*.1)),
});

/** RFC5011 observations operate on this trust point, never on a leaf lookup. */
function dnssecAnchorContext(caseId,{zone='lab.example.',anchors=['A'],provisioning='authenticated-out-of-band'}={}){
  const a=dnssecAuthor(15,caseId,{actorOverrides:{
    dnsChild:{position:{x:975,y:120}},
    dnsOperator:{name:'Trust-anchor operator',role:'Authenticated out-of-band provisioning',position:{x:145,y:120}},
    dnsSigner:{name:'Trust-point signing service / HSM',position:{x:975,y:365}},
  }});
  const aliases=zone==='.'?{'root-ksk-g1':'root-ksk-g1'}:{A:'child-ksk-g1',B:'child-ksk-g2'};
  const records=new Map(Object.entries(aliases).map(([alias,keyId])=>[alias,{alias,keyId,state:anchors.includes(alias)?'Valid':'Start',firstObserved:null,firstObservedOriginalTtl:null,addEligibleAt:null,observations:[],validatingLineages:[],revokedAt:null,missingSince:null,removeEligibleAt:null,resetCount:0}]));
  const bundles=new Map(),publicObjects=new Map(),capabilities=new Map(),anchorObjects=new Map(),evidenceRefs=[],numericObservations=[],managementHops=[];
  let activeBundle=null,observationSerial=0,lastObservation=null,refreshAt=null,refreshInterval=null,retryInterval=null,manualReset=false,provisioned=false;
  const authority=zone==='.'?'dnsRoot':'dnsChild';
  const selectedStore='dnsValidator';
  const unrelated=a.artifact('anchor-independent-context','Unrelated configured anchor / independent context','dnsOperator',{zone:'example.',keyRef:'example-ksk-g1',dnskeyRdataHex:dnssecAnchorKey('example-ksk-g1').dnskeyRdataHex,trustStore:'unrelated-context',provenance:'Independent explicit operator configuration; not a prerequisite for the selected trust point'},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Independent trust configuration'});
  const pending={status:'pending',scope:'anchor-management-only',reason:'No leaf DNS query is performed.'};
  Object.assign(a.initialState.dnssec,{
    query:null,trustStore:selectedStore,view:'managed-trust-point',anchorRef:anchors[0]||null,anchorArtifacts:{},revokedAnchorArtifacts:{},historicalAnchorArtifacts:{},
    trustStores:{dnsValidator:{zone,anchors:[...anchors],provisioning,managed:true,keyAliases:{...aliases},revoked:[],revokedLineageRetained:[]},unrelatedContext:{anchors:['example-ksk-g1'],artifactRef:unrelated,scope:'independent context',unchanged:true}},
    applicationResult:pending,response:{rcode:null,ede:{present:false},hops:[],flags:{hops:[],scope:'No stub or leaf query; management DNSKEY messages are separately inspectable.'}},
    publication:{inspectedObject:'trust-point DNSKEY/RRSIG observation',leafLookupPerformed:false,trustPoint:zone},
    management:{scope:'anchor-management-only',hops:[],observationHistory:[],leafLookupPerformed:false,answerCacheCreated:false,unrelatedAnchorRef:unrelated},
    timers:{keyStates:Object.fromEntries([...records].map(([alias,record])=>[alias,record.state])),refreshAvailable:true},stoppedAction:null,
  });
  a.bind('trustStores.unrelatedContext.artifactRef',unrelated,'dnsValidator','Independent trust configuration');
  for(const [custodian,keyIds] of Object.entries({dnsSigner:['child-ksk-g1','child-ksk-g2','child-zsk-g1','child-zsk-g2','child-csk-g1','child-csk-g2'],dnsRoot:['root-ksk-g1','root-zsk-g1'],dnsParent:['example-ksk-g1','example-zsk-g1']})){
    for(const keyId of keyIds){
      dnssecAnchorKey(keyId);
      const handle=a.artifact('anchor-capability-'+keyId,'Provisioned signer-only capability '+keyId,custodian,{handle:'HSM('+keyId+')',keyId,custodian,capability:'sign',publicLineage:dnssecAnchorPublicLineage(dnssecAnchorKey(keyId))},{kind:'secret',privateKey:true,initial:true,holders:[custodian],store:'Signer-only capabilities'});
      capabilities.set(keyId,handle);
    }
  }
  const liveAnchors=()=>[...records.values()].filter(record=>record.state==='Valid'||record.state==='Missing');
  const anchorValue=record=>({zone,keyRef:record.keyId,dnskeyRdataHex:dnssecAnchorKey(record.keyId).dnskeyRdataHex,trustStore:selectedStore,provenance:manualReset?'authenticated-out-of-band-manual-recovery':provisioning,stateAtInstallation:'Valid'});
  const defineAnchor=(alias,{initial=false,sourceRefs=[]}={})=>{
    const record=records.get(alias),ref=a.artifact('managed-anchor-'+alias,'Configured trust anchor '+alias+' / '+record.keyId,'dnsOperator',anchorValue(record),{kind:'trust',initial,holders:['dnsValidator'],store:'Managed trust anchors',derivedFrom:sourceRefs});
    anchorObjects.set(alias,ref);a.initialState.dnssec.anchorArtifacts[alias]=initial?ref:null;
    a.initialState.dnssec.revokedAnchorArtifacts[alias]=null;a.initialState.dnssec.historicalAnchorArtifacts[alias]=null;
    a.bind('anchorArtifacts.'+alias,ref,'dnsValidator','Managed trust anchors',{equals:ref});
    a.bind('revokedAnchorArtifacts.'+alias,ref,'dnsValidator','Revoked lineage - never usable',{equals:ref});
    a.bind('historicalAnchorArtifacts.'+alias,ref,'dnsValidator','Superseded manual configuration',{equals:ref});return ref;
  };
  for(const alias of anchors)defineAnchor(alias,{initial:true});
  const publicKeyObject=key=>{
    if(!publicObjects.has(key.id))publicObjects.set(key.id,a.artifact('anchor-public-key-'+key.id,'Public DNSKEY '+key.id+' / flags '+key.flags,zone==='.'?'dnsRoot':'dnsSigner',key,{kind:'dnskey',initial:true,holders:[zone==='.'?'dnsRoot':'dnsSigner'],store:'Pre-signed public generations'}));
    return publicObjects.get(key.id);
  };
  const timers=()=>({
    keyStates:Object.fromEntries([...records].map(([alias,record])=>[alias,record.state])),
    firstObserved:Object.fromEntries([...records].map(([alias,record])=>[alias,record.firstObserved])),
    addEligibleAt:Object.fromEntries([...records].map(([alias,record])=>[alias,record.addEligibleAt])),
    observations:Object.fromEntries([...records].map(([alias,record])=>[alias,[...record.observations]])),
    removeEligibleAt:Object.fromEntries([...records].map(([alias,record])=>[alias,record.removeEligibleAt])),
    firstObservedObjectRef:Object.fromEntries([...records].map(([alias,record])=>[alias,record.firstObservedObjectRef||null])),
    firstObservedOriginalTtl:records.get('B')?.firstObservedOriginalTtl??null,
    firstObservedOriginalTtlExpiresAt:records.get('B')?.firstObserved==null?null:records.get('B').firstObserved+records.get('B').firstObservedOriginalTtl,
    addThirtyDaysExpiresAt:records.get('B')?.firstObserved==null?null:records.get('B').firstObserved+dnssecAnchorHoldDown,
    refreshInterval,retryInterval,nextRefreshAt:refreshAt,lastValidatedObservation:lastObservation?.authenticated?lastObservation.now:null,
    signature:lastObservation?{inception:lastObservation.item.signatures.find(signature=>signature.id===(lastObservation.authorization.selectedSignatureId||lastObservation.revocations[0]?.self.selectedSignatureId||lastObservation.publicCheck?.selectedSignatureId))?.inception??lastObservation.item.signatures[0].inception,expiration:lastObservation.item.signatures.find(signature=>signature.id===(lastObservation.authorization.selectedSignatureId||lastObservation.revocations[0]?.self.selectedSignatureId||lastObservation.publicCheck?.selectedSignatureId))?.expiration??lastObservation.item.signatures[0].expiration}:null,
    refreshAvailable:true,manualReset,
    lineage:Object.fromEntries([...records].filter(([,record])=>record.lineage).map(([alias,record])=>[alias,{...record.lineage}])),
  });
  const store=()=>({zone,anchors:liveAnchors().map(record=>record.alias),provisioning:manualReset?'authenticated-out-of-band-manual-recovery':provisioning,managed:true,keyAliases:{...aliases},revoked:[...records.values()].filter(record=>record.state==='Revoked').map(record=>record.alias),revokedLineageRetained:[...records.values()].filter(record=>record.revokedAt!=null).map(record=>record.alias)});
  const stateEffects=()=>[
    dnssecPut('timers',timers()),dnssecPut('trustStores.dnsValidator',store()),dnssecPut('anchorRef',liveAnchors()[0]?.alias||null),
    dnssecPut('anchorArtifacts',Object.fromEntries([...anchorObjects].map(([alias,ref])=>[alias,['Valid','Missing'].includes(records.get(alias).state)?ref:null]))),
    dnssecPut('revokedAnchorArtifacts',Object.fromEntries([...anchorObjects].map(([alias,ref])=>[alias,records.get(alias).revokedAt!=null?ref:null]))),
    dnssecPut('historicalAnchorArtifacts',Object.fromEntries([...anchorObjects].map(([alias,ref])=>[alias,records.get(alias).manuallyReplaced?ref:null]))),
    dnssecPut('management.observationHistory',[...new Set(numericObservations.map(observation=>observation.sourceEventId))]),
  ];
  const bundle=(rrsetId,signatureIds)=>{
    const identity=[rrsetId,...signatureIds].join('|');
    if(bundles.has(identity))return bundles.get(identity);
    const rrset=dnssecAnchorRrset(rrsetId),signatures=signatureIds.map(dnssecAnchorSignature),keys=dnssecAnchorMembers(rrset),owner=zone==='.'?'dnsRoot':'dnsSigner';
    if(rrset.type!=='DNSKEY'||rrset.owner.toLowerCase()!==zone.toLowerCase())throw new TypeError('Anchor observation must be the exact selected trust-point DNSKEY RRset');
    const rrsetRef=a.artifact('anchor-generation-'+rrsetId,'Pre-signed trust-point DNSKEY generation '+rrsetId,owner,rrset,{kind:'rrset',initial:true,holders:[owner],store:'Pre-signed public generations'});
    const signatureRefs=signatures.map(signature=>a.artifact('anchor-signature-'+signature.id,'Public RRSIG(DNSKEY) '+signature.id,owner,signature,{kind:'rrsig',initial:true,holders:[owner],store:'Pre-signed public generations',derivedFrom:[rrsetRef]}));
    const keyRefs=keys.map(publicKeyObject),value={identity,rrset,signatures,keys,owner,rrsetRef,signatureRefs,keyRefs};bundles.set(identity,value);return value;
  };
  const resetPending=record=>{record.state='Start';record.firstObserved=null;record.firstObservedObjectRef=null;record.firstObservedOriginalTtl=null;record.addEligibleAt=null;record.observations=[];record.validatingLineages=[];record.resetCount++;};
  const evaluate=(item,now,{allowUntrustedMath=true}={})=>{
    const current=liveAnchors(),currentKeys=current.map(record=>dnssecAnchorKey(record.keyId)),matchingKeys=item.keys.filter(key=>currentKeys.some(anchor=>anchor.dnskeyRdataHex===key.dnskeyRdataHex));
    const anchorContext=current.map(record=>({alias:record.alias,keyId:record.keyId,state:record.state,dnskeyRdataHex:dnssecAnchorKey(record.keyId).dnskeyRdataHex,anchorArtifactRef:anchorObjects.get(record.alias)||null,trustStore:selectedStore}));
    const authorization=dnssecCheckSignature({rrset:item.rrset,signatures:item.signatures,keys:matchingKeys,now,policy:a.policy,expectedSigner:zone});
    const revocations=[];
    for(const record of current){
      const original=dnssecAnchorKey(record.keyId),revoked=item.keys.find(key=>(key.flags&128)&&key.flags===(original.flags|128)&&dnssecAnchorPublicLineage(key)===dnssecAnchorPublicLineage(original));
      if(!revoked)continue;
      const self=dnssecCheckSignature({rrset:item.rrset,signatures:item.signatures,keys:[revoked],now,policy:a.policy,expectedSigner:zone});
      if(self.valid)revocations.push({record,original,revoked,self});
    }
    const publicCheck=current.length&&allowUntrustedMath&&!authorization.valid&&!revocations.length?dnssecCheckSignature({rrset:item.rrset,signatures:item.signatures,keys:item.keys,now,policy:a.policy,expectedSigner:zone}):null;
    return {authorization,revocations,publicCheck,anchorContext,authenticated:authorization.valid||revocations.length>0,checked:authorization.checked||revocations.some(entry=>entry.self.checked)||!!publicCheck?.checked};
  };
  const applyObservation=(item,now,result,receivedObjectRef=item.rrsetRef)=>{
    const held=[],created=[],removed=[];
    for(const {record,original,revoked,self} of result.revocations){
      record.state='Revoked';record.revokedAt=now;record.missingSince=null;
      record.lineage={flagsBefore:original.flags,flagsRevoked:revoked.flags,publicKeyUnchanged:dnssecAnchorPublicLineage(original)===dnssecAnchorPublicLineage(revoked),keyTagChanged:dnssecKeyTag(original.dnskeyRdataHex)!==dnssecKeyTag(revoked.dnskeyRdataHex),originalKeyId:original.id,revokedKeyId:revoked.id,originalKeyTag:dnssecKeyTag(original.dnskeyRdataHex),revokedKeyTag:dnssecKeyTag(revoked.dnskeyRdataHex),revocationSignatureCheckedWithRevokedRdata:self.valid,permanent:true};
      const ref=anchorObjects.get(record.alias);if(ref&&a.has(ref,'dnsValidator','Managed trust anchors')){held.push(a.release(ref,'dnsValidator','Managed trust anchors'),a.acquire(ref,'dnsValidator','Revoked lineage - never usable'));removed.push(ref);}
    }
    for(const record of records.values())if(record.state==='AddPend'&&record.validatingLineages.length&&record.validatingLineages.every(lineage=>[...records.values()].some(anchor=>dnssecAnchorPublicLineage(dnssecAnchorKey(anchor.keyId))===lineage&&(anchor.state==='Revoked'||anchor.state==='Removed'))))resetPending(record);
    // A revoked self-signature authorizes only its own revocation, never a new key.
    if(result.authorization.valid){
      const validatingLineages=[...new Set(result.authorization.candidates.filter(candidate=>candidate.valid).map(candidate=>dnssecAnchorPublicLineage(dnssecAnchorKey(candidate.keyId))))];
      for(const record of records.values()){
        const key=dnssecAnchorKey(record.keyId),present=item.keys.some(member=>member.dnskeyRdataHex===key.dnskeyRdataHex);
        if(record.state==='Revoked'){
          const revokedPresent=item.keys.some(member=>(member.flags&128)&&dnssecAnchorPublicLineage(member)===dnssecAnchorPublicLineage(key));
          if(revokedPresent){record.missingSince=null;record.removeEligibleAt=null;}
          else if(record.missingSince==null){record.missingSince=now;record.removeEligibleAt=now+dnssecAnchorHoldDown;}
          continue;
        }
        if(record.state==='Removed')continue;
        if(!present){if(record.state==='AddPend')resetPending(record);else if(record.state==='Valid')record.state='Missing';continue;}
        if(record.state==='Missing')record.state='Valid';
        if(record.state==='Start'&&(key.flags&1)&&(key.flags&256)&&!(key.flags&128)&&key.protocol===3&&a.policy.validationAlgorithms.includes(key.algorithm)){
          const selected=item.signatures.find(signature=>signature.id===result.authorization.selectedSignatureId);
          record.state='AddPend';record.firstObserved=now;record.firstObservedObjectRef=receivedObjectRef;record.firstObservedOriginalTtl=selected.originalTtl;record.addEligibleAt=now+Math.max(dnssecAnchorHoldDown,selected.originalTtl);record.validatingLineages=validatingLineages;
        }
        if(record.state==='AddPend'){
          record.observations.push(now);
          if(now>=record.addEligibleAt&&now>record.firstObserved&&record.observations.length>=2){
            record.state='Valid';const ref=defineAnchor(record.alias,{sourceRefs:[item.rrsetRef,...item.signatureRefs]});held.push(...a.create(ref,'dnsValidator','Managed trust anchors'));created.push(ref);
          }
        }
      }
      const selected=item.signatures.find(signature=>signature.id===result.authorization.selectedSignatureId),intervals=dnssecAnchorIntervals(selected,now);
      refreshInterval=intervals.refreshInterval;retryInterval=intervals.retryInterval;refreshAt=now+refreshInterval;
    }
    lastObservation={now,...result,item,receivedObjectRef};return {held,created,removed};
  };
  const publish=(item,key)=>{
    if(activeBundle===item.identity)return;
    a.chapter('publication','Public trust-point observations');
    a.local(key+'-custody','Inspect the pre-signed public generation at its declared signer',item.owner,{values:{action:'release-pre-signed-generation',signatureIds:item.signatures.map(signature=>signature.id),privateLineages:item.signatures.map(signature=>dnssecAnchorPublicLineage(dnssecAnchorKey(signature.keyId))),privateCapabilitiesTransferred:false},refs:[item.rrsetRef,...item.signatureRefs,...item.signatures.map(signature=>capabilities.get(signature.keyId=== 'child-ksk-g1-revoked'?'child-ksk-g1':signature.keyId)).filter(Boolean)]});
    if(item.owner!==authority)a.publish(key+'-publish','Publish only the exact public DNSKEY generation and signatures',item.owner,authority,[item.rrsetRef,...item.signatureRefs,...item.keyRefs],{effects:[dnssecPut('publication.currentDnskeyRrset',item.rrset.id),dnssecPut('publication.dnskeyMembers',item.keys.map(member=>member.id)),dnssecPut('publication.trustPointKeys',item.keys.filter(member=>member.flags&1).map(member=>[...records.values()].find(record=>dnssecAnchorPublicLineage(dnssecAnchorKey(record.keyId))===dnssecAnchorPublicLineage(member))?.alias||member.id))]});
    else a.local(key+'-published','Select the root authority public generation',authority,{values:{rrsetId:item.rrset.id},effects:[dnssecPut('publication.currentDnskeyRrset',item.rrset.id),dnssecPut('publication.dnskeyMembers',item.keys.map(member=>member.id)),dnssecPut('publication.trustPointKeys',item.keys.filter(member=>member.flags&1).map(member=>member.id))],refs:[item.rrsetRef,...item.signatureRefs]});
    activeBundle=item.identity;
  };
  const observe=(rrsetId,signatureIds,{offset=a.clock-DNSSEC_BASE_CLOCK,boundary='authenticated-trust-point-observation',rawBoundary,allowUntrustedMath=true}={})=>{
    const now=DNSSEC_BASE_CLOCK+offset;if(now>a.clock)a.advanceTo(now,'anchor-observation-clock-'+observationSerial,'Advance to the next represented DNSKEY observation');
    const item=bundle(rrsetId,signatureIds),serial=++observationSerial,key='anchor-observation-'+serial;
    publish(item,key);a.chapter('observations','DNSKEY receipt before management trust');
    const queryId=0x5100+serial,question={qname:zone,qtype:'DNSKEY',qclass:'IN'},query=dnssecLookupMessage(queryId,question,{flags:{CD:1}}),response=dnssecLookupMessage(queryId,question,{response:true,authoritative:true});
    a.send(key+'-q','Request only the managed trust-point DNSKEY RRset','dnsResolver',authority,[],query,[dnssecPut('transport.attempted',true)]);
    const received=a.artifact(key+'-received','Received DNSKEY observation '+serial+' at '+now,authority,item.rrset,{kind:'rrset',derivedFrom:[item.rrsetRef]});
    a.local(key+'-response-data','Construct this immutable DNSKEY response occurrence',authority,{values:{now,originalTtls:item.signatures.map(signature=>signature.originalTtl),signedBytesUnchanged:true},refs:[item.rrsetRef,...item.signatureRefs,{artifactId:received,kind:'derive'}],held:a.create(received,authority,'DNS response data'),kind:'derive'});
    a.send(key+'-r','Receive public trust-point keys without installing trust',authority,'dnsResolver',[received,...item.signatureRefs,...item.keyRefs.map(artifactId=>({artifactId,recordCount:0}))],response,[dnssecPut('transport.completed',true)]);
    const hop={id:a.id+':'+caseId+':'+key,from:'dnsResolver',to:authority,transport:'UDP',question,query:{id:a.id+':'+caseId+':'+key+'-q',messageId:queryId,flags:query.flags,edns:query.edns},response:{id:a.id+':'+caseId+':'+key+'-r',inReplyTo:a.id+':'+caseId+':'+key+'-q',messageId:queryId,rcode:'NOERROR',flags:response.flags,edns:response.edns},rrsetRef:received,signatureRefs:[...item.signatureRefs]};managementHops.push(hop);
    a.local(rawBoundary||key+'-raw','Receipt is readable public data, not anchor installation','dnsResolver',{values:{now,publicReadable:true,trustCreatedByReceipt:false,leafLookupPerformed:false},effects:[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('securityStatus','not-checked'),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('management.phase','received-untrusted'),dnssecPut('management.hops',[...managementHops])],refs:[received,...item.signatureRefs]});
    a.chapter('management','Authenticate observations and update the managed anchor store');
    const result=evaluate(item,now,{allowUntrustedMath}),transition=applyObservation(item,now,result,received),selected=result.authorization.selectedEvidence||result.revocations[0]?.self.selectedEvidence||result.publicCheck?.selectedEvidence||null;
    const observation={id:a.id+':'+caseId+':'+key,sourceEventId:a.id+':'+caseId+':'+boundary,receiveSourceEventId:hop.response.id,now,receivedAt:now,rrsetId:item.rrset.id,rrsetRef:received,signatureIds:item.signatures.map(signature=>signature.id),anchorContext:result.anchorContext,authenticated:result.authenticated,ordinaryDnskeyAuthentication:result.authorization.valid,revocationOnly:!result.authorization.valid&&result.revocations.length>0,authorization:result.authorization,publicSelfSignature:result.publicCheck,revocations:result.revocations.map(entry=>({keyId:entry.original.id,revokedKeyId:entry.revoked.id,result:entry.self})),query:{...query,occurrenceId:hop.query.id,questionCount:1,answerCount:0,authorityCount:0,additionalCount:1},response:{...response,occurrenceId:hop.response.id,inReplyTo:hop.query.id,questionCount:1,answerCount:item.rrset.records.length+item.signatures.length,authorityCount:0,additionalCount:1,recordSections:{answer:[received,...item.signatureRefs],authority:[],additional:[]}},custody:{sender:authority,receiver:'dnsResolver',store:'Received public records',bodyRefs:[received,...item.signatureRefs],publicRepresentationsRetained:true}};
    numericObservations.push(observation);
    const witness=a.artifact(key+'-evidence','Reference-bound management evidence at '+now,'dnsValidator',{zone,checkedAt:now,rrsetId:item.rrset.id,receivedObjectRef:received,signatureIds:observation.signatureIds,authenticated:result.authenticated,selectedEvidence:selected,canonicalInputs:item.signatures.map(signature=>dnssecCanonicalInput(item.rrset,signature)),authorization:result.authorization,publicSelfSignature:result.publicCheck,revocationChecks:observation.revocations,evidenceMode:'symbolic-reference-bound',verificationKind:liveAnchors().length||result.revocations.length?'local-check':'not-performed'},{kind:'trust',derivedFrom:[received,...item.signatureRefs,...item.keyRefs,...anchorObjects.values()]});evidenceRefs.push(witness);
    const signature=item.signatures.find(candidate=>candidate.id===selected?.signatureId)||item.signatures[0];
    const covered=result.anchorContext.length>0,securityStatus=result.authenticated?'secure':covered?'bogus':'indeterminate';
    const reasonCode=result.authorization.valid?'authenticated-trust-point-observation':result.revocations.length?'authenticated-self-revocation':covered?'stale-anchor-no-current-path':'no-covering-trust-anchor';
    const classification=[dnssecPut('securityStatus',securityStatus),dnssecPut('reasonCode',reasonCode),dnssecPut('failureStage',result.authenticated?null:covered?'anchor-to-dnskey':'anchor-selection'),dnssecPut('firstDetector',result.authenticated?null:'dnsValidator'),dnssecPut('stoppedAction',result.authenticated?null:covered?'automatically-trust-fetched-b':'accept-untrusted-self-signed-key')];
    a.local(boundary,'Authenticate the exact observation before a permitted RFC5011 transition','dnsValidator',{values:{action:'authenticate-and-update-anchor-state',now,result:observation,untrustedPublicKeyIsNotAnAnchor:true,revokedSelfSignatureNeverAddsTrust:true,unrelatedTrustConfigurationPreserved:true},effects:[...stateEffects(),...classification,dnssecPut('signatureChecked',result.checked),dnssecPut('chainEstablished',result.authorization.valid),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind',liveAnchors().length||result.revocations.length?'local-check':'not-performed'),dnssecPut('validators.dnsValidator',{verificationKind:liveAnchors().length||result.revocations.length?'local-check':'not-performed',checkedAt:now,scope:'anchor-management-only',ordinaryDnskeyAuthentication:result.authorization.valid,revocationChecks:observation.revocations,evidenceRefs:[witness]}),dnssecPut('management.phase','checked-management-observation'),dnssecPut('evidenceRefs',[...evidenceRefs]),dnssecPut('checkedAt',now),dnssecPut('timers.signature',{inception:signature.inception,expiration:signature.expiration}),...transition.created.map(ref=>dnssecPut('anchorArtifacts.'+[...anchorObjects].find(([,value])=>value===ref)[0],ref)),...transition.removed.map(ref=>dnssecPut('anchorArtifacts.'+[...anchorObjects].find(([,value])=>value===ref)[0],null))],refs:[received,...item.signatureRefs,...item.keyRefs,...anchorObjects.values()].map(artifactId=>({artifactId,kind:'verify'})).concat([{artifactId:witness,kind:'create'}]),held:[...transition.held,...a.create(witness,'dnsValidator','Management validation evidence')],kind:'verify'});
    return {item,result,observation,received};
  };
  const provision=(alias,{manual=false,boundary='out-of-band-anchor-installed'}={})=>{
    const record=records.get(alias),key=dnssecAnchorKey(record.keyId);
    const input=a.artifact('anchor-provisioning-input-'+alias,'Authenticated out-of-band public DNSKEY provisioning input '+alias,'dnsOperator',{zone,keyRef:key.id,dnskeyRdataHex:key.dnskeyRdataHex,trustStore:selectedStore,provenance:manual?'Authenticated out-of-band manual recovery authorization':'Authenticated out-of-band initial trust authorization'},{kind:'trust',initial:true,holders:['dnsOperator'],store:'Authenticated operator provisioning input'});
    const held=[];manualReset=manual;provisioned=!manual;
    if(manual)for(const current of liveAnchors()){current.state='Removed';current.manuallyReplaced=true;const old=anchorObjects.get(current.alias);if(old&&a.has(old,'dnsValidator','Managed trust anchors'))held.push(a.release(old,'dnsValidator','Managed trust anchors'),a.acquire(old,'dnsValidator','Superseded manual configuration'));
    }
    record.state='Valid';const ref=defineAnchor(alias,{sourceRefs:[input]});held.push(...a.create(ref,'dnsValidator','Managed trust anchors'));
    a.chapter('provisioning','Explicit out-of-band trust, separate from DNS receipt');
    a.local(boundary,manual?'Authorize an explicit manual trust reset from authenticated out-of-band material':'Install the operator-authenticated initial trust anchor','dnsOperator',{values:{action:manual?'manual-trust-reset':'initial-anchor-provisioning',now:a.clock,zone,keyId:key.id,source:'authenticated-out-of-band',learnedFromDns:false,unrelatedTrustConfigurationPreserved:true},effects:[...stateEffects(),dnssecPut('anchorArtifacts.'+alias,ref),...(manual?[...records.values()].filter(current=>current.manuallyReplaced).map(current=>dnssecPut('anchorArtifacts.'+current.alias,null)):[]),dnssecPut('securityStatus','not-checked'),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('reasonCode',manual?'manual-anchor-reset-awaiting-dnskey-check':'provisioned-anchor-awaiting-dnskey-check'),dnssecPut('failureStage',null),dnssecPut('firstDetector',null),dnssecPut('stoppedAction',null),dnssecPut('management.phase','operator-provisioned'),dnssecPut('management.manualReset',manual)],refs:[input,{artifactId:ref,kind:'create'}],held,kind:'store'});
  };
  const elapsed=(offset,boundary,title)=>{
    a.chapter('timers','Independent represented hold-down and observation clocks');
    a.advanceTo(DNSSEC_BASE_CLOCK+offset,'anchor-time-'+boundary,title);
    a.local(boundary,title,'dnsValidator',{values:{now:a.clock,eligible:Object.fromEntries([...records].map(([alias,record])=>[alias,record.addEligibleAt!=null&&a.clock>=record.addEligibleAt])),freshObservation:false,automaticPromotion:false},effects:stateEffects(),refs:[...anchorObjects.values()]});
  };
  // Stable refresh runs retain every request/response occurrence and checked time,
  // but share immutable equal-byte public bodies instead of duplicating those bodies.
  const refreshUntil=(offset,{boundary='anchor-refresh-history-'+observationSerial}={})=>{
    const end=DNSSEC_BASE_CLOCK+offset,item=lastObservation?.item,bodyRef=lastObservation?.receivedObjectRef;if(!item||refreshAt==null||refreshAt>end)return;
    if(!a.has(bodyRef,authority)||!a.has(bodyRef,'dnsResolver','Received public records'))throw new TypeError('Stable refreshes require the exact previously received body at both endpoints');
    const observations=[],wire=[],milestones=[],partitionedEffects=[],packetRefs=[],fieldTransfers=[];
    const sourceEventId=a.id+':'+caseId+':'+boundary;
    const packet=(key,label,from,message,body=[])=>{
      const counts={answer:body.length?item.rrset.records.length+item.signatures.length:0,authority:0,additional:message.edns.present?1:0};
      const recordSections={answer:body.map(artifactId=>({artifactId,recordCount:a.object(artifactId).kind==='rrset'?item.rrset.records.length:1})),authority:[],additional:[]};
      const value={...message,opcode:message.flags.OPCODE,questionCount:1,answerCount:counts.answer,authorityCount:counts.authority,additionalCount:counts.additional,recordSections,transport:'UDP',encrypted:false,authenticatedEndpoint:false,objects:body.map(artifactId=>({artifactId,value:a.object(artifactId).value}))};
      const ref=a.artifact(key,label,from,value,{kind:'header',extraFields:[...a.fieldsFor('question',message.question),...a.fieldsFor('opt',message.edns)],related:body});packetRefs.push(ref);return ref;
    };
    while(refreshAt<=end){
      const now=refreshAt,clockEffects=a.clockEffects(now),serial=++observationSerial,result=evaluate(item,now),transition=applyObservation(item,now,result,bodyRef);
      if(!result.authorization.valid||transition.held.length)throw new TypeError('A stable refresh batch must not hide an authentication failure or anchor-custody transition');
      const messageId=0x7000+(serial%0x8000),question={qname:zone,qtype:'DNSKEY',qclass:'IN'},query=dnssecLookupMessage(messageId,question,{flags:{CD:1}}),response=dnssecLookupMessage(messageId,question,{response:true,authoritative:true}),identity=a.id+':'+caseId+':refresh-'+serial;
      const queryPacket=packet('anchor-refresh-'+serial+'-query','Scheduled DNSKEY query occurrence '+serial,'dnsResolver',query);
      const responsePacket=packet('anchor-refresh-'+serial+'-response','Scheduled DNSKEY response occurrence '+serial,authority,response,[bodyRef,...item.signatureRefs]);
      const entry={id:identity,sourceEventId,receiveSourceEventId:sourceEventId,now,receivedAt:now,rrsetId:item.rrset.id,rrsetRef:bodyRef,signatureIds:item.signatures.map(signature=>signature.id),anchorContext:result.anchorContext,selectedEvidence:result.authorization.selectedEvidence,authenticated:result.authorization.valid,query:{...a.object(queryPacket).value,occurrenceId:identity+':q',packetRef:queryPacket},response:{...a.object(responsePacket).value,occurrenceId:identity+':r',inReplyTo:identity+':q',packetRef:responsePacket},custody:{sender:authority,receiver:'dnsResolver',store:'Received public records',bodyRefs:[bodyRef,...item.signatureRefs],queryPacketRef:queryPacket,responsePacketRef:responsePacket,publicRepresentationsRetained:true,transportPacketsDisposedAfterParsing:true}};
      observations.push(entry);numericObservations.push(entry);
      const receivedEffects=[dnssecPut('received',true),dnssecPut('signatureChecked',false),dnssecPut('chainEstablished',false),dnssecPut('securityStatus','not-checked'),dnssecPut('management.phase','received-untrusted')];
      const checkEffects=[dnssecPut('signatureChecked',result.checked),dnssecPut('chainEstablished',result.authorization.valid),dnssecPut('securityStatus',result.authorization.valid?'secure':'bogus'),dnssecPut('reasonCode','authenticated-trust-point-observation'),dnssecPut('checkedAt',now),dnssecPut('timers.lastValidatedObservation',now),dnssecPut('timers.nextRefreshAt',refreshAt),dnssecPut('management.phase','checked-management-observation'),dnssecPut('management.currentObservationId',identity),dnssecPut('validators.dnsValidator',{verificationKind:'local-check',checkedAt:now,scope:'anchor-management-only',ordinaryDnskeyAuthentication:result.authorization.valid,evidenceSourceEventId:sourceEventId,selectedEvidence:result.authorization.selectedEvidence})];
      for(const record of records.values())if(record.state==='AddPend'&&record.observations.at(-1)===now)checkEffects.push(dnssecAppend('timers.observations.'+record.alias,now));
      partitionedEffects.push(...clockEffects,...receivedEffects,...checkEffects);
      milestones.push(
        {id:'refresh-'+serial+'-query-created',phase:0,effects:a.create(queryPacket,'dnsResolver','DNS output','plain','temporary'),stateEffects:clockEffects},
        {id:'refresh-'+serial+'-query-received-response-created',phase:.35,effects:[a.release(queryPacket,'dnsResolver','DNS output'),a.acquire(queryPacket,authority,'DNS inbox','plain','temporary'),...a.create(responsePacket,authority,'DNS output','plain','temporary')],stateEffects:[]},
        {id:'refresh-'+serial+'-response-received',phase:.85,effects:[a.release(responsePacket,authority,'DNS output'),a.acquire(responsePacket,'dnsResolver','DNS inbox','plain','temporary')],stateEffects:receivedEffects},
        {id:'refresh-'+serial+'-parsed-and-checked',phase:.95,effects:[a.release(queryPacket,authority,'DNS inbox'),a.release(responsePacket,'dnsResolver','DNS inbox')],stateEffects:checkEffects},
      );
      wire.push({messageId:identity+':q',representedAt:now,sourceEventId,from:'dnsResolver',to:authority,start:0,end:1,objects:[{artifactId:queryPacket,representationId:'plain'}]},{messageId:identity+':r',representedAt:now,sourceEventId,inReplyTo:identity+':q',from:authority,to:'dnsResolver',start:0,end:1,objects:[responsePacket,bodyRef,...item.signatureRefs].map(artifactId=>({artifactId,representationId:'plain'}))});
      fieldTransfers.push({from:'dnsResolver',to:authority,objects:[queryPacket]},{from:authority,to:'dnsResolver',objects:[responsePacket,bodyRef,...item.signatureRefs]});
    }
    for(const [index,observation] of observations.entries()){
      const count=observations.length;
      for(let offset=0;offset<4;offset++){const milestone=milestones[index*4+offset];milestone.at=(index+milestone.phase)/count;delete milestone.phase;}
      observation.sourceCursor={sourceEventId,startProgress:index/count,completeProgress:(index+.95)/count,queryCreated:milestones[index*4].id,responseReceived:milestones[index*4+2].id,checked:milestones[index*4+3].id};
      wire[index*2].start=(index+.1)/count;wire[index*2].end=(index+.35)/count;
      wire[index*2+1].start=(index+.5)/count;wire[index*2+1].end=(index+.85)/count;
    }
    a.chapter('refresh','Authenticated active-refresh history');
    const finalEffects=stateEffects();
    const step=a.local(boundary,'Retain each concrete scheduled DNSKEY exchange and authenticated refresh','dnsValidator',{values:{action:'scheduled-authenticated-dnskey-refresh',count:observations.length,observations,originalTtl:item.signatures[0].originalTtl,refreshFormula:'MAX(1h,MIN(15d,OriginalTTL/2,remaining-signature-interval/2))',retryFormula:'MAX(1h,MIN(1d,OriginalTTL*0.1,remaining-signature-interval*0.1))',sameImmutableBodies:true,noNetworkTimeoutInThisRun:true},effects:[...partitionedEffects,...finalEffects],refs:[...packetRefs,bodyRef,...item.signatureRefs].map(artifactId=>({artifactId,kind:'inspect'})),kind:'inspect'});
    const event=a.inventory.events[step.id];event.messages.push(...wire);event.milestones=[...milestones,{id:'complete',at:1,effects:event.effects,stateEffects:finalEffects}];
    const eventIndex=a.steps.indexOf(step),cursor=milestone=>({eventIndex,milestone});
    const phaseCursors=observations.map((observation,index)=>({
      before:cursor(index?milestones[index*4-1].id:'before'),
      queryCreated:cursor(milestones[index*4].id),
      queryReceived:cursor(milestones[index*4+1].id),
      responseReceived:cursor(milestones[index*4+2].id),
      checked:cursor(milestones[index*4+3].id),
    }));
    const localContexts=new Map();
    const localContext=actorId=>{
      if(!localContexts.has(actorId))localContexts.set(actorId,{channel:'internal',protocolLabel:'Local DNS operation',layers:[{protocol:'DNSSEC management',transport:'Local process',from:actorId,to:actorId,protection:'Local construction, inspection and reference-bound checking are not DNS network hops.'}]});
      return localContexts.get(actorId);
    };
    const inspectionIntervals=new Map([[bodyRef,[phaseCursors[0].responseReceived,phaseCursors[0].checked]],...item.signatureRefs.map(ref=>[ref,[phaseCursors[0].responseReceived,phaseCursors[0].checked]])]);
    for(const [index,observation] of observations.entries()){
      inspectionIntervals.set(observation.query.packetRef,[phaseCursors[index].queryCreated,phaseCursors[index].queryCreated]);
      inspectionIntervals.set(observation.response.packetRef,[phaseCursors[index].responseReceived,phaseCursors[index].checked]);
    }
    for(const operation of step.attributeOperations){
      const [start,end]=inspectionIntervals.get(operation.instanceId)||[cursor('complete'),cursor('complete')];
      Object.assign(operation,localContext(operation.actorId),{heldCursorStart:start,heldCursorEnd:end});
    }
    for(const [index,transfer] of fieldTransfers.entries()){
      const message=wire[index],packetRef=transfer.objects[0];
      const packetValue=a.object(packetRef).value;
      const packetContext={channel:'backchannel',protocolLabel:packetValue.transport,layers:[{protocol:'DNS',transport:packetValue.transport,from:transfer.from,to:transfer.to,protection:'No DNSSEC confidentiality'}]};
      const messageMetadata=Object.freeze({...packetContext,messageId:message.messageId,packetRef,wireStart:message.start,wireEnd:message.end,sourceCursor:Object.freeze({sourceEventId,startProgress:message.start,completeProgress:message.end}),heldCursorStart:Object.freeze({eventIndex,progress:message.start}),heldCursorEnd:Object.freeze({eventIndex,progress:message.end})});
      for(const artifactId of transfer.objects)for(const [actorId,kind] of [[transfer.from,'send'],[transfer.to,'receive']]){
        const operations=a.operations(artifactId,actorId,kind,sourceEventId,{holders:[actorId],carriedAs:'DNS message '+message.messageId});
        for(const operation of operations)Object.assign(operation,messageMetadata);
        step.attributeOperations.push(...operations);
      }
    }
    const localOperations=(artifactId,actorId,kind,start,end)=>{
      step.attributeOperations.push(...a.operations(artifactId,actorId,kind,sourceEventId).map(operation=>({...operation,...localContext(actorId),heldCursorStart:start,heldCursorEnd:end})));
    };
    for(const [index,observation] of observations.entries()){
      const phase=phaseCursors[index];
      localOperations(observation.query.packetRef,'dnsResolver','create',phase.before,phase.queryCreated);
      localOperations(observation.query.packetRef,authority,'use',phase.queryReceived,phase.queryReceived);
      localOperations(observation.response.packetRef,authority,'create',phase.queryReceived,phase.queryReceived);
      for(const ref of [bodyRef,...item.signatureRefs,...item.keyRefs,...observation.anchorContext.map(anchor=>anchor.anchorArtifactRef).filter(Boolean)]){
        localOperations(ref,'dnsValidator','use',phase.responseReceived,phase.checked);
        localOperations(ref,'dnsValidator','verify',phase.responseReceived,phase.checked);
      }
      localOperations(observation.query.packetRef,authority,'dispose',phase.responseReceived,phase.checked);
      localOperations(observation.response.packetRef,'dnsResolver','dispose',phase.responseReceived,phase.checked);
    }
    const milestonePositions=new Map(event.milestones.map(milestone=>[milestone.id,milestone.at]));
    const cursorPosition=point=>Object.hasOwn(point,'progress')?point.progress:point.milestone==='before'?-1:milestonePositions.get(point.milestone);
    step.attributeOperations.sort((left,right)=>cursorPosition(left.heldCursorStart)-cursorPosition(right.heldCursorStart)||cursorPosition(left.heldCursorEnd)-cursorPosition(right.heldCursorEnd));
    step.from='dnsValidator';step.to='dnsValidator';step.eventType='local';
    Object.assign(step,localContext('dnsValidator'));
  };
  const removeBookkeeping=(boundary='remove-bookkeeping-not-security-delay')=>{
    const removed=[];
    for(const record of records.values())if(record.state==='Revoked'&&record.removeEligibleAt!=null&&a.clock>=record.removeEligibleAt){record.state='Removed';removed.push(record.alias);}
    a.local(boundary,'Remove defunct database state, not an additional period of trust','dnsValidator',{values:{action:'remove-revoked-key-bookkeeping',now:a.clock,removed,revocationWasImmediate:true,revokedLineageRemainsPermanentlyUnusable:true},effects:stateEffects(),refs:[...anchorObjects.values()]});
  };
  const finish=()=>{
    const active=liveAnchors(),authenticated=!!lastObservation?.authenticated,hasAnchor=active.length>0;
    const status=authenticated?'secure':hasAnchor?'bogus':'indeterminate';
    let reason=hasAnchor?'stale-anchor-no-current-path':'no-covering-trust-anchor';
    if(authenticated){
      if(manualReset)reason='manual-anchor-recovery-validated';
      else if(provisioned)reason='anchor-provisioned-and-dnskey-matched';
      else if([...records.values()].some(record=>record.state==='Removed'&&record.revokedAt!=null))reason='anchor-revoked-and-bookkeeping-removed';
      else if([...records.values()].some(record=>record.state==='Valid'&&record.firstObserved!=null))reason=[...records.values()].some(record=>record.resetCount)?'anchor-add-after-authenticated-reset':'anchor-add-hold-down-complete';
      else reason='authenticated-trust-point-observation';
    }
    const failureStage=authenticated?null:hasAnchor?'anchor-to-dnskey':'anchor-selection';
    a.chapter('result','Anchor-management result - application untouched');
    a.local('anchor-management-result','Report management state without fabricating a leaf answer or application use','dnsValidator',{values:{action:'anchor-management-result',securityStatus:status,reasonCode:reason,leafLookupPerformed:false,answerCacheCreated:false,stubQueryPerformed:false,unrelatedTrustConfigurationPreserved:true},effects:[...stateEffects(),dnssecPut('signatureChecked',!!lastObservation?.checked),dnssecPut('securityStatus',status),dnssecPut('reasonCode',reason),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind',hasAnchor||authenticated?'local-check':'not-performed'),dnssecPut('acceptedForUse',false),dnssecPut('cached',false),dnssecPut('returnedToStub',false),dnssecPut('applicationResult',pending),dnssecPut('failureStage',failureStage),dnssecPut('firstDetector',authenticated?null:'dnsValidator'),dnssecPut('stoppedAction',authenticated?null:hasAnchor?'automatically-trust-fetched-b':'accept-untrusted-self-signed-key')],refs:[...anchorObjects.values(),...evidenceRefs,unrelated]});
    return a.finish({
      decisionPanelLabel:'Trust-anchor provisioning and RFC5011 management',
      decisionBindings:[{label:'Managed trust point',path:'dnssec.publication.trustPoint'},{label:'Configured anchors',path:'dnssec.trustStores.dnsValidator.anchors'},{label:'RFC5011 key states',path:'dnssec.timers.keyStates'},{label:'Observation checked by',path:'dnssec.validationOwner'},{label:'Management status',path:'dnssec.securityStatus'},{label:'Management reason',path:'dnssec.reasonCode'},{label:'Application (not queried)',path:'dnssec.applicationResult.status'}],
      chapterCaption:'One anchor-management history. Playback does not advance represented time, install keys, perform leaf lookups or change unrelated trust contexts.',
      protocolTimeline:{label:'RFC5011 management clocks - not answer TTLs',explanation:'Thirty days, first-observed signed Original TTL, active refresh, RRSIG validity and removal bookkeeping are independent. Eligibility is never an observation or an automatic promotion.',entries:[
        {id:'anchor-minimum-add',label:'Minimum 30-day add hold-down',startPath:'dnssec.timers.firstObserved.B',deadlinePath:'dnssec.timers.addThirtyDaysExpiresAt',statusPath:'dnssec.timers.keyStates.B',detail:'This is necessary but not sufficient; first Original TTL expiry and a later authenticated observation are also required.'},
        {id:'anchor-first-original-ttl',label:'First observation Original TTL expiry',startPath:'dnssec.timers.firstObserved.B',deadlinePath:'dnssec.timers.firstObservedOriginalTtlExpiresAt',statusPath:'dnssec.timers.keyStates.B',detail:'This signed Original TTL is remembered from the first observation; later received TTLs cannot shorten it.'},
        {id:'anchor-next-refresh',label:'Next active DNSKEY refresh',startPath:'dnssec.timers.lastValidatedObservation',deadlinePath:'dnssec.timers.nextRefreshAt',detail:'A failed query would use the separate retry interval, without treating unreachability as authenticated absence.'},
        {id:'anchor-signature',label:'Current management RRSIG validity',startPath:'dnssec.timers.signature.inception',deadlinePath:'dnssec.timers.signature.expiration',detail:'Every observation is checked at its actual represented time against exact independently verified material.'},
        {id:'anchor-remove',label:'Revoked-key removal bookkeeping',deadlinePath:'dnssec.timers.removeEligibleAt.A',statusPath:'dnssec.timers.keyStates.A',detail:'The key is unusable immediately on authenticated self-revocation; waiting does not extend trust.'},
      ]},
      dnssecNumericBindings:{scope:'anchor-management-only',trustPoint:zone,observations:numericObservations.map(observation=>({id:observation.id,now:observation.now,rrsetId:observation.rrsetId,signatureIds:observation.signatureIds})),leafPathConsumed:false},
      dnssecManagementObservationLedger:{scope:'anchor-management-only',sourceCursorResolution:'Each sourceEventId resolves to one canonical step; a compact refresh batch contains individually correlated occurrence IDs, represented receipt times, exact message headers, immutable body references and checked evidence.',observations:numericObservations},
    });
  };
  return {a,records,observe,provision,elapsed,refreshUntil,removeBookkeeping,finish};
}

function dnssecAnchorProvisionedCase(){
  const c=dnssecAnchorContext('provisioned-anchor',{zone:'.',anchors:[]});
  c.provision('root-ksk-g1');
  c.observe('root-dnskey-g1',['root-dnskey-g1-by-ksk'],{rawBoundary:'raw-trust-point-dnskey-received',boundary:'retrieved-root-key-matches-provisioning'});
  return c.finish();
}
function dnssecAnchorUntrustedCase(){
  const c=dnssecAnchorContext('untrusted-self-signed-key',{anchors:[],provisioning:'none'});
  c.observe('child-dnskey-g1',['child-dnskey-g1-by-ksk'],{rawBoundary:'raw-trust-point-dnskey-received',boundary:'self-signature-is-not-anchor-provisioning',allowUntrustedMath:false});
  return c.finish();
}
function dnssecAnchorAddCase(){
  const c=dnssecAnchorContext('rfc5011-add');
  c.observe('child-anchor-observation',['child-anchor-observation-long-signature'],{rawBoundary:'raw-trust-point-dnskey-received',boundary:'new-sep-enters-addpend'});
  c.refreshUntil(30*dnssecAnchorDay,{boundary:'refresh-observations-before-eligibility'});
  c.elapsed(35*dnssecAnchorDay,'timer-expired-alone-does-not-install','Both eligibility clocks have expired; no new observation has occurred');
  c.observe('child-anchor-observation',['child-anchor-observation-long-signature'],{offset:35*dnssecAnchorDay+1,boundary:'post-hold-down-valid-observation-installs'});
  return c.finish();
}
function dnssecAnchorInterruptedCase(){
  const c=dnssecAnchorContext('add-hold-down-interrupted');
  c.observe('child-dnskey-rollover',['child-dnskey-rollover-old-long'],{rawBoundary:'raw-trust-point-dnskey-received',boundary:'addpend-initial'});
  c.refreshUntil(10*dnssecAnchorDay-3600);
  c.observe('child-anchor-omission',['child-anchor-omission-signature'],{offset:10*dnssecAnchorDay,boundary:'validated-keyrem-resets'});
  c.refreshUntil(20*dnssecAnchorDay-3600);
  c.observe('child-dnskey-rollover',['child-dnskey-rollover-old-long'],{offset:20*dnssecAnchorDay,boundary:'newkey-restarts-hold-down'});
  c.refreshUntil(30*dnssecAnchorDay);
  c.elapsed(30*dnssecAnchorDay,'old-deadline-insufficient','The old deadline cannot complete the restarted hold-down');
  c.refreshUntil(50*dnssecAnchorDay-3600);
  c.elapsed(50*dnssecAnchorDay,'restarted-timer-alone-does-not-install','The restarted timer is eligible but still needs an authenticated observation');
  c.observe('child-dnskey-rollover',['child-dnskey-rollover-old-long'],{offset:50*dnssecAnchorDay+1,boundary:'fresh-valid-observation-after-new-deadline'});
  return c.finish();
}
function dnssecAnchorRevokeCase(){
  const c=dnssecAnchorContext('revoke-and-remove',{anchors:['A','B']});
  c.observe('child-dnskey-a-b-g0',['child-dnskey-a-b-g0-by-ksk'],{rawBoundary:'raw-trust-point-dnskey-received',boundary:'initial-already-valid-a-and-b'});
  // The initial one-hour signature is not reused at any future observation.
  c.observe('child-dnskey-ksk-overlap3',['child-dnskey-ksk-overlap3-by-child-ksk-g1-long','child-dnskey-ksk-overlap3-by-child-ksk-g2-long'],{offset:3600,boundary:'current-long-lived-a-b-z0-observation'});
  c.refreshUntil(dnssecAnchorDay-3600);
  c.observe('child-dnskey-ksk-only-final',['child-dnskey-ksk-only-final-long-signature'],{offset:dnssecAnchorDay,boundary:'withdrawal-is-missing-not-revoked'});
  c.refreshUntil(2*dnssecAnchorDay-3600);
  c.observe('child-dnskey-ksk-overlap3',['child-dnskey-ksk-overlap3-by-child-ksk-g1-long','child-dnskey-ksk-overlap3-by-child-ksk-g2-long'],{offset:2*dnssecAnchorDay,boundary:'keypres-restores-valid'});
  c.refreshUntil(3*dnssecAnchorDay-3600);
  c.observe('revoked-dnskey-a-b-z0',['revoked-dnskey-a-b-z0-self-signature','revoked-dnskey-a-b-z0-by-b-refresh'],{offset:3*dnssecAnchorDay,boundary:'validated-self-revocation-immediate'});
  c.refreshUntil(4*dnssecAnchorDay-3600);
  const withdrawn=c.observe('child-dnskey-ksk-only-final',['child-dnskey-ksk-only-final-long-signature'],{offset:4*dnssecAnchorDay,boundary:'authenticated-revoked-key-absence'});
  c.a.local('revoked-key-withdrawn','The published set omits revoked A; the validator separately authenticated the absence','dnsChild',{values:{now:c.a.clock,rrsetId:withdrawn.item.rrset.id,removalEligibilityIsValidatorBookkeeping:true},refs:[withdrawn.item.rrsetRef]});
  c.refreshUntil(34*dnssecAnchorDay);
  c.removeBookkeeping();return c.finish();
}
function dnssecAnchorOfflineCase(){
  const c=dnssecAnchorContext('offline-misses-rollover');
  c.a.chapter('offline','No observations while the resolver is offline');
  c.a.local('resolver-offline','The resolver cannot observe introduction, hold-down or revocation','dnsResolver',{values:{now:c.a.clock,refreshAvailable:false,observationHistory:[],elapsedTimeCannotCreateObservations:true},effects:[dnssecPut('timers.refreshAvailable',false)]});
  c.observe('child-dnskey-manual-day90',['child-dnskey-manual-day90-current-signature'],{offset:90*dnssecAnchorDay,rawBoundary:'raw-trust-point-dnskey-received',boundary:'return-with-stale-anchor'});
  return c.finish();
}
function dnssecAnchorManualCase(){
  const c=dnssecAnchorContext('manual-recovery');
  c.observe('child-dnskey-manual-day90',['child-dnskey-manual-day90-current-signature'],{offset:90*dnssecAnchorDay,rawBoundary:'stale-current-keyset-received',boundary:'stale-anchor-failure-before-manual-repair'});
  c.provision('B',{manual:true,boundary:'stale-trust-reset-authorized'});
  c.observe('child-dnskey-manual-day90',['child-dnskey-manual-day90-current-signature'],{offset:90*dnssecAnchorDay+1,rawBoundary:'raw-trust-point-dnskey-received',boundary:'new-anchor-path-checked'});
  return c.finish();
}

export const DNSSEC_ANCHOR_CASE_BUILDERS={
  'lab-dnssec15':{
    'provisioned-anchor':dnssecAnchorProvisionedCase,
    'untrusted-self-signed-key':dnssecAnchorUntrustedCase,
    'rfc5011-add':dnssecAnchorAddCase,
    'add-hold-down-interrupted':dnssecAnchorInterruptedCase,
    'revoke-and-remove':dnssecAnchorRevokeCase,
    'offline-misses-rollover':dnssecAnchorOfflineCase,
    'manual-recovery':dnssecAnchorManualCase,
  },
};
