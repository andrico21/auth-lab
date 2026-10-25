import {DNSSEC_BASE_CLOCK,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecCanonicalInput,dnssecCanonicalRrsetWire,dnssecCheckSignature,dnssecDsMatchesKey,dnssecTtlWindow,dnssecValidateChain} from './dnssec-validation.js';

const dnssecPublicationConstraintOrder=Object.freeze(['implementation-capability','operator-policy','digest-capability','digest-policy']);

/** Select exact immutable signed tuples, never synthesize signatures for a changed generation. */
export function dnssecPublicationBundle(signatureIds,keyIds=[]){
  const signatures=signatureIds.map(id=>dnssecMaterial('signatures',id));
  if(!signatures.length)throw new TypeError('Publication needs at least one concrete signature');
  const rrset=dnssecMaterial('rrsets',signatures[0].rrsetId);
  if(signatures.some(signature=>signature.rrsetId!==rrset.id))throw new TypeError('Mixed publication RRsets');
  return Object.freeze({rrset,signatures:Object.freeze(signatures),keys:Object.freeze(keyIds.map(id=>dnssecMaterial('keys',id)))});
}
export function dnssecPublicationDs(rrset){
  if(!['DS','CDS'].includes(rrset.type))throw new TypeError('Expected DS-format public RDATA');
  return rrset.records.map(record=>{const [keyTag,algorithm,digestType,...digest]=record.trim().split(/\s+/);return Object.freeze({owner:rrset.owner,keyTag:Number(keyTag),algorithm:Number(algorithm),digestType:Number(digestType),digestHex:digest.join('').toLowerCase()});});
}
export function dnssecPublicationPath(child,delegation){
  return [
    {zone:'.',dnskeyRrset:dnssecMaterial('rrsets','root-dnskey-g1'),dnskeySignatures:[dnssecMaterial('signatures','root-dnskey-path-long')],keys:['root-ksk-g1','root-zsk-g1'].map(id=>dnssecMaterial('keys',id))},
    {zone:'example.',dsRrset:dnssecMaterial('rrsets','root-example-ds'),dsSignatures:[dnssecMaterial('signatures','root-example-ds-path-long')],dnskeyRrset:dnssecMaterial('rrsets','example-dnskey-g1'),dnskeySignatures:[dnssecMaterial('signatures','example-dnskey-path-long')],keys:['example-ksk-g1','example-zsk-g1'].map(id=>dnssecMaterial('keys',id))},
    {zone:'lab.example.',dsRrset:delegation.rrset,dsSignatures:delegation.signatures,dnskeyRrset:child.rrset,dnskeySignatures:child.signatures,keys:child.keys},
  ];
}
export function dnssecPublicationValidate({child,delegation,answer,now,policy}){
  return dnssecValidateChain({anchor:{zone:'.',keys:[dnssecMaterial('keys','root-ksk-g1')]},links:dnssecPublicationPath(child,delegation),answer:{rrset:answer.rrset,signatures:answer.signatures},now,policy});
}
/** Cache lifetime belongs to the selected usable signature and the actual receipt, not publication. */
export function dnssecPublicationWindow(bundle,{now,receivedAt=now,receivedTtl=bundle.rrset.ttl,rrsigTtl=bundle.rrset.ttl,keys=bundle.keys,policy}={}){
  const result=dnssecCheckSignature({rrset:bundle.rrset,signatures:bundle.signatures,keys,now,policy,expectedSigner:bundle.signatures[0].signer});
  const selected=bundle.signatures.find(signature=>signature.id===result.selectedSignatureId);
  return {result,window:selected?dnssecTtlWindow({receivedTtl,rrsigTtl,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,now,receivedAt}):{valid:false,reason:result.reason,remainingSeconds:0,expiresAt:now,limits:null}};
}
export function dnssecPublicationReadyAt({publishedAt=DNSSEC_BASE_CLOCK,propagation=0,priorTtl=0,lastOldSignatureAt=publishedAt,maximumDataTtl=0}){
  return Object.freeze({activationAt:publishedAt+propagation+priorTtl,retirementAt:lastOldSignatureAt+maximumDataTtl});
}

/** Decode the actual fixed MX transport presentations, including bounded DNS name compression. */
export function dnssecPublicationDecodeMxPacket(wireHex){
  if(typeof wireHex!=='string'||wireHex.length%2||!/^[0-9a-f]+$/i.test(wireHex))throw new TypeError('Invalid DNS wire hex');
  const bytes=Uint8Array.from(wireHex.match(/../g),value=>Number.parseInt(value,16));
  const uint=(offset,width)=>{if(offset<0||offset+width>bytes.length)throw new RangeError('Truncated DNS packet');let value=0;for(let index=0;index<width;index++)value=value*256+bytes[offset+index];return value;};
  const name=start=>{
    let offset=start,end=null;const labels=[],visited=new Set();
    for(let depth=0;depth<=bytes.length;depth++){
      if(visited.has(offset))throw new TypeError('Cyclic DNS compression');visited.add(offset);
      const size=uint(offset,1);
      if((size&192)===192){const target=((size&63)<<8)|uint(offset+1,1);end??=offset+2;offset=target;continue;}
      if(size&192||size>63)throw new TypeError('Invalid DNS label');
      offset++;if(!size)return {value:labels.join('.')+'.',next:end??offset};
      if(offset+size>bytes.length)throw new RangeError('Truncated DNS name');
      labels.push(Array.from(bytes.slice(offset,offset+size),octet=>octet>=33&&octet<=126&&octet!==46&&octet!==92?String.fromCharCode(octet):'\\'+String(octet).padStart(3,'0')).join(''));offset+=size;
    }
    throw new TypeError('DNS compression depth exceeded');
  };
  let offset=12;const questions=uint(4,2),answers=uint(6,2),records=[];let owner=null,ttl=null;
  for(let index=0;index<questions;index++){offset=name(offset).next;uint(offset,4);offset+=4;}
  for(let index=0;index<answers;index++){
    const recordOwner=name(offset);offset=recordOwner.next;const type=uint(offset,2),rrclass=uint(offset+2,2),recordTtl=uint(offset+4,4),length=uint(offset+8,2),rdata=offset+10;
    if(type!==15||rrclass!==1)throw new TypeError('Expected the fixed IN MX answer');
    const preference=uint(rdata,2),exchange=name(rdata+2);
    if(exchange.next!==rdata+length)throw new TypeError('MX RDLENGTH does not match expanded transport name');
    if(owner!==null&&owner.toLowerCase()!==recordOwner.value.toLowerCase())throw new TypeError('Mixed MX owners');
    owner=recordOwner.value;ttl=ttl===null?recordTtl:Math.min(ttl,recordTtl);records.push(preference+' '+exchange.value);offset=rdata+length;
  }
  if(!records.length)throw new TypeError('Missing MX answer');
  return Object.freeze({owner,type:'MX',class:'IN',ttl,records:Object.freeze(records)});
}

/** Compare eligible referenced public keys, not literal CDS bytes or key tags alone. */
export function dnssecPublicationSignalIntent({cds,cdnskey,keys,policy,eligibleDigestTypes=[2]}){
  const ds=dnssecPublicationDs(cds),eligible=ds.filter(record=>eligibleDigestTypes.includes(record.digestType));
  const keyWires=new Map(keys.map(key=>[key.id,dnssecCanonicalRrsetWire({owner:cdnskey.owner,type:'CDNSKEY',class:'IN',ttl:0,records:[key.flags+' '+key.protocol+' '+key.algorithm+' '+key.publicKeyBase64]},{originalTtl:0})]));
  const publishedWires=cdnskey.records.map(record=>dnssecCanonicalRrsetWire({...cdnskey,records:[record]},{originalTtl:0}));
  const cdnskeyIds=keys.filter(key=>publishedWires.includes(keyWires.get(key.id))).map(key=>key.id).sort();
  const cdsIds=[...new Set(eligible.flatMap(record=>keys.filter(key=>dnssecDsMatchesKey(record,key,policy).valid).map(key=>key.id)))].sort();
  return Object.freeze({eligibleDigestTypes:Object.freeze([...eligibleDigestTypes]),cdsKeyIds:Object.freeze(cdsIds),cdnskeyIds:Object.freeze(cdnskeyIds),keyIds:Object.freeze(cdsIds),consistent:eligible.length>0&&cdsIds.length>0&&JSON.stringify(cdsIds)===JSON.stringify(cdnskeyIds),allEligibleDigestsMatched:eligible.every(record=>keys.some(key=>dnssecDsMatchesKey(record,key,policy).valid))});
}

export function dnssecPublicationCanonicalParts(rrset,signature){
  const rrsetWireHex=dnssecCanonicalRrsetWire(rrset,{originalTtl:signature.originalTtl}),signatureHex=signature.signatureHex,rrsigRdataHex=signature.rrsigRdataHex;
  const prefix=rrsigRdataHex.slice(0,rrsigRdataHex.length-signatureHex.length),inputHex=dnssecCanonicalInput(rrset,signature);
  return {rrsetWireHex,rrsigPrefixHex:prefix,signatureHex,rrsigMetadataIncluded:inputHex===prefix+rrsetWireHex,signatureOctetsExcludedFromInput:rrsigRdataHex===prefix+signatureHex&&inputHex.length===prefix.length+rrsetWireHex.length};
}
export function dnssecPublicationCanonicalRdatas(rrset){
  const wire=dnssecCanonicalRrsetWire(rrset),result=[];let offset=0;
  while(offset<wire.length){
    let size;do{size=Number.parseInt(wire.slice(offset,offset+2),16);offset+=2+size*2;}while(size);
    const length=Number.parseInt(wire.slice(offset+16,offset+20),16);offset+=20;result.push(wire.slice(offset,offset+length*2));offset+=length*2;
  }
  return result;
}
export function dnssecPublicationApplicationRecords(rrset){
  if(rrset.type!=='MX')return rrset.records;
  return dnssecPublicationCanonicalRdatas(rrset).map(wire=>{const preference=Number.parseInt(wire.slice(0,4),16),labels=[];let offset=4,size;while((size=Number.parseInt(wire.slice(offset,offset+2),16))){offset+=2;let label='';for(let index=0;index<size;index++){const octet=Number.parseInt(wire.slice(offset+index*2,offset+index*2+2),16);label+=octet>=33&&octet<=126&&octet!==46&&octet!==92?String.fromCharCode(octet):'\\'+String(octet).padStart(3,'0');}labels.push(label);offset+=size*2;}return preference+' '+labels.join('.')+'.';});
}
export function dnssecPublicationPolicyDetails({child,delegation,policy,result,focus='capabilities'}){
  const ds=dnssecPublicationDs(delegation.rrset),advertisedSigningAlgorithms=[...new Set(ds.map(record=>record.algorithm))].sort((a,b)=>a-b),dsDigestTypes=[...new Set(ds.map(record=>record.digestType))].sort((a,b)=>a-b),implementationCapable=[...policy.implementationCapabilities.validationAlgorithms],implementationDigestTypes=[...policy.implementationCapabilities.dsDigestTypes],usableDsPaths=ds.filter(record=>child.keys.some(key=>dnssecDsMatchesKey(record,key,policy).valid)).length;
  const selected=result?.selectedEvidence.find(item=>item.stage==='answer-signature'),selectedDs=result?.selectedEvidence.find(item=>item.stage==='ds-digest'&&item.zone==='lab.example.'),selectedAlgorithm=selected?dnssecMaterial('keys',selected.keyId).algorithm:null,signingAlgorithm=selectedAlgorithm??child.signatures[0].algorithm,dsDigest=selectedDs?.digestType??ds.find(record=>policy.dsDigestTypes.includes(record.digestType))?.digestType??ds[0].digestType;
  const algorithm=policy.registry.algorithms.find(row=>Number(row.number)===signingAlgorithm),digest=policy.registry.dsDigests.find(row=>Number(row.value)===dsDigest),unsupported=advertisedSigningAlgorithms.filter(value=>!policy.validationAlgorithms.includes(value));
  const relatedDeprecated=policy.registry.algorithms.filter(row=>unsupported.some(value=>value===Number(row.number)||policy.registry.algorithms.find(item=>Number(item.number)===value)?.mnemonic==='RSASHA1'&&row.mnemonic.startsWith('RSASHA1'))).map(row=>Number(row.number));
  // Registry requirements, the declared engine, fixed arithmetic coverage,
  // publisher generation and operator use policy are independent dimensions.
  const rejectedPaths=ds.map(record=>{
    const reasons=[];
    if(!implementationCapable.includes(record.algorithm))reasons.push('implementation-capability');
    if(!policy.validationAlgorithms.includes(record.algorithm))reasons.push('operator-policy');
    if(!implementationDigestTypes.includes(record.digestType))reasons.push('digest-capability');
    if(!policy.dsDigestTypes.includes(record.digestType))reasons.push('digest-policy');
    const primaryReason=reasons.includes('implementation-capability')?'implementation-capability':reasons.includes('digest-capability')?'digest-capability':reasons[0]||null;
    return {algorithm:record.algorithm,digestType:record.digestType,reasons,primaryReason};
  }).filter(path=>path.reasons.length);
  // Primary blockers explain rejection without erasing other independent limits.
  const unsupportedReasons=dnssecPublicationConstraintOrder.filter(reason=>rejectedPaths.some(path=>path.reasons.includes(reason)));
  const primaryReasons=[...new Set(rejectedPaths.map(path=>path.primaryReason))],unsupportedReason=primaryReasons.length>1?'multiple-path-constraints':primaryReasons[0]||null;
  return {signingAlgorithm,dsDigest,advertisedSigningAlgorithms,dsDigestTypes,implementationCapable,implementationDigestTypes,implementationDeclarationScope:policy.implementationCapabilities.declarationScope,fixtureValidationAlgorithms:[...policy.fixtureCoverage.validationAlgorithms],fixtureDigestTypes:[...policy.fixtureCoverage.dsDigestTypes],fixtureCoverageScope:policy.fixtureCoverage.scope,publisherSigningAlgorithms:[...policy.signingAlgorithms],operatorAccepted:focus==='capabilities'?[...policy.validationAlgorithms]:policy.validationAlgorithms.includes(signingAlgorithm),usableDsPaths,unsupportedReason,unsupportedReasons,rejectedPaths,operatorUnsupported:relatedDeprecated.sort((a,b)=>a-b),usedPathAlgorithm:selectedAlgorithm,usedDsDigest:selectedDs?.digestType??dsDigest,allSignaturesMustVerify:false,obsoleteExtrasPoisonAnswer:unsupported.length>0&&result?.securityStatus!=='secure',...focus==='digest'?{useForDelegation:digest.useForDelegation,useForValidation:digest.useForValidation,implementForDelegation:digest.implementForDelegation,implementForValidation:digest.implementForValidation,compatibilityValidation:policy.id==='legacy-ds-sha1'&&policy.dsDigestTypes.includes(dsDigest),newDsCreated:false}:{useForSigning:algorithm.useForSigning,useForValidation:algorithm.useForValidation,implementForSigning:algorithm.implementForSigning,implementForValidation:algorithm.implementForValidation}};
}
