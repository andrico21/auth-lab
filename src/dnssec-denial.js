import {DNSSEC_MATERIAL,dnssecProfile} from './dnssec-fixtures.js';
import {dnssecCanonicalName,dnssecCheckSignature,dnssecTtlWindow} from './dnssec-validation.js';

function dnssecDenialFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(dnssecDenialFreeze);Object.freeze(value);}return value;}
function dnssecDenialLabels(name){const hex=dnssecCanonicalName(name),labels=[];let p=0;while(p<hex.length){const size=parseInt(hex.slice(p,p+2),16);p+=2;if(!size)break;labels.push(hex.slice(p,p+size*2));p+=size*2;}return labels;}
function dnssecDenialEqual(a,b){return dnssecCanonicalName(a)===dnssecCanonicalName(b);}
function dnssecDenialWithin(name,zone){const n=dnssecDenialLabels(name),z=dnssecDenialLabels(zone);return n.length>=z.length&&z.every((label,i)=>label===n[n.length-z.length+i]);}
function dnssecDenialSuffix(name,count){if(count===0)return '.';const labels=dnssecDenialLabels(name).slice(-count);return labels.map(label=>{let text='';for(let i=0;i<label.length;i+=2){const byte=parseInt(label.slice(i,i+2),16);text+=byte>32&&byte<127&&byte!==46&&byte!==92?String.fromCharCode(byte):'\\'+String(byte).padStart(3,'0');}return text;}).join('.')+'.';}
export function dnssecDenialCompareNames(a,b){const aa=dnssecDenialLabels(a).reverse(),bb=dnssecDenialLabels(b).reverse();for(let i=0;i<Math.min(aa.length,bb.length);i++){if(aa[i]!==bb[i])return aa[i]<bb[i]?-1:1;}return Math.sign(aa.length-bb.length);}
export function dnssecDenialIntervalContains(owner,next,name){const cmp=dnssecDenialCompareNames(owner,next),left=dnssecDenialCompareNames(owner,name),right=dnssecDenialCompareNames(name,next);return cmp<0?left<0&&right<0:cmp>0?left<0||right<0:!dnssecDenialEqual(owner,name);}
const dnssecDenialTypeCodes={A:1,NS:2,CNAME:5,SOA:6,MX:15,TXT:16,AAAA:28,DNAME:39,DS:43,RRSIG:46,NSEC:47,DNSKEY:48,NSEC3:50,NSEC3PARAM:51,CDS:59,CDNSKEY:60,NXNAME:128};
function dnssecDenialType(type){if(typeof type==='number')return type;const text=String(type).toUpperCase();return dnssecDenialTypeCodes[text]??(/^TYPE\d+$/.test(text)?Number(text.slice(4)):null);}
function dnssecDenialParse(rrset){if(!['NSEC','NSEC3'].includes(rrset.type)||rrset.records.length!==1)throw new TypeError('Denial proof must contain one NSEC or NSEC3 record');const parts=rrset.records[0].trim().split(/\s+/);if(rrset.type==='NSEC')return {format:'NSEC',owner:rrset.owner,next:parts[0],types:parts.slice(1).map(dnssecDenialType)};return {format:'NSEC3',owner:rrset.owner,ownerHash:rrset.owner.split('.')[0].toUpperCase(),hashAlgorithm:Number(parts[0]),flags:Number(parts[1]),iterations:Number(parts[2]),saltHex:parts[3]==='-'?'':parts[3].toLowerCase(),nextHash:parts[4].toUpperCase(),types:parts.slice(5).map(dnssecDenialType)};}
function dnssecDenialHash(name,parameters){const canonical=dnssecCanonicalName(name);const entry=Object.values(DNSSEC_MATERIAL.nsec3).find(item=>dnssecCanonicalName(item.owner)===canonical&&item.hashAlgorithm===parameters.hashAlgorithm&&item.iterations===parameters.iterations&&item.saltHex.toLowerCase()===parameters.saltHex);if(entry)return {hash:entry.hashBase32hex.toUpperCase(),reference:entry.id,canonicalNameHex:canonical,...parameters,totalHashApplications:entry.iterations+1};const profile=DNSSEC_MATERIAL.vectors['resolution-profile-fixtures:queriedNameHashes'];if(parameters.hashAlgorithm===1&&parameters.iterations===0&&parameters.saltHex===''&&profile){const key=Object.keys(profile).find(owner=>dnssecCanonicalName(owner)===canonical);if(key)return {hash:profile[key].toUpperCase(),reference:'resolution-profile-fixtures:queriedNameHashes:'+key,canonicalNameHex:canonical,...parameters,totalHashApplications:1};}return null;}
function dnssecDenialHashCovers(record,hash){return record.ownerHash<record.nextHash?record.ownerHash<hash&&hash<record.nextHash:record.ownerHash>record.nextHash?hash>record.ownerHash||hash<record.nextHash:hash!==record.ownerHash;}
/** Describe authenticated parsed inputs; display annotations never decide proof acceptance. */
export function dnssecDenialDescribeProof(record){
  const order=['SOA','NS','A','AAAA','CNAME','DNAME','DS','DNSKEY','NSEC3PARAM','RRSIG','NSEC','NSEC3'],names=record.types.map(code=>Object.keys(dnssecDenialTypeCodes).find(name=>dnssecDenialTypeCodes[name]===code)||'TYPE'+code);
  names.sort((a,b)=>{const ai=order.indexOf(a),bi=order.indexOf(b);return (ai<0?order.length:ai)-(bi<0?order.length:bi)||(a<b?-1:a>b?1:0);});
  const description={...record,typeCodes:[...record.types],types:names};
  if(record.format==='NSEC3'){
    const tuple=Object.values(DNSSEC_MATERIAL.nsec3).find(tuple=>tuple.hashAlgorithm===record.hashAlgorithm&&tuple.iterations===record.iterations&&tuple.saltHex.toLowerCase()===record.saltHex&&tuple.hashBase32hex.toUpperCase()===record.ownerHash);
    const profile=DNSSEC_MATERIAL.vectors['nsec3-no-wildcard'],profileMatches=profile.hashAlgorithm===record.hashAlgorithm&&profile.iterations===record.iterations&&profile.saltHex.toLowerCase()===record.saltHex&&dnssecDenialEqual(record.owner,record.ownerHash+'.'+profile.zone);
    const chain=profileMatches?profile.chain.find(tuple=>tuple.rrsetId===record.rrsetId&&tuple.ownerHash===record.ownerHash&&tuple.nextHash===record.nextHash&&tuple.flags===record.flags):null;
    const query=!tuple&&!chain&&record.hashAlgorithm===1&&record.iterations===0&&record.saltHex===''?Object.entries(DNSSEC_MATERIAL.vectors['resolution-profile-fixtures:queriedNameHashes']).find(([,hash])=>hash.toUpperCase()===record.ownerHash):null;
    description.originalOwner=tuple?.owner||chain?.originalOwner||query?.[0]||null;
    description.originalOwnerReference=tuple?.id||(chain?'nsec3-no-wildcard#chain:'+chain.rrsetId:query?'resolution-profile-fixtures:queriedNameHashes:'+query[0]:null);
    description.originalOwnerSource='independent exact hash/parameter reference; not a DNSSEC assertion or hash inversion';
  }
  return dnssecDenialFreeze(description);
}

/** Keys are authenticated by the caller. This checks proof evidence, not chain/AD/application acceptance. */
export function dnssecCheckDenial({qname,qtype,zone,proofs=[],keys=[],now,policy=dnssecProfile(),purpose='negative',wildcardOwner=null,delegation=null,delegationNs=null,requiredZone=zone,aggressive=false,compact=false}){
  const checks=[],records=[],hashes=[],proofRoles=[];let checked=false;
  const result=(valid,reason,kind=null,extra={})=>dnssecDenialFreeze({checked,valid,reason,kind,zone,proofZone:zone,qname,qtype,purpose,records,proofRoles,checks,hashes,evidenceMode:'symbolic-reference-bound',evidenceRefs:checks.flatMap(check=>check.signature.evidenceRefs||[]),...extra});
  for(const proof of proofs){const signature=dnssecCheckSignature({rrset:proof.rrset,signatures:proof.signatures,keys,now,policy,expectedSigner:zone});checked||=signature.checked;checks.push({rrsetId:proof.rrset.id,signature});if(!signature.valid)return result(false,'denial-signature-not-usable');if(!dnssecDenialWithin(proof.rrset.owner,zone))return result(false,'proof-owner-outside-zone');const record=dnssecDenialParse(proof.rrset);record.rrsetId=proof.rrset.id;if(record.types.some(type=>type===null))return result(false,'unknown-bitmap-type');if(record.format==='NSEC'&&!dnssecDenialWithin(record.next,zone))return result(false,'proof-next-outside-zone');records.push(record);}
  if(!dnssecDenialWithin(qname,requiredZone)||!dnssecDenialEqual(zone,requiredZone))return result(false,'proof-from-wrong-zone');
  if(records.some(record=>record.format==='NSEC3'&&dnssecDenialLabels(record.owner).length!==dnssecDenialLabels(zone).length+1))return result(false,'nsec3-owner-not-direct-hash-label');
  if(purpose==='no-ds'&&dnssecDenialType(qtype)!==43)return result(false,'no-ds-purpose-requires-ds-question');
  if(!records.length)return result(false,'missing-denial-proof');
  const role=(name,record)=>{if(record)proofRoles.push({role:name,rrsetId:record.rrsetId});return record;};
  const lacks=record=>record&&!record.types.includes(dnssecDenialType(qtype))&&!record.types.includes(5);
  // RFC 6840 section 4.1: a valid signature does not grant authority below
  // a delegation or DNAME. The signer is already constrained to zone above.
  const ancestorDelegation=(record,owner)=>record.types.includes(2)&&!record.types.includes(6)&&!dnssecDenialEqual(owner,zone);
  const authorityFailure=(record,owner)=>!dnssecDenialWithin(qname,owner)?null:ancestorDelegation(record,owner)&&(!dnssecDenialEqual(qname,owner)||dnssecDenialType(qtype)!==43)?'ancestor-delegation-not-denial-authority':record.types.includes(39)&&!dnssecDenialEqual(qname,owner)?'dname-subtree-not-denial-authority':null;
  if(records.every(record=>record.format==='NSEC')){
    for(const record of records){const reason=authorityFailure(record,record.owner);if(reason)return result(false,reason);}
    const exact=records.find(record=>dnssecDenialEqual(record.owner,qname));
    const isCompact=compact||records.some(record=>record.types.includes(128));
    if(isCompact){if(aggressive)return result(false,'compact-proof-not-wide-aggressive-evidence');if(!exact)return result(false,'compact-proof-owner-mismatch');role('exact-owner-bitmap',exact);const minimumNext='\\000.'+qname;if(!dnssecDenialEqual(exact.next,minimumNext))return result(false,'compact-proof-not-minimally-covering');if(!lacks(exact))return result(false,'requested-type-or-cname-present');const nxname=exact.types.includes(128),ent=!nxname&&exact.types.every(type=>type===46||type===47);return result(true,nxname?'compact-nxname-bitmap-authenticated':ent?'authenticated-empty-nonterminal':'authenticated-type-absence',nxname?'compact-nxdomain':ent?'empty-nonterminal':'nodata',{nxname,compact:true,broadSynthesisAllowed:false,qnameCovered:nxname,wildcardCovered:false});}
    if(purpose==='no-ds'){if(!exact||!exact.types.includes(2)||exact.types.includes(6)||exact.types.includes(43))return result(false,'no-ds-requires-parent-delegation-bitmap');role('exact-delegation-no-ds',exact);return result(true,'authenticated-no-ds-at-delegation','no-ds',{insecureDelegation:qname});}
    if(exact&&lacks(exact)){role('exact-owner-type-absence',exact);return result(true,'authenticated-type-absence','nodata',{ownerMatched:true});}
    if(exact)return result(false,'requested-type-or-cname-present');
    const cover=role('requested-name-interval',records.find(record=>dnssecDenialIntervalContains(record.owner,record.next,qname)&&!(record.types.includes(2)&&!record.types.includes(6)&&dnssecDenialWithin(qname,record.owner))));
    if(!cover)return result(false,'requested-name-not-covered');
    if(dnssecDenialWithin(cover.next,qname)&&!dnssecDenialEqual(cover.next,qname)){return result(true,'authenticated-empty-nonterminal','empty-nonterminal',{qnameCovered:true,descendant:cover.next});}
    let closestEncloser=zone;for(let count=dnssecDenialLabels(qname).length-1;count>=dnssecDenialLabels(zone).length;count--){const suffix=dnssecDenialSuffix(qname,count);if(records.some(record=>dnssecDenialWithin(record.owner,suffix)||dnssecDenialWithin(record.next,suffix))){closestEncloser=suffix;break;}}
    if(wildcardOwner){const expected='*.'+closestEncloser;if(!dnssecDenialEqual(wildcardOwner,expected))return result(false,'wildcard-closest-encloser-mismatch');}
    const wildcard=wildcardOwner||'*.'+closestEncloser,nextCloser=dnssecDenialSuffix(qname,dnssecDenialLabels(closestEncloser).length+1),extra={closestEncloser,nextCloser,wildcard,qnameCovered:true,nextCloserCovered:true};
    if(purpose==='wildcard-positive')return result(true,'wildcard-signature-and-no-closer-match-verified','wildcard-positive',extra);
    if(purpose==='wildcard-nodata'){const wildcardMatch=role('wildcard-owner-type-absence',records.find(record=>dnssecDenialEqual(record.owner,wildcard)&&lacks(record)));return wildcardMatch?result(true,'wildcard-type-absence-plus-no-closer-match','nodata-wildcard',{...extra,wildcardOwnerMatched:true}):result(false,'wildcard-type-absence-proof-missing',null,extra);}
    const wildcardCover=role('closest-wildcard-interval',records.find(record=>dnssecDenialIntervalContains(record.owner,record.next,wildcard)));return wildcardCover?result(true,'authenticated-name-and-wildcard-absence','nxdomain',{...extra,wildcardCovered:true}):result(false,'missing-wildcard-exclusion',null,{...extra,wildcardCovered:false});
  }
  if(!records.every(record=>record.format==='NSEC3'))return result(false,'mixed-denial-formats');
  const parameters={hashAlgorithm:records[0].hashAlgorithm,iterations:records[0].iterations,saltHex:records[0].saltHex};
  if(records.some(record=>record.hashAlgorithm!==parameters.hashAlgorithm||record.iterations!==parameters.iterations||record.saltHex!==parameters.saltHex))return result(false,'nsec3-hash-parameter-mismatch');
  if(parameters.hashAlgorithm!==1)return result(false,'unsupported-nsec3-hash');
  if(parameters.iterations>(policy.nsec3?.maxIterations??policy.nsec3?.iterations??0))return result(false,'nsec3-iterations-resource-policy');
  if(aggressive&&records.some(record=>record.flags&1))return result(false,'optout-not-secure-aggressive-absence');
  const hash=name=>{const value=dnssecDenialHash(name,parameters);if(value)hashes.push({name,...value});return value?.hash||null;};
  const qhash=hash(qname),match=qhash&&records.find(record=>record.ownerHash===qhash);
  if(match){const reason=authorityFailure(match,qname);if(reason)return result(false,reason);}
  if(match&&lacks(match)){role('matching-name-hash-bitmap',match);if(purpose==='no-ds'&&(!match.types.includes(2)||match.types.includes(6)||match.types.includes(43)))return result(false,'no-ds-requires-parent-delegation-bitmap');return result(true,purpose==='no-ds'?'authenticated-no-ds-at-delegation':'authenticated-nsec3-type-absence',purpose==='no-ds'?'no-ds':'nodata',{ownerMatched:true});}
  if(match)return result(false,'requested-type-or-cname-present');
  let closestEncloser=null,closestRecord=null;for(let count=dnssecDenialLabels(qname).length-1;count>=dnssecDenialLabels(zone).length;count--){const name=dnssecDenialSuffix(qname,count),value=hash(name),record=value&&records.find(item=>item.ownerHash===value);if(record){closestEncloser=name;closestRecord=record;break;}}
  if(!closestEncloser){const wildcardHash=hash('*.'+zone);return result(false,'nsec3-closest-encloser-match-missing',null,{nextCloserCovered:!!qhash&&records.some(record=>dnssecDenialHashCovers(record,qhash)),wildcardCovered:!!wildcardHash&&records.some(record=>!(record.flags&1)&&dnssecDenialHashCovers(record,wildcardHash))});}role('matching-closest-encloser-hash',closestRecord);
  // RFC 5155 section 8.3 requires a proper-zone closest encloser, not
  // a delegation or a name whose descendants are redirected by DNAME.
  if(closestRecord.types.includes(39))return result(false,'dname-subtree-not-denial-authority');
  if(closestRecord.types.includes(2)&&!closestRecord.types.includes(6))return result(false,'ancestor-delegation-not-denial-authority');
  const nextCloser=dnssecDenialSuffix(qname,dnssecDenialLabels(closestEncloser).length+1),nextHash=hash(nextCloser),wildcard='*.'+closestEncloser,extra={closestEncloser,nextCloser,wildcard};if(!nextHash)return result(false,'nsec3-independent-hash-tuple-missing',null,extra);
  const nextProof=role('covering-next-closer-hash',records.find(record=>dnssecDenialHashCovers(record,nextHash)));if(!nextProof)return result(false,'nsec3-next-closer-not-covered',null,extra);
  extra.nextCloserCovered=true;
  if(nextProof.flags&1){if(aggressive)return result(false,'optout-not-secure-aggressive-absence',null,extra);if(purpose!=='optout-delegation'||!delegation||!dnssecDenialEqual(delegation,nextCloser)||!delegationNs||delegationNs.type!=='NS'||!dnssecDenialEqual(delegationNs.owner,delegation)||!delegationNs.records.length)return result(false,'optout-does-not-prove-name-absence',null,extra);return result(true,'authenticated-optout-unsigned-delegation','optout-delegation',{...extra,insecureDelegation:delegation,optOut:true,delegationNsId:delegationNs.id});}
  const wildcardHash=hash(wildcard);if(!wildcardHash)return result(false,'nsec3-independent-hash-tuple-missing',null,extra);const wildcardProof=role('covering-closest-wildcard-hash',records.find(record=>!(record.flags&1)&&dnssecDenialHashCovers(record,wildcardHash)));return wildcardProof?result(true,'authenticated-nsec3-closest-next-and-wildcard','nxdomain',{...extra,qnameCovered:true,wildcardCovered:true,optOut:false}):result(false,'nsec3-wildcard-exclusion-missing',null,extra);
}

export function dnssecDenialCacheWindow({rrset,signatures,check,receivedAt,now,receivedTtl=rrset.ttl,rrsigTtl=receivedTtl,negativeSoa=null,maxNegativeProofTtl=10800}){const selected=signatures.find(signature=>signature.id===check.selectedSignatureId);if(!check.valid||!selected)return dnssecDenialFreeze({valid:false,expiresAt:receivedAt,remainingSeconds:0,reason:'no-usable-signature'});const window=dnssecTtlWindow({receivedTtl,rrsigTtl,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,receivedAt,now}),cap=negativeSoa?Math.min(negativeSoa.ttl,negativeSoa.minimum,maxNegativeProofTtl):['NSEC','NSEC3'].includes(rrset.type)?maxNegativeProofTtl:Infinity,expiresAt=Math.min(window.expiresAt,receivedAt+cap);return dnssecDenialFreeze({...window,expiresAt,remainingSeconds:Math.max(0,expiresAt-now),valid:window.valid&&expiresAt>now,selectedSignatureId:selected.id,signatureDeadline:selected.expiration});}
export function dnssecDenialCacheKey({view,trustStore,qname,qtype,qclass='IN',checkingContext='CD0',negativeKind=null,failure=false}){return [view,trustStore,dnssecDenialSuffix(qname,dnssecDenialLabels(qname).length),...negativeKind==='NXDOMAIN'?[]:[String(qtype).toUpperCase()],qclass,...failure?[checkingContext]:[]];}
export function dnssecDenialCacheEligible(entry,context,now){return entry.expiresAt>now&&entry.signatureDeadline>=now&&JSON.stringify(entry.key)===JSON.stringify(dnssecDenialCacheKey(context));}
