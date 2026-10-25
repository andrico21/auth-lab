import {dnssecCheckSignature,dnssecDsMatchesKey,dnssecCanonicalName} from './dnssec-validation.js';

const dnssecParentSameSet=(left,right)=>left.length===right.length&&left.every(value=>right.includes(value));
const dnssecParentUnique=values=>[...new Set(values)].sort();
const dnssecParentWords=record=>String(record).trim().split(/\s+/);

/** RFC9975 uses the current delegation implementation column, not all supported digests. */
export function dnssecParentEligibleDigests(policy){
  return policy.registry.dsDigests.filter(row=>row.implementForDelegation==='MUST'&&row.useForDelegation!=='MUST NOT').map(row=>Number(row.value)).filter(Number.isInteger);
}
export function dnssecParentDsRecords(rrset,owner=rrset.owner){
  return rrset.records.map(record=>{const [tag,algorithm,digestType,...digest]=dnssecParentWords(record);return {owner,keyTag:Number(tag),algorithm:Number(algorithm),digestType:Number(digestType),digestHex:digest.join('').toLowerCase()};});
}
export function dnssecParentKeyRecords(rrset,keys){
  return rrset.records.map(record=>{
    const [flags,protocol,algorithm,...publicKey]=dnssecParentWords(record),bytes=publicKey.join('');
    return keys.find(key=>dnssecCanonicalName(key.owner)===dnssecCanonicalName(rrset.owner)&&key.flags===Number(flags)&&key.protocol===Number(protocol)&&key.algorithm===Number(algorithm)&&key.publicKeyBase64===bytes)||null;
  });
}
export function dnssecParentIntent(rrset,keys,policy){
  if(!rrset)return {kind:'no-change',keys:[],valid:true,reason:'authenticated-nodata'};
  const records=rrset.records.map(dnssecParentWords),cds=rrset.type==='CDS';
  const exactDelete=records.length===1&&(cds?records[0].length===4&&Number(records[0][0])===0&&Number(records[0][1])===0&&Number(records[0][2])===0&&records[0][3].toLowerCase()==='00':records[0].length===4&&Number(records[0][0])===0&&Number(records[0][1])===3&&Number(records[0][2])===0&&records[0][3]==='AA==');
  if(exactDelete)return {kind:'delete',keys:[],valid:true,reason:'exact-authenticated-singleton-delete'};
  const sentinel=records.some(record=>cds?Number(record[1])===0||Number(record[2])===0:Number(record[2])===0);
  if(sentinel){
    const eligible=dnssecParentEligibleDigests(policy),validKeyReferences=cds?dnssecParentUnique(dnssecParentDsRecords(rrset).filter(ds=>eligible.includes(ds.digestType)).flatMap(ds=>keys.filter(key=>dnssecDsMatchesKey(ds,key,policy).valid).map(key=>key.id))):dnssecParentUnique(dnssecParentKeyRecords(rrset,keys).filter(Boolean).map(key=>key.id));
    return {kind:'malformed',keys:[],valid:false,reason:'malformed-delete-signal',validKeyReferences};
  }
  if(!cds){
    const selected=dnssecParentKeyRecords(rrset,keys),valid=selected.length>0&&selected.every(key=>key&&key.protocol===3&&(key.flags&256)!==0&&policy.validationAlgorithms.includes(key.algorithm));
    return {kind:'update',keys:dnssecParentUnique(selected.filter(Boolean).map(key=>key.id)),valid,reason:valid?'eligible-cdnskey-identity':'unusable-cdnskey'};
  }
  const eligible=dnssecParentEligibleDigests(policy),descriptors=dnssecParentDsRecords(rrset).filter(ds=>eligible.includes(ds.digestType)),matches=descriptors.map(ds=>keys.filter(key=>dnssecDsMatchesKey(ds,key,policy).valid));
  const valid=descriptors.length>0&&matches.every(list=>list.length>0);
  return {kind:'update',keys:dnssecParentUnique(matches.flatMap(list=>list.map(key=>key.id))),valid,reason:valid?'eligible-cds-digest-identity':'unmatched-eligible-cds',eligibleDigestTypes:eligible,ignoredDigestTypes:dnssecParentUnique(dnssecParentDsRecords(rrset).filter(ds=>!eligible.includes(ds.digestType)).map(ds=>ds.digestType))};
}

/** A timeout has no DNS response and cannot vote as NODATA or DELETE. */
export function dnssecParentCompareSignals({addresses,responses,keys,policy,deferUnreachable=true}){
  const observed=[],missing=[],failures=[];
  for(const address of addresses){
    const response=responses.find(item=>item.address===address);
    if(!response||response.transport==='timeout'){missing.push(address);continue;}
    const types={};
    for(const type of ['CDS','CDNSKEY']){
      const item=response[type];
      if(!item||!item.authenticated){failures.push({address,type,reason:'signal-not-authenticated'});continue;}
      types[type]=dnssecParentIntent(item.rrset,keys,policy);
      if(!types[type].valid)failures.push({address,type,reason:types[type].reason});
    }
    if(types.CDS&&types.CDNSKEY){
      const crossType=types.CDS.kind===types.CDNSKEY.kind&&dnssecParentSameSet(types.CDS.keys,types.CDNSKEY.keys);
      if(!crossType)failures.push({address,reason:'cds-cdnskey-keyset-disagreement'});
      observed.push({address,types,crossType,kind:types.CDNSKEY.kind,keys:types.CDNSKEY.keys});
    }
  }
  const first=observed[0],sameAcross=!!first&&observed.every(item=>item.kind===first.kind&&dnssecParentSameSet(item.keys,first.keys));
  if(!sameAcross&&observed.length){const nodata=observed.some(item=>item.kind==='no-change');failures.push({reason:nodata?'nodata-delete-inconsistency':'inconsistent-authority-intent'});}
  const malformed=failures.find(item=>item.reason==='malformed-delete-signal'),unauthenticated=failures.find(item=>item.reason==='signal-not-authenticated'),cross=failures.find(item=>item.reason==='cds-cdnskey-keyset-disagreement'),across=failures.find(item=>['nodata-delete-inconsistency','inconsistent-authority-intent'].includes(item.reason));
  const reason=malformed?.reason||unauthenticated?.reason||cross?.reason||across?.reason||(missing.length&&deferUnreachable?'retry-unreachable-authority':!first?'no-received-signal':first.kind==='no-change'?'no-change':'eligible-keysets-consistent');
  return {checked:true,consistent:failures.length===0&&sameAcross,complete:missing.length===0,allAddressesQueried:addresses.every(address=>responses.some(item=>item.address===address)),deferred:missing.length>0&&deferUnreachable,valid:failures.length===0&&sameAcross&&(!deferUnreachable||missing.length===0),kind:first?.kind||null,keys:first?.keys||[],observed,missing,failures,reason};
}

/** Simulate the proposed delegation using only digest-matched DNSKEY signers. */
export function dnssecParentContinuity({ds,dnskeyRrset,signatures,keys,now,policy}){
  const matches=keys.filter(key=>ds.some(record=>dnssecDsMatchesKey(record,key,policy).valid));
  const check=dnssecCheckSignature({rrset:dnskeyRrset,signatures,keys:matches,now,policy,expectedSigner:dnskeyRrset.owner});
  return {checked:true,valid:matches.length>0&&check.valid,matchedKeyIds:matches.map(key=>key.id),signatureCheck:check,reason:matches.length===0?'no-proposed-ds-key-match':check.valid?'resulting-dnskey-path-usable':'no-ds-matched-dnskey-signature'};
}
export function dnssecParentLockPolicy({automationActor='registry',clientUpdateProhibited=false,serverUpdateProhibited=false,transferProhibited=false,deleteProhibited=false,explicitAutomationSuspension=false}={}){
  return {automationActor,clientUpdateProhibited,serverUpdateProhibited,transferProhibited,deleteProhibited,registrarEppUpdateRejected:automationActor==='registrar'&&serverUpdateProhibited,automationSuspended:explicitAutomationSuspension,allowed:!explicitAutomationSuspension&&!(automationActor==='registrar'&&serverUpdateProhibited)};
}
export function dnssecParentManualChange(state,{source,ds,authenticated}){
  if(!authenticated)return {...state,accepted:false,reason:'manual-channel-not-authenticated'};
  const outOfBand=source==='manual-recovery',empty=ds.length===0;
  return {...state,ds:[...ds],generation:empty?'absent':outOfBand?'ds-manual-k1':state.generation,automationSuspended:outOfBand?empty:state.automationSuspended,accepted:true,reason:outOfBand?empty?'out-of-band-removal-suspends':'nonempty-manual-provision-resumes':'in-band-delete-keeps-automation'};
}
export function dnssecParentDsyncEndpoint(rrset,addressRecords){
  const entries=rrset.records.map(record=>{const [rrtype,scheme,port,target]=dnssecParentWords(record),addresses=addressRecords.filter(item=>item.owner===target&&['A','AAAA'].includes(item.type)).flatMap(item=>item.records),usable=(rrtype==='CDS'||rrtype==='59')&&Number(scheme)===1&&Number(port)>0&&Number(port)<=65535&&addresses.length>0;return {rrtype,scheme:Number(scheme),port:Number(port),target,addresses,resolves:addresses.length>0,ignored:!usable,usable};});
  return {entries,selected:entries.find(entry=>entry.usable)||null};
}
