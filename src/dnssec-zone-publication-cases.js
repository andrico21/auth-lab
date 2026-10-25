import {dnssecAuthor,dnssecPut,dnssecAppend} from './dnssec-authoring.js';
import {DNSSEC_BASE_CLOCK,DNSSEC_MATERIAL,dnssecMaterial} from './dnssec-fixtures.js';
import {dnssecCanonicalName,dnssecCanonicalRrsetWire,dnssecCheckSignature,dnssecValidateChain,dnssecTtlWindow} from './dnssec-validation.js';
import {dnssecLookupPath,dnssecLookupMessage} from './dnssec-lookup.js';

// Fixed public wire records are decoded here, not accepted because of their fixture IDs.
const dnssecZoneTypes={1:'A',2:'NS',5:'CNAME',6:'SOA',15:'MX',16:'TXT',28:'AAAA',43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',63:'ZONEMD',250:'TSIG',251:'IXFR',252:'AXFR'};
const dnssecZoneHex=(value,width=2)=>value.toString(16).padStart(width,'0');
const dnssecZoneUint=(hex,offset,length)=>Number.parseInt(hex.slice(offset*2,(offset+length)*2),16);
function dnssecZoneName(hex,offset,visited=new Set()){
  const labels=[];let cursor=offset,end=null;
  while(true){
    if(cursor*2>=hex.length||visited.has(cursor))throw new TypeError('Invalid fixed DNS name');
    visited.add(cursor);const length=dnssecZoneUint(hex,cursor++,1);
    if((length&192)===192){const pointer=((length&63)<<8)|dnssecZoneUint(hex,cursor,1);end??=cursor+1;const suffix=dnssecZoneName(hex,pointer,visited);labels.push(...suffix.name.slice(0,-1).split('.').filter(Boolean));break;}
    if(length===0)break;if(length>63)throw new TypeError('Invalid DNS label length');
    let label='';for(let i=0;i<length;i++){const byte=dnssecZoneUint(hex,cursor++,1);label+=byte>=33&&byte<=126&&byte!==46&&byte!==92?String.fromCharCode(byte):'\\'+String(byte).padStart(3,'0');}labels.push(label);
  }
  return {name:labels.join('.')+'.',end:end??cursor};
}
function dnssecZoneBase64(hex){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';let encoded='';
  for(let offset=0;offset<hex.length;offset+=6){
    const octets=Math.min(3,(hex.length-offset)/2),word=Number.parseInt(hex.slice(offset,offset+6).padEnd(6,'0'),16);
    encoded+=alphabet[(word>>>18)&63]+alphabet[(word>>>12)&63]+(octets>1?alphabet[(word>>>6)&63]:'=')+(octets>2?alphabet[word&63]:'=');
  }
  return encoded;
}
function dnssecZoneBitmap(hex,offset,end){
  const types=[];let previousWindow=-1;
  while(offset<end){
    if(offset+2>end)throw new TypeError('Truncated DNS type bitmap');
    const window=dnssecZoneUint(hex,offset++,1),length=dnssecZoneUint(hex,offset++,1);
    if(window<=previousWindow||length<1||length>32||offset+length>end)throw new TypeError('Invalid DNS type bitmap');
    for(let octet=0;octet<length;octet++){const bits=dnssecZoneUint(hex,offset+octet,1);for(let bit=0;bit<8;bit++)if(bits&(128>>>bit)){const type=window*256+octet*8+bit;types.push(dnssecZoneTypes[type]||'TYPE'+type);}}
    offset+=length;previousWindow=window;
  }
  return types.join(' ');
}
function dnssecZoneRdata(hex,type,offset,end){
  const size=end-offset,raw=hex.slice(offset*2,end*2),uint=(at,length)=>dnssecZoneUint(hex,offset+at,length);
  // Empty UPDATE delete/prerequisite RDATA is a management operation, not a
  // cryptographically usable ordinary RR. Preserve its exact empty body.
  if(!size)return '\\# 0';
  if(type===1){if(size!==4)throw new TypeError('Invalid wire A RDATA');return [0,1,2,3].map(at=>uint(at,1)).join('.');}
  if(type===28){if(size!==16)throw new TypeError('Invalid wire AAAA RDATA');return raw.match(/.{4}/g).join(':');}
  if([2,5].includes(type)){const name=dnssecZoneName(hex,offset);if(name.end!==end)throw new TypeError('Invalid wire name RDATA');return name.name;}
  if(type===6){const m=dnssecZoneName(hex,offset),r=dnssecZoneName(hex,m.end);if(r.end+20!==end)throw new TypeError('Invalid wire SOA RDATA');return m.name+' '+r.name+' '+[0,4,8,12,16].map(at=>dnssecZoneUint(hex,r.end+at,4)).join(' ');}
  if(type===15){const name=dnssecZoneName(hex,offset+2);if(size<3||name.end!==end)throw new TypeError('Invalid wire MX RDATA');return uint(0,2)+' '+name.name;}
  if(type===16){
    const strings=[];let cursor=offset;
    while(cursor<end){const length=dnssecZoneUint(hex,cursor++,1);if(cursor+length>end)throw new TypeError('Truncated wire TXT RDATA');let text='"';for(let index=0;index<length;index++){const octet=dnssecZoneUint(hex,cursor++,1);text+=octet>=32&&octet<=126&&octet!==34&&octet!==92?String.fromCharCode(octet):'\\'+String(octet).padStart(3,'0');}strings.push(text+'"');}
    return strings.join(' ');
  }
  if(type===48){if(size<4)throw new TypeError('Truncated wire DNSKEY RDATA');return uint(0,2)+' '+uint(2,1)+' '+uint(3,1)+' '+dnssecZoneBase64(raw.slice(8));}
  if(type===43){if(size<5)throw new TypeError('Truncated wire DS RDATA');return uint(0,2)+' '+uint(2,1)+' '+uint(3,1)+' '+raw.slice(8);}
  if(type===46){
    if(size<19)throw new TypeError('Truncated wire RRSIG RDATA');const signer=dnssecZoneName(hex,offset+18),covered=uint(0,2);
    if(signer.end>=end)throw new TypeError('Missing wire RRSIG signature');
    return (dnssecZoneTypes[covered]||'TYPE'+covered)+' '+[uint(2,1),uint(3,1),uint(4,4),uint(8,4),uint(12,4),uint(16,2)].join(' ')+' '+signer.name+' '+dnssecZoneBase64(hex.slice(signer.end*2,end*2));
  }
  if(type===47){const next=dnssecZoneName(hex,offset);if(next.end>=end)throw new TypeError('Missing wire NSEC bitmap');return next.name+' '+dnssecZoneBitmap(hex,next.end,end);}
  if(type===63){if(size<7)throw new TypeError('Truncated wire ZONEMD RDATA');return uint(0,4)+' '+uint(4,1)+' '+uint(5,1)+' '+raw.slice(12);}
  return '\\# '+size+' '+raw;
}
function dnssecZoneDecode(hex){
  if(!/^(?:[0-9a-f]{2})+$/.test(hex)||hex.length<24)throw new TypeError('Invalid fixed DNS message');
  const id=dnssecZoneUint(hex,0,2),bits=dnssecZoneUint(hex,2,2),counts=[4,6,8,10].map(offset=>dnssecZoneUint(hex,offset,2));let cursor=12;
  const questions=[];for(let i=0;i<counts[0];i++){const n=dnssecZoneName(hex,cursor);cursor=n.end;questions.push({qname:n.name,qtype:dnssecZoneTypes[dnssecZoneUint(hex,cursor,2)]||'TYPE'+dnssecZoneUint(hex,cursor,2),qclass:dnssecZoneUint(hex,cursor+2,2)===1?'IN':'CLASS'+dnssecZoneUint(hex,cursor+2,2)});cursor+=4;}
  const records=[];for(let section=0;section<3;section++)for(let i=0;i<counts[section+1];i++){
    const start=cursor,n=dnssecZoneName(hex,cursor);cursor=n.end;
    const type=dnssecZoneUint(hex,cursor,2),rrclass=dnssecZoneUint(hex,cursor+2,2),ttl=dnssecZoneUint(hex,cursor+4,4),size=dnssecZoneUint(hex,cursor+8,2),rdataOffset=cursor+10;cursor=rdataOffset+size;
    if(cursor*2>hex.length)throw new TypeError('Truncated DNS record');
    const text=dnssecZoneRdata(hex,type,rdataOffset,cursor);
    const rrset={owner:n.name,type:dnssecZoneTypes[type]||'TYPE'+type,typeCode:type,class:rrclass===1?'IN':'CLASS'+rrclass,ttl,records:[text]};
    const record={start,end:cursor,section:['answer','authority','additional'][section],type,rrclass,ttl,owner:n.name,rdataHex:hex.slice(rdataOffset*2,cursor*2),rrset};
    if(type===6)record.serial=Number(text.split(' ')[2]);
    if(type===46){const signer=dnssecZoneName(hex,rdataOffset+18),signatureHex=hex.slice(signer.end*2,cursor*2);record.signature={id:'wire-rrsig-'+signatureHex,owner:n.name,typeCovered:dnssecZoneUint(hex,rdataOffset,2),algorithm:dnssecZoneUint(hex,rdataOffset+2,1),labels:dnssecZoneUint(hex,rdataOffset+3,1),originalTtl:dnssecZoneUint(hex,rdataOffset+4,4),expiration:dnssecZoneUint(hex,rdataOffset+8,4),inception:dnssecZoneUint(hex,rdataOffset+12,4),keyTag:dnssecZoneUint(hex,rdataOffset+16,2),signer:signer.name,signatureHex,rrsigRdataHex:record.rdataHex};}
    if(type===250){const algorithm=dnssecZoneName(hex,rdataOffset),at=algorithm.end,macSize=dnssecZoneUint(hex,at+8,2),tail=at+10+macSize;record.tsig={keyName:n.name,algorithm:algorithm.name,timeSigned:dnssecZoneUint(hex,at,6),fudge:dnssecZoneUint(hex,at+6,2),macHex:hex.slice((at+10)*2,tail*2),messageId:dnssecZoneUint(hex,tail,2),error:dnssecZoneUint(hex,tail+2,2),otherDataHex:hex.slice((tail+6)*2,cursor*2),tsigRdataHex:record.rdataHex,macSize};}
    records.push(record);
  }
  if(cursor*2!==hex.length)throw new TypeError('Trailing fixed DNS bytes');
  const opcode=(bits>>11)&15,flags={QR:(bits>>15)&1,OPCODE:({0:'QUERY',4:'NOTIFY',5:'UPDATE'})[opcode]||'OPCODE'+opcode,opcode,AA:(bits>>10)&1,TC:(bits>>9)&1,RD:(bits>>8)&1,RA:(bits>>7)&1,Z:(bits>>6)&1,AD:(bits>>5)&1,CD:(bits>>4)&1,DO:null,CO:null};
  const tsig=records.find(record=>record.type===250);if(tsig&&tsig!==records.at(-1))throw new TypeError('TSIG must be last');
  const unsignedWireHex=tsig?hex.slice(0,20)+dnssecZoneHex(counts[3]-1,4)+hex.slice(24,tsig.start*2):hex;
  return {id,messageId:id,opcode,question:questions[0]?{...questions[0],qdcount:questions.length}:undefined,flags,rcode:({0:'NOERROR',5:'REFUSED',9:'NOTAUTH'})[bits&15]||'RCODE'+(bits&15),edns:{present:false},counts,records,tsig:tsig?.tsig||null,unsignedWireHex,wireHex:hex};
}
function dnssecZoneMacInput(packet,{requestMacHex='',priorMacHex='',continuation=false}={}){
  const tsig=packet.tsig;if(!tsig)return null;
  const previous=priorMacHex||requestMacHex,prefix=previous?dnssecZoneHex(previous.length/2,4)+previous:'';
  const message=dnssecZoneHex(tsig.messageId,4)+packet.unsignedWireHex.slice(4),timers=dnssecZoneHex(tsig.timeSigned,12)+dnssecZoneHex(tsig.fudge,4);
  return prefix+message+(continuation?timers:dnssecCanonicalName(tsig.keyName)+'00ff00000000'+dnssecCanonicalName(tsig.algorithm)+timers+dnssecZoneHex(tsig.error,4)+dnssecZoneHex(tsig.otherDataHex.length/2,4)+tsig.otherDataHex);
}
function dnssecZoneAuthenticate(packet,key,references,now,context={}){
  const tsig=packet.tsig,macInputHex=dnssecZoneMacInput(packet,context),timeValid=!!tsig&&Math.abs(now-tsig.timeSigned)<=tsig.fudge;
  const tuple=tsig&&references.find(ref=>ref.keyFingerprint===key.fingerprint&&ref.keyName===tsig.keyName&&ref.algorithm===tsig.algorithm&&ref.macInputHex===macInputHex&&ref.macHex===tsig.macHex);
  const macValid=!!tuple&&tsig.keyName===key.keyName&&tsig.algorithm===key.algorithm&&tsig.messageId===packet.id;
  return {checked:true,macValid,timeValid,valid:macValid&&timeValid,principal:macValid?tsig.keyName:null,macInputHex,evidenceMode:'symbolic-reference-bound',evidenceRef:tuple?.id||null,reason:!macValid?'TSIG-BADSIG':!timeValid?'TSIG-BADTIME':'TSIG-valid'};
}
function dnssecZoneGroup(records){
  const groups=new Map();for(const record of records.filter(record=>record.type!==250)){
    const rrset=record.rrset,key=rrset.owner.toLowerCase()+'|'+rrset.type+'|'+rrset.class+'|'+rrset.ttl;
    if(!groups.has(key))groups.set(key,{...rrset,records:[]});const group=groups.get(key);for(const text of rrset.records)if(!group.records.includes(text))group.records.push(text);
  }return [...groups.values()];
}
function dnssecZoneCanonicalZone(rrsets){
  const entries=[];for(const rrset of rrsets){
    if(rrset.owner.toLowerCase()==='lab.example.'&&rrset.typeCode===63)continue;
    for(const text of rrset.records){const single={...rrset,records:[text]};if(rrset.owner.toLowerCase()==='lab.example.'&&rrset.typeCode===46&&text.split(' ')[0]==='ZONEMD')continue;
      const wire=dnssecCanonicalRrsetWire(single),labels=rrset.owner.toLowerCase().split('.').filter(Boolean).reverse(),rdata=dnssecZoneDecode('000080000000000100000000'+wire).records[0].rdataHex;entries.push({wire,labels,rdata,type:rrset.typeCode});
    }
  }
  entries.sort((left,right)=>{for(let i=0;i<Math.min(left.labels.length,right.labels.length);i++){if(left.labels[i]!==right.labels[i])return left.labels[i]<right.labels[i]?-1:1;}return left.labels.length-right.labels.length||left.type-right.type||(left.rdata<right.rdata?-1:left.rdata>right.rdata?1:0);});
  return [...new Set(entries.map(entry=>entry.wire))].join('');
}
function dnssecZoneBase(a,initialRecords){
  const links=dnssecLookupPath(),capabilities=[];
  for(const [owner,keyIds] of Object.entries({dnsSigner:['child-ksk-g1','child-zsk-g1'],dnsParent:['example-ksk-g1','example-zsk-g1'],dnsRoot:['root-ksk-g1','root-zsk-g1']}))for(const keyId of keyIds)capabilities.push(a.artifact('signing-capability-'+keyId,'Signer-only capability '+keyId,owner,{handle:'hsm:'+owner+':'+keyId,keyId,custodian:owner,capability:'sign'},{kind:'secret',privateKey:true,initial:true,holders:[owner],store:'Signer-only capabilities'}));
  const anchor=dnssecMaterial('keys','root-ksk-g1'),anchorRef=a.artifact('root-anchor','Explicit synthetic root trust anchor','dnsOperator',{zone:'.',keyRef:anchor.id,provenance:'Out-of-band configured synthetic root; not the Internet root',dnskeyRdataHex:anchor.dnskeyRdataHex},{kind:'trust',initial:true,holders:['dnsValidator'],store:'Configured trust anchors'});
  a.initialState.dnssec.anchorRef=anchorRef;a.bind('anchorRef',anchorRef,'dnsValidator','Configured trust anchors');
  const initialGeneration=dnssecZoneGeneration(a,'g0',initialRecords,'dnsSigner',{initial:true,holders:['dnsChild','dnsPrimary','dnsSecondary']}),old=initialGeneration.refs;
  Object.assign(a.initialState.dnssec,{stoppedAction:null,view:'synthetic-public',trustStore:'zone-lab',cacheNamespace:{view:'synthetic-public',trustStore:'zone-lab',checkingContext:'CD0'},retainedCacheRefs:{answer:null},publication:{childGeneration:'g0',activeSecondaryObjects:old,retainedSecondaryObjects:[],signingPrivateKeysPresent:false,transfer:{primaryGeneration:'g0',secondaryGeneration:'g0',serial:initialGeneration.serial,availableDifferenceBases:[initialGeneration.serial],complete:false},management:{received:false,tsigChecked:false,authorized:false,applied:false}},trustStores:{'zone-lab':{anchors:[anchor.id],provenance:'Explicit out-of-band provisioning'}}});
  old.forEach((ref,index)=>{
    a.bind('publication.activeSecondaryObjects.'+index,ref,'dnsSecondary','Explicit initial serving generation g0',{equals:ref});
    a.bind('publication.retainedSecondaryObjects.'+index,ref,'dnsSecondary','Retained historical generation g0',{equals:ref});
  });
  return {links,capabilities,anchor,anchorRef,old,initialGeneration};
}
function dnssecZoneKeys(a,input){
  const keys={};for(const [id,key] of Object.entries(input)){
    keys[id]={...key,capabilityRefs:{}};for(const custodian of key.custodians)keys[id].capabilityRefs[custodian]=a.artifact('transaction-capability-'+id+'-'+custodian,'Private shared transaction capability '+key.keyName,custodian,{handle:'mac-service:'+custodian+':'+key.fingerprint,keyId:key.keyName,custodian,capability:'TSIG HMAC; not DNSSEC signing',fingerprint:key.fingerprint},{kind:'secret',privateKey:true,initial:true,holders:[custodian],store:'Private transaction key service'});
  }return keys;
}
function dnssecZoneWire(a,key,title,from,to,wireHex,effects=[],generations=[]){
  const packet=dnssecZoneDecode(wireHex),refs=[];
  for(const [index,record] of packet.records.entries()){
    const value=record.tsig?{...record.tsig,authenticatedUpdateWireHex:wireHex,unsignedUpdateWireHex:packet.unsignedWireHex}:record.rrset;
    const sources=record.type===250?[]:generations.flatMap(generation=>record.type===46?generation.signatures.filter(signature=>signature.rrsigRdataHex===record.rdataHex&&signature.owner.toLowerCase()===record.owner.toLowerCase()).map(signature=>generation.signatureRefs.get(signature)):generation.rrsets.filter(rrset=>rrset.owner.toLowerCase()===record.owner.toLowerCase()&&rrset.typeCode===record.type&&dnssecCanonicalRrsetWire(rrset).includes(dnssecCanonicalRrsetWire(record.rrset))).map(rrset=>generation.rrsetRefs.get(rrset)));
    if(generations.length&&record.type!==250&&!sources.length)throw new TypeError('Wire record is not in the actually published or explicitly held generation');
    const ref=a.artifact(key+'-rr-'+index,title+' / '+record.owner+' '+(dnssecZoneTypes[record.type]||record.type),from,value,{kind:record.tsig?'tsig':'rrset',derivedFrom:sources});
    a.local(key+'-record-'+index,'Prepare exact public wire record',from,{values:{result:{wireRdataHex:record.rdataHex,section:record.section}},refs:[...sources,{artifactId:ref,kind:'create'}],held:a.create(ref,from,'Prepared transaction records'),kind:'create'});refs.push({artifactId:ref,section:record.section,recordCount:1});record.artifactRef=ref;
  }
  const message={...packet,records:undefined,tsig:packet.tsig,inReplyTo:packet.flags.QR?packet.id:null,correlationId:packet.id,actualWireCounts:{question:packet.counts[0],answer:packet.counts[1],authority:packet.counts[2],additional:packet.counts[3]}};
  a.send(key,title,from,to,refs,message,[...effects,...packet.tsig?[dnssecPut('timers.transaction',{timeSigned:packet.tsig.timeSigned,fudge:packet.tsig.fudge,expiresAt:packet.tsig.timeSigned+packet.tsig.fudge})]:[]],'TCP');return packet;
}
function dnssecZoneHop(from,to,query,response,transport='UDP'){
  const describe=packet=>({id:packet.id,messageId:packet.messageId,...packet.flags,flags:packet.flags,question:packet.question,edns:packet.edns,...packet.rcode?{rcode:packet.rcode}:{},...packet.wireHex?{wireHex:packet.wireHex}:{},...packet.tsig?{tsig:packet.tsig,tsigError:packet.tsig.error,tsigSigned:packet.tsig.macSize>0,macSize:packet.tsig.macSize}:{}});
  return {from,to,transport,question:query.question,query:describe(query),response:{...describe(response),inReplyTo:query.id}};
}
function dnssecZoneObserve(a,boundary,title,actor,result,effects=[],refs=[]){return a.local(boundary,title,actor,{values:{now:a.clock,result,evidenceMode:'symbolic-reference-bound',verificationKind:'local-check'},effects,refs,kind:'verify',boundary});}
function dnssecZoneLookup(a,base,generation){
  const {rrsets,signatures,rrsetRefs,signatureRefs}=generation;
  const question={qname:'www.lab.example.',qtype:'A',qclass:'IN'},leaf=rrsets.find(rrset=>rrset.owner.toLowerCase()===question.qname&&rrset.typeCode===1),leafSignatures=signatures.filter(signature=>signature.owner.toLowerCase()===question.qname&&signature.typeCovered===1);
  if(!leaf||!leafSignatures.length)throw new TypeError('Transferred generation lacks the signed leaf');
  const links=base.links.map(link=>link.zone==='lab.example.'?{...link,dnskeyRrset:rrsets.find(rrset=>rrset.typeCode===48),dnskeySignatures:signatures.filter(signature=>signature.typeCovered===48)}:link),hops=[];
  a.chapter('lookup','Query the actually installed secondary generation');
  const stubQuery=dnssecLookupMessage(19000,question,{recursive:true,flags:{AD:1}});a.initialState.dnssec.query=question;
  a.send('stub-query','Stub requests an address','dnsStub','dnsResolver',[],stubQuery);
  const evidence=[];let id=19010;
  for(const link of links){
    for(const [kind,rrset,sigs,owner] of [['ds',link.dsRrset,link.dsSignatures,link.zone==='example.'?'dnsRoot':'dnsParent'],['keys',link.dnskeyRrset,link.dnskeySignatures,link.zone==='.'?'dnsRoot':link.zone==='example.'?'dnsParent':'dnsSecondary']]){
      if(!rrset)continue;
      const refs=owner==='dnsSecondary'?[rrsetRefs.get(rrset),...sigs.map(signature=>signatureRefs.get(signature))]:[a.artifact('lookup-'+id,'Available public '+rrset.owner+' '+rrset.type,owner,rrset,{kind:'rrset',initial:true,holders:[owner],store:'Initial authority publication'}),...sigs.map((sig,index)=>a.artifact('lookup-'+id+'-signature-'+index,'Available RRSIG('+rrset.type+')',owner,sig,{kind:'rrsig',initial:true,holders:[owner],store:'Public signatures'}))];
      const q={qname:rrset.owner,qtype:rrset.type},request=dnssecLookupMessage(id,q,{flags:{CD:0}}),response=dnssecLookupMessage(id,q,{response:true,authoritative:true});
      a.send('evidence-q-'+id,'Request public '+rrset.type,'dnsResolver',owner,[],request);a.send('evidence-r-'+id,'Receive public '+rrset.type,owner,'dnsResolver',refs,response);evidence.push(...refs);hops.push(dnssecZoneHop('dnsResolver',owner,request,response));id++;
    }
  }
  const answerRef=a.artifact('leaf-response','Exact installed answer occurrence','dnsSecondary',{...leaf,ttl:300},{kind:'rrset',derivedFrom:[rrsetRefs.get(leaf)]}),sigRefs=leafSignatures.map(signature=>signatureRefs.get(signature));
  a.local('secondary-serves-signed-public-rrsets','Secondary serves public records without signing','dnsSecondary',{values:{result:{answerSource:'dnsSecondary',answerSignatureIssuer:leafSignatures[0].keyId||'child-zsk-g1',transmitterIsSigner:false}},effects:[dnssecPut('publication.answerSource','dnsSecondary'),dnssecPut('publication.answerSignatureIssuer','child-zsk-g1'),dnssecPut('publication.transmitterIsSigner',false)],refs:[rrsetRefs.get(leaf),...sigRefs,{artifactId:answerRef,kind:'create'}],held:a.create(answerRef,'dnsSecondary','DNS response data')});
  const q=dnssecLookupMessage(id,question,{flags:{CD:0}}),r={...dnssecLookupMessage(id,question,{response:true,authoritative:true}),receivedRrsetTtl:300,receivedRrsigTtl:300};a.send('leaf-query','Query the installed secondary','dnsResolver','dnsSecondary',[],q);a.send('raw-answer-received','Receive the signed answer before local checking','dnsSecondary','dnsResolver',[answerRef,...sigRefs],r,[dnssecPut('received',true)]);hops.push(dnssecZoneHop('dnsResolver','dnsSecondary',q,r));
  const checked=dnssecValidateChain({anchor:{zone:'.',keys:[base.anchor]},links,answer:{rrset:a.object(answerRef).value,signatures:leafSignatures},now:a.clock,policy:a.policy});
  dnssecZoneObserve(a,'local-validation-complete','Validate the actual received chain and answer','dnsValidator',checked,[...['signatureChecked','chainEstablished','securityStatus','evidenceRefs'].map(field=>dnssecPut(field,checked[field]??[])),dnssecPut('reasonCode',checked.securityStatus==='secure'?'valid-path':checked.reasonCode),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind','local-check'),dnssecPut('checkedAt',a.clock)],[base.anchorRef,...evidence,answerRef,...sigRefs].map(artifactId=>({artifactId,kind:'verify'})));
  const selected=checked.checks.find(check=>check.stage==='answer-signature')?.result?.selectedEvidence,window=selected?dnssecTtlWindow({receivedTtl:300,rrsigTtl:300,originalTtl:selected.originalTtl,signatureExpiration:selected.expiration,now:a.clock,receivedAt:a.clock}):{valid:false,remainingSeconds:0,expiresAt:a.clock},accepted=checked.securityStatus==='secure'&&window.valid;
  a.local('selected-answer-signature-window','Inspect the actually usable answer signature window','dnsValidator',{values:{result:{selected}},effects:[dnssecPut('timers.signature',selected?{inception:selected.inception,expiration:selected.expiration}:null)],refs:sigRefs});
  const cache={id:'dns19-answer-cache',kind:'positive',key:['synthetic-public','zone-lab',question.qname,'A','IN'],view:'synthetic-public',trustStore:'zone-lab',checkingContext:'CD0',receivedAt:a.clock,expiresAt:window.expiresAt,remainingTtl:window.remainingSeconds,signatureDeadline:selected?.expiration??null,securityStatus:checked.securityStatus,validationOwner:'dnsValidator',evidenceRefs:checked.evidenceRefs||[]},cacheRef=a.artifact('answer-cache','Accepted exact-answer cache','dnsResolver',cache,{kind:'cache',derivedFrom:[answerRef,...sigRefs]});
  a.local('accepted-answer-cache-decision','Apply resolver acceptance and cache policy','dnsResolver',{values:{result:{accepted,window}},effects:[dnssecPut('acceptedForUse',accepted),dnssecPut('cached',accepted),dnssecPut('cacheEntries',accepted?[cache]:[]),dnssecPut('retainedCacheRefs.answer',accepted?cacheRef:null)],refs:[answerRef,...sigRefs,...accepted?[{artifactId:cacheRef,kind:'create'}]:[]],held:accepted?a.create(cacheRef,'dnsResolver','Answer cache'):[]});a.bind('retainedCacheRefs.answer',cacheRef,'dnsResolver','Answer cache');
  const returned=a.artifact('returned-answer','TTL-bounded returned answer','dnsResolver',{...leaf,ttl:accepted?window.remainingSeconds:0},{kind:'rrset',derivedFrom:[answerRef]});
  a.local('prepare-return','Prepare bounded outgoing representation','dnsResolver',{values:{result:{remainingAuthenticatedLifetime:window.remainingSeconds}},refs:[{artifactId:returned,kind:'create'}],held:a.create(returned,'dnsResolver','Stub response')});
  const response={...dnssecLookupMessage(19000,question,{response:true,recursive:true,rcode:accepted?'NOERROR':'SERVFAIL',flags:{AD:accepted?1:0}}),returnedRrsetTtl:accepted?window.remainingSeconds:0,returnedRrsigTtl:accepted?window.remainingSeconds:0};a.send('stub-response-received','Return resolver result to stub','dnsResolver','dnsStub',accepted?[returned,...sigRefs]:[],response,[dnssecPut('returnedToStub',true),dnssecPut('response.rcode',response.rcode),dnssecPut('response.flags',response.flags),...hops.map(hop=>dnssecAppend('response.hops',hop)),dnssecAppend('response.hops',dnssecZoneHop('dnsStub','dnsResolver',stubQuery,response))]);
  a.local('application-acceptance','Application consumes only the accepted resolver result','dnsApp',{values:{result:{accepted}},effects:[dnssecPut('applicationResult',accepted?{status:'answer',qname:question.qname,qtype:'A',data:[...leaf.records]}:{status:'error',reason:checked.reasonCode})],refs:accepted?[returned]:[]});
}

function dnssecZoneTextRecords(zoneText){
  const records=[];
  for(const line of zoneText.trim().split('\n')){
    const fields=line.trim().split(/\s+/),owner=fields.shift(),ttl=Number(fields.shift()),rrclass=fields.shift(),type=fields.shift(),typeCode=Number(Object.keys(dnssecZoneTypes).find(code=>dnssecZoneTypes[code]===type));
    if(!Number.isInteger(ttl)||rrclass!=='IN'||!typeCode)throw new TypeError('Unsupported fixed zone text');
    const rrset={owner,ttl,class:rrclass,type,typeCode,records:[fields.join(' ')]},wire=dnssecCanonicalRrsetWire(rrset),packet=dnssecZoneDecode('000080000000000100000000'+wire);
    records.push(packet.records[0]);
  }
  return records;
}
function dnssecZoneGeneration(a,key,records,owner,{initial=false,holders=[owner],derivedFrom=[]}={}){
  const rrsets=dnssecZoneGroup(records.filter(record=>record.type!==46)),signatures=records.filter(record=>record.signature).map(record=>{const reference=Object.values(DNSSEC_MATERIAL.signatures).find(signature=>signature.rrsigRdataHex===record.signature.rrsigRdataHex);return {...reference,...record.signature,id:reference?.id||record.signature.id,keyId:reference?.keyId};}).filter((signature,index,all)=>all.findIndex(other=>other.rrsigRdataHex===signature.rrsigRdataHex&&other.owner.toLowerCase()===signature.owner.toLowerCase())===index),rrsetRefs=new Map(),signatureRefs=new Map(),refs=[];
  for(const [index,rrset] of rrsets.entries()){
    const ref=a.artifact(key+'-rrset-'+index,key+' '+rrset.owner+' '+rrset.type,owner,rrset,{kind:'rrset',initial,holders,store:initial?'Explicit initial serving generation g0':'Candidate complete zone',derivedFrom});rrsetRefs.set(rrset,ref);refs.push(ref);
  }
  for(const [index,signature] of signatures.entries()){
    const ref=a.artifact(key+'-signature-'+index,key+' '+signature.owner+' RRSIG('+signature.typeCovered+')',owner,signature,{kind:'rrsig',initial,holders,store:initial?'Explicit initial serving generation g0':'Candidate complete zone',derivedFrom});signatureRefs.set(signature,ref);refs.push(ref);
  }
  const soa=records.find(record=>record.type===6),serial=soa?.serial??null;
  return {rrsets,signatures,rrsetRefs,signatureRefs,refs,serial,records};
}
function dnssecZoneCreateGeneration(a,key,generation,owner,title){
  a.local(key,title,owner,{values:{result:{serial:generation.serial,rrsets:generation.rrsets.length,signatures:generation.signatures.length,signingPrivateKeysTransferred:false}},refs:generation.refs.map(artifactId=>({artifactId,kind:'create'})),held:generation.refs.flatMap(ref=>a.create(ref,owner,'Candidate complete zone')),kind:'create'});
}
function dnssecZoneFixture(){
  return dnssecMaterial('vectors','dns19-public-reference-vectors');
}
function dnssecZoneSigner(a,base,generation,boundary){
  const checks=generation.rrsets.filter(rrset=>generation.signatures.some(signature=>signature.owner.toLowerCase()===rrset.owner.toLowerCase()&&signature.typeCovered===rrset.typeCode)).map(rrset=>dnssecCheckSignature({rrset,signatures:generation.signatures.filter(signature=>signature.owner.toLowerCase()===rrset.owner.toLowerCase()&&signature.typeCovered===rrset.typeCode),keys:base.links[2].keys,now:a.clock,policy:a.policy,expectedSigner:'lab.example.'}));
  if(!checks.length||checks.some(check=>!check.valid))throw new TypeError('Independent signing generation has no complete usable signature evidence');
  const issuerIds=[...new Set(checks.map(check=>check.selectedKeyId))];
  const signingCapabilities=issuerIds.map(issuer=>base.capabilities.find(ref=>a.object(ref).value.custodian==='dnsSigner'&&a.object(ref).value.keyId===issuer&&a.has(ref,'dnsSigner')));
  if(signingCapabilities.some(ref=>!ref))throw new TypeError('Signer lacks an explicitly provisioned signing capability');
  dnssecZoneObserve(a,boundary,'Offline signing is separate from transaction authentication','dnsSigner',{checks,issuerIds,operation:'Opaque offline signing service uses exact independently produced signature octets',privateCapabilitiesExported:false},[dnssecPut('publication.childGeneration','g1'),dnssecPut('publication.dnskeySignatures',['child-ksk-g1']),dnssecPut('publication.answerSignatures',['child-zsk-g1']),dnssecPut('publication.signerOfflineAfterExport',true),dnssecPut('publication.management.tsigDidNotCreateRrsig',true)],[...signingCapabilities.map(artifactId=>({artifactId,kind:'inspect'})),...generation.refs]);
}
function dnssecZoneTransfer(a,base,fixture,keys,stream,{boundary,now,notify=false,fallback=false}){
  const requestFixed=fixture.messages[stream.requestMessageId],responseFixed=stream.responseMessageIds.map(id=>fixture.messages[id]);
  if(!requestFixed||!responseFixed.length)throw new TypeError('Missing independent transfer stream');
  const fullRecords=responseFixed.flatMap(message=>dnssecZoneDecode(message.wireHex).records).filter(record=>record.section==='answer'),opening=fullRecords[0],closing=fullRecords.at(-1),requestPreview=dnssecZoneDecode(requestFixed.wireHex),requestedBase=requestPreview.records.find(record=>record.type===6)?.serial,kind=requestPreview.question?.qtype==='IXFR'&&fullRecords[1]?.type===6&&fullRecords[1].serial===requestedBase?'IXFR':'AXFR';
  if(opening?.type!==6||closing?.type!==6)throw new TypeError('Transfer has no opening/closing SOA');
  const allData=dnssecZoneTextRecords(stream.resultZoneText);
  const signerGeneration=dnssecZoneGeneration(a,'signed-g1',allData,'dnsSigner');
  dnssecZoneCreateGeneration(a,'signer-output',signerGeneration,'dnsSigner','Prepare independently produced complete signed-zone output');
  dnssecZoneSigner(a,base,signerGeneration,a.caseId==='offline-signer-secondary'?'offline-zone-signed':a.caseId==='tsig-authenticated-update'?'signing-is-separate-from-tsig':'signing-is-separate-from-transfer');
  if(a.caseId==='offline-signer-secondary')a.advanceTo(DNSSEC_BASE_CLOCK+60,'controlled-handoff-clock');
  a.publish('primary-imports-signed-artifact','Controlled handoff of the exact signed public generation','dnsSigner','dnsPrimary',signerGeneration.refs,{effects:[dnssecPut('publication.transfer.primaryGeneration','g1'),dnssecPut('publication.transfer.serial',signerGeneration.serial),dnssecPut('publication.signingPrivateKeysPresent',false)]});
  if(notify){
    const query=dnssecLookupMessage(19100,{qname:'lab.example.',qtype:'SOA'},{edns:false,flags:{opcode:4,AA:1}}),ack=dnssecLookupMessage(19100,{qname:'lab.example.',qtype:'SOA'},{edns:false,response:true,flags:{opcode:4}});
    a.send('notify-request','NOTIFY is a hint, not a zone transfer','dnsPrimary','dnsSecondary',[],query);a.send('notify-only-hint','Acknowledge NOTIFY without installing a generation','dnsSecondary','dnsPrimary',[],{...ack,inReplyTo:19100},[dnssecPut('publication.notifications',{qname:'lab.example.',qtype:'SOA',queryFlags:query.flags,ackRcode:'NOERROR'})]);
    a.advanceTo(DNSSEC_BASE_CLOCK+1,'soa-check-clock');
    const soa=signerGeneration.rrsets.find(rrset=>rrset.typeCode===6),querySoa=dnssecLookupMessage(19101,{qname:'lab.example.',qtype:'SOA'},{edns:false});
    a.send('soa-query','Check the primary SOA before requesting differences','dnsSecondary','dnsPrimary',[],querySoa);a.send('soa-response','Receive the published SOA serial','dnsPrimary','dnsSecondary',[signerGeneration.rrsetRefs.get(soa)],dnssecLookupMessage(19101,querySoa.question,{edns:false,response:true,authoritative:true}));
  }
  if(now>a.clock)a.advanceTo(now,'transfer-clock');
  const request=dnssecZoneWire(a,'transfer-request','Request the selected immutable zone transfer','dnsSecondary','dnsPrimary',requestFixed.wireHex),transferKey=Object.values(keys).find(key=>key.keyName===request.tsig?.keyName);
  if(!transferKey)throw new TypeError('Transfer peer has no configured shared key');
  const requestCheck=dnssecZoneAuthenticate(request,transferKey,fixture.macReferenceTuples,a.clock),requestedSerial=request.records.find(record=>record.type===6)?.serial??null,historyAvailable=requestedSerial!==null&&a.initialState.dnssec.publication.transfer.availableDifferenceBases.includes(requestedSerial),authorized=requestCheck.valid&&transferKey.custodians.includes('dnsPrimary')&&transferKey.custodians.includes('dnsSecondary')&&request.question?.qname.toLowerCase()==='lab.example.'&&['AXFR','IXFR'].includes(request.question?.qtype);
  dnssecZoneObserve(a,fallback?'ixfr-history-unavailable':'authorize-transfer','Authenticate the requester, then apply the transfer ACL','dnsPrimary',{requestCheck,authorized,requestAuthoritySoaSerial:requestedSerial,requestedSerial,historyAvailable},[dnssecPut('publication.transfer.authorized',authorized),dnssecPut('publication.transfer.requested',request.question.qtype),dnssecPut('publication.transfer.requestedSerial',requestedSerial),dnssecPut('publication.transfer.historyAvailable',historyAvailable),dnssecPut('publication.transfer.fallback',request.question.qtype==='IXFR'&&!historyAvailable?'AXFR-style-full-zone':null),dnssecPut('publication.transfer.soaChecked',notify),dnssecPut('publication.transfer.serialOld',base.initialGeneration.serial),dnssecPut('publication.transfer.serialNew',signerGeneration.serial),dnssecPut('publication.transfer.requestAuthoritySoaSerial',requestedSerial),dnssecPut('publication.transfer.kind',kind),dnssecPut('publication.transfer.transport','TCP')],[transferKey.capabilityRefs.dnsPrimary,...request.records.map(record=>record.artifactRef)]);
  if(notify)dnssecZoneObserve(a,'secondary-checks-soa-then-requests-ixfr','The secondary has checked SOA and requested differences from its actually held serial','dnsSecondary',{serialOld:base.initialGeneration.serial,serialNew:signerGeneration.serial,requestAuthoritySoaSerial:request.records.find(record=>record.type===6)?.serial,requestMessageId:request.id},[],request.records.map(record=>record.artifactRef));
  if(!authorized)throw new TypeError('Independent selected transfer is not authenticated and authorized');
  const responseClock=DNSSEC_BASE_CLOCK+(notify||fallback?2:a.caseId==='tsig-authenticated-update'?300:120);
  if(responseClock>a.clock)a.advanceTo(responseClock,'transfer-response-clock');
  const received=[],checks=[];let priorMacHex='';
  for(const [index,message] of responseFixed.entries()){
    const packet=dnssecZoneWire(a,'transfer-response-'+index,'Receive authenticated transfer message '+(index+1),'dnsPrimary','dnsSecondary',message.wireHex,[],[signerGeneration,base.initialGeneration]);
    const context=index===0?{requestMacHex:request.tsig.macHex}:{priorMacHex,continuation:true},check=dnssecZoneAuthenticate(packet,transferKey,fixture.macReferenceTuples,a.clock,context);checks.push(check);received.push(...packet.records.filter(record=>record.section==='answer'));priorMacHex=packet.tsig?.macHex||'';
    dnssecZoneObserve(a,'transfer-authentication-'+index,'Check this exact transfer message and MAC chain','dnsSecondary',check,[],[transferKey.capabilityRefs.dnsSecondary,...packet.records.map(record=>record.artifactRef)]);
  }
  const candidateRecords=kind==='IXFR'?dnssecZoneApplyIxfr(base.initialGeneration.records,received):received;
  const sequenceBound=received.length===fullRecords.length&&received.every((record,index)=>dnssecCanonicalRrsetWire(record.rrset)===dnssecCanonicalRrsetWire(fullRecords[index].rrset)),sameSerial=opening.serial===closing.serial&&opening.serial===signerGeneration.serial,candidateBound=dnssecZoneCanonicalZone(dnssecZoneGroup(candidateRecords))===dnssecZoneCanonicalZone(dnssecZoneGroup(allData)),complete=checks.every(check=>check.valid)&&sameSerial&&sequenceBound&&candidateBound;
  const candidate=dnssecZoneGeneration(a,'received-g1',candidateRecords,'dnsSecondary',{derivedFrom:[...kind==='IXFR'?base.old:[],...received.map(record=>record.artifactRef).filter(Boolean)]});
  dnssecZoneCreateGeneration(a,'assemble-received-zone',candidate,'dnsSecondary',kind==='IXFR'?'Apply only the received exact delete/add sequence to g0':'Assemble only the received complete full-zone records');
  if(!complete)throw new TypeError('Selected reference transfer is not complete');
  a.local(boundary,'Atomically move old serving records to history and install the authenticated received generation','dnsSecondary',{values:{result:{checks,openingSoaSerial:opening.serial,closingSoaSerial:closing.serial,complete,sequenceBound,atomic:true,previousGenerationRetainedForInspection:true,privateSigningKeysPresent:false}},effects:[dnssecPut('publication.activeSecondaryObjects',candidate.refs),dnssecPut('publication.retainedSecondaryObjects',base.old),dnssecPut('publication.transfer.authentication','TSIG-valid'),dnssecPut('publication.transfer.tsigVerified',checks.every(check=>check.valid)),dnssecPut('publication.transfer.firstAndLastMessageAuthenticated',checks[0].valid&&checks.at(-1).valid),dnssecPut('publication.transfer.complete',complete),dnssecPut('publication.transfer.atomicInstall',complete),dnssecPut('publication.transfer.secondaryGeneration','g1'),dnssecPut('publication.transfer.serial',candidate.serial),dnssecPut('publication.transfer.openingSoaSerial',opening.serial),dnssecPut('publication.transfer.closingSoaSerial',closing.serial),dnssecPut('publication.childGeneration','g1')],refs:[...base.old,...candidate.refs],held:[...base.old.flatMap(ref=>[a.release(ref,'dnsSecondary','Explicit initial serving generation g0'),a.acquire(ref,'dnsSecondary','Retained historical generation g0')]),...candidate.refs.map(ref=>a.acquire(ref,'dnsSecondary','Installed serving generation g1'))],kind:'verify',boundary});
  candidate.refs.forEach((ref,index)=>a.bind('publication.activeSecondaryObjects.'+index,ref,'dnsSecondary','Installed serving generation g1',{equals:ref}));
  return candidate;
}

function dnssecZoneApplyIxfr(initialRecords,received){
  if(received.length<4||received[0].type!==6||received[1].type!==6||received.at(-1).type!==6)throw new TypeError('Incomplete IXFR framing');
  const data=initialRecords.filter(record=>record.type!==250),oldSerial=data.find(record=>record.type===6)?.serial;
  if(received[1].serial!==oldSerial)throw new TypeError('IXFR base serial is not the actually held secondary serial');
  const next=received.findIndex((record,index)=>index>1&&record.type===6);if(next<0)throw new TypeError('IXFR is missing the new SOA');
  const removals=received.slice(1,next),additions=received.slice(next,-1),remaining=[...data];
  for(const record of removals){const wire=dnssecCanonicalRrsetWire(record.rrset),index=remaining.findIndex(existing=>dnssecCanonicalRrsetWire(existing.rrset)===wire);if(index<0)throw new TypeError('IXFR tries to delete a record not held in the initial generation');remaining.splice(index,1);}
  for(const record of additions){const wire=dnssecCanonicalRrsetWire(record.rrset);if(!remaining.some(existing=>dnssecCanonicalRrsetWire(existing.rrset)===wire))remaining.push(record);}
  if(remaining.find(record=>record.type===6)?.serial!==received[0].serial||received.at(-1).serial!==received[0].serial)throw new TypeError('IXFR result serial/framing mismatch');
  return remaining;
}
function dnssecZoneUpdate(a,base,fixture,keys,update,{denied=false,modified=false}={}){
  const requestFixed=fixture.messages[update.requestMessageId],request=dnssecZoneWire(a,modified?'receive-modified-update':denied?'receive-policy-update':'receive-update-before-authentication','Receive UPDATE before authentication','dnsOperator','dnsPrimary',requestFixed.wireHex,[dnssecPut('publication.management.received',true),dnssecPut('publication.management.opcode','UPDATE')]);
  if(!denied&&!modified)a.advanceTo(DNSSEC_BASE_CLOCK+1,'update-check-clock');
  const key=Object.values(keys).find(value=>value.keyName===request.tsig?.keyName);if(!key)throw new TypeError('No configured transaction capability for UPDATE');
  const authentication=dnssecZoneAuthenticate(request,key,fixture.macReferenceTuples,a.clock),changes=request.records.filter(record=>record.section==='authority'&&record.type!==250),zoneAllowed=request.opcode===5&&request.question?.qname.toLowerCase()==='lab.example.'&&request.question?.qtype==='SOA',scopeAllowed=changes.length>0&&changes.every(record=>record.owner.toLowerCase()==='www.lab.example.'&&record.type===1&&[1,254,255].includes(record.rrclass)),authorized=authentication.valid&&key.keyName==='update-key.'&&key.custodians.includes('dnsOperator')&&key.custodians.includes('dnsPrimary')&&zoneAllowed&&scopeAllowed;
  const applied=authorized,rcode=!authentication.valid?'NOTAUTH':authorized?'NOERROR':'REFUSED',reason=!authentication.valid?'tsig-badsig':!authorized?'tsig-principal-policy-denied':null;
  const management={received:true,opcode:'UPDATE',principal:authentication.principal,tsigChecked:true,macValid:authentication.macValid,timeValid:authentication.timeValid,authorized,applied:false,rcode,...!authentication.valid?{tsigError:16,tsigErrorName:'BADSIG',responseTsigSigned:false,responseMacSize:0}:{},scope:{zone:'lab.example.',principal:'update-key.',owner:'www.lab.example.',type:'A'},requestMacInputHex:authentication.macInputHex};
  dnssecZoneObserve(a,modified?'detect-mac-mismatch-and-reject':denied?'authenticate-management-principal':'authenticate-update-request','Authenticate exact transaction bytes, then evaluate the configured update scope','dnsPrimary',{authentication,zoneAllowed,scopeAllowed,changes,authorized,applied},[dnssecPut('publication.management',management),...applied?[dnssecPut('publication.transfer.serial',2026102302)]:[],...reason?[dnssecPut('reasonCode',reason),dnssecPut('validationOwner','dnsPrimary'),dnssecPut('verificationKind','local-check'),dnssecPut('firstDetector','dnsPrimary'),dnssecPut('failureStage',modified?'transaction-mac-verification':'update-authorization'),dnssecPut('stoppedAction',modified?'authorize-or-apply-update':'apply-update')]:[]],[key.capabilityRefs.dnsPrimary,...request.records.map(record=>record.artifactRef)]);
  if(applied){
    const committedRecords=dnssecZoneApplyUpdate(base.initialGeneration.records,changes),serial=(base.initialGeneration.serial+1)>>>0;
    base.updatedInputRef=a.artifact('committed-unsigned-update','Atomically committed authorized unsigned zone input','dnsPrimary',{zone:'lab.example.',generation:'g1-unsigned',serial,rrsets:committedRecords.map(record=>record.rrset),pendingSigning:true},{kind:'publication',derivedFrom:[...base.old,...changes.map(record=>record.artifactRef)]});base.committedRecords=committedRecords;
    a.local('atomic-update-commit','Commit only the actual authenticated authorized UPDATE operations','dnsPrimary',{values:{result:{serial,changes:changes.map(record=>record.rrset),dnssecSignaturesCreated:false}},effects:[dnssecPut('publication.management.applied',true),dnssecPut('publication.management.committedRef',base.updatedInputRef),dnssecPut('publication.transfer.serial',serial)],refs:[...changes.map(record=>record.artifactRef),{artifactId:base.updatedInputRef,kind:'create'}],held:a.create(base.updatedInputRef,'dnsPrimary','Committed unsigned update'),kind:'create'});a.bind('publication.management.committedRef',base.updatedInputRef,'dnsPrimary','Committed unsigned update');
  }
  const responseFixed=fixture.messages[update.responseMessageId],response=dnssecZoneWire(a,'update-response','Return the correlated management response','dnsPrimary','dnsOperator',responseFixed.wireHex);
  if(response.id!==request.id||response.opcode!==5||response.rcode!==rcode)throw new TypeError('Independent UPDATE response does not match evaluated policy/result');
  const responseCheck=authentication.valid?dnssecZoneAuthenticate(response,key,fixture.macReferenceTuples,a.clock,{requestMacHex:request.tsig.macHex}):null,responseTsigValid=!!responseCheck?.valid;
  if(authentication.valid&&!responseTsigValid)throw new TypeError('Authenticated UPDATE response lacks exact MAC evidence');
  if(!authentication.valid&&(response.tsig?.error!==16||response.tsig?.macSize!==0))throw new TypeError('BADSIG response must use the unsigned zero-MAC error');
  dnssecZoneObserve(a,denied?'refuse-authorized-scope-violation':modified?'management-authentication-result':'verify-tsig-then-authorize-update','Inspect the separate management result, without creating DNSSEC trust',denied||applied?'dnsPrimary':'dnsOperator',{responseCheck,rcode,responseTsigValid,applied},[dnssecPut('publication.management.responseTsigValid',responseTsigValid),dnssecPut('response.rcode',rcode),dnssecAppend('response.hops',dnssecZoneHop('dnsOperator','dnsPrimary',request,response,'TCP')),...reason?[dnssecPut('securityStatus','not-checked'),dnssecPut('reasonCode',reason),dnssecPut('validationOwner','dnsPrimary'),dnssecPut('verificationKind','local-check'),dnssecPut('firstDetector','dnsPrimary'),dnssecPut('failureStage',modified?'transaction-mac-verification':'update-authorization'),dnssecPut('stoppedAction',modified?'authorize-or-apply-update':'apply-update'),dnssecPut('preservedState',['g0 zone data','old SOA serial','existing RRSIGs']),dnssecPut('applicationResult',modified?{status:'error',operation:'UPDATE',reason:'TSIG-BADSIG'}:{status:'refused',operation:'UPDATE',reason:'policy-denied'})]:[]]);
  if(!applied)return null;
  const resultRecords=dnssecZoneTextRecords(fixture.streams[update.transferStreamId].resultZoneText),committed=base.committedRecords.filter(record=>record.owner.toLowerCase()==='www.lab.example.'&&record.type===1).map(record=>dnssecCanonicalRrsetWire(record.rrset)).sort(),published=resultRecords.filter(record=>record.owner.toLowerCase()==='www.lab.example.'&&record.type===1).map(record=>dnssecCanonicalRrsetWire(record.rrset)).sort();
  if(JSON.stringify(committed)!==JSON.stringify(published))throw new TypeError('Signed generation does not contain the actually authorized UPDATE data');
  a.advanceTo(DNSSEC_BASE_CLOCK+2,'separate-signing-clock');
  a.publish('signer-receives-authorized-update','Hand the actual committed public data to the separate signer','dnsPrimary','dnsSigner',[base.updatedInputRef],{store:'Authorized unsigned signer input'});
  dnssecZoneObserve(a,'update-requires-separate-signer','An authorized UPDATE still needs the separate offline signer','dnsSigner',{committedRecords:changes.map(record=>record.rrset),transactionMacCreatesDnssecSignature:false},[dnssecPut('publication.management.tsigDidNotCreateRrsig',true)]);
  return fixture.streams[update.transferStreamId];
}
function dnssecZoneZonemd(a,base,fixture){
  const vector=dnssecMaterial('vectors','child-zone-authenticated-simple-sha384'),originalRecords=dnssecZoneTextRecords(vector.zoneText),changedRecords=originalRecords.map(record=>record.owner.toLowerCase()==='ns.unsigned.lab.example.'&&record.type===1?{...record,rrset:{...record.rrset,records:['192.0.2.201']}}:record),candidate=dnssecZoneGeneration(a,'zonemd-candidate',changedRecords,'dnsPrimary'),candidateRef=a.artifact('zonemd-zone-file','Received complete zone candidate','dnsPrimary',{zone:'lab.example.',generation:'g1-incomplete',serial:vector.serial,rrsets:changedRecords.map(record=>record.rrset),canonicalZoneWireHex:dnssecZoneCanonicalZone(dnssecZoneGroup(changedRecords))},{kind:'publication'});
  dnssecZoneCreateGeneration(a,'candidate-source',candidate,'dnsPrimary','Prepare complete candidate retaining the authenticated expected digest');
  a.local('candidate-source-file','Prepare exact whole-zone file','dnsPrimary',{values:{result:{serial:vector.serial,unsignedGlueChanged:true}},refs:[{artifactId:candidateRef,kind:'create'}],held:a.create(candidateRef,'dnsPrimary','Whole-zone candidate')});
  a.publish('receive-whole-zone-before-checks','Receive the complete whole-zone candidate before authentication','dnsPrimary','dnsSecondary',[candidateRef,...candidate.refs],{effects:[dnssecPut('received',true),dnssecPut('publication.transfer.candidateGeneration','g1-incomplete'),dnssecPut('publication.transfer.complete',true),dnssecPut('publication.zonemd',{scheme:1,hashAlgorithm:1,serial:vector.serial,expectedDigestAuthenticated:false,matched:null})],store:'Uninstalled candidate zone',transport:'Declared complete public zone-file handoff'});
  a.chapter('zonemd-authentication','Authenticate digest origin, then check complete-zone integrity');
  const soa=candidate.rrsets.find(rrset=>rrset.typeCode===6),zonemd=candidate.rrsets.find(rrset=>rrset.typeCode===63),soaSignatures=candidate.signatures.filter(signature=>signature.typeCovered===6),zonemdSignatures=candidate.signatures.filter(signature=>signature.typeCovered===63),links=base.links.map(link=>link.zone==='lab.example.'?{...link,dnskeyRrset:candidate.rrsets.find(rrset=>rrset.typeCode===48),dnskeySignatures:candidate.signatures.filter(signature=>signature.typeCovered===48)}:link),evidence=[];
  let index=0;for(const link of links)for(const [rrset,signatures,owner] of [[link.dsRrset,link.dsSignatures,link.zone==='example.'?'dnsRoot':'dnsParent'],[link.dnskeyRrset,link.dnskeySignatures,link.zone==='.'?'dnsRoot':link.zone==='example.'?'dnsParent':'dnsSecondary']]){
    if(!rrset||owner==='dnsSecondary')continue;
    const refs=[a.artifact('zonemd-chain-'+index,'Concrete public chain RRset',owner,rrset,{kind:'rrset',initial:true,holders:[owner],store:'Initial authority publication'}),...signatures.map((signature,j)=>a.artifact('zonemd-chain-'+index+'-signature-'+j,'Concrete public chain signature',owner,signature,{kind:'rrsig',initial:true,holders:[owner],store:'Initial authority publication'}))],question={qname:rrset.owner,qtype:rrset.type};a.send('zonemd-chain-query-'+index,'Request digest-origin trust evidence','dnsSecondary',owner,[],dnssecLookupMessage(19200+index,question));a.send('zonemd-chain-response-'+index,'Receive digest-origin trust evidence',owner,'dnsSecondary',refs,dnssecLookupMessage(19200+index,question,{response:true,authoritative:true}));evidence.push(...refs);index++;
  }
  const soaCheck=dnssecValidateChain({anchor:{zone:'.',keys:[base.anchor]},links,answer:{rrset:soa,signatures:soaSignatures},now:a.clock,policy:a.policy}),zonemdCheck=dnssecValidateChain({anchor:{zone:'.',keys:[base.anchor]},links,answer:{rrset:zonemd,signatures:zonemdSignatures},now:a.clock,policy:a.policy}),zonemdParts=zonemd.records[0].split(' '),serial=Number(zonemdParts[0]),scheme=Number(zonemdParts[1]),hashAlgorithm=Number(zonemdParts[2]),expectedDigestHex=zonemdParts[3],serialMatches=serial===candidate.serial,descriptorValid=scheme===1&&hashAlgorithm===1&&expectedDigestHex.length===96,authenticated=soaCheck.securityStatus==='secure'&&zonemdCheck.securityStatus==='secure'&&serialMatches&&descriptorValid;
  const selectedZonemdSignature=zonemdCheck.checks.find(check=>check.stage==='answer-signature')?.result?.selectedEvidence;
  a.local('selected-zonemd-signature-window','Inspect the authenticated expected-digest signature window','dnsValidator',{values:{result:{selectedEvidence:selectedZonemdSignature}},effects:[dnssecPut('timers.signature',selectedZonemdSignature?{inception:selectedZonemdSignature.inception,expiration:selectedZonemdSignature.expiration}:null)],refs:zonemdSignatures.map(signature=>candidate.signatureRefs.get(signature))});
  const individualChecks=candidate.rrsets.filter(rrset=>candidate.signatures.some(signature=>signature.typeCovered===rrset.typeCode&&signature.owner.toLowerCase()===rrset.owner.toLowerCase())).map(rrset=>dnssecCheckSignature({rrset,signatures:candidate.signatures.filter(signature=>signature.typeCovered===rrset.typeCode&&signature.owner.toLowerCase()===rrset.owner.toLowerCase()),keys:base.links[2].keys,now:a.clock,policy:a.policy,expectedSigner:'lab.example.'}));
  dnssecZoneObserve(a,'authenticate-expected-soa-and-zonemd','Authenticate SOA and expected ZONEMD through the concrete root-to-child path','dnsValidator',{soaCheck,zonemdCheck,individualChecks,serialMatches},[dnssecPut('signatureChecked',soaCheck.signatureChecked&&zonemdCheck.signatureChecked),dnssecPut('chainEstablished',soaCheck.chainEstablished&&zonemdCheck.chainEstablished),dnssecPut('securityStatus',zonemdCheck.securityStatus),dnssecPut('publication.zonemd.expectedDigestAuthenticated',authenticated),dnssecPut('publication.zonemd.soaSignatureValid',soaCheck.securityStatus==='secure'),dnssecPut('publication.zonemd.zonemdSignatureValid',zonemdCheck.securityStatus==='secure'),dnssecPut('publication.zonemd.serialMatches',serialMatches),dnssecPut('publication.zonemd.individualAvailableRrsetsValid',individualChecks.every(check=>check.valid))],[base.anchorRef,...evidence,...candidate.refs].map(artifactId=>({artifactId,kind:'verify'})));
  const canonicalZoneWireHex=dnssecZoneCanonicalZone(dnssecZoneGroup(changedRecords)),tuple=fixture.zonemdReferenceTuples.find(reference=>reference.scheme===scheme&&reference.hashAlgorithm===hashAlgorithm&&reference.canonicalZoneWireHex===canonicalZoneWireHex),matched=authenticated&&!!tuple&&tuple.digestHex===expectedDigestHex;
  if(!tuple)throw new TypeError('Complete actual canonical zone has no independently computed SHA384 tuple');
  dnssecZoneObserve(a,'detect-whole-zone-digest-mismatch','Compare actual complete-zone bytes, including changed unsigned glue','dnsSecondary',{canonicalZoneWireHex,computedDigestHex:tuple.digestHex,expectedDigestHex,evidenceRef:tuple.id,authenticated,matched},[dnssecPut('publication.zonemd.matched',matched),dnssecPut('publication.zonemd.tamperedUnsignedGlue',{owner:'ns.unsigned.lab.example.',before:'192.0.2.200',after:'192.0.2.201'}),dnssecPut('publication.zonemd.acceptedForServing',matched),dnssecPut('publication.transfer.candidateInstalled',matched),dnssecPut('publication.childGeneration',matched?'g1':'g0')],[candidateRef]);
  dnssecZoneObserve(a,'management-result-classification','Classify whole-zone integrity separately from DNSSEC RRset security','dnsValidator',{authenticated,matched,servingGeneration:matched?'g1':'g0'},[dnssecPut('reasonCode',matched?'zonemd-whole-zone-integrity-valid':'zonemd-whole-zone-integrity-failed'),dnssecPut('validationOwner','dnsValidator'),dnssecPut('verificationKind','local-check'),dnssecPut('failureStage',matched?null:'zonemd-digest-comparison'),dnssecPut('firstDetector',matched?null:'dnsSecondary'),dnssecPut('stoppedAction',matched?null:'install-candidate-zone'),dnssecPut('preservedState',matched?[]:['previous complete g0 serving generation','DNSSEC secure status of authenticated SOA/ZONEMD, not whole-zone completeness']),dnssecPut('applicationResult',{status:'pending',reason:'No leaf lookup/application acceptance in this management case.'})]);
}

function dnssecZoneCase(caseId,{streamId='axfr',updateId=null,notify=false,fallback=false,zonemd=false}={}){
  const fixture=dnssecZoneFixture(),stream=fixture.streams[streamId],initialText=zonemd?dnssecMaterial('vectors','child-zone-authenticated-simple-sha384').zoneText:stream.baseZoneText,a=dnssecAuthor(19,caseId,{actorOverrides:{dnsSigner:{position:{x:145,y:365}},dnsOperator:{position:{x:145,y:610}},dnsValidator:{position:{x:560,y:365},parentId:zonemd?'dnsSecondary':'dnsResolver'},dnsChild:{position:{x:975,y:610}},dnsParent:{position:{x:975,y:365}},dnsRoot:{position:{x:975,y:610}},dnsPrimary:{position:{x:560,y:120}},dnsSecondary:{position:{x:975,y:120}}}}),base=dnssecZoneBase(a,dnssecZoneTextRecords(initialText)),keys=dnssecZoneKeys(a,fixture.keys);
  // A retained serving generation is not retained IXFR difference history.
  if(fallback)a.initialState.dnssec.publication.transfer.availableDifferenceBases=[];
  a.chapter('publication','Zone management, signing and replication');
  dnssecZoneObserve(a,'explicit-initial-custody','Inspect explicitly provisioned g0 and separate private capabilities','dnsOperator',{initialSecondaryGeneration:'g0',initialReceipt:'Declared initial holding, not an invented prior transfer',serial:base.initialGeneration.serial,initialPublicObjects:base.old,signerPrivateCapabilityHolders:['dnsSigner'],transactionSharedKeyHolders:Object.values(keys).map(key=>({keyName:key.keyName,custodians:key.custodians})),nativeInteropClaim:false},[],base.old);
  if(zonemd){dnssecZoneZonemd(a,base,fixture);return dnssecZoneFinish(a);}
  let selected=stream;
  if(updateId){selected=dnssecZoneUpdate(a,base,fixture,keys,fixture.updates[updateId],{denied:updateId==='apexNsDenied',modified:updateId==='mutatedRetainedMac'});if(!selected)return dnssecZoneFinish(a);}
  const boundary=notify?'ixfr-complete-authenticated-atomic-install':fallback?'authenticate-complete-full-zone':updateId?'serve-new-signed-generation':'secondary-authenticated-transfer-completes',now=DNSSEC_BASE_CLOCK+(notify?1:fallback?0:updateId?300:120),generation=dnssecZoneTransfer(a,base,fixture,keys,selected,{boundary,now,notify,fallback});
  if(caseId==='offline-signer-secondary')a.advanceTo(DNSSEC_BASE_CLOCK+121,'secondary-query-clock');
  dnssecZoneLookup(a,base,generation);return dnssecZoneFinish(a);
}
export const DNSSEC_ZONE_CASE_BUILDERS={
  'lab-dnssec19':{
    'offline-signer-secondary':()=>dnssecZoneCase('offline-signer-secondary'),
    'notify-ixfr':()=>dnssecZoneCase('notify-ixfr',{streamId:'ixfr',notify:true}),
    'axfr-fallback':()=>dnssecZoneCase('axfr-fallback',{streamId:'fallback',fallback:true}),
    'tsig-authenticated-update':()=>dnssecZoneCase('tsig-authenticated-update',{streamId:'updateAxfr',updateId:'wwwAllowed'}),
    'tsig-valid-policy-denied':()=>dnssecZoneCase('tsig-valid-policy-denied',{updateId:'apexNsDenied'}),
    'tsig-failure':()=>dnssecZoneCase('tsig-failure',{updateId:'mutatedRetainedMac'}),
    'zonemd-mismatch':()=>dnssecZoneCase('zonemd-mismatch',{zonemd:true}),
  },
};

function dnssecZoneApplyUpdate(initialRecords,changes){
  let records=initialRecords.filter(record=>!(record.type===46&&(record.signature?.typeCovered===6||record.signature?.owner.toLowerCase()==='www.lab.example.'&&record.signature.typeCovered===1)));
  for(const change of changes){
    const same=record=>record.owner.toLowerCase()===change.owner.toLowerCase()&&record.type===change.type;
    if(change.rrclass===255)records=records.filter(record=>!same(record));
    else if(change.rrclass===254)records=records.filter(record=>!same(record)||record.rdataHex!==change.rdataHex);
    else if(change.rrclass===1){const added={...change,rrset:{...change.rrset,class:'IN'}};if(!records.some(record=>same(record)&&record.rdataHex===change.rdataHex))records.push(added);}
    else throw new TypeError('Unsupported authorized UPDATE class');
  }
  return records.map(record=>{
    if(record.type!==6)return record;
    const fields=record.rrset.records[0].split(' ');fields[2]=String((record.serial+1)>>>0);
    const rrset={...record.rrset,records:[fields.join(' ')]};
    return dnssecZoneDecode('000080000000000100000000'+dnssecCanonicalRrsetWire(rrset)).records[0];
  });
}

function dnssecZoneFinish(a){
  return a.finish({decisionPanelLabel:'DNSSEC, transaction authorization and zone integrity are separate',decisionBindings:[{label:'DNSSEC status',path:'dnssec.securityStatus'},{label:'First detector',path:'dnssec.firstDetector'},{label:'Failure stage',path:'dnssec.failureStage'},{label:'UPDATE authenticated',path:'dnssec.publication.management.macValid'},{label:'UPDATE authorized',path:'dnssec.publication.management.authorized'},{label:'Secondary generation',path:'dnssec.publication.transfer.secondaryGeneration'},{label:'Whole-zone digest match',path:'dnssec.publication.zonemd.matched'},{label:'Application result',path:'dnssec.applicationResult.status'}],protocolTimeline:{label:'Independent transaction, signature and cache windows',explanation:'Only explicit protocol-clock events advance seconds. TSIG Fudge is not a DNSSEC signature lifetime or a zone-installation authorization; playback does not age any of them.',entries:[{id:'transaction-window',label:'TSIG signed transaction window',startPath:'dnssec.timers.transaction.timeSigned',deadlinePath:'dnssec.timers.transaction.expiresAt',detail:'The exact independently produced message binds its Time Signed and Fudge; valid MAC and time do not grant update or transfer rights.'},{id:'answer-cache',label:'Accepted answer cache lifetime',startPath:'dnssec.cacheEntries.0.receivedAt',deadlinePath:'dnssec.cacheEntries.0.expiresAt',statusPath:'dnssec.cacheEntries.0.securityStatus',detail:'Four TTL/signature bounds apply only after separate local DNSSEC validation and acceptance.'},{id:'signature-window',label:'Exact authenticated RRSIG window',startPath:'dnssec.timers.signature.inception',deadlinePath:'dnssec.timers.signature.expiration',detail:'Signed inception/expiration remain immutable while received or outgoing TTL decreases.'}]},dnssecAuthoringScope:{liveConformance:false,browserCryptography:false,archivalTransferClaim:false}});
}
