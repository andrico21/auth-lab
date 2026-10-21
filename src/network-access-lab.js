import {labAttribute,labP,labStep,labScenario} from './lab-common.js';

// Offline symbolic fixtures. No network I/O or runtime cryptography.
export const NETWORKLAB_ATTRIBUTES={};
export const NETWORKLAB_SOURCES=[
  ['2865','June 2000','2-5','Standards Track'],['3579','September 2003','2-3','Informational'],['3748','June 2004','3-4','Standards Track'],
  ['9190','February 2022','2.1.1, 2.2-2.3, 5.3-5.6','Standards Track'],['5216','March 2008','2.1.1, 2.3','Standards Track'],
  ['5247','August 2008','1.4, 2-3','Standards Track'],['2548','March 1999','2.4.2-2.4.3','Informational'],['6238','May 2011','4-5','Informational'],
  ['2866','June 2000','3-5','Informational'],['2869','June 2000','5.16','Informational'],['5080','December 2007','2.1-2.2','Standards Track'],
  ['5176','January 2008','2-3, 6','Informational'],['6614','May 2012','2','Experimental'],['9765','April 2025','3-5','Experimental'],
  ['8446','August 2018','2, 4.4, 7','Standards Track'],['5246','August 2008','7.4, 8','Standards Track'],['3580','September 2003','3','Informational'],
].map(([number,revision,section,publicationStatus])=>({name:'RFC '+number,standard:'RFC '+number,section,url:'https://www.rfc-editor.org/rfc/rfc'+number,revision,retrieved:'2026-10-21',publicationStatus,errata:'https://www.rfc-editor.org/errata/rfc'+number,errataDisposition:'Pinned published text; no unverified erratum incorporated.'}));
NETWORKLAB_SOURCES.push(
  {name:'Microsoft NPS accounts and network policy',standard:'Microsoft NPS policy',section:'RADIUS server / AD DS account database and network policies',url:'https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top',revision:'79ebe6bf20524768b259c357913592494f5690b0; updated 2025-09-22',retrieved:'2026-10-21',publicationStatus:'Vendor documentation',errata:'Versioned vendor page; no RFC errata registry'},
  {name:'Microsoft EAP certificate requirements',standard:'Microsoft EAP certificate requirements',section:'Client certificate requirements / Server certificate requirements',url:'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/certificate-requirements-eap-tls-peap',revision:'13b2d50440e0b880deadd46afe076b6b3625235f; updated 2026-02-19',retrieved:'2026-10-21',publicationStatus:'Vendor documentation',errata:'Versioned vendor page; no RFC errata registry'},
  {name:'Microsoft NPS and Windows EAP support',standard:'Microsoft documented NPS profile',section:'TLS 1.3 / Known issues',url:'https://learn.microsoft.com/en-us/windows-server/networking/technologies/extensible-authentication-protocol/windows-11-changes',revision:'16dafaddc757fb0b4ad7e5f8da33fbfc888fbcd4; updated 2025-09-15',retrieved:'2026-10-21',errata:'Vendor versioned page; no RFC errata registry'},
  {name:'Strong certificate account mapping',standard:'Microsoft KB5014754',section:'Certificate mappings / Full Enforcement / Schannel',url:'https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers',revision:'2546ce70e1715ed6ab73ca90438cc5142d6bf85e; updated 2026-09-17',retrieved:'2026-10-21',errata:'Vendor changelog; enforcement date correction 2025-09-10'}
);
const netActorSpecs={
  netPeer:{name:'Alice / supplicant',art:'workstation',role:'EAP peer or local credential input',plainRole:'Supplies the credential and validates the EAP server.',kind:'client',color:'#38bdf8',position:{x:150,y:270},notes:['Only synthetic credentials. EAP-TLS terminates here, not at the NAS.']},
  netNas:{name:'Access switch / NAS',art:'networkSwitch',role:'802.1X authenticator; RADIUS client',plainRole:'Relays EAP and enforces the accepted access policy.',kind:'service',color:'#f59e0b',position:{x:530,y:270},notes:['EAPOL on access link; RADIUS on backend link. No TLS private keys or EMSK.']},
  netServer:{name:'RADIUS / EAP server',art:'radiusServer',role:'Credential validator and authorization authority',plainRole:'Authenticates the peer and decides access policy.',kind:'idp',color:'#22c55e',position:{x:940,y:270},notes:['Trust and account configuration predate this exchange.']},
  netProxy:{name:'Realm proxy',role:'Adjacent-peer RADIUS server and client',plainRole:'Routes a configured realm and validates each independent hop.',kind:'service',color:'#a78bfa',position:{x:560,y:120},notes:['Proxy-State is own forwarding context, not EAP server State. Hop-protected MSK can be recovered here; inner EAP-TLS secrets cannot.']},
  netAccount:{name:'AD DS account service',role:'Certificate account binding and membership authority',plainRole:'Answers a scoped strong-account-mapping and group-policy check.',kind:'idp',color:'#a78bfa',position:{x:975,y:610},notes:['No unsupported LDAP bind or Kerberos AS exchange is invented.']},
  netCollector:{name:'Accounting collector',role:'RADIUS accounting server',plainRole:'Stores correlated records before acknowledging delivery.',kind:'service',color:'#34d399',position:{x:975,y:610},notes:['Accounting delivery knowledge is distinct from NAS service state.']},
  netController:{name:'Session controller',role:'Dynamic Authorization Client',plainRole:'Requests an existing session change or disconnect and learns the result only from a valid reply.',kind:'service',color:'#a78bfa',position:{x:145,y:365},notes:['NAS is the Dynamic Authorization Server for this exchange, although it is the access RADIUS client.']},
  netOtp:{name:'TOTP authenticator',art:'workstation',role:'Provisioned RFC6238 factor',plainRole:'Keeps its own enrollment seed and computes the current short-lived response locally.',kind:'client',color:'#e879f9',position:{x:145,y:610},parentId:'netPeer',notes:['A local software authenticator component, not the NAS; only code output crosses to the user and NAS.']},
};
const netFieldHelp={
  Code:'RADIUS packet code selects Access-Request, Challenge, Accept or Reject; receipt is not trust or admission.',
  Identifier:'Eight-bit RADIUS correlation identifier, checked against the outstanding adjacent-peer request.',
  'RADIUS Identifier':'Eight-bit RADIUS request/reply correlation, independent of the inner EAP Identifier.',
  'EAP Identifier':'EAP Request/Response correlation octet; a relay does not replace it with the RADIUS Identifier.',
  'Request Authenticator':'Unpredictable Access-Request authenticator; participates in password hiding and response verification, not proof of whole-packet confidentiality.',
  'Response Authenticator':'Classic RADIUS MD5 response integrity/correlation value bound to the original Request Authenticator and adjacent-peer shared secret.',
  'Message-Authenticator':'HMAC-MD5 integrity required for classic RADIUS packets carrying EAP-Message; invalid integrity causes discard, not Access-Reject.',
  'User-Name':'Claimed routing/login name. An outer EAP identity is not a verified certificate identity.',
  'User-Password':'Classic RFC 2865 reversible password hiding with adjacent-peer shared secret and Request Authenticator; not TLS and not whole-packet encryption.',
  'NAS-Identifier':'Stable identity of the original NAS enforcing the service, required in each request unless NAS-IP-Address is supplied. Preserved through proxy forwarding; distinct from the adjacent source address or TLS peer used to select trust.',
  'NAS-Port':'The NAS access port to which this request and eventual enforcement apply.',
  State:'Server-issued opaque challenge context, echoed byte-for-byte by the NAS without interpretation.',
  'EAP-Message':'Ordered RADIUS attribute fragments concatenate into one EAP packet; RADIUS attribute splitting is not TLS/EAP fragmentation.',
  'Filter-Id':'Named authorization filter selected by policy; effective only after the NAS verifies and applies a supported result.',
  'Session-Timeout':'Maximum authorized service duration in seconds; not an OAuth token lifetime or browser session.',
  'MS-MPPE-Recv-Key':'Protected RFC 2548 vendor key carrier for the first 32 MSK octets, bound to salt, adjacent-peer secret and Request Authenticator.',
  'MS-MPPE-Send-Key':'Protected RFC 2548 vendor key carrier for the second 32 MSK octets; not the EMSK or a TLS traffic secret.',
};
Object.assign(netFieldHelp,{
  'Proxy-State':'Proxy-owned ordered return-routing context. Append only the forwarding proxy own value and remove only that value on return; unrelated to EAP server State.',
  'Acct-Session-Id':'Stable NAS service correlation identifier shared by Start, Interim-Update and Stop, never a fresh login for each record.',
  'Acct-Status-Type':'Accounting event type Start, Interim-Update or Stop. Delivery acknowledgement is independent from access enforcement.',
  'Acct-Delay-Time':'Seconds the NAS has attempted to deliver this accounting record. Updating it changes accounting packet/authenticator bookkeeping, not logical record identity.',
  'Acct-Session-Time':'Elapsed service duration in seconds, not sender acknowledgement time.',
  'Acct-Input-Octets':'Cumulative octets received from the peer at the NAS, not a delta to add again on retries.',
  'Acct-Output-Octets':'Cumulative octets sent to the peer by the NAS, not a second usage charge on retransmission.',
  'Acct-Input-Packets':'Cumulative packets received from the peer for this Acct-Session-Id.',
  'Acct-Output-Packets':'Cumulative packets sent to the peer for this Acct-Session-Id.',
  'Acct-Terminate-Cause':'Reason the service actually ended. Admin-Reset follows a processed Disconnect; accounting receipt does not cause termination.',
  'Error-Cause':'Dynamic authorization failure reason: 401 Unsupported Attribute, 405 Unsupported Service, 503 Session Context Not Found. A NAK is not an Access-Reject login result.',
  'Event-Timestamp':'Original dynamic-request send time, checked against the configured freshness window and retained on retries; stale values are silently discarded.',
  Token:'Opaque 16-octet RADIUS/1.1 request/response correlation token. Replaces the Authenticator field and Identifier function; not an MD5 value.',
  Reserved:'RADIUS/1.1 former Identifier octet: send zero and ignore on reception. Correlation uses the 16-octet Token instead.',
  Length:'Encoded complete RADIUS packet length, including its 20-octet header and attributes.',
  'ALPN offered':'Client TLS Application-Layer Protocol Negotiation list; RADIUS/1.1 requires the explicitly supported radius/1.1 profile.',
  'ALPN selected':'Negotiated TLS application protocol. Only an accepted radius/1.1 association removes historic RADIUS MD5/shared-secret semantics.',
  MSK:'Method-exported master session key. Endpoint-local derivation is separate from authorized protected distribution to the intended authenticator.',
  EMSK:'Extended master session key. Only the peer and EAP server derive it; it is never distributed to NAS or proxy.',
  Exporter:'RFC9190 TLS1.3 TLS-Exporter uses label EXPORTER_EAP_TLS_Key_Material, context the single EAP Type octet 0x0D, and 128 output octets: MSK [0,64), EMSK [64,128). Not the TLS1.2 PRF.',
  'Exporter label':'RFC9190 key-material exporter label EXPORTER_EAP_TLS_Key_Material, distinct from any Method-Id exporter label.',
  'Exporter context':'Exactly one context octet: EAP Type 0x0D (13), not the ASCII text "0x0D" and not an empty context.',
  'Exporter length':'128 output octets; MSK is octets 0-63 and EMSK is octets 64-127 (zero-based).',
  PRF:'TLS1.2 EAP-TLS PRF with label client EAP encryption and client_random || server_random, not the TLS1.3 exporter.',
  Transcript:'Endpoint-local ordered TLS handshake transcript, separate from RADIUS and EAP correlation identifiers.',
  'TLS records':'TLS handshake or application records. TLS1.3 certificate flights after ServerHello are encrypted; pass-through NAS/proxy cannot decode inner fields.',
  'Server Certificate':'Public server certificate chain; TLS1.2 visible before encryption, TLS1.3 protected after ServerHello; never contains the private key.',
  'Client Certificate':'Public client certificate and usage/binding identity, not proof of group policy or a private-key transfer.',
  'Decoded certificate':'Certificate fields recovered by the legitimate TLS endpoint. Decryption precedes issuer/name/use/time/revocation and possession validation.',
  'Service-Type':'Requested or authorized NAS service. Unsupported CoA service yields NAK 405 rather than mutating the existing session.',
});
const netRadiusFields=new Set(['Code','Identifier','RADIUS Identifier','Length','Request Authenticator','Response Authenticator','User-Name','User-Password','NAS-Identifier','NAS-Port','State','Proxy-State','Filter-Id','Session-Timeout','Service-Type']);
function netFieldReference(name,profile,type,protocol=''){
  const rfc=number=>NETWORKLAB_SOURCES.find(source=>source.standard==='RFC '+number);
  if(profile==='radius11')return rfc(/Token|Reserved|Password|Authenticator|ALPN/.test(name)||['Code','Length'].includes(name)?9765:netRadiusFields.has(name)?2865:8446);
  if(name.startsWith('MS-MPPE-'))return rfc(2548);
  if(name.startsWith('Acct-'))return rfc(2866);
  if(profile==='dynamic'||['Error-Cause','Event-Timestamp'].includes(name))return rfc(5176);
  if(profile==='accounting')return rfc(2866);
  if(netRadiusFields.has(name))return rfc(2865);
  if(['EAP-Message','Message-Authenticator'].includes(name))return rfc(3579);
  if(['EAP Identifier','EAP Code','Type','EAP-Response'].includes(name))return rfc(3748);
  if(name==='EAP-TLS flags')return rfc(5216);
  if(['MSK','EMSK'].includes(name))return rfc(5247);
  if(name==='PRF')return rfc(5216);
  if(name.startsWith('Exporter')||name==='Transcript')return rfc(profile==='nps12'?5216:9190);
  if(profile==='nps12'&&/binding|mapped|account|group|membership/i.test(name))return NETWORKLAB_SOURCES.find(source=>source.standard===(/group|membership/i.test(name)?'Microsoft NPS policy':'Microsoft KB5014754'));
  if(profile==='nps12'&&/EKU|certificate.*(use|check)|issuer/i.test(name))return NETWORKLAB_SOURCES.find(source=>source.standard==='Microsoft EAP certificate requirements');
  if(/Issuer trust|Server identity|EKU|validity|Revocation|Authenticated identity/.test(name)&&['eap13','proxy'].includes(profile))return rfc(9190);
  if(type==='session'&&['eap13','nps12'].includes(profile))return rfc(3580);
  if(/TLS|Certificate|certificate|private|ephemeral|Derivation|Finished/.test(name)||type==='private-key'||/Local TLS/.test(protocol))return rfc(profile==='nps12'?5246:8446);
  if(profile==='totp'&&/TOTP|step|factor|window/i.test(name))return rfc(6238);
  if(/RADIUS/.test(protocol))return rfc(2865);
  return rfc(profile==='eap13'?9190:profile==='nps12'?5216:profile==='transport'||profile==='comparison'?6614:2865);
}
function netFieldSection(name,source,profile){
  if(profile==='radius11'&&source.standard==='RFC 9765')return /Token|Reserved/.test(name)||['Code','Length'].includes(name)?'4.1-4.2':name==='User-Password'?'5.1.1':name.includes('Message-Authenticator')?'5.2':name.includes('ALPN')?'3.1-3.3':source.section;
  if(name.startsWith('Exporter'))return '2.3';
  if(name.startsWith('MS-MPPE-'))return name.includes('Recv')?'2.4.3':'2.4.2';
  if(source.standard==='RFC 5176')return name==='Error-Cause'?'3.5':name==='Event-Timestamp'?'6.3':'2.3, 3';
  const sections={'State':'5.24','Proxy-State':'5.33','User-Password':'5.2','User-Name':'5.1','NAS-Identifier':'5.32','NAS-Port':'5.5','Filter-Id':'5.11','Session-Timeout':'5.27','Service-Type':'5.6','EAP-Message':'3.1','Message-Authenticator':'3.2','EAP Identifier':'4.1','EAP Code':'4.1','Exporter':'2.3','PRF':'2.3','MSK':'1.4','EMSK':'1.4'};
  return sections[name]||source.section;
}
function netObjectMeaning(label,type){
  if(/EMSK/.test(label))return netFieldHelp.EMSK;
  if(/MSK/.test(label))return netFieldHelp.MSK;
  if(/transcript/i.test(label))return netFieldHelp.Transcript;
  return ({
    'private-key':'Protected local signing or ephemeral private-key handle. Only its logical owner can inspect it; no wire export or relay possession is permitted.',
    'certificate':'Provisioned public certificate and key chain. A distinct wire representation and endpoint-local validation determine usable trust; the private key is a separate object.',
    'shared-secret':'Adjacent RADIUS peer association secret. Both configured endpoints retain local copies; it is never transmitted and is not an EAP-TLS traffic secret.',
    'secret':'Enrollment secret held only by its provisioned authenticator and validator. Short-lived responses do not disclose the seed.',
    'trust-record':'Initially provisioned issuer, peer identity, certificate use, validity or source-authorization policy. Receiving a certificate does not create this trust.',
    'account-record':'Local credential/account authority record. A scoped validation result is not a transfer of account secrets or a fictional backend login.',
    'session':'NAS-enforced service identity. Creation or removal occurs only at the explicit local enforcement boundary, independently from AAA reply generation.',
    'accounting-record':'Correlated durable usage record. Receipt, validation/storage, sender acknowledgement and service lifetime are separate facts.',
    'challenge-context':'Server-issued challenge correlation context. The NAS preserves opaque bytes without interpreting the validator state.',
    'dynamic-request':'Selectors identify an existing NAS/session; requested policy changes are separate. Source, integrity and freshness must validate before action.',
    'dynamic-result':'Original cached ACK/NAK result. Recipient-side action precedes transmission; sender knowledge follows only valid correlated receipt.',
    'routing-policy':'Explicit local allowed-realm route, not an inferred AD forest trust or universal unknown-realm result.',
    'key':'Locally derived traffic/key material with exact layer and owner scope. Named protected AAA distribution is separate from TLS key derivation.',
    'transaction':'One immutable request/result correlation object. Retry occurrences do not become new logical authentications or sessions.',
  })[type]||'Explicit '+type+' state with authored owner, readers, receipt and release boundaries; values are symbolic fixtures.';
}
let netCollectDefinitions=true;
function netWithoutRegistration(build){
  const previous=netCollectDefinitions;netCollectDefinitions=false;
  try{return build();}finally{netCollectDefinitions=previous;}
}
function netPut(path,value){return {op:'put',path,value};}
function netAuthor(slug,title,profile='pap',options={}){
  const id='lab-net-'+slug,steps=[],definitions={},inventory={artifacts:[],initial:[],events:{},bindings:[]};
  const actorIds=options.actorIds||['netPeer','netNas','netServer'];
  const actors=Object.fromEntries(actorIds.map(actor=>[actor,{id:actor,...netActorSpecs[actor],...options.actorOverrides?.[actor]}]));
  let fieldSerial=0;
  const object=(key,label,creator,readers,value,{initial=false,type='protocol-object',representation='plain',store='local store',holders=[creator],protectedValue}={})=>{
    const artifactId=id+':'+key+':g1';
    const attributeId='net'+slug.replace(/-/g,'_')+'_object_'+key.replace(/-/g,'_');
    const source=netFieldReference(/EMSK/.test(label)?'EMSK':/MSK/.test(label)?'MSK':label,profile,type);
    if(type!=='message')definitions[attributeId]={...labAttribute(label,netObjectMeaning(label,type),creator,'Preserve '+label+' ownership, exact local/protected values and independent lifetime; '+netObjectMeaning(label,type),value,source.standard,source.url),section:source.section,readers:[...readers],synthetic:true};
    const representations=[{representationId:representation,format:representation,readableBy:readers,fields:type==='message'?[]:[{attributeId,name:label,value,readableBy:readers}]}];
    if(protectedValue!==undefined){
      definitions[attributeId+'_wire']={...labAttribute('Protected '+label,'Exact protected carrier for '+label+'. The wire container is distinct from its locally decoded fields.',creator,'Show the actual protected carrier without substituting local plaintext or derived key material.',protectedValue,source.standard,source.url),section:source.section,readers:[...actorIds],synthetic:true};
      representations.push({representationId:'wire',format:'protected wire',readableBy:actorIds,fields:[{attributeId:attributeId+'_wire',name:'Protected '+label,value:protectedValue,readableBy:actorIds}]});
    }
    inventory.artifacts.push({artifactId,type,label,creator,representations});
    if(initial){inventory.initial.push({op:'create',artifactId});for(const actorId of holders)inventory.initial.push({op:'acquire',artifactId,actorId,store,representationId:representation});}
    return artifactId;
  };
  const acquire=(artifactId,actorId,store='local store',representationId='plain')=>({op:'acquire',artifactId,actorId,store,representationId});
  const release=(artifactId,actorId,store='local store',representationId='plain')=>({op:'release',artifactId,actorId,store,representationId});
  const create=(artifactId,...holders)=>[{op:'create',artifactId},...holders.map(actorId=>acquire(artifactId,actorId))];
  const event=(key,title,from,to,protocol,values,summary,{effects=[],held=[],readers,representation='plain',channel,checks=[],localKind='inspect'}={})=>{
    const sourceEventId=id+':'+key,local=from===to,fieldIds=[],payload=[],operations=[];
    for(const [name,value] of Object.entries(values)){
      const attributeId=(options.attributePrefix||'net'+slug.replace(/-/g,'_'))+'_'+(++fieldSerial);
      const meaning=profile==='radius11'&&name==='User-Password'?'RFC9765 User-Password is text inside the negotiated confidential TLS association, not historic MD5-obfuscated blocks.':profile==='radius11'&&name==='Message-Authenticator'?'Not sent in RADIUS/1.1; an obsolete received Message-Authenticator is ignored, not verified with a shared secret.':['accounting','dynamic'].includes(profile)&&name==='Request Authenticator'?'Accounting-style MD5 integrity over Code, Identifier, Length, zero authenticator, attributes and configured adjacent secret; recompute when encoded attributes change.':netFieldHelp[name]||name+': '+summary;
      const source=netFieldReference(name,profile,undefined,protocol);
      const section=netFieldSection(name,source,profile);
      definitions[attributeId]={...labAttribute(name,meaning,from,'Use '+name+' at its authored '+representation+' boundary: '+meaning,value,source.standard,source.url),section,readers:[...(readers||[from,to])],synthetic:true};
      fieldIds.push(attributeId);payload.push(labP(name,value,meaning,attributeId));
      const occurrence={attributeId,instanceId:sourceEventId+':fields',creator:from,holders:local?[from]:[from,to],inspectors:readers||[from,to],fieldPath:name,representation,value,sourceEventId,exactValueRef:sourceEventId+':fields:'+representation+':'+name};
      if(local)operations.push({...occurrence,kind:localKind,actorId:from,detail:summary});
      else operations.push({...occurrence,kind:'send',actorId:from,detail:summary},{...occurrence,kind:'receive',actorId:to,detail:summary});
    }
    const step=labStep(sourceEventId,title,from,to,key,channel||(local?'internal':'backchannel'),summary,summary,fieldIds,payload,checks,operations);
    step.eventType=local?'local':'message';step.protocolLabel=protocol;step.beginnerSummary=summary;step.protocolDetail=summary;step.cryptoDetail='SYM(...) is symbolic, not captured or computed cryptography.';
    const transport=local?'local computation':protocol.startsWith('EAPOL')?'IEEE 802.1X access link':channel==='human'?'declared local input':protocol.includes('Accounting')?'UDP 1813':protocol.includes('Dynamic')?'UDP 3799':protocol.includes('TLS')&&!protocol.startsWith('RADIUS / EAP')?'TCP 2083':protocol.startsWith('Teaching-only')?'scoped teaching disclosure, no wire protocol claimed':'UDP 1812';
    step.layers=[{protocol,transport,from,to,protection:local?'Actor-local operation; no remote effect':protocol.startsWith('Teaching-only')?'Documented logical boundary only; no fabricated backend protocol':protocol.includes('TLS')?'Named TLS profile; endpoint-local keys, not relay secrets':'Profile-specific integrity; not whole-packet encryption'}];
    if(!local&&profile==='eap13'){
      const hasTls=Object.values(values).some(value=>/ClientHello|ServerHello|encrypted|Certificate|application_data/.test(String(value)));
      step.layers=[{protocol:protocol.startsWith('EAPOL')?'EAPOL':'RADIUS',transport:protocol.startsWith('EAPOL')?'IEEE 802.1X access link':'UDP 1812',from,to,protection:protocol.startsWith('EAPOL')?'No whole-link encryption asserted':'Classic RADIUS authenticators; adjacent-peer integrity',keyRef:protocol.startsWith('EAPOL')?undefined:id+':radius-secret:g1'},{protocol:'EAP',transport:'Encapsulated EAP request/response',from:from==='netServer'?'netServer':from==='netPeer'?'netPeer':'netNas',to,protection:'EAP code and identifier are distinct from outer RADIUS correlation'}];
      if(hasTls)step.layers.push({protocol:'TLS 1.3 inside EAP-TLS',transport:'EAP method records',from:from==='netServer'||from==='netNas'&&to==='netPeer'?'netServer':'netPeer',to:to==='netPeer'||from==='netServer'?'netPeer':'netServer',protection:'TLS record protection after ServerHello; no NAS decryption',keyRef:from==='netServer'||to==='netPeer'?id+':tls-secrets:g1':id+':peer-tls-secrets:g1',certificateRole:'Inner EAP-TLS mutual endpoint authentication, not transport certificates'});
    }
    if(!local&&profile==='nps12'&&(protocol.startsWith('EAPOL')||protocol==='RADIUS / EAP-Message')){
      step.layers=[{protocol:protocol.startsWith('EAPOL')?'EAPOL':'RADIUS',transport:protocol.startsWith('EAPOL')?'IEEE 802.1X access link':'UDP 1812',from,to,protection:protocol.startsWith('EAPOL')?'No protected data link claimed':'Adjacent RADIUS authenticators',keyRef:protocol.startsWith('EAPOL')?undefined:id+':radius-secret:g1'},{protocol:'EAP',transport:'TLS1.2 EAP method carriage',from,to,protection:'Independent EAP identifier correlation'}];
      if(Object.values(values).some(value=>/ClientHello|ServerHello|Certificate|Finished/.test(String(value))))step.layers.push({protocol:'TLS1.2 inside EAP-TLS',transport:'EAP method records',from:from==='netServer'||to==='netPeer'?'netServer':'netPeer',to:to==='netPeer'||from==='netServer'?'netPeer':'netServer',protection:'TLS1.2 certificate flights visible before ChangeCipherSpec; Finished encrypted after CCS',keyRef:from==='netServer'||to==='netPeer'?id+':netServer-tls:g1':id+':netPeer-tls:g1',certificateRole:'Inner full-handshake EAP-TLS endpoint certificate; not outer RadSec transport identity'});
    }
    step.protocolEffects=effects;steps.push(step);
    inventory.events[sourceEventId]={effects:[...held],messages:[]};
    if(!local){
      const packet=object(key+'-packet',title,from,readers||[from,to],JSON.stringify(values),{representation,type:'message'});
      inventory.artifacts.at(-1).representations[0].fields=payload.map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:readers||[from,to]}));
      inventory.events[sourceEventId].effects.push({op:'create',artifactId:packet},acquire(packet,to,'pending inbox',representation));
      inventory.events[sourceEventId].messages.push({from,to,objects:[{artifactId:packet,representationId:representation}],start:0,end:1});
      // Packet copies survive receipt until the next explicit local/network event.
      step.netPacket=packet;
    }
    return step;
  };
  const cleanedPackets=new Set();
  const cleanupInbox=(step,at)=>{
    if(cleanedPackets.has(step.netPacket))return;
    cleanedPackets.add(step.netPacket);
    inventory.events[at.id].effects.push(release(step.netPacket,step.to,'pending inbox',step.attributeOperations[0]?.representation||'plain'));
  };
  const finish=()=>{
    for(let index=0;index<steps.length;index++){
      const packet=steps[index];
      if(!packet.netPacket||cleanedPackets.has(packet.netPacket))continue;
      let consume=steps.slice(index+1).find(step=>step.from===packet.to&&step.to===packet.to);
      if(!consume)consume=event('consume-'+index,'Consume received protocol packet',packet.to,packet.to,'Local packet consumption',{'Source event':packet.id},'Release only this actor-local packet inbox after processing; history is retained.');
      cleanupInbox(packet,consume);
    }
    if(options.bindings)inventory.bindings.push(...options.bindings);
    const source=profile==='eap13'?NETWORKLAB_SOURCES.find(s=>s.standard==='RFC 9190'):NETWORKLAB_SOURCES[0];
    const model=labScenario({id,title,summary:title+' - symbolic offline access decision',workspace:'network',family:'network-access',protocol:profile==='eap13'?'EAP-TLS':'RADIUS',category:'Network access',standard:source.standard,source:source.url,supportNote:'Standards-based teaching profile; no live interoperability run.',learningObjective:'Separate receipt, credential validation, policy and NAS enforcement.',prerequisites:['Provisioned synthetic credential','Configured trust and adjacent-peer association'],keywords:['network','RADIUS','802.1X',profile],profile:{id:'net-'+profile+'-v1',name:profile==='eap13'?'RFC 9190 wired full mutual EAP-TLS 1.3':'RFC 2865 PAP-style password',version:'1',implementation:'Deterministic offline standards illustration',publicationStatus:'Standards Track',supportStatus:'Standards-based teaching profile; no live interoperability run',algorithms:profile==='eap13'?['TLS_AES_128_GCM_SHA256','ECDHE P-256','ECDSA P-256','RFC 9190 exporter']:['Classic MD5 password hiding and response authenticator; legacy comparison only'],transports:['EAPOL where applicable','RADIUS/UDP 1812'],assumptions:['No resumption','Preprovisioned trust and secrets','No runtime cryptography'],completion:'NAS applies accepted policy, not merely Access-Accept generation',sources:[source],cryptoDetail:'All SYM and HANDLE fixtures are symbolic, not production bytes.'},initialState:{network:{port:'unauthorized',status:'authenticating',serverIdentity:false,peerIdentity:false,policy:'pending',reply:'none',mskReleased:false,logicalAuthentications:0,wifiUsable:false},sessions:{}},networkInventory:inventory},definitions,steps,actors);
    model.status='reference';
    model.profile.sources=profile==='eap13'?NETWORKLAB_SOURCES.filter(source=>['RFC 2865','RFC 3579','RFC 3748','RFC 9190','RFC 5247','RFC 2548','RFC 5080','RFC 8446','RFC 3580'].includes(source.standard)):[NETWORKLAB_SOURCES[0],NETWORKLAB_SOURCES[10]];
    model.relatedLessons=profile==='eap13'?[
      {id:'lab-net-nps-ad-tls12',title:'Compare NPS TLS 1.2',summary:'A separate Windows Server 2022 / Windows 11 24H2 full-handshake configuration model with strong account mapping; not NPS TLS 1.3 support.'},
      {id:'lab-net-enterprise-wifi-eap',title:'Compare the bounded Wi-Fi decision',summary:'Same EAP role separation, but EAP completion is not a usable protected Wi-Fi link.'},
      {id:'lab-net-radius-udp-radsec',title:'Compare UDP and RadSec envelopes',summary:'Outer NAS-to-AAA transport TLS is distinct from inner peer-to-EAP-server TLS.'},
    ]:[{id:'lab-net-eap-tls13-wired',title:'Compare certificate-based EAP-TLS',summary:'The NAS relays an endpoint TLS method instead of receiving a PAP-style password.'}];
    if(options.meta)Object.assign(model,options.meta);
    if(options.initialState)model.initialState={...model.initialState,...options.initialState,network:{...model.initialState.network,...options.initialState.network}};
    if(options.profileMetadata)model.profile={...model.profile,...options.profileMetadata};
    if(netCollectDefinitions)Object.assign(NETWORKLAB_ATTRIBUTES,definitions);
    return model;
  };
  return {id,steps,definitions,inventory,object,acquire,release,create,event,cleanupInbox,finish};
}
function netPasswordRepresentative(){
  const a=netAuthor('radius-password-accept','RADIUS password accept');
  const secret=a.object('radius-secret','Adjacent-peer shared secret','netNas',['netNas','netServer'],'HANDLE(NAS-AAA shared secret)',{initial:true,holders:['netNas','netServer'],type:'shared-secret'});
  const credential=a.object('password','Synthetic password','netPeer',['netPeer','netNas','netServer'],'SYM(alice password)',{initial:true,type:'credential',protectedValue:'SYM(hidden password blocks)'});
  a.object('account-record','Local password verifier and access policy','netServer',['netServer'],'HANDLE(local account record)',{initial:true,type:'account-record'});
  a.event('input','Local credential entry','netPeer','netNas','Local credential input',{'User-Name':'alice@corp.example','Password':'SYM(alice password)'},'Alice supplies the synthetic password locally to the NAS; this is not EAP or a browser login.',{channel:'human',held:[a.acquire(credential,'netNas')]});
  const request=a.event('request','Access-Request','netNas','netServer','RADIUS/UDP',{'Code':'1 Access-Request','Identifier':'41','Request Authenticator':'SYM(random request authenticator 41)','User-Name':'alice@corp.example','User-Password':'SYM(hidden password blocks)','NAS-Identifier':'switch.corp.example','NAS-Port':'7'},'NAS requests password authentication. Only User-Password is hidden; the packet is not encrypted.',{held:[a.acquire(credential,'netServer','credential validation','wire')]});
  const wirePassword=request.payload.find(field=>field.name==='User-Password');
  a.inventory.artifacts.find(artifact=>artifact.artifactId===credential).representations.find(rep=>rep.representationId==='wire').fields=[{attributeId:wirePassword.attributeId,name:wirePassword.name,value:wirePassword.value,readableBy:['netNas','netServer']}];
  a.inventory.events[request.id].messages[0].objects.push({artifactId:credential,representationId:'wire'});
  const check=a.event('validate','Validate credentials and policy','netServer','netServer','Local RADIUS validation',{'Credential check':'valid','Policy':'Filter-Id employee-wired'},'Server verifies the configured NAS, recovers the password with its local secret and checks its local account and service policy.',{held:[a.acquire(credential,'netServer','credential validation'),a.release(credential,'netServer','credential validation','wire')],effects:[netPut('network.peerIdentity',true),netPut('network.policy','accepted'),netPut('network.logicalAuthentications',1)]});a.cleanupInbox(request,check);
  const reply=a.event('accept','Access-Accept delivery','netServer','netNas','RADIUS/UDP',{'Code':'2 Access-Accept','Identifier':'41','Response Authenticator':'SYM(MD5 response with original Request Authenticator and shared secret)','Filter-Id':'employee-wired','Session-Timeout':'3600'},'The accepted policy reaches the NAS as an untrusted pending reply. No service is active yet.',{effects:[netPut('network.reply','received-unverified')],held:[a.release(credential,'netServer','credential validation')]});
  const verify=a.event('verify-reply','Verify response correlation','netNas','netNas','Local RADIUS validation',{'Response verification':'Identifier 41 and Response Authenticator valid','Target':'switch.corp.example port 7'},'NAS checks outstanding transaction and response authenticator before trusting authorization attributes.',{effects:[netPut('network.reply','verified')]});a.cleanupInbox(reply,verify);
  const session=a.object('service-session','Authorized NAS service','netNas',['netNas'],'SYM(session-7 employee-wired)',{type:'session'});
  a.inventory.bindings.push({path:'sessions.access',presentWhen:'exists',actorId:'netNas',artifactId:session,representationId:'plain',store:'local store'});
  a.event('enforce','Apply NAS service policy','netNas','netNas','Local NAS enforcement',{'Effective Filter-Id':'employee-wired','Service':'active'},'Only now the NAS applies its supported policy and activates exactly one service; no OAuth token, browser session or Kerberos ticket exists.',{effects:[netPut('network.port','authorized'),netPut('network.status','port authorized'),netPut('sessions.access',{id:'session-7',actor:'alice@corp.example',filter:'employee-wired',active:true})],held:[...a.create(session,'netNas'),a.release(credential,'netNas')]});
  return a.finish();
}
function netCertificateDetails(a,artifactId,actor,variant='normal',nps=false){
  const server=actor==='netServer',expired=variant.includes('expired'),badIssuer=['untrusted-issuer','bad-client-chain'].includes(variant);
  const fields={
    Subject:server?'CN=radius.corp.example, OU=Network Access Certificate Authentication Demonstration, O=Example Reserved Documentation Enterprise':'CN=Alice Example, OU=Reserved Certificate Teaching Fixtures, O=Example Enterprise',
    Issuer:badIssuer?'CN=Untrusted Example Test CA':'CN=Example Enterprise Test CA',
    'Subject Alternative Name':server?variant==='wrong-server-name'?'DNS:unexpected.corp.example':'DNS:radius.corp.example':'UPN:alice@corp.example',
    'Extended Key Usage':server?'serverAuth':variant==='inappropriate-client-EKU'?'serverAuth only':'clientAuth',
    'Not Before':'2026-01-01T00:00:00Z',
    'Not After':expired?'2026-10-20T00:00:00Z':'2027-01-01T00:00:00Z',
  };
  const artifact=a.inventory.artifacts.find(item=>item.artifactId===artifactId),readers=[...artifact.representations[0].readableBy];
  for(const [name,value] of Object.entries(fields)){
    const attributeId='netCertificate_'+a.id.replace(/-/g,'_')+'_'+actor+'_'+name.replace(/ /g,'_');
    const source=nps?NETWORKLAB_SOURCES.find(source=>source.standard==='Microsoft EAP certificate requirements'):NETWORKLAB_SOURCES.find(source=>source.standard==='RFC 9190');
    a.definitions[attributeId]={...labAttribute(name,'Public certificate '+name+' fixture checked independently from private-key possession and access policy.',actor,'Validate issuer/name/use/time at the receiving TLS endpoint, not at an EAP relay.',value,source.standard,source.url),section:nps?source.section:'2.2, 5.3',readers,synthetic:true};
    artifact.representations[0].fields.push({attributeId,name,value,readableBy:readers});
  }
  return fields;
}
function netEapRepresentative(slug='eap-tls13-wired',title='Wired 802.1X EAP-TLS 1.3',options={}){
  const a=netAuthor(slug,title,'eap13',options.wifi?{actorOverrides:{netNas:{name:'Enterprise AP / NAS',art:'accessPoint',role:'Pass-through 802.11 authenticator; RADIUS client',plainRole:'Relays EAP but does not establish protected Wi-Fi link traffic in this bounded lesson.'}},profileMetadata:{name:'RFC9190 bounded enterprise Wi-Fi EAP decision',transports:['Peer/AP EAPOL','AP/AAA RADIUS UDP1812'],completion:'EAP access decision complete; Wi-Fi link establishment not shown',assumptions:['No wireless secure-association handshake or key installation shown','No usable protected Wi-Fi traffic, MACsec or Internet reachability claimed']}}:{});
  a.object('radius-secret','NAS to AAA shared secret','netNas',['netNas','netServer'],'HANDLE(NAS-AAA secret)',{initial:true,holders:['netNas','netServer'],type:'shared-secret'});
  for(const actor of ['netPeer','netServer']){
    a.object(actor+'-private-key','Protected certificate private key',actor,[actor],'HANDLE('+actor+' non-exportable signing key)',{initial:true,type:'private-key'});
    const certificate=a.object(actor+'-certificate','Provisioned certificate and public key',actor,['netPeer','netServer'],'SYM('+actor+' certificate chain)',{initial:true,type:'certificate',protectedValue:'SYM(TLS1.3 encrypted '+actor+' certificate chain)'});
    netCertificateDetails(a,certificate,actor,(actor==='netServer'&&options.failure==='server'||actor==='netPeer'&&options.failure==='client')?options.variant||'normal':'normal');
    a.object(actor+'-trust','Issuer, identity, EKU, validity and revocation policy',actor,[actor],'HANDLE('+actor+' configured trust policy)',{initial:true,type:'trust-record'});
  }
  const tls=a.object('tls-secrets','Server TLS 1.3 traffic secrets','netServer',['netServer'],'SYM(endpoint TLS traffic secrets)',{type:'key'});
  const peerTls=a.object('peer-tls-secrets','Peer TLS 1.3 traffic secrets','netPeer',['netPeer'],'SYM(endpoint TLS traffic secrets)',{type:'key'});
  const exporter='TLS-Exporter(label EXPORTER_EAP_TLS_Key_Material, context Type=0x0D (one octet), length 128)';
  const msk=a.object('msk','Server EAP MSK 64 octets','netServer',['netServer','netNas'],'SYM('+exporter+'; MSK octets 0-63)',{type:'key',protectedValue:'SYM(protected first 32 MSK octets) | SYM(protected second 32 MSK octets)'});
  const peerMsk=a.object('peer-msk','Peer locally derived EAP MSK 64 octets','netPeer',['netPeer'],'SYM('+exporter+'; MSK octets 0-63)',{type:'key'});
  const emsk=a.object('emsk','Server EAP EMSK 64 octets','netServer',['netServer'],'SYM('+exporter+'; EMSK octets 64-127)',{type:'key'});
  const peerEmsk=a.object('peer-emsk','Peer locally derived EAP EMSK 64 octets','netPeer',['netPeer'],'SYM('+exporter+'; EMSK octets 64-127)',{type:'key'});
  const transcript=a.object('transcript','Peer EAP-TLS transcript state','netPeer',['netPeer'],'SYM(handshake transcript generation 1)',{type:'transcript'});
  const serverTranscript=a.object('server-transcript','Server EAP-TLS transcript state','netServer',['netServer'],'SYM(handshake transcript generation 1)',{type:'transcript'});
  const peerEphemeral=a.object('peer-ephemeral','Peer ephemeral ECDHE private share','netPeer',['netPeer'],'HANDLE(peer ephemeral P-256 private share)',{type:'private-key'});
  const serverEphemeral=a.object('server-ephemeral','Server ephemeral ECDHE private share','netServer',['netServer'],'HANDLE(server ephemeral P-256 private share)',{type:'private-key'});
  const challenge=a.object('eap-context','Opaque EAP challenge State','netServer',['netServer','netNas'],'SYM(opaque context 1)',{type:'challenge-context'});
  const eap=(key,title,from,to,values,summary,extra={})=>a.event(key,title,from,to,'EAPOL / EAP-TLS',values,summary,{channel:'backchannel',...extra});
  const radius=(key,title,from,to,values,summary,extra={})=>a.event(key,title,from,to,'RADIUS / EAP-Message',{'Message-Authenticator':'SYM(HMAC-MD5 adjacent-peer integrity)',...values,...values.Code==='Access-Request'?{'NAS-Identifier':options.wifi?'ap.corp.example':'switch.corp.example'}:{}},summary,extra);
  const finish=()=>netFinishEapInventory(a,{invalidServer:options.failure==='server',invalidPeer:options.failure==='client'});
  const fail=(kind,detector,exported=false)=>{
    const variant=options.variant||({'server':'untrusted-issuer','client':'inappropriate-client-EKU','policy':'unauthorized-group'}[kind]);
    const alert=variant.includes('expired')?'certificate_expired':variant.includes('revoked')?'certificate_revoked':variant==='bad-client-chain'||variant==='untrusted-issuer'?'unknown_ca':variant==='wrong-server-name'?'certificate_unknown':kind==='client'?'unsupported_certificate':'access_denied';
    if(detector==='netPeer'){
      eap('alert-peer','Peer sends encrypted TLS fatal alert','netPeer','netNas',{'EAP Identifier':'3','TLS alert':'SYM(encrypted '+alert+'; '+variant+')'},'Peer reports the named certificate failure after ServerHello, using established TLS handshake record protection.',{representation:'wire'});
      radius('alert-backend','Relay encrypted peer alert','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'43','Request Authenticator':'SYM(RA43)','State':'SYM(opaque context 1)','EAP-Message':'Response/EAP-TLS id3 encrypted fatal alert'},'NAS relays an opaque method alert, not the peer certificate private key.',{representation:'wire'});
    }else{
      radius('alert-backend','Server sends encrypted TLS failure alert','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':'43','Response Authenticator':'SYM(response43)','State':'SYM(opaque context 1)','EAP-Message':'Request/EAP-TLS id4 SYM(encrypted '+alert+'; '+variant+')'},'The EAP endpoint identifies the exact failing check. No protected success 0x00 or MSK release is sent.',{representation:'wire'});
      a.event('alert-envelope-check','NAS checks failure challenge envelope','netNas','netNas','Local RADIUS validation',{'Checks':'Response and Message-Authenticator, request correlation valid'},'Only a valid adjacent envelope is relayed; NAS does not decrypt the inner alert.');
      eap('alert-peer','Relay encrypted server alert','netNas','netPeer',{'EAP Identifier':'4','TLS alert':'SYM(encrypted '+alert+'; '+variant+')'},'The peer receives the endpoint-protected failure alert.',{representation:'wire'});
      eap('alert-ack-peer','Peer acknowledges failure flight','netPeer','netNas',{'EAP Identifier':'4','EAP-TLS data':'empty'},'Peer acknowledges this EAP request, not successful authentication.');
      radius('alert-ack-backend','Relay failure acknowledgement','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'44','Request Authenticator':'SYM(RA44)','State':'SYM(opaque context 1)','EAP-Message':'Response/EAP-TLS id4 empty'},'This gives the server a response to its last failure request.');
    }
    const status=kind==='server'?'server certificate rejected':kind==='client'?'client certificate rejected':'policy denied';
    radius('failure','Access-Reject and EAP-Failure','netServer','netNas',{'Code':'Access-Reject','RADIUS Identifier':detector==='netPeer'?'43':'44','Response Authenticator':'SYM(correlated failure response)','EAP-Message':'EAP-Failure','Failure check':variant},'The selected endpoint failure terminates this method; NAS has no accepted policy or released MSK.',{effects:[netPut('network.status',status),netPut('network.policy','denied')]});
    a.event('failure-check','Verify correlated failure and keep port closed','netNas','netNas','Local NAS enforcement',{'Result':'verified failure','Controlled port':'unauthorized'},'The NAS validates the failure response and never opens the port.',{held:[a.release(challenge,'netNas','challenge cache')],effects:[netPut('network.port','unauthorized')]});
    eap('failure-peer','Deliver EAP-Failure','netNas','netPeer',{'EAP Code':'Failure','EAP Identifier':detector==='netPeer'?'3':'4'},'EAP failure is a method outcome, not an exported bearer credential.');
    a.event('cleanup','Server releases failed method context','netServer','netServer','Local cleanup',{'Cleanup':'Only server TLS, ephemeral, transcript, challenge and any derived exporter copies'},'Remote peer holdings are not erased by this local cleanup.',{held:[a.release(tls,'netServer'),a.release(serverTranscript,'netServer'),a.release(serverEphemeral,'netServer'),a.release(challenge,'netServer'),...exported?[a.release(msk,'netServer'),a.release(emsk,'netServer')]:[]]});
    a.event('peer-cleanup','Peer consumes failure and releases own method context','netPeer','netPeer','Local cleanup',{'Cleanup':'Peer-only TLS, ephemeral, transcript and any derived exporter copies'},'Only peer-local transient state is removed; initial credential/trust stores remain.',{held:[a.release(peerTls,'netPeer'),a.release(transcript,'netPeer'),a.release(peerEphemeral,'netPeer'),...exported?[a.release(peerMsk,'netPeer'),a.release(peerEmsk,'netPeer')]:[]]});
    return finish();
  };
  eap('identity-request','EAP Identity request','netNas','netPeer',{'EAP Code':'Request','EAP Identifier':'1','Type':'Identity'},'The controlled port is unauthorized; EAPOL authentication traffic remains possible.');
  eap('identity-response','Privacy-friendly identity','netPeer','netNas',{'EAP Code':'Response','EAP Identifier':options.variant==='wrong-EAP-Identifier'?'9':'1','Identity':'anonymous@corp.example'},'An outer routing identity is not an authenticated certificate identity.');
  if(options.variant==='wrong-EAP-Identifier'){
    a.event('eap-correlation-check','Discard unexpected EAP response Identifier','netNas','netNas','Local EAP correlation',{'Expected EAP Identifier':'1','Received EAP Identifier':'9','Result':'discard'},'The response cannot advance another EAP request. No RADIUS or TLS method result is inferred.',{effects:[netPut('network.status','EAP response discarded')]});
    return a.finish();
  }
  radius('identity-backend','Relay identity to AAA','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'41','Request Authenticator':'SYM(RA41)','EAP-Message':'Response/Identity id 1 anonymous@corp.example','NAS-Identifier':'switch.corp.example'},'NAS is the RADIUS client; it does not terminate EAP-TLS.');
  if(options.variant==='invalid-Message-Authenticator'){
    const source=a.steps.at(-1),field=source.payload.find(field=>field.name==='Message-Authenticator');
    field.value='SYM(invalid HMAC-MD5)';
    const definition=a.definitions[field.attributeId];definition.example=field.value;
    source.attributeOperations.filter(op=>op.attributeId===field.attributeId).forEach(op=>op.value=field.value);
    a.inventory.artifacts.find(artifact=>artifact.artifactId===source.netPacket).representations[0].fields.find(item=>item.attributeId===field.attributeId).value=field.value;
    a.event('integrity-check','Detect invalid Message-Authenticator','netServer','netServer','Local RADIUS integrity',{'Message-Authenticator':'invalid','Result':'silent discard'},'Invalid integrity on an EAP-bearing classic request is discarded, not given an invented Access-Reject.',{effects:[netPut('network.status','request silently discarded')]});
    netObserve(a,'integrity-check',source.netPacket,'netServer','discarded','Invalid mandatory EAP-bearing RADIUS integrity.');
    a.event('timeout','NAS has no valid reply','netNas','netNas','Local scripted timeout',{'Knowledge':'no valid result'},'Timeout does not authenticate an identity or open a controlled port.');
    return a.finish();
  }
  a.event('identity-check','Validate identity request and create EAP context','netServer','netServer','Local RADIUS validation',{'Checks':'Configured NAS and valid Message-Authenticator; privacy-friendly claimed identity','State':'SYM(opaque context 1)'},'A valid envelope creates method context, not an authenticated identity. Server-issued State will correlate later method rounds.',{held:a.create(challenge,'netServer')});
  radius('start-backend','EAP-TLS Start challenge','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':options.variant==='wrong-RADIUS-Identifier'?'99':'41','Response Authenticator':'SYM(response41)','State':'SYM(opaque context 1)','EAP-Message':'Request/EAP-TLS id 2 S=1'},'Server issues an opaque State value; NAS correlates the challenge before relaying it.');
  if(options.variant==='wrong-RADIUS-Identifier'){
    a.event('correlation-check','Discard response for another RADIUS transaction','netNas','netNas','Local RADIUS correlation',{'Expected Identifier':'41','Received Identifier':'99','Trusted result':'none'},'An unmatched reply cannot advance the outstanding transaction or relay a trusted EAP request.',{effects:[netPut('network.reply','discarded'),netPut('network.status','reply discarded')]});
    a.event('cleanup','Server expires only its abandoned challenge','netServer','netServer','Local method cleanup',{'Cleanup':'server challenge context'},'A server-local expiry does not pretend the NAS trusted an invalid reply.',{held:[a.release(challenge,'netServer')]});
    return a.finish();
  }
  a.event('start-check','Validate challenge','netNas','netNas','Local RADIUS validation',{'Checks':'Response Authenticator, Message-Authenticator, outstanding id 41'},'Challenge integrity and request correlation are checked before EAP relay.');
  eap('start-peer','Relay EAP-TLS Start','netNas','netPeer',{'EAP Identifier':'2','EAP-TLS flags':'S=1'},'NAS relays EAP-TLS Start on EAPOL.');
  a.event('peer-start','Peer prepares ClientHello locally','netPeer','netPeer','Local TLS 1.3 preparation',{'Ephemeral private share':'HANDLE(peer ephemeral P-256 private share)','Public key_share':'SYM(peer P-256 public share)','Transcript':'SYM(handshake transcript generation 1)'},'Peer creates a private ephemeral share and its local transcript before sending only the public ClientHello.',{held:[...a.create(transcript,'netPeer'),...a.create(peerEphemeral,'netPeer')]});
  eap('clienthello-peer','TLS ClientHello','netPeer','netNas',{'EAP Identifier':'2','EAP-Response':'ClientHello TLS1.3 key_share P-256'},'The peer begins the TLS handshake, not an encrypted Wi-Fi data link.');
  radius('clienthello-backend','Relay ClientHello','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'42','Request Authenticator':'SYM(RA42)','State':'SYM(opaque context 1)','EAP-Message':'Response/EAP-TLS id2 ClientHello'},'NAS echoes State byte-for-byte. EAP-Message attributes concatenate in order; there is no User-Password.');
  if(['reordered-EAP-Message','fragment-sequence'].includes(options.variant)){
    const source=a.steps.at(-1),field=source.payload.find(field=>field.name==='EAP-Message');
    field.value=options.variant==='reordered-EAP-Message'?'SYM(EAP-Message attribute fragments reversed: TLS-body before EAP-header)':'SYM(EAP-TLS fragment M=1 without required length / unexpected fragment acknowledgement)';
    a.definitions[field.attributeId].example=field.value;
    source.attributeOperations.filter(op=>op.attributeId===field.attributeId).forEach(op=>op.value=field.value);
    a.inventory.artifacts.find(artifact=>artifact.artifactId===source.netPacket).representations[0].fields.find(item=>item.attributeId===field.attributeId).value=field.value;
    a.event('fragment-check','Reject malformed EAP method framing','netServer','netServer','Local EAP-TLS framing validation',{'Failing check':options.variant,'TLS transcript':'not accepted'},'RADIUS attribute concatenation order and TLS/EAP fragment flags/acknowledgements are distinct checks. This selected malformed method input fails before TLS key creation.',{effects:[netPut('network.status','malformed EAP method input')]});
    radius('failure','Selected malformed-method Access-Reject','netServer','netNas',{'Code':'Access-Reject','RADIUS Identifier':'42','Response Authenticator':'SYM(response42)','EAP-Message':'EAP-Failure id2'},'This is the selected method-framing failure branch, not a reply to invalid RADIUS integrity.');
    a.event('failure-check','NAS checks failure and keeps port closed','netNas','netNas','Local RADIUS validation',{'Result':'verified method failure','Controlled port':'unauthorized'},'No key or network session exists.',{held:[a.release(challenge,'netNas','challenge cache')]});
    eap('failure-peer','Deliver EAP-Failure','netNas','netPeer',{'EAP Code':'Failure','EAP Identifier':'2'},'Peer learns failure, not an accepted TLS result.');
    a.event('cleanup','Server releases failed challenge','netServer','netServer','Local cleanup',{'Cleanup':'challenge only; no TLS keys created'},'Only server-owned context is cleared.',{held:[a.release(challenge,'netServer')]});
    a.event('peer-cleanup','Peer releases abandoned local attempt','netPeer','netPeer','Local cleanup',{'Cleanup':'peer ephemeral share and transcript only'},'No TLS secret or exporter material had been created.',{held:[a.release(peerEphemeral,'netPeer'),a.release(transcript,'netPeer')]});
    return finish();
  }
  a.event('server-derive','Server validates request and derives handshake secrets','netServer','netServer','Local TLS 1.3 derivation',{'Envelope check':'Message-Authenticator, State and EAP id2 valid','Derivation':'ECDHE(local private share, received public share), HKDF handshake traffic secrets','Transcript':'ClientHello and locally generated ServerHello'},'Server validates the RADIUS request and locally derives its TLS handshake secrets. No traffic secret is transmitted.',{held:[...a.create(serverTranscript,'netServer'),...a.create(tls,'netServer')]});
  a.inventory.events[a.id+':server-derive'].effects.push(...a.create(serverEphemeral,'netServer'));
  radius('serverflight-backend','Server handshake flight','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':'42','State':'SYM(opaque context 1)','Response Authenticator':'SYM(response42)','EAP-Message':'Request/EAP-TLS id3 ServerHello; encrypted EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished'},'TLS1.3 certificate fields after ServerHello are encrypted to the peer, not readable by the pass-through NAS.',{representation:'wire'});
  a.event('serverflight-check','Validate AAA flight envelope','netNas','netNas','Local RADIUS validation',{'Checks':'Response correlation and both RADIUS authenticators valid'},'NAS validates only its adjacent RADIUS envelope; it cannot validate or decrypt the EAP-TLS certificate.');
  eap('serverflight-peer','Relay encrypted server flight','netNas','netPeer',{'EAP Identifier':'3','TLS records':'SYM(ServerHello + encrypted server certificate flight)'},'Peer receives the TLS records but has not yet trusted the server certificate.',{representation:'wire'});
  a.event('peer-derive','Peer derives handshake secrets and decrypts flight','netPeer','netPeer','Local TLS 1.3 derivation',{'Derivation':'ECDHE(local private share, received public share), HKDF handshake traffic secrets','Decoded certificate':'SYM(netServer certificate chain)'},'Peer derives its own endpoint secrets and decrypts the received certificate flight. A decrypted certificate is not yet a validated certificate.',{held:a.create(peerTls,'netPeer')});
  const serverProblem=options.failure==='server'?options.variant||'untrusted-issuer':'normal';
  a.event('server-check','Validate server certificate and Finished','netPeer','netPeer','Local TLS 1.3 validation',{'Issuer trust':serverProblem==='untrusted-issuer'?'untrusted issuer':'trusted configured issuer','Server identity':serverProblem==='wrong-server-name'?'unexpected.corp.example does not match radius.corp.example':'radius.corp.example matches configured name','EKU':'serverAuth','Certificate validity':serverProblem==='expired-server-cert'?'expired at fixture time 2026-10-21':'current at fixture time 2026-10-21','Revocation check':serverProblem==='revoked-server-cert'?'revoked':'checked good','CertificateVerify and Finished':options.failure==='server'?'not accepted after certificate check failed':'valid'},'The peer validates trust, configured server name, use, time, revocation, signature and Finished before sending its credential proof.',{effects:[netPut('network.serverIdentity',options.failure!=='server')]});
  netObserve(a,'server-check',a.id+':netServer-certificate:g1','netPeer',options.failure==='server'?'invalid':'valid',options.variant||'Issuer, configured name, use, validity, revocation, signature and Finished.');
  if(options.failure==='server')return fail('server','netPeer');
  eap('peerflight-peer','Encrypted peer authentication','netPeer','netNas',{'EAP Identifier':'3','TLS records':'SYM(encrypted peer Certificate, CertificateVerify, Finished)'},'Only certificate proof is sent. The peer private key never leaves its protected local store.',{representation:'wire'});
  radius('peerflight-backend','Relay peer authentication','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'43','Request Authenticator':'SYM(RA43)','State':'SYM(opaque context 1)','EAP-Message':'Response/EAP-TLS id3 encrypted peer certificate flight'},'NAS relays encrypted TLS records without learning the peer private fields.',{representation:'wire'});
  a.event('server-decrypt','Server decrypts received peer flight','netServer','netServer','Local TLS 1.3 record processing',{'Decoded certificate':'SYM(netPeer certificate chain)'},'Server uses its own local TLS secrets to decrypt the peer certificate flight; validation is the next boundary.');
  const clientProblem=options.failure==='client'?options.variant||'inappropriate-client-EKU':'normal';
  a.event('peer-check','Validate peer certificate and Finished','netServer','netServer','Local TLS 1.3 validation',{'RADIUS envelope':'Message-Authenticator, State and EAP id3 valid','Decoded certificate':'SYM(netPeer certificate chain)','Issuer trust':clientProblem==='bad-client-chain'?'untrusted client chain':'trusted configured issuer','EKU':clientProblem==='inappropriate-client-EKU'?'serverAuth only; required clientAuth absent':'clientAuth','Certificate validity':clientProblem==='expired-client-cert'?'expired at fixture time 2026-10-21':'current at fixture time 2026-10-21','Revocation check':clientProblem==='revoked-client-cert'?'revoked':'checked good','CertificateVerify and Finished':options.failure==='client'?'not accepted after certificate check failed':'valid','Authenticated identity':options.failure==='client'?'none':'alice@corp.example'},'EAP server decrypts the peer flight and authenticates the certificate identity. Cryptographic success is still not network authorization.',{effects:[netPut('network.peerIdentity',options.failure!=='client'),netPut('network.status',options.failure==='client'?'client certificate rejected':'identity verified')]});
  netObserve(a,'peer-check',a.id+':netPeer-certificate:g1','netServer',options.failure==='client'?'invalid':'valid',options.variant||'Client chain, use, time, revocation, signature and Finished.');
  if(options.failure==='client')return fail('client','netServer');
  const exporterFields={'Exporter':exporter,'Exporter label':'EXPORTER_EAP_TLS_Key_Material','Exporter context':'0x0D (one octet)','Exporter length':'128 octets','MSK':'octets 0-63 (64 octets)','EMSK':'octets 64-127 (64 octets)'};
  a.event('server-export','Server exporter derivation','netServer','netServer','Local RFC 9190 exporter',exporterFields,'Server derives separate MSK and EMSK locally using EAP Type 0x0D as the exporter context. Policy has not yet permitted MSK export.',{held:[...a.create(msk,'netServer'),...a.create(emsk,'netServer')]});
  a.event('peer-export','Peer exporter derivation','netPeer','netPeer','Local RFC 9190 exporter',exporterFields,'Peer independently derives equal key material in separate local objects with the same one-octet Type context. These keys were not transmitted from the server.',{held:[...a.create(peerMsk,'netPeer'),...a.create(peerEmsk,'netPeer')]});
  a.event('policy','Authorize authenticated identity','netServer','netServer','Local network policy',{'Policy':options.failure==='policy'?'deny: '+(options.variant||'unauthorized-group'):'employee wired permitted','Filter-Id':options.failure==='policy'?'none':'employee-wired'},'Authorization must permit the access result and MSK release; identity alone does not grant either.',{effects:[netPut('network.policy',options.failure==='policy'?'denied':'accepted'),netPut('network.logicalAuthentications',1)]});
  if(options.failure==='policy')return fail('policy','netServer',true);
  radius('protected-success-backend','Protected success indication','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':'43','Response Authenticator':'SYM(response43)','State':'SYM(opaque context 1)','EAP-Message':'Request/EAP-TLS id4 TLS application_data SYM(encrypted 0x00)'},'After validating the peer and policy, server sends the required TLS1.3 protected success indication.',{representation:'wire'});
  a.event('protected-success-check','Verify success challenge envelope','netNas','netNas','Local RADIUS validation',{'Checks':'RADIUS authenticators and id43 valid'},'NAS verifies this challenge without decrypting its protected success byte.');
  eap('protected-success-peer','Relay protected success','netNas','netPeer',{'EAP Identifier':'4','TLS application_data':'SYM(encrypted 0x00)'},'Peer receives protected success; the controlled port is still not authorized.',{representation:'wire'});
  a.event('protected-success-verify','Peer validates protected success','netPeer','netPeer','Local EAP-TLS validation',{'TLS application_data':'0x00 verified'},'The peer verifies protected success before acknowledging the EAP request.');
  eap('empty-peer','Empty EAP-TLS response','netPeer','netNas',{'EAP Identifier':'4','EAP-TLS data':'empty'},'Peer acknowledges the protected success request.');
  radius('empty-backend','Relay protected-success acknowledgement','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'44','Request Authenticator':'SYM(RA44)','State':'SYM(opaque context 1)','EAP-Message':'Response/EAP-TLS id4 empty'},'Server receives the required empty response before issuing EAP-Success.');
  radius('accept','Access-Accept with exported keys','netServer','netNas',{'Code':'Access-Accept','RADIUS Identifier':'44','Response Authenticator':'SYM(response44)','EAP-Message':'EAP-Success id4','Filter-Id':'employee-wired','MS-MPPE-Recv-Key':'SYM(protected first 32 MSK octets)','MS-MPPE-Send-Key':'SYM(protected second 32 MSK octets)'},'Only authorized MSK halves use RFC2548 protected carriers. EMSK and TLS traffic secrets are never exported to NAS.',{held:[a.acquire(msk,'netNas','AAA key inbox','wire')],effects:[netPut('network.reply','received-unverified')]});
  a.event('verify-reply','Validate result and recover MSK','netNas','netNas','Local RADIUS validation',{'Checks':'RADIUS id44; Response Authenticator; Message-Authenticator; EAP id4; supported policy','Key recovery':'RFC2548 MPPE salt and adjacent secret plus RA44'},'NAS verifies the correlated result before recovering the protected MSK halves; receipt alone did not open the port.',{held:[a.acquire(msk,'netNas','lower-layer key cache'),a.release(msk,'netNas','AAA key inbox','wire')],effects:[netPut('network.reply','verified'),netPut('network.mskReleased',true)]});
  const session=a.object('port-session','Authorized controlled port','netNas',['netNas'],'SYM(session-7 employee-wired)',{type:'session'});
  if(!options.wifi)a.inventory.bindings.push({path:'sessions.access',presentWhen:'exists',actorId:'netNas',artifactId:session,representationId:'plain',store:'local store'});
  a.event('enforce',options.wifi?'Complete bounded Wi-Fi EAP decision':'Authorize controlled port','netNas','netNas','Local 802.1X enforcement',{'Controlled port':options.wifi?'EAP decision only; no installed protected link':'authorized','Filter-Id':'employee-wired','MACsec':'not established','Wi-Fi protected link':'not established','Internet reachability':'not asserted'},options.wifi?'EAP access decision complete; Wi-Fi link establishment not shown. No secure-association/key-installation handshake or usable protected traffic is claimed.':'Only now the wired controlled port is authorized. EAP-TLS did not establish MACsec or prove Internet reachability.',{held:options.wifi?[]:a.create(session,'netNas'),effects:[netPut('network.port',options.wifi?'decision-only':'authorized'),netPut('network.status',options.wifi?'EAP access decision complete; Wi-Fi link establishment not shown':'port authorized'),...options.wifi?[]:[netPut('sessions.access',{id:'session-7',active:true,filter:'employee-wired'})]]});
  a.inventory.events[a.id+':enforce'].effects.push(a.release(challenge,'netNas','challenge cache'));
  eap('success-peer','EAP-Success to peer','netNas','netPeer',{'EAP Code':'Success','EAP Identifier':'4'},'NAS delivers the EAP result; this is not a bearer Access-Accept token.');
  a.event('cleanup','Server releases method and forwarding context','netServer','netServer','Local cleanup',{'Cleanup':'Server TLS transcript, traffic secrets, EMSK and AAA MSK forwarding copy released'},'Server cleanup affects only server holdings, not independent peer or NAS caches.',{held:[a.release(tls,'netServer'),a.release(serverTranscript,'netServer'),a.release(emsk,'netServer'),a.release(msk,'netServer')]});
  a.inventory.events[a.id+':cleanup'].effects.push(a.release(challenge,'netServer'),a.release(serverEphemeral,'netServer'));
  a.event('peer-cleanup','Peer consumes EAP result and releases method context','netPeer','netPeer','Local cleanup',{'EAP result':'Success id4 consumed','Cleanup':'Peer TLS traffic secrets, transcript and EMSK released; separate local MSK cache retained'},'Only the peer releases its own method-layer holdings. The final EAP-Success is explicitly consumed here.',{held:[a.release(peerTls,'netPeer'),a.release(transcript,'netPeer'),a.release(peerEmsk,'netPeer')]});
  a.inventory.events[a.id+':peer-cleanup'].effects.push(a.release(peerEphemeral,'netPeer'));
  return finish();
}
function netFinishEapInventory(a,{invalidServer=false,invalidPeer=false}={}){
  const exists=key=>Object.hasOwn(a.inventory.events,a.id+':'+key);
  const object=key=>a.id+':'+key+':g1';
  const expose=(key,objectKey,receiver,store,representationId='plain')=>{
    if(!exists(key))return;
    const artifactId=object(objectKey),event=a.inventory.events[a.id+':'+key];
    event.effects.push(a.acquire(artifactId,receiver,store,representationId));
    if(event.messages.length)event.messages[0].objects.push({artifactId,representationId});
  };
  const release=(key,objectKey,actor,store,representationId='plain')=>{
    if(exists(key))a.inventory.events[a.id+':'+key].effects.push(a.release(object(objectKey),actor,store,representationId));
  };
  expose('start-backend','eap-context','netNas','pending challenge');
  expose('start-check','eap-context','netNas','challenge cache');
  release('start-check','eap-context','netNas','pending challenge');
  expose('serverflight-backend','netServer-certificate','netNas','TLS relay','wire');
  expose('serverflight-peer','netServer-certificate','netPeer','TLS certificate inbox','wire');
  expose('peer-derive','netServer-certificate','netPeer','decrypted certificate inbox');
  if(!invalidServer)expose('server-check','netServer-certificate','netPeer','validated peer certificates');
  release('server-check','netServer-certificate','netPeer','decrypted certificate inbox');
  release('server-check','netServer-certificate','netPeer','TLS certificate inbox','wire');
  release('serverflight-peer','netServer-certificate','netNas','TLS relay','wire');
  expose('peerflight-peer','netPeer-certificate','netNas','TLS relay','wire');
  expose('peerflight-backend','netPeer-certificate','netServer','TLS certificate inbox','wire');
  expose('server-decrypt','netPeer-certificate','netServer','decrypted certificate inbox');
  if(!invalidPeer)expose('peer-check','netPeer-certificate','netServer','validated peer certificates');
  release('peer-check','netPeer-certificate','netServer','decrypted certificate inbox');
  release('peer-check','netPeer-certificate','netServer','TLS certificate inbox','wire');
  release('peerflight-backend','netPeer-certificate','netNas','TLS relay','wire');
  if(exists('accept')){
    const packet=a.steps.find(step=>step.id===a.id+':accept');
    netExactCarrier(a,packet,object('msk'),'wire',field=>field.name.startsWith('MS-MPPE-'));
    netObserve(a,'verify-reply',object('msk'),'netNas','valid','Exact RFC2548 carrier recovery after request/response correlation and integrity checks.');
  }
  return a.finish();
}
function netTransportCertificateObjects(a){
  return Object.fromEntries(['netNas','netServer'].map(actor=>[actor,a.object(actor+'-outer-certificate','Outer TLS transport certificate',actor,['netNas','netServer'],'SYM('+actor+' outer transport certificate chain)',{initial:true,type:'certificate',protectedValue:'SYM(encrypted '+actor+' outer transport certificate chain)'})]));
}
function netTransportCertificateBindings(a,certificates,{serverFlight,clientFlight,nasCheck,serverCheck,nasValidation=nasCheck,nasValid=true}){
  const attach=(sourceKey,artifactId,name,representation,actor,store)=>{
    const step=a.steps.find(step=>step.id===a.id+':'+sourceKey);
    if(!step)return;
    const artifact=a.inventory.artifacts.find(item=>item.artifactId===artifactId);
    const rep=artifact.representations.find(item=>item.representationId===representation);
    const value=rep.fields[0].value,attributeId='netTransport_'+sourceKey.replace(/-/g,'_')+'_'+a.id.replace(/-/g,'_')+'_'+representation;
    a.definitions[attributeId]={...labAttribute(name,representation==='wire'?'TLS1.3 encrypted transport Certificate bytes, not the decoded public certificate or private key.':'Certificate fields decoded only by the legitimate transport TLS endpoint before the authored identity/trust check.',artifact.creator,'Authenticate the configured adjacent transport peer, distinct from an inner EAP credential.',value,'RFC 8446','https://www.rfc-editor.org/rfc/rfc8446'),section:'4.4.2',readers:[step.from,step.to]};
    step.fields.push(attributeId);step.payload.push(labP(name,value,a.definitions[attributeId].meaning,attributeId));
    const occurrence={attributeId,instanceId:artifactId,fieldPath:'Certificate',creator:artifact.creator,holders:[step.from,step.to],inspectors:[step.from,step.to],representation,value,sourceEventId:step.id,exactValueRef:artifactId+':Certificate:'+representation};
    step.attributeOperations.push(...(step.from===step.to?[{...occurrence,kind:'inspect',actorId:step.from}]:[{...occurrence,kind:'send',actorId:step.from},{...occurrence,kind:'receive',actorId:step.to}]));
    if(step.netPacket)a.inventory.artifacts.find(item=>item.artifactId===step.netPacket).representations[0].fields.push({attributeId,name,value,readableBy:[step.from,step.to]});
    if(representation==='wire')rep.fields=[{attributeId,name,value,readableBy:['netNas','netServer']}];
    a.inventory.events[step.id].effects.push(a.acquire(artifactId,actor,store,representation));
    if(step.from!==step.to)a.inventory.events[step.id].messages[0].objects.push({artifactId,representationId:representation});
  };
  attach(serverFlight,certificates.netServer,'Protected transport server Certificate','wire','netNas','transport certificate inbox');
  const nasCertificateStore=nasValidation===nasCheck?(nasValid?'validated transport certificates':'rejected transport certificate'):'decoded transport certificates';
  attach(nasCheck,certificates.netServer,'Decoded transport server Certificate','plain','netNas',nasCertificateStore);
  attach(clientFlight,certificates.netNas,'Protected transport client Certificate','wire','netServer','transport certificate inbox');
  attach(serverCheck,certificates.netNas,'Decoded transport client Certificate','plain','netServer','validated transport certificates');
  for(const [decodedAt,checkedAt,artifactId,actor] of [[nasCheck,nasValidation,certificates.netServer,'netNas'],[serverCheck,serverCheck,certificates.netNas,'netServer']]){
    if(a.inventory.events[a.id+':'+decodedAt])a.inventory.events[a.id+':'+decodedAt].effects.push(a.release(artifactId,actor,'transport certificate inbox','wire'));
    if(a.inventory.events[a.id+':'+checkedAt]){
      if(decodedAt!==checkedAt)a.inventory.events[a.id+':'+checkedAt].effects.push(a.release(artifactId,actor,nasCertificateStore),a.acquire(artifactId,actor,nasValid?'validated transport certificates':'rejected transport certificate'));
      netObserve(a,checkedAt,artifactId,actor,actor==='netNas'&&!nasValid?'invalid':'valid','Exact configured outer transport certificate validation; no inner EAP credential substitution.');
    }
  }
}
function netProfile(name,numbers,{status='Standards Track',algorithms=[],transports=['RADIUS/UDP 1812'],completion='Verified supported authorization is applied by the NAS',assumptions=[]}={}){
  const sources=NETWORKLAB_SOURCES.filter(source=>{
    const number=Number(source.standard.slice(4));
    return numbers.includes(number)||number===8446&&numbers.some(value=>[9190,6614,9765].includes(value))||number===5246&&numbers.includes(5216)||number===3580&&numbers.some(value=>[9190,5216].includes(value));
  });
  return {id:'net-'+name.toLowerCase().replace(/[^a-z0-9]+/g,'-')+'-v1',name,version:'1',implementation:'Offline documented teaching model; no live interoperability run',publicationStatus:status,supportStatus:'Standards illustration, not a product support claim',algorithms,transports,assumptions:['Synthetic symbolic values; no runtime crypto',...assumptions],completion,sources,cryptoDetail:'SYM(...) denotes symbolic wire/derived material; HANDLE(...) denotes a local protected reference, never actual secret bytes.'};
}
function netObserve(a,key,artifactId,actorId,result,detail){
  a.inventory.events[a.id+':'+key].effects.push({op:'observe',artifactId,actorId,kind:'verification',result,detail});
}
function netUseAuthoredFields(a,artifactId,representationId,step,readers){
  a.inventory.artifacts.find(item=>item.artifactId===artifactId).representations.find(rep=>rep.representationId===representationId).fields=step.payload.map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:[...readers]}));
}
function netExactCarrier(a,step,artifactId,representationId,predicate){
  const artifact=a.inventory.artifacts.find(item=>item.artifactId===artifactId);
  artifact.representations.find(rep=>rep.representationId===representationId).fields=step.payload.filter(predicate).map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:[step.from,step.to]}));
  a.inventory.events[step.id].messages[0].objects.push({artifactId,representationId});
}
function netPasswordChoice(slug,title,{reject=false,challenge=false,invalidTotp=false,retry=false,variant='normal'}={}){
  const a=netAuthor(slug,title,challenge?'totp':'pap',{actorIds:['netPeer',...(challenge?['netOtp']:[]),'netNas','netServer'],meta:{family:retry?'network-lifecycle':'network-access'},profileMetadata:netProfile(challenge?'Illustrative password plus TOTP policy':'Classic PAP-style password',[2865,5080,...(challenge?[6238]:[])],{status:challenge?'Standards Track RADIUS; Informational TOTP; illustrative composition policy':'Standards Track',algorithms:['RFC2865 MD5 password hiding and response integrity',...(challenge?['TOTP HMAC-SHA-1, 30-second step, current step only']:[])],assumptions:['Classic UDP is a legacy comparison, not a recommended new deployment','Password database is local; no fictional backend authentication']})});
  a.object('radius-secret','Adjacent NAS-AAA secret','netNas',['netNas','netServer'],'HANDLE(NAS-AAA secret)',{initial:true,holders:['netNas','netServer'],type:'shared-secret'});
  a.object('account-record','Local account verifier and policy','netServer',['netServer'],'HANDLE(alice local password record and allowed NAS ports)',{initial:true,type:'account-record'});
  const password=a.object('password','Synthetic password input','netPeer',['netPeer','netNas','netServer'],reject?'SYM(incorrect password)':'SYM(alice password)',{initial:true,type:'credential',protectedValue:'SYM(hidden password blocks)'});
  const context=challenge?a.object('challenge-context','Opaque TOTP challenge State','netServer',['netServer','netNas'],'SYM(challenge1)',{type:'challenge-context'}):null;
  let seed,otp;
  if(challenge){
    seed=a.object('totp-seed','TOTP enrollment seed','netOtp',['netOtp','netServer'],'HANDLE(unique Alice TOTP seed)',{initial:true,holders:['netOtp','netServer'],type:'secret'});
    otp=a.object('totp-code','One-time current-step input','netOtp',['netOtp','netPeer','netNas','netServer'],invalidTotp?'SYM(invalid or expired TOTP)':'SYM(valid current-step TOTP)',{type:'credential',protectedValue:'SYM(hidden TOTP response)'});
  }
  const input=a.event('input','Local password entry','netPeer','netNas','Local credential input',{'User-Name':'alice@corp.example','Password':reject?'SYM(incorrect password)':'SYM(alice password)'},'Declared local input gives the NAS this password; no EAP method is implied.',{channel:'human',held:[a.acquire(password,'netNas')]});
  a.inventory.events[input.id].messages[0].objects.push({artifactId:password,representationId:'plain'});
  const requestFields={'Code':'1 Access-Request','Identifier':'41','Request Authenticator':'SYM(RA41)','User-Name':'alice@corp.example','User-Password':'SYM(hidden password blocks)','NAS-Identifier':'switch.corp.example','NAS-Port':'7'};
  const request=a.event('request','Access-Request','netNas','netServer','RADIUS/UDP',requestFields,'NAS sends one password authentication transaction.',{held:[a.acquire(password,'netServer','credential scratch','wire')]});
  netExactCarrier(a,request,password,'wire',field=>field.name==='User-Password');
  a.event(challenge?'password-check':'validate','Validate password and service policy','netServer','netServer','Local RADIUS validation',{'Password check':reject?'invalid':'valid','NAS association':'configured adjacent secret','Policy':reject?'reject':'employee-wired permitted'},'Server recovers only the hidden password field and evaluates its local account and NAS policy.',{held:[a.acquire(password,'netServer','credential scratch'),a.release(password,'netServer','credential scratch','wire')],effects:[netPut('network.peerIdentity',!reject),netPut('network.policy',reject?'rejected':challenge?'pending':'accepted'),netPut('network.logicalAuthentications',1)]});
  netObserve(a,challenge?'password-check':'validate',password,'netServer',reject?'invalid':'valid','Password and configured NAS policy validation, not transport admission.');
  let failed=reject,replyIdentifier='41',requestAuthenticator='SYM(RA41)';
  if(challenge){
    a.event('challenge-create','Create factor challenge context','netServer','netServer','Local illustrative MFA policy',{'State':'SYM(challenge1)','Factor window':'30 seconds; accept current fixture step once'},'Password success alone does not authorize access. This password/TOTP composition is authored server policy.',{held:a.create(context,'netServer'),effects:[netPut('network.challenge','SYM(challenge1)')]});
    a.event('challenge','Access-Challenge','netServer','netNas','RADIUS/UDP',{'Code':'11 Access-Challenge','Identifier':'41','Response Authenticator':'SYM(response41)','State':'SYM(challenge1)','Reply-Message':'Enter current synthetic TOTP'},'The NAS receives a correlated challenge and opaque State, not a TOTP seed.',{held:[a.acquire(context,'netNas','challenge inbox')]});
    a.event('challenge-check','Verify challenge response','netNas','netNas','Local RADIUS validation',{'Checks':'Identifier41 and Response Authenticator bound to RA41 valid','State':'SYM(challenge1)'},'NAS validates the challenge before prompting; it preserves State without interpreting it.',{held:[a.acquire(context,'netNas','challenge cache'),a.release(context,'netNas','challenge inbox')]});
    a.event('prompt','Prompt for second factor','netNas','netPeer','Local user prompt',{'Reply-Message':'Enter current synthetic TOTP'},'NAS displays the server prompt; this is local human input, not an EAP packet.',{channel:'human'});
    a.event('factor-create','Authenticator computes TOTP locally','netOtp','netOtp','Local RFC6238 derivation',{'Time step':'30 seconds','Moving factor':'floor((fixture Unix time - T0)/30)','TOTP':invalidTotp?'SYM(invalid or expired TOTP)':'SYM(valid current-step TOTP)'},'The authenticator uses its enrollment seed locally. The seed is never sent to NAS.',{held:a.create(otp,'netOtp')});
    const display=a.event('factor-display','Display current code to Alice','netOtp','netPeer','Local authenticator display',{'TOTP':invalidTotp?'SYM(invalid or expired TOTP)':'SYM(valid current-step TOTP)'},'Only the short-lived code, not the enrollment seed, leaves the authenticator component.',{channel:'local-ipc',held:[a.acquire(otp,'netPeer')]});
    a.inventory.events[display.id].messages[0].objects.push({artifactId:otp,representationId:'plain'});
    a.event('factor-input','Local TOTP input','netPeer','netNas','Local credential input',{'TOTP':invalidTotp?'SYM(invalid or expired TOTP)':'SYM(valid current-step TOTP)'},'Only the short-lived TOTP response is supplied to NAS.',{channel:'human',held:[a.acquire(otp,'netNas')]});
    const state=variant==='missing-State'?undefined:variant==='altered-State'?'SYM(challenge altered)':'SYM(challenge1)';
    const continuation=a.event('continuation','Challenge response Access-Request','netNas','netServer','RADIUS/UDP',{'Code':'1 Access-Request','Identifier':'42','Request Authenticator':'SYM(RA42)','User-Name':'alice@corp.example',...(state===undefined?{}:{State:state}),'User-Password':'SYM(hidden TOTP response)','NAS-Identifier':'switch.corp.example'},'The response is another packet under the same logical authentication; the NAS must echo the exact State.',{held:[a.acquire(otp,'netServer','factor scratch','wire')]});
    netExactCarrier(a,continuation,otp,'wire',field=>field.name==='User-Password');
    failed=invalidTotp||variant==='missing-State'||variant==='altered-State';
    a.event('factor-check','Validate State and TOTP once','netServer','netServer','Local illustrative factor policy',{'State check':state==='SYM(challenge1)'?'unchanged':'invalid or missing','TOTP check':state!=='SYM(challenge1)'?'not evaluated':invalidTotp?'invalid or expired':'valid current unconsumed step','Policy':failed?'reject and terminate challenge':'accept employee-wired'},'Only the issued context, valid unconsumed current-step TOTP and access policy can authorize this fixture.',{held:[a.acquire(otp,'netServer','factor scratch'),a.release(otp,'netServer','factor scratch','wire'),a.release(context,'netServer')],effects:[netPut('network.factor',failed?'invalid':'valid'),netPut('network.policy',failed?'rejected':'accepted'),netPut('network.challenge',null)]});
    if(state==='SYM(challenge1)')netObserve(a,'factor-check',otp,'netServer',invalidTotp?'invalid':'valid','Validate the current unconsumed TOTP only after exact issued State correlation.');
    else netObserve(a,'factor-check',context,'netServer','invalid','Issued challenge State is missing or altered; the supplied TOTP is not evaluated.');
    a.steps.find(step=>step.id===a.id+':factor-check').protocolEffects.push(netPut('tokenConsumption.netTotpCurrentStep',!failed));
    a.event('factor-cleanup','Release validation scratch','netServer','netServer','Local cleanup',{'Cleanup':'Password and TOTP scratch released; enrollment seed retained'},'The validator retains enrollment configuration, not reusable request copies.',{held:[a.release(password,'netServer','credential scratch'),a.release(otp,'netServer','factor scratch')]});
    replyIdentifier='42';requestAuthenticator='SYM(RA42)';
  }else a.event('credential-cleanup','Release password validation scratch','netServer','netServer','Local cleanup',{'Cleanup':'request password scratch released'},'A local server cleanup removes only its own decoded request copy.',{held:[a.release(password,'netServer','credential scratch')]});
  const replyFields={'Code':failed?'3 Access-Reject':'2 Access-Accept','Identifier':replyIdentifier,'Response Authenticator':'SYM(response bound to '+requestAuthenticator+')',...failed?{}:{'Filter-Id':'employee-wired','Session-Timeout':'3600'}};
  const wireReplyFields={...replyFields};
  if(variant==='invalid-response-authenticator')wireReplyFields['Response Authenticator']='SYM(invalid response authenticator)';
  if(variant==='wrong-recipient')wireReplyFields['Response Authenticator']='SYM(response for another NAS secret and request)';
  if(variant==='wrong-transaction')wireReplyFields.Identifier='99';
  if(variant==='timeout-is-not-reject'){
    a.event('lost-reply','Server rejection not delivered','netServer','netServer','Teaching-only network loss',{'Undelivered result':'Access-Reject for invalid password'},'Server knows the credential failed; NAS has no trusted rejection receipt.');
    a.event('timeout','NAS observes no valid response','netNas','netNas','Local scripted timeout',{'Knowledge':'unknown remote outcome','Controlled port':'unauthorized'},'A timeout is not a trusted Access-Reject and never activates service.',{held:[a.release(password,'netNas')],effects:[netPut('network.status','timeout, no trusted result')]});
    return a.finish();
  }
  if(retry){
    const cached=a.object('cached-response','Duplicate cache original response','netServer',['netServer'],JSON.stringify(replyFields),{type:'transaction'});
    a.event('cache','Cache original logical result','netServer','netServer','Local RFC5080 duplicate handling',{'Cache key':'NAS source IP + source UDP port + Identifier41 + RA41','Cached response':'SYM(original Access-Accept)'},'Cache the one logical authentication result before a scripted lost wire attempt.',{held:a.create(cached,'netServer')});
    a.event('lost-reply','Scripted original response loss','netServer','netServer','Teaching-only network loss',{'Wire attempt':'response attempt1 dropped before NAS delivery','Identifier':'41'},'This disclosure is not a delivered protocol packet. NAS has neither reply knowledge nor admission.',{effects:[netPut('network.reply','none')]});
    a.event('retry-timeout','NAS fixed retry deadline','netNas','netNas','Local scripted timeout',{'Elapsed':'2 seconds fixed teaching schedule','Outstanding transaction':'id41 RA41'},'A sender timeout does not undo the server decision or authenticate another session.');
    a.event('retry-request','Retransmit identical Access-Request','netNas','netServer','RADIUS/UDP',requestFields,'Attempt2 has a distinct wire occurrence under the same transaction and identical request attributes.');
    a.event('duplicate-check','Return cached result without processing login again','netServer','netServer','Local RFC5080 duplicate handling',{'Duplicate':'same source/port/id41/RA41, valid request','Logical authentication count':'1'},'Valid cached duplicate selects the original response; no repeated password check, logical login or session creation.',{effects:[netPut('network.logicalAuthentications',1)]});
  }
  if(variant==='late-reply')a.event('advance-transaction','Expire old NAS transaction before late response','netNas','netNas','Local transaction lifecycle',{'Old outstanding transaction':'id41 expired','New outstanding transaction':'id99; no result yet'},'A late valid reply for id41 cannot advance the unrelated currently outstanding id99.',{effects:[netPut('network.activeTransaction','99')]});
  a.event(failed?'reject':'accept',failed?'Access-Reject':'Access-Accept','netServer','netNas','RADIUS/UDP',wireReplyFields,failed?'Server rejects this authentication; receipt still requires correlation verification.':variant==='normal'?'The accepted response arrives pending validation; the NAS has not activated service.':'Controlled response-input fixture: '+variant+'. The stored original logical result is unchanged.',{effects:[netPut('network.reply','received-unverified')]});
  const invalidReply=['invalid-response-authenticator','wrong-recipient','wrong-transaction','late-reply'].includes(variant);
  a.event('verify-reply','Check response transaction and integrity','netNas','netNas','Local RADIUS validation',{'Checks':invalidReply?'selected '+variant+' fails':'Identifier, outstanding NAS transaction and Response Authenticator valid'},invalidReply?'Invalid or stale reply is discarded; it cannot advance another transaction.':'Only the intended NAS validates and consumes this transaction response.',{effects:[netPut('network.reply',invalidReply?'discarded':'verified')]});
  if(!failed&&!invalidReply){
    const session=a.object('service-session','Authorized NAS service','netNas',['netNas'],'SYM(session7 employee-wired)',{type:'session'});
    a.inventory.bindings.push({path:'sessions.access',presentWhen:'exists',actorId:'netNas',artifactId:session,representationId:'plain',store:'local store'});
    a.event('enforce','Apply accepted NAS policy','netNas','netNas','Local NAS enforcement',{'Service':'active','Filter-Id':'employee-wired'},'Only verified supported policy activates one service. No browser token or Kerberos ticket is manufactured.',{held:a.create(session,'netNas'),effects:[netPut('network.port','authorized'),netPut('network.status','port authorized'),netPut('sessions.access',{id:'session-7',active:true,filter:'employee-wired'})]});
  }else a.event('enforce','Keep NAS service unauthorized','netNas','netNas','Local NAS enforcement',{'Service':'unauthorized','Reason':invalidReply?'reply discarded':'credential/factor policy rejected'},'No authorized session exists. A rejection is not a timeout, and an invalid reply is not a trusted rejection.',{effects:[netPut('network.port','unauthorized'),netPut('network.status',invalidReply?'reply discarded':'authentication rejected')]});
  a.event('nas-cleanup','NAS releases input and challenge context','netNas','netNas','Local cleanup',{'Cleanup':'NAS password and factor scratch released'},'NAS removes only its own credential/challenge copies; enrollment credentials remain with their owners.',{held:[a.release(password,'netNas'),...challenge?[a.release(otp,'netNas'),a.release(context,'netNas','challenge cache')]:[]]});
  if(challenge){
    a.event('factor-peer-cleanup','Alice clears copied factor response','netPeer','netPeer','Local input cleanup',{'Cleanup':'copied TOTP response only'},'The user input copy is cleared locally; NAS and validator copies have their own independent release events.',{held:[a.release(otp,'netPeer')]});
    a.event('factor-code-cleanup','Authenticator clears its displayed response','netOtp','netOtp','Local authenticator cleanup',{'Cleanup':'short-lived displayed code, not enrollment seed'},'The authenticator keeps the seed private; successful validation consumed the permitted step once.',{held:[a.release(otp,'netOtp')]});
  }
  return a.finish();
}
function netAccounting({variant='normal'}={}){
  const a=netAuthor('radius-accounting-lifecycle','Accounting Start, Interim-Update and Stop','accounting',{actorIds:['netNas','netCollector'],meta:{family:'network-lifecycle',protocol:'RADIUS Accounting',standard:'RFC 2866 / RFC 2869'},profileMetadata:netProfile('Correlated accounting lifecycle',[2866,2869,5080],{status:'Informational base with Standards Track updates',algorithms:['Classic accounting Request/Response Authenticator'],transports:['RADIUS/UDP 1813'],completion:'Start, Interim and Stop stored once; sender delivery acknowledgements tracked separately'}),initialState:{network:{port:'authorized',status:'accounting delivery pending',accounting:{stored:[],acked:[]}},sessions:{access:{id:'session-7',active:true,filter:'employee-wired'}}}});
  a.object('accounting-secret','NAS-collector shared secret','netNas',['netNas','netCollector'],'HANDLE(NAS-collector secret)',{initial:true,holders:['netNas','netCollector'],type:'shared-secret'});
  const session=a.object('existing-service','Existing authorized service','netNas',['netNas'],'SYM(session-7 employee-wired)',{initial:true,type:'session'});
  a.inventory.bindings.push({path:'sessions.access.active',equals:true,actorId:'netNas',artifactId:session,representationId:'plain',store:'local store'});
  const stored=[],acked=[];
  for(const [key,status,id,time,input,output,packetsIn,packetsOut] of [['start','Start','61',0,0,0,0,0],['interim','Interim-Update','62',30,1000,2000,10,20],['stop','Stop','63',60,3000,5000,30,50]]){
    if(key==='stop')a.event('local-stop','Terminate service locally','netNas','netNas','Local NAS enforcement',{'Session':'session-7','Cause':'User-Request'},'Service ends locally before Accounting Stop. Collector receipt is not the cause of service termination.',{held:[a.release(session,'netNas')],effects:[netPut('sessions.access.active',false),netPut('network.port','unauthorized')]});
    const values={'Code':'4 Accounting-Request','Identifier':id,'Request Authenticator':'SYM(accounting MD5 Code+id+Length+zero16+attributes+secret)','NAS-Identifier':'switch.corp.example','Acct-Session-Id':'session-7','Acct-Status-Type':status,'Acct-Delay-Time':'0',...(key==='start'?{}:{'Acct-Session-Time':String(time),'Acct-Input-Octets':String(input),'Acct-Output-Octets':String(output),'Acct-Input-Packets':String(packetsIn),'Acct-Output-Packets':String(packetsOut)}),...(key==='stop'?{'Acct-Terminate-Cause':'1 User-Request'}:{})};
    const record=a.object(key+'-record',status+' accounting record','netNas',['netNas','netCollector'],JSON.stringify(values),{type:'accounting-record'});
    a.event(key+'-create','Create '+status+' record','netNas','netNas','Local accounting record',values,'One stable Acct-Session-Id correlates cumulative counters; record lifetime is independent from session lifetime.',{held:a.create(record,'netNas')});
    netUseAuthoredFields(a,record,'plain',a.steps.at(-1),['netNas','netCollector']);
    const request=a.event(key,'Send '+status+' accounting','netNas','netCollector','RADIUS Accounting/UDP',values,'Collector receives an unverified record; no acknowledgement knowledge is created at NAS.',{held:[a.acquire(record,'netCollector','accounting inbox')],effects:[netPut('network.status','accounting delivery pending')]});
    request.layers=[{protocol:'RADIUS Accounting',transport:'UDP 1813',from:'netNas',to:'netCollector',protection:'RFC2866 Request Authenticator with NAS-collector secret',keyRef:a.id+':accounting-secret:g1'}];
    a.inventory.events[request.id].messages[0].objects.push({artifactId:record,representationId:'plain'});
    stored.push(status);
    a.event(key+'-store','Validate and store '+status+' once','netCollector','netCollector','Local accounting validation',{'Check':'Configured NAS, valid Request Authenticator','Record key':'session-7 / '+status,'Stored status':status},'Collector acknowledges only after successfully recording the event. Duplicate logical status records are not counted twice.',{held:[a.acquire(record,'netCollector','durable accounting store'),a.release(record,'netCollector','accounting inbox')],effects:[netPut('network.accounting.stored',[...stored])]});
    netObserve(a,key+'-store',record,'netCollector','valid','Authenticated accounting record stored under one session/status identity.');
    if(key==='start'&&variant==='lost-accounting-response'){
      a.event('lost-accounting-response','Scripted accounting acknowledgement loss','netCollector','netCollector','Teaching-only network loss',{'Response':'Accounting-Response id61 dropped'},'Collector has stored Start, while NAS still has delivery pending; network access is not revoked.');
      a.event('accounting-timeout','NAS accounting retry deadline','netNas','netNas','Local accounting timer',{'Delivery':'pending','Acct-Delay-Time retry':'2 seconds'},'Accounting retry changes delay bookkeeping, not the logical event or active session.');
    }
    if(key==='start'&&['lost-accounting-response','duplicate-accounting-request'].includes(variant)){
      a.event('accounting-retry','Retransmit Start with updated delay','netNas','netCollector','RADIUS Accounting/UDP',{...values,'Identifier':'64','Acct-Delay-Time':'2','Request Authenticator':'SYM(recomputed accounting authenticator for updated delay)'},'Accounting retry follows its own rules; updated Acct-Delay-Time requires recomputed authenticator and distinct packet correlation.');
      a.event('accounting-duplicate-check','Recognize already recorded Start','netCollector','netCollector','Local accounting duplicate handling',{'Session':'session-7','Logical event':'Start already stored','Record count':'1'},'Deduplicate the logical record without double-counting counters or creating another session.',{effects:[netPut('network.accounting.stored',['Start'])]});
    }
    const ack=a.event(key+'-ack','Accounting-Response '+status,'netCollector','netNas','RADIUS Accounting/UDP',{'Code':'5 Accounting-Response','Identifier':key==='start'&&['lost-accounting-response','duplicate-accounting-request'].includes(variant)?'64':id,'Response Authenticator':'SYM(response bound to corresponding Accounting-Request)'},'A reply in flight is not sender acknowledgement knowledge.');
    ack.layers=[{protocol:'RADIUS Accounting',transport:'UDP 1813',from:'netCollector',to:'netNas',protection:'RFC2866 correlated Response Authenticator',keyRef:a.id+':accounting-secret:g1'}];
    acked.push(status);
    a.event(key+'-ack-check','Verify '+status+' delivery acknowledgement','netNas','netNas','Local accounting validation',{'Check':'Expected response Identifier, NAS association and Response Authenticator valid','Acknowledged':status},'Only a valid correlated Accounting-Response changes NAS delivery knowledge. It does not create or revoke access.',{effects:[netPut('network.accounting.acked',[...acked]),netPut('network.status',key==='stop'?'session disconnected; accounting acknowledged':'accounting acknowledged')]});
  }
  return a.finish();
}
function netDynamic(slug,title,{disconnect=false,nak=false,variant='normal'}={}){
  const absent=nak&&disconnect||variant==='session-not-found'||variant==='stale-session';
  const discarded=['untrusted-client','invalid-request-authenticator','stale-Event-Timestamp'].includes(variant);
  const error=variant==='wrong-recipient'?403:absent?503:variant==='unsupported-attribute'?401:405;
  const a=netAuthor(slug,title,'dynamic',{actorIds:['netController','netNas',...(disconnect&&!nak?['netCollector']:[])],meta:{family:'network-lifecycle',protocol:'RADIUS Dynamic Authorization',standard:'RFC 5176'},profileMetadata:netProfile('Trusted existing-session '+(disconnect?'Disconnect':'CoA'),[5176,2866],{status:'Informational',algorithms:['Classic dynamic Request/Response Authenticator','Event-Timestamp and duplicate cache'],transports:['UDP 3799',...(disconnect&&!nak?['UDP 1813 accounting']:[])],assumptions:['Configured trusted Dynamic Authorization Client','Selectors are NAS-Identifier and Acct-Session-Id, separate from requested Filter-Id','Fixed 30-second timestamp and duplicate-detection window; no claim this legacy integrity is recommended new deployment'],completion:'Recipient action precedes ACK; sender learns only on valid correlated ACK receipt'}),initialState:{network:{port:absent?'unauthorized':'authorized',controllerKnowledge:'pending',logicalOperations:0,accounting:{stored:[],acked:[]}},sessions:{...absent?{}:{access:{id:'session-7',active:true,filter:'employee-wired'}},unrelated:{id:'session-8',active:true,filter:'guest'}}}});
  const targetPolicy=absent?null:a.object('target-policy','Effective employee-wired policy','netNas',['netNas'],'employee-wired',{initial:true,type:'authorization'});
  const targetContext=absent?null:a.object('target-auth-context','Target session authentication/key-cache context','netNas',['netNas'],'HANDLE(session-7 associated authentication context)',{initial:true,type:'authentication-context'});
  const changedPolicy=a.object('quarantine-policy','Effective quarantine policy','netNas',['netNas'],'quarantine',{type:'authorization'});
  a.object('dynamic-secret','Trusted controller-NAS secret','netController',['netController','netNas'],'HANDLE(controller-NAS secret)',{initial:true,holders:['netController','netNas'],type:'shared-secret'});
  a.object('source-policy','Trusted dynamic source and timestamp policy','netNas',['netNas'],'SYM(controller.corp.example authorized; time1792540800 window30)',{initial:true,type:'trust-record'});
  const unrelated=a.object('unrelated-session','Unrelated active session','netNas',['netNas'],'SYM(session-8 guest)',{initial:true,type:'session'});
  a.inventory.bindings.push({path:'sessions.unrelated.active',equals:true,actorId:'netNas',artifactId:unrelated,representationId:'plain',store:'local store'});
  let target;
  if(!absent){target=a.object('target-session','Target active session identity','netNas',['netNas'],'SYM(session-7 identity)',{initial:true,type:'session'});a.inventory.bindings.push({path:'sessions.access.active',equals:true,actorId:'netNas',artifactId:target,representationId:'plain',store:'local store'});}
  const requestValues={'Code':disconnect?'40 Disconnect-Request':'43 CoA-Request','Identifier':disconnect?'82':'81','Request Authenticator':variant==='invalid-request-authenticator'?'SYM(invalid authenticator)':'SYM(RFC5176 accounting-style Request Authenticator)','NAS-Identifier':variant==='wrong-recipient'?'other-nas.corp.example':'switch.corp.example','Acct-Session-Id':absent?'absent-7':'session-7','Event-Timestamp':variant==='stale-Event-Timestamp'?'1792540700':'1792540800',...disconnect?{}:nak?variant==='unsupported-attribute'?{'Unsupported-Attribute':'SYM(unsupported extension)'}:{'Service-Type':'SYM(unsupported service)'}:{'Filter-Id':'quarantine'}};
  const operation=a.object('dynamic-request',disconnect?'Disconnect request':'CoA request','netController',['netController','netNas'],JSON.stringify(requestValues),{type:'dynamic-request'});
  a.event('request-create','Create existing-session request','netController','netController','Local dynamic request',requestValues,'The controller selects one existing NAS session; this is not another login or Access-Request.',{held:a.create(operation,'netController')});
  netUseAuthoredFields(a,operation,'plain',a.steps.at(-1),['netController','netNas']);
  const request=a.event('request',disconnect?'Disconnect-Request':'CoA-Request','netController','netNas','RADIUS Dynamic Authorization/UDP',requestValues,'The NAS receives the operation but must validate trust, integrity, freshness and target before acting.',{held:[a.acquire(operation,'netNas','pending operation')]});
  request.layers=[{protocol:'RADIUS Dynamic Authorization',transport:'UDP 3799',from:'netController',to:'netNas',protection:'RFC5176 request integrity plus source authorization and Event-Timestamp',keyRef:a.id+':dynamic-secret:g1'}];
  a.inventory.events[request.id].messages[0].objects.push({artifactId:operation,representationId:'plain'});
  a.event('request-check','Validate dynamic source and packet','netNas','netNas','Local RFC5176 validation',{'Source':variant==='untrusted-client'?'untrusted':'configured trusted DAC','Request integrity':variant==='invalid-request-authenticator'?'invalid':'valid','Timestamp':variant==='stale-Event-Timestamp'?'outside 30-second window':'current','NAS target':variant==='wrong-recipient'?'wrong recipient':'matches'},'Only a trusted, authenticated, current request for this NAS may reach session selection.',{held:[a.release(operation,'netNas','pending operation')]});
  netObserve(a,'request-check',operation,'netNas',discarded?'discarded':'valid','Source authorization, recipient identity, request authenticator and Event-Timestamp.');
  if(discarded){
    a.event('discard','Silently discard invalid dynamic request','netNas','netNas','Local silent discard',{'Reason':variant,'Reply':'none'},'No ACK or NAK is fabricated for this untrusted, integrity-invalid or stale request. An authenticated NAS-identifier mismatch instead follows the explicit NAK403 path. Sessions remain unchanged.',{effects:[netPut('network.status','request silently discarded')]});
    a.event('timeout','Controller observes no valid response','netController','netController','Local scripted timeout',{'Knowledge':'unknown remote result'},'A timeout is not a recipient NAK and does not remove any NAS session.',{effects:[netPut('network.controllerKnowledge','unknown')]});
    return a.finish();
  }
  const failed=nak||absent||variant==='wrong-recipient';
  a.event('operation',failed?'Reject unsupported or absent operation':disconnect?'Terminate selected session':'Apply supported filter change','netNas','netNas','Local NAS enforcement',{'Selected session':absent?'absent-7':'session-7','Operation result':failed?'NAK Error-Cause '+error:disconnect?'target disconnected; associated context cleared':'same session identity; filter quarantine','Unrelated session':'session-8 unchanged'},'The recipient action or rejection occurs now, before any ACK can be generated. No unrelated session is removed.',{held:disconnect&&!failed?[a.release(target,'netNas')]:[],effects:failed?[netPut('network.errorCause',error),netPut('network.logicalOperations',0)]:[netPut('network.logicalOperations',1),...disconnect?[netPut('sessions.access.active',false),netPut('network.port','unauthorized'),netPut('network.status','session disconnected')]:[netPut('sessions.access.filter','quarantine'),netPut('network.status','policy changed')]]});
  if(!failed){
    const effect=a.inventory.events[a.id+':operation'].effects;
    effect.push(a.release(targetPolicy,'netNas'));
    if(disconnect)effect.push(a.release(targetContext,'netNas'));
    else effect.push(...a.create(changedPolicy,'netNas'));
    a.steps.at(-1).protocolEffects.push(netPut('network.effectivePolicy',disconnect?null:'quarantine'));
  }
  const responseValues={'Code':disconnect?failed?'42 Disconnect-NAK':'41 Disconnect-ACK':failed?'45 CoA-NAK':'44 CoA-ACK','Identifier':disconnect?'82':'81','Response Authenticator':'SYM(correlated RFC5176 response)',...failed?{'Error-Cause':error+' '+(error===503?'Session Context Not Found':error===403?'NAS Identification Mismatch':error===401?'Unsupported Attribute':'Unsupported Service')}:{},'Event-Timestamp':'1792540800'};
  const cached=a.object('dynamic-result','Cached dynamic operation result','netNas',['netNas','netController'],JSON.stringify(responseValues),{type:'dynamic-result'});
  a.event('cache-result','Cache the original dynamic result','netNas','netNas','Local RFC5176 duplicate cache',{'Cache key':'sourceIP/sourceUDPport/Identifier/requestAuthenticator','Window':'same 30-second Event-Timestamp window'},'Cache the result so a valid duplicate cannot apply the operation twice.',{held:a.create(cached,'netNas')});
  const lost=variant==='lost-CoA-ACK'||variant==='lost-Disconnect-ACK';
  if(lost)a.event('lost-ack','Scripted ACK loss before controller delivery','netNas','netNas','Teaching-only network loss',responseValues,'NAS has already processed the operation. This local disclosure is not controller receipt; sender cannot infer failure.',{effects:[netPut('network.controllerKnowledge','pending')]});
  else{
    const reply=a.event(failed?'nak':'ack',failed?'Send correlated NAK':'Send ACK after operation','netNas','netController','RADIUS Dynamic Authorization/UDP',responseValues,'Controller receives an unverified result; NAS action already happened.',{held:[a.acquire(cached,'netController','dynamic result inbox')]});
    a.inventory.events[reply.id].messages[0].objects.push({artifactId:cached,representationId:'plain'});
    a.event(failed?'nak-check':'ack-check','Controller verifies dynamic result','netController','netController','Local dynamic reply validation',{'Check':'Expected NAS, Identifier, Response Authenticator and Event-Timestamp valid','Result':failed?'rejected':disconnect?'disconnected':'changed'},'Only valid correlated receipt gives the controller result knowledge; it cannot retroactively cause the NAS operation.',{effects:[netPut('network.controllerKnowledge',failed?'rejected':disconnect?'disconnected':'changed')]});
    a.inventory.events[a.id+':'+(failed?'nak-check':'ack-check')].effects.push(a.release(cached,'netController','dynamic result inbox'),a.acquire(cached,'netController','verified operation result'));
    netObserve(a,failed?'nak-check':'ack-check',cached,'netController','valid','Correlated authenticated result changes sender knowledge, not recipient-side action.');
  }
  netUseAuthoredFields(a,cached,'plain',a.steps.find(step=>step.id===a.id+':'+(lost?'lost-ack':failed?'nak':'ack')),['netNas','netController']);
  if(lost||variant==='duplicate-CoA-request'||variant==='duplicate-Disconnect-request'){
    a.event('retry-timeout','Controller fixed retry/observation deadline','netController','netController','Local scripted timeout',{'Knowledge':lost?'unknown, no valid ACK':'known result; duplicate robustness example'},'No timer event changes NAS policy or resurrects a terminated session.',{effects:lost?[netPut('network.controllerKnowledge','unknown')]:[]});
    if(!lost){
      a.event('retry-request','Valid duplicate dynamic request','netController','netNas','RADIUS Dynamic Authorization/UDP',requestValues,'Original Identifier, Event-Timestamp and request authenticator are retained within the duplicate window.');
      a.event('duplicate-check','Select cached result without another action','netNas','netNas','Local RFC5176 duplicate handling',{'Operation count':failed?'0':'1','Cached response':responseValues.Code},'Duplicate detection returns the cached original outcome; no policy reapplication or unrelated-session mutation.',{effects:[netPut('network.logicalOperations',failed?0:1)]});
      a.event('cached-response','Return original cached dynamic response','netNas','netController','RADIUS Dynamic Authorization/UDP',responseValues,'This is another wire occurrence of the same result, not another operation.');
      a.event('cached-response-check','Verify cached reply','netController','netController','Local dynamic reply validation',{'Check':'Same original transaction and current timestamp'},'The controller retains its existing result knowledge.');
    }
  }
  if(disconnect&&!failed){
    a.object('accounting-secret','Independent NAS-collector secret','netNas',['netNas','netCollector'],'HANDLE(NAS-collector secret)',{initial:true,holders:['netNas','netCollector'],type:'shared-secret'});
    const stop=a.object('stop-record','Accounting Stop after administrative termination','netNas',['netNas','netCollector'],'SYM(session-7 Stop time60 counters3000/5000 Admin-Reset)',{type:'accounting-record'});
    a.event('stop-create','Create separate Accounting Stop','netNas','netNas','Local accounting record',{'Acct-Session-Id':'session-7','Acct-Status-Type':'Stop','Acct-Terminate-Cause':'6 Admin-Reset','Acct-Session-Time':'60','Acct-Input-Octets':'3000','Acct-Output-Octets':'5000'},'Accounting Stop is a subsequent independent event, not the cause of Disconnect-ACK.',{held:a.create(stop,'netNas')});
    a.event('stop','Send Accounting Stop','netNas','netCollector','RADIUS Accounting/UDP',{'Code':'4 Accounting-Request','NAS-Identifier':'switch.corp.example','Identifier':'63','Request Authenticator':'SYM(accounting request authenticator)','Acct-Session-Id':'session-7','Acct-Status-Type':'Stop','Acct-Delay-Time':'0','Acct-Terminate-Cause':'6 Admin-Reset','Acct-Session-Time':'60','Acct-Input-Octets':'3000','Acct-Output-Octets':'5000'},'Collector receives the stopped target session record, never a record terminating session-8.',{held:[a.acquire(stop,'netCollector','accounting inbox')]});
    a.event('stop-store','Validate and record Stop','netCollector','netCollector','Local accounting validation',{'Check':'NAS association and accounting authenticator valid','Stored':'Stop for session-7'},'The collector stores the record separately from controller ACK knowledge.',{held:[a.acquire(stop,'netCollector','durable accounting store'),a.release(stop,'netCollector','accounting inbox')],effects:[netPut('network.accounting.stored',['Stop'])]});
    a.event('stop-ack','Accounting-Response','netCollector','netNas','RADIUS Accounting/UDP',{'Code':'5 Accounting-Response','Identifier':'63','Response Authenticator':'SYM(accounting response63)'},'Separate accounting acknowledgement, not another dynamic ACK.');
    a.event('stop-ack-check','Verify accounting acknowledgement','netNas','netNas','Local accounting validation',{'Check':'id63 and Response Authenticator valid'},'Accounting delivery completes without changing the unrelated active session.',{effects:[netPut('network.accounting.acked',['Stop'])]});
  }
  return a.finish();
}
function netNps(slug,title,{mappingRejected=false,variant='normal'}={}){
  const denied=mappingRejected||['UPN-only-mapping','missing-SID-binding','group-denied'].includes(variant);
  const a=netAuthor(slug,title,'nps12',{actorIds:['netPeer','netNas','netServer','netAccount'],meta:{protocol:'EAP-TLS / NPS TLS 1.2',standard:'RFC 5216 / documented NPS configuration',supportNote:'Windows Server 2022 NPS / Windows 11 24H2 documented configuration model; no live interoperability run or tested patch build claimed.'},profileMetadata:netProfile('Windows Server 2022 NPS / Windows 11 24H2 full EAP-TLS 1.2',[2865,3579,5216,5247,2548],{algorithms:['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS1.2 PRF client EAP encryption','Certificate SID extension or explicit strong mapping, never UPN-only'],transports:['Peer/NAS EAPOL','NAS/NPS RADIUS UDP1812'],assumptions:['Full authentication, not resumption; NPS TLS1.3 not claimed','Provisioned trusted issuer and configured server-name policy','Modern strong account binding and employee group policy'],completion:'Valid certificate + strong mapping + group policy + verified NAS application'})});
  a.object('radius-secret','NAS-NPS shared secret','netNas',['netNas','netServer'],'HANDLE(NAS-NPS secret)',{initial:true,holders:['netNas','netServer'],type:'shared-secret'});
  const certs={},secrets={},msks={},emsks={},ephemerals={};
  for(const actor of ['netPeer','netServer']){
    a.object(actor+'-private','Certificate private key',actor,[actor],'HANDLE('+actor+' private signing key)',{initial:true,type:'private-key'});
    ephemerals[actor]=a.object(actor+'-ephemeral','TLS1.2 local ECDHE private share',actor,[actor],'HANDLE('+actor+' TLS1.2 ephemeral private share)',{type:'private-key'});
    certs[actor]=a.object(actor+'-cert','TLS1.2 public certificate',actor,['netPeer','netNas','netServer'],'SYM('+actor+' TLS1.2 certificate chain)',{initial:true,type:'certificate'});
    netCertificateDetails(a,certs[actor],actor,'normal',true);
    a.object(actor+'-trust','Configured certificate and revocation policy',actor,[actor],'SYM(trusted issuer, EKU, name, validity, revocation)',{initial:true,type:'trust-record'});
    secrets[actor]=a.object(actor+'-tls','TLS1.2 endpoint master and traffic-secret handles',actor,[actor],'SYM(TLS1.2 master secret and record keys)',{type:'key'});
    msks[actor]=a.object(actor+'-msk','TLS1.2 locally derived MSK',actor,actor==='netServer'?['netServer','netNas']:['netPeer'],'SYM(TLS1.2 PRF MSK64)',{type:'key',...(actor==='netServer'?{protectedValue:'SYM(protected TLS1.2 MSK key halves)'}:{})});
    emsks[actor]=a.object(actor+'-emsk','TLS1.2 locally derived EMSK',actor,[actor],'SYM(TLS1.2 PRF EMSK64)',{type:'key'});
  }
  const account=a.object('account-record','AD strong account binding and groups','netAccount',['netAccount'],'SYM(account SID S-1-5-21-example-1101, strong certificate SID binding, employee-wired group)',{initial:true,type:'account-record'});
  const context=a.object('eap-context','Opaque EAP State','netServer',['netServer','netNas'],'SYM(nps-context1)',{type:'challenge-context'});
  const eap=(key,title,from,to,fields,text,extra={})=>a.event(key,title,from,to,'EAPOL / EAP-TLS1.2',fields,text,extra);
  const radius=(key,title,from,to,fields,text,extra={})=>a.event(key,title,from,to,'RADIUS / EAP-Message',{'Message-Authenticator':'SYM(adjacent HMAC-MD5)',...fields,...fields.Code==='Access-Request'?{'NAS-Identifier':'switch.corp.example'}:{}},text,extra);
  eap('identity-request','Request EAP Identity','netNas','netPeer',{'EAP Identifier':'1','Type':'Identity'},'The Windows peer is an EAP supplicant; switch is RADIUS client.');
  eap('identity-response','Respond with routing identity','netPeer','netNas',{'EAP Identifier':'1','Identity':'anonymous@corp.example'},'Outer identity does not establish the mapped account.');
  radius('identity-backend','Relay identity to NPS','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'41','Request Authenticator':'SYM(NPS RA41)','EAP-Message':'Response/Identity id1'},'NAS forwards EAP rather than authenticating the certificate.');
  a.event('identity-check','Validate NAS and begin full method','netServer','netServer','Local NPS validation',{'Checks':'Configured NAS, valid Message-Authenticator','State':'SYM(nps-context1)'},'This documented NPS configuration begins a full TLS1.2 authentication, not resumed TLS1.3.',{held:a.create(context,'netServer')});
  radius('start','NPS EAP-TLS Start','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':'41','Response Authenticator':'SYM(response41)','State':'SYM(nps-context1)','EAP-Message':'Request/EAP-TLS id2 Start'},'Opaque State correlates the full TLS1.2 method.',{held:[a.acquire(context,'netNas','challenge inbox')]});
  a.event('start-check','Check NPS challenge envelope','netNas','netNas','Local RADIUS validation',{'Checks':'Response and Message-Authenticator valid; id41'},'NAS validates the challenge before relaying EAP.',{held:[a.acquire(context,'netNas','challenge cache'),a.release(context,'netNas','challenge inbox')]});
  eap('start-peer','Relay TLS Start','netNas','netPeer',{'EAP Identifier':'2','Type':'EAP-TLS Start'},'Only authentication frames traverse the unauthorized access port.');
  eap('clienthello-peer','TLS1.2 ClientHello','netPeer','netNas',{'EAP Identifier':'2','ClientHello':'TLS1.2, ECDHE_RSA AES128_GCM_SHA256; fresh client_random; no resumption'},'Full TLS1.2 protocol and key schedule are pinned separately from the generic TLS1.3 lesson.');
  radius('clienthello-backend','Relay full ClientHello','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'42','Request Authenticator':'SYM(NPS RA42)','State':'SYM(nps-context1)','EAP-Message':'Response/EAP-TLS id2 ClientHello TLS1.2'},'State unchanged; no User-Password is combined with EAP-Message.');
  a.event('hello-check','Validate ClientHello envelope','netServer','netServer','Local NPS/TLS validation',{'Checks':'Message-Authenticator, State, EAP id and supported TLS1.2 suite'},'NPS accepts only the configured full-handshake TLS1.2 profile.');
  a.inventory.events[a.id+':hello-check'].effects.push(...a.create(ephemerals.netServer,'netServer'));
  const serverFlight={'Code':'Access-Challenge','RADIUS Identifier':'42','Response Authenticator':'SYM(response42)','State':'SYM(nps-context1)','EAP-Message':'Request/EAP-TLS id3 ServerHello, Certificate, signed ECDHE ServerKeyExchange, CertificateRequest, ServerHelloDone','Server Certificate':'SYM(netServer TLS1.2 certificate chain)'};
  const sf=radius('serverflight-backend','TLS1.2 server certificate flight','netServer','netNas',serverFlight,'TLS1.2 certificates are visible before ChangeCipherSpec. NAS may read the public certificate but never the private key.',{held:[a.acquire(certs.netServer,'netNas','TLS relay')]});a.inventory.events[sf.id].messages[0].objects.push({artifactId:certs.netServer,representationId:'plain'});
  a.event('serverflight-check','Validate adjacent RADIUS flight','netNas','netNas','Local RADIUS validation',{'Checks':'id42 and both authenticators valid'},'Envelope validation is separate from peer TLS certificate validation.');
  const sp=eap('serverflight-peer','Relay visible TLS1.2 server certificate','netNas','netPeer',{'EAP Identifier':'3','TLS flight':'ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone','Server Certificate':'SYM(netServer TLS1.2 certificate chain)'},'The legitimate peer receives the public chain before validating issuer, configured name, use, time and revocation.',{held:[a.acquire(certs.netServer,'netPeer','certificate inbox'),a.release(certs.netServer,'netNas','TLS relay')]});a.inventory.events[sp.id].messages[0].objects.push({artifactId:certs.netServer,representationId:'plain'});
  a.event('server-check','Validate NPS server certificate and key-exchange proof','netPeer','netPeer','Local TLS1.2 validation',{'Checks':'trusted issuer; configured radius.corp.example; serverAuth; validity; revocation; signed ECDHE parameters'},'TLS1.2 server Finished has not yet been received. Certificate validation alone does not complete the handshake.',{effects:[netPut('network.serverIdentity',true)]});netObserve(a,'server-check',certs.netServer,'netPeer','valid','Configured Windows EAP certificate validation, not merely UPN matching.');
  a.event('peer-derive','Peer derives TLS1.2 secret locally','netPeer','netPeer','Local TLS1.2 key schedule',{'Derivation':'ECDHE shared secret, TLS1.2 PRF master secret and traffic keys'},'Peer independently derives its own secret handles; nothing is sent to NAS.',{held:a.create(secrets.netPeer,'netPeer')});
  a.inventory.events[a.id+':peer-derive'].effects.push(...a.create(ephemerals.netPeer,'netPeer'));
  const peerFields={'EAP Identifier':'3','Client Certificate':'SYM(netPeer TLS1.2 certificate chain)','TLS flight':'Certificate, ClientKeyExchange, CertificateVerify, ChangeCipherSpec, encrypted Finished'};
  const pp=eap('peerflight-peer','Full peer certificate and Finished flight','netPeer','netNas',peerFields,'The certificate and key-exchange/signature fields precede encryption; Finished is encrypted after ChangeCipherSpec.',{held:[a.acquire(certs.netPeer,'netNas','TLS relay')]});a.inventory.events[pp.id].messages[0].objects.push({artifactId:certs.netPeer,representationId:'plain'});
  const pb=radius('peerflight-backend','Relay TLS1.2 peer flight','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'43','Request Authenticator':'SYM(NPS RA43)','State':'SYM(nps-context1)','EAP-Message':'Response/EAP-TLS id3 Certificate, ClientKeyExchange, CertificateVerify, CCS, encrypted Finished','Client Certificate':'SYM(netPeer TLS1.2 certificate chain)'},'NAS transports public certificate fields without obtaining endpoint traffic secrets.',{held:[a.acquire(certs.netPeer,'netServer','certificate inbox'),a.release(certs.netPeer,'netNas','TLS relay')]});a.inventory.events[pb.id].messages[0].objects.push({artifactId:certs.netPeer,representationId:'plain'});
  a.event('server-derive','NPS derives TLS1.2 endpoint keys locally','netServer','netServer','Local TLS1.2 key schedule',{'Derivation':'ECDHE shared secret, master secret and TLS1.2 traffic keys'},'Server derivation is independent from peer derivation and precedes its Finished verification.',{held:a.create(secrets.netServer,'netServer')});
  a.event('peer-check','Validate peer chain, CertificateVerify and Finished','netServer','netServer','Local TLS1.2 validation',{'Checks':'clientAuth, chain, time/revocation, possession signature, transcript Finished','Certificate identity':'valid Alice certificate'},'A valid certificate and possession proof still do not establish a strong AD account binding or group permission.',{effects:[netPut('network.peerIdentity',true),netPut('network.status','identity verified')]});netObserve(a,'peer-check',certs.netPeer,'netServer','valid','Certificate cryptography succeeds independently of mapping.');
  const check=a.event('account-query','Scoped certificate-to-account check','netServer','netAccount','Teaching-only documented account-service boundary',{'Certificate binding':denied&&variant!=='group-denied'?'UPN-only; no accepted SID/strong mapping':'SID extension S-1-5-21-example-1101 or explicit strong mapping','Required group':'employee-wired'},'This is a scoped documented account/policy check, not a fabricated LDAP bind, Kerberos AS exchange or live NPS capture.');check.eventType='teaching-disclosure';
  a.event('mapping','Validate strong binding and account membership','netAccount','netAccount','Local account policy',{'Certificate validity':'already established by NPS','Account binding':denied&&variant!=='group-denied'?'no strong binding':'SID/explicit strong mapping valid','Group':variant==='group-denied'?'not permitted':'employee-wired'},'UPN match alone is insufficient under the chosen modern strong-mapping policy.',{effects:[netPut('network.accountServiceMapping',denied&&variant!=='group-denied'?null:'S-1-5-21-example-1101')]});netObserve(a,'mapping',account,'netAccount',denied?'denied':'valid','Strong certificate binding and employee group decision are separate from TLS cryptography.');
  a.event('account-result','Return scoped mapping and policy result','netAccount','netServer','Teaching-only documented account-service boundary',{'Mapped account':denied&&variant!=='group-denied'?'none':'S-1-5-21-example-1101','Policy':denied?'denied':'employee-wired allowed'},'Only this scoped result crosses the boundary; AD account secrets are not sent to NPS.').eventType='teaching-disclosure';
  a.event('mapping-result-check','NPS consumes scoped account result','netServer','netServer','Local documented account-result validation',{'Mapped identity':denied&&variant!=='group-denied'?'none':'S-1-5-21-example-1101','Policy membership':denied?'denied':'allowed'},'NPS learns the mapped identity only after receiving and processing the account-service result, not from certificate validity alone.',{effects:[netPut('network.mappedAccount',denied&&variant!=='group-denied'?null:'S-1-5-21-example-1101')]});
  a.event('policy','NPS decides network access policy','netServer','netServer','Local NPS network policy',{'Result':denied?'denied':'accepted employee-wired'},'Mapping and group policy must succeed before EAP success or MSK distribution.',{effects:[netPut('network.policy',denied?'denied':'accepted')]});
  if(!denied){
    radius('server-finished','TLS1.2 server ChangeCipherSpec and Finished','netServer','netNas',{'Code':'Access-Challenge','RADIUS Identifier':'43','Response Authenticator':'SYM(response43)','State':'SYM(nps-context1)','EAP-Message':'Request/EAP-TLS id4 ChangeCipherSpec, encrypted server Finished'},'TLS1.2 completes with ChangeCipherSpec and Finished; no TLS1.3 protected application_data 0x00 is invented.');
    a.event('finished-envelope','Check server Finished RADIUS envelope','netNas','netNas','Local RADIUS validation',{'Checks':'id43 and both authenticators valid'},'NAS can validate its envelope, not the endpoint Finished.');
    eap('finished-peer','Relay server Finished','netNas','netPeer',{'EAP Identifier':'4','TLS flight':'ChangeCipherSpec, SYM(encrypted server Finished)'},'Peer receives the final server proof before EAP completion.');
    a.event('finished-check','Peer validates server Finished','netPeer','netPeer','Local TLS1.2 validation',{'Finished':'valid transcript proof'},'Only this local check completes peer-side TLS1.2 verification.');
    for(const actor of ['netServer','netPeer'])a.event(actor+'-export',actor==='netPeer'?'Peer derives TLS1.2 MSK and EMSK':'Server derives TLS1.2 MSK and EMSK',actor,actor,'Local RFC5216 PRF',{'PRF':'TLS-PRF(master_secret, client EAP encryption, client_random || server_random)','MSK':'first 64 octets','EMSK':'next 64 octets'},'Endpoint-local RFC5216 PRF output is distinct from TLS traffic secrets; TLS1.3 exporter formula is not used.',{held:[...a.create(msks[actor],actor),...a.create(emsks[actor],actor)]});
    eap('empty-peer','Empty EAP-TLS response','netPeer','netNas',{'EAP Identifier':'4','Data':'empty'},'Peer acknowledges the server handshake flight.');
    radius('empty-backend','Relay empty response','netNas','netServer',{'Code':'Access-Request','RADIUS Identifier':'44','Request Authenticator':'SYM(NPS RA44)','State':'SYM(nps-context1)','EAP-Message':'Response/EAP-TLS id4 empty'},'Server has the method acknowledgement before EAP-Success.');
    const accept=radius('accept','NPS Access-Accept and key carriers','netServer','netNas',{'Code':'Access-Accept','RADIUS Identifier':'44','Response Authenticator':'SYM(response44)','EAP-Message':'EAP-Success id4','Filter-Id':'employee-wired','MS-MPPE-Recv-Key':'SYM(protected first32 TLS1.2 MSK octets)','MS-MPPE-Send-Key':'SYM(protected second32 TLS1.2 MSK octets)'},'Only the permitted MSK halves are distributed to NAS after certificate, strong binding and group policy.',{held:[a.acquire(msks.netServer,'netNas','AAA key inbox','wire')],effects:[netPut('network.reply','received-unverified')]});netExactCarrier(a,accept,msks.netServer,'wire',field=>field.name.startsWith('MS-MPPE-'));
    a.event('verify-reply','NAS verifies NPS result and unwraps MSK','netNas','netNas','Local RADIUS validation',{'Checks':'id44, Response/Message-Authenticator, EAP id4, supported Filter-Id','Recovery':'RFC2548 salt + NAS-NPS secret + RA44'},'Received key bytes remain protected until NAS validates the correct packet and unwraps the intended carrier.',{held:[a.acquire(msks.netServer,'netNas','lower-layer key cache'),a.release(msks.netServer,'netNas','AAA key inbox','wire')],effects:[netPut('network.reply','verified'),netPut('network.mskReleased',true)]});
    const session=a.object('port-session','NPS-authorized controlled port','netNas',['netNas'],'SYM(session-7 employee-wired)',{type:'session'});a.inventory.bindings.push({path:'sessions.access',presentWhen:'exists',actorId:'netNas',artifactId:session,store:'local store'});
    a.event('enforce','NAS applies NPS access policy','netNas','netNas','Local 802.1X enforcement',{'Controlled port':'authorized','Filter-Id':'employee-wired'},'Only supported verified authorization opens the controlled port.',{held:[...a.create(session,'netNas'),a.release(context,'netNas','challenge cache')],effects:[netPut('network.port','authorized'),netPut('network.status','port authorized'),netPut('sessions.access',{id:'session-7',active:true,filter:'employee-wired'})]});
    eap('success-peer','Deliver EAP-Success','netNas','netPeer',{'EAP Code':'Success','EAP Identifier':'4'},'This completes EAP, not MACsec or Wi-Fi link security.');
  }else{
    radius('failure','NPS Access-Reject and EAP-Failure','netServer','netNas',{'Code':'Access-Reject','RADIUS Identifier':'43','Response Authenticator':'SYM(response43)','EAP-Message':'EAP-Failure','Mapping result':variant==='group-denied'?'mapped but group denied':'no accepted strong binding'},'Cryptographically valid certificate alone cannot produce a mapped identity or successful EAP result.',{effects:[netPut('network.status',variant==='group-denied'?'policy denied':'account mapping rejected')]});
    a.event('failure-check','NAS verifies rejection and keeps port closed','netNas','netNas','Local RADIUS validation',{'Checks':'correlation and authenticators valid','Port':'unauthorized'},'A trusted rejection never opens the port or distributes MSK.',{held:[a.release(context,'netNas','challenge cache')]});
    eap('failure-peer','Deliver EAP-Failure','netNas','netPeer',{'EAP Code':'Failure','EAP Identifier':'3'},'The peer learns method failure, not AD account secrets.');
  }
  a.event('cleanup','NPS releases own method scratch','netServer','netServer','Local cleanup',{'Cleanup':'NPS TLS keys and challenge context; any local exporter scratch'},'NPS local cleanup cannot erase peer keys or independently retained NAS material.',{held:[a.release(secrets.netServer,'netServer'),a.release(context,'netServer'),...denied?[]:[a.release(msks.netServer,'netServer'),a.release(emsks.netServer,'netServer')]]});
  a.inventory.events[a.id+':cleanup'].effects.push(a.release(ephemerals.netServer,'netServer'));
  a.event('peer-cleanup','Peer consumes result and releases method keys','netPeer','netPeer','Local cleanup',{'Cleanup':'Peer TLS traffic secrets and any EMSK scratch; public certificate retained'},'The peer releases only its own state; the configured private key remains local.',{held:[a.release(secrets.netPeer,'netPeer'),...denied?[]:[a.release(emsks.netPeer,'netPeer')]]});
  a.inventory.events[a.id+':peer-cleanup'].effects.push(a.release(ephemerals.netPeer,'netPeer'));
  const model=a.finish();
  model.profile.implementation='Windows Server 2022 NPS and Windows 11 24H2 configuration targets; no exact tested patch build or live interoperability run';
  model.profile.sources.push(...NETWORKLAB_SOURCES.filter(source=>source.standard.startsWith('Microsoft')));
  return model;
}
function netRadius11(slug,title,{unavailable=false,variant='normal'}={}){
  const a=netAuthor(slug,title,'radius11',{actorIds:unavailable?['netNas','netServer']:['netPeer','netNas','netServer'],meta:{family:'network-transport',protocol:'RADIUS/1.1',standard:'RFC 9765',source:'https://www.rfc-editor.org/rfc/rfc9765',status:'experimental'},profileMetadata:netProfile('Experimental negotiated RADIUS/1.1',[9765],{status:'Experimental',algorithms:['TLS1.3 TLS_AES_128_GCM_SHA256','ALPN radius/1.1','Opaque 16-octet Token correlation; no RADIUS MD5/shared secret'],transports:['TLS1.3 over TCP2083'],assumptions:['Two explicitly capable peers; no NPS support claim','Strict required profile; no UDP upgrade or silent fallback'],completion:unavailable?'Connection stops without an acceptable profile; no user authentication decision':'Token-correlated result verified before service enforcement'})});
  for(const actor of ['netNas','netServer']){
    a.object(actor+'-transport-trust','Configured transport peer trust',actor,[actor],'SYM(trusted issuer, configured adjacent TLS peer identity)',{initial:true,type:'trust-record'});
    a.object(actor+'-transport-private','Transport certificate private key',actor,[actor],'HANDLE('+actor+' transport signing key)',{initial:true,type:'private-key'});
  }
  const transportCertificates=netTransportCertificateObjects(a);
  const outerNas=a.object('nas-transport-key','NAS local outer TLS traffic secrets','netNas',['netNas'],'SYM(TLS1.3 transport traffic secrets)',{type:'key'});
  const outerServer=a.object('server-transport-key','Server local outer TLS traffic secrets','netServer',['netServer'],'SYM(TLS1.3 transport traffic secrets)',{type:'key'});
  a.object('strict-profile-policy','Required negotiated application profile','netNas',['netNas'],'SYM(require radius/1.1; no historic profile or UDP fallback)',{initial:true,type:'trust-record'});
  a.event('negotiate','TLS1.3 ClientHello offers RADIUS/1.1','netNas','netServer','TLS1.3 / ALPN',{'ClientHello':'TLS1.3 or later; fresh key_share','ALPN offered':'radius/1.1'},'ALPN is sent for this preconfigured TLS association. The NAS strict no-fallback policy is local configuration, not a transmitted TLS field.');
  if(unavailable){
    if(variant==='absent-ALPN'){
      a.event('server-derive','Legacy server derives its TLS handshake secrets','netServer','netServer','Local TLS1.3 derivation',{'ALPN support':'not configured; does not acknowledge offered ALPN','Derivation':'local ECDHE/HKDF handshake keys'},'RFC9765 permits a legacy no-ALPN server to continue TLS without selecting an application profile; the strict client must then close.',{held:a.create(outerServer,'netServer')});
      a.event('no-alpn-flight','ServerHello and unacknowledged ALPN','netServer','netNas','TLS1.3',{'TLS records':'SYM(ServerHello and encrypted EncryptedExtensions without ALPN)'},'This bounded handshake flight contains no accepted application profile and no RADIUS data.',{representation:'wire'});
      a.event('nas-derive','NAS derives keys to inspect EncryptedExtensions','netNas','netNas','Local TLS1.3 derivation',{'Derivation':'local ECDHE/HKDF','Decoded ALPN result':'absent'},'Decryption reveals missing ALPN; no mutually accepted RADIUS association is inferred.',{held:a.create(outerNas,'netNas')});
      a.event('negotiate-check','Strict NAS rejects missing negotiated profile','netNas','netNas','Local RFC9765 ALPN policy',{'Required ALPN':'radius/1.1','Received ALPN':'absent','Decision':'close connection; no fallback'},'The client, not a fictional user validator, detects that its required profile was not obtained.',{effects:[netPut('network.transport','required profile unavailable'),netPut('network.fallback',false)]});
      a.event('failure','Client closes the unqualified TLS connection','netNas','netServer','TLS connection close',{'Close':'client connection close, no RADIUS application data'},'The optional Protocol-Error mechanism is not used. No historic profile or UDP fallback is attempted.',{effects:[netPut('network.status','required profile unavailable')]});
      a.event('server-cleanup','Server consumes close and clears only its keys','netServer','netServer','Local transport cleanup',{'Cleanup':'server local handshake secrets'},'No authentication or EAP result was produced.',{held:[a.release(outerServer,'netServer')]});
      a.event('failure-consume','NAS clears its failed handshake context','netNas','netNas','Local transport cleanup',{'Result':'required profile unavailable; no application traffic'},'Only the NAS clears its own local handshake keys.',{held:[a.release(outerNas,'netNas')]});
    }else{
      a.event('negotiate-check','Server finds no common ALPN protocol','netServer','netServer','Local RFC9765 ALPN policy',{'Client offered':'radius/1.1','Server configured protocols':variant==='only-radius10'?'radius/1.0 only':'no allowed radius/1.1 profile','Decision':'no_application_protocol (120) and close'},'An ALPN-aware server must not select an unoffered radius/1.0 value. Disjoint protocol lists produce a transport alert, not a user-authentication rejection.',{effects:[netPut('network.transport','required profile unavailable'),netPut('network.fallback',false)]});
      a.event('failure','Server sends no_application_protocol and closes','netServer','netNas','TLS negotiation failure',{'TLS alert':'120 no_application_protocol','Alert protection':'before ServerHello in this selected failure; no TLS traffic keys established'},'The server stops before application traffic. This is neither Access-Reject nor a fallback to another transport.',{effects:[netPut('network.status','required profile unavailable')]});
      a.event('failure-consume','NAS consumes ALPN negotiation failure','netNas','netNas','Local transport state',{'Result':'connection unavailable; no user decision'},'NAS obtains no RADIUS or EAP authentication result.');
    }
    return a.finish();
  }
  a.event('server-derive','Server derives outer TLS secrets locally','netServer','netServer','Local TLS1.3 derivation',{'Derivation':'ECDHE/HKDF from local private and received public shares'},'Traffic secrets remain local; RADIUS has no shared secret in this negotiated profile.',{held:a.create(outerServer,'netServer')});
  a.event('server-flight','TLS1.3 server authenticated handshake flight','netServer','netNas','TLS1.3 / ALPN',{'ALPN selected':'radius/1.1','TLS records':'ServerHello, encrypted CertificateRequest, Certificate, CertificateVerify, Finished'},'Mutually authenticated transport must complete before any RADIUS/1.1 application packet.');
  a.event('nas-derive','NAS derives outer TLS secrets locally','netNas','netNas','Local TLS1.3 derivation',{'Derivation':'ECDHE/HKDF; decrypt server flight'},'The NAS derives equal key material independently, not by receiving server secret objects.',{held:a.create(outerNas,'netNas')});
  a.event('nas-peer-check','NAS validates TLS server and selected ALPN','netNas','netNas','Local TLS peer validation',{'Checks':'configured identity, chain, use, validity/revocation, CertificateVerify, Finished; ALPN radius/1.1'},'Certificate trust and negotiated profile must match local requirements.');
  a.event('client-flight','TLS1.3 client authentication and Finished','netNas','netServer','TLS1.3',{'TLS records':'SYM(encrypted NAS Certificate, CertificateVerify, Finished)'},'Only certificate proof, never transport private keys, traverses the connection.',{representation:'wire'});
  a.event('negotiate-check','Server validates mutual TLS and profile','netServer','netServer','Local TLS peer validation',{'Checks':'NAS certificate proof, Finished and ALPN radius/1.1 valid'},'Both peers explicitly use the Experimental profile. MD5, RADIUS shared-secret and legacy Authenticator semantics are removed.',{effects:[netPut('network.transport','radius/1.1'),netPut('network.usesMd5',false),netPut('network.usesRadiusSharedSecret',false)]});
  const password=a.object('password','Synthetic local password','netPeer',['netPeer','netNas','netServer'],'SYM(alice password)',{initial:true,type:'credential',protectedValue:'SYM(TLS encrypted User-Password text)'});
  a.object('local-verifier','Local password verifier','netServer',['netServer'],'HANDLE(alice local verifier)',{initial:true,type:'account-record'});
  a.event('input','Declared local password input','netPeer','netNas','Local credential input',{'User-Name':'alice@corp.example','Password':'SYM(alice password)'},'NAS receives this local teaching input; this is not a new EAP method.',{channel:'human',held:[a.acquire(password,'netNas')]});
  const token=a.object('token','Opaque RADIUS/1.1 transaction Token','netNas',['netNas','netServer'],'SYM(16-octet opaque Token1)',{type:'transaction'});
  a.event('token-create','Create request correlation Token','netNas','netNas','Local RFC9765 packet construction',{'Token':'SYM(16-octet opaque Token1)','Reserved':'0','Length':'encoded packet length'},'The old Identifier octet is reserved and sent zero. The 16-octet Token replaces Request/Response Authenticator and correlation Identifier.',{held:a.create(token,'netNas')});
  const decodedRequest={'Code':'1 Access-Request','NAS-Identifier':'switch.corp.example','Reserved':variant==='reserved-field-ignored'?'7':'0','Length':'20 + encoded attributes','Token':'SYM(16-octet opaque Token1)','User-Name':'alice@corp.example','User-Password':'SYM(alice password)',...variant==='Message-Authenticator-ignored'?{'Message-Authenticator':'SYM(obsolete attribute ignored if received)'}:{}};
  const request=a.event('request','RADIUS/1.1 Access-Request inside TLS','netNas','netServer','RADIUS/1.1 / TLS',{'TLS record':'SYM(TLS encrypted User-Password text)'},'Actual wire form is a TLS protected record. The packet inside uses text User-Password, not historic MD5-hidden blocks; inner fields appear only at explicit endpoint decryption.',{representation:'wire',held:[a.acquire(password,'netServer','credential inbox','wire')]});
  netExactCarrier(a,request,password,'wire',field=>field.name==='TLS record');
  a.event('decode-request','Server decrypts RADIUS/1.1 packet fields','netServer','netServer','Local RFC9765 TLS record decryption',decodedRequest,'Only the authenticated TLS endpoint recovers Code, reserved byte, opaque Token and attribute text. Normal senders omit Message-Authenticator; the named receive fixture ignores an obsolete received attribute.',{held:[a.acquire(token,'netServer','transaction inbox')]});
  request.layers=[{protocol:'TLS1.3',transport:'TCP 2083',from:'netNas',to:'netServer',protection:'Mutual TLS record confidentiality/integrity',keyRef:outerNas},{protocol:'RADIUS/1.1',transport:'Negotiated radius/1.1',from:'netNas',to:'netServer',protection:'No shared secret, MD5, legacy Authenticator or sent Message-Authenticator; Token correlation'}];
  a.event('validate','Validate profile packet and local password policy','netServer','netServer','Local RFC9765 application validation',{'Reserved octet':'ignored on reception','Token':'opaque outstanding transaction Token1','Password':'text decoded from TLS; local verifier succeeds','Obsolete Message-Authenticator':'ignored if received'},'Only permitted TLS endpoints decode the password. The selected policy is the same small local password policy, not NPS.',{held:[a.acquire(password,'netServer','credential scratch'),a.release(password,'netServer','credential inbox','wire')],effects:[netPut('network.peerIdentity',true),netPut('network.policy','accepted'),netPut('network.logicalAuthentications',1)]});
  a.event('accept','RADIUS/1.1 Access-Accept','netServer','netNas','RADIUS/1.1 / TLS',{'TLS record':'SYM(encrypted RADIUS/1.1 Access-Accept)'},'The protected TLS wire record contains the same response Token and authorization attributes; no RADIUS Response Authenticator or Message-Authenticator is generated.',{representation:'wire',effects:[netPut('network.reply','received-unverified')]});
  a.event('decode-reply','NAS decrypts RADIUS/1.1 result fields','netNas','netNas','Local RFC9765 TLS record decryption',{'Code':'2 Access-Accept','Reserved':'0','Length':'20 + encoded attributes','Token':variant==='wrong-token'?'SYM(other 16-octet Token)':'SYM(16-octet opaque Token1)','Filter-Id':'employee-wired'},'Decrypted fields are still pending transaction correlation. A decrypted Token is not an authorization by itself.');
  a.event('verify-reply','Verify TLS association and Token correlation','netNas','netNas','Local RFC9765 response validation',{'Token result':variant==='wrong-token'?'no matching transaction; discard':'matches outstanding Token1'},'A valid TLS record with the wrong Token still cannot advance another transaction.',{effects:[netPut('network.reply',variant==='wrong-token'?'discarded':'verified')]});
  if(variant!=='wrong-token'){
    const session=a.object('service-session','RADIUS/1.1 authorized NAS service','netNas',['netNas'],'SYM(session-7 employee-wired)',{type:'session'});a.inventory.bindings.push({path:'sessions.access',presentWhen:'exists',actorId:'netNas',artifactId:session,store:'local store'});
    a.event('enforce','Apply RADIUS/1.1 result','netNas','netNas','Local NAS enforcement',{'Service':'active','Filter-Id':'employee-wired'},'Only correlated verified authorization activates service.',{held:a.create(session,'netNas'),effects:[netPut('network.port','authorized'),netPut('network.status','port authorized'),netPut('sessions.access',{id:'session-7',active:true,filter:'employee-wired'})]});
  }else a.event('enforce','Discard wrong-Token response','netNas','netNas','Local NAS enforcement',{'Service':'unauthorized'},'Wrong transaction correlation creates no service.');
  a.event('server-cleanup','Server clears local request scratch','netServer','netServer','Local cleanup',{'Cleanup':'password and request Token inbox released; TLS association retained'},'Cleanup affects only server holdings.',{held:[a.release(password,'netServer','credential scratch'),a.release(token,'netServer','transaction inbox')]});
  a.event('nas-cleanup','NAS clears input and completed transaction','netNas','netNas','Local cleanup',{'Cleanup':'password input and Token transaction released'},'Only NAS input/transaction scratch is removed; initial user credential and transport configuration remain.',{held:[a.release(password,'netNas'),a.release(token,'netNas')]});
  netTransportCertificateBindings(a,transportCertificates,{serverFlight:'server-flight',clientFlight:'client-flight',nasCheck:'nas-derive',nasValidation:'nas-peer-check',serverCheck:'negotiate-check'});
  return a.finish();
}
function netRadsecPeerRejected({variant='wrong-transport-peer'}={}){
  const a=netAuthor('radsec-peer-rejected','RadSec transport peer identity rejected','transport',{actorIds:['netNas','netServer'],meta:{family:'network-transport',protocol:'RADIUS/TLS transport',standard:'RFC 6614',source:'https://www.rfc-editor.org/rfc/rfc6614',status:'experimental'},profileMetadata:netProfile('RFC6614 transport peer rejection',[6614],{status:'Experimental',algorithms:['TLS1.3 mutually authenticated transport; historic RADIUS format not reached'],transports:['TCP2083 TLS1.3'],completion:'TLS peer rejected before application RADIUS acceptance'})});
  const trust=a.object('transport-trust','Expected transport peer trust and name','netNas',['netNas'],'SYM(expected radius.corp.example; configured issuer)',{initial:true,type:'trust-record'});
  a.object('transport-private','Server transport signing key','netServer',['netServer'],'HANDLE(server transport private key)',{initial:true,type:'private-key'});
  const certificate=a.object('transport-certificate','Presented transport peer certificate','netServer',['netNas','netServer'],'SYM('+variant+' certificate)',{initial:true,type:'certificate',protectedValue:'SYM(encrypted transport server certificate flight)'});
  const traffic=a.object('nas-handshake-secret','NAS-local TLS handshake traffic secret','netNas',['netNas'],'SYM(local handshake traffic secret)',{type:'key'});
  a.event('hello','TLS1.3 ClientHello','netNas','netServer','TLS1.3',{'Endpoint':'TCP 2083','ClientHello':'fresh key_share'},'Preconfigured RadSec establishes transport before carrying RADIUS; no UDP upgrade occurs.');
  const flight=a.event('certificate','Server transport handshake flight','netServer','netNas','TLS1.3',{'TLS records':'SYM(ServerHello and encrypted Certificate, CertificateVerify, Finished)'},'NAS receives a transport certificate, not an EAP peer certificate.',{representation:'wire',held:[a.acquire(certificate,'netNas','TLS inbox','wire')]});a.inventory.events[flight.id].messages[0].objects.push({artifactId:certificate,representationId:'wire'});
  a.event('derive','NAS derives handshake secrets and decrypts certificate','netNas','netNas','Local TLS1.3 derivation',{'Derivation':'local ECDHE/HKDF','Decoded certificate':'SYM('+variant+' certificate)'},'Decryption is not trust; no RADIUS application association exists yet.',{held:[...a.create(traffic,'netNas'),a.acquire(certificate,'netNas','certificate scratch'),a.release(certificate,'netNas','TLS inbox','wire')]});
  a.event('transport-check','Validate configured transport identity','netNas','netNas','Local TLS certificate validation',{'Trust/name check':variant==='untrusted-transport-issuer'?'issuer untrusted':'configured peer name mismatch','RADIUS application traffic':'not accepted'},'The transport peer fails trust/identity before user authentication. No RADIUS or EAP rejection is inferred.',{effects:[netPut('network.transport','peer rejected'),netPut('network.status','transport failure')]});netObserve(a,'transport-check',certificate,'netNas','invalid',variant);netObserve(a,'transport-check',trust,'netNas','denied','Configured peer authentication policy not satisfied.');
  a.event('failure','Encrypted fatal transport alert','netNas','netServer','TLS1.3 alert',{'TLS alert':'SYM(encrypted certificate_unknown)','RADIUS packets':'none'},'After ServerHello the selected fatal alert is protected by TLS handshake keys; it is not Access-Reject.',{representation:'wire'});
  a.event('cleanup','NAS releases failed transport scratch','netNas','netNas','Local cleanup',{'Cleanup':'local TLS handshake key and decoded certificate scratch'},'Only local failed-handshake context is cleared.',{held:[a.release(traffic,'netNas'),a.release(certificate,'netNas','certificate scratch')]});
  a.event('server-consume','Server consumes peer alert','netServer','netServer','Local TLS failure handling',{'Application association':'not established'},'No user credentials were requested or validated.');
  return a.finish();
}
function netCloneScope(value,oldId,newId,pathPrefix){
  if(typeof value==='string'){
    if(value.startsWith(oldId+':'))return newId+value.slice(oldId.length);
    if(pathPrefix&&value.startsWith('network.'))return 'network.transactions.'+pathPrefix+'.'+value.slice(8);
    if(pathPrefix&&value.startsWith('sessions.access'))return 'sessions.'+pathPrefix+value.slice(15);
    return value;
  }
  if(Array.isArray(value))return value.map(item=>netCloneScope(item,oldId,newId,pathPrefix));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,netCloneScope(item,oldId,newId,pathPrefix)]));
  return value;
}
function netAppendScopedEap(a,base,scope,{radsec=false,outerKeys}={}){
  const scopedId=a.id+':'+scope;
  const clone=value=>netCloneScope(value,base.id,scopedId,scope);
  Object.assign(a.definitions,clone(base.definitions()));
  const ledger=base.networkInventory;
  const protectedPackets=new Set(radsec?base.steps().filter(step=>step.from!==step.to&&step.layers.some(layer=>layer.protocol==='RADIUS')).map(step=>step.netPacket):[]);
  const scopedPackets=new Set([...protectedPackets].map(clone));
  const decodedEffects=effects=>effects.map(effect=>effect.op==='release'&&scopedPackets.has(effect.artifactId)?{...effect,store:'decoded packet inbox',representationId:'radius-decoded'}:effect);
  a.inventory.artifacts.push(...clone(ledger.artifacts.filter(artifact=>!protectedPackets.has(artifact.artifactId))));
  if(radsec){
    const secret=a.inventory.artifacts.find(artifact=>artifact.artifactId===scopedId+':radius-secret:g1');
    const field=secret.representations[0].fields[0];field.value='radsec (historic RFC6614 fixed secret)';
    a.definitions[field.attributeId].example=field.value;
  }
  a.inventory.initial.push(...clone(ledger.initial));
  a.inventory.bindings.push(...clone(ledger.bindings));
  for(const original of base.steps()){
    const step=clone(original);
    delete step.netPacket;
    step.title=(radsec?'RadSec':'UDP')+' / '+step.title;
    if(protectedPackets.has(original.netPacket)){
      const key=step.id.slice(a.id.length+1),source=clone(ledger.events[original.id]);
      const innerLayers=step.layers.map(layer=>layer.protocol==='RADIUS'?{...layer,transport:'RFC6614 RADIUS inside TLS',protection:'Historic fixed secret radsec; MD5 packet mechanisms retained inside outer TLS'}:layer);
      const wire=a.event(key,step.title,step.from,step.to,'RADIUS / outer RadSec TLS1.3',{'TLS record':'SYM(outer RadSec TLS1.3 application_data '+key+' ciphertext)'},'Opaque outer TLS record on TCP 2083. RADIUS fields become available only after the receiving transport endpoint processes this record; inner EAP-TLS remains independently protected.',{representation:'outer-wire'});
      wire.layers=[{protocol:'TLS1.3 outer RadSec',transport:'TCP 2083',from:step.from,to:step.to,protection:'Mutual NAS-AAA TLS record confidentiality/integrity; no clear RADIUS fields on wire',keyRef:outerKeys[step.from],certificateRole:'Outer transport peer authentication'},...innerLayers];
      const decode=a.event(key+'-decode','RadSec endpoint decodes / '+original.title,step.to,step.to,'Local outer RadSec TLS1.3 record processing',Object.fromEntries(step.payload.map(field=>[field.name,field.value])),'The receiving TLS endpoint uses its own outer traffic secrets to recover the RADIUS envelope. This is not RADIUS integrity validation, inner EAP-TLS decryption, MSK recovery or NAS admission.',{representation:'radius-decoded',localKind:'decrypt',effects:step.protocolEffects,held:decodedEffects(source.effects.filter(effect=>effect.artifactId!==wire.netPacket))});
      decode.layers=[{protocol:'TLS1.3 outer RadSec local decode',transport:'Endpoint-local record processing',from:step.to,to:step.to,protection:'Only outer transport decryption; inner EAP-TLS records stay opaque',keyRef:outerKeys[step.to]},...innerLayers];
      const packet=a.inventory.artifacts.find(artifact=>artifact.artifactId===wire.netPacket);
      packet.representations.push({representationId:'radius-decoded',format:'Endpoint-decoded RADIUS; inner EAP-TLS still protected',readableBy:[step.to],fields:decode.payload.map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:[step.to]}))});
      a.cleanupInbox(wire,decode);
      a.inventory.events[decode.id].effects.push({...a.acquire(wire.netPacket,step.to,'decoded packet inbox','radius-decoded'),retention:'temporary'});
      continue;
    }
    if(original.id===base.id+':enforce')step.protocolEffects.push(netPut('network.comparison.'+scope,'authorized'),netPut('network.logicalAuthentications',radsec?2:1),netPut('network.status',radsec?'UDP and RadSec comparison complete':'UDP complete; RadSec transaction not yet started'),...radsec?[netPut('network.port','authorized')]:[]);
    a.steps.push(step);
    const event=clone(ledger.events[original.id]);
    a.inventory.events[step.id]={...event,effects:decodedEffects(event.effects)};
  }
}
function netTransportComparison({variant='normal'}={}){
  const udp=netWithoutRegistration(()=>netEapRepresentative('comparison-udp','Independent UDP EAP transaction'));
  const radsec=netWithoutRegistration(()=>netEapRepresentative('comparison-radsec','Independent RadSec EAP transaction'));
  const a=netAuthor('radius-udp-radsec','Classic UDP and RadSec - two visible EAP-TLS transactions','comparison',{meta:{family:'network-transport',protocol:'RADIUS/UDP versus RFC6614 RADIUS/TLS',standard:'RFC 2865 / RFC 6614',source:'https://www.rfc-editor.org/rfc/rfc6614',status:'experimental'},profileMetadata:netProfile('Paired full EAP-TLS1.3 over UDP and historic RadSec',[2865,3579,9190,5247,2548,6614],{status:'Standards Track EAP plus Experimental RFC6614 transport',algorithms:['Inner TLS1.3 EAP endpoint keys','Independent outer TLS1.3 RadSec endpoint keys','Historic fixed RADIUS/TLS secret radsec; MD5 packet rules retained'],transports:['UDP1812 first transaction','TCP2083/TLS second transaction','EAPOL on both access exchanges'],completion:'Two independently verified applications of the same employee-wired policy; distinct sessions and TLS contexts'}),initialState:{network:{comparison:{udp:'pending',radsec:'pending'},transactions:{udp:udp.initialState.network,radsec:radsec.initialState.network}},sessions:{}}});
  for(const actor of ['netNas','netServer']){
    a.object(actor+'-outer-private','Outer RadSec transport signing key',actor,[actor],'HANDLE('+actor+' outer TLS private key)',{initial:true,type:'private-key'});
    a.object(actor+'-outer-trust','Outer RadSec trust and expected peer',actor,[actor],'SYM(transport trust distinct from inner EAP issuer/name policy)',{initial:true,type:'trust-record'});
  }
  const transportCertificates=netTransportCertificateObjects(a);
  const nasOuter=a.object('nas-outer-tls','NAS local outer TLS traffic secrets','netNas',['netNas'],'SYM(outer RadSec TLS secrets)',{type:'key'});
  const serverOuter=a.object('server-outer-tls','Server local outer TLS traffic secrets','netServer',['netServer'],'SYM(outer RadSec TLS secrets)',{type:'key'});
  netAppendScopedEap(a,udp,'udp');
  a.event('outer-hello','Begin distinct RadSec transport','netNas','netServer','Outer TLS1.3',{'TCP endpoint':'2083','ClientHello':'fresh outer transport key_share','ALPN radius/1.1':'not selected'},'The completed UDP transaction is not upgraded. A second independently configured RadSec transaction establishes its own outer transport.');
  a.event('outer-server-derive','Server derives outer handshake secrets locally','netServer','netServer','Local TLS1.3 derivation',{'Derivation':'outer ECDHE/HKDF'},'Outer TLS belongs to NAS and AAA, not to the EAP peer.',{held:a.create(serverOuter,'netServer')});
  a.event('outer-server-flight','Outer server authentication flight','netServer','netNas','Outer TLS1.3',{'TLS records':'ServerHello and encrypted transport CertificateRequest, Certificate, CertificateVerify, Finished'},'These are transport credentials, never the inner EAP credential identities.',{representation:'wire'});
  if(variant==='inner-outer-TLS-confusion'){
    a.event('layer-confusion-check','Reject inner credential used as outer transport trust','netNas','netNas','Local outer TLS identity validation',{'Supplied identity':'inner EAP certificate policy','Required identity':'configured outer NAS-AAA transport peer','Result':'wrong layer, reject'},'An EAP identity cannot substitute for RadSec transport identity. The already completed UDP session remains independent.',{held:a.create(nasOuter,'netNas'),effects:[netPut('network.transport','outer peer rejected'),netPut('network.status','outer transport identity rejected')]});
    a.event('transport-failure','Send protected outer TLS alert','netNas','netServer','Outer TLS1.3 alert',{'Alert':'SYM(encrypted certificate_unknown)'},'No second RADIUS/EAP transaction is carried over this rejected outer association.',{representation:'wire'});
    a.event('outer-server-cleanup','Server consumes alert and clears own context','netServer','netServer','Local outer TLS cleanup',{'Cleanup':'server outer traffic secrets'},'UDP session and inner endpoint holdings are not removed.',{held:[a.release(serverOuter,'netServer')]});
    a.event('outer-nas-cleanup','NAS clears only rejected outer context','netNas','netNas','Local outer TLS cleanup',{'Cleanup':'NAS outer traffic secrets'},'No successful RadSec service or second session is invented.',{held:[a.release(nasOuter,'netNas')]});
    netTransportCertificateBindings(a,transportCertificates,{serverFlight:'outer-server-flight',clientFlight:'outer-client-flight',nasCheck:'layer-confusion-check',serverCheck:'transport-check',nasValid:false});
    return a.finish();
  }
  a.event('outer-nas-check','NAS derives keys and verifies outer peer','netNas','netNas','Local outer TLS validation',{'Checks':'outer configured issuer/name/use/time/revocation, CertificateVerify and Finished'},'The NAS can decrypt outer transport records, but still cannot decrypt the later peer-to-EAP-server inner TLS.',{held:a.create(nasOuter,'netNas')});
  a.event('outer-client-flight','Outer client authentication and Finished','netNas','netServer','Outer TLS1.3',{'TLS records':'SYM(encrypted NAS transport Certificate, CertificateVerify, Finished)'},'NAS proves its transport identity with its own private key; it is not the supplicant certificate.',{representation:'wire'});
  a.event('transport-check','Verify mutually authenticated outer association','netServer','netServer','Local outer TLS validation',{'Checks':'NAS transport certificate, proof and Finished valid','Historic RADIUS secret':'radsec'},'Only now can the second RADIUS transaction use the confidential transport. Ordinary RadSec does not become RADIUS/1.1.',{effects:[netPut('network.transport','TLS peer verified')]});
  // The second complete canonical EAP history has separate session/key identities.
  netAppendScopedEap(a,radsec,'radsec',{radsec:true,outerKeys:{netNas:nasOuter,netServer:serverOuter}});
  a.event('outer-server-cleanup','Server closes its outer transport context','netServer','netServer','Local outer TLS cleanup',{'Cleanup':'server outer traffic keys released'},'Server-local closure does not erase NAS transport keys or either accepted access session.',{held:[a.release(serverOuter,'netServer')]});
  a.event('outer-nas-cleanup','NAS closes its outer transport context','netNas','netNas','Local outer TLS cleanup',{'Cleanup':'NAS outer traffic keys released'},'Each endpoint clears only its own outer TLS context.',{held:[a.release(nasOuter,'netNas')]});
  netTransportCertificateBindings(a,transportCertificates,{serverFlight:'outer-server-flight',clientFlight:'outer-client-flight',nasCheck:'outer-nas-check',serverCheck:'transport-check'});
  return a.finish();
}
function netProxyUnknown(){
  const a=netAuthor('radius-proxy-unknown-realm','Unknown realm - configured proxy reject','proxy',{actorIds:['netNas','netProxy'],actorOverrides:{netNas:{position:{x:145,y:365}},netProxy:{position:{x:975,y:365}}},meta:{protocol:'RADIUS realm proxy',standard:'RFC 2865 / RFC 3579'},profileMetadata:netProfile('Configured unknown-realm reject policy',[2865,3579],{algorithms:['Adjacent NAS-proxy authenticators'],assumptions:['Static realm routes; unknown.example has no allowed route'],completion:'Proxy locally rejects; no home server is contacted'}),initialState:{network:{route:'pending',homeContacted:false}}});
  a.object('nas-proxy-secret','NAS-proxy shared secret','netNas',['netNas','netProxy'],'HANDLE(NAS-proxy secret)',{initial:true,holders:['netNas','netProxy'],type:'shared-secret'});
  const policy=a.object('route-policy','Static allowed realm routes','netProxy',['netProxy'],'SYM(corp.example -> home.corp.example; unknown.example -> local reject)',{initial:true,type:'routing-policy'});
  a.event('request','Access-Request to proxy','netNas','netProxy','RADIUS/UDP',{'Code':'Access-Request','NAS-Identifier':'switch.corp.example','Identifier':'41','Request Authenticator':'SYM(NAS RA41)','User-Name':'anonymous@unknown.example','EAP-Message':'Response/Identity id1','Message-Authenticator':'SYM(NAS-proxy HMAC)','Proxy-State':'[upstream0]'},'The proxy is the RADIUS server on this adjacent hop; no AD forest trust is consulted.');
  a.event('route','Verify NAS packet and select configured reject','netProxy','netProxy','Local proxy route policy',{'Checks':'configured NAS and valid Message-Authenticator','Realm':'unknown.example','Allowed route':'none','Policy':'local reject'},'Unknown-realm rejection is this selected local policy, not a universal required RADIUS response.',{effects:[netPut('network.route','none'),netPut('network.policy','local reject')]});netObserve(a,'route',policy,'netProxy','denied','No allowed route for unknown.example.');
  a.event('failure','Proxy Access-Reject','netProxy','netNas','RADIUS/UDP',{'Code':'Access-Reject','Identifier':'41','Response Authenticator':'SYM(NAS-proxy response41)','Message-Authenticator':'SYM(NAS-proxy HMAC)','EAP-Message':'EAP-Failure id1','Proxy-State':'[upstream0]'},'Proxy returns original upstream Proxy-State unmodified; no home-server exchange or successful EAP identity is invented.');
  a.event('failure-check','NAS validates rejection and keeps port closed','netNas','netNas','Local RADIUS validation',{'Checks':'Expected proxy, id41, authenticators valid','Port':'unauthorized'},'This trusted routing-policy rejection creates no NAS session.');
  return a.finish();
}
function netProxySuccess({variant='normal'}={}){
  const base=netWithoutRegistration(()=>netEapRepresentative('radius-proxy-realm','Realm-routed EAP-TLS proxy'));
  const a=netAuthor('radius-proxy-realm','Realm-routed EAP-TLS proxy','proxy',{attributePrefix:'netProxyRealmOuter',actorIds:['netPeer','netNas','netProxy','netServer'],actorOverrides:{netPeer:{position:{x:145,y:365}},netNas:{position:{x:560,y:365}},netProxy:{position:{x:975,y:120}},netServer:{position:{x:975,y:610}}},meta:{protocol:'EAP-TLS / per-hop RADIUS proxy',standard:'RFC 2865 / RFC 3579 / RFC 2548',source:'https://www.rfc-editor.org/rfc/rfc2865'},profileMetadata:netProfile('Static realm routing with explicit hop key access',[2865,3579,9190,5247,2548],{algorithms:['Inner TLS1.3 endpoint secrets only','Distinct NAS-proxy and proxy-home RADIUS authenticators','RFC2548 hop-protected MSK rewrapping'],transports:['EAPOL access link','NAS-proxy UDP1812','Proxy-home UDP1812'],assumptions:['corp.example routes only to home.corp.example','Proxy terminates hop protection and can recover transported MSK halves; never EMSK/private keys/inner TLS secrets'],completion:'Every adjacent reply verified, ordered Proxy-State preserved, NAS policy applied once'})});
  Object.assign(a.definitions,netCloneScope(base.definitions(),base.id,a.id));
  const basePacketIds=new Set(base.networkInventory.artifacts.filter(artifact=>artifact.type==='message').map(artifact=>artifact.artifactId));
  const oldSecret=base.id+':radius-secret:g1';
  a.inventory.artifacts.push(...netCloneScope(base.networkInventory.artifacts.filter(artifact=>!basePacketIds.has(artifact.artifactId)&&artifact.artifactId!==oldSecret),base.id,a.id));
  const keepEffect=effect=>!basePacketIds.has(effect.artifactId)&&effect.artifactId!==oldSecret;
  a.inventory.initial.push(...base.networkInventory.initial.filter(keepEffect).map(effect=>({...effect})));
  a.inventory.bindings.push(...base.networkInventory.bindings.map(binding=>({...binding})));
  const nasSecret=a.object('nas-proxy-secret','NAS-proxy adjacent secret','netNas',['netNas','netProxy'],'HANDLE(NAS-proxy secret)',{initial:true,holders:['netNas','netProxy'],type:'shared-secret'});
  const homeSecret=a.object('proxy-home-secret','Proxy-home adjacent secret','netProxy',['netProxy','netServer'],'HANDLE(proxy-home secret)',{initial:true,holders:['netProxy','netServer'],type:'shared-secret'});
  const routeValue=variant==='wrong-home-route'?'SYM(corp.example -> disallowed-home.invalid; destination not allowlisted)':'SYM(corp.example -> home.corp.example)';
  const route=a.object('realm-route','Configured realm route','netProxy',['netProxy'],routeValue,{initial:true,type:'routing-policy'});
  const forwarding=a.object('proxy-state','Own ordered Proxy-State context','netProxy',['netProxy'],'SYM(proxy1 after upstream0)',{type:'routing-context'});
  const msk=a.inventory.artifacts.find(artifact=>artifact.artifactId===a.id+':msk:g1');
  for(const key of ['netPeer-certificate','netServer-certificate']){
    const wire=a.inventory.artifacts.find(artifact=>artifact.artifactId===a.id+':'+key+':g1').representations.find(rep=>rep.representationId==='wire');
    wire.readableBy.push('netProxy');wire.fields.forEach(field=>field.readableBy.push('netProxy'));
  }
  msk.representations.find(rep=>rep.representationId==='plain').readableBy.push('netProxy');
  msk.representations.find(rep=>rep.representationId==='plain').fields.forEach(field=>field.readableBy.push('netProxy'));
  const homeWire={representationId:'home-wire',format:'RFC2548 home-to-proxy protected key carriers',readableBy:['netServer','netProxy'],fields:[]};
  msk.representations.push(homeWire);
  let routed=false;
  for(const original of base.steps()){
    const key=original.id.slice(base.id.length+1),fields=Object.fromEntries(original.payload.map(field=>[field.name,field.value]));
    const source=base.networkInventory.events[original.id];
    const effects=source.effects.filter(keepEffect).map(effect=>({...effect}));
    const backend=original.from!==original.to&&['netNas','netServer'].includes(original.from)&&['netNas','netServer'].includes(original.to);
    if(!backend){
      const verifiesReturn=original.from==='netNas'&&original.to==='netNas'&&['start-check','serverflight-check','protected-success-check','verify-reply'].includes(key);
      if(verifiesReturn)fields['Proxy-State return check']='[upstream0] matches outstanding NAS request context';
      if(original.from==='netServer'&&key==='identity-check')fields.Checks='Configured adjacent RADIUS proxy and valid Message-Authenticator; privacy-friendly claimed identity';
      if(original.from==='netNas'&&key==='verify-reply')fields['Key recovery']='RFC2548 MPPE salt + NAS-proxy secret + original NAS Request Authenticator';
      const copied=a.event(key,original.title,original.from,original.to,original.protocolLabel,fields,original.summary,{channel:original.channel,effects:[...original.protocolEffects,...(verifiesReturn?[netPut('network.proxyReturnValid',true)]:[])],held:effects,representation:original.attributeOperations[0]?.representation||'plain'});
      copied.layers=original.layers;
      // Preserve explicitly authored certificate and key receipt messages; never derive holdings from fields.
      for(const message of source.messages)for(const object of message.objects)if(!basePacketIds.has(object.artifactId))a.inventory.events[copied.id].messages[0]?.objects.push({...object});
      continue;
    }
    const outward=original.from==='netNas';
    const originalId=Number(fields['RADIUS Identifier']||fields.Identifier||41);
    const homeId=String(originalId+30);
    const ingressFields={...fields,'RADIUS Identifier':outward?String(originalId):homeId,'Proxy-State':outward?'[upstream0]':'[upstream0, proxy1]','Message-Authenticator':outward?'SYM(NAS-proxy HMAC-MD5)':'SYM(proxy-home HMAC-MD5)'};
    if(!outward&&ingressFields['Response Authenticator'])ingressFields['Response Authenticator']='SYM(proxy-home response '+homeId+' bound to corresponding proxy-home Request Authenticator)';
    if(!outward&&key==='accept'){
      ingressFields['MS-MPPE-Recv-Key']='SYM(home-proxy protected first32 MSK octets)';
      ingressFields['MS-MPPE-Send-Key']='SYM(home-proxy protected second32 MSK octets)';
    }
    const ingress=a.event(key+'-ingress',outward?'NAS sends to proxy':'Home server replies to proxy',original.from,'netProxy','RADIUS/UDP per-hop',ingressFields,'This adjacent-peer envelope terminates at the proxy. Inner EAP/TLS records remain opaque to it.',{held:!outward&&key==='accept'?[a.acquire(msk.artifactId,'netProxy','home key inbox','home-wire')]:[]});
    const certificateCarrier=key==='serverflight-backend'?a.id+':netServer-certificate:g1':key==='peerflight-backend'?a.id+':netPeer-certificate:g1':null;
    if(certificateCarrier){
      a.inventory.events[ingress.id].effects.push(a.acquire(certificateCarrier,'netProxy','TLS forwarding scratch','wire'));
      a.inventory.events[ingress.id].messages[0].objects.push({artifactId:certificateCarrier,representationId:'wire'});
    }
    ingress.layers=[{protocol:'RADIUS',transport:'UDP 1812',from:original.from,to:'netProxy',protection:'Independent adjacent Message/Response Authenticator',keyRef:outward?nasSecret:homeSecret},{protocol:'EAP-TLS1.3',transport:'Opaque EAP-Message relay',from:outward?'netPeer':'netServer',to:outward?'netServer':'netPeer',protection:'TLS record secrets only peer and EAP server; not proxy'}];
    if(variant==='wrong-hop-secret'){
      const field=ingress.payload.find(item=>item.name==='Message-Authenticator');
      field.value='SYM(invalid NAS-proxy Message-Authenticator using wrong adjacent secret)';
      a.definitions[field.attributeId].example=field.value;
      ingress.attributeOperations.filter(operation=>operation.attributeId===field.attributeId).forEach(operation=>operation.value=field.value);
      a.inventory.artifacts.find(artifact=>artifact.artifactId===ingress.netPacket).representations[0].fields.find(item=>item.attributeId===field.attributeId).value=field.value;
    }
    const invalid=variant==='wrong-hop-secret';
    a.event(key+'-proxy-check','Verify incoming hop and return context','netProxy','netProxy','Local RADIUS proxy validation',{'Adjacent peer':outward?'NAS':'home server','Integrity':invalid?'invalid selected hop secret':'valid','Proxy-State':outward?'preserve [upstream0], append own proxy1':'verify ordered [upstream0,proxy1], remove own last entry only'},'Proxy-State is per-hop forwarding context, not server-issued EAP State; State and EAP-Message are forwarded unchanged.',{held:!outward&&key==='accept'?[a.acquire(msk.artifactId,'netProxy','MSK forwarding scratch'),a.release(msk.artifactId,'netProxy','home key inbox','home-wire')]:[]});
    if(invalid){
      a.event('discard','Proxy silently discards invalid adjacent packet','netProxy','netProxy','Local silent discard',{'Reason':'wrong-hop-secret','Home forwarding':'none for this invalid request'},'Invalid hop integrity is not an invented Access-Reject. No NAS admission occurs.',{effects:[netPut('network.status','invalid proxy hop discarded')]});
      a.event('timeout','NAS observes proxy timeout','netNas','netNas','Local scripted timeout',{'Trusted reply':'none'},'No local timer removes remote credentials or creates access.');
      // No method context was created at home on this first invalid request.
      return a.finish();
    }
    if(!routed){
      a.event('route','Select configured home realm','netProxy','netProxy','Local realm routing policy',{'User-Name':'anonymous@corp.example','Route':routeValue,'No AD trust inference':'static route only'},'Proxy selects a configured realm candidate only after validating its adjacent NAS request, then checks destination authorization.',{held:a.create(forwarding,'netProxy'),effects:[netPut('network.route',variant==='wrong-home-route'?'disallowed candidate':'corp.example -> home.corp.example'),netPut('network.homeContacted',false)]});netObserve(a,'route',route,'netProxy',variant==='wrong-home-route'?'denied':'valid','Exact configured realm route and destination allowlist.');
      routed=true;
    }
    if(variant==='wrong-home-route'){
      a.event('route-rejected','Reject untrusted home-route configuration','netProxy','netProxy','Local realm route authorization',{'Route':'disallowed home target','Forwarding':'none'},'A configured but unauthorized home route is not followed; no home-server authentication or NAS admission is invented.',{held:[a.release(forwarding,'netProxy')],effects:[netPut('network.homeContacted',false),netPut('network.route','rejected'),netPut('network.status','route rejected')]});
      a.event('timeout','NAS sees no trusted result','netNas','netNas','Local scripted timeout',{'Trusted result':'none'},'No valid result exists to admit this transaction.');
      return a.finish();
    }
    const outgoingFields={...fields,'RADIUS Identifier':outward?homeId:String(originalId),'Proxy-State':outward?'[upstream0, proxy1]':variant==='Proxy-State-order'?'[proxy1, upstream0]':'[upstream0]','Message-Authenticator':outward?'SYM(proxy-home HMAC-MD5)':'SYM(NAS-proxy HMAC-MD5)'};
    if(outgoingFields['Request Authenticator'])outgoingFields['Request Authenticator']='SYM('+(outward?'proxy-home':'NAS-proxy')+' request '+(outward?homeId:originalId)+')';
    if(outgoingFields['Response Authenticator'])outgoingFields['Response Authenticator']='SYM('+(outward?'proxy-home':'NAS-proxy')+' response '+(outward?homeId:originalId)+')';
    const forwarded=a.event(key,outward?'Proxy forwards to home':'Proxy returns to NAS','netProxy',original.to,'RADIUS/UDP per-hop',outgoingFields,outward?'Proxy appends only its own context and reauthenticates for the independent home association.':'Proxy removes only its own Proxy-State, preserves ordered upstream values and reauthenticates for NAS.',{effects:[...original.protocolEffects,netPut('network.proxyState',outward?['upstream0','proxy1']:variant==='Proxy-State-order'?['proxy1','upstream0']:['upstream0'])],held:[...effects,...(!outward&&key==='accept'?[a.release(msk.artifactId,'netProxy','MSK forwarding scratch')]:[])],representation:original.attributeOperations[0]?.representation||'plain'});
    if(outward)forwarded.protocolEffects.push(netPut('network.homeContacted',true));
    if(certificateCarrier)a.inventory.events[forwarded.id].effects.push(a.release(certificateCarrier,'netProxy','TLS forwarding scratch','wire'));
    forwarded.layers=[{protocol:'RADIUS',transport:'UDP 1812',from:'netProxy',to:original.to,protection:'Independent adjacent integrity and RFC2548 key hiding',keyRef:outward?homeSecret:nasSecret},{protocol:'EAP-TLS1.3',transport:'Unchanged EAP-Message',from:outward?'netPeer':'netServer',to:outward?'netServer':'netPeer',protection:'Endpoint-only TLS confidentiality; proxy cannot read certificates encrypted by TLS1.3'}];
    for(const message of source.messages)for(const object of message.objects)if(!basePacketIds.has(object.artifactId))a.inventory.events[forwarded.id].messages[0].objects.push({...object});
    if(!outward&&variant==='Proxy-State-order'){
      a.event('proxy-state-check','NAS rejects malformed ordered return context','netNas','netNas','Local RADIUS correlation check',{'Proxy-State':'[proxy1,upstream0] does not match expected upstream context','Result':'discard, no port admission'},'Reordered or unremoved proxy context is not treated as a valid return for the outstanding request.',{held:[a.release(a.id+':eap-context:g1','netNas','pending challenge')],effects:[netPut('network.status','invalid proxy return context')]});
      a.steps.at(-1).protocolEffects.push(netPut('network.proxyReturnValid',false),netPut('network.reply','discarded'));
      a.event('home-cleanup','Home releases abandoned method context','netServer','netServer','Local method cleanup',{'Cleanup':'issued challenge context only'},'Only the server clears its own abandoned challenge.',{held:[a.release(a.id+':eap-context:g1','netServer')]});
      a.event('proxy-cleanup','Proxy clears own rejected context','netProxy','netProxy','Local cleanup',{'Cleanup':'proxy1 context'},'No NAS or peer context is removed by proxy cleanup.',{held:[a.release(forwarding,'netProxy')]});
      return a.finish();
    }
    if(!outward&&key==='accept'){
      homeWire.fields=ingress.payload.filter(field=>field.name.startsWith('MS-MPPE-')).map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:['netServer','netProxy']}));
      a.inventory.events[ingress.id].messages[0].objects.push({artifactId:msk.artifactId,representationId:'home-wire'});
      msk.representations.find(rep=>rep.representationId==='wire').fields=forwarded.payload.filter(field=>field.name.startsWith('MS-MPPE-')).map(field=>({attributeId:field.attributeId,name:field.name,value:field.value,readableBy:['netProxy','netNas']}));
      msk.representations.find(rep=>rep.representationId==='wire').readableBy=['netProxy','netNas'];
      netObserve(a,key+'-proxy-check',msk.artifactId,'netProxy','valid','Proxy legitimately unwraps protected home-hop MSK halves, rewraps them for NAS and deletes forwarding scratch; no EMSK access.');
    }
  }
  a.event('proxy-cleanup','Proxy releases its own forwarding context','netProxy','netProxy','Local proxy cleanup',{'Cleanup':'own proxy1 routing context released; no inner TLS key ever held'},'Only proxy forwarding context is removed; independently installed NAS key/cache/session remains.',{held:[a.release(forwarding,'netProxy')]});
  return a.finish();
}
const netPresetDefinitions=[
  ['radius-password-accept','network-access',2865,variant=>variant==='normal'?netPasswordRepresentative():netPasswordChoice('radius-password-accept','RADIUS password accept - controlled input',{reject:variant==='invalid-password',variant}),['invalid-password','invalid-response-authenticator','wrong-recipient']],
  ['radius-password-reject','network-access',2865,variant=>netPasswordChoice('radius-password-reject','RADIUS password reject',{reject:true,variant}),['timeout-is-not-reject']],
  ['radius-password-totp','network-access',2865,variant=>netPasswordChoice('radius-password-totp','Password plus TOTP challenge',{challenge:true,invalidTotp:variant==='expired-TOTP',variant}),['missing-State','altered-State','expired-TOTP']],
  ['radius-challenge-rejected','network-access',2865,variant=>netPasswordChoice('radius-challenge-rejected','TOTP challenge rejected',{challenge:true,invalidTotp:true,variant}),['invalid-TOTP','expired-TOTP','missing-State','altered-State']],
  ['eap-tls13-wired','network-access',9190,variant=>netEapRepresentative('eap-tls13-wired','Wired 802.1X EAP-TLS 1.3',{variant}),['invalid-Message-Authenticator','wrong-RADIUS-Identifier','wrong-EAP-Identifier','reordered-EAP-Message','fragment-sequence']],
  ['eap-server-cert-rejected','network-access',9190,variant=>netEapRepresentative('eap-server-cert-rejected','EAP server certificate rejected',{failure:'server',variant:variant==='normal'?'untrusted-issuer':variant}),['untrusted-issuer','wrong-server-name','expired-server-cert','revoked-server-cert']],
  ['eap-client-cert-rejected','network-access',9190,variant=>netEapRepresentative('eap-client-cert-rejected','EAP client certificate rejected',{failure:'client',variant:variant==='normal'?'inappropriate-client-EKU':variant}),['bad-client-chain','inappropriate-client-EKU','expired-client-cert','revoked-client-cert']],
  ['eap-policy-denied','network-access',9190,variant=>netEapRepresentative('eap-policy-denied','Valid certificate identity, access policy denied',{failure:'policy',variant:variant==='normal'?'unauthorized-group':variant}),['unauthorized-group','disallowed-NAS']],
  ['nps-ad-tls12','network-access',5216,variant=>netNps('nps-ad-tls12','NPS AD DS full EAP-TLS 1.2',{variant}),['UPN-only-mapping','missing-SID-binding','group-denied']],
  ['nps-mapping-rejected','network-access',5216,variant=>netNps('nps-mapping-rejected','NPS strong certificate mapping rejected',{mappingRejected:true,variant}),['UPN-only-mapping','missing-SID-binding']],
  ['radius-accounting-lifecycle','network-lifecycle',2866,variant=>netAccounting({variant}),['lost-accounting-response','duplicate-accounting-request']],
  ['radius-udp-radsec','network-transport',6614,variant=>netTransportComparison({variant}),['inner-outer-TLS-confusion']],
  ['radsec-peer-rejected','network-transport',6614,variant=>netRadsecPeerRejected({variant:variant==='normal'?'wrong-transport-peer':variant}),['wrong-transport-peer','untrusted-transport-issuer']],
  ['radius-proxy-realm','network-access',2865,variant=>netProxySuccess({variant}),['wrong-home-route','wrong-hop-secret','Proxy-State-order']],
  ['radius-proxy-unknown-realm','network-access',2865,()=>netProxyUnknown(),['unknown-realm']],
  ['radius-coa-ack','network-lifecycle',5176,variant=>netDynamic('radius-coa-ack','CoA changes an existing session filter',{variant}),['lost-CoA-ACK','duplicate-CoA-request','untrusted-client','invalid-request-authenticator','wrong-recipient','stale-Event-Timestamp']],
  ['radius-coa-nak','network-lifecycle',5176,variant=>netDynamic('radius-coa-nak','CoA request rejected without policy change',{nak:true,variant}),['unsupported-service','unsupported-attribute','session-not-found','stale-Event-Timestamp']],
  ['radius-disconnect-ack','network-lifecycle',5176,variant=>netDynamic('radius-disconnect-ack','Disconnect target session then acknowledge',{disconnect:true,variant}),['lost-Disconnect-ACK','duplicate-Disconnect-request','stale-session','stale-Event-Timestamp']],
  ['radius-disconnect-nak','network-lifecycle',5176,variant=>netDynamic('radius-disconnect-nak','Disconnect absent session NAK',{disconnect:true,nak:true,variant}),['session-not-found','untrusted-client','invalid-request-authenticator','stale-Event-Timestamp']],
  ['radius-udp-retransmission','network-lifecycle',5080,variant=>netPasswordChoice('radius-udp-retransmission','Lost UDP reply and duplicate-safe retry',{retry:true,variant}),['late-reply','wrong-transaction','invalid-response-authenticator']],
  ['enterprise-wifi-eap','network-access',9190,variant=>netEapRepresentative('enterprise-wifi-eap','Enterprise Wi-Fi - bounded EAP decision',{wifi:true,variant}),['no-usable-protected-link']],
  ['radius11','network-transport',9765,variant=>netRadius11('radius11','Experimental negotiated RADIUS/1.1',{variant}),['Message-Authenticator-ignored','reserved-field-ignored','wrong-token']],
  ['radius11-required-unavailable','network-transport',9765,variant=>netRadius11('radius11-required-unavailable','Required RADIUS/1.1 unavailable',{unavailable:true,variant}),['absent-ALPN','only-radius10','no-common-ALPN']],
];
function netFreezeData(value){
  if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(netFreezeData);Object.freeze(value);}
  return value;
}
function netBuildPreset(preset,variant){
  const [suffix,family,number,build]=preset,model=build(variant);
  const primary=NETWORKLAB_SOURCES.find(source=>source.standard==='RFC '+number);
  model.family=family;model.standard=primary.standard;model.source=primary.url;
  if(['radius-password-accept','radius-password-reject','radius-udp-retransmission'].includes(suffix))model.profile=netProfile('RFC 2865 PAP-style password',[2865,5080],{algorithms:['Classic MD5 password hiding and response integrity; legacy comparison only'],transports:['Declared local credential input','RADIUS/UDP 1812'],assumptions:['Local synthetic account verifier','Configured adjacent-peer secret','Request correlation and RFC5080 duplicate handling'],completion:'NAS verifies and applies accepted supported authorization before one service becomes active'});
  if(suffix==='enterprise-wifi-eap')model.profile={...model.profile,id:'net-eap13-bounded-wifi-v1'};
  model.initialState=netFreezeData(model.initialState);
  if(number===6614||number===9765)model.status='experimental';
  if(['pap','totp'].some(profile=>model.profile.id.includes(profile)))model.supportNote+=' Classic UDP is a legacy transport comparison, not a recommended new deployment.';
  if(suffix==='radius-udp-radsec'||suffix.startsWith('radius11'))model.relatedLessons=[
    {id:'lab-net-radius-udp-radsec',title:'UDP and historic RadSec',summary:'Same EAP policy in two complete independently scoped transactions; ordinary RadSec retains historic packet mechanisms.'},
    {id:'lab-net-radius11',title:'Negotiated RADIUS/1.1',summary:'Experimental ALPN radius/1.1 changes packet correlation and removes MD5/shared-secret mechanisms only on the negotiated association.'},
  ].filter(link=>link.id!==model.id);
  return model;
}
export const NETWORKLAB_SCENARIOS=netPresetDefinitions.map(preset=>netBuildPreset(preset,'normal'));
// Verification-only named inputs, never catalog additions or runtime context mutations.
export function buildNetworkScenarioFixture(id,{variant='normal'}={}){
  const preset=netPresetDefinitions.find(row=>'lab-net-'+row[0]===id);
  if(!preset)throw new RangeError('Unknown network fixture '+id);
  if(variant!=='normal'&&!preset[4].includes(variant))throw new RangeError('Unknown named network input '+variant);
  return netWithoutRegistration(()=>{
    const model=netBuildPreset(preset,variant);
    model.negativeVariant=variant;
    return model;
  });
}
