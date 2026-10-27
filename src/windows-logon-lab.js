import {labAttribute,labP,labStep,labScenario} from './lab-common.js';
import {CRYPTOLAB_SCENARIOS} from './kerberos-crypto-lab.js';
import {SMBLAB_SCENARIOS} from './smb-access-lab.js';
import {buildKerberosHeldObjects} from './held-object-kerberos.js';
const wslFieldCatalog=new Map();
const wslCryptoSourceCache=new Map();
export function wslAcceptedCrypto(sourceId){
  if(!wslCryptoSourceCache.has(sourceId)){const source=CRYPTOLAB_SCENARIOS.find(model=>model.id===sourceId);if(!source)throw new RangeError('Unknown accepted crypto source: '+sourceId);wslCryptoSourceCache.set(sourceId,wslFreeze(source.contextualize({kerberosRealm:'CORP.EXAMPLE',servicePrincipal:'host/workstation.corp.example'})));}
  return wslCryptoSourceCache.get(sourceId);
}
const wslPrerequisites={
  WLOG01:['WORKGROUPPC local standard bob account; local SAM password provider.','Interactive logon allowed unless named deny-right case; no domain/cloud/Hello/automatic sign-in.'],
  WLOG02:['AD DS member WORKSTATION; CORP\\alice, working DC/DNS/time/machine relationship.','Selected AES password preauthentication; FAST isolated in WLOG06; no implicit NTLM fallback.'],
  WLOG03:['Domain member with distinct local WORKSTATION\\alice and CORP\\alice SIDs/password fixtures.','Explicit .\\alice selects only local SAM; no authority guessing.'],
  WLOG04:['Prior successful online CORP\\alice password sign-in; cache count10 and retained entry unless changed by a named case.','DC unreachable, not rejecting; new session has no live TGT. Protected Users prohibits cached-verifier creation.'],
  WLOG05:['Provisioned nonexportable smart-card key and public certificate; current strong SID or issuer/serial account binding.','Accepted RFC4556 fresh-DH reference, not a literal Windows trace; current MS-PKCA24.0 CMS/checksum/freshness and CG nonce gates are recorded.','Offline smart-card, PKINIT+FAST and WHfB trust mechanisms remain separately unsatisfied research branches.'],
  WLOG06:['AD DS member, RequireFAST=true, client/DC/realm support and usable preexisting computer TGT.','Accepted AD04 protected challenge/finished/reply-strengthening history; bootstrap and optional fallback are separately linked lessons.'],
  WLOG07:['Existing locked/unlocked session, token and process identities seeded explicitly.','Domain-required profile sets RequireDC=true and cache count0; cached profile uses cache count10 and stale facts.'],
  WLOG08:['Nonjoined WORKGROUPPC local bob; domain console sign-in not supported by this selected fixture.','Explicit CORP\\alice credentials are later supplied to a fresh accepted SMB journey.','Default is configured Kerberos. Named bad-password/share-denial comparisons explicitly select existing NTLMv2 fixtures before playback, never after a Kerberos failure.'],
  WELEV01:['Classic Admin Approval Mode, named non-built-in administrator and UAC enabled.','High-integrity comparison is a separate previously authorized context, not automatic elevation after denial.'],
  WELEV02:['Classic Admin Approval Mode; administrator consent on secure desktop; no auto-elevation.','Correlated harmless helper explicitly requests elevation; original process/session remain independent.'],
  WELEV03:['Existing standard-user desktop; policy prompts for a separate administrator credential.','Local admin2 uses SAM; named CORP admin2 uses reachable domain Kerberos plus local administrator eligibility.'],
  WELEV04:['Secondary Logon available; /user:WORKSTATION\\operator, not /netonly.','Selected alternate account has local logon right; /profile versus /noprofile is explicit. Native runas help/error observation remains unavailable.'],
  WELEV05:['Existing local bob desktop; LOGON_NETCREDENTIALS_ONLY / NewCredentials, with no same-server SMB session unless comparison changes it.','No authority validation at launch. Configured Kerberos default; bad-password/share-denial use explicitly selected accepted NTLMv2 comparison fixtures.'],
  WELEV06:['Windows11 Enterprise25H2 reference26200.9711 / KB5127648; Administrator-protection mode1 and credential-prompt1, reboot assumed.','Availability evidence does not resolve the retained CSP Insider applicability label or replace missing native policy/token/log observations.','One isolated process, no children/extra references; no inherited domain/cloud SSO or invented Hello internals.']
};

export const WINDOWSLOGONLAB_ATTRIBUTES={};
export const WINDOWSLOGONLAB_SOURCES=[
  {id:'next-windows-W-S01',name:'Credential provider and LSA boundaries',url:'https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication',revision:'Captured official page; see source matrix'},
  {id:'next-windows-W-S06',name:'Access-token fields and lifetime',url:'https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens',revision:'2025-07-08'},
  {id:'next-windows-W-S33',name:'MS-KILE interactive logon and FAST',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9',revision:'49.0 / 2026-09-28'},
  {id:'next-windows-W-S12',name:'MS-PKCA smart-card logon and product gates',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-PKCA/d0cf1763-3541-4008-a75f-a577fa5e8c5b',revision:'24.0 / 2026-03-09'},
  {id:'next-windows-W-S09',name:'Credential Guard custody and exclusions',url:'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works',revision:'2025-06-12'},
  {id:'next-windows-W-S32',name:'Pinned Windows 11 servicing reference',url:'https://support.microsoft.com/en-us/servicing/os/windows-11/2026/10/kb5127648-windows-11-24h2-25h2-26h2-security-update',revision:'2026-10-13 / KB5127648'}
].map(source=>({...source,standard:source.name,section:'See independently captured source matrix for exact sections',retrieved:'2026-10-21',errata:'No native platform conformance or installed-build observation claimed.'}));
const wslSource='https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens';
export function wslFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(wslFreeze);Object.freeze(value);}return value;}
// Expanded OS roles use explicit cells, not a sub-card-height vertical stack.
// The external-inventory layout still has to fit every physical card in 1120x730.
const wslActorPositions=wslFreeze({
  wslUser:{x:110,y:120},wslUI:{x:335,y:120},wslLSA:{x:560,y:120},
  wslPackage:{x:785,y:120},wslDC:{x:1010,y:120},
  wslCard:{x:110,y:365},wslSAM:{x:335,y:365},wslIso:{x:560,y:365},
  wslMachine:{x:785,y:365},wslFile:{x:1010,y:365},
  wslProcess:{x:110,y:610},wslBroker:{x:335,y:610},wslChild:{x:560,y:610},
  wslObject:{x:785,y:610},wslNetwork:{x:1010,y:610},
  wslWorkstation:{x:560,y:120}
});
export function wslToken(id,account='WORKGROUPPC\\bob',options={}){
  const domain=account.startsWith('CORP\\'),admin=options.admin===true,full=options.full===true;
  return {tokenId:id,owner:'kernel token authority',type:'primary',account,userSid:options.sid||(domain?'S-1-5-21-440-550-660-1101':account.endsWith('alice')?'S-1-5-21-110-220-330-1002':account.endsWith('admin2')?'S-1-5-21-110-220-330-1003':account.endsWith('operator')?'S-1-5-21-110-220-330-1004':'S-1-5-21-110-220-330-1001'),authenticationId:options.luid||'LUID(0x0:0x7101)',groups:[{sid:'S-1-5-32-545',attributes:['enabled','mandatory'],source:'local alias policy'},...(domain?[{sid:'S-1-5-21-440-550-660-513',attributes:['enabled','mandatory'],source:'domain authorization data'}]:[]),...(admin?[{sid:'S-1-5-32-544',attributes:full?['enabled','owner']:['deny-only'],source:'local administrator membership'}]:[])],privileges:[{name:'SeChangeNotifyPrivilege',enabled:true},...(admin&&full?[{name:'SeDebugPrivilege',enabled:false},{name:'SeBackupPrivilege',enabled:false}]:[])],integrity:full?'high':'medium',integritySid:full?'S-1-16-12288':'S-1-16-8192',elevationType:admin?(full?'Full':'Limited'):'Default',elevated:full,lifetime:'until final token reference released; session lifetime is independent',sourceIdentity:domain?'validated domain identity/group facts':'local SAM identity/group facts',localPolicyProvenance:'explicit workstation alias membership, rights and privileges',...options};
}
export function wslAuthor(meta,inputs,attributeRegistry){
  const candidateInvalid=inputs.passwordMatches===false||inputs.pinValid===false||inputs.userProofValid===false||(meta.code==='WELEV05'&&inputs.networkPasswordValid===false);
  inputs={...inputs,credentialCandidate:candidateInvalid?'SYM(selected invalid credential fixture)':'SYM(selected valid credential fixture)'};
  const inputFixture={candidate:inputs.credentialCandidate,expected:'SYM(selected valid credential fixture)'};
  const id=meta.id,prefix=id.replace(/-/g,'_')+'_';
  const definitions={},artifacts=[],initial=[],events={},bindings=[],steps=[];
  // Protection compositions opt into owner-local lifecycle events. Legacy logon
  // lessons keep their authored cleanup boundaries and authority fixtures.
  const ownerLocalCleanup=meta.family==='windows-protection';
  const reuse=[];
  let completedModel;
  const actors={
    wslUser:{id:'wslUser',name:'User',role:'Local interactive input',kind:'client',color:'#2563eb'},
    wslWorkstation:{id:'wslWorkstation',name:'Physical Windows workstation',role:'One local OS boundary; child roles remain distinct owners',kind:'client',color:'#2563eb'},
    wslUI:{id:'wslUI',parentId:'wslWorkstation',name:'LogonUI / Winlogon',role:'Credential collection and result display',kind:'client',color:'#2563eb'},
    wslLSA:{id:'wslLSA',parentId:'wslWorkstation',name:'Workstation LSA / LSASS',role:'Local authentication and logon policy',kind:'service',color:'#08916d'},
    wslPackage:{id:'wslPackage',parentId:'wslLSA',name:'Selected authentication package',role:'In-process LSASS module; not a second credential database or network peer',kind:'service',color:'#08916d'},
    wslSAM:{id:'wslSAM',parentId:'wslLSA',name:'SAM / protected local cache',role:'Local account or cached verifier authority',kind:'authenticator',color:'#7c3aed'},
    wslProcess:{id:'wslProcess',parentId:'wslWorkstation',name:'Kernel token / user processes',role:'Local token, profile and desktop',kind:'service',color:'#b45309'}
  };
  const state={deviceMembership:inputs.joined?'AD DS member':'workgroup',consoleAuthority:inputs.authority||'WORKGROUPPC',localAccount:null,localSid:null,outboundAccount:null,effectivePolicy:{credentialGuard:'enabled; domain TGT protected by LSAIso/VBS, SAM/cache/service tickets excluded',denyInteractive:!!inputs.denyInteractive},credentialVerified:false,consoleAllowed:false,token:null,sessionId:null,processId:null,desktopReady:false,locked:false,resourceAllowed:null,tgtAccepted:false,hostTicketAccepted:false,networkAuthenticated:false,clientKnowsResult:false,detector:null,failure:null,...meta.initial};
  state.privilegeState=state.token?state.token.integrity+' / '+state.token.elevationType:'no process token created';
  state.verifierAuthority=meta.code==='WLOG04'?'protected local cached verifier':meta.code==='WLOG07'?(inputs.unlockMode==='domain-required'?'CORP DC required':inputs.unlockMode==='domain-cached'?'local cached unlock verifier':'local SAM unlock verifier'):meta.code==='WELEV02'?'consent only; no new password verification':meta.code==='WELEV05'?'none at launch; deferred network authority':meta.code==='WELEV06'?'configured OS verification boundary':meta.code==='WELEV03'?(inputs.alternateAuthority==='CORP'?'CORP KDC then local eligibility':'local SAM then administrator eligibility'):['WLOG02','WLOG05','WLOG06'].includes(meta.code)?'CORP KDC then local workstation admission':'local SAM / selected local policy';
  state.failureStage=null;state.failureReason=null;state.authenticationPackage=['WLOG02','WLOG05','WLOG06'].includes(meta.code)||inputs.unlockMode==='domain-required'||inputs.alternateAuthority==='CORP'?'Kerberos':meta.code==='WELEV05'?'Negotiate / NewCredentials deferred context':meta.code==='WELEV02'?'none: classic consent reuses existing authentication':meta.code==='WELEV06'?'OS platform verification boundary; internal provider unmodeled':'MSV1_0 / selected local or cached validation';
  // Lifecycle belongs to the holding, not readability or a successful authentication verdict.
  function acquire(o,actor,store=o.store,representationId='plain',retention=o.retention){return {op:'acquire',artifactId:o.artifactId,actorId:actor,store,representationId,retention,holdingId:[actor,o.artifactId,representationId,store].join('|')};}
  function object(key,label,type,creator,value,readers=[creator],options={}){
    const attributeId=prefix+key.replace(/-/g,'_'),artifactId=id+':'+key;
    definitions[attributeId]=labAttribute(label,options.meaning||label+' in this explicitly selected Windows fixture.',creator,options.purpose||'Separate identity, credential custody and local authorization. Read permission alone grants no holding.',value,options.standard||'Windows security API reference',options.source||wslSource);
    if(attributeRegistry)attributeRegistry[attributeId]=definitions[attributeId];
    const representations=[{representationId:'plain',format:'symbolic Windows reference value',readableBy:readers,fields:[{attributeId,name:label,value,readableBy:readers}]}];
    if(options.wire)representations.push({representationId:'wire',format:options.wireFormat||'protected Kerberos envelope',readableBy:[],fields:[{attributeId,name:label+' envelope',value:options.wire,readableBy:[]}],protection:options.wire});
    // Durable policy and live OS contexts survive the attempt. Input, protocol work
    // buffers and validation scratch are scoped to it unless explicitly installed.
    const retention=options.retention||(['policy','token','session','process','certificate','result','data'].includes(type)?'retained':'temporary');
    const o={artifactId,attributeId,key,type,label,creator,generation:1,value,readers,representations,store:options.store||'local security state',wire:options.wire,retention};artifacts.push(o);return o;
  }
  function seed(o,holders=[o.creator]){o.retention='retained';initial.push({op:'create',artifactId:o.artifactId},...holders.map(a=>acquire(o,a)));return o;}
  function add(stage,title,from,to,{objects=[],creates=[],uses=[],verify=[],receives=[],releases=[],puts={},type='local-check',wire=false,representation='plain',summary=title,checkResult='accepted',protocolLabel=null,layers=null}={}){
    const stepId=id+':'+stage,effects=[],ops=[];
    const occurrence=(o,actor,kind,representation='plain')=>({attributeId:o.attributeId,instanceId:o.artifactId,creator:o.creator,holders:[actor],inspectors:representation==='wire'?[]:o.readers,fieldPath:(representation==='wire'?'envelope.':'decoded.')+o.key,representation,value:representation==='wire'?o.wire:o.value,sourceEventId:stepId,exactValueRef:o.artifactId+':'+representation,actorId:actor,kind,detail:kind+' '+o.label+' at '+stage+'. '+(wire?'Actual declared network carrier.':'Local OS state or distinct-owner IPC; not an OS wire protocol.')});
    for(const o of creates){effects.push({op:'create',artifactId:o.artifactId},acquire(o,o.creator));ops.push(occurrence(o,o.creator,'create'));if(o.wire){effects.push(acquire(o,o.creator,'serialized protected envelope','wire','temporary'));ops.push(occurrence(o,o.creator,'create','wire'));}}
    for(const o of uses){
      ops.push(occurrence(o,from,'use'));
      if(!verify.includes(o))effects.push({op:'observe',artifactId:o.artifactId,actorId:from,representationId:'plain',kind:'knowledge',result:'use at '+stage});
    }
    for(const o of verify){ops.push({...occurrence(o,from,'verify'),detail:checkResult+': '+summary});effects.push({op:'observe',artifactId:o.artifactId,actorId:from,kind:'verification',result:checkResult,representationId:'plain'});}
    for(const o of objects){const rep=(wire||representation==='wire')&&o.wire?'wire':'plain';if(from!==to){ops.push(occurrence(o,from,'send',rep),occurrence(o,to,'receive',rep));effects.push(acquire(o,to,wire?'network inbox':'local IPC inbox',rep,rep==='wire'?'temporary':o.retention));}else if(!creates.includes(o)&&!uses.includes(o)&&!verify.includes(o))ops.push(occurrence(o,from,'inspect',rep));}
    for(const entry of receives){const o=entry.object;effects.push(acquire(o,entry.actor,entry.store||o.store,entry.representation||'plain',entry.retention||o.retention));ops.push(occurrence(o,entry.actor,entry.kind||'store',entry.representation||'plain'));}
    for(const entry of releases){const o=entry.object,actor=entry.actor||o.creator,store=entry.store||o.store,rep=entry.representation||'plain';effects.push({op:'release',holdingId:entry.holdingId||[actor,o.artifactId,rep,store].join('|')});ops.push(occurrence(o,actor,'evict',rep));}
    const visible=[...new Set([...objects,...creates,...uses,...verify,...receives.map(e=>e.object),...releases.map(e=>e.object)])];
    const step=labStep(stepId,title,from,to,meta.phase||'Windows workstation',wire?'backchannel':'internal',summary,summary,visible.map(o=>o.attributeId),visible.map(o=>labP(o.label,(wire||representation==='wire')&&o.wire?o.wire:o.value,definitions[o.attributeId].meaning,o.attributeId)),['Credential validation, local admission, token creation and resource access are separate.','Synthetic offline values; no native Windows execution claim.'],ops);
    step.eventType=type;step.workstationStage=stage;step.protocolLabel=protocolLabel||(wire?'Kerberos over TCP/88':from===to?'Local OS operation':['wslLSA','wslSAM','wslPackage'].includes(from)&&['wslLSA','wslSAM','wslPackage'].includes(to)?'Local in-process OS call':'Local OS input, IPC or handle transfer');step.beginnerSummary=summary;
    step.layers=layers||(wire?[{protocol:'Kerberos',transport:'TCP / port88',from,to,protection:'Field-specific Kerberos protection; symbolic keys, not TLS'}]:[]);
    if(puts.token)puts.privilegeState=puts.token.integrity+' / '+puts.token.elevationType;
    if(puts.failure){puts.failureStage=puts.failure.stage;puts.failureReason=puts.failure.reason;}
    step.protocolEffects=Object.entries(puts).map(([path,value])=>({op:'put',path:'workstation.'+path,value}));
    events[stepId]={milestones:[{id:'complete',at:1,effects}],...(from!==to&&objects.length?{messages:[{messageId:stepId+(wire?':network':':local-IPC'),from,to,objects:objects.map(o=>({artifactId:o.artifactId,representationId:(wire||representation==='wire')&&o.wire?'wire':'plain'})),start:0,end:1}]}:{})};steps.push(step);return step;
  }
  function deny(stage,detector,reason,buffer,scratch=[],checks={}){
    const result=object('failure-'+stage,'Attempt failure at '+stage,'result',detector,{stage,reason,...(checks.request?{requestId:checks.request.value.requestId,operation:checks.request.value.operation,credentialContextRef:checks.request.value.credentialContextRef}:{})},[...new Set([detector,'wslLSA','wslUI',...(checks.viaActors||[]),...(checks.replyActor?[checks.replyActor]:[])])]);
    add(stage,'Reject: '+reason,detector,detector,{...checks,checkResult:'rejected',creates:[result],puts:{...(checks.puts||{}),failure:{stage,reason},detector,clientKnowsResult:false},summary:reason+' Only the detector knows this outcome now.'});
    if(checks.replyActor){const route=[detector,...(checks.viaActors||[]),checks.replyActor];for(let n=1;n<route.length;n++)add(stage+'-result-'+n,'Return the scoped local operation result to its actual consumer',route[n-1],route[n],{objects:[result],puts:n===route.length-1?{clientKnowsResult:true}:{},wire:route[n-1]==='wslDC'&&route[n]==='wslLSA',type:route[n-1]==='wslDC'?'network-exchange':'local-result'});}
    else{if(detector!=='wslLSA')add(stage+'-return','Return failure to LSA',detector,'wslLSA',{objects:[result],wire:detector==='wslDC',type:detector==='wslDC'?'network-exchange':'local-call'});add(stage+'-display','Return failure to credential UI','wslLSA','wslUI',{objects:[result],puts:{clientKnowsResult:true},type:'local-result'});}
    if(scratch.length)add(stage+'-scratch-cleanup','Release only this failed attempt temporary operation handles','wslLSA','wslLSA',{releases:scratch,type:'local-cleanup'});if(buffer)cleanup(buffer);return finish();
  }
  function liveHoldings(){const live=new Map();for(const effect of [...initial,...steps.flatMap(step=>events[step.id].milestones.flatMap(m=>m.effects))]){if(effect.op==='acquire')live.set(effect.holdingId,effect);else if(effect.op==='release')live.delete(effect.holdingId);}return [...live.values()];}
  function holds(object,actor,representation='plain'){return liveHoldings().some(effect=>effect.artifactId===object.artifactId&&effect.actorId===actor&&effect.representationId===representation);}
  function releaseOwned(stage,title,holdings,puts={}){
    const owners=[...new Set(holdings.map(effect=>effect.actorId))];
    for(const [index,owner] of owners.entries())add(stage+'-'+owner,title,owner,owner,{releases:holdings.filter(effect=>effect.actorId===owner).map(effect=>({object:artifacts.find(o=>o.artifactId===effect.artifactId),actor:owner,store:effect.store,representation:effect.representationId,holdingId:effect.holdingId})),puts:index===owners.length-1?puts:{},type:'local-cleanup'});
  }
  function cleanup(buffer){
    const holdings=liveHoldings().filter(effect=>effect.artifactId===buffer.artifactId);
    if(ownerLocalCleanup){releaseOwned('input-cleanup','Release this owner’s temporary credential input',holdings,{inputReleased:true});return;}
    add('input-cleanup','Release temporary credential input','wslLSA','wslLSA',{releases:holdings.map(e=>({object:buffer,actor:e.actorId,store:e.store,representation:e.representationId})),puts:{inputReleased:true},type:'local-cleanup'});
  }
  function prepareTransfers(){
    const prepared=[],live=new Map();
    const apply=effect=>{if(effect.op==='acquire')live.set(effect.holdingId,effect);else if(effect.op==='release')live.delete(effect.holdingId);};
    initial.forEach(apply);
    for(const step of steps){
      const event=events[step.id],senders=event.messages||[];
      const available=[...live.values(),...event.milestones.flatMap(m=>m.effects).filter(effect=>effect.op==='acquire')];
      // Composed carriers serialize existing sender-owned protocol objects.
      // A wire copy is not a new issuer object or a receiver acceptance.
      for(const message of senders)for(const carried of message.objects){
        if(!['wire','opaque','ciphertext','netlogon'].includes(carried.representationId))continue;
        const owns=effect=>effect.actorId===message.from&&effect.artifactId===carried.artifactId;
        if(available.some(effect=>owns(effect)&&effect.representationId===carried.representationId)||!available.some(owns))continue;
        const object=artifacts.find(o=>o.artifactId===carried.artifactId);
        const outgoing=step.attributeOperations.filter(op=>op.kind==='send'&&op.actorId===message.from&&op.instanceId===carried.artifactId&&op.representation===carried.representationId);
        if(!object||!outgoing.length)continue;
        const serialized=acquire(object,message.from,'serialized carrier output',carried.representationId,'temporary');
        event.milestones[0].effects.push(serialized);available.push(serialized);
        event.milestones.at(-1).effects.push({op:'release',holdingId:serialized.holdingId});
        const protectedOutput=['ciphertext','netlogon'].includes(carried.representationId);
        step.attributeOperations.push(...outgoing.map(op=>({...op,kind:protectedOutput?'encrypt':'store',holders:[message.from],sourceEventId:step.id,detail:protectedOutput?'Apply the fixture-selected carrier protection locally before transfer; preserve the object creator and defer receiver acceptance.':'Serialize the existing sender-owned object into its declared carrier representation without changing origin or accepting it at the receiver.'})));
      }
      const effects=event.milestones.flatMap(m=>m.effects);
      const local=effects.filter(effect=>effect.op==='acquire'&&senders.some(message=>message.from===effect.actorId&&message.objects.some(o=>o.artifactId===effect.artifactId)));
      if(local.length){
        const created=new Set(local.map(effect=>effect.artifactId)),preEffects=effects.filter(effect=>local.includes(effect)||effect.op==='create'&&created.has(effect.artifactId));
        const operations=(step.attributeOperations||[]).filter(op=>['create','derive','encrypt','store'].includes(op.kind)&&local.some(effect=>effect.actorId===op.actorId&&effect.artifactId===op.instanceId&&effect.representationId===op.representation)||op.kind==='use'&&senders.some(message=>message.from===op.actorId));
        for(const effect of effects)if(effect.op==='observe'&&effect.kind==='knowledge'&&operations.some(op=>op.kind==='use'&&op.instanceId===effect.artifactId&&op.actorId===effect.actorId&&op.representation===effect.representationId))preEffects.push(effect);
        const preparation={...step,id:step.id+':prepare-transfer',title:'Prepare local representations before '+step.title,from:senders[0].from,to:senders[0].from,channel:'internal',layers:[],protocolLabel:'Local OS preparation',eventType:'localOperation',workstationStage:step.workstationStage+':prepare-transfer',summary:'Construct or serialize the exact sender-local representations before the existing transfer starts.',detail:'Local preparation only. No wire message, recipient decoding or authentication verdict occurs here.',fields:[...new Set(operations.map(op=>op.attributeId))],payload:(step.payload||[]).filter(field=>operations.some(op=>op.attributeId===field.attributeId)),attributeOperations:operations,protocolEffects:[]};
        step.attributeOperations=(step.attributeOperations||[]).filter(op=>!operations.includes(op));
        for(const authored of steps)for(const op of authored.attributeOperations||[])if(op.sourceEventId===step.id&&operations.some(prepared=>prepared.instanceId===op.instanceId&&prepared.attributeId===op.attributeId)){
          op.sourceEventId=preparation.id;if(op.exactValueRef)op.exactValueRef=op.exactValueRef.split('@'+step.id+'#').join('@'+preparation.id+'#');
        }
        for(const op of operations)if(op.sourceEventId===step.id){op.sourceEventId=preparation.id;if(op.exactValueRef)op.exactValueRef=op.exactValueRef.split('@'+step.id+'#').join('@'+preparation.id+'#');}
        for(const record of reuse)if(record.clientContextStartsAt===step.id)record.clientContextStartsAt=preparation.id;
        events[preparation.id]={milestones:[{id:'complete',at:1,effects:preEffects}]};
        for(const milestone of event.milestones)milestone.effects=milestone.effects.filter(effect=>!preEffects.includes(effect));
        prepared.push(preparation);
      }
      prepared.push(step);
      effects.forEach(apply);
    }
    steps.splice(0,steps.length,...prepared);
  }
  function finish(){
    if(completedModel)return completedModel;
    prepareTransfers();
    const live=new Map();
    for(const effect of [...initial,...steps.flatMap(step=>events[step.id].milestones.flatMap(m=>m.effects))]){
      if(effect.op==='acquire')live.set(effect.holdingId,effect);
      else if(effect.op==='release')live.delete(effect.holdingId);
    }
    const scratch=[...live.values()].filter(effect=>effect.retention==='temporary'&&artifacts.some(o=>o.artifactId===effect.artifactId&&o.key));
    if(scratch.length){
      if(ownerLocalCleanup)releaseOwned('attempt-cleanup','Release owner-local attempt scratch without closing accepted sessions',scratch);
      else add('attempt-cleanup','Release completed attempt work buffers without closing live sessions','wslLSA','wslLSA',{releases:scratch.map(effect=>({object:artifacts.find(o=>o.artifactId===effect.artifactId),actor:effect.actorId,store:effect.store,representation:effect.representationId})),type:'local-cleanup',summary:'The attempt has completed or stopped. Release only its remaining temporary protocol/input/validation buffers; authoritative records, accepted credentials, active processes and their tokens survive.'});
    }
    const positions={};
    for(const actor of Object.values(actors)){
      actor.position=(meta.positions||meta.actorPositions)?.[actor.id]||wslActorPositions[actor.id];
      positions[actor.id]=actor.position;
    }
    meta={...meta,positions,actorPositions:positions};
    const model=labScenario({...meta,workspace:'workstations',initialState:{workstation:state},fixtureInputs:wslFreeze({...inputs}),workstationInventory:{artifacts,initial,events,bindings},profile:{name:'Windows 11 Enterprise 25H2 reference',version:'26200.9711 / KB5127648 / 2026-10-13',publicationStatus:'official API/spec references',supportStatus:'authored reference; no installed Windows or live AD verification',implementation:'Offline deterministic symbolic model',assumptions:['Credential Guard explicitly enabled; protected domain credentials use opaque LSAIso/VBS custody.','AD DS Server 2025 compatibility assumed, installed DC build unavailable.','No Entra join, consumer Hello, automatic sign-in or implicit NTLM fallback.'],startingSummary:[state.deviceMembership,'Console authority: '+state.consoleAuthority,'Initial local process: '+(state.localAccount||'none; this is a new sign-in attempt'),'Selected verifier: '+state.verifierAuthority,...(inputs.adminMode?['Elevation policy: '+inputs.adminMode]:[]),...(inputs.networkMechanism?['Network profile: '+inputs.networkMechanism]:[]),'Authentication, admission, token creation and resource access remain separate.'],transports:['local OS calls / distinct-owner IPC','Kerberos TCP/88 only where explicitly authored'],completion:meta.completion||'Declared local session or elevation boundary; linked network journeys start independent authored contexts.',algorithms:['Symbolic security object handles; no production crypto'],cryptoDetail:{mode:'symbolic'},sources:meta.sources||WINDOWSLOGONLAB_SOURCES,...meta.profile},prerequisites:meta.prerequisites||wslPrerequisites[meta.code]||[],learningObjective:meta.learningObjective||meta.summary,sourceSupportNote:'Official source bytes and independent expected outcomes: docs/next-expansion/windows-workstation-{sources,worksheet}.json. Native Windows inspection, runas help and live KDC evidence unavailable.'},definitions,steps,actors);
    model.workstationInventory.reuse=reuse;
    model.status='reference';model.protocol='Windows workstation security';
    model.workspace=meta.workspace||'workstations';
    model.sourceSupportNote=meta.sourceSupportNote||model.sourceSupportNote;
    model.decisionBindings=[{label:'Device membership',path:'workstation.deviceMembership'},{label:'Console authority',path:'workstation.consoleAuthority'},{label:'Local process identity',path:'workstation.localAccount'},{label:'Outbound identity',path:'workstation.outboundAccount'},meta.code==='WELEV03'?{label:'Alternate administrator credential verified',path:'workstation.alternateVerified'}:{label:'Credential verified for this attempt',path:'workstation.credentialVerified'},{label:'Console allowed',path:'workstation.consoleAllowed'},{label:'Desktop ready',path:'workstation.desktopReady'},{label:'Privilege state',path:'workstation.privilegeState'},{label:'Resource allowed',path:'workstation.resourceAllowed'},{label:meta.code==='WELEV05'?'Requesting process Q knows network result':'Caller/UI knows result',path:'workstation.clientKnowsResult'}];
    model.decisionBindings.push({label:'Selected authentication boundary',path:'workstation.verifierAuthority'});if(Object.hasOwn(state,'childAccount'))model.decisionBindings.push({label:'Helper process identity',path:'workstation.childAccount'},{label:'Helper integrity',path:'workstation.childIntegrity'});
    model.decisionBindings.push({label:'Selected package',path:'workstation.authenticationPackage'},{label:'First rejecting boundary',path:'workstation.failureStage'},{label:'Reason',path:'workstation.failureReason'});
    return completedModel=model;
  }
  return {id,state,actors,object,seed,add,deny,cleanup,finish,acquire,holds,steps,definitions,artifacts,initial,events,bindings,reuse,inputFixture,credentialsMatch:()=>inputFixture.candidate===inputFixture.expected};
}

const wslLocalVariants={default:{},'bad-password':{passwordMatches:false},'disabled-account':{accountEnabled:false},'deny-interactive':{denyInteractive:true},'profile-failure':{profileLoads:false}};
function wslLocalLogon(variantId='default'){
  if(!Object.hasOwn(wslLocalVariants,variantId))throw new RangeError('Unknown WLOG01 variant: '+variantId);
  const f={passwordMatches:true,accountEnabled:true,profileLoads:true,denyInteractive:false,authority:'WORKGROUPPC',...wslLocalVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog01',code:'WLOG01',title:'Workgroup workstation: local password logon',family:'windows-logon',summary:'Where does the first local access token appear, and can a verified password still fail to reach a desktop?',variantId,profileControls:[{id:'account-authority',label:'Console account authority',value:'local',options:[{value:'local',label:'Workgroup local account',scenarioId:'lab-wlog01'},{value:'domain',label:'Joined workstation - online domain account',scenarioId:'lab-wlog02'},{value:'member-local',label:'Joined workstation - explicit local account',scenarioId:'lab-wlog03'}]}],relatedLessons:[{id:'lab-wlog02',title:'Domain password sign-in',summary:'Different account authority; opens a separate authored context.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  const verifier=a.seed(a.object('sam-verifier','Local SAM verifier','credential','wslSAM','HANDLE(SAM:bob:verifier)',['wslSAM'],{store:'SAM durable account database'}));
  const policy=a.seed(a.object('local-policy','Console rights and file DACL','policy','wslLSA',{allowInteractive:true,denyInteractive:f.denyInteractive,fileAllowSid:'S-1-5-21-110-220-330-1001'},['wslLSA','wslProcess']));
  const buffer=a.object('credential-input','Temporary password input','credential','wslUI',a.inputFixture.candidate,['wslUI','wslLSA','wslSAM'],{store:'temporary credential input'});
  a.add('collect','Collect explicitly local credential','wslUser','wslUI',{creates:[buffer],puts:{inputCollected:true},type:'local-input'});
  const request=a.object('logon-request','Interactive logon request','request','wslUI',{authority:'WORKGROUPPC',account:'bob',package:'MSV1_0',logonType:'Interactive(2)'},['wslUI','wslLSA','wslSAM']);
  a.add('submit','Submit to local authentication package','wslUI','wslLSA',{creates:[request],objects:[request,buffer],type:'local-call'});
  wslDispatchPackage(a,buffer);
  a.add('sam-request','Dispatch candidate to selected local authority','wslLSA','wslSAM',{objects:[request,buffer],type:'local-call'});
  if(!a.credentialsMatch()||!f.accountEnabled)return wslCompleteVariant(a.deny('verify','wslSAM',f.accountEnabled?'local verifier mismatch':'local account disabled',buffer,[],{uses:[verifier],verify:[buffer]}),wslLocalLogon,wslLocalVariants);
  const validation=a.object('validation-result','SAM validation result','identity','wslSAM',{verified:true,account:'WORKGROUPPC\\bob',userSid:'S-1-5-21-110-220-330-1001'},['wslSAM','wslLSA']);
  a.add('verify','Validate at local SAM','wslSAM','wslSAM',{uses:[verifier],creates:[validation],puts:{credentialVerified:true},summary:'SAM validates the selected local credential. No network or domain authority is involved.'});
  a.add('verify-return','Return account facts to LSA','wslSAM','wslLSA',{objects:[validation],type:'local-call'});
  if(f.denyInteractive)return wslCompleteVariant(a.deny('authorize','wslLSA','SeDenyInteractiveLogonRight applies despite valid password',buffer),wslLocalLogon,wslLocalVariants);
  const token=wslToken(a.id+':token');const tokenObject=a.object('primary-token','Primary access token','token','wslLSA',token,['wslLSA','wslProcess'],{store:'kernel token table'});
  const luid=a.object('logon-luid','Logon session identifier','session','wslLSA',token.authenticationId,['wslLSA','wslProcess']);
  a.add('authorize','Authorize console logon and create first token','wslLSA','wslLSA',{uses:[policy],creates:[luid,tokenObject],puts:{consoleAllowed:true,token,localAccount:token.account,localSid:token.userSid,sessionId:'SESSION(local-1)'},type:'local-create'});
  a.add('process','Attach token to userinit and shell startup','wslLSA','wslProcess',{objects:[tokenObject],puts:{processId:'PID(userinit-4100)'},type:'local-create'});
  a.cleanup(buffer);
  if(!f.profileLoads)return wslCompleteVariant(a.deny('desktop','wslProcess','profile startup failed after token creation'),wslLocalLogon,wslLocalVariants);
  const desktop=a.object('desktop-session','Loaded profile and ready desktop','session','wslProcess',{profile:'C:\\Users\\bob',session:'SESSION(local-1)',desktop:'WinSta0\\Default'},['wslProcess']);
  a.add('desktop','Load profile and mark desktop ready','wslProcess','wslProcess',{creates:[desktop],puts:{desktopReady:true},type:'local-create'});
  const decision=a.object('file-decision','Selected file access decision','result','wslProcess',{requested:'read',allowed:true,tokenSid:token.userSid},['wslProcess','wslUI']);
  a.add('access','Check file DACL with active token','wslProcess','wslProcess',{uses:[tokenObject],creates:[decision],puts:{resourceAllowed:true}});
  a.add('result','User learns desktop and file result','wslProcess','wslUI',{objects:[decision],puts:{clientKnowsResult:true},type:'local-result'});
  return wslCompleteVariant(a.finish(),wslLocalLogon,wslLocalVariants);
}
export function wslCompleteVariant(model,factory,variants){model.catalogAttributeIds=[...new Set([...(wslFieldCatalog.get(model.id)||[]),...model.ids])];if(model.family==='windows-logon'&&!model.profileControls)model.profileControls=[{id:'account-authority',label:'Console account authority',value:model.code==='WLOG01'?'local':model.code==='WLOG03'?'member-local':'domain',options:[{value:'local',label:'Workgroup local password',scenarioId:'lab-wlog01'},{value:'domain',label:'Joined online domain password',scenarioId:'lab-wlog02'},{value:'member-local',label:'Joined explicit local account',scenarioId:'lab-wlog03'}]}];model.variantChoices=Object.entries(variants).map(([id,changes])=>({id,label:id==='default'?(model.code==='WELEV01'?'Filtered-token comparison - protected write denied':'Default selected profile'):id,description:id==='default'?'Run the declared base fixture.':'Changed fixture inputs: '+JSON.stringify(changes)}));model.withVariant=id=>factory(id);return wslFreeze(model);}

// Explicit composition maps preserve corrected accepted event/object lineage.
export function wslCompositeMap(value,record){
  const actorMap={cryptoUser:'wslUser',cryptoCard:'wslCard',cryptoClient:'wslLSA',cryptoComputer:'wslMachine',cryptoKdc:'wslDC',cryptoAs:'wslDC',cryptoTgs:'wslDC',cryptoService:'wslMachine',smbClient:'wslNetwork',smbServer:'wslFile',smbDC:'wslDC',...record.actorAliases};
  function mapString(s){
    if(actorMap[s])return actorMap[s];
    if(record.fieldMap[s])return record.fieldMap[s];
    if(record.valueOverrides?.[s])return record.valueOverrides[s];
    for(const [eventId,mapped] of Object.entries(record.eventMap||{}))s=s.split(eventId).join(mapped);
    return s.split(record.sourceId+'-').join(record.ownerId+':'+record.kind+':').split(record.sourceId+':').join(record.ownerId+':'+record.kind+':');
  }
  function walk(v,protectedParent=false){
    const protectedHere=protectedParent||!!(v&&typeof v==='object'&&!Array.isArray(v)&&record.protectedArtifacts?.includes(v.artifactId||v.instanceId));
    if(typeof v==='string'){const mapped=mapString(v);return protectedParent&&record.credentialGuard!==false&&['wslLSA','wslNetwork'].includes(mapped)?'wslIso':mapped;}
    if(Array.isArray(v))return v.map(x=>walk(x,protectedHere));
    if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[mapString(k),walk(x,protectedHere)]));
    return v;
  }
  return walk(value);
}
function wslSourceOperation(op,kind,stepId){
  // Accepted AD inventories name their local and protected representations
  // plain/opaque, including public DER/CMS values that are not ciphertext.
  const representation=kind==='ad'?({'decoded-local':'plain','wire-encoded':'plain','signed-container':'plain','opaque-ciphertext':'opaque'}[op.representation]||op.representation):op.representation;
  // One logical shared key retains its first creator. A second endpoint
  // reconstructs and stores its own local representation, not a second object.
  const reconstruct=op.kind==='derive'&&op.creator&&op.actorId!==op.creator;
  return {...op,representation,kind:reconstruct?'store':op.kind,...(reconstruct?{detail:(op.detail||'')+' Independently reconstructs the existing logical key in endpoint-local memory; no key transport or creator reassignment.'}:{}),sourceEventId:op.sourceEventId||stepId,exactValueRef:op.exactValueRef||op.instanceId+':'+op.fieldPath+':'+representation};
}
export function wslAppendSource(a,source,kind,through,{aliases={},effects={},valueOverrides={},beforeIssue=null,credentialGuard=true,actorAliases={}}={}){
  const all=source.steps(),end=through?all.findIndex(s=>(s.labCryptoStage||s.smbStage)===through):all.length-1;
  if(end<0)throw new TypeError('Missing explicit accepted handoff stage: '+through);
  const selected=all.slice(0,end+1),fieldMap=Object.fromEntries(Object.keys(source.definitions()).map(field=>[field,a.id.replace(/-/g,'_')+'_'+kind+'_'+field]));
  if(kind==='ad'){fieldMap.kerberosConfiguredMaterial=a.id.replace(/-/g,'_')+'_ad_configured_material';a.definitions[fieldMap.kerberosConfiguredMaterial]=labAttribute('Configured Kerberos authority material','Preexisting protected authority key reference; not issued by this sign-in.','Declared KDC/service configuration','Keep configured key custody separate from newly created reply/session keys.','HANDLE(preexisting configured key)','RFC4120 / pinned Windows source matrix',wslSource);}
  const eventMap=Object.fromEntries(selected.map(s=>[s.id,a.id+':'+(aliases[s.labCryptoStage||s.smbStage]||kind+':'+(s.labCryptoStage||s.smbStage))]));
  const record={valueOverrides,credentialGuard,actorAliases,kind,ownerId:a.id,sourceId:source.id,fieldMap,eventMap,protectedArtifacts:kind==='ad'?[source.id+':user-tgt-session-key:1',source.id+':issued-ticket-session-key:1',source.id+':user-long-term-key:1']:kind==='smb'?[source.id+':tgt-key']:[],sourceContext:{kerberosRealm:'CORP.EXAMPLE',servicePrincipal:kind==='ad'?'host/workstation.corp.example':'cifs/files.corp.example'},sourceStepIds:selected.map(s=>s.id)};
  for(const [field,definition] of Object.entries(source.definitions()))a.definitions[fieldMap[field]]=wslCompositeMap(definition,record);
  const actorMapping={cryptoUser:'wslUser',cryptoCard:'wslCard',cryptoClient:'wslLSA',cryptoComputer:'wslMachine',cryptoKdc:'wslDC',cryptoAs:'wslDC',cryptoTgs:'wslDC',cryptoService:'wslMachine',smbClient:'wslNetwork',smbServer:'wslFile',smbDC:'wslDC',...actorAliases};
  for(const [key,actor] of Object.entries(source.actors())){const target=actorMapping[key];if(target&&!a.actors[target])a.actors[target]={...wslCompositeMap(actor,record),id:target,parentId:['wslCard','wslDC','wslFile'].includes(target)?undefined:'wslWorkstation'};}
  a.state[kind]=wslCompositeMap(kind==='smb'?source.initialState.smb:source.initialState,record);
  for(const original of selected){const stage=original.labCryptoStage||original.smbStage,step=wslCompositeMap(original,record);step.id=eventMap[original.id];step.workstationStage=aliases[stage]||kind+':'+stage;step.attributeOperations=(step.attributeOperations||[]).map(op=>wslSourceOperation(op,kind,step.id));step.protocolEffects=[...(original.protocolEffects||[]).map(effect=>({...wslCompositeMap(effect,record),path:'workstation.'+kind+'.'+(kind==='smb'?effect.path.replace(/^smb\./,''):effect.path)})),...Object.entries({...effects[stage],...(effects[stage]?.failure?{failureStage:effects[stage].failure.stage,failureReason:effects[stage].failure.reason}:{})}).map(([path,value])=>({op:'put',path:'workstation.'+path,value}))];if(kind==='ad')step.layers=original.eventType==='network'?[{protocol:'Kerberos ' + (original.labCryptoStage||''),transport:'TCP / port88',from:step.from,to:step.to,protection:'Accepted source field-specific symbolic protection'}]:[];a.steps.push(step);a.events[step.id]={milestones:[{id:'complete',at:1,effects:[]}]};}
  if(kind==='smb'){
    const ledger=wslCompositeMap(source.smbInventory,record);a.artifacts.push(...ledger.artifacts);Object.assign(a.events,ledger.events);a.bindings.push(...ledger.bindings.map(binding=>({...binding,path:'workstation.smb.'+binding.path.replace(/^smb\./,'')})));
    const clientOwners=new Set(['wslNetwork','wslIso']),alreadyRequired=new Set(ledger.initial.filter(effect=>effect.op==='acquire'&&!clientOwners.has(effect.actorId)).map(effect=>effect.artifactId)),activation=[];
    for(const effect of ledger.initial){if(effect.op==='acquire'&&clientOwners.has(effect.actorId)||effect.op==='create'&&!alreadyRequired.has(effect.artifactId))activation.push(effect);else a.initial.push(effect);}
    record.clientContextStartsAt=eventMap[selected[0].id];a.events[record.clientContextStartsAt].milestones[0].effects.unshift(...activation);
  }else{
    const ledger=wslCompositeMap(buildKerberosHeldObjects({model:source,steps:all,actors:source.actors(),config:{},contextId:a.id+':ad',choiceId:source.id}),record);
    a.artifacts.push(...ledger.artifacts);a.initial.push(...ledger.initial);
    a.bindings.push(...ledger.bindings.map(binding=>({...binding,path:'workstation.ad.'+binding.path})));
    if(record.sourceId.startsWith('lab-ad-fast-as-')){
      const eventId=eventMap[source.id+'-prerequisites'];
      if(eventId)ledger.events[eventId]={milestones:[{id:'complete',at:1,effects:['fast-policy','fast-capability'].map(key=>({op:'observe',artifactId:wslCompositeMap(source.id+':'+key+':1',record),actorId:'wslLSA',representationId:'plain',kind:'verification',result:'Checked configured FAST policy and realm/DC capability before using armor'}))}]};
    }
    if(record.sourceId==='lab-ad-fast-as-checksum'){
      const eventId=eventMap[source.id+'-request-binding'];
      if(eventId)ledger.events[eventId]={milestones:[{id:'complete',at:1,effects:['fast-request','outer-request'].map(key=>({op:'observe',artifactId:wslCompositeMap(source.id+':'+key+':1',record),actorId:'wslDC',kind:'verification',result:'Rejected the exact protected request checksum binding before accepting the user proof'}))}]};
    }
    for(const step of a.steps.filter(step=>Object.values(eventMap).includes(step.id))){
      const event=ledger.events[step.id];if(!event)throw new RangeError('Missing explicitly mapped Kerberos inventory event: '+step.id);
      a.events[step.id]=event;
      step.attributeOperations=step.attributeOperations.map(op=>{
        const artifact=ledger.artifacts.find(artifact=>artifact.artifactId===op.instanceId);
        if(artifact&&op.creator&&op.creator!==artifact.creator)throw new TypeError('Mapped Windows creator differs from accepted inventory: '+op.instanceId);
        return artifact?{...op,creator:artifact.creator}:op;
      });
    }
  if(beforeIssue){
    const issuance=selected.find(step=>step.labCryptoStage==='protect-response');
    if(!issuance)throw new TypeError('Policy gate requires the accepted FAST issuance stage');
    const at=a.steps.findIndex(step=>step.id===eventMap[issuance.id]),tail=a.steps.splice(at);
    record.policyPermitted=beforeIssue(a,{source,record})!==false;
    if(record.policyPermitted)a.steps.push(...tail);
    else{for(const step of tail)delete a.events[step.id];record.sourceStepIds=selected.filter(step=>a.steps.some(mapped=>mapped.id===eventMap[step.id])).map(step=>step.id);}
  }
  }a.reuse.push(record);
  return record;
}
// Continue only the standardized protected error tail in the same FAST
// conversation. Common armor/proof objects keep their original identities.
export function wslAppendFastPolicyError(a,source,record,reason='KDC_ERR_POLICY'){
  const all=source.steps(),selected=all.filter(step=>['kdc-reject','error-result','decode-error'].includes(step.labCryptoStage));
  if(selected.length!==3)throw new TypeError('Accepted FAST error source schema changed');
  const prefixFor=id=>'crypto'+id.replace(/^lab-/,'').split('-').map(part=>part[0].toUpperCase()+part.slice(1)).join('');
  const errorPrefix=prefixFor(source.id),acceptedPrefix=prefixFor(record.sourceId);
  const fieldMap=Object.fromEntries(Object.keys(source.definitions()).map(field=>[field,a.id.replace(/-/g,'_')+'_ad_'+field.replace(errorPrefix,acceptedPrefix)]));
  const eventMap=Object.fromEntries(selected.map(step=>[step.id,a.id+':ad:'+step.labCryptoStage]));
  const errorRecord={...record,sourceId:source.id,fieldMap,eventMap,valueOverrides:{...record.valueOverrides,'encrypted-challenge':reason,'<profile-gated error code>':reason}};
  const ledger=wslCompositeMap(buildKerberosHeldObjects({model:source,steps:all,actors:source.actors(),config:{},contextId:a.id+':ad',choiceId:source.id}),errorRecord);
  for(const [field,definition] of Object.entries(source.definitions()))a.definitions[fieldMap[field]]=wslCompositeMap(definition,errorRecord);
  for(const artifact of ledger.artifacts)if(!a.artifacts.some(existing=>existing.artifactId===artifact.artifactId))a.artifacts.push(artifact);
  for(const original of selected){
    const step=wslCompositeMap(original,errorRecord);step.id=eventMap[original.id];step.workstationStage='ad:'+original.labCryptoStage;
    step.attributeOperations=(step.attributeOperations||[]).map(op=>wslSourceOperation(op,'ad',step.id));
    step.protocolEffects=(original.protocolEffects||[]).map(effect=>({...wslCompositeMap(effect,errorRecord),path:'workstation.ad.'+effect.path}));
    step.layers=original.eventType==='network'?[{protocol:'Kerberos FAST protected error',transport:'TCP / port88',from:step.from,to:step.to,protection:'RFC6113 5.4.4 enc-fast-rep usage52; PA-FX-ERROR; request nonce'}]:[];
    a.steps.push(step);a.events[step.id]=ledger.events[step.id];
    if(!a.events[step.id])throw new TypeError('Missing accepted FAST error inventory event');
  }
  record.policyErrorSourceId=source.id;record.policyErrorSteps=selected.map(step=>step.id);
}
export function wslSourceNetwork(a,{badPassword=false,shareDenied=false,failureStage='network',requestingProcess='wslProcess',credentialContextRef=a.id+':outbound-credential',contextReference=null,existingConnection=false,dcReachable=true,mechanism='Kerberos',desktopIdentity=null,clientJoined=null}={}){
  a.actors.wslNetwork={id:'wslNetwork',parentId:'wslWorkstation',name:'Windows SSP / SMB redirector',role:'OS-owned network security context, distinct from the requesting user process',kind:'service',color:'#08916d'};
  const request=a.object('network-request','Scoped application SMB read request','request',requestingProcess,{requestId:a.id+':network-request-1',operation:'SMB read quarterly report',server:'files.corp.example',credentialContextRef},[requestingProcess,'wslNetwork']);
  a.add('network-prepare','Create the requesting process scoped SMB operation',requestingProcess,requestingProcess,{creates:[request],type:'local-create'});
  a.add('network-request','Request a fresh SMB operation with an opaque credential-context reference',requestingProcess,'wslNetwork',{uses:contextReference?[contextReference]:[],objects:[request],type:'local-call'});
  if(existingConnection||!dcReachable){
    a.deny('network','wslNetwork',existingConnection?'existing same-server SMB context would obscure new credential selection; choose a fresh connection':'required domain authority unavailable for the selected fresh network attempt',null,[],{replyActor:requestingProcess,viaActors:[],verify:[request],request});return;
  }
  const source=SMBLAB_SCENARIOS.find(m=>m.id==='lab-smb-nonjoined-'+(badPassword?'bad-credential':shareDenied?'share-denied':mechanism==='NTLMv2'?'ntlm':'kerberos'));
  if(!source)throw new TypeError('Accepted SMB fixture missing');
  if(source.id.endsWith('kerberos'))a.actors.wslIso={id:'wslIso',parentId:'wslWorkstation',name:'LSAIso / VBS protected credentials',role:'Selected protected Kerberos TGT-key custody; service/SMB keys remain outside this protected store',kind:'authenticator',color:'#7c3aed'};
  const failure=badPassword||shareDenied,detector=badPassword?'wslDC':'wslFile',sourceDetector=badPassword?'dc-verify':'share-check';
  const effects={};if(failure)effects[sourceDetector]={failure:{stage:failureStage,reason:badPassword?'domain credential rejected in accepted SMB validation':'share ACL denied in accepted SMB session'},detector,clientKnowsResult:false,networkAuthenticated:!badPassword,resourceAllowed:false};
  const valueOverrides=desktopIdentity?{'WORKGROUPPC\\bob':desktopIdentity,[source.smbInventory.artifacts.find(object=>object.key==='desktop').value]:desktopIdentity+'; local session already established'}:{};
  const record=wslAppendSource(a,source,'smb',undefined,{aliases:failure?{[sourceDetector]:failureStage}:{},effects,valueOverrides});record.credentialContextArtifactId=credentialContextRef;record.requestingProcess=requestingProcess;record.requestArtifactId=request.artifactId;
  if(typeof clientJoined==='boolean')a.state.smb.clientJoined=clientJoined;
  if(desktopIdentity||typeof clientJoined==='boolean')record.sourceContext={...record.sourceContext,desktopIdentity,clientJoined};
  const result=a.object('network-result','Verified OS network result returned to the requesting process','result','wslNetwork',{requestId:request.value.requestId,operation:request.value.operation,authenticated:!badPassword,resourceAllowed:!badPassword&&!shareDenied,networkIdentity:'CORP\\alice',credentialContextRef},['wslNetwork',requestingProcess]);
  const data=!failure?a.artifacts.find(o=>o.artifactId===a.id+':smb:file-data'):null;if(!failure&&!data)throw new TypeError('Accepted SMB success must expose its exact accepted file-data object');
  if(data){data.retention='retained';data.readers.push(requestingProcess);const plain=data.representations.find(rep=>rep.representationId==='plain');plain.readableBy.push(requestingProcess);for(const field of plain.fields)field.readableBy.push(requestingProcess);}
  a.add('network-handoff','Return the verified SMB operation result to its requesting process','wslNetwork',requestingProcess,{uses:[request],creates:[result],objects:[result,...(data?[data]:[])],puts:{networkAuthenticated:!badPassword,resourceAllowed:!badPassword&&!shareDenied,linkedJourneyId:source.id,clientKnowsResult:true},type:'local-result',summary:'The OS protocol client has processed the actual protected SMB result before returning this correlated operation to its requester. No parent-process notification or data transfer is implied. Explicit NTLM credential/hash inputs remain in LSASS-side memory and are not claimed protected by Credential Guard (W-S09). Named NTLM comparisons are configured before playback, never fallback after a Kerberos error.'});
}
export function wslAddAuthority(a){
  a.actors.wslDC={id:'wslDC',name:'CORP AD DS KDC',role:'Server 2025 reference account authority',kind:'idp',color:'#7c3aed'};
  a.actors.wslMachine={id:'wslMachine',parentId:'wslWorkstation',name:'Workstation Kerberos acceptor / computer context',role:'Separate computer identity and local ticket interpretation',kind:'authenticator',color:'#b45309'};
  a.actors.wslIso={id:'wslIso',parentId:'wslWorkstation',name:'LSAIso / VBS protected credentials',role:'Protected domain TGT custody; opaque LSA operation handles',kind:'authenticator',color:'#7c3aed'};
}
export function wslSeedPolicy(a,f){const broker=!!a.actors.wslBroker,o=a.object('local-policy','Effective workstation logon/elevation policy','policy','wslLSA',{denyInteractive:!!f.denyInteractive,credentialGuard:'enabled',authority:f.authority||'WORKGROUPPC',cacheCount:f.cacheCount??10,unlockMode:f.unlockMode||null,adminMode:f.adminMode||'classic',promptPolicy:f.promptPolicy??null,elevationAllowed:f.elevationAllowed??null,alternateLogonRight:f.alternateLogonRight??null,secondaryLogonAvailable:f.secondaryLogon??null,featureAvailable:f.featureAvailable??null},['wslLSA','wslPackage','wslSAM','wslProcess',...(a.actors.wslMachine?['wslMachine']:[]),...(broker?['wslBroker']:[])]);return a.seed(o,['wslLSA',...(broker?['wslBroker']:[])]);}
export function wslDispatchPackage(a,buffer=null){
  if(a.selectedPackage)return a.selectedPackage;
  const selected=a.object('authentication-package','Selected in-process authentication package','policy','wslLSA',{name:a.state.authenticationPackage,hostProcess:'LSASS',boundary:'logical module call; not an OS wire',credentialCustody:'shared process references; protected domain key material stays in declared LSAIso/VBS custody'},['wslLSA','wslPackage']);
  if(buffer&&!buffer.readers.includes('wslPackage'))buffer.readers.push('wslPackage');
  a.add('package-dispatch','Dispatch through the selected in-process authentication package','wslLSA','wslPackage',{creates:[selected],objects:[selected,...(buffer?[buffer]:[])],type:'local-call',summary:'LSASS selects the declared package. This local module reference does not validate the credential, contact an authority or create a token.'});a.selectedPackage=selected;return selected;
}
export function wslInput(a,label='Password input',key='credential-input',readers=['wslUI','wslLSA','wslSAM']){
  const buffer=a.object(key,label,'credential','wslUI',{buffer:'HANDLE(temporary synthetic input; no real secret)',candidateFixture:a.inputFixture.candidate},readers,{store:'temporary credential input'});
  a.add('input','Collect account-scoped input','wslUser','wslUI',{creates:[buffer],type:'local-input'});
  a.add('submit','Submit input to selected LSA package','wslUI','wslLSA',{objects:[buffer],type:'local-call'});wslDispatchPackage(a,buffer);return buffer;
}
export function wslCreateDesktop(a,account,{stage='token',policy,stale=false}={}){
  const token=wslToken(a.id+':token',account,{sourceIdentity:stale?'cached domain identity snapshot; no fresh domain status':account.startsWith('CORP\\')?'validated domain identity/group facts':'local SAM identity/group facts'});
  const object=a.object('primary-token','Locally created primary token','token','wslLSA',token,['wslLSA','wslProcess'],{store:'kernel token table'});
  a.add(stage,'Apply local admission policy and create token','wslLSA','wslLSA',{uses:policy?[policy]:[],creates:[object],puts:{credentialVerified:true,consoleAllowed:true,token,localAccount:account,localSid:token.userSid,sessionId:'SESSION('+a.id+')',staleKnowledge:stale},type:'local-create'});
  a.add('process','Create userinit/shell under local token','wslLSA','wslProcess',{objects:[object],puts:{processId:'PID('+a.id+'-shell)'},type:'local-create'});
  const profile=a.object('profile','User profile and desktop','session','wslProcess',{account,session:'SESSION('+a.id+')',profile:'C:\\Users\\'+account.split('\\').at(-1)},['wslProcess']);
  a.add('desktop','Load profile and open interactive desktop','wslProcess','wslProcess',{creates:[profile],puts:{desktopReady:true},type:'local-create'});return object;
}
export function wslSealCase(a,factory,variants){
  const model=a.finish();
  model.profileControls||=[{id:'account-authority',label:'Console authority',value:model.code==='WLOG03'?'member-local':model.code==='WLOG01'?'local':'domain',options:[{value:'local',label:'Workgroup local password',scenarioId:'lab-wlog01'},{value:'domain',label:'Joined online domain password',scenarioId:'lab-wlog02'},{value:'member-local',label:'Joined explicit local account',scenarioId:'lab-wlog03'}]}];
  return wslCompleteVariant(model,factory,variants);
}
const wslOnlineVariants={default:{},'wrong-password':{userProofValid:false},'clock-or-spn':{clockValid:false},'clock-skew':{clockValid:false},'unknown-host-spn':{hostSpnValid:false},'host-key-mismatch':{hostKeyMatches:false},'denied-local-logon':{denyInteractive:true},'password-change-required':{passwordChangeRequired:true},'missing-host-reply-context':{hostReplyContext:'missing'},'wrong-host-reply-context':{hostReplyContext:'wrong'}};
function wslOnlineLogon(variantId='default'){
  if(!Object.hasOwn(wslOnlineVariants,variantId))throw new RangeError('Unknown WLOG02 variant');
  const f={joined:true,authority:'CORP',userProofValid:true,clockValid:true,hostSpnValid:true,hostKeyMatches:true,denyInteractive:false,passwordChangeRequired:false,...wslOnlineVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog02',code:'WLOG02',title:'Online AD DS password sign-in to local desktop',family:'windows-logon',variantId,summary:'AS/TGS credentials are accepted before the workstation creates its own token.',relatedLessons:[{id:'lab-ad-first-sign-in',title:'Kerberos password AS and service journey',summary:'Independent accepted protocol context.'},{id:'lab-wlog06',title:'Required FAST',summary:'Separate machine armor from user authentication.'},{id:'lab-smb-nonjoined-kerberos',title:'SMB resource authorization',summary:'A desktop is not a share grant.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  wslAddAuthority(a);const policy=wslSeedPolicy(a,f),buffer=wslInput(a);
  const credential=wslPasswordAS(a,f,{buffer});if(credential.denied)return wslCompleteVariant(credential.denied,wslOnlineLogon,wslOnlineVariants);
  const {tgt,tgtKey}=credential;
  if(!wslHostTicket(a,f,{tgt,tgtKey,policy,buffer}))return wslCompleteVariant(a.finish(),wslOnlineLogon,wslOnlineVariants);
  if(f.denyInteractive)return wslCompleteVariant(a.deny('token','wslLSA','local deny interactive right applies',buffer),wslOnlineLogon,wslOnlineVariants);
  wslCreateDesktop(a,'CORP\\alice',{policy});a.cleanup(buffer);
  a.add('network-boundary','Desktop ready; resource access is a separate journey','wslProcess','wslProcess',{puts:{clientKnowsResult:true},summary:'The local token exists only after host-ticket interpretation and workstation admission. No share or file permission is inferred.'});
  return wslSealCase(a,wslOnlineLogon,wslOnlineVariants);
}
export function wslPasswordAS(a,f,{buffer,account='CORP\\alice',acceptedPuts={},failureStage='as',beforeIssue=null}={}){
  const user=account.split('\\').at(-1);
  const clientKey=a.object('client-user-key',f.etype?'Client '+f.etype+' preauthentication handle':'Client AES preauthentication handle','credential','wslLSA','HANDLE('+(f.etype||'AES128')+' '+account+' account key selected from input)',['wslLSA']);
  const authorityKey=a.seed(a.object('kdc-user-key','KDC authoritative account AES key','credential','wslDC','HANDLE(AD '+account+' authoritative '+(f.etype||'AES128')+' account key)',['wslDC'],{store:'AD account database'}));
  const accountPolicy=a.seed(a.object('kdc-account-policy','Authoritative account and preauthentication policy','policy','wslDC',{account,accountEnabled:!f.onlineRejects,passwordChangeRequired:!!f.passwordChangeRequired,clockWithinWindow:f.clockValid!==false},['wslDC'],{store:'AD account policy'}));
  const request=a.object('as-request','AS-REQ preauthentication','request','wslLSA',{cname:user,realm:'CORP.EXAMPLE',sname:'krbtgt/CORP.EXAMPLE',nonce:41001,...(f.etype?{selectedPreauthEtype:f.etype}:{}),padata:'EncryptedData(PA-ENC-TIMESTAMP; '+(a.credentialsMatch()?'selected matching key':'selected nonmatching candidate key')+'; '+(f.clockValid===false?'out-of-window time':'declared fresh time')+'); no plaintext password'},['wslLSA','wslDC']);
  a.add('as-prepare','Select account key and create timestamp proof locally','wslLSA','wslLSA',{uses:buffer?[buffer]:[],creates:[clientKey,request]});
  a.add('as-request','Send AS-REQ to selected KDC','wslLSA','wslDC',{objects:[request],wire:true,type:'network-exchange'});
  if(!a.credentialsMatch()||f.clockValid===false||f.passwordChangeRequired||f.onlineRejects)return {denied:a.deny(failureStage,'wslDC',f.onlineRejects?'reachable authoritative account policy rejects sign-in; local cache cannot override it':f.passwordChangeRequired?'password change required; no inline change protocol':f.clockValid===false?'preauthentication clock skew':'preauthentication credential rejected',buffer,[{object:clientKey}],{uses:[authorityKey,accountPolicy],verify:[request]})};
  if(beforeIssue){
    a.add('as-proof-check','Validate timestamp proof before account authentication-policy admission','wslDC','wslDC',{uses:[authorityKey,accountPolicy],verify:[request]});
    if(beforeIssue(a,{request,authorityKey,accountPolicy})===false)return {policyDenied:true};
  }
  const credentialOwner=f.credentialGuard===false?'wslLSA':'wslIso',credentialStore=f.credentialGuard===false?'normal OS TGT credential':'protected TGT credential';
  const issuedMinutes=f.ticketIssuedMinutes??0;
  const lifetime=f.ticketLifetimeMinutes===undefined?null:{issuedMinutes,startMinutes:issuedMinutes,durationMinutes:f.ticketLifetimeMinutes,endMinutes:issuedMinutes+f.ticketLifetimeMinutes,renewMinutes:issuedMinutes+f.ticketLifetimeMinutes};
  const ticketDescription='Ticket('+user+' -> krbtgt/CORP.EXAMPLE; krbtgt ciphertext)'+(lifetime?'; issued='+lifetime.issuedMinutes+'min; duration='+lifetime.durationMinutes+'min; endtime='+lifetime.endMinutes+'min; renew-till='+lifetime.renewMinutes+'min':'');
  const tgt=a.object('tgt','Opaque user TGT','ticket','wslDC',ticketDescription,['wslDC'],{wire:ticketDescription});
  if(lifetime)tgt.lifetime={...lifetime};
  const tgtKey=a.object('tgt-session-key','Issued user TGT session key','session-key','wslDC','HANDLE(independent '+account+' TGT session key)',['wslDC',credentialOwner],{store:credentialStore});
  const reply=a.object('as-client-reply','Encrypted AS client reply','reply','wslDC',{nonce:41001,client:user+'@CORP.EXAMPLE',sessionKeyRef:tgtKey.artifactId,target:'krbtgt/CORP.EXAMPLE',lifetime:lifetime||'declared 8h reference'},['wslDC','wslLSA'],{wire:'EncryptedData(client account AES key, EncASRepPart)'});
  a.add('as','KDC validates proof and creates independent ticket credential','wslDC','wslDC',{uses:[authorityKey,accountPolicy],verify:[request],creates:[tgt,tgtKey,reply]});
  a.add('as-reply','Receive AS-REP ciphertext, not a usable credential yet','wslDC','wslLSA',{objects:[tgt,reply],wire:true,type:'network-exchange'});
  a.add('as-decode','Decrypt AS client part without installing the credential','wslLSA','wslLSA',{uses:[clientKey],receives:[{object:reply,actor:'wslLSA',kind:'decrypt'}]});
  a.add('as-accept','Validate AS client nonce, identity, target and lifetime','wslLSA','wslLSA',{verify:[reply],receives:[{object:tgt,actor:'wslLSA',store:'accepted TGT credential',representation:'wire',retention:'retained'},{object:tgtKey,actor:credentialOwner,store:credentialStore,retention:'retained'}],puts:{credentialVerified:true,tgtAccepted:true,outboundAccount:account,...acceptedPuts}});
  a.add('as-scratch-cleanup','Release this transaction preauthentication operation handle','wslLSA','wslLSA',{releases:[{object:clientKey}],type:'local-cleanup'});
  return {tgt,tgtKey};
}
export function wslHostTicket(a,f,{tgt,tgtKey,policy,buffer,account='CORP\\alice',beforeIssue=null,compoundArmor=null}={}){
  const serviceAccount=f.serviceAccountName||'WORKSTATION$',target=f.servicePrincipal||'host/workstation.corp.example',serviceActor=f.serviceActor||'wslMachine';
  const authorityKey=a.seed(a.object('kdc-machine-service-key',f.serviceAccountName?'KDC authoritative target service account key':'KDC authoritative workstation machine account key','credential','wslDC','HANDLE(AD '+serviceAccount+' authoritative '+target+' service key)',['wslDC'],{store:'AD account database',meaning:'The KDC-owned '+serviceAccount+' account key used to encrypt '+target+' tickets. This is not a transported workstation credential handle.',standard:'RFC4120 3.3.3; MS-KILE 4.1',source:'https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3'}));
  const machineKey=a.seed(a.object('machine-service-key',f.serviceAccountName?'Local acceptor service-account key handle':'Workstation local machine service key handle','credential',serviceActor,f.serviceActor?{key:'HANDLE('+serviceAccount+' service identity key)',account:serviceAccount,servicePrincipal:target}:'HANDLE('+serviceAccount+' service identity key)',[serviceActor],{store:f.serviceActor?'target service credential context':'machine credential context',meaning:f.serviceAccountName?'Provisioned local acceptor credential for '+serviceAccount+', distinct from the computer armor context and the KDC database key. Never transmitted to the KDC.':'Local workstation machine credential/keytab-equivalent handle for interpreting its host ticket. Provisioned separately from the KDC account database; never sent to the DC.'}));
  const source=a.reuse.find(record=>record.kind==='ad'),sourceTicketId=source?a.id+':ad:'+(source.sourceId.includes('pkinit')?'user-tgt:1':'issued-ticket:1'):null,sourceKeyId=source?a.id+':ad:'+(source.sourceId.includes('pkinit')?'user-tgt-session-key:1':'issued-ticket-session-key:1'):null;
  const borrowed=instanceId=>{const occurrence=a.steps.flatMap(step=>step.attributeOperations||[]).find(op=>op.instanceId===instanceId);if(!occurrence)throw new TypeError('Missing accepted credential handoff: '+instanceId);return occurrence;};
  const sourceKey=tgtKey||(()=>{const op=borrowed(sourceKeyId);return {artifactId:sourceKeyId,attributeId:op.attributeId,key:'protected-user-tgt-key',creator:op.creator,value:op.value,readers:['wslIso','wslDC'],store:'credential cache'};})();
  const requestId=a.id+':host-request-52001';
  const operationOwner=f.credentialGuard===false?'wslLSA':'wslIso';
  const context=a.object('credential-context-reference','Opaque accepted TGT operation reference','credential','wslLSA',{ticketRef:tgt?.artifactId||sourceTicketId,sessionKeyRef:sourceKey.artifactId,requestId,nonce:52001,request:target},['wslLSA','wslIso']);
  a.add('host-tgs-prepare',f.credentialGuard===false?'Request normal-OS TGT operation':'Request protected TGT operation through local LSAIso IPC','wslLSA',operationOwner,{creates:[context],objects:[context],type:'local-call'});
  const subkey=a.object('host-reply-subkey','Fresh request-bound TGS authenticator subkey','session-key',operationOwner,{key:'HANDLE(fresh AES128 TGS authenticator subkey)',requestId,nonce:52001,target,keyUsage:9},[...new Set([operationOwner,'wslLSA','wslDC'])],{source:'https://www.rfc-editor.org/rfc/rfc4120#section-3.3.2',standard:'RFC4120 3.3.2, 3.3.3; 7.5.1',meaning:'Per-request authenticator subkey selected for EncTGSRepPart key usage9. It is not the protected TGT session key or the workstation service key.'});
  const proof=a.object('host-operation-proof','Fresh encrypted TGS authenticator output','proof',operationOwner,{ciphertext:'SYM(authenticator encrypted by '+(f.credentialGuard===false?'normal-OS':'protected')+' TGT session key; key usage7)',requestId,nonce:52001,target,replySubkeyRef:subkey.artifactId,requestChecksum:'SYM(TGT-key checksum of this exact KDC-REQ-BODY; key usage6)'},[...new Set([operationOwner,'wslLSA','wslDC'])]);
  a.add('host-tgs-operation',f.credentialGuard===false?'Create request-bound authenticator and fresh reply subkey in normal OS custody':'Create request-bound authenticator and fresh reply subkey in protected custody',operationOwner,operationOwner,{uses:[context,sourceKey],creates:[subkey,proof]});
  a.add('host-tgs-operation-return','Return opaque authenticator and independent reply subkey, never the TGT secret',operationOwner,'wslLSA',{objects:[proof,subkey],type:'local-call'});
  const request=a.object('host-tgs-request','Host workstation TGS request','request','wslLSA',{requestId,sname:target,realm:'CORP.EXAMPLE',nonce:52001,opaqueTicketRef:tgt?.artifactId||sourceTicketId,authenticatorRef:proof.artifactId,replySubkeyRef:subkey.artifactId},['wslLSA','wslDC']);
  a.add('host-tgs-encode','Encode selected host request without exporting the TGT key','wslLSA','wslLSA',{uses:[context,proof],creates:[request]});
  let fastArmor=null,fastRequest=null;
  if(compoundArmor){
    fastArmor=a.object('compound-armor-key','Explicit compound TGS armor key','session-key','wslLSA',{derivation:'KRB-FX-CF2(explicit_armor_key, user_authenticator_subkey, " explicitarmor", " tgsarmor")',explicitArmorRef:compoundArmor.explicitKey.artifactId,userSubkeyRef:subkey.artifactId,requestId},['wslLSA','wslDC']);
    fastRequest=a.object('compound-fast-request','Compound FAST protected TGS request','request','wslLSA',{requestId,outerPaTgsReq:proof.artifactId,explicitComputerArmor:compoundArmor.proof.artifactId,reqChecksum:'key usage50 checksum over DER outer PA-TGS-REQ AP-REQ, not AS body',innerRequest:request.artifactId,nonce:52001},['wslLSA','wslDC'],{wire:'PA-FX-FAST {explicit computer armor AP-REQ; checksum50; enc-fast-req51}'});
    a.add('compound-request-protect','Bind computer explicit armor to user TGS authenticator subkey','wslLSA','wslLSA',{uses:[compoundArmor.explicitKey,subkey,request,proof],creates:[fastArmor,fastRequest],summary:'MS-KILE 3.3.5.7.4 extends RFC6113: preserve leading spaces in " explicitarmor"/" tgsarmor"; checksum usage50 binds outer AP-REQ; encrypt inner TGS request usage51. No AS encrypted challenge is transplanted.'});
  }
  const requestStep=a.add('host-tgs-request','Send TGS-REQ with opaque TGT and encrypted authenticator','wslLSA','wslDC',{objects:[...(compoundArmor?[fastRequest,compoundArmor.proof,compoundArmor.ticket]:[request]),proof,...(tgt?[tgt]:[])],wire:true,type:'network-exchange'});
  if(sourceTicketId){
    const op=borrowed(sourceTicketId),send={...op,kind:'send',actorId:'wslLSA',representation:'opaque',holders:['wslLSA','wslDC'],sourceEventId:requestStep.id},receive={...send,kind:'receive',actorId:'wslDC'};
    requestStep.attributeOperations.push(send,receive);requestStep.fields.push(op.attributeId);requestStep.payload.push(labP('Opaque accepted TGT',op.value,'Same accepted immutable ticket, inside this TGS request.',op.attributeId));
    const event=a.events[requestStep.id];event.messages[0].objects.push({artifactId:sourceTicketId,representationId:'opaque'});event.milestones[0].effects.push({op:'acquire',artifactId:sourceTicketId,actorId:'wslDC',store:'TGS request inbox',representationId:'opaque',retention:'temporary',holdingId:['wslDC',sourceTicketId,'opaque','TGS request inbox'].join('|')});
  }
  const krbtgtKey=a.seed(a.object('kdc-krbtgt-key','KDC authoritative krbtgt ticket-decryption key','credential','wslDC','HANDLE(CORP.EXAMPLE krbtgt ticket-decryption key)',['wslDC'],{store:'AD account database'}));
  const requestTicket=tgt||a.artifacts.find(object=>object.artifactId===sourceTicketId);
  if(!requestTicket)throw new TypeError('Host TGS request requires the exact accepted TGT');
  if(tgt&&!a.holds(requestTicket,'wslDC'))a.add('host-tgt-decode','Decode the exact received user TGT under existing KDC krbtgt authority','wslDC','wslDC',{uses:[krbtgtKey],receives:[{object:requestTicket,actor:'wslDC',kind:'decrypt',retention:'temporary'}]});
  if(compoundArmor)a.add('compound-user-authenticator','Recover and validate the user TGS authenticator subkey before deriving compound armor','wslDC','wslDC',{uses:[krbtgtKey,sourceKey],verify:[proof],receives:[{object:subkey,actor:'wslDC',kind:'decrypt'}]});
  if(compoundArmor){
    a.add('compound-ticket-decode','Decode the exact computer armor ticket with existing KDC authority','wslDC','wslDC',{uses:[krbtgtKey],receives:[{object:compoundArmor.ticket,actor:'wslDC',kind:'decrypt',retention:'temporary'}]});
    a.add('compound-proof-decode','Decode the computer authenticator using its existing ticket session key','wslDC','wslDC',{uses:[compoundArmor.key],receives:[{object:compoundArmor.proof,actor:'wslDC',kind:'decrypt'},{object:compoundArmor.sub,actor:'wslDC',kind:'decrypt'}]});
    a.add('compound-kdc-key','Recover computer explicit armor and bind the validated user subkey','wslDC','wslDC',{uses:[compoundArmor.key,compoundArmor.sub,subkey],verify:[compoundArmor.ticket,compoundArmor.proof],receives:[{object:compoundArmor.explicitKey,actor:'wslDC',kind:'derive'},{object:fastArmor,actor:'wslDC',kind:'derive'}]});
    a.add('compound-request-decode','Decode the exact FAST envelope and inner TGS request using compound armor','wslDC','wslDC',{uses:[fastArmor],receives:[{object:fastRequest,actor:'wslDC',kind:'decrypt'},{object:request,actor:'wslDC',kind:'decrypt'}]});
    a.add('compound-kdc-armor','Validate computer armor ticket/PAC and decoded compound TGS request at KDC','wslDC','wslDC',{uses:[krbtgtKey,compoundArmor.key,subkey,fastArmor],verify:[compoundArmor.ticket,compoundArmor.proof,fastRequest],puts:{machineAccepted:true},summary:'Validate krbtgt-encrypted computer ticket, authenticator freshness and its existing KDC-issued PAC before accepting device evidence; independently CF2 computer subkey/key then bind user subkey; verify AP-REQ checksum50 on the decoded inner request51.'});
    a.add('compound-kdc-device-facts','Record verified device evidence from the existing armor-ticket PAC','wslDC','wslDC',{uses:[compoundArmor.ticket],creates:[compoundArmor.pac],summary:'Materialize this KDC-local validation evidence only after current armor verification. The PAC was issued with the preexisting computer ticket; this step does not mint another PAC or reacquire an already-live evidence holding.'});
  }
  const verifiedRequest=a.add('host-tgs-verify','KDC decrypts TGT and verifies authenticator freshness, identity and request checksum','wslDC','wslDC',{uses:[krbtgtKey,sourceKey,...(compoundArmor?[subkey]:[])],verify:[...(tgt?[tgt]:[]),proof,request],receives:compoundArmor?[]:[{object:subkey,actor:'wslDC',kind:'decrypt'}],summary:compoundArmor?'KDC verifies the krbtgt ticket, request-bound authenticator and key-usage6 body checksum. Compound armor already recovered this same authenticator subkey at its earlier user-proof boundary; this check reuses that holding, not a second acquisition. Only the verified request can produce a client reply.':'KDC interprets the krbtgt-encrypted TGT, uses its session key to verify the authenticator and key-usage6 request-body checksum, checks client/freshness/replay binding, and obtains the per-request subkey from that authenticator. Only this verified request can produce a client reply.'});
  if(sourceTicketId){
    const op=borrowed(sourceTicketId);
    verifiedRequest.attributeOperations.push({...op,kind:'verify',actorId:'wslDC',holders:['wslDC'],representation:'opaque',sourceEventId:verifiedRequest.id,detail:'Verify the exact accepted krbtgt ticket before accepting its request-bound authenticator.'});
    a.events[verifiedRequest.id].milestones[0].effects.push({op:'observe',artifactId:sourceTicketId,actorId:'wslDC',representationId:'opaque',kind:'verification',result:'accepted TGT and matching request authenticator'});
  }
  if(f.hostSpnValid===false){a.deny('host-ticket','wslDC','selected workstation host SPN is not registered',buffer);return false;}
  const ticket=a.object('host-ticket',f.serviceActor?'Remote host service ticket':'Host workstation service ticket','ticket','wslDC',{client:account,server:target,...(f.serviceActor?{userSid:f.userSid,serviceAccount,issuer:'CORP.EXAMPLE'}:{}),...(f.forwardableServiceEvidence?{flags:['forwardable']}:{ }),authorization:compoundArmor?'PAC KERB_VALIDATION_INFO + validated PAC_DEVICE_INFO / device claims':'PAC KERB_VALIDATION_INFO'},['wslDC',serviceActor],{wire:'Ticket('+target+'; '+serviceAccount+' ciphertext)',...(f.retainServiceCredential?{retention:'retained'}:{})});
  if(beforeIssue&&beforeIssue(a,{request,proof,subkey,sourceKey,target})===false){
    if(compoundArmor){
      const error=a.object('compound-fast-error','Protected compound TGS policy error','reply','wslDC',{requestId,nonce:52001,padata:[{type:137,value:{errorCode:compoundArmor.errorCode||'KDC_ERR_POLICY',reason:compoundArmor.failureReason||'target service authentication policy',eData:null}}],strengthenKey:null,finished:null},['wslDC','wslLSA'],{wire:'KRB-ERROR.e-data METHOD-DATA -> PA-FX-FAST -> enc-fast-rep(armor_key, usage52; PA-FX-ERROR137; nonce)'});
      a.add('compound-error-protect','Create standardized protected TGS error without ticket or strengthen-key','wslDC','wslDC',{uses:[fastArmor],creates:[error]});
      a.add('compound-error-response','Deliver protected TGS policy error to protocol client','wslDC','wslLSA',{objects:[error],wire:true});
      a.add('compound-error-decode','Validate armor integrity, nonce and inner PA-FX-ERROR before client knowledge','wslLSA','wslLSA',{uses:[fastArmor],receives:[{object:error,actor:'wslLSA',kind:'decrypt'}],verify:[error],puts:{clientPolicyErrorAccepted:true},summary:'RFC6113 5.4.4: ignore unauthenticated outer error text; decrypt usage52, validate nonce and process PA-FX-ERROR137. Error has neither strengthen-key nor finished. No service ticket is created.'});
    }
    return false;
  }
  const key=a.object('host-session-key','Independent host ticket session key','session-key','wslDC','HANDLE(independent host ticket session key)',['wslDC','wslLSA',serviceActor],f.retainServiceCredential?{retention:'retained'}:{});
  let clientReplyKey=subkey,fastResponse=null,strengthen=null;
  if(compoundArmor){
    strengthen=a.object('compound-strengthen-key','Mandatory FAST TGS strengthen key','session-key','wslDC',{key:'HANDLE(fresh independent FAST strengthen key)',requestId},['wslDC','wslLSA']);
    clientReplyKey=a.object('compound-final-reply-key','Strengthened TGS reply key','session-key','wslDC',{derivation:'CF2(strengthen-key, original user authenticator subkey, "strengthenkey", "replykey")',strengthenRef:strengthen.artifactId,originalReplyRef:subkey.artifactId,requestId,nonce:52001,target,keyUsage:9},['wslDC','wslLSA']);
    fastResponse=a.object('compound-fast-response','Protected FAST TGS response and finished binding','reply','wslDC',{requestId,nonce:52001,strengthenRef:strengthen.artifactId,finishedTicket:ticket.artifactId,finishedChecksumUsage:53,client:account},['wslDC','wslLSA'],{wire:'enc-fast-rep(armor_key, usage52; mandatory strengthen-key; finished ticket checksum53)'});
    a.add('compound-response-protect','Create mandatory TGS strengthening and protected finished metadata','wslDC','wslDC',{uses:[fastArmor,subkey],creates:[strengthen,clientReplyKey,fastResponse]});
  }
  const reply=a.object('host-client-reply','Protected TGS client part','reply','wslDC',{requestId,nonce:52001,server:target,sessionKeyRef:key.artifactId,replyKeyRef:clientReplyKey.artifactId,keyUsage:9},['wslDC','wslLSA'],{wire:compoundArmor?'EncryptedData(CF2 strengthened TGS reply key, key usage9, EncTGSRepPart)':'EncryptedData(fresh authenticator subkey, key usage9, EncTGSRepPart)'});
  a.add('host-ticket','KDC encrypts distinct host ticket and request-bound client reply','wslDC','wslDC',{uses:[authorityKey,clientReplyKey],verify:[request],creates:[ticket,key,reply],summary:compoundArmor?'Validated compound TGS policy admits this ticket; the client reply uses mandatory FAST strengthening of the original user authenticator subkey. Service key and new service session key remain independent.':'After TGT/authenticator/request verification the KDC encrypts the host ticket under its authoritative WORKSTATION$ account key, but the client reply under this request authenticator subkey using key usage9. The workstation-local service key is separate and is never transported. The new host session key is independent of all these keys.'});a.add('host-tgs-reply','Receive host TGS reply ciphertext','wslDC','wslLSA',{objects:[ticket,reply,...(fastResponse?[fastResponse]:[])],wire:true,type:'network-exchange'});
  if(compoundArmor){
    a.add('compound-response-check','Decode and verify FAST response before accepting client credential','wslLSA','wslLSA',{uses:[fastArmor,subkey],receives:[{object:fastResponse,actor:'wslLSA',kind:'decrypt'},{object:strengthen,actor:'wslLSA',kind:'decrypt'}],verify:[fastResponse],summary:'Decrypt enc-fast-rep usage52; verify nonce, client identity, finished exact ticket checksum53 and mandatory strengthen-key. Receipt alone installs no service credential.'});
    a.add('compound-client-strengthen','Independently derive strengthened TGS client reply key','wslLSA','wslLSA',{uses:[strengthen,subkey],receives:[{object:clientReplyKey,actor:'wslLSA',kind:'derive'}]});
  }
  let selectedReplyKey=clientReplyKey;
  if(f.hostReplyContext==='missing'){
    a.add('host-reply-context-select','The pending request has lost its local reply-key holding','wslLSA','wslLSA',{releases:[{object:subkey,actor:'wslLSA',store:'local IPC inbox'}]});selectedReplyKey=null;
  }else if(f.hostReplyContext==='wrong'){
    selectedReplyKey=a.object('wrong-host-reply-subkey','Unrelated pending-request subkey','session-key','wslLSA',{key:'HANDLE(unrelated request authenticator subkey)',requestId:a.id+':other-host-request',nonce:52002,target,keyUsage:9},['wslLSA']);
    a.add('host-reply-context-select','Select a mismatched local pending-request context','wslLSA','wslLSA',{creates:[selectedReplyKey]});
  }
  if(!selectedReplyKey||selectedReplyKey.artifactId!==reply.value.replyKeyRef||selectedReplyKey.value.requestId!==request.value.requestId||selectedReplyKey.value.nonce!==request.value.nonce||selectedReplyKey.value.target!==request.value.sname){
    a.deny('host-reply-context','wslLSA','missing or mismatched TGS authenticator subkey for this pending reply',buffer,[],{uses:selectedReplyKey?[selectedReplyKey]:[],verify:[request]});return false;
  }
  a.add('host-reply-context-check','Match the held subkey to the pending request before decryption','wslLSA','wslLSA',{uses:[selectedReplyKey],verify:[request]});
  a.add('host-client-decode','Decrypt scoped TGS client part with the matching authenticator subkey','wslLSA','wslLSA',{uses:[selectedReplyKey],receives:[{object:reply,actor:'wslLSA',kind:'decrypt'}]});a.add('host-tgs-accept','Validate TGS client nonce, SPN and lifetime','wslLSA','wslLSA',{verify:[reply],receives:[{object:key,actor:'wslLSA'},...(f.retainServiceCredential?[{object:ticket,actor:'wslLSA',store:'accepted service credential',representation:'wire',retention:'retained'}]:[])]});
  if(f.serviceActor){a.serviceContext=wslRemoteService(a,{ticket,key,serviceKey:machineKey,account,userSid:f.userSid,target,serviceActor,prefix:'host'});return !!a.serviceContext;}
  a.add('local-ticket-submit','Pass opaque host ticket to local workstation acceptor','wslLSA','wslMachine',{objects:[ticket],representation:'wire',type:'local-call',summary:'Distinct-owner local IPC, not a fabricated network AP exchange.'});
  if(f.hostKeyMatches===false){a.deny('local-ticket-check','wslMachine','host ticket cannot be accepted under selected machine identity',buffer,[],{uses:[machineKey]});return false;}
  a.add('local-ticket-decode','Interpret ticket with the machine service key locally','wslMachine','wslMachine',{uses:[machineKey],receives:[{object:ticket,actor:'wslMachine',kind:'decrypt'},{object:key,actor:'wslMachine'}]});
  const sid=f.userSid||(account.endsWith('admin2')?'S-1-5-21-440-550-660-1102':'S-1-5-21-440-550-660-1101'),facts=a.object('validated-logon-information','Validated domain logon data','identity','wslMachine',{account,userSid:sid,domainGroups:['S-1-5-21-440-550-660-513'],source:'MS-PAC2.5 KERB_VALIDATION_INFO; selected checks accepted'},['wslMachine','wslLSA']);
  a.add('local-ticket-check','Validate interpreted host ticket and authorization data','wslMachine','wslMachine',{verify:[ticket],creates:[facts],puts:{hostTicketAccepted:true}});a.add('logon-facts-return','Return domain facts to local policy','wslMachine','wslLSA',{objects:[facts],type:'local-call'});return true;
}
export function wslRemoteService(a,{ticket,key,serviceKey,account,userSid,target,clientActor='wslLSA',serviceActor='wslFile',prefix='host'}){
  const requestId=a.id+':'+prefix+'-ap-1',ctime='SYM(fresh '+requestId+' time)',usec=1;
  const krbSource='https://www.rfc-editor.org/rfc/rfc4120#section-3.2',gssSource='https://www.rfc-editor.org/rfc/rfc4121';
  const options={source:krbSource,standard:'RFC4120 3.2 / 5.5; MS-KILE Windows AES mutual authentication'};
  const initiator=a.object(prefix+'-initiator-subkey','Fresh service AP initiator subkey','session-key',clientActor,'HANDLE(fresh '+prefix+' AP initiator subkey)',[clientActor,serviceActor],options);
  const authenticator=a.object(prefix+'-ap-request','Fresh target-service AP authenticator','proof',clientActor,{requestId,client:account,target,ctime,cusec:usec,keyUsage:11,sessionKeyRef:key.artifactId,initiatorSubkey:initiator.artifactId,gssChecksum:{type:'0x8003',flags:['mutual','integrity','confidentiality','replay','sequence'],channelBinding:'declared null binding input; no external transport-binding claim'}},[clientActor,serviceActor],{...options,wire:'AP-REQ{opaque target ticket; Authenticator encrypted in ticket-session key, usage11}'});
  a.add(prefix+'-ap-prepare','Create a fresh service authenticator, distinct from TGS proof',clientActor,clientActor,{uses:[key],objects:[ticket],representation:'wire',creates:[initiator,authenticator]});
  const apLayers=[{protocol:'Kerberos AP',transport:'declared service application channel',from:clientActor,to:serviceActor,protection:'Target-encrypted ticket and usage11 authenticator; no raw key transfer'}];
  a.add(prefix+'-ap-request','Present target ticket and fresh service proof',clientActor,serviceActor,{objects:[ticket,authenticator],wire:true,protocolLabel:'Kerberos AP-REQ / target service',layers:apLayers});
  a.add(prefix+'-service-decode','Interpret ticket and authenticator using the target-owned service key',serviceActor,serviceActor,{uses:[serviceKey],receives:[{object:ticket,actor:serviceActor,kind:'decrypt'},{object:key,actor:serviceActor,kind:'decrypt',retention:'retained'},{object:authenticator,actor:serviceActor,kind:'decrypt'},{object:initiator,actor:serviceActor,kind:'decrypt'}]});
  const serviceMatches=ticket.value.server===target&&authenticator.value.target===target&&authenticator.value.client===ticket.value.client&&(!ticket.value.serviceAccount||serviceKey.value.account===ticket.value.serviceAccount);
  if(!serviceMatches){a.deny(prefix+'-service-check',serviceActor,'ticket, authenticator or provisioned service identity mismatch',null,[],{replyActor:clientActor});return null;}
  const facts=a.object(prefix+'-validated-service-facts','Validated target-service PAC identity','identity',serviceActor,{account:ticket.value.client,userSid:ticket.value.userSid||userSid,source:'Verified target ticket and PAC; same-domain writable KDC',requestId},[serviceActor],{...options,retention:'retained'});
  const context=a.object(prefix+'-service-context','Server-owned authenticated service context','session',serviceActor,{contextId:a.id+':'+prefix+'-service-context',userSid:facts.value.userSid,role:'server authorization context; local opaque token reference',nativeTokenFields:null,factsRef:facts.artifactId},[serviceActor],{...options,retention:'retained'});
  a.add(prefix+'-service-check','Validate service identity, freshness, replay and PAC before creating context',serviceActor,serviceActor,{verify:[ticket,authenticator],creates:[facts,context],puts:{hostTicketAccepted:true,serverServiceProofAccepted:true}});
  const acceptor=a.object(prefix+'-acceptor-subkey','Distinct Windows AES acceptor subkey','session-key',serviceActor,'HANDLE(distinct '+prefix+' completed-context acceptor subkey)',[serviceActor,clientActor],{source:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8',standard:'MS-KILE cryptographic material; RFC4121 2 / 4.2.2',retention:'retained'});
  const reply=a.object(prefix+'-ap-reply','Mutual service AP-REP','reply',serviceActor,{requestId,ctime,cusec:usec,keyUsage:12,acceptorSubkeyRef:acceptor.artifactId},[serviceActor,clientActor],{...options,wire:'AP-REP.enc-part = EncAPRepPart(ticket-session key, usage12; echoed time; distinct acceptor subkey)'});
  a.add(prefix+'-service-reply-prepare','Create mutual proof and independent completed-context subkey',serviceActor,serviceActor,{uses:[key,authenticator],creates:[acceptor,reply]});
  a.add(prefix+'-service-reply','Return target-service mutual authentication proof',serviceActor,clientActor,{objects:[reply],wire:true,protocolLabel:'Kerberos AP-REP / target service',layers:[{protocol:'Kerberos AP',transport:'declared service application channel',from:serviceActor,to:clientActor,protection:'EncAPRepPart in ticket-session key, usage12'}]});
  a.add(prefix+'-mutual-decode','Decrypt mutual reply into unaccepted request scratch',clientActor,clientActor,{uses:[key],receives:[{object:reply,actor:clientActor,kind:'decrypt'},{object:acceptor,actor:clientActor,store:'unaccepted AP reply scratch',kind:'decrypt',retention:'temporary'}]});
  const correlated=reply.value.requestId===authenticator.value.requestId&&reply.value.ctime===authenticator.value.ctime&&reply.value.cusec===authenticator.value.cusec;
  if(!correlated){a.deny(prefix+'-mutual-check',clientActor,'AP-REP does not match the pending service authenticator',null,[],{replyActor:'wslProcess'});return null;}
  a.add(prefix+'-mutual-accept','Verify exact AP-REP correlation before installing completed service context',clientActor,clientActor,{verify:[reply],receives:[{object:acceptor,actor:clientActor,store:'completed service context',retention:'retained'}],releases:[{object:acceptor,actor:clientActor,store:'unaccepted AP reply scratch'}],puts:{networkAuthenticated:true,clientServiceContextAccepted:true}});
  return {ticket,key,initiator,acceptor,authenticator,reply,facts,context,clientActor,serviceActor,target,source:gssSource};
}


const wslExplicitVariants={default:{},'domain-password-for-local-user':{passwordMatches:false,inputAuthority:'CORP'},'local-account-missing':{accountExists:false},'local-sid-denied':{aclAllows:false}};
function wslExplicitLocal(variantId='default'){
  if(!Object.hasOwn(wslExplicitVariants,variantId))throw new RangeError('Unknown WLOG03 variant');
  const f={joined:true,authority:'WORKSTATION',accountExists:true,passwordMatches:true,aclAllows:true,inputAuthority:'WORKSTATION',...wslExplicitVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog03',code:'WLOG03',title:'Explicit local account on a domain member: same name, different SID',family:'windows-logon',variantId,summary:'WORKSTATION\\alice is not CORP\\alice; the selected account authority never silently changes.',relatedLessons:[{id:'lab-wlog02',title:'Online domain alice',summary:'Different SID and authority; separate authored context.'},{id:'lab-welev05',title:'Network-only credentials',summary:'Outbound identity can differ without replacing this desktop.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  const policy=wslSeedPolicy(a,f),verifier=f.accountExists?a.seed(a.object('sam-verifier','WORKSTATION alice verifier','credential','wslSAM','HANDLE(local SAM alice verifier)',['wslSAM'])):null;
  const scope=a.object('account-scope','Explicit normalized local account scope','identity','wslUI',{entered:'.\\alice',normalized:'WORKSTATION\\alice',localSid:'S-1-5-21-110-220-330-1002',domainComparisonSid:'S-1-5-21-440-550-660-1101'},['wslUI','wslLSA','wslSAM','wslProcess']);
  a.add('scope','Choose .\\alice and normalize WORKSTATION authority','wslUser','wslUI',{creates:[scope],type:'local-input'});
  a.add('scope-submit','Submit the explicitly selected local account authority','wslUI','wslLSA',{objects:[scope],type:'local-call'});
  const buffer=wslInput(a);a.add('sam-request','Dispatch only to local SAM authority','wslLSA','wslSAM',{objects:[buffer,scope],type:'local-call'});
  if(!f.accountExists||!a.credentialsMatch())return wslCompleteVariant(a.deny('sam','wslSAM',f.accountExists?'domain password does not match explicitly selected local account':'selected local account absent',buffer,[],{uses:verifier?[verifier]:[],verify:[buffer]}),wslExplicitLocal,wslExplicitVariants);
  const result=a.object('sam-validation','Local account validation','identity','wslSAM',{account:'WORKSTATION\\alice',sid:'S-1-5-21-110-220-330-1002',verified:true},['wslSAM','wslLSA']);
  a.add('sam','Validate only local alice','wslSAM','wslSAM',{uses:[verifier],creates:[result],puts:{credentialVerified:true}});a.add('sam-return','Return local account facts','wslSAM','wslLSA',{objects:[result],type:'local-call'});
  const token=wslCreateDesktop(a,'WORKSTATION\\alice',{policy});a.cleanup(buffer);
  if(!f.aclAllows){a.add('acl-denial','Selected ACL excludes local SID','wslProcess','wslProcess',{uses:[token],puts:{resourceAllowed:false}});return wslCompleteVariant(a.deny('compare','wslProcess','local SID cannot satisfy the selected domain-SID allow ACE'),wslExplicitLocal,wslExplicitVariants);}
  const comparison=a.object('sid-comparison','SID-specific ACL comparison','result','wslProcess',{actualSid:'S-1-5-21-110-220-330-1002',comparisonSid:'S-1-5-21-440-550-660-1101',actualAllow:true,comparisonTransfersIdentity:false},['wslProcess']);
  a.add('compare','Evaluate ACL without switching the process principal','wslProcess','wslProcess',{uses:[token],creates:[comparison],puts:{resourceAllowed:true,clientKnowsResult:true}});return wslSealCase(a,wslExplicitLocal,wslExplicitVariants);
}
const wslCachedVariants={default:{},'no-cache':{cacheExists:false},'cache-disabled':{cacheCount:0},'cache-evicted':{cacheExists:false},'cache-mismatch':{passwordMatches:false},'protected-user':{protectedUser:true,cacheExists:false},'online-rejection':{dcReachable:true,onlineRejects:true},'stale-password-or-disable':{remoteAccountChanged:true}};
function wslCachedLogon(variantId='default'){
  if(!Object.hasOwn(wslCachedVariants,variantId))throw new RangeError('Unknown WLOG04 variant');
  const f={joined:true,authority:'CORP',dcReachable:false,onlineRejects:false,cacheExists:true,cacheCount:10,protectedUser:false,passwordMatches:true,remoteAccountChanged:false,...wslCachedVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog04',code:'WLOG04',title:'Offline cached domain validation: local desktop, no fresh KDC grant',family:'windows-logon',variantId,initial:{freshDomainKnowledge:false},summary:'A protected local verifier can allow a disconnected desktop, but is not a transferable domain credential.',relatedLessons:[{id:'lab-wlog02',title:'Fresh online domain logon',summary:'Requires actual KDC responses.'},{id:'lab-wlog07',title:'Unlock an existing session',summary:'Unlock does not create a fresh token.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  const policy=wslSeedPolicy(a,f),buffer=wslInput(a);
  let cache=null;if(f.cacheExists&&f.cacheCount>0&&!f.protectedUser)cache=a.seed(a.object('cached-verifier','Preexisting cached domain verifier and account snapshot','credential','wslSAM',{verifier:'HANDLE(local-only cached verifier; never a network credential)',identity:'CORP\\alice',sid:'S-1-5-21-440-550-660-1101',groupsAsOf:'prior successful online logon'},['wslSAM','wslLSA'],{store:'protected registry cached-domain store'}));
  if(f.dcReachable){wslAddAuthority(a);const online=wslPasswordAS(a,f,{buffer,failureStage:'attempt'});if(!online.denied)throw new TypeError('Cached online-rejection fixture must reject at the actual KDC policy check');return wslCompleteVariant(online.denied,wslCachedLogon,wslCachedVariants);}
  const availability=a.object('availability-result','Authority availability result','result','wslLSA','DC unreachable; no account validation response received',['wslLSA']);
  a.add('attempt','Establish unavailability, not a rejection','wslLSA','wslLSA',{creates:[availability]});
  a.add('cache-policy-request','Ask the protected local store for this prior entry','wslLSA','wslSAM',{objects:[policy],type:'local-call'});
  if(!cache)return wslCompleteVariant(a.deny('cache-policy','wslSAM',f.protectedUser?'Protected Users policy prevented cached verifier creation':f.cacheCount===0?'cached logons disabled':'no retained prior cached verifier',buffer,[],{verify:[policy]}),wslCachedLogon,wslCachedVariants);
  a.add('cache-policy','Evaluate cache policy and locate the retained entry','wslSAM','wslSAM',{uses:[policy,cache]});a.add('cache-read','Return only the local cached-verifier handle to the authentication package','wslSAM','wslLSA',{objects:[cache],type:'local-call'});
  if(!a.credentialsMatch())return wslCompleteVariant(a.deny('verify','wslLSA','current input does not match local cached verifier',buffer,[],{uses:[cache],verify:[buffer]}),wslCachedLogon,wslCachedVariants);
  const validation=a.object('cached-validation','Local cached validation outcome','identity','wslLSA',{verifiedLocally:true,freshDomainApproval:false,account:'CORP\\alice'},['wslSAM','wslLSA']);
  a.add('verify-cache','Compare fresh input with the local cached verifier','wslLSA','wslLSA',{uses:[cache,buffer],creates:[validation]});
  a.add('verify','Accept only local/stale cached validation','wslLSA','wslLSA',{verify:[validation],puts:{credentialVerified:true,freshDomainKnowledge:false}});
  wslCreateDesktop(a,'CORP\\alice',{stage:'session',policy,stale:f.remoteAccountChanged});a.cleanup(buffer);
  a.add('resource','Later network authentication is a separate requirement','wslProcess','wslProcess',{puts:{clientKnowsResult:true,freshDomainKnowledge:false},summary:f.remoteAccountChanged?'A DC-side password/account change is unknown offline. The local verifier can still match; there is no claim of fresh account approval.':'No new AS-REP, TGT or domain status exists in this disconnected session.'});
  return wslSealCase(a,wslCachedLogon,wslCachedVariants);
}
const wslUnlockVariants={default:{},'bad-credential':{passwordMatches:false},'required-dc-unavailable':{unlockMode:'domain-required',dcReachable:false,cacheCount:0},'cached-domain-change':{unlockMode:'domain-cached',remoteAccountChanged:true},'other-user':{selectedUser:'other'},'domain-required':{unlockMode:'domain-required',dcReachable:true,cacheCount:0},'domain-cached':{unlockMode:'domain-cached',cacheCount:10}};
function wslUnlock(variantId='default'){
  if(!Object.hasOwn(wslUnlockVariants,variantId))throw new RangeError('Unknown WLOG07 variant');
  const f={unlockMode:'local',passwordMatches:true,dcReachable:true,cacheCount:10,remoteAccountChanged:false,selectedUser:'locked-user',...wslUnlockVariants[variantId]};f.joined=f.unlockMode!=='local';f.authority=f.joined?'CORP':'WORKGROUPPC';
  const token=wslToken('lab-wlog07:existing-token',f.joined?'CORP\\alice':'WORKGROUPPC\\bob',{luid:'LUID(existing-7)'});
  const a=wslAuthor({id:'lab-wlog07',code:'WLOG07',title:'Unlock the existing local or domain Windows session',family:'windows-logon',variantId,initial:{token,localAccount:token.account,localSid:token.userSid,sessionId:'SESSION(existing-7)',processId:'PID(existing-4700)',desktopReady:true,consoleAllowed:true,locked:false,freshDomainKnowledge:false},summary:'Lock retains existing process/token/session identity. Selected unlock policy decides which authority can release interactive access.',profileControls:[{id:'unlock-policy',label:'Unlock authority and cache policy',value:f.unlockMode,options:[{value:'local',label:'Local account verifier',scenarioId:'lab-wlog07',variantId:'default'},{value:'domain-required',label:'DC required; cache count0',scenarioId:'lab-wlog07',variantId:'domain-required'},{value:'domain-cached',label:'Cached domain facts; cache count10',scenarioId:'lab-wlog07',variantId:'domain-cached'}]}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  const existing=a.seed(a.object('existing-token','Existing primary token and process reference','token','wslProcess',token,['wslProcess','wslLSA'],{store:'existing kernel token reference'}),['wslProcess','wslLSA']);const policy=wslSeedPolicy(a,f);
  const lockState=a.object('lock-state','Interactive session lock request','session','wslProcess',{sessionId:'SESSION(existing-7)',action:'lock'},['wslProcess','wslUI']);a.add('lock','Lock interactive access without logging off or transferring the token','wslProcess','wslUI',{uses:[existing],creates:[lockState],objects:[lockState],puts:{locked:true},type:'local-state'});
  if(f.selectedUser!=='locked-user')return wslCompleteVariant(a.deny('input','wslUI','different identity belongs to switch-user/new logon, not unlock'),wslUnlock,wslUnlockVariants);
  const buffer=wslInput(a,'Unlock credential');a.add('policy','Select effective unlock authority and cache behavior','wslLSA','wslLSA',{uses:[policy]});
  if(f.unlockMode==='domain-required'){
    if(!f.dcReachable)return wslCompleteVariant(a.deny('verify','wslLSA','required DC unavailable; cache count0 forbids a substitute',buffer),wslUnlock,wslUnlockVariants);
    wslAddAuthority(a);const credential=wslPasswordAS(a,{userProofValid:true,clockValid:true},{buffer,account:token.account,acceptedPuts:{freshDomainKnowledge:true}});
    if(credential.denied)return wslCompleteVariant(credential.denied,wslUnlock,wslUnlockVariants);
    const result=a.object('unlock-validation','Bind accepted reauthentication to the existing locked session','identity','wslLSA',{sessionId:'SESSION(existing-7)',userSid:token.userSid,reauthenticationAccepted:true,refreshExistingProcessGroups:false},['wslLSA']);
    a.add('verify','Apply accepted domain proof only to this locked-session identity','wslLSA','wslLSA',{creates:[result],puts:{credentialVerified:true,freshDomainKnowledge:true}});
  }else{
    const verifier=a.seed(a.object('unlock-verifier',f.unlockMode==='domain-cached'?'Preexisting cached unlock validator':'Local account unlock verifier','credential','wslSAM','HANDLE(selected local-only unlock verifier)',['wslSAM']));
    a.add('unlock-local-request','Dispatch to selected local validator','wslLSA','wslSAM',{objects:[buffer],type:'local-call'});
    if(!a.credentialsMatch())return wslCompleteVariant(a.deny('verify','wslSAM','unlock credential rejected; original session remains locked',buffer,[],{uses:[verifier],verify:[buffer]}),wslUnlock,wslUnlockVariants);
    const result=a.object('unlock-validation','Selected local unlock validation','identity','wslSAM',{account:token.account,accepted:true,staleDomainFacts:f.unlockMode==='domain-cached'},['wslSAM','wslLSA']);a.add('verify','Check selected local unlock verifier','wslSAM','wslSAM',{uses:[verifier],creates:[result],puts:{credentialVerified:true,staleKnowledge:f.remoteAccountChanged,freshDomainKnowledge:false}});a.add('unlock-return','Return verification, without refreshing existing groups','wslSAM','wslLSA',{objects:[result],type:'local-call'});
  }
  a.add('resume','Resume the same desktop and processes','wslLSA','wslProcess',{uses:[existing],puts:{locked:false,clientKnowsResult:true},type:'local-state'});a.cleanup(buffer);return wslSealCase(a,wslUnlock,wslUnlockVariants);
}
const wslNonjoinedVariants={default:{},'bad-network-password':{networkPasswordValid:false},'no-kerberos-prerequisite':{networkPrerequisites:false},'resource-denial':{shareAllows:false}};
function wslNonjoined(variantId='default'){
  if(!Object.hasOwn(wslNonjoinedVariants,variantId))throw new RangeError('Unknown WLOG08 variant');
  const f={joined:false,authority:'WORKGROUPPC',networkPasswordValid:true,networkPrerequisites:true,shareAllows:true,...wslNonjoinedVariants[variantId]};
  f.networkMechanism=(!f.networkPasswordValid||!f.shareAllows)?'Explicit accepted NTLMv2 comparison':'Configured Kerberos required';
  const a=wslAuthor({id:'lab-wlog08',code:'WLOG08',title:'Nonjoined PC: local desktop and explicit domain network identity',family:'windows-logon',variantId,summary:'Typing CORP\\alice does not join the PC. Explicit network credentials later authenticate only the separate resource attempt.',relatedLessons:[{id:'lab-smb-nonjoined-kerberos',title:'Accepted configured Kerberos SMB journey',summary:'Separate realm/SPN prerequisites, session and share/file grants.'},{id:'lab-smb-nonjoined-ntlm',title:'Explicit NTLMv2 compatibility',summary:'Not an implicit nonjoined fallback.'},{id:'lab-welev05',title:'runas /netonly',summary:'Defer outbound validation while preserving the local SID.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  const policy=wslSeedPolicy(a,f),membership=a.seed(a.object('membership','Workgroup device membership and console authority','policy','wslLSA',{joined:false,consoleAccountAuthority:'WORKGROUPPC',domainInteractiveRelationship:false},['wslLSA','wslUI']));
  a.add('membership-display','Display the actual local console authority','wslLSA','wslUI',{objects:[membership],type:'local-call'});a.add('scope','Select unsupported domain console identity on nonjoined device','wslUser','wslUI',{type:'local-input'});
  const denied=a.object('console-failure','Domain console logon unsupported in selected workgroup profile','result','wslLSA',{domainConsoleDenied:true,domainTokenCreated:false},['wslLSA','wslUI']);a.add('console-deny','Return explicit domain-console denial','wslLSA','wslUI',{creates:[denied],objects:[denied],puts:{domainConsoleDenied:true},type:'local-result'});
  const verifier=a.seed(a.object('sam-verifier','Local bob account verifier','credential','wslSAM','HANDLE(SAM bob verifier)',['wslSAM']));const buffer=wslInput(a,'Local bob password');a.add('local-sam-request','Submit local bob candidate to SAM','wslLSA','wslSAM',{objects:[buffer],type:'local-call'});a.add('local-validate','SAM validates local bob for this new local logon','wslSAM','wslLSA',{uses:[verifier],puts:{credentialVerified:true},type:'local-call'});wslCreateDesktop(a,'WORKGROUPPC\\bob',{policy});a.cleanup(buffer);
  const outbound=a.object('outbound-credential','Explicit outbound credential context','credential','wslLSA',{account:'CORP\\alice',credential:'HANDLE(scoped explicit network input)',validated:false},['wslLSA'],{store:'scoped network credential context'});a.add('network-input','Enter separate domain network credentials','wslUser','wslLSA',{creates:[outbound],puts:{outboundAccount:'CORP\\alice'},type:'local-input'});
  if(!f.networkPrerequisites){wslAddAuthority(a);return wslCompleteVariant(a.deny('smb','wslProcess','configured Kerberos KDC/SPN/discovery prerequisites unavailable; no NTLM fallback',null,[],{replyActor:'wslProcess'}),wslNonjoined,wslNonjoinedVariants);}
  wslSourceNetwork(a,{badPassword:!f.networkPasswordValid,shareDenied:!f.shareAllows,failureStage:'smb'});return wslSealCase(a,wslNonjoined,wslNonjoinedVariants);
}


const wslCardVariants={default:{},'bad-pin':{pinValid:false},'weak-mapping':{strongMapping:false},'invalid-user-cert':{userCertValid:false},'expired-user-cert':{certificateTimeValid:false},'revoked-user-cert':{revocationGood:false},'untrusted-user-cert':{certificateTrusted:false},'invalid-kdc-proof':{kdcProofValid:false},'card-removed':{cardPresent:false}};
function wslSmartCard(variantId='default'){
  if(!Object.hasOwn(wslCardVariants,variantId))throw new RangeError('Unknown WLOG05 variant');
  const f={joined:true,authority:'CORP',pinValid:true,cardPresent:true,strongMapping:true,userCertValid:true,certificateTimeValid:true,revocationGood:true,certificateTrusted:true,kdcProofValid:true,hostSpnValid:true,hostKeyMatches:true,...wslCardVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog05',code:'WLOG05',title:'Smart-card sign-in: local PIN, PKINIT and local desktop',family:'windows-logon',variantId,initial:{passwordCredential:false},summary:'Reuse the accepted AD03 fresh-DH protocol and its exact corrected key lineage, then continue host-ticket/local policy stages.',profile:{supportStatus:'RFC fresh-DH architectural composition; modern Windows algorithm, freshness and native inspection gates explicitly unresolved',algorithms:['Accepted RFC4556 fresh-DH reference; distinct DH/reply/TGT keys','Current strong binding required; no RSA key-transport or weak-UPN default','MS-PKCA24.0 modern CMS/PAChecksum2/CG nonce gates recorded in source matrix']},relatedLessons:[{id:'lab-ad-pkinit-success',title:'Accepted AD03 PKINIT fresh DH',summary:'Exact protocol/key history reused here; standalone context is separate.'},{id:'lab-ad-pkinit-binding',title:'Strong binding denial',summary:'Certificate trust does not establish account binding.'},{id:'lab-wlog02',title:'Host ticket and local desktop admission',summary:'Tokens are created by the workstation, not by the KDC.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  wslAddAuthority(a);a.actors.wslCard={id:'wslCard',name:'Provisioned smart card / CSP-KSP',role:'Local PIN authorization and nonexportable signing key',kind:'authenticator',color:'#7c3aed'};
  const policy=wslSeedPolicy(a,f),buffer=wslInput(a,'Protected local PIN input','credential-input',['wslUI','wslLSA','wslCard']);
  const certificate=a.seed(a.object('selected-certificate','Provisioned public certificate selection','certificate','wslCard',{certificate:'SYM(public certificate and issuer chain)',strongBinding:'SID or explicit issuer/serial binding; enrollment preexisting'},['wslCard','wslLSA','wslDC']));
  a.add('certificate-selection','Return the selected public certificate to the local package','wslCard','wslUI',{objects:[certificate],type:'local-call'});a.add('select','Authorize the selected card operation through local PIN input','wslUI','wslCard',{objects:[buffer],uses:[certificate],type:'local-call'});
  if(!f.cardPresent)a.add('card-removal','Remove selected card before the required private-key operation','wslUser','wslCard',{puts:{cardAvailableForSigning:false},type:'local-state'});
  if(!a.credentialsMatch()||!f.cardPresent){a.seed(a.object('card-key','Provisioned nonexportable signing key','credential','wslCard','HANDLE(card private key; never exported)',['wslCard']));return wslCompleteVariant(a.deny('sign','wslCard',f.cardPresent?'card rejects PIN authorization':'card removed before required private-key operation',buffer),wslSmartCard,wslCardVariants);}
  const badCert=!f.userCertValid||!f.certificateTimeValid||!f.revocationGood||!f.certificateTrusted;
  const sourceVariant=!f.strongMapping?'binding':badCert?'trust':!f.kdcProofValid?'kdc-trust':'success';
  const source=wslAcceptedCrypto('lab-ad-pkinit-'+sourceVariant);
  const failed=sourceVariant!=='success',stage=sourceVariant==='kdc-trust'?'accept':'pkinit',detector=sourceVariant==='kdc-trust'?'wslLSA':'wslDC',sourceDetector=sourceVariant==='kdc-trust'?'client-reject':'kdc-reject';
  const reason=sourceVariant==='binding'?'certificate cannot be strongly bound to selected account':sourceVariant==='trust'?!f.certificateTimeValid?'user certificate expired':!f.revocationGood?'user certificate revoked':!f.certificateTrusted?'user certificate chain untrusted':'user certificate purpose/trust check rejected':'KDC signed DH proof not accepted';
  let valueOverrides={};
  if(badCert){
    const definitions=Object.entries(source.definitions()),trustDefinition=definitions.find(([field])=>field.endsWith('CertificateTrust'))?.[1],rejectionDefinition=definitions.find(([field])=>field.endsWith('Rejection'))?.[1];
    if(!trustDefinition||!rejectionDefinition)throw new TypeError('Accepted PKINIT rejection path requires its explicit trust/rejection field schema');
    valueOverrides={[trustDefinition.example]:'KDC certificate validation context: '+reason,[rejectionDefinition.example]:reason};
  }
  wslAppendSource(a,source,'ad',failed?undefined:'accept-tgt',{valueOverrides,aliases:failed?{[sourceDetector]:stage}:{},effects:failed?{[sourceDetector]:{failure:{stage,reason},detector,clientKnowsResult:false}}:{}});
  if(failed){a.add('pkinit-result','Deliver selected authentication failure to LogonUI','wslLSA','wslUI',{puts:{clientKnowsResult:true},summary:'The preceding accepted source events distinguish KDC certificate rejection, protected reply receipt and local KDC-proof rejection. No user TGT or local token was installed.',type:'local-result'});a.cleanup(buffer);return wslSealCase(a,wslSmartCard,wslCardVariants);}
  a.add('accept','Install accepted user credential handle, not a password','wslLSA','wslLSA',{puts:{credentialVerified:true,tgtAccepted:true,passwordCredential:false,outboundAccount:'CORP\\alice'},summary:'The mapped AD03 accept-tgt event has verified/decrypted the AS client part. The local LSA references an opaque protected TGT credential; the card PIN/private key are not reusable domain passwords.'});
  if(!wslHostTicket(a,f,{policy,buffer}))return wslCompleteVariant(a.finish(),wslSmartCard,wslCardVariants);
  wslCreateDesktop(a,'CORP\\alice',{policy});a.cleanup(buffer);a.add('result','Desktop result becomes visible','wslProcess','wslUI',{puts:{clientKnowsResult:true},type:'local-result'});return wslSealCase(a,wslSmartCard,wslCardVariants);
}
const wslFastVariants={default:{},'armor-missing':{machineTgt:false},'realm-or-dc-unsupported':{fastSupported:false},'realm-unsupported':{realmFast:false},'dc-unsupported':{dcFast:false},'tampered-fast':{fastRequestValid:false},'tampered-fast-reply':{fastReplyValid:false},'bad-user-proof':{userProofValid:false},bootstrap:{machineTgt:false,bootstrap:true}};
function wslFast(variantId='default'){
  if(!Object.hasOwn(wslFastVariants,variantId))throw new RangeError('Unknown WLOG06 variant');
  const f={joined:true,authority:'CORP',machineTgt:true,fastSupported:true,realmFast:true,dcFast:true,fastRequestValid:true,fastReplyValid:true,userProofValid:true,hostSpnValid:true,hostKeyMatches:true,bootstrap:false,...wslFastVariants[variantId]};
  const a=wslAuthor({id:'lab-wlog06',code:'WLOG06',title:'Required FAST: computer armor, user proof and local desktop',family:'windows-logon',variantId,initial:{machineAccepted:false,replyStrengthened:false},summary:'Reuse accepted AD04 PA-ENCRYPTED-CHALLENGE and corrected reply strengthening without conflating computer and user identities.',relatedLessons:[{id:'lab-ad-fast-as-success',title:'Accepted armored user AS',summary:'Exact operation/key history reused in this composite.'},{id:'lab-ad-fast-as-bootstrap',title:'Computer bootstrap exception',summary:'No recursive requirement to already possess machine armor.'},{id:'lab-ad-fast-as-optional-fallback',title:'Explicit optional FAST comparison',summary:'Not an automatic fallback in this required profile.'}]},f,variantId==='default'?WINDOWSLOGONLAB_ATTRIBUTES:null);
  wslAddAuthority(a);const policy=wslSeedPolicy(a,f);wslDispatchPackage(a);
  if(!f.machineTgt||!f.fastSupported||!f.realmFast||!f.dcFast)return wslCompleteVariant(a.deny('armor-ready',!f.machineTgt?'wslMachine':'wslLSA',!f.machineTgt?f.bootstrap?'computer bootstrap must run separately before this user-AS journey':'required computer armor credential missing':'required realm/DC FAST capability unavailable'),wslFast,wslFastVariants);
  a.add('armor-ready','Check required FAST policy and existing computer armor','wslLSA','wslMachine',{objects:[policy],summary:'Computer authentication is not Alice authentication. Required FAST has no unadvertised password-AS fallback.'});
  const sourceVariant=!f.fastRequestValid?'checksum':!f.userProofValid?'challenge':!f.fastReplyValid?'response-nonce':'success';
  const source=wslAcceptedCrypto('lab-ad-fast-as-'+sourceVariant);
  const failed=sourceVariant!=='success',replyFailure=sourceVariant==='response-nonce',stage=replyFailure?'accept':'kdc',detector=replyFailure?'wslLSA':'wslDC',sourceDetector=replyFailure?'response-reject':'kdc-reject',effects={'armor-kdc':{machineAccepted:true}};
  if(failed)effects[sourceDetector]={failure:{stage,reason:replyFailure?'protected FAST reply nonce/binding rejected':sourceVariant==='checksum'?'FAST request checksum rejected':'valid armor but Alice user proof rejected'},detector,clientKnowsResult:false};
  wslAppendSource(a,source,'ad',undefined,{aliases:failed?{[sourceDetector]:stage}:{},effects});
  if(failed){a.add('fast-result','Deliver the accepted protected failure to sign-in UI','wslLSA','wslUI',{puts:{clientKnowsResult:true},summary:'Mapped AD04 protects and accepts the error separately from its wire receipt. Machine credential and prior disclosures remain; no user credential or desktop grant.',type:'local-result'});return wslSealCase(a,wslFast,wslFastVariants);}
  a.add('accept','Accept strengthened user AS credential through protected package handle','wslLSA','wslLSA',{puts:{credentialVerified:true,tgtAccepted:true,replyStrengthened:true,outboundAccount:'CORP\\alice'},summary:'Corrected AD04 uses CF2(strengthen-key,padata-reply-key,"strengthenkey","replykey") and an independent issued user TGT session key. Neither armor nor computer identity substitutes for Alice proof.'});
  if(!wslHostTicket(a,f,{policy}))return wslCompleteVariant(a.finish(),wslFast,wslFastVariants);
  wslCreateDesktop(a,'CORP\\alice',{policy});a.add('result','Publish local desktop completion','wslProcess','wslUI',{puts:{clientKnowsResult:true},type:'local-result'});return wslSealCase(a,wslFast,wslFastVariants);
}


export function wslRegisterFields(modelId,registry,keys,sourceModels=[]){
  const prefix=modelId.replace(/-/g,'_')+'_',declared=wslFieldCatalog.get(modelId)||new Set();
  for(const key of keys){const fieldId=prefix+key.replace(/-/g,'_');declared.add(fieldId);registry[fieldId]||=labAttribute(key.replace(/-/g,' '),'Declared Windows workstation field schema; the active fixture supplies its exact value and representation.','Explicit scenario-owned local authority or creator.','Make this field discoverable for every required named input case without constructing all variants at startup.','HANDLE(case-specific symbolic value)','Windows security API / pinned source matrix',wslSource);}
  for(const {model,kind} of sourceModels)for(const [sourceField,definition] of Object.entries(model.definitions())){const fieldId=prefix+kind+'_'+sourceField;declared.add(fieldId);registry[fieldId]||=definition;}
  wslFieldCatalog.set(modelId,declared);
}
const wslHostFields=['machine-service-key','kdc-krbtgt-key','credential-context-reference','host-operation-proof','host-reply-subkey','wrong-host-reply-subkey','host-tgs-request','host-ticket','host-session-key','host-client-reply','validated-logon-information','failure-host-reply-context'];
const wslDesktopFields=['primary-token','profile'];
const wslSchemas={
  'lab-wlog01':['sam-verifier','local-policy','credential-input','logon-request','validation-result','logon-luid','primary-token','desktop-session','file-decision','failure-verify','failure-authorize','failure-desktop'],
  'lab-wlog02':['local-policy','credential-input','client-user-key','kdc-user-key','as-request','tgt','tgt-session-key','as-client-reply',...wslHostFields,...wslDesktopFields,'failure-as','failure-host-ticket','failure-local-ticket-check','failure-token'],
  'lab-wlog03':['local-policy','sam-verifier','account-scope','credential-input','sam-validation',...wslDesktopFields,'sid-comparison','failure-sam','failure-compare'],
  'lab-wlog04':['local-policy','credential-input','cached-verifier','client-user-key','kdc-user-key','kdc-account-policy','as-request','availability-result','cached-validation',...wslDesktopFields,'failure-cache-policy','failure-verify','failure-attempt'],
  'lab-wlog05':['local-policy','credential-input','selected-certificate','card-key',...wslHostFields,...wslDesktopFields,'failure-sign','failure-host-ticket','failure-local-ticket-check'],
  'lab-wlog06':['local-policy',...wslHostFields,...wslDesktopFields,'failure-armor-ready','failure-host-ticket','failure-local-ticket-check'],
  'lab-wlog07':['existing-token','lock-state','local-policy','credential-input','unlock-validation','unlock-verifier','client-user-key','kdc-user-key','as-request','tgt','tgt-session-key','as-client-reply','failure-input','failure-verify'],
  'lab-wlog08':['local-policy','membership','console-failure','sam-verifier','credential-input',...wslDesktopFields,'outbound-credential','failure-smb']
};
for(const [id,keys] of Object.entries(wslSchemas)){
  const sourceModels=id==='lab-wlog05'?CRYPTOLAB_SCENARIOS.filter(m=>m.id.startsWith('lab-ad-pkinit-')).map(model=>({model,kind:'ad'})):id==='lab-wlog06'?CRYPTOLAB_SCENARIOS.filter(m=>['lab-ad-fast-as-success','lab-ad-fast-as-checksum','lab-ad-fast-as-challenge','lab-ad-fast-as-response-nonce'].includes(m.id)).map(model=>({model,kind:'ad'})):id==='lab-wlog08'?SMBLAB_SCENARIOS.filter(m=>['lab-smb-nonjoined-kerberos','lab-smb-nonjoined-bad-credential','lab-smb-nonjoined-share-denied'].includes(m.id)).map(model=>({model,kind:'smb'})):[];
  wslRegisterFields(id,WINDOWSLOGONLAB_ATTRIBUTES,[...keys,'authentication-package',...(id==='lab-wlog08'?['network-request','network-result']:[]),...(['lab-wlog02','lab-wlog07'].includes(id)?['kdc-account-policy']:[]),...(['lab-wlog05','lab-wlog06'].includes(id)?['ad-configured-material']:[])],sourceModels);
}
const wslFactories={'lab-wlog01':wslLocalLogon,'lab-wlog02':wslOnlineLogon,'lab-wlog03':wslExplicitLocal,'lab-wlog04':wslCachedLogon,'lab-wlog05':wslSmartCard,'lab-wlog06':wslFast,'lab-wlog07':wslUnlock,'lab-wlog08':wslNonjoined};
export const WINDOWSLOGONLAB_SCENARIOS=Object.values(wslFactories).map(factory=>factory());
export function buildWindowsLogonFixture(scenarioId,variantId='default'){const factory=wslFactories[scenarioId];if(!factory)throw new RangeError('Unknown Windows logon fixture: '+scenarioId);return factory(variantId);}

