import { CRYPTOLAB_ATTRIBUTES } from './kerberos-crypto-lab.js';
import { SMBLAB_ATTRIBUTES, SMBLAB_SCENARIOS } from './smb-access-lab.js';
import { buildWindowsRemoteSmbReference, WINDOWSREMOTELAB_ATTRIBUTES } from './windows-remote-administration-lab.js';
import { wslAuthor, wslFreeze, wslAddAuthority, wslPasswordAS, wslHostTicket, wslRemoteService, wslAppendSource, wslAppendFastPolicyError, wslAcceptedCrypto, wslSourceNetwork, wslRegisterFields, wslInput } from './windows-logon-lab.js';

// Inputs are declared independently of the source-only expectation ledger.
const wprotCases=wslFreeze({
 WPROT01:{'running-kerberos':{},'disabled-comparison':{credentialGuard:false,cgConfigured:false},'configured-not-running':{credentialGuard:false},'local-account':{accountAuthority:'SAM',mechanism:'NTLMv2'},'service-ticket-custody':{},'authority-still-usable':{},'credssp-default-unavailable':{operation:'CredSSP',credentialSource:'signed-in'},'explicit-prompted-input':{credentialSource:'prompted',mechanism:'NTLMv2'},'ntlmv2-operation':{mechanism:'NTLMv2'},'unconstrained-unavailable':{delegation:'unconstrained'},'constrained-continuation':{delegation:'constrained'},'credential-manager-types':{operation:'CredentialManager'}},
 WPROT02:{'protected-access-blocked':{processRequest:true},'protection-absent':{pplRunning:false,pplConfigured:false,processRequest:true},'audit-plugin':{pluginMode:'audit',pluginSigningLevel:'third-party',sharedSections:true,pplRunning:false},'enforce-plugin':{pluginSigningLevel:'third-party',sharedSections:true},'compatible-plugin':{},'ppl-and-cg':{credentialGuard:true,cgConfigured:true,processRequest:true},'configured-not-effective':{pplRunning:false,processRequest:true},'unaffected-authentication':{pluginSigningLevel:'third-party',sharedSections:true,pluginOptional:true}},
 WPROT03:{'aes-kerberos':{},'ntlm-denied':{mechanism:'NTLMv2'},'rc4-preauth-denied':{etype:'RC4'},'des-preauth-denied':{etype:'DES'},'unconstrained-denied':{delegation:'unconstrained'},'constrained-denied':{delegation:'constrained'},'offline-unavailable':{offline:true},'lifetime-expired':{nowMinutes:241,existingCredential:true},'fresh-authentication':{nowMinutes:241,existingCredential:true,freshAuthentication:true},'membership-next-signin':{membershipChanged:true,existingCredential:true}},
 WPROT04:{'allowed-device':{},'device-denied-audit':{deviceAllowed:false,enforced:false},'device-denied-enforce':{deviceAllowed:false},'required-armor-missing':{machineTgt:false},'forged-device-label':{armorValid:false,deviceLabel:'WORKSTATION'},'direct-policy':{assignedSilo:false,siloMember:false},'policy-lifetime':{allowedFrom:false,armored:false,lifetimeMinutes:90},'ineligible-domain':{domainFunctionality:5}},
 WPROT05:{'allowed-service':{},'target-rule-audit':{targetAllowed:false,siloEnforced:false},'target-rule-enforce':{targetAllowed:false},'ticket-then-acl-denial':{resourceAllows:false},'required-context-missing':{deviceClaims:false},'no-target-policy':{targetPolicy:false},'assigned-only':{siloMember:false},'member-only':{assignedSilo:false},'silo-over-direct':{directEnforced:false},'account-type-selection':{},'domain-rid500-exception':{domainRid:500,ownAccountAS:true,targetPolicy:false,lifetimeMinutes:90},'silo-audit-state':{siloEnforced:false,directEnforced:true,targetAllowed:false}}
});
const wprotSubfixtures=wslFreeze({
 'WPROT05/account-type-selection/user':{targetAccountType:'User'},'WPROT05/account-type-selection/managed-service':{targetAccountType:'ManagedServiceAccount'},'WPROT05/account-type-selection/computer':{targetAccountType:'Computer'},
 'WPROT01/credential-manager-types/windows-domain':{credentialManagerType:'Windows-domain'},'WPROT01/credential-manager-types/generic':{credentialManagerType:'generic'},
 'WPROT03/membership-next-signin/old-session':{membershipPhase:'old-session'},'WPROT03/membership-next-signin/new-signin':{membershipPhase:'new-signin'},
 'WPROT03/lifetime-expired/renewal':{lifetimeOperation:'renewal'},'WPROT03/fresh-authentication/fresh-lineage':{lifetimeOperation:'fresh-AS'},
 'WPROT01/constrained-continuation/kcd':{delegationMode:'KCD'},'WPROT01/constrained-continuation/rbcd':{delegationMode:'RBCD'}
});
const wprotDefaultSubfixtures=wslFreeze({'WPROT01/credential-manager-types':'windows-domain','WPROT01/constrained-continuation':'kcd','WPROT03/membership-next-signin':'new-signin','WPROT03/lifetime-expired':'renewal','WPROT03/fresh-authentication':'fresh-lineage','WPROT05/account-type-selection':'computer'});
const wprotTitles={WPROT01:'Credential Guard: protected custody and usable authority',WPROT02:'LSA protection: process and plugin boundaries',WPROT03:'Protected Users: client and DC restrictions',WPROT04:'Authentication policy: allowed device and AS issuance',WPROT05:'Authentication silos: target policy and service admission'};
const wprotSupportNotes=wslFreeze({
 WPROT01:'Microsoft Credential Guard documentation distinguishes configured status, running VBS isolation and observed evidence. Only selected domain sign-in secrets are isolated; normal-OS service credentials, explicit inputs, local SAM accounts and independent resource permission remain separate. Native Windows/DC observations are not provided.',
 WPROT02:'Microsoft LSA protection documentation defines protected-process access and Microsoft signing/shared-section checks. Audit and enforcement have different effects, and neither proves Credential Guard is running. Native process or Code Integrity events are not claimed.',
 WPROT03:'Microsoft Protected Users and MS-KILE define eligible human-user AES, NTLM and delegation restrictions. This profile has no explicit authentication policy; its original four-hour credential lineage is distinct from retained local sessions and fresh authentication. Native Windows/DC observations are not provided.',
 WPROT04:'MS-KILE AS policy checks use validated computer armor PAC evidence, not workstation-name text. RFC6113 protects the AS request, reply and policy error; lifetime-only policy uses a separately eligible ordinary AS exchange. Native Windows/DC observations are not provided.',
 WPROT05:'MS-KILE requires silo assignment plus membership and account-type policy selection. The resolved target service account owns AllowedToAuthenticateTo. Its KDC ticket decision remains separate from the service resource ACL; compound TGS armor uses the Windows-specific key binding. Native Windows/DC observations are not provided.'
});
const wprotStandards={WPROT01:'Microsoft Credential Guard / RFC4120',WPROT02:'Microsoft LSA protected-process and Code Integrity requirements',WPROT03:'Microsoft Protected Users / MS-KILE 3.3.5.6',WPROT04:'MS-KILE 3.3.5.6 / RFC6113 5.4',WPROT05:'MS-KILE 3.3.5.4-7 / RFC6113 5.4'};
// Use the workstation lab's five-column physical grid, with a separate cell for
// every expanded owner and clear horizontal/vertical routing corridors.
const wprotPositions=wslFreeze({
 wslUser:{x:110,y:120},wslUI:{x:335,y:120},wslLSA:{x:560,y:120},wslPackage:{x:785,y:120},wslDC:{x:1010,y:120},
 wslSAM:{x:785,y:365},wslIso:{x:335,y:365},wslMachine:{x:560,y:365},wslWorkstation:{x:785,y:365},wprotBackend:{x:1010,y:365},
 wslProcess:{x:335,y:610},wslNetwork:{x:560,y:610},wprotComputer:{x:785,y:610},wslFile:{x:1010,y:610}
});
const wprotCompactPositions=wslFreeze({
 wslUser:{x:170,y:190},wslWorkstation:{x:550,y:190},wslDC:{x:970,y:190},wprotBackend:{x:970,y:425},wslFile:{x:970,y:610}
});
const wprotRoles=wslFreeze({
 wslUser:'Interactive input',
 wslWorkstation:'One OS; distinct local owners',
 wslUI:'Input and result display',
 wslLSA:'Local logon and policy',
 wslPackage:'In-process authentication',
 wslSAM:'Local account / cached verifier',
 wslProcess:'Token, profile and desktop',
 wslIso:'Isolated credential operations',
 wslMachine:'Computer identity / acceptor',
 wslDC:'Domain KDC / account authority',
 wslNetwork:'OS network security context',
 wslFile:'Service and resource authority',
 wprotBackend:'Continuation service / resource',
 wprotComputer:'Computer armor identity'
});
const wprotCardNames=wslFreeze({
 wslWorkstation:'Workstation',wslUI:'Logon UI',wslLSA:'LSA / LSASS',wslPackage:'Auth package',
 wslSAM:'SAM verifier',wslProcess:'User process',wslIso:'LSAIso / VBS',wslMachine:'Kerberos acceptor',
 wslDC:'AD DS KDC',wslNetwork:'Network SSP',wslFile:'Report service',wprotBackend:'Backend service',wprotComputer:'Computer armor'
});
export const WINDOWSPROTECTIONLAB_ATTRIBUTES={};
export const WINDOWSPROTECTIONLAB_SOURCES=wslFreeze([
 {id:'wprot-S10',name:'Configure Credential Guard',url:'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure',section:'Configured, running and observed status'},
 {id:'wprot-S11',name:'Credential Guard considerations',url:'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues',section:'Delegation and saved Windows credentials'},
 {id:'wprot-S12',name:'Additional LSA protection',url:'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection',section:'Process protection, signing, shared sections, audit and enforcement'},
 {id:'wprot-S14',name:'Protected Users',url:'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group',section:'Client and DC restrictions'},
 {id:'wprot-S16',name:'MS-KILE AS exchange',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/a076994a-47a9-4d16-af77-d4abb523afe4',section:'3.3.5.6'},
 {id:'wprot-S17',name:'MS-KILE TGS exchange',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2e5dcf34-4b51-44a0-b45a-277ed616ca39',section:'3.3.5.7'},
 {id:'wprot-S19',name:'MS-KILE policy selection',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/80f6b0ad-18a4-4dad-ae7f-a2b5da0c7e49',section:'3.3.5.5'},
 {id:'wprot-S22',name:'RFC6113 FAST processing',url:'https://www.rfc-editor.org/rfc/rfc6113',section:'5.4: request, response and protected error handling'},
 {id:'wprot-compound',name:'MS-KILE compound TGS explicit armor',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ee7826f5-d985-4a6b-a167-0df0525daea0',section:'3.3.5.7.4'},
 {id:'wprot-S13',name:'Credential Guard architecture and exclusions',url:'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works',section:'Isolation boundary and protection limits'},
 {id:'wprot-S15',name:'Authentication policies and silos',url:'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos',section:'Administrative model and enforcement'},
 {id:'wprot-S18',name:'MS-KILE silo membership',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/089c5fed-a29d-472d-8388-8ed04d8010bf',section:'3.3.5.4'},
 {id:'wprot-S23',name:'RFC4120 AS/TGS/AP and lifetimes',url:'https://www.rfc-editor.org/rfc/rfc4120',section:'2.3; 3.1-3.3; 5.5'},
 {id:'wprot-S25',name:'Remote Credential Guard comparison',url:'https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard',section:'Credential forwarding and independent second-hop identity'},
 {id:'wprot-S26',name:'Protected accounts prerequisites',url:'https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/how-to-configure-protected-accounts',section:'Device restrictions versus lifetime-only policies'},
 {id:'wprot-SFU',name:'MS-SFU constrained delegation',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c920c148-8a9c-42e9-b8e9-db5755cd281b',section:'S4U2proxy request, policy, reply and service continuation'},
 {id:'wprot-NLMP',name:'MS-NLMP NTLMv2 calculations',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3',section:'3.3.2'},
 {id:'wprot-SMB2',name:'MS-SMB2 SMB3.1.1',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962',section:'Session, share, file and protected result processing'},
 {id:'wprot-RFC4121',name:'RFC4121 completed Kerberos context',url:'https://www.rfc-editor.org/rfc/rfc4121',section:'2; 4.2.2'},
 {id:'wprot-PAC',name:'MS-PAC authorization data',url:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962',section:'2.5; 2.12; 2.13'}
]);
function wprotInputs(code,variant,overrides={}){
 const common={joined:true,authority:'CORP',account:'CORP\\alice',accountAuthority:'AD',accountType:'User',targetAccountType:'Computer',domainRid:1101,mechanism:'Kerberos',etype:'AES128',credentialSource:'signed-in',credentialGuard:true,cgConfigured:true,pplConfigured:false,pplRunning:false,domainFunctionality:7,protectedUser:false,explicitAuthenticationPolicy:false,resourceAllows:true,delegation:'none',delegationMode:'KCD',kcdServiceTrusted:true,kcdAllowedSpn:'host/workstation.corp.example',rbcdTargetAllowsService:true,accountSensitive:false,deviceClaims:true,machineTgt:true,armorValid:true,deviceAllowed:true,actualDeviceSid:'S-1-5-21-440-550-660-2101',allowedDeviceSid:'S-1-5-21-440-550-660-2101',deviceLabel:'WORKSTATION',assignedSilo:true,siloMember:true,directEnforced:true,siloEnforced:true,enforced:true,targetAllowed:true,targetPolicy:true,allowedFrom:true,armored:true,lifetimeMinutes:120,nowMinutes:0,existingCredential:false,freshAuthentication:false,membershipChanged:false,offline:false,pluginMode:'enforce',pluginSigningLevel:'Microsoft-LSA',pluginRequiredSigningLevel:'Microsoft-LSA',sharedSections:false,pluginFunction:'optional synthetic smart-card helper',pluginOptional:false,requesterProtectionLevel:'none',requestedProcessRights:['PROCESS_VM_READ'],processDaclAllows:false,processRequest:false};
 const f={...common,...(code==='WPROT02'?{credentialGuard:false,cgConfigured:false,pplConfigured:true,pplRunning:true}:{}),...(code==='WPROT03'?{protectedUser:true,lifetimeMinutes:240}:{}),...(['WPROT04','WPROT05'].includes(code)?{explicitAuthenticationPolicy:true}:{}),...wprotCases[code][variant],...overrides};
 f.retainServiceCredential=true;f.userSid='S-1-5-21-440-550-660-'+f.domainRid;
 f.securityServicesRunning=f.credentialGuard?[1,2]:[2];f.credentialGuard=f.securityServicesRunning.includes(1);
 f.caseId=variant;
 if(code==='WPROT03'&&f.mechanism==='NTLMv2')f.credentialSource='explicit supplied credential; not client SSO cache';
 if(code==='WPROT04'){f.assignedSilo=false;f.siloMember=false;}
 if(code==='WPROT05'){f.serviceAccountName={User:'svcHost',ManagedServiceAccount:'gmsaHost$',Computer:'PROTECTED$'}[f.targetAccountType];f.servicePrincipal='host/protected.corp.example';f.serviceActor='wslFile';}
 f.forwardableServiceEvidence=f.delegation==='constrained'&&!f.protectedUser;
 if(f.delegation==='constrained')f.kcdAllowedSpn='host/backend.corp.example';
 if(f.domainRid===500)f.account='CORP\\Administrator';
 if(f.accountAuthority==='SAM'){f.account='TARGET\\ops';f.userSid='S-1-5-21-110-220-330-1001';f.domainRid=null;f.localRid=1001;}
 return wslFreeze(f);
}
function wprotDecision(a,stage,actor,label,value,puts={}){const o=a.object(stage,label,'result',actor,value,[...new Set([actor,'wslLSA','wslProcess'])]);a.add(stage,label,actor,actor,{creates:[o],puts});return o;}
function wprotReturn(a,result,code,{denied=false}={}){
 if(result.creator!=='wslLSA')a.add('decision-response','Return detector-owned scoped operation result',result.creator,'wslLSA',{objects:[result],wire:result.creator==='wslDC',type:result.creator==='wslDC'?'network-response':'local-result',puts:{serverResultReturned:true}});
 a.add('client-result','Deliver correlated result to application','wslLSA','wslProcess',{objects:[result],type:'local-result',puts:{clientKnowsResult:true,resultCode:code,...(denied?{failureStage:result.key,failureReason:code}:{})}});
}
function wprotStop(a,stage,actor,code,puts={},checks=[]){const r=wprotDecision(a,stage,actor,'Scoped rejection: '+code,{requestId:a.id+':attempt',code}, {detector:actor,...puts});if(checks.length)a.add(stage+'-checks','Record exact failed evidence',actor,actor,{verify:checks,checkResult:'rejected'});wprotReturn(a,r,code,{denied:true});return false;}
function wprotSelectPolicy(a,f,{target=false}={}){
 const prefix=target?'target':'account',type=target?f.targetAccountType:f.accountType,slot={User:'user',ManagedServiceAccount:'service',Computer:'computer'}[type];if(!slot)throw new RangeError('Unsupported protection account type: '+type);
 const account=target?'CORP\\'+f.serviceAccountName:f.account,sid=target?{User:'S-1-5-21-440-550-660-4101',ManagedServiceAccount:'S-1-5-21-440-550-660-4201',Computer:'S-1-5-21-440-550-660-4301'}[type]:f.userSid,siloId='CN=ProtectionReference,CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=corp,DC=example';
 const directory=a.seed(a.object(prefix+'-directory-record','Authoritative '+(target?'SPN service':'requesting')+' account directory record','identity','wslDC',{account,sid,accountType:type,accountAuthority:target?'AD':f.accountAuthority,domainRid:target?Number(sid.split('-').at(-1)):f.domainRid,assignedSilo:f.assignedSilo?siloId:null,directPolicy:prefix+'-direct-policy',servicePrincipals:target?[f.servicePrincipal]:[]},['wslDC']));
 const ruleFor=accountType=>({lifetimeMinutes:f.lifetimeMinutes,allowedFrom:accountType==='Computer'||!f.allowedFrom?null:{right:'ACTRL_DS_CONTROL_ACCESS',allowDeviceSid:f.allowedDeviceSid,denyDeviceSid:f.deviceAllowed?null:f.actualDeviceSid},allowedTo:target&&f.targetPolicy?{right:'ACTRL_DS_CONTROL_ACCESS',requiredUser:f.userSid,requiredDevice:f.allowedDeviceSid,denyUserSid:f.targetAllowed?null:f.userSid}:null});
 const silo=a.seed(a.object(prefix+'-silo-record','Authoritative silo membership, policy slots and enforcement','policy','wslDC',{siloId,memberSids:f.siloMember?[sid]:[],enforced:f.siloEnforced,policySlots:Object.fromEntries(['User','ManagedServiceAccount','Computer'].map(accountType=>[{User:'user',ManagedServiceAccount:'service',Computer:'computer'}[accountType],{policyName:'silo-'+{User:'user',ManagedServiceAccount:'service',Computer:'computer'}[accountType],...ruleFor(accountType)}]))},['wslDC']));
 const direct=a.seed(a.object(prefix+'-direct-policy','Directly assigned account policy and enforcement','policy','wslDC',{policyId:prefix+'-direct-policy',policyName:'direct-'+slot,enforced:target?f.directEnforced:f.enforced,...ruleFor(type)},['wslDC']));
 const belongs=directory.value.assignedSilo===silo.value.siloId&&silo.value.memberSids.includes(directory.value.sid),exempt=!target&&directory.value.accountAuthority==='AD'&&directory.value.domainRid===500,source=exempt||target&&!f.targetPolicy?'none':belongs&&target?'silo':'direct';
 if(target&&!directory.value.servicePrincipals.includes(f.servicePrincipal))throw new RangeError('Target SPN has no authoritative service-account mapping');
 const selected=source==='silo'?silo.value.policySlots[slot]:source==='direct'?direct.value:null,enforced=source==='silo'?silo.value.enforced:source==='direct'?direct.value.enforced:false;
 const value={account:directory.value.account,accountType:directory.value.accountType,policySlot:type,belongsToSilo:belongs,assignedSilo:directory.value.assignedSilo!==null,memberListIncludes:silo.value.memberSids.includes(sid),source,enforced,policyName:selected?.policyName||null,allowedFrom:exempt?null:selected?.allowedFrom||null,allowedTo:selected?.allowedTo||null,accountPolicyExempt:exempt,lifetimeMinutes:exempt?480:(selected?.lifetimeMinutes??f.lifetimeMinutes),accountRecordRef:directory.artifactId,siloRecordRef:silo.artifactId,enforcementRecordRef:source==='silo'?silo.artifactId:source==='direct'?direct.artifactId:null};
 const policy=a.object(prefix+'-policy','KDC authoritative '+(target?'target service':'requesting account')+' effective policy','policy','wslDC',value,['wslDC'],{store:'Resolved AD account/silo policy decision'});
 a.add(target?'policy-selection':'account-policy-selection','Resolve account assignment AND membership, account-type slot and enforcement provenance','wslDC','wslDC',{uses:[directory,silo,direct],creates:[policy],puts:{belongsToSilo:belongs,effectivePolicySource:source,effectiveEnforced:enforced,policySlot:type,targetPolicyName:value.policyName,...(!target?{accountPolicyExempt:exempt}:{})}});return policy;
}
function wprotCompound(a,f){
 const owner='wprotComputer';a.actors[owner]={id:owner,parentId:'wslWorkstation',name:'Computer armor credential context',role:'Machine identity is independent of target service-account type',kind:'authenticator',color:'#7c3aed'};
 const ticket=a.seed(a.object('computer-armor-ticket','Preexisting computer armor TGT','ticket','wslDC',{principal:'WORKSTATION$',issuer:'same-domain writable KDC',pacDeviceSid:f.actualDeviceSid,pacClaims:f.deviceClaims?['managed-device']:[]},['wslDC'],{wire:'krbtgt-encrypted computer TGT'}),[owner]);
 const key=a.seed(a.object('computer-armor-ticket-key','Computer armor TGT session key','session-key','wslDC','HANDLE(preexisting computer TGT key)',[owner,'wslDC']),[owner,'wslDC']);
 const pac=a.object('computer-armor-pac','Validated current armor-ticket PAC evidence','identity','wslDC',{deviceSid:ticket.value.pacDeviceSid,claims:ticket.value.pacClaims,validatedIssuer:'CORP writable KDC',evidenceTicketRef:ticket.artifactId},['wslDC'],{store:'KDC protected computer ticket provenance',retention:'temporary'});
 const sub=a.object('computer-armor-subkey','Fresh computer armor AP subkey','session-key',owner,'HANDLE(fresh computer armor subkey)',[owner,'wslDC']);
 const proof=a.object('computer-armor-proof','Encrypted computer armor AP-REQ','proof',owner,{ticketRef:ticket.artifactId,subkeyRef:sub.artifactId,freshness:'fresh ctime/cusec and replay check'},[owner,'wslDC'],{wire:'AP-REQ(computer TGT; authenticator encrypted in computer TGT key)'});
 const explicitKey=a.object('computer-explicit-armor-key','Computer explicit armor contribution','session-key',owner,{derivation:'CF2(computer armor subkey, computer ticket session key, \"subkeyarmor\", \"ticketarmor\")'},[owner,'wslLSA','wslDC']);
 a.add('computer-armor-operation','Construct computer armor in machine credential context',owner,owner,{uses:[ticket,key],creates:[sub,proof,explicitKey]});
 a.add('computer-armor-return','Return opaque computer armor proof and independent contribution',owner,'wslLSA',{objects:[ticket,proof,explicitKey],type:'local-call'});return {ticket,key,pac,sub,proof,explicitKey};
}
function wprotAS(a,f,{policy=null,fast=false}={}){
 if(f.protectedUser&&!['AES128','AES256'].includes(f.etype)){
  const constraints=a.seed(a.object('pu-account-constraints','KDC Protected Users preauthentication constraints','policy','wslDC',{account:f.account,protectedUser:true,allowedEtypes:['AES128','AES256']},['wslDC']));
  const request=a.object('legacy-as-request','Deliberately incompatible AS preauthentication input','request','wslProcess',{cname:f.account,realm:'CORP.EXAMPLE',sname:'krbtgt/CORP.EXAMPLE',nonce:41001,etype:f.etype,padata:{type:'PA-ENC-TIMESTAMP',encryptedTimestamp:'SYM(submitted '+f.etype+' ciphertext; key usage1)'},origin:'Rejected comparison input; not a permitted protected-client fallback'},['wslProcess','wslLSA','wslDC']);
  a.add('legacy-as-input','Select a submitted legacy comparison, without creating protected-client legacy keys','wslProcess','wslProcess',{creates:[request]});
  a.add('legacy-as-submit','Pass the explicit rejected comparison to the protocol boundary','wslProcess','wslLSA',{objects:[request],type:'local-call'});
  a.add('as-request','Send the deliberately incompatible AS-REQ for the DC restriction comparison','wslLSA','wslDC',{objects:[request],wire:true});
  if(!constraints.value.allowedEtypes.includes(request.value.etype))return wprotStop(a,'pu-check','wslDC','KDC_ERR_ETYPE_NOTSUPP',{tgtAccepted:false},[request]);
  throw new RangeError('Legacy comparison must select a prohibited Protected Users enctype');
 }
 const baselineLifetime=f.protectedUser?240:480,configuredLifetime=policy?.value.lifetimeMinutes??null;
 const lifetime=policy?.value.enforced&&configuredLifetime>0?configuredLifetime:baselineLifetime;
 const issuedMinutes=f.nowMinutes??0,endMinutes=issuedMinutes+lifetime;
 const ticketTimes={ticketIssuedMinutes:issuedMinutes,ticketStartMinutes:issuedMinutes,ticketDurationMinutes:lifetime,ticketEndMinutes:endMinutes,ticketRenewMinutes:endMinutes};
 const armorPac=fast?a.seed(a.object('armor-device-pac','KDC-owned computer armor PAC evidence','identity','wslDC',{deviceSid:f.actualDeviceSid,claims:f.deviceClaims?['managed-device']:[],ticketPrincipal:'WORKSTATION$',issuer:'CORP writable KDC'},['wslDC'])):null;
 const gate=()=>{
  if(policy){const rule=policy.value.allowedFrom,sid=armorPac?.value.deviceSid,wouldDeny=!!rule&&(sid!==rule.allowDeviceSid||sid===rule.denyDeviceSid),allow=!policy.value.enforced||!wouldDeny;
   const d=wprotDecision(a,'as-policy','wslDC','Evaluate authoritative account AS admission and lifetime',{policyRef:policy.artifactId,armorPacRef:armorPac?.artifactId||null,armorDeviceSid:armorPac?.value.deviceSid||null,wouldDeny,enforced:policy.value.enforced,allow,configuredLifetimeMinutes:configuredLifetime,baselineLifetimeMinutes:baselineLifetime,lifetimeMinutes:lifetime,issuedMinutes,durationMinutes:lifetime,endMinutes,renewMinutes:endMinutes},{policyAllowed:allow,policyWouldDeny:wouldDeny,...ticketTimes});
   if(!allow){if(!fast)wprotReturn(a,d,'KDC_ERR_POLICY',{denied:true});return false;}
  }else wprotDecision(a,'pu-check','wslDC','Apply independent eligible human-user Kerberos restrictions',{protectedUser:f.protectedUser,etype:f.etype,lifetimeMinutes:lifetime,issuedMinutes,durationMinutes:lifetime,endMinutes,renewMinutes:endMinutes},ticketTimes);
  return true;
 };
 if(fast){
  if(!f.machineTgt)return wprotStop(a,'armor-ready','wslLSA','required-device-context-unavailable',{machineAccepted:false,tgtAccepted:false});
  const source=wslAcceptedCrypto('lab-ad-fast-as-success');
  if(!f.armorValid){
   const armorDefinition=Object.entries(source.definitions()).find(([field])=>field.endsWith('ArmorTicket'))[1],overrides={[armorDefinition.example]:'Untrusted computer armor ticket; textual WORKSTATION label does not establish issuer or PAC'};
   wslAppendSource(a,source,'ad','fast-request',{credentialGuard:f.credentialGuard,valueOverrides:overrides});
   return wprotStop(a,'device-evidence','wslDC','untrusted-device-evidence',{machineAccepted:false,tgtAccepted:false});
  }
  const overrides={};for(const [field,definition] of Object.entries(source.definitions()))if(field.endsWith('IssuedTicket')||field.endsWith('ReplyEncPart'))overrides[definition.example]=definition.example+'; issued='+issuedMinutes+'min; duration='+lifetime+'min; endtime='+endMinutes+'min; renew-till='+endMinutes+'min';
  const record=wslAppendSource(a,source,'ad','accept-ticket',{credentialGuard:f.credentialGuard,valueOverrides:overrides,effects:{'armor-kdc':{machineAccepted:true}},beforeIssue:gate});
  if(record.policyPermitted===false){
   wslAppendFastPolicyError(a,wslAcceptedCrypto('lab-ad-fast-as-challenge'),record,'KDC_ERR_POLICY');
   const local=wprotDecision(a,'as-policy-client-result','wslLSA','Use only the accepted protected FAST error as caller result',{request:a.id+':ad:fast-request',reason:'KDC_ERR_POLICY'},{clientPolicyErrorAccepted:true});wprotReturn(a,local,'KDC_ERR_POLICY',{denied:true});return false;
  }
  a.add('as-accepted','Install validated FAST user TGT after protected reply checks','wslLSA','wslLSA',{puts:{tgtAccepted:true,credentialVerified:true,...ticketTimes,replyStrengthened:true,newCredentialLineage:!!f.freshAuthentication}});return {};
 }
 const buffer=wslInput(a,'Temporary account-scoped authentication input','credential-input',['wslUI','wslLSA','wslPackage']);
 const credential=wslPasswordAS(a,{...f,ticketLifetimeMinutes:lifetime,ticketIssuedMinutes:issuedMinutes},{buffer,account:f.account,beforeIssue:gate,acceptedPuts:{...ticketTimes,newCredentialLineage:!!f.freshAuthentication}});return credential.policyDenied||credential.denied?false:credential;
}
function wprotResource(a,f){
 const rule=a.seed(a.object('resource-rule','Independent host service resource ACL','policy','wslMachine',{object:'report',requestedRight:'READ_DATA',allowUserSid:f.resourceAllows?f.userSid:null},['wslMachine']));
 const facts=a.artifacts.find(o=>o.key==='validated-logon-information'),key=a.artifacts.find(o=>o.key==='host-session-key');
 if(!facts||!key)throw new TypeError('Resource operation requires accepted service context and normal-OS service key');
 const request=a.object('resource-request','Application request under accepted service credential','request','wslLSA',{requestId:a.id+':attempt',operation:'read report',requestedRight:'READ_DATA',credentialRef:key.artifactId},['wslLSA','wslMachine']);
 a.add('resource-authority-check','The live accepted service credential remains usable under Credential Guard','wslLSA','wslLSA',{uses:[key],creates:[request],puts:{liveAuthorityUsable:true}});
 a.add('resource-submit','Request the independent host service operation','wslLSA','wslMachine',{objects:[request],type:'local-call'});
 const allowed=rule.value.requestedRight===request.value.requestedRight&&rule.value.allowUserSid!==null&&rule.value.allowUserSid===facts.value.userSid;
 const result=a.object('resource-check','Independent resource authorization decision','result','wslMachine',{requestId:request.value.requestId,ruleRef:rule.artifactId,validatedFactsRef:facts.artifactId,allowed},['wslMachine','wslLSA','wslProcess']);
 a.add('resource-check','Authorize requested operation independently of ticket issuance','wslMachine','wslMachine',{uses:[rule,facts],verify:[request],creates:[result],puts:{networkAuthenticated:true,resourceAllowed:allowed,serviceCredentialHolder:'wslLSA'}});
 wprotReturn(a,result,allowed?'success':'resource-denied',{denied:!allowed});
}
function wprotProtection(a,f){
 let prior=null;
 if(f.accountAuthority==='AD'){
  const owner=f.credentialGuard?'wslIso':'wslLSA';
  const record=a.seed(a.object('prior-account-record','Source-owned prior domain sign-in account facts','policy','wslDC',{account:f.account,userSid:f.userSid,acceptedPriorSignin:true,issuer:'CORP writable KDC'},['wslDC']));
  const tgt=a.seed(a.object('prior-signin-tgt','Previously accepted sign-in TGT','ticket','wslDC',{account:f.account,issuer:'CORP.EXAMPLE',lineage:'prior-domain-signin',accountRecord:record.artifactId},['wslDC'],{wire:'Opaque retained krbtgt-encrypted sign-in TGT'}),['wslLSA']);
  const tgtKey=a.seed(a.object('prior-signin-tgt-key',f.credentialGuard?'Previously accepted protected sign-in TGT key':'Previously accepted normal-OS sign-in TGT key','session-key','wslDC','HANDLE(prior sign-in TGT session key)',['wslDC',owner]),['wslDC',owner]);
  const session=a.seed(a.object('live-signin-session','Existing local signed-in application session','session','wslProcess',{account:f.account,userSid:f.userSid,credentialLineage:tgt.artifactId,exactNativeTokenFields:null},['wslProcess']));
  a.state.localAccount=f.account;a.state.localSid=f.userSid;a.state.sessionId=session.artifactId;a.state.localSessionRetained=true;a.state.priorCredentialAccepted=true;a.state.privilegeState='existing session; exact native token fields unobserved';
  prior={tgt,tgtKey};
 }
 if(f.operation==='CredentialManager'){
  const domain=a.seed(a.object('vault-domain','Saved domain Windows credential','credential','wslIso',{type:'Windows-domain',opaque:'HANDLE(protected Windows credential)'},['wslIso']));
  const generic=a.seed(a.object('vault-generic','Application-owned generic credential','credential','wslProcess',{type:'generic',value:'SYM(application credential)'},['wslProcess']));
  const selected=f.credentialManagerType==='generic'?generic:domain;
  const r=wprotDecision(a,'credential-source','wslLSA','Resolve credential type without blanket Vault export',{domainRef:domain.artifactId,genericRef:generic.artifactId,selectedType:selected.value.type},{domainWindowsCredentialProtected:true,genericCredentialProtected:false,selectedCredentialProtected:selected===domain,selectedCredentialExportable:selected===generic});wprotReturn(a,r,'typed-availability');return;
 }
 if(f.operation==='CredSSP'){
  const secret=a.seed(a.object('signed-in-protected-input','Protected signed-in domain credential','credential','wslIso','HANDLE(protected signed-in domain credential; not cleartext)',['wslIso']));
  const handle=a.seed(a.object('signed-in-credential-handle','Normal-OS opaque sign-in credential handle','credential','wslLSA',{source:f.credentialSource,protectedInputRef:secret.artifactId,cleartextAvailable:false},['wslLSA']));
  const request=a.object('credssp-source-request','CredSSP selected reusable credential-source request','request','wslProcess',{source:f.credentialSource,requiresCleartext:true,credentialHandle:handle.artifactId},['wslProcess','wslLSA']);
  a.add('credssp-source-prepare','Request the selected sign-in credential source, not a new password prompt','wslProcess','wslProcess',{creates:[request]});a.add('credssp-source-request','Ask normal-OS LSA for the selected default reusable source','wslProcess','wslLSA',{objects:[request],type:'local-call'});
  const available=!request.value.requiresCleartext||handle.value.cleartextAvailable;
  const result=wprotDecision(a,'credential-source','wslLSA','Evaluate selected credential-source availability without exporting protected input',{requestId:request.artifactId,handleRef:handle.artifactId,available},{credentialAvailable:available,delegatedCredential:false});
  wprotReturn(a,result,available?'success':'source-unavailable',{denied:!available});return;
 }
 if(f.mechanism==='NTLMv2'){
  wprotNtlm(a,f);return;
 }
 const c=f.caseId==='authority-still-usable'?prior:wprotAS(a,f);if(!c)return;
 if(f.caseId==='authority-still-usable')a.add('prior-credential-select','Select already accepted sign-in authority without re-prompting','wslLSA','wslLSA',{uses:[prior.tgt],puts:{credentialVerified:true,tgtAccepted:true}});
 if(!wslHostTicket(a,f,c))return;
 if(f.delegation==='unconstrained'){wprotStop(a,'delegation-check','wslLSA','delegation-unavailable',{delegatedCredential:false});return;}
 if(f.delegation==='constrained'){wprotConstrained(a,f);return;}
 wprotResource(a,f);
}
function wprotRemoteResource(a,f,remote,prefix='host'){
 const {clientActor,serviceActor,acceptor,facts,context}=remote,requestId=a.id+':'+prefix+'-operation-1',source='https://www.rfc-editor.org/rfc/rfc4121';
 const rule=a.seed(a.object(prefix+'-resource-rule','Independent target resource ACL','policy',serviceActor,{resource:'protected report',requestedMask:1,aces:f.resourceAllows?[{type:'allow',sid:f.userSid,mask:1}]:[]},[serviceActor]));
 const operation=a.object(prefix+'-operation','Completed-context protected resource request','request',clientActor,{requestId,resource:rule.value.resource,requestedMask:1,sequence:1,acceptorSubkeyRef:acceptor.artifactId,sentByAcceptor:false},[clientActor,serviceActor],{source,standard:'RFC4121 4.2.2; independent resource ACL',wire:'CFX Wrap{SentByAcceptor=0, Sealed=1, AcceptorSubkey=1, initiator sequence1; protected resource request}'});
 a.add(prefix+'-operation-prepare','Protect the resource request with the completed-context acceptor subkey',clientActor,clientActor,{uses:[acceptor],creates:[operation]});
 const layers=(from,to)=>[{protocol:'Kerberos GSS CFX Wrap',transport:'declared service application channel',from,to,protection:'Confidentiality/integrity, directional sequence and AcceptorSubkey=1'}];
 a.add(prefix+'-operation','Send the protected resource operation',clientActor,serviceActor,{objects:[operation],wire:true,protocolLabel:'Kerberos completed-context application Wrap',layers:layers(clientActor,serviceActor)});
 a.add(prefix+'-operation-decode','Unwrap and verify request context, direction and sequence',serviceActor,serviceActor,{uses:[acceptor],receives:[{object:operation,actor:serviceActor,kind:'decrypt'}],verify:[operation]});
 const allowed=operation.value.acceptorSubkeyRef===acceptor.artifactId&&operation.value.sequence===1&&!operation.value.sentByAcceptor&&context.value.factsRef===facts.artifactId&&context.value.userSid===facts.value.userSid&&rule.value.aces.some(ace=>ace.type==='allow'&&ace.sid===facts.value.userSid&&(ace.mask&operation.value.requestedMask)===operation.value.requestedMask);
 const result=a.object(prefix+'-resource-result','Source-owned resource decision and protected response','result',serviceActor,{requestId,resource:operation.value.resource,allowed,sequence:1,sentByAcceptor:true},[serviceActor,clientActor],{source,standard:'RFC4121 4.2.2',wire:'CFX Wrap{SentByAcceptor=1, Sealed=1, AcceptorSubkey=1, acceptor sequence1; correlated resource result}'});
 a.add('resource-check','Evaluate the requested mask against the server context and independent ACL',serviceActor,serviceActor,{uses:[rule,facts,context],verify:[operation],creates:[result],puts:{resourceAllowed:allowed,serviceCredentialHolder:clientActor}});
 a.add(prefix+'-operation-result','Return protected resource result to the authenticated initiator',serviceActor,clientActor,{objects:[result],wire:true,protocolLabel:'Kerberos completed-context application Wrap',layers:layers(serviceActor,clientActor)});
 a.add(prefix+'-operation-result-decode','Decode the protected response in the established context',clientActor,clientActor,{uses:[acceptor],receives:[{object:result,actor:clientActor,kind:'decrypt'}]});
 const correlated=result.value.requestId===operation.value.requestId&&result.value.resource===operation.value.resource&&result.value.sequence===1&&result.value.sentByAcceptor;
 if(!correlated)throw new RangeError('Protected resource response does not match its pending request');
 a.add(prefix+'-operation-result-check','Accept only the correlated, direction-checked protected result',clientActor,clientActor,{verify:[result]});
 const local=a.object(prefix+'-local-result','Verified operation result returned to its local caller','result',clientActor,{requestId,operationStatus:allowed?'success':'resource-denied',allowed},[clientActor,'wslLSA','wslProcess']);
 a.add(prefix+'-local-result','Create caller result only after actual protected response validation',clientActor,clientActor,{uses:[result],creates:[local],type:'local-result'});
 wprotReturn(a,local,allowed?(a.auditOutcome?'audit':'success'):'resource-denied',{denied:!allowed});
}
function wprotConstrained(a,f){
 // MS-SFU S4U2proxy with an already accepted forwardable user service ticket.
 // This is service-account authority, never an export of the user's protected TGT.
 const sfuCreate=a.object,sfuSource='https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c920c148-8a9c-42e9-b8e9-db5755cd281b';
 a.object=(key,label,type,creator,value,readers,options={})=>sfuCreate(key,label,type,creator,value,readers,{source:sfuSource,standard:'MS-SFU S4U2proxy; RFC4120 3.3/5.5; RFC4121 2/4.2.2',...options});
 a.actors.wprotBackend={id:'wprotBackend',name:'BACKEND service acceptor',role:'Distinct constrained continuation service and resource authority',kind:'service',color:'#b45309'};
 const evidence=a.artifacts.find(o=>o.key==='host-ticket'),target='host/backend.corp.example',requestId=a.id+':s4u-1';
 const policy=a.seed(a.object('s4u-policy','Authoritative scoped delegation policy','policy','wslDC',{mode:f.delegationMode,delegationNotAllowed:f.accountSensitive||f.protectedUser,protectedUsers:f.protectedUser,allowedTargets:f.kcdServiceTrusted?[f.kcdAllowedSpn]:[],targetAllowedServiceSid:f.rbcdTargetAllowsService?'S-1-5-21-440-550-660-2101':null,requesterServiceSid:'S-1-5-21-440-550-660-2101'},['wslDC']));
 const serviceTgt=a.seed(a.object('s4u-service-tgt','Service 1 own preexisting TGT','ticket','wslDC',{client:'WORKSTATION$',target:'krbtgt/CORP.EXAMPLE'},['wslDC'],{wire:'krbtgt ciphertext for WORKSTATION$ own TGT'}),['wslMachine']);
 const serviceTgtKey=a.seed(a.object('s4u-service-tgt-key','Service 1 own TGT session key','session-key','wslDC','HANDLE(service-account TGT key; not user TGT key)',['wslDC','wslMachine']),['wslDC','wslMachine']);
 const backendKey=a.seed(a.object('s4u-backend-key','Backend long-term service key','credential','wslDC',{key:'HANDLE(backend service identity key)',account:'BACKEND$',servicePrincipal:target},['wslDC','wprotBackend']),['wslDC','wprotBackend']);
 const subkey=a.object('s4u-reply-subkey','Fresh S4U TGS authenticator subkey','session-key','wslMachine',{requestId,nonce:62001,target},['wslMachine','wslDC']);
 const proof=a.object('s4u-authenticator','Service-account TGS authenticator','proof','wslMachine',{requestId,subkeyRef:subkey.artifactId,bodyChecksumUsage:6,authenticatorUsage:7},['wslMachine','wslDC'],{wire:'Authenticator(service-account TGT key; request-body checksum6; fresh subkey)'});
 const request=a.object('s4u-request','S4U2proxy TGS request','request','wslMachine',{requestId,nonce:62001,sname:target,cnameInAdditionalTicket:true,additionalTicketRef:evidence.artifactId,serviceTgtRef:serviceTgt.artifactId,rbcd:f.delegationMode==='RBCD'},['wslMachine','wslDC']);
 a.add('s4u-prepare','Construct S4U2proxy from service account and accepted user evidence','wslMachine','wslMachine',{uses:[serviceTgtKey,evidence],creates:[subkey,proof,request]});
 a.add('s4u-request','Send TGS request with CNAME-IN-ADDL-TKT and exact evidence ticket','wslMachine','wslDC',{objects:[serviceTgt,proof,request,evidence],wire:true});
 const krbtgt=a.artifacts.find(object=>object.key==='kdc-krbtgt-key');
 a.add('s4u-ticket-decode','Decode the exact service-account TGT under existing KDC krbtgt authority','wslDC','wslDC',{uses:[krbtgt],receives:[{object:serviceTgt,actor:'wslDC',kind:'decrypt',retention:'temporary'}]});
 a.add('s4u-authenticator-decode','Decode the exact received service authenticator using its TGT session key','wslDC','wslDC',{uses:[serviceTgtKey],receives:[{object:proof,actor:'wslDC',kind:'decrypt'},{object:subkey,actor:'wslDC',kind:'decrypt'}]});
 a.add('s4u-proof-check','Validate service TGT, fresh authenticator, body checksum and evidence ticket','wslDC','wslDC',{uses:[serviceTgtKey],verify:[serviceTgt,proof,request,evidence]});
 const p=policy.value,allowed=!!evidence.value.flags?.includes('forwardable')&&!p.delegationNotAllowed&&(p.mode==='RBCD'?p.targetAllowedServiceSid===p.requesterServiceSid:p.allowedTargets.includes(request.value.sname));
 const decision=wprotDecision(a,'delegation-check','wslDC','Evaluate '+f.delegationMode+' account-owned delegation conditions',{policyRef:policy.artifactId,evidenceTicket:evidence.artifactId,forwardable:evidence.value.flags?.includes('forwardable'),allowed},{delegationAllowed:!!allowed,delegatedCredential:false});
 if(!allowed){wprotReturn(a,decision,'delegation-denied',{denied:true});return;}
 const key=a.object('s4u-session-key','Independent delegated service session key','session-key','wslDC','HANDLE(independent backend session key)',['wslDC','wslMachine','wprotBackend'],{retention:'retained'});
 const ticket=a.object('constrained-service-ticket','KDC scoped constrained continuation ticket','ticket','wslDC',{client:f.account,server:target,userSid:f.userSid,serviceAccount:'BACKEND$',authorization:'PAC copied from validated additional user service ticket',delegation:{transitedService:'host/workstation.corp.example',mode:f.delegationMode}},['wslDC','wprotBackend'],{wire:'Ticket(backend-key ciphertext; user cname; S4U_DELEGATION_INFO)',retention:'retained'});
 const reply=a.object('s4u-client-reply','Request-bound S4U TGS client reply','reply','wslDC',{requestId,nonce:62001,server:target,keyRef:key.artifactId,replyKeyRef:subkey.artifactId,keyUsage:9},['wslDC','wslMachine'],{wire:'EncTGSRepPart(fresh service authenticator subkey, usage9)'});
 a.add('delegation-issue','Issue backend-scoped credential only after constrained policy admission','wslDC','wslDC',{uses:[decision,backendKey,subkey],creates:[ticket,key,reply]});
 a.add('delegation-response','Return constrained TGS credential to Service 1','wslDC','wslMachine',{objects:[ticket,reply],wire:true});
 a.add('s4u-client-decode','Decrypt exact pending S4U reply with selected service subkey','wslMachine','wslMachine',{uses:[subkey],receives:[{object:reply,actor:'wslMachine',kind:'decrypt'}]});
 a.add('s4u-client-accept','Check nonce, target, lifetime and request correlation before installing credential','wslMachine','wslMachine',{verify:[reply],receives:[{object:key,actor:'wslMachine',retention:'retained'},{object:ticket,actor:'wslMachine',store:'accepted delegated service credential',representation:'wire',retention:'retained'}]});
 const remote=wslRemoteService(a,{ticket,key,serviceKey:backendKey,account:f.account,userSid:f.userSid,target,clientActor:'wslMachine',serviceActor:'wprotBackend',prefix:'s4u'});
 if(remote)wprotRemoteResource(a,f,remote,'s4u');
}
function wprotNtlm(a,f){
 if(f.protectedUser){
  const source=SMBLAB_SCENARIOS.find(model=>model.id==='lab-smb-nonjoined-ntlm');
  wslAppendSource(a,source,'smb','dc-request',{credentialGuard:false});
  a.state.smb.clientJoined=f.joined;
  wprotTemporarySourceInput(a);
  const validation=a.artifacts.find(o=>o.artifactId===a.id+':smb:validation');
  const rejected=wprotDecision(a,'ntlm-policy','wslDC','DC rejects Protected Users NTLM independent of valid supplied proof',{validationRef:validation.artifactId,protectedUser:true},{credentialVerified:false,tgtAccepted:false,detector:'wslDC'});
  const authorityReply=a.object('pu-ntlm-authority-reply','Protected DC policy rejection returned to accepting server','result','wslDC',{validationRef:validation.artifactId,authenticated:false,reason:'Protected Users NTLM restriction',nativeNtstatus:null},['wslDC','wslFile'],{wire:'Netlogon secure-channel protected validation failure; no session key'});
  a.add('pu-ntlm-authority-encode','Prepare authority rejection without successful key information','wslDC','wslDC',{uses:[rejected,validation],creates:[authorityReply]});
  a.add('pu-ntlm-authority-response','Return failure on server-owned Netlogon channel','wslDC','wslFile',{objects:[authorityReply],wire:true,protocolLabel:'Netlogon protected validation result',layers:[{protocol:'Netlogon',transport:'member-server machine secure channel',from:'wslDC',to:'wslFile'}]});
  a.add('pu-ntlm-server-process','Accept authority rejection before mapping final SESSION_SETUP failure','wslFile','wslFile',{receives:[{object:authorityReply,actor:'wslFile',kind:'decrypt'}],verify:[authorityReply]});
  const response=a.object('pu-ntlm-service-response','Correlated denied SMB SESSION_SETUP response','result','wslFile',{request:'pending NTLM AUTHENTICATE SESSION_SETUP',authenticated:false,reason:'authority policy restriction; no successful session',nativeNtstatus:null},['wslFile','wslNetwork'],{wire:'SMB2 SESSION_SETUP failure for pending MessageId/SessionId; no success signing-key claim'});
  a.add('pu-ntlm-service-encode','Prepare server-owned authentication failure response','wslFile','wslFile',{uses:[authorityReply],creates:[response]});
  a.add('pu-ntlm-service-return','Deliver denied session result to actual protocol client','wslFile','wslNetwork',{objects:[response],wire:true,protocolLabel:'SMB3.1.1 SESSION_SETUP response',layers:[{protocol:'SMB3.1.1',transport:'TCP445',from:'wslFile',to:'wslNetwork'}]});
  a.add('pu-ntlm-client-process','Correlate denied session response before caller result','wslNetwork','wslNetwork',{receives:[{object:response,actor:'wslNetwork',kind:'decode'}],verify:[response]});
  a.add('pu-ntlm-caller-result','Return policy rejection to requesting application','wslNetwork','wslProcess',{objects:[response],puts:{resultCode:'authentication-denied',clientKnowsResult:true},type:'local-result'});return;
 }
 if(f.accountAuthority==='SAM'){
  a.actors.wslSAM={id:'wslSAM',parentId:'wslFile',name:'TARGET local SAM verifier',role:'Selected target-local account authority, never the domain KDC',kind:'authenticator',color:'#7c3aed'};
  const source=buildWindowsRemoteSmbReference({authority:'TARGET',admin:false,resource:'reports',shareRule:'allow-user',fileRule:'allow-user',mechanism:'NTLMv2',joined:f.joined});
  wslAppendSource(a,source,'smb',undefined,{credentialGuard:false,actorAliases:{smbSAM:'wslSAM'}});
  const r=wprotDecision(a,'local-verify','wslSAM','Preserve accepted target-local SAM proof and source-owned result',{sourceId:source.id,account:'TARGET\\ops',domainCredentialIsolationApplies:false},{credentialVerified:true,isolationActive:false,resourceAllowed:true});wprotReturn(a,r,'success');return;
 }
 if(f.credentialSource==='prompted'){
  const input=a.object('explicit-prompt','Separately prompted NTLM credential','credential','wslUI',{source:'explicit prompted input, not sign-in secret export',value:'SYM(explicit credential)'},['wslUI','wslLSA']);a.add('prompt-input','Collect independent prompted input','wslUI','wslUI',{creates:[input]});a.add('prompt-submit','Submit independent supplied credential to normal-OS package','wslUI','wslLSA',{objects:[input],type:'local-call',puts:{promptedInputProtected:false}});
  a.add('prompt-package-input','Use only the separately supplied input for this NTLM package context','wslLSA','wslNetwork',{objects:[input],type:'local-call'});
 }
 // The accepted NTLMv2 SMB composition supplies proof, DC validation, MIC,
 // signing/encryption, correlated replies and cleanup; no protocol captions replace it.
 const context=a.seed(a.object('network-credential-context','Opaque selected NTLM credential context','credential','wslLSA',{source:f.credentialSource,protectedSource:f.credentialSource!=='prompted',account:f.account},['wslLSA','wslProcess','wslNetwork']),['wslLSA','wslProcess']);
 wslSourceNetwork(a,{badPassword:false,shareDenied:false,mechanism:'NTLMv2',credentialContextRef:context.artifactId,contextReference:context,desktopIdentity:f.account,clientJoined:f.joined});
 if(f.credentialSource!=='prompted')wprotIsolateAcceptedNtlm(a);
 if(f.credentialSource==='prompted')wprotTemporarySourceInput(a);
 const result=a.artifacts.find(object=>object.key==='network-result');if(!result)throw new RangeError('Accepted NTLM journey omitted its checked application result');
 a.add('client-result','Record completion of the actual accepted SMB response, without additional DC traffic','wslNetwork','wslNetwork',{uses:[result],puts:{credentialVerified:true,clientKnowsResult:true,resultCode:'success'},type:'local-result'});
}
function wprotTemporarySourceInput(a){
 const prefix=a.id+':smb:',credential=a.artifacts.find(o=>o.artifactId===prefix+'credential');if(!credential)throw new TypeError('Missing accepted explicit NTLM input');
 const keys=['credential','nt-hash','response-key','client-base-key',...(!a.steps.some(step=>step.workstationStage==='network-handoff')?['session-key']:[])],temporaryIds=new Set(keys.map(key=>prefix+key));
 for(const artifact of a.artifacts)if(temporaryIds.has(artifact.artifactId))artifact.retention='temporary';
 const prompted=a.artifacts.find(o=>o.key==='explicit-prompt');
 if(prompted){
  credential.value='HANDLE(normal-OS NTLM package credential derived from '+prompted.artifactId+')';
  for(const rep of credential.representations)for(const field of rep.fields)field.value=credential.value;
  for(const step of a.steps){for(const op of step.attributeOperations||[])if(op.instanceId===credential.artifactId)op.value=credential.value;for(const field of step.payload||[])if(field.attributeId===credential.attributeId)field.value=credential.value;}
 }
 for(const effect of [...a.initial,...Object.values(a.events).flatMap(event=>event.milestones.flatMap(m=>m.effects))])if(effect.op==='acquire'&&temporaryIds.has(effect.artifactId))effect.retention='temporary';
}
function wprotIsolateAcceptedNtlm(a){
 const prefix=a.id+':smb:',find=key=>a.artifacts.find(object=>object.artifactId===prefix+key),secretIds=new Set(['credential','nt-hash','response-key'].map(key=>prefix+key));
 const moved=['nt-hash','response-key','ntlm-proof','client-base-key'].map(find),outputs=['ntlm-proof','client-base-key'].map(find),normalOutputs=['session-key','ntlm-authenticate'].map(find),credential=find('credential'),challenge=find('ntlm-challenge'),negotiate=find('ntlm-negotiate'),derive=a.steps.find(step=>step.workstationStage==='smb:ntlm-derive');
 if(!derive||moved.some(object=>!object)||normalOutputs.some(object=>!object))throw new TypeError('Accepted NTLMv2 operation schema changed');
 const operationIds=new Set([...secretIds,...outputs.map(object=>object.artifactId)]),temporaryIds=new Set([...moved.map(object=>object.artifactId),find('ntlm-authenticate').artifactId]);
 for(const artifact of a.artifacts){
  if(temporaryIds.has(artifact.artifactId))artifact.retention='temporary';
  if(!operationIds.has(artifact.artifactId))continue;
  artifact.creator='wslIso';
  if(secretIds.has(artifact.artifactId)){
   artifact.label=artifact.key==='credential'?'Protected signed-in NTLM source':'Isolated '+artifact.key+' operation handle';artifact.readers=['wslIso'];artifact.value=artifact.key==='credential'?'HANDLE(protected signed-in domain NTOWF source)':'HANDLE(isolated '+artifact.key+')';
   for(const rep of artifact.representations){rep.readableBy=['wslIso'];for(const field of rep.fields){field.readableBy=['wslIso'];field.value=artifact.value;}}
   a.definitions[artifact.attributeId]={...a.definitions[artifact.attributeId],name:artifact.label,example:artifact.value,origin:'Isolated sign-in credential authority'};
  }else{artifact.readers=[...new Set([...artifact.readers,'wslIso'])];for(const rep of artifact.representations){rep.readableBy=[...new Set([...rep.readableBy,'wslIso'])];for(const field of rep.fields)field.readableBy=[...new Set([...field.readableBy,'wslIso'])];}}
 }
 const remap=effect=>{
  if(temporaryIds.has(effect.artifactId)&&effect.op==='acquire')effect.retention='temporary';
  if(secretIds.has(effect.artifactId)&&effect.actorId==='wslNetwork'){effect.actorId='wslIso';if(effect.holdingId)effect.holdingId=effect.holdingId.replace(/^wslNetwork\|/,'wslIso|');}
  if(effect.op==='release'&&[...secretIds].some(id=>effect.holdingId.includes('|'+id+'|')))effect.holdingId=effect.holdingId.replace(/^wslNetwork\|/,'wslIso|');
 };
 a.initial.forEach(remap);for(const event of Object.values(a.events))for(const milestone of event.milestones)milestone.effects.forEach(remap);
 for(const step of a.steps)for(const op of step.attributeOperations||[]){
  if(operationIds.has(op.instanceId))op.creator='wslIso';
  if(secretIds.has(op.instanceId)){op.actorId=op.actorId==='wslNetwork'?'wslIso':op.actorId;op.holders=op.holders.map(owner=>owner==='wslNetwork'?'wslIso':owner);op.inspectors=['wslIso'];op.value=a.artifacts.find(object=>object.artifactId===op.instanceId).value;}
 }
 const index=a.steps.indexOf(derive);a.steps.splice(index,1);delete a.events[derive.id];
 const request=a.object('ntlm-operation','Request for the exact accepted NTLMv2 challenge','request','wslNetwork',{requestId:a.id+':ntlm-operation',challengeRef:challenge.artifactId,negotiateRef:negotiate.artifactId},['wslNetwork','wslIso']);
 const start=a.steps.length;
 challenge.readers=[...new Set([...challenge.readers,'wslIso'])];
 for(const view of challenge.representations.filter(view=>view.representationId==='plain')){view.readableBy=[...new Set([...view.readableBy,'wslIso'])];for(const field of view.fields)field.readableBy=[...new Set([...field.readableBy,'wslIso'])];}
 const challengeInput={...challenge,retention:'temporary'};
 a.add('ntlm-operation-request','Pass the exact server challenge as transient isolated-operation input','wslNetwork','wslIso',{creates:[request],objects:[request,challengeInput],type:'local-call',summary:'Only the fresh challenge/target information enters the isolated response primitive. NEGOTIATE and the MIC transcript stay with the normal-OS SSP; this borrowed challenge holding lasts only for the operation.'});
 a.add('ntlm-operation-compute','Compute accepted NTLMv2 proof and candidate base key without exporting NTOWF','wslIso','wslIso',{uses:[request,credential,challenge],creates:moved,summary:'The accepted MS-NLMP response and candidate SessionBaseKey expressions use the protected credential. Normal-OS SSPs still select the exported session key, serialize AUTHENTICATE and compute its MIC.'});
 a.add('ntlm-operation-return','Return proof and independent candidate base key, never the protected input','wslIso','wslNetwork',{objects:outputs,type:'local-result'});
 normalOutputs[0].retention='retained';
 const normal=a.add('smb:ntlm-derive','Construct NTLM AUTHENTICATE and transcript MIC in the normal OS','wslNetwork','wslNetwork',{uses:[...outputs,negotiate],verify:[challenge],creates:normalOutputs,summary:'Reuse the accepted NTLMv2 KEY_EXCH and MIC expressions. The normal-OS SSP chooses ExportedSessionKey and constructs the protocol token from isolated proof/base-key outputs; it never reads the protected NTOWF.'});
 normal.protocolEffects=derive.protocolEffects;normal.smbStage=derive.smbStage;
 const replacement=a.steps.splice(start);a.steps.splice(index,0,...replacement);
 const record=a.reuse.find(item=>item.kind==='smb');record.isolatedOperationStages=['ntlm-operation-request','ntlm-operation-compute','ntlm-operation-return'].map(stage=>a.id+':'+stage);record.normalEncodingStage=normal.id;
}
function wprotPpl(a,f){
 if(f.credentialGuard)a.seed(a.object('ppl-independent-protected-input','Independent CG protected credential reference','credential','wslIso','HANDLE(protected domain TGT key; PPL grants no access to this store)',['wslIso']));
 if(f.processRequest){const prohibited=f.requestedProcessRights.some(right=>['PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_CREATE_THREAD','PROCESS_DUP_HANDLE'].includes(right)),pplBlocks=f.pplRunning&&f.requesterProtectionLevel==='none'&&prohibited;
  const request=a.seed(a.object('process-access-request','Synthetic process-access request metadata','request','wslProcess',{requesterProtectionLevel:f.requesterProtectionLevel,target:'LSASS',requestedRights:f.requestedProcessRights,otherDaclAllows:f.processDaclAllows},['wslProcess','wslLSA']));a.add('process-submit','Submit synthetic access-mask request, not exploit code','wslProcess','wslLSA',{objects:[request],type:'local-call'});
  const r=wprotDecision(a,'process-check','wslLSA','Evaluate effective protected-process boundary and separate DACL',{pplBlocks,daclAllows:f.processDaclAllows},{processAccessAllowed:!pplBlocks&&f.processDaclAllows,pplBoundaryApplied:f.pplRunning});wprotReturn(a,r,pplBlocks?'access-denied':'other-controls-apply');return;
 }
 const incompatible=f.pluginSigningLevel!==f.pluginRequiredSigningLevel||f.sharedSections,blocked=f.pplRunning&&f.pluginMode==='enforce'&&incompatible;
 const plugin=a.seed(a.object('plugin-metadata','Synthetic LSA plugin requirements','policy','wslLSA',{actualSigningLevel:f.pluginSigningLevel,requiredSigningLevel:f.pluginRequiredSigningLevel,sharedSections:f.sharedSections,function:f.pluginFunction,optional:f.pluginOptional},['wslLSA']));
 const r=wprotDecision(a,'plugin-check','wslLSA','Evaluate Microsoft signing-level and shared-section requirements',{pluginRef:plugin.artifactId,incompatible,mode:f.pluginMode,syntheticDiagnosticIds:incompatible?(f.pluginMode==='audit'?[3065,3066]:[3033,3063]):[],nativeEventsObserved:false},{pluginLoaded:!blocked,pluginWouldDeny:incompatible,pplBoundaryApplied:f.pplRunning});
 if(blocked&&!f.pluginOptional){wprotReturn(a,r,'plugin-blocked',{denied:true});return;}
 const c=wprotAS(a,f);if(!c)return;wprotReturn(a,r,f.pluginMode==='audit'&&incompatible?'audit':'success');
}
function wprotRenewal(a,f,old){
 const requestId=a.id+':renewal-63001',owner=f.credentialGuard?'wslIso':'wslLSA';
 const oldKey=a.seed(a.object('old-ticket-key','Original credential-lineage TGT session key','session-key','wslDC','HANDLE(original PU TGT key; separate from fresh-AS key)',['wslDC',owner]),['wslDC',owner]);
 const request=a.object('renewal-request','Renew original four-hour credential lineage','request','wslLSA',{requestId,ticketRef:old.artifactId,nowMinutes:f.nowMinutes,renewTill:old.value.renewTillMinutes,nonce:63001,kdcOptions:['RENEW'],sname:'krbtgt/CORP.EXAMPLE'},['wslLSA',owner,'wslDC']);
 a.add('renewal-prepare','Create RENEW request bound to the original credential lineage','wslLSA','wslLSA',{creates:[request]});
 a.add('renewal-operation-request','Request fresh renewal authenticator without exporting original TGT key','wslLSA',owner,{objects:[request],type:'local-call'});
 const subkey=a.object('renewal-subkey','Fresh renewal TGS authenticator subkey','session-key',owner,{requestId,nonce:63001,target:'krbtgt/CORP.EXAMPLE'},[owner,'wslLSA','wslDC']);
 const proof=a.object('renewal-proof','Original-lineage request-bound renewal authenticator','proof',owner,{requestId,subkeyRef:subkey.artifactId,bodyChecksumUsage:6,authenticatorUsage:7},[owner,'wslLSA','wslDC'],{wire:'Encrypted TGS authenticator(original lineage TGT key; fresh time; RENEW body checksum6)'});
 a.add('renewal-operation','Create independent authenticator for this renewal attempt',owner,owner,{uses:[oldKey,request],creates:[subkey,proof]});
 a.add('renewal-operation-return','Return renewal proof and independent reply subkey only',owner,'wslLSA',{objects:[proof,subkey],type:'local-result'});
 a.add('renewal-request','Send RENEW TGS request, old ticket and exact fresh authenticator','wslLSA','wslDC',{objects:[request,old,proof],wire:true});
 const krbtgt=a.seed(a.object('renewal-krbtgt-key','KDC original-TGT decryption authority key','credential','wslDC','HANDLE(CORP krbtgt account key)',['wslDC']));
 a.add('renewal-ticket-decode','Interpret original ticket only under KDC krbtgt authority','wslDC','wslDC',{uses:[krbtgt],receives:[{object:old,actor:'wslDC',kind:'decrypt'}]});
 a.add('renewal-proof-check','Check original ticket, fresh authenticator and exact renewal request','wslDC','wslDC',{uses:[oldKey],verify:[old,proof,request],receives:[{object:subkey,actor:'wslDC',kind:'decrypt'}]});
 if(request.value.nowMinutes<=old.value.renewTillMinutes)throw new RangeError('Expired-lineage fixture requires the original renewal boundary');
 wprotStop(a,'renewal-check','wslDC','renewal-denied',{newCredentialLineage:false,tgtAccepted:false},[old,request]);
}
function wprotPu(a,f){
 if(f.offline){const cache=a.seed(a.object('cache-policy','Protected Users cached-verifier evidence','policy','wslSAM',{cachedVerifierCreated:false,cacheEntries:[],source:'Protected Users effective at selected sign-in'},['wslSAM']));wprotStop(a,'cache-check','wslSAM','cached-verifier-unavailable',{cachedVerifierPresent:false,tgtAccepted:false},[cache]);return;}
 if(f.mechanism==='NTLMv2'){wprotNtlm(a,f);return;}
 if(f.existingCredential){
  const old=a.seed(a.object('old-ticket-lineage','Intentionally pre-existing credential lineage','ticket','wslDC',{lineage:'PU-original-0',issuedMinutes:0,endMinutes:240,renewTillMinutes:240,expired:f.nowMinutes>240},['wslLSA','wslDC'],{wire:'Opaque krbtgt-encrypted original PU TGT; original end/renew-till 240min'}),['wslLSA']);
  const session=a.seed(a.object('existing-local-session','Retained local session independent of TGT expiry','session','wslProcess',{id:'prior-session',credentialLineage:old.artifactId},['wslProcess']));a.add('session-observe','Retain existing local session; expiry is not automatic logoff','wslProcess','wslProcess',{uses:[session],puts:{localSessionRetained:true,oldSessionPurged:false}});
  if(f.membershipChanged){wprotDecision(a,'membership-check','wslLSA','Apply client protections at new sign-in, not retroactive global purge',{oldSessionMembership:false,directoryMembership:true,phase:f.membershipPhase||'new-signin'},{newSigninProtected:true,clientProtectionEffective:f.membershipPhase!=='old-session',oldSessionPurged:false});}
  if(f.membershipPhase==='old-session'){const oldResult=wprotDecision(a,'old-session-result','wslLSA','Retain pre-membership client session without inventing new sign-in',{sessionRef:session.artifactId,credentialRef:old.artifactId},{clientProtectionEffective:false,newSigninProtected:false});wprotReturn(a,oldResult,'success');return;}
  if(f.nowMinutes>240&&!f.freshAuthentication){wprotRenewal(a,f,old);return;}
 }
 const c=wprotAS(a,f);if(!c)return;
 if(f.delegation==='constrained'){if(wslHostTicket(a,f,c))wprotConstrained(a,f);return;}
 if(f.delegation==='unconstrained'){wprotStop(a,'delegation-check','wslDC','delegation-denied',{delegatedCredential:false,delegationAllowed:false});return;}
 const r=wprotDecision(a,'pu-result','wslLSA','Retain only accepted human-user credential lineage',{newAuthentication:f.freshAuthentication,clientCachesLongTermKey:false,cachedVerifierCreated:false},{cachedVerifierPresent:false,newCredentialLineage:f.freshAuthentication});wprotReturn(a,r,'success');
}
function wprotPolicyAS(a,f){
 if(f.domainFunctionality<6){wprotStop(a,'capability-check','wslLSA','unsupported-policy-profile',{policySupported:false,tgtAccepted:false});return;}
 const policy=wprotSelectPolicy(a,f),c=wprotAS(a,f,{policy,fast:f.allowedFrom&&f.armored});if(!c)return;
 const applied=a.steps.flatMap(step=>step.protocolEffects||[]).find(effect=>effect.path==='workstation.ticketDurationMinutes')?.value;
 const r=wprotDecision(a,'policy-as-result','wslLSA','Client accepts new credential only after reply checks',{credentialAccepted:true,configuredLifetimeMinutes:policy.value.lifetimeMinutes,lifetimeMinutes:applied},{policySupported:true});wprotReturn(a,r,a.steps.some(s=>s.protocolEffects?.some(e=>e.path==='workstation.policyWouldDeny'&&e.value))?'audit':'success');
}
function wprotPolicyTGS(a,f){
 if(f.domainRid===500){const own=wprotSelectPolicy(a,f);if(!wprotAS(a,f,{policy:own}))return;}
 const target=wprotSelectPolicy(a,f,{target:true});
 a.actors.wslFile={id:'wslFile',name:'PROTECTED report service ('+f.serviceAccountName+')',role:'Distinct target '+f.targetAccountType+' service account and local resource authority',kind:'service',color:'#b45309'};
 // No AS exchange is invented here: these are intentionally pre-existing,
 // independently accepted user credentials, then a fresh service-ticket attempt.
 const owner=f.credentialGuard?'wslIso':'wslLSA';
 const tgt=a.seed(a.object('preexisting-user-tgt','Preexisting accepted user TGT','ticket','wslDC',{principal:f.account,issuer:'same-domain writable KDC',pacUserSid:f.userSid},['wslDC'],{wire:'krbtgt-encrypted accepted user TGT'}),['wslLSA']);
 const tgtKey=a.seed(a.object('preexisting-user-tgt-key','Preexisting user TGT session key','session-key','wslDC','HANDLE(accepted user TGT key)',['wslDC',owner]),['wslDC',owner]);
 const userPac=a.seed(a.object('user-pac','KDC-authoritative user PAC evidence','identity','wslDC',{userSid:f.userSid,claims:['eligible-user'],issuer:'same-domain writable KDC'},['wslDC']));
 const compound=target.value.allowedTo?wprotCompound(a,f):null;
 let denialCode=null;
 if(compound){compound.errorCode=compound.pac.value.claims.includes('managed-device')?'KDC_ERR_POLICY':'<profile-gated error code>';compound.failureReason=compound.pac.value.claims.includes('managed-device')?'target-service allowed-to rule denied':'required validated claim context unavailable';}
 const accepted=wslHostTicket(a,f,{tgt,tgtKey,account:f.account,compoundArmor:compound,beforeIssue:()=>{
  if(target.value.allowedTo&&!compound.pac.value.claims.includes('managed-device')){denialCode='required-policy-context-unavailable';wprotDecision(a,'tgs-context','wslDC','Required validated policy claim context unavailable',{armorPacRef:compound.pac.artifactId,requiredClaim:'managed-device'},{policyAllowed:false,detector:'wslDC'});return false;}
  const rule=target.value.allowedTo,wouldDeny=!!rule&&(userPac.value.userSid!==rule.requiredUser||userPac.value.userSid===rule.denyUserSid||compound.pac.value.deviceSid!==rule.requiredDevice),allow=!target.value.enforced||!wouldDeny;
  const r=wprotDecision(a,'tgs-policy','wslDC','Evaluate TARGET SERVICE AllowedToAuthenticateTo using validated user and armor PACs',{targetAccount:target.value.account,policyRef:target.artifactId,userPacRef:userPac.artifactId,armorPacRef:compound?.pac.artifactId||null,wouldDeny,enforced:target.value.enforced,allow},{policyAllowed:allow,policyWouldDeny:wouldDeny});
  if(wouldDeny&&!target.value.enforced)a.auditOutcome=true;
  if(!allow){denialCode='KDC_ERR_POLICY';return false;}return true;
 }});if(!accepted){if(denialCode){const local=wprotDecision(a,'tgs-policy-client-result','wslLSA','Return only the accepted protected TGS error',{request:a.id+':host-request-52001',reason:denialCode});wprotReturn(a,local,denialCode,{denied:true});}return;}
 wprotRemoteResource(a,f,a.serviceContext);
}
function wprotBindSeedOccurrences(a){
 // Accepted crypto operations identify static VALUE origin as initial. In this
 // composition the occurrence belongs to its actual step; the seed provenance
 // and exact value reference remain initial, with no new creation or holding.
 for(const step of a.steps)for(const operation of step.attributeOperations||[])if(operation.sourceEventId==='initial'){operation.seedSourceEventId='initial';operation.sourceEventId=step.id;}
}
function wprotReleaseImportedScratch(a){
 const sourceArtifacts=new Set(a.artifacts.filter(artifact=>a.reuse.some(record=>artifact.artifactId.startsWith(a.id+':'+record.kind+':'))).map(artifact=>artifact.artifactId));
 const live=new Map(),apply=effect=>{if(effect.op==='acquire')live.set(effect.holdingId,{...effect});else if(effect.op==='release')live.delete(effect.holdingId);else if(effect.op==='move'&&live.has(effect.holdingId))live.set(effect.holdingId,{...live.get(effect.holdingId),...effect,op:'acquire'});};
 function releaseOwned(stage,title,holdings){
  const byOwner=new Map(),released=[];
  for(const holding of holdings){if(!byOwner.has(holding.actorId))byOwner.set(holding.actorId,[]);byOwner.get(holding.actorId).push(holding);}
  for(const [owner,owned] of byOwner){
   const step=a.add(stage+'-'+owner,title,owner,owner,{type:'local-cleanup',summary:'At the source lifecycle boundary each owner releases only its own exact temporary representations. Accepted credentials, authoritative records and unrelated sessions survive.'});
   for(const holding of owned){
    a.events[step.id].milestones[0].effects.push({op:'release',holdingId:holding.holdingId});
    const artifact=a.artifacts.find(item=>item.artifactId===holding.artifactId),view=artifact.representations.find(rep=>rep.representationId===holding.representationId);
    for(const field of view?.fields||[])step.attributeOperations.push({attributeId:field.attributeId,instanceId:artifact.artifactId,creator:artifact.creator,holders:[owner],inspectors:view.readableBy||[],fieldPath:field.path||field.name,representation:holding.representationId,value:field.value,sourceEventId:step.id,exactValueRef:artifact.artifactId+':'+holding.representationId,actorId:owner,kind:'evict',detail:'Release this owner’s exact temporary source holding at its lifecycle boundary; no cross-host cleanup or wire exchange.'});
   }
   step.fields=[...new Set(step.attributeOperations.map(op=>op.attributeId))];released.push(step);
  }
  return released;
 }
 for(const effect of a.initial)apply(effect);
 const ordered=[];
 for(const step of [...a.steps]){
  const cleanup=[];
  for(const milestone of a.events[step.id].milestones)milestone.effects=milestone.effects.filter(effect=>{
   const holding=effect.op==='release'?live.get(effect.holdingId):null;
   if(step.from===step.to&&holding?.retention==='temporary'&&sourceArtifacts.has(holding.artifactId)){cleanup.push(holding);return false;}
   apply(effect);return true;
  });
  ordered.push(step);
  if(cleanup.length){
   step.attributeOperations=step.attributeOperations.filter(op=>op.kind!=='evict'||!cleanup.some(holding=>holding.actorId===op.actorId&&holding.artifactId===op.instanceId&&holding.representationId===op.representation));
   for(const local of releaseOwned('source-cleanup-'+step.id.slice(a.id.length+1).replaceAll(':','-'),'Release source scratch at its owner after '+step.title,cleanup)){
    ordered.push(local);for(const milestone of a.events[local.id].milestones)for(const effect of milestone.effects)apply(effect);
   }
  }
 }
 a.steps.splice(0,a.steps.length,...ordered);
 releaseOwned('source-attempt-cleanup','Release completed source-attempt scratch at its actual owner',[...live.values()].filter(holding=>holding.retention==='temporary'&&sourceArtifacts.has(holding.artifactId)));
}
function wprotBuild(code,selected='default',overrides={},subfixtureId=null){
 if(!Object.hasOwn(wprotCases,code))throw new RangeError('Unknown protection plan: '+code);
 const first=Object.keys(wprotCases[code])[0],variant=selected==='default'?first:selected;if(!Object.hasOwn(wprotCases[code],variant))throw new RangeError('Unknown '+code+' variant: '+selected);
 const f=wprotInputs(code,variant,overrides),id='lab-'+code.toLowerCase(),isolation=f.credentialGuard&&f.accountAuthority==='AD',positions=f.accountAuthority==='SAM'?{...wprotPositions,wslSAM:{x:110,y:365},wslFile:{x:110,y:610}}:wprotPositions;
 const a=wslAuthor({id,code,planId:code,title:wprotTitles[code],family:'windows-protection',workspace:'windows',phase:'Credential protection',variantId:variant,positions,summary:'Separate secret custody, local protection, KDC admission and resource permission using source-owned decisions.',sources:WINDOWSPROTECTIONLAB_SOURCES,sourceSupportNote:wprotSupportNotes[code],profile:{name:'Scoped '+code+' / '+variant,version:'Windows 11 Enterprise 25H2 26200.9711 / KB5127648; Server 2025 DC build unobserved',implementation:'Documented symbolic reference',assumptions:['Declared configured/effective state, not automatic defaults.','Same-domain writable KDC; no RODC, loopback or cross-forest interoperability claim.','Source-qualified settings are declared scenario inputs, not live OS observations.'],startingSummary:['Account authority: '+f.accountAuthority,'CG configured: '+f.cgConfigured+'; running: '+f.credentialGuard+'; selected secret isolated: '+isolation,'PPL configured: '+f.pplConfigured+'; effective: '+f.pplRunning],sources:WINDOWSPROTECTIONLAB_SOURCES},relatedLessons:[{id:'lab-wlog02',title:'Protected TGT operation reference',summary:'Independent sign-in and service credential context.'},{id:'lab-wlog06',title:'Required FAST',summary:'Computer armor and user authentication remain distinct.'},{id:'lab-wlog04',variantId:'protected-user',title:'Protected Users offline sign-in',summary:'No cached verifier is created by that protected sign-in.'}],initial:{effectivePolicy:{credentialGuard:{configured:f.cgConfigured,running:f.credentialGuard,observed:false,securityServicesRunning:f.securityServicesRunning,restartRequired:false,uefiLock:false},lsaProtection:{configured:f.pplConfigured,running:f.pplRunning,observed:false},protectedUsers:f.protectedUser},isolationActive:isolation,machineAccepted:false,policyAllowed:null,policySupported:f.domainFunctionality>=6,delegatedCredential:false,clientKnowsResult:false,resultCode:null,cachedVerifierPresent:false}},f,WINDOWSPROTECTIONLAB_ATTRIBUTES);
 wslAddAuthority(a);a.state.verifierAuthority=f.accountAuthority==='SAM'?'target-local SAM':code==='WPROT02'?'local protected-process/code-integrity boundary':'CORP writable KDC';a.state.authenticationPackage=f.mechanism==='NTLMv2'?'MSV1_0 / NTLMv2':'Kerberos AES';
 const sourceId={WPROT01:'wprot-S13',WPROT02:'wprot-S12',WPROT03:'wprot-S14',WPROT04:'wprot-S16',WPROT05:'wprot-S17'}[code],defaultSource=WINDOWSPROTECTIONLAB_SOURCES.find(source=>source.id===sourceId).url,createObject=a.object;
 a.object=(key,label,type,creator,value,readers,options={})=>createObject(key,label,type,creator,value,readers,{source:defaultSource,standard:wprotStandards[code],...options});
 const status=a.seed(a.object('effective-status','Configured, effective and observed protection states','policy','wslLSA',{profileId:code.toLowerCase()+'-'+variant,cgConfigured:f.cgConfigured,cgRunning:f.credentialGuard,selectedSecretIsolated:isolation,securityServicesRunning:f.securityServicesRunning,runtimeObserved:false,pplConfigured:f.pplConfigured,pplRunning:f.pplRunning,boot:'completed boot; no live toggle',processNameIsEvidence:false},['wslLSA']));a.add('profile-status','Read scoped effective status; configuration is not runtime proof','wslLSA','wslLSA',{uses:[status]});
 if(code==='WPROT01')wprotProtection(a,f);else if(code==='WPROT02')wprotPpl(a,f);else if(code==='WPROT03')wprotPu(a,f);else if(code==='WPROT04')wprotPolicyAS(a,f);else wprotPolicyTGS(a,f);
 a.state.profileId=code.toLowerCase()+'-'+variant;
 wprotBindSeedOccurrences(a);
 wprotReleaseImportedScratch(a);
 const compactPositions={};
 for(const actor of Object.values(a.actors)){
  // Compact children share only their physical host's anchor. Their identities,
  // inventories and full role descriptions remain available in expanded view.
  let host=actor;while(host.parentId&&a.actors[host.parentId])host=a.actors[host.parentId];
  compactPositions[actor.id]=wprotCompactPositions[host.id]||positions[actor.id];
  if(wprotCardNames[actor.id])actor.cardName=wprotCardNames[actor.id];
  const role=actor.id==='wslSAM'&&f.accountAuthority==='SAM'?'Target-local account authority':actor.id==='wslFile'&&code==='WPROT05'?'Target policy / resource access':wprotRoles[actor.id];
  if(role){actor.plainRole=actor.plainRole||actor.role;actor.role=role;}
 }
 const model=a.finish();
 model.expandedPositions=model.positions;model.compactPositions=compactPositions;model.physicalHostBoundaries=true;
 model.profile.transports=[...new Set(['Local OS calls / distinct-owner IPC',...a.steps.flatMap(step=>(step.layers||[]).map(layer=>layer.transport).filter(Boolean))])];
 model.profileId=code.toLowerCase()+'-'+variant;model.canonicalCaseId=code+'/'+variant;model.planId=code;model.defaultVariantId=first;
 model.defaultSubfixtureId=wprotDefaultSubfixtures[model.canonicalCaseId]?model.canonicalCaseId+'/'+wprotDefaultSubfixtures[model.canonicalCaseId]:null;
 model.subfixtureId=subfixtureId||model.defaultSubfixtureId;
 model.platformProfile={client:{edition:'Windows 11 Enterprise',version:'25H2',build:'26200.9711',update:'KB5127648 / 2026-10-13',joined:true,role:'member workstation',installation:'declared existing installation; no inferred defaults'},target:{edition:'Windows 11 Enterprise',version:'25H2',build:'26200.9711',role:'member machine; never DC'},dc:{edition:'Windows Server 2025',build:null,observed:false,role:'same-domain writable KDC'},domainFunctionalLevel:'Windows Server 2016 or later eligible reference',accountSid:f.userSid,selectedLogonType:f.accountAuthority==='SAM'?3:2,evidenceLevel:'documented symbolic; native unperformed',...f};
 model.sourceSupportNote=wprotSupportNotes[code];
 model.protectionLimits=code==='WPROT01'?['CG protects the declared domain sign-in TGT/NTOWF inputs, not local SAM accounts or every LSASS object.','Kerberos service tickets and independent service/session keys are normal-OS credentials.','Cached offline verifiers are local-only validation data, outside the network-secret isolation guarantee.','Credential input capture, explicitly prompted NTLM input and generic application-owned secrets are not isolated sign-in secrets.','Already available session authority remains usable; service and resource authorization still decide each operation.','A privileged VM host is outside this guest-isolation guarantee. No native runtime or memory-erasure certification is claimed.']:code==='WPROT02'?['PPL process access and Microsoft signing/shared-section enforcement are independent of CG secret isolation.','Audit diagnostics are synthetic fixture evidence, not captured Windows events; audit never silently becomes enforcement.']:code==='WPROT03'?['Eligible human domain user; Protected Users alone, with no explicit authentication policy.','Original four-hour ticket/renewal lineage, fresh AS authentication and retained local session are separate.']:['Account-policy admission and ticket issuance never grant resource ACL access.','Same-domain writable-DC and explicit source-owned PAC/armor profile only; native Windows/DC behavior is unperformed.'];
 model.profile.assumptions.push(...model.protectionLimits);
 model.variantChoices=Object.keys(wprotCases[code]).map(key=>({id:key,label:key.replace(/-/g,' '),description:'Immutable source-authored '+code+' case profile.'}));model.withVariant=key=>wprotBuild(code,key);
 model.subfixtureChoices=Object.keys(wprotSubfixtures).filter(key=>key.startsWith(code+'/'+variant+'/')).map(key=>({id:key,label:key.split('/').at(-1)}));
 model.withSubfixture=key=>{if(!model.subfixtureChoices.some(choice=>choice.id===key))throw new RangeError('Unknown '+model.canonicalCaseId+' comparison profile: '+key);return buildWindowsProtectionSubfixture(key);};
 model.catalogAttributeIds=[...new Set([...(wprotFieldIds[id]||[]),...model.ids])];
 const decisions=code==='WPROT01'?['isolationActive','credentialVerified','tgtAccepted','hostTicketAccepted','delegationAllowed','resourceAllowed']:code==='WPROT02'?['isolationActive','pluginLoaded','pplBoundaryApplied','processAccessAllowed']:code==='WPROT03'?['credentialVerified','tgtAccepted','delegationAllowed','localSessionRetained','newCredentialLineage']:code==='WPROT04'?['machineAccepted','policyAllowed','policyWouldDeny','effectivePolicySource','effectiveEnforced','tgtAccepted']:['machineAccepted','policyAllowed','policyWouldDeny','effectivePolicySource','effectiveEnforced','policySlot','hostTicketAccepted','networkAuthenticated','resourceAllowed'];
 model.decisionBindings=[...decisions,'resultCode','clientKnowsResult'].map(path=>({label:path==='resultCode'?'Scoped lesson outcome (not a native status number)':path.replace(/([A-Z])/g,' $1'),path:'workstation.'+path}));return wslFreeze(model);
}
function wprotLazy(code){
 const id='lab-'+code.toLowerCase(),first=Object.keys(wprotCases[code])[0];let current=null;const get=()=>current||(current=wprotBuild(code,first));
 const descriptor={id,code,planId:code,family:'windows-protection',workspace:'windows',category:'Credential protection',protocol:'Windows security / Kerberos / NTLMv2',status:'reference',universalLab:true,factorSelectable:false,jweAdaptable:false,title:wprotTitles[code],summary:'Credential custody, protection boundaries and KDC policy decisions.',variantId:first,defaultVariantId:first,variantChoices:Object.keys(wprotCases[code]).map(key=>({id:key,label:key.replace(/-/g,' ')})),catalogAttributeIds:wprotFieldIds[id],ids:wprotFieldIds[id],definitions:()=>Object.fromEntries(wprotFieldIds[id].map(field=>[field,WINDOWSPROTECTIONLAB_ATTRIBUTES[field]])),steps:()=>get().steps(),actors:()=>get().actors(),withVariant:key=>wprotBuild(code,key),withSubfixture:key=>get().withSubfixture(key)};
 for(const key of ['initialState','workstationInventory','profile','fixtureInputs','positions','actorPositions','compactPositions','expandedPositions','physicalHostBoundaries','decisionBindings','sourceSupportNote','subfixtureChoices','subfixtureId','defaultSubfixtureId','relatedLessons','canonicalCaseId','platformProfile'])Object.defineProperty(descriptor,key,{enumerable:true,get:()=>get()[key]});
 descriptor.examples=()=>get().examples();
 return descriptor;
}
export function buildWindowsProtectionFixture(scenarioId,variantId='default'){const code=scenarioId.replace(/^lab-/,'').toUpperCase();return wprotBuild(code,variantId);}
export function buildWindowsProtectionSubfixture(id){const changes=wprotSubfixtures[id];if(!changes)throw new RangeError('Unknown protection comparison fixture: '+id);const [code,variant]=id.split('/');return wprotBuild(code,variant,changes,id);}
export const WINDOWSPROTECTIONLAB_SUBFIXTURES=wslFreeze(Object.keys(wprotSubfixtures).map(id=>({id,label:id.split('/').at(-1),caseId:id.split('/').slice(0,2).join('/')})));
const wprotFieldIds={};
const wprotLocalFields=['effective-status','account-policy','target-policy','account-policy-selection','policy-selection','as-policy','policy-as-result','tgs-policy','tgs-context','audit-result','resource-rule','resource-check','pu-check','pu-result','cache-policy','cache-check','old-ticket-lineage','existing-local-session','membership-check','renewal-request','renewal-check','process-access-request','process-check','plugin-metadata','plugin-check','credential-source','vault-domain','vault-generic','explicit-prompt','sam-authority','sam-request','local-verify','ntlm-attempt','ntlm-protected-key','ntlm-operation','ntlm-operation-proof','ntlm-policy','delegation-check','constrained-service-ticket','preexisting-user-tgt','preexisting-user-tgt-key','user-pac','computer-armor-ticket','computer-armor-ticket-key','computer-armor-pac','computer-armor-subkey','computer-armor-proof','computer-explicit-armor-key','compound-armor-key','compound-fast-request','compound-strengthen-key','compound-final-reply-key','compound-fast-response','capability-check','armor-ready','device-evidence','client-user-key','kdc-user-key','kdc-account-policy','as-request','tgt','tgt-session-key','as-client-reply','kdc-machine-service-key','machine-service-key','credential-context-reference','host-reply-subkey','host-operation-proof','host-tgs-request','kdc-krbtgt-key','host-ticket','host-session-key','host-client-reply','validated-logon-information'];
// Metadata uses schemas only. No default or all-case trace is constructed here.
for(const code of Object.keys(wprotCases)){
 const id='lab-'+code.toLowerCase(),prefix=id.replace(/-/g,'_')+'_';
 wslRegisterFields(id,WINDOWSPROTECTIONLAB_ATTRIBUTES,[...wprotLocalFields,'network-request','network-result','network-credential-context','ppl-independent-protected-input','armor-device-pac','pu-ntlm-authority-reply','pu-ntlm-service-response','s4u-policy','s4u-service-tgt','s4u-service-tgt-key','s4u-backend-key','s4u-reply-subkey','s4u-authenticator','s4u-request','s4u-session-key','s4u-client-reply','s4u-initiator-subkey','s4u-ap-request','s4u-acceptor-subkey','s4u-ap-reply','s4u-resource-rule','s4u-operation','s4u-resource-result','s4u-local-result']);
 wslRegisterFields(id,WINDOWSPROTECTIONLAB_ATTRIBUTES,['old-session-result','old-ticket-key','renewal-subkey','renewal-proof','renewal-krbtgt-key','ad-configured-material','credential-input','authentication-package','live-signin-session','compound-fast-error','as-policy-client-result','tgs-policy-client-result','resource-request','prior-account-record','prior-signin-tgt','prior-signin-tgt-key','signed-in-protected-input','signed-in-credential-handle','credssp-source-request','legacy-as-request','pu-account-constraints']);
 wslRegisterFields(id,WINDOWSPROTECTIONLAB_ATTRIBUTES,['account-directory-record','account-silo-record','account-direct-policy','target-directory-record','target-silo-record','target-direct-policy','ntlm-operation-compute',...['host','s4u'].flatMap(kind=>['initiator-subkey','ap-request','validated-service-facts','service-context','acceptor-subkey','ap-reply','unaccepted-ap-reply','resource-rule','operation','resource-result','local-result'].map(key=>kind+'-'+key))]);
 wprotFieldIds[id]=Object.keys(WINDOWSPROTECTIONLAB_ATTRIBUTES).filter(key=>key.startsWith(prefix));
 const sourceSets=['WPROT01','WPROT03'].includes(code)?[[SMBLAB_ATTRIBUTES,'smb',key=>key.startsWith('smb_ntlm_')],...(code==='WPROT01'?[[WINDOWSREMOTELAB_ATTRIBUTES,'sam',key=>key.startsWith('wra_01_')]]:[])]:code==='WPROT04'?[[CRYPTOLAB_ATTRIBUTES,'ad',key=>key.startsWith('cryptoAdFastAsSuccess')]]:[];
 for(const [registry,kind,include] of sourceSets)for(const [field,definition] of Object.entries(registry))if(include(field)){const sourceField=kind==='sam'?field.replace(/^wra_01_/,'wra_source_'):field,mapped=prefix+(kind==='sam'?'smb':kind)+'_'+sourceField;WINDOWSPROTECTIONLAB_ATTRIBUTES[mapped]=definition;wprotFieldIds[id].push(mapped);}
 if(code==='WPROT04')for(const [field,definition] of Object.entries(CRYPTOLAB_ATTRIBUTES))if(field.startsWith('cryptoAdFastAsChallenge')){const mapped=prefix+'ad_'+field.replace('cryptoAdFastAsChallenge','cryptoAdFastAsSuccess');WINDOWSPROTECTIONLAB_ATTRIBUTES[mapped]=definition;if(!wprotFieldIds[id].includes(mapped))wprotFieldIds[id].push(mapped);}
}
export const WINDOWSPROTECTIONLAB_SCENARIOS=Object.keys(wprotCases).map(wprotLazy);
