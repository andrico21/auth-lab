import {labAttribute,labStep,labScenario} from './lab-common.js';
import {buildSmbAccessReference} from './smb-access-lab.js';

// Input-only WP0 fixtures. Independent literal answers live in remote-cases.json;
// production never imports that manifest or derives decisions from case names.
const wraCaseInputs=[{"planId":"WRA01","caseId":"default-filtered","changes":{}},{"planId":"WRA01","caseId":"explicit-zero","changes":{"latfp":0}},{"planId":"WRA01","caseId":"filter-disabled","changes":{"latfp":1}},{"planId":"WRA01","caseId":"full-token-acl-denied","changes":{"latfp":1,"shareRule":"deny-user"}},{"planId":"WRA01","caseId":"ordinary-share-allowed","changes":{"resource":"reports","shareRule":"allow-user"}},{"planId":"WRA01","caseId":"bad-password","changes":{"passwordMatches":false}},{"planId":"WRA01","caseId":"local-standard-user","changes":{"admin":false,"latfp":1}},{"planId":"WRA01","caseId":"reused-session","changes":{"sessionMode":"reuse","latfp":1}},{"planId":"WRA01","caseId":"ntlm-unavailable","changes":{"ntlmAllowed":false}},{"planId":"WRA02","caseId":"rid500-aam-off","changes":{"rid":500,"fat":0,"latfp":0}},{"planId":"WRA02","caseId":"renamed-rid500","changes":{"rid":500,"name":"renamed-admin","fat":0,"latfp":0}},{"planId":"WRA02","caseId":"rid500-aam-on","changes":{"rid":500,"fat":1,"latfp":0}},{"planId":"WRA02","caseId":"rid500-filter-disabled","changes":{"rid":500,"fat":1,"latfp":1}},{"planId":"WRA02","caseId":"name-is-not-rid","changes":{"name":"Administrator"}},{"planId":"WRA02","caseId":"account-disabled","changes":{"rid":500,"enabled":false}},{"planId":"WRA03","caseId":"domain-admin-joined","changes":{"authority":"CORP","joined":true,"mechanism":"Kerberos"}},{"planId":"WRA03","caseId":"domain-admin-nonjoined","changes":{"authority":"CORP","joined":false,"mechanism":"Kerberos"}},{"planId":"WRA03","caseId":"domain-ntlm-explicit","changes":{"authority":"CORP","mechanism":"NTLMv2"}},{"planId":"WRA03","caseId":"domain-user-read","changes":{"authority":"CORP","mechanism":"Kerberos","admin":false,"resource":"reports","shareRule":"allow-user"}},{"planId":"WRA03","caseId":"domain-user-admin-denied","changes":{"authority":"CORP","mechanism":"Kerberos","admin":false,"latfp":1}},{"planId":"WRA03","caseId":"same-name-different-authority","changes":{}},{"planId":"WRA03","caseId":"domain-proof-failed","changes":{"authority":"CORP","mechanism":"NTLMv2","passwordMatches":false}},{"planId":"WRA04","caseId":"network-logon-denied","changes":{"denyNetwork":true}},{"planId":"WRA04","caseId":"share-denied","changes":{"latfp":1,"shareRule":"deny-user"}},{"planId":"WRA04","caseId":"file-denied","changes":{"latfp":1,"fileRule":"deny-user"}},{"planId":"WRA04","caseId":"deny-only-sid","changes":{}},{"planId":"WRA04","caseId":"client-elevated","changes":{"clientElevated":true}},{"planId":"WRA04","caseId":"management-endpoint-denied","changes":{"authority":"CORP","mechanism":"Kerberos","endpoint":"WinRM","shareRule":"allow-user","endpointRule":"deny-user"}},{"planId":"WRA04","caseId":"signed-denial","changes":{"latfp":1,"shareRule":"deny-user"}},{"planId":"WRA04","caseId":"encrypted-denial","changes":{"latfp":1,"fileRule":"deny-user","encrypt":true}},{"planId":"WRA05","caseId":"default-non-elevated","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true}},{"planId":"WRA05","caseId":"broad-allow","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"apBroad":true}},{"planId":"WRA05","caseId":"user-sid-match","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"apList":"user"}},{"planId":"WRA05","caseId":"group-sid-match","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"apList":"group"}},{"planId":"WRA05","caseId":"no-list-match","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"apList":"unrelated"}},{"planId":"WRA05","caseId":"broad-overrides-list","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"apBroad":true,"apList":"unrelated"}},{"planId":"WRA05","caseId":"nonadmin-listed","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"admin":false,"apList":"user"}},{"planId":"WRA05","caseId":"unavailable-profile","changes":{"authority":"CORP","mechanism":"Kerberos","ap":true,"featureAvailable":false}}];
const wraPairs={"WRA01/default-filtered":[{"id":"local","changes":{}},{"id":"domain","changes":{"authority":"CORP","mechanism":"Kerberos"}}],"WRA01/reused-session":[{"id":"reused","changes":{}},{"id":"fresh","changes":{"sessionMode":"fresh"}},{"id":"later-proof-denial","changes":{"sessionMode":"prior-session-denial","passwordMatches":false}}],"WRA03/same-name-different-authority":[{"id":"local","changes":{}},{"id":"domain","changes":{"authority":"CORP","mechanism":"Kerberos"}}],"WRA04/deny-only-sid":[{"id":"allow-ace","changes":{}},{"id":"deny-ace","changes":{"shareRule":"deny-admin-allow-user"}}],"WRA04/client-elevated":[{"id":"elevated","changes":{}},{"id":"standard","changes":{"clientElevated":false}}]};

function wraFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(wraFreeze);Object.freeze(value);}return value;}
wraFreeze(wraCaseInputs);wraFreeze(wraPairs);
const wraBase=wraFreeze({authority:'TARGET',name:'ops',rid:1001,admin:true,enabled:true,passwordMatches:true,ntlmAllowed:true,mechanism:'NTLMv2',joined:false,latfp:null,fat:0,enableLua:1,denyNetwork:false,resource:'ADMIN$',shareRule:'allow-admin',fileRule:'allow-user',endpoint:'SMB',endpointRule:'allow-user',clientElevated:false,sessionMode:'fresh',ap:false,apBroad:false,apList:'empty',featureAvailable:true,encrypt:true});
const wraTitles={WRA01:'Local administrator authenticates, ADMIN$ is denied',WRA02:'Built-in Administrator and RID500 policy',WRA03:'Domain account from joined or nonjoined PC',WRA04:'Locate the denial: logon, endpoint, share or file',WRA05:'Administrator Protection: remote domain elevation policy'};
const wraSourceURLs={S01:'https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction',S02:'https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts',S03:'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration',S04:'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-mssecurityguide#applyuacrestrictionstolocalaccountsonnetworklogon',S05:'https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens',S06:'https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token',S07:'https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritycontexttoken',S08:'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624',S09:'https://learn.microsoft.com/en-us/windows/win32/wmisdk/user-account-control-and-wmi',S20:'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/',S21:'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions',S23:'https://www.rfc-editor.org/rfc/rfc4120.txt',S24:'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962'};
const wraSourceSections={S01:['Local user accounts; domain user accounts; UAC remote settings','2026-02-12'],S02:['Administrator RID500 identity; restrictions on remote use of local accounts','2026-04-13'],S03:['Built-in Administrator Admin Approval Mode; EnableLUA; registry settings','2026-05-14'],S04:['ApplyUACRestrictionsToLocalAccountsOnNetworkLogon; SecGuide.admx mapping','2026-10-14'],S05:['Access token contents; primary and impersonation tokens','2025-07-08'],S06:['SE_GROUP_ENABLED; SE_GROUP_USE_FOR_DENY_ONLY and ACE matching','Captured page update metadata 2018-05-31'],S07:['QuerySecurityContextToken parameters, server impersonation and CloseHandle','Captured page update metadata 2018-12-05'],S08:['Logon type3 Network versus type10 RemoteInteractive; versioned fields','2021-09-07'],S09:['Remote management: DCOM launch/activation, namespace Remote Enable and object rights','Captured page update metadata 2018-05-31'],S20:['Remote logon behavior under Administrator protection; broad and SID-list exceptions','2026-10-13'],S21:['The two Allow remote logon with elevated privileges policies; Windows Insider Preview [11.0.26100.9278] applicability','2026-10-14'],S23:['Kerberos AS/TGS/AP exchanges, sections3.1-3.3 and5.5','RFC4120 / July2005'],S24:['MS-SMB2 sections2.2.3-2.2.14,2.2.41,3.1.4.2,3.3.5.5,3.3.5.7,3.3.5.9; MS-NLMP3.3.2; MS-KILE3.1.1.2','MS-SMB2 88.0 / 2026-09-28; captured NLMP/KILE primary clauses']};
export const WINDOWSREMOTELAB_SOURCES=wraFreeze(Object.entries(wraSourceURLs).map(([id,url])=>({id:'wra-'+id,name:id+' - remote administration primary source',standard:id==='S24'?'MS-SMB2 / MS-NLMP / MS-APDS / MS-KILE':id==='S23'?'RFC4120':'Microsoft Windows security documentation',section:wraSourceSections[id][0],url,retrieved:'2026-10-25',revision:wraSourceSections[id][1],errata:'Source-qualified symbolic reference, not native evidence; historical UAC wording and AP overview/CSP applicability disagreement retained.'})));
const wraBroadLabel='User Account Control: Allow remote logon with elevated privileges for domain users in the local Administrators group when Administrator protection is enabled';
const wraListLabel='User Account Control: Allow remote logon with elevated privileges for specified domain users and groups when Administrator protection is enabled';
const wraAdminSID='S-1-5-32-544',wraUsersSID='S-1-5-32-545',wraDomainGroup='S-1-5-21-440-550-660-2100';
const wraExpanded=wraFreeze({smbClient:{x:170,y:190},smbServer:{x:550,y:190},smbSAM:{x:790,y:425},smbDC:{x:970,y:190}});
const wraCompact=wraFreeze({smbClient:{x:170,y:190},smbServer:{x:620,y:190},smbSAM:{x:620,y:190},smbDC:{x:970,y:190}});
function wraPolicy(f){return wraFreeze({EnableLUA:1,LocalAccountTokenFilterPolicy:f.latfp,FilterAdministratorToken:f.fat,applyUACRestrictions:f.latfp!==1,restrictionLabel:'Apply UAC restrictions to local accounts on network logons',registryPath:'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',admx:'SecGuide.admx / Pol_SecGuide_0201_LATFP',csp:'MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon',polarity:'Enabled restriction = LATFP absent/0. LATFP1 removes ordinary local network filtering; not a recommended access-denied fix.',administratorProtection:f.ap,apBroad:f.apBroad,apSIDList:f.apList==='user'?[f.sid]:f.apList==='group'?[wraDomainGroup]:f.apList==='unrelated'?['S-1-5-21-999-999-999-1001']:[],apBroadPolicyLabel:wraBroadLabel,apListPolicyLabel:wraListLabel,denyNetwork:f.denyNetwork,allowNetwork:[wraUsersSID],denyNetworkSIDs:f.denyNetwork?[f.sid]:[],credentialGuard:{configured:'not selected',running:'unknown; not required by this reference'},lsaProtection:{configured:'not selected',running:'unknown'},provenance:'immutable declared member-machine profile; effective/restarted assumed, not observed'});}
function wraAccount(f){return wraFreeze({principal:f.authority+'\\'+f.name,authority:f.authority,userSid:f.sid,rid:f.rid,enabled:f.enabled,targetAdministrator:f.admin,directoryMembershipUnchanged:true,domainGroups:f.authority==='CORP'?[wraDomainGroup]:[],nonblankPassword:true,logonType:3,sourceDesktop:'WORKGROUPPC\\bob'});}
function wraAdmission(account,policy){
  if(!account.enabled)return {allowed:false,status:'STATUS_ACCOUNT_DISABLED',reason:'resolved target account is disabled'};
  const sids=[account.userSid,wraUsersSID,...account.domainGroups,...(account.targetAdministrator?[wraAdminSID]:[])];
  if(policy.denyNetworkSIDs.some(sid=>sids.includes(sid)))return {allowed:false,status:'STATUS_LOGON_TYPE_NOT_GRANTED',reason:'applicable deny-network-logon right overrides allow'};
  if(!policy.allowNetwork.some(sid=>sids.includes(sid)))return {allowed:false,status:'STATUS_LOGON_TYPE_NOT_GRANTED',reason:'no applicable network logon allow right'};
  return {allowed:true,status:'STATUS_SUCCESS',reason:'enabled account and explicit target network right'};
}
export function evaluateWindowsRemoteContext(account,policy,contextId='target-context'){
  const admin=account.targetAdministrator;
  let mode='standard',reason='no target Administrators membership';
  if(admin){
    if(account.authority==='CORP'){
      if(policy.administratorProtection){
        const listMatch=policy.apSIDList.includes(account.userSid)||account.domainGroups.some(sid=>policy.apSIDList.includes(sid));
        mode=policy.apBroad||listMatch?'full':'non-elevated';reason=policy.apBroad?'AP broad target-admin policy overrides SID list':listMatch?'eligible target-admin user/group SID exception':'AP target-admin reference with no exception';
      }else{mode='full';reason='classic AP-off domain target-admin network comparison';}
    }else{mode=policy.LocalAccountTokenFilterPolicy===1||account.rid===500&&policy.FilterAdministratorToken===0?'full':'filtered';reason=policy.LocalAccountTokenFilterPolicy===1?'explicit LATFP1 comparison':account.rid===500&&policy.FilterAdministratorToken===0?'RID500 built-in exception, AAM off':'effective local network restriction';}
  }
  const full=mode==='full';
  return wraFreeze({tokenId:contextId,owner:'smbServer',type:'impersonation',role:'target service authorization context; not source primary process token',account:account.principal,userSid:account.userSid,authenticationId:'LUID('+contextId+')',logonType:3,mode,reason,groups:[{sid:wraUsersSID,attributes:['enabled','mandatory']},...account.domainGroups.map(sid=>({sid,attributes:['enabled']})),...(admin?[{sid:wraAdminSID,attributes:full?['enabled']:['deny-only'],membershipStillPresent:true}]:[])],privileges:[{name:'SeChangeNotifyPrivilege',present:true,enabled:true},...(full?[{name:'SeDebugPrivilege',present:true,enabled:false},{name:'SeBackupPrivilege',present:true,enabled:false}]:[])],removedPrivileges:admin&&!full?['SeDebugPrivilege','SeBackupPrivilege']:[],privilegeInventoryEvidence:'declared symbolic access-check fixture, not exhaustive native token enumeration',integrity:'unknown',integritySid:null,elevationType:'unknown',elevatedNativeFlag:null,nativeFields:'unobserved; unknown, including RID500 FAT1/LATFP1 and AP details',remotePrompt:false});
}
function wraReadablePolicy(configured,applied=null){
  const describe=snapshot=>snapshot?{
    rawLATFP:snapshot.LocalAccountTokenFilterPolicy,effectiveLATFP:snapshot.LocalAccountTokenFilterPolicy??0,
    applyRemoteRestrictions:snapshot.applyUACRestrictions,
    latfpDisplay:snapshot.LocalAccountTokenFilterPolicy===null?'absent (effective 0)':String(snapshot.LocalAccountTokenFilterPolicy),
    restrictionsDisplay:snapshot.applyUACRestrictions?'Enabled':'Disabled',
    EnableLUA:snapshot.EnableLUA,FilterAdministratorToken:snapshot.FilterAdministratorToken,
    administratorProtection:snapshot.administratorProtection
  }:null;
  return wraFreeze({label:'Apply remote restrictions',policyLabel:configured.restrictionLabel,registryValueName:'LocalAccountTokenFilterPolicy',registryPath:configured.registryPath,polarity:configured.polarity,configured:describe(configured),applied:describe(applied),appliedStatus:applied?'Applied when this target context was created':'No new target context; policy not applied to a new token',scope:'Configured policy changes do not retroactively replace an existing session context.'});
}
function wraTokenComparison(account,appliedPolicy,after,refs){
  const before={
    artifactRef:refs.beforeRef,owner:'smbServer',kind:'modeled-target-filter-input',usableToken:false,
    label:'Modeled target-side filter input/reference',scope:'Not the source-client token and not an observed native full token',
    account:account.principal,userSid:account.userSid,targetAdministrator:account.targetAdministrator,
    groups:[{sid:wraUsersSID,attributes:['enabled','mandatory']},...account.domainGroups.map(sid=>({sid,attributes:['enabled']})),...(account.targetAdministrator?[{sid:wraAdminSID,attributes:['enabled'],membershipStillPresent:true}]:[])],
    privileges:[{name:'SeChangeNotifyPrivilege',present:true,enabled:true},...(account.targetAdministrator?[{name:'SeDebugPrivilege',present:true,enabled:false},{name:'SeBackupPrivilege',present:true,enabled:false}]:[])],
    integrity:'unknown',elevationType:'unknown',nativeFields:'Unobserved; exact native token inventory is unknown'
  };
  const afterView={artifactRef:refs.afterRef,owner:after.owner,kind:'applied-target-context',label:'Applied target service context',userSid:after.userSid,account:after.account,mode:after.mode,type:after.type,groups:after.groups,privileges:after.privileges,removedPrivileges:after.removedPrivileges,integrity:after.integrity,elevationType:after.elevationType,nativeFields:after.nativeFields};
  const privilegeView=(view,name)=>{const privilege=view.privileges.find(p=>p.name===name);return privilege?{present:true,enabled:privilege.enabled,state:privilege.enabled?'enabled':'disabled'}:{present:false,enabled:null,state:'removed'};};
  const groupSIDs=[...new Set([...before.groups,...afterView.groups].map(group=>group.sid))];
  const privilegeNames=[...new Set([...before.privileges,...afterView.privileges].map(privilege=>privilege.name))];
  return wraFreeze({schemaVersion:1,owner:'smbServer',evidenceLevel:'Modeled target-side source reference; no native token observation',before,after:afterView,
    groups:groupSIDs.map(sid=>({sid,beforeAttributes:before.groups.find(group=>group.sid===sid)?.attributes||[],afterAttributes:afterView.groups.find(group=>group.sid===sid)?.attributes||[],directoryMembershipUnchanged:true})),
    privileges:privilegeNames.map(name=>({name,before:privilegeView(before,name),after:privilegeView(afterView,name)})),
    policyRef:refs.policyRef,appliedPolicy,policyAtContextCreation:wraReadablePolicy(appliedPolicy,appliedPolicy),
    userSIDUnchanged:before.userSid===afterView.userSid,additionalTokenOrGrantCreated:false});
}
// Ordered, explicit DACL subset. Remaining requested bits are evaluated against
// ACEs in order; a deny-only SID never satisfies allow. No privilege bypass.
export function evaluateWindowsRemoteAccess(token,requestedMask,aces){
  if(!Number.isInteger(requestedMask)||requestedMask<=0)throw new RangeError('A positive explicit access mask is required');
  const groups=new Map(token.groups.map(group=>[group.sid,group.attributes]));
  let remaining=requestedMask,deniedMask=0;const evaluations=[];
  for(const ace of aces){
    if(!['allow','deny'].includes(ace.type)||!Number.isInteger(ace.mask))throw new RangeError('Unsupported explicit ACE');
    const attributes=ace.sid===token.userSid?['enabled']:groups.get(ace.sid)||[];
    const applicable=ace.type==='deny'?attributes.includes('enabled')||attributes.includes('deny-only'):attributes.includes('enabled')&&!attributes.includes('deny-only');
    const matchedMask=applicable?remaining&ace.mask:0;
    evaluations.push({...ace,attributes:[...attributes],applicable,matchedMask});
    if(ace.type==='deny'&&matchedMask){deniedMask=matchedMask;break;}
    if(ace.type==='allow')remaining&=~matchedMask;
    if(!remaining)break;
  }
  return wraFreeze({requestedMask,aces,evaluations,allowed:!deniedMask&&!remaining,deniedMask,ungrantedMask:remaining,tokenRef:token.tokenId,privilegeBypass:false});
}
function wraACEs(f,kind){
  const rule=kind==='share'?f.shareRule:kind==='file'?f.fileRule:f.endpointRule;
  if(rule==='allow-admin')return [{type:'allow',sid:wraAdminSID,mask:1}];
  if(rule==='deny-user')return [{type:'deny',sid:f.sid,mask:1},{type:'allow',sid:wraUsersSID,mask:1}];
  if(rule==='deny-admin-allow-user')return [{type:'deny',sid:wraAdminSID,mask:1},{type:'allow',sid:f.sid,mask:1}];
  if(rule==='allow-user')return [{type:'allow',sid:f.sid,mask:1}];
  throw new RangeError('Unknown resource rule '+rule);
}
function wraProfile(f,planId,caseId,subfixtureId){return wraFreeze({id:planId+'/'+caseId+'/'+subfixtureId,name:wraTitles[planId],version:'Windows 11 Enterprise 25H2 / 26200.9711 / KB5127648 reference',implementation:'Offline source-owned symbolic Windows/SMB reference; no native interoperability claim',publicationStatus:'Captured Microsoft documentation and protocol revisions',supportStatus:f.ap?'Build-qualified architectural comparison; S21 still labels Insider Preview [11.0.26100.9278], Desktop only':'Declared member-machine AP-off classic UAC reference',clientJoined:f.joined,targetRole:'member workstation, not DC',accountAuthority:f.authority,logonType:3,effectivePolicy:wraPolicy(f),credentialSource:'explicit nonblank synthetic password; desktop unchanged',assumptions:['EnableLUA1; effective settings/restart assumed, not UI-toggle runtime evidence','Enabled and nonblank account unless case explicitly changes enabled state','No blanket domain-admin full-token claim outside classic AP-off profile','Exact integrity/elevation/native privilege inventories unknown; source-only tests are not native evidence',f.ap?'S20 availability overview and S21 preview/build applicability disagreement retained':'S01 historical wording corroborated by S02/S03; no native build certification','SMB3.1.1 with explicit SHA512/AES-CMAC/AES128-GCM choices; no guest/anonymous','UAC remote policy is not interactive elevation or RDP type10 admission'],prerequisites:f.authority==='CORP'?['AD DS Server2025 capability reference; exact installed DC build unavailable','Explicit domain credential; reachable/discovered KDC, DNS and clock tolerance','cifs/target.corp.example resolves to TARGET$; secure machine channel for domain NTLM','No device/FAST claims, Protected Users or authentication-policy restrictions imposed']:['Target-local SAM verifier; NTLMv2 explicitly permitted unless selected blocked case','No domain TGT, KDC or DC validates target-local credentials'],algorithms:['SMB3.1.1 SHA512 preauthentication','SP800-108 counter HMAC-SHA256 purpose-separated keys','AES-CMAC signatures and AES128-GCM directional transforms',f.mechanism==='Kerberos'?'KILE AES mutual AP, distinct initiator/acceptor subkeys':'NTLMv2 configured challenge/response, MIC and KEY_EXCH compatibility'],transports:['SMB TCP445',...(f.authority==='CORP'?[f.mechanism==='Kerberos'?'Kerberos TCP88':'server/DC protected Netlogon machine channel']:[]),'Target policy/token/access checks are local, not OS wire'],sources:WINDOWSREMOTELAB_SOURCES,nativeEvidence:'unperformed',wmiScope:'Related source S09 separates DCOM launch/activation, namespace Remote Enable and object rights. No WMIC default or WMI protocol implementation.',completion:'Proof, target admission/context, resource decision, protected response receipt and client knowledge stay separate.'});}
const wraFieldKeys=['desktop','credential','policy','preauth-0','preauth-1','preauth-2','preauth-3','preauth-4','preauth-5','share-policy','file-policy','target-policy','target-account','prior-session','dialects','server-offer','account-verifier','netlogon-channel','ntlm-negotiate','ntlm-challenge','nt-hash','response-key','ntlm-proof','client-base-key','session-key','ntlm-authenticate','authority-base-key','sam-result','validation','dc-result','spnego-complete','client-account-key','dc-account-key','krbtgt-key','cifs-service-key','as-request','tgt','tgt-key','as-reply','tgs-request','cifs-ticket','ticket-key','tgs-reply','initiator-subkey','ap-request','target-token','session-context','signing-key','app-key','c2s-key','s2c-key','tree-request','share-access-input','tree','create-request','file-access-input','file-handle','read-request','file-data','endpoint-rule','endpoint-result','comparison-result'];
// A policy change is a new source-owned snapshot, never mutation of the token.
wraFieldKeys.push('changed-target-policy','prior-token','target-filter-input','token-comparison','endpoint-local-result','reused-session-record');
for(const stage of ['negotiate-request','negotiate-response','session-negotiate','session-challenge','session-authenticate','session-kerberos','authentication-failure','session-success','tree-request','tree-denied','tree-success','create-request','create-denied','create-success','read-request','read-success']){wraFieldKeys.push(stage+'-header');if(['authentication-failure','tree-denied','create-denied'].includes(stage))wraFieldKeys.push(stage+'-error-body');if(['create-request','create-denied','create-success','read-request','read-success'].includes(stage))wraFieldKeys.push(stage+'-transform');}
export const WINDOWSREMOTELAB_ATTRIBUTES={};
for(const planId of Object.keys(wraTitles))for(const key of wraFieldKeys){const id='wra_'+planId.slice(3)+'_'+key;WINDOWSREMOTELAB_ATTRIBUTES[id]=labAttribute(key.replace(/-/g,' '),'Source-owned remote administration object; exact selected value is constructed lazily.','Declared source/target/authority owner','Credential proof, policy, target context and resource rules are independent.','Selected case value', 'Windows / MS-SMB2 reference',wraSourceURLs.S05);}
wraFreeze(WINDOWSREMOTELAB_ATTRIBUTES);
const wraPut=(path,value)=>({op:'put',path:'workstation.'+path,value});
function wraFinish(data,{f,planId,caseId,subfixtureId,profile,policy,account}){
  const {id,artifacts,initial,events,bindings,steps,actors,definitions}=data;
  const state={...data.initialState.smb,verifierAuthority:f.authority==='TARGET'?'TARGET SAM':f.mechanism==='Kerberos'?'CORP KDC':'CORP domain DC through target machine secure channel',authenticationPackage:f.mechanism==='Kerberos'?'Kerberos / KILE':'NTLMv2 / MSV1_0',localAccount:'WORKGROUPPC\\bob',localSid:'S-1-5-21-700-800-900-1001',outboundAccount:account.principal,sourceClientElevated:f.clientElevated,sourceDesktopPreserved:true,profileAvailable:f.featureAvailable,responseReceived:false,returnedResult:null,failureStage:null,inputReleased:false,remotePrompt:false};
  const normalized=[];let firstDetector=null,finalStatus=null;
  state.admissionDecision='not-evaluated';
  state.verdictExplanation=null;
  const explainFirstDecision=(stage,step)=>{
    const status=steps.find(candidate=>candidate.smbStage==='authentication-failure')?.smbFrame.status;
    if(stage==='sam-verify'||stage==='dc-verify')return (stage==='sam-verify'?'TARGET SAM':'The CORP domain authority')+' rejected the received credential proof, so no new target session or resource grant was established.';
    if(stage==='authentication-reject')return 'The target rejected the selected NTLM mechanism under its incoming-authentication policy before establishing a new session.';
    if(stage==='target-admission')return status==='STATUS_ACCOUNT_DISABLED'?'The target rejected network logon because the resolved account is disabled, despite internal credential-proof verification.':'The target rejected network logon because its applicable network-logon rights do not admit this identity, despite internal proof verification.';
    if(stage==='applicability')return step.protocolEffects.find(effect=>effect.path==='workstation.serverDecision')?.value==='needs-evidence'?'The AP comparison needs evidence for this listed nonadmin because documented target-admin applicability establishes neither elevation nor denial.':'The declared AP feature/build profile is unavailable, so no classic-mode substitute or new target context is inferred.';
    if(stage==='share-check'||stage==='file-check'){
      const decision=artifacts.find(artifact=>artifact.key===(stage==='share-check'?'share-access-input':'file-access-input')).value;
      return 'The target denied '+(stage==='share-check'?'share connection':'file read')+' because '+(decision.deniedMask?'an applicable deny ACE matches the requested mask':'the requested mask lacks an enabled-SID allow grant')+'; the authenticated session'+(stage==='file-check'?' and admitted share':'')+' remain valid.';
    }
    if(stage==='endpoint-check')return 'The fixed management endpoint rule denied the requested operation after accepted first-hop authentication, without changing the proven identity.';
    return 'The target stopped at its first source-owned decision boundary without manufacturing downstream grants.';
  };
  const addLocal=(stage,title,actor,effects=[],puts=[],ops=[],objects=[])=>{
    const eventId=id+':'+stage;
    for(const operation of ops)operation.sourceEventId=eventId;
    const step=labStep(eventId,title,actor,actor,'Windows remote administration','internal',title,title,[...new Set(ops.map(op=>op.attributeId))],[],['Source-owned symbolic transition; not a native Windows trace.'],ops);
    Object.assign(step,{smbStage:stage,workstationStage:stage,eventType:'local',protocolLabel:'Local target/client operation',layers:[],protocolEffects:puts});
    events[eventId]={milestones:[{id:'complete',at:1,effects}]};normalized.push(step);return step;
  };
  const allEffects=event=>(event?.milestones||[]).flatMap(m=>m.effects||[]);
  const holding=(o,actor,rep,store,retention='temporary')=>({op:'acquire',artifactId:o.artifactId,actorId:actor,representationId:rep,store,retention,holdingId:[actor,o.artifactId,rep,store].join('|')});
  const opFor=(o,actor,kind,rep='plain')=>({attributeId:o.attributeId,instanceId:o.artifactId,creator:o.creator,holders:[actor],inspectors:o.representations.find(r=>r.representationId===rep).readableBy,fieldPath:'reference.'+o.key,representation:rep,value:o.representations.find(r=>r.representationId===rep).fields[0].value,sourceEventId:id+':prepare-'+o.key,exactValueRef:o.artifactId+':'+rep,kind,actorId:actor});
  const live=new Map();const apply=e=>{if(e.op==='acquire')live.set(e.holdingId,e);else if(e.op==='release')live.delete(e.holdingId);};
  const persistentSeed=new Set(['desktop','policy','share-policy','file-policy','target-policy','changed-target-policy','target-account','prior-session','prior-token','reused-session-record','account-verifier','netlogon-channel','dc-account-key','krbtgt-key','cifs-service-key','endpoint-rule','target-filter-input','token-comparison','endpoint-local-result','comparison-result']);
  const installed=new Set(['target-token','session-context','signing-key','app-key','c2s-key','s2c-key','tree','file-handle','file-data']);
  const sessionAccepted=steps.some(s=>s.smbStage==='client-session'),domainAccepted=steps.some(s=>s.smbStage==='as-accept');
  function retention(e){
    const o=artifacts.find(a=>a.artifactId===e.artifactId);if(e.op!=='acquire'||!o)return 'temporary';
    const domainCredential=domainAccepted&&['tgt','tgt-key','cifs-ticket','ticket-key','initiator-subkey'].includes(o.key)&&['smbClient','smbServer','smbDC'].includes(e.actorId);
    return (persistentSeed.has(o.key)||sessionAccepted&&(installed.has(o.key)||o.key==='session-key')||domainCredential)&&(e.representationId==='plain'||domainCredential&&['tgt','cifs-ticket'].includes(o.key)&&e.representationId==='wire')?'retained':'temporary';
  }
  for(const e of initial){if(e.op==='acquire')e.retention=retention(e);apply(e);}
  for(const step of steps){
    const stage=step.smbStage,event=events[step.id],effects=allEffects(event);
    step.workstationStage=stage;step.phase='Windows remote administration';
    step.protocolEffects=(step.protocolEffects||[]).map(e=>({...e,path:e.path.replace(/^smb\./,'workstation.')}));
    const rejected=effects.some(e=>e.op==='observe'&&String(e.result).startsWith('rejected'))||step.protocolEffects.some(e=>e.path==='workstation.detector');
    if(!firstDetector&&rejected){firstDetector=stage;step.protocolEffects.push(wraPut('failureStage',stage));}
    if(stage==='authentication-reject'){
      const frame=steps.find(s=>s.smbStage==='authentication-failure')?.smbFrame;
      if(frame){step.protocolEffects.push(wraPut('serverDecision',frame.status));if(!firstDetector){firstDetector=stage;step.protocolEffects.push(wraPut('failureStage',stage),wraPut('detector','smbServer'));}}
    }
    if(stage==='as-validate')step.protocolEffects.push(wraPut('credentialVerified',true));
    if(stage==='target-admission')step.protocolEffects.push(wraPut('admissionDecision',step.protocolEffects.find(e=>e.path==='workstation.admissionAllowed').value?'allowed':'denied'));
    if(stage==='applicability')step.protocolEffects.push(wraPut('admissionDecision',step.protocolEffects.find(e=>e.path==='workstation.serverDecision').value));
    if(stage==='share-check'&&!firstDetector&&step.protocolEffects.some(e=>e.path==='workstation.resourceAllowed'&&e.value===false)){firstDetector=stage;step.protocolEffects.push(wraPut('failureStage',stage));}
    if(stage==='read-check')step.protocolEffects.push(wraPut('resourceAllowed',true),wraPut('serverDecision','STATUS_SUCCESS'));
    if(firstDetector===stage)step.protocolEffects.push(wraPut('verdictExplanation',explainFirstDecision(stage,step)));
    if(stage==='read-accept'&&!firstDetector&&finalStatus==='STATUS_SUCCESS')step.protocolEffects.push(wraPut('verdictExplanation','The client accepted the protected read result only after credential proof, target admission, share policy and file ACL checks all allowed their separate operations.'));
    // A final SMB result has separate decision, local transmission readiness,
    // wire receipt, authenticated unwrap, and caller knowledge checkpoints.
    const terminalFrame=step.smbFrame&&['authentication-failure','tree-denied','create-denied','read-success'].includes(stage);
    if(terminalFrame){finalStatus=step.smbFrame.status;step.protocolEffects.push(wraPut('responseReceived',true));}
    if(['authentication-failure-accept','tree-denied-accept','create-denied-accept','read-accept'].includes(stage))step.protocolEffects.push(wraPut('clientKnowsResult',true),wraPut('returnedResult',finalStatus));
    if(['authentication-failure-accept','tree-denied-accept','create-denied-accept','read-accept'].includes(stage))step.protocolEffects.push(wraPut('resultDomain','SMB/NTSTATUS'));
    // Move sender construction/serialization into a prior local event. A reader
    // permission never creates a holding, and wire receipt is not decryption.
    const messages=event.messages||[],preEffects=[],preOps=[];
    for(const message of messages){
      const same=effects.filter(e=>e.op==='acquire'&&e.actorId===message.from&&message.objects.some(o=>o.artifactId===e.artifactId));
      for(const acquisition of same){const create=effects.find(e=>e.op==='create'&&e.artifactId===acquisition.artifactId);if(create&&!preEffects.includes(create))preEffects.push(create);preEffects.push(acquisition);}
      for(const carried of message.objects){
        const o=artifacts.find(a=>a.artifactId===carried.artifactId);
        const available=[...live.values(),...preEffects];
        if(!available.some(e=>e.op==='acquire'&&e.actorId===message.from&&e.artifactId===o.artifactId&&e.representationId===carried.representationId)){
          if(!available.some(e=>e.op==='acquire'&&e.actorId===message.from&&e.artifactId===o.artifactId))throw new Error('Sender lacks source object '+stage+' '+o.key);
          preEffects.push(holding(o,message.from,carried.representationId,'serialized carrier output'));
          preOps.push(opFor(o,message.from,['ciphertext','netlogon'].includes(carried.representationId)?'encrypt':'store',carried.representationId));
        }
      }
    }
    for(const operation of step.attributeOperations||[])if(['create','derive','store'].includes(operation.kind)&&preEffects.some(e=>e.op==='acquire'&&e.actorId===operation.actorId&&e.artifactId===operation.instanceId)){preOps.push(operation);}
    if(preEffects.length){
      const prep=addLocal(stage+'-prepare-transfer','Prepare sender-owned representations before transfer',messages[0].from,preEffects,[],preOps);
      for(const operation of preOps)operation.sourceEventId=prep.id;
      step.attributeOperations=step.attributeOperations.filter(op=>!preOps.includes(op));
      for(const milestone of event.milestones)milestone.effects=milestone.effects.filter(e=>!preEffects.includes(e));
      for(const e of preEffects){if(e.op==='acquire')e.retention=retention(e);apply(e);}
    }
    for(const e of allEffects(event)){if(e.op==='acquire')e.retention=retention(e);apply(e);}
    if(terminalFrame)addLocal(stage+'-transmit','Transmit the already-prepared correlated SMB result',step.from,[],[wraPut('responseTransmitted',true)]);
    normalized.push(step);
  }
  if(steps.some(s=>s.smbStage==='applicability')){
    const decision=steps.find(s=>s.smbStage==='applicability').protocolEffects.find(e=>e.path==='workstation.serverDecision').value;
    const qualification='Local lesson evaluation of declared source applicability; not a received Windows, WinRM or SMB response.';
    const resultValue={status:decision,comparisonId:id+':profile-comparison',resultDomain:'local-lesson-comparison',qualification};
    const o={artifactId:id+':comparison-result',attributeId:'wra_'+planId.slice(3)+'_comparison-result',key:'comparison-result',type:'result',creator:'smbClient',label:'Locally evaluated bounded applicability result',value:resultValue,readers:['smbClient'],store:'local lesson comparison results',representations:[{representationId:'plain',format:'local lesson symbolic result',readableBy:['smbClient'],fields:[{attributeId:'wra_'+planId.slice(3)+'_comparison-result',name:'Applicability',value:resultValue,readableBy:['smbClient']}]}]};artifacts.push(o);definitions[o.attributeId]=WINDOWSREMOTELAB_ATTRIBUTES[o.attributeId];
    const make=[{op:'create',artifactId:o.artifactId},holding(o,'smbClient','plain',o.store,'retained')];
    addLocal('applicability-result','Compute and know the local lesson applicability comparison','smbClient',make,[wraPut('localComparisonKnown',true),wraPut('resultDomain','local-lesson-comparison'),wraPut('localComparisonQualification',qualification),wraPut('clientKnowsResult',true),wraPut('returnedResult',decision)],[opFor(o,'smbClient','create')]);make.forEach(apply);
    addLocal('applicability-accept','Inspect the already-known local unavailable/needs-evidence comparison','smbClient',[],[],[opFor(o,'smbClient','verify')]);
    bindings.push({path:'smb.localComparisonKnown',artifactId:o.artifactId,actorId:'smbClient',representationId:'plain',store:o.store,presentWhen:'truthy'});
    // Source applicability is a modeled target checkpoint; the local lesson
    // comparison does not transfer its internal artifacts or report wire receipt.
    for(const s of normalized)if(s.smbStage==='applicability')s.protocolEffects=s.protocolEffects.filter(e=>!['workstation.clientKnowsResult','workstation.clientKnowsFailure'].includes(e.path));
  }
  const temporary=[...live.values()].filter(e=>e.retention==='temporary');
  const cleanupOwners=[...new Set(temporary.map(effect=>effect.actorId))];
  for(const [index,owner] of cleanupOwners.entries()){
    const owned=temporary.filter(effect=>effect.actorId===owner);
    addLocal('attempt-cleanup-'+owner,'Release owner-local scratch while retaining desktop, authority and accepted sessions',owner,owned.map(effect=>({op:'release',holdingId:effect.holdingId})),index===cleanupOwners.length-1?[wraPut('inputReleased',true)]:[],owned.map(effect=>opFor(artifacts.find(object=>object.artifactId===effect.artifactId),owner,'evict',effect.representationId)));
  }
  for(const binding of bindings)binding.path=binding.path.replace(/^smb\./,'workstation.');
  const positions={},compactPositions={};for(const [actorId,actor] of Object.entries(actors)){actor.position={...wraExpanded[actorId]};positions[actorId]=actor.position;compactPositions[actorId]={...wraCompact[actorId]};}
  const model=labScenario({id,planId,canonicalCaseId:planId+'/'+caseId,variantId:caseId,subfixtureId,title:wraTitles[planId],summary:'Separate '+account.principal+' proof, target admission/context and requested-operation authorization.',workspace:'windows',family:'windows-remote-administration',category:'Remote administration',protocol:'SMB3.1.1 / '+f.mechanism,standard:'Microsoft Windows security / MS-SMB2 88.0',source:wraSourceURLs.S01,status:'reference',initialState:wraFreeze({workstation:state}),workstationInventory:{artifacts,initial,events,bindings,reuse:[{sourceId:'accepted SMB3.1.1 authoring',authority:f.authority,mechanism:f.mechanism,origin:'source-owned protocol events, not relabelled CORP fixture',priorSessionMode:f.sessionMode}]},fixtureInputs:wraFreeze(f),profile,positions,actorPositions:positions,expandedPositions:positions,compactPositions,sourceSupportNote:'Microsoft local-account/UAC policy, access-token/SID API references and SMB3.1.1 protocol clauses support this symbolic member-machine comparison. Native Windows/DC/token/log evidence is unperformed; exact RID500 native token fields remain unknown, and Administrator protection overview availability differs from the CSP preview/build applicability label.',keywords:['remote administration','UAC','filtering','local SAM','SID','deny-only','LATFP','ADMIN$','SMB',planId],relatedLessons:[{id:'lab-welev05',title:'NewCredentials / netonly',summary:'Local desktop and deferred outbound identity are distinct.'},{id:'lab-wlog08',title:'Nonjoined client and domain credentials',summary:'Starts a separate demonstration; credentials/session state are not transferred.'},{id:'lab-win-rdp-normal',title:'Remote-interactive RDP admission',summary:'Type10 admission/elevation is not this type3 network context.'},{id:'lab-welev06',title:'Local Administrator Protection architecture',summary:'Separate local elevation identity; not necessarily the network token identity.'}]},definitions,normalized,actors);
  model.decisionBindings=[['Credential authority','verifierAuthority'],['Credential proof verified','credentialVerified'],['Target admission established','admissionAllowed'],['Admission decision / applicability','admissionDecision'],['Target context','token.mode'],['Operation allowed','resourceAllowed'],['Server decision','serverDecision'],['Result transmitted','responseTransmitted'],['Client receipt','responseReceived'],['Client knows result','clientKnowsResult'],['Returned result','returnedResult'],['First detecting boundary','failureStage'],['Prior session retained','priorSession'],['Source desktop identity','localAccount']].map(([label,path])=>({label,path:'workstation.'+path}));
  model.decisionBindings.push({label:'First-decision explanation',path:'workstation.verdictExplanation'},{label:'Token policy comparison',path:'workstation.tokenComparison'},{label:'Configured versus applied remote policy',path:'workstation.policyComparison'});
  model.decisionBindings.find(binding=>binding.path==='workstation.responseTransmitted').label='Operation wire response transmitted';
  model.decisionBindings.find(binding=>binding.path==='workstation.responseReceived').label='Operation wire response received';
  model.decisionBindings.push({label:'Local lesson comparison known',path:'workstation.localComparisonKnown'},{label:'Result domain',path:'workstation.resultDomain'},{label:'Local comparison qualification',path:'workstation.localComparisonQualification'});
  return wraSeal(model,planId,caseId);
}
function wraSeal(model,planId,caseId){
  const entries=wraCaseInputs.filter(row=>row.planId===planId),pairs=wraPairs[planId+'/'+caseId]||[{id:'default',changes:{}}];
  model.defaultVariantId=entries[0].caseId;model.variantChoices=entries.map(row=>({id:row.caseId,label:row.caseId.replace(/-/g,' ')}));
  model.defaultSubfixtureId=pairs[0].id;model.subfixtureChoices=pairs.map(row=>({id:row.id,label:row.id.replace(/-/g,' ')}));
  model.withVariant=id=>buildWindowsRemoteAdministrationFixture(model.id,id);model.withSubfixture=id=>buildWindowsRemoteAdministrationFixture(model.id,caseId,id);
  model.catalogAttributeIds=wraFieldKeys.map(key=>'wra_'+planId.slice(3)+'_'+key);return model;
}
export function buildWindowsRemoteAdministrationFixture(modelId,caseId='default',subfixtureId='default'){
  const planId=modelId.replace(/^lab-/,'').toUpperCase();if(!Object.hasOwn(wraTitles,planId))throw new RangeError('Unknown remote administration model '+modelId);
  const entries=wraCaseInputs.filter(row=>row.planId===planId);if(caseId==='default')caseId=entries[0].caseId;
  const row=entries.find(entry=>entry.caseId===caseId);if(!row)throw new RangeError('Unknown '+planId+' case '+caseId);
  const pairs=wraPairs[planId+'/'+caseId]||[{id:'default',changes:{}}];if(subfixtureId==='default')subfixtureId=pairs[0].id;
  const pair=pairs.find(entry=>entry.id===subfixtureId);if(!pair)throw new RangeError('Unknown '+planId+'/'+caseId+' subfixture '+subfixtureId);
  return wraConstruct({...wraBase,...row.changes,...pair.changes},{modelId,planId,caseId,subfixtureId});
}
// Accepted source carrier for protection lessons that need an actual local SAM
// network operation without changing this module's canonical case denominator.
export function buildWindowsRemoteSmbReference(inputs={}){
  return wraConstruct({...wraBase,...inputs},{modelId:'wra-sam-source-reference',planId:'WRA01',caseId:'source-reference',subfixtureId:'default'},true);
}
function wraConstruct(f,{modelId,planId,caseId,subfixtureId},raw=false){
  f.sid='S-1-5-21-'+(f.authority==='TARGET'?'110-220-330':'440-550-660')+'-'+f.rid;
  if(f.enableLua!==1||f.authority==='TARGET'&&f.mechanism!=='NTLMv2')throw new RangeError('Unsupported declared remote profile');
  const account=wraAccount(f),policy=wraPolicy(f),profile=wraProfile(f,planId,caseId,subfixtureId);
  const contextPolicy=f.sessionMode==='reuse'?wraPolicy({...f,latfp:0}):policy;
  const priorSession=f.sessionMode==='prior-session-denial'?{sessionId:'prior-session-0',owner:'smbServer',account:account.principal,token:evaluateWindowsRemoteContext(account,wraPolicy({...f,latfp:0}),'prior-context-0'),provenance:'independent previously accepted logon; current failed proof cannot revoke it'}:null;
  const verifierValue='HANDLE('+f.authority+':'+account.principal+':NTOWFv2:password-fixture-A)';
  const candidateVerifier=f.passwordMatches?verifierValue:'HANDLE('+f.authority+':'+account.principal+':NTOWFv2:password-fixture-B)';
  // These are symbolic equations, not computed HMAC bytes. The verifier uses
  // its own source-owned record and the received challenge, never a case name
  // or the candidate's validity Boolean to decide whether a proof matches.
  const ntlmProof=(verifier,challenge)=>'SYM(NTProofStr=HMAC-MD5(ResponseKeyNT, ServerChallenge || NTLMv2_CLIENT_CHALLENGE); ResponseKeyNT='+verifier+'; ServerChallenge=8-byte ServerChallenge field of the selected CHALLENGE_MESSAGE; selected challenge binding='+challenge+'; NTLMv2_CLIENT_CHALLENGE contains timestamp, client challenge, target AV pairs with the MsvAvFlags MIC-presence bit, and terminators; AUTHENTICATE_MESSAGE.MIC is a separate transcript MIC, not client-challenge bytes)';
  return buildSmbAccessReference({
    id:modelId,fieldPrefix:'wra_'+(raw?'source':planId.slice(3))+'_',suffix:'remote-'+planId.toLowerCase(),title:wraTitles[planId],summary:'Source-owned remote administration reference',
    kerberos:f.mechanism==='Kerberos',failure:!f.ntlmAllowed?'blocked':!f.passwordMatches?'password':undefined,
    remote:{
      inputs:f,principal:account.principal,authority:f.authority,account,policy,originalPolicy:contextPolicy,priorSession,
      verifierValue,createNtlmProof:challenge=>ntlmProof(candidateVerifier,challenge),
      verifyNtlmProof:(proof,challenge,verifier)=>proof.value===ntlmProof(verifier.value,challenge.value),
      resourceRules:Object.fromEntries(['share','file','endpoint'].map(kind=>[kind,{resource:kind==='endpoint'?f.endpoint:f.resource,requestedMask:1,aces:wraACEs(f,kind)}])),
      applicability:afterProof=>!f.featureAvailable?{supported:false,result:'unavailable-profile',reason:'Declared feature/build/effective configuration unsupported; no classic-mode substitution'}:afterProof&&f.ap&&!f.admin?{supported:false,result:'needs-evidence',reason:'Listed nonadmin is outside documented target-admin applicability. Infer neither membership grant nor definite denial/elevation.'}:{supported:true},
      admit:()=>wraAdmission(account,policy),context:()=>evaluateWindowsRemoteContext(account,contextPolicy,modelId+':target-context'),
      describePolicy:wraReadablePolicy,compareTokens:(after,refs)=>wraTokenComparison(account,contextPolicy,after,refs),
      access:(token,kind)=>evaluateWindowsRemoteAccess(token,1,wraACEs(f,kind)),
      finish:data=>raw?labScenario({id:modelId,initialState:data.initialState,smbInventory:{artifacts:data.artifacts,initial:data.initial,events:data.events,bindings:data.bindings}},data.definitions,data.steps,data.actors):wraFinish(data,{f,planId,caseId,subfixtureId,profile,policy,account})
    }
  });
}
// Cheap catalog descriptors. No protocol steps, source hydration or variant
// cross-product is constructed until a selected model is actually requested.
export const WINDOWSREMOTELAB_SCENARIOS=Object.keys(wraTitles).map(planId=>{
  const entries=wraCaseInputs.filter(row=>row.planId===planId),id='lab-'+planId.toLowerCase(),defaultVariantId=entries[0].caseId;
  let selected;const get=()=>selected||(selected=buildWindowsRemoteAdministrationFixture(id));
  const descriptor={id,planId,title:wraTitles[planId],summary:'Identity proof, target policy, local authorization context and requested-operation decisions.',workspace:'windows',family:'windows-remote-administration',category:'Remote administration',protocol:'Windows security / SMB3.1.1',status:'reference',universalLab:true,factorSelectable:false,jweAdaptable:false,variantId:defaultVariantId,defaultVariantId,variantChoices:entries.map(row=>({id:row.caseId,label:row.caseId.replace(/-/g,' ')})),catalogAttributeIds:wraFieldKeys.map(key=>'wra_'+planId.slice(3)+'_'+key),keywords:['UAC','remote administration','filtering','SAM','SID','LATFP',planId],withVariant:caseId=>buildWindowsRemoteAdministrationFixture(id,caseId),withSubfixture:subfixtureId=>buildWindowsRemoteAdministrationFixture(id,defaultVariantId,subfixtureId),steps:()=>get().steps(),actors:()=>get().actors(),definitions:()=>Object.fromEntries(wraFieldKeys.map(key=>{const field='wra_'+planId.slice(3)+'_'+key;return [field,WINDOWSREMOTELAB_ATTRIBUTES[field]];})),examples:()=>get().examples()};
  descriptor.ids=descriptor.catalogAttributeIds;
  for(const key of ['initialState','workstationInventory','profile','fixtureInputs','positions','actorPositions','compactPositions','expandedPositions','decisionBindings','sourceSupportNote','subfixtureChoices','defaultSubfixtureId','canonicalCaseId','subfixtureId','relatedLessons'])Object.defineProperty(descriptor,key,{enumerable:true,get:()=>get()[key]});
  return descriptor;
});
