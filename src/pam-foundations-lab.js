import {unixWsAuthor,unixWsFreeze,unixWsDeclareCatalog} from './linux-logon-lab.js';
import {PAM_CONFIGURATIONS} from './pam-configurations.js';
import {PAM_API_PHASES,pamEvaluate,pamApiBoundary} from './pam-stack-evaluator.js';
import {PAM_UNIX_STATE_PATHS} from './pam-existing-integration.js';

export const PAMFOUNDATIONSLAB_ATTRIBUTES={};
export const PAMFOUNDATIONSLAB_SOURCES=[{name:'Pinned Linux-PAM configuration, dispatcher and application lifecycle',url:'https://github.com/linux-pam/linux-pam/tree/584ef2275254016ee68126f90dab6df3604124b9',revision:'584ef2275254016ee68126f90dab6df3604124b9',section:'Linux-PAM configuration controls, module dispatcher, application API and module phases',retrieved:'2026-10-25',sourceRowId:'next-unix-PAMFOUNDATIONS',snapshot:'docs/pam-foundations/sources.json',errata:'Source-pinned documentation-backed symbolic fixture. Installed library/module builds and distribution defaults are not implied.'}];
const pamCaseIds=['local-login-success','required-deferred-failure','requisite-immediate-failure','sufficient-early-success','sufficient-after-failure','sufficient-failure-fallback','optional-nondecisive','optional-only-success','optional-only-failure','bracket-success-jump','bracket-default-denial','include-termination','substack-termination','substack-failure','substack-jump-boundary','account-denied','password-change-required','session-failure','module-unavailable','conversation-failure','soft-hard-limits','service-selection'];
export const PAM_SUBFIXTURES=unixWsFreeze({'substack-jump-boundary':['parent-jump','child-in-range','child-overrun'],'password-change-required':['change-success','change-unsupported','change-prelim-failure','change-update-failure'],'soft-hard-limits':['limits-success','limits-application-error'],'service-selection':['service-login','service-deny']});
const pamChoices=unixWsFreeze(pamCaseIds.map(id=>({id,label:id.replaceAll('-',' '),description:'Pinned configuration-driven '+id.replaceAll('-',' ')})));
const pamApiLabel=(name,flags=PAM_API_PHASES[name].flags)=>{const descriptor=PAM_API_PHASES[name];return descriptor.api+'()'+(descriptor.internal?' '+flags+' dispatch':'');};
const pamDecisionBindings=unixWsFreeze([{label:'Authentication aggregate',path:'workstation.pamResults.authenticate'},{label:'Account aggregate',path:'workstation.pamResults.account'},{label:'Password-change API aggregate',path:'workstation.pamResults.password'},{label:'Session setup aggregate',path:'workstation.pamResults.open'},{label:'Authenticated identity',path:'workstation.authenticatedIdentity'},{label:'Caller decision',path:'workstation.callerDecision'},{label:'Admission',path:'workstation.admitted'},{label:'Session active',path:'workstation.session'},{label:'Credential-phase bookkeeping active',path:'workstation.moduleCredentials'},{label:'Partial session cleanup pending',path:'workstation.partialSessionResources'}]);
const pamBaseKeys=['configuration','identity','authority-g2','transaction','conversation','conversation-result','new-secret','module-credentials','session','partial-session','limits','caller-identity','decision'];
const pamSchemaKeys=[...pamBaseKeys];
for(const phase of ['start','authenticate','account','password','prelim','update','setcred','open','close','end'])for(const flags of phase==='setcred'?['default','delete']:['default'])pamSchemaKeys.push('call-'+phase+'-'+flags+'-control','aggregate-'+phase+'-'+flags);
const pamModelConfigurationIds=new Set(['afs-login','afs-deny','afs-child','afs-child-fail','afs-child-range','afs-child-overrun','afs-child-in-range','afs-parent-child-overrun',...pamCaseIds.map(id=>'afs-'+id)]);
for(const config of Object.values(PAM_CONFIGURATIONS)){
  if(!pamModelConfigurationIds.has(config.id))continue;
  for(const [index,line] of config.text.split('\n').entries()){
    const type=/^(auth|account|password|session)\s/.exec(line)?.[1];
    const phases={auth:['authenticate','setcred'],account:['account'],password:['prelim','update'],session:['open','close']}[type]||[];
    for(const phase of phases)for(const flags of phase==='setcred'?['default','delete']:['default'])pamSchemaKeys.push('evaluation-'+phase+'-'+config.id+'-'+(index+1)+'-'+flags);
  }
}
unixWsDeclareCatalog(PAMFOUNDATIONSLAB_ATTRIBUTES,{'lab-pam01':pamSchemaKeys},PAMFOUNDATIONSLAB_SOURCES);
export function createPamFoundationsCase(caseId='local-login-success',subfixtureId=null){
  if(caseId==='default')caseId=pamCaseIds[0];
  if(!pamCaseIds.includes(caseId))throw new RangeError('Unknown PAM case '+caseId);
  const subs=PAM_SUBFIXTURES[caseId]||[];
  if(subfixtureId!==null&&!subs.includes(subfixtureId))throw new RangeError('Unknown PAM subfixture '+subfixtureId);
  const sub=subfixtureId||subs[0]||null;
  const passwordCallerFlags=caseId==='password-change-required'?'PAM_CHANGE_EXPIRED_AUTHTOK':0;
  const pamCallerFlags=(name,flags)=>name==='password'?passwordCallerFlags:flags==='delete'?PAM_API_PHASES[name].cleanupFlags:PAM_API_PHASES[name].flags;
  let service=Object.hasOwn(PAM_CONFIGURATIONS,'afs-'+caseId)?'afs-'+caseId:'afs-login';
  if(sub==='child-in-range'||sub==='child-overrun')service='afs-'+sub;
  if(sub==='child-overrun')service='afs-parent-child-overrun';
  if(sub==='service-deny')service='afs-deny';
  const selectedFiles=new Set([service]);
  const includeTree=[];
  function includeFiles(id){for(const line of PAM_CONFIGURATIONS[id].text.split('\n')){const child=/^(?:auth|account|password|session)\s+(include|substack)\s+(\S+)/.exec(line);if(child){includeTree.push({parent:id,child:child[2],type:child[1]});if(!selectedFiles.has(child[2])){selectedFiles.add(child[2]);includeFiles(child[2]);}}}}
  includeFiles(service);if(PAM_CONFIGURATIONS[service].text.includes('pam_limits.so'))selectedFiles.add('limits.conf');
  const configuration={service,revision:PAMFOUNDATIONSLAB_SOURCES[0].revision,files:[...selectedFiles].map(id=>PAM_CONFIGURATIONS[id]),includeTree};
  if(caseId==='requisite-immediate-failure'||caseId==='sufficient-after-failure')configuration.comparison={from:'afs-sufficient-after-failure',to:'afs-requisite-immediate-failure',changedLines:[{line:2,before:'auth required pam_debug.so auth=auth_err',after:'auth requisite pam_debug.so auth=auth_err'}],unchanged:'Every other physical row is byte-identical.'};
  const A='pamCaller',P='pamLib',M='pamModule';
  const w=unixWsAuthor({id:'lab-pam01',title:'Linux-PAM: read configuration and follow the decision',family:'linux-logon',topic:'PAM configuration',pamConfiguration:configuration,startingSummary:['Selected service '+service+'; local labuser uid1000.','PAM dispatch is local; debug hooks simulate module results for learning control flow.','Independent authentication, account and session decisions; unrelated session retained.'],prerequisites:['Linux-PAM commit '+configuration.revision+'; authored /etc/pam.d fixtures, not distro defaults.','pam_setcred installs module credentials only; caller owns UID/GID/groups.'],relatedLessons:[{id:'lab-llog01',title:'Local login through PAM',summary:'Separate local sign-in fixture; no state transfer.'}]},PAMFOUNDATIONSLAB_ATTRIBUTES,PAMFOUNDATIONSLAB_SOURCES,{[A]:'Calling login application',[P]:'libpam dispatcher',[M]:'Selected module and local backend'},{localIdentity:'uid1000',identityResolved:true});
  const cfg=w.object('configuration','Selected physical PAM configuration','configuration',P,JSON.stringify(configuration),[P,A],{seed:true});
  Object.assign(w.state.workstation,{moduleCredentials:false,partialSessionResources:false,processActive:false,authorityGeneration:1,passwordChanged:false,callerDecision:'not evaluated',pamResults:Object.fromEntries(['authenticate','account','password','setcred','open','close','setcred-delete','end'].map(phase=>[phase,'not evaluated']))});
  const authority=w.object('identity','Local account/verifier authority generation1','credential-authority-state',M,'labuser uid1000 gid1000; opaque local verifier generation1',[M],{seed:true,generation:1});
  const tx=w.object('transaction','PAM transaction handle','transaction',P,'HANDLE('+service+' labuser conversation callback; opaque application reference)',[P,A]);
  const secret=w.object('conversation','Redacted conversation response','secret',A,'OPAQUE(input; never production credential)',[A,P],{store:'conversation transient'});
  let serial=0;
  function boundary(title,phase,puts={},made=[],drop=[]){const actor=phase==='caller'||phase==='limits'?A:P;const step=w.event('api-'+serial++,title,actor,actor,actor===P?[cfg]:[],{puts,made,drop});step.pamEvaluation=pamApiBoundary(service,phase,title,{callerFlags:passwordCallerFlags});return step;}
  function call(title,name,flags='default',lastStatus=null){const apiFlags=pamCallerFlags(name,flags),step=w.event('call-'+name+'-'+flags,title,A,P,[],{control:{label:'Local PAM API arguments',value:JSON.stringify({service,user:'labuser',api:PAM_API_PHASES[name].api,flags:apiFlags,transaction:name==='start'?null:'opaque pamh reference',conversation:'application callback',...(name==='end'?{pamStatus:lastStatus}:{})})}});step.pamEvaluation={...pamApiBoundary(service,name,title),flags:apiFlags};}
  function returned(name,status,flags='default'){const apiFlags=pamCallerFlags(name,flags),result=w.object('aggregate-'+name+'-'+flags,'PAM API aggregate return','pam-aggregate',P,JSON.stringify({api:PAM_API_PHASES[name].api,status,service,flags:apiFlags}),[P,A]);const step=w.event('return-'+name+'-'+flags,name+' returns '+status+' to the caller',P,A,[result],{made:[result],puts:{['pamResults.'+name+(flags==='delete'?'-delete':'')]:status}});step.pamEvaluation={...pamApiBoundary(service,name,'Local API return; aggregate is not a module status'),flags:apiFlags,aggregateReturn:status};step.pamAggregate=status;return result;}
  if(caseId==='requisite-immediate-failure')boundary('Configuration diff, line 2 only: required -> requisite; compare sufficient-after-failure','configuration');
  call('pam_start selects service and registers the application conversation','start');
  const started=w.event('start-result','pam_start returns opaque transaction handle',P,A,[tx],{made:[tx],puts:{transactionStarted:true}});started.pamEvaluation=pamApiBoundary(service,'start','Initialization returns handle; no module hook');
  const convError=caseId==='conversation-failure';
  const needsConversation=PAM_CONFIGURATIONS[service].text.split('\n').some(line=>/^auth\s/.test(line)&&line.includes('pam_unix.so'));
  function converse(){
    if(!needsConversation){boundary('No credential prompt is required; pam_debug informational callbacks are not credential proof','authenticate',{conversationStatus:'no credential prompt'});return;}
    const conversation=w.object('conversation-result','Caller conversation callback result','conversation-status',A,convError?'PAM_CONV_ERR; no input supplied':'PAM_SUCCESS; opaque input supplied',[A,P]);
    const payload=convError?[conversation]:[conversation,secret];
    const step=w.event('conversation-response',convError?'Caller callback returns PAM_CONV_ERR':'Caller callback returns an opaque response to the requesting module',A,P,payload,{made:payload,puts:{conversationStatus:convError?'PAM_CONV_ERR':'PAM_SUCCESS'}});step.pamEvaluation=pamApiBoundary(service,'conversation','Callback result, not a module return');
  }
  const inputs={};
  for(const phase of ['authenticate','setcred','account','prelim','update','open','close'])inputs['pam_unix.so:'+phase]='PAM_SUCCESS';
  inputs['pam_limits.so:open']='PAM_SUCCESS';inputs['pam_limits.so:close']='PAM_SUCCESS';
  if(caseId==='account-denied')inputs['pam_unix.so:account']='PAM_ACCT_EXPIRED';
  if(caseId==='password-change-required')inputs['pam_unix.so:account']='PAM_NEW_AUTHTOK_REQD';
  if(caseId==='session-failure')inputs['pam_limits.so:open']='PAM_PERM_DENIED';
  if(sub==='limits-application-error')inputs['pam_limits.so:open']='PAM_PERM_DENIED';
  if(convError)inputs['pam_unix.so:authenticate']='PAM_AUTHTOK_ERR';
  if(sub==='change-prelim-failure')inputs['pam_unix.so:prelim']='PAM_AUTHTOK_ERR';
  if(sub==='change-update-failure')inputs['pam_unix.so:update']='PAM_AUTHTOK_ERR';
  const evaluations={};let authCache={},openCache={},candidate=null;
  function phase(name,flags='default'){
    const evaluation=pamEvaluate(service,name,{inputs,cache:name==='setcred'?authCache:name==='close'?openCache:{},callerFlags:passwordCallerFlags});
    if(!PAM_API_PHASES[name].internal)evaluation.flags=pamCallerFlags(name,flags);
    const api=pamApiLabel(name,evaluation.flags);
    if(name==='prelim'||name==='update')boundary('Libpam internally dispatches '+api,name);
    else call('Application calls '+api+(name==='setcred'?(flags==='delete'?' PAM_DELETE_CRED':' PAM_ESTABLISH_CRED'):''),name,flags);
    if(name==='authenticate')converse();
    evaluations[name+(flags==='delete'?'-delete':'')]=evaluation;
    for(const row of evaluation.trace){
      row.flags=evaluation.flags;
      if(row.module==='pam_limits.so'&&name==='open'){const limits=PAM_CONFIGURATIONS['limits.conf'];row.resourceConfiguration={configurationId:limits.id,configurationHash:limits.sha256,file:limits.file,rows:limits.text.trimEnd().split('\n').map((text,index)=>({line:index+1,text})),applicationResult:row.rawReturn==='PAM_SUCCESS'?'applied':'not applied; session setup denied'};}
      if(row.executed&&row.module==='pam_unix.so'&&name==='update'&&row.rawReturn==='PAM_SUCCESS'){
        const committed=w.object('authority-g2','Local verifier authority generation2','credential-authority-state',M,'labuser opaque local verifier generation2; committed only after collected candidate passes selected update',[M],{generation:2});committed.replaces=[authority.artifactId];
        const commit=w.event('password-authority-commit','Selected privileged password module atomically commits local authority generation2',P,P,[candidate],{made:[committed],drop:[{object:authority,actor:M}],checks:[{object:candidate,actor:P,result:'collected candidate accepted; selected local write succeeds'}],puts:{authorityGeneration:2,passwordChanged:true}});commit.pamEvaluation=pamApiBoundary(service,'password','Authority commit is a local backend effect, not a second PAM hook',{callerFlags:passwordCallerFlags});
      }
      const key='evaluation-'+name+'-'+row.configurationId+'-'+row.line+'-'+flags,record=w.object(key,'PAM '+name+' '+row.file+':'+row.line,'pam-return',P,JSON.stringify(row),[P,A]);
      const proofInput=row.executed&&row.module==='pam_unix.so'&&name==='authenticate'&&needsConversation&&!convError;
      const tokenInput=row.executed&&row.module==='pam_unix.so'&&name==='update'&&candidate;
      const step=w.event(key,(row.executed?'Evaluate ':'Skip ')+row.file+':'+row.line+' '+row.control+' '+row.module,P,P,[cfg,...(proofInput?[secret]:[]),...(tokenInput?[candidate]:[])],{made:[record],checks:[...(proofInput?[{object:secret,actor:P,result:'Selected opaque local backend returns '+row.rawReturn}]:[]),...(tokenInput?[{object:candidate,actor:P,result:'Selected token update returns '+row.rawReturn}]:[])],puts:{pamEvaluation:row}});step.pamEvaluation=row;
    }
    if(name==='authenticate')authCache=evaluation.cache;if(name==='open')openCache=evaluation.cache;
    if(name==='prelim'||name==='update')boundary(api+' internal dispatch returns '+evaluation.status,name,{['pamResults.'+name]:evaluation.status});
    else returned(name,evaluation.status,flags);
    return evaluation.status;
  }
  const auth=phase('authenticate');let admitted=false,credentials=false,opened=false;
  boundary('Caller records authentication independently','caller',{authenticated:auth==='PAM_SUCCESS',authenticatedIdentity:auth==='PAM_SUCCESS'?'labuser':null,clientKnowsAuthentication:auth==='PAM_SUCCESS'});
  let status=auth;
  if(auth==='PAM_SUCCESS'){
    status=phase('account');
    if(status==='PAM_NEW_AUTHTOK_REQD'){
      if(sub==='change-unsupported')boundary('Caller does not support token change; service denied','password-change',{failure:'required token change unsupported'});
      else{
        call('Caller invokes pam_chauthtok(PAM_CHANGE_EXPIRED_AUTHTOK)','password');
        status=phase('prelim');
        if(status==='PAM_SUCCESS'){
          candidate=w.object('new-secret','Collected redacted new authentication token','secret',A,'OPAQUE(new local password candidate; collected before update validation)',[A,P],{store:'conversation transient'});
          const collected=w.event('password-candidate','Application callback collects new token before update validation',A,P,[candidate],{made:[candidate]});collected.pamEvaluation=pamApiBoundary(service,'password','Conversation input is not a token-update result',{callerFlags:passwordCallerFlags});
          status=phase('update');
        }
        returned('password',status);
      }
    }
    if(status==='PAM_SUCCESS'){
      boundary('Caller prepares default groups independently before pam_setcred','caller',{defaultGroupsPrepared:true});
      status=phase('setcred');credentials=status==='PAM_SUCCESS';
      if(credentials){
        const cred=w.object('module-credentials','Successful setcred lifecycle record','pam-credential-lifecycle',P,'PAM_SUCCESS lifecycle record; selected pam_unix/debug/permit hooks may create no credentials; not a native handle, ticket, UID, GID or default groups',[P]);boundary('Record successful credential phase without inventing process credentials','setcred',{moduleCredentials:true},[cred]);
        w.bindings.push({path:'workstation.moduleCredentials',artifactId:cred.artifactId,actorId:P,representationId:'plain',store:cred.store,presentWhen:'truthy'});
        const partial=w.object('partial-session','Attempt-local session setup bookkeeping','session-preparation',P,'Track partially executed hooks for applicable close_session cleanup; not a granted session or native resource handle',[P]);boundary('Track attempt-local session setup for partial cleanup','open',{partialSessionResources:true},[partial]);
        w.bindings.push({path:'workstation.partialSessionResources',artifactId:partial.artifactId,actorId:P,representationId:'plain',store:partial.store,presentWhen:'truthy'});
        status=phase('open');opened=status==='PAM_SUCCESS';
        if(opened){
          admitted=true;const session=w.object('session','Admitted session','session',A,'HANDLE(labuser '+service+' session)',[A]);
          const process=w.object('caller-identity','Caller-installed process UID/GID/groups','process-credential',A,'HANDLE(uid1000 gid1000 groups1000; application installation, not pam_setcred)',[A]);
          w.bindings.push({path:'workstation.session',artifactId:session.artifactId,actorId:A,representationId:'plain',store:session.store,presentWhen:'truthy'},{path:'workstation.processActive',artifactId:process.artifactId,actorId:A,representationId:'plain',store:process.store,presentWhen:'truthy'});
          boundary('Caller separately installs GID and UID; launches admitted service','caller',{admitted:true,session:true,sessionWasCreated:true,processActive:true,callerDecision:'launch',processIdentity:'uid1000;gid1000;groups1000'},[session,process]);
          if(service==='afs-login'){
            const limits=Object.fromEntries(PAM_CONFIGURATIONS['limits.conf'].text.trim().split('\n').map(line=>{const [,type,,value]=line.split(/\s+/);return [type,Number(value)];}));
            const limit=w.object('limits','Applied nofile soft/hard resource settings','resource-limit',A,JSON.stringify({...limits,source:'limits.conf',control:'required controls PAM return, not resource hardness'}),[A]);boundary('Resource fixture applies soft'+limits.soft+'/hard'+limits.hard+'; soft is enforced','limits',{limits},[limit]);
          }
          phase('close');boundary('Caller releases this session and process only','caller',{session:false,processActive:false},[],[{object:session,actor:A},{object:process,actor:A}]);
        }else{
          boundary('Open-session failure: no service; close applicable partial session resources','cleanup',{failure:status,session:false});phase('close');
        }
        boundary('Release attempt-local session setup resources','cleanup',{partialSessionResources:false},[],[{object:partial,actor:P}]);
        phase('setcred','delete');boundary('pam_setcred DELETE_CRED releases module credentials','delete-credentials',{moduleCredentials:false},[],[{object:cred,actor:P}]);
      }
    }
  }
  const callerDecision=admitted?'launch':sub==='change-unsupported'?'deny: required token change unsupported':'deny: '+status;
  if(!admitted)boundary('Caller denies launch without erasing valid authentication','caller',{admitted:false,failure:status,clientKnowsFailure:true,callerDecision});
  const decision=w.object('decision','Caller final launch decision','caller-decision',A,JSON.stringify({auth,admitted,status,callerDecision,unrelatedSession:'retained'}),[A]);boundary('Caller retains independent proof, admission and launch result','caller',{callerDecision},[decision]);
  call('Caller invokes pam_end after applicable session and credential teardown','end','default',status);
  boundary('pam_end releases transaction; caller clears conversation; unrelated session retained','end',{transactionEnded:true},[],[{object:tx,actor:P},{object:tx,actor:A,store:'local IPC inbox'},...(needsConversation&&!convError?[{object:secret,actor:A},{object:secret,actor:P,store:'local IPC inbox'}]:[]),...(candidate?[{object:candidate,actor:A},{object:candidate,actor:P,store:'local IPC inbox'}]:[])]);
  returned('end','PAM_SUCCESS');
  for(const step of w.steps)if(!step.pamEvaluation)step.pamEvaluation=pamApiBoundary(service,'caller','Sender-local preparation or local API transport; no module hook');
  const comparisons=[{id:'lab-pam01',variantId:'sufficient-after-failure',title:'Why continue after failure?',summary:'Required failure is remembered; later successful rows still execute in this independent case.'},{id:'lab-pam01',variantId:'requisite-immediate-failure',title:'Change only required to requisite',summary:'The same module outcomes stop at line 2; inspect the exact one-line configuration diff.'}];
  const model=w.finish();return unixWsFreeze({...model,pamStatePaths:PAM_UNIX_STATE_PATHS,decisionBindings:pamDecisionBindings,relatedLessons:[...model.relatedLessons,...comparisons],profileId:'afs-linux-pam-pinned',profile:{...model.profile,version:configuration.revision,revision:configuration.revision,configurationId:service},fixture:{caseId,subfixtureId:sub,service,user:'labuser',moduleInputs:inputs,evidence:'Symbolic selected backend inputs; not installed PAM observations'},planId:'PAM01',canonicalCaseId:'PAM01/'+caseId,variantId:caseId,defaultVariantId:pamCaseIds[0],variantChoices:pamChoices,subfixtureId:sub,defaultSubfixtureId:subs[0]||null,subfixtureChoices:subs.map(id=>({id,label:id.replaceAll('-',' ')})),withVariant:id=>createPamFoundationsCase(id),withSubfixture:id=>createPamFoundationsCase(caseId,id),pamConfiguration:configuration,pamEvaluations:evaluations,pamOutcome:{auth,admitted,status,callerDecision,credentialsEstablished:credentials,sessionOpened:opened}});
}
export const PAMFOUNDATIONSLAB_SCENARIOS=[createPamFoundationsCase()];
