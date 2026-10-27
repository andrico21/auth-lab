import {PAM_CONFIGURATIONS} from './pam-configurations.js';

export const PAM_API_PHASES=Object.freeze(Object.fromEntries(Object.entries({
  start:{type:null,api:'pam_start',hook:null,flags:null,label:'Transaction initialization'},
  authenticate:{type:'auth',api:'pam_authenticate',hook:'pam_sm_authenticate',flags:0,label:'Authentication',dispatch:true,debugArgument:'auth'},
  account:{type:'account',api:'pam_acct_mgmt',hook:'pam_sm_acct_mgmt',flags:0,label:'Account admission',dispatch:true,debugArgument:'acct'},
  password:{type:'password',api:'pam_chauthtok',hook:null,flags:0,label:'Required token change'},
  prelim:{type:'password',api:'pam_chauthtok',hook:'pam_sm_chauthtok',flags:'PAM_PRELIM_CHECK',label:'Preliminary token check',dispatch:true,internal:true,debugArgument:'prechauthtok'},
  update:{type:'password',api:'pam_chauthtok',hook:'pam_sm_chauthtok',flags:'PAM_UPDATE_AUTHTOK',label:'Token update',dispatch:true,internal:true,debugArgument:'chauthtok'},
  setcred:{type:'auth',api:'pam_setcred',hook:'pam_sm_setcred',flags:'PAM_ESTABLISH_CRED',cleanupFlags:'PAM_DELETE_CRED',label:'Module credential lifecycle',dispatch:true,useCachedChain:true,debugArgument:'cred'},
  open:{type:'session',api:'pam_open_session',hook:'pam_sm_open_session',flags:0,label:'Session setup',dispatch:true,debugArgument:'open_session'},
  close:{type:'session',api:'pam_close_session',hook:'pam_sm_close_session',flags:0,label:'Session teardown',dispatch:true,useCachedChain:true,debugArgument:'close_session'},
  end:{type:null,api:'pam_end',hook:null,flags:null,label:'Transaction cleanup'},
  conversation:{type:null,api:null,hook:null,flags:null,label:'Application conversation callback'},
  caller:{type:null,api:null,hook:null,flags:null,label:'Caller operation or decision'},
  configuration:{type:null,api:null,hook:null,flags:null,label:'Configuration comparison'},
  limits:{type:'session',api:null,hook:null,flags:null,label:'Observed resource limits'},
  cleanup:{type:'session',api:null,hook:null,flags:null,label:'Partial local resource cleanup'},
  'password-change':{type:'password',api:null,hook:null,flags:null,label:'Caller token-change capability'},
  'delete-credentials':{type:'auth',api:'pam_setcred',hook:null,flags:'PAM_DELETE_CRED',label:'Credential-phase bookkeeping cleanup'}
}).map(([id,descriptor])=>[id,Object.freeze(descriptor)])));
export function pamParseConfiguration(id,phase,ancestors=[]){
  const descriptor=PAM_API_PHASES[phase];if(!descriptor?.dispatch)throw new RangeError('Unsupported PAM dispatch phase '+phase);
  if(!Object.hasOwn(PAM_CONFIGURATIONS,id)||ancestors.includes(id))throw new RangeError('Unsupported or recursive PAM configuration: '+id);
  const c=PAM_CONFIGURATIONS[id],items=[];
  for(const [index,raw] of c.text.split('\n').entries()){
    const text=raw.trim();if(!text||text.startsWith('#'))continue;
    const match=/^(auth|account|password|session)\s+(\[[^\]]+\]|required|requisite|sufficient|optional|include|substack)\s+(\S+)(?:\s+(.*))?$/.exec(text);
    if(!match)throw new SyntaxError('Unsupported PAM syntax '+id+':'+(index+1));
    const [,type,control,module,args='']=match;if(type!==descriptor.type)continue;
    const row={configurationId:id,configurationHash:c.sha256,file:c.file,line:index+1,text:raw,type,control,module,args};
    if(control==='include')items.push(...pamParseConfiguration(module,phase,[...ancestors,id]));
    else if(control==='substack')items.push({...row,children:pamParseConfiguration(module,phase,[...ancestors,id])});
    else items.push(row);
  }
  return items;
}
function pamAction(control,status){
  const s=status.replace(/^PAM_/,'').toLowerCase();
  if(control.startsWith('[')){
    const pairs=Object.fromEntries(control.slice(1,-1).split(/\s+/).map(x=>x.split('=')));
    const a=pairs[s]??pairs.default;if(!a||!(/^(ok|bad|done|die|ignore)$/.test(a)||/^[1-9]\d*$/.test(a)))throw new SyntaxError('Unsupported PAM action '+a);
    return /^\d+$/.test(a)?Number(a):a;
  }
  const positive=status==='PAM_SUCCESS'||status==='PAM_NEW_AUTHTOK_REQD';
  if(status==='PAM_IGNORE')return 'ignore';
  if(control==='required')return positive?'ok':'bad';
  if(control==='requisite')return positive?'ok':'die';
  if(control==='sufficient')return positive?'done':'ignore';
  return positive?'ok':'ignore';
}
function pamModuleResult(row,phase,inputs){
  if(row.module==='pam_unavailable.so')return {status:'PAM_MODULE_UNKNOWN',hookCalled:false,reason:'module unavailable; no function dispatched'};
  const override=inputs[row.configurationId+':'+row.line+':'+phase]??inputs[row.module+':'+phase];
  if(override)return {status:override,hookCalled:true};
  if(row.module==='pam_debug.so'){
    const key=PAM_API_PHASES[phase].debugArgument;
    const args=Object.fromEntries(row.args.split(/\s+/).map(x=>x.split('=')));
    return {status:'PAM_'+(args[key]||'success').toUpperCase(),hookCalled:true};
  }
  if(row.module==='pam_deny.so')return {status:{authenticate:'PAM_AUTH_ERR',setcred:'PAM_CRED_ERR',account:'PAM_AUTH_ERR',open:'PAM_SESSION_ERR',close:'PAM_SESSION_ERR',prelim:'PAM_AUTHTOK_ERR',update:'PAM_AUTHTOK_ERR'}[phase],hookCalled:true};
  if(row.module==='pam_permit.so')return {status:'PAM_SUCCESS',hookCalled:true};
  if(['pam_unix.so','pam_limits.so','pam_sss.so','pam_rootok.so','pam_systemd.so','pam_access.so'].includes(row.module))throw new RangeError('Selected backend fixture must declare hook outcome: '+row.module+' '+phase);
  throw new RangeError('Unsupported module '+row.module);
}
function pamDispatchFlags(phase,callerFlags){
  const descriptor=PAM_API_PHASES[phase];
  if(descriptor.internal)return callerFlags?callerFlags+' | '+descriptor.flags:descriptor.flags;
  return phase==='password'?callerFlags:descriptor.flags;
}
export function pamEvaluate(service,phase,{inputs={},cache={},callerFlags=0}={}){
  const descriptor=PAM_API_PHASES[phase];if(!descriptor?.dispatch)throw new RangeError('Unsupported PAM phase '+phase);
  const flags=pamDispatchFlags(phase,callerFlags);
  const rows=pamParseConfiguration(service,phase),trace=[],frozen={...cache};
  const selectedService=PAM_CONFIGURATIONS[service].service||service;
  const accumulator={impression:'undefined',status:'PAM_PERM_DENIED'};
  const cached=descriptor.useCachedChain===true;
  const snapshot=()=>({...accumulator});
  function visit(items,depth,resume=null){
    for(let index=0;index<items.length;index++){
      const row=items[index];if(row.children){visit(row.children,depth+1,items[index+1]||resume);continue;}
      const before=snapshot(),result=pamModuleResult(row,phase,inputs),key=row.configurationId+':'+row.line;
      const controlStatus=cached?(cache[key]??result.status):result.status;
      if(!cached)frozen[key]=result.status;
      const action=pamAction(row.control,controlStatus),raw=result.status;
      let stop=false,reason=null,skip=0;
      if(action==='ok'||action==='done'||(typeof action==='number'&&cached)){
        if(accumulator.impression==='undefined'||(accumulator.impression==='positive'&&accumulator.status==='PAM_SUCCESS')){
          if(raw!=='PAM_IGNORE'||controlStatus===raw){accumulator.impression='positive';accumulator.status=raw;}
        }
        stop=action==='done'&&accumulator.impression==='positive';
      }else if(action==='bad'||action==='die'){
        if(accumulator.impression!=='negative'){accumulator.impression='negative';accumulator.status=raw==='PAM_IGNORE'?'PAM_PERM_DENIED':raw;}
        stop=action==='die';
      }
      if(typeof action==='number'){
        skip=Math.min(action,items.length-index-1);
        if(skip<action){accumulator.impression='negative';accumulator.status='PAM_PERM_DENIED';reason='jump overrun in current scope; denial retained when parent resumes';}
        else reason='numeric jump skips '+skip+' current-scope item(s); substack counts as one';
      }
      if(stop){skip=items.length-index-1;reason='terminate current scope';}
      const next=items[index+skip+1]||resume;
      trace.push({...row,service:selectedService,apiPhase:phase,api:descriptor.api,flags,moduleHook:result.hookCalled?descriptor.hook:null,hookCalled:result.hookCalled,rawReturn:raw,controlStatus,mappedAction:action,accumulatorBefore:before,accumulatorAfter:snapshot(),depth,nextRow:next?{configurationId:next.configurationId,line:next.line}:null,skipStopReason:reason||result.reason||'continue',executed:true});
      function skipped(item,skipDepth=depth){trace.push({...item,service:selectedService,children:undefined,apiPhase:phase,api:descriptor.api,flags,moduleHook:null,hookCalled:false,rawReturn:null,controlStatus:null,mappedAction:null,accumulatorBefore:snapshot(),accumulatorAfter:snapshot(),depth:skipDepth,nextRow:null,skipStopReason:reason,executed:false});if(item.children)item.children.forEach(child=>skipped(child,skipDepth+1));}
      items.slice(index+1,index+skip+1).forEach(item=>skipped(item));index+=skip;
      if(stop)break;
    }
  }
  visit(rows,0);
  if(accumulator.status==='PAM_SUCCESS'&&accumulator.impression!=='positive')accumulator.status='PAM_PERM_DENIED';
  return {service:selectedService,configurationId:service,phase,flags,status:accumulator.status,impression:accumulator.impression,trace,cache:frozen};
}
export function pamApiBoundary(configurationId,apiPhase,reason,{callerFlags=0}={}){const c=PAM_CONFIGURATIONS[configurationId],descriptor=PAM_API_PHASES[apiPhase];if(!descriptor)throw new RangeError('Unsupported PAM boundary phase '+apiPhase);return {configurationId,service:c.service||configurationId,configurationHash:c.sha256,file:c.file,line:null,apiPhase,type:descriptor.type,api:descriptor.api,flags:pamDispatchFlags(apiPhase,callerFlags),moduleHook:null,hookCalled:false,rawReturn:null,mappedAction:null,accumulatorBefore:null,accumulatorAfter:null,depth:null,nextRow:null,skipStopReason:reason,executed:null,inapplicable:'API boundary or caller operation, not a module hook'};}
