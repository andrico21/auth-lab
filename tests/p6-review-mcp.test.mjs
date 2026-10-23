import test from 'node:test';
import assert from 'node:assert/strict';
import {buildMCPScenarioFixture,MCPLAB_CASE_BUILDERS,mcpRefreshGrantDecision} from '../src/mcp-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildMCPHeldObjects} from '../src/held-object-mcp.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';

const resource='https://mcp.lab.example/team/mcp',issuer='https://login.lab.example/tenant-a';
const clientUrl='https://client.lab.example/oauth/metadata.json',redirect='http://127.0.0.1:49152/callback';
function fixture(id,variant='default'){
  const model=buildMCPScenarioFixture(id,{variant}),steps=model.steps();
  const index=key=>{const n=steps.findIndex(step=>step.id===id+':'+key);assert.ok(n>=0,'Missing '+id+'/'+variant+':'+key);return n;};
  const step=key=>steps[index(key)];
  const fields=key=>Object.fromEntries(step(key).attributeOperations.filter(op=>op.attributeId.startsWith('mcp_field_')).map(op=>{let value=op.value;try{value=JSON.parse(value);}catch{}return [op.fieldPath,value];}));
  const compiled=compileHeldObjects(buildMCPHeldObjects({model,steps,actors:model.actors(),contextId:id+':'+variant}),{model,steps});
  const state=key=>reconstructProtocolState(model,key===undefined?steps.length-1:index(key)).mcp;
  const holdings=(key)=>projectHeldObjects(compiled,{eventIndex:key===undefined?steps.length-1:index(key),milestone:'complete'}).holdings;
  const has=(artifact,actor,key)=>holdings(key).some(h=>h.artifactId===id+':'+artifact&&h.actorId===actor);
  const value=artifact=>model.mcpInventory.artifacts.find(a=>a.artifactId===id+':'+artifact).representations[0].fields[0].value;
  return {model,steps,index,step,fields,state,holdings,has,value,compiled};
}

test('P6-MCP-01 preserves the exact write operation from initial request through OAuth and bounded retry',()=>{
  const expectedArgs={path:'demo/report.txt',content:'Reviewed report update'};
  for(const variant of ['default','challenge-outside-metadata','missing-challenge-scope','smaller-grant','hierarchy-not-permission','upgrade-acl-denied']){
    const f=fixture('lab-mcp06',variant),initial=f.fields('write-request-recover').Request,retry=f.fields('operation-construct');
    assert.equal(initial.headers['Mcp-Name'],'write_file');assert.equal(initial.body.params.name,'write_file');assert.deepEqual(initial.body.params.arguments,expectedArgs);
    assert.equal(retry.Headers['Mcp-Name'],'write_file');assert.equal(retry.Body.params.name,'write_file');assert.deepEqual(retry.Body.params.arguments,expectedArgs);
    const approval=JSON.parse(f.value('operation-approval')),tx=JSON.parse(f.value('stepup-grant-transaction'));
    for(const operation of [approval,tx.operation]){assert.equal(operation.tool,'write_file');assert.equal(operation.target,'demo/report.txt');assert.deepEqual(operation.arguments,expectedArgs);assert.deepEqual(operation.requiredScopes,['files:write']);}
    assert.equal(f.fields('operation-host-approval').Tool,'write_file');assert.equal(f.fields('operation-policy').Tool,'write_file');assert.equal(f.fields('operation-policy').Required,'files:write');
    assert.equal(f.state('operation-policy').operationExecuted,false);assert.equal(f.state('operation-policy').resultLearned,false);
    assert.ok(f.index('write-request-recover')<f.index('stepup-grant-authorization-recover'));assert.ok(f.index('stepup-grant-scope-accept')<f.index('operation-host-approval'));
    const success=['default','challenge-outside-metadata','missing-challenge-scope'].includes(variant);
    assert.equal(f.state().operationExecuted,success);assert.equal(f.state().resultLearned,success);assert.equal(f.state().priorReadGrant.valid,true);
    assert.equal(f.has('read-access-g1','mcpC'),true);assert.equal(f.has('prior-read-grant','mcpC'),true);
    if(success){assert.ok(f.index('operation-policy')<f.index('operation-execute'));assert.equal(f.fields('operation-execute').Tool,'write_file');assert.equal(f.fields('operation-execute').Result,'SYM(write completed for demo/report.txt)');assert.equal(f.state('operation-result-wire-recover').resultLearned,false);}
    else{assert.equal(f.steps.some(s=>s.id.endsWith(':operation-execute')),false);assert.equal(f.state().resourceAuthorized,false);}
  }
});

test('P6-MCP-01 smaller grant changes AS consent and response, never the read+write client request',()=>{
  for(const [variant,granted] of [['default',['files:read','files:write']],['smaller-grant',['files:read']],['hierarchy-not-permission',['files:read','files:*']]]){
    const f=fixture('lab-mcp06',variant);
    assert.deepEqual(f.state('stepup-check').requestedScopes,['files:read','files:write']);
    for(const key of ['stepup-grant-authorization-recover','stepup-grant-browser-as-recover'])assert.equal(f.fields(key).scope,'files:read files:write');
    assert.deepEqual(f.fields('stepup-grant-consent').Requested,['files:read','files:write']);assert.deepEqual(f.fields('stepup-grant-consent').Scopes,granted);
    assert.equal(JSON.parse(Buffer.from(f.value('stepup-grant-access-g1').split('.')[1],'base64url')).scope,granted.join(' '));
    assert.equal(f.fields('stepup-grant-token-response-recover').scope,variant==='default'?undefined:granted.join(' '));
    assert.equal(f.state('stepup-grant-token-response-recover').grantedScopes,undefined);assert.deepEqual(f.state('stepup-grant-scope-accept').grantedScopes,granted);
    assert.deepEqual(f.fields('operation-policy').Granted,granted);
    if(variant==='smaller-grant')assert.equal(f.fields('operation-denied-recover').Headers['WWW-Authenticate'],'Bearer error="insufficient_scope", resource_metadata="https://mcp.lab.example/metadata/team", scope="files:write"');
    if(variant==='default')assert.equal(f.fields('operation-policy').ACL,true);
  }
});

test('P6-MCP-02 missing and invalid Bearer responses retain their resource-specific wire contract',()=>{
  const cases=[['lab-mcp01','later-missing-token','operation-missing-recover',false],['lab-mcp05','expired','resource-invalid-recover',true],['lab-mcp05','bad-signature','resource-invalid-recover',true],['lab-mcp08','clientinfo-only','operation-missing-recover',false],['lab-mcp08','cached-tools','operation-missing-recover',false],['lab-mcp07','revocation-propagated','revoked-resource-recover',true],['lab-mcp11','default','incoming-rejected-recover',true],['lab-mcp09','upstream-expired','upstream-reject-recover',true]];
  for(const [id,variant,key,invalid] of cases){
    const f=fixture(id,variant),reply=f.fields(key),metadata=id==='lab-mcp09'?'https://api.lab.example/files/.well-known/oauth-protected-resource':'https://mcp.lab.example/metadata/team';
    assert.equal(reply.HTTP,401);assert.equal(reply.Headers['WWW-Authenticate'],'Bearer '+(invalid?'error="invalid_token", ':'')+'resource_metadata="'+metadata+'", scope="files:read"');
    assert.equal(f.state(key).operationExecuted,false);assert.equal(f.state(key).resultLearned,false);assert.equal(f.model.mcpInventory.artifacts.some(a=>a.type==='result'),false);
  }
  for(const [id,cases] of Object.entries(MCPLAB_CASE_BUILDERS))for(const variant of Object.keys(cases)){
    const f=fixture(id,variant);
    for(const step of f.steps){
      if(!step.id.endsWith('-recover'))continue;
      const key=step.id.slice(id.length+1),packet=f.fields(key);
      if(packet.HTTP===401){assert.match(packet.Headers?.['WWW-Authenticate']||'',/^Bearer /,id+'/'+variant+':'+key);assert.equal(f.state(key).resultLearned,false);}
    }
  }
});

test('P6-MCP-02 token-endpoint failures are AS errors without a resource Bearer challenge',()=>{
  for(const [id,variant,key,error] of [['lab-mcp04','wrong-verifier','grant-invalid-grant-recover','invalid_grant'],['lab-mcp04','reused-code','grant-invalid-grant-recover','invalid_grant'],['lab-mcp07','rotated-reuse','refresh-invalid-recover','invalid_grant'],['lab-mcp07','refresh-scope-escalation','refresh-invalid-recover','invalid_scope'],['lab-mcp07','refresh-resource-escalation','refresh-invalid-recover','invalid_target']]){
    const f=fixture(id,variant),packet=f.fields(key);assert.equal(packet.HTTP,400);assert.equal(packet.error,error);assert.deepEqual(packet.Headers,{});assert.equal(f.step(key).from,'mcpC');assert.equal(f.state().operationExecuted,false);
  }
});

test('P6-MCP-03 valid excessive-scope/resource requests retain generation 1 without issuing access or invoking R',()=>{
  for(const [variant,error,requestedResource,requestedScope] of [['refresh-scope-escalation','invalid_scope',resource,'files:admin'],['refresh-resource-escalation','invalid_target','https://api.lab.example/files','files:read']]){
    const f=fixture('lab-mcp07',variant),request=f.fields('refresh-request-recover');assert.equal(request.scope,requestedScope);assert.equal(request.resource,requestedResource);
    assert.equal(f.fields('refresh-check').Input.valid,true);assert.equal(f.fields('refresh-check').Decision.reason,error);assert.equal(f.fields('refresh-invalid-recover').error,error);
    for(const key of ['refresh-check','refresh-invalid-recover','refresh-request-rejected']){assert.equal(f.has('refresh-g1','mcpC',key),true);assert.equal(f.has('refresh-g1','mcpA',key),true);}
    assert.equal(f.state().refreshGeneration1Valid,true);assert.equal(f.state().permittedRefreshRetryAvailable,true);assert.equal(f.state().reauthorizationRequired,false);
    assert.deepEqual(f.fields('refresh-request-rejected').Allowed,{resource,scopes:['files:read']});
    assert.equal(f.steps.some(s=>s.id.endsWith(':refresh-rotate')||s.id.endsWith(':operation-construct')),false);assert.equal(f.model.mcpInventory.artifacts.some(a=>a.artifactId.endsWith(':renewed-access-g2')),false);
    const sameGrant={valid:true,revoked:false,client:'desktop-client',resource,scopes:['files:read'],generation:1,currentGeneration:1};
    assert.deepEqual(mcpRefreshGrantDecision({refresh:sameGrant,client:'desktop-client',resource,scopes:['files:read']}),{ok:true,oldGenerationValid:false,newGeneration:2,scopes:['files:read']});
  }
  for(const variant of ['rotated-reuse','refresh-rejected']){const f=fixture('lab-mcp07',variant);assert.equal(f.fields('refresh-invalid-recover').error,'invalid_grant');assert.equal(f.has('refresh-g1','mcpC','reauthorize-required'),false);assert.equal(f.state().reauthorizationRequired,true);}
  assert.equal(mcpRefreshGrantDecision({refresh:{valid:true,expired:true},client:'desktop-client',resource,scopes:['files:read']}).reason,'invalid_grant');
});

test('P6-MCP-04 CIMD is resolved only after AS receipt of the complete same authorization transaction',()=>{
  for(const variant of ['default','cimd-id-mismatch','redirect-absent','malformed-cimd','cimd-unavailable','disallowed-domain']){
    const f=fixture('lab-mcp03',variant),params=f.fields('grant-browser-as-recover');
    assert.deepEqual(params,{response_type:'code',client_id:clientUrl,redirect_uri:redirect,state:'SYM(state-grant)',code_challenge:'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method:'S256',resource,scope:'files:read'});
    assert.deepEqual(f.fields('grant-authorization-recover'),params);assert.equal(f.has('grant-authorization-request','mcpA','grant-browser-as'),false);assert.equal(f.has('grant-authorization-request','mcpA','grant-browser-as-recover'),true);
    assert.ok(f.index('grant-browser-as-recover')<f.index('cimd-request-binding'));assert.deepEqual(f.fields('registration-check').Request,params);
    assert.equal(f.steps.some(s=>s.id.includes(':registration-verdict')),false);
    if(variant!=='disallowed-domain'){assert.ok(f.index('grant-browser-as-recover')<f.index('cimd-request-protect'));assert.equal(f.fields('cimd-request-recover').URL,clientUrl);assert.equal(f.has('grant-authorization-request','mcpA','cimd-request-protect'),true);}
    if(variant==='default'){
      assert.ok(f.index('registration-check')<f.index('grant-as-authentication'));assert.ok(f.index('grant-consent')<f.index('grant-issue-code'));assert.equal(f.has('selected-registration','mcpA','registration-check'),true);assert.equal(f.has('selected-registration','mcpC'),false);assert.equal(f.state().resultLearned,true);
    }else{
      assert.equal(f.fields('registration-check').Accepted,false);assert.equal(f.fields('registration-error-recover').state,params.state);assert.equal(f.fields('registration-error-recover').client_id,clientUrl);assert.equal(f.fields('registration-error-recover').HTTP,400);assert.equal(f.step('registration-error').to,'mcpB');
      for(const suffix of ['grant-as-authentication','grant-issue-code','grant-token-request'])assert.equal(f.steps.some(s=>s.id==='lab-mcp03:'+suffix),false);assert.equal(f.state().operationExecuted,false);
    }
  }
  const existing=fixture('lab-mcp03','existing-registration'),dcr=fixture('lab-mcp03','dcr-compatibility');
  for(const f of [existing,dcr])assert.equal(f.steps.some(s=>s.id.includes(':cimd-request')),false);
  assert.equal(existing.fields('grant-browser-as-recover').client_id,'desktop-client');assert.equal(existing.steps.some(s=>s.id.includes(':dcr-request')),false);
  assert.equal(dcr.fields('dcr-request-recover').Request.application_type,'native');assert.equal(dcr.fields('dcr-response-recover').HTTP,201);assert.ok(dcr.index('dcr-response-recover')<dcr.index('grant-prepare'));assert.equal(dcr.fields('grant-browser-as-recover').client_id,'dcr-native-client');
});

for(const variant of ['upstream-expired','upstream-wrong-audience'])test('P6-MCP-A1 / P6C-MCP-01 '+variant+' returns a complete tool error without changing either grant boundary',()=>{
  const f=fixture('lab-mcp09',variant),state=f.state('upstream-validation');
  assert.equal(state.downstreamTokenAccepted,true);assert.equal(state.upstreamTokenAccepted,false);assert.equal(state.tokenAccepted,true);assert.equal(f.has('downstream-token-context','mcpR','upstream-validation'),true);
  for(const [label,path] of [['Downstream C->P token accepted','mcp.downstreamTokenAccepted'],['Upstream P->U token accepted','mcp.upstreamTokenAccepted']])assert.ok(f.model.decisionBindings.some(b=>b.label===label&&b.path===path));
  assert.equal(f.fields('upstream-reject-recover').HTTP,401);assert.equal(f.state('proxy-upstream-mapping').upstreamRenewalRequired,true);
  const request=f.fields('downstream-request-recover').Request.body,mapped=f.fields('proxy-upstream-error-recover');
  assert.equal(mapped.HTTP,200);assert.deepEqual(mapped.Headers,{});assert.equal(mapped.Body.jsonrpc,'2.0');assert.equal(mapped.Body.id,request.id);
  assert.equal(mapped.Body.result.resultType,'complete');assert.equal(mapped.Body.result.isError,true);assert.match(mapped.Body.result.content[0].text,/proxy must renew its upstream API grant/);assert.match(mapped.Body.result.content[0].text,/proxy token remains accepted/);
  assert.equal(f.state().downstreamTokenAccepted,true);assert.equal(f.state().upstreamTokenAccepted,false);assert.equal(f.state().operationExecuted,false);assert.equal(f.state().resultLearned,false);
  assert.equal(f.has('upstream-result','mcpR'),false);assert.equal(f.has('proxy-result','mcpC'),false);
  for(let eventIndex=-1;eventIndex<f.steps.length;eventIndex++){
    const frame=projectHeldObjects(f.compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
    assert.equal(frame.holdings.some(h=>h.artifactId==='lab-mcp09:upstream-access-g1'&&h.actorId==='mcpC'),false);assert.equal(frame.holdings.some(h=>h.artifactId==='lab-mcp09:downstream-access-g1'&&h.actorId==='mcpU'),false);
  }
  assert.equal(JSON.stringify(mapped).includes(f.value('upstream-access-g1')),false);assert.equal(JSON.stringify(mapped).includes(f.value('downstream-access-g1')),false);
});

test('P6C-MCP-01 the successful proxy comparison remains complete and accepts only authorized output',()=>{
  const f=fixture('lab-mcp09'),request=f.fields('downstream-request-recover').Request.body,mapped=f.fields('proxy-result-wire-recover');
  assert.equal(mapped.HTTP,200);assert.equal(mapped.Body.jsonrpc,'2.0');assert.equal(mapped.Body.id,request.id);assert.equal(mapped.Body.result.resultType,'complete');assert.notEqual(mapped.Body.result.isError,true);
  assert.equal(f.state().downstreamTokenAccepted,true);assert.equal(f.state().upstreamTokenAccepted,true);assert.equal(f.state().operationExecuted,true);assert.equal(f.state().resultLearned,true);
  assert.equal(f.has('proxy-result','mcpC'),true);assert.equal(f.has('upstream-access-g1','mcpC'),false);assert.equal(f.has('downstream-access-g1','mcpU'),false);
  assert.equal(JSON.stringify(mapped).includes(f.value('upstream-access-g1')),false);assert.equal(JSON.stringify(mapped).includes(f.value('downstream-access-g1')),false);
});
