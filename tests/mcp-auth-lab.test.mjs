import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {buildMCPScenarioFixture,mcpAuthorizationIssuerDecision,mcpCanonicalResource,mcpDiscoveryCandidates,mcpParseChallenges,mcpScopeUnion,mcpRegistrationChoice,mcpCimdDecision,mcpStepUpDecision,mcpRefreshGrantDecision,mcpProxyConsentDecision,mcpRequestEnvelope,mcpValidateEnvelope,mcpDestinationDecision} from '../src/mcp-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
const final=model=>reconstructProtocolState(model,model.steps().length-1).mcp;
const at=(model,suffix)=>{const eventIndex=model.steps().findIndex(step=>step.id===model.id+':'+suffix);assert.ok(eventIndex>=0,'Missing MCP checkpoint '+model.id+':'+suffix);return reconstructProtocolState(model,eventIndex).mcp;};

test('MCP issuer matrix compares present issuer without normalization before redemption',()=>{
  for(const advertised of [true,false,undefined]){
    assert.equal(mcpAuthorizationIssuerDecision({advertised,iss:'https://as.example/tenant',expectedIssuer:'https://as.example/tenant'}).ok,true);
    for(const iss of ['https://AS.example/tenant','https://as.example:443/tenant','https://as.example/tenant/'])assert.equal(mcpAuthorizationIssuerDecision({advertised,iss,expectedIssuer:'https://as.example/tenant'}).ok,false);
    assert.equal(mcpAuthorizationIssuerDecision({advertised,expectedIssuer:'https://as.example/tenant'}).ok,advertised!==true);
  }
});
test('MCP path discovery order and quoted multi-challenge parsing are independent fixture expectations',()=>{
  assert.deepEqual(mcpDiscoveryCandidates('https://r.example/team/mcp','https://a.example/tenant'),{resource:['https://r.example/.well-known/oauth-protected-resource/team/mcp','https://r.example/.well-known/oauth-protected-resource'],authorization:['https://a.example/.well-known/oauth-authorization-server/tenant','https://a.example/.well-known/openid-configuration/tenant','https://a.example/tenant/.well-known/openid-configuration']});
  const challenges=mcpParseChallenges('Basic realm="old", Bearer resource_metadata="https://r.example/meta?q=a,b", scope="files:read files:write"');
  assert.equal(challenges[1].parameters.resource_metadata,'https://r.example/meta?q=a,b');assert.equal(challenges[1].parameters.scope,'files:read files:write');
  assert.deepEqual(mcpDiscoveryCandidates('https://r.example/team/mcp','https://a.example','https://r.example/explicit').resource,['https://r.example/explicit']);
});
test('MCP registration and scope are issuer-bound and least-privilege sets',()=>{
  assert.equal(mcpRegistrationChoice({issuer:'A',existing:{issuer:'A'},cimdAdvertised:true}),'existing');
  assert.equal(mcpRegistrationChoice({issuer:'B',existing:{issuer:'A'},cimdAdvertised:true}),'cimd');
  assert.equal(mcpRegistrationChoice({issuer:'B',dcrAdvertised:true}),'configuration-required');
  assert.equal(mcpRegistrationChoice({issuer:'B',dcrAdvertised:true,compatibility:true}),'deprecated-dcr');
  assert.deepEqual(mcpScopeUnion(['files:read'],['files:write','files:read']),['files:read','files:write']);
});
test('MCP current transport mirrors exact request metadata and never needs session initialization',()=>{
  const request=mcpRequestEnvelope();assert.equal(mcpValidateEnvelope(request).ok,true);assert.equal(request.method,'POST');assert.equal(request.path,'/team/mcp');assert.equal(request.headers['Mcp-Session-Id'],undefined);
  request.headers['Mcp-Name']='delete_file';assert.deepEqual(mcpValidateEnvelope(request),{ok:false,status:400,reason:'HeaderMismatch'});
});
test('MCP Appendix B PKCE value has an independent SHA256 oracle',()=>{
  assert.equal(createHash('sha256').update('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk').digest('base64url'),'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  const model=buildMCPScenarioFixture('lab-mcp01'),value=key=>model.mcpInventory.artifacts.find(artifact=>artifact.artifactId===model.id+':'+key).representations[0].fields[0].value;
  assert.equal(createHash('sha256').update(value('grant-verifier')).digest('base64url'),value('grant-challenge'));
});
test('MCP01 receipt, token validation, policy, execution and result learning are distinct',()=>{
  const model=buildMCPScenarioFixture('lab-mcp01');
  assert.equal(at(model,'grant-token-response-recover').tokenAccepted,false);
  assert.equal(at(model,'operation-request-wire').tokenAccepted,false);
  assert.equal(at(model,'operation-token').tokenAccepted,true);
  assert.equal(at(model,'operation-policy').operationExecuted,false);
  assert.equal(at(model,'operation-result-wire-recover').resultLearned,false);
  assert.equal(final(model).resultLearned,true);
});
test('MCP01 negative inputs stop the correct next action and preserve unrelated grant',()=>{
  for(const variant of ['consent-cancel','later-missing-token','pkce-absent']){
    const model=buildMCPScenarioFixture('lab-mcp01',{variant}),state=final(model);
    assert.equal(state.operationExecuted,false,variant);assert.equal(state.resultLearned,false,variant);assert.equal(state.priorReadGrant.valid,true,variant);
    if(variant==='pkce-absent')assert.equal(model.steps().some(s=>s.id.includes('grant-authorization')),false);
    if(variant==='consent-cancel')assert.equal(state.currentToken,undefined);
    if(variant==='later-missing-token')assert.equal(state.responseStatus,401);
  }
});
test('MCP client-local stops preserve the latest server-authored decision',()=>{
  for(const [id,variant,suffix,status] of [['lab-mcp01','pkce-absent','pkce-stop',401],['lab-mcp06','repeated-challenge','retry-stop',403]]){
    const model=buildMCPScenarioFixture(id,{variant}),index=model.steps().findIndex(step=>step.id===id+':'+suffix);
    assert.ok(index>0,'The client stop follows an actual server challenge');
    assert.equal(reconstructProtocolState(model,index-1).mcp.serverDecision,status);
    assert.equal(reconstructProtocolState(model,index).mcp.serverDecision,status);
    assert.equal(final(model).serverDecision,status);
    assert.equal(final(model).operationExecuted,false);
  }
});
test('MCP URL policy blocks unsafe destinations before credential send, with explicit response limits',()=>{
  for(const url of ['javascript:alert(1)','data:text/plain,x','file:///demo'])assert.equal(mcpDestinationDecision({url}).stage,'before-send');
  assert.equal(mcpDestinationDecision({url:'https://public.example/meta',addresses:['169.254.169.254']}).ok,false);
  assert.equal(mcpDestinationDecision({url:'https://private.example/meta',addresses:['10.1.2.3'],allowPrivate:true}).ok,true);
  assert.equal(mcpDestinationDecision({url:'https://public.example/meta',bytes:65537}).stage,'after-response');
});
test('MCP canonical resource handling does not weaken exact issuer comparison',()=>{
  assert.equal(mcpCanonicalResource('HTTPS://MCP.LAB.EXAMPLE/team/mcp'),'https://mcp.lab.example/team/mcp');
  assert.equal(mcpCanonicalResource('https://mcp.lab.example/team/mcp#other'),null);
  assert.equal(mcpCanonicalResource('mcp.lab.example/team/mcp'),null);
});
test('MCP CIMD validation creates only registration trust after exact document and redirect checks',()=>{
  const input={url:'https://client.example/metadata.json',document:{client_id:'https://client.example/metadata.json',client_name:'Untrusted name',redirect_uris:['http://127.0.0.1:49152/callback']},redirect:'http://127.0.0.1:49152/callback'};
  assert.equal(mcpCimdDecision(input).ok,true);
  assert.equal(mcpCimdDecision({...input,document:{...input.document,client_id:input.url+'/'}}).ok,false);
  assert.equal(mcpCimdDecision({...input,advertised:false}).ok,false);
  assert.equal(mcpCimdDecision({...input,redirect:'https://other.example/callback'}).ok,false);
  assert.equal(mcpCimdDecision({...input,document:'{broken'}).ok,false);
});
test('MCP bounded step-up preserves requested scopes and does not infer hierarchy',()=>{
  assert.deepEqual(mcpStepUpDecision({previousRequested:['files:read'],challengeScopes:['files:write'],metadataScopes:['files:read']}),{ok:true,requested:['files:read','files:write'],attempt:1});
  assert.equal(mcpStepUpDecision({attempt:2}).ok,false);
  assert.deepEqual(mcpStepUpDecision({previousRequested:['files:read'],challengeScopes:undefined,metadataScopes:undefined}).requested,['files:read']);
});
test('MCP rotating refresh rejects old generation and resource/scope escalation',()=>{
  const input={refresh:{valid:true,client:'C',resource:'R',scopes:['read'],generation:1},client:'C',resource:'R',scopes:['read']};
  assert.equal(mcpRefreshGrantDecision(input).newGeneration,2);
  assert.equal(mcpRefreshGrantDecision({...input,refresh:{...input.refresh,valid:false}}).reason,'invalid_grant');
  assert.equal(mcpRefreshGrantDecision({...input,resource:'U'}).ok,false);
  assert.equal(mcpRefreshGrantDecision({...input,scopes:['write']}).ok,false);
  assert.equal(mcpRefreshGrantDecision({...input,network:'timeout'}).reauthorize,false);
});
test('MCP upstream cookie or global consent cannot authorize a distinct downstream client',()=>{
  const input={record:{integrity:true,approved:true,user:'U',client:'C1',redirect:'https://c1.example/callback',scopes:['read'],csrf:'tx1'},user:'U',client:'C1',redirect:'https://c1.example/callback',scopes:['read'],csrf:'tx1'};
  assert.equal(mcpProxyConsentDecision(input).ok,true);
  assert.equal(mcpProxyConsentDecision({...input,client:'C2'}).upstreamContactAllowed,false);
  assert.equal(mcpProxyConsentDecision({...input,csrf:'other'}).downstreamCodeAllowed,false);
  assert.equal(mcpProxyConsentDecision({...input,record:{approved:true}}).ok,false);
});
test('MCP initial scope fallback is not reused to infer permissions from a scope-less step-up',()=>{
  assert.deepEqual(mcpStepUpDecision({previousRequested:[],metadataScopes:['files:read'],initial:true}).requested,['files:read']);
  assert.deepEqual(mcpStepUpDecision({previousRequested:['files:read'],metadataScopes:['files:write']}).requested,['files:read']);
  const request=mcpRequestEnvelope();delete request.headers['MCP-Protocol-Version'];delete request.body.params._meta['io.modelcontextprotocol/protocolVersion'];assert.equal(mcpValidateEnvelope(request).ok,false);
});
test('MCP stdio uses one real newline-delimited JSON-RPC line and separates provider IPC from stdout',()=>{
  const model=buildMCPScenarioFixture('lab-mcp13'),request=model.mcpInventory.artifacts.find(artifact=>artifact.artifactId===model.id+':stdio-request').representations[0].fields[0].value;
  assert.equal(request.endsWith('\n'),true);assert.equal(request.slice(0,-1).includes('\n'),false);assert.equal(JSON.parse(request).method,'tools/call');
  const provider=model.steps().find(step=>step.id===model.id+':provider-delivery'),sent=provider.attributeOperations.filter(operation=>operation.kind==='send'),received=provider.attributeOperations.filter(operation=>operation.kind==='receive');
  assert.equal(sent.some(operation=>operation.instanceId===model.id+':server-credential'&&operation.actorId==='mcpO'),true);
  assert.equal(received.some(operation=>operation.instanceId===model.id+':server-credential'&&operation.actorId==='mcpR'),true);
  for(const key of ['stdio-call','stdio-result'])assert.equal(model.steps().find(step=>step.id===model.id+':'+key).attributeOperations.some(operation=>operation.instanceId===model.id+':server-credential'),false);
  assert.equal(final(model).httpOAuthStarted,false);
});
test('Proxy-local refusal reaches the client only after protected response recovery',()=>{
  for(const [id,variants,key] of [
    ['lab-mcp09',['upstream-consent-denied','missing-upstream-token','other-client-grant'],'upstream-stop'],
    ['lab-mcp11',['forward-p-token'],'passthrough-stop'],
  ])for(const variant of variants){
    const model=buildMCPScenarioFixture(id,{variant});
    for(const checkpoint of [key+'-decision',key]){
      const state=at(model,checkpoint);
      assert.equal(state.clientKnowledge,'not attempted',id+'/'+variant);
      assert.equal(state.resultLearned,false,id+'/'+variant);
      assert.equal(state.upstreamRequests,0,id+'/'+variant);
    }
    const received=at(model,key+'-recover');
    assert.equal(received.responseStatus,403);
    assert.notEqual(received.clientKnowledge,'not attempted');
    assert.equal(received.operationExecuted,false);
    assert.equal(received.resultLearned,false);
    assert.equal(received.priorReadGrant.valid,true);
  }
});
test('Corrected two-grant proxy learns upstream output before it can deliver an accepted client result',()=>{
  const model=buildMCPScenarioFixture('lab-mcp11',{variant:'corrected-two-grants'});
  assert.equal(at(model,'upstream-token').resultLearned,false);
  assert.equal(at(model,'upstream-result-wire').upstreamResultAccepted,undefined);
  assert.equal(at(model,'upstream-result-wire-recover').upstreamResultAccepted,undefined);
  assert.equal(at(model,'upstream-result-accept').upstreamResultAccepted,true);
  assert.equal(at(model,'corrected-proxy-result-wire-recover').resultLearned,false);
  assert.equal(at(model,'corrected-proxy-result-accept').resultLearned,true);
});
