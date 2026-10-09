import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, FLOWS } from '../src/protocol-data.js';
import { GRANTLAB_ATTRIBUTES, GRANTLAB_SCENARIOS, GRANTLAB_SOURCES } from '../src/extended-grants-lab.js';

const grantTestModel=id=>GRANTLAB_SCENARIOS.find(s=>s.id===id);
const grantTestStage=(model,key)=>model.steps().find(s=>s.labGrantStage===key);
const grantTestWire=s=>s.attributeOperations.filter(o=>['send','receive'].includes(o.kind));
const grantTestIdsByName=(model,name)=>Object.entries(model.definitions()).filter(([,d])=>d.name===name).map(([id])=>id);
const grantTestIdByName=(model,name)=>grantTestIdsByName(model,name)[0];

test('extended grant scenarios have immutable independent models and real actor/attribute lifecycle ledgers',()=>{
  assert.equal(GRANTLAB_SCENARIOS.length,8);assert.equal(new Set(GRANTLAB_SCENARIOS.map(s=>s.id)).size,8);
  const original=JSON.stringify(FLOWS),allUsed=new Set();
  for(const model of GRANTLAB_SCENARIOS){
    assert.ok(model.id.startsWith('lab-'));assert.equal(model.universalLab,true);assert.equal(model.factorSelectable,false);assert.equal(model.jweAdaptable,false);
    assert.ok(model.supportNote);assert.ok(model.source.startsWith('https://'));assert.equal(model.steps(),model.steps());assert.ok(Object.isFrozen(model.steps()));
    const defs=model.definitions(),actors=model.actors(),steps=model.steps();assert.equal(new Set(steps.map(s=>s.id)).size,steps.length);
    assert.deepEqual(new Set(Object.keys(defs)),new Set(model.ids));
    for(const id of model.ids){assert.ok(id.startsWith('grant'),id);allUsed.add(id);for(const property of ['name','meaning','description','origin','generator','purpose','example','standard','source'])assert.ok(defs[id][property],id+': '+property);assert.ok(steps.some(s=>s.attributeOperations.some(o=>o.attributeId===id&&o.kind!=='inspect')),id+' has an actual lifecycle');assert.ok(Object.isFrozen(defs[id]));}
    for(const step of steps){assert.ok(Object.isFrozen(step));for(const actor of [step.from,step.to])assert.ok(ACTORS[actor]&&actors[actor],step.id+': '+actor);assert.ok(Array.isArray(step.attributeOperations));for(const op of step.attributeOperations){assert.ok(defs[op.attributeId],step.id+': '+op.attributeId);assert.ok(actors[op.actorId],step.id+': '+op.actorId);}for(const p of step.payload)if(p.attributeId)assert.ok(defs[p.attributeId],step.id+': '+p.attributeId);}
  }
  assert.deepEqual(allUsed,new Set(Object.keys(GRANTLAB_ATTRIBUTES)));assert.equal(JSON.stringify(FLOWS),original);assert.ok(GRANTLAB_SOURCES.every(s=>/openid\.net|rfc-editor\.org|keycloak\.org/.test(s.url)));
});

test('CIBA Ping authenticates a handle-only callback before an independent authenticated token fetch',()=>{
  const model=grantTestModel('lab-ciba-ping'),ping=grantTestStage(model,'ping'),verify=grantTestStage(model,'ping-check'),fetch=grantTestStage(model,'fetch');
  assert.equal(model.status,'supported');assert.match(model.supportNote,/admin policy table/);
  assert.deepEqual(ping.payload.map(p=>p.name),['Authorization','auth_req_id']);assert.match(ping.payload[0].value,/^Bearer /);
  assert.equal(ping.payload.some(p=>/^(id_token|access_token|refresh_token)$/.test(p.name)),false);
  assert.ok(model.steps().indexOf(ping)<model.steps().indexOf(verify));assert.ok(model.steps().indexOf(verify)<model.steps().indexOf(grantTestStage(model,'ack')));assert.ok(model.steps().indexOf(grantTestStage(model,'ack'))<model.steps().indexOf(fetch));
  assert.equal(fetch.payload.find(p=>p.name==='grant_type').value,'urn:openid:params:grant-type:ciba');assert.match(fetch.payload.find(p=>p.name==='Authorization').value,/^Basic /);
  assert.ok(fetch.payload.some(p=>p.name==='auth_req_id'));assert.equal(model.steps().some(s=>s.fields.some(id=>/urn:openid:params:jwt:claim:auth_req_id|at_hash|rt_hash/.test(model.definitions()[id].name))),false);
});

test('CIBA Push is labelled standards-only and validates sender, request binding and exact access/refresh hashes',()=>{
  const model=grantTestModel('lab-ciba-push'),push=grantTestStage(model,'push'),verify=grantTestStage(model,'push-check'),defs=model.definitions();
  assert.equal(model.status,'standards-only');assert.match(model.supportNote,/does not claim Keycloak Push support/);
  assert.equal(model.steps().some(s=>s.labGrantStage==='fetch'),false);assert.equal(model.steps().some(s=>s.payload.some(p=>p.name==='grant_type')),false);
  for(const name of ['Authorization','auth_req_id','id_token','access_token','refresh_token'])assert.ok(push.payload.some(p=>p.name===name),name);
  assert.match(push.payload.find(p=>p.name==='Authorization').value,/^Bearer /);
  for(const name of ['at_hash','urn:openid:params:jwt:claim:rt_hash','urn:openid:params:jwt:claim:auth_req_id']){
    const id=grantTestIdByName(model,name);assert.ok(id,name);assert.ok(grantTestStage(model,'issuer').attributeOperations.some(o=>o.attributeId===id&&o.kind==='derive'));
    assert.ok(grantTestWire(push).filter(o=>o.attributeId===id).every(o=>o.carriedAs==='id_token claims'));
    assert.ok(verify.attributeOperations.some(o=>o.attributeId===id&&o.kind==='verify'&&o.actorId==='app'));
  }
  assert.match(defs[grantTestIdByName(model,'at_hash')].purpose,/ASCII\(access_token\)/);assert.match(verify.detail,/received refresh_token/);
  const issuerOps=grantTestStage(model,'issuer').attributeOperations;
  assert.ok(issuerOps.findIndex(o=>o.attributeId===grantTestIdByName(model,'at_hash')&&o.kind==='derive')<issuerOps.findIndex(o=>o.attributeId===grantTestIdByName(model,'id_token')&&o.kind==='derive'),'Push hash claims exist before the full ID token is signed.');
});

test('alternate CIBA hint uses exactly one hint and a configured profile without substituting it for device authentication',()=>{
  const model=grantTestModel('lab-ciba-hint-token'),request=grantTestStage(model,'request'),profile=grantTestStage(model,'hint-check');
  assert.equal(model.status,'standards-only');assert.deepEqual(request.payload.filter(p=>['login_hint','login_hint_token','id_token_hint'].includes(p.name)).map(p=>p.name),['login_hint_token']);
  assert.equal(request.payload.some(p=>p.name==='client_notification_token'),false);assert.equal(model.steps().some(s=>s.labGrantStage==='ping'||s.labGrantStage==='push'),false);
  for(const name of ['login_hint_token','iss (login_hint_token)','exp (login_hint_token)'])assert.ok(profile.attributeOperations.some(o=>o.attributeId===grantTestIdByName(model,name)&&o.kind==='verify'),name);
  assert.match(grantTestStage(model,'prepare').detail,/id_token_hint.*decrypt an encrypted ID token first/);assert.match(grantTestStage(model,'prepare').detail,/user_code.*optional.*not a Device Flow code/);
  assert.match(profile.detail,/does not authenticate or approve/);assert.ok(model.steps().indexOf(profile)<model.steps().indexOf(grantTestStage(model,'approve')));assert.ok(model.steps().indexOf(grantTestStage(model,'proof-check'))<model.steps().indexOf(grantTestStage(model,'issuer')));
});

test('CIBA callback protection and all private signing keys stay with their actual backend recipients',()=>{
  for(const model of GRANTLAB_SCENARIOS){
    const defs=model.definitions();
    for(const step of model.steps())for(const op of grantTestWire(step)){
      assert.doesNotMatch(defs[op.attributeId].name,/\(private\)/,step.id+' private signing key cannot travel');
      if(defs[op.attributeId].name==='Authorization (controlled-service callback)')assert.ok(['realmA','realmB'].includes(op.actorId),step.id);
      if(defs[op.attributeId].name==='client_notification_token')assert.ok(['app','realmA'].includes(op.actorId),step.id);
      if(defs[op.attributeId].name==='Authorization (client authentication)')assert.ok(['app','realmA'].includes(op.actorId),step.id);
    }
  }
});

test('every extended CIBA success creates, delivers and interprets the required Bearer token_type',()=>{
  for(const scenario of ['lab-ciba-ping','lab-ciba-push','lab-ciba-hint-token']){
    const model=grantTestModel(scenario),id=grantTestIdByName(model,'token_type');
    assert.ok(id,scenario+' defines the required response member');
    assert.equal(model.definitions()[id].example,'Bearer');
    const issuance=grantTestStage(model,'issuer');
    assert.ok(issuance.attributeOperations.some(o=>o.attributeId===id&&o.kind==='create'&&o.actorId==='realmA'));
    const response=grantTestStage(model,scenario==='lab-ciba-push'?'push':'tokens');
    assert.equal(response.payload.find(p=>p.attributeId===id)?.value,'Bearer',scenario+' has explicit wire value');
    assert.equal(response.payload.find(p=>p.attributeId===id)?.name,'token_type');
    assert.deepEqual(response.attributeOperations.filter(o=>o.attributeId===id).map(o=>[o.kind,o.actorId]),[['send','realmA'],['receive','app']]);
    const interpretation=grantTestStage(model,scenario==='lab-ciba-push'?'push-check':'validate');
    assert.ok(interpretation.attributeOperations.some(o=>o.attributeId===id&&o.kind==='verify'&&o.actorId==='app'));
    assert.match(interpretation.detail,/token_type=Bearer/);
    const callback=grantTestStage(model,scenario==='lab-ciba-push'?'push':'ping');
    if(callback){
      const auth=callback.payload.find(p=>p.name==='Authorization');
      assert.notEqual(auth?.attributeId,id,'Callback sender authentication is distinct from result token usage.');
      if(scenario!=='lab-ciba-push')assert.ok(!callback.fields.includes(id),'Ping remains a handle-only notification.');
    }
  }
});

test('the actor client-credentials result carries OAuth Bearer metadata before any token exchange',()=>{
  const model=grantTestModel('lab-exchange-delegation'),stage=grantTestStage(model,'actor-result');
  assert.equal(stage.payload.find(p=>p.name==='token_type')?.value,'Bearer');
  assert.ok(stage.payload.some(p=>p.name==='access_token'));
  assert.ok(!stage.payload.some(p=>p.name==='issued_token_type'));
  const id=stage.payload.find(p=>p.name==='token_type').attributeId;
  assert.deepEqual(stage.attributeOperations.filter(o=>o.attributeId===id).map(o=>[o.kind,o.actorId]),[['create','realmA'],['send','realmA'],['receive','app'],['verify','app']]);
  assert.match(grantTestStage(model,'subject-response').detail,/not a complete token-response JSON example.*token_type.*omitted/);
});

test('Keycloak V2 ID and refresh result wrappers preserve issued types and avoid invented response members',()=>{
  const idModel=grantTestModel('lab-exchange-id-token'),idResponse=grantTestStage(idModel,'response');
  assert.equal(idResponse.payload.some(p=>p.name==='id_token'),false);assert.ok(idResponse.payload.some(p=>p.name==='access_token'));
  assert.equal(idResponse.payload.find(p=>p.name==='issued_token_type').value,'urn:ietf:params:oauth:token-type:id_token');assert.equal(idResponse.payload.find(p=>p.name==='token_type').value,'N_A');
  assert.match(grantTestStage(idModel,'interpret').detail,/never|Check issued_token_type/);assert.match(grantTestStage(idModel,'interpret').summary,/does not use it as an API bearer/);
  const refreshModel=grantTestModel('lab-exchange-refresh-token'),response=grantTestStage(refreshModel,'response');
  assert.equal(response.payload.find(p=>p.name==='issued_token_type').value,'urn:ietf:params:oauth:token-type:refresh_token');assert.equal(response.payload.find(p=>p.name==='token_type').value,'Bearer');assert.ok(response.payload.some(p=>p.name==='access_token'));assert.ok(response.payload.some(p=>p.name==='refresh_token'));
  assert.match(refreshModel.supportNote,/Allow refresh token.*Same session.*valid existing online subject session/);assert.match(grantTestStage(refreshModel,'policy').detail,/explicit refresh-exchange option is Same session.*existing valid subject session is online/);
  assert.equal(refreshModel.definitions()[grantTestIdByName(refreshModel,'Allow refresh token in Standard Token Exchange (local)')].example,'Same session');
  assert.match(grantTestStage(refreshModel,'policy').detail,/Reject a transient or offline subject session and scope=offline_access/);
  assert.match(grantTestStage(refreshModel,'policy').detail,/never creates a new user session.*requester’s client session within the same existing user session/);
});

test('refresh-result response semantics are explicitly pinned to the documented Keycloak convention',()=>{
  const model=grantTestModel('lab-exchange-refresh-token'),response=grantTestStage(model,'response');
  assert.match(model.supportNote,/Keycloak 26\.8\.0 documented provider convention/);
  assert.match(response.title,/Keycloak.*convention/);
  assert.match(response.detail,/RFC 8693 §2\.2\.1.*token carried by access_token.*provider-specific/);
  assert.match(model.definitions()[grantTestIdByName(model,'issued_token_type')].standard,/Keycloak 26\.8\.0/);
  assert.equal(response.payload.find(p=>p.name==='issued_token_type').value,'urn:ietf:params:oauth:token-type:refresh_token');
  assert.equal(response.payload.find(p=>p.name==='access_token').value,'<exchanged access token>');
  assert.equal(response.payload.find(p=>p.name==='refresh_token').value,'<policy-authorized exchange refresh token>');
  assert.match(grantTestStage(model,'interpret').detail,/rather than assuming issued_token_type=refresh_token changes the access_token member into a refresh credential/);
});

test('Preview delegation requires actual permission and consent before may_act, actor-token comparison and act result',()=>{
  const model=grantTestModel('lab-exchange-delegation'),steps=model.steps(),defs=model.definitions(),mint=grantTestStage(model,'mint-subject'),exchange=grantTestStage(model,'exchange'),check=grantTestStage(model,'relationship'),result=grantTestStage(model,'result');
  assert.equal(model.status,'preview');assert.match(model.supportNote,/FGAP V2.*consent/);
  assert.ok(steps.indexOf(grantTestStage(model,'permission'))<steps.indexOf(mint));assert.ok(steps.indexOf(grantTestStage(model,'consent'))<steps.indexOf(mint));
  assert.ok(mint.attributeOperations.some(o=>o.attributeId===grantTestIdByName(model,'may_act')&&o.kind==='create'));
  for(const name of ['subject_token','subject_token_type','actor_token','actor_token_type'])assert.ok(exchange.payload.some(p=>p.name===name),name);
  assert.match(check.detail,/distinct subject and actor.*may_act\.sub\/client_id/);assert.match(check.detail,/no refresh token or session identifier/);
  assert.ok(result.payload.some(p=>p.name==='act'));assert.equal(result.payload.some(p=>p.name==='may_act'),false);
  assert.equal(result.payload.find(p=>p.name==='issued_token_type').value,'urn:ietf:params:oauth:token-type:access_token');assert.equal(result.payload.find(p=>p.name==='token_type').value,'Bearer');
  for(const name of ['issued_token_type','token_type']){
    const id=grantTestIdByName(model,name);assert.ok(check.attributeOperations.some(o=>o.attributeId===id&&o.kind==='create'));assert.ok(grantTestWire(result).some(o=>o.attributeId===id&&o.kind==='receive'&&o.actorId==='app'));
  }
  assert.match(grantTestStage(model,'handoff').detail,/own service-account access token/);assert.doesNotMatch(grantTestStage(model,'handoff').detail,/identity token/);
  assert.equal(steps.some(s=>s.payload.some(p=>p.name==='refresh_token')),false);assert.ok(defs[grantTestIdByName(model,'act')].purpose.includes('actor-app'));
});

test('external-to-Keycloak chaining keeps JWT authorization and internal V2 exchange as two separate grants',()=>{
  const model=grantTestModel('lab-exchange-external-in'),jwt=grantTestStage(model,'jwt-request'),v2=grantTestStage(model,'v2'),trust=grantTestStage(model,'trust');
  assert.equal(model.status,'supported');assert.equal(jwt.payload.find(p=>p.name==='grant_type').value,'urn:ietf:params:oauth:grant-type:jwt-bearer');assert.ok(jwt.payload.some(p=>p.name==='assertion'));assert.equal(jwt.payload.some(p=>p.name==='subject_token'),false);
  assert.equal(v2.payload.find(p=>p.name==='grant_type').value,'urn:ietf:params:oauth:grant-type:token-exchange');assert.ok(v2.payload.some(p=>p.name==='subject_token'));assert.equal(v2.payload.some(p=>p.name==='assertion'),false);
  assert.ok(model.steps().indexOf(grantTestStage(model,'local-result'))<model.steps().indexOf(v2));assert.match(trust.detail,/exactly one accepted Keycloak audience.*unique unused jti.*prior account link/);
  assert.ok(trust.attributeOperations.some(o=>o.attributeId===grantTestIdByName(model,'jti (assertion)')&&o.kind==='store'));assert.match(model.supportNote,/previously linked local user/);
});

test('deprecated internal-to-external retrieval reads a stored linked token without inventing a provider token exchange',()=>{
  const model=grantTestModel('lab-exchange-external-out'),steps=model.steps(),requestIndex=steps.indexOf(grantTestStage(model,'request'));
  assert.equal(model.status,'deprecated');assert.match(model.supportNote,/Preview.*deprecated.*FGAP V1/);assert.match(model.supportNote,/Identity Brokering APIs.*recommended/);
  assert.ok(grantTestStage(model,'request').payload.some(p=>p.name==='requested_issuer'));
  for(const step of steps.slice(requestIndex))assert.equal([step.from,step.to].includes('realmB'),false,'No new external provider backchannel during legacy retrieval.');
  assert.match(grantTestStage(model,'retrieval').detail,/no token-exchange backchannel/);assert.ok(grantTestStage(model,'retrieval').attributeOperations.some(o=>o.attributeId===grantTestIdByName(model,'Stored external token/account link (local)')&&o.kind==='use'));
  assert.equal(grantTestStage(model,'result').payload[0].name,'access_token');
});
