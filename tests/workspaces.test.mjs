import test from 'node:test';
import assert from 'node:assert/strict';
import {parseStudioRoute,studioRoute,workspaceOf,visibleActorId,scenarioPositions} from '../src/workspaces.js';
import {projectScenarioContext,scenarioContextRows} from '../src/scenario-context.js';
import {RuntimeEnvironment} from '../src/runtime-environment.js';
const models={ad:{id:'ad',workspace:'kerberos',family:'ad-ds'},bridge:{id:'bridge',workspace:'kerberos',family:'keycloak-bridge'},ssh:{id:'ssh',workspace:'ssh'}};
test('route allowlist owns workspaces, bridge identity and unknown fallback',()=>{
  for(const id of Object.keys(models)){const route=parseStudioRoute(studioRoute(id,models),models);assert.equal(route.scenarioId,id);assert.equal(route.workspace,workspaceOf(models[id]));}
  for(const route of ['#/ssh/https://evil.example','#/kerberos?realm=secret','#/web/__proto__','#/ssh/%73sh'])assert.equal(parseStudioRoute(route,models).valid,false);
  assert.equal(parseStudioRoute('#/web/basic-keycloak',models,['basic-keycloak']).scenarioId,'basic-keycloak');
});
test('parent grouping changes visible ownership only and positions remain actor-owned',()=>{
  const actors={kdc:{id:'kdc'},as:{id:'as',parentId:'kdc'},client:{id:'client'}};
  const steps=[{from:'client',to:'as',attributeOperations:[]}],model={positions:{kdc:{x:975,y:120},as:{x:560,y:365},client:{x:145,y:120}}};
  assert.equal(visibleActorId('as',actors),'kdc');assert.equal(visibleActorId('as',actors,true),'as');
  assert.deepEqual(Object.keys(scenarioPositions(model,steps,actors)),['client','kdc']);
  assert.deepEqual(Object.keys(scenarioPositions(model,steps,actors,true)),['client','as']);assert.equal(steps[0].to,'as');
});
test('runtime binding rebuilds declared scalar occurrences without inventing credentials or patching ciphertext',()=>{
  const model={initialState:{policy:{realm:'CORP.EXAMPLE'},credentials:{}},protocolValues:{realm:'CORP.EXAMPLE',opaque:'ciphertext(CORP.EXAMPLE)'},runtimeBindings:[{field:'kerberosRealm',attributeId:'realm',actorId:'kdc',label:'Realm',example:'CORP.EXAMPLE',statePaths:['policy.realm','credentials.tgt.realm'],valueRefs:['realm','opaque']}],actors:()=>({kdc:{context:[]}}),definitions:()=>({})};
  const steps=[{payload:[{attributeId:'realm',value:'CORP.EXAMPLE'},{attributeId:'ticket',value:'ciphertext(CORP.EXAMPLE)'}],attributeOperations:[{attributeId:'realm',value:'CORP.EXAMPLE'}],protocolEffects:[{op:'put',path:'credentials.tgt',value:{realm:'CORP.EXAMPLE',instanceId:'tgt-1'}}]}];
  const result=projectScenarioContext(model,steps,{kerberosRealm:'ACME.EXAMPLE'});
  assert.equal(result.steps[0].payload[0].value,'ACME.EXAMPLE');assert.equal(result.steps[0].payload[1].value,'ciphertext(CORP.EXAMPLE)');assert.equal(result.steps[0].protocolEffects[0].value.realm,'ACME.EXAMPLE');
  assert.deepEqual(result.initialState.credentials,{});assert.equal(result.protocolValues.opaque,'ciphertext(CORP.EXAMPLE)');assert.equal(model.initialState.policy.realm,'CORP.EXAMPLE');
  assert.equal(scenarioContextRows(model,'kdc',{kerberosRealm:'ACME.EXAMPLE'})[0].value,'ACME.EXAMPLE');
});
test('typed page-only environment validates SSH/Kerberos inputs and clears them on reset',()=>{
  const env=new RuntimeEnvironment();env.updateDraft({sshHost:'server.corp.example',caURL:'https://ca.corp.example',kerberosRealm:'CORP.EXAMPLE',servicePrincipal:'host/server.corp.example@CORP.EXAMPLE',unixAccount:'alice'});assert.equal(env.apply().ok,true);
  assert.equal(env.applied.sshHost,'server.corp.example');env.reset();assert.equal(env.applied.sshHost,'');
  for(const patch of [{sshHost:'https://server'},{servicePrincipal:'invalid'},{unixAccount:'alice;cat'},{kerberosRealm:'bad realm'}]){env.reset();env.updateDraft(patch);assert.equal(env.apply().ok,false);}
});
