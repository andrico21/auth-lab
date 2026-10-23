import test from 'node:test';
import assert from 'node:assert/strict';
import {parseStudioRoute,studioRoute,workspaceOf,visibleActorId,scenarioPositions} from '../src/workspaces.js';
import {projectScenarioContext,scenarioContextRows} from '../src/scenario-context.js';
import {RuntimeEnvironment} from '../src/runtime-environment.js';
import {readFileSync} from 'node:fs';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {CARD_BOUNDS,GRAPH_WIDTH,GRAPH_HEIGHT,validateLayoutRoutes} from '../src/layout.js';
const planned=JSON.parse(readFileSync(new URL('../docs/expansion/plan-manifest.json',import.meta.url),'utf8')).scenarios;
const plannedWorkspace={windows:'windows',network:'network','kerberos-spake':'kerberos',pake:'foundations'};
const roots=[
  ['web','basic-keycloak'],['ssh','lab-ssh-cert-success'],['kerberos','lab-ad-first-sign-in'],
  ['windows','lab-win-ntlmv2-domain'],['network','lab-net-eap-tls13-wired'],['foundations','lab-pake-spake2-success'],
  ['kerberos/keycloak','lab-kc-kerberos-sso'],['kerberos/mit','lab-krb-spake-success'],
  ['windows/integrated','lab-win-ntlmv2-domain'],['windows/desktop','lab-win-rdp-normal'],['windows/management','lab-win-winrm-second-hop-denied'],
  ['network/access','lab-net-eap-tls13-wired'],['network/lifecycle','lab-net-radius-accounting-lifecycle'],['network/transport','lab-net-radius-udp-radsec'],
  ['foundations/spake2','lab-pake-spake2-success'],['foundations/spake2plus','lab-pake-spake2plus-success'],
];
const models={ad:{id:'ad',workspace:'kerberos',family:'ad-ds'},bridge:{id:'bridge',workspace:'kerberos',family:'keycloak-bridge'},ssh:{id:'ssh',workspace:'ssh'}};
test('route allowlist owns workspaces, bridge identity and unknown fallback',()=>{
  for(const id of Object.keys(models)){const route=parseStudioRoute(studioRoute(id,models),models);assert.equal(route.scenarioId,id);assert.equal(route.workspace,workspaceOf(models[id]));}
  for(const route of ['#/ssh/https://evil.example','#/kerberos?realm=secret','#/web/__proto__','#/ssh/%73sh'])assert.equal(parseStudioRoute(route,models).valid,false);
  assert.equal(parseStudioRoute('#/web/basic-keycloak',models,['basic-keycloak']).scenarioId,'basic-keycloak');
});
test('workspace and family root URLs select their declared default rather than Web fallback',()=>{
  for(const [path,scenarioId] of roots)assert.deepEqual(parseStudioRoute('#/'+path,LAB_MODELS),{workspace:path.split('/')[0],scenarioId,valid:true},path);
});
test('every independently planned preset has an allowlisted leaf route in its owning workspace',()=>{
  for(const {id,family} of planned){
    const workspace=plannedWorkspace[family],route=studioRoute(id,LAB_MODELS);
    assert.equal(workspaceOf(LAB_MODELS[id]),workspace,id);
    assert.deepEqual(parseStudioRoute(route,LAB_MODELS),{workspace,scenarioId:id,valid:true},id);
    assert.equal(parseStudioRoute(route.replace('#/'+workspace+'/','#/web/'),LAB_MODELS).valid,false,id);
  }
});
test('unknown explicit workspaces and families are errors, while untagged legacy models remain Web',()=>{
  assert.equal(workspaceOf({id:'legacy'}),'web');
  for(const workspace of ['unknown','',null,'__proto__'])assert.throws(()=>workspaceOf({workspace}),RangeError);
  assert.throws(()=>studioRoute('bad',{bad:{id:'bad',workspace:'unknown'}}),RangeError);
  assert.throws(()=>studioRoute('bad',{bad:{id:'bad',workspace:'windows',family:'ad-ds'}}),RangeError);
  for(const hash of ['', '#', '#/web', '#/web/basic-keycloak'])assert.deepEqual(parseStudioRoute(hash,LAB_MODELS,['basic-keycloak']),{workspace:'web',scenarioId:'basic-keycloak',valid:true});
  assert.deepEqual(parseStudioRoute('#/web/core',LAB_MODELS),{workspace:'web',scenarioId:'core',valid:true});
  for(const path of ['unknown','windows/mit','kerberos/desktop','network/spake2','foundations/access','windows/desktop/lab-win-ntlmv2-domain','kerberos/lab-krb-spake-success','foundations/spake2/lab-pake-spake2plus-success','network/access/lab-net-radius-accounting-lifecycle']){
    assert.deepEqual(parseStudioRoute('#/'+path,LAB_MODELS),{workspace:'web',scenarioId:'basic-keycloak',valid:false},path);
  }
});
test('parent grouping changes visible ownership only and positions remain actor-owned',()=>{
  const actors={kdc:{id:'kdc'},as:{id:'as',parentId:'kdc'},client:{id:'client'}};
  const steps=[{from:'client',to:'as',attributeOperations:[]}],model={positions:{kdc:{x:975,y:120},as:{x:560,y:365},client:{x:145,y:120}}};
  assert.equal(visibleActorId('as',actors),'kdc');assert.equal(visibleActorId('as',actors,true),'as');
  assert.deepEqual(Object.keys(scenarioPositions(model,steps,actors)),['client','kdc']);
  assert.deepEqual(Object.keys(scenarioPositions(model,steps,actors,true)),['client','as']);assert.equal(steps[0].to,'as');
});
test('expanded Windows roles retain separated cards and usable local/IPC graph ports',()=>{
  for(const [id,variant]of [['lab-wlog08','default'],['lab-welev03','domain-admin-credential']]){
    const model=variant==='default'?LAB_MODELS[id]:LAB_MODELS[id].withVariant(variant),steps=model.steps();
    const positions=scenarioPositions(model,steps,model.actors(),true),entries=Object.entries(positions);
    for(const [actor,{x,y}]of entries){
      assert.ok(x-CARD_BOUNDS.width/2>=10&&x+CARD_BOUNDS.width/2<=GRAPH_WIDTH-10,id+' '+actor+' horizontal bounds');
      assert.ok(y-CARD_BOUNDS.height/2>=10&&y+CARD_BOUNDS.height/2<=GRAPH_HEIGHT-10,id+' '+actor+' vertical bounds');
    }
    for(let i=0;i<entries.length;i++)for(let j=i+1;j<entries.length;j++){
      const [a,p]=entries[i],[b,q]=entries[j];
      assert.ok(Math.abs(p.x-q.x)>=CARD_BOUNDS.width+20||Math.abs(p.y-q.y)>=CARD_BOUNDS.height+20,id+' overlapping roles '+a+' / '+b);
    }
    assert.deepEqual(validateLayoutRoutes(positions,steps.map(step=>[step.from,step.to])),{ok:true},id+' retains routes for the actual IPC and local operations');
  }
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
