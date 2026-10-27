import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {LEARNING_PRESETS} from '../src/learning-presets.js';
import {STUDIO_FAMILIES,studioRoute,studioVariantId,parseStudioRoute,studioWorkspaceOptions} from '../src/workspaces.js';
import {WINDOWS_SECURITY_COMPARISONS,windowsSecurityRelatedLessons} from '../src/windows-security-comparisons.js';
const contract=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/routing-contract.json',import.meta.url),'utf8'));
const metadata={
  'lab-wra01':{id:'lab-wra01',workspace:'windows',family:'windows-remote-administration',defaultVariantId:'local-admin-filtered',variantChoices:[{id:'local-admin-filtered'},{id:'ordinary-share'}]},
  'lab-wprot01':{id:'lab-wprot01',workspace:'windows',family:'windows-protection',defaultVariantId:'enabled',variantChoices:[{id:'enabled'},{id:'disabled-comparison'}]},
  'lab-wlog04':{id:'lab-wlog04',workspace:'workstations',family:'windows-logon',variantChoices:[{id:'default'},{id:'protected-user'}]},
};
for(const model of Object.values(metadata))for(const key of ['withVariant','steps','actors'])model[key]=()=>{throw new Error('Route validation must not evaluate a model');};
const wlogBase='#/workstations/windows-logon/lab-wlog04';
const wraBase='#/windows/remote-administration/lab-wra01';

test('new families retain concrete defaults and PAM remains in Linux sign-in',()=>{
  for(const expected of contract.familyDefaults){
    const family=STUDIO_FAMILIES.find(item=>item.workspace===expected.workspace&&item.id===expected.family);
    assert.ok(family);assert.equal(family.routeSegment,expected.routeSegment);assert.equal(family.defaultId,expected.scenarioId);
    assert.deepEqual(parseStudioRoute('#/'+expected.workspace+'/'+expected.routeSegment,LAB_MODELS),{workspace:expected.workspace,scenarioId:expected.scenarioId,valid:true});
  }
  assert.equal(LAB_MODELS['lab-pam01'].family,'linux-logon');
  const options=studioWorkspaceOptions(LAB_MODELS);
  for(const id of ['lab-wra01','lab-wprot01'])assert.ok(options.some(option=>option.scenarioId===id));
});

test('old no-case routes and result shapes stay unchanged across the entire actual registry',()=>{
  for(const [id,model] of Object.entries(LAB_MODELS)){
    const route=studioRoute(id,LAB_MODELS);
    assert.equal(route.includes('?'),false,id);
    assert.equal(studioRoute(id,LAB_MODELS,'default'),route,id);
    assert.deepEqual(parseStudioRoute(route,LAB_MODELS),{workspace:model.workspace||'web',scenarioId:id,valid:true},id);
  }
  for(const [id,path] of [['lab-dnssec01','resolution'],['lab-dnssec04','validation'],['lab-dnssec06','forwarding-trust'],['lab-dnssec02','signing-publication'],['lab-dnssec12','keys-delegation']]){
    assert.equal(studioRoute(id,LAB_MODELS),'#/dnssec/'+path+'/'+id);
    assert.deepEqual(parseStudioRoute('#/dnssec/'+path,LAB_MODELS),{workspace:'dnssec',scenarioId:id,valid:true});
  }
  const presetIds=LEARNING_PRESETS.map(preset=>preset.id);
  for(const id of ['core',...presetIds])assert.deepEqual(parseStudioRoute(studioRoute(id,LAB_MODELS),LAB_MODELS,presetIds),{workspace:'web',scenarioId:id,valid:true});
});

test('case routes serialize canonical selections and resolve runtime default aliases without evaluating',()=>{
  assert.equal(studioRoute('lab-wra01',metadata),wraBase);
  assert.equal(studioRoute('lab-wra01',metadata,'local-admin-filtered'),wraBase+'?case=local-admin-filtered');
  assert.equal(studioVariantId('lab-wra01',metadata),'local-admin-filtered');
  assert.deepEqual(parseStudioRoute(wraBase+'?case=default',metadata),{workspace:'windows',scenarioId:'lab-wra01',valid:true,variantId:'local-admin-filtered'});
  assert.deepEqual(parseStudioRoute(wraBase+'?case=ordinary-share',metadata),{workspace:'windows',scenarioId:'lab-wra01',valid:true,variantId:'ordinary-share'});
  assert.deepEqual(parseStudioRoute('#/windows/remote-administration?case=ordinary-share',metadata),{workspace:'windows',scenarioId:'lab-wra01',valid:true,variantId:'ordinary-share'});
  assert.deepEqual(parseStudioRoute(wlogBase+'?%63ase=%70rotected%2Duser',metadata),{workspace:'workstations',scenarioId:'lab-wlog04',valid:true,variantId:'protected-user'});
  assert.equal(studioRoute('lab-wlog04',metadata,'protected-user'),wlogBase+'?case=protected-user');
});

test('legacy canonical default aliases select the declared default without inventing another URL',()=>{
  const id='lab-dnssec05',base=studioRoute(id,LAB_MODELS);
  assert.equal(studioVariantId(id,LAB_MODELS,'unaware-stub'),'default');
  assert.equal(studioRoute(id,LAB_MODELS,'unaware-stub'),base);
  assert.deepEqual(parseStudioRoute(base+'?case=unaware-stub',LAB_MODELS),{workspace:'dnssec',scenarioId:id,valid:true,variantId:'default'});
  assert.equal(parseStudioRoute(base+'?case=unaware-stub-extra',LAB_MODELS).reason,'unknown-case');
});

test('every actual registered variant round trips and new default aliases resolve first named case',()=>{
  for(const [id,model] of Object.entries(LAB_MODELS))for(const choice of model.variantChoices||[]){
    if(choice.id==='default')continue;
    const parsed=parseStudioRoute(studioRoute(id,LAB_MODELS,choice.id),LAB_MODELS);
    assert.deepEqual(parsed,{workspace:model.workspace||'web',scenarioId:id,valid:true,variantId:choice.id},id+'/'+choice.id);
  }
  for(const prefix of ['lab-wra','lab-wprot','lab-pam'])for(const model of Object.values(LAB_MODELS).filter(model=>model.id.startsWith(prefix))){
    assert.equal(model.defaultVariantId,model.variantChoices[0].id,model.id);
    assert.equal(model.variantChoices.some(choice=>choice.id==='default'),false,model.id);
    assert.equal(studioVariantId(model.id,LAB_MODELS),model.defaultVariantId,model.id);
    assert.equal(parseStudioRoute(studioRoute(model.id,LAB_MODELS)+'?case=default',LAB_MODELS).variantId,model.defaultVariantId,model.id);
  }
});

test('unknown duplicate encoded empty and unsafe case queries fall back clearly before evaluation',()=>{
  const invalid=[
    ['?case=missing','unknown-case'],['?case=Protected-user','unknown-case'],
    ['?case=protected-user&case=protected-user','duplicate-case'],['?case=default&%63ase=protected-user','duplicate-case'],
    ['?case=','invalid-case'],['?case','invalid-case'],['?case=%','invalid-query'],['?case=%C0%AF','invalid-query'],
    ['?case=%00','invalid-case'],['?case=%0Aprotected-user','invalid-case'],['?case=%253Cscript%253E','invalid-case'],
    ['?case=protected+user','invalid-case'],['?case=../protected-user','invalid-case'],['?case=%3Cscript%3E','invalid-case'],
    ['?case=protected-user#extra','invalid-case'],['?case=protected-user&password=secret','unsupported-query'],['?','unsupported-query'],
  ];
  for(const [query,reason] of invalid){
    const result=parseStudioRoute(wlogBase+query,metadata);
    assert.deepEqual(result,{workspace:'workstations',scenarioId:'lab-wlog04',valid:false,reason},query);
    assert.equal(Object.hasOwn(result,'variantId'),false,query);
  }
  assert.equal(parseStudioRoute('#/web/core?case=default',metadata).reason,'unknown-case');
  assert.deepEqual(parseStudioRoute('#/windows/protection/unknown?case=anything',metadata),{workspace:'web',scenarioId:'basic-keycloak',valid:false});
  for(const selected of ['unknown','protected user','%70rotected-user','<script>',null])assert.throws(()=>studioRoute('lab-wlog04',metadata,selected),RangeError);
});

test('seven static comparisons link actual canonical destinations with the required boundaries',()=>{
  assert.equal(WINDOWS_SECURITY_COMPARISONS.length,contract.comparison.mechanismCount);
  for(const expected of contract.comparison.rows){
    const row=WINDOWS_SECURITY_COMPARISONS.find(item=>item.mechanism===expected.mechanism);
    assert.ok(row,expected.mechanism);assert.deepEqual(row.targets.map(target=>target.id),expected.targets);
    for(const target of row.targets){assert.ok(LAB_MODELS[target.id],target.id);assert.equal(parseStudioRoute(studioRoute(target.id,LAB_MODELS,target.variantId||'default'),LAB_MODELS).valid,true);}
  }
});

test('related lessons use explicit validated selections including protected-user and real RDP modes',()=>{
  const all=[];
  for(const id of Object.keys(LAB_MODELS))for(const target of windowsSecurityRelatedLessons(id)){
    assert.ok(LAB_MODELS[target.id],id+' -> '+target.id);
    assert.ok(target.title&&target.summary);
    const parsed=parseStudioRoute(studioRoute(target.id,LAB_MODELS,target.variantId||'default'),LAB_MODELS);
    assert.equal(parsed.valid,true,id+' -> '+target.id);
    if(target.variantId)assert.equal(parsed.variantId,target.variantId);
    all.push(target);
  }
  assert.ok(all.some(target=>target.id===contract.comparison.requiredRelatedCase.id&&target.variantId==='protected-user'));
  for(const id of contract.comparison.requiredRelatedDestinations)assert.ok(all.some(target=>target.id===id),id);
  for(const id of ['lab-wlog01','lab-wlog02','lab-welev01','lab-welev06'])assert.ok(windowsSecurityRelatedLessons(id).length,id+' shortcut');
  assert.deepEqual(windowsSecurityRelatedLessons('unknown'),[]);assert.deepEqual(windowsSecurityRelatedLessons('__proto__'),[]);
  assert.ok(Object.isFrozen(WINDOWS_SECURITY_COMPARISONS));assert.ok(Object.isFrozen(windowsSecurityRelatedLessons('lab-wprot03')));
});
