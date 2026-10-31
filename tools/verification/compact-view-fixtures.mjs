import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {types} from 'node:util';

export const COMPACT_ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
export const COMPACT_CONTROL='/home/andrico/.cache/auth-lab-held-qa/windows-protection-independent-relocation-07-ieT06V/source';
export const compactHash=value=>createHash('sha256').update(value).digest('hex');
// Tagged encoding is lossless for undefined, sparse arrays, -0 and typed data.
// Object key order alone is presentation; no protocol field is dropped.
export function compactEncode(value,seen=new Set()) {
  if(value===undefined)return ['undefined'];
  if(value===null)return ['null'];
  const type=typeof value;
  if(type==='number')return ['number',Object.is(value,-0)?'-0':String(value)];
  if(type==='bigint')return ['bigint',String(value)];
  if(type==='string'||type==='boolean')return [type,value];
  if(type!=='object')throw new TypeError('Unsupported canonical data: '+type);
  if(seen.has(value))throw new TypeError('Cyclic canonical data');seen.add(value);
  let encoded;
  if(Array.isArray(value))encoded=['array',Array.from({length:value.length},(_,i)=>Object.hasOwn(value,i)?compactEncode(value[i],seen):['hole'])];
  else if(ArrayBuffer.isView(value))encoded=['typed',value.constructor.name,Buffer.from(value.buffer,value.byteOffset,value.byteLength).toString('hex')];
  else if(value instanceof ArrayBuffer)encoded=['buffer',Buffer.from(value).toString('hex')];
  else if(value instanceof Date)encoded=['date',value.toISOString()];
  else if(value instanceof Map)encoded=['map',[...value].map(([k,v])=>[compactEncode(k,seen),compactEncode(v,seen)])];
  else if(value instanceof Set)encoded=['set',[...value].map(v=>compactEncode(v,seen))];
  else encoded=['object',Object.keys(value).sort().map(key=>[key,compactEncode(value[key],seen)])];
  seen.delete(value);return encoded;
}
export const compactStable=value=>JSON.stringify(compactEncode(value));


export const compactId=(kind,value)=>kind+'-'+compactHash(compactStable(value)).slice(0,24);
export const compactImport=(root,name)=>import(pathToFileURL(path.join(root,name)).href);

export function compactInputIdentity(root,extra=[]) {
  const names=[];
  const walk=relative=>{
    const absolute=path.join(root,relative),stat=fs.lstatSync(absolute);
    assert.ok(!stat.isSymbolicLink(),'Input symlink: '+relative);
    if(stat.isDirectory())for(const name of fs.readdirSync(absolute).sort())walk(relative+'/'+name);
    else {assert.ok(stat.isFile(),'Regular input: '+relative);names.push(relative);}
  };
  for(const name of ['src','tests','assets','index.html','build.mjs','package.json','security-policy.mjs','dist/auth-flow-studio.html'])walk(name);
  const files=Object.fromEntries(names.sort().map(name=>[name,compactHash(fs.readFileSync(path.join(root,name)))]));
  const external=Object.fromEntries([...new Set([fileURLToPath(import.meta.url),...extra])].sort().map(name=>[name,compactHash(fs.readFileSync(name))]));
  return {files,external,sha256:compactHash(compactStable({files,external})),htmlSha256:files['dist/auth-flow-studio.html']};
}

export async function compactRegistry(root) {
  const {installHarness}=await compactImport(root,'tests/dom-harness.mjs');
  const harness=installHarness();
  const presets=await compactImport(root,'src/learning-presets.js');
  const catalog=await compactImport(root,'src/lab-catalog.js');
  const helper=await compactImport(root,'tools/verification/held-object-fixtures.mjs');
  return {root,harness,...presets,...catalog,...helper};
}
export function compactEnumerate(registry) {
  const {LEARNING_PRESETS,LAB_SCENARIOS,LAB_MODELS,heldCoreConfigurations}=registry;
  const presetIds=new Set(LEARNING_PRESETS.map(p=>p.id));
  const choices=[...LEARNING_PRESETS.map(p=>({id:p.id,label:p.title,kind:'preset',modelId:p.modelId||null,category:p.category,summary:p.summary,profile:p.profile||null})),{id:'core',label:'Core lab · configurable sign-in, SAML, FIDO and grants',kind:'configurable-core',modelId:null,category:'Custom configuration',summary:'Explore your own combination using Advanced configuration.'},...LAB_SCENARIOS.filter(m=>!presetIds.has(m.id)).map(m=>({id:m.id,label:m.title,kind:'registered-model',modelId:m.id,category:m.category,summary:m.summary,status:m.status,workspace:m.workspace||'web',profile:m.profile||null}))];
  assert.equal(choices.length,328,'Actual deduplicated picker inventory');assert.equal(new Set(choices.map(c=>c.id)).size,choices.length);
  assert.equal(LEARNING_PRESETS.length,12,'Actual presets');
  const cases=[],variants=[],members=[];
  let registeredVariantChoices=0,defaultOnlyModels=0;
  const add=entry=>{entry.id=compactId('case',entry);cases.push(entry);};
  for(const choice of choices){
    const base=LAB_MODELS[choice.modelId||choice.id];
    if(!base){add({choiceId:choice.id,variant:'default',member:null,kind:choice.kind,configuration:{}});continue;}
    const registered=base.variantChoices?.length?base.variantChoices:[{id:'default',label:'Default'}];
    if(base.variantChoices?.length)registeredVariantChoices+=base.variantChoices.length;else defaultOnlyModels++;
    for(const variant of registered){
      const selected=variant.id==='default'||variant.id===base.defaultVariantId?base:base.withVariant(variant.id);
      variants.push({choiceId:choice.id,modelId:base.id,...variant});
      // The default is a real selectable state even when it aliases the first member.
      add({choiceId:choice.id,variant:variant.id,member:null,kind:'registered-case',configuration:{}});
      for(const member of selected.subfixtureChoices||[]){
        assert.equal(typeof selected.withSubfixture,'function');
        members.push({choiceId:choice.id,variant:variant.id,...member});
        add({choiceId:choice.id,variant:variant.id,member:member.id,kind:'registered-member',configuration:{}});
      }
    }
  }
  const core=[];
  for(const configuration of heldCoreConfigurations()){
    const entry={choiceId:'core',variant:'default',member:null,kind:'supported-core-configuration',configuration};
    entry.id=compactId('case',entry);core.push(entry);
  }
  assert.equal(new Set(core.map(c=>c.id)).size,core.length,'Supported Core configurations have unique normalized inputs');
  cases.push(...core);
  return {schemaVersion:1,kind:'compact-view-frozen-catalog',scope:'Registry metadata only; no semantic, DOM, device or human acceptance',choices,variants,members,cases,counts:{pickerIdentities:choices.length,presets:LEARNING_PRESETS.length,registeredVariantChoices,defaultOnlyModels,variantAndDefaultStates:variants.length,registeredComparisonMembers:members.length,supportedCoreConfigurations:core.length,finiteCases:cases.length},status:'unperformed'};
}

const compactDeepSelectors=[
  ['Core/web','basic-keycloak'],['Core/web','core'],['Core/web','lab-spa-api'],['Core/web','lab-bff-api'],
  ['SSH','lab-ssh-cert-success'],['SSH','lab-ssh-cert-principal'],
  ['Kerberos','lab-ad-pkinit-success'],['Kerberos','lab-ad-pkinit-kdc-trust'],['Kerberos','lab-ad-fast-tgs-success'],
  ['Forests','lab-ad-forest-one-way'],['Forests','lab-ad-forest-one-way-reverse'],
  ['Windows/RDP','lab-win-rdp-remote-credential-guard'],['Windows/RDP','lab-win-rdp-rcg-kerberos-unavailable'],['Windows/RDP','lab-wra01','default-filtered'],['Windows/RDP','lab-wra01','full-token-acl-denied'],['Windows/RDP','lab-wprot03','fresh-authentication'],
  ['SMB','lab-smb-nonjoined-kerberos'],['SMB','lab-smb-nonjoined-share-denied'],['SMB','lab-smb-multichannel-binding-success'],
  ['RADIUS','lab-net-eap-tls13-wired'],['RADIUS','lab-net-radius-udp-radsec'],['RADIUS','lab-net-radius-disconnect-ack'],
  ['PAKE/JWT','lab-pake-spake2-success'],['PAKE/JWT','lab-pake-spake2-password-mismatch'],['PAKE/JWT','lab-jwt03','invalid-inner-signature'],['PAKE/JWT','lab-jwt08','id-substitution'],
  ['PAM/sudo','lab-lelev01','wrong-password'],['macOS','lab-mlog01','unlock-password'],['macOS','lab-melev01','right-denied'],
  ['NFS','lab-nfs-v42-kerberos-read','read-denied'],['NFS','lab-nfs-v3-auth-sys','root-squash'],['NFS','lab-nfs-gss-protection','krb5i'],
  ['Kubernetes','lab-k8s04','bob'],['Kubernetes','lab-k8s06','pod-log-denied'],['Kubernetes','lab-k8s09','cached-old-expired'],
  ['MCP','lab-mcp01','default'],['MCP','lab-mcp09','upstream-consent-denied'],['MCP','lab-mcp13','os-denied'],
  ['DNSSEC','lab-dnssec01','warm-answer-cache'],['DNSSEC','lab-dnssec06','both-validate'],['DNSSEC','lab-dnssec15','rfc5011-add'],['DNSSEC/DNS-R10','lab-dnssec09','cname-bogus-target'],
];
export function compactDeepFixtures(catalog) {
  const fixtures=[];
  const resolve=(group,choiceId,variant='default',member=null)=>{
    let entry=catalog.cases.find(c=>c.choiceId===choiceId&&c.variant===variant&&c.member===member&&c.kind!=='supported-core-configuration');
    // Some named defaults have a real non-default ID. Resolve from registry, never invent a URL alias.
    if(!entry&&variant==='default')entry=catalog.cases.find(c=>c.choiceId===choiceId&&c.member===member&&c.kind!=='supported-core-configuration');
    assert.ok(entry,'Missing MC17 selector: '+[choiceId,variant,member].filter(Boolean).join('/'));
    if(!fixtures.some(f=>f.caseId===entry.id))fixtures.push({id:compactId('deep',{group,caseId:entry.id}),group,caseId:entry.id,selector:{choiceId:entry.choiceId,variant:entry.variant,member:entry.member},kind:'registered',status:'unperformed',operations:['initial','every-authored-prefix','terminal','rewind','field-history','exact-history','switch-continuity']});
  };
  for(const args of compactDeepSelectors)resolve(...args);
  for(const member of ['change-success','change-prelim-failure','change-update-failure','change-unsupported'])resolve('PAM01','lab-pam01','password-change-required',member);
  for(const variant of ['default','new-policy-denied','update-failed','directory-unreachable','directory-online','post-change-account-denied'])resolve('LLOG04/reached-change','lab-llog04',variant);
  // Include every actual SAML/direct-FIDO registration, including the registered failure branches.
  for(const choice of catalog.choices.filter(c=>/saml|fido|webauthn|passkey/i.test(c.id+' '+c.label)))
    for(const entry of catalog.cases.filter(c=>c.choiceId===choice.id))resolve('SAML/FIDO actual registry',entry.choiceId,entry.variant,entry.member);
  for(const entry of catalog.cases.filter(c=>c.kind==='supported-core-configuration'&&['fido-login','fido-enrollment'].includes(c.configuration.mode))){
    fixtures.push({id:compactId('deep',{group:'Direct FIDO positive Core configurations',caseId:entry.id}),group:'Direct FIDO positive Core configurations',caseId:entry.id,selector:{choiceId:'core',configuration:entry.configuration},kind:'supported-core-configuration',status:'unperformed',operations:['initial','every-authored-prefix','terminal','rewind','field-history','exact-history','switch-continuity']});
  }
  const sourceOnly={choiceId:'lab-llog04',variant:'default',member:null,kind:'source-only-factory',configuration:{},factory:{module:'src/linux-logon-lab.js',export:'createLinuxPasswordChangeCase',baseline:'lab-llog04',overrides:{prelimOk:false}}};
  sourceOnly.id=compactId('case',sourceOnly);
  fixtures.push({id:compactId('deep',sourceOnly),group:'PAM/sudo source-only',caseId:sourceOnly.id,selector:sourceOnly,kind:'source-only-factory',lesson:false,url:false,status:'unperformed',operations:['initial','every-authored-prefix','terminal','rewind','field-history','exact-history','switch-continuity']});
  return {schemaVersion:1,kind:'compact-view-MC17-deep-fixtures',fixtures,sourceOnlyCases:[sourceOnly],counts:{uniqueFixtures:fixtures.length,registeredFixtures:fixtures.filter(f=>f.kind==='registered').length,supportedCoreFixtures:fixtures.filter(f=>f.kind==='supported-core-configuration').length,sourceOnlyFactories:1},status:'unperformed'};
}

// Compilation keeps its original application inputs. Only the collector's
// detached serializable mirror is frozen, preserving aliases and leaving
// stateful built-ins mutable so graph identity reuse cannot hide their changes.
function compactOwnedMirror(value) {
  const memo=new WeakMap(),owned=[],shared=[];
  const typedName=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),Symbol.toStringTag).get;
  const copy=(input,location)=>{
    if(input===null||typeof input!=='object'){
      if(typeof input==='function'||typeof input==='symbol')throw new TypeError('Non-cloneable Compact fixture field: '+location+' ('+typeof input+')');
      return input;
    }
    if(memo.has(input))return memo.get(input);
    if(types.isProxy(input))throw new TypeError('Non-cloneable Compact fixture proxy: '+location);
    let output;
    if(ArrayBuffer.isView(input)){
      const buffer=copy(input.buffer,location+'.buffer');
      output=types.isDataView(input)?new DataView(buffer,input.byteOffset,input.byteLength):new globalThis[typedName.call(input)](buffer,input.byteOffset,input.length);
      Object.setPrototypeOf(output,Object.getPrototypeOf(input));
      memo.set(input,output);
      const constructor=Object.getOwnPropertyDescriptor(input,'constructor');
      if(constructor){
        if(!Object.hasOwn(constructor,'value'))throw new TypeError('Non-cloneable Compact fixture accessor: '+location+'.constructor');
        Object.defineProperty(output,'constructor',{value:Object.freeze({name:input.constructor.name}),configurable:true});
      }
      return output;
    }
    if(input instanceof ArrayBuffer||types.isSharedArrayBuffer(input)){
      output=types.isSharedArrayBuffer(input)?new SharedArrayBuffer(input.byteLength):new ArrayBuffer(input.byteLength);
      new Uint8Array(output).set(new Uint8Array(input));
      memo.set(input,output);
      if(types.isSharedArrayBuffer(input))shared.push([input,output,location]);
      return output;
    }
    if(input instanceof Date){
      if(input.toISOString!==Date.prototype.toISOString)throw new TypeError('Non-cloneable Compact fixture Date hook: '+location);
      output=new Date(Date.prototype.getTime.call(input));memo.set(input,output);return output;
    }
    if(input instanceof Map){
      output=new Map();memo.set(input,output);
      for(const [key,item] of input)output.set(copy(key,location+'.<map-key>'),copy(item,location+'.<map-value>'));
      return output;
    }
    if(input instanceof Set){
      output=new Set();memo.set(input,output);
      for(const item of input)output.add(copy(item,location+'.<set-value>'));
      return output;
    }
    const array=Array.isArray(input);
    output=array?new Array(input.length):Object.create(Object.getPrototypeOf(input)===null?null:Object.prototype);
    memo.set(input,output);owned.push(output);
    const keys=array?Array.from({length:input.length},(_,index)=>String(index)).filter(key=>Object.hasOwn(input,key)):Object.keys(input);
    for(const key of keys){
      const descriptor=Object.getOwnPropertyDescriptor(input,key);
      if(!Object.hasOwn(descriptor,'value'))throw new TypeError('Non-cloneable Compact fixture accessor: '+location+'.'+key);
      Object.defineProperty(output,key,{value:copy(descriptor.value,location+'.'+key),enumerable:true,writable:true,configurable:true});
    }
    return output;
  };
  const mirror=copy(value,'fixture');
  // Shared buffers are object-tagged by compactEncode. Populate their own
  // fields after allocating views so buffer-to-view cycles keep their aliases.
  for(let index=0;index<shared.length;index++){
    const [input,output,location]=shared[index];
    for(const key of Object.keys(input)){
      const descriptor=Object.getOwnPropertyDescriptor(input,key);
      if(!Object.hasOwn(descriptor,'value'))throw new TypeError('Non-cloneable Compact fixture accessor: '+location+'.'+key);
      Object.defineProperty(output,key,{value:copy(descriptor.value,location+'.'+key),enumerable:true,writable:true,configurable:true});
    }
  }
  for(const node of owned)Object.freeze(node);
  return mirror;
}

export async function compactFixture(registry,entry) {
  const fixture=registry.makeHeldObjectFixture(entry.choiceId,{...entry.configuration,lessonVariant:entry.variant,lessonSubfixture:entry.member});
  const {app}=fixture;
  if(entry.kind==='source-only-factory'){
    const module=await compactImport(registry.root,entry.factory.module);
    const model=module[entry.factory.export]({...registry.LAB_MODELS[entry.factory.baseline].fixture,...entry.factory.overrides});
    Object.defineProperty(app,'labModel',{configurable:true,value:model});app.scenarioMemo.clear();
  }
  const source=app.scenarioSnapshot(),base=app.labModel;
  const model=base?{...base,steps:()=>source.steps,initialState:source.initialState||base.initialState,protocolValues:source.protocolValues||base.protocolValues}:null;
  const {resolveActor}=await compactImport(registry.root,'src/player.js');
  const actorIds=[...new Set(source.steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(operation=>operation.actorId)]).map(id=>resolveActor(id,app.authenticator)))];
  const actors=model?.workspace?model.actors(app.protocolConfig()):Object.fromEntries(actorIds.map(id=>[id,app.actor(id)]));
  const config={...app.protocolConfig(),oidcFlow:app.oidcFlow,tokenProtection:app.tokenProtection,assertionProtection:app.assertionProtection};
  const {buildHeldObjects}=await compactImport(registry.root,'src/held-objects.js');
  const compiled=buildHeldObjects({choiceId:entry.choiceId,model,steps:source.steps,actors,config,contextId:entry.id});
  const {projectHeldObjects,heldObjectTrace,inspectHeldObject}=await compactImport(registry.root,'src/held-object-state.js');
  const inventories=Object.fromEntries(Object.entries(model||{}).filter(([key])=>/inventor/i.test(key)));
  const authored={steps:source.steps,actors,config,initialState:projectHeldObjects(compiled).state,inventories,scenarioSnapshot:source,plan:compiled.plan};
  const mirror=compactOwnedMirror({authored,initialState:model?.initialState,protocolValues:model?.protocolValues});
  const owned=mirror.authored,ownedSource=owned.scenarioSnapshot;
  const ownedModel=model?{...model,...owned.inventories,steps:()=>ownedSource.steps,initialState:ownedSource.initialState||mirror.initialState,protocolValues:ownedSource.protocolValues||mirror.protocolValues}:null;
  return {app,model:ownedModel,source:ownedSource,actors:owned.actors,config:owned.config,inventories:owned.inventories,compiled,authored:owned,studyActor:id=>owned.actors[resolveActor(id,app.authenticator)]||owned.actors[id],project:cursor=>projectHeldObjects(compiled,cursor),trace:artifactId=>heldObjectTrace(compiled,artifactId),inspect:(snapshot,id)=>inspectHeldObject(snapshot,id)};
}
