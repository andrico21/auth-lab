import test from 'node:test';
import assert from 'node:assert/strict';
import {SMBMULTI_SCENARIOS,SMBMULTI_ATTRIBUTES} from '../src/smb-multichannel-lab.js';
import {SMBLAB_SCENARIOS} from '../src/smb-access-lab.js';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {buildHeldObjects} from '../src/held-objects.js';
import {projectHeldObjects,inspectHeldObject,heldObjectTrace} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
Object.assign(ATTRIBUTES,SMBMULTI_ATTRIBUTES);
const model=suffix=>SMBMULTI_SCENARIOS.find(m=>m.id==='lab-smb-multichannel-binding-'+suffix);
const index=(m,stage)=>m.steps().findIndex(s=>s.smbStage===stage);
const at=(m,stage)=>reconstructProtocolState(m,index(m,stage)).smb;
const obj=(m,key)=>m.smbInventory.artifacts.find(a=>a.key===key);
const fixture=suffix=>{const m=model(suffix),steps=m.steps(),compiled=buildHeldObjects({model:m,steps,actors:m.actors(),config:{},choiceId:m.id,contextId:m.id+':test'});return {m,steps,compiled,frame:(stage,milestone='complete')=>projectHeldObjects(compiled,{eventIndex:index(m,stage),milestone})};};
const holding=(frame,a,actor,rep)=>frame.holdings.find(h=>h.artifactId===a.artifactId&&h.actorId===actor&&(!rep||h.representationId===rep));

test('Both multichannel lessons are registered modern SMB models and leave the base model untouched',()=>{
  const base=SMBLAB_SCENARIOS.find(m=>m.id==='lab-smb-nonjoined-kerberos');
  assert.equal(obj(base,'dialects').value.includes('MULTI_CHANNEL'),false);
  for(const m of SMBMULTI_SCENARIOS){assert.equal(LAB_MODELS[m.id],m);assert.equal(m.profile.dialect,'0x0311');assert.equal(m.family,'windows-files');assert.match(m.profile.kdfSourceDiscrepancy,/client binding HTML/);assert.match(m.profile.kdfSourceDiscrepancy,/server/);for(const key of ['dialects','server-offer'])assert.match(obj(m,key).value,/MULTI_CHANNEL/);assert.equal(m.steps().some(s=>s.id.startsWith(base.id)),false);}
});

test('Every boundary has complete ownership and every observation is supported by possession',()=>{
  for(const suffix of ['success','rejected']){const f=fixture(suffix);for(let i=-1;i<f.steps.length;i++){const state=projectHeldObjects(f.compiled,{eventIndex:i,milestone:i<0?'initial':'complete'});assert.equal(state.coverageStatus,'complete');if(i<0)continue;for(const e of f.m.smbInventory.events[f.steps[i].id].milestones.flatMap(m=>m.effects).filter(e=>e.op==='observe'))assert.ok(state.holdings.some(h=>h.artifactId===e.artifactId&&h.actorId===e.actorId&&h.representationId===e.representationId),f.steps[i].id+'/'+e.artifactId);}}
});

test('Second-connection messages have independent request matching and negotiation does not authenticate the channel',()=>{
  for(const m of SMBMULTI_SCENARIOS){const pending=new Map();for(const step of m.steps()){if(!step.smbFrame)continue;const f=step.smbFrame,k=f.connectionId+':'+f.messageId;if(f.status){assert.equal(pending.get(k),f.command,step.id);pending.delete(k);}else{assert.equal(pending.has(k),false);pending.set(k,f.command);}}assert.equal(pending.size,0);assert.equal(at(m,'mc-negotiate-check').channel2Negotiated,true);assert.equal(at(m,'mc-negotiate-check').channel2Usable,false);assert.equal(at(m,'mc-negotiate-check').serverAuthenticated,true);}
});

test('Binding uses existing Session.SigningKey, a fresh same-user GSS context and a new transcript-derived channel key',()=>{
  const m=model('success'),steps=m.steps(),binding=steps[index(m,'mc-binding-request')],reply=steps[index(m,'mc-binding-success')];
  assert.equal(binding.smbFrame.sessionId,'session-1');assert.equal(binding.smbFrame.binding,true);assert.equal(binding.smbFrame.encrypted,false);assert.equal(binding.smbFrame.signed,true);assert.equal(binding.layers[0].keyRef,obj(m,'signing-key').artifactId);
  assert.equal(reply.layers[0].keyRef,obj(m,'mc-channel-signing-key').artifactId);assert.equal(reply.smbFrame.preauthHashed,false);
  assert.match(obj(m,'mc-binding-request').value,/PreviousSessionId=0/);assert.match(obj(m,'mc-channel-signing-key').value,/binding GSS key/);assert.match(obj(m,'mc-channel-signing-key').value,/SMBSigningKey/);assert.match(obj(m,'mc-channel-signing-key').value,/mc-preauth-3/);
  assert.ok(index(m,'mc-gss-accept')<index(m,'mc-same-user'));assert.equal(at(m,'mc-same-user').bindingSameUser,true);assert.ok(index(m,'mc-same-user')<index(m,'mc-server-channel'));
  const tail=steps.slice(index(m,'mc-existing'));assert.equal(tail.some(s=>s.from==='smbDC'||s.to==='smbDC'),false);
});

test('No client channel or key appears before AP-REP verification and derivation; response receipt does not permit I/O',()=>{
  const f=fixture('success'),key=obj(f.m,'mc-gss-key'),signing=obj(f.m,'mc-channel-signing-key'),channel=obj(f.m,'mc-channel2');
  assert.equal(holding(f.frame('mc-binding-success'),key,'smbClient'),undefined);assert.equal(holding(f.frame('mc-binding-success'),signing,'smbClient'),undefined);assert.equal(holding(f.frame('mc-binding-success'),channel,'smbClient'),undefined);
  assert.ok(holding(f.frame('mc-client-gss'),key,'smbClient','plain'));assert.equal(holding(f.frame('mc-client-gss'),signing,'smbClient'),undefined);assert.ok(holding(f.frame('mc-client-channel-key'),signing,'smbClient','plain'));
  for(const stage of ['mc-server-channel','mc-binding-success','mc-client-gss','mc-client-channel-key'])assert.equal(at(f.m,stage).channel2Usable,false,stage);
  assert.equal(at(f.m,'mc-client-channel-verify').channel2Usable,true);assert.ok(index(f.m,'mc-client-channel-verify')<index(f.m,'mc-read-request'));
  const wire=holding(f.frame('mc-binding-success'),obj(f.m,'mc-ap-reply'),'smbClient','wire');assert.ok(wire);assert.match(inspectHeldObject(f.frame('mc-binding-success'),wire.holdingId).fields[0].value,/encrypted/);
});

test('Session and directional cipher keys are retained and never transmitted or regenerated by binding',()=>{
  const f=fixture('success'),keys=['session-key','signing-key','app-key','c2s-key','s2c-key'];
  const before=f.frame('mc-existing'),after=f.frame('mc-read-accept');for(const key of keys){const a=obj(f.m,key);for(const actor of ['smbClient','smbServer']){assert.ok(holding(before,a,actor,'plain'));assert.ok(holding(after,a,actor,'plain'));}assert.equal(f.steps.slice(index(f.m,'mc-existing')).flatMap(s=>f.m.smbInventory.events[s.id].milestones.flatMap(m=>m.effects)).some(e=>e.op==='create'&&e.artifactId===a.artifactId),false);}
  const localKeys=new Set([...keys,'mc-initiator-subkey','mc-gss-key','mc-channel-signing-key'].map(k=>obj(f.m,k).artifactId));for(const e of Object.values(f.m.smbInventory.events))for(const message of e.messages||[])for(const o of message.objects)assert.equal(localKeys.has(o.artifactId),false);
  for(const [stage,key] of [['mc-read-request','c2s-key'],['mc-read-response','s2c-key']]){const s=f.steps[index(f.m,stage)];assert.equal(s.layers[0].keyRef,obj(f.m,key).artifactId);assert.equal(s.smbFrame.encrypted,true);assert.equal(s.smbFrame.signed,false);assert.equal(s.smbFrame.connectionId,'tcp-2');assert.equal(s.smbFrame.treeId,'tree-1');}
  assert.match(obj(f.m,'mc-followup-read').value,/FileId=file-1/);
  for(const direction of ['C2S','S2C']){const nonces=f.m.smbInventory.artifacts.filter(a=>a.key.endsWith('-transform')).map(a=>a.value.match(new RegExp(direction+' nonce12 #(\\d+)'))?.[1]).filter(Boolean);assert.equal(new Set(nonces).size,nonces.length,direction);assert.deepEqual(nonces.map(Number),[1,2,3,4]);}
});

test('Encrypted I/O fields remain opaque until authenticated unwrap and data accepted only afterwards',()=>{
  for(const suffix of ['success','rejected']){const f=fixture(suffix),data=obj(f.m,'mc-read-data'),header=obj(f.m,'mc-read-response-header');for(const a of [data,header]){assert.equal(holding(f.frame('mc-read-response'),a,'smbClient','plain'),undefined);const h=holding(f.frame('mc-read-response'),a,'smbClient','ciphertext');assert.ok(h);assert.match(inspectHeldObject(f.frame('mc-read-response'),h.holdingId).fields[0].value,/Opaque AES128-GCM/);assert.ok(holding(f.frame('mc-read-response-unwrap'),a,'smbClient','plain'));}assert.equal(at(f.m,'mc-read-response-unwrap').followupFileRead,undefined);assert.equal(at(f.m,'mc-read-accept').followupFileRead,true);}
});

test('Early invalid signature rejection is learned by the client later and preserves original-session I/O',()=>{
  const f=fixture('rejected'),m=f.m;
  assert.equal(at(m,'mc-binding-preconditions').bindingServerKnowsFailure,true);assert.equal(at(m,'mc-binding-preconditions').bindingClientKnowsFailure,false);assert.equal(at(m,'mc-binding-error').bindingClientKnowsFailure,false);assert.equal(at(m,'mc-binding-error-check').bindingClientKnowsFailure,true);
  assert.equal(obj(m,'mc-gss-key'),undefined);assert.equal(obj(m,'mc-channel-signing-key'),undefined);assert.equal(obj(m,'mc-channel2'),undefined);assert.equal(index(m,'mc-gss-accept'),-1);
  assert.equal(f.steps[index(m,'mc-binding-error')].layers[0].keyRef,obj(m,'signing-key').artifactId);assert.equal(f.steps[index(m,'mc-binding-error')].smbFrame.status,'STATUS_ACCESS_DENIED');
  for(const stage of ['mc-binding-preconditions','mc-binding-error-check','mc-read-accept']){const s=at(m,stage);for(const field of ['serverAuthenticated','clientSessionAccepted','treeConnected','fileOpened','channel1Usable'])assert.equal(s[field],true,stage+'/'+field);assert.equal(s.channel2Usable,false);}
  assert.equal(at(m,'mc-read-accept').channel1ReadAfterBindingFailure,true);assert.equal(f.steps[index(m,'mc-read-request')].smbFrame.connectionId,'tcp-1');assert.match(obj(m,'mc-binding-error').representations[0].fields[0].value,/no new channel/);assert.match(m.profile.assumptions.join(' '),/TLS channel binding/);
});

test('Exact-object and field replay include local derivation, actual wire protection and decoding boundaries',()=>{
  const f=fixture('success');
  for(const [key,stage,kind] of [['mc-gss-key','mc-server-channel','use'],['mc-channel-signing-key','mc-client-channel-key','store'],['mc-channel-signing-key','mc-client-channel-verify','use'],['mc-read-data','mc-read-response-unwrap','decrypt']]){const a=obj(f.m,key),field=buildAttributeTrace(getAttributeUsage(f.steps,a.attributeId),f.m.examples());assert.ok(field.some(r=>r.sourceStepId===f.m.id+':'+stage&&r.traceKind===kind),key+'/'+stage);const exact=heldObjectTrace(f.compiled,a.artifactId);assert.ok(exact.some(r=>r.sourceStepId===f.m.id+':'+stage),key);}
  const data=obj(f.m,'mc-read-data'),exact=heldObjectTrace(f.compiled,data.artifactId),sent=exact.find(r=>r.sourceStepId===f.m.id+':mc-read-response'),decoded=exact.find(r=>r.sourceStepId===f.m.id+':mc-read-response-unwrap');assert.equal(sent.representationId,'ciphertext');assert.match(sent.payload[0].value,/Opaque/);assert.equal(decoded.representationId,'plain');assert.match(decoded.payload[0].value,/quarterly/);
  for(const step of f.steps)for(const [i,op] of step.attributeOperations.entries())if(op.kind==='send'){const created=step.attributeOperations.findIndex(o=>o.instanceId===op.instanceId&&['create','derive'].includes(o.kind));assert.ok(created<0||created<i,step.id);}
});


test('Cached CIFS ticket stays opaque when the client constructs its binding GSS token',()=>{
  const f=fixture('success'),ticket=obj(f.m,'cifs-ticket'),step=f.steps[index(f.m,'mc-gss-init')];
  assert.equal(holding(f.frame('mc-gss-init'),ticket,'smbClient','plain'),undefined);
  const operation=step.attributeOperations.find(o=>o.instanceId===ticket.artifactId);assert.equal(operation.representation,'wire');assert.equal(operation.kind,'use');assert.match(operation.value,/ciphertext/);
  const payload=step.payload.find(p=>p.attributeId===ticket.attributeId);assert.equal(payload.value,operation.value);assert.doesNotMatch(payload.value,/Decoded CIFS/);
  const trace=buildAttributeTrace(getAttributeUsage(f.steps,ticket.attributeId),f.m.examples());const local=trace.find(r=>r.sourceStepId===step.id);assert.ok(local);assert.equal(local.payload[0].value,operation.value);assert.equal(local.from,'smbClient');const exact=heldObjectTrace(f.compiled,ticket.artifactId).find(r=>r.sourceStepId===step.id);assert.ok(exact);assert.equal(exact.representationId,'wire');assert.equal(exact.payload[0].value,operation.value);
});
