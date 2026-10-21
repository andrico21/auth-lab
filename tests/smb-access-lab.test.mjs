import test from 'node:test';
import assert from 'node:assert/strict';
import {SMBLAB_SCENARIOS} from '../src/smb-access-lab.js';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {buildHeldObjects} from '../src/held-objects.js';
import {projectHeldObjects,heldObjectTrace} from '../src/held-object-state.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {parseStudioRoute,studioRoute} from '../src/workspaces.js';

const model=s=>SMBLAB_SCENARIOS.find(m=>m.id==='lab-smb-nonjoined-'+s);
const index=(m,stage)=>m.steps().findIndex(s=>s.smbStage===stage);
const state=(m,stage)=>reconstructProtocolState(m,stage?index(m,stage):m.steps().length-1).smb;
function fixture(s){const m=model(s),steps=m.steps(),compiled=buildHeldObjects({model:m,steps,actors:m.actors(),config:{},contextId:m.id,choiceId:m.id});return {m,compiled,id:key=>m.id+':'+key,frame:(stage,milestone='complete')=>projectHeldObjects(compiled,{eventIndex:index(m,stage),milestone})};}
const has=(frame,id,actor,rep='plain',store)=>frame.holdings.some(h=>h.artifactId===id&&h.actorId===actor&&h.representationId===rep&&(!store||h.store===store));

test('All SMB models are discoverable in the file-access family with a readable modern profile',()=>{
  assert.equal(SMBLAB_SCENARIOS.length,10);
  assert.equal(parseStudioRoute('#/windows/files',LAB_MODELS).scenarioId,'lab-smb-nonjoined-kerberos');
  for(const m of SMBLAB_SCENARIOS){assert.equal(parseStudioRoute(studioRoute(m.id,LAB_MODELS),LAB_MODELS).scenarioId,m.id);assert.equal(m.family,'windows-files');assert.equal(m.profile.dialect,'0x0311');assert.match(JSON.stringify(m.profile.cryptoDetail),/SHA512/);assert.match(JSON.stringify(m.profile.cryptoDetail),/AES128-GCM/);assert.equal(m.profile.sources[0].revision,'88.0 / 2026-09-28; dialect0x0311');}
});

test('Local workstation identity and join state do not change at any canonical boundary',()=>{
  for(const m of SMBLAB_SCENARIOS)for(let i=-1;i<m.steps().length;i++){const s=reconstructProtocolState(m,i).smb;assert.equal(s.clientJoined,false,m.id);assert.equal(s.localDesktopIdentity,'WORKGROUPPC\\bob');assert.equal(s.networkIdentity,'CORP\\alice');}
});

test('SMB requests and responses remain paired; continuation does not establish a session',()=>{
  for(const m of SMBLAB_SCENARIOS){const pending=new Map();for(const step of m.steps()){if(!step.smbFrame)continue;const f=step.smbFrame;if(!f.status){assert.equal(pending.has(f.messageId),false);pending.set(f.messageId,f.command);}else{assert.equal(pending.get(f.messageId),f.command,step.id);pending.delete(f.messageId);}}assert.equal(pending.size,0,m.id);}
  const m=model('ntlm');assert.equal(state(m,'session-challenge').sessionIdAllocated,true);assert.equal(state(m,'session-challenge').clientSessionAccepted,false);assert.equal(state(m,'session-authenticate').serverAuthenticated,false);assert.equal(state(m,'session-success').clientSessionAccepted,false);assert.equal(state(m,'client-session').clientSessionAccepted,true);
});

test('Preauthentication context includes exact exchange through final client request, not signed success',()=>{
  for(const [suffix,count] of [['ntlm',5],['kerberos',3]]){const m=model(suffix);assert.equal(state(m).preauthMessages,count);assert.equal(state(m,'server-key-derivation').preauthHash,m.id+':preauth-'+count);assert.equal(m.steps().find(s=>s.smbStage==='session-success').smbFrame.preauthHashed,false);assert.equal(m.steps().filter(s=>s.smbFrame?.preauthHashed).length,count);const key=m.smbInventory.artifacts.find(o=>o.key==='signing-key');assert.match(key.value,new RegExp('Context=preauth-'+count));}
});

test('NTLM compatibility uses server DC validation without direct client/DC traffic or hash export',()=>{
  const f=fixture('ntlm');assert.equal(f.m.steps().some(s=>s.from==='smbClient'&&s.to==='smbDC'||s.from==='smbDC'&&s.to==='smbClient'),false);
  for(const stage of ['session-authenticate','dc-request','dc-result']){const frame=f.frame(stage);for(const key of ['credential','nt-hash','response-key']){assert.equal(has(frame,f.id(key),'smbServer'),false);assert.equal(has(frame,f.id(key),'smbDC'),false);}}
  assert.equal(has(f.frame('dc-request'),f.id('ntlm-proof'),'smbDC'),false);assert.equal(has(f.frame('dc-request'),f.id('ntlm-proof'),'smbDC','netlogon'),true);assert.equal(has(f.frame('dc-verify'),f.id('ntlm-proof'),'smbDC'),true);
  assert.equal(has(f.frame('dc-result'),f.id('session-key'),'smbServer'),false);assert.equal(has(f.frame('ntlm-accept'),f.id('session-key'),'smbServer'),true);
  const wire=f.m.smbInventory.events[f.id('dc-request')].messages[0];assert.ok(wire.objects.every(o=>o.representationId!=='plain'));
});

test('KILE AP-REP acceptor key reaches C only after mutual verification, before client KDF',()=>{
  const f=fixture('kerberos');assert.equal(has(f.frame('session-success'),f.id('session-key'),'smbClient'),false);assert.equal(has(f.frame('client-mechanism'),f.id('session-key'),'smbClient'),true);
  for(const key of ['signing-key','app-key','c2s-key','s2c-key']){assert.equal(has(f.frame('client-mechanism'),f.id(key),'smbClient'),false);assert.equal(has(f.frame('client-key-derivation'),f.id(key),'smbClient'),true);assert.equal(has(f.frame('client-key-derivation'),f.id(key),'smbDC'),false);}
  assert.equal(has(f.frame('as-reply'),f.id('dc-account-key'),'smbDC'),true);assert.equal(has(f.frame('as-reply'),f.id('tgt-key'),'smbClient'),false);assert.equal(has(f.frame('as-accept'),f.id('tgt-key'),'smbClient'),true);
  assert.notEqual(f.id('initiator-subkey'),f.id('session-key'));assert.match(f.m.smbInventory.artifacts.find(o=>o.key==='session-key').value,/acceptor/);
});

test('Keys are derived locally and never occur as transmitted SMB or Netlogon objects',()=>{
  for(const m of SMBLAB_SCENARIOS)for(const event of Object.values(m.smbInventory.events))for(const message of event.messages||[])for(const o of message.objects){const key=m.smbInventory.artifacts.find(a=>a.artifactId===o.artifactId).key;assert.equal(['session-key','signing-key','app-key','c2s-key','s2c-key','initiator-subkey','nt-hash','response-key','credential'].includes(key),false,m.id+'/'+key);}
});

test('Final SESSION_SETUP and TREE_CONNECT are signed; file operations use directional AEAD',()=>{
  const m=model('kerberos');for(const stage of ['session-success','tree-request','tree-success']){const s=m.steps().find(s=>s.smbStage===stage);assert.equal(s.smbFrame.signed,true);assert.equal(s.smbFrame.encrypted,false);assert.equal(s.layers[0].keyRef,m.id+':signing-key');}
  for(const stage of ['create-request','create-success','read-request','read-success']){const s=m.steps().find(s=>s.smbStage===stage);assert.equal(s.smbFrame.encrypted,true);assert.equal(s.smbFrame.signed,false);assert.equal(s.smbFrame.treeId,'tree-1');assert.equal(s.layers[0].keyRef,m.id+(s.from==='smbClient'?':c2s-key':':s2c-key'));}
  const nonces=m.smbInventory.artifacts.filter(o=>o.key.endsWith('-transform')).map(o=>o.value.match(/Nonce=(.*?); remaining/)[1]);assert.equal(new Set(nonces).size,nonces.length);
});

test('Encrypted object receipt precedes authenticated plaintext acquisition and application use',()=>{
  const f=fixture('kerberos');assert.equal(has(f.frame('create-request'),f.id('create-request'),'smbServer'),false);assert.equal(has(f.frame('create-request'),f.id('create-request'),'smbServer','ciphertext'),true);assert.equal(has(f.frame('create-request-unwrap'),f.id('create-request'),'smbServer'),true);
  assert.equal(has(f.frame('read-success'),f.id('file-data'),'smbClient'),false);assert.equal(has(f.frame('read-success'),f.id('file-data'),'smbClient','ciphertext'),true);assert.equal(has(f.frame('read-success-unwrap'),f.id('file-data'),'smbClient'),true);assert.equal(state(f.m,'read-success-unwrap').fileRead,false);assert.equal(state(f.m,'read-accept').fileRead,true);
  const trace=heldObjectTrace(f.compiled,f.id('file-data'));assert.ok(trace.some(t=>t.sourceStepId===f.id('read-success')&&t.representationId==='ciphertext'));assert.ok(trace.some(t=>t.sourceStepId===f.id('read-success-unwrap')&&t.representationId==='plain'));
});

test('Independent authentication, share and file denials preserve only justified earlier state',()=>{
  const expected={
    'ntlm-blocked':[false,false,false,'incoming NTLM blocked'],
    'bad-credential':[false,false,false,'bad domain credential'],
    'dc-unavailable':[false,false,false,'DC validation unavailable'],
    'share-denied':[true,false,false,'share access denied'],
    'file-denied':[true,true,false,'file access denied'],
  };
  for(const [suffix,[session,tree,file,failure]] of Object.entries(expected)){const m=model(suffix),s=state(m);assert.equal(s.clientSessionAccepted,session);assert.equal(s.treeConnected,tree);assert.equal(s.fileOpened,file);assert.equal(s.fileRead,false);assert.equal(s.failure,failure);assert.equal(s.clientKnowsFailure,true);}
  const dc=model('dc-unavailable');assert.equal(dc.steps().some(s=>s.smbStage==='dc-request'||s.smbStage==='dc-verify'),false);
  const bad=model('bad-credential');assert.equal(state(bad,'dc-verify').serverKnowsFailure,false);assert.equal(state(bad,'authentication-reject').clientKnowsFailure,false);
});

test('Tampered signature is visible on the wire; response discard and selected disconnect precede share access',()=>{
  const f=fixture('signature-rejected'),m=f.m;assert.match(m.steps().find(s=>s.smbStage==='session-success').payload.map(p=>p.value).join(' '),/INVALID altered AES-CMAC/);assert.equal(state(m).clientSessionAccepted,false);assert.equal(state(m).clientDisconnected,true);assert.equal(state(m).serverAuthenticated,true);assert.equal(m.steps().some(s=>s.smbStage==='tree-request'),false);assert.equal(has(f.frame('client-disconnect'),f.id('signing-key'),'smbClient'),false);
});

test('Bad GCM tag yields no client plaintext and frees nondurable client handles',()=>{
  const f=fixture('encryption-rejected'),m=f.m;assert.match(m.steps().find(s=>s.smbStage==='read-success').payload.map(p=>p.value).join(' '),/INVALID altered GCM/);assert.equal(has(f.frame('read-success-reject'),f.id('file-data'),'smbClient'),false);assert.equal(state(m).fileRead,false);assert.equal(state(m).clientSessionWasAccepted,true);assert.equal(state(m).treeWasConnected,true);assert.equal(state(m).fileWasOpened,true);assert.equal(state(m).clientSessionAccepted,false);assert.equal(state(m).treeConnected,false);assert.equal(state(m).fileOpened,false);
  for(const key of ['session-context','tree','file-handle'])assert.equal(has(f.frame('client-disconnect'),f.id(key),'smbClient','plain',m.smbInventory.artifacts.find(o=>o.key===key).store),false);
  assert.ok(m.steps().find(s=>s.smbStage==='client-disconnect').attributeOperations.some(o=>o.kind==='evict'));
});

test('No common encryption cipher is legitimate negotiation followed by an explicit local policy stop',()=>{
  const m=model('encryption-unavailable');assert.match(m.steps().find(s=>s.smbStage==='negotiate-response').payload.map(p=>p.value).join(' '),/Ciphers\[0\]=0/);assert.equal(m.steps().find(s=>s.smbStage==='negotiate-response').smbFrame.status,'STATUS_SUCCESS');assert.equal(m.steps().some(s=>s.smbFrame?.command==='SESSION_SETUP'),false);assert.equal(state(m).clientKnowsFailure,true);assert.equal(state(m).serverKnowsFailure,false);
});

test('Local field histories expose creation before send, derivation at both endpoints and handle verification',()=>{
  for(const m of SMBLAB_SCENARIOS)for(const step of m.steps()){const ops=step.attributeOperations;for(const [i,op] of ops.entries())if(op.kind==='send'){const c=ops.findIndex(o=>o.instanceId===op.instanceId&&['create','derive'].includes(o.kind));assert.ok(c<0||c<i,step.id);}}
  const m=model('kerberos');for(const stage of ['server-key-derivation','client-key-derivation'])for(const key of ['signing-key','app-key','c2s-key','s2c-key'])assert.ok(m.steps().find(s=>s.smbStage===stage).attributeOperations.some(o=>o.instanceId===m.id+':'+key&&o.kind==='derive'));
  for(const stage of ['client-session','tree-accept','create-accept'])assert.ok(m.steps().find(s=>s.smbStage===stage).attributeOperations.some(o=>o.kind==='verify'));
});

test('Every SMB boundary compiles with complete explicit ownership and observations require possession',()=>{
  for(const m of SMBLAB_SCENARIOS){const f=fixture(m.id.slice('lab-smb-nonjoined-'.length));for(let i=-1;i<m.steps().length;i++){const frame=projectHeldObjects(f.compiled,{eventIndex:i,milestone:i<0?'initial':'complete'});assert.equal(frame.coverageStatus,'complete');if(i<0)continue;for(const observation of m.smbInventory.events[m.steps()[i].id].milestones[0].effects.filter(e=>e.op==='observe'))assert.ok(has(frame,observation.artifactId,observation.actorId,observation.representationId),m.steps()[i].id+'/'+observation.artifactId);}}
});
