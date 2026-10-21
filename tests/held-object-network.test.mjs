import test from 'node:test';
import assert from 'node:assert/strict';
import {NETWORKLAB_SCENARIOS,buildNetworkScenarioFixture} from '../src/network-access-lab.js';
import {buildNetworkHeldObjects} from '../src/held-object-network.js';
import {compileHeldObjects,projectHeldObjects,heldObjectTrace,inspectHeldObject} from '../src/held-object-state.js';

function netFixture(suffix){
  const model=typeof suffix==='string'?NETWORKLAB_SCENARIOS.find(item=>item.id==='lab-net-'+suffix):suffix,steps=model.steps(),actors=model.actors();
  const plan=buildNetworkHeldObjects({model,steps,actors,config:{},contextId:model.id+':fixture:'+(model.negativeVariant||'normal'),choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const frame=(key,milestone='complete')=>{
    const eventIndex=steps.findIndex(step=>step.id===model.id+':'+key);assert.notEqual(eventIndex,-1,key);
    return projectHeldObjects(compiled,{eventIndex,milestone});
  };
  const has=(snapshot,key,actor,representation)=>snapshot.holdings.some(holding=>holding.artifactId===model.id+':'+key+':g1'&&holding.actorId===actor&&(!representation||holding.representationId===representation));
  return {model,steps,plan,compiled,frame,has};
}
test('Network inventories compile complete coverage at all authored boundaries',()=>{
  for(const model of NETWORKLAB_SCENARIOS){
    const fixture=netFixture(model.id.replace('lab-net-',''));
    for(let eventIndex=-1;eventIndex<fixture.steps.length;eventIndex++){
      const snapshot=projectHeldObjects(fixture.compiled,{eventIndex,milestone:eventIndex===-1?'initial':'complete'});
      assert.equal(snapshot.coverageStatus,'complete');
    }
  }
  assert.equal(buildNetworkHeldObjects({model:{id:'other'}}),null);
});
test('NET-R01 exact wire password differs from decoded value and retains receiver history',()=>{
  const f=netFixture('radius-password-accept');
  assert.equal(f.has(f.frame('request','before'),'password','netServer'),false);
  assert.equal(f.has(f.frame('request'),'password','netServer','wire'),true);
  assert.equal(f.has(f.frame('request'),'password','netServer','plain'),false);
  assert.equal(f.has(f.frame('validate'),'password','netServer','plain'),true);
  assert.equal(f.has(f.frame('accept'),'password','netServer'),false);
  const artifact=f.plan.artifacts.find(item=>item.artifactId===f.model.id+':password:g1');
  assert.equal(artifact.representations.find(rep=>rep.representationId==='wire').fields[0].value,'SYM(hidden password blocks)');
  assert.equal(artifact.representations.find(rep=>rep.representationId==='plain').fields[0].value,'SYM(alice password)');
  const trace=heldObjectTrace(f.compiled,artifact.artifactId);assert.ok(trace.some(row=>row.sourceStepId===f.model.id+':request'));
});
test('NET-E01 certificates are opaque at NAS but explicitly decoded by the legitimate peer',()=>{
  const f=netFixture('eap-tls13-wired');
  assert.equal(f.has(f.frame('serverflight-peer','before'),'netServer-certificate','netPeer'),false);
  assert.equal(f.has(f.frame('serverflight-peer'),'netServer-certificate','netPeer','wire'),true);
  assert.equal(f.has(f.frame('serverflight-peer'),'netServer-certificate','netPeer','plain'),false);
  assert.equal(f.has(f.frame('peer-derive'),'netServer-certificate','netPeer','plain'),true);
  assert.equal(f.has(f.frame('peer-check'),'netPeer-certificate','netServer','plain'),true);
  for(const artifact of f.plan.artifacts.filter(item=>item.type==='private-key'))for(const rep of artifact.representations)assert.deepEqual(rep.readableBy,[artifact.creator]);
  const final=f.frame('peer-cleanup');
  for(const key of ['netPeer-private-key','netServer-private-key','tls-secrets','peer-tls-secrets','emsk','peer-emsk'])assert.equal(f.has(final,key,'netNas'),false,key);
});
test('NET-E01 local key derivations and authorized MPPE export are different occurrences',()=>{
  const f=netFixture('eap-tls13-wired');
  assert.equal(f.has(f.frame('serverflight-peer'),'peer-tls-secrets','netPeer'),false);
  assert.equal(f.has(f.frame('peer-derive'),'peer-tls-secrets','netPeer'),true);
  assert.equal(f.has(f.frame('peer-check'),'msk','netServer'),false);
  assert.equal(f.has(f.frame('server-export'),'msk','netServer'),true);
  assert.equal(f.has(f.frame('peer-export'),'peer-msk','netPeer'),true);
  assert.equal(f.has(f.frame('peer-export'),'msk','netPeer'),false);
  assert.equal(f.has(f.frame('accept','before'),'msk','netNas'),false);
  assert.equal(f.has(f.frame('accept'),'msk','netNas','wire'),true);
  assert.equal(f.has(f.frame('accept'),'msk','netNas','plain'),false);
  assert.equal(f.has(f.frame('verify-reply'),'msk','netNas','plain'),true);
  assert.equal(f.has(f.frame('verify-reply'),'msk','netServer'),true,'NAS verification does not release server holding');
  assert.equal(f.has(f.frame('cleanup'),'peer-tls-secrets','netPeer'),true,'Server local cleanup cannot release peer secret');
  assert.equal(f.has(f.frame('peer-cleanup'),'peer-tls-secrets','netPeer'),false);
  assert.equal(f.has(f.frame('peer-cleanup'),'msk','netNas','plain'),true,'Independent lower-layer cache retained');
  const key=f.plan.artifacts.find(item=>item.artifactId===f.model.id+':msk:g1');
  assert.deepEqual(key.representations.find(rep=>rep.representationId==='wire').fields.map(field=>field.name),['MS-MPPE-Recv-Key','MS-MPPE-Send-Key']);
  const trace=heldObjectTrace(f.compiled,key.artifactId).find(row=>row.sourceStepId===f.model.id+':accept');
  assert.equal(trace.inspectionActorId,'netNas');assert.equal(trace.representationId,'wire');
});

test('TOTP seed stays with the provisioned authenticator and validator, never the NAS or user input component',()=>{
  const f=netFixture('radius-password-totp');
  const initial=projectHeldObjects(f.compiled,{eventIndex:-1,milestone:'initial'});
  assert.equal(f.has(initial,'totp-seed','netOtp'),true);
  assert.equal(f.has(initial,'totp-seed','netServer'),true);
  for(let index=-1;index<f.steps.length;index++){
    const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:index===-1?'initial':'complete'});
    assert.equal(f.has(frame,'totp-seed','netNas'),false);
    assert.equal(f.has(frame,'totp-seed','netPeer'),false);
  }
  assert.equal(f.has(f.frame('factor-create'),'totp-code','netOtp'),true);
  assert.equal(f.has(f.frame('factor-display'),'totp-code','netPeer'),true);
  assert.equal(f.has(f.frame('factor-input'),'totp-code','netNas'),true);
  assert.equal(f.has(f.frame('factor-code-cleanup'),'totp-code','netOtp'),false);
});
test('NPS TLS1.2 public certificates are visible at NAS, but private/TLS/EMSK handles remain endpoint-local',()=>{
  const f=netFixture('nps-ad-tls12');
  assert.equal(f.has(f.frame('serverflight-backend'),'netServer-cert','netNas','plain'),true);
  assert.equal(f.has(f.frame('peerflight-peer'),'netPeer-cert','netNas','plain'),true);
  for(let index=-1;index<f.steps.length;index++){
    const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:index===-1?'initial':'complete'});
    for(const key of ['netPeer-private','netServer-private','netPeer-ephemeral','netServer-ephemeral','netPeer-tls','netServer-tls','netPeer-emsk','netServer-emsk'])assert.equal(f.has(frame,key,'netNas'),false,key);
  }
  assert.equal(f.has(f.frame('accept'),'netServer-msk','netNas','wire'),true);
  assert.equal(f.has(f.frame('accept'),'netServer-msk','netNas','plain'),false);
  assert.equal(f.has(f.frame('verify-reply'),'netServer-msk','netNas','plain'),true);
  const denied=netFixture('nps-mapping-rejected');
  assert.equal(denied.has(denied.frame('peer-cleanup'),'netServer-msk','netNas'),false);
});
test('Proxy can recover only authorized hop-carried MSK, never inner TLS/private/EMSK material',()=>{
  const f=netFixture('radius-proxy-realm');
  assert.equal(f.has(f.frame('accept-ingress','before'),'msk','netProxy'),false);
  assert.equal(f.has(f.frame('accept-ingress'),'msk','netProxy','home-wire'),true);
  assert.equal(f.has(f.frame('accept-ingress'),'msk','netProxy','plain'),false);
  assert.equal(f.has(f.frame('accept-proxy-check'),'msk','netProxy','plain'),true);
  assert.equal(f.has(f.frame('accept'),'msk','netProxy','plain'),false,'Proxy scratch deleted after forwarding');
  assert.equal(f.has(f.frame('accept'),'msk','netNas','wire'),true);
  for(let index=-1;index<f.steps.length;index++){
    const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:index===-1?'initial':'complete'});
    for(const actor of ['netNas','netProxy'])for(const key of ['netPeer-private-key','netServer-private-key','peer-ephemeral','server-ephemeral','tls-secrets','peer-tls-secrets','emsk','peer-emsk'])assert.equal(f.has(frame,key,actor),false,key+'/'+actor);
  }
  const msk=f.plan.artifacts.find(item=>item.artifactId===f.model.id+':msk:g1');
  const trace=heldObjectTrace(f.compiled,msk.artifactId);
  assert.equal(trace.find(row=>row.sourceStepId===f.model.id+':accept-ingress').representationId,'home-wire');
  assert.equal(trace.find(row=>row.sourceStepId===f.model.id+':accept').representationId,'wire');
  const home=msk.representations.find(rep=>rep.representationId==='home-wire').fields.map(field=>field.value);
  const nas=msk.representations.find(rep=>rep.representationId==='wire').fields.map(field=>field.value);
  assert.notDeepEqual(home,nas,'Protected carrier values are rewrapped for different adjacent secrets');
});
test('Dynamic authorization retains identity but replaces effective policy, or removes only selected context',()=>{
  const coa=netFixture('radius-coa-ack');
  assert.equal(coa.has(coa.frame('operation'),'target-session','netNas'),true);
  assert.equal(coa.has(coa.frame('operation'),'target-policy','netNas'),false);
  assert.equal(coa.has(coa.frame('operation'),'quarantine-policy','netNas'),true);
  assert.equal(coa.has(coa.frame('operation'),'target-auth-context','netNas'),true);
  const disconnect=netFixture('radius-disconnect-ack');
  assert.equal(disconnect.has(disconnect.frame('operation'),'target-session','netNas'),false);
  assert.equal(disconnect.has(disconnect.frame('operation'),'target-auth-context','netNas'),false);
  assert.equal(disconnect.has(disconnect.frame('operation'),'unrelated-session','netNas'),true);
  assert.equal(disconnect.has(disconnect.frame('operation'),'stop-record','netNas'),false,'Accounting Stop is subsequent');
  const lost=netFixture(buildNetworkScenarioFixture('lab-net-radius-disconnect-ack',{variant:'lost-Disconnect-ACK'}));
  assert.equal(lost.has(lost.frame('retry-timeout'),'dynamic-result','netController'),false,'Undelivered ACK is not sender possession');
});
test('Paired transport contexts keep outer NAS TLS distinct from both inner endpoint contexts',()=>{
  const f=netFixture('radius-udp-radsec');
  assert.equal(f.has(f.frame('outer-nas-check'),'nas-outer-tls','netNas'),true);
  assert.equal(f.has(f.frame('outer-nas-cleanup'),'nas-outer-tls','netNas'),false);
  const final=f.frame('outer-nas-cleanup');
  for(const scope of ['udp','radsec']){
    assert.ok(final.holdings.some(holding=>holding.artifactId===f.model.id+':'+scope+':port-session:g1'&&holding.actorId==='netNas'));
    assert.ok(!final.holdings.some(holding=>holding.artifactId===f.model.id+':'+scope+':peer-tls-secrets:g1'&&holding.actorId==='netNas'));
  }
  const secret=f.plan.artifacts.find(artifact=>artifact.artifactId===f.model.id+':radsec:radius-secret:g1');
  assert.equal(secret.representations[0].fields[0].value,'radsec (historic RFC6614 fixed secret)');
});
test('RADIUS/1.1 password receipt is protected wire until local TLS endpoint processing',()=>{
  const f=netFixture('radius11');
  assert.equal(f.has(f.frame('request'),'password','netServer','wire'),true);
  assert.equal(f.has(f.frame('request'),'password','netServer','plain'),false);
  assert.equal(f.has(f.frame('validate'),'password','netServer','plain'),true);
  const password=f.plan.artifacts.find(artifact=>artifact.artifactId===f.model.id+':password:g1');
  assert.equal(password.representations.find(rep=>rep.representationId==='wire').fields[0].value,'SYM(TLS encrypted User-Password text)');
  assert.equal(f.has(f.frame('request'),'token','netServer'),false);
  assert.equal(f.has(f.frame('decode-request'),'token','netServer'),true);
});

const netHeldNegativeInputs=[
  ['radius-password-accept',['invalid-password','invalid-response-authenticator','wrong-recipient']],
  ['radius-password-reject',['timeout-is-not-reject']],
  ['radius-password-totp',['missing-State','altered-State','expired-TOTP']],
  ['radius-challenge-rejected',['invalid-TOTP','expired-TOTP','missing-State','altered-State']],
  ['eap-tls13-wired',['invalid-Message-Authenticator','wrong-RADIUS-Identifier','wrong-EAP-Identifier','reordered-EAP-Message','fragment-sequence']],
  ['eap-server-cert-rejected',['untrusted-issuer','wrong-server-name','expired-server-cert','revoked-server-cert']],
  ['eap-client-cert-rejected',['bad-client-chain','inappropriate-client-EKU','expired-client-cert','revoked-client-cert']],
  ['eap-policy-denied',['unauthorized-group','disallowed-NAS']],
  ['nps-ad-tls12',['UPN-only-mapping','missing-SID-binding','group-denied']],
  ['nps-mapping-rejected',['UPN-only-mapping','missing-SID-binding']],
  ['radius-accounting-lifecycle',['lost-accounting-response','duplicate-accounting-request']],
  ['radius-udp-radsec',['inner-outer-TLS-confusion']],
  ['radsec-peer-rejected',['wrong-transport-peer','untrusted-transport-issuer']],
  ['radius-proxy-realm',['wrong-home-route','wrong-hop-secret','Proxy-State-order']],
  ['radius-proxy-unknown-realm',['unknown-realm']],
  ['radius-coa-ack',['lost-CoA-ACK','duplicate-CoA-request','untrusted-client','invalid-request-authenticator','wrong-recipient','stale-Event-Timestamp']],
  ['radius-coa-nak',['unsupported-service','unsupported-attribute','session-not-found','stale-Event-Timestamp']],
  ['radius-disconnect-ack',['lost-Disconnect-ACK','duplicate-Disconnect-request','stale-session','stale-Event-Timestamp']],
  ['radius-disconnect-nak',['session-not-found','untrusted-client','invalid-request-authenticator','stale-Event-Timestamp']],
  ['radius-udp-retransmission',['late-reply','wrong-transaction','invalid-response-authenticator']],
  ['enterprise-wifi-eap',['no-usable-protected-link']],
  ['radius11',['Message-Authenticator-ignored','reserved-field-ignored','wrong-token']],
  ['radius11-required-unavailable',['absent-ALPN','only-radius10','no-common-ALPN']],
];
for(const [suffix,variants] of netHeldNegativeInputs)for(const variant of variants)test('Complete exact inventory on named input '+suffix+' / '+variant,()=>{
  const f=netFixture(buildNetworkScenarioFixture('lab-net-'+suffix,{variant}));
  for(let index=-1;index<f.steps.length;index++){
    const frame=projectHeldObjects(f.compiled,{eventIndex:index,milestone:index===-1?'initial':'complete'});
    assert.equal(frame.coverageStatus,'complete');
    for(const holding of frame.holdings){
      const artifact=frame.artifacts.find(item=>item.artifactId===holding.artifactId);
      if(artifact.type==='private-key')assert.equal(holding.actorId,artifact.creator,'No private-key transfer on failure');
      if(artifact.artifactId.endsWith(':emsk:g1'))assert.ok(['netPeer','netServer'].includes(holding.actorId),'No EMSK at NAS/proxy');
    }
  }
});

test('RADIUS/1.1 decrypting a transport certificate is not validation',()=>{
  const f=netFixture('radius11'),certificate=f.model.id+':netServer-outer-certificate:g1';
  assert.equal(f.has(f.frame('server-flight'),'netServer-outer-certificate','netNas','wire'),true);
  assert.equal(f.has(f.frame('server-flight'),'netServer-outer-certificate','netNas','plain'),false);
  assert.equal(f.has(f.frame('nas-derive'),'netServer-outer-certificate','netNas','plain'),true);
  const decoded=f.model.networkInventory.events[f.model.id+':nas-derive'].effects;
  const validated=f.model.networkInventory.events[f.model.id+':nas-peer-check'].effects;
  assert.ok(!decoded.some(effect=>effect.op==='observe'&&effect.artifactId===certificate),'Local decryption does not mark peer certificate trusted');
  assert.ok(validated.some(effect=>effect.op==='observe'&&effect.artifactId===certificate&&effect.result==='valid'));
  assert.ok(decoded.some(effect=>effect.op==='acquire'&&effect.artifactId===certificate&&effect.store==='decoded transport certificates'));
  assert.ok(validated.some(effect=>effect.op==='release'&&effect.artifactId===certificate&&effect.store==='decoded transport certificates'));
  assert.ok(validated.some(effect=>effect.op==='acquire'&&effect.artifactId===certificate&&effect.store==='validated transport certificates'));
});

test('NET-03 all eight RadSec occurrences replay opaque outer records and separate endpoint decodes',()=>{
  const f=netFixture('radius-udp-radsec');
  const keys=['identity-backend','start-backend','clienthello-backend','serverflight-backend','peerflight-backend','protected-success-backend','empty-backend','accept'];
  for(const key of keys){
    const suffix='radsec:'+key,eventId=f.model.id+':'+suffix,packetId=eventId+'-packet:g1';
    const send=f.steps.find(step=>step.id===eventId),decode=f.steps.find(step=>step.id===eventId+'-decode');
    assert.equal(f.steps.indexOf(decode),f.steps.indexOf(send)+1,'Immediate distinct local transport decode: '+key);
    assert.equal(decode.from,send.to);assert.equal(decode.to,send.to);assert.equal(decode.eventType,'local');
    assert.deepEqual(send.payload.map(field=>field.name),['TLS record']);
    const ciphertext='SYM(outer RadSec TLS1.3 application_data '+suffix+' ciphertext)';
    assert.equal(send.payload[0].value,ciphertext);
    assert.deepEqual(send.attributeOperations.map(op=>[op.kind,op.representation,op.value]),[['send','outer-wire',ciphertext],['receive','outer-wire',ciphertext]]);
    assert.equal(send.layers[0].keyRef,f.model.id+':'+(send.from==='netNas'?'nas':'server')+'-outer-tls:g1');
    assert.equal(decode.layers[0].keyRef,f.model.id+':'+(send.to==='netNas'?'nas':'server')+'-outer-tls:g1');
    assert.equal(f.has(f.frame(suffix,'before'),'radsec:'+key+'-packet',send.to),false);
    const receipt=f.frame(suffix),outer=receipt.holdings.find(holding=>holding.artifactId===packetId&&holding.actorId===send.to);
    assert.equal(outer.representationId,'outer-wire');
    assert.deepEqual(inspectHeldObject(receipt,outer.holdingId).fields.map(field=>[field.name,field.value]),[['TLS record',ciphertext]]);
    assert.ok(!receipt.holdings.some(holding=>holding.artifactId===packetId&&holding.representationId==='radius-decoded'));
    const decoded=f.frame(suffix+'-decode'),holding=decoded.holdings.find(holding=>holding.artifactId===packetId&&holding.actorId===send.to);
    assert.equal(holding.representationId,'radius-decoded');
    assert.ok(!decoded.holdings.some(holding=>holding.artifactId===packetId&&holding.representationId==='outer-wire'));
    const fields=inspectHeldObject(decoded,holding.holdingId).fields;
    assert.ok(fields.some(field=>field.name==='Code'));
    assert.deepEqual(fields.map(field=>[field.name,field.value]),decode.payload.map(field=>[field.name,field.value]));
    for(const field of fields){
      const operation=decode.attributeOperations.find(action=>action.attributeId===field.attributeId);
      assert.ok(operation,'Held decoded field has an authored local operation');
      assert.equal(operation.kind,'decrypt');assert.equal(operation.actorId,holding.actorId);
      assert.equal(operation.representation,holding.representationId);
      assert.equal(operation.value,field.value);assert.equal(operation.sourceEventId,decode.id);
    }
    assert.ok(fields.some(field=>field.name==='EAP-Message'));
    assert.ok(!fields.some(field=>field.name==='TLS record'||field.name==='Decoded certificate'));
    if(['serverflight-backend','peerflight-backend','protected-success-backend'].includes(key))assert.match(fields.find(field=>field.name==='EAP-Message').value,/encrypted/);
    const trace=heldObjectTrace(f.compiled,packetId),wireRow=trace.find(row=>row.sourceStepId===eventId),decodeRow=trace.find(row=>row.sourceStepId===decode.id);
    assert.equal(wireRow.representationId,'outer-wire');
    assert.deepEqual(wireRow.payload.map(field=>[field.name,field.value]),[['TLS record',ciphertext]],'Wire replay never upgrades to later decoded fields');
    assert.equal(decodeRow.representationId,'radius-decoded');
    assert.ok(decodeRow.payload.some(field=>field.name==='Code'));
    assert.equal(decodeRow.inspectionActorId,send.to);
    assert.deepEqual(f.model.networkInventory.events[eventId].messages[0].objects,[{artifactId:packetId,representationId:'outer-wire'}]);
    for(const actor of ['netNas','netServer']){
      assert.equal(f.has(decoded,actor==='netNas'?'nas-outer-tls':'server-outer-tls',actor),true);
      assert.equal(f.has(decoded,actor==='netNas'?'server-outer-tls':'nas-outer-tls',actor),false);
    }
    for(const object of ['radsec:tls-secrets','radsec:peer-tls-secrets','radsec:emsk','radsec:peer-emsk','radsec:netPeer-private-key','radsec:netServer-private-key'])assert.equal(f.has(decoded,object,'netNas'),false,object);
  }
  assert.equal(f.has(f.frame('radsec:serverflight-backend'),'radsec:netServer-certificate','netNas'),false);
  assert.equal(f.has(f.frame('radsec:serverflight-backend-decode'),'radsec:netServer-certificate','netNas','wire'),true);
  assert.equal(f.has(f.frame('radsec:serverflight-backend-decode'),'radsec:netServer-certificate','netNas','plain'),false);
  assert.equal(f.has(f.frame('radsec:accept'),'radsec:msk','netNas'),false);
  assert.equal(f.has(f.frame('radsec:accept-decode'),'radsec:msk','netNas','wire'),true);
  assert.equal(f.has(f.frame('radsec:accept-decode'),'radsec:msk','netNas','plain'),false);
  assert.equal(f.has(f.frame('radsec:verify-reply'),'radsec:msk','netNas','plain'),true);
});
