import test from 'node:test';
import assert from 'node:assert/strict';
import {NETWORKLAB_SCENARIOS,NETWORKLAB_ATTRIBUTES,NETWORKLAB_SOURCES,buildNetworkScenarioFixture} from '../src/network-access-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {getAttributeUsage,getAttributeContext} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {ATTRIBUTES} from '../src/protocol-data.js';

const netModel=suffix=>NETWORKLAB_SCENARIOS.find(model=>model.id==='lab-net-'+suffix);
const netAt=(model,key)=>{
  const index=model.steps().findIndex(step=>step.id===model.id+':'+key);
  assert.notEqual(index,-1,'Authored boundary '+key);
  return reconstructProtocolState(model,index);
};
test('NET-R01 response receipt and verification are not admission',()=>{
  const model=netModel('radius-password-accept');
  assert.equal(reconstructProtocolState(model,-1).network.port,'unauthorized');
  assert.equal(netAt(model,'validate').network.peerIdentity,true);
  for(const key of ['validate','accept','verify-reply']){
    const state=netAt(model,key);assert.equal(state.network.port,'unauthorized');assert.deepEqual(state.sessions,{});
  }
  assert.equal(netAt(model,'accept').network.reply,'received-unverified');
  assert.equal(netAt(model,'verify-reply').network.reply,'verified');
  const final=netAt(model,'enforce');assert.equal(final.network.port,'authorized');assert.equal(final.sessions.access.id,'session-7');
  assert.equal(final.network.logicalAuthentications,1);
  assert.deepEqual(Object.keys(final.sessions),['access']);
});
test('NET-E01 identity, Finished, policy, key receipt and enforcement remain separate',()=>{
  const model=netModel('eap-tls13-wired');
  for(const key of ['identity-backend','serverflight-peer'])assert.equal(netAt(model,key).network.serverIdentity,false);
  assert.equal(netAt(model,'server-check').network.serverIdentity,true);
  assert.equal(netAt(model,'peerflight-backend').network.peerIdentity,false);
  assert.equal(netAt(model,'peer-check').network.peerIdentity,true);
  assert.equal(netAt(model,'peer-check').network.policy,'pending');
  assert.equal(netAt(model,'policy').network.policy,'accepted');
  for(const key of ['peer-check','policy','protected-success-peer','empty-backend','accept','verify-reply'])assert.equal(netAt(model,key).network.port,'unauthorized',key);
  assert.equal(netAt(model,'accept').network.mskReleased,false);
  assert.equal(netAt(model,'verify-reply').network.mskReleased,true);
  assert.equal(netAt(model,'enforce').network.port,'authorized');
  assert.equal(netAt(model,'cleanup').network.wifiUsable,false);
  const request=model.steps().find(step=>step.id.endsWith(':clienthello-backend'));
  assert.ok(request.payload.some(field=>field.name==='Message-Authenticator'));
  assert.ok(!request.payload.some(field=>field.name==='User-Password'));
});
test('EAP-TLS policy and protected success precede Access-Accept',()=>{
  const steps=netModel('eap-tls13-wired').steps();
  assert.ok(steps.findIndex(step=>step.id.endsWith(':policy'))<steps.findIndex(step=>step.id.endsWith(':protected-success-backend')));
  assert.ok(steps.findIndex(step=>step.id.endsWith(':empty-backend'))<steps.findIndex(step=>step.id.endsWith(':accept')));
});

const netFinal=model=>reconstructProtocolState(model,model.steps().length-1);
const netPath=(state,path)=>path.split('.').reduce((value,key)=>value?.[key],state);
const netExpectedTerminals=[
  ['radius-password-accept',{'network.port':'authorized','network.logicalAuthentications':1,'sessions.access.active':true}],
  ['radius-password-reject',{'network.port':'unauthorized','network.status':'authentication rejected','sessions.access':undefined}],
  ['radius-password-totp',{'network.port':'authorized','network.factor':'valid','network.challenge':null,'network.logicalAuthentications':1}],
  ['radius-challenge-rejected',{'network.port':'unauthorized','network.factor':'invalid','network.challenge':null,'sessions.access':undefined}],
  ['eap-tls13-wired',{'network.port':'authorized','network.mskReleased':true}],
  ['eap-server-cert-rejected',{'network.port':'unauthorized','network.serverIdentity':false,'network.mskReleased':false}],
  ['eap-client-cert-rejected',{'network.port':'unauthorized','network.serverIdentity':true,'network.peerIdentity':false,'network.mskReleased':false}],
  ['eap-policy-denied',{'network.port':'unauthorized','network.peerIdentity':true,'network.policy':'denied','network.mskReleased':false}],
  ['nps-ad-tls12',{'network.port':'authorized','network.mappedAccount':'S-1-5-21-example-1101'}],
  ['nps-mapping-rejected',{'network.port':'unauthorized','network.peerIdentity':true,'network.mappedAccount':null,'network.status':'account mapping rejected'}],
  ['radius-accounting-lifecycle',{'sessions.access.active':false,'network.accounting.stored':['Start','Interim-Update','Stop'],'network.accounting.acked':['Start','Interim-Update','Stop']}],
  ['radius-udp-radsec',{'network.port':'authorized','network.comparison.udp':'authorized','network.comparison.radsec':'authorized','network.logicalAuthentications':2,'sessions.udp.active':true,'sessions.radsec.active':true}],
  ['radsec-peer-rejected',{'network.port':'unauthorized','network.transport':'peer rejected','network.logicalAuthentications':0}],
  ['radius-proxy-realm',{'network.port':'authorized','network.homeContacted':true,'network.proxyState':['upstream0']}],
  ['radius-proxy-unknown-realm',{'network.port':'unauthorized','network.homeContacted':false,'network.route':'none'}],
  ['radius-coa-ack',{'sessions.access.id':'session-7','sessions.access.filter':'quarantine','sessions.access.active':true,'network.controllerKnowledge':'changed','network.logicalOperations':1,'sessions.unrelated.active':true}],
  ['radius-coa-nak',{'sessions.access.filter':'employee-wired','sessions.access.active':true,'network.controllerKnowledge':'rejected','network.errorCause':405}],
  ['radius-disconnect-ack',{'sessions.access.active':false,'sessions.unrelated.active':true,'network.controllerKnowledge':'disconnected','network.accounting.stored':['Stop']}],
  ['radius-disconnect-nak',{'sessions.access':undefined,'sessions.unrelated.active':true,'network.controllerKnowledge':'rejected','network.errorCause':503}],
  ['radius-udp-retransmission',{'network.port':'authorized','network.logicalAuthentications':1,'sessions.access.active':true}],
  ['enterprise-wifi-eap',{'network.port':'decision-only','network.wifiUsable':false,'network.status':'EAP access decision complete; Wi-Fi link establishment not shown','sessions.access':undefined}],
  ['radius11',{'network.port':'authorized','network.transport':'radius/1.1','network.usesMd5':false,'network.usesRadiusSharedSecret':false}],
  ['radius11-required-unavailable',{'network.port':'unauthorized','network.transport':'required profile unavailable','network.fallback':false,'network.logicalAuthentications':0}],
];
test('All 23 fixed network presets meet independent enforcement/knowledge predicates',()=>{
  for(const [suffix,expected] of netExpectedTerminals){
    const model=netModel(suffix),final=netFinal(model);
    for(const [path,value] of Object.entries(expected))assert.deepEqual(netPath(final,path),value,suffix+': '+path);
  }
});
test('Every fresh network login keeps NAS admission closed through reply verification',()=>{
  for(const suffix of ['radius-password-totp','radius-udp-retransmission','nps-ad-tls12','radius-proxy-realm','radius11']){
    const model=netModel(suffix),steps=model.steps(),enforce=steps.findIndex(step=>step.id===model.id+':enforce');
    assert.ok(enforce>=0,suffix);
    for(let index=-1;index<enforce;index++)assert.equal(reconstructProtocolState(model,index).network.port,'unauthorized',suffix+' early boundary '+index);
    assert.equal(netAt(model,'verify-reply').network.reply,'verified',suffix);
    assert.equal(netAt(model,'verify-reply').network.port,'unauthorized',suffix);
  }
});
test('NPS full TLS1.2 and account-result knowledge never masquerade as TLS1.3',()=>{
  const model=netModel('nps-ad-tls12'),steps=model.steps(),text=steps.flatMap(step=>step.payload.map(field=>field.value)).join(' ');
  assert.match(text,/ServerHelloDone/);assert.match(text,/ClientKeyExchange/);assert.match(text,/ChangeCipherSpec/);
  assert.ok(!steps.some(step=>step.id.endsWith(':protected-success-backend')));
  assert.equal(netAt(model,'peer-check').network.mappedAccount,undefined);
  assert.equal(netAt(model,'mapping').network.mappedAccount,undefined);
  assert.equal(netAt(model,'mapping').network.accountServiceMapping,'S-1-5-21-example-1101');
  assert.equal(netAt(model,'mapping-result-check').network.mappedAccount,'S-1-5-21-example-1101');
  for(const step of steps.filter(step=>step.id.endsWith(':account-query')||step.id.endsWith(':account-result')))assert.equal(step.eventType,'teaching-disclosure');
});
test('Accounting service lifetime, record persistence and acknowledgement knowledge are separate',()=>{
  const model=netModel('radius-accounting-lifecycle');
  assert.deepEqual(netAt(model,'start-store').network.accounting.stored,['Start']);
  assert.deepEqual(netAt(model,'start-store').network.accounting.acked,[]);
  assert.equal(netAt(model,'start-store').sessions.access.active,true);
  assert.equal(netAt(model,'interim-store').sessions.access.active,true);
  assert.equal(netAt(model,'local-stop').sessions.access.active,false);
  assert.deepEqual(netAt(model,'local-stop').network.accounting.stored,['Start','Interim-Update']);
  const values=key=>Object.fromEntries(model.steps().find(step=>step.id.endsWith(':'+key)).payload.map(field=>[field.name,field.value]));
  assert.equal(values('interim')['Acct-Input-Octets'],'1000');
  assert.equal(values('stop')['Acct-Input-Octets'],'3000');
  assert.equal(values('stop')['Acct-Output-Octets'],'5000');
  for(const key of ['start','interim','stop'])assert.equal(values(key)['Acct-Session-Id'],'session-7');
});
test('CoA and Disconnect actor-local action precedes controller ACK knowledge',()=>{
  for(const [suffix,result] of [['radius-coa-ack','changed'],['radius-disconnect-ack','disconnected']]){
    const model=netModel(suffix);
    assert.equal(netAt(model,'operation').network.controllerKnowledge,'pending');
    assert.equal(netAt(model,'ack').network.controllerKnowledge,'pending');
    assert.equal(netAt(model,'ack-check').network.controllerKnowledge,result);
    if(result==='changed')assert.equal(netAt(model,'operation').sessions.access.filter,'quarantine');
    else assert.equal(netAt(model,'operation').sessions.access.active,false);
    for(let index=-1;index<model.steps().length;index++)assert.equal(reconstructProtocolState(model,index).sessions.unrelated.active,true);
  }
});
test('T01 is two actual transactions with independent inner and outer TLS identities',()=>{
  const model=netModel('radius-udp-radsec'),steps=model.steps();
  const udp=steps.findIndex(step=>step.id===model.id+':udp:enforce');
  const outer=steps.findIndex(step=>step.id===model.id+':outer-hello');
  const radsec=steps.findIndex(step=>step.id===model.id+':radsec:identity-request');
  assert.ok(udp>=0&&outer>udp&&radsec>outer);
  const first=reconstructProtocolState(model,udp);
  assert.equal(first.sessions.udp.active,true);assert.equal(first.sessions.radsec,undefined);
  assert.equal(first.network.comparison.radsec,'pending');
  const layer=steps.find(step=>step.id===model.id+':radsec:serverflight-backend').layers;
  assert.ok(layer.some(item=>item.protocol==='TLS1.3 outer RadSec'&&item.certificateRole.includes('Outer')));
  assert.ok(layer.some(item=>item.protocol==='TLS 1.3 inside EAP-TLS'&&item.certificateRole.includes('Inner')));
});
test('RADIUS/1.1 uses actual negotiated packet rules rather than historic authenticators',()=>{
  const model=netModel('radius11'),decode=model.steps().find(step=>step.id.endsWith(':decode-request'));
  const fields=Object.fromEntries(decode.payload.map(field=>[field.name,field.value]));
  assert.equal(fields.Reserved,'0');
  assert.equal(fields['User-Password'],'SYM(alice password)');
  for(const absent of ['Identifier','Request Authenticator','Response Authenticator','Message-Authenticator'])assert.equal(fields[absent],undefined,absent);
  assert.ok(!model.networkInventory.artifacts.some(artifact=>artifact.type==='shared-secret'));
  assert.equal(model.status,'experimental');
  assert.ok(netAt(model,'negotiate-check').network.usesMd5===false);
});

const netNegativeGroups=[
  ['radius-password-accept',['invalid-password','invalid-response-authenticator','wrong-recipient'],{'network.port':'unauthorized','sessions.access':undefined}],
  ['radius-password-reject',['timeout-is-not-reject'],{'network.port':'unauthorized','network.reply':'none'}],
  ['radius-password-totp',['missing-State','altered-State','expired-TOTP'],{'network.port':'unauthorized','network.factor':'invalid','network.challenge':null}],
  ['radius-challenge-rejected',['invalid-TOTP','expired-TOTP','missing-State','altered-State'],{'network.port':'unauthorized','network.factor':'invalid'}],
  ['eap-tls13-wired',['invalid-Message-Authenticator','wrong-RADIUS-Identifier','wrong-EAP-Identifier','reordered-EAP-Message','fragment-sequence'],{'network.port':'unauthorized','network.mskReleased':false,'sessions.access':undefined}],
  ['eap-server-cert-rejected',['untrusted-issuer','wrong-server-name','expired-server-cert','revoked-server-cert'],{'network.serverIdentity':false,'network.port':'unauthorized','network.mskReleased':false}],
  ['eap-client-cert-rejected',['bad-client-chain','inappropriate-client-EKU','expired-client-cert','revoked-client-cert'],{'network.serverIdentity':true,'network.peerIdentity':false,'network.port':'unauthorized'}],
  ['eap-policy-denied',['unauthorized-group','disallowed-NAS'],{'network.peerIdentity':true,'network.policy':'denied','network.port':'unauthorized','network.mskReleased':false}],
  ['nps-ad-tls12',['UPN-only-mapping','missing-SID-binding'],{'network.peerIdentity':true,'network.mappedAccount':null,'network.port':'unauthorized'}],
  ['nps-ad-tls12',['group-denied'],{'network.mappedAccount':'S-1-5-21-example-1101','network.policy':'denied','network.port':'unauthorized'}],
  ['nps-mapping-rejected',['UPN-only-mapping','missing-SID-binding'],{'network.mappedAccount':null,'network.port':'unauthorized'}],
  ['radius-accounting-lifecycle',['lost-accounting-response','duplicate-accounting-request'],{'network.accounting.stored':['Start','Interim-Update','Stop'],'network.accounting.acked':['Start','Interim-Update','Stop']}],
  ['radius-udp-radsec',['inner-outer-TLS-confusion'],{'sessions.udp.active':true,'sessions.radsec':undefined,'network.comparison.radsec':'pending','network.logicalAuthentications':1}],
  ['radsec-peer-rejected',['wrong-transport-peer','untrusted-transport-issuer'],{'network.transport':'peer rejected','network.logicalAuthentications':0,'sessions.access':undefined}],
  ['radius-proxy-realm',['wrong-home-route','wrong-hop-secret','Proxy-State-order'],{'network.port':'unauthorized','sessions.access':undefined}],
  ['radius-proxy-unknown-realm',['unknown-realm'],{'network.homeContacted':false,'network.port':'unauthorized'}],
  ['radius-coa-ack',['lost-CoA-ACK'],{'sessions.access.filter':'quarantine','network.controllerKnowledge':'unknown','network.logicalOperations':1}],
  ['radius-coa-ack',['duplicate-CoA-request'],{'sessions.access.filter':'quarantine','network.controllerKnowledge':'changed','network.logicalOperations':1}],
  ['radius-coa-ack',['untrusted-client','invalid-request-authenticator','stale-Event-Timestamp'],{'sessions.access.filter':'employee-wired','network.controllerKnowledge':'unknown','network.logicalOperations':0}],
  ['radius-coa-ack',['wrong-recipient'],{'sessions.access.filter':'employee-wired','network.controllerKnowledge':'rejected','network.errorCause':403}],
  ['radius-coa-nak',['unsupported-service'],{'sessions.access.filter':'employee-wired','network.errorCause':405}],
  ['radius-coa-nak',['unsupported-attribute'],{'sessions.access.filter':'employee-wired','network.errorCause':401}],
  ['radius-coa-nak',['session-not-found'],{'sessions.access':undefined,'network.errorCause':503}],
  ['radius-coa-nak',['stale-Event-Timestamp'],{'sessions.access.filter':'employee-wired','network.controllerKnowledge':'unknown'}],
  ['radius-disconnect-ack',['lost-Disconnect-ACK'],{'sessions.access.active':false,'sessions.unrelated.active':true,'network.controllerKnowledge':'unknown','network.accounting.stored':['Stop']}],
  ['radius-disconnect-ack',['duplicate-Disconnect-request'],{'sessions.access.active':false,'network.logicalOperations':1,'network.accounting.stored':['Stop']}],
  ['radius-disconnect-ack',['stale-session'],{'sessions.access':undefined,'sessions.unrelated.active':true,'network.errorCause':503}],
  ['radius-disconnect-ack',['stale-Event-Timestamp'],{'sessions.access.active':true,'sessions.unrelated.active':true,'network.controllerKnowledge':'unknown'}],
  ['radius-disconnect-nak',['session-not-found'],{'sessions.unrelated.active':true,'network.errorCause':503}],
  ['radius-disconnect-nak',['untrusted-client','invalid-request-authenticator','stale-Event-Timestamp'],{'sessions.unrelated.active':true,'network.controllerKnowledge':'unknown'}],
  ['radius-udp-retransmission',['late-reply','wrong-transaction','invalid-response-authenticator'],{'network.logicalAuthentications':1,'network.port':'unauthorized','network.reply':'discarded','sessions.access':undefined}],
  ['enterprise-wifi-eap',['no-usable-protected-link'],{'network.port':'decision-only','network.wifiUsable':false,'sessions.access':undefined}],
  ['radius11',['Message-Authenticator-ignored','reserved-field-ignored'],{'network.port':'authorized','network.usesMd5':false,'network.usesRadiusSharedSecret':false}],
  ['radius11',['wrong-token'],{'network.port':'unauthorized','network.reply':'discarded','sessions.access':undefined}],
  ['radius11-required-unavailable',['absent-ALPN','only-radius10','no-common-ALPN'],{'network.transport':'required profile unavailable','network.logicalAuthentications':0,'network.fallback':false}],
];
for(const [suffix,variants,expected] of netNegativeGroups)for(const variant of variants)test('Named network input: '+suffix+' / '+variant,()=>{
  const original=JSON.stringify(NETWORKLAB_ATTRIBUTES);
  const model=buildNetworkScenarioFixture('lab-net-'+suffix,{variant}),final=netFinal(model);
  for(const [path,value] of Object.entries(expected))assert.deepEqual(netPath(final,path),value,path);
  assert.equal(NETWORKLAB_SCENARIOS.length,23,'Negative inputs are not extra catalog entries');
  assert.equal(JSON.stringify(NETWORKLAB_ATTRIBUTES),original,'Fixture construction does not mutate canonical field help/values');
  if(['invalid-Message-Authenticator','untrusted-client','invalid-request-authenticator','stale-Event-Timestamp'].includes(variant))assert.ok(!model.steps().some(step=>step.from!==step.to&&step.payload.some(field=>/Access-Reject|CoA-NAK|Disconnect-NAK/.test(String(field.value)))),'Silent discard does not manufacture a reject/NAK');
});

test('Independent negative worksheets distinguish detector-boundary state from terminal propagation',async()=>{
  const {readFile}=await import('node:fs/promises');
  const worksheet=JSON.parse(await readFile(new URL('../docs/expansion/network-scenarios.json',import.meta.url),'utf8'));
  for(const row of worksheet.scenarios)for(const negative of row.negativeCases){
    const model=buildNetworkScenarioFixture(row.id,{variant:negative.name});
    const boundary=model.steps().findIndex(step=>step.id===row.id+':'+negative.detectionBoundary);
    assert.ok(boundary>=0,row.id+'/'+negative.name+' has its own detector event');
    const detected=reconstructProtocolState(model,boundary),terminal=netFinal(model);
    for(const [label,state,predicates] of [['detected',detected,negative.stateAfterDetection],['terminal',terminal,negative.terminalPredicate]]){
      for(const [path,value] of Object.entries(predicates))assert.deepEqual(netPath(state,path),value==='absent'?undefined:value,row.id+'/'+negative.name+'/'+label+'/'+path);
    }
  }
});

for(const suffix of ['radius-password-totp','radius-challenge-rejected'])for(const variant of ['missing-State','altered-State'])test('Invalid issued State skips factor validation: '+suffix+' / '+variant,()=>{
  const model=buildNetworkScenarioFixture('lab-net-'+suffix,{variant});
  const check=model.steps().find(step=>step.id===model.id+':factor-check');
  assert.equal(check.payload.find(field=>field.name==='TOTP check').value,'not evaluated');
  const observations=model.networkInventory.events[check.id].effects.filter(effect=>effect.op==='observe');
  assert.ok(observations.some(effect=>effect.artifactId===model.id+':challenge-context:g1'&&effect.result==='invalid'));
  assert.ok(!observations.some(effect=>effect.artifactId===model.id+':totp-code:g1'),'Context failure is not a claim that the supplied TOTP was evaluated');
});

test('NET-01 RFC9190 exporter fields and local key provenance use the one-octet EAP Type context',()=>{
  let exporters=0;
  for(const model of NETWORKLAB_SCENARIOS)for(const step of model.steps().filter(step=>step.protocolLabel==='Local RFC 9190 exporter')){
    exporters++;
    const fields=Object.fromEntries(step.payload.map(field=>[field.name,field.value]));
    assert.equal(fields['Exporter label'],'EXPORTER_EAP_TLS_Key_Material');
    assert.equal(fields['Exporter context'],'0x0D (one octet)');
    assert.equal(fields['Exporter length'],'128 octets');
    assert.equal(fields.MSK,'octets 0-63 (64 octets)');
    assert.equal(fields.EMSK,'octets 64-127 (64 octets)');
    assert.equal(fields.Exporter,'TLS-Exporter(label EXPORTER_EAP_TLS_Key_Material, context Type=0x0D (one octet), length 128)');
    for(const field of step.payload.filter(field=>field.name.startsWith('Exporter'))){
      const definition=model.definitions()[field.attributeId];
      assert.equal(definition.standard,'RFC 9190');assert.equal(definition.section,'2.3');
    }
    const objects=model.networkInventory.events[step.id].effects.filter(effect=>effect.op==='create').map(effect=>model.networkInventory.artifacts.find(artifact=>artifact.artifactId===effect.artifactId));
    assert.equal(objects.length,2);
    for(const artifact of objects){
      const value=artifact.representations.find(rep=>rep.representationId==='plain').fields[0].value;
      assert.match(value,/EXPORTER_EAP_TLS_Key_Material, context Type=0x0D \(one octet\), length 128/);
      assert.match(value,/EMSK/.test(artifact.label)?/EMSK octets 64-127/:/MSK octets 0-63/);
    }
  }
  assert.equal(exporters,12,'Both endpoints in all five applicable default presets, including both T01 transactions');
  for(const step of netModel('nps-ad-tls12').steps().filter(step=>step.protocolLabel==='Local RFC5216 PRF')){
    assert.equal(step.payload.find(field=>field.name==='PRF').value,'TLS-PRF(master_secret, client EAP encryption, client_random || server_random)');
    assert.ok(!step.payload.some(field=>field.name.startsWith('Exporter')));
  }
});

test('NET-02 every default and named-input request view retains the original required NAS identity',()=>{
  const fixtures=[...NETWORKLAB_SCENARIOS,...netNegativeGroups.flatMap(([suffix,variants])=>variants.map(variant=>buildNetworkScenarioFixture('lab-net-'+suffix,{variant})))];
  for(const model of fixtures){
    const expected=model.id==='lab-net-enterprise-wifi-eap'?'ap.corp.example':'switch.corp.example';
    const views=[...model.steps().map(step=>({id:step.id,fields:step.payload})),...model.networkInventory.artifacts.flatMap(artifact=>artifact.representations.map(rep=>({id:artifact.artifactId+'/'+rep.representationId,fields:rep.fields})))];
    for(const view of views){
      const fields=Object.fromEntries(view.fields.map(field=>[field.name,field.value]));
      if(!/Access-Request|Accounting-Request/.test(fields.Code||''))continue;
      assert.equal(fields['NAS-Identifier'],expected,model.negativeVariant+' / '+view.id);
    }
  }
  const proxy=netModel('radius-proxy-realm');
  for(const key of ['identity-backend','clienthello-backend','peerflight-backend','empty-backend']){
    const pair=[key+'-ingress',key].map(suffix=>proxy.steps().find(step=>step.id===proxy.id+':'+suffix));
    assert.equal(pair[0].payload.find(field=>field.name==='NAS-Identifier').value,'switch.corp.example');
    assert.equal(pair[1].payload.find(field=>field.name==='NAS-Identifier').value,'switch.corp.example');
  }
});

test('NET-04 pinned source and composite profile categories preserve Informational versus Experimental',()=>{
  const categories={
    'RFC 2865':'Standards Track','RFC 3579':'Informational','RFC 3748':'Standards Track','RFC 9190':'Standards Track',
    'RFC 5216':'Standards Track','RFC 5247':'Standards Track','RFC 2548':'Informational','RFC 6238':'Informational',
    'RFC 2866':'Informational','RFC 2869':'Informational','RFC 5080':'Standards Track','RFC 5176':'Informational',
    'RFC 6614':'Experimental','RFC 9765':'Experimental','RFC 8446':'Standards Track','RFC 5246':'Standards Track','RFC 3580':'Informational',
  };
  for(const source of NETWORKLAB_SOURCES.filter(source=>source.standard.startsWith('RFC ')))assert.equal(source.publicationStatus,categories[source.standard],source.standard);
  for(const model of NETWORKLAB_SCENARIOS)for(const source of model.profile.sources.filter(source=>source.standard.startsWith('RFC ')))assert.equal(source.publicationStatus,categories[source.standard],model.id+'/'+source.standard);
});

test('Independent correction worksheet pins exporter bytes, NAS identity and all eight RadSec decode contracts',async()=>{
  const {readFile}=await import('node:fs/promises');
  const worksheet=JSON.parse(await readFile(new URL('../docs/expansion/network-scenarios.json',import.meta.url),'utf8'));
  const expected=worksheet.reviewCorrections;
  assert.equal(expected.exporter.label,'EXPORTER_EAP_TLS_Key_Material');
  assert.deepEqual([...Buffer.from(expected.exporter.contextHex,'hex')],[13]);
  assert.equal(expected.exporter.contextLengthOctets,1);assert.equal(expected.exporter.outputLengthOctets,128);
  assert.deepEqual(expected.exporter.mskRange,[0,64]);assert.deepEqual(expected.exporter.emskRange,[64,128]);
  const model=netModel('radius-udp-radsec'),row=worksheet.scenarios.find(row=>row.id===model.id);
  const transmissions=row.messageLedger.filter(message=>message.representationId==='outer-wire');
  assert.equal(transmissions.length,8);
  assert.deepEqual(transmissions.map(message=>message.event.slice('radsec:'.length)),expected.radsec.eventSuffixes);
  for(const message of transmissions){
    const wire=model.steps().find(step=>step.id===model.id+':'+message.event),decode=model.steps().find(step=>step.id===model.id+':'+message.decodeEvent);
    assert.deepEqual(Object.fromEntries(wire.payload.map(field=>[field.name,field.value])),message.fields);
    assert.equal(wire.layers[0].keyRef,message.keyReference);
    assert.equal(decode.from,message.decodeActor);assert.equal(decode.to,message.decodeActor);
    assert.equal(decode.layers[0].keyRef,message.decodeKeyReference);
    assert.equal(decode.payload.find(field=>field.name==='Code').value,message.decodedFields.Code);
    if(message.decodedFields.Code==='Access-Request')assert.equal(decode.payload.find(field=>field.name==='NAS-Identifier').value,expected.nasIdentity.wired);
  }
  for(const [standard,category] of Object.entries(expected.sourceCategories))assert.equal(NETWORKLAB_SOURCES.find(source=>source.standard===standard).publicationStatus,category);
});

test('NET-05 all 53 recovered RadSec fields are receiver-local decrypt replays with exact canonical provenance',()=>{
  const model=netModel('radius-udp-radsec'),steps=model.steps(),definitions=model.definitions();
  const previous=Object.fromEntries(Object.keys(definitions).map(id=>[id,ATTRIBUTES[id]]));
  Object.assign(ATTRIBUTES,definitions);
  try{
    const decodes=steps.filter(step=>step.id.includes(':radsec:')&&step.id.endsWith('-decode'));
    assert.equal(decodes.length,8);
    let count=0;
    for(const decode of decodes){
      const index=steps.indexOf(decode),wire=steps[index-1];
      const original=steps.find(step=>step.id===decode.id.replace(':radsec:',':udp:').replace(/-decode$/,''));
      assert.equal(decode.from,wire.to);assert.equal(decode.to,wire.to);
      assert.deepEqual(decode.payload.map(field=>[field.name,field.value]),original.payload.map(field=>[field.name,field.value]));
      for(const field of decode.payload){
        count++;
        const actions=decode.attributeOperations.filter(action=>action.attributeId===field.attributeId);
        assert.equal(actions.length,1);
        const action=actions[0];
        assert.equal(action.kind,'decrypt');assert.equal(action.actorId,wire.to);
        assert.equal(action.representation,'radius-decoded');assert.equal(action.value,field.value);
        assert.equal(action.sourceEventId,decode.id);assert.equal(action.fieldPath,field.name);
        assert.equal(action.instanceId,decode.id+':fields');
        assert.equal(action.exactValueRef,decode.id+':fields:radius-decoded:'+field.name);
        assert.deepEqual(action.holders,[wire.to]);
        const trace=buildAttributeTrace(getAttributeUsage(steps,field.attributeId));
        assert.equal(trace.length,1);assert.equal(trace[0].traceKind,'decrypt');
        assert.equal(trace[0].sourceIndex,index);assert.equal(trace[0].sourceStepId,decode.id);
        assert.equal(trace[0].from,wire.to);assert.equal(trace[0].to,wire.to);
        assert.deepEqual(trace[0].traceActions,actions);
        assert.equal(trace[0].payload[0].value,field.value);
        assert.deepEqual(getAttributeContext(steps,field.attributeId),[]);
      }
    }
    assert.equal(count,53);
    const context=steps.flatMap(step=>step.attributeOperations).find(action=>action.kind==='inspect');
    assert.ok(context);
    assert.deepEqual(getAttributeUsage(steps,context.attributeId),[]);
    assert.ok(getAttributeContext(steps,context.attributeId).length);
  }finally{
    for(const id of Object.keys(definitions)){
      if(previous[id])ATTRIBUTES[id]=previous[id];else delete ATTRIBUTES[id];
    }
  }
});
