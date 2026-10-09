import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { SSHLAB_ATTRIBUTES, SSHLAB_SCENARIOS, SSHLAB_SOURCES } from '../src/ssh-access-lab.js';
import { reconstructProtocolState, buildProtocolInstances, validateProtocolScenario } from '../src/protocol-state.js';
import { projectScenarioContext, scenarioContextRows } from '../src/scenario-context.js';

const model=id=>SSHLAB_SCENARIOS.find(item=>item.id==='lab-ssh-'+id);
const step=(m,key)=>m.steps().find(item=>item.sshStage===key);
const index=(m,key)=>m.steps().indexOf(step(m,key));
const after=(m,key)=>reconstructProtocolState(m,index(m,key));
const last=m=>reconstructProtocolState(m,m.steps().length-1);
const definitions=m=>m.definitions();
const attribute=(m,name)=>Object.keys(definitions(m)).find(id=>definitions(m)[id].name===name);
const wire=s=>s.attributeOperations.filter(operation=>['send','receive'].includes(operation.kind));
const packet=(m,key,name)=>step(m,key).payload.find(item=>item.name===name)?.value;

function readCertificate(base64) {
  const bytes=Buffer.from(base64,'base64');let offset=0;
  const u32=()=>{const value=bytes.readUInt32BE(offset);offset+=4;return value;};
  const u64=()=>{const value=Number(bytes.readBigUInt64BE(offset));offset+=8;return value;};
  const string=()=>{const length=u32(),value=bytes.subarray(offset,offset+length);offset+=length;return value;};
  const result={algorithm:string().toString(),nonce:string(),publicKey:string(),serial:u64(),type:u32(),keyId:string().toString()};
  const principals=string();let principalOffset=0;result.principals=[];
  while(principalOffset<principals.length){const length=principals.readUInt32BE(principalOffset);principalOffset+=4;result.principals.push(principals.subarray(principalOffset,principalOffset+length).toString());principalOffset+=length;}
  result.validAfter=u64();result.validBefore=u64();result.criticalOptions=string();result.extensions=string();result.reserved=string();result.caPublicKey=string();result.signature=string();
  assert.equal(offset,bytes.length,'Decoded certificate consumes the exact wire fixture, without trailing bytes.');
  return result;
}

test('SSH catalog exposes four qualified architectures and every source event has valid state/instance history',()=>{
  assert.equal(SSHLAB_SCENARIOS.length,29);
  assert.equal(new Set(SSHLAB_SCENARIOS.map(item=>item.id)).size,29);
  const allIds=new Set();
  for(const m of SSHLAB_SCENARIOS){
    assert.equal(m.workspace,'ssh');assert.equal(m.protocol,'ssh');assert.equal(m.family,'ssh-access');assert.ok(m.supportNote);
    assert.ok(['reference','documented-architecture'].includes(m.evidenceLevel));assert.ok(Array.isArray(m.runtimeBindings));assert.ok(Object.keys(m.actors()).length<=9);
    const valid=validateProtocolScenario(m);assert.deepEqual(valid.errors,[],m.id);
    for(let position=-1;position<m.steps().length;position++){
      assert.ok(Object.isFrozen(reconstructProtocolState(m,position)));
      assert.ok(Object.isFrozen(buildProtocolInstances(m,position)));
    }
    const defs=m.definitions();
    for(const id of m.ids){allIds.add(id);assert.ok(defs[id]);for(const key of ['name','meaning','origin','purpose','example','standard','source'])assert.notEqual(defs[id][key],undefined,id+': '+key);}
    for(const event of m.steps()){
      assert.ok(m.actors()[event.from]);assert.ok(m.actors()[event.to]);assert.ok(event.interactionType);
      for(const operation of event.attributeOperations){assert.ok(defs[operation.attributeId]);assert.ok(operation.instanceId);assert.ok(operation.fieldPath);assert.ok(operation.representation);assert.equal(operation.sourceEventId,event.id);assert.deepEqual(m.protocolValues[operation.exactValueRef],operation.value);}
    }
  }
  assert.deepEqual(allIds,new Set(Object.keys(SSHLAB_ATTRIBUTES)));
  assert.ok(SSHLAB_SOURCES.every(source=>source.url.startsWith('https://')));
  for(const id of ['cert-success','device-cadence','sssd-success','gss-success'])assert.equal(model(id).featured,true);
});

test('native CLI PKCE is created locally, challenge crosses authorization, verifier crosses only direct redemption',()=>{
  const m=model('cert-success'),verifier=attribute(m,'code_verifier'),challenge=attribute(m,'code_challenge');
  const secret=step(m,'prepare').attributeOperations.find(operation=>operation.attributeId===verifier&&operation.kind==='create');
  assert.equal(secret.actorId,'sshCli');
  const digest=createHash('sha256').update(secret.value,'ascii').digest('base64url');
  assert.equal(step(m,'prepare').attributeOperations.find(operation=>operation.attributeId===challenge).value,digest);
  for(const key of ['open-browser','authorize']){
    assert.ok(wire(step(m,key)).some(operation=>operation.attributeId===challenge));
    assert.equal(wire(step(m,key)).some(operation=>operation.attributeId===verifier),false);
  }
  assert.deepEqual(wire(step(m,'redeem')).filter(operation=>operation.attributeId===verifier).map(operation=>operation.actorId),['sshCli','sshIdp']);
  assert.match(packet(m,'callback','redirect_uri'),/^http:\/\/127\.0\.0\.1:\d+\/oauth\/callback$/);
  assert.ok(index(m,'callback-check')<index(m,'redeem'));assert.equal(after(m,'validate-identity').transaction.focus,'terminal');
});

test('Smallstep enrollment carries exact public SSH bytes + ID-token ott, with provisioner-client audience',()=>{
  const m=model('cert-success'),request=step(m,'enroll');
  assert.deepEqual(request.payload.map(item=>item.name),['publicKey','ott','certType','keyID','principals','validAfter','validBefore']);
  const publicBytes=Buffer.from(packet(m,'enroll','publicKey'),'base64');
  assert.equal(publicBytes.readUInt32BE(0),11);assert.equal(publicBytes.subarray(4,15).toString(),'ssh-ed25519');assert.equal(publicBytes.readUInt32BE(15),32);assert.equal(publicBytes.length,51);
  assert.equal(packet(m,'enroll','ott'),packet(m,'tokens','id_token'));
  assert.equal(definitions(m)[attribute(m,'aud')].example,'step-ssh');
  assert.match(definitions(m)[attribute(m,'aud')].purpose,/not the CA URL or SSH hostname/);
  assert.equal(request.payload.some(item=>/csr|signature|proof/i.test(item.name)),false);
  assert.match(request.detail,/no mandatory SSH CSR/);
  assert.ok(!request.payload.some(item=>item.name==='access_token'));
});

test('certificate wire object is identical at issuance, response, installation and userauth, with independent signatures',()=>{
  const m=model('cert-success'),encoded=packet(m,'certificate','crt'),decoded=readCertificate(encoded);
  assert.equal(decoded.algorithm,'ssh-ed25519-cert-v01@openssh.com');assert.equal(decoded.type,1);assert.equal(decoded.serial,1);assert.deepEqual(decoded.principals,['alice']);assert.equal(decoded.publicKey.length,32);assert.ok(decoded.validBefore>decoded.validAfter);
  assert.equal(packet(m,'install','crt'),encoded);assert.equal(packet(m,'userauth','public key blob'),encoded);
  const instances=buildProtocolInstances(m,m.steps().length-1),cert=instances.find(item=>item.instanceId.endsWith(':certificate-1'));
  assert.equal(cert.creator,'sshCa');assert.ok(cert.holders.includes('sshAgent'));assert.ok(cert.holders.includes('sshHost'));
  for(const name of ['signature (certificate CA)','signature (server key exchange)','signature (SSH user proof)'])assert.ok(attribute(m,name));
  assert.notEqual(attribute(m,'signature (certificate CA)'),attribute(m,'signature (SSH user proof)'));
  assert.match(step(m,'issue').detail,/synthetic.*illustrative/);
});

test('SSH network publickey packet contains eight canonical fields and never transmits the local session identifier or private key',()=>{
  const m=model('cert-success'),request=step(m,'userauth');
  assert.deepEqual(request.payload.map(item=>item.name),['SSH_MSG_USERAUTH_REQUEST','user name','service name','method name','boolean TRUE','public key algorithm name','public key blob','signature (SSH user proof)']);
  assert.equal(packet(m,'userauth','boolean TRUE'),true);assert.equal(packet(m,'userauth','service name'),'ssh-connection');assert.equal(packet(m,'userauth','method name'),'publickey');
  const session=attribute(m,'session identifier (local)');
  assert.equal(wire(request).some(operation=>operation.attributeId===session),false);
  assert.ok(step(m,'sign').attributeOperations.some(operation=>operation.actorId==='sshAgent'&&operation.kind==='use'));
  assert.ok(step(m,'host-policy').attributeOperations.some(operation=>operation.attributeId===session&&operation.kind==='verify'&&operation.actorId==='sshHost'));
  for(const event of m.steps())if(event.interactionType==='network')for(const operation of wire(event))assert.doesNotMatch(definitions(m)[operation.attributeId].name,/private key|private\)/i);
  for(const event of m.steps())if([event.from,event.to].includes('sshHost'))for(const operation of wire(event))assert.doesNotMatch(definitions(m)[operation.attributeId].name,/id_token|access_token|^ott$/);
});

test('wrong audience comparison preserves a valid native login then rejects a distinct token at the CA boundary',()=>{
  const m=model('cert-audience'),aud=attribute(m,'aud');
  assert.equal(step(m,'validate-identity').attributeOperations.find(operation=>operation.attributeId===aud).value,'step-ssh');
  assert.ok(index(m,'validate-identity')<index(m,'alternate-token-issued'));assert.ok(index(m,'alternate-token-input')<index(m,'enroll'));
  const check=step(m,'ca-identity').attributeOperations.find(operation=>operation.attributeId===aud);
  assert.equal(check.value,'another-client');assert.ok(check.instanceId.endsWith(':id-token-2'));
  assert.notEqual(packet(m,'enroll','ott'),packet(m,'tokens','id_token'));
  assert.equal(last(m).failure.actor,'sshCa');assert.equal(last(m).failure.reason,'wrong_id_token_audience');assert.equal(last(m).credentials.userCertificate,undefined);
});

test('callback and verifier errors stop before enrollment and keep foreign transaction objects distinct',()=>{
  for(const [variant,key,actor] of [['callback','callback-check','sshCli'],['pkce','pkce-check','sshIdp']]){
    const m=model('cert-'+variant);assert.equal(step(m,'enroll'),undefined);assert.equal(last(m).credentials.userCertificate,undefined);assert.equal(last(m).failure.actor,actor);assert.equal(last(m).failure.event,step(m,key).id);
  }
  const m=model('cert-callback'),state=attribute(m,'state');
  const original=step(m,'prepare').attributeOperations.find(operation=>operation.attributeId===state),incoming=wire(step(m,'callback')).find(operation=>operation.attributeId===state);
  assert.notEqual(original.instanceId,incoming.instanceId);
});

test('host trust precedes user proof; issuer trust, copied certificate, cross-session proof and account denials have separate outcomes',()=>{
  const host=model('cert-host');assert.equal(step(host,'userauth'),undefined);assert.equal(last(host).failure.reason,'untrusted_host_key');assert.equal(last(host).credentials.userCertificate.status,'installed');
  const reasons={userca:'untrusted_user_ca',copy:'wrong_private_key',session:'signature_wrong_transport',account:'account_access_denied',root:'principal_account_mismatch'};
  for(const [variant,reason] of Object.entries(reasons)){
    const m=model('cert-'+variant);assert.ok(step(m,'userauth'));assert.equal(last(m).failure.actor,'sshHost');assert.equal(last(m).failure.reason,reason);assert.equal(last(m).sessions.ssh.authenticated,false);assert.equal(step(m,'channel'),undefined);assert.equal(last(m).credentials.userCertificate.status,'installed');
  }
  assert.equal(last(model('cert-copy')).credentials.matchingKeyAvailable,false);assert.ok(last(model('cert-copy')).credentials.userKey.instanceId.endsWith(':key-2'));
  const principal=model('cert-principal');assert.deepEqual(packet(principal,'enroll','principals'),['root']);assert.equal(step(principal,'issue'),undefined);assert.equal(last(principal).failure.reason,'unauthorized_principal');
});

test('revocation publication, host installation, token/certificate expiry and existing channels retain separate authority and knowledge',()=>{
  const m=model('cert-lifecycle'),initial=reconstructProtocolState(m,-1);
  assert.equal(initial.protocolClock,1791381600);assert.equal(initial.lifetimes.oauthToken.expiresAt,1791381900);assert.equal(initial.lifetimes.sshCertificate.expiresAt,1791385200);assert.equal(initial.lifetimes.sshSession.expiresAt,null);
  assert.equal(after(m,'disable').authorities.idp.userEnabled,false);assert.equal(after(m,'disable').sessions.ssh.authenticated,true);
  const published=after(m,'publish-revocation');assert.deepEqual(published.authorities.ca.publishedRevocations,[1]);assert.deepEqual(published.knowledge.host.revokedSerials,[]);
  assert.deepEqual(after(m,'install-revocation').knowledge.host.revokedSerials,[1]);assert.equal(after(m,'new-auth-revoked').lifecycle.newAuthenticationAfterInstall,'rejected_revoked_certificate');
  assert.equal(after(m,'token-expiry').credentials.idToken.status,'expired');assert.equal(after(m,'token-expiry').credentials.userCertificate.status,'installed');
  assert.equal(after(m,'certificate-expiry').protocolClock,1791385201);assert.equal(after(m,'certificate-expiry').credentials.userCertificate.status,'expired');assert.equal(after(m,'certificate-expiry').sessions.ssh.authenticated,true);
  assert.equal(last(m).sessions.ssh.channels,2);assert.equal(last(m).lifecycle.reissuanceOutcome,'denied_by_current_authorities');
  assert.deepEqual(after(m,'publish-revocation').knowledge.host.revokedSerials,[],'Seeking backwards must not retain future KRL installation.');
});

test('positive user-certificate reissuance requires fresh factor approval and creates certificate2 while retaining key1',()=>{
  const m=model('cert-reissue'),before=after(m,'channel'),final=last(m);
  assert.equal(final.credentials.userKey.instanceId,before.credentials.userKey.instanceId);assert.notEqual(final.credentials.userCertificate.instanceId,before.credentials.userCertificate.instanceId);
  assert.equal(final.credentials.userCertificate.serial,2);assert.equal(final.credentials.userCertificate.publicKeyInstance,before.credentials.userKey.instanceId);assert.ok(final.credentials.userCertificate.validBefore>before.credentials.userCertificate.validBefore);
  assert.equal(final.credentials.userCertificate.status,'installed');assert.equal(final.credentials.idToken.instanceId.endsWith(':id-token-2'),true);
  assert.ok(index(m,'reissue-factor-check')<index(m,'reissue-token-issue'));assert.ok(index(m,'reissue-policy')<index(m,'reissue-issue'));
  assert.notEqual(packet(m,'reissue-enroll','ott'),packet(m,'enroll','ott'));assert.equal(packet(m,'reissue-enroll','publicKey'),packet(m,'enroll','publicKey'));
  const first=readCertificate(packet(m,'certificate','crt')),second=readCertificate(packet(m,'reissue-certificate','crt'));
  assert.equal(second.serial,2);assert.deepEqual(second.publicKey,first.publicKey);assert.notEqual(second.keyId,first.keyId);assert.ok(second.validBefore>first.validBefore);
  assert.equal(final.sessions.ssh.channels,1,'Installing a new certificate does not reauthenticate an existing SSH connection.');
});

test('RFC Device reference defaults omitted interval, accumulates slow_down and backs off timeout without early polls',()=>{
  const m=model('device-cadence');assert.ok(!step(m,'response').payload.some(item=>item.name==='interval'));
  assert.equal(after(m,'default-interval').transaction.pollInterval,5);assert.equal(after(m,'slow-1').transaction.pollInterval,10);assert.equal(after(m,'slow-2').transaction.pollInterval,15);assert.equal(after(m,'timeout').transaction.pollInterval,30);
  const pollTimes=['poll-1','poll-2','poll-3','poll-4','final-poll'].map(key=>after(m,key).protocolClock);
  assert.deepEqual(pollTimes,[1791381605,1791381610,1791381620,1791381635,1791381665]);
  assert.equal(after(m,'human-approve').transaction.approved,true);assert.equal(after(m,'human-approve').transaction.status,'pending');assert.equal(after(m,'tokens').transaction.status,'complete');
  for(const key of ['poll-1','poll-2','poll-3','poll-4','final-poll'])assert.deepEqual(step(m,key).payload.map(item=>item.name),['grant_type','client_id','device_code']);
  assert.match(m.supportNote,/Smallstep.*4xx.*same interval/);assert.equal(last(m).sessions.ssh.authenticated,true);
});

test('Device terminal errors and cancellation cannot accept later success; a restart uses fresh codes',()=>{
  for(const [variant,reason] of [['denied','access_denied'],['expired','expired_token'],['clienterror','unauthorized_client']]){
    const m=model('device-'+variant);assert.equal(last(m).failure.reason,reason);assert.equal(last(m).transaction.pollingStopped,true);assert.equal(step(m,'enroll'),undefined);
  }
  const expired=model('device-expired');assert.ok(last(expired).protocolClock>last(expired).transaction.expiresAt);
  const cancelled=model('device-cancel');assert.equal(last(cancelled).transaction.status,'cancelled');assert.equal(last(cancelled).transaction.lateResultIgnored,true);assert.equal(last(cancelled).credentials.idToken,undefined);assert.equal(step(cancelled,'enroll'),undefined);
  const restart=model('device-restart');assert.equal(last(restart).transactions.old.status,'cancelled');assert.ok(last(restart).transaction.instanceId.endsWith(':device-transaction-2'));assert.equal(packet(restart,'final-poll','device_code'),'device-ssh-cli-2');assert.equal(packet(restart,'restart-display','user_code'),'ABCD-5678');
});

test('SSSD remote client keeps private Device codes, client authentication and all tokens off the workstation prompt path',()=>{
  for(const m of SSHLAB_SCENARIOS.filter(item=>item.id.startsWith('lab-ssh-sssd-'))){
    assert.equal(m.actors().sssd.parentId,'sshHost');assert.equal(m.actors().pam.parentId,'sshHost');assert.match(m.supportNote,/Technology Preview/);assert.match(m.supportNote,/not a verified trace/);
    for(const event of m.steps())for(const operation of wire(event)){
      const name=definitions(m)[operation.attributeId].name;
      if(/device_code|client_secret|Client authentication|access_token|Authorization \(identity lookup\)/.test(name))assert.ok(['sssd','sshIdp'].includes(operation.actorId),event.id+' '+name);
    }
  }
  const m=model('sssd-success');assert.equal(step(m,'device-request').from,'sssd');assert.equal(step(m,'poll').from,'sssd');assert.ok(index(m,'host-check')<index(m,'device-request'));
  assert.deepEqual(Object.keys(packet(m,'sssd-info','SSS_PAM_OAUTH2_INFO')),['verification_uri','verification_uri_complete','user_code']);
  assert.deepEqual(step(m,'poll').payload.map(item=>item.name),['grant_type (Device polling)','client_id (Device authentication)','Client authentication (remote SSSD)','device_code']);
});

test('keyboard-interactive Enter is one empty string; a zero-prompt comparison has zero responses',()=>{
  const m=model('sssd-success'),zero=model('sssd-zero');
  assert.equal(packet(m,'ssh-info','SSH_MSG_USERAUTH_INFO_REQUEST').num_prompts,1);assert.equal(packet(m,'ssh-info','SSH_MSG_USERAUTH_INFO_REQUEST').prompts[0].echo,false);
  assert.deepEqual(packet(m,'conversation-response','SSH_MSG_USERAUTH_INFO_RESPONSE'),{num_responses:1,responses:['']});
  assert.deepEqual(packet(zero,'conversation-response','SSH_MSG_USERAUTH_INFO_RESPONSE'),{num_responses:0,responses:[]});
  assert.equal(packet(zero,'ssh-info','SSH_MSG_USERAUTH_INFO_REQUEST').num_prompts,0);assert.match(step(m,'conversation-response').detail,/not ENTER, newline, user_code or device_code/);
});

test('SSSD service lookup and interactive tokens are independent; cached lookup skips API and never skips Device approval',()=>{
  const m=model('sssd-success'),cached=model('sssd-cached');
  assert.equal(packet(m,'lookup-token-request','grant_type (identity lookup)'),'client_credentials');assert.notEqual(packet(m,'lookup-token','access_token (identity lookup service)'),packet(m,'token-result','access_token (interactive user)'));
  assert.equal(step(cached,'lookup-token-request'),undefined);assert.equal(step(cached,'lookup-query'),undefined);assert.ok(step(cached,'cached-lookup'));assert.ok(step(cached,'device-request'));assert.ok(step(cached,'identity-match'));
  assert.equal(last(m).policy.createLocalAccount,false);assert.equal(last(m).policy.createHome,false);assert.equal(last(m).policy.createKerberosTgt,false);assert.equal(last(m).credentials.homeTgt,undefined);
});

test('SSSD approved identity mismatch, identity lookup and account policy reject at their owning boundary',()=>{
  for(const [variant,actor,event] of [['bob','sssd','identity-match'],['domain','sssd','identity-match'],['account','pam','account-policy'],['lookup','sssd','lookup-failed'],['permission','sssd','lookup-failed']]){
    const m=model('sssd-'+variant);assert.equal(last(m).failure.actor,actor);assert.equal(last(m).failure.event,step(m,event).id);assert.equal(last(m).sessions.ssh.authenticated,false);assert.equal(step(m,'channel'),undefined);
    if(['lookup','permission'].includes(variant))assert.equal(step(m,'device-created'),undefined);
    else assert.equal(last(m).transaction.status,'complete','A successful OAuth token result must not bypass local identity/account rejection.');
  }
  assert.notEqual(last(model('sssd-bob')).resolvedIdentity.providerId,last(model('sssd-bob')).approvedIdentity.providerId);
  assert.notEqual(last(model('sssd-domain')).resolvedIdentity.domain,last(model('sssd-domain')).approvedIdentity.domain);
});

test('SSH GSS uses Kerberos context tokens and a MIC after context completion; no SPNEGO/HTTP exchange is emitted',()=>{
  const m=model('gss-success');assert.equal(packet(m,'gss-offer','method name'),'gssapi-with-mic');assert.match(packet(m,'gss-offer','GSS mechanism OID'),/^1\.2\.840\.113554\.1\.2\.2/);
  assert.equal(after(m,'context-complete').sessions.gss.established,true);assert.ok(index(m,'context-complete')<index(m,'mic-create'));assert.ok(index(m,'mic')<index(m,'mic-check'));
  assert.deepEqual(step(m,'mic').payload.map(item=>item.name),['SSH_MSG_USERAUTH_GSSAPI_MIC']);assert.equal(last(m).policy.delegation,false);assert.equal(last(m).policy.gssKeyExchange,false);
  for(const event of m.steps())for(const item of event.payload)assert.doesNotMatch(String(item.value),/SPNEGO|negTokenInit|Authorization:|WWW-Authenticate:/);
  const denied=model('gss-account');assert.equal(last(denied).sessions.gss.established,true);assert.equal(last(denied).sessions.ssh.authenticated,false);assert.equal(step(denied,'channel'),undefined);
});

test('runtime account rebuilds a coherent fresh fixture, re-encodes certificate bytes, preserves mismatch branches and page-only addresses',()=>{
  const baseline=model('cert-success'),custom=baseline.contextualize({unixAccount:'charlie'});
  assert.equal(packet(custom,'userauth','user name'),'charlie');assert.deepEqual(readCertificate(packet(custom,'certificate','crt')).principals,['charlie']);assert.deepEqual(last(custom).credentials.userCertificate.principals,['charlie']);assert.equal(last(custom).policy.identityMapping.account,'charlie');assert.equal(last(custom).sessions.ssh.authenticated,true);
  assert.notEqual(packet(custom,'certificate','crt'),packet(baseline,'certificate','crt'));assert.equal(packet(baseline,'userauth','user name'),'alice');
  assert.deepEqual(validateProtocolScenario(custom).errors,[]);
  const context={caURL:'https://my-ca.example.test:8443',sshHost:'ssh.internal.example.test',appCallbackURL:'http://127.0.0.1:60001/return',unixAccount:'charlie'};
  const projected=projectScenarioContext(custom,custom.steps(),context);
  assert.ok(scenarioContextRows(custom,'sshCa',context).some(row=>row.value===context.caURL));assert.ok(scenarioContextRows(custom,'sshHost',context).some(row=>row.value===context.sshHost));
  const request=projected.steps.find(event=>event.sshStage==='enroll');assert.equal(request.payload.find(item=>item.name==='ott').value,packet(custom,'enroll','ott'));
  assert.deepEqual(readCertificate(projected.steps.find(event=>event.sshStage==='certificate').payload[0].value).principals,['charlie']);
  const root=baseline.contextualize({unixAccount:'root'});assert.deepEqual(readCertificate(packet(root,'certificate','crt')).principals,['root']);
  const denied=model('cert-root').contextualize({unixAccount:'root'});assert.equal(packet(denied,'userauth','user name'),'administrator');assert.equal(last(denied).failure.reason,'principal_account_mismatch');
  const issuer='https://login.example.test/tenant/v2.0',external=baseline.contextualize({aIssuerURL:issuer});
  assert.equal(external.definitions()[attribute(external,'iss')].example,issuer);assert.equal(last(external).policy.identityMapping.issuer,issuer);assert.equal(external.definitions()[attribute(external,'aud')].example,'step-ssh');
  assert.ok(scenarioContextRows(external,'sshIdp',{aIssuerURL:issuer}).some(row=>row.value===issuer));
  const externalSssd=model('sssd-success').contextualize({aIssuerURL:issuer});assert.equal(last(externalSssd).resolvedIdentity.issuer,issuer);assert.equal(last(externalSssd).approvedIdentity.issuer,issuer);assert.equal(last(externalSssd).identityMatched,true);
  for(const m of SSHLAB_SCENARIOS)for(const binding of m.runtimeBindings)assert.ok(m.definitions()[binding.attributeId],m.id+': bound field must have a real definition');
});
