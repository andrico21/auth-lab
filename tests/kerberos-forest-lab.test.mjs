import test from 'node:test';
import assert from 'node:assert/strict';
import { FORESTLAB_ATTRIBUTES, FORESTLAB_SCENARIOS, FORESTLAB_SOURCES } from '../src/kerberos-forest-lab.js';
import { reconstructProtocolState, buildProtocolInstances, validateProtocolScenario } from '../src/protocol-state.js';

const forestModel = suffix => FORESTLAB_SCENARIOS.find(model => model.id === 'lab-ad-forest-' + suffix);
const forestEvent = (model,key) => model.steps().find(step => step.id === model.id+'-'+key);
const forestIndex = (model,key) => model.steps().findIndex(step => step.id === model.id+'-'+key);
const forestState = (model,key) => reconstructProtocolState(model,forestIndex(model,key));
const forestFinal = model => reconstructProtocolState(model,model.steps().length-1);
const forestAllOps = model => model.steps().flatMap(step=>step.attributeOperations);
const forestWire = (model,id) => forestAllOps(model).filter(op=>op.attributeId===id&&['send','receive'].includes(op.kind));

test('required AD-06 matrix supplies 14 independent immutable reference presets and explicit actor registries',()=>{
  assert.equal(FORESTLAB_SCENARIOS.length,14);
  assert.equal(new Set(FORESTLAB_SCENARIOS.map(m=>m.id)).size,14);
  for(const model of FORESTLAB_SCENARIOS){
    assert.equal(model.workspace,'kerberos');assert.equal(model.family,'ad-ds');assert.equal(model.protocol,'kerberos');
    assert.match(model.status,/reference/i);assert.match(model.supportNote,/Windows build.*not asserted/);
    assert.equal(Object.isFrozen(model.steps()),true);
    const actors=model.actors();
    const parentIds=new Set(Object.values(actors).map(actor=>actor.parentId).filter(Boolean));
    assert.ok(Object.values(actors).filter(actor=>!actor.parentId).length<=9,'collapsed visible groups fit the stage');
    assert.ok(Object.values(actors).filter(actor=>!parentIds.has(actor.id)).length<=9,'expanded logical actors replace parent cards');
    for(const [id,actor] of Object.entries(actors)){
      for(const key of ['id','name','role','kind','color'])assert.ok(actor[key],model.id+':'+id+':'+key);
      assert.ok(model.positions[id],model.id+':'+id+' has a scenario-owned position');
    }
    for(const step of model.steps()){
      assert.ok(actors[step.from]);assert.ok(actors[step.to]);assert.ok(step.attributeOperations.length);
      assert.equal(step.protocolEffects[0].op,'advance');assert.equal(step.protocolEffects[0].value,1);
      for(const op of step.attributeOperations){
        assert.ok(FORESTLAB_ATTRIBUTES[op.attributeId]);assert.ok(actors[op.actorId]);
        assert.ok(op.instanceId&&op.fieldPath&&op.representation&&op.sourceEventId&&op.exactValueRef);
        assert.deepEqual(model.protocolValues[op.exactValueRef],op.value,'exact reference resolves the occurrence representation');
      }
    }
    const validation=validateProtocolScenario(model);assert.deepEqual(validation.errors,[],model.id);assert.deepEqual(validation.warnings,[],model.id);
  }
  for(const source of FORESTLAB_SOURCES)assert.match(source.url,/^https:\/\/(www\.rfc-editor\.org|learn\.microsoft\.com)\//);
});

test('each glossary definition has a meaningful authored occurrence; static keys never travel',()=>{
  const operations=FORESTLAB_SCENARIOS.flatMap(forestAllOps);
  for(const [id,definition] of Object.entries(FORESTLAB_ATTRIBUTES)){
    for(const key of ['name','meaning','origin','purpose','standard','source'])assert.ok(definition[key],id+':'+key);
    assert.ok(operations.some(op=>op.attributeId===id),id+' is not an unused glossary placeholder');
  }
  for(const localId of ['forestTrustKey','forestServiceKey','forestTrust','forestSuffixRouting','forestAllowedToAuthenticate','forestSidFiltering','forestCache','forestAcl','forestContext','forestTransited']){
    assert.equal(operations.some(op=>op.attributeId===localId&&['send','receive'].includes(op.kind)),false,localId+' stays local');
  }
  const keys=operations.filter(op=>op.attributeId==='forestSessionKey'&&['send','receive'].includes(op.kind));
  assert.ok(keys.length);assert.ok(keys.every(op=>op.representation==='ciphertext'&&op.carriedAs==='TGS-REP.enc-part'));
});

test('forest KDCs expose stable logical TGS actors while retaining physical DC ownership and stage positions',()=>{
  for(const model of FORESTLAB_SCENARIOS){
    const actors=model.actors(),parents=Object.values(actors).filter(actor=>actor.id.startsWith('kdc')&&!actor.parentId);
    for(const parent of parents){
      const child=actors[parent.id+'Tgs'];assert.ok(child,'logical TGS is authored for '+parent.id);
      assert.equal(child.parentId,parent.id);assert.deepEqual(child.context,parent.context);
      assert.deepEqual(model.positions[child.id],model.positions[parent.id],'expansion substitutes the logical TGS in the same card slot');
      assert.match(child.role,/Ticket-granting service/);
      assert.equal(model.steps().some(step=>step.from===parent.id||step.to===parent.id),false,'physical parent is only a collapsed presentation group');
      assert.equal(forestAllOps(model).some(operation=>operation.actorId===parent.id),false,'source ledger always addresses logical TGS');
    }
    for(const operation of forestAllOps(model).filter(op=>op.actorId.endsWith('Tgs')&&['create','derive'].includes(op.kind))){
      assert.equal(operation.creator,actors[operation.actorId].parentId,'physical KDC remains the credential creation boundary');
    }
    assert.equal(Object.values(actors).some(actor=>actor.id.endsWith('As')),false,'home TGT is an initial prerequisite, so no fabricated AS flow is rendered');
  }
});

test('one-way resource trust allows A to B while its independent reverse fixture fails at the declared owner',()=>{
  const forward=forestModel('one-way'),reverse=forestModel('one-way-reverse');
  assert.equal(forestFinal(forward).access.resource,'allowed');
  assert.equal(forestFinal(forward).sessions.service.principal,'alice@A.EXAMPLE');
  const final=forestFinal(reverse);assert.equal(final.access.resource,null);assert.deepEqual(final.sessions,{});
  assert.equal(Object.keys(final.credentials).length,1,'no referral or service credential issued');
  assert.equal(final.knowledge.workstation.failure.actorId,'kdcHomeTgs');
  assert.equal(final.knowledge.workstation.failure.eventId,reverse.id+'-reject-trust');
  assert.equal(forestWire(reverse,'forestApReq').length,0);assert.equal(forestWire(reverse,'forestApRep').length,0);
  assert.deepEqual(final.cache.workstation,reverse.initialState.cache.workstation,'home credential retained');
  assert.equal(forestState(reverse,'reject-trust').knowledge.workstation.failure,null,'the client has not learned the detector result yet');
  assert.ok(forestState(reverse,'error-trust').knowledge.workstation.failure);
});

test('two-way trust has separately playable principal directions and independent instances',()=>{
  const a=forestModel('two-way-a-b'),b=forestModel('two-way-b-a');
  assert.equal(forestFinal(a).sessions.service.principal,'alice@A.EXAMPLE');
  assert.equal(forestFinal(b).sessions.service.principal,'bob@B.EXAMPLE');
  assert.equal(forestFinal(a).access.resource,'allowed');assert.equal(forestFinal(b).access.resource,'allowed');
  const aIds=new Set(Object.values(forestFinal(a).credentials).map(c=>c.id));
  assert.ok(Object.values(forestFinal(b).credentials).every(c=>!aIds.has(c.id)),'changing direction creates a separate transaction fixture');
});

test('F09: all 14 preset routes classify every hop from explicit forest ownership and selected trust direction',()=>{
  // These expectations are an independent fixture inventory, not another
  // suffix predicate or a copy of the builder's classification helper.
  const crossAB=[['a.example','b.example',true]],crossBA=[['b.example','a.example',true]];
  const expected={
    'one-way':crossAB,'one-way-reverse':crossBA,
    'two-way-a-b':crossAB,'two-way-b-a':crossBA,
    'child-domains':[['eu.a.example','a.example',false],['a.example','b.example',true],['b.example','us.b.example',false]],
    'three-denied':[['a.example','c.example',true]],'three-direct':[['a.example','c.example',true]],
    'same-forest':[['eu.a.example','a.example',false]],
    'selective-denied':crossAB,'sid-filtering':crossAB,'invalid-pac':crossAB,'acl-denied':crossAB,
    'cached-referrals':crossAB,'cached-service':crossAB,
  };
  const owners={'a.example':'Forest A','eu.a.example':'Forest A','b.example':'Forest B','us.b.example':'Forest B','c.example':'Forest C'};
  assert.equal(Object.keys(expected).length,FORESTLAB_SCENARIOS.length);
  for(const [suffix,expectedRoute] of Object.entries(expected)){
    const model=forestModel(suffix),hops=model.initialState.policies.referralHops;
    assert.deepEqual(hops.map(hop=>[hop.fromDomain,hop.toDomain,hop.forestBoundary]),expectedRoute,model.id);
    for(const hop of hops){
      assert.equal(hop.fromForest,owners[hop.fromDomain],model.id+' explicit source owner');
      assert.equal(hop.toForest,owners[hop.toDomain],model.id+' explicit destination owner');
      assert.equal(hop.relationshipType,hop.forestBoundary?'forest':'parent-child');
      assert.equal(hop.trustDirection,hop.toDomain+' (resource) trusts '+hop.fromDomain+' (account)');
      if(['one-way-reverse','three-denied'].includes(suffix)){
        assert.equal(hop.configuredTrust,null,'the requested boundary exists but its needed identity trust is absent');
      }else{
        assert.deepEqual(hop.configuredTrust,{resource:hop.toDomain,account:hop.fromDomain,type:hop.relationshipType,enabled:true},model.id+' selects the correct next-hop relationship');
      }
      assert.match(hop.pacPolicy,hop.forestBoundary?/forest-trust direction and PAC boundary policy/:/Same-forest parent\/child PAC policy/);
      for(const [domain,owner] of [[hop.fromDomain,hop.fromForest],[hop.toDomain,hop.toForest]]){
        const actor=Object.values(model.actors()).find(actor=>!actor.parentId&&actor.name===domain+' KDC');
        assert.ok(actor,model.id+' has the declared KDC owner');assert.equal(actor.role,'KDC · '+owner);
      }
    }
    assert.deepEqual(forestFinal(model).policies.referralHops,hops,'playback preserves authored topology for successful, denied and cached routes');
  }
});

test('F09: every issued or cached referral teaches its own boundary policy; A→B and B→A are symmetric',()=>{
  for(const model of FORESTLAB_SCENARIOS){
    const stages=model.steps().filter(step=>/-(issue|cached)-referral-\d+$/.test(step.id));
    const denied=['lab-ad-forest-one-way-reverse','lab-ad-forest-three-denied'].includes(model.id);
    assert.equal(stages.length,denied?0:model.initialState.policies.referralHops.length,model.id);
    for(const step of stages){
      const number=Number(step.id.match(/-(\d+)$/)[1]),hop=model.initialState.policies.referralHops[number-1];
      assert.deepEqual(step.referralHop,hop,model.id+' stage exposes the same explicit relationship');
      assert.equal(Object.isFrozen(step.referralHop),true,'fixed step metadata cannot change during seeking');
      if(hop.forestBoundary){
        assert.ok(step.detail.includes('named forest boundary ('+hop.fromForest+' → '+hop.toForest+')'));
        assert.ok(step.detail.includes(hop.trustDirection));assert.match(step.detail,/PAC boundary policy/);
        assert.doesNotMatch(step.detail,/within one participating forest/);
      }else{
        assert.ok(step.detail.includes('within one participating forest ('+hop.fromForest+')'));
        assert.match(step.detail,/same-forest PAC policy/);assert.doesNotMatch(step.detail,/named forest boundary/);
      }
      if(step.id.includes('-issue-referral-')){
        const check=step.attributeOperations.find(op=>op.attributeId==='forestTrust'&&op.kind==='verify');
        assert.equal(check.fieldPath,'TDO.nextHopRelationship');assert.deepEqual(check.value,hop);
        assert.equal(check.actorId,step.from,'the issuing logical TGS checks its own authored next-hop policy');
        assert.match(check.detail,/explicit next-hop trust, forest ownership/);
        assert.ok(check.detail.includes(hop.pacPolicy));
      }
    }
  }
  const forward=forestEvent(forestModel('two-way-a-b'),'issue-referral-1');
  const reverse=forestEvent(forestModel('two-way-b-a'),'issue-referral-1');
  assert.equal(forward.referralHop.forestBoundary,true);assert.equal(reverse.referralHop.forestBoundary,true);
  assert.equal(forward.referralHop.fromForest,reverse.referralHop.toForest);
  assert.equal(forward.referralHop.toForest,reverse.referralHop.fromForest);
});

test('child-domain cross-forest path is client-driven through all four KDCs without a shortcut',()=>{
  const model=forestModel('child-domains');
  assert.deepEqual(Object.keys(model.initialState.credentials),['home']);
  assert.deepEqual(model.initialState.policies.suffixRouting,['eu.a.example','a.example','b.example','us.b.example']);
  const requests=model.steps().filter(s=>s.channel==='kerberos'&&s.attributeOperations.some(o=>o.attributeId==='forestTgsReq'&&o.kind==='send'));
  assert.deepEqual(requests.map(s=>s.from),['workstation','workstation','workstation','workstation']);
  assert.deepEqual(requests.map(s=>s.to),['kdcHomeTgs','kdcRootATgs','kdcRootBTgs','kdcResourceTgs']);
  const returns=model.steps().filter(s=>/return-referral/.test(s.id));
  assert.deepEqual(returns.map(s=>[s.from,s.to]),[['kdcHomeTgs','workstation'],['kdcRootATgs','workstation'],['kdcRootBTgs','workstation']]);
  assert.deepEqual(forestFinal(model).knowledge.workstation.route,['a.example','b.example','us.b.example']);
  assert.equal(forestFinal(model).sessions.service.principal,'alice@EU.A.EXAMPLE');
  assert.equal(Object.keys(forestFinal(model).credentials).length,5);
});

test('referrals retain original cname/crealm, per-hop issuer/target provenance and independent session keys',()=>{
  const model=forestModel('child-domains'),credentials=Object.values(forestFinal(model).credentials);
  assert.ok(credentials.every(c=>c.cname==='alice'&&c.crealm==='EU.A.EXAMPLE'));
  assert.deepEqual(credentials.filter(c=>c.kind==='referral').map(c=>[c.issuerRealm,c.targetRealm,c.sname]),[
    ['EU.A.EXAMPLE','A.EXAMPLE','krbtgt/A.EXAMPLE'],['A.EXAMPLE','B.EXAMPLE','krbtgt/B.EXAMPLE'],['B.EXAMPLE','US.B.EXAMPLE','krbtgt/US.B.EXAMPLE']]);
  assert.equal(new Set(credentials.map(c=>c.sessionKeyId)).size,5);
  assert.ok(credentials.filter(c=>c.kind==='referral').every(c=>c.pac.resourceGroups.length===0));
  assert.ok(credentials.find(c=>c.kind==='service').pac.resourceGroups.length>0);
  assert.equal(forestAllOps(model).some(op=>op.fieldPath==='issuerRealm'),false,'provenance metadata is not invented wire issuer field');
});

test('three forests reject implied transitivity and accept only the explicit suitable C-trusts-A fixture',()=>{
  const denied=forestModel('three-denied'),direct=forestModel('three-direct');
  assert.deepEqual(denied.initialState.policies.trusts.map(t=>[t.resource,t.account]),[['b.example','a.example'],['c.example','b.example']]);
  assert.equal(forestFinal(denied).access.resource,null);assert.equal(Object.keys(forestFinal(denied).credentials).length,1);
  assert.equal(forestWire(denied,'forestTgsRep').length,0);
  assert.ok(direct.initialState.policies.trusts.some(t=>t.resource==='c.example'&&t.account==='a.example'));
  assert.equal(forestFinal(direct).access.resource,'allowed');assert.equal(forestFinal(direct).sessions.service.principal,'alice@A.EXAMPLE');
  assert.match(forestEvent(denied,'trust-check').detail,/different hop/,'error/failing hop is a fixture choice, not universal Windows claim');
});

test('same-forest lesson retains hierarchy and does not claim a forest-boundary trust',()=>{
  const model=forestModel('same-forest');
  assert.equal(model.initialState.policies.trusts[0].type,'parent-child');
  assert.equal(forestFinal(model).credentials.referral1.sname,'krbtgt/A.EXAMPLE');
  assert.equal(forestFinal(model).sessions.service.principal,'alice@EU.A.EXAMPLE');
  assert.match(forestEvent(model,'issue-referral-1').detail,/within one participating forest/);
});

test('selective authentication is checked at resource KDC before issuance and retains already cached referrals',()=>{
  const model=forestModel('selective-denied'),check=forestEvent(model,'selective-check');
  assert.equal(check.from,'kdcResourceTgs');assert.equal(check.to,'kdcResourceTgs');
  const op=check.attributeOperations.find(o=>o.attributeId==='forestAllowedToAuthenticate');
  assert.equal(op.value.object,'HTTP/files.b.example');assert.equal(op.value.allowed,false);
  assert.ok(forestState(model,'selective-check').credentials.referral1);
  assert.equal(forestState(model,'selective-check').credentials.service,undefined);
  assert.equal(forestFinal(model).credentials.service,undefined);
  assert.equal(forestFinal(model).knowledge.workstation.failure.actorId,'kdcResourceTgs');
  assert.equal(forestWire(model,'forestApReq').length,0);assert.equal(forestWire(model,'forestApRep').length,0);
  assert.equal(model.steps().some(s=>s.id.endsWith('-acl')),false,'no final resource ACL without an authenticated application context');
});

test('SID filtering preserves eligible identity while invalid PAC follows a distinct pre-ticket failure',()=>{
  const filtered=forestModel('sid-filtering'),invalid=forestModel('invalid-pac');
  const incoming=forestFinal(filtered).credentials.referral1.pac.extraSids;
  const outgoing=forestFinal(filtered).credentials.service.pac.extraSids;
  assert.equal(incoming.length,2);assert.deepEqual(outgoing,['S-1-5-21-100-2101']);
  assert.equal(forestFinal(filtered).sessions.service.principal,'alice@A.EXAMPLE');
  assert.equal(forestFinal(filtered).access.resource,'allowed');
  assert.equal(forestFinal(invalid).credentials.service,undefined);assert.equal(forestWire(invalid,'forestApReq').length,0);
  assert.equal(forestFinal(invalid).knowledge.workstation.failure.actorId,'kdcResourceTgs');
  assert.equal(forestAllOps(invalid).some(o=>o.attributeId==='forestSidFiltering'),false,'invalid PAC is not repaired by SID filtering');
});

test('resource ACL denial preserves successful authentication and mutually authenticated context',()=>{
  const model=forestModel('acl-denied');
  const accepted=forestState(model,'accept');assert.equal(accepted.sessions.service.authenticated,true);assert.equal(accepted.access.resource,null);
  const final=forestFinal(model);assert.equal(final.sessions.service.authenticated,true);assert.equal(final.knowledge.workstation.serviceAuthenticated,true);
  assert.equal(final.access.resource,'denied');assert.equal(final.knowledge.workstation.failure,null);
  assert.ok(forestWire(model,'forestApRep').length>0);assert.equal(forestWire(model,'forestError').length,0);
});

test('cached referral removes only its acquisition while cached service removes every TGS exchange',()=>{
  const referral=forestModel('cached-referrals'),service=forestModel('cached-service');
  assert.ok(referral.initialState.credentials.referral1);assert.equal(referral.initialState.credentials.service,undefined);
  assert.equal(referral.steps().some(s=>s.id.endsWith('-issue-referral-1')),false);
  assert.equal(referral.steps().filter(s=>s.attributeOperations.some(o=>o.attributeId==='forestTgsReq'&&o.kind==='send')).length,1);
  assert.ok(forestFinal(referral).credentials.service);
  assert.equal(forestFinal(referral).credentials.referral1.id,referral.initialState.credentials.referral1.id);
  assert.ok(service.initialState.credentials.service);assert.equal(forestWire(service,'forestTgsReq').length,0);assert.equal(forestWire(service,'forestTgsRep').length,0);
  assert.ok(forestWire(service,'forestApReq').length>0);
  assert.equal(forestFinal(service).credentials.service.id,service.initialState.credentials.service.id);
});

test('authenticator identity is fresh per TGS/AP use while credential identity stays fixed through cache and presentation',()=>{
  const model=forestModel('child-domains'),ops=forestAllOps(model);
  const created=ops.filter(o=>o.attributeId==='forestAuthenticator'&&o.kind==='create');
  assert.equal(created.length,5);assert.equal(new Set(created.map(o=>o.instanceId)).size,5);
  const serviceId=forestFinal(model).credentials.service.id;
  const serviceTicketOps=ops.filter(o=>o.attributeId==='forestTicket'&&o.instanceId===serviceId);
  for(const kind of ['create','receive','verify','store','use','send'])assert.ok(serviceTicketOps.some(o=>o.kind===kind),kind+' preserves service ticket instance');
  assert.equal(new Set(serviceTicketOps.map(o=>o.value)).size,1);
  for(const createdOp of created){
    const wireOps=ops.filter(o=>o.attributeId==='forestAuthenticator'&&o.instanceId===createdOp.instanceId&&o.kind==='send');
    assert.equal(wireOps.length,1,'fresh authenticator belongs to exactly one outgoing request');
  }
});

test('every TGS proof binds its exact request body and receiving KDC records independent replay protection',()=>{
  const model=forestModel('child-domains'),ops=forestAllOps(model);
  const checksums=ops.filter(o=>o.attributeId==='forestChecksum'&&o.kind==='derive');
  assert.equal(checksums.length,4);
  assert.ok(checksums.every(o=>o.value.includes('KDC-REQ-BODY; usage 6')));
  for(const checksum of checksums){
    const carried=ops.filter(o=>o.attributeId==='forestChecksum'&&o.instanceId===checksum.instanceId&&o.kind==='send');
    assert.equal(carried.length,1);assert.equal(carried[0].representation,'ciphertext');
    assert.equal(carried[0].carriedAs,'PA-TGS-REQ.AP-REQ.authenticator');
  }
  const final=forestFinal(model);
  for(const actor of ['kdcHomeTgs','kdcRootATgs','kdcRootBTgs','kdcResourceTgs'])assert.equal(final.replayCache[actor].length,1,actor+' records its received proof');
  assert.equal(final.replayCache.service.length,1,'application proof has separate replay protection');
  assert.equal(new Set(Object.values(final.replayCache).flat()).size,5,'no request reuses another layer’s authenticator');
});

test('client receives opaque ticket bytes without decoded PAC or EncTicketPart inspection',()=>{
  const model=forestModel('child-domains'),ops=forestAllOps(model);
  assert.equal(ops.some(o=>o.actorId==='workstation'&&o.representation==='decoded'&&o.fieldPath.startsWith('EncTicketPart')),false);
  for(const op of ops.filter(o=>o.attributeId==='forestTicketCipher'&&['send','receive'].includes(o.kind)))assert.equal(op.representation,'ciphertext');
  const serverDecode=ops.filter(o=>o.actorId==='service'&&o.representation==='decoded');assert.ok(serverDecode.length);
  assert.ok(serverDecode.every(o=>o.inspectors.includes('service')));
  for(const op of ops.filter(o=>o.attributeId==='forestSessionKey'&&o.kind==='receive'))assert.equal(op.inspectors.includes('workstation'),false,'encrypted reply occurrence is not plaintext inspection');
});

test('KILE transit data is explained as separate from trust/PAC and final authorization checks',()=>{
  const model=forestModel('one-way'),accept=forestEvent(model,'accept');
  assert.match(accept.detail,/does not check transited/);assert.match(accept.detail,/ignores TRANSITED-POLICY-CHECKED/);
  assert.equal(accept.attributeOperations.find(o=>o.attributeId==='forestTransited').kind,'use');
  assert.equal(forestEvent(model,'acl').attributeOperations.find(o=>o.attributeId==='forestAcl').kind,'verify');
});

test('every prefix restores credential/cache/policy/replay knowledge without future state or mutation',()=>{
  for(const model of FORESTLAB_SCENARIOS){
    for(let index=-1;index<model.steps().length;index++){
      const direct=reconstructProtocolState(model,index);const again=reconstructProtocolState(model,index);
      assert.deepEqual(direct,again);assert.equal(direct.protocolClock,1700000000+index+1);
      assert.ok(Object.isFrozen(direct));assert.doesNotThrow(()=>buildProtocolInstances(model,index));
      if(index<forestIndex(model,'accept')&&forestIndex(model,'accept')>=0){assert.equal(direct.sessions.service,undefined);assert.deepEqual(direct.replayCache.service,[]);}
    }
    assert.deepEqual(reconstructProtocolState(model,-1).credentials,model.initialState.credentials,'reset returns exact initial credential instances');
  }
});

test('focused replay uses the owning source event and reconstructs hidden prior referral cache',()=>{
  const model=forestModel('child-domains'),index=forestIndex(model,'ap-request');
  const full=reconstructProtocolState(model,index);
  // Field/link projections carry the source index; reconstruct the source model,
  // never a filtered sequence which would omit the earlier KDC/cache events.
  const focusedOccurrence=buildProtocolInstances(model,index).find(i=>i.instanceId===full.credentials.service.id).occurrences.find(o=>o.eventId===model.id+'-ap-request');
  assert.ok(focusedOccurrence);assert.equal(focusedOccurrence.eventIndex,index);
  const focused=reconstructProtocolState(model,focusedOccurrence.eventIndex);
  assert.deepEqual(focused,full);assert.equal(Object.keys(focused.credentials).length,5);
  assert.equal(focused.sessions.service,undefined,'application proof has arrived but is not accepted until its later owner check');
});
