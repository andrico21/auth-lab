import test from 'node:test';
import assert from 'node:assert/strict';
import { LIFELAB_SCENARIOS } from '../src/lifecycle-lab.js';
import { GRANTLAB_SCENARIOS } from '../src/extended-grants-lab.js';
import { SAMLLAB_SCENARIOS } from '../src/saml-advanced-lab.js';
import { BRANCHLAB_SCENARIOS } from '../src/branching-lab.js';
import { buildWebHeldObjects } from '../src/held-object-web.js';
import { compileHeldObjects, projectHeldObjects, assertHeldObjectCoverage, inspectHeldObject, heldObjectTrace, heldCursorForPlayback } from '../src/held-object-state.js';
import { FlowPlayer, authoredMessageTiming } from '../src/player.js';

const models=[...LIFELAB_SCENARIOS,...GRANTLAB_SCENARIOS,...SAMLLAB_SCENARIOS,...BRANCHLAB_SCENARIOS];
function fixture(id,revision='test') {
  const model=models.find(item=>item.id===id);
  assert.ok(model,id);
  const config={},steps=model.steps(config),actors=model.actors(config);
  const plan=buildWebHeldObjects({model,steps,actors,config,contextId:id+':'+revision,choiceId:id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const at=(step,milestone='complete')=>projectHeldObjects(compiled,{eventIndex:steps.findIndex(item=>item.id===step),milestone});
  return {model,steps,plan,compiled,at,initial:()=>projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'})};
}
const has=(snapshot,artifactId,actorId,store)=>snapshot.holdings.some(item=>item.artifactId===artifactId&&item.actorId===actorId&&(!store||item.store===store));
const observation=(snapshot,id,actor,result)=>snapshot.observations.some(item=>item.artifactId===id&&item.actorId===actor&&item.result===result);

for(const model of models)test(model.id+' has explicit actor/store coverage at every source cursor',()=>{
  const f=fixture(model.id);
  assert.equal(assertHeldObjectCoverage(f.compiled),true);
  const snapshots=[f.initial(),...f.steps.flatMap(step=>[f.at(step.id,'before'),f.at(step.id)])];
  for(const snapshot of snapshots) {
    assert.equal(snapshot.coverageStatus,'complete');
    assert.deepEqual(new Set(snapshot.coverage.map(item=>item.actorId)),new Set(Object.keys(model.actors())));
    for(const holding of snapshot.holdings) {
      const coverage=snapshot.coverage.find(item=>item.actorId===holding.actorId);
      assert.ok(coverage.stores.includes(holding.store),model.id+':'+holding.store);
      assert.ok(coverage.categories.includes(snapshot.artifacts.find(item=>item.artifactId===holding.artifactId).type));
    }
  }
  const final=snapshots.at(-1);
  assert.equal(final.holdings.some(item=>item.retention==='temporary'),false,'All transient receipts and transaction secrets have explicit release/promotion.');
  assert.equal(new Set(f.plan.artifacts.map(item=>item.artifactId)).size,f.plan.artifacts.length);
});

test('refresh rotation separates issuer consumption, delayed delivery, receipt and conforming installation',()=>{
  const f=fixture('lab-refresh-rotation'),p=key=>'lab-refresh-rotation-'+key;
  const initial=f.initial();
  for(const id of ['R0','AT0','ID0','client-secret','app-session'])assert.ok(has(initial,id,'app'));
  const issued=f.at(p('issue'));
  assert.ok(has(issued,'R0','app','credentials'));
  assert.ok(has(issued,'AT0','app','credentials'));
  assert.equal(has(issued,'R1','app'),false);
  assert.ok(issued.authority.some(item=>item.artifactId==='R0'&&item.status==='consumed'));
  const delayed=f.at(p('response'),'delayed-response');
  assert.ok(has(delayed,'R0','app'));
  assert.equal(has(delayed,'R1','app'),false);
  assert.ok(delayed.inFlight.length);
  const received=f.at(p('response'),'received');
  assert.ok(has(received,'R0','app','credentials'));
  assert.ok(has(received,'R1','app','response'));
  assert.equal(has(received,'R1','app','credentials'),false);
  const installed=f.at(p('replace'));
  assert.equal(has(installed,'R0','app'),false);
  assert.equal(has(installed,'AT0','app'),false);
  for(const id of ['R1','AT1','ID1'])assert.ok(has(installed,id,'app','credentials'));
  assert.equal(installed.holdings.find(item=>item.actorId==='app'&&item.artifactId==='R1').holdingId,received.holdings.find(item=>item.actorId==='app'&&item.artifactId==='R1').holdingId,'Response promotion preserves the exact holding/control identity.');
  assert.equal(installed.holdings.find(item=>item.actorId==='app'&&item.artifactId==='R1').retention,'retained');
  assert.deepEqual(f.plan.artifacts.find(item=>item.artifactId==='R1').derivedFrom,['R0']);
  assert.deepEqual(f.plan.artifacts.find(item=>item.artifactId==='AT1').replaces,['AT0']);
  assert.ok(installed.artifacts.some(item=>item.artifactId==='R0'),'Discard preserves historical identity.');
  assert.ok(has(f.at(p('error')),'R1','app'),'Delayed queued R0 failure does not erase installed R1.');
  assert.deepEqual(f.at(p('replace')),installed,'Pure rewind/replay projection is deterministic.');
});

test('offline credentials and offline policy survive the explicit online logout boundary',()=>{
  const f=fixture('lab-offline-access'),p=key=>'lab-offline-access-'+key;
  assert.equal(has(f.initial(),'ROff0','app'),false,'Consent flow has not issued its offline credential yet.');
  const issued=f.at(p('issue'));
  assert.ok(has(issued,'ROff0','app','credentials'));
  assert.ok(has(issued,'offline-session','realmA','offline-sessions'));
  const later=f.at(p('refresh-later'));
  assert.equal(issued.protocolClock,0);
  assert.equal(later.protocolClock,600,'Only the explicit later-refresh boundary advances fixture time.');
  assert.equal(f.at(p('refresh-later'),'before').protocolClock,0);
  const policy=later.artifacts.find(item=>item.artifactId==='offline-session').representations[0].fields.find(item=>item.attributeId==='lifeOfflinePolicy').value;
  assert.ok(later.protocolClock<policy.idleDeadlineClock&&later.protocolClock<policy.maxDeadlineClock);
  assert.equal(has(later,'op-cookie','browser'),false);
  assert.equal(has(later,'op-session','realmA'),false);
  assert.ok(has(later,'ROff0','app'));
  assert.ok(has(later,'offline-session','realmA'));
  assert.ok(observation(later,'offline-session','realmA','accepted'));
  const final=f.at(p('replacement'));
  assert.equal(has(final,'ROff0','app'),false);
  assert.ok(has(final,'ROff1','app'));
  assert.ok(has(final,'offline-session','realmA'));
  assert.equal(final.observations.some(item=>item.actorId==='realmB'),false,'No invented API revocation knowledge.');
});

test('metadata is a received candidate before the separate trust rollover installation',()=>{
  const f=fixture('lab-saml-metadata');
  const candidate=f.at('sl-meta-idp-response');
  assert.ok(has(candidate,'idp-metadata','app','candidate-metadata'));
  assert.equal(has(candidate,'installed-idp-next','app'),false);
  assert.ok(has(candidate,'idp-trust','app','configuration'));
  const installed=f.at('sl-meta-rollover');
  assert.equal(has(installed,'idp-metadata','app','candidate-metadata'),false);
  assert.ok(has(installed,'installed-idp-next','app','trust-cache'));
  assert.ok(has(installed,'idp-trust','app','configuration'),'No invented retirement of old key during overlap.');
  assert.ok(observation(installed,'idp-metadata','app','trusted and installed'));
  assert.equal(f.at('sl-meta-sp-response').holdings.some(item=>item.artifactId==='installed-sp-trust'),false);
  assert.ok(has(f.at('sl-meta-validate-sp'),'installed-sp-trust','realmA'));
});

test('SAML artifact is not an assertion and resolution receipt precedes local SP acceptance',()=>{
  const f=fixture('lab-saml-artifact');
  const browser=f.at('sl-artifact-browser');
  assert.ok(has(browser,'artifact','browser'));
  assert.equal(has(browser,'assertion','browser'),false);
  assert.ok(has(browser,'assertion','realmA'));
  const received=f.at('sl-artifact-response');
  for(const id of ['resolved-container','response','assertion'])assert.ok(has(received,id,'app','response'));
  assert.equal(has(received,'sp-session','app'),false);
  assert.ok(received.authority.some(item=>item.artifactId==='artifact'&&item.status==='consumed'));
  const accepted=f.at('sl-artifact-validate');
  assert.ok(has(accepted,'sp-session','app','sessions'));
  assert.ok(has(accepted,'assertion-replay','app','replay-cache'));
  assert.equal(has(accepted,'assertion','app'),false,'Transient assertion bytes are released after validation.');
});

test('expired, replayed and denied SAML attempts retain distinct rejected receipts without sessions',()=>{
  const f=fixture('lab-saml-validation-failures');
  const expired=f.at('sl-fail-expired-wire');
  assert.ok(has(expired,'expired-assertion','app','received-rejected'));
  assert.equal(observation(expired,'expired-assertion','app','rejected'),false,'Receipt is not verification.');
  assert.ok(observation(f.at('sl-fail-expired-check'),'expired-assertion','app','rejected'));
  const final=f.at('sl-fail-denied-submit');
  for(const id of ['expired-assertion','replay-assertion','denied-response'])assert.ok(has(final,id,'app','received-rejected'));
  assert.equal(final.holdings.some(item=>item.actorId==='app'&&item.store==='sessions'),false);
  assert.equal(f.plan.artifacts.some(item=>item.artifactId==='denied-assertion'),false);
  assert.ok(has(final,'prior-replay','app','replay-cache'));
});

test('backchannel recipients and replay caches are independent exact event identities',()=>{
  const f=fixture('lab-backchannel-logout'),p=key=>'lab-backchannel-logout-'+key;
  assert.ok(has(f.at(p('notify')),'app-session','app'),'Receipt does not end an RP session.');
  assert.equal(has(f.at(p('session')),'app-session','app'),false);
  assert.ok(has(f.at(p('session')),'second-session','realmB'));
  assert.ok(has(f.at(p('second-apply')),'J1-replay','realmB'));
  assert.ok(has(f.at(p('second-apply')),'J0-replay','app'));
  assert.ok(observation(f.at(p('duplicate-check')),'J0','app','replay rejected'));
  const final=f.at(p('fresh-response'));
  assert.ok(has(final,'J2-replay','app'));
  assert.equal(has(final,'app-session','app'),false);
  const token=f.plan.artifacts.find(item=>item.artifactId==='J1');
  assert.deepEqual(token.representations[0].readableBy,['realmA','realmB']);
});

test('frontchannel successful first iframe does not fabricate second RP browser/session removal',()=>{
  const f=fixture('lab-frontchannel-logout'),p=key=>'lab-frontchannel-logout-'+key;
  const first=f.at(p('first-response'));
  assert.equal(has(first,'app-session','app'),false);
  assert.equal(has(first,'app-cookie','browser'),false);
  const blocked=f.at(p('blocked'));
  assert.ok(has(blocked,'second-session','realmB'));
  assert.ok(has(blocked,'second-browser-state','browser','second-origin-storage'));
  assert.ok(observation(blocked,'second-browser-state','browser','incomplete/unknown'));
  const held=blocked.holdings.find(item=>item.artifactId==='second-browser-state');
  assert.ok(inspectHeldObject(blocked,held.holdingId).fields.every(field=>field.redacted&&!Object.hasOwn(field,'value')),'A browser transport holding cannot inspect the RP-protected fields.');
});

for(const id of ['lab-ciba-ping','lab-ciba-push','lab-ciba-hint-token'])test(id+' pending handle and notification do not deliver tokens early',()=>{
  const f=fixture(id),p=key=>id+'-'+key;
  const pending=f.at(p('handle'));
  assert.ok(has(pending,'handle','app','pending'));
  for(const token of ['AT','RT','ID'])assert.equal(has(pending,token,'app'),false);
  const signed=f.at(p('issuer'));
  for(const token of ['AT','RT','ID'])assert.equal(has(signed,token,'app'),false);
  if(id==='lab-ciba-ping')for(const token of ['AT','RT','ID'])assert.equal(has(f.at(p('ping')),token,'app'),false);
  const arrival=f.at(p(id==='lab-ciba-push'?'push':'tokens'));
  for(const token of ['AT','RT','ID']) {
    assert.ok(has(arrival,token,'app','response'));
    assert.equal(has(arrival,token,'app','credentials'),false);
  }
  const accepted=f.at(p(id==='lab-ciba-push'?'push-check':'validate'));
  for(const token of ['AT','RT','ID'])assert.ok(has(accepted,token,'app','credentials'));
  assert.equal(has(f.at(p('done')),'handle','app'),false);
});

for(const id of ['lab-exchange-id-token','lab-exchange-refresh-token'])test(id+' preserves the input and separates output lineage/type',()=>{
  const f=fixture(id),p=key=>id+'-'+key;
  assert.ok(has(f.initial(),'subject','app'));
  assert.equal(has(f.at(p('policy')),'result','app'),false);
  assert.ok(has(f.at(p('response')),'result','app','response'));
  const interpreted=f.at(p('interpret'));
  assert.ok(has(interpreted,'subject','app'));
  assert.ok(has(interpreted,'result','app','credentials'));
  assert.deepEqual(f.plan.artifacts.find(item=>item.artifactId==='result').derivedFrom,['subject']);
  assert.equal(f.plan.artifacts.find(item=>item.artifactId==='result').type,id==='lab-exchange-id-token'?'id-token':'access-token');
  assert.equal(has(interpreted,'refresh','app'),id==='lab-exchange-refresh-token');
  assert.equal(interpreted.authority.some(item=>item.artifactId==='subject'&&item.status==='consumed'),false);
});

test('external grant and subsequent exchange preserve all exact inputs while linked-token retrieval does not mint',()=>{
  const incoming=fixture('lab-exchange-external-in');
  const final=incoming.at('lab-exchange-external-in-final');
  for(const id of ['assertion','local','narrowed'])assert.ok(has(final,id,'app','credentials'));
  assert.deepEqual(incoming.plan.artifacts.find(item=>item.artifactId==='local').derivedFrom,['assertion']);
  assert.deepEqual(incoming.plan.artifacts.find(item=>item.artifactId==='narrowed').derivedFrom,['local']);
  assert.ok(has(final,'assertion-replay','realmA'));
  const outgoing=fixture('lab-exchange-external-out');
  const returned=outgoing.at('lab-exchange-external-out-result');
  assert.ok(has(returned,'external','app'));
  assert.ok(has(returned,'external','realmA','broker-credentials'));
  assert.ok(has(returned,'subject','app'));
  assert.equal(outgoing.plan.artifacts.filter(item=>item.type==='access-token').length,2,'Retrieval reuses the same externally issued token identity.');
});

test('cancelled passkey has no fabricated assertion or authenticator private-key transfer',()=>{
  const f=fixture('lab-passkey-cancel');
  const cancelled=f.at('branch-cancel-local');
  assert.ok(has(cancelled,'cancellation','browser'));
  assert.equal(cancelled.artifacts.some(item=>/assertion|passkey-private/.test(item.artifactId)),false);
  assert.equal(cancelled.holdings.some(item=>item.actorId==='hello'),false);
  const password=f.at('branch-cancel-password');
  assert.ok(has(password,'password-proof','realmA','request'));
  assert.equal(has(password,'password-proof','app'),false);
});

test('account linking and recovery require verified local proof and keep credentials with their actual owners',()=>{
  const link=fixture('lab-broker-account-link');
  assert.equal(has(link.at('branch-link-match'),'identity-link','realmA'),false);
  assert.equal(has(link.at('branch-link-verify'),'identity-link','realmA'),false);
  assert.ok(has(link.at('branch-link-store'),'identity-link','realmA','accounts'));
  const recovery=fixture('lab-account-recovery');
  assert.ok(has(recovery.at('branch-recovery-delivery'),'reset-action','user'));
  assert.equal(has(recovery.at('branch-recovery-delivery'),'reset-action','app'),false);
  assert.equal(has(recovery.at('branch-recovery-check'),'new-password-verifier','realmA'),false);
  const updated=recovery.at('branch-recovery-store');
  assert.ok(has(updated,'new-password-verifier','realmA','configuration'));
  assert.equal(has(updated,'password-verifier','realmA'),false);
  assert.ok(has(updated,'action-replay','realmA','replay-cache'));
});

test('silent failure and expired online refresh cannot invent successful generations',()=>{
  const silent=fixture('lab-sso-login-required'),end=silent.at('lab-sso-login-required-next');
  assert.equal(end.artifacts.some(item=>['authorization-code','access-token','refresh-token','session'].includes(item.type)),false);
  const expiry=fixture('lab-session-expiry');
  assert.equal(expiry.at('lab-session-expiry-deadline','before').protocolClock,0);
  assert.equal(expiry.at('lab-session-expiry-deadline').protocolClock,1201,'Illustrative authored idle deadline is 1200 seconds, not a wall-clock timeout.');
  assert.ok(has(expiry.at('lab-session-expiry-deadline'),'R0','app'));
  assert.equal(has(expiry.at('lab-session-expiry-error'),'R0','app'),true);
  assert.equal(has(expiry.at('lab-session-expiry-recover'),'R0','app'),false);
  assert.ok(has(expiry.at('lab-session-expiry-recover'),'AT0','app'));
  assert.equal(expiry.plan.artifacts.some(item=>item.artifactId==='R1'),false);
});

test('exact object traces and revision-qualified contexts do not merge refresh generations',()=>{
  const a=fixture('lab-refresh-rotation','A'),b=fixture('lab-refresh-rotation','B');
  assert.notEqual(a.compiled.contextId,b.compiled.contextId);
  const trace=heldObjectTrace(a.compiled,'R1');
  assert.ok(trace.length);
  for(const row of trace) {
    assert.ok(row.heldCursorStart&&row.heldCursorEnd);
    assert.equal(row.sourceStepId,a.steps[row.sourceIndex].id);
  }
  const final=a.at('lab-refresh-rotation-replace');
  assert.ok(final.holdings.filter(item=>item.artifactId==='R1').every(item=>item.qualifiedArtifactId.startsWith(a.compiled.contextId+'#')));
});

test('refresh receipt and packet phase agree before, at and after arrival in journey, connection and exact replay',()=>{
  const f=fixture('lab-refresh-rotation'),sourceId='lab-refresh-rotation-response';
  const source=f.steps.find(step=>step.id===sourceId);
  const event=f.plan.events[sourceId],receipt=event.milestones.find(item=>item.id==='received').at;
  assert.equal(receipt,.75,'Receipt remains separate from the complete boundary and later identity checks/install.');
  const exact=heldObjectTrace(f.compiled,'R1').find(row=>row.sourceStepId===sourceId&&row.heldCursorEnd.milestone==='received');
  assert.ok(exact);
  for(const count of [0,1,6,19]) for(const speed of [0,.01,.5,1,4]) for(const reducedMotion of [false,true]) {
    const payload=Array.from({length:count},(_,index)=>({name:'field-'+index,value:'value-'+index}));
    const journey=f.steps.map(step=>step===source?{...source,payload}:step);
    const connection=journey.slice(0,journey.findIndex(step=>step.id===sourceId)+1).filter(step=>(step.from==='app'&&step.to==='realmA')||(step.from==='realmA'&&step.to==='app'));
    for(const [kind,queue,row] of [['demo',journey,journey.find(step=>step.id===sourceId)],
      ['connection',connection,connection.find(step=>step.id===sourceId)],['object',[{...exact,payload}],{...exact,payload}]]) {
      const player=new FlowPlayer({getTiming:(step,kind)=>authoredMessageTiming(f.plan,step,kind)});
      player.setSpeed(speed);player.setReducedMotion(reducedMotion);
      const index=queue.findIndex(step=>step.id===row.id),duration=player.totalDuration([row]);
      const offset=player.totalDuration(queue.slice(0,index)),total=player.totalDuration(queue);
      const timing=authoredMessageTiming(f.plan,row,kind),start=timing.start,end=timing.end;
      const boundary=(receipt-start)/(end-start);
      // Connection and exact receipt end their replay interval; seek past it stays frozen.
      for(const delta of [-1e-6,0,1e-6]) {
        const fraction=Math.max(0,Math.min(1,boundary+delta));
        player.seek(queue,(offset+duration*fraction)/total,kind);
        const frame=player.snapshot(),held=projectHeldObjects(f.compiled,heldCursorForPlayback(f.compiled,{...frame,queue:player.queue}));
        const received=delta>=0,label=`${kind}, ${count} fields, speed ${speed}, reduced ${reducedMotion}, delta ${delta}`;
        assert.equal(frame.messagePhase,received?'received':'in-flight',label);
        const travelEnd=380+(Math.max(1,count)-1)*1290+1050;
        const lastFieldEnd=frame.messageStart*duration+Math.min(travelEnd,(frame.messageEnd-frame.messageStart)*duration);
        assert.equal(frame.visible,!received&&frame.elapsed<=lastFieldEnd,label);
        assert.equal(held.inFlight.some(message=>message.messageId===frame.messageId),!received,label);
        assert.equal(held.cursor.milestone,received?'received':'delayed-response',label);
        for(const id of ['R1','AT1','ID1']) {
          assert.equal(has(held,id,'app','response'),received,label);
          assert.equal(has(held,id,'app','credentials'),false,'Receipt is not installation: '+label);
        }
        assert.ok(has(held,'R0','app','credentials'),label);
        assert.equal(held.observations.some(item=>item.artifactId==='ID1'&&item.result==='accepted'),false,label);
        if(received)assert.equal(frame.progress,1,label);
        else assert.ok(frame.progress>.99,label);
        assert.deepEqual(held.state,f.at(sourceId,received?'received':'delayed-response').state,label);
      }
    }
  }
  const installed=f.at('lab-refresh-rotation-replace');
  assert.ok(observation(installed,'ID1','app','accepted'));
  for(const id of ['R1','AT1','ID1'])assert.ok(has(installed,id,'app','credentials'));
});

for(const [id,first,second,last] of [
  ['lab-saml-sp-slo','sl-sp-slo-start','sl-sp-slo-second-terminate','sl-sp-slo-final-response'],
  ['lab-saml-idp-slo','sl-idp-slo-first-terminate','sl-idp-slo-second-terminate','sl-idp-slo-finish'],
  ['lab-saml-soap-slo','sl-soap-slo-first-terminate','sl-soap-slo-second-terminate','sl-soap-slo-complete'],
])test(id+' terminates only the actual participant at each authored boundary',()=>{
  const f=fixture(id),initial=f.initial();
  for(const [object,actor] of [['sp-session','app'],['idp-session','realmA'],['second-session','realmB']])assert.ok(has(initial,object,actor));
  assert.equal(has(f.at(first),'sp-session','app'),false);
  assert.ok(has(f.at(first),'second-session','realmB'));
  assert.equal(has(f.at(second),'second-session','realmB'),false);
  const final=f.at(last);
  assert.equal(final.holdings.some(item=>item.type==='session'||item.store==='sessions'),false);
  assert.equal(final.holdings.some(item=>item.retention==='temporary'),false);
  for(const artifact of f.plan.artifacts.filter(item=>item.type==='saml-logout-request')) {
    const name=artifact.representations[0].fields.find(item=>item.attributeId==='slNameIDApp'||item.attributeId==='slNameIDOther');
    assert.ok(name,'Each request carries its own participant subject association.');
  }
});

test('delegation retains independent subject/actor inputs and scopes acceptance to its API result',()=>{
  const f=fixture('lab-exchange-delegation');
  const before=f.at('lab-exchange-delegation-exchange');
  assert.ok(has(before,'subject','app','credentials'));
  assert.ok(has(before,'actor','app','credentials'));
  assert.equal(has(before,'delegated','app'),false);
  const final=f.at('lab-exchange-delegation-api');
  for(const id of ['subject','actor','delegated'])assert.ok(has(final,id,'app','credentials'));
  assert.deepEqual(f.plan.artifacts.find(item=>item.artifactId==='delegated').derivedFrom,['subject','actor']);
  assert.ok(observation(final,'delegated','realmB','authorized'));
  assert.equal(final.observations.some(item=>item.actorId==='realmB'&&['subject','actor'].includes(item.artifactId)),false);
});

test('client authentication is a separate received credential, not subject-token consumption',()=>{
  const f=fixture('lab-exchange-id-token');
  const received=f.at('lab-exchange-id-token-request');
  assert.ok(has(received,'client-auth','app','configuration'),'Sending copies the retained backend credential.');
  assert.ok(has(received,'client-auth','realmA','client-auth-request'));
  const input=received.holdings.find(item=>item.artifactId==='client-auth'&&item.actorId==='realmA');
  assert.ok(inspectHeldObject(received,input.holdingId).fields.every(field=>field.readable));
  assert.equal(has(f.at('lab-exchange-id-token-policy'),'client-auth','realmA','client-auth-request'),false);
});
