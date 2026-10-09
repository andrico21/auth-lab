import test from 'node:test';
import assert from 'node:assert/strict';
import {getJourneySteps,getExampleOverrides} from '../src/architecture-variants.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {applyJweProtection} from '../src/jwe-data.js';
import {getProviderProfile} from '../src/learning-presets.js';
import {installHarness,HarnessEvent} from './dom-harness.mjs';

const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {clock,document}=harness;
const canonical=step=>step.id.match(/(?:^|-)(l\d{2})$/)?.[1];
const scalar=step=>step.payload.find(item=>item.attributeId==='audience')?.value;
const mount=()=>{const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();app.selectLabScenario('core');return app;};
const unmount=app=>{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();};
const trace=(steps,architecture,upstream)=>buildAttributeTrace(getAttributeUsage(steps,'audience'),getExampleOverrides(architecture,upstream));

test('each core factor and realm topology retains the actual token audience from issuance through recipient validation',()=>{
  for(const mode of ['password','passkey','one-time-code','password-totp','passkey-totp'])
    for(const architecture of ['native','web'])for(const upstream of ['single','keycloak','external']){
      const client=architecture==='web'?'web-app':'desktop-app';
      const steps=getJourneySteps(mode,architecture,upstream),actual=trace(steps,architecture,upstream);
      const expected=upstream==='single'?[
        ['create','realmA','realmA',client],['send','realmA','app',client],['verify','app','app',client],
      ]:[
        ['create','realmB','realmB','realm-a-broker'],['send','realmB','realmA','realm-a-broker'],['verify','realmA','realmA','realm-a-broker'],
        ['create','realmA','realmA',client],['send','realmA','app',client],['verify','app','app',client],
      ];
      assert.deepEqual(actual.map(moment=>[moment.traceKind,moment.from,moment.to,scalar(moment)]),expected,[mode,architecture,upstream].join('/'));
      assert.equal(steps.find(step=>canonical(step)==='l25').attributeValues.audience,client);
      if(upstream!=='single')assert.equal(steps.find(step=>canonical(step)==='l19').attributeValues.audience,'realm-a-broker');
    }
});

test('JWE claim extraction and both validation stages preserve per-leg audience while encrypted transport has no plaintext aud packet',()=>{
  for(const architecture of ['native','web'])for(const upstream of ['single','keycloak','external']){
    const client=architecture==='web'?'web-app':'desktop-app';
    const steps=applyJweProtection(getJourneySteps('password',architecture,upstream),{protection:'both-jwe'});
    const actual=trace(steps,architecture,upstream);
    assert.equal(actual.some(moment=>moment.from!==moment.to),false,'aud stays inside issuer/recipient when encrypted');
    for(const moment of actual){
      const broker=moment.sourceStepId.includes('-l18-')||canonical({id:moment.sourceStepId})==='l19';
      assert.equal(scalar(moment),broker?'realm-a-broker':client,moment.sourceStepId);
    }
    const claimChecks=actual.filter(moment=>moment.sourceStepId.endsWith('validate-claims')&&moment.traceKind==='verify');
    assert.equal(claimChecks.length,upstream==='single'?1:2);
    const wires=steps.filter(step=>step.jweStage==='wire');
    assert.ok(wires.length);
    assert.ok(wires.every(step=>!getAttributeUsage([step],'audience').length));
    for(const id of ['idTokenA',...(upstream==='single'?[]:['idTokenB'])]){
      const recovered=buildAttributeTrace(getAttributeUsage(steps,id)).filter(moment=>moment.sourceStepId.endsWith('verify-inner')||['l19','l25'].includes(canonical({id:moment.sourceStepId})));
      assert.ok(recovered.length);
      assert.ok(recovered.every(moment=>moment.payload.find(item=>item.attributeId===id).value==='Recovered inner JWS: header.payload.signature (schematic, local only)'),id+' keeps its recovered local representation');
    }
  }
});

test('the actual aud index and seek player display the receiving client audience across native/web, one/two realm and external profiles',()=>{
  const app=mount();try{
    for(const architecture of ['native','web'])for(const profile of ['single','keycloak','generic','entra','okta','cognito'])for(const protectedToken of [false,true]){
      app.clearAttribute();Object.assign(app,{mode:'password',architecture,upstream:['single','keycloak'].includes(profile)?profile:'external',
        providerProfileId:['single','keycloak'].includes(profile)?'generic':profile,providerManaged:!['single','keycloak','generic'].includes(profile),
        applicationProtocol:'oidc',brokerProtocol:'oidc',oidcFlow:'authorization-code',tokenProtection:protectedToken?'app-jwe':'signed'});
      app.refreshConfiguration();
      const choice=app.refs['attribute-index-list'].querySelector('[data-index-attribute="audience"]');assert.ok(choice);choice.click();app.player.stop(false);
      assert.equal(app.attributeSelection,'audience');
      const expectedClient=architecture==='web'?'web-app':'desktop-app';
      const expectedBroker=['single','keycloak','generic'].includes(profile)?'realm-a-broker':getProviderProfile(profile).examples.clientIdBroker;
      const checks=app.traceQueue.filter(moment=>moment.traceKind==='verify');
      assert.equal(checks.length,profile==='single'?(protectedToken?2:1):(protectedToken?3:2));
      // Exercise real paused packet previews in reverse order, rather than
      // asserting only the source snapshots or app's cached trace model.
      for(const moment of [...checks].reverse()){
        const expected=moment.from==='app'?expectedClient:expectedBroker;
        assert.equal(moment.from,moment.to);assert.equal(scalar(moment),expected,[architecture,profile,protectedToken,moment.sourceStepId].join('/'));
        const index=app.traceQueue.indexOf(moment),duration=app.player.totalDuration([moment]);
        const before=app.traceQueue.slice(0,index).reduce((sum,step)=>sum+app.player.totalDuration([step]),0);
        const fraction=(before+Math.min(duration*.5,905))/app.player.totalDuration(app.traceQueue);
        app.refs.seek.value=String(Math.round(fraction*1000));app.refs.seek.dispatchEvent(new HarnessEvent('input'));
        assert.equal(app.player.status,'paused');assert.equal(app.currentStep.id,moment.id);
        assert.equal(app.refs['packet-name'].textContent,'aud');assert.equal(app.refs['packet-value'].textContent,expected);
        assert.equal(app.refs.packet.hidden,false);assert.equal(clock.frames.size,0);
      }
    }
  }finally{unmount(app);}
});

test('core ID-token audience snapshots do not alias token-exchange requested audience or access-token aud',()=>{
  const app=mount();try{
    app.selectLabScenario('backend-token-exchange');
    const values=id=>{app.selectAttribute(id,false);return app.traceQueue.map(moment=>moment.payload.find(item=>item.attributeId===id)?.value);};
    assert.ok(values('exchangeAudienceRequest').every(value=>value==='orders-api'));
    const source=values('exchangeSourceAudience');assert.ok(source.length);assert.ok(source.every(value=>value==='[requester-client, orders-api]'));
    const result=values('exchangeResultAudience');assert.ok(result.length);assert.ok(result.every(value=>value==='[orders-api]'));
    app.selectAttribute('audience',false);assert.equal(app.traceQueue.length,0,'the core ID-token scalar has no token-exchange operations');
  }finally{unmount(app);}
});
