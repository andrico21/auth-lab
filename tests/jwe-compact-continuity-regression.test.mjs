import test from 'node:test';
import assert from 'node:assert/strict';
import { ATTRIBUTES } from '../src/protocol-data.js';
import { getJourneySteps } from '../src/architecture-variants.js';
import { getSamlSteps } from '../src/saml-data.js';
import { getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { JWE_ATTRIBUTES, applyJweProtection } from '../src/jwe-data.js';
import { applyProviderProfile } from '../src/learning-presets.js';

Object.assign(ATTRIBUTES,JWE_ATTRIBUTES);
const cases=[
  {title:'both OIDC hops',applicationProtocol:'oidc',brokerProtocol:'oidc',tokenProtection:'both-jwe',hops:['broker','app']},
  {title:'SAML application with an OIDC broker',applicationProtocol:'saml',brokerProtocol:'oidc',tokenProtection:'broker-jwe',hops:['broker']},
  {title:'OIDC application with a SAML broker',applicationProtocol:'oidc',brokerProtocol:'saml',tokenProtection:'app-jwe',hops:['app']},
];
const compactId=hop=>'jweCompact'+(hop==='app'?'App':'Broker');
const tokenId=hop=>hop==='app'?'idTokenA':'idTokenB';
const fieldValue=(step,id)=>step.payload.find(item=>item.attributeId===id)?.value;
const valueOnWire=(steps,hop)=>steps.find(step=>step.jweHop===hop&&step.jweStage==='wire').payload.find(item=>item.name==='id_token').value;
const compactMoments=trace=>[['wrap','derive'],['wire','send'],['unwrap','verify']].map(([stage,kind])=>trace.find(step=>step.jweStage===stage&&step.traceKind===kind));

test('compact companion field keeps its exact assembly value at send and structure check without changing HTTP fields or glossary syntax',()=>{
  for(const example of cases){
    const config={mode:'password',architecture:'web',upstream:'external',binding:'redirect',initiation:'sp',providerManaged:true,...example};
    const source=example.applicationProtocol==='oidc'&&example.brokerProtocol==='oidc'?getJourneySteps('password','web','external'):getSamlSteps(config);
    const encrypted=applyJweProtection(source,{protection:example.tokenProtection});
    const steps=applyProviderProfile(encrypted,{},'generic',config).steps;
    for(const hop of example.hops){
      const id=compactId(hop),expected=valueOnWire(steps,hop),syntax=JWE_ATTRIBUTES[id].example;
      assert.equal(expected.split('.').length,5,example.title+' / '+hop);
      assert.match(syntax,/^protected\.encrypted_key\.iv\.ciphertext\.tag/);
      const trace=buildAttributeTrace(getAttributeUsage(steps,id),{[id]:'A fallback that must never replace this occurrence'});
      const moments=compactMoments(trace);
      assert.equal(trace.length,3,'one assembly, one transfer and one structure check');
      assert.deepEqual(moments.map(step=>step.traceKind),['derive','send','verify']);
      for(const moment of moments)assert.equal(fieldValue(moment,id),expected,example.title+' / '+hop+' / '+moment.jweStage);
      assert.equal(moments[0].from,moments[0].to,'assembly stays local');
      assert.notEqual(moments[1].from,moments[1].to,'send crosses the actual issuer/recipient connection');
      assert.equal(moments[2].from,moments[2].to,'structure verification stays local');
      assert.equal(moments[2].from,moments[1].to,'the recipient checks the exact received compact value');
      const wire=steps.find(step=>step.jweHop===hop&&step.jweStage==='wire');
      assert.equal(wire.payload.filter(item=>item.name==='id_token').length,1);
      assert.equal(wire.payload.some(item=>/JWE Compact Serialization/.test(item.name)),false,'companion projection adds no HTTP field');
      assert.equal(JWE_ATTRIBUTES[id].example,syntax,'the explanatory glossary syntax remains intact');
      const tokenTrace=buildAttributeTrace(getAttributeUsage(steps,tokenId(hop)));
      for(const local of tokenTrace.filter(step=>step.jweStage==='verify-inner'||step.jweInboundHop===hop)){
        assert.equal(local.from,local.to);
        assert.match(fieldValue(local,tokenId(hop)),/^Recovered inner JWS:/,'ID-token recovery retains its local signed representation');
      }
    }
  }
});

// Native-browser visual acceptance remains separate. These checks exercise
// actual index/timeline controls, the player packet and backward slider seek.
const {installHarness,HarnessEvent}=await import('./dom-harness.mjs');
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const change=(app,id,value)=>{const control=app.querySelector('#'+id);control.value=value;control.dispatchEvent(new HarnessEvent('change'));};
const assertPacket=(app,id,expected)=>{
  assert.equal(app.player.snapshot().packet.attributeId,id);
  assert.equal(app.player.snapshot().packet.value,expected);
  assert.equal(app.refs.packet.hidden,false);
  assert.equal(app.refs['packet-value'].textContent,expected.slice(0,38)+(expected.length>38?'\u2026':''));
};
test('index-selected compact field keeps the same visible player value through assembly, send, check and reverse seek',()=>{
  for(const example of cases){
    const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
    try{
      app.selectLabScenario('corporate-external');change(app,'provider-profile','generic');
      change(app,'app-protocol',example.applicationProtocol);change(app,'broker-protocol',example.brokerProtocol);change(app,'token-protection',example.tokenProtection);
      for(const hop of example.hops){
        const id=compactId(hop),expected=valueOnWire(app.steps,hop);
        const indexEntry=app.refs['attribute-index-list'].querySelector('[data-index-attribute="'+id+'"]');
        assert.ok(indexEntry,example.title+' exposes '+id+' in the actual index');indexEntry.click();
        assert.equal(app.attributeSelection,id);
        const moments=compactMoments(app.traceQueue);
        assert.deepEqual(moments.map(step=>step.traceKind),['derive','send','verify']);
        for(const moment of moments){
          const index=app.traceQueue.indexOf(moment);
          app.refs.timeline.querySelector('[data-step="'+index+'"]').click();clock.advance(600);
          assertPacket(app,id,expected);
        }
        const durations=app.traceQueue.map(step=>app.player.totalDuration([step]));
        const total=durations.reduce((sum,duration)=>sum+duration,0);
        for(const moment of [...moments].reverse()){
          const index=app.traceQueue.indexOf(moment),offset=durations.slice(0,index).reduce((sum,duration)=>sum+duration,0);
          app.refs.seek.value=String(Math.round((offset+600)/total*1000));app.refs.seek.dispatchEvent(new HarnessEvent('input'));
          assert.equal(app.player.status,'paused','seeking previews without starting playback');
          assert.equal(app.currentStep.jweStage,moment.jweStage);
          assert.equal(app.player.snapshot().step.id,moment.id);
          assertPacket(app,id,expected);
          clock.advance(200);assertPacket(app,id,expected);
        }
        assert.equal(app.definition(id).example,JWE_ATTRIBUTES[id].example,'index help retains its explanatory syntax template');
      }
    }finally{
      app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();
    }
  }
});
