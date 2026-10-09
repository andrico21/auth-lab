import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTORS, ATTRIBUTES } from '../src/protocol-data.js';
import { getJourneySteps, getActorOverrides } from '../src/architecture-variants.js';
import { getSamlSteps } from '../src/saml-data.js';
import { getAttributeUsage } from '../src/attribute-usage.js';
import { buildAttributeTrace } from '../src/attribute-trace.js';
import { JWE_ATTRIBUTES, applyJweProtection } from '../src/jwe-data.js';
import { applyProviderProfile, getProviderProfile } from '../src/learning-presets.js';

Object.assign(ATTRIBUTES,JWE_ATTRIBUTES);
const protectedValue=step=>step.payload.find(item=>item.name==='id_token')?.value;
const fieldValue=(step,id)=>step.payload.find(item=>item.attributeId===id)?.value;
const stage=(steps,hop,name)=>steps.find(step=>step.jweHop===hop&&step.jweStage===name);
const externalActors=()=>Object.fromEntries(Object.entries(ACTORS).map(([id,actor])=>[id,{...actor,...getActorOverrides('web','external')[id]}]));
const configuration=(applicationProtocol,tokenProtection,providerManaged=false)=>({
  mode:'password',architecture:'web',upstream:'external',applicationProtocol,brokerProtocol:'oidc',
  binding:'redirect',initiation:'sp',tokenProtection,providerManaged,
});
const sourceSteps=config=>config.applicationProtocol==='saml'?getSamlSteps(config):getJourneySteps('password','web','external');
const assertCompact=(value,label)=>{
  assert.equal(value.split('.').length,5,label);
  assert.ok(value.split('.').every(part=>/^[A-Za-z0-9_-]+$/.test(part)),label+' has five encoded parts');
  const header=JSON.parse(Buffer.from(value.split('.')[0],'base64url').toString());
  assert.deepEqual(header,{alg:'RSA-OAEP-256',enc:'A256GCM',kid:'broker-enc-2026',cty:'JWT'});
};

test('Generic provider keeps a protected broker definition and example across OIDC/SAML app legs and both factor boundaries',()=>{
  const provider=getProviderProfile('generic');
  for(const applicationProtocol of ['oidc','saml'])for(const tokenProtection of ['broker-jwe','both-jwe'])for(const providerManaged of [false,true]){
    const config=configuration(applicationProtocol,tokenProtection,providerManaged);
    const source=applyJweProtection(sourceSteps(config),{protection:tokenProtection}),actors=externalActors();
    const original=JSON.stringify({source,actors});
    const adapted=applyProviderProfile(source,actors,'generic',config),wire=stage(adapted.steps,'broker','wire');
    const compact=protectedValue(wire),definition=adapted.attributeOverrides.idTokenB;
    assertCompact(compact,[applicationProtocol,tokenProtection,providerManaged].join(' / '));
    assert.equal(adapted.exampleOverrides.idTokenB,compact);
    assert.equal(definition.example,compact);
    assert.match(definition.name,/nested JWE/);
    assert.match(definition.meaning,/five-part compact JWE/);
    assert.match(definition.purpose,/decrypts/);
    assert.ok(definition.origin.includes(provider.title));
    assert.ok(definition.origin.includes(provider.examples.issuer));
    assert.ok(definition.purpose.includes(provider.examples.clientIdBroker));
    assert.match(definition.standard,/RFC 7516/);
    assert.equal(definition.source,'https://www.rfc-editor.org/rfc/rfc7516');
    assert.equal(JSON.stringify({source,actors}),original,'presentation adapter leaves its inputs intact');
    assert.equal(adapted.steps.some(step=>step.jweHop==='app'),applicationProtocol==='oidc'&&tokenProtection==='both-jwe');
  }
  const signed=applyProviderProfile(getJourneySteps('password','web','external'),externalActors(),'generic',configuration('oidc','signed'));
  assert.match(signed.attributeOverrides.idTokenB.example,/^JWT: iss=/);
  assert.match(signed.attributeOverrides.idTokenB.standard,/OIDC/);
});

test('compact assembly derives occurrence-bound token and JWE values before the wire independently of glossary fallbacks',()=>{
  for(const applicationProtocol of ['oidc','saml'])for(const tokenProtection of ['broker-jwe','both-jwe']){
    const config=configuration(applicationProtocol,tokenProtection),steps=applyJweProtection(sourceSteps(config),{protection:tokenProtection});
    for(const hop of applicationProtocol==='oidc'&&tokenProtection==='both-jwe'?['broker','app']:['broker']){
      const token=hop==='broker'?'idTokenB':'idTokenA',compactId='jweCompact'+(hop==='broker'?'Broker':'App');
      const wrap=stage(steps,hop,'wrap'),wire=stage(steps,hop,'wire'),compact=protectedValue(wire);
      assert.equal(fieldValue(wrap,token),compact,'compact assembly payload belongs to this ID token');
      assert.equal(wrap.attributeValues[token],compact);
      assert.equal(wrap.attributeValues[compactId],compact);
      for(const id of [token,compactId]){
        const trace=buildAttributeTrace(getAttributeUsage(steps,id),{[id]:'JWT: an intentionally incompatible signed-token fallback'});
        const assembly=trace.find(step=>step.sourceStepId===wrap.id&&step.traceKind==='derive');
        assert.ok(assembly,id+' has an explicit derive operation');
        assert.equal(fieldValue(assembly,id),compact,id+' derives exactly the next wire representation');
      }
      const tokenTrace=buildAttributeTrace(getAttributeUsage(steps,token),{[token]:'JWT: fallback'});
      const transmitted=tokenTrace.find(step=>step.sourceStepId===wire.id&&step.traceKind==='send');
      assert.equal(fieldValue(transmitted,token),compact,'wire token is independently read from the wire payload');
      const recovered=tokenTrace.filter(step=>step.jweStage==='verify-inner'||step.jweInboundHop===hop);
      assert.ok(recovered.length>=2,'signature verification and ordinary validation expose the recovered token');
      for(const local of recovered){
        assert.equal(local.from,local.to,'decrypted token remains local');
        assert.match(fieldValue(local,token),/^Recovered inner JWS:/);
        assert.notEqual(fieldValue(local,token),compact);
      }
    }
  }
});

test('Generic adapter recognizes an already expanded broker JWE model without a repeated control setting',()=>{
  const config=configuration('oidc','broker-jwe');
  const expanded=applyJweProtection(sourceSteps(config),{protection:'broker-jwe'});
  const adapted=applyProviderProfile(expanded,externalActors(),'generic',{upstream:'external'});
  assert.equal(adapted.attributeOverrides.idTokenB.example,protectedValue(stage(adapted.steps,'broker','wire')));
  assert.match(adapted.attributeOverrides.idTokenB.meaning,/five-part compact JWE/);
});

// Check the actual selected-field queue and visible animated packet in the
// existing offline harness. It does not replace native-browser visual QA.
const {installHarness,HarnessEvent}=await import('./dom-harness.mjs');
const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const change=(app,id,value)=>{const control=app.querySelector('#'+id);control.value=value;control.dispatchEvent(new HarnessEvent('change'));};
test('corporate Generic broker JWE focused animation assembles and sends the same compact token, then recovers a local JWS',()=>{
  for(const applicationProtocol of ['oidc','saml'])for(const tokenProtection of ['broker-jwe','both-jwe']){
    const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
    try{
      app.selectLabScenario('corporate-external');change(app,'provider-profile','generic');
      change(app,'app-protocol',applicationProtocol);change(app,'token-protection',tokenProtection);
      const compact=protectedValue(stage(app.steps,'broker','wire'));
      assertCompact(compact,applicationProtocol+' / '+tokenProtection);
      assert.equal(app.definition('idTokenB').example,compact);
      assert.match(app.definition('idTokenB').name,/nested JWE/);
      app.selectAttribute('idTokenB',false);
      const assembly=app.traceQueue.findIndex(step=>step.jweStage==='wrap'&&step.traceKind==='derive');
      const wire=app.traceQueue.findIndex(step=>step.jweStage==='wire'&&step.traceKind==='send');
      const recovered=app.traceQueue.findIndex(step=>step.jweStage==='verify-inner'&&step.traceKind==='derive');
      assert.ok(assembly>=0&&wire>assembly&&recovered>wire,'assembly, transfer and recovery have their own ordered moments');
      for(const [index,expected]of [[assembly,compact],[wire,compact],[recovered,'Recovered inner JWS: header.payload.signature (schematic, local only)']]){
        assert.equal(fieldValue(app.traceQueue[index],'idTokenB'),expected);
        app.selectStep(index,true);clock.advance(600);
        assert.equal(app.player.snapshot().packet.value,expected,'animated packet reads the specific occurrence');
        assert.equal(app.refs.packet.hidden,false);
        assert.equal(app.refs['packet-value'].textContent,expected.slice(0,38)+(expected.length>38?'\u2026':''));
      }
    }finally{
      app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();
    }
  }
});
