import test from 'node:test';
import assert from 'node:assert/strict';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {WEBLAB_ATTRIBUTES,WEBLAB_SCENARIOS} from '../src/web-api-lab.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {installHarness} from './dom-harness.mjs';

// Independent RFC 6750 §3.1 fixtures: invalid credentials use the illustrated
// 401 challenge; accepted credentials lacking permission use 403. These values
// are not taken from the model's constructors or glossary fallback examples.
const outcomes=[
  {create:'web-error-invalid-check',send:'web-error-401',status:'401 Unauthorized',challenge:'Bearer error="invalid_token"',error:'invalid_token'},
  {create:'web-error-audience-check',send:'web-error-audience-401',status:'401 Unauthorized',challenge:'Bearer error="invalid_token"',error:'invalid_token'},
  {create:'web-error-permission',send:'web-error-403',status:'403 Forbidden',challenge:'Bearer error="insufficient_scope", scope="orders:write"',error:'insufficient_scope'},
  {create:'web-error-success-response',send:'web-error-success-response',status:'200 OK'},
];
const fields={webHttpStatus:'status',webChallengeHeader:'challenge',webBearerError:'error'};
Object.assign(ATTRIBUTES,WEBLAB_ATTRIBUTES);
const model=WEBLAB_SCENARIOS.find(item=>item.id==='lab-api-errors');
const stage=id=>model.steps().find(item=>item.id===id);
const expectedFrames=id=>outcomes.filter(outcome=>Object.hasOwn(outcome,fields[id])).flatMap(outcome=>[
  {stage:outcome.create,kind:'create',from:'realmB',to:'realmB',value:outcome[fields[id]]},
  {stage:outcome.send,kind:'send',from:'realmB',to:'app',value:outcome[fields[id]]},
]);
const harness=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const {clock,document}=harness;

test('each API outcome snapshots matching creation and transmission values without a generic status/error fallback',()=>{
  for(const outcome of outcomes)for(const id of [outcome.create,outcome.send]){
    const item=stage(id);assert.ok(Object.isFrozen(item.attributeValues));
    assert.equal(item.attributeValues.webHttpStatus,outcome.status,id+' status snapshot');
    if(outcome.error){
      assert.equal(item.attributeValues.webChallengeHeader,outcome.challenge,id+' challenge snapshot');
      assert.equal(item.attributeValues.webBearerError,outcome.error,id+' error snapshot');
      assert.equal(item.fields.includes('webResource'),false,'Failure cannot return protected data');
    }else{
      assert.equal(item.fields.includes('webChallengeHeader'),false,'Successful response has no invented challenge');
      assert.equal(item.fields.includes('webBearerError'),false,'Successful response has no invented error');
      assert.equal(Object.hasOwn(item.attributeValues,'webBearerError'),false);
    }
    for(const member of item.payload.filter(member=>member.name==='HTTP'||member.attributeId==='webHttpStatus')){
      assert.equal(member.attributeId,'webHttpStatus',id+' status payload identifies its scalar');
      assert.equal(member.value,outcome.status,id+' visible status matches the snapshot');
    }
  }
  assert.equal(stage('web-error-403').attributeValues.webRequiredScope,'orders:write');
  assert.equal(stage('web-error-permission').attributeValues.webRequiredScope,'orders:write');
  assert.equal(model.steps().length,14,'All four independent request cases remain');
});

test('focused response-field traces create and send the exact same branch values even with incorrect supplied fallback examples',()=>{
  for(const id of Object.keys(fields)){
    const trace=buildAttributeTrace(getAttributeUsage(model.steps(),id),{[id]:'unrelated generic fallback'});
    assert.deepEqual(trace.map(frame=>({stage:frame.sourceStepId,kind:frame.traceKind,from:frame.from,to:frame.to,value:frame.payload.find(member=>member.attributeId===id).value})),expectedFrames(id),id);
  }
});

test('actual app/player packets retain the 401, 403 and 200 field values for every create/send occurrence',()=>{
  const app=new AuthFlowStudio();document.body.appendChild(app);app.connectedCallback();
  try{
    app.selectLabScenario('lab-api-errors');app.player.setSpeed(4);
    for(const id of Object.keys(fields)){
      app.selectAttribute(id,false);
      const wanted=expectedFrames(id),seen=new Map();
      assert.deepEqual(app.traceQueue.map(frame=>({stage:frame.sourceStepId,kind:frame.traceKind,from:frame.from,to:frame.to,value:frame.payload[0].value})),wanted,id+' displayed queue');
      const unsubscribe=app.player.subscribe(event=>{
        if(event.type!=='frame'||!event.visible)return;
        assert.equal(event.packet.attributeId,id);
        const key=event.step.sourceStepId+':'+event.step.traceKind;
        const expected=wanted.find(frame=>key===frame.stage+':'+frame.kind);
        assert.ok(expected,key+' expected occurrence');
        assert.equal(event.packet.value,expected.value,key+' visible packet');
        seen.set(key,event.packet.value);
      });
      try{app.playAttribute();clock.until(()=>app.player.status!=='playing');}
      finally{unsubscribe();}
      assert.equal(app.player.status,'complete');
      assert.deepEqual([...seen.entries()],wanted.map(frame=>[frame.stage+':'+frame.kind,frame.value]),id+' every expected packet was observed');
      app.seekPlayback(.88);app.seekPlayback(.12);
      const current=app.currentStep;
      const expected=wanted.find(frame=>frame.stage===current.sourceStepId&&frame.kind===current.traceKind);
      assert.ok(expected);assert.equal(current.payload[0].value,expected.value,id+' reverse seek retains this occurrence');
    }
  }finally{app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
});

test('adjacent SPA, BFF, introspection and key-rotation status traces bind only their authored response occurrences',()=>{
  const expected={
    'lab-spa-api':[
      ['web-spa-api-response','create','realmB','realmB','200 OK'],
      ['web-spa-api-response','send','realmB','browser','200 OK'],
    ],
    'lab-bff-api':[
      ['web-bff-api-response','create','realmB','realmB','200 OK'],
      ['web-bff-api-response','send','realmB','app','200 OK'],
      ['web-bff-ui-response','send','app','browser','200 OK'],
    ],
    'lab-api-introspection':[
      ['web-intro-resource','create','realmB','realmB','200 OK'],
      ['web-intro-resource','send','realmB','app','200 OK'],
      ['web-intro-reject-inactive','create','realmB','realmB','401 Unauthorized'],
      ['web-intro-reject-inactive','send','realmB','app','401 Unauthorized'],
    ],
    'lab-jwks-rotation':[
      ['web-rotation-success','create','realmB','realmB','200 OK'],
      ['web-rotation-success','send','realmB','app','200 OK'],
    ],
  };
  for(const [modelId,wanted]of Object.entries(expected)){
    const model=WEBLAB_SCENARIOS.find(item=>item.id===modelId);
    const queue=buildAttributeTrace(getAttributeUsage(model.steps(),'webHttpStatus'),{webHttpStatus:'unrelated fallback'});
    assert.deepEqual(queue.map(frame=>[frame.sourceStepId,frame.traceKind,frame.from,frame.to,frame.payload[0].value]),wanted,modelId);
    for(const step of model.steps()){
      for(const member of step.payload.filter(member=>member.attributeId==='webHttpStatus')){
        assert.ok(/^(200 OK|401 Unauthorized)$/.test(member.value));
        assert.equal(step.fields.includes('webHttpStatus'),true,'Only explicitly declared status operations are bound');
      }
      for(const member of step.payload.filter(member=>member.name==='HTTP'&&/^(GET|POST|OPTIONS) /.test(member.value)))assert.equal(member.attributeId,undefined,'Request lines do not become response status fields');
      if(step.id.endsWith('-api-response')||step.id==='web-intro-resource'||step.id==='web-rotation-success')assert.equal(step.attributeValues.webHttpStatus,'200 OK');
    }
  }
});
