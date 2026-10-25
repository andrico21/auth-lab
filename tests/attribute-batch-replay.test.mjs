import test from 'node:test';
import assert from 'node:assert/strict';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {compileHeldObjects,projectHeldObjects,heldCursorForPlayback,heldObjectTrace} from '../src/held-object-state.js';
import {FlowPlayer,authoredMessageTiming} from '../src/player.js';

// Two opposite transfers and two local checks share one authored source event.
// Their values and partial protocol/custody prefixes must survive field replay.
function fixture(){
  const cursor=value=>typeof value==='number'?{eventIndex:0,progress:value}:{eventIndex:0,milestone:value};
  const operation=(kind,actorId,instanceId,value,start,end,messageId)=>({attributeId:'stateApp',kind,actorId,instanceId,value,sourceEventId:'batch',heldCursorStart:cursor(start),heldCursorEnd:cursor(end),...(messageId?{messageId,channel:'network',protocolLabel:'Selected message transport'}:{})});
  const effects=[{op:'put',path:'requestReceived',value:true},{op:'put',path:'responseReceived',value:true},{op:'put',path:'firstCheckCompleted',value:true},{op:'put',path:'secondCheckCompleted',value:true}];
  const steps=[{id:'batch',from:'client',to:'client',channel:'internal',payload:[],fields:['stateApp'],protocolEffects:effects,attributeOperations:[
    operation('send','client','request','request',0,.2,'request-message'),
    operation('receive','issuer','request','request',0,.2,'request-message'),
    operation('send','issuer','response','response',.3,.6,'response-message'),
    operation('receive','client','response','response',.3,.6,'response-message'),
    operation('verify','client','response','response','response-arrives','first-check'),
    operation('verify','client','response','response','first-check','second-check'),
  ]}];
  const model={id:'batched-replay',steps,initialState:{requestReceived:false,responseReceived:false,firstCheckCompleted:false,secondCheckCompleted:false}};
  const acquire=(artifactId,actorId)=>({op:'acquire',artifactId,actorId,store:'messages',holdingId:actorId+':'+artifactId,representationId:'plain',retention:'retained'});
  const artifact=(artifactId,creator)=>({artifactId,creator,type:'message',label:artifactId,representations:[{representationId:'plain',format:'plain',readableBy:['client','issuer'],fields:[{attributeId:'stateApp',value:artifactId}]}]});
  const plan={scenarioId:model.id,contextId:'batched-replay-test',actors:{client:{},issuer:{}},artifacts:[artifact('request','client'),artifact('response','issuer')],initial:[{op:'create',artifactId:'request'},acquire('request','client'),{op:'create',artifactId:'response'},acquire('response','issuer')],events:{batch:{messages:[
    {messageId:'request-message',from:'client',to:'issuer',start:0,end:.2,objects:[{artifactId:'request',representationId:'plain'}]},
    {messageId:'response-message',from:'issuer',to:'client',start:.3,end:.6,objects:[{artifactId:'response',representationId:'plain'}]},
  ],milestones:[
    {id:'request-arrives',at:.2,effects:[acquire('request','issuer')],stateEffects:[effects[0]]},
    {id:'response-ready',at:.3,effects:[]},
    {id:'response-arrives',at:.6,effects:[acquire('response','client')],stateEffects:[effects[1]]},
    {id:'first-check',at:.7,effects:[],stateEffects:[effects[2]]},
    {id:'second-check',at:.9,effects:[],stateEffects:[effects[3]]},
    {id:'complete',at:1,effects:[]},
  ]}},coverage:['client','issuer'].map(actorId=>({actorId,status:'complete',support:'supported',stores:[],categories:[],gaps:[]})),bindings:[]};
  return {steps,model,compiled:compileHeldObjects(plan,{model,steps})};
}

test('batched field replay preserves both directions, local check boundaries and backward custody',()=>{
  const {steps,compiled}=fixture();
  const trace=buildAttributeTrace(getAttributeUsage(steps,'stateApp'));
  assert.deepEqual(trace.map(row=>[row.traceKind,row.from,row.to,row.payload[0].value]),[
    ['send','client','issuer','request'],['send','issuer','client','response'],
    ['verify','client','client','response'],['verify','client','client','response'],
  ]);
  const frame=(row,elapsed=1)=>projectHeldObjects(compiled,heldCursorForPlayback(compiled,{status:'paused',kind:'attribute',step:row,duration:1,stepElapsed:elapsed}));
  const requestStart=frame(trace[0],0),requestEnd=frame(trace[0]);
  assert.equal(requestStart.state.requestReceived,false);
  assert.equal(requestEnd.state.requestReceived,true);
  assert.equal(requestEnd.state.responseReceived,false);
  assert.equal(requestEnd.holdings.some(holding=>holding.artifactId==='response'&&holding.actorId==='client'),false);
  const responseEnd=frame(trace[1]);
  assert.equal(responseEnd.state.responseReceived,true);
  assert.equal(responseEnd.state.firstCheckCompleted,false);
  assert.equal(responseEnd.holdings.some(holding=>holding.artifactId==='response'&&holding.actorId==='client'),true);
  const player=new FlowPlayer({requestFrame:()=>0,cancelFrame:()=>{},getTiming:(row,kind)=>authoredMessageTiming(compiled.plan,row,kind)});
  player.seek([trace[1]],.999,'attribute');
  assert.equal(player.snapshot().messageId,'response-message');
  assert.equal(player.snapshot().messagePhase,'in-flight');
  assert.equal(projectHeldObjects(compiled,heldCursorForPlayback(compiled,player.snapshot())).state.responseReceived,false);
  player.seek([trace[1]],1,'attribute');
  assert.equal(player.snapshot().messagePhase,'received');
  assert.deepEqual(projectHeldObjects(compiled,heldCursorForPlayback(compiled,player.snapshot())),responseEnd,'Packet arrival and canonical response custody change together');
  const firstCheck=frame(trace[2]),secondCheck=frame(trace[3]);
  assert.equal(firstCheck.state.firstCheckCompleted,true);
  assert.equal(firstCheck.state.secondCheckCompleted,false);
  assert.equal(secondCheck.state.secondCheckCompleted,true);
  assert.deepEqual(frame(trace[2]),firstCheck,'Backward replay returns to the first check without retaining the second result');
  assert.deepEqual(frame(trace[0]),requestEnd,'Backward replay removes future response custody and checks');
  const exactResponse=heldObjectTrace(compiled,'response').find(row=>row.messageId==='response-message');
  assert.deepEqual(projectHeldObjects(compiled,exactResponse.heldCursorEnd),responseEnd,'Exact-object and field replay agree at the same received response');
  assert.deepEqual(secondCheck.state,projectHeldObjects(compiled,{eventIndex:0,milestone:'complete'}).state,'All completed checks agree with the full source journey');
});
