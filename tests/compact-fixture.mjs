import assert from 'node:assert/strict';
import { installHarness, HarnessEvent } from './dom-harness.mjs';
import { compileHeldObjects, projectHeldObjects } from '../src/held-object-state.js';
export const { document, window, clock } = installHarness();
export { HarnessEvent };
export const { AuthFlowStudio } = await import('../src/app.js');
export const steps = [
  {id:'compact-receipt',from:'realmA',to:'app',title:'Receive then verify',summary:'Receipt is not verification.',detail:'The response arrives before the local check.',channel:'server',fields:['clientIdApp'],payload:[{id:'clientIdApp',name:'client_id',value:'compact-client'}],
    attributeOperations:[{attributeId:'clientIdApp',kind:'send',actorId:'realmA',detail:'Send the exact response field.'},{attributeId:'clientIdApp',kind:'receive',actorId:'app',detail:'Receive the response before local verification.'}],
    attributeValues:{clientIdApp:'compact-client'}},
  {id:'compact-release',from:'app',to:'app',title:'Release response',summary:'Release the inspected response.',detail:'History is not possession.',channel:'local',fields:[],payload:[]},
  {id:'compact-finish',from:'app',to:'app',title:'Finish study',summary:'Finish only at the final boundary.',detail:'No implied future effects.',channel:'local',fields:[],payload:[]},
];
export function compiledFixture() {
  const actors={app:{id:'app',name:'Application'},realmA:{id:'realmA',name:'Issuer'},browser:{id:'browser',name:'Browser'}};
  const acquire=(actorId,store,holdingId)=>({op:'acquire',artifactId:'response',actorId,store,holdingId,retention:'temporary',representationId:'plain'});
  return compileHeldObjects({contextId:'compact-fixture@0',scenarioId:'compact-fixture',actors,
    artifacts:[{artifactId:'response',type:'response',label:'Exact response',creator:'realmA',expiresAt:60,representations:[{representationId:'plain',format:'opaque',readableBy:['realmA','app'],fields:[{attributeId:'clientIdApp',name:'client_id',value:'compact-client'},{attributeId:'issuerSecret',name:'issuer_private',value:'issuer-only-value',readableBy:['realmA']}]}]}],
    initial:[{op:'create',artifactId:'response'},acquire('realmA','output','issuer-response')],
    events:{
      'compact-receipt':{messages:[{messageId:'response-message',from:'realmA',to:'app',start:0,end:.4,objects:[{artifactId:'response',representationId:'plain'}]}],milestones:[
        {id:'received',at:.4,effects:[{op:'advance',value:7},{op:'release',holdingId:'issuer-response'},acquire('app','response','app-response'),{op:'observe',artifactId:'response',actorId:'app',kind:'verification',result:'pending',requestId:'request-1',endpoint:'/token',policy:'explicit local policy'}]},
        {id:'verified',at:.8,effects:[{op:'observe',artifactId:'response',actorId:'app',kind:'verification',result:'verified',requestId:'request-1',endpoint:'/token',policy:'explicit local policy'}]},
        {id:'complete',at:1,effects:[]}]},
      'compact-release':{milestones:[{id:'complete',at:1,effects:[{op:'release',holdingId:'app-response'}]}]},
      'compact-finish':{milestones:[{id:'complete',at:1,effects:[{op:'authority',artifactId:'response',authorityId:'realmA',status:'consumed',detail:'Only at the final source boundary.'}]}]},
    },
    coverage:[
      {actorId:'app',status:'complete',support:'supported',stores:['response'],categories:['credentials'],gaps:[]},
      {actorId:'realmA',status:'partial',support:'supported',stores:['output'],categories:['credentials'],gaps:[{reason:'Issuer cache eviction is not modeled.'}]},
      {actorId:'browser',status:'not-modeled',support:'supported',stores:[],categories:[],gaps:[{reason:'Browser extension storage is outside this model.'}]},
    ],bindings:[],limitations:[],interactions:[]},{steps});
}
export function mount({mode='compact',width=390,storage}={}) {
  window.innerWidth=width;window.localStorage=storage||{getItem:()=>mode,setItem(){}};
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.addEventListener('focusin',event=>{document.activeElement=event.target;});app.connectedCallback();return app;
}
export function fixture(options) {
  const app=mount(options),compiled=compiledFixture();app.activeSteps=steps;
  app.heldView.compiled=()=>compiled;app.heldView.contextId=compiled.contextId;app.heldView.reset();app.heldView.actorId='app';
  app.player.inspectQueue(steps,{cursor:projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}).cursor,boundary:'initial'});
  return {app,compiled};
}
export function unmount(app) {
  app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();
}
export const button=(app,action)=>app.querySelector('[data-compact-action="'+action+'"]');
export const cursor=(app)=>app.heldView.snapshot().cursor;
export function at(app,eventIndex,milestone) {app.inspectSourceCursor({eventIndex,milestone});}
export function canonical(app) {
  const value=app.heldView.snapshot();
  return {cursor:value.cursor,state:value.state,holdings:value.holdings,artifacts:value.artifacts,observations:value.observations,authority:value.authority,coverage:value.coverage,protocolClock:value.protocolClock};
}
export function assertCursor(app,eventIndex,milestone) {assert.equal(cursor(app).eventIndex,eventIndex);assert.equal(cursor(app).milestone,milestone);}
