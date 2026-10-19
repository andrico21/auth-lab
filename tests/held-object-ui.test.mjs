import test from 'node:test';
import assert from 'node:assert/strict';
import { installHarness, HarnessEvent } from './dom-harness.mjs';
import { compileHeldObjects, projectHeldObjects, heldCursorForPlayback } from '../src/held-object-state.js';
import { holdingSlots, holdingControlKey, fullDockGeometry, compactDockGeometry, detachedHoldingStatus } from '../src/held-object-view.js';

const {document,clock}=installHarness();
const {AuthFlowStudio}=await import('../src/app.js');
const sourceSteps=[
  {id:'ui-issue',from:'realmA',to:'realmA',title:'Issue replacement',phase:'Issuance',summary:'Create R1 without delivering it.',detail:'Authority and possession differ.',channel:'local',fields:[],payload:[]},
  {id:'ui-arrive',from:'realmA',to:'app',title:'Replacement arrives',phase:'Delivery',summary:'Receive the exact response.',detail:'Receipt is separate from installation.',channel:'server',fields:[],payload:[{name:'refresh_token',value:'R1'}]},
  {id:'ui-install',from:'app',to:'app',title:'Install replacement',phase:'Storage',summary:'Move R1 and release R0.',detail:'A conforming replacement releases only the old holding.',channel:'local',fields:[],payload:[]},
];
const acquire=(artifactId,actorId,store,holdingId,retention='retained')=>({op:'acquire',artifactId,actorId,store,holdingId,retention,representationId:'plain'});
function fixture(){
  const actors={app:{id:'app'},realmA:{id:'realmA'},browser:{id:'browser'}};
  const artifact=(artifactId,creator='app')=>({artifactId,type:'refresh_token',label:artifactId,creator,representations:[{representationId:'plain',format:'opaque',readableBy:creator==='realmA'?['realmA','app']:['app'],fields:[{attributeId:'uiValue',name:'value',value:artifactId}]}]});
  const plan={contextId:'ui-fixture@0',scenarioId:'ui-fixture',actors,artifacts:[artifact('R0'),artifact('R1','realmA'),artifact('secret'),artifact('session'),artifact('AT0')],
    initial:[{op:'create',artifactId:'R0'},acquire('R0','app','credentials','app-r0'),{op:'create',artifactId:'secret'},acquire('secret','app','configuration','app-secret'),{op:'create',artifactId:'session'},acquire('session','app','session','app-session'),{op:'create',artifactId:'AT0'},acquire('AT0','app','credentials','app-at0')],
    events:{
      'ui-issue':{milestones:[{id:'complete',at:1,effects:[{op:'create',artifactId:'R1'},acquire('R1','realmA','output','issuer-r1','temporary'),{op:'authority',artifactId:'R0',authorityId:'realmA',status:'consumed',detail:'Client has not received replacement yet.'}]}]},
      'ui-arrive':{milestones:[{id:'complete',at:1,effects:[{op:'release',holdingId:'issuer-r1'},acquire('R1','app','response','app-r1','temporary'),{op:'observe',artifactId:'R1',actorId:'app',kind:'verification',result:'pending',requestId:'refresh-1',endpoint:'/token',policy:'selected response policy'}]}],messages:[{messageId:'r1-response',from:'realmA',to:'app',objects:[{artifactId:'R1',representationId:'plain'}],start:0,end:1}]},
      'ui-install':{milestones:[{id:'complete',at:1,effects:[{op:'release',holdingId:'app-r0'},{op:'move',holdingId:'app-r1',store:'credentials',retention:'retained'},{op:'observe',artifactId:'R1',actorId:'app',kind:'acceptance',result:'installed',requestId:'refresh-1',endpoint:'/token',policy:'selected response policy'}]}]},
    },coverage:Object.keys(actors).map(actorId=>({actorId,status:'complete',support:'supported',stores:['configuration','credentials','session','output','response'],categories:['credentials'],gaps:[]})),bindings:[],limitations:[],interactions:[]};
  return compileHeldObjects(plan,{steps:sourceSteps});
}
// Match the established explicit-focus fixture. This models app decisions,
// not native browser focus navigation or computed layout.
function mount(){
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;
  app.connectedCallback();app.addEventListener('focusin',event=>{document.activeElement=event.target;});return app;
}
function mountFixture(){
  const app=mount();
  const compiled=fixture(),view=app.heldView;let current=projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'});
  view.compiled=()=>compiled;view.snapshot=()=>current;view.contextId=compiled.contextId;view.initial=true;view.lastKey='';app.activeSteps=sourceSteps;app.index=0;app.heldGeometry=null;view.actorId='app';view.render();
  return {app,view,compiled,setCursor(cursor){current=projectHeldObjects(compiled,cursor);view.render();return current;},get snapshot(){return current;}};
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();}
const control=(app,id)=>[...app.querySelectorAll('[data-holding-id]')].find(item=>item.dataset.holdingId===id&&!item.closest('[hidden]'));

test('exact control identity, ordering and overflow pinning never merge equal attribute generations',()=>{
  const rows=['a','b','c','d'].map((id,ordinal)=>({contextId:'one',actorId:'app',artifactId:id,representationId:'plain',holdingId:'h-'+id,ordinal}));
  const slots=holdingSlots(rows,'h-d');
  assert.deepEqual(slots.visible.map(item=>item.artifactId),['a','d']);
  assert.deepEqual(slots.hidden.map(item=>item.artifactId),['b','c']);
  assert.notEqual(holdingControlKey(rows[0]),holdingControlKey({...rows[0],contextId:'two'}));
  assert.notEqual(holdingControlKey(rows[0]),holdingControlKey({...rows[0],artifactId:'a-next'}));
});

test('full docks have independent composite geometry, actor ports and reserved collapsed cells',()=>{
  const actors=['person','workstation','home','rootA','rootB','resource','service'];
  const pairs=actors.flatMap((id,index)=>[[id,id],[id,actors[(index+1)%actors.length]]]);
  const full=fullDockGeometry(actors,actors,pairs,1120,730);
  assert.ok(full,'dense forest topology has a valid full dock mode');
  for(const bounds of Object.values(full.bounds)){assert.equal(bounds.right-bounds.left,316);assert.equal(bounds.bottom-bounds.top,174);assert.ok(bounds.left>=22&&bounds.right<=1098);}
  assert.ok(full.routes.get('person>person').startsWith('M 22 125'),'self route starts on actor left, not its dock');
  const collapsed=fullDockGeometry(['cli','agent','browser'],['cli','browser'],[['cli','browser']],1120,730);
  const expanded=fullDockGeometry(['cli','agent','browser'],['cli','agent','browser'],[['cli','browser']],1120,730);
  assert.deepEqual(collapsed.positions.cli,expanded.positions.cli);
  assert.deepEqual(collapsed.bounds.agent,expanded.bounds.agent);
  assert.equal(fullDockGeometry(actors,actors,pairs,1119,730),null,'narrow final CSS box uses external controls');
  assert.equal(fullDockGeometry(actors,actors,pairs,1120,729),null);
  assert.equal(fullDockGeometry([...actors,'eight','nine','ten'],actors,pairs,1120,730),null);
});

test('initial UI shows seeded holdings, explicit complete-empty and no future creation',()=>{
  const f=mountFixture();try{
    assert.equal(f.app.querySelector('#show-held-objects').hasAttribute('checked'),true);
    assert.equal(f.view.visible,true);assert.equal(f.view.root.hidden,false);
    assert.match(f.view.root.textContent,/Before step 1/);
    assert.ok(control(f.app,'app-r0'));
    assert.equal(control(f.app,'app-r1'),undefined);
    f.view.actorId='browser';f.view.lastKey='';f.view.render();
    assert.match(f.view.root.textContent,/No held objects/);
    assert.equal(f.app.querySelector('button button'),null,'inventory controls are never nested in actor buttons');
  }finally{unmount(f.app);}
});

test('R0 selection survives arrival, detaches on release, and rewinds without selecting R1',()=>{
  const f=mountFixture();try{
    control(f.app,'app-r0').focus();control(f.app,'app-r0').click();
    const originalKey=document.activeElement.dataset.heldKey;
    f.setCursor({eventIndex:0,milestone:'complete'});
    assert.equal(f.view.selection.artifactId,'R0');
    assert.equal(document.activeElement.dataset.heldKey,originalKey);
    assert.equal(control(f.app,'app-r1'),undefined,'issuer creation does not deliver R1');
    f.setCursor({eventIndex:1,milestone:'complete'});
    assert.ok(control(f.app,'app-r1'));
    assert.equal(document.activeElement.dataset.heldKey,originalKey);
    f.setCursor({eventIndex:2,milestone:'complete'});
    assert.equal(control(f.app,'app-r0'),undefined);
    assert.match(f.view.inspector.textContent,/No longer held/);
    assert.equal(f.view.selection.artifactId,'R0');
    assert.equal(document.activeElement.dataset.heldActor,'app');
    f.setCursor({eventIndex:-1,milestone:'initial'});
    assert.ok(control(f.app,'app-r0'));
    assert.equal(f.view.selection.artifactId,'R0');
  }finally{unmount(f.app);}
});

test('detached labels distinguish future creation, receipt and old possession',()=>{
  const compiled=fixture(),received=projectHeldObjects(compiled,{eventIndex:1,milestone:'complete'}).holdings.find(item=>item.holdingId==='app-r1');
  assert.equal(detachedHoldingStatus(compiled,projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}),received),'Not created');
  assert.equal(detachedHoldingStatus(compiled,projectHeldObjects(compiled,{eventIndex:0,milestone:'complete'}),received),'Not yet held');
  const old=projectHeldObjects(compiled,{eventIndex:-1,milestone:'initial'}).holdings.find(item=>item.holdingId==='app-r0');
  assert.equal(detachedHoldingStatus(compiled,projectHeldObjects(compiled,{eventIndex:2,milestone:'complete'}),old),'No longer held');
});

test('authored move preserves exact selection and request-scoped inspection without generation substitution',()=>{
  const f=mountFixture();try{
    f.setCursor({eventIndex:1,milestone:'complete'});control(f.app,'app-r1').click();
    assert.equal(f.view.selection.store,'response');
    f.setCursor({eventIndex:2,milestone:'complete'});
    assert.equal(f.view.selection.artifactId,'R1');assert.equal(f.view.selection.store,'credentials');assert.equal(f.view.selection.retention,'retained');
    assert.match(f.view.inspector.textContent,/refresh-1/);assert.match(f.view.inspector.textContent,/selected response policy/);assert.match(f.view.inspector.textContent,/not automatic holder knowledge/);
  }finally{unmount(f.app);}
});

test('hide, help dismissal and responsive recovery retain semantic selection without stale focus',()=>{
  const f=mountFixture();try{
    control(f.app,'app-r0').click();
    f.view.inspector.querySelector('[data-held-help]').click();
    assert.ok(f.view.inspector.querySelector('[role="dialog"]'));
    document.activeElement.dispatchEvent(new HarnessEvent('keydown',{key:'Escape'}));
    assert.equal(f.view.inspector.querySelector('[role="dialog"]'),null);
    assert.ok(document.activeElement.hasAttribute('data-held-help'));
    const before=f.snapshot.cursor;
    const toggle=f.app.querySelector('#show-held-objects');toggle.checked=false;toggle.dispatchEvent(new HarnessEvent('change'));
    assert.equal(f.view.root.hidden,true);assert.equal(document.activeElement,toggle);assert.equal(f.view.selection.artifactId,'R0');
    toggle.checked=true;toggle.dispatchEvent(new HarnessEvent('change'));
    assert.equal(f.view.root.hidden,false);assert.deepEqual(f.snapshot.cursor,before);
    control(f.app,'app-r0').focus();f.view.resize();
    assert.equal(document.activeElement.dataset.holdingId,'app-r0');assert.deepEqual(f.snapshot.cursor,before);
  }finally{unmount(f.app);}
});

test('exact history is an artifact trace and shares canonical snapshots with full playback',()=>{
  const f=mountFixture();try{
    f.setCursor({eventIndex:1,milestone:'complete'});control(f.app,'app-r1').click();
    f.view.trace('R1');f.app.player.pause();
    assert.equal(f.app.objectTraceSelection,'R1');assert.equal(f.app.attributeSelection,null);
    assert.ok(f.app.player.queue.length>0);
    for(const row of f.app.player.queue){
      assert.equal(row.artifactId,'R1');assert.ok(row.heldCursorStart&&row.heldCursorEnd);
      const cursor=heldCursorForPlayback(f.compiled,{status:'complete',step:row},row);
      assert.deepEqual(projectHeldObjects(f.compiled,cursor),projectHeldObjects(f.compiled,row.heldCursorEnd));
    }
    assert.match(f.app.refs['attribute-focus'].textContent,/EXACT OBJECT HISTORY/);
  }finally{unmount(f.app);}
});

test('real app initial, selected completion, seek start and Reset share the protocol-state cursor',()=>{
  const app=mount();try{
    assert.deepEqual(app.heldView.snapshot().cursor,{eventIndex:-1,milestone:'initial'});
    assert.equal(app.protocolSnapshot().sourceIndex,-1);
    app.selectStep(0,false);
    assert.deepEqual(app.protocolSnapshot().cursor,{eventIndex:0,milestone:'complete'});
    app.seekPlayback(0);
    assert.deepEqual(app.protocolSnapshot().cursor,{eventIndex:0,milestone:'before'});
    app.reset();
    assert.deepEqual(app.heldView.snapshot().cursor,{eventIndex:-1,milestone:'initial'});
    assert.equal(app.protocolSnapshot().sourceIndex,-1);
    const compiled=app.heldView.compiled();app.heldView.render();app.heldView.render();assert.equal(app.heldView.compiled(),compiled,'immutable context compilation is memoized');
  }finally{unmount(app);}
});

test('reduced motion advances authored event commits without scheduling animation frames',()=>{
  const app=mount();try{
    app.player.setReducedMotion(true);app.player.play([app.steps[0]],'demo');
    assert.equal(clock.frames.size,0);
    const before=app.heldView.snapshot().cursor;
    clock.advance(700);
    assert.equal(app.player.status,'complete');
    assert.equal(app.heldView.snapshot().cursor.milestone,'complete');
    assert.notDeepEqual(app.heldView.snapshot().cursor,before);
    assert.equal(clock.frames.size,0);
  }finally{unmount(app);}
});

test('partial-known and unmodeled owners never claim complete empty inventory',()=>{
  const f=mountFixture();try{
    const state=f.snapshot;
    f.view.snapshot=()=>({...state,coverage:state.coverage.map(record=>record.actorId==='app'?{...record,status:'partial',gaps:[{store:'pending',reason:'Pending-transaction lifecycle is not authored.'}]}:record.actorId==='browser'?{...record,status:'not-modeled'}:record)});
    f.view.lastKey='';f.view.render();
    assert.match(f.view.root.textContent,/Known held objects - incomplete model/);
    assert.match(f.view.root.textContent,/Pending-transaction lifecycle is not authored/);
    f.view.actorId='browser';f.view.lastKey='';f.view.render();
    assert.match(f.view.root.textContent,/Inventory not modeled/);
    assert.doesNotMatch(f.view.root.textContent,/No held objects/);
  }finally{unmount(f.app);}
});

test('same-cursor frames preserve controls and do not repeat meaningful announcements',()=>{
  const f=mountFixture();try{
    f.view.render();const original=control(f.app,'app-r0'),announcement=f.app.querySelector('#held-announcement').textContent;
    for(let frame=0;frame<10;frame++)f.view.render({type:'frame',progress:frame/10});
    assert.equal(control(f.app,'app-r0'),original);
    assert.equal(f.app.querySelector('#held-announcement').textContent,announcement);
  }finally{unmount(f.app);}
});

test('component collapse keeps the logical child selection and returns to its initiating checkbox',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-ad-first-sign-in',{navigate:false});
    app.selectStep(app.steps.length-1,false);
    const holding=app.heldView.snapshot().holdings.find(item=>app.scenarioOwnedActors[item.actorId]?.parentId);
    assert.ok(holding,'authored KDC material retains a logical component owner');
    app.heldView.select(holding);const cursor=app.heldView.snapshot().cursor;
    const checkbox=app.querySelector('#show-internals');checkbox.checked=true;checkbox.dispatchEvent(new HarnessEvent('change'));
    checkbox.checked=false;checkbox.dispatchEvent(new HarnessEvent('change'));
    assert.equal(document.activeElement,checkbox);
    assert.equal(app.heldView.selection.actorId,holding.actorId);
    assert.deepEqual(app.heldView.snapshot().cursor,cursor);
  }finally{unmount(app);}
});

test('failed environment Apply is atomic while Reset and scenario switches clear exact selections',()=>{
  const app=mount();try{
    const holding=app.heldView.snapshot().holdings[0];assert.ok(holding);
    app.heldView.select(holding);
    const context=app.heldView.compiled(),snapshot=app.heldView.snapshot();
    const input=app.refs['environment-fields'].querySelector('[data-environment-field="appURL"]');assert.ok(input);
    input.value='javascript:alert(1)';
    assert.equal(app.applyEnvironment().ok,false);
    assert.equal(app.heldView.compiled(),context);
    assert.equal(app.heldView.snapshot(),snapshot);
    assert.equal(app.heldView.selection.holdingId,holding.holdingId);
    app.resetEnvironment();assert.equal(app.heldView.selection,null);
    app.heldView.select(app.heldView.snapshot().holdings[0]);
    app.selectLabScenario('lab-ad-first-sign-in',{navigate:false});
    assert.equal(app.heldView.selection,null);
    assert.deepEqual(app.heldView.snapshot().cursor,{eventIndex:-1,milestone:'initial'});
  }finally{unmount(app);}
});

test('compact geometry preserves base centers while routing from actual fixed-CSS actor bounds',()=>{
  const positions={app:{x:170,y:380},browser:{x:440,y:265},realmA:{x:820,y:170}},pairs=[['app','realmA'],['realmA','browser'],['app','app']];
  const compact=compactDockGeometry(positions,pairs,1105);
  assert.ok(compact);assert.equal(compact.mode,'compact');assert.deepEqual(compact.positions,positions);
  for(const [id,b] of Object.entries(compact.actorBounds)){
    assert.ok(Math.abs((b.right-b.left)*compact.scaleX-82)<1e-9);
    assert.ok(Math.abs((b.bottom-b.top)*compact.scaleY-132)<1e-9);
    assert.equal(compact.bounds[id].right-compact.bounds[id].left,164);
    assert.equal(compact.bounds[id].bottom-compact.bounds[id].top,174);
  }
  const endpoint=compact.routes.get('app>app').match(/^M ([\d.-]+) ([\d.-]+)/);
  assert.equal(Number(endpoint[1]),compact.actorBounds.app.left);
  assert.equal(Number(endpoint[2]),positions.app.y);
  const minimum=compactDockGeometry(positions,pairs,960);assert.ok(minimum);
  assert.ok(164*minimum.scaleX>=140&&174*minimum.scaleY>=140,'fixed 140x140 content fits the scaled reserved envelope');
  assert.notEqual(compact.key,minimum.key,'actual transformed port geometry participates in route-cache identity');
  assert.equal(compactDockGeometry(positions,pairs,959),null);
  assert.equal(compactDockGeometry(positions,pairs,1105,1105*730/1120,959),null,'visible CSS viewport also gates compact controls');
  assert.equal(compactDockGeometry({app:{x:170,y:380},realmA:{x:180,y:380}},[['app','realmA']],1105),null,'overlapping reserved envelopes use external fallback');
  assert.equal(compactDockGeometry({app:{x:20,y:380}},[['app','app']],1105),null,'out-of-bounds envelopes cannot be certified');
});

test('compact summary opens the complete owner list and preserves exact selection across mode changes',()=>{
  const f=mountFixture();try{
    control(f.app,'app-r0').focus();control(f.app,'app-r0').click();
    const exactKey=document.activeElement.dataset.heldKey,cursor=f.snapshot.cursor;
    const positions={app:{x:170,y:380},realmA:{x:820,y:170}},pairs=sourceSteps.map(step=>[step.from,step.to]);
    f.app.heldGeometry=compactDockGeometry(positions,pairs,1105);assert.ok(f.app.heldGeometry);
    f.app.refs.graph.dataset.heldGeometry='compact';
    // Explicit boxes exercise target-gate and focus decisions only. Actual
    // CSS sizing, zoom and clipping remain native-browser acceptance.
    f.app.refs.actors.querySelectorAll('[data-actor]').forEach(card=>{card.getBoundingClientRect=()=>({width:82,height:132});});
    f.view.lastKey='';f.view.render();
    assert.equal(document.activeElement.dataset.heldKey,exactKey);
    const summary=f.view.docks.querySelector('[data-held-actor="app"]');assert.ok(summary);
    assert.match(summary.getAttribute('aria-label'),/separate logical-owner inventories/);
    assert.equal(summary.getAttribute('aria-expanded'),'true');
    summary.click();assert.equal(f.view.root.querySelector('[data-holding-id]'),null);
    f.view.docks.querySelector('[data-held-actor="app"]').click();
    assert.ok(control(f.app,'app-r0'));assert.equal(f.view.selection.artifactId,'R0');
    f.app.heldGeometry=null;f.app.refs.graph.dataset.heldGeometry='external';f.view.lastKey='';f.view.render();
    assert.equal(f.view.selection.artifactId,'R0');assert.deepEqual(f.snapshot.cursor,cursor);
  }finally{unmount(f.app);}
});
