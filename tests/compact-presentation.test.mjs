import test from 'node:test';
import assert from 'node:assert/strict';
import { PresentationPreference, PRESENTATION_PREFERENCE_KEY } from '../src/presentation-preference.js';
import { fixture, mount, unmount, AuthFlowStudio, steps, button, clock, window, document, HarnessEvent, canonical, at } from './compact-fixture.mjs';

for(const stored of ['compact','full'])test('validated stored '+stored+' wins over the opposite viewport',()=>{
  const writes=[],preference=new PresentationPreference({innerWidth:stored==='compact'?1440:390,localStorage:{getItem:key=>{assert.equal(key,PRESENTATION_PREFERENCE_KEY);return stored;},setItem:(...args)=>writes.push(args)}});
  assert.equal(preference.mode,stored);assert.equal(preference.source,'stored');assert.deepEqual(writes,[]);
});
for(const [width,expected]of [[700,'compact'],[701,'full'],[undefined,'full'],[NaN,'full'],[0,'full']])test('automatic initial width '+width+' selects '+expected+' without persistence',()=>{
  const writes=[],preference=new PresentationPreference({innerWidth:width,localStorage:{getItem:()=> 'COMPACT',setItem:(...args)=>writes.push(args)}});
  assert.equal(preference.mode,expected);assert.deepEqual(writes,[]);
});
test('blocked storage getter and writes retain a valid explicit page-memory choice',()=>{
  const host={innerWidth:700,get localStorage(){throw new Error('blocked file storage');}},preference=new PresentationPreference(host);
  assert.equal(preference.mode,'compact');assert.equal(preference.select('full'),'full');assert.equal(preference.source,'explicit-memory');
  host.innerWidth=390;assert.equal(preference.mode,'full');assert.throws(()=>preference.select('auto'),RangeError);assert.equal(preference.mode,'full');
});
test('explicit persistence stores only the enum under its versioned key',()=>{
  const writes=[],preference=new PresentationPreference({innerWidth:390,localStorage:{getItem:()=>null,setItem:(...args)=>writes.push(args)}});
  preference.select('full');preference.select('compact');assert.deepEqual(writes,[[PRESENTATION_PREFERENCE_KEY,'full'],[PRESENTATION_PREFERENCE_KEY,'compact']]);
});
test('resize, orientation and other-tab storage events do not switch or route the active page',()=>{
  const app=mount({storage:{getItem:()=>null,setItem(){throw new Error('blocked');}}}),oldHistory=window.history,historyCalls=[];
  window.history={pushState:(...args)=>historyCalls.push(['push',...args]),replaceState:(...args)=>historyCalls.push(['replace',...args])};try{
    const source=app.scenarioSnapshot(),config=app.protocolConfig(),route=window.location?.hash;
    app.switchPresentation('full');assert.equal(app.presentationSource,'explicit-memory');
    for(const type of ['resize','orientationchange','storage']){window.innerWidth=320;window.dispatchEvent(new HarnessEvent(type,{key:PRESENTATION_PREFERENCE_KEY,newValue:'compact'}));assert.equal(app.presentationMode,'full');}
    app.switchPresentation('compact');button(app,'diagram').click();assert.equal(app.presentationMode,'full');
    assert.equal(app.scenarioSnapshot(),source);assert.deepEqual(app.protocolConfig(),config);assert.equal(window.location?.hash,route);
    assert.deepEqual(historyCalls,[]);
  }finally{unmount(app);if(oldHistory===undefined)delete window.history;else window.history=oldHistory;}
});

function record(app){
  return {canonical:canonical(app),player:app.player.snapshot(),index:app.index,traceIndex:app.traceIndex,initial:app.heldView.initial,selected:app.heldView.selected,
    inspection:structuredClone(app.inspection),selection:structuredClone(app.heldView.selection),actor:app.heldView.actorId,expanded:[...app.heldView.expanded],
    trace:app.traceQueue,field:app.attributeSelection,object:app.objectTraceSelection,query:app.attributeQuery,
    config:app.protocolConfig(),scenario:app.labScenarioId,variant:app.lessonVariant,member:app.lessonSubfixture,provider:app.providerProfileId,
    environment:structuredClone({draft:app.runtimeEnvironment.draft,applied:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision}),
    layouts:structuredClone(app.customLayouts),internals:app.showInternals,detail:app.learningDetail};
}
for(const state of ['initial','playing-partial','receipt','completed-row','final','speed-zero','field','exact','connection'])test('switch preserves exact postpause canonical and queue state: '+state,()=>{
  const {app,compiled}=fixture();try{
    if(state==='playing-partial'){app.playCompact();clock.frame();clock.frame(100);}
    if(state==='receipt')at(app,0,'received');
    if(state==='completed-row')app.inspectQueueBoundary(1);
    if(state==='final')app.inspectQueueBoundary(2);
    if(state==='speed-zero'){at(app,0,'received');app.player.setSpeed(0);}
    if(state==='field'){assert.equal(app.enterFieldTrace('clientIdApp'),true);assert.equal(app.attributeSelection,'clientIdApp');assert.deepEqual(app.player.queue.map(row=>row.sourceIndex),[0]);}
    if(state==='exact')app.enterObjectTrace('response');
    if(state==='connection'){app.player.inspectQueue([steps[0]],{kind:'connection'});app.inspectQueueBoundary(0);}
    app.attributeQuery='retained search';app.catalogQuery='retained catalog';app.learningDetail='fields';app.showInternals=true;
    app.customLayouts[app.layoutKey]={app:{x:170,y:380}};
    const draft=app.runtimeEnvironment.updateDraft({clientID:'unapplied compact draft'});
    const source=app.scenarioSnapshot(),queue=app.player.queue,player=app.player;
    let postpause=null,pauseCalls=0;const originalPause=player.pause;
    player.pause=function(){pauseCalls++;originalPause.call(this);postpause=record(app);};
    const playing=player.status==='playing',before=record(app);
    app.switchPresentation('full');assert.equal(pauseCalls,playing?1:0);
    const expected=playing?postpause:before;assert.deepEqual(record(app),expected,'compare the exact pause callback result, not a prior animation frame');
    assert.equal(app.player,player);assert.equal(app.player.queue,queue);assert.equal(app.scenarioSnapshot(),source);assert.equal(app.heldView.compiled(),compiled);
    app.switchPresentation('compact');assert.deepEqual(record(app),expected);assert.equal(app.player.queue,queue);assert.equal(pauseCalls,playing?1:0);
    assert.equal(app.catalogQuery,'retained catalog');assert.equal(app.runtimeEnvironment.draft,draft);
    if(state==='speed-zero'){assert.equal(player.speed,0);assert.equal(clock.frames.size,0);button(app,'play').click();assert.equal(player.speed,1);assert.equal(player.status,'playing');}
  }finally{unmount(app);}
});

test('named case, nondefault comparison member, provider and environment identities survive both presenters',()=>{
  const app=mount();try{
    app.selectLabScenario('lab-pam01',{variant:'password-change-required'});app.selectLessonSubfixture('change-prelim-failure');
    app.setLearningDetail('crypto');const source=app.scenarioSnapshot(),compiled=app.heldView.compiled(),before=record(app);
    app.switchPresentation('full');app.switchPresentation('compact');
    assert.equal(app.lessonVariant,'password-change-required');assert.equal(app.lessonSubfixture,'change-prelim-failure');assert.equal(app.learningDetail,'crypto');
    assert.equal(app.scenarioSnapshot(),source);assert.equal(app.heldView.compiled(),compiled);assert.deepEqual(record(app),before);
  }finally{unmount(app);}
});

test('previously inspected detached exact history retains safe fields, authority and custody through a switch',()=>{
  const {app}=fixture();try{
    at(app,0,'received');const holding=app.heldView.snapshot().holdings.find(item=>item.holdingId==='app-response');app.heldView.select(holding);
    app.compactView.render('selection');const inspected=structuredClone(app.heldView.inspectionData());
    assert.equal(inspected.fields.some(field=>field.value==='compact-client'),true);
    assert.deepEqual(inspected.fields.find(field=>field.attributeId==='issuerSecret'),{attributeId:'issuerSecret',name:'issuer_private',readable:false,redacted:true});
    assert.equal(inspected.protocolClock,7);assert.equal(inspected.selection.store,'response');assert.equal(inspected.selection.representationId,'plain');
    at(app,1,'complete');const detached=structuredClone(app.heldView.inspectionData());assert.equal(detached.status,'No longer held');
    assert.deepEqual(detached.fields,inspected.fields);assert.deepEqual(detached.observations,inspected.observations);assert.deepEqual(detached.authority,inspected.authority);
    app.switchPresentation('full');app.switchPresentation('compact');assert.deepEqual(app.heldView.inspectionData(),detached);
    assert.equal(app.heldView.selection.holdingId,'app-response');assert.match(app.querySelector('#held-inspector').textContent,/compact-client/);
    assert.doesNotMatch(app.querySelector('#held-inspector').textContent,/issuer-only-value/);
  }finally{unmount(app);}
});

test('cold Compact runs no Full graph work, no observers and only one shared player scheduler',()=>{
  const originals=new Map(),calls=[];const oldObserver=globalThis.ResizeObserver;
  for(const name of ['fullShell','renderFull','renderActors','renderConnections','renderPacket','renderTimeline','renderStepAttributes']){originals.set(name,AuthFlowStudio.prototype[name]);AuthFlowStudio.prototype[name]=function(){calls.push(name);throw new Error('Inactive Full work: '+name);};}
  globalThis.ResizeObserver=class{constructor(){throw new Error('Cold Compact created an observer');}};
  let app;try{
    app=mount();assert.equal(app.querySelector('#graph'),null);assert.equal(app.player.listeners.size,1);app.playCompact();clock.frame();clock.frame(20);
    assert.deepEqual(calls,[]);assert.equal(clock.frames.size,1);assert.equal(app.player.listeners.size,1);
    app.player.pause();assert.equal(clock.frames.size,0);
  }finally{if(app)unmount(app);for(const [name,method]of originals)AuthFlowStudio.prototype[name]=method;if(oldObserver===undefined)delete globalThis.ResizeObserver;else globalThis.ResizeObserver=oldObserver;}
});

test('twenty switches unmount outgoing listeners and observers; disconnect unsubscribes and cancels scheduling',()=>{
  const oldObserver=globalThis.ResizeObserver,live=new Set();globalThis.ResizeObserver=class{constructor(){live.add(this);}observe(){}disconnect(){live.delete(this);}};
  const app=mount();try{
    const shared=app.sharedListeners.length;
    for(let index=0;index<20;index++){
      const root=app.compactView.root;app.switchPresentation('full');assert.equal(app.compactView.listeners.length,0);for(const listeners of root.listeners.values())assert.equal(listeners.size,0);
      const fullListeners=app.fullView.listeners.length;assert.ok(fullListeners>0);app.switchPresentation('compact');assert.equal(app.fullView.listeners.length,0);assert.equal(live.size,0);
      assert.equal(app.sharedListeners.length,shared);assert.equal(app.player.listeners.size,1);assert.equal(clock.frames.size,0);
    }
    app.playCompact();assert.equal(clock.frames.size,1);app.disconnectedCallback();assert.equal(app.player.listeners.size,0);assert.equal(app.sharedListeners.length,0);assert.equal(app.compactView.listeners.length,0);assert.equal(clock.frames.size,0);assert.equal(live.size,0);
  }finally{unmount(app);if(oldObserver===undefined)delete globalThis.ResizeObserver;else globalThis.ResizeObserver=oldObserver;}
});

test('reduced motion remains shared after Full unmount and removes its media listener on disconnect',()=>{
  const oldMatch=window.matchMedia,listeners=new Set(),media={matches:false,addEventListener(type,fn){if(type==='change')listeners.add(fn);},removeEventListener(type,fn){if(type==='change')listeners.delete(fn);}};
  window.matchMedia=()=>media;const {app}=fixture({mode:'full'});try{
    app.switchPresentation('compact');assert.equal(listeners.size,1);app.playCompact();media.matches=true;for(const listener of listeners)listener();
    assert.equal(app.player.reducedMotion,true);assert.equal(clock.frames.size,0);assert.notEqual(app.player.timer,null);
    clock.advance(600);assert.equal(app.player.position,1);assert.equal(app.player.status,'playing');
    app.disconnectedCallback();assert.equal(listeners.size,0);assert.equal(app.player.timer,null);
  }finally{unmount(app);window.matchMedia=oldMatch;}
});

test('manual controls retain focus and animation frames retain the reader and focused disclosure summary',()=>{
  const {app}=fixture();try{
    const root=app.compactView.root,title=app.querySelector('#compact-current-title'),summary=app.querySelector('[data-compact-disclosure="data"] summary');
    button(app,'next').focus();button(app,'next').click();assert.equal(document.activeElement,button(app,'next'));
    button(app,'next').click();
    button(app,'previous').focus();button(app,'previous').click();assert.equal(document.activeElement,button(app,'previous'));
    summary.focus();app.playCompact();clock.frame();clock.frame(20);clock.frame(20);
    assert.equal(document.activeElement,summary);assert.equal(app.compactView.root,root);assert.equal(app.querySelector('#compact-current-title'),title);
    assert.equal(app.querySelector('[data-compact-disclosure="data"] summary'),summary);assert.deepEqual(root.scrollCalls,[]);
  }finally{unmount(app);}
});

test('applied runtime context and a different unfinished draft keep their exact revision and values across switches',()=>{
  const app=mount();try{
    app.runtimeEnvironment.updateDraft({appURL:'https://compact-applied.example.test',clientID:'compact-applied-client'});
    const result=app.runtimeEnvironment.apply(app.environmentOptions);assert.equal(result.ok,true);
    app.refreshConfiguration();
    const applied=app.runtimeEnvironment.applied,revision=app.runtimeEnvironment.revision;
    const draft=app.runtimeEnvironment.updateDraft({appURL:'https://compact-unapplied.example.test',clientID:'unfinished-client'});
    const source=app.scenarioSnapshot(),compiled=app.heldView.compiled(),before=canonical(app);
    app.switchPresentation('full');app.switchPresentation('compact');
    assert.equal(app.runtimeEnvironment.applied,applied);assert.equal(app.runtimeEnvironment.draft,draft);assert.equal(app.runtimeEnvironment.revision,revision);
    assert.equal(app.runtimeEnvironment.applied.appURL,'https://compact-applied.example.test');assert.equal(app.runtimeEnvironment.draft.appURL,'https://compact-unapplied.example.test');
    assert.equal(app.scenarioSnapshot(),source);assert.equal(app.heldView.compiled(),compiled);assert.deepEqual(canonical(app),before);
    assert.ok(app.querySelector('#compact-configuration').textContent.includes('https://compact-unapplied.example.test'));
  }finally{unmount(app);}
});
