import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers';
import {gzipSync,gunzipSync} from 'node:zlib';
import {DecompressionStream as NativeDecompressionStream,TransformStream} from 'node:stream/web';
import {installHarness,HarnessElement,HarnessEvent} from './dom-harness.mjs';

// These are consumer regressions, not a linguistic review or a browser-support
// certification. Both programs load current generated resources. The emitted
// program is the exact single inline script, without rewriting or rebuilding it.
const bundle=process.env.LOCALIZATION_RECOVERY_BUNDLE||new URL('../dist/auth-flow-studio.html',import.meta.url);
const preferenceKey='auth-flow-studio.locale.v1';
const nativeResponse=globalThis.Response;
const globalKeys=['HTMLElement','customElements','document','window','matchMedia','requestAnimationFrame','cancelAnimationFrame','setTimeout','clearTimeout','atob','btoa','TextEncoder','TextDecoder','URL','URLSearchParams','DecompressionStream','fetch'];
const descriptors=()=>new Map(globalKeys.map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)]));
function restore(saved){for(const [key,descriptor]of saved)if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}

// Reuse the Compact suite's canonical held-state projection and already-loaded
// source component. Its module installs the shared harness, so restore that
// installation immediately; each case owns and restores its own environment.
const beforeFixture=descriptors();
let SourceComponent,canonical;
try{({AuthFlowStudio:SourceComponent,canonical}=await import('./compact-fixture.mjs'));}finally{restore(beforeFixture);}

const pack=value=>'gzip:'+gzipSync(typeof value==='string'?value:JSON.stringify(value)).toString('base64');
const unpack=value=>JSON.parse(gunzipSync(Buffer.from(value.slice(5),'base64')).toString());
const turn=()=>new Promise(resolve=>nextTurn(resolve));
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};

async function withApp(loading,options={},exercise){
  const {savedLocale='en'}=options,capability=Object.hasOwn(options,'capability')?options.capability:NativeDecompressionStream;
  const saved=descriptors(),replaceChild=Object.getOwnPropertyDescriptor(HarnessElement.prototype,'replaceChild');
  const unhandled=[],network=[],releases=[],writes=[];
  const onUnhandled=reason=>unhandled.push(reason);
  process.on('unhandledRejection',onUnhandled);
  let app,harness,target;
  try{
    // DOM bookkeeping missing from the shared offline harness, not a replacement
    // runtime/harness or a claim about native focus/accessibility behavior.
    Object.defineProperty(HarnessElement.prototype,'replaceChild',{configurable:true,writable:true,value(next,old){this.insertBefore(next,old);this.removeChild(old);return old;}});
    target=loading==='source'?globalThis:{structuredClone,Response:nativeResponse,ReadableStream,Uint8Array};
    harness=installHarness(target);
    target.DecompressionStream=capability;
    target.fetch=(...args)=>{network.push(args);throw new Error('Offline locale recovery attempted a network request.');};
    const {document,window,registry}=harness;
    window.innerWidth=390;
    window.localStorage={getItem:key=>key===preferenceKey?savedLocale:key==='auth-flow-studio.presentation.v1'?'compact':null,setItem:(key,value)=>writes.push([key,value])};
    let Component=SourceComponent;
    if(loading==='emitted'){
      const scripts=[...fs.readFileSync(bundle,'utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
      assert.equal(scripts.length,1,'The exact built standalone has one inline program');
      new vm.Script(scripts[0][1],{filename:'localization-recovery:exact-built-inline'}).runInContext(vm.createContext(target),{timeout:5000});
      Component=registry.get('auth-flow-studio');
    }else assert.equal(loading,'source');
    app=new Component();
    Object.defineProperty(app,'isConnected',{get:()=>document.body.contains(app)});
    app.addEventListener('focusin',event=>{document.activeElement=event.target;});
    document.activeElement=document.body;document.body.appendChild(app);
    await app.connectedCallback();
    const mounted={...harness,app,target,writes,releases};
    await exercise(mounted);
    // A real event-loop boundary, not a timed race that can miss a late rejected
    // promise. Deliberate failures must be consumed by the actual UI handlers.
    await turn();
    assert.deepEqual(unhandled,[],'Startup and selection do not leak rejected promises');
    assert.deepEqual(network,[],'Failure and retry remain offline');
  }finally{
    // Resolve deferred stream work before restoring globals or advancing to the
    // next test, including when an intermediate assertion has failed.
    for(const release of releases)release();
    if(app?.initializingLocale)await app.initializingLocale.catch(()=>{});
    if(app?.localePreparation)await app.localePreparation.catch(()=>{});
    if(app?.localizer?.englishPreparation)await app.localizer.englishPreparation.catch(()=>{});
    if(app?.initialized)app.disconnectedCallback();
    if(app?.parentElement)app.parentElement.removeChild(app);
    harness?.clock.frames.clear();harness?.clock.timers.clear();
    await turn();
    process.removeListener('unhandledRejection',onUnhandled);
    if(replaceChild)Object.defineProperty(HarnessElement.prototype,'replaceChild',replaceChild);else delete HarnessElement.prototype.replaceChild;
    restore(saved);
  }
}

// All locale requests enter through the mounted selector's actual change
// listener. Await its live preparation job rather than calling the controller
// directly (the listener intentionally does not return its result).
function choose({app},tag){
  const selector=app.refs['language-select'];
  assert.equal(selector.disabled,false,'Recovery language selector stays usable');
  selector.value=tag;selector.dispatchEvent(new HarnessEvent('change',{bubbles:true}));
  return app.localePreparation||Promise.resolve(false);
}
function settled(app){
  assert.equal(app.hasAttribute('aria-busy'),false);
  assert.equal(app.localePreparation,null);
  assert.equal(app.pendingLocale,null);
  assert.equal(app.localizer.prepared,null);
  assert.equal(app.localizer.englishPreparation,null);
  assert.equal(app.localizer.initialPreparation,null);
  assert.equal(app.refs['language-select'].value,app.localizer.locale);
}
function failureStatus(mounted,tag,active){
  const {app,clock}=mounted,toast=app.refs.toast;
  assert.equal(app.localizer.locale,active,'A failure never activates a partial locale');
  assert.equal(app.localeFailure.tag,tag);
  assert.equal(typeof app.localeFailure.error?.message,'string');
  assert.equal(toast.hidden,false);
  assert.equal(toast.getAttribute('role'),'status');
  assert.equal(toast.getAttribute('lang'),'en','Recovery announcement is explicitly English');
  assert.equal(toast.getAttribute('dir'),'ltr','Recovery announcement is not inherited RTL');
  assert.equal(toast.hasAttribute('data-locale-failure'),true);
  assert.match(toast.textContent,/\b(?:could not|unable|failed|failure|unavailable|error)\b/iu,'The status conveys failure, without pinning its exact prose');
  assert.match(toast.textContent,/\b(?:retry|another|choose|try)\b/iu,'The status offers a recovery action');
  assert.ok(toast.textContent.includes(app.localizer.constructor.metadata(tag).name),'The failed language is identified');
  assert.ok(toast.textContent.includes(app.localizer.constructor.metadata(active).name),'The retained language is identified');
  assert.equal(app.toastTimer,null,'Locale failure status is persistent');
  const text=toast.textContent;
  clock.advance(6000);
  assert.equal(toast.hidden,false,'The normal five-second toast expiry cannot hide failure');
  assert.equal(toast.textContent,text);
  settled(app);
}
function englishStartup(mounted){
  const {app}=mounted,selector=app.refs['language-select'];
  assert.equal(app.initialized,true,'Saved-locale failure still boots the application');
  assert.equal(app.localizer.locale,'en');
  assert.equal(app.getAttribute('lang'),'en');
  assert.equal(app.refs.studio.getAttribute('lang'),'en');
  assert.equal(app.localizer.initialFailure,null,'Startup reports and consumes its recorded failure');
  assert.equal(app.initializingLocale??null,null);
  assert.equal(selector.value,'en');assert.equal(selector.disabled,false);
  const label=app.querySelector('#'+selector.getAttribute('aria-labelledby'));
  assert.equal(label.textContent,'Language','The actual selector has an English accessible label');
  assert.equal(selector.querySelector('option[value="en"]').textContent,'English');
  assert.ok(selector.querySelector('option[value="ru"]'),'The failed language remains retryable');
  app.querySelector('[data-presentation-choice="full"]').click();
  assert.equal(app.presentationMode,'full','English startup has a functioning non-language control');
  app.querySelector('[data-presentation-choice="compact"]').click();
  assert.equal(app.presentationMode,'compact');
}
function pausedLesson(mounted){
  const {app}=mounted;
  app.selectLabScenario('web-mfa',{navigate:false});
  assert.equal(app.labScenarioId,'web-mfa');
  assert.equal(app.enterFieldTrace('clientIdApp'),true);
  assert.ok(app.traceQueue.length>0,'The actual selected lesson supplies a field trace');
  app.inspectQueueBoundary(0,'end');
  assert.equal(app.player.status,'paused');
  assert.equal(app.player.kind,'attribute');
  return record(app);
}
function record(app){
  return {
    state:JSON.stringify({held:canonical(app),player:app.player.snapshot(),scenario:app.labScenarioId,variant:app.lessonVariant,member:app.lessonSubfixture,index:app.index,traceIndex:app.traceIndex,field:app.attributeSelection,object:app.objectTraceSelection,inspection:app.inspection,selection:app.heldView.selection,actor:app.heldView.actorId,expanded:[...app.heldView.expanded],initial:app.heldView.initial,selected:app.heldView.selected,config:app.protocolConfig()}),
    player:app.player,queue:app.player.queue,trace:app.traceQueue,source:app.scenarioSnapshot(),compiled:app.heldView.compiled(),
    selector:app.refs['language-select'],presenter:app.presenter,presentation:app.querySelector('#presentation-host').children[0],catalog:app.localizer.catalog,
  };
}
function preserved(app,before,{failed=false}={}){
  const after=record(app);
  assert.equal(after.state,before.state,'Exact paused player and held-state snapshots survive the request');
  for(const key of ['player','queue','trace','source','compiled'])assert.equal(after[key],before[key],key+' identity is not rebuilt by locale recovery');
  if(failed)for(const key of ['selector','presenter','presentation','catalog'])assert.equal(after[key],before[key],key+' remains mounted on failed activation');
}
function recovered(app,tag){
  assert.equal(app.localizer.locale,tag);
  assert.equal(app.localizer.catalog.locale,tag,'A real generated native catalog is active, not English-only pretend success');
  assert.equal(app.localeFailure??null,null);
  assert.equal(app.refs.toast.hasAttribute('data-locale-failure'),false,'Success removes the old persistent failure marker');
  settled(app);
}
function deferFirstDecode(mounted){
  const entered=deferred(),release=deferred(),error=new Error('Controlled late gzip stream rejection');
  let constructors=0;
  mounted.releases.push(()=>release.resolve());
  mounted.target.DecompressionStream=class {
    constructor(format){
      constructors++;
      if(constructors!==1)return new NativeDecompressionStream(format);
      entered.resolve();
      return new TransformStream({async transform(_chunk,controller){await release.promise;controller.error(error);}});
    }
  };
  return {entered:entered.promise,release:()=>release.resolve(),error,count:()=>constructors};
}

for(const loading of ['source','emitted']){
  for(const startupFault of ['missing API','throwing constructor'])test(loading+' saved ru startup recovers from '+startupFault+' and supports a real retry',async()=>{
    const error=new Error('Authored unavailable gzip constructor');
    const capability=startupFault==='missing API'?undefined:class {constructor(){throw error;}};
    await withApp(loading,{savedLocale:'ru',capability},async mounted=>{
      failureStatus(mounted,'ru','en');englishStartup(mounted);
      if(startupFault==='throwing constructor')assert.equal(mounted.app.localeFailure.error,error);
      assert.deepEqual(mounted.writes.filter(([key])=>key===preferenceKey),[],'Failed startup does not overwrite the saved preference');
      const before=pausedLesson(mounted);
      await choose(mounted,'ru');failureStatus(mounted,'ru','en');preserved(mounted.app,before,{failed:true});
      mounted.target.DecompressionStream=NativeDecompressionStream;
      await choose(mounted,'ru');recovered(mounted.app,'ru');preserved(mounted.app,before);
      assert.equal(mounted.writes.filter(([key])=>key===preferenceKey).at(-1)?.[1],'ru');
    });
  });

  test(loading+' a failed explicit change retains the exact synchronous postpause prefix of active playback',async()=>{
    await withApp(loading,{},async mounted=>{
      const {app,clock,target}=mounted;
      pausedLesson(mounted);app.inspectQueueBoundary(0,'start');
      app.querySelector('[data-compact-action="play"]').click();
      clock.frame();clock.frame(100);
      assert.equal(app.player.status,'playing');
      const queue=app.player.queue,trace=app.traceQueue,pause=app.player.pause;
      let postpause=null,pauses=0;
      app.player.pause=function(...args){pauses++;const result=pause.apply(this,args);postpause=record(app);return result;};
      try{
        target.DecompressionStream=undefined;
        await choose(mounted,'ru');
        assert.equal(pauses,1,'The consumer establishes its paused prefix before decoding');
        assert.equal(app.player.status,'paused');
        assert.equal(app.player.queue,queue);assert.equal(app.traceQueue,trace);
        failureStatus(mounted,'ru','en');preserved(app,postpause,{failed:true});
        assert.equal(clock.frames.size,0,'Failure does not leave playback scheduled');
      }finally{app.player.pause=pause;}
    });
  });

  for(const kind of ['missing API','constructor rejection','stream decode rejection','invalid catalog JSON','invalid catalog table'])test(loading+' explicit '+kind+' preserves a selected native lesson and exact paused trace',async()=>{
    await withApp(loading,{},async mounted=>{
      const {app,target}=mounted;
      await choose(mounted,'he');recovered(app,'he');
      const before=pausedLesson(mounted),original=app.localizer.resources;
      const error=new Error('Authored explicit gzip constructor rejection');
      let decoders=0;
      if(kind==='missing API')target.DecompressionStream=undefined;
      else if(kind==='constructor rejection')target.DecompressionStream=class {constructor(){throw error;}};
      else{
        target.DecompressionStream=class {constructor(format){decoders++;return new NativeDecompressionStream(format);}};
        const table=unpack(original.ru);
        if(kind==='invalid catalog table')table.bindings[0]=table.messages.length;
        const resource=kind==='stream decode rejection'?'gzip:'+Buffer.from('This is deliberately not a gzip stream.').toString('base64'):kind==='invalid catalog JSON'?pack('{"locale":"ru",'):pack(table);
        app.localizer.resources={...original,ru:resource};
      }
      await choose(mounted,'ru');failureStatus(mounted,'ru','he');preserved(app,before,{failed:true});
      if(kind==='constructor rejection')assert.equal(app.localeFailure.error,error);
      if(kind==='invalid catalog JSON')assert.equal(app.localeFailure.error.name,'SyntaxError');
      if(kind==='invalid catalog table')assert.equal(app.localeFailure.error.name,'RangeError','The table index validator, not an absent API, rejects the resource');
      if(!['missing API','constructor rejection'].includes(kind))assert.equal(decoders,1,'The selected stream actually reaches decoding');
      // A newer independent notification must no longer carry a locale-failure
      // tag. Canceling with the current language must not hide that notification.
      const notification='A separate study notification remains available.';
      app.showToast(notification,'en');const timer=app.toastTimer;
      assert.equal(app.refs.toast.hasAttribute('data-locale-failure'),false);
      await choose(mounted,'he');
      assert.equal(app.refs.toast.textContent,notification);assert.equal(app.refs.toast.hidden,false);
      assert.equal(app.toastTimer,timer);assert.equal(app.localeFailure,null);settled(app);
      preserved(app,before,{failed:true});
    });
  });

  for(const latest of ['fr','en'])test(loading+' a late stream failure cannot override the latest '+latest+' selector intent',async()=>{
    await withApp(loading,{},async mounted=>{
      const {app}=mounted;
      // Warm the actual source table first so only the requested real ru catalog
      // is gated. The deferred stream is the only controlled async test double.
      await choose(mounted,'ru');recovered(app,'ru');await choose(mounted,'en');
      const before=pausedLesson(mounted),gate=deferFirstDecode(mounted);
      const first=choose(mounted,'ru');assert.equal(app.getAttribute('aria-busy'),'true');
      await gate.entered;
      const notification='An unrelated notification arrived during language preparation.';
      app.showToast(notification,'en');
      const last=choose(mounted,latest);assert.equal(last,first,'Rapid changes share the one preparation worker');
      gate.release();await last;
      if(latest==='fr')recovered(app,'fr');else{
        assert.equal(app.localizer.locale,'en');assert.equal(app.localeFailure??null,null);settled(app);
        assert.equal(app.refs.toast.textContent,notification,'A stale failure and English cancellation leave the newer notification untouched');
        assert.equal(app.refs.toast.hidden,false);
      }
      assert.equal(app.refs.toast.hasAttribute('data-locale-failure'),false);
      assert.equal(gate.count(),latest==='fr'?2:1,'Only the failed request and final native intent are decoded');
      preserved(app,before,{failed:latest==='en'});
    });
  });

  test(loading+' repeated requests settle once, remain retryable and clear the old accessible failure after capability restoration',async()=>{
    await withApp(loading,{},async mounted=>{
      const {app}=mounted;
      await choose(mounted,'ru');await choose(mounted,'en');
      const before=pausedLesson(mounted),gate=deferFirstDecode(mounted);
      const first=choose(mounted,'ru');await gate.entered;
      assert.equal(choose(mounted,'ru'),first);assert.equal(choose(mounted,'ru'),first);
      gate.release();await first;
      assert.equal(gate.count(),1,'Repeated pending intent does not launch duplicate decompression');
      assert.equal(app.localeFailure.error,gate.error);
      failureStatus(mounted,'ru','en');preserved(app,before,{failed:true});
      mounted.target.DecompressionStream=NativeDecompressionStream;
      await choose(mounted,'ru');recovered(app,'ru');preserved(app,before);
      const success=app.refs.toast.textContent;
      mounted.clock.advance(6000);
      assert.equal(app.refs.toast.hidden,true,'Recovered ordinary notifications are no longer persistent failure status');
      assert.equal(app.refs.toast.textContent,success);
      assert.equal(app.refs.toast.hasAttribute('data-locale-failure'),false);
    });
  });
}
