import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, mount, unmount, steps, button, clock, document, cursor, canonical, at, assertCursor } from './compact-fixture.mjs';
import { compileHeldObjects, projectHeldObjects } from '../src/held-object-state.js';

const partial=(app,index=0,fraction=.2)=>app.player.inspectQueue(steps,{position:index,elapsed:app.player.durationFor(steps[index])*fraction});

test('initial navigation inspects row zero end; Play instead starts row zero without future effects',()=>{
  for(const command of ['next','play']){
    const {app}=fixture();try{
      assertCursor(app,-1,'initial');assert.equal(button(app,'previous').disabled,true);
      assert.equal(button(app,'next').disabled,false);assert.equal(button(app,'play').textContent,'Play');
      button(app,command).focus();button(app,command).click();
      assert.equal(app.player.position,0);
      if(command==='next'){assertCursor(app,0,'complete');assert.equal(app.player.elapsed,app.player.durationFor(steps[0]));assert.equal(app.player.status,'paused');}
      else {assert.equal(app.player.elapsed,0);assert.equal(app.player.status,'playing');assertCursor(app,0,'before');}
      assert.equal(app.heldView.snapshot().authority.length,0);
      assert.equal(document.activeElement,button(app,command));
    }finally{unmount(app);}
  }
});

test('partial row Previous selects preceding end, Next current end, and Resume retains exact queue and elapsed',()=>{
  for(const command of ['previous','next','play']){
    const {app}=fixture();try{
      partial(app,1,.37);const queue=app.player.queue,elapsed=app.player.elapsed;
      assert.equal(button(app,'play').textContent,'Resume');button(app,command).focus();button(app,command).click();
      assert.equal(app.player.queue,queue,'navigation never creates a suffix queue');
      if(command==='previous'){assert.equal(app.player.position,0);assertCursor(app,0,'complete');}
      if(command==='next'){assert.equal(app.player.position,1);assertCursor(app,1,'complete');}
      if(command==='play'){
        assert.equal(app.player.position,1);assert.equal(app.player.elapsed,elapsed);assert.equal(app.player.status,'playing');
        clock.frame();assert.equal(app.player.elapsed,elapsed);clock.frame(25);assert.equal(app.player.elapsed,elapsed+25);
      }else{assert.equal(app.player.status,'paused');assert.equal(clock.frames.size,0);}
      assert.equal(document.activeElement,button(app,command));
    }finally{unmount(app);}
  }
});

test('Previous from the first partial row reaches initial, not first-row completion',()=>{
  const {app}=fixture();try{partial(app);button(app,'previous').click();assertCursor(app,-1,'initial');assert.equal(app.player.elapsed,0);assert.equal(app.player.status,'idle');assert.equal(button(app,'previous').disabled,true);}finally{unmount(app);}
});

test('manual navigation retains usable playback focus when its boundary disables the activating control',()=>{
  for(const [command,start,eventIndex,milestone,label] of [['previous',0,-1,'initial','Play'],['next',1,2,'complete','Replay']]){
    const {app}=fixture();try{
      app.inspectQueueBoundary(start);
      const control=button(app,command);control.focus();control.click();
      assertCursor(app,eventIndex,milestone);
      assert.equal(control.disabled,true);
      assert.equal(document.activeElement,button(app,'play'));
      assert.equal(button(app,'play').disabled,false);
      assert.equal(button(app,'play').textContent,label);
      assert.equal(clock.frames.size,0);
    }finally{unmount(app);}
  }
});

test('completed row Next selects following end while Continue traverses the original queue',()=>{
  for(const command of ['next','play']){
    const {app}=fixture();try{
      app.inspectQueueBoundary(0);const queue=app.player.queue;button(app,command).click();assert.equal(app.player.queue,queue);
      if(command==='next'){assert.equal(app.player.position,1);assertCursor(app,1,'complete');assert.equal(app.player.status,'paused');}
      else {assert.equal(app.player.status,'playing');clock.frame();clock.frame(1);assert.equal(app.player.position,1);assert.equal(app.player.elapsed,1);assertCursor(app,1,'before');}
    }finally{unmount(app);}
  }
});

test('final completed row remains complete until explicit Replay, with Next disabled',()=>{
  const {app}=fixture();try{
    app.inspectQueueBoundary(2);assertCursor(app,2,'complete');assert.equal(button(app,'next').disabled,true);assert.equal(button(app,'play').textContent,'Replay');
    const end=canonical(app);clock.advance(1000);assert.deepEqual(canonical(app),end);assert.equal(app.player.status,'complete');
    button(app,'play').click();assert.equal(app.player.position,0);assert.equal(app.player.elapsed,0);assert.equal(app.player.status,'playing');assertCursor(app,0,'before');
  }finally{unmount(app);}
});

test('playing manual navigation pauses at the current row before choosing its endpoint',()=>{
  const {app}=fixture();try{
    app.playCompact();clock.frame();clock.frame(100);assert.equal(app.player.status,'playing');button(app,'next').click();
    assert.equal(app.player.status,'paused');assertCursor(app,0,'complete');assert.equal(clock.frames.size,0);
  }finally{unmount(app);}
});

test('exact history initial and duplicate source rows use canonical named endpoints, not trace indices',()=>{
  const {app,compiled}=fixture();try{
    app.enterObjectTrace('response');const rows=app.player.queue;
    assert.equal(rows[0].sourceIndex,-1);assert.deepEqual(rows[0].heldCursorEnd,{eventIndex:-1,milestone:'initial'});
    const received=rows.findIndex(row=>row.heldCursorEnd.eventIndex===0&&row.heldCursorEnd.milestone==='received');
    const verified=rows.findIndex(row=>row.heldCursorEnd.eventIndex===0&&row.heldCursorEnd.milestone==='verified');
    assert.ok(received>0);assert.ok(verified>received);assert.equal(rows[received].sourceIndex,rows[verified].sourceIndex);
    for(const index of [0,received,verified]){
      app.inspectQueueBoundary(index);assert.deepEqual(cursor(app),rows[index].heldCursorEnd);
      assert.deepEqual(canonical(app).holdings,projectHeldObjects(compiled,rows[index].heldCursorEnd).holdings);
      assert.equal(app.player.position,index);
      const before=canonical(app);app.returnToJourney();assert.equal(app.player.kind,'demo');assert.equal(app.objectTraceSelection,null);assert.deepEqual(canonical(app),before);
      assert.equal(app.player.position,Math.max(0,before.cursor.eventIndex));
      app.enterObjectTrace('response');
    }
  }finally{unmount(app);}
});

test('connection receipt endpoint and Return to journey leave later local verification and authority pending',()=>{
  const {app,compiled}=fixture();try{
    app.player.inspectQueue([steps[0]],{kind:'connection'});app.inspectQueueBoundary(0);
    assertCursor(app,0,'received');assert.equal(app.compactView.projection.rowComplete,true);assert.equal(app.compactView.projection.sourceComplete,false);
    assert.equal(app.heldView.snapshot().observations.some(item=>item.result==='verified'),false);
    assert.deepEqual(canonical(app).observations,projectHeldObjects(compiled,{eventIndex:0,milestone:'received'}).observations);
    const before=canonical(app);button(app,'return').click();assert.deepEqual(canonical(app),before);assertCursor(app,0,'received');
    assert.equal(app.player.elapsed,app.player.durationFor(steps[0])*.4);assert.equal(app.player.kind,'demo');assert.equal(app.heldView.snapshot().authority.length,0);
  }finally{unmount(app);}
});

test('empty field investigation keeps its prefix, explains the scope and disables all playback navigation',()=>{
  const {app}=fixture();try{
    at(app,0,'received');const before=canonical(app);assert.equal(app.enterFieldTrace('refreshToken'),true);
    assert.equal(app.player.queue.length,0);assert.deepEqual(canonical(app),before);
    for(const action of ['previous','next','play'])assert.equal(button(app,action).disabled,true);
    assert.match(app.querySelector('#compact-result').textContent,/No authored action matches this investigation/);
    assert.match(app.querySelector('#compact-queue').textContent,/No matching rows/);
    app.returnToJourney();assert.deepEqual(canonical(app),before);
  }finally{unmount(app);}
});

test('partial and not-modeled inventories render canonical caveat reasons, never object coercion or false emptiness',()=>{
  const {app}=fixture();try{
    for(const actorId of ['realmA','browser']){
      const coverage=app.heldView.snapshot().coverage.find(item=>item.actorId===actorId),owner=app.querySelector('[data-compact-owner="'+actorId+'"]');
      assert.equal(coverage.status,actorId==='realmA'?'partial':'not-modeled');
      for(const gap of coverage.gaps)assert.ok(owner.textContent.includes(gap.reason),gap.reason);
      assert.doesNotMatch(owner.textContent,/\[object Object\]|Coverage: complete|No currently held objects\./);
    }
    assert.match(app.querySelector('[data-compact-owner="browser"]').textContent,/does not establish an empty inventory/);
  }finally{unmount(app);}
});

test('the actual app canonical plan renders a deliberately declared coverage gap without coercion',()=>{
  const app=mount();try{
    const original=app.heldView.compiled(),record=original.plan.coverage.find(item=>item.actorId==='app');
    assert.ok(record,'the current Basic Keycloak plan declares application coverage');
    const reason='Specific omitted-policy caveat from a source-only consumer fixture.';
    const plan={...original.plan,contextId:original.contextId+':compact-gap-consumer',
      coverage:original.plan.coverage.map(item=>item===record?{...item,status:'partial',gaps:[{reason}]}:item)};
    const compiled=compileHeldObjects(plan,{steps:app.steps});
    app.heldView.compiled=()=>compiled;app.heldView.contextId=compiled.contextId;app.heldView.reset();app.compactView.render('coverage-fixture');
    const coverage=app.heldView.snapshot().coverage.find(item=>item.actorId==='app');
    assert.equal(coverage.status,'partial');assert.deepEqual(coverage.gaps,[{reason}]);
    const owner=app.querySelector('[data-compact-owner="app"]');
    assert.ok(owner.textContent.includes(coverage.gaps[0].reason));assert.doesNotMatch(owner.textContent,/\[object Object\]|Coverage: complete|No currently held objects\./);
  }finally{unmount(app);}
});
