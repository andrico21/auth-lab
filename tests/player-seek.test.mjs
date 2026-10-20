import test from 'node:test';
import assert from 'node:assert/strict';
import { FlowPlayer, authoredMessageTiming } from '../src/player.js';

const stageDuration = count => 380 + Math.max(1, count) * 1290 + 800;
const queue = Object.freeze([
  Object.freeze({ id: 'authorize', from: 'browser', to: 'realmA', payload: Object.freeze([{ id: 'clientId', name: 'client_id' }]) }),
  Object.freeze({ id: 'redirect', from: 'realmA', to: 'browser', payload: Object.freeze([{ id: 'code', name: 'code' }, { id: 'state', name: 'state' }]) }),
  Object.freeze({ id: 'token', from: 'app', to: 'realmA', payload: Object.freeze([{ id: 'code', name: 'code' }, { id: 'codeVerifier', name: 'code_verifier' }, { id: 'redirectUri', name: 'redirect_uri' }]) }),
]);

function clockPlayer(options = {}) {
  let time = 0, serial = 0;
  const frames = new Map();
  const player = new FlowPlayer({
    requestFrame(callback) { const id = ++serial; frames.set(id, callback); return id; },
    cancelFrame(id) { frames.delete(id); },
    ...options,
  });
  function frame(delta = 100) {
    time += delta;
    for (const [id, callback] of [...frames]) { frames.delete(id); callback(time); }
  }
  function finish() {
    for (let i = 0; i < 1000 && player.status === 'playing'; i += 1) frame();
    assert.equal(player.status, 'complete');
  }
  return { player, frames, frame, finish };
}

function close(actual, expected) { assert.ok(Math.abs(actual - expected) < 1e-8, `${actual} ~= ${expected}`); }

test('full-queue duration and absolute progress count every payload and retain the existing stage timing', () => {
  const { player } = clockPlayer();
  assert.equal(player.totalDuration(), 0);
  assert.equal(player.totalDuration(queue), 11280);
  assert.equal(player.totalDuration([{ id: 'local', payload: [] }]), stageDuration(1));
  player.seek(queue, .5);
  const snapshot = player.snapshot();
  assert.equal(snapshot.duration, stageDuration(2));
  assert.equal(snapshot.overallDuration, 11280);
  assert.equal(snapshot.overallElapsed, 5640);
  assert.equal(snapshot.stepElapsed, 3170);
  assert.equal(snapshot.elapsed, 3170);
  assert.equal(snapshot.overallProgress, .5);
  assert.equal(snapshot.step.id, 'redirect');
  assert.equal(snapshot.packet.id, 'state');
  assert.equal(snapshot.visible, false, 'this preview is in the final packet gap');
});

test('seeking previews the exact packet position in both directions without scheduling animation', () => {
  const { player, frames } = clockPlayer(), events = [];
  player.subscribe(event => events.push(event));
  const total = player.totalDuration(queue), firstHalf = 380 + 1050 / 2;
  player.seek(queue, firstHalf / total);
  let snapshot = player.snapshot();
  assert.equal(player.status, 'paused');
  assert.equal(frames.size, 0);
  assert.equal(snapshot.step.from, 'browser');
  assert.equal(snapshot.step.to, 'realmA');
  assert.equal(snapshot.packet.id, 'clientId');
  assert.equal(snapshot.visible, true);
  close(snapshot.progress, .5);
  assert.deepEqual(events.map(event => event.type), ['step', 'state', 'frame']);
  player.seek(queue, (stageDuration(1) + 380 + 1050 / 4) / total, 'link');
  snapshot = player.snapshot();
  assert.equal(snapshot.kind, 'link');
  assert.equal(snapshot.step.from, 'realmA');
  assert.equal(snapshot.step.to, 'browser');
  assert.equal(snapshot.packet.id, 'code');
  close(snapshot.progress, .25);
  assert.equal(frames.size, 0);
});

test('seek boundaries select the new stage, include lead and tail, and clamp to a frozen end', () => {
  const { player, frames } = clockPlayer();
  const sameLength = [queue[0], queue[0]];
  player.seek(sameLength, .5);
  assert.equal(player.position, 1);
  assert.equal(player.elapsed, 0);
  assert.equal(player.snapshot().visible, false);
  player.seek(queue, -1);
  assert.equal(player.position, 0);
  assert.equal(player.elapsed, 0);
  assert.equal(player.snapshot().overallProgress, 0);
  assert.equal(player.snapshot().visible, false);
  player.seek(queue, 2);
  const end = player.snapshot();
  assert.equal(end.step.id, 'token');
  assert.equal(end.stepElapsed, stageDuration(3));
  assert.equal(end.overallProgress, 1);
  assert.equal(end.visible, false);
  assert.equal(end.status, 'paused');
  assert.equal(frames.size, 0);
  player.resume();
  assert.equal(player.status, 'complete');
  assert.equal(frames.size, 0);
});

test('seeking during playback cancels the pending frame and resumes from the preview without time jumps', () => {
  const { player, frames, frame } = clockPlayer();
  player.play(queue);
  frame(); frame();
  assert.equal(frames.size, 1);
  player.seek(queue, .7, 'attribute');
  assert.equal(frames.size, 0);
  assert.equal(player.status, 'paused');
  const elapsed = player.elapsed, overallElapsed = player.snapshot().overallElapsed;
  frame(10000);
  assert.equal(player.elapsed, elapsed);
  player.resume();
  assert.equal(frames.size, 1);
  frame(10000);
  assert.equal(player.elapsed, elapsed, 'the first resumed frame only establishes the clock origin');
  frame();
  close(player.elapsed, elapsed + 100);
  close(player.snapshot().overallElapsed, overallElapsed + 100);
  assert.equal(player.kind, 'attribute');
});

test('seeked playback preserves the entire remaining stage order, carry-over time and exact final progress', () => {
  const { player, frame, finish } = clockPlayer(), seen = [], completed = [];
  player.subscribe(event => { if (event.type === 'step') seen.push(event.step.id); if (event.type === 'stepcomplete') completed.push(event.step.id); });
  player.seek(queue, .1);
  const initialOverall = player.snapshot().overallElapsed;
  player.setSpeed(4); player.resume(); frame();
  for (let i = 0; i < 4; i += 1) frame();
  close(player.snapshot().overallElapsed, initialOverall + 1600);
  assert.equal(player.position, 1, 'the clock has crossed the first stage boundary');
  finish();
  assert.deepEqual(seen, queue.map(stage => stage.id));
  assert.deepEqual(completed, queue.map(stage => stage.id));
  assert.equal(player.snapshot().overallProgress, 1);
  assert.equal(player.snapshot().overallElapsed, player.totalDuration());
});

test('0 speed freezes the packet; very slow positive speeds resume only through explicit Play', () => {
  const { player, frames, frame } = clockPlayer();
  player.play(queue); frame(); frame();
  const elapsed = player.elapsed;
  assert.equal(player.setSpeed(0), true);
  assert.equal(player.speed, 0);
  assert.equal(player.status, 'paused');
  assert.equal(frames.size, 0);
  player.resume();
  assert.equal(player.status, 'paused', 'Play at zero speed stays stopped');
  frame(10000);
  assert.equal(player.elapsed, elapsed);
  player.setSpeed(.01);
  assert.equal(player.status, 'paused', 'choosing a positive speed does not unexpectedly resume');
  player.resume(); frame(); frame();
  close(player.elapsed, elapsed + 1);
  player.pause();
  player.setSpeed(.025); player.resume(); frame(); frame();
  close(player.elapsed, elapsed + 3.5);
});

test('starting a fresh queue at zero speed remains paused and does not discard its initial preview', () => {
  const { player, frames } = clockPlayer();
  player.setSpeed(0); player.play(queue, 'link');
  assert.equal(player.status, 'paused');
  assert.equal(player.kind, 'link');
  assert.equal(player.snapshot().step.id, 'authorize');
  assert.equal(frames.size, 0);
  player.setSpeed(.05);
  assert.equal(player.status, 'paused');
  player.resume();
  assert.equal(player.status, 'playing');
  assert.equal(frames.size, 1);
});

test('invalid speed and seek inputs cannot produce NaN state or interrupt an existing queue', () => {
  const { player, frames } = clockPlayer();
  player.play(queue);
  for (const speed of [NaN, Infinity, -Infinity, -1, '', ' ', null, undefined, {}, 'fast']) {
    assert.equal(player.setSpeed(speed), false);
    assert.equal(player.speed, 1);
    assert.equal(player.status, 'playing');
  }
  for (const fraction of [NaN, Infinity, -Infinity, 'middle']) assert.equal(player.seek(queue, fraction), false);
  assert.equal(player.seek(undefined, .5), false);
  assert.equal(player.status, 'playing');
  assert.equal(frames.size, 1);
  player.setSpeed(.0001); assert.equal(player.speed, .01);
  player.setSpeed(100); assert.equal(player.speed, 4);
});

test('queues are shallow copied, source stages remain unchanged, and empty seeking clears playback', () => {
  const { player, frames } = clockPlayer(), copy = queue.slice();
  player.seek(copy, .4, 'attribute');
  copy.pop();
  assert.equal(player.queue.length, 3);
  assert.equal(player.queue[1], queue[1]);
  assert.equal(queue.length, 3);
  assert.equal(queue[1].payload.length, 2);
  player.resume();
  assert.equal(frames.size, 1);
  assert.equal(player.seek([], .5), true);
  assert.equal(player.status, 'idle');
  assert.equal(player.queue.length, 0);
  assert.equal(player.snapshot().overallDuration, 0);
  assert.equal(player.snapshot().overallProgress, 0);
  assert.equal(frames.size, 0);
});

test('authored message bounds contain every field route regardless of payload count or playback speed', () => {
  const plan = { events: { transfer: { messages: [{messageId:'wire',start:.2,end:.63,objects:[{artifactId:'token'}]}] } } };
  for (const count of [0, 1, 6, 29]) for (const speed of [0, .01, .5, 1, 4]) {
    const step = {id:'transfer',payload:Array.from({length:count},(_,index)=>({name:'field-'+index}))};
    const {player, frames} = clockPlayer({getTiming:(row,kind)=>authoredMessageTiming(plan,row,kind)});
    player.setSpeed(speed);
    for (const [fraction, phase] of [[.199999,'pending'],[.2,'in-flight'],[.629999,'in-flight'],[.63,'received'],[.630001,'received'],[.8,'received']]) {
      player.seek([step],fraction);
      const snapshot=player.snapshot();
      assert.equal(snapshot.messagePhase,phase,`count ${count}, speed ${speed}, position ${fraction}`);
      assert.equal(snapshot.visible,phase==='in-flight');
      close(snapshot.messageStart,.2); close(snapshot.messageEnd,.63);
      if(phase==='received'){assert.equal(snapshot.progress,1);assert.equal(snapshot.packetIndex,Math.max(1,count)-1);}
      if(fraction===.629999){assert.equal(snapshot.packetIndex,Math.max(1,count)-1);assert.ok(snapshot.progress>.999);}
    }
    assert.equal(frames.size,0);
  }
});

test('exact replay uses its authored cursor interval and does not replay a previous message during later checks', () => {
  const plan={events:{source:{milestones:[{id:'delayed',at:.25},{id:'received',at:.75},{id:'complete',at:1}],
    messages:[{messageId:'wire',start:0,end:.75,objects:[{artifactId:'token'}]}]}}};
  const row={id:'exact',sourceStepId:'source',artifactId:'token',payload:[{name:'token'}],
    heldCursorStart:{eventIndex:2,milestone:'delayed'},heldCursorEnd:{eventIndex:2,milestone:'received'}};
  const {player}=clockPlayer({getTiming:(step,kind)=>authoredMessageTiming(plan,step,kind)});
  player.seek([row],.999999,'object');
  assert.equal(player.snapshot().messagePhase,'in-flight');
  assert.ok(player.snapshot().progress>.999);
  player.seek([row],1,'object');
  assert.equal(player.snapshot().messagePhase,'received');
  assert.equal(player.snapshot().visible,false);
  assert.equal(player.snapshot().progress,1);
  const check={...row,heldCursorStart:row.heldCursorEnd,heldCursorEnd:{eventIndex:2,milestone:'complete'}};
  player.seek([check],.5,'object');
  assert.equal(player.snapshot().messagePhase,'local');
  assert.equal(player.snapshot().visible,false);
});

test('seek/resume crosses the authored receipt once at slow and fast speeds, including reduced-motion completion', () => {
  const plan={events:{transfer:{messages:[{messageId:'wire',start:0,end:.75,objects:[{artifactId:'token'}]}]}}};
  const step={id:'transfer',payload:Array.from({length:6},(_,index)=>({name:'field-'+index}))};
  for(const speed of [.01,.5,1,4]) {
    const {player,frame}=clockPlayer({getTiming:(row,kind)=>authoredMessageTiming(plan,row,kind)});
    const duration=player.totalDuration([step]);
    player.setSpeed(speed);player.seek([step],(.75*duration-speed*50)/duration);
    assert.equal(player.snapshot().messagePhase,'in-flight');
    player.resume();frame();
    assert.equal(player.snapshot().messagePhase,'in-flight','Resuming establishes origin without advancing.');
    frame();
    assert.equal(player.snapshot().messagePhase,'received');
    assert.equal(player.snapshot().visible,false);
    player.pause();
    player.seek([step],.749999);player.setReducedMotion(true);player.resume();
    assert.equal(player.snapshot().messagePhase,'in-flight');
    player.cancel();player.advanceReducedMotion();
    assert.equal(player.snapshot().messagePhase,'received');
    assert.equal(player.snapshot().progress,1);
    assert.equal(player.snapshot().status,'complete');
  }
});

test('exact message presentation matches the occurrence route and representation rather than an artifact label',()=>{
  const plan={events:{source:{milestones:[{id:'received',at:.75},{id:'complete',at:1}],messages:[
    {messageId:'outer',from:'issuer',to:'client',start:0,end:.5,objects:[{artifactId:'object',representationId:'outer'}]},
    {messageId:'inner',from:'issuer',to:'client',start:.5,end:.75,objects:[{artifactId:'object',representationId:'inner'}]},
    {messageId:'other-owner',from:'client',to:'resource',start:0,end:1,objects:[{artifactId:'object',representationId:'inner'}]},
  ]}}};
  const row={id:'exact',sourceStepId:'source',artifactId:'object',representationId:'inner',from:'issuer',to:'client',payload:[{name:'same name'}],
    heldCursorStart:{eventIndex:0,milestone:'before'},heldCursorEnd:{eventIndex:0,milestone:'received'}};
  const {player}=clockPlayer({getTiming:(step,kind)=>authoredMessageTiming(plan,step,kind)});
  player.seek([row],.5);
  assert.equal(player.snapshot().messageId,'inner');
  assert.equal(player.snapshot().messagePhase,'pending');
  player.seek([row],.9);
  assert.equal(player.snapshot().messageId,'inner');
  assert.equal(player.snapshot().messagePhase,'in-flight');
  player.seek([row],1);
  assert.equal(player.snapshot().messageId,'inner');
  assert.equal(player.snapshot().messagePhase,'received');
  assert.equal(player.snapshot().visible,false);
});

test('connection replay maps its clock into the authored route interval while exact cursor bounds take precedence',()=>{
  const plan={events:{source:{milestones:[{id:'delayed',at:.25},{id:'received',at:.75},{id:'complete',at:1}],messages:[
    {messageId:'wire',from:'issuer',to:'client',start:.2,end:.75,objects:[{artifactId:'token'}]},
    {messageId:'other-route',from:'issuer',to:'resource',start:0,end:1,objects:[{artifactId:'other'}]},
  ]}}};
  const row={id:'source',from:'issuer',to:'client',payload:[{name:'token'}]};
  const {player}=clockPlayer({getTiming:(step,kind)=>authoredMessageTiming(plan,step,kind)});
  player.seek([row],.75,'connection');
  assert.equal(player.snapshot().messagePhase,'in-flight','Connection .75 is not source .75.');
  close(player.snapshot().messageStart,0);close(player.snapshot().messageEnd,1);
  player.seek([row],.999999,'connection');
  assert.equal(player.snapshot().messagePhase,'in-flight');
  player.seek([row],1,'connection');
  assert.equal(player.snapshot().messagePhase,'received');
  assert.equal(player.snapshot().visible,false);
  const full=authoredMessageTiming(plan,row,'demo');
  assert.equal(full.start,0);assert.equal(full.end,1,'Full replay retains the whole authored source interval.');
  const exact={...row,sourceStepId:'source',artifactId:'token',
    heldCursorStart:{eventIndex:0,milestone:'delayed'},heldCursorEnd:{eventIndex:0,milestone:'received'}};
  const interval=authoredMessageTiming(plan,exact,'connection');
  assert.equal(interval.start,.25);
  assert.equal(interval.end,.75);
});
