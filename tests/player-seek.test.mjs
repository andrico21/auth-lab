import test from 'node:test';
import assert from 'node:assert/strict';
import { FlowPlayer } from '../src/player.js';

const stageDuration = count => 380 + Math.max(1, count) * 1290 + 800;
const queue = Object.freeze([
  Object.freeze({ id: 'authorize', from: 'browser', to: 'realmA', payload: Object.freeze([{ id: 'clientId', name: 'client_id' }]) }),
  Object.freeze({ id: 'redirect', from: 'realmA', to: 'browser', payload: Object.freeze([{ id: 'code', name: 'code' }, { id: 'state', name: 'state' }]) }),
  Object.freeze({ id: 'token', from: 'app', to: 'realmA', payload: Object.freeze([{ id: 'code', name: 'code' }, { id: 'codeVerifier', name: 'code_verifier' }, { id: 'redirectUri', name: 'redirect_uri' }]) }),
]);

function clockPlayer() {
  let time = 0, serial = 0;
  const frames = new Map();
  const player = new FlowPlayer({
    requestFrame(callback) { const id = ++serial; frames.set(id, callback); return id; },
    cancelFrame(id) { frames.delete(id); },
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
