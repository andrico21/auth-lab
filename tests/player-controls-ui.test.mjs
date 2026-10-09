import test from 'node:test';
import assert from 'node:assert/strict';
import { installHarness, HarnessEvent } from './dom-harness.mjs';

// These exercise the actual controls and deterministic packet rendering.
// Native range dragging, visual layout and browser keyboard behavior still need
// an actual browser; this harness does not claim to cover those interactions.
const { document, clock } = installHarness();
const { AuthFlowStudio } = await import('../src/app.js');

function mount() { const app = new AuthFlowStudio(); document.body.appendChild(app); app.connectedCallback(); return app; }
function unmount(app) { app.disconnectedCallback(); document.body.removeChild(app); clock.frames.clear(); clock.timers.clear(); }
function input(app, id, value) { const control = app.refs[id]; control.value = value; control.dispatchEvent(new HarnessEvent('input')); }
function finish(app) { clock.until(() => app.player.status !== 'playing'); assert.equal(app.player.status, 'complete'); }
const duration = step => 380 + Math.max(1, step.payload.length) * 1290 + 800;

// Select semantic protocol packets, independently of the app's cached timeline
// offsets. Range granularity is 1/1000, so the middle of a packet is deliberately
// used instead of an exact stage or inter-packet boundary.
function seekPacket(app, step, name) {
  const stages = app.visibleSteps, index = stages.indexOf(step), packet = step.payload.findIndex(field => field.name === name);
  assert.ok(index >= 0 && packet >= 0, 'the intended protocol packet belongs to this study path');
  const elapsed = stages.slice(0, index).reduce((sum, stage) => sum + duration(stage), 0) + 380 + packet * 1290 + 525;
  const total = stages.reduce((sum, stage) => sum + duration(stage), 0);
  input(app, 'seek', String(Math.round(elapsed / total * 1000)));
  assert.equal(app.player.snapshot().step.id, step.id);
  assert.equal(app.player.snapshot().packet.name, name);
  assert.equal(app.refs['packet-name'].textContent, name);
  assert.equal(app.refs.packet.hidden, false);
  assert.ok(app.player.snapshot().progress > .35 && app.player.snapshot().progress < .65, 'the packet is actually midway along the selected connection');
}

test('seek control previews forward and backward RFC packets on their real connections, without running frames', () => {
  const app = mount(); try {
    assert.equal(app.refs.seek.getAttribute('min'), '0');
    assert.equal(app.refs.seek.getAttribute('max'), '1000');
    const token = app.steps.find(step => step.from === 'app' && step.to === 'realmA' && step.payload.some(field => field.name === 'code_verifier'));
    assert.ok(token, 'the normal web login redeems its code with the backend PKCE verifier');
    seekPacket(app, token, 'code_verifier');
    assert.equal(app.player.status, 'paused');
    assert.equal(clock.frames.size, 0);
    assert.ok(app.refs.inspector.textContent.includes(token.title));
    assert.match(app.refs.seek.getAttribute('aria-valuetext'), /Redeem the code from the backend/);
    const laterValue = Number(app.refs.seek.value), laterStep = app.visibleIndex;
    const authorize = app.steps.find(step => step.from === 'browser' && step.to === 'realmA' && step.payload.some(field => field.name === 'code_challenge'));
    seekPacket(app, authorize, 'code_challenge');
    assert.ok(Number(app.refs.seek.value) < laterValue && app.visibleIndex < laterStep);
    assert.equal(app.currentStep.from, 'browser');
    assert.equal(app.currentStep.to, 'realmA');
    assert.ok(!app.currentStep.payload.some(field => field.name === 'code_verifier'), 'backward seeking never inserts the private verifier into the browser authorization request');
    const elapsed = app.player.elapsed;
    clock.advance(2000);
    assert.equal(app.player.elapsed, elapsed);
    assert.equal(clock.frames.size, 0);
  } finally { unmount(app); }
});

test('seek endpoints freeze at the first and last stage, and Reset clears the preview and all progress', () => {
  const app = mount(); try {
    input(app, 'seek', '1000');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.currentStep.id, app.steps.at(-1).id);
    assert.equal(app.refs.seek.value, '1000');
    assert.equal(app.refs.progress.style.width, '100%');
    assert.equal(app.refs.progress.parentElement.getAttribute('aria-valuenow'), '100');
    assert.equal(app.refs.packet.hidden, true);
    assert.equal(clock.frames.size, 0);
    app.refs.play.click();
    assert.equal(app.player.status, 'complete');
    assert.equal(app.refs.seek.value, '1000');
    assert.equal(app.refs.progress.style.width, '100%');
    app.querySelector('#reset').click();
    assert.equal(app.player.status, 'idle');
    assert.equal(app.refs.seek.value, '0');
    assert.equal(app.refs.progress.style.width, '0%');
    assert.equal(app.visibleIndex, 0);
    assert.equal(app.refs.packet.hidden, true);
    input(app, 'seek', '0');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.currentStep.id, app.steps[0].id);
    assert.equal(app.player.elapsed, 0);
    assert.equal(app.refs.packet.hidden, true);
  } finally { unmount(app); }
});

test('Play after seeking resumes the selected packet and plays precisely the remaining complete journey', () => {
  const app = mount(); try {
    const token = app.steps.find(step => step.from === 'app' && step.to === 'realmA' && step.payload.some(field => field.name === 'code_verifier'));
    seekPacket(app, token, 'code_verifier');
    const initial = app.player.elapsed, start = app.visibleIndex, seen = [];
    input(app, 'speed', '4');
    const unsubscribe = app.player.subscribe(event => { if (event.type === 'step') seen.push(event.step.id); });
    app.refs.play.click();
    assert.equal(app.player.status, 'playing');
    clock.frame();
    assert.equal(app.player.elapsed, initial, 'the first frame does not jump away from the inspected packet');
    finish(app); unsubscribe();
    assert.deepEqual(seen, app.steps.slice(start + 1).map(step => step.id), 'the already previewed stage is continued rather than restarted');
    assert.equal(app.refs.seek.value, '1000');
    assert.equal(app.refs.progress.style.width, '100%');
  } finally { unmount(app); }
});

test('attribute timeline seeking stays inside the selected RFC field lifecycle and resumes its remaining moments', () => {
  const app = mount(); try {
    app.selectAttribute('codeVerifier', false);
    const send = app.traceQueue.find(step => step.traceKind === 'send' && step.from === 'app' && step.to === 'realmA');
    assert.ok(send, 'the verifier lifecycle includes its confidential backend token request');
    seekPacket(app, send, 'code_verifier');
    assert.equal(app.attributeSelection, 'codeVerifier');
    assert.equal(app.player.kind, 'attribute');
    assert.deepEqual(app.player.queue.map(step => step.id), app.traceQueue.map(step => step.id));
    assert.ok(app.player.queue.every(step => step.payload.every(field => field.attributeId === 'codeVerifier')), 'other protocol fields stay outside the animated attribute path');
    assert.match(app.refs['seek-position'].textContent, /^Moment /);
    const start = app.traceIndex, seen = [];
    const unsubscribe = app.player.subscribe(event => { if (event.type === 'step') seen.push(event.step.id); });
    input(app, 'speed', '4'); app.refs.play.click(); finish(app); unsubscribe();
    assert.deepEqual(seen, app.traceQueue.slice(start + 1).map(step => step.id));
    assert.equal(app.refs.seek.value, '1000');
    assert.equal(app.attributeSelection, 'codeVerifier');
    app.querySelector('#reset').click();
    assert.equal(app.attributeSelection, 'codeVerifier');
    assert.equal(app.traceIndex, 0);
    assert.equal(app.refs.seek.value, '0');
  } finally { unmount(app); }
});

test('connection replay reports its position within the whole journey, and seeking switches back to that whole journey', () => {
  const app = mount(); try {
    const edge = app.refs.connections.querySelector('[data-pair="browser--realmA"]');
    assert.ok(edge);
    edge.querySelector('.connection-hit').click();
    assert.equal(app.player.kind, 'connection');
    assert.ok(app.player.queue.length < app.steps.length);
    assert.ok(Number(app.refs.seek.value) > 0, 'this link begins after the initial web sign-in stages');
    assert.match(app.refs.seek.getAttribute('aria-valuetext'), /Ask the single realm for sign-in/);
    input(app, 'seek', '850');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.player.kind, 'demo');
    assert.deepEqual(app.player.queue.map(step => step.id), app.steps.map(step => step.id));
    assert.equal(app.refs.seek.value, '850');
    assert.ok(app.visibleIndex > 4, 'the slider can leave the replayed link and inspect a later journey participant');
  } finally { unmount(app); }
});

test('0.01× playback advances slowly, 0 freezes its packet, and main Resume restores the last running speed', () => {
  const app = mount(); try {
    assert.equal(app.refs.speed.getAttribute('min'), '0');
    assert.equal(app.refs.speed.getAttribute('step'), '0.01');
    input(app, 'seek', '100'); input(app, 'speed', '0.01');
    assert.equal(app.refs['speed-label'].textContent, '0.01×');
    app.refs.play.click(); clock.frame();
    const elapsed = app.player.elapsed;
    clock.advance(1000);
    assert.ok(Math.abs(app.player.elapsed - elapsed - 10) < 1e-8, 'one real second advances only ten animation milliseconds');
    input(app, 'speed', '0');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.refs['speed-label'].textContent, 'Stopped');
    const stopped = app.player.elapsed, position = app.refs.seek.value;
    clock.advance(2000);
    assert.equal(app.player.elapsed, stopped);
    assert.equal(app.refs.seek.value, position);
    app.refs.play.click();
    assert.equal(app.player.status, 'playing');
    assert.equal(app.player.speed, .01);
    assert.equal(app.refs.speed.value, '0.01');
    clock.frame();
    assert.equal(app.player.elapsed, stopped);
  } finally { unmount(app); }
});

test('attribute focus Resume at zero speed restores the last running speed without restarting the selected packet', () => {
  const app = mount(); try {
    app.selectAttribute('codeVerifier', false); input(app, 'seek', '500'); input(app, 'speed', '.05');
    app.refs.play.click(); clock.frame(); clock.advance(200);
    input(app, 'speed', '0');
    const elapsed = app.player.elapsed, queue = app.player.queue.map(step => step.id);
    const button = app.refs['attribute-focus'].querySelector('[data-trace-play]');
    assert.equal(button.textContent, 'Resume'); button.click();
    assert.equal(app.player.status, 'playing');
    assert.equal(app.player.speed, .05);
    assert.equal(app.player.elapsed, elapsed);
    assert.deepEqual(app.player.queue.map(step => step.id), queue);
  } finally { unmount(app); }
});

test('inspector Replay complete attribute path restores speed after Stop and starts the entire selected path', () => {
  const app = mount(); try {
    app.selectAttribute('codeVerifier', false); input(app, 'seek', '600'); input(app, 'speed', '.1'); input(app, 'speed', '0');
    const button = app.refs.inspector.querySelector('[data-trace-play]'); assert.ok(button); button.click();
    assert.equal(app.player.status, 'playing');
    assert.equal(app.player.speed, .1);
    assert.equal(app.player.position, 0);
    assert.equal(app.player.elapsed, 0);
    assert.deepEqual(app.player.queue.map(step => step.id), app.traceQueue.map(step => step.id));
  } finally { unmount(app); }
});

test('inspector Replay exchange restores the last non-zero speed and replays only that exchange', () => {
  const app = mount(); try {
    input(app, 'seek', '700'); input(app, 'speed', '.25'); input(app, 'speed', '0');
    const step = app.currentStep, button = app.refs.inspector.querySelector('[data-replay]'); assert.ok(button); button.click();
    assert.equal(app.player.status, 'playing');
    assert.equal(app.player.speed, .25);
    assert.equal(app.player.position, 0);
    assert.equal(app.player.elapsed, 0);
    assert.deepEqual(app.player.queue.map(stage => stage.id), [step.id]);
  } finally { unmount(app); }
});
