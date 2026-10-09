import test from 'node:test';
import assert from 'node:assert/strict';
import { installHarness, HarnessEvent } from './dom-harness.mjs';

// Exact reviewer reproductions at the application's click/key/frame boundary.
// This harness checks packet/state identity, not native browser painting.
const { document, clock } = installHarness();
const { AuthFlowStudio } = await import('../src/app.js');
const { pairKey } = await import('../src/player.js');

function mount() { const app = new AuthFlowStudio(); document.body.appendChild(app); app.connectedCallback(); return app; }
function unmount(app) { app.disconnectedCallback(); document.body.removeChild(app); clock.frames.clear(); clock.timers.clear(); }
function input(app, id, value) { app.refs[id].value = value; app.refs[id].dispatchEvent(new HarnessEvent('input')); }
function finish(app) { clock.until(() => app.player.status !== 'playing'); assert.equal(app.player.status, 'complete'); }
function stoppedVerifier(app) {
  input(app, 'seek', '108');
  assert.equal(app.player.status, 'paused');
  assert.equal(app.refs.packet.hidden, false);
  assert.equal(app.refs['packet-name'].textContent, 'code_verifier');
  input(app, 'speed', '.37'); input(app, 'speed', '0');
  assert.equal(app.player.speed, 0);
  assert.equal(clock.frames.size, 0);
}
function assertNewReplay(app) {
  assert.equal(app.player.speed, .37, 'explicit replay restores the last positive speed');
  assert.equal(app.player.status, 'playing');
  assert.equal(app.player.elapsed, 0);
  assert.equal(app.refs.packet.hidden, true, 'the previous packet is hidden immediately during the new stage lead-in');
  assert.equal(clock.frames.size, 1);
}

for (const action of ['click', 'Enter', 'Space']) test(`R8: connection ${action} Replay at zero speed removes the old private-verifier packet and starts its own request`, () => {
  const app = mount(); try {
    stoppedVerifier(app);
    const target = app.refs.connections.querySelector('[data-pair="browser--realmA"] .connection-hit');
    assert.match(target.getAttribute('aria-label'), /^Replay /);
    if (action === 'click') target.click();
    else { target.focus(); target.dispatchEvent(new HarnessEvent('keydown', { key: action === 'Space' ? ' ' : action })); }
    assertNewReplay(app);
    assert.equal(app.player.kind, 'connection');
    assert.equal(app.currentStep.id, 'single-web-password-l04');
    assert.equal(app.currentStep.from, 'browser');
    assert.equal(app.currentStep.to, 'realmA');
    assert.equal(app.refs['packet-name'].textContent, 'HTTP', 'packet state belongs to the replacement queue before any clock callback');
    assert.ok(!app.currentStep.payload.some(field => field.name === 'code_verifier'));
    clock.frame(); clock.advance(1400);
    assert.equal(app.refs.packet.hidden, false);
    assert.equal(app.refs['packet-name'].textContent, 'HTTP');
    assert.ok(app.player.elapsed > 380);
  } finally { unmount(app); }
});

test('R8: intentionally paused queue replacement synchronizes its packet immediately without restoring speed', () => {
  const app = mount(); try {
    stoppedVerifier(app);
    const authorize = app.steps.find(step => step.id === 'single-web-password-l04');
    app.player.play([authorize], 'step');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.player.speed, 0);
    assert.equal(app.currentStep.id, authorize.id);
    assert.equal(app.refs.packet.hidden, true);
    assert.equal(app.refs['packet-name'].textContent, 'HTTP');
    assert.equal(clock.frames.size, 0);
    clock.advance(2000);
    assert.equal(app.player.elapsed, 0);
    assert.equal(app.refs.packet.hidden, true);
    input(app, 'speed', '.01');
    assert.equal(app.player.status, 'paused', 'a positive speed setting alone is still not a Play action');
    assert.equal(clock.frames.size, 0);
  } finally { unmount(app); }
});

for (const action of ['next', 'timeline', 'attribute']) test(`R8: explicit ${action} activation replays after Stop while a deliberate seek remains paused`, () => {
  const app = mount(); try {
    stoppedVerifier(app);
    if (action === 'next') app.querySelector('#next').click();
    if (action === 'timeline') app.refs.timeline.querySelector('[data-step="1"]').click();
    if (action === 'attribute') app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]').click();
    assertNewReplay(app);
    if (action === 'attribute') {
      assert.equal(app.attributeSelection, 'codeVerifier');
      assert.equal(app.player.kind, 'attribute');
      assert.deepEqual(app.player.queue.map(step => step.id), app.traceQueue.map(step => step.id));
    } else {
      assert.equal(app.player.kind, 'step');
      assert.equal(app.player.queue.length, 1);
    }
    input(app, 'seek', '500');
    assert.equal(app.player.status, 'paused');
    assert.equal(app.player.speed, .37);
    assert.equal(clock.frames.size, 0);
    const elapsed = app.player.elapsed;
    clock.advance(1000);
    assert.equal(app.player.elapsed, elapsed);
  } finally { unmount(app); }
});

test('non-animated step selection retains a stopped speed and does not start a replay', () => {
  const app = mount(); try {
    stoppedVerifier(app); app.selectStep(1, false);
    assert.equal(app.player.speed, 0);
    assert.equal(app.player.status, 'idle');
    assert.equal(app.refs.packet.hidden, true);
    assert.equal(clock.frames.size, 0);
  } finally { unmount(app); }
});

function visitedState(app) {
  return {
    visited: [...app.visited].sort(),
    styled: app.refs.connections.querySelectorAll('[data-pair]').filter(edge => edge.classList.contains('is-visited')).map(edge => edge.dataset.pair).sort(),
    step: app.currentStep.id,
    progress: app.refs.progress.style.width,
    range: app.refs.seek.value,
  };
}

for (const scenario of ['lab-token-revocation', 'lab-frontchannel-logout', 'lab-mtls', 'lab-jwt-grant', 'lab-exchange-delegation', 'lab-saml-metadata', 'lab-concurrent-sessions']) test(`L1: ${scenario} end-seek and Play preserve all naturally completed links including the terminal exchange`, () => {
  const app = mount(); try {
    app.selectLabScenario(scenario); assert.equal(app.labScenarioId, scenario); input(app, 'speed', '4'); app.refs.play.click(); finish(app);
    const natural = visitedState(app), last = app.steps.at(-1), finalPair = pairKey(app.nodeId(last.from), app.nodeId(last.to));
    assert.ok(app.visited.has(finalPair));
    app.querySelector('#reset').click(); input(app, 'seek', '999');
    assert.equal(app.currentStep.id, last.id);
    assert.ok(!app.visited.has(finalPair), 'the nearly complete terminal stage is not marked complete prematurely');
    input(app, 'seek', '1000');
    assert.equal(app.player.status, 'paused');
    assert.ok(app.visited.has(finalPair), '100% represents a fully elapsed terminal stage');
    assert.deepEqual(visitedState(app), natural);
    app.refs.play.click();
    assert.equal(app.player.status, 'complete');
    assert.deepEqual(visitedState(app), natural);
  } finally { unmount(app); }
});

test('L1: code_verifier focused end-seek and Play preserve terminal local verification and natural completion styling', () => {
  const app = mount(); try {
    app.selectAttribute('codeVerifier', false); input(app, 'speed', '4'); app.refs.play.click(); finish(app);
    const natural = visitedState(app), last = app.traceQueue.at(-1);
    assert.equal(last.traceKind, 'verify');
    assert.equal(last.from, 'realmA');
    assert.equal(last.to, 'realmA');
    const finalPair = pairKey(app.nodeId(last.from), app.nodeId(last.to));
    assert.ok(app.visited.has(finalPair));
    app.querySelector('#reset').click(); input(app, 'seek', '999');
    assert.equal(app.currentStep.id, last.id);
    assert.ok(!app.visited.has(finalPair));
    input(app, 'seek', '1000');
    assert.equal(app.player.status, 'paused');
    assert.ok(app.visited.has(finalPair));
    assert.deepEqual(visitedState(app), natural);
    app.refs.play.click();
    assert.equal(app.player.status, 'complete');
    assert.deepEqual(visitedState(app), natural);
  } finally { unmount(app); }
});
