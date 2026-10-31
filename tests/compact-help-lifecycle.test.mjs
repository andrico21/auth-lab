import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, unmount, at, button, document, HarnessEvent } from './compact-fixture.mjs';

const helpTrigger = app => app.querySelector('#held-inspector [data-held-help]');
const helpClose = app => app.querySelector('#held-inspector [data-held-help-close]');
const holdings = app => app.querySelector('[data-compact-disclosure="holdings"]');

function assertVisibleFocus(app, expected = document.activeElement) {
  assert.equal(document.activeElement, expected);
  assert.equal(app.contains(expected), true, 'focus remains connected to the application');
  assert.equal(expected.closest('[hidden]'), null, 'focus is not in a hidden region');
  for (let parent = expected.parentElement; parent && parent !== app; parent = parent.parentElement) {
    if (parent.tagName === 'DETAILS' && !parent.hasAttribute('open')) assert.equal(parent.querySelector('summary')?.contains(expected), true, 'a closed disclosure exposes only its own summary, not its body');
  }
}

function selectResponse(app) {
  at(app, 0, 'received');
  const outer = holdings(app);
  // The harness has no capture phase; bubble these notifications to the
  // delegated toggle listener. Real non-bubbling toggles are checked in-browser.
  outer.setAttribute('open', '');
  outer.dispatchEvent(new HarnessEvent('toggle'));
  const owner = app.querySelector('[data-compact-owner="app"]');
  owner.setAttribute('open', '');
  owner.dispatchEvent(new HarnessEvent('toggle'));
  const holding = app.querySelector('[data-holding-id="app-response"]');
  holding.focus();
  holding.click();
  return outer;
}

// Native buttons synthesize click for Enter/Space; the harness does not implement
// that browser default, so focus followed by click represents keyboard activation.
function activate(control) {
  assert.ok(control);
  control.focus();
  control.click();
}

function assertHelp(app, open) {
  assert.equal(app.heldView.helpOpen, open);
  assert.equal(!!app.querySelector('#held-inspector .held-help[role="dialog"]'), open);
  assert.equal(helpTrigger(app).getAttribute('aria-expanded'), String(open));
  assert.equal(holdings(app).hasAttribute('open'), true);
}

for (const dismissal of ['Close', 'Escape', 'trigger']) test('keyboard Inventory help open and '+dismissal+' keep holdings open and restore connected trigger focus', () => {
  const {app} = fixture();
  try {
    selectResponse(app);
    activate(helpTrigger(app));
    assertHelp(app, true);
    assertVisibleFocus(app, helpClose(app));
    assert.equal(app.querySelector('.held-help').contains(document.activeElement), true);
    if (dismissal === 'Escape') {
      const event = new HarnessEvent('keydown', {key:'Escape'});
      helpClose(app).dispatchEvent(event);
    } else activate(dismissal === 'Close' ? helpClose(app) : helpTrigger(app));
    assertHelp(app, false);
    assertVisibleFocus(app, helpTrigger(app));
  } finally { unmount(app); }
});

test('Escape dismisses nonmodal help before either the owner inventory or outer holdings disclosure', () => {
  const {app} = fixture();
  try {
    selectResponse(app);
    activate(helpTrigger(app));
    const owner = app.querySelector('[data-compact-owner="app"]');
    const summary = owner.querySelector('summary');
    summary.focus();
    summary.dispatchEvent(new HarnessEvent('keydown', {key:'Escape'}));
    assertHelp(app, false);
    assert.equal(owner.hasAttribute('open'), true);
    assertVisibleFocus(app, helpTrigger(app));
    helpTrigger(app).dispatchEvent(new HarnessEvent('keydown', {key:'Escape'}));
    assert.equal(holdings(app).hasAttribute('open'), false, 'normal outer Escape dismissal remains available after help closes');
    assertVisibleFocus(app, holdings(app).querySelector('summary'));
  } finally { unmount(app); }
});

test('inspector replacement preserves logical help focus and Close targets the replacement trigger', () => {
  const {app} = fixture();
  try {
    selectResponse(app);
    activate(helpTrigger(app));
    const previous = helpClose(app);
    at(app, 0, 'verified');
    assert.notEqual(helpClose(app), previous, 'new observations replace the inspector controls');
    assert.equal(app.contains(previous), false);
    assertHelp(app, true);
    assertVisibleFocus(app, helpClose(app));
    activate(helpClose(app));
    assertHelp(app, false);
    assertVisibleFocus(app, helpTrigger(app));
    at(app, 1, 'complete');
    assertVisibleFocus(app, helpTrigger(app));
    activate(helpTrigger(app));
    helpClose(app).dispatchEvent(new HarnessEvent('keydown', {key:'Escape'}));
    assertHelp(app, false);
    assertVisibleFocus(app, helpTrigger(app));
  } finally { unmount(app); }
});

test('playback renders do not focus open help unless the learner is interacting with help', () => {
  const {app} = fixture();
  try {
    selectResponse(app);
    assert.equal(app.heldView.helpOpen, false);
    activate(helpTrigger(app));
    button(app, 'play').focus();
    at(app, 0, 'verified');
    assertHelp(app, true);
    assertVisibleFocus(app, button(app, 'play'));
    app.compactView.render('mount');
    assertVisibleFocus(app, button(app, 'play'));
  } finally { unmount(app); }
});

test('help state survives Full and Compact switches and both presenters keep explicit close and Escape usable', () => {
  const {app} = fixture();
  try {
    selectResponse(app);
    activate(helpTrigger(app));
    app.switchPresentation('full');
    const show = app.querySelector('#show-held-objects');
    show.checked = true;
    show.dispatchEvent(new HarnessEvent('change'));
    assert.equal(app.heldView.helpOpen, true);
    assert.ok(helpClose(app));
    activate(helpClose(app));
    assert.equal(app.heldView.helpOpen, false);
    assert.equal(helpClose(app), null);
    assertVisibleFocus(app, helpTrigger(app));
    activate(helpTrigger(app));
    assertVisibleFocus(app, helpClose(app));
    helpClose(app).dispatchEvent(new HarnessEvent('keydown', {key:'Escape'}));
    assert.equal(app.heldView.helpOpen, false);
    assertVisibleFocus(app, helpTrigger(app));
    app.switchPresentation('compact');
    assertHelp(app, false);
    assertVisibleFocus(app);
    activate(helpTrigger(app));
    assertHelp(app, true);
    assertVisibleFocus(app, helpClose(app));
    app.switchPresentation('full');
    app.switchPresentation('compact');
    assertHelp(app, true);
    assertVisibleFocus(app);
    activate(helpClose(app));
    assertHelp(app, false);
    assertVisibleFocus(app, helpTrigger(app));
  } finally { unmount(app); }
});
