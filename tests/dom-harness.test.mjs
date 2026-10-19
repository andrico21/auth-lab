import test from 'node:test';
import assert from 'node:assert/strict';
import {HarnessElement} from './dom-harness.mjs';

// Selector behavior only, not browser layout or a timing threshold.
test('harness selectors retain document order, unique matches and descendant scope',()=>{
  const root=new HarnessElement('section');root.id='scope';
  root.innerHTML='<div class="group"><button id="first" class="target"></button><span><button id="nested" class="target"></button></span></div><button id="last" class="target"></button>';
  assert.equal(root.querySelector('#last, .target').id,'first','selector-list order does not override document order');
  assert.deepEqual(root.querySelectorAll('.target, #nested').map(node=>node.id),['first','nested','last'],'each descendant occurs once');
  assert.equal(root.querySelector('#scope'),null,'queries exclude the query root itself');
  assert.deepEqual(root.querySelectorAll('#scope .group button').map(node=>node.id),['first','nested']);
  const group=root.querySelector('.group');
  assert.equal(group.querySelector('#scope .group #nested').id,'nested','ancestor matching may reach outside the queried subtree');
  assert.equal(group.querySelector('#last'),null,'results stay inside the queried subtree');
});

test('harness queries reflect attribute changes, removals and replacement without stale matches',()=>{
  const root=new HarnessElement('section');
  root.innerHTML='<button id="before" class="old" data-label="A &amp; B"></button>';
  const button=root.querySelector('button'),previous=root.querySelectorAll('.old');
  assert.equal(root.querySelector('[data-label="A &amp; B"]'),button);
  button.id='after';button.classList.remove('old');button.classList.add('new');button.setAttribute('data-label','updated');
  assert.equal(root.querySelector('#before, .old, [data-label="A &amp; B"]'),null);
  assert.equal(root.querySelector('#after.new[data-label="updated"]'),button);
  assert.deepEqual(previous,[button],'earlier querySelectorAll results remain static');
  button.removeAttribute('data-label');assert.equal(root.querySelector('[data-label]'),null);
  root.innerHTML='<button id="replacement" class="new"></button>';
  assert.equal(root.querySelector('.new').id,'replacement');
  assert.equal(root.contains(button),false);
});

test('harness matches and closest use the current nearest matching ancestor',()=>{
  const root=new HarnessElement('section');root.classList.add('owner');
  root.innerHTML='<div class="owner"><button data-action="open"><span class="label">Open</span></button></div>';
  const label=root.querySelector('.label'),button=root.querySelector('button'),owner=root.querySelector('div');
  assert.equal(label.closest('.label'),label);
  assert.equal(label.closest('.missing, .owner'),owner);
  assert.equal(button.matches('SECTION .owner BUTTON[data-action="open"]'),true);
  owner.classList.remove('owner');assert.equal(label.closest('.owner'),root);
  root.removeChild(owner);assert.equal(label.closest('section'),null);
  assert.equal(label.closest('.missing'),null);
});
