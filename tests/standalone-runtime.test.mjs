import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {execFileSync} from 'node:child_process';
import {installHarness,HarnessEvent} from './dom-harness.mjs';
import {ACTORS,FLOWS} from '../src/protocol-data.js';

// Keep compiled boot in its own isolated worker, not the retained source-app DOM heap.
// The existing five-second VM budget and consumer assertions remain unchanged.
function select(app,id,value){const select=app.querySelector('#'+id);select.value=value;select.dispatchEvent(new HarnessEvent('change'));}
function configureCore(app){app.selectLabScenario('core');select(app,'mode','passkey');select(app,'architecture','native');select(app,'upstream','keycloak');select(app,'authenticator','hello');}

test('the built standalone HTML has no external runtime assets and its inline bundle boots',()=>{
  const root=new URL('../',import.meta.url);
  // Exercise the build itself, ensuring this checks current source rather than stale output.
  execFileSync(process.execPath,[new URL('../build.mjs',import.meta.url).pathname],{cwd:root.pathname,stdio:'pipe'});
  const html=fs.readFileSync(new URL('../dist/auth-flow-studio.html',import.meta.url),'utf8');
  const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];assert.equal(scripts.length,1);
  const sandbox={structuredClone},built=installHarness(sandbox);built.document.body.innerHTML=html.replace(/<script(?:\s[^>]*)?>[\s\S]*?<\/script>/gi,'').replace(/<style(?:\s[^>]*)?>[\s\S]*?<\/style>/gi,'');
  assert.equal(built.document.querySelectorAll('script[src]').length,0);assert.equal(built.document.querySelectorAll('link[rel="stylesheet"]').length,0);
  const styles=[...html.matchAll(/<style(?:\s[^>]*)?>([\s\S]*?)<\/style>/gi)].map(match=>match[1]).join('\n');
  assert.doesNotMatch(styles,/@import\b|url\(\s*['"]?(?:https?:)?\/\//i,'CSS has no remote imports, images, or fonts');
  assert.doesNotMatch(html,/<script\b[^>]*\bsrc\s*=/i,'JavaScript is embedded');assert.doesNotMatch(html,/<link\b[^>]*\brel=["'](?:stylesheet|preload)["']/i,'Styles and fonts are embedded');
  const compiled=new vm.Script(scripts[0][1],{filename:'dist/auth-flow-studio.html:inline-script'});compiled.runInContext(vm.createContext(sandbox),{timeout:5000});
  const Component=built.registry.get('auth-flow-studio');assert.equal(typeof Component,'function');
  const app=new Component();built.document.body.appendChild(app);app.connectedCallback();configureCore(app);
  assert.equal(app.refs.actors.querySelectorAll('[data-actor]').length,Object.keys(ACTORS).length);
  assert.equal(app.refs.timeline.querySelectorAll('[data-step]').length,FLOWS.login.length);
  app.refs.play.click();built.clock.frame();built.clock.advance(500);assert.equal(app.player.status,'playing');assert.equal(app.refs.packet.hidden,false);assert.ok(app.refs['packet-name'].textContent);
  app.disconnectedCallback();assert.equal(built.clock.frames.size,0);built.clock.timers.clear();
});
