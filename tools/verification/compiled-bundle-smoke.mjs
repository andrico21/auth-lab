#!/usr/bin/env node
/** Parse and evaluate the actual emitted script in the existing offline harness.
 * This establishes bundle compilation/boot, not native CSP or visual correctness.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv.includes('--help')||process.argv.includes('-h')){console.log('Usage: node tools/verification/compiled-bundle-smoke.mjs [project-directory]\nDefaults to this repository. Run the application build first.\nEvidence: docs/verification, or AUTH_LAB_QA_EVIDENCE_DIR. Offline harness smoke check.');process.exit(0);}
const project=path.resolve(process.argv[2]||path.join(here,'../..'));
const evidenceDir=path.resolve(process.env.AUTH_LAB_QA_EVIDENCE_DIR||path.join(project,'docs/verification'));fs.mkdirSync(evidenceDir,{recursive:true});
const {installHarness}=await import(pathToFileURL(path.join(project,'tests/dom-harness.mjs')).href);
const harness=installHarness();
const html=fs.readFileSync(path.join(project,'dist/auth-flow-studio.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const styles=[...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map(m=>m[1]);
const report={kind:'compiled-bundle-offline-smoke',nativeBrowser:false,timestamp:new Date().toISOString(),project,htmlSha256:createHash('sha256').update(html).digest('hex'),scenarios:[]};
let app;
try{
  assert.equal(scripts.length,1);assert.equal(styles.length,1);
  const policy=html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)?.[1];assert.ok(policy);
  const hash=value=>"'sha256-"+createHash('sha256').update(value).digest('base64')+"'";
  assert.ok(policy.includes('script-src '+hash(scripts[0])));assert.ok(policy.includes('style-src '+hash(styles[0])));
  assert.ok(policy.includes("connect-src 'none'"));assert.ok(!/unsafe-inline|unsafe-eval/.test(policy));
  new vm.Script(scripts[0],{filename:'auth-flow-studio.emitted.js'}).runInThisContext();
  const Klass=harness.registry.get('auth-flow-studio');assert.ok(Klass);
  app=new Klass();harness.document.body.appendChild(app);app.connectedCallback();
  assert.equal(app.labScenarioId,'basic-keycloak');
  const ids=app.refs['lab-scenario'].querySelectorAll('option').map(option=>option.value||option.getAttribute('value'));
  assert.equal(new Set(ids).size,ids.length);
  for(const id of ids){
    app.selectLabScenario(id);assert.equal(app.labScenarioId,id);assert.ok(app.steps.length);
    const actors=app.refs.actors.querySelectorAll('[data-actor]').filter(actor=>!actor.hidden);assert.ok(actors.length);
    assert.ok(app.refs.connections.querySelectorAll('.connection-line').length);
    report.scenarios.push({id,steps:app.steps.length,actors:actors.map(actor=>actor.dataset.actor)});
  }
  report.passed=true;
}catch(error){report.passed=false;report.reason=String(error.stack||error);process.exitCode=1;}
finally{if(app){app.disconnectedCallback();harness.document.body.removeChild(app);}harness.clock.frames.clear();harness.clock.timers.clear();fs.writeFileSync(path.join(evidenceDir,'compiled-bundle-status.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,scenarioCount:report.scenarios.length,htmlSha256:report.htmlSha256,reason:report.reason?.split('\n')[0]},null,2));}
