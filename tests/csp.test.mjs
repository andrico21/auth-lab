import test, {before, after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {SOURCE_CSP} from '../security-policy.mjs';
import {installHarness, HarnessEvent} from './dom-harness.mjs';

// Verify emitted bytes and browser-compatible markup. This suite does not
// pretend that the DOM harness enforces CSP or replaces a native browser.
const project=fileURLToPath(new URL('../',import.meta.url));
const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'auth-flow-csp-'));
const template=fs.readFileSync(path.join(project,'index.html'),'utf8');
const output=()=>fs.readFileSync(path.join(fixture,'dist/auth-flow-studio.html'),'utf8');
const build=()=>execFileSync(process.execPath,[path.join(fixture,'build.mjs')],{stdio:'pipe'});
const hash=text=>"'sha256-"+createHash('sha256').update(text,'utf8').digest('base64')+"'";
const meta=html=>{
  const matches=[...html.matchAll(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/g)];
  assert.equal(matches.length,1,'one enforced policy');
  return {value:matches[0][1],index:matches[0].index};
};
const directives=value=>new Map(value.split(';').map(item=>item.trim().split(/\s+/)).filter(item=>item[0]).map(([name,...sources])=>[name,sources]));
const contents=(html,tag)=>[...html.matchAll(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,'gi'))].map(match=>match[1]);
let built;
before(()=>{
  for(const name of ['build.mjs','security-policy.mjs','index.html','src'])fs.cpSync(path.join(project,name),path.join(fixture,name),{recursive:true});
  build();built=output();
});
after(()=>fs.rmSync(fixture,{recursive:true,force:true}));

test('source CSP precedes assets and permits only same-origin scripts/styles, with no connections or HTML handlers',()=>{
  const policy=meta(template),rules=directives(policy.value);
  assert.equal(policy.value,SOURCE_CSP);
  assert.ok(policy.index>template.indexOf('<meta charset='));
  assert.ok(policy.index<template.indexOf('<link '));
  assert.ok(policy.index<template.indexOf('<script '));
  assert.deepEqual(rules.get('script-src'),["'self'"]);
  assert.deepEqual(rules.get('style-src'),["'self'"]);
  for(const name of ['default-src','script-src-attr','style-src-attr','connect-src','img-src','font-src','media-src','object-src','frame-src','worker-src','manifest-src','base-uri','form-action'])assert.deepEqual(rules.get(name),["'none'"],name);
  assert.doesNotMatch(policy.value,/unsafe-inline|unsafe-eval|unsafe-hashes|\*|https?:|data:|blob:/);
  for(const unsupported of ['frame-ancestors','sandbox','report-uri','report-to'])assert.equal(rules.has(unsupported),false,'unsupported meta directive is not advertised');
});

test('standalone CSP authorizes exactly the final embedded script and stylesheet; tampered content has no matching hash',()=>{
  const policy=meta(built),rules=directives(policy.value);
  const scripts=contents(built,'script'),styles=contents(built,'style');
  assert.equal(scripts.length,1);assert.equal(styles.length,1);
  assert.ok(policy.index<built.indexOf('<style>'));assert.ok(policy.index<built.indexOf('<script>'));
  assert.deepEqual(rules.get('script-src'),[hash(scripts[0])]);
  assert.deepEqual(rules.get('style-src'),[hash(styles[0])]);
  assert.equal(rules.get('script-src').includes(hash(scripts[0]+'\nwindow.injected=true;')),false);
  assert.equal(rules.get('style-src').includes(hash(styles[0]+'\n.actor-card{display:none}')),false);
  assert.doesNotMatch(policy.value,/'self'|unsafe-inline|unsafe-eval|unsafe-hashes|\*|https?:|data:|blob:/);
  assert.deepEqual(rules.get('connect-src'),["'none'"]);
  assert.deepEqual(rules.get('script-src-attr'),["'none'"]);
  assert.deepEqual(rules.get('style-src-attr'),["'none'"]);
  const markup=built.replace(/<script>[\s\S]*?<\/script>/g,'').replace(/<style>[\s\S]*?<\/style>/g,'');
  assert.doesNotMatch(markup,/\s(?:style|on\w+)\s*=/i);
  assert.doesNotMatch(markup,/<(?:script|link)\b[^>]*\b(?:src|href)\s*=/i);
});

test('CRLF and CR source files produce identical standalone bytes and browser-matching hashes',()=>{
  const files=['index.html','src/app.js','src/styles.css'];
  const originals=files.map(name=>fs.readFileSync(path.join(fixture,name),'utf8'));
  try{
    files.forEach((name,index)=>fs.writeFileSync(path.join(fixture,name),originals[index].replace(/\n/g,index===2?'\r':'\r\n')));
    build();assert.equal(output(),built);assert.doesNotMatch(output(),/\r/);
  }finally{files.forEach((name,index)=>fs.writeFileSync(path.join(fixture,name),originals[index]));}
});

test('script hash covers the emitted closing-tag escaping, not the unescaped source',()=>{
  const appFile=path.join(fixture,'src/app.js'),original=fs.readFileSync(appFile,'utf8');
  try{
    fs.writeFileSync(appFile,original+'\n// literal </script> in a teaching example\n');
    build();const html=output(),scripts=contents(html,'script');
    assert.equal(scripts.length,1);assert.ok(scripts[0].includes('literal <\\/script>'));
    assert.deepEqual(directives(meta(html).value).get('script-src'),[hash(scripts[0])]);
  }finally{fs.writeFileSync(appFile,original);}
});

test('builder fails closed on missing/changed/late policies or invalid asset placeholders',()=>{
  const file=path.join(fixture,'index.html'),tag=template.match(/<meta http-equiv="Content-Security-Policy"[^>]*>/)[0];
  const styleTag='<link rel="stylesheet" href="src/styles.css">',scriptTag='<script type="module" src="src/app.js"></script>';
  try{
    for(const variant of [
      template.replace(tag,''),template.replace(tag,tag+'\n'+tag),template.replace("script-src 'self'","script-src 'unsafe-inline'"),
      template.replace(tag,'').replace('</body>',tag+'\n</body>'),
      template.replace(tag,'').replace('</head>',tag+'\n</head>'),
      template.replace(styleTag,''),template.replace(styleTag,styleTag+'\n'+styleTag),
      template.replace(scriptTag,''),template.replace(scriptTag,scriptTag+'\n'+scriptTag),
    ]){
      fs.writeFileSync(file,variant);
      const result=spawnSync(process.execPath,[path.join(fixture,'build.mjs')],{encoding:'utf8'});
      assert.notEqual(result.status,0);assert.match(result.stderr,/CSP/);
    }
  }finally{fs.writeFileSync(file,template);}
});

test('runtime renders positions through CSSOM and keeps hostile identifier text inert in inputs and help',async()=>{
  const harness=installHarness(),{AuthFlowStudio}=await import('../src/app.js');
  const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();
  try{
    const source=fs.readFileSync(path.join(project,'src/app.js'),'utf8');
    assert.doesNotMatch(source,/\sstyle\s*=|\.style\.cssText\s*=|setAttribute\(\s*['"]style['"]/i);
    for(const card of app.refs.actors.querySelectorAll('[data-actor]')){
      const expected=app.positions[card.dataset.actor];
      assert.equal(parseFloat(card.style.left),expected.x/1120*100);
      assert.equal(parseFloat(card.style.top),expected.y/730*100);
    }
    const hostile='client"><img src=x onerror="window.injected=true"><script>window.injected=true</script>';
    const field=app.refs['environment-fields'].querySelector('[data-environment-field="clientID"]');
    field.value=hostile;field.dispatchEvent(new HarnessEvent('input'));
    app.querySelector('#environment-apply').click();
    assert.equal(app.runtimeEnvironment.applied.clientID,hostile);
    assert.equal(app.refs['environment-fields'].querySelector('[data-environment-field="clientID"]').value,hostile);
    app.refs.actors.querySelector('[data-actor="app"]').click();
    assert.ok(app.refs.inspector.textContent.includes(hostile));
    assert.equal(app.querySelectorAll('img').length,0);
    assert.equal(app.querySelectorAll('script').length,0);
    assert.equal(app.querySelectorAll('[onerror]').length,0);
  }finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
});
