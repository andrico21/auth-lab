#!/usr/bin/env bun
// Diagnostic native keyboard/layout collection only. Importing helpers never launches a browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DEFAULT_CHECKOUT, DEFAULT_BROWSER, DEFAULT_PLAYWRIGHT, DEFAULT_LIBRARIES, LOAD_MODES,
  captureInputs, runtimeIdentity, fileIdentity, launchBrowser, createStaticServer,
  createBrowserSession, settle, studyState, assertClean} from './compact-mobile-browser.mjs';

const HELP = `Usage: bun tools/verification/run-compact-review01-browser.mjs --out=NEW_EXTERNAL_DIRECTORY --mode=source-http|emitted-http|standalone-file
  [--root=CHECKOUT] [--playwright-module=PATH] [--chromium-executable=PATH] [--library-path=PATH] [--cell=EXACT_ID]
All options use =VALUE. One load mode per run; output must not exist or be inside the checkout.
Runs serial synthetic 320/390 CSS-pixel viewports, light/dark, Basic Keycloak/Core/MCP09.
Uses real Chromium keyboard/pointer input, the app's actual controls, unchanged CSP and helper request allowlist.
Explicit programmatic fixture/cursor/focus setup is labelled, never claimed as keyboard navigation.
Writes compact-review01-browser-status.json, inputs-before/after.json, cells/*.json, actions.jsonl,
and at most 12 screenshots, including failures. Exit 1 means a failed check or collection/input failure.
Default: all58 diagnostic cells. --cell selects one labelled focused diagnostic; all other cells remain explicitly unperformed.
Not timing, physical-phone, human speech, screen-reader/AT, native-protocol or release acceptance.`;
if (process.argv.includes('--help')) { console.log(HELP); process.exit(0); }
const options = {}, allowed = new Set(['root','out','mode','playwright-module','chromium-executable','library-path','cell']);
for (const arg of process.argv.slice(2)) {
  const match = /^--([^=]+)=(.+)$/.exec(arg);
  assert.ok(match && allowed.has(match[1]), 'Unknown option: '+arg+'\n'+HELP);
  assert.ok(!Object.hasOwn(options,match[1]), 'Duplicate option: '+match[1]); options[match[1]]=match[2];
}
assert.ok(options.out && LOAD_MODES.includes(options.mode), HELP);
const root = fs.realpathSync(options.root || DEFAULT_CHECKOUT), runner = fileURLToPath(import.meta.url);
const out = path.resolve(options.out);
fs.mkdirSync(path.dirname(out), {recursive:true});
const realOut = path.join(fs.realpathSync(path.dirname(out)),path.basename(out));
assert.ok(realOut !== root && !realOut.startsWith(root+path.sep), 'Output must be external to checkout');
fs.mkdirSync(out); fs.mkdirSync(path.join(out,'cells')); fs.mkdirSync(path.join(out,'screenshots'));
const json = (name,value) => fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2)+'\n');
const text = error => String(error.stack || error);
const report = {schemaVersion:1,kind:'compact-review01-native-input-layout-diagnostic',status:'collecting',root,mode:options.mode,
  startedAt:new Date().toISOString(),argv:[process.execPath,...process.argv.slice(1)],runtime:runtimeIdentity(),cells:[],unperformedCells:[],screenshots:[],errors:[],inputChecks:[],
  coverageScope:options.cell?'focused-cell-not-complete-matrix':'complete-review01-diagnostic-matrix',selectedCell:options.cell||null,
  methods:{input:'Actual Playwright keyboard.press/type and locator.click on app controls. Locator focus is explicit untimed setup; keyboard view transfers use actual Tab/Shift+Tab, pointer view transfers use real trusted pointer activation.',
    viewport:'Automated synthetic phone-sized Chromium viewports, not physical phones or touch/OS input.',
    playback:'Bounded animation-frame state observations, not timing/performance acceptance. No app methods wrapped, clocks replaced or production CSP weakened.',
    artifacts:'At most 12 viewport screenshots total, including failure captures; exact before/after source, standalone, producer, helper, browser/module/package/runtime hashes.',
    budgets:'Shared helper native 60000ms action/navigation budgets; screenshot 15000ms; unchanged helper 200-event evidence cap; serial fresh contexts.'},
  externalGates:['Physical phone testing','Human reading/speech acceptance','Screen reader and assistive technology acceptance','Owner approval','Astra closure','Native protocol acceptance','Timing/performance acceptance','Publication/release authorization']};
const save = () => json('compact-review01-browser-status.json',report);
let before, launch, server, active;
function identities() {
  const modulePath=fs.realpathSync(options['playwright-module'] || process.env.PLAYWRIGHT_MODULE || DEFAULT_PLAYWRIGHT);
  const browserPath=fs.realpathSync(options['chromium-executable'] || process.env.CHROMIUM_EXECUTABLE || DEFAULT_BROWSER);
  const review=fileIdentity(path.join(root,'docs/compact-view/inputs/compact-review-01.html.input.txt'));
  assert.equal(review.sha256,'fd47e111f9d12cebb95671784baa33c356a4385b5c265b4a92a1c0201760f2dd','Frozen review input');
  return {inputs:captureInputs(root),producer:{path:runner,...fileIdentity(runner)},helper:fileIdentity(path.join(path.dirname(runner),'compact-mobile-browser.mjs')),
    review,runtime:runtimeIdentity(),browser:{path:browserPath,...fileIdentity(browserPath)},module:{path:modulePath,...fileIdentity(modulePath)},
    package:fileIdentity(path.join(path.dirname(modulePath),'package.json')),
    libraryPath:options['library-path'] || process.env.LD_LIBRARY_PATH || DEFAULT_LIBRARIES};
}
function unchanged(label) { const current=identities(); assert.deepEqual(current,before,'Exact input/runtime identity: '+label); report.inputChecks.push({label,status:'unchanged'}); }
function check(row,name,actual,expected=true) {
  try { assert.deepEqual(actual,expected,name); row.checks.push({name,status:'passed',actual}); }
  catch (error) { row.checks.push({name,status:'failed',actual,expected}); throw error; }
}
async function invariant(page) { return page.evaluate(() => {
  const a=document.querySelector('auth-flow-studio');
  return {snapshot:a.heldView.snapshot(),steps:a.scenarioSnapshot().steps,scenario:a.labScenarioId,variant:a.lessonVariant,
    workspace:a.workspace,family:a.family,config:a.protocolConfig(),cursor:a.heldView.snapshot().cursor,selection:a.index,
    attribute:a.attributeSelection,object:a.objectTraceSelection,url:location.href,history:history.length};
}); }
async function geometry(page) { return page.evaluate(() => {
  const n=document.activeElement, r=n.getBoundingClientRect(), closed=[];
  for(let p=n.parentElement;p;p=p.parentElement) {
    // The closed details' own first summary is visible and legitimately focusable.
    if(p.tagName==='DETAILS'&&!p.open&&!(n===p.querySelector(':scope > summary')))closed.push(p.id||p.dataset.compactOwner||p.dataset.compactDisclosure||p.tagName);
  }
  const s=getComputedStyle(n), id=n.id||n.getAttribute('data-compact-action')||n.getAttribute('data-index-attribute')||n.tagName;
  return {viewport:{width:innerWidth,height:innerHeight},page:{client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,body:document.body.scrollWidth},scroll:{x:scrollX,y:scrollY},
    focus:{id,tag:n.tagName,text:(n.textContent||'').trim().slice(0,200),connected:n.isConnected,hidden:!!n.closest('[hidden],[inert]'),closedAncestors:closed,
      rendered:!!n.getClientRects().length&&s.visibility!=='hidden'&&s.display!=='none',focusVisible:n.matches(':focus-visible'),
      box:{left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height},
      inViewport:r.top>=-1&&r.left>=-1&&r.right<=innerWidth+1&&r.top<innerHeight&&r.bottom>0}};
}); }
async function layout(row,page,label,{focus=true}={}) {
  const g=await geometry(page); row.layout.push({label,...g});
  check(row,label+' page has no horizontal overflow',g.page.scroll<=g.page.client+1&&g.page.body<=g.page.client+1);
  if(focus) {
    check(row,label+' connected rendered focus outside hidden/closed ancestors',g.focus.connected&&g.focus.rendered&&!g.focus.hidden&&g.focus.closedAncestors.length===0);
    check(row,label+' focus surface intersects viewport',g.focus.inViewport);
  }
  return g;
}
async function action(row,page,name,fn) {
  const record={name,status:'attempted',before:await geometry(page)};
  try { const result=await fn(); await settle(page); record.after=await geometry(page); record.status='passed'; return result; }
  catch(error) {record.status='failed';record.error=text(error);throw error;}
  finally { row.actions.push(record);fs.appendFileSync(path.join(out,'actions.jsonl'),JSON.stringify({cell:row.id,...record})+'\n'); }
}
const key=(row,page,value)=>action(row,page,'trusted keyboard '+value,()=>page.keyboard.press(value));
async function focus(row,page,selector) { await action(row,page,'explicit visible focus setup '+selector,async()=>{
  const control=page.locator(selector);await control.waitFor({state:'visible'});await control.focus();
  assert.equal(await control.evaluate(n=>document.activeElement===n),true,'Focus setup reaches the intended visible control');
}); }
async function enter(row,page,selector) { await focus(row,page,selector); await key(row,page,'Enter'); }
async function type(row,page,selector,value) {
  await focus(row,page,selector);await key(row,page,'ControlOrMeta+A');
  await action(row,page,'trusted text input '+value,()=>page.keyboard.type(value));
}
async function open(row,page,selector) { if(!await page.locator(selector).evaluate(n=>n.open))await enter(row,page,selector+' > summary'); }
async function shot(row,page,suffix='surface') {
  if(report.screenshots.length>=12)return;
  const name='screenshots/'+row.id+'-'+suffix+'.png';
  await page.screenshot({path:path.join(out,name),fullPage:false,timeout:15000});
  report.screenshots.push({cell:row.id,path:name,...fileIdentity(path.join(out,name))});
}
async function ready(page) { await page.waitForFunction(()=>{const a=document.querySelector('auth-flow-studio');return a?.presenter&&a.player&&a.steps?.length&&a.heldView?.compiled()?.plan&&a.scenarioPicker&&a.workspacePicker;});await settle(page); }
async function setup(row,page,scenario) {
  await action(row,page,'explicit public fixture selection '+scenario,()=>page.evaluate(id=>document.querySelector('auth-flow-studio').selectLabScenario(id),scenario));await ready(page);
  check(row,'real selected lesson',await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),scenario);
  if(scenario==='lab-mcp09')check(row,'real MCP09 profile',await page.evaluate(()=>!!document.querySelector('auth-flow-studio').labModel?.profile));
}
async function view(row,page,mode) { await enter(row,page,'[data-presentation-choice="'+mode+'"]');check(row,'view '+mode,await page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode),mode); }
async function collect(spec,fn) {
  if(options.cell&&spec.id!==options.cell){report.unperformedCells.push({...spec,status:'unperformed',reason:'Outside explicit focused-cell selection'});return;}
  const row={...spec,status:'attempted',checks:[],actions:[],layout:[]};report.cells.push(row);save();
  try {
    unchanged('before '+row.id);
    active=await createBrowserSession({browser:launch.browser,server,rootName:'candidate',root,identity:before.inputs,loadingMode:options.mode,
      viewport:{width:row.width,height:844},touch:false,preference:'compact',diagnostic:true});row.browserEvidence=active.evidence;row.target=active.target;
    const page=active.page;await page.goto(active.target,{waitUntil:'domcontentloaded'});await ready(page);
    if(await page.locator('#studio').getAttribute('data-theme')!==row.theme)await enter(row,page,'#theme-toggle');
    check(row,'actual theme',await page.locator('#studio').getAttribute('data-theme'),row.theme);
    await setup(row,page,row.scenario||'basic-keycloak');await fn(row,page);
    await settle(page);assertClean(active.evidence);check(row,'trusted keyboard events retained',active.evidence.trustedEvents.some(e=>e.type==='keydown'&&e.trusted));
    check(row,'no synthetic input events',active.evidence.trustedEvents.filter(e=>e.kind==='input').every(e=>e.trusted));assert.deepEqual(server.errors,[]);
    row.finalState=await studyState(page);row.status='passed';
  } catch(error) {row.status='failed';row.error=text(error);if(active)try{await shot(row,active.page,'failure');}catch(captureError){row.captureError=text(captureError);}}
  finally {
    if(active) {try{await active.close();}catch(error){row.status='failed';row.cleanupError=text(error);}active=null;}
    try{unchanged('after '+row.id);}catch(error){row.status='failed';row.inputError=text(error);}
    const name='cells/'+row.id+'.json';json(name,row);report.cells[report.cells.indexOf(row)]={id:row.id,kind:row.kind,width:row.width,theme:row.theme,scenario:row.scenario,status:row.status,path:name,...fileIdentity(path.join(out,name)),error:row.error};save();
  }
}
const fields='[data-compact-disclosure="fields"]',holdings='[data-compact-disclosure="holdings"]';
async function definition(row,page,selector) {
  const metadata=await page.locator(selector).evaluate(n=>({controls:n.getAttribute('aria-controls'),popup:n.getAttribute('aria-haspopup'),keys:n.getAttribute('aria-keyshortcuts'),id:n.dataset.indexAttribute||n.dataset.attribute}));
  check(row,'Compact inline control metadata '+metadata.id,metadata.controls==='compact-field-definition'&&!metadata.popup&&!metadata.keys);
  const beforeState=await invariant(page);
  await focus(row,page,selector);await key(row,page,'F2');
  check(row,'Compact has no F2 popup',await page.locator('#attribute-popup').evaluate(n=>n.hidden));
  await key(row,page,'Enter');
  check(row,'Enter focuses meaningful reading region before Follow',await page.evaluate(id=>{const a=document.querySelector('auth-flow-studio'),n=a.querySelector('#compact-field-definition'),d=a.definition(id);return document.activeElement===n&&n.getAttribute('role')==='region'&&n.textContent.includes(d.name)&&n.textContent.includes(d.meaning||d.description)&&n.textContent.includes(d.purpose)&&!!n.querySelector('[data-compact-field-trace]');},metadata.id));
  check(row,'definition browsing does not evaluate/select',await invariant(page),beforeState);
  check(row,'definition precedes index in DOM and layout',await page.evaluate(()=>{const d=document.querySelector('#compact-field-definition'),i=document.querySelector('#attribute-index');return !!(d.compareDocumentPosition(i)&Node.DOCUMENT_POSITION_FOLLOWING)&&d.getBoundingClientRect().bottom<=i.getBoundingClientRect().top+1;}));
  await layout(row,page,'definition '+metadata.id);return metadata.id;
}
async function fieldCell(row,page) {
  await open(row,page,fields);
  const current=await page.locator('#attribute-index-list [data-index-attribute]').evaluateAll(ns=>ns.map(n=>({id:n.dataset.indexAttribute,unused:n.classList.contains('is-unavailable')})));
  check(row,'current fields nonempty bounded 40',current.length>0&&current.length<=40);
  check(row,'current lesson relevance',await page.evaluate(rows=>{const a=document.querySelector('auth-flow-studio');return rows.every(r=>!r.unused||a.steps.some(s=>s.fields?.includes(r.id))||a.labModel?.ids.includes(r.id));},current));
  const id=await definition(row,page,'#attribute-index-list [data-index-attribute="'+current[0].id+'"]');
  if(!(row.width===390&&row.theme==='dark'))await shot(row,page,'definition');
  await enter(row,page,'[data-compact-field-trace="'+id+'"]');
  check(row,'lesson Follow focuses paused action with Return',await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return a.player.status!=='playing'&&document.activeElement===a.querySelector('#compact-current-title')&&!a.querySelector('[data-compact-action="return"]').hidden;}));
  await layout(row,page,'lesson scoped current action');
  const scopedPrefix=await invariant(page);
  await enter(row,page,'[data-compact-action="field-definition"]');
  check(row,'lesson Back focuses reading region',await page.evaluate(()=>document.activeElement===document.querySelector('#compact-field-definition')));
  await enter(row,page,'[data-compact-action="return"]');
  check(row,'lesson Return preserves canonical prefix',(await invariant(page)).snapshot,scopedPrefix.snapshot);
  await enter(row,page,'#compact-field-scope-global');
  const first=await page.locator('#attribute-index-list [data-index-attribute]').evaluateAll(ns=>ns.map(n=>n.dataset.indexAttribute));check(row,'global initial 40',first.length,40);
  await enter(row,page,'[data-compact-field-more]');
  const expanded=await page.locator('#attribute-index-list [data-index-attribute]').evaluateAll(ns=>ns.map(n=>n.dataset.indexAttribute));check(row,'global expanded 80',expanded.length,80);check(row,'global first batch stable',expanded.slice(0,40),first);
  check(row,'Show more focuses first new field',await page.evaluate(id=>document.activeElement.dataset.indexAttribute===id,expanded[40]));
  const lookup=await page.evaluate(currentIds=>{const a=document.querySelector('auth-flow-studio');return [...a.attributeIndexRows.entries].map(([id,row])=>({id,name:a.definition(id).name,search:row.search})).find(r=>!currentIds.includes(r.id)&&r.name.length>5&&r.name.length<=32);},current.map(r=>r.id));
  assert.ok(lookup,'Real out-of-lesson global field in first 80');
  await type(row,page,'#attribute-search',lookup.name);
  for(let batch=0;batch<10&&!await page.locator('#attribute-index-list [data-index-attribute="'+lookup.id+'"]').count();batch++) {
    assert.ok(await page.locator('[data-compact-field-more]').isVisible(),'Actual global search match remains available');
    await enter(row,page,'[data-compact-field-more]');
  }
  check(row,'global search metadata and out-of-lesson match',await page.evaluate(({id,q})=>{const a=document.querySelector('auth-flow-studio');return a.attributeIndexRows.global&&a.attributeIndexRows.entries.has(id)&&[...a.attributeIndexRows.entries.values()].every(row=>row.search.includes(q.toLowerCase()))&&a.refs['attribute-index-meta'].textContent.includes('matching global fields');},{id:lookup.id,q:lookup.name}));
  await definition(row,page,'#attribute-index-list [data-index-attribute="'+lookup.id+'"]');
  await enter(row,page,'#compact-field-scope-current');
  // Actual action controls are distinct from the definition-index controls.
  const actionField=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),index=a.steps.findIndex(s=>s.fields?.length);if(index<0)return null;a.inspectSourceCursor({eventIndex:index,milestone:'complete'});return a.querySelector('#compact-data .field-name[data-attribute]')?.dataset.attribute;});
  assert.ok(actionField,'Real authored action has a field control');await open(row,page,'[data-compact-disclosure="data"]');
  if(await page.locator('#compact-data details.progressive-fields').count())await open(row,page,'#compact-data details.progressive-fields');
  await definition(row,page,'#compact-data .field-name[data-attribute="'+actionField+'"]');
  await view(row,page,'full');await enter(row,page,'#index-open');
  const fullSelector='#attribute-index-list [data-index-attribute="'+id+'"]';
  check(row,'Full field advertises dialog and F2',await page.locator(fullSelector).evaluate(n=>n.getAttribute('aria-haspopup')==='dialog'&&n.getAttribute('aria-keyshortcuts')==='F2'));
  await focus(row,page,fullSelector);await key(row,page,'F2');
  check(row,'Full F2 opens and focuses dialog',await page.evaluate(()=>{const n=document.querySelector('#attribute-popup');return !n.hidden&&n.getAttribute('role')==='dialog'&&n.contains(document.activeElement);}));
  await key(row,page,'Escape');check(row,'Full Escape returns connected field',await page.locator(fullSelector).evaluate(n=>document.activeElement===n&&n.isConnected&&document.querySelector('#attribute-popup').hidden));
  await view(row,page,'compact');await layout(row,page,'after Full roundtrip');
}
async function helpCell(row,page) {
  await action(row,page,'explicit canonical cursor setup for actual current holding',()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');a.inspectSourceCursor({eventIndex:a.steps.length-1,milestone:'complete'});}));
  await open(row,page,holdings);
  const holding=await page.evaluate(()=>{const n=document.querySelector('[data-holding-id]');return n?{id:n.dataset.holdingId,owner:n.closest('[data-compact-owner]').dataset.compactOwner}:null;});
  assert.ok(holding,'Real model current holding exists');const owner='[data-compact-owner="'+holding.owner+'"]';
  await open(row,page,owner);await enter(row,page,'[data-holding-id="'+holding.id+'"]');
  for(const dismissal of ['Close','Escape']) {
    await enter(row,page,'#held-inspector [data-held-help]');
    check(row,'help opened with focus inside '+dismissal,await page.evaluate(()=>{const n=document.querySelector('#held-inspector .held-help[role="dialog"]');return !!n&&n.contains(document.activeElement);}));
    await layout(row,page,'help open '+dismissal);
    if(dismissal==='Close')await enter(row,page,'#held-inspector [data-held-help-close]');else await key(row,page,'Escape');
    check(row,'help dismiss retains holdings and surviving trigger '+dismissal,await page.evaluate(()=>document.querySelector('[data-compact-disclosure="holdings"]').open&&!document.querySelector('auth-flow-studio').heldView.helpOpen&&document.activeElement===document.querySelector('#held-inspector [data-held-help]')));
    await layout(row,page,'help dismissed '+dismissal);
  }
  await enter(row,page,'#held-inspector [data-held-help]');
  await action(row,page,'explicit presenter rerender while help has focus',()=>page.evaluate(()=>document.querySelector('auth-flow-studio').compactView.render('mount')));
  check(row,'rerender retains connected help focus',await page.evaluate(()=>document.querySelector('#held-inspector .held-help').contains(document.activeElement)&&document.activeElement.isConnected));
  await view(row,page,'full');await view(row,page,'compact');
  check(row,'help state survives presenter switch',await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.helpOpen));
  await focus(row,page,owner+' > summary');await key(row,page,'Escape');
  check(row,'first Escape dismisses help, not owner',await page.locator(owner).evaluate(n=>n.open&&!document.querySelector('auth-flow-studio').heldView.helpOpen));
  await focus(row,page,owner+' > summary');await key(row,page,'Escape');
  check(row,'subsequent owner Escape returns visible own summary',await page.locator(owner).evaluate(n=>!n.open&&document.activeElement===n.querySelector(':scope > summary')&&document.querySelector('[data-compact-disclosure="holdings"]').open));
  await layout(row,page,'closed owner own summary is valid focus');
}
async function tabTo(row,page,selector,reverse) {
  const path=[];
  for(let i=0;i<80;i++) {
    if(await page.locator(selector).evaluate(n=>n===document.activeElement)) {row.tabPaths.push({selector,reverse,path});return;}
    await key(row,page,reverse?'Shift+Tab':'Tab');
    path.push(await page.evaluate(()=>({id:document.activeElement.id,view:document.activeElement.dataset.presentationChoice,tag:document.activeElement.tagName})));
  }
  throw new Error('Native Tab traversal did not reach '+selector);
}
async function pickerSnapshot(page,kind) {return page.evaluate(k=>{const p=document.querySelector('auth-flow-studio')[k+'Picker'];return {query:p.input.value,expanded:p.input.getAttribute('aria-expanded'),active:p.input.getAttribute('aria-activedescendant'),ids:p.results.map(r=>r.id),draft:p.draft,suspended:p.suspended};},kind);}
async function emptyPickerVisits(row,page,{pointer=false}={}) {
  const kind=row.picker,prefix=kind==='scenario'?'lab-scenario':'workspace',input='#'+prefix+'-search';
  const retained=await invariant(page);
  const closed=async label=>{
    check(row,label+' normal closed selected UI without empty drafts',await page.evaluate(k=>{
      const p=document.querySelector('auth-flow-studio')[k+'Picker'],selected=p.options.find(o=>o.id===p.selectedId);
      return !p.opened&&p.menu.hidden&&p.clearButton.hidden&&p.input.value===(selected.selectedLabel||selected.title)&&
        p.input.getAttribute('aria-expanded')==='false'&&p.toggleButton.getAttribute('aria-expanded')==='false'&&
        !p.input.hasAttribute('aria-activedescendant')&&p.draft===null&&p.suspended===null;
    },kind));
  };
  for(const [index,value] of ['','   '].entries()){
    const destination=index===0?(row.start==='compact'?'full':'compact'):row.start;
    const target='[data-presentation-choice="'+destination+'"]',label=value?'whitespace visit':'untouched focus visit';
    if(pointer)await action(row,page,'trusted pointer empty picker focus',()=>page.locator(input).click());
    else{await focus(row,page,'#theme-toggle');await focus(row,page,input);}
    check(row,label+' opens fresh',await page.locator(input).inputValue(),'');
    if(value)await action(row,page,'trusted whitespace input',()=>page.keyboard.type(value));
    if(pointer)await action(row,page,'trusted outside pointer view '+destination,()=>page.locator(target).click());
    else{
      await key(row,page,'Tab');await closed(label+' after Tab');
      await enter(row,page,target);
    }
    check(row,label+' actual destination',await page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode),destination);
    await closed(label+' after view switch');
    if(pointer)await action(row,page,'trusted pointer ordinary reopen',()=>page.locator(input).click());
    else await focus(row,page,input);
    check(row,label+' ordinary reopen has no history',await page.locator(input).inputValue(),'');
    check(row,label+' full unfiltered results',await page.evaluate(k=>{const p=document.querySelector('auth-flow-studio')[k+'Picker'];return p.results.length===new Set(p.options.map(o=>o.id)).size;},kind));
    await key(row,page,'Escape');await closed(label+' after cancel');
    check(row,label+' preserves canonical cursor and route',await invariant(page),retained);
  }
}
async function pickerCell(row,page) {
  row.tabPaths=[];const prefix=row.picker==='scenario'?'lab-scenario':'workspace',input='#'+prefix+'-search';
  if(row.start==='full')await view(row,page,'full');
  if(row.start==='full'&&!row.reverse&&await page.locator('#attribute-index').isVisible())await enter(row,page,'#attribute-index-toggle');
  const beforeState=await invariant(page);
  await type(row,page,input,'kerberos');await key(row,page,'ArrowDown');await key(row,page,'ArrowDown');
  const draft=await pickerSnapshot(page,row.picker);check(row,'query has multiple actual matches',draft.ids.length>2);check(row,'Arrow keys select non-first match',draft.active!== (row.picker==='scenario'?'scenario-option-':'workspace-option-')+draft.ids[0]);
  const other=row.start==='compact'?'full':'compact';
  await tabTo(row,page,'[data-presentation-choice="'+other+'"]',row.reverse);
  check(row,'Tab dismissal clears displayed query',await page.locator(input).getAttribute('aria-expanded'),'false');
  check(row,'Tab dismissal clears active descendant',await page.locator(input).getAttribute('aria-activedescendant'),null);
  await key(row,page,'Enter');await focus(row,page,input);
  const restored=await pickerSnapshot(page,row.picker);
  check(row,'view switch restores exact draft/results/active',{query:restored.query,active:restored.active,ids:restored.ids},{query:draft.query,active:draft.active,ids:draft.ids});
  check(row,'view switch never changes canonical/cursor/route',await invariant(page),beforeState);
  await layout(row,page,'restored '+row.picker+' draft');
  await key(row,page,'Escape');await view(row,page,row.start);await focus(row,page,input);
  check(row,'Escape invalidates restored draft',await page.locator(input).inputValue(),'');await key(row,page,'Escape');
  await emptyPickerVisits(row,page);
}
async function dismissalCell(row,page) {
  const prefix=row.picker==='scenario'?'lab-scenario':'workspace',input='#'+prefix+'-search',other=row.start==='compact'?'full':'compact';
  if(row.start==='full')await view(row,page,'full');
  const beforeState=await invariant(page);
  // Ordinary Tab/blur clears, and normal reopening abandons the pending draft.
  await type(row,page,input,'kerberos');await key(row,page,'ArrowDown');await key(row,page,'Tab');
  check(row,'ordinary Tab displays selected label not query',(await page.locator(input).inputValue())!=='kerberos');
  await focus(row,page,input);check(row,'ordinary reopen starts fresh',await page.locator(input).inputValue(),'');await key(row,page,'Escape');
  await type(row,page,input,'kerberos');await focus(row,page,'#theme-toggle');
  check(row,'ordinary blur closes picker',await page.locator(input).getAttribute('aria-expanded'),'false');
  await focus(row,page,input);check(row,'ordinary blur reopen fresh',await page.locator(input).inputValue(),'');await key(row,page,'Escape');
  await type(row,page,input,'kerberos');
  // Explicit toggle cancellation is trusted keyboard input on the real toggle.
  await enter(row,page,'#'+prefix+'-toggle');await view(row,page,other);await focus(row,page,input);
  check(row,'explicit cancel cannot resurrect text',await page.locator(input).inputValue(),'');await key(row,page,'Escape');
  await type(row,page,input,'kerberos');await enter(row,page,'#'+prefix+'-clear');await key(row,page,'Escape');await view(row,page,row.start);await focus(row,page,input);
  check(row,'clear cannot resurrect text',await page.locator(input).inputValue(),'');await key(row,page,'Escape');
  check(row,'all noncommitting dismissals preserve canonical/cursor/route',await invariant(page),beforeState);
}
async function commitCell(row,page) {
  row.tabPaths=[];
  const kind=row.picker,prefix=kind==='scenario'?'lab-scenario':'workspace',peer=kind==='scenario'?'workspace':'lab-scenario';
  await type(row,page,'#'+peer+'-search','kerberos');await key(row,page,'ArrowDown');await key(row,page,'Tab');
  await type(row,page,'#'+prefix+'-search',kind==='scenario'?'SAML Artifact':'SSH access');
  const expected=kind==='scenario'?'lab-saml-artifact':'lab-ssh-cert-success';
  const targetId=kind==='scenario'?'lab-saml-artifact':'workspace-ssh';
  const count=await page.evaluate(k=>document.querySelector('auth-flow-studio')[k+'Picker'].results.length,kind);
  for(let i=0;i<count;i++) {
    if(await page.evaluate(({k,id})=>{const p=document.querySelector('auth-flow-studio')[k+'Picker'];return p.results[p.activeIndex]?.id===id;},{k:kind,id:targetId}))break;
    await key(row,page,'ArrowDown');
  }
  check(row,'real commit target active',await page.evaluate(({k,id})=>{const p=document.querySelector('auth-flow-studio')[k+'Picker'];return p.results[p.activeIndex]?.id===id;},{k:kind,id:targetId}));
  await key(row,page,'Enter');check(row,'Enter commits actual chosen destination',await page.evaluate(()=>document.querySelector('auth-flow-studio').labScenarioId),expected);
  const committed=await invariant(page);await view(row,page,'full');
  for(const p of [prefix,peer]) {await focus(row,page,'#'+p+'-search');check(row,'commit invalidates stale draft '+p,await page.locator('#'+p+'-search').inputValue(),'');await key(row,page,'Escape');}
  check(row,'reopening does not undo commit or evaluate again',await invariant(page),committed);
}
async function pointerCell(row,page) {
  const prefix=row.picker==='scenario'?'lab-scenario':'workspace',input='#'+prefix+'-search';
  const click=selector=>action(row,page,'trusted pointer activation '+selector,()=>page.locator(selector).click());
  if(row.start==='full')await click('[data-presentation-choice="full"]');
  check(row,'actual pointer starting view',await page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode),row.start);
  const retained=await invariant(page);
  await click(input);await key(row,page,'ControlOrMeta+A');await action(row,page,'trusted query text input',()=>page.keyboard.type('kerberos'));
  await key(row,page,'ArrowDown');await key(row,page,'ArrowDown');
  const draft=await pickerSnapshot(page,row.picker);
  check(row,'pointer transfer starts with real active non-first result',draft.query==='kerberos'&&draft.ids.length>2&&draft.active!== (row.picker==='scenario'?'scenario-option-':'workspace-option-')+draft.ids[0]);
  const other=row.start==='compact'?'full':'compact';
  await click('[data-presentation-choice="'+other+'"]');
  check(row,'actual pointer destination view',await page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode),other);
  await click(input);const restored=await pickerSnapshot(page,row.picker);
  check(row,'pointer restores exact query active result and matches',{query:restored.query,active:restored.active,ids:restored.ids},{query:draft.query,active:draft.active,ids:draft.ids});
  check(row,'pointer browsing and view change preserve canonical cursor and route',await invariant(page),retained);
  await layout(row,page,'actual pointer restored draft');
  await key(row,page,'Escape');await click('[data-presentation-choice="'+row.start+'"]');await click(input);
  check(row,'explicit Escape does not resurrect after later pointer switch',await page.locator(input).inputValue(),'');
  check(row,'cancelled pointer roundtrip preserves canonical cursor and route',await invariant(page),retained);
  check(row,'actual trusted pointerdown events retained',active.evidence.trustedEvents.some(event=>event.type==='pointerdown'&&event.trusted));
  await key(row,page,'Escape');
  await emptyPickerVisits(row,page,{pointer:true});
}

async function fullReplayCell(row,page) {
  if(row.parent==='object'){
    await action(row,page,'explicit canonical cursor setup for actual account-password holding',()=>page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio');a.inspectSourceCursor({eventIndex:a.steps.length-1,milestone:'complete'});
    }));
    const holding=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio');return a.heldView.snapshot().holdings.find(h=>h.artifactId==='account-password');
    });
    assert.ok(holding,'Actual Basic account-password holding exists');
    await open(row,page,holdings);await open(row,page,'[data-compact-owner="'+holding.actorId+'"]');
    await enter(row,page,'[data-holding-id="'+holding.holdingId+'"]');
    await view(row,page,'full');
    await enter(row,page,'#held-inspector [data-held-trace="account-password"]');
    await action(row,page,'explicit pause actual exact object history',()=>page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause()));
  }else{
    await view(row,page,'full');
    await enter(row,page,'#index-open');await type(row,page,'#attribute-search','client_id');
    await enter(row,page,'#attribute-index-list [data-index-attribute="clientIdApp"]');
    await action(row,page,'explicit pause actual selected field history',()=>page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause()));
    await enter(row,page,'#follow');
  }
  const parent=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio');return {rows:a.traceQueue,object:a.objectTraceSelection,attribute:a.attributeSelection,
      expected:'Selected action replay within '+(a.objectTraceSelection?'exact object history: account-password':'field history: '+a.selectionName())};
  });
  check(row,'real selected parent history has multiple actions',parent.rows.length>1);
  check(row,'actual requested parent selected',{object:parent.object,attribute:parent.attribute},
    row.parent==='object'?{object:'account-password',attribute:null}:{object:null,attribute:'clientIdApp'});
  await enter(row,page,'#inspector [data-replay]');
  await action(row,page,'explicit pause real Full inspector one-action replay',()=>page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause()));
  const retained=await invariant(page);
  const replay=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),q=a.studyQueue();return {kind:q.kind,rows:q.rows,label:q.label,clock:a.player.snapshot(),parents:a.traceQueue,
      object:a.objectTraceSelection,attribute:a.attributeSelection,step:a.currentStep};
  });
  check(row,'actual Full inspector Replay loads one action',replay.rows.length,1);
  check(row,'actual Full inspector Replay kind',replay.kind,row.parent==='object'?'step':'attribute-step');
  check(row,'one-action Replay retains complete parent history',replay.parents,parent.rows);
  check(row,'one-action Replay correctly names its parent scope',replay.label,parent.expected);
  check(row,'real inspector action details remain rendered',await page.locator('#inspector [data-replay]').isVisible());
  for(const mode of ['compact','full','compact']){
    await view(row,page,mode);
    check(row,'Replay canonical prefix cursor selection and route survive '+mode,await invariant(page),retained);
    check(row,'Replay queue parent and exact paused clock survive '+mode,await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio'),q=a.studyQueue();return {kind:q.kind,rows:q.rows,label:q.label,clock:a.player.snapshot(),parents:a.traceQueue,
        object:a.objectTraceSelection,attribute:a.attributeSelection,step:a.currentStep};
    }),replay);
    if(mode==='compact'){
      check(row,'Compact scope and playback both name single-action parent scope',await page.evaluate(expected=>{
        const a=document.querySelector('auth-flow-studio');return a.querySelector('#compact-scope').textContent.includes(expected)&&a.querySelector('#compact-queue-label').textContent.includes(expected);
      },parent.expected));
      await open(row,page,'[data-compact-disclosure="data"]');
      check(row,'Compact heading identifies the exact selected action',await page.locator('#compact-current-title').textContent(),replay.rows[0].title);
    }else check(row,'Full actual Replay control survives roundtrip',await page.locator('#inspector [data-replay]').isVisible());
    await layout(row,page,'Full inspector '+row.parent+' Replay '+mode);
  }
}

async function pathCell(row,page) {
  // Discover real authored boundaries and unused definitions, not harness-only fixtures.
  const partial=await page.evaluate(()=>{
    const a=document.querySelector('auth-flow-studio'),position=Math.min(1,a.steps.length-1),duration=a.player.durationFor(a.steps[position]);
    a.player.inspectQueue(a.steps,{position,elapsed:duration*.37,kind:'demo'});
    const clock=a.player.snapshot();return {position,stepElapsed:clock.stepElapsed,duration:clock.duration,canonical:a.heldView.snapshot().cursor};
  });
  check(row,'real fractional source clock has not completed',partial.stepElapsed>0&&partial.stepElapsed<partial.duration&&partial.canonical.milestone!=='complete');
  row.partialCursor=partial.canonical;row.partialClock=partial;
  await open(row,page,fields);await enter(row,page,'#compact-field-scope-global');await enter(row,page,'[data-compact-field-more]');
  const empty=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return [...a.attributeIndexRows.entries.keys()].map(id=>({id,name:a.definition(id).name,rows:a.buildAttributeTrace(id,a.attributeUsage(a.steps,id)).length})).filter(r=>!r.rows&&r.name.length>5).sort((a,b)=>a.name.length-b.name.length)[0];});
  assert.ok(empty,'Actual global definition with empty lesson path');row.emptyField=empty;
  for(const {id,name} of [{id:'clientIdApp',name:'client_id'},empty]) {
    await type(row,page,'#attribute-search',name);
    // Search is global and still batched; locate the real match without dropping metadata.
    for(let batch=0;batch<10&&!await page.locator('#attribute-index-list [data-index-attribute="'+id+'"]').count();batch++) {
      assert.ok(await page.locator('[data-compact-field-more]').isVisible(),'Actual search match remains available');
      await enter(row,page,'[data-compact-field-more]');
    }
    const selector='#attribute-index-list [data-index-attribute="'+id+'"]';
    assert.equal(await page.locator(selector).count(),1,'Actual global definition for '+id);
    await definition(row,page,selector);const previous=await invariant(page);
    await enter(row,page,'[data-compact-field-trace="'+id+'"]');
    const scoped=await invariant(page);
    check(row,'Follow is explicit paused scope '+id,await page.evaluate(id=>{const a=document.querySelector('auth-flow-studio');return a.attributeSelection===id&&a.player.status!=='playing'&&document.activeElement===a.querySelector('#compact-current-title')&&!a.querySelector('[data-compact-action="return"]').hidden;},id));
    await layout(row,page,'focused path action '+id);
    await key(row,page,'Tab');
    check(row,'action and playback are connected by native keyboard navigation',await page.evaluate(()=>!!document.activeElement.closest('.compact-playback')));
    await layout(row,page,'reachable playback '+id);
    row.pathSurfaces||=[];row.pathSurfaces.push(await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),box=n=>{const r=n.getBoundingClientRect();return {top:r.top,bottom:r.bottom,left:r.left,right:r.right};};return {queue:a.studyQueue(),current:box(a.querySelector('.compact-current')),playback:box(a.querySelector('.compact-playback')),return:box(a.querySelector('[data-compact-action="return"]')),title:a.querySelector('#compact-current-title').textContent};}));
    if(id==='clientIdApp') {
      check(row,'real nonempty path',await page.evaluate(()=>document.querySelector('auth-flow-studio').studyQueue().rows.length>0));
      await shot(row,page,'focused-action');
      await focus(row,page,'#play');await key(row,page,'Enter');
      const samples=await page.evaluate(()=>new Promise(resolve=>{const samples=[];function sample(){const a=document.querySelector('auth-flow-studio');samples.push({focus:document.activeElement.id,scrollX,scrollY,position:a.player.position,elapsed:a.player.elapsed,status:a.player.status});if(samples.length===12)resolve(samples);else requestAnimationFrame(sample);}requestAnimationFrame(sample);}));
      row.playbackSamples=samples;check(row,'automatic playback preserves control focus and scroll',samples.every(s=>s.focus==='play'&&s.scrollX===samples[0].scrollX&&Math.abs(s.scrollY-samples[0].scrollY)<1));
      check(row,'actual running playback observed',samples.some(s=>s.status==='playing')&&samples.some(s=>s.elapsed!==samples[0].elapsed||s.position!==samples[0].position));
      await key(row,page,'Enter');
    } else {
      check(row,'real empty path',await page.evaluate(()=>document.querySelector('auth-flow-studio').studyQueue().rows.length),0);
      check(row,'empty path retains partial canonical prefix',scoped.snapshot,previous.snapshot);
      check(row,'empty path Play disabled',await page.locator('#play').isDisabled());
    }
    const atReturn=await invariant(page);
    await enter(row,page,'[data-compact-action="field-definition"]');
    check(row,'Back to definition focuses reading region',await page.evaluate(()=>document.activeElement===document.querySelector('#compact-field-definition')));
    check(row,'Back to definition preserves scoped prefix',await invariant(page),atReturn);
    await enter(row,page,'[data-compact-action="return"]');
    const returned=await invariant(page);check(row,'Return journey preserves canonical prefix '+id,returned.snapshot,atReturn.snapshot);
    check(row,'Return journey exits scope and focuses action',await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return !a.attributeSelection&&!a.objectTraceSelection&&document.activeElement===a.querySelector('#compact-current-title');}));
    await layout(row,page,'returned current action '+id);
    // Restore the same real partial boundary for the next independent path.
    await action(row,page,'explicit restore actual fractional source clock',()=>page.evaluate(clock=>{const a=document.querySelector('auth-flow-studio');a.player.inspectQueue(a.steps,{position:clock.position,elapsed:clock.stepElapsed,kind:'demo'});},partial));
  }
}

save();
try {
  assert.ok(process.versions.bun,'Use provisioned Bun runtime');before=identities();json('inputs-before.json',before);report.inputsBefore=fileIdentity(path.join(out,'inputs-before.json'));save();
  launch=await launchBrowser({modulePath:before.module.path,executablePath:before.browser.path,libraryPath:before.libraryPath});report.browser=launch.identity;
  server=await createStaticServer({roots:{candidate:root},identities:{candidate:before.inputs}});
  // Reserve screenshots for both useful definition and focused-action surfaces.
  for(const width of [320,390])for(const theme of ['light','dark'])for(const scenario of ['basic-keycloak','core','lab-mcp09']) {
    await collect({id:`fields-${width}-${theme}-${scenario}`,kind:'fields',width,theme,scenario},fieldCell);
  }
  for(const width of [320,390])for(const theme of ['light','dark']) {
    await collect({id:`help-${width}-${theme}`,kind:'help',width,theme,scenario:'core'},helpCell);
    await collect({id:`paths-${width}-${theme}`,kind:'paths',width,theme,scenario:'basic-keycloak'},pathCell);
  }
  for(const width of [320,390])for(const picker of ['scenario','workspace'])for(const start of ['compact','full'])for(const reverse of [false,true]) {
    const theme=reverse?'dark':'light';
    await collect({id:`picker-${width}-${picker}-${start}-${reverse?'backward':'forward'}`,kind:'picker',width,theme,picker,start,reverse},pickerCell);
  }
  for(const width of [320,390])for(const picker of ['scenario','workspace'])for(const start of ['compact','full']) {
    await collect({id:`dismiss-${width}-${picker}-${start}`,kind:'dismissal',width,theme:start==='full'?'dark':'light',picker,start},dismissalCell);
  }
  for(const picker of ['scenario','workspace'])await collect({id:`commit-${picker}`,kind:'commit',width:320,theme:'dark',picker},commitCell);
  for(const width of [320,390])for(const picker of ['scenario','workspace'])for(const start of ['compact','full']) {
    await collect({id:`pointer-${width}-${picker}-${start}`,kind:'pointer',width,theme:start==='full'?'dark':'light',picker,start},pointerCell);
  }
  for(const width of [320,390])for(const parent of ['object','field']){
    await collect({id:`full-replay-${width}-${parent}`,kind:'full-inspector-replay',width,theme:parent==='object'?'light':'dark',scenario:'basic-keycloak',parent},fullReplayCell);
  }
} catch(error) {report.errors.push(text(error));}
finally {
  if(active)try{await active.close();}catch(error){report.errors.push(text(error));}
  if(launch)try{await launch.close();}catch(error){report.errors.push(text(error));}
  if(server)try{await server.close();}catch(error){report.errors.push(text(error));}
  try {const after=identities();json('inputs-after.json',after);report.inputsAfter=fileIdentity(path.join(out,'inputs-after.json'));assert.deepEqual(after,before,'Exact before/after identities');}catch(error){report.errors.push(text(error));}
  report.finishedAt=new Date().toISOString();report.status=report.errors.length||report.cells.some(row=>row.status!=='passed')||report.cells.length!==(options.cell?1:58)?'failed':'passed-with-external-gates-open';
  report.counts={attempted:report.cells.length,passed:report.cells.filter(row=>row.status==='passed').length,failed:report.cells.filter(row=>row.status==='failed').length,screenshots:report.screenshots.length};save();
  console.log(JSON.stringify({status:report.status,out,counts:report.counts,externalGates:report.externalGates}));process.exitCode=report.status==='failed'?1:0;
}
