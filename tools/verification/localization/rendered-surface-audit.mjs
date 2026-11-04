#!/usr/bin/env bun
// Independent DOM comparison, not a second translation corpus or coverage oracle.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
import {parse} from 'acorn';
import {fullAncestor} from 'acorn-walk';
import {extractUIContracts,UI_MODULES} from './ui-contracts.mjs';
import {PERFORMANCE_FIXTURES} from './performance-fixtures.mjs';
import {installHarness,HarnessElement} from '../../../tests/dom-harness.mjs';
import {captureInputs,fileIdentity} from '../compact-mobile-browser.mjs';

export const SURFACE_LOCALES=['ru','uk','he','de','ar-AE','fr','pl'];
const ownRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const digest=value=>createHash('sha256').update(value).digest('hex');
const normalized=value=>String(value).replace(/\s+/g,' ').trim();
const inherited=(node,attribute)=>{for(let current=node;current;current=current.parentElement)if(current.hasAttribute?.(attribute))return current.getAttribute(attribute);return null;};
function exposure(node){
  for(let current=node;current;current=current.parentElement){
    if(current.hidden||current.getAttribute?.('aria-hidden')==='true')return 'hidden';
    const details=current.parentElement;
    if(details?.tagName==='DETAILS'&&!details.hasAttribute('open')&&current.tagName!=='SUMMARY')return 'closed-disclosure';
  }
  return 'exposed';
}
function locator(node){
  const parts=[];
  for(let current=node;current?.tagName;current=current.parentElement){
    const semantic=['data-learning-preset','data-index-attribute','data-actor','data-study-key'].find(attribute=>current.hasAttribute(attribute));
    parts.unshift(current.tagName.toLowerCase()+(current.id?'#'+current.id:semantic?'['+semantic+'='+JSON.stringify(current.getAttribute(semantic))+']':':nth-child('+((current.parentElement?.children.indexOf(current)??0)+1)+')'));
    if(current.id||semantic)break;
  }
  return parts.join(' > ');
}

// Read every text node and accessible text attribute, including hidden content.
// No Localizer request list or message registry decides which DOM nodes exist.
export function renderedSurfaceInventory(root,{locale='en',english=[]}={}){
  const englishText=new Set(english.map(record=>record.text)),records=[];
  const add=(node,kind,value)=>{
    const text=normalized(value);if(!text||!/[\p{L}]/u.test(text))return;
    const language=inherited(node,'lang'),protectedNode=inherited(node,'translate')==='no'||!!node.closest?.('[data-technical-ltr]');
    const classification=protectedNode?'protected-directive':locale==='en'?'english-reference':language==='en'?'explicit-English-fallback':englishText.has(text)?'unchanged-English-review': 'changed-text-not-linguistically-approved';
    records.push({locator:locator(node),kind,text,language,selected:node.getAttribute('aria-pressed')??node.getAttribute('aria-selected'),exposure:exposure(node),classification});
  };
  const visit=node=>{
    if(!node.tagName)return;
    if(['SCRIPT','STYLE'].includes(node.tagName))return;
    for(const attribute of ['aria-label','aria-description','title','placeholder','alt'])if(node.hasAttribute(attribute))add(node,'attribute:'+attribute,node.getAttribute(attribute));
    for(const child of node.childNodes||[])if(child.tagName)visit(child);else add(node,'text',child.textContent);
  };
  visit(root);return records;
}

export function resolvedAccessibleName(root,node){
  assert.ok(node,'Accessible-name consumer exists');
  const ids=(node.getAttribute('aria-labelledby')||'').trim().split(/\s+/).filter(Boolean);
  if(ids.length){
    const targets=ids.map(id=>{const matches=[...root.querySelectorAll('[id]')].filter(target=>target.id===id);assert.equal(matches.length,1,'Unique labelled-by target '+id);return matches[0];});
    for(const target of targets)assert.ok(normalized(target.textContent),'Nonempty labelled-by target '+target.id);
    return {name:targets.map(target=>normalized(target.textContent)).join(' '),targets};
  }
  return {name:normalized(node.getAttribute('aria-label')||node.textContent),targets:[]};
}

export async function mountSurfaceApp({root=ownRoot,loading='source'}={}){
  const replaceChild=Object.getOwnPropertyDescriptor(HarnessElement.prototype,'replaceChild');
  const querySelector=Object.getOwnPropertyDescriptor(HarnessElement.prototype,'querySelector');
  // The harness has no child combinators or pseudo-classes. Supply the exact
  // browser selector used by shared-chrome refresh rather than report its
  // skipped menu update as a production localization defect.
  Object.defineProperty(HarnessElement.prototype,'querySelector',{configurable:true,writable:true,value(selector){
    if(selector==='.scenario-picker-menu-heading > span:last-child'){
      const heading=querySelector.value.call(this,'.scenario-picker-menu-heading'),children=heading?.children,last=children?.[children.length-1];
      return last?.tagName==='SPAN'?last:null;
    }
    return querySelector.value.call(this,selector);
  }});
  if(!replaceChild)Object.defineProperty(HarnessElement.prototype,'replaceChild',{configurable:true,writable:true,value(next,old){this.insertBefore(next,old);this.removeChild(old);return old;}});
  let harness,Component,inlineSha256=null;
  if(loading==='source'){
    harness=installHarness();
    ({AuthFlowStudio:Component}=await import(pathToFileURL(path.join(root,'src/app.js')).href));
  }else{
    assert.equal(loading,'emitted');
    const html=fs.readFileSync(path.join(root,'dist/auth-flow-studio.html'),'utf8');
    const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
    assert.equal(scripts.length,1,'Exact standalone contains one inline program');
    const sandbox={structuredClone,DecompressionStream,CompressionStream,Response,ReadableStream,Uint8Array};
    harness=installHarness(sandbox);inlineSha256=digest(scripts[0][1]);
    new vm.Script(scripts[0][1],{filename:path.join(root,'dist/auth-flow-studio.html:inline-script')}).runInContext(vm.createContext(sandbox),{timeout:5000});
    Component=harness.registry.get('auth-flow-studio');
  }
  const app=new Component();
  // The shared offline harness leaves connection/focus bookkeeping to callers.
  // Supply those DOM facts without faking native Tab or accessibility behavior.
  Object.defineProperty(app,'isConnected',{get:()=>harness.document.body.contains(app)});
  app.addEventListener('focusin',event=>{harness.document.activeElement=event.target;});
  harness.document.activeElement=harness.document.body;
  harness.document.body.appendChild(app);await app.connectedCallback();
  if(app.localizer.initialPreparation)await app.localizer.initialPreparation;
  app.switchPresentation('full');app.selectLabScenario('basic-keycloak');
  return {...harness,app,inlineSha256,dispose(){app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();Object.defineProperty(HarnessElement.prototype,'querySelector',querySelector);if(replaceChild)Object.defineProperty(HarnessElement.prototype,'replaceChild',replaceChild);else delete HarnessElement.prototype.replaceChild;}};
}

function dynamicSinkInventory(source,module){
  const ast=parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true}),records=[];
  fullAncestor(ast,(node,ancestors)=>{
    const snippet=source.slice(node.start,node.end);
    const escapedMember=node.type==='CallExpression'&&['escapeHtml','compactEscape'].includes(node.callee.name)&&node.arguments.some(argument=>argument.type==='MemberExpression');
    const assignment=node.type==='AssignmentExpression'&&node.left.type==='MemberExpression'&&['textContent','innerHTML'].includes(node.left.property.name);
    const accessible=node.type==='CallExpression'&&node.callee.type==='MemberExpression'&&node.callee.property.name==='setAttribute'&&/^(?:aria-label|title|placeholder|alt)$/.test(node.arguments[0]?.value);
    const toast=node.type==='CallExpression'&&node.callee.type==='MemberExpression'&&node.callee.property.name==='showToast';
    if(!escapedMember&&!assignment&&!accessible&&!toast)return;
    const explicitEnglish=toast&&node.arguments[1]?.type==='Literal'&&node.arguments[1].value==='en';
    const method=[...ancestors].reverse().find(parent=>parent.type==='MethodDefinition');
    records.push({module,line:node.loc.start.line,method:method?.key?.name||null,kind:toast?'toast-consumer-call':escapedMember?'escaped-dynamic-member':assignment?'DOM-assignment':'accessible-attribute-setter',...(toast?{classification:explicitEnglish?'explicit-English-boundary':'toast-language-binding-review'}:{}),source:snippet,sourceSha256:digest(snippet),qualification:explicitEnglish?'Intentional explicit English boundary; runtime must retain lang=en. Not Native coverage.':'Review candidate, not proof of a bypass. Resolve producer, protection and runtime use.'});
  });
  return records;
}

export async function main(argv=process.argv.slice(2)){
  const options={};for(const arg of argv){const match=/^--(root|out)=(.+)$/.exec(arg);assert.ok(match,'Usage: rendered-surface-audit.mjs --out=NEW_DIRECTORY [--root=CHECKOUT]');assert.ok(!Object.hasOwn(options,match[1]));options[match[1]]=match[2];}
  assert.ok(options.out,'Exclusive output directory required');
  const root=fs.realpathSync(options.root||ownRoot),out=path.resolve(options.out);
  assert.ok(!out.startsWith(root+path.sep)&&out!==root,'Evidence remains outside candidate source');fs.mkdirSync(out,{recursive:false});
  const inputsBefore=captureInputs(root),handoffs=['ui-application-source-contracts.json','ui-source-handoffs.json','ui-renderer-factory-contracts.json'].map(name=>path.join(root,'docs/localization/generated',name));
  // Persist exact evidence before any UI assertion or collection can fail.
  fs.writeFileSync(path.join(out,'inputs-before.json'),JSON.stringify(inputsBefore,null,2)+'\n',{flag:'wx'});
  fs.copyFileSync(fileURLToPath(import.meta.url),path.join(out,'producer.mjs'),fs.constants.COPYFILE_EXCL);
  const ui=extractUIContracts({root,handoffs}),sourceSinks=UI_MODULES.flatMap(module=>dynamicSinkInventory(fs.readFileSync(path.join(root,module),'utf8'),module));
  assert.equal(ui.summary.complete,true,'Use the complete current source-bound UI contracts');assert.deepEqual(ui.unresolved,[]);assert.deepEqual(ui.residual,[]);
  fs.writeFileSync(path.join(out,'source-ui-residuals.json'),JSON.stringify({scope:ui.summary.scope,residual:ui.residual,unresolved:ui.unresolved,dynamicSinkCandidates:sourceSinks},null,2)+'\n');
  const report={kind:'independent-rendered-surface-audit',schemaVersion:1,scope:'Selected existing renderer fixtures, DOM harness only; neither all-occurrence coverage nor browser, human AT or linguistic acceptance.',fixtures:PERFORMANCE_FIXTURES,producerSha256:digest(fs.readFileSync(fileURLToPath(import.meta.url))),sourceModules:ui.summary.modules,loads:[],counts:{},qualification:{historicalBrowserCells:96,historicalNestedFullCopyProbes:{status:'unperformed',count:80,reason:'Exact-value copy controls were Compact-only. Historical cell-level pass does not imply nested checks performed.'},humanAT:'unperformed'}};
  report.inputsBefore=inputsBefore;report.uiHandoffs=handoffs.map(file=>({path:file,...fileIdentity(file)}));
  report.selectedFieldConsumers=[];
  report.qualification.domHarnessMenuSelector='Exact .scenario-picker-menu-heading > span:last-child adapter supplies the browser selector omitted by the shared harness; not a runtime translation change.';
  const rowsPath='rendered-surfaces.jsonl.gz',fd=fs.openSync(path.join(out,rowsPath),'wx'),rowsHash=createHash('sha256');
  let rowsBuffer=[],bufferBytes=0,decodedBytes=0,rowCount=0;
  const flushRows=()=>{if(bufferBytes){fs.writeFileSync(fd,gzipSync(rowsBuffer.join(''),{level:6}));rowsBuffer=[];bufferBytes=0;}};
  const appendRow=row=>{const line=JSON.stringify(row)+'\n',size=Buffer.byteLength(line);rowsHash.update(line);decodedBytes+=size;rowCount++;rowsBuffer.push(line);bufferBytes+=size;if(bufferBytes>=1024*1024)flushRows();};
  try{
    for(const loading of ['source','emitted']){
      const mounted=await mountSurfaceApp({root,loading});const {app}=mounted;
      report.loads.push({loading,inlineSha256:mounted.inlineSha256});
      try{
        for(const fixture of PERFORMANCE_FIXTURES)for(const presentation of ['full','compact']){
          await app.changeLocale('en',{explicit:false});app.selectLabScenario(fixture.scenarioId,{variant:fixture.variantId,navigate:false});app.switchPresentation(presentation);
          for(const details of app.querySelectorAll('details')){details.open=false;details.removeAttribute('open');}app.hidePopups();
          if(fixture.queueBoundary!==undefined)app.inspectQueueBoundary(fixture.queueBoundary,fixture.queueEdge);
          const phases=['closed','disclosed','selected-field'];
          const prepare=phase=>{
            if(phase!=='closed')for(const details of app.querySelectorAll('details')){details.open=true;details.setAttribute('open','');}
            if(phase==='selected-field'){
              // Compact populates its lazy field index only after it is opened.
              // An empty hidden index must not silently skip the selected phase.
              const index=app.refs['attribute-index'];assert.ok(index,'Actual field index exists');
              index.hidden=false;app.renderAttributeIndex();
              const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute]'),id=field?.dataset.indexAttribute;
              assert.ok(id,'Selected-field phase has an actual rendered field');
              if(presentation==='full')app.showAttributePopup(id,field);else app.compactView.showField(id);
              const consumer=app.querySelector(presentation==='full'?'#attribute-popup':'#compact-field-definition');
              assert.equal(consumer.hidden,false,'Actual selected-field consumer is open');
              const accessible=resolvedAccessibleName(app,consumer);
              assert.ok(accessible.name,'Selected-field consumer has an actual accessible name');
              report.selectedFieldConsumers.push({loading,fixture:fixture.id,presentation,locale:app.localizer.locale,fieldId:id,locator:locator(consumer),name:accessible.name,labelledByTargets:accessible.targets.map(locator)});
            }
          };
          const references=new Map();for(const phase of phases){prepare(phase);references.set(phase,renderedSurfaceInventory(app));}
          for(const locale of SURFACE_LOCALES){
            await app.changeLocale(locale,{explicit:false});
            // Reset disclosures before collecting the closed phase of each locale.
            for(const details of app.querySelectorAll('details')){details.open=false;details.removeAttribute('open');}app.hidePopups();
            for(const phase of phases){prepare(phase);const rows=renderedSurfaceInventory(app,{locale,english:references.get(phase)});
              for(const row of rows){report.counts[row.classification]=(report.counts[row.classification]||0)+1;appendRow({loading,fixture:fixture.id,presentation,locale,phase,...row});}
            }
          }
        }
      }finally{mounted.dispose();}
    }
  }finally{try{flushRows();if(!rowCount)fs.writeFileSync(fd,gzipSync(''));}finally{fs.closeSync(fd);}}
  report.evidenceRows={path:rowsPath,encoding:'gzip-concatenated-members; utf8-jsonl',records:rowCount,decodedBytes,decodedSha256:rowsHash.digest('hex'),...fileIdentity(path.join(out,rowsPath))};
  report.inputsAfter=captureInputs(root);assert.deepEqual(report.inputsAfter,inputsBefore,'Source and exact emitted inputs unchanged during rendered audit');
  report.status='collected-requires-review';report.note='Unchanged English is a concrete review inventory, not an automatic linguistic failure: formal names and approved identities need separate adjudication. Protected directives and lang=en fallback remain separate. Quick-start tests independently require every actual visible title/summary to differ from English.';
  fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().then(report=>console.log(JSON.stringify(report))).catch(error=>{console.error(error);process.exitCode=1;});
