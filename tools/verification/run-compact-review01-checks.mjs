#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {captureInputs,fileIdentity,runtimeIdentity} from './compact-mobile-browser.mjs';

const args={};
for(const argument of process.argv.slice(2)){
  const match=/^--(root|html|out|mode)=(.+)$/.exec(argument);
  assert.ok(match&&!args[match[1]],'Expected unique --root/html/out/mode=VALUE');args[match[1]]=match[2];
}
for(const name of ['root','html','out','mode'])assert.ok(args[name],'Missing --'+name);
assert.ok(['source','emitted'].includes(args.mode));
const root=fs.realpathSync(args.root),html=fs.realpathSync(args.html),out=path.resolve(args.out);
assert.ok(!fs.existsSync(out),'Fresh output directory required');
assert.ok(!out.startsWith(root+path.sep),'Evidence must be outside source');
fs.mkdirSync(out);
const before=captureInputs(root),self=fileURLToPath(import.meta.url);
assert.deepEqual(fileIdentity(html),before.standalone,'Companion must match the actual built input');
const report={schemaVersion:1,kind:'compact-review01-positive-dom-verification',mode:args.mode,status:'running',startedAt:new Date().toISOString(),runtime:runtimeIdentity(),producer:{path:'tools/verification/run-compact-review01-checks.mjs',...fileIdentity(self)},inputsBefore:before,checks:[],qualification:'Actual source/emitted DOM-harness checks, not native layout, phone timing, human speech, independent-review acceptance or full-corpus recollection. Counts are grouped behavior records, not invented assertion totals.'};
const save=()=>fs.writeFileSync(path.join(out,'status.json'),JSON.stringify(report,null,2)+'\n');
save();
const {installHarness,HarnessEvent}=await import(pathToFileURL(path.join(root,'tests/dom-harness.mjs')).href);
let harness,Component;
if(args.mode==='emitted'){
  const sandbox={structuredClone};harness=installHarness(sandbox);
  const scripts=[...fs.readFileSync(html,'utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];assert.equal(scripts.length,1);
  new vm.Script(scripts[0][1],{filename:'review01-built:inline'}).runInContext(vm.createContext(sandbox),{timeout:5000});
  Component=harness.registry.get('auth-flow-studio');
}else{
  harness=installHarness();({AuthFlowStudio:Component}=await import(pathToFileURL(path.join(root,'src/app.js')).href));
}
const {document,window,clock}=harness;
const mount=(mode='compact')=>{
  window.innerWidth=390;window.localStorage={getItem:()=>mode,setItem(){}};
  const app=new Component();document.body.appendChild(app);document.activeElement=document.body;
  app.addEventListener('focusin',event=>{document.activeElement=event.target;});app.connectedCallback();return app;
};
const close=app=>{app.disconnectedCallback();document.body.removeChild(app);document.activeElement=document.body;clock.frames.clear();clock.timers.clear();};
const canonical=app=>JSON.stringify(app.heldView.snapshot());
const preserved=app=>JSON.stringify({canonical:app.heldView.snapshot(),player:app.player.snapshot(),case:app.lessonVariant,member:app.lessonSubfixture,chapter:app.graphChapter?.id,object:app.objectTraceSelection,field:app.attributeSelection});
const key=(node,value,options={})=>{const event=new HarnessEvent('keydown',{key:value,...options});node.dispatchEvent(event);return event;};
const fields=app=>Array.from(app.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]'));
function check(id,name,run){
  try{const observations=run();report.checks.push({id,name,status:'passed',observations});}
  catch(error){report.checks.push({id,name,status:'failed',error:String(error.stack||error)});}
  save();
}

for(const initial of ['compact','full'])for(const lesson of ['lab-dnssec01','lab-dnssec15','lab-mcp09'])check('MC-R01','Repeated remounts, partial cursor, real chapter jumps and comparison: '+initial+'/'+lesson,()=>{
  const app=mount(initial);try{
    app.selectLabScenario(lesson);const position=Math.min(2,app.steps.length-1);
    app.player.inspectQueue(app.steps,{position,elapsed:app.player.durationFor(app.steps[position])*.37,kind:'demo'});
    const retained=preserved(app),queue=app.player.queue,observations=[];
    for(const mode of [initial,initial==='compact'?'full':'compact',initial,initial==='compact'?'full':'compact']){
      app.switchPresentation(mode);assert.equal(preserved(app),retained);assert.equal(app.player.queue,queue);
      const chapters=Array.from(app.labModel.chapters),buttons=Array.from(app.querySelectorAll('[data-lesson-chapter]'));
      assert.deepEqual(buttons.map(button=>button.dataset.lessonChapter),chapters.map(chapter=>chapter.id));
      for(let index=0;index<chapters.length;index++){
        assert.equal(buttons[index].disabled,!chapters[index].stepIds.length);
        assert.equal(buttons[index].getAttribute('aria-pressed'),String(chapters[index].id===app.graphChapter.id));
      }
      const comparison=app.querySelector('#chapter-token-comparison'),tokens=Array.from(app.labModel.chapterComparison||[]);
      for(const token of tokens)for(const value of [token.artifactId,token.issuer,token.resource])assert.ok(comparison.textContent.includes(value));
      observations.push({mode,chapterIds:buttons.map(button=>button.dataset.lessonChapter),disabled:buttons.map(button=>button.disabled),comparison:tokens.length?comparison.textContent:null,cursor:app.heldView.snapshot().cursor});
    }
    for(const chapter of Array.from(app.labModel.chapters).filter(chapter=>chapter.stepIds.length)){
      const index=app.steps.findIndex(step=>step.id===chapter.stepIds[0]);
      Array.from(app.querySelectorAll('[data-lesson-chapter]')).find(button=>button.dataset.lessonChapter===chapter.id).click();
      assert.equal(app.heldView.snapshot().cursor.eventIndex,index);assert.equal(app.heldView.snapshot().cursor.milestone,'complete');assert.equal(app.graphChapter.id,chapter.id);
    }
    return {initial,lesson,observations,jumpChapterIds:Array.from(app.labModel.chapters).filter(chapter=>chapter.stepIds.length).map(chapter=>chapter.id)};
  }finally{close(app);}
});

for(const [lesson,suffix]of [['lab-smb-multichannel-binding-success','mc-read-response'],['lab-smb-multichannel-binding-success','mc-read-response-unwrap'],['lab-smb-multichannel-binding-success','mc-read-accept'],['lab-mcp09',null]])check('MC-R02','Authored crypto override/fallback, incomplete prefix and detail transitions: '+lesson+'/'+suffix,()=>{
  const app=mount();try{
    app.selectLabScenario(lesson);app.setLearningDetail('crypto');
    const index=app.steps.findIndex(step=>suffix?step.id.endsWith(':'+suffix):!step.cryptoDetail),step=app.steps[index];assert.ok(index>=0);
    const expected=step.cryptoDetail||app.labModel.profile.cryptoDetail;assert.ok(expected);
    app.inspectSourceCursor({eventIndex:index,milestone:'before'});
    assert.ok(!app.refs['compact-data'].textContent.includes(expected));assert.equal(app.refs['compact-data'].querySelector('.payload-list'),null);
    app.inspectSourceCursor({eventIndex:index,milestone:'complete'});const retained=canonical(app),observations=[];
    for(const mode of ['compact','full','compact']){
      app.switchPresentation(mode);let node=mode==='compact'?app.refs['compact-data']:app.refs.inspector;
      assert.ok(node.textContent.includes(expected));app.setLearningDetail('fields');node=mode==='compact'?app.refs['compact-data']:app.refs.inspector;assert.ok(!node.textContent.includes(expected));
      app.setLearningDetail('crypto');node=mode==='compact'?app.refs['compact-data']:app.refs.inspector;assert.ok(node.textContent.includes(expected));assert.equal(canonical(app),retained);
      observations.push({mode,expectedTextPresent:true});
    }
    return {lesson,eventId:step.id,index,explanation:expected,fallback:!step.cryptoDetail,incompletePayloadWithheld:true,observations};
  }finally{close(app);}
});

for(const investigation of ['object','field'])for(const control of ['timeline','inspector'])check('MC-R03','Selected history action retains exact parent scope: '+investigation+'/'+control,()=>{
  const app=mount('full');try{
    if(investigation==='object')app.heldView.trace('account-password');else app.selectAttribute('clientIdApp',false);
    const parent=app.traceQueue,selection=investigation==='object'?app.objectTraceSelection:app.attributeSelection;assert.ok(parent.length>1);
    const completeLabel=investigation==='object'?'Exact object history: '+selection:'Field path: '+app.selectionName(selection);
    assert.equal(app.studyQueue().label,completeLabel);
    if(control==='timeline')app.refs.timeline.querySelector('[data-step="1"]').click();
    else{
      app.player.pause();
      if(investigation==='field')app.querySelector('#follow').click();
      assert.equal(app.inspection.type,'step');app.refs.inspector.querySelector('[data-replay]').click();
    }
    clock.frame();clock.frame(35);app.player.pause();
    const retained=preserved(app),queue=app.player.queue,row=queue[0],observations=[];
    const expected='Selected action replay within '+(investigation==='object'?'exact object history: '+selection:'field history: '+app.selectionName(selection));
    assert.equal(queue.length,1);assert.equal(app.player.kind,control==='timeline'?'trace-step':investigation==='object'?'step':'attribute-step');assert.ok(parent.includes(row));
    for(const mode of ['compact','full','compact']){
      app.switchPresentation(mode);assert.equal(preserved(app),retained);assert.equal(app.player.queue,queue);assert.equal(app.traceQueue,parent);
      const label=app.studyQueue().label;assert.match(label,investigation==='object'?/Selected action replay within exact object history/:/Selected action replay within field history/);
      assert.equal(label,expected);assert.notEqual(label,completeLabel);
      if(mode==='compact'){
        assert.ok(app.refs['compact-scope'].textContent.includes(label));assert.ok(app.refs['compact-queue-label'].textContent.includes(label));
        assert.equal(app.querySelectorAll('[data-compact-row]').length,1);assert.equal(app.refs['compact-current-title'].textContent,row.title);
      }
      observations.push({mode,label,cursor:app.heldView.snapshot().cursor,elapsed:app.player.elapsed,actionTitle:row.title,actionDetail:row.detail});
    }
    return {investigation,control,parentRows:parent.length,activeRows:queue.length,kind:app.player.kind,parentSelection:selection,completeLabel,observations};
  }finally{close(app);}
});

check('MC-R03','Parent-free inspector replay is not the complete journey',()=>{
  const app=mount('full');try{
    app.refs.inspector.querySelector('[data-replay]').click();clock.frame();clock.frame(35);app.player.pause();
    const retained=preserved(app),queue=app.player.queue,row=queue[0],observations=[];
    assert.equal(queue.length,1);assert.equal(app.player.kind,'step');assert.equal(app.objectTraceSelection,null);assert.equal(app.attributeSelection,null);
    for(const mode of ['compact','full','compact']){
      app.switchPresentation(mode);assert.equal(preserved(app),retained);assert.equal(app.player.queue,queue);
      const label=app.studyQueue().label;assert.equal(label,'Selected action replay');
      if(mode==='compact'){
        assert.ok(app.refs['compact-scope'].textContent.includes(label));assert.ok(app.refs['compact-queue-label'].textContent.includes(label));assert.equal(app.querySelectorAll('[data-compact-row]').length,1);
        assert.equal(app.refs['compact-current-title'].textContent,row.title);
      }
      observations.push({mode,label,cursor:app.heldView.snapshot().cursor,elapsed:app.player.elapsed});
    }
    app.querySelector('[data-compact-action="return"]').click();
    const journey=app.player.queue,returned=preserved(app);assert.deepEqual(journey,app.steps);assert.ok(journey.length>1);assert.equal(app.player.kind,'demo');
    for(const mode of ['full','compact']){
      app.switchPresentation(mode);assert.equal(preserved(app),returned);assert.equal(app.player.queue,journey);assert.equal(app.studyQueue().label,'Journey');
      if(mode==='compact')assert.equal(app.querySelectorAll('[data-compact-row]').length,journey.length);
    }
    return {control:'inspector',activeRows:queue.length,parentSelection:null,observations,returnedJourneyRows:journey.length,returnedLabel:app.studyQueue().label};
  }finally{close(app);}
});

for(const surface of ['index','action'])check('MC-R04','Inline field metadata and reading target; Full F2 still opens and returns: '+surface,()=>{
  const app=mount();try{
    let controls;
    if(surface==='index'){app.openFieldIndex();controls=fields(app);}
    else{const index=app.steps.findIndex(step=>step.fields?.length);app.inspectSourceCursor({eventIndex:index,milestone:'complete'});controls=Array.from(app.refs['compact-data'].querySelectorAll('[data-attribute]'));}
    assert.ok(controls.length);
    for(const control of controls){assert.equal(control.hasAttribute('aria-haspopup'),false);assert.equal(control.hasAttribute('aria-keyshortcuts'),false);assert.equal(control.getAttribute('aria-controls'),'compact-field-definition');}
    const control=controls[0],id=control.dataset.indexAttribute||control.dataset.attribute;control.focus();control.click();
    assert.equal(document.activeElement,app.refs['compact-field-definition']);assert.ok(app.refs['compact-field-definition'].textContent.includes(app.definition(id).meaning||app.definition(id).description));
    assert.equal(app.refs['attribute-popup'].hidden,true);app.switchPresentation('full');if(surface==='index')app.openFieldIndex();
    const full=Array.from((surface==='index'?app.refs['attribute-index-list']:app.refs.inspector).querySelectorAll(surface==='index'?'[data-index-attribute]':'[data-attribute]')).find(node=>(node.dataset.indexAttribute||node.dataset.attribute)===id);assert.ok(full);
    full.focus();key(full,'F2');assert.equal(app.refs['attribute-popup'].hidden,false);assert.ok(app.refs['attribute-popup'].contains(document.activeElement));
    key(document.activeElement,'Escape');assert.equal(app.refs['attribute-popup'].hidden,true);assert.ok(app.contains(document.activeElement));
    return {surface,fieldId:id,compactDestination:'compact-field-definition',compactReadingFocus:'region',fullPopupKeyboard:true,fullReturnConnected:true};
  }finally{close(app);}
});

for(const dismissal of ['close','Escape'])check('MC-R05','Inventory help opens inside, dismisses itself and restores connected trigger: '+dismissal,()=>{
  const app=mount();try{
    const outer=app.querySelector('[data-compact-disclosure="holdings"]');outer.setAttribute('open','');outer.dispatchEvent(new HarnessEvent('toggle'));
    const holding=app.heldView.snapshot().holdings.find(item=>item.artifactId==='account-password');assert.ok(holding);
    const owner=Array.from(app.querySelectorAll('[data-compact-owner]')).find(node=>node.dataset.compactOwner===holding.actorId);owner.setAttribute('open','');owner.dispatchEvent(new HarnessEvent('toggle'));
    Array.from(app.querySelectorAll('[data-holding-id]')).find(node=>node.dataset.holdingId===holding.holdingId).click();
    const trigger=app.querySelector('[data-held-help]');trigger.focus();trigger.click();assert.equal(app.heldView.helpOpen,true);assert.ok(app.querySelector('.held-help').contains(document.activeElement));
    const closeButton=app.querySelector('[data-held-help-close]');if(dismissal==='close')closeButton.click();else key(closeButton,'Escape');
    assert.equal(app.heldView.helpOpen,false);assert.equal(app.querySelector('.held-help'),null);assert.equal(outer.hasAttribute('open'),true);assert.equal(document.activeElement,app.querySelector('[data-held-help]'));assert.ok(app.contains(document.activeElement));
    return {dismissal,helpOpen:false,holdingsOpen:true,focusOnSurvivingTrigger:true};
  }finally{close(app);}
});

for(const pickerName of ['scenarioPicker','workspacePicker'])for(const initial of ['compact','full'])for(const method of ['keyboard','pointer'])check('MC-R06','Unfinished search/result survives '+method+' view activation: '+pickerName+'/'+initial,()=>{
  const app=mount(initial);try{
    const picker=app[pickerName],retained=canonical(app),scenario=app.labScenarioId;
    picker.input.focus();picker.input.value='kerberos';picker.input.dispatchEvent(new HarnessEvent('input'));key(picker.input,'End');
    const active=picker.input.getAttribute('aria-activedescendant');assert.ok(active);
    const target=app.querySelector('[data-presentation-choice="'+(initial==='compact'?'full':'compact')+'"]');
    if(method==='keyboard')key(picker.input,'Tab',{shiftKey:true});else target.dispatchEvent(new HarnessEvent('pointerdown'));
    picker.input.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:target}));target.focus();target.click();picker.input.focus();
    assert.equal(picker.input.value,'kerberos');assert.equal(picker.input.getAttribute('aria-activedescendant'),active);assert.equal(app.labScenarioId,scenario);assert.equal(canonical(app),retained);
    key(picker.input,'Escape');app.switchPresentation(initial);picker.input.focus();assert.equal(picker.input.value,'');assert.equal(canonical(app),retained);
    const emptyDraftVisits=[];
    for(const draft of ['','   ']){
      key(picker.input,'Escape');const selectedLabel=picker.input.value;assert.ok(selectedLabel.trim());
      picker.input.focus();assert.equal(picker.input.value,'');
      if(draft){picker.input.value=draft;picker.input.dispatchEvent(new HarnessEvent('input'));}
      const choice=app.querySelector('[data-presentation-choice="'+(app.presentationMode==='compact'?'full':'compact')+'"]');
      if(method==='keyboard')key(picker.input,'Tab',{shiftKey:true});else choice.dispatchEvent(new HarnessEvent('pointerdown'));
      picker.input.dispatchEvent(new HarnessEvent('focusout',{relatedTarget:choice}));choice.focus();choice.click();
      assert.equal(picker.input.getAttribute('aria-expanded'),'false');assert.equal(picker.input.value,selectedLabel);
      assert.equal(app.labScenarioId,scenario);assert.equal(canonical(app),retained);
      picker.input.focus();assert.equal(picker.input.value,'');assert.equal(picker.input.getAttribute('aria-expanded'),'true');
      emptyDraftVisits.push({draft,closedLabel:selectedLabel,closedSelectionPreserved:true,ordinaryReopenFresh:true});
    }
    return {picker:pickerName,initial,method,restoredQuery:'kerberos',activeResult:active,cancelNotResurrected:true,emptyDraftVisits};
  }finally{close(app);}
});

for(const lesson of ['basic-keycloak','core','lab-mcp09'])check('MC-R07','Finite field batches, definition-first order and explicit paused Follow/Return: '+lesson,()=>{
  const app=mount();try{
    app.selectLabScenario(lesson);app.openFieldIndex();assert.ok(fields(app).length>0&&fields(app).length<=40);
    const definition=app.refs['compact-field-definition'],index=app.refs['attribute-index'];assert.equal(definition.parentElement.children[1],definition);assert.equal(definition.parentElement.children[2],index);
    const selected=fields(app).find(node=>!node.classList.contains('is-unavailable'));assert.ok(selected);const id=selected.dataset.indexAttribute;
    selected.click();assert.equal(document.activeElement,definition);assert.ok(definition.textContent.includes(app.definition(id).name));
    definition.querySelector('[data-compact-field-trace]').click();assert.notEqual(app.player.status,'playing');assert.equal(document.activeElement,app.refs['compact-current-title']);assert.ok(app.querySelector('.compact-current').scrollCalls.length);
    const retained=canonical(app);app.querySelector('[data-compact-action="field-definition"]').click();assert.equal(document.activeElement,definition);assert.equal(canonical(app),retained);
    app.querySelector('[data-compact-action="return"]').click();assert.equal(app.attributeSelection,null);assert.equal(canonical(app),retained);assert.equal(document.activeElement,app.refs['compact-current-title']);
    app.querySelector('[data-compact-field-scope="global"]').click();assert.equal(fields(app).length,40);
    const globalSummary=app.refs['attribute-index-meta'].textContent;app.refs['compact-field-more'].click();assert.equal(fields(app).length,80);assert.equal(document.activeElement,fields(app)[40]);
    return {lesson,initialMaximum:40,globalFirstBatch:40,expandedBatch:80,globalSummary,definitionBeforeResults:true,pausedFollow:true,backDefinition:true,returnCursorPreserved:true};
  }finally{close(app);}
});

report.inputsAfter=captureInputs(root);report.inputsUnchanged=JSON.stringify(before)===JSON.stringify(report.inputsAfter);
if(!report.inputsUnchanged)report.checks.push({id:'input-binding',name:'All app/test/HTML inputs unchanged during collection',status:'failed'});
report.counts={attempted:report.checks.length,passed:report.checks.filter(check=>check.status==='passed').length,failed:report.checks.filter(check=>check.status==='failed').length};
report.status=report.counts.failed?'failed':'passed';report.finishedAt=new Date().toISOString();save();
console.log(JSON.stringify({mode:args.mode,status:report.status,counts:report.counts,inputsUnchanged:report.inputsUnchanged,out}));process.exitCode=report.counts.failed?1:0;
