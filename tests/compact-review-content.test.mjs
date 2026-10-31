import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, unmount, fixture, canonical, clock } from './compact-fixture.mjs';
import { projectHeldObjects } from '../src/held-object-state.js';

const chapterButtons = app => [...app.querySelectorAll('[data-lesson-chapter]')];
const actionData = app => app.presentationMode === 'compact' ? app.refs['compact-data'] : app.refs.inspector;
function studyState(app) {
  return {canonical:canonical(app),player:app.player.snapshot(),scenario:app.labScenarioId,variant:app.lessonVariant,member:app.lessonSubfixture,chapter:app.graphChapter?.id,field:app.attributeSelection,object:app.objectTraceSelection};
}
function assertChapters(app) {
  const chapters=app.labModel.chapters,buttons=chapterButtons(app);
  assert.deepEqual(buttons.map(button=>button.dataset.lessonChapter),chapters.map(chapter=>chapter.id));
  for(let index=0;index<chapters.length;index++) {
    assert.equal(buttons[index].disabled,chapters[index].stepIds.length===0);
    assert.equal(buttons[index].getAttribute('aria-pressed'),String(chapters[index].id===app.graphChapter.id));
  }
  const tokens=app.labModel.chapterComparison||[];
  if(tokens.length) {
    const rows=[...app.querySelector('#chapter-token-comparison').querySelectorAll('tbody tr')];
    assert.equal(rows.length,tokens.length);
    const held=app.heldView.snapshot().holdings;
    for(let index=0;index<tokens.length;index++) {
      const token=tokens[index],cells=rows[index].querySelectorAll('td');
      assert.ok(cells[0].textContent.includes(token.artifactId));
      assert.ok(cells[1].textContent.includes(token.issuer));
      assert.ok(cells[2].textContent.includes(token.resource));
      assert.match(cells[3].textContent,held.some(holding=>holding.artifactId===token.artifactId)?/representation is held/:/Not held/);
    }
  }
}

for(const initialMode of ['compact','full'])for(const lesson of ['lab-dnssec01','lab-dnssec15','lab-mcp09'])test('chapter navigation and credential comparison survive repeated '+initialMode+' remounts: '+lesson,()=>{
  const app=mount({mode:initialMode});try {
    app.selectLabScenario(lesson);
    const position=Math.min(2,app.steps.length-1),elapsed=app.player.durationFor(app.steps[position])*.37;
    app.player.inspectQueue(app.steps,{position,elapsed,kind:'demo'});
    assert.ok(app.player.snapshot().stepElapsed>0&&app.player.snapshot().stepElapsed<app.player.snapshot().duration);
    const before=studyState(app),queue=app.player.queue,source=app.scenarioSnapshot();
    for(const mode of [initialMode,initialMode==='compact'?'full':'compact',initialMode,initialMode==='compact'?'full':'compact']) {
      app.switchPresentation(mode);
      assertChapters(app);
      assert.deepEqual(studyState(app),before);
      assert.equal(app.player.queue,queue);
      assert.equal(app.scenarioSnapshot(),source);
    }
    for(const chapter of app.labModel.chapters.filter(chapter=>chapter.stepIds.length)) {
      const index=app.steps.findIndex(step=>step.id===chapter.stepIds[0]);
      chapterButtons(app).find(button=>button.dataset.lessonChapter===chapter.id).click();
      assert.deepEqual(app.heldView.snapshot().cursor,{eventIndex:index,milestone:'complete'});
      assert.equal(app.graphChapter.id,chapter.id);
      assert.deepEqual(app.heldView.snapshot().holdings,projectHeldObjects(app.heldView.compiled(),{eventIndex:index,milestone:'complete'}).holdings);
      assert.equal(app.lessonVariant,before.variant);
      assert.equal(app.lessonSubfixture,before.member);
      assertChapters(app);
    }
  }finally{unmount(app);}
});

for(const suffix of ['mc-read-response','mc-read-response-unwrap','mc-read-accept'])test('per-event cryptographic interpretation remains authored and prefix-scoped: '+suffix,()=>{
  const app=mount();try {
    app.selectLabScenario('lab-smb-multichannel-binding-success');app.setLearningDetail('crypto');
    const index=app.steps.findIndex(step=>step.id.endsWith(':'+suffix)),step=app.steps[index];
    assert.ok(index>=0&&step.cryptoDetail);
    app.inspectSourceCursor({eventIndex:index,milestone:'before'});
    assert.equal(actionData(app).textContent.includes(step.cryptoDetail),false);
    assert.equal(actionData(app).querySelector('.payload-list'),null);
    app.inspectSourceCursor({eventIndex:index,milestone:'complete'});
    const before=canonical(app);
    for(const mode of ['compact','full','compact']) {
      app.switchPresentation(mode);assert.ok(actionData(app).textContent.includes(step.cryptoDetail));
      app.setLearningDetail('fields');assert.equal(actionData(app).textContent.includes(step.cryptoDetail),false);
      app.setLearningDetail('crypto');assert.ok(actionData(app).textContent.includes(step.cryptoDetail));
      assert.deepEqual(canonical(app),before);
    }
  }finally{unmount(app);}
});

test('a completed MCP event uses the real profile cryptographic fallback without showing it at an incomplete prefix',()=>{
  const app=mount();try {
    app.selectLabScenario('lab-mcp09');app.setLearningDetail('crypto');
    const index=app.steps.findIndex(step=>!step.cryptoDetail),explanation=app.labModel.profile.cryptoDetail;
    assert.ok(index>=0&&explanation);
    app.inspectSourceCursor({eventIndex:index,milestone:'before'});
    assert.equal(actionData(app).textContent.includes(explanation),false);
    app.inspectSourceCursor({eventIndex:index,milestone:'complete'});
    for(const mode of ['compact','full','compact']) {
      app.switchPresentation(mode);assert.ok(actionData(app).textContent.includes(explanation));
    }
  }finally{unmount(app);}
});

test('crypto-detail view changes do not reveal an unreadable holder field or a future local check',()=>{
  const {app}=fixture();try {
    app.setLearningDetail('crypto');app.inspectSourceCursor({eventIndex:0,milestone:'received'});
    app.heldView.select(app.heldView.snapshot().holdings.find(holding=>holding.holdingId==='app-response'));
    app.compactView.render('selection');const before=canonical(app);
    for(const mode of ['compact','full','compact']) {
      app.switchPresentation(mode);
      const inspector=app.querySelector('#held-inspector');
      assert.ok(inspector.textContent.includes('compact-client'));
      assert.equal(inspector.textContent.includes('issuer-only-value'),false);
      assert.ok(inspector.textContent.includes('Not readable by this holder'));
      assert.equal(app.heldView.snapshot().observations.some(item=>item.result==='verified'),false);
      assert.deepEqual(canonical(app),before);
    }
  }finally{unmount(app);}
});

for(const investigation of ['object','field'])for(const control of ['timeline','inspector'])test('selected '+investigation+' history '+control+' action retains its parent scope and one-row paused replay',()=>{
  const app=mount({mode:'full'});try {
    if(investigation==='object')app.heldView.trace('account-password');else app.selectAttribute('clientIdApp',false);
    const parent=app.traceQueue,selection=investigation==='object'?app.objectTraceSelection:app.attributeSelection;
    assert.ok(parent.length>1);
    assert.match(app.studyQueue().label,investigation==='object'?/Exact object history/:/Field path/);
    const completeLabel=investigation==='object'?'Exact object history: '+selection:'Field path: '+app.selectionName(selection);
    assert.equal(app.studyQueue().label,completeLabel);
    if(control==='timeline')app.refs.timeline.querySelector('[data-step="1"]').click();
    else {
      app.player.pause();
      if(investigation==='field')app.querySelector('#follow').click();
      assert.equal(app.inspection.type,'step');
      app.refs.inspector.querySelector('[data-replay]').click();
    }
    clock.frame();clock.frame(35);app.player.pause();
    const queue=app.player.queue,before=studyState(app),row=queue[0];
    const expected='Selected action replay within '+(investigation==='object'?'exact object history: '+selection:'field history: '+app.selectionName(selection));
    assert.equal(queue.length,1);assert.equal(app.player.kind,control==='timeline'?'trace-step':investigation==='object'?'step':'attribute-step');
    assert.ok(parent.includes(row));
    for(const mode of ['compact','full','compact']) {
      app.switchPresentation(mode);assert.equal(app.player.queue,queue);assert.equal(app.traceQueue,parent);
      assert.deepEqual(studyState(app),before);
      const label=app.studyQueue().label;
      assert.match(label,investigation==='object'?/Selected action replay within exact object history/:/Selected action replay within field history/);
      if(investigation==='object')assert.ok(label.includes(selection));else assert.ok(label.includes(app.selectionName(selection)));
      assert.equal(label,expected);assert.notEqual(label,completeLabel);
      if(mode==='compact') {
        assert.ok(app.refs['compact-scope'].textContent.includes(label));
        assert.ok(app.refs['compact-queue-label'].textContent.includes(label));
        assert.equal(app.querySelectorAll('[data-compact-row]').length,1);
        assert.equal(app.refs['compact-current-title'].textContent,row.title);
      }
    }
  }finally{unmount(app);}
});

test('parent-free inspector action replay stays distinct from the complete journey through view switches',()=>{
  const app=mount({mode:'full'});try {
    app.refs.inspector.querySelector('[data-replay]').click();clock.frame();clock.frame(35);app.player.pause();
    const queue=app.player.queue,before=studyState(app),row=queue[0];
    assert.equal(queue.length,1);assert.equal(app.player.kind,'step');
    assert.equal(app.objectTraceSelection,null);assert.equal(app.attributeSelection,null);
    for(const mode of ['compact','full','compact']) {
      app.switchPresentation(mode);assert.equal(app.player.queue,queue);assert.deepEqual(studyState(app),before);
      assert.equal(app.studyQueue().label,'Selected action replay');
      if(mode==='compact') {
        assert.ok(app.refs['compact-scope'].textContent.includes('Selected action replay'));
        assert.ok(app.refs['compact-queue-label'].textContent.includes('Selected action replay'));
        assert.equal(app.querySelectorAll('[data-compact-row]').length,1);
        assert.equal(app.refs['compact-current-title'].textContent,row.title);
      }
    }
    app.querySelector('[data-compact-action="return"]').click();
    const journey=app.player.queue,returned=studyState(app);
    assert.deepEqual(journey,app.steps);assert.ok(journey.length>1);assert.equal(app.player.kind,'demo');
    for(const mode of ['full','compact']) {
      app.switchPresentation(mode);assert.equal(app.player.queue,journey);assert.deepEqual(studyState(app),returned);
      assert.equal(app.studyQueue().label,'Journey');
      if(mode==='compact')assert.equal(app.querySelectorAll('[data-compact-row]').length,journey.length);
    }
  }finally{unmount(app);}
});
