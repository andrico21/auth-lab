import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {LAB_MODELS} from '../src/lab-catalog.js';
import {ATTRIBUTES} from '../src/protocol-data.js';
import {getAttributeUsage} from '../src/attribute-usage.js';
import {buildAttributeTrace} from '../src/attribute-trace.js';
import {buildHeldObjects} from '../src/held-objects.js';
import {heldObjectTrace,projectHeldObjects} from '../src/held-object-state.js';

const families=['nfs','windows-workstation','unix-workstation','jwt','kubernetes','mcp'];
const compiledCases=new Map();
for(const family of families){
  const worksheet=JSON.parse(readFileSync(new URL('../docs/next-expansion/'+family+'-worksheet.json',import.meta.url),'utf8'));
  for(const row of worksheet.rows||worksheet.scenarios)for(const fixture of row.nativeReplay||[]){
    test(row.runtimeId+' '+fixture.kind+' field and exact-object history retain the declared boundary '+fixture.at.stepId,()=>{
      const variant=fixture.caseId||'default',key=row.runtimeId+':'+variant;
      if(!compiledCases.has(key)){
        const base=LAB_MODELS[row.runtimeId],model=variant==='default'?base:base.withVariant(variant),steps=model.steps();
        compiledCases.set(key,{model,steps,compiled:buildHeldObjects({model,steps,actors:model.actors(),config:{},contextId:'independent-replay:'+key,choiceId:row.runtimeId})});
      }
      const {model,steps,compiled}=compiledCases.get(key),index=steps.findIndex(step=>step.id===fixture.at.stepId);
      assert.ok(index>=0,'The independently named source boundary exists');
      const expected=projectHeldObjects(compiled,{eventIndex:index,milestone:fixture.at.milestone});
      assert.ok(expected.holdings.some(h=>h.actorId===fixture.holding.actorId&&h.artifactId===fixture.holding.artifactId&&h.representationId===fixture.holding.representation),'The exact selected representation is held at the boundary');
      const exact=heldObjectTrace(compiled,fixture.holding.artifactId).findLast(step=>step.sourceStepId===fixture.at.stepId);
      assert.ok(exact,'Exact history must include the actual local use/check or protected receipt');
      assert.deepEqual(projectHeldObjects(compiled,exact.heldCursorEnd),expected,'Exact history reconstructs the full canonical prefix');
      const previous=ATTRIBUTES[fixture.fieldId];
      ATTRIBUTES[fixture.fieldId]=model.definitions()[fixture.fieldId];
      try{
        const field=buildAttributeTrace(getAttributeUsage(steps,fixture.fieldId),model.examples()).findLast(step=>step.sourceStepId===fixture.at.stepId);
        assert.ok(field,'Field replay must include the actual operation, not only inspect-only glossary context');
        assert.ok(field.traceActions.some(action=>action.instanceId===fixture.holding.artifactId),'The field occurrence is bound to this exact object, not another value with the same field name');
        assert.deepEqual(projectHeldObjects(compiled,{eventIndex:field.sourceIndex,milestone:fixture.at.milestone}),expected,'Field replay reconstructs the full canonical prefix');
      }finally{
        if(previous)ATTRIBUTES[fixture.fieldId]=previous;else delete ATTRIBUTES[fixture.fieldId];
      }
    });
  }
}
