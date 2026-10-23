import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {buildMCPScenarioFixture} from '../src/mcp-auth-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildMCPHeldObjects} from '../src/held-object-mcp.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';
const worksheet=JSON.parse(readFileSync(new URL('../docs/next-expansion/mcp-worksheet.json',import.meta.url),'utf8'));
const pathValue=(value,path)=>path.split('.').reduce((record,key)=>record?.[key],value);

test('Every independently authored MCP default and compound input evaluates exact canonical checkpoints',()=>{
  for(const row of worksheet.scenarios)for(const expected of row.canonicalCases){
    const model=buildMCPScenarioFixture(row.runtimeId,{variant:expected.id}),steps=model.steps(),plan=buildMCPHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+model.variantId}),compiled=compileHeldObjects(plan,{model,steps});
    for(const predicate of expected.assertions){
      const at=predicate.at,eventIndex=at.end?steps.length-1:at.milestone==='initial'?-1:steps.findIndex(step=>step.id===at.stepId);
      assert.ok(eventIndex>=0||at.milestone==='initial',row.planId+'/'+expected.id+' missing '+at.stepId);
      const label=row.planId+'/'+expected.id+' '+(at.stepId||at.milestone||'end');
      if(predicate.target==='state')assert.deepEqual(pathValue(reconstructProtocolState(model,eventIndex),predicate.path),predicate.equals,label+' '+predicate.path);
      else{
        const snapshot=projectHeldObjects(compiled,{eventIndex,milestone:at.milestone||'complete'}),present=snapshot.holdings.some(h=>h.actorId===predicate.actorId&&h.artifactId===predicate.artifactId&&(!predicate.representation||h.representationId===predicate.representation));
        assert.equal(present,predicate.present,label+' '+predicate.artifactId);
      }
    }
  }
});
test('Unsupported MCP rows and fixture inputs reject instead of authorizing a default case',()=>{
  assert.throws(()=>buildMCPScenarioFixture('lab-mcp99'),RangeError);
  assert.throws(()=>buildMCPScenarioFixture('lab-mcp01',{variant:'unsupported-input'}),RangeError);
});
test('MCP proxy preserves separate downstream and upstream credential custody through delivery and acceptance',()=>{
  const model=buildMCPScenarioFixture('lab-mcp09'),steps=model.steps(),plan=buildMCPHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+model.variantId}),compiled=compileHeldObjects(plan,{model,steps});
  const artifacts=new Map(model.mcpInventory.artifacts.map(artifact=>[artifact.artifactId,artifact]));
  const incoming=artifacts.get(model.id+':downstream-access-g1'),upstream=artifacts.get(model.id+':upstream-access-g1');
  assert.notEqual(incoming.artifactId,upstream.artifactId);
  assert.equal(incoming.creator,'mcpA');assert.equal(upstream.creator,'mcpS');
  for(let eventIndex=-1;eventIndex<steps.length;eventIndex++){
    const frame=projectHeldObjects(compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
    assert.equal(frame.holdings.some(h=>h.actorId==='mcpC'&&h.artifactId===upstream.artifactId),false);
    assert.equal(frame.holdings.some(h=>h.actorId==='mcpU'&&h.artifactId===incoming.artifactId),false);
  }
  const at=key=>reconstructProtocolState(model,steps.findIndex(step=>step.id===model.id+':'+key)).mcp;
  assert.equal(at('downstream-request-recover').downstreamTokenAccepted,undefined);
  assert.equal(at('downstream-validate').downstreamTokenAccepted,true);
  assert.equal(at('upstream-result-wire-recover').upstreamResultAccepted,undefined);
  assert.equal(at('upstream-result-accept').upstreamResultAccepted,true);
  assert.equal(at('proxy-result-wire-recover').resultLearned,false);
  assert.equal(at('proxy-result-accept').resultLearned,true);
});
test('MCP refresh rotation preserves generation identity and keeps refresh credentials away from resource',()=>{
  const model=buildMCPScenarioFixture('lab-mcp07'),steps=model.steps(),plan=buildMCPHeldObjects({model,steps,actors:model.actors(),contextId:model.id+':'+model.variantId}),compiled=compileHeldObjects(plan,{model,steps});
  const rotation=steps.findIndex(step=>step.id.endsWith(':refresh-rotate')),receipt=steps.findIndex(step=>step.id.endsWith(':refresh-response-recover'));
  assert.equal(reconstructProtocolState(model,rotation).mcp.refreshGeneration1Valid,false);
  assert.equal(projectHeldObjects(compiled,{eventIndex:rotation,milestone:'complete'}).holdings.some(h=>h.actorId==='mcpC'&&h.artifactId.endsWith(':refresh-g2')),false);
  assert.equal(projectHeldObjects(compiled,{eventIndex:receipt,milestone:'complete'}).holdings.some(h=>h.actorId==='mcpC'&&h.artifactId.endsWith(':refresh-g2')),true);
  for(let eventIndex=-1;eventIndex<steps.length;eventIndex++)assert.equal(projectHeldObjects(compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'}).holdings.some(h=>h.actorId==='mcpR'&&h.artifactId.includes(':refresh-g')),false);
});
