import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {LAB_SCENARIOS,LAB_ATTRIBUTES} from '../src/lab-catalog.js';
import {LEARNING_PRESETS} from '../src/learning-presets.js';
import {filterScenarioOptions} from '../src/scenario-picker.js';
import {createScenarioSearchMetadata,validateScenarioSearchMetadata} from '../src/scenario-search-metadata.js';

const fixtures=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/search-fixtures.json',import.meta.url),'utf8'));
const coverage=JSON.parse(readFileSync(new URL('../docs/windows-protection-expansion/search-metadata-coverage.json',import.meta.url),'utf8'));
const core={id:'core',title:'Core lab',ids:[]};
const entries=[...LAB_SCENARIOS,...LEARNING_PRESETS,core];
const presetIds=new Set(LEARNING_PRESETS.map(row=>row.id));
const options=[...LEARNING_PRESETS,core,...LAB_SCENARIOS.filter(row=>!presetIds.has(row.id))].map(model=>({id:model.id,title:model.title,summary:model.summary,category:model.category,...createScenarioSearchMetadata(model,LAB_ATTRIBUTES)}));

test('SEARCH01 registry covers every actual scenario, preset and Core without pseudo-scenarios',()=>{
  assert.deepEqual(validateScenarioSearchMetadata(entries),{identities:328,registryEntries:328});
  assert.equal(LAB_SCENARIOS.length,317);
  assert.equal(LEARNING_PRESETS.length,12);
  assert.deepEqual(new Set(coverage.entries.map(row=>row.id)),new Set(entries.map(row=>row.id)));
  for(const model of entries){
    const metadata=createScenarioSearchMetadata(model,LAB_ATTRIBUTES);
    assert.equal(new Set(metadata.searchTags.map(tag=>tag.toLowerCase())).size,metadata.searchTags.length);
    assert.equal(metadata.searchTags.some(tag=>!tag.trim()),false);
  }
});

for(const fixture of fixtures.fixtures){
  test('SEARCH01 independent operator query: '+fixture.query,()=>{
    const results=filterScenarioOptions(options,fixture.query);
    assert.equal(new Set(results.map(row=>row.id)).size,results.length);
    if(fixture.first)assert.equal(results[0]?.id,fixture.first);
    for(const expected of fixture.required){
      const index=results.findIndex(row=>row.id===expected.id);
      assert.ok(index>=0,expected.id+' is discoverable');
      assert.ok(index<expected.maxRank,expected.id+' is within rank '+expected.maxRank+' (actual '+(index+1)+')');
      if(expected.variantId)assert.equal(results[index].variantId,expected.variantId);
      if(expected.matchingVariantIds){
        for(const id of expected.matchingVariantIds)assert.ok(results[index].matchingVariantIds?.includes(id),id+' is an explicit selectable case');
        assert.equal(results[index].variantId,undefined);
      }
    }
    for(const result of results){
      const model=entries.find(row=>row.id===result.id);
      for(const id of result.matchingVariantIds||[result.variantId].filter(Boolean))assert.ok(model.variantChoices.some(choice=>choice.id===id));
    }
  });
}

test('SEARCH01 metadata construction never evaluates models or constructs variants or object histories',()=>{
  const model={id:'lab-wlog04',title:'Offline login',variantChoices:[{id:'protected-user',label:'Protected users'}],steps(){throw new Error('steps must not run');},withVariant(){throw new Error('variants must not instantiate');},get objectHistory(){throw new Error('history must not expand');}};
  const metadata=createScenarioSearchMetadata(model);
  const option={id:model.id,title:model.title,...metadata};
  for(const query of ['offline','protected users offline','unknown'])filterScenarioOptions([option],query);
  assert.equal(filterScenarioOptions([option],'protected users offline')[0].variantId,'protected-user');
});


test('SEARCH01 preserves exact baseline title, ID and real attribute-name discovery',()=>{
  for(const id of ['lab-spa-api','lab-ad-pkinit-success','lab-net-eap-tls13-wired','lab-dnssec06','lab-wlog04']){
    const option=options.find(row=>row.id===id);
    assert.ok(filterScenarioOptions(options,id).some(row=>row.id===id));
    assert.ok(filterScenarioOptions(options,option.title).some(row=>row.id===id));
  }
  assert.ok(filterScenarioOptions(options,'CODE_VERIFIER').some(row=>row.id==='lab-mcp02'));
  assert.ok(filterScenarioOptions(options,'EAP-TLS').some(row=>row.id==='lab-net-eap-tls13-wired'));
});
