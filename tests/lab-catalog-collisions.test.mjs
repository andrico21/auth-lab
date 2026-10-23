import test from 'node:test';
import assert from 'node:assert/strict';
import {buildLabCatalogRegistry} from '../src/lab-catalog.js';

const group=(attributes={},scenarios=[])=>({source:'fixture-owned-module',attributes,scenarios,sources:[]});
const model=(id,eventIds=[],catalogAttributeIds=[])=>({id,ids:[],catalogAttributeIds,steps:()=>eventIds.map(id=>({id}))});

test('a lab field cannot shadow an existing core field',()=>{
  assert.throws(()=>buildLabCatalogRegistry([group({credential:{name:'different credential'}})],[{credential:{name:'core credential'}}]),RangeError);
});
test('a later model cannot replace an earlier model with the same identity',()=>{
  assert.throws(()=>buildLabCatalogRegistry([group({},[model('lab-one')]),group({},[model('lab-one')])]),RangeError);
});
test('distinct models cannot share an ambiguous canonical source event identity',()=>{
  assert.throws(()=>buildLabCatalogRegistry([group({},[model('lab-one',['same-event']),model('lab-two',['same-event'])])]),RangeError);
});
test('variant-only operational fields must exist before a case can be selected',()=>{
  assert.throws(()=>buildLabCatalogRegistry([group({},[model('lab-one',[],['undeclared-branch-field'])])]),RangeError);
});
