import test from 'node:test';
import assert from 'node:assert/strict';
import {DNSSEC_BASE_CLOCK,dnssecMaterial} from '../src/dnssec-fixtures.js';
import {dnssecCheckDenial} from '../src/dnssec-denial.js';

// Independently signed additive fixture inputs, not modified original tuples.
// Primary rules: RFC 6840 section 4.1; RFC 5155 section 8.3;
// RFC 6672 sections 2.3 and 5.3.4 distinguish DNAME owner from descendants.
const parent=['review-correction-nsec3-ancestor-delegation-0','review-correction-nsec3-ancestor-delegation-1'];
const dname={
  NSEC:['review-correction-nsec-dname-apex','review-correction-nsec-dname-branch','review-correction-nsec-dname-z'],
  NSEC3:['review-correction-nsec3-dname-0','review-correction-nsec3-dname-1']
};
function evaluate(ids,{qname,qtype='AAAA',zone='lab.example.',key='child-zsk-g1',...options}){
  const result=dnssecCheckDenial({qname,qtype,zone,now:DNSSEC_BASE_CLOCK,keys:[dnssecMaterial('keys',key)],
    proofs:ids.map(id=>({rrset:dnssecMaterial('rrsets',id),signatures:[dnssecMaterial('signatures',id+'-signature')]})),...options});
  assert.equal(result.checked,true);
  assert.equal(result.checks.length,ids.length);
  assert.ok(result.checks.every(check=>check.signature.valid),'Every unmodified independently signed proof must authenticate before its authority is evaluated');
  return result;
}

for(const qtype of ['A','AAAA','CNAME']){
  test(`NSEC3 parent matching hash cannot deny ${qtype} at the child cut`,()=>{
    const result=evaluate(parent,{qname:'lab.example.',qtype,zone:'example.',key:'example-zsk-g1'});
    assert.equal(result.valid,false);
    assert.equal(result.reason,'ancestor-delegation-not-denial-authority');
  });
}
test('the same signed parent NSEC3 matching hash is valid DS absence',()=>{
  for(const purpose of ['negative','no-ds']){
    const result=evaluate(parent,{qname:'lab.example.',qtype:'DS',zone:'example.',key:'example-zsk-g1',purpose});
    assert.equal(result.valid,true);
    assert.equal(result.kind,purpose==='no-ds'?'no-ds':'nodata');
  }
});
for(const qtype of ['A','AAAA','DS']){
  test(`a matched NSEC3 delegation is not an authoritative closest encloser for below-cut ${qtype}`,()=>{
    const result=evaluate(parent,{qname:'no.lab.example.',qtype,zone:'example.',key:'example-zsk-g1'});
    assert.equal(result.valid,false);
    assert.equal(result.reason,'ancestor-delegation-not-denial-authority');
  });
}
for(const [format,ids] of Object.entries(dname)){
  test(`${format} DNAME bitmap cannot deny descendants even with authenticated covering proofs`,()=>{
    for(const qtype of ['A','AAAA','DS']){
      const result=evaluate(ids,{qname:'no.branch.lab.example.',qtype});
      assert.equal(result.valid,false);
      assert.equal(result.reason,'dname-subtree-not-denial-authority');
    }
  });
  test(`${format} DNAME owner itself still permits authenticated absence of another type`,()=>{
    const result=evaluate(ids,{qname:'branch.lab.example.'});
    assert.equal(result.valid,true);
    assert.equal(result.kind,'nodata');
    assert.equal(evaluate(ids,{qname:'branch.lab.example.',qtype:'DNAME'}).valid,false);
  });
  test(`${format} signed DNAME bitmap can participate in denying an unrelated name`,()=>{
    const result=evaluate(ids,{qname:'cee.lab.example.',qtype:'A'});
    assert.equal(result.valid,true);
    assert.equal(result.kind,'nxdomain');
    assert.equal(result.closestEncloser,'lab.example.');
    assert.equal(result.wildcardCovered,true);
  });
}
