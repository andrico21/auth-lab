import {DNSSEC_ATTRIBUTES,DNSSEC_SOURCES} from './dnssec-fields.js';
import {dnssecLessonMeta} from './dnssec-lessons.js';
import {dnssecLookupCase} from './dnssec-lookup.js';
import {DNSSEC_RESOLUTION_CASE_BUILDERS} from './dnssec-resolution-cases.js';
import {DNSSEC_NETWORK_CASE_BUILDERS} from './dnssec-network-cases.js';
import {DNSSEC_DENIAL_CASE_BUILDERS} from './dnssec-denial-cases.js';
import {DNSSEC_SIGNING_CASE_BUILDERS} from './dnssec-signing-cases.js';
import {DNSSEC_ANCHOR_CASE_BUILDERS} from './dnssec-anchor-cases.js';
import {DNSSEC_PARENT_CASE_BUILDERS} from './dnssec-parent-cases.js';
import {DNSSEC_ZONE_CASE_BUILDERS} from './dnssec-zone-publication-cases.js';

function dnssecLabFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(dnssecLabFreeze);Object.freeze(value);}return value;}
const dnssecLabBuilders=Object.fromEntries(Object.entries({
  'lab-dnssec01':{
    'cold-secure':()=>dnssecLookupCase(1,'cold-secure'),
    'warm-answer-cache':()=>dnssecLookupCase(1,'warm-answer-cache',{warm:true}),
    'partial-chain-cache':()=>dnssecLookupCase(1,'partial-chain-cache',{cachedParent:true}),
    'tampered-answer':()=>dnssecLookupCase(1,'tampered-answer',{cachedParent:true,cachedChild:true,mutation:['192.0.2.82','192.0.2.81']}),
  },
  ...DNSSEC_RESOLUTION_CASE_BUILDERS,
  ...DNSSEC_NETWORK_CASE_BUILDERS,
  ...DNSSEC_DENIAL_CASE_BUILDERS,
  ...DNSSEC_SIGNING_CASE_BUILDERS,
  ...DNSSEC_ANCHOR_CASE_BUILDERS,
  ...DNSSEC_PARENT_CASE_BUILDERS,
  ...DNSSEC_ZONE_CASE_BUILDERS,
}).sort(([left],[right])=>left.localeCompare(right)));
export function buildDNSSECScenarioFixture(id,{variant='default'}={}){
  if(!Object.hasOwn(dnssecLabBuilders,id))throw new RangeError('Unknown DNSSEC fixture '+id);
  const meta=dnssecLessonMeta(Number(id.slice(-2))),selected=variant==='default'?meta.defaultCaseId:variant,builders=dnssecLabBuilders[id];
  if(!Object.hasOwn(builders,selected))throw new RangeError('Unknown DNSSEC case '+id+'/'+variant);
  const model=builders[selected]();
  model.variantChoices=meta.caseIds.map((caseId,index)=>({id:index===0?'default':caseId,caseId,label:caseId.replaceAll('-',' '),description:'Explicit fixed '+caseId+' input profile'}));
  model.withVariant=variantId=>buildDNSSECScenarioFixture(id,{variant:variantId});
  return dnssecLabFreeze(model);
}
export const DNSSECLAB_ATTRIBUTES=DNSSEC_ATTRIBUTES;
export const DNSSECLAB_SOURCES=DNSSEC_SOURCES;
export const DNSSECLAB_SCENARIOS=Object.keys(dnssecLabBuilders).map(id=>buildDNSSECScenarioFixture(id));
export const DNSSECLAB_CASE_BUILDERS=dnssecLabFreeze(Object.fromEntries(Object.entries(dnssecLabBuilders).map(([id,builders])=>[id,Object.fromEntries(Object.keys(builders).map(caseId=>[caseId,()=>buildDNSSECScenarioFixture(id,{variant:caseId})]))])));
