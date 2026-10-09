import {WEBLAB_ATTRIBUTES,WEBLAB_SOURCES,WEBLAB_SCENARIOS} from './web-api-lab.js';
import {LIFELAB_ATTRIBUTES,LIFELAB_SOURCES,LIFELAB_SCENARIOS} from './lifecycle-lab.js';
import {PROTLAB_ATTRIBUTES,PROTLAB_SOURCES,PROTLAB_SCENARIOS} from './protection-lab.js';
import {GRANTLAB_ATTRIBUTES,GRANTLAB_SOURCES,GRANTLAB_SCENARIOS} from './extended-grants-lab.js';
import {SAMLLAB_ATTRIBUTES,SAMLLAB_SOURCES,SAMLLAB_SCENARIOS} from './saml-advanced-lab.js';
import {BRANCHLAB_ATTRIBUTES,BRANCHLAB_SOURCES,BRANCHLAB_SCENARIOS} from './branching-lab.js';

export const LAB_ATTRIBUTES={...WEBLAB_ATTRIBUTES,...LIFELAB_ATTRIBUTES,...PROTLAB_ATTRIBUTES,...GRANTLAB_ATTRIBUTES,...SAMLLAB_ATTRIBUTES,...BRANCHLAB_ATTRIBUTES};
export const LAB_SOURCES=[...WEBLAB_SOURCES,...LIFELAB_SOURCES,...PROTLAB_SOURCES,...GRANTLAB_SOURCES,...SAMLLAB_SOURCES,...BRANCHLAB_SOURCES];
export const LAB_SCENARIOS=[...WEBLAB_SCENARIOS,...LIFELAB_SCENARIOS,...PROTLAB_SCENARIOS,...GRANTLAB_SCENARIOS,...SAMLLAB_SCENARIOS,...BRANCHLAB_SCENARIOS];
export const LAB_MODELS=Object.fromEntries(LAB_SCENARIOS.map(model=>[model.id,model]));
export const LAB_CATEGORIES=[...new Set(LAB_SCENARIOS.map(model=>model.category))];
export const LAB_TOPICS=Object.fromEntries(LAB_SCENARIOS.map(model=>['topic-'+model.id,{id:'topic-'+model.id,name:model.title,attributeIds:model.ids,summary:model.summary,labScenarioId:model.id}]));
export function labAttributeScenarios(id){return LAB_SCENARIOS.filter(model=>model.ids.includes(id)||id==='topic-'+model.id);}
