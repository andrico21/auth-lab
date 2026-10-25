import {WEBLAB_ATTRIBUTES,WEBLAB_SOURCES,WEBLAB_SCENARIOS} from './web-api-lab.js';
import {LIFELAB_ATTRIBUTES,LIFELAB_SOURCES,LIFELAB_SCENARIOS} from './lifecycle-lab.js';
import {PROTLAB_ATTRIBUTES,PROTLAB_SOURCES,PROTLAB_SCENARIOS} from './protection-lab.js';
import {GRANTLAB_ATTRIBUTES,GRANTLAB_SOURCES,GRANTLAB_SCENARIOS} from './extended-grants-lab.js';
import {SAMLLAB_ATTRIBUTES,SAMLLAB_SOURCES,SAMLLAB_SCENARIOS} from './saml-advanced-lab.js';
import {BRANCHLAB_ATTRIBUTES,BRANCHLAB_SOURCES,BRANCHLAB_SCENARIOS} from './branching-lab.js';
import {ADLAB_ATTRIBUTES,ADLAB_SOURCES,ADLAB_SCENARIOS} from './kerberos-ad-lab.js';
import {CRYPTOLAB_ATTRIBUTES,CRYPTOLAB_SOURCES,CRYPTOLAB_SCENARIOS} from './kerberos-crypto-lab.js';
import {FORESTLAB_ATTRIBUTES,FORESTLAB_SOURCES,FORESTLAB_SCENARIOS} from './kerberos-forest-lab.js';
import {SSHLAB_ATTRIBUTES,SSHLAB_SOURCES,SSHLAB_SCENARIOS} from './ssh-access-lab.js';
import {WINDOWSLAB_ATTRIBUTES,WINDOWSLAB_SOURCES,WINDOWSLAB_SCENARIOS} from './windows-auth-lab.js';
import {SMBLAB_ATTRIBUTES,SMBLAB_SOURCES,SMBLAB_SCENARIOS} from './smb-access-lab.js';
import {SMBMULTI_ATTRIBUTES,SMBMULTI_SOURCES,SMBMULTI_SCENARIOS} from './smb-multichannel-lab.js';
import {NETWORKLAB_ATTRIBUTES,NETWORKLAB_SOURCES,NETWORKLAB_SCENARIOS} from './network-access-lab.js';
import {SPAKELAB_ATTRIBUTES,SPAKELAB_SOURCES,SPAKELAB_SCENARIOS} from './kerberos-spake-lab.js';
import {PAKELAB_ATTRIBUTES,PAKELAB_SOURCES,PAKELAB_SCENARIOS} from './pake-lab.js';
import {ATTRIBUTES} from './protocol-data.js';
import {VARIANT_ATTRIBUTES} from './architecture-variants.js';
import {FIDO_ATTRIBUTES} from './attribute-usage.js';
import {SAML_ATTRIBUTES} from './saml-data.js';
import {JWE_ATTRIBUTES} from './jwe-data.js';
import {SERVICE_ATTRIBUTES} from './service-account-data.js';
import {DEVICE_ATTRIBUTES} from './device-flow-data.js';
import {CIBA_ATTRIBUTES} from './ciba-data.js';
import {EXCHANGE_ATTRIBUTES} from './token-exchange-data.js';
import {NFSLAB_ATTRIBUTES,NFSLAB_SOURCES,NFSLAB_SCENARIOS} from './nfs-access-lab.js';
import {WINDOWSLOGONLAB_ATTRIBUTES,WINDOWSLOGONLAB_SOURCES,WINDOWSLOGONLAB_SCENARIOS} from './windows-logon-lab.js';
import {WINDOWSELEVLAB_ATTRIBUTES,WINDOWSELEVLAB_SOURCES,WINDOWSELEVLAB_SCENARIOS} from './windows-elevation-lab.js';
import {LINUXLOGONLAB_ATTRIBUTES,LINUXLOGONLAB_SOURCES,LINUXLOGONLAB_SCENARIOS} from './linux-logon-lab.js';
import {LINUXELEVLAB_ATTRIBUTES,LINUXELEVLAB_SOURCES,LINUXELEVLAB_SCENARIOS} from './linux-elevation-lab.js';
import {MACOSLOGONLAB_ATTRIBUTES,MACOSLOGONLAB_SOURCES,MACOSLOGONLAB_SCENARIOS} from './macos-logon-lab.js';
import {MACOSELEVLAB_ATTRIBUTES,MACOSELEVLAB_SOURCES,MACOSELEVLAB_SCENARIOS} from './macos-elevation-lab.js';
import {JWTLAB_ATTRIBUTES,JWTLAB_SOURCES,JWTLAB_SCENARIOS} from './jwt-validation-lab.js';
import {KUBERNETESAUTHLAB_ATTRIBUTES,KUBERNETESAUTHLAB_SOURCES,KUBERNETESAUTHLAB_SCENARIOS} from './kubernetes-auth-lab.js';
import {KUBERNETESRBACLAB_ATTRIBUTES,KUBERNETESRBACLAB_SOURCES,KUBERNETESRBACLAB_SCENARIOS} from './kubernetes-rbac-lab.js';
import {MCPLAB_ATTRIBUTES,MCPLAB_SOURCES,MCPLAB_SCENARIOS} from './mcp-auth-lab.js';
import {DNSSECLAB_ATTRIBUTES,DNSSECLAB_SOURCES,DNSSECLAB_SCENARIOS} from './dnssec-lab.js';

/** Reject ambiguity before any dictionary can silently overwrite an owner. */
export function buildLabCatalogRegistry(modules,reservedAttributeGroups){
  const attributes=Object.create(null),models=Object.create(null),scenarios=[],sources=[],fields=new Set(),events=new Set();
  if(reservedAttributeGroups)for(const group of reservedAttributeGroups)for(const id of Object.keys(group))fields.add(id);
  for(const group of modules){
    for(const [id,definition] of Object.entries(group.attributes)){
      if(fields.has(id))throw new RangeError('Duplicate field ID '+id+' in '+group.source);
      fields.add(id);attributes[id]=definition;
    }
    sources.push(...group.sources);
  }
  for(const group of modules)for(const model of group.scenarios){
    if(typeof model.id!=='string'||!model.id)throw new TypeError('Missing model ID in '+group.source);
    if(Object.hasOwn(models,model.id))throw new RangeError('Duplicate model ID '+model.id+' in '+group.source);
    for(const id of model.catalogAttributeIds||model.ids)if(!fields.has(id))throw new RangeError('Undeclared catalog field '+id+' in '+model.id);
    for(const step of model.steps()){
      if(typeof step.id!=='string'||!step.id)throw new TypeError('Missing event ID in '+model.id);
      if(events.has(step.id))throw new RangeError('Duplicate event ID '+step.id+' in '+model.id);
      events.add(step.id);
    }
    models[model.id]=model;scenarios.push(model);
  }
  return {attributes,sources,scenarios,models};
}
const labCatalogModules=[
  {source:'src/web-api-lab.js',attributes:WEBLAB_ATTRIBUTES,sources:WEBLAB_SOURCES,scenarios:WEBLAB_SCENARIOS},
  {source:'src/lifecycle-lab.js',attributes:LIFELAB_ATTRIBUTES,sources:LIFELAB_SOURCES,scenarios:LIFELAB_SCENARIOS},
  {source:'src/protection-lab.js',attributes:PROTLAB_ATTRIBUTES,sources:PROTLAB_SOURCES,scenarios:PROTLAB_SCENARIOS},
  {source:'src/extended-grants-lab.js',attributes:GRANTLAB_ATTRIBUTES,sources:GRANTLAB_SOURCES,scenarios:GRANTLAB_SCENARIOS},
  {source:'src/saml-advanced-lab.js',attributes:SAMLLAB_ATTRIBUTES,sources:SAMLLAB_SOURCES,scenarios:SAMLLAB_SCENARIOS},
  {source:'src/branching-lab.js',attributes:BRANCHLAB_ATTRIBUTES,sources:BRANCHLAB_SOURCES,scenarios:BRANCHLAB_SCENARIOS},
  {source:'src/kerberos-ad-lab.js',attributes:ADLAB_ATTRIBUTES,sources:ADLAB_SOURCES,scenarios:ADLAB_SCENARIOS},
  {source:'src/kerberos-crypto-lab.js',attributes:CRYPTOLAB_ATTRIBUTES,sources:CRYPTOLAB_SOURCES,scenarios:CRYPTOLAB_SCENARIOS},
  {source:'src/kerberos-forest-lab.js',attributes:FORESTLAB_ATTRIBUTES,sources:FORESTLAB_SOURCES,scenarios:FORESTLAB_SCENARIOS},
  {source:'src/ssh-access-lab.js',attributes:SSHLAB_ATTRIBUTES,sources:SSHLAB_SOURCES,scenarios:SSHLAB_SCENARIOS},
  {source:'src/windows-auth-lab.js',attributes:WINDOWSLAB_ATTRIBUTES,sources:WINDOWSLAB_SOURCES,scenarios:WINDOWSLAB_SCENARIOS},
  {source:'src/smb-access-lab.js',attributes:SMBLAB_ATTRIBUTES,sources:SMBLAB_SOURCES,scenarios:SMBLAB_SCENARIOS},
  {source:'src/smb-multichannel-lab.js',attributes:SMBMULTI_ATTRIBUTES,sources:SMBMULTI_SOURCES,scenarios:SMBMULTI_SCENARIOS},
  {source:'src/network-access-lab.js',attributes:NETWORKLAB_ATTRIBUTES,sources:NETWORKLAB_SOURCES,scenarios:NETWORKLAB_SCENARIOS},
  {source:'src/kerberos-spake-lab.js',attributes:SPAKELAB_ATTRIBUTES,sources:SPAKELAB_SOURCES,scenarios:SPAKELAB_SCENARIOS},
  {source:'src/pake-lab.js',attributes:PAKELAB_ATTRIBUTES,sources:PAKELAB_SOURCES,scenarios:PAKELAB_SCENARIOS},
  {source:'src/nfs-access-lab.js',attributes:NFSLAB_ATTRIBUTES,sources:NFSLAB_SOURCES,scenarios:NFSLAB_SCENARIOS},
  {source:'src/windows-logon-lab.js',attributes:WINDOWSLOGONLAB_ATTRIBUTES,sources:WINDOWSLOGONLAB_SOURCES,scenarios:WINDOWSLOGONLAB_SCENARIOS},
  {source:'src/windows-elevation-lab.js',attributes:WINDOWSELEVLAB_ATTRIBUTES,sources:WINDOWSELEVLAB_SOURCES,scenarios:WINDOWSELEVLAB_SCENARIOS},
  {source:'src/linux-logon-lab.js',attributes:LINUXLOGONLAB_ATTRIBUTES,sources:LINUXLOGONLAB_SOURCES,scenarios:LINUXLOGONLAB_SCENARIOS},
  {source:'src/linux-elevation-lab.js',attributes:LINUXELEVLAB_ATTRIBUTES,sources:LINUXELEVLAB_SOURCES,scenarios:LINUXELEVLAB_SCENARIOS},
  {source:'src/macos-logon-lab.js',attributes:MACOSLOGONLAB_ATTRIBUTES,sources:MACOSLOGONLAB_SOURCES,scenarios:MACOSLOGONLAB_SCENARIOS},
  {source:'src/macos-elevation-lab.js',attributes:MACOSELEVLAB_ATTRIBUTES,sources:MACOSELEVLAB_SOURCES,scenarios:MACOSELEVLAB_SCENARIOS},
  {source:'src/jwt-validation-lab.js',attributes:JWTLAB_ATTRIBUTES,sources:JWTLAB_SOURCES,scenarios:JWTLAB_SCENARIOS},
  {source:'src/kubernetes-auth-lab.js',attributes:KUBERNETESAUTHLAB_ATTRIBUTES,sources:KUBERNETESAUTHLAB_SOURCES,scenarios:KUBERNETESAUTHLAB_SCENARIOS},
  {source:'src/kubernetes-rbac-lab.js',attributes:KUBERNETESRBACLAB_ATTRIBUTES,sources:KUBERNETESRBACLAB_SOURCES,scenarios:KUBERNETESRBACLAB_SCENARIOS},
  {source:'src/mcp-auth-lab.js',attributes:MCPLAB_ATTRIBUTES,sources:MCPLAB_SOURCES,scenarios:MCPLAB_SCENARIOS},
  {source:'src/dnssec-lab.js',attributes:DNSSECLAB_ATTRIBUTES,sources:DNSSECLAB_SOURCES,scenarios:DNSSECLAB_SCENARIOS},
];
const labCatalogRegistry=buildLabCatalogRegistry(labCatalogModules,[ATTRIBUTES,VARIANT_ATTRIBUTES,FIDO_ATTRIBUTES,SAML_ATTRIBUTES,JWE_ATTRIBUTES,SERVICE_ATTRIBUTES,DEVICE_ATTRIBUTES,CIBA_ATTRIBUTES,EXCHANGE_ATTRIBUTES]);
export const LAB_ATTRIBUTES=labCatalogRegistry.attributes;
export const LAB_SOURCES=labCatalogRegistry.sources;
export const LEGACY_LAB_SCENARIOS=[...WEBLAB_SCENARIOS,...LIFELAB_SCENARIOS,...PROTLAB_SCENARIOS,...GRANTLAB_SCENARIOS,...SAMLLAB_SCENARIOS,...BRANCHLAB_SCENARIOS];
export const LAB_SCENARIOS=labCatalogRegistry.scenarios;
export const LAB_MODELS=labCatalogRegistry.models;
export const LAB_CATEGORIES=[...new Set(LAB_SCENARIOS.map(model=>model.category))];
export const LAB_TOPICS=Object.fromEntries(LAB_SCENARIOS.map(model=>['topic-'+model.id,{id:'topic-'+model.id,name:model.title,attributeIds:model.catalogAttributeIds||model.ids,summary:model.summary,labScenarioId:model.id}]));
const labCatalogAttributeModels=new Map();
for(const model of LAB_SCENARIOS)for(const id of [...(model.catalogAttributeIds||model.ids),'topic-'+model.id]){
  const models=labCatalogAttributeModels.get(id);
  if(!models)labCatalogAttributeModels.set(id,[model]);
  else if(models.at(-1)!==model)models.push(model);
}
export function labAttributeScenarios(id){const models=labCatalogAttributeModels.get(id);return models?models.slice():[];}
