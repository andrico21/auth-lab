// Verification uses the application's actual scenarioSnapshot pipeline without
// rendering the expensive DOM catalog for every normalized Core configuration.
import {installHarness} from '../../tests/dom-harness.mjs';
export const heldFixtureHarness=installHarness();
const {AuthFlowStudio}=await import('../../src/app.js');
const {getPresetConfiguration,getLearningPreset,LEARNING_PRESETS,PROVIDER_PROFILES}=await import('../../src/learning-presets.js');
const {LAB_MODELS,LAB_SCENARIOS}=await import('../../src/lab-catalog.js');
const {RuntimeEnvironment}=await import('../../src/runtime-environment.js');
const {JOURNEYS}=await import('../../src/architecture-variants.js');
const {resolveActor}=await import('../../src/player.js');

export const HELD_OBJECT_CHOICES=[...LEARNING_PRESETS.map(preset=>preset.id),'core',...LAB_SCENARIOS.filter(model=>!LEARNING_PRESETS.some(preset=>preset.id===model.id)).map(model=>model.id)];

export function makeHeldObjectFixture(choiceId='core',overrides={}) {
  const preset=getLearningPreset(choiceId);
  const profile=preset?.providerSelectable?'entra':'generic';
  const app=new AuthFlowStudio();
  Object.assign(app,getPresetConfiguration(preset?choiceId:'basic-keycloak',profile),overrides,{
    labScenarioId:choiceId,runtimeEnvironment:new RuntimeEnvironment(),scenarioMemo:new Map(),
    showInternals:false,workspace:'web',family:'ad-ds',index:0,
  });
  if(Object.hasOwn(overrides,'binding'))app.samlBinding=overrides.binding;
  if(Object.hasOwn(overrides,'initiation'))app.samlInitiation=overrides.initiation;
  if(Object.hasOwn(overrides,'encryptAssertions'))app.assertionProtection=overrides.encryptAssertions?'encrypted':'signed';
  const model=app.labModel;
  if(model){app.upstream='single';app.architecture=model.architecture||'web';app.applicationProtocol=model.protocol==='saml'?'saml':'oidc';app.oidcFlow='authorization-code';app.mode='passkey';app.tokenProtection='signed';app.assertionProtection='signed';}
  const snapshot=app.scenarioSnapshot(),steps=snapshot.steps;
  const ids=[...new Set(steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(operation=>operation.actorId)]).map(id=>resolveActor(id,app.authenticator)))];
  const actors=model?.workspace?model.actors(app.protocolConfig()):Object.fromEntries(ids.map(id=>[id,app.actor(id)]));
  const config={...app.protocolConfig(),oidcFlow:app.oidcFlow,tokenProtection:app.tokenProtection,assertionProtection:app.assertionProtection};
  return {choiceId,model,steps,actors,config,contextId:choiceId+'@context-'+app.runtimeEnvironment.revision+':'+JSON.stringify(config),app};
}

// These are applicable normalized dimensions, not a pairwise sample. Disabled
// controls do not create additional supported possession configurations.
export function* heldCoreConfigurations() {
  const base=getPresetConfiguration('basic-keycloak');
  const human=['password','one-time-code','password-totp','passkey','passkey-totp'];
  for(const upstream of ['single','keycloak','external']){
    const profiles=upstream==='external'?PROVIDER_PROFILES:[PROVIDER_PROFILES[0]];
    for(const profile of profiles){
      const managed=upstream==='external'&&profile.id!=='generic';
      for(const mode of managed?['password']:human){
        for(const applicationProtocol of ['oidc','saml']){
          const brokerProtocols=upstream==='single'?['oidc']:managed?[profile.protocol]:['oidc','saml'];
          for(const brokerProtocol of brokerProtocols){
            const saml=applicationProtocol==='saml'||upstream!=='single'&&brokerProtocol==='saml';
            const appJwe=applicationProtocol==='oidc',brokerJwe=upstream!=='single'&&brokerProtocol==='oidc'&&profile.brokerTokenProtection.includes('jwe');
            const protections=['signed',...(appJwe?['app-jwe']:[]),...(brokerJwe?['broker-jwe']:[]),...(appJwe&&brokerJwe?['both-jwe']:[])];
            for(const architecture of applicationProtocol==='saml'?['web']:['native','web'])
              for(const authenticator of JOURNEYS[mode].passkey?['hello','yubikey']:['hello'])
                for(const binding of saml?['redirect','post']:['redirect'])
                  for(const initiation of applicationProtocol==='saml'?['sp','idp']:['sp'])
                    for(const encryptAssertions of saml?[false,true]:[false])
                      for(const tokenProtection of protections)
                        for(const providerManaged of upstream==='external'&&profile.id==='generic'&&mode==='password'?[false,true]:[managed])
                          yield {...base,mode,upstream,architecture,authenticator,applicationProtocol,brokerProtocol,binding,initiation,encryptAssertions,tokenProtection,providerProfileId:profile.id,providerManaged};
          }
        }
      }
    }
  }
  for(const mode of ['enrollment','totp-enrollment'])
    for(const upstream of ['single','keycloak','external'])
      for(const authenticator of mode==='enrollment'?['hello','yubikey']:['hello'])
        yield {...base,mode,architecture:'web',upstream,authenticator};
  for(const mode of ['fido-login','fido-enrollment'])
    for(const authenticator of ['hello','yubikey'])
      yield {...base,mode,architecture:'web',upstream:'single',authenticator};
  for(const oidcFlow of ['client-credentials','token-exchange'])
    yield {...base,mode:'passkey',oidcFlow,architecture:'web',upstream:'single'};
  for(const oidcFlow of ['device','ciba'])
    for(const architecture of oidcFlow==='device'?['native','web']:['web'])
      for(const mode of human)
        for(const authenticator of JOURNEYS[mode].passkey?['hello','yubikey']:['hello'])
          for(const tokenProtection of ['signed','app-jwe'])
            yield {...base,mode,oidcFlow,architecture,authenticator,upstream:'single',tokenProtection};
}

export const HELD_OBJECT_SCOPE_EXCLUSIONS=[
  {dimension:'Core SPA/BFF',reason:'SPA and BFF are separate shipped fixed fixtures, not additional Core architectures.'},
  {dimension:'Managed external factor internals',reason:'Provider-owned ceremonies are opaque; no password, OTP, authenticator store or achieved assurance is invented.'},
  {dimension:'Managed broker JWE',reason:'Named provider profiles support signed upstream identity results; app-side JWE remains independent.'},
  {dimension:'Human factors in client_credentials/token exchange',reason:'These single-realm confidential grants do not perform a fresh human ceremony.'},
  {dimension:'SAML/direct-FIDO native deployment',reason:'These journeys normalize to a web service provider/relying party.'},
  {dimension:'Enrollment encryption/grants',reason:'Enrollment is a verified-account ceremony, not a new SSO token response.'},
  {dimension:'Device/CIBA broker topology',reason:'These fixtures use one realm; CIBA authentication service is not another realm.'},
  {dimension:'Inapplicable control aliases',reason:'Disabled factor, request-binding, initiation, provider and protection dimensions normalize to the applicable journey, not phantom holdings.'},
];
