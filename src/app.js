import { ACTORS, ATTRIBUTES, FLOWS, SOURCES, LEARNING_NOTES } from './protocol-data.js';
import { JOURNEYS, ARCHITECTURES, UPSTREAMS, VARIANT_ATTRIBUTES, getJourneySteps, getActorOverrides, getExampleOverrides, getAttributeOverrides } from './architecture-variants.js';
import { ATTRIBUTE_TOPICS, getAttributeUsage, getAttributeContext, getAttributeIds, getStepAttributeOperations } from './attribute-usage.js';
import { buildAttributeTrace, TRACE_ACTION_LABELS } from './attribute-trace.js';
import { FIDO_ATTRIBUTES, FIDO_SOURCES } from './attribute-usage.js';
import { FIDO_JOURNEYS, getFidoSteps, getFidoActorOverrides, getFidoAttributeOverrides, getFidoExampleOverrides, applyFidoTransport } from './fido-direct.js';
import { SAML_ATTRIBUTES, SAML_SOURCES, SAML_TOPIC_IDS, getSamlSteps, getSamlActorOverrides, getSamlAttributeOverrides, getSamlExampleOverrides } from './saml-data.js';
import { JWE_ATTRIBUTES, JWE_SOURCES, JWE_TOPIC_IDS, applyJweProtection, getJweActorOverrides, getJweAttributeOverrides } from './jwe-data.js';
import { SERVICE_ATTRIBUTES, SERVICE_SOURCES, SERVICE_TOPIC_IDS, getServiceAccountSteps, getServiceAccountActorOverrides, getServiceAccountAttributeOverrides, getServiceAccountExampleOverrides } from './service-account-data.js';
import { DEVICE_ATTRIBUTES, DEVICE_SOURCES, DEVICE_TOPIC_IDS, getDeviceSteps, getDeviceActorOverrides, getDeviceAttributeOverrides, getDeviceExampleOverrides } from './device-flow-data.js';
import { CIBA_ATTRIBUTES, CIBA_SOURCES, CIBA_TOPIC_IDS, getCibaSteps, getCibaActorOverrides, getCibaAttributeOverrides, getCibaExampleOverrides } from './ciba-data.js';
import { EXCHANGE_ATTRIBUTES, EXCHANGE_SOURCES, EXCHANGE_TOPIC_IDS, getTokenExchangeSteps, getTokenExchangeActorOverrides, getTokenExchangeAttributeOverrides, getTokenExchangeExampleOverrides } from './token-exchange-data.js';
import { actorIllustration } from './actor-art.js';
import { FlowPlayer, resolveActor, pairKey, connectionSteps } from './player.js';
import { POSITIONS, getPositions, GRAPH_WIDTH, GRAPH_HEIGHT, connectionPath, channelCategory, validateLayoutRoutes } from './layout.js';
import { CARD_BOUNDS } from './layout.js';
import { placeStepOverlay } from './step-overlay-layout.js';
import { LAB_ATTRIBUTES, LAB_SOURCES, LAB_SCENARIOS, LAB_MODELS, LAB_CATEGORIES, LAB_TOPICS, labAttributeScenarios } from './lab-catalog.js';
import { ScenarioPicker, filterScenarioOptions } from './scenario-picker.js';
import { captureFocusTarget, resolveFocusTarget, isVisibleFocusTarget } from './focus-target.js';
import { LEARNING_PRESETS, PROVIDER_PROFILES, getLearningPreset, getProviderProfile, getPresetConfiguration, applyProviderProfile } from './learning-presets.js';
import { RuntimeEnvironment, RUNTIME_ENVIRONMENT_FIELDS, RUNTIME_PROVIDER_FIELDS } from './runtime-environment.js';

Object.assign(ATTRIBUTES,VARIANT_ATTRIBUTES,FIDO_ATTRIBUTES);
Object.assign(ATTRIBUTES,SAML_ATTRIBUTES,JWE_ATTRIBUTES);
Object.assign(ATTRIBUTES,SERVICE_ATTRIBUTES,DEVICE_ATTRIBUTES,CIBA_ATTRIBUTES,EXCHANGE_ATTRIBUTES);
Object.assign(ATTRIBUTES,LAB_ATTRIBUTES);
Object.assign(ATTRIBUTE_TOPICS,LAB_TOPICS);
const labCanonicalName=name=>String(name).replace(/\s*\([^)]*\)/g,'').trim();
for(const [topic,names]of Object.entries({clientIdentity:['client_id'],pkce:['code_verifier','code_challenge','code_challenge_method'],state:['state'],nonce:['nonce']})){
  ATTRIBUTE_TOPICS[topic].attributeIds.push(...Object.entries(LAB_ATTRIBUTES).filter(([,def])=>names.includes(labCanonicalName(def.name))&&(topic!=='nonce'||/OpenID|OIDC/.test(def.standard))).map(([id])=>id));
}
ATTRIBUTE_TOPICS.webauthn.attributeIds.push(...Object.entries(LAB_ATTRIBUTES).filter(([,def])=>/WebAuthn/.test(def.standard)).map(([id])=>id));
Object.assign(ATTRIBUTE_TOPICS,{
  saml:{id:'saml',name:'SAML · requests, assertions and trust',attributeIds:SAML_TOPIC_IDS,summary:'A service provider requests sign-in, the identity provider returns an assertion, and the recipient checks its signature and intended audience. XML Encryption can protect the assertion.'},
  jwe:{id:'jwe',name:'JWE · encrypt the signed ID token',attributeIds:JWE_TOPIC_IDS,summary:'The issuer signs the ID token, encrypts it with a fresh content key and protects that key for its recipient. The recipient decrypts locally, then verifies the inner signature and identity claims.'},
  serviceAccounts:{id:'serviceAccounts',name:'Service accounts · client_credentials',attributeIds:SERVICE_TOPIC_IDS,summary:'A confidential service authenticates itself and obtains an access token for its own service-account identity. No person, browser or MFA ceremony participates.'},
  deviceFlow:{id:'deviceFlow',name:'Device Authorization · two codes and polling',attributeIds:DEVICE_TOPIC_IDS,summary:'The limited-input client retains device_code. The person enters user_code in a separate browser, authenticates and approves. Polling observes the interval and obtains tokens only after approval.'},
  ciba:{id:'ciba',name:'CIBA · backchannel authentication and polling',attributeIds:CIBA_TOPIC_IDS,summary:'A confidential client identifies the person with login_hint. Realm A delegates verification and approval to its controlled authentication service; the consumption client polls using auth_req_id.'},
  tokenExchange:{id:'tokenExchange',name:'Token exchange · Standard V2',attributeIds:EXCHANGE_TOPIC_IDS,summary:'A confidential requester exchanges an existing access token inside the same realm. This example explicitly enforces downscoping; the original token retains its own validity.'},
});

const advancedFlowModels={
  'client-credentials':{title:'Service account · client_credentials',summary:'The service authenticates as itself and receives a token with its configured service-account permissions.',steps:getServiceAccountSteps,actors:getServiceAccountActorOverrides,definitions:getServiceAccountAttributeOverrides,examples:getServiceAccountExampleOverrides,ids:SERVICE_TOPIC_IDS,hasPerson:false},
  device:{title:'Device Authorization Flow',summary:'A separate browser authenticates the person and approves the device while the requesting application polls.',steps:getDeviceSteps,actors:getDeviceActorOverrides,definitions:getDeviceAttributeOverrides,examples:getDeviceExampleOverrides,ids:DEVICE_TOPIC_IDS,hasPerson:true},
  ciba:{title:'CIBA · Poll delivery',summary:'The consumption client makes a backchannel request. A controlled authentication service verifies the person on a separate device.',steps:getCibaSteps,actors:getCibaActorOverrides,definitions:getCibaAttributeOverrides,examples:getCibaExampleOverrides,ids:CIBA_TOPIC_IDS,hasPerson:true},
  'token-exchange':{title:'Token exchange · Standard V2',summary:'A backend exchanges an existing Realm A access token for a configured API target under an explicit downscope policy.',steps:getTokenExchangeSteps,actors:getTokenExchangeActorOverrides,definitions:getTokenExchangeAttributeOverrides,examples:getTokenExchangeExampleOverrides,ids:EXCHANGE_TOPIC_IDS,hasPerson:false},
};
const grantTopicFlows={serviceAccounts:'client-credentials',deviceFlow:'device',ciba:'ciba',tokenExchange:'token-exchange'};

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const iconPaths = {
  play:'M8 5v14l11-7z', pause:'M8 5v14M16 5v14', reset:'M3 10a9 9 0 1 1 2 8M3 4v6h6',
  search:'M21 21l-5-5M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0', previous:'m14 6-6 6 6 6', next:'m10 6 6 6-6 6', close:'m6 6 12 12M18 6 6 18',
  sun:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1',
  book:'M4 4h6a3 3 0 0 1 2 3 3 3 0 0 1 3-3h5v16h-5a3 3 0 0 0-3 2 3 3 0 0 0-3-2H4zM12 7v15',
  arrow:'M5 12h14m-5-5 5 5-5 5', check:'m5 12 4 4 10-10', link:'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2',
  info:'M12 11v6M12 7h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0', shield:'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z'
};
const uiIcon = (name, filled=false) => `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="${filled?'currentColor':'none'}" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${iconPaths[name]||iconPaths.info}"/></svg>`;
const channelLabels = {browser:'Browser navigation',server:'Server exchange',passkey:'Passkey proof',human:'User interaction',local:'Local processing'};
const modeMetadata = {...JOURNEYS,...FIDO_JOURNEYS};
const ATTR_KIND = {static:'Configured / stored',generated:'Creates / computes',received:'Receives / verifies'};

export class AuthFlowStudio extends HTMLElement {
  connectedCallback() {
    if(this.initialized) return;
    this.initialized=true;
    Object.assign(this,getPresetConfiguration('basic-keycloak'));this.index=0;
    this.labScenarioId='basic-keycloak';this.catalogQuery='';this.customLayouts={};this.moveParticipants=false;this.dragState=null;
    this.runtimeEnvironment=new RuntimeEnvironment();this.scenarioMemo=new Map();
    this.attributeSelection=null;this.attributeQuery='';this.traceQueue=[];this.traceIndex=0;this.activeSteps=null;
    this.inspection={type:'step'}; this.visited=new Set(); this.packetIdentity='';
    this.theme='dark'; this.closeTimer=null; this.attributeTimer=null;this.showStepAttributes=true;this.stepOverlayIdentity='';this.lastRunningSpeed=1;
    this.player=new FlowPlayer();
    this.unsubscribe=this.player.subscribe(event=>this.onPlayer(event));
    this.innerHTML=this.shell();
    this.refs={};
    ['studio','graph','connections','actors','packet','packet-name','packet-value','packet-count','timeline','inspector','inspector-heading','progress','story','play','speed','speed-label','seek','seek-position','mode','authenticator','architecture','upstream','status','actor-popup','attribute-popup','toast','attribute-index','attribute-search','attribute-index-list','attribute-topics','attribute-focus','attribute-index-meta','attribute-index-empty','app-protocol','broker-protocol','saml-binding','saml-initiation','token-protection','assertion-protection','protocol-summary','step-attributes','step-attributes-tether','show-step-attributes','oidc-flow','lab-scenario','lab-catalog','lab-search','lab-cards','lab-support','move-participants','provider-settings','provider-profile','provider-note','environment-fields','environment-errors','environment-status'].forEach(id=>this.refs[id]=this.querySelector('#'+id));
    this.refs['show-step-attributes'].checked=this.showStepAttributes;
    const presetIds=new Set(LEARNING_PRESETS.map(preset=>preset.id));
    const pickerOptions=[...LEARNING_PRESETS.map(preset=>({id:preset.id,title:preset.title,category:preset.category,summary:preset.summary,searchText:[preset.title,preset.summary,preset.id,preset.config.applicationProtocol,preset.config.oidcFlow,...(LAB_MODELS[preset.modelId]?.ids||[]).map(id=>[ATTRIBUTES[id]?.name,ATTRIBUTES[id]?.standard].join(' ')),LAB_MODELS[preset.modelId]?.category||'',LAB_MODELS[preset.modelId]?.status||'',preset.id==='basic-keycloak'?'ordinary standard default oauth logon login pkce':preset.id==='corporate-external'?'entra microsoft okta amazon cognito aws federation corporate':'' ].join(' ')})),{id:'core',title:'Core lab · configurable sign-in, SAML, FIDO and grants',category:'Custom configuration',summary:'Explore your own combination using Advanced configuration.',searchText:'core configurable sign-in login keycloak native localhost web oidc oauth saml fido webauthn passkey yubikey windows hello password totp mfa authorization code pkce service account device ciba token exchange'},...LAB_SCENARIOS.filter(model=>!presetIds.has(model.id)).map(model=>({id:model.id,title:model.title,category:model.category,summary:model.summary,searchText:[model.title,model.summary,model.category,model.status,model.protocol||'oidc',...model.ids.map(id=>[ATTRIBUTES[id]?.name,ATTRIBUTES[id]?.standard].join(' '))].join(' ')}))];
    this.scenarioPicker=new ScenarioPicker(this.querySelector('#lab-scenario-picker'),pickerOptions,id=>this.selectLabScenario(id),this);
    this.bind(); this.renderAll();
  }
  disconnectedCallback() { this.player?.stop(false); this.unsubscribe?.();this.scenarioPicker?.destroy();window.removeEventListener('pagehide',this.environmentPageHide);window.removeEventListener('pageshow',this.environmentPageShow); clearTimeout(this.closeTimer); clearTimeout(this.attributeTimer); }
  get learningPreset() {return getLearningPreset(this.labScenarioId);}
  get labModel() {return LAB_MODELS[this.learningPreset?.modelId||this.labScenarioId]||null;}
  get providerProfile() {return getProviderProfile(this.providerProfileId)||getProviderProfile('generic');}
  get providerOwnsAuthentication() {return this.upstream==='external'&&!this.labModel&&!this.isDirectFido&&!this.isAdvancedFlow&&(this.providerManaged||this.providerProfileId!=='generic');}
  canProbeJourney(mode,upstream=this.upstream) {return !(upstream==='external'&&(this.providerManaged||this.providerProfileId!=='generic')&&modeMetadata[mode]?.enrollment);}
  get environmentOptions() {return {profileId:this.providerProfile.id,providerProfile:this.providerProfile,architecture:this.architecture,executionEnvironment:this.advancedFlow?.executionEnvironment||(this.isDirectFido?'browser':this.architecture==='native'?'native':'server'),clientActor:this.advancedFlow?.clientActor||'app',upstream:this.upstream,directFido:this.isDirectFido};}
  get isDirectFido() {return !this.labModel&&!!modeMetadata[this.mode]?.directFido;}
  get advancedFlow() {return this.labModel||advancedFlowModels[this.oidcFlow]||null;}
  get isAdvancedFlow() {return !!this.advancedFlow;}
  get isSingleRealm() {return !this.isDirectFido&&this.upstream==='single';}
  get isUsingSaml() {return !this.labModel&&!this.isDirectFido&&(this.applicationProtocol==='saml'||this.upstream!=='single'&&this.brokerProtocol==='saml');}
  protocolConfig(mode=this.mode) {return {mode,architecture:this.architecture,upstream:this.upstream,authenticator:this.authenticator,applicationProtocol:this.applicationProtocol,brokerProtocol:this.brokerProtocol,binding:this.samlBinding,initiation:this.samlInitiation,encryptAssertions:this.assertionProtection==='encrypted',providerManaged:this.providerManaged,providerProfileId:this.providerProfileId};}
  journeyFor(mode=this.mode,overrides={}) {
    return this.scenarioSnapshot(mode,overrides).steps;
  }
  scenarioSnapshot(mode=this.mode,overrides={}) {
    const config={...this.protocolConfig(mode),...overrides};
    const signature=JSON.stringify([this.labScenarioId,config,this.oidcFlow,this.tokenProtection,this.runtimeEnvironment.revision]);
    if(this.scenarioMemo.has(signature))return this.scenarioMemo.get(signature);
    const raw=this.baseJourneyFor(mode,overrides);
    const saml=config.applicationProtocol==='saml'||config.upstream!=='single'&&config.brokerProtocol==='saml';
    const sourceActors=Object.fromEntries(Object.entries(ACTORS).map(([id,a])=>[id,{...a,...getActorOverrides(config.architecture,config.upstream)[id],...(saml?getSamlActorOverrides(config)[id]:{})}]));
    const provider=!this.labModel&&config.upstream==='external'&&!FIDO_JOURNEYS[mode]&&!(advancedFlowModels[config.oidcFlow||this.oidcFlow])?applyProviderProfile(raw,sourceActors,config.providerProfileId,config):{steps:raw,actors:{},attributeOverrides:{},exampleOverrides:{}};
    const snapshot={...provider,steps:this.runtimeEnvironment.projectSteps(provider.steps,{...this.environmentOptions,architecture:config.architecture,upstream:config.upstream,directFido:!!FIDO_JOURNEYS[mode]})};
    if(this.scenarioMemo.size>80)this.scenarioMemo.clear();this.scenarioMemo.set(signature,snapshot);return snapshot;
  }
  baseJourneyFor(mode=this.mode,overrides={}) {
    if(this.labModel&&!overrides.forceCore)return this.labModel.steps({...this.protocolConfig(mode),...overrides});
    if(FIDO_JOURNEYS[mode])return getFidoSteps(mode,this.authenticator);
    const config={...this.protocolConfig(mode),...overrides};
    const model=advancedFlowModels[config.oidcFlow||this.oidcFlow];
    if(model&&!modeMetadata[mode]?.enrollment)return applyJweProtection(model.steps(config),{protection:config.tokenProtection||this.tokenProtection,authenticator:config.authenticator});
    const steps=(config.applicationProtocol==='saml'||config.upstream!=='single'&&config.brokerProtocol==='saml')?getSamlSteps(config):applyFidoTransport(getJourneySteps(mode,config.architecture,config.upstream),config.authenticator);
    return applyJweProtection(steps,{protection:config.tokenProtection||this.tokenProtection,authenticator:config.authenticator});
  }
  get steps() { return this.activeSteps||this.journeyFor(); }
  get visibleSteps() {return this.attributeSelection?this.traceQueue:this.steps;}
  get visibleIndex() {return this.attributeSelection?this.traceIndex:this.index;}
  get currentStep() { return this.visibleSteps[this.visibleIndex]; }
  get layoutKey() {return this.labModel?.id||(this.learningPreset?this.learningPreset.id:'core-'+this.architecture);}
  get positions() {
    const positions={...getPositions(this.architecture),...(this.customLayouts[this.layoutKey]||{})};
    if(!this.labModel&&!this.learningPreset)return positions;
    const ids=new Set(this.steps.flatMap(s=>[this.nodeId(s.from),this.nodeId(s.to),...(s.attributeOperations||[]).map(op=>this.nodeId(op.actorId))]));
    return Object.fromEntries(Object.entries(positions).filter(([id])=>ids.has(id)));
  }
  actor(id) {
    const key=resolveActor(id,this.authenticator),overrides=this.isDirectFido?getFidoActorOverrides(this.mode,this.authenticator):getActorOverrides(this.architecture,this.upstream),a={...ACTORS[key],...overrides[key],...(this.isUsingSaml?getSamlActorOverrides(this.protocolConfig())[key]:{}),...(this.isAdvancedFlow?this.advancedFlow.actors(this.protocolConfig())[key]:{}),...this.scenarioSnapshot().actors[key]};
    const extras=this.isAdvancedFlow||this.isDirectFido||this.applicationProtocol==='saml'?[]:key==='browser'?['clientIdApp','codeChallenge','codeChallengeMethod']:key==='realmA'?['clientIdApp','codeChallenge','codeChallengeMethod','codeVerifier']:[];
    a.attributes=[...a.attributes,...extras.filter(field=>!a.attributes.some(item=>item.id===field)).map(field=>({id:field,kind:'received'}))];
    const fidoFields=this.labModel||this.providerOwnsAuthentication?[]:this.authenticator==='yubikey'&&key==='browser'?[['ctapGetAssertion','generated'],['ctapMakeCredential','generated'],['ctapResidentKey','generated'],['pinUvAuthProtocol','static'],['pinUvAuthToken','received'],['pinUvAuthParam','generated']]:key==='yubikey'?[['ctapGetAssertion','received'],['ctapMakeCredential','received'],['ctapResidentKey','received'],['transports','static'],['pinUvAuthProtocol','static'],['pinUvAuthToken','generated'],['pinUvAuthParam','received']]:[];
    a.attributes.push(...fidoFields.filter(([field])=>!a.attributes.some(item=>item.id===field)).map(([id,kind])=>({id,kind})));
    if(!this.labModel&&this.authenticator==='yubikey'&&['browser','yubikey'].includes(key)){
      const responseIds=new Set(['ctapCredential','ctapCredentialId','ctapAuthData','ctapSignature','ctapUser','ctapFmt','ctapAttStmt']);
      const activeIds=new Set(this.steps.flatMap(step=>step.fields||[]));
      for(const field of responseIds)if(activeIds.has(field)&&!a.attributes.some(item=>item.id===field))a.attributes.push({id:field,kind:key==='yubikey'?'generated':'received'});
      const conversion=this.steps.find(step=>/api-conversion$/.test(step.ctapOperation||''));
      if(conversion){
        const registering=conversion.ctapOperation==='registration-api-conversion';
        if(key==='yubikey')a.attributes=a.attributes.filter(item=>!['signature','userHandle',...(registering?['credentialId']:[])].includes(item.id)).map(item=>!registering&&['privateKey','credentialPublicKey','credentialId'].includes(item.id)?{...item,kind:'static'}:item);
        else{
          const constructed=new Set(registering?['credentialId','authenticatorData','attestationObject']:['credentialId','authenticatorData','signature','userHandle']);
          a.attributes=a.attributes.map(item=>constructed.has(item.id)?{...item,kind:'generated'}:item);
          for(const field of constructed)if(!a.attributes.some(item=>item.id===field))a.attributes.push({id:field,kind:'generated'});
        }
      }
    }
    if(!this.isDirectFido){const addition=getJweActorOverrides({protection:this.tokenProtection,steps:this.steps,authenticator:this.authenticator})[key];if(addition){a.attributes.push(...(addition.attributes||[]).filter(field=>!a.attributes.some(item=>item.id===field.id)));a.notes=[...(a.notes||[]),...(addition.notes||[])];}}
    return this.runtimeEnvironment.projectActor(a,this.environmentOptions);
  }
  definition(id) {
    const signature=JSON.stringify([this.mode,this.authenticator,this.architecture,this.upstream,this.applicationProtocol,this.brokerProtocol,this.samlBinding,this.samlInitiation,this.tokenProtection,this.assertionProtection,this.oidcFlow,this.labScenarioId,this.providerProfileId,this.providerManaged,this.runtimeEnvironment.revision]);
    if(this.definitionMemo?.signature!==signature){
      const overrides={...(this.isDirectFido?getFidoAttributeOverrides(this.mode):getAttributeOverrides(this.architecture,this.upstream)),...(this.isUsingSaml?getSamlAttributeOverrides(this.protocolConfig()):{}),...(this.isAdvancedFlow?this.advancedFlow.definitions(this.protocolConfig()):{}),...(!this.isDirectFido?getJweAttributeOverrides({protection:this.tokenProtection,steps:this.steps}):{}),...this.scenarioSnapshot().attributeOverrides};
      this.definitionMemo={signature,overrides,values:new Map()};
    }
    if(this.definitionMemo.values.has(id))return this.definitionMemo.values.get(id);
    const definition={...ATTRIBUTES[id],...this.definitionMemo.overrides[id]};
    if(modeMetadata[this.mode]?.passkey&&id==='clientDataJSON'&&modeMetadata[this.mode]?.enrollment)definition.example=String(definition.example).replaceAll('webauthn.get','webauthn.create');
    const projected=this.runtimeEnvironment.projectDefinition(id,definition,this.environmentOptions);this.definitionMemo.values.set(id,projected);
    return projected;
  }
  nodeId(id) { return resolveActor(id,this.authenticator); }
  illustration(id) {return actorIllustration(this.labModel?.actors(this.protocolConfig())[id]?.art|| (id==='realmB'&&(this.upstream==='external'||this.oidcFlow==='ciba')?'external':id==='app'&&this.architecture==='web'?'webapp':id));}
  shell() {
    return `<main class="studio" id="studio" data-theme="dark">
      <header class="app-header">
        <div class="brand"><span class="brand-mark">${uiIcon('shield')}</span><div><div class="brand-title">Auth Flow Studio</div><div class="brand-subtitle">Trust, made visible</div></div></div>
        <div class="header-actions"><span class="lab-label">INTERACTIVE LEARNING LAB</span><button class="button quiet" id="index-open">${uiIcon('book')}<span>Attribute index</span></button><button class="button quiet" id="glossary-open"><span>Field guide</span></button><button class="icon-button" id="theme-toggle" aria-label="Switch color theme">${uiIcon('sun')}</button></div>
      </header>
      <section class="hero"><div class="eyebrow">OIDC · SAML · JWE · FIDO2 · MFA</div><h1>Follow every proof.<br><span>Understand every handoff.</span></h1><p>Explore sign-in, protected APIs, token lifecycle and protocol variants. Follow the whole journey, or trace one attribute.</p></section>
      <section class="quick-start" id="quick-start" aria-label="Ready-made corporate scenarios"><div class="quick-start-heading"><h2>Choose a ready-made scenario</h2><p>Choose a scenario, then press Play. The settings are already selected.</p></div><div class="quick-start-grid">${[...LEARNING_PRESETS.filter(p=>['basic-keycloak','basic-saml'].includes(p.id)),...LEARNING_PRESETS.filter(p=>p.common&&!['basic-keycloak','basic-saml'].includes(p.id))].map(p=>`<button class="quick-preset" data-learning-preset="${p.id}" aria-pressed="${p.id===this.labScenarioId}"><strong>${escapeHtml(p.title)}</strong><span>${escapeHtml(p.summary)}</span></button>`).join('')}</div></section>
      <section class="lab-navigation"><div class="select-field scenario-picker" id="lab-scenario-picker"><label for="lab-scenario-search">Universal lab scenario</label><div class="scenario-picker-control"><span class="scenario-picker-icon" aria-hidden="true">${uiIcon('search')}</span><input id="lab-scenario-search" type="search" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="lab-scenario-results" aria-describedby="lab-scenario-hint" autocomplete="off" spellcheck="false" placeholder="Search scenarios, protocols or attributes…"><button type="button" id="lab-scenario-clear" aria-label="Clear scenario search" hidden>×</button><button type="button" id="lab-scenario-toggle" tabindex="-1" aria-label="Show scenario choices" aria-expanded="false" aria-controls="lab-scenario-results">${uiIcon('next')}</button></div><span class="scenario-picker-hint" id="lab-scenario-hint">Type to search · Start with Basic Keycloak sign-in</span><div class="scenario-picker-menu" id="lab-scenario-menu" hidden><div class="scenario-picker-menu-heading"><span id="lab-scenario-search-status" role="status" aria-live="polite"></span><span>↑ ↓ to navigate · Enter to choose</span></div><div class="scenario-picker-results" id="lab-scenario-results" role="listbox" aria-label="Lab scenarios"></div></div><select id="lab-scenario" hidden aria-hidden="true" tabindex="-1">${LEARNING_PRESETS.map(p=>`<option value="${p.id}">${escapeHtml(p.title)}</option>`).join('')}<option value="core">Core lab · configurable sign-in, SAML, FIDO and grants</option>${LAB_CATEGORIES.map(category=>`<optgroup label="${escapeHtml(category)}">${LAB_SCENARIOS.filter(model=>model.category===category&&!getLearningPreset(model.id)).map(model=>`<option value="${model.id}">${escapeHtml(model.title)}</option>`).join('')}</optgroup>`).join('')}</select></div><button class="button quiet" id="lab-open">Browse ${LAB_SCENARIOS.length} extended scenarios</button></section>
      <details class="lab-catalog" id="lab-catalog"><summary><strong>Scenario library</strong><span>Applications · token lifecycle · protections · protocol variants · failure paths</span></summary><label class="sr-only" for="lab-search">Find a scenario</label><input id="lab-search" class="glossary-search" type="search" placeholder="Search SPA, refresh, DPoP, logout, Artifact, consent…"><div class="lab-cards" id="lab-cards"></div></details>
      <div class="lab-support" id="lab-support" hidden></div>
      <section class="provider-settings" id="provider-settings" hidden><div class="select-field"><label for="provider-profile">External identity provider</label><select id="provider-profile">${PROVIDER_PROFILES.map(profile=>`<option value="${profile.id}">${escapeHtml(profile.title)}</option>`).join('')}</select></div><div class="provider-description"><p id="provider-note"></p><p id="provider-protection-note" hidden></p><div id="provider-sources" class="provider-sources"></div></div></section>
      <details class="advanced-configuration" id="advanced-configuration"><summary><strong>Advanced configuration</strong><span>Optional · explore another combination</span></summary><div class="advanced-layout-controls"><label class="overlay-toggle"><input type="checkbox" id="move-participants"><span>Move participants</span></label><button class="button quiet" id="layout-reset">Reset layout</button></div>
      <section class="toolbar" aria-label="Scenario settings">
        <div class="select-field"><label for="mode">Learning journey</label><select id="mode">${Object.entries(modeMetadata).map(([key,m])=>`<option value="${key}">${m.title}</option>`).join('')}</select></div>
        <div class="select-field"><label for="architecture">Application</label><select id="architecture">${Object.entries(ARCHITECTURES).map(([key,a])=>`<option value="${key}">${escapeHtml(a.name||a.title)}</option>`).join('')}</select></div>
        <div class="select-field"><label for="upstream">Identity setup</label><select id="upstream">${Object.entries(UPSTREAMS).map(([key,p])=>`<option value="${key}">${escapeHtml(key==='keycloak'?'Two Keycloak realms':key==='external'?'Keycloak + external OIDC IdP':p.name||p.title)}</option>`).join('')}</select></div>
        <div class="select-field"><label for="authenticator">Passkey device</label><select id="authenticator"><option value="hello">Windows Hello</option><option value="yubikey">YubiKey</option></select></div>

      </section>
      <details class="protocol-toolbar" open><summary><strong>Protocols & protection</strong><span id="protocol-summary">OIDC · signed ID tokens</span></summary><div class="protocol-grid">
        <div class="select-field"><label for="oidc-flow">OAuth / OIDC learning flow</label><select id="oidc-flow"><option value="authorization-code">Authorization Code · interactive sign-in</option><option value="client-credentials">Service account · client_credentials</option><option value="device">Device Authorization Flow</option><option value="ciba">CIBA · Poll delivery</option><option value="token-exchange">Token exchange · Standard V2</option></select></div>
        <div class="select-field"><label for="app-protocol">Application ↔ Realm A</label><select id="app-protocol"><option value="oidc">OIDC · Authorization Code</option><option value="saml">SAML 2.0 · Web SSO</option></select></div>
        <div class="select-field"><label for="broker-protocol">Realm A ↔ upstream IdP</label><select id="broker-protocol"><option value="oidc">OIDC · Authorization Code</option><option value="saml">SAML 2.0 · Web SSO</option></select></div>
        <div class="select-field"><label for="saml-binding">SAML request binding</label><select id="saml-binding"><option value="redirect">HTTP-Redirect · signed query</option><option value="post">HTTP-POST · signed XML</option></select></div>
        <div class="select-field"><label for="saml-initiation">SAML application initiation</label><select id="saml-initiation"><option value="sp">SP initiated · app requests login</option><option value="idp">IdP initiated · configured unsolicited SSO</option></select></div>
        <div class="select-field"><label for="token-protection">OIDC ID token protection</label><select id="token-protection"><option value="signed">Signed JWS</option><option value="app-jwe">App ID token · signed then JWE</option><option value="broker-jwe">Broker ID token · signed then JWE</option><option value="both-jwe">All OIDC ID tokens · signed then JWE</option></select></div>
        <div class="select-field"><label for="assertion-protection">SAML assertion protection</label><select id="assertion-protection"><option value="signed">Signed assertion</option><option value="encrypted">Signed + XML Encryption</option></select></div>
      </div><p class="protocol-note">SAML responses use HTTP-POST. Encryption protects the message; signatures and recipient checks still establish trust. JWE applies to OIDC ID tokens, while SAML uses XML Encryption.</p></details></details>
      <details class="environment-panel" id="environment-panel"><summary><strong>Use your environment</strong><span>Optional · addresses for this open page</span></summary><p class="environment-note">Show your application and identity-provider addresses in the animation. Values stay in this open page and return to examples on reload, navigation away or Reset environment. The animation makes no requests to these addresses.</p><div id="environment-fields"></div><p class="environment-errors" id="environment-errors" role="alert" hidden></p><div class="environment-actions"><button class="button primary" id="environment-apply">Apply to animation</button><button class="button quiet" id="environment-reset">Reset environment</button><span id="environment-status" role="status"></span></div></details>
      <div class="workspace">
        <div class="diagram-column"><div class="map-controls" id="map-controls" role="group" aria-label="Animation controls">
        <div class="playback-controls"><button class="button primary" id="play">${uiIcon('play',true)}<span>Play demo</span></button><button class="icon-button" id="reset" aria-label="Reset demo">${uiIcon('reset')}</button></div>
        <div class="speed-control"><label for="speed">Playback speed <output class="speed-value" id="speed-label">1×</output></label><input id="speed" type="range" min="0" max="4" step="0.01" value="1" aria-label="Playback speed" title="0 pauses; speeds start at 0.01×. Play restores the last non-zero speed."></div>
        <label class="overlay-toggle"><input type="checkbox" id="show-step-attributes" checked><span>Show step attributes</span></label>
        <div class="seek-control"><label for="seek"><span>Explore the timeline</span><output id="seek-position">Step 1</output></label><input id="seek" type="range" min="0" max="1000" step="1" value="0" aria-label="Seek through the current journey" aria-describedby="seek-hint"><span id="seek-hint">Drag to inspect any moment · playback stays paused · press Play to continue</span></div>
        </div>
        <section class="map-panel" aria-label="Interactive authentication map">
          <div class="map-heading"><div><h2 id="scenario-title">Sign in with a passkey</h2><p id="scenario-description"></p></div><span class="live-status" id="status">READY TO EXPLORE</span></div>
          <div class="attribute-focus-bar" id="attribute-focus" hidden></div>
          <div class="map-scroll"><div class="graph-canvas" id="graph">
            <div class="zone-label device">${uiIcon('info')}<span>YOUR DEVICE</span></div><div class="zone-label cloud">IDENTITY SERVICES</div>
            <svg class="graph-connections" id="connections" viewBox="0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}" aria-label="Connections between authentication participants"><defs>${Object.keys(channelLabels).map(c=>`<marker id="arrow-${c}" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto-start-reverse" viewBox="0 0 7 7"><path d="M0 0 7 3.5 0 7" class="arrow-fill ${c}"/></marker>`).join('')}</defs><g id="connection-paths"></g></svg>
            <div id="actors"></div>
            <svg class="step-attributes-tether" id="step-attributes-tether" viewBox="0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}" aria-hidden="true" hidden><path/></svg>
            <div class="step-attributes" id="step-attributes" role="group" aria-label="Attribute names in the active step" hidden></div>
            <div class="packet-position" id="packet" hidden><div class="packet-chip"><span class="packet-orb"></span><div><span class="packet-name" id="packet-name"></span><code class="packet-value" id="packet-value"></code></div><span class="packet-count" id="packet-count"></span></div></div>
          </div></div>
          <div class="map-footer"><div class="legend">${Object.entries(channelLabels).filter(([key])=>key!=='human').map(([key,label])=>`<span class="legend-item"><span class="legend-dot" data-channel="${key}"></span>${label}</span>`).join('')}</div><p class="map-hint">Hover or focus a participant for help. F2 moves keyboard focus inside the help panel; Tab explores its controls, Escape returns. Click a connection to replay its exchanges.</p></div>
          <div class="current-story" id="story" aria-live="polite"></div>
          <div class="progress-track" role="progressbar" aria-label="Journey progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="progress-bar" id="progress"></div></div>
        </section></div>
        <div class="study-sidebar"><aside class="attribute-index-panel" id="attribute-index" aria-label="Separate attribute index"><div class="attribute-index-heading"><div><h2>Attribute index</h2><p>Click a field to animate its path. Hover or focus it for help. F2 moves focus inside that help panel; Tab explores, Escape returns.</p></div><button class="icon-button" id="attribute-index-toggle" aria-label="Hide attribute index">${uiIcon('close')}</button></div><label class="sr-only" for="attribute-search">Search attributes, PKCE or purpose</label><input class="glossary-search" id="attribute-search" type="search" placeholder="Search client_id, PKCE, secret…"><div class="attribute-topic-list" id="attribute-topics"></div><p class="attribute-index-meta" id="attribute-index-meta"></p><div class="attribute-index-list" id="attribute-index-list"></div><p id="attribute-index-empty" hidden>No matching attributes.</p></aside>
        <aside class="inspector-panel" aria-label="Participant and exchange inspector"><div class="inspector-top"><span id="inspector-heading">EXCHANGE INSPECTOR</span><button class="icon-button" id="follow" aria-label="Follow the current demo step" title="Follow the current step">${uiIcon('arrow')}</button></div><div class="inspector-content" id="inspector"></div></aside></div>
      </div>
      <section class="timeline-panel" aria-label="Ordered journey steps"><div class="timeline-head"><div><span class="eyebrow">THE JOURNEY</span><h2>One exchange at a time</h2></div><div class="timeline-controls"><button class="icon-button" id="previous" aria-label="Previous step">${uiIcon('previous')}</button><button class="icon-button" id="next" aria-label="Next step">${uiIcon('next')}</button></div></div><div class="timeline-strip" id="timeline"></div></section>
      <details class="coverage-panel"><summary><strong>SPA, API & coverage</strong><span>Core controls + ${LAB_SCENARIOS.length} extended scenarios</span></summary><div class="coverage-content"><div><h3>SPA and API are different roles</h3><p>A <strong>Single Page Application (SPA)</strong> runs in the browser. A pure browser OAuth client cannot keep a client secret. The SPA walkthrough shows its HTTPS callback, Code + PKCE, token handling, CORS and a separate resource API.</p><p>An <strong>API</strong> checks the access token’s trust, intended audience, lifetime and permissions. API introspection, 401/403, JWKS rotation, certificate binding and DPoP are distinct scenarios. An ID token is the client’s login result, not an API credential.</p><p>A <strong>Backend for Frontend (BFF)</strong> retains credentials and tokens on the server and gives the browser an opaque session cookie. The BFF → API scenario shows this boundary.</p><h3>How to use the lab</h3><p>Choose a scenario above or browse the searchable library. Play the entire process, click a connection, or select one attribute. Enable Show step attributes to keep the message’s complete names beside its active link. Enable Move participants to drag cards or use arrow keys; Reset layout restores their positions.</p></div><div><h3>Animated coverage</h3><ul><li>Core configurable OIDC/SAML sign-in: one realm, two realms, independent upstream IdP, native loopback and confidential web callback; passwords, passkeys, FIDO2, TOTP and configured MFA.</li>${LAB_CATEGORIES.map(category=>'<li>'+escapeHtml(category)+' · '+LAB_SCENARIOS.filter(model=>model.category===category).length+' scenarios</li>').join('')}</ul><h3>Support is visible</h3><p>Each scenario links to primary documentation and identifies supported/configured Keycloak behavior, Preview/deprecated behavior or a standards-only profile. CIBA Push and alternate signed-hint profiles are not presented as built-in Keycloak features. Legacy grants are educational comparisons.</p><h3>Practical limits</h3><p>This is an offline protocol simulator. Values and cryptographic operations are schematic; it does not configure or contact a live server. Provider-specific policies and every combination of extensions are not expanded into separate presets. Detailed factor ceremonies remain available in the core journeys. Version-specific support is stated in the scenario’s note.</p></div></div></details>
      <footer class="sources-footer"><p class="documentation-baseline">Documentation baseline: <a href="https://www.keycloak.org/2026/10/keycloak-2680-released" target="_blank" rel="noopener noreferrer">Keycloak 26.8.0</a> · checked 8 October 2026. Support depends on feature flags, client policy and realm configuration. This offline model is not a live compatibility test.</p><details><summary>Protocol notes & primary sources</summary><div class="source-notes">${(LEARNING_NOTES||[]).filter(note=>['One authenticator per attempt','Sessions can shorten real sign-in','Passkey plus TOTP is an explicit flow','TOTP codes can be phished'].includes(note.title)).map(note=>`<p>${escapeHtml(note.text)}</p>`).join('')}<p>Illustrative messages and values. Login assumes a fresh session. Registration starts with a verified relying-party account. FIDO2 combines WebAuthn and CTAP: external FIDO2 keys use CTAP2 locally; Windows Hello uses the platform authenticator path. In single-realm sign-in, Realm A verifies the selected method and returns the selected protocol’s identity result. In brokered sign-in the upstream provider verifies WebAuthn. For OIDC, application client_id is a configured public identifier; the app validates the ID token’s aud against it. For SAML, Keycloak’s registered client identifier is the SP entity ID, used as AuthnRequest Issuer and assertion Audience; the XML does not gain an OAuth client_id parameter. In direct FIDO2 sign-in the web application itself is the relying party, using its own RP ID and public-key credential records.</p><p>Passkey + TOTP and passwordless TOTP require explicit configured flows. TOTP alone is one factor. External providers must support and configure the chosen method; login-form field names and credential policies are provider-specific.</p><p>SAML Web SSO uses Redirect/POST requests and POST responses. Assertion encryption uses XML Encryption. JWE protects OIDC ID tokens; recipients decrypt locally before verifying the inner signature and applicable claims. Device and CIBA tokens have no invented Authorization Code, PKCE or nonce stages.</p><p>Service accounts act as the application’s own identity and receive an access token without a human login or MFA. Device user_code is not TOTP: it links a separate browser to a private device_code. CIBA uses an administrator-controlled authentication-channel service; its illustrated password/passkey/TOTP policy is a service implementation, not a built-in CIBA browser redirect flow. Standard Token Exchange V2 here is same-realm and access-token-to-access-token; strict downscoping is explicitly configured, not assumed from the grant.</p></div><p>Animated coverage and remaining variants are listed in SPA, API & coverage above. These examples illustrate messages, not live authentication or exhaustive Keycloak configuration.</p><div class="source-links">${[...SOURCES,...FIDO_SOURCES,...SAML_SOURCES,...JWE_SOURCES,...SERVICE_SOURCES,...DEVICE_SOURCES,...CIBA_SOURCES,...EXCHANGE_SOURCES,...LAB_SOURCES].map(source=>`<a href="${escapeHtml(source.url||source.source)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.label||source.name||source.title)}</a>`).join('')}</div></details><span>Built to explore · RFC / OASIS / W3C / FIDO names, plain-language explanations</span></footer>
      <div id="actor-popup" class="floating-panel" role="dialog" aria-modal="false" aria-label="Participant attributes" hidden></div>
      <div id="attribute-popup" class="attribute-tooltip" role="dialog" aria-modal="false" aria-label="Attribute explanation" hidden></div>
      <div id="toast" class="toast" role="status" hidden></div>
    </main>`;
  }
  bind() {
    this.querySelector('#quick-start').addEventListener('click',e=>{const button=e.target.closest('[data-learning-preset]');if(button)this.selectLabScenario(button.dataset.learningPreset);});
    this.refs['provider-profile'].addEventListener('change',()=>{this.providerProfileId=this.refs['provider-profile'].value;this.brokerProtocol=this.providerProfile.protocol;this.providerManaged=this.providerProfileId!=='generic'||!!this.learningPreset?.providerSelectable;this.refreshConfiguration();});
    this.refs['environment-fields'].addEventListener('input',e=>{const field=e.target.closest('[data-environment-field]');if(field){const key=field.dataset.environmentField;this.runtimeEnvironment.updateDraft(key.startsWith('provider.')?{provider:{[key.slice(9)]:field.value}}:{[key]:field.value},{profileId:this.providerProfile.id});}});
    this.querySelector('#environment-apply').addEventListener('click',()=>this.applyEnvironment());
    this.querySelector('#environment-reset').addEventListener('click',()=>this.resetEnvironment());
    this.environmentPageHide=()=>this.resetEnvironment();this.environmentPageShow=e=>{if(e.persisted)this.resetEnvironment();};
    window.addEventListener('pagehide',this.environmentPageHide);window.addEventListener('pageshow',this.environmentPageShow);
    this.refs['lab-scenario'].addEventListener('change',()=>this.selectLabScenario(this.refs['lab-scenario'].value));
    this.querySelector('#lab-open').addEventListener('click',()=>{this.refs['lab-catalog'].open=!this.refs['lab-catalog'].open;if(this.refs['lab-catalog'].open)this.refs['lab-search'].focus();});
    this.refs['lab-search'].addEventListener('input',()=>{this.catalogQuery=this.refs['lab-search'].value;this.renderCatalog();});
    this.refs['lab-cards'].addEventListener('click',event=>{const card=event.target.closest('[data-lab-scenario]');if(card)this.selectLabScenario(card.dataset.labScenario);});
    this.refs['move-participants'].addEventListener('change',()=>{this.moveParticipants=!!this.refs['move-participants'].checked;this.refs.graph.classList.toggle('is-move-mode',this.moveParticipants);});
    this.querySelector('#layout-reset').addEventListener('click',()=>{delete this.customLayouts[this.layoutKey];this.renderAll();this.renderPacket(this.player.snapshot());this.renderStepAttributes(this.player.snapshot(),true);});
    ['mode','authenticator','architecture','upstream'].forEach(key=>this.refs[key].addEventListener('change',()=>{const wasDirect=this.isDirectFido;this.labScenarioId='core';this[key]=this.refs[key].value;if(key==='mode'&&(this.isDirectFido||modeMetadata[this.mode]?.enrollment))this.oidcFlow='authorization-code';if(key==='mode'&&this.isDirectFido&&!wasDirect){this.authenticator='yubikey';this.refs.authenticator.value='yubikey';}this.refreshConfiguration();}));
    this.refs['oidc-flow'].addEventListener('change',()=>{this.labScenarioId='core';this.oidcFlow=this.refs['oidc-flow'].value;if(this.isAdvancedFlow){this.applicationProtocol='oidc';if(this.isDirectFido||modeMetadata[this.mode]?.enrollment)this.mode='passkey';this.refs.mode.value=this.mode;}this.refreshConfiguration();});
    [['app-protocol','applicationProtocol'],['broker-protocol','brokerProtocol'],['saml-binding','samlBinding'],['saml-initiation','samlInitiation'],['token-protection','tokenProtection'],['assertion-protection','assertionProtection']].forEach(([id,key])=>this.refs[id].addEventListener('change',()=>{this.labScenarioId='core';this[key]=this.refs[id].value;if(id==='app-protocol'&&this.applicationProtocol==='saml')this.oidcFlow='authorization-code';this.refreshConfiguration();}));
    this.refs.play.addEventListener('click',()=>{
      this.ensureRunningSpeed();
      if(this.player.status==='playing')this.player.pause();
      else if(this.player.status==='paused')this.player.resume();
      else if(this.attributeSelection)this.playAttribute();
      else {this.inspection={type:'step'};this.visited.clear();this.player.play(this.steps,'demo');}
    });
    this.querySelector('#reset').addEventListener('click',()=>this.reset());
    this.refs.speed.addEventListener('input',()=>this.player.setSpeed(this.refs.speed.value));
    this.refs.seek.addEventListener('input',()=>this.seekPlayback(Number(this.refs.seek.value)/1000));
    this.refs['show-step-attributes'].addEventListener('change',()=>{this.showStepAttributes=!!this.refs['show-step-attributes'].checked;this.renderStepAttributes(this.player.snapshot(),true);});
    this.querySelector('#previous').addEventListener('click',()=>this.selectStep(Math.max(0,this.visibleIndex-1),true));
    this.querySelector('#next').addEventListener('click',()=>this.selectStep(Math.min(this.visibleSteps.length-1,this.visibleIndex+1),true));
    this.querySelector('#follow').addEventListener('click',()=>{this.inspection={type:'step'};this.renderInspector();});
    this.querySelector('#glossary-open').addEventListener('click',()=>{this.inspection={type:'glossary'};this.renderInspector();});
    this.querySelector('#index-open').addEventListener('click',()=>{this.refs['attribute-index'].hidden=false;this.refs['attribute-search'].focus();});
    this.querySelector('#attribute-index-toggle').addEventListener('click',()=>{this.hidePopups();this.refs['attribute-index'].hidden=true;this.restoreTargetFocus({elementId:'index-open'});});
    this.refs['attribute-search'].addEventListener('input',()=>{this.attributeQuery=this.refs['attribute-search'].value;this.filterAttributeIndex();});
    this.refs['attribute-index'].addEventListener('click',e=>{const field=e.target.closest('[data-index-attribute]');const topic=e.target.closest('[data-trace-topic]');if(field)this.selectAttribute(field.dataset.indexAttribute);if(topic)this.selectAttribute(topic.dataset.traceTopic);});
    this.refs['attribute-index-list'].addEventListener('mouseover',e=>{const field=e.target.closest('[data-index-attribute]');if(field&&!field.contains(e.relatedTarget))this.showAttributePopup(field.dataset.indexAttribute,field);});
    this.refs['attribute-index-list'].addEventListener('mouseout',()=>this.deferCloseAttribute());
    this.refs['attribute-index-list'].addEventListener('focusin',e=>{const field=e.target.closest('[data-index-attribute]');if(field)this.showAttributePopup(field.dataset.indexAttribute,field);});
    this.refs['attribute-index-list'].addEventListener('focusout',e=>this.deferCloseAttribute(e.relatedTarget));
    this.refs['attribute-focus'].addEventListener('click',e=>{if(e.target.closest('[data-clear-trace]'))this.clearAttribute();if(e.target.closest('[data-trace-play]')){this.ensureRunningSpeed();if(this.player.status==='playing')this.player.pause();else if(this.player.status==='paused')this.player.resume();else this.playAttribute();}});
    this.querySelector('#theme-toggle').addEventListener('click',()=>{this.theme=this.theme==='dark'?'light':'dark';this.refs.studio.dataset.theme=this.theme;});
    this.refs.timeline.addEventListener('click',e=>{const button=e.target.closest('[data-step]');if(button)this.selectStep(Number(button.dataset.step),true);});
    this.refs.actors.addEventListener('click',e=>{const node=e.target.closest('[data-actor]');if(node&&!this.moveParticipants)this.inspectActor(node.dataset.actor);});
    this.refs.actors.addEventListener('pointerdown',event=>this.startActorDrag(event));
    this.refs.actors.addEventListener('pointermove',event=>this.updateActorDrag(event));
    this.refs.actors.addEventListener('pointerup',event=>this.endActorDrag(event));
    this.refs.actors.addEventListener('pointercancel',event=>this.endActorDrag(event));
    this.refs.actors.addEventListener('keydown',event=>{const card=event.target.closest('[data-actor]'),delta={ArrowLeft:[-12,0],ArrowRight:[12,0],ArrowUp:[0,-12],ArrowDown:[0,12]}[event.key];if(this.moveParticipants&&card&&delta){event.preventDefault();const p=this.positions[card.dataset.actor];this.moveActor(card.dataset.actor,p.x+delta[0],p.y+delta[1]);}});
    this.refs.actors.addEventListener('mouseover',e=>{const node=e.target.closest('[data-actor]');if(node&&!node.contains(e.relatedTarget))this.showActorPopup(node.dataset.actor,node);});
    this.refs.actors.addEventListener('mouseout',e=>{const node=e.target.closest('[data-actor]');if(node&&!node.contains(e.relatedTarget))this.deferCloseActor();});
    this.refs.actors.addEventListener('focusin',e=>{const node=e.target.closest('[data-actor]');if(node)this.showActorPopup(node.dataset.actor,node);});
    this.refs.actors.addEventListener('focusout',e=>this.deferCloseActor(e.relatedTarget));
    this.refs.connections.addEventListener('click',e=>{const edge=e.target.closest('[data-pair]');if(edge)this.replayConnection(edge.dataset.pair);});
    this.refs.connections.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){const edge=e.target.closest('[data-pair]');if(edge){e.preventDefault();this.replayConnection(edge.dataset.pair);}}});
    [this.refs.inspector,this.refs['actor-popup']].forEach(container=>{
      container.addEventListener('mouseover',e=>{const field=e.target.closest('[data-attribute]');if(field&&!field.contains(e.relatedTarget))this.showAttributePopup(field.dataset.attribute,field);});
      container.addEventListener('mouseout',e=>{const field=e.target.closest('[data-attribute]');if(field&&!field.contains(e.relatedTarget))this.deferCloseAttribute();});
      container.addEventListener('focusin',e=>{const field=e.target.closest('[data-attribute]');if(field)this.showAttributePopup(field.dataset.attribute,field);});
      container.addEventListener('focusout',e=>this.deferCloseAttribute(e.relatedTarget));
      container.addEventListener('click',e=>{const field=e.target.closest('[data-attribute]');if(field)this.selectAttribute(field.dataset.attribute);});
    });
    this.refs.inspector.addEventListener('click',e=>{
      if(e.target.closest('[data-replay]')&&this.currentStep){this.ensureRunningSpeed();this.player.play([this.currentStep],this.attributeSelection?'attribute-step':'step');}
      const trace=e.target.closest('[data-trace-step]');if(trace)this.selectStep(Number(trace.dataset.traceStep),true);
      if(e.target.closest('[data-trace-play]')){this.ensureRunningSpeed();this.playAttribute();}
      if(e.target.closest('[data-clear-trace]'))this.clearAttribute();
      const available=e.target.closest('[data-trace-mode]');if(available){this.exitLab();this.mode=available.dataset.traceMode;this.refs.mode.value=this.mode;this.refreshConfiguration();this.playAttribute();}
      const setup=e.target.closest('[data-trace-upstream]');if(setup){this.exitLab();this.upstream=setup.dataset.traceUpstream;this.mode=setup.dataset.setupMode||this.mode;this.refs.upstream.value=this.upstream;this.refs.mode.value=this.mode;this.refreshConfiguration();this.playAttribute();}
      const device=e.target.closest('[data-trace-device]');if(device){this.exitLab();this.authenticator=device.dataset.traceDevice;this.refs.authenticator.value=this.authenticator;this.refreshConfiguration();this.playAttribute();}
      const protocol=e.target.closest('[data-trace-protocol]');if(protocol)this.exploreProtocol(protocol.dataset.traceProtocol);
      const grant=e.target.closest('[data-trace-grant]');if(grant)this.exploreGrant(grant.dataset.traceGrant,{mode:grant.dataset.grantMode,authenticator:grant.dataset.grantAuthenticator,upstream:grant.dataset.grantUpstream,architecture:grant.dataset.grantArchitecture});
      const lab=e.target.closest('[data-trace-lab]');if(lab){this.selectLabScenario(lab.dataset.traceLab);this.playAttribute();}
      const exchange=e.target.closest('[data-exchange-step]');if(exchange)this.selectStep(Number(exchange.dataset.exchangeStep),true);
      const use=e.target.closest('[data-use-authenticator]');if(use){this.exitLab();this.authenticator=use.dataset.useAuthenticator;this.refs.authenticator.value=this.authenticator;if(!modeMetadata[this.mode]?.passkey)this.mode='passkey';this.refs.mode.value=this.mode;this.refreshConfiguration();}
      if(e.target.closest('[data-use-totp]')){this.exitLab();this.mode='password-totp';this.refs.mode.value=this.mode;this.refreshConfiguration();}
      if(e.target.closest('[data-back]')){this.inspection={type:'step'};this.renderInspector();}
    });
    this.refs.inspector.addEventListener('input',e=>{if(e.target.matches('#glossary-search'))this.filterGlossary(e.target.value);});
    this.refs['actor-popup'].addEventListener('mouseenter',()=>clearTimeout(this.closeTimer));
    this.refs['actor-popup'].addEventListener('mouseleave',()=>this.deferCloseActor());
    this.refs['actor-popup'].addEventListener('click',e=>{if(e.target.closest('[data-close]'))this.dismissPopup('actor');});
    this.refs['attribute-popup'].addEventListener('mouseenter',()=>{clearTimeout(this.attributeTimer);if(this.refs['actor-popup'].contains(this.attributeAnchor))clearTimeout(this.closeTimer);});
    this.refs['attribute-popup'].addEventListener('mouseleave',()=>{this.deferCloseAttribute();this.deferCloseActor();});
    this.refs['attribute-popup'].addEventListener('click',e=>{if(e.target.closest('[data-close]'))this.dismissPopup('attribute');});
    ['actor','attribute'].forEach(kind=>{
      this.refs[kind+'-popup'].addEventListener('focusin',()=>{if(kind==='actor'||this.refs['actor-popup'].contains(this.attributeAnchor))clearTimeout(this.closeTimer);if(kind==='attribute'||this.popupOwnsFocus('attribute'))clearTimeout(this.attributeTimer);});
      this.refs[kind+'-popup'].addEventListener('focusout',e=>{this.deferCloseAttribute(e.relatedTarget);this.deferCloseActor(e.relatedTarget);});
    });
    this.addEventListener('keydown',e=>{
      if(e.key==='Escape'){
        if(this.refs['attribute-popup'].contains(e.target))this.dismissPopup('attribute');
        else if(this.refs['actor-popup'].contains(e.target))this.dismissPopup('actor');
        else this.hidePopups();
      }
      if(e.key==='F2'){
        const field=e.target.closest('[data-index-attribute], [data-attribute]'),card=e.target.closest('[data-actor]');
        if(field){e.preventDefault();this.showAttributePopup(field.dataset.indexAttribute||field.dataset.attribute,field);this.refs['attribute-popup'].querySelector('.source-link').focus();}
        else if(card){e.preventDefault();this.showActorPopup(card.dataset.actor,card);this.refs['actor-popup'].querySelector('[data-attribute], [data-close]').focus();}
      }
    });
    window.addEventListener('resize',()=>{this.resizeHelpPanels();this.renderStepAttributes(this.player.snapshot(),true);});
    window.addEventListener('blur',()=>{if(this.player.status==='playing')this.player.pause();});
  }
  selectLabScenario(id) {
    const preset=getLearningPreset(id);
    if(id!=='core'&&!preset&&!LAB_MODELS[id])return;
    const keys=['mode','authenticator','architecture','upstream','applicationProtocol','brokerProtocol','samlBinding','samlInitiation','tokenProtection','assertionProtection','oidcFlow','providerProfileId','providerManaged'];
    if(this.labScenarioId==='core')this.coreConfiguration=Object.fromEntries(keys.map(key=>[key,this[key]]));
    this.labScenarioId=id;
    if(preset){const profile=preset.providerSelectable?(this.providerProfileId==='generic'?'entra':this.providerProfileId):'generic';Object.assign(this,getPresetConfiguration(id,profile));this.labScenarioId=id;}
    if(id==='core'&&this.coreConfiguration)Object.assign(this,this.coreConfiguration);
    if(id==='core'){if(this.providerProfileId==='generic')this.providerManaged=false;this.querySelector('#advanced-configuration').open=true;this.querySelector('#advanced-configuration').setAttribute('open','');}
    if(this.labModel&&this.attributeSelection)this.attributeSelection=this.labAttributeAlias(this.attributeSelection);
    this.dragState=null;this.refreshConfiguration();
  }
  exitLab() {
    if(this.learningPreset&&!this.labModel){this.labScenarioId='core';return;}
    if(!this.labModel)return;
    this.labScenarioId='core';if(this.coreConfiguration)Object.assign(this,this.coreConfiguration);
  }
  labAttributeAlias(id) {
    if(!this.labModel||LAB_ATTRIBUTES[id]||ATTRIBUTE_TOPICS[id]||this.labModel.ids.includes(id))return id;
    const name=labCanonicalName(ATTRIBUTES[id]?.name||id);
    return this.labModel.ids.find(candidate=>labCanonicalName(ATTRIBUTES[candidate]?.name)===name&&(name!=='nonce'||/OpenID|OIDC/.test(ATTRIBUTES[candidate]?.standard)))||id;
  }
  renderCatalog() {
    const returnTarget=this.refs['lab-cards'].contains(document.activeElement)?captureFocusTarget(this,document.activeElement):null;
    const matches=new Set(filterScenarioOptions(this.scenarioPicker.options,this.catalogQuery).map(option=>option.id));
    this.refs['lab-cards'].innerHTML=LAB_SCENARIOS.filter(model=>matches.has(model.id)).map(model=>`<button class="lab-card ${model.id===(this.labModel?.id||this.labScenarioId)?'is-selected':''}" data-lab-scenario="${model.id}" aria-pressed="${model.id===(this.labModel?.id||this.labScenarioId)}"><span class="lab-card-category">${escapeHtml(model.category)}</span><strong>${escapeHtml(model.title)}</strong><p>${escapeHtml(model.summary)}</p><span class="lab-card-status">${escapeHtml(model.status)} · ${model.steps(this.protocolConfig()).length} steps</span></button>`).join('')||'<p class="empty-state">No matching scenarios.</p>';
    if(returnTarget)this.restoreTargetFocus(returnTarget,{fallbackSelector:'#lab-scenario-search'});
  }
  renderLabSupport() {
    const model=this.labModel,panel=this.refs['lab-support'];panel.hidden=!model;
    if(!model){panel.innerHTML='';return;}
    panel.dataset.level=/legacy|deprecated|discouraged|preview|standard.*only/i.test(model.status)?'special':'supported';
    panel.innerHTML=`<div><span class="lab-support-badge">${escapeHtml(model.status)}</span><strong>${escapeHtml(model.category)}</strong><p>${escapeHtml(model.supportNote)}</p></div><a href="${escapeHtml(model.source)}" target="_blank" rel="noopener noreferrer">Primary documentation</a>`;
  }
  environmentFields() {
    const saml=this.applicationProtocol==='saml',broker=this.upstream!=='single'&&!this.labModel&&!this.isDirectFido,brokerSaml=broker&&this.brokerProtocol==='saml',external=this.upstream==='external'&&broker;
    const used=field=>{
      if(field.key==='appURL')return true;
      if(this.isDirectFido)return false;
      if(field.key==='brokerAlias')return broker;
      if(['keycloakBBaseURL','realmB'].includes(field.key))return this.upstream==='keycloak'&&broker;
      if(/^b[A-Z]/.test(field.key))return this.upstream==='keycloak'&&broker&&(/SsoURL$|EntityID$/.test(field.key)?brokerSaml:!brokerSaml);
      if(['acsURL','appEntityID'].includes(field.key))return saml;
      if(field.key==='clientID')return !saml;
      if(field.key==='appCallbackURL')return !saml&&(!this.isAdvancedFlow||this.labModel?.ids.some(id=>this.labModel.definitions(this.protocolConfig())[id]?.name==='redirect_uri'));
      if(/^a[A-Z]/.test(field.key))return /SsoURL$|EntityID$/.test(field.key)?saml||brokerSaml:!saml||broker&&!brokerSaml;
      return true;
    };
    const common=RUNTIME_ENVIRONMENT_FIELDS.filter(used);
    const provider=external?RUNTIME_PROVIDER_FIELDS.filter(field=>this.brokerProtocol==='saml'?['samlEntityID','ssoURL'].includes(field.key):!['samlEntityID','ssoURL'].includes(field.key)&&(field.key!=='loginDomainURL'||this.providerProfile.id==='cognito')):[];
    return [...common.map(field=>({...field,path:field.key})),...provider.map(field=>({...field,path:'provider.'+field.key}))];
  }
  renderEnvironmentFields() {
    const draft=this.runtimeEnvironment.draft,provider=draft.providers[this.providerProfile.id]||{};
    const input=field=>`<label class="environment-field"><span>${escapeHtml(field.label)}</span><input type="text" data-environment-field="${field.path}" value="${escapeHtml(field.path.startsWith('provider.')?provider[field.key]||'':draft[field.key]||'')}" placeholder="Keep the example value" autocomplete="off" spellcheck="false" aria-describedby="environment-errors"></label>`;
    const fields=this.environmentFields();
    this.refs['environment-fields'].innerHTML='<div class="environment-grid">'+fields.filter(field=>!field.advanced).map(input).join('')+'</div><details class="environment-advanced"><summary>Exact endpoints & identifiers</summary><p class="environment-note">An issuer, an endpoint, a client_id and a SAML entityID are separate values. External endpoints stay explicit; an arbitrary issuer does not determine their paths.</p><div class="environment-grid">'+fields.filter(field=>field.advanced).map(input).join('')+'</div></details>';
    this.refs['environment-status'].textContent=this.runtimeEnvironment.active?'Your environment is active for this open page.':'Using example addresses.';
  }
  applyEnvironment() {
    this.refs['environment-fields'].querySelectorAll('[data-environment-field]').forEach(field=>{const key=field.dataset.environmentField;this.runtimeEnvironment.updateDraft(key.startsWith('provider.')?{provider:{[key.slice(9)]:field.value}}:{[key]:field.value},{profileId:this.providerProfile.id});});
    const result=this.runtimeEnvironment.apply({...this.environmentOptions,activeFields:this.environmentFields().map(field=>field.path)}),errors=this.refs['environment-errors'];
    errors.hidden=result.ok;errors.textContent=result.ok?'':Object.entries(result.errors).map(([key,message])=>(this.environmentFields().find(field=>field.path===key)?.label||key)+': '+message).join(' ');
    this.refs['environment-fields'].querySelectorAll('[data-environment-field]').forEach(field=>field.setAttribute('aria-invalid',String(!!result.errors?.[field.dataset.environmentField])));
    if(result.ok)this.refreshConfiguration();
  }
  resetEnvironment() {
    this.player.stop(false);this.runtimeEnvironment.reset();this.scenarioMemo.clear();this.definitionMemo=null;
    this.hidePopups();
    for(const kind of ['actor','attribute']){this.refs[kind+'-popup'].innerHTML='';this[kind+'Anchor']=null;this[kind+'FocusTarget']=null;}
    for(const id of ['packet-name','packet-value','packet-count'])this.refs[id].textContent='';
    this.packetIdentity='';this.attributeUsages=[];
    this.refs['environment-errors'].hidden=true;this.refs['environment-errors'].textContent='';this.refreshConfiguration();
  }
  moveActor(id,x,y) {
    const current=this.positions;if(!current[id]||!Number.isFinite(x)||!Number.isFinite(y))return false;
    const margin=24,hx=CARD_BOUNDS.width/2+margin,hy=CARD_BOUNDS.height/2+margin;
    const candidate={x:Math.max(hx,Math.min(GRAPH_WIDTH-hx,x)),y:Math.max(hy,Math.min(GRAPH_HEIGHT-hy,y))};
    if(Object.entries(current).some(([other,p])=>other!==id&&Math.abs(p.x-candidate.x)<CARD_BOUNDS.width+margin&&Math.abs(p.y-candidate.y)<CARD_BOUNDS.height+margin))return false;
    const proposed={...current,[id]:candidate};
    const pairs=[...this.steps,...this.traceQueue].map(step=>[this.nodeId(step.from),this.nodeId(step.to)]);
    const routes=validateLayoutRoutes(proposed,pairs);
    if(!routes.ok){this.showToast('Leave more room for connections and local processing around participants.');return false;}
    if(this.player.status==='playing')this.player.pause();
    if(!this.customLayouts[this.layoutKey])this.customLayouts[this.layoutKey]={};
    this.customLayouts[this.layoutKey][id]=candidate;this.refreshMapGeometry();return true;
  }
  refreshMapGeometry() {
    const positions=this.positions;
    this.refs.actors.querySelectorAll('[data-actor]').forEach(card=>{const p=positions[card.dataset.actor];if(p){card.style.left=p.x/GRAPH_WIDTH*100+'%';card.style.top=p.y/GRAPH_HEIGHT*100+'%';}});
    this.renderConnections();this.updateStep();this.renderPacket(this.player.snapshot());this.renderStepAttributes(this.player.snapshot(),true);
  }
  ensureLayoutRoutes(extraSteps=[]) {
    const pairs=[...this.steps,...extraSteps].map(step=>[this.nodeId(step.from),this.nodeId(step.to)]);
    if(validateLayoutRoutes(this.positions,pairs).ok)return false;
    delete this.customLayouts[this.layoutKey];
    this.showToast('Layout reset to leave room for this scenario’s connections.');
    return true;
  }
  startActorDrag(event) {
    const card=event.target.closest('[data-actor]');if(!this.moveParticipants||!card||event.button!==undefined&&event.button!==0)return;
    event.preventDefault();this.hidePopups();if(this.player.status==='playing')this.player.pause();
    const p=this.positions[card.dataset.actor],rect=this.refs.graph.getBoundingClientRect();
    this.dragState={id:card.dataset.actor,card,pointerId:event.pointerId,startX:event.clientX,startY:event.clientY,x:p.x,y:p.y,rect};
    card.setPointerCapture?.(event.pointerId);card.classList.add('is-dragging');
  }
  updateActorDrag(event) {
    const drag=this.dragState;if(!drag||event.pointerId!==drag.pointerId)return;
    event.preventDefault();this.moveActor(drag.id,drag.x+(event.clientX-drag.startX)*GRAPH_WIDTH/(drag.rect.width||GRAPH_WIDTH),drag.y+(event.clientY-drag.startY)*GRAPH_HEIGHT/(drag.rect.height||GRAPH_HEIGHT));
  }
  endActorDrag(event) {
    if(!this.dragState||event.pointerId!==this.dragState.pointerId)return;
    this.dragState.card.classList.remove('is-dragging');this.dragState.card.releasePointerCapture?.(event.pointerId);this.dragState=null;
  }
  renderAll() {
    if(this.labModel){this.upstream='single';this.architecture=this.labModel.architecture||'web';this.applicationProtocol=this.labModel.protocol==='saml'?'saml':'oidc';this.oidcFlow='authorization-code';this.mode='passkey';this.tokenProtection='signed';this.assertionProtection='signed';}
    else if(this.isAdvancedFlow){this.upstream='single';this.applicationProtocol='oidc';if(this.oidcFlow!=='device')this.architecture='web';if(this.isDirectFido||modeMetadata[this.mode]?.enrollment)this.mode='passkey';}
    if(this.isDirectFido||this.applicationProtocol==='saml')this.architecture='web';
    if(this.providerOwnsAuthentication&&modeMetadata[this.mode]?.enrollment)this.mode='password';
    if(this.upstream==='external'&&!this.labModel&&!this.isDirectFido&&!this.isAdvancedFlow&&this.providerProfileId!=='generic')this.brokerProtocol=this.providerProfile.protocol;
    this.refs.mode.value=this.mode;
    this.refs.architecture.value=this.architecture;
    this.refs.upstream.value=this.upstream;
    this.updateProtocolControls();
    this.activeSteps=this.journeyFor();
    this.ensureLayoutRoutes(this.traceQueue);
    const meta=modeMetadata[this.mode];
    this.querySelector('#scenario-title').textContent=this.advancedFlow?.title||meta.title;
    const description=this.isSingleRealm?meta.description.replace(/the upstream provider/gi,'the Keycloak realm').replace(/upstream/gi,'Realm A'):meta.description;
    const protocolText=this.applicationProtocol==='saml'?'SAML assertion → web service provider':'OIDC code + PKCE → application';
    this.querySelector('#scenario-description').textContent=description+' · '+(this.isDirectFido?'Web application is the WebAuthn relying party · RP ID app.example.test · direct credential verification':this.isSingleRealm?'One Keycloak realm verifies the person · '+protocolText:(ARCHITECTURES[this.architecture].name||ARCHITECTURES[this.architecture].title)+' · '+protocolText+' · '+(this.upstream==='external'?'Independent upstream IdP':UPSTREAMS[this.upstream].name||UPSTREAMS[this.upstream].title));
    if(this.isAdvancedFlow)this.querySelector('#scenario-description').textContent=this.advancedFlow.summary+(this.labModel?'':this.advancedFlow.hasPerson?' · '+meta.title:' · No new end-user authentication');
    if(this.providerOwnsAuthentication){this.querySelector('#scenario-title').textContent='Provider-managed sign-in · '+this.providerProfile.title;this.querySelector('#scenario-description').textContent=this.applicationProtocol.toUpperCase()+' application · '+this.brokerProtocol.toUpperCase()+' federation · Authentication and MFA follow the external provider policy. No particular credential method or assurance level is assumed.';}
    if(this.learningPreset){this.querySelector('#scenario-title').textContent=this.learningPreset.title;this.querySelector('#scenario-description').textContent=this.learningPreset.summary+(this.upstream==='external'?' · '+this.providerProfile.title:'');}
    this.querySelector('#scenario-description').textContent=this.runtimeEnvironment.projectValue(this.querySelector('#scenario-description').textContent,this.environmentOptions);
    this.refs.mode.disabled=this.isAdvancedFlow&&!this.advancedFlow.hasPerson;
    this.querySelector('label[for="mode"]').textContent=this.isAdvancedFlow?(this.advancedFlow.hasPerson?'Verification method':'Human authentication'):'Learning journey';
    Object.entries(modeMetadata).forEach(([value,m])=>{const option=this.refs.mode.querySelector('[value="'+value+'"]');option.disabled=this.isAdvancedFlow&&!!(m.directFido||m.enrollment);option.textContent=this.isAdvancedFlow&&!this.advancedFlow.hasPerson&&value===this.mode?'Not used in this grant':m.title;});
    this.refs.authenticator.disabled=!meta.passkey||this.isAdvancedFlow&&!this.advancedFlow.hasPerson;
    if(this.upstream==='external'&&(this.providerManaged||this.providerProfileId!=='generic')){this.refs.mode.disabled=true;this.refs.authenticator.disabled=true;this.querySelector('label[for="mode"]').textContent='Corporate authentication';this.refs.mode.querySelector('[value="'+this.mode+'"]').textContent='Managed by the external provider';}
    this.refs.architecture.disabled=this.isDirectFido||this.applicationProtocol==='saml'||this.isAdvancedFlow&&this.oidcFlow!=='device';this.refs.upstream.disabled=this.isDirectFido||this.isAdvancedFlow;
    this.refs.architecture.querySelector('[value="web"]').textContent=this.isDirectFido?'Network web app · relying-party server':this.applicationProtocol==='saml'?'Network web app · SAML service provider':ARCHITECTURES.web.title;
    this.refs.architecture.title=this.isDirectFido?'Direct WebAuthn is served by the web application at its HTTPS origin.':this.applicationProtocol==='saml'?'This SAML Web SSO example uses the server’s HTTPS Assertion Consumer Service (ACS).':'';
    this.refs.architecture.querySelector('[value="native"]').textContent=this.oidcFlow==='device'?'Limited-input device · public client':ARCHITECTURES.native.name||ARCHITECTURES.native.title;
    if(this.isAdvancedFlow){this.refs.architecture.querySelector('[value="web"]').textContent=this.oidcFlow==='device'?'Device service · confidential backend':this.oidcFlow==='ciba'?'Consumption app · confidential backend':this.oidcFlow==='token-exchange'?'Token requester · confidential backend':'Background service · confidential client';this.refs.architecture.title=this.oidcFlow==='device'?'Choose public or confidential device-client authentication; neither variant has an inbound application callback.':'This example authenticates its confidential backend directly to Realm A.';}
    this.refs.upstream.querySelector('[value="external"]').textContent='Keycloak + external '+(this.brokerProtocol==='saml'?'SAML':'OIDC')+' IdP';
    this.refs.upstream.title=this.isDirectFido?'The web application verifies the credential directly; no upstream IdP participates.':this.isAdvancedFlow?'This grant walkthrough uses one Keycloak realm. CIBA’s controlled authentication service is a separate integration, not another realm.':'';
    this.refs['lab-scenario'].value=this.labScenarioId;
    this.scenarioPicker.setSelected(this.labScenarioId);
    if(this.labModel){
      this.refs.mode.disabled=true;this.refs.authenticator.disabled=true;this.refs.architecture.disabled=true;this.refs.upstream.disabled=true;
      this.querySelector('label[for="mode"]').textContent='Scenario policy';this.refs.mode.querySelector('[value="'+this.mode+'"]').textContent='Defined by this scenario';
      this.refs.architecture.querySelector('[value="'+this.architecture+'"]').textContent=this.labModel.clientKind|| (this.architecture==='native'?'Browser / public client deployment':'Server / protocol deployment');
      this.refs.upstream.title='Participants and identity roles are specified by the selected scenario.';
    }
    this.renderCatalog();this.renderLabSupport();
    this.querySelectorAll('[data-learning-preset]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.learningPreset===this.labScenarioId)));
    this.refs['provider-settings'].hidden=this.upstream!=='external'||!!this.labModel||this.isDirectFido;
    this.refs['provider-profile'].value=this.providerProfile.id;
    this.refs['provider-note'].textContent=this.providerProfile.assumptions.join(' ');
    this.querySelector('#provider-sources').innerHTML=this.providerProfile.sources.map(source=>`<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.name)}</a>`).join('');
    this.renderEnvironmentFields();
    this.renderActors();this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.renderInspector();this.updateStep();this.updateControls();
  }
  updateProtocolControls() {
    const direct=this.isDirectFido,enrollment=!!modeMetadata[this.mode]?.enrollment;
    const appOidc=!direct&&this.applicationProtocol==='oidc'&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson),brokerOidc=!direct&&!this.isAdvancedFlow&&this.upstream!=='single'&&this.brokerProtocol==='oidc';
    const brokerEncryptionAllowed=this.upstream!=='external'||this.providerProfile.brokerTokenProtection?.includes('jwe');
    if(!brokerEncryptionAllowed&&['broker-jwe','both-jwe'].includes(this.tokenProtection)){this.tokenProtection=this.tokenProtection==='both-jwe'&&appOidc?'app-jwe':'signed';this.showToast('This provider profile uses signed broker identity results. Choose Generic external IdP to study broker JWE on an OIDC leg.');}
    if(this.isAdvancedFlow&&(!appOidc||this.tokenProtection==='broker-jwe'))this.tokenProtection='signed';
    const saml=!direct&&(this.applicationProtocol==='saml'||this.upstream!=='single'&&this.brokerProtocol==='saml');
    const values={'oidc-flow':this.oidcFlow,'app-protocol':this.applicationProtocol,'broker-protocol':this.brokerProtocol,'saml-binding':this.samlBinding,'saml-initiation':this.samlInitiation,'token-protection':this.tokenProtection,'assertion-protection':this.assertionProtection};
    const disabled={'app-protocol':direct,'broker-protocol':direct||this.upstream==='single'||this.upstream==='external'&&this.providerProfileId!=='generic','saml-binding':!saml||enrollment,'saml-initiation':direct||this.applicationProtocol!=='saml'||enrollment,'token-protection':direct||enrollment||!appOidc&&!brokerOidc,'assertion-protection':!saml||enrollment};
    disabled['oidc-flow']=direct||enrollment||this.applicationProtocol==='saml';
    Object.entries(values).forEach(([id,value])=>{this.refs[id].value=value;this.refs[id].disabled=disabled[id];});
    const protectionOptions={'app-jwe':!appOidc,'broker-jwe':!brokerOidc||!brokerEncryptionAllowed,'both-jwe':!brokerEncryptionAllowed||!appOidc&&!brokerOidc};
    Object.entries(protectionOptions).forEach(([value,disabled])=>{this.refs['token-protection'].querySelector('[value="'+value+'"]').disabled=disabled;});
    let summary=direct?'Direct FIDO2 · application is the RP':enrollment?'Credential enrollment · verified account':(this.applicationProtocol.toUpperCase()+' application'+(this.upstream==='single'?' · one realm':' · '+this.brokerProtocol.toUpperCase()+' broker'));
    if(this.isAdvancedFlow)summary=this.advancedFlow.title+' · one realm';
    this.refs['app-protocol'].querySelector('[value="oidc"]').textContent=this.isAdvancedFlow?'OIDC / OAuth · selected grant':'OIDC · Authorization Code';
    if(!direct&&!enrollment&&(appOidc&&['app-jwe','both-jwe'].includes(this.tokenProtection)||brokerOidc&&['broker-jwe','both-jwe'].includes(this.tokenProtection)))summary+=' · JWE';
    if(!direct&&!enrollment&&saml&&this.assertionProtection==='encrypted')summary+=' · XML Encryption';
    this.refs['protocol-summary'].textContent=summary;
    const protectionNote=this.querySelector('#provider-protection-note');protectionNote.hidden=brokerEncryptionAllowed;protectionNote.textContent=this.brokerProtocol==='saml'?'This base provider profile uses signed SAML identity results. SAML assertion encryption uses XML Encryption; OIDC ID-token encryption uses JWE. Application-side protection follows the application protocol selected above.':'This base provider profile uses signed broker ID tokens. An OIDC application leg can use Keycloak-to-application JWE independently. Choose Generic external IdP to study configured broker JWE.';
    if(this.labModel){Object.keys(values).forEach(id=>this.refs[id].disabled=true);this.refs['protocol-summary'].textContent=this.labModel.title+' · scenario-specific protocol';}
  }
  renderActors() {
    const activeActors=new Set(this.steps.flatMap(s=>[this.nodeId(s.from),this.nodeId(s.to)]));
    this.refs.actors.innerHTML=Object.keys(ACTORS).map(id=>{
      const a=this.actor(id),p=this.positions[a.id];if(!p)return '';
      const isAlternative=(a.id==='hello'||a.id==='yubikey')&&a.id!==this.authenticator;
      const context=this.actorContextHtml(a.id,true);
      const role=this.labModel?a.role:this.isAdvancedFlow?{user:'The person approving',app:this.oidcFlow==='device'?(this.architecture==='web'?'Confidential device client':'Public device client'):this.oidcFlow==='ciba'?'Confidential CIBA client':this.oidcFlow==='token-exchange'?'Confidential token requester':'Confidential service client',browser:this.oidcFlow==='ciba'?'Separate authentication device':'Separate verification device',realmA:this.oidcFlow==='ciba'?'OIDC CIBA provider':'OAuth authorization server',realmB:'Authentication channel',hello:'Platform authenticator',yubikey:'FIDO2 security key',totp:'Authenticator app'}[a.id]:{user:'The person signing in',app:this.isDirectFido?'WebAuthn relying party':this.applicationProtocol==='saml'?'SAML service provider':this.architecture==='web'?'Confidential OIDC backend':'Native OIDC client',browser:'System browser',realmA:this.isSingleRealm?'Keycloak · '+this.applicationProtocol.toUpperCase()+' provider':'IdP 1 · '+this.brokerProtocol.toUpperCase()+' broker',realmB:this.upstream==='external'?'Independent '+this.brokerProtocol.toUpperCase()+' provider':'IdP 2 · Checks identity',hello:'Platform authenticator',yubikey:'FIDO2 security key',totp:'Authenticator app'}[a.id]||a.plainRole;
      return `<button class="actor-card ${context?'has-context':''} ${this.isAdvancedFlow?'is-advanced':''} ${activeActors.has(a.id)?'':'is-muted'}" data-actor="${a.id}" aria-haspopup="dialog" aria-controls="actor-popup" aria-keyshortcuts="F2" ${context?`aria-describedby="actor-context-${a.id}"`:''} ${!this.labModel&&this.isSingleRealm&&a.id==='realmB'&&this.oidcFlow!=='ciba'?'hidden':''} aria-label="Inspect ${escapeHtml(a.name)}"><span class="actor-status">${!this.labModel&&isAlternative?'OPTION':activeActors.has(a.id)?'':this.isDirectFido||this.isSingleRealm?'NOT USED':'OPTION'}</span><span class="actor-art">${this.illustration(a.id)}</span><span class="actor-name">${escapeHtml(a.name)}</span><span class="actor-role">${escapeHtml(role)}</span>${context}<span class="actor-trace-action" hidden></span></button>`;
    }).join('');
    // Assign individual CSSOM properties after insertion; HTML style attributes
    // are intentionally forbidden by the standalone page's CSP.
    this.refs.actors.querySelectorAll('[data-actor]').forEach(card=>{const p=this.positions[card.dataset.actor];card.style.left=p.x/GRAPH_WIDTH*100+'%';card.style.top=p.y/GRAPH_HEIGHT*100+'%';});
  }
  actorContextRows(id) {
    const model=this.advancedFlow,config=this.protocolConfig(),options={...this.environmentOptions,applicationProtocol:this.applicationProtocol,brokerProtocol:this.brokerProtocol,labScenarioId:model?(model.id||'grant-'+this.oidcFlow):undefined,oidcFlow:this.oidcFlow};
    if(!model)return this.runtimeEnvironment.participantContext(id,options);
    const actor=model.actors(config)[id];if(!actor)return Object.freeze([]);
    const definitions={...ATTRIBUTES,...model.definitions(config)},examples=model.examples(config),value=key=>examples[key]??definitions[key]?.example;
    // These bindings name the actor's issuer, rather than another party's
    // assertion/hint/audience that the same actor happens to receive.
    const ownIssuer={
      'lab-ciba-push':{realmA:['grantCibaPushIssuer','OIDC issuer']},
      'lab-ciba-hint-token':{realmA:['grantCibaHintTokenIssuer','OIDC issuer']},
      'lab-jwt-grant':{realmB:['protGrantIss','Assertion issuer']},
      'lab-exchange-external-in':{realmB:['grantExchangeExternalInIssuer','Assertion issuer']},
      'lab-broker-account-link':{realmB:['branchExternalIssuer','OIDC issuer']},
    }[model.id]?.[id];
    if(ownIssuer){const [key,label]=ownIssuer,source=value(key),projected=this.runtimeEnvironment.projectValue(source,{...this.environmentOptions,attributeId:key});return Object.freeze([Object.freeze({key:'issuerURL',label,value:projected,provenance:projected===source?'example':'applied'})]);}
    // Other reused upstream slots are APIs, secondary RPs or controlled
    // authentication services. They have no declared Keycloak deployment.
    if(id==='realmB')return Object.freeze([]);
    const exampleValues={};
    if(id===options.clientActor){
      const owned=name=>{const matches=actor.attributes.filter(field=>definitions[field.id]?.name===name);return matches.length===1?value(matches[0].id):undefined;};
      const callback=owned('redirect_uri'),client=owned('client_id');
      if(callback){exampleValues.redirectApp=callback;try{exampleValues.appURL=new URL(callback).origin;}catch{/* omit an ambiguous application address */}}
      if(client)exampleValues.clientIdApp=client;
    }
    return this.runtimeEnvironment.participantContext(id,{...options,exampleValues});
  }
  actorContextHtml(id,compact=false) {
    const rows=this.actorContextRows(id);if(!rows.length)return '';
    if(!compact)return '<section class="participant-context"><h3 class="section-title">Displayed environment</h3><dl>'+rows.map(row=>`<dt>${escapeHtml(row.label)}</dt><dd><code>${escapeHtml(row.value)}</code></dd>`).join('')+'</dl></section>';
    const byKey=key=>rows.find(row=>row.key===key),primary=id===this.environmentOptions.clientActor&&this.environmentOptions.executionEnvironment==='native'?byKey('appCallbackURL')||byKey('appURL'):byKey('appURL')||byKey('keycloakBaseURL')||byKey('issuerURL')||byKey('ssoURL')||byKey('samlEntityID');
    if(!primary)return '';
    const realm=byKey('realm'),entity=byKey('samlEntityID');
    const identity=realm?realm:entity&&entity!==primary?entity:null;
    return `<span class="actor-context" id="actor-context-${id}" aria-label="${escapeHtml(primary.label)}: ${escapeHtml(primary.value)}" title="${escapeHtml(rows.map(row=>row.label+': '+row.value).join('\n'))}">${identity?`<span class="actor-context-identity">${escapeHtml(identity.label)}: ${escapeHtml(identity.value)}</span>`:''}<code class="actor-context-address">${escapeHtml(primary.value)}</code></span>`;
  }
  renderConnections() {
    const pairs=new Map();
    const focusPairs=new Set(this.traceQueue.map(s=>pairKey(this.nodeId(s.from),this.nodeId(s.to))));
    [...this.steps,...(this.attributeSelection?this.traceQueue:[])].forEach(s=>{
      const from=this.nodeId(s.from),to=this.nodeId(s.to),key=pairKey(from,to);
      if(!pairs.has(key))pairs.set(key,{from,to,channel:channelCategory(s.channel),count:0});
      pairs.get(key).count++;
    });
    this.querySelector('#connection-paths').innerHTML=[...pairs.entries()].map(([key,p])=>{
      const label=`Replay ${p.count} ordered exchange${p.count===1?'':'s'} between ${this.actor(p.from).name} and ${this.actor(p.to).name}`;
      const outside=this.attributeSelection&&!focusPairs.has(key),d=connectionPath(p.from,p.to,this.positions);
      return `<g class="connection-group ${outside?'is-outside-trace':''}" data-pair="${key}" data-channel="${p.channel}"><title>${escapeHtml(label)}</title><path class="connection-line ${p.channel}" d="${d}"/><path class="connection-hit" d="${d}" role="button" tabindex="${outside?-1:0}" aria-label="${escapeHtml(label)}"/></g>`;
    }).join('');
  }
  renderTimeline() {
    this.refs.timeline.innerHTML=this.visibleSteps.map((s,i)=>`<button class="timeline-step ${i===this.visibleIndex?'is-current':''} ${this.attributeSelection?'is-trace-step':''}" data-step="${i}" aria-current="${i===this.visibleIndex?'step':'false'}"><span class="step-number">${String(i+1).padStart(2,'0')}</span><span class="step-title">${escapeHtml(s.title)}</span><span class="step-phase">${escapeHtml(this.attributeSelection?(s.traceKind+' · journey '+(s.sourceIndex+1)):s.phase)}</span></button>`).join('');
  }
  selectStep(index,animate=false) {
    this.player.stop(false);this.hidePopups();
    if(this.attributeSelection){this.traceIndex=index;this.index=this.traceQueue[index]?.sourceIndex||0;this.inspection=this.traceInspection();}
    else {this.index=index;this.inspection={type:'step'};}
    this.refs.packet.hidden=true;this.hideStepAttributes();this.updateStep();this.renderInspector();this.updateControls();
    if(animate&&this.currentStep){this.ensureRunningSpeed();this.player.play([this.currentStep],this.attributeSelection?'attribute-step':'step');}
  }
  reset() {
    if(this.attributeSelection){this.selectAttribute(this.attributeSelection,false);return;}
    this.player.stop(false);this.index=0;this.visited.clear();this.packetIdentity='';this.inspection={type:'step'};
    this.attributeSelection=null;this.traceQueue=[];this.traceIndex=0;
    this.hidePopups();this.refs.packet.hidden=true;this.hideStepAttributes();this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.updateStep();this.renderInspector();this.updateControls();
  }
  replayConnection(pair) {
    this.hidePopups();const exchanges=connectionSteps(this.visibleSteps,pair,this.authenticator);
    if(!exchanges.length)return;
    this.ensureRunningSpeed();
    this.inspection=this.attributeSelection?this.traceInspection():{type:'connection',pair,exchanges};this.renderInspector();
    this.player.play(exchanges,this.attributeSelection?'attribute-connection':'connection');
  }
  inspectActor(id) {this.hidePopups();this.inspection={type:'actor',id};this.renderInspector();this.updateNodeSelection();}
  updateNodeSelection() {this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>n.classList.toggle('is-selected',this.inspection.type==='actor'&&n.dataset.actor===this.inspection.id));}
  updateStep() {
    const s=this.currentStep;
    if(!s){this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>{n.classList.remove('is-source','is-target','is-trace-participant');n.classList.add('is-outside-trace');n.querySelector('.actor-trace-action').hidden=true;});this.refs.connections.querySelectorAll('[data-pair]').forEach(g=>{g.classList.remove('is-active');g.querySelector('.connection-line').removeAttribute('marker-end');});this.refs.story.innerHTML='<p class="empty-state">This field has no replayable operation in this journey. Choose one of the available journeys in the inspector.</p>';this.refs.progress.style.width='0%';this.refs.progress.parentElement.setAttribute('aria-valuenow','0');return;}
    const source=this.nodeId(s.from),target=this.nodeId(s.to),pair=pairKey(source,target),category=channelCategory(s.channel);
    const focusActors=new Set(this.traceQueue.flatMap(step=>[this.nodeId(step.from),this.nodeId(step.to)]));
    this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>{
      n.classList.toggle('is-source',n.dataset.actor===source);n.classList.toggle('is-target',n.dataset.actor===target);
      n.classList.toggle('is-outside-trace',!!this.attributeSelection&&!focusActors.has(n.dataset.actor));n.classList.toggle('is-trace-participant',!!this.attributeSelection&&focusActors.has(n.dataset.actor));
      const badge=n.querySelector('.actor-trace-action'),active=!!this.attributeSelection&&(n.dataset.actor===source||n.dataset.actor===target);
      badge.hidden=!active;if(active)badge.textContent=s.from===s.to?TRACE_ACTION_LABELS[s.traceKind]:n.dataset.actor===source?'Send':'Receive';
    });
    this.refs.connections.querySelectorAll('[data-pair]').forEach(g=>{
      const active=g.dataset.pair===pair;g.classList.toggle('is-active',active);g.classList.toggle('is-visited',this.visited.has(g.dataset.pair));
      if(active){g.dataset.channel=category;const path=g.querySelector('.connection-line');path.setAttribute('d',connectionPath(source,target,this.positions));path.setAttribute('class','connection-line '+category);path.setAttribute('marker-end','url(#arrow-'+category+')');}
      else g.querySelector('.connection-line').removeAttribute('marker-end');
    });
    this.refs.timeline.querySelectorAll('[data-step]').forEach(button=>{const n=Number(button.dataset.step);button.classList.toggle('is-current',n===this.visibleIndex);button.classList.toggle('is-done',n<this.visibleIndex);button.setAttribute('aria-current',n===this.visibleIndex?'step':'false');});
    const percentage=Math.round(this.visibleIndex/this.visibleSteps.length*100);this.refs.progress.style.width=percentage+'%';
    this.refs.progress.parentElement.setAttribute('aria-valuenow',percentage);
    this.refs.story.innerHTML=`<span class="story-index">${String(this.visibleIndex+1).padStart(2,'0')} / ${String(this.visibleSteps.length).padStart(2,'0')}</span><div><span class="story-phase">${escapeHtml(this.attributeSelection?'ATTRIBUTE PATH · '+s.traceKind:s.phase)}</span><p>${escapeHtml(s.summary)}</p></div>`;
    this.updateNodeSelection();
  }
  onPlayer(event) {
    if(event.type==='step'&&event.step){
      const index=this.steps.findIndex(s=>s.id===(event.step.sourceStepId||event.step.id));if(index>=0)this.index=index;
      if(this.attributeSelection){const traceIndex=this.traceQueue.findIndex(s=>s.id===event.step.id);if(traceIndex>=0)this.traceIndex=traceIndex;}
      this.updateStep();if(this.inspection.type==='step'||(this.attributeSelection&&['attribute','topic'].includes(this.inspection.type)))this.renderInspector();
      const button=this.refs.timeline.querySelector(`[data-step="${this.visibleIndex}"]`);
      if(button)this.refs.timeline.scrollTo?.({left:this.refs.timeline.scrollLeft+button.getBoundingClientRect().left-this.refs.timeline.getBoundingClientRect().left-(this.refs.timeline.clientWidth-button.offsetWidth)/2,behavior:'smooth'});
      this.packetIdentity='';
      // A new queue can deliberately stay paused and never receive a frame.
      // Its packet must replace the previous step's packet immediately.
      this.refs.packet.hidden=true;this.renderPacket(event);
    }
    if(event.type==='frame')this.renderPacket(event);
    if(['step','frame','state','complete'].includes(event.type))this.updateSeekControls(event);
    if(event.type==='stepcomplete'&&event.step){this.visited.add(pairKey(this.nodeId(event.step.from),this.nodeId(event.step.to)));this.hideStepAttributes();}
    if(event.type==='complete'){
      this.refs.packet.hidden=true;this.hideStepAttributes();
      if(event.kind==='demo'||event.kind==='attribute'){this.showToast(event.kind==='attribute'?'Attribute path complete. Choose another field or return to the full journey.':'Journey complete. Replay any connection to explore its details.');}
      this.updateStep();if(event.kind==='demo'||event.kind==='attribute'){this.refs.progress.style.width='100%';this.refs.progress.parentElement.setAttribute('aria-valuenow','100');}
    }
    if(['state','speed','complete'].includes(event.type))this.updateControls();
    if(event.type==='state')this.renderStepAttributes(event);
  }
  hideStepAttributes() {
    if(!this.refs)return;
    this.refs['step-attributes'].hidden=true;this.refs['step-attributes-tether'].hidden=true;this.stepOverlayIdentity='';
  }
  stepAttributeItems(step) {
    const source=step.sourceStepId?this.steps.find(s=>s.id===step.sourceStepId)||step:step;
    const from=this.nodeId(step.from),to=this.nodeId(step.to),operations=getStepAttributeOperations(source,this.authenticator);
    const local=operations.filter(a=>!['inspect','send','receive'].includes(a.kind));
    let relevant=from===to?local.filter(a=>a.actorId===from):operations.filter(a=>a.kind==='send'&&a.actorId===from);
    if(from!==to&&!relevant.length)relevant=local.filter(a=>a.actorId===from||a.actorId===to);
    const items=new Map();
    for(const operation of relevant){
      const definition=ATTRIBUTES[operation.attributeId];if(!definition)continue;
      const name=definition.name.replace(/\s*\([^)]*\)/g,'').trim();
      if(!items.has(name))items.set(name,{name,ids:[]});
      const item=items.get(name);if(!item.ids.includes(operation.attributeId))item.ids.push(operation.attributeId);
    }
    return [...items.values()];
  }
  renderStepAttributes(event,force=false) {
    if(!this.refs)return;
    if(!this.showStepAttributes||!['playing','paused'].includes(event.status)||!event.step){this.hideStepAttributes();return;}
    const overlay=this.refs['step-attributes'],step=event.step;
    if(force||this.stepOverlayIdentity!==step.id){
      const items=this.stepAttributeItems(step);
      if(!items.length){this.hideStepAttributes();return;}
      this.stepOverlayIdentity=step.id;
      overlay.innerHTML=items.map(item=>`<code data-step-attribute="${escapeHtml(item.ids.join(' '))}">${escapeHtml(item.name)}</code>`).join('');
      overlay.dataset.step=step.sourceStepId||step.id;overlay.dataset.channel=channelCategory(step.channel);overlay.hidden=false;
      this.positionStepAttributes(step);
    }
    const current=event.visible?(event.packet?.attributeId||(event.packet?this.payloadAttributeId(event.packet,step):null)):null;
    overlay.querySelectorAll('[data-step-attribute]').forEach(field=>field.classList.toggle('is-current',!!current&&field.dataset.stepAttribute.split(' ').includes(current)));
  }
  positionStepAttributes(step) {
    const pair=pairKey(this.nodeId(step.from),this.nodeId(step.to)),group=this.refs.connections.querySelector(`[data-pair="${pair}"]`),path=group?.querySelector('.connection-line');
    if(!path){this.hideStepAttributes();return;}
    const overlay=this.refs['step-attributes'],graphRect=this.refs.graph.getBoundingClientRect(),panelRect=overlay.getBoundingClientRect();
    const size={width:panelRect.width*GRAPH_WIDTH/(graphRect.width||GRAPH_WIDTH),height:panelRect.height*GRAPH_HEIGHT/(graphRect.height||GRAPH_HEIGHT)};
    const length=path.getTotalLength(),points=Array.from({length:25},(_,i)=>path.getPointAtLength(length*i/24));
    const placement=placeStepOverlay(points,size,this.positions);
    overlay.style.left=placement.x/GRAPH_WIDTH*100+'%';overlay.style.top=placement.y/GRAPH_HEIGHT*100+'%';
    const anchor=placement.anchor,edge={x:Math.max(placement.x,Math.min(placement.x+placement.width,anchor.x)),y:Math.max(placement.y,Math.min(placement.y+placement.height,anchor.y))},tether=this.refs['step-attributes-tether'];
    tether.dataset.channel=channelCategory(step.channel);tether.querySelector('path').setAttribute('d',`M ${anchor.x} ${anchor.y} L ${edge.x} ${edge.y}`);tether.hidden=false;
  }
  renderPacket(event) {
    if(!event.step)return;
    this.renderStepAttributes(event);
    const from=this.nodeId(event.step.from),to=this.nodeId(event.step.to),pair=pairKey(from,to);
    const group=[...this.refs.connections.querySelectorAll('[data-pair]')].find(g=>g.dataset.pair===pair);
    const path=group?.querySelector('.connection-line');if(!path)return;
    const packet=event.packet||{name:'Local action',value:event.step.title};
    const identity=event.step.id+':'+event.packetIndex;
    if(identity!==this.packetIdentity){
      this.packetIdentity=identity;this.refs['packet-name'].textContent=packet.name;this.refs['packet-value'].textContent=String(packet.value).slice(0,38)+(String(packet.value).length>38?'…':'');
      this.refs['packet-count'].textContent=(event.packetIndex+1)+'/'+Math.max(1,event.step.payload.length);
      this.refs.packet.dataset.channel=channelCategory(event.step.channel);
      if(!window.matchMedia('(prefers-reduced-motion: reduce)').matches)this.refs.packet.querySelector('.packet-chip').animate?.([{opacity:.2,transform:'scale(.86)'},{opacity:1,transform:'scale(1)'}],{duration:180,fill:'both'});
    }
    this.refs.packet.hidden=!event.visible;
    if(event.visible){
      const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const point=path.getPointAtLength(path.getTotalLength()*(reduced?.5:event.progress));
      this.refs.packet.style.left=Math.max(112,Math.min(GRAPH_WIDTH-112,point.x))/GRAPH_WIDTH*100+'%';this.refs.packet.style.top=Math.max(40,Math.min(GRAPH_HEIGHT-40,point.y))/GRAPH_HEIGHT*100+'%';
    }
  }
  ensureRunningSpeed() {if(this.player.speed===0)this.player.setSpeed(this.lastRunningSpeed||1);}
  studyClock() {
    const steps=this.visibleSteps;
    if(this.seekMemo?.steps===steps)return this.seekMemo;
    const durations=steps.map(step=>this.player.totalDuration([step])),offsets=[];let total=0;
    for(const duration of durations){offsets.push(total);total+=duration;}
    return this.seekMemo={steps,durations,offsets,total};
  }
  seekPlayback(fraction) {
    const clock=this.studyClock();if(!clock.steps.length)return;
    this.hidePopups();this.inspection=this.attributeSelection?this.traceInspection():{type:'step'};
    this.visited.clear();this.packetIdentity='';
    this.player.seek(clock.steps,fraction,this.attributeSelection?'attribute':'demo');
    const state=this.player.snapshot(),completedCount=this.visibleIndex+(state.stepElapsed>=state.duration?1:0);
    for(let i=0;i<completedCount;i++){const step=clock.steps[i];this.visited.add(pairKey(this.nodeId(step.from),this.nodeId(step.to)));}
    this.updateStep();this.renderInspector();this.updateSeekControls(this.player.snapshot());
  }
  updateSeekControls(event=this.player.snapshot()) {
    if(!this.refs?.seek)return;
    const clock=this.studyClock(),found=event.step?clock.steps.findIndex(step=>step.id===event.step.id):-1,index=found>=0?found:Math.max(0,Math.min(clock.steps.length-1,this.visibleIndex));
    const elapsed=(clock.offsets[index]||0)+(found>=0?Math.min(clock.durations[index],Math.max(0,event.stepElapsed||0)):0),fraction=clock.total?Math.max(0,Math.min(1,elapsed/clock.total)):0;
    this.refs.seek.value=String(Math.round(fraction*1000));this.refs.seek.disabled=!clock.steps.length;
    const stamp=ms=>{const seconds=Math.floor(ms/1000);return String(Math.floor(seconds/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0');};
    this.refs['seek-position'].textContent=(this.attributeSelection?'Moment ':'Step ')+(index+1)+' / '+clock.steps.length+' · '+stamp(elapsed)+' / '+stamp(clock.total);
    this.refs.seek.setAttribute('aria-valuetext',(this.attributeSelection?'Moment ':'Step ')+(index+1)+' of '+clock.steps.length+': '+(clock.steps[index]?.title||''));
    const percentage=Math.round(fraction*100);this.refs.progress.style.width=percentage+'%';this.refs.progress.parentElement.setAttribute('aria-valuenow',percentage);
  }
  updateControls() {
    const status=this.player.status;
    const label=status==='playing'?'Pause':status==='paused'?'Resume':this.attributeSelection?'Play attribute path':'Play demo';
    this.refs.play.innerHTML=uiIcon(status==='playing'?'pause':'play',status!=='playing')+'<span>'+label+'</span>';
    this.refs.play.setAttribute('aria-label',label+' animation');
    this.refs.play.disabled=!!this.attributeSelection&&!this.traceQueue.length;
    if(this.player.speed>0)this.lastRunningSpeed=this.player.speed;
    this.refs.speed.value=String(this.player.speed);this.refs['speed-label'].textContent=this.player.speed===0?'Stopped':this.player.speed+'×';
    this.refs.status.textContent=status==='playing'?(this.attributeSelection?'FOLLOWING ATTRIBUTE':this.player.kind==='connection'?'REPLAYING CONNECTION':'DEMO RUNNING'):status==='paused'?'PAUSED':status==='complete'?'COMPLETE':'READY TO EXPLORE';
    this.refs.status.dataset.status=status;
    this.querySelector('#previous').disabled=this.visibleIndex===0||!this.visibleSteps.length;this.querySelector('#next').disabled=this.visibleIndex>=this.visibleSteps.length-1;
    this.refs['attribute-focus'].querySelectorAll('[data-trace-play]').forEach(button=>{button.textContent=status==='playing'?'Pause':status==='paused'?'Resume':'Replay path';button.disabled=!this.traceQueue.length;});
    this.updateSeekControls();
  }
  renderInspector() {
    const returnTarget=this.refs.inspector.contains(document.activeElement)?captureFocusTarget(this,document.activeElement):null;
    const view=this.inspection;
    this.refs['inspector-heading'].textContent={step:'EXCHANGE INSPECTOR',actor:'PARTICIPANT INSPECTOR',attribute:'ATTRIBUTE LIFECYCLE',topic:'ATTRIBUTE LIFECYCLE',glossary:'FIELD GUIDE',connection:'CONNECTION INSPECTOR'}[view.type];
    let html='';
    if(view.type==='step')html=this.stepHtml(this.currentStep,this.visibleIndex);
    if(view.type==='actor')html=this.actorHtml(this.actor(view.id));
    if(view.type==='attribute'||view.type==='topic')html=this.traceHtml(view.id);
    if(view.type==='glossary')html=`<div class="inspector-kicker">CANONICAL NAMES · PLAIN ENGLISH</div><h2 class="inspector-title">Know what moves.</h2><p class="inspector-summary">Every field has a job. Hover to learn its meaning; click to keep the explanation open.</p><label class="sr-only" for="glossary-search">Search protocol fields</label><input class="glossary-search" id="glossary-search" type="search" placeholder="Search a field or purpose…"><div class="glossary-list">${Object.entries(ATTRIBUTES).map(([id,a])=>`<button class="attribute-button" data-attribute="${id}" data-search="${escapeHtml((a.name+' '+a.meaning+' '+a.purpose).toLowerCase())}"><code>${escapeHtml(a.name)}</code><span>${escapeHtml(a.standard)}</span></button>`).join('')}</div>`;
    if(view.type==='connection'){
      const actors=view.pair.split('--').map(id=>this.actor(id));
      html=`<div class="inspector-kicker">ORDERED EXCHANGES ON THIS CONNECTION</div><h2 class="inspector-title">${escapeHtml(actors[0].name)} ${uiIcon('link')} ${escapeHtml(actors[1].name)}</h2><p class="inspector-summary">This connection carries ${view.exchanges.length} exchange${view.exchanges.length===1?'':'s'} during the journey. The demo sends each named object in order.</p><div class="connection-exchanges">${view.exchanges.map(s=>{const i=this.steps.findIndex(item=>item.id===s.id);return `<button class="connection-exchange" data-exchange-step="${i}"><span class="step-number">${String(i+1).padStart(2,'0')}</span><div><strong>${escapeHtml(s.title)}</strong><span>${escapeHtml(this.actor(s.from).name)} → ${escapeHtml(this.actor(s.to).name)}</span></div>${uiIcon('play')}</button>`;}).join('')}</div><div class="context-note">Each exchange uses the actual sender and receiver. Browser redirects and direct server requests are separate hops.</div>`;
    }
    this.refs.inspector.innerHTML=html;this.updateNodeSelection();
    if(returnTarget)this.restoreTargetFocus(returnTarget);
  }
  stepHtml(s,index) {
    if(!s)return '<div class="empty-state">Choose a journey to explore.</div>';
    const from=this.actor(s.from),to=this.actor(s.to),category=channelCategory(s.channel);
    const fields=s.fields||[];
    return `<div class="inspector-kicker">STEP ${String(index+1).padStart(2,'0')} OF ${this.visibleSteps.length} · ${escapeHtml(s.phase)}</div><h2 class="inspector-title">${escapeHtml(s.title)}</h2><p class="inspector-summary">${escapeHtml(s.summary)}</p><div class="route-row"><span class="route-actor">${escapeHtml(from.name)}</span>${uiIcon('arrow')}<span class="route-actor">${escapeHtml(to.name)}</span></div><span class="channel-badge" data-channel="${category}">${channelLabels[category]} · ${escapeHtml(s.channel)}</span><p class="step-detail">${escapeHtml(s.detail)}</p><button class="button quiet replay-button" data-replay>${uiIcon('play')}Replay this step</button><h3 class="section-title">${s.from===s.to?'What is created or checked':'Message fields & nested objects'}</h3>${s.from!==s.to?'<p class="field-description">Fields animate individually for learning. They belong to one message; each field is not a separate request.</p>':''}<div class="payload-list">${s.payload.map((p,i)=>{
      const id=this.payloadAttributeId(p,s);
      return `<div class="payload-row"><button class="field-name" ${id&&ATTRIBUTES[id]?`data-attribute="${id}"`:''}><span class="payload-number">${i+1}</span><code>${escapeHtml(p.name)}</code>${id&&ATTRIBUTES[id]?uiIcon('info'):''}</button><code class="field-value">${escapeHtml(p.value)}</code>${p.description?`<span class="field-description">${escapeHtml(p.description)}</span>`:''}</div>`;
    }).join('')}</div>${s.checks?.length?`<h3 class="section-title">What the receiver checks</h3><ul class="check-list">${s.checks.map(check=>`<li>${uiIcon('check')}<span>${escapeHtml(check)}</span></li>`).join('')}</ul>`:''}<h3 class="section-title">Explore these attributes</h3><div class="attribute-list">${fields.filter(id=>ATTRIBUTES[id]).map(id=>this.attributeButton(id)).join('')}</div>`;
  }
  attributeButton(id,kind) {const a=this.definition(id);return `<button class="attribute-button" data-attribute="${id}" aria-haspopup="dialog" aria-controls="attribute-popup" aria-keyshortcuts="F2"><code>${escapeHtml(a.name)}</code>${kind?`<span class="kind-badge ${kind}">${escapeHtml(ATTR_KIND[kind]||kind)}</span>`:uiIcon('info')}</button>`;}
  payloadAttributeId(payload,step) {
    if(payload.attributeId&&ATTRIBUTES[payload.attributeId])return payload.attributeId;
    const names=payload.name.replace(/^response\./,'').split(' / ');
    const exact=step.fields.find(id=>{
      const a=ATTRIBUTES[id];if(!a)return false;
      const candidates=a.name.split(' / ').map(n=>n.replace(/\s*\([^)]*\)/g,'').trim());
      return candidates.some(n=>names.includes(n));
    });
    if(exact)return exact;
    const aliases={URL:'authorizationEndpoint',T:'otpCounter',TOTP:'otpCode',otp:'otpCode',secret:'otpSecret',algorithm:'otpAlgorithm',digits:'otpDigits',period:'otpPeriod',username:'userName',rp:'rpObject',user:'userObject',authenticatorSelection:'authenticatorSelection','Provisioning URI (de facto)':'otpUri','Enrollment OTP input (form-specific)':'otpCode','OTP input':'otpCode'};
    const alias=payload.name==='username'&&step.fields.includes('loginUsername')?'loginUsername':aliases[payload.name];
    if(alias&&ATTRIBUTES[alias]&&step.fields.includes(alias))return alias;
    return null;
  }
  refreshConfiguration() {
    const selection=this.attributeSelection;
    this.player.stop(false);this.hidePopups();this.activeSteps=null;this.attributeSelection=null;this.traceQueue=[];this.traceIndex=0;this.index=0;this.visited.clear();this.inspection={type:'step'};this.refs.packet.hidden=true;this.hideStepAttributes();
    this.renderAll();if(selection)this.selectAttribute(selection,false);
  }
  exploreProtocol(protocol) {
    this.exitLab();
    const id=this.attributeSelection,broker=/Broker$|B$/.test(id||'')||['clientSecret','authorizationHeader'].includes(id);
    if(this.isAdvancedFlow)this.oidcFlow='authorization-code';
    if(this.isDirectFido||modeMetadata[this.mode]?.enrollment){this.mode='passkey';this.refs.mode.value=this.mode;}
    if(broker&&this.upstream==='single')this.upstream='keycloak';
    if(broker&&this.upstream==='external'&&this.providerProfileId!=='generic'&&(protocol==='saml'?'saml':'oidc')!==this.providerProfile.protocol){this.providerProfileId='generic';this.providerManaged=false;}
    if(protocol==='saml'){
      if(broker)this.brokerProtocol='saml';else this.applicationProtocol='saml';
      const ordered=(current,values)=>[current,...values.filter(value=>value!==current)];
      let candidate;
      for(const binding of ordered(this.samlBinding,['redirect','post'])){
        for(const initiation of ordered(this.samlInitiation,['sp','idp'])){
          for(const encryptAssertions of ordered(this.assertionProtection==='encrypted',[false,true])){
            if(!candidate&&getAttributeUsage(this.journeyFor(this.mode,{binding,initiation,encryptAssertions}),id,this.authenticator).length)candidate={binding,initiation,encryptAssertions};
          }
        }
      }
      if(candidate){this.samlBinding=candidate.binding;this.samlInitiation=candidate.initiation;this.assertionProtection=candidate.encryptAssertions?'encrypted':'signed';}
    }else if(protocol==='oidc'){
      if(broker)this.brokerProtocol='oidc';else this.applicationProtocol='oidc';
    }else{
      if(broker){this.brokerProtocol='oidc';this.tokenProtection='broker-jwe';}
      else {this.applicationProtocol='oidc';this.tokenProtection='app-jwe';}
    }
    this.refreshConfiguration();this.playAttribute();
  }
  exploreGrant(flow,options={}) {
    this.exitLab();
    this.oidcFlow=flow;this.applicationProtocol='oidc';
    for(const key of ['mode','authenticator','upstream','architecture'])if(options[key]){this[key]=options[key];this.refs[key].value=this[key];}
    if(this.isDirectFido||modeMetadata[this.mode]?.enrollment)this.mode='passkey';
    this.refreshConfiguration();this.playAttribute();
  }
  attributeUsage(steps,id,authenticator=this.authenticator) {
    if(LAB_TOPICS[id]&&LAB_TOPICS[id].labScenarioId!==(this.labModel?.id||this.labScenarioId))return [];
    if(grantTopicFlows[id]&&grantTopicFlows[id]!==this.oidcFlow)return [];
    return getAttributeUsage(steps,id,authenticator);
  }
  findAuthorizationJourney(id) {
    if(grantTopicFlows[id])return null;
    const modes=[this.mode,...Object.keys(modeMetadata).filter(m=>m!==this.mode)];
    const unique=values=>[...new Set(values)];
    for(const mode of modes)for(const upstream of unique([this.upstream,'single','keycloak','external']))for(const architecture of unique([this.architecture,'web','native']))for(const authenticator of unique([this.authenticator,'yubikey','hello'])){
      if(!this.canProbeJourney(mode,upstream))continue;
      const config={forceCore:true,oidcFlow:'authorization-code',applicationProtocol:'oidc',brokerProtocol:upstream==='external'&&this.providerProfileId!=='generic'?this.providerProfile.protocol:'oidc',upstream,architecture,authenticator};
      if(getAttributeUsage(this.journeyFor(mode,config),id,authenticator).length)return {mode,upstream,architecture,authenticator};
    }
    return null;
  }
  traceInspection() {return {type:ATTRIBUTE_TOPICS[this.attributeSelection]?'topic':'attribute',id:this.attributeSelection};}
  selectAttribute(id,animate=true) {
    const returnTarget=captureFocusTarget(this,document.activeElement);
    id=this.labAttributeAlias(id);
    if(!getAttributeIds(id).length)return;
    this.player.stop(false);this.hidePopups();this.attributeSelection=id;this.traceIndex=0;this.visited.clear();this.packetIdentity='';
    this.attributeUsages=this.attributeUsage(this.steps,id);
    const examples={...this.runtimeEnvironment.projectExamples({...(this.isDirectFido?getFidoExampleOverrides():getExampleOverrides(this.architecture,this.upstream)),...(this.isUsingSaml?getSamlExampleOverrides(this.protocolConfig()):{}),...(this.isAdvancedFlow?this.advancedFlow.examples(this.protocolConfig()):{}),...this.scenarioSnapshot().exampleOverrides},this.environmentOptions)};
    getAttributeIds(id).forEach(field=>examples[field]=this.definition(field).example);
    this.traceQueue=buildAttributeTrace(this.attributeUsages,examples);
    if(this.ensureLayoutRoutes(this.traceQueue))this.renderActors();
    this.index=this.traceQueue[0]?.sourceIndex||0;this.inspection=this.traceInspection();this.refs.packet.hidden=true;this.hideStepAttributes();
    this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.renderInspector();this.updateStep();this.updateControls();
    if(returnTarget&&(returnTarget.attributeId||returnTarget.topicId))this.restoreTargetFocus(returnTarget,{attributeId:ATTRIBUTE_TOPICS[id]?undefined:id,preferIndex:true});
    if(animate&&this.traceQueue.length)this.playAttribute();
  }
  clearAttribute() {
    this.attributeSelection=null;this.traceQueue=[];this.attributeUsages=[];this.reset();
  }
  playAttribute() {
    if(!this.attributeSelection||!this.traceQueue.length)return;
    this.ensureRunningSpeed();
    this.inspection=this.traceInspection();this.visited.clear();this.player.play(this.traceQueue,'attribute');
  }
  selectionName(id=this.attributeSelection) {return ATTRIBUTE_TOPICS[id]?.name||this.definition(id).name||id;}
  indexContext(id) {
    if(LAB_ATTRIBUTES[id])return labAttributeScenarios(id).map(model=>model.title).join(' · ');
    if(this.isAdvancedFlow&&getAttributeUsage(this.steps,id,this.authenticator).length)return this.advancedFlow.title;
    if(SERVICE_ATTRIBUTES[id])return 'Service accounts · client_credentials';
    if(DEVICE_ATTRIBUTES[id])return 'Device Authorization Flow';
    if(CIBA_ATTRIBUTES[id])return 'CIBA · controlled authentication channel';
    if(EXCHANGE_ATTRIBUTES[id])return 'Token exchange · Standard V2';
    if(SAML_ATTRIBUTES[id])return /Broker$|B$/.test(id)?'SAML · upstream IdP ↔ Realm A':/App$/.test(id)?'SAML · Realm A ↔ application':/A$/.test(id)?'SAML · Realm A provider / broker':'SAML XML · binding / assertion / SP policy';
    if(JWE_ATTRIBUTES[id])return /Broker$/.test(id)?'JWE · upstream IdP → Realm A':'JWE · Realm A → application';
    if(this.isDirectFido&&(/WebAuthn|FIDO|CTAP/.test(this.definition(id).standard)||['privateKey','credentialPublicKey'].includes(id)))return 'Web application RP ↔ authenticator';
    if(this.isSingleRealm&&(/Broker|B$/.test(id)||['clientSecret','authorizationHeader'].includes(id)))return 'Brokered setup · unused here';
    if(this.isSingleRealm&&id.startsWith('otp'))return 'TOTP · Keycloak Realm A';
    if(this.isSingleRealm&&(/WebAuthn|FIDO|CTAP/.test(this.definition(id).standard)||['privateKey','credentialPublicKey'].includes(id)))return 'Realm A ↔ authenticator';
    if(/Broker|B$/.test(id)||['clientSecret','authorizationHeader'].includes(id))return 'Realm A ↔ upstream provider';
    if(/App|A$/.test(id)||['codeVerifier','codeChallenge','codeChallengeMethod'].includes(id))return 'Application ↔ Realm A';
    if(id.startsWith('otp'))return 'TOTP · upstream provider';
    const a=this.definition(id);return a.standard?.split(' / ')[0]||'Protocol attribute';
  }
  renderAttributeIndex() {
    const focused=document.activeElement;
    const focusKey=this.refs['attribute-index-list'].contains(focused)?['data-index-attribute',focused.dataset.indexAttribute]:this.refs['attribute-topics'].contains(focused)?['data-trace-topic',focused.dataset.traceTopic]:null;
    const steps=this.steps;
    this.refs['attribute-topics'].innerHTML=Object.entries(ATTRIBUTE_TOPICS).filter(([,topic])=>!topic.labScenarioId||topic.labScenarioId===(this.labModel?.id||this.labScenarioId)).map(([id,topic])=>{
      const count=this.attributeUsage(steps,id).length;
      const summary=id==='clientIdentity'&&this.isAdvancedFlow?'The configured public client identifier selects the registration. Confidential variants authenticate the client separately; no identifier is generated per request.':this.isSingleRealm?topic.summary.replace(/\bB\b/g,'Realm A'):topic.summary;
      return `<button class="attribute-topic ${id===this.attributeSelection?'is-selected':''}" data-trace-topic="${id}" aria-pressed="${id===this.attributeSelection}" title="${escapeHtml(summary)}"><span>${escapeHtml({clientIdentity:'client_id · App',pkce:'PKCE',webauthn:'WebAuthn',fido2:'FIDO2 / CTAP2',totp:'TOTP',saml:'SAML',jwe:'JWE',serviceAccounts:'Service accounts',deviceFlow:'Device Flow',ciba:'CIBA',tokenExchange:'Token exchange'}[id]||topic.name||id)}</span><span>${count}</span></button>`;
    }).join('');
    this.refs['attribute-index-list'].innerHTML=Object.entries(ATTRIBUTES).sort((a,b)=>a[1].name.localeCompare(b[1].name)||a[0].localeCompare(b[0])).map(([id])=>{
      const a=this.definition(id),count=getAttributeUsage(steps,id,this.authenticator).length;
      const topics=Object.values(ATTRIBUTE_TOPICS).filter(t=>t.attributeIds.includes(id)).map(t=>t.name).join(' ');
      const search=(a.name+' '+a.meaning+' '+a.purpose+' '+a.origin+' '+a.standard+' '+topics).toLowerCase();
      return `<button class="attribute-index-item ${id===this.attributeSelection?'is-selected':''} ${count?'':'is-unavailable'}" data-index-attribute="${id}" aria-haspopup="dialog" aria-controls="attribute-popup" aria-keyshortcuts="F2" data-index-search="${escapeHtml(search)}" aria-pressed="${id===this.attributeSelection}"><code>${escapeHtml(a.name)}</code><span class="attribute-index-count" title="Journey steps with an operation">${count}</span><span class="attribute-index-context">${escapeHtml(this.indexContext(id))}</span></button>`;
    }).join('');
    this.refs['attribute-search'].value=this.attributeQuery;this.filterAttributeIndex();
    if(focusKey){
      const replacement=this.refs['attribute-index'].querySelector('['+focusKey[0]+'="'+focusKey[1]+'"]');
      if(replacement&&!replacement.hidden){
        if(this.attributeAnchor===focused)this.attributeAnchor=replacement;
        this.restoringPopupFocus=true;try{replacement.focus({preventScroll:true});}finally{this.restoringPopupFocus=false;}
      }
    }
  }
  filterAttributeIndex() {
    const q=this.attributeQuery.trim().toLowerCase();let count=0;
    this.refs['attribute-index-list'].querySelectorAll('[data-index-attribute]').forEach(button=>{button.hidden=!button.dataset.indexSearch.includes(q);if(!button.hidden)count++;});
    let topics=0;this.refs['attribute-topics'].querySelectorAll('[data-trace-topic]').forEach(button=>{const topic=ATTRIBUTE_TOPICS[button.dataset.traceTopic];button.hidden=!!q&&!((topic.name+' '+topic.summary+' '+topic.attributeIds.map(id=>this.definition(id).name).join(' ')).toLowerCase().includes(q));if(!button.hidden)topics++;});
    this.refs['attribute-index-meta'].textContent=count+' attributes · numbers count journey steps · 0 means unused in this setup';
    this.refs['attribute-index-empty'].hidden=!!(count||topics);
  }
  renderFocus() {
    const focus=this.refs['attribute-focus'];focus.hidden=!this.attributeSelection;
    if(!this.attributeSelection){focus.innerHTML='';return;}
    focus.innerHTML=`<div class="focus-caption"><span class="eyebrow">FOLLOW ONE ATTRIBUTE</span><strong>${escapeHtml(this.selectionName())}</strong><p class="focus-summary">${this.traceQueue.length} animated moments in ${this.attributeUsages.length} journey steps. Only selected fields move; local operations stay with their participant.</p></div><div class="focus-controls"><button class="button primary" data-trace-play ${this.traceQueue.length?'':'disabled'}>${uiIcon('play')}Replay path</button><button class="button quiet" data-clear-trace>Full journey</button></div>`;
  }
  traceHtml(id) {
    const topic=ATTRIBUTE_TOPICS[id],a=this.definition(id),steps=this.traceQueue,current=this.currentStep;
    const summary=this.isAdvancedFlow&&id==='clientIdentity'?'Follow this application’s configured client identifier through the selected grant. It identifies a registration and is distinct from client authentication.':topic?.summary||a.meaning;
    const available=this.labModel?[]:Object.entries(modeMetadata).filter(([mode,m])=>this.canProbeJourney(mode)&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson&&!m.directFido&&!m.enrollment)&&this.attributeUsage(this.journeyFor(mode),id).length);
    let html=`<div class="trace-heading"><div class="inspector-kicker">CREATION · TRANSFER · LOCAL CHECKS</div><h2>${escapeHtml(this.selectionName(id))}</h2><p>${escapeHtml(this.isDirectFido?String(summary).replace(/\bB\b/g,'the web application'):this.isSingleRealm?String(summary).replace(/\bB\b/g,'Realm A'):this.upstream==='external'?String(summary).replace(/\bB\b/g,'the upstream provider'):summary)}</p></div>`;
    if(!steps.length){
      const contexts=getAttributeContext(this.steps,id,this.authenticator);
      html+=`<div class="context-note">No replayable operation for this attribute in the current journey.${contexts.length?' It appears only as related context here.':''}</div><h3 class="section-title">Available journeys</h3><div class="attribute-list">${available.map(([mode,m])=>`<button class="button" data-trace-mode="${mode}">${escapeHtml(m.title)}</button>`).join('')||'<p>This is configured context; it is not transmitted by the simulated exchanges.</p>'}</div>`;
      const ids=getAttributeIds(id),labChoices=LAB_SCENARIOS.filter(model=>model.id!==this.labScenarioId&&(id==='topic-'+model.id||ids.some(field=>model.ids.includes(field))));
      if(labChoices.length)html+='<h3 class="section-title">Available lab scenarios</h3><div class="attribute-list">'+labChoices.map(model=>`<button class="button" data-trace-lab="${model.id}">Explore ${escapeHtml(model.title)}</button>`).join('')+'</div>';
      if(FIDO_ATTRIBUTES[id]&&!this.providerOwnsAuthentication&&this.authenticator!=='yubikey'&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson))html+='<div class="context-note">These CTAP2 operations belong to the external FIDO2 security-key path. Windows Hello uses its platform interface.</div><button class="button primary" data-trace-device="yubikey">Explore with YubiKey</button>';
      if(id==='saml'||SAML_ATTRIBUTES[id])html+='<div class="context-note">SAML Web SSO carries XML requests and assertions. Switch to the matching protocol to follow this field.</div><button class="button primary" data-trace-protocol="saml">Explore SAML</button>';
      if(id==='jwe'||JWE_ATTRIBUTES[id])html+='<div class="context-note">JWE protects an OIDC ID token when the issuer and recipient support and configure encryption.</div><button class="button primary" data-trace-protocol="jwe">Enable JWE and trace</button>';
      const grantTopics={'client-credentials':'serviceAccounts',device:'deviceFlow',ciba:'ciba','token-exchange':'tokenExchange'};
      const grants=Object.entries(advancedFlowModels).filter(([flow,model])=>flow!==this.oidcFlow&&(id===grantTopics[flow]||model.ids.includes(id)));
      if(grants.length)html+='<h3 class="section-title">Other grant walkthroughs</h3><div class="attribute-list">'+grants.map(([flow,model])=>`<button class="button" data-trace-grant="${flow}">Explore ${escapeHtml(model.title)}</button>`).join('')+'</div>';
      const codeJourney=this.isAdvancedFlow?this.findAuthorizationJourney(id):null;
      if(codeJourney)html+=`<button class="button primary" data-trace-grant="authorization-code" data-grant-mode="${codeJourney.mode}" data-grant-authenticator="${codeJourney.authenticator}" data-grant-upstream="${codeJourney.upstream}" data-grant-architecture="${codeJourney.architecture}">Explore Authorization Code · ${escapeHtml(modeMetadata[codeJourney.mode].title)}${codeJourney.authenticator==='yubikey'?' · YubiKey':''}</button>`;
      if(!this.isDirectFido&&this.applicationProtocol==='saml'&&(['pkce','clientIdentity','clientIdApp','redirectApp','stateApp','nonceApp','codeA','idTokenA','accessTokenA','refreshToken','codeVerifier','codeChallenge','codeChallengeMethod','clientSecretApp','authorizationHeaderApp'].includes(id))||!this.isDirectFido&&this.brokerProtocol==='saml'&&['clientIdBroker','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','clientSecret','authorizationHeader'].includes(id))html+='<button class="button primary" data-trace-protocol="oidc">Explore the OIDC hop</button>';
      const setups=Object.entries(UPSTREAMS).filter(([key])=>!this.isAdvancedFlow&&key!==this.upstream).map(([key,value])=>{
        const modes=[this.mode,...Object.keys(JOURNEYS)].filter(mode=>JOURNEYS[mode]);
        const mode=modes.find(mode=>this.canProbeJourney(mode,key)&&this.attributeUsage(this.journeyFor(mode,{upstream:key}),id).length);
        return mode?`<button class="button" data-trace-upstream="${key}" data-setup-mode="${mode}">Explore ${escapeHtml(key==='keycloak'?'two Keycloak realms':value.label||value.title)}</button>`:'';
      }).filter(Boolean);
      if(setups.length)html+='<h3 class="section-title">Other identity setups</h3><div class="attribute-list">'+setups.join('')+'</div>';
    }else{
      if(id==='clientIdentity'||id==='clientIdApp')html+=this.labModel?'<div class="context-note">Configured during client registration and reused across requests. This public identifier selects the application; confidential-client authentication is a separate check. Follow the selected scenario to see whether it travels in an authorization form, HTTP Basic header, or signed client assertion. An ID token’s aud identifies its client; an access token’s aud identifies its intended resource recipient.</div>':this.isAdvancedFlow?'<div class="context-note">Configured during client registration; this public identifier selects the application. A confidential client authenticates separately using its protected credential. In this Basic example its client ID is encoded in Authorization; a public device client instead sends client_id in the form. Device/CIBA ID-token aud identifies the client. A service-account or exchanged access-token aud identifies the configured API recipient, not necessarily this client.</div>':'<div class="context-note">Configured during client registration and reused across logins. This public identifier selects the application; it is not a secret. In the authorization request it is client_id. During redemption the native app sends it in the body; this web backend identifies itself through Authorization: Basic. The application later compares the ID token’s aud with this configured identifier.</div>';
      if(id==='pkce'||['codeVerifier','codeChallenge','codeChallengeMethod'].includes(id))html+='<div class="trace-formula"><pre><code>code_challenge =\nBASE64URL(SHA256(ASCII(code_verifier)))\n\nRealm A recomputes the same value\nand compares it with the saved challenge.</code></pre></div>';
      html+=`<button class="button primary" data-trace-play>${uiIcon('play')}Replay complete attribute path</button><div class="trace-heading"><h3 class="section-title">CURRENT MOMENT · ${this.traceIndex+1} / ${steps.length}</h3><h3>${escapeHtml(current?.title)}</h3><p>${escapeHtml(current?.detail)}</p><p class="trace-step-route">${escapeHtml(this.actor(current.from).name)} → ${escapeHtml(this.actor(current.to).name)} · journey step ${current.sourceIndex+1}</p></div><h3 class="section-title">Where and how it is used</h3><div class="trace-step-list">${steps.map((s,i)=>`<button data-trace-step="${i}" class="${i===this.traceIndex?'is-active':''}" aria-current="${i===this.traceIndex?'step':'false'}"><span class="trace-step-number">${i+1}</span><span class="trace-step-title">${escapeHtml(s.title)}</span><span class="trace-step-route">${escapeHtml(this.actor(s.from).name)} → ${escapeHtml(this.actor(s.to).name)} · journey ${s.sourceIndex+1}</span><span class="trace-action" data-action="${s.traceKind}">${escapeHtml(TRACE_ACTION_LABELS[s.traceKind])}</span></button>`).join('')}</div>`;
    }
    html+='<button class="back-button" data-clear-trace>'+uiIcon('previous')+'Return to full journey</button>';
    if(topic)html+=`<h3 class="section-title">Fields in this topic</h3><div class="attribute-list">${topic.attributeIds.map(field=>this.attributeButton(field)).join('')}</div>`;
    else html+=`<details class="trace-definition" open><summary>Meaning, origin & primary source</summary>${this.attributeHtml(id,true)}</details>`;
    return html;
  }
  actorHtml(actor) {
    if(!actor)return '';
    return `<div class="inspector-kicker">${escapeHtml(actor.role)}</div><div class="inspector-actor-art">${this.illustration(actor.id)}</div><h2 class="inspector-title">${escapeHtml(actor.name)}</h2><p class="inspector-summary">${escapeHtml(actor.plainRole)}</p>${this.actorContextHtml(actor.id)}${this.actorAttributesHtml(actor)}${(actor.notes||[]).map(note=>`<div class="context-note">${escapeHtml(note)}</div>`).join('')}${['hello','yubikey'].includes(actor.id)?`<button class="button primary" data-use-authenticator="${actor.id}">Use this passkey device</button>`:actor.id==='totp'?'<button class="button primary" data-use-totp>Explore Password + TOTP</button>':''}`;
  }
  actorAttributesHtml(actor) {
    return Object.entries(ATTR_KIND).map(([kind,label])=>{
      const fields=actor.attributes.filter(item=>item.kind===kind&&ATTRIBUTES[item.id]);
      return fields.length?`<section class="attribute-group"><h3 class="section-title"><span class="kind-badge ${kind}">${label}</span></h3><div class="attribute-list">${fields.map(item=>this.attributeButton(item.id)).join('')}</div></section>`:'';
    }).join('');
  }
  attributeHtml(id,pinned=false) {
    const a=this.definition(id);if(!ATTRIBUTES[id])return '';
    return `<div class="definition"><div class="inspector-kicker">${escapeHtml(a.standard)}</div><h2 class="${pinned?'inspector-title':'popup-title'}"><code>${escapeHtml(a.name)}</code></h2><p class="inspector-summary">${escapeHtml(a.meaning||a.description)}</p><dl><dt>Where it comes from</dt><dd>${escapeHtml(a.origin||a.generator)}</dd><dt>Why it exists</dt><dd>${escapeHtml(a.purpose)}</dd><dt>Example</dt><dd><code>${escapeHtml(a.example)}</code></dd></dl><a class="source-link" href="${escapeHtml(a.source)}" target="_blank" rel="noopener noreferrer">Read the primary specification ${uiIcon('arrow')}</a></div>`;
  }
  showActorPopup(id,anchor) {
    if(this.restoringPopupFocus)return;
    clearTimeout(this.closeTimer);const actor=this.actor(id);if(!ACTORS[id])return;
    const popup=this.refs['actor-popup'],active=document.activeElement;
    const nestedFocus=!this.refs['attribute-popup'].hidden&&popup.contains(this.attributeAnchor)&&this.refs['attribute-popup'].contains(active);
    if(!popup.hidden&&(this.actorAnchor===anchor||popup.contains(active)||nestedFocus)){this.placePopup(popup,this.actorAnchor,370);return;}
    if(popup.contains(this.attributeAnchor)){clearTimeout(this.attributeTimer);this.closePopup('attribute');}
    this.setPopupAnchor('actor',anchor);
    this.refs['actor-popup'].innerHTML=`<div class="popup-heading"><div><h2 class="popup-title">${escapeHtml(actor.name)}</h2><p class="popup-subtitle">${escapeHtml(actor.plainRole)}</p></div><button class="icon-button popup-close" data-close aria-label="Close participant attributes">${uiIcon('close')}</button></div><p class="popup-keyboard-status" role="status">Keyboard focus is inside this panel · Tab explores · Escape returns</p>${this.actorContextHtml(actor.id)}${this.actorAttributesHtml(actor)}<p class="popup-hint">Hover or focus a field for help. F2 moves focus into its explanation; Tab reaches the source link, Escape returns. Click a field to study its path.</p>`;
    this.refs['actor-popup'].hidden=false;this.placePopup(this.refs['actor-popup'],anchor,370);
  }
  showAttributePopup(id,anchor) {
    if(this.restoringPopupFocus)return;
    clearTimeout(this.attributeTimer);if(this.refs['actor-popup'].contains(anchor))clearTimeout(this.closeTimer);
    if(!ATTRIBUTES[id])return;
    const popup=this.refs['attribute-popup'];
    if(!popup.hidden&&(this.attributeAnchor===anchor||popup.contains(document.activeElement))){this.placePopup(popup,this.attributeAnchor,340);return;}
    this.setPopupAnchor('attribute',anchor);
    this.refs['attribute-popup'].setAttribute('aria-label',this.definition(id).name+' explanation');
    this.refs['attribute-popup'].innerHTML=`<div class="popup-heading"><span>Attribute explanation</span><button class="icon-button popup-close" data-close aria-label="Close attribute explanation">${uiIcon('close')}</button></div><p class="popup-keyboard-status" role="status">Keyboard focus is inside this panel · Tab explores · Escape returns</p>`+this.attributeHtml(id);
    this.refs['attribute-popup'].hidden=false;this.placePopup(this.refs['attribute-popup'],anchor,340);
  }
  placePopup(popup,anchor,preferredWidth) {
    const rect=anchor.getBoundingClientRect(),margin=14,width=Math.min(preferredWidth,window.innerWidth-margin*2);
    popup.style.width=width+'px';
    const height=Math.min(popup.offsetHeight||360,window.innerHeight-margin*2);
    let left=rect.right+12;
    if(left+width>window.innerWidth-margin)left=rect.left-width-12;
    left=Math.max(margin,Math.min(left,window.innerWidth-width-margin));
    const top=Math.max(margin,Math.min(rect.top-8,window.innerHeight-height-margin));
    popup.style.left=left+'px';popup.style.top=top+'px';
  }
  resizeHelpPanels() {
    clearTimeout(this.closeTimer);clearTimeout(this.attributeTimer);
    const active=document.activeElement,actor=this.refs['actor-popup'],attribute=this.refs['attribute-popup'];
    const attributeOwned=!attribute.hidden&&this.popupOwnsFocus('attribute',active);
    const nested=!attribute.hidden&&(actor.contains(this.attributeAnchor)||this.attributeFocusTarget?.region==='actor-popup');
    const actorOwned=!actor.hidden&&(this.popupOwnsFocus('actor',active)||nested&&attributeOwned);
    if(nested&&attributeOwned&&(actor.hidden||!isVisibleFocusTarget(this,this.actorAnchor))){this.dismissPopup('actor');return;}
    if(!actor.hidden){
      if(actorOwned){
        if(!isVisibleFocusTarget(this,this.actorAnchor)){this.dismissPopup('actor');return;}
        this.placePopup(actor,this.actorAnchor,370);
      }else this.closePopup('actor');
    }
    if(!attribute.hidden){
      if(attributeOwned){
        if(!isVisibleFocusTarget(this,this.attributeAnchor)){this.dismissPopup('attribute');return;}
        this.placePopup(attribute,this.attributeAnchor,340);
      }else this.closePopup('attribute');
    }
  }
  setPopupAnchor(kind,anchor){
    this[kind+'Anchor']?.setAttribute('aria-expanded','false');this[kind+'Anchor']=anchor;
    this[kind+'FocusTarget']=captureFocusTarget(this,anchor);
    anchor.setAttribute('aria-haspopup','dialog');anchor.setAttribute('aria-controls',kind+'-popup');anchor.setAttribute('aria-expanded','true');anchor.setAttribute('aria-keyshortcuts','F2');
  }
  popupOwnsFocus(kind,active=document.activeElement){
    if(!active)return false;
    if(this.refs[kind+'-popup'].contains(active)||this[kind+'Anchor']?.contains(active))return true;
    return kind==='actor'&&!this.refs['attribute-popup'].hidden&&this.refs['actor-popup'].contains(this.attributeAnchor)&&this.refs['attribute-popup'].contains(active);
  }
  closePopup(kind){this.refs[kind+'-popup'].hidden=true;this[kind+'Anchor']?.setAttribute('aria-expanded','false');}
  dismissPopup(kind){
    const target=this[kind+'FocusTarget'];
    if(kind==='actor')this.hidePopups();else{clearTimeout(this.attributeTimer);this.closePopup('attribute');}
    this.restoreTargetFocus(target);
  }
  restoreTargetFocus(target,options={}){const node=resolveFocusTarget(this,target,options);if(node&&node!==document.activeElement){this.restoringPopupFocus=true;try{node.focus({preventScroll:true});}finally{this.restoringPopupFocus=false;}}}
  deferCloseActor(next){clearTimeout(this.closeTimer);if(this.popupOwnsFocus('actor',next))return;this.closeTimer=setTimeout(()=>{if(!this.popupOwnsFocus('actor'))this.closePopup('actor');},250);}
  deferCloseAttribute(next){clearTimeout(this.attributeTimer);if(this.popupOwnsFocus('attribute',next))return;this.attributeTimer=setTimeout(()=>{if(!this.popupOwnsFocus('attribute'))this.closePopup('attribute');},180);}
  hidePopups(){clearTimeout(this.closeTimer);clearTimeout(this.attributeTimer);if(this.refs?.['actor-popup'])this.closePopup('actor');if(this.refs?.['attribute-popup'])this.closePopup('attribute');}
  filterGlossary(query){const q=query.trim().toLowerCase();this.refs.inspector.querySelectorAll('[data-search]').forEach(button=>button.hidden=!button.dataset.search.includes(q));}
  showToast(message){this.refs.toast.textContent=message;this.refs.toast.hidden=false;clearTimeout(this.toastTimer);this.toastTimer=setTimeout(()=>{this.refs.toast.hidden=true;},5000);}
}

customElements.define('auth-flow-studio',AuthFlowStudio);
