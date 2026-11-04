import { ACTORS, ATTRIBUTES, FLOWS, SOURCES } from './protocol-data.js';
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
import { FlowPlayer, authoredMessageTiming, resolveActor, pairKey, connectionSteps } from './player.js';
import { POSITIONS, getPositions, GRAPH_WIDTH, GRAPH_HEIGHT, connectionPath, channelCategory, validateLayoutRoutes } from './layout.js';
import { CARD_BOUNDS } from './layout.js';
import { placeStepOverlay } from './step-overlay-layout.js';
import { LAB_ATTRIBUTES, LAB_SOURCES, LAB_SCENARIOS, LAB_MODELS, LAB_TOPICS, labAttributeScenarios } from './lab-catalog.js';
import { ScenarioPicker, filterScenarioOptions } from './scenario-picker.js';
import { createScenarioSearchMetadata } from './scenario-search-metadata.js';
import { WINDOWS_SECURITY_COMPARISONS, windowsSecurityRelatedLessons } from './windows-security-comparisons.js';
import { PAM_API_PHASES } from './pam-stack-evaluator.js';
import { captureFocusTarget, resolveFocusTarget, isVisibleFocusTarget } from './focus-target.js';
import { LEARNING_PRESETS, PROVIDER_PROFILES, getLearningPreset, getProviderProfile, getPresetConfiguration, applyProviderProfile } from './learning-presets.js';
import { RuntimeEnvironment, RUNTIME_ENVIRONMENT_FIELDS, RUNTIME_PROVIDER_FIELDS } from './runtime-environment.js';
import { STUDIO_WORKSPACES, STUDIO_FAMILIES, workspaceOf, studioRoute, studioVariantId, parseStudioRoute, visibleActorId, scenarioActorIds, scenarioPositions, studioWorkspaceOptions } from './workspaces.js';
import { scenarioContextRows, projectScenarioContext, scenarioBindingValue } from './scenario-context.js';
import { buildProtocolInstances } from './protocol-state.js';
import { HeldObjectView } from './held-object-view.js';
import { StudyController } from './study-controller.js';
import { FOOTER_NOTE_BINDINGS } from './localization-notes.js';
import { prepareSearchQuery, createSearchFields, mergeSearchFields, rankSearchFields, localizedSearchIndex } from './locale-search.js';

Object.assign(ATTRIBUTES,VARIANT_ATTRIBUTES,FIDO_ATTRIBUTES);
Object.assign(ATTRIBUTES,SAML_ATTRIBUTES,JWE_ATTRIBUTES);
Object.assign(ATTRIBUTES,SERVICE_ATTRIBUTES,DEVICE_ATTRIBUTES,CIBA_ATTRIBUTES,EXCHANGE_ATTRIBUTES);
const studioCoreSearchAttributeIds=Object.keys(ATTRIBUTES);
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
const studioFieldTopicText=new Map();
for(const topic of Object.values(ATTRIBUTE_TOPICS))for(const id of topic.attributeIds)studioFieldTopicText.set(id,(studioFieldTopicText.get(id)||'')+' '+topic.name);

const advancedFlowModels={
  'client-credentials':{title:'Service account · client_credentials',summary:'The service authenticates as itself and receives a token with its configured service-account permissions.',steps:getServiceAccountSteps,actors:getServiceAccountActorOverrides,definitions:getServiceAccountAttributeOverrides,examples:getServiceAccountExampleOverrides,ids:SERVICE_TOPIC_IDS,hasPerson:false},
  device:{title:'Device Authorization Flow',summary:'A separate browser authenticates the person and approves the device while the requesting application polls.',steps:getDeviceSteps,actors:getDeviceActorOverrides,definitions:getDeviceAttributeOverrides,examples:getDeviceExampleOverrides,ids:DEVICE_TOPIC_IDS,hasPerson:true},
  ciba:{title:'CIBA · Poll delivery',summary:'The consumption client makes a backchannel request. A controlled authentication service verifies the person on a separate device.',steps:getCibaSteps,actors:getCibaActorOverrides,definitions:getCibaAttributeOverrides,examples:getCibaExampleOverrides,ids:CIBA_TOPIC_IDS,hasPerson:true},
  'token-exchange':{title:'Token exchange · Standard V2',summary:'A backend exchanges an existing Realm A access token for a configured API target under an explicit downscope policy.',steps:getTokenExchangeSteps,actors:getTokenExchangeActorOverrides,definitions:getTokenExchangeAttributeOverrides,examples:getTokenExchangeExampleOverrides,ids:EXCHANGE_TOPIC_IDS,hasPerson:false},
};
const grantTopicFlows={serviceAccounts:'client-credentials',deviceFlow:'device',ciba:'ciba',tokenExchange:'token-exchange'};

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Protocol fixtures use JSON-shaped objects and arrays as well as scalars.
// Format before HTML escaping; textContent consumers use the same formatter.
const formatProtocolValue = (value,compact=false) => value===undefined?'':value!==null&&typeof value!=='object'?String(value):JSON.stringify(value,null,compact?0:2);
const iconPaths = {
  play:'M8 5v14l11-7z', pause:'M8 5v14M16 5v14', reset:'M3 10a9 9 0 1 1 2 8M3 4v6h6',
  search:'M21 21l-5-5M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0', previous:'m14 6-6 6 6 6', next:'m10 6 6 6-6 6', close:'m6 6 12 12M18 6 6 18',
  sun:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1',
  book:'M4 4h6a3 3 0 0 1 2 3 3 3 0 0 1 3-3h5v16h-5a3 3 0 0 0-3 2 3 3 0 0 0-3-2H4zM12 7v15',
  arrow:'M5 12h14m-5-5 5 5-5 5', check:'m5 12 4 4 10-10', link:'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2',
  info:'M12 11v6M12 7h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0', shield:'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z'
};
const uiIcon = (name, filled=false) => `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="${filled?'currentColor':'none'}" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${iconPaths[name]||iconPaths.info}"/></svg>`;
const channelLabels = {browser:'Browser navigation',server:'Server exchange',network:'Protocol exchange',ipc:'Local IPC',passkey:'Passkey proof',human:'User interaction',local:'Local processing',unknown:'Unclassified channel'};
const modeMetadata = {...JOURNEYS,...FIDO_JOURNEYS};
const ATTR_KIND = {static:'Configured / stored',generated:'Creates / computes',received:'Receives / verifies'};

export class AuthFlowStudio extends StudyController {
  ui(key,source,params={}) {return this.localizer.html(key,source,params);}
  uiText(key,source,params={}) {return this.localizer.text(key,source,params);}
  localeContext(extra={}) {return {scenarioId:this.baseLabModel?.id||this.labScenarioId||'core',variantId:this.lessonVariant||'default',subfixtureId:this.lessonSubfixture||null,...extra};}
  prose(ownerId,fieldPath,source,context={}) {return '<span class="locale-prose">'+this.localizer.explainHtml(ownerId,fieldPath,source,this.localeContext(context))+'</span>';}
  proseText(ownerId,fieldPath,source,context={}) {return this.localizer.explain(ownerId,fieldPath,source,this.localeContext(context));}
  ltr(value) {return '<bdi dir="ltr" translate="no">'+escapeHtml(value)+'</bdi>';}
  rawValueAttrs(value) {return 'dir="ltr" translate="no" data-copy-raw-json="'+escapeHtml(JSON.stringify(String(value??'')))+'"';}
  rich(key,template,parameters) {return this.localizer.rich(key,template,parameters);}
  coverageCategories() {
    const groups=new Map(),options=studioWorkspaceOptions(LAB_MODELS);
    for(const model of LAB_SCENARIOS){
      let category,key;
      if(typeof model.category==='string'){
        key='category:'+model.category;
        category={ownerId:'lesson:'+model.id,fieldPath:'category',source:model.category,context:this.localeContext({scenarioId:model.id,variantId:'default',subfixtureId:null})};
      }else{
        const workspace=workspaceOf(model),option=options.find(item=>item.workspace===workspace&&item.family===model.family)||options.find(item=>item.id==='workspace-'+workspace);
        if(!option)throw new RangeError('Missing coverage navigation metadata for '+model.id);
        key=option.id;category={ownerId:'workspace-option:'+option.id,fieldPath:'title',source:option.title};
      }
      const group=groups.get(key);
      if(group)group.count++;else groups.set(key,{category,count:1});
    }
    return [...groups.values()].map(({category,count})=>'<li>'+this.ui('ui.coverage.category-count',category.source+' · '+count+' scenarios',{category,count})+'</li>').join('');
  }
  renderPickerHints() {
    const workspace=STUDIO_WORKSPACES.find(item=>item.id===this.workspace)||STUDIO_WORKSPACES[0];
    const id=workspace.defaultId,title=LAB_MODELS[id]?.title||getLearningPreset(id)?.title||workspace.title;
    this.refs['lab-scenario-hint'].innerHTML=this.ui('ui.picker.global-hint','Global search · Start with '+title,{title:{ownerId:'lesson:'+id,fieldPath:'title',source:title}});
  }
  stepReference(row,field,source=row[field]) {
    if(field==='title'&&row.traceActions&&!row.artifactId)return {key:'ui.trace.title.'+row.traceKind,source,params:{names:(row.fields||[]).map(id=>ATTRIBUTES[id]?.name||id).join(', ')}};
    const artifactTitle=field==='title'&&row.artifactId&&row.traceKind;
    return {ownerId:artifactTitle?'artifact:'+row.artifactId:'step:'+(row.sourceStepId||row.id),fieldPath:artifactTitle?'trace.title':field,source,context:this.localeContext(artifactTitle?{sourceStepId:row.sourceStepId,traceKind:row.traceKind,from:row.from,to:row.to,messageId:row.messageId,holdingId:row.holdingId,representationId:row.representationId}:{})};
  }
  stepProse(row,field,source,asHtml=true) {
    if(source===undefined||source===null||source==='')return '';
    if(row.traceActions&&!row.artifactId&&(field==='summary'||field==='detail')){
      const seen=new Set(),parts=[];
      for(const action of row.traceActions){
        if(!action.detail||seen.has(action.detail))continue;seen.add(action.detail);
        const context={attributeId:action.attributeId,actorId:action.actorId,operationKind:action.kind,messageId:action.messageId??null},owner='step:'+(row.sourceStepId||row.id);
        parts.push(asHtml?this.prose(owner,'attributeOperations.detail',action.detail,context):this.proseText(owner,'attributeOperations.detail',action.detail,context));
      }
      return parts.join(' ');
    }
    const reference=this.stepReference(row,field,source);
    if(reference.key)return asHtml?this.ui(reference.key,source,reference.params):this.uiText(reference.key,source,reference.params);
    return asHtml?this.prose(reference.ownerId,reference.fieldPath,source,reference.context):this.proseText(reference.ownerId,reference.fieldPath,source,reference.context);
  }
  traceAction(kind,asHtml=true) {
    const source=TRACE_ACTION_LABELS[kind];if(!source)return asHtml?this.ltr(kind):String(kind??'');
    return asHtml?this.ui('ui.trace.action.'+kind,source):this.uiText('ui.trace.action.'+kind,source);
  }
  selectionProse(id=this.attributeSelection,asHtml=true) {
    const topic=ATTRIBUTE_TOPICS[id];
    if(topic)return asHtml?this.prose('topic:'+id,'name',topic.name):this.proseText('topic:'+id,'name',topic.name);
    const name=this.definition(id).name||id;return asHtml?this.ltr(name):name;
  }
  studyQueueLabel(queue,asHtml=true) {
    const render=(key,params={})=>asHtml?this.ui(key,queue.label,params):this.uiText(key,queue.label,params);
    const object=this.objectTraceSelection;
    const topic=this.attributeSelection?ATTRIBUTE_TOPICS[this.attributeSelection]:null,selected=this.attributeSelection?this.selectionName():'';
    const params=topic?{selection:{ownerId:'topic:'+this.attributeSelection,fieldPath:'name',source:selected}}:{selection:selected};
    const scope=topic?'topic':'field';
    if(['step','attribute-step','trace-step'].includes(queue.kind)){
      if(object)return render('ui.queue.selected.object',{object});
      if(this.attributeSelection)return render('ui.queue.selected.'+scope,params);
      return render('ui.queue.selected');
    }
    if(queue.kind==='connection')return render('ui.queue.connection');
    if(queue.kind==='trace-connection')return render('ui.queue.trace-connection');
    if(queue.kind==='object')return render('ui.queue.object',{object});
    if(queue.kind==='attribute')return render('ui.queue.attribute.'+scope,params);
    return render('ui.queue.journey');
  }
  footerBaselineHtml() {
    return this.rich('ui.footer.baseline', 'Expansion journeys declare their own pinned source revision, implementation assumptions and completion boundary before Play. The Web documentation baseline is {baseline} · checked {retrieved}; {windows}, Network, {kerberos} and {pake} use their separate profiles. {reference} and {experimental} do not certify product support. This offline symbolic model is not a live compatibility test.', {
      baseline:{kind:'source',value:'Keycloak 26.8.0',node:{tag:'a',attributes:{href:'https://www.keycloak.org/2026/10/keycloak-2680-released',target:'_blank',rel:'noopener noreferrer'}}},
      retrieved:{kind:'exact',value:'8 October 2026'},windows:{kind:'protected',value:'Windows'},kerberos:{kind:'protected',value:'MIT Kerberos'},pake:{kind:'protected',value:'PAKE'},reference:{kind:'exact',value:'Reference'},experimental:{kind:'exact',value:'Experimental'},
    });
  }
  connectedCallback() {
    if(this.initialized) return;
    const localeReady=this.initializeLocale();
    if(localeReady){
      if(!this.initializingLocale)this.initializingLocale=localeReady.then(()=>{this.initializingLocale=null;if(this.isConnected)this.connectedCallback();});
      return this.initializingLocale;
    }
    this.initialized=true;
    Object.assign(this,getPresetConfiguration('basic-keycloak'));this.index=0;
    this.labScenarioId='basic-keycloak';this.catalogQuery='';this.customLayouts={};this.moveParticipants=false;this.dragState=null;
    this.workspace='web';this.family='ad-ds';this.showInternals=false;this.learningDetail='journey';this.lessonVariant='default';this.lessonSubfixture=null;
    this.runtimeEnvironment=new RuntimeEnvironment();this.scenarioMemo=new Map();
    this.attributeSelection=null;this.attributeQuery='';this.traceQueue=[];this.traceIndex=0;this.activeSteps=null;
    this.inspection={type:'step'}; this.visited=new Set(); this.packetIdentity='';
    this.theme='dark'; this.closeTimer=null; this.attributeTimer=null;this.showStepAttributes=true;this.stepOverlayIdentity='';this.lastRunningSpeed=1;
    this.player=new FlowPlayer({getTiming:(step,kind)=>authoredMessageTiming(this.heldView?.compiled().plan,step,kind)});
    this.unsubscribe=this.player.subscribe(event=>this.onPlayer(event));
    this.initializePresentation();this.innerHTML=this.shell();this.cacheRefs();
    this.heldView=new HeldObjectView(this,{mount:false});
    const presetIds=new Set(LEARNING_PRESETS.map(preset=>preset.id));
    const coreSearchOption={id:'core',title:'Core lab · configurable sign-in, SAML, FIDO and grants',category:'Custom configuration',summary:'Explore your own combination using Advanced configuration.',protocol:'OAuth / OIDC / SAML / WebAuthn',ids:studioCoreSearchAttributeIds};
    const pickerOptions=[
      ...LEARNING_PRESETS.map(preset=>({id:preset.id,title:preset.title,category:preset.category,summary:preset.summary,...createScenarioSearchMetadata({...preset,ids:LAB_MODELS[preset.modelId]?.catalogAttributeIds||LAB_MODELS[preset.modelId]?.ids||studioCoreSearchAttributeIds},ATTRIBUTES)})),
      {...coreSearchOption,...createScenarioSearchMetadata(coreSearchOption,ATTRIBUTES)},
      ...LAB_SCENARIOS.filter(model=>!presetIds.has(model.id)).map(model=>({
        id:model.id,title:model.title,category:model.category,summary:model.summary,status:model.status,
        profileLabel:model.profile?[model.profile.name,model.profile.publicationStatus,model.profile.supportStatus].filter(Boolean).join(' · '):'',
        ...createScenarioSearchMetadata(model,ATTRIBUTES),
      })),
    ];
    this.scenarioOptionsById=new Map(pickerOptions.map(option=>[option.id,option]));
    this.scenarioPicker=new ScenarioPicker(this.querySelector('#lab-scenario-picker'),pickerOptions,(id,result)=>this.selectSearchResult(id,result),this,{localization:this.localizer,localizationKind:'scenario'});
    this.workspaceOptions=studioWorkspaceOptions(LAB_MODELS);
    this.workspacePicker=new ScenarioPicker(this.querySelector('#workspace-navigation'),this.workspaceOptions,id=>{const target=this.workspaceOptions.find(option=>option.id===id);if(target)this.selectLabScenario(target.scenarioId);},this,{localization:this.localizer,localizationKind:'workspace',prefix:'workspace',optionPrefix:'workspace-option',optionAttribute:'data-workspace-option',singular:'learning destination',plural:'learning destinations',emptyMessage:'No matching workspace or family. Try a protocol, platform or access task.'});
    this.bindShared();this.prepareStudyConfiguration();this.syncSharedNavigation();this.mountPresentation();this.openRoute();
    if(this.localizer.initialFailure){const {tag,error}=this.localizer.initialFailure;this.localizer.initialFailure=null;this.reportLocaleFailure(tag,error);}
  }
  disconnectedCallback() { if(!this.initialized)return;this.destroyPresentation();this.heldView?.destroy();this.player?.stop(false);this.unsubscribe?.();this.scenarioPicker?.destroy();this.workspacePicker?.destroy();clearTimeout(this.closeTimer);clearTimeout(this.attributeTimer);clearTimeout(this.toastTimer); }
  get learningPreset() {return getLearningPreset(this.labScenarioId);}
  get baseLabModel() {return LAB_MODELS[this.learningPreset?.modelId||this.labScenarioId]||null;}
  get labModel() {
    const base=this.baseLabModel;
    if(!base||(!base.contextualize&&!base.withVariant)||!this.runtimeEnvironment)return base;
    const variant=this.lessonVariant||'default',subfixture=this.lessonSubfixture||null,key=JSON.stringify([base.id,variant,subfixture,this.runtimeEnvironment.revision]);
    if(this.contextModelMemo?.key!==key){
      let selected=variant==='default'||variant===base.defaultVariantId?base:base.withVariant(variant);
      if(subfixture)selected=selected.withSubfixture(subfixture);
      this.contextModelMemo={key,model:selected.contextualize?selected.contextualize(this.runtimeEnvironment.applied,{revision:this.runtimeEnvironment.revision}):selected};
    }
    return this.contextModelMemo.model;
  }
  get providerProfile() {return getProviderProfile(this.providerProfileId)||getProviderProfile('generic');}
  get providerOwnsAuthentication() {return this.upstream==='external'&&!this.labModel&&!this.isDirectFido&&!this.isAdvancedFlow&&(this.providerManaged||this.providerProfileId!=='generic');}
  canProbeJourney(mode,upstream=this.upstream) {return !(upstream==='external'&&(this.providerManaged||this.providerProfileId!=='generic')&&modeMetadata[mode]?.enrollment);}
  get environmentOptions() {return this.environmentOptionsFor(this.labModel);}
  environmentOptionsFor(model) {
    const flow=model||advancedFlowModels[this.oidcFlow]||null,directFido=!model&&!!modeMetadata[this.mode]?.directFido;
    return {profileId:this.providerProfile.id,providerProfile:this.providerProfile,architecture:this.architecture,executionEnvironment:flow?.executionEnvironment||(directFido?'browser':this.architecture==='native'?'native':'server'),clientActor:flow?.clientActor||'app',upstream:this.upstream,directFido};
  }
  get scenarioOwnedActors(){return this.labModel?.workspace?this.labModel.actors(this.protocolConfig()):null;}
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
    const signature=JSON.stringify([this.labScenarioId,this.lessonVariant,this.lessonSubfixture,config,this.oidcFlow,this.tokenProtection,this.runtimeEnvironment.revision]);
    if(this.scenarioMemo.has(signature))return this.scenarioMemo.get(signature);
    const raw=this.baseJourneyFor(mode,overrides);
    const saml=config.applicationProtocol==='saml'||config.upstream!=='single'&&config.brokerProtocol==='saml';
    const sourceActors=Object.fromEntries(Object.entries(ACTORS).map(([id,a])=>[id,{...a,...getActorOverrides(config.architecture,config.upstream)[id],...(saml?getSamlActorOverrides(config)[id]:{})}]));
    const provider=!this.labModel&&config.upstream==='external'&&!FIDO_JOURNEYS[mode]&&!(advancedFlowModels[config.oidcFlow||this.oidcFlow])?applyProviderProfile(raw,sourceActors,config.providerProfileId,config):{steps:raw,actors:{},attributeOverrides:{},exampleOverrides:{}};
    const snapshot={...provider,steps:this.labModel?.workspace?provider.steps:this.runtimeEnvironment.projectSteps(provider.steps,{...this.environmentOptions,architecture:config.architecture,upstream:config.upstream,directFido:!!FIDO_JOURNEYS[mode]})};
    if(this.labModel?.workspace)Object.assign(snapshot,projectScenarioContext(this.labModel,snapshot.steps,this.runtimeEnvironment.applied));
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
  get hasTrace() {return !!(this.attributeSelection||this.objectTraceSelection);}
  get visibleSteps() {return this.hasTrace?this.traceQueue:this.steps;}
  get visibleIndex() {return this.hasTrace?this.traceIndex:this.index;}
  get currentStep() { return this.visibleSteps[Math.max(0,this.visibleIndex)]; }
  get graphChapter(){
    const chapters=this.labModel?.chapters;if(!chapters?.length)return null;
    const step=this.currentStep,sourceId=step?.sourceStepId||step?.id||this.steps[0]?.id;
    return chapters.find(chapter=>chapter.stepIds.includes(sourceId))||chapters[0];
  }
  get graphSteps(){
    const steps=this.steps,trace=this.hasTrace?this.traceQueue:null,chapter=this.graphChapter;
    if(!chapter)return trace?[...steps,...trace]:steps;
    if(this.graphProjection?.steps!==steps||this.graphProjection.trace!==trace||this.graphProjection.chapter!==chapter){
      const ids=new Set(chapter.stepIds),source=steps.filter(step=>ids.has(step.id));
      this.graphProjection={steps,trace,chapter,projected:trace?[...source,...trace.filter(step=>ids.has(step.sourceStepId||step.id))]:source};
    }
    return this.graphProjection.projected;
  }
  get layoutKey() {const base=this.labModel?.id||(this.learningPreset?this.learningPreset.id:'core-'+this.architecture);return this.graphChapter?base+'@chapter-'+this.graphChapter.id:base;}
  get positions() {return this.heldGeometry?.positions||this.basePositions;}
  get basePositions() {
    const layoutSteps=this.graphSteps;
    const positions={...(this.scenarioOwnedActors?scenarioPositions(this.labModel,layoutSteps,this.scenarioOwnedActors,this.showInternals):getPositions(this.architecture)),...(this.customLayouts[this.layoutKey]||{})};
    if(!this.labModel&&!this.learningPreset)return positions;
    const ids=new Set(scenarioActorIds(layoutSteps).map(id=>this.nodeId(id)));
    return Object.fromEntries(Object.entries(positions).filter(([id])=>ids.has(id)));
  }
  actor(id) {
    const key=resolveActor(id,this.authenticator),overrides=this.isDirectFido?getFidoActorOverrides(this.mode,this.authenticator):getActorOverrides(this.architecture,this.upstream),a={id:key,name:key,role:'Participant',plainRole:'',attributes:[],notes:[],...ACTORS[key],...overrides[key],...(this.isUsingSaml?getSamlActorOverrides(this.protocolConfig())[key]:{}),...(this.isAdvancedFlow?this.advancedFlow.actors(this.protocolConfig())[key]:{}),...this.scenarioSnapshot().actors[key]};
    if(this.scenarioOwnedActors&&!this.showInternals)for(const child of Object.values(this.scenarioOwnedActors))if(child.parentId===key)a.attributes=[...a.attributes,...child.attributes.filter(item=>!a.attributes.some(existing=>existing.id===item.id)).map(item=>({...item,ownerId:child.id,ownerName:child.name}))];
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
    const signature=JSON.stringify([this.mode,this.authenticator,this.architecture,this.upstream,this.applicationProtocol,this.brokerProtocol,this.samlBinding,this.samlInitiation,this.tokenProtection,this.assertionProtection,this.oidcFlow,this.labScenarioId,this.lessonVariant,this.lessonSubfixture,this.providerProfileId,this.providerManaged,this.runtimeEnvironment.revision]);
    if(this.definitionMemo?.signature!==signature){
      const overrides={...(this.isDirectFido?getFidoAttributeOverrides(this.mode):getAttributeOverrides(this.architecture,this.upstream)),...(this.isUsingSaml?getSamlAttributeOverrides(this.protocolConfig()):{}),...(this.isAdvancedFlow?this.advancedFlow.definitions(this.protocolConfig()):{}),...(!this.isDirectFido?getJweAttributeOverrides({protection:this.tokenProtection,steps:this.steps}):{}),...this.scenarioSnapshot().attributeOverrides};
      this.definitionMemo={signature,overrides,values:new Map()};
    }
    if(this.definitionMemo.values.has(id))return this.definitionMemo.values.get(id);
    const definition={...ATTRIBUTES[id],...this.definitionMemo.overrides[id]};
    if(modeMetadata[this.mode]?.passkey&&id==='clientDataJSON'&&modeMetadata[this.mode]?.enrollment)definition.example=String(definition.example).replaceAll('webauthn.get','webauthn.create');
    const projected=this.runtimeEnvironment.projectDefinition(id,definition,this.environmentOptions);
    const binding=this.labModel?.runtimeBindings?.find(item=>item.attributeId===id&&this.runtimeEnvironment.applied[item.field]);
    const result=binding&&projected.example===binding.example?{...projected,example:scenarioBindingValue(binding,this.runtimeEnvironment.applied)}:projected;this.definitionMemo.values.set(id,result);
    return result;
  }
  nodeId(id) { const logical=resolveActor(id,this.authenticator);return this.scenarioOwnedActors?visibleActorId(logical,this.scenarioOwnedActors,this.showInternals):logical; }
  illustration(id) {const actor=this.labModel?.actors(this.protocolConfig())[id],kindArt={person:'user',human:'user',user:'user',client:'app',application:'app',workstation:'app',computer:'app',idp:'realmA',kdc:'realmA',as:'realmA',tgs:'realmA',server:'webapp',service:'webapp',host:'webapp',ca:'realmB',authenticator:'smartcard',card:'smartcard',key:'yubikey',agent:'hello',browser:'browser',pam:'webapp',sssd:'webapp'};return actorIllustration(actor?.art||actor?.artwork||kindArt[actor?.kind]|| (id==='realmB'&&(this.upstream==='external'||this.oidcFlow==='ciba')?'external':id==='app'&&this.architecture==='web'?'webapp':id));}
  shell() {
    return `<main class="studio" id="studio" data-theme="${this.theme}" data-presentation-mode="${this.presentationMode}">
      <header class="app-header">
        <div class="brand"><span class="brand-mark">${uiIcon('shield')}</span><div><div class="brand-title">${this.ui("ui.app.shell.text.0001","Auth Flow Studio")}</div><div class="brand-subtitle">${this.ui("ui.app.shell.text.0002","Trust, made visible")}</div></div></div>
        <div class="header-actions">${this.languageSelectorHtml()}<div class="presentation-switch" id="presentation-switch" role="group" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0003","View"))}"><span>${this.ui("ui.app.shell.text.0004","View")}</span><button type="button" class="button quiet" data-presentation-choice="compact" aria-pressed="${this.presentationMode==='compact'}">${this.ui("ui.app.shell.text.0005","Compact")}</button><button type="button" class="button quiet" data-presentation-choice="full" aria-pressed="${this.presentationMode==='full'}">${this.ui("ui.app.shell.text.0006","Full")}</button></div><span class="lab-label">${this.ui("ui.app.shell.text.0007","INTERACTIVE LEARNING LAB")}</span><button class="button quiet" id="index-open" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0008","Attribute index"))}" title="${escapeHtml(this.uiText("ui.app.shell.attribute.0009","Attribute index"))}">${uiIcon('book')}<span>${this.ui("ui.app.shell.text.0010","Attribute index")}</span></button><button class="button quiet" id="glossary-open" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0011","Field guide"))}" title="${escapeHtml(this.uiText("ui.app.shell.attribute.0012","Field guide"))}">${uiIcon('info')}<span>${this.ui("ui.app.shell.text.0013","Field guide")}</span></button><button class="icon-button" id="theme-toggle" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0014","Switch color theme"))}">${uiIcon('sun')}</button></div>
      </header>
      <div class="learning-navigation"><nav class="workspace-navigation select-field scenario-picker" id="workspace-navigation" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0015","Learning workspaces"))}"><label for="workspace-search">${this.ui("ui.app.shell.text.0016","Workspace or family")}</label><div class="scenario-picker-control"><span class="scenario-picker-icon" aria-hidden="true">${uiIcon('search')}</span><input id="workspace-search" type="search" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="workspace-results" aria-describedby="workspace-hint" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(this.uiText("ui.app.shell.attribute.0017","Search workspaces and families"))}"><button type="button" id="workspace-clear" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0018","Clear workspace search"))}" hidden>×</button><button type="button" id="workspace-toggle" tabindex="-1" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0019","Show workspace and family choices"))}" aria-expanded="false" aria-controls="workspace-results">${uiIcon('next')}</button></div><span class="scenario-picker-hint" id="workspace-hint">${this.ui("ui.app.shell.text.0020","Grouped destinations · choosing starts a fresh lesson")}</span><div class="scenario-picker-menu" id="workspace-menu" hidden><div class="scenario-picker-menu-heading"><span id="workspace-search-status" role="status" aria-live="polite"></span><span>${this.ui("ui.app.shell.text.0021","↑ ↓ to navigate · Enter to choose")}</span></div><div class="scenario-picker-results" id="workspace-results" role="listbox" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0022","Workspaces and families"))}"></div></div></nav>
      <section class="lab-navigation"><div class="select-field scenario-picker" id="lab-scenario-picker"><label for="lab-scenario-search">${this.ui("ui.app.shell.text.0023","Universal lab scenario")}</label><div class="scenario-picker-control"><span class="scenario-picker-icon" aria-hidden="true">${uiIcon('search')}</span><input id="lab-scenario-search" type="search" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="lab-scenario-results" aria-describedby="lab-scenario-hint" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(this.uiText("ui.app.shell.attribute.0024","Search scenarios, protocols or attributes…"))}"><button type="button" id="lab-scenario-clear" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0025","Clear scenario search"))}" hidden>×</button><button type="button" id="lab-scenario-toggle" tabindex="-1" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0026","Show scenario choices"))}" aria-expanded="false" aria-controls="lab-scenario-results">${uiIcon('next')}</button></div><span class="scenario-picker-hint" id="lab-scenario-hint">${this.ui("ui.app.shell.text.0027","Type to search · Start with Basic Keycloak sign-in")}</span><div class="scenario-picker-menu" id="lab-scenario-menu" hidden><div class="scenario-picker-menu-heading"><span id="lab-scenario-search-status" role="status" aria-live="polite"></span><span>${this.ui("ui.app.shell.text.0028","↑ ↓ to navigate · Enter to choose")}</span></div><div class="scenario-picker-results" id="lab-scenario-results" role="listbox" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0029","Lab scenarios"))}"></div></div></div></section>
      </div>
      <section class="search-case-choice" id="search-case-choice" role="dialog" aria-modal="false" aria-labelledby="search-case-choice-title" hidden></section>
      <div id="presentation-host"></div>
      <footer class="sources-footer"><p class="documentation-baseline">${this.footerBaselineHtml()}</p><details data-study-key="footer.notes"><summary>${this.ui("ui.app.shell.text.0032","Protocol notes & primary sources")}</summary><div class="source-notes">${FOOTER_NOTE_BINDINGS.map(binding=>`<p>${this.prose('learning-note:'+binding.id,'text',binding.note.text)}</p>`).join('')}<p>${this.ui("ui.app.shell.text.0033","Illustrative messages and values. Login assumes a fresh session. Registration starts with a verified relying-party account. FIDO2 combines WebAuthn and CTAP: external FIDO2 keys use CTAP2 locally; Windows Hello uses the platform authenticator path. In single-realm sign-in, Realm A verifies the selected method and returns the selected protocol’s identity result. In brokered sign-in the upstream provider verifies WebAuthn. For OIDC, application client_id is a configured public identifier; the app validates the ID token’s aud against it. For SAML, Keycloak’s registered client identifier is the SP entity ID, used as AuthnRequest Issuer and assertion Audience; the XML does not gain an OAuth client_id parameter. In direct FIDO2 sign-in the web application itself is the relying party, using its own RP ID and public-key credential records.")}</p><p>${this.ui("ui.app.shell.text.0034","Passkey + TOTP and passwordless TOTP require explicit configured flows. TOTP alone is one factor. External providers must support and configure the chosen method; login-form field names and credential policies are provider-specific.")}</p><p>${this.ui("ui.app.shell.text.0035","SAML Web SSO uses Redirect/POST requests and POST responses. Assertion encryption uses XML Encryption. JWE protects OIDC ID tokens; recipients decrypt locally before verifying the inner signature and applicable claims. Device and CIBA tokens have no invented Authorization Code, PKCE or nonce stages.")}</p><p>${this.ui("ui.app.shell.text.0036","Service accounts act as the application’s own identity and receive an access token without a human login or MFA. Device user_code is not TOTP: it links a separate browser to a private device_code. CIBA uses an administrator-controlled authentication-channel service; its illustrated password/passkey/TOTP policy is a service implementation, not a built-in CIBA browser redirect flow. Standard Token Exchange V2 here is same-realm and access-token-to-access-token; strict downscoping is explicitly configured, not assumed from the grant.")}</p></div><p>${this.ui("ui.app.shell.text.0037","Animated coverage and remaining variants are listed in SPA, API & coverage above. These examples illustrate messages, not live authentication or exhaustive Keycloak configuration.")}</p><div class="source-links" lang="en" dir="ltr" translate="no">${[...SOURCES,...FIDO_SOURCES,...SAML_SOURCES,...JWE_SOURCES,...SERVICE_SOURCES,...DEVICE_SOURCES,...CIBA_SOURCES,...EXCHANGE_SOURCES,...LAB_SOURCES].map(source=>`<a href="${escapeHtml(source.url||source.source)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.label||source.name||source.title)}</a>`).join('')}</div></details><p class="studio-credit"><span>${this.ui("ui.app.shell.text.0038","Version")} <span id="studio-version" dir="ltr" translate="no">${escapeHtml(this.getAttribute('data-build-version')||'1.0')}</span></span><a lang="en" dir="ltr" translate="no" href="https://github.com/andrico21" target="_blank" rel="noopener noreferrer">Kirill Andrienko</a><a lang="en" dir="ltr" translate="no" href="https://github.com/andrico21/auth-lab" target="_blank" rel="noopener noreferrer">andrico21/auth-lab</a></p><span>${this.ui("ui.app.shell.text.0039","Built to explore · RFC / Microsoft / IEEE / OASIS / W3C / FIDO names, plain-language explanations")}</span></footer>
      <div id="actor-popup" class="floating-panel" role="dialog" aria-modal="false" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0040","Participant attributes"))}" hidden></div>
      <div id="attribute-popup" class="attribute-tooltip" role="dialog" aria-modal="false" aria-label="${escapeHtml(this.uiText("ui.app.shell.attribute.0041","Attribute explanation"))}" hidden></div>
      <div id="toast" class="toast" role="status" hidden></div>
      <div id="held-announcement" class="sr-only" role="status" aria-live="polite" aria-atomic="true"></div>
    </main>`;
  }
  fullShell() {
    return `
      <section class="journey-introduction" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0042","Learning question and starting context"))}"><h1 id="learning-question"></h1><p id="learning-start"></p><div id="learning-boundary"></div></section>
      <div class="journey-link-controls"><span id="current-lesson-case" class="current-lesson-case" hidden></span><button class="button quiet" id="copy-lesson-link">${this.ui("ui.app.fullShell.text.0043","Copy lesson link")}</button><label id="lesson-link-manual" hidden>${this.ui("ui.app.fullShell.text.0044","Copy the named lesson/case link (comparison controls use defaults)")}<input id="lesson-link-value" type="text" readonly aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0045","Named lesson and case link"))}"></label></div>
      <section class="lesson-inputs" id="lesson-inputs" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0046","Selected lesson profile and case"))}" hidden></section>
      <div class="workspace">
        <div class="diagram-column"><div class="map-controls" id="map-controls" role="group" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0047","Animation controls"))}">
        <div class="playback-controls"><button class="button primary" id="play">${uiIcon('play',true)}<span>${this.ui("ui.app.fullShell.text.0048","Play demo")}</span></button><button class="icon-button" id="reset" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0049","Reset demo"))}">${uiIcon('reset')}</button></div>
        <div class="speed-control"><label for="speed">${this.ui("ui.app.fullShell.text.0050","Playback speed")} <output class="speed-value" id="speed-label">1×</output></label><input id="speed" type="range" min="0" max="4" step="0.01" value="1" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0051","Playback speed"))}" title="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0052","0 pauses; speeds start at 0.01×. Play restores the last non-zero speed."))}"></div>
        </div>
        <section class="map-panel" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0053","Interactive authentication map"))}">
          <div class="map-heading"><div><h2 id="scenario-title">${this.ui("ui.app.fullShell.text.0054","Sign in with a passkey")}</h2></div><span class="live-status" id="status">${this.ui("ui.app.fullShell.text.0055","READY TO EXPLORE")}</span></div>
          <section class="lesson-chapters" id="lesson-chapters" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0056","Linked canonical journey chapters"))}" hidden></section>
          <div class="attribute-focus-bar" id="attribute-focus" hidden></div>
          <div class="map-scroll"><div class="graph-canvas" id="graph">
            <div class="trust-zones" id="trust-zones" aria-hidden="true"></div>
            <div class="zone-label device">${uiIcon('info')}<span>${this.ui("ui.app.fullShell.text.0057","YOUR DEVICE")}</span></div><div class="zone-label cloud">${this.ui("ui.app.fullShell.text.0058","IDENTITY SERVICES")}</div>
            <svg class="graph-connections" id="connections" viewBox="0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}" aria-label="${escapeHtml(this.uiText('ui.app.fullShell.connections.label','Connections between authentication participants'))}"><defs>${Object.keys(channelLabels).map(c=>`<marker id="arrow-${c}" markerUnits="userSpaceOnUse" markerWidth="9" markerHeight="9" refX="7" refY="3.5" orient="auto-start-reverse" viewBox="0 0 7 7"><path d="M0 0 7 3.5 0 7" class="arrow-fill ${c}"/></marker>`).join('')}</defs><g id="connection-paths"></g></svg>
            <div id="actors"></div>
            <div id="held-docks" class="held-docks"></div>
            <svg class="step-attributes-tether" id="step-attributes-tether" viewBox="0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}" aria-hidden="true" hidden><path/></svg>
            <div class="step-attributes" id="step-attributes" role="group" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0059","Attribute names in the active step"))}" hidden></div>
            <div class="packet-position" id="packet" hidden><div class="packet-chip"><span class="packet-orb"></span><div><span class="packet-name" id="packet-name"></span><code class="packet-value" id="packet-value" dir="ltr" translate="no"></code><span class="packet-explanation locale-prose" id="packet-explanation" hidden></span></div><span class="packet-count" id="packet-count" dir="ltr" translate="no"></span></div></div>
          </div></div>
          <div class="map-display-controls" role="group" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0060","Map display options"))}">
            <label class="overlay-toggle"><input type="checkbox" id="show-step-attributes" checked><span>${this.ui("ui.app.fullShell.text.0061","Show step attributes")}</span></label>
            <label class="overlay-toggle" id="internals-control" hidden><input type="checkbox" id="show-internals"><span>${this.ui("ui.app.fullShell.text.0062","Show component internals")}</span></label>
            <label class="overlay-toggle"><input type="checkbox" id="show-held-objects" checked><span>${this.ui("ui.app.fullShell.text.0063","Show held objects")}</span></label>
          </div>
        <div class="seek-control"><label for="seek"><span>${this.ui("ui.app.fullShell.text.0064","Explore the timeline")}</span><output id="seek-position">${this.ui("ui.app.fullShell.text.0065","Step 1")}</output></label><input id="seek" type="range" min="0" max="1000" step="1" value="0" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0066","Seek through the current journey"))}" aria-describedby="seek-hint"><span id="seek-hint">${this.ui("ui.app.fullShell.text.0067","Drag to inspect any moment · playback stays paused · press Play to continue")}</span></div>
          <section id="step-attributes-external" class="step-attributes-external" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0068","Attribute names in the active step"))}" hidden></section>
          <div id="held-active-message" class="held-active-message" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0069","Active message"))}" hidden></div>
          <section class="lesson-decisions" id="lesson-decisions" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0070","Current identity, trust and access decisions"))}" hidden></section>
          <section class="windows-remote-evidence" id="windows-remote-evidence" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0071","Target policy and before-after authorization context"))}" hidden></section>
          <section class="pam-configuration-panel" id="pam-configuration-panel" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0072","PAM configuration and current evaluation"))}" hidden></section>
          <section class="lifetime-strip" id="lifetime-strip" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0073","Four independent credential and session lifetimes"))}" hidden></section>
          <p class="map-description" id="scenario-description"></p>
          <div class="scenario-environment" id="scenario-environment" hidden></div>
          <div class="map-footer"><div class="legend">${Object.entries(channelLabels).map(([key,label])=>`<span class="legend-item"><span class="legend-dot" data-channel="${key}"></span>${this.ui('ui.channel.'+key,label)}</span>`).join('')}</div><p class="map-hint">${this.ui("ui.app.fullShell.text.0074","Hover or focus a participant for help. F2 moves keyboard focus inside the help panel; Tab explores its controls, Escape returns. Click a connection to replay its exchanges.")}</p></div>
          <div class="current-story" id="story" aria-live="polite"></div>
          <div class="progress-track" role="progressbar" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0075","Journey progress"))}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="progress-bar" id="progress"></div></div>
        </section></div>
        <div class="study-sidebar"><aside class="attribute-index-panel" id="attribute-index" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0076","Separate attribute index"))}"><div class="attribute-index-heading"><div><h2>${this.ui("ui.app.fullShell.text.0077","Attribute index")}</h2><p>${this.ui("ui.app.fullShell.text.0078","Click a field to animate its path. Hover or focus it for help. F2 moves focus inside that help panel; Tab explores, Escape returns.")}</p></div><button class="icon-button" id="attribute-index-toggle" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0079","Hide attribute index"))}">${uiIcon('close')}</button></div><label class="sr-only" for="attribute-search">${this.ui("ui.app.fullShell.text.0080","Search attributes, PKCE or purpose")}</label><input class="glossary-search" id="attribute-search" type="search" placeholder="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0081","Search client_id, PKCE, secret…"))}"><div class="attribute-topic-list" id="attribute-topics"></div><p class="attribute-index-meta" id="attribute-index-meta"></p><div class="attribute-index-list" id="attribute-index-list"></div><p id="attribute-index-empty" hidden>${this.ui("ui.app.fullShell.text.0082","No matching attributes.")}</p></aside>
        <aside class="inspector-panel" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0083","Participant and exchange inspector"))}"><div class="inspector-top"><span id="inspector-heading">${this.ui("ui.app.fullShell.text.0084","EXCHANGE INSPECTOR")}</span><button class="icon-button" id="follow" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0085","Follow the current demo step"))}" title="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0086","Follow the current step"))}">${uiIcon('arrow')}</button></div><div class="inspector-content" id="inspector"></div></aside></div>
      </div>
      <section id="held-objects" class="held-objects" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0087","Current logical-owner inventory"))}"></section>
      <section id="held-inspector" class="held-inspector" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0088","Exact held object inspector"))}" hidden></section>
      <section class="timeline-panel" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0089","Ordered journey steps"))}"><div class="timeline-head"><div><span class="eyebrow">${this.ui("ui.app.fullShell.text.0090","THE JOURNEY")}</span><h2>${this.ui("ui.app.fullShell.text.0091","One exchange at a time")}</h2></div><div class="timeline-controls"><button class="icon-button" id="previous" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0092","Previous step"))}">${uiIcon('previous')}</button><button class="icon-button" id="next" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0093","Next step"))}">${uiIcon('next')}</button></div></div><div class="timeline-strip" id="timeline"></div></section>
      <details class="protocol-state-panel" id="protocol-state-panel" hidden><summary><strong>${this.ui("ui.app.fullShell.text.0094","Current protocol state and object history")}</strong><span id="protocol-state-summary"></span></summary><p class="environment-note">${this.ui("ui.app.fullShell.text.0095","Current state uses the same authored cursor as held objects. The cumulative field-instance ledger below is history, not current possession. Playback speed and card movement do not change protocol time. Values are symbolic examples; private keys and opaque ciphertext are not decrypted by this lab.")}</p><h3>${this.ui("ui.app.fullShell.text.0096","Field-instance history")}</h3><div id="protocol-instance-list"></div><h3>${this.ui("ui.app.fullShell.text.0097","Current protocol state")}</h3><pre id="protocol-state-value"></pre></details>
      <details class="windows-security-comparison" id="windows-security-comparison" hidden><summary>${this.ui("ui.app.fullShell.text.0098","Compare Windows security boundaries")}</summary><p>${this.ui("ui.app.fullShell.text.0099","Each link opens its own configured lesson. No credential, token or session is transferred.")}</p><div id="windows-security-comparison-rows"></div></details>
      <details class="ready-journeys" id="ready-journeys"><summary>${this.ui("ui.app.fullShell.text.0100","More ready-made journeys and the full library")}</summary>
      <button class="button quiet" id="lab-open">${this.ui("ui.app.fullShell.text.0101","Browse the full scenario library")}</button>
      <section class="workspace-presets" id="workspace-presets" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0102","Ready-made workspace scenarios"))}" hidden></section>
      <section class="quick-start" id="quick-start" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0103","Ready-made corporate scenarios"))}"><div class="quick-start-heading"><h2>${this.ui("ui.app.fullShell.text.0104","Choose a ready-made scenario")}</h2><p>${this.ui("ui.app.fullShell.text.0105","Choose a scenario, then press Play. The settings are already selected.")}</p></div><div class="quick-start-grid">${[...LEARNING_PRESETS.filter(p=>['basic-keycloak','basic-saml'].includes(p.id)),...LEARNING_PRESETS.filter(p=>p.common&&!['basic-keycloak','basic-saml'].includes(p.id))].map(p=>`<button class="quick-preset" data-learning-preset="${p.id}" aria-pressed="${p.id===this.labScenarioId}"><strong>${this.prose('lesson:'+p.id,'title',p.title,{scenarioId:p.id,variantId:'default',subfixtureId:null})}</strong><span>${this.prose('lesson:'+p.id,'summary',p.summary,{scenarioId:p.id,variantId:'default',subfixtureId:null})}</span></button>`).join('')}</div></section>
      <details class="lab-catalog" id="lab-catalog"><summary><strong>${this.ui("ui.app.fullShell.text.0106","Scenario library")}</strong><span>${this.ui("ui.app.fullShell.text.0107","Applications · token lifecycle · protections · protocol variants · failure paths")}</span></summary><label class="sr-only" for="lab-search">${this.ui("ui.app.fullShell.text.0108","Find a scenario")}</label><input id="lab-search" class="glossary-search" type="search" placeholder="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0109","Search SPA, refresh, DPoP, logout, Artifact, consent…"))}"><div class="lab-cards" id="lab-cards"></div></details>
      </details><details class="lesson-reference" id="lesson-reference" hidden><summary>${this.ui("ui.app.fullShell.text.0110","Profile, primary sources and related journeys")}</summary>
      <div class="lab-support" id="lab-support" hidden></div>
      <section class="learning-profile" id="learning-profile" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0111","Selected teaching profile and completion boundary"))}" hidden><div id="learning-profile-content"></div><div class="learning-detail-controls" role="group" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0112","Lesson detail"))}"><button class="button quiet" id="learning-detail-journey" data-learning-detail="journey" aria-pressed="true">${this.ui("ui.app.fullShell.text.0113","Journey")}</button><button class="button quiet" id="learning-detail-fields" data-learning-detail="fields" aria-pressed="false">${this.ui("ui.app.fullShell.text.0114","Fields")}</button><button class="button quiet" id="learning-detail-crypto" data-learning-detail="crypto" aria-pressed="false">${this.ui("ui.app.fullShell.text.0115","Cryptographic detail")}</button></div><div id="learning-profile-crypto" hidden></div><div class="related-journeys" id="related-journeys" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0116","Compare related journeys"))}" hidden></div></section>
      </details>
      <section class="provider-settings" id="provider-settings" hidden><div class="select-field"><label for="provider-profile">${this.ui("ui.app.fullShell.text.0117","External identity provider")}</label><select id="provider-profile">${PROVIDER_PROFILES.map(profile=>{const title=this.proseText('provider:'+profile.id,'title',profile.title),literal=title===profile.title;return `<option value="${profile.id}"${literal?' dir="ltr" translate="no" lang="en"':''}>${escapeHtml(title)}</option>`;}).join('')}</select></div><div class="provider-description"><p id="provider-note"></p><p id="provider-protection-note" hidden></p><div id="provider-sources" class="provider-sources"></div></div></section>
      <details class="advanced-configuration" id="advanced-configuration"><summary><strong>${this.ui("ui.app.fullShell.text.0118","Advanced configuration")}</strong><span>${this.ui("ui.app.fullShell.text.0119","Optional · explore another combination")}</span></summary><div class="advanced-layout-controls"><label class="overlay-toggle"><input type="checkbox" id="move-participants"><span>${this.ui("ui.app.fullShell.text.0120","Move participants")}</span></label><button class="button quiet" id="layout-reset">${this.ui("ui.app.fullShell.text.0121","Reset layout")}</button></div>
      <section class="toolbar" aria-label="${escapeHtml(this.uiText("ui.app.fullShell.attribute.0122","Scenario settings"))}">
        <div class="select-field"><label for="mode">${this.ui("ui.app.fullShell.text.0123","Learning journey")}</label><select id="mode">${Object.entries(modeMetadata).map(([key,metadata])=>`<option value="${key}">${escapeHtml(this.proseText('mode:'+key,'title',metadata.title))}</option>`).join('')}</select></div>
        <div class="select-field"><label for="architecture">${this.ui("ui.app.fullShell.text.0124","Application")}</label><select id="architecture">${Object.entries(ARCHITECTURES).map(([key,architecture])=>`<option value="${key}">${escapeHtml(this.proseText('architecture:'+key,architecture.name?'name':'title',architecture.name||architecture.title))}</option>`).join('')}</select></div>
        <div class="select-field"><label for="upstream">${this.ui("ui.app.fullShell.text.0125","Identity setup")}</label><select id="upstream">${Object.entries(UPSTREAMS).map(([key,upstream])=>`<option value="${key}">${key==='keycloak'?this.ui('ui.upstream.two-realms','Two Keycloak realms'):key==='external'?this.ui('ui.upstream.external','Keycloak + external OIDC IdP'):escapeHtml(this.proseText('upstream:'+key,upstream.name?'name':'title',upstream.name||upstream.title))}</option>`).join('')}</select></div>
        <div class="select-field"><label for="authenticator">${this.ui("ui.app.fullShell.text.0126","Passkey device")}</label><select id="authenticator" dir="ltr" translate="no"><option value="hello" lang="en">Windows Hello</option><option value="yubikey" lang="en">YubiKey</option></select></div>

      </section>
      <details data-study-key="protocol.controls" class="protocol-toolbar" open><summary><strong>${this.ui("ui.app.fullShell.text.0129","Protocols & protection")}</strong><span id="protocol-summary">${this.ui("ui.app.fullShell.text.0130","OIDC · signed ID tokens")}</span></summary><div class="protocol-grid">
        <div class="select-field"><label for="oidc-flow">${this.ui("ui.app.fullShell.text.0131","OAuth / OIDC learning flow")}</label><select id="oidc-flow"><option value="authorization-code">${this.ui("ui.app.fullShell.text.0132","Authorization Code · interactive sign-in")}</option><option value="client-credentials">${this.ui("ui.app.fullShell.text.0133","Service account · client_credentials")}</option><option value="device">${this.ui("ui.app.fullShell.text.0134","Device Authorization Flow")}</option><option value="ciba">${this.ui("ui.app.fullShell.text.0135","CIBA · Poll delivery")}</option><option value="token-exchange">${this.ui("ui.app.fullShell.text.0136","Token exchange · Standard V2")}</option></select></div>
        <div class="select-field"><label for="app-protocol">${this.ui("ui.app.fullShell.text.0137","Application ↔ Realm A")}</label><select id="app-protocol"><option value="oidc">${this.ui("ui.app.fullShell.text.0138","OIDC · Authorization Code")}</option><option value="saml">${this.ui("ui.app.fullShell.text.0139","SAML 2.0 · Web SSO")}</option></select></div>
        <div class="select-field"><label for="broker-protocol">${this.ui("ui.app.fullShell.text.0140","Realm A ↔ upstream IdP")}</label><select id="broker-protocol"><option value="oidc">${this.ui("ui.app.fullShell.text.0141","OIDC · Authorization Code")}</option><option value="saml">${this.ui("ui.app.fullShell.text.0142","SAML 2.0 · Web SSO")}</option></select></div>
        <div class="select-field"><label for="saml-binding">${this.ui("ui.app.fullShell.text.0143","SAML request binding")}</label><select id="saml-binding"><option value="redirect">${this.ui("ui.app.fullShell.text.0144","HTTP-Redirect · signed query")}</option><option value="post">${this.ui("ui.app.fullShell.text.0145","HTTP-POST · signed XML")}</option></select></div>
        <div class="select-field"><label for="saml-initiation">${this.ui("ui.app.fullShell.text.0146","SAML application initiation")}</label><select id="saml-initiation"><option value="sp">${this.ui("ui.app.fullShell.text.0147","SP initiated · app requests login")}</option><option value="idp">${this.ui("ui.app.fullShell.text.0148","IdP initiated · configured unsolicited SSO")}</option></select></div>
        <div class="select-field"><label for="token-protection">${this.ui("ui.app.fullShell.text.0149","OIDC ID token protection")}</label><select id="token-protection"><option value="signed">${this.ui("ui.app.fullShell.text.0150","Signed JWS")}</option><option value="app-jwe">${this.ui("ui.app.fullShell.text.0151","App ID token · signed then JWE")}</option><option value="broker-jwe">${this.ui("ui.app.fullShell.text.0152","Broker ID token · signed then JWE")}</option><option value="both-jwe">${this.ui("ui.app.fullShell.text.0153","All OIDC ID tokens · signed then JWE")}</option></select></div>
        <div class="select-field"><label for="assertion-protection">${this.ui("ui.app.fullShell.text.0154","SAML assertion protection")}</label><select id="assertion-protection"><option value="signed">${this.ui("ui.app.fullShell.text.0155","Signed assertion")}</option><option value="encrypted">${this.ui("ui.app.fullShell.text.0156","Signed + XML Encryption")}</option></select></div>
      </div><p class="protocol-note">${this.ui("ui.app.fullShell.text.0157","SAML responses use HTTP-POST. Encryption protects the message; signatures and recipient checks still establish trust. JWE applies to OIDC ID tokens, while SAML uses XML Encryption.")}</p></details></details>
      <details class="environment-panel" id="environment-panel"><summary><strong>${this.ui("ui.app.fullShell.text.0158","Use your environment")}</strong><span>${this.ui("ui.app.fullShell.text.0159","Optional · addresses for this open page")}</span></summary><p class="environment-note">${this.ui("ui.app.fullShell.text.0160","Show your application and identity-provider addresses in the animation. Values stay in this open page and return to examples on reload, navigation away or Reset environment. The animation makes no requests to these addresses.")}</p><div id="environment-fields"></div><p class="environment-errors" id="environment-errors" role="alert" hidden></p><div class="environment-actions"><button class="button primary" id="environment-apply">${this.ui("ui.app.fullShell.text.0161","Apply to animation")}</button><button class="button quiet" id="environment-reset">${this.ui("ui.app.fullShell.text.0162","Reset environment")}</button><span id="environment-status" role="status"></span></div></details>
      <details data-study-key="coverage.panel" class="coverage-panel"><summary><strong>${this.ui('ui.app.fullShell.text.0163','SPA, API & coverage')}</strong><span>${this.ui('ui.coverage.extended','Core controls + '+LAB_SCENARIOS.length+' extended scenarios',{count:LAB_SCENARIOS.length})}</span></summary><div class="coverage-content"><div><h3>${this.ui('ui.app.fullShell.text.0164','SPA and API are different roles')}</h3><p>${this.rich('ui.coverage.spa','A {spa} runs in the browser. A pure browser OAuth client cannot keep a client secret. The SPA walkthrough shows its HTTPS callback, Code + PKCE, token handling, CORS and a separate resource API.',{spa:{kind:'protected',value:'Single Page Application (SPA)',node:{tag:'strong'}}})}</p><p>${this.rich('ui.coverage.api','An {api} checks the access token’s trust, intended audience, lifetime and permissions. API introspection, 401/403, JWKS rotation, certificate binding and DPoP are distinct scenarios. An ID token is the client’s login result, not an API credential.',{api:{kind:'protected',value:'API',node:{tag:'strong'}}})}</p><p>${this.rich('ui.coverage.bff','A {bff} retains credentials and tokens on the server and gives the browser an opaque session cookie. The BFF → API scenario shows this boundary.',{bff:{kind:'protected',value:'Backend for Frontend (BFF)',node:{tag:'strong'}}})}</p><h3>${this.ui('ui.app.fullShell.text.0172','How to use the lab')}</h3><p>${this.ui('ui.app.fullShell.text.0173','Choose a scenario above or browse the searchable library. Play the entire process, click a connection, or select one attribute. Enable Show step attributes to keep the message’s complete names beside its active link. Enable Move participants to drag cards or use arrow keys; Reset layout restores their positions.')}</p></div><div><h3>${this.ui('ui.app.fullShell.text.0174','Animated coverage')}</h3><ul><li>${this.ui('ui.app.fullShell.text.0175','Core configurable OIDC/SAML sign-in: one realm, two realms, independent upstream IdP, native loopback and confidential web callback; passwords, passkeys, FIDO2, TOTP and configured MFA.')}</li>${this.coverageCategories()}</ul><h3>${this.ui('ui.app.fullShell.text.0176','Support is visible')}</h3><p>${this.ui('ui.app.fullShell.text.0177','Each scenario links to primary documentation and identifies supported/configured Keycloak behavior, Preview/deprecated behavior or a standards-only profile. CIBA Push and alternate signed-hint profiles are not presented as built-in Keycloak features. Legacy grants are educational comparisons.')}</p><h3>${this.ui('ui.app.fullShell.text.0178','Practical limits')}</h3><p>${this.ui('ui.app.fullShell.text.0179','This is an offline protocol simulator. Values and cryptographic operations are schematic; it does not configure or contact a live server. Provider-specific policies and every combination of extensions are not expanded into separate presets. Detailed factor ceremonies remain available in the core journeys. Version-specific support is stated in the scenario’s note.')}</p></div></div></details>
    `;
  }
  bindFull() {
    this.listenFull(this.querySelector('#workspace-presets'), 'click', event=>{const button=event.target.closest('[data-lab-scenario]');if(button)this.selectJourneyFromControl(button,button.dataset.labScenario);});
    this.listenFull(this.querySelector('#lesson-inputs'), 'change', event=>{
      const control=event.target,returnTarget=captureFocusTarget(this,control);
      if(control.id==='lesson-case')this.selectLessonVariant(control.value);
      else if(control.id==='lesson-subfixture')this.selectLessonSubfixture(control.value);
      else if(control.dataset.profileControl){
        const profile=this.labModel?.profileControls?.find(item=>item.id===control.dataset.profileControl),option=profile?.options.find(item=>item.value===control.value);
        if(option)this.selectLabScenario(option.scenarioId||this.labScenarioId,{variant:option.variantId||'default'});
      }
      if(returnTarget)this.restoreTargetFocus(returnTarget,{fallbackSelector:'#play'});
    });
    this.listenFull(this.querySelector('#lesson-chapters'), 'click', event=>{
      const button=event.target.closest('[data-lesson-chapter]'),chapter=this.labModel?.chapters?.find(item=>item.id===button?.dataset.lessonChapter);
      if(!chapter?.stepIds.length)return;
      if(this.hasTrace)this.clearAttribute();
      const index=this.steps.findIndex(step=>step.id===chapter.stepIds[0]);if(index>=0)this.selectStep(index,false);
    });
    this.listenFull(this.querySelector('#learning-profile'), 'click', event=>{
      const detail=event.target.closest('[data-learning-detail]');
      if(detail&&['journey','fields','crypto'].includes(detail.dataset.learningDetail)){
        this.learningDetail=detail.dataset.learningDetail;this.renderLearningProfile();this.updateStep();this.renderInspector();
      }
    });
    this.listenFull(this.querySelector('#show-internals'), 'change', ()=>{
      this.hidePopups();this.showInternals=this.querySelector('#show-internals').checked;this.renderAll();this.renderPacket(this.player.snapshot());
      this.querySelector('#show-internals').focus();
    });
    this.listenFull(this.querySelector('#quick-start'), 'click', e=>{const button=e.target.closest('[data-learning-preset]');if(button)this.selectLabScenario(button.dataset.learningPreset);});
    this.listenFull(this.refs['provider-profile'], 'change', ()=>{this.providerProfileId=this.refs['provider-profile'].value;this.brokerProtocol=this.providerProfile.protocol;this.providerManaged=this.providerProfileId!=='generic'||!!this.learningPreset?.providerSelectable;this.refreshConfiguration();});
    this.listenFull(this.refs['environment-fields'], 'input', e=>{const field=e.target.closest('[data-environment-field]');if(field){const key=field.dataset.environmentField;this.runtimeEnvironment.updateDraft(key.startsWith('provider.')?{provider:{[key.slice(9)]:field.value}}:{[key]:field.value},{profileId:this.providerProfile.id});}});
    this.listenFull(this.querySelector('#environment-apply'), 'click', ()=>this.applyEnvironment());
    this.listenFull(this.querySelector('#environment-reset'), 'click', ()=>this.resetEnvironment());
    this.listenFull(this.querySelector('#lab-open'), 'click', ()=>{this.querySelector('#ready-journeys').open=true;this.refs['lab-catalog'].open=!this.refs['lab-catalog'].open;if(this.refs['lab-catalog'].open)this.refs['lab-search'].focus();});
    this.listenFull(this.refs['lab-search'], 'input', event=>{this.catalogQuery=event.target.value;if(event.isComposing||this.localeCompositions.has(event.target)){this.localeDeferredInputs.add(event.target);return;}this.localeDeferredInputs.delete(event.target);this.renderCatalog();});
    this.listenFull(this.refs['lab-cards'], 'click', event=>{const card=event.target.closest('[data-lab-scenario]');if(card)this.selectSearchResult(card.dataset.labScenario,this.catalogResultsById?.get(card.dataset.labScenario),card);});
    this.listenFull(this.querySelector('#copy-lesson-link'), 'click', ()=>this.copyLessonLink());
    this.listenFull(this.refs['move-participants'], 'change', ()=>{this.moveParticipants=!!this.refs['move-participants'].checked;this.refs.graph.classList.toggle('is-move-mode',this.moveParticipants);this.heldView.configureGeometry();this.renderActors();this.renderConnections();this.renderPacket(this.player.snapshot());});
    this.listenFull(this.querySelector('#layout-reset'), 'click', ()=>{delete this.customLayouts[this.layoutKey];this.renderAll();this.renderPacket(this.player.snapshot());this.renderStepAttributes(this.player.snapshot(),true);});
    ['mode','authenticator','architecture','upstream'].forEach(key=>this.listenFull(this.refs[key], 'change', ()=>{const wasDirect=this.isDirectFido;this.labScenarioId='core';this[key]=this.refs[key].value;if(key==='mode'&&(this.isDirectFido||modeMetadata[this.mode]?.enrollment))this.oidcFlow='authorization-code';if(key==='mode'&&this.isDirectFido&&!wasDirect){this.authenticator='yubikey';this.refs.authenticator.value='yubikey';}this.refreshConfiguration();}));
    this.listenFull(this.refs['oidc-flow'], 'change', ()=>{this.labScenarioId='core';this.oidcFlow=this.refs['oidc-flow'].value;if(this.isAdvancedFlow){this.applicationProtocol='oidc';if(this.isDirectFido||modeMetadata[this.mode]?.enrollment)this.mode='passkey';this.refs.mode.value=this.mode;}this.refreshConfiguration();});
    [['app-protocol','applicationProtocol'],['broker-protocol','brokerProtocol'],['saml-binding','samlBinding'],['saml-initiation','samlInitiation'],['token-protection','tokenProtection'],['assertion-protection','assertionProtection']].forEach(([id,key])=>this.listenFull(this.refs[id], 'change', ()=>{this.labScenarioId='core';this[key]=this.refs[id].value;if(id==='app-protocol'&&this.applicationProtocol==='saml')this.oidcFlow='authorization-code';this.refreshConfiguration();}));
    this.listenFull(this.refs.play, 'click', ()=>{
      if(this.player.inspectionBoundary){this.playCompact();return;}
      this.ensureRunningSpeed();
      if(this.player.status==='playing')this.player.pause();
      else if(this.player.status==='paused')this.player.resume();
      else if(this.hasTrace)this.playAttribute();
      else {this.inspection={type:'step'};this.visited.clear();this.player.play(this.steps,'demo');}
    });
    this.listenFull(this.querySelector('#reset'), 'click', ()=>this.reset());
    this.listenFull(this.refs.speed, 'input', ()=>this.player.setSpeed(this.refs.speed.value));
    this.listenFull(this.refs.seek, 'input', ()=>this.seekPlayback(Number(this.refs.seek.value)/1000));
    this.listenFull(this.refs['show-step-attributes'], 'change', ()=>{this.showStepAttributes=!!this.refs['show-step-attributes'].checked;this.renderStepAttributes(this.player.snapshot(),true);});
    this.listenFull(this.querySelector('#previous'), 'click', ()=>this.selectStep(Math.max(0,this.visibleIndex-1),true));
    this.listenFull(this.querySelector('#next'), 'click', ()=>this.selectStep(Math.min(this.visibleSteps.length-1,this.visibleIndex+1),true));
    this.listenFull(this.querySelector('#follow'), 'click', ()=>{this.inspection={type:'step'};this.renderInspector();});
    this.listenFull(this.querySelector('#attribute-index-toggle'), 'click', ()=>{this.hidePopups();this.refs['attribute-index'].hidden=true;this.restoreTargetFocus({elementId:'index-open'});});
    this.listenFull(this.refs['attribute-search'], 'input', event=>{this.attributeQuery=event.target.value;if(event.isComposing||this.localeCompositions.has(event.target)){this.localeDeferredInputs.add(event.target);return;}this.localeDeferredInputs.delete(event.target);this.renderAttributeIndex();});
    this.listenFull(this.refs['attribute-index'], 'click', e=>{const field=e.target.closest('[data-index-attribute]');const topic=e.target.closest('[data-trace-topic]');if(field)this.selectAttribute(field.dataset.indexAttribute);if(topic)this.selectAttribute(topic.dataset.traceTopic);});
    this.listenFull(this.refs['attribute-index-list'], 'pointerover', e=>{const field=e.target.closest('[data-index-attribute]');if(e.pointerType!=='touch'&&field&&!field.contains(e.relatedTarget))this.showAttributePopup(field.dataset.indexAttribute,field);});
    this.listenFull(this.refs['attribute-index-list'], 'pointerout', ()=>this.deferCloseAttribute());
    this.listenFull(this.refs['attribute-index-list'], 'focusin', e=>{const field=e.target.closest('[data-index-attribute]');if(field?.matches(':focus-visible'))this.showAttributePopup(field.dataset.indexAttribute,field);});
    this.listenFull(this.refs['attribute-index-list'], 'focusout', e=>this.deferCloseAttribute(e.relatedTarget));
    this.listenFull(this.refs['attribute-focus'], 'click', e=>{if(e.target.closest('[data-clear-trace]'))this.clearAttribute();if(e.target.closest('[data-trace-play]')){this.ensureRunningSpeed();if(this.player.status==='playing')this.player.pause();else if(this.player.status==='paused')this.player.resume();else this.playAttribute();}});
    this.listenFull(this.refs.timeline, 'click', e=>{const button=e.target.closest('[data-step]');if(button)this.selectStep(Number(button.dataset.step),true);});
    this.listenFull(this.querySelector('#protocol-state-panel'), 'toggle', event=>{if(event.target.id==='protocol-state-panel')this.renderProtocolState();else if(event.target.matches('[data-instance-history]'))this.renderProtocolInstanceHistory(event.target);}, true);
    this.listenFull(this.refs.actors, 'click', e=>{const node=e.target.closest('[data-actor]');if(node&&!this.moveParticipants)this.inspectActor(node.dataset.actor);});
    this.listenFull(this.refs.actors, 'pointerdown', event=>this.startActorDrag(event));
    this.listenFull(this.refs.actors, 'pointermove', event=>this.updateActorDrag(event));
    this.listenFull(this.refs.actors, 'pointerup', event=>this.endActorDrag(event));
    this.listenFull(this.refs.actors, 'pointercancel', event=>this.endActorDrag(event));
    this.listenFull(this.refs.actors, 'keydown', event=>{const card=event.target.closest('[data-actor]'),delta={ArrowLeft:[-12,0],ArrowRight:[12,0],ArrowUp:[0,-12],ArrowDown:[0,12]}[event.key];if(this.moveParticipants&&card&&delta){event.preventDefault();const p=this.positions[card.dataset.actor];this.moveActor(card.dataset.actor,p.x+delta[0],p.y+delta[1]);}});
    this.listenFull(this.refs.actors, 'pointerover', e=>{const node=e.target.closest('[data-actor]');if(e.pointerType!=='touch'&&node&&!node.contains(e.relatedTarget))this.showActorPopup(node.dataset.actor,node);});
    this.listenFull(this.refs.actors, 'pointerout', e=>{const node=e.target.closest('[data-actor]');if(node&&!node.contains(e.relatedTarget))this.deferCloseActor();});
    this.listenFull(this.refs.actors, 'focusin', e=>{const node=e.target.closest('[data-actor]');if(node?.matches(':focus-visible'))this.showActorPopup(node.dataset.actor,node);});
    this.listenFull(this.refs.actors, 'focusout', e=>this.deferCloseActor(e.relatedTarget));
    this.listenFull(this.refs.connections, 'click', e=>{const edge=e.target.closest('[data-pair]');if(edge)this.replayConnection(edge.dataset.pair);});
    this.listenFull(this.refs.connections, 'keydown', e=>{if(e.key==='Enter'||e.key===' '){const edge=e.target.closest('[data-pair]');if(edge){e.preventDefault();this.replayConnection(edge.dataset.pair);}}});
    [this.refs.inspector,this.refs['actor-popup']].forEach(container=>{
      this.listenFull(container, 'pointerover', e=>{const field=e.target.closest('[data-attribute]');if(e.pointerType!=='touch'&&field&&!field.contains(e.relatedTarget))this.showAttributePopup(field.dataset.attribute,field);});
      this.listenFull(container, 'pointerout', e=>{const field=e.target.closest('[data-attribute]');if(field&&!field.contains(e.relatedTarget))this.deferCloseAttribute();});
      this.listenFull(container, 'focusin', e=>{const field=e.target.closest('[data-attribute]');if(field?.matches(':focus-visible'))this.showAttributePopup(field.dataset.attribute,field);});
      this.listenFull(container, 'focusout', e=>this.deferCloseAttribute(e.relatedTarget));
      this.listenFull(container, 'click', e=>{const field=e.target.closest('[data-attribute]');if(field)this.selectAttribute(field.dataset.attribute);});
    });
    this.listenFull(this.refs.inspector, 'click', e=>{
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
    this.listenFull(this.refs.inspector, 'input', event=>{if(!event.target.matches('#glossary-search'))return;this.glossaryQuery=event.target.value;if(event.isComposing||this.localeCompositions.has(event.target)){this.localeDeferredInputs.add(event.target);return;}this.localeDeferredInputs.delete(event.target);this.filterGlossary(event.target.value);});
    this.listenFull(this.refs['actor-popup'], 'mouseenter', ()=>clearTimeout(this.closeTimer));
    this.listenFull(this.refs['actor-popup'], 'mouseleave', ()=>this.deferCloseActor());
    this.listenFull(this.refs['actor-popup'], 'click', e=>{if(e.target.closest('[data-close]'))this.dismissPopup('actor');});
    this.listenFull(this.refs['attribute-popup'], 'mouseenter', ()=>{clearTimeout(this.attributeTimer);if(this.refs['actor-popup'].contains(this.attributeAnchor))clearTimeout(this.closeTimer);});
    this.listenFull(this.refs['attribute-popup'], 'mouseleave', ()=>{this.deferCloseAttribute();this.deferCloseActor();});
    this.listenFull(this.refs['attribute-popup'], 'click', e=>{if(e.target.closest('[data-close]'))this.dismissPopup('attribute');});
    ['actor','attribute'].forEach(kind=>{
      this.listenFull(this.refs[kind+'-popup'], 'focusin', ()=>{
        if(kind==='actor'||this.refs['actor-popup'].contains(this.attributeAnchor))clearTimeout(this.closeTimer);
        if(kind==='attribute'||this.popupOwnsFocus('attribute'))clearTimeout(this.attributeTimer);
        // :focus-within reveals the keyboard hint and changes the measured height.
        const popup=this.refs[kind+'-popup'],anchor=this[kind+'Anchor'];
        if(anchor&&!popup.hidden)this.placePopup(popup,anchor,kind==='actor'?370:340);
      });
      this.listenFull(this.refs[kind+'-popup'], 'focusout', e=>{this.deferCloseAttribute(e.relatedTarget);this.deferCloseActor(e.relatedTarget);});
    });
    this.listenFull(this, 'keydown', e=>{
      if(e.isComposing||e.keyCode===229||this.localeCompositions.has(e.target))return;
      if(e.key==='Escape'){
        if(this.refs['attribute-popup'].contains(e.target))this.dismissPopup('attribute');
        else if(this.refs['actor-popup'].contains(e.target))this.dismissPopup('actor');
        else this.hidePopups();
      }
      if(e.key==='F2'){
        const field=e.target.closest('[data-index-attribute], [data-attribute]'),card=e.target.closest('[data-actor]');
        if(field){e.preventDefault();if(this.showAttributePopup(field.dataset.indexAttribute||field.dataset.attribute,field))this.refs['attribute-popup'].querySelector('.source-link')?.focus();}
        else if(card){e.preventDefault();if(this.showActorPopup(card.dataset.actor,card))this.refs['actor-popup'].querySelector('[data-attribute], [data-close]')?.focus();}
      }
    });
    this.windowResizeListener=()=>{this.resizeHelpPanels();const state=this.player.snapshot();this.renderPacket(state);this.renderStepAttributes(state,true);};
    this.listenFull(window, 'resize', this.windowResizeListener);
  }
  selectJourneyFromControl(button,id,{variant='default'}={}){
    const returnTarget=button.contains(document.activeElement)?captureFocusTarget(this,document.activeElement):null;
    this.selectLabScenario(id,{variant});
    // These surfaces replace their buttons on selection. Return keyboard focus
    // to the chosen starter when available, otherwise to the persistent Play.
    if(returnTarget)this.restoreTargetFocus({...returnTarget,scenarioId:id,region:returnTarget.region||'workspace-presets'},{fallbackSelector:'#play',preventScroll:false});
  }
  selectSearchResult(id,result,button=null){
    const model=LAB_MODELS[getLearningPreset(id)?.modelId||id],variants=result?.matchingCases||result?.matchingVariantIds?.map(variantId=>(model?.variantChoices||[]).find(choice=>choice.id===variantId)).filter(Boolean)||[];
    if(!result?.variantId&&variants.length>1){
      this.player.pause();this.searchCaseChoice={id,variants,returnTarget:captureFocusTarget(this,button||this.querySelector('#lab-scenario-search'))};
      this.renderSearchCaseChoice();this.querySelector('#search-case-choice [data-search-case]')?.focus();return false;
    }
    this.closeSearchCaseChoice();
    const variant=result?.variantId||'default';
    if(button)this.selectJourneyFromControl(button,id,{variant});else this.selectLabScenario(id,{variant});
    if(result?.variantId){this.refs.play.focus();this.announceSelectedCase();}
  }
  renderSearchCaseChoice(){
    const choice=this.searchCaseChoice;if(!choice)return;
    const model=LAB_MODELS[getLearningPreset(choice.id)?.modelId||choice.id],title=model?.title||choice.id;
    const titleRef=model?{ownerId:'lesson:'+model.id,fieldPath:'title',source:title,context:this.localeContext({scenarioId:model.id,variantId:'default'})}:null;
    const summary=titleRef?this.ui('ui.case.multiple-label',title+' has several relevant cases. The current demonstration has not been replaced.',{title:titleRef}):this.ui('ui.case.multiple-id',title+' has several relevant cases. The current demonstration has not been replaced.',{id:title});
    const panel=this.querySelector('#search-case-choice');panel.hidden=false;
    panel.innerHTML='<h2 id="search-case-choice-title">'+this.ui('ui.case.choose','Choose a matching case')+'</h2><p>'+summary+'</p><div class="search-case-buttons">'+choice.variants.map(variant=>'<button class="button quiet" data-search-case="'+escapeHtml(variant.id)+'">'+(variant.label?this.prose('lesson:'+(model?.id||choice.id),'searchVariants.label',variant.label,{scenarioId:model?.id||choice.id,variantId:variant.id}):this.ltr(variant.id))+'</button>').join('')+'</div><button class="button quiet" data-cancel-search-case>'+this.ui('ui.case.cancel','Cancel')+'</button>';
  }
  announceSelectedCase(){
    const model=this.baseLabModel,variant=model?.variantChoices?.find(choice=>choice.id===this.lessonVariant);
    if(variant?.label)this.notify('ui.case.selected-label','Selected case: '+variant.label,{label:{ownerId:'lesson:'+model.id,fieldPath:'searchVariants.label',source:variant.label,context:this.localeContext()}});
    else this.notify('ui.case.selected-id','Selected case: '+this.lessonVariant,{id:this.lessonVariant});
  }
  closeSearchCaseChoice(restore=false){
    const target=this.searchCaseChoice?.returnTarget;this.searchCaseChoice=null;
    const panel=this.querySelector('#search-case-choice');panel.hidden=true;panel.innerHTML='';
    if(restore&&target)this.restoreTargetFocus(target,{fallbackSelector:'#lab-scenario-search'});
  }
  async copyLessonLink(){
    const route=studioRoute(this.labScenarioId,LAB_MODELS,this.lessonVariant||'default'),url=String(window.location?.href||'').split(/[?#]/)[0]+route;
    const manual=this.querySelector('#lesson-link-manual'),input=this.querySelector('#lesson-link-value');input.value=url;
    if(globalThis.navigator?.clipboard?.writeText){
      try{await globalThis.navigator.clipboard.writeText(url);manual.hidden=true;this.notify('ui.link.copied','Named lesson/case link copied. Comparison controls reopen at defaults.');return;}catch{/* Browser permission can require manual copying; never report a failed copy as success. */}
    }
    manual.hidden=false;input.focus();input.select?.();this.notify('ui.link.unavailable','Clipboard unavailable. Select and copy the lesson link shown.');
  }
  selectLabScenario(id,{navigate=true,variant='default'}={}) {
    const preset=getLearningPreset(id),base=LAB_MODELS[preset?.modelId||id];
    if(id!=='core'&&!preset&&!base)return;
    variant=studioVariantId(base?.id||id,LAB_MODELS,variant);
    const keys=['mode','authenticator','architecture','upstream','applicationProtocol','brokerProtocol','samlBinding','samlInitiation','tokenProtection','assertionProtection','oidcFlow','providerProfileId','providerManaged'];
    if(this.labScenarioId==='core')this.coreConfiguration=Object.fromEntries(keys.map(key=>[key,this[key]]));
    this.labScenarioId=id;this.lessonVariant=variant;this.lessonSubfixture=null;
    this.closeSearchCaseChoice();
    this.querySelector('#lesson-link-manual').hidden=true;
    this.workspace=workspaceOf(LAB_MODELS[preset?.modelId||id]);this.family=this.labModel?.family||'ad-ds';this.showInternals=false;this.learningDetail='journey';
    if(preset){const profile=preset.providerSelectable?(this.providerProfileId==='generic'?'entra':this.providerProfileId):'generic';Object.assign(this,getPresetConfiguration(id,profile));this.labScenarioId=id;}
    if(id==='core'&&this.coreConfiguration)Object.assign(this,this.coreConfiguration);
    if(id==='core'){if(this.providerProfileId==='generic')this.providerManaged=false;if(this.presentationMode==='full'){this.querySelector('#advanced-configuration').open=true;this.querySelector('#advanced-configuration').setAttribute('open','');}}
    if(this.labModel&&this.attributeSelection)this.attributeSelection=this.labAttributeAlias(this.attributeSelection);
    this.dragState=null;this.refreshConfiguration();
    if(navigate)this.writeRoute();
  }
  selectLessonVariant(id){
    const base=this.baseLabModel;
    if(!base?.withVariant)throw new RangeError('This lesson has no selectable cases.');
    this.lessonVariant=studioVariantId(base.id,LAB_MODELS,id);this.lessonSubfixture=null;this.attributeSelection=null;this.objectTraceSelection=null;this.definitionMemo=null;
    this.querySelector('#lesson-link-manual').hidden=true;
    this.refreshConfiguration();this.writeRoute();
    this.announceSelectedCase();
  }
  selectLessonSubfixture(id){
    const model=this.labModel,choice=model?.subfixtureChoices?.find(member=>member.id===id);
    if(!model?.withSubfixture||!choice)throw new RangeError('Unknown comparison profile: '+id);
    this.lessonSubfixture=id;this.attributeSelection=null;this.objectTraceSelection=null;this.definitionMemo=null;
    this.refreshConfiguration();this.notify('ui.case.comparison-profile','Comparison profile: '+choice.label+'. A copied link reopens the named case at its defaults.',{label:{ownerId:'lesson:'+model.id,fieldPath:'subfixtureChoices.label',source:choice.label,context:this.localeContext({subfixtureId:choice.id})}});
  }
  selectWorkspace(id){
    const workspace=STUDIO_WORKSPACES.find(item=>item.id===id);if(!workspace)return;
    const models=LAB_SCENARIOS.filter(model=>workspaceOf(model)===id);
    this.selectLabScenario(LAB_MODELS[workspace.defaultId]?workspace.defaultId:id==='web'?'basic-keycloak':models[0]?.id||'basic-keycloak');
  }
  openRoute(){
    if(!window.location)return;const hash=window.location.hash||'';
    const route=parseStudioRoute(hash,LAB_MODELS,LEARNING_PRESETS.map(preset=>preset.id));
    const variant=studioVariantId(route.scenarioId,LAB_MODELS,route.variantId||'default');
    if(!route.valid||route.scenarioId!==this.labScenarioId||variant!==this.lessonVariant||this.lessonSubfixture)this.selectLabScenario(route.scenarioId,{navigate:false,variant});
    if(!route.valid){if(window.history?.replaceState)window.history.replaceState(null,'',studioRoute(route.scenarioId,LAB_MODELS));this.notify('ui.link.unsupported','The lesson link has an unsupported selection ('+(route.reason||'unknown route')+'). Showing its safe default.',{reason:route.reason||'unknown route'});}
  }
  writeRoute(){
    const route=studioRoute(this.labScenarioId,LAB_MODELS,this.lessonVariant||'default');if(window.location&&window.location.hash!==route&&window.history?.pushState)window.history.pushState(null,'',route);
  }
  syncSharedNavigation(){
    this.workspace=workspaceOf(this.labModel);
    const workspace=STUDIO_WORKSPACES.find(item=>item.id===this.workspace),selected=this.workspaceOptions.find(option=>option.workspace===this.workspace&&option.family===this.family)||this.workspaceOptions.find(option=>option.id==='workspace-'+this.workspace);
    if(selected)this.workspacePicker.setSelected(selected.id);
    this.scenarioPicker.setSelected(this.labScenarioId);
    this.renderPickerHints();
  }
  renderWorkspace(){
    const workspace=STUDIO_WORKSPACES.find(item=>item.id===this.workspace),families=STUDIO_FAMILIES.filter(item=>item.workspace===this.workspace);
    this.querySelector('#quick-start').hidden=this.workspace!=='web';
    const panel=this.querySelector('#workspace-presets');panel.hidden=this.workspace==='web';
    const models=LAB_SCENARIOS.filter(model=>workspaceOf(model)===this.workspace&&(!families.length||model.family===this.family));
    const family=families.find(item=>item.id===this.family),defaultId=family?.defaultId||workspace.defaultId;
    const starters=models.filter(model=>model.featured||model.id===defaultId||model.id==='lab-kc-kerberos-sso');
    panel.innerHTML='<p>'+this.ui('ui.app.renderWorkspace.chooseJourney','Choose a ready-made journey, then press Play. Search the full catalog for failure paths and comparisons.')+'</p><div class="workspace-preset-grid">'+(starters.length?starters:models.slice(0,4)).slice(0,6).map(model=>'<button class="quick-preset" data-lab-scenario="'+escapeHtml(model.id)+'" aria-pressed="'+(model.id===this.labScenarioId)+'"><strong>'+this.prose('lesson:'+model.id,'title',model.title,{scenarioId:model.id,variantId:'default',subfixtureId:null})+'</strong><span>'+this.prose('lesson:'+model.id,'summary',model.summary,{scenarioId:model.id,variantId:'default',subfixtureId:null})+'</span></button>').join('')+'</div>';
    const internals=!!Object.values(this.scenarioOwnedActors||{}).some(actor=>actor.parentId);this.querySelector('#internals-control').hidden=!internals;this.querySelector('#show-internals').checked=this.showInternals;
    this.querySelectorAll('.zone-label').forEach(label=>label.hidden=this.workspace!=='web');
    this.refs.graph.classList.toggle('workspace-protocol',this.workspace!=='web');
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
    const grouped=STUDIO_FAMILIES.some(family=>family.workspace===this.workspace),query=this.catalogQuery;
    const rows=query.trim()?filterScenarioOptions(this.scenarioPicker.options,query,this.localizer):LAB_SCENARIOS.filter(model=>workspaceOf(model)===this.workspace&&(!grouped||model.family===this.family)).map(model=>this.scenarioOptionsById.get(model.id)).filter(Boolean);
    this.catalogResultsById=new Map(rows.map(row=>[row.id,row]));
    this.refs['lab-cards'].innerHTML=rows.map(row=>{
      const owner='lesson:'+row.id,context={scenarioId:row.id,variantId:'default',subfixtureId:null};
      const caseLabel=!row.caseLabel?'':Array.isArray(row.matchingVariantIds)?this.ui('ui.app.renderCatalog.matchingCases',row.matchingVariantIds.length+' matching cases',{count:row.matchingVariantIds.length}):this.prose(owner,'searchVariants.label',row.caseLabel,{...context,variantId:row.variantId||'default'});
      return '<button class="lab-card '+(row.id===this.labScenarioId?'is-selected':'')+'" data-lab-scenario="'+escapeHtml(row.id)+'" aria-pressed="'+(row.id===this.labScenarioId)+'"><span class="lab-card-category">'+this.prose(owner,'category',row.category,context)+'</span><strong>'+this.prose(owner,'title',row.title,context)+'</strong><p>'+this.prose(owner,'summary',row.summary,context)+'</p>'+(row.profileLabel?'<span class="lab-card-profile">'+this.ltr(row.profileLabel)+'</span>':'')+(caseLabel?'<span class="lab-card-case">'+caseLabel+'</span>':'')+'<span class="lab-card-status">'+(row.status?this.prose(owner,'status',row.status,context):this.ui('ui.app.renderCatalog.configuredLesson','Configured lesson'))+'</span></button>';
    }).join('')||'<p class="empty-state">'+this.ui('ui.app.renderCatalog.empty','No matching scenarios.')+'</p>';
    if(returnTarget)this.restoreTargetFocus(returnTarget,{fallbackSelector:'#lab-scenario-search'});
  }
  renderLabSupport() {
    const model=this.labModel,panel=this.refs['lab-support'];panel.hidden=!model;
    this.querySelector('#lesson-reference').hidden=!model;
    if(!model){panel.innerHTML='';return;}
    panel.dataset.level=/reference|experimental|legacy|deprecated|discouraged|preview|standard.*only/i.test(model.status)?'special':'supported';
    const owner='lesson:'+model.id;
    panel.innerHTML='<div><span class="lab-support-badge">'+this.prose(owner,'status',model.status)+'</span><strong>'+this.prose(owner,'category',model.category)+'</strong><p>'+this.prose(owner,'supportNote',model.supportNote)+'</p></div><a href="'+escapeHtml(model.source)+'" target="_blank" rel="noopener noreferrer">'+this.ui('ui.app.renderLabSupport.text.0180','Primary documentation')+'</a>';
  }
  renderLearningProfile(){
    const model=this.labModel,profile=model?.profile,panel=this.querySelector('#learning-profile'),owner=model?'lesson:'+model.id:null;
    const starting=profile?.startingSummary||model?.prerequisites?.slice(0,2);
    const compact=this.presentationMode==='compact',actors=[...new Set(this.steps.flatMap(step=>compact?[step.from,step.to]:[this.nodeId(step.from),this.nodeId(step.to)]))].map(id=>compact?this.studyActor(id).name:this.actor(id).name);
    const question=this.querySelector('#learning-question');
    if(model?.learningObjective)question.innerHTML=this.prose(owner,'learningObjective',model.learningObjective);
    else{
      const preset=this.learningPreset,flow=preset?.title?null:this.advancedFlow,mode=preset?.title||flow?.title?null:modeMetadata[this.mode];
      const title=preset?.title||flow?.title||mode?.title;
      const titleOwner='lesson:'+(preset?.title?preset.id:flow?.title?(flow.id||this.oidcFlow):this.mode);
      question.innerHTML=title?this.rich('ui.app.renderLearningProfile.question','What establishes trust during {title}?',{title:{kind:'human',value:{ownerId:titleOwner,fieldPath:'title',source:title,context:this.localeContext()}}}):this.ui('ui.app.renderLearningProfile.questionDefault','What establishes trust during this journey?');
    }
    const start=this.querySelector('#learning-start');
    if(starting){
      const source=Array.isArray(starting)?starting.join(' '):starting;
      const fieldPath=profile?.startingSummary?(Array.isArray(starting)?'profile.startingSummary.joined':'profile.startingSummary'):'prerequisites.startingSummary';
      start.innerHTML=this.rich('ui.app.renderLearningProfile.startSummary','Start: {summary}',{summary:{kind:'human',value:{ownerId:owner,fieldPath,source,context:this.localeContext({binding:fieldPath,semanticRole:'starting-credentials-and-trust'})}}});
    }else{
      const preset=this.learningPreset,names=actors.join(' · ');
      start.innerHTML=preset?.summary?this.rich('ui.app.renderLearningProfile.startActorsSummary','Start: {actors} - {summary}',{actors:{kind:'protected',value:names},summary:{kind:'human',value:{ownerId:'lesson:'+preset.id,fieldPath:'summary',source:preset.summary,context:this.localeContext()}}}):this.rich('ui.app.renderLearningProfile.startActors','Start: {actors}',{actors:{kind:'protected',value:names}});
    }
    const lastStep=this.steps.at(-1),completion=profile?.completion||lastStep?.summary;
    const completionRef=profile?.completion?{ownerId:owner,fieldPath:'profile.completion',source:profile.completion,context:this.localeContext()}:lastStep?.summary?{ownerId:'step:'+(lastStep.sourceStepId||lastStep.id),fieldPath:'summary',source:lastStep.summary,context:this.localeContext()}:null;
    this.querySelector('#learning-boundary').innerHTML=(profile?'<span class="profile-pin">'+this.ltr(profile.name===model.title?model.protocol||profile.name:profile.name)+' · '+this.ltr(profile.version)+'</span>':'')+'<p>'+(completion?this.rich('ui.app.renderLearningProfile.finish','Finish: {completion}',{completion:{kind:'human',value:completionRef}}):this.ui('ui.app.renderLearningProfile.finishDefault','Finish: Follow the authored outcome and its acceptance boundary.'))+'</p>';
    this.renderLessonInputs();
    panel.hidden=!profile;
    this.renderWindowsSecurityComparison();
    if(!profile)return;
    const assumptions=[],seenAssumptions=new Set();
    for(const [fieldPath,items] of [['prerequisites',model.prerequisites||[]],['profile.assumptions',profile.assumptions||[]]])for(const item of items){
      if(seenAssumptions.has(item))continue;seenAssumptions.add(item);
      assumptions.push({source:item,fieldPath,context:{binding:fieldPath,semanticRole:'starting-credentials-and-trust'}});
    }
    this.querySelector('#learning-profile-content').innerHTML='<div class="profile-badges"><span>'+this.ltr(profile.name)+' · '+this.ltr(profile.version)+'</span><span>'+this.ltr(profile.publicationStatus)+'</span><span>'+this.ltr(profile.supportStatus)+'</span></div><h2>'+this.prose(owner,'learningObjective',model.learningObjective)+'</h2><p>'+this.prose(owner,'profile.implementation',profile.implementation)+'</p><dl class="profile-boundaries"><dt>'+this.ui('ui.app.renderLearningProfile.text.0182','Starting credentials and trust')+'</dt><dd><ul>'+assumptions.map(item=>'<li>'+this.prose(owner,item.fieldPath,item.source,item.context)+'</li>').join('')+'</ul></dd><dt>'+this.ui('ui.app.renderLearningProfile.text.0183','Completion means')+'</dt><dd>'+this.prose(owner,'profile.completion',profile.completion)+'</dd><dt>'+this.ui('ui.app.renderLearningProfile.text.0184','Transport profile')+'</dt><dd>'+(profile.transports||[]).map(transport=>this.ltr(transport)).join(' · ')+'</dd></dl>'+(model.threatExplanation?'<p class="profile-threat">'+this.prose(owner,'threatExplanation',model.threatExplanation)+'</p>':'');
    panel.querySelectorAll('[data-learning-detail]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.learningDetail===this.learningDetail)));
    const crypto=this.querySelector('#learning-profile-crypto');crypto.hidden=this.learningDetail!=='crypto';
    const cryptoProseFields=['numericalVerification','clock','encoded','binding.publicKeyEncoding'];
    const cryptoAnnotations=this.localizer.locale==='en'||!profile.cryptoDetail||typeof profile.cryptoDetail!=='object'?'':cryptoProseFields.map(path=>{
      const value=path.split('.').reduce((item,key)=>item?.[key],profile.cryptoDetail);
      return typeof value==='string'?'<p>'+this.prose(owner,'profile.cryptoDetail.'+path,value)+'</p>':'';
    }).join('');
    const cryptoDetail=profile.cryptoDetail!==null&&typeof profile.cryptoDetail==='object'?'<pre '+this.rawValueAttrs(formatProtocolValue(profile.cryptoDetail))+'>'+escapeHtml(formatProtocolValue(profile.cryptoDetail))+'</pre>'+cryptoAnnotations:'<p>'+this.prose(owner,'profile.cryptoDetail',formatProtocolValue(profile.cryptoDetail))+'</p>';
    crypto.innerHTML='<h3>'+this.ui('ui.app.renderLearningProfile.text.0185','Exact parameters and source boundary')+'</h3>'+cryptoDetail+'<pre '+this.rawValueAttrs(formatProtocolValue(profile.algorithms))+'>'+escapeHtml(formatProtocolValue(profile.algorithms))+'</pre><ul class="profile-sources">'+(profile.sources||[]).map(source=>{
      const sourceContext={binding:'profile.sources:'+JSON.stringify([source.url,source.standard,source.section])};
      return '<li><a href="'+escapeHtml(source.url)+'" target="_blank" rel="noopener noreferrer">'+this.ltr(source.standard)+' · '+this.ltr(source.section)+'</a><span>'+this.rich('ui.app.renderLearningProfile.sourceRevision','Revision {revision} · retrieved {retrieved}',{revision:{kind:'protected',value:source.revision??''},retrieved:{kind:'protected',value:source.retrieved??''}})+'</span><span>'+this.prose(owner,'profile.sources.errata',source.errata,sourceContext)+'</span></li>';
    }).join('')+'</ul>';
    const linuxComparison=['macos-logon','macos-elevation'].includes(model.family)?[{id:'lab-pam01',title:'Linux-PAM comparison, not a macOS stack',summary:'Open the separately authored Linux service configuration. This does not claim macOS uses these modules, files or controls.'}]:[];
    const related=this.querySelector('#related-journeys'),seen=new Set(),lessons=[...(model.relatedLessons||[]).map(lesson=>({lesson,sourceOrigin:'authored'})),...windowsSecurityRelatedLessons(model.id).map(lesson=>({lesson,sourceOrigin:'windows-security'})),...linuxComparison.map(lesson=>({lesson,sourceOrigin:'macos-linux-comparison'}))].filter(({lesson})=>{
      if(!LAB_MODELS[lesson?.id])return false;
      try{studioVariantId(lesson.id,LAB_MODELS,lesson.variantId||'default');}catch{return false;}
      const key=lesson.id+'|'+(lesson.variantId||'default');if(seen.has(key))return false;seen.add(key);return true;
    });related.hidden=!lessons.length;
    related.innerHTML=lessons.map(({lesson,sourceOrigin})=>{
      const context={binding:'relatedLessons:'+lesson.id+'|'+(lesson.variantId||'default'),sourceOrigin,targetScenarioId:lesson.id,targetVariantId:lesson.variantId||'default'};
      const title=sourceOrigin==='macos-linux-comparison'?this.ui('ui.app.renderLearningProfile.linuxComparisonTitle','Linux-PAM comparison, not a macOS stack',{pam:'Linux-PAM',macos:'macOS'}):this.prose(owner,'relatedLessons.title',lesson.title,context);
      const summary=sourceOrigin==='macos-linux-comparison'?this.ui('ui.app.renderLearningProfile.linuxComparisonSummary','Open the separately authored Linux service configuration. This does not claim macOS uses these modules, files or controls.',{linux:'Linux',macos:'macOS'}):this.prose(owner,'relatedLessons.summary',lesson.summary,context);
      return '<button class="related-journey" data-compare-scenario="'+escapeHtml(lesson.id)+'"'+(lesson.variantId?' data-compare-variant="'+escapeHtml(lesson.variantId)+'"':'')+'><strong>'+title+'</strong><span>'+summary+'</span></button>';
    }).join('');
  }
  renderWindowsSecurityComparison(){
    const panel=this.querySelector('#windows-security-comparison'),model=this.labModel;
    panel.hidden=!(model&&(workspaceOf(model)==='windows'||['windows-logon','windows-elevation'].includes(model.family)));
    if(panel.hidden)return;
    const key=JSON.stringify([model.id,this.localizer.revision]);if(this.windowsComparisonKey===key)return;this.windowsComparisonKey=key;
    this.querySelector('#windows-security-comparison-rows').innerHTML=WINDOWS_SECURITY_COMPARISONS.map(row=>{
      const owner='windows-security-comparison:'+row.targets[0].id;
      return '<section class="security-comparison-row" data-study-key="'+escapeHtml(owner)+'"><h3 class="locale-prose" data-copy-disabled>'+this.prose(owner,'mechanism',row.mechanism,this.localeContext())+'</h3><p class="locale-prose" data-copy-disabled>'+this.prose(owner,'boundary',row.boundary,this.localeContext())+'</p><div>'+row.targets.filter(target=>{if(!LAB_MODELS[target.id])return false;try{studioVariantId(target.id,LAB_MODELS,target.variantId||'default');return true;}catch{return false;}}).map(target=>'<button class="button quiet locale-prose" data-study-key="security-comparison-target:'+escapeHtml(target.id)+':'+escapeHtml(target.variantId||'default')+'" data-copy-disabled data-compare-scenario="'+escapeHtml(target.id)+'"'+(target.variantId?' data-compare-variant="'+escapeHtml(target.variantId)+'"':'')+'>'+this.prose('lesson:'+target.id,'securityComparison.title',target.title,this.localeContext({scenarioId:target.id,variantId:target.variantId||'default',binding:'security-comparison-target:'+target.id+':'+(target.variantId||'default')}))+'</button>').join('')+'</div></section>';
    }).join('');
  }
  renderPamConfiguration(){
    const model=this.labModel,configuration=model?.pamConfiguration,panel=this.querySelector('#pam-configuration-panel');
    panel.hidden=!configuration;
    if(!configuration){this.pamRenderKey=null;panel.innerHTML='';return;}
    const snapshot=this.protocolSnapshot(),step=this.currentStep,cursor=snapshot?.cursor;
    const key=JSON.stringify([this.heldView.contextId,cursor,step?.id,this.localizer.revision]);
    if(this.pamRenderKey===key)return;this.pamRenderKey=key;
    const sourceId=step?.sourceStepId||step?.id,sourceIndex=this.steps.findIndex(row=>row.id===sourceId),sourceStep=this.steps[sourceIndex],declared=sourceStep?.pamEvaluation;
    const explanation=model.id!=='lab-pam01'&&(sourceStep?.pamRelatedLesson||(model.relatedLessons||[]).find(lesson=>lesson.id==='lab-pam01'));
    const completed=sourceIndex>=0&&cursor&&(cursor.eventIndex>sourceIndex||cursor.eventIndex===sourceIndex&&cursor.milestone==='complete');
    const readState=path=>path?.split('.').reduce((current,key)=>current&&Object.hasOwn(current,key)?current[key]:undefined,snapshot?.state);
    const canonical=readState(model.pamStatePaths?.evaluation);
    const evaluation=completed&&canonical&&declared&&canonical.configurationId===declared.configurationId&&canonical.line===declared.line&&canonical.apiPhase===declared.apiPhase&&canonical.flags===declared.flags?canonical:declared;
    const files=configuration.files||[],activeFile=files.find(file=>file.id===evaluation?.configurationId||file.file===evaluation?.file)||files[0],scope=configuration.assumption||model.fixture?.evidence;
    const phaseDescriptor=PAM_API_PHASES[evaluation?.apiPhase],phase=evaluation?.type||phaseDescriptor?.type;
    const rows=(activeFile?.text||'').split('\n').map((text,index)=>({text,line:index+1})).filter(row=>{
      if(!phase)return row.line===evaluation?.line;
      const tokens=row.text.trim().split(/\s+/),type=tokens[0]===configuration.service?tokens[1]:tokens[0];
      return type?.replace(/^-/,'')===phase||row.line===evaluation?.line;
    });
    const raw=item=>{const text=formatProtocolValue(item,true);return '<span '+this.rawValueAttrs(text)+'>'+this.ltr(text)+'</span>';};
    const value=item=>item===null||item===undefined?this.ui('ui.app.renderPamConfiguration.notApplicable','Not applicable at this boundary'):raw(item);
    const returned=(item,display=value)=>completed?display(item):this.ui('ui.app.renderPamConfiguration.pendingPrefix','Pending at the current source prefix');
    const stepProse=(field,item)=>item===null||item===undefined?value(item):this.prose('step:'+sourceId,'pamEvaluation.'+field,item,this.localeContext());
    const accumulator=item=>item===null||item===undefined?value(item):(item.impression==='undefined'?this.ui('ui.app.renderPamConfiguration.undecided','Undecided (undefined)',{impression:'undefined'}):raw(item.impression))+' / '+raw(item.status);
    const next=evaluation?.nextRow,nextLabel=next?(next.configurationId===evaluation.configurationId?this.ui('ui.app.renderPamConfiguration.nextLine','Line '+next.line,{line:next.line}):this.ui('ui.app.renderPamConfiguration.nextFileLine','Line '+next.line+' in '+next.configurationId,{line:next.line,configurationId:next.configurationId})):value(null);
    const phaseLabels={
      start:()=>this.ui('ui.app.renderPamConfiguration.phase.start','Transaction initialization'),
      authenticate:()=>this.ui('ui.app.renderPamConfiguration.phase.authenticate','Authentication'),
      account:()=>this.ui('ui.app.renderPamConfiguration.phase.account','Account admission'),
      password:()=>this.ui('ui.app.renderPamConfiguration.phase.password','Required token change'),
      prelim:()=>this.ui('ui.app.renderPamConfiguration.phase.prelim','Preliminary token check'),
      update:()=>this.ui('ui.app.renderPamConfiguration.phase.update','Token update'),
      setcred:()=>this.ui('ui.app.renderPamConfiguration.phase.setcred','Module credential lifecycle'),
      open:()=>this.ui('ui.app.renderPamConfiguration.phase.open','Session setup'),
      close:()=>this.ui('ui.app.renderPamConfiguration.phase.close','Session teardown'),
      end:()=>this.ui('ui.app.renderPamConfiguration.phase.end','Transaction cleanup'),
      conversation:()=>this.ui('ui.app.renderPamConfiguration.phase.conversation','Application conversation callback'),
      caller:()=>this.ui('ui.app.renderPamConfiguration.phase.caller','Caller operation or decision'),
      configuration:()=>this.ui('ui.app.renderPamConfiguration.phase.configuration','Configuration comparison'),
      limits:()=>this.ui('ui.app.renderPamConfiguration.phase.limits','Observed resource limits'),
      cleanup:()=>this.ui('ui.app.renderPamConfiguration.phase.cleanup','Partial local resource cleanup'),
      'password-change':()=>this.ui('ui.app.renderPamConfiguration.phase.passwordChange','Caller token-change capability'),
      'delete-credentials':()=>this.ui('ui.app.renderPamConfiguration.phase.deleteCredentials','Credential-phase bookkeeping cleanup')
    };
    const phaseHtml=phaseDescriptor?.label?phaseLabels[evaluation?.apiPhase]?.()||raw(phaseDescriptor.label):value(phase);
    const apiSource=evaluation?.api||phaseDescriptor?.api||phaseDescriptor?.label||evaluation?.apiPhase;
    const apiHtml=[apiSource?(evaluation?.api||phaseDescriptor?.api?raw(apiSource):phaseHtml):'',evaluation?.flags!==null&&evaluation?.flags!==undefined?raw(evaluation.flags):''].filter(Boolean).join(' / ');
    const evaluationRows=evaluation?[
      [phaseDescriptor?.internal?this.ui('ui.app.renderPamConfiguration.internalFlags','Internal module dispatch / flags'):this.ui('ui.app.renderPamConfiguration.apiFlags','API call / flags'),apiHtml||value(null)],
      [this.ui('ui.app.renderPamConfiguration.phase','PAM phase'),phaseHtml],
      [this.ui('ui.app.renderPamConfiguration.moduleHook','Module hook'),value(evaluation.moduleHook)],
      [this.ui('ui.app.renderPamConfiguration.hookCalled','Hook called'),completed?value(evaluation.hookCalled):this.ui('ui.app.renderPamConfiguration.notReturned','Not returned at this prefix')],
      [this.ui('ui.app.renderPamConfiguration.rawReturn','Raw hook or loader return'),returned(evaluation.rawReturn)],
      [this.ui('ui.app.renderPamConfiguration.controlStatus','Control status'),returned(evaluation.controlStatus)],
      [this.ui('ui.app.renderPamConfiguration.mappedAction','Mapped control action'),returned(evaluation.mappedAction)],
      [this.ui('ui.app.renderPamConfiguration.accumulatorBefore','Accumulator before'),accumulator(evaluation.accumulatorBefore)],
      [this.ui('ui.app.renderPamConfiguration.accumulatorAfter','Accumulator after'),returned(evaluation.accumulatorAfter,accumulator)],
      [this.ui('ui.app.renderPamConfiguration.depth','Substack depth'),value(evaluation.depth)],
      [this.ui('ui.app.renderPamConfiguration.nextRow','Next row'),completed?nextLabel:this.ui('ui.app.renderPamConfiguration.pendingPrefix','Pending at the current source prefix')],
      [this.ui('ui.app.renderPamConfiguration.skipReason','Skip / stop reason'),returned(evaluation.skipStopReason,item=>stepProse('skipStopReason',item))],
      ...(evaluation.apiPending?[[this.ui('ui.app.renderPamConfiguration.aggregateReturn','API aggregate return'),this.ui('ui.app.renderPamConfiguration.apiPending','Pending: current API call has not completed')]]:Object.hasOwn(evaluation,'aggregateReturn')?[[this.ui('ui.app.renderPamConfiguration.aggregateReturn','API aggregate return'),returned(evaluation.aggregateReturn)]]:[]),
    ]:[];
    const expanded=new Set([...panel.querySelectorAll('details[open]')].map(details=>details.dataset.pamDisclosure));
    const focused=panel.contains(document.activeElement)?document.activeElement.closest('[data-pam-disclosure]')?.dataset.pamDisclosure:null;
    const results=readState(model.pamStatePaths?.results),resultGroups={public:{},internal:{},pending:{}};
    for(const [resultPhase,status] of Object.entries(results||{})){
      const group=status==='not evaluated'?'pending':PAM_API_PHASES[resultPhase]?.internal?'internal':'public';
      resultGroups[group][resultPhase]=status;
    }
    panel.innerHTML='<h3 class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.heading','PAM configuration → current evaluation')+'</h3><p class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.service','Service:')+' <strong>'+raw(configuration.service)+'</strong> · '+(configuration.revision?raw(configuration.revision):this.ui('ui.app.renderPamConfiguration.pinnedProfile','Pinned Linux-PAM learning profile'))+'</p>'+
      (scope?'<p class="environment-note locale-prose" data-copy-disabled>'+this.prose('lesson:'+model.id,configuration.assumption?'pamConfiguration.assumption':'fixture.evidence',scope,this.localeContext())+'</p>':'')+
      (configuration.settings?'<p class="pam-boundary-note locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.callerSettings','Selected caller settings:')+' '+Object.entries(configuration.settings).map(([name,item])=>'<code '+this.rawValueAttrs(name)+'>'+this.ltr(name)+'</code> = '+value(item)).join('; ')+'</p>':'')+
      (evaluation?'<p class="pam-active-location locale-prose" data-copy-disabled>'+(evaluation.line?this.ui('ui.app.renderPamConfiguration.physicalLine','Physical line '+evaluation.line+' in '+(evaluation.file||activeFile?.file),{line:evaluation.line,file:evaluation.file||activeFile?.file}):this.ui('ui.app.renderPamConfiguration.callerBoundary','Caller/API boundary: no module line'))+' · '+(apiHtml||this.ui('ui.app.renderPamConfiguration.noPhase','No module API phase'))+'</p>':'<p class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.notEvaluation','This step is not a PAM module evaluation. No module hook or stack result is implied.')+'</p>')+
      (evaluation?.inapplicable?'<p class="pam-boundary-note locale-prose" data-copy-disabled>'+stepProse('inapplicable',evaluation.inapplicable)+'</p>':'')+
      (rows.length?'<ol class="pam-source-lines" data-technical-ltr dir="ltr" aria-label="'+escapeHtml(this.uiText('ui.app.renderPamConfiguration.currentPhaseConfiguration','Current PAM phase configuration'))+'">'+rows.map(row=>'<li value="'+row.line+'" data-pam-line="'+row.line+'"'+(row.line===evaluation?.line?' aria-current="step"':'')+'><span class="locale-prose" data-copy-disabled>'+(row.line===evaluation?.line?this.ui('ui.app.renderPamConfiguration.currentLine','Current line '+row.line+': ',{line:row.line}):this.ui('ui.app.renderPamConfiguration.line','Line '+row.line+': ',{line:row.line}))+'</span><code '+this.rawValueAttrs(row.text)+'>'+this.ltr(row.text)+'</code></li>').join('')+'</ol>':'')+
      (declared?.resourceConfiguration?'<section class="pam-resource-configuration" data-study-key="pam-resource-configuration" aria-label="'+escapeHtml(this.uiText('ui.app.renderPamConfiguration.resourceBoundary','Resource limits, separate from PAM control'))+'"><h4 class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.resourceLimits','Soft / hard resource limits - not PAM control')+'</h4><p>'+raw(declared.resourceConfiguration.file)+'</p><ol class="pam-source-lines" data-technical-ltr dir="ltr">'+declared.resourceConfiguration.rows.map(row=>'<li value="'+row.line+'" data-pam-resource-line="'+row.line+'"><span class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.resourceLine','Resource line '+row.line+': ',{line:row.line})+'</span><code '+this.rawValueAttrs(row.text)+'>'+this.ltr(row.text)+'</code></li>').join('')+'</ol><p class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.applicationResult','Application result:')+' '+(completed?stepProse('resourceConfiguration.applicationResult',declared.resourceConfiguration.applicationResult):this.ui('ui.app.renderPamConfiguration.pendingPrefix','Pending at the current source prefix'))+'</p></section>':'')+
      (evaluationRows.length?'<dl class="pam-evaluation">'+evaluationRows.map(([label,item])=>'<div><dt class="locale-prose" data-copy-disabled>'+label+'</dt><dd class="locale-prose" data-copy-disabled>'+item+'</dd></div>').join('')+'</dl>':'')+
      (configuration.comparison?'<details data-pam-disclosure="comparison" data-study-key="pam-comparison"'+(expanded.has('comparison')?' open':'')+'><summary class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.compareControl','Compare the changed PAM control line')+'</summary><pre data-technical-ltr '+this.rawValueAttrs(formatProtocolValue(configuration.comparison))+'>'+escapeHtml(formatProtocolValue(configuration.comparison))+'</pre></details>':'')+
      (explanation&&LAB_MODELS[explanation.id]?'<button class="button quiet locale-prose" data-study-key="pam-related-lesson" data-copy-disabled data-compare-scenario="'+escapeHtml(explanation.id)+'"'+(explanation.variantId?' data-compare-variant="'+escapeHtml(explanation.variantId)+'"':'')+'>'+(sourceStep?.pamRelatedLesson?this.prose('step:'+sourceId,'pamRelatedLesson.title',explanation.title,this.localeContext()):this.prose('lesson:'+model.id,'relatedLessons.title',explanation.title,this.localeContext({binding:'relatedLessons:'+explanation.id})))+'</button>':'')+
      '<p class="pam-boundary-note locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.separateDecisions','A module return, the PAM aggregate, and application admission are separate decisions. The identity and admission decisions above use the current canonical source prefix.')+'</p>'+
      (results?[
        ['aggregates',this.ui('ui.app.renderPamConfiguration.completedAggregates','Completed API aggregate results'),'public'],
        ['password-dispatch',this.ui('ui.app.renderPamConfiguration.passwordDispatch','Internal password dispatch results'),'internal'],
        ['pending-results',this.ui('ui.app.renderPamConfiguration.pendingResults','Pending / not-started results'),'pending']
      ].map(([id,label,group])=>'<details data-pam-disclosure="'+id+'" data-study-key="pam-'+id+'"'+(expanded.has(id)?' open':'')+'><summary class="locale-prose" data-copy-disabled>'+label+'</summary>'+(group==='internal'?'<p class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.internalPasses','prelim and update are internal passes inside the enclosing pam_chauthtok call, not separate application calls.',{prelim:'prelim',update:'update',api:'pam_chauthtok'})+'</p>':'')+'<pre data-technical-ltr '+this.rawValueAttrs(formatProtocolValue(resultGroups[group]))+'>'+escapeHtml(formatProtocolValue(resultGroups[group]))+'</pre></details>').join(''):'')+
      '<details data-pam-disclosure="configuration" data-study-key="pam-configuration"'+(expanded.has('configuration')?' open':'')+'><summary class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.completeFiles','Complete configuration files and include tree')+'</summary>'+files.map(file=>'<section data-study-key="pam-file:'+escapeHtml(file.id||file.file)+'"><h4>'+raw(file.file||file.id)+'</h4><p class="pam-file-hash">'+this.ltr('SHA-256')+' <code '+this.rawValueAttrs(file.sha256)+'>'+this.ltr(file.sha256)+'</code></p><pre data-technical-ltr '+this.rawValueAttrs(file.text)+'>'+escapeHtml(file.text)+'</pre></section>').join('')+'<h4 class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderPamConfiguration.includeTree','Include / substack tree')+'</h4><pre data-technical-ltr '+this.rawValueAttrs(formatProtocolValue(configuration.includeTree))+'>'+escapeHtml(formatProtocolValue(configuration.includeTree))+'</pre></details>';
    if(focused)[...panel.querySelectorAll('[data-pam-disclosure]')].find(details=>details.dataset.pamDisclosure===focused)?.querySelector('summary')?.focus({preventScroll:true});
  }
  renderLessonInputs(){
    const model=this.labModel,panel=this.querySelector('#lesson-inputs'),cases=model?.variantChoices||[],controls=model?.profileControls||[],members=model?.subfixtureChoices||[];
    const selected=cases.find(choice=>choice.id===(this.lessonVariant||'default')),member=members.find(choice=>choice.id===(this.lessonSubfixture||model.subfixtureId||model.defaultSubfixtureId||members[0]?.id)),caseLabel=this.querySelector('#current-lesson-case');
    const owner='lesson:'+model?.id;
    const caseRef=choice=>({ownerId:owner,fieldPath:'searchVariants.label',source:choice.label,context:this.localeContext({variantId:choice.id,binding:'searchVariants:'+choice.id})});
    const memberRef=choice=>({ownerId:owner,fieldPath:'subfixtureChoices.label',source:choice.label,context:this.localeContext({subfixtureId:choice.id,binding:'subfixtureChoices:'+choice.id})});
    caseLabel.hidden=!(cases.length>1&&selected);
    caseLabel.classList.add('locale-prose');caseLabel.setAttribute('data-copy-disabled','');caseLabel.dataset.studyKey='current-lesson-case';
    caseLabel.innerHTML=selected?(members.length>1&&member?this.ui('ui.app.renderLessonInputs.currentCaseWithProfile','Case: '+selected.label+' ('+selected.id+') · '+member.label,{case:caseRef(selected),id:selected.id,profile:memberRef(member)}):this.ui('ui.app.renderLessonInputs.currentCase','Case: '+selected.label+' ('+selected.id+')',{case:caseRef(selected),id:selected.id})):'';
    panel.hidden=cases.length<2&&!controls.length&&members.length<2;
    if(panel.hidden){panel.innerHTML='';return;}
    const profiles=controls.map(control=>'<label class="select-field" data-study-key="profile-control:'+escapeHtml(control.id)+'" for="lesson-profile-'+escapeHtml(control.id)+'"><span class="locale-prose" data-copy-disabled>'+this.prose(owner,'profileControls.label',control.label,this.localeContext({binding:'profileControls:'+control.id}))+'</span><select class="locale-prose" data-copy-disabled id="lesson-profile-'+escapeHtml(control.id)+'" data-profile-control="'+escapeHtml(control.id)+'">'+control.options.map(option=>'<option value="'+escapeHtml(option.value)+'" '+(option.value===control.value?'selected':'')+'>'+escapeHtml(this.proseText(owner,'profileControls['+control.id+'].options.label',option.label,this.localeContext({binding:'profileControls['+control.id+'].options:'+option.value})))+'</option>').join('')+'</select></label>').join('');
    const caseControl=cases.length>1?'<label class="select-field" data-study-key="lesson-case-control" for="lesson-case"><span class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderLessonInputs.text.0186','Compare a case')+'</span><select class="locale-prose" data-copy-disabled id="lesson-case">'+cases.map(choice=>'<option value="'+escapeHtml(choice.id)+'" '+(choice.id===(this.lessonVariant||'default')?'selected':'')+'>'+escapeHtml(this.proseText(owner,'searchVariants.label',choice.label,this.localeContext({variantId:choice.id,binding:'searchVariants:'+choice.id})))+'</option>').join('')+'</select></label>':'';
    const comparison=members.length>1?'<label class="select-field" data-study-key="lesson-subfixture-control" for="lesson-subfixture"><span class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderLessonInputs.comparisonProfile','Comparison profile')+'</span><select class="locale-prose" data-copy-disabled id="lesson-subfixture">'+members.map(choice=>'<option value="'+escapeHtml(choice.id)+'"'+(choice.id===member?.id?' selected':'')+'>'+escapeHtml(this.proseText(owner,'subfixtureChoices.label',choice.label,this.localeContext({subfixtureId:choice.id,binding:'subfixtureChoices:'+choice.id})))+'</option>').join('')+'</select></label><p class="environment-note locale-prose" data-copy-disabled>'+this.ui('ui.app.renderLessonInputs.localInputs','These comparison inputs stay local. Lesson/case links reopen this named case at its default profile.')+'</p>':'';
    const ordinaryShare=model?.id==='lab-wra01'&&selected?.id==='default-filtered'?'<button class="button quiet locale-prose" data-study-key="ordinary-share-comparison" data-copy-disabled data-compare-scenario="lab-wra01" data-compare-variant="ordinary-share-allowed" title="'+escapeHtml(this.uiText('ui.app.renderLessonInputs.ordinaryShareTitle','Start the ordinary-share case at its default profile'))+'">'+this.ui('ui.app.renderLessonInputs.ordinaryShare','Compare an ordinary share instead')+'</button>':'';
    panel.innerHTML='<div id="lesson-input-controls" class="lesson-profile-controls"><h3 class="locale-prose" data-copy-disabled>'+(selected?this.ui('ui.app.renderLessonInputs.supportedProfileCase','Case / supported profile - '+selected.id,{id:selected.id}):this.ui('ui.app.renderLessonInputs.supportedProfile','Case / supported profile'))+'</h3><div class="lesson-profile-control-list">'+caseControl+ordinaryShare+profiles+comparison+'</div></div>';
  }
  environmentFields(model=this.labModel) {
    if(model?.workspace){const wanted=new Set((model.runtimeBindings||[]).map(binding=>binding.field));return RUNTIME_ENVIRONMENT_FIELDS.filter(field=>wanted.has(field.key)).map(field=>({...field,path:field.key}));}
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
    const input=field=>{const helpId='environment-help-'+field.path.replaceAll('.','-'),context={phase:'environment-fields',fieldPath:field.path};return `<label class="environment-field"><span>${this.prose('environment-field:'+field.path,'label',field.label,context)}</span><input type="text" dir="ltr" translate="no" data-environment-field="${field.path}" value="${escapeHtml(field.path.startsWith('provider.')?provider[field.key]||'':draft[field.key]||'')}" placeholder="${escapeHtml(this.uiText("ui.app.renderEnvironmentFields.attribute.0187","Keep the example value"))}" autocomplete="off" spellcheck="false" aria-invalid="false" aria-describedby="environment-errors${field.note?' '+helpId:''}">${field.note?`<small id="${helpId}">${this.prose('environment-field:'+field.path,'note',field.note,context)}</small>`:''}</label>`;};
    const fields=this.environmentFields();
    this.refs['environment-fields'].innerHTML='<div class="environment-grid">'+fields.filter(field=>!field.advanced).map(input).join('')+'</div><details class="environment-advanced" data-study-key="environment-advanced"><summary>'+this.ui('ui.environment.advanced.title','Exact endpoints & identifiers')+'</summary><p class="environment-note">'+this.ui('ui.environment.advanced.note','An issuer, an endpoint, a client_id and a SAML entityID are separate values. External endpoints stay explicit; an arbitrary issuer does not determine their paths.')+'</p><div class="environment-grid">'+fields.filter(field=>field.advanced).map(input).join('')+'</div></details>';
    this.refs['environment-status'].innerHTML=this.runtimeEnvironment.active?this.ui('ui.environment.status.active','Your environment is active for this open page.'):this.ui('ui.environment.status.example','Using example addresses.');
  }
  applyEnvironment() {
    // Read the immutable base registry, not a reconstruction of the current
    // applied model: even a constructor failure must leave correction possible.
    const registry=this.baseLabModel,base=this.lessonVariant!=='default'&&registry?.withVariant?registry.withVariant(this.lessonVariant):registry,fields=this.environmentFields(base),options={...this.environmentOptionsFor(base),activeFields:fields.map(field=>field.path)};
    this.refs['environment-fields'].querySelectorAll('[data-environment-field]').forEach(field=>{const key=field.dataset.environmentField;this.runtimeEnvironment.updateDraft(key.startsWith('provider.')?{provider:{[key.slice(9)]:field.value}}:{[key]:field.value},{profileId:this.providerProfile.id});});
    const result=this.runtimeEnvironment.apply(options,base?.contextualize?(context,metadata)=>base.contextualize(context,metadata):null),errors=this.refs['environment-errors'];
    const validationFactories=new Map([
      ["Use a value without control characters.", {key:"ui.environment.validation.controlCharacters", params:{}}],
      ["Use a value of at most 2048 characters.", {key:"ui.environment.validation.maximumLength", params:{"limit":2048}}],
      ["Use a DNS host name without a URL scheme, port or path.", {key:"ui.environment.validation.hostName", params:{}}],
      ["Use a Unix account name such as alice.", {key:"ui.environment.validation.account", params:{"example":"alice"}}],
      ["Use a named path segment.", {key:"ui.environment.validation.namedSegment", params:{}}],
      ["Use an absolute URI, such as https://… or urn:….", {key:"ui.environment.validation.absoluteUri", params:{"https":"https://…","urn":"urn:…"}}],
      ["Use a complete HTTPS URL.", {key:"ui.environment.validation.httpsUrl", params:{}}],
      ["Use an identifier URI such as https://… or urn:….", {key:"ui.environment.validation.identifierUri", params:{"https":"https://…","urn":"urn:…"}}],
      ["Use an address without embedded credentials.", {key:"ui.environment.validation.credentials", params:{}}],
      ["Use HTTPS; native callbacks may use HTTP on localhost.", {key:"ui.environment.validation.https", params:{"https":"HTTPS","http":"HTTP","host":"localhost"}}],
      ["Use an address without a fragment.", {key:"ui.environment.validation.fragment", params:{}}],
      ["Use an issuer or deployment address without a query.", {key:"ui.environment.validation.query", params:{}}],
      ["This lab accepts a Kerberos realm of 1-254 letters, digits, dots, underscores or hyphens, starting with a letter or digit (for example CORP.EXAMPLE).", {key:"ui.environment.validation.kerberosRealm", params:{"protocol":"Kerberos","range":"1-254","example":"CORP.EXAMPLE"}}],
      ["Use a lab service principal such as HTTP/server.corp.example or HTTP/server.corp.example@CORP.EXAMPLE. Escaped principal names are outside this lab input contract.", {key:"ui.environment.validation.servicePrincipal", params:{"example":"HTTP/server.corp.example","qualifiedExample":"HTTP/server.corp.example@CORP.EXAMPLE"}}],
      ["Could not rebuild the animation from these example values. Check this field and try again; your previous animation is unchanged.", {key:"ui.environment.validation.rebuild", params:{}}]
    ]);
    const validationMessage=message=>{
      const known=validationFactories.get(message);if(known)return {key:known.key,source:message,params:known.params};
      const realm=message.match(/^The service realm qualifier must match the account Kerberos realm \(([^)]+)\)\. Use the separate cross-realm lessons for a service in another realm\.$/);
      return realm?{key:'ui.environment.validation.serviceRealm',source:message,params:{realm:realm[1]}}:null;
    };
    errors.hidden=result.ok;errors.innerHTML=result.ok?'':Object.entries(result.errors).map(([key,message])=>{
      const field=fields.find(field=>field.path===key),validation=validationMessage(message)||{ownerId:'environment-validation',fieldPath:'message',source:message,context:{fieldPath:key}};
      const label=field?{kind:'human',value:{ownerId:'environment-field:'+key,fieldPath:'label',source:field.label,context:this.localeContext({phase:'environment-fields',fieldPath:key})}}:{kind:'protected',value:key};
      return this.rich(field?'ui.environment.validation.field':'ui.environment.validation.path','{field}: {message}',{field:label,message:{kind:'human',value:validation}});
    }).join(' ');
    this.refs['environment-fields'].querySelectorAll('[data-environment-field]').forEach(field=>{const invalid=!!result.errors?.[field.dataset.environmentField];field.setAttribute('aria-invalid',String(invalid));if(invalid)field.setAttribute('aria-errormessage','environment-errors');else field.removeAttribute('aria-errormessage');});
    if(result.ok){if(base?.contextualize)this.contextModelMemo={key:JSON.stringify([base.id,this.lessonVariant||'default',result.revision]),model:result.model};this.refreshConfiguration();}
    return result;
  }
  resetEnvironment() {
    this.player.stop(false);this.runtimeEnvironment.reset();this.scenarioMemo.clear();this.definitionMemo=null;
    this.hidePopups();
    for(const kind of ['actor','attribute']){this.refs[kind+'-popup'].innerHTML='';this[kind+'Anchor']=null;this[kind+'FocusTarget']=null;}
    if(this.presentationMode==='full')for(const id of ['packet-name','packet-value','packet-count'])this.refs[id].textContent='';
    this.packetIdentity='';this.attributeUsages=[];
    if(this.presentationMode==='full'){this.refs['environment-errors'].hidden=true;this.refs['environment-errors'].textContent='';}
    this.refreshConfiguration();
  }
  moveActor(id,x,y) {
    const current=this.heldGeometry?this.basePositions:this.positions;if(!current[id]||!Number.isFinite(x)||!Number.isFinite(y))return false;
    const margin=24,hx=CARD_BOUNDS.width/2+margin,hy=CARD_BOUNDS.height/2+margin;
    const candidate={x:Math.max(hx,Math.min(GRAPH_WIDTH-hx,x)),y:Math.max(hy,Math.min(GRAPH_HEIGHT-hy,y))};
    if(Object.entries(current).some(([other,p])=>other!==id&&Math.abs(p.x-candidate.x)<CARD_BOUNDS.width+margin&&Math.abs(p.y-candidate.y)<CARD_BOUNDS.height+margin))return false;
    const proposed={...current,[id]:candidate};
    const pairs=this.graphSteps.map(step=>[this.nodeId(step.from),this.nodeId(step.to)]);
    const routes=validateLayoutRoutes(proposed,pairs);
    if(!routes.ok){this.notify('ui.layout.room-warning','Leave more room for connections and local processing around participants.');return false;}
    if(this.player.status==='playing')this.player.pause();
    if(!this.customLayouts[this.layoutKey])this.customLayouts[this.layoutKey]={};
    this.customLayouts[this.layoutKey][id]=candidate;this.heldView?.configureGeometry();this.refreshMapGeometry();return true;
  }
  refreshMapGeometry() {
    const positions=this.positions;
    this.refs.actors.querySelectorAll('[data-actor]').forEach(card=>{const p=positions[card.dataset.actor];if(p){card.style.left=p.x/GRAPH_WIDTH*100+'%';card.style.top=p.y/GRAPH_HEIGHT*100+'%';}});
    this.renderScenarioEnvironment();this.renderConnections();this.updateStep();this.renderPacket(this.player.snapshot());this.renderStepAttributes(this.player.snapshot(),true);
  }
  ensureLayoutRoutes(extraSteps=[]) {
    const chapter=this.graphChapter,extra=chapter?extraSteps.filter(step=>chapter.stepIds.includes(step.sourceStepId||step.id)):extraSteps;
    const pairs=[...this.graphSteps,...extra].map(step=>[this.nodeId(step.from),this.nodeId(step.to)]);
    if(validateLayoutRoutes(this.positions,pairs).ok)return false;
    delete this.customLayouts[this.layoutKey];
    this.notify('ui.layout.reset','Layout reset to leave room for this scenario’s connections.');
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
  prepareStudyConfiguration() {
    if(this.labModel){this.upstream='single';this.architecture=this.labModel.architecture||'web';this.applicationProtocol=this.labModel.protocol==='saml'?'saml':'oidc';this.oidcFlow='authorization-code';this.mode='passkey';this.tokenProtection='signed';this.assertionProtection='signed';}
    else if(this.isAdvancedFlow){this.upstream='single';this.applicationProtocol='oidc';if(this.oidcFlow!=='device')this.architecture='web';if(this.isDirectFido||modeMetadata[this.mode]?.enrollment)this.mode='passkey';}
    if(this.isDirectFido||this.applicationProtocol==='saml')this.architecture='web';
    if(this.providerOwnsAuthentication&&modeMetadata[this.mode]?.enrollment)this.mode='password';
    if(this.upstream==='external'&&!this.labModel&&!this.isDirectFido&&!this.isAdvancedFlow&&this.providerProfileId!=='generic')this.brokerProtocol=this.providerProfile.protocol;
    const direct=this.isDirectFido,appOidc=!direct&&this.applicationProtocol==='oidc'&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson),brokerEncryptionAllowed=this.upstream!=='external'||this.providerProfile.brokerTokenProtection?.includes('jwe');
    if(!brokerEncryptionAllowed&&['broker-jwe','both-jwe'].includes(this.tokenProtection)){this.tokenProtection=this.tokenProtection==='both-jwe'&&appOidc?'app-jwe':'signed';this.notify('ui.provider.signed-broker','This provider profile uses signed broker identity results. Choose Generic external IdP to study broker JWE on an OIDC leg.');}
    if(this.isAdvancedFlow&&(!appOidc||this.tokenProtection==='broker-jwe'))this.tokenProtection='signed';
    this.activeSteps=this.journeyFor();this.heldView.compiled();
  }
  renderAll() {this.prepareStudyConfiguration();this.syncSharedNavigation();this.presenter.render('configuration');}
  renderScenarioDescription() {
    const meta=modeMetadata[this.mode];
    let englishTitle=this.advancedFlow?.title||meta.title;
    const modeDescription=this.isSingleRealm?meta.description.replace(/the upstream provider/gi,'the Keycloak realm').replace(/upstream/gi,'Realm A'):meta.description;
    const protocolText=this.applicationProtocol==='saml'?'SAML assertion → web service provider':'OIDC code + PKCE → application';
    let englishDescription=modeDescription+' · '+(this.isDirectFido?'Web application is the WebAuthn relying party · RP ID app.example.test · direct credential verification':this.isSingleRealm?'One Keycloak realm verifies the person · '+protocolText:(ARCHITECTURES[this.architecture].name||ARCHITECTURES[this.architecture].title)+' · '+protocolText+' · '+(this.upstream==='external'?'Independent upstream IdP':UPSTREAMS[this.upstream].name||UPSTREAMS[this.upstream].title));
    if(this.isAdvancedFlow)englishDescription=this.advancedFlow.summary+(this.labModel?'':this.advancedFlow.hasPerson?' · '+meta.title:' · No new end-user authentication');
    if(this.providerOwnsAuthentication){englishTitle='Provider-managed sign-in · '+this.providerProfile.title;englishDescription=this.applicationProtocol.toUpperCase()+' application · '+this.brokerProtocol.toUpperCase()+' federation · Authentication and MFA follow the external provider policy. No particular credential method or assurance level is assumed.';}
    if(this.learningPreset){englishTitle=this.learningPreset.title;englishDescription=this.learningPreset.summary+(this.upstream==='external'?' · '+this.providerProfile.title:'');}
    const project=source=>this.runtimeEnvironment.projectValue(source,this.environmentOptions);
    englishDescription=project(englishDescription);
    const branch=this.learningPreset?'preset':this.providerOwnsAuthentication?'provider':this.isAdvancedFlow?this.labModel?'lesson':this.advancedFlow.hasPerson?'grant-person':'grant-no-person':this.isDirectFido?'direct':this.isSingleRealm?'single-realm':'broker';
    const context={phase:'scenario-description',branch,modeId:this.mode,applicationProtocol:this.applicationProtocol,brokerProtocol:this.brokerProtocol,upstream:this.upstream,architecture:this.architecture};
    const human=(ownerId,fieldPath,source,projected=false)=>({ownerId,fieldPath,source:projected?project(source):source,context:this.localeContext({...context,projected})});
    const modeTitle=human('mode:'+this.mode,'title',meta.title,true),modeProse=human('mode:'+this.mode,'description',modeDescription,true);
    const protocolKey=this.applicationProtocol==='saml'?'ui.scenario.protocol.saml':'ui.scenario.protocol.oidc',protocol={key:protocolKey,source:protocolText};
    const flow=this.advancedFlow,preset=this.learningPreset;
    let titleHtml,descriptionHtml;
    if(branch==='preset'){
      titleHtml=this.prose('lesson:'+preset.id,'title',englishTitle,context);
      const summary=human('lesson:'+preset.id,'summary',preset.summary,true);
      descriptionHtml=this.upstream==='external'?this.ui('ui.scenario.presetProvider',englishDescription,{summary,provider:project(this.providerProfile.title)}):this.prose('lesson:'+preset.id,'summary',englishDescription,{...context,projected:true});
    }else if(branch==='provider'){
      titleHtml=this.ui('ui.scenario.providerTitle',englishTitle,{provider:this.providerProfile.title});
      descriptionHtml=this.ui('ui.scenario.providerDescription',englishDescription,{applicationProtocol:this.applicationProtocol.toUpperCase(),brokerProtocol:this.brokerProtocol.toUpperCase()});
    }else{
      titleHtml=flow?this.prose('lesson:'+flow.id,'title',englishTitle,context):this.prose('mode:'+this.mode,'title',englishTitle,context);
      if(branch==='lesson')descriptionHtml=this.prose('lesson:'+flow.id,'summary',englishDescription,{...context,projected:true});
      else if(branch==='grant-person')descriptionHtml=this.ui('ui.scenario.grantPerson',englishDescription,{summary:human('lesson:'+flow.id,'summary',flow.summary,true),mode:modeTitle});
      else if(branch==='grant-no-person')descriptionHtml=this.ui('ui.scenario.grantNoPerson',englishDescription,{summary:human('lesson:'+flow.id,'summary',flow.summary,true)});
      else if(branch==='direct')descriptionHtml=this.ui('ui.scenario.directDescription',englishDescription,{description:modeProse,rpId:project('app.example.test')});
      else if(branch==='single-realm')descriptionHtml=this.ui('ui.scenario.singleDescription',englishDescription,{description:modeProse,protocol});
      else{
        const architecture=ARCHITECTURES[this.architecture],upstream=UPSTREAMS[this.upstream];
        const upstreamText=this.upstream==='external'?{key:'ui.scenario.independentProvider',source:'Independent upstream IdP'}:human('upstream:'+this.upstream,upstream.name?'name':'title',upstream.name||upstream.title,true);
        descriptionHtml=this.ui('ui.scenario.brokerDescription',englishDescription,{description:modeProse,architecture:human('architecture:'+this.architecture,architecture.name?'name':'title',architecture.name||architecture.title,true),protocol,upstream:upstreamText});
      }
    }
    this.querySelector('#scenario-title').innerHTML='<span class="locale-prose">'+titleHtml+'</span>';
    this.querySelector('#scenario-description').innerHTML='<span class="locale-prose">'+descriptionHtml+'</span>';
  }
  renderFull(reason='state') {
    this.refs.mode.value=this.mode;
    this.refs.architecture.value=this.architecture;
    this.refs.upstream.value=this.upstream;
    this.updateProtocolControls();
    this.renderWorkspace();
    if(reason!=='presentation'){this.graphChapterKey=this.graphChapter?.id||null;this.heldView?.configureGeometry();if(!this.heldGeometry)this.ensureLayoutRoutes(this.traceQueue);}
    const meta=modeMetadata[this.mode];
    this.renderScenarioDescription();
    this.refs.mode.disabled=this.isAdvancedFlow&&!this.advancedFlow.hasPerson;
    this.querySelector('label[for="mode"]').textContent=this.isAdvancedFlow?(this.advancedFlow.hasPerson?this.uiText('ui.modes.label.verification','Verification method'):this.uiText('ui.modes.label.human','Human authentication')):this.uiText('ui.modes.label.journey','Learning journey');
    Object.entries(modeMetadata).forEach(([value,m])=>{const option=this.refs.mode.querySelector('[value="'+value+'"]');option.disabled=this.isAdvancedFlow&&!!(m.directFido||m.enrollment);option.textContent=this.isAdvancedFlow&&!this.advancedFlow.hasPerson&&value===this.mode?this.uiText('ui.modes.option.notUsed','Not used in this grant'):this.proseText('mode:'+value,'title',m.title,{phase:'mode-option'});});
    this.refs.authenticator.disabled=!meta.passkey||this.isAdvancedFlow&&!this.advancedFlow.hasPerson;
    if(this.upstream==='external'&&(this.providerManaged||this.providerProfileId!=='generic')){this.refs.mode.disabled=true;this.refs.authenticator.disabled=true;this.querySelector('label[for="mode"]').textContent=this.uiText('ui.modes.label.corporate','Corporate authentication');this.refs.mode.querySelector('[value="'+this.mode+'"]').textContent=this.uiText('ui.modes.option.managed','Managed by the external provider');}
    this.refs.architecture.disabled=this.isDirectFido||this.applicationProtocol==='saml'||this.isAdvancedFlow&&this.oidcFlow!=='device';this.refs.upstream.disabled=this.isDirectFido||this.isAdvancedFlow;
    this.refs.architecture.querySelector('[value="web"]').textContent=this.isDirectFido?this.uiText('ui.modes.architecture.direct','Network web app · relying-party server'):this.applicationProtocol==='saml'?this.uiText('ui.modes.architecture.saml','Network web app · SAML service provider'):this.proseText('architecture:web','title',ARCHITECTURES.web.title,{phase:'architecture-option'});
    this.refs.architecture.title=this.isDirectFido?this.uiText('ui.modes.architecture.directHelp','Direct WebAuthn is served by the web application at its HTTPS origin.'):this.applicationProtocol==='saml'?this.uiText('ui.modes.architecture.samlHelp','This SAML Web SSO example uses the server’s HTTPS Assertion Consumer Service (ACS).'):'';
    this.refs.architecture.querySelector('[value="native"]').textContent=this.oidcFlow==='device'?this.uiText('ui.modes.architecture.devicePublic','Limited-input device · public client'):this.proseText('architecture:native',ARCHITECTURES.native.name?'name':'title',ARCHITECTURES.native.name||ARCHITECTURES.native.title,{phase:'architecture-option'});
    if(this.isAdvancedFlow){this.refs.architecture.querySelector('[value="web"]').textContent=this.oidcFlow==='device'?this.uiText('ui.modes.architecture.deviceBackend','Device service · confidential backend'):this.oidcFlow==='ciba'?this.uiText('ui.modes.architecture.cibaBackend','Consumption app · confidential backend'):this.oidcFlow==='token-exchange'?this.uiText('ui.modes.architecture.exchangeBackend','Token requester · confidential backend'):this.uiText('ui.modes.architecture.background','Background service · confidential client');this.refs.architecture.title=this.oidcFlow==='device'?this.uiText('ui.modes.architecture.deviceHelp','Choose public or confidential device-client authentication; neither variant has an inbound application callback.'):this.uiText('ui.modes.architecture.backendHelp','This example authenticates its confidential backend directly to Realm A.');}
    this.refs.upstream.querySelector('[value="external"]').textContent=this.uiText('ui.modes.upstream.external','Keycloak + external '+(this.brokerProtocol==='saml'?'SAML':'OIDC')+' IdP',{protocol:this.brokerProtocol==='saml'?'SAML':'OIDC'});
    this.refs.upstream.title=this.isDirectFido?this.uiText('ui.modes.upstream.directHelp','The web application verifies the credential directly; no upstream IdP participates.'):this.isAdvancedFlow?this.uiText('ui.modes.upstream.grantHelp','This grant walkthrough uses one Keycloak realm. CIBA’s controlled authentication service is a separate integration, not another realm.'):'';
    if(this.labModel){
      this.refs.mode.disabled=true;this.refs.authenticator.disabled=true;this.refs.architecture.disabled=true;this.refs.upstream.disabled=true;
      this.querySelector('label[for="mode"]').textContent=this.uiText('ui.modes.label.scenario','Scenario policy');this.refs.mode.querySelector('[value="'+this.mode+'"]').textContent=this.uiText('ui.modes.option.scenario','Defined by this scenario');
      this.refs.architecture.querySelector('[value="'+this.architecture+'"]').textContent=this.labModel.clientKind?this.proseText('lesson:'+this.labModel.id,'clientKind',this.labModel.clientKind,{phase:'architecture-option'}):this.architecture==='native'?this.uiText('ui.modes.architecture.browserDeployment','Browser / public client deployment'):this.uiText('ui.modes.architecture.serverDeployment','Server / protocol deployment');
      this.refs.upstream.title=this.uiText('ui.modes.upstream.scenarioHelp','Participants and identity roles are specified by the selected scenario.');
    }
    this.renderCatalog();this.renderLabSupport();this.renderLearningProfile();
    this.querySelectorAll('[data-learning-preset]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.learningPreset===this.labScenarioId)));
    this.refs['provider-settings'].hidden=this.upstream!=='external'||!!this.labModel||this.isDirectFido;
    this.refs['provider-profile'].value=this.providerProfile.id;
    this.refs['provider-note'].innerHTML=this.providerProfile.assumptions.map(assumption=>this.prose('provider:'+this.providerProfile.id,'assumptions',assumption,{phase:'provider-assumptions'})).join(' ');
    this.querySelector('#provider-sources').innerHTML=this.providerProfile.sources.map(source=>`<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" dir="ltr" translate="no">${escapeHtml(source.name)}</a>`).join('');
    this.renderEnvironmentFields();
    this.renderActors();this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.renderInspector();this.updateStep();this.updateControls();
  }
  updateProtocolControls() {
    const direct=this.isDirectFido,enrollment=!!modeMetadata[this.mode]?.enrollment;
    const appOidc=!direct&&this.applicationProtocol==='oidc'&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson),brokerOidc=!direct&&!this.isAdvancedFlow&&this.upstream!=='single'&&this.brokerProtocol==='oidc';
    const brokerEncryptionAllowed=this.upstream!=='external'||this.providerProfile.brokerTokenProtection?.includes('jwe');
    const saml=!direct&&(this.applicationProtocol==='saml'||this.upstream!=='single'&&this.brokerProtocol==='saml');
    const values={'oidc-flow':this.oidcFlow,'app-protocol':this.applicationProtocol,'broker-protocol':this.brokerProtocol,'saml-binding':this.samlBinding,'saml-initiation':this.samlInitiation,'token-protection':this.tokenProtection,'assertion-protection':this.assertionProtection};
    const disabled={'app-protocol':direct,'broker-protocol':direct||this.upstream==='single'||this.upstream==='external'&&this.providerProfileId!=='generic','saml-binding':!saml||enrollment,'saml-initiation':direct||this.applicationProtocol!=='saml'||enrollment,'token-protection':direct||enrollment||!appOidc&&!brokerOidc,'assertion-protection':!saml||enrollment};
    disabled['oidc-flow']=direct||enrollment||this.applicationProtocol==='saml';
    Object.entries(values).forEach(([id,value])=>{this.refs[id].value=value;this.refs[id].disabled=disabled[id];});
    const protectionOptions={'app-jwe':!appOidc,'broker-jwe':!brokerOidc||!brokerEncryptionAllowed,'both-jwe':!brokerEncryptionAllowed||!appOidc&&!brokerOidc};
    Object.entries(protectionOptions).forEach(([value,disabled])=>{this.refs['token-protection'].querySelector('[value="'+value+'"]').disabled=disabled;});
    let summary=direct?'Direct FIDO2 · application is the RP':enrollment?'Credential enrollment · verified account':(this.applicationProtocol.toUpperCase()+' application'+(this.upstream==='single'?' · one realm':' · '+this.brokerProtocol.toUpperCase()+' broker'));
    if(this.isAdvancedFlow)summary=this.advancedFlow.title+' · one realm';
    const baseSummary=summary,summaryKey=this.isAdvancedFlow?'ui.protocolControls.summary.advanced':direct?'ui.protocolControls.summary.direct':enrollment?'ui.protocolControls.summary.enrollment':this.upstream==='single'?'ui.protocolControls.summary.single':'ui.protocolControls.summary.broker';
    const summaryParams=this.isAdvancedFlow?{title:{ownerId:'lesson:'+this.advancedFlow.id,fieldPath:'title',source:this.advancedFlow.title,context:this.localeContext({phase:'protocol-summary'})}}:direct||enrollment?{}:{applicationProtocol:this.applicationProtocol.toUpperCase(),...(this.upstream==='single'?{}:{brokerProtocol:this.brokerProtocol.toUpperCase()})};
    this.refs['app-protocol'].querySelector('[value="oidc"]').textContent=this.isAdvancedFlow?this.uiText('ui.protocolControls.oidcGrant','OIDC / OAuth · selected grant'):this.uiText('ui.protocolControls.oidcCode','OIDC · Authorization Code');
    if(!direct&&!enrollment&&(appOidc&&['app-jwe','both-jwe'].includes(this.tokenProtection)||brokerOidc&&['broker-jwe','both-jwe'].includes(this.tokenProtection)))summary+=' · JWE';
    if(!direct&&!enrollment&&saml&&this.assertionProtection==='encrypted')summary+=' · XML Encryption';
    const protection=summary.slice(baseSummary.length+3);
    this.refs['protocol-summary'].innerHTML=summary===baseSummary?this.ui(summaryKey,summary,summaryParams):this.ui('ui.protocolControls.summary.protection',summary,{summary:{key:summaryKey,source:baseSummary,params:summaryParams},protection});
    this.refs['protocol-summary'].classList.add('locale-prose');
    const protectionNote=this.querySelector('#provider-protection-note');protectionNote.hidden=brokerEncryptionAllowed;protectionNote.innerHTML=this.brokerProtocol==='saml'?this.ui('ui.protocolControls.providerProtection.saml','This base provider profile uses signed SAML identity results. SAML assertion encryption uses XML Encryption; OIDC ID-token encryption uses JWE. Application-side protection follows the application protocol selected above.'):this.ui('ui.protocolControls.providerProtection.oidc','This base provider profile uses signed broker ID tokens. An OIDC application leg can use Keycloak-to-application JWE independently. Choose Generic external IdP to study configured broker JWE.');
    if(this.labModel){Object.keys(values).forEach(id=>this.refs[id].disabled=true);this.refs['protocol-summary'].innerHTML=this.ui('ui.protocolControls.summary.scenario',this.labModel.title+' · scenario-specific protocol',{title:{ownerId:'lesson:'+this.labModel.id,fieldPath:'title',source:this.labModel.title,context:this.localeContext({phase:'protocol-summary'})}});}
    const fixedProfile=!!this.labModel?.profile;
    this.querySelector('.toolbar').hidden=fixedProfile;this.querySelector('.protocol-toolbar').hidden=fixedProfile;
  }
  actorCardRole(actor) {
    if(this.labModel)return this.ltr(actor.role);
    if(this.isAdvancedFlow){
      switch(actor.id){
        case 'user':return this.ui('ui.actor.role.approver','The person approving');
        case 'app':
          if(this.oidcFlow==='device')return this.architecture==='web'?this.ui('ui.actor.role.confidential-device','Confidential device client'):this.ui('ui.actor.role.public-device','Public device client');
          if(this.oidcFlow==='ciba')return this.ui('ui.actor.role.ciba-client','Confidential CIBA client');
          return this.oidcFlow==='token-exchange'?this.ui('ui.actor.role.token-requester','Confidential token requester'):this.ui('ui.actor.role.service-client','Confidential service client');
        case 'browser':return this.oidcFlow==='ciba'?this.ui('ui.actor.role.authentication-device','Separate authentication device'):this.ui('ui.actor.role.verification-device','Separate verification device');
        case 'realmA':return this.oidcFlow==='ciba'?this.ui('ui.actor.role.ciba-provider','OIDC CIBA provider'):this.ui('ui.actor.role.authorization-server','OAuth authorization server');
        case 'realmB':return this.ui('ui.actor.role.authentication-channel','Authentication channel');
      }
    }
    switch(actor.id){
      case 'user':return this.ui('ui.actor.role.signing-in','The person signing in');
      case 'app':return this.isDirectFido?this.ui('ui.actor.role.webauthn-rp','WebAuthn relying party'):this.applicationProtocol==='saml'?this.ui('ui.actor.role.saml-sp','SAML service provider'):this.architecture==='web'?this.ui('ui.actor.role.oidc-backend','Confidential OIDC backend'):this.ui('ui.actor.role.oidc-native','Native OIDC client');
      case 'browser':return this.ui('ui.actor.role.browser','System browser');
      case 'realmA':return this.isSingleRealm?this.ui('ui.actor.role.realm-provider','Keycloak · '+this.applicationProtocol.toUpperCase()+' provider',{protocol:this.applicationProtocol.toUpperCase()}):this.ui('ui.actor.role.realm-broker','IdP 1 · '+this.brokerProtocol.toUpperCase()+' broker',{protocol:this.brokerProtocol.toUpperCase()});
      case 'realmB':return this.upstream==='external'?this.ui('ui.actor.role.independent-provider','Independent '+this.brokerProtocol.toUpperCase()+' provider',{protocol:this.brokerProtocol.toUpperCase()}):this.ui('ui.actor.role.identity-checker','IdP 2 · Checks identity');
      case 'hello':return this.ui('ui.actor.role.platform','Platform authenticator');
      case 'yubikey':return this.ui('ui.actor.role.security-key','FIDO2 security key');
      case 'totp':return this.ui('ui.actor.role.authenticator-app','Authenticator app');
      default:return this.prose('actor:'+actor.id,'plainRole',actor.plainRole);
    }
  }
  renderActors() {
    const activeActors=new Set(this.graphSteps.flatMap(s=>[this.nodeId(s.from),this.nodeId(s.to)]));
    this.refs.actors.innerHTML=Object.keys(this.scenarioOwnedActors||ACTORS).map(id=>{
      if(this.scenarioOwnedActors&&this.nodeId(id)!==id)return '';
      const a=this.actor(id),p=this.positions[a.id];if(!p)return '';
      const isAlternative=(a.id==='hello'||a.id==='yubikey')&&a.id!==this.authenticator;
      const context=this.actorContextHtml(a.id,true);
      const role=this.actorCardRole(a),label=this.uiText('ui.actor.inspect','Inspect '+a.name,{name:a.name});
      return `<button class="actor-card ${context?'has-context':''} ${this.isAdvancedFlow?'is-advanced':''} ${activeActors.has(a.id)?'':'is-muted'}" data-actor="${a.id}" aria-haspopup="dialog" aria-controls="actor-popup" aria-keyshortcuts="F2" ${context?`aria-describedby="actor-context-${a.id}"`:''} ${!this.labModel&&this.isSingleRealm&&a.id==='realmB'&&this.oidcFlow!=='ciba'?'hidden':''} aria-label="${escapeHtml(label)}"><span class="actor-status locale-prose">${!this.labModel&&isAlternative?this.ui('ui.actor.option','OPTION'):activeActors.has(a.id)?'':this.isDirectFido||this.isSingleRealm?this.ui('ui.actor.not-used','NOT USED'):this.ui('ui.actor.option','OPTION')}</span><span class="actor-art">${this.illustration(a.id)}</span><span class="actor-name">${this.ltr(a.cardName||a.name)}</span><span class="actor-role locale-prose">${role}</span>${context}<span class="actor-trace-action locale-prose" hidden></span></button>`;
    }).join('');
    // Assign individual CSSOM properties after insertion; HTML style attributes
    // are intentionally forbidden by the standalone page's CSP.
    this.refs.actors.querySelectorAll('[data-actor]').forEach(card=>{const p=this.positions[card.dataset.actor];card.style.left=p.x/GRAPH_WIDTH*100+'%';card.style.top=p.y/GRAPH_HEIGHT*100+'%';const color=this.actor(card.dataset.actor).color;if(/^#[0-9a-f]{3,8}$/i.test(color||''))card.style.setProperty('--actor-color',color);});
    this.renderScenarioEnvironment();
    this.heldView?.render();
  }
  renderScenarioEnvironment(){
    const panel=this.querySelector('#scenario-environment');panel.hidden=!this.labModel?.workspace;
    const zones=this.querySelector('#trust-zones');zones.innerHTML='';
    if(panel.hidden){panel.innerHTML='';return;}
    const positions=this.positions,owned=this.scenarioOwnedActors,actors=Object.values(owned).filter(actor=>positions[this.nodeId(actor.id)]);
    panel.innerHTML=actors.map(actor=>{const rows=this.actorContextRows(actor.id);return rows.length?'<div class="scenario-context-item"><strong>'+this.ltr(actor.name)+'</strong>'+rows.map(row=>'<span class="locale-prose">'+this.prose('actor:'+actor.id,'contextRows.'+row.key+'.label',row.label,{phase:'environment-context',rowKey:row.key})+' <code '+this.rawValueAttrs(row.value)+'>'+escapeHtml(row.value)+'</code></span>').join('')+'</div>':'';}).join('');
    panel.hidden=!panel.innerHTML;
    if(this.labModel.physicalHostBoundaries){
      const roots=new Map(),hostIds=new Set(),groups=new Map();
      for(const actor of Object.values(owned)){
        let host=actor;while(host.parentId&&owned[host.parentId])host=owned[host.parentId];
        roots.set(actor.id,host);if(actor.parentId)hostIds.add(host.id);
      }
      for(const [id,p]of Object.entries(positions)){
        if(this.nodeId(id)!==id)continue;
        const host=roots.get(id);if(!host||!hostIds.has(host.id)&&!['idp','service','host','ca','kdc'].includes(host.kind))continue;
        const b=this.heldGeometry?.bounds[id]||{left:p.x-CARD_BOUNDS.width/2,right:p.x+CARD_BOUNDS.width/2,top:p.y-CARD_BOUNDS.height/2,bottom:p.y+CARD_BOUNDS.height/2},group=groups.get(host.id);
        if(group){group.left=Math.min(group.left,b.left);group.right=Math.max(group.right,b.right);group.top=Math.min(group.top,b.top);group.bottom=Math.max(group.bottom,b.bottom);}
        else groups.set(host.id,{title:host.name,...b});
      }
      zones.innerHTML=[...groups].map(([id,group])=>`<div class="trust-zone" data-zone-host="${escapeHtml(id)}"><span>${escapeHtml(group.title)}</span></div>`).join('');
      zones.querySelectorAll('[data-zone-host]').forEach(zone=>{
        const b=groups.get(zone.dataset.zoneHost);zone.style.left=(b.left-10)/GRAPH_WIDTH*100+'%';zone.style.top=(b.top-10)/GRAPH_HEIGHT*100+'%';zone.style.width=(b.right-b.left+20)/GRAPH_WIDTH*100+'%';zone.style.height=(b.bottom-b.top+20)/GRAPH_HEIGHT*100+'%';zone.style.transform='none';
      });
      return;
    }
    const declared=this.labModel.trustZones||Object.values(this.scenarioOwnedActors).filter(actor=>this.positions[actor.id]&&['idp','service','host','ca','kdc'].includes(actor.kind)).map(actor=>({id:actor.id,title:actor.parentId?this.scenarioOwnedActors[actor.parentId]?.name||actor.name:actor.name,actors:[actor.id]}));
    zones.innerHTML=declared.flatMap(zone=>(zone.actors||[]).map(actorId=>{const id=this.nodeId(actorId),formal=Object.values(owned).some(actor=>actor.name===zone.title);return this.positions[id]?'<div class="trust-zone" data-zone-actor="'+id+'"><span class="locale-prose">'+(formal?this.ltr(zone.title):this.prose('lesson:'+this.labModel.id,'trustZones.title',zone.title,{zoneId:zone.id}))+'</span></div>':'';})).join('');
    zones.querySelectorAll('[data-zone-actor]').forEach(zone=>{const p=this.positions[zone.dataset.zoneActor];zone.style.left=p.x/GRAPH_WIDTH*100+'%';zone.style.top=p.y/GRAPH_HEIGHT*100+'%';});
  }
  protocolSnapshot(){
    const snapshot=this.scenarioSnapshot();
    if(this.protocolMemo?.source!==snapshot){
      const variant=this.lessonVariant&&this.lessonVariant!=='default'?':variant-'+this.lessonVariant:'',base=this.labModel;
      const model=Object.create(base||Object.prototype,{
        instanceScope:{value:this.labScenarioId+'@context-'+this.runtimeEnvironment.revision+variant,enumerable:true},
        steps:{value:()=>snapshot.steps,enumerable:true},
        initialState:{value:snapshot.initialState||base?.initialState||{},enumerable:true},
        protocolValues:{value:snapshot.protocolValues||base?.protocolValues||{},enumerable:true},
      });
      this.protocolMemo={source:snapshot,model,instances:new Map()};
    }
    const held=this.heldView.snapshot(),sourceIndex=held.cursor.milestone==='complete'?held.cursor.eventIndex:Math.max(-1,held.cursor.eventIndex-1);
    const memo=this.protocolMemo;
    return {model:memo.model,sourceIndex,selectedSourceIndex:held.cursor.eventIndex,cursor:held.cursor,state:held.state,get instances(){
      if(!memo.instances.has(sourceIndex)){memo.instances.clear();memo.instances.set(sourceIndex,buildProtocolInstances(memo.model,sourceIndex));}
      return memo.instances.get(sourceIndex);
    }};
  }
  renderProtocolState(){
    const panel=this.querySelector('#protocol-state-panel'),open=panel.hasAttribute('open');
    const cursor=this.heldView.snapshot().cursor,key=JSON.stringify([this.heldView.contextId,cursor,this.attributeSelection,open,this.localizer.revision]);
    if(this.protocolRenderKey===key)return;this.protocolRenderKey=key;
    const snapshot=this.protocolSnapshot();panel.hidden=!snapshot;this.renderLifetimes(snapshot);
    if(!snapshot)return;
    this.renderLessonDecisions(snapshot);
    const position=snapshot.cursor.eventIndex<0?{key:'ui.state.beforeFirst',source:'Before step 1',params:{}}:{key:'ui.state.sourceEvent',source:'Source event '+(snapshot.cursor.eventIndex+1)+' / '+snapshot.cursor.milestone,params:{event:snapshot.cursor.eventIndex+1,milestone:snapshot.cursor.milestone}};
    this.querySelector('#protocol-state-summary').innerHTML=this.ui('ui.state.summary',position.source+' / '+snapshot.model.steps().length+' · protocol clock '+snapshot.state.protocolClock+' · fixture '+this.labScenarioId+'@context-'+this.runtimeEnvironment.revision,{position,steps:snapshot.model.steps().length,clock:snapshot.state.protocolClock,fixture:this.labScenarioId+'@context-'+this.runtimeEnvironment.revision});
    const list=this.querySelector('#protocol-instance-list'),stateValue=this.querySelector('#protocol-state-value');
    if(!open){stateValue.textContent='';list.innerHTML='';return;}
    const expanded=new Set([...list.querySelectorAll('[data-instance-history][open]')].map(details=>details.dataset.instanceHistory));
    const focused=list.contains(document.activeElement)?document.activeElement.closest('[data-instance-history]')?.dataset.instanceHistory:null;
    const rawState=JSON.stringify(snapshot.state,null,2);stateValue.textContent=rawState;stateValue.setAttribute('dir','ltr');stateValue.setAttribute('translate','no');stateValue.dataset.copyRawJson=JSON.stringify(rawState);
    const records=snapshot.instances.filter(record=>!this.attributeSelection||record.definitionIds?.includes(this.attributeSelection)||record.definitionId===this.attributeSelection);
    list.innerHTML=records.length?'<div class="instance-table-scroll" dir="ltr" data-technical-ltr><table class="instance-table"><thead><tr><th class="locale-prose">'+this.ui('ui.state.objectInstance','Object instance')+'</th><th class="locale-prose">'+this.ui('ui.state.creatorHoldersInspectors','Creator / holders / inspectors')+'</th><th class="locale-prose">'+this.ui('ui.state.exactOccurrence','Exact field occurrence')+'</th></tr></thead><tbody>'+records.map(record=>{const id=record.qualifiedInstanceId||record.instanceId,count=record.occurrences.length;return `<tr><td><code ${this.rawValueAttrs(id)}>${escapeHtml(id)}</code></td><td class="locale-prose">${record.creator?this.ltr(record.creator):this.ui('ui.state.configuredBefore','Configured before the journey')}<br>${this.ui('ui.state.observedHolders','Observed holders: '+(record.holders||[]).join(', '),{holders:(record.holders||[]).join(', ')})}<br>${this.ui('ui.state.inspectorsAcrossFields','Inspectors across fields: '+(record.inspectors||[]).join(', '),{inspectors:(record.inspectors||[]).join(', ')})}</td><td><details data-instance-history="${escapeHtml(id)}" data-study-key="${escapeHtml('protocol-instance:'+id)}"${expanded.has(id)?' open':''}><summary class="locale-prose">${this.ui('ui.state.occurrenceCount',count+(count===1?' exact field occurrence':' exact field occurrences'),{count})}</summary><div class="instance-history-value"></div></details></td></tr>`;}).join('')+'</tbody></table></div>':'<p class="environment-note locale-prose">'+this.ui('ui.state.noInstances','No instantiated object is visible in this prefix.')+'</p>';
    const disclosures=[...list.querySelectorAll('[data-instance-history]')];
    for(const details of disclosures)if(details.hasAttribute('open'))this.renderProtocolInstanceHistory(details);
    if(focused)(disclosures.find(details=>details.dataset.instanceHistory===focused)?.querySelector('summary')||panel.querySelector('summary')).focus({preventScroll:true});
  }
  renderProtocolInstanceHistory(details){
    if(!this.contains(details))return;
    const target=details.querySelector('.instance-history-value');
    if(!details.hasAttribute('open')){target.innerHTML='';delete details.dataset.protocolHistoryKey;return;}
    if(details.dataset.protocolHistoryKey===this.protocolRenderKey)return;
    const record=this.protocolSnapshot().instances.find(record=>(record.qualifiedInstanceId||record.instanceId)===details.dataset.instanceHistory);
    if(!record)throw new TypeError('Protocol instance is not present at the current source cursor.');
    target.setAttribute('dir','ltr');target.setAttribute('data-technical-ltr','');
    target.innerHTML=record.occurrences.map(occurrence=>{const inspectors=(occurrence.inspectors||[]).join(', '),value=occurrence.value===undefined?undefined:typeof occurrence.value==='string'?occurrence.value:JSON.stringify(occurrence.value);return `<div class="instance-occurrence locale-prose"><code ${this.rawValueAttrs(occurrence.fieldPath)}>${escapeHtml(occurrence.fieldPath)}</code> · ${this.ltr(occurrence.representation)} · ${this.ltr(occurrence.eventId)}<br>${this.ui('ui.state.occurrenceActor','Actor: '+occurrence.actorId+' · '+occurrence.kind,{actor:occurrence.actorId,kind:occurrence.kind})}<br>${inspectors?this.ui('ui.state.permittedInspectors','Permitted inspectors of this occurrence: '+inspectors,{inspectors}):this.ui('ui.state.inspectorsNotDeclared','Permitted inspectors of this occurrence: not declared')}<br>${value===undefined?this.ui('ui.state.bytesNotExposed','Exact bytes are intentionally not exposed'):`<code ${this.rawValueAttrs(value)}>${escapeHtml(value)}</code>`}</div>`;}).join('');
    details.dataset.protocolHistoryKey=this.protocolRenderKey;
  }
  renderLessonDecisions(snapshot){
    const panel=this.querySelector('#lesson-decisions'),remote=this.labModel?.family==='windows-remote-administration',bindings=(this.labModel?.decisionBindings||[]).filter(binding=>!remote||!['workstation.tokenComparison','workstation.policyComparison','workstation.verdictExplanation','workstation.localComparisonQualification'].includes(binding.path)),dnssec=snapshot.state.dnssec;
    const owner='lesson:'+(this.labModel?.id||this.labScenarioId),contextFor=binding=>this.localeContext(binding?{binding}:{}),lesson=(field,source,binding)=>this.prose(owner,field,source,contextFor(binding));
    const isDnssec=this.labModel?.workspace==='dnssec',compareHops=isDnssec&&['lab-dnssec05','lab-dnssec06'].includes(this.labModel.id);
    panel.setAttribute('aria-label',this.labModel?.decisionPanelLabel?this.proseText(owner,'decisionPanelLabel',this.labModel.decisionPanelLabel,contextFor()):this.uiText('ui.decisions.panelLabel','Current identity, trust and access decisions'));
    panel.hidden=!bindings.length;
    this.renderWindowsRemoteEvidence(snapshot);
    const raw=[],rows=bindings.map(binding=>{
      const value=binding.path.split('.').reduce((current,key)=>current&&Object.hasOwn(current,key)?current[key]:undefined,snapshot.state);
      const display=binding.values&&Object.hasOwn(binding.values,String(value))?lesson('decisionBindings.values',binding.values[String(value)],'decision:'+binding.path+':'+value):value===undefined?this.ui('ui.decisions.notDeclared','Not declared'):value===null?this.ui('ui.decisions.notReached','Not reached'):value===true?this.ui('ui.decisions.yes','Yes'):value===false?this.ui('ui.decisions.no','No'):isDnssec?this.dnssecDecisionDisplay(binding.path,value,dnssec):this.ltr(formatProtocolValue(value,true));
      const label=lesson('decisionBindings.label',binding.label,'decisionBindings:'+binding.path);
      if(isDnssec)raw.push(`<div><dt class="locale-prose">${label}</dt><dd>${this.ltr(binding.path)}: ${this.ltr(formatProtocolValue(value,true))}</dd></div>`);
      return `<div><dt class="locale-prose">${isDnssec&&binding.path==='dnssec.received'?this.ui('ui.decisions.freshAuthorityReceipt','Fresh authority data received'):label}</dt><dd class="locale-prose">${display}</dd></div>`;
    }).join('');
    const cacheReused=compareHops&&Object.values(dnssec.validators||{}).some(validator=>validator.reusedAuthenticatedCache===true),yesNo=value=>value?this.ui('ui.decisions.yes','Yes'):this.ui('ui.decisions.no','No');
    const receiptRows=compareHops?`<div><dt class="locale-prose">${this.ui('ui.app.renderLessonDecisions.text.0188','Authenticated cache reused')}</dt><dd class="locale-prose">${yesNo(cacheReused)}</dd></div><div><dt class="locale-prose">${this.ui('ui.app.renderLessonDecisions.text.0189','Response delivered to stub')}</dt><dd class="locale-prose">${yesNo(dnssec.returnedToStub)}</dd></div>`:'';
    const previousDetails=panel.querySelector('.dnssec-decision-details'),detailsOpen=previousDetails?.hasAttribute('open'),detailsFocused=previousDetails?.contains(document.activeElement);
    const comparisonFocused=document.activeElement===panel.querySelector('.dnssec-hop-comparison [tabindex="0"]');
    const sourceFocused=panel.querySelector('.dnssec-context-panel')?.contains(document.activeElement)?document.activeElement.getAttribute('data-dnssec-source-key'):null;
    const details=isDnssec?`<details class="dnssec-decision-details" data-study-key="dnssec-decision-identifiers"${detailsOpen?' open':''}><summary class="locale-prose">${this.ui('ui.app.renderLessonDecisions.text.0190','Raw DNSSEC decision identifiers')}</summary><dl dir="ltr" data-technical-ltr>${raw.join('')}</dl></details>`:'';
    const receiptContext=cacheReused?'<p class="dnssec-receipt-context locale-prose">'+this.ui('ui.decisions.cacheReceiptContext','The resolver reused an earlier authenticated cache occurrence: no fresh authority receipt or fetch and no fresh signature check. Cache reuse, response delivery to the stub and application use are separate boundaries.')+'</p>':'';
    const context=this.labModel?.dnssecContext;
    const contextMarkup=isDnssec&&context?`<section class="dnssec-context-panel locale-prose" aria-label="${escapeHtml(this.proseText(owner,'dnssecContext.title',context.title,contextFor()))}"><h3>${lesson('dnssecContext.title',context.title)}</h3><p>${lesson('dnssecContext.explanation',context.explanation)}</p><dl>${context.records.map(record=>{const definition=this.definition(record.fieldId),binding='dnssecContext.records:'+record.fieldId,labelRef={ownerId:owner,fieldPath:'dnssecContext.records.label',source:record.label,context:contextFor(binding)};return `<div><dt>${lesson('dnssecContext.records.label',record.label,binding)}</dt><dd>${this.prose('field:'+record.fieldId,'origin',definition.origin,this.localeContext())} ${(definition.sources||[definition.source]).map((url,index)=>`<a data-dnssec-source-key="${escapeHtml(record.fieldId+':'+index)}" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${this.ui('ui.decisions.recordSource',record.label+' source '+(index+1),{label:labelRef,number:index+1})}</a>`).join(' ')}</dd></div>`;}).join('')}</dl><p>${lesson('dnssecContext.parentDecision',context.parentDecision)}</p></section>`:'';
    const markup=bindings.length?'<dl>'+rows+receiptRows+'</dl>'+receiptContext+details+(compareHops?this.dnssecHopComparison(dnssec):'')+contextMarkup:'';
    if(panel.innerHTML!==markup){
      panel.innerHTML=markup;
      if(detailsFocused)panel.querySelector('.dnssec-decision-details summary')?.focus({preventScroll:true});
      else if(comparisonFocused)panel.querySelector('.dnssec-hop-comparison [tabindex="0"]')?.focus({preventScroll:true});
      else if(sourceFocused)Array.from(panel.querySelectorAll('.dnssec-context-panel a')).find(link=>link.getAttribute('data-dnssec-source-key')===sourceFocused)?.focus({preventScroll:true});
    }
    const chapters=this.labModel?.chapters||[],controls=this.querySelector('#lesson-chapters');controls.hidden=!chapters.length;
    if(!chapters.length){if(controls.children.length)controls.innerHTML='';this.chapterControlsModel=null;return;}
    if(this.chapterControlsModel!==this.labModel||this.chapterControlsLocaleRevision!==this.localizer.revision){
      this.chapterControlsModel=this.labModel;this.chapterControlsLocaleRevision=this.localizer.revision;
      controls.innerHTML='<p class="locale-prose">'+(this.labModel?.chapterCaption?lesson('chapterCaption',this.labModel.chapterCaption):this.ui('ui.decisions.chapterCaption','Linked chapters share one canonical history. Jumping seeks that history, not a new grant.'))+'</p><div class="chapter-buttons">'+chapters.map(chapter=>{const labelRef={ownerId:owner,fieldPath:'chapters.label',source:chapter.label,context:contextFor('chapters:'+chapter.id)};return `<button type="button" class="button quiet locale-prose" data-lesson-chapter="${escapeHtml(chapter.id)}" ${chapter.stepIds.length?'':'disabled'}>${chapter.stepIds.length?lesson('chapters.label',chapter.label,'chapters:'+chapter.id):this.ui('ui.decisions.chapterNotReached',chapter.label+' - not reached in this case',{label:labelRef})}</button>`;}).join('')+'</div><div id="chapter-token-comparison"></div>';
    }
    controls.querySelectorAll('[data-lesson-chapter]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.lessonChapter===this.graphChapter?.id)));
    const comparison=controls.querySelector('#chapter-token-comparison'),tokens=this.labModel?.chapterComparison||[];
    const holdings=tokens.length?this.heldView.snapshot().holdings:null;
    if(comparison)comparison.innerHTML=tokens.length?'<div class="instance-table-scroll" dir="ltr" data-technical-ltr><table class="instance-table"><thead><tr>'+'<th class="locale-prose">'+this.ui('ui.decisions.separateCredential','Separate credential')+'</th><th class="locale-prose">'+this.ui('ui.decisions.issuer','Issuer')+'</th><th class="locale-prose">'+this.ui('ui.decisions.resource','Resource')+'</th><th class="locale-prose">'+this.ui('ui.decisions.currentPrefix','Current prefix')+'</th>'+'</tr></thead><tbody>'+tokens.map(token=>`<tr><td class="locale-prose">${lesson('chapterComparison.label',token.label,'chapterComparison:'+token.artifactId)}<br><code ${this.rawValueAttrs(token.artifactId)}>${escapeHtml(token.artifactId)}</code></td><td>${this.ltr(token.issuer)}</td><td>${this.ltr(token.resource)}</td><td class="locale-prose">${holdings.some(holding=>holding.artifactId===token.artifactId)?this.ui('ui.decisions.heldNotPermission','A representation is held; this alone is not validation or permission.'):this.ui('ui.decisions.notHeld','Not held in this source prefix.')}</td></tr>`).join('')+'</tbody></table></div>':'';
  }
  renderWindowsRemoteEvidence(snapshot){
    const panel=this.querySelector('#windows-remote-evidence');
    if(this.labModel?.family!=='windows-remote-administration'){panel.hidden=true;if(this.remoteEvidenceKey!==null){panel.innerHTML='';this.remoteEvidenceKey=null;}return;}
    const state=snapshot.state.workstation,policy=state.policyComparison,comparison=state.tokenComparison,key=JSON.stringify([this.heldView.contextId,snapshot.cursor,this.localizer.revision]);
    panel.hidden=!(policy||comparison||state.verdictExplanation||state.localComparisonQualification);
    if(this.remoteEvidenceKey===key)return;this.remoteEvidenceKey=key;
    const raw=item=>{const text=formatProtocolValue(item,true);return '<span '+this.rawValueAttrs(text)+'>'+this.ltr(text)+'</span>';};
    const value=item=>item===null||item===undefined?this.ui('ui.app.renderWindowsRemoteEvidence.notApplied','Not applied'):raw(item);
    const prose=(path,item)=>item===null||item===undefined?value(item):this.prose('lesson:'+this.labModel.id,'snapshot.state.workstation.'+path,item,this.localeContext());
    const policyValue=record=>record?(record.rawLATFP===null?this.ui('ui.app.renderWindowsRemoteEvidence.absentEffective','absent; '+record.effectiveLATFP,{effective:record.effectiveLATFP}):raw([record.latfpDisplay,record.effectiveLATFP].join('; '))):value(null);
    const policyRows=policy?[
      [prose('policyComparison.label',policy.label),prose('policyComparison.configured.restrictionsDisplay',policy.configured.restrictionsDisplay),prose('policyComparison.applied.restrictionsDisplay',policy.applied?.restrictionsDisplay)],
      [this.ui('ui.app.renderWindowsRemoteEvidence.rawEffective',policy.registryValueName+' (raw; effective)',{registryValueName:policy.registryValueName}),policyValue(policy.configured),policyValue(policy.applied)],
      [raw('EnableLUA'),value(policy.configured.EnableLUA),value(policy.applied?.EnableLUA)],
      [raw('FilterAdministratorToken'),value(policy.configured.FilterAdministratorToken),value(policy.applied?.FilterAdministratorToken)],
      [raw('Administrator Protection'),value(policy.configured.administratorProtection),value(policy.applied?.administratorProtection)],
    ]:[];
    if(state.configuredPolicy?.administratorProtection){
      policyRows.push([raw(state.configuredPolicy.apBroadPolicyLabel),value(state.configuredPolicy.apBroad),value(state.appliedPolicy?.apBroad)]);
      policyRows.push([raw(state.configuredPolicy.apListPolicyLabel),state.configuredPolicy.apSIDList.length?raw(state.configuredPolicy.apSIDList.join(', ')):this.ui('ui.app.renderWindowsRemoteEvidence.emptySidList','Empty SID list'),state.appliedPolicy?(state.appliedPolicy.apSIDList.length?raw(state.appliedPolicy.apSIDList.join(', ')):this.ui('ui.app.renderWindowsRemoteEvidence.emptySidList','Empty SID list')):value(null)]);
    }
    const table=(id,caption,captionText,headings,rows)=>'<div class="instance-table-scroll" data-technical-ltr dir="ltr" data-study-key="'+id+'" tabindex="0" aria-label="'+escapeHtml(captionText)+'"><table class="instance-table"><caption class="locale-prose" data-copy-disabled>'+caption+'</caption><thead><tr>'+headings.map(heading=>'<th scope="col" class="locale-prose" data-copy-disabled>'+heading+'</th>').join('')+'</tr></thead><tbody>'+rows.map(([label,...cells])=>'<tr><th scope="row" class="locale-prose" data-copy-disabled>'+label+'</th>'+cells.map(cell=>'<td class="locale-prose" data-copy-disabled>'+cell+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
    const open=panel.querySelector('[data-remote-comparison]')?.hasAttribute('open'),focused=document.activeElement===panel.querySelector('[data-remote-comparison] > summary');
    const tokenRows=comparison?[
      [this.ui('ui.app.renderWindowsRemoteEvidence.contextRole','Context role'),prose('tokenComparison.before.label',comparison.before.label),raw(comparison.after.type+' / '+comparison.after.mode)],
      [this.ui('ui.app.renderWindowsRemoteEvidence.logicalOwner','Logical owner'),raw(this.actor(comparison.before.owner).name),raw(this.actor(comparison.after.owner).name)],
      [this.ui('ui.app.renderWindowsRemoteEvidence.account','Account'),value(comparison.before.account),value(comparison.after.account)],
      [this.ui('ui.app.renderWindowsRemoteEvidence.accountSid','Account SID'),value(comparison.before.userSid),value(comparison.after.userSid)],
      ...comparison.groups.map(group=>[raw('SID '+group.sid),group.beforeAttributes.length?raw(group.beforeAttributes.join(', ')):this.ui('ui.app.renderWindowsRemoteEvidence.notPresent','Not present'),group.afterAttributes.length?raw(group.afterAttributes.join(', ')):this.ui('ui.app.renderWindowsRemoteEvidence.notPresent','Not present')]),
      ...comparison.privileges.map(privilege=>[raw(privilege.name),value(privilege.before.state),value(privilege.after.state)]),
      [this.ui('ui.app.renderWindowsRemoteEvidence.nativeIntegrity','Native integrity / elevation type'),raw(comparison.before.integrity+' / '+comparison.before.elevationType),raw(comparison.after.integrity+' / '+comparison.after.elevationType)],
    ]:[];
    panel.innerHTML=(state.verdictExplanation?'<p class="windows-verdict locale-prose" data-study-key="windows-verdict" data-copy-disabled data-windows-verdict>'+prose('verdictExplanation',state.verdictExplanation)+'</p>':'')+
      (state.localComparisonQualification?'<p class="environment-note locale-prose" data-study-key="local-comparison-qualification" data-copy-disabled data-local-comparison-qualification>'+prose('localComparisonQualification',state.localComparisonQualification)+'</p>':'')+
      (policy?'<h3 class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderWindowsRemoteEvidence.configuredPolicy','Configured policy versus the current target context')+'</h3><p class="locale-prose" data-copy-disabled>'+raw(policy.policyLabel)+' · '+prose('policyComparison.polarity',policy.polarity)+'</p>'+table('remote-policy-snapshots',this.ui('ui.app.renderWindowsRemoteEvidence.policySnapshots','Remote policy snapshots'),this.uiText('ui.app.renderWindowsRemoteEvidence.policySnapshots','Remote policy snapshots'),[this.ui('ui.app.renderWindowsRemoteEvidence.control','Control'),this.ui('ui.app.renderWindowsRemoteEvidence.configuredReference','Configured reference'),this.ui('ui.app.renderWindowsRemoteEvidence.appliedAtCreation','Applied at context creation')],policyRows)+'<p class="locale-prose" data-copy-disabled>'+prose('policyComparison.appliedStatus',policy.appliedStatus)+' '+prose('policyComparison.scope',policy.scope)+' '+this.ui('ui.app.renderWindowsRemoteEvidence.caseReset','Selecting a case resets this demonstration; it does not change a production policy.')+'</p>':'')+
      (comparison?'<details data-remote-comparison data-study-key="remote-token-comparison"'+(open?' open':'')+'><summary class="locale-prose" data-copy-disabled>'+this.ui('ui.app.renderWindowsRemoteEvidence.compareContext','Compare target-side filter input and applied context')+'</summary><p class="locale-prose" data-copy-disabled>'+prose('tokenComparison.before.scope',comparison.before.scope)+'. '+prose('tokenComparison.evidenceLevel',comparison.evidenceLevel)+'. '+this.ui('ui.app.renderWindowsRemoteEvidence.separateAttributes','Directory membership and SID attributes are separate; a removed privilege is not a disabled privilege.')+'</p>'+table('remote-target-context',this.ui('ui.app.renderWindowsRemoteEvidence.beforeAfter','Before / after target authorization context'),this.uiText('ui.app.renderWindowsRemoteEvidence.beforeAfter','Before / after target authorization context'),[this.ui('ui.app.renderWindowsRemoteEvidence.field','Field'),this.ui('ui.app.renderWindowsRemoteEvidence.before','Before: modeled target input'),this.ui('ui.app.renderWindowsRemoteEvidence.after','After: current target context')],tokenRows)+'</details>':'');
    if(focused)panel.querySelector('[data-remote-comparison] > summary')?.focus({preventScroll:true});
  }
  dnssecDecisionDisplay(path,value,state){
    if(path==='dnssec.validationOwner'||path==='dnssec.firstDetector')return this.ltr(this.actor(value).name);
    if(path==='dnssec.anchorRef')return this.ui('ui.dnssec.provisionedAnchor','Explicitly provisioned trust anchor');
    if(path==='dnssec.reasonCode'){
      if(value==='authenticated-parent-proves-unsigned-delegation')return state?.applicationResult?.policy==='secure-only'&&state.applicationResult.status==='refused'?this.ui('ui.dnssec.unsignedRefused','Authenticated evidence of an unsigned delegation gives an insecure result. This is not a finding that the answer was forged. The selected secure-only application refuses it.',{status:'insecure',policy:'secure-only'}):this.ui('ui.dnssec.unsignedSeparatePolicy','Authenticated evidence of an unsigned delegation gives an insecure result. This is not a finding that the answer was forged. Application policy is evaluated separately.',{status:'insecure'});
      const explanations={
      "awaiting-data":()=>this.ui("ui.dnssec.reason.awaiting-data","Waiting for data; no validation decision yet.",{}),
      "complete-anchor-ds-dnskey-answer-path":()=>this.ui("ui.dnssec.reason.complete-anchor-ds-dnskey-answer-path","The answer is authenticated through the configured anchor, parent DS and child DNSKEY.",{"ds":"DS","dnskey":"DNSKEY"}),
      "validated-exact-answer-cache-reuse":()=>this.ui("ui.dnssec.reason.validated-exact-answer-cache-reuse","Reusing the exact previously authenticated answer; no fresh signature check.",{}),
      "cached-parent-chain-fresh-child-and-answer":()=>this.ui("ui.dnssec.reason.cached-parent-chain-fresh-child-and-answer","Using the authenticated parent cache, then checking the fresh child keys and answer.",{}),
      "authenticated-cache-can-retain-ad-for-cd-one":()=>this.ui("ui.dnssec.reason.authenticated-cache-can-retain-ad-for-cd-one","The earlier authenticated cache result can retain AD, even for this CD=1 query.",{"ad":"AD","cd":"CD=1"}),
      "fresh-cd-one-query-bypasses-cd-zero-upstream-error-context":()=>this.ui("ui.dnssec.reason.fresh-cd-one-query-bypasses-cd-zero-upstream-error-context","A fresh CD=1 query bypassed the separate cached CD=0 upstream SERVFAIL context.",{"freshCD":"CD=1","cachedCD":"CD=0","rcode":"SERVFAIL"}),
      "trusted-resolver-ad-assertion-not-stub-independent-check":()=>this.ui("ui.dnssec.reason.trusted-resolver-ad-assertion-not-stub-independent-check","The stub relies on its configured resolver and trusted channel, not an independent stub signature check.",{}),
      "ad-without-trusted-resolver-and-channel-is-insufficient":()=>this.ui("ui.dnssec.reason.ad-without-trusted-resolver-and-channel-is-insufficient","An AD assertion without a trusted resolver and channel is insufficient for application use.",{"ad":"AD"}),
      "upstream-validation-failure-no-raw-data-for-local-check":()=>this.ui("ui.dnssec.reason.upstream-validation-failure-no-raw-data-for-local-check","The upstream returned SERVFAIL without raw records for an independent local check.",{"rcode":"SERVFAIL"}),
      "answer-rdata-does-not-match-signature":()=>this.ui("ui.dnssec.reason.answer-rdata-does-not-match-signature","The received answer data do not match the signed record occurrence.",{})
      };
      if(Object.hasOwn(explanations,value))return explanations[value]();
    }
    if(path==='dnssec.securityStatus'){
      const statuses={
      "secure":()=>this.ui("ui.dnssec.status.secure","Secure - authenticated",{"status":"Secure"}),
      "insecure":()=>this.ui("ui.dnssec.status.insecure","Insecure - no secure signed path",{"status":"Insecure"}),
      "bogus":()=>this.ui("ui.dnssec.status.bogus","Bogus - validation failed",{"status":"Bogus"}),
      "indeterminate":()=>this.ui("ui.dnssec.status.indeterminate","Indeterminate - trust could not be established",{"status":"Indeterminate"}),
      "not-checked":()=>this.ui("ui.dnssec.status.not-checked","Not checked",{})
      };
      if(Object.hasOwn(statuses,value))return statuses[value]();
    }
    switch(String(value)){
      case "absent":return this.ui("ui.dnssec.decisionLabel.absent","Absent");
      case "all-authority-attempts-time-out-before-proof-receipt":return this.ui("ui.dnssec.decisionLabel.all-authority-attempts-time-out-before-proof-receipt","All authority attempts time out before proof receipt");
      case "ancestor-proof-cannot-deny-below-child-delegation":return this.ui("ui.dnssec.decisionLabel.ancestor-proof-cannot-deny-below-child-delegation","Ancestor proof cannot deny below child delegation");
      case "anchor-add-after-authenticated-reset":return this.ui("ui.dnssec.decisionLabel.anchor-add-after-authenticated-reset","Anchor add after authenticated reset");
      case "anchor-add-hold-down-complete":return this.ui("ui.dnssec.decisionLabel.anchor-add-hold-down-complete","Anchor add hold down complete");
      case "anchor-provisioned-and-dnskey-matched":return this.rich("ui.dnssec.decisionLabel.anchor-provisioned-and-dnskey-matched","Anchor provisioned and {dnskey} matched",{"dnskey":{"kind":"protected","value":"dnskey"}});
      case "anchor-revoked-and-bookkeeping-removed":return this.ui("ui.dnssec.decisionLabel.anchor-revoked-and-bookkeeping-removed","Anchor revoked and bookkeeping removed");
      case "answer":return this.ui("ui.dnssec.decisionLabel.answer","Answer");
      case "authenticate-dname-check-synthesis-then-target":return this.rich("ui.dnssec.decisionLabel.authenticate-dname-check-synthesis-then-target","Authenticate {dname} check synthesis then target",{"dname":{"kind":"protected","value":"dname"}});
      case "authenticated-bootstrap-published":return this.ui("ui.dnssec.decisionLabel.authenticated-bootstrap-published","Authenticated bootstrap published");
      case "authenticated-ds-has-no-supported-algorithm-or-digest-path":return this.rich("ui.dnssec.decisionLabel.authenticated-ds-has-no-supported-algorithm-or-digest-path","Authenticated {ds} has no supported algorithm or digest path",{"ds":{"kind":"protected","value":"ds"}});
      case "authenticated-ds-removal-published":return this.rich("ui.dnssec.decisionLabel.authenticated-ds-removal-published","Authenticated {ds} removal published",{"ds":{"kind":"protected","value":"ds"}});
      case "authenticated-name-and-wildcard-absence":return this.ui("ui.dnssec.decisionLabel.authenticated-name-and-wildcard-absence","Authenticated name and wildcard absence");
      case "authenticated-optout-delegation-not-wide-name-absence":return this.rich("ui.dnssec.decisionLabel.authenticated-optout-delegation-not-wide-name-absence","Authenticated {optout} delegation not wide name absence",{"optout":{"kind":"protected","value":"optout"}});
      case "authenticated-parent-ds-and-child-key":return this.rich("ui.dnssec.decisionLabel.authenticated-parent-ds-and-child-key","Authenticated parent {ds} and child key",{"ds":{"kind":"protected","value":"ds"}});
      case "authenticated-supported-ds-has-no-matching-child-key":return this.rich("ui.dnssec.decisionLabel.authenticated-supported-ds-has-no-matching-child-key","Authenticated supported {ds} has no matching child key",{"ds":{"kind":"protected","value":"ds"}});
      case "authenticated-transport-with-independent-bogus-dnssec":return this.rich("ui.dnssec.decisionLabel.authenticated-transport-with-independent-bogus-dnssec","Authenticated transport with independent {bogus} {dnssec}",{"bogus":{"kind":"protected","value":"bogus"},"dnssec":{"kind":"protected","value":"dnssec"}});
      case "authenticated-transport-with-independent-secure-dnssec":return this.rich("ui.dnssec.decisionLabel.authenticated-transport-with-independent-secure-dnssec","Authenticated transport with independent {secure} {dnssec}",{"secure":{"kind":"protected","value":"secure"},"dnssec":{"kind":"protected","value":"dnssec"}});
      case "authenticated-trust-point-observation":return this.ui("ui.dnssec.decisionLabel.authenticated-trust-point-observation","Authenticated trust point observation");
      case "authenticated-unsupported-ds-digest":return this.rich("ui.dnssec.decisionLabel.authenticated-unsupported-ds-digest","Authenticated unsupported {ds} digest",{"ds":{"kind":"protected","value":"ds"}});
      case "authenticated-unsupported-signing-algorithm":return this.ui("ui.dnssec.decisionLabel.authenticated-unsupported-signing-algorithm","Authenticated unsupported signing algorithm");
      case "bootstrap-no-independent-authentication":return this.ui("ui.dnssec.decisionLabel.bootstrap-no-independent-authentication","Bootstrap no independent authentication");
      case "bootstrap-only-in-domain-nameservers":return this.ui("ui.dnssec.decisionLabel.bootstrap-only-in-domain-nameservers","Bootstrap only in domain nameservers");
      case "bootstrap-signaling-zone-insecure":return this.rich("ui.dnssec.decisionLabel.bootstrap-signaling-zone-insecure","Bootstrap signaling zone {insecure}",{"insecure":{"kind":"protected","value":"insecure"}});
      case "cached-co-nxdomain-reset-to-noerror-for-do-one-co-zero":return this.rich("ui.dnssec.decisionLabel.cached-co-nxdomain-reset-to-noerror-for-do-one-co-zero","Cached {co} {nxdomain} reset to {noerror} for {do} one {co} zero",{"co":{"kind":"protected","value":"co"},"nxdomain":{"kind":"protected","value":"nxdomain"},"noerror":{"kind":"protected","value":"noerror"},"do":{"kind":"protected","value":"do"}});
      case "cached-locally-established-failure-suppresses-network":return this.ui("ui.dnssec.decisionLabel.cached-locally-established-failure-suppresses-network","Cached locally established failure suppresses network");
      case "cached-signature-key-unavailable":return this.ui("ui.dnssec.decisionLabel.cached-signature-key-unavailable","Cached signature key unavailable");
      case "cached-wildcard-plus-valid-no-closer-proof":return this.ui("ui.dnssec.decisionLabel.cached-wildcard-plus-valid-no-closer-proof","Cached wildcard plus valid no closer proof");
      case "canonical-rrset-differs-from-signed-input":return this.rich("ui.dnssec.decisionLabel.canonical-rrset-differs-from-signed-input","Canonical {rrset} differs from signed input",{"rrset":{"kind":"protected","value":"rrset"}});
      case "cds-cdnskey-keyset-disagreement":return this.rich("ui.dnssec.decisionLabel.cds-cdnskey-keyset-disagreement","{cds} {cdnskey} keyset disagreement",{"cds":{"kind":"protected","value":"Cds"},"cdnskey":{"kind":"protected","value":"cdnskey"}});
      case "co-enabled-hops-restore-nxdomain-with-signed-nxname":return this.rich("ui.dnssec.decisionLabel.co-enabled-hops-restore-nxdomain-with-signed-nxname","{co} enabled hops restore {nxdomain} with signed {nxname}",{"co":{"kind":"protected","value":"Co"},"nxdomain":{"kind":"protected","value":"nxdomain"},"nxname":{"kind":"protected","value":"nxname"}});
      case "compact-ent-matching-proof-without-nxname":return this.rich("ui.dnssec.decisionLabel.compact-ent-matching-proof-without-nxname","Compact {ent} matching proof without {nxname}",{"ent":{"kind":"protected","value":"ent"},"nxname":{"kind":"protected","value":"nxname"}});
      case "compact-exact-owner-existing-type-absence-without-nxname":return this.rich("ui.dnssec.decisionLabel.compact-exact-owner-existing-type-absence-without-nxname","Compact exact owner existing type absence without {nxname}",{"nxname":{"kind":"protected","value":"nxname"}});
      case "complete-edns-udp-answer-validated":return this.rich("ui.dnssec.decisionLabel.complete-edns-udp-answer-validated","Complete {edns} {udp} answer validated",{"edns":{"kind":"protected","value":"edns"},"udp":{"kind":"protected","value":"udp"}});
      case "configured-private-anchor-no-longer-authenticates-new-key-generation":return this.ui("ui.dnssec.decisionLabel.configured-private-anchor-no-longer-authenticates-new-key-generation","Configured private anchor no longer authenticates new key generation");
      case "conflicting-provider-cds-intent":return this.rich("ui.dnssec.decisionLabel.conflicting-provider-cds-intent","Conflicting provider {cds} intent",{"cds":{"kind":"protected","value":"cds"}});
      case "cross-provider-key-unavailable":return this.ui("ui.dnssec.decisionLabel.cross-provider-key-unavailable","Cross provider key unavailable");
      case "declared-trusted-upstream-remote-assertion":return this.ui("ui.dnssec.decisionLabel.declared-trusted-upstream-remote-assertion","Declared trusted upstream remote assertion");
      case "descendant-proves-ent-exists-without-requested-rrset":return this.rich("ui.dnssec.decisionLabel.descendant-proves-ent-exists-without-requested-rrset","Descendant proves {ent} exists without requested {rrset}",{"ent":{"kind":"protected","value":"ent"},"rrset":{"kind":"protected","value":"rrset"}});
      case "dnskey-protocol-field-invalid-for-verification":return this.rich("ui.dnssec.decisionLabel.dnskey-protocol-field-invalid-for-verification","{dnskey} protocol field invalid for verification",{"dnskey":{"kind":"protected","value":"Dnskey"}});
      case "dnskey-without-zone-flag-cannot-verify-rrset":return this.rich("ui.dnssec.decisionLabel.dnskey-without-zone-flag-cannot-verify-rrset","{dnskey} without zone flag cannot verify {rrset}",{"dnskey":{"kind":"protected","value":"Dnskey"},"rrset":{"kind":"protected","value":"rrset"}});
      case "ds-absent":return this.rich("ui.dnssec.decisionLabel.ds-absent","{ds} absent",{"ds":{"kind":"protected","value":"Ds"}});
      case "ds-boot":return this.rich("ui.dnssec.decisionLabel.ds-boot","{ds} boot",{"ds":{"kind":"protected","value":"Ds"}});
      case "ds-manual-k1":return this.rich("ui.dnssec.decisionLabel.ds-manual-k1","{ds} manual {k1}",{"ds":{"kind":"protected","value":"Ds"},"k1":{"kind":"protected","value":"k1"}});
      case "ds0":return this.rich("ui.dnssec.decisionLabel.ds0","{identifier}",{"identifier":{"kind":"protected","value":"Ds0"}});
      case "ds01":return this.rich("ui.dnssec.decisionLabel.ds01","{identifier}",{"identifier":{"kind":"protected","value":"Ds01"}});
      case "each-link-and-target-authenticated":return this.ui("ui.dnssec.decisionLabel.each-link-and-target-authenticated","Each link and target authenticated");
      case "eligible-keysets-consistent":return this.ui("ui.dnssec.decisionLabel.eligible-keysets-consistent","Eligible keysets consistent");
      case "empty-applicable-trust-store-not-authenticated-insecurity":return this.ui("ui.dnssec.decisionLabel.empty-applicable-trust-store-not-authenticated-insecurity","Empty applicable trust store not authenticated insecurity");
      case "error":return this.ui("ui.dnssec.decisionLabel.error","Error");
      case "exact-authenticated-negative-cache-reuse":return this.ui("ui.dnssec.decisionLabel.exact-authenticated-negative-cache-reuse","Exact authenticated negative cache reuse");
      case "exact-owner-bitmap-denies-type-and-cname":return this.rich("ui.dnssec.decisionLabel.exact-owner-bitmap-denies-type-and-cname","Exact owner bitmap denies type and {cname}",{"cname":{"kind":"protected","value":"cname"}});
      case "exact-positive-cache-still-eligible-after-publication-change":return this.ui("ui.dnssec.decisionLabel.exact-positive-cache-still-eligible-after-publication-change","Exact positive cache still eligible after publication change");
      case "expired-cache-excluded-fresh-evidence-validated":return this.ui("ui.dnssec.decisionLabel.expired-cache-excluded-fresh-evidence-validated","Expired cache excluded fresh evidence validated");
      case "explicit-dnskey-answer-not-suppressed-by-do-zero":return this.rich("ui.dnssec.decisionLabel.explicit-dnskey-answer-not-suppressed-by-do-zero","Explicit {dnskey} answer not suppressed by {do} zero",{"dnskey":{"kind":"protected","value":"dnskey"},"do":{"kind":"protected","value":"do"}});
      case "failure-cache-expired-requery-and-revalidate-repaired-data":return this.ui("ui.dnssec.decisionLabel.failure-cache-expired-requery-and-revalidate-repaired-data","Failure cache expired requery and revalidate repaired data");
      case "forwarding-route-unreachable-after-bounded-attempts":return this.ui("ui.dnssec.decisionLabel.forwarding-route-unreachable-after-bounded-attempts","Forwarding route unreachable after bounded attempts");
      case "g0":return this.rich("ui.dnssec.decisionLabel.g0","{identifier}",{"identifier":{"kind":"protected","value":"G0"}});
      case "g1":return this.rich("ui.dnssec.decisionLabel.g1","{identifier}",{"identifier":{"kind":"protected","value":"G1"}});
      case "inconsistent-authority-intent":return this.ui("ui.dnssec.decisionLabel.inconsistent-authority-intent","Inconsistent authority intent");
      case "independent-upstream-and-local-checks":return this.ui("ui.dnssec.decisionLabel.independent-upstream-and-local-checks","Independent upstream and local checks");
      case "independently-provisioned-child-anchor":return this.ui("ui.dnssec.decisionLabel.independently-provisioned-child-anchor","Independently provisioned child anchor");
      case "invalid-metatype-query-rejected-locally":return this.ui("ui.dnssec.decisionLabel.invalid-metatype-query-rejected-locally","Invalid metatype query rejected locally");
      case "known-secure-answer-with-required-dnssec-data-stripped":return this.rich("ui.dnssec.decisionLabel.known-secure-answer-with-required-dnssec-data-stripped","Known {secure} answer with required {dnssec} data stripped",{"secure":{"kind":"protected","value":"secure"},"dnssec":{"kind":"protected","value":"dnssec"}});
      case "known-secure-path-missing-stripped-dnssec-records":return this.rich("ui.dnssec.decisionLabel.known-secure-path-missing-stripped-dnssec-records","Known {secure} path missing stripped {dnssec} records",{"secure":{"kind":"protected","value":"secure"},"dnssec":{"kind":"protected","value":"dnssec"}});
      case "lab.example.":return this.rich("ui.dnssec.decisionLabel.lab.example.","{identifier}",{"identifier":{"kind":"protected","value":"Lab.example."}});
      case "lagged-signature-key-unavailable":return this.ui("ui.dnssec.decisionLabel.lagged-signature-key-unavailable","Lagged signature key unavailable");
      case "leaf-signature-verification-failed":return this.ui("ui.dnssec.decisionLabel.leaf-signature-verification-failed","Leaf signature verification failed");
      case "local-check-fails-on-unchecked-upstream-answer":return this.ui("ui.dnssec.decisionLabel.local-check-fails-on-unchecked-upstream-answer","Local check fails on unchecked upstream answer");
      case "local-checks-data-fetched-by-upstream":return this.ui("ui.dnssec.decisionLabel.local-checks-data-fetched-by-upstream","Local checks data fetched by upstream");
      case "local-private-anchor-authenticates-declared-view":return this.ui("ui.dnssec.decisionLabel.local-private-anchor-authenticates-declared-view","Local private anchor authenticates declared view");
      case "malformed-delete-signal":return this.ui("ui.dnssec.decisionLabel.malformed-delete-signal","Malformed delete signal");
      case "manual-anchor-recovery-validated":return this.ui("ui.dnssec.decisionLabel.manual-anchor-recovery-validated","Manual anchor recovery validated");
      case "manual-anchor-reset-awaiting-dnskey-check":return this.rich("ui.dnssec.decisionLabel.manual-anchor-reset-awaiting-dnskey-check","Manual anchor reset awaiting {dnskey} check",{"dnskey":{"kind":"protected","value":"dnskey"}});
      case "manual-and-automatic-channel-state-distinguished":return this.ui("ui.dnssec.decisionLabel.manual-and-automatic-channel-state-distinguished","Manual and automatic channel state distinguished");
      case "matching-qname-hash-bitmap-denies-aaaa-and-cname":return this.rich("ui.dnssec.decisionLabel.matching-qname-hash-bitmap-denies-aaaa-and-cname","Matching {qname} hash bitmap denies {aaaa} and {cname}",{"qname":{"kind":"protected","value":"qname"},"aaaa":{"kind":"protected","value":"aaaa"},"cname":{"kind":"protected","value":"cname"}});
      case "minimally-covering-proof-cannot-deny-other-name-or-subtree":return this.ui("ui.dnssec.decisionLabel.minimally-covering-proof-cannot-deny-other-name-or-subtree","Minimally covering proof cannot deny other name or subtree");
      case "missing-authenticated-delegation-proof-after-parent-requery":return this.ui("ui.dnssec.decisionLabel.missing-authenticated-delegation-proof-after-parent-requery","Missing authenticated delegation proof after parent requery");
      case "name-interval-alone-does-not-exclude-wildcard":return this.ui("ui.dnssec.decisionLabel.name-interval-alone-does-not-exclude-wildcard","Name interval alone does not exclude wildcard");
      case "negative":return this.ui("ui.dnssec.decisionLabel.negative","Negative");
      case "new-negative-answer-synthesized-from-validated-proof-cache":return this.ui("ui.dnssec.decisionLabel.new-negative-answer-synthesized-from-validated-proof-cache","New negative answer synthesized from validated proof cache");
      case "no-applicable-trust-anchor-anywhere":return this.ui("ui.dnssec.decisionLabel.no-applicable-trust-anchor-anywhere","No applicable trust anchor anywhere");
      case "no-covering-trust-anchor":return this.ui("ui.dnssec.decisionLabel.no-covering-trust-anchor","No covering trust anchor");
      case "no-usable-notification-endpoint":return this.ui("ui.dnssec.decisionLabel.no-usable-notification-endpoint","No usable notification endpoint");
      case "nodata-delete-inconsistency":return this.rich("ui.dnssec.decisionLabel.nodata-delete-inconsistency","{nodata} delete inconsistency",{"nodata":{"kind":"protected","value":"Nodata"}});
      case "notified-checked-ds-update-published":return this.rich("ui.dnssec.decisionLabel.notified-checked-ds-update-published","Notified checked {ds} update published",{"ds":{"kind":"protected","value":"ds"}});
      case "nsec-proves-query-and-closest-wildcard-absent":return this.rich("ui.dnssec.decisionLabel.nsec-proves-query-and-closest-wildcard-absent","{nsec} proves query and closest wildcard absent",{"nsec":{"kind":"protected","value":"Nsec"}});
      case "nsec3-closest-encloser-next-closer-and-wildcard-proved":return this.rich("ui.dnssec.decisionLabel.nsec3-closest-encloser-next-closer-and-wildcard-proved","{nsec3} closest encloser next closer and wildcard proved",{"nsec3":{"kind":"protected","value":"Nsec3"}});
      case "nsec3-covering-hashes-without-matching-closest-encloser":return this.rich("ui.dnssec.decisionLabel.nsec3-covering-hashes-without-matching-closest-encloser","{nsec3} covering hashes without matching closest encloser",{"nsec3":{"kind":"protected","value":"Nsec3"}});
      case "one-usable-valid-signature-is-sufficient":return this.ui("ui.dnssec.decisionLabel.one-usable-valid-signature-is-sufficient","One usable valid signature is sufficient");
      case "operator-nta-validation-bypass":return this.rich("ui.dnssec.decisionLabel.operator-nta-validation-bypass","Operator {nta} validation bypass",{"nta":{"kind":"protected","value":"nta"}});
      case "operator-unsupported-sha1-signature":return this.rich("ui.dnssec.decisionLabel.operator-unsupported-sha1-signature","Operator unsupported {sha1} signature",{"sha1":{"kind":"protected","value":"sha1"}});
      case "parent-authenticated-ds-nodata-child-is-insecure":return this.rich("ui.dnssec.decisionLabel.parent-authenticated-ds-nodata-child-is-insecure","Parent authenticated {ds} {nodata} child is {insecure}",{"ds":{"kind":"protected","value":"ds"},"nodata":{"kind":"protected","value":"nodata"},"insecure":{"kind":"protected","value":"insecure"}});
      case "parent-ds-update-after-retry":return this.rich("ui.dnssec.decisionLabel.parent-ds-update-after-retry","Parent {ds} update after retry",{"ds":{"kind":"protected","value":"ds"}});
      case "parent-ds-update-published":return this.rich("ui.dnssec.decisionLabel.parent-ds-update-published","Parent {ds} update published",{"ds":{"kind":"protected","value":"ds"}});
      case "parent-policy-declines-bootstrap":return this.ui("ui.dnssec.decisionLabel.parent-policy-declines-bootstrap","Parent policy declines bootstrap");
      case "pending":return this.ui("ui.dnssec.decisionLabel.pending","Pending");
      case "private-dnskey-conflicts-with-authenticated-public-ds":return this.rich("ui.dnssec.decisionLabel.private-dnskey-conflicts-with-authenticated-public-ds","Private {dnskey} conflicts with authenticated public {ds}",{"dnskey":{"kind":"protected","value":"dnskey"},"ds":{"kind":"protected","value":"ds"}});
      case "private-route-plus-independent-locally-provisioned-anchor":return this.ui("ui.dnssec.decisionLabel.private-route-plus-independent-locally-provisioned-anchor","Private route plus independent locally provisioned anchor");
      case "proof-records-do-not-form-single-nsec3-parameter-chain":return this.rich("ui.dnssec.decisionLabel.proof-records-do-not-form-single-nsec3-parameter-chain","Proof records do not form single {nsec3} parameter chain",{"nsec3":{"kind":"protected","value":"nsec3"}});
      case "provisioned-anchor-awaiting-dnskey-check":return this.rich("ui.dnssec.decisionLabel.provisioned-anchor-awaiting-dnskey-check","Provisioned anchor awaiting {dnskey} check",{"dnskey":{"kind":"protected","value":"dnskey"}});
      case "refused":return this.ui("ui.dnssec.decisionLabel.refused","Refused");
      case "reject-ineligible-synthesis-and-fetch-authoritative-answer":return this.ui("ui.dnssec.decisionLabel.reject-ineligible-synthesis-and-fetch-authoritative-answer","Reject ineligible synthesis and fetch authoritative answer");
      case "reported-and-retried-update-published":return this.ui("ui.dnssec.decisionLabel.reported-and-retried-update-published","Reported and retried update published");
      case "requested-ds-would-break-validation":return this.rich("ui.dnssec.decisionLabel.requested-ds-would-break-validation","Requested {ds} would break validation",{"ds":{"kind":"protected","value":"ds"}});
      case "required-matching-dnskey-absent-after-refetch":return this.rich("ui.dnssec.decisionLabel.required-matching-dnskey-absent-after-refetch","Required matching {dnskey} absent after refetch",{"dnskey":{"kind":"protected","value":"dnskey"}});
      case "resolver-checks-unaware-stub-does-not":return this.ui("ui.dnssec.decisionLabel.resolver-checks-unaware-stub-does-not","Resolver checks unaware stub does not");
      case "resolver-clock-skew-causes-time-validation-failure":return this.ui("ui.dnssec.decisionLabel.resolver-clock-skew-causes-time-validation-failure","Resolver clock skew causes time validation failure");
      case "rrsig-expired-at-resolver-clock":return this.rich("ui.dnssec.decisionLabel.rrsig-expired-at-resolver-clock","{rrsig} expired at resolver clock",{"rrsig":{"kind":"protected","value":"Rrsig"}});
      case "rrsig-inception-after-resolver-clock":return this.rich("ui.dnssec.decisionLabel.rrsig-inception-after-resolver-clock","{rrsig} inception after resolver clock",{"rrsig":{"kind":"protected","value":"Rrsig"}});
      case "rrsig-signer-or-key-does-not-match-authoritative-zone":return this.rich("ui.dnssec.decisionLabel.rrsig-signer-or-key-does-not-match-authoritative-zone","{rrsig} signer or key does not match authoritative zone",{"rrsig":{"kind":"protected","value":"Rrsig"}});
      case "same-owner-two-explicit-views-independently-authenticated":return this.ui("ui.dnssec.decisionLabel.same-owner-two-explicit-views-independently-authenticated","Same owner two explicit views independently authenticated");
      case "secure-alias-does-not-authenticate-unsigned-target":return this.rich("ui.dnssec.decisionLabel.secure-alias-does-not-authenticate-unsigned-target","{secure} alias does not authenticate unsigned target",{"secure":{"kind":"protected","value":"Secure"}});
      case "secure-alias-target-signature-fails":return this.rich("ui.dnssec.decisionLabel.secure-alias-target-signature-fails","{secure} alias target signature fails",{"secure":{"kind":"protected","value":"Secure"}});
      case "secure-delegation-answer-missing-required-rrsig":return this.rich("ui.dnssec.decisionLabel.secure-delegation-answer-missing-required-rrsig","{secure} delegation answer missing required {rrsig}",{"secure":{"kind":"protected","value":"Secure"},"rrsig":{"kind":"protected","value":"rrsig"}});
      case "selected-nsec3-iteration-resource-policy-refuses-proof":return this.rich("ui.dnssec.decisionLabel.selected-nsec3-iteration-resource-policy-refuses-proof","Selected {nsec3} iteration resource policy refuses proof",{"nsec3":{"kind":"protected","value":"nsec3"}});
      case "signature-bound-excludes-cache-and-refetch-signature-is-expired":return this.ui("ui.dnssec.decisionLabel.signature-bound-excludes-cache-and-refetch-signature-is-expired","Signature bound excludes cache and refetch signature is expired");
      case "signature-expired":return this.ui("ui.dnssec.decisionLabel.signature-expired","Signature expired");
      case "signature-mismatch":return this.ui("ui.dnssec.decisionLabel.signature-mismatch","Signature mismatch");
      case "signed-nxname-identifies-nonexistent-name-with-noerror":return this.rich("ui.dnssec.decisionLabel.signed-nxname-identifies-nonexistent-name-with-noerror","Signed {nxname} identifies nonexistent name with {noerror}",{"nxname":{"kind":"protected","value":"nxname"},"noerror":{"kind":"protected","value":"noerror"}});
      case "stale-anchor-no-current-path":return this.ui("ui.dnssec.decisionLabel.stale-anchor-no-current-path","Stale anchor no current path");
      case "stub-independently-validates-with-own-anchor":return this.ui("ui.dnssec.decisionLabel.stub-independently-validates-with-own-anchor","Stub independently validates with own anchor");
      case "supported-ds-no-matching-key":return this.rich("ui.dnssec.decisionLabel.supported-ds-no-matching-key","Supported {ds} no matching key",{"ds":{"kind":"protected","value":"ds"}});
      case "temporary-operator-bypass-expires-and-unrepaired-zone-fails-again":return this.ui("ui.dnssec.decisionLabel.temporary-operator-bypass-expires-and-unrepaired-zone-fails-again","Temporary operator bypass expires and unrepaired zone fails again");
      case "transaction-mac-verification":return this.rich("ui.dnssec.decisionLabel.transaction-mac-verification","Transaction {mac} verification",{"mac":{"kind":"protected","value":"mac"}});
      case "transport-fails-before-complete-validation-input":return this.ui("ui.dnssec.decisionLabel.transport-fails-before-complete-validation-input","Transport fails before complete validation input");
      case "truncated-udp-not-complete-correlated-tcp-retry-validates":return this.rich("ui.dnssec.decisionLabel.truncated-udp-not-complete-correlated-tcp-retry-validates","Truncated {udp} not complete correlated {tcp} retry validates",{"udp":{"kind":"protected","value":"udp"},"tcp":{"kind":"protected","value":"tcp"}});
      case "unchecked-diagnostic-response-not-accepted-application-answer":return this.ui("ui.dnssec.decisionLabel.unchecked-diagnostic-response-not-accepted-application-answer","Unchecked diagnostic response not accepted application answer");
      case "update-authorization":return this.ui("ui.dnssec.decisionLabel.update-authorization","Update authorization");
      case "usable-signature-over-exact-rrset":return this.rich("ui.dnssec.decisionLabel.usable-signature-over-exact-rrset","Usable signature over exact {rrset}",{"rrset":{"kind":"protected","value":"rrset"}});
      case "valid-path":return this.ui("ui.dnssec.decisionLabel.valid-path","Valid path");
      case "valid-wildcard-signature-without-no-closer-proof":return this.ui("ui.dnssec.decisionLabel.valid-wildcard-signature-without-no-closer-proof","Valid wildcard signature without no closer proof");
      case "wildcard-signature-and-no-closer-match-verified":return this.ui("ui.dnssec.decisionLabel.wildcard-signature-and-no-closer-match-verified","Wildcard signature and no closer match verified");
      case "wildcard-type-absence-plus-no-closer-match":return this.ui("ui.dnssec.decisionLabel.wildcard-type-absence-plus-no-closer-match","Wildcard type absence plus no closer match");
      case "zonemd-digest-comparison":return this.rich("ui.dnssec.decisionLabel.zonemd-digest-comparison","{zonemd} digest comparison",{"zonemd":{"kind":"protected","value":"Zonemd"}});
    }
    return this.ltr(formatProtocolValue(value,true));
  }
  dnssecHopComparison(state){
    const hops=state.response.traceHops||[],priorContexts=state.upstreamErrorEntries||[];
    const ref=(key,source,params={})=>({key,source,params}),render=message=>this.ui(message.key,message.source,message.params);
    const packet=message=>!message?ref('ui.dnssec.hops.pendingResponse','Pending - response not received'):message.edns?.present?ref('ui.dnssec.hops.packetFlags','AD='+message.flags.AD+' / CD='+message.flags.CD+' / DO='+message.edns.DO,{ad:'AD='+message.flags.AD,cd:'CD='+message.flags.CD,do:'DO='+message.edns.DO}):ref('ui.dnssec.hops.packetNoOpt','AD='+message.flags.AD+' / CD='+message.flags.CD+' / OPT absent (no DO bit)',{ad:'AD='+message.flags.AD,cd:'CD='+message.flags.CD,opt:'OPT',do:'DO'});
    const cell=(name,html)=>`<td class="locale-prose" data-dnssec-hop-cell="${name}">${html}</td>`;
    const priorRows=priorContexts.map(entry=>`<tr data-dnssec-cache-context="${escapeHtml(entry.id)}"><th class="locale-prose" scope="row" data-dnssec-hop-cell="identity">${this.ui('ui.app.dnssecHopComparison.text.0191','Retained cached upstream error context')}<br><code ${this.rawValueAttrs(entry.id)}>${escapeHtml(entry.id)}</code><br>${this.ui('ui.app.dnssecHopComparison.text.0192','No current query is represented by this retained context.')}</th>${cell('query',this.ui('ui.dnssec.hops.priorQuery','CD='+entry.queryCD+'; AD not recorded; DO not recorded',{cd:'CD='+entry.queryCD,ad:'AD',do:'DO'}))}${cell('response',this.ui('ui.dnssec.hops.priorResponse','AD / CD / DO not recorded for this prior response',{ad:'AD',cd:'CD',do:'DO'}))}${cell('delivery',this.ui('ui.dnssec.hops.priorDelivery',entry.rcode+' retained from '+entry.receivedAt+'; expires at '+entry.expiresAt,{rcode:entry.rcode,received:entry.receivedAt,expires:entry.expiresAt}))}${cell('owner',this.ui('ui.dnssec.hops.priorOwner',this.actor(entry.validationOwner).name+' - retained remote error, not a local validation failure',{actor:this.actor(entry.validationOwner).name}))}</tr>`).join('');
    const rows=hops.map(hop=>{
      const attempts=hop.attempts||[{query:hop.query,response:hop.response}];
      const packets=side=>attempts.map((attempt,index)=>{const value=packet(attempt[side]);return attempts.length>1?this.ui('ui.dnssec.hops.numberedPacket','Attempt '+(index+1)+': '+value.source,{number:index+1,packet:value}):render(value);}).join('; ');
      const events=attempts.map(attempt=>this.ui('ui.dnssec.hops.queryEvent','Query event: '+attempt.query.id,{event:attempt.query.id})+(attempt.response?'<br>'+this.ui('ui.dnssec.hops.responseEvent','Response event: '+attempt.response.id,{event:attempt.response.id}):'')).join('<br>');
      const validator=hop.checkingOwner?state.validators?.[hop.checkingOwner]:null;
      const checked=validator?.verificationKind==='local-check'&&(validator.signatureChecked===true||validator.chainEstablished===true||validator.decisionArtifact||Number.isFinite(validator.checkedAt));
      const observation=validator?.reusedAuthenticatedCache?ref('ui.dnssec.hops.reusedCache','earlier authenticated cache reused; no fresh check'):checked?validator.securityStatus?ref('ui.dnssec.hops.validationStatus','local validation '+validator.securityStatus,{status:validator.securityStatus}):ref('ui.dnssec.hops.validationPerformed','local validation performed'):ref('ui.dnssec.hops.notChecked','not yet independently checked');
      const check=hop.checkingOwner?ref('ui.dnssec.hops.checker',this.actor(hop.checkingOwner).name+' - '+observation.source,{actor:this.actor(hop.checkingOwner).name,observation}):ref('ui.dnssec.hops.noChecker','No independent DNSSEC checker declared for this hop',{protocol:'DNSSEC'});
      const reliesOnStubChannel=hop.relianceOwner==='dnsStub'&&state.stub?.assertionAccepted===true;
      const reliesOnRemote=state.verificationKind==='remote-assertion'&&state.validationOwner===hop.checkingOwner;
      const relianceObservation=reliesOnStubChannel?ref('ui.dnssec.hops.trustedChannel','relies on the configured resolver and trusted channel'):reliesOnRemote?ref('ui.dnssec.hops.remoteAssertion','relies on the remote assertion'):ref('ui.dnssec.hops.noRelianceObservation','no explicit reliance-acceptance observation in this prefix');
      const reliance=hop.relianceOwner?ref('ui.dnssec.hops.reliance',this.actor(hop.relianceOwner).name+' - '+relianceObservation.source,{actor:this.actor(hop.relianceOwner).name,observation:relianceObservation}):null;
      const owner=reliance?this.ui('ui.dnssec.hops.checkAndReliance',check.source+'; '+reliance.source,{check,reliance}):render(check);
      const attempt=hop.priorContextId?ref('ui.dnssec.hops.freshQuery','Fresh query, separate from retained context '+hop.priorContextId,{context:hop.priorContextId}):hop.retryOf?ref('ui.dnssec.hops.retry','Retry of '+hop.retryOf,{query:hop.retryOf}):ref('ui.dnssec.hops.currentAttempt','Current attempt');
      const delivery=hop.response?ref('ui.dnssec.hops.received','Received '+hop.response.rcode,{rcode:hop.response.rcode}):hop.delivery?.queryDelivered===false?hop.delivery.responseAbsentReason?ref('ui.dnssec.hops.queryNotDeliveredReason','Pending - query not delivered; '+hop.delivery.responseAbsentReason,{reason:hop.delivery.responseAbsentReason}):ref('ui.dnssec.hops.queryNotDelivered','Pending - query not delivered; no receipt'):ref('ui.dnssec.hops.pendingResponse','Pending - response not received');
      const count=attempts.length;
      return `<tr data-dnssec-hop-id="${escapeHtml(hop.id)}"><th class="locale-prose" scope="row" data-dnssec-hop-cell="identity">${this.ltr(this.actor(hop.from).name+' → '+this.actor(hop.to).name)}<br>${this.ltr(hop.question.qname+' '+hop.question.qtype+' / '+hop.transport)} / ${render(attempt)}<br><code ${this.rawValueAttrs(hop.id)}>${escapeHtml(hop.id)}</code><br>${events}</th>${cell('query',packets('query'))}${cell('response',packets('response'))}${cell('delivery',this.ui('ui.dnssec.hops.attemptDelivery',count+' attempt'+(count===1?'':'s')+'; '+delivery.source,{count,delivery}))}${cell('owner',owner)}</tr>`;
    }).join('');
    return '<section class="dnssec-hop-comparison locale-prose" aria-label="'+escapeHtml(this.uiText('ui.dnssec.hops.sectionLabel','DNS query and response comparison',{protocol:'DNS'}))+'"><div class="instance-table-scroll" dir="ltr" data-technical-ltr role="region" aria-label="'+escapeHtml(this.uiText('ui.dnssec.hops.regionLabel','Per-hop DNS flag comparison',{protocol:'DNS'}))+'" tabindex="0"><table class="instance-table"><caption class="locale-prose">'+this.ui('ui.dnssec.hops.caption','DNS query and response at the current cursor',{protocol:'DNS'})+'</caption><thead><tr><th class="locale-prose" scope="col">'+this.ui('ui.dnssec.hops.hopAttempt','Hop / attempt')+'</th><th class="locale-prose" scope="col">'+this.ui('ui.dnssec.hops.queryFlags','Query AD / CD / DO',{ad:'AD',cd:'CD',do:'DO'})+'</th><th class="locale-prose" scope="col">'+this.ui('ui.dnssec.hops.responseFlags','Response AD / CD / DO',{ad:'AD',cd:'CD',do:'DO'})+'</th><th class="locale-prose" scope="col">'+this.ui('ui.dnssec.hops.deliveryHeading','RCODE / delivery',{rcode:'RCODE'})+'</th><th class="locale-prose" scope="col">'+this.ui('ui.dnssec.hops.validationReliance','Validation / reliance')+'</th></tr></thead><tbody>'+priorRows+rows+'</tbody></table></div>'+(!hops.length?'<p>'+this.ui('ui.dnssec.hops.noCompletedQuery','No query has completed in this source prefix.')+'</p>':'')+'<p>'+this.ui('ui.dnssec.hops.boundaries','The authoritative response uses CD=0 under its authoritative rule; recursive responses echo the query CD bit. DO is an OPT request/response bit, not proof of security. A received response, a local validation decision and accepted reliance are separate observations.',{authoritativeCD:'CD=0',cd:'CD',do:'DO',opt:'OPT'})+'</p></section>';
  }
  refreshChapterProjection(){
    const chapter=this.graphChapter,key=chapter?.id||null;
    if(this.graphChapterKey===key)return;
    this.graphChapterKey=key;this.heldGeometry=null;this.heldView.geometrySignature=null;this.heldView.configureGeometry();
    if(!this.heldGeometry)this.ensureLayoutRoutes(this.traceQueue);
    this.renderActors();this.renderConnections();
  }
  renderProtocolTimeline(snapshot){
    const panel=this.querySelector('#lifetime-strip'),timeline=this.labModel.protocolTimeline,state=snapshot.state,now=state.protocolClock,owner='lesson:'+this.labModel.id,context={phase:'protocol-timeline'};
    const read=path=>path?.split('.').reduce((current,key)=>current&&Object.hasOwn(current,key)?current[key]:undefined,state);
    const human=(fieldPath,source,extra={})=>({ownerId:owner,fieldPath,source,context:this.localeContext({...context,...extra})});
    panel.hidden=false;panel.setAttribute('aria-label',this.proseText(owner,'protocolTimeline.label',timeline.label,context));
    const cards=timeline.entries.map(entry=>{
      const start=read(entry.startPath),deadline=read(entry.deadlinePath),status=read(entry.statusPath),detail=read(entry.detailPath),entryPath='protocolTimeline.entries.'+entry.id,entryContext={...context,entryId:entry.id};
      const exists=Number.isFinite(start)&&Number.isFinite(deadline),elapsed=entry.mode==='elapsed',remaining=exists?deadline-now:null;
      const value=exists?Math.max(0,Math.min(100,(elapsed?now-start:remaining)/Math.max(1,deadline-start)*100)):0;
      const text=!exists?this.ui('ui.protocolTimeline.notEstablished','Not established'):remaining>0?elapsed?this.ui('ui.protocolTimeline.untilBoundary',remaining+' s until the next eligibility boundary',{seconds:remaining}):this.ui('ui.protocolTimeline.remaining',remaining+' s remaining',{seconds:remaining}):entry.onElapsed?this.prose(owner,entryPath+'.onElapsed',entry.onElapsed,entryContext):elapsed?this.ui('ui.protocolTimeline.windowElapsed','Window elapsed; observe the declared state before accepting.'):this.ui('ui.protocolTimeline.expired','Expired');
      const label=human(entryPath+'.label',entry.label,{entryId:entry.id}),aria=elapsed?this.uiText('ui.protocolTimeline.elapsedAria',entry.label+' elapsed window',{label}):this.uiText('ui.protocolTimeline.remainingAria',entry.label+' remaining lifetime',{label});
      return `<div class="lifetime-card" data-lifetime="${escapeHtml(entry.id)}" data-active="${exists&&remaining>0}"><strong>${this.prose(owner,entryPath+'.label',entry.label,entryContext)}</strong><span class="locale-prose">${text}</span><progress max="100" value="${value}" aria-label="${escapeHtml(aria)}"></progress>${status===undefined?'':`<p class="locale-prose">${this.ui('ui.protocolTimeline.currentState','Current state: '+formatProtocolValue(status,true),{state:formatProtocolValue(status,true)})}</p>`}<p>${detail===undefined?(entry.detail?this.prose(owner,entryPath+'.detail',entry.detail,entryContext):''):'<code '+this.rawValueAttrs(formatProtocolValue(detail,true))+'>'+escapeHtml(formatProtocolValue(detail,true))+'</code>'}</p></div>`;
    }).join('');
    panel.innerHTML='<p class="lifetime-heading locale-prose">'+this.ui('ui.protocolTimeline.heading',timeline.label+' · protocol time '+now+' s',{label:human('protocolTimeline.label',timeline.label),time:now})+'</p><div class="lifetime-grid">'+cards+'</div><p class="lifetime-note">'+this.prose(owner,'protocolTimeline.explanation',timeline.explanation,context)+'</p>';
  }
  renderLifetimes(snapshot){
    if(snapshot&&this.labModel?.protocolTimeline){this.renderProtocolTimeline(snapshot);return;}
    const panel=this.querySelector('#lifetime-strip'),state=snapshot?.state;panel.hidden=!state?.lifetimes;
    if(panel.hidden){panel.innerHTML='';return;}
    panel.setAttribute('aria-label',this.uiText('ui.lifetimes.panelLabel','Four independent credential and session lifetimes'));
    const now=state.protocolClock,start=snapshot.model.initialState.protocolClock,ref=(key,source,params={})=>({key,source,params}),render=message=>message.ownerId?this.prose(message.ownerId,message.fieldPath,message.source,message.context):this.ui(message.key,message.source,message.params);
    const channels=state.sessions.ssh?.channels||0;
    const entries=[
      {key:'idpSession',label:ref('ui.lifetimes.idpSession','IdP browser session',{protocol:'IdP'}),exists:!!state.sessions.idp,active:!!state.sessions.idp?.authenticated,expires:state.sessions.idp?.expiresAt,detail:state.sessions.idp?.endedBy?{ownerId:'lesson:'+(this.labModel?.id||this.labScenarioId),fieldPath:'state.sessions.idp.endedBy',source:state.sessions.idp.endedBy,context:this.localeContext()}:ref('ui.lifetimes.idpOwnsSession','The IdP owns its SSO session.',{idp:'IdP',sso:'SSO'})},
      {key:'oauthToken',label:ref('ui.lifetimes.enrollmentToken','OIDC enrollment token',{protocol:'OIDC'}),exists:!!state.credentials.idToken,active:!!state.credentials.idToken&&state.credentials.idToken.status!=='expired',expires:state.credentials.idToken?.expiresAt,detail:state.tokenConsumption['id-token-1']?ref('ui.lifetimes.consumedToken','Consumed for enrollment; possession does not reopen SSH.',{protocol:'SSH'}):ref('ui.lifetimes.tokenCheck','The CLI and CA check this client-bound token.',{cli:'CLI',ca:'CA'})},
      {key:'sshCertificate',label:ref('ui.lifetimes.sshCertificate','SSH user certificate',{protocol:'SSH'}),exists:!!state.credentials.userCertificate,active:!!state.credentials.userCertificate&&!(state.knowledge.host?.revokedSerials||[]).includes(state.credentials.userCertificate.serial),expires:state.credentials.userCertificate?.validBefore,detail:(state.knowledge.host?.revokedSerials||[]).includes(state.credentials.userCertificate?.serial)?ref('ui.lifetimes.revocationInstalled','This host has installed the revocation.'):state.authorities.ca?.publishedRevocations?.length?ref('ui.lifetimes.revocationPublished','CA published revocation; this host has not installed it.',{ca:'CA'}):ref('ui.lifetimes.certificateCheck','The host checks certificate validity for a new authentication.')},
      {key:'sshSession',label:ref('ui.lifetimes.sshConnection','Established SSH connection',{protocol:'SSH'}),exists:!!state.sessions.ssh?.authenticated,active:!!state.sessions.ssh?.authenticated,expires:null,detail:state.sessions.ssh?.authenticated?ref('ui.lifetimes.openChannels','Open under this preset policy · '+channels+' channel'+(channels===1?'':'s'),{count:channels}):ref('ui.lifetimes.notAuthenticated','The connection has not authenticated.')},
    ];
    const text=entry=>!entry.exists?this.ui('ui.lifetimes.notEstablished','Not established'):Number.isFinite(entry.expires)&&now>=entry.expires?this.ui('ui.lifetimes.expired','Expired'):!entry.active?this.ui('ui.lifetimes.ended','Ended / rejected'):entry.expires==null?this.ui('ui.lifetimes.openSeparate','Open · separate lifetime'):this.ui('ui.lifetimes.minutesRemaining',Math.ceil((entry.expires-now)/60)+' min remaining',{count:Math.ceil((entry.expires-now)/60),unit:'min'});
    panel.innerHTML='<p class="lifetime-heading locale-prose">'+this.ui('ui.lifetimes.heading','Four independent timelines · simulated elapsed '+Math.max(0,now-start)+' s',{elapsed:Math.max(0,now-start)+' s'})+'</p><div class="lifetime-grid" dir="ltr" data-technical-ltr>'+entries.map(entry=>`<div class="lifetime-card locale-prose" data-lifetime="${entry.key}" data-active="${entry.exists&&entry.active&&(!Number.isFinite(entry.expires)||now<entry.expires)}"><strong>${render(entry.label)}</strong><span>${text(entry)}</span><progress dir="ltr" data-technical-ltr max="100" value="${entry.exists?Number.isFinite(entry.expires)?Math.max(0,Math.min(100,(entry.expires-now)/Math.max(1,entry.expires-start)*100)):entry.active?100:0:0}" aria-label="${escapeHtml(this.uiText('ui.lifetimes.remainingLabel',entry.label.source+' remaining lifetime',{label:entry.label}))}"></progress><p>${render(entry.detail)}</p></div>`).join('')+'</div><p class="lifetime-note locale-prose">'+this.ui('ui.lifetimes.separateEvents','Logout, token expiry, certificate expiry and an existing SSH connection are separate events. Rewind restores only the knowledge available at that source event.',{protocol:'SSH'})+'</p>';
  }
  actorContextRows(id) {
    if(this.labModel?.workspace)return scenarioContextRows(this.labModel,id,this.runtimeEnvironment.applied);
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
    const label=row=>({ownerId:'actor:'+id,fieldPath:'contextRows.'+row.key+'.label',source:row.label,context:this.localeContext({phase:'environment-context',rowKey:row.key})});
    const caption=row=>this.uiText('ui.environment.context.caption',row.label+': '+row.value,{label:label(row),value:row.value});
    if(!compact)return '<section class="participant-context"><h3 class="section-title">'+this.ui('ui.environment.context.heading','Displayed environment')+'</h3><dl>'+rows.map(row=>`<dt>${this.prose('actor:'+id,'contextRows.'+row.key+'.label',row.label,{phase:'environment-context',rowKey:row.key})}</dt><dd><code ${this.rawValueAttrs(row.value)}>${escapeHtml(row.value)}</code></dd>`).join('')+'</dl></section>';
    const byKey=key=>rows.find(row=>row.key===key),primary=this.labModel?.workspace?rows[0]:id===this.environmentOptions.clientActor&&this.environmentOptions.executionEnvironment==='native'?byKey('appCallbackURL')||byKey('appURL'):byKey('appURL')||byKey('keycloakBaseURL')||byKey('issuerURL')||byKey('ssoURL')||byKey('samlEntityID');
    if(!primary)return '';
    const realm=byKey('realm'),entity=byKey('samlEntityID');
    const identity=realm?realm:entity&&entity!==primary?entity:null;
    return `<span class="actor-context" id="actor-context-${id}" aria-label="${escapeHtml(caption(primary))}" title="${escapeHtml(rows.map(caption).join('\n'))}">${identity?`<span class="actor-context-identity locale-prose">${this.rich('ui.environment.context.caption','{label}: {value}',{label:{kind:'human',value:label(identity)},value:{kind:'protected',value:identity.value}})}</span>`:''}<code class="actor-context-address" ${this.rawValueAttrs(primary.value)}>${escapeHtml(primary.value)}</code></span>`;
  }
  connectionRoute(from,to) {return this.heldGeometry?.routes.get(from+'>'+to)||connectionPath(from,to,this.positions);}
  renderConnections() {
    const pairs=new Map();
    const focusPairs=new Set(this.traceQueue.map(s=>pairKey(this.nodeId(s.from),this.nodeId(s.to))));
    this.graphSteps.forEach(s=>{
      const from=this.nodeId(s.from),to=this.nodeId(s.to),key=pairKey(from,to);
      if(!pairs.has(key))pairs.set(key,{from,to,channel:channelCategory(s.channel),count:0});
      pairs.get(key).count++;
    });
    this.querySelector('#connection-paths').innerHTML=[...pairs.entries()].map(([key,p])=>{
      const label=p.from===p.to?this.uiText('ui.connection.operations','Replay '+p.count+' ordered operation'+(p.count===1?'':'s')+' within '+this.actor(p.from).name,{count:p.count,actor:this.actor(p.from).name}):this.uiText('ui.connection.exchanges','Replay '+p.count+' ordered exchange'+(p.count===1?'':'s')+' between '+this.actor(p.from).name+' and '+this.actor(p.to).name,{count:p.count,from:this.actor(p.from).name,to:this.actor(p.to).name});
      const outside=this.hasTrace&&!focusPairs.has(key),d=this.connectionRoute(p.from,p.to);
      return `<g class="connection-group ${outside?'is-outside-trace':''}" data-pair="${key}" data-channel="${p.channel}"><title>${escapeHtml(label)}</title><path class="edge-focus" d="${d}" aria-hidden="true"/><path class="connection-line ${p.channel}" d="${d}"/><path class="connection-hit" d="${d}" role="button" tabindex="${outside?-1:0}" aria-label="${escapeHtml(label)}"/></g>`;
    }).join('');
  }
  renderTimeline() {
    this.refs.timeline.innerHTML=this.visibleSteps.map((step,index)=>'<button class="timeline-step '+(index===this.visibleIndex?'is-current':'')+' '+(this.hasTrace?'is-trace-step':'')+'" data-step="'+index+'" aria-current="'+(index===this.visibleIndex?'step':'false')+'"><span class="step-number" dir="ltr" translate="no">'+String(index+1).padStart(2,'0')+'</span><span class="step-title locale-prose">'+this.stepProse(step,'title',step.title)+'</span><span class="step-phase locale-prose">'+(this.hasTrace?this.ui('ui.timeline.trace-phase',step.traceKind+' · journey '+(step.sourceIndex+1),{kind:step.traceKind,index:step.sourceIndex+1}):this.ltr(step.phase))+'</span></button>').join('');
  }
  selectStep(index,animate=false) {
    if(this.presentationMode==='compact')return this.inspectQueueBoundary(index,'end');
    this.player.stop(false);this.hidePopups();
    this.heldView?.selectStep();
    if(this.hasTrace){this.traceIndex=index;this.index=this.traceQueue[index]?.sourceIndex||0;this.inspection=this.traceInspection();}
    else {this.index=index;this.inspection={type:'step'};}
    this.refs.packet.hidden=true;this.hideStepAttributes();this.updateStep();this.renderInspector();this.updateControls();
    if(animate&&this.currentStep){this.ensureRunningSpeed();this.player.play([this.currentStep],this.hasTrace?'trace-step':'step');}
  }
  reset() {
    this.heldView?.reset();
    if(this.attributeSelection){this.selectAttribute(this.attributeSelection,false);return;}
    this.player.stop(false);this.index=0;this.visited.clear();this.packetIdentity='';this.inspection={type:'step'};
    this.attributeSelection=null;this.objectTraceSelection=null;this.traceQueue=[];this.traceIndex=0;
    this.hidePopups();
    if(this.presentationMode==='compact'){this.compactView.render('reset');return;}
    this.refs.packet.hidden=true;this.hideStepAttributes();this.refreshChapterProjection();this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.updateStep();this.renderInspector();this.updateControls();
  }
  replayConnection(pair) {
    this.hidePopups();const exchanges=this.visibleSteps.filter(step=>pairKey(this.nodeId(step.from),this.nodeId(step.to))===pair);
    if(!exchanges.length)return;
    this.ensureRunningSpeed();
    this.inspection=this.hasTrace?this.traceInspection():{type:'connection',pair,exchanges};this.renderInspector();
    this.player.play(exchanges,this.hasTrace?'trace-connection':'connection');
  }
  inspectActor(id) {this.hidePopups();this.inspection={type:'actor',id};this.renderInspector();this.updateNodeSelection();}
  updateNodeSelection() {this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>n.classList.toggle('is-selected',this.inspection.type==='actor'&&n.dataset.actor===this.inspection.id));}
  updateStep() {
    if(this.presentationMode==='compact'){this.compactView.render('step');return;}
    this.refreshChapterProjection();
    this.renderProtocolState();
    this.renderPamConfiguration();
    this.heldView?.render();
    const s=this.currentStep;
    if(!s){this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>{n.classList.remove('is-source','is-target','is-trace-participant');n.classList.add('is-outside-trace');n.querySelector('.actor-trace-action').hidden=true;});this.refs.connections.querySelectorAll('[data-pair]').forEach(g=>{g.classList.remove('is-active');delete g.dataset.presentation;g.querySelector('.connection-line').removeAttribute('marker-end');});this.refs.story.innerHTML='<p class="empty-state">'+this.ui('ui.story.no-operation','This field has no replayable operation in this journey. Choose one of the available journeys in the inspector.')+'</p>';this.refs.progress.style.width='0%';this.refs.progress.parentElement.setAttribute('aria-valuenow','0');return;}
    const source=this.nodeId(s.from),target=this.nodeId(s.to),pair=pairKey(source,target),category=channelCategory(s.channel);
    const presentation=s.from===s.to?'local':source===target?'folded':'transfer';
    const focusActors=new Set(this.traceQueue.flatMap(step=>[this.nodeId(step.from),this.nodeId(step.to)]));
    this.refs.actors.querySelectorAll('[data-actor]').forEach(n=>{
      n.classList.toggle('is-source',n.dataset.actor===source);n.classList.toggle('is-target',n.dataset.actor===target);
      n.classList.toggle('is-outside-trace',this.hasTrace&&!focusActors.has(n.dataset.actor));n.classList.toggle('is-trace-participant',this.hasTrace&&focusActors.has(n.dataset.actor));
      const badge=n.querySelector('.actor-trace-action'),active=(this.hasTrace||presentation!=='transfer')&&(n.dataset.actor===source||n.dataset.actor===target);
      badge.hidden=!active;if(active)badge.innerHTML=presentation==='local'?(s.traceKind?this.traceAction(s.traceKind):this.ui('ui.story.local','Local processing')):presentation==='folded'?this.ui('ui.story.internal','Internal exchange'):n.dataset.actor===source?this.ui('ui.story.send','Send'):this.ui('ui.story.receive','Receive');
    });
    this.refs.connections.querySelectorAll('[data-pair]').forEach(g=>{
      const active=g.dataset.pair===pair;g.classList.toggle('is-active',active);g.classList.toggle('is-visited',this.visited.has(g.dataset.pair));
      if(active){g.dataset.channel=category;g.dataset.presentation=presentation;const path=g.querySelector('.connection-line');path.setAttribute('d',this.connectionRoute(source,target));path.setAttribute('class','connection-line '+category);if(presentation==='local')path.removeAttribute('marker-end');else path.setAttribute('marker-end','url(#arrow-'+category+')');}
      else {delete g.dataset.presentation;g.querySelector('.connection-line').removeAttribute('marker-end');}
    });
    this.refs.timeline.querySelectorAll('[data-step]').forEach(button=>{const n=Number(button.dataset.step);button.classList.toggle('is-current',n===this.visibleIndex);button.classList.toggle('is-done',n<this.visibleIndex);button.setAttribute('aria-current',n===this.visibleIndex?'step':'false');});
    const percentage=Math.max(0,Math.round(this.visibleIndex/this.visibleSteps.length*100));this.refs.progress.style.width=percentage+'%';
    this.refs.progress.parentElement.setAttribute('aria-valuenow',percentage);
    const summaryField=this.learningDetail==='journey'&&this.labModel?.profile&&s.beginnerSummary?'beginnerSummary':'summary';
    const phase=this.objectTraceSelection?this.ui('ui.story.object-phase','EXACT OBJECT HISTORY · '+s.traceKind,{kind:s.traceKind}):this.attributeSelection?this.ui('ui.story.field-phase','ATTRIBUTE PATH · '+s.traceKind,{kind:s.traceKind}):this.ltr(s.phase);
    this.refs.story.innerHTML='<span class="story-index" dir="ltr" translate="no">'+String(this.visibleIndex+1).padStart(2,'0')+' / '+String(this.visibleSteps.length).padStart(2,'0')+'</span><div><span class="story-phase locale-prose">'+phase+'</span><p>'+this.stepProse(s,summaryField,s[summaryField])+'</p></div>';
    this.updateNodeSelection();
  }
  onPlayer(event) {
    if(event.type==='step'&&event.step){
      const row=event.step,index=row.sourceIndex??this.steps.findIndex(step=>step.id===(row.sourceStepId||row.id));
      if(index>=-1)this.index=event.kind==='demo'&&event.inspectionBoundary==='initial'?-1:index;
      if(this.hasTrace){
        const same=this.player.queue.length===this.traceQueue.length&&this.player.queue.every((step,i)=>step===this.traceQueue[i]);
        const traceIndex=same?event.queuePosition:this.traceQueue.indexOf(row);
        if(traceIndex>=0)this.traceIndex=traceIndex;
      }
    }
    if(event.type==='speed'&&event.speed>0)this.lastRunningSpeed=event.speed;
    if(event.type==='stepcomplete'&&event.step)this.visited.add(pairKey(this.nodeId(event.step.from),this.nodeId(event.step.to)));
    this.heldView.event(event);this.presenter.onPlayer(event);
  }
  onFullPlayer(event) {
    this.heldView.render(event);
    if(['frame','stepcomplete','complete','state'].includes(event.type))this.renderProtocolState();
    if(['stepcomplete','state'].includes(event.type))this.renderPamConfiguration();
    if(event.type==='step'&&event.step){
      this.updateStep();if(this.inspection.type==='step'||(this.attributeSelection&&['attribute','topic'].includes(this.inspection.type)))this.renderInspector();
      const button=this.refs.timeline.querySelector(`[data-step="${this.visibleIndex}"]`);
      if(button)this.refs.timeline.scrollTo?.({left:this.refs.timeline.scrollLeft+button.getBoundingClientRect().left-this.refs.timeline.getBoundingClientRect().left-(this.refs.timeline.clientWidth-button.offsetWidth)/2,behavior:'smooth'});
      this.packetIdentity='';
      // A new queue can deliberately stay paused and never receive a frame.
      // Its packet must replace the previous step's packet immediately.
      this.refs.packet.hidden=true;this.renderPacket(event);
    }
    if(['frame','stepcomplete','complete','state'].includes(event.type)&&event.step)this.renderPacket(event);
    if(['step','frame','state','complete'].includes(event.type))this.updateSeekControls(event);
    if(event.type==='stepcomplete'&&event.step)this.hideStepAttributes();
    if(event.type==='complete'){
      this.refs.packet.hidden=true;this.hideStepAttributes();
      if(event.kind==='attribute')this.notify('ui.playback.field-complete','Attribute path complete. Choose another field or return to the full journey.');else if(event.kind==='demo')this.notify('ui.playback.journey-complete','Journey complete. Replay any connection to explore its details.');
      this.updateStep();if(event.kind==='demo'||event.kind==='attribute'){this.refs.progress.style.width='100%';this.refs.progress.parentElement.setAttribute('aria-valuenow','100');}
    }
    if(['state','speed','complete'].includes(event.type))this.updateControls();
    if(event.type==='state')this.renderStepAttributes(event);
  }
  hideStepAttributes() {
    if(!this.refs)return;
    this.refs['step-attributes'].hidden=true;this.refs['step-attributes-tether'].hidden=true;this.stepOverlayIdentity='';
    this.refs['step-attributes-external'].hidden=true;
  }
  stepAttributeItems(step) {
    const source=step.sourceStepId?this.steps.find(s=>s.id===step.sourceStepId)||step:step;
    // Projected checks can be local even when their source step is a send.
    // Match the projected logical owners, never their folded display cards.
    const authenticator=source.authenticatorKind||source.selectedAuthenticator||this.authenticator;
    const from=resolveActor(step.from,authenticator),to=resolveActor(step.to,authenticator),operations=getStepAttributeOperations(source,this.authenticator);
    const local=operations.filter(a=>!['inspect','send','receive'].includes(a.kind)),isLocal=step.from===step.to;
    let relevant=isLocal?local.filter(a=>a.actorId===from):operations.filter(a=>a.kind==='send'&&a.actorId===from);
    if(!isLocal&&!relevant.length)relevant=local.filter(a=>a.actorId===from||a.actorId===to);
    if(this.learningDetail==='journey'&&!this.hasTrace&&source.overviewFields)relevant=relevant.filter(operation=>source.overviewFields.includes(operation.attributeId));
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
    if(force||this.stepOverlayIdentity!==step.id||this.stepOverlayGeometry!==this.heldGeometry){
      const items=this.stepAttributeItems(step);
      if(!items.length){this.hideStepAttributes();return;}
      this.stepOverlayIdentity=step.id;
      this.stepOverlayGeometry=this.heldGeometry;
      if(overlay.parentElement!==this.refs.graph)this.refs.graph.appendChild(overlay);
      overlay.classList.remove('is-external');this.refs['step-attributes-external'].hidden=true;
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
    const bounds=this.heldGeometry?Object.values(this.heldGeometry.bounds):Object.values(this.positions).map(position=>({left:position.x-CARD_BOUNDS.width/2,right:position.x+CARD_BOUNDS.width/2,top:position.y-CARD_BOUNDS.height/2,bottom:position.y+CARD_BOUNDS.height/2}));
    const placement=placeStepOverlay(points,size,bounds);
    if(!placement.fits){
      overlay.classList.add('is-external');this.refs['step-attributes-external'].appendChild(overlay);
      this.refs['step-attributes-external'].hidden=false;this.refs['step-attributes-tether'].hidden=true;
      return;
    }
    overlay.style.left=placement.x/GRAPH_WIDTH*100+'%';overlay.style.top=placement.y/GRAPH_HEIGHT*100+'%';
    const anchor=placement.anchor,edge={x:Math.max(placement.x,Math.min(placement.x+placement.width,anchor.x)),y:Math.max(placement.y,Math.min(placement.y+placement.height,anchor.y))},tether=this.refs['step-attributes-tether'];
    tether.dataset.channel=channelCategory(step.channel);tether.querySelector('path').setAttribute('d',`M ${anchor.x} ${anchor.y} L ${edge.x} ${edge.y}`);tether.hidden=false;
  }
  renderPacket(event) {
    if(!event.step){
      this.refs.packet.hidden=true;
      for(const key of ['messagePhase','messageId','routeProgress','presentation','playback'])delete this.refs.packet.dataset[key];
      const external=this.querySelector('#held-active-message');external.hidden=true;external.textContent='';this.externalMessageKey='';delete external.dataset.messagePhase;delete external.dataset.presentation;external.setAttribute('aria-label',this.uiText('ui.app.fullShell.attribute.0069','Active message'));
      return;
    }
    this.refs.packet.dataset.messagePhase=event.messagePhase;
    this.refs.packet.dataset.messageId=event.messageId||'';
    this.refs.packet.dataset.routeProgress=String(event.progress);
    this.renderStepAttributes(event);
    const from=this.nodeId(event.step.from),to=this.nodeId(event.step.to),pair=pairKey(from,to);
    const presentation=event.step.from===event.step.to?'local':from===to?'folded':'transfer';
    this.refs.packet.dataset.presentation=presentation;this.refs.packet.dataset.playback=event.status;
    const group=[...this.refs.connections.querySelectorAll('[data-pair]')].find(g=>g.dataset.pair===pair);
    const path=group?.querySelector('.connection-line');if(!path)return;
    const packet=event.packet,exact=!!packet&&!packet.redacted&&packet.value!==undefined;
    const identity=event.step.id+':'+event.packetIndex;
    if(identity!==this.packetIdentity){
      const title=event.step.title,titleRef=this.stepReference(event.step,'title',title);
      this.packetIdentity=identity;this.refs['packet-name'].innerHTML=packet?this.ltr(packet.name):this.ui('ui.packet.local-action','Local action');
      this.refs['packet-value'].hidden=!exact;this.refs['packet-explanation'].hidden=exact;
      if(exact){const value=formatProtocolValue(packet.value,true);this.refs['packet-value'].textContent=value.slice(0,38)+(value.length>38?'…':'');}
      else this.refs['packet-explanation'].innerHTML=packet?packet.redacted?this.ui('ui.packet.unreadable','Unreadable at this boundary.'):this.ui('ui.packet.no-example','No exact example is declared.'):this.stepProse(event.step,'title',title);
      if(!packet)this.packetDetailReference={key:'ui.packet.local-detail',source:'Local action: '+title,params:{title:titleRef}};
      else if(exact)this.packetDetailReference={key:'ui.packet.detail',source:packet.name+': '+formatProtocolValue(packet.value)+' · '+title,params:{name:packet.name,value:formatProtocolValue(packet.value),title:titleRef}};
      else if(packet.redacted)this.packetDetailReference={key:'ui.packet.unreadable-detail',source:packet.name+': Unreadable at this boundary. · '+title,params:{name:packet.name,title:titleRef}};
      else this.packetDetailReference={key:'ui.packet.no-example-detail',source:packet.name+': No exact example is declared. · '+title,params:{name:packet.name,title:titleRef}};
      this.refs['packet-count'].textContent=(event.packetIndex+1)+'/'+Math.max(1,event.step.payload.length);
      this.refs.packet.dataset.channel=channelCategory(event.step.channel);
      if(presentation!=='local'&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches)this.refs.packet.querySelector('.packet-chip').animate?.([{opacity:.2,transform:'scale(.86)'},{opacity:1,transform:'scale(1)'}],{duration:180,fill:'both'});
    }
    this.refs.packet.hidden=!event.visible;
    if(event.visible){
      const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const point=path.getPointAtLength(path.getTotalLength()*((presentation==='local'||reduced)? .5:event.progress));
      const graphRect=this.refs.graph.getBoundingClientRect(),packetRect=this.refs.packet.getBoundingClientRect();
      const width=graphRect.width||GRAPH_WIDTH,height=graphRect.height||GRAPH_HEIGHT,x=point.x/GRAPH_WIDTH*width,y=point.y/GRAPH_HEIGHT*height;
      // Keep the route point inside the complete chip, anchoring its edge
      // instead of moving the packet's logical position off the path.
      const left=Math.max(0,Math.min(width-packetRect.width,x-packetRect.width/2)),top=Math.max(0,Math.min(height-packetRect.height,y-packetRect.height/2));
      this.refs.packet.style.left=point.x/GRAPH_WIDTH*100+'%';this.refs.packet.style.top=point.y/GRAPH_HEIGHT*100+'%';
      this.refs.packet.style.transform=`translate(${left-x}px, ${top-y}px)`;
    }
    const external=this.querySelector('#held-active-message');external.hidden=presentation!=='local'&&(!this.heldGeometry||event.messagePhase==='local');
    if(!external.hidden){
      external.dataset.messagePhase=event.messagePhase;external.dataset.presentation=presentation;
      const key=identity+':'+this.localizer.revision+':'+presentation+':'+event.messagePhase;
      if(this.externalMessageKey!==key){
        this.externalMessageKey=key;external.setAttribute('aria-label',presentation==='local'?this.uiText('ui.packet.active-local','Active local operation'):this.uiText('ui.app.fullShell.attribute.0069','Active message'));
        const detail=this.packetDetailReference;
        external.innerHTML=presentation==='local'?this.ui('ui.packet.local-processing','Local processing at '+this.actor(event.step.from).name+' · '+detail.source,{actor:this.actor(event.step.from).name,detail}):this.ui('ui.packet.phase-detail',detail.source+' · '+event.messagePhase,{detail,phase:event.messagePhase});
      }
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
    this.hidePopups();this.inspection=this.hasTrace?this.traceInspection():{type:'step'};
    this.visited.clear();this.packetIdentity='';
    this.player.seek(clock.steps,fraction,this.objectTraceSelection?'object':this.attributeSelection?'attribute':'demo');
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
    const params={position:index+1,total:clock.steps.length,elapsed:stamp(elapsed),duration:stamp(clock.total)},row=clock.steps[index];
    this.refs['seek-position'].innerHTML=this.attributeSelection?this.ui('ui.seek.moment-position','Moment '+params.position+' / '+params.total+' · '+params.elapsed+' / '+params.duration,params):this.ui('ui.seek.step-position','Step '+params.position+' / '+params.total+' · '+params.elapsed+' / '+params.duration,params);
    const title=row?.title||'',reference=row?this.stepReference(row,'title',title):null,source=(this.attributeSelection?'Moment ':'Step ')+params.position+' of '+params.total+': '+title;
    const label=reference?this.attributeSelection?this.uiText('ui.seek.moment-label',source,{position:params.position,total:params.total,title:reference}):this.uiText('ui.seek.step-label',source,{position:params.position,total:params.total,title:reference}):this.attributeSelection?this.uiText('ui.seek.empty-moment','Moment '+params.position+' of '+params.total+': ',{position:params.position,total:params.total}):this.uiText('ui.seek.empty-step','Step '+params.position+' of '+params.total+': ',{position:params.position,total:params.total});
    this.refs.seek.setAttribute('aria-valuetext',label);
    const percentage=Math.round(fraction*100);this.refs.progress.style.width=percentage+'%';this.refs.progress.parentElement.setAttribute('aria-valuenow',percentage);
  }
  updateControls() {
    if(this.presentationMode==='compact'){this.compactView.render('controls');return;}
    const status=this.player.status;if(status==='idle')this.renderPacket(this.player.snapshot());
    const label=status==='playing'?this.ui('ui.playback.pause','Pause'):status==='paused'?this.ui('ui.playback.resume','Resume'):this.objectTraceSelection?this.ui('ui.playback.play-object','Play exact object history'):this.attributeSelection?this.ui('ui.playback.play-field','Play attribute path'):this.ui('ui.playback.play-demo','Play demo');
    this.refs.play.innerHTML=uiIcon(status==='playing'?'pause':'play',status!=='playing')+'<span id="play-label">'+label+'</span>';this.refs.play.removeAttribute('aria-label');this.refs.play.setAttribute('aria-labelledby','play-label');
    this.refs.play.disabled=this.hasTrace&&!this.traceQueue.length;
    if(this.player.speed>0)this.lastRunningSpeed=this.player.speed;
    this.refs.speed.value=String(this.player.speed);this.refs['speed-label'].innerHTML=this.player.speed===0?this.ui('ui.playback.stopped','Stopped'):this.ltr(this.player.speed+'×');
    this.refs.status.innerHTML=status==='playing'?(this.attributeSelection?this.ui('ui.playback.following','FOLLOWING ATTRIBUTE'):this.player.kind==='connection'?this.ui('ui.playback.connection','REPLAYING CONNECTION'):this.ui('ui.playback.running','DEMO RUNNING')):status==='paused'?this.ui('ui.playback.paused','PAUSED'):status==='complete'?this.ui('ui.playback.complete','COMPLETE'):this.ui('ui.playback.ready','READY TO EXPLORE');
    this.refs.status.dataset.status=status;
    this.querySelector('#previous').disabled=this.visibleIndex<=0||!this.visibleSteps.length;this.querySelector('#next').disabled=this.visibleIndex>=this.visibleSteps.length-1;
    this.refs['attribute-focus'].querySelectorAll('[data-trace-play]').forEach(button=>{button.innerHTML=status==='playing'?this.ui('ui.playback.pause','Pause'):status==='paused'?this.ui('ui.playback.resume','Resume'):this.ui('ui.playback.replay-path','Replay path');button.disabled=!this.traceQueue.length;});
    this.updateSeekControls();
  }
  renderInspector() {
    if(this.presentationMode==='compact'){this.compactView.render('inspection');return;}
    const returnTarget=this.refs.inspector.contains(document.activeElement)?captureFocusTarget(this,document.activeElement):null,view=this.inspection;
    const headings={step:['ui.inspector.step','EXCHANGE INSPECTOR'],actor:['ui.inspector.actor','PARTICIPANT INSPECTOR'],attribute:['ui.inspector.field','ATTRIBUTE LIFECYCLE'],topic:['ui.inspector.field','ATTRIBUTE LIFECYCLE'],glossary:['ui.inspector.glossary','FIELD GUIDE'],connection:['ui.inspector.connection','CONNECTION INSPECTOR']};
    this.refs['inspector-heading'].innerHTML=this.ui(headings[view.type][0],headings[view.type][1]);let html='';
    if(view.type==='step')html=this.stepHtml(this.currentStep,this.visibleIndex);
    if(view.type==='actor')html=this.actorHtml(this.actor(view.id));
    if(view.type==='attribute'||view.type==='topic')html=this.traceHtml(view.id);
    if(view.type==='glossary')html='<div class="inspector-kicker">'+this.ui('ui.app.renderInspector.text.0193','CANONICAL NAMES · PLAIN ENGLISH')+'</div><h2 class="inspector-title">'+this.ui('ui.app.renderInspector.text.0194','Know what moves.')+'</h2><p class="inspector-summary">'+this.ui('ui.app.renderInspector.text.0195','Every field has a job. Hover to learn its meaning; click to keep the explanation open.')+'</p><label class="sr-only" for="glossary-search">'+this.ui('ui.app.renderInspector.text.0196','Search protocol fields')+'</label><input class="glossary-search" id="glossary-search" type="search" dir="auto" value="'+escapeHtml(this.glossaryQuery||'')+'" placeholder="'+escapeHtml(this.uiText('ui.app.renderInspector.attribute.0197','Search a field or purpose…'))+'"><div class="glossary-list">'+Object.entries(ATTRIBUTES).map(([id,definition])=>'<button class="attribute-button technical-ltr" data-attribute="'+escapeHtml(id)+'" data-glossary-attribute="'+escapeHtml(id)+'"><code dir="ltr" translate="no">'+escapeHtml(definition.name)+'</code><span dir="ltr" translate="no">'+escapeHtml(definition.standard)+'</span></button>').join('')+'</div>';
    if(view.type==='connection'){
      const actors=view.pair.split('--').map(id=>this.actor(id)),count=view.exchanges.length;
      html='<div class="inspector-kicker">'+this.ui('ui.app.renderInspector.text.0198','ORDERED EXCHANGES ON THIS CONNECTION')+'</div><h2 class="inspector-title">'+this.ltr(actors[0].name)+' '+uiIcon('link')+' '+this.ltr(actors[1].name)+'</h2><p class="inspector-summary">'+this.ui('ui.inspector.connection-summary','This connection carries '+count+' exchange'+(count===1?'':'s')+' during the journey. The demo sends each named object in order.',{count})+'</p><div class="connection-exchanges">'+view.exchanges.map(step=>{const index=this.steps.findIndex(item=>item.id===step.id);return '<button class="connection-exchange technical-ltr" data-exchange-step="'+index+'"><span class="step-number" dir="ltr" translate="no">'+String(index+1).padStart(2,'0')+'</span><div><strong class="locale-prose">'+this.stepProse(step,'title',step.title)+'</strong><span dir="ltr">'+this.ltr(this.actor(step.from).name)+' → '+this.ltr(this.actor(step.to).name)+'</span></div>'+uiIcon('play')+'</button>';}).join('')+'</div><div class="context-note">'+this.ui('ui.app.renderInspector.text.0199','Each exchange uses the actual sender and receiver. Browser redirects and direct server requests are separate hops.')+'</div>';
    }
    this.refs.inspector.innerHTML=html;if(view.type==='glossary')this.filterGlossary(this.glossaryQuery||'');this.updateNodeSelection();if(returnTarget)this.restoreTargetFocus(returnTarget);
  }
  stepHtml(s,index) {
    if(!s)return '<div class="empty-state">'+this.ui('ui.step.empty','Choose a journey to explore.')+'</div>';
    const from=this.actor(s.from),to=this.actor(s.to),category=channelCategory(s.channel),profile=this.labModel?.profile;
    const fields=s.fields||[],authored=s.sourceStepId?this.steps.find(step=>step.id===s.sourceStepId)||s:s,owner='step:'+(s.sourceStepId||s.id);
    const protocolLabel=s.protocolLabel||authored.protocolLabel||s.channel;
    const protocol=s.sourceStepId&&s.from===s.to?(TRACE_ACTION_LABELS[s.traceKind]?this.traceAction(s.traceKind):this.ui('ui.step.local-object-processing','Local object processing')):this.ltr(protocolLabel);
    const summaryField=profile&&this.learningDetail==='journey'&&s.beginnerSummary?'beginnerSummary':'summary';
    const inspectedPayload=s.sourceStepId?s.payload:s.detailedPayload||s.payload;
    const payload=(inspectedPayload||[]).map((p,i)=>{
      const id=this.payloadAttributeId(p,s),value=formatProtocolValue(p.value),key='step:'+(s.sourceStepId||s.id)+':payload:'+(id||p.name);
      let display;
      if(p.redacted)display='<span class="field-value locale-prose" data-copy-disabled="unreadable">'+this.ui('ui.payload.unreadable','Not readable by this holder')+'</span>';
      else if(p.value===undefined)display='<span class="field-value locale-prose" data-copy-disabled>'+this.ui('ui.payload.no-example','No exact example is declared.')+'</span>';
      else{
        const raw='<code class="field-value" '+this.rawValueAttrs(value)+'>'+escapeHtml(value)+'</code>';
        display=profile&&value.length>120?'<details class="long-protocol-value" data-study-key="'+escapeHtml(key)+'"><summary>'+this.ui('ui.payload.show-full','Show full value: '+p.name,{name:p.name})+'</summary>'+raw+'</details>':raw;
      }
      const carried=s.traceActions&&!s.artifactId?s.traceActions.find(action=>action.attributeId===(p.attributeId||id))?.carriedAs:null;
      const description=p.description?'<span class="field-description">'+(carried?this.ui('ui.trace.carried-inside',p.description,{container:carried}):this.prose(owner,'payload.description',p.description,{attributeId:p.attributeId||id,payloadName:p.name}))+'</span>':'';
      return '<div class="payload-row"><button class="field-name" '+(id&&ATTRIBUTES[id]?'data-attribute="'+id+'" '+this.fieldControlMetadata():'')+'><span class="payload-number" dir="ltr" translate="no">'+(i+1)+'</span><code dir="ltr" translate="no">'+escapeHtml(p.name)+'</code>'+(id&&ATTRIBUTES[id]?uiIcon('info'):'')+'</button>'+display+description+'</div>';
    }).join('');
    const fieldHeading=s.from===s.to?this.ui('ui.payload.local-heading','Local derivation and checks'):this.ui('ui.payload.wire-heading','Wire message fields and protected envelopes');
    const fieldSection='<h3 class="section-title">'+fieldHeading+'</h3>'+(s.from!==s.to?'<p class="field-description">'+this.ui('ui.payload.single-message','These fields form one message. Moving field chips are not independent deliveries. Protected wire values remain distinct from an actor’s decoded local view.')+'</p>':'')+'<div class="payload-list">'+payload+'</div>';
    const projectedFields=profile&&this.learningDetail==='journey'?'<details class="progressive-fields" data-study-key="'+escapeHtml('step:'+(s.sourceStepId||s.id)+':fields')+'"><summary>'+this.ui('ui.app.stepHtml.text.0200','Inspect this event’s fields')+'</summary>'+fieldSection+'</details>':fieldSection;
    const layerRows=s.layers||authored.layers||[];
    const layers=profile&&this.learningDetail!=='journey'&&layerRows.length?'<h3 class="section-title">'+this.ui('ui.app.stepHtml.text.0201','Canonical protocol layers')+'</h3><ul class="protocol-layer-list">'+layerRows.map(layer=>'<li><strong>'+this.ltr(layer.protocol)+' · '+this.ltr(layer.transport)+'</strong><span class="technical-ltr">'+this.ltr(this.actor(layer.from).name)+' → '+this.ltr(this.actor(layer.to).name)+'</span><span>'+this.prose(owner,'layers.protection',layer.protection,{protocol:layer.protocol,transport:layer.transport,from:layer.from,to:layer.to})+'</span>'+(layer.keyRef?'<span>'+this.ui('ui.layer.key-reference','Key reference: '+layer.keyRef,{reference:layer.keyRef})+'</span>':'')+(layer.certificateRole?'<span>'+this.ui('ui.layer.certificate-role','Certificate role: '+layer.certificateRole,{role:layer.certificateRole})+'</span>':'')+'</li>').join('')+'</ul>':'';
    let crypto='';
    if(profile&&this.learningDetail==='crypto'){
      const detail=s.cryptoDetail||authored.cryptoDetail||profile.cryptoDetail;
      const content=detail&&typeof detail==='object'?'<pre '+this.rawValueAttrs(formatProtocolValue(detail))+'>'+escapeHtml(formatProtocolValue(detail))+'</pre>':s.cryptoDetail||authored.cryptoDetail?'<p class="step-detail">'+this.prose(owner,'cryptoDetail',detail)+'</p>':'<p class="step-detail">'+this.prose('lesson:'+this.labModel.id,'profile.cryptoDetail',detail)+'</p>';
      crypto='<h3 class="section-title">'+this.ui('ui.app.stepHtml.text.0202','Cryptographic interpretation')+'</h3>'+content;
    }
    const kicker=this.ui('ui.step.position','STEP '+String(index+1).padStart(2,'0')+' OF '+this.visibleSteps.length,{position:String(index+1).padStart(2,'0'),total:this.visibleSteps.length});
    const channel=this.ui('ui.channel.'+category,channelLabels[category]||channelLabels.unknown);
    const descriptionField=s.protocolDetail?'protocolDetail':'detail';
    const checks=s.checks?.length?'<h3 class="section-title">'+this.ui('ui.app.stepHtml.text.0203','What the receiver checks')+'</h3><ul class="check-list">'+s.checks.map(check=>'<li>'+uiIcon('check')+'<span>'+this.prose(owner,'checks',check)+'</span></li>').join('')+'</ul>':'';
    return '<div class="inspector-kicker">'+kicker+' · '+this.ltr(s.phase)+'</div><h2 class="inspector-title">'+this.stepProse(s,'title',s.title)+'</h2><p class="inspector-summary">'+this.stepProse(s,summaryField,s[summaryField])+'</p><div class="route-row"><span class="route-actor">'+this.ltr(from.name)+'</span>'+uiIcon('arrow')+'<span class="route-actor">'+this.ltr(to.name)+'</span></div><span class="channel-badge" data-channel="'+category+'">'+channel+' · '+protocol+'</span>'+(!profile||this.learningDetail!=='journey'?'<p class="step-detail step-description">'+this.stepProse(s,descriptionField,s[descriptionField])+'</p>':'')+'<button class="button quiet replay-button" data-replay>'+uiIcon('play')+this.ui('ui.step.replay','Replay this step')+'</button>'+projectedFields+layers+crypto+checks+'<h3 class="section-title">'+this.ui('ui.app.stepHtml.text.0204','Explore these attributes')+'</h3><div class="attribute-list">'+fields.filter(id=>ATTRIBUTES[id]).map(id=>this.attributeButton(id)).join('')+'</div>';
  }
  fieldControlMetadata() {return this.presentationMode==='compact'?'aria-controls="compact-field-definition"':'aria-haspopup="dialog" aria-controls="attribute-popup" aria-keyshortcuts="F2"';}
  attributeButton(id,kind,ownerName) {const a=this.definition(id);return `<button class="attribute-button" data-attribute="${id}" ${this.fieldControlMetadata()}><code dir="ltr" translate="no">${escapeHtml(a.name)}</code>${ownerName?`<span class="attribute-owner">${this.ltr(ownerName)}</span>`:''}${kind?`<span class="kind-badge ${kind}">${this.ui('ui.attribute-kind.'+kind,ATTR_KIND[kind]||kind)}</span>`:uiIcon('info')}</button>`;}
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
    this.heldView?.reset();this.objectTraceSelection=null;
    this.player.stop(false);this.hidePopups();this.activeSteps=null;this.attributeSelection=null;this.traceQueue=[];this.traceIndex=0;this.index=0;this.visited.clear();this.inspection={type:'step'};
    if(this.presentationMode==='full'){this.refs.packet.hidden=true;this.hideStepAttributes();}
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
    if(grantTopicFlows[id]||LAB_ATTRIBUTES[id]||LAB_TOPICS[id])return null;
    const modes=[this.mode,...Object.keys(modeMetadata).filter(m=>m!==this.mode)];
    const unique=values=>[...new Set(values)];
    for(const mode of modes)for(const upstream of unique([this.upstream,'single','keycloak','external']))for(const architecture of unique([this.architecture,'web','native']))for(const authenticator of unique([this.authenticator,'yubikey','hello'])){
      if(!this.canProbeJourney(mode,upstream))continue;
      const config={forceCore:true,oidcFlow:'authorization-code',applicationProtocol:'oidc',brokerProtocol:upstream==='external'&&this.providerProfileId!=='generic'?this.providerProfile.protocol:'oidc',upstream,architecture,authenticator};
      if(getAttributeUsage(this.journeyFor(mode,config),id,authenticator).length)return {mode,upstream,architecture,authenticator};
    }
    return null;
  }
  traceInspection() {return this.objectTraceSelection?{type:'step'}:{type:ATTRIBUTE_TOPICS[this.attributeSelection]?'topic':'attribute',id:this.attributeSelection};}
  buildAttributeTrace(id,usages=this.attributeUsage(this.steps,id)) {
    const examples={...this.runtimeEnvironment.projectExamples({...(this.isDirectFido?getFidoExampleOverrides():getExampleOverrides(this.architecture,this.upstream)),...(this.isUsingSaml?getSamlExampleOverrides(this.protocolConfig()):{}),...(this.isAdvancedFlow?this.advancedFlow.examples(this.protocolConfig()):{}),...this.scenarioSnapshot().exampleOverrides},this.environmentOptions)};
    getAttributeIds(id).forEach(field=>examples[field]=this.definition(field).example);
    return buildAttributeTrace(usages,examples,this.scenarioSnapshot().protocolValues||this.labModel?.protocolValues||{});
  }
  selectAttribute(id,animate=true) {
    if(this.presentationMode==='compact')return this.enterFieldTrace(id);
    const returnTarget=captureFocusTarget(this,document.activeElement);
    id=this.labAttributeAlias(id);
    if(!getAttributeIds(id).length)return;
    this.objectTraceSelection=null;
    this.player.stop(false);this.hidePopups();this.attributeSelection=id;this.traceIndex=0;this.visited.clear();this.packetIdentity='';
    this.attributeUsages=this.attributeUsage(this.steps,id);
    this.traceQueue=this.buildAttributeTrace(id,this.attributeUsages);
    if(this.scenarioOwnedActors&&!this.showInternals&&this.attributeUsages.some(usage=>usage.actions.some(action=>this.scenarioOwnedActors[action.actorId]?.parentId))){this.showInternals=true;this.renderActors();this.renderWorkspace();}
    this.heldView?.configureGeometry();this.renderActors();
    if(!this.heldGeometry&&this.ensureLayoutRoutes(this.traceQueue))this.renderActors();
    this.index=this.traceQueue[0]?.sourceIndex||0;this.inspection=this.traceInspection();this.refs.packet.hidden=true;this.hideStepAttributes();
    this.renderConnections();this.renderTimeline();this.renderAttributeIndex();this.renderFocus();this.renderInspector();this.updateStep();this.updateControls();
    if(returnTarget&&(returnTarget.attributeId||returnTarget.topicId))this.restoreTargetFocus(returnTarget,{attributeId:ATTRIBUTE_TOPICS[id]?undefined:id,preferIndex:true});
    if(animate&&this.traceQueue.length)this.playAttribute();
  }
  clearAttribute() {
    this.attributeSelection=null;this.objectTraceSelection=null;this.traceQueue=[];this.attributeUsages=[];this.reset();
  }
  playAttribute() {
    if(!this.hasTrace||!this.traceQueue.length)return;
    this.ensureRunningSpeed();
    this.inspection=this.traceInspection();this.visited.clear();this.player.play(this.traceQueue,this.objectTraceSelection?'object':'attribute');
  }
  selectionName(id=this.attributeSelection) {return ATTRIBUTE_TOPICS[id]?.name||this.definition(id).name||id;}
  indexContext(id,definition) {
    if(LAB_ATTRIBUTES[id]){
      const models=labAttributeScenarios(id);
      return models.length?models.map(model=>this.prose('lesson:'+model.id,'title',model.title,{scenarioId:model.id,variantId:'default',subfixtureId:null})).join(' · '):definition.standard?this.ltr(definition.standard):this.ui('ui.index.context.protocol','Protocol attribute');
    }
    if(this.isAdvancedFlow&&getAttributeUsage(this.steps,id,this.authenticator).length)return this.prose('lesson:'+(this.advancedFlow.id||this.oidcFlow),'title',this.advancedFlow.title);
    if(SERVICE_ATTRIBUTES[id])return this.ui('ui.index.context.service','Service accounts · client_credentials');
    if(DEVICE_ATTRIBUTES[id])return this.ui('ui.index.context.device','Device Authorization Flow');
    if(CIBA_ATTRIBUTES[id])return this.ui('ui.index.context.ciba','CIBA · controlled authentication channel');
    if(EXCHANGE_ATTRIBUTES[id])return this.ui('ui.index.context.exchange','Token exchange · Standard V2');
    if(SAML_ATTRIBUTES[id])return /Broker$|B$/.test(id)?this.ui('ui.index.context.saml-upstream','SAML · upstream IdP ↔ Realm A'):/App$/.test(id)?this.ui('ui.index.context.saml-app','SAML · Realm A ↔ application'):/A$/.test(id)?this.ui('ui.index.context.saml-broker','SAML · Realm A provider / broker'):this.ui('ui.index.context.saml-policy','SAML XML · binding / assertion / SP policy');
    if(JWE_ATTRIBUTES[id])return /Broker$/.test(id)?this.ui('ui.index.context.jwe-upstream','JWE · upstream IdP → Realm A'):this.ui('ui.index.context.jwe-app','JWE · Realm A → application');
    if(this.isDirectFido&&(/WebAuthn|FIDO|CTAP/.test(definition.standard)||['privateKey','credentialPublicKey'].includes(id)))return this.ui('ui.index.context.direct','Web application RP ↔ authenticator');
    if(this.isSingleRealm&&(/Broker|B$/.test(id)||['clientSecret','authorizationHeader'].includes(id)))return this.ui('ui.index.context.unused-broker','Brokered setup · unused here');
    if(this.isSingleRealm&&id.startsWith('otp'))return this.ui('ui.index.context.realm-totp','TOTP · Keycloak Realm A');
    if(this.isSingleRealm&&(/WebAuthn|FIDO|CTAP/.test(definition.standard)||['privateKey','credentialPublicKey'].includes(id)))return this.ui('ui.index.context.realm-authenticator','Realm A ↔ authenticator');
    if(/Broker|B$/.test(id)||['clientSecret','authorizationHeader'].includes(id))return this.ui('ui.index.context.broker','Realm A ↔ upstream provider');
    if(/App|A$/.test(id)||['codeVerifier','codeChallenge','codeChallengeMethod'].includes(id))return this.ui('ui.index.context.application','Application ↔ Realm A');
    if(id.startsWith('otp'))return this.ui('ui.index.context.upstream-totp','TOTP · upstream provider');
    return definition.standard?this.ltr(definition.standard.split(' / ')[0]):this.ui('ui.index.context.protocol','Protocol attribute');
  }
  fieldTopicSearchText() {
    if(this.localizer.locale==='en')return null;
    if(this.activeFieldTopicText?.revision===this.localizer.revision)return this.activeFieldTopicText.values;
    const values=new Map();
    for(const [id,topic]of Object.entries(ATTRIBUTE_TOPICS)){
      const title=this.proseText('topic:'+id,'name',topic.name);
      for(const field of topic.attributeIds)values.set(field,(values.get(field)||'')+' '+title);
    }
    this.activeFieldTopicText={revision:this.localizer.revision,values};return values;
  }
  fieldSearchRank(id,definition,query) {
    if(query.empty)return 0;
    if(this.fieldSearchRevision!==this.localizer.revision||this.fieldSearchSource!==this.definitionMemo){this.fieldSearchRevision=this.localizer.revision;this.fieldSearchSource=this.definitionMemo;this.fieldSearchRecords=new Map();this.activeFieldTopicText=null;}
    this.englishFieldSearch??=new WeakMap();
    let base=this.englishFieldSearch.get(definition);
    if(!base){base=createSearchFields({identifiers:[id,definition.name],phrases:[definition.meaning||definition.description||'',definition.purpose||'',definition.origin||definition.generator||''],context:[definition.standard||'',studioFieldTopicText.get(id)||'']});this.englishFieldSearch.set(definition,base);}
    if(base.exact.has(query.identifier))return -1;
    let record=this.fieldSearchRecords.get(id);
    if(record?.definition!==definition){
      const overlay=localizedSearchIndex(this.localizer,'field',id,definition,this.localeContext()),topics=this.fieldTopicSearchText()?.get(id)||'';
      const extra=topics?createSearchFields({context:[topics]}):null;
      record={definition,base,combined:overlay||extra?mergeSearchFields(base,overlay?.base,extra):base};this.fieldSearchRecords.set(id,record);
    }
    const original=rankSearchFields(record.base,query);if(original!==null)return original;
    const localized=rankSearchFields(record.combined,query);return localized===null?null:localized+4;
  }
  topicSearchRank(id,topic,query) {
    if(query.empty)return 0;
    this.englishTopicSearch??=new WeakMap();
    let cached=this.englishTopicSearch.get(topic);
    if(!cached||cached.memo!==this.definitionMemo){
      const identifiers=[id,...topic.attributeIds.map(field=>this.definition(field).name)];
      cached={memo:this.definitionMemo,fields:createSearchFields({identifiers,phrases:[topic.name,topic.summary||'']})};this.englishTopicSearch.set(topic,cached);
    }
    const original=rankSearchFields(cached.fields,query);if(original!==null)return original;
    const overlay=localizedSearchIndex(this.localizer,'topic',id,topic,this.localeContext());
    if(!overlay)return null;
    const localized=rankSearchFields(overlay.base,query,cached.fields);return localized===null?null:localized+4;
  }
  renderAttributeIndex() {
    if(this.refs['attribute-index'].hidden)return;
    const focused=document.activeElement,focusKey=this.refs['attribute-index-list'].contains(focused)?['data-index-attribute',focused.dataset.indexAttribute]:this.refs['attribute-topics'].contains(focused)?['data-trace-topic',focused.dataset.traceTopic]:null;
    const steps=this.steps,query=prepareSearchQuery(this.attributeQuery),compact=this.presentationMode==='compact',browser=compact?this.compactView.fieldBrowser:null;
    const queryIdentity=this.attributeQuery.trim().toLowerCase();
    if(compact&&browser.context!==this.heldView.contextId){browser.context=this.heldView.contextId;browser.scope='current';browser.limit=this.compactView.fieldBatchSize;}
    if(compact&&browser.query!==queryIdentity){browser.query=queryIdentity;browser.limit=this.compactView.fieldBatchSize;}
    const usageIds=new Set();
    for(const step of steps)for(const action of getStepAttributeOperations(step,this.authenticator))if(action.kind!=='inspect')usageIds.add(action.attributeId);
    let indexIds=!compact&&this.labModel?.profile&&query.empty?new Set(this.labModel.ids):null;
    if(compact&&query.empty&&browser.scope!=='global'){
      indexIds=new Set([...usageIds,...(this.labModel?.ids||[])]);
      for(const step of steps)for(const id of step.fields||[])indexIds.add(id);
    }
    const hasUsage=id=>ATTRIBUTE_TOPICS[id]?ATTRIBUTE_TOPICS[id].attributeIds.some(field=>usageIds.has(field)):usageIds.has(id);
    const topicLabels={clientIdentity:['ui.index.topic.client','client_id · App'],pkce:['ui.index.topic.pkce','PKCE'],webauthn:['ui.index.topic.webauthn','WebAuthn'],fido2:['ui.index.topic.fido','FIDO2 / CTAP2'],totp:['ui.index.topic.totp','TOTP'],saml:['ui.index.topic.saml','SAML'],jwe:['ui.index.topic.jwe','JWE'],serviceAccounts:['ui.index.topic.service','Service accounts'],deviceFlow:['ui.index.topic.device','Device Flow'],ciba:['ui.index.topic.ciba','CIBA'],tokenExchange:['ui.index.topic.exchange','Token exchange']};
    this.refs['attribute-topics'].innerHTML=Object.entries(ATTRIBUTE_TOPICS).filter(([,topic])=>!topic.labScenarioId||topic.labScenarioId===(this.labModel?.id||this.labScenarioId)).map(([id,topic])=>{
      const count=hasUsage(id)?this.attributeUsage(steps,id).length:0;if(indexIds&&!count)return '';
      const source=id==='clientIdentity'&&this.isAdvancedFlow?'The configured public client identifier selects the registration. Confidential variants authenticate the client separately; no identifier is generated per request.':this.isSingleRealm?topic.summary.replace(/\bB\b/g,'Realm A'):topic.summary;
      const summary=id==='clientIdentity'&&this.isAdvancedFlow?this.uiText('ui.index.topic.client-summary',source):this.proseText('topic:'+id,'summary',source,{realm:this.isSingleRealm?'single':this.upstream});
      const label=topicLabels[id]?this.ui(topicLabels[id][0],topicLabels[id][1]):this.prose('topic:'+id,'name',topic.name||id);
      return '<button class="attribute-topic '+(id===this.attributeSelection?'is-selected':'')+'" data-trace-topic="'+escapeHtml(id)+'" aria-pressed="'+(id===this.attributeSelection)+'" title="'+escapeHtml(summary)+'"><span>'+label+'</span><span dir="ltr" translate="no">'+count+'</span></button>';
    }).join('');
    let matches=Object.entries(ATTRIBUTES).filter(([id])=>!indexIds||indexIds.has(id)).map(([id,definition])=>({id,definition,rank:query.empty?0:this.fieldSearchRank(id,this.definition(id),query)})).filter(row=>row.rank!==null);
    matches.sort((left,right)=>left.rank-right.rank||left.definition.name.localeCompare(right.definition.name)||left.id.localeCompare(right.id));
    const rows=(compact?matches.slice(0,browser.limit):matches).map(({id})=>{
      const definition=this.definition(id),count=hasUsage(id)?getAttributeUsage(steps,id,this.authenticator).length:0,pressed=String(id===this.attributeSelection);
      const className='attribute-index-item technical-ltr '+(id===this.attributeSelection?'is-selected':'')+' '+(count?'':'is-unavailable'),descriptionId='field-index-context-'+id;
      const label=this.uiText('ui.index.field-label',definition.name+'. '+count+' source steps in this journey.',{name:definition.name,count});
      const contents='<code dir="ltr" translate="no">'+escapeHtml(definition.name)+'</code><span class="attribute-index-count" dir="ltr" translate="no" title="'+escapeHtml(this.uiText('ui.app.renderAttributeIndex.attribute.0205','Journey steps with an operation'))+'">'+count+'</span><span class="attribute-index-context locale-prose" id="'+escapeHtml(descriptionId)+'">'+this.indexContext(id,definition)+'</span>';
      return {id,pressed,className,contents,label,markup:'<button class="'+className+'" data-index-attribute="'+escapeHtml(id)+'" aria-label="'+escapeHtml(label)+'" aria-describedby="'+escapeHtml(descriptionId)+'" '+this.fieldControlMetadata()+' aria-pressed="'+pressed+'">'+contents+'</button>'};
    });
    const list=this.refs['attribute-index-list'],signature=this.localizer.revision+'\0'+rows.map(row=>row.id).join('\0');
    if(this.attributeIndexRows?.list===list&&this.attributeIndexRows.signature===signature){
      for(const row of rows){
        const previous=this.attributeIndexRows.entries.get(row.id);if(previous.markup===row.markup)continue;
        previous.node.setAttribute('class',row.className);previous.node.setAttribute('aria-label',row.label);previous.node.setAttribute('aria-pressed',row.pressed);previous.node.innerHTML=row.contents;previous.markup=row.markup;
      }
    }else{
      list.innerHTML=rows.map(row=>row.markup).join('');
      const entries=new Map();let index=0;for(const node of list.querySelectorAll('[data-index-attribute]')){const row=rows[index++];entries.set(row.id,{node,markup:row.markup});}
      this.attributeIndexRows={list,signature,entries};
    }
    this.attributeIndexRows.total=matches.length;this.attributeIndexRows.global=!indexIds;
    this.refs['attribute-search'].placeholder=this.uiText('ui.index.search-placeholder','Search fields across every journey');
    if(!this.localeCompositions.has(this.refs['attribute-search']))this.refs['attribute-search'].value=this.attributeQuery;
    this.filterAttributeIndex();
    if(focusKey){
      const replacement=[...this.refs['attribute-index'].querySelectorAll('['+focusKey[0]+']')].find(node=>node.getAttribute(focusKey[0])===focusKey[1]);
      if(replacement&&!replacement.hidden){
        if(this.attributeAnchor===focused)this.attributeAnchor=replacement;
        this.restoringPopupFocus=true;try{replacement.focus({preventScroll:true});}finally{this.restoringPopupFocus=false;}
      }
    }
  }
  filterAttributeIndex() {
    const query=prepareSearchQuery(this.attributeQuery);let count=0;
    for(const [id,{node}]of this.attributeIndexRows.entries){node.hidden=!query.empty&&this.fieldSearchRank(id,this.definition(id),query)===null;if(!node.hidden)count++;}
    let topics=0;
    this.refs['attribute-topics'].querySelectorAll('[data-trace-topic]').forEach(button=>{const id=button.dataset.traceTopic;button.hidden=this.topicSearchRank(id,ATTRIBUTE_TOPICS[id],query)===null;if(!button.hidden)topics++;});
    if(this.presentationMode==='compact'){
      const total=this.attributeIndexRows.total,global=this.attributeIndexRows.global,batch=this.compactView.fieldBatchSize,params={count:total,visible:count,total,batch};
      const source='Showing '+count+' of '+total+(!query.empty?' matching global fields':global?' global fields':' current-lesson fields')+' · '+batch+' per batch · numbers count current-journey steps';
      this.refs['attribute-index-meta'].textContent=!query.empty?this.uiText('ui.index.meta.matching',source,params):global?this.uiText('ui.index.meta.global',source,params):this.uiText('ui.index.meta.current',source,params);
      const more=this.refs['compact-field-more'],remaining=Math.min(batch,total-count);more.hidden=count>=total;more.textContent=this.uiText('ui.index.more','Show '+remaining+' more fields',{count:remaining});
      for(const button of this.querySelectorAll('[data-compact-field-scope]'))button.setAttribute('aria-pressed',String(button.dataset.compactFieldScope===(global?'global':'current')));
    }else{
      const source=count+(!query.empty?' matching attributes · global catalog search · numbers count current-journey steps':this.labModel?.profile?' current-journey attributes · type to search all protocols':' attributes · numbers count journey steps · 0 means unused in this setup');
      this.refs['attribute-index-meta'].textContent=!query.empty?this.uiText('ui.index.meta.full-matching',source,{count}):this.labModel?.profile?this.uiText('ui.index.meta.full-current',source,{count}):this.uiText('ui.index.meta.full-global',source,{count});
    }
    this.refs['attribute-index-empty'].hidden=!!(count||topics);
  }
  renderFocus() {
    const focus=this.refs['attribute-focus'];focus.hidden=!this.hasTrace;
    if(!this.hasTrace){focus.innerHTML='';return;}
    if(this.objectTraceSelection){focus.innerHTML='<div class="focus-caption"><span class="eyebrow">'+this.ui('ui.app.renderFocus.text.0206','EXACT OBJECT HISTORY')+'</span><strong>'+this.ltr(this.objectTraceSelection)+'</strong><p>'+this.ui('ui.app.renderFocus.text.0207','Canonical source-prefix replay, including earlier source events. History does not imply current possession.')+'</p></div><div class="focus-controls"><button class="button primary" data-trace-play>'+this.ui('ui.app.renderFocus.text.0208','Replay exact history')+'</button><button class="button quiet" data-clear-trace>'+this.ui('ui.app.renderFocus.text.0209','Full journey')+'</button></div>';return;}
    const source=this.traceQueue.length+' animated moments in '+this.attributeUsages.length+' journey steps. Only selected fields move; local operations stay with their participant.';
    focus.innerHTML='<div class="focus-caption"><span class="eyebrow">'+this.ui('ui.app.renderFocus.text.0210','FOLLOW ONE ATTRIBUTE')+'</span><strong>'+this.selectionProse()+'</strong><p class="focus-summary">'+this.ui('ui.focus.summary',source,{moments:this.traceQueue.length,steps:this.attributeUsages.length})+'</p></div><div class="focus-controls"><button class="button primary" data-trace-play '+(this.traceQueue.length?'':'disabled')+'>'+uiIcon('play')+this.ui('ui.playback.replay-path','Replay path')+'</button><button class="button quiet" data-clear-trace>'+this.ui('ui.app.renderFocus.text.0211','Full journey')+'</button></div>';
  }
  traceHtml(id) {
    const topic=ATTRIBUTE_TOPICS[id],definition=this.definition(id),steps=this.traceQueue,current=this.currentStep;
    const advanced=this.isAdvancedFlow&&id==='clientIdentity',original=advanced?'Follow this application’s configured client identifier through the selected grant. It identifies a registration and is distinct from client authentication.':topic?.summary||definition.meaning;
    const summary=this.isDirectFido?String(original).replace(/\bB\b/g,'the web application'):this.isSingleRealm?String(original).replace(/\bB\b/g,'Realm A'):this.upstream==='external'?String(original).replace(/\bB\b/g,'the upstream provider'):original;
    const summaryHtml=advanced?this.ui('ui.trace.client-summary',summary):this.prose((topic?'topic:':'field:')+id,topic?'summary':'meaning',summary,{realm:this.isDirectFido?'direct':this.isSingleRealm?'single':this.upstream});
    const available=this.labModel?[]:Object.entries(modeMetadata).filter(([mode,metadata])=>this.canProbeJourney(mode)&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson&&!metadata.directFido&&!metadata.enrollment)&&this.attributeUsage(this.journeyFor(mode),id).length);
    let html='<div class="trace-heading"><div class="inspector-kicker">'+this.ui('ui.app.traceHtml.text.0212','CREATION · TRANSFER · LOCAL CHECKS')+'</div><h2>'+this.selectionProse(id)+'</h2><p>'+summaryHtml+'</p></div>';
    if(!steps.length){
      const contexts=getAttributeContext(this.steps,id,this.authenticator);
      const missing=contexts.length?this.ui('ui.trace.context-only','No replayable operation for this attribute in the current journey. It appears only as related context here.'):this.ui('ui.trace.no-operation','No replayable operation for this attribute in the current journey.');
      html+='<div class="context-note">'+missing+'</div><h3 class="section-title">'+this.ui('ui.app.traceHtml.text.0213','Available journeys')+'</h3><div class="attribute-list">'+(available.map(([mode,metadata])=>'<button class="button" data-trace-mode="'+mode+'">'+this.prose('mode:'+mode,'title',metadata.title)+'</button>').join('')||'<p>'+this.ui('ui.trace.not-transmitted','This is configured context; it is not transmitted by the simulated exchanges.')+'</p>')+'</div>';
      const ids=getAttributeIds(id),labChoices=LAB_SCENARIOS.filter(model=>model.id!==this.labScenarioId&&(id==='topic-'+model.id||ids.some(field=>model.ids.includes(field))));
      const explore=model=>this.ui('ui.trace.explore-lesson','Explore '+model.title,{title:{ownerId:'lesson:'+model.id,fieldPath:'title',source:model.title,context:this.localeContext({scenarioId:model.id,variantId:'default'})}});
      if(labChoices.length)html+='<h3 class="section-title">'+this.ui('ui.trace.available-labs','Available lab scenarios')+'</h3><div class="attribute-list">'+labChoices.map(model=>'<button class="button" data-trace-lab="'+model.id+'">'+explore(model)+'</button>').join('')+'</div>';
      if(FIDO_ATTRIBUTES[id]&&!this.providerOwnsAuthentication&&this.authenticator!=='yubikey'&&(!this.isAdvancedFlow||this.advancedFlow.hasPerson))html+='<div class="context-note">'+this.ui('ui.trace.external-fido','These CTAP2 operations belong to the external FIDO2 security-key path. Windows Hello uses its platform interface.')+'</div><button class="button primary" data-trace-device="yubikey">'+this.ui('ui.trace.explore-yubikey','Explore with YubiKey')+'</button>';
      if(id==='saml'||SAML_ATTRIBUTES[id])html+='<div class="context-note">'+this.ui('ui.trace.saml','SAML Web SSO carries XML requests and assertions. Switch to the matching protocol to follow this field.')+'</div><button class="button primary" data-trace-protocol="saml">'+this.ui('ui.trace.explore-saml','Explore SAML')+'</button>';
      if(id==='jwe'||JWE_ATTRIBUTES[id])html+='<div class="context-note">'+this.ui('ui.trace.jwe','JWE protects an OIDC ID token when the issuer and recipient support and configure encryption.')+'</div><button class="button primary" data-trace-protocol="jwe">'+this.ui('ui.trace.explore-jwe','Enable JWE and trace')+'</button>';
      const grantTopics={'client-credentials':'serviceAccounts',device:'deviceFlow',ciba:'ciba','token-exchange':'tokenExchange'};
      const grants=Object.entries(advancedFlowModels).filter(([flow,model])=>flow!==this.oidcFlow&&(id===grantTopics[flow]||model.ids.includes(id)));
      if(grants.length)html+='<h3 class="section-title">'+this.ui('ui.trace.other-grants','Other grant walkthroughs')+'</h3><div class="attribute-list">'+grants.map(([flow,model])=>'<button class="button" data-trace-grant="'+flow+'">'+explore(model)+'</button>').join('')+'</div>';
      const codeJourney=this.isAdvancedFlow?this.findAuthorizationJourney(id):null;
      if(codeJourney){
        const modeTitle=modeMetadata[codeJourney.mode].title,params={title:{ownerId:'mode:'+codeJourney.mode,fieldPath:'title',source:modeTitle,context:this.localeContext()}};
        const label=codeJourney.authenticator==='yubikey'?this.ui('ui.trace.authorization-code-yubikey','Explore Authorization Code · '+modeTitle+' · YubiKey',params):this.ui('ui.trace.authorization-code','Explore Authorization Code · '+modeTitle,params);
        html+='<button class="button primary" data-trace-grant="authorization-code" data-grant-mode="'+codeJourney.mode+'" data-grant-authenticator="'+codeJourney.authenticator+'" data-grant-upstream="'+codeJourney.upstream+'" data-grant-architecture="'+codeJourney.architecture+'">'+label+'</button>';
      }
      if(!this.isDirectFido&&this.applicationProtocol==='saml'&&(['pkce','clientIdentity','clientIdApp','redirectApp','stateApp','nonceApp','codeA','idTokenA','accessTokenA','refreshToken','codeVerifier','codeChallenge','codeChallengeMethod','clientSecretApp','authorizationHeaderApp'].includes(id))||!this.isDirectFido&&this.brokerProtocol==='saml'&&['clientIdBroker','redirectBroker','stateBroker','nonceBroker','codeB','idTokenB','accessTokenB','clientSecret','authorizationHeader'].includes(id))html+='<button class="button primary" data-trace-protocol="oidc">'+this.ui('ui.trace.explore-oidc','Explore the OIDC hop')+'</button>';
      const setups=Object.entries(UPSTREAMS).filter(([key])=>!this.isAdvancedFlow&&key!==this.upstream).map(([key,value])=>{
        const modes=[this.mode,...Object.keys(JOURNEYS)].filter(mode=>JOURNEYS[mode]),mode=modes.find(mode=>this.canProbeJourney(mode,key)&&this.attributeUsage(this.journeyFor(mode,{upstream:key}),id).length);
        if(!mode)return '';
        const title=value.label||value.title,label=key==='keycloak'?this.ui('ui.trace.explore-two-realms','Explore two Keycloak realms'):this.ui('ui.trace.explore-upstream','Explore '+title,{title:{ownerId:'upstream:'+key,fieldPath:value.label?'label':'title',source:title,context:this.localeContext()}});
        return '<button class="button" data-trace-upstream="'+key+'" data-setup-mode="'+mode+'">'+label+'</button>';
      }).filter(Boolean);
      if(setups.length)html+='<h3 class="section-title">'+this.ui('ui.trace.other-setups','Other identity setups')+'</h3><div class="attribute-list">'+setups.join('')+'</div>';
    }else{
      if(id==='clientIdentity'||id==='clientIdApp'){
        const note=this.labModel?this.ui('ui.trace.registered-client','Configured during client registration and reused across requests. This public identifier selects the application; confidential-client authentication is a separate check. Follow the selected scenario to see whether it travels in an authorization form, HTTP Basic header, or signed client assertion. An ID token’s aud identifies its client; an access token’s aud identifies its intended resource recipient.'):this.isAdvancedFlow?this.ui('ui.trace.grant-client','Configured during client registration; this public identifier selects the application. A confidential client authenticates separately using its protected credential. In this Basic example its client ID is encoded in Authorization; a public device client instead sends client_id in the form. Device/CIBA ID-token aud identifies the client. A service-account or exchanged access-token aud identifies the configured API recipient, not necessarily this client.'):this.ui('ui.trace.core-client','Configured during client registration and reused across logins. This public identifier selects the application; it is not a secret. In the authorization request it is client_id. During redemption the native app sends it in the body; this web backend identifies itself through Authorization: Basic. The application later compares the ID token’s aud with this configured identifier.');
        html+='<div class="context-note">'+note+'</div>';
      }
      if(id==='pkce'||['codeVerifier','codeChallenge','codeChallengeMethod'].includes(id)){
        const formula='code_challenge =\nBASE64URL(SHA256(ASCII(code_verifier)))';
        html+='<div class="trace-formula"><pre '+this.rawValueAttrs(formula)+'><code dir="ltr" translate="no">'+escapeHtml(formula)+'</code></pre><p>'+this.ui('ui.trace.pkce-check','Realm A recomputes the same value\nand compares it with the saved challenge.')+'</p></div>';
      }
      html+='<button class="button primary" data-trace-play>'+uiIcon('play')+this.ui('ui.trace.replay-complete','Replay complete attribute path')+'</button><div class="trace-heading"><h3 class="section-title">'+this.ui('ui.trace.current-moment','CURRENT MOMENT · '+(this.traceIndex+1)+' / '+steps.length,{position:this.traceIndex+1,total:steps.length})+'</h3><h3>'+this.stepProse(current,'title',current?.title)+'</h3><p>'+this.stepProse(current,'detail',current?.detail)+'</p><p class="trace-step-route">'+this.ui('ui.trace.current-route',this.actor(current.from).name+' → '+this.actor(current.to).name+' · journey step '+(current.sourceIndex+1),{from:this.actor(current.from).name,to:this.actor(current.to).name,index:current.sourceIndex+1})+'</p></div><h3 class="section-title">'+this.ui('ui.app.traceHtml.text.0214','Where and how it is used')+'</h3><div class="trace-step-list">'+steps.map((step,index)=>'<button data-trace-step="'+index+'" class="'+(index===this.traceIndex?'is-active':'')+'" aria-current="'+(index===this.traceIndex?'step':'false')+'"><span class="trace-step-number" dir="ltr" translate="no">'+(index+1)+'</span><span class="trace-step-title">'+this.stepProse(step,'title',step.title)+'</span><span class="trace-step-route">'+this.ui('ui.trace.route',this.actor(step.from).name+' → '+this.actor(step.to).name+' · journey '+(step.sourceIndex+1),{from:this.actor(step.from).name,to:this.actor(step.to).name,index:step.sourceIndex+1})+'</span><span class="trace-action" data-action="'+step.traceKind+'">'+this.traceAction(step.traceKind)+'</span></button>').join('')+'</div>';
    }
    html+='<button class="back-button" data-clear-trace>'+uiIcon('previous')+this.ui('ui.trace.return','Return to full journey')+'</button>';
    if(topic)html+='<h3 class="section-title">'+this.ui('ui.app.traceHtml.text.0215','Fields in this topic')+'</h3><div class="attribute-list">'+topic.attributeIds.map(field=>this.attributeButton(field)).join('')+'</div>';
    else html+='<details class="trace-definition" data-study-key="trace-definition:'+escapeHtml(id)+'" open><summary>'+this.ui('ui.app.traceHtml.text.0216','Meaning, origin & primary source')+'</summary>'+this.attributeHtml(id,true)+'</details>';
    return html;
  }
  actorHtml(actor) {
    if(!actor)return '';
    const owner='actor:'+actor.id;
    return '<div class="inspector-kicker">'+this.ltr(actor.role)+'</div><div class="inspector-actor-art">'+this.illustration(actor.id)+'</div><h2 class="inspector-title">'+this.ltr(actor.name)+'</h2><p class="inspector-summary">'+this.prose(owner,'plainRole',actor.plainRole)+'</p>'+this.actorContextHtml(actor.id)+this.actorAttributesHtml(actor)+(actor.notes||[]).map(note=>'<div class="context-note">'+this.prose(owner,'notes',note)+'</div>').join('')+(['hello','yubikey'].includes(actor.id)?'<button class="button primary" data-use-authenticator="'+actor.id+'">'+this.ui('ui.app.actorHtml.text.0217','Use this passkey device')+'</button>':actor.id==='totp'?'<button class="button primary" data-use-totp>'+this.ui('ui.actor.explore-totp','Explore Password + TOTP')+'</button>':'');
  }
  actorAttributesHtml(actor) {
    return Object.entries(ATTR_KIND).map(([kind,label])=>{
      const fields=actor.attributes.filter(item=>item.kind===kind&&ATTRIBUTES[item.id]);
      return fields.length?'<section class="attribute-group"><h3 class="section-title"><span class="kind-badge '+kind+'">'+this.ui('ui.attribute-kind.'+kind,label)+'</span></h3><div class="attribute-list">'+fields.map(item=>this.attributeButton(item.id,undefined,item.ownerName)).join('')+'</div></section>':'';
    }).join('');
  }
  attributeHtml(id,pinned=false) {
    const a=this.definition(id);if(!ATTRIBUTES[id])return '';
    const example=formatProtocolValue(a.example),owner='field:'+id;
    return '<div class="definition"><div class="inspector-kicker">'+this.ltr(a.standard)+'</div><h2 '+(pinned?'':'id="attribute-popup-field-title" ')+'class="'+(pinned?'inspector-title':'popup-title')+'"><code '+this.rawValueAttrs(a.name)+'>'+escapeHtml(a.name)+'</code></h2><p class="inspector-summary">'+this.prose(owner,a.meaning?'meaning':'description',a.meaning||a.description)+'</p><dl><dt>'+this.ui('ui.app.attributeHtml.text.0218','Where it comes from')+'</dt><dd>'+this.prose(owner,a.origin?'origin':'generator',a.origin||a.generator)+'</dd><dt>'+this.ui('ui.app.attributeHtml.text.0219','Why it exists')+'</dt><dd>'+this.prose(owner,'purpose',a.purpose)+'</dd><dt>'+this.ui('ui.app.attributeHtml.text.0220','Example')+'</dt><dd><code '+this.rawValueAttrs(example)+'>'+escapeHtml(example)+'</code></dd></dl><a class="source-link" href="'+escapeHtml(a.source)+'" target="_blank" rel="noopener noreferrer">'+this.ui('ui.attribute.read-source','Read the primary specification')+' '+uiIcon('arrow')+'</a></div>';
  }
  showActorPopup(id,anchor) {
    if(this.restoringPopupFocus)return false;
    clearTimeout(this.closeTimer);const key=resolveActor(id,this.authenticator),registry=this.scenarioOwnedActors||ACTORS;
    if(!registry[key]||!anchor||!this.contains(anchor)){this.closePopup('actor');return false;}
    const actor=this.actor(key);
    this.actorHelpId=key;
    const popup=this.refs['actor-popup'],active=document.activeElement;
    const nestedFocus=!this.refs['attribute-popup'].hidden&&popup.contains(this.attributeAnchor)&&this.refs['attribute-popup'].contains(active);
    if(!popup.hidden&&(this.actorAnchor===anchor||popup.contains(active)||nestedFocus)){this.placePopup(popup,this.actorAnchor,370);return true;}
    if(popup.contains(this.attributeAnchor)){clearTimeout(this.attributeTimer);this.closePopup('attribute');}
    this.setPopupAnchor('actor',anchor);
    popup.setAttribute('aria-labelledby','actor-popup-title');popup.removeAttribute('aria-label');
    this.refs['actor-popup'].innerHTML=`<div class="popup-heading"><div><h2 class="popup-title" id="actor-popup-title">${this.ltr(actor.name)}</h2><p class="popup-subtitle">${this.prose('actor:'+actor.id,'plainRole',actor.plainRole)}</p></div><button class="icon-button popup-close" data-close aria-label="${escapeHtml(this.uiText("ui.app.showActorPopup.attribute.0221","Close participant attributes"))}">${uiIcon('close')}</button></div><p class="popup-keyboard-status" role="status">${this.ui("ui.app.showActorPopup.text.0222","Keyboard focus is inside this panel · Tab explores · Escape returns")}</p>${this.actorContextHtml(actor.id)}${this.actorAttributesHtml(actor)}<p class="popup-hint">${this.ui("ui.app.showActorPopup.text.0223","Hover or focus a field for help. F2 moves focus into its explanation; Tab reaches the source link, Escape returns. Click a field to study its path.")}</p>`;
    this.refs['actor-popup'].hidden=false;this.placePopup(this.refs['actor-popup'],anchor,370);return true;
  }
  showAttributePopup(id,anchor) {
    if(this.restoringPopupFocus)return false;
    clearTimeout(this.attributeTimer);if(this.refs['actor-popup'].contains(anchor))clearTimeout(this.closeTimer);
    if(!ATTRIBUTES[id]||!anchor||!this.contains(anchor)){this.closePopup('attribute');return false;}
    const popup=this.refs['attribute-popup'];
    this.attributeHelpId=id;
    if(!popup.hidden&&(this.attributeAnchor===anchor||popup.contains(document.activeElement))){this.placePopup(popup,this.attributeAnchor,340);return true;}
    this.setPopupAnchor('attribute',anchor);
    popup.setAttribute('aria-labelledby','attribute-popup-title attribute-popup-field-title');popup.removeAttribute('aria-label');
    this.refs['attribute-popup'].innerHTML=`<div class="popup-heading"><span id="attribute-popup-title">${this.ui("ui.app.showAttributePopup.text.0224","Attribute explanation")}</span><button class="icon-button popup-close" data-close aria-label="${escapeHtml(this.uiText("ui.app.showAttributePopup.attribute.0225","Close attribute explanation"))}">${uiIcon('close')}</button></div><p class="popup-keyboard-status" role="status">${this.ui("ui.app.showAttributePopup.text.0226","Keyboard focus is inside this panel · Tab explores · Escape returns")}</p>`+this.attributeHtml(id);
    this.refs['attribute-popup'].hidden=false;this.placePopup(this.refs['attribute-popup'],anchor,340);return true;
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
  restoreTargetFocus(target,options={}){const node=resolveFocusTarget(this,target,options);if(node&&node!==document.activeElement){this.restoringPopupFocus=true;try{node.focus({preventScroll:options.preventScroll!==false});}finally{this.restoringPopupFocus=false;}}}
  deferCloseActor(next){clearTimeout(this.closeTimer);if(this.popupOwnsFocus('actor',next))return;this.closeTimer=setTimeout(()=>{if(!this.popupOwnsFocus('actor'))this.closePopup('actor');},250);}
  deferCloseAttribute(next){clearTimeout(this.attributeTimer);if(this.popupOwnsFocus('attribute',next))return;this.attributeTimer=setTimeout(()=>{if(!this.popupOwnsFocus('attribute'))this.closePopup('attribute');},180);}
  hidePopups(){clearTimeout(this.closeTimer);clearTimeout(this.attributeTimer);if(this.refs?.['actor-popup'])this.closePopup('actor');if(this.refs?.['attribute-popup'])this.closePopup('attribute');}
  filterGlossary(query){this.glossaryQuery=query;const prepared=prepareSearchQuery(query);this.refs.inspector.querySelectorAll('[data-glossary-attribute]').forEach(button=>{const id=button.dataset.glossaryAttribute;button.hidden=!prepared.empty&&this.fieldSearchRank(id,this.definition(id),prepared)===null;});}
  showToast(message,language=this.localizer.locale){this.refs.toast.removeAttribute('data-locale-failure');this.refs.toast.textContent=message;this.refs.toast.setAttribute('lang',language);this.refs.toast.setAttribute('dir',language==='en'?'ltr':this.localizer.direction);this.refs.toast.hidden=false;clearTimeout(this.toastTimer);this.toastTimer=setTimeout(()=>{this.refs.toast.hidden=true;},5000);}
}

customElements.define('auth-flow-studio',AuthFlowStudio);
