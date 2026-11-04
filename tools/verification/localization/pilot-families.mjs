// Actual-program diagnostic only. Importing this module never launches a browser.
import assert from 'node:assert/strict';

export const PILOT_CELLS=['en','de','he'].map(locale=>({id:'pilot-families-'+locale+'-full-source-http',kind:'pilot',locale,presentation:'full',loadingMode:'source-http',width:1440}));
export const PILOT_SCOPE=['Core','Full','Compact','participant/field/help','picker/catalog/cases','protocol-state/history','held/object/connection','lesson/profile/environment','PAM','Windows-remote/protection','DNSSEC','crypto/JWT/MCP/SMB','notes/footer'];

export async function installPilotCapture(page){
  await page.addInitScript(()=>{
    const capture=window.__localizationPilot={stage:'boot',requests:new Map(),pending:null,nextChunkIndex:1,maximumResidentRecords:0,requestCalls:0,methods:new Map(),stack:[],events:[],errors:[]};
    const scalar=value=>value===null||['string','number','boolean'].includes(typeof value);
    const structured=(value,seen=new Set())=>{
      if(value===undefined)return {$undefined:true};
      if(typeof value==='bigint')return {$bigint:String(value)};
      if(scalar(value))return value;
      if(typeof value!=='object')throw new TypeError('Non-data localization parameter: '+typeof value);
      if(seen.has(value))throw new TypeError('Cyclic localization parameter');
      const next=new Set(seen);next.add(value);
      return Array.isArray(value)?value.map(item=>structured(item,next)):Object.fromEntries(Object.keys(value).sort().map(key=>[key,structured(value[key],next)]));
    };
    const record=request=>{
      capture.requestCalls++;
      const app=document.querySelector('auth-flow-studio'),context=request.context||{};
      const row={...request,context:Object.fromEntries(Object.entries(context).filter(([key,value])=>key!=='parameters'&&scalar(value))),parameters:structured(request.parameters||context.parameters||{}),runtime:{scenarioId:app?.labScenarioId||null,variantId:app?.lessonVariant||null,subfixtureId:app?.lessonSubfixture||null,presentation:app?.presentationMode||null}};
      const key=JSON.stringify(row),prior=capture.requests.get(key),surface=[capture.stage,...capture.stack].join(' > ');
      if(prior){prior.count++;prior.surfaces.add(surface);return;}
      if(capture.requests.size>=100000)throw new Error('Pilot request limit reached; no silent truncation');
      capture.requests.set(key,{...row,count:1,surfaces:new Set([surface])});
      capture.maximumResidentRecords=Math.max(capture.maximumResidentRecords,capture.requests.size);
    };
    const instrument=localizer=>{
      if(!localizer||localizer.__pilotInstrumented)return;
      Object.defineProperty(localizer,'__pilotInstrumented',{value:true});
      for(const method of ['explanation','resolve','rich']){
        const original=localizer[method];if(typeof original!=='function')throw new Error('Missing Localizer capture API '+method);
        localizer[method]=function(...args){
          if(method==='explanation'){const [owner,field,exactEnglish,context,html]=args;record({method,owner,field,exactEnglish:String(exactEnglish??''),context:context||{},html:!!html});}
          else if(method==='resolve'){const [key,exactEnglish,parameters,html,rich]=args;if(typeof key==='string')record({method,key,owner:'ui:'+key,field:'message',exactEnglish:String(exactEnglish??''),parameters:parameters||{},rich:structured(rich||{}),html:!!html});}
          else{const [key,template,parameters={}]=args;const values=Object.fromEntries(Object.entries(parameters).map(([name,descriptor])=>[name,descriptor.value]));record({method,key,owner:'ui:'+key,field:'message',exactEnglish:localizer.referenceText(template,values),template,sourceKind:'typed-rich-template',parameters});}
          return original.apply(this,args);
        };
      }
    };
    // Intercept only the real application's class registration. The setter observes the
    // real service assignment before shell rendering; no production module is changed.
    const define=customElements.define;
    customElements.define=function(name,constructor,options){
      if(name==='auth-flow-studio'){
        const prototype=constructor.prototype,values=new WeakMap();
        if(Object.getOwnPropertyDescriptor(prototype,'localizer'))throw new Error('Unexpected existing localizer descriptor');
        Object.defineProperty(prototype,'localizer',{configurable:true,get(){return values.get(this);},set(value){instrument(value);values.set(this,value);}});
        for(const method of Object.getOwnPropertyNames(prototype)){
          const descriptor=Object.getOwnPropertyDescriptor(prototype,method);
          if(typeof descriptor.value!=='function'||!(/^(render|shell$|fullShell$|footer|indexContext$)|Html$/.test(method)))continue;
          const original=descriptor.value;
          Object.defineProperty(prototype,method,{...descriptor,value:function(...args){const key=capture.stage+' > '+method;capture.methods.set(key,(capture.methods.get(key)||0)+1);capture.stack.push(method);try{return original.apply(this,args);}finally{capture.stack.pop();}}});
        }
      }
      return define.call(this,name,constructor,options);
    };
    for(const type of ['click','keydown','input','change'])document.addEventListener(type,event=>{
      if(capture.events.length>=10000)throw new Error('Pilot trusted-event limit reached; no silent truncation');
      const node=event.target;capture.events.push({stage:capture.stage,type,trusted:event.isTrusted,key:event.key||null,tag:node?.tagName,id:node?.id||null,attributes:node?.getAttributeNames?Object.fromEntries(node.getAttributeNames().filter(name=>name.startsWith('data-')).map(name=>[name,node.getAttribute(name)])):{}});
    },true);
  });
}

export async function capturePilotFamilies({page,action,settle,raw,row}){
  const witnesses=[],attempts=[],required=new Set(),completed=new Set();
  const requestChunks=[];
  let drainError=null;
  // A browser turn stages one immutable batch and swaps the live Map. Only the
  // exact durably stored batch is acknowledged; calls during I/O stay live.
  const drain=async()=>{
    if(drainError)throw drainError;
    try{
      while(true){
      const batch=await page.evaluate(()=>{
        const c=window.__localizationPilot;
        if(c.pending)return c.pending;
        if(!c.requests.size)return null;
        const requests=[...c.requests.values()].map(record=>({...record,surfaces:[...record.surfaces].sort()}));
        c.pending={schemaVersion:1,kind:'actual-renderer-family-localizer-request-chunk',chunkIndex:c.nextChunkIndex++,stage:c.stage,requestRecords:requests.length,requestCalls:requests.reduce((sum,record)=>sum+record.count,0),requests};
        c.requests=new Map();
        return c.pending;
      });
      if(!batch)return;
      const descriptor=await raw(row,'pilot-localizer-request-chunk-'+batch.chunkIndex,batch);
      const reference={...descriptor,chunkIndex:batch.chunkIndex,requestRecords:batch.requestRecords,requestCalls:batch.requestCalls};
      requestChunks.push(reference);row.pilotRequestChunks=requestChunks;
      await page.evaluate(index=>{
        const c=window.__localizationPilot;
        if(c.pending?.chunkIndex!==index)throw new Error('Pilot chunk acknowledgement mismatch');
        c.pending=null;
      },batch.chunkIndex);
      }
    }catch(error){
      drainError=error;
      row.pilotCaptureStorageError=String(error.stack||error);
      throw error;
    }
  };
  const q=value=>JSON.stringify(value),visible=selector=>page.locator(selector+':visible').first();
  const stage=name=>page.evaluate(name=>{window.__localizationPilot.stage=name;},name);
  const observe=()=>page.evaluate(()=>{const a=document.querySelector('auth-flow-studio'),c=window.__localizationPilot;return {scenarioId:a.labScenarioId,modelId:a.labModel?.id||null,family:a.labModel?.family||null,planId:a.labModel?.planId||null,variantId:a.lessonVariant,subfixtureId:a.lessonSubfixture,presentation:a.presentationMode,configuration:a.protocolConfig(),directFido:a.isDirectFido,cursor:a.heldView.snapshot().cursor,queueKind:a.studyQueue().kind,requestCalls:c.requestCalls,methods:[...c.methods].filter(([name])=>name.startsWith(c.stage+' > ')).map(([name,count])=>({name,count}))};});
  const attempt=async(name,fn,{requiredSurface=false}={})=>{
    if(requiredSurface)required.add(name);
    await stage(name);const record={name,status:'attempted',before:await observe()};attempts.push(record);row.pilotAttempts=attempts;
    try{
      record.result=await fn();record.after=await observe();record.requestCalls=record.after.requestCalls-record.before.requestCalls;
      record.status=record.result?.status==='unperformed'?'unperformed':'performed';
      if(requiredSurface){assert.equal(record.status,'performed','Required surface was not exercised: '+name);completed.add(name);}
      return record.result;
    }catch(error){record.status='failed';record.error=String(error.stack||error);throw error;}
    finally{await drain();}
  };
  const click=async(selector,{optional=false}={})=>{
    const node=visible(selector);
    if(!await node.count()){assert.ok(optional,'Required actual visible control: '+selector);return {status:'unperformed',reason:'No applicable visible control',selector};}
    const control=await node.evaluate(n=>({tag:n.tagName,id:n.id,attributes:Object.fromEntries(n.getAttributeNames().filter(key=>key.startsWith('data-')).map(key=>[key,n.getAttribute(key)])),label:n.getAttribute('aria-label')||n.textContent}));
    await action(row,'pilot activate '+selector,()=>node.click());witnesses.push({method:'trusted pointer',selector,control});return {selector,control};
  };
  const open=async(selector,{optional=false}={})=>{
    const node=page.locator(selector).first();
    if(!await node.count()||!await node.isVisible()){assert.ok(optional,'Required actual disclosure: '+selector);return {status:'unperformed',reason:'Disclosure not applicable to this model/presentation',selector};}
    const alreadyOpen=await node.evaluate(n=>n.open);
    if(!alreadyOpen)await click(selector+' > summary');
    assert.equal(await node.evaluate(n=>n.open),true,'Actual disclosure opened: '+selector);
    return {selector,alreadyOpen};
  };
  const region=async selector=>{
    const node=visible(selector);assert.ok(await node.count(),'Required rendered region '+selector);
    const evidence=await node.evaluate(n=>({id:n.id,tag:n.tagName,textExcerpt:n.textContent.slice(0,2000),textCharacters:n.textContent.length,excerptLimit:2000,proseNodes:n.querySelectorAll('.locale-prose').length,technicalNodes:n.querySelectorAll('[translate="no"]').length,controls:[...n.querySelectorAll('button,select,summary,a')].filter(n=>n.checkVisibility()).map(n=>({tag:n.tagName,id:n.id,attributes:Object.fromEntries(n.getAttributeNames().filter(key=>key.startsWith('data-')).map(key=>[key,n.getAttribute(key)]))}))}));
    assert.ok(evidence.textExcerpt.trim(),'Rendered region contains actual content '+selector);
    return {selector,...evidence};
  };
  const keyboardSelect=async(selector,value)=>{
    const node=visible(selector);assert.ok(await node.count(),'Authored select must be reachable '+selector);
    const options=await node.locator('option').evaluateAll(nodes=>nodes.filter(n=>!n.disabled).map(n=>({value:n.value,label:n.textContent}))),current=await node.inputValue();
    const target=value??options.find(option=>option.value!==current)?.value;
    assert.ok(target!==undefined&&options.some(option=>option.value===target),'Actual alternate authored option '+selector);
    await action(row,'pilot open native select '+selector,()=>node.click());
    await action(row,'pilot select Home '+selector,()=>page.keyboard.press('Home'));
    for(let index=0;index<options.findIndex(option=>option.value===target);index++)await action(row,'pilot select ArrowDown '+selector,()=>page.keyboard.press('ArrowDown'));
    await action(row,'pilot select Enter '+selector,()=>page.keyboard.press('Enter'));
    assert.equal(await page.locator(selector).first().inputValue(),target,'Trusted selector selected actual authored value');
    return {selector,method:'trusted native-select pointer/keyboard',options,before:current,selected:target};
  };
  const query=async(selector,text)=>{
    await click(selector);await action(row,'pilot query select all',()=>page.keyboard.press('ControlOrMeta+A'));
    if(text)await action(row,'pilot actual authored query',()=>page.keyboard.insertText(text));else await action(row,'pilot clear query',()=>page.keyboard.press('Backspace'));
    assert.equal(await page.locator(selector).inputValue(),text);return {selector,text,method:'trusted keyboard actual authored query'};
  };
  const metadata=await page.evaluate(async()=>{
    const load=name=>import(new URL('./src/'+name,document.baseURI).href),presets=await load('learning-presets.js'),fido=await load('fido-direct.js');
    const sources=[
      ['PAM','pam-foundations-lab.js','PAMFOUNDATIONSLAB_SCENARIOS'],
      ['Windows-remote','windows-remote-administration-lab.js','WINDOWSREMOTELAB_SCENARIOS'],
      ['Windows-protection','windows-protection-lab.js','WINDOWSPROTECTIONLAB_SCENARIOS'],
      ['Windows-logon/profile','windows-logon-lab.js','WINDOWSLOGONLAB_SCENARIOS'],
      ['DNSSEC','dnssec-lab.js','DNSSECLAB_SCENARIOS'],
      ['DNSSEC context','dnssec-lab.js','DNSSECLAB_SCENARIOS'],
      ['crypto','kerberos-crypto-lab.js','CRYPTOLAB_SCENARIOS'],
      ['JWT','jwt-validation-lab.js','JWTLAB_SCENARIOS'],
      ['MCP','mcp-auth-lab.js','MCPLAB_SCENARIOS'],
      ['SMB','smb-multichannel-lab.js','SMBMULTI_SCENARIOS'],
    ],groups=[];
    for(const [family,module,exportName]of sources){
      const members=(await load(module))[exportName];if(!Array.isArray(members))throw new TypeError('Missing actual source catalog '+exportName);
      const score=model=>(model.chapters?.length||0)+(model.subfixtureChoices?.length||0)+(model.profileControls?.length||0)+(model.featured?10:0)+(family==='SMB'&&!model.profile?.failureCase?10:0)+(family==='DNSSEC'&&model.family==='forwarding-trust'?1000:0)+(family==='JWT'&&model.profile?.algorithms?.some(value=>String(value).includes('RSA-OAEP-256'))?1000:0);
      const eligible=family==='DNSSEC context'?members.filter(model=>model.dnssecContext?.records?.length):members;
      const model=[...eligible].sort((a,b)=>score(b)-score(a)||a.id.localeCompare(b.id))[0];
      groups.push({family,module,exportName,id:model?.id,familyMetadata:model?.family,planId:model?.planId,variantCount:model?.variantChoices?.length||0,chapterCount:model?.chapters?.length||0});
    }
    const app=document.querySelector('auth-flow-studio'),core=app.scenarioPicker.options.find(option=>option.id==='core'),oidc=presets.LEARNING_PRESETS.find(p=>p.config.applicationProtocol==='oidc'&&p.config.oidcFlow==='authorization-code'&&p.config.upstream==='single'),saml=presets.LEARNING_PRESETS.find(p=>p.config.applicationProtocol==='saml'),direct=Object.entries(fido.FIDO_JOURNEYS).find(([,mode])=>mode.directFido&&!mode.enrollment);
    if(!core||!oidc||!saml||!direct)throw new Error('Missing actual Core OIDC/SAML/FIDO metadata');
    return {coreId:core.id,core:[{family:'Core OIDC',id:core.id,configuration:{...oidc.config},sourcePreset:oidc.id},{family:'Core SAML',id:core.id,configuration:{...saml.config},sourcePreset:saml.id},{family:'Core FIDO',id:core.id,configuration:{...oidc.config,mode:direct[0]},sourcePreset:oidc.id,sourceMode:direct[0]}],groups,options:app.scenarioPicker.options.map(option=>({id:option.id,title:option.title,category:option.category}))};
  });
  const selected=[...metadata.core,...metadata.groups],surfaces=['journey','protocol/history','participant','held/help/object','field/definition/trace','specialized'];
  assert.ok(selected.every(item=>item.id),'Every required family has an actual source-owned representative');
  for(const item of selected)for(const presentation of ['full','compact'])for(const surface of surfaces)required.add(item.family+' '+presentation+' '+surface);
  required.add('authored field-instance history interaction');
  row.pilotDiscovery={metadata,selected:selected.map(item=>({...item,status:'discovered-from-source-export-membership'}))};
  const position=async representative=>{
    const result=await page.evaluate(()=>{
      const a=document.querySelector('auth-flow-studio');a.returnToJourney();
      const preferred=a.steps.map((step,index)=>({step,index})).find(({step})=>step.pamEvaluation?.line),boundary=a.labModel?.planId==='PAM01'&&preferred?preferred.index:a.steps.length-1;
      if(boundary<0)throw new Error('Representative has no actual authored source steps');
      a.inspectQueueBoundary(boundary,'end');a.player.setSpeed(.01);
      return {boundary,sourceStepId:a.steps[boundary].id,cursor:a.heldView.snapshot().cursor};
    });await settle(page);return result;
  };
  const setup=async(representative,presentation)=>{
    if(await page.evaluate(()=>document.querySelector('auth-flow-studio').presentationMode)!==presentation)await click('[data-presentation-choice='+q(presentation)+']');
    const actual=await page.evaluate(representative=>{
      const a=document.querySelector('auth-flow-studio');
      if(representative.configuration){a.selectLabScenario(representative.sourcePreset,{navigate:false});a.coreConfiguration={...representative.configuration};}
      a.selectLabScenario(representative.id,{navigate:false});
      return {scenarioId:a.labScenarioId,modelId:a.labModel?.id||null,modelFamily:a.labModel?.family||null,planId:a.labModel?.planId||null,configuration:a.protocolConfig(),directFido:a.isDirectFido,variantChoices:a.labModel?.variantChoices?.map(v=>({id:v.id,label:v.label}))||[]};
    },representative);await settle(page);
    assert.equal(actual.scenarioId,representative.id);
    if(representative.family==='Core SAML')assert.equal(actual.configuration.applicationProtocol,'saml');
    if(representative.family==='Core OIDC')assert.equal(actual.configuration.applicationProtocol,'oidc');
    if(representative.family==='Core FIDO')assert.equal(actual.directFido,true);
    if(representative.family==='PAM')assert.equal(actual.planId,'PAM01','Specialized PAM foundations, not generic SSH PAM');
    if(representative.family==='Windows-remote')assert.equal(actual.modelFamily,'windows-remote-administration');
    if(representative.family==='Windows-protection')assert.equal(actual.modelFamily,'windows-protection');
    witnesses.push({family:representative.family,presentation,method:'Explicit untimed actual selectLabScenario API, source-owned Core configuration when applicable, and authored inspectQueueBoundary',actual,position:await position(representative)});
    return actual;
  };
  const native=async()=>{
    if(row.locale==='en')return;
    const evidence=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return {locale:a.localizer.locale,appLang:a.lang,documentLang:document.documentElement.lang,direction:a.dir,diagnostics:a.localizer.diagnostics()};});
    assert.equal(evidence.locale,row.locale);assert.equal(evidence.appLang,row.locale);assert.equal(evidence.documentLang,row.locale);assert.deepEqual(evidence.diagnostics.fallbacks,[],'No native renderer-family coverage may count English fallback');return evidence;
  };
  try{
    await drain();
    for(const representative of selected)for(const presentation of ['full','compact']){
      const prefix=representative.family+' '+presentation;
      await attempt(prefix+' journey',async()=>{const actual=await setup(representative,presentation);return {actual,title:await region('#scenario-title'),description:await region('#scenario-description')};},{requiredSurface:true});
      await attempt(prefix+' lesson controls',async()=>{
        const authored=await page.evaluate(()=>{const m=document.querySelector('auth-flow-studio').labModel;return {variants:m?.variantChoices?.length||0,subfixtures:m?.subfixtureChoices?.length||0,profileControls:m?.profileControls?.map(control=>({id:control.id,options:control.options.length}))||[]};}),controls=[];
        if(authored.variants>1)controls.push(await keyboardSelect('#lesson-case'));
        const featureCase=await page.evaluate(()=>{
          const a=document.querySelector('auth-flow-studio'),base=a.baseLabModel;if(!base?.withVariant)return null;
          for(const choice of base.variantChoices||[]){const model=base.withVariant(choice.id);if((model.subfixtureChoices?.length||0)>1||(model.profileControls||[]).some(control=>control.options.length>1))return {id:choice.id,subfixtures:model.subfixtureChoices?.map(c=>({id:c.id,label:c.label}))||[],profiles:model.profileControls?.map(c=>({id:c.id,options:c.options.length}))||[]};}return null;
        });
        if(featureCase){
          await page.evaluate(id=>document.querySelector('auth-flow-studio').selectLessonVariant(id),featureCase.id);await settle(page);controls.push({method:'Explicit untimed selectLessonVariant API for discovered supported control case',...featureCase});
          if(featureCase.subfixtures.length>1)controls.push(await keyboardSelect('#lesson-subfixture'));
        }
          const profiles=await page.locator('#lesson-inputs select[data-profile-control]').evaluateAll(nodes=>nodes.map(n=>({id:n.id,values:[...n.options].filter(n=>!n.disabled).map(n=>n.value)})));
          for(const profile of profiles)if(profile.values.length>1)controls.push(await keyboardSelect('[id='+q(profile.id)+']'));
        await setup(representative,presentation);return controls.length?{authored,controls}:{status:'unperformed',reason:'This representative has no authored alternate case/subfixture/profile control',authored};
      });
      await attempt(prefix+' specialized',async()=>{
        await open('#lesson-reference',{optional:true});
        if(presentation==='compact'){await open('[data-compact-disclosure="configuration"]');await open('[data-compact-disclosure="data"]');await open('[data-compact-disclosure="overview"]');}
        const result={},profile=await page.evaluate(()=>!!document.querySelector('auth-flow-studio').labModel?.profile);
        if(profile){await click('[data-learning-detail="crypto"]');result.profile=await region('#learning-profile-crypto');}
        if(representative.family==='PAM'){result.configuration=await region('#pam-configuration-panel');assert.ok(await page.locator('#pam-configuration-panel .pam-source-lines').count(),'Specialized PAM physical source-line renderer');await open('#pam-configuration-panel [data-pam-disclosure="configuration"]');result.files=await region('#pam-configuration-panel [data-pam-disclosure="configuration"]');}
        else if(representative.family==='Windows-remote'){result.remote=await region('#windows-remote-evidence');assert.ok(await page.locator('#windows-remote-evidence table').count(),'Specialized remote policy/token table renderer');await open('#windows-remote-evidence [data-remote-comparison]',{optional:true});}
        else if(representative.family==='Windows-protection'){await open('#windows-security-comparison');result.protection=await region('#windows-security-comparison');result.decisions=await region('#lesson-decisions');}
        else if(representative.family==='DNSSEC'){result.decisions=await region('#lesson-decisions');result.hops=await region('.dnssec-hop-comparison');await open('.dnssec-decision-details');}
        else if(representative.family==='DNSSEC context'){result.decisions=await region('#lesson-decisions');result.context=await region('.dnssec-context-panel');await open('.dnssec-decision-details');}
        else if(!profile)result.core=await region(presentation==='full'?'#inspector':'#compact-data');
        const chapters=await page.locator('[data-lesson-chapter]:visible').evaluateAll(nodes=>nodes.filter(n=>!n.disabled).map(n=>({id:n.dataset.lessonChapter,text:n.textContent})));
        if(chapters.length){await click('[data-lesson-chapter='+q(chapters[0].id)+']');result.chapter=chapters[0];await position(representative);}
        return {...result,native:await native()};
      },{requiredSurface:true});
      await attempt(prefix+' protocol/history',async()=>{
        if(presentation==='compact')await open('[data-compact-disclosure="state"]');else await open('#protocol-state-panel');
        const source=await page.evaluate(()=>{const snapshot=document.querySelector('auth-flow-studio').protocolSnapshot();return {cursor:snapshot.cursor,instances:snapshot.instances.length};});
        const histories=await page.locator('#protocol-instance-list [data-instance-history]').evaluateAll(nodes=>nodes.map(n=>n.dataset.instanceHistory));
        if(!source.instances){assert.deepEqual(histories,[],'No history controls invented for an empty source ledger');return {source,state:await region('#protocol-state-panel'),emptyLedger:await region('#protocol-instance-list .environment-note'),history:{status:'unperformed',reason:'Actual source snapshot has zero instantiated objects at this prefix; not history-interaction evidence'}};}
        assert.ok(histories.length,'Nonempty current-prefix source ledger has actual history controls');
        const selector='#protocol-instance-list [data-instance-history='+q(histories[0])+']';await open(selector);const history=await region(selector);completed.add('authored field-instance history interaction');
        return {source,state:await region('#protocol-state-panel'),history,instanceId:histories[0]};
      },{requiredSurface:true});
      await attempt(prefix+' participant',async()=>{
        if(presentation==='full'){const card=visible('[data-actor]');assert.ok(await card.count(),'Actual graph participant');const actor=await card.getAttribute('data-actor');await click('[data-actor='+q(actor)+']');await card.focus();await action(row,'pilot participant F2',()=>page.keyboard.press('F2'));const popup=await region('#actor-popup');await click('#actor-popup [data-close]');return {actor,popup};}
        await open('[data-compact-disclosure="holdings"]');const owner=await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.snapshot().holdings[0]?.actorId);assert.ok(owner,'Actual current logical owner');await open('[data-compact-owner='+q(owner)+']');
        return {owner,inventory:await region('[data-compact-owner='+q(owner)+']'),qualification:'Compact logical-owner inventory/context is the participant surface; no Full-only participant popup claimed'};
      },{requiredSurface:true});
      await attempt(prefix+' held/help/object',async()=>{
        if(presentation==='compact')await open('[data-compact-disclosure="holdings"]');
        if(presentation==='full'&&await page.locator('#show-held-objects').count()&&!await page.locator('#show-held-objects').isChecked())await click('#show-held-objects');
        const selection=await page.evaluate(()=>{
          const a=document.querySelector('auth-flow-studio'),view=a.heldView,snapshot=view.snapshot(),holding=snapshot.holdings.find(h=>view.buildTrace(h.artifactId).length>0);
          if(!holding)throw new Error('No current authored holding with an actual object-history queue');
          view.select(holding);if(a.presentationMode==='compact')a.compactView.render('selection');
          return {holding:{holdingId:holding.holdingId,actorId:holding.actorId,artifactId:holding.artifactId,representationId:holding.representationId},cursor:snapshot.cursor,method:'Explicit untimed permitted HeldStudyState.select(currentHolding) API; no canonical holding mutation'};
        });await settle(page);
        await click('#held-inspector [data-held-help]');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.helpOpen),true);const help=await region('#held-inspector');
        await click('#held-inspector [data-held-help-close]');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').heldView.helpOpen),false);
        await click('#held-inspector [data-held-trace]');let trace=await observe();assert.equal(trace.queueKind,'object');
        await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());await click('#play');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.status),'playing','Trusted object replay actually starts');
        await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());trace=await observe();await position(representative);return {selection,help,trace,replay:'Trusted actual object-history control and Play; explicit untimed pause/restoration'};
      },{requiredSurface:true});
      await attempt(prefix+' field/definition/trace',async()=>{
        const id=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return [...new Set(a.steps.flatMap(step=>[...(step.fields||[]),...(step.attributeOperations||[]).map(operation=>operation.attributeId)]))].find(id=>a.attributeUsage(a.steps,id).length>0);});assert.ok(id,'Actual authored used field');
        if(presentation==='compact')await open('[data-compact-disclosure="fields"]');else if(!await page.locator('#attribute-index').isVisible())await click('#index-open');
        const selector='#attribute-index-list [data-index-attribute='+q(id)+']';if(!await visible(selector).count())await query('#attribute-search',id);
        let definition;
        if(presentation==='full'){const node=visible(selector);assert.ok(await node.count());await node.focus();await action(row,'pilot field F2',()=>page.keyboard.press('F2'));definition=await region('#attribute-popup');await click('#attribute-popup [data-close]');await click(selector);}
        else{await click(selector);definition=await region('#compact-field-definition');await click('[data-compact-field-trace='+q(id)+']');}
        await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());const trace=await observe();assert.equal(trace.queueKind,'attribute');assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').attributeSelection),id);await position(representative);return {id,definition,trace};
      },{requiredSurface:true});
      if(presentation==='full')await attempt(prefix+' connection',async()=>{
        const hasConnection=await page.evaluate(()=>{const a=document.querySelector('auth-flow-studio');return a.steps.some(step=>a.nodeId(step.from)!==a.nodeId(step.to));});
        if(!hasConnection)return {status:'unperformed',reason:'This authored representative has only same-owner local steps; no graph connection is applicable'};
        const node=visible('.connection-hit[tabindex="0"]');assert.ok(await node.count(),'Applicable actual graph connection');
        const control=await node.evaluate(n=>({pair:n.parentElement.dataset.pair,path:n.getAttribute('d'),label:n.getAttribute('aria-label')}));await node.focus();await action(row,'pilot connection trusted Enter',()=>page.keyboard.press('Enter'));assert.equal(await page.evaluate(()=>document.querySelector('auth-flow-studio').player.kind),'connection');
        await page.evaluate(()=>document.querySelector('auth-flow-studio').player.pause());const inspector=await region('#inspector');await position(representative);return {control,inspector};
      });
      await native();
    }
    await attempt('shared picker/catalog/environment/notes',async()=>{
      await setup(selected[0],'full');await open('#ready-journeys');await open('#lab-catalog');await open('#environment-panel');await open('[data-study-key="footer.notes"]');
      const source=metadata.options.find(option=>option.id===selected.find(item=>item.family==='PAM').id);assert.ok(source);await query('#lab-scenario-search',source.title);
      assert.ok(await page.evaluate(id=>document.querySelector('auth-flow-studio').scenarioPicker.results.some(option=>option.id===id),source.id),'Actual picker returned authored-title target');await action(row,'pilot close picker',()=>page.keyboard.press('Escape'));
      await query('#lab-search',source.title);assert.ok(await page.locator('#lab-cards [data-lab-scenario='+q(source.id)+']').count(),'Actual catalog returned authored-title target');
      return {source,picker:'Actual trusted authored-title query',catalog:await region('#lab-cards'),environment:await region('#environment-panel'),notes:await region('[data-study-key="footer.notes"]')};
    },{requiredSurface:true});
    assert.ok(completed.has('authored field-instance history interaction'),'At least one real authored nonempty instance history must be opened');
    assert.ok(attempts.some(item=>item.name.endsWith(' connection')&&item.status==='performed'),'At least one actual graph connection replay must be exercised');
    assert.ok(attempts.some(item=>item.name.endsWith(' lesson controls')&&item.status==='performed'&&item.result.controls?.some(control=>control.selector==='#lesson-case')),'Actual authored case selector exercised');
    assert.ok(attempts.some(item=>item.name.endsWith(' lesson controls')&&item.result.controls?.some(control=>control.selector==='#lesson-subfixture')),'Actual authored comparison subfixture selector exercised');
    assert.ok(attempts.some(item=>item.name.endsWith(' lesson controls')&&item.result.controls?.some(control=>control.selector?.includes('lesson-profile-'))),'Actual authored profile selector exercised');
  }finally{
    let finalDrainError=null;
    try{await drain();}catch(error){finalDrainError=error;}
    const captured=await page.evaluate(()=>{const c=window.__localizationPilot,a=document.querySelector('auth-flow-studio');return {schemaVersion:2,kind:'actual-renderer-family-localizer-requests',requestCalls:c.requestCalls,methods:[...c.methods].map(([method,count])=>({method,count})),events:c.events,errors:c.errors,locale:a.localizer.locale,diagnostics:a.localizer.diagnostics(),storage:{encoding:'lossless-gzip-json-chunks',residentRequestLimit:100000,maximumResidentRecords:c.maximumResidentRecords,pendingRequestRecords:(c.pending?.requestRecords||0)+c.requests.size}};});
    captured.requestRecords=requestChunks.reduce((sum,chunk)=>sum+chunk.requestRecords,0);
    captured.requestChunks=requestChunks.map(chunk=>({...chunk,path:chunk.path.split('/').pop()}));
    row.pilotCapture=await raw(row,'pilot-localizer-requests',captured);row.pilotWitnesses=witnesses;row.pilotAttempts=attempts;
    row.pilotScope={requested:PILOT_SCOPE,classification:row.locale==='en'?'Source-mode actual-program diagnostic, not translation/native/human acceptance':'Native engineering renderer-family pilot with zero-fallback checks, not linguistic/human/AT/release acceptance',required:[...required].map(name=>({name,status:completed.has(name)?'performed':'unperformed'})),unperformed:attempts.filter(item=>item.status==='unperformed'),familiesUnperformed:selected.flatMap(item=>['full','compact'].filter(presentation=>surfaces.some(surface=>!completed.has(item.family+' '+presentation+' '+surface))).map(presentation=>({family:item.family,presentation,reason:'Required actual surface did not complete; see retained failure'}))),notCovered:['Exhaustive finite content/case matrix','OS/human IME and AT','Physical-device/browser matrix','Native text scaling','Human linguistic approval',...(row.locale==='en'?['Native locales']:['Other native locales'])]};
    if(finalDrainError)throw finalDrainError;
    assert.ok(captured.requestRecords,'Actual Localizer requests captured');assert.ok(captured.events.every(event=>event.trusted),'No synthetic interaction evidence');
    assert.equal(captured.storage.pendingRequestRecords,0,'All actual requests durably acknowledged');
    assert.equal(requestChunks.reduce((sum,chunk)=>sum+chunk.requestCalls,0),captured.requestCalls,'Every actual Localizer call retained');
    assert.equal(requestChunks.reduce((sum,chunk)=>sum+chunk.requestRecords,0),captured.requestRecords,'Every chunk record accounted');
    if(row.locale!=='en'){assert.equal(captured.locale,row.locale);assert.deepEqual(captured.diagnostics.fallbacks,[],'Native pilot keeps strict zero fallback');}
  }
  assert.deepEqual([...required].filter(name=>!completed.has(name)),[],'Every required family/surface must have actual evidence, not only a shell visit');
  return {capture:row.pilotCapture,witnesses,attempts,scope:row.pilotScope};
}
