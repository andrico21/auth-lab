export const LOCALE_PREFERENCE_KEY = 'auth-flow-studio.locale.v1';
export const LOCALES = Object.freeze([
  Object.freeze({tag:'en',name:'English',direction:'ltr'}),
  Object.freeze({tag:'ru',name:'Русский',direction:'ltr'}),
  Object.freeze({tag:'uk',name:'Українська',direction:'ltr'}),
  Object.freeze({tag:'he',name:'עברית',direction:'rtl'}),
  Object.freeze({tag:'de',name:'Deutsch',direction:'ltr'}),
  Object.freeze({tag:'ar-AE',name:'العربية (الإمارات)',direction:'rtl'}),
  Object.freeze({tag:'fr',name:'Français',direction:'ltr'}),
  Object.freeze({tag:'pl',name:'Polski',direction:'ltr'}),
]);
const localeByTag = new Map(LOCALES.map(locale=>[locale.tag,locale]));
const localePluralCategories={en:['one','other'],ru:['one','few','many','other'],uk:['one','few','many','other'],he:['one','two','other'],de:['one','other'],'ar-AE':['zero','one','two','few','many','other'],fr:['one','many','other'],pl:['one','few','many','other']};
const localeEscape = value=>String(value??'').replace(/[&<>"']/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const localeBidiControls = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const localeUnsafeMarkup = /<[^>]*>|(?<![a-z0-9+.-])(?:[a-z][a-z0-9+.-]*:\/\/|javascript:|(?:data|file):(?=\S)|data:\s*(?:[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+)?(?:;[^\s,]*)*,|file:\s*(?:[/\\]|[a-z]:[/\\]))|\bwww\./iu;
const localePlaceholder = /\{([A-Za-z][A-Za-z0-9_]*)\}/g;
const localeOwn = (value,key)=>value!=null&&Object.hasOwn(value,key);
const localeString = value=>value==null?'':String(value);
const localeCounts = message=>{
  const result=Object.create(null);
  for(const match of message.matchAll(localePlaceholder))result[match[1]]=(result[match[1]]||0)+1;
  return result;
};
const localeSameCounts = (left,right)=>{
  const keys=Object.keys(left);
  return keys.length===Object.keys(right).length&&keys.every(key=>left[key]===right[key]);
};
const localeRegexEscape = value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const localePacked = value=>typeof value==='string'&&value.startsWith('gzip:');
const localeInflate = async value=>{
  if(typeof DecompressionStream!=='function')throw new TypeError('Offline language catalogs require gzip DecompressionStream support.');
  const encoded=value.slice(5),bytes=typeof Uint8Array.fromBase64==='function'?Uint8Array.fromBase64(encoded):Uint8Array.from(atob(encoded),character=>character.charCodeAt(0));
  return new Response(new Response(bytes).body.pipeThrough(new DecompressionStream('gzip'))).text();
};

/** English plus one selected catalog. No protocol objects enter this service. */
export class Localizer {
  constructor({host=globalThis,catalogs={},bindings={messages:[]},initialLocale}={}) {
    this.host=host;this.resources=catalogs;this.bindingResource=bindings;
    this.locale='en';this.direction='ltr';this.revision=0;this.source='default';
    this.catalog=null;this.contracts=null;this.owners=null;this.matchers=new Map();
    this.pluralRules=null;this.numberFormatter=null;this.searchCache=new Map();this.pluralDataSource=null;this.numberDataSource=null;
    this.fallbacks=new Map();this.coverage=new Map();this.resolvedLanguages=new Map();
    this.sourceWasPacked=localePacked(bindings);this.englishPreparation=null;this.prepared=null;this.preparationRevision=0;this.initialPreparation=null;this.initialFailure=null;
    let selected=initialLocale;
    if(selected===undefined)try{selected=host.localStorage.getItem(LOCALE_PREFERENCE_KEY);}catch{}
    if(!localeByTag.has(selected))selected='en';
    else if(initialLocale===undefined)this.source='stored';
    if(selected!=='en'){
      if(this.needsPreparation(selected))this.initialPreparation=this.prepare(selected).then(()=>{this.activate(selected,{persist:false});}).catch(error=>{this.initialFailure={tag:selected,error};this.discardPrepared();}).finally(()=>{this.initialPreparation=null;});
      else try{this.activate(selected,{persist:false});}catch(error){this.initialFailure={tag:selected,error};this.discardPrepared();}
    }
  }
  static valid(tag) {return localeByTag.has(tag);}
  static metadata(tag) {return localeByTag.get(tag)||localeByTag.get('en');}
  needsPreparation(tag) {
    return tag!=='en'&&(localePacked(this.bindingResource)||localePacked(this.resources[tag])&&this.prepared?.tag!==tag);
  }
  discardPrepared() {this.preparationRevision++;this.prepared=null;}
  async prepare(tag) {
    if(!localeByTag.has(tag))throw new RangeError('Unknown display locale.');
    if(tag==='en'){this.discardPrepared();return;}
    if(!this.needsPreparation(tag))return;
    const revision=++this.preparationRevision;this.prepared=null;
    if(localePacked(this.bindingResource)&&!this.englishPreparation){
      const encoded=this.bindingResource;
      this.englishPreparation=localeInflate(encoded).then(value=>{this.bindingResource=value;}).finally(()=>{this.englishPreparation=null;});
    }
    const resource=this.resources[tag],target=localePacked(resource)?localeInflate(resource):resource;
    const [,decoded]=await Promise.all([this.englishPreparation,target]);
    if(revision===this.preparationRevision)this.prepared={tag,resource:decoded};
  }
  activate(tag,{persist=true}={}) {
    if(!localeByTag.has(tag))throw new RangeError('Unknown display locale.');
    if(tag===this.locale){this.discardPrepared();return false;}
    if(this.needsPreparation(tag))throw new TypeError('Prepare the selected display resources before activation.');
    let catalog=null;
    if(tag!=='en'){
      const resource=this.prepared?.tag===tag?this.prepared.resource:this.resources[tag];
      if(resource!==undefined){
        catalog=typeof resource==='function'?resource():typeof resource==='string'?JSON.parse(resource):resource;
        if(catalog?.format==='auth-lab-l10n-catalog-table')catalog=this.decodeCatalog(catalog,tag);
        if(!catalog||catalog.locale!==tag||!catalog.entries||typeof catalog.entries!=='object')throw new TypeError('The selected offline language catalog is invalid.');
      }
    }
    this.discardPrepared();
    this.locale=tag;this.direction=localeByTag.get(tag).direction;this.catalog=catalog;
    this.revision++;this.matchers.clear();this.searchCache=new Map();this.coverage.clear();this.fallbacks.clear();this.resolvedLanguages.clear();
    this.pluralRules=null;this.numberFormatter=null;this.pluralDataSource=null;this.numberDataSource=null;
    if(persist){
      this.source='explicit-memory';
      try{this.host.localStorage.setItem(LOCALE_PREFERENCE_KEY,tag);this.source='explicit-stored';}catch{}
    }
    return true;
  }
  decodeCatalog(table,tag) {
    this.ensureContracts();
    if(table.schemaVersion!==2||table.locale!==tag||!this.sourceSetSha256||table.sourceSetSha256!==this.sourceSetSha256||!Array.isArray(table.messages)||!Array.isArray(table.bindings)||table.bindings.length!==this.bindingOrder.length)throw new TypeError('Catalog table does not bind this English source set.');
    const entries=Object.create(null);
    const identities=table.identityJustifications||{};
    if(!identities||typeof identities!=='object'||Array.isArray(identities)||Object.keys(identities).some(index=>!/^(0|[1-9]\d*)$/.test(index)||Number(index)>=table.bindings.length||table.bindings[Number(index)]===-1))throw new TypeError('Catalog identity binding is invalid.');
    for(let index=0;index<table.bindings.length;index++){
      const message=table.bindings[index];if(message===-1)continue;
      if(!Number.isInteger(message)||message<0||message>=table.messages.length)throw new RangeError('Catalog message index is invalid.');
      const key=this.bindingOrder[index];entries[key]={sourceSha256:this.contracts.get(key).sourceSha256,message:table.messages[message]};
      if(localeOwn(identities,index))entries[key].identityJustification=identities[index];
    }
    return {locale:tag,entries,aliases:table.aliases||{}};
  }
  ensureContracts() {
    if(this.contracts)return;
    const resource=typeof this.bindingResource==='function'?this.bindingResource():typeof this.bindingResource==='string'?JSON.parse(this.bindingResource):this.bindingResource;
    let messages,indexed=false;
    if(resource?.format==='auth-lab-l10n-source-table'){
      if(resource.schemaVersion!==2||!/^[a-f0-9]{64}$/.test(resource.sourceSetSha256||'')||!['schemas','owners','fields','contexts','classifications','bindings'].every(name=>Array.isArray(resource[name]))||!resource.keys||typeof resource.keys!=='object'||Array.isArray(resource.keys))throw new TypeError('English source table is invalid.');
      const aliases=new Map();
      for(const [key,index]of Object.entries(resource.keys)){
        if(!key||/^(0|[1-9]\d*)$/.test(key)||!Number.isInteger(index)||index<0||index>=resource.bindings.length||aliases.has(index))throw new TypeError('Explicit display key binding is invalid.');
        aliases.set(index,key);
      }
      indexed=true;messages=resource.bindings.map((row,index)=>{
        if(!Array.isArray(row)||row.length!==5||row.some(value=>!Number.isInteger(value)||value<0))throw new TypeError('English source binding is invalid.');
        const [schemaIndex,ownerIndex,fieldIndex,contextIndex,classIndex]=row,schema=resource.schemas[schemaIndex],owner=resource.owners[ownerIndex],field=resource.fields[fieldIndex],context=resource.contexts[contextIndex],classification=resource.classifications[classIndex];
        if(!Array.isArray(schema)||schema.length!==4||!/^[a-f0-9]{64}$/.test(schema[0]||'')||typeof owner!=='string'||typeof field!=='string'||!context||typeof context!=='object'||Array.isArray(context)||typeof classification!=='string')throw new TypeError('English source pool index is invalid.');
        return {key:aliases.get(index)??index,sourceSha256:schema[0],english:schema[1],parameters:schema[2],placeholderCounts:schema[3],owner:{semanticId:owner,fieldPath:field},context,classification};
      });
      this.sourceSetSha256=resource.sourceSetSha256;this.bindingOrder=messages.map(message=>message.key);
      if(this.sourceWasPacked)this.bindingResource=null;
    }else messages=Array.isArray(resource)?resource:resource.messages||Object.values(resource.entries||{});
    this.contracts=new Map();this.owners=new Map();
    for(const contract of messages){
      if(!contract||typeof contract.key!=='string'&&(!indexed||!Number.isInteger(contract.key)||contract.key<0))throw new TypeError('A display contract requires a semantic binding or explicit UI key.');
      if(this.contracts.has(contract.key))throw new RangeError('Duplicate display message key: '+contract.key);
      this.contracts.set(contract.key,contract);
      const owner=contract.owner||{},ownerId=owner.id||owner.semanticId||contract.ownerId,field=owner.fieldPath||contract.fieldPath;
      if(ownerId&&field){const key=ownerId+'\0'+field,entries=this.owners.get(key)||[];entries.push(contract);this.owners.set(key,entries);}
    }
  }
  cardinal(value,locale=this.locale) {
    if(typeof value!=='number'||!Number.isFinite(value)||value<0)throw new TypeError('UI counts must be finite nonnegative numbers.');
    if(locale!==this.locale)return this.fallbackCardinal(value,locale);
    if(!this.pluralRules){
      try{
        if(!Intl.PluralRules.supportedLocalesOf([locale]).length)throw new RangeError('Locale plural data unavailable.');
        const rules=new Intl.PluralRules(locale,{type:'cardinal'});
        if(rules.resolvedOptions().locale.split('-')[0]!==locale.split('-')[0])throw new RangeError('Wrong plural locale.');
        for(const probe of [0,1,2,3,4,5,11,12,14,21,22,25,100,101,102,1000000,0.1,1.5])if(rules.select(probe)!==this.fallbackCardinal(probe,locale))throw new RangeError('Runtime cardinal data differs from CLDR 49.');
        this.pluralRules=rules;this.pluralDataSource='Intl verified against CLDR 49 probes';
      }catch{
        this.pluralRules={select:count=>this.fallbackCardinal(count,locale)};this.pluralDataSource='CLDR 49 ordinary-decimal fallback';
      }
    }
    return this.pluralRules.select(value);
  }
  /** CLDR 49 cardinal operands for ordinary decimal UI counts, no compact notation. */
  fallbackCardinal(value,locale=this.locale) {
    const language=locale.split('-')[0],integer=Number.isInteger(value),i=Math.floor(value),mod10=i%10,mod100=i%100;
    if(language==='ar')return value===0?'zero':value===1?'one':value===2?'two':integer&&mod100>=3&&mod100<=10?'few':integer&&mod100>=11&&mod100<=99?'many':'other';
    if(language==='he')return integer&&i===1||!integer&&i===0?'one':integer&&i===2?'two':'other';
    if(language==='ru'||language==='uk')return !integer?'other':mod10===1&&mod100!==11?'one':mod10>=2&&mod10<=4&&(mod100<12||mod100>14)?'few':mod10===0||mod10>=5||mod100>=11&&mod100<=14?'many':'other';
    if(language==='pl')return !integer?'other':i===1?'one':mod10>=2&&mod10<=4&&(mod100<12||mod100>14)?'few':'many';
    if(language==='fr')return i===0||i===1?'one':integer&&i!==0&&i%1000000===0?'many':'other';
    return integer&&i===1?'one':'other';
  }
  formatCount(value) {
    if(typeof value!=='number'||!Number.isFinite(value)||value<0)throw new TypeError('Invalid UI count.');
    if(!this.numberFormatter){
      try{
        if(!Intl.NumberFormat.supportedLocalesOf([this.locale]).length)throw new RangeError('Locale number data unavailable.');
        const formatter=new Intl.NumberFormat(this.locale+'-u-nu-latn',{useGrouping:false,maximumFractionDigits:20});
        if(formatter.resolvedOptions().locale.split('-')[0]!==this.locale.split('-')[0])throw new RangeError('Wrong number locale.');
        this.numberFormatter=formatter;this.numberDataSource='Intl Latin UI digits without grouping';
      }catch{
        // Versioned UI policy: Latin digits, no grouping; CLDR 49 decimal separators.
        const comma=/^(ru|uk|de|fr|pl)$/.test(this.locale);
        this.numberFormatter={format:count=>String(count).replace('.',comma?',':'.')};this.numberDataSource='CLDR 49 Latin-digit decimal-separator fallback';
      }
    }
    return this.numberFormatter.format(value);
  }
  sourceTemplate(contract,params) {
    const english=contract.english;
    if(typeof english==='string')return english;
    const forms=english?.plural||english?.forms;
    return forms?.[this.cardinal(params.count,'en')]||forms?.other||'';
  }
  values(contract,provided) {
    const definitions=contract.parameters||{},result=Object.create(null);
    for(const key of Object.keys(provided))if(!localeOwn(definitions,key))return null;
    for(const [name,definition] of Object.entries(definitions)){
      const supplied=localeOwn(provided,name),value=supplied?provided[name]:definition.value;
      if(value===undefined)return null;
      if(definition.kind==='count'){
        if(typeof value!=='number'||!Number.isFinite(value)||value<0)return null;
      }else if(definition.kind==='human'){
        if(!value||typeof value!=='object'||typeof value.source!=='string'||!(typeof value.key==='string'||typeof value.ownerId==='string'&&typeof value.fieldPath==='string'))return null;
      }else if(!['string','number','bigint','boolean'].includes(typeof value))return null;
      if(supplied&&!definition.dynamic&&localeOwn(definition,'value')&&definition.kind!=='count'&&value!==definition.value)return null;
      result[name]=value;
    }
    return result;
  }
  referenceText(template,values) {
    return template.replace(localePlaceholder,(_,name)=>{
      const value=values[name];return value&&typeof value==='object'?value.source:localeString(value);
    });
  }
  matchSource(contract,source,provided) {
    if(typeof contract.english==='object'&&(!Number.isFinite(provided.count)||provided.count<0))return null;
    const definitions=contract.parameters||{},capture=(name,definition)=>definition.dynamic&&['exact','protected'].includes(definition.kind)&&!localeOwn(provided,name);
    const implicit=Object.entries(definitions).some(([name,definition])=>capture(name,definition));
    let values=this.values(contract,provided);
    // A captured example is evidence for that realization, not an explicit
    // boundary supplied by the caller or a fixed source literal.
    if(values&&this.referenceText(this.sourceTemplate(contract,values),values)===source)return {values,priority:implicit?1:2};
    if(!implicit)return null;
    const template=this.sourceTemplate(contract,provided);
    const fixed=Object.entries(definitions).filter(([name,definition])=>!capture(name,definition)).map(([name,definition])=>{const value=localeOwn(provided,name)?provided[name]:definition.value;return [name,value&&typeof value==='object'?value.source:localeString(value)];});
    const signature=contract.key+'\0'+template+'\0'+JSON.stringify(fixed);
    let matcher=this.matchers.get(signature);
    if(!matcher){
      const names=[],groups=new Map(),parts=[],greedy=[];let cursor=0,previousCapture=null;
      for(const match of template.matchAll(localePlaceholder)){
        const name=match[1],literal=template.slice(cursor,match.index),definition=definitions[name],captured=definition&&capture(name,definition);
        if(captured&&previousCapture&&previousCapture!==name&&!literal)return null;
        parts.push(localeRegexEscape(literal));greedy.push(localeRegexEscape(literal));
        if(captured){
          let group=groups.get(name);
          if(group===undefined){group='c'+names.length;groups.set(name,group);names.push(name);parts.push('(?<'+group+'>[\\s\\S]*?)');greedy.push('(?<'+group+'>[\\s\\S]*)');}
          else{parts.push('\\k<'+group+'>');greedy.push('\\k<'+group+'>');}
        }else{
          const value=localeOwn(provided,name)?provided[name]:definition?.value;if(value===undefined)return null;
          const escaped=localeRegexEscape(value&&typeof value==='object'?value.source:localeString(value));parts.push(escaped);greedy.push(escaped);
        }
        previousCapture=captured?name:null;cursor=match.index+match[0].length;
      }
      const tail=localeRegexEscape(template.slice(cursor));parts.push(tail);greedy.push(tail);
      matcher={pattern:new RegExp('^'+parts.join('')+'$','u'),alternative:names.length>1?new RegExp('^'+greedy.join('')+'$','u'):null,names};
      if(this.matchers.size>=512)this.matchers.delete(this.matchers.keys().next().value);
      this.matchers.set(signature,matcher);
    }
    const match=matcher.pattern.exec(source);if(!match)return null;
    // Lazy and greedy matching choose the extreme valid capture partitions.
    // Different tuples mean the caller did not provide an exact boundary.
    if(matcher.alternative){
      const alternative=matcher.alternative.exec(source);
      if(!alternative||matcher.names.some((_,index)=>match[index+1]!==alternative[index+1]))return null;
    }
    const captured={...provided};for(let index=0;index<matcher.names.length;index++)captured[matcher.names[index]]=match[index+1];
    values=this.values(contract,captured);
    return values&&this.referenceText(template,values)===source?{values,priority:0}:null;
  }
  validateMessage(contract,entry,values) {
    if(!entry||entry.sourceSha256!==contract.sourceSha256)return null;
    let message=entry.message;
    if((typeof contract.english==='object')!==(message!==null&&typeof message==='object'))return null;
    if(message&&typeof message==='object'){
      const forms=message.plural,categories=localePluralCategories[this.locale];
      if(!forms||!localeOwn(values,'count')||Object.keys(forms).length!==categories.length||!categories.every(category=>typeof forms[category]==='string'))return null;
      message=forms[this.cardinal(values.count)];
      for(const branch of Object.values(forms))if(!this.validBranch(contract,branch,values))return null;
    }
    if(!this.validBranch(contract,message,values))return null;
    if(message===this.sourceTemplate(contract,values)&&contract.classification!=='protected-only'){
      const justification=entry.identityJustification,forms=typeof contract.english==='string'?[contract.english]:Object.values(contract.english.plural);
      const structural=justification?.kind==='structural-template'&&justification.sourceSha256===contract.sourceSha256&&forms.every(form=>!/\p{L}/u.test(form.replace(localePlaceholder,'')));
      const reviewed=justification&&typeof justification.approvalId==='string'&&justification.approvalId.trim()&&typeof justification.reason==='string'&&justification.reason.trim();
      if(!structural&&!reviewed)return null;
    }
    return message;
  }
  validBranch(contract,message,values) {
    if(typeof message!=='string'||!message||localeBidiControls.test(message)||localeUnsafeMarkup.test(message)||/[{}]/.test(message.replace(localePlaceholder,'')))return false;
    const required=contract.placeholderCounts||localeCounts(this.sourceTemplate(contract,values)),actual=localeCounts(message);
    return localeSameCounts(required,actual)&&Object.keys(actual).every(name=>localeOwn(contract.parameters||{},name));
  }
  fallback(key,source,reason,html) {
    const identity=key+'\0'+reason;this.fallbacks.set(identity,(this.fallbacks.get(identity)||0)+1);this.resolvedLanguages.set(key,'en');
    return html?'<span lang="en" dir="ltr">'+localeEscape(source)+'</span>':source;
  }
  parts(message,contract,values,html,{rich={},english=false}={}) {
    let untranslatedHuman=false;
    const render=(value,name)=>{
      const definition=contract.parameters[name],kind=definition.kind;
      let result;
      if(kind==='human'){
        if(english)result=html?localeEscape(value.source):value.source;
        else if(value.ownerId)result=html?this.explainHtml(value.ownerId,value.fieldPath,value.source,value.context||{}):this.explain(value.ownerId,value.fieldPath,value.source,value.context||{});
        else result=html?this.html(value.key,value.source,value.params||{}):this.text(value.key,value.source,value.params||{});
        if(!english&&this.language(value.ownerId?value.ownerId+'.'+value.fieldPath:value.key)==='en')untranslatedHuman=true;
      }else{
        const text=kind==='count'&&!english?this.formatCount(value):localeString(value);
        result=!html?text:['protected','exact','source','count'].includes(kind)?'<bdi'+(kind==='source'?' lang="en"':'')+' dir="'+(definition.direction==='auto'?'auto':'ltr')+'" translate="no">'+localeEscape(text)+'</bdi>':localeEscape(text);
      }
      return html&&rich[name]?.node?this.richNode(result,rich[name],value):result;
    };
    let cursor=0,result='';
    for(const match of message.matchAll(localePlaceholder)){
      const literal=message.slice(cursor,match.index);result+=html?localeEscape(literal):literal;result+=render(values[match[1]],match[1]);cursor=match.index+match[0].length;
    }
    const tail=message.slice(cursor);return untranslatedHuman?null:result+(html?localeEscape(tail):tail);
  }
  richNode(contents,descriptor,value) {
    const {tag,attributes={}}=descriptor.node;
    if(!['strong','em','code','a'].includes(tag))throw new TypeError('Unknown renderer-owned message element.');
    if(tag==='code'&&descriptor.kind==='human')throw new TypeError('Translated prose cannot become a raw code value.');
    const allowed=tag==='a'?['href','target','rel']:[];
    if(Object.keys(attributes).some(name=>!allowed.includes(name)))throw new TypeError('Unknown renderer-owned message attribute.');
    let attrs=Object.entries(attributes).map(([name,entry])=>' '+name+'="'+localeEscape(entry)+'"').join('');
    if(tag==='code')attrs+=' dir="ltr" translate="no" data-copy-raw-json="'+localeEscape(JSON.stringify(localeString(value)))+'"';
    return '<'+tag+attrs+'>'+contents+'</'+tag+'>';
  }
  rich(key,template,parameters={}) {
    const definitions={},values={};
    for(const [name,descriptor]of Object.entries(parameters)){
      if(!descriptor||!['protected','exact','source','human','count'].includes(descriptor.kind))throw new TypeError('A rich message requires typed renderer parameters.');
      definitions[name]={kind:descriptor.kind,direction:descriptor.direction};values[name]=descriptor.value;
    }
    const contract={parameters:definitions},source=this.referenceText(template,values);
    if(this.locale==='en'){this.resolvedLanguages.set(key,'en');return this.parts(template,contract,values,true,{rich:parameters,english:true});}
    const result=this.resolve(key,source,values,true,parameters);
    return this.resolvedLanguages.get(key)==='en'?'<span lang="en" dir="ltr">'+this.parts(template,contract,values,true,{rich:parameters,english:true})+'</span>':result;
  }
  resolve(key,source,params,html,rich={}) {
    source=localeString(source);
    if(this.locale==='en'){this.resolvedLanguages.set(key,'en');return html?localeEscape(source):source;}
    this.ensureContracts();const contract=this.contracts.get(key);
    if(!contract)return this.fallback(key,source,'missing-source-contract',html);
    if(contract.classification==='ambiguous')return this.fallback(key,source,'ambiguous-source-contract',html);
    const matched=this.matchSource(contract,source,params);
    if(!matched)return this.fallback(key,source,'stale-source-or-parameter-contract',html);
    const values=matched.values,entry=this.catalog?.entries[key],message=this.validateMessage(contract,entry,values);
    if(message===null)return this.fallback(key,source,entry?'stale-or-invalid-translation':'missing-translation',html);
    const rendered=this.parts(message,contract,values,html,{rich});if(rendered===null)return this.fallback(key,source,'missing-human-translation',html);
    this.coverage.set(key,(this.coverage.get(key)||0)+1);this.resolvedLanguages.set(key,this.locale);return rendered;
  }
  text(key,source,params={}) {return this.resolve(key,source,params,false);}
  html(key,source,params={}) {return this.resolve(key,source,params,true);}
  plural(key,count,source,params={}) {return this.text(key,source,{...params,count});}
  language(key) {return this.resolvedLanguages.get(key)||this.locale;}
  explanation(ownerId,fieldPath,source,context,html) {
    source=localeString(source);const identity=ownerId+'.'+fieldPath;
    if(!source){this.resolvedLanguages.set(identity,this.locale);return '';}
    if(this.locale==='en'){this.resolvedLanguages.set(identity,'en');return html?localeEscape(source):source;}
    this.ensureContracts();const candidates=this.owners.get(ownerId+'\0'+fieldPath)||[];
    let selected=null,specificity=-1,priority=-1,ambiguous=false;
    for(const contract of candidates){
      const constraints=Object.entries(contract.context||{});
      if(constraints.some(([key,value])=>context[key]!==value))continue;
      const matched=this.matchSource(contract,source,context.parameters||{});if(!matched)continue;
      if(constraints.length>specificity||constraints.length===specificity&&matched.priority>priority){selected=contract;specificity=constraints.length;priority=matched.priority;ambiguous=false;}
      else if(constraints.length===specificity&&matched.priority===priority)ambiguous=true;
    }
    if(ambiguous)return this.fallback(identity,source,'ambiguous-explanation-binding',html);
    if(!selected)return this.fallback(identity,source,'missing-explanation-binding',html);
    const rendered=this.resolve(selected.key,source,context.parameters||{},html);this.resolvedLanguages.set(identity,this.language(selected.key));return rendered;
  }
  explain(ownerId,fieldPath,source,context={}) {return this.explanation(ownerId,fieldPath,source,context,false);}
  explainHtml(ownerId,fieldPath,source,context={}) {return this.explanation(ownerId,fieldPath,source,context,true);}
  searchEntry(kind,id,record,context={}) {
    if(this.locale==='en')return null;
    const signature=JSON.stringify([context,record.name,record.title,record.summary,record.category,record.meaning,record.purpose,record.origin,record.selectedLabel,record.searchVariants?.map(variant=>[variant.id,variant.label,variant.searchTags,variant.searchContext])]);
    const key=kind+'\0'+id,cached=this.searchCache.get(key);if(cached?.signature===signature)return cached.entry;
    let entry;
    const owner=(kind==='field'?'field:':kind==='actor'?'actor:':kind==='topic'?'topic:':kind==='workspace'||kind==='workspace-option'?'workspace-option:':'lesson:')+id;
    entry={revision:this.revision};
    for(const field of ['title','summary','category','meaning','purpose','origin','selectedLabel'])if(typeof record[field]==='string')entry[field]=this.explain(owner,field,record[field],context);
    if(kind==='topic'&&typeof record.name==='string')entry.title=this.explain(owner,'name',record.name,context);
    const aliases=this.catalog?.aliases?.[kind]?.[id];if(aliases)entry.searchTags=aliases.slice();
    if(record.searchVariants)entry.searchVariants=record.searchVariants.map(variant=>({...variant,label:typeof variant.label==='string'?this.explain(owner,'searchVariants.label',variant.label,{...context,variantId:variant.id}):variant.id}));
    this.searchCache.set(key,{signature,entry});return entry;
  }
  metadata(root,{documentOwner=false}={}) {
    root.setAttribute('lang',this.locale);root.setAttribute('dir',this.direction);
    if(documentOwner){const document=root.ownerDocument;document.documentElement.setAttribute('lang',this.locale);document.documentElement.setAttribute('dir',this.direction);}
  }
  diagnostics() {
    const resources=Object.values(this.resources),inactive=resources.filter(resource=>resource&&typeof resource==='object'&&resource!==this.catalog).length;
    return {locale:this.locale,direction:this.direction,revision:this.revision,activeCatalog:this.catalog?.locale||null,inactiveParsedCatalogs:inactive,opaqueResourceProviders:resources.filter(resource=>typeof resource==='function').length,englishContracts:this.contracts?.size||0,activeSearchEntries:this.searchCache.size,activeSourceMatchers:this.matchers.size,sourceMatcherLimit:512,exercisedMessages:this.coverage.size,fallbacks:[...this.fallbacks].map(([key,count])=>({key,count})),pluralDataSource:this.pluralDataSource,numberDataSource:this.numberDataSource,pluralRuleFallbackVersion:'CLDR 49 ordinary decimal cardinal counts'};
  }
}
