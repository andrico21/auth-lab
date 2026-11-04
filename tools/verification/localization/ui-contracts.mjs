import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';
import {parse} from 'acorn';
import {fullAncestor} from 'acorn-walk';
import {parseFragment} from 'parse5';
import {ProtectedRegistry, sha256, stableJson, semanticParameters} from './protected.mjs';

// Authoring-time syntax extraction only: never import or evaluate a renderer.
export const UI_MODULES = ['src/app.js','src/study-controller.js','src/scenario-picker.js','src/compact-view.js','src/held-object-view.js','src/held-study-projection.js'];
const rootDefault = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const parameterProtection = new ProtectedRegistry();
const unwrap = node => node?.type === 'ChainExpression' ? unwrap(node.expression) : node;
const name = node => node?.type === 'Identifier' ? node.name : node?.value;
const literal = node => node?.type === 'Literal' && typeof node.value === 'string' ? node.value : node?.type === 'TemplateLiteral' && !node.expressions.length ? node.quasis[0].value.cooked : null;
const counts = value => {const result={};for(const match of value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g))result[match[1]]=(result[match[1]]||0)+1;return result;};
const raw = (info,node) => node ? info.source.slice(node.start,node.end) : '';
function readModule(root,module) {
  const source=fs.readFileSync(path.join(root,module),'utf8');
  const ast=parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true});
  const nodes=[],parents=new Map();
  fullAncestor(ast,(node,ancestors)=>{nodes.push(node);parents.set(node,ancestors.slice(0,-1));});
  return {module,source,ast,nodes,parents,sourceSha256:sha256(source)};
}
function site(info,node) {
  const ancestors=info.parents.get(node)||[];
  const method=[...ancestors].reverse().find(item=>item.type==='MethodDefinition');
  const fn=[...ancestors].reverse().find(item=>item.type==='FunctionDeclaration');
  const cls=[...ancestors].reverse().find(item=>item.type==='ClassDeclaration'||item.type==='ClassExpression');
  return {module:info.module,export:cls?.id?.name||fn?.id?.name||'<module>',method:name(method?.key)||fn?.id?.name||'<module>',start:node.start,end:node.end,line:node.loc.start.line,column:node.loc.start.column,sourceFileSha256:info.sourceSha256,callSha256:sha256(raw(info,node))};
}
function callee(info,node) {
  node=unwrap(node);if(!node)return '';
  if(node.type==='Identifier')return node.name;
  if(node.type==='MemberExpression')return callee(info,node.object)+'.'+(node.computed?literal(node.property)||'['+raw(info,node.property)+']':name(node.property));
  if(node.type==='ThisExpression')return 'this';
  return raw(info,node);
}
function direct(info,node) {
  let target=callee(info,node.callee);
  const member=unwrap(node.callee);
  if(member?.type==='MemberExpression'&&member.object.type==='Identifier'){
    const receiver=binding(info,member.object.name,node);
    if(receiver)target=callee(info,receiver)+'.'+name(member.property);
  }
  const leaf=target.split('.').at(-1);
  if(/(?:^|\.)(?:localizer|localization)\.(?:text|html|plural|rich)$/.test(target))return {kind:leaf,key:0,english:leaf==='plural'?2:1,params:leaf==='plural'?3:2,count:leaf==='plural'?1:null,provenance:target};
  if(/^(?:this|app|this\.app)\.(?:ui|uiText|rich)$/.test(target))return {kind:leaf==='rich'?'rich':leaf==='ui'?'html':'text',key:0,english:1,params:2,count:null,provenance:'app UI helper: '+target};
  return null;
}
function functionName(info,node) {
  const parents=info.parents.get(node)||[],parent=parents.at(-1);
  if(parent?.type==='MethodDefinition')return 'this.'+name(parent.key);
  if(parent?.type==='VariableDeclarator'&&parent.id.type==='Identifier')return parent.id.name;
  if(node.type==='FunctionDeclaration')return node.id.name;
  return null;
}
function wrapperKey(info,node) {
  const id=functionName(info,node);
  return id&&!id.startsWith('this.')&&node.type!=='FunctionDeclaration'?id+'@'+node.start:id;
}
function wrapperFor(info,call,aliases) {
  const target=callee(info,call.callee),init=unwrap(call.callee)?.type==='Identifier'?binding(info,target,call):null;
  return aliases.get(init?target+'@'+init.start:target);
}
function wrappers(info) {
  const result=new Map(),definitions=[];
  for(const node of info.nodes)if(node.type==='VariableDeclarator'&&node.id.type==='Identifier'){
    let target=unwrap(node.init);
    if(target?.type==='CallExpression'&&name(unwrap(target.callee)?.property)==='bind')target=unwrap(target.callee).object;
    if(target?.type==='MemberExpression'){
      const contract=direct(info,{...node,callee:target});
      if(contract)result.set(node.id.name+'@'+node.init.start,{...contract,provenance:{alias:node.id.name,site:site(info,node),forwardedTo:callee(info,target)}});
    }
  }
  for(const node of info.nodes)if(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(node.type)){
    const id=wrapperKey(info,node);if(id)definitions.push({id,node});
  }
  let changed=true;
  while(changed){changed=false;
    for(const {id,node} of definitions){if(result.has(id))continue;
      const args=node.params.map(param=>param.type==='AssignmentPattern'?name(param.left):name(param));
      const calls=info.nodes.filter(call=>call.type==='CallExpression'&&call.start>=node.start&&call.end<=node.end&&enclosingFunction(info,call)===node);
      for(const call of calls){const contract=direct(info,call)||wrapperFor(info,call,result);if(!contract)continue;
        const key=name(call.arguments[contract.key]);if(!key||!args.includes(key))continue;
        const englishArg=contract.capturedEnglish||call.arguments[contract.english];let english=args.indexOf(name(englishArg));
        // Renderer wrappers realize a source template before forwarding it.
        if(english<0){const sourceArg=args.findIndex(arg=>/^(?:source|english|englishSource|sourceTemplate|exactEnglishSource)$/.test(arg));if(sourceArg>=0)english=sourceArg;}
        const count=contract.count===null?null:args.indexOf(name(call.arguments[contract.count]));
        const params=args.findIndex(arg=>/^(?:params|parameters)$/.test(arg));
        result.set(id,{kind:contract.kind,key:args.indexOf(key),english:english<0?null:english,...(english<0?{capturedEnglish:englishArg}:{}),params:params<0?null:params,count:count===-1?null:count,provenance:{wrapper:id,site:site(info,node),forwardedTo:callee(info,call.callee)}});changed=true;break;
      }
    }
  }
  return result;
}
function wrapperTables(infos) {
  const tables=new Map(infos.map(info=>[info.module,wrappers(info)])),classes=new Map();
  for(const info of infos)for(const node of info.nodes)if(node.type==='ClassDeclaration'&&node.id)classes.set(node.id.name,{info,node});
  const methods=(className,seen=new Set())=>{
    if(seen.has(className)||!classes.has(className))return new Map();
    const {info,node}=classes.get(className),result=methods(name(node.superClass),new Set([...seen,className]));
    for(const [alias,contract] of tables.get(info.module))if(alias.startsWith('this.')&&contract.provenance?.site?.export===className)result.set(alias,contract);
    return result;
  };
  const controller=infos.find(info=>info.module==='src/app.js')?.nodes.find(node=>node.type==='ClassDeclaration')?.id?.name;
  const controllerMethods=methods(controller);
  for(const info of infos){
    const aliases=new Map(tables.get(info.module));
    for(const node of info.nodes)if(node.type==='ClassDeclaration'&&node.superClass)for(const [alias,contract] of methods(name(node.superClass)))if(!aliases.has(alias))aliases.set(alias,{...contract,provenance:{...contract.provenance,inheritedFrom:name(node.superClass)}});
    for(const [alias,contract] of controllerMethods)for(const receiver of ['app','this.app'])aliases.set(receiver+alias.slice(4),{...contract,provenance:{...contract.provenance,receiver}});
    tables.set(info.module,aliases);
  }
  return tables;
}
function enclosingFunction(info,node) {return [...(info.parents.get(node)||[])].reverse().find(item=>['FunctionExpression','FunctionDeclaration','ArrowFunctionExpression'].includes(item.type));}
function binding(info,id,at) {
  const ancestors=info.parents.get(at)||[];
  const lexicalScope=node=>{
    const parents=info.parents.get(node)||[],declaration=parents.at(-1);
    if(declaration?.type==='VariableDeclaration'&&declaration.kind==='var')return enclosingFunction(info,node)||info.ast;
    return [...parents].reverse().find(item=>['BlockStatement','Program','ForStatement','ForOfStatement','ForInStatement','CatchClause'].includes(item.type));
  };
  return info.nodes.filter(node=>node.type==='VariableDeclarator'&&node.id.type==='Identifier'&&node.id.name===id&&node.start<at.start&&ancestors.includes(lexicalScope(node))).at(-1)?.init;
}
function value(info,node,env={},seen=new Set()) {
  node=unwrap(node);if(!node)return undefined;
  const identity=callee(info,node);if(Object.hasOwn(env,identity))return env[identity];
  if(node.type==='Literal')return node.value;
  if(node.type==='ArrayExpression')return node.elements.map(element=>value(info,element,env,seen));
  if(node.type==='ObjectExpression'){
    const result=Object.create(null);
    for(const property of node.properties){if(property.type!=='Property'||property.kind!=='init')return undefined;const key=property.computed?value(info,property.key,env,seen):name(property.key);if(key===undefined)return undefined;result[key]=value(info,property.value,env,seen);}
    return result;
  }
  if(node.type==='MemberExpression'){
    const object=value(info,node.object,env,seen),property=node.computed?value(info,node.property,env,seen):name(node.property);
    if(object&&typeof object==='object'&&property!==undefined&&Object.hasOwn(object,property))return object[property];
  }
  if(node.type==='TemplateLiteral'){
    let text='';for(let i=0;i<node.quasis.length;i++){text+=node.quasis[i].value.cooked;if(i<node.expressions.length){const part=value(info,node.expressions[i],env,seen);if(part===undefined)return undefined;text+=part;}}return text;
  }
  if(node.type==='Identifier'&&!seen.has(node.name)){const init=binding(info,node.name,node);if(init)return value(info,init,env,new Set([...seen,node.name]));}
  if(node.type==='LogicalExpression'){
    const left=value(info,node.left,env,seen);if(left===undefined)return undefined;
    if(node.operator==='||')return left||value(info,node.right,env,seen);
    if(node.operator==='&&')return left&&value(info,node.right,env,seen);
    if(node.operator==='??')return left??value(info,node.right,env,seen);
  }
  if(node.type==='BinaryExpression'){
    const left=value(info,node.left,env,seen),right=value(info,node.right,env,seen);if(left===undefined||right===undefined)return undefined;
    switch(node.operator){case '+':return left+right;case '===':return left===right;case '!==':return left!==right;case '==':return left==right;case '!=':return left!=right;case '>':return left>right;case '>=':return left>=right;case '<':return left<right;case '<=':return left<=right;}
  }
  if(node.type==='ConditionalExpression'){const test=value(info,node.test,env,seen);if(test!==undefined)return value(info,test?node.consequent:node.alternate,env,seen);}
  if(node.type==='UnaryExpression'&&node.operator==='!'){const test=value(info,node.argument,env,seen);if(test!==undefined)return !test;}
  return undefined;
}
function memberOptions(info,node,env) {
  const resolved=value(info,node,env);if(resolved!==undefined)return [{value:resolved,env,conditions:[]}];
  node=unwrap(node);if(node?.type!=='MemberExpression')return [];
  const result=[];
  for(const object of memberOptions(info,node.object,env)){
    if(!object.value||typeof object.value!=='object')continue;
    const known=node.computed?value(info,node.property,object.env):name(node.property);
    for(const key of known===undefined?Object.keys(object.value):[known])if(Object.hasOwn(object.value,key)){
      const source=raw(info,node.property);
      result.push({value:object.value[key],env:known===undefined?{...object.env,[source]:key}:object.env,conditions:known===undefined?[...object.conditions,{source,equals:key}]:object.conditions});
    }
  }
  return result;
}
function bindPattern(pattern,item,env) {
  if(!pattern)return;
  if(pattern.type==='Identifier')env[pattern.name]=item;
  else if(pattern.type==='AssignmentPattern')bindPattern(pattern.left,item,env);
  else if(pattern.type==='ArrayPattern')for(const [index,part] of pattern.elements.entries())bindPattern(part,item?.[index],env);
  else if(pattern.type==='ObjectPattern')for(const property of pattern.properties)if(property.type==='Property')bindPattern(property.value,item?.[name(property.key)],env);
}
function scopeContexts(info,node,base={}) {
  let contexts=[base];
  for(const fn of info.parents.get(node)||[]){
    if(!['ArrowFunctionExpression','FunctionExpression'].includes(fn.type))continue;
    const call=info.parents.get(fn)?.at(-1),member=unwrap(call?.callee);
    if(call?.type!=='CallExpression'||!['map','flatMap','filter','forEach'].includes(name(member?.property)))continue;
    let sequence=member.object;
    while(sequence?.type==='CallExpression'&&['filter','slice','sort'].includes(name(unwrap(sequence.callee)?.property)))sequence=unwrap(sequence.callee).object;
    const next=[];
    for(const env of contexts){
      const operation=sequence?.type==='CallExpression'?callee(info,sequence.callee):'',object=operation.startsWith('Object.')?value(info,sequence.arguments[0],env):null;
      const items=operation==='Object.entries'&&object?Object.entries(object):operation==='Object.keys'&&object?Object.keys(object):operation==='Object.values'&&object?Object.values(object):value(info,sequence,env);
      if(!Array.isArray(items)){next.push(env);continue;}
      for(const [index,item] of items.entries()){const bound={...env};bindPattern(fn.params[0],item,bound);bindPattern(fn.params[1],index,bound);next.push(bound);}
    }
    contexts=next;
  }
  return contexts;
}
function dictionaryContexts(info,node,base={}) {
  const domains=new Map(),seen=new Set();
  const visit=expression=>{
    expression=unwrap(expression);if(!expression||seen.has(expression))return;seen.add(expression);
    if(expression.type==='Identifier'){const init=binding(info,expression.name,expression);if(init)visit(init);}
    if(expression.type==='MemberExpression'&&expression.computed&&value(info,expression.property,base)===undefined){
      const object=value(info,expression.object,base);
      if(object&&typeof object==='object'){const source=raw(info,expression.property);domains.set(source,[...new Set([...(domains.get(source)||[]),...Object.keys(object)])]);}
    }
    for(const child of Object.values(expression))if(Array.isArray(child)){for(const part of child)if(part?.type)visit(part);}else if(child?.type)visit(child);
  };visit(node);
  let contexts=[base];
  for(const [source,keys] of domains)contexts=contexts.flatMap(env=>keys.map(key=>({...env,[source]:key})));
  return contexts;
}
function alternatives(info,node,env={}) {
  const resolved=value(info,node,env);if(typeof resolved==='string')return [{text:resolved,conditions:[]}];
  node=unwrap(node);
  if(node?.type==='MemberExpression')return memberOptions(info,node,env).filter(option=>typeof option.value==='string').map(option=>({text:option.value,conditions:option.conditions}));
  if(node?.type==='Identifier'){const init=binding(info,node.name,node);if(init)return alternatives(info,init,env);}
  if(node?.type==='BinaryExpression'&&node.operator==='+'){
    const result=[];
    for(const left of alternatives(info,node.left,env))for(const right of alternatives(info,node.right,env)){
      const conditions=[...left.conditions,...right.conditions];
      if(!conditions.some((condition,index)=>conditions.slice(index+1).some(other=>other.source===condition.source&&other.value!==condition.value)))result.push({text:left.text+right.text,conditions});
    }
    return result;
  }
  if(node?.type==='ConditionalExpression')return [...alternatives(info,node.consequent,env).map(item=>({...item,conditions:[...item.conditions,{source:raw(info,node.test),value:true}]})),...alternatives(info,node.alternate,env).map(item=>({...item,conditions:[...item.conditions,{source:raw(info,node.test),value:false}]}))];
  return [];
}
function objectParams(info,node) {
  node=unwrap(node);if(node?.type==='Identifier')node=binding(info,node.name,node);
  if(!node)return {entries:[],issues:[]};
  if(node.type!=='ObjectExpression')return {entries:[],issues:[{reason:'dynamic-parameter-object',source:raw(info,node)}]};
  const entries=[],issues=[];
  for(const property of node.properties){if(property.type!=='Property'||property.computed){issues.push({reason:'spread-or-computed-parameter',source:raw(info,property)});continue;}entries.push([name(property.key),property.value]);}
  return {entries,issues};
}
function referenceHelper(info,node,allowOwner=false) {
  const fn=node?.type==='Identifier'?binding(info,node.name,node):null;
  let body=fn?.body;if(body?.type==='BlockStatement')body=body.body.find(item=>item.type==='ReturnStatement')?.argument;
  if(body?.type!=='ObjectExpression')return null;
  const fields=new Map(body.properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
  if(!fields.has('source')||!fields.has('key')&&!(allowOwner&&fields.has('ownerId')&&fields.has('fieldPath')))return null;
  const args=fn.params.map(param=>name(param.type==='AssignmentPattern'?param.left:param));
  const key=args.indexOf(name(fields.get('key'))),english=args.indexOf(name(fields.get('source'))),params=args.indexOf(name(fields.get('params')));
  const fieldArguments=Object.fromEntries([...fields].map(([field,expr])=>[field,{index:args.indexOf(name(expr)),source:raw(info,expr)}]));
  return english>=0&&(key>=0||allowOwner)?{kind:'reference',key,english,params:params<0?null:params,count:null,fieldArguments,provenance:{structuredReference:node.name,site:site(info,fn)}}:null;
}
function typedReference(info,node,env={},seen=new Set(),argumentsByName=new Map()) {
  node=unwrap(node);if(!node)return null;
  if(node.type==='Literal'&&node.value===null)return {typed:false,nullable:true,sources:[],hasParams:false};
  if(node.type==='Identifier'){
    const init=binding(info,node.name,node);return init&&!seen.has(init.start)?typedReference(info,init,env,new Set([...seen,init.start]),argumentsByName):null;
  }
  const merge=proofs=>proofs.length&&proofs.every(Boolean)&&proofs.some(proof=>proof.typed)?{typed:true,nullable:proofs.some(proof=>proof.nullable),sources:[...new Set(proofs.flatMap(proof=>proof.sources))],hasParams:proofs.some(proof=>proof.hasParams),factories:proofs.flatMap(proof=>proof.factories||[])}:null;
  if(node.type==='ConditionalExpression'){
    const selected=value(info,node.test,env);
    return selected!==undefined?typedReference(info,selected?node.consequent:node.alternate,env,seen,argumentsByName):merge([node.consequent,node.alternate].map(branch=>typedReference(info,branch,env,seen,argumentsByName)));
  }
  if(node.type==='ObjectExpression'){
    const fields=new Map(node.properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
    if(!fields.has('source')||!fields.has('key')&&!(fields.has('ownerId')&&fields.has('fieldPath')))return null;
    const source=fields.get('source'),actual=source.type==='Identifier'&&argumentsByName.has(source.name)?argumentsByName.get(source.name):source;
    return {typed:true,nullable:false,sources:[raw(info,actual)],hasParams:fields.has('params')};
  }
  if(node.type==='CallExpression'&&callee(info,node.callee).startsWith('this.')){
    const methodName=name(unwrap(node.callee)?.property),owner=site(info,node).export;
    const method=info.nodes.find(candidate=>candidate.type==='MethodDefinition'&&name(candidate.key)===methodName&&site(info,candidate.value).export===owner);
    if(!method||seen.has(method.start))return null;
    const params=new Map(method.value.params.map((param,index)=>[name(param.type==='AssignmentPattern'?param.left:param),node.arguments[index]||(param.type==='AssignmentPattern'?param.right:undefined)]).filter(([,argument])=>argument));
    const returns=info.nodes.filter(candidate=>candidate.type==='ReturnStatement'&&enclosingFunction(info,candidate)===method.value);
    const proof=merge(returns.map(statement=>typedReference(info,statement.argument,env,new Set([...seen,method.start]),params)));
    if(proof)proof.factories=[...(proof.factories||[]),{module:info.module,method:methodName,sourceSha256:sha256(raw(info,method))}];
    return proof;
  }
  return null;
}
function parameter(info,node,key,env) {
  const source=raw(info,node),constant=value(info,node,env);
  if(['Identifier','ConditionalExpression'].includes(node.type)){
    const proof=typedReference(info,node,env);
    if(proof?.typed)return {definition:{kind:'human',dynamic:true,sourcePath:source,reference:{...(proof.sources.length===1?{source:{source:proof.sources[0]}}:{}),sources:proof.sources,factories:proof.factories||[]}}};
  }
  if(node.type==='Identifier'){
    const init=binding(info,node.name,node);
    if(init&&['ObjectExpression','ConditionalExpression','CallExpression'].includes(init.type)){const result=parameter(info,init,key,env);if(result.definition)result.definition.sourcePath=source;return result;}
  }
  if(node.type==='CallExpression'){
    const helper=referenceHelper(info,node.callee,true);
    if(helper){
      const reference={};
      for(const [field,binding] of Object.entries(helper.fieldArguments)){const expr=node.arguments[binding.index];if(expr){const resolved=value(info,expr,env);reference[field]={source:raw(info,expr),...(resolved!==undefined?{value:resolved}:{})};}else reference[field]={factorySource:binding.source};}
      return {definition:{kind:'human',dynamic:true,sourcePath:source,reference}};
    }
    const proof=typedReference(info,node,env);
    if(proof?.typed)return {definition:{kind:'human',dynamic:true,sourcePath:source,reference:{...(proof.sources.length===1?{source:{source:proof.sources[0]}}:{}),sources:proof.sources,factories:proof.factories||[]}}};
  }
  if(node.type==='ObjectExpression'){
    const fields=new Map(node.properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
    if((fields.has('key')||fields.has('ownerId')&&fields.has('fieldPath'))&&fields.has('source')){
      const reference={};
      for(const [field,expr] of fields){const resolved=value(info,expr,env);reference[field]={source:raw(info,expr),...(resolved!==undefined?{value:resolved}:{})};}
      return {definition:{kind:'human',dynamic:true,sourcePath:source,reference}};
    }
    return {issue:{reason:'untyped-human-parameter-object',parameter:key,source}};
  }
  if(key==='count')return {definition:{kind:'count',dynamic:true,sourcePath:source}};
  if(typeof constant==='string'&&['undefined','null','true','false'].includes(constant))return {definition:{kind:'protected',dynamic:false,value:constant,sourcePath:source}};
  if(/(?:title|summary|detail|label|noun|singular|plural|message|description|explanation|contextText)$/i.test(key)||/\.(?:title|summary|detail|plainRole|label|singular|plural|description|explanation)\b/.test(source))return {issue:{reason:'human-parameter-needs-structured-reference',parameter:key,source}};
  const formal=typeof constant==='string'?parameterProtection.references(constant,[],{ui:true}):null;
  if(formal?.classification==='protected-only'&&formal.protectedReferences.length)return {definition:{kind:'protected',dynamic:false,value:constant,sourcePath:source}};
  if(node.type==='ConditionalExpression'){
    const variants=alternatives(info,node,env);
    if(variants.some(variant=>/[A-Za-z]/.test(variant.text)&&parameterProtection.references(variant.text,[],{ui:true}).classification!=='protected-only'))return {issue:{reason:'English-grammar-parameter-needs-whole-message',parameter:key,source,variants:variants.map(variant=>variant.text)}};
  }
  if(typeof constant==='string'&&/(?:name|names|id|protocol|actor|role|profile|status|code|kind|transport|format|protection|value|store)$/i.test(key))return {definition:{kind:'protected',dynamic:false,value:constant,sourcePath:source}};
  if(typeof constant==='string'&&/[a-zA-Z]{2}/.test(constant)&&!/[_.:/=\\{}]|\b[A-Z]{2,}\b/.test(constant))return {issue:{reason:'English-grammar-parameter-needs-whole-message',parameter:key,source,value:constant}};
  return {definition:{kind:'exact',dynamic:constant===undefined,sourcePath:source,...(constant!==undefined?{value:constant}:{})}};
}
function richParameter(info,node,key,env) {
  if(node.type==='Identifier'){const init=binding(info,node.name,node);if(init)return richParameter(info,init,key,env);}
  if(node.type==='ConditionalExpression'){
    const selected=value(info,node.test,env);
    if(selected!==undefined)return richParameter(info,selected?node.consequent:node.alternate,key,env);
  }
  if(node.type!=='ObjectExpression')return {issue:{reason:'dynamic-rich-descriptor',parameter:key,source:raw(info,node)}};
  const fields=new Map(node.properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
  const kind=value(info,fields.get('kind'),env),valueNode=fields.get('value');
  if(!['protected','exact','source','human','count'].includes(kind)||!valueNode)return {issue:{reason:'invalid-rich-parameter-kind',parameter:key,source:raw(info,node)}};
  const constant=value(info,valueNode,env);
  const result=kind==='human'?parameter(info,valueNode,key,env):{definition:{kind,dynamic:constant===undefined,sourcePath:raw(info,valueNode),...(constant!==undefined?{value:constant}:{})}};
  if(kind==='human'&&result.definition?.kind!=='human'){
    if(constant!==undefined)return {issue:{reason:'human-rich-descriptor-requires-structured-value',parameter:key,source:raw(info,valueNode)}};
    delete result.issue;
    result.definition={kind:'human',dynamic:true,sourcePath:raw(info,valueNode),structuredReferenceRequired:true,typeContract:'explicit-renderer-rich-descriptor; runtime enforces key/source or ownerId/fieldPath/source'};
  }
  if(result.definition){
    const direction=value(info,fields.get('direction'),env);if(direction)result.definition.direction=direction;
    result.fragment={source:raw(info,node),sourceSha256:sha256(raw(info,node)),...(fields.has('node')?{rendererNodeSource:raw(info,fields.get('node'))}:{})};
  }
  return result;
}
function bindStaticParameters(english,parameters,providedNames) {
  const occupied=[...english.matchAll(/\{[A-Za-z][A-Za-z0-9_]*\}/g)].map(match=>({start:match.index,end:match.index+match[0].length})),matches=[];
  for(const [parameter,definition] of Object.entries(parameters)){
    if(!providedNames.has(parameter)||definition.dynamic||!['protected','exact','source'].includes(definition.kind)||!['string','number','boolean'].includes(typeof definition.value))continue;
    const text=String(definition.value);if(!text)continue;
    let start=0;
    while((start=english.indexOf(text,start))!==-1){
      const end=start+text.length,boundary=!/[\p{L}\p{N}_]/u.test(english[start-1]||'')&&!/[\p{L}\p{N}_]/u.test(english[end]||'');
      if(boundary&&!occupied.some(range=>start<range.end&&end>range.start))matches.push({parameter,start,end});
      start=end;
    }
  }
  matches.sort((left,right)=>left.start-right.start||right.end-left.end);
  let output='',cursor=0;
  for(const match of matches)if(match.start>=cursor){output+=english.slice(cursor,match.start)+'{'+match.parameter+'}';cursor=match.end;}
  return output+english.slice(cursor);
}
function template(info,node,params,env={},issues=[]) {
  node=unwrap(node);if(!node)return null;
  const source=raw(info,node);
  for(const [key,definition] of Object.entries(params))if(definition.sourcePath===source||definition.kind==='human'&&definition.reference?.source?.source===source)return '{'+key+'}';
  if(node.type==='Identifier'){const init=binding(info,node.name,node);if(init)return template(info,init,params,env,issues);}
  if(!['BinaryExpression','TemplateLiteral','ConditionalExpression'].includes(node.type)){
    const resolved=value(info,node,env);if(typeof resolved==='string')return resolved;
  }
  if(node.type==='TemplateLiteral'){
    let result='';for(let i=0;i<node.quasis.length;i++){result+=node.quasis[i].value.cooked;if(i<node.expressions.length){const text=template(info,node.expressions[i],params,env,issues);if(text===null)return null;result+=text;}}return result;
  }
  if(node.type==='BinaryExpression'&&node.operator==='+'){const left=template(info,node.left,params,env,issues),right=template(info,node.right,params,env,issues);return left===null||right===null?null:left+right;}
  if(node.type==='ConditionalExpression'){const test=value(info,node.test,env);if(test!==undefined)return template(info,test?node.consequent:node.alternate,params,env,issues);}
  issues.push({reason:'dynamic-English-source-needs-contract',source});return null;
}
function pickerEnvironments(infos) {
  const picker=infos.find(info=>info.module==='src/scenario-picker.js');if(!picker)return [{}];
  const ctor=picker.nodes.find(node=>node.type==='MethodDefinition'&&name(node.key)==='constructor');
  const pattern=ctor?.value.params.at(-1)?.left,defaults={};
  for(const property of pattern?.properties||[]){const node=property.value;if(node.type==='AssignmentPattern'){const val=value(picker,node.right);if(val!==undefined)defaults['this.'+name(node.left)]=val;}}
  const environments=[{...defaults,'this.localizationKind':'scenario'}];
  for(const info of infos)for(const node of info.nodes)if(node.type==='NewExpression'&&callee(info,node.callee)==='ScenarioPicker'){
    const env={...defaults};for(const property of node.arguments.at(-1)?.properties||[]){const val=value(info,property.value);if(val!==undefined)env['this.'+name(property.key)]=val;}
    env['this.localizationKind']||=env['this.prefix']==='workspace'?'workspace':'scenario';environments.push(env);
  }
  // Domain comes from the actual constructor's kind selection, not translated nouns.
  for(const node of picker.nodes)if(node.type==='AssignmentPattern'&&name(node.left)==='localizationKind'&&node.right.type==='ConditionalExpression')for(const branch of [node.right.consequent,node.right.alternate]){const kind=literal(branch);if(kind&&!environments.some(env=>env['this.localizationKind']===kind))environments.push({...defaults,'this.localizationKind':kind});}
  return [...new Map(environments.map(env=>[stableJson(env),env])).values()];
}
function protectForms(registry,forms,parameters,providedNames=new Set(),context={}) {
  const byValue=new Map(),references=[],ambiguous=[],output={},normalized={...forms};let serial=0;
  for(const [old,definition] of Object.entries(parameters))if(definition.kind==='protected'&&Object.hasOwn(definition,'value')&&!providedNames.has(old)&&!/^protected\d+$/.test(old)){
    let key;do{key='protected'+(++serial);}while(Object.hasOwn(parameters,key));
    parameters[key]=definition;delete parameters[old];
    for(const form of Object.keys(normalized))normalized[form]=normalized[form].split('{'+old+'}').join('{'+key+'}');
  }
  for(const [form,english] of Object.entries(normalized)){
    const scanned=english.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g,placeholder=>' '.repeat(placeholder.length));
    const numericReferences=[...new Set([...scanned.matchAll(/\b\d+(?:\.\d+)?(?:×)?/g)].map(match=>match[0]))].map(value=>({value,formal:true,kind:'fixed-ui-number',sourcePath:'fixed-ui-number:'+value}));
    const protection=registry.references(scanned,numericReferences,{ui:true,...context}),remap=new Map();
    ambiguous.push(...protection.ambiguousReferences.map(reference=>({...reference,form})));
    for(const [old,definition] of Object.entries(protection.parameters)){
      const identity=stableJson(definition);let key=byValue.get(identity);if(!key){do{key='protected'+(++serial);}while(Object.hasOwn(parameters,key));byValue.set(identity,key);parameters[key]=definition;}remap.set(old,key);
    }
    let text='',cursor=0;
    for(const reference of protection.protectedReferences){text+=english.slice(cursor,reference.start)+'{'+remap.get(reference.parameter)+'}';cursor=reference.end;}
    output[form]=text+english.slice(cursor);
    for(const reference of protection.protectedReferences)references.push({...reference,parameter:remap.get(reference.parameter),form});
  }
  for(const [form,text] of Object.entries(output))for(const [parameter,occurrences] of Object.entries(counts(text))){
    const definition=parameters[parameter];
    if(!definition||!['protected','exact','source'].includes(definition.kind)||references.some(reference=>reference.form===form&&reference.parameter===parameter))continue;
    const registryId=Object.hasOwn(definition,'value')?registry.add('typed-ui-reference',String(definition.value),'ui-contract',definition.sourcePath||parameter):null;
    references.push({parameter,occurrences,form,...(registryId?{registryId}:{}),...(definition.dynamic?{dynamic:true}:{}),kind:definition.kind});
  }
  return {forms:output,protectedReferences:references,ambiguousReferences:ambiguous};
}
function residuals(info,covered) {
  // SVG geometry is technical, but the SVG's name/title/description are prose.
  const output=[],blocked=new Set(['code','pre','script','style','path','marker','textarea']);let serial=0;
  const marker=()=>'\ue000'+(++serial)+'\ue001';
  const compose=(node,env)=>{
    if(node.type==='Literal'&&typeof node.value==='string')return node.value;
    if(node.type==='TemplateLiteral')return node.quasis.map((quasi,index)=>(quasi.value.cooked||'')+(index<node.expressions.length?compose(node.expressions[index],env):'')).join('');
    if(node.type==='BinaryExpression'&&node.operator==='+')return compose(node.left,env)+compose(node.right,env);
    const known=node.type==='CallExpression'?undefined:value(info,node,env);
    return typeof known==='string'?known:marker();
  };
  const human=text=>/[A-Za-z]{2}/.test(text.replace(/\ue000\d+\ue001/g,''))&&parameterProtection.references(text.replace(/\ue000\d+\ue001/g,''),[],{ui:true}).classification!=='protected-only';
  for(const node of info.nodes){
    if(covered.some(call=>node.start>=call.start&&node.end<=call.end))continue;
    const parent=info.parents.get(node)?.at(-1);
    if(parent?.type==='BinaryExpression'&&parent.operator==='+')continue;
    if(!['Literal','TemplateLiteral','BinaryExpression'].includes(node.type)||node.type==='BinaryExpression'&&node.operator!=='+')continue;
    for(const context of scopeContexts(info,node,{})){
      const html=compose(node,context);if(!/<[A-Za-z!/]/.test(html))continue;
      const visit=(element,protectedParent=false)=>{
        const attrs=Object.fromEntries((element.attrs||[]).map(attribute=>[attribute.name,attribute.value]));
        const protectedHere=protectedParent||blocked.has(element.tagName)||attrs.translate==='no';
        if(!protectedHere){
          for(const attribute of element.attrs||[])if(['aria-label','title','placeholder','alt'].includes(attribute.name)&&human(attribute.value))output.push({...site(info,node),context,kind:'attribute',element:element.tagName,attribute:attribute.name,english:attribute.value,reason:'unwrapped-human-HTML-static',templateSha256:sha256(html)});
          for(const child of element.childNodes||[])if(child.nodeName==='#text'&&human(child.value||''))output.push({...site(info,node),context,kind:'text',element:element.tagName,english:child.value.trim(),reason:/\ue000/.test(child.value)?'unwrapped-mixed-human-HTML':'unwrapped-human-HTML-static',templateSha256:sha256(html)});
        }
        for(const child of element.childNodes||[])if(child.nodeName!=='#text')visit(child,protectedHere);
      };visit(parseFragment(html));
    }
  }
  return output;
}

function sourceFactories(info) {
  const factories=[],seen=new Set();
  const add=(node,key,english,params,kind)=>{
    const uiKey=(expression,seen=new Set())=>{
      expression=unwrap(expression);if(!expression||seen.has(expression))return false;
      const next=new Set([...seen,expression]);
      if(literal(expression)?.startsWith('ui.'))return true;
      if(expression.type==='Identifier')return uiKey(binding(info,expression.name,expression),next);
      if(expression.type==='ConditionalExpression')return uiKey(expression.consequent,next)&&uiKey(expression.alternate,next);
      if(expression.type==='BinaryExpression'&&expression.operator==='+')return uiKey(expression.left,next)||uiKey(expression.right,next);
      return expression.type==='TemplateLiteral'&&expression.quasis.some(quasi=>quasi.value.cooked?.startsWith('ui.'));
    };
    if(!uiKey(key)||seen.has(node.start))return;
    seen.add(node.start);
    const factory={...node,type:'UISourceFactory',callee:{type:'Identifier',name:'<'+kind+'>'},arguments:[key,english,params].filter((item,index)=>index<2||item),sourceFactory:kind,uiContract:{kind:'reference',key:0,english:1,params:params?2:null,count:null,provenance:{factory:kind}}};
    info.parents.set(factory,info.parents.get(node)||[]);factories.push(factory);
  };
  for(const node of info.nodes){
    if(node.type==='NewExpression'&&callee(info,node.callee)==='Map')for(const pair of node.arguments[0]?.elements||[]){
      if(pair?.type!=='ArrayExpression'||pair.elements[1]?.type!=='ObjectExpression')continue;
      const fields=new Map(pair.elements[1].properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
      add(pair,fields.get('key'),pair.elements[0],fields.get('params'),'literal-English-map');
    }
    if(node.type==='ObjectExpression'){
      const fields=new Map(node.properties.filter(item=>item.type==='Property').map(item=>[name(item.key),item.value]));
      if(fields.has('source'))add(node,fields.get('key'),fields.get('source'),fields.get('params'),'structured-reference-object');
    }
  }
  return factories;
}
function matchesHandoff(info,location,keyNode,englishNode,parameterNode,handoff,{dynamicKey=false}={}) {
  const sites=[handoff,...(handoff.sourceSites||[]).map(site=>({...handoff,...site}))];
  return sites.some(site=>{
    if(site.module!==info.module||site.method!==location.method)return false;
    const expected=site.sourceCallSha256||site.callSha256;
    if(expected)return expected===location.callSha256;
    return site.sourceExpression===raw(info,englishNode)&&(site.parameterExpression??'')===raw(info,parameterNode)&&(!dynamicKey||site.keyExpression===raw(info,keyNode));
  });
}
function validateProducer(handoff,sourceInfo) {
  const producer=handoff.producer;if(!producer)return {binding:null};
  let info;try{info=sourceInfo(producer.module);}catch(error){return {issue:{reason:'missing-handoff-producer-source',producer,error:String(error.message)}};}
  const owner=producer.method?info.nodes.find(node=>node.type==='MethodDefinition'&&name(node.key)===producer.method):info.nodes.find(node=>(node.type==='VariableDeclarator'||node.type==='FunctionDeclaration')&&name(node.id)===producer.export);
  if(!owner)return {issue:{reason:'missing-handoff-producer-owner',producer}};
  if(producer.ownerSourceSha256&&producer.ownerSourceSha256!==sha256(raw(info,owner)))return {issue:{reason:'stale-handoff-producer-owner',producer,currentOwnerSourceSha256:sha256(raw(info,owner))}};
  let reference=owner;
  if(producer.expression){reference=info.nodes.find(node=>node.start>=owner.start&&node.end<=owner.end&&raw(info,node)===producer.expression);if(!reference)return {issue:{reason:'stale-handoff-producer-expression',producer}};}
  if(producer.property){
    const property=owner.init?.properties?.find(node=>node.type==='Property'&&name(node.key)===producer.property),current=value(info,property?.value);
    const declared=typeof handoff.english==='string'?handoff.english.replace(/\{(\w+)\}/g,(whole,key)=>Object.hasOwn(handoff.parameters?.[key]||{},'value')?String(handoff.parameters[key].value):whole):undefined;
    if(typeof current!=='string'||declared!==current)return {issue:{reason:'stale-handoff-producer-property',producer,current,declared}};
    reference=property;
  }
  if(producer.fieldPath){
    reference=info.nodes.find(node=>node.start>=owner.start&&node.end<=owner.end&&(node.type==='Property'&&name(node.key)===producer.fieldPath||node.type==='VariableDeclarator'&&name(node.id)===producer.fieldPath));
    if(!reference)return {issue:{reason:'missing-handoff-producer-field',producer}};
  }
  return {binding:{...producer,sourceFileSha256:info.sourceSha256,sourceSha256:sha256(raw(info,reference)),start:reference.start,end:reference.end}};
}
/** Returns Localizer-ready shared units and separately source-bound occurrences. */
export function extractUIContracts({root=rootDefault,modules=UI_MODULES,handoffs=[],unambiguousOnly=false}={}) {
  root=fs.realpathSync(root);
  const infos=modules.map(module=>readModule(root,module)),registry=new ProtectedRegistry(),messages=new Map(),occurrences=[],unresolved=[],residual=[],wrapperInventory=[],callInventory=[];
  const sourceInfos=new Map(infos.map(info=>[info.module,info]));
  const sourceInfo=module=>{if(!sourceInfos.has(module))sourceInfos.set(module,readModule(root,module));return sourceInfos.get(module);};
  const referenceMatches=reference=>{try{const info=sourceInfo(reference.module);return info.nodes.some(node=>raw(info,node)===reference.source&&sha256(reference.source)===reference.sourceSha256);}catch{return false;}};
  const handoffMessages=new Map(),authoringInputs=[];
  for(const handoff of handoffs){
    const input=typeof handoff==='string'?fs.readFileSync(handoff,'utf8'):stableJson(handoff),data=JSON.parse(input);
    authoringInputs.push({file:typeof handoff==='string'?path.basename(handoff):'<inline-authoring-declaration>',sourceSha256:sha256(input)});
    for(const item of data.messages||data.contracts||data.newUIContracts||[]){
      const method=item.method||(item.owner?.export?.includes('.')?item.owner.export.split('.').at(-1):undefined);
      handoffMessages.set(item.key,{module:data.module||item.owner?.module,...item,...(method?{method}:{})});
    }
  }
  const pickerEnvs=pickerEnvironments(infos),sourceWrappers=wrapperTables(infos);
  for(const info of infos){
    const aliases=sourceWrappers.get(info.module),covered=[];
    wrapperInventory.push(...[...aliases].map(([alias,contract])=>({module:info.module,alias,...contract,...(contract.capturedEnglish?{capturedEnglish:raw(info,contract.capturedEnglish)}:{})})));
    for(const call of [...info.nodes.filter(node=>node.type==='CallExpression'),...sourceFactories(info)].sort((left,right)=>left.start-right.start)){
      const contract=call.uiContract||direct(info,call)||wrapperFor(info,call,aliases)||referenceHelper(info,call.callee);if(!contract)continue;
      covered.push(call);const location=site(info,call),keyNode=call.arguments[contract.key],englishNode=contract.capturedEnglish||call.arguments[contract.english];
      if(call.sourceFactory)location.sourceFactory=call.sourceFactory;
      // Identical calls in one semantic method remain distinct source occurrences.
      // The ordinal is relative to the same method and exact call fingerprint,
      // never a source byte offset or a message identity by itself.
      location.repetition=callInventory.filter(item=>item.module===location.module&&item.method===location.method&&item.callSha256===location.callSha256).length;
      const enclosing=enclosingFunction(info,call),ownAlias=enclosing&&wrapperKey(info,enclosing);
      if(ownAlias&&aliases.has(ownAlias)&&keyNode?.type==='Identifier'&&enclosing.params.some(param=>name(param.type==='AssignmentPattern'?param.left:param)===keyNode.name)){
        callInventory.push({...location,status:'wrapper-forwarding',wrapper:ownAlias,callee:callee(info,call.callee)});continue;
      }
      if(ownAlias&&keyNode?.type==='MemberExpression'&&name(keyNode.property)==='key'&&englishNode?.type==='MemberExpression'&&name(englishNode.property)==='source'&&callee(info,keyNode.object)===callee(info,englishNode.object)&&enclosing.params.some(param=>name(param)===name(keyNode.object))){
        callInventory.push({...location,status:'wrapper-forwarding',wrapper:ownAlias,structuredReference:true,callee:callee(info,call.callee)});continue;
      }
      if(keyNode?.type==='MemberExpression'&&name(keyNode.property)==='key'){
        const proof=typedReference(info,keyNode.object),parameterNode=contract.params===null?null:call.arguments[contract.params];
        const sameSource=englishNode?.type==='MemberExpression'&&name(englishNode.property)==='source'&&callee(info,keyNode.object)===callee(info,englishNode.object)||proof?.sources.includes(raw(info,englishNode));
        const sameParams=!proof?.hasParams||parameterNode?.type==='MemberExpression'&&name(parameterNode.property)==='params'&&callee(info,parameterNode.object)===callee(info,keyNode.object);
        if(proof?.typed&&sameSource&&sameParams){callInventory.push({...location,status:'wrapper-forwarding',wrapper:ownAlias||'<typed-reference-consumer>',structuredReference:true,sourceFactories:proof.factories||[],callee:callee(info,call.callee)});continue;}
      }
      const inventory={...location,callee:callee(info,call.callee),status:'unresolved',messageKeys:[]};callInventory.push(inventory);
      const environments=(info.module==='src/scenario-picker.js'?pickerEnvs:[{}]).flatMap(env=>scopeContexts(info,call,env)).flatMap(env=>dictionaryContexts(info,englishNode,env));let bound=0;
      for(const env of environments){
        let keys=alternatives(info,keyNode,env);
        if(!keys.length)keys=[...handoffMessages.values()].filter(item=>matchesHandoff(info,location,keyNode,englishNode,contract.params===null?null:call.arguments[contract.params],item,{dynamicKey:true})).map(item=>({text:item.key,conditions:[],declaredFamily:true}));
        if(!keys.length){
          const declaredCandidates=[...handoffMessages.values()].filter(item=>item.module===info.module&&item.method===location.method&&item.keyExpression===raw(info,keyNode)).map(item=>({key:item.key,sourceExpression:item.sourceExpression,parameterExpression:item.parameterExpression}));
          unresolved.push({...location,reason:'dynamic-or-missing-message-key',keySource:raw(info,keyNode),englishSource:raw(info,englishNode),parameterSource:raw(info,contract.params===null?null:call.arguments[contract.params]),declaredCandidates,context:env});continue;
        }
        for(const keyBranch of keys){
          const key=keyBranch.text,issues=[],parameters={},fragments={},parameterSource=objectParams(info,contract.params===null?null:call.arguments[contract.params]);issues.push(...parameterSource.issues);
          const messageEnv={...env,...Object.fromEntries(keyBranch.conditions.map(condition=>[condition.source,Object.hasOwn(condition,'equals')?condition.equals:condition.value]))};
          for(const [id,node] of parameterSource.entries){const result=contract.kind==='rich'?richParameter(info,node,id,messageEnv):parameter(info,node,id,messageEnv);if(result.issue)issues.push(result.issue);else parameters[id]=result.definition;if(result.fragment)fragments[id]=result.fragment;}
          const countNode=contract.count===null?(contract.kind==='rich'?null:parameterSource.entries.find(([id])=>id==='count')?.[1]):call.arguments[contract.count];
          if(countNode)parameters.count={kind:'count',dynamic:true,sourcePath:raw(info,countNode)};
          let plural=contract.kind==='plural'||Boolean(countNode),handoffApplied=false,producerBinding=null;const forms={};
          const supplied=handoffMessages.get(key);
          if(plural){for(const [form,count] of [['one',1],['other',2]]){
            const branchEnv={...messageEnv,[raw(info,countNode)]:count};
            // The count remains a placeholder; only its noun conditional is selected.
            const formNode=unwrap(englishNode);
            forms[form]=template(info,formNode,parameters,branchEnv,issues);
          }}else forms.source=template(info,englishNode,parameters,messageEnv,issues);
          const providedNames=new Set(parameterSource.entries.map(([id])=>id));
          for(const form of Object.keys(forms))if(typeof forms[form]==='string')forms[form]=bindStaticParameters(forms[form],parameters,providedNames);
          if(supplied){
            const expected=supplied.sourceCallSha256||supplied.callSha256;
            const expressionBound=matchesHandoff(info,location,keyNode,englishNode,contract.params===null?null:call.arguments[contract.params],supplied,{dynamicKey:Boolean(keyBranch.declaredFamily)});
            const authored=value(info,englishNode,messageEnv);
            const realized=typeof supplied.english==='string'?supplied.english.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(whole,id)=>Object.hasOwn(supplied.parameters?.[id]||{},'value')?String(supplied.parameters[id].value):whole):undefined;
            const literalFactoryBound=typeof authored==='string'&&authored===realized&&supplied.module===info.module&&supplied.method===location.method;
            const staleReferences=(supplied.sourceReferences||[]).filter(reference=>!referenceMatches(reference));
            const producer=validateProducer(supplied,sourceInfo);
            if(producer.issue)issues.push(producer.issue);
            if((expressionBound||literalFactoryBound)&&!staleReferences.length&&!producer.issue&&supplied.english){
              const declared=typeof supplied.english==='string'?{source:supplied.english}:supplied.english.plural;
              if(declared){
                plural=Boolean(supplied.english?.plural);for(const field of Object.keys(forms))delete forms[field];Object.assign(forms,declared);
                for(const [id,definition] of Object.entries(supplied.parameters||{})){
                  const sourcePath=parameters[id]?.sourcePath||(id==='count'&&countNode?raw(info,countNode):raw(info,contract.params===null?null:call.arguments[contract.params]));
                  parameters[id]={...definition,dynamic:definition.dynamic??!Object.hasOwn(definition,'value'),sourcePath};
                }
                for(let index=issues.length-1;index>=0;index--){
                  const issue=issues[index];
                  const grammarName=/^(?:noun|singular|plural)$/i.test(issue.parameter||'')||/\.(?:singular|plural)\b/.test(issue.source||'');
                  const typedTechnicalConstant=issue.reason==='English-grammar-parameter-needs-whole-message'&&!issue.variants&&supplied.parameters?.[issue.parameter]?.kind==='protected'&&supplied.parameters[issue.parameter].value===issue.value;
                  if(['dynamic-English-source-needs-contract','dynamic-parameter-object','spread-or-computed-parameter'].includes(issue.reason)||issue.reason==='human-parameter-needs-structured-reference'&&!grammarName&&supplied.parameters?.[issue.parameter]&&['human','protected','exact','source'].includes(supplied.parameters[issue.parameter].kind)||typedTechnicalConstant)issues.splice(index,1);
                }
                handoffApplied=true;
                producerBinding=producer.binding;
              }
            }else if(Object.values(forms).some(text=>text===null)||issues.length)issues.push({reason:'stale-or-unbound-handoff-source',expected,actual:location.callSha256,staleReferences});
          }
          for(const form of Object.keys(forms))if(typeof forms[form]==='string')forms[form]=bindStaticParameters(forms[form],parameters,providedNames);
          if(Object.values(forms).some(text=>text===null))issues.push({reason:'unresolved-English-reference'});
          if(issues.length){unresolved.push({...location,key,context:env,keyConditions:keyBranch.conditions,issues,englishSource:raw(info,englishNode),parameterSource:contract.params===null?'':raw(info,call.arguments[contract.params])});continue;}
          const protection=protectForms(registry,forms,parameters,providedNames,{ownerId:'ui:'+key,fieldPath:'message',sourceModule:info.module}),english=plural?{plural:protection.forms}:protection.forms.source;
          if(protection.ambiguousReferences.length)unresolved.push({...location,key,reason:'unclassified-protected-references',references:protection.ambiguousReferences});
          const required=Object.values(protection.forms).map(counts);
          if(required.some(item=>stableJson(item)!==stableJson(required[0]))){unresolved.push({...location,key,reason:'plural-parameter-contract-differs',forms:protection.forms,placeholderCounts:required});continue;}
          if(plural&&countNode&&parameters.count?.kind==='count'&&!Object.hasOwn(required[0],'count'))parameters.count.role='selector';
          const missing=Object.keys(required[0]).filter(id=>!Object.hasOwn(parameters,id));
          if(missing.length){unresolved.push({...location,key,reason:'untyped-template-parameters',parameters:missing});continue;}
          const unused=Object.keys(parameters).filter(id=>!Object.hasOwn(required[0],id)&&!(parameters[id].kind==='count'&&parameters[id].role==='selector'));
          if(unused.length){unresolved.push({...location,key,reason:'unused-provided-parameters',parameters:unused,forms});continue;}
          const parameterContract=semanticParameters(parameters);
          const sourceSha256=sha256(stableJson({english,parameters:parameterContract}));
          const protectedOnly=Object.values(protection.forms).every(text=>!/[\p{L}]/u.test(text.replace(/\{\w+\}/g,'')));
          const message={key,english,sourceSha256,referenceTemplate:english,parameters,protectedReferences:protection.protectedReferences,ambiguousReferences:protection.ambiguousReferences,placeholderCounts:required[0],owner:{module:info.module,export:location.export,semanticId:'ui:'+key,fieldPath:'message'},context:supplied?.context||{},classification:protection.ambiguousReferences.length?'ambiguous':protectedOnly?'protected-only':protection.protectedReferences.length||Object.keys(parameters).length?'mixed':'prose',fingerprintAlgorithm:'sha256(stableJson({english,parameters:withoutSourcePath}))'};
          message.fingerprintAlgorithm='sha256(stableJson({english,parameters:withoutSourceBindings}))';
          message.nativeProseNumerator=!protectedOnly&&message.classification!=='ambiguous';
          if(protectedOnly&&Object.keys(parameters).length){
            const humanParameters=Object.keys(parameters).filter(name=>parameters[name].kind==='human');
            message.composition={kind:'structural-template',sourceSha256,literalProse:false,parameters:Object.keys(parameters),humanParameters};
            if(humanParameters.length&&message.classification!=='ambiguous')message.classification='mixed';
          }
          message.sourceEnglish=plural?{plural:forms}:forms.source;
          message.source={module:info.module,export:location.export,method:location.method};
          const previous=messages.get(key);
          if(previous&&previous.sourceSha256!==sourceSha256){unresolved.push({...location,key,reason:'explicit-key-contract-conflict',previous:previous.sourceSha256,current:sourceSha256,english});continue;}
          if(!previous)messages.set(key,message);
          const binding={...location,messageKey:key,referenceEnglishSource:raw(info,englishNode),referenceSha256:sha256(raw(info,englishNode)),context:env,keyConditions:keyBranch.conditions,parameters:Object.fromEntries(Object.entries(parameters).filter(([,definition])=>definition.dynamic).map(([id,definition])=>[id,{source:definition.sourcePath,sourceSha256:sha256(definition.sourcePath)}])),...(Object.keys(fragments).length?{rendererFragments:fragments}:{}),wrapper:contract.provenance};
          if(handoffApplied){binding.sourceBinding='explicit-source-handoff';binding.declaredContractSha256=sha256(stableJson(supplied));}
          if(producerBinding)binding.producer=producerBinding;
          const occurrence={id:'ui-occurrence:'+sha256(stableJson({module:info.module,export:location.export,method:location.method,key,callSha256:location.callSha256,repetition:location.repetition,context:env,keyConditions:keyBranch.conditions})).slice(0,32),...binding};
          if(!occurrences.some(item=>item.id===occurrence.id))occurrences.push(occurrence);
          inventory.messageKeys.push(key);bound++;
        }
      }
      if(bound)inventory.status='bound';
    }
    residual.push(...residuals(info,covered));
  }
  const unresolvedKeys=new Set(unresolved.map(record=>record.key).filter(Boolean)),omitted=[];
  const units=[...messages.values()].filter(message=>{
    const omit=unambiguousOnly&&(message.classification==='ambiguous'||unresolvedKeys.has(message.key));
    if(omit)omitted.push({key:message.key,sourceSha256:message.sourceSha256,reason:'unresolved-or-ambiguous-source-contract'});
    return !omit;
  }).sort((a,b)=>a.key.localeCompare(b.key));
  if(unambiguousOnly){
    const keys=new Set(units.map(message=>message.key));
    for(let index=occurrences.length-1;index>=0;index--)if(!keys.has(occurrences[index].messageKey))occurrences.splice(index,1);
    for(const call of callInventory)if(call.status==='bound'&&!call.messageKeys.some(key=>keys.has(key)))call.status='omitted-ambiguous';
  }
  const summary={schemaVersion:1,scope:'Explicit source-bound UI only; canonical/generated explanatory inventory is separate.',root,modules:infos.map(info=>({module:info.module,sourceSha256:info.sourceSha256,sourceBytes:Buffer.byteLength(info.source)})),counts:{explicitCallsites:callInventory.length,wrapperForwardingCallsites:callInventory.filter(call=>call.status==='wrapper-forwarding').length,boundCallsites:callInventory.filter(call=>call.status==='bound').length,unresolvedCallsites:callInventory.filter(call=>call.status==='unresolved').length,sourceContracts:units.length,sourceOccurrences:occurrences.length,pluralContracts:units.filter(message=>typeof message.english==='object').length,unresolvedRecords:unresolved.length,residualHTMLRecords:residual.length,protectedReferences:registry.entries.size,englishBytes:units.reduce((total,message)=>total+Buffer.byteLength(typeof message.english==='string'?message.english:stableJson(message.english)),0)},fingerprintPolicy:'Actual reference template and typed parameter contract; call/file hashes bind each source occurrence separately.',complete:unresolved.length===0&&residual.length===0};
  summary.extractor={module:'tools/verification/localization/ui-contracts.mjs',sourceSha256:sha256(fs.readFileSync(fileURLToPath(import.meta.url))),protectedRegistrySha256:sha256(fs.readFileSync(new URL('./protected.mjs',import.meta.url)))};
  summary.modules=[...sourceInfos.values()].map(info=>({module:info.module,sourceSha256:info.sourceSha256,sourceBytes:Buffer.byteLength(info.source),role:modules.includes(info.module)?'renderer':'producer-reference'})).sort((left,right)=>left.module.localeCompare(right.module));
  summary.authoringInputs=authoringInputs;
  summary.sourceSetSha256=sha256(stableJson({modules:summary.modules,extractor:summary.extractor,authoringInputs}));
  summary.selection=unambiguousOnly?'unambiguous-only preliminary source inventory':'all source-bound contracts';
  summary.counts.omittedContracts=omitted.length;
  summary.counts.nativeProseContracts=units.filter(message=>message.nativeProseNumerator).length;
  summary.counts.referenceCompositionContracts=units.filter(message=>message.composition?.humanParameters.length).length;
  summary.counts.protectedOnlyContracts=units.filter(message=>message.classification==='protected-only').length;
  summary.counts.omittedCallsites=callInventory.filter(call=>call.status==='omitted-ambiguous').length;
  summary.counts.sourceFactorySites=callInventory.filter(call=>call.sourceFactory).length;
  summary.counts.boundFactorySites=callInventory.filter(call=>call.sourceFactory&&call.status==='bound').length;
  summary.counts.unresolvedFactorySites=callInventory.filter(call=>call.sourceFactory&&call.status==='unresolved').length;
  summary.counts.explicitCallsites-=summary.counts.sourceFactorySites;
  summary.counts.boundCallsites-=summary.counts.boundFactorySites;
  summary.counts.unresolvedCallsites-=summary.counts.unresolvedFactorySites;
  return {summary,messages:units,occurrences,unresolved,residual,omitted,wrappers:wrapperInventory,calls:callInventory,protectedReferences:registry.toJSON()};
}
export function writeUIContracts(result,out) {
  fs.mkdirSync(out,{recursive:true});const artifacts={};
  for(const [filename,value] of Object.entries({'ui-contracts.json':{messages:result.messages,occurrences:result.occurrences,unresolved:result.unresolved,residual:result.residual,omitted:result.omitted,protectedReferences:result.protectedReferences,sourceFiles:result.summary.modules,summary:result.summary},'messages.json':{messages:result.messages},'occurrences.json':result.occurrences,'unresolved.json':result.unresolved,'residual-html.json':result.residual,'omitted.json':result.omitted,'wrappers.json':result.wrappers,'calls.json':result.calls,'protected-references.json':result.protectedReferences})){
    const data=JSON.stringify(value)+'\n',compressed=gzipSync(data,{level:9});fs.writeFileSync(path.join(out,filename),data);fs.writeFileSync(path.join(out,filename+'.gz'),compressed);artifacts[filename]={bytes:Buffer.byteLength(data),gzipBytes:compressed.length,sha256:sha256(data)};
  }
  const summary={...result.summary,artifacts};fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');return summary;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2),options={handoffs:[]};let out;
  for(let index=0;index<args.length;index++){
    const arg=args[index];if(arg==='--unambiguous-only'){options.unambiguousOnly=true;continue;}if(!['--root','--out','--handoff'].includes(arg)||!args[index+1])throw new Error('Usage: bun ui-contracts.mjs --root ROOT --out DIRECTORY [--handoff JSON] [--unambiguous-only]');
    const val=args[++index];if(arg==='--root')options.root=val;else if(arg==='--out')out=val;else options.handoffs.push(val);
  }
  if(!out)throw new Error('--out is required.');
  console.log(JSON.stringify(writeUIContracts(extractUIContracts(options),out)));
}
