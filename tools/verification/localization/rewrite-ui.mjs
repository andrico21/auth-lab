import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {parse} from 'acorn';
import {fullAncestor} from 'acorn-walk';
import {parseFragment} from 'parse5';

// Authoring tool only. Produces proposals, never edits source or translates DOM.
// Assigned literal keys remain in source when English wording changes later.
export function proposeStaticMessages(source,{module='src/app.js',prefix='ui.app'}={}) {
  const ast=parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true});
  const edits=[],messages=[],unresolved=[],used=new Set();
  for(const match of source.matchAll(/['"]((?:ui\.)[^'"]+)['"]/g))used.add(match[1]);
  let sequence=0;
  const allocate=(owner,kind)=>{let key;do{key=prefix+'.'+owner+'.'+kind+'.'+String(++sequence).padStart(4,'0');}while(used.has(key));used.add(key);return key;};
  fullAncestor(ast,(node,ancestors)=>{
    if(node.type!=='TemplateLiteral'||!node.quasis.some(quasi=>/<[A-Za-z!/]/.test(quasi.value.raw)))return;
    const method=[...ancestors].reverse().find(ancestor=>ancestor.type==='MethodDefinition');
    if(!method||method.static)return;
    const owner=method.key.name||method.key.value,coordinates=[],parts=[];
    for(let index=0;index<node.quasis.length;index++){
      const quasi=node.quasis[index],raw=quasi.value.raw;parts.push(raw);
      for(let offset=0;offset<raw.length;offset++)coordinates.push(quasi.start+offset);
      if(index<node.expressions.length){const marker='\ue000'+index+'\ue001';parts.push(marker);for(let offset=0;offset<marker.length;offset++)coordinates.push(null);}
    }
    const html=parts.join(''),document=parseFragment(html,{sourceCodeLocationInfo:true});
    const marker=/[\ue000\ue001]/u,blocked=new Set(['code','pre','script','style','svg','path','marker','textarea']);
    const add=(start,end,english,kind,element)=>{
      if(start===undefined||end===undefined||end<=start||marker.test(html.slice(start,end)))return;
      const from=coordinates[start],last=coordinates[end-1];if(from==null||last==null||last-from!==end-start-1)return;
      const raw=source.slice(from,last+1);if(raw.includes('\\')||/\$\{/.test(raw))return;
      const key=allocate(owner,kind),call=kind==='attribute'?'escapeHtml(this.uiText('+JSON.stringify(key)+','+JSON.stringify(english)+'))':'this.ui('+JSON.stringify(key)+','+JSON.stringify(english)+')';
      edits.push({start:from,end:last+1,replacement:'${'+call+'}',line:source.slice(0,from).split('\n').length});
      messages.push({key,english,owner:{module,export:'AuthFlowStudio',semanticId:'ui:'+owner,fieldPath:kind},element,sourceSha256:crypto.createHash('sha256').update(english).digest('hex')});
    };
    const visit=(element,protectedParent=false)=>{
      const tag=element.tagName||'',attrs=Object.fromEntries((element.attrs||[]).map(attribute=>[attribute.name,attribute.value]));
      const protectedHere=protectedParent||blocked.has(tag)||attrs.translate==='no'||tag==='a'&&/^https?:/.test(attrs.href||'')&&/^(?:RFC\b|[A-Z][A-Za-z0-9_. /:+-]*\d|Kirill Andrienko$|andrico21\/)/.test(element.childNodes?.map(child=>child.value||'').join('')||'');
      const identity=attrs.id||attrs['data-study-key']||attrs.class||tag;
      if(!protectedHere){
        for(const name of ['aria-label','title','placeholder','alt']){
          const value=attrs[name],location=element.sourceCodeLocation?.attrs?.[name];
          if(!value||!location||marker.test(value)||!/[A-Za-z]{2}/.test(value))continue;
          const original=html.slice(location.startOffset,location.endOffset),match=/^[^=]+\s*=\s*(["'])([\s\S]*)\1$/.exec(original);if(!match)continue;
          const valueStart=location.startOffset+original.indexOf(match[1])+1;
          add(valueStart,location.endOffset-1,value,'attribute',identity+':'+name);
        }
        for(const child of element.childNodes||[])if(child.nodeName==='#text'){
          const location=child.sourceCodeLocation,text=child.value,trimmed=text?.trim();
          if(!location||!trimmed||!/[A-Za-z]{2}/.test(trimmed)||marker.test(text))continue;
          const siblings=(element.childNodes||[]),hasProseExpression=siblings.some(sibling=>sibling.nodeName==='#text'&&marker.test(sibling.value||''));
          if(hasProseExpression){unresolved.push({owner,element:identity,reason:'mixed-dynamic-message',english:text});continue;}
          const raw=html.slice(location.startOffset,location.endOffset),leading=raw.match(/^\s*/)[0].length,trailing=raw.match(/\s*$/)[0].length;
          add(location.startOffset+leading,location.endOffset-trailing,trimmed,'text',identity);
        }
      }
      for(const child of element.childNodes||[])if(child.nodeName!=='#text')visit(child,protectedHere);
    };
    visit(document);
  });
  edits.sort((left,right)=>left.start-right.start);
  for(let index=1;index<edits.length;index++)if(edits[index].start<edits[index-1].end)throw new Error('Overlapping static UI proposal.');
  let rewritten=source;for(const edit of [...edits].reverse())rewritten=rewritten.slice(0,edit.start)+edit.replacement+rewritten.slice(edit.end);
  // Parsing is structural validation of this authoring proposal, not app acceptance.
  parse(rewritten,{ecmaVersion:'latest',sourceType:'module'});
  const before=source.split('\n'),after=rewritten.split('\n');
  if(before.length!==after.length)throw new Error('Static message extraction changed source line boundaries.');
  const lines=before.flatMap((line,index)=>line===after[index]?[]:[{line:index+1,before:line,after:after[index]}]);
  return {module,sourceSha256:crypto.createHash('sha256').update(source).digest('hex'),messages,unresolved,lines,rewritten};
}
if(process.argv[1]&&path.resolve(process.argv[1])===path.resolve(new URL(import.meta.url).pathname)){
  const file=process.argv[2],output=process.argv[3];if(!file||!output)throw new Error('Usage: bun rewrite-ui.mjs SOURCE PROPOSAL.json');
  const proposal=proposeStaticMessages(fs.readFileSync(file,'utf8'));fs.writeFileSync(output,JSON.stringify(proposal,null,2)+'\n');
  console.log(JSON.stringify({file,proposedMessages:proposal.messages.length,changedLines:proposal.lines.length,mixedDynamicFragments:proposal.unresolved.length,proposal:output}));
}
