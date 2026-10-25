import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {installHarness} from './dom-harness.mjs';

// DNSSEC_DOM_BUNDLE selects an already-built standalone file. This test never builds.
const sandbox=process.env.DNSSEC_DOM_BUNDLE?{structuredClone}:globalThis;
const {document,clock,registry}=installHarness(sandbox);
let AuthFlowStudio;
if(process.env.DNSSEC_DOM_BUNDLE){
  const html=fs.readFileSync(process.env.DNSSEC_DOM_BUNDLE,'utf8');
  const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length,1);
  new vm.Script(scripts[0][1],{filename:'dnssec-teaching:standalone'}).runInContext(vm.createContext(sandbox));
  AuthFlowStudio=registry.get('auth-flow-studio');
}else ({AuthFlowStudio}=await import('../src/app.js'));
const text=node=>node?.textContent.replace(/\s+/g,' ').trim()||'';
function mount(id,variant){
  const app=new AuthFlowStudio();document.body.appendChild(app);document.activeElement=document.body;app.connectedCallback();
  app.addEventListener('focusin',event=>{document.activeElement=event.target;});
  app.selectLabScenario(id);if(variant)app.selectLessonVariant(variant);return app;
}
function unmount(app){app.disconnectedCallback();document.body.removeChild(app);clock.frames.clear();clock.timers.clear();}
function end(app){app.selectStep(app.visibleSteps.length-1,false);}
function cell(row,name){const found=row.querySelector('[data-dnssec-hop-cell="'+name+'"]');assert.ok(found,'Rendered '+name+' cell');return text(found);}
function comparePrefix(app){
  const panel=app.querySelector('.dnssec-hop-comparison');assert.ok(panel,'DNS05/06 exposes its hop comparison without opening the field catalog');
  const table=panel.querySelector('table');assert.ok(table);
  const hops=app.protocolSnapshot().state.dnssec.response.traceHops||[],rows=Array.from(table.querySelectorAll('tbody tr[data-dnssec-hop-id]'));
  assert.deepEqual(rows.map(row=>row.dataset.dnssecHopId),Array.from(hops,hop=>hop.id),'Rendered identities are precisely the current canonical prefix');
  for(const [index,hop] of hops.entries()){
    const row=rows[index];assert.match(cell(row,'identity'),new RegExp(hop.question.qtype));assert.ok(cell(row,'identity').includes(hop.id));
    for(const side of ['query','response']){
      const packet=hop[side],value=cell(row,side);
      if(!packet){assert.match(value,/pending|not received/i);continue;}
      assert.match(value,new RegExp('AD='+packet.flags.AD+'(?:\\b|$)'));
      assert.match(value,new RegExp('CD='+packet.flags.CD+'(?:\\b|$)'));
      assert.ok(value.includes(packet.edns.present?'DO='+packet.edns.DO:'OPT absent'),'DO=0 and absent OPT are different wire states');
    }
    assert.ok(cell(row,'delivery').includes(hop.response?.rcode||'Pending'));
    assert.ok(cell(row,'owner').length>0,'Responsibility is explained even before a check');
  }
  return rows;
}
function decision(app,label){const list=app.querySelector('#lesson-decisions').querySelector('dl'),row=Array.from(list.children).find(row=>text(row.querySelector('dt'))===label);assert.ok(row,'Decision '+label);return text(row.querySelector('dd'));}

test('DNS05 compares literal no-OPT and DO=0 query/response cells, and distinguishes cache reuse from fresh receipt',()=>{
  const app=mount('lab-dnssec05','unaware-stub');try{
    end(app);let rows=comparePrefix(app),stub=rows.find(row=>row.dataset.dnssecHopId==='lab-dnssec05:stub');assert.ok(stub);
    assert.match(cell(stub,'query'),/OPT absent/);assert.match(cell(stub,'response'),/OPT absent/);
    app.selectLessonVariant('ad-interest-without-do');end(app);rows=comparePrefix(app);stub=rows.find(row=>row.dataset.dnssecHopId==='lab-dnssec05:stub');
    assert.match(cell(stub,'query'),/DO=0/);assert.match(cell(stub,'response'),/DO=0/);
    app.selectLessonVariant('response-flags-and-cached-ad');end(app);rows=comparePrefix(app);stub=rows.find(row=>row.dataset.dnssecHopId==='lab-dnssec05:stub');
    assert.match(cell(stub,'query'),/AD=1.*CD=1.*DO=1/);assert.match(cell(stub,'response'),/AD=1.*CD=1.*DO=1/);
    assert.equal(decision(app,'Fresh authority data received'),'No');
    assert.equal(decision(app,'Authenticated cache reused'),'Yes');
    assert.equal(decision(app,'Response delivered to stub'),'Yes');
    assert.equal(decision(app,'Application received'),'Answer');
    assert.match(text(app.querySelector('.dnssec-receipt-context')),/no fresh.*(?:receipt|fetch).*no fresh.*check/i);
    assert.equal(app.protocolSnapshot().state.dnssec.transport.authorityQueries,0,'Clarity text does not invent authority work');
  }finally{unmount(app);}
});

test('DNS06 renders current canonical pending/received hops, authoritative CD=0, rewind and reset',()=>{
  const app=mount('lab-dnssec06','both-validate');try{
    assert.equal(comparePrefix(app).length,0,'Reset has no future query');
    const queryIndex=app.steps.findIndex(step=>step.id.endsWith(':stub:q'));assert.ok(queryIndex>=0);
    app.selectStep(queryIndex,false);let rows=comparePrefix(app);assert.equal(rows.length,1);assert.match(cell(rows[0],'response'),/pending/i);assert.match(cell(rows[0],'delivery'),/Pending/);
    end(app);rows=comparePrefix(app);
    const actual=app.protocolSnapshot().state.dnssec.response.traceHops;
    const byRoute=(from,to)=>{const hop=actual.find(hop=>hop.from===from&&hop.to===to&&hop.question.qtype==='A');assert.ok(hop);return rows.find(row=>row.dataset.dnssecHopId===hop.id);};
    assert.match(cell(byRoute('dnsStub','dnsResolver'),'query'),/AD=1.*CD=0.*DO=1/);
    assert.match(cell(byRoute('dnsResolver','dnsUpstream'),'query'),/AD=1.*CD=1.*DO=1/);
    const authority=byRoute('dnsUpstream','dnsChild');assert.match(cell(authority,'query'),/AD=0.*CD=1.*DO=1/);assert.match(cell(authority,'response'),/CD=0/);
    const authorityHop=actual.find(hop=>hop.id===authority.dataset.dnssecHopId);assert.ok(authorityHop.checkingOwner);assert.ok(cell(authority,'owner').includes(app.actor(authorityHop.checkingOwner).name));
    assert.match(text(app.querySelector('.dnssec-hop-comparison')),/authoritative.*CD=0.*recursive.*echo/i);
    app.selectStep(queryIndex,false);rows=comparePrefix(app);assert.equal(rows.length,1);assert.match(cell(rows[0],'response'),/pending/i);
    app.querySelector('#reset').click();assert.equal(comparePrefix(app).length,0);
  }finally{unmount(app);}
});

test('DNS06 retained CD0 SERVFAIL context and fresh CD1 query remain visibly separate without an invented prior hop',()=>{
  const app=mount('lab-dnssec06','cached-upstream-servfail-cd-zero-then-cd-one');try{
    end(app);const rows=comparePrefix(app),state=app.protocolSnapshot().state.dnssec,hops=state.response.traceHops;
    const prior=state.upstreamErrorEntries[0],freshHop=hops.find(hop=>hop.priorContextId===prior.id);assert.ok(freshHop);
    const first=app.querySelector('[data-dnssec-cache-context=\"'+prior.id+'\"]'),fresh=rows.find(row=>row.dataset.dnssecHopId===freshHop.id);assert.ok(first);assert.ok(fresh);
    assert.equal(first.hasAttribute('data-dnssec-hop-id'),false,'Retained context is not invented current wire history');
    assert.match(cell(first,'query'),/CD=0/);assert.match(cell(first,'query'),/AD.*not recorded.*DO.*not recorded/i);assert.match(cell(first,'delivery'),/SERVFAIL/);
    assert.match(cell(fresh,'query'),/CD=1/);assert.match(cell(fresh,'delivery'),/NOERROR/);
    assert.match(cell(first,'identity'),/cached|retained/i);assert.match(cell(fresh,'identity'),/fresh/i);
    assert.match(cell(first,'response'),/not recorded/i);
  }finally{unmount(app);}
});

test('ordinary and exact filtered replay render the same canonical hop prefixes as the full journey',()=>{
  const app=mount('lab-dnssec06','both-validate');try{
    app.selectAttribute('dnssec_header_flags_CD',false);assert.ok(app.traceQueue.length);end(app);comparePrefix(app);
    app.selectStep(0,false);comparePrefix(app);
    app.querySelector('[data-clear-trace]').click();assert.equal(comparePrefix(app).length,0);
    end(app);const full=Array.from(app.protocolSnapshot().state.dnssec.response.traceHops,hop=>hop.id);
    const held=app.heldView.snapshot().holdings.find(holding=>holding.actorId==='dnsApp'&&holding.artifactId.includes('application-result'));assert.ok(held);
    app.heldView.select(held);const replay=app.querySelector('[data-held-trace]');assert.ok(replay);replay.click();assert.ok(app.objectTraceSelection);
    end(app);comparePrefix(app);assert.deepEqual(Array.from(app.protocolSnapshot().state.dnssec.response.traceHops,hop=>hop.id),full);
    app.selectStep(0,false);comparePrefix(app);
    app.clearAttribute();assert.equal(comparePrefix(app).length,0);
  }finally{unmount(app);}
});

test('DNS verdicts use display names, keep raw identifiers in details, and explain secure-only refusal of authenticated insecurity',()=>{
  const app=mount('lab-dnssec01');try{
    end(app);assert.match(decision(app,'Checked by'),/In-process DNSSEC validator/);assert.doesNotMatch(decision(app,'Checked by'),/^dnsValidator$/);
    assert.match(decision(app,'Reason'),/authenticated|verified/i);assert.doesNotMatch(decision(app,'Reason'),/complete-anchor-ds-dnskey-answer-path/);
    const details=app.querySelector('.dnssec-decision-details');assert.ok(details?.querySelector('summary'));assert.match(text(details),/dnsValidator/);assert.match(text(details),/complete-anchor-ds-dnskey-answer-path/);
    app.selectLabScenario('lab-dnssec03');app.selectLessonVariant('proved-no-ds');end(app);
    assert.match(text(app.querySelector('#lesson-decisions')),/authenticated.*unsigned delegation.*insecure/i);
    assert.match(text(app.querySelector('#lesson-decisions')),/secure-only.*refus/i);
    assert.match(text(app.querySelector('#lesson-decisions')),/not.*forg/i);
  }finally{unmount(app);}
});

test('ordinary DNS16 directly explains CSYNC NS/glue versus CDS/CDNSKEY DS intent with the existing source',()=>{
  const app=mount('lab-dnssec16');try{
    const panel=app.querySelector('.dnssec-context-panel');assert.ok(panel);assert.equal(panel.hidden,false);
    assert.match(text(panel),/CSYNC/);assert.match(text(panel),/NS.*glue/i);assert.match(text(panel),/CDS.*CDNSKEY.*DS/i);
    assert.match(text(panel),/CSYNC.*(?:not|never).*DS/i);assert.match(text(panel),/parent.*(?:policy|decision|authentication)/i);
    assert.ok(Array.from(panel.querySelectorAll('a')).some(link=>link.getAttribute('href')==='https://www.rfc-editor.org/rfc/rfc7477.html'));
    assert.equal(app.attributeSelection,null,'The explanation is reachable without a field-catalog search or replay');
    app.selectLabScenario('lab-dnssec01');assert.equal(app.querySelector('.dnssec-context-panel'),null,'DNS16 context does not leak into another lesson');
  }finally{unmount(app);}
});

test('DNS16 preserves the exact source-link identity when multiple context links share one RFC URL',()=>{
  const app=mount('lab-dnssec16');try{
    const href='https://www.rfc-editor.org/rfc/rfc7477.html';
    const links=Array.from(app.querySelectorAll('.dnssec-context-panel a')).filter(link=>link.getAttribute('href')===href);
    assert.equal(links.length,3,'CSYNC, CDS and CDNSKEY independently reference RFC7477');
    const names=links.map(text);
    for(const name of names){
      const find=()=>Array.from(app.querySelectorAll('.dnssec-context-panel a')).find(link=>text(link)===name);
      find().focus();
      for(const index of [app.visibleSteps.length-1,0,app.visibleSteps.length-1]){
        app.selectStep(index,false);
        assert.equal(document.activeElement,find(),'The initiating field source, not another link with the same href, retains focus: '+name);
      }
    }
  }finally{unmount(app);}
});

test('DNS disclosure and comparison keyboard targets survive canonical cursor redraws',()=>{
  const app=mount('lab-dnssec06','both-validate');try{
    const details=app.querySelector('.dnssec-decision-details');details.setAttribute('open','');details.querySelector('summary').focus();
    end(app);assert.ok(app.querySelector('.dnssec-decision-details').hasAttribute('open'));assert.equal(document.activeElement,app.querySelector('.dnssec-decision-details summary'));
    const region=app.querySelector('.dnssec-hop-comparison [tabindex="0"]');assert.equal(region.getAttribute('role'),'region');assert.ok(region.getAttribute('aria-label'));region.focus();
    app.selectStep(app.steps.findIndex(step=>step.id.endsWith(':stub:q')),false);
    assert.equal(document.activeElement,app.querySelector('.dnssec-hop-comparison [tabindex="0"]'));
    assert.ok(app.querySelector('.dnssec-decision-details').hasAttribute('open'),'Comparison focus does not close the independent raw-ID disclosure');
  }finally{unmount(app);}
});


test('retry comparison retains every reached query identity and flag set without inventing responses on rewind',()=>{
  const app=mount('lab-dnssec06','forwarder-loop-or-unreachable');try{
    for(const count of [1,2,3,2,1]){
      const expected=Array.from({length:count},(_,index)=>`lab-dnssec06:forwarder-loop-or-unreachable:attempt-${index+1}:q`);
      const index=app.steps.findIndex(step=>step.id===expected.at(-1));assert.ok(index>=0);app.selectStep(index,false);
      const rows=Array.from(app.querySelectorAll('[data-dnssec-hop-id]')).filter(row=>row.dataset.dnssecHopId.includes(':attempt-'));
      const identities=rows.map(row=>cell(row,'identity')).join(' '),queries=rows.map(row=>cell(row,'query')).join(' ');
      for(const id of expected)assert.ok(identities.includes(id),'Reached actual query event is visible: '+id);
      for(let next=count+1;next<=3;next++)assert.ok(!identities.includes(`attempt-${next}:q`),'Future attempt identity is not visible');
      assert.equal((queries.match(/AD=1\s*\/\s*CD=1\s*\/\s*DO=1/g)||[]).length,count);
      for(const row of rows)assert.doesNotMatch(cell(row,'response'),/NOERROR|SERVFAIL/,'An undelivered attempt has no DNS response RCODE');
    }
  }finally{unmount(app);}
});

test('DNS-R10 alias cache inspector preserves the corrected lifetime across full, field and exact replay',()=>{
  const app=mount('lab-dnssec09','cname-bogus-target'),aliasId='lab-dnssec09:alias-cache',T=1792713600;
  try{
    const boundary=app.steps.findIndex(step=>step.dnssecBoundary==='accepted-use-and-cache-boundary');assert.ok(boundary>=0);
    const check=(required=false)=>{
      const snapshot=app.heldView.snapshot(),alias=snapshot.state.dnssec.namespaceCaches?.find(entry=>entry.id===aliasId);
      const holding=snapshot.holdings.find(item=>item.actorId==='dnsResolver'&&item.artifactId===aliasId);
      if(required)assert.ok(alias,'Completing each replay mode must reach the actual alias cache');
      if(!alias){assert.equal(holding,undefined,'No current alias holding before cache creation');return;}
      assert.ok(holding);
      app.heldView.select(holding);
      const shown=JSON.parse(app.querySelector('#held-inspector pre').textContent);
      assert.equal(shown.id,aliasId);
      assert.equal(shown.securityStatus,'secure');
      assert.equal(shown.receivedAt,T);
      assert.equal(shown.validatedAt,T);
      assert.equal(shown.expiresAt,T+300);
      assert.equal(shown.remainingTtl,300);
      assert.equal(shown.signatureDeadline,T+3600);
      assert.equal(shown.authenticatedProofDeadline,T+3600);
      assert.equal(JSON.stringify(shown),JSON.stringify(alias),'Rendered exact object and canonical state agree at this replay prefix');
      assert.equal(app.protocolSnapshot().state.dnssec.namespaceCaches.find(entry=>entry.id===aliasId).remainingTtl,300);
    };
    for(const index of [boundary-1,boundary,app.steps.length-1,boundary-1,boundary]){app.selectStep(index,false);check(index>=boundary);}
    end(app);
    assert.equal(app.protocolSnapshot().state.dnssec.applicationResult.status,'error');
    app.selectAttribute('dnssec_cache_record',false);
    for(const index of [app.visibleSteps.length-1,0,app.visibleSteps.length-1]){app.selectStep(index,false);check(index===app.visibleSteps.length-1);}
    app.clearAttribute();end(app);
    const holding=app.heldView.snapshot().holdings.find(item=>item.actorId==='dnsResolver'&&item.artifactId===aliasId);assert.ok(holding);
    app.heldView.select(holding);app.querySelector('[data-held-trace]').click();
    assert.equal(app.objectTraceSelection,aliasId);
    for(const index of [app.visibleSteps.length-1,0,app.visibleSteps.length-1]){app.selectStep(index,false);check(index===app.visibleSteps.length-1);}
    app.clearAttribute();app.selectStep(boundary-1,false);check();
  }finally{unmount(app);}
});
