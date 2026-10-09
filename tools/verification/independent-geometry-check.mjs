#!/usr/bin/env node
/** Offline route geometry checks, explicitly not native browser layout checks. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv.includes('--help')||process.argv.includes('-h')){console.log('Usage: node tools/verification/independent-geometry-check.mjs [project-directory]\nDefaults to this repository. Evidence: docs/verification, or AUTH_LAB_QA_EVIDENCE_DIR.\nOffline logical geometry checks; not native browser validation.');process.exit(0);}
const project=path.resolve(process.argv[2]||path.join(here,'../..'));
const evidenceDir=path.resolve(process.env.AUTH_LAB_QA_EVIDENCE_DIR||path.join(project,'docs/verification'));fs.mkdirSync(evidenceDir,{recursive:true});
const imp=file=>import(pathToFileURL(path.join(project,file)).href);
const {installHarness}=await imp('tests/dom-harness.mjs');
const harness=installHarness();
const {AuthFlowStudio}=await imp('src/app.js');
const {LAB_SCENARIOS}=await imp('src/lab-catalog.js');
const {LEARNING_PRESETS}=await imp('src/learning-presets.js');
const {CARD_BOUNDS,GRAPH_WIDTH,GRAPH_HEIGHT}=await imp('src/layout.js');
const report={kind:'offline-independent-route-sampling',nativeBrowser:false,timestamp:new Date().toISOString(),project,scenarios:[],failures:[]};
const app=new AuthFlowStudio();harness.document.body.appendChild(app);app.connectedCallback();

function cubicSegments(value){
  const t=value.match(/[MC]|-?\d+(?:\.\d+)?/g);let n=0,p;const out=[];
  assert.equal(t[n++],'M');p={x:Number(t[n++]),y:Number(t[n++])};
  while(n<t.length){assert.equal(t[n++],'C');const s=[p];for(let i=0;i<3;i++)s.push({x:Number(t[n++]),y:Number(t[n++])});out.push(s);p=s[3];}
  return out;
}
function point(s,t){const w=[(1-t)**3,3*(1-t)**2*t,3*(1-t)*t*t,t**3];return {x:s.reduce((v,p,i)=>v+p.x*w[i],0),y:s.reduce((v,p,i)=>v+p.y*w[i],0)};}

try{
  for(const id of [...new Set([...LEARNING_PRESETS.map(p=>p.id),'core',...LAB_SCENARIOS.map(s=>s.id)])]){
    try{
      app.selectLabScenario(id);
      const views=Object.values(app.scenarioOwnedActors||{}).some(actor=>actor.parentId)?[false,true]:[false];
      for(const expanded of views){
      const stateBefore=app.protocolSnapshot?.()?.state;
      app.showInternals=expanded;if(expanded)app.renderAll();
      assert.deepEqual(app.protocolSnapshot?.()?.state,stateBefore,id+' component expansion preserves protocol state');
      const positions=app.positions;
      for(const [actor,p]of Object.entries(positions)){
        assert.ok(Number.isFinite(p.x)&&Number.isFinite(p.y),id+' finite position '+actor);
        assert.ok(p.x>=CARD_BOUNDS.width/2&&p.x<=GRAPH_WIDTH-CARD_BOUNDS.width/2,id+' horizontal bounds '+actor);
        assert.ok(p.y>=CARD_BOUNDS.height/2&&p.y<=GRAPH_HEIGHT-CARD_BOUNDS.height/2,id+' vertical bounds '+actor);
      }
      const cards=Object.entries(positions);
      for(let a=0;a<cards.length;a++)for(let b=a+1;b<cards.length;b++)assert.ok(Math.abs(cards[a][1].x-cards[b][1].x)>=CARD_BOUNDS.width||Math.abs(cards[a][1].y-cards[b][1].y)>=CARD_BOUNDS.height,id+' '+cards[a][0]+' / '+cards[b][0]+' card overlap');
      let routeCount=0,sampleCount=0;
      for(const line of app.refs.connections.querySelectorAll('.connection-line')){
        routeCount++;
        for(const segment of cubicSegments(line.getAttribute('d'))){
          const hull=segment.slice(1).reduce((s,p,i)=>s+Math.hypot(p.x-segment[i].x,p.y-segment[i].y),0);
          const count=Math.max(20,Math.ceil(hull*2));
          for(let n=0;n<=count;n++){
            sampleCount++;const p=point(segment,n/count);
            for(const [actor,center]of Object.entries(positions))assert.ok(!(Math.abs(p.x-center.x)<CARD_BOUNDS.width/2-.01&&Math.abs(p.y-center.y)<CARD_BOUNDS.height/2-.01),id+' '+line.parentElement.dataset.pair+' intersects '+actor);
          }
        }
      }
      assert.ok(routeCount>0,id+' has rendered routes');
      report.scenarios.push({id,expanded,steps:app.steps.length,actors:Object.keys(positions).length,routeCount,sampleCount});
      }
    }catch(error){report.failures.push({id,error:String(error.stack||error)});}
  }
}finally{app.disconnectedCallback();harness.document.body.removeChild(app);harness.clock.frames.clear();harness.clock.timers.clear();}
report.passed=report.failures.length===0;fs.writeFileSync(path.join(evidenceDir,'independent-geometry-status.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({passed:report.passed,scenarioCount:report.scenarios.length,samples:report.scenarios.reduce((n,s)=>n+s.sampleCount,0),failures:report.failures.map(f=>({id:f.id,error:f.error.split('\n')[0]}))},null,2));if(!report.passed)process.exitCode=1;
