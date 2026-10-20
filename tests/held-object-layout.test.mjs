import test from 'node:test';
import assert from 'node:assert/strict';
import { fullDockGeometry, compactDockGeometry } from '../src/held-object-view.js';
import { visibleActorId } from '../src/workspaces.js';
import { ADLAB_SCENARIOS } from '../src/kerberos-ad-lab.js';
import { CRYPTOLAB_SCENARIOS } from '../src/kerberos-crypto-lab.js';
import { FORESTLAB_SCENARIOS } from '../src/kerberos-forest-lab.js';
import { SSHLAB_SCENARIOS } from '../src/ssh-access-lab.js';

const models=[...ADLAB_SCENARIOS,...CRYPTOLAB_SCENARIOS,...FORESTLAB_SCENARIOS,...SSHLAB_SCENARIOS];
const model=id=>models.find(item=>item.id===id);
function composition(source,expanded=false){
  const actors=source.actors(),steps=source.steps(),physical=id=>visibleActorId(id,actors,expanded);
  const participants=new Set(steps.flatMap(step=>[step.from,step.to,...(step.attributeOperations||[]).map(op=>op.actorId)]).map(physical));
  const ids=[...new Set(Object.keys(actors).map(physical))].filter(id=>participants.has(id));
  const anchors=Object.fromEntries(ids.map(id=>[id,source.positions[id]||actors[id].position]));
  const pairs=steps.map(step=>[physical(step.from),physical(step.to)]);
  return {ids,anchors,pairs,geometry:fullDockGeometry(ids,ids,pairs,1120,730,{},anchors)};
}
function assertClear(geometry){
  const bounds=Object.values(geometry.bounds);
  for(const b of bounds){
    assert.equal(b.right-b.left,316);assert.equal(b.bottom-b.top,174);
    assert.ok(b.left>=22&&b.right<=1098&&b.top>=22&&b.bottom<=708,'complete composite stays inside the frame');
  }
  for(let i=0;i<bounds.length;i++)for(let j=i+1;j<bounds.length;j++){
    const a=bounds[i],b=bounds[j];
    assert.ok(a.right+20<=b.left||b.right+20<=a.left||a.bottom+20<=b.top||b.bottom+20<=a.top,'composites retain their route clearance');
  }
  for(const [key,path] of geometry.routes){
    const points=[...path.matchAll(/[ML] ([\d.-]+) ([\d.-]+)/g)].map(match=>({x:Number(match[1]),y:Number(match[2])}));
    assert.ok(points.length>=2,key);
    for(let i=1;i<points.length;i++)assert.ok(points[i].x===points[i-1].x||points[i].y===points[i-1].y,key+' is orthogonal');
    for(let i=1;i<points.length-2;i++){
      const a=points[i],b=points[i+1];
      for(const r of bounds){
        const crosses=a.x===b.x?a.x>r.left&&a.x<r.right&&Math.max(a.y,b.y)>r.top&&Math.min(a.y,b.y)<r.bottom:a.y>r.top&&a.y<r.bottom&&Math.max(a.x,b.x)>r.left&&Math.min(a.x,b.x)<r.right;
        assert.equal(crosses,false,key+' does not cross an inventory');
      }
    }
  }
}

test('collapsed AD, FAST, forests and all SSH architectures retain full physical inventories',()=>{
  for(const source of models){
    const {ids,geometry}=composition(source);
    assert.ok(geometry,source.id+' fits full desktop mode');
    assert.deepEqual(Object.keys(geometry.bounds).sort(),[...ids].sort(),source.id+' reserves precisely the physical actors');
    assertClear(geometry);
    if(geometry.positions.cryptoClient&&geometry.positions.cryptoKdc)assert.ok(geometry.positions.cryptoClient.x<geometry.positions.cryptoKdc.x,source.id+' retains the FAST client/KDC columns even without a leftmost actor');
  }
});

test('AD first sign-in retains its authored three-column topology and adjacent service row',()=>{
  const {geometry}=composition(model('lab-ad-first-sign-in')),p=geometry.positions;
  assert.ok(p.adUser.x<p.adWorkstation.x&&p.adWorkstation.x<p.adKdc.x);
  assert.equal(p.adUser.y,p.adWorkstation.y);assert.equal(p.adKdc.y,p.adWorkstation.y);
  assert.equal(p.adService.x,p.adWorkstation.x);
  assert.equal(p.adService.y-p.adWorkstation.y,240,'service is not stranded below a redundant logical KDC row');
  assert.equal(geometry.bounds.adAs,undefined);assert.equal(geometry.bounds.adTgs,undefined);
});

test('collapsed logical aliases do not consume cells, while cursor-hidden physical actors do',()=>{
  const ids=['cli','agent','browser','idp'],anchors={cli:{x:145,y:365},agent:{x:145,y:610},browser:{x:560,y:120},idp:{x:975,y:120}};
  const collapsed=fullDockGeometry(ids,['cli','browser','idp'],[['cli','browser']],1120,730,{agent:'cli'},anchors);
  const physical=fullDockGeometry(['cli','browser','idp'],['cli','browser','idp'],[['cli','browser']],1120,730,{},anchors);
  assert.deepEqual(collapsed.bounds,physical.bounds);assert.deepEqual(collapsed.positions,physical.positions);
  const hidden=fullDockGeometry(['cli','browser','idp'],['cli','browser'],[['cli','browser']],1120,730,{},anchors);
  assert.deepEqual(hidden.bounds,physical.bounds);assert.deepEqual(hidden.positions.cli,physical.positions.cli);
  assert.deepEqual(hidden.positions.browser,physical.positions.browser);
  const expanded=fullDockGeometry(ids,ids,[['cli','agent'],['cli','browser']],1120,730,{},anchors);
  assert.ok(expanded);assert.ok(expanded.bounds.agent);assert.ok(expanded.positions.cli.y<expanded.positions.agent.y);
});

test('SSH enrollment, remote Device client and GSS keep their distinct authored composition',()=>{
  for(const id of ['lab-ssh-cert-success','lab-ssh-sssd-success','lab-ssh-gss-success']){
    const source=model(id);assert.ok(source,id);
    for(const expanded of [false,true]){
      const {geometry}=composition(source,expanded);assert.ok(geometry,id+' internals='+expanded);
      const p=geometry.positions;if(p.user)assert.ok(p.user.y<p.sshCli.y,id+' keeps participating person above workstation');
      assertClear(geometry);
      if(p.browser&&p.sshIdp){assert.ok(p.sshCli.x<p.browser.x&&p.browser.x<p.sshIdp.x);}
      if(p.sshCa){assert.equal(p.sshCa.x,p.sshIdp.x);assert.ok(p.sshIdp.y<p.sshCa.y);}
      if(expanded&&p.sshAgent){assert.equal(p.sshAgent.x,p.sshCli.x);assert.ok(p.sshCli.y<p.sshAgent.y);}
      if(expanded&&p.pam&&p.sssd){assert.equal(p.pam.x,p.sssd.x);assert.ok(p.pam.y<p.sssd.y);}
      if(p.kdc){assert.equal(p.kdc.y,p.sshCli.y);assert.equal(p.sshHost.y,p.sshCli.y);assert.ok(p.sshCli.x<p.kdc.x&&p.kdc.x<p.sshHost.x);assert.equal(geometry.bounds.user,undefined,'cache-only GSS does not reserve an unused human cell');assert.equal(p.sshCli.y,365,'active GSS peers are centered in the map');}
    }
  }
});

test('compact and external choices keep physical topology without shrinking final controls',()=>{
  const {anchors,pairs}=composition(model('lab-ad-first-sign-in'));
  const compact=compactDockGeometry(anchors,pairs,960);
  assert.ok(compact);assert.equal(compact.mode,'compact');assert.deepEqual(compact.positions,anchors);
  assert.equal(compactDockGeometry(anchors,pairs,959),null,'smaller viewport requires external inventories');
  assert.equal(fullDockGeometry(Object.keys(anchors),Object.keys(anchors),pairs,1119,730,{},anchors),null);
  const crowded={...anchors,logicalDuplicate:{...anchors.adKdc}};
  assert.equal(compactDockGeometry(crowded,pairs,960),null,'unsafe expanded physical overlaps use external inventories');
});

test('Paper E dense forest and SSH grids preserve their declared cells through expansion',()=>{
  const forestCells={user:{x:104,y:125},workstation:{x:104,y:365},kdcHome:{x:484,y:125},kdcRootA:{x:864,y:125},kdcRootB:{x:864,y:365},kdcResource:{x:864,y:605},service:{x:484,y:605}};
  for(const expanded of [false,true]){
    const {geometry}=composition(model('lab-ad-forest-child-domains'),expanded);assert.ok(geometry);
    for(const [id,point]of Object.entries(forestCells)){
      const visible=expanded&&id.startsWith('kdc')?id+'Tgs':id;
      assert.deepEqual(geometry.positions[visible],point,visible+' occupies the declared physical DC cell');
      if(visible!==id)assert.equal(geometry.positions[id],undefined,'no duplicate ancestor card');
    }
    assertClear(geometry);
  }
  const source=model('lab-ssh-cert-success'),folded=composition(source).geometry,expanded=composition(source,true).geometry;
  for(const [id,point]of Object.entries(folded.positions))assert.deepEqual(expanded.positions[id],point,id+' does not move when the agent is revealed');
  assert.deepEqual(folded.positions.sshCli,{x:104,y:365});assert.deepEqual(expanded.positions.sshAgent,{x:104,y:605});
  assert.equal(folded.positions.sshAgent,undefined,'the reserved agent cell is vacant when folded');
});

test('same-row AD exchanges use the available interior row corridor rather than the frame edge',()=>{
  const {geometry}=composition(model('lab-ad-first-sign-in')),upper=geometry.bounds.adWorkstation,lower=geometry.bounds.adService;
  const path=geometry.routes.get('adUser>adWorkstation');
  assert.ok(path,'the human/workstation exchange exists');
  const points=[...path.matchAll(/[ML] ([\d.-]+) ([\d.-]+)/g)].map(match=>({x:Number(match[1]),y:Number(match[2])}));
  assert.ok(points.some((point,index)=>index&&point.y===points[index-1].y&&point.x!==points[index-1].x&&point.y>upper.bottom&&point.y<lower.top),'the visible exchange travels between the actor rows');
  assertClear(geometry);
});

test('local routes reserve a painted activity lane clear of actor focus and composite frames',()=>{
  for(const source of models){
    const {geometry}=composition(source);assert.ok(geometry,source.id);
    for(const [key,path]of geometry.routes){
      const [from,to]=key.split('>');if(from!==to)continue;
      const b=geometry.bounds[from],points=[...path.matchAll(/[ML] ([\d.-]+) ([\d.-]+)/g)].map(match=>({x:Number(match[1]),y:Number(match[2])}));
      const first=points[0],last=points.at(-1),lane=points[1].y;
      assert.ok(first.y===b.top||first.y===b.bottom,key+' attaches to a card edge');
      assert.equal(last.y,first.y,key+' returns to the same edge');
      assert.ok(first.x>=b.left&&first.x<=b.left+164&&last.x>=b.left&&last.x<=b.left+164,key+' avoids the adjacent inventory');
      assert.ok(lane<=b.top-24||lane>=b.bottom+24,key+' clears the focus/frame paint');
      const marker={x:(first.x+last.x)/2,y:lane};
      assert.ok(marker.x>=6&&marker.x<=1114&&marker.y>=6&&marker.y<=724,key+' keeps a bounded local marker inside the graph');
    }
    assertClear(geometry);
  }
  const compact=compactDockGeometry({actor:{x:104,y:120}},[['actor','actor']],960);
  assert.ok(compact);const points=[...compact.routes.get('actor>actor').matchAll(/[ML] ([\d.-]+) ([\d.-]+)/g)].map(match=>({x:Number(match[1]),y:Number(match[2])}));
  assert.ok(points[1].y>=compact.bounds.actor.bottom+24,'a tight top margin selects the clear bottom lane');
});
