import test from 'node:test';
import assert from 'node:assert/strict';
import {CARD_BOUNDS,GRAPH_WIDTH,GRAPH_HEIGHT,getPositions,connectionPath,validateLayoutRoutes} from '../src/layout.js';

// Independent SVG sampling: no router visibility graph, obstacle predicate,
// route cache or DOM geometry shim is used to decide whether a path is safe.
function sampleRoute(path,positions) {
  const tokens=path.match(/[MC]|-?\d+(?:\.\d+)?/g);
  let offset=0;
  assert.equal(tokens[offset++],'M');
  let start={x:Number(tokens[offset++]),y:Number(tokens[offset++])};
  const points=[start];
  while(offset<tokens.length) {
    assert.equal(tokens[offset++],'C');
    const controls=[start];
    for(let n=0;n<3;n++)controls.push({x:Number(tokens[offset++]),y:Number(tokens[offset++])});
    const length=controls.slice(1).reduce((sum,p,n)=>sum+Math.hypot(p.x-controls[n].x,p.y-controls[n].y),0);
    const count=Math.max(24,Math.ceil(length*2));
    for(let n=0;n<=count;n++) {
      const t=n/count,weights=[(1-t)**3,3*t*(1-t)**2,3*t*t*(1-t),t**3];
      const p={x:controls.reduce((sum,v,i)=>sum+v.x*weights[i],0),y:controls.reduce((sum,v,i)=>sum+v.y*weights[i],0)};
      assert.ok(Number.isFinite(p.x)&&Number.isFinite(p.y),'route coordinates remain finite');
      assert.ok(p.x>=0&&p.x<=GRAPH_WIDTH&&p.y>=0&&p.y<=GRAPH_HEIGHT,'route stays on the map');
      for(const [id,center]of Object.entries(positions)) {
        const inside=Math.abs(p.x-center.x)<CARD_BOUNDS.width/2&&Math.abs(p.y-center.y)<CARD_BOUNDS.height/2;
        assert.equal(inside,false,'route enters '+id+' at '+p.x+','+p.y);
      }
      points.push(p);
    }
    start=controls[3];
  }
  return points;
}

test('F01: the accepted moved web layout retains a visible, clear TOTP self-action loop',()=>{
  const positions=getPositions('web');positions.user={x:634,y:399};
  const original=structuredClone(positions);
  const points=sampleRoute(connectionPath('totp','totp',positions),positions);
  const xmin=Math.min(...points.map(p=>p.x)),xmax=Math.max(...points.map(p=>p.x));
  const ymin=Math.min(...points.map(p=>p.y)),ymax=Math.max(...points.map(p=>p.y));
  assert.ok((xmax-xmin)*(ymax-ymin)>100,'the local action uses a real loop rather than a zero-length line');
  assert.deepEqual(positions,original,'building an adaptive loop does not alter actor positions');
});

test('F01: all ordered routes remain clear after moving the user into the reported location',()=>{
  const positions=getPositions('web');positions.user={x:634,y:399};
  const pairs=Object.keys(positions).flatMap(from=>Object.keys(positions).map(to=>({from,to})));
  assert.deepEqual(validateLayoutRoutes(positions,pairs),{ok:true});
  for(const {from,to}of pairs)sampleRoute(connectionPath(from,to,positions),positions);
});

test('adaptive local loops remain routable at all movement clamp corners',()=>{
  const hx=CARD_BOUNDS.width/2+24,hy=CARD_BOUNDS.height/2+24;
  for(const x of [hx,GRAPH_WIDTH-hx])for(const y of [hy,GRAPH_HEIGHT-hy]) {
    const positions={actor:{x,y}};
    assert.deepEqual(validateLayoutRoutes(positions),{ok:true});
    sampleRoute(connectionPath('actor','actor',positions),positions);
  }
});

test('candidate validation checks local operations even when no journey contains self-transfers',()=>{
  const positions={actor:{x:500,y:350},left:{x:316,y:350},right:{x:684,y:350},top:{x:500,y:156},bottom:{x:500,y:544}};
  const before=structuredClone(positions);
  const result=validateLayoutRoutes(positions);
  assert.equal(result.ok,false);
  assert.equal(result.from,'actor');assert.equal(result.to,'actor');
  assert.match(result.reason,/No unobstructed self-action loop/);
  assert.deepEqual(positions,before,'an unavailable local route leaves the candidate unchanged');
});

test('candidate validation rejects an unroutable transfer without mutation or an escaping exception',()=>{
  // Visible cards do not overlap, but all four 14-unit connection-port stubs
  // of the middle participant are blocked by its surrounding participants.
  const positions={app:{x:400,y:400},left:{x:210,y:400},right:{x:590,y:400},top:{x:400,y:200},bottom:{x:400,y:600}};
  const before=structuredClone(positions);
  const result=validateLayoutRoutes(positions,[{from:'app',to:'left'}]);
  assert.equal(result.ok,false);assert.equal(result.from,'app');assert.equal(result.to,'left');
  assert.match(result.reason,/unobstructed graph port|unobstructed graph route/);
  assert.deepEqual(positions,before);
});

test('candidate validation reports malformed route inputs and supports every documented pair representation',()=>{
  const positions={first:{x:200,y:200},second:{x:700,y:450}};
  for(const pair of [{from:'first',to:'second'},['first','second'],'first>second'])assert.deepEqual(validateLayoutRoutes(positions,[pair]),{ok:true});
  assert.equal(validateLayoutRoutes(positions,[{from:'first',to:'missing'}]).ok,false);
  assert.equal(validateLayoutRoutes({actor:{x:NaN,y:100}}).ok,false);
  assert.equal(validateLayoutRoutes(null).ok,false);
  assert.equal(validateLayoutRoutes(positions,null).ok,false);
});
