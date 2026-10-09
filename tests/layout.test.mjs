import test from 'node:test';
import assert from 'node:assert/strict';
import {GRAPH_WIDTH,GRAPH_HEIGHT,CARD_BOUNDS,POSITIONS,getPositions,connectionPath} from '../src/layout.js';
import {FLOWS} from '../src/protocol-data.js';

// Parse and sample independently of the router and the app's DOM harness.
// The conservative logical box corresponds to a 125×130 card on an 860px map.
const physicalBounds={width:164,height:174};
function cubicPath(path) {
  const tokens=path.match(/[MC]|-?\d+(?:\.\d+)?/g);
  let offset=0,current,segments=[];
  assert.equal(tokens[offset++],'M');
  current={x:Number(tokens[offset++]),y:Number(tokens[offset++])};
  while(offset<tokens.length) {
    assert.equal(tokens[offset++],'C');
    const points=[current];
    for(let i=0;i<3;i++)points.push({x:Number(tokens[offset++]),y:Number(tokens[offset++])});
    segments.push(points);current=points[3];
  }
  return segments;
}
function sample(points,t) {
  const weights=[(1-t)**3,3*(1-t)**2*t,3*(1-t)*t*t,t**3];
  return {x:points.reduce((sum,p,i)=>sum+p.x*weights[i],0),y:points.reduce((sum,p,i)=>sum+p.y*weights[i],0)};
}
function isInside(point,center) {
  return Math.abs(point.x-center.x)<physicalBounds.width/2&&Math.abs(point.y-center.y)<physicalBounds.height/2;
}
function assertClear(path,positions,label) {
  const segments=cubicPath(path);
  assert.ok(segments.length>0&&segments.length<40,label+' bounded route complexity');
  for(const segment of segments) {
    const hullLength=segment.slice(1).reduce((sum,p,i)=>sum+Math.hypot(p.x-segment[i].x,p.y-segment[i].y),0);
    const count=Math.max(10,Math.ceil(hullLength*2));
    for(let n=0;n<=count;n++) {
      const point=sample(segment,n/count);
      assert.ok(Number.isFinite(point.x)&&Number.isFinite(point.y),label+' finite path');
      assert.ok(point.x>=0&&point.x<=GRAPH_WIDTH&&point.y>=0&&point.y<=GRAPH_HEIGHT,label+' fits map');
      for(const [id,center]of Object.entries(positions))assert.equal(isInside(point,center),false,label+' crosses '+id+' at '+point.x+','+point.y);
    }
  }
  return segments;
}

test('native and network application layouts preserve the device and server positions',()=>{
  const native=getPositions('native'),web=getPositions('web');
  assert.deepEqual(native,POSITIONS);assert.deepEqual(web.app,{x:820,y:605});
  for(const id of Object.keys(POSITIONS).filter(id=>id!=='app'))assert.deepEqual(web[id],native[id]);
  native.app.x=0;assert.equal(POSITIONS.app.x,170,'callers cannot mutate the shared default');
  assert.ok(CARD_BOUNDS.width>=physicalBounds.width&&CARD_BOUNDS.height>=physicalBounds.height);
});

test('every ordered actor connection, including self-actions, avoids every card in both architectures',()=>{
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    for(const from of Object.keys(positions))for(const to of Object.keys(positions)) {
      assertClear(connectionPath(from,to,positions),positions,architecture+' '+from+'→'+to);
    }
  }
});

test('connections leave and enter each participant normal to its side, so arrows point toward the actor',()=>{
  const normal=(port,center)=>Math.abs(port.x-center.x)>physicalBounds.width/2?{x:Math.sign(port.x-center.x),y:0}:{x:0,y:Math.sign(port.y-center.y)};
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    for(const from of Object.keys(positions))for(const to of Object.keys(positions)) {
      const segments=cubicPath(connectionPath(from,to,positions));
      const first=segments[0],last=segments.at(-1),out=normal(first[0],positions[from]),inside=normal(last[3],positions[to]);
      const start={x:first[1].x-first[0].x,y:first[1].y-first[0].y},end={x:last[3].x-last[2].x,y:last[3].y-last[2].y};
      const label=architecture+' '+from+'→'+to;
      assert.ok(start.x*out.x+start.y*out.y>0,label+' outward start');
      assert.ok(end.x*inside.x+end.y*inside.y<0,label+' inward end');
      assert.ok(Math.abs(start.x*out.y-start.y*out.x)<.002,label+' perpendicular start');
      assert.ok(Math.abs(end.x*inside.y-end.y*inside.x)<.002,label+' perpendicular end');
    }
  }
});

test('every protocol exchange uses clear routes for either passkey authenticator and architecture',()=>{
  const pairs=new Set(['user>browser','browser>app','app>browser','app>realmA','realmA>app']);
  for(const steps of Object.values(FLOWS))for(const step of steps)for(const authenticator of ['hello','yubikey']) {
    const resolve=id=>id==='authenticator'?authenticator:id;
    pairs.add(resolve(step.from)+'>'+resolve(step.to));
  }
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    for(const pair of pairs){const [from,to]=pair.split('>');assertClear(connectionPath(from,to,positions),positions,architecture+' '+pair);}
  }
});

test('opposite directions share geometry and unknown actors fail explicitly',()=>{
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    const forward=cubicPath(connectionPath('app','realmA',positions)),backward=cubicPath(connectionPath('realmA','app',positions));
    assert.deepEqual(forward[0][0],backward.at(-1)[3]);assert.deepEqual(forward.at(-1)[3],backward[0][0]);
    const a=sample(forward[Math.floor(forward.length/2)],.5),b=sample(backward[Math.floor(backward.length/2)],.5);
    assert.ok(Math.abs(a.x-b.x)<.002&&Math.abs(a.y-b.y)<.002);
  }
  assert.throws(()=>connectionPath('missing','app'),/Unknown graph actor/);
});
