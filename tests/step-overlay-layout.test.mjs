import test from 'node:test';
import assert from 'node:assert/strict';
import {GRAPH_WIDTH,GRAPH_HEIGHT,CARD_BOUNDS,getPositions,connectionPath} from '../src/layout.js';
import {placeStepOverlay} from '../src/step-overlay-layout.js';

// Independently sample the real SVG cubic paths, then emulate 25 points from
// getPointAtLength rather than assuming a particular router's internal shape.
function sampledPath(path) {
  const tokens=path.match(/[MC]|-?\d+(?:\.\d+)?/g);
  let offset=0,current;
  const dense=[];
  assert.equal(tokens[offset++],'M');
  current={x:Number(tokens[offset++]),y:Number(tokens[offset++])};
  dense.push(current);
  while(offset<tokens.length) {
    assert.equal(tokens[offset++],'C');
    const segment=[current];
    for(let n=0;n<3;n++)segment.push({x:Number(tokens[offset++]),y:Number(tokens[offset++])});
    for(let n=1;n<=30;n++) {
      const t=n/30,weights=[(1-t)**3,3*(1-t)**2*t,3*(1-t)*t*t,t**3];
      dense.push({x:segment.reduce((sum,point,i)=>sum+point.x*weights[i],0),
        y:segment.reduce((sum,point,i)=>sum+point.y*weights[i],0)});
    }
    current=segment[3];
  }
  const distances=[0];
  for(let n=1;n<dense.length;n++)distances.push(distances.at(-1)+Math.hypot(dense[n].x-dense[n-1].x,dense[n].y-dense[n-1].y));
  return Array.from({length:25},(_,n)=> {
    const distance=distances.at(-1)*n/24;
    let next=distances.findIndex(value=>value>=distance);
    if(next<=0)return {...dense[0]};
    const fraction=(distance-distances[next-1])/(distances[next]-distances[next-1]||1);
    return {x:dense[next-1].x+(dense[next].x-dense[next-1].x)*fraction,
      y:dense[next-1].y+(dense[next].y-dense[next-1].y)*fraction};
  });
}

function assertBounded(panel,label='panel') {
  assert.ok(Number.isFinite(panel.x)&&Number.isFinite(panel.y),label+' finite coordinates');
  assert.ok(panel.x>=10-1e-7&&panel.y>=10-1e-7,label+' minimum map padding');
  assert.ok(panel.x+panel.width<=GRAPH_WIDTH-10+1e-7&&panel.y+panel.height<=GRAPH_HEIGHT-10+1e-7,label+' maximum map padding');
  assert.ok(Number.isFinite(panel.anchor.x)&&Number.isFinite(panel.anchor.y),label+' finite tether anchor');
}

function assertNoCards(panel,positions,label='panel') {
  for(const [id,position]of Object.entries(positions)) {
    const width=Math.max(0,Math.min(panel.x+panel.width,position.x+CARD_BOUNDS.width/2+8)-
      Math.max(panel.x,position.x-CARD_BOUNDS.width/2-8));
    const height=Math.max(0,Math.min(panel.y+panel.height,position.y+CARD_BOUNDS.height/2+8)-
      Math.max(panel.y,position.y-CARD_BOUNDS.height/2-8));
    assert.ok(width*height<1e-6,label+' overlaps participant '+id+' or its eight-pixel clearance');
  }
}

function assertAnchorOnPath(anchor,points,label='panel') {
  const distance=(a,b)=> {
    const dx=b.x-a.x,dy=b.y-a.y;
    const fraction=Math.max(0,Math.min(1,((anchor.x-a.x)*dx+(anchor.y-a.y)*dy)/(dx*dx+dy*dy||1)));
    return Math.hypot(anchor.x-a.x-dx*fraction,anchor.y-a.y-dy*fraction);
  };
  assert.ok(points.length===1 ? Math.hypot(points[0].x-anchor.x,points[0].y-anchor.y)<1e-7 :
    points.slice(1).some((point,i)=>distance(points[i],point)<1e-7),label+' anchor stays on the sampled route');
}

test('step panels remain bounded and avoid every actor for all real ordered routes in both layouts',()=> {
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    for(const from of Object.keys(positions))for(const to of Object.keys(positions)) {
      const points=sampledPath(connectionPath(from,to,positions));
      for(const size of [{width:220,height:120},{width:280,height:180},{width:200,height:60}]) {
        const label=architecture+' '+from+'→'+to+' '+size.width+'×'+size.height;
        const panel=placeStepOverlay(points,size,positions);
        assertBounded(panel,label);assertNoCards(panel,positions,label);assertAnchorOnPath(panel.anchor,points,label);
        assert.equal(panel.width,size.width);assert.equal(panel.height,size.height);
      }
    }
  }
});

test('reversing a connection preserves placement and its tether location',()=> {
  for(const architecture of ['native','web']) {
    const positions=getPositions(architecture);
    for(const [from,to]of [['app','realmA'],['browser','realmB'],['user','app'],['realmA','realmA']]) {
      const points=sampledPath(connectionPath(from,to,positions));
      const forward=placeStepOverlay(points,{width:280,height:180},positions);
      const reverse=placeStepOverlay([...points].reverse(),{width:280,height:180},positions);
      for(const key of ['x','y','width','height'])assert.ok(Math.abs(forward[key]-reverse[key])<1e-5,key+' is direction-independent');
      assert.ok(Math.hypot(forward.anchor.x-reverse.anchor.x,forward.anchor.y-reverse.anchor.y)<1e-5,'anchor is direction-independent');
    }
  }
});

test('a crowded route falls back to a free region rather than covering participants',()=> {
  const positions={left:{x:260,y:220},middle:{x:450,y:220},right:{x:640,y:220},
    lowerLeft:{x:260,y:410},lowerMiddle:{x:450,y:410},lowerRight:{x:640,y:410}};
  const points=[{x:355,y:180},{x:355,y:450}];
  const panel=placeStepOverlay(points,{width:280,height:180},positions);
  assertBounded(panel);assertNoCards(panel,positions);assertAnchorOnPath(panel.anchor,points);
  assert.ok(panel.x>=730 || panel.y>=505 || panel.x+panel.width<=170,
    'panel moves to an empty canvas region when immediate route space is too small');
});

test('a simple clear connection keeps the panel beside the link and near its middle',()=> {
  const points=[{x:200,y:300},{x:800,y:300}];
  const panel=placeStepOverlay(points,{width:220,height:120},{});
  assertBounded(panel);
  assert.ok(Math.abs(panel.x+panel.width/2-500)<1e-7,'panel is centered on connection midpoint');
  assert.ok(panel.y+panel.height<=300-14 || panel.y>=300+14,'panel keeps the animated connection visible');
});

test('degenerate input and oversize panels have deterministic bounded fallbacks without mutation',()=> {
  const points=[{x:120,y:240}],positions=getPositions('native');
  const before=JSON.stringify({points,positions});
  const panel=placeStepOverlay(points,{width:5000,height:5000},positions);
  assertBounded(panel);assert.equal(panel.width,GRAPH_WIDTH-20);assert.equal(panel.height,GRAPH_HEIGHT-20);
  assertAnchorOnPath(panel.anchor,points);
  assert.equal(JSON.stringify({points,positions}),before);
  const fallback=placeStepOverlay([{x:NaN,y:0}],{},{});
  assertBounded(fallback);assert.deepEqual(fallback.anchor,{x:GRAPH_WIDTH/2,y:GRAPH_HEIGHT/2});
});
