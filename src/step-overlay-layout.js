import {GRAPH_WIDTH,GRAPH_HEIGHT,CARD_BOUNDS} from './layout.js';

const overlayLayoutPadding = 10;
const overlayLayoutCardClearance = 8;
const overlayLayoutLinkClearance = 14;

function overlayLayoutClamp(value,minimum,maximum) {
  return Math.max(minimum,Math.min(maximum,value));
}

function overlayLayoutPointDistance(a,b) {
  return Math.hypot(a.x-b.x,a.y-b.y);
}

function overlayLayoutPathMiddle(points) {
  if(points.length===1)return {...points[0]};
  const lengths=points.slice(1).map((point,i)=>overlayLayoutPointDistance(points[i],point));
  let remaining=lengths.reduce((sum,length)=>sum+length,0)/2;
  for(let i=0;i<lengths.length;i++) {
    if(remaining<=lengths[i]) {
      const fraction=lengths[i] ? remaining/lengths[i] : 0;
      return {x:points[i].x+(points[i+1].x-points[i].x)*fraction,
        y:points[i].y+(points[i+1].y-points[i].y)*fraction};
    }
    remaining-=lengths[i];
  }
  return {...points.at(-1)};
}

function overlayLayoutRectangleDistance(point,rectangle) {
  return Math.hypot(Math.max(rectangle.x-point.x,0,point.x-rectangle.x-rectangle.width),
    Math.max(rectangle.y-point.y,0,point.y-rectangle.y-rectangle.height));
}

function overlayLayoutCollisionArea(rectangle,obstacles) {
  return obstacles.reduce((sum,obstacle)=>sum+
    Math.max(0,Math.min(rectangle.x+rectangle.width,obstacle.right)-Math.max(rectangle.x,obstacle.left))*
    Math.max(0,Math.min(rectangle.y+rectangle.height,obstacle.bottom)-Math.max(rectangle.y,obstacle.top)),0);
}

// Liang-Barsky clipping gives the fraction of each sampled route segment hidden
// by a panel. Prefer an adjacent panel over one that hides moving messages.
function overlayLayoutCoveredLength(a,b,rectangle) {
  const dx=b.x-a.x,dy=b.y-a.y;
  let low=0,high=1;
  const checks=[[-dx,a.x-rectangle.x],[dx,rectangle.x+rectangle.width-a.x],
    [-dy,a.y-rectangle.y],[dy,rectangle.y+rectangle.height-a.y]];
  for(const [direction,distance]of checks) {
    if(Math.abs(direction)<1e-9) {
      if(distance<0)return 0;
      continue;
    }
    const fraction=distance/direction;
    if(direction<0)low=Math.max(low,fraction);
    else high=Math.min(high,fraction);
    if(low>=high)return 0;
  }
  return overlayLayoutPointDistance(a,b)*(high-low);
}

function overlayLayoutAnchor(points,rectangle,middle) {
  const center={x:rectangle.x+rectangle.width/2,y:rectangle.y+rectangle.height/2};
  let best=points[0],bestScore=Infinity;
  const consider=point=> {
    const score=overlayLayoutRectangleDistance(point,rectangle)+overlayLayoutPointDistance(point,middle)*.15;
    // Coordinates break ties consistently when the connection is reversed.
    if(score<bestScore-1e-7 || Math.abs(score-bestScore)<1e-7 &&
      (point.x<best.x-1e-7 || Math.abs(point.x-best.x)<1e-7&&point.y<best.y)) {
      best=point;bestScore=score;
    }
  };
  points.forEach(consider);
  for(let i=1;i<points.length;i++) {
    const a=points[i-1],b=points[i],dx=b.x-a.x,dy=b.y-a.y;
    const fraction=overlayLayoutClamp(((center.x-a.x)*dx+(center.y-a.y)*dy)/(dx*dx+dy*dy||1),0,1);
    consider({x:a.x+dx*fraction,y:a.y+dy*fraction});
  }
  return {...best};
}

/** Place a measured panel beside an active connection in logical graph units. */
export function placeStepOverlay(points,size,positions) {
  const width=overlayLayoutClamp(Number(size?.width)||220,1,GRAPH_WIDTH-overlayLayoutPadding*2);
  const height=overlayLayoutClamp(Number(size?.height)||120,1,GRAPH_HEIGHT-overlayLayoutPadding*2);
  const route=(points||[]).filter(point=>Number.isFinite(point?.x)&&Number.isFinite(point?.y)).map(point=>({x:point.x,y:point.y}));
  if(!route.length)route.push({x:GRAPH_WIDTH/2,y:GRAPH_HEIGHT/2});
  const middle=overlayLayoutPathMiddle(route);
  const obstacles=Object.values(positions||{}).map(position=>({
    left:position.x-CARD_BOUNDS.width/2-overlayLayoutCardClearance,
    right:position.x+CARD_BOUNDS.width/2+overlayLayoutCardClearance,
    top:position.y-CARD_BOUNDS.height/2-overlayLayoutCardClearance,
    bottom:position.y+CARD_BOUNDS.height/2+overlayLayoutCardClearance
  }));
  const candidates=new Map();
  const add=(x,y)=> {
    x=overlayLayoutClamp(x,overlayLayoutPadding,GRAPH_WIDTH-overlayLayoutPadding-width);
    y=overlayLayoutClamp(y,overlayLayoutPadding,GRAPH_HEIGHT-overlayLayoutPadding-height);
    candidates.set(x.toFixed(5)+','+y.toFixed(5),{x,y,width,height});
  };
  // First consider positions next to the route, including its exact midpoint.
  for(const point of [middle,...route]) {
    const left=point.x-width-overlayLayoutLinkClearance,right=point.x+overlayLayoutLinkClearance;
    const above=point.y-height-overlayLayoutLinkClearance,below=point.y+overlayLayoutLinkClearance;
    add(left,point.y-height/2);add(right,point.y-height/2);
    add(point.x-width/2,above);add(point.x-width/2,below);
    for(const x of [left,right])for(const y of [above,below])add(x,y);
  }
  // Actor edges partition all possible panel origins. Their intersections find
  // a free rectangle whenever one exists, even if the middle of the link is busy.
  const xs=[overlayLayoutPadding,GRAPH_WIDTH-overlayLayoutPadding-width,middle.x-width/2];
  const ys=[overlayLayoutPadding,GRAPH_HEIGHT-overlayLayoutPadding-height,middle.y-height/2];
  for(const obstacle of obstacles) {
    xs.push(obstacle.left-width,obstacle.right);
    ys.push(obstacle.top-height,obstacle.bottom);
  }
  for(const x of xs)for(const y of ys)add(x,y);
  let best,bestCollision=Infinity,bestScore=Infinity;
  for(const rectangle of candidates.values()) {
    const collision=overlayLayoutCollisionArea(rectangle,obstacles);
    if(collision>bestCollision+1e-7)continue;
    const anchor=overlayLayoutAnchor(route,rectangle,middle);
    const center={x:rectangle.x+width/2,y:rectangle.y+height/2};
    const inflated={x:rectangle.x-4,y:rectangle.y-4,width:width+8,height:height+8};
    let covered=0;
    for(let i=1;i<route.length;i++)covered+=overlayLayoutCoveredLength(route[i-1],route[i],inflated);
    const score=overlayLayoutRectangleDistance(anchor,rectangle)+
      overlayLayoutPointDistance(anchor,middle)*.16+overlayLayoutPointDistance(center,middle)*.08+
      Math.min(250,covered*.6);
    if(collision<bestCollision-1e-7 || score<bestScore-1e-7 ||
      Math.abs(score-bestScore)<1e-7&&
      (rectangle.x<best.x-1e-7 || Math.abs(rectangle.x-best.x)<1e-7&&rectangle.y<best.y)) {
      best={...rectangle,anchor};bestCollision=collision;bestScore=score;
    }
  }
  return best;
}
