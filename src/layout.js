export const GRAPH_WIDTH = 1120;
export const GRAPH_HEIGHT = 730;
export const POSITIONS = {
  user: {x:125,y:130}, app: {x:170,y:380}, browser: {x:440,y:265},
  realmA: {x:820,y:170}, realmB: {x:965,y:365},
  hello: {x:195,y:605}, yubikey: {x:435,y:605}, totp: {x:625,y:605}
};

// Logical bounds include the largest card at the narrowest supported graph.
// Wider layouts have additional room between cards and their connections.
export const CARD_BOUNDS = {width:164,height:174};
const ROUTE_CLEARANCE = 10;
const HALF_WIDTH = CARD_BOUNDS.width/2;
const HALF_HEIGHT = CARD_BOUNDS.height/2;
const ROUTE_PADDING = 10;
const CORNER_RADIUS = 10;
const PORT_STUB = 14;
const BEND_COST = 22;
const layoutCache = new Map();

export function getPositions(architecture='native') {
  const positions=Object.fromEntries(Object.entries(POSITIONS).map(([id,p])=>[id,{...p}]));
  if(architecture==='web')positions.app={x:820,y:605};
  return positions;
}

function rectangle(id,p,clearance=ROUTE_CLEARANCE) {
  return {id,left:p.x-HALF_WIDTH-clearance,right:p.x+HALF_WIDTH+clearance,
    top:p.y-HALF_HEIGHT-clearance,bottom:p.y+HALF_HEIGHT+clearance};
}

function inRectangle(point,rect) {
  // Perimeter routes remain ten pixels outside the visible card.
  return point.x>rect.left+.001&&point.x<rect.right-.001&&point.y>rect.top+.001&&point.y<rect.bottom-.001;
}

function segmentIsClear(a,b,rectangles) {
  if(Math.abs(a.x-b.x)<.001) {
    const low=Math.min(a.y,b.y),high=Math.max(a.y,b.y);
    return !rectangles.some(r=>a.x>r.left+.001&&a.x<r.right-.001&&high>r.top+.001&&low<r.bottom-.001);
  }
  if(Math.abs(a.y-b.y)<.001) {
    const low=Math.min(a.x,b.x),high=Math.max(a.x,b.x);
    return !rectangles.some(r=>a.y>r.top+.001&&a.y<r.bottom-.001&&high>r.left+.001&&low<r.right-.001);
  }
  return false;
}

function ports(p) {
  const hx=HALF_WIDTH+ROUTE_CLEARANCE,hy=HALF_HEIGHT+ROUTE_CLEARANCE;
  return [
    {x:p.x-hx-PORT_STUB,y:p.y,direction:3,base:{x:p.x-hx,y:p.y}},
    {x:p.x+hx+PORT_STUB,y:p.y,direction:1,base:{x:p.x+hx,y:p.y}},
    {x:p.x,y:p.y-hy-PORT_STUB,direction:4,base:{x:p.x,y:p.y-hy}},
    {x:p.x,y:p.y+hy+PORT_STUB,direction:2,base:{x:p.x,y:p.y+hy}}
  ];
}

function buildVisibilityGraph(positions) {
  const rectangles=Object.entries(positions).map(([id,p])=>rectangle(id,p));
  const xs=[ROUTE_PADDING,GRAPH_WIDTH-ROUTE_PADDING],ys=[ROUTE_PADDING,GRAPH_HEIGHT-ROUTE_PADDING];
  for(const [id,p]of Object.entries(positions)) {
    const r=rectangle(id,p);xs.push(r.left,p.x,r.right);ys.push(r.top,p.y,r.bottom);
    for(const port of ports(p)){xs.push(port.x);ys.push(port.y);}
  }
  const unique=values=>[...new Set(values)].sort((a,b)=>a-b);
  const xValues=unique(xs),yValues=unique(ys),nodes=[],index=new Map();
  for(const y of yValues)for(const x of xValues) {
    const p={x,y};
    if(x<ROUTE_PADDING||x>GRAPH_WIDTH-ROUTE_PADDING||y<ROUTE_PADDING||y>GRAPH_HEIGHT-ROUTE_PADDING||rectangles.some(r=>inRectangle(p,r)))continue;
    index.set(x+','+y,nodes.length);nodes.push({...p,neighbors:[]});
  }
  const link=(a,b,direction)=>{
    if(a===undefined||b===undefined||!segmentIsClear(nodes[a],nodes[b],rectangles))return;
    const distance=Math.abs(nodes[a].x-nodes[b].x)+Math.abs(nodes[a].y-nodes[b].y);
    const forward=direction===1?1:2,reverse=direction===1?3:4;
    nodes[a].neighbors.push({index:b,direction:forward,distance});nodes[b].neighbors.push({index:a,direction:reverse,distance});
  };
  for(const y of yValues) {
    let previous;
    for(const x of xValues){const current=index.get(x+','+y);if(current!==undefined){link(previous,current,1);previous=current;}}
  }
  for(const x of xValues) {
    let previous;
    for(const y of yValues){const current=index.get(x+','+y);if(current!==undefined){link(previous,current,2);previous=current;}}
  }
  return {nodes,index,rectangles,paths:new Map()};
}

function graphFor(positions) {
  const key=Object.entries(positions).map(([id,p])=>id+':'+p.x+','+p.y).sort().join('|');
  if(!layoutCache.has(key)) {
    // Prevent an unbounded cache if a future version offers custom layouts.
    if(layoutCache.size>8)layoutCache.clear();
    layoutCache.set(key,buildVisibilityGraph(positions));
  }
  return layoutCache.get(key);
}

class RouteHeap {
  constructor(){this.items=[];}
  push(value){let i=this.items.length;this.items.push(value);while(i){const p=(i-1)>>1;if(this.items[p].score<=value.score)break;this.items[i]=this.items[p];i=p;}this.items[i]=value;}
  pop(){const first=this.items[0],last=this.items.pop();if(this.items.length){let i=0;while(true){const left=i*2+1,right=left+1;let child=left;if(right<this.items.length&&this.items[right].score<this.items[left].score)child=right;if(child>=this.items.length||this.items[child].score>=last.score)break;this.items[i]=this.items[child];i=child;}this.items[i]=last;}return first;}
  get length(){return this.items.length;}
}

function simplify(points) {
  const result=[];
  for(const p of points) {
    const a=result.at(-2),b=result.at(-1);
    if(b&&b.x===p.x&&b.y===p.y)continue;
    if(a&&b&&((a.x===b.x&&b.x===p.x)||(a.y===b.y&&b.y===p.y)))result.pop();
    result.push({x:p.x,y:p.y});
  }
  return result;
}

function routeBetween(from,to,positions,graph) {
  const {nodes,index}=graph;
  const usable=p=>index.has(p.x+','+p.y)&&segmentIsClear(p.base,p,graph.rectangles);
  const starts=ports(positions[from]).filter(usable);
  const ends=ports(positions[to]).filter(usable);
  if(!starts.length||!ends.length)throw new Error('Actor has no unobstructed graph port: '+from+' / '+to);
  const goalNodes=new Map(ends.map(p=>[index.get(p.x+','+p.y),p]));
  const heuristic=node=>Math.min(...ends.map(p=>Math.abs(p.x-node.x)+Math.abs(p.y-node.y)));
  const costs=new Map(),previous=new Map(),startPorts=new Map(),heap=new RouteHeap();
  for(const p of starts) {
    const node=index.get(p.x+','+p.y),state=node*5+p.direction;
    costs.set(state,0);startPorts.set(state,p);heap.push({state,cost:0,score:heuristic(nodes[node])});
  }
  let found;
  while(heap.length) {
    const current=heap.pop();if(current.cost!==costs.get(current.state))continue;
    const nodeIndex=Math.floor(current.state/5),direction=current.state%5;
    // Appending the final inward stub must not reverse an outward arrival.
    if(goalNodes.has(nodeIndex)&&goalNodes.get(nodeIndex).direction!==direction){found=current.state;break;}
    for(const edge of nodes[nodeIndex].neighbors) {
      const state=edge.index*5+edge.direction;
      const reverses=(direction-edge.direction+4)%4===2;
      if(startPorts.has(current.state)&&!previous.has(current.state)&&reverses)continue;
      const cost=current.cost+edge.distance+(direction!==edge.direction?BEND_COST:0);
      if(cost>=(costs.get(state)??Infinity))continue;
      costs.set(state,cost);previous.set(state,current.state);heap.push({state,cost,score:cost+heuristic(nodes[edge.index])});
    }
  }
  if(found===undefined)throw new Error('No unobstructed graph route: '+from+' / '+to);
  const result=[goalNodes.get(Math.floor(found/5)).base];
  let start;
  for(let state=found;state!==undefined;state=previous.get(state)){result.push(nodes[Math.floor(state/5)]);start=state;}
  result.push(startPorts.get(start).base);
  return simplify(result.reverse());
}

function selfRoute(id,positions,graph) {
  const p=positions[id],own=rectangle(id,p);
  const sides=[
    {vertical:true,base:own.right,sign:1,center:p.y,min:own.top+8,max:own.bottom-8,limit:GRAPH_WIDTH-ROUTE_PADDING},
    {vertical:true,base:own.left,sign:-1,center:p.y,min:own.top+8,max:own.bottom-8,limit:ROUTE_PADDING},
    {vertical:false,base:own.top,sign:-1,center:p.x,min:own.left+8,max:own.right-8,limit:ROUTE_PADDING},
    {vertical:false,base:own.bottom,sign:1,center:p.x,min:own.left+8,max:own.right-8,limit:GRAPH_HEIGHT-ROUTE_PADDING}
  ];
  // The default 60×32 loop needs more space than some perfectly routable
  // moved layouts provide. Fit its depth to the actual free corridor, then
  // try narrower attachment spans and other clear portions of each side.
  for(const span of [60,40,24,16])for(const side of sides) {
    const half=span/2,clamp=n=>Math.max(side.min+half,Math.min(side.max-half,n));
    const centers=[clamp(side.center),side.min+half,side.max-half];
    for(const r of graph.rectangles)if(r.id!==id) {
      const low=side.vertical?r.top:r.left,high=side.vertical?r.bottom:r.right;
      centers.push(clamp(low-half),clamp(high+half));
    }
    for(const center of new Set(centers)) {
      const low=center-half,high=center+half;
      if(low<ROUTE_PADDING||high>(side.vertical?GRAPH_HEIGHT:GRAPH_WIDTH)-ROUTE_PADDING)continue;
      let depth=Math.min(32,(side.limit-side.base)*side.sign);
      for(const r of graph.rectangles)if(r.id!==id) {
        const crossLow=side.vertical?r.top:r.left,crossHigh=side.vertical?r.bottom:r.right;
        if(high<=crossLow+.001||low>=crossHigh-.001)continue;
        const near=side.vertical?r.left:r.top,far=side.vertical?r.right:r.bottom;
        if(side.sign>0&&far>side.base+.001)depth=Math.min(depth,Math.max(0,near-side.base));
        if(side.sign<0&&near<side.base-.001)depth=Math.min(depth,Math.max(0,side.base-far));
      }
      if(depth<2)continue;
      const outer=side.base+side.sign*depth;
      const points=side.vertical?
        [{x:side.base,y:low},{x:outer,y:low},{x:outer,y:high},{x:side.base,y:high}]:
        [{x:low,y:side.base},{x:low,y:outer},{x:high,y:outer},{x:high,y:side.base}];
      if(points.slice(1).every((b,i)=>segmentIsClear(points[i],b,graph.rectangles)))return points;
    }
  }
  throw new Error('No unobstructed self-action loop: '+id);
}

function format(value){return Number(value.toFixed(3));}
function point(p){return format(p.x)+' '+format(p.y);}
function straightSegment(a,b) {
  const c1={x:a.x+(b.x-a.x)/3,y:a.y+(b.y-a.y)/3},c2={x:a.x+(b.x-a.x)*2/3,y:a.y+(b.y-a.y)*2/3};
  return ` C ${point(c1)}, ${point(c2)}, ${point(b)}`;
}

// Cubic commands provide smooth corners and work with native SVG length APIs.
function roundedPath(points) {
  let path='M '+point(points[0]),current=points[0];
  for(let i=1;i<points.length-1;i++) {
    const corner=points[i],next=points[i+1];
    const incoming=Math.abs(corner.x-current.x)+Math.abs(corner.y-current.y),outgoing=Math.abs(next.x-corner.x)+Math.abs(next.y-corner.y);
    const radius=Math.min(CORNER_RADIUS,incoming/2,outgoing/2);
    const start={x:corner.x+(current.x-corner.x)*radius/incoming,y:corner.y+(current.y-corner.y)*radius/incoming};
    const end={x:corner.x+(next.x-corner.x)*radius/outgoing,y:corner.y+(next.y-corner.y)*radius/outgoing};
    path+=straightSegment(current,start)+` C ${point(corner)}, ${point(corner)}, ${point(end)}`;current=end;
  }
  return path+straightSegment(current,points.at(-1));
}

export function connectionPath(from,to,positions=POSITIONS) {
  if(!positions[from]||!positions[to])throw new Error('Unknown graph actor: '+from+' / '+to);
  const graph=graphFor(positions),key=from+'>'+to;
  if(!graph.paths.has(key)) {
    const reverse=graph.paths.get(to+'>'+from);
    const points=reverse&&from!==to?[...reverse].reverse():from===to?selfRoute(from,positions,graph):routeBetween(from,to,positions,graph);
    graph.paths.set(key,points);
  }
  return roundedPath(graph.paths.get(key));
}

// Check a proposed layout without changing its positions or the active UI.
// Focused replay adds local create/check/store operations even when a journey
// contains only transfers, so each visible actor must retain a self route.
export function validateLayoutRoutes(positions,pairs=[]) {
  if(!positions||typeof positions!=='object')return {ok:false,reason:'Invalid graph positions'};
  for(const [id,p]of Object.entries(positions))if(!p||!Number.isFinite(p.x)||!Number.isFinite(p.y))return {ok:false,from:id,to:id,reason:'Invalid graph position: '+id};
  const routes=new Map(Object.keys(positions).map(id=>[id+'>'+id,{from:id,to:id}]));
  try {
    for(const pair of pairs) {
      const [from,to]=typeof pair==='string'?pair.split('>'):Array.isArray(pair)?pair:[pair?.from,pair?.to];
      routes.set(from+'>'+to,{from,to});
    }
    for(const {from,to}of routes.values()) {
      try{connectionPath(from,to,positions);}
      catch(error){return {ok:false,from,to,reason:error.message};}
    }
    return {ok:true};
  }catch(error){return {ok:false,reason:error.message};}
}

export function channelCategory(channel='') {
  const c=channel.toLowerCase();
  if(c.includes('webauthn') || c.includes('ctap')) return 'passkey';
  if(c.includes('back') || c.includes('server')) return 'server';
  if(c.includes('human') || c.includes('user')) return 'human';
  if(c.includes('local') || c.includes('internal') || c.includes('totp') || c.includes('qr')) return 'local';
  return 'browser';
}
