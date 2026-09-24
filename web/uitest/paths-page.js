var window = this;
window.addEventListener = function(){};
var FAILURE = null;
function fail(e){ FAILURE = e; }
function mkEl(){ var o = { innerHTML:'', style:{}, hidden:true, onclick:null, value:'', dataset:{},
  addEventListener:function(){}, appendChild:function(){}, setAttribute:function(){},
  getBoundingClientRect:function(){ return {left:0,top:0,width:100,height:50,bottom:0}; },
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, parentNode:null };
  return o; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#paths' };
var setTimeout = function(){};
load('web/static/lib.js');

// Projection must put the equator and prime meridian in the middle.
var mid = FS.project(0, 0, 720, 360);
if (Math.abs(mid[0] - 360) > 0.001 || Math.abs(mid[1] - 180) > 0.001) throw new Error('projection centre wrong: ' + mid);
var tl = FS.project(90, -180, 720, 360);
if (tl[0] !== 0 || tl[1] !== 0) throw new Error('north-west corner wrong: ' + tl);
print('FS.project OK');

var GRAPH = { nodes: [
  { id:'h1', index:1, ips:['192.168.1.254'], located:false, silent:false },
  { id:'h2', index:2, ips:['172.11.154.1'], located:true, lat:39.18, lon:-96.57, country:'US', city:'Manhattan', region:'Kansas', rtt_ms:3.4 },
  { id:'h3', index:3, ips:['32.130.107.216','32.130.107.218'], located:true, lat:32.78, lon:-96.80, country:'US', city:'Dallas', rtt_ms:16.7 },
  { id:'h4', index:4, ips:['1.1.1.1'], located:true, lat:-33.86, lon:151.20, country:'AU', city:'Sydney', rtt_ms:18.9 },
  { id:'s5', index:5, ips:[], located:false, silent:true } ],
  legs: [
    { from:'h2', to:'h3', destinations:['1.1.1.1','8.8.8.8'], shared:true },
    { from:'h3', to:'h4', destinations:['1.1.1.1'], shared:false } ] };
var DESTS = { destinations: [ { dst:'1.1.1.1', name:'one.one.one.one', country:'AU', city:'Sydney', hops:6, answered:5, complete:1, ts:1790200000 } ] };
var STATUS = { active:true, last_run:1790200000, destinations:2, hops:11, error:'' };

FS.get = function(p){
  if (p.indexOf('/api/paths/status') === 0) return Promise.resolve(STATUS);
  if (p.indexOf('/api/paths/graph') === 0) return Promise.resolve(GRAPH);
  if (p.indexOf('/api/paths/destinations') === 0) return Promise.resolve(DESTS);
  return Promise.resolve({});
};
load('web/static/pages3.js');

var el = mkEl();
FS.pages.paths.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  ['Where the traffic goes', 'one.one.one.one', 'Manhattan', 'pathmap'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('page missing ' + s);
  });
  // A shared leg must be drawn once, thicker, and in the neutral colour.
  if (h.indexOf('class="leg shared"') < 0) throw new Error('shared legs are not marked');
  if (h.indexOf('stroke="var(--muted)"') < 0) throw new Error('a shared leg must not take one destination\'s colour');
  // The unlocated hop must be listed, not placed at zero.
  if (h.indexOf('192.168.1.254') < 0) throw new Error('an unplaced hop must still be listed');
  if (h.indexOf('Not on the map') < 0) throw new Error('unplaced hops need their own section');
  // Silent hops are counted, never drawn.
  if (h.indexOf('never answered') < 0) throw new Error('silent hops should be counted');
  // Two addresses at one hop is one circle, not two.
  var circles = (h.match(/class="hop"/g) || []).length;
  if (circles !== 3) throw new Error('want 3 plotted hops (one per located node), got ' + circles);
  print('Paths page renders the map, shared legs, unplaced hops and the destination list');
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
