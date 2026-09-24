var window = this;
window.addEventListener = function(){};
var FAILURE = null;
function fail(e){ FAILURE = e; }
var navigator = { geolocation: { getCurrentPosition: function(){} } };
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
  { id:'h4', index:4, ips:['1.1.1.1'], located:true, lat:-33.86, lon:151.20, country:'AU', city:'Sydney', rtt_ms:18.9,
    impossible:true, distance_km:14071, floor_ms:140.7, why:'answers in 18.9 ms, but 14071 km away cannot answer in less than 141 ms' },
  { id:'s5', index:5, ips:[], located:false, silent:true } ],
  legs: [
    { from:'h2', to:'h3', destinations:['1.1.1.1','8.8.8.8'], shared:true },
    { from:'h3', to:'h4', destinations:['1.1.1.1'], shared:false, straight_km:13500,
      cables:[{ name:'Southern Cross NEXT', km:13700, floor_ms:137 }] } ] };
var DESTS = { destinations: [ { dst:'1.1.1.1', name:'one.one.one.one', country:'AU', city:'Sydney', hops:6, answered:5, complete:1, ts:1790200000 } ] };
var DEVS = { devices: [
  { key:'192.168.1.119', name:'MacBookPro', addresses:['192.168.1.119','2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6'], destinations:9 },
  { key:'192.168.2.188', name:'roku-ultra', addresses:['192.168.2.188'], destinations:2 } ] };
var HOME = { ok:true, lat:39.1836, lon:-96.5717, source:'public address', configured:'',
  public_address:'162.202.41.52',
  detected:{ lat:39.1836, lon:-96.5717, city:'Manhattan', region:'Kansas', country:'US' },
  note:'Declaring this matters more than it looks.' };
var CAB = { cables: [
  { name:'Grace Hopper', km:6900, runs:[[[-70.0,40.7],[-30.0,45.0],[-5.0,50.1]]] },
  // A run that wraps the antimeridian; it must break, not stripe the map.
  { name:'Pacific Light', km:12800, runs:[[[170.0,20.0],[179.0,21.0],[-179.0,21.5],[-150.0,22.0]]] } ],
  attribution:"Submarine cable routes from TeleGeography's public cable map." };
var STATUS = { active:true, last_run:1790200000, destinations:2, hops:11, error:'' };

FS.get = function(p){
  if (p.indexOf('/api/paths/status') === 0) return Promise.resolve(STATUS);
  if (p.indexOf('/api/paths/graph') === 0) return Promise.resolve(GRAPH);
  if (p.indexOf('/api/paths/destinations') === 0) return Promise.resolve(DESTS);
  if (p.indexOf('/api/paths/devices') === 0) return Promise.resolve(DEVS);
  if (p.indexOf('/api/paths/home') === 0) return Promise.resolve(HOME);
  if (p.indexOf('/api/paths/cables') === 0) return Promise.resolve(CAB);
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
  // The device filter must be a picker of devices, not a box for typing an
  // address, and one entry per device however many addresses it holds.
  if (h.indexOf('<select id="f-dev"') < 0) throw new Error('the device filter should be a picker');
  if (h.indexOf('MacBookPro') < 0 || h.indexOf('roku-ultra') < 0) throw new Error('devices missing from the picker');
  if (h.indexOf('2 addresses') < 0) throw new Error('a multi-address device should say so');
  if (h.indexOf('every device') < 0) throw new Error('there must be a way back to everything');
  // The origin must be shown, settable, and detectable both ways.
  if (h.indexOf('Your location') < 0) throw new Error('the origin should be declarable on the page');
  if (h.indexOf("Use this browser's location") < 0) throw new Error('browser auto-detect missing');
  if (h.indexOf('Use the public address') < 0) throw new Error('address auto-detect missing');
  if (h.indexOf('Manhattan') < 0) throw new Error('what the public address suggests should be shown');
  // A placement the latency rules out is circled on the map and explained.
  if (h.indexOf('class="ruledout"') < 0) throw new Error('an impossible placement must be marked on the map');
  if (h.indexOf('RULED OUT') < 0) throw new Error('the reason should be in the hover text');
  if (h.indexOf('Ruled out by latency') < 0) throw new Error('impossible placements need a count');
  // Cables are drawn behind the routes, and a run crossing the antimeridian
  // must break rather than stripe straight across the map.
  if (h.indexOf('class="cable"') < 0) throw new Error('cables are not drawn');
  if ((h.match(/class="cable"/g) || []).length !== 2) throw new Error('want one path per cable run');
  var pac = h.slice(h.indexOf('class="cable"', h.indexOf('class="cable"') + 1));
  if ((pac.slice(0, 200).match(/M/g) || []).length < 2) throw new Error('a run wrapping the antimeridian must break into two subpaths');
  if (h.indexOf('TeleGeography') < 0) throw new Error('the source should be credited on the page');
  if (h.indexOf('could have crossed') < 0) throw new Error('candidate cables should appear in the hover text');
  if (h.indexOf('Southern Cross NEXT') < 0) throw new Error('the candidate name is missing');
  print('Map page renders routes, cables, shared legs, unplaced hops, devices, the origin with both detectors, and placements the physics rules out');
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
