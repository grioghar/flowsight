var window = this;
window.addEventListener = function(){};
var FAILURE = null;
function fail(e){ FAILURE = e; }
var navigator = { geolocation: { getCurrentPosition: function(){} } };
function mkEl(){ var o = { innerHTML:'', style:{ setProperty:function(){} }, hidden:true, onclick:null, value:'', dataset:{},
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
load('web/static/land.js');

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
  // Placed by its own hostname, against a database that said London.
  { id:'h35', index:6, ips:['51.10.49.216'], names:['po1.owr03.lax31.ntwk.msn.net'], located:true,
    lat:34.0522, lon:-118.2437, country:'US', region:'CA', city:'Los Angeles', rtt_ms:134.7,
    location_source:'name', database_said:'London, England, GB', moved_km:8756, db_lat:51.5072, db_lon:-0.1276,
    detail:{ pop_code:'lax', pop_city:'Los Angeles, CA, US', asn:'8075',
      as_name:'MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US', prefix:'51.10.0.0/15',
      rir:'ripencc', allocated:'1993-09-01', net_name:'MSFT-51-10', org:'Microsoft Corporation',
      org_addr:'One Microsoft Way, Redmond, WA, 98052, United States',
      facilities:[{ name:'Equinix LA1 - Los Angeles', address:'600 W 7th St, Los Angeles, CA, 90017-3859, US' }],
      facilities_scoped:true } },
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
  public_v4:['162.202.41.52'], public_v6:['2600:1700:3ab0:f43f::1'],
  detected:{ lat:39.1836, lon:-96.5717, city:'Manhattan', region:'Kansas', country:'US' },
  note:'Declaring this matters more than it looks.' };
var CAB = { cables: [
  { name:'Grace Hopper', km:6900, runs:[[[-70.0,40.7],[-30.0,45.0],[-5.0,50.1]]] },
  // A run that wraps the antimeridian; it must break, not stripe the map.
  { name:'Pacific Light', km:12800, runs:[[[170.0,20.0],[179.0,21.0],[-179.0,21.5],[-150.0,22.0]]] } ],
  attribution:"Submarine cable routes from TeleGeography's public cable map." };
var STATUS = { active:true, last_run:1790200000, destinations:2, hops:11, error:'' };

var ROUTE = { destination:'1.1.1.1',
  inside:{ addresses:['192.168.1.119','2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6'], name:'MacBookPro', vendor:'Apple' },
  hops:[
    { id:'h1', index:1, ips:['192.168.1.254'], located:false },
    { id:'h2', index:2, ips:['172.11.154.1'], names:['172-11-154-1.lightspeed.tpkaks.sbcglobal.net'],
      located:true, city:'Topeka', country:'US', rtt_ms:3.4 },
    { id:'s3', index:3, ips:[], silent:true, located:false },
    { id:'h4', index:4, ips:['1.1.1.1'], located:true, city:'Sydney', country:'AU', rtt_ms:18.9,
      impossible:true, why:'answers in 18.9 ms, but 14071 km away cannot answer in less than 141 ms' } ] };

FS.get = function(p){
  if (p.indexOf('/api/paths/path') === 0) return Promise.resolve(ROUTE);
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
  var circles = (h.match(/class="hop /g) || []).length;
  if (circles !== 4) throw new Error('want 4 plotted hops (one per located node), got ' + circles);

  // A hop must carry its operator, not just a dot. Measured, resolved,
  // inferred and registered are four different kinds of claim and the card
  // has to keep them apart.
  if (h.indexOf('AS8075') < 0) throw new Error('the network running a hop should be named');
  if (h.indexOf('51.10.0.0/15') < 0) throw new Error('the announced prefix should be shown');
  if (h.indexOf('RIPENCC') < 0) throw new Error('the registry should be shown');
  if (h.indexOf('Equinix LA1') < 0) throw new Error('published buildings should be listed');
  if (h.indexOf('600 W 7th St') < 0) throw new Error('a building needs its street address');
  if (h.indexOf('head office, not this router') < 0)
    throw new Error('a registrant address must not be passed off as the router\'s location');
  if (h.indexOf('does not publish which rack') < 0)
    throw new Error('a building list must say what it does not prove');
  if (h.indexOf('Who runs it') < 0) throw new Error('registry detail needs its own heading');
  if (h.indexOf('Site, read from the router name') < 0)
    throw new Error('an inference from a hostname must be labelled as one');
  // The correction has to be visible and auditable, not silent.
  if (h.indexOf('class="corrected"') < 0) throw new Error('a corrected placement should be drawn');
  if (h.indexOf('class="ghost"') < 0) throw new Error('the abandoned position should be marked');
  if (h.indexOf('The database said') < 0) throw new Error('the card must say what it overruled');
  if (h.indexOf('London, England, GB') < 0) throw new Error('the overruled answer must be quoted');
  if (h.indexOf('the router\u2019s own name') < 0) throw new Error('the placement source should be named');
  if (h.indexOf('hoppanel') < 0) throw new Error('there should be a panel for hop detail');
  // Zooming shrinks the viewBox, which would scale the dots along with the
  // geography and bury the detail the zoom was for. Every circle has to carry
  // the size it was drawn at so the zoom can divide it back down.
  var sized = (h.match(/data-r="/g) || []).length;
  var circles2 = (h.match(/<circle/g) || []).length;
  if (sized !== circles2) throw new Error('every circle needs data-r, got ' + sized + ' of ' + circles2);
  if (h.indexOf('data-r="7"') < 0) throw new Error('the ruled-out ring should carry its base radius');
  if (h.indexOf('data-r="2.5"') < 0) throw new Error('the ghost should carry its base radius');
  // Scoped and unscoped facility lists are different claims.
  if (h.indexOf('Buildings this operator occupies in Los Angeles') < 0)
    throw new Error('a scoped building list should name the city it was narrowed to');
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
  // The origin's own public address belongs beside the coordinates: it is how
  // a reader checks the point the whole map is drawn from.
  if (h.indexOf('162.202.41.52') < 0) throw new Error('the public IPv4 address should be shown');
  if (h.indexOf('2600:1700:3ab0:f43f::1') < 0) throw new Error('the public IPv6 address should be shown');
  if (h.indexOf('used for the origin') < 0)
    throw new Error('with more than one address, say which one produced the coordinates');
  // A placement the latency rules out is circled on the map and explained.
  if (h.indexOf('class="ruledout"') < 0) throw new Error('an impossible placement must be marked on the map');
  if (h.indexOf('RULED OUT') < 0) throw new Error('the reason should be in the hover text');
  if (h.indexOf('Ruled out by latency') < 0) throw new Error('impossible placements need a count');
  // Cables are drawn behind the routes, and a run crossing the antimeridian
  // must break rather than stripe straight across the map.
  // Land, so the thing reads as a map rather than a grid with dots on it.
  if (h.indexOf('class="land"') < 0) throw new Error('the map has no land on it');
  if (!FS.landPath || FS.landPath.length < 10000) throw new Error('land outlines look truncated');
  if (h.indexOf('Natural Earth') < 0) throw new Error('the land source should be credited');
  if (h.indexOf('class="cable"') < 0) throw new Error('cables are not drawn');
  if ((h.match(/class="cable"/g) || []).length !== 2) throw new Error('want one path per cable run');
  var pac = h.slice(h.indexOf('class="cable"', h.indexOf('class="cable"') + 1));
  if ((pac.slice(0, 200).match(/M/g) || []).length < 2) throw new Error('a run wrapping the antimeridian must break into two subpaths');
  if (h.indexOf('TeleGeography') < 0) throw new Error('the source should be credited on the page');
  if (h.indexOf('could have crossed') < 0) throw new Error('candidate cables should appear in the hover text');
  if (h.indexOf('Southern Cross NEXT') < 0) throw new Error('the candidate name is missing');
  print('Map page renders routes, cables, shared legs, unplaced hops, devices, the origin with both detectors, and placements the physics rules out');

  // With a route chosen, the page must show it as a trail that starts inside
  // the network and ends at the address that was reached.
  var el2 = mkEl();
  FS.pages.paths.render(el2, { params:{ dst:'1.1.1.1' } }).then(function(){
    var t = el2.innerHTML;
    if (t.indexOf('class="trail"') < 0) throw new Error('a chosen route should be drawn as a trail');
    // It begins inside, not at the first router that answered.
    if (t.indexOf('MacBookPro') < 0) throw new Error('the trail must start with the device on this network');
    if (t.indexOf('192.168.1.119') < 0) throw new Error('the internal address should be the first step');
    var insideAt = t.indexOf('MacBookPro'), gwAt = t.indexOf('192.168.1.254');
    if (!(insideAt >= 0 && gwAt > insideAt)) throw new Error('the internal address must come before the gateway');
    // Every link in between, in order, ending at the endpoint.
    if (t.indexOf('tpkaks') < 0) throw new Error('intermediate hops belong in the trail');
    if (t.indexOf('endpoint') < 0) throw new Error('the last step should be marked as the endpoint');
    var endAt = t.lastIndexOf('1.1.1.1');
    if (!(endAt > gwAt)) throw new Error('the endpoint must come last');
    // A hop that never answered still carried the traffic and keeps its place.
    if (t.indexOf('no answer') < 0) throw new Error('a silent hop should still occupy its step');
    if (t.indexOf('crumb silent') < 0) throw new Error('a silent step should be marked as such');
    // An impossible placement stays flagged inside the trail.
    if (t.indexOf('bad') < 0) throw new Error('a ruled-out hop should be flagged in the trail');
    // Steps are tied to the map, and the rest of the map steps back.
    if (t.indexOf('data-crumb="h2"') < 0) throw new Error('steps must be addressable to light up their dot');
    if (t.indexOf('onroute') < 0) throw new Error('the chosen route should be lifted out on the map');
    if (t.indexOf('offroute') < 0) throw new Error('other routes should be dimmed, not removed');
    if (t.indexOf('Show every route') < 0) throw new Error('there must be a way back to all routes');
    print('Map page renders the chosen route as a trail from the inside address to the endpoint');
  }).catch(fail);
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
