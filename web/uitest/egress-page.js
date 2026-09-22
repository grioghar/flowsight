var window = this;
// Assertions run inside a promise; the result is rethrown after the queue
// drains, because an uncaught throw is what makes the engine exit non-zero.
var FAILURE = null;
function fail(e){ FAILURE = e; }
var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{},
  addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#egress' };
var setTimeout = function(){};
load('web/static/lib.js');

// One tunnel moving a lot, one unnamed destination, one ordinary download.
var TUNNEL = { key:'a', local:'192.168.1.178', local_name:'seedbox', peer:'79.127.160.158',
  peer_port:51820, proto:'udp', group:'tunnel', group_title:'Encrypted tunnel', service:'WireGuard',
  out:263517066416, in:102413038016, rate_out:9000000, rate_in:3000000, age:30020, flags:['volume'], since:1 };
var UNNAMED = { key:'b', local:'192.168.1.55', local_name:'', peer:'203.0.113.9', peer_port:8443,
  proto:'tcp', group:'unknown', group_title:'Unnamed destination', service:'',
  out:104857600, in:2048, rate_out:1500000, rate_in:100, age:120, flags:['unnamed','ratio'], since:1 };
// A Plex server answering a viewer: it really has sent the bytes, and it is
// not data leaving. It must be shown, marked, and left out of the totals.
var SERVING = { key:'d', local:'192.168.1.105', local_name:'plex-host', peer:'8.41.21.29',
  peer_name:'ip-8-41-21-29.ideatek.com', peer_port:32400, proto:'tcp', group:'other',
  group_title:'Other', service:'ideatek.com', out:3221225472, in:3670016,
  rate_out:0, rate_in:0, age:23000, flags:[], since:1, serving:true };
var NORMAL = { key:'c', local:'192.168.1.42', local_name:'mac', peer:'140.82.114.3', peer_name:'github.com',
  peer_port:443, proto:'tcp', group:'code-host', group_title:'Code hosting', service:'github.com',
  out:14863, in:616615, rate_out:0, rate_in:50000, age:69, flags:[], since:1 };

FS.get = function(p){
  if (p.indexOf('/api/egress/live') === 0) return Promise.resolve({ transfers:[TUNNEL, UNNAMED, NORMAL, SERVING],
    sampled: 1790062000, groups:[], note:'Read from the firewall.' });
  if (p.indexOf('/api/egress/summary') === 0) return Promise.resolve({
    devices:[{key:'192.168.1.178',name:'seedbox',out:263517066416,in:1,rate_out:9000000,flows:1}],
    groups:[{key:'tunnel',title:'Encrypted tunnel',out:263517066416,in:1,rate_out:9000000,flows:1}],
    total_out:263622000000, total_in:102413040000, rate_out:10500100, transfers:3, sampled:1790062000 });
  if (p.indexOf('/api/egress/events') === 0) return Promise.resolve({ events:[
    { ts:1790062000, kind:'unnamed', severity:'high', message:'192.168.1.55 has sent 100 MB to 203.0.113.9, which has no name',
      transfer: UNNAMED } ] });
  return Promise.resolve({});
};
FS.post = function(){ return Promise.resolve({ ok:true }); };
load('web/static/pages3.js');

var el = mkEl();
FS.pages.egress.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  ['seedbox', 'WireGuard', 'github.com', 'Unnamed destination', 'Moving now (4)'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('live table missing ' + s);
  });
  if (h.indexOf('data-stop="192.168.1.178"') < 0) throw new Error('no stop control for a running transfer');
  if (h.indexOf('class="flagged"') < 0) throw new Error('flagged transfers are not marked');
  if (h.indexOf('has no name') < 0) throw new Error('flagged events not listed');
  // The tunnel's 263 GB must read as sent, not received.
  if (h.indexOf('245 GB') < 0 && h.indexOf('245.4 GB') < 0) throw new Error('byte total not rendered: ' + h.slice(0, 200));
  if (h.indexOf('serving') < 0) throw new Error('an inbound connection is not marked as serving');
  if (h.indexOf('reaching out') < 0) throw new Error('outbound connections are not marked');
  // The Plex server's 3 GB must not be counted as data this network sent.
  var kpi = h.slice(h.indexOf('Sent, open connections') - 400, h.indexOf('Sent, open connections') + 200);
  if (kpi.indexOf('3.0 GB') >= 0 || kpi.indexOf('248') >= 0) throw new Error('serving bytes counted as sent: ' + kpi);
  print('Data out page renders live transfers, flags, serving vs reaching out, and the stop control');
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
