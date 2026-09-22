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
var NORMAL = { key:'c', local:'192.168.1.42', local_name:'mac', peer:'140.82.114.3', peer_name:'github.com',
  peer_port:443, proto:'tcp', group:'code-host', group_title:'Code hosting', service:'github.com',
  out:14863, in:616615, rate_out:0, rate_in:50000, age:69, flags:[], since:1 };

FS.get = function(p){
  if (p.indexOf('/api/egress/live') === 0) return Promise.resolve({ transfers:[TUNNEL, UNNAMED, NORMAL],
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
  ['seedbox', 'WireGuard', 'github.com', 'Unnamed destination', 'Moving now (3)'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('live table missing ' + s);
  });
  if (h.indexOf('data-stop="192.168.1.178"') < 0) throw new Error('no stop control for a running transfer');
  if (h.indexOf('class="flagged"') < 0) throw new Error('flagged transfers are not marked');
  if (h.indexOf('has no name') < 0) throw new Error('flagged events not listed');
  // The tunnel's 263 GB must read as sent, not received.
  if (h.indexOf('245 GB') < 0 && h.indexOf('245.4 GB') < 0) throw new Error('byte total not rendered: ' + h.slice(0, 200));
  print('Data out page renders live transfers, flags and the stop control');
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
