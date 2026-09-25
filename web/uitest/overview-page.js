// The Overview's "who did it" subtitles carry links to the hosts; they must
// arrive as links, not as escaped tag text.
var window = this; var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'#overview' }; var setTimeout = function(){};
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24; FS.since = function(){ return 'hours=24'; };
FS.get = function(p){
  if (p.indexOf('/api/visibility/summary') === 0) return Promise.resolve({ throughput_bps: 1000, active_flows: 3, active_hosts: 2, blocked_last_hour: 0, alerts_last_hour: 0 });
  if (p.indexOf('/api/visibility/top') === 0) return Promise.resolve({
    hosts: [{ ip: '192.168.1.5', name: 'mac', flows: 10, apps: 2, bytes_in: 10, bytes_out: 5 }],
    apps: [{ app: 'TLS', flows: 8, hosts: 3, top_hosts: [{ ip: '192.168.1.5', name: 'mac' }, { ip: '192.168.1.9' }], bytes_in: 100, bytes_out: 50 }],
    domains: [{ domain: 'example.com', flows: 4, hosts: 1, top_hosts: [{ ip: '192.168.1.5', name: 'mac' }], dst_ip: '93.184.216.34', traced: true }],
    categories: [{ category: 'Web', flows: 8 }], blocked: [] });
  if (p.indexOf('/api/visibility/timeseries') === 0) return Promise.resolve({ traffic: [] });
  if (p.indexOf('/api/system/health') === 0) return Promise.resolve({ modules: {} });
  if (p.indexOf('/api/system/findings') === 0) return Promise.resolve({ findings: [] });
  if (p.indexOf('/api/dns/summary') === 0) return Promise.resolve({ totals: {} });
  if (p.indexOf('/api/setup/state') === 0) return Promise.resolve({ completed: true });
  return Promise.resolve({});
};
load('web/static/pages.js');
var el = mkEl(); var FAILURE = null;
FS.pages.overview.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  if (h.indexOf('&lt;a') >= 0) throw new Error('escaped anchor tags in the overview');
  if (h.indexOf('<a href="#host/192.168.1.5">mac</a>') < 0) throw new Error('who-did subtitle lost its host link');
  if (h.indexOf('#flows?app=TLS') < 0) throw new Error('application link missing');
  print('overview page: who-did subtitles are links');
}).catch(function(e){ FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
