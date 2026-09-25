// Host page renders the visibility card with counts, descriptions, and filter links
var window = this; var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'#host/192.168.1.5' }; var setTimeout = function(){};
function URLSearchParams(obj) {
  this.params = obj || {}; this.set = function(k, v) { this.params[k] = v; }; this.toString = function() { return Object.entries(this.params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'); };
}
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24; FS.since = function(){ return 'hours=24'; };
FS.go = function(url){ /* navigation stub */ };
FS.setTitle = function(t) { /* stub */ };
FS.get = function(p){
  if (p.indexOf('/api/visibility/host') === 0) return Promise.resolve({
    host: { ip: '192.168.1.5', name: 'testhost', mac: '00:11:22:33:44:55', vendor: 'TestVendor', first_seen: 1000000, last_seen: 1000100 },
    device: { zone: 'LAN', class: 'laptop' },
    totals: { bytes_in: 1000000, bytes_out: 500000, flows: 50, blocked: 5 },
    dns_totals: { queries: 100, blocked: 10, domains: 20 },
    apps: [{ app: 'TLS', category: 'Web', flows: 30, bytes_in: 800000, bytes_out: 300000 }],
    domains: [{ domain: 'example.com', category: 'Web', flows: 20, bytes_in: 500000, bytes_out: 200000 }],
    destinations: [{ ip: '93.184.216.34', name: 'example.com', port: 443, proto: 'tcp', bytes_in: 500000, bytes_out: 200000 }],
    dns: [{ domain: 'example.com', action: 'pass', list: '', queries: 50 }],
    dns_blocked: [],
    tls: [{ sni: 'example.com', version: 'TLS 1.3', mode: 'splice', sessions: 20 }],
    flows: [{ ts: 1000000, src_ip: '192.168.1.5', src_name: 'testhost', dst_ip: '93.184.216.34', dst_name: 'example.com', dst_port: 443, proto: 'tcp', app: 'TLS', category: 'Web', domain: 'example.com', bytes_in: 100000, bytes_out: 50000, verdict: 'observed', policy: '' }],
    timeline: [{ t: 1000000, bytes_in: 500000, bytes_out: 200000, flows: 25, blocked: 2 }],
    addresses: ['192.168.1.5']
  });
  if (p.indexOf('/api/visibility/visibility') === 0) return Promise.resolve({
    ip: '192.168.1.5',
    hours: 24,
    visibility: {
      inspected: 5,
      sni: 20,
      opaque: 10,
      quic: 5,
      http: 5,
      dns: 5
    }
  });
  if (p.indexOf('/api/scan/result') === 0) return Promise.resolve({ error: 'not found' });
  return Promise.resolve({});
};
load('web/static/pages.js');
var el = mkEl(); var FAILURE = null;
FS.pages.host.render(el, { arg: '192.168.1.5', params:{} }).then(function(){
  var h = el.innerHTML;
  // Check that the visibility card is rendered
  if (h.indexOf('What FlowSight can see for this device') < 0) throw new Error('visibility card title missing');
  // Check that visibility types are shown
  if (h.indexOf('inspected') < 0) throw new Error('inspected visibility not shown');
  if (h.indexOf('sni') < 0) throw new Error('sni visibility not shown');
  if (h.indexOf('opaque') < 0) throw new Error('opaque visibility not shown');
  if (h.indexOf('quic') < 0) throw new Error('quic visibility not shown');
  // Check that filter links exist for visibility types
  if (h.indexOf('#flows?ip=192.168.1.5&visibility=inspected') < 0) throw new Error('inspected filter link missing');
  if (h.indexOf('#flows?ip=192.168.1.5&visibility=sni') < 0) throw new Error('sni filter link missing');
  // Check that counts are shown
  if (h.indexOf('5 sessions') < 0 && h.indexOf('20 sessions') < 0) throw new Error('session counts not shown');
  print('host page: visibility card renders with counts, descriptions, and filter links');
}).catch(function(e){ FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
