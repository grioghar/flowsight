// Sessions page renders the visibility column showing what FlowSight can see
var window = this; var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'#flows' }; var setTimeout = function(){};
function URLSearchParams(obj) {
  this.params = obj || {}; this.set = function(k, v) { this.params[k] = v; }; this.toString = function() { return Object.entries(this.params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'); };
}
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24; FS.since = function(){ return 'minutes=30'; };
FS.go = function(url){ /* navigation stub */ };
FS.get = function(p){
  if (p.indexOf('/api/visibility/flows') === 0) return Promise.resolve({
    flows: [
      { ts: 1000000, src_ip: '192.168.1.5', src_name: 'client', dst_ip: '93.184.216.34', dst_name: 'example.com', dst_port: 443, app: 'TLS', proto: 'tcp', tls_version: '1.3', domain: 'example.com', bytes_in: 1000, bytes_out: 500, duration: 10, verdict: 'observed', policy: '', source: 'ntopng', visibility: 'sni' },
      { ts: 1000001, src_ip: '192.168.1.5', src_name: 'client', dst_ip: '192.0.2.1', dst_name: 'gateway', dst_port: 53, app: 'DNS', proto: 'udp', domain: 'example.com', bytes_in: 100, bytes_out: 50, duration: 0.1, verdict: 'observed', policy: '', source: 'ntopng', visibility: 'dns' },
      { ts: 1000002, src_ip: '192.168.1.6', src_name: 'device2', dst_ip: '8.8.8.8', dst_name: 'google-dns', dst_port: 443, app: 'QUIC', proto: 'udp', tls_version: '', domain: '', bytes_in: 2000, bytes_out: 1000, duration: 5, verdict: 'observed', policy: '', source: 'ntopng', visibility: 'quic' },
      { ts: 1000003, src_ip: '192.168.1.5', src_name: 'client', dst_ip: '1.1.1.1', dst_name: 'cloudflare', dst_port: 443, app: 'TLS', proto: 'tcp', tls_version: '1.3', domain: '', bytes_in: 500, bytes_out: 250, duration: 3, verdict: 'observed', policy: '', source: 'ntopng', visibility: 'opaque' },
      { ts: 1000004, src_ip: '192.168.1.10', src_name: 'secure-device', dst_ip: '185.199.108.153', dst_name: 'cdn.example.org', dst_port: 443, app: 'TLS', proto: 'tcp', tls_version: '1.3', domain: 'cdn.example.org', bytes_in: 3000, bytes_out: 1500, duration: 15, verdict: 'observed', policy: '', source: 'squid', visibility: 'inspected' }
    ],
    home_country: 'US'
  });
  return Promise.resolve({});
};
load('web/static/pages.js');
var el = mkEl(); var FAILURE = null;
FS.pages.flows.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  // Check that visibility values appear in the output
  if (h.indexOf('sni') < 0) throw new Error('visibility "sni" not shown in sessions');
  if (h.indexOf('dns') < 0) throw new Error('visibility "dns" not shown in sessions');
  if (h.indexOf('quic') < 0) throw new Error('visibility "quic" not shown in sessions');
  if (h.indexOf('opaque') < 0) throw new Error('visibility "opaque" not shown in sessions');
  if (h.indexOf('inspected') < 0) throw new Error('visibility "inspected" not shown in sessions');
  // Verify all 5 test sessions are present
  if ((h.match(/example\.com/g) || []).length < 2) throw new Error('domains not shown');
  print('sessions page: visibility values are displayed');
}).catch(function(e){ FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
