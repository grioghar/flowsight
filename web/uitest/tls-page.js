var window = this;
// A failure has to be a failure. The assertions run inside a promise, so the
// result is recorded and rethrown once the microtask queue has drained; an
// uncaught throw is what makes the engine exit non-zero for run.sh.
var FAILURE = null;
function fail(e){ FAILURE = e; }
var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null,
  addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode: null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#tls' };
var setTimeout = function(f){ };
load('web/static/lib.js');
// Capture what the page asks for and answer with one certificate of each shape.
var CERT = { fingerprint:'ab12', subject:"CN=grafana.com,O=Raintank Inc.,C=US",
  issuer:"CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
  serial:'12345', not_before: 1780000000, not_after: 1792195199, key_type:'RSA', key_bits:2048,
  sig_alg:'SHA256-RSA', self_signed:0, trusted:1, seen:4, first_seen:1789000000, last_seen:1790000000,
  source:'probe', sans:'["grafana.com","*.grafana.com"]', snis:'["grafana.com"]', attrs:'{"tls_version":"TLS/1.3"}' };
var THIN = { fingerprint:'cd34', subject:'CN=thin.example', issuer:'', seen:1,
  first_seen:1789000000, last_seen:1790000000, source:'squid' };
FS.get = function(p){
  if (p.indexOf('/api/tls/summary') === 0) return Promise.resolve({ totals:{sessions:10}, ca:{exists:false},
    versions:[{version:'TLS/1.3',sessions:9}], modes:[{mode:'splice',sessions:9}], issuers:[{issuer:CERT.issuer,seen:3}] });
  if (p.indexOf('/api/tls/certs') === 0) return Promise.resolve({ certificates:[CERT, THIN] });
  if (p.indexOf('/api/tls/sessions') === 0) return Promise.resolve({ sessions:[] });
  if (p.indexOf('/api/web/pinned') === 0) return Promise.resolve({ pinned:[] });
  return Promise.resolve({});
};
FS.post = function(){ return Promise.resolve({}); };
load('web/static/pages.js');
var el = mkEl();
var captured = null;
FS.modal = function(html){ captured = html; };
FS.pages.tls.render(el, { params:{} }).then(function(){
  if (el.innerHTML.indexOf('Versions and handling') < 0) throw new Error('compact card missing');
  if (el.innerHTML.indexOf('data-cert="ab12"') < 0) throw new Error('cert row not marked');
  if (!handlers.click) throw new Error('no click handler bound');
  // Simulate a click on the certificate row.
  handlers.click({ target:{ closest:function(sel){ return sel === 'tr[data-cert]'
    ? { getAttribute:function(){ return 'ab12'; } } : null; } } });
  if (!captured) throw new Error('modal not opened');
  ['DigiCert Global G2','SHA256-RSA','2048-bit','*.grafana.com','TLS/1.3','12345'].forEach(function(s){
    if (captured.indexOf(s) < 0) throw new Error('modal missing ' + s);
  });
  print('TLS page renders, row click opens the full certificate');
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
