var window = this;
var FAILURE = null;
function fail(e){ FAILURE = e; }
var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, className: '',
  addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode: null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var FS = { hostLink:function(ip){return ip;}, pill:function(x){return x;}, registeredPages:{},
  registerPage:function(k,v){ this.registeredPages[k]=v; }};
var get = function(url){ var fixtures = {
  '/api/scan/status': { enabled:true, queued:2, running:0, nmap_installed:true, last_sweep: Math.floor(Date.now()/1000)-3600 },
  '/api/scan/results?hours=24': { results:[{
    ip:'192.168.1.100', mac:'aa:bb:cc:dd:ee:ff', hostname:'laptop',
    os_guess:'Linux 5.x', os_confidence:0.85, open_ports:[
      {port:22, protocol:'tcp', state:'open', service:'ssh'},
      {port:80, protocol:'tcp', state:'open', service:'http'}
    ], services:{ssh:{name:'ssh'}}, findings:['mdns_respond'],
    nmap_enhanced:true, finished: Math.floor(Date.now()/1000)-1200
  }]}
}; return Promise.resolve(fixtures[url] || {error:'not found'}); };
var esc = function(x){ return x; }; var num = function(x){ return String(x); }; var ago = function(t){ return 'ago'; };
var card = function(title, content){ return '<div class="card"><h3>' + title + '</h3>' + content + '</div>'; };
var kpi = function(label, value, detail){ return '<div class="kpi">' + label + ': ' + value + '</div>'; };
var pill = function(x){ return '<span class="pill">' + x + '</span>'; };
var table = function(rows, cols){ var html = '<table><tbody>';
  rows.forEach(function(r){ html += '<tr>'; cols.forEach(function(c){ html += '<td>' + (c.f ? c.f(r) : r[c.k] || '') + '</td>'; }); html += '</tr>'; });
  html += '</tbody></table>'; return html; };
var post = function(url, data){ return Promise.resolve({}); };

function testScanPage(){
  var el = mkEl(); el.innerHTML = '';
  var page = FS.registeredPages['scan'];
  if(!page) { fail('scan page not registered'); return Promise.resolve(); }

  return page.render(el).then(function(){
    if(!el.innerHTML.includes('ready')) fail('status card missing');
    if(!el.innerHTML.includes('queued')) fail('queue status missing');
    if(!el.innerHTML.includes('laptop') && !el.innerHTML.includes('192.168.1.100')) fail('hostname/ip missing');
    if(!el.innerHTML.includes('Linux')) fail('OS guess missing');
    if(!el.innerHTML.includes('22') || !el.innerHTML.includes('80')) fail('ports missing');
    if(!el.innerHTML.includes('mdns')) fail('findings missing');
    console.log('Scan page renders, status card and results table with all columns OK');
  }).catch(function(e){ fail(e); });
}

testScanPage().then(function(){
  if(FAILURE) throw FAILURE;
}).catch(function(e){
  console.log('Exception:', e);
  process.exit(1);
});
