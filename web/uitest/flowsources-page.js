var window = this;
var FAILURE = null;
function fail(e){ FAILURE = e; }
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{},
  addEventListener:function(){}, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#flowsources', hostname:'192.168.1.1' };
var setTimeout = function(){};
load('web/static/lib.js');

var STATUS = {
  enabled: true,
  ok: true,
  error: '',
  exporters: [
    {
      address: '192.168.1.50',
      protocol: 'netflow5',
      records_total: 1500,
      flows_total: 1500,
      drops_total: 0,
      templates: 0,
      last_seen: 1695298765
    },
    {
      address: '192.168.1.51',
      protocol: 'ipfix',
      records_total: 800,
      flows_total: 800,
      drops_total: 0,
      templates: 2,
      last_seen: 1695298750
    }
  ]
};

FS.get = function(p){
  if (p.indexOf('/api/netflow/status') === 0) return Promise.resolve(STATUS);
  return Promise.resolve({});
};
load('web/static/pages.js');

var el = mkEl();
FS.pages.flowsources.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  ['Connected exporters', '192.168.1.50', 'netflow5', '192.168.1.51', 'ipfix', 'Templates'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('page missing: ' + s);
  });

  // Test empty exporter state
  STATUS.exporters = [];
  var el2 = mkEl();
  return FS.pages.flowsources.render(el2, { params:{} }).then(function(){
    if (el2.innerHTML.indexOf('No exporters connected') < 0) throw new Error('empty state must be shown');
    print('Flow sources page renders exporter table and empty state');
  });
}).catch(fail);

if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
