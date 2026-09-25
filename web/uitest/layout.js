var window = this;
var FAILURE = null; function fail(e){ FAILURE = e; }
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, classList:{contains:function(){return false}}, children:[],
  addEventListener:function(){}, appendChild:function(){}, querySelector:function(){ return null; }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode: null }; }
var document = { getElementById:function(){ return null; }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){}, removeItem:function(){} };
var location = { hash:'#overview' };
var setTimeout = function(f){ };
load('web/static/lib.js');
// The ordering rule: saved keys first in saved order, the rest keep their place; unknown saved keys are ignored.
var got = FS.layout.order(['traffic','flows','dns','hosts'], ['dns','gone','traffic']);
if (got.join(',') !== 'dns,traffic,flows,hosts') throw new Error('order wrong: ' + got.join(','));
if (FS.layout.order(['a','b'], null).join(',') !== 'a,b') throw new Error('no saved order should keep built-in');
// apply() on a bare stub must not throw.
FS.layout.apply(mkEl());
print('card layout ordering OK');
