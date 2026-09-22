// Minimal harness: load lib.js, then exercise the pieces the TLS page added.
var window = this, document = { getElementById: function(){ return null; },
  querySelector: function(){ return null; }, querySelectorAll: function(){ return []; },
  addEventListener: function(){}, body: { contains: function(){ return false; } },
  createElement: function(){ return { style:{}, setAttribute:function(){}, appendChild:function(){} }; } };
var localStorage = { getItem: function(){ return null; }, setItem: function(){} };
var location = { hash: '#tls' };
var setTimeout = function(){};
load('web/static/lib.js');
var out = FS.strip([{label:'TLS/1.3', value: 900},{label:'TLS/1.2', value: 100}]);
if (out.indexOf('90.00%') < 0) throw new Error('strip width wrong: ' + out);
if (out.indexOf('striplegend') < 0) throw new Error('strip legend missing');
print('FS.strip OK');
// rowAttr must reach the <tr>
var t = FS.table([{a:1, fingerprint:'abc'}], [{t:'A', k:'a'}], { rowAttr: function(r){ return 'data-cert="'+r.fingerprint+'"'; } });
if (t.indexOf('data-cert="abc"') < 0) throw new Error('rowAttr not applied');
print('rowAttr OK');
// A table with no opts must still render.
if (FS.table([{a:1}], [{t:'A', k:'a'}]).indexOf('<td') < 0) throw new Error('plain table broke');
print('plain table OK');
