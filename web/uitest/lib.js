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

// A dialog opened inside the OPNsense panel must land on the slice of the
// frame the reader is actually looking at, without changing the document's
// height (the host sizes the frame from that).
(function () {
  var style = {};
  var modal = { hidden: false, style: style };
  var realQ = FS.$;
  FS.$ = function (sel, root) { return sel === '#modal' ? modal : realQ(sel, root); };
  FS.embedded = true; FS.hostView = { top: 1840, height: 900 };
  FS.placeModal();
  if (style.transform !== 'translateY(1840px)') throw new Error('modal not moved to the visible band: ' + style.transform);
  if (style.height !== '900px') throw new Error('modal height wrong: ' + style.height);
  if (style.position) throw new Error('modal must stay position:fixed, got ' + style.position);
  FS.embedded = false;
  FS.placeModal();
  if (style.transform !== '') throw new Error('standalone modal must not be moved');
  FS.$ = realQ;
  print('FS.placeModal OK');
})();
