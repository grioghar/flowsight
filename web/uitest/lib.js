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

// Zoom rewrites the viewBox, which scales the drawing and the ink on top of
// it alike. The map wants the first and not the second, so panZoom has to
// publish the factor both ways: as --z for CSS, and to a callback for the
// attributes CSS cannot reach.
(function () {
  var attrs = {}, props = {}, handlers = {}, zooms = [];
  var svg = {
    style: { setProperty: function (k, v) { props[k] = v; } },
    setAttribute: function (k, v) { attrs[k] = v; },
    addEventListener: function (n, f) { handlers[n] = f; },
    getBoundingClientRect: function () { return { left: 0, top: 0, width: 720, height: 360 }; }
  };
  var realWindow = window.addEventListener;
  window.addEventListener = function () {};
  var h = FS.panZoom(svg, 720, 360, function (z) { zooms.push(z); });
  window.addEventListener = realWindow;

  if (attrs.viewBox !== '0 0 720 360') throw new Error('initial viewBox wrong: ' + attrs.viewBox);
  if (props['--z'] !== 1) throw new Error('unzoomed factor should be 1, got ' + props['--z']);
  if (zooms[0] !== 1) throw new Error('callback should fire at rest, got ' + zooms[0]);

  // Wheel up zooms in: the viewBox must shrink and the factor must rise.
  handlers.wheel({ preventDefault: function () {}, deltaY: -1, clientX: 360, clientY: 180 });
  var w = parseFloat(attrs.viewBox.split(' ')[2]);
  if (!(w < 720)) throw new Error('zooming in should shrink the viewBox, got ' + attrs.viewBox);
  var z = zooms[zooms.length - 1];
  if (Math.abs(z - 720 / w) > 1e-9) throw new Error('factor must be the actual scale: ' + z + ' vs ' + (720 / w));
  if (!(z > 1)) throw new Error('zooming in should raise the factor, got ' + z);
  if (props['--z'] !== z) throw new Error('--z and the callback must agree');

  // Reset puts it back, and says so, rather than leaving the ink shrunk.
  h.reset();
  if (attrs.viewBox !== '0 0 720 360') throw new Error('reset did not restore the viewBox');
  if (zooms[zooms.length - 1] !== 1) throw new Error('reset must publish a factor of 1');

  // A caller that wants none of this must still work.
  var plain = { style: { setProperty: function () {} }, setAttribute: function () {},
    addEventListener: function () {}, getBoundingClientRect: function () { return {}; } };
  window.addEventListener = function () {};
  if (!FS.panZoom(plain, 720, 360)) throw new Error('panZoom must still work without a callback');
  window.addEventListener = realWindow;
  print('FS.panZoom publishes the zoom factor OK');
})();

// Touch: one finger pans, two pinch, and the content under the midpoint has
// to stay under the midpoint or the map slides out from under the fingers.
(function () {
  var attrs = {}, handlers = {}, captured = {};
  var svg = {
    style: { setProperty: function () {} },
    setAttribute: function (k, v) { attrs[k] = v; },
    addEventListener: function (n, f) { handlers[n] = f; },
    setPointerCapture: function (id) { captured[id] = true; },
    hasPointerCapture: function (id) { return !!captured[id]; },
    releasePointerCapture: function (id) { delete captured[id]; },
    getBoundingClientRect: function () { return { left: 0, top: 0, width: 720, height: 360 }; }
  };
  var realPE = window.PointerEvent;
  window.PointerEvent = function () {};
  var h = FS.panZoom(svg, 720, 360);
  var box = function () { return attrs.viewBox.split(' ').map(parseFloat); };

  if (!handlers.pointerdown) throw new Error('touch and pen need pointer handlers');
  if (handlers.mousedown) throw new Error('mouse must not be wired twice when pointers are available');

  // A tap must not be captured. A captured pointer makes the browser retarget
  // the click that follows to the map, and on a touchscreen there is no hover
  // to fall back on, so hop cards would stop opening entirely.
  handlers.pointerdown({ pointerId: 1, clientX: 360, clientY: 180 });
  if (captured[1]) throw new Error('a tap must not be captured, or it never reaches the hop under it');
  handlers.pointermove({ pointerId: 1, clientX: 362, clientY: 181 });
  if (attrs.viewBox !== '0 0 720 360') throw new Error('a wobble under the slop must not pan: ' + attrs.viewBox);
  if (captured[1]) throw new Error('a wobble must not take the capture either');
  handlers.pointerup({ pointerId: 1 });

  // One finger dragged in earnest pans, and takes the capture as it goes so a
  // finger leaving the element does not strand the gesture.
  handlers.pointerdown({ pointerId: 1, clientX: 360, clientY: 180 });
  handlers.pointermove({ pointerId: 1, clientX: 432, clientY: 180 });
  if (!captured[1]) throw new Error('a real drag must take the capture');
  var v = box();
  if (Math.abs(v[0] - -72) > 0.001) throw new Error('one finger should pan, got x=' + v[0]);
  handlers.pointerup({ pointerId: 1 });
  if (captured[1]) throw new Error('the capture must be released');
  h.reset();

  // Two fingers 100 apart, spread to 200: the drawing must halve.
  handlers.pointerdown({ pointerId: 1, clientX: 310, clientY: 180 });
  handlers.pointerdown({ pointerId: 2, clientX: 410, clientY: 180 });
  handlers.pointermove({ pointerId: 1, clientX: 260, clientY: 180 });
  handlers.pointermove({ pointerId: 2, clientX: 460, clientY: 180 });
  v = box();
  if (Math.abs(v[2] - 360) > 0.5) throw new Error('pinching out should halve the viewBox, got w=' + v[2]);
  // The midpoint never moved, so the point under it must not have either.
  var midX = v[0] + 0.5 * v[2], midY = v[1] + 0.5 * v[3];
  if (Math.abs(midX - 360) > 0.5 || Math.abs(midY - 180) > 0.5)
    throw new Error('the pinch centre drifted to ' + midX + ',' + midY);

  // Lifting one finger must not jump: the remaining finger re-bases.
  handlers.pointerup({ pointerId: 2 });
  var before = box();
  handlers.pointermove({ pointerId: 1, clientX: 260, clientY: 180 });
  var after = box();
  if (Math.abs(before[0] - after[0]) > 0.001 || Math.abs(before[1] - after[1]) > 0.001)
    throw new Error('lifting a finger jumped the map from ' + before + ' to ' + after);
  handlers.pointerup({ pointerId: 1 });

  window.PointerEvent = realPE;
  print('FS.panZoom pans and pinches with touch OK');
})();
