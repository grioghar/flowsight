// Country codes stay short on the page; the full name is the tooltip.
var window = this;
var document = { createElement: function(){ return { style:{} }; }, addEventListener: function(){} };
var localStorage = { getItem: function(){ return null; }, setItem: function(){} };
var location = { hash: '' }; var setTimeout = function(){};
load('web/static/lib.js');
var h = FS.cc('ca', { cls: 'pill warn', suffix: '12' });
if (h.indexOf('>CA 12<') < 0) throw new Error('code not shown: ' + h);
if (h.indexOf('title="Canada"') < 0) throw new Error('name not in the tooltip: ' + h);
var l = FS.cc('IE', { href: '#flows?country=IE', title: '3 sessions' });
if (l.indexOf('<a ') !== 0 || l.indexOf('Ireland — 3 sessions') < 0) throw new Error('linked pill: ' + l);
if (FS.countryName('xx') !== 'XX' || FS.countryName('') !== '') throw new Error('unknown codes fall back to themselves');
if (Object.keys(FS.COUNTRIES).length < 240) throw new Error('table too small');
print('country pills: code on the page, name on hover');
