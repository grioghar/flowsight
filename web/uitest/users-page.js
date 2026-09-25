// Users page: renders active users and their sessions from RADIUS/LDAP
var window = this; var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'#users' }; var setTimeout = function(){};
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24;
FS.get = function(p){
  if (p.indexOf('/api/users') === 0) return Promise.resolve({
    users: [
      { user: 'alice', source: 'radius', ipv4: '192.168.1.10', ipv6: '2001:db8::1', device_name: 'laptop', nas_ip: '10.0.1.1', nas_id: 'gateway', start_ts: 1695753600, last_seen: 1695753900, active: true },
      { user: 'bob', source: 'radius', ipv4: '192.168.1.11', ipv6: '2001:db8::2', device_name: 'phone', nas_ip: '10.0.1.1', nas_id: 'gateway', start_ts: 1695750000, last_seen: 1695753000, active: true }
    ],
    count: 2
  });
  return Promise.resolve({});
};
FS.post = function(p){
  if (p.indexOf('/api/users/session') === 0) return Promise.resolve({ status: 'created' });
  return Promise.resolve({});
};
load('web/static/pages3.js');
var el = mkEl(); var FAILURE = null;
FS.pages.users.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  if (h.indexOf('Active users') < 0) throw new Error('Active users KPI missing');
  if (h.indexOf('alice') < 0) throw new Error('user alice missing');
  if (h.indexOf('bob') < 0) throw new Error('user bob missing');
  if (h.indexOf('192.168.1.10') < 0) throw new Error('alice IPv4 missing');
  if (h.indexOf('2001:db8::1') < 0) throw new Error('alice IPv6 missing');
  if (h.indexOf('radius') < 0) throw new Error('RADIUS source missing');
  if (h.indexOf('laptop') < 0) throw new Error('device name missing');
  if (h.indexOf('Add session manually') < 0) throw new Error('Add session form missing');
  if (h.indexOf('10.0.1.1') < 0) throw new Error('NAS IP missing');
  print('users page: renders active users and form');
}).catch(function(e){ FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
