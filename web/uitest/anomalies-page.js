var window = this;
// Assertions run inside a promise; the result is rethrown after the queue
// drains, because an uncaught throw is what makes the engine exit non-zero.
var FAILURE = null;
function fail(e){ FAILURE = e; }
var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{},
  addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#anomalies' };
var setTimeout = function(){};
load('web/static/lib.js');

// Test anomalies
var ANOMALIES = [
  {
    id: 1, ts: 1695312000, device: 'office-mac', mac: '34:d2:70:98:9a:43',
    kind: 'new_country', severity: 'high',
    title: 'First connection to IE',
    detail: 'Device office-mac (34:d2:70:98:9a:43) first connected to IE. Known countries: US, CA',
    acked: 0
  },
  {
    id: 2, ts: 1695308400, device: 'iot-device', mac: 'aa:bb:cc:dd:ee:ff',
    kind: 'beaconing', severity: 'high',
    title: 'Beacon to 192.0.2.1 (~60s period)',
    detail: 'Device iot-device (aa:bb:cc:dd:ee:ff) shows regular beacon traffic to 192.0.2.1 with ~60s interval, 256 bytes per packet',
    acked: 0
  },
  {
    id: 3, ts: 1695304800, device: 'laptop-dell', mac: '11:22:33:44:55:66',
    kind: 'new_port', severity: 'medium',
    title: 'First connection to tcp/8443',
    detail: 'Device laptop-dell (11:22:33:44:55:66) first connected to tcp/8443. Known ports: tcp/443, tcp/80, udp/53',
    acked: 1
  }
];

var PROFILE = {
  mac: '34:d2:70:98:9a:43',
  first_seen: 1694707200,
  countries: {
    'US': { first_seen: 1694707200, last_seen: 1695312000, count: 124, bytes: 5240000 },
    'CA': { first_seen: 1694966400, last_seen: 1695225600, count: 18, bytes: 480000 }
  },
  ports: {
    'tcp:443': { first_seen: 1694707200, last_seen: 1695312000, count: 89, bytes: 4150000 },
    'udp:53': { first_seen: 1694707200, last_seen: 1695312000, count: 1240, bytes: 42000 }
  },
  destinations: {
    '1.1.1.1': { first_seen: 1694707200, last_seen: 1695312000, count: 302, bytes: 18000 },
    'example.com': { first_seen: 1694750400, last_seen: 1695301200, count: 156, bytes: 2850000 }
  }
};

var STATUS = {
  devices: 42,
  settings: {
    learning_days: 7,
    max_destinations: 50,
    bytes_multiplier: 2.0,
    beaconing_min_sessions: 5,
    beaconing_cv_threshold: 0.2,
    dns_tunnel_min_length: 20,
    dns_tunnel_min_entropy: 5.0,
    dns_tunnel_min_rate: 0.3,
    cooldown_minutes: 60,
    excluded_zones: ['guest']
  }
};

FS.get = function(p){
  if (p.indexOf('/api/baseline/anomalies') === 0) return Promise.resolve({ anomalies: ANOMALIES });
  if (p.indexOf('/api/baseline/profile') === 0) return Promise.resolve({ profile: PROFILE });
  if (p.indexOf('/api/baseline/status') === 0) return Promise.resolve(STATUS);
  return Promise.resolve({});
};
FS.post = function(){ return Promise.resolve({ ok:true }); };
load('web/static/pages.js');

// Test: anomalies page renders without error
if (typeof FS !== 'undefined' && FS.pages && FS.pages.anomalies) {
  (async function() {
    try {
      var el = { innerHTML: '' };
      await FS.pages.anomalies.render(el);
      if (!el.innerHTML.includes('office-mac')) {
        fail(new Error('Anomalies page should render device names'));
      }
      if (!el.innerHTML.includes('First connection to IE')) {
        fail(new Error('Anomalies page should render anomaly titles'));
      }
    } catch (e) {
      fail(e);
    }
  })();
} else {
  fail(new Error('FS.pages.anomalies not registered'));
}
