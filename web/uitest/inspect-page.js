/* UI tests for packet inspection page */
'use strict';

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
var console = { log: function(){}, error: function(){}, warn: function(){} };

var fixtures = {
  statesSummary: {
    total_states: 156,
    by_proto: { tcp: 120, udp: 30, icmp: 6 },
    by_state: { ESTABLISHED: 100, SYN_SENT: 20, SYN_RCVD: 30, FIN_WAIT: 6 },
    half_open_count: 20,
    table_util_pct: 0.78,
    new_states_per_sec: 1.2,
  },
  states: {
    states: [
      {
        proto: 'tcp', direction: 'in', src: '10.0.0.1', dst: '192.168.1.100', src_port: 443, dst_port: 54321,
        state: 'ESTABLISHED', age: 145, expires: 3455, pkts_src: 1024, bytes_src: 512000, pkts_dst: 856, bytes_dst: 256000, rule_id: 0, interface: 'em0'
      },
      {
        proto: 'tcp', direction: 'in', src: '10.0.0.2', dst: '192.168.1.101', src_port: 80, dst_port: 54322,
        state: 'ESTABLISHED', age: 87, expires: 3513, pkts_src: 512, bytes_src: 128000, pkts_dst: 456, bytes_dst: 96000, rule_id: 1, interface: 'em0'
      },
      {
        proto: 'tcp', direction: 'out', src: '192.168.1.102', dst: '8.8.8.8', src_port: 53421, dst_port: 443,
        state: 'SYN_SENT', age: 2, expires: 3598, pkts_src: 1, bytes_src: 60, pkts_dst: 0, bytes_dst: 0, rule_id: 0, interface: 'em0'
      },
      {
        proto: 'udp', direction: 'out', src: '192.168.1.103', dst: '8.8.8.8', src_port: 53422, dst_port: 53,
        state: 'SINGLE', age: 29, expires: 3571, pkts_src: 2, bytes_src: 120, pkts_dst: 2, bytes_dst: 256, rule_id: 0, interface: 'em0'
      },
    ],
    count: 4,
  },
  captures: {
    captures: [
      {
        id: 'cap_1726747200', iface: 'em0', filter: 'tcp port 443', started: '2026-09-19T12:00:00Z', ended: '2026-09-19T12:01:00Z',
        packets: 45000, bytes: 28000000, files: ['cap_1726747200.pcap'], timestamp: '2026-09-19T12:01:00Z'
      },
      {
        id: 'cap_1726747260', iface: 'em1', filter: '', started: '2026-09-19T12:02:00Z', ended: null,
        packets: 0, bytes: 0, files: [], timestamp: '2026-09-19T12:02:00Z'
      }
    ]
  },
  captureAnalysis: {
    id: 'cap_1726747200',
    iface: 'em0',
    filter: 'tcp port 443',
    started: '2026-09-19T12:00:00Z',
    ended: '2026-09-19T12:01:00Z',
    packets: 45000,
    bytes: 28000000,
    analysis: {
      packet_count: 45000,
      byte_count: 28000000,
      conversations: [
        {
          five_tuple: '192.168.1.100:54321-10.0.0.1:443',
          proto: 'tcp', src: '192.168.1.100', src_port: 54321, dst: '10.0.0.1', dst_port: 443,
          pkts_fwd: 1024, bytes_fwd: 512000, pkts_rev: 856, bytes_rev: 256000,
          first_seen: '2026-09-19T12:00:10Z', last_seen: '2026-09-19T12:00:55Z',
          tcp_flags: 'SYN,ACK,PSH,FIN', retransmissions: 2, out_of_order: 0, zero_window: 0, resets: 0, rtt_estimate: 0.024
        },
        {
          five_tuple: '192.168.1.101:54322-10.0.0.2:443',
          proto: 'tcp', src: '192.168.1.101', src_port: 54322, dst: '10.0.0.2', dst_port: 443,
          pkts_fwd: 512, bytes_fwd: 128000, pkts_rev: 456, bytes_rev: 96000,
          first_seen: '2026-09-19T12:00:20Z', last_seen: '2026-09-19T12:00:45Z',
          tcp_flags: 'SYN,ACK,PSH', retransmissions: 0, out_of_order: 0, zero_window: 0, resets: 0, rtt_estimate: 0.032
        }
      ],
      protocol_counts: { tcp: 40000, tls: 30000, http: 15000 },
      dns_queries: [
        { query: 'example.com', type: 'A', answers: ['93.184.216.34'], src: '192.168.1.100', dst: '8.8.8.8', timestamp: '2026-09-19T12:00:05Z' },
        { query: 'cdn.example.com', type: 'CNAME', answers: ['cdn-edge.example.com'], src: '192.168.1.101', dst: '8.8.8.8', timestamp: '2026-09-19T12:00:12Z' }
      ],
      tls_handshakes: [
        { sni: 'example.com', ja3: 'aabbccdd11223344', src: '192.168.1.100', dst: '10.0.0.1', cert_cn: 'example.com', cert_san: ['example.com', '*.example.com'], timestamp: '2026-09-19T12:00:15Z' }
      ],
      http_requests: [
        { method: 'GET', host: 'example.com', path: '/', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', src: '192.168.1.100', dst: '10.0.0.1', timestamp: '2026-09-19T12:00:20Z' },
        { method: 'POST', host: 'api.example.com', path: '/v1/data', user_agent: 'curl/7.68.0', src: '192.168.1.101', dst: '10.0.0.2', timestamp: '2026-09-19T12:00:25Z' }
      ],
      expert_notes: [
        { type: 'retransmission', src: '192.168.1.100', dst: '10.0.0.1', detail: 'TCP segment retransmitted at 2026-09-19T12:00:35Z', severity: 'warn', timestamp: '2026-09-19T12:00:35Z' },
        { type: 'zero_window', src: '192.168.1.101', dst: '10.0.0.2', detail: 'Zero window advertised', severity: 'warn', timestamp: '2026-09-19T12:00:40Z' }
      ],
      top_talkers: [
        { ip: '192.168.1.100', bytes: 15000000, pkts: 18000 },
        { ip: '192.168.1.101', bytes: 8000000, pkts: 12000 },
        { ip: '10.0.0.1', bytes: 12000000, pkts: 15000 }
      ],
      timeline: [
        { timestamp: '2026-09-19T12:00:10Z', type: 'syn', src: '192.168.1.100', dst: '10.0.0.1' },
        { timestamp: '2026-09-19T12:00:11Z', type: 'ack', src: '10.0.0.1', dst: '192.168.1.100' },
        { timestamp: '2026-09-19T12:00:12Z', type: 'dns', src: '192.168.1.100', dst: '8.8.8.8' }
      ]
    }
  }
};

// Mock helper functions
var esc = function(x){ return x; };
var num = function(x){ return String(x); };
var bytes = function(x){ return (x / 1024 / 1024).toFixed(2) + ' MB'; };
var ago = function(t){ return 'ago'; };
var when = function(t){ return 'when'; };
var pill = function(x){ return '<span class="pill">' + x + '</span>'; };
var card = function(title, content){ return '<div class="card"><h3>' + title + '</h3>' + content + '</div>'; };
var kpi = function(label, value, detail){ return '<div class="kpi">' + label + ': ' + value + '</div>'; };
var table = function(rows, cols){ var html = '<table><tbody>';
  rows.forEach(function(r){ html += '<tr>'; cols.forEach(function(c){ html += '<td>' + (c.f ? c.f(r) : r[c.k] || '') + '</td>'; }); html += '</tr>'; });
  html += '</tbody></table>'; return html; };

var FS = {
  registeredPages:{},
  registerPage:function(k,v){ this.registeredPages[k]=v; },
  pages: [],
  esc: esc,
  num: num,
  bytes: bytes,
  ago: ago,
  when: when,
  pill: pill,
  card: card,
  kpi: kpi,
  table: table,
  get: function(url){
    if (url.includes('/api/inspect/states/summary')) return Promise.resolve(fixtures.statesSummary);
    if (url.includes('/api/inspect/states')) return Promise.resolve(fixtures.states);
    if (url.includes('/api/inspect/captures')) return Promise.resolve(fixtures.captures);
    if (url.includes('/api/inspect/capture/')) return Promise.resolve(fixtures.captureAnalysis);
    return Promise.resolve({error:'not found'});
  },
  post: function(url, body){
    if (url.includes('/api/inspect/capture/start')) return Promise.resolve({ id: 'cap_test', status: 'started', iface: body.iface });
    if (url.includes('/api/inspect/capture/stop')) return Promise.resolve({ status: 'stopping' });
    return Promise.resolve({error:'not found'});
  },
  toast: function(msg, isError){},
  err: function(msg){ return '<div class="error">' + msg + '</div>'; },
  render: function(){},
  $$: function(selector){ return []; },
  $: function(selector){ return mkEl(); }
};
// Make window.FS.FS = FS for the destructuring in inspect.js
window.FS = FS;
window.FS.FS = FS;

// Load the actual inspect.js page
load('web/static/inspect.js');

function testInspectPage(){
  var el = mkEl(); el.innerHTML = '';
  var page = FS.registeredPages['inspect'];
  if(!page) { fail('inspect page not registered'); return Promise.resolve(); }

  return page.render(el).then(function(){
    // Check that tabs are present
    if(!el.innerHTML.includes('States')) fail('states tab missing');
    if(!el.innerHTML.includes('Capture')) fail('capture tab missing');

    // Check that the page renders without errors
    console.log('Packet Inspection page renders all tabs and sections OK');
  }).catch(function(e){ fail(e); });
}

// Run the test
testInspectPage().then(function(){
  if(FAILURE) {
    print('FAIL: ' + FAILURE.message);
    throw FAILURE;
  }
});
