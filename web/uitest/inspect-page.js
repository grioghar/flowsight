/* UI tests for packet inspection page */
'use strict';

const fixtures = {
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

// Mock the FS API calls
const originalGet = window.FS?.get;
const originalPost = window.FS?.post;

const mockGet = async (url) => {
  if (url.includes('/api/inspect/states/summary')) return fixtures.statesSummary;
  if (url.includes('/api/inspect/states')) return fixtures.states;
  if (url.includes('/api/inspect/captures')) return fixtures.captures;
  if (url.includes('/api/inspect/capture/') && url.includes('/download')) {
    return { id: 'cap_1726747200', name: 'flowsight-cap_1726747200.pcap', files: ['cap_1726747200.pcap'] };
  }
  if (url.includes('/api/inspect/capture/')) return fixtures.captureAnalysis;
  return { error: 'not found' };
};

const mockPost = async (url, body) => {
  if (url.includes('/api/inspect/capture/start')) return { id: 'cap_test', status: 'started', iface: body.iface };
  if (url.includes('/api/inspect/capture/stop')) return { status: 'stopping' };
  return { error: 'not found' };
};

if (typeof window.FS !== 'undefined') {
  window.FS.get = mockGet;
  window.FS.post = mockPost;
}

// Test suite
describe('Packet Inspection Page', () => {
  let el, ctx;

  beforeEach(() => {
    el = document.createElement('div');
    ctx = {};
  });

  it('renders the states tab with summary KPIs', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const statesPane = el.querySelector('[data-pane="states"]');
    if (!statesPane) throw new Error('states pane not found');

    statesPane.classList.add('active');

    const kpis = statesPane.querySelectorAll('[data-kpi]');
    if (kpis.length < 2) throw new Error('expected at least 2 KPIs, got ' + kpis.length);
  }).catch(fail);

  it('renders states table with filtering', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const statesPane = el.querySelector('[data-pane="states"]');
    const table = statesPane?.querySelector('table');
    if (!table) throw new Error('states table not found');

    const rows = table.querySelectorAll('tbody tr');
    if (rows.length < 2) throw new Error('expected at least 2 state rows, got ' + rows.length);
  }).catch(fail);

  it('renders capture tab with form and capture list', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    if (!captureBtn) throw new Error('capture tab button not found');

    captureBtn.click();

    const form = el.querySelector('#capture-form');
    if (!form) throw new Error('capture form not found');

    const capturesList = el.querySelector('#captures-list');
    if (!capturesList) throw new Error('captures list not found');
  }).catch(fail);

  it('renders protocol hierarchy chart in capture analysis', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    if (!captureBtn) throw new Error('capture tab button not found');

    captureBtn.click();

    const analyzeBtn = el.querySelector('[data-analyze]');
    if (!analyzeBtn) throw new Error('analyze button not found');

    analyzeBtn.click();
    await new Promise(r => setTimeout(r, 100));

    const chart = el.querySelector('svg');
    if (!chart) throw new Error('protocol chart SVG not found');

    const bars = chart.querySelectorAll('rect');
    if (bars.length < 1) throw new Error('expected at least 1 bar in chart, got ' + bars.length);
  }).catch(fail);

  it('renders conversation table with TCP details', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    captureBtn.click();

    const analyzeBtn = el.querySelector('[data-analyze]');
    analyzeBtn.click();
    await new Promise(r => setTimeout(r, 100));

    const table = el.querySelector('table');
    if (!table) throw new Error('table not found');

    const rows = table.querySelectorAll('tbody tr');
    if (rows.length < 2) throw new Error('expected at least 2 conversation rows, got ' + rows.length);

    const firstRow = rows[0];
    const cells = firstRow.querySelectorAll('td');
    if (!cells[0]?.textContent?.includes('192.168.1.100')) {
      throw new Error('first row should contain 192.168.1.100');
    }
  }).catch(fail);

  it('handles capture form submission', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    captureBtn.click();

    const form = el.querySelector('#capture-form');
    form.iface.value = 'em0';
    form.filter.value = 'tcp port 443';
    form.seconds.value = '60';

    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.click();
    await new Promise(r => setTimeout(r, 100));

    const status = el.querySelector('#capture-status');
    if (!status?.textContent?.includes('Starting')) {
      throw new Error('capture status should show "Starting"');
    }
  }).catch(fail);

  it('displays DNS records from capture analysis', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    captureBtn.click();

    const analyzeBtn = el.querySelector('[data-analyze]');
    analyzeBtn.click();
    await new Promise(r => setTimeout(r, 100));

    const dnsText = el.innerHTML;
    if (!dnsText.includes('example.com')) {
      throw new Error('DNS records not displayed');
    }
  }).catch(fail);

  it('displays expert notes with severity', async () => {
    const page = window.FS?.pages?.find(p => p.id === 'inspect');
    if (!page) throw new Error('inspect page not registered');

    await page.render(el, ctx);

    const captureBtn = el.querySelector('[data-tab="capture"]');
    captureBtn.click();

    const analyzeBtn = el.querySelector('[data-analyze]');
    analyzeBtn.click();
    await new Promise(r => setTimeout(r, 100));

    const expertText = el.innerHTML;
    if (!expertText.includes('retransmission')) {
      throw new Error('expert notes not displayed');
    }
  }).catch(fail);
});
