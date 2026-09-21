/* FlowSight pages: visibility. Each page is {title, render(el, ctx)} */
'use strict';
(function () {
  const { esc, num, bytes, bps, dur, ago, when, pill, card, kpi, table, bars, chart, donut, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Overview
  FS.registerPage('overview', {
    title: 'Overview', refresh: 15,
    async render(el) {
      const [sum, top, ts, health, findings, dns] = await Promise.all([
        get('/api/visibility/summary'), get(`/api/visibility/top?${FS.since()}&limit=8`),
        get(`/api/visibility/timeseries?${FS.since()}`), get('/api/system/health'),
        get('/api/system/findings'), get(`/api/dns/summary?${FS.since()}&limit=8`)]);
      if (sum.error && !sum.throughput_bps) { el.innerHTML = FS.err('Visibility unavailable: ' + sum.error); return; }
      const traffic = ts.traffic || [];
      const openF = (findings.findings || []).filter(f => !f.acked);
      const sev = { critical: 0, high: 0, medium: 0, low: 0 }; openF.forEach(f => sev[f.severity] = (sev[f.severity] || 0) + 1);
      el.innerHTML = `
      <div class="grid cols-6">
        ${kpi('Throughput', bps(sum.throughput_bps), (sum.throughput_download_bps || sum.throughput_upload_bps) ? `↓ ${bps(sum.throughput_download_bps)} · ↑ ${bps(sum.throughput_upload_bps)} · ${num(sum.throughput_pps)} pps` : num(sum.throughput_pps) + ' pps')}
        ${kpi('Active flows', num(sum.active_flows), num(sum.flows_last_hour) + ' in the last hour')}
        ${kpi('Active hosts', num(sum.active_hosts), num(sum.hosts_last_hour) + ' local, last hour')}
        ${kpi('Blocked', num(sum.blocked_last_hour + (sum.dns_blocked_last_hour || 0)), 'last hour (web + DNS)', sum.blocked_last_hour ? 'warn' : '')}
        ${kpi('Threats', num(sum.alerts_last_hour), 'IDS alerts, last hour', sum.alerts_last_hour ? 'bad' : '')}
        ${kpi('Findings', num(openF.length), `${sev.critical + sev.high} high or critical`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Traffic', chart([{ name: 'download', points: traffic.map(p => [p.t, p.bytes_in]) }, { name: 'upload', points: traffic.map(p => [p.t, p.bytes_out]) }], { fmt: bytes, area: true, tall: true }) + FS.legend(['download', 'upload']))}
        ${card('Throughput', chart(((ts.throughput_download_bps || []).length || (ts.throughput_upload_bps || []).length)
          ? [{ name: 'inbound (download)', points: (ts.throughput_download_bps || []).map(p => [p.t, p.v]) }, { name: 'outbound (upload)', points: (ts.throughput_upload_bps || []).map(p => [p.t, p.v]) }]
          : [{ name: 'bps', points: (ts.throughput_bps || []).map(p => [p.t, p.v]) }], { fmt: bps, area: true, tall: true }) + FS.legend(['inbound (download)', 'outbound (upload)']), 'inbound and outbound')}
      </div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Top hosts', bars((top.hosts || []).map(h => ({ label: h.name || h.ip, sub: h.name ? h.ip : '', value: (h.bytes_in || 0) + (h.bytes_out || 0), href: '#host/' + h.ip })), bytes))}
        ${card('Top applications', bars((top.apps || []).map(a => ({ label: a.app, sub: a.category, value: (a.bytes_in || 0) + (a.bytes_out || 0), href: '#flows?app=' + encodeURIComponent(a.app) })), bytes))}
        ${card('Top categories', donut((top.categories || []).map(c => ({ label: c.category, value: (c.bytes_in || 0) + (c.bytes_out || 0) })), bytes))}
      </div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Top sites', bars((top.domains || []).map(d => ({ label: d.domain, sub: d.category || '', value: (d.bytes_in || 0) + (d.bytes_out || 0), href: '#flows?domain=' + encodeURIComponent(d.domain) })), bytes))}
        ${card('Blocked', bars((top.blocked || []).map(b => ({ label: (b.name || b.ip) + ' → ' + b.app, value: b.flows, href: '#host/' + b.ip }))) )}
        ${card('DNS', dns.error ? FS.err(dns.error) : `<div class="kv"><dt>Queries</dt><dd>${num((dns.totals || {}).queries)}</dd><dt>Blocked</dt><dd>${num((dns.totals || {}).blocked)} (${FS.pct((dns.totals || {}).blocked, (dns.totals || {}).queries)})</dd><dt>Clients</dt><dd>${num((dns.totals || {}).clients)}</dd><dt>Domains</dt><dd>${num((dns.totals || {}).domains)}</dd></div><div style="margin-top:8px">${bars((dns.blocked || []).slice(0, 5).map(d => ({ label: d.domain, value: d.queries, sub: d.list })))}</div>`)}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Modules', Object.entries(health.modules || {}).map(([n, m]) => `<div class="barrow" style="grid-template-columns:auto 1fr auto"><span><i class="dot ${m.ok ? 'ok' : 'bad'}"></i><b>${esc(n)}</b></span><span class="muted small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.detail || '')}</span><span class="small muted">${(m.capabilities || []).join(', ')}</span></div>`).join(''), `<a href="#system">details</a>`)}
        ${card('Open findings', openF.length ? table(openF.slice(0, 8), [{ t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' }, { t: 'Finding', f: r => `<b>${esc(r.title)}</b><div class="muted small">${esc(r.detail || '').slice(0, 140)}</div>` }, { t: 'Module', k: 'module' }, { t: 'Since', f: r => ago(r.ts), sort: 'ts' }]) : FS.empty('No open findings'), `<a href="#findings">all</a>`)}
      </div>`;
    }
  });

  // ------------------------------------------------------------- Hosts
  FS.registerPage('hosts', {
    title: 'Hosts', refresh: 30,
    async render(el, ctx) {
      const d = await get(`/api/identity/hosts?${FS.since()}${ctx.params.all ? '&all=1' : ''}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      let rows = d.hosts || [];
      const q = (ctx.params.q || '').toLowerCase();
      if (q) rows = rows.filter(h => JSON.stringify(h).toLowerCase().includes(q));
      el.innerHTML = `<div class="actions"><span class="muted">${rows.length} hosts seen in the last ${FS.state.hours}h</span><span class="spacer" style="flex:1"></span><a class="btn" href="#hosts?all=1">Include inactive</a></div>` +
        card('Hosts', table(rows, [
          { t: 'Host', f: r => hostLink(r.ip, r.name), sort: 'name' },
          { t: 'MAC', f: r => `<span class="mono">${esc(r.mac || '')}</span>${r.randomized ? ' ' + pill('private', '') : ''}`, sort: 'mac' },
          { t: 'Vendor', k: 'vendor' }, { t: 'Zone', f: r => r.zone ? pill(r.zone, 'info') : '', sort: 'zone' },
          { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
          { t: 'Flows', f: r => num(r.flows), num: true, sort: 'flows' }, { t: 'Blocked', f: r => r.blocked ? `<span class="sev-high">${num(r.blocked)}</span>` : '0', num: true, sort: 'blocked' },
          { t: 'Alerts', f: r => r.alerts ? `<span class="sev-high">${num(r.alerts)}</span>` : '0', num: true, sort: 'alerts' },
          { t: 'Last seen', f: r => ago(r.last_seen), sort: 'last_seen' }]));
    }
  });

  // ------------------------------------------------------------- Host detail
  FS.registerPage('host', {
    title: 'Host', refresh: 30,
    async render(el, ctx) {
      const ip = ctx.arg; if (!ip) { el.innerHTML = FS.err('no host given'); return; }
      const d = await get(`/api/visibility/host?ip=${encodeURIComponent(ip)}&${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const h = d.host || {}, dev = d.device || {}, t = d.totals || {}, dt = d.dns_totals || {};
      FS.setTitle((h.name || ip) + (h.name ? ` · ${ip}` : ''));
      el.innerHTML = `
      <div class="grid cols-4">
        ${card('Identity', `<dl class="kv"><dt>Address</dt><dd class="mono">${esc(ip)}</dd><dt>Name</dt><dd>${esc(h.name || '—')} <a href="#" id="rename" class="small">rename</a></dd><dt>MAC</dt><dd class="mono">${esc(h.mac || '—')}</dd><dt>Vendor</dt><dd>${esc(h.vendor || '—')}</dd><dt>Zone</dt><dd>${esc(dev.zone || h.zone || '—')}</dd><dt>Class</dt><dd>${esc(dev.class || dev.device_type || h.device_type || '—')}</dd><dt>First seen</dt><dd>${h.first_seen ? when(h.first_seen) : '—'}</dd><dt>Last seen</dt><dd>${ago(h.last_seen)}</dd></dl>`)}
        ${kpi('Traffic', bytes((t.bytes_in || 0) + (t.bytes_out || 0)), `${bytes(t.bytes_in)} down · ${bytes(t.bytes_out)} up`)}
        ${kpi('Flows', num(t.flows), `${num(t.blocked)} blocked`, t.blocked ? 'warn' : '')}
        ${kpi('DNS', num(dt.queries), `${num(dt.blocked)} blocked · ${num(dt.domains)} domains`, dt.blocked ? 'warn' : '')}
      </div>
      <div style="margin-top:14px">${card('Activity', chart([{ name: 'download', points: (d.timeline || []).map(p => [p.t, p.bytes_in]) }, { name: 'upload', points: (d.timeline || []).map(p => [p.t, p.bytes_out]) }, { name: 'blocked', points: (d.timeline || []).map(p => [p.t, p.blocked]) , color: '#dc2626'}], { fmt: bytes, area: true, tall: true }) + FS.legend(['download', 'upload', 'blocked flows']))}</div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Applications', bars((d.apps || []).map(a => ({ label: a.app, sub: a.category, value: (a.bytes_in || 0) + (a.bytes_out || 0) })), bytes))}
        ${card('Sites', bars((d.domains || []).map(a => ({ label: a.domain, sub: a.category || '', value: (a.bytes_in || 0) + (a.bytes_out || 0), href: '#flows?ip=' + ip + '&domain=' + encodeURIComponent(a.domain) })), bytes))}
        ${card('Destinations', bars((d.destinations || []).map(a => ({ label: a.name || a.ip, sub: `${a.ip}:${a.port}/${a.proto}`, value: (a.bytes_in || 0) + (a.bytes_out || 0) })), bytes))}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('DNS', table(d.dns || [], [{ t: 'Domain', f: r => domainLink(r.domain) }, { t: 'Action', f: r => r.action === 'pass' ? pill('pass', 'ok') : pill(r.action + (r.list ? ' · ' + r.list : ''), 'bad'), sort: 'action' }, { t: 'Queries', k: 'queries', num: true }]))}
        ${card('TLS', table(d.tls || [], [{ t: 'Server name', k: 'sni' }, { t: 'Version', k: 'version' }, { t: 'Mode', f: r => pill(r.mode || 'splice', r.mode === 'bump' ? 'warn' : r.mode === 'terminate' ? 'bad' : ''), sort: 'mode' }, { t: 'Sessions', k: 'sessions', num: true }]))}
      </div>
      <div style="margin-top:14px">${card('Recent flows', table(d.flows || [], [{ t: 'When', f: r => when(r.end_ts || r.ts), sort: 'ts' }, { t: 'Destination', f: r => `${FS.ipTag(r.dst_ip, r.dst_name)}:${r.dst_port} <span class="muted small">${esc(r.proto)}</span>`, sort: 'dst_ip' }, { t: 'Application', f: r => `${esc(r.app || '')} <span class="muted small">${esc(r.category || '')}</span>`, sort: 'app' }, { t: 'Site', f: r => esc(r.domain || ''), sort: 'domain' }, { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' }, { t: 'Verdict', f: r => FS.verdictPill(r.verdict) + (r.policy ? ` <span class="muted small">${esc(r.policy)}</span>` : ''), sort: 'verdict' }]))}</div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Alerts', table(d.alerts || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' }, { t: 'Signature', k: 'signature' }, { t: 'Peer', f: r => r.src_ip === ip ? esc(r.dst_ip) : esc(r.src_ip) }]))}
        ${card('Findings', table(d.findings || [], [{ t: 'Severity', f: r => FS.sevPill(r.severity) }, { t: 'Finding', f: r => `<b>${esc(r.title)}</b><div class="muted small">${esc(r.detail || '')}</div>` }]))}
      </div>`;
      FS.$('#rename', el).onclick = async (e) => { e.preventDefault(); const name = prompt('Display name for ' + ip, h.name || ''); if (name === null) return; const r = await post('/api/identity/name', { ip, name }); if (r.error) FS.toast(r.error, true); else FS.render(); };
    }
  });

  // ------------------------------------------------------------- Flows / sessions
  FS.registerPage('flows', {
    title: 'Sessions', refresh: 10,
    async render(el, ctx) {
      const p = ctx.params; const qs = new URLSearchParams({ minutes: p.minutes || 30, limit: 500 });
      if (p.ip) qs.set('ip', p.ip); if (p.app) qs.set('app', p.app); if (p.blocked) qs.set('blocked', '1');
      const d = await get('/api/visibility/flows?' + qs);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      let rows = d.flows || [];
      if (p.domain) rows = rows.filter(f => (f.domain || '').includes(p.domain));
      const filt = (k, v) => v ? `<span class="chip">${esc(k)}: ${esc(v)} <button data-k="${esc(k)}">×</button></span>` : '';
      el.innerHTML = `<div class="actions"><div class="chips">${filt('ip', p.ip)}${filt('app', p.app)}${filt('domain', p.domain)}${p.blocked ? filt('only', 'blocked') : ''}</div><span style="flex:1"></span><div class="seg" id="win">${[15, 30, 60, 240, 1440].map(m => `<button data-m="${m}" class="${String(p.minutes || 30) === String(m) ? 'on' : ''}">${m < 60 ? m + 'm' : (m / 60) + 'h'}</button>`).join('')}</div><a class="btn" href="#flows?blocked=1${p.ip ? '&ip=' + p.ip : ''}">Blocked only</a></div>` +
        card(`${rows.length} sessions`, table(rows, [
          { t: 'When', f: r => when(r.end_ts || r.ts), sort: 'ts' },
          { t: 'Client', f: r => hostLink(r.src_ip, r.src_name), sort: 'src_ip' },
          { t: 'Server', f: r => `${FS.ipTag(r.dst_ip, r.dst_name)}:${r.dst_port}`, sort: 'dst_ip' },
          { t: 'App', f: r => `<a href="#flows?app=${encodeURIComponent(r.app || '')}">${esc(r.app || '')}</a> <span class="muted small">${esc(r.category || '')}</span>`, sort: 'app' },
          { t: 'Site', f: r => domainLink(r.domain), sort: 'domain' },
          { t: 'Proto', f: r => `${esc(r.proto || '')}${r.tls_version ? ' <span class="muted small">' + esc(r.tls_version) + '</span>' : ''}`, sort: 'proto' },
          { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
          { t: 'Duration', f: r => dur(r.duration), num: true, sort: 'duration' },
          { t: 'Verdict', f: r => FS.verdictPill(r.verdict) + (r.policy ? ` <span class="muted small">${esc(r.policy)}</span>` : ''), sort: 'verdict' },
          { t: 'Source', k: 'source' }]));
      FS.$$('#win button', el).forEach(b => b.onclick = () => { p.minutes = b.dataset.m; FS.go('#flows?' + new URLSearchParams(p)); });
      FS.$$('.chip button', el).forEach(b => b.onclick = () => { delete p[b.dataset.k === 'only' ? 'blocked' : b.dataset.k]; FS.go('#flows?' + new URLSearchParams(p)); });
    }
  });

  // ------------------------------------------------------------- Applications
  FS.registerPage('apps', {
    title: 'Applications', refresh: 30,
    async render(el) {
      const d = await get(`/api/visibility/apps?${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const rows = d.apps || [];
      const byCat = {}; rows.forEach(a => { const c = a.category || 'Unknown'; byCat[c] = (byCat[c] || 0) + (a.bytes_in || 0) + (a.bytes_out || 0); });
      const breedPill = b => b ? pill(b, { Safe: 'ok', Acceptable: 'ok', Fun: 'info', Unsafe: 'warn', Dangerous: 'bad', Potentially_Dangerous: 'warn' }[b] || '') : '';
      el.innerHTML = `<div class="two">${card('Applications', table(rows, [
        { t: 'Application', f: r => `<a href="#flows?app=${encodeURIComponent(r.app)}">${esc(r.app)}</a>`, sort: 'app' },
        { t: 'Category', k: 'category' }, { t: 'Breed', f: r => breedPill(r.breed), sort: 'breed' },
        { t: 'Hosts', k: 'hosts', num: true }, { t: 'Flows', f: r => num(r.flows), num: true, sort: 'flows' },
        { t: 'Blocked', f: r => r.blocked ? `<span class="sev-high">${num(r.blocked)}</span>` : '0', num: true, sort: 'blocked' },
        { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
        { t: 'Block', f: r => `<button class="btn small" data-app="${esc(r.app)}">policy…</button>` }]))}
      <div class="stack">${card('By category', donut(Object.entries(byCat).map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value), bytes))}${card('About', `<p class="small muted">Applications are identified by nDPI on the first packets of each flow. Breed is nDPI's own risk grouping. Use <b>policy…</b> to deny an application for a group of devices; enforcement is at the firewall and needs no inline engine.</p>`)}</div></div>`;
      FS.$$('button[data-app]', el).forEach(b => b.onclick = () => FS.quickPolicy({ apps: [b.dataset.app] }));
    }
  });

  // ------------------------------------------------------------- Web
  FS.registerPage('web', {
    title: 'Web', refresh: 30,
    async render(el, ctx) {
      const [s, l, st] = await Promise.all([get(`/api/web/summary?${FS.since()}&limit=12`), get('/api/web/log?limit=300' + (ctx.params.blocked ? '&blocked=1' : '')), get('/api/web/status')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {};
      const state = !st.intercepting ? pill('interception off', 'warn') : st.running ? pill('intercepting', 'ok') : pill('proxy down', 'bad');
      el.innerHTML = `<div class="grid cols-4">${kpi('Requests', num(t.requests), `${num(t.domains)} sites · ${num(t.clients)} clients`)}${kpi('Blocked', num(t.blocked), FS.pct(t.blocked, t.requests) + ' of requests', t.blocked ? 'warn' : '')}${kpi('TLS handling', (s.tls_modes || []).map(m => `${esc(m.mode || 'splice')} ${num(m.sessions)}`).join(' · ') || '—', 'splice = untouched, bump = inspected')}${card('Proxy', `<div>${state}</div><div class="small muted" style="margin-top:6px">${esc(st.error || (st.intercepting ? 'Port 80 and 443 from local networks pass through the FlowSight proxy.' : 'Enable interception in the web module settings to see server names and block sites.'))}</div><div class="actions"><a class="btn" href="#modules/web">Settings</a></div>`)}</div>
      <div class="grid cols-3" style="margin-top:14px">${card('Top sites', bars((s.sites || []).map(d => ({ label: d.domain, sub: d.category || '', value: d.requests, href: '#flows?domain=' + encodeURIComponent(d.domain) }))))}${card('Categories', donut((s.categories || []).map(c => ({ label: c.category, value: c.requests }))))}${card('Blocked sites', bars((s.blocked || []).map(d => ({ label: d.domain, value: d.requests }))))}</div>
      <div style="margin-top:14px">${card('Requests', table(l.requests || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Client', f: r => hostLink(r.src_ip, r.src_name), sort: 'src_ip' }, { t: 'Site', f: r => domainLink(r.domain), sort: 'domain' }, { t: 'Category', k: 'category' }, { t: 'Proto', f: r => esc(r.proto) + (r.tls_version ? ' <span class="muted small">' + esc(r.tls_version) + '</span>' : '') }, { t: 'Bytes', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Verdict', f: r => FS.verdictPill(r.verdict), sort: 'verdict' }]), `<a href="#web?blocked=1">blocked only</a>`)}</div>`;
    }
  });

  // ------------------------------------------------------------- DNS
  FS.registerPage('dns', {
    title: 'DNS', refresh: 30,
    async render(el, ctx) {
      const p = ctx.params; const lq = new URLSearchParams({ limit: 300 }); if (p.client) lq.set('client', p.client); if (p.domain) lq.set('domain', p.domain); if (p.blocked) lq.set('blocked', '1');
      const [s, l, ts] = await Promise.all([get(`/api/dns/summary?${FS.since()}&limit=12`), get('/api/dns/log?' + lq), get(`/api/dns/timeseries?${FS.since()}`)]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {}, live = s.live || {};
      el.innerHTML = `<div class="grid cols-5" style="grid-template-columns:repeat(5,minmax(0,1fr))">${kpi('Queries', num(t.queries), `${num(t.clients)} clients · ${num(t.domains)} domains`)}${kpi('Blocked', num(t.blocked), FS.pct(t.blocked, t.queries), t.blocked ? 'warn' : '')}${kpi('Cache hits', FS.pct(live.cached, live.queries), 'of answers (raw window)')}${kpi('Failures', num((live.nxdomain || 0) + (live.servfail || 0)), `${num(live.nxdomain)} NXDOMAIN · ${num(live.servfail)} SERVFAIL`)}${kpi('Latency', (live.avg_ms || 0).toFixed(1) + ' ms', 'average resolution')}</div>
      <div style="margin-top:14px">${card('Queries over time', chart([{ name: 'queries', points: (ts.series || []).map(x => [x.t, x.queries]) }, { name: 'blocked', points: (ts.series || []).map(x => [x.t, x.blocked]), color: '#dc2626' }], { area: true, tall: true }) + FS.legend(['queries', 'blocked']))}</div>
      <div class="grid cols-4" style="margin-top:14px">${card('Top domains', bars((s.top || []).map(d => ({ label: d.domain, value: d.queries, href: '#dns?domain=' + encodeURIComponent(d.domain) }))))}${card('Most blocked', bars((s.blocked || []).map(d => ({ label: d.domain, sub: d.list, value: d.queries }))))}${card('Clients', bars((s.clients || []).map(c => ({ label: c.name || c.ip, sub: `${num(c.blocked)} blocked`, value: c.queries, href: '#dns?client=' + c.ip }))))}${card('Blocked by', donut((s.lists || []).map(x => ({ label: x.list, value: x.queries }))))}</div>
      <div style="margin-top:14px">${card('Query log', `<div class="chips" style="margin-bottom:8px">${p.client ? `<span class="chip">client: ${esc(p.client)} <a href="#dns">×</a></span>` : ''}${p.domain ? `<span class="chip">domain: ${esc(p.domain)} <a href="#dns">×</a></span>` : ''}</div>` + table(l.queries || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Client', f: r => hostLink(r.client, r.client_name), sort: 'client' }, { t: 'Domain', f: r => `<a href="#dns?domain=${encodeURIComponent(r.domain)}">${esc(r.domain)}</a>`, sort: 'domain' }, { t: 'Type', k: 'qtype' }, { t: 'Result', f: r => r.action === 'pass' ? pill(r.rcode || 'ok', r.rcode === 'NOERROR' ? 'ok' : '') : pill('blocked' + (r.list ? ' · ' + r.list : ''), 'bad'), sort: 'action' }, { t: 'Source', k: 'answer_source' }, { t: 'ms', f: r => (r.ms || 0).toFixed(0), num: true, sort: 'ms' }]), `<a href="#dns?blocked=1">blocked only</a>`)}</div>`;
    }
  });

  // ------------------------------------------------------------- Threats
  FS.registerPage('threats', {
    title: 'Threats', refresh: 30,
    async render(el, ctx) {
      const [s, a] = await Promise.all([get(`/api/ids/summary?${FS.since()}`), get(`/api/ids/alerts?${FS.since()}&limit=300${ctx.params.severity ? '&severity=' + ctx.params.severity : ''}`)]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const sev = {}; (s.by_severity || []).forEach(x => sev[x.severity] = x.alerts);
      el.innerHTML = `<div class="grid cols-4">${kpi('Alerts', num(s.total), `${num(s.blocked)} dropped by IPS`, s.total ? 'warn' : '')}${kpi('Critical / high', num((sev.critical || 0) + (sev.high || 0)), `${num(sev.medium)} medium · ${num(sev.low)} low`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}${kpi('Sources', num((s.by_source || []).length), 'distinct attacking addresses')}${card('Engine', s.source_error ? `<div>${pill('not reading', 'bad')}</div><div class="small muted" style="margin-top:6px">${esc(s.source_error)}</div>` : `<div>${pill('Suricata', 'ok')}</div><div class="small muted" style="margin-top:6px">Alerts are read from the EVE log; Suricata's own rules and mode are managed in its service settings.</div>`)}</div>
      <div class="grid cols-3" style="margin-top:14px">${card('Top signatures', bars((s.by_signature || []).slice(0, 10).map(x => ({ label: x.signature, sub: `sid ${x.sig_id}`, value: x.alerts }))))}${card('Categories', donut((s.by_category || []).map(x => ({ label: x.category || 'uncategorised', value: x.alerts }))))}${card('Sources', bars((s.by_source || []).map(x => ({ label: x.name || x.ip, sub: x.local ? 'local' : '', value: x.alerts, href: x.local ? '#host/' + x.ip : '' }))))}</div>
      <div style="margin-top:14px">${card('Alerts', table(a.alerts || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' }, { t: 'Signature', f: r => `<b>${esc(r.signature)}</b><div class="muted small">${esc(r.category || '')} · sid ${esc(r.sig_id)}</div>`, sort: 'signature' }, { t: 'Source', f: r => hostLink(r.src_ip, r.src_ip_name) + ':' + r.src_port, sort: 'src_ip' }, { t: 'Destination', f: r => hostLink(r.dst_ip, r.dst_ip_name) + ':' + r.dst_port, sort: 'dst_ip' }, { t: 'Proto', k: 'proto' }, { t: 'Action', f: r => FS.verdictPill(r.verdict), sort: 'verdict' }]))}</div>`;
    }
  });

  // ------------------------------------------------------------- TLS
  FS.registerPage('tls', {
    title: 'TLS', refresh: 60,
    async render(el, ctx) {
      const [s, c, sess] = await Promise.all([get(`/api/tls/summary?${FS.since()}`), get(`/api/tls/certs?${FS.since()}&limit=200${ctx.params.problem ? '&problem=1' : ''}${ctx.params.q ? '&q=' + encodeURIComponent(ctx.params.q) : ''}`), get('/api/tls/sessions?limit=200')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {}, ca = s.ca || {};
      const caCard = ca.exists ? `<div>${pill('CA ready', 'ok')}</div><dl class="kv small" style="margin-top:8px"><dt>Subject</dt><dd>${esc(ca.subject)}</dd><dt>Valid until</dt><dd>${new Date(ca.not_after * 1000).toISOString().slice(0, 10)}</dd><dt>SHA-256</dt><dd class="mono" style="word-break:break-all">${esc(ca.fingerprint_sha256)}</dd></dl><div class="actions"><a class="btn" href="${FS.base ? FS.base + encodeURIComponent('/api/tls/ca/download') : '/api/tls/ca/download'}">Download certificate</a><button class="btn danger" id="ca-del">Delete CA</button></div><div class="help">Install this certificate as a trusted root on every device whose policy has TLS inspection turned on. Devices without it will see certificate warnings for inspected sites.</div>`
        : `<div>${pill('no CA', 'warn')}</div><div class="small muted" style="margin:8px 0">Without a CA the proxy only peeks at handshakes: server names and, optionally, certificates are recorded but nothing is decrypted. Create a CA to allow policies to inspect selected devices.</div><div class="actions"><button class="btn primary" id="ca-create">Create inspection CA</button></div>`;
      el.innerHTML = `<div class="grid cols-4">${kpi('TLS sessions', num(t.sessions), `${num(t.names)} server names · ${num(t.clients)} clients`)}${kpi('Inspected', num(t.inspected), FS.pct(t.inspected, t.sessions) + ' of sessions decrypted', t.inspected ? 'warn' : '')}${kpi('Problem certificates', num(s.problem_certificates), 'expired or self-signed, seen this window', s.problem_certificates ? 'warn' : '')}${card('Inspection CA', caCard)}</div>
      <div class="grid cols-3" style="margin-top:14px">${card('Versions', donut((s.versions || []).map(v => ({ label: v.version, value: v.sessions }))))}${card('Handling', donut((s.modes || []).map(v => ({ label: v.mode, value: v.sessions }))))}${card('Issuers', bars((s.issuers || []).map(i => ({ label: (i.issuer || '').replace(/^.*CN=/, ''), value: i.seen }))))}</div>
      <div style="margin-top:14px">${card('Certificates', table(c.certificates || [], [{ t: 'Subject', f: r => `<b>${esc((r.subject || '').replace(/^.*CN=/, ''))}</b><div class="muted small">${esc(r.subject || '')}</div>`, sort: 'subject' }, { t: 'Issuer', f: r => esc((r.issuer || '').replace(/^.*CN=/, '')), sort: 'issuer' }, { t: 'Names', f: r => esc((JSON.parse(r.snis || '[]')).slice(0, 3).join(', ')) }, { t: 'Expires', f: r => r.not_after ? `<span class="${r.not_after < Date.now() / 1000 ? 'sev-high' : ''}">${new Date(r.not_after * 1000).toISOString().slice(0, 10)}</span>` : '—', sort: 'not_after' }, { t: 'Flags', f: r => (r.self_signed ? pill('self-signed', 'warn') : '') }, { t: 'Seen', f: r => num(r.seen), num: true, sort: 'seen' }, { t: 'Last', f: r => ago(r.last_seen), sort: 'last_seen' }, { t: 'Via', k: 'source' }]), `<a href="#tls?problem=1">problems only</a>`)}</div>
      <div style="margin-top:14px">${card('Recent sessions', table(sess.sessions || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Client', f: r => hostLink(r.src_ip), sort: 'src_ip' }, { t: 'Server name', k: 'sni' }, { t: 'Server', f: r => `${FS.ipTag(r.dst_ip)}:${r.dst_port || ''}` }, { t: 'Version', k: 'version' }, { t: 'Mode', f: r => pill(r.mode || 'splice', r.mode === 'bump' ? 'warn' : r.mode === 'terminate' ? 'bad' : ''), sort: 'mode' }, { t: 'JA3', f: r => `<span class="mono small">${esc((r.ja3 || '').slice(0, 12))}</span>` }, { t: 'Via', k: 'source' }]))}</div>`;
      const cr = FS.$('#ca-create', el); if (cr) cr.onclick = async () => { const name = prompt('Common name for the CA', 'FlowSight Inspection CA'); if (!name) return; const r = await post('/api/tls/ca/create', { name }); if (r.error) FS.toast(r.error, true); else { FS.toast('CA created'); FS.render(); } };
      const dl = FS.$('#ca-del', el); if (dl) dl.onclick = async () => { if (!await FS.confirm('Delete the inspection CA? Every policy with TLS inspection stops decrypting, and a new CA would have to be installed on devices again.')) return; const r = await post('/api/tls/ca/delete', {}); if (r.error) FS.toast(r.error, true); else FS.render(); };
    }
  });
})();
