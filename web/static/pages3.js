/* FlowSight pages: firewall hygiene, alerting, reports, updates, devices & zones. */
'use strict';
(function () {
  const { esc, num, bytes, ago, when, pill, card, kpi, table, bars, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Firewall hygiene
  FS.registerPage('firewall', {
    title: 'Firewall hygiene', refresh: 60,
    async render(el, ctx) {
      const [s, r, f, c] = await Promise.all([get('/api/rulehygiene/summary'), get('/api/rulehygiene/rules'), get('/api/rulehygiene/findings'), get('/api/rulehygiene/changes')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const sev = s.by_severity || {};
      const score = Number(s.risk_score || 0);
      const kind = score >= 50 ? 'bad' : score >= 20 ? 'warn' : 'ok';
      const rules = r.rules || [];
      const findings = f.findings || [];
      el.innerHTML = `<div class="grid cols-4">${kpi('Risk score', score, 'lower is better; weighted open findings', kind)}${kpi('Rules analysed', num(s.rules_analysed), s.ruleset_loaded ? 'ruleset loaded ' + esc(s.ruleset_loaded) : '')}${kpi('Findings', num(findings.length), `${num(sev.critical || 0)} critical · ${num(sev.high || 0)} high · ${num(sev.medium || 0)} medium`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}${card('Analysis', `<div class="small muted">Last run ${esc(s.last_run || 'never')}. Findings are grounded in live pf counters, so "unused" means never matched since the ruleset was loaded, not merely quiet today.</div><div class="actions"><button class="btn primary" id="run">Analyse now</button></div>`)}</div>
      <div style="margin-top:14px">${card('Findings', table(findings, [{ t: 'Severity', f: x => FS.sevPill(x.severity), sort: 'severity' }, { t: 'Kind', f: x => pill(x.kind), sort: 'kind' }, { t: 'Finding', f: x => `<b>${esc(x.title)}</b><div class="muted small">${esc(x.detail || '')}</div>` }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.subject || '')}</span>` }, { t: 'Since', f: x => ago(x.ts), sort: 'ts' }]))}</div>
      <div style="margin-top:14px">${card('Rules with live counters', table(rules, [{ t: '#', f: x => x.index != null ? x.index : '', num: true, sort: 'index' }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.rule || x.text || '')}</span>${x.description ? `<div class="small">${esc(x.description)}</div>` : ''}`, sort: 'rule' }, { t: 'Interface', k: 'interface' }, { t: 'Evaluations', f: x => num(x.evaluations), num: true, sort: 'evaluations' }, { t: 'Packets', f: x => num(x.packets), num: true, sort: 'packets' }, { t: 'Bytes', f: x => bytes(x.bytes), num: true, sort: 'bytes' }, { t: 'States', f: x => num(x.states), num: true, sort: 'states' }, { t: 'Findings', f: x => (x.findings || []).map(k => pill(k, 'warn')).join(' ') }]))}</div>
      <div style="margin-top:14px">${card('Ruleset changes', table(c.changes || [], [{ t: 'When', f: x => when(x.ts), sort: 'ts' }, { t: 'By', k: 'actor' }, { t: 'Summary', f: x => esc(x.summary || '') }, { t: '', f: x => x.diff_bytes ? `<button class="btn small" data-diff="${x.id}">diff</button>` : '' }]))}</div>`;
      FS.$('#run', el).onclick = async () => { const x = await post('/api/rulehygiene/run', {}); FS.toast(x.error || 'Analysis started', !!x.error); setTimeout(FS.render, 3000); };
      FS.$$('[data-diff]', el).forEach(b => b.onclick = async () => { const x = await get('/api/system/changes?id=' + b.dataset.diff); FS.modal(`<h2>${esc((x.change || {}).subject || 'change')}</h2><pre class="code">${FS.diffHtml((x.change || {}).diff || '')}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); });
    }
  });

  // ------------------------------------------------------------- Alerting
  FS.registerPage('alerts', {
    title: 'Alerting', refresh: 60,
    async render(el) {
      const d = await get('/api/alerting/status'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const channels = d.channels || [];
      const rules = Object.values(d.rules || {});
      const TYPES = ['email', 'webhook', 'discord', 'slack', 'ntfy'];
      el.innerHTML = `<div class="grid cols-2">
        ${card('Channels', `<div class="actions"><button class="btn primary" id="ch-new">Add channel</button></div>` + table(channels, [{ t: 'Name', f: x => `<b>${esc(x.name)}</b>` }, { t: 'Type', f: x => pill(x.type, 'info') }, { t: 'Target', f: x => esc(x.to || x.url || x.topic || x.host || '') }, { t: '', f: x => `<button class="btn small" data-test="${esc(x.name)}">Test</button> <button class="btn small" data-edit="${esc(x.name)}">Edit</button> <button class="btn small danger" data-del="${esc(x.name)}">Delete</button>` }], { empty: 'No channels yet. Add email, a webhook, Discord, Slack or ntfy.' }))}
        ${card('Rules', table(rules, [{ t: 'On', f: x => `<input type="checkbox" data-rule="${esc(x.name)}" ${x.enabled ? 'checked' : ''}>` }, { t: 'Rule', f: x => `<b>${esc(x.subject || x.name)}</b><div class="muted small">${esc(x.kind)} · threshold ${x.threshold} in ${FS.dur(x.window || 0)} · cooldown ${FS.dur(x.cooldown || 0)}</div>` }, { t: 'Severity', f: x => FS.sevPill(x.severity) }, { t: 'Channels', f: x => (x.channels || []).length ? (x.channels || []).map(c => pill(c)).join(' ') : '<span class="muted small">all</span>' }]) + `<div class="actions"><button class="btn primary" id="rules-save">Save rules</button></div>`)}
      </div>
      <div style="margin-top:14px">${card('Recent notifications', table(d.notifications || [], [{ t: 'When', f: x => when(x.ts), sort: 'ts' }, { t: 'Rule', k: 'rule' }, { t: 'Subject', k: 'subject' }, { t: 'Channel', k: 'channel' }, { t: 'Result', f: x => x.ok ? pill('sent', 'ok') : pill(x.error || 'failed', 'bad') }]))}</div>`;
      const edit = (name) => {
        const ch = channels.find(x => x.name === name) || { type: 'email' };
        const fieldsFor = (type, v) => ({
          email: [['host', 'SMTP host'], ['port', 'Port'], ['user', 'User'], ['password', 'Password'], ['from', 'From'], ['to', 'To (comma separated)'], ['tls', 'TLS: starttls, implicit or none']],
          webhook: [['url', 'URL']], discord: [['url', 'Webhook URL']], slack: [['url', 'Incoming webhook URL']], ntfy: [['url', 'Topic URL (https://ntfy.sh/topic)'], ['token', 'Access token (optional)']]
        }[type] || []).map(([k, l]) => `<label>${esc(l)}</label><input type="text" name="${k}" value="${esc(v[k] == null ? '' : v[k])}" autocomplete="off">`).join('');
        FS.modal(`<h2>${name ? 'Edit' : 'Add'} channel</h2><form class="f"><label>Name</label><input type="text" name="name" value="${esc(ch.name || '')}" required><label>Type</label><select name="type">${TYPES.map(t => `<option ${t === ch.type ? 'selected' : ''}>${t}</option>`).join('')}</select><div id="cf">${fieldsFor(ch.type, ch)}</div><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" onclick="FS.closeModal()">Cancel</button></div></form>`, (b) => {
          const f = FS.$('form', b);
          f.type.onchange = () => { FS.$('#cf', b).innerHTML = fieldsFor(f.type.value, {}); };
          f.onsubmit = async (e) => { e.preventDefault(); const o = { name: f.name.value.trim(), type: f.type.value }; FS.$$('#cf input', b).forEach(i => { o[i.name] = i.name === 'port' ? Number(i.value) : i.value; if (i.name === 'to') o.to = i.value.split(',').map(x => x.trim()).filter(Boolean); }); const next = channels.filter(x => x.name !== name && x.name !== o.name); next.push(o); const r = await post('/api/alerting/channels', { channels: next }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } };
        });
      };
      FS.$('#ch-new', el).onclick = () => edit(null);
      FS.$$('[data-edit]', el).forEach(b => b.onclick = () => edit(b.dataset.edit));
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm(`Delete channel "${b.dataset.del}"?`)) return; const r = await post('/api/alerting/channels', { channels: channels.filter(x => x.name !== b.dataset.del) }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-test]', el).forEach(b => b.onclick = async () => { const r = await post('/api/alerting/channels/test', { name: b.dataset.test }); FS.toast(r.error || 'Test message sent', !!r.error); });
      FS.$('#rules-save', el).onclick = async () => { const out = {}; rules.forEach(x => { out[x.name] = { ...x, enabled: FS.$(`[data-rule="${x.name}"]`, el).checked }; }); const r = await post('/api/alerting/rules', { rules: out }); FS.toast(r.error || 'Rules saved', !!r.error); };
    }
  });

  // ------------------------------------------------------------- Reports
  FS.registerPage('reports', {
    title: 'Reports', refresh: 0,
    async render(el) {
      const d = await get('/api/reports/schedules'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const scheds = d.schedules || [];
      const link = (p) => FS.base ? FS.base + encodeURIComponent(p) : p;
      el.innerHTML = `<div class="grid cols-2">
        ${card('On demand', `<p class="small muted">A self-contained HTML report of the selected window: traffic, hosts, applications, web, DNS, threats, TLS and open findings. Export raw data as CSV.</p><div class="actions"><a class="btn primary" target="_blank" href="${link('/api/reports/preview?hours=' + FS.state.hours)}">Open report (${FS.state.hours}h)</a>${['flows', 'dns', 'alerts', 'hosts'].map(k => `<a class="btn" href="${link('/api/reports/export?kind=' + k + '&hours=' + FS.state.hours)}">${k}.csv</a>`).join('')}</div>`)}
        ${card('Scheduled reports', `<div class="actions"><button class="btn primary" id="new">New schedule</button></div>` + table(scheds, [{ t: 'Name', f: x => `<b>${esc(x.name)}</b>${x.enabled ? '' : ' ' + pill('off', 'warn')}` }, { t: 'Cadence', f: x => `${esc(x.cadence)} at ${String(x.hour).padStart(2, '0')}:00, last ${x.window}h` }, { t: 'Recipients', f: x => esc((x.recipients || []).join(', ')) }, { t: '', f: x => `<button class="btn small" data-run="${esc(x.name)}">Send now</button> <button class="btn small danger" data-del="${esc(x.name)}">Delete</button>` }], { empty: 'No schedules. Reports are emailed through the email channel configured under Alerting.' }))}
      </div>`;
      FS.$('#new', el).onclick = () => FS.modal(`<h2>New scheduled report</h2><form class="f"><label>Name</label><input type="text" name="name" required><div class="row"><div><label>Cadence</label><select name="cadence"><option>daily</option><option>weekly</option><option>monthly</option></select></div><div><label>Hour (0-23)</label><input type="number" name="hour" value="7" min="0" max="23"></div></div><div class="row"><div><label>Window (hours)</label><input type="number" name="window" value="24"></div><div><label>Recipients</label><input type="text" name="recipients" placeholder="a@example.com, b@example.com"></div></div><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" onclick="FS.closeModal()">Cancel</button></div></form>`, (b) => { FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const s = { name: f.name.value.trim(), cadence: f.cadence.value, hour: Number(f.hour.value), window: Number(f.window.value), recipients: f.recipients.value.split(',').map(x => x.trim()).filter(Boolean), enabled: true }; const r = await post('/api/reports/schedules', { schedules: [...scheds.filter(x => x.name !== s.name), s] }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } }; });
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { const r = await post('/api/reports/schedules', { schedules: scheds.filter(x => x.name !== b.dataset.del) }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-run]', el).forEach(b => b.onclick = async () => { const r = await post('/api/reports/run?name=' + encodeURIComponent(b.dataset.run), { name: b.dataset.run }); FS.toast(r.error || 'Report sent', !!r.error); });
    }
  });

  // ------------------------------------------------------------- Updates
  FS.registerPage('updates', {
    title: 'Updates', refresh: 0,
    async render(el) {
      const d = await get('/api/updater/status'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = `<div class="grid cols-3">${kpi('Installed', esc(d.current_version), d.last_check > 0 ? 'checked ' + ago(d.last_check) : 'not checked yet')}${kpi('Latest', esc(d.latest_version || '—'), d.available ? (d.applicable ? 'update available' : 'available but not verifiable') : 'up to date', d.available ? 'warn' : 'ok')}${card('Actions', `<div class="actions"><button class="btn" id="check">Check now</button><button class="btn primary" id="apply" ${d.applicable ? '' : 'disabled'}>Install update</button><button class="btn" id="rollback">Roll back</button></div><div class="help">Updates are downloaded from the release manifest, verified by checksum and signature, swapped in atomically and the service restarted. The previous binary is kept for roll back.</div>`)}</div>
      ${d.notes ? `<div style="margin-top:14px">${card('Release notes', `<pre class="code">${esc(d.notes)}</pre>`)}</div>` : ''}${d.error ? `<div style="margin-top:14px">${card('Last error', `<div class="sev-high small">${esc(d.error)}</div>`)}</div>` : ''}`;
      FS.$('#check', el).onclick = async () => { const r = await post('/api/updater/check', {}); FS.toast(r.error || 'Checked', !!r.error); FS.render(); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Install the update and restart FlowSight?')) return; const r = await post('/api/updater/apply', {}); FS.toast(r.error || 'Updating… the service will restart', !!r.error); };
      FS.$('#rollback', el).onclick = async () => { if (!await FS.confirm('Roll back to the previous binary and restart?')) return; const r = await post('/api/updater/rollback', {}); FS.toast(r.error || 'Rolling back…', !!r.error); };
    }
  });

  // ------------------------------------------------------------- Devices (enrolment)
  // Shared loader: devices, zones and rules come from the enroll module; the
  // two pages cross-link on the zone id.
  const enrollLoad = async (zoneFilter) => {
    const [s, dv, z, ru] = await Promise.all([get('/api/enroll'), get('/api/enroll/devices' + (zoneFilter ? '?zone=' + encodeURIComponent(zoneFilter) : '')), get('/api/enroll/zones'), get('/api/enroll/rules')]);
    const zones = ((z && z.zones) || ((z && z.document) || {}).zones || []);
    const devices = (dv && dv.devices) || [];
    const mode = (s && s.mode) || (z && z.mode) || 'monitor';
    return { s, dv, z, ru, zones, devices, mode };
  };
  const zoneName = (zones, id) => { const zz = zones.find(x => x.id === id); return zz ? (zz.name || zz.id) : (id || ''); };
  const modeControls = (mode, el) => {
    FS.$('#mode', el).onclick = async () => { const next = mode === 'enforce' ? 'monitor' : 'enforce'; if (next === 'enforce' && !await FS.confirm('Enforce mode writes DHCP reservations and firewall isolation. Devices present now stay where they are; only new devices are placed. Continue?')) return; const r = await post('/api/enroll/mode', { mode: next }); FS.toast(r.error || 'Mode: ' + next, !!r.error); FS.render(); };
  };

  FS.registerPage('devices', {
    title: 'Devices', refresh: 30,
    async render(el, ctx) {
      const { s, zones, devices, mode } = await enrollLoad(ctx.params.zone);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const zoneOpts = (cur) => `<option value="">—</option>` + zones.map(x => `<option value="${esc(x.id)}" ${x.id === cur ? 'selected' : ''}>${esc(x.name || x.id)}</option>`).join('');
      const byZone = {}; devices.forEach(d => { byZone[d.zone || ''] = (byZone[d.zone || ''] || 0) + 1; });
      const unplaced = byZone[''] || 0;
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Devices', num(devices.length), `${num(s.unidentified || 0)} unidentified · ${num(unplaced)} without a zone`)}${kpi('Zones', num(zones.length), zones.map(x => `<a href="#zones?zone=${esc(x.id)}">${esc(x.id)}</a> ${num(byZone[x.id] || 0)}`).join(' · ') || 'none defined')}${card('Actions', `<div class="actions"><button class="btn" id="reconcile">Re-identify</button><a class="btn" href="#zones">Zones &amp; placement</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Devices' + (ctx.params.zone ? ` in zone ${esc(zoneName(zones, ctx.params.zone))}` : ''), table(devices, [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}${x.randomized ? ' · private MAC' : ''}</div>`, sort: 'hostname' }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '', sort: 'ip' }, { t: 'Vendor', f: x => esc(x.vendor || '') + (x.vendor_class ? `<div class="muted small">${esc(x.vendor_class)}</div>` : ''), sort: 'vendor' }, { t: 'Class', f: x => esc(x.class || ''), sort: 'class' }, { t: 'Zone', f: x => `<select data-mac="${esc(x.mac)}">${zoneOpts(x.zone)}</select>${x.zone ? ` <a class="small" href="#zones?zone=${esc(x.zone)}">view</a>` : ''}${x.pinned ? ' ' + pill('pinned', '') : ''}`, sort: 'zone' }, { t: 'Why', f: x => `<span class="small muted">${esc(x.why || x.rule || '')}</span>` }, { t: 'Seen', f: x => ago(x.last_seen), sort: 'last_seen' }]), ctx.params.zone ? `<a href="#devices">all devices</a>` : zones.map(x => `<a href="#devices?zone=${esc(x.id)}">${esc(x.id)}</a>`).join(' · '))}</div>
      <div class="help" style="margin-top:8px"><b>Devices</b> is the enrolment inventory: one row per physical device (by MAC) learned from DHCP, with a class and a zone, whether or not it is talking right now. <a href="#hosts">Hosts</a> is what traffic shows: one row per address seen in flows and DNS in the selected window, with its traffic. A device's address links to its host page. Addresses are shown by name when FlowSight knows one; with <a href="#modules/enrich">Settings › enrich</a> on, bare addresses gain their reverse-DNS name and country.</div>`;
      FS.$$('select[data-mac]', el).forEach(sel => sel.onchange = async () => { const r = await post('/api/enroll/assign', { mac: sel.dataset.mac, zone: sel.value }); FS.toast(r.error || (sel.value ? 'Assigned and pinned' : 'Unpinned: the rules place it'), !!r.error); if (!r.error) FS.render(); });
      FS.$('#reconcile', el).onclick = async () => { const r = await post('/api/enroll/reconcile', {}); FS.toast(r.error || 'Re-identified', !!r.error); FS.render(); };
      modeControls(mode, el);
    }
  });

  // ------------------------------------------------------------- Zones (enrolment)
  FS.registerPage('zones', {
    title: 'Zones', refresh: 0,
    async render(el, ctx) {
      const { s, z, ru, zones, devices, mode } = await enrollLoad('');
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const byZone = {}; devices.forEach(d => { (byZone[d.zone || ''] = byZone[d.zone || ''] || []).push(d); });
      const sel = ctx.params.zone || '';
      const zoneRows = zones.map(x => Object.assign({ count: (byZone[x.id] || []).length }, x));
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Zones', num(zones.length), `${num((byZone[''] || []).length)} devices without a zone`)}${kpi('Placed devices', num(devices.length - (byZone[''] || []).length), `of ${num(devices.length)}`)}${card('Actions', `<div class="actions"><button class="btn" id="plan">Plan placement</button><button class="btn primary" id="apply" ${mode === 'enforce' ? '' : 'disabled'}>Apply placement</button><a class="btn" href="#devices">Devices</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Zones', table(zoneRows, [{ t: 'Zone', f: x => `<b>${esc(x.name || x.id)}</b><div class="muted small mono">${esc(x.id)}</div>`, sort: 'id' }, { t: 'Subnet', f: x => `<span class="mono">${esc(x.subnet || x.cidr || '')}</span>` }, { t: 'Isolation', f: x => esc(x.isolation || x.policy || (x.isolate ? 'isolated' : '')) }, { t: 'Devices', f: x => `<a href="#devices?zone=${esc(x.id)}">${num(x.count)}</a>`, num: true, sort: 'count' }, { t: 'Members', f: x => (byZone[x.id] || []).slice(0, 6).map(d => d.ip ? FS.hostLink(d.ip, d.hostname || d.guest_name) : esc(d.hostname || d.mac)).join(', ') + ((byZone[x.id] || []).length > 6 ? ` … <a href="#devices?zone=${esc(x.id)}">all</a>` : '') }]), `<a href="#devices">devices without a zone: ${num((byZone[''] || []).length)}</a>`)}</div>
      ${sel && byZone[sel] ? `<div style="margin-top:14px">${card(`Devices in ${esc(zoneName(zones, sel))}`, table(byZone[sel], [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}</div>` }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '' }, { t: 'Class', k: 'class' }, { t: 'Seen', f: x => ago(x.last_seen) }]), `<a href="#devices?zone=${esc(sel)}">open in Devices</a>`)}</div>` : ''}
      <div class="grid cols-2" style="margin-top:14px">${card('Zones (zones.json)', `<form class="f" id="zf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((z && (z.document || z)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save zones</button></div></form>`)}${card('Classification rules (enroll-rules.json)', `<form class="f" id="rf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((ru && (ru.document || ru)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save rules</button></div></form>`)}</div>`;
      FS.$('#plan', el).onclick = async () => { const r = await get('/api/enroll/plan'); FS.modal(`<h2>Placement plan</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Apply device placement (DHCP reservations) and zone isolation now?')) return; const r = await post('/api/enroll/apply', {}); FS.modal(`<h2>Applied</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`); };
      modeControls(mode, el);
      FS.$('#zf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/zones', doc); FS.toast(r.error || 'Zones saved', !!r.error); FS.render(); };
      FS.$('#rf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/rules', doc); FS.toast(r.error || 'Rules saved', !!r.error); };
    }
  });
  // Old deep links keep working.
  FS.registerPage('enroll', { title: 'Devices', refresh: 0, async render(el, ctx) { FS.go('#devices' + (ctx.params.zone ? '?zone=' + encodeURIComponent(ctx.params.zone) : '')); } });

  // ------------------------------------------------------------- Deep inspection
  FS.registerPage('deep', {
    title: 'Deep inspection', refresh: 15,
    async render(el, ctx) {
      const [s, r] = await Promise.all([get('/api/mitm/status'), get('/api/mitm/requests?limit=300' + (ctx.params.q ? '&q=' + encodeURIComponent(ctx.params.q) : ''))]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const state = !s.licensed ? pill('business tier', 'warn') : !s.enabled ? pill('off', '') : s.listening ? pill('inspecting', 'ok') : pill('not listening', 'bad');
      el.innerHTML = `<div class="grid cols-4">
        ${kpi('State', state, s.error ? esc(s.error) : (s.enabled ? `loopback port ${s.port}` : 'switch it on under Settings › mitm'))}
        ${kpi('Requests', num(s.requests), `${bytes(s.bytes_in)} in · ${bytes(s.bytes_out)} out`)}
        ${kpi('Decoded', num(s.decoded), 'DNS-over-HTTPS questions recovered')}
        ${card('Scope', `<div class="small">Clients: ${(s.clients || []).length ? (s.clients || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every client a policy decrypts</span>'}</div>
          <div class="small" style="margin-top:4px">Names: ${(s.names || []).length ? (s.names || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every name that is decrypted</span>'}</div>
          <div class="actions"><a class="btn" href="#modules/mitm">Settings</a><a class="btn" href="#tls">Pinned sites</a></div>`)}
      </div>
      <div style="margin-top:14px">${card('Recent requests', table(r.requests || [], [
        { t: 'When', f: x => when(x.ts), sort: 'ts' },
        { t: 'Client', f: x => FS.hostLink(x.client), sort: 'client' },
        { t: 'Request', f: x => `<span class="mono small">${esc(x.method)} ${esc(x.url)}</span>`, sort: 'url' },
        { t: 'Status', f: x => x.status ? pill(String(x.status), x.status >= 400 ? 'bad' : 'ok') : pill('failed', 'bad'), sort: 'status' },
        { t: 'Type', f: x => `<span class="small muted">${esc((x.content_type || '').split(';')[0])}</span>`, sort: 'content_type' },
        { t: 'Size', f: x => bytes(x.bytes_in), num: true, sort: 'bytes_in' },
        { t: 'Took', f: x => (x.ms || 0).toFixed(0) + ' ms', num: true, sort: 'ms' },
        { t: '', f: x => `<button class="btn small" data-det="${esc(JSON.stringify(x).replace(/"/g, '&quot;'))}">Headers</button>` },
      ]), `<span class="muted small">${esc(s.note || '')}</span>`)}</div>`;
      FS.$$('[data-det]', el).forEach(b => b.onclick = () => {
        const x = JSON.parse(b.dataset.det);
        FS.modal(`<h2>${esc(x.method)} ${esc(x.url)}</h2><pre class="code">${esc(Object.entries(x.headers || {}).map(([k, v]) => k + ': ' + v).join('\n') || 'headers were not recorded')}</pre>
          <div class="small muted">${esc(x.note || '')}</div><div class="actions"><button class="btn" onclick="FS.closeModal()">Close</button></div>`);
      });
    }
  });

  // ------------------------------------------------------------- Data out
  // The one page that is about the present tense. Everything else in
  // FlowSight reports what happened; this reports what is happening, because
  // a transfer you read about tomorrow is a transfer that finished.
  const rate = (b) => b > 0 ? FS.bps(b * 8) : '<span class="muted">idle</span>';
  // The pill says what kind of destination this is, in words. An unnamed one
  // is called out in red: an address nothing can put a name to is the row
  // most worth reading on this page.
  const groupPill = (t) => {
    const tone = { unknown: 'bad', tunnel: 'warn', 'cloud-storage': 'warn', 'file-transfer': 'warn',
      webmail: 'warn', 'remote-access': 'warn', ai: 'warn' }[t.group] || '';
    return pill(t.group_title || t.group, tone);
  };
  FS.registerPage('egress', {
    title: 'Data out', refresh: 5,
    async render(el, ctx) {
      const [live, sum, ev] = await Promise.all([
        get('/api/egress/live?min_kb=' + (ctx.params.all ? 0 : 64)),
        get('/api/egress/summary'),
        get('/api/egress/events?limit=200')]);
      if (live.error && !live.transfers) { el.innerHTML = FS.err(live.error); return; }
      const rows = live.transfers || [];
      // Only connections this network opened count as data leaving. A server
      // here answering the internet has really sent the bytes, and saying so
      // is useful, but it is not the same question.
      const outbound = rows.filter(t => !t.serving);
      const watched = outbound.filter(t => ['cloud-storage', 'file-transfer', 'webmail', 'messaging',
        'ai', 'remote-access', 'code-host', 'tunnel', 'unknown'].includes(t.group));
      const events = ev.events || [];
      const open = events.filter(e => e.severity === 'high' || e.severity === 'medium').length;

      el.innerHTML = `<div class="grid cols-4">
        ${kpi('Leaving now', FS.bps((sum.rate_out || 0) * 8), `${num(sum.transfers)} connections carrying data`, sum.rate_out > 1e6 ? 'warn' : '')}
        ${kpi('Sent, open connections', bytes(outbound.reduce((a, t) => a + t.out, 0)), `${num(rows.length - outbound.length)} more are this network serving requests from outside`)}
        ${kpi('To watched destinations', num(watched.length), 'cloud storage, mail, tunnels, unnamed', watched.length ? 'warn' : '')}
        ${kpi('Flagged', num(open), 'transfers that crossed a threshold', open ? 'bad' : '')}</div>

      <div class="grid cols-2" style="margin-top:14px">
        ${card('By destination', bars((sum.groups || []).map(g => ({ label: g.title || g.key, value: g.out })), bytes))}
        ${card('By device', bars((sum.devices || []).map(d => ({ label: d.name || d.key, sub: d.name ? d.key : '', value: d.out, href: '#host/' + d.key })), bytes))}
      </div>

      <div style="margin-top:14px" id="live-card">${card(`Moving now (${num(rows.length)})`, table(rows, [
        { t: 'Device', f: r => FS.addrCell(r.local, r.local_name), sort: 'local' },
        { t: 'Direction', f: r => r.serving
            ? `<span class="muted small" title="The far side opened this connection: something here is answering the internet, not reaching out to it">serving</span>`
            : pill('reaching out', ''), sort: 'serving' },
        { t: 'Destination', f: r => `<b>${esc(r.service || r.peer_name || r.peer)}</b>${(r.peer_name && r.peer_name !== r.service) ? `<div class="muted small">${esc(r.peer_name)}</div>` : ''}<div class="muted small">${esc(r.peer)}:${r.peer_port} ${esc(r.proto)}</div>`, sort: 'peer_name' },
        { t: 'Kind', f: r => groupPill(r), sort: 'group' },
        { t: 'Sending', f: r => `<b>${rate(r.rate_out)}</b>`, num: true, sort: 'rate_out' },
        { t: 'Sent', f: r => bytes(r.out), num: true, sort: 'out' },
        { t: 'Received', f: r => bytes(r.in), num: true, sort: 'in' },
        { t: 'Open for', f: r => FS.dur(r.age), num: true, sort: 'age' },
        { t: 'Flags', f: r => (r.flags || []).map(f => pill(f, 'warn')).join(' ') },
        { t: '', f: r => `<button class="btn small danger" data-stop="${esc(r.local)}" data-peer="${esc(r.peer)}">Stop</button>` }],
        { rowAttr: r => (r.flags || []).length ? 'class="flagged"' : '' }),
        ctx.params.all ? '<a href="#egress">hide small connections</a>' : '<a href="#egress?all=1">show every connection</a>')}</div>

      <div style="margin-top:14px">${card('Flagged transfers', table(events, [
        { t: 'When', f: r => when(r.ts), sort: 'ts' },
        { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' },
        { t: 'What', f: r => `<b>${esc(r.message)}</b>`, sort: 'message' },
        { t: 'Kind', f: r => pill(r.kind), sort: 'kind' },
        { t: 'Device', f: r => hostLink(r.transfer.local, r.transfer.local_name), sort: 'transfer' }],
        { empty: 'Nothing has crossed a threshold. Thresholds are in Settings, under egress.' }))}</div>

      <div class="help" style="margin-top:12px">${esc(live.note || '')} Sampled ${live.sampled ? ago(live.sampled) : 'never'}.</div>`;

      FS.$$('[data-stop]', el).forEach(b => b.onclick = async () => {
        if (!await FS.confirm(`Stop the transfer from ${b.dataset.stop} to ${b.dataset.peer}? The connection is dropped at the firewall. The device may open another one.`)) return;
        const r = await post('/api/egress/stop', { local: b.dataset.stop, peer: b.dataset.peer });
        FS.toast(r.error || 'Transfer stopped', !!r.error);
        FS.render();
      });
    }
  });

  // ------------------------------------------------------------- Priority
  // The page for the one module that changes traffic rather than describing
  // it, so it leads with whether shaping is actually in force and what the
  // queues are holding, not with the settings.
  FS.registerPage('qos', {
    title: 'Priority', refresh: 15,
    async render(el, ctx) {
      const [s, p] = await Promise.all([get('/api/qos/status'), get('/api/qos/preview')]);
      if (s.error && !s.rules) { el.innerHTML = FS.err(s.error); return; }
      const rules = s.rules || [];
      const broken = rules.filter(r => r.error);
      const state = !s.active ? pill('off', '')
        : s.applied ? pill('shaping', 'warn') : pill('not applied', 'bad');

      el.innerHTML = `<div class="grid cols-4">
        ${card('State', `<div>${state}</div><div class="small muted" style="margin-top:6px">${s.applied ? 'The queue is on this firewall' : 'The carrier still decides what waits'}</div>`)}
        ${kpi('Link, as shaped', s.applied ? `${Math.round(s.down_mbit)} / ${Math.round(s.up_mbit)}` : '—', 'Mbit/s down / up, after headroom')}
        ${kpi('Rules', num(rules.length - broken.length), broken.length ? `${broken.length} cannot be read` : 'all readable', broken.length ? 'bad' : '')}
        ${kpi('Resolved names', num(Object.keys(s.resolved || {}).length), 'domains with addresses to match on')}</div>

      ${!s.active ? `<div class="help" style="margin-top:14px">Shaping is off, so the link behaves exactly as it does now and nothing below is in force. It is switched on in <a href="#modules?m=qos">Settings › qos</a>, which also needs the rates the link really carries.</div>` : ''}
      ${s.error ? `<div style="margin-top:14px">${card('Not applied', `<div class="sev-high">${esc(s.error)}</div>`)}</div>` : ''}

      <div style="margin-top:14px">${card('Rules', table(rules, [
        { t: 'Match', f: r => `<b>${esc(r.match)}</b><div class="muted small">${r.is_host ? 'an address here' : 'a service out there'}</div>`, sort: 'match' },
        { t: 'Class', f: r => r.class ? pill(r.class, r.class === 'high' ? 'ok' : r.class === 'low' ? '' : 'info') : '<span class="muted">unchanged</span>', sort: 'class' },
        { t: 'Ceiling', f: r => r.ceiling ? `${r.ceiling} Mbit/s` : '<span class="muted">none</span>', num: true, sort: 'ceiling' },
        { t: 'Matches', f: r => r.is_host ? '<span class="muted small">the address itself</span>'
            : ((s.resolved || {})[r.match] ? `${num(s.resolved[r.match])} addresses` : '<span class="muted small">nothing looked it up yet</span>') },
        { t: 'Problem', f: r => r.error ? `<span class="sev-high small">${esc(r.error)}</span>` : '' }],
        { empty: 'No rules. Everything shares the link equally.' }))}</div>

      ${s.applied ? `<div style="margin-top:14px">${card('Queues', table(s.queues || [], [
        { t: 'Queue', f: r => esc(r.name), sort: 'name' },
        { t: 'From dummynet', f: r => `<span class="mono small">${esc(r.detail)}</span>` }],
        { empty: 'Nothing queued yet. A queue only holds something back when the link is full.' }))}</div>` : ''}

      <div style="margin-top:14px">${card('Firewall rules these settings produce', `<pre class="mono small" style="white-space:pre-wrap;overflow-x:auto">${esc(p.anchor || 'nothing; there is no rule to apply')}</pre>`,
        p.lan ? `on <b>${esc(p.lan)}</b>` : '<span class="sev-high">no LAN interface detected</span>')}</div>

      <div class="help" style="margin-top:12px">${esc(s.note || '')}</div>`;
    }
  });

  // ------------------------------------------------------------- Paths
  // A map of where traffic goes, drawn from measured routes.
  //
  // Two honesties are built into the drawing rather than written in a
  // caption. Legs shared by several destinations are one line in a neutral
  // colour, because that is literally one piece of wire carrying both. And
  // hops with no coordinates are not placed at zero, which would pile a
  // stack of routers into the Gulf of Guinea; they go in their own row
  // underneath, counted and named.
  const MAPW = 720, MAPH = 360;
  FS.registerPage('paths', {
    title: 'Paths', refresh: 120,
    async render(el, ctx) {
      const q = [];
      if (ctx.params.device) q.push('device=' + encodeURIComponent(ctx.params.device));
      if (ctx.params.country) q.push('country=' + encodeURIComponent(ctx.params.country));
      if (ctx.params.max_latency) q.push('max_latency=' + encodeURIComponent(ctx.params.max_latency));
      if (ctx.params.max_hops) q.push('max_hops=' + encodeURIComponent(ctx.params.max_hops));
      const [st, g, dests, devs, home, cab] = await Promise.all([
        get('/api/paths/status'),
        get('/api/paths/graph' + (q.length ? '?' + q.join('&') : '')),
        get('/api/paths/destinations?limit=400'),
        get('/api/paths/devices'),
        get('/api/paths/home'),
        get('/api/paths/cables?detail=36')]);
      if (st.error && !g.nodes) { el.innerHTML = FS.err(st.error); return; }

      const nodes = g.nodes || [], legs = g.legs || [];
      const byId = {}; nodes.forEach(n => byId[n.id] = n);
      const located = nodes.filter(n => n.located);
      const impossible = nodes.filter(n => n.impossible);
      const unlocated = nodes.filter(n => !n.located && !n.silent);
      const silent = nodes.filter(n => n.silent).length;

      // One colour per destination for the legs only it uses; everything
      // shared takes a single neutral colour, which is what "these are the
      // same leg" should look like.
      const dstColour = {};
      let ci = 0;
      legs.forEach(l => (l.destinations || []).forEach(d => {
        if (!(d in dstColour)) dstColour[d] = FS.palette[ci++ % FS.palette.length];
      }));
      const legColour = (l) => l.shared ? 'var(--muted)' : (dstColour[(l.destinations || [])[0]] || FS.palette[0]);

      const xy = (n) => FS.project(n.lat, n.lon, MAPW, MAPH);
      // Cables first, so they sit behind the routes. A run is broken wherever
      // it wraps the antimeridian rather than drawn straight across the map.
      let cables = '';
      (cab.cables || []).forEach(c => {
        (c.runs || []).forEach(run => {
          let d = '', prev = null;
          run.forEach(p => {
            const [x, y] = FS.project(p[1], p[0], MAPW, MAPH);
            d += (prev === null || Math.abs(x - prev) > MAPW * 0.5 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1) + ' ';
            prev = x;
          });
          cables += `<path class="cable" d="${d.trim()}"/>`;
        });
      });
      let lines = '', dots = '';
      legs.forEach(l => {
        const a = byId[l.from], b = byId[l.to];
        if (!a || !b || !a.located || !b.located) return;
        const [x1, y1] = xy(a), [x2, y2] = xy(b);
        const n = (l.destinations || []).length;
        const cbl = (l.cables || []).length
          ? `\ncould have crossed: ${l.cables.map(c => `${c.name} (${num(c.km)} km)`).join(', ')}`
          : (l.straight_km ? `\nno cable serves both ends` : '');
        lines += `<path class="leg ${l.shared ? 'shared' : ''}" stroke="${legColour(l)}" d="M${x1.toFixed(1)},${y1.toFixed(1)} L${x2.toFixed(1)},${y2.toFixed(1)}"><title>${esc(a.ips.join(', '))} &rarr; ${esc(b.ips.join(', '))}\n${n} destination${n === 1 ? '' : 's'}${esc(cbl)}</title></path>`;
      });
      located.forEach(n => {
        const [x, y] = xy(n);
        const label = [n.city, n.region, n.country].filter(Boolean).join(', ');
        if (n.impossible) dots += `<circle class="ruledout" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="7"/>`;
        if (n.moved_km && n.db_lat) {
          // Drawn from where the database put it to where the name says it is,
          // so a reader can see the size of the correction rather than take it.
          const [px, py] = xy({ lat: n.db_lat, lon: n.db_lon });
          dots += `<path class="corrected" d="M${px.toFixed(1)},${py.toFixed(1)} L${x.toFixed(1)},${y.toFixed(1)}"/><circle class="ghost" cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="2.5"/>`;
        }
        dots += `<circle class="hop ${n.detail && n.detail.asn ? 'rich' : ''}" data-hop="${esc(n.id)}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(2 + Math.min(3, n.ips.length)).toFixed(1)}" fill="${FS.palette[n.index % FS.palette.length]}"><title>hop ${n.index}\n${esc(n.ips.join(', '))}${label ? '\n' + esc(label) : ''}${n.rtt_ms ? '\n' + n.rtt_ms + ' ms' : ''}${n.why ? '\nRULED OUT: ' + esc(n.why) : ''}\nclick for detail</title></circle>`;
      });

      // What a hop is, told in the order the evidence deserves: what was
      // measured, then what the router called itself, then what a registry
      // says about the block, then buildings -- each labelled, so a street
      // address published by an operator is never mistaken for this router's
      // address, and a head office is never mistaken for either.
      const hopCard = (n) => {
        const d = n.detail || {};
        const r = (k, v, cls) => v ? `<div class="hr ${cls || ''}"><span>${esc(k)}</span><b>${esc(v)}</b></div>` : '';
        const grp = (t) => `<div class="hg">${esc(t)}</div>`;
        let h = `<h4>Hop ${n.index} &mdash; <span class="mono">${esc(n.ips.join(', '))}</span></h4>`;
        h += grp('Measured') + r('Round trip', n.rtt_ms ? n.rtt_ms + ' ms' : '');
        if (n.names && n.names.length) h += grp('Resolved') + r('Router name', n.names.join(', '));
        if (d.pop_city) {
          h += grp('Site, read from the router name') + r('Code in the name', d.pop_code) + r('Site', d.pop_city);
          if (n.database_said) h += r('The database said', `${n.database_said} — ${num(Math.round(n.moved_km))} km away; the name is first-hand, so it wins`, 'warn');
        }
        if (d.asn) {
          h += grp('Who runs it') + r('Network', 'AS' + d.asn + (d.as_name ? '  ' + d.as_name : ''))
             + r('Announced prefix', d.prefix)
             + r('Registry', d.rir ? d.rir.toUpperCase() + (d.allocated ? ', allocated ' + d.allocated : '') : '')
             + r('Allocation', d.net_name) + r('Registrant', d.org)
             + r('Registrant address', d.org_addr ? d.org_addr + '  (head office, not this router)' : '', 'soft');
        }
        if ((d.facilities || []).length) {
          h += grp(d.facilities_scoped ? `Buildings this operator occupies in ${d.pop_city.split(',')[0]}` : 'Operator buildings, not narrowed to this hop');
          h += d.facilities.map(f => `<div class="hfac ${d.facilities_scoped ? '' : 'dim'}"><b>${esc(f.name)}</b>${f.address ? `<div class="muted small">${esc(f.address)}</div>` : ''}</div>`).join('');
          h += `<div class="muted small" style="margin-top:5px">${d.facilities_scoped
            ? 'One of these, most likely. An operator publishes which buildings it occupies; it does not publish which rack answers a traceroute.'
            : 'The router name gave no site, so this is everywhere that operator is. It is not evidence about this hop.'}</div>`;
        }
        h += grp('Placement') + r('Shown at', [n.city, n.region, n.country].filter(Boolean).join(', '))
           + r('Source', n.location_source === 'name' ? 'the router\u2019s own name' : 'address database');
        if (n.why) h += r('Impossible', n.why, 'warn');
        return h;
      };
      // Every card is rendered into the page rather than built on click, so
      // the detail is in the document a reader can search, print or save, and
      // the panel is never empty on arrival.
      const hopCards = located.map((n, i) =>
        `<div class="hopcard" data-for="${esc(n.id)}"${i ? ' hidden' : ''}>${hopCard(n)}</div>`).join('');

      // Built before the template so it is part of the page, not appended to it.
      const rulesOut = impossible.length ? `<div style="margin-top:14px">${card('Placements the physics rules out', table(impossible.map(n => ({
          index: n.index, ips: n.ips.join(', '),
          where: [n.city, n.region, n.country].filter(Boolean).join(', '),
          rtt: n.rtt_ms, floor: n.floor_ms, km: n.distance_km })), [
          { t: 'Hop', f: r => num(r.index), num: true, sort: 'index' },
          { t: 'Address', f: r => `<span class="mono small">${esc(r.ips)}</span>`, sort: 'ips' },
          { t: 'Database says', f: r => esc(r.where) || '<span class="muted">unknown</span>', sort: 'where' },
          { t: 'Answered in', f: r => `${r.rtt} ms`, num: true, sort: 'rtt' },
          { t: 'Could not beat', f: r => `${r.floor} ms`, num: true, sort: 'floor' },
          { t: 'Away', f: r => `${num(r.km)} km`, num: true, sort: 'km' }]),
          'light in fibre covers about 200,000 km/s, so nothing can answer sooner than twice the distance divided by that')}</div>` : '';

      const countries = {};
      nodes.forEach(n => { if (n.country) countries[n.country] = (countries[n.country] || 0) + 1; });

      el.innerHTML = `<div class="grid cols-4">
        ${kpi('Destinations with a route', num((dests.destinations || []).length), `${num(st.hops)} hops measured`)}
        ${kpi('Placed on the map', num(located.length), `${num(unlocated.length)} have no coordinates`, unlocated.length > located.length ? 'warn' : '')}
        ${kpi('Ruled out by latency', num(impossible.length), impossible.length ? 'too far away to have answered that fast' : 'every placement is possible', impossible.length ? 'bad' : '')}
        ${card('Tracing', st.active ? `<div>${pill('on', 'ok')}</div><div class="small muted" style="margin-top:6px">Last run ${st.last_run > 0 ? ago(st.last_run) : 'not yet'}.</div>`
          : `<div>${pill('off', '')}</div><div class="small muted" style="margin-top:6px">Switch it on in <a href="#modules?m=paths">Settings &rsaquo; paths</a>. Nothing is probed that this network has not already contacted.</div>`)}</div>

      <div style="margin-top:14px">${card('Your location', `
        <div class="small">${home.ok
          ? `Drawing from <b>${home.lat.toFixed(4)}, ${home.lon.toFixed(4)}</b> <span class="muted">(${esc(home.source)})</span>`
          : `<span class="sev-high">Not known yet.</span> Without it the map has no origin and nothing can be checked against the speed of light.`}</div>
        ${home.detected && (home.detected.lat || home.detected.lon) ? `<div class="muted small" style="margin-top:4px">Your public address ${esc(home.public_address || '')} places you near ${esc([home.detected.city, home.detected.region, home.detected.country].filter(Boolean).join(', '))}.</div>` : ''}
        <div class="actions" style="margin-top:8px">
          <input id="h-lat" style="width:110px" placeholder="latitude" value="${home.ok ? home.lat.toFixed(4) : ''}">
          <input id="h-lon" style="width:110px" placeholder="longitude" value="${home.ok ? home.lon.toFixed(4) : ''}">
          <button class="btn primary" id="h-save">Save</button>
          <button class="btn" id="h-browser">Use this browser's location</button>
          ${home.detected && (home.detected.lat || home.detected.lon) ? `<button class="btn" id="h-detect">Use the public address</button>` : ''}
          ${home.configured ? `<button class="btn" id="h-clear">Go back to detecting it</button>` : ''}
        </div>
        <div class="help" style="margin-top:6px">${esc(home.note || '')}</div>`)}</div>

      <div style="margin-top:14px">${card('Where the traffic goes', `
        <div class="actions" style="margin-bottom:8px">
          <label class="small">Country
            <select id="f-country"><option value="">any</option>${Object.keys(countries).sort().map(c => `<option value="${esc(c)}" ${ctx.params.country === c ? 'selected' : ''}>${esc(c)} (${countries[c]})</option>`).join('')}</select></label>
          <label class="small">Slower than (ms) <input id="f-lat" type="number" min="0" style="width:80px" value="${esc(ctx.params.max_latency || '')}" placeholder="any"></label>
          <label class="small">Within hops <input id="f-hops" type="number" min="1" max="64" style="width:70px" value="${esc(ctx.params.max_hops || '')}" placeholder="any"></label>
          <label class="small">Device
            <select id="f-dev"><option value="">every device</option>${(devs.devices || []).map(d => {
              const sel = (d.addresses || []).includes(ctx.params.device) ? 'selected' : '';
              const n = (d.addresses || []).length;
              return `<option value="${esc(d.key)}" ${sel}>${esc(d.name || d.key)} &middot; ${d.destinations} dest${n > 1 ? ` (${n} addresses)` : ''}</option>`;
            }).join('')}</select></label>
          <button class="btn small" id="f-apply">Apply</button>
          <button class="btn small" id="f-clear">Clear</button>
          <button class="btn small" id="f-reset">Reset zoom</button>
        </div>
        <svg class="pathmap" id="pathmap" viewBox="0 0 ${MAPW} ${MAPH}" preserveAspectRatio="xMidYMid meet">
          ${FS.landPath ? `<path class="land" d="${FS.landPath}"/>` : ''}${FS.graticule(MAPW, MAPH, 30)}${cables}${lines}${dots}
        </svg>
        <div class="hoppanel" id="hoppanel">${hopCards || '<div class="muted small">No hop has coordinates yet.</div>'}
          <div class="muted small" style="margin-top:9px">Click any hop on the map for who runs it, where it is, and how that was decided.</div></div>
        <div class="help" style="margin-top:8px">Land outlines are Natural Earth 1:110m, public domain. ${(cab.cables || []).length ? `${num(cab.cables.length)} submarine cables drawn behind the routes. ${esc(cab.attribution || '')} A traceroute never names a cable, so hovering a long leg shows which ones <em>could</em> have carried it, after discarding any too long to have produced the latency measured. ` : ''}Wheel to zoom, drag to pan. A thick grey line is a leg several destinations share. Coloured lines belong to one destination each. Coordinates come from an address database: dependable for end-user addresses and rough for carrier equipment, which is why placements the measured latency rules out are circled rather than trusted. Where a router's hostname carries a site code, that is used instead of the database, and an amber line shows where the two disagreed.</div>`)}</div>

      ${rulesOut}

      ${unlocated.length || silent ? `<div class="unlocated">${card('Not on the map', table(unlocated.map(n => ({
          index: n.index, ips: n.ips.join(', '), names: (n.names || []).join(', '), country: n.country || '' })), [
          { t: 'Hop', f: r => num(r.index), num: true, sort: 'index' },
          { t: 'Address', f: r => `<span class="mono small">${esc(r.ips)}</span>`, sort: 'ips' },
          { t: 'Name', f: r => esc(r.names) || '<span class="muted">none</span>', sort: 'names' },
          { t: 'Country', f: r => esc(r.country) || '<span class="muted">unknown</span>', sort: 'country' }],
          { empty: 'Every hop has coordinates.' }),
          `${num(silent)} hop${silent === 1 ? '' : 's'} never answered and are not shown at all`)}</div>` : ''}

      <div style="margin-top:14px">${card('Destinations', table(dests.destinations || [], [
        { t: 'Destination', f: r => `<b>${esc(r.name || r.dst)}</b>${r.name ? `<div class="muted small mono">${esc(r.dst)}</div>` : ''}`, sort: 'dst' },
        { t: 'Where', f: r => esc([r.city, r.country].filter(Boolean).join(', ')) || '<span class="muted">unknown</span>', sort: 'country' },
        { t: 'Hops', f: r => num(r.hops), num: true, sort: 'hops' },
        { t: 'Answered', f: r => num(r.answered), num: true, sort: 'answered' },
        { t: 'Reached', f: r => r.complete ? pill('yes', 'ok') : pill('no', ''), sort: 'complete' },
        { t: 'Traced', f: r => ago(r.ts), sort: 'ts' }],
        { empty: 'Nothing traced yet.' }))}</div>`;


      const saveHome = async (lat, lon) => {
        const r = await post('/api/paths/home', { lat: lat, lon: lon });
        FS.toast(r.error || 'Location saved', !!r.error);
        if (!r.error) FS.render();
      };
      FS.$('#h-save', el).onclick = () => {
        const la = parseFloat(FS.$('#h-lat', el).value), lo = parseFloat(FS.$('#h-lon', el).value);
        if (isNaN(la) || isNaN(lo)) { FS.toast('Give a latitude and a longitude', true); return; }
        saveHome(la, lo);
      };
      const browserBtn = FS.$('#h-browser', el);
      if (browserBtn) browserBtn.onclick = () => {
        if (!navigator.geolocation) { FS.toast('This browser will not share a location', true); return; }
        FS.toast('Asking the browser…');
        navigator.geolocation.getCurrentPosition(
          (p) => saveHome(p.coords.latitude, p.coords.longitude),
          (e) => FS.toast('The browser declined: ' + (e && e.message ? e.message : 'no reason given'), true),
          { enableHighAccuracy: false, timeout: 15000, maximumAge: 600000 });
      };
      const detectBtn = FS.$('#h-detect', el);
      if (detectBtn) detectBtn.onclick = () => saveHome(home.detected.lat, home.detected.lon);
      const clearBtn = FS.$('#h-clear', el);
      if (clearBtn) clearBtn.onclick = async () => {
        const r = await post('/api/paths/home', { clear: true });
        FS.toast(r.error || 'Back to detecting it', !!r.error);
        if (!r.error) FS.render();
      };

      const cards = el.querySelectorAll('.hopcard');
      el.querySelectorAll('.hop').forEach(c => {
        const show = () => {
          const want = c.getAttribute('data-hop');
          cards.forEach(d => { d.hidden = d.getAttribute('data-for') !== want; });
        };
        c.addEventListener('click', show);
        c.addEventListener('mouseenter', show);
      });

      FS.panZoomHandle = FS.panZoom(FS.$('#pathmap', el), MAPW, MAPH);
      const go = () => {
        const p = [];
        const c = FS.$('#f-country', el).value, la = FS.$('#f-lat', el).value,
              ho = FS.$('#f-hops', el).value, dv = FS.$('#f-dev', el).value;
        if (c) p.push('country=' + encodeURIComponent(c));
        if (la) p.push('max_latency=' + encodeURIComponent(la));
        if (ho) p.push('max_hops=' + encodeURIComponent(ho));
        if (dv) p.push('device=' + encodeURIComponent(dv));
        FS.go('paths' + (p.length ? '?' + p.join('&') : ''));
      };
      FS.$('#f-apply', el).onclick = go;
      FS.$('#f-clear', el).onclick = () => FS.go('paths');
      FS.$('#f-reset', el).onclick = () => FS.panZoomHandle && FS.panZoomHandle.reset();
    }
  });

})();
